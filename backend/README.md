# backend — API FastAPI

Núcleo de processamento do BeeIA. Recebe os logs brutos do Cowrie e do Dionaea, classifica os ataques com os modelos de ML de cada honeypot, persiste no banco, geolocaliza os IPs, bloqueia atacantes via firewall e transmite tudo em tempo real para o dashboard.

---

## Como rodar

```bash
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000

# Modo desenvolvimento (recarrega ao salvar)
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

> O modelo `ml/cowrie/models/cowrie_rf.joblib` precisa existir antes de iniciar.
> Execute `cd ml/cowrie && python train.py` se ainda não treinou.
>
> O modelo do Dionaea (`ml/dionaea/models/dionaea_rf.joblib`) é **opcional**: se
> não existir, o backend loga um aviso e segue rodando só com o Cowrie — não
> quebra o startup. Execute `cd ml/dionaea && python train.py` para habilitá-lo.

---

## Arquivos

### `main.py` — Aplicação principal

Ponto de entrada. Define todas as rotas REST, o endpoint WebSocket e o ciclo de vida da aplicação (startup/shutdown).

**No startup faz:**
1. Inicializa o banco SQLite (aplica migração de schema se necessário)
2. Carrega o modelo de ML do Cowrie
3. Tenta carregar o modelo do Dionaea e iniciar o `dionaea_watcher` (best-effort — segue sem ele se o modelo não existir)
4. Inicia o `cowrie_watcher` em thread paralela

Os callbacks `_on_session` (Cowrie) e `_on_dionaea_session` (Dionaea) montam o dicionário do ataque e delegam persistência, broadcast via WebSocket e auto-bloqueio ao helper comum `_finalize_attack`.

### `log_watcher.py` — Monitor de logs

Classe genérica reutilizada pelos dois honeypots. Monitora um arquivo JSONL com **tail contínuo** (lê linha por linha conforme são escritas), agrupa eventos por `session_id` e, ao encontrar um evento do conjunto `session_end_events` configurado na instância, entrega a lista completa de eventos ao callback.

```
Honeypot escreve linha → log_watcher lê → acumula eventos por session
→ evento de fim de sessão → envia lista de eventos → classifier.predict()
```

`main.py` instancia duas `LogWatcher`: uma para o Cowrie (`cowrie.session.closed`/`cowrie.session.timeout`, padrão) e outra para o Dionaea (`dionaea.connection.free`, log path e label customizados).

### `classifier.py` — Classificador ML do Cowrie

Carrega `cowrie_rf.joblib` e expõe o método `predict(events)`. Internamente replica a extração de features de `data_pipeline/extract_features.py` para funcionar sem dependência do módulo de pipeline.

Retorna: `{ attack_type, confidence, features }`

### `dionaea_classifier.py` — Classificador ML do Dionaea

Mesmo padrão de `classifier.py`, carregando `ml/dionaea/models/dionaea_rf.joblib` e replicando a extração de features de `data_pipeline/extract_dionaea_features.py` (10 features: conexões, portas, protocolos, shellcode, download, payload, login).

### `database.py` — Banco de dados

SQLite puro (sem ORM). Duas tabelas:

- **`attacks`** — cada sessão classificada, de qualquer honeypot (`honeypot` = `cowrie`/`dionaea`), com o superconjunto de features comportamentais das duas fontes e metadados
- **`blocked_ips`** — IPs bloqueados com timestamp e motivo

Colunas adicionadas após o schema original (`honeypot`, `protocol`, `connection_count`, `unique_ports`, `has_shellcode`) são aplicadas via `ALTER TABLE` em `database.init()` — bancos `data/beeia.db` criados antes da integração do Dionaea são migrados automaticamente na primeira execução.

### `firewall.py` — Bloqueio de IPs

Detecta o sistema operacional e executa o comando correto:

| SO | Comando |
|---|---|
| Linux | `iptables -I INPUT -s <IP> -j DROP` |
| Windows | `netsh advfirewall firewall add rule ...` |

O auto-bloqueio é disparado quando a confiança do modelo ≥ 95% (configurável via `AUTO_BLOCK_THRESHOLD` no `.env`).

### `geo.py` — Geolocalização

Consulta `ip-api.com` (gratuito, sem chave de API, limite de 45 req/min). Mantém cache em memória para evitar requisições repetidas e respeita o rate limit com intervalo mínimo de 1.4 segundos entre chamadas. IPs privados são ignorados automaticamente.

### `llm.py` — Relatórios em linguagem natural

Usa a API da Anthropic (`ANTHROPIC_API_KEY` no `.env`, modelo configurável via `LLM_MODEL`, padrão `claude-haiku-4-5`) para gerar um relatório com sumário executivo, análise técnica e recomendações de mitigação a partir dos dados agregados em `database.get_report_data()`. Não faz nenhuma requisição se `ANTHROPIC_API_KEY` estiver vazia — a rota `/api/report` retorna 503 nesse caso.

### `auth.py` — Autenticação por API key

Protege as rotas REST e o WebSocket com uma chave compartilhada (`BEEIA_API_KEY` no `.env`, header `X-API-Key` ou `?api_key=` no WS). Sem a variável configurada, a API roda sem autenticação (modo dev local — loga um aviso no startup). **Não é suficiente sozinha para expor o backend publicamente** — ver [`md-usotcc/proteger-dashboard.md`](../md-usotcc/proteger-dashboard.md).

### `ratelimit.py` — Rate limiting

`RateLimiter` em memória, por IP. Aplicado globalmente (60 req/min) via `api_router` em `main.py`, com limite adicional mais estrito em `/api/report` (5 a cada 10 min — evita gasto descontrolado de créditos da API da Anthropic).

---

## Rotas da API

| Método | Rota | Descrição |
|---|---|---|
| `GET` | `/api/stats` | Totais, IPs únicos, tipo predominante, bloqueados, contagem por honeypot |
| `GET` | `/api/attacks` | Lista paginada de ataques (`?limit&offset&attack_type&honeypot`) |
| `GET` | `/api/attacks/chart` | Série temporal por hora (`?hours=24`) |
| `GET` | `/api/attacks/top-ips` | IPs mais ativos (`?limit=10`) |
| `GET` | `/api/geo` | Pontos geográficos para o mapa |
| `GET` | `/api/blocked` | Lista de IPs bloqueados |
| `GET` | `/api/report` | Relatório em linguagem natural via LLM (`?hours=24`) |
| `POST` | `/api/block/{ip}` | Bloqueia um IP manualmente |
| `DELETE` | `/api/block/{ip}` | Desbloqueia um IP |
| `WS` | `/ws` | WebSocket — eventos em tempo real |

### Eventos WebSocket

O servidor envia mensagens JSON com o campo `type`:

```json
{ "type": "stats",       "data": { "total_attacks": 42, ... } }
{ "type": "new_attack",  "data": { "src_ip": "1.2.3.4", "attack_type": "brute_force", ... } }
{ "type": "ip_blocked",  "data": { "ip": "1.2.3.4" } }
```

O cliente recebe `stats` imediatamente ao conectar, e `new_attack` a cada nova sessão classificada.

---

## Variáveis de ambiente

| Variável | Padrão | Descrição |
|---|---|---|
| `AUTO_BLOCK_THRESHOLD` | `0.95` | Confiança mínima para auto-bloqueio |
| `COWRIE_LOG_PATH` | `data/cowrie/log/cowrie.json` | Caminho do log do Cowrie |
| `DIONAEA_LOG_PATH` | `data/dionaea/log/dionaea.json` | Caminho do log do Dionaea |
| `ANTHROPIC_API_KEY` | — | Chave da API Anthropic para o módulo LLM (`/api/report`) |
| `LLM_MODEL` | `claude-haiku-4-5` | Modelo usado para gerar os relatórios |
| `BEEIA_API_KEY` | — (sem auth) | Chave exigida em todas as rotas REST + WS. **Defina antes de expor fora de localhost.** |
| `CORS_ORIGINS` | `http://localhost:5173` | Origens autorizadas via CORS, separadas por vírgula |

> **Antes de deixar este backend acessível fora da sua máquina**, leia [`md-usotcc/proteger-dashboard.md`](../md-usotcc/proteger-dashboard.md) — sem `BEEIA_API_KEY` e sem colocar atrás de um proxy autenticado, qualquer pessoa pode bloquear/desbloquear IPs no seu firewall e gastar sua cota da API da Anthropic.

---

## Banco de dados

O arquivo `data/beeia.db` (SQLite) é criado automaticamente na primeira execução. Está no diretório `data/` que é gitignored.

Para inspecionar manualmente:

```bash
sqlite3 data/beeia.db

.tables
SELECT attack_type, COUNT(*) FROM attacks GROUP BY attack_type;
SELECT * FROM blocked_ips;
```
