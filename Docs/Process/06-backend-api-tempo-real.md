# Processo 06 — Backend: Classificação e Resposta em Tempo Real

Módulo `backend/` (FastAPI) — núcleo de processamento do BeeIA. Recebe os logs brutos do Cowrie e do Dionaea, classifica os ataques com o modelo de ML de cada honeypot, persiste no banco, geolocaliza os IPs, bloqueia atacantes via firewall e transmite tudo em tempo real para o dashboard.

## Como rodar

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
# desenvolvimento (recarrega ao salvar):
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

> O modelo `ml/cowrie/models/cowrie_rf.joblib` precisa existir antes de iniciar (ver [05-machine-learning-treinamento.md](05-machine-learning-treinamento.md)). O modelo do Dionaea é **opcional** — sem ele, o backend loga um aviso e segue rodando só com o Cowrie (ver [12-honeypot-dionaea.md](12-honeypot-dionaea.md)).

## Arquivos e processo de cada um

### `main.py` — orquestração

Ponto de entrada. Define rotas REST, endpoint WebSocket e o ciclo de vida da aplicação. No **startup**:

1. Inicializa o banco SQLite (aplica migração de schema se necessário).
2. Carrega o modelo de ML do Cowrie.
3. Tenta carregar o modelo do Dionaea e iniciar o watcher dele — best-effort, não quebra o startup se o modelo não existir.
4. Inicia o watcher do Cowrie em thread paralela.

Os callbacks `_on_session` (Cowrie) e `_on_dionaea_session` (Dionaea) só montam o dicionário do ataque; persistência, broadcast via WebSocket e auto-bloqueio ficam num helper comum, `_finalize_attack()`, para não duplicar essa lógica entre os dois honeypots.

### `log_watcher.py` — monitor de logs

Classe genérica, **reutilizada pelos dois honeypots**. Faz **tail contínuo** de um arquivo JSONL (lê linha por linha conforme são escritas), agrupa eventos por `session_id` e, ao encontrar um evento do conjunto `session_end_events` configurado na instância, entrega a lista completa de eventos ao classificador.

```
Honeypot escreve linha → log_watcher lê → acumula eventos por session
→ evento de fim de sessão → envia lista de eventos → classifier.predict()
```

`main.py` instancia duas `LogWatcher`: uma para o Cowrie (`cowrie.session.closed`/`cowrie.session.timeout`, o padrão da classe) e outra para o Dionaea (`dionaea.connection.free`, log path e label customizados via `DIONAEA_LOG_PATH`).

### `classifier.py` — classificação (Cowrie)

Carrega `cowrie_rf.joblib` e expõe `predict(events)`. **Reimplementa** a extração de features de `data_pipeline/extract_features.py` (as mesmas 13 features) para não acoplar o backend em produção ao módulo de pipeline offline. Retorna:

```json
{ "attack_type": "brute_force", "confidence": 0.97, "features": { ... } }
```

### `dionaea_classifier.py` — classificação (Dionaea)

Mesmo padrão de `classifier.py`, carregando `dionaea_rf.joblib` e reimplementando a extração de `data_pipeline/extract_dionaea_features.py` (10 features: conexões, portas, protocolos, shellcode, download, payload, login). Detalhes em [12-honeypot-dionaea.md](12-honeypot-dionaea.md).

### `database.py` — persistência

SQLite puro (sem ORM), duas tabelas:

- **`attacks`** — cada sessão classificada de qualquer honeypot (campo `honeypot` = `cowrie`/`dionaea`), com o superconjunto de features comportamentais das duas fontes e metadados.
- **`blocked_ips`** — IPs bloqueados, com timestamp e motivo.

O arquivo `data/beeia.db` é criado automaticamente na primeira execução (gitignored). Colunas adicionadas após o schema original (`honeypot`, `protocol`, `connection_count`, `unique_ports`, `has_shellcode`) são aplicadas via `ALTER TABLE` em `database.init()` — bancos criados antes da integração do Dionaea são migrados automaticamente.

```bash
sqlite3 data/beeia.db
.tables
SELECT attack_type, COUNT(*) FROM attacks GROUP BY attack_type;
SELECT * FROM blocked_ips;
```

### `firewall.py` — bloqueio automático de IPs

Detecta o SO e executa o comando correspondente:

| SO | Comando |
|---|---|
| Linux | `iptables -I INPUT -s <IP> -j DROP` |
| Windows | `netsh advfirewall firewall add rule ...` |

O auto-bloqueio dispara quando a confiança do modelo ≥ **95%** (`AUTO_BLOCK_THRESHOLD`, configurável via `.env`).

### `geo.py` — geolocalização

Consulta `ip-api.com` (gratuito, sem chave, limite de **45 req/min**). Mantém cache em memória para evitar requisições repetidas e respeita o rate limit com intervalo mínimo de 1.4s entre chamadas. IPs privados são ignorados automaticamente.

> **Limitação conhecida** (citada no artigo, Seção 6.2): esse limite de 45 req/min pode gerar lacunas geográficas em cenários de alta volumetria de ataques.

### `llm.py` — módulo de relatórios em linguagem natural

Implementado usando a API da Anthropic (`ANTHROPIC_API_KEY` no `.env`, modelo configurável via `LLM_MODEL`, padrão `claude-haiku-4-5`). A rota `GET /api/report?hours=24` chama `database.get_report_data(hours)` — que agrega distribuição de tipos, top 5 IPs, países de origem e médias das features comportamentais (tentativas de login, comandos, duração, taxas de reverse shell/wget-curl/recon/download) — e passa esses dados para `llm.generate_report()`, que monta o prompt e retorna um relatório estruturado em três seções: sumário executivo, análise técnica e recomendações de mitigação priorizadas (conforme artigo, Seção 4.5). Sem `ANTHROPIC_API_KEY` configurada, a rota retorna `503`.

## Processo completo de uma sessão

```
1. Honeypot fecha a sessão → evento de fim (cowrie.session.closed | dionaea.connection.free)
2. log_watcher detecta o evento, junta todos os eventos da sessão
3. classifier.predict(events) → extrai as features do honeypot → predict_proba → {attack_type, confidence}
4. _finalize_attack() grava a linha em `attacks` (database.py)
5. geo.py resolve país/cidade do src_ip (cache + rate limit)
6. Se confidence >= AUTO_BLOCK_THRESHOLD → firewall.py bloqueia o IP → grava em `blocked_ips`
7. WebSocket faz broadcast do evento new_attack (e ip_blocked, se aplicável) para todos os clientes conectados
```

## Rotas REST

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

```json
{ "type": "stats",       "data": { "total_attacks": 42, ... } }
{ "type": "new_attack",  "data": { "src_ip": "1.2.3.4", "attack_type": "brute_force", ... } }
{ "type": "ip_blocked",  "data": { "ip": "1.2.3.4" } }
```

O cliente recebe `stats` imediatamente ao conectar, e `new_attack` a cada nova sessão classificada.

## Variáveis de ambiente

| Variável | Padrão | Descrição |
|---|---|---|
| `AUTO_BLOCK_THRESHOLD` | `0.95` | Confiança mínima para auto-bloqueio |
| `COWRIE_LOG_PATH` | `data/cowrie/log/cowrie.json` | Caminho do log do Cowrie |
| `DIONAEA_LOG_PATH` | `data/dionaea/log/dionaea.json` | Caminho do log do Dionaea |
| `ANTHROPIC_API_KEY` | — | Chave da API Anthropic para o módulo LLM |
| `LLM_MODEL` | `claude-haiku-4-5` | Modelo usado para gerar os relatórios |
| `BEEIA_API_KEY` | — (sem auth) | Chave exigida em `X-API-Key` (REST) / `?api_key=` (WS) |
| `CORS_ORIGINS` | `http://localhost:5173` | Origens autorizadas via CORS, separadas por vírgula |

## Segurança da API (`auth.py`, `ratelimit.py`)

Implementado em 2026-07-29, depois de identificar que a API não tinha nenhuma proteção — qualquer pessoa alcançando o backend podia bloquear/desbloquear IPs arbitrários ou esgotar a cota da API da Anthropic via `/api/report`.

- **`auth.py`** — dependency `require_api_key` (rotas REST, via `api_router = APIRouter(dependencies=[...])` em `main.py`) e `ws_key_is_valid()` (checagem manual dentro de `ws_endpoint`, já que dependencies de rota HTTP não se aplicam automaticamente a rotas WebSocket). Sem `BEEIA_API_KEY` configurada, tudo funciona sem autenticação — modo dev local.
- **`ratelimit.py`** — `RateLimiter` em memória, por IP. Um limite global (60 req/min, aplicado a todo `api_router`) e um mais estrito só em `/api/report` (5 a cada 10 min).
- Com `BEEIA_API_KEY` definida, `/docs`, `/redoc` e `/openapi.json` ficam desabilitados (reduz superfície de reconhecimento).
- **Isso não é suficiente para expor o backend na internet sozinho** — a chave fica embutida no bundle do frontend (visível a quem abrir a página). A camada que realmente restringe *quem chega* à página é o proxy reverso com Basic Auth — ver [`md-usotcc/proteger-dashboard.md`](../../md-usotcc/proteger-dashboard.md) e `docker/nginx/dist/conf/beeia.conf`.

## Próximo processo

[07-frontend-dashboard.md](07-frontend-dashboard.md) — como o dashboard consome essas rotas e o WebSocket.
