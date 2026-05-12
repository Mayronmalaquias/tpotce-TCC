# backend — API FastAPI

Núcleo de processamento do BeeIA. Recebe os logs brutos do Cowrie, classifica os ataques com o modelo de ML, persiste no banco, geolocalizas os IPs, bloqueia atacantes via firewall e transmite tudo em tempo real para o dashboard.

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

---

## Arquivos

### `main.py` — Aplicação principal

Ponto de entrada. Define todas as rotas REST, o endpoint WebSocket e o ciclo de vida da aplicação (startup/shutdown).

**No startup faz:**
1. Inicializa o banco SQLite
2. Carrega o modelo de ML
3. Inicia o `LogWatcher` em thread paralela

### `log_watcher.py` — Monitor de logs

Monitora `data/cowrie/log/cowrie.json` com um **tail contínuo** (lê o arquivo linha por linha conforme novas linhas são escritas). Agrupa os eventos por `session_id` e, ao receber `cowrie.session.closed`, entrega a lista completa de eventos para o classificador.

```
Cowrie escreve linha → log_watcher lê → acumula eventos por session
→ session.closed → envia lista de eventos → classifier.predict()
```

### `classifier.py` — Classificador ML

Carrega `cowrie_rf.joblib` e expõe o método `predict(events)`. Internamente replica a extração de features de `data_pipeline/extract_features.py` para funcionar sem dependência do módulo de pipeline.

Retorna: `{ attack_type, confidence, features }`

### `database.py` — Banco de dados

SQLite puro (sem ORM). Duas tabelas:

- **`attacks`** — cada sessão classificada com todas as features e metadados
- **`blocked_ips`** — IPs bloqueados com timestamp e motivo

### `firewall.py` — Bloqueio de IPs

Detecta o sistema operacional e executa o comando correto:

| SO | Comando |
|---|---|
| Linux | `iptables -I INPUT -s <IP> -j DROP` |
| Windows | `netsh advfirewall firewall add rule ...` |

O auto-bloqueio é disparado quando a confiança do modelo ≥ 95% (configurável via `AUTO_BLOCK_THRESHOLD` no `.env`).

### `geo.py` — Geolocalização

Consulta `ip-api.com` (gratuito, sem chave de API, limite de 45 req/min). Mantém cache em memória para evitar requisições repetidas e respeita o rate limit com intervalo mínimo de 1.4 segundos entre chamadas. IPs privados são ignorados automaticamente.

---

## Rotas da API

| Método | Rota | Descrição |
|---|---|---|
| `GET` | `/api/stats` | Totais, IPs únicos, tipo predominante, bloqueados |
| `GET` | `/api/attacks` | Lista paginada de ataques (`?limit&offset&attack_type`) |
| `GET` | `/api/attacks/chart` | Série temporal por hora (`?hours=24`) |
| `GET` | `/api/attacks/top-ips` | IPs mais ativos (`?limit=10`) |
| `GET` | `/api/geo` | Pontos geográficos para o mapa |
| `GET` | `/api/blocked` | Lista de IPs bloqueados |
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
