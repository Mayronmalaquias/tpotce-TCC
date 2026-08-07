# Processo 12 — Honeypot Dionaea (Captura de Malware)

Segundo honeypot do BeeIA, implementado em 2026-07-29 seguindo o padrão já estabelecido pelo Cowrie (ver [03-honeypot-cowrie-e-infraestrutura.md](03-honeypot-cowrie-e-infraestrutura.md), [04-pipeline-de-dados.md](04-pipeline-de-dados.md) e [05-machine-learning-treinamento.md](05-machine-learning-treinamento.md)) — infraestrutura Docker própria, pipeline de dados sintéticos próprio, modelo de ML próprio (features diferentes das do Cowrie) e integração no backend/frontend existentes.

## Contexto teórico (artigo, Seção 2.1)

O Dionaea atua como um mecanismo de **baixa a média interatividade**, projetado para capturar payloads e artefatos maliciosos de forma automatizada, emulando protocolos amplamente explorados por worms e botnets: **SMB, HTTP, FTP, TFTP** (e, na implementação do BeeIA, também MSSQL, MQTT, MySQL e SIP). Ao contrário do Cowrie — que mimetiza um shell interativo completo — o Dionaea foca em deixar o atacante "completar" a exploração de um serviço vulnerável até o ponto de baixar/entregar o payload malicioso, que o honeypot então captura.

## Infraestrutura Docker

Serviço `dionaea` adicionado ao `docker-compose.yml`, seguindo o mesmo padrão do `cowrie` (imagem `${TPOT_REPO}/dionaea:${TPOT_VERSION}`, rede própria `dionaea_local`, `read_only: true`, volumes sob `${TPOT_DATA_PATH}/dionaea/`).

| Porta | Serviço emulado |
|---|---|
| 21 | FTP |
| 42 | WINS |
| 69/udp | TFTP |
| 135 | MSRPC |
| 443 | HTTPS |
| 445 | SMB |
| 1433 | MSSQL |
| 1723 | PPTP |
| 1883 | MQTT |
| 3306 | MySQL |
| 5060 (tcp+udp) | SIP |
| 27017 | MongoDB |

> A configuração de portas/volumes segue o padrão conhecido do T-Pot CE para o Dionaea — como o repositório não tinha nenhum resquício de configuração do Dionaea (foi limpo para conter só o Cowrie), essa é uma configuração best-effort baseada na estrutura do T-Pot. Ajustar se divergir da imagem realmente publicada em `${TPOT_REPO}/dionaea` ao fazer o primeiro deploy real.

## Normalização de sessão (diferença fundamental em relação ao Cowrie)

O Dionaea real trata **cada conexão TCP/UDP como um objeto isolado** — não existe um conceito nativo de "sessão do atacante" como no Cowrie (que tem um shell interativo contínuo, com `session_id` estável do connect ao closed). O BeeIA normaliza isso agrupando, sob um único `session`, todas as conexões que um mesmo IP faz contra o Dionaea dentro de uma janela curta — o suficiente para caracterizar o padrão de comportamento (scan de portas, sondagem, exploit, download de malware).

Essa normalização está documentada e implementada em `data_pipeline/generate_dionaea_logs.py` (dataset sintético) e precisa ser replicada em `backend/dionaea_watcher.py`/`main.py` ao integrar o Dionaea real — hoje o `LogWatcher` genérico já suporta isso via o parâmetro `session_end_events={"dionaea.connection.free"}`, mas o agrupamento real dependerá de como o `dionaea.json` de produção representa múltiplas conexões do mesmo IP.

### Formato normalizado dos eventos (`dionaea.json`)

| `eventid` | Campos | Significado |
|---|---|---|
| `dionaea.connection.tcp.accept` / `.udp.accept` | `session`, `timestamp`, `src_ip`, `src_port`, `dst_port`, `protocol` | Nova conexão a um serviço emulado (`smbd`, `ftpd`, `mssqld`, `mqttd`, `httpd`, `mysqld`, `sipd`, `upnpd`, `tftpd`) |
| `dionaea.data.in` | `session`, `timestamp`, `data_length`, `has_shellcode` | Payload recebido do atacante |
| `dionaea.login.attempt` | `session`, `timestamp`, `username`, `password` | Tentativa de autenticação (serviços com login: FTP, MSSQL, MQTT) |
| `dionaea.download.complete` | `session`, `timestamp`, `url`, `md5_hash`, `file_size` | Download de payload capturado pelo honeypot |
| `dionaea.connection.free` | `session`, `timestamp`, `duration` | Fim da janela de atividade — dispara a classificação |

## Pipeline de dados (`data_pipeline/`)

| Arquivo | Função |
|---|---|
| `generate_dionaea_logs.py` | Gera sessões sintéticas (4 classes) no formato normalizado acima |
| `extract_dionaea_features.py` | Agrupa eventos por `session`, extrai 10 features numéricas |
| `build_dionaea_dataset.py` | Orquestra os dois passos acima (`python build_dionaea_dataset.py --sessions 500`) |

### Classes de ataque sintetizadas

| Classe | Comportamento simulado |
|---|---|
| `port_scan` | Conexões rápidas a 5+ portas/serviços distintos, sem payload, intervalos muito curtos (scan automatizado) |
| `service_probe` | 1-3 conexões, payload pequeno/benigno, sem assinatura de exploit, pode incluir tentativa de login |
| `exploit_attempt` | Conexão a SMB/MSSQL com payload grande e assinatura de shellcode (`has_shellcode=1`) |
| `malware_download` | Conexão seguida de `dionaea.download.complete` — payload capturado pelo honeypot |

### 10 features extraídas por sessão

```
connection_count             unique_protocols              has_shellcode
unique_ports                 avg_connection_interval_ms     has_download
session_duration_s           min_connection_interval_ms     payload_size_avg
login_attempt_count
```

Diferentes das 13 features do Cowrie (que são centradas em login/shell/comandos) — aqui o foco é conexão/porta/payload, compatível com o que o Dionaea de fato observa. Detalhes em [`ml/dionaea/README.md`](../../ml/dionaea/README.md).

## Modelo de ML (`ml/dionaea/`)

Mesma estrutura do `ml/cowrie/train.py`: split 80/20 estratificado, validação cruzada 5-fold, RF/SVM/XGBoost via `--model`, salva `models/dionaea_rf.joblib` + `dionaea_rf_meta.json`. No dataset sintético (500 sessões/classe), F1-macro = 1,0000 no RF — mesma observação já feita para o Cowrie: reflete a separabilidade de dados sintéticos, não uma validação com tráfego real.

## Integração no backend

- **`backend/dionaea_classifier.py`** — mesmo padrão de `classifier.py`: carrega `dionaea_rf.joblib`, reimplementa a extração das 10 features, expõe `predict(events)`.
- **`backend/log_watcher.py`** — generalizado para aceitar `session_end_events` configurável (antes hardcoded para eventos do Cowrie). `main.py` instancia dois `LogWatcher`: um para o Cowrie (padrão) e outro para o Dionaea (`session_end_events={"dionaea.connection.free"}`, `log_path` via `DIONAEA_LOG_PATH`).
- **`backend/main.py`** — `_on_dionaea_session()` monta o dicionário do ataque (com `honeypot="dionaea"`, `protocol`, `connection_count`, `unique_ports`, `has_shellcode`) e delega a um helper comum, `_finalize_attack()`, compartilhado com o callback do Cowrie — evita duplicar a lógica de persistência/broadcast/auto-bloqueio entre os dois honeypots.
- **Carregamento best-effort**: se `ml/dionaea/models/dionaea_rf.joblib` não existir, o backend loga um aviso no startup e continua rodando só com o Cowrie — não quebra a inicialização.
- **`backend/database.py`** — a tabela `attacks` ganhou um superconjunto de colunas: `honeypot` (`cowrie`/`dionaea`), `protocol`, `connection_count`, `unique_ports`, `has_shellcode`. Bancos `data/beeia.db` criados antes dessa integração são migrados automaticamente via `ALTER TABLE` em `database.init()` (SQLite não tem `ADD COLUMN IF NOT EXISTS`, então a migração checa `PRAGMA table_info` antes de cada `ALTER`). O campo `has_file_download` é reaproveitado para representar "download de malware" nos dois honeypots (semântica compatível).
- **`/api/attacks`** ganhou o filtro `?honeypot=cowrie|dionaea`. **`/api/stats`** e **`/api/report`** (dados do LLM) ganharam `honeypot_counts`.

## Integração no frontend

Como o `attack_type` `malware_download` é reaproveitado entre os dois honeypots, o badge/cor já existentes no `AttackFeed.jsx`/`Charts.jsx`/`GeoMap.jsx` funcionam automaticamente para ele. Três tipos novos, exclusivos do Dionaea, foram adicionados aos mapas de label/cor em `Overview.jsx`, `AttackFeed.jsx`, `Charts.jsx` e `GeoMap.jsx`: `port_scan` (teal), `service_probe` (amarelo), `exploit_attempt` (rosa). O `AttackFeed.jsx` ganhou uma coluna **Honeypot** (badge "Cowrie"/"Dionaea") entre o IP de origem e o tipo de ataque.

## O que ainda falta (deploy real, não código)

- Validar a imagem `${TPOT_REPO}/dionaea` e as portas/volumes reais contra a documentação oficial do T-Pot CE ao subir o container pela primeira vez — a config atual é best-effort (ver seção Infraestrutura acima).
- Confirmar o schema real do `dionaea.json` produzido pela imagem oficial contra o formato normalizado assumido aqui (ver tabela de eventos acima) e ajustar `dionaea_classifier.py`/agrupamento de sessão se necessário.
- Coletar e rotular dados reais do Dionaea para retreinamento (mesma pendência já existente para o Cowrie — ver [10-limitacoes-e-trabalhos-futuros.md](10-limitacoes-e-trabalhos-futuros.md)).

## Próximo processo

[10-limitacoes-e-trabalhos-futuros.md](10-limitacoes-e-trabalhos-futuros.md) — status atualizado do que falta no roadmap.
