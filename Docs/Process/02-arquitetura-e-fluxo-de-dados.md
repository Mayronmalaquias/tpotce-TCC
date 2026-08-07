# Processo 02 — Arquitetura e Fluxo de Dados

O BeeIA opera em **dois modos complementares**, conforme descrito na metodologia do artigo (Seção 3.1):

1. **Modo offline (preparação)** — executado uma única vez, antes de subir o ambiente, para treinar os modelos de ML (um por honeypot).
2. **Modo produção (tempo real)** — ativado após `docker compose up`, processa ataques reais continuamente.

## Modo offline — preparação dos modelos

```
data_pipeline/generate_logs.py              data_pipeline/generate_dionaea_logs.py
     │  4 classes de ataque (Cowrie)              │  4 classes de ataque (Dionaea)
     ↓                                             ↓
cowrie_logs.jsonl + session_labels.csv       dionaea_logs.jsonl + dionaea_session_labels.csv
     │                                             │
     ↓                                             ↓
data_pipeline/extract_features.py            data_pipeline/extract_dionaea_features.py
     │  agrupa por sessão, 13 features             │  agrupa por sessão, 10 features
     ↓                                             ↓
training_features.csv                        dionaea_training_features.csv
     │                                             │
     ↓                                             ↓
ml/cowrie/train.py                           ml/dionaea/train.py
     │  RF (ou SVM/XGBoost), CV 5-fold             │  RF (ou SVM/XGBoost), CV 5-fold
     ↓                                             ↓
ml/cowrie/models/cowrie_rf.joblib            ml/dionaea/models/dionaea_rf.joblib
```

Detalhado em [04-pipeline-de-dados.md](04-pipeline-de-dados.md), [05-machine-learning-treinamento.md](05-machine-learning-treinamento.md) e [12-honeypot-dionaea.md](12-honeypot-dionaea.md).

## Modo produção — tempo real

```
Cowrie (container)                    Dionaea (container)
     │  SSH/Telnet                         │  SMB/FTP/MSSQL/MQTT/...
     ↓                                     ↓
data/cowrie/log/cowrie.json          data/dionaea/log/dionaea.json
     │        (volumes compartilhados entre container e backend)
     ↓  tail contínuo                      ↓  tail contínuo
backend/log_watcher.py (uma instância por honeypot — classe genérica)
     │  agrupa eventos por session_id
     │  evento de fim de sessão → dispara classificação
     ↓
backend/classifier.py                backend/dionaea_classifier.py
     │  13 features                        │  10 features
     │  cowrie_rf.joblib → predict_proba   │  dionaea_rf.joblib → predict_proba
     ↓                                     ↓
     └─────────────────┬───────────────────┘
                        ↓
     ├──→ backend/database.py    salva no SQLite (data/beeia.db, campo honeypot)
     ├──→ backend/geo.py         geolocaliza o IP (ip-api.com)
     ├──→ backend/firewall.py    bloqueia IPs (confiança ≥ 95%)
     ├──→ backend/llm.py         gera relatório sob demanda (GET /api/report)
     └──→ WebSocket              transmite para o dashboard
                                        │
                                        ↓
                                frontend/  (React + Vite)
                                ├── cards de métricas
                                ├── feed de ataques ao vivo (com badge de honeypot)
                                ├── gráficos (barras + donut)
                                ├── mapa geográfico (Leaflet)
                                └── relatório em linguagem natural (LLM)
```

Detalhado em [03-honeypot-cowrie-e-infraestrutura.md](03-honeypot-cowrie-e-infraestrutura.md), [12-honeypot-dionaea.md](12-honeypot-dionaea.md), [06-backend-api-tempo-real.md](06-backend-api-tempo-real.md) e [07-frontend-dashboard.md](07-frontend-dashboard.md).

## Estilo arquitetural

Não é microserviços nem monolito clássico: é um conjunto de **processos Python independentes** (backend FastAPI, honeypots em containers, pipeline/treino como scripts CLI) que se comunicam por:

- **Arquivo compartilhado** — o log JSONL de cada honeypot (`data/cowrie/log/cowrie.json`, `data/dionaea/log/dionaea.json`) é o ponto de integração entre o container e o backend.
- **SQLite** — fonte de verdade para o backend (`data/beeia.db`), sem ORM. Uma única tabela `attacks` com um superconjunto de colunas comportamentais; o campo `honeypot` identifica a origem, e cada honeypot preenche apenas o subconjunto relevante.
- **WebSocket** — canal de push em tempo real do backend para o frontend.
- **API da Anthropic** — chamada sob demanda pelo `llm.py` (não é um canal contínuo, só quando o usuário pede um relatório).

## Estrutura de diretórios do repositório

```
beeia/
├── docker/                    # Configurações dos containers
│   ├── cowrie/                #   Honeypot SSH/Telnet
│   ├── nginx/                 #   Proxy reverso
│   └── tpotinit/              #   Inicialização do ambiente
│                               #   (dionaea usa a imagem T-Pot direto no docker-compose.yml)
│
├── data_pipeline/             # Geração e processamento de dados para treino (Cowrie + Dionaea)
├── ml/
│   ├── cowrie/                 # Modelo ML do Cowrie (13 features)
│   └── dionaea/                # Modelo ML do Dionaea (10 features)
├── backend/                   # API FastAPI
├── frontend/                  # Dashboard React + Vite
├── data/                      # Dados gerados (gitignored)
├── md-usotcc/                 # Tutoriais de uso operacional
├── Docs/
│   ├── TCC_SENDLER/           # Artigo e banner do TCC
│   └── Process/                # Esta pasta — documentação por processo
├── docker-compose.yml
├── .env                        # Não versionado (contém segredos)
└── .env.example                 # Template versionado
```

## Stack tecnológico por camada

| Camada | Tecnologias |
|---|---|
| Honeypots | Cowrie 2.x, Dionaea, Docker Compose |
| Proxy/infra | Nginx, tpotinit (herdados do T-Pot CE) |
| Data Pipeline | Python 3.11+ (stdlib puro) |
| Machine Learning | scikit-learn (RF, SVM), XGBoost (opcional), joblib — um modelo por honeypot |
| LLM | API Anthropic (Claude), modelo padrão `claude-haiku-4-5` |
| Backend | FastAPI, SQLite, WebSocket, uvicorn |
| Frontend | React 18, Vite, Tailwind CSS, Recharts, Leaflet |
| Geolocalização | ip-api.com (gratuito, sem chave) |
| Firewall | iptables (Linux) / netsh (Windows) |

> O repositório é um fork/derivado do **T-Pot CE** (Telekom Security) — daí a presença de `tpotinit`, variáveis `TPOT_*` no `.env` e o formato do `docker-compose.yml`. Cowrie e Dionaea são dois honeypots do T-Pot já ativados no BeeIA; outros honeypots do T-Pot podem ser adicionados seguindo o mesmo padrão (ver [12-honeypot-dionaea.md](12-honeypot-dionaea.md) § Adicionar novo honeypot).
