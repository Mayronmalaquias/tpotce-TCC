# BeeIA — Análise de Ameaças em Sistemas Ciber-Físicos usando Honeypots e IA

**TCC — IESB 2026/1**  
Caio Silveira Guimarães Souza & Mayron Malaquias Oliveira  
Orientador: Prof. Pablo Coelho Ferreira

---

## O que é este projeto

O BeeIA é um sistema de monitoramento de ameaças cibernéticas que combina quatro tecnologias:

- **Honeypots Cowrie e Dionaea** — iscas de rede que atraem e registram ataques reais: Cowrie (SSH/Telnet) e Dionaea (SMB/FTP/MSSQL/MQTT e outros serviços vulneráveis emulados, foco em captura de malware)
- **Machine Learning** — classifica cada sessão de ataque automaticamente por tipo e criticidade (um modelo por honeypot, com features específicas para cada tipo de tráfego)
- **LLM** — gera relatórios em linguagem natural (sumário executivo, análise técnica, recomendações) a partir dos dados agregados
- **Dashboard em tempo real** — exibe ataques, gráficos e mapa geográfico conforme chegam

---

## Arquitetura e fluxo de dados

```
┌──────────────────────────────────────────────────────────────────────┐
│  PREPARAÇÃO (offline — feito uma vez antes de subir o sistema)       │
│                                                                      │
│  data_pipeline/generate_logs.py                                      │
│       │  gera sessões sintéticas realistas (4 classes de ataque)     │
│       ↓                                                              │
│  data/dataset/cowrie_logs.jsonl + session_labels.csv                 │
│       │                                                              │
│       ↓                                                              │
│  data_pipeline/extract_features.py                                   │
│       │  agrupa por sessão, extrai 13 features numéricas             │
│       ↓                                                              │
│  data/dataset/training_features.csv                                  │
│       │                                                              │
│       ↓                                                              │
│  ml/cowrie/train.py                                                  │
│       │  treina Random Forest com validação cruzada 5-fold           │
│       ↓                                                              │
│  ml/cowrie/models/cowrie_rf.joblib   ←── modelo salvo               │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│  PRODUÇÃO (tempo real — após docker compose up)                      │
│                                                                      │
│  Cowrie (container)          Dionaea (container)                    │
│       │  SSH/Telnet               │  SMB/FTP/MSSQL/MQTT/...         │
│       ↓                           ↓                                  │
│  data/cowrie/log/cowrie.json   data/dionaea/log/dionaea.json        │
│       │                           │       (volumes compartilhados)  │
│       ↓ tail contínuo             ↓ tail contínuo                    │
│  backend/log_watcher.py (Cowrie watcher + Dionaea watcher)          │
│       │  agrupa eventos por session_id                               │
│       │  evento de fim de sessão → dispara classificação             │
│       ↓                                                              │
│  backend/classifier.py         backend/dionaea_classifier.py        │
│       │  13 features               │  10 features                   │
│       │  cowrie_rf.joblib          │  dionaea_rf.joblib              │
│       ↓                           ↓                                  │
│       └──────────┬────────────────┘                                  │
│                   ↓                                                  │
│       ├──→ backend/database.py    salva no SQLite (data/beeia.db)   │
│       ├──→ backend/geo.py         geolocaliza o IP (ip-api.com)     │
│       ├──→ backend/firewall.py    bloqueia IPs (confiança ≥ 95%)    │
│       ├──→ backend/llm.py         gera relatório sob demanda        │
│       └──→ WebSocket              transmite para o dashboard         │
│                                           │                          │
│                                           ↓                          │
│                                   frontend/  (React + Vite)          │
│                                   ├── cards de métricas              │
│                                   ├── feed de ataques ao vivo        │
│                                   ├── gráficos (barras + donut)      │
│                                   ├── mapa geográfico (Leaflet)      │
│                                   └── relatório em linguagem natural │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Estrutura do repositório

```
beeia/
├── docker/                    # Configurações dos containers
│   ├── cowrie/                #   Honeypot SSH/Telnet
│   ├── nginx/                 #   Proxy reverso
│   └── tpotinit/              #   Inicialização do ambiente
│                               #   (dionaea usa a imagem oficial do T-Pot direto no compose)
│
├── data_pipeline/             # Geração e processamento de dados para treino
│   ├── generate_logs.py               #   Gera logs sintéticos no formato Cowrie
│   ├── extract_features.py            #   Extrai features por sessão do Cowrie (JSONL → CSV)
│   ├── build_dataset.py               #   Orquestra os dois passos acima (Cowrie)
│   ├── generate_dionaea_logs.py       #   Gera logs sintéticos no formato Dionaea
│   ├── extract_dionaea_features.py    #   Extrai features por sessão do Dionaea (JSONL → CSV)
│   └── build_dionaea_dataset.py       #   Orquestra os dois passos acima (Dionaea)
│
├── ml/
│   ├── cowrie/                # Modelo ML específico do Cowrie (13 features)
│   │   ├── train.py           #   Treina o classificador (RF, SVM ou XGBoost)
│   │   ├── requirements.txt
│   │   └── models/            #   Modelos salvos (gitignored)
│   └── dionaea/                # Modelo ML específico do Dionaea (10 features)
│       ├── train.py
│       ├── requirements.txt
│       └── models/            #   Modelos salvos (gitignored)
│
├── backend/                   # API FastAPI
│   ├── main.py                #   App principal, rotas REST, WebSocket
│   ├── classifier.py          #   Carrega modelo do Cowrie e classifica sessões
│   ├── dionaea_classifier.py  #   Carrega modelo do Dionaea e classifica sessões
│   ├── log_watcher.py         #   Monitora logs em tempo real (genérico, um por honeypot)
│   ├── database.py            #   SQLite — ataques (Cowrie + Dionaea) e IPs bloqueados
│   ├── firewall.py            #   Bloqueia IPs (iptables / netsh)
│   ├── geo.py                 #   Geolocalização de IPs
│   ├── llm.py                 #   Relatórios em linguagem natural (API Anthropic)
│   └── requirements.txt
│
├── frontend/                  # Dashboard React + Vite
│   └── src/
│       ├── App.jsx
│       ├── components/
│       │   ├── Overview.jsx   #   Cards de métricas
│       │   ├── AttackFeed.jsx #   Feed de ataques em tempo real
│       │   ├── Charts.jsx     #   Gráficos (Recharts)
│       │   ├── GeoMap.jsx     #   Mapa geográfico (Leaflet)
│       │   └── Report.jsx     #   Relatório em linguagem natural (LLM)
│       └── hooks/
│           └── useWebSocket.js
│
├── data/                      # Dados gerados (gitignored)
│   ├── cowrie/log/            #   Logs brutos do Cowrie
│   ├── dionaea/log/           #   Logs brutos do Dionaea
│   ├── dataset/               #   CSVs de treino
│   └── beeia.db               #   Banco SQLite de ataques
│
├── md-usotcc/                 # Tutoriais de uso
├── docker-compose.yml
├── .env                        # Não versionado — copie de .env.example
└── .env.example

---

## Pré-requisitos

| Ferramenta | Versão mínima | Para quê |
|---|---|---|
| Docker + Compose | 24 + v2 | Subir o Cowrie |
| Python | 3.11+ | Backend, ML, data pipeline |
| Node.js | 18+ | Frontend |

> O sistema foi desenvolvido para rodar em **Linux**. No Windows, use **WSL2** para o Docker e o backend.

---

## Como rodar — passo a passo

### Passo 1 — Gerar o dataset de treino

```bash
cd data_pipeline
python build_dataset.py --sessions 500          # Cowrie
python build_dionaea_dataset.py --sessions 500  # Dionaea
```

Isso cria em `data/dataset/`:
- `cowrie_logs.jsonl` / `dionaea_logs.jsonl` — sessões sintéticas por honeypot
- `session_labels.csv` / `dionaea_session_labels.csv` — rótulos por sessão
- `training_features.csv` (13 features) / `dionaea_training_features.csv` (10 features)

### Passo 2 — Treinar os modelos de ML

```bash
cd ml/cowrie   && pip install -r requirements.txt && python train.py
cd ../dionaea  && pip install -r requirements.txt && python train.py
```

Gera `ml/cowrie/models/cowrie_rf.joblib` e `ml/dionaea/models/dionaea_rf.joblib` com as métricas de acurácia. **O modelo do Dionaea é opcional** — se ausente, o backend sobe normalmente só com o Cowrie ativo.

### Passo 3 — Subir os Honeypots

```bash
# Configure as credenciais de acesso web no .env
# (veja instruções em md-usotcc/rodar-cowrie.md)

docker compose up -d
```

O Cowrie começa a escutar nas portas 22 (SSH) e 23 (Telnet); o Dionaea nas portas dos serviços emulados (21, 445, 1433, 1883, 3306, entre outras — ver `docker-compose.yml`).

### Passo 4 — Iniciar o Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

### Passo 5 — Iniciar o Frontend

```bash
cd frontend
npm install
npm run dev
```

Acesse `http://localhost:5173`.

---

## Retreinamento com dados reais

Após os honeypots coletarem ataques reais, é possível retreinar os modelos com dados autênticos (mesmo fluxo para os dois):

```bash
# 1. Extrair features dos logs reais
cd data_pipeline
python extract_features.py          # lê data/cowrie/log/cowrie.json
python extract_dionaea_features.py  # lê data/dionaea/log/dionaea.json

# 2. Revisar/rotular os dados (opcional — modelo pode usar pseudo-labels)

# 3. Retreinar
cd ml/cowrie  && python train.py --dataset ../../data/dataset/real_features.csv
cd ../dionaea && python train.py --dataset ../../data/dataset/dionaea_real_features.csv
```

---

## Segurança — antes de publicar

Os honeypots são feitos para ficar públicos; **o dashboard/API não são**. Antes de expor o sistema fora da sua máquina:

1. Defina `BEEIA_API_KEY` no `.env` e `VITE_API_KEY` (mesmo valor) no `frontend/.env`, rebuilde o frontend.
2. Ajuste `CORS_ORIGINS` no `.env` para o domínio real do dashboard.
3. Não exponha a porta 8000 do backend diretamente — use o proxy reverso autenticado (`docker/nginx/dist/conf/beeia.conf`, porta 64298, Basic Auth via `WEB_USER`).
4. Bloqueie a porta 8000 para acesso externo no firewall do host.

Rate limiting já vem ativo por padrão (60 req/min geral, 5 a cada 10 min em `/api/report`). Guia completo: [`md-usotcc/proteger-dashboard.md`](md-usotcc/proteger-dashboard.md).

---

## Documentação específica por módulo

| Módulo | README |
|---|---|
| Pipeline de dados | [data_pipeline/README.md](data_pipeline/README.md) |
| Modelo ML (Cowrie) | [ml/cowrie/README.md](ml/cowrie/README.md) |
| Modelo ML (Dionaea) | [ml/dionaea/README.md](ml/dionaea/README.md) |
| Backend (API) | [backend/README.md](backend/README.md) |
| Frontend (Dashboard) | [frontend/README.md](frontend/README.md) |
| Documentação por processo | [Docs/Process/](Docs/Process/README.md) |
| Guia: proteger o dashboard antes de publicar | [md-usotcc/proteger-dashboard.md](md-usotcc/proteger-dashboard.md) |

---

## Tecnologias

| Camada | Tecnologias |
|---|---|
| Honeypots | Cowrie 2.x (SSH/Telnet), Dionaea (SMB/FTP/MSSQL/MQTT/...), Docker |
| Data Pipeline | Python (stdlib) |
| Machine Learning | scikit-learn (Random Forest, SVM), XGBoost — um modelo por honeypot |
| LLM | API Anthropic (Claude) — relatórios em linguagem natural |
| Backend | FastAPI, SQLite, WebSocket |
| Frontend | React 18, Vite, Tailwind CSS, Recharts, Leaflet |

---

## Cronograma (2026/1)

| Entrega | Data |
|---|---|
| Documentação Inicial | 02/04/2026 |
| Infraestrutura e Honeypot | 05/04/2026 |
| Base de Dados e Dataset | 12/04/2026 |
| Machine Learning | 26/04/2026 |
| Interface e API | 10/05/2026 |
| Relatório de Resultados | 17/05/2026 |
| Prévia da Defesa | 24/05/2026 |
| Versão Final do TCC | 07/06/2026 |
