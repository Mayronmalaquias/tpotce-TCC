# BeeIA — Análise de Ameaças em Sistemas Ciber-Físicos usando Honeypots e IA

**TCC — IESB 2026/1**  
Caio Silveira Guimarães Souza & Mayron Malaquias Oliveira  
Orientador: Prof. Pablo Coelho Ferreira

---

## O que é este projeto

O BeeIA é um sistema de monitoramento de ameaças cibernéticas que combina três tecnologias:

- **Honeypot Cowrie** — isca de rede que atrai e registra ataques reais de SSH/Telnet
- **Machine Learning** — classifica cada sessão de ataque automaticamente por tipo e criticidade
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
│  Cowrie (container Docker)                                           │
│       │  detecta conexão SSH/Telnet → escreve eventos em:           │
│       ↓                                                              │
│  data/cowrie/log/cowrie.json   (volume compartilhado)               │
│       │                                                              │
│       ↓  (tail contínuo do arquivo)                                  │
│  backend/log_watcher.py                                              │
│       │  agrupa eventos por session_id                               │
│       │  ao receber cowrie.session.closed → dispara classificação    │
│       ↓                                                              │
│  backend/classifier.py                                               │
│       │  extrai as mesmas 13 features                                │
│       │  carrega cowrie_rf.joblib → predict_proba                    │
│       ↓                                                              │
│       ├──→ backend/database.py    salva no SQLite (data/beeia.db)   │
│       ├──→ backend/geo.py         geolocaliza o IP (ip-api.com)     │
│       ├──→ backend/firewall.py    bloqueia IPs (confiança ≥ 95%)    │
│       └──→ WebSocket              transmite para o dashboard         │
│                                           │                          │
│                                           ↓                          │
│                                   frontend/  (React + Vite)          │
│                                   ├── cards de métricas              │
│                                   ├── feed de ataques ao vivo        │
│                                   ├── gráficos (barras + donut)      │
│                                   └── mapa geográfico (Leaflet)      │
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
│
├── data_pipeline/             # Geração e processamento de dados para treino
│   ├── generate_logs.py       #   Gera logs sintéticos no formato Cowrie
│   ├── extract_features.py    #   Extrai features por sessão (JSONL → CSV)
│   └── build_dataset.py       #   Orquestra os dois passos acima
│
├── ml/
│   └── cowrie/                # Modelo ML específico do Cowrie
│       ├── train.py           #   Treina o classificador (RF ou XGBoost)
│       ├── requirements.txt
│       └── models/            #   Modelos salvos (gitignored)
│
├── backend/                   # API FastAPI
│   ├── main.py                #   App principal, rotas REST, WebSocket
│   ├── classifier.py          #   Carrega modelo e classifica sessões
│   ├── log_watcher.py         #   Monitora cowrie.json em tempo real
│   ├── database.py            #   SQLite — ataques e IPs bloqueados
│   ├── firewall.py            #   Bloqueia IPs (iptables / netsh)
│   ├── geo.py                 #   Geolocalização de IPs
│   └── requirements.txt
│
├── frontend/                  # Dashboard React + Vite
│   └── src/
│       ├── App.jsx
│       ├── components/
│       │   ├── Overview.jsx   #   Cards de métricas
│       │   ├── AttackFeed.jsx #   Feed de ataques em tempo real
│       │   ├── Charts.jsx     #   Gráficos (Recharts)
│       │   └── GeoMap.jsx     #   Mapa geográfico (Leaflet)
│       └── hooks/
│           └── useWebSocket.js
│
├── data/                      # Dados gerados (gitignored)
│   ├── cowrie/log/            #   Logs brutos do Cowrie
│   ├── dataset/               #   CSVs de treino
│   └── beeia.db               #   Banco SQLite de ataques
│
├── md-usotcc/                 # Tutoriais de uso
├── docker-compose.yml
└── .env
```

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
python build_dataset.py --sessions 500
```

Isso cria em `data/dataset/`:
- `cowrie_logs.jsonl` — 2000 sessões sintéticas
- `session_labels.csv` — rótulos por sessão
- `training_features.csv` — 13 features por sessão, pronto para treino

### Passo 2 — Treinar o modelo de ML

```bash
cd ml/cowrie
pip install -r requirements.txt
python train.py
```

Gera `ml/cowrie/models/cowrie_rf.joblib` com as métricas de acurácia.

### Passo 3 — Subir o Honeypot Cowrie

```bash
# Configure as credenciais de acesso web no .env
# (veja instruções em md-usotcc/rodar-cowrie.md)

docker compose up -d
```

O Cowrie começa a escutar na porta 22 (SSH) e 23 (Telnet).

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

Após o Cowrie coletar ataques reais, é possível retreinar o modelo com dados autênticos:

```bash
# 1. Extrair features dos logs reais do Cowrie
cd data_pipeline
python extract_features.py  # lê data/cowrie/log/cowrie.json

# 2. Revisar/rotular os dados (opcional — modelo pode usar pseudo-labels)

# 3. Retreinar
cd ml/cowrie
python train.py --dataset ../../data/dataset/real_features.csv
```

---

## Documentação específica por módulo

| Módulo | README |
|---|---|
| Pipeline de dados | [data_pipeline/README.md](data_pipeline/README.md) |
| Modelo ML (Cowrie) | [ml/cowrie/README.md](ml/cowrie/README.md) |
| Backend (API) | [backend/README.md](backend/README.md) |
| Frontend (Dashboard) | [frontend/README.md](frontend/README.md) |

---

## Tecnologias

| Camada | Tecnologias |
|---|---|
| Honeypot | Cowrie 2.x, Docker |
| Data Pipeline | Python (stdlib) |
| Machine Learning | scikit-learn (Random Forest), XGBoost |
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
