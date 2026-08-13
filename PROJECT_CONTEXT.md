# PROJECT CONTEXT — BeeIA

> Documento mestre de arquitetura e contexto do projeto. Gerado a partir do código-fonte do repositório e do artigo em `Docs/TCC_SENDLER/Artigo_TCC1_ENGC_ENGT_CCO.pdf`.
> Última atualização: 2026-07-29.

---

## 1. Visão Geral e Objetivo do Projeto

**BeeIA** é o TCC (2026/1, IESB) de **Caio Silveira Guimarães Souza** e **Mayron Malaquias Oliveira**, orientados pelo **Prof. Pablo Coelho Ferreira**. O nome completo do trabalho é *"BeeIA: Análise de Ameaças em Sistemas Ciber-Físicos Usando Honeypots e Inteligência Artificial"*.

### Resumo executivo

O BeeIA é um sistema inteligente de monitoramento e análise de ameaças cibernéticas que integra quatro camadas:

1. **Captura** — dois honeypots reais em containers Docker isolados: **Cowrie** (SSH/Telnet) e **Dionaea** (SMB/FTP/MSSQL/MQTT e outros serviços vulneráveis emulados, foco em captura de malware).
2. **Classificação** — classificadores supervisionados (Random Forest, SVM, XGBoost) categorizam cada sessão de ataque por tipo — um modelo por honeypot, treinado sobre features comportamentais específicas (13 para o Cowrie, 10 para o Dionaea).
3. **Interpretação (LLM)** — um módulo usando a API da Anthropic gera relatórios em linguagem natural (sumário executivo, análise técnica, recomendações de mitigação) a partir das estatísticas agregadas, sob demanda.
4. **Visualização** — um dashboard React em tempo real exibe os ataques classificados, gráficos, mapa geográfico e os relatórios gerados pelo LLM.

### Problema que o projeto resolve

- **Fadiga de alertas (alert fatigue):** um único servidor exposto à internet gera milhares de eventos/hora, inviabilizando a triagem manual por analistas de SOC.
- **Falta de contexto tático:** é difícil distinguir, em tempo real, scanning automatizado de estágios avançados de intrusão (injeção de comando, reverse shell).
- **Ferramentas tradicionais (firewalls, IDS por assinatura)** falham contra ataques polimórficos e de dia zero.

### Proposta de valor

Honeypots não têm tráfego legítimo — qualquer interação é, por definição, hostil, o que reduz drasticamente falsos positivos em relação a IDS convencionais. O BeeIA soma a isso classificação automática por ML (sem depender de assinaturas) e uma camada de tradução para linguagem natural, buscando democratizar a análise de segurança em organizações sem equipe especializada.

---

## 2. Arquitetura e Tecnologias

### Estilo arquitetural

Pipeline de dados desacoplado em **dois modos**:

- **Modo offline (preparação)** — executado uma vez, antes de subir o ambiente: geração de dataset sintético → extração de features → treino do modelo → artefato `.joblib` salvo em disco.
- **Modo produção (tempo real)** — ativado após `docker compose up`: honeypot → log watcher (tail contínuo) → classificador → persistência + geolocalização + firewall → broadcast via WebSocket → dashboard.

Não é microserviços nem monolito clássico: é um conjunto de processos Python independentes (backend FastAPI, dois honeypots em containers, pipeline/treino como scripts CLI) que se comunicam por **arquivo compartilhado** (log JSONL de cada honeypot) e **SQLite** como fonte de verdade para o backend.

### Stack tecnológico (real, por camada)

| Camada | Tecnologias implementadas |
|---|---|
| Honeypots | Cowrie 2.x (SSH/Telnet) e Dionaea (SMB/FTP/MSSQL/MQTT/...), Docker Compose |
| Proxy/infra | Nginx, tpotinit (herdados do T-Pot CE) |
| Pipeline de dados | Python 3.11+ stdlib puro (`json`, `re`, `csv`, `datetime`, `statistics`) — sem dependências externas |
| Machine Learning | scikit-learn (`RandomForestClassifier`, `SVC`), XGBoost (opcional, via flag `--model xgboost`), `joblib` — um modelo por honeypot |
| LLM | API Anthropic (pacote `anthropic`), modelo padrão `claude-haiku-4-5` (configurável via `LLM_MODEL`) |
| Backend | FastAPI, Uvicorn, WebSocket nativo, SQLite (sem ORM), `requests` (geolocalização) |
| Frontend | React 18, Vite 5, Tailwind CSS 3, Recharts 2, React-Leaflet + Leaflet, lucide-react |
| Firewall | `iptables` (Linux) / `netsh advfirewall` (Windows) via subprocess |
| Geolocalização | `ip-api.com` (gratuito, sem chave, 45 req/min) |

> **Nota:** o repositório é um fork/derivado limpo do **T-Pot CE** (Telekom Security) — daí a presença de `tpotinit`, `docker-compose.yml` no formato T-Pot e variáveis `TPOT_*` no `.env`. Cowrie e Dionaea estão ativos; a estrutura permite adicionar outros honeypots do T-Pot no futuro seguindo o mesmo padrão usado para o Dionaea (ver seção 3.5).

### Fluxo de dados completo

```
┌─ OFFLINE (uma vez, por honeypot) ──────────────────────────────────┐
│ data_pipeline/generate_logs.py            generate_dionaea_logs.py │
│   → 4 classes, formato Cowrie               → 4 classes, formato    │
│                                                normalizado Dionaea  │
│ cowrie_logs.jsonl + labels                dionaea_logs.jsonl + lbl │
│   → extract_features.py                     → extract_dionaea_...  │
│ training_features.csv (13 features)       dionaea_training_...csv  │
│                                              (10 features)          │
│   → ml/cowrie/train.py                      → ml/dionaea/train.py  │
│     (RF/SVM/XGBoost, CV 5-fold, F1-macro)                           │
│ ml/cowrie/models/cowrie_rf.joblib         ml/dionaea/models/...    │
└──────────────────────────────────────────────────────────────────┘

┌─ PRODUÇÃO (tempo real, após docker compose up) ───────────────────┐
│ Cowrie (container) → cowrie.json    Dionaea (container) → dionaea.json (volumes) │
│   → backend/log_watcher.py (tail contínuo, uma instância por honeypot)           │
│   → evento de fim de sessão → backend/classifier.py | dionaea_classifier.py      │
│       extrai features → predict_proba (modelo carregado)                        │
│       ├─ backend/database.py  → SQLite (data/beeia.db, campo honeypot)          │
│       ├─ backend/geo.py       → geolocaliza IP (ip-api.com)                     │
│       ├─ backend/firewall.py  → bloqueia se confiança ≥ 95%                     │
│       ├─ backend/llm.py       → relatório sob demanda (GET /api/report)         │
│       └─ WebSocket /ws        → broadcast para o dashboard                       │
│                                        ↓                                          │
│                          frontend/ (React + Vite)                                │
│                          Overview · AttackFeed · Charts · GeoMap · Report         │
└──────────────────────────────────────────────────────────────────┘
```

---

## 3. Processos e Funcionalidades Implementadas

### 3.1 `data_pipeline/` — geração e processamento de dados

| Arquivo | Função |
|---|---|
| `generate_logs.py` | Gera sessões sintéticas realistas em JSONL, formato idêntico ao Cowrie real, cobrindo 4 classes de ataque. |
| `extract_features.py` | Agrupa eventos por `session_id`, extrai as 13 features numéricas → CSV. Funciona tanto com logs sintéticos quanto reais (`data/cowrie/log/cowrie.json`). |
| `build_dataset.py` | Orquestra os dois passos acima (`python build_dataset.py --sessions N`). |
| `generate_dionaea_logs.py` | Gera sessões sintéticas no formato normalizado do Dionaea (JSONL), cobrindo 4 classes de ataque. |
| `extract_dionaea_features.py` | Agrupa eventos por `session`, extrai as 10 features numéricas do Dionaea → CSV. |
| `build_dionaea_dataset.py` | Orquestra os dois passos acima para o Dionaea. |

**Classes de ataque sintetizadas (Cowrie):** `brute_force`, `command_injection`, `recon`, `malware_download`.
**Classes de ataque sintetizadas (Dionaea):** `port_scan`, `service_probe`, `exploit_attempt`, `malware_download`.

**13 features do Cowrie:** `login_attempt_count`, `login_success`, `unique_usernames`, `unique_passwords`, `session_duration_s`, `command_count`, `avg_login_interval_ms`, `min_login_interval_ms`, `has_wget_curl`, `has_reverse_shell`, `has_recon_commands`, `has_file_download`, `command_rate_per_min`.

**10 features do Dionaea:** `connection_count`, `unique_ports`, `unique_protocols`, `session_duration_s`, `avg_connection_interval_ms`, `min_connection_interval_ms`, `has_shellcode`, `has_download`, `payload_size_avg`, `login_attempt_count`.

> O Dionaea real trata cada conexão como um objeto isolado — o BeeIA normaliza isso agrupando, sob um único `session`, as conexões de um mesmo IP numa janela curta. Ver [`Docs/Process/12-honeypot-dionaea.md`](Docs/Process/12-honeypot-dionaea.md).

### 3.2 `ml/cowrie/` e `ml/dionaea/` — treinamento dos classificadores

Ambos os `train.py` implementam e comparam **três algoritmos** (`--model rf|svm|xgboost`, padrão `rf`): `RandomForestClassifier` (n_estimators=300, max_features="sqrt"), `SVC` (kernel RBF, probability=True), `XGBClassifier` (opcional, requer `xgboost` instalado). Fazem split 80/20 estratificado, validação cruzada 5-fold com métrica F1-macro, treinam o modelo final, exibem matriz de confusão e importância de features, e salvam `<honeypot>_rf.joblib` + `<honeypot>_rf_meta.json`.

> Estrutura de pastas paralelas por honeypot (`ml/<honeypot>/`) — validada na prática com a adição do Dionaea. Um novo honeypot segue o mesmo padrão.

### 3.3 `backend/` — API FastAPI (núcleo de processamento)

| Arquivo | Responsabilidade |
|---|---|
| `main.py` | Entry point. Rotas REST, endpoint WebSocket, lifecycle (`lifespan`): inicializa SQLite, carrega modelo ML do Cowrie, tenta carregar o do Dionaea (best-effort), inicia os `LogWatcher` em threads paralelas. Callbacks `_on_session`/`_on_dionaea_session` delegam a um helper comum `_finalize_attack`. |
| `log_watcher.py` | Classe genérica reutilizada pelos dois honeypots — tail contínuo de um log JSONL; agrupa eventos por `session_id`; dispara classificação no evento de fim de sessão configurado na instância (`cowrie.session.closed` ou `dionaea.connection.free`). |
| `classifier.py` | Carrega `cowrie_rf.joblib`; reimplementa a extração das 13 features (independente do `data_pipeline`) para não acoplar backend a scripts offline; expõe `predict(events)` → `{attack_type, confidence, features}`. |
| `dionaea_classifier.py` | Mesmo padrão, carregando `dionaea_rf.joblib` e reimplementando as 10 features do Dionaea. |
| `database.py` | SQLite puro, tabelas `attacks` (campo `honeypot` identifica a origem; superconjunto de colunas comportamentais dos dois honeypots) e `blocked_ips`. Migração automática via `ALTER TABLE` em `init()` para bancos criados antes da integração do Dionaea. |
| `firewall.py` | Detecta SO e executa `iptables` (Linux) ou `netsh advfirewall` (Windows); bloqueio automático quando confiança ≥ `AUTO_BLOCK_THRESHOLD` (padrão 0.95, configurável via `.env`). |
| `geo.py` | Geolocalização via `ip-api.com`; cache em memória; rate limit de 1.4s entre chamadas; ignora IPs privados. |
| `llm.py` | Usa a API da Anthropic (`ANTHROPIC_API_KEY`, `LLM_MODEL` padrão `claude-haiku-4-5`) para gerar relatório a partir de `database.get_report_data()`. Sem a chave configurada, `/api/report` retorna 503. |
| `auth.py` | API key compartilhada (`BEEIA_API_KEY`) exigida em toda rota REST (`api_router`) e no WS (`ws_key_is_valid`). Sem a variável, roda sem autenticação (modo dev). |
| `ratelimit.py` | `RateLimiter` em memória por IP — 60 req/min global, 5/10min em `/api/report`. |

> **Segurança (adicionado em 2026-07-29):** por padrão, antes disso, o backend não tinha autenticação, CORS aberto (`*`) nem rate limit — qualquer um alcançando a API podia bloquear/desbloquear IPs arbitrários ou esgotar a cota da Anthropic via `/api/report`. Agora exige `BEEIA_API_KEY` (defesa em profundidade — a chave fica embutida no bundle do frontend, então não substitui controle de acesso à página) e restringe CORS via `CORS_ORIGINS`. A camada que efetivamente restringe quem chega ao dashboard é um proxy reverso com Basic Auth (`docker/nginx/dist/conf/beeia.conf`, porta 64298, reaproveita as credenciais `WEB_USER` do T-Pot) — ver [`md-usotcc/proteger-dashboard.md`](md-usotcc/proteger-dashboard.md). **Os honeypots (Cowrie/Dionaea) continuam feitos para ficar públicos — só o dashboard/API precisavam dessa proteção.**

**Rotas REST:**

| Método | Rota | Descrição |
|---|---|---|
| GET | `/api/stats` | Totais, IPs únicos, tipo predominante, bloqueados, contagem por honeypot |
| GET | `/api/attacks` | Lista paginada (`?limit&offset&attack_type&honeypot`) |
| GET | `/api/attacks/chart` | Série temporal por hora (`?hours=24`) |
| GET | `/api/attacks/top-ips` | IPs mais ativos |
| GET | `/api/geo` | Pontos geográficos para o mapa |
| GET | `/api/blocked` | IPs bloqueados |
| GET | `/api/report` | Relatório em linguagem natural via LLM (`?hours=24`) |
| POST | `/api/block/{ip}` | Bloqueio manual |
| DELETE | `/api/block/{ip}` | Desbloqueio |
| WS | `/ws` | Eventos em tempo real (`stats`, `new_attack`, `ip_blocked`) |

### 3.4 `frontend/` — dashboard React

5 componentes implementados (ver `src/components/`): `Overview.jsx` (4 cards de métricas), `AttackFeed.jsx` (feed em tempo real, coluna de honeypot, badges por tipo, barra de confiança, bloqueio manual), `Charts.jsx` (barras empilhadas por hora + donut de distribuição), `GeoMap.jsx` (Leaflet, tile CartoDB Dark Matter, círculos proporcionais por IP), `Report.jsx` (relatório em linguagem natural via LLM, seletor de período). Hook `useWebSocket.js` gerencia conexão e reconexão automática (5s).

Fluxo: carga inicial via REST (`/api/stats`, `/api/attacks`, `/api/attacks/chart`, `/api/geo`) + atualização incremental via WebSocket + re-sync REST a cada 30s. `Report.jsx` é sob demanda (não faz parte do polling automático, custa uma chamada de API paga).

### 3.5 Infraestrutura Docker

`docker-compose.yml` (herdado da estrutura T-Pot CE): serviços `tpotinit` (init/orquestração, `network_mode: host`), `cowrie` (portas 22/23), `dionaea` (portas 21/42/69/135/443/445/1433/1723/1883/3306/5060/27017 — configuração best-effort seguindo o padrão conhecido do T-Pot CE, a validar em deploy real), `nginx` (proxy, portas 64297/64294). Configuração via `.env` (`TPOT_*`, `WEB_USER`, blackhole, persistência de logs, timezone do attack map, `ANTHROPIC_API_KEY`, `LLM_MODEL`, `COWRIE_LOG_PATH`, `DIONAEA_LOG_PATH`).

### O que **não** está implementado (apesar de aparecer no artigo)

- **Componente `HeatMap.jsx`** — o artigo cita 5 componentes do dashboard incluindo um mapa de calor; o `Report.jsx` implementado é uma funcionalidade diferente (coincide em número, não substitui o mapa de calor). Não existe rota `/api/attacks/heatmap`.
- **Validação com Red Teaming e testes com Hydra/Metasploit** — descritos no artigo (seções 5.2/5.3) como validação experimental; não há scripts, harness de teste ou evidências no repositório.
- **Exportação STIX/TAXII / integração MISP** — mencionado como trabalho futuro no artigo, não iniciado.

> Honeypot Dionaea e módulo LLM — descritos no artigo como pendentes numa versão anterior deste documento — **já estão implementados** (Dionaea em 2026-07-29, LLM em 2026-07-28).

---

## 4. Resumo Teórico e Mapeamento do Artigo (TCC)

Fonte: `Docs/TCC_SENDLER/Artigo_TCC1_ENGC_ENGT_CCO.pdf`.

### Referencial teórico (Seção 2)

- **Honeypots (2.1):** ativo de informação cujo valor está no uso não autorizado (Spitzner, 2002); ausência de tráfego legítimo reduz falsos positivos vs. IDS por assinatura. Cowrie = média/alta interatividade (emula shell SSH/Telnet completo); Dionaea = baixa/média interatividade (captura payloads via SMB/HTTP/FTP/TFTP). Integração via Docker inspirada na arquitetura T-Pot.
- **ML aplicado a segurança (2.2):** abordagem supervisionada escolhida por permitir rotulagem prévia. Três classificadores avaliados:
  - **Random Forest** — ensemble/bagging, robusto a overfitting, bom para dados tabulares de alta variância.
  - **SVM (kernel RBF)** — maximiza margem geométrica; desempenho inferior em fronteiras discretas/limiarizadas (confirmado nos resultados).
  - **XGBoost** — gradient boosting sequencial, estado da arte em benchmarks (ex. NSL-KDD).
  - Seleção do modelo final via **F1-macro sob validação cruzada** (mitiga desbalanceamento de classes).
- **Engenharia de features (2.3):** a qualidade das features é mais impactante que o algoritmo escolhido; as 13 features do BeeIA cobrem volume de login, timing de automação (<100ms), comandos de recon, wget/curl, indicadores de reverse shell.
- **LLM (2.4):** transformers treinados em corpora massivos; no BeeIA, recebe estatísticas classificadas e geraria relatórios com perfil do atacante, técnicas e recomendações de mitigação.

### Metodologia (Seção 3)

- **Cenário de testes:** organização fictícia de médio porte, DMZ exposta à internet, servidores Linux simulando SSH/SMB/HTTP — usado para orientar a geração de dados sintéticos.
- **Pipeline offline:** `generate_logs.py` → `extract_features.py` → `train.py` (80/20, CV k=5, salva melhor F1-macro em joblib) — **mapeamento 1:1 com o código real**.
- **Fluxo de produção:** Cowrie/Dionaea → `log_watcher.py` → `classifier.py`/`dionaea_classifier.py` (`predict_proba`) → SQLite + geo → confiança >95% → `iptables`. **Mapeamento 1:1 com o código real desde 2026-07-29.**

### Resultados e experimentos (Seção 5)

- Treino: 1.600 amostras (80%), teste: 400 amostras (20%).
- **F1-macro (validação cruzada):** Random Forest = 1,0000, XGBoost = 1,0000, SVM = 0,8525.
- **Modelo escolhido para produção: Random Forest** (menor custo computacional de inferência que XGBoost, apesar de empate técnico).
- Matriz de confusão do RF no teste: 100% de acerto em todas as 4 classes (sem falsos positivos/negativos) — resultado esperado de dados sintéticos bem separáveis; overlap teórico entre `recon` e `command_injection` (ambos com login bem-sucedido) seria distinguido por `has_reverse_shell` e `command_rate_per_min`.
- Features mais discriminativas no RF: `command_count` e `has_reverse_shell`.
- Testes de latência (com Hydra, Metasploit, scripts de recon): <2s da sessão até o dashboard — **não verificável no código atual** (sem harness de teste automatizado no repo).
- Red Teaming (5.3) citado como validação complementar — sem artefatos no repositório.

### Discussão (Seção 6)

- **Contribuições:** (1) integração Cowrie+Dionaea+ML+LLM em plataforma aberta; (2) comparação RF/SVM/XGBoost como baseline; (3) gerador sintético elimina cold start; (4) LLM como camada de interpretação para gestores.
- **Limitações reconhecidas pelos autores:** treino só em dados sintéticos na fase inicial; APTs podem mimetizar comportamento legítimo por longos períodos; rate limit do ip-api.com (45 req/min) pode gerar lacunas geográficas em alta volumetria.
- **Trabalhos futuros (6.3):** (a) Elasticpot; (b) active learning com dados reais; (c) TimescaleDB para séries temporais de alta volumetria; (d) exportação de IoCs em STIX/TAXII para MISP.

---

## 5. Roadmap e O que Ainda Será Implementado

Com base nas lacunas entre artigo e código, e no cronograma do projeto:

### Pendências diretas do artigo (TCC1 → TCC2)

1. ~~Integrar honeypot Dionaea~~ — **concluído em 2026-07-29**: serviço no `docker-compose.yml`, pipeline sintético e modelo próprio em `ml/dionaea/` (10 features), integração completa no backend e frontend. Detalhes em [`Docs/Process/12-honeypot-dionaea.md`](Docs/Process/12-honeypot-dionaea.md). Pendência residual: validar portas/volumes/schema do `dionaea.json` contra um deploy real (a config atual é best-effort).
2. ~~Implementar o módulo LLM~~ — **concluído em 2026-07-28**: `backend/llm.py` + rota `GET /api/report`, API Anthropic, modelo `claude-haiku-4-5` (configurável). Frontend consome via `Report.jsx`.
3. **Componente `HeatMap.jsx`** no frontend + rota `/api/attacks/heatmap` no backend (intensidade por janela temporal × categoria).
4. **Formalizar validação experimental:** scripts/harness reproduzível para os testes citados (Hydra para brute force, Metasploit para command injection, medição de latência sessão→dashboard) — hoje são apenas descritos em texto, sem artefato versionado.
5. **Retreinamento com dados reais**: fluxo já documentado para os dois honeypots (`extract_features.py`/`extract_dionaea_features.py`) mas depende de rotulagem manual ou pseudo-labels — nenhum dado real foi coletado/rotulado ainda.

### Trabalhos futuros de mais longo prazo (citados no artigo, não iniciados)

- Elasticpot (outro honeypot).
- Active learning incremental com dados reais.
- Migração de séries temporais para TimescaleDB (hoje é SQLite puro).
- Exportação de IoCs em STIX/TAXII para integração com MISP.

### Cronograma declarado (README, 2026/1)

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

> Data atual do sistema: 2026-07-29 — **todas as datas do cronograma já passaram**. Ao usar este documento, confirme com o usuário o status real de cada etapa antes de assumir que algo está pendente ou concluído; o cronograma pode estar desatualizado em relação ao andamento real do TCC (possivelmente já em fase de TCC2 ou pós-defesa).

---

## 6. Diretrizes para IAs Assistentes (Prompt de Contexto)

Ao gerar ou alterar código neste repositório, siga:

### Convenções observadas no código existente

- **Python:** sem framework de ORM no backend (SQLite acessado via `sqlite3`/queries diretas em `database.py`); scripts de `data_pipeline/` usam **apenas stdlib**, sem dependências externas — mantenha essa restrição ao editar esse módulo especificamente.
- **Features de ML:** a lista de features de cada honeypot é a mesma em dois lugares — pipeline offline (`data_pipeline/extract_<honeypot>_features.py`) e backend (`backend/<honeypot>_classifier.py`) — **qualquer feature nova precisa ser adicionada nos dois extratores** para não gerar divergência treino/inferência (data leakage já é uma preocupação citada no artigo). Cowrie e Dionaea têm listas de features **diferentes** — não misturar.
- **Modelos ML:** artefato salvo via `joblib`, incluindo o pipeline completo (modelo + encoder/scaler). Novo honeypot = nova pasta `ml/<honeypot>/` com seu próprio `train.py` e `models/` — padrão já seguido por `ml/cowrie/` e `ml/dionaea/`.
- **Frontend:** componentes funcionais React com hooks, Tailwind para estilo (tema escuro), Recharts para gráficos, Leaflet para mapas. Sem gerenciador de estado global (Redux/Zustand) — estado vive em `App.jsx` e é passado via props; WebSocket centralizado em `useWebSocket.js`.
- **API:** rotas REST simples sob `/api/*`, paginação via `limit`/`offset`, sem autenticação implementada atualmente.
- **Nomenclatura de arquivos/pastas:** em português nos READMEs e comentários de domínio (ex. "ataques", "bloqueados"), mas identificadores de código (variáveis, funções, rotas) em inglês.
- **Docker Compose:** segue convenção herdada do T-Pot CE — variáveis `TPOT_*` no `.env`, `pull_policy` controlável, volumes mapeados para `${TPOT_DATA_PATH}`. Não renomeie essas variáveis sem necessidade — quebra compatibilidade com o restante do stack T-Pot caso outros honeypots sejam adicionados depois.
- **Dados e modelos são gitignored** (`data/`, `ml/**/models/`) — nunca commitar datasets gerados ou `.joblib` treinados.
- **Segredos (`.env`) são gitignored** — desde 2026-07-28, `.env` está fora do controle de versão (havia sido commitado por engano antes disso). Use `.env.example` como template versionado, sem valores reais.

### Regras específicas

1. **Não confundir o que está no artigo com o que está implementado.** O artigo (TCC1) já descrevia Dionaea, LLM, HeatMap e Red Teaming — Dionaea e LLM foram implementados (2026-07-28/29); HeatMap e Red Teaming ainda não. Ao propor mudanças, deixe claro se está *implementando algo que o artigo já promete* ou *implementando algo novo além do artigo* — isso importa para a coerência da defesa do TCC.
2. **Priorize simplicidade e prazo curto** — é um projeto de TCC com prazos apertados, não um produto comercial. Evite abstrações prematuras (ex. ORM, filas de mensagens, microserviços) a menos que explicitamente solicitado.
3. **Mantenha o formato de log de cada honeypot idêntico entre sintético e real** — decisão de design deliberada (citada no artigo, seção 4.2, e replicada para o Dionaea) para eliminar divergência treino/produção. Alterações em `generate_logs.py`/`generate_dionaea_logs.py` devem preservar o schema de eventos assumido pelo respectivo classificador.
4. **Comunicação em português, direta e objetiva**, alinhada ao estilo dos READMEs existentes.
5. **Ao adicionar um novo honeypot:** seguir o padrão já validado com Cowrie e Dionaea — pasta `ml/<honeypot>/` própria, serviço no `docker-compose.yml`, `data_pipeline/generate_<honeypot>_logs.py` + `extract_<honeypot>_features.py`, `backend/<honeypot>_classifier.py`, nova instância de `LogWatcher` em `main.py` com `session_end_events` próprio, e extensão da tabela `attacks` em `database.py` (`_MIGRATIONS`/`_ATTACK_COLUMNS`) se houver campos novos. Não reutilizar cegamente as features de outro honeypot — cada um observa um tipo de tráfego diferente.
6. **Ao tocar em qualquer classificador:** lembre que `backend/classifier.py`/`dionaea_classifier.py` duplicam intencionalmente a lógica de extração de features do respectivo módulo em `data_pipeline/` (para o backend não depender do módulo de pipeline em produção) — mudanças em uma extração devem ser espelhadas na outra.
7. **Ao adicionar `attack_type` novo:** se o tipo for compartilhável entre honeypots (ex. `malware_download`), reaproveite a mesma string — os mapas de cor/label no frontend (`Overview.jsx`, `AttackFeed.jsx`, `Charts.jsx`, `GeoMap.jsx`) já tratam disso automaticamente. Se for exclusivo de um honeypot, adicione a entrada nos 4 arquivos (não há um módulo de constantes compartilhado — é a convenção já em uso no projeto).

---

## Documentação complementar

| Módulo | README |
|---|---|
| Pipeline de dados | [data_pipeline/README.md](data_pipeline/README.md) |
| Modelo ML (Cowrie) | [ml/cowrie/README.md](ml/cowrie/README.md) |
| Modelo ML (Dionaea) | [ml/dionaea/README.md](ml/dionaea/README.md) |
| Backend (API) | [backend/README.md](backend/README.md) |
| Frontend (Dashboard) | [frontend/README.md](frontend/README.md) |
| Documentação por processo | [Docs/Process/README.md](Docs/Process/README.md) |
| Guia: rodar Cowrie | [md-usotcc/rodar-cowrie.md](md-usotcc/rodar-cowrie.md) |
| Guia: testar via PuTTY | [md-usotcc/rodar-putty.md](md-usotcc/rodar-putty.md) |
| Artigo completo (TCC1) | [Docs/TCC_SENDLER/Artigo_TCC1_ENGC_ENGT_CCO.pdf](Docs/TCC_SENDLER/Artigo_TCC1_ENGC_ENGT_CCO.pdf) |
