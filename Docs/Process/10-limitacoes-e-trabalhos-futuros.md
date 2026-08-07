# Processo 10 — Limitações e Trabalhos Futuros

Este documento cruza as **limitações reconhecidas pelo artigo** (Seção 6.2) com as **lacunas reais entre o artigo e o código** identificadas por inspeção direta do repositório, e lista o roadmap declarado.

## Limitações reconhecidas no artigo (Seção 6.2)

- **Treinamento exclusivo em dados sintéticos** na fase inicial — mitigado (segundo o artigo) pelo Red Teaming.
- **Ataques APT** podem mimetizar comportamento legítimo por longos períodos, escapando da classificação comportamental por sessão.
- **Dependência do ip-api.com** impõe limite de 45 req/min, podendo gerar lacunas geográficas em cenários de alta volumetria.

## Lacunas entre o artigo e o código (verificado 2026-07-29)

O artigo (TCC1) descreve uma arquitetura mais ambiciosa do que o código atual entrega. **Isso é esperado em um TCC1** (fase de fundamentação teórica/proposta) mas é importante ter clareza do que já está pronto para a defesa e o que ainda precisa ser codificado antes do TCC2/versão final.

| Item descrito no artigo | Está no código? | Onde deveria estar |
|---|---|---|
| Honeypot Dionaea (captura de malware) | ✅ Sim (desde 2026-07-29) | `docker-compose.yml` + `ml/dionaea/` + `backend/dionaea_classifier.py` |
| Módulo LLM de relatórios em linguagem natural | ✅ Sim (desde 2026-07-28) | `backend/llm.py` + rota `GET /api/report` |
| Componente `HeatMap.jsx` (mapa de calor) | ❌ Não | `frontend/src/components/` |
| Rota `/api/attacks/heatmap` | ❌ Não | `backend/main.py` |
| Comparação RF/SVM/XGBoost | ✅ Sim (Cowrie e Dionaea) | `ml/cowrie/train.py` e `ml/dionaea/train.py --model {rf,svm,xgboost}` |
| Pipeline sintético de dados | ✅ Sim (Cowrie e Dionaea) | `data_pipeline/` |
| Classificação em tempo real + auto-bloqueio | ✅ Sim (dois honeypots) | `backend/` |
| Dashboard com feed, gráficos, mapa e relatório | ✅ Sim (5 componentes) | `frontend/` |
| Harness de teste com Hydra/Metasploit | ❌ Não | Nenhum script versionado |
| Validação com Red Teaming | ❌ Não | Nenhum artefato versionado |
| Exportação STIX/TAXII / integração MISP | ❌ Não | Trabalho futuro declarado |

> O 5º componente do frontend (`Report.jsx`) não é o `HeatMap.jsx` que o artigo descreve — são funcionalidades diferentes que coincidem em número. O mapa de calor continua pendente.

## Pendências diretas (curto prazo, antes do TCC2)

1. ~~Integrar Dionaea~~ — **concluído em 2026-07-29**: serviço no `docker-compose.yml`, pipeline sintético (`data_pipeline/generate_dionaea_logs.py` + `extract_dionaea_features.py`), modelo próprio em `ml/dionaea/` (10 features), integração completa no backend (`dionaea_classifier.py`, watcher genérico, coluna `honeypot` no banco) e no frontend (badges de novos tipos + coluna Honeypot). Detalhes em [12-honeypot-dionaea.md](12-honeypot-dionaea.md).
2. ~~Implementar o módulo LLM no backend~~ — **concluído em 2026-07-28**: `backend/llm.py` + rota `GET /api/report?hours=24`, usando a API da Anthropic (modelo `claude-haiku-4-5` por padrão, configurável via `LLM_MODEL`). Dados agregados via `database.get_report_data()`.
3. ~~Frontend não consumia `/api/report`~~ — **concluído em 2026-07-28**: `frontend/src/components/Report.jsx` consome a rota com seletor de período e tratamento de erro/loading.
4. **Componente `HeatMap.jsx`** + rota `/api/attacks/heatmap` (intensidade por janela temporal × categoria).
5. **Formalizar validação experimental**: scripts/harness reproduzível para os testes citados (Hydra, Metasploit, medição de latência sessão→dashboard) — hoje só descritos em texto, sem artefato versionado.
6. **Coleta e rotulagem de dados reais**: o fluxo de retreinamento já existe tecnicamente para os dois honeypots (`extract_features.py`/`extract_dionaea_features.py` apontando para os respectivos logs em `data/`), mas depende de rotulagem manual ou pseudo-labels — nenhum dado real foi coletado/rotulado ainda.
7. **Validar a infraestrutura Docker do Dionaea contra um deploy real** — a configuração de portas/volumes em `docker-compose.yml` é best-effort (baseada no padrão conhecido do T-Pot CE), já que o repositório não tinha nenhum resquício de config do Dionaea. Ajustar se divergir da imagem `${TPOT_REPO}/dionaea` real. Idem para o schema do `dionaea.json` assumido em `backend/dionaea_classifier.py` (ver [12-honeypot-dionaea.md](12-honeypot-dionaea.md)).

## Trabalhos futuros de mais longo prazo (Seção 6.3 do artigo)

- **Elasticpot** — outro honeypot a integrar (mesmo padrão usado para o Dionaea: pasta `ml/elasticpot/`, watcher próprio, extensão da tabela `attacks`).
- **Active learning** incremental com dados reais.
- **TimescaleDB** para séries temporais de alta volumetria (hoje é SQLite puro).
- **Exportação de IoCs em STIX/TAXII** para integração com o MISP.

## Recomendação de uso deste documento

Ao planejar a próxima etapa de desenvolvimento, verificar primeiro esta lista antes de assumir que algo do artigo já está pronto — evita retrabalho e mantém a coerência entre o que é apresentado na defesa e o que de fato roda no sistema.

## Próximo processo

[11-cronograma-e-status.md](11-cronograma-e-status.md) — prazos declarados do TCC e status atual.
