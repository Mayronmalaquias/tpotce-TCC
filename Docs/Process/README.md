# Docs/Process — Índice de Processos do BeeIA

Cada arquivo nesta pasta documenta **um processo específico** do projeto BeeIA — desde a infraestrutura até a teoria por trás das decisões técnicas. Use este índice para navegar.

| # | Arquivo | Conteúdo |
|---|---|---|
| 01 | [visao-geral-e-objetivo.md](01-visao-geral-e-objetivo.md) | O que é o BeeIA, problema que resolve, proposta de valor |
| 02 | [arquitetura-e-fluxo-de-dados.md](02-arquitetura-e-fluxo-de-dados.md) | Como as partes se conectam — modo offline e modo produção |
| 03 | [honeypot-cowrie-e-infraestrutura.md](03-honeypot-cowrie-e-infraestrutura.md) | Processo de captura de ataques: Cowrie + Docker Compose |
| 04 | [pipeline-de-dados.md](04-pipeline-de-dados.md) | Processo de geração e extração de features do dataset |
| 05 | [machine-learning-treinamento.md](05-machine-learning-treinamento.md) | Processo de treino e seleção do classificador |
| 06 | [backend-api-tempo-real.md](06-backend-api-tempo-real.md) | Processo de classificação, persistência e resposta em tempo real |
| 07 | [frontend-dashboard.md](07-frontend-dashboard.md) | Processo de visualização dos ataques |
| 08 | [referencial-teorico.md](08-referencial-teorico.md) | Base teórica do artigo — honeypots, ML, LLM |
| 09 | [resultados-e-experimentos.md](09-resultados-e-experimentos.md) | Métricas, validação e resultados obtidos no artigo |
| 10 | [limitacoes-e-trabalhos-futuros.md](10-limitacoes-e-trabalhos-futuros.md) | O que falta implementar, lacunas artigo × código |
| 11 | [cronograma-e-status.md](11-cronograma-e-status.md) | Datas de entrega do TCC e status |
| 12 | [honeypot-dionaea.md](12-honeypot-dionaea.md) | Segundo honeypot: infraestrutura, pipeline, ML e integração no backend/frontend |

> Para uma visão consolidada de tudo em um único documento, veja [PROJECT_CONTEXT.md](../../PROJECT_CONTEXT.md) na raiz do repositório. Os arquivos aqui detalham cada processo individualmente; o `PROJECT_CONTEXT.md` é o resumo executivo.
