# Processo 11 — Cronograma e Status

## Cronograma declarado (README.md, 2026/1)

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

## Status observado por entrega (com base no código, 2026-07-29)

| Entrega | Status técnico observado |
|---|---|
| Documentação Inicial | ✅ Artigo TCC1 presente em `Docs/TCC_SENDLER/` |
| Infraestrutura e Honeypot | ✅ Cowrie e Dionaea funcionais via Docker Compose |
| Base de Dados e Dataset | ✅ Pipeline sintético completo para os dois honeypots (`data_pipeline/`) |
| Machine Learning | ✅ Treino RF/SVM/XGBoost implementado e comparado (um modelo por honeypot) |
| Interface e API | ✅ Backend FastAPI + frontend React funcionais, incluindo relatório via LLM |
| Relatório de Resultados | ⚠️ Métricas descritas no artigo; sem harness de teste reproduzível no repo |
| Prévia da Defesa | — (não verificável pelo código) |
| Versão Final do TCC | — (não verificável pelo código) |

> ⚠️ **Atenção:** a data atual do sistema (2026-07-29) é **posterior a todas as datas do cronograma acima**, incluindo "Versão Final do TCC" (07/06/2026). Isso sugere que o projeto já passou dessas fases — possivelmente em andamento de TCC2, pós-defesa, ou o cronograma pode estar desatualizado. **Confirmar com a dupla/orientador o status real antes de assumir que alguma entrega está pendente.**

## Equipe

| Papel | Nome | E-mail |
|---|---|---|
| Autor (Engenharia) | Mayron Malaquias Oliveira | mayron.oliveira@iesb.edu.br |
| Autora/Autor (Ciência da Computação) | Caio Silveira Guimarães Souza | caio.silveira@iesb.edu.br |
| Orientador | Prof. Pablo Coelho Ferreira, MsC | pablo.ferreira@iesb.br |

## Como manter este documento atualizado

Ao concluir uma entrega ou mudar uma data, atualizar a tabela de status acima e, se necessário, a tabela de cronograma no `README.md` da raiz do repositório para manter as duas fontes coerentes.
