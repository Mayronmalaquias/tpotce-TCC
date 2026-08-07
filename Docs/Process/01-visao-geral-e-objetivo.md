# Processo 01 — Visão Geral e Objetivo do BeeIA

## O que é

**BeeIA** — *"Análise de Ameaças em Sistemas Ciber-Físicos Usando Honeypots e Inteligência Artificial"* — é o TCC (IESB, 2026/1) de **Caio Silveira Guimarães Souza** e **Mayron Malaquias Oliveira**, orientado pelo **Prof. Pablo Coelho Ferreira**.

É um sistema de monitoramento de ameaças cibernéticas que integra quatro camadas:

1. **Honeypots** — iscas de rede que atraem e registram ataques reais: **Cowrie** (SSH/Telnet) e **Dionaea** (SMB/FTP/MSSQL/MQTT e outros serviços vulneráveis emulados, foco em captura de malware).
2. **Machine Learning** — classifica cada sessão de ataque automaticamente por tipo, com base em comportamento (não em assinaturas) — um modelo por honeypot, com features específicas para o tipo de tráfego capturado.
3. **LLM** — gera relatórios em linguagem natural (sumário executivo, análise técnica, recomendações de mitigação) a partir dos dados agregados.
4. **Dashboard em tempo real** — exibe ataques, gráficos e mapa geográfico conforme chegam.

Todas as quatro camadas descritas no artigo do TCC1 já estão implementadas no código (ver [10-limitacoes-e-trabalhos-futuros.md](10-limitacoes-e-trabalhos-futuros.md) para o que ainda falta: componente `HeatMap.jsx`, harness de testes formal e coleta de dados reais).

## Problema que resolve

- **Fadiga de alertas (alert fatigue):** um único servidor exposto à internet pode gerar milhares de eventos por hora. A sobrecarga de dados brutos inviabiliza a análise manual e eleva o risco de incidentes críticos passarem despercebidos.
- **Lacuna de contexto tático:** analistas de segurança têm dificuldade em distinguir, em tempo real, scanning automatizado (superficial) de estágios avançados de intrusão — como injeção de comandos ou reverse shells.
- **Limitação das ferramentas tradicionais:** firewalls e IDS baseados em assinatura falham diante de ataques polimórficos e de dia zero.

## Proposta de valor

- Honeypots não têm usuários legítimos nem tráfego autorizado — **qualquer interação é, por definição, hostil**. Isso reduz drasticamente falsos positivos em relação a IDS convencionais baseados em heurística/assinatura.
- A classificação por ML é **comportamental**, não depende de assinaturas conhecidas — o modelo não usa nem o IP de origem como feature, apenas o padrão de interação da sessão.
- A camada de interpretação (LLM) visa **democratizar a análise de segurança**: traduzir telemetria técnica em recomendações acionáveis para gestores sem formação técnica em segurança.

## Contexto acadêmico

- Curso: Engenharia/Ciência da Computação — Centro Universitário IESB.
- Cronograma e prazos: ver [11-cronograma-e-status.md](11-cronograma-e-status.md).
- Artigo-fonte: `Docs/TCC_SENDLER/Artigo_TCC1_ENGC_ENGT_CCO.pdf`.

## Próximo processo

Para entender como as peças se conectam tecnicamente, veja [02-arquitetura-e-fluxo-de-dados.md](02-arquitetura-e-fluxo-de-dados.md).
