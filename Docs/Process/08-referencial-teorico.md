# Processo 08 — Referencial Teórico (Artigo TCC1, Seção 2)

Fonte: `Docs/TCC_SENDLER/Artigo_TCC1_ENGC_ENGT_CCO.pdf`. Este documento resume os conceitos teóricos que embasam as decisões técnicas do BeeIA.

## 2.1 Honeypots e Sistemas de Captura de Ameaças

Um honeypot é um ativo de informação cujo valor reside no **uso não autorizado, ilícito ou malicioso** de seus recursos (**Spitzner, 2002**). Diferente de sistemas de produção, honeypots não têm usuários legítimos, processos corporativos ativos ou tráfego autorizado — **qualquer interação é, por premissa operacional, classificada como anomalia ou atividade hostil**. Essa ausência de ruído operacional reduz drasticamente as taxas de falsos positivos, contornando uma das principais limitações dos IDS convencionais baseados em assinaturas ou perfis heurísticos.

Honeypots são categorizados pela taxonomia clássica de segurança segundo o **nível de interatividade**, que dita o grau de liberdade concedido ao atacante e, por consequência, o volume/profundidade dos dados coletados:

- **Cowrie** — média a alta interatividade. Emula um shell interativo Linux completo nos protocolos SSH (porta 22) e Telnet (porta 23). Permite ao atacante executar comandos, tentar elevar privilégios e explorar um sistema de arquivos simulado, capturando granularmente toda a sessão em logs JSON estruturados.
- **Dionaea** — baixa a média interatividade. Projetado para capturar payloads e artefatos maliciosos automaticamente, emulando protocolos amplamente explorados por worms e botnets (SMB, HTTP, FTP, TFTP).

A integração dessas ferramentas em ambientes isolados e conteinerizados via Docker (como na arquitetura de distribuições consolidadas, ex. **T-Pot**) viabiliza a consolidação de volumes compartilhados e o monitoramento centralizado de múltiplos vetores de ataque sem comprometer a integridade do host.

## 2.2 Machine Learning Aplicado à Segurança

A aplicação de IA em detecção de intrusões se subdivide essencialmente em abordagens **supervisionadas** e **não supervisionadas** (**Alpaydin, 2021**). No contexto de classificação de sessões de honeypot — onde padrões de ataque podem ser previamente rotulados a partir de comportamentos e assinaturas de telemetria conhecidas — a modelagem supervisionada demonstra maior adequação e estabilidade estatística.

O BeeIA adota uma abordagem de **aprendizado multi-algoritmo**, avaliando três classificadores preditivos para seleção do modelo ótimo em produção:

### Random Forest

Opera sob o princípio de **aprendizado por conjunto** (ensemble learning), construindo múltiplas árvores de decisão independentes durante o treino. A predição final baseia-se em **votação majoritária (bagging)**, o que confere alta robustez contra overfitting e excelente capacidade de lidar com dados tabulares de alta variância — típicos de logs de rede.

### SVM (Support Vector Machines)

Mapeia os vetores de entrada em um espaço de características de alta dimensionalidade por meio de funções de Kernel (**RBF** — Radial Basis Function), buscando um hiperplano de separação linear que maximize a margem geométrica entre classes. Eficaz em cenários com fronteiras de decisão complexas, mas pode apresentar desempenho subótimo em dados tabulares cujas transições de classe ocorrem de forma discreta ou limiarizada — **confirmado empiricamente nos resultados do BeeIA** (ver [09-resultados-e-experimentos.md](09-resultados-e-experimentos.md)).

### XGBoost (Extreme Gradient Boosting)

Implementa uma arquitetura avançada de **gradient boosting**, na qual árvores de decisão são treinadas de forma sequencial e iterativa — cada nova árvore é otimizada para corrigir os erros residuais de classificação das estruturas anteriores. A minimização de uma função de perda regularizada confere ao XGBoost histórico de performance de estado da arte em benchmarks públicos de segurança (ex. **NSL-KDD**).

### Critério de seleção

O BeeIA automatiza a triagem entre esses três algoritmos usando a métrica **F1-macro sob validação cruzada**, ponderando o balanço ideal entre precisão e revocação e mitigando efeitos de desbalanceamento de classes antes da implantação do pipeline definitivo de inferência.

## 2.3 Engenharia de Features para Logs de Rede

Argumenta-se que **a qualidade das features é mais impactante que a escolha do algoritmo**. Para sessões SSH, as features mais discriminativas incluem:

- Número de tentativas de login
- Intervalo mínimo entre tentativas (automação indicada por < 100 ms)
- Presença de comandos de reconhecimento
- Uso de `wget`/`curl`
- Indicadores de reverse shell

O BeeIA utiliza **13 features** derivadas dessas categorias (lista completa em [04-pipeline-de-dados.md](04-pipeline-de-dados.md)).

## 2.4 Modelos de Linguagem de Grande Escala (LLM)

Large Language Models são redes neurais de transformadores treinadas em corpora massivos de texto. No BeeIA, a LLM (planejada) receberia as estatísticas classificadas e geraria relatórios com **perfil do atacante, técnicas utilizadas e recomendações de mitigação**, tornando os dados acessíveis a gestores sem formação técnica.

> **Status de implementação:** este módulo é teórico/planejado no artigo — não existe integração de LLM no código atual. Ver [10-limitacoes-e-trabalhos-futuros.md](10-limitacoes-e-trabalhos-futuros.md).

## Referências citadas no artigo

- ALPAYDIN, Ethem. *Machine learning*. MIT Press, 2021.
- HUANG, Cheng, et al. "Automatic identification of honeypot server using machine learning techniques." *Security and Communication Networks* 2019.1 (2019): 2627608.
- TANENBAUM, Andrew S. *Redes de computadores*, 6ª edição, 2021.
- WICKHAM, Hadley. "Data analysis." *ggplot2: elegant graphics for data analysis*. Springer, 2016. 189-201.
- ZHANG, Y.; YUAN, X.; TZENG, N.-F. "Pseudo-Honeypot: Toward Efficient and Scalable Spam Sniffer." *Proc. 49th Int'l Conf on Dependable Systems and Networks*, IEEE, 2019. 435-446.
- SPITZNER, Lance. (2002) — definição clássica de honeypot.
- *Redes de Computadores e a Internet: Uma Abordagem Top-Down*.

## Próximo processo

[09-resultados-e-experimentos.md](09-resultados-e-experimentos.md) — como essa teoria se traduziu em métricas mensuradas.
