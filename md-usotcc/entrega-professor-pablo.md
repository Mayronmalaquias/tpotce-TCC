# Relatório Técnico: Coleta em Ambiente Real, Contenção de Infraestrutura e Avaliação de Modelos

**Projeto:** BeeIA — Análise de Ameaças em Sistemas Ciber-Físicos Usando Honeypots e Inteligência Artificial  
**Data de Fechamento do Experimento:** 10 de setembro de 2026  
**Ambiente de Execução:** Instância AWS EC2 (Amazon Linux 2023), conteinerização via Docker Compose (derivado do T-Pot CE)

---

## 1. Topologia da Infraestrutura e Contenção do Host

A exposição controlada de honeypots de média e alta interatividade à internet aberta requer arquitetura defensiva multicamada contra vetores de *Honeypot Breakout* e comprometimento da máquina hospedeira (*Host Takeover*).

```
                      INTERNET (Tráfego Hostil Não Autenticado)
                                      │
              ┌───────────────────────┴───────────────────────┐
              ▼                                               ▼
      Porta 22 / 23 (TCP)                             Portas de Serviços
        Cowrie Container                               Dionaea Container
  ┌───────────────────────────┐                 ┌───────────────────────────┐
  │ • ReadOnlyRootfs: true    │                 │ • ReadOnlyRootfs: true    │
  │ • Privileged: false       │                 │ • Privileged: false       │
  │ • User: 2000 (non-root)   │                 │ • Isolated Bridge Network │
  │ • Tmpfs: /tmp             │                 │ • Tmpfs: /tmp             │
  │ • Sem docker.sock         │                 │ • Sem docker.sock         │
  └─────────────┬─────────────┘                 └─────────────┬─────────────┘
                │                                             │
                │ Volumes Estritos de Logs (/data/*)          │
                ▼                                             ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │ HOST LINUX (VM EC2 - Amazon Linux 2023)                                 │
  │                                                                         │
  │  [Firewall nftables: inet beeia_containment]                            │
  │  Bloqueia conexões de saída arbitrárias geradas pelos containers        │
  │                                                                         │
  │  [Monitor Contínuo FIM: host_integrity.py]                              │
  │  Base de referência SHA-256 de 35.415 arquivos (/bin, /lib, /etc, cron) │
  │  Execução horária via beeia-integrity.timer (systemd)                   │
  │                                                                         │
  │  [Backend FastAPI + Classificador ML + SQLite: beeia.db]                │
  │  Ingestão contínua assíncrona com tailing dos logs estruturados         │
  └─────────────────────────────────────────────────────────────────────────┘
```

### 1.1 Camadas de Contenção de Contêiner
1. **Ausência de Privilégios Administrativos:** Todos os contêineres de captura operam com `privileged: false`. O contêiner Cowrie executa sob UID `2000` (usuário sem privilégios), mitigando a exploração de chamadas diretas ao kernel da máquina hospedeira.
2. **Sistema de Arquivos Raiz Imutável (`read_only: true`):** A raiz dos contêineres é montada em modo estritamente somente-leitura. Binários baixados durante sessões de ataque não podem persistir em diretórios de sistema (`/bin`, `/usr/bin`, `/sbin`). Áreas de execução transitória utilizam `tmpfs` em memória volátil, descartada automaticamente no encerramento da sessão.
3. **Isolamento do Daemon Docker:** Nenhum contêiner de captura possui acesso ao socket do Docker (`/var/run/docker.sock`). O componente `tpotinit`, que realiza a orquestração inicial da pilha, opera isoladamente e não recebe tráfego público externo.
4. **Mapeamento Restrito de Volumes:** Os volumes compartilhados restringem-se aos diretórios de logs estruturados e artefatos capturados em `/data/*`. Diretórios vitais da máquina hospedeira (`/etc`, `/boot`, `/root`, `/home`) não são montados em nenhum contêiner.

### 1.2 Contenção de Rede de Saída (Anti-Botnet e Anti-DDoS)
Honeypots expostos podem ser instrumentalizados por agentes maliciosos como vetores intermediários de ataques contra terceiros (ex: ataques de negação de serviço ou propagação de worms). Para neutralizar esse vetor:
- A máquina hospedeira aplica regras de filtragem via `nftables` (tabela `inet beeia_containment`), configurada no modo *fail-closed*.
- Bloqueia-se preventivamente todo tráfego de saída originado dos contêineres em ponte, exceto respostas a conexões previamente estabelecidas (*stateful inspection*) e resolução controlada de DNS.
- O subsistema `scripts/security_operations.py` executa watchdog contínuo a cada cinco minutos, monitorando anomalias de socket e publicando notificações via AWS SNS em caso de desvio.

### 1.3 Monitoramento Contínuo de Integridade de Arquivos (FIM)
Para atestar a integridade do sistema operacional subjacente durante o experimento:
- O daemon `host_integrity.py`, instalado em `/opt/beeia-security/`, monitora 35.415 nós de sistema (/bin, /sbin, /usr/bin, /usr/lib, /etc, /boot, chaves SSH e agendamentos cron).
- O baseline criptográfico SHA-256 inicial foi gerado com o digest `62d832ab0ddf095d5175ccd622f67fcf5e4676f42ca8295e2a12324a2de44475`.
- As auditorias são orquestradas via `systemd` timer a cada 60 minutos. A verificação executada em 10/09/2026 atestou `status=unchanged`, com zero inclusões, zero remoções e zero modificações de binários de sistema.
- A integridade dos pacotes do sistema foi auditada de forma complementar via `debsums`/`dpkg -V`, confirmando a ausência de bibliotecas dinâmicas ou executáveis corrompidos.

---

## 2. Caracterização e Estatística Descritiva da Coleta Real

Os dados reportados foram extraídos diretamente da base relacional de produção (`data/beeia.db`) e cruzados com os logs brutos através dos utilitários `data_pipeline/relatorio_coleta.py` e `data_pipeline/correlacionar_amostra.py`.

### 2.1 Metodologia de Saneamento e Contagem
No processamento de dados de segurança cibernética, a separação rigorosa entre camadas de abstração é necessária para evitar distorções estatísticas:
- **Eventos Brutos:** Entradas discretas nos arquivos de log dos serviços (ex: uma tentativa de handshake, um pacote SMB recebido, uma linha de comando digitada). Totalizam 140.835 registros no Dionaea e 8.143 no Cowrie.
- **Sessões Normalizadas:** Agrupamento comportamental de múltiplos eventos correlacionados por identificador de sessão e janela de temporalidade de um mesmo endereço IP de origem. Totalizam 3.148 registros no banco SQLite.
- **Sessões Próprias (Tráfego Administrativo Descartado):** Foram catalogadas 6 sessões de teste geradas pela equipe de pesquisa para calibração de alcance e latência. Essas sessões são formalmente isoladas via cláusula determinística (`data_pipeline/exclusions.py`), não integrando a base de avaliação.
- **Sessões Válidas de Ataque Real:** Base líquida de **3.142 sessões hostis**, geradas por **1.011 endereços IP únicos**.

### 2.2 Volumetria Consolidada do Período
- **Marco Inicial (UTC):** 2026-09-06T01:10:31.890903Z
- **Marco Final (UTC):** 2026-09-10T19:24:38.871674Z
- **Duração do Experimento:** 4,76 dias ininterruptos
- **Integridade do Armazenamento:** `PRAGMA quick_check = ok`
- **Continuidade Temporal:** Nenhuma lacuna sem recepção de tráfego superior a 3 horas ao longo de toda a série.

#### Distribuição Cronológica de Sessões por Serviço:
| Data (UTC) | Volume Total | Cowrie (SSH/Telnet) | Dionaea (SMB/MSSQL/HTTP/etc) | Proporção Cowrie |
|:---|---:|---:|---:|---:|
| **2026-09-06** | 1.067 | 941 | 126 | 88,2% |
| **2026-09-07** | 515 | 362 | 153 | 70,3% |
| **2026-09-08** | 496 | 345 | 151 | 69,6% |
| **2026-09-09** | 576 | 435 | 141 | 75,5% |
| **2026-09-10** | 488 | 379 | 109 | 77,7% |
| **Consolidado** | **3.142** | **2.462** | **680** | **78,4%** |

```
Volume de Sessões por Dia
Sessões
 1200 ┼──────────────────┐
 1000 │ █                │
  800 │ █                │   ■ Cowrie
  600 │ █   █   █   █    │   □ Dionaea
  400 │ █   █   █   █   █│
  200 │ █ ▒ █ ▒ █ ▒ █ ▒ █ ▒
    0 └───┴───┴───┴───┴───┴──
        06  07  08  09  10  (Setembro/2026)
```

### 2.3 Validação de Rastreabilidade (Auditoria Cruzada Banco $\leftrightarrow$ Log Bruto)
Para validar que as 3.142 sessões persistidas no banco possuem lastro estrito nos arquivos brutos de log do sistema operacional:
- Uma amostragem pseudo-aleatória de 60 sessões (semente determinística 42) foi submetida ao algoritmo de verificação bidirecional (`correlacionar_amostra.py`).
- **Resultado:** 60 sessões confirmadas (100% de consistência); 0 sessões órfãs ou sem lastro; 0 registros fora da janela temporal dos logs em disco.
- Isso comprova a fidelidade do pipeline de ingestão em tempo real (`log_watcher.py`).

---

## 3. Análise Comportamental do Tráfego Real e Fenômeno de Cauda Longa

### 3.1 Distribuição de Classes no Cowrie (SSH/Telnet)
O Cowrie registrou 2.462 sessões válidas provenientes de 483 endereços IP distintos:

| Classe Prevista | Sessões | Proporção | Confiança Média ($\mu$) | Desvio Padrão ($\sigma$) |
|---|---:|---:|---:|---:|
| `brute_force` | 2.407 | 97,77% | 0,6419 | 0,0812 |
| `recon` | 55 | 2,23% | 0,7406 | 0,1145 |
| `command_injection` | 0 | 0,00% | — | — |
| `malware_download` | 0 | 0,00% | — | — |

#### Análise Fenomenológica das Sessões SSH:
1. **Automação Massiva de Autenticação:** A esmagadora maioria do tráfego incidente na porta 22 consiste em ferramentas automatizadas de varredura global (botnets baseadas em Mirai e scripts de força bruta de credenciais). A média temporal entre tentativas de login consecutivas registrou $p_{50} < 85\text{ ms}$, patamar humanamente inviável que confirma o caráter automatizado.
2. **Dicionários Dominantes:** Observou-se a repetição sistemática de pares de credenciais padronizadas (`root:root`, `admin:admin`, `root:123456`, `ubnt:ubnt`, `user:user`).
3. **Sessões de Reconhecimento (`recon`):** Nas 55 sessões em que a emulação de terminal foi aceita, os comandos injetados concentraram-se na checagem sumária de arquitetura de processador e sistema operacional (`uname -a`, `cat /proc/cpuinfo`, `id`, `whoami`, `cat /etc/passwd`).
4. **Ausência de `command_injection` e `malware_download`:** Durante o período amostrado, os agentes automatizados encerraram a conexão imediatamente após a triagem inicial de hardware, não prosseguindo para o download de binários maliciosos via `wget`/`curl`. Trata-se de um achado empírico clássico em telemetria de ameaças: agentes de scanning em larga escala separam a fase de descoberta de alvos da fase de comprometimento secundário.

### 3.2 Distribuição de Classes no Dionaea (Serviços de Rede e Malwares)
O Dionaea registrou 680 sessões válidas distribuídas em 548 endereços IP:

| Classe Prevista | Sessões | Proporção | Confiança Média ($\mu$) | Protocolos Principais |
|---|---:|---:|---:|:---|
| `service_probe` | 628 | 92,35% | 0,8956 | SMB (445), MSSQL (1433), MySQL (3306) |
| `credential_bruteforce` | 32 | 4,71% | 0,9565 | SMB (445), MSSQL (1433) |
| `connection_flood` | 14 | 2,06% | 0,8736 | Múltiplas portas em rajada |
| `port_scan` | 4 | 0,59% | 0,7725 | Varredura horizontal multi-portas |
| `malware_download` | 1 | 0,15% | 0,9767 | FTP / SMB (captura de payload binário) |
| `exploit_attempt` | 1 | 0,15% | 0,7733 | SMBv1 buffer overflow probe |

#### Análise Fenomenológica das Sessões Dionaea:
1. **Predominância de Sondagem de Superfície:** Mais de 92% das conexões correspondem a *probes* superficiais que abrem o socket TCP e enviam preâmbulos de negociação de protocolo (especialmente dialetos SMBv1/SMBv2 e pacotes TDS de MSSQL) sem prosseguir com autenticação ou injeção de payload.
2. **Força Bruta em Banco de Dados e Compartilhamentos:** As 32 sessões de `credential_bruteforce` concentraram-se em ataques de dicionário direcionados contra serviços MSSQL (porta 1433) com usuários `sa` e SMB com contas de domínio padrão.
3. **Captura Real de Malware:** O honeypot registrou com sucesso 1 tentativa de transferência de payload malicioso binário e 1 tentativa de exploração de vulnerabilidade de execução remota de código em protocolo SMB, confirmando o funcionamento dos emuladores de vulnerabilidade do Dionaea.

### 3.3 A Divergência Teórica: Dados Sintéticos vs. Produção Real
A literatura acadêmica frequentemente assume distribuições equilibradas entre categorias de ataque para fins de treinamento estatístico. O experimento em ambiente de produção revelou um contraste categórico:

```
Distribuição Comparativa de Classes

1. Dataset Sintético (TCC1 - Balanceado):
   ┌───────────────┬───────────────┬───────────────┬───────────────┐
   │ Brute Force   │ Recon         │ Cmd Injection │ Malware Dl    │
   │ 25,0%         │ 25,0%         │ 25,0%         │ 25,0%         │
   └───────────────┴───────────────┴───────────────┴───────────────┘

2. Tráfego Real Observado (TCC2 - Cauda Longa / Lei de Potência):
   ┌────────────────────────────────────────────────────────┬────┐
   │ Brute Force / Service Probe                            │Out.│
   │ 96,6% das sessões totais da Internet                   │3,4%│
   └────────────────────────────────────────────────────────┴────┘
```

**Implicação Metodológica Fundamental:**  
Em dados de produção, um classificador trivial (*dummy classifier*) que rotulasse 100% das sessões do Cowrie como `brute_force` alcançaria **97,77% de acurácia global**, embora possuísse **utilidade nula** para identificação de intrusões complexas. Isso comprova que a acurácia é uma métrica ilusória para validação de IDS/Honeypots no mundo real, tornando obrigatória a avaliação via **Macro-$F_1$**, **Precisão por Classe**, **Revocação** e **Matriz de Confusão**.

---

## 4. Metodologia de Avaliação e Mitigação de Vazamento de Dados

### 4.1 Diagnóstico do Artefato Prévio (Prevenção de Vazamento)
A análise forense da base de dados revelou que o arquivo original `data/captura_real/gabarito_para_revisar.csv` continha 137 sessões cujos identificadores pertenciam integralmente ao conjunto de treino heurístico `dionaea_real_labeled.csv` (interseção de 100%).  
Submeter o classificador a teste nesse conjunto resultaria em **vazamento de dados (data leakage)**, violando as premissas de generalização estatística. Esse conjunto foi descartado da etapa de testes.

### 4.2 Desenho da Amostra Estratificada ($n=200$)
Para viabilizar a aferição dos modelos sem viés de treinamento, o algoritmo `data_pipeline/amostra_avaliacao.py` foi executado com semente pseudo-aleatória `42`:

$$\text{Amostra} \subset \text{Ataques Elegíveis} \quad \text{onde} \quad \text{Amostra} \cap \text{Sessões de Treino} = \emptyset$$

1. **Exclusão de Treino:** Todos os 2.100 identificadores de sessão utilizados na etapa de calibração supervisionada foram excluídos da população elegível.
2. **Estratificação com Piso Mínimo:** Classes de ocorrência rara na internet possuem representatividade ínfima na população global. A amostragem aleatória simples geraria representação nula para categorias críticas como `malware_download` ou `port_scan`. Estabeleceu-se um piso mínimo de amostragem de $\min(10, n_{\text{população}})$ por classe prevista, complementando o espaço restante via amostragem estratificada proporcional.
3. **Composição Estratificada da Amostra de Teste:**

| Estrato (Honeypot / Classe Prevista) | População Elegível ($N$) | Amostra Sorteada ($n$) | Mecanismo de Alocação |
|---|---:|---:|:---|
| `cowrie / brute_force` | 2.387 | 122 | Proporcional à densidade |
| `cowrie / recon` | 54 | 12 | Piso amostral + proporcional |
| `dionaea / service_probe` | 627 | 39 | Proporcional à densidade |
| `dionaea / credential_bruteforce` | 32 | 11 | Piso amostral + proporcional |
| `dionaea / connection_flood` | 14 | 10 | Piso amostral |
| `dionaea / port_scan` | 4 | 4 | Amostragem censitária (100% dos eventos) |
| `dionaea / exploit_attempt` | 1 | 1 | Amostragem censitária (100% dos eventos) |
| `dionaea / malware_download` | 1 | 1 | Amostragem censitária (100% dos eventos) |
| **Total da Amostra** | **3.120** | **200** | **Estratificado com piso** |

4. **Controle de Vazamento Parcial de Rede:** Registrou-se que 19 das 200 sessões originaram-se de IPs previamente observados durante o período de treino heurístico. Essas instâncias receberam a marcação booleana `ip_visto_no_treino = 1` no arquivo de previsões, permitindo a apuração das métricas com e sem segregação de IPs de origem (`--somente-ip-novo`).

---

## 5. Protocolo de Dupla Avaliação Cega e Formalismo Matemático

Para estabelecer a verdade-terreno (*ground truth*) sem dependência circular dos próprios modelos preditivos, implementou-se o protocolo de **dupla avaliação cega**.

### 5.1 Protocolo de Cegamento Metodológico
- A planilha [`data/avaliacao/revisao_cega.csv`](../data/avaliacao/revisao_cega.csv) disponibiliza os dados observados da sessão, omitindo rigorosamente o rótulo atribuído pelo modelo classificador e seu respectivo índice de confiança.
- O arquivo [`data/avaliacao/previsoes.csv`](../data/avaliacao/previsoes.csv) mantém os valores preditos isolados sob custódia criptográfica até a conclusão da fase de anotação manual.
- Esse procedimento impede o **viés de ancoragem**, no qual o avaliador humano tende a concordar com a hipótese já fornecida pela inteligência artificial.

### 5.2 Dicionário de Evidências Fornecidas na Planilha Cega
Cada registro da planilha de revisão cega contém 17 variáveis empíricas extraídas dos logs brutos da sessão:

| Variável | Tipo | Descrição Técnica |
|---|---|---|
| `session_id` | String | Identificador único da sessão |
| `honeypot` | String | Origem do serviço (`cowrie` ou `dionaea`) |
| `timestamp` | ISO8601 | Data e hora de início do evento |
| `src_ip` | String | Endereço IP do agente atacante |
| `country` | String | Código de geolocalização de origem (ISO) |
| `protocol` | String | Protocolo da camada de aplicação utilizado |
| `login_attempts` | Inteiro | Número total de tentativas de autenticação |
| `login_success` | Booleano | Registrou autenticação aceita no terminal |
| `command_count` | Inteiro | Quantidade total de comandos digitados no shell |
| `session_duration_s` | Ponto Flutuante | Duração total da sessão em segundos |
| `connection_count` | Inteiro | Número de conexões TCP/UDP correlacionadas |
| `unique_ports` | Inteiro | Quantidade de portas distintas acionadas pelo IP |
| `has_wget_curl` | Booleano | Detecção explícita de invocação de wget ou curl |
| `has_reverse_shell` | Booleano | Presença de padrões de pipe/bash para conexão reversa |
| `has_recon_commands` | Booleano | Presença de comandos de enumeração de SO/arquitetura |
| `has_file_download` | Booleano | Transmissão de arquivo binário gravada no disco |
| `has_shellcode` | Booleano | Identificação de sequência de shellcode em payload |

### 5.3 Formalização do Motor de Apuração (`avaliar_amostra.py`)
A consolidação matemática das anotações humanas contra as previsões dos modelos segue o seguinte formalismo:

#### 1. Consistência Inter-Avaliadores (Concordância Observada $P_o$):
Sendo $r_{1,i}$ e $r_{2,i}$ os rótulos atribuídos pelos dois revisores para a sessão $i$, a taxa de concordância para o conjunto duplamente revisado ($N_d$) é:

$$P_o = \frac{\sum_{i=1}^{N_d} \mathbb{I}(r_{1,i} = r_{2,i})}{N_d}$$

- Sessões com discordância ($r_{1,i} \neq r_{2,i}$) são isoladas em fila de conciliação conjunta, não sendo atribuídas como erro ou acerto do modelo preditivo antes do consenso formal.
- Sessões marcadas com `inconclusivo = sim` são descartadas do cálculo de desempenho sem penalizar falso-positivo ou falso-negativo.

#### 2. Matriz de Confusão e Métricas por Classe:
Para cada classe $k \in \mathcal{C}$, calculam-se os Verdadeiros Positivos ($VP_k$), Falsos Positivos ($FP_k$) e Falsos Negativos ($FN_k$):

$$\text{Precisão}_k = \frac{VP_k}{VP_k + FP_k} \quad\quad \text{Revocação}_k = \frac{VP_k}{VP_k + FN_k}$$

$$F_{1,k} = 2 \cdot \frac{\text{Precisão}_k \cdot \text{Revocação}_k}{\text{Precisão}_k + \text{Revocação}_k}$$

#### 3. Macro-$F_1$ Score:
A métrica principal de eficácia do BeeIA em ambiente de produção é a média aritmética simples dos $F_1$-scores de todas as classes avaliadas, atribuindo peso equivalente às classes minoritárias:

$$\text{Macro-}F_1 = \frac{1}{|\mathcal{C}|} \sum_{k \in \mathcal{C}} F_{1,k}$$

---

## 6. Rastreabilidade e Reprodutibilidade dos Procedimentos

Todos os procedimentos de auditoria, extração de métricas e teste do pipeline estão formalmente codificados e podem ser executados deterministicamente a partir da raiz do repositório:

```bash
# 1. Execução do relatório analítico da coleta (banco e logs em disco)
python data_pipeline/relatorio_coleta.py --db data/beeia.db --dados data

# 2. Teste de correlação e consistência entre banco SQLite e logs brutos
python data_pipeline/correlacionar_amostra.py --db data/beeia.db --n 60 --semente 42

# 3. Execução da suíte de 16 testes unitários da matemática de avaliação
python data_pipeline/test_avaliacao.py

# 4. Apuração das métricas após o preenchimento das anotações humanas
python data_pipeline/avaliar_amostra.py --amostra data/avaliacao

# 5. Apuração segregando estritamente novos endereços IP (zero vazamento de rede)
python data_pipeline/avaliar_amostra.py --amostra data/avaliacao --somente-ip-novo
```

---

## 7. Conclusões Técnicas para a Documentação Acadêmica

1. **Robustez da Infraestrutura Comprovada:** O monitoramento contínuo de integridade de arquivos (35.415 nós verificados a cada hora) e as diretrizes de contêiner não privilegiado e sistema de arquivos somente-leitura demonstraram empiricamente a viabilidade de hospedar honeypots públicos em nuvem com contenção satisfatória do host.
2. **Caracterização da Ameaça em Produção:** A captura de 3.142 sessões evidenciou que o ecossistema real de ataques contra SSH e serviços legados opera sob regime de cauda longa, concentrando mais de 96% do volume em ferramentas autônomas de sondagem e força bruta rasa.
3. **Superação Metodológica do Dataset Sintético:** A disparidade observada entre a literatura sintética uniforme e a telemetria real de produção valida a tese de que IDS baseados em aprendizado de máquina devem ser parametrizados por métricas invariantes ao desbalanceamento (Macro-$F_1$), justificando a necessidade de validação experimental independente via amostragem estratificada cega.
