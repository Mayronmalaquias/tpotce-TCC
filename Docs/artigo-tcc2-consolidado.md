# BeeIA — Documento Consolidado para o TCC2

**Análise de Ameaças em Sistemas Ciber-Físicos Usando Honeypots e Inteligência Artificial**

Caio Silveira Guimarães Souza · Mayron Malaquias Oliveira
Orientador: Prof. Pablo Coelho Ferreira, MsC — Centro Universitário IESB

---

## Como usar este documento

Consolida o conteúdo do artigo do TCC1 com tudo que foi medido depois que o
sistema entrou em produção real. Cada seção indica o que **se mantém**, o que
**precisa ser corrigido** e o que é **resultado novo**.

Três marcadores aparecem ao longo do texto:

| Marcador | Significado |
|---|---|
| ✅ **Confirmado** | O artigo já dizia isso e a medição sustenta |
| ⚠️ **Corrigir** | O artigo afirma algo que a medição contradiz — precisa mudar no texto |
| 🆕 **Novo** | Resultado que não existia no TCC1 |

> A mudança mais importante deste documento: o TCC1 fecha com F1-macro = 1,0000
> e nenhuma limitação empírica. O TCC2 fecha com um sistema em produção há
> semanas, um gap sim→real quantificado e uma conclusão corrigida sobre a
> comparação entre algoritmos. O segundo é um trabalho científico melhor,
> mesmo — e principalmente — porque os números são menores.

---

## 1. Introdução e Objetivo

✅ **Confirmado, sem alteração.**

O BeeIA integra quatro camadas: honeypots (Cowrie para SSH/Telnet, Dionaea para
SMB/MySQL/MSSQL e outros serviços), classificação por *machine learning*
baseada em comportamento, geração de relatórios por LLM e dashboard em tempo
real.

**Problema atacado:** fadiga de alertas, ausência de contexto tático para
distinguir varredura automatizada de intrusão avançada, e a limitação de
firewalls e IDS baseados em assinatura diante de ataques polimórficos.

**Proposta de valor:** honeypots não têm usuários legítimos — toda interação é,
por definição, hostil, o que reduz drasticamente o falso positivo. A
classificação é comportamental e não usa o IP de origem como feature.

---

## 2. Referencial Teórico

✅ **Confirmado, sem alteração.** Honeypots (Spitzner, 2002), classificação
supervisionada, engenharia de features e LLM como camada de interpretação.

🆕 Um ponto do referencial ganhou sustentação empírica inesperada: a afirmação
de que **a qualidade das features importa mais que a escolha do algoritmo**.
Três medições independentes convergem para isso:

1. Random Forest, SVM e XGBoost empatam dentro do desvio padrão (Seção 5.1).
2. LSTM e Transformer também empatam entre si (Seção 5.5).
3. Trocar a **representação** — de 13 features agregadas para a sequência crua
   de eventos — produz ganho maior que qualquer troca de algoritmo (Seção 5.5),
   e trocar a **origem dos dados** (sintéticos → reais) muda o desempenho por
   completo (Seção 5.6).

O algoritmo é, consistentemente, a variável que menos importa.

---

## 3. Metodologia

✅ **Confirmado:** geração sintética → extração de features → treino com
validação cruzada estratificada (k=5), seleção por F1-macro.

🆕 **Adicionado ao método:** injeção controlada de ambiguidade no gerador
sintético, parametrizada por um coeficiente de ruído contínuo `noise ∈ [0,1]`.

**Justificativa.** As quatro classes do gerador original eram separáveis por
três flags binárias:

| classe | `login_success` | `has_reverse_shell` | `has_wget_curl` |
|---|---|---|---|
| `brute_force` | 0 | 0 | 0 |
| `command_injection` | 1 | **1** | 0 |
| `malware_download` | 1 | 0 | **1** |
| `recon` | 1 | 0 | 0 |

Uma árvore de decisão de três nós resolve essa tabela. O F1 = 1,0000 relatado
no TCC1 mede a capacidade do modelo de **reconstruir o `if/else` do gerador**,
não de reconhecer ataques. O ruído injeta cinco fontes de ambiguidade que
existem no tráfego real:

1. campanhas de força bruta que efetivamente acertam a senha e encerram sem
   executar nada (ficam idênticas a um `recon` que desistiu);
2. `recon` que baixa ferramenta de enumeração via `curl` (dispara
   `has_wget_curl` sem ser download de malware);
3. injeção de comando sem *reverse shell*, usando persistência via `crontab` ou
   chave SSH (remove a feature mais discriminativa da classe);
4. *dropper* que também abre canal de retorno (caso real de botnets tipo Mirai);
5. sessões truncadas logo após o *handshake* e 5% de erro de rotulagem.

🆕 **Segunda adição ao método:** uma representação alternativa dos dados. Além
do vetor de 13 features agregadas, cada sessão passou a ser codificada também
como **sequência de eventos**, preservando ordem, ritmo e comandos executados.
Isso permite comparar features escritas à mão contra features aprendidas pelo
próprio modelo (Seção 5.5), mantendo dataset e divisão idênticos.

---

## 4. Arquitetura e Implementação

✅ **Confirmado.** Pipeline: honeypot → `log_watcher` → `classifier` → SQLite +
geolocalização → bloqueio automático via `iptables` acima do limiar de
confiança → *broadcast* WebSocket para o dashboard.

🆕 **Camadas de segurança**, ausentes no TCC1: autenticação por chave de API,
CORS restrito, *rate limiting* por IP (60 req/min global, 5 a cada 10 min na
rota do LLM, que consome cota paga) e proxy reverso com *Basic Auth* sobre TLS.

🆕 **Implantação real:** instância AWS EC2 `t3.micro` (*free tier*), quatro
containers Docker, backend como serviço `systemd`, domínio próprio com
certificado Let's Encrypt e renovação automática. Documentado em
[`Docs/Process/13-deploy-publicacao-aws.md`](Process/13-deploy-publicacao-aws.md).

Um detalhe operacional merece registro no texto por ser contraintuitivo: **o
honeypot SSH precisa da porta 22, que é a mesma do SSH administrativo real**.
A solução foi mover o `sshd` legítimo para a porta 2222, deixando a 22
inteiramente para o Cowrie.

---

## 5. Resultados

### 5.1 Comparação entre algoritmos

⚠️ **CORRIGIR — esta é a alteração mais importante do documento.**

**O que o TCC1 afirma:**

| Algoritmo | F1-macro | Explicação dada no artigo |
|---|---|---|
| Random Forest | 1,0000 | — |
| SVM | 0,8525 | *"natureza não linear e puramente tabular de algumas fronteiras de decisão; árvores particionam melhor o espaço amostral"* |
| XGBoost | 1,0000 | — |

**O que a medição mostra:** a explicação está errada. O SVM não foi prejudicado
pelo algoritmo, e sim por **ausência de normalização**. O `SVC` era instanciado
sem `StandardScaler`, enquanto as features misturam flags binárias (0/1) com
contagens que chegam a 299 (`login_attempt_count`) e durações de até 300
segundos. Como o kernel RBF mede distância euclidiana, uma única feature
dominava o espaço inteiro.

Efeito isolado da normalização, mesmo dataset e mesma semente:

| Configuração | F1-macro | Tempo |
|---|---|---|
| `SVC` sem normalização | 0,7798 | 4,2 s |
| `SVC` + `StandardScaler` | **0,9240** | **1,8 s** |

Com pré-processamento correto e dataset não trivial (ruído 0,6), **os três
algoritmos são estatisticamente indistinguíveis** ao longo de 30 execuções
independentes:

| Algoritmo | F1-macro médio | Desvio | Execuções |
|---|---|---|---|
| **SVM** | **0,9281** | 0,0056 | 30 |
| Random Forest | 0,9265 | 0,0058 | 30 |
| XGBoost | 0,9265 | 0,0063 | 30 |

As diferenças são muito menores que o desvio. E a inversão vai além da acurácia:
na busca de hiperparâmetros, o SVM foi **o mais rápido** — 2 s contra 33 s do
Random Forest e 164 s do XGBoost.

**O que muda no texto.** A escolha do Random Forest para produção **continua
correta**, justificada pelo menor custo de inferência em classificação de
sessões em tempo real. O que precisa ser reescrito é a *razão* pela qual os
outros foram preteridos: não por inferioridade do algoritmo, e sim por empate
técnico com vantagem operacional do Random Forest.

> **Por que isso importa na defesa.** Manter a versão atual deixa uma pergunta
> fácil na mão da banca: *"vocês normalizaram os dados antes de treinar o
> SVM?"*. Chegar com a correção já feita e medida transforma uma vulnerabilidade
> em demonstração de rigor.

### 5.2 Degradação controlada por ambiguidade

🆕 **Resultado novo.** Substitui o F1 = 1,0000 isolado por uma curva.

| Ruído | Random Forest | SVM | XGBoost |
|---|---|---|---|
| 0,0 | 1,0000 | 1,0000 | 1,0000 |
| 0,2 | 0,9748 | 0,9745 | 0,9756 |
| 0,4 | 0,9473 | 0,9500 | 0,9488 |
| 0,6 | 0,9231 | 0,9241 | 0,9222 |
| 0,8 | 0,9052 | 0,9047 | 0,9041 |
| 1,0 | 0,8874 | 0,8931 | 0,8897 |

Sete execuções independentes por ponto. A degradação é monotônica e suave, e os
três modelos a acompanham juntos — evidência de que a ambiguidade injetada é
progressiva e não um artefato de um algoritmo específico.

**Leitura para o texto:** o `noise = 0,0` reproduz exatamente o resultado do
TCC1, o que valida a continuidade entre os dois trabalhos. Os demais pontos
mostram que o 1,0000 não era mérito do modelo, e sim propriedade do dataset.

### 5.3 Curva de aprendizado

🆕 **Resultado novo.** Random Forest, cinco execuções por ponto, ruído 0,6.

| Sessões/classe | F1-macro | Desvio |
|---|---|---|
| 25 | 0,9086 | 0,0272 |
| 50 | 0,9128 | 0,0092 |
| 100 | 0,9239 | 0,0085 |
| 250 | 0,9252 | 0,0060 |
| 500 | 0,9237 | 0,0041 |
| 1.000 | 0,9278 | 0,0020 |

O desempenho satura entre 100 e 250 sessões por classe. Passar de 250 para
1.000 rende 0,003 de F1 — dentro do ruído. **Volume de dados não é o gargalo do
projeto**, o que reforça que o esforço deve ir para qualidade de features e
dados reais, não para gerar mais amostras sintéticas.

### 5.4 Ablação de features

🆕 **Resultado novo**, com ressalva metodológica importante.

Removendo uma feature por vez (Random Forest, ruído 0,6), apenas
`session_duration_s` apresenta impacto mensurável (**−0,0188**). As outras doze
ficam entre −0,0010 e +0,0002 — indistinguíveis de zero.

⚠️ **Este resultado não deve ser lido como "doze features são descartáveis".**
Ablação *leave-one-out* subestima importância quando há redundância: se
`command_count` e `command_rate_per_min` carregam a mesma informação, remover
uma não muda nada porque a outra cobre. A leitura correta é **redundância
mútua**. Medir a contribuição real exigiria remoção em grupos ou importância por
permutação — registrado como trabalho futuro.

### 5.5 Features aprendidas vs. features escritas à mão

🆕 **Resultado novo.** Responde a uma pergunta que o TCC1 não levanta.

**O problema.** O pipeline reduz cada sessão a 13 números agregados: quantos
logins, quantos comandos, tem `wget` sim ou não. Isso descarta o que talvez
seja a informação mais rica de um ataque — a **ordem** dos eventos, o **ritmo**
entre eles e **quais** comandos foram executados. Uma sessão é, na origem, uma
sequência:

```
connect → login.failed → login.failed → login.success
        → "uname -a" → "cat /etc/passwd" → "wget http://.../bot.sh" → closed
```

**A pergunta:** um modelo que lê a sequência crua aprende representações
melhores do que as features que escrevemos manualmente?

**Representação.** Cada evento vira uma tripla: tipo do evento (categórico),
binário invocado (`wget`, `cat`, `uname` — argumentos descartados, pois URLs e
caminhos aleatórios são ruído) e intervalo desde o evento anterior em
`log(1 + ms)`. A escala logarítmica é necessária porque os intervalos vão de
dezenas de milissegundos (automação) a dezenas de segundos (operador humano);
em escala linear o modelo enxergaria apenas os extremos.

**Protocolo.** 40.000 sessões geradas com ruído 0,6, divididas em 27.200 de
treino, 4.800 de validação e 8.000 de teste. As três abordagens usam
**exatamente o mesmo dataset e o mesmo split**, o que torna a comparação direta.

| Classe | LSTM | Transformer | Random Forest |
|---|---|---|---|
| `brute_force` | **0,9404** | 0,9356 | 0,9202 |
| `command_injection` | 0,9276 | **0,9292** | 0,9158 |
| `malware_download` | 0,9246 | **0,9257** | 0,9173 |
| `recon` | **0,9586** | 0,9585 | 0,9476 |
| **F1-macro** | **0,9378** | 0,9373 | 0,9252 |
| Acurácia | 0,9377 | 0,9373 | 0,9253 |

**Os modelos de sequência vencem** — por +0,0126 (LSTM) e +0,0121
(Transformer). A vantagem é consistente: as duas redes superam o Random Forest
em **todas as quatro classes**, não em uma isolada, o que afasta a hipótese de
variação por acaso numa classe específica.

**LSTM e Transformer empatam.** A diferença de 0,0005 é ruído — para
comparação, o próprio Random Forest varia ±0,0058 entre sementes (Seção 5.1).
Não há vencedor entre as duas arquiteturas neste problema.

**O custo é o dado decisivo:**

| Abordagem | Tempo de treino | Parâmetros |
|---|---|---|
| Random Forest | segundos | — |
| LSTM | 150 min (25 épocas) | ~350 mil |
| Transformer | 497 min (parada antecipada) | 630 mil |

O Transformer levou **3,3× mais tempo que o LSTM para chegar ao mesmo lugar**.
E o LSTM custou ordens de magnitude mais que o Random Forest para ganhar 1,3
ponto percentual.

**Interpretação para o texto.** O enquadramento honesto não é "redes neurais
venceram". É: *features aprendidas superam as manuais, mas por margem pequena e
a um custo desproporcional*. Para o BeeIA em produção — que classifica sessões
em tempo real numa instância `t3.micro` com 1 GiB de RAM — o Random Forest
continua sendo a escolha correta, agora por um motivo **medido**, não presumido.

Isso fecha de forma coerente com a Seção 5.1: lá, o pré-processamento importou
mais que o algoritmo; aqui, a representação importou mais que a arquitetura.
Ambos apontam para a mesma tese do referencial teórico — **a qualidade da
entrada pesa mais que a escolha do modelo**.

> ⚠️ **Ressalva obrigatória no texto.** É **uma execução de cada arquitetura**.
> Com o desvio conhecido do Random Forest (±0,0058), a diferença de 0,0126 é
> sugestiva mas **não estatisticamente estabelecida**. Afirmar superioridade
> exigiria repetir o treino neural com múltiplas sementes.

### 5.6 Validação com tráfego real ⭐

🆕 **Resultado novo e principal contribuição do TCC2.**

O sistema foi exposto à internet e operou por **14 dias corridos**
(22/08 a 06/09/2026). Captura do Dionaea:

| Métrica | Valor |
|---|---|
| Eventos registrados | **112.364** (nenhuma linha inválida) |
| Endereços IP atacantes distintos | **1.576** |
| Sessões após agrupamento temporal | 2.100 |
| Tentativas de login com credenciais | 24.924 |
| Binários de malware efetivamente baixados | 18 |
| Requisições DCERPC (exploração de SMB/RPC) | 13 |

Distribuição por protocolo: `smbd` 69% (porta 445), `mysqld` (3306), `mssqld`
(1433), `httpd` (443), além de FTP, PPTP, MQTT e MSRPC.

#### 5.6.1 O modelo treinado em dados sintéticos aplicado ao tráfego real

| Classe prevista | Sessões | Confiança média |
|---|---|---|
| `service_probe` | 2.083 (**99,2%**) | 0,697 |
| `port_scan` | 17 (0,8%) | 0,612 |
| `exploit_attempt` | **0** | — |
| `malware_download` | **0** | — |

**O modelo colapsa em uma única classe.** Duas das quatro classes que ele
aprendeu nunca são previstas. A confiança média cai de 1,00 para 0,70.

#### 5.6.2 Causa: deslocamento de distribuição

| Feature | Treino sintético | Tráfego real |
|---|---|---|
| `connection_count` | máx. **9** | máx. **11.004** (média 53) |
| `login_attempt_count` | máx. **1** | máx. **696** (média 11,9) |
| `has_shellcode` | 40% das amostras | **sempre 0** |
| `has_download` | 20% das amostras | 18 em 112 mil conexões |

O modelo nunca observou uma sessão com mais de nove conexões; a realidade
apresenta sessões com onze mil. Nunca observou mais de uma tentativa de login;
a realidade apresenta 696.

O caso mais grave é `has_shellcode`: presente em 40% do treino e **é o sinal que
define `exploit_attempt`**, mas estruturalmente zero na captura real, porque o
emulador de shellcode do Dionaea (tabela `emu_profiles`) não registrou nenhuma
ocorrência em 14 dias. O mesmo vale para `payload_size_avg`, que o Dionaea não
registra em lugar nenhum.

**Conclusão:** não é que o modelo erre. É que ele **não tem como acertar** duas
de suas quatro classes, porque as features que as definem não existem em
produção. Duas das dez features do vetor são indisponíveis no mundo real.

#### 5.6.3 Consequência operacional

O bloqueio automático dispara com confiança ≥ 0,95. Em 2.100 sessões reais,
**uma única** ultrapassou esse limiar. A resposta automática descrita no artigo
está, na prática, **inerte em produção** — e isso só foi descoberto porque houve
medição em ambiente real.

#### 5.6.4 A taxonomia sintética não corresponde ao tráfego real

Duas premissas do dataset original não se sustentam:

- **`port_scan` foi modelado como varredura vertical** (um IP tocando muitas
  portas). A internet realiza varredura **horizontal** — uma porta em milhares
  de alvos. No tráfego real, `unique_ports` tem percentil 99 igual a 1 e máximo
  6. A feature que define a classe praticamente não varia.
- **Não havia classe para força bruta de credenciais**, que na prática responde
  por 24.924 tentativas de login — o segundo comportamento mais frequente.

O tráfego real é nitidamente **bimodal**: `connection_count` tem mediana 1 e
percentil 90 igual a 114; `login_attempt_count` tem percentil 90 igual a 2 e
percentil 95 igual a 123. Não há distribuição contínua — há ruído de fundo de um
lado e ataque sustentado do outro. Os limiares da rotulagem foram posicionados
nesse vale, e não escolhidos arbitrariamente.

Taxonomia derivada da observação:

| Classe | Sessões | % |
|---|---|---|
| `service_probe` | 1.804 | 85,9% |
| `credential_bruteforce` | 205 | 9,8% |
| `connection_flood` | 53 | 2,5% |
| `malware_download` | 18 | 0,9% |
| `port_scan` | 11 | 0,5% |
| `exploit_attempt` | 9 | 0,4% |

#### 5.6.5 O comportamento carrega sinal real

Treinado sobre os rótulos reais, o modelo alcança **F1-macro 0,868**. Mas como
os rótulos derivam de regras sobre as próprias features, esse número é
circular — o modelo poderia estar apenas redescobrindo a heurística.

O teste decisivo: **remover as features das quais os rótulos derivam**
(`has_download` e `login_attempt_count`) e verificar se o comportamento sozinho
sustenta a classificação.

| Classe | F1 com indicador definidor | F1 só com comportamento | n |
|---|---|---|---|
| `credential_bruteforce` | 0,993 | **0,955** | 205 |
| `port_scan` | 0,957 | **0,957** | 11 |
| `connection_flood` | 0,990 | **0,933** | 53 |
| `malware_download` | 0,941 | **0,788** | 18 |
| `service_probe` | 0,996 | **0,993** | 1.804 |
| `exploit_attempt` | 0,333 | **0,333** | 9 |
| **F1-macro** | **0,868** | **0,826** | |

A queda é de apenas **0,042**.

**Este é o resultado mais importante do trabalho.** O modelo identifica força
bruta de credenciais com F1 0,955 *sem jamais observar a contagem de logins* —
aprende pelo ritmo e volume das conexões. Detecta 13 dos 18 downloads de malware
sem saber que houve download. Isso não é memorização: é **generalização**, e é
o que permite detectar um ataque novo cujo indicador explícito ainda não existe.

O resultado também aponta com precisão onde investir: **`exploit_attempt`
permanece em 0,333 nos dois cenários** (acerta 2 de 9). Não é falha de
generalização — é ausência de feature. O sinal de exploração está nas tabelas
`dcerpc*` do Dionaea, que não integram o vetor de features atual.

### 5.7 Itens do TCC1 sem artefato verificável

⚠️ **Precisam ser removidos, refeitos ou marcados como não reproduzíveis.**

O TCC1 relata testes com **Hydra** e **Metasploit** com latência inferior a 2
segundos, e validação por **Red Teaming** com equipes sem conhecimento prévio
dos limiares. Não há scripts, harness ou evidências versionadas no repositório
para nenhum dos dois. O harness experimental criado para o TCC2
(`ml/experiments/`) cobre a parte de classificação, mas não a de latência nem a
de Red Teaming.

---

## 6. Discussão

### 6.1 Contribuições

✅ **Mantidas:** integração de Cowrie, Dionaea, ML e LLM em plataforma aberta;
comparação de três classificadores como linha de base; gerador sintético que
elimina o problema de partida a frio; LLM como camada de interpretação.

🆕 **Acrescentar:**

1. **Quantificação do gap simulação→realidade** em detecção de intrusão por
   honeypot — um modelo com F1 = 1,0000 em dados sintéticos colapsa para uma
   única classe em tráfego real, com causa identificada e mensurada.
2. **Demonstração de que features comportamentais generalizam** (queda de apenas
   0,042 ao remover os indicadores definidores dos rótulos), enquanto features
   dependentes de indicador explícito não transferem.
3. **Harness experimental reproduzível** com cinco eixos de avaliação — lacuna
   que o próprio TCC1 registrava.
4. **Correção metodológica** na comparação entre algoritmos, com efeito medido
   e isolado.
5. **Comparação entre features escritas à mão e features aprendidas** por
   modelos de sequência (LSTM e Transformer) sobre eventos crus, com dataset e
   divisão idênticos — as aprendidas vencem em todas as classes, mas por margem
   pequena e a um custo de treino ordens de magnitude maior.

### 6.2 Limitações

✅ **Mantidas:** treino inicial exclusivamente sintético; APTs podem mimetizar
comportamento legítimo por longos períodos; limite de 45 requisições/minuto da
API de geolocalização.

🆕 **Acrescentar — todas medidas, não hipotéticas:**

1. **Duas das dez features do Dionaea não existem em captura real**
   (`has_shellcode`, `payload_size_avg`), impedindo estruturalmente a previsão
   de duas classes.
2. **O bloqueio automático é inerte em produção:** 1 sessão em 2.100 atinge o
   limiar de 0,95.
3. **A rotulagem de dados reais é heurística**, não *ground truth*. Uma amostra
   estratificada de 137 sessões foi separada para validação manual — ainda
   pendente.
4. **`exploit_attempt` não é detectável** com o vetor de features atual
   (F1 0,333, 2 acertos em 9).
5. **Forte desbalanceamento de classes** no tráfego real (85,9% em uma única
   classe), que exige métricas por classe — a acurácia global é enganosa.
6. **Captura de 14 dias e um único ponto de coleta**, sem variação geográfica ou
   temporal.
7. **A comparação entre features manuais e aprendidas usa uma única execução por
   arquitetura.** Dado o desvio de ±0,0058 entre sementes do Random Forest, a
   diferença de 0,0126 é sugestiva mas não estatisticamente estabelecida.
8. **Os modelos de sequência foram avaliados apenas em dados sintéticos.** O
   volume de sessões reais do Cowrie coletado até aqui é insuficiente para
   treiná-los, então não se sabe se a vantagem observada sobrevive ao tráfego
   real — justamente o cenário em que o modelo tabular já falhou (Seção 5.6).

### 6.3 Trabalhos futuros

✅ **Mantidos:** Elasticpot; *active learning* incremental; TimescaleDB para
séries temporais; exportação de IoCs em STIX/TAXII para MISP.

🆕 **Priorizados pela medição:**

1. **Features de DCERPC** para viabilizar a detecção de exploração — é o item de
   maior retorno, com alvo identificado (F1 0,333 → ?).
2. **Validação manual do gabarito** de 137 sessões, convertendo o gap sim→real
   de qualitativo em precisão e recall por classe.
3. **Retreino contínuo** com dados reais rotulados, fechando o ciclo de melhoria
   progressiva.
4. **Recalibração do limiar de bloqueio** a partir da distribuição real de
   confiança, hoje centrada em 0,70.
5. **Ablação por permutação ou em grupos**, para medir importância de features
   correlacionadas corretamente.
6. **Repetir o treino dos modelos de sequência com múltiplas sementes**, para
   converter a vantagem observada em afirmação estatística. Com o cache de
   sequências implementado, cada execução dispensa o reprocessamento do log.
7. **Avaliar os modelos de sequência em tráfego real**, assim que o volume de
   sessões do Cowrie permitir — é a pergunta que decide se a representação
   sequencial ajuda onde mais importa.

---

## 7. Correções de Software Descobertas em Produção

🆕 Seção nova. Todos os defeitos abaixo foram descobertos **por observação do
sistema em operação real**, não por inspeção de código — o que reforça o valor
metodológico de implantar de fato.

| Defeito | Efeito observado | Correção |
|---|---|---|
| Caminhos de log relativos resolvidos contra o diretório do `systemd` | O watcher vigiava caminho inexistente e dormia em silêncio; **o pipeline nunca processou um único evento em produção** | Caminho relativo passa a ser resolvido pela raiz do projeto, com aviso explícito se o arquivo não existir |
| Rotação de log pelo `tpotinit` | O watcher mantinha o descritor do arquivo antigo e parava de capturar sem emitir erro; **duas semanas de captura perdidas** | Detecção de rotação por `(st_ino, st_dev)` e por truncamento, com reabertura e registro em log |
| Esquema do Dionaea real diferente do sintético | O log real não possui campo `session`; como o agrupamento depende dele, **100% dos eventos reais eram descartados** | Extrator específico para o formato real, com sessões sintetizadas por IP e janela temporal |
| `ws://` fixo no frontend | Em página HTTPS o navegador bloqueia como conteúdo misto e o construtor lança exceção dentro do `useEffect`, derrubando a árvore React inteira — **dashboard em tela preta em produção** | Protocolo acompanha o da página (`wss://`) e o construtor foi isolado em `try/catch` |
| `SVC` sem normalização | Comparação injusta entre algoritmos e busca de hiperparâmetros que não convergia | `Pipeline(StandardScaler, SVC)` nos dois scripts de treino e no harness |
| Serviço desistia após 5 falhas | `Start request repeated too quickly` — backend permaneceu inativo por duas semanas | `StartLimitIntervalSec=0` e `RestartSec=10` |

**Lição metodológica para o texto:** cinco dos seis defeitos são invisíveis em
ambiente de desenvolvimento. Três deles produzem falha **silenciosa** — o
serviço permanece `active`, sem erro em log, capturando nada. Em segurança, um
sistema de detecção que falha em silêncio é pior que um que falha ruidosamente,
porque produz falsa sensação de cobertura.

---

## 8. Reprodutibilidade

Todos os resultados desta seção são reproduzíveis a partir do repositório:

```bash
# Dataset com ambiguidade controlada
cd data_pipeline
python build_dataset.py --sessions 500 --noise 0.6

# Suite experimental completa (~10 min)
cd ../ml/experiments
python run_experiments.py --honeypot cowrie
# -> results/report.md + results/raw_results.jsonl

# Pipeline de dados reais
cd ../../data_pipeline
python extract_dionaea_real.py --sqlite ../data/captura_real/dionaea.sqlite.1
python label_dionaea_real.py

# Modelos de sequência: LSTM, Transformer e baseline Random Forest
cd ../ml/sequence
python train.py --comparar --epocas 25 \
    --features ../../data/dataset/training_features_grande.csv
# -> resultados/comparacao.json (salvo a cada arquitetura concluída)

# Testes de regressão
cd ../..
python backend/tests/test_log_watcher.py
python backend/tests/test_sessao_sintetizada.py
```

> O treino dos modelos de sequência leva horas. O script salva o resultado ao
> concluir cada arquitetura e **retoma** o que já foi feito numa execução
> anterior, de modo que uma interrupção não custa repetir o que já rodou.

| Artefato | Caminho |
|---|---|
| Relatório experimental (379 execuções) | `ml/experiments/results/report.md` |
| Execuções brutas | `ml/experiments/results/raw_results.jsonl` |
| Rodada anterior (SVM sem normalização) | `ml/experiments/results/arquivo/` |
| Sessões reais rotuladas | `data/captura_real/dionaea_real_labeled.csv` |
| Predições do modelo sintético sobre o real | `data/captura_real/dionaea_real_predicted.csv` |
| Gabarito para validação manual | `data/captura_real/gabarito_para_revisar.csv` |
| Comparação features manuais × aprendidas | `ml/sequence/resultados/comparacao.json` |
| Checkpoints dos modelos de sequência | `ml/sequence/resultados/{lstm,transformer}.pt` |

---

## 9. Resumo das Alterações Necessárias no Texto do Artigo

| Seção | Ação |
|---|---|
| 5.1 | **Reescrever** a explicação do desempenho do SVM: normalização ausente, não limitação do algoritmo. Atualizar a tabela comparativa. |
| 5.1 | **Manter** a escolha do Random Forest, alterando a justificativa para empate técnico com vantagem de custo de inferência. |
| 5.2 e 5.3 | **Remover ou marcar** como não reproduzíveis os testes com Hydra, Metasploit e Red Teaming, na ausência de artefatos. |
| 5 (novas) | **Acrescentar** degradação por ruído, curva de aprendizado, ablação, comparação entre features manuais e aprendidas e — principal — validação com tráfego real. |
| 3 | **Acrescentar** a representação sequencial como segunda codificação dos dados, ao lado do vetor de 13 features. |
| 6.1 | **Acrescentar** as quatro contribuições novas. |
| 6.2 | **Acrescentar** as seis limitações medidas. |
| 6.3 | **Repriorizar** trabalhos futuros a partir da medição. |
| Nova seção | **Criar** a seção de defeitos descobertos em produção, com a lição sobre falha silenciosa. |
