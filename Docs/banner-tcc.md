# Conteúdo do Banner — BeeIA

Texto pronto para diagramação. Formato de referência: **90 × 120 cm, retrato**,
o padrão de banner acadêmico. Leitura a 1–2 metros de distância.

> **Princípio que guiou a redação:** um banner não é o artigo reduzido. Quem
> passa lê o título, olha um número grande e decide em três segundos se para.
> Por isso o destaque central não é a arquitetura do sistema — é o achado que
> só existe porque o sistema foi exposto à internet de verdade.

---

## Cabeçalho

**Título:**

> ## Análise de Ameaças em Sistemas Ciber-Físicos Usando Honeypots e Inteligência Artificial

**Subtítulo** (menor, abaixo — é ele que diferencia o trabalho):

> ### Quando um classificador com 100% de acurácia encontra a internet real

**Autores:**

Caio Silveira Guimarães Souza · Mayron Malaquias Oliveira
Orientador: Prof. Pablo Coelho Ferreira, MsC
Centro Universitário IESB — Engenharia da Computação / Ciência da Computação — 2026

---

## 1. Introdução

Um servidor exposto à internet gera milhares de eventos por hora. Essa
sobrecarga inviabiliza a análise manual e faz incidentes críticos passarem
despercebidos. Ferramentas baseadas em assinatura ainda falham diante de
ataques polimórficos e de dia zero.

**Honeypots** são iscas de rede sem usuários legítimos: toda interação é, por
definição, hostil — o que praticamente elimina o falso positivo.

**O BeeIA** integra honeypots, classificação por aprendizado de máquina baseada
em comportamento, geração de relatórios por LLM e um painel em tempo real.

---

## 2. Objetivo

Classificar automaticamente, **em tempo real e por comportamento**, o tipo de
ataque recebido por honeypots expostos à internet — e **medir honestamente** o
quanto um modelo treinado em dados sintéticos funciona diante de tráfego
hostil real.

---

## 3. Metodologia

```
Honeypots            →  Extração        →  Classificação  →  Resposta
Cowrie (SSH/Telnet)     de features        Random Forest     Bloqueio automático
Dionaea (SMB/MySQL)     por sessão         SVM · XGBoost     Painel em tempo real
                                                             Relatório por LLM
```

**Quatro etapas:**

1. **Coleta** — dois honeypots em instância AWS EC2 exposta à internet.
2. **Features comportamentais** — 13 por sessão no Cowrie, 10 no Dionaea:
   volume e cadência de login, comandos executados, indicadores de *reverse
   shell* e download. **O endereço IP não é usado como feature.**
3. **Treino** — comparação de três classificadores com validação cruzada
   estratificada (k=5) e 30 execuções independentes.
4. **Validação em produção** — 14 dias de exposição real e comparação direta
   entre o desempenho sintético e o real.

---

## 4. Resultados

### 4.1 Os três algoritmos empatam

Com pré-processamento correto e dataset não trivial, 30 execuções:

| Algoritmo | F1-macro | Desvio |
|---|---|---|
| SVM | 0,9281 | ± 0,0056 |
| Random Forest | 0,9265 | ± 0,0058 |
| XGBoost | 0,9265 | ± 0,0063 |

> **Achado metodológico:** o SVM parecia inferior (0,78) apenas por falta de
> normalização das features. Corrigido o pré-processamento, sobe para 0,92 e
> torna-se o mais rápido a treinar. **A escolha do algoritmo importa menos que
> a preparação dos dados.**

### 4.2 O resultado central — DESTAQUE VISUAL PRINCIPAL

**Elemento gráfico sugerido: duas barras lado a lado, contraste forte.**

```
   DADOS SINTÉTICOS                    INTERNET REAL
   F1-macro = 1,0000                   99,2% das sessões
   4 classes detectadas                caem em 1 única classe
   confiança média 1,00                confiança média 0,70
                                       0 exploits detectados
```

**14 dias · 112.364 eventos · 1.576 IPs atacantes**

O modelo perfeito **colapsa** em tráfego real. Não por erro, mas porque **duas
das dez features que ele usa não existem no mundo real** — o emulador de
shellcode do honeypot não registrou uma única ocorrência em 14 dias.

**Consequência operacional:** o bloqueio automático dispara com confiança
≥ 0,95. Apenas **1 sessão em 2.100** atingiu esse limiar.

### 4.3 O comportamento generaliza

Treinado com dados reais rotulados, removendo as features de onde os rótulos
derivam — o teste que separa memorizar de aprender:

| Classe | F1 (só comportamento) |
|---|---|
| Força bruta de credenciais | **0,955** |
| Varredura de portas | 0,957 |
| Sondagem de serviço | 0,993 |
| Download de malware | 0,788 |
| Tentativa de exploração | 0,333 |

**F1-macro: 0,868 → 0,826** ao remover os indicadores explícitos — queda de
apenas 0,042.

> O modelo identifica força bruta **sem jamais observar a contagem de logins**:
> aprende pelo ritmo e volume das conexões. É isso que permite detectar um
> ataque novo, cujo indicador ainda não existe.

---

## 5. Conclusão

1. **Acurácia perfeita em dados sintéticos não significa detecção.** As classes
   do gerador eram separáveis por três variáveis binárias — o modelo
   reconstruía a regra que criou os dados.
2. **Features comportamentais transferem para o mundo real** (queda de 0,042 ao
   remover indicadores explícitos); features dependentes de indicador não.
3. **Implantar de verdade revelou o que a inspeção de código não revelou:**
   cinco defeitos críticos, três deles de **falha silenciosa** — o serviço
   permanecia ativo, sem erro, capturando nada.
4. Em segurança, **um detector que falha em silêncio é pior que um que falha
   ruidosamente**: produz falsa sensação de cobertura.

**Trabalhos futuros:** features de DCERPC para viabilizar a detecção de
exploração (hoje em F1 0,333); validação manual do gabarito; retreino contínuo
com dados reais; recalibração do limiar de bloqueio.

---

## 6. Referências

1. SPITZNER, L. *Honeypots: Tracking Hackers*. Addison-Wesley, 2002.
2. BREIMAN, L. Random Forests. *Machine Learning*, v. 45, n. 1, 2001.
3. CHEN, T.; GUESTRIN, C. XGBoost: A Scalable Tree Boosting System. *KDD*, 2016.
4. CORTES, C.; VAPNIK, V. Support-Vector Networks. *Machine Learning*, v. 20, 1995.
5. PEDREGOSA, F. et al. Scikit-learn: Machine Learning in Python. *JMLR*, v. 12, 2011.

*Repositório e resultados reproduzíveis: github.com/Mayronmalaquias/tpotce-TCC*

---

# Notas de diagramação

## Hierarquia visual

O olho deve percorrer nesta ordem:

1. **Título** — maior elemento
2. **Bloco 4.2** — o contraste sintético × real, no centro geométrico do banner
3. **Números grandes** — `112.364`, `1.576`, `99,2%`, `1 em 2.100`
4. Restante do texto

Se o leitor parar depois do item 3, ainda saiu sabendo qual é a contribuição.

## O que ampliar

Estes números merecem corpo tipográfico grande, isolados do texto corrido:

| Número | Legenda curta |
|---|---|
| **112.364** | eventos de ataque capturados |
| **1.576** | endereços IP atacantes distintos |
| **14 dias** | de exposição real à internet |
| **99,2%** | das sessões reais em uma única classe |
| **1 / 2.100** | sessões atingiram o limiar de bloqueio |

## Figuras sugeridas (por prioridade)

1. **Barras comparativas sintético × real** — a figura mais importante. Duas
   barras, contraste cromático forte (ex.: azul × vermelho).
2. **Curva de degradação por ruído** — linha descendente de 1,0000 a 0,8874.
   Mostra visualmente que o F1 = 1,0 era propriedade do dataset, não do modelo.
3. **Diagrama do pipeline** — os quatro blocos da Seção 3, horizontal.
4. **Mapa-múndi com os IPs atacantes** — apelo visual forte; a distribuição
   geográfica dos 1.576 IPs já está no banco. Use se sobrar espaço.
5. **Captura do painel** em operação, pequena, como prova de funcionamento.

## Paleta

Coerente com o painel do sistema: fundo escuro, texto claro, um acento âmbar
(referência à abelha do nome BeeIA). Se a norma do IESB exigir fundo branco,
inverta mantendo o âmbar como acento.

## Aviso sobre densidade

O conteúdo acima já está próximo do limite de um banner. **Se faltar espaço,
corte nesta ordem:** Seção 4.1 (tabela dos três algoritmos, mantendo só a
citação), depois as referências 4 e 5, depois a Seção 1 reduzida a duas frases.

**Não corte** a Seção 4.2 nem a 4.3 — são a contribuição do trabalho.
