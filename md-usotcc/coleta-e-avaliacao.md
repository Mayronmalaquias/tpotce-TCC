# Período de coleta e avaliação dos classificadores — 10/09/2026

Fecha os itens 4 e 5 do plano. Os números vêm de scripts que qualquer pessoa
pode rodar de novo; nenhum foi digitado à mão a partir da tela.

```bash
python data_pipeline/relatorio_coleta.py --db data/beeia.db --dados data
python data_pipeline/correlacionar_amostra.py --db data/beeia.db --n 60
python data_pipeline/amostra_avaliacao.py --db data/beeia.db --n 200
python data_pipeline/avaliar_amostra.py --amostra data/avaliacao
```

---

## 1. Período de coleta

Medido em 10/09/2026 às 19:10 UTC, com `PRAGMA quick_check` = `ok`.

| | |
|---|---|
| Início (UTC) | 2026-09-06T01:10:31Z |
| Fim (UTC) | 2026-09-10T19:08:54Z |
| Duração | **4,75 dias** |
| Sessões no banco | 3.124 |
| Sessões próprias (nossos testes) | 6 |
| **Elegíveis para avaliação** | **3.118** |
| IPs distintos | 1.008 |

### Três contagens que não são a mesma coisa

Confundir as três é o erro mais fácil de cometer na escrita do TCC:

- **Eventos** — linhas nos logs brutos. Uma conexão, um login, um comando.
- **Sessões** — registros classificados no banco. Uma sessão agrega vários eventos.
- **Próprias** — sessões geradas pelos nossos testes de alcance. Não são
  tráfego de atacante e saem da avaliação.

O dashboard devolve no máximo 100 registros por requisição. **Esse número não é
o total do experimento** e não deve aparecer como tal em lugar nenhum.

### Distribuição

| Honeypot | Sessões | IPs distintos |
|---|---:|---:|
| Cowrie | 2.439 | 480 |
| Dionaea | 679 | 548 |

| Dia (UTC) | Total | Cowrie | Dionaea |
|---|---:|---:|---:|
| 06/09 | 1.067 | 941 | 126 |
| 07/09 | 515 | 362 | 153 |
| 08/09 | 496 | 345 | 151 |
| 09/09 | 576 | 435 | 141 |
| 10/09 | 464 | 356 | 108 |

Nenhuma lacuna acima de 3 h sem sessão. As duas interrupções registradas
(reinício da contenção às 16:48 e reboot às 17:07 de 10/09) duraram segundos e
não abriram buraco detectável na série.

### Classes previstas — isto **não** é acurácia

É o que o modelo disse, sem ninguém ter conferido:

| Honeypot | Classe prevista | Sessões | Confiança média |
|---|---|---:|---:|
| Cowrie | brute_force | 2.385 | 0,642 |
| Cowrie | recon | 54 | 0,747 |
| Dionaea | service_probe | 627 | 0,896 |
| Dionaea | credential_bruteforce | 32 | 0,957 |
| Dionaea | connection_flood | 14 | 0,874 |
| Dionaea | port_scan | 4 | 0,773 |
| Dionaea | malware_download | 1 | 0,977 |
| Dionaea | exploit_attempt | 1 | 0,773 |

**O desbalanceamento é extremo e precisa ser discutido na banca.** No Cowrie,
97,8% das sessões caíram em `brute_force`, e duas das quatro classes do modelo
(`command_injection`, `malware_download`) **nunca foram previstas**. No Dionaea,
92% caíram em `service_probe`. Um classificador que respondesse sempre a classe
majoritária teria acurácia parecida — é por isso que a avaliação da seção 3
reporta macro-F1 e matriz de confusão, e não só acurácia.

### Correlação entre banco e log bruto

Amostra aleatória de 60 sessões (semente 42), conferidas de volta no log
original: **60 confirmadas, 0 sem lastro, 0 fora da janela.** Taxa de
confirmação 100%.

O identificador difere entre os dois honeypots: o Cowrie grava o campo
`session`, e o Dionaea real não tem campo de sessão — o identificador é
sintetizado como `<ip>-<timestamp>`, então a conferência é por IP de origem.

### Limitações do período

1. **São 4,75 dias, não uma semana.** Qualquer texto que diga "uma semana de
   coleta" está errado.
2. **Os logs brutos começam em 22/08, o banco em 06/09.** Os honeypots
   capturavam desde 22/08, mas nada chegava ao banco: o `LogWatcher` agrupava
   por um campo `session` que o log real do Dionaea não tem, e descartava o
   evento em silêncio. Só há dados a partir do dia em que isso foi corrigido.
   **Duas semanas de captura não viraram dados analisáveis.**
3. **Os logs rotacionam e são apagados.** A janela reconstruível a partir do
   disco é menor que a do banco e encolhe com o tempo. Preservar cópia externa
   antes de qualquer análise é obrigatório.
4. A coleta segue ativa: qualquer número aqui envelhece. A data de corte de cada
   afirmação precisa aparecer junto dela.

---

## 2. Não existe verdade-terreno ainda

Antes de medir desempenho, é preciso dizer o que **não** dá para fazer hoje.

O modelo Dionaea foi treinado com rótulos **heurísticos**, gerados por regras em
`data_pipeline/label_dionaea_real.py` a partir das distribuições observadas — não
por revisão humana. Existe um `data/captura_real/gabarito_para_revisar.csv` com
137 sessões separadas justamente para validar essa heurística.

Duas conferências feitas em 10/09/2026:

| Verificação | Resultado |
|---|---|
| Gabarito dentro do conjunto de treino | **137 de 137 (100%)** |
| Linhas com `label_revisado` preenchido | **0** |
| Linhas com `revisor_concorda` preenchido | **0** |

Ou seja: o gabarito **não serve para avaliar o modelo** — o modelo foi treinado
exatamente naquelas sessões, com aqueles rótulos. Medir ali seria vazamento, e o
resultado sairia otimista sem significar nada. E, de qualquer forma, ninguém o
revisou ainda.

**Nenhuma métrica de acurácia, precisão, recall ou F1 sobre dados reais pode ser
reportada neste momento.** O que existe é o caminho para produzi-la, na seção
seguinte.

---

## 3. Amostra de avaliação

Sorteada em 10/09/2026 com `amostra_avaliacao.py`, semente 42.

| | |
|---|---|
| População elegível | 3.120 |
| Sessões sorteadas | **200** |
| IDs de treino excluídos | 2.100 |
| Sessões cujo IP já aparecia no treino | 19 (marcadas, não removidas) |
| Proporcional à população | **não** — piso de 10 por classe |

### Sem vazamento

Os `session_id` do treino (`real-NNNNNN`, da captura de 14 dias) e os do banco
(`<ip>-<timestamp>`) não têm nenhuma interseção: **zero sessões de treino na
amostra**. Verificado, não presumido.

Há sobreposição mais fraca: **106 dos 549 IPs** do Dionaea no banco também
aparecem no treino. Não é vazamento de sessão, mas o modelo pode ter aprendido
padrões daquele IP. Por isso cada sessão da amostra carrega
`ip_visto_no_treino`, e a apuração aceita `--somente-ip-novo` para reportar as
métricas **com e sem** esses casos. Nenhum dado foi descartado por causa disso.

### Desenho por estrato

| Honeypot / classe prevista | Na amostra | Na população |
|---|---:|---:|
| cowrie / brute_force | 122 | 2.387 |
| cowrie / recon | 12 | 54 |
| dionaea / service_probe | 39 | 627 |
| dionaea / credential_bruteforce | 11 | 32 |
| dionaea / connection_flood | 10 | 14 |
| dionaea / port_scan | 4 | 4 |
| dionaea / exploit_attempt | 1 | 1 |
| dionaea / malware_download | 1 | 1 |

O piso por classe existe para que classe rara tenha precisão e recall
calculáveis. **O preço é que a amostra deixa de ser proporcional à população**,
então as métricas por classe não se transferem direto para o total coletado. O
desenho fica gravado em `amostra.json` e a apuração repete esse aviso na saída.

Três classes (`port_scan`, `exploit_attempt`, `malware_download`) têm 4, 1 e 1
sessão na população inteira. Nenhuma métrica sobre elas será estável — o
relatório marca `suporte baixo` abaixo de 10 e isso precisa ser dito na banca em
vez de escondido atrás de uma média.

### Revisão cega

`revisao_cega.csv` traz a evidência de cada sessão — tentativas de login,
comandos, duração, portas, flags de download, shellcode e reverse shell — e
**não traz a previsão do modelo**. Isso é deliberado: quem vê o palpite antes de
decidir acaba medindo concordância com o modelo, não acerto. As previsões ficam
em `previsoes.csv`, separadas, e só se encontram com os rótulos na apuração.

Protocolo:

1. Dois revisores preenchem `rotulo_revisor1` e `rotulo_revisor2`
   independentemente, **sem abrir `previsoes.csv`**.
2. `inconclusivo` existe para sessão ambígua. Forçar rótulo inventa acerto ou
   erro; sessão inconclusiva sai do cálculo e é contada em separado.
3. Discordância entre revisores **não vira verdade**: sai do cálculo, é contada,
   e a lista de sessões em disputa aparece na saída para revisão conjunta.
4. `avaliar_amostra.py` calcula matriz de confusão, precisão, recall e F1 por
   classe, macro-F1, acurácia, e a taxa de concordância entre os revisores.

A concordância entre revisores é reportada de propósito: F1 alto sobre uma
rotulagem em que os próprios humanos discordam não sustenta conclusão.

---

## 4. O que fica pendente

1. **Rotular as 200 sessões.** É trabalho de vocês — nenhum rótulo foi gerado
   automaticamente e nenhum número de desempenho existe até isso acontecer.
2. **Decidir o que fazer com as classes que nunca são previstas.** Duas das
   quatro classes do Cowrie não apareceram uma vez sequer em 2.439 sessões. Ou o
   tráfego real não tem esses comportamentos, ou o modelo não os reconhece — a
   rotulagem manual vai distinguir os dois casos, e essa é uma das discussões
   mais fortes que o TCC pode ter.
3. **Ampliar o período** se a banca exigir uma semana cheia. Hoje são 4,75 dias.
4. Ver também [contenção e alertas](contencao-e-alertas.md) e o
   [plano de avaliação](proxima-etapa-coleta-real.md).
