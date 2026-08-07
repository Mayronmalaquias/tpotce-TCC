# Processo 09 — Resultados e Experimentos (Artigo TCC1, Seção 5)

Fonte: `Docs/TCC_SENDLER/Artigo_TCC1_ENGC_ENGT_CCO.pdf`.

## 5.1 Desempenho dos classificadores

Os três modelos (Random Forest, SVM, XGBoost) foram treinados em **1.600 amostras (80%)** e avaliados em **400 amostras de teste (20%)**.

### Comparativo de F1-macro (validação cruzada)

| Algoritmo | F1-macro |
|---|---|
| Random Forest | **1,0000** |
| SVM | 0,8525 |
| XGBoost | **1,0000** |

O comportamento inferior da SVM decorre da natureza não linear e puramente tabular de algumas fronteiras de decisão do dataset sintético — abordagens baseadas em árvores de decisão demonstram maior capacidade de particionamento do espaço amostral nesses casos.

### Modelo escolhido para produção: Random Forest

Apesar do empate técnico com XGBoost, optou-se pelo **Random Forest** devido ao seu **menor custo computacional de inferência** em comparação ao modelo sequencial do XGBoost — decisão relevante para um sistema que classifica sessões em tempo real.

### Matriz de confusão do Random Forest (400 amostras de teste)

| Real \ Predito | brute_force | cmd_injection | malware_dl | recon |
|---|---|---|---|---|
| **brute_force** | 100 | 0 | 0 | 0 |
| **cmd_injection** | 0 | 100 | 0 | 0 |
| **malware_dl** | 0 | 0 | 100 | 0 |
| **recon** | 0 | 0 | 0 | 100 |

**Acurácia geral = 1,0000; F1-macro = 1,0000.** Não foram registrados falsos positivos ou falsos negativos no conjunto de teste.

> A perfeita segregação reflete a separabilidade do **dataset sintético**. A matriz de confusão teoricamente esperada em dados mais ambíguos evidenciaria maior sobreposição entre `recon` e `command_injection` (ambas envolvem login bem-sucedido) — a distinção seria feita principalmente por `has_reverse_shell` e `command_rate_per_min`.

### Importância das features (Random Forest)

As variáveis **`command_count`** e **`has_reverse_shell`** consolidaram-se como os principais preditores para a separação das classes.

## 5.2 Validação do pipeline

Testes simulados com **Hydra** (brute force), **Metasploit** (command injection) e scripts de reconhecimento confirmaram **latência inferior a 2 segundos** da sessão até o dashboard, incluindo atualização do mapa de calor em tempo real. O bloqueio via `iptables` foi verificado com `iptables -L`.

> **Status de implementação:** não há scripts, harness de teste ou evidências desses testes versionados no repositório atual — são descritos no artigo como validação experimental realizada, mas não reproduzível diretamente a partir do código presente. Ver [10-limitacoes-e-trabalhos-futuros.md](10-limitacoes-e-trabalhos-futuros.md).

## 5.3 Validação com Red Teaming

Testes de penetração reais (Red Teaming) foram conduzidos em ambiente controlado, com equipes **sem conhecimento prévio dos limiares do sistema**, fornecendo estimativas mais conservadoras e realistas das métricas de detecção — complementando a validação sintética.

> Idem: sem artefatos versionados no repositório.

## 5.4 Relatório gerado pela LLM (exemplo ilustrativo)

> *"Sumário Executivo: No período analisado, o sistema identificou 342 tentativas de intrusão: 68% brute_force, 18% recon e 14% sofisticadas (malware download ou reverse shell). Três IPs foram bloqueados automaticamente. Recomenda-se revisão das políticas SSH e adoção de autenticação por chave pública."*

> Este relatório é um exemplo do output esperado do módulo LLM descrito na teoria (Seção 2.4) e na implementação (Seção 4.5 do artigo) — **o módulo em si não está implementado no backend**.

## Discussão — contribuições (Seção 6.1 do artigo)

1. Integração de Cowrie, Dionaea, ML e LLM em plataforma aberta.
2. Avaliação comparativa de RF, SVM e XGBoost como baseline.
3. Gerador sintético que elimina o *cold start problem*.
4. LLM como camada de interpretação contextual para gestores.

## Próximo processo

[10-limitacoes-e-trabalhos-futuros.md](10-limitacoes-e-trabalhos-futuros.md) — o que o artigo reconhece como limitação e o que ainda falta implementar no código.
