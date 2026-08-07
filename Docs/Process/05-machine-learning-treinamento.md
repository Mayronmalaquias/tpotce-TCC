# Processo 05 — Machine Learning: Treinamento e Seleção do Modelo

Módulo `ml/cowrie/` — modelo de ML específico para o honeypot Cowrie. Classifica cada sessão em uma de 4 categorias com base nas 13 features comportamentais extraídas em [04-pipeline-de-dados.md](04-pipeline-de-dados.md).

> Cada honeypot do projeto terá sua própria pasta dentro de `ml/` com modelo e features específicos para o tipo de tráfego que ele captura (ex.: `ml/dionaea/`, ainda não criada).

## Algoritmos avaliados

O BeeIA adota uma abordagem **multi-algoritmo**, comparando três classificadores supervisionados:

| Algoritmo | Princípio | Observação do artigo |
|---|---|---|
| **Random Forest** | Ensemble/bagging — múltiplas árvores de decisão, votação majoritária | Alta robustez a overfitting, bom para dados tabulares de alta variância |
| **SVM** (kernel RBF) | Maximiza a margem geométrica entre classes em espaço de alta dimensão | Desempenho inferior em fronteiras discretas/limiarizadas |
| **XGBoost** | Gradient boosting sequencial — cada árvore corrige erros residuais da anterior | Estado da arte em benchmarks públicos (ex. NSL-KDD) |

Implementados em `ml/cowrie/train.py` via flag `--model`:

```bash
python train.py                 # Random Forest (padrão)
python train.py --model svm     # SVM (kernel RBF, probability=True)
python train.py --model xgboost # XGBoost (requer: pip install xgboost)
```

## Processo de treino (executado por `train.py`)

1. Carrega e valida o CSV de features (`training_features.csv`).
2. Split estratificado **80% treino / 20% teste**.
3. Validação cruzada estratificada **5-fold** no conjunto de treino, métrica **F1-macro**.
4. Treino final no conjunto de treino completo + avaliação no conjunto de teste.
5. Exibe matriz de confusão e importância das features.
6. Salva o modelo em `models/`.

```bash
cd ml/cowrie
pip install -r requirements.txt
python train.py
# Opções avançadas:
python train.py --dataset ../../data/dataset/training_features.csv --seed 42
```

## Critério de seleção do modelo

A escolha usa a métrica **F1-macro sob validação cruzada**, que pondera precisão e revocação de forma equilibrada entre classes, mitigando desbalanceamento antes da implantação.

**Resultado obtido no artigo** (ver [09-resultados-e-experimentos.md](09-resultados-e-experimentos.md) para detalhes): Random Forest e XGBoost empataram com F1-macro = 1,0000; SVM ficou em 0,8525. **Random Forest foi escolhido para produção** por ter menor custo computacional de inferência que o XGBoost (modelo sequencial), apesar do empate técnico.

## Parâmetros do Random Forest (modelo de produção)

| Parâmetro | Valor | Motivo |
|---|---|---|
| `n_estimators` | 300 | Equilíbrio entre acurácia e tempo de treino |
| `max_features` | `"sqrt"` | Reduz correlação entre árvores |
| `max_depth` | `None` | Árvores crescem livremente (dados bem separáveis) |
| `min_samples_split` | 2 | Padrão |

## Saída do treino

```
models/
├── cowrie_rf.joblib          ← modelo + label encoder (carregado pelo backend)
└── cowrie_rf_meta.json       ← métricas e metadados em JSON
```

O `.joblib` contém o **pipeline completo scikit-learn** (modelo + `StandardScaler`), conforme descrito na implementação (artigo, Seção 4.3). É carregado diretamente por `backend/classifier.py` em produção.

> `ml/**/models/` está no `.gitignore` — modelos treinados nunca são commitados.

## Retreinamento com dados reais

Após o Cowrie coletar ataques reais:

```bash
# 1. Extrair features dos logs reais
cd data_pipeline
python extract_features.py   # gera ../data/dataset/real_features.csv (sem coluna 'label')

# 2. Rotular manualmente (ou usar pseudo-labels do modelo atual)
#    Editar o CSV e adicionar a coluna 'label'

# 3. Retreinar
cd ml/cowrie
python train.py --dataset ../../data/dataset/real_features.csv
```

O backend recarrega o modelo automaticamente na próxima inicialização. **Nenhum dado real foi coletado/rotulado ainda** — o modelo em produção é treinado 100% em dados sintéticos.

## Adicionar novo honeypot (padrão a seguir)

```
ml/
├── cowrie/      ← SSH/Telnet (atual)
│   ├── train.py
│   └── models/
├── dionaea/     ← malware/exploits (futuro)
│   ├── train.py
│   └── models/
└── heralding/   ← credenciais multi-protocolo (futuro)
    ├── train.py
    └── models/
```

Cada honeypot terá suas próprias features específicas para o tipo de tráfego que captura — **não reutilizar cegamente as 13 features do Cowrie**.

## Próximo processo

[06-backend-api-tempo-real.md](06-backend-api-tempo-real.md) — como o modelo `.joblib` gerado aqui é carregado e usado para classificar ataques em produção.
