# Resultados Experimentais — BeeIA

Gerado em 2026-09-05 23:13. Total de execucoes: **379**.

Produzido por `ml/experiments/run_experiments.py`. Cada linha agrega varias
execucoes independentes — o desvio padrao vem da variacao entre seeds, nao de
uma unica rodada.

---

# Honeypot: cowrie

## Estabilidade entre seeds

Substitui o F1 unico de `train.py` por uma media com desvio real.

| Modelo | F1-macro medio | Desvio | Execucoes |
|---|---|---|---|
| rf | 0.9265 | 0.0058 | 30 |
| svm | 0.9281 | 0.0056 | 30 |
| xgboost | 0.9265 | 0.0063 | 30 |

## Degradacao por ambiguidade

`noise=0.0` reproduz o dataset original (classes separaveis por tres flags binarias, F1=1.0). Valores maiores injetam sobreposicao entre classes, sessoes truncadas e erro de rotulagem.

| Ruido | Modelo | F1-macro medio | Desvio | Execucoes |
|---|---|---|---|---|
| 0.0 | rf | 1.0000 | 0.0000 | 7 |
| 0.0 | svm | 1.0000 | 0.0000 | 7 |
| 0.0 | xgboost | 1.0000 | 0.0000 | 7 |
| 0.2 | rf | 0.9748 | 0.0024 | 7 |
| 0.2 | svm | 0.9745 | 0.0020 | 7 |
| 0.2 | xgboost | 0.9756 | 0.0024 | 7 |
| 0.4 | rf | 0.9473 | 0.0057 | 7 |
| 0.4 | svm | 0.9500 | 0.0042 | 7 |
| 0.4 | xgboost | 0.9488 | 0.0059 | 7 |
| 0.6 | rf | 0.9231 | 0.0056 | 7 |
| 0.6 | svm | 0.9241 | 0.0050 | 7 |
| 0.6 | xgboost | 0.9222 | 0.0041 | 7 |
| 0.8 | rf | 0.9052 | 0.0060 | 7 |
| 0.8 | svm | 0.9047 | 0.0039 | 7 |
| 0.8 | xgboost | 0.9041 | 0.0059 | 7 |
| 1.0 | rf | 0.8874 | 0.0050 | 7 |
| 1.0 | svm | 0.8931 | 0.0054 | 7 |
| 1.0 | xgboost | 0.8897 | 0.0043 | 7 |

## Curva de aprendizado

Quanto dado e de fato necessario para saturar o desempenho.

| Sessoes/classe | Modelo | F1-macro medio | Desvio | Execucoes |
|---|---|---|---|---|
| 25.0 | rf | 0.9086 | 0.0272 | 5 |
| 25.0 | svm | 0.8926 | 0.0269 | 5 |
| 25.0 | xgboost | 0.9029 | 0.0172 | 5 |
| 50.0 | rf | 0.9128 | 0.0092 | 5 |
| 50.0 | svm | 0.9033 | 0.0190 | 5 |
| 50.0 | xgboost | 0.9120 | 0.0085 | 5 |
| 100.0 | rf | 0.9239 | 0.0085 | 5 |
| 100.0 | svm | 0.9212 | 0.0098 | 5 |
| 100.0 | xgboost | 0.9209 | 0.0036 | 5 |
| 250.0 | rf | 0.9252 | 0.0060 | 5 |
| 250.0 | svm | 0.9277 | 0.0061 | 5 |
| 250.0 | xgboost | 0.9276 | 0.0061 | 5 |
| 500.0 | rf | 0.9237 | 0.0041 | 5 |
| 500.0 | svm | 0.9241 | 0.0052 | 5 |
| 500.0 | xgboost | 0.9237 | 0.0021 | 5 |
| 1000.0 | rf | 0.9278 | 0.0020 | 5 |
| 1000.0 | svm | 0.9311 | 0.0022 | 5 |
| 1000.0 | xgboost | 0.9292 | 0.0037 | 5 |

## Ablacao de features

Impacto no F1-macro ao remover cada feature (mais negativo = mais critica).

| Feature removida | Delta F1 medio | Desvio |
|---|---|---|
| session_duration_s | -0.0188 | 0.0057 |
| command_rate_per_min | -0.0010 | 0.0009 |
| command_count | -0.0008 | 0.0009 |
| has_reverse_shell | -0.0005 | 0.0005 |
| avg_login_interval_ms | -0.0004 | 0.0007 |
| has_file_download | -0.0003 | 0.0006 |
| has_wget_curl | -0.0001 | 0.0005 |
| unique_passwords | -0.0001 | 0.0004 |
| unique_usernames | -0.0001 | 0.0002 |
| login_success | +0.0000 | 0.0004 |
| has_recon_commands | +0.0001 | 0.0002 |
| login_attempt_count | +0.0002 | 0.0004 |
| min_login_interval_ms | +0.0002 | 0.0003 |

## Busca de hiperparametros

| Modelo | F1-macro (CV) | F1-macro (teste) | Melhores parametros |
|---|---|---|---|
| rf | 0.9345 | 0.9277 | n_estimators=500, min_samples_split=20, min_samples_leaf=2, max_features=log2, max_depth=10 |
| svm | 0.9309 | 0.9227 | svc__kernel=rbf, svc__gamma=0.01, svc__C=1000 |
| xgboost | 0.9332 | 0.9277 | subsample=0.6, n_estimators=200, max_depth=3, learning_rate=0.01, colsample_bytree=0.8 |
