"""
Treina o classificador do Dionaea com trafego REAL capturado em producao.

Diferencas em relacao a `train.py`, que usa o dataset sintetico:

1. **Origem dos dados.** Le sessoes reais rotuladas por
   `data_pipeline/label_dionaea_real.py`, e nao amostras geradas.

2. **Conjunto de features reduzido.** Usa apenas as 7 features que o backend
   consegue calcular lendo o `dionaea.json` em tempo real. Ficam de fora:

       has_download      registrado so no dionaea.sqlite, nao no JSON
       payload_size_avg  o Dionaea nao registra tamanho de payload
       has_shellcode     depende de emu_profiles, vazia em 14 dias de captura

   Treinar com features indisponiveis em producao criaria distorcao entre
   treino e execucao: o modelo aprenderia a depender de sinais que nunca
   receberia. Melhor um modelo honesto com 7 features do que um otimista com 10.

3. **Taxonomia observada.** Seis classes derivadas do trafego real, incluindo
   `credential_bruteforce` e `connection_flood`, que nao existiam no gerador
   sintetico e respondem por boa parte do trafego hostil real.

4. **Classes desbalanceadas.** `service_probe` concentra 86% das sessoes, o que
   e a realidade de um honeypot exposto. Usa `class_weight="balanced"` e
   reporta metricas por classe — acuracia global aqui e enganosa.

Uso:
    python train_real.py
    python train_real.py --dataset ../../data/captura_real/dionaea_real_labeled.csv
"""

import argparse
import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import StratifiedKFold, cross_val_predict, train_test_split
from sklearn.preprocessing import LabelEncoder

DATASET_PATH = "../../data/captura_real/dionaea_real_labeled.csv"
MODELS_DIR   = Path("models")

# Exatamente o que `backend/dionaea_classifier.py` consegue extrair do
# dionaea.json ao vivo. Qualquer mudanca aqui precisa ser espelhada la.
FEATURE_COLS = [
    "connection_count",
    "unique_ports",
    "unique_protocols",
    "session_duration_s",
    "avg_connection_interval_ms",
    "min_connection_interval_ms",
    "login_attempt_count",
]

LABEL_COL = "label"


def _secao(titulo):
    print("\n" + "=" * 58)
    print("  " + titulo)
    print("=" * 58)


def train(dataset_path, seed=42):
    _secao("1/4  Carregando sessoes reais")

    csv_path = Path(dataset_path)
    if not csv_path.exists():
        print("ERRO: nao encontrado: {}".format(csv_path), file=sys.stderr)
        print("Gere com: cd data_pipeline && python label_dionaea_real.py", file=sys.stderr)
        sys.exit(1)

    df = pd.read_csv(csv_path)
    faltando = [c for c in FEATURE_COLS + [LABEL_COL] if c not in df.columns]
    if faltando:
        print("ERRO: colunas ausentes: {}".format(faltando), file=sys.stderr)
        sys.exit(1)

    X = df[FEATURE_COLS].values.astype(float)
    le = LabelEncoder()
    y = le.fit_transform(df[LABEL_COL].values)
    classes = list(le.classes_)

    print("  Sessoes  : {}".format(len(df)))
    print("  Features : {} (apenas as disponiveis ao vivo)".format(len(FEATURE_COLS)))
    print("  Classes  : {}".format(len(classes)))
    print()
    for cls, n in df[LABEL_COL].value_counts().items():
        pct = n / len(df) * 100
        print("  {:<24} {:>5}  ({:5.1f}%)  {}".format(cls, n, pct, "#" * int(pct / 2)))

    # ── validacao cruzada sobre o conjunto inteiro ───────────────────────────
    _secao("2/4  Validacao cruzada estratificada (k=5)")

    modelo = RandomForestClassifier(
        n_estimators=300, class_weight="balanced", random_state=seed, n_jobs=-1)
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=seed)
    pred_cv = cross_val_predict(modelo, X, y, cv=cv, n_jobs=-1)

    rep_cv = classification_report(y, pred_cv, target_names=classes,
                                   output_dict=True, zero_division=0)
    print("  {:<24} {:>8} {:>8} {:>8} {:>7}".format("classe", "prec", "recall", "f1", "n"))
    for cls in classes:
        r = rep_cv[cls]
        print("  {:<24} {:>8.3f} {:>8.3f} {:>8.3f} {:>7}".format(
            cls, r["precision"], r["recall"], r["f1-score"], int(r["support"])))
    print("\n  F1-macro : {:.4f}".format(rep_cv["macro avg"]["f1-score"]))
    print("  Acuracia : {:.4f}  (enganosa: 86% das sessoes sao de uma classe)".format(
        rep_cv["accuracy"]))

    # ── treino final e avaliacao em teste separado ──────────────────────────
    _secao("3/4  Treino final (80/20 estratificado)")

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=seed)
    modelo.fit(X_tr, y_tr)
    y_pred = modelo.predict(X_te)
    rep = classification_report(y_te, y_pred, target_names=classes,
                                output_dict=True, zero_division=0)

    print("  Treino: {} sessoes  |  Teste: {} sessoes".format(len(X_tr), len(X_te)))
    print("\n  F1-macro (teste): {:.4f}".format(rep["macro avg"]["f1-score"]))
    print("\n  Matriz de confusao (linhas = real, colunas = predito):\n")
    cm = confusion_matrix(y_te, y_pred)
    largura = max(len(c) for c in classes) + 2
    print(" " * largura + "".join("{:>7}".format(c[:6]) for c in classes))
    for i, cls in enumerate(classes):
        print("{:<{w}}".format(cls, w=largura) + "".join("{:>7}".format(v) for v in cm[i]))

    print("\n  Importancia das features:\n")
    ranked = sorted(zip(FEATURE_COLS, modelo.feature_importances_),
                    key=lambda x: x[1], reverse=True)
    escala = 40 / ranked[0][1] if ranked[0][1] else 1
    for feat, imp in ranked:
        print("  {:<28} {:.4f}  {}".format(feat, imp, "#" * int(imp * escala)))

    # ── persistencia ────────────────────────────────────────────────────────
    _secao("4/4  Salvando")

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    model_path = MODELS_DIR / "dionaea_real_rf.joblib"
    meta_path  = MODELS_DIR / "dionaea_real_rf_meta.json"

    joblib.dump({"model": modelo, "label_encoder": le, "feature_cols": FEATURE_COLS},
                model_path)

    meta = {
        "honeypot": "dionaea",
        "origem_dos_dados": "captura real em producao",
        "observacao": ("Treinado apenas com as features que o backend calcula ao vivo "
                       "a partir do dionaea.json. has_download, payload_size_avg e "
                       "has_shellcode ficaram de fora por nao existirem em captura real."),
        "model_type": "rf",
        "feature_cols": FEATURE_COLS,
        "classes": classes,
        "cv_f1_macro": round(rep_cv["macro avg"]["f1-score"], 4),
        "cv_accuracy": round(rep_cv["accuracy"], 4),
        "test_f1_macro": round(rep["macro avg"]["f1-score"], 4),
        "per_class_cv": {
            cls: {
                "precision": round(rep_cv[cls]["precision"], 4),
                "recall":    round(rep_cv[cls]["recall"], 4),
                "f1":        round(rep_cv[cls]["f1-score"], 4),
                "support":   int(rep_cv[cls]["support"]),
            } for cls in classes
        },
        "total_sessoes": len(df),
        "seed": seed,
    }
    meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")

    print("  Modelo    : {}".format(model_path))
    print("  Metadados : {}".format(meta_path))
    print("\n  F1-macro (CV): {:.4f}\n".format(rep_cv["macro avg"]["f1-score"]))


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Treina o classificador do Dionaea com trafego real capturado")
    ap.add_argument("--dataset", default=DATASET_PATH)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    train(args.dataset, args.seed)
