"""
Classificador de ataques SSH/Telnet para o honeypot Cowrie.

Entrada : ../../data/dataset/training_features.csv
           (gerado por data_pipeline/build_dataset.py)

Saidas  : models/cowrie_<modelo>.joblib        - modelo treinado
          models/cowrie_<modelo>_meta.json     - metadados e metricas

Uso:
    python train.py                        # Random Forest (padrao)
    python train.py --model xgboost        # XGBoost (requer: pip install xgboost)
    python train.py --dataset /caminho/custom.csv --seed 7
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
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.preprocessing import LabelEncoder

from sklearn.svm import SVC

try:
    from xgboost import XGBClassifier
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

# ── configuracao ──────────────────────────────────────────────────────────────

DATASET_PATH = "../../data/dataset/training_features.csv"
MODELS_DIR   = Path("models")

# Features extraidas pelo data_pipeline/extract_features.py
FEATURE_COLS = [
    "login_attempt_count",
    "login_success",
    "unique_usernames",
    "unique_passwords",
    "session_duration_s",
    "command_count",
    "avg_login_interval_ms",
    "min_login_interval_ms",
    "has_wget_curl",
    "has_reverse_shell",
    "has_recon_commands",
    "has_file_download",
    "command_rate_per_min",
]

LABEL_COL = "label"

# ── utilidades de exibicao ────────────────────────────────────────────────────

def _print_section(title: str) -> None:
    print(f"\n{'=' * 52}")
    print(f"  {title}")
    print(f"{'=' * 52}")


def _print_confusion_matrix(cm: np.ndarray, classes: list) -> None:
    w = max(len(c) for c in classes) + 2
    header = " " * w + "".join(f"{c:>{w}}" for c in classes)
    print(header)
    for i, label in enumerate(classes):
        row = f"{label:<{w}}" + "".join(f"{v:>{w}}" for v in cm[i])
        print(row)


def _print_feature_importance(importances: np.ndarray, cols: list) -> None:
    ranked = sorted(zip(cols, importances), key=lambda x: x[1], reverse=True)
    bar_scale = 40 / ranked[0][1]
    for feat, imp in ranked:
        bar = "#" * int(imp * bar_scale)
        print(f"  {feat:<26} {imp:.4f}  {bar}")

# ── treino e avaliacao ────────────────────────────────────────────────────────

def train(dataset_path: str, model_type: str = "rf", seed: int = 42) -> None:

    # ------------------------------------------------------------------
    # 1. Carrega dados
    # ------------------------------------------------------------------
    _print_section("1/4  Carregando dataset")

    csv_path = Path(dataset_path)
    if not csv_path.exists():
        print(f"ERRO: arquivo nao encontrado: {csv_path}", file=sys.stderr)
        print("Execute primeiro: cd data_pipeline && python build_dataset.py", file=sys.stderr)
        sys.exit(1)

    df = pd.read_csv(csv_path)

    missing = [c for c in FEATURE_COLS + [LABEL_COL] if c not in df.columns]
    if missing:
        print(f"ERRO: colunas ausentes no CSV: {missing}", file=sys.stderr)
        sys.exit(1)

    X = df[FEATURE_COLS].values.astype(float)
    le = LabelEncoder()
    y = le.fit_transform(df[LABEL_COL].values)
    classes = list(le.classes_)

    print(f"  Sessoes  : {len(df)}")
    print(f"  Features : {len(FEATURE_COLS)}")
    print(f"  Classes  : {len(classes)}")
    print()
    for cls, count in df[LABEL_COL].value_counts().sort_index().items():
        pct = count / len(df) * 100
        bar = "#" * int(pct / 2)
        print(f"  {cls:<22} {count:>5}  ({pct:4.1f}%)  {bar}")

    # ------------------------------------------------------------------
    # 2. Split treino / teste estratificado (80/20)
    # ------------------------------------------------------------------
    _print_section("2/4  Split treino / teste  (80% / 20%)")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=seed
    )
    print(f"  Treino : {len(X_train)} sessoes")
    print(f"  Teste  : {len(X_test)} sessoes")

    # ------------------------------------------------------------------
    # 3. Configura modelo
    # ------------------------------------------------------------------
    _print_section(f"3/4  Treinamento  [{model_type}]")

    if model_type == "svm":
        model = SVC(
            kernel="rbf",
            C=10,
            gamma="scale",
            probability=True,
            random_state=seed,
        )
    elif model_type == "xgboost":
        if not XGBOOST_AVAILABLE:
            print("ERRO: XGBoost nao instalado.", file=sys.stderr)
            print("  Instale com: pip install xgboost", file=sys.stderr)
            sys.exit(1)
        model = XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            eval_metric="mlogloss",
            random_state=seed,
            n_jobs=-1,
            verbosity=0,
        )
    else:
        model = RandomForestClassifier(
            n_estimators=300,
            max_depth=None,
            min_samples_split=2,
            min_samples_leaf=1,
            max_features="sqrt",
            random_state=seed,
            n_jobs=-1,
        )

    # Validacao cruzada (5-fold) no conjunto de treino
    print("  Validacao cruzada 5-fold no conjunto de treino...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=seed)
    cv_f1  = cross_val_score(model, X_train, y_train, cv=cv, scoring="f1_macro",   n_jobs=-1)
    cv_acc = cross_val_score(model, X_train, y_train, cv=cv, scoring="accuracy",   n_jobs=-1)
    print(f"\n  Acuracia  CV: {cv_acc.mean():.4f}  (+/- {cv_acc.std():.4f})")
    print(f"  F1-macro  CV: {cv_f1.mean():.4f}  (+/- {cv_f1.std():.4f})")
    print(f"  Por fold    : {[round(v, 4) for v in cv_f1]}")

    # Treino final no conjunto completo de treino
    print("\n  Treinando modelo final...")
    model.fit(X_train, y_train)
    print("  Concluido.")

    # ------------------------------------------------------------------
    # 4. Avaliacao no conjunto de teste
    # ------------------------------------------------------------------
    _print_section("4/4  Avaliacao no conjunto de teste")

    y_pred   = model.predict(X_test)
    report   = classification_report(y_test, y_pred, target_names=classes, output_dict=True)
    report_s = classification_report(y_test, y_pred, target_names=classes)

    print(report_s)

    print("Matriz de confusao  (linhas = real | colunas = predito):\n")
    cm = confusion_matrix(y_test, y_pred)
    _print_confusion_matrix(cm, classes)

    if hasattr(model, "feature_importances_"):
        print("\nImportancia das features:\n")
        _print_feature_importance(model.feature_importances_, FEATURE_COLS)

    # ------------------------------------------------------------------
    # 5. Salva modelo e metadados
    # ------------------------------------------------------------------
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    prefix = f"cowrie_{model_type}"

    model_path = MODELS_DIR / f"{prefix}.joblib"
    meta_path  = MODELS_DIR / f"{prefix}_meta.json"

    joblib.dump({"model": model, "label_encoder": le, "feature_cols": FEATURE_COLS}, model_path)

    meta = {
        "honeypot":          "cowrie",
        "model_type":        model_type,
        "feature_cols":      FEATURE_COLS,
        "classes":           classes,
        "cv_f1_macro_mean":  round(float(cv_f1.mean()), 4),
        "cv_f1_macro_std":   round(float(cv_f1.std()),  4),
        "cv_acc_mean":       round(float(cv_acc.mean()), 4),
        "test_accuracy":     round(report["accuracy"], 4),
        "test_f1_macro":     round(report["macro avg"]["f1-score"], 4),
        "per_class_metrics": {
            cls: {
                "precision": round(report[cls]["precision"], 4),
                "recall":    round(report[cls]["recall"],    4),
                "f1":        round(report[cls]["f1-score"],  4),
                "support":   int(report[cls]["support"]),
            }
            for cls in classes
        },
        "train_size": len(X_train),
        "test_size":  len(X_test),
        "seed":       seed,
    }
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)

    print(f"\n{'=' * 52}")
    print(f"  Modelo salvo  : {model_path}")
    print(f"  Metadados     : {meta_path}")
    print(f"{'=' * 52}")
    print(f"\n  Acuracia final (teste) : {report['accuracy']:.4f}")
    print(f"  F1-macro  final (teste): {report['macro avg']['f1-score']:.4f}\n")


# ── entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Treina classificador de ataques SSH/Telnet para o Cowrie"
    )
    parser.add_argument(
        "--model", choices=["rf", "svm", "xgboost"], default="rf",
        help="Algoritmo: rf=Random Forest (padrao) | xgboost=XGBoost"
    )
    parser.add_argument(
        "--dataset", default=DATASET_PATH,
        help="Caminho do CSV de features (padrao: ../../data/dataset/training_features.csv)"
    )
    parser.add_argument(
        "--seed", type=int, default=42,
        help="Semente aleatoria para reproducibilidade (padrao: 42)"
    )
    args = parser.parse_args()
    train(args.dataset, args.model, args.seed)
