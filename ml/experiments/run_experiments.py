"""
Harness experimental do BeeIA — produz as metricas que sustentam o artigo.

Motivacao: o treino padrao (`ml/<honeypot>/train.py`) reporta F1-macro = 1.0000
com desvio 0.0000. Esse numero nao mede deteccao de ataque: as classes do
gerador sintetico sao separaveis por tres flags binarias, entao o modelo apenas
reconstroi o if/else que criou os dados. Este harness ataca isso por cinco
frentes, todas reprodutiveis e versionadas:

  seeds     - N execucoes independentes -> media +/- desvio REAL
  noise     - degradacao conforme a ambiguidade injetada no gerador
  curve     - curva de aprendizado (quanto dado e realmente necessario)
  hyper     - busca de hiperparametros (RandomizedSearchCV)
  ablation  - remocao de cada feature -> quais sustentam o resultado

Os resultados sao gravados incrementalmente em results/raw_results.jsonl, de
modo que a execucao pode ser acompanhada enquanto roda e uma interrupcao nao
perde o que ja foi medido.

Uso:
    python run_experiments.py --honeypot cowrie
    python run_experiments.py --honeypot cowrie --experiments seeds --seeds 30
    python run_experiments.py --report        # so regera o relatorio markdown
"""

import argparse
import contextlib
import io
import json
import sys
import time
import warnings
from datetime import datetime
from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score
from sklearn.model_selection import (
    RandomizedSearchCV,
    StratifiedKFold,
    cross_val_score,
    train_test_split,
)
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.svm import SVC

warnings.filterwarnings("ignore")

try:
    from xgboost import XGBClassifier
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

HERE         = Path(__file__).resolve().parent
REPO         = HERE.parent.parent
PIPELINE_DIR = REPO / "data_pipeline"
RESULTS_DIR  = HERE / "results"
RAW_PATH     = RESULTS_DIR / "raw_results.jsonl"
REPORT_PATH  = RESULTS_DIR / "report.md"
CACHE_DIR    = REPO / "data" / "experiments_cache"

sys.path.insert(0, str(PIPELINE_DIR))

# ── configuracao por honeypot ────────────────────────────────────────────────

HONEYPOTS = {
    "cowrie": {
        "features": [
            "login_attempt_count", "login_success", "unique_usernames",
            "unique_passwords", "session_duration_s", "command_count",
            "avg_login_interval_ms", "min_login_interval_ms", "has_wget_curl",
            "has_reverse_shell", "has_recon_commands", "has_file_download",
            "command_rate_per_min",
        ],
        "generator": "generate_logs",
        "extractor": "extract_features",
        "supports_noise": True,
    },
    "dionaea": {
        "features": [
            "connection_count", "unique_ports", "unique_protocols",
            "session_duration_s", "avg_connection_interval_ms",
            "min_connection_interval_ms", "has_shellcode", "has_download",
            "payload_size_avg", "login_attempt_count",
        ],
        "generator": "generate_dionaea_logs",
        "extractor": "extract_dionaea_features",
        "supports_noise": False,
    },
}

# ── modelos avaliados ────────────────────────────────────────────────────────

MODELS = ["rf", "svm", "xgboost"]


def build_model(name, seed, **overrides):
    if name == "rf":
        params = dict(n_estimators=300, max_depth=None, min_samples_split=2,
                      min_samples_leaf=1, max_features="sqrt", n_jobs=-1)
        params.update(overrides)
        return RandomForestClassifier(random_state=seed, **params)
    if name == "svm":
        # StandardScaler e obrigatorio aqui: as features vao de flags binarias
        # (0/1) a contagens na casa das centenas, e o kernel RBF usa distancia
        # euclidiana — sem normalizar, uma unica feature domina o espaco.
        # Medido neste dataset: F1 0.7798 -> 0.9240 e 2,3x mais rapido.
        # max_iter limita combinacoes patologicas (C alto + kernel poly), que
        # sem teto rodam praticamente para sempre na busca de hiperparametros.
        params = dict(kernel="rbf", C=10, gamma="scale", probability=False,
                      cache_size=500, max_iter=1_000_000)
        params.update(overrides)
        return make_pipeline(StandardScaler(), SVC(random_state=seed, **params))
    if name == "xgboost":
        if not XGBOOST_AVAILABLE:
            return None
        params = dict(n_estimators=300, max_depth=6, learning_rate=0.1,
                      subsample=0.8, colsample_bytree=0.8, n_jobs=-1,
                      eval_metric="mlogloss", verbosity=0)
        params.update(overrides)
        return XGBClassifier(random_state=seed, **params)
    raise ValueError(name)


SEARCH_SPACES = {
    "rf": {
        "n_estimators": [100, 200, 300, 500, 800],
        "max_depth": [None, 5, 10, 20, 40],
        "min_samples_split": [2, 5, 10, 20],
        "min_samples_leaf": [1, 2, 4, 8],
        "max_features": ["sqrt", "log2", None],
    },
    # prefixo `svc__` porque o modelo e um Pipeline (StandardScaler + SVC)
    "svm": {
        "svc__C": [0.1, 1, 10, 100, 1000],
        "svc__gamma": ["scale", "auto", 0.001, 0.01, 0.1],
        "svc__kernel": ["rbf", "poly", "sigmoid"],
    },
    "xgboost": {
        "n_estimators": [100, 200, 300, 500],
        "max_depth": [3, 6, 9, 12],
        "learning_rate": [0.01, 0.05, 0.1, 0.3],
        "subsample": [0.6, 0.8, 1.0],
        "colsample_bytree": [0.6, 0.8, 1.0],
    },
}

# ── dados ────────────────────────────────────────────────────────────────────

_cache = {}


def get_dataset(honeypot, sessions, seed, noise):
    """Gera (ou reaproveita do cache em disco) um dataset com os parametros dados."""
    key = (honeypot, sessions, seed, noise)
    if key in _cache:
        return _cache[key]

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    tag = "{}_s{}_seed{}_n{:.2f}".format(honeypot, sessions, seed, noise)
    csv_path = CACHE_DIR / (tag + ".csv")

    if not csv_path.exists():
        cfg = HONEYPOTS[honeypot]
        gen_mod = __import__(cfg["generator"])
        ext_mod = __import__(cfg["extractor"])
        logs   = CACHE_DIR / (tag + "_logs.jsonl")
        labels = CACHE_DIR / (tag + "_labels.csv")

        kwargs = dict(logs_path=str(logs), labels_path=str(labels),
                      sessions_per_class=sessions, seed=seed)
        if cfg["supports_noise"]:
            kwargs["noise"] = noise

        with contextlib.redirect_stdout(io.StringIO()):
            gen_mod.generate_dataset(**kwargs)
            ext_mod.extract_features(logs_path=str(logs), labels_path=str(labels),
                                     output_path=str(csv_path))
        logs.unlink(missing_ok=True)
        labels.unlink(missing_ok=True)

    df = pd.read_csv(csv_path)
    if len(_cache) < 40:          # limite de memoria
        _cache[key] = df
    return df


def to_xy(df, features):
    X = df[features].values.astype(float)
    y = LabelEncoder().fit_transform(df["label"].values)
    return X, y

# ── registro de resultados ───────────────────────────────────────────────────

def record(**row):
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    row["ts"] = datetime.now().isoformat(timespec="seconds")
    with open(RAW_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


def log(msg):
    print("[{:%H:%M:%S}] {}".format(datetime.now(), msg), flush=True)

# ── experimentos ─────────────────────────────────────────────────────────────

def evaluate(model, X, y, seed, folds=5):
    cv = StratifiedKFold(n_splits=folds, shuffle=True, random_state=seed)
    f1 = cross_val_score(model, X, y, cv=cv, scoring="f1_macro", n_jobs=-1)
    return {"cv_f1_mean": float(f1.mean()), "cv_f1_std": float(f1.std())}


def exp_seeds(hp, cfg, n_seeds, sessions, noise):
    """Media +/- desvio sobre N execucoes independentes."""
    log("[seeds] {}: {} seeds x {} modelos (ruido={})".format(hp, n_seeds, len(MODELS), noise))
    for seed in range(n_seeds):
        df = get_dataset(hp, sessions, seed, noise)
        X, y = to_xy(df, cfg["features"])
        for m in MODELS:
            model = build_model(m, seed)
            if model is None:
                continue
            t0 = time.time()
            res = evaluate(model, X, y, seed)
            record(experiment="seeds", honeypot=hp, model=m, seed=seed,
                   noise=noise, sessions=sessions,
                   elapsed_s=round(time.time() - t0, 2), **res)
        log("  seed {}/{} concluida".format(seed + 1, n_seeds))


def exp_noise(hp, cfg, levels, n_seeds, sessions):
    """Degradacao conforme a ambiguidade injetada no gerador."""
    if not cfg["supports_noise"]:
        log("[noise] {}: gerador ainda nao suporta ruido — pulando".format(hp))
        return
    log("[noise] {}: {} niveis x {} seeds".format(hp, len(levels), n_seeds))
    for noise in levels:
        for seed in range(n_seeds):
            df = get_dataset(hp, sessions, seed, noise)
            X, y = to_xy(df, cfg["features"])
            for m in MODELS:
                model = build_model(m, seed)
                if model is None:
                    continue
                res = evaluate(model, X, y, seed)
                record(experiment="noise", honeypot=hp, model=m, seed=seed,
                       noise=noise, sessions=sessions, **res)
        log("  ruido {} concluido".format(noise))


def exp_curve(hp, cfg, sizes, n_seeds, noise):
    """Curva de aprendizado: desempenho x volume de dados."""
    log("[curve] {}: {} tamanhos x {} seeds".format(hp, len(sizes), n_seeds))
    for size in sizes:
        for seed in range(n_seeds):
            df = get_dataset(hp, size, seed, noise)
            X, y = to_xy(df, cfg["features"])
            for m in MODELS:
                model = build_model(m, seed)
                if model is None:
                    continue
                res = evaluate(model, X, y, seed)
                record(experiment="curve", honeypot=hp, model=m, seed=seed,
                       noise=noise, sessions=size, total_samples=len(df), **res)
        log("  {} sessoes/classe concluido".format(size))


def exp_ablation(hp, cfg, n_seeds, sessions, noise):
    """Impacto da remocao de cada feature."""
    feats = cfg["features"]
    log("[ablation] {}: {} features x {} seeds".format(hp, len(feats), n_seeds))
    for seed in range(n_seeds):
        df = get_dataset(hp, sessions, seed, noise)
        X_full, y = to_xy(df, feats)
        base = evaluate(build_model("rf", seed), X_full, y, seed)
        record(experiment="ablation", honeypot=hp, model="rf", seed=seed,
               noise=noise, removed="(nenhuma)", delta_f1=0.0, **base)
        for f in feats:
            subset = [c for c in feats if c != f]
            X, _ = to_xy(df, subset)
            res = evaluate(build_model("rf", seed), X, y, seed)
            record(experiment="ablation", honeypot=hp, model="rf", seed=seed,
                   noise=noise, removed=f,
                   delta_f1=round(res["cv_f1_mean"] - base["cv_f1_mean"], 4), **res)
        log("  seed {}/{} concluida".format(seed + 1, n_seeds))


def exp_hyper(hp, cfg, n_iter, sessions, noise):
    """Busca aleatoria de hiperparametros por modelo."""
    log("[hyper] {}: {} combinacoes por modelo".format(hp, n_iter))
    df = get_dataset(hp, sessions, 0, noise)
    X, y = to_xy(df, cfg["features"])
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, stratify=y,
                                              random_state=42)
    for m in MODELS:
        model = build_model(m, 42)
        if model is None:
            log("  {} indisponivel — pulando".format(m))
            continue
        t0 = time.time()
        search = RandomizedSearchCV(
            model, SEARCH_SPACES[m], n_iter=n_iter,
            cv=StratifiedKFold(5, shuffle=True, random_state=42),
            scoring="f1_macro", n_jobs=-1, random_state=42,
        )
        search.fit(X_tr, y_tr)
        test_f1 = f1_score(y_te, search.best_estimator_.predict(X_te), average="macro")
        record(experiment="hyper", honeypot=hp, model=m, noise=noise, sessions=sessions,
               best_params={k: str(v) for k, v in search.best_params_.items()},
               cv_f1_mean=float(search.best_score_), test_f1=float(test_f1),
               elapsed_s=round(time.time() - t0, 1))
        log("  {}: CV F1={:.4f}  teste={:.4f}  ({:.0f}s)".format(
            m, search.best_score_, test_f1, time.time() - t0))

# ── relatorio ────────────────────────────────────────────────────────────────

def build_report():
    if not RAW_PATH.exists():
        print("Nenhum resultado ainda.", file=sys.stderr)
        return
    rows = [json.loads(l) for l in RAW_PATH.read_text(encoding="utf-8").splitlines() if l.strip()]
    df = pd.DataFrame(rows)

    out = ["# Resultados Experimentais — BeeIA", "",
           "Gerado em {:%Y-%m-%d %H:%M}. Total de execucoes: **{}**.".format(datetime.now(), len(df)),
           "",
           "Produzido por `ml/experiments/run_experiments.py`. Cada linha agrega varias",
           "execucoes independentes — o desvio padrao vem da variacao entre seeds, nao de",
           "uma unica rodada.", ""]

    def table(sub, group, headers, title, note=""):
        if sub.empty:
            return
        out.append("## " + title)
        out.append("")
        if note:
            out.append(note)
            out.append("")
        g = sub.groupby(group)["cv_f1_mean"].agg(["mean", "std", "count"]).reset_index()
        g["std"] = g["std"].fillna(0.0)
        out.append("| " + " | ".join(headers) + " |")
        out.append("|" + "---|" * len(headers))
        for _, r in g.iterrows():
            keys = [str(r[k]) for k in group]
            out.append("| " + " | ".join(keys) +
                       " | {:.4f} | {:.4f} | {} |".format(r["mean"], r["std"], int(r["count"])))
        out.append("")

    for hp in df["honeypot"].dropna().unique():
        d = df[df["honeypot"] == hp]
        out.append("---")
        out.append("")
        out.append("# Honeypot: " + str(hp))
        out.append("")

        table(d[d.experiment == "seeds"], ["model"],
              ["Modelo", "F1-macro medio", "Desvio", "Execucoes"],
              "Estabilidade entre seeds",
              "Substitui o F1 unico de `train.py` por uma media com desvio real.")

        table(d[d.experiment == "noise"], ["noise", "model"],
              ["Ruido", "Modelo", "F1-macro medio", "Desvio", "Execucoes"],
              "Degradacao por ambiguidade",
              "`noise=0.0` reproduz o dataset original (classes separaveis por tres flags "
              "binarias, F1=1.0). Valores maiores injetam sobreposicao entre classes, "
              "sessoes truncadas e erro de rotulagem.")

        table(d[d.experiment == "curve"], ["sessions", "model"],
              ["Sessoes/classe", "Modelo", "F1-macro medio", "Desvio", "Execucoes"],
              "Curva de aprendizado",
              "Quanto dado e de fato necessario para saturar o desempenho.")

        if "removed" in d.columns:
            abl = d[(d.experiment == "ablation") & (d.removed.notna()) &
                    (d.removed != "(nenhuma)")]
            if not abl.empty:
                out.append("## Ablacao de features")
                out.append("")
                out.append("Impacto no F1-macro ao remover cada feature "
                           "(mais negativo = mais critica).")
                out.append("")
                g = abl.groupby("removed")["delta_f1"].agg(["mean", "std"]).sort_values("mean").reset_index()
                out.append("| Feature removida | Delta F1 medio | Desvio |")
                out.append("|---|---|---|")
                for _, r in g.iterrows():
                    sd = r["std"] if pd.notna(r["std"]) else 0.0
                    out.append("| {} | {:+.4f} | {:.4f} |".format(r["removed"], r["mean"], sd))
                out.append("")

        hyp = d[d.experiment == "hyper"]
        if not hyp.empty:
            out.append("## Busca de hiperparametros")
            out.append("")
            out.append("| Modelo | F1-macro (CV) | F1-macro (teste) | Melhores parametros |")
            out.append("|---|---|---|---|")
            for _, r in hyp.iterrows():
                bp = r.get("best_params") or {}
                params = ", ".join("{}={}".format(k, v) for k, v in bp.items())
                out.append("| {} | {:.4f} | {:.4f} | {} |".format(
                    r["model"], r["cv_f1_mean"], r.get("test_f1", float("nan")), params))
            out.append("")

    REPORT_PATH.write_text("\n".join(out), encoding="utf-8")
    print("Relatorio: {}  ({} execucoes)".format(REPORT_PATH, len(df)))

# ── entry point ──────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Harness experimental do BeeIA")
    ap.add_argument("--honeypot", default="cowrie", choices=["cowrie", "dionaea", "both"])
    ap.add_argument("--experiments", default="seeds,noise,curve,ablation,hyper",
                    help="Lista separada por virgula: seeds,noise,curve,ablation,hyper")
    ap.add_argument("--seeds", type=int, default=30, help="Execucoes independentes (padrao: 30)")
    ap.add_argument("--sessions", type=int, default=500, help="Sessoes por classe (padrao: 500)")
    ap.add_argument("--noise", type=float, default=0.6,
                    help="Ruido nos experimentos que nao variam ruido (padrao: 0.6)")
    ap.add_argument("--noise-levels", default="0.0,0.2,0.4,0.6,0.8,1.0")
    ap.add_argument("--curve-sizes", default="25,50,100,250,500,1000")
    ap.add_argument("--hyper-iter", type=int, default=60)
    ap.add_argument("--report", action="store_true", help="So regera o relatorio e sai")
    args = ap.parse_args()

    if args.report:
        build_report()
        return

    hps = ["cowrie", "dionaea"] if args.honeypot == "both" else [args.honeypot]
    wanted = [e.strip() for e in args.experiments.split(",") if e.strip()]
    t_start = time.time()

    log("Inicio | honeypots={} | experimentos={} | seeds={}".format(hps, wanted, args.seeds))
    if not XGBOOST_AVAILABLE:
        log("AVISO: xgboost nao instalado — apenas rf e svm serao avaliados")

    for hp in hps:
        cfg = HONEYPOTS[hp]
        if "seeds" in wanted:
            exp_seeds(hp, cfg, args.seeds, args.sessions, args.noise)
        if "noise" in wanted:
            levels = [float(x) for x in args.noise_levels.split(",")]
            exp_noise(hp, cfg, levels, max(5, args.seeds // 4), args.sessions)
        if "curve" in wanted:
            sizes = [int(x) for x in args.curve_sizes.split(",")]
            exp_curve(hp, cfg, sizes, max(5, args.seeds // 6), args.noise)
        if "ablation" in wanted:
            exp_ablation(hp, cfg, max(5, args.seeds // 6), args.sessions, args.noise)
        if "hyper" in wanted:
            exp_hyper(hp, cfg, args.hyper_iter, args.sessions, args.noise)

    build_report()
    log("Concluido em {:.1f} min".format((time.time() - t_start) / 60))


if __name__ == "__main__":
    main()
