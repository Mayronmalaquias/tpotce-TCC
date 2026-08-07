"""
Pipeline completo do Dionaea: geração de logs → extração de features → CSV pronto para ML.

Uso:
    python build_dionaea_dataset.py
    python build_dionaea_dataset.py --sessions 1000
    python build_dionaea_dataset.py --sessions 200 --seed 7

Saída em ../data/dataset/:
    dionaea_logs.jsonl              — logs brutos no formato normalizado do Dionaea
    dionaea_session_labels.csv      — session_id,label
    dionaea_training_features.csv   — dataset com 10 features numéricas + label
"""

import argparse

from generate_dionaea_logs import generate_dataset
from extract_dionaea_features import extract_features

LOGS_PATH     = "../data/dataset/dionaea_logs.jsonl"
LABELS_PATH   = "../data/dataset/dionaea_session_labels.csv"
FEATURES_PATH = "../data/dataset/dionaea_training_features.csv"


def main(sessions_per_class: int = 500, seed: int = 42) -> None:
    print(f"[1/2] Gerando logs sintéticos do Dionaea ({sessions_per_class} sessões por classe)...\n")
    generate_dataset(
        logs_path=LOGS_PATH,
        labels_path=LABELS_PATH,
        sessions_per_class=sessions_per_class,
        seed=seed,
    )

    print(f"\n[2/2] Extraindo features por sessão...")
    extract_features(
        logs_path=LOGS_PATH,
        labels_path=LABELS_PATH,
        output_path=FEATURES_PATH,
    )

    print("\n" + "-" * 50)
    print("Dataset do Dionaea pronto!")
    print(f"  Arquivo: {FEATURES_PATH}")
    print()
    print("  Features numéricas (10):")
    print("    connection_count            — conexões na sessão")
    print("    unique_ports                — portas de destino distintas")
    print("    unique_protocols            — protocolos/serviços distintos")
    print("    session_duration_s          — duração total da sessão")
    print("    avg_connection_interval_ms  — cadência média entre conexões")
    print("    min_connection_interval_ms  — intervalo mínimo (detecta scan)")
    print("    has_shellcode               — payload com assinatura de exploit (0/1)")
    print("    has_download                — download de malware capturado (0/1)")
    print("    payload_size_avg            — tamanho médio dos payloads (bytes)")
    print("    login_attempt_count         — tentativas de login em serviços com auth")
    print()
    print("  Classes (4):")
    print("    port_scan  |  service_probe  |  exploit_attempt  |  malware_download")
    print("-" * 50)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Constrói o dataset de treino ML do Dionaea (BeeIA)")
    parser.add_argument("--sessions", type=int, default=500,
                        help="Sessões por classe de ataque (padrão: 500)")
    parser.add_argument("--seed", type=int, default=42,
                        help="Semente aleatória para reprodutibilidade (padrão: 42)")
    args = parser.parse_args()
    main(args.sessions, args.seed)
