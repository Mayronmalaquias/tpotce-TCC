"""
Pipeline completo: geração de logs → extração de features → CSV pronto para ML.

Uso:
    python build_dataset.py
    python build_dataset.py --sessions 1000
    python build_dataset.py --sessions 200 --seed 7

Saída em ../data/dataset/:
    cowrie_logs.jsonl       — logs brutos no formato Cowrie
    session_labels.csv      — session_id,label
    training_features.csv   — dataset com 13 features numéricas + label
"""

import argparse

from generate_logs import generate_dataset
from extract_features import extract_features

LOGS_PATH     = "../data/dataset/cowrie_logs.jsonl"
LABELS_PATH   = "../data/dataset/session_labels.csv"
FEATURES_PATH = "../data/dataset/training_features.csv"


def main(sessions_per_class: int = 500, seed: int = 42) -> None:
    print(f"[1/2] Gerando logs sintéticos ({sessions_per_class} sessões por classe)...\n")
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
    print("Dataset pronto!")
    print(f"  Arquivo: {FEATURES_PATH}")
    print()
    print("  Features numéricas (13):")
    print("    login_attempt_count    — volume de tentativas de login")
    print("    login_success          — 0/1 acesso ao shell")
    print("    unique_usernames       — variedade de usuários testados")
    print("    unique_passwords       — variedade de senhas testadas")
    print("    session_duration_s     — duração total da sessão")
    print("    command_count          — comandos executados")
    print("    avg_login_interval_ms  — cadência média entre logins")
    print("    min_login_interval_ms  — intervalo mínimo (detecta brute force)")
    print("    has_wget_curl          — download via wget/curl (0/1)")
    print("    has_reverse_shell      — padrão de reverse shell (0/1)")
    print("    has_recon_commands     — enumeração do sistema (0/1)")
    print("    has_file_download      — evento de download registrado (0/1)")
    print("    command_rate_per_min   — taxa de comandos por minuto")
    print()
    print("  Classes (4):")
    print("    brute_force  |  command_injection  |  recon  |  malware_download")
    print("-" * 50)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Constrói o dataset de treino ML do BeeIA")
    parser.add_argument("--sessions", type=int, default=500,
                        help="Sessões por classe de ataque (padrão: 500)")
    parser.add_argument("--seed", type=int, default=42,
                        help="Semente aleatória para reprodutibilidade (padrão: 42)")
    args = parser.parse_args()
    main(args.sessions, args.seed)
