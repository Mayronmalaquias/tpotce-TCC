"""
Treina modelos de sequencia sobre eventos brutos do Cowrie e compara com o
Random Forest sobre features escritas a mao.

A pergunta do experimento
-------------------------
O pipeline atual reduz cada sessao a 13 numeros agregados. Isso descarta a
ordem dos eventos, o ritmo entre eles e quais comandos foram executados. Um
modelo de sequencia le a sessao como ela e — uma sucessao de eventos — e
aprende sozinho o que importa.

    features manuais : 13 numeros  ->  Random Forest
    features aprendidas: sequencia ->  LSTM / Transformer

A hipotese nula e que o Random Forest vence: a literatura e consistente em
mostrar arvores superando redes neurais em dados tabulares. Se for esse o
caso, e resultado — e um resultado que so se obtem testando.

Uso:
    python train.py --arquitetura lstm --epocas 30
    python train.py --arquitetura transformer --epocas 30
    python train.py --comparar          # roda as duas e o baseline RF
"""

import argparse
import json
import time
from datetime import datetime
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from torch.utils.data import DataLoader, TensorDataset

from dataset import EVENT_TYPES, construir_tensores

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
RESULTADOS = HERE / "resultados"

LOGS_PADRAO   = REPO / "data" / "dataset" / "cowrie_logs.jsonl"
LABELS_PADRAO = REPO / "data" / "dataset" / "session_labels.csv"

torch.manual_seed(42)
np.random.seed(42)


# ── modelos ──────────────────────────────────────────────────────────────────

class CodificadorDeEventos(nn.Module):
    """Parte comum: transforma a tripla (tipo, comando, intervalo) num vetor.

    Os tres sinais entram por caminhos separados porque sao de naturezas
    diferentes — dois categoricos e um continuo — e concatenar embeddings com
    o intervalo bruto deixa a rede escolher como pesar cada um.
    """

    def __init__(self, n_comandos, dim_evento=32, dim_comando=32):
        super().__init__()
        self.emb_evento  = nn.Embedding(len(EVENT_TYPES), dim_evento, padding_idx=0)
        self.emb_comando = nn.Embedding(n_comandos, dim_comando, padding_idx=0)
        self.dim_saida = dim_evento + dim_comando + 1

    def forward(self, tipos, comandos, intervalos):
        return torch.cat([
            self.emb_evento(tipos),
            self.emb_comando(comandos),
            intervalos.unsqueeze(-1),
        ], dim=-1)


class ClassificadorLSTM(nn.Module):
    def __init__(self, n_comandos, n_classes, dim_oculta=128, camadas=2, dropout=0.3):
        super().__init__()
        self.codificador = CodificadorDeEventos(n_comandos)
        self.lstm = nn.LSTM(
            self.codificador.dim_saida, dim_oculta, num_layers=camadas,
            batch_first=True, bidirectional=True,
            dropout=dropout if camadas > 1 else 0.0,
        )
        self.dropout = nn.Dropout(dropout)
        self.saida = nn.Linear(dim_oculta * 2, n_classes)

    def forward(self, tipos, comandos, intervalos, tamanhos):
        x = self.codificador(tipos, comandos, intervalos)
        # empacota para o LSTM ignorar o padding — sem isso o modelo aprende
        # a partir de posicoes vazias e o resultado degrada silenciosamente
        empacotado = nn.utils.rnn.pack_padded_sequence(
            x, tamanhos.cpu(), batch_first=True, enforce_sorted=False)
        saida, _ = self.lstm(empacotado)
        desempacotado, _ = nn.utils.rnn.pad_packed_sequence(saida, batch_first=True)

        # media sobre os passos validos de cada sequencia
        mascara = (torch.arange(desempacotado.size(1), device=tipos.device)[None, :]
                   < tamanhos[:, None]).float().unsqueeze(-1)
        agregado = (desempacotado * mascara).sum(1) / mascara.sum(1).clamp(min=1)
        return self.saida(self.dropout(agregado))


class ClassificadorTransformer(nn.Module):
    def __init__(self, n_comandos, n_classes, dim_modelo=128, cabecas=4,
                 camadas=3, dropout=0.3, max_len=200):
        super().__init__()
        self.codificador = CodificadorDeEventos(n_comandos)
        self.projecao = nn.Linear(self.codificador.dim_saida, dim_modelo)
        self.posicional = nn.Parameter(torch.randn(1, max_len, dim_modelo) * 0.02)
        camada = nn.TransformerEncoderLayer(
            d_model=dim_modelo, nhead=cabecas, dim_feedforward=dim_modelo * 4,
            dropout=dropout, batch_first=True, norm_first=True,
        )
        self.encoder = nn.TransformerEncoder(camada, num_layers=camadas)
        self.dropout = nn.Dropout(dropout)
        self.saida = nn.Linear(dim_modelo, n_classes)

    def forward(self, tipos, comandos, intervalos, tamanhos):
        x = self.projecao(self.codificador(tipos, comandos, intervalos))
        x = x + self.posicional[:, :x.size(1)]

        preenchimento = (torch.arange(x.size(1), device=tipos.device)[None, :]
                         >= tamanhos[:, None])
        x = self.encoder(x, src_key_padding_mask=preenchimento)

        validos = (~preenchimento).float().unsqueeze(-1)
        agregado = (x * validos).sum(1) / validos.sum(1).clamp(min=1)
        return self.saida(self.dropout(agregado))


# ── treino ───────────────────────────────────────────────────────────────────

def log(msg):
    print("[{:%H:%M:%S}] {}".format(datetime.now(), msg), flush=True)


def preparar_dados(logs, labels, batch=128):
    log("Construindo sequencias a partir de {}".format(Path(logs).name))
    dados = construir_tensores(str(logs), str(labels))

    le = LabelEncoder()
    y = le.fit_transform(dados["rotulos"])
    classes = list(le.classes_)

    idx = np.arange(len(y))
    idx_tr, idx_te = train_test_split(idx, test_size=0.2, stratify=y, random_state=42)
    idx_tr, idx_val = train_test_split(idx_tr, test_size=0.15,
                                       stratify=y[idx_tr], random_state=42)

    def montar(indices, embaralhar):
        ds = TensorDataset(
            torch.from_numpy(dados["tipos"][indices]),
            torch.from_numpy(dados["comandos"][indices]),
            torch.from_numpy(dados["intervalos"][indices]),
            torch.from_numpy(dados["tamanhos"][indices]),
            torch.from_numpy(y[indices]),
        )
        return DataLoader(ds, batch_size=batch, shuffle=embaralhar)

    log("  sessoes: {} treino | {} validacao | {} teste".format(
        len(idx_tr), len(idx_val), len(idx_te)))
    log("  vocabulario de comandos: {}".format(len(dados["vocab_cmd"])))

    return (montar(idx_tr, True), montar(idx_val, False), montar(idx_te, False),
            classes, len(dados["vocab_cmd"]), dados, y, idx_tr, idx_te)


def avaliar(modelo, loader, dispositivo):
    modelo.eval()
    reais, preditos = [], []
    with torch.no_grad():
        for tipos, cmds, ints, tams, y in loader:
            saida = modelo(tipos.to(dispositivo), cmds.to(dispositivo),
                           ints.to(dispositivo), tams.to(dispositivo))
            preditos.extend(saida.argmax(1).cpu().numpy())
            reais.extend(y.numpy())
    return np.array(reais), np.array(preditos)


def treinar(arquitetura, dados_prep, epocas, lr, dispositivo, paciencia=6):
    (tr, val, te, classes, n_cmd, *_) = dados_prep

    if arquitetura == "lstm":
        modelo = ClassificadorLSTM(n_cmd, len(classes))
    else:
        modelo = ClassificadorTransformer(n_cmd, len(classes))
    modelo = modelo.to(dispositivo)

    n_param = sum(p.numel() for p in modelo.parameters())
    log("{}: {} parametros".format(arquitetura, "{:,}".format(n_param)))

    otimizador = torch.optim.AdamW(modelo.parameters(), lr=lr, weight_decay=1e-4)
    escalonador = torch.optim.lr_scheduler.CosineAnnealingLR(otimizador, T_max=epocas)
    criterio = nn.CrossEntropyLoss(label_smoothing=0.05)

    melhor_f1, melhor_estado, sem_melhora = 0.0, None, 0
    historico = []

    for epoca in range(1, epocas + 1):
        modelo.train()
        perda_total, t0 = 0.0, time.time()
        for tipos, cmds, ints, tams, y in tr:
            otimizador.zero_grad()
            saida = modelo(tipos.to(dispositivo), cmds.to(dispositivo),
                           ints.to(dispositivo), tams.to(dispositivo))
            perda = criterio(saida, y.to(dispositivo))
            perda.backward()
            nn.utils.clip_grad_norm_(modelo.parameters(), 1.0)
            otimizador.step()
            perda_total += perda.item()
        escalonador.step()

        reais, preditos = avaliar(modelo, val, dispositivo)
        rep = classification_report(reais, preditos, output_dict=True, zero_division=0)
        f1 = rep["macro avg"]["f1-score"]
        historico.append({"epoca": epoca, "perda": perda_total / len(tr),
                          "val_f1_macro": f1, "segundos": round(time.time() - t0, 1)})

        marca = ""
        if f1 > melhor_f1:
            melhor_f1 = f1
            melhor_estado = {k: v.detach().cpu().clone() for k, v in modelo.state_dict().items()}
            sem_melhora = 0
            marca = "  <- melhor"
        else:
            sem_melhora += 1

        log("  epoca {:>3}/{}  perda={:.4f}  val_F1={:.4f}  ({:.0f}s){}".format(
            epoca, epocas, perda_total / len(tr), f1, time.time() - t0, marca))

        if sem_melhora >= paciencia:
            log("  parada antecipada: {} epocas sem melhora".format(paciencia))
            break

    if melhor_estado:
        modelo.load_state_dict(melhor_estado)

    reais, preditos = avaliar(modelo, te, dispositivo)
    rep = classification_report(reais, preditos, target_names=classes,
                                output_dict=True, zero_division=0)
    return modelo, rep, historico, classes


def baseline_random_forest(dados_prep, features_csv):
    """Random Forest sobre as 13 features manuais, mesmo split do modelo neural."""
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier

    (_, _, _, classes, _, dados, y, idx_tr, idx_te) = dados_prep

    caminho = Path(features_csv)
    if not caminho.exists():
        log("baseline pulado: {} nao existe".format(caminho))
        return None

    df = pd.read_csv(caminho)
    cols = [c for c in df.columns if c not in ("session_id", "src_ip", "label")]
    if len(df) != len(y):
        log("baseline pulado: CSV tem {} linhas e as sequencias {}".format(len(df), len(y)))
        return None

    X = df[cols].values.astype(float)
    rf = RandomForestClassifier(n_estimators=300, random_state=42, n_jobs=-1)
    rf.fit(X[idx_tr], y[idx_tr])
    pred = rf.predict(X[idx_te])
    return classification_report(y[idx_te], pred, target_names=classes,
                                 output_dict=True, zero_division=0)


def main():
    ap = argparse.ArgumentParser(description="Modelos de sequencia para o BeeIA")
    ap.add_argument("--arquitetura", choices=["lstm", "transformer"], default="lstm")
    ap.add_argument("--comparar", action="store_true",
                    help="Roda LSTM, Transformer e o baseline Random Forest")
    ap.add_argument("--epocas", type=int, default=30)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--batch", type=int, default=128)
    ap.add_argument("--logs", default=str(LOGS_PADRAO))
    ap.add_argument("--labels", default=str(LABELS_PADRAO))
    ap.add_argument("--features", default=str(REPO / "data" / "dataset" / "training_features.csv"))
    ap.add_argument("--threads", type=int, default=0, help="0 = deixa o torch decidir")
    args = ap.parse_args()

    if args.threads:
        torch.set_num_threads(args.threads)

    dispositivo = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    log("dispositivo: {} | threads: {}".format(dispositivo, torch.get_num_threads()))

    dados_prep = preparar_dados(args.logs, args.labels, args.batch)
    classes = dados_prep[3]

    RESULTADOS.mkdir(parents=True, exist_ok=True)
    caminho_json = RESULTADOS / "comparacao.json"

    def salvar(dados):
        caminho_json.write_text(json.dumps(dados, indent=2, ensure_ascii=False),
                                encoding="utf-8")

    # Aproveita resultados de execucoes anteriores: permite retomar so a
    # arquitetura que faltou sem repetir horas de treino ja feitas.
    resultados = {}
    if caminho_json.exists():
        try:
            resultados = json.loads(caminho_json.read_text(encoding="utf-8"))
            if resultados:
                log("resultados anteriores encontrados: {}".format(
                    ", ".join(resultados)))
        except json.JSONDecodeError:
            pass

    arquiteturas = ["lstm", "transformer"] if args.comparar else [args.arquitetura]
    for arq in arquiteturas:
        log("=" * 60)
        log("Treinando {}".format(arq))
        log("=" * 60)
        t0 = time.time()
        modelo, rep, historico, _ = treinar(arq, dados_prep, args.epocas, args.lr, dispositivo)
        resultados[arq] = {
            "f1_macro_teste": rep["macro avg"]["f1-score"],
            "acuracia_teste": rep["accuracy"],
            "por_classe": {c: {"f1": rep[c]["f1-score"], "n": int(rep[c]["support"])}
                           for c in classes},
            "minutos": round((time.time() - t0) / 60, 1),
            "historico": historico,
        }
        torch.save({"state_dict": modelo.state_dict(), "classes": classes},
                   RESULTADOS / "{}.pt".format(arq))
        log("{}: F1-macro no teste = {:.4f}  ({:.1f} min)".format(
            arq, rep["macro avg"]["f1-score"], (time.time() - t0) / 60))

        # Persiste a cada arquitetura concluida. Uma rodada dessas leva horas;
        # salvar so no final ja custou perder o resultado de um LSTM inteiro
        # quando o processo foi interrompido.
        salvar(resultados)

    if args.comparar:
        log("=" * 60)
        log("Baseline: Random Forest sobre as 13 features manuais")
        rep_rf = baseline_random_forest(dados_prep, args.features)
        if rep_rf:
            resultados["random_forest"] = {
                "f1_macro_teste": rep_rf["macro avg"]["f1-score"],
                "acuracia_teste": rep_rf["accuracy"],
                "por_classe": {c: {"f1": rep_rf[c]["f1-score"], "n": int(rep_rf[c]["support"])}
                               for c in classes},
            }
            log("random_forest: F1-macro no teste = {:.4f}".format(
                rep_rf["macro avg"]["f1-score"]))
            salvar(resultados)

    salvar(resultados)

    log("=" * 60)
    log("RESULTADO FINAL")
    for nome, r in sorted(resultados.items(), key=lambda x: -x[1]["f1_macro_teste"]):
        log("  {:<16} F1-macro = {:.4f}".format(nome, r["f1_macro_teste"]))
    log("Salvo em {}".format(RESULTADOS / "comparacao.json"))


if __name__ == "__main__":
    main()
