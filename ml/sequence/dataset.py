"""
Converte sessoes do Cowrie em sequencias para modelos neurais.

Motivacao
---------
O pipeline atual reduz cada sessao a 13 numeros agregados (quantos logins,
quantos comandos, tem wget sim/nao). Isso descarta o que talvez seja a
informacao mais rica de um ataque: a **ordem** dos eventos, o **ritmo** entre
eles e **quais** comandos foram executados.

Uma sessao e, na origem, uma sequencia:

    connect -> login.failed -> login.failed -> login.success
            -> "uname -a" -> "cat /etc/passwd" -> "wget http://.../bot.sh"
            -> closed

Este modulo preserva essa estrutura para permitir a comparacao central do
TCC2: **features aprendidas pelo modelo vs. features escritas a mao**.

Representacao
-------------
Cada evento vira uma tripla:

    (tipo_do_evento, token_do_comando, intervalo_desde_o_evento_anterior)

  * tipo_do_evento    — categorico, vocabulario pequeno e fechado
  * token_do_comando  — o binario invocado (`wget`, `cat`, `uname`...);
                        vale 0 para eventos que nao sao comando
  * intervalo         — em log(1 + ms), porque os intervalos variam de
                        dezenas de milissegundos (automacao) a dezenas de
                        segundos (operador humano), e a escala linear faria o
                        modelo enxergar so os extremos

Sequencias longas sao truncadas: uma sessao de forca bruta pode ter 300
tentativas de login, e as primeiras dezenas ja carregam o padrao.
"""

import json
import math
from collections import Counter
from pathlib import Path

MAX_LEN = 200          # eventos por sessao (cobre >99% dos casos)
PAD = 0                # indice reservado para preenchimento

# Vocabulario fechado de eventos do Cowrie. Indice 0 fica para o padding e 1
# para eventos desconhecidos, de modo que o modelo nao quebre se o honeypot
# passar a emitir um evento novo.
EVENT_TYPES = [
    "<pad>", "<unk>",
    "cowrie.session.connect",
    "cowrie.client.version",
    "cowrie.login.failed",
    "cowrie.login.success",
    "cowrie.command.input",
    "cowrie.session.file_download",
    "cowrie.session.closed",
]
EVENT_TO_ID = {e: i for i, e in enumerate(EVENT_TYPES)}


def _token_do_comando(texto):
    """Extrai o binario invocado, ignorando argumentos.

    `wget http://x/bot.sh -O /tmp/a` vira `wget`. Guardar a linha inteira
    inflaria o vocabulario com URLs e caminhos aleatorios, que sao ruido —
    o que discrimina o comportamento e qual ferramenta foi usada.
    """
    if not texto:
        return None
    primeiro = texto.strip().split()
    if not primeiro:
        return None
    binario = primeiro[0].strip("/").split("/")[-1]
    return binario.lower()[:24] or None


def construir_vocabulario_de_comandos(sessoes, minimo=5):
    """Monta o vocabulario a partir dos comandos vistos no conjunto de treino.

    Comandos que aparecem menos de `minimo` vezes viram <unk>: sao ruido
    (typos de bot, strings aleatorias) e so aumentariam a tabela de embeddings.
    """
    contagem = Counter()
    for eventos in sessoes:
        for ev in eventos:
            if ev.get("eventid") == "cowrie.command.input":
                tok = _token_do_comando(ev.get("input", ""))
                if tok:
                    contagem[tok] += 1

    vocab = {"<pad>": 0, "<unk>": 1, "<nao-comando>": 2}
    for tok, n in contagem.most_common():
        if n >= minimo:
            vocab[tok] = len(vocab)
    return vocab


def carregar_sessoes(logs_path, labels_path):
    """Agrupa o JSONL por sessao e devolve (lista_de_eventos, lista_de_rotulos)."""
    rotulos = {}
    with open(labels_path, encoding="utf-8") as f:
        next(f)                                    # cabecalho
        for linha in f:
            partes = linha.strip().split(",")
            if len(partes) >= 2:
                rotulos[partes[0]] = partes[1]

    por_sessao = {}
    with open(logs_path, encoding="utf-8") as f:
        for linha in f:
            linha = linha.strip()
            if not linha:
                continue
            try:
                ev = json.loads(linha)
            except json.JSONDecodeError:
                continue
            sid = ev.get("session")
            if sid:
                por_sessao.setdefault(sid, []).append(ev)

    sessoes, alvos = [], []
    for sid, eventos in por_sessao.items():
        if sid in rotulos:
            sessoes.append(eventos)
            alvos.append(rotulos[sid])
    return sessoes, alvos


def _ms_desde(ts_anterior, ts_atual):
    """Intervalo em milissegundos entre dois timestamps ISO do Cowrie."""
    from datetime import datetime
    fmt = "%Y-%m-%dT%H:%M:%S.%fZ"
    try:
        a = datetime.strptime(ts_anterior, fmt)
        b = datetime.strptime(ts_atual, fmt)
        return max(0.0, (b - a).total_seconds() * 1000)
    except (ValueError, TypeError):
        return 0.0


def codificar_sessao(eventos, vocab_cmd, max_len=MAX_LEN):
    """Uma sessao -> (tipos, comandos, intervalos), todos de tamanho max_len."""
    eventos = eventos[:max_len]

    tipos, comandos, intervalos = [], [], []
    ts_anterior = None

    for ev in eventos:
        eid = ev.get("eventid", "")
        tipos.append(EVENT_TO_ID.get(eid, 1))

        if eid == "cowrie.command.input":
            tok = _token_do_comando(ev.get("input", ""))
            comandos.append(vocab_cmd.get(tok, 1) if tok else 2)
        else:
            comandos.append(2)                     # <nao-comando>

        ts = ev.get("timestamp")
        delta = _ms_desde(ts_anterior, ts) if ts_anterior else 0.0
        # log(1+ms): comprime a escala para o modelo distinguir automacao
        # (dezenas de ms) de operacao humana (segundos) na mesma faixa util
        intervalos.append(math.log1p(delta))
        ts_anterior = ts or ts_anterior

    faltando = max_len - len(tipos)
    if faltando > 0:
        tipos     += [PAD] * faltando
        comandos  += [PAD] * faltando
        intervalos += [0.0] * faltando

    return tipos, comandos, intervalos, min(len(eventos), max_len)


def _caminho_do_cache(logs_path, max_len):
    """Cache nomeado pelo tamanho e mtime do log: muda o log, muda o cache."""
    origem = Path(logs_path)
    try:
        marca = "{}_{}".format(origem.stat().st_size, int(origem.stat().st_mtime))
    except OSError:
        marca = "0"
    return origem.parent / "seq_cache_{}_{}_{}.npz".format(origem.stem, max_len, marca)


def construir_tensores(logs_path, labels_path, vocab_cmd=None, max_len=MAX_LEN,
                       usar_cache=True):
    """Pipeline completo: JSONL -> arrays prontos para o DataLoader.

    Parsear o JSONL leva minutos num dataset grande (331 MB / 2 milhoes de
    linhas), e o resultado e deterministico. O cache em .npz evita repetir isso
    a cada execucao de treino.
    """
    import numpy as np

    cache = _caminho_do_cache(logs_path, max_len)
    if usar_cache and cache.exists():
        z = np.load(cache, allow_pickle=True)
        return {
            "tipos": z["tipos"], "comandos": z["comandos"],
            "intervalos": z["intervalos"], "tamanhos": z["tamanhos"],
            "rotulos": list(z["rotulos"]),
            "vocab_cmd": json.loads(str(z["vocab_cmd"])),
        }

    sessoes, alvos = carregar_sessoes(logs_path, labels_path)
    if vocab_cmd is None:
        vocab_cmd = construir_vocabulario_de_comandos(sessoes)

    tipos, comandos, intervalos, tamanhos = [], [], [], []
    for eventos in sessoes:
        t, c, i, n = codificar_sessao(eventos, vocab_cmd, max_len)
        tipos.append(t); comandos.append(c); intervalos.append(i); tamanhos.append(n)

    resultado = {
        "tipos":      np.array(tipos, dtype=np.int64),
        "comandos":   np.array(comandos, dtype=np.int64),
        "intervalos": np.array(intervalos, dtype=np.float32),
        "tamanhos":   np.array(tamanhos, dtype=np.int64),
        "rotulos":    alvos,
        "vocab_cmd":  vocab_cmd,
    }

    if usar_cache:
        np.savez_compressed(
            cache, tipos=resultado["tipos"], comandos=resultado["comandos"],
            intervalos=resultado["intervalos"], tamanhos=resultado["tamanhos"],
            rotulos=np.array(alvos), vocab_cmd=json.dumps(vocab_cmd))

    return resultado


if __name__ == "__main__":
    import sys
    logs = sys.argv[1] if len(sys.argv) > 1 else "../../data/dataset/cowrie_logs.jsonl"
    lbls = sys.argv[2] if len(sys.argv) > 2 else "../../data/dataset/session_labels.csv"

    if not Path(logs).exists():
        print("Gere o dataset antes:")
        print("  cd data_pipeline && python build_dataset.py --sessions 500 --noise 0.6")
        sys.exit(1)

    dados = construir_tensores(logs, lbls)
    print("sessoes           :", len(dados["rotulos"]))
    print("vocabulario de cmd:", len(dados["vocab_cmd"]))
    print("comprimento medio :", float(dados["tamanhos"].mean().round(1)))
    print("comprimento maximo:", int(dados["tamanhos"].max()))
    print("\ncomandos mais frequentes no vocabulario:")
    for tok, idx in list(dados["vocab_cmd"].items())[3:18]:
        print("  ", tok)
