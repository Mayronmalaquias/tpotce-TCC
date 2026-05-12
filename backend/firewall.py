"""
Bloqueio/desbloqueio de IPs no firewall do host.
Detecta automaticamente o sistema operacional:
  Linux   → iptables
  Windows → netsh advfirewall
"""

import ipaddress
import platform
import subprocess
from typing import Tuple

_OS = platform.system()  # "Linux" | "Windows" | "Darwin"


def _validate(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _run(cmd: list[str]) -> Tuple[bool, str]:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        ok  = res.returncode == 0
        msg = (res.stdout or res.stderr or "ok").strip()
        return ok, msg
    except Exception as exc:
        return False, str(exc)


def block_ip(ip: str) -> Tuple[bool, str]:
    if not _validate(ip):
        return False, f"IP invalido: {ip}"

    if _OS == "Linux":
        return _run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])

    if _OS == "Windows":
        return _run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name=BeeIA-Block-{ip}",
            "dir=in", "action=block", f"remoteip={ip}", "enable=yes",
        ])

    return False, f"Firewall nao suportado neste SO: {_OS}"


def unblock_ip(ip: str) -> Tuple[bool, str]:
    if not _validate(ip):
        return False, f"IP invalido: {ip}"

    if _OS == "Linux":
        return _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])

    if _OS == "Windows":
        return _run([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name=BeeIA-Block-{ip}",
        ])

    return False, f"Firewall nao suportado neste SO: {_OS}"
