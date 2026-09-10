"""
Rate limiting simples em memória, por IP de origem.

Não é distribuído — cada processo do backend tem seu próprio contador. É
suficiente para o BeeIA, que roda como processo único (`uvicorn main:app`),
mas não escala para múltiplos workers/réplicas sem um backend compartilhado
(Redis, etc.).

Uso: instancie um `RateLimiter` por escopo desejado e registre-o como
dependency da rota — `Depends(meu_limiter)`.
"""

import ipaddress
import os
import time
from collections import defaultdict

from fastapi import HTTPException, Request, status

# O backend fica atras do nginx, entao `request.client.host` e sempre o gateway
# do Docker: sem isto, todo o trafego da internet cai num unico balde e um
# atacante sozinho tranca os demais para fora. X-Forwarded-For so e aceito
# quando o peer imediato e um proxy confiavel — de qualquer outra origem o
# header e forjavel e ignora-lo e o que impede burlar o limite.
_DEFAULT_TRUSTED = "127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"


def _trusted_networks() -> list:
    redes = []
    for item in os.getenv("BEEIA_TRUSTED_PROXIES", _DEFAULT_TRUSTED).split(","):
        item = item.strip()
        if not item:
            continue
        try:
            redes.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue
    return redes


def client_ip(request: Request) -> str:
    peer = request.client.host if request.client else ""
    if not peer:
        return "unknown"
    try:
        endereco = ipaddress.ip_address(peer)
    except ValueError:
        return peer
    if not any(endereco in rede for rede in _trusted_networks()):
        return peer
    encaminhado = request.headers.get("x-forwarded-for", "")
    original = encaminhado.split(",")[0].strip()
    if not original:
        return peer
    try:
        ipaddress.ip_address(original)
    except ValueError:
        return peer
    return original


class RateLimiter:
    def __init__(self, max_calls: int, period_s: float):
        self.max_calls = max_calls
        self.period_s = period_s
        self._hits: dict[str, list[float]] = defaultdict(list)

    def __call__(self, request: Request) -> None:
        client_ip_addr = client_ip(request)
        now = time.time()
        window = self._hits[client_ip_addr]

        cutoff = now - self.period_s
        while window and window[0] < cutoff:
            window.pop(0)

        if len(window) >= self.max_calls:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Muitas requisições — limite de {self.max_calls} a cada {int(self.period_s)}s.",
            )

        window.append(now)
