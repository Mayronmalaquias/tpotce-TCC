"""
Rate limiting simples em memória, por IP de origem.

Não é distribuído — cada processo do backend tem seu próprio contador. É
suficiente para o BeeIA, que roda como processo único (`uvicorn main:app`),
mas não escala para múltiplos workers/réplicas sem um backend compartilhado
(Redis, etc.).

Uso: instancie um `RateLimiter` por escopo desejado e registre-o como
dependency da rota — `Depends(meu_limiter)`.
"""

import time
from collections import defaultdict

from fastapi import HTTPException, Request, status


class RateLimiter:
    def __init__(self, max_calls: int, period_s: float):
        self.max_calls = max_calls
        self.period_s = period_s
        self._hits: dict[str, list[float]] = defaultdict(list)

    def __call__(self, request: Request) -> None:
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        window = self._hits[client_ip]

        cutoff = now - self.period_s
        while window and window[0] < cutoff:
            window.pop(0)

        if len(window) >= self.max_calls:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Muitas requisições — limite de {self.max_calls} a cada {int(self.period_s)}s.",
            )

        window.append(now)
