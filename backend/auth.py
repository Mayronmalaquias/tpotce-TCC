"""
Autenticação por API key compartilhada para o backend do BeeIA.

Não é um sistema de usuários/login — é a barreira mínima para que a API
(rotas REST e WebSocket) não fique completamente aberta na internet. Pensada
para ser usada em conjunto com um proxy reverso autenticado (ver
`docker/nginx/dist/conf/beeia.conf` e `md-usotcc/proteger-dashboard.md`), não
como única linha de defesa.

Se BEEIA_API_KEY não estiver definida no .env, a autenticação fica desligada
(modo desenvolvimento local) — isso é intencional para não travar o fluxo de
`Como rodar` do README para quem só está testando na própria máquina.
"""

import os
import secrets

from fastapi import Header, HTTPException, WebSocket, status


def _configured_key() -> str:
    return os.getenv("BEEIA_API_KEY", "")


def auth_enabled() -> bool:
    return bool(_configured_key())


def require_api_key(x_api_key: str = Header(default="", alias="X-API-Key")) -> None:
    """Dependency para rotas HTTP — usar via `Depends(require_api_key)`."""
    key = _configured_key()
    if key and not secrets.compare_digest(x_api_key, key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key ausente ou inválida (header X-API-Key).",
        )


def ws_key_is_valid(ws: WebSocket) -> bool:
    """Checagem manual para o endpoint /ws — WebSocket não é resolvido pelas
    dependencies de rota HTTP da mesma forma, então o endpoint chama isso
    antes de aceitar a conexão."""
    key = _configured_key()
    if not key:
        return True
    supplied = ws.headers.get("x-api-key") or ws.query_params.get("api_key") or ""
    return secrets.compare_digest(supplied, key)
