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

import base64
import hashlib
import hmac
import os
import secrets

from fastapi import Header, HTTPException, WebSocket, status

# Custo do PBKDF2. Alto de proposito: a unica defesa contra quem baixou o hash
# e o tempo de derivacao. Gravado dentro do proprio hash, entao aumentar este
# valor no futuro nao invalida as senhas ja cadastradas.
PBKDF2_ITERATIONS = 600_000
_ALGORITHM = "pbkdf2_sha256"


def _configured_key() -> str:
    return os.getenv("BEEIA_API_KEY", "")


def auth_enabled() -> bool:
    return bool(_configured_key())


def configured_key() -> str:
    """A chave que o navegador passa a usar depois do login."""
    return _configured_key()


# ── login por usuario e senha ─────────────────────────────────────────────────
#
# A senha NUNCA e guardada em texto, nem no .env, nem no bundle do frontend:
# BEEIA_LOGIN_PASSWORD_HASH guarda a saida de `hash_password`. Trocar a senha e
# regerar o hash e reiniciar o backend — nao exige rebuild do frontend.


def hash_password(password: str, *, iterations: int = PBKDF2_ITERATIONS,
                  salt: bytes | None = None) -> str:
    """Gera `pbkdf2_sha256:<iteracoes>:<salt>:<hash>` para o .env.

    Separador `:` e nao `$`: o .env e lido pelo docker-compose e pelo systemd,
    e os dois interpolam `$`, o que corromperia o hash em silencio. Base64 nunca
    produz `:`, entao o campo continua sem ambiguidade.
    """
    salt = secrets.token_bytes(16) if salt is None else salt
    derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return "{}:{}:{}:{}".format(
        _ALGORITHM, iterations,
        base64.b64encode(salt).decode(),
        base64.b64encode(derived).decode(),
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt_b64, hash_b64 = encoded.split(":")
        if algorithm != _ALGORITHM:
            return False
        expected = base64.b64decode(hash_b64)
        derived = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), base64.b64decode(salt_b64), int(iterations))
    except (ValueError, TypeError):
        # Hash mal formado e senha errada dao o mesmo resultado para quem chama.
        return False
    return hmac.compare_digest(derived, expected)


def login_enabled() -> bool:
    return bool(os.getenv("BEEIA_LOGIN_USER") and os.getenv("BEEIA_LOGIN_PASSWORD_HASH"))


def verify_login(username: str, password: str) -> bool:
    """Confere usuario e senha sem revelar qual dos dois estava errado.

    A derivacao roda mesmo quando o usuario nao bate, para que o tempo de
    resposta nao diga a um atacante se o nome existe.
    """
    expected_user = os.getenv("BEEIA_LOGIN_USER", "")
    encoded = os.getenv("BEEIA_LOGIN_PASSWORD_HASH", "")
    if not expected_user or not encoded:
        return False
    user_ok = hmac.compare_digest(username.encode(), expected_user.encode())
    password_ok = verify_password(password, encoded)
    return user_ok and password_ok


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
