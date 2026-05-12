"""
Geolocalização de IPs via ip-api.com (gratuito, sem chave, 45 req/min).
Cache em memória para evitar requisições repetidas.
"""

import ipaddress
import time
from typing import Optional

import requests

_cache: dict[str, Optional[dict]] = {}
_last_req = 0.0
_MIN_INTERVAL = 1.4  # segundos entre requisições (seguro abaixo do limite)


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True


def get_location(ip: str) -> Optional[dict]:
    if ip in _cache:
        return _cache[ip]

    if _is_private(ip):
        _cache[ip] = None
        return None

    global _last_req
    wait = _MIN_INTERVAL - (time.time() - _last_req)
    if wait > 0:
        time.sleep(wait)

    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,city,lat,lon"},
            timeout=5,
        )
        data = resp.json()
        _last_req = time.time()

        if data.get("status") == "success":
            result = {
                "country":   data.get("country"),
                "city":      data.get("city"),
                "latitude":  data.get("lat"),
                "longitude": data.get("lon"),
            }
            _cache[ip] = result
            return result
    except Exception:
        pass

    _cache[ip] = None
    return None
