"""
Teste da identificacao do cliente por tras do proxy.

O backend fica atras do nginx, entao o peer imediato e sempre o gateway do
Docker. Sem ler X-Forwarded-For, todo o trafego da internet cairia num unico
balde de rate limit e um atacante sozinho trancaria os demais para fora.

Mas confiar no header sem checar a origem seria pior: qualquer um mandaria um
XFF novo a cada requisicao e o limite deixaria de existir. Este teste fixa os
dois lados.

    python backend/tests/test_ratelimit_proxy.py
"""
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ratelimit  # noqa: E402


def request_de(peer, xff=None):
    pedido = Mock()
    pedido.client = Mock(host=peer) if peer else None
    pedido.headers = {"x-forwarded-for": xff} if xff else {}
    return pedido


class TesteIdentificacaoDoCliente(unittest.TestCase):
    def setUp(self):
        self._antes = dict(os.environ)
        os.environ.pop("BEEIA_TRUSTED_PROXIES", None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._antes)

    def test_usa_o_xff_quando_vem_do_proxy_confiavel(self):
        pedido = request_de("172.20.0.1", "203.0.113.9")
        self.assertEqual(ratelimit.client_ip(pedido), "203.0.113.9")

    def test_pega_o_primeiro_da_cadeia(self):
        pedido = request_de("172.20.0.1", "203.0.113.9, 10.1.2.3, 172.20.0.1")
        self.assertEqual(ratelimit.client_ip(pedido), "203.0.113.9")

    def test_ignora_xff_forjado_por_peer_nao_confiavel(self):
        # Requisicao direta da internet, sem passar pelo nginx: o header e do
        # atacante e nao pode valer nada.
        pedido = request_de("203.0.113.50", "1.2.3.4")
        self.assertEqual(ratelimit.client_ip(pedido), "203.0.113.50")

    def test_xff_invalido_cai_para_o_peer(self):
        for lixo in ("nao-e-ip", "", "   ", "999.999.999.999"):
            pedido = request_de("172.20.0.1", lixo)
            self.assertEqual(ratelimit.client_ip(pedido), "172.20.0.1")

    def test_sem_cliente_nao_explode(self):
        self.assertEqual(ratelimit.client_ip(request_de(None)), "unknown")

    def test_lista_de_proxies_configuravel(self):
        os.environ["BEEIA_TRUSTED_PROXIES"] = "198.51.100.0/24"
        confiavel = request_de("198.51.100.7", "203.0.113.9")
        self.assertEqual(ratelimit.client_ip(confiavel), "203.0.113.9")
        # O padrao privado deixa de valer quando a lista e sobrescrita.
        antigo = request_de("172.20.0.1", "203.0.113.9")
        self.assertEqual(ratelimit.client_ip(antigo), "172.20.0.1")

    def test_entrada_invalida_na_lista_nao_derruba_as_demais(self):
        os.environ["BEEIA_TRUSTED_PROXIES"] = "lixo,,172.20.0.0/16"
        pedido = request_de("172.20.0.1", "203.0.113.9")
        self.assertEqual(ratelimit.client_ip(pedido), "203.0.113.9")


class TesteBaldesSeparados(unittest.TestCase):
    def test_ips_atras_do_mesmo_proxy_nao_compartilham_o_limite(self):
        limiter = ratelimit.RateLimiter(max_calls=2, period_s=60)
        for _ in range(2):
            limiter(request_de("172.20.0.1", "203.0.113.1"))
        # Estourou para o primeiro IP...
        with self.assertRaises(Exception):
            limiter(request_de("172.20.0.1", "203.0.113.1"))
        # ...mas o segundo IP nao pode ser afetado.
        limiter(request_de("172.20.0.1", "203.0.113.2"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
