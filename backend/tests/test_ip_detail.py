"""
Teste do detalhamento por IP.

A tela mostra "o que este IP tentou fazer". O risco e o resumo mentir: se as
contagens saissem das linhas devolvidas com LIMIT, um IP com muitas sessoes
apareceria com numeros menores do que a realidade. Este teste fixa que o resumo
agrega TODAS as sessoes do IP, e que o corte da lista e sinalizado.

    python backend/tests/test_ip_detail.py
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import database  # noqa: E402


def sessao(ip, **campos):
    base = {
        "session_id": campos.pop("session_id", f"s-{ip}-{campos.get('n', 0)}"),
        "src_ip": ip,
        "attack_type": "brute_force",
        "confidence": 0.9,
        "timestamp": "2026-09-10T12:00:00Z",
    }
    campos.pop("n", None)
    base.update(campos)
    return base


class TesteDetalhePorIp(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._antes = database.DB_PATH
        database.DB_PATH = Path(self._tmp.name) / "teste.db"
        database.init()

    def tearDown(self):
        database.DB_PATH = self._antes
        self._tmp.cleanup()

    def test_ip_desconhecido_devolve_vazio(self):
        self.assertEqual(database.get_ip_detail("203.0.113.1"), {})

    def test_resumo_agrega_todas_as_sessoes_mesmo_com_limite(self):
        for i in range(10):
            database.insert_attack(sessao("203.0.113.7", n=i, login_attempts=3, command_count=2))
        detalhe = database.get_ip_detail("203.0.113.7", limit=4)

        self.assertEqual(detalhe["resumo"]["total_sessoes"], 10)
        self.assertEqual(detalhe["resumo"]["login_attempts"], 30)
        self.assertEqual(detalhe["resumo"]["command_count"], 20)
        self.assertEqual(len(detalhe["sessoes"]), 4)
        self.assertTrue(detalhe["sessoes_truncadas"])

    def test_nao_marca_truncado_quando_cabe_tudo(self):
        for i in range(3):
            database.insert_attack(sessao("203.0.113.8", n=i))
        detalhe = database.get_ip_detail("203.0.113.8", limit=50)
        self.assertEqual(len(detalhe["sessoes"]), 3)
        self.assertFalse(detalhe["sessoes_truncadas"])

    def test_separa_por_tipo_e_por_honeypot(self):
        database.insert_attack(sessao("203.0.113.9", n=1, attack_type="brute_force"))
        database.insert_attack(sessao("203.0.113.9", n=2, attack_type="brute_force"))
        database.insert_attack(sessao("203.0.113.9", n=3, attack_type="port_scan",
                                      honeypot="dionaea"))
        detalhe = database.get_ip_detail("203.0.113.9")

        por_tipo = {r["attack_type"]: r["count"] for r in detalhe["por_tipo"]}
        por_hp = {r["honeypot"]: r["count"] for r in detalhe["por_honeypot"]}
        self.assertEqual(por_tipo, {"brute_force": 2, "port_scan": 1})
        self.assertEqual(por_hp, {"cowrie": 2, "dionaea": 1})
        self.assertEqual(detalhe["resumo"]["honeypots"], 2)

    def test_marca_comportamento_visto_em_qualquer_sessao(self):
        # O IP baixou arquivo em UMA sessao entre varias: o resumo tem de acusar.
        database.insert_attack(sessao("203.0.113.10", n=1))
        database.insert_attack(sessao("203.0.113.10", n=2, has_wget_curl=1,
                                      has_file_download=1))
        resumo = database.get_ip_detail("203.0.113.10")["resumo"]
        self.assertEqual(resumo["has_wget_curl"], 1)
        self.assertEqual(resumo["has_file_download"], 1)
        self.assertEqual(resumo["has_reverse_shell"], 0)

    def test_nao_mistura_ips(self):
        database.insert_attack(sessao("203.0.113.11", n=1))
        database.insert_attack(sessao("203.0.113.12", n=1))
        self.assertEqual(database.get_ip_detail("203.0.113.11")["resumo"]["total_sessoes"], 1)

    def test_aspas_no_ip_nao_quebram_a_consulta(self):
        self.assertEqual(database.get_ip_detail("' OR 1=1 --"), {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
