"""
Teste da rotulagem cega.

O que nao pode quebrar: a tela nunca recebe a previsao do modelo, um revisor
nunca ve os rotulos do outro, e rotulo fora da taxonomia do honeypot e recusado.

    python backend/tests/test_rotulagem.py
"""
import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import rotulagem  # noqa: E402

CAMPOS = ["session_id", "honeypot", "timestamp", "src_ip", "country", "protocol",
          "login_attempts", "login_success", "command_count", "session_duration_s",
          "connection_count", "unique_ports", "has_wget_curl", "has_reverse_shell",
          "has_recon_commands", "has_file_download", "has_shellcode",
          "rotulo_revisor1", "rotulo_revisor2", "inconclusivo", "observacao"]


class TesteRotulagem(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        with (base / "revisao_cega.csv").open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=CAMPOS)
            w.writeheader()
            w.writerow({"session_id": "c1", "honeypot": "cowrie", "timestamp": "2026-09-06T01:00:00Z",
                        "src_ip": "203.0.113.1", "rotulo_revisor1": "command_injection"})
            w.writerow({"session_id": "d1", "honeypot": "dionaea", "timestamp": "2026-09-06T02:00:00",
                        "src_ip": "203.0.113.2"})
        (base / "evidencias_revisao.json").write_text(json.dumps({"sessoes": {
            "c1": {"eventos": [{"t": "2026-09-06T01:00:00Z", "ev": "session.connect"}], "total": 1, "truncado": False},
            "d1": {"eventos": [], "total": 0, "truncado": False}}}), encoding="utf-8")
        # Uma previsao ao lado, como no servidor real: nao pode vazar.
        (base / "previsoes.csv").write_text("session_id,honeypot,previsto\nc1,cowrie,brute_force\n", encoding="utf-8")
        self.antes = rotulagem.DIR_AVALIACAO
        rotulagem.DIR_AVALIACAO = base
        rotulagem._cache.clear()

    def tearDown(self):
        rotulagem.DIR_AVALIACAO = self.antes
        rotulagem._cache.clear()
        self.tmp.cleanup()

    def test_sessoes_nao_trazem_previsao_nem_rotulo(self):
        texto = json.dumps(rotulagem.sessoes())
        for proibido in ("previsto", "brute_force", "confianca", "rotulo_revisor", "command_injection"):
            self.assertNotIn(proibido, texto)
        self.assertEqual(len(rotulagem.sessoes()), 2)

    def test_revisor_nao_ve_rotulos_do_outro(self):
        rotulagem.marca("mayron", "c1", "recon", None)
        self.assertEqual(rotulagem.rotulos_de("caio")["rotulos"], {})
        self.assertEqual(rotulagem.rotulos_de("mayron")["rotulos"]["c1"]["rotulo"], "recon")
        self.assertEqual(rotulagem.rotulos_de("Mayron")["revisor"], "1")

    def test_progresso_so_tem_contagens(self):
        rotulagem.marca("caio", "d1", "service_probe", None)
        p = rotulagem.progresso()
        self.assertEqual(p, {"total": 2, "revisores": {"mayron": 0, "caio": 1}})

    def test_recusa_classe_de_outro_honeypot_e_sessao_ou_revisor_desconhecidos(self):
        with self.assertRaises(rotulagem.RotuloInvalido):
            rotulagem.marca("mayron", "d1", "brute_force", None)
        with self.assertRaises(rotulagem.RotuloInvalido):
            rotulagem.marca("mayron", "x9", "recon", None)
        with self.assertRaises(rotulagem.RotuloInvalido):
            rotulagem.marca("fulano", "c1", "recon", None)

    def test_observacao_nao_apaga_rotulo_e_rotulo_vazio_limpa(self):
        rotulagem.marca("mayron", "c1", "fora_da_taxonomia", None)
        rotulagem.marca("mayron", "c1", None, "so conexao")
        e = rotulagem.rotulos_de("mayron")["rotulos"]["c1"]
        self.assertEqual((e["rotulo"], e["observacao"]), ("fora_da_taxonomia", "so conexao"))
        rotulagem.marca("mayron", "c1", "", None)
        self.assertEqual(rotulagem.rotulos_de("mayron")["rotulos"]["c1"]["rotulo"], "")

    def test_comportamentos_ficam_na_ordem_de_precedencia_e_nao_apagam_rotulo(self):
        rotulagem.marca("mayron", "c1", "malware_download", None)
        rotulagem.marca("mayron", "c1", None, None, ["recon", "malware_download", "command_injection"])
        e = rotulagem.rotulos_de("mayron")["rotulos"]["c1"]
        self.assertEqual(e["rotulo"], "malware_download")
        self.assertEqual(e["comportamentos"], ["malware_download", "command_injection", "recon"])
        rotulagem.marca("mayron", "c1", None, None, [])
        self.assertEqual(rotulagem.rotulos_de("mayron")["rotulos"]["c1"]["comportamentos"], [])

    def test_recusa_comportamento_de_outro_honeypot_ou_especial(self):
        with self.assertRaises(rotulagem.RotuloInvalido):
            rotulagem.marca("mayron", "d1", None, None, ["recon"])
        with self.assertRaises(rotulagem.RotuloInvalido):
            rotulagem.marca("mayron", "c1", None, None, ["inconclusivo"])

    def test_sem_evidencias_fica_indisponivel(self):
        (rotulagem.DIR_AVALIACAO / "evidencias_revisao.json").unlink()
        rotulagem._cache.clear()
        with self.assertRaises(rotulagem.RotulagemIndisponivel):
            rotulagem.sessoes()


if __name__ == "__main__":
    unittest.main()
