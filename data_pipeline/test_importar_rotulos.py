"""
Testes da importacao de rotulos da pagina e da apuracao por honeypot.

    python data_pipeline/test_importar_rotulos.py
"""
import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

AQUI = Path(__file__).resolve().parent
sys.path.insert(0, str(AQUI))

import importar_rotulos as importacao  # noqa: E402


def planilha():
    return [
        {"session_id": "c1", "honeypot": "cowrie", "rotulo_revisor1": "",
         "rotulo_revisor2": "", "inconclusivo": "", "observacao": ""},
        {"session_id": "c2", "honeypot": "cowrie", "rotulo_revisor1": "",
         "rotulo_revisor2": "", "inconclusivo": "", "observacao": ""},
        {"session_id": "d1", "honeypot": "dionaea", "rotulo_revisor1": "",
         "rotulo_revisor2": "", "inconclusivo": "", "observacao": ""},
    ]


def doc(revisor, **rotulos):
    return {"revisor": revisor,
            "rotulos": {sid: (v if isinstance(v, dict) else {"rotulo": v})
                        for sid, v in rotulos.items()}}


class TesteImportacao(unittest.TestCase):
    def test_preenche_cada_revisor_na_sua_coluna(self):
        linhas = planilha()
        importacao.importa(linhas, [doc("1", c1="recon"), doc("2", c1="brute_force")])
        self.assertEqual(linhas[0]["rotulo_revisor1"], "recon")
        self.assertEqual(linhas[0]["rotulo_revisor2"], "brute_force")

    def test_recusa_revisor_repetido(self):
        with self.assertRaises(importacao.ErroImportacao):
            importacao.importa(planilha(), [doc("1", c1="recon"), doc("1", c2="recon")])

    def test_recusa_classe_de_outro_honeypot(self):
        with self.assertRaises(importacao.ErroImportacao):
            importacao.importa(planilha(), [doc("1", d1="brute_force")])

    def test_recusa_sessao_desconhecida(self):
        with self.assertRaises(importacao.ErroImportacao):
            importacao.importa(planilha(), [doc("1", x9="recon")])

    def test_nao_sobrescreve_rotulo_existente_sem_pedir(self):
        linhas = planilha()
        linhas[0]["rotulo_revisor1"] = "recon"
        with self.assertRaises(importacao.ErroImportacao):
            importacao.importa(linhas, [doc("1", c1="brute_force")])
        importacao.importa(linhas, [doc("1", c1="brute_force")], substituir=True)
        self.assertEqual(linhas[0]["rotulo_revisor1"], "brute_force")

    def test_inconclusivo_marca_a_coluna_e_observacoes_ficam_separadas(self):
        linhas = planilha()
        importacao.importa(linhas, [
            doc("1", c1={"rotulo": "inconclusivo", "observacao": "so conexao"}),
            doc("2", c1={"rotulo": "fora_da_taxonomia", "observacao": "sem login"})])
        self.assertEqual(linhas[0]["inconclusivo"], "1")
        self.assertEqual(linhas[0]["observacao"], "R1: so conexao | R2: sem login")

    def test_reimportar_nao_duplica_observacao(self):
        linhas = planilha()
        docs = [doc("1", c1={"rotulo": "recon", "observacao": "uname"})]
        importacao.importa(linhas, docs)
        importacao.importa(linhas, docs)
        self.assertEqual(linhas[0]["observacao"], "R1: uname")


class TesteApuracaoPorHoneypot(unittest.TestCase):
    def roda(self, *extra):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            campos = ["session_id", "honeypot", "rotulo_revisor1", "rotulo_revisor2",
                      "inconclusivo", "observacao"]
            revisao = [
                ["c1", "cowrie", "brute_force", "brute_force", "", ""],
                ["c2", "cowrie", "fora_da_taxonomia", "fora_da_taxonomia", "", ""],
                ["d1", "dionaea", "service_probe", "service_probe", "", ""],
            ]
            with (base / "revisao_cega.csv").open("w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(campos)
                w.writerows(revisao)
            with (base / "previsoes.csv").open("w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["session_id", "honeypot", "previsto", "confianca", "ip_visto_no_treino"])
                w.writerows([["c1", "cowrie", "brute_force", "0.6", "0"],
                             ["c2", "cowrie", "brute_force", "0.6", "0"],
                             ["d1", "dionaea", "service_probe", "0.9", "0"]])
            saida = base / "r.json"
            r = subprocess.run([sys.executable, str(AQUI / "avaliar_amostra.py"),
                                "--amostra", str(base), "--json", str(saida), *extra],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            return json.loads(saida.read_text(encoding="utf-8"))

    def test_filtra_honeypot_e_exclui_fora_da_taxonomia(self):
        r = self.roda("--honeypot", "cowrie")
        self.assertEqual(r["n"], 1)
        self.assertEqual(r["classes"], ["brute_force"])
        self.assertEqual(r["fora_da_taxonomia"]["sessoes"], 1)

    def test_fora_da_taxonomia_como_classe_conta_como_erro(self):
        r = self.roda("--honeypot", "cowrie", "--fora-da-taxonomia", "classe")
        self.assertEqual(r["n"], 2)
        self.assertEqual(r["acuracia"], 0.5)
        self.assertEqual(r["por_classe"]["brute_force"]["precisao"], 0.5)


if __name__ == "__main__":
    unittest.main()
