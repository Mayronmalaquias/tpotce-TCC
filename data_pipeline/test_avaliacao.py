"""
Testes da amostragem e da apuracao de desempenho.

Estes numeros vao para a monografia. Um erro de sinal em precisao/recall nao
aparece como falha em lugar nenhum — sai como um resultado plausivel e errado.
Por isso a matriz de confusao e as metricas sao conferidas contra um caso
calculado a mao.

    python data_pipeline/test_avaliacao.py
"""
import contextlib
import csv
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import amostra_avaliacao as amostragem  # noqa: E402
import avaliar_amostra as apuracao  # noqa: E402


class TesteMetricas(unittest.TestCase):
    def test_caso_calculado_a_mao(self):
        # 6 sessoes. Para a classe "a": 2 acertos, 1 previsto errado como "a"
        # (vindo de "b"), 1 "a" perdido como "b".
        #   precisao(a) = 2/3 = 0.6667 ; recall(a) = 2/3 = 0.6667 ; F1 = 0.6667
        # Para "b": VP=2, FP=1 (o "a" que virou "b"), FN=1
        #   precisao(b) = 2/3 ; recall(b) = 2/3 ; F1 = 0.6667
        pares = [("a", "a"), ("a", "a"), ("a", "b"),
                 ("b", "b"), ("b", "b"), ("b", "a")]
        m = apuracao.metricas(pares)
        self.assertEqual(m["n"], 6)
        self.assertAlmostEqual(m["acuracia"], 4 / 6, places=4)
        self.assertAlmostEqual(m["por_classe"]["a"]["precisao"], 2 / 3, places=3)
        self.assertAlmostEqual(m["por_classe"]["a"]["recall"], 2 / 3, places=3)
        self.assertAlmostEqual(m["macro_f1"], 2 / 3, places=3)
        self.assertEqual(m["por_classe"]["a"]["suporte"], 3)

    def test_classe_nunca_prevista_tem_recall_zero_e_nao_divide_por_zero(self):
        pares = [("rara", "comum"), ("comum", "comum"), ("comum", "comum")]
        m = apuracao.metricas(pares)
        self.assertEqual(m["por_classe"]["rara"]["recall"], 0.0)
        self.assertEqual(m["por_classe"]["rara"]["precisao"], 0.0)
        self.assertEqual(m["por_classe"]["rara"]["f1"], 0.0)

    def test_acerto_perfeito(self):
        m = apuracao.metricas([("x", "x"), ("y", "y")])
        self.assertEqual(m["acuracia"], 1.0)
        self.assertEqual(m["macro_f1"], 1.0)

    def test_marca_suporte_insuficiente(self):
        pares = [("rara", "rara")] + [("comum", "comum")] * 20
        m = apuracao.metricas(pares)
        self.assertTrue(m["por_classe"]["rara"]["suporte_insuficiente"])
        self.assertFalse(m["por_classe"]["comum"]["suporte_insuficiente"])

    def test_acuracia_alta_nao_esconde_macro_f1_baixo(self):
        # 19 da classe majoritaria certos, 1 da minoritaria errado.
        pares = [("comum", "comum")] * 19 + [("rara", "comum")]
        m = apuracao.metricas(pares)
        self.assertGreater(m["acuracia"], 0.9)
        self.assertLess(m["macro_f1"], 0.6)


class TesteConsolidacaoDeRotulos(unittest.TestCase):
    def test_concordancia_vira_verdade(self):
        r = apuracao.consolida_rotulos([
            {"session_id": "s1", "rotulo_revisor1": "a", "rotulo_revisor2": "a"}])
        self.assertEqual(r["verdade"], {"s1": "a"})
        self.assertEqual(r["concordaram"], 1)

    def test_discordancia_nao_vira_verdade(self):
        r = apuracao.consolida_rotulos([
            {"session_id": "s1", "rotulo_revisor1": "a", "rotulo_revisor2": "b"}])
        self.assertEqual(r["verdade"], {})
        self.assertEqual(len(r["discordancias"]), 1)

    def test_inconclusivo_fica_de_fora_mesmo_com_rotulo(self):
        r = apuracao.consolida_rotulos([
            {"session_id": "s1", "rotulo_revisor1": "a", "rotulo_revisor2": "a",
             "inconclusivo": "sim"}])
        self.assertEqual(r["verdade"], {})
        self.assertEqual(r["inconclusivas"], ["s1"])

    def test_revisor_unico_e_aproveitado_mas_nao_conta_como_concordancia(self):
        r = apuracao.consolida_rotulos([
            {"session_id": "s1", "rotulo_revisor1": "a", "rotulo_revisor2": ""}])
        self.assertEqual(r["verdade"], {"s1": "a"})
        self.assertEqual(r["duplamente_revisadas"], 0)

    def test_linha_em_branco_nao_inventa_rotulo(self):
        r = apuracao.consolida_rotulos([
            {"session_id": "s1", "rotulo_revisor1": "  ", "rotulo_revisor2": ""}])
        self.assertEqual(r["verdade"], {})
        self.assertEqual(r["sem_rotulo"], ["s1"])


def banco_de_teste(caminho, linhas):
    with contextlib.closing(sqlite3.connect(caminho)) as db:
        db.execute("""CREATE TABLE attacks (session_id TEXT, src_ip TEXT, honeypot TEXT,
                      attack_type TEXT, confidence REAL, timestamp TEXT)""")
        db.executemany("INSERT INTO attacks VALUES (?,?,?,?,?,?)", linhas)
        db.commit()


class TesteAmostragem(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.db = self.dir / "t.db"
        linhas = []
        for i in range(300):
            linhas.append((f"s{i}", f"203.0.113.{i % 200}", "cowrie", "brute_force",
                           0.7, f"2026-09-0{i % 5 + 1}T10:00:00Z"))
        for i in range(5):
            linhas.append((f"raro{i}", f"198.51.100.{i}", "dionaea", "port_scan",
                           0.9, "2026-09-03T10:00:00Z"))
        banco_de_teste(self.db, linhas)

    def tearDown(self):
        self._tmp.cleanup()

    def test_exclui_sessoes_de_treino(self):
        elegiveis = amostragem.carrega_elegiveis(self.db, {"s0", "s1", "s2"})
        ids = {l["session_id"] for l in elegiveis}
        self.assertNotIn("s0", ids)
        self.assertEqual(len(elegiveis), 302)

    def test_piso_por_classe_garante_classe_rara(self):
        elegiveis = amostragem.carrega_elegiveis(self.db, set())
        escolhidas, desenho = amostragem.sorteia(elegiveis, n=50, min_por_classe=5, semente=1)
        raras = [l for l in escolhidas if l["attack_type"] == "port_scan"]
        self.assertEqual(len(raras), 5)
        self.assertEqual(desenho["dionaea/port_scan"]["piso_aplicado"], 5)

    def test_piso_nao_pede_mais_do_que_existe(self):
        elegiveis = amostragem.carrega_elegiveis(self.db, set())
        escolhidas, _ = amostragem.sorteia(elegiveis, n=50, min_por_classe=99, semente=1)
        raras = [l for l in escolhidas if l["attack_type"] == "port_scan"]
        self.assertEqual(len(raras), 5)

    def test_mesma_semente_mesma_amostra(self):
        elegiveis = amostragem.carrega_elegiveis(self.db, set())
        a, _ = amostragem.sorteia(elegiveis, 40, 3, semente=7)
        b, _ = amostragem.sorteia(elegiveis, 40, 3, semente=7)
        c, _ = amostragem.sorteia(elegiveis, 40, 3, semente=8)
        self.assertEqual([x["session_id"] for x in a], [x["session_id"] for x in b])
        self.assertNotEqual([x["session_id"] for x in a], [x["session_id"] for x in c])

    def test_nao_repete_sessao(self):
        elegiveis = amostragem.carrega_elegiveis(self.db, set())
        escolhidas, _ = amostragem.sorteia(elegiveis, 120, 5, semente=3)
        ids = [l["session_id"] for l in escolhidas]
        self.assertEqual(len(ids), len(set(ids)))

    def test_planilha_cega_nao_traz_a_previsao(self):
        proibidas = {"attack_type", "confidence", "previsto", "confianca"}
        self.assertFalse(proibidas & set(amostragem.COLUNAS_EVIDENCIA))
        self.assertIn("login_attempts", amostragem.COLUNAS_EVIDENCIA)
        self.assertIn("rotulo_revisor1", amostragem.COLUNAS_REVISAO)


if __name__ == "__main__":
    unittest.main(verbosity=2)
