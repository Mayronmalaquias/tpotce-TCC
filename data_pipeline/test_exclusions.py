import contextlib
import sqlite3
import tempfile
import unittest
from pathlib import Path

from exclusions import EXCLUDED_SESSION_IDS, load_excluded_ips, report, where_clause


def make_db(path, rows):
    with contextlib.closing(sqlite3.connect(path)) as db:
        db.execute("CREATE TABLE attacks (session_id TEXT, src_ip TEXT)")
        db.executemany("INSERT INTO attacks VALUES (?, ?)", rows)
        db.commit()


class ExclusionTests(unittest.TestCase):
    def test_exclui_sessoes_de_teste_e_preserva_o_resto(self):
        conhecidas = sorted(EXCLUDED_SESSION_IDS)
        rows = [(s, "10.0.0.1") for s in conhecidas] + [
            ("sessao_real_1", "203.0.113.7"),
            ("sessao_real_2", "198.51.100.4"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "t.db"
            make_db(db, rows)
            result = report(db)
        self.assertEqual(result["total_no_banco"], len(rows))
        self.assertEqual(result["excluidas"], len(conhecidas))
        self.assertEqual(result["para_avaliacao"], 2)

    def test_filtra_por_ip_quando_a_lista_local_existe(self):
        clause, params = where_clause(ips=["203.0.113.7"])
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "t.db"
            make_db(db, [("outra", "203.0.113.7"), ("mantida", "198.51.100.4")])
            with contextlib.closing(sqlite3.connect(db)) as con:
                kept = [r[0] for r in con.execute(
                    f"SELECT session_id FROM attacks WHERE {clause}", params)]
        self.assertEqual(kept, ["mantida"])

    def test_sem_arquivo_local_nao_quebra(self):
        self.assertEqual(load_excluded_ips(Path("nao_existe.local.txt")), [])
        clause, params = where_clause(ips=[])
        self.assertNotIn("src_ip", clause)
        self.assertEqual(len(params), len(EXCLUDED_SESSION_IDS))

    def test_comentario_e_linha_vazia_sao_ignorados(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "ips.txt"
            f.write_text("# comentario\n\n 203.0.113.7 # inline\n203.0.113.7\n", encoding="utf-8")
            self.assertEqual(load_excluded_ips(f), ["203.0.113.7"])


if __name__ == "__main__":
    unittest.main()
