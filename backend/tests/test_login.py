"""
Teste do login por usuario e senha.

A senha deixou de ser digitada como chave da API: o navegador manda usuario e
senha, o servidor confere contra um hash PBKDF2 e devolve a chave. O que este
teste protege:

- a senha em texto nunca esta no servidor, so o hash;
- usuario errado e senha errada dao a MESMA resposta, sem dizer qual falhou;
- forca bruta esbarra no limite por IP antes de ficar barata;
- sem login configurado, a rota recusa em vez de deixar entrar.

    python backend/tests/test_login.py
"""
import os
import tempfile
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import auth  # noqa: E402

# Valores ficticios de propósito: este repositorio e publico e as
# credenciais reais vivem so no .env da VM.
USUARIO = "usuario-de-teste"
SENHA = "senha-de-teste-nao-usada-em-producao"


class TesteHashDeSenha(unittest.TestCase):
    def test_nao_usa_cifrao_por_causa_do_env(self):
        # docker-compose e systemd interpolam `$` no .env: um hash com cifrao
        # chegaria corrompido ao servidor e ninguem conseguiria entrar.
        self.assertNotIn("$", auth.hash_password(SENHA))

    def test_hash_nao_contem_a_senha(self):
        codificado = auth.hash_password(SENHA)
        self.assertNotIn(SENHA, codificado)
        self.assertTrue(codificado.startswith("pbkdf2_sha256:"))

    def test_salt_diferente_a_cada_geracao(self):
        self.assertNotEqual(auth.hash_password(SENHA), auth.hash_password(SENHA))

    def test_confere_senha_certa_e_recusa_errada(self):
        codificado = auth.hash_password(SENHA)
        self.assertTrue(auth.verify_password(SENHA, codificado))
        self.assertFalse(auth.verify_password(SENHA + "9", codificado))
        self.assertFalse(auth.verify_password("", codificado))

    def test_hash_invalido_nao_explode(self):
        for ruim in ("", "lixo", "pbkdf2_sha256:x:y:z", "outro:1:YQ==:YQ==", "a:b:c",
                     "pbkdf2_sha256$600000$YQ==$YQ=="):
            self.assertFalse(auth.verify_password(SENHA, ruim))

    def test_iteracoes_vem_do_hash_e_nao_do_codigo(self):
        # Um hash gerado com custo antigo continua validando depois de subirmos
        # o padrao — senao trocar PBKDF2_ITERATIONS trancaria todo mundo fora.
        antigo = auth.hash_password(SENHA, iterations=1000)
        self.assertIn(":1000:", antigo)
        self.assertTrue(auth.verify_password(SENHA, antigo))


class TesteVerificacaoDeLogin(unittest.TestCase):
    def setUp(self):
        self._antes = dict(os.environ)
        os.environ["BEEIA_LOGIN_USER"] = USUARIO
        os.environ["BEEIA_LOGIN_PASSWORD_HASH"] = auth.hash_password(SENHA, iterations=1000)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._antes)

    def test_login_valido(self):
        self.assertTrue(auth.login_enabled())
        self.assertTrue(auth.verify_login(USUARIO, SENHA))

    def test_usuario_ou_senha_errados(self):
        self.assertFalse(auth.verify_login("outro", SENHA))
        self.assertFalse(auth.verify_login(USUARIO, "errada"))
        self.assertFalse(auth.verify_login("", ""))

    def test_sem_configuracao_o_login_fica_desligado(self):
        del os.environ["BEEIA_LOGIN_PASSWORD_HASH"]
        self.assertFalse(auth.login_enabled())
        self.assertFalse(auth.verify_login(USUARIO, SENHA))


class TesteRotaDeLogin(unittest.TestCase):
    """Sobe a app de verdade e bate na rota, com dependencias reais."""

    @classmethod
    def setUpClass(cls):
        os.environ["BEEIA_API_KEY"] = "chave-secreta-de-teste"
        os.environ["BEEIA_LOGIN_USER"] = USUARIO
        os.environ["BEEIA_LOGIN_PASSWORD_HASH"] = auth.hash_password(SENHA, iterations=1000)

        import database
        cls._tmp = tempfile.TemporaryDirectory()
        database.DB_PATH = Path(cls._tmp.name) / "teste.db"
        database.init()

        from fastapi.testclient import TestClient
        import main
        cls.main = main
        cls.client = TestClient(main.app)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def setUp(self):
        # Cada teste comeca com a janela do rate limit limpa.
        self.main._login_rate_limit._hits.clear()

    def test_login_correto_devolve_a_chave(self):
        r = self.client.post("/api/login", json={"username": USUARIO, "password": SENHA})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["key"], "chave-secreta-de-teste")

    def test_credenciais_erradas_dao_401_com_a_mesma_mensagem(self):
        usuario = self.client.post("/api/login", json={"username": "x", "password": SENHA})
        senha = self.client.post("/api/login", json={"username": USUARIO, "password": "x"})
        self.assertEqual(usuario.status_code, 401)
        self.assertEqual(senha.status_code, 401)
        self.assertEqual(usuario.json()["detail"], senha.json()["detail"])

    def test_a_chave_nao_vaza_em_resposta_de_erro(self):
        r = self.client.post("/api/login", json={"username": "x", "password": "y"})
        self.assertNotIn("chave-secreta-de-teste", r.text)

    def test_forca_bruta_esbarra_no_limite_por_ip(self):
        for _ in range(5):
            self.client.post("/api/login", json={"username": USUARIO, "password": "errada"})
        bloqueado = self.client.post("/api/login", json={"username": USUARIO, "password": SENHA})
        self.assertEqual(bloqueado.status_code, 429)

    def test_rota_protegida_continua_exigindo_a_chave(self):
        self.assertEqual(self.client.get("/api/stats").status_code, 401)
        ok = self.client.get("/api/stats", headers={"X-API-Key": "chave-secreta-de-teste"})
        self.assertEqual(ok.status_code, 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
