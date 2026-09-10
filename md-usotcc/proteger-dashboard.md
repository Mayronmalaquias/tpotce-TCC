# Guia: Protegendo o Dashboard/API do BeeIA Antes de Expor Publicamente

Os honeypots (Cowrie, Dionaea) **são feitos para ficar públicos** — é assim que capturam tráfego malicioso real. O **dashboard e a API do backend não são** — por padrão, antes deste guia, eles não tinham autenticação nenhuma, CORS aberto (`*`) e nenhum rate limit, o que significa que qualquer pessoa na internet poderia:

- Bloquear/desbloquear qualquer IP no seu firewall via `/api/block/{ip}`.
- Gastar sua cota da API da Anthropic chamando `/api/report` repetidamente.
- Ler todos os dados de ataques capturados.

Este guia cobre as camadas de proteção já implementadas no código e como ativá-las.

---

## Endereço do dashboard publicado

Endereço informado pela equipe em 08/09/2026: **[https://honeypot.mirondev.com:64298/](https://honeypot.mirondev.com:64298/)**.

Use esse link para acesso pelo navegador, incluindo apresentações e testes com o orientador. Caso o proxy solicite autenticação, utilize as credenciais fornecidas pela equipe, sem publicá-las neste documento. O endereço do dashboard não identifica a porta SSH do honeypot.

## Camada 1 — API key no backend (`BEEIA_API_KEY`)

Toda rota REST (exceto quando a variável está vazia) e o WebSocket exigem uma chave compartilhada.

```bash
# 1. Gere uma chave
python -c "import secrets; print(secrets.token_urlsafe(32))"

# 2. Configure no .env da raiz (backend lê de lá)
BEEIA_API_KEY=<chave-gerada>

# 3. Configure a MESMA chave no frontend
cd frontend
cp .env.example .env
# edite frontend/.env e cole a mesma chave em VITE_API_KEY

# 4. Rebuilde o frontend (a chave é embutida no bundle em tempo de build)
npm run build
```

Sem `BEEIA_API_KEY` definida, o backend roda sem autenticação (avisa no log `[BeeIA] AVISO: ...`) — aceitável só em `localhost`/desenvolvimento.

> **Limite dessa camada:** como o frontend é uma SPA, a chave fica embutida no JavaScript entregue ao navegador — qualquer pessoa que abra a página consegue extraí-la. Ela não substitui controle de acesso à própria página (Camada 2), é defesa em profundidade contra bots/scripts que batem direto na API sem nunca carregar o dashboard.

## Camada 2 — CORS restrito (`CORS_ORIGINS`)

```bash
# .env da raiz
CORS_ORIGINS=https://honeypot.mirondev.com:64298
```

Impede que **outros sites** façam requisições ao seu backend a partir do navegador de um visitante (CSRF-like via JS). Não impede chamadas diretas via `curl`/scripts — para isso, use a Camada 1 (API key) e a Camada 3 (rede).

## Camada 3 — Rate limiting

Já ativo por padrão, sem configuração:

| Escopo | Limite |
|---|---|
| Qualquer rota `/api/*` | 60 requisições/minuto por IP |
| `/api/report` (chama a API da Anthropic — custa dinheiro) | 5 requisições a cada 10 minutos por IP |

É em memória (não sobrevive a múltiplos processos/workers) — suficiente para o BeeIA rodando como processo único.

## Camada 4 — Proxy reverso autenticado (Basic Auth via nginx)

**A camada mais importante.** Em vez de expor a porta 8000 do backend (e o `npm run dev`/build do frontend) diretamente na internet, coloque tudo atrás do nginx do T-Pot, que já vem com Basic Auth pronto (mesmo mecanismo usado pelo Kibana/painel original do T-Pot).

### Como o acesso funciona hoje (mudou em 10/09/2026)

O popup do navegador **não existe mais**. O Basic Auth do nginx foi removido a
pedido e substituído por uma tela de login no próprio painel.

Fluxo atual:

1. A página do dashboard carrega sem pedir nada.
2. A tela de login manda `POST /api/login` com usuário e senha.
3. O backend confere a senha contra um hash **PBKDF2-SHA256, 600 mil iterações**,
   e só então devolve a `BEEIA_API_KEY`.
4. O navegador guarda a chave em `sessionStorage` e usa em `/api/*` e `/ws`.

A senha em texto não existe em lugar nenhum: nem no `.env`, nem no bundle do
frontend, nem no banco. O `.env` guarda só o hash.

| Variável | Para quê |
|---|---|
| `BEEIA_LOGIN_USER` | nome de usuário do login |
| `BEEIA_LOGIN_PASSWORD_HASH` | saída de `auth.hash_password()` |
| `BEEIA_API_KEY` | a chave que o login devolve; continua protegendo `/api/*` |
| `BEEIA_TRUSTED_PROXIES` | de quem aceitar `X-Forwarded-For` (padrão: redes privadas) |

**Trocar a senha** — não exige rebuild do frontend, só reiniciar o backend:

```bash
cd ~/beeia/backend
./venv/bin/python -c 'import auth; print(auth.hash_password("nova-senha-aqui"))'
# cole em BEEIA_LOGIN_PASSWORD_HASH= no ~/beeia/.env
sudo systemctl restart beeia-backend
```

> O separador do hash é `:` e não `$` de propósito: o `.env` é lido pelo
> docker-compose e pelo systemd, e os dois interpolam `$` — um hash com cifrão
> chegaria corrompido e ninguém conseguiria entrar.

**O que protege contra força bruta:** o custo do PBKDF2 (~0,4 s por tentativa) e
um limite de **5 tentativas a cada 5 minutos por IP de origem**. O IP é lido do
`X-Forwarded-For` só quando a requisição vem do proxy confiável — vindo de
qualquer outra origem o header é ignorado, senão bastaria forjá-lo para escapar
do limite.

> **O que se perdeu ao tirar o popup.** Antes, quem não tivesse a credencial não
> conseguia nem baixar a página. Agora a página e os arquivos estáticos são
> públicos e a senha do login é a única barreira — numa máquina que existe
> justamente para atrair scanners. Uma senha fraca aqui é a diferença entre um
> painel protegido e um painel aberto. Para voltar atrás, as linhas de
> `auth_basic` estão comentadas em `docker/nginx/dist/conf/beeia.conf`.

**Recuperar acesso**, se ninguém lembrar da senha: gere um hash novo pelo comando
acima e reinicie o backend. Não há como recuperar a senha antiga — só substituir.

### Passo a passo

1. **Gere as credenciais WEB_USER** (se ainda não fez isso — mesmo passo do `md-usotcc/rodar-cowrie.md`):

   ```bash
   htpasswd -n -b "seu_usuario" "sua_senha" | base64 -w0
   # cole o resultado em WEB_USER= no .env
   ```

2. **Configure `BEEIA_API_KEY`/`VITE_API_KEY`** (Camada 1, acima) e rode `npm run build` no frontend.

3. **Confirme onde o backend do BeeIA vai rodar.** O arquivo `docker/nginx/dist/conf/beeia.conf` assume, por padrão, que o backend roda **na mesma máquina que o Docker** (usa `host.docker.internal`, já mapeado no `docker-compose.yml` via `extra_hosts`). Se o seu backend rodar em outra máquina/VM, edite `docker/nginx/dist/conf/beeia.conf` e troque `host.docker.internal` pelo IP real nas duas linhas `proxy_pass`.

4. **Suba o ambiente:**

   ```bash
   docker compose up -d nginx
   ```

   O arquivo `beeia.conf` é montado como volume no container `nginx` (não precisa rebuildar imagem nenhuma — a config funciona com a imagem oficial `${TPOT_REPO}/nginx`).

5. **Acesse:** `https://<IP-ou-domínio>:64298/` — o navegador vai pedir usuário/senha (WEB_USER) antes de carregar a página. Depois disso, o dashboard chama `/api/*` e `/ws` através do mesmo domínio/porta, já autenticado.

6. **Bloqueie a porta 8000 no firewall do host** para não-localhost/rede do Docker — o backend não deveria ser alcançável diretamente, só através do nginx:

   ```bash
   # Linux, exemplo permitindo só localhost e a rede do Docker
   sudo iptables -A INPUT -p tcp --dport 8000 -s 127.0.0.1 -j ACCEPT
   sudo iptables -A INPUT -p tcp --dport 8000 -j DROP
   ```

   ```powershell
   # Windows — restringe a porta 8000 a conexões locais
   New-NetFirewallRule -DisplayName "BeeIA backend (bloqueia externo)" -Direction Inbound -LocalPort 8000 -Protocol TCP -Action Block -RemoteAddress Internet
   ```

## Checklist antes de publicar

- [ ] `BEEIA_API_KEY` gerada e configurada no `.env` (backend) e `frontend/.env` (`VITE_API_KEY`), frontend rebuildado.
- [ ] `CORS_ORIGINS` apontando para o domínio real (não `*`, não `localhost`).
- [ ] Acesso ao dashboard passando pelo nginx (`https://.../:64298`) com Basic Auth, não direto na porta 8000/5173.
- [ ] Porta 8000 do backend bloqueada para tráfego externo no firewall do host.
- [ ] `WEB_USER` com senha forte, não a de exemplo do README.
- [ ] Ciente de que o Dionaea armazena binários de malware capturados — confira os termos de uso do seu provedor de hospedagem antes de publicar.
- [ ] Ciente de que o modelo de ML foi treinado só com dados sintéticos (ver [`Docs/Process/09-resultados-e-experimentos.md`](../Docs/Process/09-resultados-e-experimentos.md)) — espere classificações erradas em tráfego real até haver retreinamento com dados reais.
- [ ] Trate a máquina dos honeypots como descartável — se for comprometida de verdade (esse é o objetivo), não reaproveite esse host para outra coisa.
