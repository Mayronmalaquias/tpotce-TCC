# Guia: Publicando o BeeIA numa Instância AWS EC2 (Free Tier)

Guia prático, passo a passo, para colocar o BeeIA numa instância real acessível pela internet, usando só o que está coberto pelo tier gratuito da AWS. Para entender o *porquê* de cada decisão (por que SSM em vez de SSH, por que o backend roda fora do Docker, etc.), veja [`Docs/Process/13-deploy-publicacao-aws.md`](../Docs/Process/13-deploy-publicacao-aws.md).

> Antes de seguir este guia, já é preciso ter: modelos treinados (`ml/cowrie/models/`, `ml/dionaea/models/`) e o frontend buildado (`frontend/dist/`) — localmente ou prontos para copiar.

---

## 1. Lançar a instância EC2

No console EC2 → **Launch Instance**:

| Campo | Valor |
|---|---|
| AMI | Amazon Linux 2023 |
| Tipo de instância | `t3.micro` (free tier) |
| Par de chaves | Crie um novo (`.pem`) — só será usado antes de desativar o SSH real, ver passo 5 |
| Rede/sub-rede | Padrão (VPC/subnet default) |
| IAM instance profile | Crie/associe um role com a policy `AmazonSSMManagedInstanceCore` (necessário para o passo 3) |
| Armazenamento | 20 GiB gp3 (dentro dos 30 GiB gratuitos) |
| Especificação de crédito | **Standard** (não "Unlimited" — evita cobrança por burst sustentado de CPU) |

### Grupo de segurança

Crie um novo grupo de segurança com estas regras de entrada (tipo "Custom TCP" quando a porta não tiver preset, ex. Telnet):

| Porta | Protocolo | Origem |
|---|---|---|
| 22 | TCP | Anywhere (0.0.0.0/0) |
| 23 | TCP | Anywhere |
| 21 | TCP | Anywhere |
| 42 | TCP | Anywhere |
| 69 | UDP | Anywhere |
| 135 | TCP | Anywhere |
| 443 | TCP | Anywhere |
| 445 | TCP | Anywhere |
| 1433 | TCP | Anywhere |
| 1723 | TCP | Anywhere |
| 1883 | TCP | Anywhere |
| 3306 | TCP | Anywhere |
| 5060 | TCP + UDP | Anywhere |
| 27017 | TCP | Anywhere |
| 64298 | TCP | **My IP** (restrinja — é o dashboard, não o honeypot) |

### User data (script de inicialização)

Cole em "Advanced details → User data" — instala Docker e já prepara 2 GiB de swap (`t3.micro` só tem 1 GiB de RAM, insuficiente para build + 4 containers):

```bash
#!/bin/bash
dnf install -y docker git python3.11 python3.11-pip
systemctl enable --now docker
usermod -aG docker ec2-user

fallocate -l 2G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo '/swapfile swap swap defaults 0 0' >> /etc/fstab
```

Revise o resumo final antes de lançar: confirme **Standard** (não Unlimited) e que a regra 64298 não ficou em "Anywhere" por engano.

---

## 2. Conectar via SSM (não SSH)

A porta 22 vai acabar sendo ocupada pelo Cowrie — administração é feita via **Session Manager**, sem chave SSH:

Console AWS → **EC2 → Instances → selecione a instância → Connect → Session Manager → Connect**.

Isso abre um terminal direto no navegador. Todos os comandos dos próximos passos rodam nesse terminal (ou via `aws ssm start-session` no CLI, se preferir).

---

## 3. Instalar o docker-compose standalone

Muitas AMIs não têm o plugin `docker compose` no caminho esperado. Use o binário standalone:

```bash
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
docker-compose version
```

---

## 4. Clonar o repositório e transferir modelos/build

Do seu computador local (com o repositório já clonado e os modelos treinados):

```bash
# no terminal SSM: clone o repo
git clone <url-do-seu-repositorio> ~/beeia
cd ~/beeia

# de volta no SEU computador (PowerShell), copie o par de chaves .pem
# baixado no passo 1 para uma pasta acessível, depois:
scp -i "caminho\para\sua-chave.pem" -r frontend\dist ec2-user@<IP-DA-INSTANCIA>:~/beeia/frontend/dist
scp -i "caminho\para\sua-chave.pem" -r ml\cowrie\models ec2-user@<IP-DA-INSTANCIA>:~/beeia/ml/cowrie/models
scp -i "caminho\para\sua-chave.pem" -r ml\dionaea\models ec2-user@<IP-DA-INSTANCIA>:~/beeia/ml/dionaea/models
```

> **Atenção:** se `frontend/dist` já existir no destino (por exemplo, por estar versionado no git), o `scp -r` copia o conteúdo *para dentro* dele em vez de substituí-lo, gerando `dist/dist/...`. Confira com `ls ~/beeia/frontend/dist` depois do envio; se duplicou, corrija com `mv`.

---

## 5. Configurar o `.env` e gerar credenciais

No terminal SSM:

```bash
cd ~/beeia
cp .env.example .env

# Gere a API key do backend
python3.11 -c "import secrets; print(secrets.token_urlsafe(32))"
# cole o resultado em BEEIA_API_KEY= no .env

# Gere as credenciais do dashboard (Basic Auth)
sudo dnf install -y httpd-tools
HTPASSWD_LINE=$(htpasswd -nb "seu_usuario" "sua_senha_forte")
echo "$HTPASSWD_LINE"
# base64 do resultado vai em WEB_USER= no .env
echo -n "$HTPASSWD_LINE" | base64 -w0
```

Edite `~/beeia/.env` (`nano .env`) e preencha `BEEIA_API_KEY`, `WEB_USER`, `CORS_ORIGINS` (deixe `https://<IP-ou-domínio>:64298` por enquanto), `ANTHROPIC_API_KEY` (se for usar o relatório LLM).

Depois, escreva as credenciais reais direto no arquivo que o nginx lê (editar só o `.env` não é suficiente — o container lê `data/nginx/conf/nginxpasswd`, não o `.env`):

```bash
mkdir -p ~/beeia/data/nginx/conf
echo "$HTPASSWD_LINE" | sudo tee ~/beeia/data/nginx/conf/nginxpasswd
sudo chmod 644 ~/beeia/data/nginx/conf/nginxpasswd
```

No **seu computador**, configure `frontend/.env` com o mesmo valor de `BEEIA_API_KEY` (em `VITE_API_KEY`) e rode `npm run build` antes do `scp` do passo 4 — a chave é embutida no bundle em tempo de build.

---

## 6. Subir os containers

```bash
cd ~/beeia
sudo docker-compose up -d
docker ps
```

Espera-se 4 containers: `tpotinit`, `cowrie`, `dionaea`, `nginx`, todos `Up`/`healthy`.

### Se `cowrie` falhar com `bind: address already in use` na porta 22

O `sshd` real do sistema ainda está ocupando a porta. **Confirme primeiro que o Session Manager está funcionando** (passo 2), só então:

```bash
sudo systemctl stop sshd
sudo systemctl disable sshd
sudo docker-compose up -d
```

A partir daqui, não há mais acesso SSH à instância — só SSM.

---

## 7. Subir o backend como serviço systemd

```bash
# garanta que o diretório data/ (onde fica o beeia.db) é gravável pelo ec2-user
# — ele pode já existir com outro dono, criado pelos bind mounts do Docker
sudo chown ec2-user:ec2-user ~/beeia/data

cd ~/beeia/backend
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
deactivate

sudo tee /etc/systemd/system/beeia-backend.service > /dev/null <<'EOF'
[Unit]
Description=BeeIA backend
After=network.target docker.service

[Service]
User=ec2-user
WorkingDirectory=/home/ec2-user/beeia/backend
ExecStart=/home/ec2-user/beeia/backend/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
Restart=always
EnvironmentFile=/home/ec2-user/beeia/.env

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now beeia-backend
sudo systemctl status beeia-backend
```

Se aparecer `sqlite3.OperationalError: unable to open database file` no `journalctl -u beeia-backend`, é o mesmo problema de dono do diretório `data/` — repita o `chown` acima e `sudo systemctl restart beeia-backend`.

Teste local:

```bash
grep BEEIA_API_KEY ~/beeia/.env
curl -s -H "X-API-Key: <valor-copiado-acima>" http://localhost:8000/api/stats
```

Deve retornar um JSON com `total_attacks`, etc.

---

## 8. Testar de ponta a ponta

1. **Dashboard:** `https://<IP-da-instância>:64298/` — aceite o aviso de certificado autoassinado, autentique com as credenciais do passo 5.
2. **Honeypot:** de outra máquina, `ssh root@<IP-da-instância>` (qualquer senha costuma ser aceita pelo Cowrie), rode alguns comandos (`whoami`, `cat /etc/passwd`, `wget http://exemplo.com/x`) e `exit`. A sessão deve aparecer no feed do dashboard em poucos segundos, classificada por tipo de ataque.

> Se o SSH client reclamar de "host key changed", é esperado — antes a porta 22 respondia com a chave do `sshd` real; agora é o Cowrie. Rode `ssh-keygen -R <IP>` e conecte de novo.

---

## Domínio próprio e certificado confiável (Let's Encrypt)

Só faça esta seção se tiver um domínio próprio disponível. Sem ela, o dashboard continua funcional com o certificado autoassinado (só com aviso no navegador).

### 0. Pré-requisito: IP fixo (Elastic IP)

O IP público de uma instância EC2 muda a cada stop/start. Antes de criar o registro DNS, aloque um **Elastic IP** (Console EC2 → Elastic IPs → Allocate) e associe-o à instância — é gratuito enquanto estiver associado a uma instância em execução.

### 1. DNS

No painel do seu provedor de domínio, crie um registro:

| Tipo | Nome | Valor |
|---|---|---|
| A | `honeypot` (ou o subdomínio de sua escolha) | `<Elastic-IP-da-instância>` |

Aguarde a propagação (geralmente minutos) e confirme com `nslookup honeypot.seudominio.com`.

### 2. Abrir a porta 80 no grupo de segurança

Necessária só para a validação HTTP-01 do Let's Encrypt (nenhum honeypot usa essa porta):

Console EC2 → Security Groups → sua regra → **Add rule**: Custom TCP, porta 80, origem `0.0.0.0/0`.

### 3. Emitir o certificado

No terminal SSM:

```bash
sudo dnf install -y python3-pip
sudo pip3 install certbot

sudo certbot certonly --standalone \
  -d honeypot.seudominio.com \
  --agree-tos -m seu-email@exemplo.com --non-interactive
```

Gera `/etc/letsencrypt/live/honeypot.seudominio.com/{fullchain.pem,privkey.pem}`.

### 4. Colocar o certificado onde o nginx já procura

O volume `data/nginx/cert/` já é montado inteiro em `/etc/nginx/cert/` dentro do container — não precisa editar `docker-compose.yml`, só copiar os arquivos para lá:

```bash
DOMAIN=honeypot.seudominio.com
sudo cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem ~/beeia/data/nginx/cert/beeia-fullchain.pem
sudo cp /etc/letsencrypt/live/$DOMAIN/privkey.pem   ~/beeia/data/nginx/cert/beeia-privkey.pem
sudo chown 2000:2000 ~/beeia/data/nginx/cert/beeia-*.pem
sudo chmod 640 ~/beeia/data/nginx/cert/beeia-*.pem
```

### 5. Apontar o `beeia.conf` para o novo certificado

```bash
sudo sed -i \
  -e "s#server_name _;#server_name $DOMAIN;#" \
  -e "s#ssl_certificate     /etc/nginx/cert/nginx.crt;#ssl_certificate     /etc/nginx/cert/beeia-fullchain.pem;#" \
  -e "s#ssl_certificate_key /etc/nginx/cert/nginx.key;#ssl_certificate_key /etc/nginx/cert/beeia-privkey.pem;#" \
  ~/beeia/docker/nginx/dist/conf/beeia.conf

cd ~/beeia
sudo docker-compose restart nginx
docker logs nginx --tail 30
```

Acesse `https://honeypot.seudominio.com:64298/` — sem aviso de certificado inválido.

### 6. Renovação automática

Certificados Let's Encrypt expiram a cada 90 dias. Configure um cron para renovar e reimplantar automaticamente:

```bash
sudo crontab -e
```

Adicione (troque `honeypot.seudominio.com` pelo seu domínio real):

```
0 3 * * * certbot renew --quiet --deploy-hook "cp /etc/letsencrypt/live/honeypot.seudominio.com/fullchain.pem /home/ec2-user/beeia/data/nginx/cert/beeia-fullchain.pem && cp /etc/letsencrypt/live/honeypot.seudominio.com/privkey.pem /home/ec2-user/beeia/data/nginx/cert/beeia-privkey.pem && chown 2000:2000 /home/ec2-user/beeia/data/nginx/cert/beeia-*.pem && chmod 640 /home/ec2-user/beeia/data/nginx/cert/beeia-*.pem && docker restart nginx"
```

### 7. Se quiser abrir o dashboard para terceiros (QA, orientador)

A regra de porta 64298 do grupo de segurança está restrita ao seu IP (passo 1). Para permitir acesso de outras origens, mude a origem da regra para `0.0.0.0/0` — a Basic Auth continua sendo a proteção real de acesso; a restrição por IP era só uma camada extra.

---

## Manutenção

```bash
# Ver status dos containers
docker ps

# Logs de um container específico
docker logs cowrie --tail 50
docker logs nginx --tail 50

# Logs do backend
sudo journalctl -u beeia-backend -f

# Reiniciar tudo
cd ~/beeia
sudo docker-compose restart
sudo systemctl restart beeia-backend
```

---

## Troubleshooting — problemas encontrados no primeiro deploy

| Sintoma | Causa | Correção |
|---|---|---|
| `docker: 'compose' is not a docker command` | Plugin não estava no caminho esperado pelo Docker instalado | Instalar o binário standalone (passo 3) |
| `Swap: 0B` (`free -h`) | User data sem a seção de swap | Criar manualmente: `fallocate -l 2G /swapfile; chmod 600 /swapfile; mkswap /swapfile; swapon /swapfile` |
| `scp` cria `frontend/dist/dist/...` | `frontend/dist` já existia no destino (versionado no git) | `mv dist dist_old && mv dist_old/dist dist && rm -rf dist_old` |
| `WEB_USER` continua com o valor de exemplo do README | Edição manual do `.env` não é suficiente/não persistiu | Gerar credencial real com `htpasswd -nb` e escrever direto em `data/nginx/conf/nginxpasswd` (passo 5) |
| `cat: nginxpasswd: Permission denied` | Arquivo pertence ao uid interno do container T-Pot (`2000`) | Normal — use `sudo cat` para conferir, ou `chmod 644` se precisar |
| `Error starting userland proxy: ... bind: address already in use` no `cowrie` | `sshd` real do SO ainda ocupa a porta 22 | `sudo systemctl disable --now sshd` (só depois de confirmar SSM, passo 6) |
| `sqlite3.OperationalError: unable to open database file` no backend | Diretório `data/` criado pelo Docker com dono diferente do `ec2-user` | `sudo chown ec2-user:ec2-user ~/beeia/data` (passo 7) |
| `ssh`: "host key changed" ao testar o honeypot | Esperado — porta 22 trocou de dono (sshd real → Cowrie) | `ssh-keygen -R <IP>` e reconectar |

---

## Antes de considerar "publicado"

Revise o checklist de [`md-usotcc/proteger-dashboard.md`](proteger-dashboard.md) — API key, CORS, porta 8000 bloqueada externamente, credenciais fortes — e lembre que o Dionaea armazena binários de malware capturados de verdade: confira os termos de uso do seu provedor de hospedagem antes de deixar o ambiente no ar por muito tempo.
