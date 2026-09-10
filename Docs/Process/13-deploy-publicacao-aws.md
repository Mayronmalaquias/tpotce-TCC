# Processo 13 — Publicação em Produção (AWS EC2)

Este processo documenta a transição do BeeIA de "roda localmente" para "publicado numa instância real, alcançável pela internet" — decisões de infraestrutura, por quê cada uma foi tomada, e os problemas reais encontrados no primeiro deploy. Para os comandos exatos, passo a passo, use [`md-usotcc/publicar-aws.md`](../../md-usotcc/publicar-aws.md); este documento explica o *porquê* de cada escolha.

## Por que AWS EC2 (tier gratuito)

O projeto tinha ~US$200 em créditos AWS disponíveis, mas a decisão foi **não depender deles** e ficar inteiramente dentro do free tier — elimina risco de cobrança surpresa num projeto de TCC sem orçamento dedicado:

- **Instância:** `t3.micro` (2 vCPU, 1 GiB RAM) — o único tipo coberto pelo free tier de 12 meses.
- **Especificação de crédito: "Standard"**, não "Unlimited" — `t3.micro` é uma instância *burstable*; no modo Unlimited, picos sustentados de CPU são cobrados à parte. Standard simplesmente limita a performance ao invés de gerar custo.
- **Armazenamento:** 20 GiB gp3 (dentro dos 30 GiB gratuitos).
- **AMI:** Amazon Linux 2023 — já vem com o agente SSM pré-instalado (ver seção de acesso administrativo).

## Topologia da instância

Uma única VM concentra tudo:

```
EC2 t3.micro (Amazon Linux 2023)
├── Docker Compose (honeypots + proxy)
│   ├── tpotinit   — inicialização/orquestração do ambiente T-Pot
│   ├── cowrie     — honeypot SSH/Telnet (portas 22/23)
│   ├── dionaea    — honeypot multi-protocolo (21,42,69,135,443,445,1433,1723,1883,3306,5060,27017)
│   └── nginx      — proxy reverso com Basic Auth (porta 64298)
└── backend BeeIA — processo systemd (uvicorn), FORA do Docker
```

**Por que o backend roda fora do Docker:** reaproveita a mesma venv Python usada em desenvolvimento, sem precisar manter um `Dockerfile` extra e reconstruir imagem a cada mudança de código — no contexto de um TCC com prazo curto, iterar direto via `systemctl restart` + `journalctl` é mais rápido que rebuildar container. O container `nginx` alcança esse processo do host via `host.docker.internal`, resolvido com `extra_hosts: ["host.docker.internal:host-gateway"]` no `docker-compose.yml` (ver [06-backend-api-tempo-real.md](06-backend-api-tempo-real.md)).

## Acesso administrativo: SSM em vez de SSH

Problema estrutural: **o Cowrie precisa ocupar a porta 22** para ser um honeypot SSH convincente — mas a porta 22 já é usada pelo `sshd` real do sistema operacional, usado normalmente para administração remota. As duas coisas não podem escutar na mesma porta.

Decisão: abrir mão do SSH para administração e usar **AWS Systems Manager Session Manager** desde o início —

1. A instância recebe uma *IAM instance profile* com a policy `AmazonSSMManagedInstanceCore`.
2. Toda administração (deploy, debug, comandos) acontece via SSM, sem chave SSH.
3. Só depois de confirmar que o SSM funciona é que o `sshd` real é desativado (`systemctl disable --now sshd`) — liberando a porta 22 para o container do Cowrie.

Essa ordem importa: desativar o `sshd` antes de validar o SSM deixaria a instância sem nenhum acesso administrativo em caso de falha.

## Grupo de segurança

| Porta(s) | Serviço | Origem recomendada | Motivo |
|---|---|---|---|
| 22, 23 | Cowrie (SSH/Telnet falsos) | `0.0.0.0/0` | Precisa estar aberto — é o honeypot |
| 21, 42, 69/udp, 135, 443, 445, 1433, 1723, 1883, 3306, 5060 tcp+udp, 27017 | Dionaea | `0.0.0.0/0` | Idem — superfície de captura |
| 64298 | Dashboard (nginx + Basic Auth) | Restrito (IP próprio) por padrão; `0.0.0.0/0` se precisar dar acesso a terceiros (QA, orientador) | Não é honeypot — Basic Auth é a proteção real, a restrição de IP é uma camada extra |
| 80 | Desafio HTTP-01 do Let's Encrypt (opcional) | `0.0.0.0/0` | Só necessário se for usar domínio próprio com certificado confiável — ver seção abaixo |

## Armazenamento e swap

`t3.micro` tem apenas 1 GiB de RAM — insuficiente para instalar dependências Python (scikit-learn, pandas) e rodar os 4 containers simultaneamente sem estourar memória. Foi criado manualmente um swapfile de 2 GiB (`fallocate` + `mkswap` + `swapon`, persistido em `/etc/fstab`) antes de subir o `docker-compose`.

## Backend como serviço systemd

Unit `beeia-backend.service`: `User=ec2-user`, `WorkingDirectory` na venv do backend, `EnvironmentFile=.env`, `Restart=always`. Roda em paralelo aos containers Docker, escutando em `0.0.0.0:8000` — alcançável apenas pelo `nginx` (via `host.docker.internal`) e por `localhost`, nunca exposto direto à internet (ver checklist de segurança em [`md-usotcc/proteger-dashboard.md`](../../md-usotcc/proteger-dashboard.md)).

**Problema real encontrado:** a pasta `data/` (onde o SQLite cria `beeia.db`) já existia no host — criada previamente pelos bind mounts do Docker Compose para os volumes dos honeypots — com dono/permissão que não permitiam ao `ec2-user` (dono do processo systemd) escrever ali. `database.init()` já cria o diretório-pai automaticamente (`DB_PATH.parent.mkdir(parents=True, exist_ok=True)`), mas isso não ajuda quando o diretório já existe com o dono errado. Corrigido com `chown` **não-recursivo**, aplicado só na pasta raiz `data/` — preservando o dono original (uid `2000`, usado internamente pelas imagens T-Pot) nas subpastas de cada honeypot.

## Camada opcional: domínio próprio + certificado confiável

Por padrão, `docker/nginx/dist/conf/beeia.conf` usa o certificado autoassinado que já vem com a imagem `nginx` do T-Pot (`/etc/nginx/cert/nginx.crt`) — funcional, mas gera aviso de segurança no navegador. Quando há um domínio próprio disponível, é possível trocar por um certificado confiável via **Let's Encrypt** (`certbot`, modo `standalone`), sem exigir mudança nenhuma na imagem Docker: o volume `${TPOT_DATA_PATH}/nginx/cert` já é montado inteiro em `/etc/nginx/cert/` no container, então basta colocar os arquivos do Let's Encrypt lá e apontar `ssl_certificate`/`ssl_certificate_key` para eles.

Ponto de atenção: o IP público de uma instância EC2 **muda a cada stop/start**, a menos que se associe um **Elastic IP** (gratuito enquanto associado a uma instância em execução). Um registro DNS apontando para o IP dinâmico quebra na primeira reinicialização — associar o Elastic IP antes de criar o registro DNS é pré-requisito, não opcional.

Passo a passo completo (DNS, `certbot`, edição do `beeia.conf`, renovação automática via cron) em [`md-usotcc/publicar-aws.md`](../../md-usotcc/publicar-aws.md#dominio-proprio-e-certificado-confiavel-lets-encrypt).

## Problemas reais encontrados no primeiro deploy

| Problema | Causa | Correção |
|---|---|---|
| `docker: 'compose' is not a docker command` | Plugin do Docker Compose não estava no diretório escaneado pelo Docker instalado via user-data | Binário standalone `docker-compose` instalado direto em `/usr/local/bin` |
| `Swap: 0B` | Script de user-data usado no launch não incluía a criação de swap | Swapfile de 2 GiB criado manualmente pós-boot |
| `scp -r frontend\dist` duplicou em `dist/dist/...` | `frontend/dist` já estava versionado no git (não deveria) — já existia no clone antes do `scp`, que copiou o conteúdo *para dentro* do diretório existente em vez de substituí-lo | Diretório corrigido manualmente; `frontend/dist` deveria estar no `.gitignore` |
| `WEB_USER` continuava com o valor de exemplo do README (`meu_usuario`) | Edição via `nano` não persistiu | Credenciais reais geradas com `htpasswd -nb`, escritas diretamente no arquivo montado (`data/nginx/conf/nginxpasswd`) via `sudo tee`, com o `.env` sincronizado via `sed` |
| `cat: nginxpasswd: Permission denied` | Arquivo pertence ao uid `2000` (usuário interno do container T-Pot) — permissão `rwxrwxr--` já permitia leitura por "outros", mas o susto valeu a checagem | `chmod 644` (ou `sudo cat`) confirma o conteúdo sem alterar o funcionamento |
| `bind: address already in use` no container `cowrie` | O `sshd` real do SO ainda ocupava a porta 22 | `systemctl disable --now sshd` (só depois de confirmar acesso via SSM) |
| `sqlite3.OperationalError: unable to open database file` no `beeia-backend.service` | Diretório `data/` já existia com dono diferente do `ec2-user` (criado pelos bind mounts do Docker) | `chown ec2-user:ec2-user data/` (não-recursivo) |

## Validação end-to-end realizada

1. `docker ps` — 4 containers (`tpotinit`, `cowrie`, `dionaea`, `nginx`) em execução/saudáveis.
2. `systemctl status beeia-backend` — `active (running)`, `Application startup complete` no log.
3. `curl -H "X-API-Key: ..." http://localhost:8000/api/stats` — resposta JSON válida.
4. Acesso ao dashboard via `https://<IP>:64298/` — Basic Auth solicitado, painel carrega.
5. Ataque real simulado: `ssh root@<IP>` a partir de outra máquina cai no shell falso do Cowrie; comandos digitados (`whoami`, `cat /etc/passwd`, `wget ...`) geram uma sessão completa que aparece no feed do dashboard em tempo real, classificada pelo modelo de ML.

## Próximo processo

Não há um próximo processo numerado — este é o último elo da cadeia (código → treino → deploy). Para a visão consolidada de tudo, volte ao [PROJECT_CONTEXT.md](../../PROJECT_CONTEXT.md).
