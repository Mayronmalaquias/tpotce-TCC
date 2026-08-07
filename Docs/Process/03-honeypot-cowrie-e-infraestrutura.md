# Processo 03 — Honeypot Cowrie e Infraestrutura Docker

## O que é um honeypot (contexto teórico)

Um honeypot é um ativo de informação cujo valor reside no **uso não autorizado, ilícito ou malicioso** de seus recursos (Spitzner, 2002). Diferente de sistemas de produção, não tem usuários legítimos nem tráfego autorizado — **qualquer interação é, por premissa, uma anomalia hostil**. Isso reduz drasticamente falsos positivos em relação a IDS convencionais baseados em assinatura/heurística.

Honeypots são categorizados pelo nível de interatividade concedido ao atacante:

- **Cowrie** (usado no BeeIA) — interatividade média/alta, emula um shell Linux SSH/Telnet completo. O atacante pode executar comandos, tentar elevar privilégios e explorar um sistema de arquivos simulado. Toda a sessão é capturada em logs estruturados JSON.
- **Dionaea** (citado no artigo, **não implementado no código**) — interatividade baixa/média, emula protocolos como SMB/HTTP/FTP/TFTP para capturar payloads de worms/botnets automaticamente.

## Processo de captura (Cowrie)

1. Cowrie escuta nas portas **22 (SSH)** e **23 (Telnet)**.
2. Ao receber uma conexão, emula um shell Linux interativo completo.
3. Cada evento da sessão (conexão, tentativa de login, comando executado, download, encerramento) é escrito como uma linha JSON em `data/cowrie/log/cowrie.json`.
4. Esse arquivo é um **volume compartilhado** com o backend, que faz tail contínuo dele (ver [06-backend-api-tempo-real.md](06-backend-api-tempo-real.md)).

### Eventos relevantes do Cowrie

| `eventid` | Significado |
|---|---|
| `cowrie.session.connect` | Nova conexão SSH/Telnet |
| `cowrie.login.failed` | Tentativa de login falhou |
| `cowrie.login.success` | Login bem-sucedido |
| `cowrie.command.input` | Comando digitado no shell falso |
| `cowrie.session.file_download` | Download de arquivo (wget/curl) |
| `cowrie.session.closed` | Sessão encerrada — **dispara a classificação** |

## Infraestrutura Docker

O `docker-compose.yml` segue a estrutura herdada do **T-Pot CE** (Telekom Security), da qual este repositório é um fork/derivado limpo (apenas o serviço Cowrie está ativo; outros honeypots do T-Pot podem ser adicionados no futuro).

### Serviços definidos

| Serviço | Função | Portas |
|---|---|---|
| `tpotinit` | Inicialização/orquestração do ambiente, `network_mode: host` | — |
| `cowrie` | Honeypot SSH/Telnet | 22, 23 |
| `nginx` | Proxy reverso para a interface web | 64297, 64294 |

### Volumes do Cowrie

```yaml
volumes:
  - ${TPOT_DATA_PATH}/cowrie/downloads:/home/cowrie/cowrie/dl
  - ${TPOT_DATA_PATH}/cowrie/keys:/home/cowrie/cowrie/etc
  - ${TPOT_DATA_PATH}/cowrie/log:/home/cowrie/cowrie/log
  - ${TPOT_DATA_PATH}/cowrie/log/tty:/home/cowrie/cowrie/log/tty
```

### Variáveis de ambiente (`.env`)

| Variável | Padrão | Descrição |
|---|---|---|
| `WEB_USER` | (vazio) | Credenciais de acesso web via nginx (gerar com `htpasswd`) |
| `TPOT_BLACKHOLE` | `DISABLED` | Nullrouting de IPs de scanners conhecidos |
| `TPOT_PERSISTENCE` | `on` | Mantém logs por N dias |
| `TPOT_PERSISTENCE_CYCLES` | `30` | Dias de retenção |
| `TPOT_ATTACKMAP_TEXT` | `ENABLED` | Exibe eventos no console |
| `TPOT_REPO` | `ghcr.io/telekom-security` | Registro das imagens Docker |
| `TPOT_VERSION` | `24.04.1` | Versão das imagens T-Pot |
| `TPOT_PULL_POLICY` | `always` | Política de download de imagem |
| `TPOT_DATA_PATH` | `./data` | Caminho de persistência dos dados/logs |
| `TPOT_OSTYPE` | `linux` | SO do host |

## Como subir o ambiente

```bash
# 1. Configurar WEB_USER no .env (veja md-usotcc/rodar-cowrie.md)
# 2. Subir os containers
docker compose up -d

# Verificar status
docker ps
docker logs cowrie
```

> O sistema foi desenvolvido para rodar em **Linux**. No Windows, use **WSL2** para Docker e backend.

## Protocolo de teste manual

Guia completo em [`md-usotcc/rodar-cowrie.md`](../../md-usotcc/rodar-cowrie.md) — inclui simulação de intrusão via SSH externo e inspeção do `cowrie.json` gerado. Também há [`md-usotcc/rodar-putty.md`](../../md-usotcc/rodar-putty.md) para testes via PuTTY (Windows).

## Pendência conhecida

O honeypot **Dionaea**, citado extensivamente no artigo como parte da arquitetura (captura de malware via SMB/HTTP/FTP/TFTP), **não está no `docker-compose.yml`**. Ver [10-limitacoes-e-trabalhos-futuros.md](10-limitacoes-e-trabalhos-futuros.md).
