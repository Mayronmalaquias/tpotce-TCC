# Guia de Segurança, Contenção e Integridade do Host (VM)

Este documento descreve as diretrizes de segurança aplicadas à máquina hospedeira (Host Linux) onde os honeypots do **BeeIA** estão em execução, detalhando a mitigação contra **Honeypot Breakout (Container Escape)** e os procedimentos de **FIM (File Integrity Monitoring)**.

---

## 1. Contexto e Modelo de Ameaça

Honeypots como Cowrie e Dionaea são projetados para atrair tráfego hostil da internet. Ao interagir com o honeypot, atacantes podem tentar:
1. **Explorar o container** (simulação interativa ou injeção de payload).
2. **Honeypot Escape (Fuga do Container):** Utilizar exploits de kernel ou falhas de configuração do Docker para escapar do ambiente de emulação e comprometer o sistema operacional host.
3. **Adulteração de Binários e Persistência:** Instalar rootkits ou alterar executáveis e bibliotecas essenciais (`/bin/ps`, `/bin/ls`, `/usr/bin/ss`, bibliotecas `.so`) para ocultar processos e manter acesso ao servidor físico/VM.

---

## 2. Camadas de Contenção Implementadas (Docker)

Para impedir que invasões nos honeypots alcancem o sistema operacional da máquina host, o BeeIA adota as seguintes defesas por design:

| Camada de Segurança | Implementação | Propósito |
|---|---|---|
| **Contêineres não privilegiados** | `privileged: false` | Impede que o processo dentro do container tenha acesso direto aos dispositivos de hardware do host. |
| **Sistema de Arquivos Read-Only** | `read_only: true` (no `docker-compose.yml`) | O sistema de arquivos raiz do container é somente-leitura. Malwares baixados pelo atacante não conseguem alterar binários do container. |
| **Volumes Estritos e Isolados** | Apenas `/data/...` montados | Nenhum diretório sensível do host (`/etc`, `/bin`, `/root`) é compartilhado com os honeypots. |
| **Isolamento do Docker Socket** | `/var/run/docker.sock` inacessível | Honeypots não possuem acesso ao socket do Docker, impossibilitando a criação de containers com privilégios de root sobre o host. |
| **Armazenamento Volátil** | `tmpfs` para `/tmp` | Dados transitórios são armazenados na memória RAM (`tmpfs`), sendo descartados no reinício. |

---

## 3. Como Executar a Auditoria de Integridade no Host

Foi criado o script automatizado [`scripts/check_host_integrity.sh`](../scripts/check_host_integrity.sh). Ele realiza a checagem completa de integridade de binários, contenção do docker, usuários e portas abertas.

### Passo a passo na VM:

```bash
# 1. Acesse o diretório do projeto na VM
cd ~/tpotce-TCC

# 2. Garanta permissão de execução
chmod +x scripts/check_host_integrity.sh

# 3. Execute como root (ou sudo)
sudo bash scripts/check_host_integrity.sh
```

### O que o script faz automaticamente:
1. **Verificação de Isolamento Docker:** Inspeciona os containers ativos para confirmar que não operam em modo `--privileged` e que não têm acesso ao `docker.sock`.
2. **Integridade de Binários e Bibliotecas (`debsums`):** Compara os hashes MD5 de todos os executáveis do sistema (`/bin`, `/sbin`, `/usr/bin`, `/usr/lib`) com os hashes oficiais assinados pelo repositório da distribuição Debian/Ubuntu.
3. **Auditoria de Privilégios (UID 0):** Checa se existem contas ocultas com privilégio de root em `/etc/passwd`.
4. **Persistência e Chaves SSH:** Inspeciona `authorized_keys` e crontabs do sistema.
5. **Portas e Conexões Ativas:** Analisa sockets abertos (`ss -tulpn`) e conexões de saída ativas (verificando se o host não foi transformado em botnet ou abriu reverse shell).
6. **Geração de Baseline SHA-256:** Gera um arquivo de hashes dos binários administrativos críticos em `reports/baseline_critical_binaries_<data>.sha256`.

O relatório final é salvo em `reports/host_integrity_<data>.log`.

---

## 4. Monitoramento Contínuo com AIDE (File Integrity Monitoring)

Para garantir integridade contínua a longo prazo (como exigido em ambientes de segurança de alta conformidade):

```bash
# 1. Instalar o AIDE
sudo apt update && sudo apt install -y aide

# 2. Inicializar o banco de hashes de referência
sudo aideinit

# 3. Mover o banco gerado para o arquivo ativo
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# 4. Para verificar a integridade a qualquer momento:
sudo aide --check
```

---

## 5. Texto Sugerido para a Seção de Metodologia / Infraestrutura do TCC

Copie e adapte o trecho abaixo no artigo/monografia:

> **Garantia de Isolamento e Monitoramento de Integridade do Host:**
>
> *"Tendo em vista que a exposição de honeypots de média e alta interatividade à internet aberta acarreta o risco inerente de honeypot breakout (fuga de container) e comprometimento da máquina hospedeira, foram adotados mecanismos rigorosos de contenção. Os honeypots Cowrie e Dionaea operam em contêineres Docker isolados, executados sem privilégios administrativos (`privileged: false`), com sistema de arquivos raiz montado em modo somente-leitura (`read_only: true`), e sem permissão de acesso ao socket de gerenciamento do Docker (`/var/run/docker.sock`). Adicionalmente, implementou-se uma rotina de monitoramento de integridade de arquivos (File Integrity Monitoring – FIM) no host Linux, baseada na verificação contínua dos hashes criptográficos de binários e bibliotecas de sistema via `debsums` e `AIDE`, além de auditoria periódica de persistência e portas de rede, assegurando que o ambiente hospedeiro permaneça não comprometido durante todo o período de coleta."*

