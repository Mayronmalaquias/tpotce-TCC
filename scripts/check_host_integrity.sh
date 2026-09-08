#!/usr/bin/env bash
# ==============================================================================
# BeeIA — Script de Auditoria de Integridade e Segurança do Host (VM)
# Projeto: BeeIA (TCC - IESB)
# Objetivo: Verificar integridade de binários/bibliotecas (FIM), contenção
#           de containers Docker, portas abertas, persistência e possíveis
#           indícios de Honeypot Breakout / Container Escape.
# ==============================================================================

set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORTS_DIR="$(pwd)/reports"
REPORT_FILE="${REPORTS_DIR}/host_integrity_${TIMESTAMP}.log"
BASELINE_FILE="${REPORTS_DIR}/baseline_critical_binaries_${TIMESTAMP}.sha256"

mkdir -p "${REPORTS_DIR}"

log() {
    local msg="[$(date +"%Y-%m-%d %H:%M:%S")] $1"
    echo -e "$msg"
    echo -e "$msg" | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" >> "${REPORT_FILE}"
}

header() {
    log "\n${BOLD}${BLUE}==============================================================================${NC}"
    log "${BOLD}${BLUE}  $1${NC}"
    log "${BOLD}${BLUE}==============================================================================${NC}"
}

pass() {
    log "  [${GREEN}PASS${NC}] $1"
}

warn() {
    log "  [${YELLOW}WARN${NC}] $1"
}

alert() {
    log "  [${RED}ALERT${NC}] $1"
}

info() {
    log "  [${CYAN}INFO${NC}] $1"
}

# ------------------------------------------------------------------------------
# 0. Verificação de Privilégios
# ------------------------------------------------------------------------------
if [ "${EUID}" -ne 0 ]; then
    echo -e "${RED}[ERRO] Este script precisa ser executado como ROOT (ou com sudo).${NC}"
    echo "Exemplo: sudo bash scripts/check_host_integrity.sh"
    exit 1
fi

clear 2>/dev/null || true
echo -e "${BOLD}${CYAN}"
echo "    ____             _____ ___ "
echo "   / __ )___  ___   /  _/   |  "
echo "  / __  / _ \/ _ \  / // /| |  "
echo " / /_/ /  __/  __/_/ // ___ |  "
echo "/_____/\___/\___//___/_/  |_|  "
echo "  Auditoria de Integridade & Contenção de Honeypot"
echo -e "${NC}"
echo "Relatório sendo salvo em: ${REPORT_FILE}"
sleep 1

# ------------------------------------------------------------------------------
# 1. Informações do Sistema Operacional
# ------------------------------------------------------------------------------
header "1. INFORMAÇÕES DO SISTEMA E KERNEL"
log "Hostname: $(hostname)"
log "Data/Hora: $(date)"
log "Uptime: $(uptime -p 2>/dev/null || uptime)"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    log "Distribuição: ${PRETTY_NAME:-Linux}"
else
    log "Distribuição: $(uname -s)"
fi
log "Kernel: $(uname -r)"

# ------------------------------------------------------------------------------
# 2. Contenção dos Containers Honeypot (Anti-Escape)
# ------------------------------------------------------------------------------
header "2. VERIFICAÇÃO DE CONTENÇÃO DOCKER (HONEYPOT ISOLATION)"

if ! command -v docker &>/dev/null; then
    warn "Docker não está instalado ou não foi encontrado no PATH."
else
    CONTAINERS=$(docker ps -a --format "{{.Names}}" 2>/dev/null || true)
    if [ -z "${CONTAINERS}" ]; then
        warn "Nenhum container Docker ativo no momento."
    else
        log "Containers encontrados: $(echo ${CONTAINERS} | tr '\n' ' ')"
        
        for c in ${CONTAINERS}; do
            # Checar se roda em modo Privileged
            PRIVILEGED=$(docker inspect --format '{{.HostConfig.Privileged}}' "$c" 2>/dev/null || echo "false")
            if [ "${PRIVILEGED}" == "true" ]; then
                alert "Container '$c' está rodando em MODO PRIVILEGIADO (--privileged)! Risco alto de escape."
            else
                pass "Container '$c' não é privilegiado (Privileged=false)."
            fi

            # Checar se o docker.sock está montado
            SOCK_MOUNT=$(docker inspect --format '{{range .Mounts}}{{if eq .Source "/var/run/docker.sock"}}{{.Source}} (rw={{.RW}}){{end}}{{end}}' "$c" 2>/dev/null || true)
            if [ -n "${SOCK_MOUNT}" ]; then
                if [[ "${SOCK_MOUNT}" == *"rw=true"* ]]; then
                    alert "Container '$c' possui montagem de ESCRITA no /var/run/docker.sock! Risco crítico de takeover do host."
                else
                    warn "Container '$c' possui /var/run/docker.sock montado como READ-ONLY (esperado em orquestradores como tpotinit)."
                fi
            else
                pass "Container '$c' NÃO possui acesso ao socket do Docker (/var/run/docker.sock)."
            fi

            # Checar ReadOnlyRootfs
            RO_ROOT=$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$c" 2>/dev/null || echo "false")
            if [ "${RO_ROOT}" == "true" ]; then
                pass "Container '$c' possui sistema de arquivos raiz em modo SOMENTE LEITURA (ReadOnlyRootfs=true)."
            else
                info "Container '$c' possui raiz com permissão de escrita padrão."
            fi
        done
    fi
fi

# ------------------------------------------------------------------------------
# 3. Integridade de Binários e Bibliotecas do Sistema (debsums / dpkg -V)
# ------------------------------------------------------------------------------
header "3. INTEGRIDADE DE PACOTES, BINÁRIOS E BIBLIOTECAS (FIM)"

if command -v debsums &>/dev/null; then
    info "Executando 'debsums -s' para verificar hashes de arquivos instalados via pacotes oficiais..."
    info "(Verificando se algum binário em /bin, /sbin, /usr/bin ou /usr/lib foi adulterado)"
    
    DEBSUMS_OUT=$(debsums -s 2>&1 || true)
    
    # Filtrar apenas binários e bibliotecas críticas
    CRITICAL_ALTERATIONS=$(echo "${DEBSUMS_OUT}" | grep -E "(/bin/|/sbin/|/lib/|/usr/bin/|/usr/sbin/|/usr/lib/)" || true)
    
    if [ -n "${CRITICAL_ALTERATIONS}" ]; then
        alert "ATENÇÃO! Foram detectados binários ou bibliotecas modificados:"
        log "${RED}${CRITICAL_ALTERATIONS}${NC}"
    else
        pass "Nenhum binário ou biblioteca do sistema foi modificado em relação aos hashes oficiais da distribuição!"
    fi

    # Alterações em arquivos de configuração comuns (/etc)
    ETC_ALTERATIONS=$(echo "${DEBSUMS_OUT}" | grep "/etc/" || true)
    if [ -n "${ETC_ALTERATIONS}" ]; then
        info "Arquivos de configuração (/etc) modificados legitimamente pelo administrador:"
        log "${ETC_ALTERATIONS}"
    fi
else
    warn "'debsums' não está instalado."
    info "Instale com: sudo apt update && sudo apt install -y debsums"
    info "Executando verificação alternativa rápida com 'dpkg -V' nos pacotes críticos..."
    
    CRITICAL_PKGS="coreutils bash openssh-server systemd libc-bin"
    for pkg in ${CRITICAL_PKGS}; do
        if dpkg -s "$pkg" &>/dev/null; then
            PKG_VERIFY=$(dpkg -V "$pkg" 2>&1 | grep -v "5c " || true)
            if [ -n "${PKG_VERIFY}" ]; then
                warn "Pacote '$pkg' possui arquivos com checksum divergente:\n${PKG_VERIFY}"
            else
                pass "Pacote essencial '$pkg' 100% íntegro segundo dpkg -V."
            fi
        fi
    done
fi

# ------------------------------------------------------------------------------
# 4. Auditoria de Contas, Privilégios e Persistência
# ------------------------------------------------------------------------------
header "4. AUDITORIA DE USUÁRIOS, PRIVILÉGIOS E PERSISTÊNCIA"

# Contas com UID 0
info "Verificando usuários com UID 0 (privilégio root)..."
UID_ZERO=$(awk -F: '($3 == 0) {print $1}' /etc/passwd)
if [ "${UID_ZERO}" == "root" ]; then
    pass "Apenas o usuário 'root' possui UID 0 no sistema."
else
    alert "ATENÇÃO: Múltiplos usuários possuem UID 0: ${UID_ZERO}"
fi

# Chaves SSH autorizadas
info "Verificando chaves SSH públicas autorizadas no host..."
for auth_file in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
    if [ -f "${auth_file}" ]; then
        KEY_COUNT=$(grep -v "^#" "${auth_file}" | grep -v "^$" | wc -l)
        info "Arquivo ${auth_file} contém ${KEY_COUNT} chave(s) cadastrada(s)."
        cat "${auth_file}" >> "${REPORT_FILE}"
    fi
done

# Agendamentos Cron
info "Verificando agendamentos de tarefas (cron / at)..."
CRON_FILES=$(ls -la /etc/cron* /var/spool/cron/crontabs 2>/dev/null || true)
echo "${CRON_FILES}" >> "${REPORT_FILE}"
pass "Tabelas do cron verificadas e salvas no relatório."

# Logins Recentes
info "Últimos logins bem-sucedidos no host:"
last -n 5 2>/dev/null | tee -a "${REPORT_FILE}" || true

# ------------------------------------------------------------------------------
# 5. Auditoria de Rede e Portas Escutando no Host
# ------------------------------------------------------------------------------
header "5. AUDITORIA DE PORTAS E CONEXÕES DE REDE"

info "Portas escutando (Listening Sockets) no host:"
if command -v ss &>/dev/null; then
    SOCKETS=$(ss -tulpn)
elif command -v netstat &>/dev/null; then
    SOCKETS=$(netstat -tulpn)
else
    SOCKETS="Comando ss/netstat não disponível."
fi
echo "${SOCKETS}" | tee -a "${REPORT_FILE}"

# Checar conexões de saída suspeitas
info "Conexões ativas de saída (verificando se o host está abrindo conexões remotas):"
OUTBOUND=$(ss -tp state established 2>/dev/null || true)
if [ -n "${OUTBOUND}" ]; then
    echo "${OUTBOUND}" | tee -a "${REPORT_FILE}"
else
    pass "Nenhuma conexão externa ativa suspeita originada do host."
fi

# ------------------------------------------------------------------------------
# 6. Geração de Baseline SHA-256 de Binários Críticos
# ------------------------------------------------------------------------------
header "6. GERAÇÃO DE BASELINE CRIPTOGRÁFICO DE BINÁRIOS CRÍTICOS"

info "Calculando hash SHA-256 dos principais binários de administração..."

CORE_BINARIES=(
    "/bin/bash"
    "/bin/sh"
    "/bin/login"
    "/bin/ls"
    "/bin/ps"
    "/usr/bin/sudo"
    "/usr/bin/ss"
    "/usr/bin/docker"
    "/usr/bin/dockerd"
    "/usr/sbin/sshd"
)

> "${BASELINE_FILE}"
for bin in "${CORE_BINARIES[@]}"; do
    if [ -f "$bin" ]; then
        sha256sum "$bin" | tee -a "${BASELINE_FILE}" >> "${REPORT_FILE}"
    fi
done
pass "Baseline SHA-256 salvo com sucesso em: ${BASELINE_FILE}"

# ------------------------------------------------------------------------------
# 7. Resumo Executivo e Diagnóstico
# ------------------------------------------------------------------------------
header "7. DIAGNÓSTICO FINAL"

log "${BOLD}Relatório completo gerado em:${NC} ${REPORT_FILE}"
log "${BOLD}Hashes SHA-256 salvos em:${NC} ${BASELINE_FILE}"

echo -e "\n${BOLD}${GREEN}==============================================================================${NC}"
echo -e "${BOLD}${GREEN}  AUDITORIA CONCLUÍDA!${NC}"
echo -e "${BOLD}${GREEN}==============================================================================${NC}"
echo -e "Você pode compartilhar o relatório '${REPORT_FILE}' ou enviar o resumo para o orientador."

