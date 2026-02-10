#!/bin/bash
# ============================================================
# securizar-common.sh - Punto de entrada unico de la biblioteca
# ============================================================
# Carga todos los modulos de lib/ y provee funciones comunes:
#   Colores, logging, ask(), require_root(), init_backup()
# ============================================================
# Uso desde cualquier script:
#   SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#   source "${SCRIPT_DIR}/lib/securizar-common.sh"
# ============================================================

[[ -n "${_SECURIZAR_COMMON_LOADED:-}" ]] && return 0
_SECURIZAR_COMMON_LOADED=1

# ── Determinar ruta de lib/ ────────────────────────────────
_SECURIZAR_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Cargar configuracion opcional ───────────────────────────
_SECURIZAR_CONF="${_SECURIZAR_LIB_DIR}/../securizar.conf"
if [[ -f "$_SECURIZAR_CONF" ]]; then
    # shellcheck source=/dev/null
    source "$_SECURIZAR_CONF"
fi

# ── Colores ─────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
ITALIC='\033[3m'
UNDERLINE='\033[4m'
NC='\033[0m'

# Colores de fondo (usados por securizar-menu.sh)
BG_GREEN='\033[42;30m'
BG_RED='\033[41;37m'
BG_YELLOW='\033[43;30m'
BG_CYAN='\033[46;30m'
BG_BLUE='\033[44;37m'
BG_MAGENTA='\033[45;37m'

# ── Logging ─────────────────────────────────────────────────
if [[ -n "${SECURIZAR_LOG_TO_FILE:-}" ]]; then
    log_info()    { echo -e "${GREEN}[+]${NC} $1" | tee -a "$SECURIZAR_LOG_TO_FILE"; }
    log_warn()    { echo -e "${YELLOW}[!]${NC} $1" | tee -a "$SECURIZAR_LOG_TO_FILE"; }
    log_error()   { echo -e "${RED}[X]${NC} $1" | tee -a "$SECURIZAR_LOG_TO_FILE"; }
    log_section() { echo -e "\n${CYAN}══════════════════════════════════════════${NC}" | tee -a "$SECURIZAR_LOG_TO_FILE"; echo -e "${CYAN}  $1${NC}" | tee -a "$SECURIZAR_LOG_TO_FILE"; echo -e "${CYAN}══════════════════════════════════════════${NC}" | tee -a "$SECURIZAR_LOG_TO_FILE"; }
    log_alert()   { echo -e "${RED}${BOLD}[!!!]${NC} $1" | tee -a "$SECURIZAR_LOG_TO_FILE"; }
else
    log_info()    { echo -e "${GREEN}[+]${NC} $1"; }
    log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
    log_error()   { echo -e "${RED}[X]${NC} $1"; }
    log_section() { echo -e "\n${CYAN}══════════════════════════════════════════${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}══════════════════════════════════════════${NC}"; }
    log_alert()   { echo -e "${RED}${BOLD}[!!!]${NC} $1"; }
fi

# ── ask() ───────────────────────────────────────────────────
ask() {
    read -p "$1 [s/N]: " resp
    [[ "$resp" =~ ^[sS]$ ]]
}

# ── require_root ────────────────────────────────────────────
require_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Este script debe ejecutarse como root: sudo bash $0"
        exit 1
    fi
}

# ── init_backup name ────────────────────────────────────────
# Crea directorio de backup y exporta BACKUP_DIR
init_backup() {
    local name="${1:-backup}"
    local base="${SECURIZAR_BACKUP_BASE:-/root}"
    BACKUP_DIR="${base}/${name}-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    log_info "Backup en: $BACKUP_DIR"
    export BACKUP_DIR
}

# ── Cargar modulos ──────────────────────────────────────────
source "${_SECURIZAR_LIB_DIR}/securizar-distro.sh"
source "${_SECURIZAR_LIB_DIR}/securizar-pkg-map.sh"
source "${_SECURIZAR_LIB_DIR}/securizar-pkg.sh"
source "${_SECURIZAR_LIB_DIR}/securizar-firewall.sh"
source "${_SECURIZAR_LIB_DIR}/securizar-paths.sh"
