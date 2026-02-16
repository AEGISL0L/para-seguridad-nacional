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

# ── Umask restrictiva ────────────────────────────────────────
# Evita que backups de /etc/shadow, configs SSH, etc. se creen world-readable
umask 0077

# ── Asegurar /usr/sbin en PATH (nft, getcap, setcap, etc.) ──
[[ ":$PATH:" != *":/usr/sbin:"* ]] && export PATH="/usr/sbin:$PATH"

# ── Determinar ruta de lib/ ────────────────────────────────
_SECURIZAR_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Cargar configuracion opcional ───────────────────────────
_SECURIZAR_CONF="${_SECURIZAR_LIB_DIR}/../securizar.conf"
if [[ -f "$_SECURIZAR_CONF" ]]; then
    # Validar que securizar.conf es seguro antes de sourcear
    _conf_owner=$(stat -c '%u' "$_SECURIZAR_CONF" 2>/dev/null || echo "")
    _conf_perms=$(stat -c '%a' "$_SECURIZAR_CONF" 2>/dev/null || echo "")
    _conf_safe=1
    if [[ "$_conf_owner" != "0" ]]; then
        if [[ $EUID -eq 0 ]]; then
            chown root:root "$_SECURIZAR_CONF" 2>/dev/null && \
                chmod 600 "$_SECURIZAR_CONF" 2>/dev/null && \
                _conf_perms=$(stat -c '%a' "$_SECURIZAR_CONF" 2>/dev/null || echo "")
        else
            echo "AVISO: securizar.conf no es propiedad de root (uid=$_conf_owner), ignorando" >&2
            _conf_safe=0
        fi
    fi
    if [[ "$_conf_safe" == "1" ]] && [[ "${_conf_perms:2:1}" =~ [2367] ]]; then
        echo "AVISO: securizar.conf es writable por otros (permisos=$_conf_perms), ignorando" >&2
        _conf_safe=0
    elif [[ "$_conf_safe" == "1" ]]; then
        # Verificar que solo contiene asignaciones de variables (KEY=value), comentarios o lineas vacias
        while IFS= read -r _line; do
            # Quitar espacios iniciales
            _line="${_line#"${_line%%[![:space:]]*}"}"
            [[ -z "$_line" || "$_line" == \#* ]] && continue
            if ! [[ "$_line" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then
                echo "AVISO: securizar.conf contiene sintaxis no permitida: $_line" >&2
                _conf_safe=0
                break
            fi
        done < "$_SECURIZAR_CONF"
    fi
    if [[ "$_conf_safe" == "1" ]]; then
        # shellcheck source=/dev/null
        source "$_SECURIZAR_CONF"
    fi
    unset _conf_owner _conf_perms _conf_safe _line
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
_log_emit() {
    if [[ -n "${SECURIZAR_LOG_TO_FILE:-}" ]]; then
        echo -e "$1" | tee -a "$SECURIZAR_LOG_TO_FILE"
    else
        echo -e "$1"
    fi
}

log_info()    { _log_emit "${GREEN}[+]${NC} $1"; }
log_warn()    { _log_emit "${YELLOW}[!]${NC} $1"; }
log_error()   { _log_emit "${RED}[X]${NC} $1"; }
log_section() { _log_emit "\n${CYAN}══════════════════════════════════════════${NC}"; _log_emit "${CYAN}  $1${NC}"; _log_emit "${CYAN}══════════════════════════════════════════${NC}"; }
log_alert()   { _log_emit "${RED}${BOLD}[!!!]${NC} $1"; }

# ── Feedback visual de cambios ────────────────────────────────
_SECURIZAR_CHANGES=()
_SECURIZAR_SKIPPED=()
_SECURIZAR_ALREADY=()

# log_change "Verbo" "detalle" -> imprime "  -> Verbo: detalle" en bold blanco
log_change() {
    local verb="$1" detail="$2"
    _SECURIZAR_CHANGES+=("  -> ${verb}: ${detail}")
    _log_emit "  ${BOLD}${WHITE}->${NC} ${BOLD}${verb}:${NC} ${detail}"
}

# log_skip "descripcion" -> imprime "  -- Omitido: desc" en dim
log_skip() {
    _SECURIZAR_SKIPPED+=("  -- Omitido: $1")
    _log_emit "  ${DIM}-- Omitido: $1${NC}"
}

# log_already "descripcion" -> imprime "  == Ya aplicado: desc" en verde dim
log_already() {
    _SECURIZAR_ALREADY+=("  == Ya aplicado: $1")
    _log_emit "  ${GREEN}==${NC} ${DIM}Ya aplicado: $1${NC}"
}

# show_changes_summary - Resumen con contadores al final del script
show_changes_summary() {
    local n_changes=${#_SECURIZAR_CHANGES[@]}
    local n_skipped=${#_SECURIZAR_SKIPPED[@]}
    local n_already=${#_SECURIZAR_ALREADY[@]}

    [[ $n_changes -eq 0 && $n_skipped -eq 0 && $n_already -eq 0 ]] && return 0

    local _out=""
    _out+="\n  ${CYAN}┌── RESUMEN DE CAMBIOS ──────────────────────────────────${NC}\n"
    _out+="  ${CYAN}│${NC}  ${BOLD}${n_changes} aplicados${NC} · ${DIM}${n_skipped} omitidos${NC} · ${GREEN}${n_already} ya presentes${NC}\n"
    _out+="  ${CYAN}│${NC}\n"

    local entry
    for entry in "${_SECURIZAR_CHANGES[@]}"; do
        _out+="  ${CYAN}│${NC} ${entry}\n"
    done

    if [[ $n_already -gt 0 ]]; then
        _out+="  ${CYAN}│${NC}\n"
        for entry in "${_SECURIZAR_ALREADY[@]}"; do
            _out+="  ${CYAN}│${NC} ${GREEN}${entry}${NC}\n"
        done
    fi

    if [[ $n_skipped -gt 0 ]]; then
        _out+="  ${CYAN}│${NC}\n"
        for entry in "${_SECURIZAR_SKIPPED[@]}"; do
            _out+="  ${CYAN}│${NC} ${DIM}${entry}${NC}\n"
        done
    fi

    _out+="  ${CYAN}└────────────────────────────────────────────────────────${NC}"

    _log_emit "$_out"
}

# reset_changes - Vacia arrays (para modulos inline del menu)
reset_changes() {
    _SECURIZAR_CHANGES=()
    _SECURIZAR_SKIPPED=()
    _SECURIZAR_ALREADY=()
}

# ── Helpers de verificacion de estado ──────────────────────────
check_sysctl()          { [[ "$(sysctl -n "$1" 2>/dev/null)" == "$2" ]]; }
check_file_exists()     { [[ -f "$1" ]]; }
check_file_contains()   { grep -q "$2" "$1" 2>/dev/null; }
check_dir_exists()      { [[ -d "$1" ]]; }
check_perm()            { [[ "$(stat -c '%a' "$1" 2>/dev/null)" == "$2" ]]; }
check_service_active()  { systemctl is-active --quiet "$1" 2>/dev/null; }
check_service_enabled() { systemctl is-enabled --quiet "$1" 2>/dev/null; }
check_executable()      { [[ -x "$1" ]]; }
check_pkg()             { pkg_is_installed "$1" 2>/dev/null; }


# ── Pre-scan: salida temprana si todo esta aplicado ────────────
_PRECHECK_OK=0
_PRECHECK_TOTAL=0

_precheck() { _PRECHECK_TOTAL=$1; _PRECHECK_OK=0; }
_pc() { eval "$@" && ((_PRECHECK_OK++)) || true; }
_precheck_result() {
    if [[ $_PRECHECK_OK -eq $_PRECHECK_TOTAL ]]; then
        log_info "Todas las ${_PRECHECK_TOTAL} secciones ya estan aplicadas"
        log_info "No es necesario ejecutar este modulo"
        exit 0
    elif [[ $_PRECHECK_OK -gt 0 ]]; then
        log_info "${_PRECHECK_OK}/${_PRECHECK_TOTAL} secciones ya aplicadas (se omitiran automaticamente)"
    fi
}

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

    # Validar que el directorio base existe y es escribible
    if [[ ! -d "$base" ]]; then
        log_error "Directorio de backup no existe: $base"
        return 1
    fi
    if [[ ! -w "$base" ]]; then
        log_error "Directorio de backup no es escribible: $base"
        return 1
    fi

    # Avisar si hay poco espacio en disco (<50MB)
    local avail_kb
    avail_kb=$(df -k "$base" 2>/dev/null | awk 'NR==2 {print $4}') || true
    if [[ -n "${avail_kb:-}" ]] && [[ "$avail_kb" -lt 51200 ]]; then
        log_warn "Espacio en disco bajo en $base: ${avail_kb}KB disponibles (<50MB)"
    fi

    BACKUP_DIR="${base}/${name}-$(date +%Y%m%d-%H%M%S)"
    if ! mkdir -p "$BACKUP_DIR"; then
        log_error "No se pudo crear directorio de backup: $BACKUP_DIR"
        return 1
    fi
    log_info "Backup en: $BACKUP_DIR"
    log_change "Backup" "directorio: $BACKUP_DIR"
    export BACKUP_DIR
}

# ── securizar_setup_traps [cleanup_func] ─────────────────────
# Instala traps ERR y EXIT para diagnóstico de errores.
# Argumento opcional: nombre de función de limpieza a ejecutar en EXIT.
_SECURIZAR_CLEANUP_FUNC=""

_securizar_exit_handler() {
    local exit_code=$?
    if [[ -n "${_SECURIZAR_CLEANUP_FUNC:-}" ]] && declare -f "${_SECURIZAR_CLEANUP_FUNC}" &>/dev/null; then
        "${_SECURIZAR_CLEANUP_FUNC}" || true
    fi
    if [[ $exit_code -ne 0 ]]; then
        log_warn "Script terminó con código de error $exit_code"
        if [[ -n "${BACKUP_DIR:-}" ]] && [[ -d "${BACKUP_DIR:-}" ]]; then
            log_warn "Backups en: ${BACKUP_DIR:-}"
        fi
    fi
}

securizar_setup_traps() {
    _SECURIZAR_CLEANUP_FUNC="${1:-}"
    trap 'log_error "Error: comando \"${BASH_COMMAND:-}\" falló en línea ${LINENO:-?} (código: $?)"' ERR
    trap '_securizar_exit_handler' EXIT
}

# ── get_privileged_group ──────────────────────────────────────
# Devuelve el grupo privilegiado del sistema (wheel o sudo)
get_privileged_group() {
    if getent group wheel &>/dev/null; then
        echo "wheel"
    elif getent group sudo &>/dev/null; then
        echo "sudo"
    else
        echo "root"
    fi
}

# ── Helpers de escritura segura ───────────────────────────────

# Crea un script ejecutable con contenido via stdin (heredoc)
safe_create_script() {
    local path="$1" mode="${2:-755}"
    cat > "$path"
    chmod "$mode" "$path"
    log_change "Creado" "$path"
}

# Escribe fichero sysctl y recarga
safe_write_sysctl() {
    local name="$1"
    local path="/etc/sysctl.d/${name}.conf"
    cat > "$path"
    chmod 644 "$path"
    log_change "Creado" "$path"
    /usr/sbin/sysctl --system > /dev/null 2>&1 || true
    log_change "Aplicado" "sysctl --system"
}

# Crea tarea cron con contenido via stdin
safe_write_cron() {
    local freq="$1" name="$2"
    local path="/etc/cron.${freq}/${name}"
    cat > "$path"
    chmod 700 "$path"
    log_change "Creado" "$path"
}

# Escribe reglas de audit y las carga
safe_write_audit_rules() {
    local name="$1"
    local path="/etc/audit/rules.d/${name}.rules"
    mkdir -p /etc/audit/rules.d
    cat > "$path"
    chmod 640 "$path"
    log_change "Creado" "$path"
    if command -v augenrules &>/dev/null; then
        augenrules --load 2>/dev/null || true
    elif command -v auditctl &>/dev/null; then
        auditctl -R "$path" 2>/dev/null || true
    fi
    log_change "Aplicado" "audit rules (${name})"
}

# Escribe drop-in de sshd y recarga con validación
safe_write_sshd_dropin() {
    local name="$1"
    local path="/etc/ssh/sshd_config.d/${name}.conf"
    mkdir -p /etc/ssh/sshd_config.d
    cat > "$path"
    log_change "Creado" "$path"
    if ! grep -q "^Include /etc/ssh/sshd_config.d/" /etc/ssh/sshd_config 2>/dev/null; then
        cp /etc/ssh/sshd_config "${BACKUP_DIR:-/tmp}/sshd_config.bak" 2>/dev/null || true
        sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
        log_change "Modificado" "/etc/ssh/sshd_config (Include)"
    fi
    if sshd -t 2>/dev/null; then
        systemctl reload "$SSH_SERVICE_NAME" 2>/dev/null || true
        log_change "Servicio" "$SSH_SERVICE_NAME reload"
    else
        log_error "Sintaxis SSH invalida - revirtiendo $path"
        rm -f "$path"
        return 1
    fi
}

# Hace backup de un fichero al BACKUP_DIR
safe_backup_file() {
    local file="$1"
    if [[ -f "$file" ]] && [[ -n "${BACKUP_DIR:-}" ]]; then
        cp -a "$file" "$BACKUP_DIR/" 2>/dev/null || true
        log_change "Backup" "$file"
    fi
}

# Actualiza o añade clave=valor en fichero de configuración
safe_update_config_key() {
    local file="$1" key="$2" value="$3" sep="${4:-\t}"
    if grep -q "^${key}" "$file" 2>/dev/null; then
        sed -i "s|^${key}.*|${key}${sep}${value}|" "$file"
    else
        printf '%s%s%s\n' "$key" "$sep" "$value" >> "$file"
    fi
    log_change "Modificado" "${file} -> ${key}=${value}"
}

# ── Carga validada de modulos ────────────────────────────────
_securizar_source_lib() {
    local lib_file="$1"
    if [[ ! -f "$lib_file" ]]; then
        echo "FATAL: Biblioteca no encontrada: $lib_file" >&2
        exit 1
    fi
    # shellcheck source=/dev/null
    source "$lib_file"
}

_securizar_source_lib "${_SECURIZAR_LIB_DIR}/securizar-distro.sh"
_securizar_source_lib "${_SECURIZAR_LIB_DIR}/securizar-pkg-map.sh"
_securizar_source_lib "${_SECURIZAR_LIB_DIR}/securizar-pkg.sh"
_securizar_source_lib "${_SECURIZAR_LIB_DIR}/securizar-firewall.sh"
_securizar_source_lib "${_SECURIZAR_LIB_DIR}/securizar-paths.sh"

# Metasploit (opcional - no fatal si no existe)
if [[ -f "${_SECURIZAR_LIB_DIR}/securizar-msf.sh" ]]; then
    _securizar_source_lib "${_SECURIZAR_LIB_DIR}/securizar-msf.sh"
fi

# ── SSH_SERVICE_NAME ─────────────────────────────────────────
# Debian usa ssh.service, el resto usa sshd.service
if [[ "$DISTRO_FAMILY" == "debian" ]]; then
    SSH_SERVICE_NAME="ssh"
else
    SSH_SERVICE_NAME="sshd"
fi
export SSH_SERVICE_NAME
