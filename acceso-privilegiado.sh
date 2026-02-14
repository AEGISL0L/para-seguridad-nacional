#!/bin/bash
# ============================================================
# acceso-privilegiado.sh - Modulo 74: Gestion de Acceso Privilegiado
# ============================================================
# Secciones:
#   S1  - Inventario de acceso privilegiado
#   S2  - Grabacion de sesiones privilegiadas
#   S3  - Politicas sudo granulares
#   S4  - Restriccion su y escalada
#   S5  - Just-In-Time access
#   S6  - Alertas de uso privilegiado
#   S7  - Control de capabilities
#   S8  - Tokens y credenciales temporales
#   S9  - Breakglass procedure
#   S10 - Auditoria integral acceso privilegiado
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "privileged-access"
securizar_setup_traps

# ── Pre-check: detectar secciones ya aplicadas ──────────────
_precheck 10
_pc 'check_executable /usr/local/bin/securizar-priv-inventory.sh'
_pc 'check_executable /usr/local/bin/securizar-session-record.sh'
_pc 'check_file_exists /etc/securizar/privileged/sudo-granular.conf'
_pc 'check_file_exists /etc/securizar/privileged/su-restrict.conf'
_pc 'check_executable /usr/local/bin/securizar-jit-access.sh'
_pc 'check_executable /usr/local/bin/securizar-priv-alerts.sh'
_pc 'check_file_exists /etc/securizar/privileged/capabilities.conf'
_pc 'check_file_exists /etc/securizar/privileged/credential-policy.conf'
_pc 'check_file_exists /etc/securizar/privileged/breakglass.conf'
_pc 'check_executable /usr/local/bin/auditoria-privileged-completa.sh'
_precheck_result

log_section "MODULO 74: GESTION DE ACCESO PRIVILEGIADO"
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

PRIV_DIR="/etc/securizar/privileged"
PRIV_BIN="/usr/local/bin"
PRIV_LOG="/var/log/securizar/privileged"
mkdir -p "$PRIV_DIR" "$PRIV_LOG" || true

# ============================================================
# S1: INVENTARIO DE ACCESO PRIVILEGIADO
# ============================================================
log_section "S1: Inventario de acceso privilegiado"

log_info "Crea herramienta de inventario de cuentas y accesos privilegiados:"
log_info "  - Usuarios con UID 0, sudoers, grupos wheel/sudo"
log_info "  - Ficheros con capabilities, conteo SUID/SGID"
log_info ""

if check_executable /usr/local/bin/securizar-priv-inventory.sh; then
    log_already "Inventario privilegiado (securizar-priv-inventory.sh existe)"
elif ask "Crear herramienta de inventario de acceso privilegiado?"; then

    cat > "$PRIV_BIN/securizar-priv-inventory.sh" << 'EOFINVENTORY'
#!/bin/bash
# ============================================================
# securizar-priv-inventory.sh - Inventario de acceso privilegiado
# ============================================================
set -euo pipefail

RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"
CYAN="\033[0;36m"; BOLD="\033[1m"; NC="\033[0m"

LOG_DIR="/var/log/securizar/privileged"
mkdir -p "$LOG_DIR"
REPORT="$LOG_DIR/inventory-$(date +%Y%m%d-%H%M%S).log"

log_r() { echo -e "$1" | tee -a "$REPORT"; }

log_r "${BOLD}=============================================${NC}"
log_r "  INVENTARIO DE ACCESO PRIVILEGIADO"
log_r "  Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
log_r "  Host: $(hostname)"
log_r "${BOLD}=============================================${NC}"
log_r ""

ISSUES=0

# Usuarios con UID 0
log_r "${CYAN}=== Usuarios con UID 0 ===${NC}"
uid0_users=$(awk -F: '$3==0 {print $1}' /etc/passwd)
uid0_count=$(echo "$uid0_users" | grep -c . || echo "0")
for u in $uid0_users; do log_r "  - $u"; done
if [[ "$uid0_count" -gt 1 ]]; then
    log_r "  ${YELLOW}[!!] Mas de 1 usuario con UID 0 ($uid0_count)${NC}"
    ISSUES=$((ISSUES + 1))
else
    log_r "  ${GREEN}[OK] Solo root tiene UID 0${NC}"
fi
log_r ""

# Grupos wheel/sudo
log_r "${CYAN}=== Miembros de wheel/sudo ===${NC}"
for grp in wheel sudo; do
    if getent group "$grp" &>/dev/null; then
        members=$(getent group "$grp" | cut -d: -f4)
        log_r "  Grupo $grp: ${members:-<vacio>}"
    fi
done
log_r ""

# Sudoers
log_r "${CYAN}=== Ficheros sudoers ===${NC}"
for f in /etc/sudoers /etc/sudoers.d/*; do
    [[ -f "$f" ]] || continue
    nopasswd=$(grep -c "NOPASSWD" "$f" 2>/dev/null || echo "0")
    log_r "  $f  (NOPASSWD entries: $nopasswd)"
    [[ "$nopasswd" -gt 0 ]] && ISSUES=$((ISSUES + 1))
done
log_r ""

# Capabilities
log_r "${CYAN}=== Ficheros con capabilities ===${NC}"
if command -v getcap &>/dev/null; then
    cap_count=0
    while IFS= read -r line; do
        [[ -n "$line" ]] && { log_r "  $line"; cap_count=$((cap_count + 1)); }
    done < <(getcap -r /usr/bin /usr/sbin /usr/local/bin 2>/dev/null || true)
    log_r "  Total: $cap_count ficheros con capabilities"
else
    log_r "  ${YELLOW}getcap no disponible${NC}"
fi
log_r ""

# SUID/SGID count
log_r "${CYAN}=== Binarios SUID/SGID ===${NC}"
suid_count=$(find /usr /bin /sbin -perm -4000 -type f 2>/dev/null | wc -l)
sgid_count=$(find /usr /bin /sbin -perm -2000 -type f 2>/dev/null | wc -l)
log_r "  SUID: $suid_count binarios"
log_r "  SGID: $sgid_count binarios"
[[ "$suid_count" -gt 30 ]] && { log_r "  ${YELLOW}[!!] Numero alto de SUID${NC}"; ISSUES=$((ISSUES + 1)); }
log_r ""

# Resumen
log_r "${BOLD}=============================================${NC}"
if [[ "$ISSUES" -eq 0 ]]; then
    log_r "  ${GREEN}Sin problemas detectados${NC}"
else
    log_r "  ${YELLOW}Problemas encontrados: $ISSUES${NC}"
fi
log_r "Reporte: $REPORT"
EOFINVENTORY
    chmod +x "$PRIV_BIN/securizar-priv-inventory.sh"
    log_change "Creado" "$PRIV_BIN/securizar-priv-inventory.sh"

else
    log_skip "Inventario de acceso privilegiado"
fi

# ============================================================
# S2: GRABACION DE SESIONES PRIVILEGIADAS
# ============================================================
log_section "S2: Grabacion de sesiones privilegiadas"

log_info "Configura grabacion de sesiones de usuarios privilegiados:"
log_info "  - Usa comando script o tlog si esta disponible"
log_info "  - Snippet en /etc/profile.d/ para sesiones sudo"
log_info ""

if check_executable /usr/local/bin/securizar-session-record.sh; then
    log_already "Grabacion de sesiones (securizar-session-record.sh existe)"
elif ask "Configurar grabacion de sesiones privilegiadas?"; then

    SESS_DIR="/var/log/securizar/sessions"
    mkdir -p "$SESS_DIR"
    chmod 0700 "$SESS_DIR"

    cat > "$PRIV_BIN/securizar-session-record.sh" << 'EOFSESSREC'
#!/bin/bash
# ============================================================
# securizar-session-record.sh - Grabacion de sesiones privilegiadas
# ============================================================
set -euo pipefail

SESS_DIR="/var/log/securizar/sessions"
mkdir -p "$SESS_DIR"
chmod 0700 "$SESS_DIR"

echo "=== Configuracion de grabacion de sesiones ==="
echo ""

# Verificar herramientas disponibles
RECORDER=""
if command -v tlog-rec &>/dev/null; then
    RECORDER="tlog"
    echo "[OK] tlog disponible - grabacion estructurada"
elif command -v script &>/dev/null; then
    RECORDER="script"
    echo "[OK] script disponible - grabacion basica"
else
    echo "[!!] Ni tlog ni script disponibles"
    exit 1
fi

# Crear snippet profile.d
PROFILE_SNIPPET="/etc/profile.d/securizar-session-record.sh"
cat > "$PROFILE_SNIPPET" << 'ENDSNIPPET'
# Grabacion de sesiones privilegiadas (securizar)
if [[ $EUID -eq 0 ]] || groups 2>/dev/null | grep -qE '\b(wheel|sudo)\b'; then
    SESS_DIR="/var/log/securizar/sessions"
    [[ -d "$SESS_DIR" ]] || return
    # Evitar recursion
    [[ -n "${SECURIZAR_RECORDING:-}" ]] && return
    export SECURIZAR_RECORDING=1
    SESS_FILE="$SESS_DIR/session-$(whoami)-$(date +%Y%m%d-%H%M%S)-$$.log"
    if command -v tlog-rec &>/dev/null; then
        exec tlog-rec --file-path="$SESS_FILE" 2>/dev/null || true
    elif command -v script &>/dev/null; then
        script -q -a "$SESS_FILE" 2>/dev/null || true
    fi
fi
ENDSNIPPET
chmod 0644 "$PROFILE_SNIPPET"

echo "[OK] Snippet creado en $PROFILE_SNIPPET"
echo "Recorder: $RECORDER"
echo "Sesiones se guardan en: $SESS_DIR"
EOFSESSREC
    chmod +x "$PRIV_BIN/securizar-session-record.sh"
    log_change "Creado" "$PRIV_BIN/securizar-session-record.sh"

    # Ejecutar para instalar snippet
    bash "$PRIV_BIN/securizar-session-record.sh" 2>/dev/null || true

else
    log_skip "Grabacion de sesiones privilegiadas"
fi

# ============================================================
# S3: POLITICAS SUDO GRANULARES
# ============================================================
log_section "S3: Politicas sudo granulares"

log_info "Crea configuracion de referencia para sudoers:"
log_info "  - Defaults seguros: log_output, use_pty, requiretty"
log_info "  - Whitelist de comandos, auditoria NOPASSWD"
log_info ""

if check_file_exists /etc/securizar/privileged/sudo-granular.conf; then
    log_already "Politicas sudo (sudo-granular.conf existe)"
elif ask "Crear politica sudo granular de referencia?"; then

    cat > "$PRIV_DIR/sudo-granular.conf" << 'EOFSUDOCONF'
# ============================================================
# sudo-granular.conf - Politica sudo granular de referencia
# ============================================================
# Generado por securizar - Modulo 74
#
# Para aplicar: copiar a /etc/sudoers.d/securizar-hardening
#   cp /etc/securizar/privileged/sudo-granular.conf \
#      /etc/sudoers.d/securizar-hardening
#   visudo -c  # Verificar sintaxis
# ============================================================

# === Defaults de seguridad ===
Defaults    log_output                  # Grabar salida de comandos sudo
Defaults    log_input                   # Grabar entrada de comandos sudo
Defaults    use_pty                     # Forzar pseudo-terminal
Defaults    requiretty                  # Requiere TTY para sudo
Defaults    timestamp_timeout=5         # Caducidad ticket: 5 minutos
Defaults    passwd_tries=3              # Maximo intentos password
Defaults    badpass_message="Acceso denegado"
Defaults    logfile="/var/log/sudo.log" # Log dedicado
Defaults    log_year                    # Incluir anio en logs
Defaults    insults=off                 # Sin mensajes insultantes
Defaults    secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# === Aliases de comandos seguros ===
Cmnd_Alias  SERVICIOS  = /usr/bin/systemctl status *, /usr/bin/systemctl restart *, /usr/bin/systemctl reload *
Cmnd_Alias  LOGS       = /usr/bin/journalctl, /usr/bin/tail -f /var/log/*
Cmnd_Alias  RED        = /usr/sbin/ss, /usr/bin/ip addr show, /usr/sbin/iptables -L
Cmnd_Alias  PAQUETES   = /usr/bin/zypper refresh, /usr/bin/zypper update, /usr/bin/apt update, /usr/bin/dnf check-update

# === Ejemplos de asignacion (adaptar) ===
# %sysadmin  ALL=(ALL) SERVICIOS, LOGS, RED
# %developers ALL=(ALL) NOPASSWD: LOGS
# operator   ALL=(ALL) PAQUETES

# === Restricciones explicitas ===
# NUNCA permitir shells sin restriccion:
# Cmnd_Alias PELIGROSO = /bin/bash, /bin/sh, /usr/bin/su, /usr/bin/passwd root
# Defaults!PELIGROSO   !use_pty
EOFSUDOCONF
    chmod 0640 "$PRIV_DIR/sudo-granular.conf"
    log_change "Creado" "$PRIV_DIR/sudo-granular.conf"

else
    log_skip "Politicas sudo granulares"
fi

# ============================================================
# S4: RESTRICCION SU Y ESCALADA
# ============================================================
log_section "S4: Restriccion su y escalada"

log_info "Documenta restricciones para el comando su y escalada:"
log_info "  - Restriccion via grupo wheel (usermod)"
log_info "  - Politicas polkit de referencia"
log_info "  - NOTA: NO se modifica /etc/pam.d/su (seguridad)"
log_info ""

if check_file_exists /etc/securizar/privileged/su-restrict.conf; then
    log_already "Restriccion su (su-restrict.conf existe)"
elif ask "Crear configuracion de restriccion su y escalada?"; then

    cat > "$PRIV_DIR/su-restrict.conf" << 'EOFSUCONF'
# ============================================================
# su-restrict.conf - Restriccion de su y escalada de privilegios
# ============================================================
# Generado por securizar - Modulo 74
#
# NOTA: Este fichero documenta recomendaciones.
#       NO se modifica /etc/pam.d/su automaticamente.
# ============================================================

# === Restriccion de su via grupo wheel ===
# Solo miembros de wheel pueden usar su:
#
# 1. Asegurar que wheel existe:
#    groupadd -f wheel
#
# 2. Agregar usuario autorizado:
#    usermod -aG wheel <usuario>
#
# 3. Para activar restriccion PAM (MANUAL, no automatico):
#    Descomentar en /etc/pam.d/su:
#    auth required pam_wheel.so use_uid
#
# 4. Verificar:
#    getent group wheel

# === Polkit: restringir acciones administrativas ===
# Fichero: /etc/polkit-1/rules.d/50-securizar-restrict.rules
#
# polkit.addRule(function(action, subject) {
#     if (action.id.indexOf("org.freedesktop.systemd1.manage-units") == 0 &&
#         !subject.isInGroup("wheel")) {
#         return polkit.Result.AUTH_ADMIN;
#     }
# });

# === Recomendaciones adicionales ===
# - Auditar uso de su: grep "su:" /var/log/auth.log
# - Preferir sudo sobre su (mayor granularidad y logging)
# - Deshabilitar login directo como root via SSH (PermitRootLogin no)
# - Monitorizar intentos fallidos de su
EOFSUCONF
    chmod 0640 "$PRIV_DIR/su-restrict.conf"
    log_change "Creado" "$PRIV_DIR/su-restrict.conf"

    # Asegurar grupo wheel existe
    if ! getent group wheel &>/dev/null; then
        groupadd -f wheel 2>/dev/null && \
            log_change "Creado" "grupo wheel" || true
    fi

else
    log_skip "Restriccion su y escalada"
fi

# ============================================================
# S5: JUST-IN-TIME ACCESS
# ============================================================
log_section "S5: Just-In-Time access"

log_info "Crea herramienta de acceso temporal sudo (JIT):"
log_info "  - Agrega usuario a wheel/sudo temporalmente"
log_info "  - Programa revocacion automatica via at/systemd-run"
log_info ""

if check_executable /usr/local/bin/securizar-jit-access.sh; then
    log_already "JIT access (securizar-jit-access.sh existe)"
elif ask "Crear herramienta de acceso JIT privilegiado?"; then

    cat > "$PRIV_BIN/securizar-jit-access.sh" << 'EOFJIT'
#!/bin/bash
# ============================================================
# securizar-jit-access.sh - Just-In-Time privileged access
# ============================================================
set -euo pipefail

usage() {
    echo "Uso: $0 <usuario> [minutos]"
    echo "  usuario  - Usuario que recibira acceso sudo temporal"
    echo "  minutos  - Duracion del acceso (default: 30, max: 480)"
    echo ""
    echo "Ejemplo: $0 jdoe 60"
    exit 1
}

[[ $# -lt 1 ]] && usage
[[ $EUID -ne 0 ]] && { echo "Error: requiere root"; exit 1; }

USER="$1"
MINUTES="${2:-30}"
LOG_DIR="/var/log/securizar/privileged"
mkdir -p "$LOG_DIR"
JIT_LOG="$LOG_DIR/jit-access.log"

# Validar usuario
if ! id "$USER" &>/dev/null; then
    echo "Error: usuario '$USER' no existe"
    exit 1
fi

# Validar minutos
if [[ "$MINUTES" -lt 1 ]] || [[ "$MINUTES" -gt 480 ]]; then
    echo "Error: minutos debe ser entre 1 y 480"
    exit 1
fi

# Determinar grupo sudo
SUDO_GRP="wheel"
getent group wheel &>/dev/null || SUDO_GRP="sudo"
if ! getent group "$SUDO_GRP" &>/dev/null; then
    echo "Error: no se encontro grupo wheel ni sudo"
    exit 1
fi

# Verificar si ya es miembro
if id -nG "$USER" 2>/dev/null | grep -qw "$SUDO_GRP"; then
    echo "[!!] $USER ya es miembro de $SUDO_GRP"
    echo "     No se aplica JIT (ya tiene acceso permanente)"
    exit 0
fi

# Agregar al grupo
usermod -aG "$SUDO_GRP" "$USER"
EXPIRY=$(date -d "+${MINUTES} minutes" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || \
         date -v+${MINUTES}M '+%Y-%m-%d %H:%M:%S' 2>/dev/null || \
         echo "en $MINUTES minutos")

echo "[OK] $USER agregado a $SUDO_GRP"
echo "     Expira: $EXPIRY"
echo "$(date '+%Y-%m-%d %H:%M:%S') JIT-GRANT user=$USER group=$SUDO_GRP minutes=$MINUTES" >> "$JIT_LOG"
logger -t securizar-jit "GRANT: $USER -> $SUDO_GRP for $MINUTES min"

# Programar revocacion
REVOKE_CMD="gpasswd -d $USER $SUDO_GRP 2>/dev/null; echo \"\$(date) JIT-REVOKE user=$USER group=$SUDO_GRP\" >> $JIT_LOG; logger -t securizar-jit \"REVOKE: $USER from $SUDO_GRP\""

if command -v systemd-run &>/dev/null; then
    systemd-run --on-active="${MINUTES}m" --timer-property=AccuracySec=10s \
        bash -c "$REVOKE_CMD" 2>/dev/null && \
        echo "[OK] Revocacion programada via systemd-run" || {
        # Fallback a at
        echo "$REVOKE_CMD" | at "now + $MINUTES minutes" 2>/dev/null && \
            echo "[OK] Revocacion programada via at" || \
            echo "[!!] No se pudo programar revocacion automatica"
    }
elif command -v at &>/dev/null; then
    echo "$REVOKE_CMD" | at "now + $MINUTES minutes" 2>/dev/null && \
        echo "[OK] Revocacion programada via at" || \
        echo "[!!] No se pudo programar revocacion - revocar manualmente"
else
    echo "[!!] Ni systemd-run ni at disponibles"
    echo "     REVOCAR MANUALMENTE: gpasswd -d $USER $SUDO_GRP"
fi
EOFJIT
    chmod +x "$PRIV_BIN/securizar-jit-access.sh"
    log_change "Creado" "$PRIV_BIN/securizar-jit-access.sh"

else
    log_skip "Just-In-Time access"
fi

# ============================================================
# S6: ALERTAS DE USO PRIVILEGIADO
# ============================================================
log_section "S6: Alertas de uso privilegiado"

log_info "Crea herramienta de alertas para uso de sudo/su:"
log_info "  - Monitoriza auth.log/journal"
log_info "  - Genera alertas via logger y email opcional"
log_info ""

if check_executable /usr/local/bin/securizar-priv-alerts.sh; then
    log_already "Alertas privilegiadas (securizar-priv-alerts.sh existe)"
elif ask "Crear herramienta de alertas de uso privilegiado?"; then

    cat > "$PRIV_BIN/securizar-priv-alerts.sh" << 'EOFALERTS'
#!/bin/bash
# ============================================================
# securizar-priv-alerts.sh - Alertas de uso privilegiado
# ============================================================
set -euo pipefail

HOURS="${1:-1}"
LOG_DIR="/var/log/securizar/privileged"
mkdir -p "$LOG_DIR"
ALERT_LOG="$LOG_DIR/alerts-$(date +%Y%m%d-%H%M%S).log"
EMAIL="${SECURIZAR_ALERT_EMAIL:-}"

log_a() { echo -e "$1" | tee -a "$ALERT_LOG"; }

log_a "=== Alertas de uso privilegiado (ultimas ${HOURS}h) ==="
log_a "Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
log_a ""

ALERTS=0

# Recopilar eventos sudo/su
TMPFILE=$(mktemp)
trap 'rm -f "$TMPFILE"' EXIT

if command -v journalctl &>/dev/null; then
    journalctl -t sudo -t su --since "${HOURS} hours ago" --no-pager 2>/dev/null > "$TMPFILE" || true
elif [[ -f /var/log/auth.log ]]; then
    grep -E "(sudo|su\[)" /var/log/auth.log 2>/dev/null > "$TMPFILE" || true
elif [[ -f /var/log/secure ]]; then
    grep -E "(sudo|su\[)" /var/log/secure 2>/dev/null > "$TMPFILE" || true
fi

# Analizar sudo
sudo_ok=$(grep -c "COMMAND=" "$TMPFILE" 2>/dev/null || echo "0")
sudo_fail=$(grep -c "authentication failure" "$TMPFILE" 2>/dev/null || echo "0")
su_events=$(grep -c "su\[" "$TMPFILE" 2>/dev/null || echo "0")

log_a "Eventos sudo exitosos:  $sudo_ok"
log_a "Eventos sudo fallidos:  $sudo_fail"
log_a "Eventos su:             $su_events"
log_a ""

# Alertas especificas
if [[ "$sudo_fail" -gt 5 ]]; then
    log_a "[ALERTA] Multiples fallos de autenticacion sudo ($sudo_fail)"
    ALERTS=$((ALERTS + 1))
fi

# Detectar sudo desde usuarios inusuales
if [[ -s "$TMPFILE" ]]; then
    log_a "=== Usuarios con actividad sudo ==="
    grep "COMMAND=" "$TMPFILE" 2>/dev/null | \
        grep -oP 'USER=\S+' | sort | uniq -c | sort -rn | head -10 | \
        while IFS= read -r line; do log_a "  $line"; done
    log_a ""

    # Root login directo
    root_direct=$(grep -c "session opened for user root" "$TMPFILE" 2>/dev/null || echo "0")
    if [[ "$root_direct" -gt 0 ]]; then
        log_a "[ALERTA] Sesiones directas como root: $root_direct"
        ALERTS=$((ALERTS + 1))
    fi
fi

# Resumen
log_a "=== Resumen ==="
log_a "Alertas generadas: $ALERTS"
logger -t securizar-priv "Alertas privilegiadas: $ALERTS (sudo_ok=$sudo_ok sudo_fail=$sudo_fail su=$su_events)"

# Email opcional
if [[ -n "$EMAIL" ]] && [[ "$ALERTS" -gt 0 ]] && command -v mail &>/dev/null; then
    mail -s "securizar: $ALERTS alertas privilegiadas en $(hostname)" "$EMAIL" < "$ALERT_LOG" 2>/dev/null || true
    log_a "Email enviado a: $EMAIL"
fi

log_a "Reporte: $ALERT_LOG"
EOFALERTS
    chmod +x "$PRIV_BIN/securizar-priv-alerts.sh"
    log_change "Creado" "$PRIV_BIN/securizar-priv-alerts.sh"

    # Cron horario
    cat > /etc/cron.hourly/securizar-priv-alerts << 'EOFCRON'
#!/bin/bash
/usr/local/bin/securizar-priv-alerts.sh 1 > /dev/null 2>&1
EOFCRON
    chmod 700 /etc/cron.hourly/securizar-priv-alerts
    log_change "Creado" "/etc/cron.hourly/securizar-priv-alerts"

else
    log_skip "Alertas de uso privilegiado"
fi

# ============================================================
# S7: CONTROL DE CAPABILITIES
# ============================================================
log_section "S7: Control de capabilities"

log_info "Documenta y audita capabilities de Linux:"
log_info "  - Auditoria con getcap, limpieza de caps innecesarias"
log_info "  - Uso de setcap como alternativa a SUID"
log_info ""

if check_file_exists /etc/securizar/privileged/capabilities.conf; then
    log_already "Control capabilities (capabilities.conf existe)"
elif ask "Crear configuracion de control de capabilities?"; then

    cat > "$PRIV_DIR/capabilities.conf" << 'EOFCAPS'
# ============================================================
# capabilities.conf - Control de capabilities de Linux
# ============================================================
# Generado por securizar - Modulo 74
#
# Linux capabilities permiten asignar privilegios granulares
# a binarios sin necesidad de SUID root.
# ============================================================

# === Auditar capabilities actuales ===
# getcap -r /usr/bin /usr/sbin /usr/local/bin 2>/dev/null
# getpcaps <PID>   # Capabilities de un proceso

# === Capabilities comunes y seguras ===
# cap_net_bind_service  - Bind puertos <1024 (ej: nginx sin root)
#   setcap 'cap_net_bind_service=+ep' /usr/sbin/nginx
#
# cap_net_raw           - Raw sockets (ej: ping)
#   setcap 'cap_net_raw=+ep' /usr/bin/ping
#
# cap_dac_read_search   - Leer cualquier fichero (ej: backup tools)
#   CUIDADO: equivale a read-all, usar con precaucion

# === Capabilities peligrosas (evitar) ===
# cap_sys_admin         - Casi equivale a root completo
# cap_sys_ptrace        - Permite inyectar en procesos
# cap_dac_override      - Ignora permisos de ficheros
# cap_setuid/cap_setgid - Permite cambiar UID/GID
# cap_sys_module        - Carga modulos de kernel

# === Reemplazar SUID por capabilities ===
# Ejemplo: Quitar SUID de ping y usar capability
#   chmod u-s /usr/bin/ping
#   setcap 'cap_net_raw=+ep' /usr/bin/ping
#
# Verificar: getcap /usr/bin/ping

# === Bounding set del kernel ===
# El bounding set limita capabilities heredables.
# Ver: cat /proc/1/status | grep Cap
# Decodificar: capsh --decode=<hex>
#
# Para restringir en servicios systemd:
#   CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
#   AmbientCapabilities=CAP_NET_BIND_SERVICE

# === Limpieza recomendada ===
# 1. Listar caps: getcap -r / 2>/dev/null
# 2. Para cada binario, evaluar si necesita la cap
# 3. Remover innecesarias: setcap -r /path/to/binary
EOFCAPS
    chmod 0640 "$PRIV_DIR/capabilities.conf"
    log_change "Creado" "$PRIV_DIR/capabilities.conf"

else
    log_skip "Control de capabilities"
fi

# ============================================================
# S8: TOKENS Y CREDENCIALES TEMPORALES
# ============================================================
log_section "S8: Tokens y credenciales temporales"

log_info "Configura politicas de tickets sudo y limpieza de cache:"
log_info "  - Timeout de tickets, limpieza de credenciales"
log_info "  - Recomendaciones para gestion de secretos"
log_info ""

if check_file_exists /etc/securizar/privileged/credential-policy.conf; then
    log_already "Politica credenciales (credential-policy.conf existe)"
elif ask "Crear politica de tokens y credenciales temporales?"; then

    cat > "$PRIV_DIR/credential-policy.conf" << 'EOFCREDPOL'
# ============================================================
# credential-policy.conf - Tokens y credenciales temporales
# ============================================================
# Generado por securizar - Modulo 74

# === Sudo ticket timeout ===
# El ticket sudo permite ejecutar sin re-autenticar durante N minutos
# Default: 15 minutos (demasiado largo para alta seguridad)
#
# Recomendacion para /etc/sudoers (via visudo):
#   Defaults timestamp_timeout=5   # 5 minutos
#   Defaults passwd_timeout=1      # 1 minuto para introducir password
#
# Para invalidar tickets manualmente:
#   sudo -k          # Invalida el ticket actual
#   sudo -K          # Elimina completamente el timestamp

# === Limpieza de credenciales en memoria ===
# - ssh-agent: ssh-add -D (eliminar claves cargadas)
# - gpg-agent: gpgconf --kill gpg-agent
# - sudo: sudo -K
# - kerberos: kdestroy
#
# Script de limpieza al cerrar sesion (~/.bash_logout):
#   sudo -K 2>/dev/null
#   ssh-add -D 2>/dev/null
#   gpgconf --kill gpg-agent 2>/dev/null

# === Recomendaciones ===
# 1. Nunca almacenar passwords en scripts (usar vault/secretos)
# 2. Usar NOPASSWD solo para comandos especificos y auditados
# 3. Rotar credenciales de servicio periodicamente
# 4. Configurar sudo con log_output para trazabilidad
# 5. Usar SSH keys con passphrase y agent forwarding limitado
# 6. Implementar MFA para acceso sudo si es posible
#    (pam_google_authenticator o similar)

# === Limpieza automatica ===
# Cron de limpieza de tickets stale:
# */30 * * * * find /run/sudo/ts -mmin +30 -delete 2>/dev/null
EOFCREDPOL
    chmod 0640 "$PRIV_DIR/credential-policy.conf"
    log_change "Creado" "$PRIV_DIR/credential-policy.conf"

else
    log_skip "Tokens y credenciales temporales"
fi

# ============================================================
# S9: BREAKGLASS PROCEDURE
# ============================================================
log_section "S9: Breakglass procedure"

log_info "Documenta procedimiento de acceso de emergencia:"
log_info "  - Password root sellada, procedimiento break-glass"
log_info "  - Trazabilidad y auditoria post-emergencia"
log_info ""

if check_file_exists /etc/securizar/privileged/breakglass.conf; then
    log_already "Breakglass procedure (breakglass.conf existe)"
elif ask "Crear documentacion de procedimiento breakglass?"; then

    cat > "$PRIV_DIR/breakglass.conf" << 'EOFBREAKGLASS'
# ============================================================
# breakglass.conf - Procedimiento de acceso de emergencia
# ============================================================
# Generado por securizar - Modulo 74
#
# El procedimiento breakglass permite acceso root de emergencia
# cuando los mecanismos normales (sudo, JIT) no estan disponibles.
# ============================================================

# === PREPARACION ===
# 1. Generar password root fuerte:
#    openssl rand -base64 32 > /root/.breakglass-pw
#    passwd root  # Establecer la password generada
#    chmod 0000 /root/.breakglass-pw
#
# 2. Cifrar y sellar la password:
#    gpg -c /root/.breakglass-pw
#    # Guardar breakglass-pw.gpg en ubicacion segura (vault, caja fuerte)
#    shred -u /root/.breakglass-pw
#
# 3. Documentar localizacion del sobre sellado

# === PROCEDIMIENTO DE EMERGENCIA ===
# 1. JUSTIFICACION: Documentar motivo del break-glass
# 2. TESTIGO: Requiere 2 personas (dual-control)
# 3. ACCESO: Obtener password sellada de la ubicacion segura
# 4. LOGIN: Usar consola fisica o IPMI/iLO (nunca SSH con root)
# 5. ACCION: Realizar solo la accion minima necesaria
# 6. REGISTRO: Todo queda en /var/log/securizar/privileged/breakglass.log
# 7. ROTACION: Cambiar password root inmediatamente despues
# 8. REPORTE: Crear informe post-incidente en 24h

# === POST-EMERGENCIA ===
# 1. Cambiar password root: passwd root
# 2. Generar nueva password sellada (repetir preparacion)
# 3. Revisar logs: journalctl -u sshd; last; lastb
# 4. Auditar acciones realizadas durante el break-glass
# 5. Actualizar registro de incidentes

# === AUDITORIA ===
# Cada uso de breakglass debe registrar:
# - Fecha/hora inicio y fin
# - Persona(s) involucrada(s)
# - Motivo / ticket de incidente
# - Acciones realizadas
# - Aprobacion del responsable de seguridad
EOFBREAKGLASS
    chmod 0640 "$PRIV_DIR/breakglass.conf"
    log_change "Creado" "$PRIV_DIR/breakglass.conf"

else
    log_skip "Breakglass procedure"
fi

# ============================================================
# S10: AUDITORIA INTEGRAL ACCESO PRIVILEGIADO
# ============================================================
log_section "S10: Auditoria integral acceso privilegiado"

log_info "Crea herramienta de auditoria integral de acceso privilegiado."
log_info ""

if check_executable /usr/local/bin/auditoria-privileged-completa.sh; then
    log_already "Auditoria integral (auditoria-privileged-completa.sh existe)"
elif ask "Crear herramienta de auditoria integral de acceso privilegiado?"; then

    cat > "$PRIV_BIN/auditoria-privileged-completa.sh" << 'EOFAUDIT'
#!/bin/bash
# ============================================================
# auditoria-privileged-completa.sh - Auditoria integral acceso privilegiado
# ============================================================
set -euo pipefail

RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"
CYAN="\033[0;36m"; BOLD="\033[1m"; DIM="\033[2m"; NC="\033[0m"

LOG_DIR="/var/log/securizar/privileged"
mkdir -p "$LOG_DIR"
REPORT="$LOG_DIR/audit-integral-$(date +%Y%m%d-%H%M%S).log"

SCORE=0
MAX=0

check() {
    local desc="$1" result="$2"
    MAX=$((MAX + 1))
    if [[ "$result" -eq 0 ]]; then
        echo -e "  ${GREEN}[OK]${NC} $desc" | tee -a "$REPORT"
        SCORE=$((SCORE + 1))
    else
        echo -e "  ${YELLOW}[!!]${NC} $desc" | tee -a "$REPORT"
    fi
}

echo -e "${BOLD}=============================================" | tee "$REPORT"
echo -e "  AUDITORIA INTEGRAL ACCESO PRIVILEGIADO" | tee -a "$REPORT"
echo -e "  $(date '+%Y-%m-%d %H:%M:%S') - $(hostname)" | tee -a "$REPORT"
echo -e "=============================================${NC}" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# 1. Herramientas securizar
echo -e "${CYAN}=== 1. Herramientas securizar ===${NC}" | tee -a "$REPORT"
check "securizar-priv-inventory.sh" "$([[ -x /usr/local/bin/securizar-priv-inventory.sh ]]; echo $?)"
check "securizar-session-record.sh" "$([[ -x /usr/local/bin/securizar-session-record.sh ]]; echo $?)"
check "securizar-jit-access.sh" "$([[ -x /usr/local/bin/securizar-jit-access.sh ]]; echo $?)"
check "securizar-priv-alerts.sh" "$([[ -x /usr/local/bin/securizar-priv-alerts.sh ]]; echo $?)"

# 2. Configuracion
echo "" | tee -a "$REPORT"
echo -e "${CYAN}=== 2. Configuracion ===${NC}" | tee -a "$REPORT"
check "sudo-granular.conf" "$([[ -f /etc/securizar/privileged/sudo-granular.conf ]]; echo $?)"
check "su-restrict.conf" "$([[ -f /etc/securizar/privileged/su-restrict.conf ]]; echo $?)"
check "capabilities.conf" "$([[ -f /etc/securizar/privileged/capabilities.conf ]]; echo $?)"
check "credential-policy.conf" "$([[ -f /etc/securizar/privileged/credential-policy.conf ]]; echo $?)"
check "breakglass.conf" "$([[ -f /etc/securizar/privileged/breakglass.conf ]]; echo $?)"

# 3. Estado del sistema
echo "" | tee -a "$REPORT"
echo -e "${CYAN}=== 3. Estado del sistema ===${NC}" | tee -a "$REPORT"

# Solo root tiene UID 0
uid0_count=$(awk -F: '$3==0' /etc/passwd | wc -l)
check "Solo root con UID 0" "$([[ "$uid0_count" -le 1 ]]; echo $?)"

# Sudo tiene log_output
sudo_log_output=$(grep -r "log_output" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -cv "^#" || echo "0")
check "Sudo log_output configurado" "$([[ "$sudo_log_output" -gt 0 ]]; echo $?)"

# Sudo timestamp_timeout razonable
sudo_timeout=$(grep -r "timestamp_timeout" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#" | head -1 || echo "")
if [[ -n "$sudo_timeout" ]]; then
    check "Sudo timestamp_timeout definido" 0
else
    check "Sudo timestamp_timeout definido" 1
fi

# Sesiones grabadas
check "Snippet grabacion sesiones" "$([[ -f /etc/profile.d/securizar-session-record.sh ]]; echo $?)"

# Grupo wheel existe
check "Grupo wheel existe" "$(getent group wheel &>/dev/null; echo $?)"

# SUID binarios razonables
suid_count=$(find /usr /bin /sbin -perm -4000 -type f 2>/dev/null | wc -l)
check "SUID binarios <30" "$([[ "$suid_count" -lt 30 ]]; echo $?)"
echo -e "  ${DIM}SUID binarios encontrados: $suid_count${NC}" | tee -a "$REPORT"

# Resumen
echo "" | tee -a "$REPORT"
echo -e "${BOLD}=============================================${NC}" | tee -a "$REPORT"
PCT=0
[[ $MAX -gt 0 ]] && PCT=$((SCORE * 100 / MAX))

if [[ $PCT -ge 80 ]]; then
    echo -e "  ${GREEN}${BOLD}PUNTUACION: ${SCORE}/${MAX} (${PCT}%) - BUENO${NC}" | tee -a "$REPORT"
elif [[ $PCT -ge 50 ]]; then
    echo -e "  ${YELLOW}${BOLD}PUNTUACION: ${SCORE}/${MAX} (${PCT}%) - MEJORABLE${NC}" | tee -a "$REPORT"
else
    echo -e "  ${RED}${BOLD}PUNTUACION: ${SCORE}/${MAX} (${PCT}%) - DEFICIENTE${NC}" | tee -a "$REPORT"
fi
echo -e "${BOLD}=============================================${NC}" | tee -a "$REPORT"
echo -e "${DIM}Reporte: $REPORT${NC}" | tee -a "$REPORT"
logger -t securizar-priv "Privileged access audit: $SCORE/$MAX ($PCT%)"
EOFAUDIT
    chmod +x "$PRIV_BIN/auditoria-privileged-completa.sh"
    log_change "Creado" "$PRIV_BIN/auditoria-privileged-completa.sh"

    # Cron semanal
    cat > /etc/cron.weekly/auditoria-privileged << 'EOFCRON'
#!/bin/bash
/usr/local/bin/auditoria-privileged-completa.sh > /dev/null 2>&1
EOFCRON
    chmod 700 /etc/cron.weekly/auditoria-privileged
    log_change "Creado" "/etc/cron.weekly/auditoria-privileged"

else
    log_skip "Auditoria integral acceso privilegiado"
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
show_changes_summary
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   ACCESO PRIVILEGIADO (MODULO 74) COMPLETADO              ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups guardados en: $BACKUP_DIR"
echo ""
echo "Comandos disponibles:"
echo "  - Inventario:       securizar-priv-inventory.sh"
echo "  - Sesiones:         securizar-session-record.sh"
echo "  - JIT access:       securizar-jit-access.sh <user> [min]"
echo "  - Alertas:          securizar-priv-alerts.sh [horas]"
echo "  - Auditoria:        auditoria-privileged-completa.sh"
echo ""
echo "Configuracion en:     $PRIV_DIR/"
echo "  - sudo-granular.conf     - Politica sudo de referencia"
echo "  - su-restrict.conf       - Restriccion su (recomendaciones)"
echo "  - capabilities.conf      - Control de capabilities"
echo "  - credential-policy.conf - Tokens y credenciales"
echo "  - breakglass.conf        - Procedimiento de emergencia"
