#!/bin/bash
# ============================================================
# proteger-ransomware.sh - Modulo 60: Proteccion Anti-Ransomware
# ============================================================
# Secciones:
#   S1  - Canary files (archivos centinela + inotify + systemd)
#   S2  - LVM snapshot protection (snapshots horarios + retencion)
#   S3  - Executable whitelisting (fapolicyd/AppArmor + bloqueo /tmp)
#   S4  - Mass file change monitoring (auditd + rate threshold)
#   S5  - Extension blacklisting & YARA (indicadores ransomware)
#   S6  - Network share protection (SMB/NFS hardening)
#   S7  - Backup immutability (append-only, btrfs readonly)
#   S8  - Process behavior analysis (crypto ops, enumeration)
#   S9  - Emergency response automation (kill, isolate, forensic)
#   S10 - Comprehensive audit (scoring + cron)
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps
init_backup "anti-ransomware"

# ── Pre-check: detectar secciones ya aplicadas ──────────────
_precheck 10
_pc 'check_file_exists /usr/local/bin/desplegar-canary-ransomware.sh'
_pc 'check_file_exists /usr/local/bin/gestionar-snapshot-ransomware.sh'
_pc 'check_file_exists /usr/local/bin/verificar-whitelisting-ransomware.sh'
_pc 'check_file_exists /usr/local/bin/analizar-cambios-masivos.sh'
_pc 'check_file_exists /usr/local/bin/escanear-ransomware.sh'
_pc 'check_file_exists /usr/local/bin/verificar-shares-ransomware.sh'
_pc 'check_file_exists /usr/local/bin/gestionar-inmutabilidad-backup.sh'
_pc 'check_file_exists /usr/local/bin/analizar-comportamiento-procesos.sh'
_pc 'check_file_exists /usr/local/bin/respuesta-emergencia-ransomware.sh'
_pc 'check_file_exists /usr/local/bin/auditar-anti-ransomware.sh'
_precheck_result

log_section "MODULO 60: PROTECCION ANTI-RANSOMWARE"
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

echo ""
echo "=================================================================="
echo "  MODULO 60 - PROTECCION ANTI-RANSOMWARE"
echo "  Canary files, LVM snapshots, whitelisting, YARA,"
echo "  network shares, immutability, behavior analysis,"
echo "  emergency response, auditoria integral"
echo "=================================================================="
echo ""

# ── Directorios base ─────────────────────────────────────────
RANSOMWARE_CONF_DIR="/etc/securizar/ransomware"
RANSOMWARE_LOG_DIR="/var/log/securizar/ransomware"
RANSOMWARE_LIB_DIR="/var/lib/securizar/ransomware"

mkdir -p /etc/securizar 2>/dev/null || true
mkdir -p "$RANSOMWARE_CONF_DIR" 2>/dev/null || true
mkdir -p "$RANSOMWARE_LOG_DIR" 2>/dev/null || true
mkdir -p "$RANSOMWARE_LIB_DIR" 2>/dev/null || true
mkdir -p /var/log/securizar 2>/dev/null || true

# ============================================================
# S1: CANARY FILES (ARCHIVOS CENTINELA)
# ============================================================
log_section "S1: CANARY FILES (ARCHIVOS CENTINELA)"

log_info "Despliega archivos centinela (canary) en ubicaciones clave:"
log_info "  - /home, /var, /tmp, /srv con contenido unico"
log_info "  - Monitor inotifywait que detecta modificaciones"
log_info "  - Servicio systemd para monitoreo continuo"
log_info "  - Script de alerta con syslog + email + bloqueo"
log_info "  - Configuracion en /etc/securizar/ransomware-canary.conf"
log_info ""

if check_file_exists /usr/local/bin/desplegar-canary-ransomware.sh; then
    log_already "Canary files anti-ransomware (desplegar-canary-ransomware.sh existe)"
elif ask "¿Desplegar archivos canary anti-ransomware?"; then

    # Instalar inotify-tools si no esta disponible
    if ! command -v inotifywait &>/dev/null; then
        log_info "Instalando inotify-tools..."
        pkg_install inotify-tools || true
    fi

    # --- Configuracion canary ---
    CANARY_CONF="${RANSOMWARE_CONF_DIR}/ransomware-canary.conf"
    if [[ -f "$CANARY_CONF" ]]; then
        cp "$CANARY_CONF" "${BACKUP_DIR}/ransomware-canary.conf.bak"
        log_change "Backup" "ransomware-canary.conf existente"
    fi

    cat > "$CANARY_CONF" << 'EOF'
# ============================================================
# ransomware-canary.conf - Configuracion de archivos centinela
# ============================================================
# Modulo 60 - Proteccion Anti-Ransomware
# ============================================================

# Directorios donde desplegar canary files
CANARY_DIRS="/home /var /tmp /srv /opt /root"

# Nombres de archivos canary (nombres atractivos para ransomware)
CANARY_NAMES="important_documents.xlsx financial_report_2024.pdf company_secrets.docx passwords_backup.txt database_dump.sql bitcoin_wallet.dat"

# Directorio oculto para canaries dentro de cada ubicacion
CANARY_SUBDIR=".securizar-canary"

# Accion ante deteccion: alert | alert+isolate | alert+isolate+shutdown
CANARY_ACTION="alert+isolate"

# Notificacion por email (vacio = deshabilitado)
CANARY_NOTIFY_EMAIL=""

# Intervalo de verificacion de integridad (segundos)
CANARY_CHECK_INTERVAL=300

# Log de eventos canary
CANARY_LOG="/var/log/securizar/ransomware/canary-events.log"

# Habilitar bloqueo automatico de proceso infractor
CANARY_AUTO_KILL="true"

# Habilitar aislamiento de red automatico
CANARY_AUTO_ISOLATE="false"

# Hash algorithm para verificacion de integridad
CANARY_HASH_ALGO="sha256"

# Maximo de alertas antes de ejecutar accion critica
CANARY_ALERT_THRESHOLD=3

# Archivo de estado de canaries desplegados
CANARY_STATE_FILE="/var/lib/securizar/ransomware/canary-state.db"
EOF
    chmod 600 "$CANARY_CONF"
    log_change "Creado" "$CANARY_CONF"

    # --- Script de despliegue de canary files ---
    log_info "Creando /usr/local/bin/desplegar-canary-ransomware.sh..."
    cat > /usr/local/bin/desplegar-canary-ransomware.sh << 'EOF'
#!/bin/bash
# ============================================================
# desplegar-canary-ransomware.sh - Despliegue de archivos centinela
# Modulo 60 - Proteccion Anti-Ransomware
# ============================================================
set -euo pipefail

CONF="/etc/securizar/ransomware/ransomware-canary.conf"
if [[ ! -f "$CONF" ]]; then
    echo "[X] No existe $CONF" >&2
    exit 1
fi
source "$CONF"

STATE_FILE="${CANARY_STATE_FILE:-/var/lib/securizar/ransomware/canary-state.db}"
LOG="${CANARY_LOG:-/var/log/securizar/ransomware/canary-events.log}"
HASH_ALGO="${CANARY_HASH_ALGO:-sha256}"

mkdir -p "$(dirname "$STATE_FILE")"
mkdir -p "$(dirname "$LOG")"

log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG"
}

generate_canary_content() {
    local name="$1"
    local dir="$2"
    local token
    token="CANARY-$(date +%s)-$(openssl rand -hex 8 2>/dev/null || head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    # Contenido que parece un documento real pero es un canary
    cat << EOFCONTENT
This document contains confidential information.
Classification: INTERNAL USE ONLY
Department: Finance & Operations
Last Modified: $(date '+%Y-%m-%d %H:%M:%S')
Author: System Administrator

--- BEGIN CONFIDENTIAL DATA ---
Project codename: Phoenix Rising
Budget allocation: \$2,450,000
Account reference: ACC-$(openssl rand -hex 4 2>/dev/null || echo "00000000")
Authorization code: AUTH-$(openssl rand -hex 6 2>/dev/null || echo "000000000000")

CANARY_TOKEN=${token}
CANARY_FILE=${name}
CANARY_DIR=${dir}
CANARY_DEPLOYED=$(date -Iseconds)
--- END CONFIDENTIAL DATA ---

WARNING: Unauthorized access to this document is strictly prohibited.
All access attempts are logged and monitored.
EOFCONTENT
    echo "$token"
}

deploy() {
    log_msg "=== DESPLIEGUE DE CANARY FILES ==="
    local deployed=0
    local state_tmp
    state_tmp=$(mktemp)

    for dir in $CANARY_DIRS; do
        [[ ! -d "$dir" ]] && continue

        local canary_dir="${dir}/${CANARY_SUBDIR}"
        mkdir -p "$canary_dir" 2>/dev/null || continue
        chmod 755 "$canary_dir"

        for name in $CANARY_NAMES; do
            local filepath="${canary_dir}/${name}"
            local token
            token=$(generate_canary_content "$name" "$dir" > "$filepath")

            # Generar hash de integridad
            local hash
            hash=$("${HASH_ALGO}sum" "$filepath" 2>/dev/null | awk '{print $1}')

            # Permisos: legible por todos (para que ransomware lo encuentre)
            chmod 644 "$filepath"

            # Registrar en estado
            echo "${filepath}|${hash}|$(date -Iseconds)|${token}" >> "$state_tmp"
            ((deployed++)) || true

            log_msg "Canary desplegado: $filepath"
        done

        # Canary files adicionales en el directorio raiz del dir
        # con nombres mas visibles
        for special_name in "IMPORTANT_README.txt" "DO_NOT_DELETE.pdf" "credentials_backup.csv"; do
            local filepath="${dir}/${special_name}"
            [[ -f "$filepath" ]] && continue
            local token
            token=$(generate_canary_content "$special_name" "$dir" > "$filepath" 2>/dev/null) || true
            if [[ -f "$filepath" ]]; then
                chmod 644 "$filepath"
                local hash
                hash=$("${HASH_ALGO}sum" "$filepath" 2>/dev/null | awk '{print $1}')
                echo "${filepath}|${hash}|$(date -Iseconds)|${token}" >> "$state_tmp"
                ((deployed++)) || true
                log_msg "Canary especial desplegado: $filepath"
            fi
        done

        # Tambien crear en subdirectorios /home/*/
        if [[ "$dir" == "/home" ]]; then
            for user_home in /home/*/; do
                [[ ! -d "$user_home" ]] && continue
                local user_canary="${user_home}${CANARY_SUBDIR}"
                mkdir -p "$user_canary" 2>/dev/null || continue
                local user_owner
                user_owner=$(stat -c '%U' "$user_home" 2>/dev/null || echo "root")

                for name in $CANARY_NAMES; do
                    local filepath="${user_canary}/${name}"
                    local token
                    token=$(generate_canary_content "$name" "$user_home" > "$filepath" 2>/dev/null) || true
                    if [[ -f "$filepath" ]]; then
                        chown "$user_owner:$user_owner" "$filepath" 2>/dev/null || true
                        chmod 644 "$filepath"
                        local hash
                        hash=$("${HASH_ALGO}sum" "$filepath" 2>/dev/null | awk '{print $1}')
                        echo "${filepath}|${hash}|$(date -Iseconds)|${token}" >> "$state_tmp"
                        ((deployed++)) || true
                    fi
                done
            done
        fi
    done

    # Guardar estado
    mv "$state_tmp" "$STATE_FILE"
    chmod 600 "$STATE_FILE"

    log_msg "Total canary files desplegados: $deployed"
    echo "[+] $deployed canary files desplegados"
}

verify() {
    log_msg "=== VERIFICACION DE INTEGRIDAD DE CANARIES ==="
    if [[ ! -f "$STATE_FILE" ]]; then
        echo "[X] No hay canaries desplegados (no existe $STATE_FILE)"
        return 1
    fi

    local total=0 ok=0 modified=0 missing=0

    while IFS='|' read -r filepath orig_hash deploy_date token; do
        ((total++)) || true

        if [[ ! -f "$filepath" ]]; then
            log_msg "ALERTA: Canary ELIMINADO: $filepath"
            logger -t "securizar-canary" -p auth.crit "CANARY FILE DELETED: $filepath"
            ((missing++)) || true
            continue
        fi

        local current_hash
        current_hash=$("${HASH_ALGO}sum" "$filepath" 2>/dev/null | awk '{print $1}')

        if [[ "$current_hash" != "$orig_hash" ]]; then
            log_msg "ALERTA: Canary MODIFICADO: $filepath (hash cambio)"
            logger -t "securizar-canary" -p auth.crit "CANARY FILE MODIFIED: $filepath old=$orig_hash new=$current_hash"
            ((modified++)) || true
        else
            ((ok++)) || true
        fi
    done < "$STATE_FILE"

    echo ""
    echo "=== RESULTADO DE VERIFICACION ==="
    echo "  Total canaries: $total"
    echo "  Intactos:       $ok"
    echo "  Modificados:    $modified"
    echo "  Eliminados:     $missing"
    echo ""

    if [[ $modified -gt 0 || $missing -gt 0 ]]; then
        echo "[!!!] ALERTA: Se detectaron cambios en canary files!"
        echo "[!!!] Esto puede indicar actividad de ransomware!"
        return 1
    else
        echo "[+] Todos los canary files estan intactos"
        return 0
    fi
}

remove() {
    log_msg "=== ELIMINACION DE CANARY FILES ==="
    if [[ ! -f "$STATE_FILE" ]]; then
        echo "[!] No hay canaries desplegados"
        return 0
    fi

    local removed=0
    while IFS='|' read -r filepath orig_hash deploy_date token; do
        if [[ -f "$filepath" ]]; then
            rm -f "$filepath"
            ((removed++)) || true
            log_msg "Canary eliminado: $filepath"
        fi
    done < "$STATE_FILE"

    rm -f "$STATE_FILE"
    echo "[+] $removed canary files eliminados"
}

list() {
    if [[ ! -f "$STATE_FILE" ]]; then
        echo "[!] No hay canaries desplegados"
        return 0
    fi

    echo ""
    echo "CANARY FILES DESPLEGADOS"
    echo "========================"
    local count=0
    while IFS='|' read -r filepath orig_hash deploy_date token; do
        ((count++)) || true
        local status="OK"
        if [[ ! -f "$filepath" ]]; then
            status="MISSING"
        else
            local current_hash
            current_hash=$("${HASH_ALGO}sum" "$filepath" 2>/dev/null | awk '{print $1}')
            [[ "$current_hash" != "$orig_hash" ]] && status="MODIFIED"
        fi
        printf "  [%-8s] %s\n" "$status" "$filepath"
    done < "$STATE_FILE"
    echo ""
    echo "Total: $count canary files"
}

usage() {
    echo "Uso: $0 {deploy|verify|remove|list}"
    echo ""
    echo "  deploy  - Desplegar canary files en directorios monitoreados"
    echo "  verify  - Verificar integridad de canary files"
    echo "  remove  - Eliminar todos los canary files"
    echo "  list    - Listar canary files y su estado"
    exit 1
}

case "${1:-}" in
    deploy)  deploy ;;
    verify)  verify ;;
    remove)  remove ;;
    list)    list ;;
    *)       usage ;;
esac
EOF
    chmod +x /usr/local/bin/desplegar-canary-ransomware.sh
    log_change "Creado" "/usr/local/bin/desplegar-canary-ransomware.sh"

    # --- Script de alerta canary ---
    log_info "Creando /usr/local/bin/alertar-canary-ransomware.sh..."
    cat > /usr/local/bin/alertar-canary-ransomware.sh << 'EOF'
#!/bin/bash
# ============================================================
# alertar-canary-ransomware.sh - Alerta por modificacion canary
# Modulo 60 - Proteccion Anti-Ransomware
# ============================================================
set -euo pipefail

CONF="/etc/securizar/ransomware/ransomware-canary.conf"
[[ -f "$CONF" ]] && source "$CONF"

LOG="${CANARY_LOG:-/var/log/securizar/ransomware/canary-events.log}"
ACTION="${CANARY_ACTION:-alert}"
NOTIFY_EMAIL="${CANARY_NOTIFY_EMAIL:-}"
AUTO_KILL="${CANARY_AUTO_KILL:-false}"
AUTO_ISOLATE="${CANARY_AUTO_ISOLATE:-false}"

EVENT_TYPE="${1:-unknown}"
FILE_PATH="${2:-unknown}"
PROCESS_INFO="${3:-unknown}"

TIMESTAMP="$(date '+%Y-%m-%d %H:%M:%S')"
HOSTNAME="$(hostname)"

mkdir -p "$(dirname "$LOG")"

log_alert() {
    echo "[$TIMESTAMP] RANSOMWARE_ALERT: $1" | tee -a "$LOG"
}

# Registrar alerta
log_alert "EVENT=$EVENT_TYPE FILE=$FILE_PATH PROCESS=$PROCESS_INFO"

# Syslog critico
logger -t "securizar-ransomware" -p auth.crit \
    "RANSOMWARE CANARY ALERT: event=$EVENT_TYPE file=$FILE_PATH process=$PROCESS_INFO"

# Journal
systemd-cat -t "securizar-ransomware" -p crit \
    echo "CANARY ALERT: $EVENT_TYPE on $FILE_PATH by $PROCESS_INFO" 2>/dev/null || true

# Intentar identificar el proceso responsable
SUSPECT_PID=""
SUSPECT_CMD=""
if [[ "$PROCESS_INFO" != "unknown" && "$PROCESS_INFO" =~ ^[0-9]+$ ]]; then
    SUSPECT_PID="$PROCESS_INFO"
    SUSPECT_CMD=$(ps -p "$SUSPECT_PID" -o comm= 2>/dev/null || echo "unknown")
elif [[ -n "$FILE_PATH" && "$FILE_PATH" != "unknown" ]]; then
    # Intentar encontrar proceso que tiene el archivo abierto
    SUSPECT_PID=$(lsof "$FILE_PATH" 2>/dev/null | awk 'NR==2{print $2}' || echo "")
    if [[ -n "$SUSPECT_PID" ]]; then
        SUSPECT_CMD=$(ps -p "$SUSPECT_PID" -o comm= 2>/dev/null || echo "unknown")
    fi
fi

# Capturar evidencia forense
EVIDENCE_DIR="/var/lib/securizar/ransomware/evidence-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"
{
    echo "=== EVIDENCIA FORENSE - CANARY ALERT ==="
    echo "Timestamp: $TIMESTAMP"
    echo "Event: $EVENT_TYPE"
    echo "File: $FILE_PATH"
    echo "Suspect PID: ${SUSPECT_PID:-N/A}"
    echo "Suspect CMD: ${SUSPECT_CMD:-N/A}"
    echo ""
    echo "=== PROCESOS ACTIVOS ==="
    ps auxf 2>/dev/null || ps aux
    echo ""
    echo "=== CONEXIONES DE RED ==="
    ss -tupna 2>/dev/null || true
    echo ""
    echo "=== ARCHIVOS ABIERTOS POR SOSPECHOSO ==="
    if [[ -n "$SUSPECT_PID" ]]; then
        ls -la /proc/"$SUSPECT_PID"/fd/ 2>/dev/null || true
        cat /proc/"$SUSPECT_PID"/cmdline 2>/dev/null | tr '\0' ' ' || true
        echo ""
        cat /proc/"$SUSPECT_PID"/maps 2>/dev/null | head -50 || true
    fi
} > "$EVIDENCE_DIR/forensic-snapshot.txt" 2>/dev/null || true
chmod 600 "$EVIDENCE_DIR/forensic-snapshot.txt"
log_alert "Evidencia forense capturada en $EVIDENCE_DIR"

# Accion: kill proceso sospechoso
if [[ "$AUTO_KILL" == "true" && -n "$SUSPECT_PID" ]]; then
    log_alert "AUTO_KILL: Matando proceso sospechoso PID=$SUSPECT_PID CMD=$SUSPECT_CMD"
    kill -STOP "$SUSPECT_PID" 2>/dev/null || true
    # Guardar info antes de matar
    cat /proc/"$SUSPECT_PID"/cmdline > "$EVIDENCE_DIR/killed-cmdline.txt" 2>/dev/null || true
    cat /proc/"$SUSPECT_PID"/environ > "$EVIDENCE_DIR/killed-environ.txt" 2>/dev/null || true
    kill -9 "$SUSPECT_PID" 2>/dev/null || true
    log_alert "Proceso $SUSPECT_PID eliminado"
fi

# Accion: aislamiento de red
if [[ "$ACTION" == *"isolate"* || "$AUTO_ISOLATE" == "true" ]]; then
    log_alert "AISLAMIENTO: Bloqueando trafico de red saliente..."
    # Guardar reglas actuales
    iptables-save > "$EVIDENCE_DIR/iptables-pre-isolate.txt" 2>/dev/null || true
    nft list ruleset > "$EVIDENCE_DIR/nft-pre-isolate.txt" 2>/dev/null || true

    # Bloquear todo excepto loopback y SSH
    if command -v nft &>/dev/null; then
        nft add table inet ransomware_isolate 2>/dev/null || true
        nft add chain inet ransomware_isolate output '{ type filter hook output priority 0; policy drop; }' 2>/dev/null || true
        nft add rule inet ransomware_isolate output oif lo accept 2>/dev/null || true
        nft add rule inet ransomware_isolate output tcp sport 22 accept 2>/dev/null || true
        nft add rule inet ransomware_isolate output ct state established accept 2>/dev/null || true
    elif command -v iptables &>/dev/null; then
        iptables -I OUTPUT -o lo -j ACCEPT 2>/dev/null || true
        iptables -I OUTPUT -p tcp --sport 22 -j ACCEPT 2>/dev/null || true
        iptables -I OUTPUT -m state --state ESTABLISHED -j ACCEPT 2>/dev/null || true
        iptables -A OUTPUT -j DROP 2>/dev/null || true
    fi
    log_alert "Red aislada - solo SSH permitido"
fi

# Accion: shutdown si es critico
if [[ "$ACTION" == *"shutdown"* ]]; then
    log_alert "SHUTDOWN: Apagando sistema por alerta critica de ransomware"
    sync
    shutdown -h +1 "RANSOMWARE DETECTADO - Apagado de emergencia en 1 minuto" 2>/dev/null || true
fi

# Notificacion por email
if [[ -n "$NOTIFY_EMAIL" ]]; then
    SUBJECT="[RANSOMWARE ALERT] ${HOSTNAME} - Canary file ${EVENT_TYPE}"
    BODY="ALERTA DE RANSOMWARE DETECTADA

Timestamp: $TIMESTAMP
Hostname: $HOSTNAME
Evento: $EVENT_TYPE
Archivo: $FILE_PATH
Proceso sospechoso: PID=${SUSPECT_PID:-N/A} CMD=${SUSPECT_CMD:-N/A}
Accion tomada: $ACTION
Evidencia: $EVIDENCE_DIR

Ejecute /usr/local/bin/respuesta-emergencia-ransomware.sh para respuesta completa."

    if command -v mail &>/dev/null; then
        echo "$BODY" | mail -s "$SUBJECT" "$NOTIFY_EMAIL" 2>/dev/null || true
    elif command -v sendmail &>/dev/null; then
        {
            echo "Subject: $SUBJECT"
            echo "To: $NOTIFY_EMAIL"
            echo ""
            echo "$BODY"
        } | sendmail "$NOTIFY_EMAIL" 2>/dev/null || true
    fi
    log_alert "Notificacion enviada a $NOTIFY_EMAIL"
fi

# Notificacion a consola de todos los usuarios logueados
wall "ALERTA DE SEGURIDAD: Posible ransomware detectado. Archivo canary ${EVENT_TYPE}: ${FILE_PATH}. Contacte al administrador." 2>/dev/null || true

log_alert "Respuesta a alerta completada. Revise $EVIDENCE_DIR"
EOF
    chmod +x /usr/local/bin/alertar-canary-ransomware.sh
    log_change "Creado" "/usr/local/bin/alertar-canary-ransomware.sh"

    # --- Monitor inotify para canary files ---
    log_info "Creando /usr/local/bin/monitor-canary-ransomware.sh..."
    cat > /usr/local/bin/monitor-canary-ransomware.sh << 'EOF'
#!/bin/bash
# ============================================================
# monitor-canary-ransomware.sh - Monitor inotify de canaries
# Modulo 60 - Proteccion Anti-Ransomware
# ============================================================
set -euo pipefail

CONF="/etc/securizar/ransomware/ransomware-canary.conf"
[[ -f "$CONF" ]] && source "$CONF"

STATE_FILE="${CANARY_STATE_FILE:-/var/lib/securizar/ransomware/canary-state.db}"
LOG="${CANARY_LOG:-/var/log/securizar/ransomware/canary-events.log}"
ALERT_SCRIPT="/usr/local/bin/alertar-canary-ransomware.sh"

mkdir -p "$(dirname "$LOG")"

log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] MONITOR: $1" | tee -a "$LOG"
}

if ! command -v inotifywait &>/dev/null; then
    log_msg "ERROR: inotifywait no encontrado. Instale inotify-tools"
    exit 1
fi

if [[ ! -f "$STATE_FILE" ]]; then
    log_msg "ERROR: No hay canaries desplegados. Ejecute: desplegar-canary-ransomware.sh deploy"
    exit 1
fi

# Construir lista de directorios a monitorear
WATCH_DIRS=()
while IFS='|' read -r filepath rest; do
    local_dir="$(dirname "$filepath")"
    # Evitar duplicados
    local found=0
    for d in "${WATCH_DIRS[@]+"${WATCH_DIRS[@]}"}"; do
        [[ "$d" == "$local_dir" ]] && found=1 && break
    done
    [[ $found -eq 0 ]] && WATCH_DIRS+=("$local_dir")
done < "$STATE_FILE"

if [[ ${#WATCH_DIRS[@]} -eq 0 ]]; then
    log_msg "ERROR: No se encontraron directorios para monitorear"
    exit 1
fi

log_msg "Iniciando monitor inotify para ${#WATCH_DIRS[@]} directorios"
log_msg "Directorios: ${WATCH_DIRS[*]}"

# Construir argumentos de inotifywait
WATCH_ARGS=()
for d in "${WATCH_DIRS[@]}"; do
    [[ -d "$d" ]] && WATCH_ARGS+=("$d")
done

if [[ ${#WATCH_ARGS[@]} -eq 0 ]]; then
    log_msg "ERROR: Ningun directorio de monitoreo existe"
    exit 1
fi

# Monitor principal con inotifywait
inotifywait -m -r \
    -e modify,delete,moved_from,moved_to,create,attrib \
    --format '%T %w%f %e' \
    --timefmt '%Y-%m-%d %H:%M:%S' \
    "${WATCH_ARGS[@]}" 2>/dev/null | while read -r timestamp filepath events; do

    # Verificar si es un canary file conocido
    if grep -qF "$filepath" "$STATE_FILE" 2>/dev/null; then
        log_msg "ALERTA: Canary afectado: $filepath evento=$events"

        # Determinar tipo de evento
        event_type="unknown"
        case "$events" in
            *DELETE*|*MOVED_FROM*)
                event_type="deleted"
                ;;
            *MODIFY*|*ATTRIB*)
                event_type="modified"
                ;;
            *CREATE*|*MOVED_TO*)
                event_type="replaced"
                ;;
        esac

        # Intentar identificar proceso responsable
        proc_info="unknown"
        # Buscar proceso que recien escribio al directorio
        suspect_pids=$(lsof "$(dirname "$filepath")" 2>/dev/null | awk 'NR>1{print $2}' | sort -u | head -5 || echo "")
        if [[ -n "$suspect_pids" ]]; then
            proc_info="$suspect_pids"
        fi

        # Ejecutar alerta
        if [[ -x "$ALERT_SCRIPT" ]]; then
            "$ALERT_SCRIPT" "$event_type" "$filepath" "$proc_info" &
        fi
    fi
done
EOF
    chmod +x /usr/local/bin/monitor-canary-ransomware.sh
    log_change "Creado" "/usr/local/bin/monitor-canary-ransomware.sh"

    # --- Servicio systemd para monitor canary ---
    log_info "Creando securizar-canary-monitor.service..."
    cat > /etc/systemd/system/securizar-canary-monitor.service << 'EOF'
[Unit]
Description=Securizar Ransomware Canary File Monitor - Modulo 60
Documentation=man:securizar(8)
After=network.target local-fs.target
Wants=network.target

[Service]
Type=simple
ExecStartPre=/usr/local/bin/desplegar-canary-ransomware.sh deploy
ExecStart=/usr/local/bin/monitor-canary-ransomware.sh
ExecStop=/bin/kill -TERM $MAINPID
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal
SyslogIdentifier=securizar-canary-monitor

# Seguridad del servicio
NoNewPrivileges=no
ProtectSystem=full
ReadWritePaths=/var/log/securizar /var/lib/securizar /etc/securizar /home /var /tmp /srv /opt
PrivateTmp=no

[Install]
WantedBy=multi-user.target
EOF
    log_change "Creado" "/etc/systemd/system/securizar-canary-monitor.service"

    # Timer para verificacion periodica de integridad
    cat > /etc/systemd/system/securizar-canary-verify.service << 'EOF'
[Unit]
Description=Securizar Canary File Integrity Verification
After=securizar-canary-monitor.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/desplegar-canary-ransomware.sh verify
StandardOutput=journal
StandardError=journal
SyslogIdentifier=securizar-canary-verify
EOF
    log_change "Creado" "/etc/systemd/system/securizar-canary-verify.service"

    cat > /etc/systemd/system/securizar-canary-verify.timer << 'EOF'
[Unit]
Description=Verificacion periodica de canary files anti-ransomware

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min
Persistent=true

[Install]
WantedBy=timers.target
EOF
    log_change "Creado" "/etc/systemd/system/securizar-canary-verify.timer"

    # Recargar systemd y habilitar
    systemctl daemon-reload 2>/dev/null || true

    if ask "¿Habilitar e iniciar el monitor de canary files ahora?"; then
        systemctl enable securizar-canary-monitor.service 2>/dev/null || true
        systemctl enable securizar-canary-verify.timer 2>/dev/null || true
        systemctl start securizar-canary-verify.timer 2>/dev/null || true
        # Desplegar canary files
        /usr/local/bin/desplegar-canary-ransomware.sh deploy 2>/dev/null || true
        log_change "Habilitado" "securizar-canary-monitor.service + timer"
        log_info "Monitor canary activo. Use: systemctl status securizar-canary-monitor"
    else
        log_skip "Inicio automatico del monitor canary"
    fi

    log_info "Canary files anti-ransomware configurados"
    log_info "  Gestion:    desplegar-canary-ransomware.sh {deploy|verify|list|remove}"
    log_info "  Monitor:    systemctl status securizar-canary-monitor"
    log_info "  Config:     $CANARY_CONF"
else
    log_skip "Canary files anti-ransomware"
fi

# ============================================================
# S2: PROTECCION CON LVM SNAPSHOTS
# ============================================================
log_section "S2: PROTECCION CON LVM SNAPSHOTS"

log_info "Proteccion automatica con snapshots LVM:"
log_info "  - Detecta volumenes logicos existentes"
log_info "  - Snapshots horarios automaticos"
log_info "  - Politica de retencion configurable"
log_info "  - Script de recuperacion desde snapshot"
log_info "  - Timer systemd para ejecucion programada"
log_info ""

if check_file_exists /usr/local/bin/gestionar-snapshot-ransomware.sh; then
    log_already "Proteccion LVM snapshot (gestionar-snapshot-ransomware.sh existe)"
elif ask "¿Configurar proteccion LVM snapshot anti-ransomware?"; then

    # Verificar si hay LVM disponible
    LVM_AVAILABLE=false
    if command -v lvs &>/dev/null; then
        LV_COUNT=$(lvs --noheadings 2>/dev/null | wc -l || echo "0")
        if [[ "$LV_COUNT" -gt 0 ]]; then
            LVM_AVAILABLE=true
            log_info "Detectados $LV_COUNT volumenes logicos LVM"
            lvs --noheadings -o lv_name,vg_name,lv_size 2>/dev/null || true
        else
            log_warn "LVM instalado pero no hay volumenes logicos"
        fi
    else
        log_warn "LVM no esta instalado en este sistema"
    fi

    # Configuracion de snapshots
    SNAP_CONF="${RANSOMWARE_CONF_DIR}/lvm-snapshot.conf"
    if [[ -f "$SNAP_CONF" ]]; then
        cp "$SNAP_CONF" "${BACKUP_DIR}/lvm-snapshot.conf.bak"
        log_change "Backup" "lvm-snapshot.conf existente"
    fi

    cat > "$SNAP_CONF" << 'EOF'
# ============================================================
# lvm-snapshot.conf - Configuracion de snapshots LVM
# ============================================================
# Modulo 60 - Proteccion Anti-Ransomware
# ============================================================

# Volumenes a proteger (auto = detectar automaticamente)
# Formato: VG/LV separados por espacio
SNAP_VOLUMES="auto"

# Tamano del snapshot (porcentaje del volumen original)
SNAP_SIZE_PCT=20

# Tamano minimo del snapshot en MB
SNAP_MIN_SIZE_MB=512

# Numero maximo de snapshots a retener por volumen
SNAP_RETENTION=24

# Prefijo para nombres de snapshot
SNAP_PREFIX="ransomware-snap"

# Habilitar snapshot automatico
SNAP_AUTO_ENABLED="true"

# Intervalo entre snapshots (en horas)
SNAP_INTERVAL_HOURS=1

# Log de operaciones
SNAP_LOG="/var/log/securizar/ransomware/lvm-snapshots.log"

# Espacio libre minimo en VG para crear snapshot (porcentaje)
SNAP_MIN_FREE_PCT=10

# Habilitar verificacion de integridad post-snapshot
SNAP_VERIFY="true"

# Notificar si el espacio libre es bajo
SNAP_LOW_SPACE_NOTIFY="true"
EOF
    chmod 600 "$SNAP_CONF"
    log_change "Creado" "$SNAP_CONF"

    # Script de gestion de snapshots LVM
    log_info "Creando /usr/local/bin/gestionar-snapshot-ransomware.sh..."
    cat > /usr/local/bin/gestionar-snapshot-ransomware.sh << 'EOF'
#!/bin/bash
# ============================================================
# gestionar-snapshot-ransomware.sh - Snapshots LVM anti-ransomware
# Modulo 60 - Proteccion Anti-Ransomware
# ============================================================
set -euo pipefail

CONF="/etc/securizar/ransomware/lvm-snapshot.conf"
if [[ ! -f "$CONF" ]]; then
    echo "[X] No existe $CONF" >&2
    exit 1
fi
source "$CONF"

LOG="${SNAP_LOG:-/var/log/securizar/ransomware/lvm-snapshots.log}"
mkdir -p "$(dirname "$LOG")"

log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG"
}

# Obtener lista de volumenes a proteger
get_volumes() {
    if [[ "${SNAP_VOLUMES:-auto}" == "auto" ]]; then
        lvs --noheadings -o vg_name,lv_name,lv_attr 2>/dev/null | \
            awk '$3 ~ /^-/ || $3 ~ /^V/ {print $1"/"$2}' | \
            grep -v "${SNAP_PREFIX}" || true
    else
        echo "$SNAP_VOLUMES" | tr ' ' '\n'
    fi
}

# Verificar espacio libre en VG
check_vg_space() {
    local vg="$1"
    local vg_free
    vg_free=$(vgs --noheadings --nosuffix --units m -o vg_free "$vg" 2>/dev/null | tr -d ' ')
    local vg_size
    vg_size=$(vgs --noheadings --nosuffix --units m -o vg_size "$vg" 2>/dev/null | tr -d ' ')

    if [[ -z "$vg_free" || -z "$vg_size" ]]; then
        return 1
    fi

    local free_pct
    free_pct=$(awk "BEGIN {printf \"%.0f\", ($vg_free/$vg_size)*100}")

    if [[ "$free_pct" -lt "${SNAP_MIN_FREE_PCT:-10}" ]]; then
        log_msg "WARN: VG $vg tiene solo ${free_pct}% libre (${vg_free}MB)"
        return 1
    fi
    return 0
}

# Calcular tamano de snapshot
calc_snap_size() {
    local vg="$1" lv="$2"
    local lv_size_mb
    lv_size_mb=$(lvs --noheadings --nosuffix --units m -o lv_size "$vg/$lv" 2>/dev/null | tr -d ' ')

    if [[ -z "$lv_size_mb" ]]; then
        echo "${SNAP_MIN_SIZE_MB:-512}"
        return
    fi

    local snap_size
    snap_size=$(awk "BEGIN {printf \"%.0f\", $lv_size_mb * ${SNAP_SIZE_PCT:-20} / 100}")

    if [[ "$snap_size" -lt "${SNAP_MIN_SIZE_MB:-512}" ]]; then
        snap_size="${SNAP_MIN_SIZE_MB:-512}"
    fi
    echo "${snap_size}"
}

create_snapshot() {
    log_msg "=== CREACION DE SNAPSHOTS ==="
    local created=0
    local errors=0

    while IFS='/' read -r vg lv; do
        [[ -z "$vg" || -z "$lv" ]] && continue

        log_msg "Procesando: $vg/$lv"

        # Verificar espacio
        if ! check_vg_space "$vg"; then
            log_msg "WARN: Espacio insuficiente en VG $vg, omitiendo $lv"
            ((errors++)) || true
            continue
        fi

        # Nombre del snapshot
        local snap_name="${SNAP_PREFIX}-${lv}-$(date +%Y%m%d-%H%M%S)"
        local snap_size
        snap_size=$(calc_snap_size "$vg" "$lv")

        log_msg "Creando snapshot: $snap_name (${snap_size}M)"

        if lvcreate -L "${snap_size}M" -s -n "$snap_name" "$vg/$lv" 2>>"$LOG"; then
            log_msg "OK: Snapshot $snap_name creado"
            ((created++)) || true

            # Verificar snapshot
            if [[ "${SNAP_VERIFY:-true}" == "true" ]]; then
                local snap_status
                snap_status=$(lvs --noheadings -o snap_percent "$vg/$snap_name" 2>/dev/null | tr -d ' ')
                log_msg "Snapshot $snap_name: ${snap_status:-0}% usado"
            fi
        else
            log_msg "ERROR: Fallo al crear snapshot $snap_name"
            ((errors++)) || true
        fi
    done < <(get_volumes)

    log_msg "Snapshots creados: $created, errores: $errors"
    echo "[+] $created snapshots creados ($errors errores)"
}

cleanup_snapshots() {
    log_msg "=== LIMPIEZA DE SNAPSHOTS ==="
    local retention="${SNAP_RETENTION:-24}"
    local removed=0

    while IFS='/' read -r vg lv; do
        [[ -z "$vg" || -z "$lv" ]] && continue

        # Listar snapshots de este LV ordenados por fecha
        local snap_list
        snap_list=$(lvs --noheadings -o lv_name "$vg" 2>/dev/null | \
            tr -d ' ' | grep "^${SNAP_PREFIX}-${lv}-" | sort || true)

        local snap_count
        snap_count=$(echo "$snap_list" | grep -c . || echo "0")

        if [[ "$snap_count" -gt "$retention" ]]; then
            local to_remove=$((snap_count - retention))
            log_msg "Limpiando $to_remove snapshots antiguos de $vg/$lv (retencion: $retention)"

            echo "$snap_list" | head -"$to_remove" | while read -r snap; do
                [[ -z "$snap" ]] && continue
                log_msg "Eliminando snapshot: $vg/$snap"
                if lvremove -f "$vg/$snap" 2>>"$LOG"; then
                    ((removed++)) || true
                else
                    log_msg "ERROR: No se pudo eliminar $vg/$snap"
                fi
            done
        fi
    done < <(get_volumes)

    log_msg "Snapshots eliminados: $removed"
    echo "[+] $removed snapshots antiguos eliminados"
}

list_snapshots() {
    echo ""
    echo "SNAPSHOTS LVM ANTI-RANSOMWARE"
    echo "=============================="

    if ! command -v lvs &>/dev/null; then
        echo "[X] LVM no disponible"
        return 1
    fi

    lvs --noheadings -o lv_name,vg_name,lv_size,snap_percent,lv_time 2>/dev/null | \
        grep "${SNAP_PREFIX}" | while read -r name vg size pct time; do
        printf "  %-45s  VG=%-10s  Size=%-8s  Used=%s%%  %s\n" \
            "$name" "$vg" "$size" "${pct:-0}" "${time:-}"
    done || echo "  No hay snapshots anti-ransomware"

    echo ""
    # Espacio libre en VGs
    echo "ESPACIO LIBRE EN VOLUME GROUPS:"
    vgs --noheadings -o vg_name,vg_size,vg_free 2>/dev/null | while read -r vg size free; do
        echo "  VG=$vg  Size=$size  Free=$free"
    done || echo "  No hay VGs disponibles"
    echo ""
}

recover_from_snapshot() {
    local target_lv="${1:-}"
    if [[ -z "$target_lv" ]]; then
        echo "Uso: $0 recover VG/LV"
        echo ""
        echo "Snapshots disponibles:"
        list_snapshots
        return 1
    fi

    local vg lv
    IFS='/' read -r vg lv <<< "$target_lv"

    echo "RECUPERACION DESDE SNAPSHOT"
    echo "==========================="
    echo ""
    echo "Volumenes snapshot disponibles para $vg/$lv:"

    local snaps
    snaps=$(lvs --noheadings -o lv_name "$vg" 2>/dev/null | \
        tr -d ' ' | grep "^${SNAP_PREFIX}-${lv}-" | sort -r || true)

    if [[ -z "$snaps" ]]; then
        echo "[X] No hay snapshots para $vg/$lv"
        return 1
    fi

    local i=1
    echo "$snaps" | while read -r snap; do
        local snap_size snap_pct
        snap_size=$(lvs --noheadings --nosuffix --units m -o lv_size "$vg/$snap" 2>/dev/null | tr -d ' ')
        snap_pct=$(lvs --noheadings -o snap_percent "$vg/$snap" 2>/dev/null | tr -d ' ')
        echo "  $i) $snap (${snap_size:-?}M, ${snap_pct:-0}% usado)"
        ((i++)) || true
    done

    echo ""
    read -p "Numero de snapshot a restaurar (0 para cancelar): " choice
    [[ "$choice" == "0" || -z "$choice" ]] && return 0

    local selected_snap
    selected_snap=$(echo "$snaps" | sed -n "${choice}p")
    if [[ -z "$selected_snap" ]]; then
        echo "[X] Seleccion invalida"
        return 1
    fi

    echo ""
    echo "ATENCION: Esto restaurara $vg/$lv desde $selected_snap"
    echo "Los datos actuales del volumen SE PERDERAN"
    read -p "¿Confirmar restauracion? (escriba SI en mayusculas): " confirm
    [[ "$confirm" != "SI" ]] && echo "Cancelado" && return 0

    log_msg "RECUPERACION: Restaurando $vg/$lv desde $selected_snap"

    # Merge del snapshot
    if lvconvert --merge "$vg/$selected_snap" 2>>"$LOG"; then
        log_msg "OK: Merge iniciado. Se requiere reboot para completar"
        echo "[+] Merge de snapshot iniciado"
        echo "[!] Se requiere REINICIAR el sistema para completar la restauracion"
        echo "    Ejecute: reboot"
    else
        log_msg "ERROR: Fallo al hacer merge de $vg/$selected_snap"
        echo "[X] Error al iniciar merge"
        return 1
    fi
}

usage() {
    echo "Uso: $0 {create|cleanup|list|recover|status}"
    echo ""
    echo "  create          - Crear snapshots de todos los volumenes protegidos"
    echo "  cleanup         - Eliminar snapshots antiguos segun retencion"
    echo "  list            - Listar snapshots existentes"
    echo "  recover VG/LV   - Recuperar volumen desde snapshot"
    echo "  status          - Mostrar estado general"
    exit 1
}

case "${1:-}" in
    create)  create_snapshot ;;
    cleanup) cleanup_snapshots ;;
    list)    list_snapshots ;;
    recover) recover_from_snapshot "${2:-}" ;;
    status)  list_snapshots ;;
    *)       usage ;;
esac
EOF
    chmod +x /usr/local/bin/gestionar-snapshot-ransomware.sh
    log_change "Creado" "/usr/local/bin/gestionar-snapshot-ransomware.sh"

    # Timer systemd para snapshots automaticos
    cat > /etc/systemd/system/securizar-lvm-snapshot.service << 'EOF'
[Unit]
Description=Securizar LVM Anti-Ransomware Snapshot
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/gestionar-snapshot-ransomware.sh create
ExecStartPost=/usr/local/bin/gestionar-snapshot-ransomware.sh cleanup
StandardOutput=journal
StandardError=journal
SyslogIdentifier=securizar-lvm-snapshot
EOF
    log_change "Creado" "/etc/systemd/system/securizar-lvm-snapshot.service"

    cat > /etc/systemd/system/securizar-lvm-snapshot.timer << 'EOF'
[Unit]
Description=Snapshot LVM anti-ransomware cada hora

[Timer]
OnBootSec=15min
OnUnitActiveSec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
    log_change "Creado" "/etc/systemd/system/securizar-lvm-snapshot.timer"

    systemctl daemon-reload 2>/dev/null || true

    if [[ "$LVM_AVAILABLE" == "true" ]]; then
        if ask "¿Habilitar snapshots LVM automaticos ahora?"; then
            systemctl enable securizar-lvm-snapshot.timer 2>/dev/null || true
            systemctl start securizar-lvm-snapshot.timer 2>/dev/null || true
            # Crear primer snapshot
            /usr/local/bin/gestionar-snapshot-ransomware.sh create 2>/dev/null || true
            log_change "Habilitado" "securizar-lvm-snapshot.timer (cada hora)"
        else
            log_skip "Inicio automatico de snapshots LVM"
        fi
    else
        log_warn "LVM no disponible - timer creado pero no activado"
        log_info "Active manualmente cuando configure LVM: systemctl enable --now securizar-lvm-snapshot.timer"
    fi

    log_info "Proteccion LVM snapshot anti-ransomware configurada"
    log_info "  Gestion: gestionar-snapshot-ransomware.sh {create|cleanup|list|recover}"
else
    log_skip "Proteccion LVM snapshot anti-ransomware"
fi

# ============================================================
# S3: WHITELISTING DE EJECUTABLES
# ============================================================
log_section "S3: WHITELISTING DE EJECUTABLES"

log_info "Control de ejecucion de aplicaciones:"
log_info "  - fapolicyd en RHEL/SUSE (si disponible)"
log_info "  - AppArmor en Debian/Ubuntu"
log_info "  - Bloqueo de ejecucion desde /tmp, /dev/shm, /var/tmp"
log_info "  - Mount options noexec en directorios temporales"
log_info "  - Reglas de ejecucion basadas en politicas"
log_info ""

if check_file_exists /usr/local/bin/verificar-whitelisting-ransomware.sh; then
    log_already "Whitelisting de ejecutables (verificar-whitelisting-ransomware.sh existe)"
elif ask "¿Configurar whitelisting de ejecutables anti-ransomware?"; then

    # --- Bloqueo de ejecucion desde /tmp, /dev/shm, /var/tmp ---
    log_info "Configurando bloqueo de ejecucion en directorios temporales..."

    FSTAB="/etc/fstab"
    if [[ -f "$FSTAB" ]]; then
        cp "$FSTAB" "${BACKUP_DIR}/fstab.bak"
        log_change "Backup" "/etc/fstab"
    fi

    # Funcion para agregar noexec a un mount point en fstab
    add_noexec_mount() {
        local mount_point="$1"
        local fstype="${2:-tmpfs}"

        if grep -q "^[^#].*[[:space:]]${mount_point}[[:space:]]" "$FSTAB" 2>/dev/null; then
            # Ya existe entrada - verificar si tiene noexec
            if grep "^[^#].*[[:space:]]${mount_point}[[:space:]]" "$FSTAB" | grep -q "noexec"; then
                log_info "$mount_point ya tiene noexec en fstab"
                return 0
            else
                # Agregar noexec a opciones existentes
                sed -i "s|\(^[^#].*[[:space:]]${mount_point}[[:space:]].*\)defaults\(.*\)|\1defaults,noexec,nosuid,nodev\2|" "$FSTAB" 2>/dev/null || true
                log_change "Modificado" "$FSTAB - noexec agregado a $mount_point"
            fi
        else
            # No existe entrada - agregar nueva
            echo "tmpfs    $mount_point    tmpfs    defaults,noexec,nosuid,nodev,size=512M    0 0" >> "$FSTAB"
            log_change "Agregado" "$FSTAB - $mount_point con noexec"
        fi

        # Remontar con noexec ahora
        mount -o remount,noexec,nosuid,nodev "$mount_point" 2>/dev/null || true
    }

    # Aplicar noexec a directorios temporales
    for tmp_dir in /tmp /dev/shm /var/tmp; do
        if mountpoint -q "$tmp_dir" 2>/dev/null || [[ -d "$tmp_dir" ]]; then
            add_noexec_mount "$tmp_dir"
        fi
    done

    # --- Politica fapolicyd (RHEL/SUSE) ---
    case "$DISTRO_FAMILY" in
        rhel|suse)
            log_info "Configurando fapolicyd para control de ejecucion..."
            if ! command -v fapolicyd &>/dev/null; then
                if ask "¿Instalar fapolicyd (control de ejecucion basado en politicas)?"; then
                    pkg_install fapolicyd || true
                else
                    log_skip "Instalacion de fapolicyd"
                fi
            fi

            if command -v fapolicyd &>/dev/null; then
                # Backup de configuracion existente
                if [[ -f /etc/fapolicyd/fapolicyd.conf ]]; then
                    cp /etc/fapolicyd/fapolicyd.conf "${BACKUP_DIR}/fapolicyd.conf.bak"
                    log_change "Backup" "/etc/fapolicyd/fapolicyd.conf"
                fi

                # Configuracion principal
                mkdir -p /etc/fapolicyd
                cat > /etc/fapolicyd/fapolicyd.conf << 'EOF'
# fapolicyd.conf - Configuracion anti-ransomware
# Modulo 60 - Proteccion Anti-Ransomware

permissive = 0
nice_val = 14
q_size = 800
uid_limit = 500

# Configuracion de base de datos
db_max_size = 50
subj_cache_size = 1549
obj_cache_size = 8191

# Integración con rpm/dpkg
integrity = sha256

# Confiar en el gestor de paquetes del sistema
trust = rpmdb,file

# Syslog
syslog_format = rule,dec,perm,uid,gid,pid,exe,:path,:ftype
EOF
                log_change "Configurado" "/etc/fapolicyd/fapolicyd.conf"

                # Reglas anti-ransomware
                if [[ -d /etc/fapolicyd/rules.d ]]; then
                    cat > /etc/fapolicyd/rules.d/90-anti-ransomware.rules << 'EOF'
# Reglas anti-ransomware para fapolicyd
# Modulo 60 - Proteccion Anti-Ransomware

# Denegar ejecucion desde /tmp
deny_audit perm=any all : dir=/tmp/
deny_audit perm=any all : dir=/var/tmp/
deny_audit perm=any all : dir=/dev/shm/

# Denegar ejecucion de scripts descargados sin firma
deny_audit perm=execute all : ftype=application/x-shellscript trust=0
deny_audit perm=execute all : ftype=application/x-executable trust=0

# Permitir ejecutables del sistema de paquetes
allow perm=any uid=0 : trust=1
allow perm=execute all : trust=1

# Denegar cualquier otro ejecutable no confiable
deny_audit perm=execute all : trust=0
EOF
                    log_change "Creado" "/etc/fapolicyd/rules.d/90-anti-ransomware.rules"
                fi

                if ask "¿Habilitar fapolicyd ahora?"; then
                    systemctl enable fapolicyd 2>/dev/null || true
                    systemctl restart fapolicyd 2>/dev/null || true
                    log_change "Habilitado" "fapolicyd.service"
                else
                    log_skip "Activacion de fapolicyd"
                fi
            fi
            ;;

        debian)
            log_info "Configurando AppArmor para control de ejecucion..."

            # Verificar AppArmor
            if ! command -v apparmor_status &>/dev/null; then
                if ask "¿Instalar AppArmor para control de ejecucion?"; then
                    pkg_install apparmor apparmor-utils || true
                else
                    log_skip "Instalacion de AppArmor"
                fi
            fi

            if command -v apparmor_status &>/dev/null; then
                # Perfil AppArmor para bloquear ejecucion desde /tmp
                mkdir -p /etc/apparmor.d
                cat > /etc/apparmor.d/securizar-anti-ransomware << 'EOF'
# AppArmor profile: securizar anti-ransomware
# Modulo 60 - Bloquea ejecucion desde directorios temporales
# Aplicado globalmente via abstractions

abi <abi/3.0>,

profile securizar-anti-ransomware flags=(attach_disconnected) {
  # Permitir lectura general
  / r,
  /** r,

  # Denegar ejecucion desde directorios temporales
  deny /tmp/** mx,
  deny /var/tmp/** mx,
  deny /dev/shm/** mx,

  # Denegar escritura a binarios del sistema
  deny /usr/bin/** w,
  deny /usr/sbin/** w,
  deny /usr/lib/** w,
  deny /usr/local/bin/** w,
  deny /usr/local/sbin/** w,

  # Denegar acceso a herramientas de cifrado por procesos no autorizados
  deny /usr/bin/openssl x,
  deny /usr/bin/gpg x,
  deny /usr/bin/gpg2 x,

  # Log de denegaciones
  audit deny /tmp/** x,
  audit deny /var/tmp/** x,
}
EOF
                log_change "Creado" "/etc/apparmor.d/securizar-anti-ransomware"

                # Script para gestionar perfiles
                cat > /usr/local/bin/gestionar-apparmor-ransomware.sh << 'EOF'
#!/bin/bash
# Gestion de perfiles AppArmor anti-ransomware
set -euo pipefail

PROFILE="/etc/apparmor.d/securizar-anti-ransomware"

case "${1:-}" in
    enforce)
        aa-enforce "$PROFILE" 2>/dev/null || true
        echo "[+] Perfil anti-ransomware en modo enforce"
        ;;
    complain)
        aa-complain "$PROFILE" 2>/dev/null || true
        echo "[+] Perfil anti-ransomware en modo complain (solo log)"
        ;;
    disable)
        aa-disable "$PROFILE" 2>/dev/null || true
        echo "[+] Perfil anti-ransomware deshabilitado"
        ;;
    status)
        apparmor_status 2>/dev/null | grep -A2 "securizar" || echo "Perfil no cargado"
        ;;
    *)
        echo "Uso: $0 {enforce|complain|disable|status}"
        exit 1
        ;;
esac
EOF
                chmod +x /usr/local/bin/gestionar-apparmor-ransomware.sh
                log_change "Creado" "/usr/local/bin/gestionar-apparmor-ransomware.sh"

                if ask "¿Cargar perfil AppArmor en modo complain (solo log)?"; then
                    apparmor_parser -r /etc/apparmor.d/securizar-anti-ransomware 2>/dev/null || true
                    aa-complain /etc/apparmor.d/securizar-anti-ransomware 2>/dev/null || true
                    log_change "Activado" "AppArmor anti-ransomware (modo complain)"
                    log_info "Para modo enforce: gestionar-apparmor-ransomware.sh enforce"
                else
                    log_skip "Activacion de perfil AppArmor anti-ransomware"
                fi
            fi
            ;;

        arch)
            log_info "Arch Linux: configurando restricciones de ejecucion via mount options..."
            log_info "Las opciones noexec ya fueron aplicadas a /tmp, /dev/shm, /var/tmp"
            ;;
    esac

    # --- Script de verificacion de whitelisting ---
    cat > /usr/local/bin/verificar-whitelisting-ransomware.sh << 'EOF'
#!/bin/bash
# ============================================================
# verificar-whitelisting-ransomware.sh - Verificar estado
# Modulo 60 - Proteccion Anti-Ransomware
# ============================================================
set -euo pipefail

echo ""
echo "ESTADO DE WHITELISTING ANTI-RANSOMWARE"
echo "======================================="
echo ""

# Verificar noexec en puntos de montaje
echo "=== MOUNT OPTIONS ==="
for mp in /tmp /dev/shm /var/tmp; do
    if mountpoint -q "$mp" 2>/dev/null; then
        opts=$(mount | grep " $mp " | awk '{print $NF}')
        if echo "$opts" | grep -q "noexec"; then
            echo "  [OK]   $mp tiene noexec ($opts)"
        else
            echo "  [FAIL] $mp SIN noexec ($opts)"
        fi
    else
        echo "  [WARN] $mp no es punto de montaje"
    fi
done
echo ""

# Verificar fapolicyd
echo "=== FAPOLICYD ==="
if command -v fapolicyd &>/dev/null; then
    if systemctl is-active fapolicyd &>/dev/null; then
        echo "  [OK]   fapolicyd activo"
    else
        echo "  [WARN] fapolicyd instalado pero inactivo"
    fi
else
    echo "  [INFO] fapolicyd no instalado"
fi
echo ""

# Verificar AppArmor
echo "=== APPARMOR ==="
if command -v apparmor_status &>/dev/null; then
    profiles=$(apparmor_status 2>/dev/null | grep "profiles are loaded" | awk '{print $1}')
    enforced=$(apparmor_status 2>/dev/null | grep "profiles are in enforce" | awk '{print $1}')
    echo "  Perfiles cargados: ${profiles:-0}"
    echo "  En enforce: ${enforced:-0}"
    if apparmor_status 2>/dev/null | grep -q "securizar-anti-ransomware"; then
        echo "  [OK]   Perfil anti-ransomware presente"
    else
        echo "  [WARN] Perfil anti-ransomware no cargado"
    fi
else
    echo "  [INFO] AppArmor no disponible"
fi
echo ""

# Intentar ejecutar desde /tmp
echo "=== TEST DE EJECUCION ==="
TEST_FILE=$(mktemp /tmp/test-exec-XXXXXX)
echo '#!/bin/bash' > "$TEST_FILE"
echo 'echo "EJECUTADO"' >> "$TEST_FILE"
chmod +x "$TEST_FILE"
if "$TEST_FILE" 2>/dev/null; then
    echo "  [FAIL] Se pudo ejecutar desde /tmp"
    rm -f "$TEST_FILE"
else
    echo "  [OK]   Ejecucion bloqueada en /tmp"
    rm -f "$TEST_FILE"
fi
echo ""
EOF
    chmod +x /usr/local/bin/verificar-whitelisting-ransomware.sh
    log_change "Creado" "/usr/local/bin/verificar-whitelisting-ransomware.sh"

    log_info "Whitelisting de ejecutables configurado"
    log_info "  Verificar: verificar-whitelisting-ransomware.sh"
else
    log_skip "Whitelisting de ejecutables anti-ransomware"
fi

# ============================================================
# S4: MONITOREO DE CAMBIOS MASIVOS DE ARCHIVOS
# ============================================================
log_section "S4: MONITOREO DE CAMBIOS MASIVOS DE ARCHIVOS"

log_info "Deteccion de cambios masivos indicativos de ransomware:"
log_info "  - Reglas auditd para create/delete/rename en masa"
log_info "  - Umbral de deteccion: >100 archivos/minuto"
log_info "  - Integracion con journald para alertas"
log_info "  - Script de analisis en tiempo real"
log_info "  - Respuesta automatica ante deteccion"
log_info ""

if check_file_exists /usr/local/bin/analizar-cambios-masivos.sh; then
    log_already "Monitoreo de cambios masivos (analizar-cambios-masivos.sh existe)"
elif ask "¿Configurar monitoreo de cambios masivos de archivos?"; then

    # Verificar auditd
    if ! command -v auditctl &>/dev/null; then
        log_info "Instalando audit..."
        pkg_install audit || true
    fi

    # Habilitar auditd
    if command -v auditctl &>/dev/null; then
        systemctl enable auditd 2>/dev/null || true
        systemctl start auditd 2>/dev/null || true

        # Backup de reglas de auditd existentes
        AUDIT_RULES_DIR=""
        if [[ -d /etc/audit/rules.d ]]; then
            AUDIT_RULES_DIR="/etc/audit/rules.d"
        elif [[ -d /etc/audit ]]; then
            AUDIT_RULES_DIR="/etc/audit"
        fi

        if [[ -n "$AUDIT_RULES_DIR" ]]; then
            # Reglas auditd para deteccion de ransomware
            AUDIT_RANSOMWARE_RULES="${AUDIT_RULES_DIR}/60-ransomware-detection.rules"
            if [[ -f "$AUDIT_RANSOMWARE_RULES" ]]; then
                cp "$AUDIT_RANSOMWARE_RULES" "${BACKUP_DIR}/60-ransomware-detection.rules.bak"
                log_change "Backup" "reglas auditd existentes"
            fi

            cat > "$AUDIT_RANSOMWARE_RULES" << 'EOF'
## ============================================================
## 60-ransomware-detection.rules - Deteccion de ransomware
## Modulo 60 - Proteccion Anti-Ransomware
## ============================================================

## Monitorear cambios masivos en directorios de datos
## rename, unlink (delete), open con O_WRONLY o O_RDWR

# Monitorear escritura/eliminacion masiva en /home
-a always,exit -F dir=/home -F perm=w -F key=ransomware_write_home
-a always,exit -F dir=/home -S rename -S renameat -S renameat2 -F key=ransomware_rename_home
-a always,exit -F dir=/home -S unlink -S unlinkat -F key=ransomware_delete_home

# Monitorear escritura/eliminacion masiva en /srv
-a always,exit -F dir=/srv -F perm=w -F key=ransomware_write_srv
-a always,exit -F dir=/srv -S rename -S renameat -S renameat2 -F key=ransomware_rename_srv
-a always,exit -F dir=/srv -S unlink -S unlinkat -F key=ransomware_delete_srv

# Monitorear escritura/eliminacion masiva en /var/lib
-a always,exit -F dir=/var/lib -F perm=w -F key=ransomware_write_varlib
-a always,exit -F dir=/var/lib -S rename -S renameat -S renameat2 -F key=ransomware_rename_varlib

# Monitorear cambios en /opt
-a always,exit -F dir=/opt -F perm=w -F key=ransomware_write_opt
-a always,exit -F dir=/opt -S rename -S renameat -S renameat2 -F key=ransomware_rename_opt

# Monitorear creacion de archivos con extensiones de ransomware
-a always,exit -S open -S openat -S creat -F exit=-EACCES -F key=ransomware_access_denied
-a always,exit -S rename -S renameat -S renameat2 -F key=ransomware_rename_global

# Monitorear uso de herramientas de cifrado
-a always,exit -F path=/usr/bin/openssl -F perm=x -F key=ransomware_crypto_tool
-a always,exit -F path=/usr/bin/gpg -F perm=x -F key=ransomware_crypto_tool
-a always,exit -F path=/usr/bin/gpg2 -F perm=x -F key=ransomware_crypto_tool
-a always,exit -F path=/usr/bin/ccrypt -F perm=x -F key=ransomware_crypto_tool
-a always,exit -F path=/usr/bin/age -F perm=x -F key=ransomware_crypto_tool

# Monitorear borrado masivo
-a always,exit -S unlink -S unlinkat -S rmdir -F dir=/home -F key=ransomware_mass_delete
-a always,exit -S unlink -S unlinkat -S rmdir -F dir=/srv -F key=ransomware_mass_delete

# Monitorear cambios en archivos de backup
-a always,exit -F dir=/var/backups -F perm=wa -F key=ransomware_backup_tamper
-a always,exit -F dir=/mnt -F perm=wa -F key=ransomware_mount_tamper
EOF
            log_change "Creado" "$AUDIT_RANSOMWARE_RULES"

            # Cargar reglas
            augenrules --load 2>/dev/null || auditctl -R "$AUDIT_RANSOMWARE_RULES" 2>/dev/null || true
            log_change "Cargadas" "reglas auditd anti-ransomware"
        fi
    fi

    # --- Configuracion de umbrales ---
    THRESHOLD_CONF="${RANSOMWARE_CONF_DIR}/mass-change-threshold.conf"
    cat > "$THRESHOLD_CONF" << 'EOF'
# ============================================================
# mass-change-threshold.conf - Umbrales de deteccion
# ============================================================
# Modulo 60 - Proteccion Anti-Ransomware
# ============================================================

# Numero de cambios por minuto que dispara alerta
THRESHOLD_FILES_PER_MIN=100

# Numero de renombramientos por minuto (indicador de cifrado)
THRESHOLD_RENAMES_PER_MIN=50

# Numero de eliminaciones por minuto
THRESHOLD_DELETES_PER_MIN=80

# Umbral de archivos con extension sospechosa creados
THRESHOLD_SUSPICIOUS_EXT=10

# Extensiones sospechosas (ransomware conocido)
SUSPICIOUS_EXTENSIONS=".encrypted .locked .crypted .crypt .crypto .enc .locky .cerber .zepto .odin .thor .aesir .zzzzz .micro .mp3 .xxx .ttt .vvv .ecc .ezz .exx .abc .aaa .xtbl .WNCRY .wncry .wcry .wncryt .lock .LOL .fun .dharma .arrow .bip .combo .gamma .heets .java .monro .STOP .djvu .roger .btc .ETH .id"

# Ventana de tiempo para analisis (segundos)
ANALYSIS_WINDOW=60

# Accion ante deteccion: alert | alert+kill | alert+isolate
MASS_CHANGE_ACTION="alert"

# Log
MASS_CHANGE_LOG="/var/log/securizar/ransomware/mass-changes.log"

# PID del analizador
ANALYZER_PID_FILE="/run/securizar-mass-change-analyzer.pid"
EOF
    chmod 600 "$THRESHOLD_CONF"
    log_change "Creado" "$THRESHOLD_CONF"

    # --- Script analizador de cambios masivos ---
    log_info "Creando /usr/local/bin/analizar-cambios-masivos.sh..."
    cat > /usr/local/bin/analizar-cambios-masivos.sh << 'EOF'
#!/bin/bash
# ============================================================
# analizar-cambios-masivos.sh - Detector de cambios masivos
# Modulo 60 - Proteccion Anti-Ransomware
# ============================================================
set -euo pipefail

CONF="/etc/securizar/ransomware/mass-change-threshold.conf"
[[ -f "$CONF" ]] && source "$CONF"

LOG="${MASS_CHANGE_LOG:-/var/log/securizar/ransomware/mass-changes.log}"
PID_FILE="${ANALYZER_PID_FILE:-/run/securizar-mass-change-analyzer.pid}"
ALERT_SCRIPT="/usr/local/bin/alertar-canary-ransomware.sh"
WINDOW="${ANALYSIS_WINDOW:-60}"
THRESHOLD="${THRESHOLD_FILES_PER_MIN:-100}"
RENAME_THRESHOLD="${THRESHOLD_RENAMES_PER_MIN:-50}"
DELETE_THRESHOLD="${THRESHOLD_DELETES_PER_MIN:-80}"
SUSP_EXT_THRESHOLD="${THRESHOLD_SUSPICIOUS_EXT:-10}"
ACTION="${MASS_CHANGE_ACTION:-alert}"

mkdir -p "$(dirname "$LOG")"
mkdir -p "$(dirname "$PID_FILE")"

log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG"
}

analyze_once() {
    local start_time
    start_time=$(date -d "-${WINDOW} seconds" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')

    # Contar eventos de auditd en la ventana
    local write_count=0 rename_count=0 delete_count=0 susp_ext_count=0

    # Analizar desde ausearch
    if command -v ausearch &>/dev/null; then
        write_count=$(ausearch -k ransomware_write_home -ts recent 2>/dev/null | grep -c "^type=SYSCALL" || echo "0")
        rename_count=$(ausearch -k ransomware_rename_global -ts recent 2>/dev/null | grep -c "^type=SYSCALL" || echo "0")
        delete_count=$(ausearch -k ransomware_mass_delete -ts recent 2>/dev/null | grep -c "^type=SYSCALL" || echo "0")

        # Buscar extensiones sospechosas en renames
        if [[ -n "${SUSPICIOUS_EXTENSIONS:-}" ]]; then
            for ext in $SUSPICIOUS_EXTENSIONS; do
                local ext_count
                ext_count=$(ausearch -k ransomware_rename_global -ts recent 2>/dev/null | grep -c "$ext" || echo "0")
                susp_ext_count=$((susp_ext_count + ext_count))
            done
        fi
    fi

    # Evaluar umbrales
    local alert_triggered=false
    local alert_reason=""

    if [[ "$write_count" -gt "$THRESHOLD" ]]; then
        alert_triggered=true
        alert_reason="Escrituras masivas: ${write_count}/${THRESHOLD} en ${WINDOW}s"
    fi

    if [[ "$rename_count" -gt "$RENAME_THRESHOLD" ]]; then
        alert_triggered=true
        alert_reason="${alert_reason:+$alert_reason | }Renombramientos masivos: ${rename_count}/${RENAME_THRESHOLD} en ${WINDOW}s"
    fi

    if [[ "$delete_count" -gt "$DELETE_THRESHOLD" ]]; then
        alert_triggered=true
        alert_reason="${alert_reason:+$alert_reason | }Eliminaciones masivas: ${delete_count}/${DELETE_THRESHOLD} en ${WINDOW}s"
    fi

    if [[ "$susp_ext_count" -gt "$SUSP_EXT_THRESHOLD" ]]; then
        alert_triggered=true
        alert_reason="${alert_reason:+$alert_reason | }Extensiones sospechosas: ${susp_ext_count}/${SUSP_EXT_THRESHOLD}"
    fi

    if [[ "$alert_triggered" == "true" ]]; then
        log_msg "ALERTA RANSOMWARE: $alert_reason"
        logger -t "securizar-ransomware" -p auth.crit "MASS CHANGE ALERT: $alert_reason"

        # Identificar procesos con mas actividad de disco
        local top_procs
        top_procs=$(ps aux --sort=-%mem | head -20 || true)
        log_msg "Procesos con mayor actividad: $top_procs"

        # Ejecutar alerta
        if [[ -x "$ALERT_SCRIPT" ]]; then
            "$ALERT_SCRIPT" "mass_change" "multiple_files" "audit_threshold" &
        fi

        # Accion adicional
        if [[ "$ACTION" == *"kill"* ]]; then
            # Buscar proceso con mas opens en audit
            local suspect_pid
            suspect_pid=$(ausearch -k ransomware_write_home -ts recent 2>/dev/null | \
                grep "^type=SYSCALL" | grep -oP 'pid=\K[0-9]+' | \
                sort | uniq -c | sort -rn | head -1 | awk '{print $2}' || echo "")
            if [[ -n "$suspect_pid" && "$suspect_pid" != "1" ]]; then
                log_msg "AUTO_KILL: Matando proceso sospechoso PID=$suspect_pid"
                kill -STOP "$suspect_pid" 2>/dev/null || true
                kill -9 "$suspect_pid" 2>/dev/null || true
            fi
        fi

        if [[ "$ACTION" == *"isolate"* ]]; then
            log_msg "AISLAMIENTO: Activando aislamiento de red"
            if [[ -x "/usr/local/bin/respuesta-emergencia-ransomware.sh" ]]; then
                /usr/local/bin/respuesta-emergencia-ransomware.sh isolate-network 2>/dev/null &
            fi
        fi

        return 1
    fi

    return 0
}

monitor_continuous() {
    echo $$ > "$PID_FILE"
    log_msg "Monitor de cambios masivos iniciado (PID: $$)"
    log_msg "Umbrales: writes=$THRESHOLD renames=$RENAME_THRESHOLD deletes=$DELETE_THRESHOLD susp_ext=$SUSP_EXT_THRESHOLD"

    while true; do
        analyze_once || true
        sleep "$WINDOW"
    done
}

status() {
    echo ""
    echo "ESTADO DEL MONITOR DE CAMBIOS MASIVOS"
    echo "======================================"
    echo ""

    if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE" 2>/dev/null)" 2>/dev/null; then
        echo "  [ACTIVO] Monitor ejecutandose (PID: $(cat "$PID_FILE"))"
    else
        echo "  [INACTIVO] Monitor no ejecutandose"
    fi
    echo ""

    echo "  Umbrales configurados:"
    echo "    Escrituras/min:    $THRESHOLD"
    echo "    Renombramientos/min: $RENAME_THRESHOLD"
    echo "    Eliminaciones/min: $DELETE_THRESHOLD"
    echo "    Extensiones sospechosas: $SUSP_EXT_THRESHOLD"
    echo ""

    echo "  Ultimas alertas:"
    if [[ -f "$LOG" ]]; then
        grep "ALERTA" "$LOG" | tail -5 | while read -r line; do
            echo "    $line"
        done
    else
        echo "    Sin alertas registradas"
    fi
    echo ""

    # Contar eventos recientes de auditd
    if command -v ausearch &>/dev/null; then
        local recent_writes
        recent_writes=$(ausearch -k ransomware_write_home -ts recent 2>/dev/null | grep -c "^type=SYSCALL" || echo "0")
        local recent_renames
        recent_renames=$(ausearch -k ransomware_rename_global -ts recent 2>/dev/null | grep -c "^type=SYSCALL" || echo "0")
        echo "  Eventos auditd recientes:"
        echo "    Escrituras: $recent_writes"
        echo "    Renombramientos: $recent_renames"
    fi
    echo ""
}

usage() {
    echo "Uso: $0 {monitor|analyze|status|stop}"
    echo ""
    echo "  monitor  - Iniciar monitoreo continuo"
    echo "  analyze  - Analisis unico del periodo reciente"
    echo "  status   - Ver estado del monitor"
    echo "  stop     - Detener monitor"
    exit 1
}

case "${1:-}" in
    monitor)  monitor_continuous ;;
    analyze)  analyze_once && echo "[+] Sin alertas" || echo "[!] Alerta detectada" ;;
    status)   status ;;
    stop)
        if [[ -f "$PID_FILE" ]]; then
            kill "$(cat "$PID_FILE")" 2>/dev/null || true
            rm -f "$PID_FILE"
            echo "[+] Monitor detenido"
        else
            echo "[!] Monitor no esta ejecutandose"
        fi
        ;;
    *)  usage ;;
esac
EOF
    chmod +x /usr/local/bin/analizar-cambios-masivos.sh
    log_change "Creado" "/usr/local/bin/analizar-cambios-masivos.sh"

    # Servicio systemd para el analizador
    cat > /etc/systemd/system/securizar-mass-change-monitor.service << 'EOF'
[Unit]
Description=Securizar Mass File Change Detector - Anti-Ransomware
Documentation=man:securizar(8)
After=auditd.service
Requires=auditd.service

[Service]
Type=simple
ExecStart=/usr/local/bin/analizar-cambios-masivos.sh monitor
ExecStop=/usr/local/bin/analizar-cambios-masivos.sh stop
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal
SyslogIdentifier=securizar-mass-change

# Seguridad
NoNewPrivileges=no
ProtectSystem=full
ReadWritePaths=/var/log/securizar /var/lib/securizar /run

[Install]
WantedBy=multi-user.target
EOF
    log_change "Creado" "/etc/systemd/system/securizar-mass-change-monitor.service"

    systemctl daemon-reload 2>/dev/null || true

    if ask "¿Habilitar monitor de cambios masivos ahora?"; then
        systemctl enable securizar-mass-change-monitor.service 2>/dev/null || true
        systemctl start securizar-mass-change-monitor.service 2>/dev/null || true
        log_change "Habilitado" "securizar-mass-change-monitor.service"
    else
        log_skip "Inicio automatico del monitor de cambios masivos"
    fi

    log_info "Monitoreo de cambios masivos configurado"
    log_info "  Analisis: analizar-cambios-masivos.sh {monitor|analyze|status}"
    log_info "  Reglas auditd: ${AUDIT_RANSOMWARE_RULES:-/etc/audit/rules.d/60-ransomware-detection.rules}"
else
    log_skip "Monitoreo de cambios masivos anti-ransomware"
fi

# ============================================================
# S5: EXTENSION BLACKLISTING & YARA
# ============================================================
log_section "S5: EXTENSION BLACKLISTING & YARA RULES"

log_info "Deteccion de indicadores de ransomware via extensiones y YARA:"
log_info "  - Base de datos de extensiones ransomware conocidas"
log_info "  - Reglas YARA para patrones: notas de rescate, crypto API"
log_info "  - Script de escaneo bajo demanda y programado"
log_info "  - Integracion con inotify para deteccion en tiempo real"
log_info "  - Actualizacion de firmas"
log_info ""

if check_file_exists /usr/local/bin/escanear-ransomware.sh; then
    log_already "Deteccion por extensiones y YARA (escanear-ransomware.sh existe)"
elif ask "¿Configurar deteccion por extensiones y YARA anti-ransomware?"; then

    # Instalar YARA si no esta disponible
    if ! command -v yara &>/dev/null; then
        log_info "Instalando YARA..."
        pkg_install yara || true
    fi

    # --- Base de datos de extensiones ransomware ---
    EXTENSIONS_DB="${RANSOMWARE_CONF_DIR}/ransomware-extensions.db"
    log_info "Creando base de datos de extensiones ransomware..."
    cat > "$EXTENSIONS_DB" << 'EOF'
# ============================================================
# ransomware-extensions.db - Extensiones conocidas de ransomware
# ============================================================
# Formato: extension|familia|prioridad(1-3)
# Prioridad: 1=critica, 2=alta, 3=media
# ============================================================

# WannaCry / WannaCrypt
.WNCRY|WannaCry|1
.wncry|WannaCry|1
.wcry|WannaCry|1
.wncryt|WannaCry|1
.WNCRYT|WannaCry|1

# Locky variantes
.locky|Locky|1
.zepto|Locky-Zepto|1
.odin|Locky-Odin|1
.thor|Locky-Thor|1
.aesir|Locky-Aesir|1
.zzzzz|Locky|1
.osiris|Locky-Osiris|1

# CryptoLocker / CryptoWall
.encrypted|CryptoGeneric|1
.locked|CryptoGeneric|1
.crypted|CryptoGeneric|1
.crypt|CryptoGeneric|2
.crypto|CryptoGeneric|2
.enc|CryptoGeneric|2

# Cerber
.cerber|Cerber|1
.cerber2|Cerber|1
.cerber3|Cerber|1
.ccc|CryptoWall|1

# STOP/Djvu
.STOP|STOP-Djvu|1
.djvu|STOP-Djvu|1
.djvuq|STOP-Djvu|1
.djvur|STOP-Djvu|1
.djvut|STOP-Djvu|1
.djvuu|STOP-Djvu|1
.udjvu|STOP-Djvu|1
.uudjvu|STOP-Djvu|1
.nols|STOP-Djvu|1
.werd|STOP-Djvu|1
.topi|STOP-Djvu|1
.reig|STOP-Djvu|1

# Dharma / CrySiS
.dharma|Dharma|1
.arrow|Dharma|1
.bip|Dharma|1
.combo|Dharma|1
.gamma|Dharma|1
.heets|Dharma|1
.java|Dharma|2
.monro|Dharma|1
.roger|Dharma|1
.wallet|Dharma|1
.arena|Dharma|1

# GandCrab
.GDCB|GandCrab|1
.CRAB|GandCrab|1
.KRAB|GandCrab|1
.gdcb|GandCrab|1

# Ryuk
.ryk|Ryuk|1
.RYK|Ryuk|1

# Maze
.maze|Maze|1

# REvil / Sodinokibi
.sodinokibi|REvil|1

# Conti
.CONTI|Conti|1

# LockBit
.lockbit|LockBit|1
.abcd|LockBit|1

# BlackCat / ALPHV
.sykffle|BlackCat|1

# Generico
.lock|Generic|2
.LOL|Generic|2
.fun|Generic|2
.xxx|Generic|3
.ttt|Generic|3
.vvv|Generic|3
.ecc|Generic|2
.ezz|Generic|2
.exx|Generic|2
.abc|Generic|3
.aaa|Generic|3
.xtbl|Generic|1
.micro|Generic|2
.mp3|TeslaCrypt|3
.btc|Generic|2
.ETH|Generic|2
.id|Generic|3
.pays|Generic|2
.ransom|Generic|1
.cry|Generic|2
.breaking_bad|Generic|2
.hacked|Generic|2
.pay|Generic|2
.payms|Generic|2
.paymst|Generic|2
.payrms|Generic|2
.keybtc@inbox_com|Generic|1
.kimcilware|KimcilWare|1
.LeChiffre|LeChiffre|1
.oor|Generic|2
.magic|Generic|2
.enigma|Enigma|1
.hush|Hush|1
.silent|Generic|2
EOF
    chmod 644 "$EXTENSIONS_DB"
    log_change "Creado" "$EXTENSIONS_DB ($(grep -c '^[^#]' "$EXTENSIONS_DB" || echo 0) extensiones)"

    # --- Reglas YARA ---
    YARA_RULES_DIR="${RANSOMWARE_CONF_DIR}/yara-rules"
    mkdir -p "$YARA_RULES_DIR"

    log_info "Creando reglas YARA anti-ransomware..."
    cat > "${YARA_RULES_DIR}/ransomware_indicators.yar" << 'EOF'
/*
 * ransomware_indicators.yar - Reglas YARA para deteccion de ransomware
 * Modulo 60 - Proteccion Anti-Ransomware
 */

rule RansomNote_Generic
{
    meta:
        description = "Detecta notas de rescate genericas"
        author = "securizar-modulo60"
        severity = "critical"

    strings:
        $r1 = "Your files have been encrypted" ascii nocase
        $r2 = "your personal files are encrypted" ascii nocase
        $r3 = "all your files have been encrypted" ascii nocase
        $r4 = "to decrypt your files" ascii nocase
        $r5 = "send bitcoin" ascii nocase
        $r6 = "bitcoin wallet" ascii nocase
        $r7 = "pay the ransom" ascii nocase
        $r8 = "decrypt your files" ascii nocase
        $r9 = "your files are locked" ascii nocase
        $r10 = "files will be permanently deleted" ascii nocase
        $r11 = "buy decryption key" ascii nocase
        $r12 = "RSA-2048" ascii nocase
        $r13 = "AES-256" ascii nocase
        $r14 = "decryption tool" ascii nocase
        $r15 = "ransom note" ascii nocase
        $r16 = "payment address" ascii nocase
        $r17 = "monero wallet" ascii nocase
        $r18 = "tor browser" ascii nocase
        $r19 = ".onion" ascii nocase

        $btc1 = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii
        $btc2 = /bc1[a-zA-HJ-NP-Z0-9]{39,59}/ ascii
        $xmr = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ ascii

    condition:
        3 of ($r*) or (1 of ($r*) and 1 of ($btc*, $xmr))
}

rule RansomNote_WannaCry
{
    meta:
        description = "Detecta notas de WannaCry"
        author = "securizar-modulo60"
        severity = "critical"

    strings:
        $w1 = "Wanna Decryptor" ascii nocase
        $w2 = "WanaCrypt0r" ascii nocase
        $w3 = "WANACRY" ascii nocase
        $w4 = "@WanaDecryptor@" ascii
        $w5 = "WanaDecryptor" ascii

    condition:
        any of them
}

rule RansomNote_LockBit
{
    meta:
        description = "Detecta notas de LockBit"
        author = "securizar-modulo60"
        severity = "critical"

    strings:
        $l1 = "LockBit" ascii nocase
        $l2 = "Restore-My-Files.txt" ascii nocase
        $l3 = "lockbit-blog" ascii nocase
        $l4 = "LOCKBIT" ascii

    condition:
        any of them
}

rule RansomNote_Dharma
{
    meta:
        description = "Detecta notas de Dharma/CrySiS"
        author = "securizar-modulo60"
        severity = "critical"

    strings:
        $d1 = "All your files have been encrypted!" ascii
        $d2 = "RETURN FILES.txt" ascii
        $d3 = "FILES ENCRYPTED.txt" ascii
        $d4 = "Info.hta" ascii
        $d5 = "decrypt@" ascii

    condition:
        2 of them
}

rule Ransomware_CryptoAPI_Usage
{
    meta:
        description = "Detecta uso sospechoso de APIs criptograficas en binarios"
        author = "securizar-modulo60"
        severity = "high"

    strings:
        $api1 = "CryptEncrypt" ascii
        $api2 = "CryptGenKey" ascii
        $api3 = "CryptAcquireContext" ascii
        $api4 = "EVP_EncryptInit" ascii
        $api5 = "EVP_EncryptUpdate" ascii
        $api6 = "EVP_EncryptFinal" ascii
        $api7 = "RSA_public_encrypt" ascii
        $api8 = "AES_encrypt" ascii

        $file1 = "FindFirstFile" ascii
        $file2 = "FindNextFile" ascii
        $file3 = "MoveFileEx" ascii
        $file4 = "DeleteFile" ascii

    condition:
        2 of ($api*) and 2 of ($file*)
}

rule Ransomware_Linux_Encryptor
{
    meta:
        description = "Detecta encriptadores de ransomware para Linux"
        author = "securizar-modulo60"
        severity = "critical"

    strings:
        $enc1 = "openssl enc" ascii
        $enc2 = "aes-256-cbc" ascii
        $enc3 = "/dev/urandom" ascii
        $loop1 = "find / -name" ascii
        $loop2 = "find /home" ascii
        $loop3 = "for f in" ascii
        $ext1 = ".encrypted" ascii
        $ext2 = ".locked" ascii
        $ext3 = ".enc" ascii
        $shred = "shred" ascii
        $rm_orig = "rm -f" ascii

    condition:
        (1 of ($enc*)) and (1 of ($loop*)) and (1 of ($ext*)) and (1 of ($shred, $rm_orig))
}

rule Ransomware_Ransom_Communication
{
    meta:
        description = "Detecta comunicacion C2 de ransomware"
        author = "securizar-modulo60"
        severity = "high"

    strings:
        $tor1 = ".onion" ascii
        $tor2 = "torproject.org" ascii
        $key_exch = "-----BEGIN PUBLIC KEY-----" ascii
        $key_rsa = "-----BEGIN RSA PUBLIC KEY-----" ascii
        $curl_post = "curl -X POST" ascii
        $wget_post = "wget --post-data" ascii

    condition:
        (1 of ($tor*) and 1 of ($key_exch, $key_rsa)) or
        (1 of ($curl_post, $wget_post) and 1 of ($key_exch, $key_rsa))
}
EOF
    log_change "Creado" "${YARA_RULES_DIR}/ransomware_indicators.yar"

    # --- Script de escaneo ---
    log_info "Creando /usr/local/bin/escanear-ransomware.sh..."
    cat > /usr/local/bin/escanear-ransomware.sh << 'EOF'
#!/bin/bash
# ============================================================
# escanear-ransomware.sh - Escaneo de indicadores de ransomware
# Modulo 60 - Proteccion Anti-Ransomware
# ============================================================
set -euo pipefail

CONF_DIR="/etc/securizar/ransomware"
EXTENSIONS_DB="${CONF_DIR}/ransomware-extensions.db"
YARA_RULES_DIR="${CONF_DIR}/yara-rules"
LOG="/var/log/securizar/ransomware/scan-results.log"
REPORT_DIR="/var/lib/securizar/ransomware/scan-reports"
ALERT_SCRIPT="/usr/local/bin/alertar-canary-ransomware.sh"

mkdir -p "$(dirname "$LOG")"
mkdir -p "$REPORT_DIR"

SCAN_TARGET="${1:-/home}"
SCAN_MODE="${2:-full}"

TIMESTAMP="$(date '+%Y-%m-%d_%H%M%S')"
REPORT_FILE="${REPORT_DIR}/scan-${TIMESTAMP}.txt"

log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG"
}

total_findings=0
critical_findings=0
high_findings=0

report() {
    echo "$1" | tee -a "$REPORT_FILE"
}

# Funcion para escanear extensiones sospechosas
scan_extensions() {
    local target="$1"
    log_msg "Escaneando extensiones ransomware en: $target"
    report "=== ESCANEO DE EXTENSIONES RANSOMWARE ==="
    report "Objetivo: $target"
    report "Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
    report ""

    if [[ ! -f "$EXTENSIONS_DB" ]]; then
        report "[!] Base de datos de extensiones no encontrada: $EXTENSIONS_DB"
        return
    fi

    local ext_found=0
    while IFS='|' read -r ext family priority; do
        [[ "$ext" =~ ^#.*$ || -z "$ext" ]] && continue

        # Buscar archivos con esta extension
        local found_files
        found_files=$(find "$target" -maxdepth 8 -name "*${ext}" -type f 2>/dev/null | head -50 || true)

        if [[ -n "$found_files" ]]; then
            local count
            count=$(echo "$found_files" | wc -l)
            ((ext_found += count)) || true
            ((total_findings += count)) || true

            case "$priority" in
                1) ((critical_findings += count)) || true ;;
                2) ((high_findings += count)) || true ;;
            esac

            report "[ALERTA P${priority}] Extension ${ext} (${family}): ${count} archivo(s)"
            echo "$found_files" | head -10 | while read -r f; do
                report "  - $f ($(stat -c '%s bytes, %y' "$f" 2>/dev/null || echo 'info no disponible'))"
            done
            if [[ "$count" -gt 10 ]]; then
                report "  ... y $((count - 10)) mas"
            fi
        fi
    done < "$EXTENSIONS_DB"

    report ""
    report "Total archivos con extensiones sospechosas: $ext_found"
    report ""
}

# Funcion para escanear con YARA
scan_yara() {
    local target="$1"

    if ! command -v yara &>/dev/null; then
        report "[!] YARA no instalado - escaneo de reglas omitido"
        return
    fi

    log_msg "Escaneando con reglas YARA en: $target"
    report "=== ESCANEO YARA ==="
    report ""

    local yara_found=0
    for rule_file in "${YARA_RULES_DIR}"/*.yar; do
        [[ ! -f "$rule_file" ]] && continue

        report "Regla: $(basename "$rule_file")"
        local yara_output
        yara_output=$(yara -r -w -f -p 4 "$rule_file" "$target" 2>/dev/null || true)

        if [[ -n "$yara_output" ]]; then
            local match_count
            match_count=$(echo "$yara_output" | wc -l)
            ((yara_found += match_count)) || true
            ((total_findings += match_count)) || true
            ((critical_findings += match_count)) || true

            report "[ALERTA] $match_count coincidencias YARA:"
            echo "$yara_output" | head -20 | while read -r match; do
                report "  $match"
            done
            if [[ "$match_count" -gt 20 ]]; then
                report "  ... y $((match_count - 20)) mas"
            fi
        else
            report "  Sin coincidencias"
        fi
        report ""
    done

    report "Total coincidencias YARA: $yara_found"
    report ""
}

# Funcion para buscar notas de rescate por nombre de archivo
scan_ransom_notes() {
    local target="$1"
    log_msg "Buscando notas de rescate en: $target"
    report "=== BUSQUEDA DE NOTAS DE RESCATE ==="
    report ""

    local note_patterns=(
        "README_DECRYPT*"
        "HOW_TO_DECRYPT*"
        "HOW_TO_RECOVER*"
        "DECRYPT_INSTRUCTION*"
        "RECOVERY_INSTRUCTIONS*"
        "YOUR_FILES_ARE_ENCRYPTED*"
        "!README!*"
        "_readme.txt"
        "RESTORE_FILES*"
        "FILES_ENCRYPTED*"
        "HELP_DECRYPT*"
        "ATTENTION!!!*"
        "DECRYPT_FILES*"
        "Restore-My-Files.txt"
        "@WanaDecryptor@*"
        "HELP_YOUR_FILES*"
        "!HELP!*"
        "#DECRYPT_MY_FILES#*"
        "RANSOM_NOTE*"
        "*-DECRYPT.txt"
        "*-DECRYPT.html"
        "_RECOVERY_+*"
        "RECOVER-FILES-*.html"
        "info.hta"
    )

    local notes_found=0
    for pattern in "${note_patterns[@]}"; do
        local found
        found=$(find "$target" -maxdepth 8 -name "$pattern" -type f 2>/dev/null | head -20 || true)
        if [[ -n "$found" ]]; then
            local count
            count=$(echo "$found" | wc -l)
            ((notes_found += count)) || true
            ((total_findings += count)) || true
            ((critical_findings += count)) || true

            report "[CRITICO] Patron '$pattern': $count archivo(s)"
            echo "$found" | while read -r f; do
                report "  - $f"
                # Mostrar primeras lineas del contenido
                head -3 "$f" 2>/dev/null | while read -r line; do
                    report "    > $line"
                done
            done
        fi
    done

    report ""
    report "Total notas de rescate encontradas: $notes_found"
    report ""
}

# Escaneo de archivos recientemente modificados en masa
scan_recent_mass_changes() {
    local target="$1"
    log_msg "Analizando cambios masivos recientes en: $target"
    report "=== ANALISIS DE CAMBIOS MASIVOS RECIENTES ==="
    report ""

    # Archivos modificados en la ultima hora
    local recent_count
    recent_count=$(find "$target" -maxdepth 6 -type f -mmin -60 2>/dev/null | wc -l || echo "0")
    report "Archivos modificados en la ultima hora: $recent_count"

    if [[ "$recent_count" -gt 500 ]]; then
        report "[ALERTA] Numero inusualmente alto de archivos modificados recientemente"
        ((total_findings++)) || true
        ((high_findings++)) || true

        # Top extensiones de archivos modificados
        report ""
        report "Top extensiones de archivos modificados:"
        find "$target" -maxdepth 6 -type f -mmin -60 2>/dev/null | \
            sed 's/.*\./\./' | sort | uniq -c | sort -rn | head -15 | \
            while read -r count ext; do
                report "  ${count} archivos con extension ${ext}"
            done
    fi

    # Archivos con la misma extension creados en el mismo minuto
    report ""
    report "Patrones sospechosos de creacion simultanea:"
    find "$target" -maxdepth 6 -type f -mmin -60 2>/dev/null | \
        sed 's/.*\./\./' | sort | uniq -c | sort -rn | head -5 | \
        while read -r count ext; do
            if [[ "$count" -gt 50 ]]; then
                report "  [SOSPECHOSO] $count archivos con extension $ext en la ultima hora"
            fi
        done
    report ""
}

# Ejecucion principal
report "============================================================"
report "  INFORME DE ESCANEO ANTI-RANSOMWARE"
report "  Modulo 60 - Proteccion Anti-Ransomware"
report "============================================================"
report "Fecha:    $(date '+%Y-%m-%d %H:%M:%S')"
report "Objetivo: $SCAN_TARGET"
report "Modo:     $SCAN_MODE"
report "Hostname: $(hostname)"
report "============================================================"
report ""

case "$SCAN_MODE" in
    ext|extensions)
        scan_extensions "$SCAN_TARGET"
        ;;
    yara)
        scan_yara "$SCAN_TARGET"
        ;;
    notes)
        scan_ransom_notes "$SCAN_TARGET"
        ;;
    recent)
        scan_recent_mass_changes "$SCAN_TARGET"
        ;;
    full|*)
        scan_extensions "$SCAN_TARGET"
        scan_yara "$SCAN_TARGET"
        scan_ransom_notes "$SCAN_TARGET"
        scan_recent_mass_changes "$SCAN_TARGET"
        ;;
esac

# Resumen
report "============================================================"
report "  RESUMEN DE ESCANEO"
report "============================================================"
report "Total hallazgos:    $total_findings"
report "Criticos:           $critical_findings"
report "Altos:              $high_findings"
report ""

if [[ "$critical_findings" -gt 0 ]]; then
    report "[!!!] SE DETECTARON INDICADORES CRITICOS DE RANSOMWARE"
    report "[!!!] Ejecute respuesta-emergencia-ransomware.sh INMEDIATAMENTE"
    logger -t "securizar-ransomware" -p auth.crit \
        "RANSOMWARE SCAN: $critical_findings hallazgos criticos en $SCAN_TARGET"
    # Trigger alerta
    if [[ -x "$ALERT_SCRIPT" ]]; then
        "$ALERT_SCRIPT" "scan_critical" "$SCAN_TARGET" "scan_$$" &
    fi
elif [[ "$total_findings" -gt 0 ]]; then
    report "[!] Se encontraron indicadores sospechosos - revisar manualmente"
    logger -t "securizar-ransomware" -p auth.warning \
        "RANSOMWARE SCAN: $total_findings hallazgos sospechosos en $SCAN_TARGET"
else
    report "[+] No se detectaron indicadores de ransomware"
fi

report ""
report "Informe completo: $REPORT_FILE"

chmod 600 "$REPORT_FILE"
log_msg "Escaneo completado: $total_findings hallazgos ($critical_findings criticos)"
echo ""
echo "Informe guardado en: $REPORT_FILE"
EOF
    chmod +x /usr/local/bin/escanear-ransomware.sh
    log_change "Creado" "/usr/local/bin/escanear-ransomware.sh"

    # Timer para escaneo diario
    cat > /etc/systemd/system/securizar-ransomware-scan.service << 'EOF'
[Unit]
Description=Securizar Anti-Ransomware Daily Scan
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/escanear-ransomware.sh /home full
ExecStartPost=/usr/local/bin/escanear-ransomware.sh /srv full
StandardOutput=journal
StandardError=journal
SyslogIdentifier=securizar-ransomware-scan
Nice=19
IOSchedulingClass=idle
EOF
    log_change "Creado" "/etc/systemd/system/securizar-ransomware-scan.service"

    cat > /etc/systemd/system/securizar-ransomware-scan.timer << 'EOF'
[Unit]
Description=Escaneo diario anti-ransomware

[Timer]
OnCalendar=*-*-* 03:00:00
RandomizedDelaySec=900
Persistent=true

[Install]
WantedBy=timers.target
EOF
    log_change "Creado" "/etc/systemd/system/securizar-ransomware-scan.timer"

    systemctl daemon-reload 2>/dev/null || true

    if ask "¿Habilitar escaneo diario anti-ransomware?"; then
        systemctl enable securizar-ransomware-scan.timer 2>/dev/null || true
        systemctl start securizar-ransomware-scan.timer 2>/dev/null || true
        log_change "Habilitado" "securizar-ransomware-scan.timer (diario 03:00)"
    else
        log_skip "Escaneo diario anti-ransomware"
    fi

    log_info "Deteccion por extensiones y YARA configurada"
    log_info "  Escanear:  escanear-ransomware.sh /ruta [full|ext|yara|notes|recent]"
    log_info "  Reglas:    ${YARA_RULES_DIR}/"
    log_info "  Extensiones: $EXTENSIONS_DB"
else
    log_skip "Deteccion por extensiones y YARA anti-ransomware"
fi

# ============================================================
# S6: PROTECCION DE SHARES DE RED
# ============================================================
log_section "S6: PROTECCION DE SHARES DE RED"

log_info "Hardening de recursos compartidos de red:"
log_info "  - SMB: firma obligatoria, sin acceso anonimo, veto files"
log_info "  - NFS: nosuid, noexec, root_squash"
log_info "  - Bloqueo de extensiones ransomware en shares"
log_info "  - Restriccion de permisos en exports"
log_info ""

if check_file_exists /usr/local/bin/verificar-shares-ransomware.sh; then
    log_already "Proteccion de shares de red (verificar-shares-ransomware.sh existe)"
elif ask "¿Configurar proteccion de shares de red anti-ransomware?"; then

    # --- Proteccion SMB/Samba ---
    SMB_CONF="/etc/samba/smb.conf"
    if [[ -f "$SMB_CONF" ]]; then
        log_info "Configuracion Samba detectada, aplicando hardening..."
        cp "$SMB_CONF" "${BACKUP_DIR}/smb.conf.bak"
        log_change "Backup" "/etc/samba/smb.conf"

        # Verificar si ya tiene parametros de seguridad
        SAMBA_CHANGES=0

        # Firma de paquetes obligatoria
        if ! grep -q "^[[:space:]]*server signing" "$SMB_CONF" 2>/dev/null; then
            # Agregar al final de la seccion [global]
            sed -i '/^\[global\]/a\\tserver signing = mandatory' "$SMB_CONF" 2>/dev/null || true
            ((SAMBA_CHANGES++)) || true
            log_change "SMB" "server signing = mandatory"
        fi

        if ! grep -q "^[[:space:]]*client signing" "$SMB_CONF" 2>/dev/null; then
            sed -i '/^\[global\]/a\\tclient signing = mandatory' "$SMB_CONF" 2>/dev/null || true
            ((SAMBA_CHANGES++)) || true
            log_change "SMB" "client signing = mandatory"
        fi

        # Deshabilitar acceso anonimo
        if ! grep -q "^[[:space:]]*restrict anonymous" "$SMB_CONF" 2>/dev/null; then
            sed -i '/^\[global\]/a\\trestrict anonymous = 2' "$SMB_CONF" 2>/dev/null || true
            ((SAMBA_CHANGES++)) || true
            log_change "SMB" "restrict anonymous = 2"
        fi

        if ! grep -q "^[[:space:]]*map to guest" "$SMB_CONF" 2>/dev/null; then
            sed -i '/^\[global\]/a\\tmap to guest = never' "$SMB_CONF" 2>/dev/null || true
            ((SAMBA_CHANGES++)) || true
            log_change "SMB" "map to guest = never"
        fi

        # SMB minimo version 2
        if ! grep -q "^[[:space:]]*server min protocol" "$SMB_CONF" 2>/dev/null; then
            sed -i '/^\[global\]/a\\tserver min protocol = SMB2' "$SMB_CONF" 2>/dev/null || true
            ((SAMBA_CHANGES++)) || true
            log_change "SMB" "server min protocol = SMB2"
        fi

        # Veto files: extensiones ransomware
        VETO_PATTERN="/*.encrypted/*.locked/*.crypted/*.crypt/*.WNCRY/*.wncry/*.wcry/"
        VETO_PATTERN+="/*.locky/*.cerber/*.zzzzz/*.micro/*.xxx/*.ttt/*.vvv/"
        VETO_PATTERN+="/*.ecc/*.ezz/*.exx/*.abc/*.aaa/*.xtbl/*.thor/*.odin/"
        VETO_PATTERN+="/*.dharma/*.arrow/*.bip/*.combo/*.gamma/*.STOP/*.djvu/"
        VETO_PATTERN+="/*.lockbit/*.ryk/*.RYK/*.maze/*.CONTI/*.enc/*.lock/"
        VETO_PATTERN+="/README_DECRYPT*/HOW_TO_DECRYPT*/DECRYPT_INSTRUCTION*/"
        VETO_PATTERN+="/RECOVERY_INSTRUCTIONS*/RESTORE_FILES*/"

        if ! grep -q "^[[:space:]]*veto files" "$SMB_CONF" 2>/dev/null; then
            sed -i '/^\[global\]/a\\tveto files = '"$VETO_PATTERN" "$SMB_CONF" 2>/dev/null || true
            ((SAMBA_CHANGES++)) || true
            log_change "SMB" "veto files (extensiones ransomware)"
        fi

        if ! grep -q "^[[:space:]]*delete veto files" "$SMB_CONF" 2>/dev/null; then
            sed -i '/^\[global\]/a\\tdelete veto files = no' "$SMB_CONF" 2>/dev/null || true
            ((SAMBA_CHANGES++)) || true
            log_change "SMB" "delete veto files = no"
        fi

        # Audit logging
        if ! grep -q "^[[:space:]]*vfs objects.*full_audit" "$SMB_CONF" 2>/dev/null; then
            sed -i '/^\[global\]/a\\tvfs objects = full_audit' "$SMB_CONF" 2>/dev/null || true
            sed -i '/vfs objects = full_audit/a\\tfull_audit:prefix = %u|%I|%m|%S' "$SMB_CONF" 2>/dev/null || true
            sed -i '/full_audit:prefix/a\\tfull_audit:success = mkdir rmdir rename unlink write pwrite' "$SMB_CONF" 2>/dev/null || true
            sed -i '/full_audit:success/a\\tfull_audit:failure = none' "$SMB_CONF" 2>/dev/null || true
            sed -i '/full_audit:failure/a\\tfull_audit:facility = local5' "$SMB_CONF" 2>/dev/null || true
            sed -i '/full_audit:facility/a\\tfull_audit:priority = notice' "$SMB_CONF" 2>/dev/null || true
            ((SAMBA_CHANGES++)) || true
            log_change "SMB" "full_audit VFS module habilitado"
        fi

        if [[ "$SAMBA_CHANGES" -gt 0 ]]; then
            # Verificar configuracion
            if command -v testparm &>/dev/null; then
                if testparm -s 2>/dev/null | grep -q "server signing"; then
                    log_info "Configuracion Samba validada correctamente"
                else
                    log_warn "Revise la configuracion de Samba manualmente"
                fi
            fi

            if ask "¿Reiniciar Samba para aplicar cambios?"; then
                systemctl restart smb 2>/dev/null || systemctl restart smbd 2>/dev/null || true
                log_change "Reiniciado" "servicio Samba"
            else
                log_skip "Reinicio de Samba"
            fi
        fi
    else
        log_info "Samba no configurado en este sistema (/etc/samba/smb.conf no existe)"
    fi

    # --- Proteccion NFS ---
    NFS_EXPORTS="/etc/exports"
    if [[ -f "$NFS_EXPORTS" ]]; then
        log_info "Exports NFS detectados, aplicando hardening..."
        cp "$NFS_EXPORTS" "${BACKUP_DIR}/exports.bak"
        log_change "Backup" "/etc/exports"

        # Verificar cada export
        NFS_HARDENED=0
        while IFS= read -r line; do
            [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue

            local_path=$(echo "$line" | awk '{print $1}')

            # Verificar opciones de seguridad
            if ! echo "$line" | grep -q "root_squash"; then
                log_warn "NFS export $local_path sin root_squash"
            fi
            if ! echo "$line" | grep -q "nosuid"; then
                log_warn "NFS export $local_path sin nosuid"
            fi
        done < "$NFS_EXPORTS"

        # Crear archivo de exports hardened como referencia
        NFS_HARDENED_CONF="${RANSOMWARE_CONF_DIR}/nfs-hardened-example.conf"
        cat > "$NFS_HARDENED_CONF" << 'EOF'
# ============================================================
# nfs-hardened-example.conf - Ejemplo de exports NFS seguro
# ============================================================
# Modulo 60 - Proteccion Anti-Ransomware
# ============================================================
# Opciones de seguridad recomendadas:
#   root_squash  - Mapear root remoto a nobody
#   nosuid       - No respetar bits SUID
#   noexec       - No permitir ejecucion
#   secure       - Solo puertos privilegiados (<1024)
#   sync         - Escritura sincrona
#   no_subtree_check - Mejor rendimiento y seguridad
#
# Ejemplo:
# /srv/datos  192.168.1.0/24(rw,sync,root_squash,nosuid,noexec,secure,no_subtree_check)
# /srv/backup 192.168.1.10(rw,sync,root_squash,nosuid,secure,no_subtree_check)
EOF
        chmod 644 "$NFS_HARDENED_CONF"
        log_change "Creado" "$NFS_HARDENED_CONF (referencia NFS hardened)"
    else
        log_info "NFS exports no configurados en este sistema"
    fi

    # --- Script de verificacion de shares ---
    cat > /usr/local/bin/verificar-shares-ransomware.sh << 'EOF'
#!/bin/bash
# ============================================================
# verificar-shares-ransomware.sh - Verificar seguridad de shares
# Modulo 60 - Proteccion Anti-Ransomware
# ============================================================
set -euo pipefail

echo ""
echo "VERIFICACION DE SEGURIDAD DE SHARES"
echo "====================================="
echo ""

# SMB/Samba
echo "=== SAMBA/SMB ==="
SMB_CONF="/etc/samba/smb.conf"
if [[ -f "$SMB_CONF" ]]; then
    echo "  Configuracion: $SMB_CONF"

    check_smb_param() {
        local param="$1" expected="$2"
        if grep -qi "^[[:space:]]*${param}" "$SMB_CONF" 2>/dev/null; then
            local val
            val=$(grep -i "^[[:space:]]*${param}" "$SMB_CONF" | tail -1 | cut -d= -f2 | tr -d ' ')
            if echo "$val" | grep -qi "$expected"; then
                echo "  [OK]   $param = $val"
            else
                echo "  [WARN] $param = $val (recomendado: $expected)"
            fi
        else
            echo "  [FAIL] $param no configurado (recomendado: $expected)"
        fi
    }

    check_smb_param "server signing" "mandatory"
    check_smb_param "client signing" "mandatory"
    check_smb_param "restrict anonymous" "2"
    check_smb_param "map to guest" "never"
    check_smb_param "server min protocol" "SMB2"

    if grep -q "veto files" "$SMB_CONF" 2>/dev/null; then
        echo "  [OK]   veto files configurado"
    else
        echo "  [WARN] veto files no configurado"
    fi

    if grep -q "full_audit" "$SMB_CONF" 2>/dev/null; then
        echo "  [OK]   full_audit habilitado"
    else
        echo "  [WARN] full_audit no habilitado"
    fi
else
    echo "  Samba no instalado"
fi
echo ""

# NFS
echo "=== NFS ==="
NFS_EXPORTS="/etc/exports"
if [[ -f "$NFS_EXPORTS" ]]; then
    echo "  Exports: $NFS_EXPORTS"
    local_exports=0
    while IFS= read -r line; do
        [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
        ((local_exports++)) || true
        local export_path
        export_path=$(echo "$line" | awk '{print $1}')

        local issues=""
        echo "$line" | grep -q "root_squash" || issues="${issues}no-root_squash "
        echo "$line" | grep -q "nosuid" || issues="${issues}no-nosuid "
        echo "$line" | grep -q "secure" || issues="${issues}no-secure "

        if [[ -n "$issues" ]]; then
            echo "  [WARN] $export_path: $issues"
        else
            echo "  [OK]   $export_path: bien configurado"
        fi
    done < "$NFS_EXPORTS"
    [[ "$local_exports" -eq 0 ]] && echo "  Sin exports activos"
else
    echo "  NFS no configurado"
fi
echo ""

# Montajes actuales
echo "=== MONTAJES DE RED ACTUALES ==="
mount | grep -E "cifs|nfs|smb" | while read -r line; do
    local mp
    mp=$(echo "$line" | awk '{print $3}')
    local opts
    opts=$(echo "$line" | grep -oP '\(.*\)')
    local issues=""
    echo "$opts" | grep -q "nosuid" || issues="${issues}no-nosuid "
    echo "$opts" | grep -q "noexec" || issues="${issues}no-noexec "

    if [[ -n "$issues" ]]; then
        echo "  [WARN] $mp: $issues"
    else
        echo "  [OK]   $mp"
    fi
done || echo "  Sin montajes de red"
echo ""
EOF
    chmod +x /usr/local/bin/verificar-shares-ransomware.sh
    log_change "Creado" "/usr/local/bin/verificar-shares-ransomware.sh"

    log_info "Proteccion de shares de red configurada"
    log_info "  Verificar: verificar-shares-ransomware.sh"
else
    log_skip "Proteccion de shares de red anti-ransomware"
fi

# ============================================================
# S7: INMUTABILIDAD DE BACKUPS
# ============================================================
log_section "S7: INMUTABILIDAD DE BACKUPS"

log_info "Proteccion de la integridad de backups:"
log_info "  - Atributo append-only (chattr +a) en directorios de backup"
log_info "  - Snapshots btrfs readonly (si aplica)"
log_info "  - Script de verificacion de integridad de backups"
log_info "  - Proteccion contra eliminacion accidental o maliciosa"
log_info ""

if check_file_exists /usr/local/bin/gestionar-inmutabilidad-backup.sh; then
    log_already "Inmutabilidad de backups (gestionar-inmutabilidad-backup.sh existe)"
elif ask "¿Configurar inmutabilidad de backups anti-ransomware?"; then

    # --- Configuracion de inmutabilidad ---
    IMMUTABLE_CONF="${RANSOMWARE_CONF_DIR}/backup-immutability.conf"
    cat > "$IMMUTABLE_CONF" << 'EOF'
# ============================================================
# backup-immutability.conf - Configuracion de inmutabilidad
# ============================================================
# Modulo 60 - Proteccion Anti-Ransomware
# ============================================================

# Directorios de backup a proteger con append-only
IMMUTABLE_DIRS="/var/backups /var/backups/securizar"

# Habilitar chattr +a (append-only) en directorios de backup
ENABLE_APPEND_ONLY="true"

# Habilitar chattr +i (immutable) en backups completados
ENABLE_IMMUTABLE_COMPLETED="true"

# Habilitar snapshots btrfs readonly (si filesystem es btrfs)
ENABLE_BTRFS_READONLY="true"

# Directorio para snapshots btrfs readonly
BTRFS_SNAP_DIR="/var/backups/.snapshots"

# Retencion de snapshots btrfs (dias)
BTRFS_SNAP_RETENTION=30

# Verificar integridad de backups existentes
VERIFY_CHECKSUMS="true"

# Archivo de checksums
CHECKSUM_FILE="/var/lib/securizar/ransomware/backup-checksums.db"

# Log
IMMUTABLE_LOG="/var/log/securizar/ransomware/backup-immutability.log"
EOF
    chmod 600 "$IMMUTABLE_CONF"
    log_change "Creado" "$IMMUTABLE_CONF"

    # Aplicar append-only a directorios de backup existentes
    for backup_dir in /var/backups /var/backups/securizar; do
        if [[ -d "$backup_dir" ]]; then
            # Verificar si el filesystem soporta chattr
            if chattr +a "$backup_dir" 2>/dev/null; then
                log_change "Protegido" "$backup_dir (append-only)"
            else
                log_warn "No se pudo aplicar append-only a $backup_dir (filesystem no soporta)"
            fi
        fi
    done

    # --- Deteccion y configuracion btrfs ---
    BTRFS_AVAILABLE=false
    if command -v btrfs &>/dev/null; then
        # Buscar montajes btrfs
        BTRFS_MOUNTS=$(mount | grep "type btrfs" | awk '{print $3}' || true)
        if [[ -n "$BTRFS_MOUNTS" ]]; then
            BTRFS_AVAILABLE=true
            log_info "Filesystems btrfs detectados:"
            echo "$BTRFS_MOUNTS" | while read -r mp; do
                log_info "  - $mp"
            done
        fi
    fi

    # --- Script de gestion de inmutabilidad ---
    log_info "Creando /usr/local/bin/gestionar-inmutabilidad-backup.sh..."
    cat > /usr/local/bin/gestionar-inmutabilidad-backup.sh << 'EOF'
#!/bin/bash
# ============================================================
# gestionar-inmutabilidad-backup.sh - Inmutabilidad de backups
# Modulo 60 - Proteccion Anti-Ransomware
# ============================================================
set -euo pipefail

CONF="/etc/securizar/ransomware/backup-immutability.conf"
[[ -f "$CONF" ]] && source "$CONF"

LOG="${IMMUTABLE_LOG:-/var/log/securizar/ransomware/backup-immutability.log}"
CHECKSUM_DB="${CHECKSUM_FILE:-/var/lib/securizar/ransomware/backup-checksums.db}"

mkdir -p "$(dirname "$LOG")"
mkdir -p "$(dirname "$CHECKSUM_DB")"

log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG"
}

# Proteger directorio con append-only
protect_append_only() {
    local dir="$1"
    if [[ ! -d "$dir" ]]; then
        log_msg "WARN: Directorio no existe: $dir"
        return 1
    fi

    # Aplicar append-only al directorio
    if chattr +a "$dir" 2>/dev/null; then
        log_msg "OK: append-only aplicado a $dir"
        echo "  [OK] $dir -> append-only"
    else
        log_msg "WARN: No se pudo aplicar append-only a $dir"
        echo "  [WARN] $dir -> append-only no soportado"
    fi

    # Aplicar immutable a archivos completados dentro del directorio
    if [[ "${ENABLE_IMMUTABLE_COMPLETED:-true}" == "true" ]]; then
        find "$dir" -maxdepth 2 -type f -name "*.tar*" -o -name "*.gz" -o -name "*.bz2" -o -name "*.xz" -o -name "*.zst" 2>/dev/null | while read -r file; do
            # Solo proteger archivos mayores a 1KB y mas viejos que 1 hora
            local file_age
            file_age=$(( $(date +%s) - $(stat -c %Y "$file" 2>/dev/null || echo "0") ))
            if [[ "$file_age" -gt 3600 ]]; then
                chattr +i "$file" 2>/dev/null && log_msg "Immutable: $file" || true
            fi
        done
    fi
}

# Crear snapshot btrfs readonly
create_btrfs_snapshot() {
    local source="$1"
    local snap_dir="${BTRFS_SNAP_DIR:-/var/backups/.snapshots}"
    mkdir -p "$snap_dir"

    if ! command -v btrfs &>/dev/null; then
        log_msg "WARN: btrfs-progs no instalado"
        return 1
    fi

    # Verificar que el source es un subvolumen btrfs
    if ! btrfs subvolume show "$source" &>/dev/null; then
        log_msg "WARN: $source no es un subvolumen btrfs"
        return 1
    fi

    local snap_name="backup-readonly-$(date +%Y%m%d-%H%M%S)"
    local snap_path="${snap_dir}/${snap_name}"

    if btrfs subvolume snapshot -r "$source" "$snap_path" 2>>"$LOG"; then
        log_msg "OK: Snapshot readonly creado: $snap_path"
        echo "  [OK] Snapshot readonly: $snap_path"
    else
        log_msg "ERROR: Fallo al crear snapshot: $snap_path"
        echo "  [FAIL] Error creando snapshot"
        return 1
    fi
}

# Limpiar snapshots btrfs antiguos
cleanup_btrfs_snapshots() {
    local snap_dir="${BTRFS_SNAP_DIR:-/var/backups/.snapshots}"
    local retention="${BTRFS_SNAP_RETENTION:-30}"

    [[ ! -d "$snap_dir" ]] && return 0

    if ! command -v btrfs &>/dev/null; then
        return 1
    fi

    log_msg "Limpiando snapshots btrfs antiguos (retencion: ${retention} dias)"
    find "$snap_dir" -maxdepth 1 -type d -name "backup-readonly-*" -mtime "+${retention}" 2>/dev/null | while read -r old_snap; do
        log_msg "Eliminando snapshot antiguo: $old_snap"
        btrfs subvolume delete "$old_snap" 2>>"$LOG" || true
    done
}

# Generar checksums de backups
generate_checksums() {
    log_msg "Generando checksums de backups..."
    local tmp_db
    tmp_db=$(mktemp)

    for dir in ${IMMUTABLE_DIRS:-/var/backups}; do
        [[ ! -d "$dir" ]] && continue
        find "$dir" -maxdepth 3 -type f \( -name "*.tar*" -o -name "*.gz" -o -name "*.bz2" -o -name "*.xz" -o -name "*.zst" -o -name "*.borg" -o -name "*.restic" \) 2>/dev/null | while read -r file; do
            local hash
            hash=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
            local size
            size=$(stat -c '%s' "$file" 2>/dev/null || echo "0")
            echo "${file}|${hash}|${size}|$(date -Iseconds)" >> "$tmp_db"
        done
    done

    mv "$tmp_db" "$CHECKSUM_DB"
    chmod 600 "$CHECKSUM_DB"
    local count
    count=$(wc -l < "$CHECKSUM_DB" 2>/dev/null || echo "0")
    log_msg "Checksums generados: $count archivos"
    echo "[+] $count checksums generados en $CHECKSUM_DB"
}

# Verificar integridad de backups
verify_checksums() {
    if [[ ! -f "$CHECKSUM_DB" ]]; then
        echo "[!] No hay checksums registrados. Ejecute: $0 checksums"
        return 1
    fi

    log_msg "Verificando integridad de backups..."
    local total=0 ok=0 modified=0 missing=0

    while IFS='|' read -r filepath orig_hash orig_size timestamp; do
        ((total++)) || true

        if [[ ! -f "$filepath" ]]; then
            log_msg "ALERTA: Backup ELIMINADO: $filepath"
            ((missing++)) || true
            echo "  [MISSING] $filepath"
            continue
        fi

        local current_hash
        current_hash=$(sha256sum "$filepath" 2>/dev/null | awk '{print $1}')
        if [[ "$current_hash" != "$orig_hash" ]]; then
            log_msg "ALERTA: Backup MODIFICADO: $filepath"
            ((modified++)) || true
            echo "  [MODIFIED] $filepath"
        else
            ((ok++)) || true
        fi
    done < "$CHECKSUM_DB"

    echo ""
    echo "RESULTADO DE VERIFICACION DE BACKUPS"
    echo "  Total:       $total"
    echo "  Intactos:    $ok"
    echo "  Modificados: $modified"
    echo "  Eliminados:  $missing"

    if [[ $modified -gt 0 || $missing -gt 0 ]]; then
        logger -t "securizar-ransomware" -p auth.crit \
            "BACKUP INTEGRITY ALERT: $modified modified, $missing missing out of $total"
        return 1
    fi
    return 0
}

# Mostrar estado
show_status() {
    echo ""
    echo "ESTADO DE INMUTABILIDAD DE BACKUPS"
    echo "==================================="
    echo ""

    echo "=== ATRIBUTOS DE DIRECTORIOS ==="
    for dir in ${IMMUTABLE_DIRS:-/var/backups}; do
        if [[ -d "$dir" ]]; then
            local attrs
            attrs=$(lsattr -d "$dir" 2>/dev/null | awk '{print $1}')
            if echo "$attrs" | grep -q "a"; then
                echo "  [OK]   $dir: append-only activo ($attrs)"
            elif echo "$attrs" | grep -q "i"; then
                echo "  [OK]   $dir: immutable activo ($attrs)"
            else
                echo "  [WARN] $dir: sin proteccion ($attrs)"
            fi
        else
            echo "  [MISS] $dir: no existe"
        fi
    done
    echo ""

    echo "=== SNAPSHOTS BTRFS ==="
    local snap_dir="${BTRFS_SNAP_DIR:-/var/backups/.snapshots}"
    if [[ -d "$snap_dir" ]]; then
        local snap_count
        snap_count=$(find "$snap_dir" -maxdepth 1 -type d -name "backup-readonly-*" 2>/dev/null | wc -l || echo "0")
        echo "  Snapshots readonly: $snap_count (en $snap_dir)"
    else
        echo "  Sin snapshots btrfs configurados"
    fi
    echo ""

    echo "=== CHECKSUMS ==="
    if [[ -f "$CHECKSUM_DB" ]]; then
        local cksum_count
        cksum_count=$(wc -l < "$CHECKSUM_DB" 2>/dev/null || echo "0")
        echo "  Archivos registrados: $cksum_count"
        echo "  Base de datos: $CHECKSUM_DB"
    else
        echo "  Sin checksums registrados"
    fi
    echo ""
}

protect_all() {
    echo "Protegiendo directorios de backup..."
    for dir in ${IMMUTABLE_DIRS:-/var/backups}; do
        protect_append_only "$dir"
    done
    echo ""

    if command -v btrfs &>/dev/null && [[ "${ENABLE_BTRFS_READONLY:-true}" == "true" ]]; then
        echo "Creando snapshots btrfs readonly..."
        for dir in ${IMMUTABLE_DIRS:-/var/backups}; do
            create_btrfs_snapshot "$dir" 2>/dev/null || true
        done
    fi

    echo ""
    generate_checksums
}

usage() {
    echo "Uso: $0 {protect|verify|checksums|btrfs-snap|btrfs-cleanup|status|unlock DIR}"
    echo ""
    echo "  protect       - Aplicar proteccion a todos los directorios"
    echo "  verify        - Verificar integridad de backups"
    echo "  checksums     - Generar/actualizar checksums"
    echo "  btrfs-snap    - Crear snapshot btrfs readonly"
    echo "  btrfs-cleanup - Limpiar snapshots btrfs antiguos"
    echo "  status        - Mostrar estado de proteccion"
    echo "  unlock DIR    - Desbloquear directorio (quitar append-only/immutable)"
    exit 1
}

case "${1:-}" in
    protect)       protect_all ;;
    verify)        verify_checksums ;;
    checksums)     generate_checksums ;;
    btrfs-snap)    create_btrfs_snapshot "${2:-/var/backups}" ;;
    btrfs-cleanup) cleanup_btrfs_snapshots ;;
    status)        show_status ;;
    unlock)
        if [[ -n "${2:-}" && -d "${2}" ]]; then
            chattr -a -i "${2}" 2>/dev/null || true
            log_msg "Desbloqueado: ${2}"
            echo "[+] Desbloqueado: ${2}"
        else
            echo "[X] Especifique un directorio valido"
        fi
        ;;
    *)  usage ;;
esac
EOF
    chmod +x /usr/local/bin/gestionar-inmutabilidad-backup.sh
    log_change "Creado" "/usr/local/bin/gestionar-inmutabilidad-backup.sh"

    # Timer para verificacion periodica
    cat > /etc/systemd/system/securizar-backup-verify.service << 'EOF'
[Unit]
Description=Securizar Backup Integrity Verification
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/gestionar-inmutabilidad-backup.sh verify
StandardOutput=journal
StandardError=journal
SyslogIdentifier=securizar-backup-verify
EOF
    log_change "Creado" "/etc/systemd/system/securizar-backup-verify.service"

    cat > /etc/systemd/system/securizar-backup-verify.timer << 'EOF'
[Unit]
Description=Verificacion diaria de integridad de backups

[Timer]
OnCalendar=*-*-* 04:00:00
RandomizedDelaySec=600
Persistent=true

[Install]
WantedBy=timers.target
EOF
    log_change "Creado" "/etc/systemd/system/securizar-backup-verify.timer"

    systemctl daemon-reload 2>/dev/null || true

    if ask "¿Habilitar verificacion diaria de integridad de backups?"; then
        systemctl enable securizar-backup-verify.timer 2>/dev/null || true
        systemctl start securizar-backup-verify.timer 2>/dev/null || true
        log_change "Habilitado" "securizar-backup-verify.timer (diario 04:00)"
    else
        log_skip "Verificacion diaria de integridad de backups"
    fi

    # Generar checksums iniciales
    if ask "¿Generar checksums iniciales de backups existentes?"; then
        /usr/local/bin/gestionar-inmutabilidad-backup.sh checksums 2>/dev/null || true
        log_change "Generados" "checksums iniciales de backups"
    else
        log_skip "Generacion de checksums iniciales"
    fi

    log_info "Inmutabilidad de backups configurada"
    log_info "  Gestion: gestionar-inmutabilidad-backup.sh {protect|verify|status|unlock}"
else
    log_skip "Inmutabilidad de backups anti-ransomware"
fi

# ============================================================
# S8: ANALISIS DE COMPORTAMIENTO DE PROCESOS
# ============================================================
log_section "S8: ANALISIS DE COMPORTAMIENTO DE PROCESOS"

log_info "Monitoreo de comportamiento sospechoso de procesos:"
log_info "  - Deteccion de operaciones criptograficas masivas"
log_info "  - Reglas auditd para syscalls crypto (mmap, mprotect)"
log_info "  - Deteccion de enumeracion rapida de archivos"
log_info "  - Analisis de patrones de I/O de disco"
log_info "  - Perfilado de comportamiento normal vs anomalo"
log_info ""

if check_file_exists /usr/local/bin/analizar-comportamiento-procesos.sh; then
    log_already "Analisis de comportamiento de procesos (analizar-comportamiento-procesos.sh existe)"
elif ask "¿Configurar analisis de comportamiento de procesos anti-ransomware?"; then

    # --- Configuracion de analisis de comportamiento ---
    BEHAVIOR_CONF="${RANSOMWARE_CONF_DIR}/process-behavior.conf"
    cat > "$BEHAVIOR_CONF" << 'EOF'
# ============================================================
# process-behavior.conf - Analisis de comportamiento
# ============================================================
# Modulo 60 - Proteccion Anti-Ransomware
# ============================================================

# Umbral de operaciones de lectura/escritura por segundo por proceso
IO_OPS_THRESHOLD=500

# Umbral de archivos abiertos por un solo proceso
OPEN_FILES_THRESHOLD=200

# Umbral de archivos enumerados (getdents) por segundo
ENUM_THRESHOLD=1000

# Procesos excluidos del monitoreo (separados por |)
EXCLUDED_PROCS="rsync|borg|restic|apt|dpkg|zypper|dnf|pacman|rpm|find|locate|updatedb|tar|gzip|bzip2|xz|zstd"

# Habilitar monitoreo de /proc/[pid]/io
MONITOR_PROC_IO="true"

# Intervalo de muestreo (segundos)
SAMPLE_INTERVAL=10

# Accion ante deteccion: log | alert | kill | isolate
BEHAVIOR_ACTION="alert"

# Log
BEHAVIOR_LOG="/var/log/securizar/ransomware/process-behavior.log"

# Directorio de perfiles de comportamiento
BEHAVIOR_PROFILES="/var/lib/securizar/ransomware/behavior-profiles"

# Habilitar aprendizaje de baseline
ENABLE_BASELINE_LEARNING="true"
BASELINE_LEARNING_HOURS=24
EOF
    chmod 600 "$BEHAVIOR_CONF"
    log_change "Creado" "$BEHAVIOR_CONF"

    # --- Reglas auditd adicionales para comportamiento ---
    if command -v auditctl &>/dev/null; then
        AUDIT_BEHAVIOR_RULES=""
        if [[ -d /etc/audit/rules.d ]]; then
            AUDIT_BEHAVIOR_RULES="/etc/audit/rules.d/61-ransomware-behavior.rules"
        elif [[ -d /etc/audit ]]; then
            AUDIT_BEHAVIOR_RULES="/etc/audit/61-ransomware-behavior.rules"
        fi

        if [[ -n "$AUDIT_BEHAVIOR_RULES" ]]; then
            if [[ -f "$AUDIT_BEHAVIOR_RULES" ]]; then
                cp "$AUDIT_BEHAVIOR_RULES" "${BACKUP_DIR}/61-ransomware-behavior.rules.bak"
            fi

            cat > "$AUDIT_BEHAVIOR_RULES" << 'EOF'
## ============================================================
## 61-ransomware-behavior.rules - Comportamiento sospechoso
## Modulo 60 - Proteccion Anti-Ransomware
## ============================================================

## Monitorear uso de APIs criptograficas via syscalls
## mmap con PROT_EXEC (carga de codigo)
-a always,exit -F arch=b64 -S mmap -F a2&0x4 -F key=ransomware_mmap_exec
-a always,exit -F arch=b32 -S mmap2 -F a2&0x4 -F key=ransomware_mmap_exec

## Monitorear mprotect (cambio de permisos de memoria)
-a always,exit -F arch=b64 -S mprotect -F a2&0x4 -F key=ransomware_mprotect_exec

## Monitorear enumeracion masiva de directorios (getdents)
-a always,exit -F arch=b64 -S getdents -S getdents64 -F dir=/home -F key=ransomware_enum_home
-a always,exit -F arch=b64 -S getdents -S getdents64 -F dir=/srv -F key=ransomware_enum_srv

## Monitorear apertura masiva de archivos
-a always,exit -F arch=b64 -S open -S openat -F dir=/home -F a1&0x241 -F key=ransomware_mass_open
-a always,exit -F arch=b64 -S open -S openat -F dir=/srv -F a1&0x241 -F key=ransomware_mass_open

## Monitorear lectura de /dev/urandom (generacion de claves)
-a always,exit -F arch=b64 -S open -S openat -F path=/dev/urandom -F key=ransomware_entropy
-a always,exit -F arch=b64 -S open -S openat -F path=/dev/random -F key=ransomware_entropy

## Monitorear fork/clone masivo (propagacion)
-a always,exit -F arch=b64 -S clone -S fork -S vfork -F key=ransomware_process_creation

## Monitorear setxattr (cambio de atributos extendidos)
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -F key=ransomware_xattr_change

## Monitorear eliminacion de snapshots de volumen
-a always,exit -F path=/usr/sbin/lvremove -F perm=x -F key=ransomware_snapshot_delete
-a always,exit -F path=/usr/sbin/vgremove -F perm=x -F key=ransomware_snapshot_delete
-a always,exit -F path=/usr/sbin/btrfs -F perm=x -F key=ransomware_snapshot_delete
EOF
            log_change "Creado" "$AUDIT_BEHAVIOR_RULES"

            # Cargar reglas
            augenrules --load 2>/dev/null || auditctl -R "$AUDIT_BEHAVIOR_RULES" 2>/dev/null || true
            log_change "Cargadas" "reglas auditd de comportamiento"
        fi
    fi

    # --- Script de analisis de comportamiento de procesos ---
    log_info "Creando /usr/local/bin/analizar-comportamiento-procesos.sh..."
    cat > /usr/local/bin/analizar-comportamiento-procesos.sh << 'EOF'
#!/bin/bash
# ============================================================
# analizar-comportamiento-procesos.sh - Analisis de comportamiento
# Modulo 60 - Proteccion Anti-Ransomware
# ============================================================
set -euo pipefail

CONF="/etc/securizar/ransomware/process-behavior.conf"
[[ -f "$CONF" ]] && source "$CONF"

LOG="${BEHAVIOR_LOG:-/var/log/securizar/ransomware/process-behavior.log}"
PROFILES_DIR="${BEHAVIOR_PROFILES:-/var/lib/securizar/ransomware/behavior-profiles}"
ALERT_SCRIPT="/usr/local/bin/alertar-canary-ransomware.sh"
IO_THRESHOLD="${IO_OPS_THRESHOLD:-500}"
FILES_THRESHOLD="${OPEN_FILES_THRESHOLD:-200}"
EXCLUDED="${EXCLUDED_PROCS:-rsync|borg|restic|apt|dpkg}"
SAMPLE_INT="${SAMPLE_INTERVAL:-10}"
ACTION="${BEHAVIOR_ACTION:-alert}"

mkdir -p "$(dirname "$LOG")"
mkdir -p "$PROFILES_DIR"

log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG"
}

# Analizar I/O de un proceso
analyze_process_io() {
    local pid="$1"
    local comm
    comm=$(cat /proc/"$pid"/comm 2>/dev/null || echo "unknown")

    # Excluir procesos conocidos
    if echo "$comm" | grep -qE "$EXCLUDED" 2>/dev/null; then
        return 0
    fi

    # Leer estadisticas de I/O
    local io_file="/proc/$pid/io"
    [[ ! -f "$io_file" ]] && return 0

    local read_bytes write_bytes syscr syscw
    read_bytes=$(grep "read_bytes:" "$io_file" 2>/dev/null | awk '{print $2}' || echo "0")
    write_bytes=$(grep "write_bytes:" "$io_file" 2>/dev/null | awk '{print $2}' || echo "0")
    syscr=$(grep "syscr:" "$io_file" 2>/dev/null | awk '{print $2}' || echo "0")
    syscw=$(grep "syscw:" "$io_file" 2>/dev/null | awk '{print $2}' || echo "0")

    # Guardar muestra actual
    local sample_file="${PROFILES_DIR}/${pid}-${comm}.sample"
    echo "${syscr}|${syscw}|${read_bytes}|${write_bytes}|$(date +%s)" >> "$sample_file" 2>/dev/null || true

    # Comparar con muestra anterior
    local prev_line
    prev_line=$(tail -2 "$sample_file" 2>/dev/null | head -1)
    if [[ -n "$prev_line" ]]; then
        local prev_syscr prev_syscw prev_rb prev_wb prev_ts
        IFS='|' read -r prev_syscr prev_syscw prev_rb prev_wb prev_ts <<< "$prev_line"

        local dt=$(($(date +%s) - prev_ts))
        [[ "$dt" -eq 0 ]] && dt=1

        local read_rate=$(( (syscr - prev_syscr) / dt ))
        local write_rate=$(( (syscw - prev_syscw) / dt ))
        local io_rate=$((read_rate + write_rate))

        # Verificar umbrales
        if [[ "$io_rate" -gt "$IO_THRESHOLD" ]]; then
            local cmdline
            cmdline=$(tr '\0' ' ' < /proc/"$pid"/cmdline 2>/dev/null || echo "unknown")
            log_msg "ALERTA IO: PID=$pid CMD=$comm IO_RATE=${io_rate}/s (umbral: $IO_THRESHOLD) CMDLINE=$cmdline"
            logger -t "securizar-ransomware" -p auth.warning \
                "PROCESS BEHAVIOR ALERT: pid=$pid comm=$comm io_rate=${io_rate}/s"

            # Accion
            handle_alert "$pid" "$comm" "high_io" "$io_rate"
        fi
    fi

    # Verificar numero de archivos abiertos
    local fd_count
    fd_count=$(ls /proc/"$pid"/fd/ 2>/dev/null | wc -l || echo "0")
    if [[ "$fd_count" -gt "$FILES_THRESHOLD" ]]; then
        log_msg "ALERTA FD: PID=$pid CMD=$comm FDs=$fd_count (umbral: $FILES_THRESHOLD)"
        handle_alert "$pid" "$comm" "high_fd" "$fd_count"
    fi

    return 0
}

# Manejar alerta
handle_alert() {
    local pid="$1" comm="$2" reason="$3" value="$4"

    case "$ACTION" in
        log)
            # Solo registrar
            ;;
        alert)
            if [[ -x "$ALERT_SCRIPT" ]]; then
                "$ALERT_SCRIPT" "behavior_${reason}" "pid=$pid" "$comm" &
            fi
            ;;
        kill)
            log_msg "AUTO_KILL: Deteniendo PID=$pid CMD=$comm (razon: $reason=$value)"
            kill -STOP "$pid" 2>/dev/null || true
            # Capturar info
            local evidence_dir="/var/lib/securizar/ransomware/evidence-behavior-$(date +%Y%m%d-%H%M%S)"
            mkdir -p "$evidence_dir"
            cp /proc/"$pid"/cmdline "$evidence_dir/cmdline" 2>/dev/null || true
            cp /proc/"$pid"/maps "$evidence_dir/maps" 2>/dev/null || true
            cp /proc/"$pid"/environ "$evidence_dir/environ" 2>/dev/null || true
            ls -la /proc/"$pid"/fd/ > "$evidence_dir/fd-list.txt" 2>/dev/null || true
            kill -9 "$pid" 2>/dev/null || true
            log_msg "Proceso eliminado. Evidencia en: $evidence_dir"
            ;;
        isolate)
            if [[ -x "/usr/local/bin/respuesta-emergencia-ransomware.sh" ]]; then
                /usr/local/bin/respuesta-emergencia-ransomware.sh isolate-network 2>/dev/null &
            fi
            ;;
    esac
}

# Detectar enumeracion rapida de directorios
detect_enumeration() {
    if ! command -v ausearch &>/dev/null; then
        return 0
    fi

    local enum_events
    enum_events=$(ausearch -k ransomware_enum_home -ts recent 2>/dev/null | grep -c "^type=SYSCALL" || echo "0")

    if [[ "$enum_events" -gt "${ENUM_THRESHOLD:-1000}" ]]; then
        log_msg "ALERTA ENUM: $enum_events eventos de enumeracion en el periodo reciente"

        # Identificar proceso con mas enumeraciones
        local top_enum_pid
        top_enum_pid=$(ausearch -k ransomware_enum_home -ts recent 2>/dev/null | \
            grep "^type=SYSCALL" | grep -oP 'pid=\K[0-9]+' | \
            sort | uniq -c | sort -rn | head -1 | awk '{print $2}' || echo "")

        if [[ -n "$top_enum_pid" ]]; then
            local top_comm
            top_comm=$(cat /proc/"$top_enum_pid"/comm 2>/dev/null || echo "unknown")
            if ! echo "$top_comm" | grep -qE "$EXCLUDED" 2>/dev/null; then
                log_msg "Proceso con mayor enumeracion: PID=$top_enum_pid CMD=$top_comm"
                handle_alert "$top_enum_pid" "$top_comm" "enumeration" "$enum_events"
            fi
        fi
    fi
}

# Detectar uso sospechoso de entropia
detect_entropy_usage() {
    if ! command -v ausearch &>/dev/null; then
        return 0
    fi

    local entropy_events
    entropy_events=$(ausearch -k ransomware_entropy -ts recent 2>/dev/null | grep -c "^type=SYSCALL" || echo "0")

    if [[ "$entropy_events" -gt 50 ]]; then
        log_msg "ALERTA ENTROPY: $entropy_events accesos a /dev/urandom en periodo reciente"

        local top_pid
        top_pid=$(ausearch -k ransomware_entropy -ts recent 2>/dev/null | \
            grep "^type=SYSCALL" | grep -oP 'pid=\K[0-9]+' | \
            sort | uniq -c | sort -rn | head -1 | awk '{print $2}' || echo "")

        if [[ -n "$top_pid" ]]; then
            local top_comm
            top_comm=$(cat /proc/"$top_pid"/comm 2>/dev/null || echo "unknown")
            if ! echo "$top_comm" | grep -qE "$EXCLUDED" 2>/dev/null; then
                log_msg "Proceso con mayor uso de entropia: PID=$top_pid CMD=$top_comm"
                handle_alert "$top_pid" "$top_comm" "entropy" "$entropy_events"
            fi
        fi
    fi
}

# Monitoreo continuo
monitor_continuous() {
    log_msg "Monitor de comportamiento iniciado (PID: $$, intervalo: ${SAMPLE_INT}s)"

    while true; do
        # Analizar todos los procesos activos
        for pid_dir in /proc/[0-9]*; do
            local pid
            pid=$(basename "$pid_dir")
            [[ "$pid" -le 2 ]] && continue
            analyze_process_io "$pid" 2>/dev/null || true
        done

        # Analizar patrones de auditd
        detect_enumeration 2>/dev/null || true
        detect_entropy_usage 2>/dev/null || true

        # Limpiar archivos de perfil antiguos (mayores a 1 hora)
        find "$PROFILES_DIR" -name "*.sample" -mmin +60 -delete 2>/dev/null || true

        sleep "$SAMPLE_INT"
    done
}

# Analisis instantaneo
analyze_now() {
    echo ""
    echo "ANALISIS INSTANTANEO DE COMPORTAMIENTO DE PROCESOS"
    echo "==================================================="
    echo ""

    echo "=== TOP PROCESOS POR I/O ==="
    local top_io
    top_io=$(find /proc/[0-9]*/io -maxdepth 0 2>/dev/null | while read -r io_file; do
        local p
        p=$(echo "$io_file" | cut -d/ -f3)
        local c
        c=$(cat /proc/"$p"/comm 2>/dev/null || echo "?")
        local wr
        wr=$(grep "syscw:" "$io_file" 2>/dev/null | awk '{print $2}' || echo "0")
        local rd
        rd=$(grep "syscr:" "$io_file" 2>/dev/null | awk '{print $2}' || echo "0")
        echo "$((rd + wr)) $p $c $rd $wr"
    done | sort -rn | head -15 || true)

    if [[ -n "$top_io" ]]; then
        printf "  %-8s %-6s %-20s %-12s %-12s\n" "TOTAL" "PID" "COMMAND" "READS" "WRITES"
        echo "$top_io" | while read -r total pid cmd reads writes; do
            printf "  %-8s %-6s %-20s %-12s %-12s\n" "$total" "$pid" "$cmd" "$reads" "$writes"
        done
    fi
    echo ""

    echo "=== TOP PROCESOS POR FILE DESCRIPTORS ==="
    for pid_dir in /proc/[0-9]*; do
        local p
        p=$(basename "$pid_dir")
        local fd_c
        fd_c=$(ls "$pid_dir/fd" 2>/dev/null | wc -l || echo "0")
        if [[ "$fd_c" -gt 50 ]]; then
            local c
            c=$(cat "$pid_dir/comm" 2>/dev/null || echo "?")
            echo "  PID=$p CMD=$c FDs=$fd_c"
        fi
    done | sort -t= -k3 -rn | head -15
    echo ""

    echo "=== EVENTOS AUDIT RECIENTES ==="
    if command -v ausearch &>/dev/null; then
        local enum_count
        enum_count=$(ausearch -k ransomware_enum_home -ts recent 2>/dev/null | grep -c "^type=SYSCALL" || echo "0")
        local entropy_count
        entropy_count=$(ausearch -k ransomware_entropy -ts recent 2>/dev/null | grep -c "^type=SYSCALL" || echo "0")
        local mmap_count
        mmap_count=$(ausearch -k ransomware_mmap_exec -ts recent 2>/dev/null | grep -c "^type=SYSCALL" || echo "0")
        echo "  Enumeraciones de directorio: $enum_count"
        echo "  Accesos a entropia:          $entropy_count"
        echo "  mmap con EXEC:               $mmap_count"
    else
        echo "  auditd no disponible"
    fi
    echo ""
}

usage() {
    echo "Uso: $0 {monitor|analyze|status}"
    echo ""
    echo "  monitor  - Monitoreo continuo de comportamiento"
    echo "  analyze  - Analisis instantaneo"
    echo "  status   - Mostrar alertas recientes"
    exit 1
}

case "${1:-}" in
    monitor)  monitor_continuous ;;
    analyze)  analyze_now ;;
    status)
        echo "Ultimas alertas de comportamiento:"
        if [[ -f "$LOG" ]]; then
            grep "ALERTA" "$LOG" | tail -20
        else
            echo "  Sin alertas"
        fi
        ;;
    *)  usage ;;
esac
EOF
    chmod +x /usr/local/bin/analizar-comportamiento-procesos.sh
    log_change "Creado" "/usr/local/bin/analizar-comportamiento-procesos.sh"

    # Servicio systemd
    cat > /etc/systemd/system/securizar-behavior-monitor.service << 'EOF'
[Unit]
Description=Securizar Process Behavior Monitor - Anti-Ransomware
Documentation=man:securizar(8)
After=auditd.service
Wants=auditd.service

[Service]
Type=simple
ExecStart=/usr/local/bin/analizar-comportamiento-procesos.sh monitor
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal
SyslogIdentifier=securizar-behavior-monitor

# No restringir demasiado - necesita acceso a /proc
ProtectSystem=full
ReadWritePaths=/var/log/securizar /var/lib/securizar /run

[Install]
WantedBy=multi-user.target
EOF
    log_change "Creado" "/etc/systemd/system/securizar-behavior-monitor.service"

    systemctl daemon-reload 2>/dev/null || true

    if ask "¿Habilitar monitor de comportamiento de procesos ahora?"; then
        systemctl enable securizar-behavior-monitor.service 2>/dev/null || true
        systemctl start securizar-behavior-monitor.service 2>/dev/null || true
        log_change "Habilitado" "securizar-behavior-monitor.service"
    else
        log_skip "Inicio automatico del monitor de comportamiento"
    fi

    log_info "Analisis de comportamiento de procesos configurado"
    log_info "  Analisis: analizar-comportamiento-procesos.sh {monitor|analyze|status}"
else
    log_skip "Analisis de comportamiento de procesos anti-ransomware"
fi

# ============================================================
# S9: RESPUESTA DE EMERGENCIA AUTOMATIZADA
# ============================================================
log_section "S9: RESPUESTA DE EMERGENCIA AUTOMATIZADA"

log_info "Automatizacion de respuesta ante ransomware detectado:"
log_info "  - Kill de procesos sospechosos"
log_info "  - Aislamiento de red (conservando SSH)"
log_info "  - Montaje en modo solo lectura"
log_info "  - Captura de evidencia forense"
log_info "  - Notificacion a administradores"
log_info "  - Playbook de contencion completo"
log_info ""

if check_file_exists /usr/local/bin/respuesta-emergencia-ransomware.sh; then
    log_already "Respuesta de emergencia (respuesta-emergencia-ransomware.sh existe)"
elif ask "¿Configurar respuesta de emergencia automatizada anti-ransomware?"; then

    # --- Configuracion de respuesta de emergencia ---
    EMERGENCY_CONF="${RANSOMWARE_CONF_DIR}/emergency-response.conf"
    cat > "$EMERGENCY_CONF" << 'EOF'
# ============================================================
# emergency-response.conf - Respuesta de emergencia
# ============================================================
# Modulo 60 - Proteccion Anti-Ransomware
# ============================================================

# Habilitar kill automatico de procesos sospechosos
AUTO_KILL_ENABLED="true"

# Habilitar aislamiento de red automatico
AUTO_ISOLATE_ENABLED="false"

# Habilitar montaje readonly automatico
AUTO_READONLY_ENABLED="false"

# Puerto SSH a preservar durante aislamiento
SSH_PORT=22

# Direcciones IP de administracion (permitidas durante aislamiento)
ADMIN_IPS=""

# Email de notificacion de emergencia
EMERGENCY_EMAIL=""

# Directorio base para evidencia forense
FORENSIC_BASE="/var/lib/securizar/ransomware/forensics"

# Habilitar captura de memoria de procesos sospechosos
CAPTURE_PROCESS_MEMORY="true"

# Maximo de procesos a matar automaticamente
MAX_AUTO_KILL=10

# Tiempo de espera antes de acciones drasticas (segundos)
GRACE_PERIOD=30

# Nivel de respuesta: 1=conservador 2=moderado 3=agresivo
RESPONSE_LEVEL=2

# Habilitar notificacion wall a usuarios
NOTIFY_WALL="true"

# Habilitar shutdown de emergencia
ENABLE_EMERGENCY_SHUTDOWN="false"

# Log de respuesta de emergencia
EMERGENCY_LOG="/var/log/securizar/ransomware/emergency-response.log"
EOF
    chmod 600 "$EMERGENCY_CONF"
    log_change "Creado" "$EMERGENCY_CONF"

    # --- Script principal de respuesta de emergencia ---
    log_info "Creando /usr/local/bin/respuesta-emergencia-ransomware.sh..."
    cat > /usr/local/bin/respuesta-emergencia-ransomware.sh << 'EOF'
#!/bin/bash
# ============================================================
# respuesta-emergencia-ransomware.sh - Respuesta de emergencia
# Modulo 60 - Proteccion Anti-Ransomware
# ============================================================
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "[X] Requiere privilegios de root"
    exit 1
fi

CONF="/etc/securizar/ransomware/emergency-response.conf"
[[ -f "$CONF" ]] && source "$CONF"

LOG="${EMERGENCY_LOG:-/var/log/securizar/ransomware/emergency-response.log}"
FORENSIC_DIR="${FORENSIC_BASE:-/var/lib/securizar/ransomware/forensics}"
SSH_P="${SSH_PORT:-22}"
RESPONSE_LVL="${RESPONSE_LEVEL:-2}"

INCIDENT_ID="RANSOM-$(date +%Y%m%d-%H%M%S)"
INCIDENT_DIR="${FORENSIC_DIR}/${INCIDENT_ID}"

mkdir -p "$(dirname "$LOG")"
mkdir -p "$INCIDENT_DIR"
chmod 700 "$INCIDENT_DIR"

log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] EMERGENCY: $1" | tee -a "$LOG"
}

# Notificacion wall
notify_all() {
    local msg="$1"
    if [[ "${NOTIFY_WALL:-true}" == "true" ]]; then
        wall "$msg" 2>/dev/null || true
    fi
    logger -t "securizar-ransomware-emergency" -p auth.crit "$msg"
}

# ── FASE 1: Captura forense rapida ──────────────────────────
capture_forensics() {
    log_msg "FASE 1: Captura forense rapida"
    notify_all "ALERTA RANSOMWARE: Captura forense en curso - Incidente $INCIDENT_ID"

    # Procesos activos
    ps auxwwf > "${INCIDENT_DIR}/processes-tree.txt" 2>/dev/null || true
    ps -eo pid,ppid,user,uid,gid,vsz,rss,stat,start,time,comm,args \
        > "${INCIDENT_DIR}/processes-detail.txt" 2>/dev/null || true

    # Conexiones de red
    ss -tupna > "${INCIDENT_DIR}/connections.txt" 2>/dev/null || true
    ss -tlnp > "${INCIDENT_DIR}/listening-ports.txt" 2>/dev/null || true

    # Interfaces y rutas
    ip addr show > "${INCIDENT_DIR}/interfaces.txt" 2>/dev/null || true
    ip route show > "${INCIDENT_DIR}/routes.txt" 2>/dev/null || true
    ip neigh show > "${INCIDENT_DIR}/arp-table.txt" 2>/dev/null || true

    # Firewall
    iptables-save > "${INCIDENT_DIR}/iptables.txt" 2>/dev/null || true
    nft list ruleset > "${INCIDENT_DIR}/nftables.txt" 2>/dev/null || true

    # Archivos abiertos
    lsof -nP > "${INCIDENT_DIR}/open-files.txt" 2>/dev/null || true

    # Modulos del kernel
    lsmod > "${INCIDENT_DIR}/kernel-modules.txt" 2>/dev/null || true

    # Usuarios logueados
    who -a > "${INCIDENT_DIR}/logged-users.txt" 2>/dev/null || true
    last -20 > "${INCIDENT_DIR}/recent-logins.txt" 2>/dev/null || true

    # Logs recientes
    journalctl --since "1 hour ago" --no-pager > "${INCIDENT_DIR}/journal-1h.txt" 2>/dev/null || true
    journalctl -t "securizar-ransomware" --no-pager > "${INCIDENT_DIR}/journal-ransomware.txt" 2>/dev/null || true

    # Auditd reciente
    if command -v ausearch &>/dev/null; then
        ausearch -ts recent > "${INCIDENT_DIR}/audit-recent.txt" 2>/dev/null || true
        ausearch -k ransomware_write_home -ts today \
            > "${INCIDENT_DIR}/audit-ransomware-writes.txt" 2>/dev/null || true
        ausearch -k ransomware_rename_global -ts today \
            > "${INCIDENT_DIR}/audit-ransomware-renames.txt" 2>/dev/null || true
        ausearch -k ransomware_crypto_tool -ts today \
            > "${INCIDENT_DIR}/audit-crypto-tools.txt" 2>/dev/null || true
    fi

    # Estado de montajes
    mount > "${INCIDENT_DIR}/mounts.txt" 2>/dev/null || true
    df -h > "${INCIDENT_DIR}/disk-usage.txt" 2>/dev/null || true

    # Hash de archivos forenses
    sha256sum "${INCIDENT_DIR}"/*.txt > "${INCIDENT_DIR}/forensic-hashes.sha256" 2>/dev/null || true

    log_msg "Captura forense completada en $INCIDENT_DIR"
}

# ── FASE 2: Identificar y matar procesos sospechosos ────────
kill_suspicious() {
    log_msg "FASE 2: Identificando procesos sospechosos"

    local killed=0
    local max_kill="${MAX_AUTO_KILL:-10}"
    local suspect_pids=()

    # Buscar procesos con alta actividad de I/O en /home o /srv
    if command -v ausearch &>/dev/null; then
        local audit_pids
        audit_pids=$(ausearch -k ransomware_write_home -ts recent 2>/dev/null | \
            grep "^type=SYSCALL" | grep -oP 'pid=\K[0-9]+' | \
            sort | uniq -c | sort -rn | head -"$max_kill" | awk '{print $2}' || true)

        for pid in $audit_pids; do
            [[ -z "$pid" || "$pid" -le 2 ]] && continue
            local comm
            comm=$(cat /proc/"$pid"/comm 2>/dev/null || echo "unknown")
            # No matar procesos del sistema
            case "$comm" in
                systemd*|sshd|bash|login|su|sudo|init|kthread*|journald|auditd) continue ;;
            esac
            suspect_pids+=("$pid")
        done
    fi

    # Buscar procesos con muchos FDs abiertos en /home
    for pid_dir in /proc/[0-9]*; do
        local p
        p=$(basename "$pid_dir")
        [[ "$p" -le 2 ]] && continue
        local fd_count
        fd_count=$(ls "$pid_dir/fd" 2>/dev/null | wc -l || echo "0")
        if [[ "$fd_count" -gt 200 ]]; then
            local c
            c=$(cat "$pid_dir/comm" 2>/dev/null || echo "unknown")
            case "$c" in
                systemd*|sshd|bash|login|su|sudo|init|kthread*|journald|auditd|Xorg|gnome*|kde*) continue ;;
            esac
            # Verificar si tiene archivos en /home abiertos
            if ls -l "$pid_dir/fd/" 2>/dev/null | grep -q "/home/"; then
                suspect_pids+=("$p")
            fi
        fi
    done

    # Eliminar duplicados
    local unique_pids
    unique_pids=$(printf '%s\n' "${suspect_pids[@]+"${suspect_pids[@]}"}" | sort -u | head -"$max_kill")

    for pid in $unique_pids; do
        [[ -z "$pid" ]] && continue
        local comm
        comm=$(cat /proc/"$pid"/comm 2>/dev/null || echo "unknown")

        # Capturar info antes de matar
        {
            echo "PID: $pid"
            echo "Command: $comm"
            echo "Cmdline: $(tr '\0' ' ' < /proc/"$pid"/cmdline 2>/dev/null || echo 'N/A')"
            echo "Exe: $(readlink -f /proc/"$pid"/exe 2>/dev/null || echo 'N/A')"
            echo "CWD: $(readlink -f /proc/"$pid"/cwd 2>/dev/null || echo 'N/A')"
            echo "User: $(stat -c '%U' /proc/"$pid" 2>/dev/null || echo 'N/A')"
            echo "FDs: $(ls /proc/"$pid"/fd 2>/dev/null | wc -l || echo 'N/A')"
        } > "${INCIDENT_DIR}/killed-${pid}-${comm}.txt" 2>/dev/null || true

        # Copiar el binario
        cp "$(readlink -f /proc/"$pid"/exe 2>/dev/null || echo '/dev/null')" \
            "${INCIDENT_DIR}/binary-${pid}-${comm}" 2>/dev/null || true

        # Capturar memoria del proceso
        if [[ "${CAPTURE_PROCESS_MEMORY:-true}" == "true" ]]; then
            cat /proc/"$pid"/maps > "${INCIDENT_DIR}/maps-${pid}.txt" 2>/dev/null || true
        fi

        # SIGSTOP primero, luego SIGKILL
        log_msg "Matando proceso sospechoso: PID=$pid CMD=$comm"
        kill -STOP "$pid" 2>/dev/null || true
        sleep 1
        kill -9 "$pid" 2>/dev/null || true
        ((killed++)) || true
    done

    log_msg "Procesos eliminados: $killed"
}

# ── FASE 3: Aislamiento de red ──────────────────────────────
isolate_network() {
    log_msg "FASE 3: Aislamiento de red"
    notify_all "ALERTA RANSOMWARE: Aislando red del sistema - solo SSH permitido"

    # Guardar estado actual
    iptables-save > "${INCIDENT_DIR}/iptables-pre-isolate.txt" 2>/dev/null || true
    nft list ruleset > "${INCIDENT_DIR}/nft-pre-isolate.txt" 2>/dev/null || true

    # Crear tabla nftables de aislamiento
    if command -v nft &>/dev/null; then
        # Eliminar tabla anterior si existe
        nft delete table inet ransomware_emergency 2>/dev/null || true

        nft add table inet ransomware_emergency 2>/dev/null || true

        # INPUT: solo SSH y loopback
        nft add chain inet ransomware_emergency input '{ type filter hook input priority -10; policy drop; }' 2>/dev/null || true
        nft add rule inet ransomware_emergency input iif lo accept 2>/dev/null || true
        nft add rule inet ransomware_emergency input ct state established,related accept 2>/dev/null || true
        nft add rule inet ransomware_emergency input tcp dport "$SSH_P" accept 2>/dev/null || true

        # IPs de admin permitidas
        if [[ -n "${ADMIN_IPS:-}" ]]; then
            for ip in $ADMIN_IPS; do
                nft add rule inet ransomware_emergency input ip saddr "$ip" accept 2>/dev/null || true
            done
        fi

        # OUTPUT: solo SSH response y DNS
        nft add chain inet ransomware_emergency output '{ type filter hook output priority -10; policy drop; }' 2>/dev/null || true
        nft add rule inet ransomware_emergency output oif lo accept 2>/dev/null || true
        nft add rule inet ransomware_emergency output ct state established,related accept 2>/dev/null || true
        nft add rule inet ransomware_emergency output tcp sport "$SSH_P" accept 2>/dev/null || true

        # FORWARD: bloquear todo
        nft add chain inet ransomware_emergency forward '{ type filter hook forward priority -10; policy drop; }' 2>/dev/null || true

        log_msg "Red aislada via nftables (solo SSH puerto $SSH_P permitido)"
    elif command -v iptables &>/dev/null; then
        # Flush y configurar con iptables
        iptables -N RANSOMWARE_ISOLATE 2>/dev/null || iptables -F RANSOMWARE_ISOLATE
        iptables -A RANSOMWARE_ISOLATE -i lo -j ACCEPT
        iptables -A RANSOMWARE_ISOLATE -m state --state ESTABLISHED,RELATED -j ACCEPT
        iptables -A RANSOMWARE_ISOLATE -p tcp --dport "$SSH_P" -j ACCEPT
        iptables -A RANSOMWARE_ISOLATE -j DROP

        iptables -I INPUT 1 -j RANSOMWARE_ISOLATE
        iptables -I OUTPUT 1 -o lo -j ACCEPT
        iptables -I OUTPUT 2 -m state --state ESTABLISHED,RELATED -j ACCEPT
        iptables -I OUTPUT 3 -p tcp --sport "$SSH_P" -j ACCEPT
        iptables -A OUTPUT -j DROP

        log_msg "Red aislada via iptables (solo SSH puerto $SSH_P permitido)"
    fi
}

# ── FASE 4: Montaje readonly ────────────────────────────────
mount_readonly() {
    log_msg "FASE 4: Remontando filesystems en modo solo lectura"
    notify_all "ALERTA RANSOMWARE: Montando filesystems en solo lectura"

    # Remontar /home, /srv, /opt como readonly
    for mp in /home /srv /opt /var/lib; do
        if mountpoint -q "$mp" 2>/dev/null; then
            mount -o remount,ro "$mp" 2>/dev/null && \
                log_msg "Remontado readonly: $mp" || \
                log_msg "WARN: No se pudo remontar $mp como readonly"
        fi
    done
}

# ── FASE 5: Notificacion ────────────────────────────────────
notify_admins() {
    log_msg "FASE 5: Notificacion a administradores"

    local subject="[EMERGENCIA RANSOMWARE] $(hostname) - ${INCIDENT_ID}"
    local body
    body="ALERTA DE RANSOMWARE - RESPUESTA DE EMERGENCIA

Incidente: $INCIDENT_ID
Hostname:  $(hostname)
Fecha:     $(date '+%Y-%m-%d %H:%M:%S')
IP:        $(ip -4 addr show scope global | grep inet | head -1 | awk '{print $2}' || echo 'N/A')

Acciones ejecutadas:
  1. Captura forense completada
  2. Procesos sospechosos eliminados
  3. Red aislada (solo SSH)
  4. Filesystems en modo solo lectura

Evidencia forense: ${INCIDENT_DIR}/

ACCIONES REQUERIDAS:
  - Conecte via SSH para investigar
  - Revise los archivos en ${INCIDENT_DIR}/
  - Ejecute: respuesta-emergencia-ransomware.sh status
  - Para restaurar red: respuesta-emergencia-ransomware.sh restore-network
  - Para restaurar montajes: respuesta-emergencia-ransomware.sh restore-mounts"

    # Email
    if [[ -n "${EMERGENCY_EMAIL:-}" ]]; then
        if command -v mail &>/dev/null; then
            echo "$body" | mail -s "$subject" "$EMERGENCY_EMAIL" 2>/dev/null || true
        elif command -v sendmail &>/dev/null; then
            {
                echo "Subject: $subject"
                echo "To: $EMERGENCY_EMAIL"
                echo "X-Priority: 1"
                echo ""
                echo "$body"
            } | sendmail "$EMERGENCY_EMAIL" 2>/dev/null || true
        fi
        log_msg "Notificacion enviada a $EMERGENCY_EMAIL"
    fi

    # Guardar resumen del incidente
    echo "$body" > "${INCIDENT_DIR}/incident-summary.txt"
    chmod 600 "${INCIDENT_DIR}/incident-summary.txt"
}

# ── Restaurar red ────────────────────────────────────────────
restore_network() {
    log_msg "Restaurando configuracion de red"

    if command -v nft &>/dev/null; then
        nft delete table inet ransomware_emergency 2>/dev/null || true
        log_msg "Tabla nftables ransomware_emergency eliminada"
    fi

    if command -v iptables &>/dev/null; then
        iptables -D INPUT -j RANSOMWARE_ISOLATE 2>/dev/null || true
        iptables -F RANSOMWARE_ISOLATE 2>/dev/null || true
        iptables -X RANSOMWARE_ISOLATE 2>/dev/null || true
        # Restaurar OUTPUT
        iptables -D OUTPUT -j DROP 2>/dev/null || true
        log_msg "Reglas iptables de aislamiento eliminadas"
    fi

    echo "[+] Red restaurada"
    notify_all "RECUPERACION: Red restaurada en $(hostname)"
}

# ── Restaurar montajes ───────────────────────────────────────
restore_mounts() {
    log_msg "Restaurando montajes a modo lectura/escritura"

    for mp in /home /srv /opt /var/lib; do
        if mountpoint -q "$mp" 2>/dev/null; then
            mount -o remount,rw "$mp" 2>/dev/null && \
                log_msg "Remontado rw: $mp" || \
                log_msg "WARN: No se pudo remontar $mp como rw"
        fi
    done

    echo "[+] Montajes restaurados"
}

# ── Estado ───────────────────────────────────────────────────
show_status() {
    echo ""
    echo "ESTADO DE RESPUESTA DE EMERGENCIA RANSOMWARE"
    echo "=============================================="
    echo ""

    # Aislamiento de red
    echo "=== AISLAMIENTO DE RED ==="
    if nft list table inet ransomware_emergency &>/dev/null 2>&1; then
        echo "  [ACTIVO] Tabla nftables de aislamiento presente"
    elif iptables -L RANSOMWARE_ISOLATE &>/dev/null 2>&1; then
        echo "  [ACTIVO] Chain iptables de aislamiento presente"
    else
        echo "  [INACTIVO] No hay aislamiento de red"
    fi
    echo ""

    # Montajes readonly
    echo "=== MONTAJES READONLY ==="
    for mp in /home /srv /opt /var/lib; do
        if mountpoint -q "$mp" 2>/dev/null; then
            local opts
            opts=$(mount | grep " $mp " | grep -oP '\(.*\)')
            if echo "$opts" | grep -q "ro[,)]"; then
                echo "  [READONLY] $mp"
            else
                echo "  [RW]       $mp"
            fi
        fi
    done
    echo ""

    # Incidentes recientes
    echo "=== INCIDENTES RECIENTES ==="
    if [[ -d "$FORENSIC_DIR" ]]; then
        ls -lt "$FORENSIC_DIR" 2>/dev/null | head -10 | while read -r line; do
            echo "  $line"
        done
    else
        echo "  Sin incidentes registrados"
    fi
    echo ""

    # Logs recientes
    echo "=== LOG DE EMERGENCIA ==="
    if [[ -f "$LOG" ]]; then
        tail -15 "$LOG" | while read -r line; do
            echo "  $line"
        done
    else
        echo "  Sin logs"
    fi
    echo ""
}

# ── Respuesta completa automatizada ─────────────────────────
full_response() {
    log_msg "=========================================="
    log_msg "INICIANDO RESPUESTA COMPLETA DE EMERGENCIA"
    log_msg "Incidente: $INCIDENT_ID"
    log_msg "Nivel de respuesta: $RESPONSE_LVL"
    log_msg "=========================================="

    notify_all "EMERGENCIA RANSOMWARE en $(hostname): Respuesta automatica iniciada - $INCIDENT_ID"

    # Fase 1: Siempre
    capture_forensics

    # Fase 2: Nivel 1+ (kill procesos)
    if [[ "$RESPONSE_LVL" -ge 1 && "${AUTO_KILL_ENABLED:-true}" == "true" ]]; then
        kill_suspicious
    fi

    # Fase 3: Nivel 2+ (aislamiento de red)
    if [[ "$RESPONSE_LVL" -ge 2 && "${AUTO_ISOLATE_ENABLED:-false}" == "true" ]]; then
        isolate_network
    fi

    # Fase 4: Nivel 3 (readonly)
    if [[ "$RESPONSE_LVL" -ge 3 && "${AUTO_READONLY_ENABLED:-false}" == "true" ]]; then
        mount_readonly
    fi

    # Fase 5: Siempre
    notify_admins

    log_msg "=========================================="
    log_msg "RESPUESTA DE EMERGENCIA COMPLETADA"
    log_msg "Evidencia en: $INCIDENT_DIR"
    log_msg "=========================================="

    echo ""
    echo "[+] Respuesta de emergencia completada"
    echo "    Incidente: $INCIDENT_ID"
    echo "    Evidencia: $INCIDENT_DIR"
    echo ""
    echo "Comandos de restauracion:"
    echo "  respuesta-emergencia-ransomware.sh restore-network"
    echo "  respuesta-emergencia-ransomware.sh restore-mounts"
    echo "  respuesta-emergencia-ransomware.sh status"
}

usage() {
    echo "Uso: $0 {respond|isolate-network|restore-network|mount-readonly|restore-mounts|forensics|status}"
    echo ""
    echo "  respond          - Ejecutar respuesta completa de emergencia"
    echo "  isolate-network  - Solo aislar la red"
    echo "  restore-network  - Restaurar conectividad de red"
    echo "  mount-readonly   - Montar filesystems en solo lectura"
    echo "  restore-mounts   - Restaurar montajes a lectura/escritura"
    echo "  forensics        - Solo captura forense"
    echo "  kill-suspects    - Solo matar procesos sospechosos"
    echo "  status           - Ver estado actual"
    exit 1
}

case "${1:-}" in
    respond)          full_response ;;
    isolate-network)  isolate_network ;;
    restore-network)  restore_network ;;
    mount-readonly)   mount_readonly ;;
    restore-mounts)   restore_mounts ;;
    forensics)        capture_forensics ;;
    kill-suspects)    kill_suspicious ;;
    status)           show_status ;;
    *)                usage ;;
esac
EOF
    chmod +x /usr/local/bin/respuesta-emergencia-ransomware.sh
    log_change "Creado" "/usr/local/bin/respuesta-emergencia-ransomware.sh"

    log_info "Respuesta de emergencia anti-ransomware configurada"
    log_info "  Emergencia: respuesta-emergencia-ransomware.sh respond"
    log_info "  Estado:     respuesta-emergencia-ransomware.sh status"
    log_info "  Config:     $EMERGENCY_CONF"
else
    log_skip "Respuesta de emergencia automatizada anti-ransomware"
fi

# ============================================================
# S10: AUDITORIA INTEGRAL ANTI-RANSOMWARE
# ============================================================
log_section "S10: AUDITORIA INTEGRAL ANTI-RANSOMWARE"

log_info "Sistema de auditoria completo:"
log_info "  - /usr/local/bin/auditar-anti-ransomware.sh (auditoria de controles)"
log_info "  - /usr/local/bin/detectar-ransomware.sh (deteccion activa)"
log_info "  - Scoring: EXCELENTE/BUENO/MEJORABLE/DEFICIENTE"
log_info "  - Cron semanal de auditoria"
log_info ""

if check_file_exists /usr/local/bin/auditar-anti-ransomware.sh; then
    log_already "Auditoria integral anti-ransomware (auditar-anti-ransomware.sh existe)"
elif ask "¿Crear sistema de auditoria integral anti-ransomware?"; then

    # --- Script de auditoria de controles ---
    log_info "Creando /usr/local/bin/auditar-anti-ransomware.sh..."
    cat > /usr/local/bin/auditar-anti-ransomware.sh << 'EOF'
#!/bin/bash
# ============================================================
# auditar-anti-ransomware.sh - Auditoria de controles
# Modulo 60 - Proteccion Anti-Ransomware
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

REPORT_DIR="/var/lib/securizar/ransomware/audit-reports"
mkdir -p "$REPORT_DIR"
REPORT_FILE="${REPORT_DIR}/audit-$(date +%Y%m%d-%H%M%S).txt"

total_checks=0
total_passed=0
total_failed=0
total_warn=0

# Contadores por seccion
s1_checks=0; s1_pass=0
s2_checks=0; s2_pass=0
s3_checks=0; s3_pass=0
s4_checks=0; s4_pass=0
s5_checks=0; s5_pass=0
s6_checks=0; s6_pass=0
s7_checks=0; s7_pass=0
s8_checks=0; s8_pass=0
s9_checks=0; s9_pass=0

check_pass() {
    echo -e "  ${GREEN}[PASS]${NC} $1"
    echo "  [PASS] $1" >> "$REPORT_FILE"
    ((total_checks++)) || true
    ((total_passed++)) || true
}

check_fail() {
    echo -e "  ${RED}[FAIL]${NC} $1"
    echo "  [FAIL] $1" >> "$REPORT_FILE"
    ((total_checks++)) || true
    ((total_failed++)) || true
}

check_warn() {
    echo -e "  ${YELLOW}[WARN]${NC} $1"
    echo "  [WARN] $1" >> "$REPORT_FILE"
    ((total_checks++)) || true
    ((total_warn++)) || true
}

section_header() {
    echo ""
    echo -e "${CYAN}━━━ $1 ━━━${NC}"
    echo "" >> "$REPORT_FILE"
    echo "=== $1 ===" >> "$REPORT_FILE"
}

echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}  AUDITORIA DE CONTROLES ANTI-RANSOMWARE${NC}"
echo -e "${BOLD}  Modulo 60 - Proteccion Anti-Ransomware${NC}"
echo -e "${BOLD}============================================================${NC}"
echo ""

{
    echo "AUDITORIA DE CONTROLES ANTI-RANSOMWARE"
    echo "Modulo 60 - Proteccion Anti-Ransomware"
    echo "Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Hostname: $(hostname)"
    echo ""
} > "$REPORT_FILE"

# ── S1: Canary Files ────────────────────────────────────────
section_header "S1: CANARY FILES"

if [[ -f /etc/securizar/ransomware/ransomware-canary.conf ]]; then
    check_pass "Configuracion canary presente"
    ((s1_checks++)); ((s1_pass++))
else
    check_fail "Configuracion canary no encontrada"
    ((s1_checks++))
fi

if [[ -x /usr/local/bin/desplegar-canary-ransomware.sh ]]; then
    check_pass "Script de despliegue canary instalado"
    ((s1_checks++)); ((s1_pass++))
else
    check_fail "Script de despliegue canary no encontrado"
    ((s1_checks++))
fi

if [[ -x /usr/local/bin/monitor-canary-ransomware.sh ]]; then
    check_pass "Script de monitor canary instalado"
    ((s1_checks++)); ((s1_pass++))
else
    check_fail "Script de monitor canary no encontrado"
    ((s1_checks++))
fi

if [[ -x /usr/local/bin/alertar-canary-ransomware.sh ]]; then
    check_pass "Script de alerta canary instalado"
    ((s1_checks++)); ((s1_pass++))
else
    check_fail "Script de alerta canary no encontrado"
    ((s1_checks++))
fi

if systemctl is-active securizar-canary-monitor.service &>/dev/null; then
    check_pass "Servicio monitor canary activo"
    ((s1_checks++)); ((s1_pass++))
else
    check_warn "Servicio monitor canary no activo"
    ((s1_checks++))
fi

if systemctl is-active securizar-canary-verify.timer &>/dev/null; then
    check_pass "Timer de verificacion canary activo"
    ((s1_checks++)); ((s1_pass++))
else
    check_warn "Timer de verificacion canary no activo"
    ((s1_checks++))
fi

STATE_FILE="/var/lib/securizar/ransomware/canary-state.db"
if [[ -f "$STATE_FILE" ]]; then
    local_count=$(wc -l < "$STATE_FILE" 2>/dev/null || echo "0")
    if [[ "$local_count" -gt 0 ]]; then
        check_pass "Canary files desplegados: $local_count"
        ((s1_checks++)); ((s1_pass++))
    else
        check_warn "Archivo de estado canary vacio"
        ((s1_checks++))
    fi
else
    check_fail "No hay canary files desplegados"
    ((s1_checks++))
fi

# ── S2: LVM Snapshots ───────────────────────────────────────
section_header "S2: LVM SNAPSHOTS"

if [[ -f /etc/securizar/ransomware/lvm-snapshot.conf ]]; then
    check_pass "Configuracion LVM snapshot presente"
    ((s2_checks++)); ((s2_pass++))
else
    check_fail "Configuracion LVM snapshot no encontrada"
    ((s2_checks++))
fi

if [[ -x /usr/local/bin/gestionar-snapshot-ransomware.sh ]]; then
    check_pass "Script de gestion de snapshots instalado"
    ((s2_checks++)); ((s2_pass++))
else
    check_fail "Script de gestion de snapshots no encontrado"
    ((s2_checks++))
fi

if systemctl is-active securizar-lvm-snapshot.timer &>/dev/null; then
    check_pass "Timer de snapshots LVM activo"
    ((s2_checks++)); ((s2_pass++))
else
    check_warn "Timer de snapshots LVM no activo"
    ((s2_checks++))
fi

if command -v lvs &>/dev/null; then
    snap_count=$(lvs --noheadings 2>/dev/null | grep -c "ransomware-snap" || echo "0")
    if [[ "$snap_count" -gt 0 ]]; then
        check_pass "Snapshots anti-ransomware existentes: $snap_count"
        ((s2_checks++)); ((s2_pass++))
    else
        check_warn "No hay snapshots anti-ransomware creados"
        ((s2_checks++))
    fi
else
    check_warn "LVM no disponible en el sistema"
    ((s2_checks++))
fi

# ── S3: Whitelisting de ejecutables ─────────────────────────
section_header "S3: WHITELISTING DE EJECUTABLES"

# Verificar noexec en /tmp
for mp in /tmp /dev/shm /var/tmp; do
    if mountpoint -q "$mp" 2>/dev/null; then
        if mount | grep " $mp " | grep -q "noexec"; then
            check_pass "$mp montado con noexec"
            ((s3_checks++)); ((s3_pass++))
        else
            check_fail "$mp sin noexec"
            ((s3_checks++))
        fi
    else
        check_warn "$mp no es punto de montaje"
        ((s3_checks++))
    fi
done

if command -v fapolicyd &>/dev/null; then
    if systemctl is-active fapolicyd &>/dev/null; then
        check_pass "fapolicyd activo"
        ((s3_checks++)); ((s3_pass++))
    else
        check_warn "fapolicyd instalado pero inactivo"
        ((s3_checks++))
    fi
elif command -v apparmor_status &>/dev/null; then
    if [[ -f /etc/apparmor.d/securizar-anti-ransomware ]]; then
        check_pass "Perfil AppArmor anti-ransomware presente"
        ((s3_checks++)); ((s3_pass++))
    else
        check_warn "Perfil AppArmor anti-ransomware no encontrado"
        ((s3_checks++))
    fi
else
    check_warn "Sin fapolicyd ni AppArmor disponible"
    ((s3_checks++))
fi

# ── S4: Monitoreo de cambios masivos ────────────────────────
section_header "S4: MONITOREO DE CAMBIOS MASIVOS"

if [[ -f /etc/securizar/ransomware/mass-change-threshold.conf ]]; then
    check_pass "Configuracion de umbrales presente"
    ((s4_checks++)); ((s4_pass++))
else
    check_fail "Configuracion de umbrales no encontrada"
    ((s4_checks++))
fi

AUDIT_RULES_FOUND=false
for rules_path in /etc/audit/rules.d/60-ransomware-detection.rules /etc/audit/60-ransomware-detection.rules; do
    if [[ -f "$rules_path" ]]; then
        check_pass "Reglas auditd anti-ransomware presentes ($rules_path)"
        ((s4_checks++)); ((s4_pass++))
        AUDIT_RULES_FOUND=true
        break
    fi
done
if [[ "$AUDIT_RULES_FOUND" == "false" ]]; then
    check_fail "Reglas auditd anti-ransomware no encontradas"
    ((s4_checks++))
fi

if [[ -x /usr/local/bin/analizar-cambios-masivos.sh ]]; then
    check_pass "Script de analisis de cambios masivos instalado"
    ((s4_checks++)); ((s4_pass++))
else
    check_fail "Script de analisis de cambios masivos no encontrado"
    ((s4_checks++))
fi

if systemctl is-active securizar-mass-change-monitor.service &>/dev/null; then
    check_pass "Monitor de cambios masivos activo"
    ((s4_checks++)); ((s4_pass++))
else
    check_warn "Monitor de cambios masivos no activo"
    ((s4_checks++))
fi

# ── S5: Extensiones & YARA ──────────────────────────────────
section_header "S5: EXTENSIONES & YARA"

if [[ -f /etc/securizar/ransomware/ransomware-extensions.db ]]; then
    ext_count=$(grep -c '^[^#]' /etc/securizar/ransomware/ransomware-extensions.db 2>/dev/null || echo "0")
    check_pass "Base de extensiones ransomware: $ext_count entradas"
    ((s5_checks++)); ((s5_pass++))
else
    check_fail "Base de extensiones ransomware no encontrada"
    ((s5_checks++))
fi

if [[ -d /etc/securizar/ransomware/yara-rules ]]; then
    yara_count=$(find /etc/securizar/ransomware/yara-rules -name "*.yar" 2>/dev/null | wc -l || echo "0")
    if [[ "$yara_count" -gt 0 ]]; then
        check_pass "Reglas YARA presentes: $yara_count archivos"
        ((s5_checks++)); ((s5_pass++))
    else
        check_warn "Directorio YARA vacio"
        ((s5_checks++))
    fi
else
    check_fail "Directorio de reglas YARA no encontrado"
    ((s5_checks++))
fi

if command -v yara &>/dev/null; then
    check_pass "YARA instalado"
    ((s5_checks++)); ((s5_pass++))
else
    check_warn "YARA no instalado"
    ((s5_checks++))
fi

if [[ -x /usr/local/bin/escanear-ransomware.sh ]]; then
    check_pass "Script de escaneo ransomware instalado"
    ((s5_checks++)); ((s5_pass++))
else
    check_fail "Script de escaneo ransomware no encontrado"
    ((s5_checks++))
fi

if systemctl is-active securizar-ransomware-scan.timer &>/dev/null; then
    check_pass "Timer de escaneo diario activo"
    ((s5_checks++)); ((s5_pass++))
else
    check_warn "Timer de escaneo diario no activo"
    ((s5_checks++))
fi

# ── S6: Shares de red ───────────────────────────────────────
section_header "S6: SHARES DE RED"

SMB_CONF="/etc/samba/smb.conf"
if [[ -f "$SMB_CONF" ]]; then
    if grep -qi "server signing.*=.*mandatory" "$SMB_CONF" 2>/dev/null; then
        check_pass "SMB server signing = mandatory"
        ((s6_checks++)); ((s6_pass++))
    else
        check_fail "SMB server signing no es mandatory"
        ((s6_checks++))
    fi

    if grep -qi "restrict anonymous.*=.*2" "$SMB_CONF" 2>/dev/null; then
        check_pass "SMB restrict anonymous = 2"
        ((s6_checks++)); ((s6_pass++))
    else
        check_fail "SMB restrict anonymous no configurado"
        ((s6_checks++))
    fi

    if grep -q "veto files" "$SMB_CONF" 2>/dev/null; then
        check_pass "SMB veto files configurado"
        ((s6_checks++)); ((s6_pass++))
    else
        check_warn "SMB veto files no configurado"
        ((s6_checks++))
    fi

    if grep -q "full_audit" "$SMB_CONF" 2>/dev/null; then
        check_pass "SMB audit logging habilitado"
        ((s6_checks++)); ((s6_pass++))
    else
        check_warn "SMB audit logging no habilitado"
        ((s6_checks++))
    fi
else
    check_warn "Samba no configurado (no aplica si no se usa SMB)"
    ((s6_checks++))
fi

if [[ -x /usr/local/bin/verificar-shares-ransomware.sh ]]; then
    check_pass "Script de verificacion de shares instalado"
    ((s6_checks++)); ((s6_pass++))
else
    check_fail "Script de verificacion de shares no encontrado"
    ((s6_checks++))
fi

# ── S7: Inmutabilidad de backups ────────────────────────────
section_header "S7: INMUTABILIDAD DE BACKUPS"

if [[ -f /etc/securizar/ransomware/backup-immutability.conf ]]; then
    check_pass "Configuracion de inmutabilidad presente"
    ((s7_checks++)); ((s7_pass++))
else
    check_fail "Configuracion de inmutabilidad no encontrada"
    ((s7_checks++))
fi

if [[ -x /usr/local/bin/gestionar-inmutabilidad-backup.sh ]]; then
    check_pass "Script de gestion de inmutabilidad instalado"
    ((s7_checks++)); ((s7_pass++))
else
    check_fail "Script de gestion de inmutabilidad no encontrado"
    ((s7_checks++))
fi

# Verificar append-only en directorios de backup
for dir in /var/backups /var/backups/securizar; do
    if [[ -d "$dir" ]]; then
        attrs=$(lsattr -d "$dir" 2>/dev/null | awk '{print $1}' || echo "")
        if echo "$attrs" | grep -q "[ai]"; then
            check_pass "$dir tiene proteccion de atributos ($attrs)"
            ((s7_checks++)); ((s7_pass++))
        else
            check_warn "$dir sin proteccion de atributos"
            ((s7_checks++))
        fi
    fi
done

CKSUM_FILE="/var/lib/securizar/ransomware/backup-checksums.db"
if [[ -f "$CKSUM_FILE" ]]; then
    cksum_count=$(wc -l < "$CKSUM_FILE" 2>/dev/null || echo "0")
    check_pass "Checksums de backup registrados: $cksum_count"
    ((s7_checks++)); ((s7_pass++))
else
    check_warn "Sin checksums de backup registrados"
    ((s7_checks++))
fi

if systemctl is-active securizar-backup-verify.timer &>/dev/null; then
    check_pass "Timer de verificacion de backups activo"
    ((s7_checks++)); ((s7_pass++))
else
    check_warn "Timer de verificacion de backups no activo"
    ((s7_checks++))
fi

# ── S8: Analisis de comportamiento ──────────────────────────
section_header "S8: ANALISIS DE COMPORTAMIENTO"

if [[ -f /etc/securizar/ransomware/process-behavior.conf ]]; then
    check_pass "Configuracion de comportamiento presente"
    ((s8_checks++)); ((s8_pass++))
else
    check_fail "Configuracion de comportamiento no encontrada"
    ((s8_checks++))
fi

BEHAVIOR_RULES_FOUND=false
for rules_path in /etc/audit/rules.d/61-ransomware-behavior.rules /etc/audit/61-ransomware-behavior.rules; do
    if [[ -f "$rules_path" ]]; then
        check_pass "Reglas auditd de comportamiento presentes"
        ((s8_checks++)); ((s8_pass++))
        BEHAVIOR_RULES_FOUND=true
        break
    fi
done
if [[ "$BEHAVIOR_RULES_FOUND" == "false" ]]; then
    check_fail "Reglas auditd de comportamiento no encontradas"
    ((s8_checks++))
fi

if [[ -x /usr/local/bin/analizar-comportamiento-procesos.sh ]]; then
    check_pass "Script de analisis de comportamiento instalado"
    ((s8_checks++)); ((s8_pass++))
else
    check_fail "Script de analisis de comportamiento no encontrado"
    ((s8_checks++))
fi

if systemctl is-active securizar-behavior-monitor.service &>/dev/null; then
    check_pass "Monitor de comportamiento activo"
    ((s8_checks++)); ((s8_pass++))
else
    check_warn "Monitor de comportamiento no activo"
    ((s8_checks++))
fi

# ── S9: Respuesta de emergencia ─────────────────────────────
section_header "S9: RESPUESTA DE EMERGENCIA"

if [[ -f /etc/securizar/ransomware/emergency-response.conf ]]; then
    check_pass "Configuracion de emergencia presente"
    ((s9_checks++)); ((s9_pass++))
else
    check_fail "Configuracion de emergencia no encontrada"
    ((s9_checks++))
fi

if [[ -x /usr/local/bin/respuesta-emergencia-ransomware.sh ]]; then
    check_pass "Script de respuesta de emergencia instalado"
    ((s9_checks++)); ((s9_pass++))
else
    check_fail "Script de respuesta de emergencia no encontrado"
    ((s9_checks++))
fi

# Verificar capacidades de respuesta
if command -v nft &>/dev/null || command -v iptables &>/dev/null; then
    check_pass "Herramientas de firewall disponibles para aislamiento"
    ((s9_checks++)); ((s9_pass++))
else
    check_fail "Sin herramientas de firewall para aislamiento"
    ((s9_checks++))
fi

if [[ -d /var/lib/securizar/ransomware/forensics ]]; then
    check_pass "Directorio de evidencia forense presente"
    ((s9_checks++)); ((s9_pass++))
else
    check_warn "Directorio de evidencia forense no presente"
    ((s9_checks++))
fi

# ══════════════════════════════════════════
# RESUMEN DE AUDITORIA
# ══════════════════════════════════════════
echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}  RESUMEN DE AUDITORIA ANTI-RANSOMWARE${NC}"
echo -e "${BOLD}============================================================${NC}"
echo ""

# Estadisticas por seccion
echo -e "  ${BOLD}Por seccion:${NC}"
printf "    %-35s %s/%s\n" "S1 Canary Files:" "$s1_pass" "$s1_checks"
printf "    %-35s %s/%s\n" "S2 LVM Snapshots:" "$s2_pass" "$s2_checks"
printf "    %-35s %s/%s\n" "S3 Whitelisting:" "$s3_pass" "$s3_checks"
printf "    %-35s %s/%s\n" "S4 Cambios Masivos:" "$s4_pass" "$s4_checks"
printf "    %-35s %s/%s\n" "S5 Extensiones & YARA:" "$s5_pass" "$s5_checks"
printf "    %-35s %s/%s\n" "S6 Shares de Red:" "$s6_pass" "$s6_checks"
printf "    %-35s %s/%s\n" "S7 Inmutabilidad Backups:" "$s7_pass" "$s7_checks"
printf "    %-35s %s/%s\n" "S8 Comportamiento:" "$s8_pass" "$s8_checks"
printf "    %-35s %s/%s\n" "S9 Respuesta Emergencia:" "$s9_pass" "$s9_checks"
echo ""

# Puntuacion global
if [[ $total_checks -gt 0 ]]; then
    global_pct=$((total_passed * 100 / total_checks))
    rating=""
    rating_color=""

    if [[ $global_pct -ge 90 ]]; then
        rating="EXCELENTE"
        rating_color="$GREEN"
    elif [[ $global_pct -ge 70 ]]; then
        rating="BUENO"
        rating_color="$GREEN"
    elif [[ $global_pct -ge 50 ]]; then
        rating="MEJORABLE"
        rating_color="$YELLOW"
    else
        rating="DEFICIENTE"
        rating_color="$RED"
    fi

    echo -e "  ${BOLD}TOTALES:${NC}"
    echo -e "    Checks: $total_checks | Pass: $total_passed | Fail: $total_failed | Warn: $total_warn"
    echo ""
    echo -e "  ${BOLD}PUNTUACION GLOBAL: ${rating_color}${total_passed}/${total_checks} (${global_pct}%) - ${rating}${NC}"
else
    echo -e "  ${YELLOW}No se realizaron verificaciones${NC}"
fi

echo ""

# Guardar en reporte
{
    echo ""
    echo "RESUMEN"
    echo "======="
    echo "Total: $total_checks | Pass: $total_passed | Fail: $total_failed | Warn: $total_warn"
    echo "Porcentaje: $((total_passed * 100 / (total_checks > 0 ? total_checks : 1)))%"
    echo "Rating: ${rating:-N/A}"
} >> "$REPORT_FILE"

chmod 600 "$REPORT_FILE"
echo "Reporte guardado en: $REPORT_FILE"
echo ""
EOF
    chmod +x /usr/local/bin/auditar-anti-ransomware.sh
    log_change "Creado" "/usr/local/bin/auditar-anti-ransomware.sh"

    # --- Script de deteccion activa ---
    log_info "Creando /usr/local/bin/detectar-ransomware.sh..."
    cat > /usr/local/bin/detectar-ransomware.sh << 'EOF'
#!/bin/bash
# ============================================================
# detectar-ransomware.sh - Deteccion activa de ransomware
# Modulo 60 - Proteccion Anti-Ransomware
# ============================================================
# Ejecuta todas las verificaciones de deteccion:
#   1. Verificar canary files
#   2. Analizar cambios masivos
#   3. Escanear extensiones sospechosas
#   4. Analizar comportamiento de procesos
#   5. Verificar integridad de backups
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

LOG="/var/log/securizar/ransomware/detection-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$(dirname "$LOG")"

ALERT_LEVEL=0
FINDINGS=()

log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG"
}

add_finding() {
    local level="$1" desc="$2"
    FINDINGS+=("[$level] $desc")
    case "$level" in
        CRITICAL) [[ $ALERT_LEVEL -lt 3 ]] && ALERT_LEVEL=3 ;;
        HIGH)     [[ $ALERT_LEVEL -lt 2 ]] && ALERT_LEVEL=2 ;;
        MEDIUM)   [[ $ALERT_LEVEL -lt 1 ]] && ALERT_LEVEL=1 ;;
    esac
}

echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}  DETECCION ACTIVA DE RANSOMWARE${NC}"
echo -e "${BOLD}  Modulo 60 - Proteccion Anti-Ransomware${NC}"
echo -e "${BOLD}============================================================${NC}"
echo ""
echo -e "Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
echo -e "Hostname: $(hostname)"
echo ""

# ── CHECK 1: Canary files ───────────────────────────────────
echo -e "${CYAN}━━━ CHECK 1: CANARY FILES ━━━${NC}"
if [[ -x /usr/local/bin/desplegar-canary-ransomware.sh ]]; then
    if /usr/local/bin/desplegar-canary-ransomware.sh verify 2>/dev/null; then
        echo -e "  ${GREEN}[OK]${NC} Canary files intactos"
    else
        echo -e "  ${RED}[ALERTA]${NC} Canary files comprometidos!"
        add_finding "CRITICAL" "Canary files modificados o eliminados"
    fi
else
    echo -e "  ${YELLOW}[SKIP]${NC} Script de canary no instalado"
fi
echo ""

# ── CHECK 2: Cambios masivos recientes ──────────────────────
echo -e "${CYAN}━━━ CHECK 2: CAMBIOS MASIVOS RECIENTES ━━━${NC}"
# Archivos modificados en la ultima hora
for check_dir in /home /srv /opt; do
    if [[ -d "$check_dir" ]]; then
        recent_count=$(find "$check_dir" -maxdepth 5 -type f -mmin -60 2>/dev/null | wc -l || echo "0")
        if [[ "$recent_count" -gt 1000 ]]; then
            echo -e "  ${RED}[ALERTA]${NC} $check_dir: $recent_count archivos modificados en la ultima hora"
            add_finding "HIGH" "$check_dir: $recent_count archivos modificados en 60min"
        elif [[ "$recent_count" -gt 500 ]]; then
            echo -e "  ${YELLOW}[WARN]${NC} $check_dir: $recent_count archivos modificados en la ultima hora"
            add_finding "MEDIUM" "$check_dir: $recent_count archivos modificados en 60min"
        else
            echo -e "  ${GREEN}[OK]${NC} $check_dir: $recent_count archivos modificados (normal)"
        fi
    fi
done
echo ""

# ── CHECK 3: Extensiones sospechosas ────────────────────────
echo -e "${CYAN}━━━ CHECK 3: EXTENSIONES SOSPECHOSAS ━━━${NC}"
SUSP_EXTS=".encrypted .locked .crypted .WNCRY .locky .cerber .dharma .lockbit .ryk .STOP .djvu .CONTI"
susp_total=0
for ext in $SUSP_EXTS; do
    ext_count=$(find /home /srv 2>/dev/null -maxdepth 6 -name "*${ext}" -type f 2>/dev/null | wc -l || echo "0")
    if [[ "$ext_count" -gt 0 ]]; then
        echo -e "  ${RED}[ALERTA]${NC} $ext_count archivos con extension $ext"
        ((susp_total += ext_count)) || true
    fi
done
if [[ "$susp_total" -gt 0 ]]; then
    add_finding "CRITICAL" "$susp_total archivos con extensiones de ransomware"
else
    echo -e "  ${GREEN}[OK]${NC} Sin archivos con extensiones de ransomware conocidas"
fi
echo ""

# ── CHECK 4: Notas de rescate ────────────────────────────────
echo -e "${CYAN}━━━ CHECK 4: NOTAS DE RESCATE ━━━${NC}"
RANSOM_NOTES=0
for pattern in "README_DECRYPT*" "HOW_TO_DECRYPT*" "DECRYPT_INSTRUCTION*" "RECOVERY_INSTRUCTIONS*" "Restore-My-Files.txt" "@WanaDecryptor@*"; do
    note_count=$(find /home /srv /tmp 2>/dev/null -maxdepth 6 -name "$pattern" -type f 2>/dev/null | wc -l || echo "0")
    if [[ "$note_count" -gt 0 ]]; then
        echo -e "  ${RED}[ALERTA]${NC} $note_count archivos coinciden con '$pattern'"
        ((RANSOM_NOTES += note_count)) || true
    fi
done
if [[ "$RANSOM_NOTES" -gt 0 ]]; then
    add_finding "CRITICAL" "$RANSOM_NOTES notas de rescate detectadas"
else
    echo -e "  ${GREEN}[OK]${NC} Sin notas de rescate detectadas"
fi
echo ""

# ── CHECK 5: Procesos sospechosos ───────────────────────────
echo -e "${CYAN}━━━ CHECK 5: PROCESOS SOSPECHOSOS ━━━${NC}"
susp_procs=0
# Procesos con muchos file descriptors en /home
for pid_dir in /proc/[0-9]*; do
    p=$(basename "$pid_dir")
    [[ "$p" -le 2 ]] && continue
    fd_count=$(ls "$pid_dir/fd" 2>/dev/null | wc -l || echo "0")
    if [[ "$fd_count" -gt 300 ]]; then
        c=$(cat "$pid_dir/comm" 2>/dev/null || echo "unknown")
        case "$c" in
            systemd*|sshd|bash|login|init|kthread*|journald|auditd|Xorg|gnome*|kde*|firefox*|chrome*) continue ;;
        esac
        # Verificar si tiene archivos en /home abiertos
        if ls -l "$pid_dir/fd/" 2>/dev/null | grep -q "/home/"; then
            echo -e "  ${YELLOW}[WARN]${NC} PID=$p CMD=$c FDs=$fd_count (archivos en /home)"
            ((susp_procs++)) || true
        fi
    fi
done
if [[ "$susp_procs" -gt 0 ]]; then
    add_finding "HIGH" "$susp_procs procesos con actividad sospechosa en /home"
else
    echo -e "  ${GREEN}[OK]${NC} Sin procesos con actividad anormal"
fi
echo ""

# ── CHECK 6: Integridad de backups ──────────────────────────
echo -e "${CYAN}━━━ CHECK 6: INTEGRIDAD DE BACKUPS ━━━${NC}"
if [[ -x /usr/local/bin/gestionar-inmutabilidad-backup.sh ]]; then
    if /usr/local/bin/gestionar-inmutabilidad-backup.sh verify 2>/dev/null; then
        echo -e "  ${GREEN}[OK]${NC} Backups intactos"
    else
        echo -e "  ${RED}[ALERTA]${NC} Integridad de backups comprometida"
        add_finding "CRITICAL" "Backups modificados o eliminados"
    fi
else
    echo -e "  ${YELLOW}[SKIP]${NC} Script de inmutabilidad no instalado"
fi
echo ""

# ══════════════════════════════════════════
# RESULTADO FINAL
# ══════════════════════════════════════════
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}  RESULTADO DE DETECCION${NC}"
echo -e "${BOLD}============================================================${NC}"
echo ""

case $ALERT_LEVEL in
    0)
        echo -e "  ${GREEN}${BOLD}ESTADO: LIMPIO - Sin indicadores de ransomware${NC}"
        ;;
    1)
        echo -e "  ${YELLOW}${BOLD}ESTADO: PRECAUCION - Indicadores de nivel medio detectados${NC}"
        echo -e "  ${YELLOW}Revise los hallazgos y monitoree la situacion${NC}"
        ;;
    2)
        echo -e "  ${RED}${BOLD}ESTADO: ALERTA - Indicadores de nivel alto detectados${NC}"
        echo -e "  ${RED}Se recomienda investigacion inmediata${NC}"
        ;;
    3)
        echo -e "  ${RED}${BOLD}ESTADO: CRITICO - POSIBLE RANSOMWARE ACTIVO${NC}"
        echo -e "  ${RED}${BOLD}Ejecute: respuesta-emergencia-ransomware.sh respond${NC}"
        logger -t "securizar-ransomware" -p auth.crit "DETECCION CRITICA: Posible ransomware activo en $(hostname)"
        ;;
esac

if [[ ${#FINDINGS[@]} -gt 0 ]]; then
    echo ""
    echo "  Hallazgos:"
    for f in "${FINDINGS[@]}"; do
        echo "    $f"
    done
fi

echo ""

# Guardar resultado
{
    echo "DETECCION ACTIVA DE RANSOMWARE"
    echo "Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Hostname: $(hostname)"
    echo "Nivel de alerta: $ALERT_LEVEL"
    echo ""
    for f in "${FINDINGS[@]+"${FINDINGS[@]}"}"; do
        echo "$f"
    done
} >> "$LOG"
chmod 600 "$LOG"

exit $ALERT_LEVEL
EOF
    chmod +x /usr/local/bin/detectar-ransomware.sh
    log_change "Creado" "/usr/local/bin/detectar-ransomware.sh"

    # --- Cron semanal de auditoria ---
    if ask "¿Programar auditoria semanal anti-ransomware?"; then
        cat > /etc/cron.weekly/auditoria-anti-ransomware << 'EOF'
#!/bin/bash
# Auditoria semanal anti-ransomware - securizar Modulo 60
LOG="/var/log/securizar/ransomware/auditoria-semanal.log"
mkdir -p "$(dirname "$LOG")"
{
    echo "=== AUDITORIA SEMANAL $(date '+%Y-%m-%d %H:%M:%S') ==="
    /usr/local/bin/auditar-anti-ransomware.sh 2>&1
    echo ""
    echo "=== DETECCION ACTIVA ==="
    /usr/local/bin/detectar-ransomware.sh 2>&1
} >> "$LOG"

# Alertar si el nivel de deteccion es critico
DETECT_RESULT=$?
if [[ $DETECT_RESULT -ge 2 ]]; then
    logger -t "securizar-ransomware" -p auth.crit "AUDITORIA SEMANAL: Nivel de alerta $DETECT_RESULT"
fi
EOF
        chmod +x /etc/cron.weekly/auditoria-anti-ransomware
        log_change "Creado" "/etc/cron.weekly/auditoria-anti-ransomware (auditoria semanal)"
    else
        log_skip "Cron de auditoria semanal anti-ransomware"
    fi

    log_info "Sistema de auditoria integral anti-ransomware instalado"
    log_info "  Auditoria:  auditar-anti-ransomware.sh"
    log_info "  Deteccion:  detectar-ransomware.sh"
    log_info "  Escaneo:    escanear-ransomware.sh /ruta [full|ext|yara|notes]"
else
    log_skip "Auditoria integral anti-ransomware"
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
show_changes_summary
echo ""
echo "=================================================================="
echo "     PROTECCION ANTI-RANSOMWARE (MODULO 60) COMPLETADO"
echo "=================================================================="
echo ""
log_info "Backups guardados en: $BACKUP_DIR"
echo ""
echo "Comandos utiles post-configuracion:"
echo "  - Canary files:       desplegar-canary-ransomware.sh {deploy|verify|list|remove}"
echo "  - LVM snapshots:      gestionar-snapshot-ransomware.sh {create|cleanup|list|recover}"
echo "  - Whitelisting:       verificar-whitelisting-ransomware.sh"
echo "  - Cambios masivos:    analizar-cambios-masivos.sh {monitor|analyze|status}"
echo "  - Escaneo YARA:       escanear-ransomware.sh /ruta [full|ext|yara|notes|recent]"
echo "  - Shares de red:      verificar-shares-ransomware.sh"
echo "  - Inmutabilidad:      gestionar-inmutabilidad-backup.sh {protect|verify|status}"
echo "  - Comportamiento:     analizar-comportamiento-procesos.sh {monitor|analyze|status}"
echo "  - Emergencia:         respuesta-emergencia-ransomware.sh {respond|status|restore-network}"
echo "  - Auditoria:          auditar-anti-ransomware.sh"
echo "  - Deteccion activa:   detectar-ransomware.sh"
echo ""
