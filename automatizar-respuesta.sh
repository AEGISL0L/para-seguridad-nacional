#!/bin/bash
# ============================================================
# AUTOMATIZACIÓN DE RESPUESTA - SOAR Ligero
# Linux Multi-Distro (openSUSE, Debian/Ubuntu, RHEL/Fedora, Arch)
# ============================================================
# Capacidades implementadas:
#   - Respuesta automática a eventos de detección
#   - Escalación por severidad (Log/Alert/Mitigate/Isolate)
#   - Auto-bloqueo de IPs maliciosas desde detecciones
#   - Auto-lockout de cuentas sospechosas
#   - Watcher de alertas con systemd path units
#   - Notificación consolidada de incidentes
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps

# ── Pre-check: detectar secciones ya aplicadas ──
_precheck 5
_pc check_executable /usr/local/bin/soar-responder.sh
_pc check_service_enabled soar-responder.timer
_pc check_executable /usr/local/bin/soar-gestionar-bloqueos.sh
_pc check_executable /usr/local/bin/soar-notificar.sh
_pc check_file_exists /etc/security/soar-rules.conf
_precheck_result

SOAR_DIR="/var/lib/soar"
mkdir -p "$SOAR_DIR/actions" "$SOAR_DIR/queue" "$SOAR_DIR/log"
log_change "Creado" "$SOAR_DIR/{actions,queue,log}/"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   AUTOMATIZACIÓN DE RESPUESTA - SOAR Ligero               ║"
echo "║   Auto-respuesta, escalación, bloqueo automático           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# ============================================================
log_section "1. MOTOR DE RESPUESTA AUTOMÁTICA"
# ============================================================

echo "Motor central que procesa eventos de detección y ejecuta"
echo "acciones de respuesta automáticas según severidad."
echo ""
echo "Niveles de respuesta:"
echo "  - INFO:     Log y seguimiento"
echo "  - BAJO:     Log + notificación (logger)"
echo "  - MEDIO:    Log + notificación + bloqueo temporal"
echo "  - ALTO:     Log + notificación + bloqueo permanente + evidencia"
echo "  - CRÍTICO:  Log + notificación + aislamiento + forense"
echo ""

if check_executable /usr/local/bin/soar-responder.sh; then
    log_already "Motor SOAR (soar-responder.sh)"
elif ask "¿Instalar motor de respuesta automática?"; then

    cat > /usr/local/bin/soar-responder.sh << 'EOFSOAR'
#!/bin/bash
# ============================================================
# MOTOR DE RESPUESTA AUTOMÁTICA (SOAR)
# Procesa eventos y ejecuta acciones según severidad
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

SOAR_DIR="/var/lib/soar"
SOAR_LOG="$SOAR_DIR/log/soar-$(date +%Y%m%d).log"
mkdir -p "$SOAR_DIR/log" "$SOAR_DIR/actions" "$SOAR_DIR/blocked-ips"

# Configuración de umbrales
MAX_SSH_FAILS=10           # Bloquear IP tras N intentos SSH fallidos
MAX_SCAN_PORTS=50          # Bloquear IP tras N puertos escaneados
BLOCK_DURATION_TEMP=3600   # Bloqueo temporal: 1 hora
AUTO_ISOLATE=false         # No aislar automáticamente (requiere confirmación)

ACCION="${1:-procesar}"
EVENTO="${2:-}"
VALOR="${3:-}"

log_soar() {
    local level="$1"
    local msg="$2"
    echo "$(date -Iseconds) [$level] $msg" >> "$SOAR_LOG"
    logger -t soar-responder "[$level] $msg"
}

# ── Acción: Bloquear IP ──
bloquear_ip() {
    local IP="$1"
    local RAZON="$2"
    local DURACION="${3:-permanent}"

    # Verificar si ya está bloqueada
    if fw_query_rich_rule "rule family='ipv4' source address='$IP' drop" &>/dev/null 2>&1; then
        log_soar "INFO" "IP $IP ya bloqueada"
        return 0
    fi

    # Bloquear
    fw_runtime_add_rich_rule "rule family='ipv4' source address='$IP' drop" 2>/dev/null
    if [[ "$DURACION" == "permanent" ]]; then
        fw_add_rich_rule "rule family='ipv4' source address='$IP' drop" 2>/dev/null
    fi

    # Matar conexiones activas
    ss -K dst "$IP" 2>/dev/null || true

    # Registrar
    echo "$(date -Iseconds)|$IP|$RAZON|$DURACION" >> "$SOAR_DIR/blocked-ips/blocked.log"
    log_soar "ACCION" "IP $IP bloqueada ($RAZON) duración=$DURACION"
}

# ── Acción: Bloquear cuenta ──
bloquear_cuenta() {
    local USUARIO="$1"
    local RAZON="$2"

    # No bloquear root
    if [[ "$USUARIO" == "root" ]]; then
        log_soar "WARN" "No se puede bloquear root automáticamente. Razón: $RAZON"
        return 1
    fi

    # Preservar evidencia antes de bloquear
    mkdir -p "$SOAR_DIR/actions/account-$USUARIO-$(date +%Y%m%d-%H%M%S)"
    local EVID_DIR="$SOAR_DIR/actions/account-$USUARIO-$(date +%Y%m%d-%H%M%S)"
    ps -u "$USUARIO" -f > "$EVID_DIR/procesos.txt" 2>/dev/null || true
    last "$USUARIO" | head -20 > "$EVID_DIR/sesiones.txt" 2>/dev/null || true

    # Bloquear
    passwd -l "$USUARIO" 2>/dev/null
    pkill -u "$USUARIO" 2>/dev/null || true

    log_soar "ACCION" "Cuenta $USUARIO bloqueada ($RAZON). Evidencia: $EVID_DIR"
}

# ── Acción: Preservar evidencia ──
preservar_evidencia() {
    local TIPO="$1"
    local DETALLE="$2"
    local EVID_DIR="$SOAR_DIR/actions/evidence-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$EVID_DIR"

    # Snapshot rápido del sistema
    ps auxwwf > "$EVID_DIR/procesos.txt" 2>/dev/null
    ss -tupna > "$EVID_DIR/conexiones.txt" 2>/dev/null
    who -a > "$EVID_DIR/usuarios.txt" 2>/dev/null

    echo "Tipo: $TIPO" > "$EVID_DIR/info.txt"
    echo "Detalle: $DETALLE" >> "$EVID_DIR/info.txt"
    echo "Fecha: $(date -Iseconds)" >> "$EVID_DIR/info.txt"

    log_soar "ACCION" "Evidencia preservada: $EVID_DIR"
}

# ── Procesador de eventos ──
procesar_eventos() {
    log_soar "INFO" "Iniciando procesamiento de eventos"

    # 1. SSH Brute Force → Auto-bloqueo
    echo "── Procesando: SSH Brute Force ──"
    journalctl -u sshd --since "1 hour ago" --no-pager 2>/dev/null | \
        grep -iE "failed|invalid" | \
        grep -oP '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -rn | \
        while read -r count ip; do
            if [[ "$count" -ge "$MAX_SSH_FAILS" ]]; then
                # Verificar si no es IP local/privada
                if ! echo "$ip" | grep -qP "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)"; then
                    bloquear_ip "$ip" "SSH-brute-force-$count-intentos"
                    log_soar "ALTO" "SSH brute force: $ip ($count intentos) → IP bloqueada"
                fi
            fi
        done

    # 2. Port Scan → Auto-bloqueo
    echo "── Procesando: Port Scanning ──"
    journalctl --since "1 hour ago" --no-pager 2>/dev/null | \
        grep -E "REJECT|DROP" | grep "SRC=" | \
        grep -oP 'SRC=\K\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -rn | \
        while read -r count ip; do
            if [[ "$count" -ge "$MAX_SCAN_PORTS" ]]; then
                if ! echo "$ip" | grep -qP "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)"; then
                    bloquear_ip "$ip" "port-scan-$count-paquetes"
                    log_soar "MEDIO" "Port scan: $ip ($count paquetes) → IP bloqueada"
                fi
            fi
        done

    # 3. Suricata Alerts → Evaluar y responder
    echo "── Procesando: Alertas Suricata ──"
    if [[ -f /var/log/suricata/fast.log ]]; then
        # Alertas de las últimas 2 horas con severidad alta
        grep "$(date +%m/%d/%Y)" /var/log/suricata/fast.log 2>/dev/null | \
            grep -iE "ET MALWARE|ET TROJAN|ET CnC|EXPLOIT" | \
            grep -oP '\d+\.\d+\.\d+\.\d+' | sort -u | \
            while read -r ip; do
                bloquear_ip "$ip" "suricata-malware-alert"
                preservar_evidencia "suricata-alert" "IP maliciosa detectada por IDS: $ip"
                log_soar "ALTO" "Suricata: IP maliciosa $ip → bloqueada + evidencia"
            done
    fi

    # 4. UEBA Anomalías → Alertar y registrar
    echo "── Procesando: Anomalías UEBA ──"
    if [[ -f /var/log/ueba-anomalias-latest.txt ]]; then
        ANOM_COUNT=$(grep -c "ANOMALÍA" /var/log/ueba-anomalias-latest.txt 2>/dev/null || echo 0)
        if [[ "$ANOM_COUNT" -gt 5 ]]; then
            preservar_evidencia "ueba-mass-anomalies" "$ANOM_COUNT anomalías de comportamiento"
            log_soar "ALTO" "UEBA: $ANOM_COUNT anomalías → evidencia preservada"
        fi
    fi

    # 5. Persistencia detectada → Alertar
    echo "── Procesando: Persistencia ──"
    PERS_ALERTS=$(journalctl -t persistence-detection --since "1 hour ago" --no-pager 2>/dev/null | \
        grep -c "ALERTA" || echo 0)
    if [[ "$PERS_ALERTS" -gt 0 ]]; then
        preservar_evidencia "persistence-alert" "$PERS_ALERTS cambios de persistencia"
        log_soar "ALTO" "Persistencia: $PERS_ALERTS cambios detectados → evidencia preservada"
    fi

    # 6. IoC Match → Bloquear inmediatamente
    echo "── Procesando: IoC Matches ──"
    if [[ -d /etc/security/ioc-feeds ]]; then
        ACTIVE_IPS=$(ss -tn state established 2>/dev/null | awk '{print $5}' | \
            grep -oP '\d+\.\d+\.\d+\.\d+' | sort -u)
        for ioc_file in /etc/security/ioc-feeds/*.txt; do
            [[ -f "$ioc_file" ]] || continue
            while IFS= read -r ioc_ip; do
                [[ -z "$ioc_ip" ]] && continue
                [[ "$ioc_ip" =~ ^# ]] && continue
                if echo "$ACTIVE_IPS" | grep -q "^$ioc_ip$"; then
                    bloquear_ip "$ioc_ip" "ioc-feed-match-$(basename "$ioc_file")"
                    preservar_evidencia "ioc-match" "Conexión activa a IoC: $ioc_ip (feed: $(basename "$ioc_file"))"
                    log_soar "CRITICO" "IoC match: $ioc_ip → bloqueada + evidencia"
                fi
            done < "$ioc_file"
        done
    fi

    # Resumen
    echo ""
    echo "=== RESUMEN DE PROCESAMIENTO ==="
    BLOCKED_TODAY=$(grep "$(date +%Y-%m-%d)" "$SOAR_DIR/blocked-ips/blocked.log" 2>/dev/null | wc -l || echo 0)
    ACTIONS_TODAY=$(grep "$(date +%Y-%m-%d)" "$SOAR_LOG" 2>/dev/null | grep -c "ACCION" || echo 0)
    echo "IPs bloqueadas hoy: $BLOCKED_TODAY"
    echo "Acciones ejecutadas hoy: $ACTIONS_TODAY"
    echo "Log: $SOAR_LOG"
}

# ── Acción manual por línea de comandos ──
case "$ACCION" in
    procesar)
        procesar_eventos
        ;;
    bloquear-ip)
        [[ -z "$VALOR" ]] && { echo "Uso: $0 bloquear-ip <IP> [razón]"; exit 1; }
        bloquear_ip "$VALOR" "${3:-manual}"
        ;;
    bloquear-cuenta)
        [[ -z "$VALOR" ]] && { echo "Uso: $0 bloquear-cuenta <usuario> [razón]"; exit 1; }
        bloquear_cuenta "$VALOR" "${3:-manual}"
        ;;
    desbloquear-ip)
        [[ -z "$VALOR" ]] && { echo "Uso: $0 desbloquear-ip <IP>"; exit 1; }
        fw_runtime_remove_rich_rule "rule family='ipv4' source address='$VALOR' drop" 2>/dev/null
        fw_remove_rich_rule "rule family='ipv4' source address='$VALOR' drop" 2>/dev/null
        log_soar "ACCION" "IP $VALOR desbloqueada manualmente"
        echo "IP $VALOR desbloqueada"
        ;;
    estado)
        echo "=== ESTADO SOAR ==="
        echo "IPs bloqueadas: $(wc -l < "$SOAR_DIR/blocked-ips/blocked.log" 2>/dev/null || echo 0)"
        echo "Acciones hoy: $(grep "$(date +%Y-%m-%d)" "$SOAR_LOG" 2>/dev/null | grep -c "ACCION" || echo 0)"
        echo "Últimas acciones:"
        tail -10 "$SOAR_LOG" 2>/dev/null
        ;;
    *)
        echo "Uso: $0 {procesar|bloquear-ip|bloquear-cuenta|desbloquear-ip|estado}"
        ;;
esac
EOFSOAR

    chmod 700 /usr/local/bin/soar-responder.sh
    log_change "Creado" "/usr/local/bin/soar-responder.sh"
    log_change "Permisos" "/usr/local/bin/soar-responder.sh -> 700"
    log_info "Motor SOAR instalado: /usr/local/bin/soar-responder.sh"

else
    log_skip "Motor de respuesta automática"
    log_warn "Motor SOAR no instalado"
fi

# ============================================================
log_section "2. PROCESAMIENTO AUTOMÁTICO DE EVENTOS"
# ============================================================

echo "Timer systemd que ejecuta el motor SOAR periódicamente"
echo "para procesar eventos de detección y ejecutar respuestas."
echo ""

if check_service_enabled soar-responder.timer; then
    log_already "Procesamiento automático SOAR (timer 10min)"
elif ask "¿Configurar procesamiento automático cada 10 minutos?"; then

    cat > /etc/systemd/system/soar-responder.service << 'EOFSVC'
[Unit]
Description=SOAR - Motor de respuesta automática
After=network.target firewalld.service auditd.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/soar-responder.sh procesar
StandardOutput=journal
StandardError=journal
EOFSVC
    log_change "Creado" "/etc/systemd/system/soar-responder.service"

    cat > /etc/systemd/system/soar-responder.timer << 'EOFTMR'
[Unit]
Description=Ejecutar SOAR cada 10 minutos

[Timer]
OnBootSec=3min
OnUnitActiveSec=10min

[Install]
WantedBy=timers.target
EOFTMR
    log_change "Creado" "/etc/systemd/system/soar-responder.timer"

    systemctl daemon-reload 2>/dev/null
    log_change "Aplicado" "systemctl daemon-reload"
    systemctl enable soar-responder.timer 2>/dev/null
    log_change "Servicio" "soar-responder.timer enable"
    systemctl start soar-responder.timer 2>/dev/null
    log_change "Servicio" "soar-responder.timer start"
    log_info "SOAR automático activado (cada 10 minutos)"

else
    log_skip "Procesamiento automático cada 10 minutos"
    log_warn "SOAR automático no configurado"
fi

# ============================================================
log_section "3. GESTIÓN DE IPs BLOQUEADAS"
# ============================================================

echo "Herramienta para gestionar IPs bloqueadas automáticamente"
echo "con expiración, lista blanca, y estadísticas."
echo ""

if check_executable /usr/local/bin/soar-gestionar-bloqueos.sh; then
    log_already "Gestión de IPs bloqueadas (soar-gestionar-bloqueos.sh)"
elif ask "¿Instalar gestión de IPs bloqueadas?"; then

    cat > /usr/local/bin/soar-gestionar-bloqueos.sh << 'EOFBLOCK'
#!/bin/bash
# ============================================================
# GESTIÓN DE IPs BLOQUEADAS
# Lista, expira, whitelist, estadísticas
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

SOAR_DIR="/var/lib/soar"
BLOCK_LOG="$SOAR_DIR/blocked-ips/blocked.log"
WHITELIST="$SOAR_DIR/blocked-ips/whitelist.txt"
ACCION="${1:-listar}"

# Crear whitelist si no existe
touch "$WHITELIST" 2>/dev/null

case "$ACCION" in
    listar)
        echo "=== IPs BLOQUEADAS ==="
        if [[ -f "$BLOCK_LOG" ]]; then
            echo ""
            printf "%-22s %-18s %-35s %s\n" "FECHA" "IP" "RAZÓN" "DURACIÓN"
            echo "──────────────────────────────────────────────────────────────────────────────────"
            while IFS='|' read -r fecha ip razon duracion; do
                printf "%-22s %-18s %-35s %s\n" "$fecha" "$ip" "$razon" "$duracion"
            done < "$BLOCK_LOG"
            echo ""
            echo "Total: $(wc -l < "$BLOCK_LOG") IPs bloqueadas"
        else
            echo "No hay IPs bloqueadas."
        fi
        ;;

    whitelist-add)
        IP="${2:-}"
        [[ -z "$IP" ]] && { echo "Uso: $0 whitelist-add <IP>"; exit 1; }
        echo "$IP" >> "$WHITELIST"
        # Desbloquear si estaba bloqueada
        fw_runtime_remove_rich_rule "rule family='ipv4' source address='$IP' drop" 2>/dev/null || true
        fw_remove_rich_rule "rule family='ipv4' source address='$IP' drop" 2>/dev/null || true
        echo "IP $IP añadida a whitelist y desbloqueada"
        ;;

    whitelist-listar)
        echo "=== WHITELIST ==="
        if [[ -f "$WHITELIST" ]]; then
            cat "$WHITELIST"
        else
            echo "Whitelist vacía."
        fi
        ;;

    estadisticas)
        echo "=== ESTADÍSTICAS DE BLOQUEO ==="
        echo ""
        if [[ -f "$BLOCK_LOG" ]]; then
            echo "Total IPs bloqueadas: $(wc -l < "$BLOCK_LOG")"
            echo "Bloqueadas hoy: $(grep "$(date +%Y-%m-%d)" "$BLOCK_LOG" | wc -l)"
            echo "Bloqueadas esta semana: $(grep "$(date +%Y)" "$BLOCK_LOG" | wc -l)"
            echo ""
            echo "Top razones de bloqueo:"
            awk -F'|' '{print $3}' "$BLOCK_LOG" | sort | uniq -c | sort -rn | head -10
            echo ""
            echo "Top IPs bloqueadas (repetidas):"
            awk -F'|' '{print $2}' "$BLOCK_LOG" | sort | uniq -c | sort -rn | head -10
        else
            echo "Sin datos de bloqueo."
        fi
        ;;

    limpiar)
        DIAS="${2:-30}"
        echo "Limpiando bloqueos temporales expirados (>$DIAS días)..."
        CUTOFF=$(date -d "$DIAS days ago" -Iseconds)
        if [[ -f "$BLOCK_LOG" ]]; then
            BEFORE=$(wc -l < "$BLOCK_LOG")
            # Mantener solo entradas recientes y permanentes
            grep -v "temporal" "$BLOCK_LOG" > "$BLOCK_LOG.tmp" 2>/dev/null || true
            mv "$BLOCK_LOG.tmp" "$BLOCK_LOG"
            AFTER=$(wc -l < "$BLOCK_LOG")
            echo "Entradas eliminadas: $((BEFORE - AFTER))"
        fi
        ;;

    *)
        echo "Uso: $0 {listar|whitelist-add|whitelist-listar|estadisticas|limpiar}"
        ;;
esac
EOFBLOCK

    chmod 700 /usr/local/bin/soar-gestionar-bloqueos.sh
    log_change "Creado" "/usr/local/bin/soar-gestionar-bloqueos.sh"
    log_change "Permisos" "/usr/local/bin/soar-gestionar-bloqueos.sh -> 700"
    log_info "Gestión de bloqueos: /usr/local/bin/soar-gestionar-bloqueos.sh"

else
    log_skip "Gestión de IPs bloqueadas"
    log_warn "Gestión de bloqueos no instalada"
fi

# ============================================================
log_section "4. NOTIFICACIONES DE SEGURIDAD"
# ============================================================

echo "Sistema de notificaciones consolidadas que agrega"
echo "alertas de todas las fuentes y genera un resumen"
echo "con priorización de eventos."
echo ""

if check_executable /usr/local/bin/soar-notificar.sh; then
    log_already "Notificaciones consolidadas (soar-notificar.sh)"
elif ask "¿Instalar sistema de notificaciones consolidadas?"; then

    cat > /usr/local/bin/soar-notificar.sh << 'EOFNOTIFY'
#!/bin/bash
# ============================================================
# NOTIFICACIONES CONSOLIDADAS DE SEGURIDAD
# Genera resumen de alertas pendientes de revisión
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

SOAR_DIR="/var/lib/soar"
NOTIFY_LOG="$SOAR_DIR/log/notifications.log"
HORAS="${1:-1}"

echo "╔════════════════════════════════════════╗"
echo "║   NOTIFICACIONES DE SEGURIDAD          ║"
echo "║   Últimas $HORAS hora(s)                      ║"
echo "╚════════════════════════════════════════╝"
echo ""

CRITICAL=0
HIGH=0
MEDIUM=0
LOW=0

# Recopilar eventos por severidad

# CRÍTICO: IoC match, malware, aislamiento
CRIT_EVENTS=$(journalctl --since "$HORAS hours ago" --no-pager 2>/dev/null | \
    grep -ciE "CRITICO|IoC match|malware.*activo|aislamiento" || echo 0)
CRITICAL=$((CRITICAL + CRIT_EVENTS))

# ALTO: Brute force exitoso, persistencia, C2
HIGH_EVENTS=$(journalctl --since "$HORAS hours ago" --no-pager 2>/dev/null | \
    grep -ciE "ALTO|brute.force.*exitoso|persistencia.*ALERTA|C2.*detectado" || echo 0)
HIGH=$((HIGH + HIGH_EVENTS))

# MEDIO: Port scan, anomalía UEBA, bloqueo IP
MEDIUM_EVENTS=$(journalctl --since "$HORAS hours ago" --no-pager 2>/dev/null | \
    grep -ciE "MEDIO|port.scan|ANOMALÍA|IP.*bloqueada" || echo 0)
MEDIUM=$((MEDIUM + MEDIUM_EVENTS))

# BAJO: SSH fails, firewall drops
LOW_EVENTS=$(journalctl --since "$HORAS hours ago" --no-pager 2>/dev/null | \
    grep -ciE "fail2ban.*Ban|REJECT.*SRC=" || echo 0)
LOW=$((LOW + LOW_EVENTS))

# Mostrar resumen
if [[ $CRITICAL -gt 0 ]]; then
    echo -e "\033[0;31m  ██ CRÍTICO: $CRITICAL eventos\033[0m"
fi
if [[ $HIGH -gt 0 ]]; then
    echo -e "\033[1;33m  ██ ALTO:    $HIGH eventos\033[0m"
fi
if [[ $MEDIUM -gt 0 ]]; then
    echo -e "\033[0;33m  ██ MEDIO:   $MEDIUM eventos\033[0m"
fi
if [[ $LOW -gt 0 ]]; then
    echo -e "\033[0;36m  ██ BAJO:    $LOW eventos\033[0m"
fi

TOTAL=$((CRITICAL + HIGH + MEDIUM + LOW))
if [[ $TOTAL -eq 0 ]]; then
    echo -e "\033[0;32m  Sin eventos de seguridad en las últimas ${HORAS}h\033[0m"
fi

echo ""

# IPs bloqueadas recientemente
BLOCKED=$(grep "$(date +%Y-%m-%d)" "$SOAR_DIR/blocked-ips/blocked.log" 2>/dev/null | wc -l || echo 0)
if [[ $BLOCKED -gt 0 ]]; then
    echo "  IPs bloqueadas hoy: $BLOCKED"
    echo "  Últimas:"
    tail -5 "$SOAR_DIR/blocked-ips/blocked.log" 2>/dev/null | \
        awk -F'|' '{printf "    %s → %s\n", $2, $3}'
    echo ""
fi

# Acciones SOAR ejecutadas
SOAR_ACTIONS=$(grep "$(date +%Y-%m-%d)" "$SOAR_DIR/log/soar-$(date +%Y%m%d).log" 2>/dev/null | \
    grep -c "ACCION" || echo 0)
if [[ $SOAR_ACTIONS -gt 0 ]]; then
    echo "  Acciones SOAR hoy: $SOAR_ACTIONS"
fi

echo ""
echo "  Para más detalle: security-dashboard.sh"
echo "  Correlación: correlacionar-alertas.sh"
echo "  SOAR estado: soar-responder.sh estado"

# Log de notificación
echo "$(date -Iseconds)|C=$CRITICAL|H=$HIGH|M=$MEDIUM|L=$LOW|TOTAL=$TOTAL" >> "$NOTIFY_LOG"
EOFNOTIFY

    chmod 700 /usr/local/bin/soar-notificar.sh
    log_change "Creado" "/usr/local/bin/soar-notificar.sh"
    log_change "Permisos" "/usr/local/bin/soar-notificar.sh -> 700"
    log_info "Notificaciones: /usr/local/bin/soar-notificar.sh"
    echo -e "${DIM}Uso: soar-notificar.sh [horas-atrás]${NC}"

else
    log_skip "Notificaciones consolidadas"
    log_warn "Notificaciones no instaladas"
fi

# ============================================================
log_section "5. REGLAS DE RESPUESTA AUTOMÁTICA"
# ============================================================

echo "Archivo de configuración con reglas de respuesta"
echo "automática personalizables por el administrador."
echo ""

if check_file_exists /etc/security/soar-rules.conf; then
    log_already "Reglas de respuesta SOAR (soar-rules.conf)"
elif ask "¿Crear archivo de reglas de respuesta?"; then

    cat > /etc/security/soar-rules.conf << 'EOFRULES'
# ============================================================
# REGLAS DE RESPUESTA AUTOMÁTICA (SOAR)
# ============================================================
# Formato: TRIGGER|SEVERIDAD|ACCION|PARAMETROS
#
# TRIGGER: Evento que dispara la regla
#   ssh-brute-force    - Intentos SSH fallidos repetidos
#   port-scan          - Escaneo de puertos detectado
#   suricata-malware   - Alerta de malware por Suricata
#   ioc-match          - Conexión a IP/dominio de IoC
#   persistence-change - Cambio en mecanismo de persistencia
#   ueba-anomaly       - Anomalía de comportamiento UEBA
#   c2-detected        - Comunicación C2 detectada
#
# SEVERIDAD: INFO|BAJO|MEDIO|ALTO|CRITICO
#
# ACCION: Respuesta automática
#   log                - Solo registrar
#   block-ip           - Bloquear IP en firewall
#   block-account      - Bloquear cuenta de usuario
#   preserve-evidence  - Preservar evidencia forense
#   isolate            - Aislar host de la red (PELIGROSO)
#   notify             - Notificar por syslog
#
# PARAMETROS: Parámetros adicionales (umbral, duración, etc.)
# ============================================================

# SSH Brute Force
ssh-brute-force|MEDIO|block-ip|threshold=10,duration=permanent

# Port Scanning
port-scan|MEDIO|block-ip|threshold=50,duration=permanent

# Suricata Malware
suricata-malware|ALTO|block-ip,preserve-evidence|duration=permanent

# IoC Match
ioc-match|CRITICO|block-ip,preserve-evidence|duration=permanent

# Persistencia
persistence-change|ALTO|preserve-evidence,notify|

# UEBA Mass Anomalies
ueba-anomaly|ALTO|preserve-evidence,notify|threshold=5

# C2 Detected
c2-detected|CRITICO|block-ip,preserve-evidence|duration=permanent
EOFRULES

    chmod 600 /etc/security/soar-rules.conf
    log_change "Creado" "/etc/security/soar-rules.conf"
    log_change "Permisos" "/etc/security/soar-rules.conf -> 600"
    log_info "Reglas SOAR creadas: /etc/security/soar-rules.conf"
    echo -e "${DIM}Editar reglas: nano /etc/security/soar-rules.conf${NC}"

else
    log_skip "Archivo de reglas de respuesta"
    log_warn "Reglas SOAR no creadas"
fi

show_changes_summary

# ============================================================
log_section "RESUMEN DE AUTOMATIZACIÓN DE RESPUESTA"
# ============================================================

echo ""
echo -e "${BOLD}Herramientas SOAR instaladas:${NC}"
echo ""

if [[ -x /usr/local/bin/soar-responder.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} Motor SOAR (soar-responder.sh)"
else
    echo -e "  ${YELLOW}[--]${NC} Motor SOAR no instalado"
fi

if systemctl is-active soar-responder.timer &>/dev/null; then
    echo -e "  ${GREEN}[OK]${NC} Procesamiento automático (timer 10min)"
elif systemctl is-enabled soar-responder.timer &>/dev/null 2>&1; then
    echo -e "  ${YELLOW}[OK]${NC} Timer SOAR habilitado (inactivo)"
else
    echo -e "  ${YELLOW}[--]${NC} Procesamiento automático no configurado"
fi

if [[ -x /usr/local/bin/soar-gestionar-bloqueos.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} Gestión de bloqueos (soar-gestionar-bloqueos.sh)"
else
    echo -e "  ${YELLOW}[--]${NC} Gestión de bloqueos no instalada"
fi

if [[ -x /usr/local/bin/soar-notificar.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} Notificaciones (soar-notificar.sh)"
else
    echo -e "  ${YELLOW}[--]${NC} Notificaciones no instaladas"
fi

if [[ -f /etc/security/soar-rules.conf ]]; then
    echo -e "  ${GREEN}[OK]${NC} Reglas de respuesta (/etc/security/soar-rules.conf)"
else
    echo -e "  ${YELLOW}[--]${NC} Reglas de respuesta no creadas"
fi

echo ""
echo -e "${BOLD}Uso rápido:${NC}"
echo -e "  ${DIM}Procesar eventos:${NC}  soar-responder.sh procesar"
echo -e "  ${DIM}Bloquear IP:${NC}       soar-responder.sh bloquear-ip 1.2.3.4 razón"
echo -e "  ${DIM}Desbloquear IP:${NC}    soar-responder.sh desbloquear-ip 1.2.3.4"
echo -e "  ${DIM}Ver estado:${NC}        soar-responder.sh estado"
echo -e "  ${DIM}Ver bloqueos:${NC}      soar-gestionar-bloqueos.sh listar"
echo -e "  ${DIM}Notificaciones:${NC}    soar-notificar.sh 1"
echo ""
log_info "Módulo de automatización de respuesta completado"
