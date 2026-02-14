#!/bin/bash
# ============================================================
# MONITORIZACIÓN CONTINUA - Operaciones de Seguridad
# Linux Multi-Distro (openSUSE, Debian/Ubuntu, RHEL/Fedora, Arch)
# ============================================================
# Capacidades implementadas:
#   - Dashboard consolidado de estado de seguridad
#   - Correlación de alertas multi-fuente
#   - Baseline de comportamiento normal del sistema
#   - Alertas unificadas con deduplicación
#   - Health check de todos los controles de seguridad
#   - Digest periódico de seguridad con priorización
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps

# --- Pre-check: verificar si ya está todo aplicado ---
_precheck 5
_pc 'check_executable /usr/local/bin/security-dashboard.sh'
_pc 'check_executable /usr/local/bin/correlacionar-alertas.sh'
_pc 'check_executable /usr/local/bin/security-baseline.sh'
_pc 'check_executable /usr/local/bin/security-healthcheck.sh'
_pc 'check_executable /usr/local/bin/security-digest.sh'
_precheck_result

MON_DIR="/var/lib/security-monitoring"
mkdir -p "$MON_DIR"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MONITORIZACIÓN CONTINUA - Operaciones de Seguridad      ║"
echo "║   Correlación, baseline, dashboard, alertas                ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# ============================================================
log_section "1. DASHBOARD DE ESTADO DE SEGURIDAD"
# ============================================================

echo "Script que muestra el estado consolidado de todos los"
echo "controles de seguridad del sistema en tiempo real."
echo ""
echo "Verifica:"
echo "  - Estado de servicios de seguridad (firewalld, auditd, fail2ban...)"
echo "  - Scripts de detección activos y última ejecución"
echo "  - Alertas recientes de todas las fuentes"
echo "  - Estado de integridad del sistema"
echo ""

if check_executable /usr/local/bin/security-dashboard.sh; then
    log_already "Dashboard de estado de seguridad (security-dashboard.sh)"
elif ask "¿Instalar dashboard de estado de seguridad?"; then

    cat > /usr/local/bin/security-dashboard.sh << 'EOFDASH'
#!/bin/bash
# ============================================================
# DASHBOARD DE ESTADO DE SEGURIDAD
# Muestra estado consolidado de todos los controles
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

clear
echo ""
echo "╔════════════════════════════════════════════════════════╗"
echo "║           DASHBOARD DE SEGURIDAD                      ║"
echo "║           $(date '+%Y-%m-%d %H:%M:%S')                          ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

# ── 1. Servicios de seguridad ──
echo -e "${BOLD}═══ SERVICIOS DE SEGURIDAD ═══${NC}"
echo ""

svc_check() {
    local name="$1"
    local svc="$2"
    if systemctl is-active "$svc" &>/dev/null; then
        echo -e "  ${GREEN}●${NC} $name"
    elif systemctl is-enabled "$svc" &>/dev/null 2>&1; then
        echo -e "  ${YELLOW}◐${NC} $name (habilitado, inactivo)"
    else
        echo -e "  ${RED}○${NC} $name (no configurado)"
    fi
}

svc_check "Firewalld" "firewalld"
svc_check "Auditd" "auditd"
svc_check "Fail2ban" "fail2ban"
svc_check "SSHd" "sshd"
svc_check "AppArmor" "apparmor"
svc_check "Suricata IDS" "suricata"
svc_check "ClamAV" "clamd"
svc_check "Arpwatch" "arpwatch"

echo ""

# ── 2. Scripts de detección ──
echo -e "${BOLD}═══ SCRIPTS DE DETECCIÓN ═══${NC}"
echo ""

det_check() {
    local name="$1"
    local script="$2"
    if [[ -x "$script" ]]; then
        # Buscar última ejecución en journal o cron log
        local last_run=""
        last_run=$(journalctl -t "$(basename "$script" .sh)" --since "7 days ago" --no-pager 2>/dev/null | tail -1 | grep -oP '^\w+ \d+ \d+:\d+:\d+' || echo "")
        if [[ -z "$last_run" ]]; then
            # Buscar en syslog
            last_run=$(journalctl --since "24 hours ago" --no-pager 2>/dev/null | grep "$(basename "$script")" | tail -1 | grep -oP '^\w+ \d+ \d+:\d+:\d+' || echo "sin registros")
        fi
        echo -e "  ${GREEN}●${NC} $name ${DIM}(última: $last_run)${NC}"
    else
        echo -e "  ${RED}○${NC} $name ${DIM}(no instalado)${NC}"
    fi
}

det_check "Masquerading (T1036)" "/usr/local/bin/detectar-masquerading.sh"
det_check "Rootkits (T1014)" "/usr/local/bin/detectar-rootkits.sh"
det_check "Ocultos (T1564)" "/usr/local/bin/detectar-ocultos.sh"
det_check "Ofuscados (T1027)" "/usr/local/bin/detectar-ofuscados.sh"
det_check "Port scan (T1046)" "/usr/local/bin/detectar-portscan.sh"
det_check "Beaconing (T1071)" "/usr/local/bin/detectar-beaconing.sh"
det_check "Tunneling (T1090)" "/usr/local/bin/detectar-tunneling.sh"
det_check "DGA (T1568)" "/usr/local/bin/detectar-dga.sh"
det_check "Exfiltración (TA0010)" "/usr/local/bin/detectar-exfiltracion.sh"
det_check "DNS tunnel (T1048)" "/usr/local/bin/detectar-dns-tunnel.sh"
det_check "Lateral (TA0008)" "/usr/local/bin/detectar-lateral.sh"
det_check "Staging (T1074)" "/usr/local/bin/detectar-staging.sh"
det_check "Recolección (T1119)" "/usr/local/bin/detectar-recoleccion.sh"
det_check "C2 completo (TA0011)" "/usr/local/bin/detectar-c2-completo.sh"
det_check "Brute force (T1110)" "/usr/local/bin/monitorear-bruteforce.sh"
det_check "Credenciales (T1552)" "/usr/local/bin/buscar-credenciales.sh"
det_check "Promiscuo (T1040)" "/usr/local/bin/detectar-promiscuo.sh"
det_check "Keylogger (T1056)" "/usr/local/bin/detectar-keylogger.sh"
det_check "Reconocimiento (T1016)" "/usr/local/bin/detectar-reconocimiento.sh"
det_check "Tool transfer (T1105)" "/usr/local/bin/detectar-tool-transfer.sh"

echo ""

# ── 3. Timers de seguridad ──
echo -e "${BOLD}═══ TIMERS SYSTEMD DE SEGURIDAD ═══${NC}"
echo ""

for timer in watchdog-seguridad detectar-promiscuo monitorear-transferencias; do
    if systemctl is-active "${timer}.timer" &>/dev/null; then
        NEXT=$(systemctl show "${timer}.timer" --property=NextElapseUSecRealtime --value 2>/dev/null | head -c 19)
        echo -e "  ${GREEN}●${NC} ${timer}.timer ${DIM}(próximo: $NEXT)${NC}"
    elif systemctl is-enabled "${timer}.timer" &>/dev/null 2>&1; then
        echo -e "  ${YELLOW}◐${NC} ${timer}.timer (habilitado, inactivo)"
    else
        echo -e "  ${DIM}○${NC} ${timer}.timer (no configurado)"
    fi
done

echo ""

# ── 4. Alertas recientes ──
echo -e "${BOLD}═══ ALERTAS RECIENTES (24h) ═══${NC}"
echo ""

ALERT_COUNT=0

# Fail2ban bans
F2B_BANS=$(journalctl -u fail2ban --since "24 hours ago" --no-pager 2>/dev/null | grep -c "Ban" || echo 0)
if [[ "$F2B_BANS" -gt 0 ]]; then
    echo -e "  ${YELLOW}⚠${NC}  Fail2ban: $F2B_BANS IPs baneadas"
    ALERT_COUNT=$((ALERT_COUNT + F2B_BANS))
fi

# Suricata alerts
if [[ -f /var/log/suricata/fast.log ]]; then
    SURI_ALERTS=$(grep "$(date +%m/%d/%Y)" /var/log/suricata/fast.log 2>/dev/null | wc -l || echo 0)
    if [[ "$SURI_ALERTS" -gt 0 ]]; then
        echo -e "  ${YELLOW}⚠${NC}  Suricata: $SURI_ALERTS alertas IDS"
        ALERT_COUNT=$((ALERT_COUNT + SURI_ALERTS))
    fi
fi

# SSH failed attempts
SSH_FAILS=$(journalctl -u sshd --since "24 hours ago" --no-pager 2>/dev/null | grep -ci "failed\|invalid" || echo 0)
if [[ "$SSH_FAILS" -gt 0 ]]; then
    echo -e "  ${YELLOW}⚠${NC}  SSH: $SSH_FAILS intentos fallidos"
    ALERT_COUNT=$((ALERT_COUNT + SSH_FAILS))
fi

# Auditd anomalies
if command -v ausearch &>/dev/null; then
    AUDIT_ANOM=$(ausearch -m ANOM_PROMISCUOUS,ANOM_ABEND -ts recent 2>/dev/null | grep -c "type=" || echo 0)
    if [[ "$AUDIT_ANOM" -gt 0 ]]; then
        echo -e "  ${RED}✗${NC}  Auditd: $AUDIT_ANOM anomalías detectadas"
        ALERT_COUNT=$((ALERT_COUNT + AUDIT_ANOM))
    fi
fi

# Firewall drops
FW_DROPS=$(journalctl --since "24 hours ago" --no-pager 2>/dev/null | grep -c "REJECT\|DROP" || echo 0)
if [[ "$FW_DROPS" -gt 0 ]]; then
    echo -e "  ${DIM}ℹ${NC}  Firewall: $FW_DROPS paquetes rechazados/dropped"
fi

# Detection script alerts
DET_ALERTS=$(journalctl --since "24 hours ago" --no-pager 2>/dev/null | grep -ciE "detectar-.*ALERTA|SOSPECHOSO|ANOMAL" || echo 0)
if [[ "$DET_ALERTS" -gt 0 ]]; then
    echo -e "  ${RED}✗${NC}  Scripts detección: $DET_ALERTS alertas"
    ALERT_COUNT=$((ALERT_COUNT + DET_ALERTS))
fi

if [[ "$ALERT_COUNT" -eq 0 ]]; then
    echo -e "  ${GREEN}✓${NC}  Sin alertas en las últimas 24 horas"
fi

echo ""

# ── 5. Estado de integridad ──
echo -e "${BOLD}═══ INTEGRIDAD DEL SISTEMA ═══${NC}"
echo ""

# Archivos críticos
for f in /etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config; do
    if [[ -f "$f" ]]; then
        MOD_TIME=$(stat -c %Y "$f" 2>/dev/null)
        MOD_AGO=$(( $(date +%s) - MOD_TIME ))
        if [[ $MOD_AGO -lt 86400 ]]; then
            echo -e "  ${YELLOW}⚠${NC}  $f modificado hace $(( MOD_AGO / 3600 ))h"
        else
            echo -e "  ${GREEN}●${NC}  $f (estable)"
        fi
    fi
done

# Binarios SUID nuevos (24h)
NEW_SUID=$(find /usr /bin /sbin -maxdepth 3 -perm /4000 -mtime -1 -type f 2>/dev/null | wc -l)
if [[ "$NEW_SUID" -gt 0 ]]; then
    echo -e "  ${RED}✗${NC}  $NEW_SUID binarios SUID modificados en 24h"
else
    echo -e "  ${GREEN}●${NC}  Sin cambios en binarios SUID"
fi

echo ""

# ── 6. Resumen ──
echo -e "${BOLD}═══ RESUMEN ═══${NC}"
echo ""
echo -e "  Total alertas (24h): ${BOLD}$ALERT_COUNT${NC}"
if [[ $ALERT_COUNT -eq 0 ]]; then
    echo -e "  Estado: ${GREEN}NORMAL${NC}"
elif [[ $ALERT_COUNT -lt 10 ]]; then
    echo -e "  Estado: ${YELLOW}ATENCIÓN${NC}"
else
    echo -e "  Estado: ${RED}ALERTA${NC} - Revisar inmediatamente"
fi
echo ""
EOFDASH

    chmod 700 /usr/local/bin/security-dashboard.sh
    log_change "Creado" "/usr/local/bin/security-dashboard.sh"
    log_change "Permisos" "/usr/local/bin/security-dashboard.sh -> 700"
    log_info "Dashboard instalado: /usr/local/bin/security-dashboard.sh"

else
    log_skip "Dashboard de estado de seguridad"
    log_warn "Dashboard no instalado"
fi

# ============================================================
log_section "2. CORRELACIÓN DE ALERTAS MULTI-FUENTE"
# ============================================================

echo "Motor de correlación que analiza alertas de múltiples"
echo "fuentes (auditd, Suricata, fail2ban, firewalld, scripts)"
echo "y detecta patrones de ataque coordinado."
echo ""
echo "Correlaciones detectadas:"
echo "  - Brute force + login exitoso = posible compromiso"
echo "  - Port scan + conexión nueva = reconocimiento + acceso"
echo "  - Descarga herramienta + ejecución sospechosa = malware"
echo "  - Conexiones C2 + transferencia datos = exfiltración"
echo ""

if check_executable /usr/local/bin/correlacionar-alertas.sh; then
    log_already "Motor de correlación de alertas (correlacionar-alertas.sh)"
elif ask "¿Instalar motor de correlación de alertas?"; then

    cat > /usr/local/bin/correlacionar-alertas.sh << 'EOFCORR'
#!/bin/bash
# ============================================================
# CORRELACIÓN DE ALERTAS MULTI-FUENTE
# Detecta patrones de ataque coordinado
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

HORAS="${1:-24}"
CORR_DIR="/var/lib/security-monitoring/correlaciones"
mkdir -p "$CORR_DIR"
REPORT="$CORR_DIR/correlacion-$(date +%Y%m%d-%H%M%S).txt"
ALERT_FILE=$(mktemp)

echo "=== CORRELACIÓN DE ALERTAS ===" | tee "$REPORT"
echo "Período: últimas $HORAS horas" | tee -a "$REPORT"
echo "Generado: $(date -Iseconds)" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

INCIDENTS=0

# ── Recopilar eventos por IP ──

declare -A IP_EVENTS
declare -A IP_SSH_FAIL
declare -A IP_SSH_OK
declare -A IP_FW_DROP
declare -A IP_SURI
declare -A IP_SCAN

# SSH failed auth por IP
while IFS= read -r line; do
    IP=$(echo "$line" | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1)
    if [[ -n "$IP" ]]; then
        IP_SSH_FAIL[$IP]=$(( ${IP_SSH_FAIL[$IP]:-0} + 1 ))
        IP_EVENTS[$IP]="${IP_EVENTS[$IP]:-} SSH_FAIL"
    fi
done < <(journalctl -u sshd --since "$HORAS hours ago" --no-pager 2>/dev/null | grep -iE "failed|invalid")

# SSH successful auth por IP
while IFS= read -r line; do
    IP=$(echo "$line" | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1)
    if [[ -n "$IP" ]]; then
        IP_SSH_OK[$IP]=$(( ${IP_SSH_OK[$IP]:-0} + 1 ))
        IP_EVENTS[$IP]="${IP_EVENTS[$IP]:-} SSH_OK"
    fi
done < <(journalctl -u sshd --since "$HORAS hours ago" --no-pager 2>/dev/null | grep -i "accepted")

# Firewall drops por IP
while IFS= read -r line; do
    IP=$(echo "$line" | grep -oP 'SRC=\K\d+\.\d+\.\d+\.\d+' | head -1)
    if [[ -n "$IP" ]]; then
        IP_FW_DROP[$IP]=$(( ${IP_FW_DROP[$IP]:-0} + 1 ))
        IP_EVENTS[$IP]="${IP_EVENTS[$IP]:-} FW_DROP"
    fi
done < <(journalctl --since "$HORAS hours ago" --no-pager 2>/dev/null | grep -E "REJECT|DROP" | grep "SRC=")

# Suricata alerts por IP
if [[ -f /var/log/suricata/fast.log ]]; then
    while IFS= read -r line; do
        IP=$(echo "$line" | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1)
        if [[ -n "$IP" ]]; then
            IP_SURI[$IP]=$(( ${IP_SURI[$IP]:-0} + 1 ))
            IP_EVENTS[$IP]="${IP_EVENTS[$IP]:-} SURICATA"
        fi
    done < <(grep "$(date +%m/%d/%Y)" /var/log/suricata/fast.log 2>/dev/null)
fi

# ── Correlación 1: Brute Force seguido de acceso exitoso ──
echo "── CORRELACIÓN 1: Brute Force → Acceso Exitoso ──" | tee -a "$REPORT"
echo "(T1110 → T1078) Posible cuenta comprometida" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

for IP in "${!IP_SSH_FAIL[@]}"; do
    FAILS=${IP_SSH_FAIL[$IP]}
    OKS=${IP_SSH_OK[$IP]:-0}
    if [[ $FAILS -ge 5 ]] && [[ $OKS -ge 1 ]]; then
        echo "  [CRÍTICO] IP $IP: $FAILS intentos fallidos SEGUIDOS de $OKS accesos exitosos" | tee -a "$REPORT"
        echo "  → Posible compromiso de cuenta. Ejecutar: pb-cuenta-comprometida.sh" | tee -a "$REPORT"
        echo "" | tee -a "$REPORT"
        ((INCIDENTS++))
        logger -t security-correlation "CRITICO: Brute force exitoso desde $IP ($FAILS fails, $OKS ok)"
    fi
done

# ── Correlación 2: Port scan + conexión establecida ──
echo "── CORRELACIÓN 2: Port Scan → Conexión Establecida ──" | tee -a "$REPORT"
echo "(T1046 → T1021) Reconocimiento seguido de acceso" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

for IP in "${!IP_FW_DROP[@]}"; do
    DROPS=${IP_FW_DROP[$IP]}
    if [[ $DROPS -ge 20 ]]; then
        # Verificar si la misma IP tiene conexiones establecidas actualmente
        ESTABLISHED=$(ss -tn state established 2>/dev/null | grep -c "$IP" || echo 0)
        if [[ $ESTABLISHED -gt 0 ]]; then
            echo "  [ALTO] IP $IP: $DROPS paquetes rechazados + $ESTABLISHED conexiones activas" | tee -a "$REPORT"
            echo "  → Port scan exitoso. Verificar conexiones: ss -tn | grep $IP" | tee -a "$REPORT"
            echo "" | tee -a "$REPORT"
            ((INCIDENTS++))
        fi
    fi
done

# ── Correlación 3: Suricata alert + conexión persistente (C2) ──
echo "── CORRELACIÓN 3: Alerta IDS → C2 Persistente ──" | tee -a "$REPORT"
echo "(T1071 → TA0011) Tráfico malicioso con conexión persistente" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

for IP in "${!IP_SURI[@]}"; do
    ALERTS=${IP_SURI[$IP]}
    if [[ $ALERTS -ge 1 ]]; then
        # Verificar si hay conexiones activas a esa IP
        ACTIVE=$(ss -tn state established 2>/dev/null | grep -c "$IP" || echo 0)
        if [[ $ACTIVE -gt 0 ]]; then
            echo "  [CRÍTICO] IP $IP: $ALERTS alertas Suricata + $ACTIVE conexiones activas" | tee -a "$REPORT"
            echo "  → Posible C2 activo. Ejecutar: pb-c2-exfiltracion.sh $IP" | tee -a "$REPORT"
            echo "" | tee -a "$REPORT"
            ((INCIDENTS++))
        fi
    fi
done

# ── Correlación 4: Multi-fuente sobre misma IP ──
echo "── CORRELACIÓN 4: Actividad Multi-Fuente por IP ──" | tee -a "$REPORT"
echo "IPs con actividad en 3+ fuentes diferentes" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

for IP in "${!IP_EVENTS[@]}"; do
    EVENTS="${IP_EVENTS[$IP]}"
    # Contar fuentes distintas
    SOURCES=$(echo "$EVENTS" | tr ' ' '\n' | sort -u | grep -c "." || echo 0)
    if [[ $SOURCES -ge 3 ]]; then
        UNIQUE=$(echo "$EVENTS" | tr ' ' '\n' | sort -u | tr '\n' ',' | sed 's/,$//')
        echo "  [ALTO] IP $IP activa en $SOURCES fuentes: $UNIQUE" | tee -a "$REPORT"
        echo "  → Actividad coordinada. Investigar inmediatamente." | tee -a "$REPORT"
        echo "" | tee -a "$REPORT"
        ((INCIDENTS++))
    fi
done

# ── Correlación 5: Cadena de ataque temporal ──
echo "── CORRELACIÓN 5: Detección de Cadena de Ataque ──" | tee -a "$REPORT"
echo "Secuencia: Acceso → Escalada → Persistencia" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# Buscar si hubo: login sospechoso + sudo anómalo + crontab modificado
SUDO_ANOM=$(journalctl --since "$HORAS hours ago" --no-pager 2>/dev/null | grep -ci "sudo.*COMMAND\|sudo.*not allowed" || echo 0)
CRON_CHANGES=0
if command -v ausearch &>/dev/null; then
    CRON_CHANGES=$(ausearch -k cron-persistence -ts recent 2>/dev/null | grep -c "type=SYSCALL" || echo 0)
fi
SYSTEMD_NEW=$(find /etc/systemd/system/ -maxdepth 1 -name "*.service" -mmin -$((HORAS * 60)) -type f 2>/dev/null | wc -l)

if [[ $SUDO_ANOM -gt 5 ]] && [[ $((CRON_CHANGES + SYSTEMD_NEW)) -gt 0 ]]; then
    echo "  [CRÍTICO] Cadena de ataque detectada:" | tee -a "$REPORT"
    echo "    - $SUDO_ANOM eventos sudo anómalos" | tee -a "$REPORT"
    echo "    - $CRON_CHANGES cambios en crontabs" | tee -a "$REPORT"
    echo "    - $SYSTEMD_NEW servicios systemd nuevos" | tee -a "$REPORT"
    echo "  → Posible compromiso completo. Ejecutar ir-recolectar-forense.sh" | tee -a "$REPORT"
    echo "" | tee -a "$REPORT"
    ((INCIDENTS++))
fi

# ── Resumen ──
echo "════════════════════════════════════════════" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"
if [[ $INCIDENTS -eq 0 ]]; then
    echo "Sin correlaciones de ataque detectadas." | tee -a "$REPORT"
else
    echo "TOTAL INCIDENTES CORRELACIONADOS: $INCIDENTS" | tee -a "$REPORT"
    echo "" | tee -a "$REPORT"
    echo "Acciones recomendadas:" | tee -a "$REPORT"
    echo "  1. Revisar cada incidente en $REPORT" | tee -a "$REPORT"
    echo "  2. Ejecutar playbook correspondiente: ir-responder.sh" | tee -a "$REPORT"
    echo "  3. Recolectar evidencia: ir-recolectar-forense.sh" | tee -a "$REPORT"
    echo "  4. Generar timeline: ir-timeline.sh $HORAS" | tee -a "$REPORT"
    logger -t security-correlation "RESUMEN: $INCIDENTS incidentes correlacionados detectados"
fi
echo "" | tee -a "$REPORT"
echo "Reporte guardado: $REPORT" | tee -a "$REPORT"

rm -f "$ALERT_FILE"
EOFCORR

    chmod 700 /usr/local/bin/correlacionar-alertas.sh
    log_change "Creado" "/usr/local/bin/correlacionar-alertas.sh"
    log_change "Permisos" "/usr/local/bin/correlacionar-alertas.sh -> 700"
    log_info "Motor de correlación instalado: /usr/local/bin/correlacionar-alertas.sh"
    echo -e "${DIM}Uso: correlacionar-alertas.sh [horas-atrás]${NC}"

else
    log_skip "Motor de correlación de alertas"
    log_warn "Motor de correlación no instalado"
fi

# ============================================================
log_section "3. BASELINE DE COMPORTAMIENTO DEL SISTEMA"
# ============================================================

echo "Herramienta para crear y verificar líneas base del"
echo "comportamiento normal del sistema. Detecta desviaciones"
echo "que puedan indicar compromiso."
echo ""
echo "Baselines creados:"
echo "  - Puertos en escucha normales"
echo "  - Servicios habilitados normales"
echo "  - Usuarios y grupos del sistema"
echo "  - Binarios SUID/SGID legítimos"
echo "  - Conexiones salientes normales"
echo ""

if check_executable /usr/local/bin/security-baseline.sh; then
    log_already "Baseline de comportamiento del sistema (security-baseline.sh)"
elif ask "¿Instalar baseline de comportamiento?"; then

    mkdir -p /var/lib/security-monitoring/baselines
    log_change "Creado" "/var/lib/security-monitoring/baselines/"

    cat > /usr/local/bin/security-baseline.sh << 'EOFBASE'
#!/bin/bash
# ============================================================
# BASELINE DE COMPORTAMIENTO DEL SISTEMA
# Crear: security-baseline.sh crear
# Verificar: security-baseline.sh verificar
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

BASE_DIR="/var/lib/security-monitoring/baselines"
mkdir -p "$BASE_DIR"
ACTION="${1:-verificar}"

crear_baseline() {
    echo "=== CREANDO BASELINE DE SEGURIDAD ==="
    echo "Fecha: $(date -Iseconds)"
    echo ""

    # Puertos en escucha
    echo "[1/6] Puertos en escucha..."
    ss -tlnp | awk 'NR>1 {print $4}' | sort > "$BASE_DIR/puertos-escucha.baseline"

    # Servicios habilitados
    echo "[2/6] Servicios habilitados..."
    systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null | \
        awk 'NR>1 && NF>1 {print $1}' | sort > "$BASE_DIR/servicios-habilitados.baseline"

    # Usuarios del sistema
    echo "[3/6] Usuarios del sistema..."
    awk -F: '{print $1":"$3":"$7}' /etc/passwd | sort > "$BASE_DIR/usuarios.baseline"

    # Binarios SUID
    echo "[4/6] Binarios SUID/SGID..."
    find / -maxdepth 5 -perm /6000 -type f 2>/dev/null | sort > "$BASE_DIR/suid-sgid.baseline"

    # Conexiones salientes habituales (destinos)
    echo "[5/6] Destinos de conexiones salientes..."
    ss -tn state established 2>/dev/null | awk 'NR>1 {print $5}' | \
        grep -oP '\d+\.\d+\.\d+\.\d+' | sort -u > "$BASE_DIR/destinos-salientes.baseline"

    # Crontabs
    echo "[6/6] Crontabs del sistema..."
    for user in $(cut -d: -f1 /etc/passwd); do
        CRON=$(crontab -u "$user" -l 2>/dev/null | grep -v "^#" | grep -v "^$")
        if [[ -n "$CRON" ]]; then
            echo "==$user==" >> "$BASE_DIR/crontabs.baseline"
            echo "$CRON" >> "$BASE_DIR/crontabs.baseline"
        fi
    done
    ls /etc/cron.d/ /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/ 2>/dev/null | sort > "$BASE_DIR/cron-files.baseline"

    # Metadata
    echo "$(date -Iseconds)" > "$BASE_DIR/baseline-timestamp.txt"
    sha256sum "$BASE_DIR"/*.baseline > "$BASE_DIR/baseline-hashes.txt" 2>/dev/null

    echo ""
    echo "Baseline creado en: $BASE_DIR"
    echo "Archivos: $(ls "$BASE_DIR"/*.baseline 2>/dev/null | wc -l)"
    echo ""
    echo "IMPORTANTE: Ejecutar esto SOLO en un sistema limpio y verificado."
}

verificar_baseline() {
    if [[ ! -f "$BASE_DIR/puertos-escucha.baseline" ]]; then
        echo "[!] No hay baseline creado. Ejecutar primero: $0 crear"
        exit 1
    fi

    echo "=== VERIFICACIÓN CONTRA BASELINE ==="
    echo "Baseline creado: $(cat "$BASE_DIR/baseline-timestamp.txt" 2>/dev/null)"
    echo "Verificación: $(date -Iseconds)"
    echo ""

    DEVIATIONS=0

    # 1. Puertos nuevos
    echo "── Puertos en escucha ──"
    CURRENT=$(mktemp)
    ss -tlnp | awk 'NR>1 {print $4}' | sort > "$CURRENT"
    NEW_PORTS=$(comm -13 "$BASE_DIR/puertos-escucha.baseline" "$CURRENT" 2>/dev/null)
    REMOVED_PORTS=$(comm -23 "$BASE_DIR/puertos-escucha.baseline" "$CURRENT" 2>/dev/null)
    if [[ -n "$NEW_PORTS" ]]; then
        echo "  [ALERTA] Puertos NUEVOS detectados:"
        echo "$NEW_PORTS" | while read -r p; do echo "    + $p"; done
        DEVIATIONS=$((DEVIATIONS + $(echo "$NEW_PORTS" | wc -l)))
    fi
    if [[ -n "$REMOVED_PORTS" ]]; then
        echo "  [AVISO] Puertos ELIMINADOS:"
        echo "$REMOVED_PORTS" | while read -r p; do echo "    - $p"; done
    fi
    [[ -z "$NEW_PORTS" ]] && [[ -z "$REMOVED_PORTS" ]] && echo "  [OK] Sin cambios"
    rm -f "$CURRENT"

    # 2. Servicios nuevos
    echo ""
    echo "── Servicios habilitados ──"
    CURRENT=$(mktemp)
    systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null | \
        awk 'NR>1 && NF>1 {print $1}' | sort > "$CURRENT"
    NEW_SVCS=$(comm -13 "$BASE_DIR/servicios-habilitados.baseline" "$CURRENT" 2>/dev/null)
    if [[ -n "$NEW_SVCS" ]]; then
        echo "  [ALERTA] Servicios NUEVOS habilitados:"
        echo "$NEW_SVCS" | while read -r s; do echo "    + $s"; done
        DEVIATIONS=$((DEVIATIONS + $(echo "$NEW_SVCS" | wc -l)))
    else
        echo "  [OK] Sin cambios"
    fi
    rm -f "$CURRENT"

    # 3. Usuarios nuevos
    echo ""
    echo "── Usuarios del sistema ──"
    CURRENT=$(mktemp)
    awk -F: '{print $1":"$3":"$7}' /etc/passwd | sort > "$CURRENT"
    NEW_USERS=$(comm -13 "$BASE_DIR/usuarios.baseline" "$CURRENT" 2>/dev/null)
    if [[ -n "$NEW_USERS" ]]; then
        echo "  [ALERTA] Usuarios NUEVOS detectados:"
        echo "$NEW_USERS" | while read -r u; do echo "    + $u"; done
        DEVIATIONS=$((DEVIATIONS + $(echo "$NEW_USERS" | wc -l)))
    else
        echo "  [OK] Sin cambios"
    fi
    rm -f "$CURRENT"

    # 4. SUID nuevos
    echo ""
    echo "── Binarios SUID/SGID ──"
    CURRENT=$(mktemp)
    find / -maxdepth 5 -perm /6000 -type f 2>/dev/null | sort > "$CURRENT"
    NEW_SUID=$(comm -13 "$BASE_DIR/suid-sgid.baseline" "$CURRENT" 2>/dev/null)
    if [[ -n "$NEW_SUID" ]]; then
        echo "  [CRÍTICO] Binarios SUID/SGID NUEVOS:"
        echo "$NEW_SUID" | while read -r b; do echo "    + $b"; done
        DEVIATIONS=$((DEVIATIONS + $(echo "$NEW_SUID" | wc -l)))
    else
        echo "  [OK] Sin cambios"
    fi
    rm -f "$CURRENT"

    # 5. Destinos nuevos
    echo ""
    echo "── Destinos de conexiones salientes ──"
    CURRENT=$(mktemp)
    ss -tn state established 2>/dev/null | awk 'NR>1 {print $5}' | \
        grep -oP '\d+\.\d+\.\d+\.\d+' | sort -u > "$CURRENT"
    NEW_DESTS=$(comm -13 "$BASE_DIR/destinos-salientes.baseline" "$CURRENT" 2>/dev/null)
    if [[ -n "$NEW_DESTS" ]]; then
        echo "  [AVISO] Destinos NUEVOS de conexiones:"
        echo "$NEW_DESTS" | while read -r d; do echo "    + $d"; done
    else
        echo "  [OK] Sin destinos nuevos"
    fi
    rm -f "$CURRENT"

    # Resumen
    echo ""
    echo "════════════════════════════════════════════"
    if [[ $DEVIATIONS -eq 0 ]]; then
        echo "Sin desviaciones del baseline. Sistema estable."
    else
        echo "DESVIACIONES DETECTADAS: $DEVIATIONS"
        echo "Investigar cada desviación antes de actualizar el baseline."
        logger -t security-baseline "ALERTA: $DEVIATIONS desviaciones del baseline detectadas"
    fi
}

case "$ACTION" in
    crear)    crear_baseline ;;
    verificar) verificar_baseline ;;
    *)
        echo "Uso: $0 {crear|verificar}"
        echo "  crear    - Crear baseline del sistema actual (ejecutar en sistema limpio)"
        echo "  verificar - Comparar estado actual contra el baseline"
        ;;
esac
EOFBASE

    chmod 700 /usr/local/bin/security-baseline.sh
    log_change "Creado" "/usr/local/bin/security-baseline.sh"
    log_change "Permisos" "/usr/local/bin/security-baseline.sh -> 700"
    log_info "Baseline instalado: /usr/local/bin/security-baseline.sh"
    echo -e "${DIM}Crear: security-baseline.sh crear${NC}"
    echo -e "${DIM}Verificar: security-baseline.sh verificar${NC}"

else
    log_skip "Baseline de comportamiento del sistema"
    log_warn "Baseline no instalado"
fi

# ============================================================
log_section "4. HEALTH CHECK DE CONTROLES DE SEGURIDAD"
# ============================================================

echo "Script que verifica periódicamente que todos los controles"
echo "de seguridad están operativos y configurados correctamente."
echo ""

if check_executable /usr/local/bin/security-healthcheck.sh; then
    log_already "Health check de controles de seguridad (security-healthcheck.sh)"
elif ask "¿Instalar health check de controles?"; then

    cat > /usr/local/bin/security-healthcheck.sh << 'EOFHC'
#!/bin/bash
# ============================================================
# HEALTH CHECK DE CONTROLES DE SEGURIDAD
# Verifica que todo funciona correctamente
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

HC_DIR="/var/lib/security-monitoring/healthchecks"
mkdir -p "$HC_DIR"
REPORT="$HC_DIR/healthcheck-$(date +%Y%m%d-%H%M%S).txt"

PASS=0
FAIL=0
WARN=0

hc_pass() { echo "  [OK]   $1" | tee -a "$REPORT"; ((PASS++)); }
hc_fail() { echo "  [FAIL] $1" | tee -a "$REPORT"; ((FAIL++)); }
hc_warn() { echo "  [WARN] $1" | tee -a "$REPORT"; ((WARN++)); }

echo "=== HEALTH CHECK DE CONTROLES DE SEGURIDAD ===" | tee "$REPORT"
echo "Fecha: $(date -Iseconds)" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# ── Servicios críticos ──
echo "── Servicios Críticos ──" | tee -a "$REPORT"
for svc in firewalld auditd sshd; do
    if systemctl is-active "$svc" &>/dev/null; then
        hc_pass "$svc activo"
    else
        hc_fail "$svc NO activo"
    fi
done

for svc in fail2ban apparmor suricata clamd; do
    if systemctl is-enabled "$svc" &>/dev/null 2>&1; then
        if systemctl is-active "$svc" &>/dev/null; then
            hc_pass "$svc activo"
        else
            hc_fail "$svc habilitado pero inactivo"
        fi
    fi
done

# ── Reglas auditd ──
echo "" | tee -a "$REPORT"
echo "── Reglas Auditd ──" | tee -a "$REPORT"
for rules_file in /etc/audit/rules.d/6*.rules; do
    if [[ -f "$rules_file" ]]; then
        RULE_COUNT=$(grep -c "^-" "$rules_file" 2>/dev/null || echo 0)
        if [[ $RULE_COUNT -gt 0 ]]; then
            hc_pass "$(basename "$rules_file") ($RULE_COUNT reglas)"
        else
            hc_warn "$(basename "$rules_file") vacío"
        fi
    fi
done

ACTIVE_RULES=$(auditctl -l 2>/dev/null | wc -l)
if [[ $ACTIVE_RULES -gt 10 ]]; then
    hc_pass "Auditd tiene $ACTIVE_RULES reglas activas"
else
    hc_warn "Auditd solo tiene $ACTIVE_RULES reglas activas (esperadas >10)"
fi

# ── Scripts de detección ──
echo "" | tee -a "$REPORT"
echo "── Scripts de Detección ──" | tee -a "$REPORT"
for script in /usr/local/bin/detectar-*.sh /usr/local/bin/monitorear-*.sh /usr/local/bin/buscar-credenciales.sh /usr/local/bin/watchdog-seguridad.sh; do
    if [[ -x "$script" ]]; then
        hc_pass "$(basename "$script") ejecutable"
    fi
done

# ── Cron jobs de seguridad ──
echo "" | tee -a "$REPORT"
echo "── Cron Jobs ──" | tee -a "$REPORT"
for cron_script in /etc/cron.daily/detectar-* /etc/cron.daily/monitorear-* /etc/cron.weekly/detectar-*; do
    if [[ -x "$cron_script" ]]; then
        hc_pass "$(basename "$cron_script")"
    fi
done

# ── Firewall ──
echo "" | tee -a "$REPORT"
echo "── Firewall ──" | tee -a "$REPORT"
if command -v firewall-cmd &>/dev/null; then
    ZONE=$(firewall-cmd --get-default-zone 2>/dev/null || echo "desconocido")
elif command -v ufw &>/dev/null; then
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        ZONE="ufw-activo"
    else
        ZONE="ufw-inactivo"
    fi
else
    ZONE="desconocido"
fi
if [[ "$ZONE" != "drop" ]] && [[ "$ZONE" != "desconocido" ]]; then
    hc_pass "Zona por defecto: $ZONE"
else
    if [[ "$ZONE" == "drop" ]]; then
        hc_warn "Zona por defecto es 'drop' - posible aislamiento activo"
    else
        hc_fail "No se pudo determinar zona del firewall"
    fi
fi

# ── Sysctl de seguridad ──
echo "" | tee -a "$REPORT"
echo "── Kernel (sysctl) ──" | tee -a "$REPORT"

check_sysctl() {
    local key="$1"
    local expected="$2"
    local desc="$3"
    local actual
    actual=$(sysctl -n "$key" 2>/dev/null)
    if [[ "$actual" == "$expected" ]]; then
        hc_pass "$desc ($key=$actual)"
    else
        hc_warn "$desc ($key=$actual, esperado $expected)"
    fi
}

check_sysctl "kernel.kptr_restrict" "2" "Punteros kernel ocultos"
check_sysctl "kernel.yama.ptrace_scope" "2" "Ptrace restringido"
check_sysctl "net.ipv4.conf.all.rp_filter" "1" "Reverse path filtering"
check_sysctl "net.ipv4.tcp_syncookies" "1" "SYN cookies"
check_sysctl "kernel.randomize_va_space" "2" "ASLR"

# ── Permisos críticos ──
echo "" | tee -a "$REPORT"
echo "── Permisos de Archivos Críticos ──" | tee -a "$REPORT"

check_perms() {
    local file="$1"
    local expected="$2"
    if [[ -f "$file" ]]; then
        local actual
        actual=$(stat -c "%a" "$file" 2>/dev/null)
        if [[ "$actual" == "$expected" ]]; then
            hc_pass "$file permisos $actual"
        else
            hc_warn "$file permisos $actual (esperado $expected)"
        fi
    fi
}

check_perms "/etc/shadow" "000"
check_perms "/etc/ssh/sshd_config" "600"
check_perms "/etc/sudoers" "440"

# ── Disco ──
echo "" | tee -a "$REPORT"
echo "── Espacio en Disco ──" | tee -a "$REPORT"
DISK_USE=$(df / 2>/dev/null | awk 'NR==2 {print $5}' | tr -d '%')
if [[ "$DISK_USE" -lt 80 ]]; then
    hc_pass "Disco root al ${DISK_USE}%"
elif [[ "$DISK_USE" -lt 90 ]]; then
    hc_warn "Disco root al ${DISK_USE}% (>80%)"
else
    hc_fail "Disco root al ${DISK_USE}% (>90%)"
fi

LOG_SIZE=$(du -sm /var/log/ 2>/dev/null | awk '{print $1}')
if [[ "${LOG_SIZE:-0}" -lt 1000 ]]; then
    hc_pass "Logs: ${LOG_SIZE}MB"
else
    hc_warn "Logs: ${LOG_SIZE}MB (>1GB)"
fi

# ── Resumen ──
echo "" | tee -a "$REPORT"
echo "════════════════════════════════════════════" | tee -a "$REPORT"
TOTAL=$((PASS + FAIL + WARN))
echo "Resultado: $PASS/$TOTAL OK | $WARN advertencias | $FAIL fallos" | tee -a "$REPORT"

if [[ $FAIL -eq 0 ]]; then
    echo "Estado: SALUDABLE" | tee -a "$REPORT"
else
    echo "Estado: REQUIERE ATENCIÓN ($FAIL controles fallidos)" | tee -a "$REPORT"
    logger -t security-healthcheck "ALERTA: $FAIL controles de seguridad fallidos"
fi
echo "Reporte: $REPORT"
EOFHC

    chmod 700 /usr/local/bin/security-healthcheck.sh
    log_change "Creado" "/usr/local/bin/security-healthcheck.sh"
    log_change "Permisos" "/usr/local/bin/security-healthcheck.sh -> 700"
    log_info "Health check instalado: /usr/local/bin/security-healthcheck.sh"

    # Cron job diario para health check
    cat > /etc/cron.daily/security-healthcheck << 'EOFHCCRON'
#!/bin/bash
/usr/local/bin/security-healthcheck.sh > /var/log/security-healthcheck-latest.txt 2>&1
# Alertar si hay fallos
if grep -q "\[FAIL\]" /var/log/security-healthcheck-latest.txt 2>/dev/null; then
    logger -t security-healthcheck "Health check diario: Se detectaron FALLOS en controles de seguridad"
fi
EOFHCCRON

    chmod 700 /etc/cron.daily/security-healthcheck
    log_change "Creado" "/etc/cron.daily/security-healthcheck"
    log_change "Permisos" "/etc/cron.daily/security-healthcheck -> 700"
    log_info "Health check diario programado en cron.daily"

else
    log_skip "Health check de controles de seguridad"
    log_warn "Health check no instalado"
fi

# ============================================================
log_section "5. DIGEST DE SEGURIDAD PERIÓDICO"
# ============================================================

echo "Genera un resumen diario de seguridad consolidando toda"
echo "la información de alertas, healthcheck, y estado del sistema"
echo "en un único reporte legible."
echo ""

if check_executable /usr/local/bin/security-digest.sh; then
    log_already "Digest de seguridad periódico (security-digest.sh)"
elif ask "¿Instalar digest de seguridad periódico?"; then

    cat > /usr/local/bin/security-digest.sh << 'EOFDIGEST'
#!/bin/bash
# ============================================================
# DIGEST DE SEGURIDAD PERIÓDICO
# Resumen consolidado de las últimas 24 horas
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

DIGEST_DIR="/var/lib/security-monitoring/digests"
mkdir -p "$DIGEST_DIR"
DIGEST="$DIGEST_DIR/digest-$(date +%Y%m%d).txt"

echo "╔════════════════════════════════════════════════════════╗" | tee "$DIGEST"
echo "║     DIGEST DE SEGURIDAD - $(date '+%Y-%m-%d')                    ║" | tee -a "$DIGEST"
echo "║     $(hostname) ($(uname -r))                         ║" | tee -a "$DIGEST"
echo "╚════════════════════════════════════════════════════════╝" | tee -a "$DIGEST"
echo "" | tee -a "$DIGEST"

# ── 1. Estado general ──
echo "=== 1. ESTADO GENERAL ===" | tee -a "$DIGEST"
echo "" | tee -a "$DIGEST"
echo "  Uptime: $(uptime -p)" | tee -a "$DIGEST"
echo "  Usuarios logueados: $(who | wc -l)" | tee -a "$DIGEST"
echo "  Carga: $(cat /proc/loadavg | awk '{print $1, $2, $3}')" | tee -a "$DIGEST"
echo "  Disco /: $(df -h / | awk 'NR==2 {print $5 " usado (" $3 "/" $2 ")"}')" | tee -a "$DIGEST"
echo "" | tee -a "$DIGEST"

# ── 2. Servicios de seguridad ──
echo "=== 2. SERVICIOS DE SEGURIDAD ===" | tee -a "$DIGEST"
echo "" | tee -a "$DIGEST"
for svc in firewalld auditd fail2ban sshd apparmor suricata clamd; do
    if systemctl is-enabled "$svc" &>/dev/null 2>&1; then
        STATUS=$(systemctl is-active "$svc" 2>/dev/null)
        echo "  $svc: $STATUS" | tee -a "$DIGEST"
    fi
done
echo "" | tee -a "$DIGEST"

# ── 3. Alertas de seguridad (24h) ──
echo "=== 3. ALERTAS DE SEGURIDAD (24h) ===" | tee -a "$DIGEST"
echo "" | tee -a "$DIGEST"

# SSH
SSH_FAIL=$(journalctl -u sshd --since "24 hours ago" --no-pager 2>/dev/null | grep -ci "failed\|invalid" || echo 0)
SSH_OK=$(journalctl -u sshd --since "24 hours ago" --no-pager 2>/dev/null | grep -ci "accepted" || echo 0)
echo "  SSH: $SSH_OK logins exitosos, $SSH_FAIL intentos fallidos" | tee -a "$DIGEST"

# Fail2ban
F2B=$(journalctl -u fail2ban --since "24 hours ago" --no-pager 2>/dev/null | grep -c "Ban" || echo 0)
echo "  Fail2ban: $F2B IPs baneadas" | tee -a "$DIGEST"

# Firewall
FW=$(journalctl --since "24 hours ago" --no-pager 2>/dev/null | grep -c "REJECT\|DROP" || echo 0)
echo "  Firewall: $FW paquetes rechazados" | tee -a "$DIGEST"

# Suricata
if [[ -f /var/log/suricata/fast.log ]]; then
    SURI=$(grep "$(date +%m/%d/%Y)" /var/log/suricata/fast.log 2>/dev/null | wc -l || echo 0)
    echo "  Suricata: $SURI alertas IDS" | tee -a "$DIGEST"
fi

# Scripts de detección
DET=$(journalctl --since "24 hours ago" --no-pager 2>/dev/null | grep -ciE "ALERTA.*detectar-|SOSPECHOSO" || echo 0)
echo "  Scripts detección: $DET alertas" | tee -a "$DIGEST"

echo "" | tee -a "$DIGEST"

# ── 4. Cambios en el sistema (24h) ──
echo "=== 4. CAMBIOS EN EL SISTEMA (24h) ===" | tee -a "$DIGEST"
echo "" | tee -a "$DIGEST"

# Archivos de configuración modificados
ETC_CHANGES=$(find /etc -maxdepth 2 -mtime -1 -type f 2>/dev/null | wc -l)
echo "  Archivos en /etc modificados: $ETC_CHANGES" | tee -a "$DIGEST"

# Usuarios creados/modificados
PASSWD_MOD=$(stat -c %Y /etc/passwd 2>/dev/null)
PASSWD_AGO=$(( $(date +%s) - ${PASSWD_MOD:-0} ))
if [[ $PASSWD_AGO -lt 86400 ]]; then
    echo "  [!] /etc/passwd modificado en las últimas 24h" | tee -a "$DIGEST"
fi

# Paquetes actualizados
ZYPPER_LOG=$(journalctl --since "24 hours ago" --no-pager 2>/dev/null | grep -c "zypper.*install\|zypper.*update" || echo 0)
echo "  Operaciones zypper: $ZYPPER_LOG" | tee -a "$DIGEST"

# Servicios nuevos
NEW_SVCS=$(find /etc/systemd/system/ -maxdepth 1 -name "*.service" -mtime -1 -type f 2>/dev/null | wc -l)
if [[ $NEW_SVCS -gt 0 ]]; then
    echo "  [!] $NEW_SVCS servicios systemd nuevos/modificados" | tee -a "$DIGEST"
fi

echo "" | tee -a "$DIGEST"

# ── 5. Top IPs sospechosas ──
echo "=== 5. TOP IPs SOSPECHOSAS ===" | tee -a "$DIGEST"
echo "" | tee -a "$DIGEST"

# IPs con más intentos SSH fallidos
journalctl -u sshd --since "24 hours ago" --no-pager 2>/dev/null | \
    grep -iE "failed|invalid" | \
    grep -oP '\d+\.\d+\.\d+\.\d+' | \
    sort | uniq -c | sort -rn | head -5 | \
    while read -r count ip; do
        echo "  $count intentos - $ip" | tee -a "$DIGEST"
    done

echo "" | tee -a "$DIGEST"

# ── 6. Health check rápido ──
echo "=== 6. HEALTH CHECK RÁPIDO ===" | tee -a "$DIGEST"
echo "" | tee -a "$DIGEST"

HC_PASS=0
HC_FAIL=0

quick_check() {
    local desc="$1"
    local cmd="$2"
    if eval "$cmd" &>/dev/null; then
        echo "  [OK] $desc" | tee -a "$DIGEST"
        ((HC_PASS++))
    else
        echo "  [!!] $desc" | tee -a "$DIGEST"
        ((HC_FAIL++))
    fi
}

quick_check "Firewall activo" "systemctl is-active firewalld"
quick_check "Auditd activo" "systemctl is-active auditd"
quick_check "Sin UID=0 extra" "test \$(awk -F: '\$3==0' /etc/passwd | wc -l) -eq 1"
quick_check "Sin ejecutables en /tmp" "test -z \"\$(find /tmp -maxdepth 2 -type f -executable 2>/dev/null | head -1)\""
quick_check "ASLR activo" "test \$(sysctl -n kernel.randomize_va_space 2>/dev/null) = '2'"
quick_check "Logs de audit presentes" "test -f /var/log/audit/audit.log"

echo "" | tee -a "$DIGEST"
echo "  Resultado: $HC_PASS OK, $HC_FAIL alertas" | tee -a "$DIGEST"

echo "" | tee -a "$DIGEST"
echo "════════════════════════════════════════════════════════" | tee -a "$DIGEST"
echo "Digest guardado: $DIGEST" | tee -a "$DIGEST"
echo "Para más detalle: security-dashboard.sh" | tee -a "$DIGEST"
EOFDIGEST

    chmod 700 /usr/local/bin/security-digest.sh
    log_change "Creado" "/usr/local/bin/security-digest.sh"
    log_change "Permisos" "/usr/local/bin/security-digest.sh -> 700"
    log_info "Digest instalado: /usr/local/bin/security-digest.sh"

    # Timer systemd para digest diario
    cat > /etc/systemd/system/security-digest.service << 'EOFSVCDIG'
[Unit]
Description=Digest diario de seguridad
After=network.target auditd.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/security-digest.sh
StandardOutput=journal
StandardError=journal
EOFSVCDIG

    cat > /etc/systemd/system/security-digest.timer << 'EOFTMRDIG'
[Unit]
Description=Ejecutar digest de seguridad diariamente

[Timer]
OnCalendar=*-*-* 06:00:00
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
EOFTMRDIG

    log_change "Creado" "/etc/systemd/system/security-digest.service"
    log_change "Creado" "/etc/systemd/system/security-digest.timer"

    systemctl daemon-reload 2>/dev/null
    log_change "Aplicado" "systemctl daemon-reload"
    systemctl enable security-digest.timer 2>/dev/null
    log_change "Servicio" "security-digest.timer enable"
    systemctl start security-digest.timer 2>/dev/null
    log_change "Servicio" "security-digest.timer start"
    log_info "Timer de digest diario activado (06:00)"

else
    log_skip "Digest de seguridad periódico"
    log_warn "Digest no instalado"
fi

# ============================================================
log_section "RESUMEN DE MONITORIZACIÓN CONTINUA"
# ============================================================

echo ""
echo -e "${BOLD}Herramientas de monitorización instaladas:${NC}"
echo ""

if [[ -x /usr/local/bin/security-dashboard.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} Dashboard de seguridad (security-dashboard.sh)"
else
    echo -e "  ${YELLOW}[--]${NC} Dashboard no instalado"
fi

if [[ -x /usr/local/bin/correlacionar-alertas.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} Correlación de alertas (correlacionar-alertas.sh)"
else
    echo -e "  ${YELLOW}[--]${NC} Correlación no instalada"
fi

if [[ -x /usr/local/bin/security-baseline.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} Baseline de comportamiento (security-baseline.sh)"
else
    echo -e "  ${YELLOW}[--]${NC} Baseline no instalado"
fi

if [[ -x /usr/local/bin/security-healthcheck.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} Health check de controles (security-healthcheck.sh)"
else
    echo -e "  ${YELLOW}[--]${NC} Health check no instalado"
fi

if [[ -x /usr/local/bin/security-digest.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} Digest periódico (security-digest.sh)"
else
    echo -e "  ${YELLOW}[--]${NC} Digest no instalado"
fi

echo ""
echo -e "${BOLD}Uso rápido:${NC}"
echo -e "  ${DIM}Ver estado:${NC}      security-dashboard.sh"
echo -e "  ${DIM}Correlacionar:${NC}   correlacionar-alertas.sh 24"
echo -e "  ${DIM}Crear baseline:${NC}  security-baseline.sh crear"
echo -e "  ${DIM}Verificar:${NC}       security-baseline.sh verificar"
echo -e "  ${DIM}Health check:${NC}    security-healthcheck.sh"
echo -e "  ${DIM}Digest diario:${NC}   security-digest.sh"
echo ""
show_changes_summary
log_info "Módulo de monitorización continua completado"
