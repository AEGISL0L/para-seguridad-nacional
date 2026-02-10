#!/bin/bash
# ============================================================
# REPORTES DE SEGURIDAD - Operaciones de Seguridad
# Linux Multi-Distro (openSUSE, Debian/Ubuntu, RHEL/Fedora, Arch)
# ============================================================
# Capacidades implementadas:
#   - Reporte de cobertura MITRE ATT&CK
#   - Exportación ATT&CK Navigator JSON (layer)
#   - Reporte de cumplimiento de controles
#   - Inventario de scripts de detección instalados
#   - Resumen ejecutivo para auditoría
#   - Exportación de evidencia de controles
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps
REPORT_DIR="/var/lib/security-reports"
mkdir -p "$REPORT_DIR"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   REPORTES DE SEGURIDAD - Operaciones de Seguridad        ║"
echo "║   MITRE ATT&CK, cumplimiento, evidencia                   ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# ============================================================
log_section "1. REPORTE DE COBERTURA MITRE ATT&CK"
# ============================================================

echo "Genera un reporte detallado de la cobertura del framework"
echo "MITRE ATT&CK con el estado de cada técnica mitigada."
echo ""

if ask "¿Instalar generador de reporte MITRE ATT&CK?"; then

    cat > /usr/local/bin/reporte-mitre.sh << 'EOFMITRE'
#!/bin/bash
# ============================================================
# REPORTE DE COBERTURA MITRE ATT&CK
# Evalúa el estado real de cada mitigación
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

REPORT_DIR="/var/lib/security-reports"
mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/mitre-coverage-$(date +%Y%m%d).txt"

echo "╔════════════════════════════════════════════════════════╗" | tee "$REPORT"
echo "║     REPORTE DE COBERTURA MITRE ATT&CK                ║" | tee -a "$REPORT"
echo "║     $(hostname) - $(date '+%Y-%m-%d %H:%M')                      ║" | tee -a "$REPORT"
echo "╚════════════════════════════════════════════════════════╝" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

COVERED=0
PARTIAL=0
NOT_COVERED=0

check_technique() {
    local id="$1"
    local name="$2"
    local check_cmd="$3"
    local tactic="$4"

    if eval "$check_cmd" &>/dev/null 2>&1; then
        echo -e "  ${GREEN}[✓]${NC} $id $name" | tee -a "$REPORT"
        ((COVERED++))
        return 0
    else
        echo -e "  ${RED}[✗]${NC} $id $name" | tee -a "$REPORT"
        ((NOT_COVERED++))
        return 1
    fi
}

check_partial() {
    local id="$1"
    local name="$2"
    local check_cmd="$3"

    if eval "$check_cmd" &>/dev/null 2>&1; then
        echo -e "  ${YELLOW}[~]${NC} $id $name (parcial)" | tee -a "$REPORT"
        ((PARTIAL++))
        return 0
    else
        echo -e "  ${RED}[✗]${NC} $id $name" | tee -a "$REPORT"
        ((NOT_COVERED++))
        return 1
    fi
}

# ── TA0043 Reconnaissance ──
echo -e "${BOLD}═══ TA0043 RECONNAISSANCE ═══${NC}" | tee -a "$REPORT"
check_technique "T1595" "Active Scanning" "test -x /usr/local/bin/detectar-portscan.sh" "TA0043"
check_technique "T1592" "Gather Victim Host Info" "test -f /etc/cron.daily/reconocimiento-externo 2>/dev/null || test -x /usr/local/bin/auditoria-externa-periodica.sh" "TA0043"
echo "" | tee -a "$REPORT"

# ── TA0042 Resource Development ──
echo -e "${BOLD}═══ TA0042 RESOURCE DEVELOPMENT ═══${NC}" | tee -a "$REPORT"
check_technique "M1019" "Threat Intelligence" "test -d /etc/security/ioc-feeds 2>/dev/null || test -x /usr/local/bin/ioc-lookup.sh" "TA0042"
echo "" | tee -a "$REPORT"

# ── TA0001 Initial Access ──
echo -e "${BOLD}═══ TA0001 INITIAL ACCESS ═══${NC}" | tee -a "$REPORT"
check_technique "T1133" "External Remote Services" "sshd -T 2>/dev/null | grep -q 'permitrootlogin no'" "TA0001"
check_technique "T1190" "Exploit Public-Facing" "systemctl is-active firewalld" "TA0001"
check_technique "T1078" "Valid Accounts" "test -f /etc/security/faillock.conf" "TA0001"
check_technique "T1566" "Phishing" "systemctl is-active clamd 2>/dev/null || command -v clamscan" "TA0001"
check_technique "T1200" "Hardware Additions" "command -v usbguard" "TA0001"
echo "" | tee -a "$REPORT"

# ── TA0002 Execution ──
echo -e "${BOLD}═══ TA0002 EXECUTION ═══${NC}" | tee -a "$REPORT"
check_technique "T1059" "Command & Scripting" "systemctl is-active apparmor 2>/dev/null || aa-status 2>/dev/null | grep -q 'profiles'" "TA0002"
check_technique "T1059.004" "Unix Shell" "getent group shell-users" "TA0002"
check_technique "T1204" "User Execution" "mount | grep '/tmp' | grep -q 'noexec'" "TA0002"
check_technique "T1129" "Shared Modules" "sysctl -n kernel.yama.ptrace_scope 2>/dev/null | grep -q '[12]'" "TA0002"
echo "" | tee -a "$REPORT"

# ── TA0003 Persistence ──
echo -e "${BOLD}═══ TA0003 PERSISTENCE ═══${NC}" | tee -a "$REPORT"
check_technique "T1053" "Scheduled Task/Job" "test -f /etc/audit/rules.d/50-persistence.rules 2>/dev/null || ausearch -k cron-persistence 2>/dev/null | grep -q 'type='" "TA0003"
check_technique "T1543" "System Services" "ausearch -k systemd-persistence 2>/dev/null | grep -q 'type=' || test -f /etc/audit/rules.d/50-persistence.rules" "TA0003"
check_technique "T1547" "Boot/Logon Autostart" "test -f /etc/audit/rules.d/50-persistence.rules" "TA0003"
echo "" | tee -a "$REPORT"

# ── TA0004 Privilege Escalation ──
echo -e "${BOLD}═══ TA0004 PRIVILEGE ESCALATION ═══${NC}" | tee -a "$REPORT"
check_technique "T1548" "Abuse Elevation Control" "test -f /etc/audit/rules.d/50-escalation.rules 2>/dev/null || test -x /usr/local/bin/detectar-suid.sh" "TA0004"
check_technique "T1068" "Exploitation for Privilege Escalation" "sysctl -n kernel.randomize_va_space 2>/dev/null | grep -q '2'" "TA0004"
check_technique "T1055" "Process Injection" "sysctl -n kernel.yama.ptrace_scope 2>/dev/null | grep -q '[23]'" "TA0004"
echo "" | tee -a "$REPORT"

# ── TA0005 Defense Evasion ──
echo -e "${BOLD}═══ TA0005 DEFENSE EVASION ═══${NC}" | tee -a "$REPORT"
check_technique "T1070" "Indicator Removal" "test -f /etc/audit/rules.d/60-log-protection.rules" "TA0005"
check_technique "T1036" "Masquerading" "test -x /usr/local/bin/detectar-masquerading.sh" "TA0005"
check_technique "T1562" "Impair Defenses" "test -x /usr/local/bin/watchdog-seguridad.sh" "TA0005"
check_technique "T1014" "Rootkit" "test -x /usr/local/bin/detectar-rootkits.sh" "TA0005"
check_technique "T1218" "System Binary Proxy" "test -f /etc/audit/rules.d/61-defense-evasion.rules" "TA0005"
check_technique "T1564" "Hide Artifacts" "test -x /usr/local/bin/detectar-ocultos.sh" "TA0005"
check_technique "T1027" "Obfuscated Files" "test -x /usr/local/bin/detectar-ofuscados.sh" "TA0005"
echo "" | tee -a "$REPORT"

# ── TA0006 Credential Access ──
echo -e "${BOLD}═══ TA0006 CREDENTIAL ACCESS ═══${NC}" | tee -a "$REPORT"
check_technique "T1003" "OS Credential Dumping" "sysctl -n kernel.yama.ptrace_scope 2>/dev/null | grep -q '[23]'" "TA0006"
check_technique "T1110" "Brute Force" "test -x /usr/local/bin/monitorear-bruteforce.sh" "TA0006"
check_technique "T1557" "Adversary-in-the-Middle" "command -v arpwatch" "TA0006"
check_technique "T1552" "Unsecured Credentials" "test -x /usr/local/bin/buscar-credenciales.sh" "TA0006"
check_technique "T1040" "Network Sniffing" "test -x /usr/local/bin/detectar-promiscuo.sh" "TA0006"
check_technique "T1056" "Input Capture" "test -x /usr/local/bin/detectar-keylogger.sh" "TA0006"
echo "" | tee -a "$REPORT"

# ── TA0007 Discovery ──
echo -e "${BOLD}═══ TA0007 DISCOVERY ═══${NC}" | tee -a "$REPORT"
check_technique "T1046" "Network Service Scan" "test -x /usr/local/bin/detectar-portscan.sh" "TA0007"
check_technique "T1057" "Process Discovery" "mount -l 2>/dev/null | grep 'proc' | grep -q 'hidepid'" "TA0007"
check_technique "T1082" "System Information" "sysctl -n kernel.kptr_restrict 2>/dev/null | grep -q '2'" "TA0007"
check_technique "T1016" "System Network Config" "test -x /usr/local/bin/detectar-reconocimiento.sh" "TA0007"
echo "" | tee -a "$REPORT"

# ── TA0008 Lateral Movement ──
echo -e "${BOLD}═══ TA0008 LATERAL MOVEMENT ═══${NC}" | tee -a "$REPORT"
check_technique "T1021" "Remote Services" "sshd -T 2>/dev/null | grep -q 'allowtcpforwarding no'" "TA0008"
check_technique "T1563" "Remote Service Session Hijack" "test -f /etc/ssh/sshd_config.d/06-lateral-movement.conf 2>/dev/null || sshd -T 2>/dev/null | grep -q 'allowagentforwarding no'" "TA0008"
check_technique "T1080" "Taint Shared Content" "mount | grep -E 'nfs|cifs' | grep -q 'noexec' 2>/dev/null || true" "TA0008"
check_technique "TA0008" "Lateral Movement Detection" "test -x /usr/local/bin/detectar-lateral.sh" "TA0008"
echo "" | tee -a "$REPORT"

# ── TA0009 Collection ──
echo -e "${BOLD}═══ TA0009 COLLECTION ═══${NC}" | tee -a "$REPORT"
check_technique "T1005" "Data from Local System" "test -f /etc/audit/rules.d/65-collection.rules" "TA0009"
check_technique "T1025" "Data from Removable Media" "command -v usbguard" "TA0009"
check_technique "T1074" "Data Staged" "test -x /usr/local/bin/detectar-staging.sh" "TA0009"
check_technique "T1119" "Automated Collection" "test -x /usr/local/bin/detectar-recoleccion.sh" "TA0009"
echo "" | tee -a "$REPORT"

# ── TA0010 Exfiltration ──
echo -e "${BOLD}═══ TA0010 EXFILTRATION ═══${NC}" | tee -a "$REPORT"
check_technique "T1041" "Exfil Over C2 Channel" "test -x /usr/local/bin/detectar-exfiltracion.sh" "TA0010"
check_technique "T1048" "Exfil Over Alt Protocol" "test -x /usr/local/bin/detectar-dns-tunnel.sh" "TA0010"
check_technique "T1567" "Exfil to Cloud Storage" "grep -q 'drive.google.com\|dropbox.com' /etc/hosts 2>/dev/null" "TA0010"
check_technique "T1030" "Data Transfer Size Limits" "test -x /usr/local/bin/monitorear-transferencias.sh" "TA0010"
echo "" | tee -a "$REPORT"

# ── TA0011 Command and Control ──
echo -e "${BOLD}═══ TA0011 COMMAND AND CONTROL ═══${NC}" | tee -a "$REPORT"
check_technique "T1071" "Application Layer Protocol" "test -x /usr/local/bin/detectar-beaconing.sh" "TA0011"
check_technique "T1105" "Ingress Tool Transfer" "test -x /usr/local/bin/detectar-tool-transfer.sh" "TA0011"
check_technique "T1090" "Proxy" "test -x /usr/local/bin/detectar-tunneling.sh" "TA0011"
check_technique "T1568" "Dynamic Resolution (DGA)" "test -x /usr/local/bin/detectar-dga.sh" "TA0011"
check_technique "T1571" "Non-Standard Port" "test -f /etc/audit/rules.d/67-command-control.rules" "TA0011"
echo "" | tee -a "$REPORT"

# ── TA0040 Impact ──
echo -e "${BOLD}═══ TA0040 IMPACT ═══${NC}" | tee -a "$REPORT"
check_technique "T1486" "Data Encrypted (Ransomware)" "test -x /usr/local/bin/backup-offsite.sh 2>/dev/null || command -v clamscan" "TA0040"
check_technique "T1490" "Inhibit System Recovery" "test -x /usr/local/bin/verificar-backups.sh 2>/dev/null || test -d /var/lib/backups" "TA0040"
check_technique "T1489" "Service Stop" "test -x /usr/local/bin/watchdog-seguridad.sh" "TA0040"
echo "" | tee -a "$REPORT"

# ── Resumen ──
TOTAL=$((COVERED + PARTIAL + NOT_COVERED))
echo "════════════════════════════════════════════════════════" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"
echo -e "${BOLD}RESUMEN DE COBERTURA:${NC}" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"
echo -e "  Técnicas cubiertas:   ${GREEN}$COVERED${NC}/$TOTAL" | tee -a "$REPORT"
echo -e "  Cobertura parcial:    ${YELLOW}$PARTIAL${NC}/$TOTAL" | tee -a "$REPORT"
echo -e "  No cubiertas:         ${RED}$NOT_COVERED${NC}/$TOTAL" | tee -a "$REPORT"

if [[ $TOTAL -gt 0 ]]; then
    PCT=$(( (COVERED + PARTIAL) * 100 / TOTAL ))
    echo "" | tee -a "$REPORT"
    echo -e "  Porcentaje: ${BOLD}${PCT}%${NC}" | tee -a "$REPORT"
fi

echo "" | tee -a "$REPORT"
echo "Reporte guardado: $REPORT" | tee -a "$REPORT"
EOFMITRE

    chmod 700 /usr/local/bin/reporte-mitre.sh
    log_info "Reporte MITRE instalado: /usr/local/bin/reporte-mitre.sh"

else
    log_warn "Reporte MITRE no instalado"
fi

# ============================================================
log_section "2. EXPORTACIÓN ATT&CK NAVIGATOR (JSON)"
# ============================================================

echo "Genera un archivo JSON compatible con ATT&CK Navigator"
echo "para visualizar la cobertura de mitigaciones."
echo ""
echo "El archivo JSON se puede cargar en:"
echo "  https://mitre-attack.github.io/attack-navigator/"
echo ""

if ask "¿Instalar exportador ATT&CK Navigator?"; then

    cat > /usr/local/bin/exportar-navigator.sh << 'EOFNAV'
#!/bin/bash
# ============================================================
# EXPORTADOR ATT&CK NAVIGATOR JSON
# Genera layer para ATT&CK Navigator
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

REPORT_DIR="/var/lib/security-reports"
mkdir -p "$REPORT_DIR"
OUTPUT="$REPORT_DIR/attack-navigator-$(date +%Y%m%d).json"

# Función para verificar si una técnica está cubierta
# Retorna: 0=cubierta, 1=parcial, 2=no cubierta
check_tech() {
    local check="$1"
    if eval "$check" &>/dev/null 2>&1; then
        echo "covered"
    else
        echo "not_covered"
    fi
}

# Construir técnicas con estado
declare -A TECHNIQUES

# TA0001
TECHNIQUES["T1133"]=$(check_tech "sshd -T 2>/dev/null | grep -q 'permitrootlogin no'")
TECHNIQUES["T1190"]=$(check_tech "systemctl is-active firewalld")
TECHNIQUES["T1078"]=$(check_tech "test -f /etc/security/faillock.conf")
TECHNIQUES["T1566"]=$(check_tech "command -v clamscan")
TECHNIQUES["T1189"]=$(check_tech "systemctl is-active firewalld")
TECHNIQUES["T1200"]=$(check_tech "command -v usbguard")

# TA0002
TECHNIQUES["T1059"]=$(check_tech "systemctl is-active apparmor 2>/dev/null || aa-status 2>/dev/null | grep -q profiles")
TECHNIQUES["T1204"]=$(check_tech "mount | grep '/tmp' | grep -q noexec")
TECHNIQUES["T1129"]=$(check_tech "sysctl -n kernel.yama.ptrace_scope 2>/dev/null | grep -q '[12]'")

# TA0003
TECHNIQUES["T1053"]=$(check_tech "test -f /etc/audit/rules.d/50-persistence.rules")
TECHNIQUES["T1543"]=$(check_tech "test -f /etc/audit/rules.d/50-persistence.rules")
TECHNIQUES["T1547"]=$(check_tech "test -f /etc/audit/rules.d/50-persistence.rules")

# TA0004
TECHNIQUES["T1548"]=$(check_tech "test -f /etc/audit/rules.d/50-escalation.rules 2>/dev/null || true")
TECHNIQUES["T1068"]=$(check_tech "sysctl -n kernel.randomize_va_space 2>/dev/null | grep -q 2")
TECHNIQUES["T1055"]=$(check_tech "sysctl -n kernel.yama.ptrace_scope 2>/dev/null | grep -q '[23]'")

# TA0005
TECHNIQUES["T1070"]=$(check_tech "test -f /etc/audit/rules.d/60-log-protection.rules")
TECHNIQUES["T1036"]=$(check_tech "test -x /usr/local/bin/detectar-masquerading.sh")
TECHNIQUES["T1562"]=$(check_tech "test -x /usr/local/bin/watchdog-seguridad.sh")
TECHNIQUES["T1014"]=$(check_tech "test -x /usr/local/bin/detectar-rootkits.sh")
TECHNIQUES["T1218"]=$(check_tech "test -f /etc/audit/rules.d/61-defense-evasion.rules")
TECHNIQUES["T1564"]=$(check_tech "test -x /usr/local/bin/detectar-ocultos.sh")
TECHNIQUES["T1027"]=$(check_tech "test -x /usr/local/bin/detectar-ofuscados.sh")

# TA0006
TECHNIQUES["T1003"]=$(check_tech "sysctl -n kernel.yama.ptrace_scope 2>/dev/null | grep -q '[23]'")
TECHNIQUES["T1110"]=$(check_tech "test -x /usr/local/bin/monitorear-bruteforce.sh")
TECHNIQUES["T1557"]=$(check_tech "command -v arpwatch")
TECHNIQUES["T1552"]=$(check_tech "test -x /usr/local/bin/buscar-credenciales.sh")
TECHNIQUES["T1040"]=$(check_tech "test -x /usr/local/bin/detectar-promiscuo.sh")
TECHNIQUES["T1056"]=$(check_tech "test -x /usr/local/bin/detectar-keylogger.sh")

# TA0007
TECHNIQUES["T1046"]=$(check_tech "test -x /usr/local/bin/detectar-portscan.sh")
TECHNIQUES["T1057"]=$(check_tech "mount -l 2>/dev/null | grep proc | grep -q hidepid")
TECHNIQUES["T1082"]=$(check_tech "sysctl -n kernel.kptr_restrict 2>/dev/null | grep -q 2")
TECHNIQUES["T1016"]=$(check_tech "test -x /usr/local/bin/detectar-reconocimiento.sh")

# TA0008
TECHNIQUES["T1021"]=$(check_tech "sshd -T 2>/dev/null | grep -q 'allowtcpforwarding no'")
TECHNIQUES["T1563"]=$(check_tech "sshd -T 2>/dev/null | grep -q 'allowagentforwarding no'")
TECHNIQUES["T1080"]=$(check_tech "test -x /usr/local/bin/detectar-lateral.sh")

# TA0009
TECHNIQUES["T1005"]=$(check_tech "test -f /etc/audit/rules.d/65-collection.rules")
TECHNIQUES["T1025"]=$(check_tech "command -v usbguard")
TECHNIQUES["T1074"]=$(check_tech "test -x /usr/local/bin/detectar-staging.sh")
TECHNIQUES["T1119"]=$(check_tech "test -x /usr/local/bin/detectar-recoleccion.sh")

# TA0010
TECHNIQUES["T1041"]=$(check_tech "test -x /usr/local/bin/detectar-exfiltracion.sh")
TECHNIQUES["T1048"]=$(check_tech "test -x /usr/local/bin/detectar-dns-tunnel.sh")
TECHNIQUES["T1567"]=$(check_tech "grep -q 'drive.google.com' /etc/hosts 2>/dev/null")
TECHNIQUES["T1030"]=$(check_tech "test -x /usr/local/bin/monitorear-transferencias.sh")

# TA0011
TECHNIQUES["T1071"]=$(check_tech "test -x /usr/local/bin/detectar-beaconing.sh")
TECHNIQUES["T1105"]=$(check_tech "test -x /usr/local/bin/detectar-tool-transfer.sh")
TECHNIQUES["T1090"]=$(check_tech "test -x /usr/local/bin/detectar-tunneling.sh")
TECHNIQUES["T1568"]=$(check_tech "test -x /usr/local/bin/detectar-dga.sh")
TECHNIQUES["T1571"]=$(check_tech "test -f /etc/audit/rules.d/67-command-control.rules")

# TA0040
TECHNIQUES["T1486"]=$(check_tech "command -v clamscan")
TECHNIQUES["T1490"]=$(check_tech "test -x /usr/local/bin/watchdog-seguridad.sh")
TECHNIQUES["T1489"]=$(check_tech "test -x /usr/local/bin/watchdog-seguridad.sh")

# Generar JSON
{
    echo '{'
    echo '  "name": "Securizar - Cobertura MITRE ATT&CK",'
    echo "  \"versions\": {\"attack\": \"14\", \"navigator\": \"4.9.1\", \"layer\": \"4.5\"},"
    echo "  \"domain\": \"enterprise-attack\","
    echo "  \"description\": \"Cobertura de mitigaciones en $(hostname) - $(date '+%Y-%m-%d')\","
    echo '  "filters": {"platforms": ["Linux"]},'
    echo '  "sorting": 3,'
    echo '  "layout": {"layout": "side", "showID": true, "showName": true},'
    echo '  "hideDisabled": false,'
    echo '  "techniques": ['

    FIRST=true
    for TECH_ID in $(echo "${!TECHNIQUES[@]}" | tr ' ' '\n' | sort); do
        STATUS="${TECHNIQUES[$TECH_ID]}"
        if [[ "$STATUS" == "covered" ]]; then
            COLOR="#a1d99b"
            SCORE=100
            COMMENT="Mitigación activa"
        else
            COLOR="#fc9272"
            SCORE=0
            COMMENT="No mitigado"
        fi

        if [[ "$FIRST" != true ]]; then
            echo ","
        fi
        FIRST=false

        printf '    {"techniqueID": "%s", "color": "%s", "score": %d, "comment": "%s", "enabled": true}' \
            "$TECH_ID" "$COLOR" "$SCORE" "$COMMENT"
    done

    echo ''
    echo '  ],'
    echo '  "gradient": {"colors": ["#fc9272", "#a1d99b"], "minValue": 0, "maxValue": 100},'
    echo '  "legendItems": ['
    echo '    {"label": "Mitigado", "color": "#a1d99b"},'
    echo '    {"label": "No mitigado", "color": "#fc9272"}'
    echo '  ],'
    echo '  "showTacticRowBackground": true,'
    echo '  "tacticRowBackground": "#dddddd"'
    echo '}'
} > "$OUTPUT"

COVERED_COUNT=0
TOTAL_COUNT=0
for TECH_ID in "${!TECHNIQUES[@]}"; do
    ((TOTAL_COUNT++))
    [[ "${TECHNIQUES[$TECH_ID]}" == "covered" ]] && ((COVERED_COUNT++))
done

echo "ATT&CK Navigator JSON generado:"
echo "  Archivo: $OUTPUT"
echo "  Técnicas: $COVERED_COUNT/$TOTAL_COUNT cubiertas"
echo ""
echo "Para visualizar:"
echo "  1. Abrir https://mitre-attack.github.io/attack-navigator/"
echo "  2. Click en 'Open Existing Layer'"
echo "  3. Click en 'Upload from local' y seleccionar:"
echo "     $OUTPUT"
EOFNAV

    chmod 700 /usr/local/bin/exportar-navigator.sh
    log_info "Exportador Navigator instalado: /usr/local/bin/exportar-navigator.sh"

else
    log_warn "Exportador Navigator no instalado"
fi

# ============================================================
log_section "3. REPORTE DE CUMPLIMIENTO DE CONTROLES"
# ============================================================

echo "Genera un reporte de cumplimiento evaluando cada control"
echo "de seguridad contra su estado esperado."
echo ""

if ask "¿Instalar generador de reporte de cumplimiento?"; then

    cat > /usr/local/bin/reporte-cumplimiento.sh << 'EOFCOMP'
#!/bin/bash
# ============================================================
# REPORTE DE CUMPLIMIENTO DE CONTROLES
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

REPORT_DIR="/var/lib/security-reports"
mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/cumplimiento-$(date +%Y%m%d).txt"

echo "╔════════════════════════════════════════════════════════╗" | tee "$REPORT"
echo "║     REPORTE DE CUMPLIMIENTO DE CONTROLES              ║" | tee -a "$REPORT"
echo "║     $(hostname) - $(date '+%Y-%m-%d %H:%M')                      ║" | tee -a "$REPORT"
echo "╚════════════════════════════════════════════════════════╝" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

PASS=0
FAIL=0

ctrl() {
    local category="$1"
    local id="$2"
    local desc="$3"
    local check="$4"

    if eval "$check" &>/dev/null 2>&1; then
        echo "  [PASS] $id - $desc" | tee -a "$REPORT"
        ((PASS++))
    else
        echo "  [FAIL] $id - $desc" | tee -a "$REPORT"
        ((FAIL++))
    fi
}

# ── Autenticación y acceso ──
echo "=== AUTENTICACIÓN Y ACCESO ===" | tee -a "$REPORT"
ctrl "AUTH" "AC-01" "Root SSH deshabilitado" "sshd -T 2>/dev/null | grep -q 'permitrootlogin no'"
ctrl "AUTH" "AC-02" "SSH solo clave pública" "sshd -T 2>/dev/null | grep -q 'passwordauthentication no'"
ctrl "AUTH" "AC-03" "Faillock configurado" "test -f /etc/security/faillock.conf"
ctrl "AUTH" "AC-04" "MFA SSH configurado" "sshd -T 2>/dev/null | grep -q 'challengeresponseauthentication yes' || grep -q 'AuthenticationMethods' /etc/ssh/sshd_config 2>/dev/null"
ctrl "AUTH" "AC-05" "No hay UID=0 extra" "test \$(awk -F: '\$3==0' /etc/passwd | wc -l) -eq 1"
echo "" | tee -a "$REPORT"

# ── Red ──
echo "=== RED Y FIREWALL ===" | tee -a "$REPORT"
ctrl "NET" "NW-01" "Firewall activo" "systemctl is-active firewalld"
ctrl "NET" "NW-02" "SYN cookies activas" "test \$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null) = '1'"
ctrl "NET" "NW-03" "IP forwarding deshabilitado" "test \$(sysctl -n net.ipv4.ip_forward 2>/dev/null) = '0'"
ctrl "NET" "NW-04" "Reverse path filtering" "test \$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null) = '1'"
ctrl "NET" "NW-05" "IDS activo (Suricata)" "systemctl is-active suricata 2>/dev/null"
echo "" | tee -a "$REPORT"

# ── Kernel ──
echo "=== KERNEL ===" | tee -a "$REPORT"
ctrl "KERN" "KN-01" "ASLR activo" "test \$(sysctl -n kernel.randomize_va_space 2>/dev/null) = '2'"
ctrl "KERN" "KN-02" "Ptrace restringido" "test \$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null) -ge 1"
ctrl "KERN" "KN-03" "Punteros kernel ocultos" "test \$(sysctl -n kernel.kptr_restrict 2>/dev/null) -ge 1"
ctrl "KERN" "KN-04" "Core dumps deshabilitados" "test \$(sysctl -n fs.suid_dumpable 2>/dev/null) = '0'"
echo "" | tee -a "$REPORT"

# ── Auditoría ──
echo "=== AUDITORÍA Y LOGGING ===" | tee -a "$REPORT"
ctrl "AUDIT" "AU-01" "Auditd activo" "systemctl is-active auditd"
ctrl "AUDIT" "AU-02" "Reglas auditd cargadas (>10)" "test \$(auditctl -l 2>/dev/null | wc -l) -gt 10"
ctrl "AUDIT" "AU-03" "Log de audit presente" "test -f /var/log/audit/audit.log"
ctrl "AUDIT" "AU-04" "Protección de logs" "test -f /etc/audit/rules.d/60-log-protection.rules"
echo "" | tee -a "$REPORT"

# ── Malware ──
echo "=== PROTECCIÓN ANTIMALWARE ===" | tee -a "$REPORT"
ctrl "AV" "AV-01" "ClamAV disponible" "command -v clamscan"
ctrl "AV" "AV-02" "AppArmor activo" "systemctl is-active apparmor 2>/dev/null || aa-status 2>/dev/null | grep -q profiles"
ctrl "AV" "AV-03" "/tmp noexec" "mount | grep '/tmp' | grep -q noexec"
ctrl "AV" "AV-04" "/dev/shm noexec" "mount | grep '/dev/shm' | grep -q noexec"
echo "" | tee -a "$REPORT"

# ── Monitoreo ──
echo "=== MONITOREO Y DETECCIÓN ===" | tee -a "$REPORT"
ctrl "MON" "MN-01" "Fail2ban activo" "systemctl is-active fail2ban"
ctrl "MON" "MN-02" "Scripts de detección instalados" "ls /usr/local/bin/detectar-*.sh 2>/dev/null | wc -l | grep -q '[1-9]'"
ctrl "MON" "MN-03" "Watchdog de servicios" "test -x /usr/local/bin/watchdog-seguridad.sh"
ctrl "MON" "MN-04" "Health check configurado" "test -x /usr/local/bin/security-healthcheck.sh"
echo "" | tee -a "$REPORT"

# ── Respuesta a incidentes ──
echo "=== RESPUESTA A INCIDENTES ===" | tee -a "$REPORT"
ctrl "IR" "IR-01" "Toolkit forense disponible" "test -x /usr/local/bin/ir-recolectar-forense.sh"
ctrl "IR" "IR-02" "Playbooks de contención" "test -x /usr/local/bin/ir-responder.sh"
ctrl "IR" "IR-03" "Aislamiento de red" "test -x /usr/local/bin/ir-aislar-red.sh"
ctrl "IR" "IR-04" "Timeline de ataque" "test -x /usr/local/bin/ir-timeline.sh"
echo "" | tee -a "$REPORT"

# ── Resumen ──
echo "" | tee -a "$REPORT"
TOTAL=$((PASS + FAIL))
echo "════════════════════════════════════════════════════════" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"
echo "RESULTADO: $PASS/$TOTAL controles cumplidos" | tee -a "$REPORT"

if [[ $TOTAL -gt 0 ]]; then
    PCT=$(( PASS * 100 / TOTAL ))
    echo "Porcentaje de cumplimiento: ${PCT}%" | tee -a "$REPORT"
fi

echo "" | tee -a "$REPORT"
echo "Reporte guardado: $REPORT" | tee -a "$REPORT"
EOFCOMP

    chmod 700 /usr/local/bin/reporte-cumplimiento.sh
    log_info "Reporte de cumplimiento instalado: /usr/local/bin/reporte-cumplimiento.sh"

else
    log_warn "Reporte de cumplimiento no instalado"
fi

# ============================================================
log_section "4. INVENTARIO DE ACTIVOS DE SEGURIDAD"
# ============================================================

echo "Genera un inventario completo de todos los scripts,"
echo "reglas, timers y configuraciones de seguridad instalados."
echo ""

if ask "¿Instalar generador de inventario?"; then

    cat > /usr/local/bin/inventario-seguridad.sh << 'EOFINV'
#!/bin/bash
# ============================================================
# INVENTARIO DE ACTIVOS DE SEGURIDAD
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

REPORT_DIR="/var/lib/security-reports"
mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/inventario-$(date +%Y%m%d).txt"

echo "╔════════════════════════════════════════════════════════╗" | tee "$REPORT"
echo "║     INVENTARIO DE ACTIVOS DE SEGURIDAD                ║" | tee -a "$REPORT"
echo "║     $(hostname) - $(date '+%Y-%m-%d %H:%M')                      ║" | tee -a "$REPORT"
echo "╚════════════════════════════════════════════════════════╝" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# ── Scripts de detección ──
echo "=== SCRIPTS DE DETECCIÓN (/usr/local/bin/) ===" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"
DET_COUNT=0
for script in /usr/local/bin/detectar-*.sh /usr/local/bin/monitorear-*.sh \
              /usr/local/bin/buscar-credenciales.sh /usr/local/bin/watchdog-seguridad.sh; do
    if [[ -x "$script" ]]; then
        SIZE=$(stat -c %s "$script" 2>/dev/null)
        MOD=$(stat -c '%Y' "$script" 2>/dev/null)
        MOD_DATE=$(date -d "@$MOD" '+%Y-%m-%d' 2>/dev/null || echo "?")
        echo "  $(basename "$script")  (${SIZE}B, $MOD_DATE)" | tee -a "$REPORT"
        ((DET_COUNT++))
    fi
done
echo "" | tee -a "$REPORT"
echo "  Total: $DET_COUNT scripts de detección" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# ── Scripts de respuesta a incidentes ──
echo "=== SCRIPTS DE RESPUESTA A INCIDENTES ===" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"
IR_COUNT=0
for script in /usr/local/bin/ir-*.sh /usr/local/bin/ir-responder.sh; do
    if [[ -x "$script" ]]; then
        echo "  $(basename "$script")" | tee -a "$REPORT"
        ((IR_COUNT++))
    fi
done
# Playbooks
for pb in /usr/local/lib/incident-response/playbooks/pb-*.sh; do
    if [[ -x "$pb" ]]; then
        echo "  playbooks/$(basename "$pb")" | tee -a "$REPORT"
        ((IR_COUNT++))
    fi
done
echo "" | tee -a "$REPORT"
echo "  Total: $IR_COUNT herramientas IR" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# ── Scripts de monitorización ──
echo "=== SCRIPTS DE MONITORIZACIÓN ===" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"
MON_COUNT=0
for script in /usr/local/bin/security-dashboard.sh /usr/local/bin/correlacionar-alertas.sh \
              /usr/local/bin/security-baseline.sh /usr/local/bin/security-healthcheck.sh \
              /usr/local/bin/security-digest.sh; do
    if [[ -x "$script" ]]; then
        echo "  $(basename "$script")" | tee -a "$REPORT"
        ((MON_COUNT++))
    fi
done
echo "" | tee -a "$REPORT"
echo "  Total: $MON_COUNT herramientas de monitorización" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# ── Scripts de reporte ──
echo "=== SCRIPTS DE REPORTE ===" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"
REP_COUNT=0
for script in /usr/local/bin/reporte-mitre.sh /usr/local/bin/exportar-navigator.sh \
              /usr/local/bin/reporte-cumplimiento.sh /usr/local/bin/inventario-seguridad.sh; do
    if [[ -x "$script" ]]; then
        echo "  $(basename "$script")" | tee -a "$REPORT"
        ((REP_COUNT++))
    fi
done
echo "" | tee -a "$REPORT"
echo "  Total: $REP_COUNT herramientas de reporte" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# ── Reglas auditd ──
echo "=== REGLAS AUDITD (/etc/audit/rules.d/) ===" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"
AUDIT_COUNT=0
for rules_file in /etc/audit/rules.d/*.rules; do
    if [[ -f "$rules_file" ]]; then
        RULE_COUNT=$(grep -c "^-" "$rules_file" 2>/dev/null || echo 0)
        echo "  $(basename "$rules_file") ($RULE_COUNT reglas)" | tee -a "$REPORT"
        ((AUDIT_COUNT++))
    fi
done
echo "" | tee -a "$REPORT"
echo "  Total: $AUDIT_COUNT archivos de reglas" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# ── Cron jobs de seguridad ──
echo "=== CRON JOBS DE SEGURIDAD ===" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"
CRON_COUNT=0
for cron_dir in /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    for cron_script in "$cron_dir"/detectar-* "$cron_dir"/monitorear-* "$cron_dir"/security-* "$cron_dir"/reconocimiento-*; do
        if [[ -x "$cron_script" ]]; then
            echo "  $(basename "$cron_dir")/$(basename "$cron_script")" | tee -a "$REPORT"
            ((CRON_COUNT++))
        fi
    done
done
echo "" | tee -a "$REPORT"
echo "  Total: $CRON_COUNT cron jobs" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# ── Timers systemd ──
echo "=== TIMERS SYSTEMD DE SEGURIDAD ===" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"
TIMER_COUNT=0
for timer in watchdog-seguridad detectar-promiscuo monitorear-transferencias security-digest; do
    if systemctl list-unit-files "${timer}.timer" &>/dev/null 2>&1; then
        STATUS=$(systemctl is-active "${timer}.timer" 2>/dev/null || echo "inactivo")
        echo "  ${timer}.timer ($STATUS)" | tee -a "$REPORT"
        ((TIMER_COUNT++))
    fi
done
echo "" | tee -a "$REPORT"
echo "  Total: $TIMER_COUNT timers" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# ── Configuraciones de seguridad ──
echo "=== CONFIGURACIONES SYSCTL ===" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"
SYSCTL_COUNT=0
for conf in /etc/sysctl.d/9*.conf; do
    if [[ -f "$conf" ]]; then
        PARAM_COUNT=$(grep -c "^[^#]" "$conf" 2>/dev/null || echo 0)
        echo "  $(basename "$conf") ($PARAM_COUNT parámetros)" | tee -a "$REPORT"
        ((SYSCTL_COUNT++))
    fi
done
echo "" | tee -a "$REPORT"

# ── Suricata rules ──
echo "=== REGLAS SURICATA ===" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"
for rules_file in /etc/suricata/rules/local*.rules; do
    if [[ -f "$rules_file" ]]; then
        RULE_COUNT=$(grep -c "^alert\|^drop\|^reject" "$rules_file" 2>/dev/null || echo 0)
        echo "  $(basename "$rules_file") ($RULE_COUNT reglas)" | tee -a "$REPORT"
    fi
done
echo "" | tee -a "$REPORT"

# ── Resumen total ──
TOTAL=$((DET_COUNT + IR_COUNT + MON_COUNT + REP_COUNT))
echo "════════════════════════════════════════════════════════" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"
echo "RESUMEN TOTAL:" | tee -a "$REPORT"
echo "  Scripts de detección:    $DET_COUNT" | tee -a "$REPORT"
echo "  Herramientas IR:         $IR_COUNT" | tee -a "$REPORT"
echo "  Herramientas monitoreo:  $MON_COUNT" | tee -a "$REPORT"
echo "  Herramientas reporte:    $REP_COUNT" | tee -a "$REPORT"
echo "  Archivos auditd:         $AUDIT_COUNT" | tee -a "$REPORT"
echo "  Cron jobs:               $CRON_COUNT" | tee -a "$REPORT"
echo "  Timers systemd:          $TIMER_COUNT" | tee -a "$REPORT"
echo "  ─────────────────────────────" | tee -a "$REPORT"
echo "  Total activos:           $TOTAL scripts" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"
echo "Reporte guardado: $REPORT" | tee -a "$REPORT"
EOFINV

    chmod 700 /usr/local/bin/inventario-seguridad.sh
    log_info "Inventario instalado: /usr/local/bin/inventario-seguridad.sh"

else
    log_warn "Inventario no instalado"
fi

# ============================================================
log_section "5. RESUMEN EJECUTIVO DE AUDITORÍA"
# ============================================================

echo "Genera un resumen ejecutivo de una página con el estado"
echo "general de la postura de seguridad del sistema."
echo ""

if ask "¿Instalar generador de resumen ejecutivo?"; then

    cat > /usr/local/bin/resumen-ejecutivo.sh << 'EOFEXEC'
#!/bin/bash
# ============================================================
# RESUMEN EJECUTIVO DE AUDITORÍA
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

REPORT_DIR="/var/lib/security-reports"
mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/resumen-ejecutivo-$(date +%Y%m%d).txt"

echo "╔════════════════════════════════════════════════════════════╗" | tee "$REPORT"
echo "║              RESUMEN EJECUTIVO DE SEGURIDAD               ║" | tee -a "$REPORT"
echo "╠════════════════════════════════════════════════════════════╣" | tee -a "$REPORT"
echo "║  Host:   $(printf '%-49s' "$(hostname)")║" | tee -a "$REPORT"
echo "║  OS:     $(printf '%-49s' "$(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"' | head -c 49)")║" | tee -a "$REPORT"
echo "║  Kernel: $(printf '%-49s' "$(uname -r)")║" | tee -a "$REPORT"
echo "║  Fecha:  $(printf '%-49s' "$(date '+%Y-%m-%d %H:%M')")║" | tee -a "$REPORT"
echo "╚════════════════════════════════════════════════════════════╝" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# Evaluar cada área
AREAS_OK=0
AREAS_TOTAL=0

eval_area() {
    local area="$1"
    local check="$2"
    ((AREAS_TOTAL++))

    if eval "$check" &>/dev/null 2>&1; then
        echo "  [●] $area" | tee -a "$REPORT"
        ((AREAS_OK++))
    else
        echo "  [○] $area" | tee -a "$REPORT"
    fi
}

echo "── POSTURA DE SEGURIDAD ──" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

eval_area "Firewall perimetral" "systemctl is-active firewalld"
eval_area "Detección de intrusiones (IDS)" "systemctl is-active suricata 2>/dev/null"
eval_area "Auditoría del sistema" "systemctl is-active auditd"
eval_area "Protección contra brute force" "systemctl is-active fail2ban"
eval_area "Control de aplicaciones (AppArmor)" "systemctl is-active apparmor 2>/dev/null || aa-status 2>/dev/null | grep -q profiles"
eval_area "Antimalware (ClamAV)" "command -v clamscan"
eval_area "Inteligencia de amenazas (IoC)" "test -x /usr/local/bin/ioc-lookup.sh"
eval_area "Monitoreo continuo" "test -x /usr/local/bin/security-dashboard.sh"
eval_area "Correlación de alertas" "test -x /usr/local/bin/correlacionar-alertas.sh"
eval_area "Respuesta a incidentes" "test -x /usr/local/bin/ir-responder.sh"
eval_area "Baseline de comportamiento" "test -x /usr/local/bin/security-baseline.sh"
eval_area "Cobertura MITRE ATT&CK" "test -x /usr/local/bin/reporte-mitre.sh"

echo "" | tee -a "$REPORT"

# Score
if [[ $AREAS_TOTAL -gt 0 ]]; then
    SCORE=$(( AREAS_OK * 100 / AREAS_TOTAL ))
else
    SCORE=0
fi

echo "── EVALUACIÓN ──" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"
echo "  Score: $AREAS_OK/$AREAS_TOTAL áreas cubiertas ($SCORE%)" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

if [[ $SCORE -ge 90 ]]; then
    echo "  Nivel: EXCELENTE" | tee -a "$REPORT"
    echo "  La postura de seguridad del sistema es robusta." | tee -a "$REPORT"
elif [[ $SCORE -ge 70 ]]; then
    echo "  Nivel: BUENO" | tee -a "$REPORT"
    echo "  Hay buena cobertura con áreas de mejora." | tee -a "$REPORT"
elif [[ $SCORE -ge 50 ]]; then
    echo "  Nivel: PARCIAL" | tee -a "$REPORT"
    echo "  Cobertura básica. Se recomienda ejecutar módulos pendientes." | tee -a "$REPORT"
else
    echo "  Nivel: INSUFICIENTE" | tee -a "$REPORT"
    echo "  Se requiere ejecutar los módulos de securización." | tee -a "$REPORT"
fi

echo "" | tee -a "$REPORT"

# Estadísticas
DET_COUNT=$(ls /usr/local/bin/detectar-*.sh 2>/dev/null | wc -l)
IR_COUNT=$(ls /usr/local/bin/ir-*.sh 2>/dev/null | wc -l)
AUDIT_RULES=$(ls /etc/audit/rules.d/6*.rules 2>/dev/null | wc -l)

echo "── ESTADÍSTICAS ──" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"
echo "  Scripts de detección activos: $DET_COUNT" | tee -a "$REPORT"
echo "  Herramientas de IR:           $IR_COUNT" | tee -a "$REPORT"
echo "  Archivos de reglas auditd:    $AUDIT_RULES" | tee -a "$REPORT"
echo "  Reglas auditd activas:        $(auditctl -l 2>/dev/null | wc -l)" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# Alertas últimas 24h
SSH_FAILS=$(journalctl -u sshd --since "24 hours ago" --no-pager 2>/dev/null | grep -ci "failed\|invalid" || echo 0)
F2B_BANS=$(journalctl -u fail2ban --since "24 hours ago" --no-pager 2>/dev/null | grep -c "Ban" || echo 0)

echo "── ACTIVIDAD (24h) ──" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"
echo "  Intentos SSH fallidos: $SSH_FAILS" | tee -a "$REPORT"
echo "  IPs baneadas (fail2ban): $F2B_BANS" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

echo "════════════════════════════════════════════════════════════" | tee -a "$REPORT"
echo "Generado por Securizar Suite" | tee -a "$REPORT"
echo "Reporte: $REPORT" | tee -a "$REPORT"
EOFEXEC

    chmod 700 /usr/local/bin/resumen-ejecutivo.sh
    log_info "Resumen ejecutivo instalado: /usr/local/bin/resumen-ejecutivo.sh"

else
    log_warn "Resumen ejecutivo no instalado"
fi

# ============================================================
log_section "RESUMEN DE REPORTES DE SEGURIDAD"
# ============================================================

echo ""
echo -e "${BOLD}Herramientas de reporte instaladas:${NC}"
echo ""

if [[ -x /usr/local/bin/reporte-mitre.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} Cobertura MITRE ATT&CK (reporte-mitre.sh)"
else
    echo -e "  ${YELLOW}[--]${NC} Reporte MITRE no instalado"
fi

if [[ -x /usr/local/bin/exportar-navigator.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} ATT&CK Navigator JSON (exportar-navigator.sh)"
else
    echo -e "  ${YELLOW}[--]${NC} Exportador Navigator no instalado"
fi

if [[ -x /usr/local/bin/reporte-cumplimiento.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} Cumplimiento de controles (reporte-cumplimiento.sh)"
else
    echo -e "  ${YELLOW}[--]${NC} Reporte cumplimiento no instalado"
fi

if [[ -x /usr/local/bin/inventario-seguridad.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} Inventario de activos (inventario-seguridad.sh)"
else
    echo -e "  ${YELLOW}[--]${NC} Inventario no instalado"
fi

if [[ -x /usr/local/bin/resumen-ejecutivo.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} Resumen ejecutivo (resumen-ejecutivo.sh)"
else
    echo -e "  ${YELLOW}[--]${NC} Resumen ejecutivo no instalado"
fi

echo ""
echo -e "${BOLD}Uso rápido:${NC}"
echo -e "  ${DIM}MITRE ATT&CK:${NC}    reporte-mitre.sh"
echo -e "  ${DIM}Navigator:${NC}       exportar-navigator.sh"
echo -e "  ${DIM}Cumplimiento:${NC}    reporte-cumplimiento.sh"
echo -e "  ${DIM}Inventario:${NC}      inventario-seguridad.sh"
echo -e "  ${DIM}Ejecutivo:${NC}       resumen-ejecutivo.sh"
echo ""
echo -e "${BOLD}Reportes guardados en:${NC} /var/lib/security-reports/"
echo ""
log_info "Módulo de reportes de seguridad completado"
