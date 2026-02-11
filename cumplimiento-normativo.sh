#!/bin/bash
# ============================================================
# cumplimiento-normativo.sh - Modulo 54: Cumplimiento Normativo
# (Regulatory Compliance Frameworks)
# ============================================================
# Secciones:
#   S1  - Framework de cumplimiento configurable
#   S2  - Evaluacion PCI-DSS v4.0
#   S3  - Evaluacion GDPR (proteccion de datos)
#   S4  - Evaluacion HIPAA (salud)
#   S5  - Evaluacion SOC 2 (Type II)
#   S6  - Evaluacion ISO 27001
#   S7  - Recoleccion de evidencias automatica
#   S8  - Generacion de informes de cumplimiento
#   S9  - Remediacion guiada
#   S10 - Auditoria integral de cumplimiento
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps
init_backup "compliance-frameworks"

log_section "MODULO 54: CUMPLIMIENTO NORMATIVO (REGULATORY COMPLIANCE)"
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

# ── Directorios base ──────────────────────────────────────
COMPLIANCE_CONF_DIR="/etc/securizar"
COMPLIANCE_EVIDENCE_DIR="/var/lib/securizar/compliance-evidence"
COMPLIANCE_REPORT_DIR="/var/log/securizar/compliance-reports"
COMPLIANCE_REMEDIATION_DIR="/var/lib/securizar"
COMPLIANCE_BIN_DIR="/usr/local/bin"

mkdir -p "$COMPLIANCE_CONF_DIR"
mkdir -p "$COMPLIANCE_EVIDENCE_DIR"
mkdir -p "$COMPLIANCE_REPORT_DIR"
mkdir -p "$COMPLIANCE_REMEDIATION_DIR"

# ── Helpers de evaluacion ─────────────────────────────────
# check_result PASS|FAIL|WARN "description" -> track results
_COMPLIANCE_PASS=0
_COMPLIANCE_FAIL=0
_COMPLIANCE_WARN=0
_COMPLIANCE_RESULTS=()

compliance_reset_counters() {
    _COMPLIANCE_PASS=0
    _COMPLIANCE_FAIL=0
    _COMPLIANCE_WARN=0
    _COMPLIANCE_RESULTS=()
}

compliance_check() {
    local status="$1" desc="$2"
    case "$status" in
        PASS) (( _COMPLIANCE_PASS++ )) || true; _COMPLIANCE_RESULTS+=("PASS|$desc") ;;
        FAIL) (( _COMPLIANCE_FAIL++ )) || true; _COMPLIANCE_RESULTS+=("FAIL|$desc") ;;
        WARN) (( _COMPLIANCE_WARN++ )) || true; _COMPLIANCE_RESULTS+=("WARN|$desc") ;;
    esac
}

compliance_score() {
    local total=$(( _COMPLIANCE_PASS + _COMPLIANCE_FAIL + _COMPLIANCE_WARN ))
    if [[ $total -eq 0 ]]; then
        printf "0"
        return
    fi
    local score=$(( (_COMPLIANCE_PASS * 100) / total ))
    printf "%d" "$score"
}

compliance_rating() {
    local score
    score=$(compliance_score)
    if [[ $score -ge 80 ]]; then
        printf "BUENO"
    elif [[ $score -ge 50 ]]; then
        printf "MEJORABLE"
    else
        printf "DEFICIENTE"
    fi
}

# ============================================================
# S1: FRAMEWORK DE CUMPLIMIENTO CONFIGURABLE
# ============================================================
log_section "S1: Framework de cumplimiento configurable"

log_info "Configuracion base del framework de cumplimiento normativo:"
log_info "  - Archivo de configuracion con frameworks activos"
log_info "  - Estructura de directorios para evidencias"
log_info "  - Script de inicializacion de cumplimiento"

if ask "¿Configurar framework de cumplimiento normativo?"; then

    # ── S1.1: Archivo de configuracion principal ──────────
    COMPLIANCE_CONF="$COMPLIANCE_CONF_DIR/compliance-framework.conf"

    if [[ -f "$COMPLIANCE_CONF" ]]; then
        cp -a "$COMPLIANCE_CONF" "$BACKUP_DIR/"
        log_change "Backup" "$COMPLIANCE_CONF"
    fi

    cat > "$COMPLIANCE_CONF" << 'COMPLIANCEEOF'
# ============================================================
# compliance-framework.conf - Configuracion de Cumplimiento Normativo
# Generado por securizar - Modulo 54
# ============================================================

# Frameworks activos (separados por espacio)
# Opciones: pci-dss gdpr hipaa soc2 iso27001
ACTIVE_FRAMEWORKS="pci-dss gdpr"

# Informacion organizativa
ORGANIZATION_NAME="Mi Organizacion"
AUDIT_CONTACT="seguridad@ejemplo.com"
COMPLIANCE_OFFICER="Responsable de Cumplimiento"

# Directorios
EVIDENCE_DIR=/var/lib/securizar/compliance-evidence
REPORT_DIR=/var/log/securizar/compliance-reports

# Retencion de evidencias y reportes (dias)
RETENTION_DAYS=365

# Nivel de detalle en reportes: minimal, standard, verbose
REPORT_DETAIL="standard"

# Programacion de evaluaciones automaticas
AUTO_EVALUATE="weekly"

# Notificaciones por email (dejar vacio para desactivar)
NOTIFY_EMAIL=""

# Umbral de alerta (porcentaje de cumplimiento)
ALERT_THRESHOLD=70

# Formato de reporte: html, json, both
REPORT_FORMAT="both"

# Idioma de reportes
REPORT_LANG="es"
COMPLIANCEEOF

    chmod 600 "$COMPLIANCE_CONF"
    chown root:root "$COMPLIANCE_CONF"
    log_change "Creado" "$COMPLIANCE_CONF (configuracion de frameworks)"

    # ── S1.2: Estructura de directorios para evidencias ───
    local evidence_subdirs=(
        "pci-dss"
        "gdpr"
        "hipaa"
        "soc2"
        "iso27001"
        "common"
        "snapshots"
        "chain-of-custody"
    )

    for subdir in "${evidence_subdirs[@]}"; do
        mkdir -p "$COMPLIANCE_EVIDENCE_DIR/$subdir"
    done
    chmod -R 700 "$COMPLIANCE_EVIDENCE_DIR"
    log_change "Creado" "Estructura de directorios de evidencias en $COMPLIANCE_EVIDENCE_DIR"

    mkdir -p "$COMPLIANCE_REPORT_DIR"/{html,json,archive}
    chmod -R 700 "$COMPLIANCE_REPORT_DIR"
    log_change "Creado" "Estructura de directorios de reportes en $COMPLIANCE_REPORT_DIR"

    # ── S1.3: Script de inicializacion ────────────────────
    INIT_SCRIPT="$COMPLIANCE_BIN_DIR/securizar-compliance-init.sh"

    cat > "$INIT_SCRIPT" << 'INITEOF'
#!/bin/bash
# ============================================================
# securizar-compliance-init.sh - Inicializar entorno de cumplimiento
# Parte del Modulo 54 - Cumplimiento Normativo
# ============================================================
set -euo pipefail

CONF_FILE="/etc/securizar/compliance-framework.conf"
if [[ ! -f "$CONF_FILE" ]]; then
    echo "[ERROR] No se encuentra $CONF_FILE"
    echo "Ejecuta primero cumplimiento-normativo.sh para crear la configuracion."
    exit 1
fi

source "$CONF_FILE"

echo "============================================================"
echo "  Inicializacion de Cumplimiento Normativo - Securizar"
echo "============================================================"
echo ""
echo "Organizacion: $ORGANIZATION_NAME"
echo "Contacto:     $AUDIT_CONTACT"
echo "Frameworks:   $ACTIVE_FRAMEWORKS"
echo ""

# Crear directorios si no existen
mkdir -p "$EVIDENCE_DIR"/{pci-dss,gdpr,hipaa,soc2,iso27001,common,snapshots,chain-of-custody}
mkdir -p "$REPORT_DIR"/{html,json,archive}

# Verificar permisos
chmod -R 700 "$EVIDENCE_DIR"
chmod -R 700 "$REPORT_DIR"

echo "[+] Directorios de evidencias verificados: $EVIDENCE_DIR"
echo "[+] Directorios de reportes verificados: $REPORT_DIR"

# Verificar herramientas necesarias
TOOLS_OK=1
for tool in openssl sha256sum tar date awk; do
    if ! command -v "$tool" &>/dev/null; then
        echo "[!] Herramienta faltante: $tool"
        TOOLS_OK=0
    fi
done

if [[ $TOOLS_OK -eq 1 ]]; then
    echo "[+] Todas las herramientas necesarias estan disponibles"
else
    echo "[!] Instala las herramientas faltantes antes de continuar"
fi

# Registrar inicializacion
INIT_LOG="$EVIDENCE_DIR/common/init-$(date +%Y%m%d-%H%M%S).log"
{
    echo "Fecha de inicializacion: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Hostname: $(hostname)"
    echo "Organizacion: $ORGANIZATION_NAME"
    echo "Frameworks activos: $ACTIVE_FRAMEWORKS"
    echo "Kernel: $(uname -r)"
    echo "OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"
} > "$INIT_LOG"

echo "[+] Log de inicializacion: $INIT_LOG"
echo ""
echo "Entorno de cumplimiento inicializado correctamente."
echo "Ejecuta los scripts de evaluacion individuales:"
echo "  - evaluar-pci-dss.sh"
echo "  - evaluar-gdpr.sh"
echo "  - evaluar-hipaa.sh"
echo "  - evaluar-soc2.sh"
echo "  - evaluar-iso27001.sh"
echo "O ejecuta: auditoria-cumplimiento.sh (evaluacion integral)"
INITEOF

    chmod 755 "$INIT_SCRIPT"
    log_change "Creado" "$INIT_SCRIPT"

    # ── S1.4: Plantilla de inventario de datos ────────────
    DATA_INVENTORY="$COMPLIANCE_CONF_DIR/gdpr-data-inventory.conf"

    if [[ ! -f "$DATA_INVENTORY" ]]; then
        cat > "$DATA_INVENTORY" << 'INVEOF'
# ============================================================
# gdpr-data-inventory.conf - Inventario de datos personales
# Plantilla para cumplimiento GDPR (Art. 30)
# ============================================================

# Formato: CATEGORY|DATA_TYPE|PURPOSE|LEGAL_BASIS|RETENTION|LOCATION
# Rellena con los datos de tu organizacion

# Ejemplo:
# EMPLEADOS|nombre,email,dni|gestion_rrhh|contrato|5_anios|/srv/rrhh/db
# CLIENTES|nombre,email,telefono|servicio|consentimiento|3_anios|/srv/crm/db
# LOGS|ip,user-agent|seguridad|interes_legitimo|1_anio|/var/log

# --- Rellena a continuacion ---
INVEOF
        chmod 600 "$DATA_INVENTORY"
        log_change "Creado" "$DATA_INVENTORY (plantilla inventario de datos)"
    else
        log_skip "Inventario de datos ya existe: $DATA_INVENTORY"
    fi

else
    log_skip "Framework de cumplimiento configurable"
fi

# ============================================================
# S2: EVALUACION PCI-DSS v4.0
# ============================================================
log_section "S2: Evaluacion PCI-DSS v4.0"

log_info "Script de evaluacion PCI-DSS v4.0 (12 requisitos):"
log_info "  - Firewalls, contrasenas por defecto, cifrado"
log_info "  - Anti-malware, parcheo, control de acceso"
log_info "  - Autenticacion, logging, pruebas de seguridad"

if ask "¿Crear script de evaluacion PCI-DSS v4.0?"; then

    PCI_SCRIPT="$COMPLIANCE_BIN_DIR/evaluar-pci-dss.sh"

    cat > "$PCI_SCRIPT" << 'PCIEOF'
#!/bin/bash
# ============================================================
# evaluar-pci-dss.sh - Evaluacion PCI-DSS v4.0
# Parte del Modulo 54 - Cumplimiento Normativo
# ============================================================
# Evalua los 12 requisitos PCI-DSS v4.0 en el sistema
# Produce informe con PASS/FAIL por requisito
# ============================================================
set -euo pipefail

CONF_FILE="/etc/securizar/compliance-framework.conf"
[[ -f "$CONF_FILE" ]] && source "$CONF_FILE"

EVIDENCE_DIR="${EVIDENCE_DIR:-/var/lib/securizar/compliance-evidence}"
REPORT_DIR="${REPORT_DIR:-/var/log/securizar/compliance-reports}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
REPORT_FILE="$REPORT_DIR/pci-dss-${TIMESTAMP}.txt"

mkdir -p "$REPORT_DIR" "$EVIDENCE_DIR/pci-dss"

PASS=0
FAIL=0
WARN=0
TOTAL=12
RESULTS=()

check_result() {
    local req="$1" status="$2" desc="$3"
    RESULTS+=("$req|$status|$desc")
    case "$status" in
        PASS) (( PASS++ )) || true ;;
        FAIL) (( FAIL++ )) || true ;;
        WARN) (( WARN++ )) || true ;;
    esac
}

echo "============================================================"
echo "  Evaluacion PCI-DSS v4.0 - Securizar"
echo "  Fecha: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "  Host:  $(hostname)"
echo "============================================================"
echo ""

# ── Requisito 1: Instalar y mantener firewall ────────────
echo "[Req 1] Instalar y mantener controles de seguridad de red..."
REQ1="FAIL"
REQ1_DESC="Firewall no detectado"

if command -v nft &>/dev/null && nft list ruleset 2>/dev/null | grep -q 'chain'; then
    REQ1="PASS"
    REQ1_DESC="nftables activo con reglas configuradas"
elif command -v iptables &>/dev/null && iptables -L -n 2>/dev/null | grep -qE 'ACCEPT|DROP|REJECT'; then
    if iptables -L INPUT -n 2>/dev/null | grep -qE 'DROP|REJECT'; then
        REQ1="PASS"
        REQ1_DESC="iptables activo con politica restrictiva"
    else
        REQ1="WARN"
        REQ1_DESC="iptables activo pero sin politica DROP por defecto"
    fi
elif command -v firewall-cmd &>/dev/null && firewall-cmd --state 2>/dev/null | grep -q 'running'; then
    REQ1="PASS"
    REQ1_DESC="firewalld activo"
fi

# Guardar evidencia de reglas de firewall
{
    echo "=== Evidencia Req 1: Firewall - $(date) ==="
    if command -v nft &>/dev/null; then
        echo "--- nftables ruleset ---"
        nft list ruleset 2>/dev/null || echo "No disponible"
    fi
    if command -v iptables &>/dev/null; then
        echo "--- iptables ---"
        iptables -L -n -v 2>/dev/null || echo "No disponible"
    fi
    if command -v firewall-cmd &>/dev/null; then
        echo "--- firewalld ---"
        firewall-cmd --list-all 2>/dev/null || echo "No disponible"
    fi
} > "$EVIDENCE_DIR/pci-dss/req1-firewall-${TIMESTAMP}.txt"

check_result "Req01" "$REQ1" "$REQ1_DESC"
echo "  [$REQ1] $REQ1_DESC"

# ── Requisito 2: No usar contrasenas por defecto ─────────
echo "[Req 2] No usar valores por defecto del proveedor..."
REQ2="PASS"
REQ2_DESC="No se detectaron credenciales por defecto"

# Verificar usuarios sin contrasena
EMPTY_PW=$(awk -F: '($2 == "" || $2 == "!") && $1 != "root" {print $1}' /etc/shadow 2>/dev/null || true)
if [[ -n "$EMPTY_PW" ]]; then
    REQ2="FAIL"
    REQ2_DESC="Usuarios sin contrasena detectados: $EMPTY_PW"
fi

# Verificar SNMP community string por defecto
if [[ -f /etc/snmp/snmpd.conf ]] && grep -qE 'community\s+(public|private)' /etc/snmp/snmpd.conf 2>/dev/null; then
    REQ2="FAIL"
    REQ2_DESC="${REQ2_DESC}; SNMP community string por defecto"
fi

# Verificar claves SSH por defecto en authorized_keys
DEFAULT_KEY_FOUND=0
while IFS= read -r authfile; do
    if [[ -f "$authfile" ]] && grep -q 'AAAAB3NzaC1yc2EAAAADAQABAAAB' "$authfile" 2>/dev/null; then
        DEFAULT_KEY_FOUND=1
    fi
done < <(find /home -name authorized_keys -type f 2>/dev/null; echo "/root/.ssh/authorized_keys")

if [[ $DEFAULT_KEY_FOUND -eq 1 ]]; then
    REQ2="WARN"
    REQ2_DESC="${REQ2_DESC}; Revisar claves SSH (posibles claves por defecto)"
fi

check_result "Req02" "$REQ2" "$REQ2_DESC"
echo "  [$REQ2] $REQ2_DESC"

# ── Requisito 3: Proteger datos de tarjeta almacenados ───
echo "[Req 3] Proteger datos de tarjeta almacenados..."
REQ3="PASS"
REQ3_DESC="Verificaciones de cifrado de datos"

# Verificar LUKS/dm-crypt
if command -v cryptsetup &>/dev/null && cryptsetup status 2>/dev/null | grep -q 'active'; then
    REQ3_DESC="Cifrado de disco activo (LUKS/dm-crypt)"
elif lsblk -o TYPE 2>/dev/null | grep -q 'crypt'; then
    REQ3_DESC="Volumenes cifrados detectados"
else
    REQ3="WARN"
    REQ3_DESC="No se detecta cifrado de disco completo (considerar LUKS)"
fi

# Buscar datos de tarjeta en texto plano (patron basico)
PAN_FOUND=0
for logdir in /var/log /tmp /var/tmp; do
    if find "$logdir" -maxdepth 2 -type f -name "*.log" -exec grep -lE '\b[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b' {} + 2>/dev/null | head -1 | grep -q .; then
        PAN_FOUND=1
        break
    fi
done

if [[ $PAN_FOUND -eq 1 ]]; then
    REQ3="FAIL"
    REQ3_DESC="Posibles datos PAN en texto plano en logs"
fi

check_result "Req03" "$REQ3" "$REQ3_DESC"
echo "  [$REQ3] $REQ3_DESC"

# ── Requisito 4: Cifrar transmision de datos ─────────────
echo "[Req 4] Cifrar transmision de datos de tarjeta..."
REQ4="PASS"
REQ4_DESC="Configuracion TLS verificada"

# Verificar versiones TLS en OpenSSL
if command -v openssl &>/dev/null; then
    OPENSSL_VER=$(openssl version 2>/dev/null || echo "desconocido")
    # Verificar que TLSv1.0/1.1 estan deshabilitados
    if openssl ciphers -v 2>/dev/null | grep -qi 'TLSv1\b'; then
        REQ4="WARN"
        REQ4_DESC="TLSv1.0 aun disponible en OpenSSL ($OPENSSL_VER)"
    fi
fi

# Verificar configuracion SSH
if [[ -f /etc/ssh/sshd_config ]]; then
    SSH_PROTO=$(grep -E '^\s*Protocol\s' /etc/ssh/sshd_config 2>/dev/null || echo "")
    if [[ -n "$SSH_PROTO" ]] && [[ "$SSH_PROTO" != *"2"* ]]; then
        REQ4="FAIL"
        REQ4_DESC="SSH Protocol 1 habilitado"
    fi
fi

# Verificar Apache/Nginx TLS
for conf in /etc/httpd/conf.d/ssl.conf /etc/apache2/mods-enabled/ssl.conf /etc/nginx/nginx.conf; do
    if [[ -f "$conf" ]] && grep -qiE 'SSLProtocol|ssl_protocols' "$conf" 2>/dev/null; then
        if grep -qiE 'TLSv1\b|TLSv1\.0|SSLv3' "$conf" 2>/dev/null; then
            REQ4="WARN"
            REQ4_DESC="Protocolos TLS inseguros habilitados en web server"
        fi
    fi
done

check_result "Req04" "$REQ4" "$REQ4_DESC"
echo "  [$REQ4] $REQ4_DESC"

# ── Requisito 5: Anti-malware ────────────────────────────
echo "[Req 5] Proteger contra malware..."
REQ5="FAIL"
REQ5_DESC="No se detecta solucion anti-malware"

if command -v clamscan &>/dev/null || command -v freshclam &>/dev/null; then
    if systemctl is-active clamav-daemon &>/dev/null || systemctl is-active clamd &>/dev/null; then
        REQ5="PASS"
        REQ5_DESC="ClamAV instalado y servicio activo"
    else
        REQ5="WARN"
        REQ5_DESC="ClamAV instalado pero servicio no activo"
    fi
fi

# Verificar AIDE/integridad de archivos
if command -v aide &>/dev/null; then
    if [[ "$REQ5" == "FAIL" ]]; then
        REQ5="WARN"
        REQ5_DESC="AIDE instalado (monitoreo de integridad), pero sin anti-malware dedicado"
    else
        REQ5_DESC="${REQ5_DESC}; AIDE tambien disponible"
    fi
fi

check_result "Req05" "$REQ5" "$REQ5_DESC"
echo "  [$REQ5] $REQ5_DESC"

# ── Requisito 6: Sistemas seguros y actualizados ─────────
echo "[Req 6] Desarrollar y mantener sistemas seguros..."
REQ6="PASS"
REQ6_DESC="Sistema actualizado"

# Verificar actualizaciones pendientes
UPDATES_PENDING=0
if command -v zypper &>/dev/null; then
    UPDATES_PENDING=$(zypper list-patches --category security 2>/dev/null | grep -c 'needed' || echo "0")
elif command -v apt-get &>/dev/null; then
    apt-get update -qq 2>/dev/null || true
    UPDATES_PENDING=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst ' || echo "0")
elif command -v dnf &>/dev/null; then
    UPDATES_PENDING=$(dnf check-update --security 2>/dev/null | grep -cE '^\S+\.\S+' || echo "0")
elif command -v pacman &>/dev/null; then
    UPDATES_PENDING=$(pacman -Qu 2>/dev/null | wc -l || echo "0")
fi

if [[ "$UPDATES_PENDING" -gt 10 ]]; then
    REQ6="FAIL"
    REQ6_DESC="$UPDATES_PENDING actualizaciones de seguridad pendientes"
elif [[ "$UPDATES_PENDING" -gt 0 ]]; then
    REQ6="WARN"
    REQ6_DESC="$UPDATES_PENDING actualizaciones pendientes"
fi

# Verificar AIDE
if command -v aide &>/dev/null; then
    REQ6_DESC="${REQ6_DESC}; AIDE instalado para control de integridad"
fi

check_result "Req06" "$REQ6" "$REQ6_DESC"
echo "  [$REQ6] $REQ6_DESC"

# ── Requisito 7: Restringir acceso ───────────────────────
echo "[Req 7] Restringir acceso a datos de tarjeta (need-to-know)..."
REQ7="PASS"
REQ7_DESC="Control de acceso verificado"

# Verificar sudoers con ALL=(ALL) NOPASSWD
if grep -rqE 'NOPASSWD.*ALL' /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
    REQ7="WARN"
    REQ7_DESC="sudo NOPASSWD:ALL detectado (revisar principio de minimo privilegio)"
fi

# Verificar archivos world-writable en directorios criticos
WW_FILES=$(find /etc /usr/local/bin -type f -perm -o+w 2>/dev/null | head -5 | wc -l || echo "0")
if [[ "$WW_FILES" -gt 0 ]]; then
    REQ7="FAIL"
    REQ7_DESC="Archivos world-writable en directorios criticos: $WW_FILES encontrados"
fi

# Verificar permisos de /etc/shadow
SHADOW_PERMS=$(stat -c '%a' /etc/shadow 2>/dev/null || echo "")
if [[ -n "$SHADOW_PERMS" ]] && [[ "$SHADOW_PERMS" != "000" ]] && [[ "$SHADOW_PERMS" != "600" ]] && [[ "$SHADOW_PERMS" != "640" ]]; then
    REQ7="FAIL"
    REQ7_DESC="Permisos de /etc/shadow demasiado permisivos: $SHADOW_PERMS"
fi

check_result "Req07" "$REQ7" "$REQ7_DESC"
echo "  [$REQ7] $REQ7_DESC"

# ── Requisito 8: Autenticacion ───────────────────────────
echo "[Req 8] Identificar usuarios y autenticar acceso..."
REQ8="PASS"
REQ8_DESC="Autenticacion verificada"

# Verificar politica de contrasenas
if [[ -f /etc/login.defs ]]; then
    PASS_MAX=$(grep -E '^\s*PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}' || echo "99999")
    PASS_MIN_LEN=$(grep -E '^\s*PASS_MIN_LEN' /etc/login.defs 2>/dev/null | awk '{print $2}' || echo "5")

    if [[ "${PASS_MAX:-99999}" -gt 90 ]]; then
        REQ8="WARN"
        REQ8_DESC="PASS_MAX_DAYS > 90 dias (PCI requiere <= 90)"
    fi
    if [[ "${PASS_MIN_LEN:-5}" -lt 8 ]]; then
        REQ8="WARN"
        REQ8_DESC="${REQ8_DESC}; PASS_MIN_LEN < 8 caracteres"
    fi
fi

# Verificar MFA/2FA
MFA_FOUND=0
if [[ -f /etc/pam.d/sshd ]] && grep -q 'pam_google_authenticator\|pam_duo\|pam_yubico\|pam_oath' /etc/pam.d/sshd 2>/dev/null; then
    MFA_FOUND=1
fi
if [[ -f /etc/pam.d/common-auth ]] && grep -q 'pam_google_authenticator\|pam_duo\|pam_yubico' /etc/pam.d/common-auth 2>/dev/null; then
    MFA_FOUND=1
fi

if [[ $MFA_FOUND -eq 0 ]]; then
    REQ8="WARN"
    REQ8_DESC="${REQ8_DESC}; MFA no detectado en PAM"
fi

# Verificar bloqueo de cuentas
if command -v pam_tally2 &>/dev/null || grep -rq 'pam_faillock\|pam_tally' /etc/pam.d/ 2>/dev/null; then
    REQ8_DESC="${REQ8_DESC}; Bloqueo de cuentas configurado"
else
    REQ8="WARN"
    REQ8_DESC="${REQ8_DESC}; Sin bloqueo de cuentas por intentos fallidos"
fi

check_result "Req08" "$REQ8" "$REQ8_DESC"
echo "  [$REQ8] $REQ8_DESC"

# ── Requisito 9: Acceso fisico ───────────────────────────
echo "[Req 9] Restringir acceso fisico..."
REQ9="PASS"
REQ9_DESC="N/A para evaluacion de software; requiere verificacion fisica manual"

# Verificar si USB esta restringido
if [[ -f /etc/modprobe.d/usb-storage.conf ]] && grep -q 'install usb-storage /bin/true\|blacklist usb-storage' /etc/modprobe.d/usb-storage.conf 2>/dev/null; then
    REQ9_DESC="${REQ9_DESC}; USB storage deshabilitado"
fi

check_result "Req09" "$REQ9" "$REQ9_DESC"
echo "  [$REQ9] $REQ9_DESC"

# ── Requisito 10: Logging y monitoreo ────────────────────
echo "[Req 10] Registrar y monitorizar acceso..."
REQ10="FAIL"
REQ10_DESC="Sistema de logging insuficiente"

LOGGING_OK=0

# Verificar auditd
if command -v auditctl &>/dev/null && systemctl is-active auditd &>/dev/null; then
    LOGGING_OK=1
    REQ10="PASS"
    REQ10_DESC="auditd activo"

    # Verificar reglas de auditoria
    AUDIT_RULES=$(auditctl -l 2>/dev/null | wc -l || echo "0")
    if [[ "$AUDIT_RULES" -lt 5 ]]; then
        REQ10="WARN"
        REQ10_DESC="auditd activo pero pocas reglas ($AUDIT_RULES)"
    fi
fi

# Verificar syslog
if systemctl is-active rsyslog &>/dev/null || systemctl is-active syslog-ng &>/dev/null || systemctl is-active systemd-journald &>/dev/null; then
    if [[ $LOGGING_OK -eq 0 ]]; then
        REQ10="WARN"
        REQ10_DESC="syslog activo pero auditd no detectado"
    else
        REQ10_DESC="${REQ10_DESC}; syslog activo"
    fi
fi

# Verificar sincronizacion NTP (necesaria para logs)
if command -v chronyc &>/dev/null && chronyc tracking &>/dev/null; then
    REQ10_DESC="${REQ10_DESC}; NTP sincronizado (chrony)"
elif command -v ntpq &>/dev/null && ntpq -p &>/dev/null; then
    REQ10_DESC="${REQ10_DESC}; NTP sincronizado (ntpd)"
elif timedatectl show 2>/dev/null | grep -q 'NTPSynchronized=yes'; then
    REQ10_DESC="${REQ10_DESC}; NTP sincronizado (systemd-timesyncd)"
fi

check_result "Req10" "$REQ10" "$REQ10_DESC"
echo "  [$REQ10] $REQ10_DESC"

# ── Requisito 11: Pruebas de seguridad ───────────────────
echo "[Req 11] Probar sistemas y redes regularmente..."
REQ11="WARN"
REQ11_DESC="Sin herramientas de escaneo de vulnerabilidades detectadas"

if command -v nmap &>/dev/null; then
    REQ11_DESC="nmap disponible para escaneo de red"
fi

if command -v lynis &>/dev/null; then
    REQ11="PASS"
    REQ11_DESC="${REQ11_DESC}; lynis disponible para auditoria"
fi

if command -v openvas &>/dev/null || command -v gvm-start &>/dev/null; then
    REQ11="PASS"
    REQ11_DESC="${REQ11_DESC}; OpenVAS/GVM disponible"
fi

# Verificar escaneos IDS/IPS
if command -v snort &>/dev/null || command -v suricata &>/dev/null; then
    REQ11_DESC="${REQ11_DESC}; IDS/IPS detectado"
fi

check_result "Req11" "$REQ11" "$REQ11_DESC"
echo "  [$REQ11] $REQ11_DESC"

# ── Requisito 12: Politicas de seguridad ─────────────────
echo "[Req 12] Mantener politicas de seguridad..."
REQ12="WARN"
REQ12_DESC="No se encontraron archivos de politica de seguridad"

# Buscar archivos de politica
POLICY_FOUND=0
for pdir in /etc/securizar /usr/local/share/securizar /etc/security; do
    if [[ -d "$pdir" ]] && find "$pdir" -name "*.conf" -o -name "*.policy" -o -name "*politica*" 2>/dev/null | grep -q .; then
        POLICY_FOUND=1
    fi
done

if [[ $POLICY_FOUND -eq 1 ]]; then
    REQ12="PASS"
    REQ12_DESC="Archivos de politica de seguridad encontrados en /etc/securizar"
fi

# Verificar banners de seguridad
if [[ -f /etc/issue ]] && [[ -s /etc/issue ]]; then
    REQ12_DESC="${REQ12_DESC}; Banner de advertencia configurado"
fi

check_result "Req12" "$REQ12" "$REQ12_DESC"
echo "  [$REQ12] $REQ12_DESC"

# ── Generar informe de PCI-DSS ───────────────────────────
echo ""
echo "============================================================"
echo "  INFORME PCI-DSS v4.0 - RESUMEN"
echo "============================================================"

SCORE=0
[[ $TOTAL -gt 0 ]] && SCORE=$(( (PASS * 100) / TOTAL ))

echo ""
echo "  Requisitos evaluados: $TOTAL"
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
echo "  WARN: $WARN"
echo "  Puntuacion: ${SCORE}%"
echo ""

if [[ $SCORE -ge 80 ]]; then
    RATING="BUENO"
elif [[ $SCORE -ge 50 ]]; then
    RATING="MEJORABLE"
else
    RATING="DEFICIENTE"
fi
echo "  Calificacion: $RATING"
echo ""

# Guardar informe
{
    echo "============================================================"
    echo "  INFORME PCI-DSS v4.0"
    echo "  Fecha: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "  Host:  $(hostname)"
    echo "  Score: ${SCORE}% ($RATING)"
    echo "============================================================"
    echo ""
    for r in "${RESULTS[@]}"; do
        IFS='|' read -r req status desc <<< "$r"
        printf "  %-8s [%-4s] %s\n" "$req" "$status" "$desc"
    done
    echo ""
    echo "  PASS=$PASS FAIL=$FAIL WARN=$WARN TOTAL=$TOTAL"
} > "$REPORT_FILE"

echo "  Informe guardado: $REPORT_FILE"

# Copiar a evidencias
cp "$REPORT_FILE" "$EVIDENCE_DIR/pci-dss/"
echo "  Evidencia guardada: $EVIDENCE_DIR/pci-dss/"
PCIEOF

    chmod 755 "$PCI_SCRIPT"
    log_change "Creado" "$PCI_SCRIPT (evaluacion PCI-DSS v4.0, 12 requisitos)"

else
    log_skip "Script de evaluacion PCI-DSS v4.0"
fi

# ============================================================
# S3: EVALUACION GDPR (PROTECCION DE DATOS)
# ============================================================
log_section "S3: Evaluacion GDPR (proteccion de datos)"

log_info "Script de evaluacion GDPR:"
log_info "  - Art.25: Privacy by design"
log_info "  - Art.30: Registros de procesamiento"
log_info "  - Art.32: Seguridad del procesamiento"
log_info "  - Art.33: Notificacion de brechas"
log_info "  - Art.35: Evaluacion de impacto (DPIA)"

if ask "¿Crear script de evaluacion GDPR?"; then

    GDPR_SCRIPT="$COMPLIANCE_BIN_DIR/evaluar-gdpr.sh"

    cat > "$GDPR_SCRIPT" << 'GDPREOF'
#!/bin/bash
# ============================================================
# evaluar-gdpr.sh - Evaluacion GDPR (Reglamento General de
#                    Proteccion de Datos)
# Parte del Modulo 54 - Cumplimiento Normativo
# ============================================================
set -euo pipefail

CONF_FILE="/etc/securizar/compliance-framework.conf"
[[ -f "$CONF_FILE" ]] && source "$CONF_FILE"

EVIDENCE_DIR="${EVIDENCE_DIR:-/var/lib/securizar/compliance-evidence}"
REPORT_DIR="${REPORT_DIR:-/var/log/securizar/compliance-reports}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
REPORT_FILE="$REPORT_DIR/gdpr-${TIMESTAMP}.txt"

mkdir -p "$REPORT_DIR" "$EVIDENCE_DIR/gdpr"

PASS=0
FAIL=0
WARN=0
TOTAL=0
RESULTS=()

check_gdpr() {
    local art="$1" status="$2" desc="$3"
    RESULTS+=("$art|$status|$desc")
    (( TOTAL++ )) || true
    case "$status" in
        PASS) (( PASS++ )) || true ;;
        FAIL) (( FAIL++ )) || true ;;
        WARN) (( WARN++ )) || true ;;
    esac
}

echo "============================================================"
echo "  Evaluacion GDPR - Securizar"
echo "  Fecha: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "  Host:  $(hostname)"
echo "============================================================"
echo ""

# ── Art. 25: Privacy by Design ───────────────────────────
echo "[Art.25] Proteccion de datos desde el diseno y por defecto..."
ART25="PASS"
ART25_DESC=""

# Verificar cifrado de disco
if lsblk -o TYPE 2>/dev/null | grep -q 'crypt'; then
    ART25_DESC="Cifrado de disco detectado"
else
    ART25="WARN"
    ART25_DESC="No se detecta cifrado de disco (recomendado para privacy by design)"
fi

# Verificar pseudonimizacion (herramientas)
if command -v gpg &>/dev/null; then
    ART25_DESC="${ART25_DESC}; GPG disponible para cifrado de datos"
fi

# Verificar que /tmp esta en tmpfs (datos temporales no persisten)
if mount | grep -q 'tmpfs on /tmp'; then
    ART25_DESC="${ART25_DESC}; /tmp en tmpfs (datos temporales no persisten)"
fi

check_gdpr "Art.25" "$ART25" "$ART25_DESC"
echo "  [$ART25] $ART25_DESC"

# ── Art. 30: Registros de actividades de procesamiento ───
echo "[Art.30] Registros de actividades de procesamiento..."
ART30="FAIL"
ART30_DESC="No se encontro inventario de procesamiento de datos"

# Verificar inventario de datos
if [[ -f /etc/securizar/gdpr-data-inventory.conf ]]; then
    INVENTORY_LINES=$(grep -cvE '^\s*#|^\s*$' /etc/securizar/gdpr-data-inventory.conf 2>/dev/null || echo "0")
    if [[ "$INVENTORY_LINES" -gt 0 ]]; then
        ART30="PASS"
        ART30_DESC="Inventario de datos encontrado ($INVENTORY_LINES entradas)"
    else
        ART30="WARN"
        ART30_DESC="Inventario de datos existe pero esta vacio (rellenar plantilla)"
    fi
fi

# Verificar audit logs
if command -v auditctl &>/dev/null && systemctl is-active auditd &>/dev/null; then
    ART30_DESC="${ART30_DESC}; auditd activo para registro de accesos"
fi

check_gdpr "Art.30" "$ART30" "$ART30_DESC"
echo "  [$ART30] $ART30_DESC"

# ── Art. 32: Seguridad del procesamiento ─────────────────
echo "[Art.32] Seguridad del procesamiento..."
ART32_SCORE=0
ART32_MAX=4
ART32_DETAILS=""

# a) Cifrado
if command -v openssl &>/dev/null; then
    (( ART32_SCORE++ )) || true
    ART32_DETAILS="Cifrado: OpenSSL disponible"
fi

# b) Confidencialidad - control de acceso
if [[ -f /etc/pam.d/system-auth ]] || [[ -f /etc/pam.d/common-auth ]]; then
    (( ART32_SCORE++ )) || true
    ART32_DETAILS="${ART32_DETAILS}; Control de acceso PAM configurado"
fi

# c) Resiliencia
if systemctl is-active auditd &>/dev/null; then
    (( ART32_SCORE++ )) || true
    ART32_DETAILS="${ART32_DETAILS}; Auditoria de sistema activa"
fi

# d) Capacidad de restauracion
BACKUP_TOOLS=0
for tool in rsync borgbackup restic tar; do
    command -v "$tool" &>/dev/null && (( BACKUP_TOOLS++ )) || true
done
if [[ $BACKUP_TOOLS -gt 0 ]]; then
    (( ART32_SCORE++ )) || true
    ART32_DETAILS="${ART32_DETAILS}; Herramientas de backup disponibles ($BACKUP_TOOLS)"
fi

if [[ $ART32_SCORE -ge 3 ]]; then
    ART32="PASS"
elif [[ $ART32_SCORE -ge 2 ]]; then
    ART32="WARN"
else
    ART32="FAIL"
fi

check_gdpr "Art.32" "$ART32" "Seguridad: $ART32_SCORE/$ART32_MAX - $ART32_DETAILS"
echo "  [$ART32] Seguridad: $ART32_SCORE/$ART32_MAX - $ART32_DETAILS"

# ── Art. 33: Notificacion de brechas ─────────────────────
echo "[Art.33] Notificacion de brechas de datos personales..."
ART33="FAIL"
ART33_DESC="No se encontraron procedimientos de respuesta a incidentes"

# Verificar procedimientos de IR
IR_FOUND=0
for irfile in /etc/securizar/incident-response.conf /usr/local/share/securizar/ir-playbook* /etc/securizar/respuesta-incidentes*; do
    if [[ -f "$irfile" ]] 2>/dev/null; then
        IR_FOUND=1
        break
    fi
done

if [[ $IR_FOUND -eq 1 ]]; then
    ART33="PASS"
    ART33_DESC="Procedimientos de respuesta a incidentes encontrados"
fi

# Verificar si existe script de respuesta a incidentes
if [[ -f /usr/local/bin/securizar-incident-response.sh ]] || command -v respuesta-incidentes &>/dev/null; then
    ART33_DESC="${ART33_DESC}; Script de respuesta a incidentes disponible"
    [[ "$ART33" == "FAIL" ]] && ART33="WARN"
fi

# Verificar alertas configuradas
if command -v mail &>/dev/null || command -v sendmail &>/dev/null; then
    ART33_DESC="${ART33_DESC}; Sistema de correo disponible para notificaciones"
fi

check_gdpr "Art.33" "$ART33" "$ART33_DESC"
echo "  [$ART33] $ART33_DESC"

# ── Art. 35: Evaluacion de impacto (DPIA) ────────────────
echo "[Art.35] Evaluacion de impacto sobre proteccion de datos..."
ART35="WARN"
ART35_DESC="Se recomienda completar una DPIA formal"

# Verificar si existe plantilla/documento DPIA
if find /etc/securizar -name "*dpia*" -o -name "*impacto*" 2>/dev/null | grep -q .; then
    ART35="PASS"
    ART35_DESC="Documentacion DPIA encontrada"
fi

check_gdpr "Art.35" "$ART35" "$ART35_DESC"
echo "  [$ART35] $ART35_DESC"

# ── Minimizacion de datos ────────────────────────────────
echo "[MinDat] Principio de minimizacion de datos..."
MINDAT="WARN"
MINDAT_DESC="Verificar manualmente que solo se recopilan datos necesarios"

# Verificar log rotation (no retener logs excesivos)
if [[ -f /etc/logrotate.conf ]] || [[ -d /etc/logrotate.d ]]; then
    MINDAT_DESC="logrotate configurado (limita retencion de datos en logs)"
    MINDAT="PASS"
fi

# Verificar retencion de journal
if [[ -f /etc/systemd/journald.conf ]]; then
    if grep -qE '^\s*MaxRetentionSec=' /etc/systemd/journald.conf 2>/dev/null; then
        MINDAT_DESC="${MINDAT_DESC}; Retencion de journal limitada"
    fi
fi

check_gdpr "MinDat" "$MINDAT" "$MINDAT_DESC"
echo "  [$MINDAT] $MINDAT_DESC"

# ── Derecho al olvido (secure deletion) ──────────────────
echo "[Olvido] Derecho al olvido - herramientas de borrado seguro..."
OLVIDO="WARN"
OLVIDO_DESC="No se detectan herramientas de borrado seguro"

if command -v shred &>/dev/null; then
    OLVIDO="PASS"
    OLVIDO_DESC="shred disponible para borrado seguro"
fi
if command -v wipe &>/dev/null; then
    OLVIDO="PASS"
    OLVIDO_DESC="${OLVIDO_DESC}; wipe disponible"
fi
if command -v srm &>/dev/null; then
    OLVIDO="PASS"
    OLVIDO_DESC="${OLVIDO_DESC}; srm disponible"
fi

check_gdpr "Olvido" "$OLVIDO" "$OLVIDO_DESC"
echo "  [$OLVIDO] $OLVIDO_DESC"

# ── Informe GDPR ─────────────────────────────────────────
echo ""
echo "============================================================"
echo "  INFORME GDPR - RESUMEN"
echo "============================================================"

SCORE=0
[[ $TOTAL -gt 0 ]] && SCORE=$(( (PASS * 100) / TOTAL ))

echo ""
echo "  Controles evaluados: $TOTAL"
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
echo "  WARN: $WARN"
echo "  Puntuacion: ${SCORE}%"
echo ""

if [[ $SCORE -ge 80 ]]; then
    RATING="BUENO"
elif [[ $SCORE -ge 50 ]]; then
    RATING="MEJORABLE"
else
    RATING="DEFICIENTE"
fi
echo "  Calificacion: $RATING"

# Guardar informe
{
    echo "============================================================"
    echo "  INFORME GDPR"
    echo "  Fecha: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "  Host:  $(hostname)"
    echo "  Score: ${SCORE}% ($RATING)"
    echo "============================================================"
    echo ""
    for r in "${RESULTS[@]}"; do
        IFS='|' read -r art status desc <<< "$r"
        printf "  %-10s [%-4s] %s\n" "$art" "$status" "$desc"
    done
    echo ""
    echo "  PASS=$PASS FAIL=$FAIL WARN=$WARN TOTAL=$TOTAL"
} > "$REPORT_FILE"

echo "  Informe guardado: $REPORT_FILE"
cp "$REPORT_FILE" "$EVIDENCE_DIR/gdpr/"
GDPREOF

    chmod 755 "$GDPR_SCRIPT"
    log_change "Creado" "$GDPR_SCRIPT (evaluacion GDPR, 7 controles)"

else
    log_skip "Script de evaluacion GDPR"
fi

# ============================================================
# S4: EVALUACION HIPAA (SALUD)
# ============================================================
log_section "S4: Evaluacion HIPAA (salud)"

log_info "Script de evaluacion HIPAA:"
log_info "  - Administrative Safeguards"
log_info "  - Physical Safeguards"
log_info "  - Technical Safeguards"
log_info "  - Cifrado en reposo y en transito"
log_info "  - Audit logging para ePHI"

if ask "¿Crear script de evaluacion HIPAA?"; then

    HIPAA_SCRIPT="$COMPLIANCE_BIN_DIR/evaluar-hipaa.sh"

    cat > "$HIPAA_SCRIPT" << 'HIPAAEOF'
#!/bin/bash
# ============================================================
# evaluar-hipaa.sh - Evaluacion HIPAA
# (Health Insurance Portability and Accountability Act)
# Parte del Modulo 54 - Cumplimiento Normativo
# ============================================================
set -euo pipefail

CONF_FILE="/etc/securizar/compliance-framework.conf"
[[ -f "$CONF_FILE" ]] && source "$CONF_FILE"

EVIDENCE_DIR="${EVIDENCE_DIR:-/var/lib/securizar/compliance-evidence}"
REPORT_DIR="${REPORT_DIR:-/var/log/securizar/compliance-reports}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
REPORT_FILE="$REPORT_DIR/hipaa-${TIMESTAMP}.txt"

mkdir -p "$REPORT_DIR" "$EVIDENCE_DIR/hipaa"

PASS=0
FAIL=0
WARN=0
TOTAL=0
RESULTS=()

check_hipaa() {
    local ctrl="$1" status="$2" desc="$3"
    RESULTS+=("$ctrl|$status|$desc")
    (( TOTAL++ )) || true
    case "$status" in
        PASS) (( PASS++ )) || true ;;
        FAIL) (( FAIL++ )) || true ;;
        WARN) (( WARN++ )) || true ;;
    esac
}

echo "============================================================"
echo "  Evaluacion HIPAA - Securizar"
echo "  Fecha: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "  Host:  $(hostname)"
echo "============================================================"
echo ""

# ── ADMINISTRATIVE SAFEGUARDS ────────────────────────────
echo "=== ADMINISTRATIVE SAFEGUARDS ==="

# 164.308(a)(1) - Risk Analysis
echo "[AS-1] Analisis de riesgo (164.308(a)(1))..."
AS1="WARN"
AS1_DESC="Se recomienda documentar un analisis de riesgo formal"

if [[ -f /etc/securizar/risk-analysis.conf ]] || find /etc/securizar -name "*riesgo*" -o -name "*risk*" 2>/dev/null | grep -q .; then
    AS1="PASS"
    AS1_DESC="Documentacion de analisis de riesgo encontrada"
fi

# Verificar si se ejecutan auditorias regulares
if command -v lynis &>/dev/null; then
    AS1_DESC="${AS1_DESC}; lynis disponible para evaluacion de riesgos"
fi

check_hipaa "AS-Risk" "$AS1" "$AS1_DESC"
echo "  [$AS1] $AS1_DESC"

# 164.308(a)(5) - Security Awareness Training
echo "[AS-2] Formacion en seguridad (164.308(a)(5))..."
AS2="WARN"
AS2_DESC="Verificar manualmente que existe programa de formacion en seguridad"

if [[ -f /etc/issue ]] && [[ -s /etc/issue ]]; then
    AS2_DESC="${AS2_DESC}; Banner de seguridad configurado"
fi

check_hipaa "AS-Train" "$AS2" "$AS2_DESC"
echo "  [$AS2] $AS2_DESC"

# 164.308(a)(6) - Incident Response
echo "[AS-3] Procedimientos de respuesta a incidentes (164.308(a)(6))..."
AS3="FAIL"
AS3_DESC="No se detectan procedimientos de respuesta a incidentes"

for irfile in /etc/securizar/incident-response* /usr/local/bin/respuesta-incidentes* /usr/local/share/securizar/ir-*; do
    if [[ -f "$irfile" ]] 2>/dev/null; then
        AS3="PASS"
        AS3_DESC="Procedimientos de IR encontrados"
        break
    fi
done

check_hipaa "AS-IR" "$AS3" "$AS3_DESC"
echo "  [$AS3] $AS3_DESC"

# ── PHYSICAL SAFEGUARDS ─────────────────────────────────
echo ""
echo "=== PHYSICAL SAFEGUARDS ==="

# 164.310(b) - Workstation Use
echo "[PS-1] Seguridad de estacion de trabajo (164.310(b))..."
PS1="PASS"
PS1_DESC="Controles de estacion de trabajo"

# Verificar bloqueo de pantalla
SCREEN_LOCK=0
if command -v xdg-screensaver &>/dev/null || [[ -f /etc/dconf/db/local.d/00-screensaver ]]; then
    SCREEN_LOCK=1
    PS1_DESC="Bloqueo de pantalla disponible"
fi

# Verificar timeout de sesion
if grep -qE '^\s*TMOUT=' /etc/profile /etc/profile.d/*.sh 2>/dev/null; then
    PS1_DESC="${PS1_DESC}; TMOUT configurado"
else
    PS1="WARN"
    PS1_DESC="${PS1_DESC}; TMOUT no configurado (sesion sin timeout)"
fi

check_hipaa "PS-Work" "$PS1" "$PS1_DESC"
echo "  [$PS1] $PS1_DESC"

# 164.310(d) - Device and Media Controls
echo "[PS-2] Controles de dispositivos y medios (164.310(d))..."
PS2="WARN"
PS2_DESC="Verificar politicas de control de medios extraibles"

# Verificar USB deshabilitado
if [[ -f /etc/modprobe.d/usb-storage.conf ]] && grep -q 'install usb-storage /bin/true\|blacklist usb-storage' /etc/modprobe.d/usb-storage.conf 2>/dev/null; then
    PS2="PASS"
    PS2_DESC="USB storage deshabilitado"
fi

# Verificar secure deletion
if command -v shred &>/dev/null; then
    PS2_DESC="${PS2_DESC}; shred disponible para borrado seguro de medios"
fi

check_hipaa "PS-Media" "$PS2" "$PS2_DESC"
echo "  [$PS2] $PS2_DESC"

# ── TECHNICAL SAFEGUARDS ─────────────────────────────────
echo ""
echo "=== TECHNICAL SAFEGUARDS ==="

# 164.312(a) - Access Control
echo "[TS-1] Control de acceso (164.312(a))..."
TS1="PASS"
TS1_DESC="Controles de acceso verificados"

# Verificar que root login esta restringido
if [[ -f /etc/ssh/sshd_config ]]; then
    PERMIT_ROOT=$(grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "")
    if [[ "$PERMIT_ROOT" == "yes" ]]; then
        TS1="WARN"
        TS1_DESC="SSH PermitRootLogin=yes (debe ser no o prohibit-password)"
    fi
fi

# Verificar PAM
if [[ -d /etc/pam.d ]]; then
    TS1_DESC="${TS1_DESC}; PAM configurado"
fi

# Verificar accounts sin contrasena
NOPW=$(awk -F: '($2 == "" ) {print $1}' /etc/shadow 2>/dev/null | wc -l || echo "0")
if [[ "$NOPW" -gt 0 ]]; then
    TS1="FAIL"
    TS1_DESC="$NOPW cuentas sin contrasena detectadas"
fi

check_hipaa "TS-Access" "$TS1" "$TS1_DESC"
echo "  [$TS1] $TS1_DESC"

# 164.312(b) - Audit Controls
echo "[TS-2] Controles de auditoria (164.312(b))..."
TS2="FAIL"
TS2_DESC="auditd no detectado"

if command -v auditctl &>/dev/null && systemctl is-active auditd &>/dev/null; then
    TS2="PASS"
    TS2_DESC="auditd activo"

    # Verificar reglas minimas
    RULES_COUNT=$(auditctl -l 2>/dev/null | wc -l || echo "0")
    TS2_DESC="${TS2_DESC}; $RULES_COUNT reglas de auditoria"

    if [[ "$RULES_COUNT" -lt 5 ]]; then
        TS2="WARN"
        TS2_DESC="${TS2_DESC} (pocas reglas - revisar configuracion)"
    fi
elif systemctl is-active systemd-journald &>/dev/null; then
    TS2="WARN"
    TS2_DESC="journald activo pero auditd recomendado para HIPAA"
fi

check_hipaa "TS-Audit" "$TS2" "$TS2_DESC"
echo "  [$TS2] $TS2_DESC"

# 164.312(c) - Integrity Controls
echo "[TS-3] Controles de integridad (164.312(c))..."
TS3="FAIL"
TS3_DESC="No se detecta sistema de control de integridad"

if command -v aide &>/dev/null; then
    TS3="PASS"
    TS3_DESC="AIDE instalado para monitoreo de integridad"
    if [[ -f /var/lib/aide/aide.db ]] || [[ -f /var/lib/aide/aide.db.gz ]]; then
        TS3_DESC="${TS3_DESC}; base de datos inicializada"
    else
        TS3="WARN"
        TS3_DESC="${TS3_DESC}; base de datos NO inicializada (ejecutar aide --init)"
    fi
fi

if command -v tripwire &>/dev/null; then
    TS3="PASS"
    TS3_DESC="${TS3_DESC}; tripwire disponible"
fi

check_hipaa "TS-Integ" "$TS3" "$TS3_DESC"
echo "  [$TS3] $TS3_DESC"

# 164.312(e) - Transmission Security
echo "[TS-4] Seguridad de transmision (164.312(e))..."
TS4="PASS"
TS4_DESC="Seguridad de transmision verificada"

# Verificar SSH
if systemctl is-active sshd &>/dev/null || systemctl is-active ssh &>/dev/null; then
    TS4_DESC="SSH activo para comunicaciones cifradas"
fi

# Verificar TLS
if command -v openssl &>/dev/null; then
    OPENSSL_VER=$(openssl version 2>/dev/null | awk '{print $2}' || echo "")
    TS4_DESC="${TS4_DESC}; OpenSSL $OPENSSL_VER"
fi

# Verificar que telnet no esta activo
if systemctl is-active telnet &>/dev/null || systemctl is-active xinetd &>/dev/null; then
    if [[ -f /etc/xinetd.d/telnet ]] && grep -q 'disable.*=.*no' /etc/xinetd.d/telnet 2>/dev/null; then
        TS4="FAIL"
        TS4_DESC="telnet activo (comunicacion sin cifrar)"
    fi
fi

check_hipaa "TS-Trans" "$TS4" "$TS4_DESC"
echo "  [$TS4] $TS4_DESC"

# ── Cifrado en reposo ────────────────────────────────────
echo "[TS-5] Cifrado de datos en reposo..."
TS5="WARN"
TS5_DESC="No se detecta cifrado de disco completo"

if lsblk -o TYPE 2>/dev/null | grep -q 'crypt'; then
    TS5="PASS"
    TS5_DESC="Volumenes cifrados detectados (LUKS/dm-crypt)"
fi

if command -v cryptsetup &>/dev/null; then
    TS5_DESC="${TS5_DESC}; cryptsetup disponible"
fi

check_hipaa "TS-EncRest" "$TS5" "$TS5_DESC"
echo "  [$TS5] $TS5_DESC"

# ── Backup y recuperacion ────────────────────────────────
echo "[TS-6] Backup y recuperacion de datos..."
TS6="WARN"
TS6_DESC="Verificar que existe plan de backup y recuperacion"

# Verificar cron de backups
BACKUP_CRON=0
if [[ -d /etc/cron.daily ]] && find /etc/cron.daily -name "*backup*" 2>/dev/null | grep -q .; then
    BACKUP_CRON=1
fi
if [[ -d /etc/cron.weekly ]] && find /etc/cron.weekly -name "*backup*" 2>/dev/null | grep -q .; then
    BACKUP_CRON=1
fi
if crontab -l 2>/dev/null | grep -qi 'backup'; then
    BACKUP_CRON=1
fi

if [[ $BACKUP_CRON -eq 1 ]]; then
    TS6="PASS"
    TS6_DESC="Backup automatizado detectado en cron"
fi

# Verificar herramientas
for tool in borgbackup restic rsync; do
    if command -v "$tool" &>/dev/null; then
        TS6_DESC="${TS6_DESC}; $tool disponible"
    fi
done

check_hipaa "TS-Backup" "$TS6" "$TS6_DESC"
echo "  [$TS6] $TS6_DESC"

# ── Informe HIPAA ────────────────────────────────────────
echo ""
echo "============================================================"
echo "  INFORME HIPAA - RESUMEN"
echo "============================================================"

SCORE=0
[[ $TOTAL -gt 0 ]] && SCORE=$(( (PASS * 100) / TOTAL ))

echo ""
echo "  Controles evaluados: $TOTAL"
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
echo "  WARN: $WARN"
echo "  Puntuacion: ${SCORE}%"
echo ""

if [[ $SCORE -ge 80 ]]; then
    RATING="BUENO"
elif [[ $SCORE -ge 50 ]]; then
    RATING="MEJORABLE"
else
    RATING="DEFICIENTE"
fi
echo "  Calificacion: $RATING"

# Guardar informe
{
    echo "============================================================"
    echo "  INFORME HIPAA"
    echo "  Fecha: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "  Host:  $(hostname)"
    echo "  Score: ${SCORE}% ($RATING)"
    echo "============================================================"
    echo ""
    for r in "${RESULTS[@]}"; do
        IFS='|' read -r ctrl status desc <<< "$r"
        printf "  %-12s [%-4s] %s\n" "$ctrl" "$status" "$desc"
    done
    echo ""
    echo "  PASS=$PASS FAIL=$FAIL WARN=$WARN TOTAL=$TOTAL"
    echo ""
    echo "  Nota: HIPAA requiere evaluaciones regulares y documentacion"
    echo "  formal adicional que no puede verificarse automaticamente."
} > "$REPORT_FILE"

echo "  Informe guardado: $REPORT_FILE"
cp "$REPORT_FILE" "$EVIDENCE_DIR/hipaa/"
echo "  Evidencia guardada: $EVIDENCE_DIR/hipaa/"
HIPAAEOF

    chmod 755 "$HIPAA_SCRIPT"
    log_change "Creado" "$HIPAA_SCRIPT (evaluacion HIPAA, safeguards administrativos/fisicos/tecnicos)"

else
    log_skip "Script de evaluacion HIPAA"
fi

# ============================================================
# S5: EVALUACION SOC 2 (TYPE II)
# ============================================================
log_section "S5: Evaluacion SOC 2 (Type II)"

log_info "Script de evaluacion SOC 2 Trust Service Criteria:"
log_info "  - Security, Availability, Processing Integrity"
log_info "  - Confidentiality, Privacy"

if ask "¿Crear script de evaluacion SOC 2?"; then

    SOC2_SCRIPT="$COMPLIANCE_BIN_DIR/evaluar-soc2.sh"

    cat > "$SOC2_SCRIPT" << 'SOC2EOF'
#!/bin/bash
# ============================================================
# evaluar-soc2.sh - Evaluacion SOC 2 Type II
# Trust Service Criteria (TSC)
# Parte del Modulo 54 - Cumplimiento Normativo
# ============================================================
set -euo pipefail

CONF_FILE="/etc/securizar/compliance-framework.conf"
[[ -f "$CONF_FILE" ]] && source "$CONF_FILE"

EVIDENCE_DIR="${EVIDENCE_DIR:-/var/lib/securizar/compliance-evidence}"
REPORT_DIR="${REPORT_DIR:-/var/log/securizar/compliance-reports}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
REPORT_FILE="$REPORT_DIR/soc2-${TIMESTAMP}.txt"

mkdir -p "$REPORT_DIR" "$EVIDENCE_DIR/soc2"

PASS=0
FAIL=0
WARN=0
TOTAL=0
RESULTS=()

check_soc2() {
    local ctrl="$1" status="$2" desc="$3"
    RESULTS+=("$ctrl|$status|$desc")
    (( TOTAL++ )) || true
    case "$status" in
        PASS) (( PASS++ )) || true ;;
        FAIL) (( FAIL++ )) || true ;;
        WARN) (( WARN++ )) || true ;;
    esac
}

echo "============================================================"
echo "  Evaluacion SOC 2 Type II - Securizar"
echo "  Fecha: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "  Host:  $(hostname)"
echo "============================================================"
echo ""

# ── TSC: SECURITY ────────────────────────────────────────
echo "=== SECURITY (Seguridad) ==="

# CC6.1 - Logical and Physical Access Controls
echo "[SEC-1] Control de acceso logico (CC6.1)..."
SEC1="PASS"
SEC1_DESC="Control de acceso logico"

# Verificar PAM
if [[ -d /etc/pam.d ]]; then
    SEC1_DESC="PAM configurado"
else
    SEC1="FAIL"
    SEC1_DESC="PAM no detectado"
fi

# Verificar sudo configurado
if [[ -f /etc/sudoers ]]; then
    SUDO_ALL=$(grep -cE 'ALL.*=.*\(ALL\).*ALL' /etc/sudoers /etc/sudoers.d/* 2>/dev/null || echo "0")
    if [[ "$SUDO_ALL" -gt 2 ]]; then
        SEC1="WARN"
        SEC1_DESC="${SEC1_DESC}; Exceso de usuarios con sudo ALL ($SUDO_ALL entradas)"
    fi
fi

# Verificar SSH key-based auth
if [[ -f /etc/ssh/sshd_config ]]; then
    if grep -qE '^\s*PasswordAuthentication\s+no' /etc/ssh/sshd_config 2>/dev/null; then
        SEC1_DESC="${SEC1_DESC}; SSH solo autenticacion por clave"
    fi
fi

check_soc2 "SEC-Access" "$SEC1" "$SEC1_DESC"
echo "  [$SEC1] $SEC1_DESC"

# CC6.6 - System Boundaries / Network Security
echo "[SEC-2] Seguridad de red (CC6.6)..."
SEC2="FAIL"
SEC2_DESC="Firewall no detectado"

if command -v nft &>/dev/null && nft list ruleset 2>/dev/null | grep -q 'chain'; then
    SEC2="PASS"
    SEC2_DESC="nftables activo"
elif command -v iptables &>/dev/null && iptables -L -n 2>/dev/null | grep -qE 'DROP|REJECT'; then
    SEC2="PASS"
    SEC2_DESC="iptables activo con reglas restrictivas"
elif command -v firewall-cmd &>/dev/null && firewall-cmd --state 2>/dev/null | grep -q 'running'; then
    SEC2="PASS"
    SEC2_DESC="firewalld activo"
fi

check_soc2 "SEC-Network" "$SEC2" "$SEC2_DESC"
echo "  [$SEC2] $SEC2_DESC"

# CC8.1 - Change Management
echo "[SEC-3] Gestion de cambios (CC8.1)..."
SEC3="WARN"
SEC3_DESC="Verificar proceso de gestion de cambios documentado"

# Verificar si git esta instalado (control de versiones)
if command -v git &>/dev/null; then
    SEC3_DESC="git disponible para control de versiones"
fi

# Verificar etckeeper (control de cambios en /etc)
if command -v etckeeper &>/dev/null; then
    SEC3="PASS"
    SEC3_DESC="${SEC3_DESC}; etckeeper activo (control de cambios en /etc)"
fi

# Verificar AIDE
if command -v aide &>/dev/null; then
    SEC3_DESC="${SEC3_DESC}; AIDE para deteccion de cambios no autorizados"
fi

check_soc2 "SEC-Change" "$SEC3" "$SEC3_DESC"
echo "  [$SEC3] $SEC3_DESC"

# ── TSC: AVAILABILITY ───────────────────────────────────
echo ""
echo "=== AVAILABILITY (Disponibilidad) ==="

# A1.1 - System Availability
echo "[AVL-1] Monitoreo de disponibilidad (A1.1)..."
AVL1="WARN"
AVL1_DESC="Sin monitoreo de disponibilidad detectado"

if systemctl is-active nagios &>/dev/null || systemctl is-active zabbix-agent &>/dev/null || \
   systemctl is-active prometheus-node-exporter &>/dev/null || systemctl is-active collectd &>/dev/null; then
    AVL1="PASS"
    AVL1_DESC="Agente de monitoreo activo"
fi

# Verificar uptime
UPTIME_DAYS=$(awk '{print int($1/86400)}' /proc/uptime 2>/dev/null || echo "0")
AVL1_DESC="${AVL1_DESC}; Uptime: ${UPTIME_DAYS} dias"

check_soc2 "AVL-Monitor" "$AVL1" "$AVL1_DESC"
echo "  [$AVL1] $AVL1_DESC"

# A1.2 - Backup & DR
echo "[AVL-2] Backup y recuperacion ante desastres (A1.2)..."
AVL2="WARN"
AVL2_DESC="Verificar plan de DR documentado"

BACKUP_TOOLS_COUNT=0
for tool in borgbackup restic rsync duplicity; do
    command -v "$tool" &>/dev/null && (( BACKUP_TOOLS_COUNT++ )) || true
done

if [[ $BACKUP_TOOLS_COUNT -gt 0 ]]; then
    AVL2_DESC="Herramientas de backup disponibles ($BACKUP_TOOLS_COUNT)"
fi

# Verificar crons de backup
if find /etc/cron.daily /etc/cron.weekly 2>/dev/null -name "*backup*" | grep -q .; then
    AVL2="PASS"
    AVL2_DESC="${AVL2_DESC}; Backup automatizado en cron"
fi

check_soc2 "AVL-Backup" "$AVL2" "$AVL2_DESC"
echo "  [$AVL2] $AVL2_DESC"

# A1.3 - Incident Response
echo "[AVL-3] Respuesta a incidentes (A1.3)..."
AVL3="FAIL"
AVL3_DESC="No se detectan procedimientos de IR"

for irfile in /etc/securizar/incident-response* /usr/local/bin/respuesta-incidentes* /usr/local/bin/securizar-incident*; do
    if [[ -f "$irfile" ]] 2>/dev/null; then
        AVL3="PASS"
        AVL3_DESC="Procedimientos de IR encontrados"
        break
    fi
done

check_soc2 "AVL-IR" "$AVL3" "$AVL3_DESC"
echo "  [$AVL3] $AVL3_DESC"

# ── TSC: PROCESSING INTEGRITY ───────────────────────────
echo ""
echo "=== PROCESSING INTEGRITY (Integridad de procesamiento) ==="

# PI1.1 - Input Validation
echo "[PI-1] Integridad de procesamiento (PI1.1)..."
PI1="WARN"
PI1_DESC="Verificar validacion de entrada en aplicaciones"

# Verificar WAF (ModSecurity, etc)
if [[ -d /etc/modsecurity ]] || [[ -f /etc/nginx/modsecurity.conf ]]; then
    PI1="PASS"
    PI1_DESC="ModSecurity (WAF) detectado"
fi

check_soc2 "PI-Valid" "$PI1" "$PI1_DESC"
echo "  [$PI1] $PI1_DESC"

# PI1.2 - Error Handling
echo "[PI-2] Manejo de errores (PI1.2)..."
PI2="PASS"
PI2_DESC="Logging de errores"

if [[ -d /var/log ]] && [[ -f /var/log/syslog ]] || [[ -f /var/log/messages ]]; then
    PI2_DESC="Logs del sistema disponibles para deteccion de errores"
fi

if systemctl is-active systemd-journald &>/dev/null; then
    PI2_DESC="${PI2_DESC}; journald activo"
fi

check_soc2 "PI-Error" "$PI2" "$PI2_DESC"
echo "  [$PI2] $PI2_DESC"

# ── TSC: CONFIDENTIALITY ────────────────────────────────
echo ""
echo "=== CONFIDENTIALITY (Confidencialidad) ==="

# C1.1 - Data Classification
echo "[CON-1] Clasificacion de datos (C1.1)..."
CON1="WARN"
CON1_DESC="Verificar politica de clasificacion de datos"

if [[ -f /etc/securizar/data-classification.conf ]] || [[ -f /etc/securizar/gdpr-data-inventory.conf ]]; then
    CON1="PASS"
    CON1_DESC="Inventario/clasificacion de datos encontrado"
fi

check_soc2 "CON-Class" "$CON1" "$CON1_DESC"
echo "  [$CON1] $CON1_DESC"

# C1.2 - Encryption
echo "[CON-2] Cifrado de datos (C1.2)..."
CON2="PASS"
CON2_DESC="Capacidades de cifrado"

if command -v openssl &>/dev/null; then
    CON2_DESC="OpenSSL disponible"
fi

if command -v gpg &>/dev/null; then
    CON2_DESC="${CON2_DESC}; GPG disponible"
fi

# Cifrado de disco
if lsblk -o TYPE 2>/dev/null | grep -q 'crypt'; then
    CON2_DESC="${CON2_DESC}; Cifrado de disco activo"
else
    CON2="WARN"
    CON2_DESC="${CON2_DESC}; Sin cifrado de disco completo"
fi

check_soc2 "CON-Encrypt" "$CON2" "$CON2_DESC"
echo "  [$CON2] $CON2_DESC"

# C1.3 - Access Control to Confidential Data
echo "[CON-3] Control de acceso a datos confidenciales (C1.3)..."
CON3="PASS"
CON3_DESC="Permisos de archivos verificados"

# Verificar permisos criticos
SHADOW_P=$(stat -c '%a' /etc/shadow 2>/dev/null || echo "000")
if [[ "$SHADOW_P" != "000" ]] && [[ "$SHADOW_P" != "600" ]] && [[ "$SHADOW_P" != "640" ]]; then
    CON3="FAIL"
    CON3_DESC="/etc/shadow permisos incorrectos: $SHADOW_P"
fi

# Verificar /etc/securizar permisos
if [[ -d /etc/securizar ]]; then
    SECURIZAR_P=$(stat -c '%a' /etc/securizar 2>/dev/null || echo "")
    if [[ -n "$SECURIZAR_P" ]] && [[ "$SECURIZAR_P" != "700" ]] && [[ "$SECURIZAR_P" != "750" ]] && [[ "$SECURIZAR_P" != "755" ]]; then
        CON3="WARN"
        CON3_DESC="${CON3_DESC}; /etc/securizar permisos: $SECURIZAR_P"
    fi
fi

check_soc2 "CON-Access" "$CON3" "$CON3_DESC"
echo "  [$CON3] $CON3_DESC"

# ── TSC: PRIVACY ────────────────────────────────────────
echo ""
echo "=== PRIVACY (Privacidad) ==="

# P1.1 - PII Handling
echo "[PRV-1] Manejo de PII (P1.1)..."
PRV1="WARN"
PRV1_DESC="Verificar politicas de manejo de datos personales"

if [[ -f /etc/securizar/gdpr-data-inventory.conf ]]; then
    PRV1_DESC="Inventario de datos personales encontrado"
    FILLED=$(grep -cvE '^\s*#|^\s*$' /etc/securizar/gdpr-data-inventory.conf 2>/dev/null || echo "0")
    if [[ "$FILLED" -gt 0 ]]; then
        PRV1="PASS"
        PRV1_DESC="${PRV1_DESC} ($FILLED entradas)"
    fi
fi

check_soc2 "PRV-PII" "$PRV1" "$PRV1_DESC"
echo "  [$PRV1] $PRV1_DESC"

# P6.1 - Retention
echo "[PRV-2] Retencion de datos (P6.1)..."
PRV2="WARN"
PRV2_DESC="Verificar politica de retencion de datos"

# Verificar logrotate
if [[ -f /etc/logrotate.conf ]]; then
    PRV2="PASS"
    PRV2_DESC="logrotate configurado para control de retencion de logs"
fi

# Verificar tmpfiles.d (limpieza automatica)
if [[ -d /etc/tmpfiles.d ]] || [[ -d /usr/lib/tmpfiles.d ]]; then
    PRV2_DESC="${PRV2_DESC}; tmpfiles.d configurado"
fi

check_soc2 "PRV-Retain" "$PRV2" "$PRV2_DESC"
echo "  [$PRV2] $PRV2_DESC"

# P4.1 - Consent
echo "[PRV-3] Consentimiento y aviso de privacidad (P4.1)..."
PRV3="WARN"
PRV3_DESC="Verificar avisos de privacidad y consentimiento (proceso manual)"

# Verificar banners
if [[ -f /etc/issue ]] && [[ -s /etc/issue ]]; then
    PRV3_DESC="${PRV3_DESC}; Banner de aviso configurado en /etc/issue"
fi

if [[ -f /etc/motd ]] && [[ -s /etc/motd ]]; then
    PRV3_DESC="${PRV3_DESC}; MOTD configurado"
fi

check_soc2 "PRV-Consent" "$PRV3" "$PRV3_DESC"
echo "  [$PRV3] $PRV3_DESC"

# ── Informe SOC 2 ────────────────────────────────────────
echo ""
echo "============================================================"
echo "  INFORME SOC 2 Type II - RESUMEN"
echo "============================================================"

SCORE=0
[[ $TOTAL -gt 0 ]] && SCORE=$(( (PASS * 100) / TOTAL ))

echo ""
echo "  Controles evaluados: $TOTAL"
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
echo "  WARN: $WARN"
echo "  Puntuacion: ${SCORE}%"
echo ""

if [[ $SCORE -ge 80 ]]; then
    RATING="BUENO"
elif [[ $SCORE -ge 50 ]]; then
    RATING="MEJORABLE"
else
    RATING="DEFICIENTE"
fi
echo "  Calificacion: $RATING"

# Guardar informe
{
    echo "============================================================"
    echo "  INFORME SOC 2 Type II"
    echo "  Fecha: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "  Host:  $(hostname)"
    echo "  Score: ${SCORE}% ($RATING)"
    echo "============================================================"
    echo ""
    echo "  TSC Categories:"
    echo "    Security | Availability | Processing Integrity"
    echo "    Confidentiality | Privacy"
    echo ""
    for r in "${RESULTS[@]}"; do
        IFS='|' read -r ctrl status desc <<< "$r"
        printf "  %-14s [%-4s] %s\n" "$ctrl" "$status" "$desc"
    done
    echo ""
    echo "  PASS=$PASS FAIL=$FAIL WARN=$WARN TOTAL=$TOTAL"
} > "$REPORT_FILE"

echo "  Informe guardado: $REPORT_FILE"
cp "$REPORT_FILE" "$EVIDENCE_DIR/soc2/"
SOC2EOF

    chmod 755 "$SOC2_SCRIPT"
    log_change "Creado" "$SOC2_SCRIPT (evaluacion SOC 2 Type II, 5 categorias TSC)"

else
    log_skip "Script de evaluacion SOC 2"
fi

# ============================================================
# S6: EVALUACION ISO 27001
# ============================================================
log_section "S6: Evaluacion ISO 27001"

log_info "Script de evaluacion ISO 27001 (Annex A controls):"
log_info "  - A.5 Politicas, A.6 Organizacion, A.8 Activos"
log_info "  - A.9 Acceso, A.10 Criptografia, A.12 Operaciones"
log_info "  - A.13 Comunicaciones, A.14 Desarrollo, A.16 Incidentes"
log_info "  - A.18 Cumplimiento"

if ask "¿Crear script de evaluacion ISO 27001?"; then

    ISO_SCRIPT="$COMPLIANCE_BIN_DIR/evaluar-iso27001.sh"

    cat > "$ISO_SCRIPT" << 'ISOEOF'
#!/bin/bash
# ============================================================
# evaluar-iso27001.sh - Evaluacion ISO 27001 (Annex A)
# Parte del Modulo 54 - Cumplimiento Normativo
# ============================================================
set -euo pipefail

CONF_FILE="/etc/securizar/compliance-framework.conf"
[[ -f "$CONF_FILE" ]] && source "$CONF_FILE"

EVIDENCE_DIR="${EVIDENCE_DIR:-/var/lib/securizar/compliance-evidence}"
REPORT_DIR="${REPORT_DIR:-/var/log/securizar/compliance-reports}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
REPORT_FILE="$REPORT_DIR/iso27001-${TIMESTAMP}.txt"

mkdir -p "$REPORT_DIR" "$EVIDENCE_DIR/iso27001"

PASS=0
FAIL=0
WARN=0
TOTAL=0
RESULTS=()

check_iso() {
    local ctrl="$1" status="$2" desc="$3"
    RESULTS+=("$ctrl|$status|$desc")
    (( TOTAL++ )) || true
    case "$status" in
        PASS) (( PASS++ )) || true ;;
        FAIL) (( FAIL++ )) || true ;;
        WARN) (( WARN++ )) || true ;;
    esac
}

echo "============================================================"
echo "  Evaluacion ISO 27001 (Annex A) - Securizar"
echo "  Fecha: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "  Host:  $(hostname)"
echo "============================================================"
echo ""

# ── A.5: Information Security Policies ───────────────────
echo "[A.5] Politicas de seguridad de la informacion..."
A5="FAIL"
A5_DESC="No se encontraron archivos de politica de seguridad"

POLICY_FILES=0
for pdir in /etc/securizar /usr/local/share/securizar; do
    if [[ -d "$pdir" ]]; then
        count=$(find "$pdir" -type f \( -name "*.conf" -o -name "*.policy" -o -name "*politica*" \) 2>/dev/null | wc -l || echo "0")
        POLICY_FILES=$(( POLICY_FILES + count ))
    fi
done

if [[ $POLICY_FILES -gt 0 ]]; then
    A5="PASS"
    A5_DESC="$POLICY_FILES archivos de politica encontrados en /etc/securizar"
fi

# Verificar banner (politica de uso aceptable)
if [[ -f /etc/issue ]] && [[ -s /etc/issue ]]; then
    A5_DESC="${A5_DESC}; Banner de uso aceptable configurado"
fi

check_iso "A.5-Policy" "$A5" "$A5_DESC"
echo "  [$A5] $A5_DESC"

# ── A.6: Organization of Information Security ────────────
echo "[A.6] Organizacion de seguridad de la informacion..."
A6="WARN"
A6_DESC="Verificar que roles de seguridad estan definidos"

# Verificar si existe configuracion de compliance
if [[ -f /etc/securizar/compliance-framework.conf ]]; then
    source /etc/securizar/compliance-framework.conf 2>/dev/null || true
    if [[ -n "${COMPLIANCE_OFFICER:-}" ]]; then
        A6="PASS"
        A6_DESC="Responsable de cumplimiento definido: ${COMPLIANCE_OFFICER}"
    fi
fi

# Verificar grupo de seguridad
if getent group security &>/dev/null || getent group secops &>/dev/null; then
    A6_DESC="${A6_DESC}; Grupo de seguridad definido en el sistema"
fi

check_iso "A.6-Org" "$A6" "$A6_DESC"
echo "  [$A6] $A6_DESC"

# ── A.8: Asset Management ───────────────────────────────
echo "[A.8] Gestion de activos..."
A8="WARN"
A8_DESC="Se recomienda mantener inventario de activos"

# Verificar inventario de activos
if [[ -f /etc/securizar/asset-inventory.conf ]] || [[ -f /etc/securizar/gdpr-data-inventory.conf ]]; then
    A8="PASS"
    A8_DESC="Inventario de activos/datos encontrado"
fi

# Verificar herramientas de inventario
if command -v lshw &>/dev/null || command -v dmidecode &>/dev/null; then
    A8_DESC="${A8_DESC}; Herramientas de inventario HW disponibles"
fi

# Snapshot del sistema como inventario basico
{
    echo "=== Inventario automatico - $(date) ==="
    echo "--- Hardware ---"
    if command -v lscpu &>/dev/null; then lscpu 2>/dev/null | head -20; fi
    echo "--- Disco ---"
    lsblk 2>/dev/null || true
    echo "--- Red ---"
    ip addr show 2>/dev/null | grep -E 'inet |link/' || true
    echo "--- Servicios ---"
    systemctl list-units --type=service --state=running 2>/dev/null | head -30 || true
} > "$EVIDENCE_DIR/iso27001/asset-inventory-${TIMESTAMP}.txt" 2>/dev/null || true

check_iso "A.8-Asset" "$A8" "$A8_DESC"
echo "  [$A8] $A8_DESC"

# ── A.9: Access Control ─────────────────────────────────
echo "[A.9] Control de acceso..."
A9="PASS"
A9_DESC="Control de acceso verificado"

# Principio de minimo privilegio
SUDO_NOPASSWD=$(grep -rcE 'NOPASSWD.*ALL' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | wc -l || echo "0")
if [[ "$SUDO_NOPASSWD" -gt 0 ]]; then
    A9="WARN"
    A9_DESC="sudo NOPASSWD:ALL detectado en $SUDO_NOPASSWD lineas"
fi

# MFA
MFA=0
if grep -rq 'pam_google_authenticator\|pam_duo\|pam_yubico\|pam_oath' /etc/pam.d/ 2>/dev/null; then
    MFA=1
    A9_DESC="${A9_DESC}; MFA configurado en PAM"
fi

# Password policy
if [[ -f /etc/login.defs ]]; then
    MAXDAYS=$(grep -E '^\s*PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}' || echo "99999")
    if [[ "${MAXDAYS:-99999}" -le 90 ]]; then
        A9_DESC="${A9_DESC}; Politica de contrasenas: max ${MAXDAYS} dias"
    else
        A9="WARN"
        A9_DESC="${A9_DESC}; PASS_MAX_DAYS=${MAXDAYS} (recomendado <=90)"
    fi
fi

check_iso "A.9-Access" "$A9" "$A9_DESC"
echo "  [$A9] $A9_DESC"

# ── A.10: Cryptography ──────────────────────────────────
echo "[A.10] Criptografia..."
A10="PASS"
A10_DESC="Capacidades criptograficas"

# OpenSSL
if command -v openssl &>/dev/null; then
    OSSL_VER=$(openssl version 2>/dev/null | awk '{print $2}' || echo "?")
    A10_DESC="OpenSSL $OSSL_VER"
fi

# GPG
if command -v gpg &>/dev/null; then
    A10_DESC="${A10_DESC}; GPG disponible"
fi

# Cifrado de disco
if lsblk -o TYPE 2>/dev/null | grep -q 'crypt'; then
    A10_DESC="${A10_DESC}; Cifrado de disco activo"
fi

# Verificar algoritmos debiles en SSH
if [[ -f /etc/ssh/sshd_config ]]; then
    if grep -qiE '^\s*Ciphers.*3des\|arcfour\|blowfish' /etc/ssh/sshd_config 2>/dev/null; then
        A10="WARN"
        A10_DESC="${A10_DESC}; Algoritmos debiles en SSH"
    fi
fi

check_iso "A.10-Crypto" "$A10" "$A10_DESC"
echo "  [$A10] $A10_DESC"

# ── A.12: Operations Security ───────────────────────────
echo "[A.12] Seguridad de operaciones..."
A12="PASS"
A12_DESC="Seguridad operacional"

# Change management
if command -v etckeeper &>/dev/null; then
    A12_DESC="etckeeper para control de cambios"
fi

# Capacity monitoring
DISK_USAGE=$(df / 2>/dev/null | awk 'NR==2 {gsub(/%/,""); print $5}' || echo "0")
if [[ "${DISK_USAGE:-0}" -gt 90 ]]; then
    A12="WARN"
    A12_DESC="${A12_DESC}; Uso de disco raiz: ${DISK_USAGE}% (alto)"
else
    A12_DESC="${A12_DESC}; Uso de disco raiz: ${DISK_USAGE}%"
fi

# Separation of environments
A12_DESC="${A12_DESC}; Verificar separacion dev/test/prod manualmente"

# Malware protection
if command -v clamscan &>/dev/null; then
    A12_DESC="${A12_DESC}; ClamAV disponible"
fi

# Backup
if find /etc/cron.daily /etc/cron.weekly -name "*backup*" 2>/dev/null | grep -q .; then
    A12_DESC="${A12_DESC}; Backup automatizado"
fi

# Logging
if systemctl is-active auditd &>/dev/null; then
    A12_DESC="${A12_DESC}; auditd activo"
fi

check_iso "A.12-Ops" "$A12" "$A12_DESC"
echo "  [$A12] $A12_DESC"

# ── A.13: Communications Security ───────────────────────
echo "[A.13] Seguridad de comunicaciones..."
A13="PASS"
A13_DESC="Controles de red"

# Firewall
FW_ACTIVE=0
if command -v nft &>/dev/null && nft list ruleset 2>/dev/null | grep -q 'chain'; then
    FW_ACTIVE=1
    A13_DESC="nftables activo"
elif command -v iptables &>/dev/null && iptables -L -n 2>/dev/null | grep -qE 'DROP|REJECT'; then
    FW_ACTIVE=1
    A13_DESC="iptables activo"
elif command -v firewall-cmd &>/dev/null && firewall-cmd --state 2>/dev/null | grep -q 'running'; then
    FW_ACTIVE=1
    A13_DESC="firewalld activo"
fi

if [[ $FW_ACTIVE -eq 0 ]]; then
    A13="FAIL"
    A13_DESC="No se detecta firewall activo"
fi

# Network segmentation
if ip route show 2>/dev/null | grep -qE 'via|scope link' && [[ $(ip route show 2>/dev/null | wc -l) -gt 2 ]]; then
    A13_DESC="${A13_DESC}; Multiples rutas de red (segmentacion posible)"
fi

# SSH
if systemctl is-active sshd &>/dev/null || systemctl is-active ssh &>/dev/null; then
    A13_DESC="${A13_DESC}; SSH activo"
fi

check_iso "A.13-Comms" "$A13" "$A13_DESC"
echo "  [$A13] $A13_DESC"

# ── A.14: System Acquisition, Development ────────────────
echo "[A.14] Adquisicion, desarrollo y mantenimiento de sistemas..."
A14="WARN"
A14_DESC="Verificar practicas de desarrollo seguro"

# Verificar compiladores y herramientas de desarrollo
if command -v gcc &>/dev/null || command -v g++ &>/dev/null; then
    A14_DESC="Compiladores presentes (verificar si necesario en produccion)"
fi

# Verificar SELinux/AppArmor (seguridad de aplicaciones)
if command -v getenforce &>/dev/null && [[ "$(getenforce 2>/dev/null)" == "Enforcing" ]]; then
    A14="PASS"
    A14_DESC="${A14_DESC}; SELinux en modo Enforcing"
elif command -v aa-status &>/dev/null && aa-status &>/dev/null; then
    A14="PASS"
    A14_DESC="${A14_DESC}; AppArmor activo"
fi

check_iso "A.14-Dev" "$A14" "$A14_DESC"
echo "  [$A14] $A14_DESC"

# ── A.16: Incident Management ───────────────────────────
echo "[A.16] Gestion de incidentes de seguridad..."
A16="FAIL"
A16_DESC="No se detectan procedimientos de IR"

for irfile in /etc/securizar/incident-response* /usr/local/bin/respuesta-incidentes* /usr/local/bin/securizar-incident*; do
    if [[ -f "$irfile" ]] 2>/dev/null; then
        A16="PASS"
        A16_DESC="Procedimientos de respuesta a incidentes encontrados"
        break
    fi
done

# Verificar herramientas forenses
if command -v volatility &>/dev/null || command -v autopsy &>/dev/null || [[ -f /usr/local/bin/forense-*.sh ]]; then
    A16_DESC="${A16_DESC}; Herramientas forenses disponibles"
    [[ "$A16" == "FAIL" ]] && A16="WARN"
fi

check_iso "A.16-Incident" "$A16" "$A16_DESC"
echo "  [$A16] $A16_DESC"

# ── A.18: Compliance ────────────────────────────────────
echo "[A.18] Cumplimiento..."
A18="PASS"
A18_DESC="Framework de cumplimiento configurado"

if [[ -f /etc/securizar/compliance-framework.conf ]]; then
    A18_DESC="Framework de cumplimiento activo"
else
    A18="WARN"
    A18_DESC="Ejecutar cumplimiento-normativo.sh para configurar framework"
fi

# Verificar licencias de software
if command -v rpm &>/dev/null; then
    A18_DESC="${A18_DESC}; Gestion de paquetes RPM"
elif command -v dpkg &>/dev/null; then
    A18_DESC="${A18_DESC}; Gestion de paquetes DPKG"
fi

check_iso "A.18-Comply" "$A18" "$A18_DESC"
echo "  [$A18] $A18_DESC"

# ── Informe ISO 27001 ────────────────────────────────────
echo ""
echo "============================================================"
echo "  INFORME ISO 27001 (Annex A) - RESUMEN"
echo "============================================================"

SCORE=0
[[ $TOTAL -gt 0 ]] && SCORE=$(( (PASS * 100) / TOTAL ))

echo ""
echo "  Controles evaluados: $TOTAL"
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
echo "  WARN: $WARN"
echo "  Puntuacion: ${SCORE}%"
echo ""

if [[ $SCORE -ge 80 ]]; then
    RATING="BUENO"
elif [[ $SCORE -ge 50 ]]; then
    RATING="MEJORABLE"
else
    RATING="DEFICIENTE"
fi
echo "  Calificacion: $RATING"

# Guardar informe
{
    echo "============================================================"
    echo "  INFORME ISO 27001 (Annex A)"
    echo "  Fecha: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "  Host:  $(hostname)"
    echo "  Score: ${SCORE}% ($RATING)"
    echo "============================================================"
    echo ""
    echo "  Annex A Controls:"
    echo "    A.5 Policies | A.6 Organization | A.8 Assets"
    echo "    A.9 Access | A.10 Crypto | A.12 Operations"
    echo "    A.13 Communications | A.14 Development"
    echo "    A.16 Incidents | A.18 Compliance"
    echo ""
    for r in "${RESULTS[@]}"; do
        IFS='|' read -r ctrl status desc <<< "$r"
        printf "  %-16s [%-4s] %s\n" "$ctrl" "$status" "$desc"
    done
    echo ""
    echo "  PASS=$PASS FAIL=$FAIL WARN=$WARN TOTAL=$TOTAL"
} > "$REPORT_FILE"

echo "  Informe guardado: $REPORT_FILE"
cp "$REPORT_FILE" "$EVIDENCE_DIR/iso27001/"
ISOEOF

    chmod 755 "$ISO_SCRIPT"
    log_change "Creado" "$ISO_SCRIPT (evaluacion ISO 27001 Annex A, 10 dominios)"

else
    log_skip "Script de evaluacion ISO 27001"
fi

# ============================================================
# S7: RECOLECCION DE EVIDENCIAS AUTOMATICA
# ============================================================
log_section "S7: Recoleccion de evidencias automatica"

log_info "Recoleccion automatizada de evidencias de cumplimiento:"
log_info "  - Snapshots de configuracion del sistema"
log_info "  - Exportacion de audit logs"
log_info "  - Paquetes de evidencia con SHA-256 y cadena de custodia"
log_info "  - Cron mensual automatico"

if ask "¿Crear sistema de recoleccion de evidencias?"; then

    # ── S7.1: Script de recoleccion de evidencias ─────────
    EVIDENCE_SCRIPT="$COMPLIANCE_BIN_DIR/recopilar-evidencias.sh"

    cat > "$EVIDENCE_SCRIPT" << 'EVIDEOF'
#!/bin/bash
# ============================================================
# recopilar-evidencias.sh - Recoleccion automatica de evidencias
# Parte del Modulo 54 - Cumplimiento Normativo
# ============================================================
set -euo pipefail

CONF_FILE="/etc/securizar/compliance-framework.conf"
[[ -f "$CONF_FILE" ]] && source "$CONF_FILE"

EVIDENCE_DIR="${EVIDENCE_DIR:-/var/lib/securizar/compliance-evidence}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
COLLECTION_DIR="$EVIDENCE_DIR/snapshots/collection-${TIMESTAMP}"
PACKAGE_NAME="compliance-evidence-${TIMESTAMP}"

mkdir -p "$COLLECTION_DIR"

echo "============================================================"
echo "  Recoleccion de Evidencias - Securizar"
echo "  Fecha: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "  Host:  $(hostname)"
echo "============================================================"
echo ""

# ── Metadata de cadena de custodia ────────────────────────
CUSTODY_FILE="$COLLECTION_DIR/chain-of-custody.txt"
{
    echo "============================================================"
    echo "  CADENA DE CUSTODIA - EVIDENCIAS DE CUMPLIMIENTO"
    echo "============================================================"
    echo "Fecha de recoleccion:  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Hostname:              $(hostname)"
    echo "FQDN:                  $(hostname -f 2>/dev/null || echo 'N/A')"
    echo "Kernel:                $(uname -r)"
    echo "OS:                    $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"' || echo 'N/A')"
    echo "Recolectado por:       $(whoami) (UID: $(id -u))"
    echo "Organizacion:          ${ORGANIZATION_NAME:-N/A}"
    echo "Contacto:              ${AUDIT_CONTACT:-N/A}"
    echo "Frameworks activos:    ${ACTIVE_FRAMEWORKS:-N/A}"
    echo ""
    echo "Metodo de recoleccion: Automatizado via recopilar-evidencias.sh"
    echo "Integridad:            SHA-256 checksums incluidos"
    echo "============================================================"
} > "$CUSTODY_FILE"
echo "[+] Cadena de custodia: $CUSTODY_FILE"

# ── 1. Configuracion del sistema ─────────────────────────
echo "[+] Recopilando configuracion del sistema..."
SYSCONF_DIR="$COLLECTION_DIR/system-config"
mkdir -p "$SYSCONF_DIR"

# /etc/securizar configs
if [[ -d /etc/securizar ]]; then
    cp -a /etc/securizar "$SYSCONF_DIR/etc-securizar" 2>/dev/null || true
fi

# SSH config
if [[ -f /etc/ssh/sshd_config ]]; then
    cp -a /etc/ssh/sshd_config "$SYSCONF_DIR/" 2>/dev/null || true
fi

# PAM config
if [[ -d /etc/pam.d ]]; then
    cp -a /etc/pam.d "$SYSCONF_DIR/pam.d" 2>/dev/null || true
fi

# Login defs
for f in /etc/login.defs /etc/security/limits.conf /etc/sysctl.conf; do
    [[ -f "$f" ]] && cp -a "$f" "$SYSCONF_DIR/" 2>/dev/null || true
done

# Sudoers (sin contenido sensible)
if [[ -f /etc/sudoers ]]; then
    grep -v '#include\|Defaults.*passwd' /etc/sudoers > "$SYSCONF_DIR/sudoers-sanitized.txt" 2>/dev/null || true
fi

echo "  Configuracion del sistema recopilada"

# ── 2. Audit logs ────────────────────────────────────────
echo "[+] Exportando audit logs..."
AUDITLOG_DIR="$COLLECTION_DIR/audit-logs"
mkdir -p "$AUDITLOG_DIR"

# Auditd logs
if [[ -d /var/log/audit ]]; then
    cp -a /var/log/audit/audit.log "$AUDITLOG_DIR/" 2>/dev/null || true
    # Solo ultimo mes de logs rotados
    find /var/log/audit -name "audit.log.*" -mtime -30 -exec cp -a {} "$AUDITLOG_DIR/" \; 2>/dev/null || true
fi

# Journal (ultimo mes)
if command -v journalctl &>/dev/null; then
    journalctl --since "30 days ago" --no-pager > "$AUDITLOG_DIR/journal-30days.txt" 2>/dev/null || true
fi

# Auth logs
for authlog in /var/log/auth.log /var/log/secure; do
    [[ -f "$authlog" ]] && cp -a "$authlog" "$AUDITLOG_DIR/" 2>/dev/null || true
done

echo "  Audit logs exportados"

# ── 3. Firewall rules ───────────────────────────────────
echo "[+] Capturando reglas de firewall..."
FW_DIR="$COLLECTION_DIR/firewall"
mkdir -p "$FW_DIR"

if command -v nft &>/dev/null; then
    nft list ruleset > "$FW_DIR/nftables-ruleset.txt" 2>/dev/null || true
fi

if command -v iptables &>/dev/null; then
    iptables-save > "$FW_DIR/iptables-save.txt" 2>/dev/null || true
fi

if command -v firewall-cmd &>/dev/null; then
    firewall-cmd --list-all-zones > "$FW_DIR/firewalld-zones.txt" 2>/dev/null || true
fi

echo "  Reglas de firewall capturadas"

# ── 4. Usuarios y acceso ────────────────────────────────
echo "[+] Capturando informacion de usuarios..."
USER_DIR="$COLLECTION_DIR/users-access"
mkdir -p "$USER_DIR"

# Lista de usuarios (sin hashes)
awk -F: '{print $1":"$3":"$4":"$5":"$6":"$7}' /etc/passwd > "$USER_DIR/users.txt" 2>/dev/null || true

# Grupos
cp -a /etc/group "$USER_DIR/groups.txt" 2>/dev/null || true

# Usuarios con UID 0
awk -F: '$3 == 0 {print $1}' /etc/passwd > "$USER_DIR/uid0-users.txt" 2>/dev/null || true

# Sudoers
getent group wheel sudo 2>/dev/null > "$USER_DIR/privileged-groups.txt" || true

# Ultimo login
lastlog 2>/dev/null | grep -v 'Never' > "$USER_DIR/lastlog.txt" || true

# Sesiones activas
who > "$USER_DIR/active-sessions.txt" 2>/dev/null || true
last -n 50 > "$USER_DIR/last-50-logins.txt" 2>/dev/null || true

echo "  Informacion de usuarios capturada"

# ── 5. Servicios y puertos ──────────────────────────────
echo "[+] Capturando servicios y puertos..."
SVC_DIR="$COLLECTION_DIR/services"
mkdir -p "$SVC_DIR"

# Servicios activos
systemctl list-units --type=service --state=running --no-pager > "$SVC_DIR/running-services.txt" 2>/dev/null || true

# Servicios habilitados
systemctl list-unit-files --type=service --state=enabled --no-pager > "$SVC_DIR/enabled-services.txt" 2>/dev/null || true

# Puertos abiertos
ss -tlnp > "$SVC_DIR/listening-ports-tcp.txt" 2>/dev/null || true
ss -ulnp > "$SVC_DIR/listening-ports-udp.txt" 2>/dev/null || true

echo "  Servicios y puertos capturados"

# ── 6. Paquetes instalados ──────────────────────────────
echo "[+] Capturando paquetes instalados..."
PKG_DIR="$COLLECTION_DIR/packages"
mkdir -p "$PKG_DIR"

if command -v rpm &>/dev/null; then
    rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' | sort > "$PKG_DIR/rpm-packages.txt" 2>/dev/null || true
fi
if command -v dpkg &>/dev/null; then
    dpkg -l | awk '/^ii/ {print $2, $3}' | sort > "$PKG_DIR/dpkg-packages.txt" 2>/dev/null || true
fi
if command -v pacman &>/dev/null; then
    pacman -Q | sort > "$PKG_DIR/pacman-packages.txt" 2>/dev/null || true
fi

echo "  Paquetes instalados capturados"

# ── 7. Crear paquete tar.gz con SHA-256 ─────────────────
echo "[+] Creando paquete de evidencias..."

# Generar checksums de todos los archivos
find "$COLLECTION_DIR" -type f | sort | while read -r f; do
    sha256sum "$f"
done > "$COLLECTION_DIR/SHA256SUMS.txt" 2>/dev/null || true

# Crear tarball
TARBALL="$EVIDENCE_DIR/snapshots/${PACKAGE_NAME}.tar.gz"
tar -czf "$TARBALL" -C "$EVIDENCE_DIR/snapshots" "collection-${TIMESTAMP}" 2>/dev/null

# SHA-256 del paquete
TARBALL_HASH=$(sha256sum "$TARBALL" | awk '{print $1}')

echo "  Paquete creado: $TARBALL"
echo "  SHA-256: $TARBALL_HASH"

# Guardar hash en archivo separado
echo "$TARBALL_HASH  ${PACKAGE_NAME}.tar.gz" > "${TARBALL}.sha256"

# Actualizar cadena de custodia
{
    echo ""
    echo "=== PAQUETE DE EVIDENCIAS ==="
    echo "Archivo: ${PACKAGE_NAME}.tar.gz"
    echo "SHA-256: $TARBALL_HASH"
    echo "Tamano:  $(du -h "$TARBALL" | awk '{print $1}')"
    echo "Archivos incluidos: $(find "$COLLECTION_DIR" -type f | wc -l)"
} >> "$CUSTODY_FILE"

# Copiar cadena de custodia a directorio dedicado
cp "$CUSTODY_FILE" "$EVIDENCE_DIR/chain-of-custody/custody-${TIMESTAMP}.txt"

echo ""
echo "============================================================"
echo "  Recoleccion de evidencias completada"
echo "  Paquete: $TARBALL"
echo "  Hash:    $TARBALL_HASH"
echo "  Custodia: $EVIDENCE_DIR/chain-of-custody/custody-${TIMESTAMP}.txt"
echo "============================================================"

# ── Limpieza por retencion ───────────────────────────────
RETENTION_DAYS="${RETENTION_DAYS:-365}"
DELETED_COUNT=0
while IFS= read -r old_pkg; do
    rm -f "$old_pkg" "${old_pkg}.sha256"
    (( DELETED_COUNT++ )) || true
done < <(find "$EVIDENCE_DIR/snapshots" -name "compliance-evidence-*.tar.gz" -mtime +"$RETENTION_DAYS" 2>/dev/null)

if [[ $DELETED_COUNT -gt 0 ]]; then
    echo "[+] Limpieza: $DELETED_COUNT paquetes antiguos eliminados (retencion: ${RETENTION_DAYS} dias)"
fi
EVIDEOF

    chmod 755 "$EVIDENCE_SCRIPT"
    log_change "Creado" "$EVIDENCE_SCRIPT (recoleccion automatica de evidencias)"

    # ── S7.2: Cron mensual ────────────────────────────────
    EVIDENCE_CRON="/etc/cron.monthly/securizar-evidencias-compliance"

    cat > "$EVIDENCE_CRON" << 'CRONEVIDEOF'
#!/bin/bash
# Recoleccion mensual de evidencias de cumplimiento - Securizar Modulo 54
/usr/local/bin/recopilar-evidencias.sh >> /var/log/securizar/compliance-reports/evidence-collection.log 2>&1
CRONEVIDEOF

    chmod 755 "$EVIDENCE_CRON"
    log_change "Creado" "$EVIDENCE_CRON (cron mensual de evidencias)"

else
    log_skip "Sistema de recoleccion de evidencias"
fi

# ============================================================
# S8: GENERACION DE INFORMES DE CUMPLIMIENTO
# ============================================================
log_section "S8: Generacion de informes de cumplimiento"

log_info "Generador de informes de cumplimiento:"
log_info "  - Ejecuta evaluaciones de frameworks activos"
log_info "  - Informe HTML con resumen ejecutivo"
log_info "  - Informe JSON legible por maquina"
log_info "  - Recomendaciones de remediacion"

if ask "¿Crear generador de informes de cumplimiento?"; then

    REPORT_SCRIPT="$COMPLIANCE_BIN_DIR/generar-informe-compliance.sh"

    cat > "$REPORT_SCRIPT" << 'REPORTEOF'
#!/bin/bash
# ============================================================
# generar-informe-compliance.sh - Generador de informes
# Parte del Modulo 54 - Cumplimiento Normativo
# ============================================================
set -euo pipefail

CONF_FILE="/etc/securizar/compliance-framework.conf"
if [[ -f "$CONF_FILE" ]]; then
    source "$CONF_FILE"
else
    echo "[!] No se encuentra $CONF_FILE - usando valores por defecto"
fi

EVIDENCE_DIR="${EVIDENCE_DIR:-/var/lib/securizar/compliance-evidence}"
REPORT_DIR="${REPORT_DIR:-/var/log/securizar/compliance-reports}"
ACTIVE_FRAMEWORKS="${ACTIVE_FRAMEWORKS:-pci-dss gdpr}"
ORGANIZATION_NAME="${ORGANIZATION_NAME:-Organizacion}"
REPORT_FORMAT="${REPORT_FORMAT:-both}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"

mkdir -p "$REPORT_DIR"/{html,json}

echo "============================================================"
echo "  Generacion de Informe de Cumplimiento - Securizar"
echo "  Fecha: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "  Organizacion: $ORGANIZATION_NAME"
echo "  Frameworks: $ACTIVE_FRAMEWORKS"
echo "============================================================"
echo ""

# ── Ejecutar evaluaciones ────────────────────────────────
declare -A FRAMEWORK_SCORES
declare -A FRAMEWORK_RATINGS
declare -A FRAMEWORK_PASS
declare -A FRAMEWORK_FAIL
declare -A FRAMEWORK_WARN
declare -A FRAMEWORK_TOTAL
OVERALL_PASS=0
OVERALL_FAIL=0
OVERALL_WARN=0
OVERALL_TOTAL=0

for fw in $ACTIVE_FRAMEWORKS; do
    echo "[+] Ejecutando evaluacion: $fw..."

    case "$fw" in
        pci-dss)
            EVAL_SCRIPT="/usr/local/bin/evaluar-pci-dss.sh"
            ;;
        gdpr)
            EVAL_SCRIPT="/usr/local/bin/evaluar-gdpr.sh"
            ;;
        hipaa)
            EVAL_SCRIPT="/usr/local/bin/evaluar-hipaa.sh"
            ;;
        soc2)
            EVAL_SCRIPT="/usr/local/bin/evaluar-soc2.sh"
            ;;
        iso27001)
            EVAL_SCRIPT="/usr/local/bin/evaluar-iso27001.sh"
            ;;
        *)
            echo "[!] Framework desconocido: $fw"
            continue
            ;;
    esac

    if [[ -f "$EVAL_SCRIPT" ]]; then
        # Ejecutar y capturar salida
        EVAL_OUTPUT=$("$EVAL_SCRIPT" 2>&1) || true

        # Extraer puntuacion de la salida
        FW_SCORE=$(echo "$EVAL_OUTPUT" | grep -oP 'Puntuacion:\s*\K[0-9]+' | tail -1 || echo "0")
        FW_PASS=$(echo "$EVAL_OUTPUT" | grep -oP 'PASS:\s*\K[0-9]+' | tail -1 || echo "0")
        FW_FAIL=$(echo "$EVAL_OUTPUT" | grep -oP 'FAIL:\s*\K[0-9]+' | tail -1 || echo "0")
        FW_WARN=$(echo "$EVAL_OUTPUT" | grep -oP 'WARN:\s*\K[0-9]+' | tail -1 || echo "0")
        FW_TOTAL=$(echo "$EVAL_OUTPUT" | grep -oP 'TOTAL=\K[0-9]+' | tail -1 || echo "0")

        FRAMEWORK_SCORES[$fw]="${FW_SCORE:-0}"
        FRAMEWORK_PASS[$fw]="${FW_PASS:-0}"
        FRAMEWORK_FAIL[$fw]="${FW_FAIL:-0}"
        FRAMEWORK_WARN[$fw]="${FW_WARN:-0}"
        FRAMEWORK_TOTAL[$fw]="${FW_TOTAL:-0}"

        if [[ "${FW_SCORE:-0}" -ge 80 ]]; then
            FRAMEWORK_RATINGS[$fw]="BUENO"
        elif [[ "${FW_SCORE:-0}" -ge 50 ]]; then
            FRAMEWORK_RATINGS[$fw]="MEJORABLE"
        else
            FRAMEWORK_RATINGS[$fw]="DEFICIENTE"
        fi

        OVERALL_PASS=$(( OVERALL_PASS + ${FW_PASS:-0} ))
        OVERALL_FAIL=$(( OVERALL_FAIL + ${FW_FAIL:-0} ))
        OVERALL_WARN=$(( OVERALL_WARN + ${FW_WARN:-0} ))
        OVERALL_TOTAL=$(( OVERALL_TOTAL + ${FW_TOTAL:-0} ))

        echo "  $fw: ${FW_SCORE:-0}% (${FRAMEWORK_RATINGS[$fw]:-N/A})"
    else
        echo "[!] Script de evaluacion no encontrado: $EVAL_SCRIPT"
        FRAMEWORK_SCORES[$fw]=0
        FRAMEWORK_RATINGS[$fw]="NO_EVALUADO"
    fi
done

# Calcular score global
OVERALL_SCORE=0
[[ $OVERALL_TOTAL -gt 0 ]] && OVERALL_SCORE=$(( (OVERALL_PASS * 100) / OVERALL_TOTAL ))

if [[ $OVERALL_SCORE -ge 80 ]]; then
    OVERALL_RATING="BUENO"
elif [[ $OVERALL_SCORE -ge 50 ]]; then
    OVERALL_RATING="MEJORABLE"
else
    OVERALL_RATING="DEFICIENTE"
fi

echo ""
echo "  Score global: ${OVERALL_SCORE}% ($OVERALL_RATING)"

# ── Generar informe HTML ─────────────────────────────────
if [[ "$REPORT_FORMAT" == "html" ]] || [[ "$REPORT_FORMAT" == "both" ]]; then
    HTML_FILE="$REPORT_DIR/html/compliance-report-${TIMESTAMP}.html"

    cat > "$HTML_FILE" << HTMLEOF_INNER
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Informe de Cumplimiento - ${ORGANIZATION_NAME} - $(date +%Y-%m-%d)</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, sans-serif; margin: 40px; background: #f5f5f5; color: #333; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 15px; }
        h2 { color: #2c3e50; margin-top: 30px; }
        h3 { color: #34495e; }
        .summary { background: #ecf0f1; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .score { font-size: 48px; font-weight: bold; text-align: center; }
        .score.bueno { color: #27ae60; }
        .score.mejorable { color: #f39c12; }
        .score.deficiente { color: #e74c3c; }
        .rating { text-align: center; font-size: 24px; font-weight: bold; margin: 10px 0; }
        .rating.bueno { color: #27ae60; }
        .rating.mejorable { color: #f39c12; }
        .rating.deficiente { color: #e74c3c; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th { background: #3498db; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:nth-child(even) { background: #f9f9f9; }
        .pass { color: #27ae60; font-weight: bold; }
        .fail { color: #e74c3c; font-weight: bold; }
        .warn { color: #f39c12; font-weight: bold; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #888; }
        .remediation { background: #fff3cd; padding: 15px; border-radius: 5px; border-left: 4px solid #f39c12; margin: 10px 0; }
        .stats { display: flex; justify-content: space-around; text-align: center; margin: 20px 0; }
        .stat-box { padding: 15px; border-radius: 8px; min-width: 120px; }
        .stat-box.pass-bg { background: #d4edda; }
        .stat-box.fail-bg { background: #f8d7da; }
        .stat-box.warn-bg { background: #fff3cd; }
        .stat-number { font-size: 32px; font-weight: bold; }
    </style>
</head>
<body>
<div class="container">
    <h1>Informe de Cumplimiento Normativo</h1>
    <p><strong>Organizacion:</strong> ${ORGANIZATION_NAME}</p>
    <p><strong>Fecha:</strong> $(date -u +%Y-%m-%dT%H:%M:%SZ)</p>
    <p><strong>Host:</strong> $(hostname)</p>
    <p><strong>Frameworks evaluados:</strong> ${ACTIVE_FRAMEWORKS}</p>

    <div class="summary">
        <h2>Resumen Ejecutivo</h2>
        <div class="score $(echo "$OVERALL_RATING" | tr '[:upper:]' '[:lower:]')">${OVERALL_SCORE}%</div>
        <div class="rating $(echo "$OVERALL_RATING" | tr '[:upper:]' '[:lower:]')">${OVERALL_RATING}</div>

        <div class="stats">
            <div class="stat-box pass-bg">
                <div class="stat-number pass">${OVERALL_PASS}</div>
                <div>Controles OK</div>
            </div>
            <div class="stat-box fail-bg">
                <div class="stat-number fail">${OVERALL_FAIL}</div>
                <div>Fallos</div>
            </div>
            <div class="stat-box warn-bg">
                <div class="stat-number warn">${OVERALL_WARN}</div>
                <div>Advertencias</div>
            </div>
        </div>
    </div>

    <h2>Resultados por Framework</h2>
    <table>
        <tr><th>Framework</th><th>Score</th><th>Calificacion</th><th>PASS</th><th>FAIL</th><th>WARN</th></tr>
HTMLEOF_INNER

    for fw in $ACTIVE_FRAMEWORKS; do
        local fw_score="${FRAMEWORK_SCORES[$fw]:-0}"
        local fw_rating="${FRAMEWORK_RATINGS[$fw]:-N/A}"
        local fw_rating_lower
        fw_rating_lower=$(echo "$fw_rating" | tr '[:upper:]' '[:lower:]')
        local fw_upper
        fw_upper=$(echo "$fw" | tr '[:lower:]' '[:upper:]')

        cat >> "$HTML_FILE" << HTMLROW
        <tr>
            <td><strong>${fw_upper}</strong></td>
            <td>${fw_score}%</td>
            <td class="${fw_rating_lower}">${fw_rating}</td>
            <td class="pass">${FRAMEWORK_PASS[$fw]:-0}</td>
            <td class="fail">${FRAMEWORK_FAIL[$fw]:-0}</td>
            <td class="warn">${FRAMEWORK_WARN[$fw]:-0}</td>
        </tr>
HTMLROW
    done

    cat >> "$HTML_FILE" << 'HTMLEOF2'
    </table>

    <h2>Recomendaciones de Remediacion</h2>
    <div class="remediation">
        <h3>Prioridad Alta (Controles FAIL)</h3>
        <ul>
            <li>Revisar y corregir todos los controles con estado FAIL</li>
            <li>Ejecutar: <code>remediar-compliance.sh</code> para remediacion guiada</li>
            <li>Verificar firewall, auditd, cifrado y politicas de contrasenas</li>
        </ul>
    </div>
    <div class="remediation">
        <h3>Prioridad Media (Controles WARN)</h3>
        <ul>
            <li>Revisar advertencias y evaluar riesgo aceptable</li>
            <li>Implementar MFA si no esta configurado</li>
            <li>Completar inventarios de datos y politicas documentadas</li>
            <li>Configurar monitoreo continuo y alertas</li>
        </ul>
    </div>

    <h2>Referencias de Evidencias</h2>
    <p>Las evidencias recopiladas se almacenan en:</p>
    <ul>
HTMLEOF2

    echo "        <li><code>${EVIDENCE_DIR}</code></li>" >> "$HTML_FILE"

    cat >> "$HTML_FILE" << 'HTMLEOF3'
    </ul>
    <p>Ejecutar <code>recopilar-evidencias.sh</code> para generar un paquete de evidencias actualizado.</p>

    <div class="footer">
        <p>Generado automaticamente por Securizar - Modulo 54: Cumplimiento Normativo</p>
        <p>Este informe es una evaluacion tecnica automatizada y no sustituye una auditoria formal.</p>
    </div>
</div>
</body>
</html>
HTMLEOF3

    echo "[+] Informe HTML: $HTML_FILE"
fi

# ── Generar informe JSON ─────────────────────────────────
if [[ "$REPORT_FORMAT" == "json" ]] || [[ "$REPORT_FORMAT" == "both" ]]; then
    JSON_FILE="$REPORT_DIR/json/compliance-report-${TIMESTAMP}.json"

    {
        echo "{"
        echo "  \"report_type\": \"compliance\","
        echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
        echo "  \"hostname\": \"$(hostname)\","
        echo "  \"organization\": \"${ORGANIZATION_NAME}\","
        echo "  \"overall_score\": ${OVERALL_SCORE},"
        echo "  \"overall_rating\": \"${OVERALL_RATING}\","
        echo "  \"overall_pass\": ${OVERALL_PASS},"
        echo "  \"overall_fail\": ${OVERALL_FAIL},"
        echo "  \"overall_warn\": ${OVERALL_WARN},"
        echo "  \"overall_total\": ${OVERALL_TOTAL},"
        echo "  \"frameworks\": {"

        local fw_count=0
        local fw_total_count=0
        for fw in $ACTIVE_FRAMEWORKS; do
            (( fw_total_count++ )) || true
        done

        for fw in $ACTIVE_FRAMEWORKS; do
            (( fw_count++ )) || true
            local comma=","
            [[ $fw_count -eq $fw_total_count ]] && comma=""

            echo "    \"$fw\": {"
            echo "      \"score\": ${FRAMEWORK_SCORES[$fw]:-0},"
            echo "      \"rating\": \"${FRAMEWORK_RATINGS[$fw]:-N/A}\","
            echo "      \"pass\": ${FRAMEWORK_PASS[$fw]:-0},"
            echo "      \"fail\": ${FRAMEWORK_FAIL[$fw]:-0},"
            echo "      \"warn\": ${FRAMEWORK_WARN[$fw]:-0},"
            echo "      \"total\": ${FRAMEWORK_TOTAL[$fw]:-0}"
            echo "    }${comma}"
        done

        echo "  },"
        echo "  \"evidence_dir\": \"${EVIDENCE_DIR}\","
        echo "  \"generated_by\": \"securizar-modulo-54\""
        echo "}"
    } > "$JSON_FILE"

    echo "[+] Informe JSON: $JSON_FILE"
fi

echo ""
echo "============================================================"
echo "  Generacion de informes completada"
echo "  Score global: ${OVERALL_SCORE}% ($OVERALL_RATING)"
echo "============================================================"
REPORTEOF

    chmod 755 "$REPORT_SCRIPT"
    log_change "Creado" "$REPORT_SCRIPT (generador de informes HTML/JSON)"

else
    log_skip "Generador de informes de cumplimiento"
fi

# ============================================================
# S9: REMEDIACION GUIADA
# ============================================================
log_section "S9: Remediacion guiada"

log_info "Herramienta de remediacion guiada de cumplimiento:"
log_info "  - Analiza gaps de la ultima evaluacion"
log_info "  - Instrucciones paso a paso"
log_info "  - Auto-fix con confirmacion del usuario"
log_info "  - Tracking de progreso"

if ask "¿Crear herramienta de remediacion guiada?"; then

    REMEDIATION_SCRIPT="$COMPLIANCE_BIN_DIR/remediar-compliance.sh"

    cat > "$REMEDIATION_SCRIPT" << 'REMEOF'
#!/bin/bash
# ============================================================
# remediar-compliance.sh - Remediacion guiada de cumplimiento
# Parte del Modulo 54 - Cumplimiento Normativo
# ============================================================
set -euo pipefail

CONF_FILE="/etc/securizar/compliance-framework.conf"
[[ -f "$CONF_FILE" ]] && source "$CONF_FILE"

REPORT_DIR="${REPORT_DIR:-/var/log/securizar/compliance-reports}"
REMEDIATION_DB="/var/lib/securizar/compliance-remediation.db"

mkdir -p "$(dirname "$REMEDIATION_DB")"
touch "$REMEDIATION_DB"

echo "============================================================"
echo "  Remediacion Guiada de Cumplimiento - Securizar"
echo "  Fecha: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "  Host:  $(hostname)"
echo "============================================================"
echo ""

# ── Funciones de remediacion ─────────────────────────────
ask_remediate() {
    local desc="$1"
    read -p "  ¿Remediar: ${desc}? [s/N]: " resp
    [[ "$resp" =~ ^[sS]$ ]]
}

log_remediation() {
    local action="$1" status="$2"
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "${ts}|${action}|${status}" >> "$REMEDIATION_DB"
    echo "  [REMEDIADO] $action ($status)"
}

REMEDIATED=0
SKIPPED=0
TOTAL_GAPS=0

# ── Analizar gaps ────────────────────────────────────────
echo "[+] Analizando gaps de cumplimiento..."
echo ""

# ── Gap 1: auditd no activo ─────────────────────────────
echo "=== Verificacion: Sistema de auditoria ==="
if ! systemctl is-active auditd &>/dev/null 2>&1; then
    (( TOTAL_GAPS++ )) || true
    echo "  [GAP] auditd no esta activo"
    echo "  Impacto: PCI-DSS Req10, HIPAA TS-Audit, ISO27001 A.12"
    echo "  Remediacion: Instalar y habilitar auditd"
    echo ""

    if ask_remediate "Habilitar auditd"; then
        # Intentar instalar si no esta presente
        if ! command -v auditctl &>/dev/null; then
            echo "  Instalando audit..."
            if command -v zypper &>/dev/null; then
                zypper install -y audit 2>/dev/null || true
            elif command -v apt-get &>/dev/null; then
                apt-get install -y auditd 2>/dev/null || true
            elif command -v dnf &>/dev/null; then
                dnf install -y audit 2>/dev/null || true
            elif command -v pacman &>/dev/null; then
                pacman -S --noconfirm audit 2>/dev/null || true
            fi
        fi

        if command -v auditctl &>/dev/null; then
            systemctl enable auditd 2>/dev/null || true
            systemctl start auditd 2>/dev/null || true
            if systemctl is-active auditd &>/dev/null; then
                log_remediation "auditd habilitado y activo" "OK"
                (( REMEDIATED++ )) || true
            else
                echo "  [ERROR] No se pudo iniciar auditd"
                log_remediation "auditd" "ERROR"
            fi
        else
            echo "  [ERROR] No se pudo instalar audit"
        fi
    else
        (( SKIPPED++ )) || true
        echo "  -- Omitido"
    fi
else
    echo "  [OK] auditd esta activo"
fi
echo ""

# ── Gap 2: Politica de contrasenas ───────────────────────
echo "=== Verificacion: Politica de contrasenas ==="
NEEDS_FIX=0
if [[ -f /etc/login.defs ]]; then
    PASS_MAX=$(grep -E '^\s*PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}' || echo "99999")
    PASS_MIN_LEN=$(grep -E '^\s*PASS_MIN_LEN' /etc/login.defs 2>/dev/null | awk '{print $2}' || echo "5")
    PASS_MIN_DAYS=$(grep -E '^\s*PASS_MIN_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}' || echo "0")

    if [[ "${PASS_MAX:-99999}" -gt 90 ]]; then
        echo "  [GAP] PASS_MAX_DAYS=${PASS_MAX} (recomendado <=90)"
        NEEDS_FIX=1
    fi
    if [[ "${PASS_MIN_LEN:-5}" -lt 8 ]]; then
        echo "  [GAP] PASS_MIN_LEN=${PASS_MIN_LEN} (recomendado >=8)"
        NEEDS_FIX=1
    fi
    if [[ "${PASS_MIN_DAYS:-0}" -lt 1 ]]; then
        echo "  [GAP] PASS_MIN_DAYS=${PASS_MIN_DAYS} (recomendado >=1)"
        NEEDS_FIX=1
    fi
fi

if [[ $NEEDS_FIX -eq 1 ]]; then
    (( TOTAL_GAPS++ )) || true
    echo "  Impacto: PCI-DSS Req8, HIPAA TS-Access, ISO27001 A.9"
    echo "  Remediacion: Ajustar PASS_MAX_DAYS=90, PASS_MIN_LEN=12, PASS_MIN_DAYS=1"
    echo ""

    if ask_remediate "Configurar politica de contrasenas"; then
        cp -a /etc/login.defs "/etc/login.defs.bak.$(date +%s)" 2>/dev/null || true

        # PASS_MAX_DAYS
        if grep -qE '^\s*PASS_MAX_DAYS' /etc/login.defs; then
            sed -i 's/^\s*PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/' /etc/login.defs
        else
            echo "PASS_MAX_DAYS	90" >> /etc/login.defs
        fi

        # PASS_MIN_LEN
        if grep -qE '^\s*PASS_MIN_LEN' /etc/login.defs; then
            sed -i 's/^\s*PASS_MIN_LEN.*/PASS_MIN_LEN\t12/' /etc/login.defs
        else
            echo "PASS_MIN_LEN	12" >> /etc/login.defs
        fi

        # PASS_MIN_DAYS
        if grep -qE '^\s*PASS_MIN_DAYS' /etc/login.defs; then
            sed -i 's/^\s*PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/' /etc/login.defs
        else
            echo "PASS_MIN_DAYS	1" >> /etc/login.defs
        fi

        log_remediation "Politica de contrasenas ajustada (MAX=90, LEN=12, MIN=1)" "OK"
        (( REMEDIATED++ )) || true
    else
        (( SKIPPED++ )) || true
        echo "  -- Omitido"
    fi
else
    echo "  [OK] Politica de contrasenas cumple requisitos"
fi
echo ""

# ── Gap 3: Log rotation/retention ────────────────────────
echo "=== Verificacion: Retencion de logs ==="
if [[ ! -f /etc/logrotate.conf ]]; then
    (( TOTAL_GAPS++ )) || true
    echo "  [GAP] logrotate no configurado"
    echo "  Impacto: GDPR MinDat, SOC2 PRV-Retain"
    echo "  Remediacion: Instalar y configurar logrotate"
    echo ""

    if ask_remediate "Instalar logrotate"; then
        if command -v zypper &>/dev/null; then
            zypper install -y logrotate 2>/dev/null || true
        elif command -v apt-get &>/dev/null; then
            apt-get install -y logrotate 2>/dev/null || true
        elif command -v dnf &>/dev/null; then
            dnf install -y logrotate 2>/dev/null || true
        elif command -v pacman &>/dev/null; then
            pacman -S --noconfirm logrotate 2>/dev/null || true
        fi

        if [[ -f /etc/logrotate.conf ]]; then
            log_remediation "logrotate instalado" "OK"
            (( REMEDIATED++ )) || true
        else
            echo "  [ERROR] No se pudo instalar logrotate"
        fi
    else
        (( SKIPPED++ )) || true
        echo "  -- Omitido"
    fi
else
    echo "  [OK] logrotate configurado"
fi
echo ""

# ── Gap 4: Cifrado de disco ─────────────────────────────
echo "=== Verificacion: Cifrado de datos en reposo ==="
if ! lsblk -o TYPE 2>/dev/null | grep -q 'crypt'; then
    (( TOTAL_GAPS++ )) || true
    echo "  [GAP] No se detecta cifrado de disco (LUKS/dm-crypt)"
    echo "  Impacto: PCI-DSS Req3, GDPR Art.25/32, HIPAA TS-EncRest"
    echo "  Remediacion: Configurar LUKS en particiones con datos sensibles"
    echo "  NOTA: Cifrado de disco requiere planificacion manual y reboot"
    echo ""
    echo "  Pasos manuales:"
    echo "    1. Identificar particiones con datos sensibles"
    echo "    2. Backup completo de datos"
    echo "    3. cryptsetup luksFormat /dev/sdXN"
    echo "    4. cryptsetup open /dev/sdXN nombre_cifrado"
    echo "    5. mkfs.ext4 /dev/mapper/nombre_cifrado"
    echo "    6. Actualizar /etc/fstab y /etc/crypttab"
    echo ""
    log_remediation "Cifrado de disco: requiere accion manual" "PENDIENTE"
else
    echo "  [OK] Cifrado de disco detectado"
fi
echo ""

# ── Gap 5: Firewall ─────────────────────────────────────
echo "=== Verificacion: Firewall ==="
FW_OK=0
if command -v nft &>/dev/null && nft list ruleset 2>/dev/null | grep -q 'chain'; then
    FW_OK=1
elif command -v iptables &>/dev/null && iptables -L -n 2>/dev/null | grep -qE 'DROP|REJECT'; then
    FW_OK=1
elif command -v firewall-cmd &>/dev/null && firewall-cmd --state 2>/dev/null | grep -q 'running'; then
    FW_OK=1
fi

if [[ $FW_OK -eq 0 ]]; then
    (( TOTAL_GAPS++ )) || true
    echo "  [GAP] Firewall no activo o sin reglas restrictivas"
    echo "  Impacto: PCI-DSS Req1, ISO27001 A.13, SOC2 SEC-Network"
    echo ""

    if ask_remediate "Habilitar firewall basico"; then
        if command -v firewall-cmd &>/dev/null; then
            systemctl enable firewalld 2>/dev/null || true
            systemctl start firewalld 2>/dev/null || true
            if firewall-cmd --state 2>/dev/null | grep -q 'running'; then
                log_remediation "firewalld habilitado y activo" "OK"
                (( REMEDIATED++ )) || true
            fi
        elif command -v nft &>/dev/null; then
            echo "  Configurar nftables manualmente o usar el modulo de hardening de red"
            log_remediation "nftables: requiere configuracion manual" "PENDIENTE"
        elif command -v iptables &>/dev/null; then
            echo "  Configurar iptables manualmente o usar el modulo de hardening de red"
            log_remediation "iptables: requiere configuracion manual" "PENDIENTE"
        else
            echo "  [ERROR] No se detecta firewall instalado"
        fi
    else
        (( SKIPPED++ )) || true
        echo "  -- Omitido"
    fi
else
    echo "  [OK] Firewall activo con reglas"
fi
echo ""

# ── Gap 6: Banner de seguridad ───────────────────────────
echo "=== Verificacion: Banner de seguridad ==="
if [[ ! -f /etc/issue ]] || [[ ! -s /etc/issue ]]; then
    (( TOTAL_GAPS++ )) || true
    echo "  [GAP] Banner de seguridad no configurado (/etc/issue)"
    echo "  Impacto: PCI-DSS Req12, ISO27001 A.5, SOC2 PRV-Consent"
    echo ""

    if ask_remediate "Configurar banner de seguridad"; then
        [[ -f /etc/issue ]] && cp -a /etc/issue "/etc/issue.bak.$(date +%s)" 2>/dev/null || true
        cat > /etc/issue << 'BANNEREOF'
*************************************************************
* AVISO: Sistema protegido. Acceso solo para personal       *
* autorizado. Toda actividad es monitoreada y registrada.   *
* El uso no autorizado sera procesado legalmente.           *
*************************************************************
BANNEREOF
        log_remediation "Banner de seguridad configurado en /etc/issue" "OK"
        (( REMEDIATED++ )) || true
    else
        (( SKIPPED++ )) || true
        echo "  -- Omitido"
    fi
else
    echo "  [OK] Banner de seguridad configurado"
fi
echo ""

# ── Gap 7: NTP sincronizado ─────────────────────────────
echo "=== Verificacion: Sincronizacion NTP ==="
NTP_OK=0
if command -v chronyc &>/dev/null && chronyc tracking &>/dev/null 2>&1; then
    NTP_OK=1
elif timedatectl show 2>/dev/null | grep -q 'NTPSynchronized=yes'; then
    NTP_OK=1
fi

if [[ $NTP_OK -eq 0 ]]; then
    (( TOTAL_GAPS++ )) || true
    echo "  [GAP] NTP no sincronizado (requerido para logs confiables)"
    echo "  Impacto: PCI-DSS Req10, todos los frameworks"
    echo ""

    if ask_remediate "Habilitar sincronizacion NTP"; then
        if command -v timedatectl &>/dev/null; then
            timedatectl set-ntp true 2>/dev/null || true
            log_remediation "NTP habilitado via timedatectl" "OK"
            (( REMEDIATED++ )) || true
        elif command -v chronyc &>/dev/null; then
            systemctl enable chronyd 2>/dev/null || true
            systemctl start chronyd 2>/dev/null || true
            log_remediation "chronyd habilitado y activo" "OK"
            (( REMEDIATED++ )) || true
        else
            echo "  Instalar chrony o ntp manualmente"
            log_remediation "NTP: instalar chrony manualmente" "PENDIENTE"
        fi
    else
        (( SKIPPED++ )) || true
        echo "  -- Omitido"
    fi
else
    echo "  [OK] NTP sincronizado"
fi
echo ""

# ── Resumen de remediacion ───────────────────────────────
echo "============================================================"
echo "  RESUMEN DE REMEDIACION"
echo "============================================================"
echo ""
echo "  Gaps encontrados: $TOTAL_GAPS"
echo "  Remediados:       $REMEDIATED"
echo "  Omitidos:         $SKIPPED"
echo "  Pendientes:       $(( TOTAL_GAPS - REMEDIATED - SKIPPED ))"
echo ""
echo "  Historial de remediacion: $REMEDIATION_DB"
echo ""

# Mostrar ultimas entradas del DB
if [[ -s "$REMEDIATION_DB" ]]; then
    echo "  Ultimas remediaciones:"
    tail -10 "$REMEDIATION_DB" | while IFS='|' read -r ts action status; do
        printf "    %-25s %-50s [%s]\n" "$ts" "$action" "$status"
    done
fi

echo ""
echo "  Ejecuta 'generar-informe-compliance.sh' para ver el impacto"
echo "  de las remediaciones en el score de cumplimiento."
REMEOF

    chmod 755 "$REMEDIATION_SCRIPT"
    log_change "Creado" "$REMEDIATION_SCRIPT (remediacion guiada con auto-fix)"

else
    log_skip "Herramienta de remediacion guiada"
fi

# ============================================================
# S10: AUDITORIA INTEGRAL DE CUMPLIMIENTO
# ============================================================
log_section "S10: Auditoria integral de cumplimiento"

log_info "Auditoria integral de cumplimiento normativo:"
log_info "  - Ejecuta todas las evaluaciones de frameworks"
log_info "  - Analisis cross-framework de gaps"
log_info "  - Score unificado y overlapping"
log_info "  - Reporte a /var/log/securizar/"

if ask "¿Crear auditoria integral de cumplimiento?"; then

    AUDIT_SCRIPT="$COMPLIANCE_BIN_DIR/auditoria-cumplimiento.sh"

    cat > "$AUDIT_SCRIPT" << 'AUDITEOF'
#!/bin/bash
# ============================================================
# auditoria-cumplimiento.sh - Auditoria integral de cumplimiento
# Parte del Modulo 54 - Cumplimiento Normativo
# ============================================================
set -euo pipefail

CONF_FILE="/etc/securizar/compliance-framework.conf"
if [[ -f "$CONF_FILE" ]]; then
    source "$CONF_FILE"
else
    echo "[!] No se encuentra $CONF_FILE - usando valores por defecto"
fi

EVIDENCE_DIR="${EVIDENCE_DIR:-/var/lib/securizar/compliance-evidence}"
REPORT_DIR="${REPORT_DIR:-/var/log/securizar/compliance-reports}"
ACTIVE_FRAMEWORKS="${ACTIVE_FRAMEWORKS:-pci-dss gdpr}"
ORGANIZATION_NAME="${ORGANIZATION_NAME:-Organizacion}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
AUDIT_LOG="/var/log/securizar/auditoria-cumplimiento-${TIMESTAMP}.log"

mkdir -p /var/log/securizar "$REPORT_DIR"

# Redirigir toda la salida al log tambien
exec > >(tee -a "$AUDIT_LOG") 2>&1

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   AUDITORIA INTEGRAL DE CUMPLIMIENTO NORMATIVO           ║"
echo "║   Securizar - Modulo 54                                  ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "Fecha:        $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Hostname:     $(hostname)"
echo "Organizacion: $ORGANIZATION_NAME"
echo "Frameworks:   $ACTIVE_FRAMEWORKS"
echo ""

# ── Ejecutar todas las evaluaciones ──────────────────────
declare -A FW_SCORES
declare -A FW_RATINGS
declare -A FW_DETAILS
OVERALL_PASS=0
OVERALL_FAIL=0
OVERALL_WARN=0
OVERALL_TOTAL=0

ALL_FRAMEWORKS="pci-dss gdpr hipaa soc2 iso27001"

echo "============================================================"
echo "  FASE 1: EVALUACION DE FRAMEWORKS"
echo "============================================================"
echo ""

for fw in $ALL_FRAMEWORKS; do
    case "$fw" in
        pci-dss)   EVAL_SCRIPT="/usr/local/bin/evaluar-pci-dss.sh"   ; FW_NAME="PCI-DSS v4.0" ;;
        gdpr)      EVAL_SCRIPT="/usr/local/bin/evaluar-gdpr.sh"      ; FW_NAME="GDPR" ;;
        hipaa)     EVAL_SCRIPT="/usr/local/bin/evaluar-hipaa.sh"     ; FW_NAME="HIPAA" ;;
        soc2)      EVAL_SCRIPT="/usr/local/bin/evaluar-soc2.sh"      ; FW_NAME="SOC 2 Type II" ;;
        iso27001)  EVAL_SCRIPT="/usr/local/bin/evaluar-iso27001.sh"  ; FW_NAME="ISO 27001" ;;
    esac

    echo "--- Evaluando: $FW_NAME ---"

    if [[ -f "$EVAL_SCRIPT" ]]; then
        EVAL_OUTPUT=$("$EVAL_SCRIPT" 2>&1) || true

        FW_SCORE=$(echo "$EVAL_OUTPUT" | grep -oP 'Puntuacion:\s*\K[0-9]+' | tail -1 || echo "0")
        FW_PASS=$(echo "$EVAL_OUTPUT" | grep -oP 'PASS:\s*\K[0-9]+' | tail -1 || echo "0")
        FW_FAIL=$(echo "$EVAL_OUTPUT" | grep -oP 'FAIL:\s*\K[0-9]+' | tail -1 || echo "0")
        FW_WARN=$(echo "$EVAL_OUTPUT" | grep -oP 'WARN:\s*\K[0-9]+' | tail -1 || echo "0")

        FW_SCORES[$fw]="${FW_SCORE:-0}"

        if [[ "${FW_SCORE:-0}" -ge 80 ]]; then
            FW_RATINGS[$fw]="BUENO"
        elif [[ "${FW_SCORE:-0}" -ge 50 ]]; then
            FW_RATINGS[$fw]="MEJORABLE"
        else
            FW_RATINGS[$fw]="DEFICIENTE"
        fi

        # Extraer lineas FAIL del output
        FAIL_LINES=$(echo "$EVAL_OUTPUT" | grep -E '\[FAIL\]' || true)
        FW_DETAILS[$fw]="$FAIL_LINES"

        OVERALL_PASS=$(( OVERALL_PASS + ${FW_PASS:-0} ))
        OVERALL_FAIL=$(( OVERALL_FAIL + ${FW_FAIL:-0} ))
        OVERALL_WARN=$(( OVERALL_WARN + ${FW_WARN:-0} ))
        OVERALL_TOTAL=$(( OVERALL_TOTAL + ${FW_PASS:-0} + ${FW_FAIL:-0} + ${FW_WARN:-0} ))

        echo "  Score: ${FW_SCORE:-0}% (${FW_RATINGS[$fw]})"
        echo ""
    else
        echo "  [!] Script no encontrado: $EVAL_SCRIPT"
        FW_SCORES[$fw]=0
        FW_RATINGS[$fw]="NO_DISPONIBLE"
        echo ""
    fi
done

# ── Score unificado ──────────────────────────────────────
UNIFIED_SCORE=0
[[ $OVERALL_TOTAL -gt 0 ]] && UNIFIED_SCORE=$(( (OVERALL_PASS * 100) / OVERALL_TOTAL ))

if [[ $UNIFIED_SCORE -ge 80 ]]; then
    UNIFIED_RATING="BUENO"
elif [[ $UNIFIED_SCORE -ge 50 ]]; then
    UNIFIED_RATING="MEJORABLE"
else
    UNIFIED_RATING="DEFICIENTE"
fi

echo ""
echo "============================================================"
echo "  FASE 2: ANALISIS CROSS-FRAMEWORK"
echo "============================================================"
echo ""

# ── Identificar requisitos overlapping ───────────────────
echo "--- Requisitos comunes entre frameworks ---"
echo ""

# Control de acceso
echo "  CONTROL DE ACCESO:"
echo "    PCI-DSS: Req 7, Req 8"
echo "    GDPR:    Art. 32 (control de acceso)"
echo "    HIPAA:   164.312(a) (Access Control)"
echo "    SOC2:    CC6.1 (Logical Access)"
echo "    ISO27001: A.9 (Access Control)"
echo ""

# Cifrado
echo "  CIFRADO:"
echo "    PCI-DSS: Req 3 (datos almacenados), Req 4 (transmision)"
echo "    GDPR:    Art. 25, Art. 32 (cifrado)"
echo "    HIPAA:   164.312(e) (Transmission), TS-EncRest"
echo "    SOC2:    C1.2 (Encryption)"
echo "    ISO27001: A.10 (Cryptography)"
echo ""

# Logging/Auditoria
echo "  LOGGING Y AUDITORIA:"
echo "    PCI-DSS: Req 10 (Logging)"
echo "    GDPR:    Art. 30 (Registros)"
echo "    HIPAA:   164.312(b) (Audit Controls)"
echo "    SOC2:    PI1.2 (Error Handling)"
echo "    ISO27001: A.12 (Operations Security)"
echo ""

# Respuesta a incidentes
echo "  RESPUESTA A INCIDENTES:"
echo "    PCI-DSS: Req 12 (Politicas)"
echo "    GDPR:    Art. 33 (Notificacion brechas)"
echo "    HIPAA:   164.308(a)(6) (IR)"
echo "    SOC2:    A1.3 (Incident Response)"
echo "    ISO27001: A.16 (Incident Management)"
echo ""

# ── Gap analysis cross-framework ─────────────────────────
echo "--- Analisis de gaps cross-framework ---"
echo ""

# Verificar gaps comunes
COMMON_GAPS=0

# Auditd
if ! systemctl is-active auditd &>/dev/null 2>&1; then
    (( COMMON_GAPS++ )) || true
    echo "  [CROSS-GAP] auditd no activo"
    echo "    Afecta: PCI-DSS(Req10), HIPAA(TS-Audit), ISO27001(A.12), SOC2(PI-Error)"
    echo ""
fi

# Firewall
FW_ACTIVE=0
command -v nft &>/dev/null && nft list ruleset 2>/dev/null | grep -q 'chain' && FW_ACTIVE=1
command -v iptables &>/dev/null && iptables -L -n 2>/dev/null | grep -qE 'DROP|REJECT' && FW_ACTIVE=1
command -v firewall-cmd &>/dev/null && firewall-cmd --state 2>/dev/null | grep -q 'running' && FW_ACTIVE=1

if [[ $FW_ACTIVE -eq 0 ]]; then
    (( COMMON_GAPS++ )) || true
    echo "  [CROSS-GAP] Firewall no activo"
    echo "    Afecta: PCI-DSS(Req1), ISO27001(A.13), SOC2(SEC-Network)"
    echo ""
fi

# Cifrado de disco
if ! lsblk -o TYPE 2>/dev/null | grep -q 'crypt'; then
    (( COMMON_GAPS++ )) || true
    echo "  [CROSS-GAP] Sin cifrado de disco"
    echo "    Afecta: PCI-DSS(Req3), GDPR(Art.25,32), HIPAA(TS-EncRest), SOC2(CON-Encrypt), ISO27001(A.10)"
    echo ""
fi

# MFA
MFA_OK=0
if grep -rq 'pam_google_authenticator\|pam_duo\|pam_yubico\|pam_oath' /etc/pam.d/ 2>/dev/null; then
    MFA_OK=1
fi
if [[ $MFA_OK -eq 0 ]]; then
    (( COMMON_GAPS++ )) || true
    echo "  [CROSS-GAP] MFA no configurado"
    echo "    Afecta: PCI-DSS(Req8), HIPAA(TS-Access), ISO27001(A.9)"
    echo ""
fi

# IR procedures
IR_OK=0
for irfile in /etc/securizar/incident-response* /usr/local/bin/respuesta-incidentes* /usr/local/bin/securizar-incident*; do
    [[ -f "$irfile" ]] 2>/dev/null && IR_OK=1 && break
done
if [[ $IR_OK -eq 0 ]]; then
    (( COMMON_GAPS++ )) || true
    echo "  [CROSS-GAP] Sin procedimientos de respuesta a incidentes"
    echo "    Afecta: PCI-DSS(Req12), GDPR(Art.33), HIPAA(AS-IR), SOC2(AVL-IR), ISO27001(A.16)"
    echo ""
fi

if [[ $COMMON_GAPS -eq 0 ]]; then
    echo "  No se detectaron gaps cross-framework criticos."
    echo ""
fi

echo "  Total gaps cross-framework: $COMMON_GAPS"
echo ""

# ── Informe final ────────────────────────────────────────
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   RESULTADO DE AUDITORIA INTEGRAL                        ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "  Frameworks evaluados:"
echo ""

printf "  %-15s %-8s %-15s\n" "FRAMEWORK" "SCORE" "CALIFICACION"
printf "  %-15s %-8s %-15s\n" "─────────────" "──────" "─────────────"

for fw in $ALL_FRAMEWORKS; do
    local fw_upper
    fw_upper=$(echo "$fw" | tr '[:lower:]' '[:upper:]')
    printf "  %-15s %-8s %-15s\n" "$fw_upper" "${FW_SCORES[$fw]:-0}%" "${FW_RATINGS[$fw]:-N/A}"
done

echo ""
echo "  ┌─────────────────────────────────────────────┐"
echo "  │  SCORE UNIFICADO: ${UNIFIED_SCORE}%"
echo "  │  CALIFICACION:    ${UNIFIED_RATING}"
echo "  │"
echo "  │  Controles totales: $OVERALL_TOTAL"
echo "  │  PASS: $OVERALL_PASS | FAIL: $OVERALL_FAIL | WARN: $OVERALL_WARN"
echo "  │  Gaps cross-framework: $COMMON_GAPS"
echo "  └─────────────────────────────────────────────┘"
echo ""

# Recomendaciones
echo "  RECOMENDACIONES:"
if [[ $UNIFIED_SCORE -lt 50 ]]; then
    echo "  [!!!] Nivel DEFICIENTE - Se requieren acciones inmediatas"
    echo "    1. Ejecutar: remediar-compliance.sh"
    echo "    2. Priorizar gaps cross-framework"
    echo "    3. Habilitar auditd, firewall y cifrado"
    echo "    4. Implementar MFA y politicas de contrasenas"
elif [[ $UNIFIED_SCORE -lt 80 ]]; then
    echo "  [!] Nivel MEJORABLE - Hay oportunidades de mejora"
    echo "    1. Ejecutar: remediar-compliance.sh"
    echo "    2. Revisar controles WARN y evaluar riesgo"
    echo "    3. Completar documentacion (inventarios, politicas, DPIA)"
    echo "    4. Programar evaluaciones periodicas"
else
    echo "  [+] Nivel BUENO - Mantener postura actual"
    echo "    1. Continuar con evaluaciones periodicas"
    echo "    2. Revisar controles WARN restantes"
    echo "    3. Mantener evidencias actualizadas"
fi

echo ""
echo "  Log de auditoria: $AUDIT_LOG"
echo ""
echo "  Proximos pasos:"
echo "    - Remediacion: remediar-compliance.sh"
echo "    - Informe:     generar-informe-compliance.sh"
echo "    - Evidencias:  recopilar-evidencias.sh"
echo ""
AUDITEOF

    chmod 755 "$AUDIT_SCRIPT"
    log_change "Creado" "$AUDIT_SCRIPT (auditoria integral cross-framework)"

    # ── S10.2: Cron semanal ──────────────────────────────
    AUDIT_CRON="/etc/cron.weekly/auditoria-cumplimiento"

    cat > "$AUDIT_CRON" << 'CRONAUDITEOF'
#!/bin/bash
# Auditoria semanal de cumplimiento normativo - Securizar Modulo 54
/usr/local/bin/auditoria-cumplimiento.sh >> /var/log/securizar/auditoria-cumplimiento-weekly.log 2>&1

# Limpiar logs antiguos (>365 dias por defecto)
CONF="/etc/securizar/compliance-framework.conf"
RETENTION=365
[[ -f "$CONF" ]] && source "$CONF" 2>/dev/null && RETENTION="${RETENTION_DAYS:-365}"

find /var/log/securizar -name "auditoria-cumplimiento-*.log" -mtime +"$RETENTION" -delete 2>/dev/null || true
find /var/log/securizar/compliance-reports -name "*.txt" -mtime +"$RETENTION" -delete 2>/dev/null || true
CRONAUDITEOF

    chmod 755 "$AUDIT_CRON"
    log_change "Creado" "$AUDIT_CRON (cron semanal de auditoria de cumplimiento)"

else
    log_skip "Auditoria integral de cumplimiento"
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
show_changes_summary

log_section "MODULO 54: CUMPLIMIENTO NORMATIVO - COMPLETADO"
log_info "Backups guardados en: $BACKUP_DIR"

log_info "Scripts de evaluacion creados:"
log_info "  - evaluar-pci-dss.sh     (PCI-DSS v4.0, 12 requisitos)"
log_info "  - evaluar-gdpr.sh        (GDPR, 7 controles)"
log_info "  - evaluar-hipaa.sh       (HIPAA, safeguards admin/fisicos/tecnicos)"
log_info "  - evaluar-soc2.sh        (SOC 2 Type II, 5 categorias TSC)"
log_info "  - evaluar-iso27001.sh    (ISO 27001 Annex A, 10 dominios)"
log_info ""
log_info "Herramientas de gestion:"
log_info "  - securizar-compliance-init.sh    (inicializar entorno)"
log_info "  - recopilar-evidencias.sh         (recoleccion automatica)"
log_info "  - generar-informe-compliance.sh   (informes HTML/JSON)"
log_info "  - remediar-compliance.sh          (remediacion guiada)"
log_info "  - auditoria-cumplimiento.sh       (auditoria integral)"
log_info ""
log_info "Crons programados:"
log_info "  - /etc/cron.monthly/securizar-evidencias-compliance"
log_info "  - /etc/cron.weekly/auditoria-cumplimiento"
log_info ""
log_warn "RECOMENDACION: Ejecuta 'auditoria-cumplimiento.sh' para ver la postura actual"
log_warn "RECOMENDACION: Edita /etc/securizar/compliance-framework.conf con tus frameworks activos"
log_info "Modulo 54 completado"
