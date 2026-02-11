#!/bin/bash
# ============================================================
# zero-trust-identity.sh - Modulo 59: Zero Trust Identity
# ============================================================
# Secciones:
#   S1  - Evaluacion de madurez Zero Trust
#   S2  - Politica Zero Trust
#   S3  - Autenticacion continua
#   S4  - Device trust y compliance
#   S5  - Identity-Aware Proxy (IAP)
#   S6  - Micro-segmentacion basada en identidad
#   S7  - Least privilege enforcement
#   S8  - Session management y monitorizacion
#   S9  - Integracion con SSO y MFA
#   S10 - Auditoria integral Zero Trust
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps
init_backup "zero-trust-identity"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MODULO 59 - ZERO TRUST IDENTITY                        ║"
echo "║   Evaluacion, politicas, autenticacion continua           ║"
echo "║   Device trust, IAP, micro-segmentacion, least priv       ║"
echo "║   Sesiones, SSO/MFA, auditoria integral                   ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

log_section "MODULO 59: ZERO TRUST IDENTITY"
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

# ── Helpers ──────────────────────────────────────────────────

# Ensure directories exist
ensure_dirs() {
    local dir
    for dir in "$@"; do
        [[ -d "$dir" ]] || mkdir -p "$dir"
    done
}

# Safe write: backup then write
safe_write_file() {
    local dest="$1"
    local perms="${2:-0644}"
    if [[ -f "$dest" ]]; then
        cp -a "$dest" "${BACKUP_DIR}/$(basename "$dest").$(date +%s).bak" 2>/dev/null || true
    fi
    local parent
    parent="$(dirname "$dest")"
    [[ -d "$parent" ]] || mkdir -p "$parent"
    cat > "$dest"
    chmod "$perms" "$dest"
}

# Check if a command exists
cmd_exists() {
    command -v "$1" &>/dev/null
}

# Check if a service is active
service_active() {
    systemctl is-active "$1" &>/dev/null 2>&1
}

# Check if a service unit exists
service_exists() {
    systemctl list-unit-files "$1.service" 2>/dev/null | grep -q "$1" 2>/dev/null
}

###############################################################################
# S1: Evaluacion de madurez Zero Trust
###############################################################################
log_section "S1: Evaluacion de madurez Zero Trust"

if ask "Crear herramienta de evaluacion Zero Trust (/usr/local/bin/evaluar-zero-trust.sh)?"; then

    ensure_dirs /usr/local/bin /var/log/securizar

    safe_write_file "/usr/local/bin/evaluar-zero-trust.sh" "0755" << 'ENDSCRIPT'
#!/bin/bash
# ============================================================
# evaluar-zero-trust.sh - Evaluacion de madurez Zero Trust
# ============================================================
# Evalua los 5 pilares del modelo Zero Trust:
#   1. Identidad  2. Dispositivos  3. Redes
#   4. Aplicaciones  5. Datos
# Mapea a CISA Zero Trust Maturity Model
# ============================================================
set -euo pipefail

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
BOLD="\033[1m"
NC="\033[0m"

REPORT_DIR="/var/log/securizar"
REPORT="${REPORT_DIR}/evaluacion-zt-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$REPORT_DIR"

log_eval() { echo "$1" | tee -a "$REPORT"; }
log_header() { echo -e "\n${CYAN}=== $1 ===${NC}" | tee -a "$REPORT"; }

log_eval "=============================================="
log_eval "  EVALUACION DE MADUREZ ZERO TRUST"
log_eval "  Fecha: $(date "+%Y-%m-%d %H:%M:%S")"
log_eval "  Host: $(hostname)"
log_eval "=============================================="

# ── Pilar 1: Identidad ──────────────────────────────────────
log_header "PILAR 1: IDENTIDAD"
IDENTITY_SCORE=0
IDENTITY_MAX=100
IDENTITY_CHECKS=0
IDENTITY_PASS=0

# Check: Password policy configured
check_identity() {
    local name="$1" check="$2" weight="$3"
    IDENTITY_CHECKS=$((IDENTITY_CHECKS + 1))
    if eval "$check" 2>/dev/null; then
        log_eval "  [OK] $name"
        IDENTITY_PASS=$((IDENTITY_PASS + 1))
        IDENTITY_SCORE=$((IDENTITY_SCORE + weight))
    else
        log_eval "  [NO] $name"
    fi
}

# MFA configured (google-authenticator or pam_u2f)
check_identity "MFA configurado (pam_google_authenticator o pam_u2f)" \
    "grep -rqs 'pam_google_authenticator\|pam_u2f' /etc/pam.d/" 15

# SSO integration (SSSD, Kerberos, LDAP)
check_identity "SSO/IdP integrado (SSSD, Kerberos, LDAP)" \
    "command -v sssd >/dev/null 2>&1 || command -v kinit >/dev/null 2>&1 || grep -rqs 'pam_ldap\|pam_sss\|pam_krb5' /etc/pam.d/" 15

# Password complexity (pwquality or cracklib)
check_identity "Politica de complejidad de password" \
    "test -f /etc/security/pwquality.conf && grep -qsE '^\s*minlen\s*=\s*[0-9]' /etc/security/pwquality.conf" 10

# Password aging
check_identity "Envejecimiento de passwords configurado" \
    "grep -qsE '^\s*PASS_MAX_DAYS\s+[0-9]+' /etc/login.defs && ! grep -qsE '^\s*PASS_MAX_DAYS\s+99999' /etc/login.defs" 10

# Certificate-based auth (SSH certs or client certs)
check_identity "Autenticacion basada en certificados" \
    "grep -rqs 'TrustedUserCAKeys' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null || test -d /etc/ssl/client-certs" 10

# Account lockout policy
check_identity "Politica de bloqueo de cuentas" \
    "grep -rqs 'pam_faillock\|pam_tally2' /etc/pam.d/" 10

# No accounts without passwords
check_identity "No hay cuentas sin password" \
    "! awk -F: '\$2==\"\" {found=1} END{exit !found}' /etc/shadow 2>/dev/null" 10

# Root login restricted
check_identity "Login de root restringido via SSH" \
    "grep -qsE '^\s*PermitRootLogin\s+(no|prohibit-password)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null" 10

# Unique UIDs
check_identity "UIDs unicos (sin duplicados)" \
    "test $(awk -F: '\"'\"'{print $3}'\"'\"' /etc/passwd | sort | uniq -d | wc -l) -eq 0" 5

# Sudo requires password
check_identity "Sudo requiere autenticacion" \
    "! grep -rqsE '^\s*[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null" 5

log_eval ""
log_eval "  Puntuacion Identidad: ${IDENTITY_SCORE}/${IDENTITY_MAX}"

# ── Pilar 2: Dispositivos ───────────────────────────────────
log_header "PILAR 2: DISPOSITIVOS"
DEVICE_SCORE=0
DEVICE_MAX=100

check_device() {
    local name="$1" check="$2" weight="$3"
    if eval "$check" 2>/dev/null; then
        log_eval "  [OK] $name"
        DEVICE_SCORE=$((DEVICE_SCORE + weight))
    else
        log_eval "  [NO] $name"
    fi
}

# Disk encryption
check_device "Cifrado de disco (LUKS)" \
    "lsblk -o TYPE 2>/dev/null | grep -q crypt || dmsetup ls --target crypt 2>/dev/null | grep -q ." 20

# Firewall active
check_device "Firewall activo" \
    "systemctl is-active firewalld >/dev/null 2>&1 || systemctl is-active ufw >/dev/null 2>&1 || iptables -L -n 2>/dev/null | grep -qv 'Chain .* (policy ACCEPT)'" 15

# AIDE or file integrity monitoring
check_device "Monitoreo de integridad (AIDE/OSSEC/Tripwire)" \
    "command -v aide >/dev/null 2>&1 || command -v ossec-control >/dev/null 2>&1 || command -v tripwire >/dev/null 2>&1" 15

# OS patches up to date (check if reboot needed or pending updates)
check_device "Parches del SO al dia" \
    "! test -f /var/run/reboot-required 2>/dev/null && ! needs-restarting -r 2>/dev/null" 15

# Secure Boot
check_device "Secure Boot habilitado" \
    "mokutil --sb-state 2>/dev/null | grep -qi 'SecureBoot enabled'" 10

# Screen lock configured
check_device "Bloqueo de pantalla configurado" \
    "command -v xdg-screensaver >/dev/null 2>&1 || gsettings get org.gnome.desktop.session idle-delay 2>/dev/null | grep -v 'uint32 0'" 5

# Antivirus (ClamAV)
check_device "Antivirus instalado (ClamAV)" \
    "command -v clamscan >/dev/null 2>&1 || command -v freshclam >/dev/null 2>&1" 10

# Auditd running
check_device "Sistema de auditoria activo (auditd)" \
    "systemctl is-active auditd >/dev/null 2>&1" 10

log_eval ""
log_eval "  Puntuacion Dispositivos: ${DEVICE_SCORE}/${DEVICE_MAX}"

# ── Pilar 3: Redes ──────────────────────────────────────────
log_header "PILAR 3: REDES"
NETWORK_SCORE=0
NETWORK_MAX=100

check_network() {
    local name="$1" check="$2" weight="$3"
    if eval "$check" 2>/dev/null; then
        log_eval "  [OK] $name"
        NETWORK_SCORE=$((NETWORK_SCORE + weight))
    else
        log_eval "  [NO] $name"
    fi
}

# Firewall with explicit rules
check_network "Firewall con reglas explicitas" \
    "iptables -L -n 2>/dev/null | grep -cE 'ACCEPT|DROP|REJECT' | grep -qv '^0$' || nft list ruleset 2>/dev/null | grep -q 'chain'" 15

# Network segmentation (multiple interfaces or VLANs)
check_network "Segmentacion de red (VLANs/interfaces multiples)" \
    "ip link show 2>/dev/null | grep -cE 'state UP' | grep -qvE '^[01]$' || ip link show 2>/dev/null | grep -q 'vlan'" 10

# TLS 1.3 supported
check_network "TLS 1.3 soportado" \
    "openssl s_client -help 2>&1 | grep -q tls1_3 || openssl version 2>/dev/null | grep -qE '1\.[1-9]|3\.[0-9]'" 15

# DNS encryption (DoT/DoH)
check_network "DNS cifrado (DoT/DoH configurado)" \
    "grep -rqs 'DNSOverTLS' /etc/systemd/resolved.conf /etc/systemd/resolved.conf.d/ 2>/dev/null || command -v stubby >/dev/null 2>&1 || grep -qs '853' /etc/resolv.conf" 10

# SSH with strong ciphers
check_network "SSH con cifrado fuerte" \
    "grep -qsE '^\s*Ciphers\s+.*aes.*gcm' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null" 10

# No unnecessary listening services
check_network "Servicios de escucha limitados (<15)" \
    "test $(ss -tlnp 2>/dev/null | grep -c LISTEN) -lt 15" 10

# IP forwarding disabled (unless router)
check_network "IP forwarding deshabilitado" \
    "test $(sysctl -n net.ipv4.ip_forward 2>/dev/null) -eq 0" 10

# VPN configured
check_network "VPN configurado (WireGuard/OpenVPN/IPsec)" \
    "command -v wg >/dev/null 2>&1 || command -v openvpn >/dev/null 2>&1 || ip xfrm state 2>/dev/null | grep -q proto" 10

# Network monitoring (tcpdump, nmap, etc)
check_network "Herramientas de monitoreo de red disponibles" \
    "command -v tcpdump >/dev/null 2>&1 || command -v tshark >/dev/null 2>&1" 5

# Fail2ban or similar
check_network "Proteccion contra fuerza bruta (fail2ban)" \
    "command -v fail2ban-client >/dev/null 2>&1 && systemctl is-active fail2ban >/dev/null 2>&1" 5

log_eval ""
log_eval "  Puntuacion Redes: ${NETWORK_SCORE}/${NETWORK_MAX}"

# ── Pilar 4: Aplicaciones ───────────────────────────────────
log_header "PILAR 4: APLICACIONES"
APP_SCORE=0
APP_MAX=100

check_app() {
    local name="$1" check="$2" weight="$3"
    if eval "$check" 2>/dev/null; then
        log_eval "  [OK] $name"
        APP_SCORE=$((APP_SCORE + weight))
    else
        log_eval "  [NO] $name"
    fi
}

# AppArmor or SELinux active
check_app "MAC activo (AppArmor/SELinux)" \
    "command -v aa-status >/dev/null 2>&1 && aa-status 2>/dev/null | grep -q 'profiles are loaded' || getenforce 2>/dev/null | grep -qi enforcing" 20

# Least privilege for services (non-root)
check_app "Servicios con minimo privilegio (no root)" \
    "test \$(ps aux 2>/dev/null | awk '\$1==\"root\" && \$11 !~ /\\[/ && \$11 !~ /^(\/usr\/lib\/systemd|\/sbin|\/lib\/systemd|systemd)/' | wc -l) -lt 30" 15

# Package signature verification enabled
check_app "Verificacion de firmas de paquetes" \
    "grep -qsE '^\s*gpgcheck\s*=\s*1' /etc/yum.conf /etc/dnf/dnf.conf 2>/dev/null || grep -qsE '^\s*repo_gpgcheck' /etc/zypp/zypp.conf 2>/dev/null || test -d /etc/apt/trusted.gpg.d" 15

# No world-writable executables
check_app "Sin ejecutables world-writable en /usr" \
    "test $(find /usr/bin /usr/sbin -perm -o+w -type f 2>/dev/null | head -5 | wc -l) -eq 0" 15

# Audit rules for sensitive binaries
check_app "Reglas de auditoria para binarios sensibles" \
    "auditctl -l 2>/dev/null | grep -qE '/usr/bin/passwd|/usr/sbin/useradd|execve'" 10

# Application whitelisting (fapolicyd)
check_app "Application whitelisting (fapolicyd)" \
    "command -v fapolicyd >/dev/null 2>&1 || test -f /etc/fapolicyd/fapolicyd.conf" 10

# Containers isolated (namespaces)
check_app "Aislamiento de contenedores/namespaces" \
    "command -v docker >/dev/null 2>&1 && docker info 2>/dev/null | grep -qi 'security.*apparmor\|seccomp\|selinux' || sysctl user.max_user_namespaces 2>/dev/null | grep -qv ' 0'" 10

# Seccomp available
check_app "Seccomp disponible" \
    "grep -q SECCOMP /proc/self/status 2>/dev/null || grep -q CONFIG_SECCOMP /boot/config-$(uname -r) 2>/dev/null" 5

log_eval ""
log_eval "  Puntuacion Aplicaciones: ${APP_SCORE}/${APP_MAX}"

# ── Pilar 5: Datos ──────────────────────────────────────────
log_header "PILAR 5: DATOS"
DATA_SCORE=0
DATA_MAX=100

check_data() {
    local name="$1" check="$2" weight="$3"
    if eval "$check" 2>/dev/null; then
        log_eval "  [OK] $name"
        DATA_SCORE=$((DATA_SCORE + weight))
    else
        log_eval "  [NO] $name"
    fi
}

# Disk encryption
check_data "Cifrado de datos en reposo (LUKS/dm-crypt)" \
    "lsblk -o TYPE 2>/dev/null | grep -q crypt || dmsetup ls --target crypt 2>/dev/null | grep -q ." 20

# File permissions restrictive (no world-readable in /etc sensitive)
check_data "Permisos restrictivos en archivos sensibles" \
    "test $(stat -c %a /etc/shadow 2>/dev/null) = 640 || test $(stat -c %a /etc/shadow 2>/dev/null) = 600 || test $(stat -c %a /etc/shadow 2>/dev/null) = 000" 15

# Backup encryption
check_data "Backups cifrados" \
    "command -v gpg >/dev/null 2>&1 || command -v age >/dev/null 2>&1" 10

# Log integrity
check_data "Integridad de logs (journald firmado o syslog remoto)" \
    "grep -qsE '^\s*Seal=yes' /etc/systemd/journald.conf 2>/dev/null || grep -rqs '@.*:514\|@@' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null" 15

# Umask restrictive
check_data "Umask restrictivo (027 o 077)" \
    "grep -qsE 'umask\s+(027|077)' /etc/profile /etc/bashrc /etc/login.defs 2>/dev/null" 10

# Tmp mounted noexec
check_data "/tmp montado con noexec" \
    "mount 2>/dev/null | grep '/tmp' | grep -q noexec" 10

# Data classification policy exists
check_data "Politica de clasificacion de datos" \
    "test -f /etc/securizar/data-classification.conf || test -f /etc/securizar/zero-trust-policy.conf" 10

# DLP tools
check_data "Herramientas DLP disponibles" \
    "command -v openscap >/dev/null 2>&1 || command -v oscap >/dev/null 2>&1 || test -f /etc/securizar/dlp-rules.conf" 10

log_eval ""
log_eval "  Puntuacion Datos: ${DATA_SCORE}/${DATA_MAX}"

# ── Resumen ─────────────────────────────────────────────────
log_header "RESUMEN DE MADUREZ ZERO TRUST"

TOTAL_SCORE=$((IDENTITY_SCORE + DEVICE_SCORE + NETWORK_SCORE + APP_SCORE + DATA_SCORE))
TOTAL_MAX=$((IDENTITY_MAX + DEVICE_MAX + NETWORK_MAX + APP_MAX + DATA_MAX))
OVERALL=$((TOTAL_SCORE * 100 / TOTAL_MAX))

log_eval ""
log_eval "  Pilar Identidad:     ${IDENTITY_SCORE}/100"
log_eval "  Pilar Dispositivos:  ${DEVICE_SCORE}/100"
log_eval "  Pilar Redes:         ${NETWORK_SCORE}/100"
log_eval "  Pilar Aplicaciones:  ${APP_SCORE}/100"
log_eval "  Pilar Datos:         ${DATA_SCORE}/100"
log_eval "  ------------------------------------------"
log_eval "  TOTAL:               ${TOTAL_SCORE}/${TOTAL_MAX}"
log_eval "  PUNTUACION GLOBAL:   ${OVERALL}%"
log_eval ""

# Map to CISA Zero Trust Maturity Model levels
if [[ $OVERALL -ge 80 ]]; then
    MATURITY="OPTIMO - Nivel Avanzado"
    log_eval "  Nivel CISA: ${MATURITY}"
    log_eval "  La organizacion tiene una postura Zero Trust madura."
elif [[ $OVERALL -ge 60 ]]; then
    MATURITY="BUENO - Nivel Intermedio Avanzado"
    log_eval "  Nivel CISA: ${MATURITY}"
    log_eval "  Buena base Zero Trust con areas de mejora."
elif [[ $OVERALL -ge 40 ]]; then
    MATURITY="MEJORABLE - Nivel Intermedio"
    log_eval "  Nivel CISA: ${MATURITY}"
    log_eval "  Se requieren mejoras significativas en varios pilares."
elif [[ $OVERALL -ge 20 ]]; then
    MATURITY="DEFICIENTE - Nivel Inicial"
    log_eval "  Nivel CISA: ${MATURITY}"
    log_eval "  Implementacion Zero Trust en etapas tempranas."
else
    MATURITY="CRITICO - Nivel Tradicional"
    log_eval "  Nivel CISA: ${MATURITY}"
    log_eval "  No hay implementacion Zero Trust significativa."
fi

log_eval ""
log_eval "Reporte guardado en: ${REPORT}"
log_eval "=============================================="

ENDSCRIPT

    log_change "Creado" "/usr/local/bin/evaluar-zero-trust.sh - evaluacion madurez Zero Trust (5 pilares, CISA)"
else
    log_skip "Herramienta de evaluacion Zero Trust"
fi

###############################################################################
# S2: Politica Zero Trust
###############################################################################
log_section "S2: Politica Zero Trust"

if ask "Crear configuracion de politica Zero Trust (/etc/securizar/zero-trust-policy.conf)?"; then

    ensure_dirs /etc/securizar

    safe_write_file "/etc/securizar/zero-trust-policy.conf" "0640" << 'ENDSCRIPT'
# ============================================================
# zero-trust-policy.conf - Politica Zero Trust
# ============================================================
# Principio fundamental: Nunca confiar, siempre verificar
# Referencia: NIST SP 800-207 / CISA Zero Trust Maturity Model
# ============================================================

# ── Identidad ────────────────────────────────────────────────
# Verificar siempre la identidad antes de conceder acceso
VERIFY_IDENTITY=always

# Requerir autenticacion multi-factor
REQUIRE_MFA=yes

# Tipo de MFA preferido: totp, u2f, certificate, push
MFA_TYPE=totp

# Duracion maxima de sesion en segundos (1 hora)
SESSION_TIMEOUT=3600

# Reautenticacion continua
CONTINUOUS_AUTH=yes

# Intervalo de reautenticacion en segundos (15 min)
REAUTH_INTERVAL=900

# ── Dispositivos ─────────────────────────────────────────────
# Verificar salud del dispositivo antes de acceso
REQUIRE_DEVICE_HEALTH=yes

# Puntuacion minima de confianza del dispositivo (0-100)
MIN_DEVICE_TRUST_SCORE=70

# Verificar cifrado de disco
REQUIRE_DISK_ENCRYPTION=yes

# Verificar firewall activo
REQUIRE_FIREWALL=yes

# Verificar parches al dia
REQUIRE_PATCHES_CURRENT=yes

# ── Red ──────────────────────────────────────────────────────
# Nivel minimo de cifrado para comunicaciones
MIN_ENCRYPTION_LEVEL=tls1.3

# Tipo de segmentacion de red
NETWORK_SEGMENTATION=microseg

# Cifrado de DNS
REQUIRE_ENCRYPTED_DNS=yes

# VPN requerida para acceso remoto
REQUIRE_VPN_REMOTE=yes

# ── Aplicaciones ─────────────────────────────────────────────
# Principio de minimo privilegio
LEAST_PRIVILEGE=enforce

# MAC obligatorio (AppArmor/SELinux)
REQUIRE_MAC=yes

# Modo MAC: enforce, complain, permissive
MAC_MODE=enforce

# Verificacion de integridad de aplicaciones
APP_INTEGRITY_CHECK=yes

# ── Datos ────────────────────────────────────────────────────
# Cifrado de datos en reposo
REQUIRE_DATA_ENCRYPTION=yes

# Clasificacion de datos requerida
REQUIRE_DATA_CLASSIFICATION=yes

# Niveles de clasificacion: publico, interno, confidencial, secreto
DATA_CLASSIFICATION_LEVELS=publico,interno,confidencial,secreto

# Prevencion de perdida de datos
DLP_ENABLED=yes

# ── Logging y Auditoria ─────────────────────────────────────
# Logging centralizado requerido
CENTRALIZED_LOGGING=yes

# Retencion de logs en dias
LOG_RETENTION_DAYS=365

# Auditoria de accesos habilitada
ACCESS_AUDIT=yes

# Alertas de anomalias
ANOMALY_ALERTS=yes

# ── Respuesta a Incidentes ───────────────────────────────────
# Bloqueo automatico ante anomalias
AUTO_BLOCK_ANOMALIES=yes

# Tiempo de bloqueo en segundos (30 min)
BLOCK_DURATION=1800

# Notificar administradores
NOTIFY_ADMINS=yes

# Canal de notificacion: email, syslog, webhook
NOTIFY_CHANNEL=syslog

ENDSCRIPT

    log_change "Creado" "/etc/securizar/zero-trust-policy.conf - politica Zero Trust completa"

    # Script para aplicar la politica
    safe_write_file "/usr/local/bin/aplicar-politica-zt.sh" "0755" << 'ENDSCRIPT'
#!/bin/bash
# ============================================================
# aplicar-politica-zt.sh - Aplicar politica Zero Trust
# ============================================================
# Lee /etc/securizar/zero-trust-policy.conf y aplica controles
# ============================================================
set -euo pipefail

POLICY_FILE="/etc/securizar/zero-trust-policy.conf"
LOG_FILE="/var/log/securizar/aplicar-politica-zt-$(date +%Y%m%d-%H%M%S).log"
mkdir -p /var/log/securizar

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
BOLD="\033[1m"
NC="\033[0m"

log_p() { echo -e "$1" | tee -a "$LOG_FILE"; }
log_ok() { log_p "${GREEN}[OK]${NC} $1"; }
log_fail() { log_p "${RED}[FAIL]${NC} $1"; }
log_warn() { log_p "${YELLOW}[WARN]${NC} $1"; }
log_head() { log_p "\n${CYAN}=== $1 ===${NC}"; }

if [[ ! -f "$POLICY_FILE" ]]; then
    log_fail "Archivo de politica no encontrado: $POLICY_FILE"
    exit 1
fi

# Source policy (validated: KEY=value format only)
while IFS= read -r line; do
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$line" || "$line" == \#* ]] && continue
    if [[ "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then
        eval "ZT_$line"
    fi
done < "$POLICY_FILE"

log_p "=============================================="
log_p "  APLICACION DE POLITICA ZERO TRUST"
log_p "  Fecha: $(date "+%Y-%m-%d %H:%M:%S")"
log_p "=============================================="

VIOLATIONS=0

# ── Verificar Identidad ──────────────────────────────────────
log_head "POLITICA DE IDENTIDAD"

if [[ "${ZT_REQUIRE_MFA:-no}" == "yes" ]]; then
    if grep -rqs "pam_google_authenticator\|pam_u2f" /etc/pam.d/; then
        log_ok "MFA configurado en PAM"
    else
        log_fail "MFA NO configurado en PAM - VIOLACION DE POLITICA"
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
fi

if [[ "${ZT_CONTINUOUS_AUTH:-no}" == "yes" ]]; then
    SUDO_TIMEOUT=$(sudo -V 2>/dev/null | grep "Authentication timestamp timeout" | awk "{print \$NF}" || echo "unknown")
    if [[ "$SUDO_TIMEOUT" != "unknown" ]]; then
        log_ok "Sudo timeout configurado: ${SUDO_TIMEOUT}"
    else
        log_warn "No se pudo verificar sudo timeout"
    fi
fi

if [[ "${ZT_SESSION_TIMEOUT:-0}" -gt 0 ]]; then
    TMOUT_SET=$(grep -rsE "^\s*TMOUT=" /etc/profile /etc/profile.d/ /etc/bashrc 2>/dev/null | head -1 || true)
    if [[ -n "$TMOUT_SET" ]]; then
        log_ok "Timeout de sesion configurado: $TMOUT_SET"
    else
        log_fail "Timeout de sesion NO configurado - VIOLACION"
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
fi

# ── Verificar Dispositivo ────────────────────────────────────
log_head "POLITICA DE DISPOSITIVO"

if [[ "${ZT_REQUIRE_DISK_ENCRYPTION:-no}" == "yes" ]]; then
    if lsblk -o TYPE 2>/dev/null | grep -q crypt || dmsetup ls --target crypt 2>/dev/null | grep -q .; then
        log_ok "Cifrado de disco activo"
    else
        log_fail "Cifrado de disco NO detectado - VIOLACION"
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
fi

if [[ "${ZT_REQUIRE_FIREWALL:-no}" == "yes" ]]; then
    if systemctl is-active firewalld >/dev/null 2>&1 || systemctl is-active ufw >/dev/null 2>&1 || \
       systemctl is-active nftables >/dev/null 2>&1; then
        log_ok "Firewall activo"
    else
        log_fail "Firewall NO activo - VIOLACION"
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
fi

# ── Verificar Red ────────────────────────────────────────────
log_head "POLITICA DE RED"

if [[ "${ZT_MIN_ENCRYPTION_LEVEL:-}" == "tls1.3" ]]; then
    if openssl version 2>/dev/null | grep -qE "1\.[1-9]|3\.[0-9]"; then
        log_ok "OpenSSL soporta TLS 1.3"
    else
        log_warn "OpenSSL puede no soportar TLS 1.3"
    fi

    # Check sshd ciphers
    if grep -rqsE "^\s*Ciphers\s+.*aes.*gcm" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null; then
        log_ok "SSH usa cifrados fuertes (AES-GCM)"
    else
        log_warn "SSH podria mejorarse con cifrados AES-GCM"
    fi
fi

if [[ "${ZT_REQUIRE_ENCRYPTED_DNS:-no}" == "yes" ]]; then
    if grep -rqs "DNSOverTLS" /etc/systemd/resolved.conf /etc/systemd/resolved.conf.d/ 2>/dev/null; then
        log_ok "DNS sobre TLS configurado"
    else
        log_fail "DNS cifrado NO configurado - VIOLACION"
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
fi

# ── Verificar Aplicaciones ───────────────────────────────────
log_head "POLITICA DE APLICACIONES"

if [[ "${ZT_REQUIRE_MAC:-no}" == "yes" ]]; then
    if command -v aa-status >/dev/null 2>&1 && aa-status 2>/dev/null | grep -q "profiles are loaded"; then
        log_ok "AppArmor activo"
    elif getenforce 2>/dev/null | grep -qi enforcing; then
        log_ok "SELinux en modo enforcing"
    else
        log_fail "MAC (AppArmor/SELinux) NO activo - VIOLACION"
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
fi

if [[ "${ZT_LEAST_PRIVILEGE:-}" == "enforce" ]]; then
    NOPASSWD_COUNT=$(grep -rcsE "^\s*[^#].*NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | awk -F: "{s+=\$NF} END{print s}" || echo 0)
    if [[ "$NOPASSWD_COUNT" -eq 0 ]]; then
        log_ok "No hay reglas NOPASSWD en sudoers"
    else
        log_fail "Encontradas ${NOPASSWD_COUNT} reglas NOPASSWD - VIOLACION de minimo privilegio"
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
fi

# ── Verificar Datos ──────────────────────────────────────────
log_head "POLITICA DE DATOS"

if [[ "${ZT_REQUIRE_DATA_ENCRYPTION:-no}" == "yes" ]]; then
    if lsblk -o TYPE 2>/dev/null | grep -q crypt; then
        log_ok "Cifrado de datos en reposo activo"
    else
        log_fail "Cifrado de datos en reposo NO activo - VIOLACION"
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
fi

if [[ "${ZT_CENTRALIZED_LOGGING:-no}" == "yes" ]]; then
    if grep -rqs "@.*:514\|@@" /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null || \
       systemctl is-active rsyslog >/dev/null 2>&1; then
        log_ok "Logging centralizado configurado"
    else
        log_warn "Logging centralizado puede no estar configurado"
    fi
fi

# ── Resultado ────────────────────────────────────────────────
log_p ""
log_p "=============================================="
if [[ $VIOLATIONS -eq 0 ]]; then
    log_p "  ${GREEN}${BOLD}RESULTADO: CUMPLIMIENTO TOTAL${NC}"
    log_p "  No se encontraron violaciones de politica."
else
    log_p "  ${RED}${BOLD}RESULTADO: ${VIOLATIONS} VIOLACIONES ENCONTRADAS${NC}"
    log_p "  Se requieren acciones correctivas."
fi
log_p "=============================================="
log_p "Reporte: $LOG_FILE"

ENDSCRIPT

    log_change "Creado" "/usr/local/bin/aplicar-politica-zt.sh - script de aplicacion de politica"
else
    log_skip "Politica Zero Trust"
fi

###############################################################################
# S3: Autenticacion continua
###############################################################################
log_section "S3: Autenticacion continua"

if ask "Configurar autenticacion continua y re-verificacion?"; then

    ensure_dirs /usr/local/bin /var/log/securizar

    # ── PAM: Reduce sudo timestamp to 5 min ──────────────────
    SUDOERS_DIR="/etc/sudoers.d"
    ZT_SUDOERS="${SUDOERS_DIR}/99-zero-trust-timeout"

    if [[ -d "$SUDOERS_DIR" ]]; then
        if [[ -f "$ZT_SUDOERS" ]]; then
            cp -a "$ZT_SUDOERS" "${BACKUP_DIR}/99-zero-trust-timeout.bak" 2>/dev/null || true
        fi
        cat > "$ZT_SUDOERS" << 'SUDOEOF'
# Zero Trust: Reducir timeout de sudo a 5 minutos
# Requiere reautenticacion frecuente
Defaults timestamp_timeout=5
Defaults passwd_timeout=2
Defaults passwd_tries=3
# Limitar TTY ticket (no compartir entre terminales)
Defaults !tty_tickets
Defaults timestamp_type=tty
SUDOEOF
        chmod 0440 "$ZT_SUDOERS"

        # Validate sudoers
        if visudo -cf "$ZT_SUDOERS" &>/dev/null; then
            log_change "Configurado" "Sudo timeout reducido a 5 minutos ($ZT_SUDOERS)"
        else
            log_error "Error de sintaxis en $ZT_SUDOERS - revirtiendo"
            rm -f "$ZT_SUDOERS"
            log_skip "Sudo timeout (error de validacion)"
        fi
    else
        log_skip "Sudo timestamp (directorio sudoers.d no existe)"
    fi

    # ── SSH re-key interval ──────────────────────────────────
    SSHD_CONF="/etc/ssh/sshd_config"
    SSHD_ZT_CONF=""

    if [[ -d /etc/ssh/sshd_config.d ]]; then
        SSHD_ZT_CONF="/etc/ssh/sshd_config.d/99-zero-trust.conf"
    elif [[ -f "$SSHD_CONF" ]]; then
        SSHD_ZT_CONF="$SSHD_CONF"
    fi

    if [[ -n "$SSHD_ZT_CONF" ]]; then
        if [[ -f "$SSHD_ZT_CONF" ]]; then
            cp -a "$SSHD_ZT_CONF" "${BACKUP_DIR}/$(basename "$SSHD_ZT_CONF").bak" 2>/dev/null || true
        fi

        if [[ "$SSHD_ZT_CONF" == *"sshd_config.d"* ]]; then
            cat > "$SSHD_ZT_CONF" << 'SSHEOF'
# Zero Trust SSH hardening
# Re-key every 500MB or 30 min
RekeyLimit 500M 1800
# Short login grace time
LoginGraceTime 60
# Max auth tries
MaxAuthTries 3
# Max sessions per connection
MaxSessions 3
# Client alive interval (detect dead sessions)
ClientAliveInterval 300
ClientAliveCountMax 2
SSHEOF
            chmod 0644 "$SSHD_ZT_CONF"
            log_change "Creado" "$SSHD_ZT_CONF - SSH Zero Trust config (re-key, timeouts)"
        else
            # Append to main sshd_config if drop-in dir not available
            {
                echo ""
                echo "# Zero Trust SSH (added by securizar)"
                echo "RekeyLimit 500M 1800"
                echo "LoginGraceTime 60"
                echo "MaxAuthTries 3"
                echo "MaxSessions 3"
                echo "ClientAliveInterval 300"
                echo "ClientAliveCountMax 2"
            } >> "$SSHD_ZT_CONF"
            log_change "Configurado" "SSH re-key y timeouts en $SSHD_ZT_CONF"
        fi
    else
        log_skip "SSH re-key (sshd_config no encontrado)"
    fi

    # ── Script de autenticacion continua ─────────────────────
    safe_write_file "/usr/local/bin/auth-continua.sh" "0755" << 'ENDSCRIPT'
#!/bin/bash
# ============================================================
# auth-continua.sh - Monitor de autenticacion continua
# ============================================================
# Detecta anomalias en sesiones de usuario y fuerza
# re-autenticacion cuando se detectan comportamientos
# sospechosos.
# ============================================================
set -euo pipefail

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
BOLD="\033[1m"
NC="\033[0m"

LOG_DIR="/var/log/securizar"
LOG_FILE="${LOG_DIR}/auth-continua-$(date +%Y%m%d).log"
POLICY_FILE="/etc/securizar/zero-trust-policy.conf"
mkdir -p "$LOG_DIR"

log_ac() { echo "[$(date "+%Y-%m-%d %H:%M:%S")] $1" | tee -a "$LOG_FILE"; }
log_alert() { echo -e "${RED}[ALERTA]${NC} $1" | tee -a "$LOG_FILE"; }

# Load policy defaults
SESSION_TIMEOUT="${ZT_SESSION_TIMEOUT:-3600}"
REAUTH_INTERVAL="${ZT_REAUTH_INTERVAL:-900}"
MAX_CONCURRENT=5

if [[ -f "$POLICY_FILE" ]]; then
    while IFS= read -r line; do
        line="${line#"${line%%[![:space:]]*}"}"
        [[ -z "$line" || "$line" == \#* ]] && continue
        if [[ "$line" =~ ^SESSION_TIMEOUT= ]]; then
            SESSION_TIMEOUT="${line#*=}"
        elif [[ "$line" =~ ^MAX_CONCURRENT_SESSIONS= ]]; then
            MAX_CONCURRENT="${line#*=}"
        fi
    done < "$POLICY_FILE"
fi

log_ac "=== Inicio de monitoreo de autenticacion continua ==="
log_ac "Session timeout: ${SESSION_TIMEOUT}s | Max concurrent: ${MAX_CONCURRENT}"

ANOMALIES=0

# ── Check 1: Concurrent sessions ────────────────────────────
echo -e "\n${CYAN}--- Verificacion de sesiones concurrentes ---${NC}"
while IFS= read -r user; do
    [[ -z "$user" ]] && continue
    SESSION_COUNT=$(who 2>/dev/null | grep -c "^${user} " || echo 0)
    if [[ "$SESSION_COUNT" -gt "$MAX_CONCURRENT" ]]; then
        log_alert "Usuario $user tiene $SESSION_COUNT sesiones (max: $MAX_CONCURRENT)"
        ANOMALIES=$((ANOMALIES + 1))
    fi
done < <(who 2>/dev/null | awk "{print \$1}" | sort -u)

# ── Check 2: Sessions from multiple IPs ─────────────────────
echo -e "\n${CYAN}--- Verificacion de sesiones multi-IP ---${NC}"
while IFS= read -r user; do
    [[ -z "$user" ]] && continue
    IP_COUNT=$(who 2>/dev/null | grep "^${user} " | awk "{print \$5}" | tr -d "()" | sort -u | wc -l)
    if [[ "$IP_COUNT" -gt 1 ]]; then
        IPS=$(who 2>/dev/null | grep "^${user} " | awk "{print \$5}" | tr -d "()" | sort -u | tr "\n" ", ")
        log_alert "Usuario $user conectado desde multiples IPs: ${IPS%,}"
        ANOMALIES=$((ANOMALIES + 1))
    fi
done < <(who 2>/dev/null | awk "{print \$1}" | sort -u)

# ── Check 3: Time-of-day violations ─────────────────────────
echo -e "\n${CYAN}--- Verificacion de horario ---${NC}"
CURRENT_HOUR=$(date +%H)
if [[ "$CURRENT_HOUR" -lt 6 || "$CURRENT_HOUR" -gt 22 ]]; then
    ACTIVE_USERS=$(who 2>/dev/null | awk "{print \$1}" | sort -u | tr "\n" ", ")
    if [[ -n "$ACTIVE_USERS" ]]; then
        log_alert "Sesiones activas fuera de horario (${CURRENT_HOUR}:00): ${ACTIVE_USERS%,}"
        ANOMALIES=$((ANOMALIES + 1))
    fi
else
    log_ac "Horario dentro del rango permitido (06:00-22:00)"
fi

# ── Check 4: Failed auth attempts ───────────────────────────
echo -e "\n${CYAN}--- Intentos de autenticacion fallidos (ultima hora) ---${NC}"
FAILED=$(journalctl -u "$( [[ -f /etc/debian_version ]] && echo ssh || echo sshd)" \
    --since "1 hour ago" 2>/dev/null | grep -ci "failed\|failure\|invalid" || echo 0)
if [[ "$FAILED" -gt 10 ]]; then
    log_alert "Detectados $FAILED intentos fallidos en la ultima hora"
    ANOMALIES=$((ANOMALIES + 1))
else
    log_ac "Intentos fallidos en la ultima hora: $FAILED (aceptable)"
fi

# ── Check 5: Idle sessions exceeding timeout ────────────────
echo -e "\n${CYAN}--- Sesiones inactivas ---${NC}"
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    USER_NAME=$(echo "$line" | awk "{print \$1}")
    IDLE=$(echo "$line" | awk "{print \$5}")
    # Simple idle detection from who -u
    if [[ "$IDLE" =~ old ]]; then
        log_alert "Sesion de $USER_NAME inactiva por mas de 24h"
        ANOMALIES=$((ANOMALIES + 1))
    fi
done < <(who -u 2>/dev/null || true)

# ── Check 6: Sudo usage anomalies ───────────────────────────
echo -e "\n${CYAN}--- Anomalias en uso de sudo ---${NC}"
SUDO_CMDS=$(journalctl -t sudo --since "1 hour ago" 2>/dev/null | grep -c "COMMAND" || echo 0)
if [[ "$SUDO_CMDS" -gt 50 ]]; then
    log_alert "Uso excesivo de sudo: $SUDO_CMDS comandos en la ultima hora"
    ANOMALIES=$((ANOMALIES + 1))
else
    log_ac "Comandos sudo en la ultima hora: $SUDO_CMDS (normal)"
fi

# ── Check 7: New user sessions from unusual locations ────────
echo -e "\n${CYAN}--- Verificacion de ubicaciones inusuales ---${NC}"
if [[ -f /var/log/lastlog ]] && command -v lastlog >/dev/null 2>&1; then
    RECENT_LOGINS=$(last -n 20 2>/dev/null | grep -v "reboot\|wtmp\|^$" | awk "{print \$1, \$3}" | sort -u || true)
    log_ac "Ultimos logins:\n$RECENT_LOGINS"
fi

# ── Resumen ──────────────────────────────────────────────────
echo ""
log_ac "=== Resumen de monitoreo ==="
if [[ "$ANOMALIES" -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}Sin anomalias detectadas${NC}"
    log_ac "RESULTADO: Sin anomalias"
else
    echo -e "${RED}${BOLD}${ANOMALIES} anomalias detectadas${NC}"
    log_ac "RESULTADO: ${ANOMALIES} anomalias - se recomienda investigar"
    echo -e "${YELLOW}Recomendacion: Revisar sesiones activas y forzar re-autenticacion${NC}"
fi

echo ""
echo "Log: $LOG_FILE"

ENDSCRIPT

    log_change "Creado" "/usr/local/bin/auth-continua.sh - monitor de autenticacion continua"
else
    log_skip "Autenticacion continua"
fi

###############################################################################
# S4: Device trust y compliance
###############################################################################
log_section "S4: Device trust y compliance"

if ask "Crear verificacion de confianza de dispositivos (/usr/local/bin/verificar-device-trust.sh)?"; then

    ensure_dirs /usr/local/bin /etc/securizar /var/log/securizar

    # ── Device inventory template ────────────────────────────
    if [[ ! -f /etc/securizar/device-inventory.conf ]]; then
        safe_write_file "/etc/securizar/device-inventory.conf" "0640" << 'ENDSCRIPT'
# ============================================================
# device-inventory.conf - Inventario de dispositivos confiables
# ============================================================
# Formato: HOSTNAME|IP|MAC|TRUST_LEVEL|LAST_CHECK|STATUS
# TRUST_LEVEL: high, medium, low, untrusted
# STATUS: compliant, non-compliant, unknown
# ============================================================

# Ejemplo:
# server-prod-01|192.168.1.10|AA:BB:CC:DD:EE:FF|high|2025-01-01|compliant
# workstation-dev|192.168.1.50|11:22:33:44:55:66|medium|2025-01-01|compliant

# ── Dispositivos registrados ─────────────────────────────────
# Agregar dispositivos autorizados debajo:

ENDSCRIPT
        log_change "Creado" "/etc/securizar/device-inventory.conf - inventario de dispositivos"
    else
        log_skip "device-inventory.conf (ya existe)"
    fi

    # ── Device trust verification script ─────────────────────
    safe_write_file "/usr/local/bin/verificar-device-trust.sh" "0755" << 'ENDSCRIPT'
#!/bin/bash
# ============================================================
# verificar-device-trust.sh - Verificacion de confianza del dispositivo
# ============================================================
# Evalua la postura de seguridad del dispositivo local y
# asigna una puntuacion de confianza (0-100).
# Deniega acceso si esta por debajo del umbral configurado.
# ============================================================
set -euo pipefail

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
BOLD="\033[1m"
NC="\033[0m"

REPORT_DIR="/var/log/securizar"
REPORT="${REPORT_DIR}/device-trust-$(hostname)-$(date +%Y%m%d-%H%M%S).log"
INVENTORY="/etc/securizar/device-inventory.conf"
POLICY="/etc/securizar/zero-trust-policy.conf"
mkdir -p "$REPORT_DIR"

# Default threshold
MIN_TRUST_SCORE=70

# Load from policy if available
if [[ -f "$POLICY" ]]; then
    while IFS= read -r line; do
        line="${line#"${line%%[![:space:]]*}"}"
        [[ -z "$line" || "$line" == \#* ]] && continue
        if [[ "$line" =~ ^MIN_DEVICE_TRUST_SCORE= ]]; then
            MIN_TRUST_SCORE="${line#*=}"
        fi
    done < "$POLICY"
fi

log_dt() { echo "$1" | tee -a "$REPORT"; }
log_ok() { echo -e "  ${GREEN}[PASS]${NC} $1 (+$2 pts)" | tee -a "$REPORT"; }
log_no() { echo -e "  ${RED}[FAIL]${NC} $1 (+0 pts)" | tee -a "$REPORT"; }
log_header() { echo -e "\n${CYAN}=== $1 ===${NC}" | tee -a "$REPORT"; }

TRUST_SCORE=0
MAX_SCORE=100
CHECKS_PASS=0
CHECKS_TOTAL=0

add_check() {
    local name="$1" check="$2" weight="$3"
    CHECKS_TOTAL=$((CHECKS_TOTAL + 1))
    if eval "$check" 2>/dev/null; then
        TRUST_SCORE=$((TRUST_SCORE + weight))
        CHECKS_PASS=$((CHECKS_PASS + 1))
        log_ok "$name" "$weight"
    else
        log_no "$name" "$weight"
    fi
}

log_dt "=============================================="
log_dt "  VERIFICACION DE CONFIANZA DEL DISPOSITIVO"
log_dt "  Host: $(hostname)"
log_dt "  Fecha: $(date "+%Y-%m-%d %H:%M:%S")"
log_dt "  Umbral minimo: ${MIN_TRUST_SCORE}/100"
log_dt "=============================================="

# ── Informacion del sistema ──────────────────────────────────
log_header "INFORMACION DEL SISTEMA"
log_dt "  Hostname: $(hostname)"
log_dt "  Kernel: $(uname -r)"
log_dt "  OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"' || echo unknown)"
log_dt "  Uptime: $(uptime -p 2>/dev/null || uptime)"

# IP addresses
log_dt "  IPs: $(ip -4 addr show 2>/dev/null | grep inet | grep -v 127.0.0.1 | awk "{print \$2}" | tr "\n" " " || echo "N/A")"

# MAC addresses
log_dt "  MACs: $(ip link show 2>/dev/null | grep "link/ether" | awk "{print \$2}" | tr "\n" " " || echo "N/A")"

# ── Checks de seguridad ─────────────────────────────────────
log_header "CHECKS DE SEGURIDAD"

# 1. Disk encryption (15 pts)
add_check "Cifrado de disco (LUKS/dm-crypt)" \
    "lsblk -o TYPE 2>/dev/null | grep -q crypt || dmsetup ls --target crypt 2>/dev/null | grep -q ." 15

# 2. Firewall active (15 pts)
add_check "Firewall activo" \
    "systemctl is-active firewalld >/dev/null 2>&1 || systemctl is-active ufw >/dev/null 2>&1 || systemctl is-active nftables >/dev/null 2>&1" 15

# 3. AIDE/integrity monitoring (10 pts)
add_check "Monitoreo de integridad (AIDE/OSSEC)" \
    "command -v aide >/dev/null 2>&1 || command -v ossec-control >/dev/null 2>&1 || command -v tripwire >/dev/null 2>&1" 10

# 4. OS patches up to date (10 pts)
add_check "Parches del SO al dia (no reboot pendiente)" \
    "! test -f /var/run/reboot-required" 10

# 5. Secure Boot (10 pts)
add_check "Secure Boot habilitado" \
    "mokutil --sb-state 2>/dev/null | grep -qi 'SecureBoot enabled'" 10

# 6. Screen lock / idle timeout (5 pts)
add_check "Bloqueo de pantalla / idle timeout" \
    "grep -rqsE 'TMOUT=' /etc/profile /etc/profile.d/ /etc/bashrc 2>/dev/null || command -v xdg-screensaver >/dev/null 2>&1" 5

# 7. Auditd running (10 pts)
add_check "Sistema de auditoria (auditd) activo" \
    "systemctl is-active auditd >/dev/null 2>&1" 10

# 8. SELinux/AppArmor (10 pts)
add_check "MAC activo (AppArmor/SELinux)" \
    "command -v aa-status >/dev/null 2>&1 && aa-status 2>/dev/null | grep -q 'profiles are loaded' || getenforce 2>/dev/null | grep -qi enforcing" 10

# 9. No world-writable in critical paths (5 pts)
add_check "Sin archivos world-writable en /etc" \
    "test $(find /etc -maxdepth 2 -perm -o+w -type f 2>/dev/null | head -3 | wc -l) -eq 0" 5

# 10. SSH hardened (5 pts)
add_check "SSH configurado de forma segura" \
    "grep -qsE '^\s*PermitRootLogin\s+(no|prohibit-password)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null" 5

# 11. NTP synchronized (5 pts)
add_check "Reloj sincronizado (NTP)" \
    "timedatectl 2>/dev/null | grep -qi 'synchronized: yes\|NTP.*active'" 5

# ── Resultado de confianza ───────────────────────────────────
log_header "RESULTADO"

# Ensure score does not exceed max
if [[ $TRUST_SCORE -gt $MAX_SCORE ]]; then
    TRUST_SCORE=$MAX_SCORE
fi

log_dt ""
log_dt "  Checks superados: ${CHECKS_PASS}/${CHECKS_TOTAL}"
log_dt "  PUNTUACION DE CONFIANZA: ${TRUST_SCORE}/${MAX_SCORE}"
log_dt ""

# Determine trust level
if [[ $TRUST_SCORE -ge 80 ]]; then
    TRUST_LEVEL="ALTA"
    COLOR="$GREEN"
elif [[ $TRUST_SCORE -ge 60 ]]; then
    TRUST_LEVEL="MEDIA"
    COLOR="$YELLOW"
elif [[ $TRUST_SCORE -ge 40 ]]; then
    TRUST_LEVEL="BAJA"
    COLOR="$YELLOW"
else
    TRUST_LEVEL="MUY BAJA"
    COLOR="$RED"
fi

echo -e "  ${BOLD}Nivel de confianza: ${COLOR}${TRUST_LEVEL}${NC}" | tee -a "$REPORT"

# Update device inventory
if [[ -f "$INVENTORY" ]]; then
    HOSTNAME=$(hostname)
    IP=$(ip -4 addr show 2>/dev/null | grep inet | grep -v 127.0.0.1 | awk "{print \$2}" | cut -d/ -f1 | head -1 || echo "unknown")
    MAC=$(ip link show 2>/dev/null | grep "link/ether" | awk "{print \$2}" | head -1 || echo "unknown")
    DATE=$(date +%Y-%m-%d)

    if [[ $TRUST_SCORE -ge 80 ]]; then
        INV_TRUST="high"
    elif [[ $TRUST_SCORE -ge 60 ]]; then
        INV_TRUST="medium"
    elif [[ $TRUST_SCORE -ge 40 ]]; then
        INV_TRUST="low"
    else
        INV_TRUST="untrusted"
    fi

    COMPLIANCE="non-compliant"
    [[ $TRUST_SCORE -ge $MIN_TRUST_SCORE ]] && COMPLIANCE="compliant"

    # Remove old entry for this host and add updated
    grep -v "^${HOSTNAME}|" "$INVENTORY" > "${INVENTORY}.tmp" 2>/dev/null || cp "$INVENTORY" "${INVENTORY}.tmp"
    echo "${HOSTNAME}|${IP}|${MAC}|${INV_TRUST}|${DATE}|${COMPLIANCE}" >> "${INVENTORY}.tmp"
    mv "${INVENTORY}.tmp" "$INVENTORY"
    chmod 0640 "$INVENTORY"
    log_dt "  Inventario actualizado: $INVENTORY"
fi

# Compliance decision
log_dt ""
if [[ $TRUST_SCORE -ge $MIN_TRUST_SCORE ]]; then
    echo -e "  ${GREEN}${BOLD}DECISION: ACCESO PERMITIDO${NC}" | tee -a "$REPORT"
    log_dt "  El dispositivo cumple el umbral minimo de confianza."
    EXIT_CODE=0
else
    echo -e "  ${RED}${BOLD}DECISION: ACCESO DENEGADO${NC}" | tee -a "$REPORT"
    log_dt "  El dispositivo NO cumple el umbral minimo (${TRUST_SCORE} < ${MIN_TRUST_SCORE})."
    log_dt "  Se requieren acciones correctivas antes de permitir acceso."
    EXIT_CODE=1
fi

log_dt ""
log_dt "Reporte: $REPORT"

exit $EXIT_CODE

ENDSCRIPT

    log_change "Creado" "/usr/local/bin/verificar-device-trust.sh - verificacion de confianza del dispositivo"
else
    log_skip "Device trust y compliance"
fi

###############################################################################
# S5: Identity-Aware Proxy (IAP)
###############################################################################
log_section "S5: Identity-Aware Proxy (IAP)"

if ask "Crear templates de Identity-Aware Proxy (/etc/securizar/iap/)?"; then

    ensure_dirs /etc/securizar/iap /usr/local/bin

    # ── nginx reverse proxy with OIDC template ──────────────
    safe_write_file "/etc/securizar/iap/nginx-oidc-proxy.conf.template" "0640" << 'ENDSCRIPT'
# ============================================================
# nginx-oidc-proxy.conf.template - Nginx como Identity-Aware Proxy
# ============================================================
# Template para proteger servicios internos con autenticacion OIDC
# Requiere: nginx, libnginx-mod-http-auth-request (o njs)
# ============================================================
# Variables a reemplazar:
#   __BACKEND_HOST__     = Host del servicio backend (ej: 127.0.0.1)
#   __BACKEND_PORT__     = Puerto del backend (ej: 8080)
#   __SERVER_NAME__      = Nombre DNS del proxy (ej: app.example.com)
#   __OIDC_PROVIDER__    = URL del proveedor OIDC
#   __CLIENT_ID__        = Client ID de la app en el IdP
#   __OAUTH2_PROXY_PORT__= Puerto de oauth2-proxy (ej: 4180)
# ============================================================

# Upstream: servicio backend protegido
upstream backend_service {
    server __BACKEND_HOST__:__BACKEND_PORT__;
    keepalive 32;
}

# Upstream: oauth2-proxy para autenticacion
upstream oauth2_proxy {
    server 127.0.0.1:__OAUTH2_PROXY_PORT__;
    keepalive 16;
}

server {
    listen 443 ssl http2;
    server_name __SERVER_NAME__;

    # TLS configuration - Zero Trust requires TLS 1.3
    ssl_certificate     /etc/ssl/certs/__SERVER_NAME__.pem;
    ssl_certificate_key /etc/ssl/private/__SERVER_NAME__.key;
    ssl_protocols       TLSv1.3;
    ssl_ciphers         TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1h;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_tickets off;

    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Authentication subrequest to oauth2-proxy
    location = /oauth2/auth {
        internal;
        proxy_pass              http://oauth2_proxy/oauth2/auth;
        proxy_pass_request_body off;
        proxy_set_header        Content-Length "";
        proxy_set_header        X-Real-IP $remote_addr;
        proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header        X-Forwarded-Proto $scheme;
        proxy_set_header        X-Original-URI $request_uri;
        proxy_set_header        Host $host;
    }

    # OAuth2 callback and sign-in/out
    location /oauth2/ {
        proxy_pass http://oauth2_proxy;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Error page for unauthorized access
    location = /oauth2/sign_in {
        proxy_pass http://oauth2_proxy/oauth2/sign_in;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # Protected application - all requests require authentication
    location / {
        auth_request /oauth2/auth;
        auth_request_set $auth_user  $upstream_http_x_auth_request_user;
        auth_request_set $auth_email $upstream_http_x_auth_request_email;
        auth_request_set $auth_groups $upstream_http_x_auth_request_groups;

        # On auth failure, redirect to sign-in
        error_page 401 = /oauth2/sign_in;

        # Pass authenticated user info to backend
        proxy_set_header X-Auth-Request-User  $auth_user;
        proxy_set_header X-Auth-Request-Email $auth_email;
        proxy_set_header X-Auth-Request-Groups $auth_groups;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host $host;

        proxy_pass http://backend_service;

        # Timeouts
        proxy_connect_timeout 10s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }

    # Health check endpoint (no auth required)
    location /health {
        access_log off;
        return 200 "OK";
    }

    # Access logging
    access_log /var/log/nginx/iap-access.log combined;
    error_log  /var/log/nginx/iap-error.log warn;
}

# HTTP -> HTTPS redirect
server {
    listen 80;
    server_name __SERVER_NAME__;
    return 301 https://$server_name$request_uri;
}

ENDSCRIPT

    log_change "Creado" "/etc/securizar/iap/nginx-oidc-proxy.conf.template - template Nginx OIDC proxy"

    # ── oauth2-proxy configuration template ──────────────────
    safe_write_file "/etc/securizar/iap/oauth2-proxy.cfg.template" "0640" << 'ENDSCRIPT'
# ============================================================
# oauth2-proxy.cfg.template - Configuracion de oauth2-proxy
# ============================================================
# Template para oauth2-proxy como componente IAP
# Referencia: https://oauth2-proxy.github.io/oauth2-proxy/
# ============================================================
# Variables a reemplazar:
#   __OIDC_ISSUER__   = URL del issuer OIDC (ej: https://keycloak.example.com/realms/master)
#   __CLIENT_ID__     = Client ID de la app
#   __CLIENT_SECRET__ = Client Secret (proteger con permisos 0600)
#   __COOKIE_SECRET__ = Secret para cookies (generar con: python3 -c "import os; import base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())")
#   __EMAIL_DOMAIN__  = Dominio de email permitido (ej: example.com)
#   __REDIRECT_URL__  = URL de callback (ej: https://app.example.com/oauth2/callback)
# ============================================================

## OAuth2 Proxy Configuration

# Listen address
http_address = "127.0.0.1:4180"

# OIDC Provider configuration
provider = "oidc"
oidc_issuer_url = "__OIDC_ISSUER__"
client_id = "__CLIENT_ID__"
client_secret = "__CLIENT_SECRET__"

# Redirect URL
redirect_url = "__REDIRECT_URL__"

# Email domain restriction
email_domains = [
    "__EMAIL_DOMAIN__"
]

# Cookie configuration
cookie_name = "_oauth2_proxy"
cookie_secret = "__COOKIE_SECRET__"
cookie_domains = []
cookie_expire = "1h"
cookie_refresh = "15m"
cookie_secure = true
cookie_httponly = true
cookie_samesite = "lax"

# Session configuration - Zero Trust: short sessions
session_store_type = "cookie"

# Upstream configuration
upstreams = [
    "http://127.0.0.1:8080"
]

# Pass auth info in headers
set_xauthrequest = true
set_authorization_header = true
pass_access_token = true
pass_authorization_header = true

# User info headers
pass_user_headers = true

# Skip provider button (direct redirect to IdP)
skip_provider_button = true

# Logging
logging_filename = "/var/log/oauth2-proxy/access.log"
standard_logging = true
auth_logging = true
request_logging = true

# Security
reverse_proxy = true
real_client_ip_header = "X-Forwarded-For"

# Allowed groups (if group-based access is configured in IdP)
# oidc_groups_claim = "groups"
# allowed_groups = ["admins", "developers"]

# Silence ping endpoint
silence_ping_logging = true

ENDSCRIPT

    log_change "Creado" "/etc/securizar/iap/oauth2-proxy.cfg.template - template oauth2-proxy"

    # ── Keycloak integration template ────────────────────────
    safe_write_file "/etc/securizar/iap/keycloak-realm.json.template" "0640" << 'ENDSCRIPT'
{
  "_comment": "============================================================",
  "_description": "Keycloak Realm Template for Zero Trust IAP Integration",
  "_note": "Import this into Keycloak to create a realm for IAP authentication",
  "_variables": {
    "__REALM_NAME__": "Name of the realm (e.g., securizar)",
    "__CLIENT_ID__": "Client ID for the application",
    "__REDIRECT_URI__": "OAuth2 redirect URI (e.g., https://app.example.com/oauth2/callback)",
    "__ADMIN_EMAIL__": "Admin email address"
  },
  "realm": "__REALM_NAME__",
  "enabled": true,
  "sslRequired": "all",
  "bruteForceProtected": true,
  "permanentLockout": false,
  "maxFailureWaitSeconds": 900,
  "minimumQuickLoginWaitSeconds": 60,
  "waitIncrementSeconds": 60,
  "quickLoginCheckMilliSeconds": 1000,
  "maxDeltaTimeSeconds": 43200,
  "failureFactor": 5,
  "passwordPolicy": "length(12) and upperCase(1) and lowerCase(1) and digits(1) and specialChars(1) and notUsername and passwordHistory(5)",
  "otpPolicyType": "totp",
  "otpPolicyAlgorithm": "HmacSHA256",
  "otpPolicyDigits": 6,
  "otpPolicyPeriod": 30,
  "loginTheme": "keycloak",
  "accessTokenLifespan": 300,
  "accessTokenLifespanForImplicitFlow": 300,
  "ssoSessionIdleTimeout": 900,
  "ssoSessionMaxLifespan": 3600,
  "offlineSessionIdleTimeout": 2592000,
  "accessCodeLifespan": 60,
  "accessCodeLifespanUserAction": 300,
  "actionTokenGeneratedByAdminLifespan": 43200,
  "actionTokenGeneratedByUserLifespan": 300,
  "clients": [
    {
      "clientId": "__CLIENT_ID__",
      "name": "Zero Trust IAP Client",
      "enabled": true,
      "clientAuthenticatorType": "client-secret",
      "redirectUris": ["__REDIRECT_URI__"],
      "webOrigins": ["+"],
      "standardFlowEnabled": true,
      "implicitFlowEnabled": false,
      "directAccessGrantsEnabled": false,
      "serviceAccountsEnabled": false,
      "publicClient": false,
      "protocol": "openid-connect",
      "defaultClientScopes": ["openid", "profile", "email", "roles"],
      "optionalClientScopes": ["groups"]
    }
  ],
  "roles": {
    "realm": [
      { "name": "zt-admin", "description": "Zero Trust Administrator" },
      { "name": "zt-user", "description": "Zero Trust Standard User" },
      { "name": "zt-readonly", "description": "Zero Trust Read-Only User" }
    ]
  },
  "requiredActions": [
    {
      "alias": "CONFIGURE_TOTP",
      "name": "Configure OTP",
      "providerId": "CONFIGURE_TOTP",
      "enabled": true,
      "defaultAction": true
    },
    {
      "alias": "UPDATE_PASSWORD",
      "name": "Update Password",
      "providerId": "UPDATE_PASSWORD",
      "enabled": true,
      "defaultAction": false
    }
  ]
}
ENDSCRIPT

    log_change "Creado" "/etc/securizar/iap/keycloak-realm.json.template - template realm Keycloak"

    # ── Script para configurar IAP ───────────────────────────
    safe_write_file "/usr/local/bin/configurar-iap.sh" "0755" << 'ENDSCRIPT'
#!/bin/bash
# ============================================================
# configurar-iap.sh - Configurar Identity-Aware Proxy
# ============================================================
# Guia interactiva para desplegar IAP con nginx + oauth2-proxy
# Protege servicios internos con autenticacion OIDC
# ============================================================
set -euo pipefail

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
BOLD="\033[1m"
NC="\033[0m"

TEMPLATE_DIR="/etc/securizar/iap"
OUTPUT_DIR="/etc/securizar/iap/generated"
LOG_FILE="/var/log/securizar/configurar-iap-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$OUTPUT_DIR" /var/log/securizar

log_iap() { echo -e "$1" | tee -a "$LOG_FILE"; }

log_iap "${BOLD}=============================================="
log_iap "  CONFIGURACION DE IDENTITY-AWARE PROXY"
log_iap "==============================================${NC}"

# ── Verificar prerrequisitos ─────────────────────────────────
log_iap "\n${CYAN}--- Verificando prerrequisitos ---${NC}"

PREREQ_OK=true

if command -v nginx >/dev/null 2>&1; then
    NGINX_VER=$(nginx -v 2>&1 | awk -F/ "{print \$2}" || echo "unknown")
    log_iap "${GREEN}[OK]${NC} Nginx instalado (v${NGINX_VER})"
else
    log_iap "${YELLOW}[WARN]${NC} Nginx no instalado"
    log_iap "  Instalar: apt/dnf/zypper install nginx"
fi

if command -v oauth2-proxy >/dev/null 2>&1; then
    log_iap "${GREEN}[OK]${NC} oauth2-proxy instalado"
else
    log_iap "${YELLOW}[WARN]${NC} oauth2-proxy no instalado"
    log_iap "  Instalar desde: https://github.com/oauth2-proxy/oauth2-proxy/releases"
fi

if ! command -v openssl >/dev/null 2>&1; then
    log_iap "${RED}[FAIL]${NC} openssl no disponible"
    PREREQ_OK=false
fi

# ── Verificar templates ──────────────────────────────────────
log_iap "\n${CYAN}--- Templates disponibles ---${NC}"
if [[ -d "$TEMPLATE_DIR" ]]; then
    for tmpl in "$TEMPLATE_DIR"/*.template; do
        [[ -f "$tmpl" ]] && log_iap "  ${GREEN}[+]${NC} $(basename "$tmpl")"
    done
else
    log_iap "${RED}[FAIL]${NC} Directorio de templates no encontrado: $TEMPLATE_DIR"
    exit 1
fi

# ── Recoger parametros ───────────────────────────────────────
log_iap "\n${CYAN}--- Configuracion del servicio ---${NC}"
echo ""

read -p "Nombre DNS del servicio (ej: app.example.com): " SERVER_NAME
SERVER_NAME="${SERVER_NAME:-app.example.com}"

read -p "Host del backend (ej: 127.0.0.1): " BACKEND_HOST
BACKEND_HOST="${BACKEND_HOST:-127.0.0.1}"

read -p "Puerto del backend (ej: 8080): " BACKEND_PORT
BACKEND_PORT="${BACKEND_PORT:-8080}"

read -p "URL del proveedor OIDC (ej: https://keycloak.example.com/realms/master): " OIDC_ISSUER
OIDC_ISSUER="${OIDC_ISSUER:-https://keycloak.example.com/realms/master}"

read -p "Client ID: " CLIENT_ID
CLIENT_ID="${CLIENT_ID:-securizar-iap}"

read -p "Client Secret: " CLIENT_SECRET
CLIENT_SECRET="${CLIENT_SECRET:-CHANGE_ME}"

read -p "Dominio de email permitido (ej: example.com): " EMAIL_DOMAIN
EMAIL_DOMAIN="${EMAIL_DOMAIN:-example.com}"

# Generate cookie secret
COOKIE_SECRET=$(openssl rand -base64 32 2>/dev/null || python3 -c "import os,base64;print(base64.urlsafe_b64encode(os.urandom(32)).decode())" 2>/dev/null || echo "GENERATE_ME_$(date +%s)")
OAUTH2_PROXY_PORT="4180"
REDIRECT_URL="https://${SERVER_NAME}/oauth2/callback"

# ── Generar configuracion nginx ──────────────────────────────
log_iap "\n${CYAN}--- Generando configuracion de nginx ---${NC}"

NGINX_TEMPLATE="${TEMPLATE_DIR}/nginx-oidc-proxy.conf.template"
NGINX_OUTPUT="${OUTPUT_DIR}/${SERVER_NAME}.conf"

if [[ -f "$NGINX_TEMPLATE" ]]; then
    sed -e "s|__BACKEND_HOST__|${BACKEND_HOST}|g" \
        -e "s|__BACKEND_PORT__|${BACKEND_PORT}|g" \
        -e "s|__SERVER_NAME__|${SERVER_NAME}|g" \
        -e "s|__OIDC_PROVIDER__|${OIDC_ISSUER}|g" \
        -e "s|__CLIENT_ID__|${CLIENT_ID}|g" \
        -e "s|__OAUTH2_PROXY_PORT__|${OAUTH2_PROXY_PORT}|g" \
        "$NGINX_TEMPLATE" > "$NGINX_OUTPUT"
    chmod 0640 "$NGINX_OUTPUT"
    log_iap "${GREEN}[OK]${NC} Nginx config generada: $NGINX_OUTPUT"
else
    log_iap "${RED}[FAIL]${NC} Template nginx no encontrada"
fi

# ── Generar configuracion oauth2-proxy ───────────────────────
log_iap "\n${CYAN}--- Generando configuracion de oauth2-proxy ---${NC}"

OAUTH2_TEMPLATE="${TEMPLATE_DIR}/oauth2-proxy.cfg.template"
OAUTH2_OUTPUT="${OUTPUT_DIR}/oauth2-proxy-${SERVER_NAME}.cfg"

if [[ -f "$OAUTH2_TEMPLATE" ]]; then
    sed -e "s|__OIDC_ISSUER__|${OIDC_ISSUER}|g" \
        -e "s|__CLIENT_ID__|${CLIENT_ID}|g" \
        -e "s|__CLIENT_SECRET__|${CLIENT_SECRET}|g" \
        -e "s|__COOKIE_SECRET__|${COOKIE_SECRET}|g" \
        -e "s|__EMAIL_DOMAIN__|${EMAIL_DOMAIN}|g" \
        -e "s|__REDIRECT_URL__|${REDIRECT_URL}|g" \
        "$OAUTH2_TEMPLATE" > "$OAUTH2_OUTPUT"
    chmod 0600 "$OAUTH2_OUTPUT"
    log_iap "${GREEN}[OK]${NC} oauth2-proxy config generada: $OAUTH2_OUTPUT"
else
    log_iap "${RED}[FAIL]${NC} Template oauth2-proxy no encontrada"
fi

# ── Instrucciones de despliegue ──────────────────────────────
log_iap "\n${CYAN}=== INSTRUCCIONES DE DESPLIEGUE ===${NC}"
log_iap ""
log_iap "1. Copiar configuracion de nginx:"
log_iap "   cp ${NGINX_OUTPUT} /etc/nginx/sites-available/${SERVER_NAME}.conf"
log_iap "   ln -s /etc/nginx/sites-available/${SERVER_NAME}.conf /etc/nginx/sites-enabled/"
log_iap ""
log_iap "2. Generar certificado TLS (o usar Let'\''s Encrypt):"
log_iap "   certbot certonly --nginx -d ${SERVER_NAME}"
log_iap "   Actualizar rutas de certificado en la config de nginx"
log_iap ""
log_iap "3. Iniciar oauth2-proxy:"
log_iap "   oauth2-proxy --config=${OAUTH2_OUTPUT}"
log_iap ""
log_iap "4. Verificar y reiniciar nginx:"
log_iap "   nginx -t && systemctl reload nginx"
log_iap ""
log_iap "5. Probar acceso:"
log_iap "   curl -I https://${SERVER_NAME}/"
log_iap "   (Deberia redirigir a login OIDC)"
log_iap ""
log_iap "${YELLOW}IMPORTANTE:${NC}"
log_iap "  - Cambiar CLIENT_SECRET en produccion"
log_iap "  - Proteger ${OAUTH2_OUTPUT} (permisos 0600)"
log_iap "  - Configurar el IdP (Keycloak/Okta/Azure AD) con el Client ID y redirect URI"
log_iap ""
log_iap "Archivos generados:"
log_iap "  ${NGINX_OUTPUT}"
log_iap "  ${OAUTH2_OUTPUT}"
log_iap "Log: ${LOG_FILE}"

ENDSCRIPT

    log_change "Creado" "/usr/local/bin/configurar-iap.sh - configurador interactivo de IAP"
else
    log_skip "Identity-Aware Proxy (IAP)"
fi

###############################################################################
# S6: Micro-segmentacion basada en identidad
###############################################################################
log_section "S6: Micro-segmentacion basada en identidad"

if ask "Configurar micro-segmentacion de red basada en identidad?"; then

    ensure_dirs /etc/securizar /usr/local/bin

    # ── Identity-Network mapping ─────────────────────────────
    if [[ ! -f /etc/securizar/identity-network-map.conf ]]; then
        safe_write_file "/etc/securizar/identity-network-map.conf" "0640" << 'ENDSCRIPT'
# ============================================================
# identity-network-map.conf - Mapa de identidad a segmentos de red
# ============================================================
# Define que usuarios/grupos pueden acceder a que segmentos de red
# Formato: TIPO|NOMBRE|REDES_PERMITIDAS|PUERTOS|DESCRIPCION
# TIPO: user, group
# REDES_PERMITIDAS: CIDRs separados por coma
# PUERTOS: tcp/udp ports separados por coma (o "all")
# ============================================================

# ── Roles de administracion ──────────────────────────────────
# Administradores: acceso completo a redes de gestion
group|wheel|10.0.0.0/8,172.16.0.0/12,192.168.0.0/16|all|Administradores - acceso completo
group|sudo|10.0.0.0/8,172.16.0.0/12,192.168.0.0/16|all|Administradores sudo - acceso completo

# ── Roles de desarrollo ─────────────────────────────────────
# Desarrolladores: acceso a redes de desarrollo y staging
group|developers|10.10.0.0/16,10.20.0.0/16|22,80,443,3000,5432,6379,8080,8443|Desarrollo y staging

# ── Roles de operaciones ────────────────────────────────────
# Operaciones: acceso a monitorizacion y logs
group|ops|10.30.0.0/16|22,80,443,5601,9090,9200,3000|Monitorizacion y logging

# ── Roles de base de datos ──────────────────────────────────
# DBAs: acceso a segmento de datos
group|dba|10.40.0.0/16|22,3306,5432,27017,6379|Segmento de bases de datos

# ── Usuarios de servicio ────────────────────────────────────
# Web servers: solo HTTP/S hacia backend
user|www-data|10.10.0.0/16|80,443,8080|Servidor web - solo backend
user|nginx|10.10.0.0/16|80,443,8080|Nginx - solo backend

# ── Acceso restringido ──────────────────────────────────────
# Usuarios regulares: solo internet y servicios basicos
group|users|0.0.0.0/0|80,443,53,123|Usuarios regulares - internet basico

ENDSCRIPT
        log_change "Creado" "/etc/securizar/identity-network-map.conf - mapa identidad-red"
    else
        log_skip "identity-network-map.conf (ya existe)"
    fi

    # ── Segmentation script ──────────────────────────────────
    safe_write_file "/usr/local/bin/segmentar-por-identidad.sh" "0755" << 'ENDSCRIPT'
#!/bin/bash
# ============================================================
# segmentar-por-identidad.sh - Micro-segmentacion basada en identidad
# ============================================================
# Lee /etc/securizar/identity-network-map.conf y crea reglas
# de firewall (iptables/nftables) por usuario/grupo usando
# el modulo owner match.
# ============================================================
set -euo pipefail

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
BOLD="\033[1m"
NC="\033[0m"

IDENTITY_MAP="/etc/securizar/identity-network-map.conf"
LOG_FILE="/var/log/securizar/segmentacion-identidad-$(date +%Y%m%d-%H%M%S).log"
mkdir -p /var/log/securizar

log_seg() { echo -e "$1" | tee -a "$LOG_FILE"; }
log_ok() { log_seg "  ${GREEN}[OK]${NC} $1"; }
log_fail() { log_seg "  ${RED}[FAIL]${NC} $1"; }
log_warn() { log_seg "  ${YELLOW}[WARN]${NC} $1"; }
log_head() { log_seg "\n${CYAN}=== $1 ===${NC}"; }

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Este script requiere privilegios de root.${NC}"
    exit 1
fi

if [[ ! -f "$IDENTITY_MAP" ]]; then
    echo -e "${RED}Mapa de identidad no encontrado: $IDENTITY_MAP${NC}"
    exit 1
fi

log_seg "${BOLD}=============================================="
log_seg "  MICRO-SEGMENTACION BASADA EN IDENTIDAD"
log_seg "  Fecha: $(date "+%Y-%m-%d %H:%M:%S")"
log_seg "==============================================${NC}"

# ── Detectar backend de firewall ─────────────────────────────
FW_BACKEND=""
if command -v nft >/dev/null 2>&1 && nft list ruleset >/dev/null 2>&1; then
    FW_BACKEND="nftables"
elif command -v iptables >/dev/null 2>&1; then
    FW_BACKEND="iptables"
else
    log_fail "No se encontro iptables ni nftables"
    exit 1
fi

log_seg "Backend de firewall: ${FW_BACKEND}"

# ── Modo de operacion ────────────────────────────────────────
MODE="${1:-show}"
log_seg "Modo: ${MODE} (usar '\''apply'\'' para aplicar reglas)"

RULES_COUNT=0
ERRORS=0

# ── Procesar mapa de identidad ───────────────────────────────
log_head "PROCESANDO MAPA DE IDENTIDAD"

while IFS= read -r line; do
    # Skip comments and empty lines
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$line" || "$line" == \#* ]] && continue

    # Parse: TIPO|NOMBRE|REDES|PUERTOS|DESCRIPCION
    IFS="|" read -r tipo nombre redes puertos descripcion <<< "$line"

    # Validate fields
    if [[ -z "$tipo" || -z "$nombre" || -z "$redes" || -z "$puertos" ]]; then
        log_warn "Linea invalida: $line"
        continue
    fi

    log_seg "\n  Procesando: ${tipo}=${nombre} -> redes=${redes} puertos=${puertos}"

    # Resolve to UID/GID
    if [[ "$tipo" == "user" ]]; then
        if ! id "$nombre" >/dev/null 2>&1; then
            log_warn "Usuario $nombre no existe, omitiendo"
            continue
        fi
        OWNER_MATCH="--uid-owner $(id -u "$nombre")"
        CHAIN_NAME="ZT_USER_$(echo "$nombre" | tr '[:lower:].-' '[:upper:]__' | head -c 20)"
    elif [[ "$tipo" == "group" ]]; then
        if ! getent group "$nombre" >/dev/null 2>&1; then
            log_warn "Grupo $nombre no existe, omitiendo"
            continue
        fi
        OWNER_MATCH="--gid-owner $(getent group "$nombre" | cut -d: -f3)"
        CHAIN_NAME="ZT_GRP_$(echo "$nombre" | tr '[:lower:].-' '[:upper:]__' | head -c 20)"
    else
        log_warn "Tipo desconocido: $tipo"
        continue
    fi

    if [[ "$FW_BACKEND" == "iptables" ]]; then
        # ── iptables rules ───────────────────────────────────
        log_seg "  Generando reglas iptables para chain: $CHAIN_NAME"

        if [[ "$MODE" == "apply" ]]; then
            # Create chain (ignore error if exists)
            iptables -N "$CHAIN_NAME" 2>/dev/null || iptables -F "$CHAIN_NAME" 2>/dev/null || true

            # Jump to chain for matching owner
            iptables -C OUTPUT -m owner $OWNER_MATCH -j "$CHAIN_NAME" 2>/dev/null || \
                iptables -A OUTPUT -m owner $OWNER_MATCH -j "$CHAIN_NAME" 2>/dev/null || true
        fi

        # Process each network CIDR
        IFS="," read -ra NET_ARRAY <<< "$redes"
        for net in "${NET_ARRAY[@]}"; do
            net="${net#"${net%%[![:space:]]*}"}"
            net="${net%"${net##*[![:space:]]}"}"

            if [[ "$puertos" == "all" ]]; then
                if [[ "$MODE" == "show" ]]; then
                    log_seg "    iptables -A $CHAIN_NAME -d $net -j ACCEPT"
                elif [[ "$MODE" == "apply" ]]; then
                    iptables -A "$CHAIN_NAME" -d "$net" -j ACCEPT 2>/dev/null && \
                        log_ok "Regla: $CHAIN_NAME -> $net (all)" || \
                        { log_fail "Error creando regla para $net"; ERRORS=$((ERRORS + 1)); }
                fi
                RULES_COUNT=$((RULES_COUNT + 1))
            else
                # Process each port
                IFS="," read -ra PORT_ARRAY <<< "$puertos"
                for port in "${PORT_ARRAY[@]}"; do
                    port="${port#"${port%%[![:space:]]*}"}"
                    port="${port%"${port##*[![:space:]]}"}"
                    if [[ "$MODE" == "show" ]]; then
                        log_seg "    iptables -A $CHAIN_NAME -d $net -p tcp --dport $port -j ACCEPT"
                        log_seg "    iptables -A $CHAIN_NAME -d $net -p udp --dport $port -j ACCEPT"
                    elif [[ "$MODE" == "apply" ]]; then
                        iptables -A "$CHAIN_NAME" -d "$net" -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
                        iptables -A "$CHAIN_NAME" -d "$net" -p udp --dport "$port" -j ACCEPT 2>/dev/null || true
                        log_ok "Regla: $CHAIN_NAME -> $net:$port (tcp/udp)"
                    fi
                    RULES_COUNT=$((RULES_COUNT + 1))
                done
            fi
        done

        # Default deny at end of chain
        if [[ "$MODE" == "apply" ]]; then
            iptables -A "$CHAIN_NAME" -j LOG --log-prefix "ZT-DENY-${CHAIN_NAME}: " 2>/dev/null || true
            iptables -A "$CHAIN_NAME" -j DROP 2>/dev/null || true
            log_ok "Default deny al final de chain $CHAIN_NAME"
        elif [[ "$MODE" == "show" ]]; then
            log_seg "    iptables -A $CHAIN_NAME -j LOG --log-prefix \"ZT-DENY-${CHAIN_NAME}: \""
            log_seg "    iptables -A $CHAIN_NAME -j DROP"
        fi

    elif [[ "$FW_BACKEND" == "nftables" ]]; then
        # ── nftables rules ───────────────────────────────────
        log_seg "  Generando reglas nftables para chain: $CHAIN_NAME"

        NFT_TABLE="securizar_zt"

        if [[ "$MODE" == "apply" ]]; then
            # Ensure table and chain exist
            nft add table inet "$NFT_TABLE" 2>/dev/null || true
            nft add chain inet "$NFT_TABLE" "$CHAIN_NAME" 2>/dev/null || \
                nft flush chain inet "$NFT_TABLE" "$CHAIN_NAME" 2>/dev/null || true

            # Create output chain if not exists
            nft add chain inet "$NFT_TABLE" output '{ type filter hook output priority 0; policy accept; }' 2>/dev/null || true
        fi

        IFS="," read -ra NET_ARRAY <<< "$redes"
        for net in "${NET_ARRAY[@]}"; do
            net="${net#"${net%%[![:space:]]*}"}"
            net="${net%"${net##*[![:space:]]}"}"

            if [[ "$puertos" == "all" ]]; then
                if [[ "$MODE" == "show" ]]; then
                    log_seg "    nft add rule inet $NFT_TABLE $CHAIN_NAME ip daddr $net accept"
                elif [[ "$MODE" == "apply" ]]; then
                    nft add rule inet "$NFT_TABLE" "$CHAIN_NAME" ip daddr "$net" accept 2>/dev/null && \
                        log_ok "nft: $CHAIN_NAME -> $net (all)" || \
                        { log_fail "Error nft: $net"; ERRORS=$((ERRORS + 1)); }
                fi
                RULES_COUNT=$((RULES_COUNT + 1))
            else
                IFS="," read -ra PORT_ARRAY <<< "$puertos"
                for port in "${PORT_ARRAY[@]}"; do
                    port="${port#"${port%%[![:space:]]*}"}"
                    port="${port%"${port##*[![:space:]]}"}"
                    if [[ "$MODE" == "show" ]]; then
                        log_seg "    nft add rule inet $NFT_TABLE $CHAIN_NAME ip daddr $net tcp dport $port accept"
                    elif [[ "$MODE" == "apply" ]]; then
                        nft add rule inet "$NFT_TABLE" "$CHAIN_NAME" ip daddr "$net" tcp dport "$port" accept 2>/dev/null || true
                        nft add rule inet "$NFT_TABLE" "$CHAIN_NAME" ip daddr "$net" udp dport "$port" accept 2>/dev/null || true
                        log_ok "nft: $CHAIN_NAME -> $net:$port"
                    fi
                    RULES_COUNT=$((RULES_COUNT + 1))
                done
            fi
        done

        # Default deny
        if [[ "$MODE" == "apply" ]]; then
            nft add rule inet "$NFT_TABLE" "$CHAIN_NAME" log prefix "\"ZT-DENY-${CHAIN_NAME}: \"" 2>/dev/null || true
            nft add rule inet "$NFT_TABLE" "$CHAIN_NAME" drop 2>/dev/null || true
        elif [[ "$MODE" == "show" ]]; then
            log_seg "    nft add rule inet $NFT_TABLE $CHAIN_NAME drop"
        fi
    fi

done < "$IDENTITY_MAP"

# ── Resumen ──────────────────────────────────────────────────
log_head "RESUMEN"
log_seg ""
log_seg "  Reglas generadas: $RULES_COUNT"
log_seg "  Errores: $ERRORS"
log_seg "  Backend: $FW_BACKEND"
log_seg "  Modo: $MODE"
log_seg ""

if [[ "$MODE" == "show" ]]; then
    log_seg "${YELLOW}Las reglas se mostraron pero NO se aplicaron.${NC}"
    log_seg "Ejecutar con '\''apply'\'' para aplicar: $0 apply"
else
    if [[ $ERRORS -eq 0 ]]; then
        log_seg "${GREEN}${BOLD}Todas las reglas aplicadas correctamente.${NC}"
    else
        log_seg "${RED}${BOLD}Se encontraron $ERRORS errores al aplicar reglas.${NC}"
    fi
fi

log_seg ""
log_seg "Log: $LOG_FILE"

ENDSCRIPT

    log_change "Creado" "/usr/local/bin/segmentar-por-identidad.sh - micro-segmentacion por identidad"
else
    log_skip "Micro-segmentacion basada en identidad"
fi

###############################################################################
# S7: Least privilege enforcement
###############################################################################
log_section "S7: Least privilege enforcement"

if ask "Crear auditoria de minimo privilegio (/usr/local/bin/auditar-privilegios-zt.sh)?"; then

    ensure_dirs /usr/local/bin /var/log/securizar

    safe_write_file "/usr/local/bin/auditar-privilegios-zt.sh" "0755" << 'ENDSCRIPT'
#!/bin/bash
# ============================================================
# auditar-privilegios-zt.sh - Auditoria de minimo privilegio
# ============================================================
# Analiza privilegios actuales y recomienda reducciones:
#   - Reglas sudoers (NOPASSWD, ALL excesivos)
#   - SUID/SGID files
#   - Capabilities en el filesystem
#   - Cuentas de servicio con privilegios excesivos
# ============================================================
set -euo pipefail

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
BOLD="\033[1m"
DIM="\033[2m"
NC="\033[0m"

REPORT_DIR="/var/log/securizar"
REPORT="${REPORT_DIR}/privilegios-zt-$(date +%Y%m%d-%H%M%S).log"
PLAYBOOK="${REPORT_DIR}/playbook-reduccion-privilegios-$(date +%Y%m%d).txt"
mkdir -p "$REPORT_DIR"

log_priv() { echo -e "$1" | tee -a "$REPORT"; }
log_ok() { log_priv "  ${GREEN}[OK]${NC} $1"; }
log_issue() { log_priv "  ${RED}[ISSUE]${NC} $1"; }
log_warn() { log_priv "  ${YELLOW}[WARN]${NC} $1"; }
log_head() { log_priv "\n${CYAN}=== $1 ===${NC}"; }

ISSUES=0
WARNINGS=0
RECOMMENDATIONS=()

add_rec() {
    RECOMMENDATIONS+=("$1")
}

log_priv "${BOLD}=============================================="
log_priv "  AUDITORIA DE MINIMO PRIVILEGIO - ZERO TRUST"
log_priv "  Fecha: $(date "+%Y-%m-%d %H:%M:%S")"
log_priv "  Host: $(hostname)"
log_priv "==============================================${NC}"

# ══════════════════════════════════════════════════════════════
# 1. Analisis de sudoers
# ══════════════════════════════════════════════════════════════
log_head "1. ANALISIS DE SUDOERS"

# Check for NOPASSWD rules
log_priv "\n  ${BOLD}1.1 Reglas NOPASSWD:${NC}"
NOPASSWD_FOUND=0
for sfile in /etc/sudoers /etc/sudoers.d/*; do
    [[ -f "$sfile" ]] || continue
    while IFS= read -r sline; do
        sline="${sline#"${sline%%[![:space:]]*}"}"
        [[ -z "$sline" || "$sline" == \#* ]] && continue
        if echo "$sline" | grep -qi "NOPASSWD"; then
            log_issue "NOPASSWD en $sfile: $sline"
            NOPASSWD_FOUND=$((NOPASSWD_FOUND + 1))
            ISSUES=$((ISSUES + 1))
        fi
    done < "$sfile"
done
if [[ $NOPASSWD_FOUND -eq 0 ]]; then
    log_ok "No se encontraron reglas NOPASSWD"
else
    add_rec "CRITICO: Eliminar ${NOPASSWD_FOUND} reglas NOPASSWD de sudoers. Usar autenticacion por password para sudo."
fi

# Check for ALL=(ALL) ALL rules
log_priv "\n  ${BOLD}1.2 Reglas excesivamente permisivas (ALL):${NC}"
ALL_RULES=0
for sfile in /etc/sudoers /etc/sudoers.d/*; do
    [[ -f "$sfile" ]] || continue
    while IFS= read -r sline; do
        sline="${sline#"${sline%%[![:space:]]*}"}"
        [[ -z "$sline" || "$sline" == \#* || "$sline" == Defaults* ]] && continue
        if echo "$sline" | grep -qE '\bALL\s*=\s*\(ALL[^)]*\)\s*(ALL|NOPASSWD)'; then
            # Skip standard group rules (wheel/sudo)
            if ! echo "$sline" | grep -qE '^%(wheel|sudo|root)\s'; then
                log_warn "Regla permisiva en $sfile: $sline"
                ALL_RULES=$((ALL_RULES + 1))
                WARNINGS=$((WARNINGS + 1))
            fi
        fi
    done < "$sfile"
done
if [[ $ALL_RULES -eq 0 ]]; then
    log_ok "No se encontraron reglas ALL excesivas (fuera de grupos estandar)"
else
    add_rec "ALTO: Restringir ${ALL_RULES} reglas sudo ALL a comandos especificos."
fi

# Check sudo timestamp timeout
log_priv "\n  ${BOLD}1.3 Timeout de sudo:${NC}"
SUDO_TIMEOUT=$(grep -rhsE "timestamp_timeout" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#" | tail -1 || true)
if [[ -n "$SUDO_TIMEOUT" ]]; then
    TIMEOUT_VAL=$(echo "$SUDO_TIMEOUT" | grep -oE "[0-9]+" | tail -1 || echo "15")
    if [[ "$TIMEOUT_VAL" -le 5 ]]; then
        log_ok "Sudo timeout configurado a ${TIMEOUT_VAL} min (Zero Trust compliant)"
    else
        log_warn "Sudo timeout es ${TIMEOUT_VAL} min (recomendado: <=5)"
        add_rec "MEDIO: Reducir sudo timestamp_timeout a 5 minutos o menos."
        WARNINGS=$((WARNINGS + 1))
    fi
else
    log_warn "Sudo timeout usa valor por defecto (15 min)"
    add_rec "MEDIO: Configurar Defaults timestamp_timeout=5 en sudoers."
    WARNINGS=$((WARNINGS + 1))
fi

# ══════════════════════════════════════════════════════════════
# 2. Archivos SUID/SGID
# ══════════════════════════════════════════════════════════════
log_head "2. ARCHIVOS SUID/SGID"

# Known acceptable SUID binaries
KNOWN_SUID="/usr/bin/passwd /usr/bin/su /usr/bin/sudo /usr/bin/newgrp /usr/bin/chsh /usr/bin/chfn /usr/bin/gpasswd /usr/bin/mount /usr/bin/umount /usr/bin/pkexec /usr/lib/dbus-1.0/dbus-daemon-launch-helper /usr/sbin/unix_chkpwd /usr/bin/crontab /usr/bin/fusermount3 /usr/bin/fusermount"

log_priv "\n  ${BOLD}2.1 SUID binaries:${NC}"
SUID_COUNT=0
SUID_UNKNOWN=0
while IFS= read -r suid_file; do
    [[ -z "$suid_file" ]] && continue
    SUID_COUNT=$((SUID_COUNT + 1))
    if ! echo " $KNOWN_SUID " | grep -q " $suid_file "; then
        log_warn "SUID no estandar: $suid_file (owner: $(stat -c '%U' "$suid_file" 2>/dev/null || echo unknown))"
        SUID_UNKNOWN=$((SUID_UNKNOWN + 1))
    fi
done < <(find /usr/bin /usr/sbin /usr/lib /usr/libexec -perm -4000 -type f 2>/dev/null || true)

log_priv "  Total SUID: $SUID_COUNT | No estandar: $SUID_UNKNOWN"
if [[ $SUID_UNKNOWN -gt 0 ]]; then
    add_rec "ALTO: Revisar $SUID_UNKNOWN binarios SUID no estandar. Considerar eliminar SUID con: chmod u-s <file>"
    ISSUES=$((ISSUES + SUID_UNKNOWN))
else
    log_ok "Todos los SUID son binarios estandar del sistema"
fi

log_priv "\n  ${BOLD}2.2 SGID binaries:${NC}"
SGID_COUNT=0
while IFS= read -r sgid_file; do
    [[ -z "$sgid_file" ]] && continue
    SGID_COUNT=$((SGID_COUNT + 1))
    log_priv "  ${DIM}SGID: $sgid_file${NC}"
done < <(find /usr/bin /usr/sbin -perm -2000 -type f 2>/dev/null | head -20 || true)
log_priv "  Total SGID: $SGID_COUNT"
if [[ $SGID_COUNT -gt 10 ]]; then
    add_rec "MEDIO: Revisar $SGID_COUNT binarios SGID. Reducir donde sea posible."
    WARNINGS=$((WARNINGS + 1))
fi

# ══════════════════════════════════════════════════════════════
# 3. Capabilities del filesystem
# ══════════════════════════════════════════════════════════════
log_head "3. CAPABILITIES DEL FILESYSTEM"

if command -v getcap >/dev/null 2>&1; then
    CAP_COUNT=0
    DANGEROUS_CAPS=0

    # Dangerous capabilities
    DANGEROUS="cap_sys_admin cap_sys_ptrace cap_sys_rawio cap_sys_module cap_dac_override cap_dac_read_search cap_setuid cap_setgid"

    while IFS= read -r cap_line; do
        [[ -z "$cap_line" ]] && continue
        CAP_COUNT=$((CAP_COUNT + 1))

        CAP_FILE=$(echo "$cap_line" | awk "{print \$1}")
        CAP_CAPS=$(echo "$cap_line" | awk "{print \$NF}")

        IS_DANGEROUS=false
        for dcap in $DANGEROUS; do
            if echo "$CAP_CAPS" | grep -qi "$dcap"; then
                IS_DANGEROUS=true
                break
            fi
        done

        if [[ "$IS_DANGEROUS" == "true" ]]; then
            log_issue "Capability peligrosa: $cap_line"
            DANGEROUS_CAPS=$((DANGEROUS_CAPS + 1))
        else
            log_priv "  ${DIM}$cap_line${NC}"
        fi
    done < <(getcap -r /usr/bin /usr/sbin /usr/lib /usr/libexec 2>/dev/null || true)

    log_priv "  Total con capabilities: $CAP_COUNT | Peligrosas: $DANGEROUS_CAPS"
    if [[ $DANGEROUS_CAPS -gt 0 ]]; then
        add_rec "ALTO: Revisar $DANGEROUS_CAPS binarios con capabilities peligrosas."
        ISSUES=$((ISSUES + DANGEROUS_CAPS))
    else
        log_ok "No se encontraron capabilities peligrosas"
    fi
else
    log_warn "getcap no disponible - no se pueden analizar capabilities"
fi

# ══════════════════════════════════════════════════════════════
# 4. Cuentas de servicio
# ══════════════════════════════════════════════════════════════
log_head "4. CUENTAS DE SERVICIO"

log_priv "\n  ${BOLD}4.1 Cuentas con shell interactivo:${NC}"
SVC_SHELL_COUNT=0
while IFS=: read -r svc_user _ svc_uid _ _ _ svc_shell; do
    [[ -z "$svc_user" ]] && continue
    # System accounts (UID < 1000) with interactive shell
    if [[ "$svc_uid" -lt 1000 && "$svc_uid" -gt 0 ]]; then
        if [[ "$svc_shell" != "/sbin/nologin" && "$svc_shell" != "/usr/sbin/nologin" && \
              "$svc_shell" != "/bin/false" && "$svc_shell" != "/usr/bin/false" && \
              "$svc_shell" != "/bin/nologin" && -n "$svc_shell" ]]; then
            log_issue "Cuenta de servicio con shell: $svc_user (UID=$svc_uid, shell=$svc_shell)"
            SVC_SHELL_COUNT=$((SVC_SHELL_COUNT + 1))
            ISSUES=$((ISSUES + 1))
        fi
    fi
done < /etc/passwd

if [[ $SVC_SHELL_COUNT -eq 0 ]]; then
    log_ok "Todas las cuentas de servicio tienen shell restrictivo"
else
    add_rec "CRITICO: Cambiar shell de $SVC_SHELL_COUNT cuentas de servicio a /sbin/nologin"
fi

log_priv "\n  ${BOLD}4.2 Cuentas con UID 0 (root):${NC}"
ROOT_ACCOUNTS=0
while IFS=: read -r ruser _ ruid _; do
    if [[ "$ruid" == "0" && "$ruser" != "root" ]]; then
        log_issue "Cuenta con UID 0 (no es root): $ruser"
        ROOT_ACCOUNTS=$((ROOT_ACCOUNTS + 1))
        ISSUES=$((ISSUES + 1))
    fi
done < /etc/passwd
if [[ $ROOT_ACCOUNTS -eq 0 ]]; then
    log_ok "Solo root tiene UID 0"
else
    add_rec "CRITICO: Eliminar $ROOT_ACCOUNTS cuentas adicionales con UID 0"
fi

log_priv "\n  ${BOLD}4.3 Cuentas sin password:${NC}"
NOPASS_ACCOUNTS=0
while IFS=: read -r npuser nphash _; do
    if [[ "$nphash" == "" || "$nphash" == "!" || "$nphash" == "*" || "$nphash" == "!!" ]]; then
        continue  # Locked or no password (normal for system accounts)
    fi
    # Check for empty password hash
    if [[ ${#nphash} -lt 4 ]]; then
        log_issue "Cuenta con password debil o vacio: $npuser"
        NOPASS_ACCOUNTS=$((NOPASS_ACCOUNTS + 1))
        ISSUES=$((ISSUES + 1))
    fi
done < /etc/shadow 2>/dev/null || true
if [[ $NOPASS_ACCOUNTS -eq 0 ]]; then
    log_ok "No se encontraron cuentas con password vacio"
fi

# ══════════════════════════════════════════════════════════════
# 5. Servicios ejecutandose como root
# ══════════════════════════════════════════════════════════════
log_head "5. SERVICIOS COMO ROOT"

ROOT_SERVICES=0
log_priv ""
while IFS= read -r proc_line; do
    [[ -z "$proc_line" ]] && continue
    PROC_NAME=$(echo "$proc_line" | awk "{print \$11}" | head -1)
    # Skip kernel threads and systemd
    [[ "$PROC_NAME" == "["* ]] && continue
    [[ "$PROC_NAME" == *"systemd"* ]] && continue
    [[ "$PROC_NAME" == *"/sbin/init"* ]] && continue
    [[ "$PROC_NAME" == *"agetty"* ]] && continue

    ROOT_SERVICES=$((ROOT_SERVICES + 1))
    if [[ $ROOT_SERVICES -le 20 ]]; then
        log_priv "  ${DIM}root: $PROC_NAME${NC}"
    fi
done < <(ps aux 2>/dev/null | awk "\$1==\"root\" && NR>1" || true)

log_priv "  Total procesos como root: $ROOT_SERVICES"
if [[ $ROOT_SERVICES -gt 30 ]]; then
    log_warn "Numero elevado de procesos root ($ROOT_SERVICES)"
    add_rec "MEDIO: Revisar $ROOT_SERVICES procesos root. Migrar servicios a cuentas dedicadas."
    WARNINGS=$((WARNINGS + 1))
else
    log_ok "Numero de procesos root aceptable ($ROOT_SERVICES)"
fi

# ══════════════════════════════════════════════════════════════
# 6. Permisos de archivos criticos
# ══════════════════════════════════════════════════════════════
log_head "6. PERMISOS DE ARCHIVOS CRITICOS"

check_perms() {
    local file="$1" expected="$2" desc="$3"
    if [[ -f "$file" ]]; then
        local actual
        actual=$(stat -c %a "$file" 2>/dev/null || echo "???")
        if [[ "$actual" == "$expected" || "$actual" -le "$expected" ]] 2>/dev/null; then
            log_ok "$desc ($file): $actual"
        else
            log_issue "$desc ($file): $actual (esperado: $expected o menor)"
            ISSUES=$((ISSUES + 1))
            add_rec "ALTO: Corregir permisos de $file: chmod $expected $file"
        fi
    fi
}

check_perms /etc/passwd "644" "passwd"
check_perms /etc/shadow "640" "shadow"
check_perms /etc/group "644" "group"
check_perms /etc/gshadow "640" "gshadow"
check_perms /etc/sudoers "440" "sudoers"
check_perms /etc/ssh/sshd_config "600" "sshd_config"
check_perms /etc/crontab "600" "crontab"

# ══════════════════════════════════════════════════════════════
# Resumen y Playbook
# ══════════════════════════════════════════════════════════════
log_head "RESUMEN"

log_priv ""
log_priv "  ${BOLD}Problemas criticos:${NC} $ISSUES"
log_priv "  ${BOLD}Advertencias:${NC} $WARNINGS"
log_priv "  ${BOLD}Recomendaciones:${NC} ${#RECOMMENDATIONS[@]}"

if [[ $ISSUES -eq 0 && $WARNINGS -eq 0 ]]; then
    log_priv "\n  ${GREEN}${BOLD}RESULTADO: BUENO - Privilegios bien configurados${NC}"
elif [[ $ISSUES -eq 0 ]]; then
    log_priv "\n  ${YELLOW}${BOLD}RESULTADO: MEJORABLE - Solo advertencias${NC}"
else
    log_priv "\n  ${RED}${BOLD}RESULTADO: DEFICIENTE - Se requieren acciones correctivas${NC}"
fi

# Generate playbook
if [[ ${#RECOMMENDATIONS[@]} -gt 0 ]]; then
    {
        echo "=============================================="
        echo "  PLAYBOOK DE REDUCCION DE PRIVILEGIOS"
        echo "  Generado: $(date "+%Y-%m-%d %H:%M:%S")"
        echo "  Host: $(hostname)"
        echo "=============================================="
        echo ""
        local idx=1
        for rec in "${RECOMMENDATIONS[@]}"; do
            echo "$idx. $rec"
            idx=$((idx + 1))
        done
        echo ""
        echo "=============================================="
        echo "  ACCIONES SUGERIDAS"
        echo "=============================================="
        echo ""
        echo "# Reducir sudo timeout:"
        echo "echo \"Defaults timestamp_timeout=5\" > /etc/sudoers.d/99-timeout"
        echo ""
        echo "# Cambiar shell de cuentas de servicio:"
        echo "# usermod -s /sbin/nologin <cuenta>"
        echo ""
        echo "# Eliminar SUID innecesario:"
        echo "# chmod u-s <archivo>"
        echo ""
        echo "# Eliminar capabilities innecesarias:"
        echo "# setcap -r <archivo>"
        echo ""
    } > "$PLAYBOOK"
    chmod 0640 "$PLAYBOOK"
    log_priv "\n  Playbook generado: $PLAYBOOK"
fi

log_priv ""
log_priv "Reporte: $REPORT"

ENDSCRIPT

    log_change "Creado" "/usr/local/bin/auditar-privilegios-zt.sh - auditoria de minimo privilegio"
else
    log_skip "Least privilege enforcement"
fi

###############################################################################
# S8: Session management y monitorizacion
###############################################################################
log_section "S8: Session management y monitorizacion"

if ask "Configurar gestion de sesiones Zero Trust?"; then

    ensure_dirs /usr/local/bin /var/log/securizar/sessions

    # ── Limit concurrent sessions per user ───────────────────
    LIMITS_CONF="/etc/security/limits.conf"
    if [[ -f "$LIMITS_CONF" ]]; then
        cp -a "$LIMITS_CONF" "${BACKUP_DIR}/limits.conf.bak" 2>/dev/null || true

        # Check if session limits already configured
        if ! grep -qs "^[^#].*maxlogins" "$LIMITS_CONF"; then
            {
                echo ""
                echo "# Zero Trust: Limitar sesiones concurrentes (added by securizar)"
                echo "*               hard    maxlogins       5"
                echo "@wheel          hard    maxlogins       10"
            } >> "$LIMITS_CONF"
            log_change "Configurado" "Limite de sesiones concurrentes en $LIMITS_CONF (5 max, 10 wheel)"
        else
            log_skip "Limites de sesiones (ya configurados en limits.conf)"
        fi
    else
        log_skip "limits.conf (no encontrado)"
    fi

    # ── Idle session timeout ─────────────────────────────────
    PROFILE_ZT="/etc/profile.d/zero-trust-session.sh"
    if [[ -d /etc/profile.d ]]; then
        if [[ -f "$PROFILE_ZT" ]]; then
            cp -a "$PROFILE_ZT" "${BACKUP_DIR}/zero-trust-session.sh.bak" 2>/dev/null || true
        fi
        cat > "$PROFILE_ZT" << 'PROFEOF'
# Zero Trust: Session controls (added by securizar)
# Idle timeout: 15 minutes (900 seconds)
readonly TMOUT=900
export TMOUT

# Session recording notice for privileged users
if groups 2>/dev/null | grep -qwE 'wheel|sudo|root'; then
    echo ""
    echo "*** AVISO: Esta sesion privilegiada puede ser grabada ***"
    echo "*** Zero Trust Policy: Todas las acciones son auditadas ***"
    echo ""
fi
PROFEOF
        chmod 0644 "$PROFILE_ZT"
        log_change "Creado" "$PROFILE_ZT - idle timeout 15 min + aviso de grabacion"
    else
        log_skip "profile.d no disponible para session timeout"
    fi

    # ── Session management script ────────────────────────────
    safe_write_file "/usr/local/bin/gestionar-sesiones-zt.sh" "0755" << 'ENDSCRIPT'
#!/bin/bash
# ============================================================
# gestionar-sesiones-zt.sh - Gestion de sesiones Zero Trust
# ============================================================
# Monitorea y gestiona sesiones de usuario:
#   - Lista sesiones activas con detalles
#   - Detecta sesiones que violan politicas
#   - Termina sesiones inactivas o no autorizadas
#   - Registra eventos de sesion
# ============================================================
set -euo pipefail

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
BOLD="\033[1m"
DIM="\033[2m"
NC="\033[0m"

SESSION_LOG_DIR="/var/log/securizar/sessions"
LOG_FILE="${SESSION_LOG_DIR}/session-mgmt-$(date +%Y%m%d-%H%M%S).log"
POLICY="/etc/securizar/zero-trust-policy.conf"
mkdir -p "$SESSION_LOG_DIR"

log_s() { echo -e "$1" | tee -a "$LOG_FILE"; }
log_ok() { log_s "  ${GREEN}[OK]${NC} $1"; }
log_warn() { log_s "  ${YELLOW}[WARN]${NC} $1"; }
log_alert() { log_s "  ${RED}[ALERT]${NC} $1"; }

# Load policy
MAX_CONCURRENT=5
SESSION_TIMEOUT_SEC=900
MAX_IDLE_HOURS=24

if [[ -f "$POLICY" ]]; then
    while IFS= read -r line; do
        line="${line#"${line%%[![:space:]]*}"}"
        [[ -z "$line" || "$line" == \#* ]] && continue
        case "$line" in
            SESSION_TIMEOUT=*) SESSION_TIMEOUT_SEC="${line#*=}" ;;
        esac
    done < "$POLICY"
fi

ACTION="${1:-report}"

log_s "${BOLD}=============================================="
log_s "  GESTION DE SESIONES - ZERO TRUST"
log_s "  Fecha: $(date "+%Y-%m-%d %H:%M:%S")"
log_s "  Accion: $ACTION"
log_s "==============================================${NC}"

VIOLATIONS=0

# ══════════════════════════════════════════════════════════════
# 1. Sesiones activas
# ══════════════════════════════════════════════════════════════
log_s "\n${CYAN}=== SESIONES ACTIVAS ===${NC}"
log_s ""
log_s "  $(printf '%-15s %-10s %-20s %-15s %s' 'USUARIO' 'TTY' 'DESDE' 'IDLE' 'LOGIN')"
log_s "  $(printf '%s' '------------------------------------------------------------------------')"

TOTAL_SESSIONS=0
while IFS= read -r wline; do
    [[ -z "$wline" ]] && continue
    W_USER=$(echo "$wline" | awk "{print \$1}")
    W_TTY=$(echo "$wline" | awk "{print \$2}")
    W_FROM=$(echo "$wline" | awk "{print \$5}" | tr -d "()")
    W_LOGIN=$(echo "$wline" | awk "{print \$3, \$4}")
    W_IDLE=$(echo "$wline" | awk "{print \$6}" 2>/dev/null || echo "?")

    log_s "  $(printf '%-15s %-10s %-20s %-15s %s' "$W_USER" "$W_TTY" "${W_FROM:-local}" "${W_IDLE:-active}" "$W_LOGIN")"
    TOTAL_SESSIONS=$((TOTAL_SESSIONS + 1))
done < <(who 2>/dev/null || true)

log_s ""
log_s "  Total sesiones: $TOTAL_SESSIONS"

# ══════════════════════════════════════════════════════════════
# 2. Verificar sesiones concurrentes
# ══════════════════════════════════════════════════════════════
log_s "\n${CYAN}=== VERIFICACION DE SESIONES CONCURRENTES ===${NC}"

while IFS= read -r u; do
    [[ -z "$u" ]] && continue
    U_COUNT=$(who 2>/dev/null | grep -c "^${u} " || echo 0)
    if [[ "$U_COUNT" -gt "$MAX_CONCURRENT" ]]; then
        log_alert "Usuario $u: $U_COUNT sesiones (max: $MAX_CONCURRENT) - VIOLACION"
        VIOLATIONS=$((VIOLATIONS + 1))

        if [[ "$ACTION" == "enforce" ]]; then
            # Kill oldest sessions exceeding limit
            EXCESS=$((U_COUNT - MAX_CONCURRENT))
            log_s "  Terminando $EXCESS sesiones excedentes de $u..."
            who 2>/dev/null | grep "^${u} " | head -n "$EXCESS" | while IFS= read -r kill_line; do
                KILL_TTY=$(echo "$kill_line" | awk "{print \$2}")
                KILL_PID=$(ps -t "$KILL_TTY" -o pid= 2>/dev/null | head -1 || true)
                if [[ -n "$KILL_PID" ]]; then
                    kill -HUP "$KILL_PID" 2>/dev/null || true
                    log_s "    Terminada sesion en $KILL_TTY (PID: $KILL_PID)"
                fi
            done
        fi
    else
        log_ok "Usuario $u: $U_COUNT sesiones (dentro del limite)"
    fi
done < <(who 2>/dev/null | awk "{print \$1}" | sort -u)

# ══════════════════════════════════════════════════════════════
# 3. Verificar sesiones inactivas
# ══════════════════════════════════════════════════════════════
log_s "\n${CYAN}=== SESIONES INACTIVAS ===${NC}"

while IFS= read -r idle_line; do
    [[ -z "$idle_line" ]] && continue
    I_USER=$(echo "$idle_line" | awk "{print \$1}")
    I_TTY=$(echo "$idle_line" | awk "{print \$2}")
    I_IDLE=$(echo "$idle_line" | awk "{print \$5}")

    if [[ "$I_IDLE" =~ old ]]; then
        log_alert "Sesion inactiva >24h: $I_USER en $I_TTY"
        VIOLATIONS=$((VIOLATIONS + 1))

        if [[ "$ACTION" == "enforce" ]]; then
            I_PID=$(ps -t "$I_TTY" -o pid= 2>/dev/null | head -1 || true)
            if [[ -n "$I_PID" ]]; then
                kill -HUP "$I_PID" 2>/dev/null || true
                log_s "    Terminada sesion inactiva en $I_TTY"
            fi
        fi
    fi
done < <(who -u 2>/dev/null || true)

# ══════════════════════════════════════════════════════════════
# 4. Verificar binding a IP de origen
# ══════════════════════════════════════════════════════════════
log_s "\n${CYAN}=== VERIFICACION DE IP BINDING ===${NC}"

while IFS= read -r u; do
    [[ -z "$u" ]] && continue
    IPS=$(who 2>/dev/null | grep "^${u} " | awk "{print \$5}" | tr -d "()" | sort -u)
    IP_COUNT=$(echo "$IPS" | grep -c . || echo 0)
    if [[ "$IP_COUNT" -gt 1 ]]; then
        log_alert "Usuario $u conectado desde $IP_COUNT IPs diferentes: $(echo $IPS | tr '\n' ' ')"
        VIOLATIONS=$((VIOLATIONS + 1))
    elif [[ "$IP_COUNT" -eq 1 ]] && [[ -n "$IPS" ]]; then
        log_ok "Usuario $u: sesion(es) desde IP unica ($IPS)"
    fi
done < <(who 2>/dev/null | awk "{print \$1}" | sort -u)

# ══════════════════════════════════════════════════════════════
# 5. Sesiones privilegiadas
# ══════════════════════════════════════════════════════════════
log_s "\n${CYAN}=== SESIONES PRIVILEGIADAS ===${NC}"

PRIV_GROUP=$(getent group wheel 2>/dev/null | cut -d: -f4 || true)
if [[ -z "$PRIV_GROUP" ]]; then
    PRIV_GROUP=$(getent group sudo 2>/dev/null | cut -d: -f4 || true)
fi

while IFS= read -r u; do
    [[ -z "$u" ]] && continue
    IS_PRIV=false
    if echo ",$PRIV_GROUP," | grep -q ",$u,"; then
        IS_PRIV=true
    elif [[ "$u" == "root" ]]; then
        IS_PRIV=true
    fi

    if [[ "$IS_PRIV" == "true" ]]; then
        U_SESSIONS=$(who 2>/dev/null | grep -c "^${u} " || echo 0)
        log_warn "Sesion privilegiada: $u ($U_SESSIONS sesiones activas)"
    fi
done < <(who 2>/dev/null | awk "{print \$1}" | sort -u)

# ══════════════════════════════════════════════════════════════
# Resumen
# ══════════════════════════════════════════════════════════════
log_s "\n${CYAN}=== RESUMEN ===${NC}"
log_s ""
log_s "  Total sesiones: $TOTAL_SESSIONS"
log_s "  Violaciones: $VIOLATIONS"
log_s "  Accion: $ACTION"
log_s ""

if [[ $VIOLATIONS -eq 0 ]]; then
    log_s "  ${GREEN}${BOLD}ESTADO: CONFORME - Sin violaciones de politica de sesiones${NC}"
else
    log_s "  ${RED}${BOLD}ESTADO: $VIOLATIONS VIOLACIONES detectadas${NC}"
    if [[ "$ACTION" == "report" ]]; then
        log_s "  Ejecutar con '\''enforce'\'' para aplicar acciones: $0 enforce"
    fi
fi

log_s ""
log_s "Log: $LOG_FILE"

ENDSCRIPT

    log_change "Creado" "/usr/local/bin/gestionar-sesiones-zt.sh - gestion de sesiones Zero Trust"

    # ── Script de grabacion de sesiones privilegiadas ────────
    safe_write_file "/usr/local/bin/grabar-sesion-privilegiada.sh" "0755" << 'ENDSCRIPT'
#!/bin/bash
# ============================================================
# grabar-sesion-privilegiada.sh - Grabacion de sesiones privilegiadas
# ============================================================
# Inicia una sesion grabada usando el comando script(1).
# Registra toda la actividad de la terminal para auditoria.
# ============================================================
set -euo pipefail

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
BOLD="\033[1m"
NC="\033[0m"

SESSION_DIR="/var/log/securizar/sessions"
mkdir -p "$SESSION_DIR"
chmod 0700 "$SESSION_DIR"

# Session metadata
SESSION_USER="${SUDO_USER:-$(whoami)}"
SESSION_ID="$(date +%Y%m%d-%H%M%S)-${SESSION_USER}-$$"
SESSION_LOG="${SESSION_DIR}/${SESSION_ID}.log"
SESSION_TIMING="${SESSION_DIR}/${SESSION_ID}.timing"
SESSION_META="${SESSION_DIR}/${SESSION_ID}.meta"

# Write metadata
cat > "$SESSION_META" << METAEOF
SESSION_ID=$SESSION_ID
USER=$SESSION_USER
REAL_UID=$(id -u "$SESSION_USER" 2>/dev/null || echo unknown)
EFFECTIVE_UID=$(id -u)
START_TIME=$(date "+%Y-%m-%d %H:%M:%S")
START_EPOCH=$(date +%s)
TTY=$(tty 2>/dev/null || echo unknown)
SOURCE_IP=${SSH_CLIENT%% *}
HOSTNAME=$(hostname)
SHELL=${SHELL:-/bin/bash}
METAEOF
chmod 0600 "$SESSION_META"

echo -e "${CYAN}=============================================="
echo -e "  SESION PRIVILEGIADA GRABADA"
echo -e "==============================================${NC}"
echo -e ""
echo -e "  ${BOLD}ID de sesion:${NC} $SESSION_ID"
echo -e "  ${BOLD}Usuario:${NC} $SESSION_USER"
echo -e "  ${BOLD}Grabacion:${NC} $SESSION_LOG"
echo -e "  ${BOLD}Timing:${NC} $SESSION_TIMING"
echo -e ""
echo -e "  ${YELLOW}Toda la actividad sera registrada.${NC}"
echo -e "  ${YELLOW}Escriba '\''exit'\'' para finalizar la sesion grabada.${NC}"
echo -e ""

# Log to syslog
logger -t "securizar-zt" "Sesion privilegiada iniciada: user=$SESSION_USER id=$SESSION_ID tty=$(tty 2>/dev/null || echo unknown)"

# Auditd event if available
if command -v auditctl >/dev/null 2>&1; then
    # Add temporary audit rule for this session
    auditctl -a always,exit -F arch=b64 -F uid="$(id -u)" -S execve -k "zt-session-${SESSION_ID}" 2>/dev/null || true
fi

# Start recorded session
if command -v script >/dev/null 2>&1; then
    # Use script with timing for full session replay capability
    script --timing="$SESSION_TIMING" --flush "$SESSION_LOG" 2>/dev/null || \
    script -t"$SESSION_TIMING" "$SESSION_LOG" 2>/dev/null || \
    script "$SESSION_LOG"
else
    echo -e "${RED}Comando '\''script'\'' no disponible.${NC}"
    echo "Usando logging basico con exec..."
    exec > >(tee -a "$SESSION_LOG") 2>&1
    bash
fi

# Session ended
END_TIME=$(date "+%Y-%m-%d %H:%M:%S")
END_EPOCH=$(date +%s)
START_EPOCH=$(grep "START_EPOCH" "$SESSION_META" | cut -d= -f2)
DURATION=$((END_EPOCH - START_EPOCH))

# Update metadata
{
    echo "END_TIME=$END_TIME"
    echo "END_EPOCH=$END_EPOCH"
    echo "DURATION_SECONDS=$DURATION"
} >> "$SESSION_META"

# Remove temporary audit rule
if command -v auditctl >/dev/null 2>&1; then
    auditctl -d always,exit -F arch=b64 -F uid="$(id -u)" -S execve -k "zt-session-${SESSION_ID}" 2>/dev/null || true
fi

# Log completion
logger -t "securizar-zt" "Sesion privilegiada finalizada: user=$SESSION_USER id=$SESSION_ID duracion=${DURATION}s"

echo ""
echo -e "${GREEN}Sesion grabada finalizada.${NC}"
echo -e "  Duracion: ${DURATION} segundos"
echo -e "  Log: $SESSION_LOG"
echo -e "  Timing: $SESSION_TIMING"
echo -e "  Metadata: $SESSION_META"
echo ""
echo -e "Para reproducir la sesion:"
echo -e "  scriptreplay ${SESSION_TIMING} ${SESSION_LOG}"

ENDSCRIPT

    log_change "Creado" "/usr/local/bin/grabar-sesion-privilegiada.sh - grabacion de sesiones privilegiadas"

    # ── Configure auditd session logging if available ────────
    AUDIT_RULES_DIR="/etc/audit/rules.d"
    if [[ -d "$AUDIT_RULES_DIR" ]]; then
        AUDIT_ZT="${AUDIT_RULES_DIR}/99-zero-trust-sessions.rules"
        if [[ ! -f "$AUDIT_ZT" ]]; then
            cat > "$AUDIT_ZT" << 'AUDITEOF'
## Zero Trust: Session monitoring rules (added by securizar)

# Monitor session open/close
-w /var/run/utmp -p wa -k zt-session
-w /var/log/wtmp -p wa -k zt-session
-w /var/log/btmp -p wa -k zt-session

# Monitor user/group changes
-w /etc/passwd -p wa -k zt-identity
-w /etc/shadow -p wa -k zt-identity
-w /etc/group -p wa -k zt-identity
-w /etc/gshadow -p wa -k zt-identity

# Monitor sudo usage
-w /etc/sudoers -p wa -k zt-privilege
-w /etc/sudoers.d/ -p wa -k zt-privilege
-w /usr/bin/sudo -p x -k zt-privilege
-w /usr/bin/su -p x -k zt-privilege

# Monitor PAM configuration
-w /etc/pam.d/ -p wa -k zt-auth

# Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k zt-auth
-w /etc/ssh/sshd_config.d/ -p wa -k zt-auth

# Monitor login events
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k zt-priv-cmd
AUDITEOF
            chmod 0640 "$AUDIT_ZT"
            log_change "Creado" "$AUDIT_ZT - reglas auditd Zero Trust para sesiones"

            # Reload audit rules if auditd is running
            if systemctl is-active auditd &>/dev/null; then
                augenrules --load 2>/dev/null || auditctl -R "$AUDIT_ZT" 2>/dev/null || true
                log_change "Recargado" "Reglas de auditd"
            fi
        else
            log_skip "Reglas auditd Zero Trust (ya existen)"
        fi
    else
        log_skip "Reglas auditd (directorio $AUDIT_RULES_DIR no existe)"
    fi
else
    log_skip "Session management y monitorizacion"
fi

###############################################################################
# S9: Integracion con SSO y MFA
###############################################################################
log_section "S9: Integracion con SSO y MFA"

if ask "Crear verificacion de SSO y MFA (/usr/local/bin/verificar-sso-mfa.sh)?"; then

    ensure_dirs /usr/local/bin /var/log/securizar

    safe_write_file "/usr/local/bin/verificar-sso-mfa.sh" "0755" << 'ENDSCRIPT'
#!/bin/bash
# ============================================================
# verificar-sso-mfa.sh - Verificacion de SSO y MFA
# ============================================================
# Verifica el estado de integracion SSO/MFA:
#   - SAML/OIDC en PAM
#   - SSSD/LDAP/Kerberos
#   - RADIUS
#   - Google Authenticator (TOTP)
#   - YubiKey/FIDO2
#   - Certificados
# ============================================================
set -euo pipefail

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
BOLD="\033[1m"
DIM="\033[2m"
NC="\033[0m"

REPORT_DIR="/var/log/securizar"
REPORT="${REPORT_DIR}/sso-mfa-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$REPORT_DIR"

log_v() { echo -e "$1" | tee -a "$REPORT"; }
log_ok() { log_v "  ${GREEN}[DISPONIBLE]${NC} $1"; }
log_no() { log_v "  ${RED}[NO DISPONIBLE]${NC} $1"; }
log_conf() { log_v "  ${GREEN}[CONFIGURADO]${NC} $1"; }
log_noconf() { log_v "  ${YELLOW}[NO CONFIGURADO]${NC} $1"; }
log_head() { log_v "\n${CYAN}=== $1 ===${NC}"; }

SSO_SCORE=0
MFA_SCORE=0

log_v "${BOLD}=============================================="
log_v "  VERIFICACION DE SSO Y MFA - ZERO TRUST"
log_v "  Fecha: $(date "+%Y-%m-%d %H:%M:%S")"
log_v "  Host: $(hostname)"
log_v "==============================================${NC}"

# ══════════════════════════════════════════════════════════════
# 1. SSO Integration
# ══════════════════════════════════════════════════════════════
log_head "1. INTEGRACION SSO"

# ── 1.1 SSSD (System Security Services Daemon) ──────────────
log_v "\n  ${BOLD}1.1 SSSD:${NC}"
if command -v sssd >/dev/null 2>&1; then
    log_ok "SSSD instalado"
    SSO_SCORE=$((SSO_SCORE + 10))

    if systemctl is-active sssd >/dev/null 2>&1; then
        log_conf "SSSD servicio activo"
        SSO_SCORE=$((SSO_SCORE + 10))
    else
        log_noconf "SSSD servicio no activo"
    fi

    if [[ -f /etc/sssd/sssd.conf ]]; then
        log_conf "sssd.conf existe"
        # Check configured domains
        SSSD_DOMAINS=$(grep -E "^\s*domains\s*=" /etc/sssd/sssd.conf 2>/dev/null | cut -d= -f2 || echo "ninguno")
        log_v "  ${DIM}Dominios: $SSSD_DOMAINS${NC}"

        # Check id_provider
        ID_PROVIDER=$(grep -E "^\s*id_provider\s*=" /etc/sssd/sssd.conf 2>/dev/null | head -1 | cut -d= -f2 | tr -d " " || echo "unknown")
        log_v "  ${DIM}ID Provider: $ID_PROVIDER${NC}"
        SSO_SCORE=$((SSO_SCORE + 10))
    else
        log_noconf "sssd.conf no encontrado"
    fi
else
    log_no "SSSD no instalado"
    log_v "  ${DIM}Instalar: apt/dnf/zypper install sssd${NC}"
fi

# ── 1.2 Kerberos ────────────────────────────────────────────
log_v "\n  ${BOLD}1.2 Kerberos:${NC}"
if command -v kinit >/dev/null 2>&1; then
    log_ok "Kerberos (kinit) instalado"
    SSO_SCORE=$((SSO_SCORE + 10))

    if [[ -f /etc/krb5.conf ]]; then
        log_conf "krb5.conf existe"
        KRB_REALM=$(grep -E "^\s*default_realm\s*=" /etc/krb5.conf 2>/dev/null | head -1 | awk "{print \$NF}" || echo "no configurado")
        log_v "  ${DIM}Default realm: $KRB_REALM${NC}"
        SSO_SCORE=$((SSO_SCORE + 10))
    else
        log_noconf "krb5.conf no encontrado"
    fi

    # Check for valid tickets
    if klist 2>/dev/null | grep -q "Valid starting"; then
        log_conf "Tickets Kerberos activos"
    else
        log_v "  ${DIM}No hay tickets Kerberos activos${NC}"
    fi
else
    log_no "Kerberos no instalado"
    log_v "  ${DIM}Instalar: apt/dnf/zypper install krb5-client${NC}"
fi

# ── 1.3 LDAP PAM integration ────────────────────────────────
log_v "\n  ${BOLD}1.3 LDAP:${NC}"
if grep -rqs "pam_ldap\|pam_sss" /etc/pam.d/ 2>/dev/null; then
    log_conf "PAM LDAP/SSS configurado"
    SSO_SCORE=$((SSO_SCORE + 10))

    # Show which PAM files have LDAP
    for pf in /etc/pam.d/*; do
        [[ -f "$pf" ]] || continue
        if grep -qs "pam_ldap\|pam_sss" "$pf"; then
            log_v "  ${DIM}  $pf: $(grep -c 'pam_ldap\|pam_sss' "$pf") regla(s)${NC}"
        fi
    done
else
    log_noconf "PAM LDAP/SSS no configurado"
fi

if [[ -f /etc/ldap.conf ]] || [[ -f /etc/openldap/ldap.conf ]] || [[ -f /etc/ldap/ldap.conf ]]; then
    log_ok "Configuracion LDAP encontrada"
    SSO_SCORE=$((SSO_SCORE + 5))
else
    log_no "Configuracion LDAP no encontrada"
fi

# ── 1.4 RADIUS ──────────────────────────────────────────────
log_v "\n  ${BOLD}1.4 RADIUS:${NC}"
if grep -rqs "pam_radius" /etc/pam.d/ 2>/dev/null; then
    log_conf "PAM RADIUS configurado"
    SSO_SCORE=$((SSO_SCORE + 10))
elif [[ -f /etc/raddb/server ]] || [[ -f /etc/freeradius/radiusd.conf ]] || [[ -f /etc/radcli/radiusclient.conf ]]; then
    log_ok "RADIUS configuracion encontrada (no en PAM)"
    SSO_SCORE=$((SSO_SCORE + 5))
else
    log_no "RADIUS no configurado"
    log_v "  ${DIM}Instalar: apt/dnf/zypper install libpam-radius-auth${NC}"
fi

# ── 1.5 SAML/OIDC ───────────────────────────────────────────
log_v "\n  ${BOLD}1.5 SAML/OIDC:${NC}"
SAML_FOUND=false
if command -v mod_auth_mellon >/dev/null 2>&1 || [[ -f /etc/apache2/mods-available/auth_mellon.conf ]] || \
   [[ -f /etc/httpd/conf.modules.d/*mellon* ]] 2>/dev/null; then
    log_ok "mod_auth_mellon (SAML) disponible"
    SAML_FOUND=true
    SSO_SCORE=$((SSO_SCORE + 5))
fi

if command -v oauth2-proxy >/dev/null 2>&1; then
    log_ok "oauth2-proxy instalado (OIDC)"
    SAML_FOUND=true
    SSO_SCORE=$((SSO_SCORE + 5))
fi

if [[ -d /etc/securizar/iap ]]; then
    log_ok "Templates IAP disponibles (/etc/securizar/iap/)"
    SSO_SCORE=$((SSO_SCORE + 5))
fi

if [[ "$SAML_FOUND" == "false" ]]; then
    log_no "SAML/OIDC no configurado"
fi

# ══════════════════════════════════════════════════════════════
# 2. MFA Deployment
# ══════════════════════════════════════════════════════════════
log_head "2. DESPLIEGUE MFA"

# ── 2.1 Google Authenticator (TOTP) ─────────────────────────
log_v "\n  ${BOLD}2.1 Google Authenticator (TOTP):${NC}"
if command -v google-authenticator >/dev/null 2>&1; then
    log_ok "google-authenticator instalado"
    MFA_SCORE=$((MFA_SCORE + 10))

    # Check PAM configuration
    if grep -rqs "pam_google_authenticator" /etc/pam.d/ 2>/dev/null; then
        log_conf "pam_google_authenticator en PAM"
        MFA_SCORE=$((MFA_SCORE + 15))

        # Which PAM files
        for pf in /etc/pam.d/*; do
            [[ -f "$pf" ]] || continue
            if grep -qs "pam_google_authenticator" "$pf"; then
                log_v "  ${DIM}  Configurado en: $pf${NC}"
            fi
        done
    else
        log_noconf "pam_google_authenticator no en PAM"
        log_v "  ${DIM}Agregar a /etc/pam.d/sshd: auth required pam_google_authenticator.so${NC}"
    fi

    # Check which users have TOTP configured
    TOTP_USERS=0
    while IFS=: read -r tuser _ tuid _ _ thome _; do
        [[ "$tuid" -lt 1000 ]] && continue
        if [[ -f "${thome}/.google_authenticator" ]]; then
            TOTP_USERS=$((TOTP_USERS + 1))
        fi
    done < /etc/passwd
    log_v "  ${DIM}Usuarios con TOTP: $TOTP_USERS${NC}"
    if [[ $TOTP_USERS -gt 0 ]]; then
        MFA_SCORE=$((MFA_SCORE + 10))
    fi
else
    log_no "google-authenticator no instalado"
    log_v "  ${DIM}Instalar: apt/dnf/zypper install google-authenticator-libpam${NC}"
fi

# ── 2.2 YubiKey / FIDO2 ─────────────────────────────────────
log_v "\n  ${BOLD}2.2 YubiKey / FIDO2:${NC}"
if command -v pamu2fcfg >/dev/null 2>&1; then
    log_ok "pam-u2f instalado (FIDO2/U2F)"
    MFA_SCORE=$((MFA_SCORE + 10))

    if grep -rqs "pam_u2f" /etc/pam.d/ 2>/dev/null; then
        log_conf "pam_u2f configurado en PAM"
        MFA_SCORE=$((MFA_SCORE + 15))
    else
        log_noconf "pam_u2f no configurado en PAM"
        log_v "  ${DIM}Agregar a PAM: auth required pam_u2f.so${NC}"
    fi

    # Check for u2f_keys files
    U2F_USERS=0
    while IFS=: read -r tuser _ tuid _ _ thome _; do
        [[ "$tuid" -lt 1000 ]] && continue
        if [[ -f "${thome}/.config/Yubico/u2f_keys" ]]; then
            U2F_USERS=$((U2F_USERS + 1))
        fi
    done < /etc/passwd
    log_v "  ${DIM}Usuarios con U2F: $U2F_USERS${NC}"
else
    log_no "pam-u2f no instalado (YubiKey/FIDO2)"
    log_v "  ${DIM}Instalar: apt/dnf/zypper install pam-u2f${NC}"
fi

if command -v ykman >/dev/null 2>&1; then
    log_ok "ykman (YubiKey Manager) instalado"
    MFA_SCORE=$((MFA_SCORE + 5))
fi

# ── 2.3 Certificate-based auth ──────────────────────────────
log_v "\n  ${BOLD}2.3 Autenticacion basada en certificados:${NC}"

# SSH CA
if grep -rqs "TrustedUserCAKeys" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null; then
    log_conf "SSH CA (TrustedUserCAKeys) configurado"
    CA_FILE=$(grep -rhsE "^\s*TrustedUserCAKeys" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null | awk "{print \$2}" | head -1)
    log_v "  ${DIM}CA file: ${CA_FILE:-unknown}${NC}"
    MFA_SCORE=$((MFA_SCORE + 15))
else
    log_noconf "SSH CA no configurado"
    log_v "  ${DIM}Configurar: TrustedUserCAKeys /etc/ssh/ca-user.pub en sshd_config${NC}"
fi

# Client TLS certificates
if [[ -d /etc/ssl/client-certs ]] || [[ -d /etc/pki/tls/client-certs ]]; then
    log_ok "Directorio de certificados de cliente existe"
    MFA_SCORE=$((MFA_SCORE + 5))
fi

# Smart card (PKCS#11)
if command -v pkcs11-tool >/dev/null 2>&1; then
    log_ok "PKCS#11 (smart card) disponible"
    MFA_SCORE=$((MFA_SCORE + 5))
    if grep -rqs "pam_pkcs11\|pam_p11" /etc/pam.d/ 2>/dev/null; then
        log_conf "PAM PKCS#11 configurado"
        MFA_SCORE=$((MFA_SCORE + 10))
    else
        log_noconf "PAM PKCS#11 no configurado"
    fi
else
    log_no "PKCS#11 no disponible"
fi

# ══════════════════════════════════════════════════════════════
# 3. SSH Authentication Methods
# ══════════════════════════════════════════════════════════════
log_head "3. METODOS DE AUTENTICACION SSH"

SSHD_CONF="/etc/ssh/sshd_config"
if [[ -f "$SSHD_CONF" ]]; then
    log_v "  ${BOLD}Configuracion actual:${NC}"

    # AuthenticationMethods
    AUTH_METHODS=$(grep -rhsE "^\s*AuthenticationMethods" "$SSHD_CONF" /etc/ssh/sshd_config.d/*.conf 2>/dev/null | head -1 || echo "default")
    log_v "  AuthenticationMethods: $AUTH_METHODS"

    # PubkeyAuthentication
    PUBKEY=$(grep -rhsE "^\s*PubkeyAuthentication" "$SSHD_CONF" /etc/ssh/sshd_config.d/*.conf 2>/dev/null | head -1 || echo "yes (default)")
    log_v "  PubkeyAuthentication: $PUBKEY"

    # PasswordAuthentication
    PASSAUTH=$(grep -rhsE "^\s*PasswordAuthentication" "$SSHD_CONF" /etc/ssh/sshd_config.d/*.conf 2>/dev/null | head -1 || echo "yes (default)")
    log_v "  PasswordAuthentication: $PASSAUTH"

    # ChallengeResponseAuthentication / KbdInteractiveAuthentication
    CHALLENGE=$(grep -rhsE "^\s*(ChallengeResponseAuthentication|KbdInteractiveAuthentication)" "$SSHD_CONF" /etc/ssh/sshd_config.d/*.conf 2>/dev/null | head -1 || echo "default")
    log_v "  ChallengeResponse/KbdInteractive: $CHALLENGE"

    # Check if MFA is enforced via AuthenticationMethods
    if echo "$AUTH_METHODS" | grep -qE "publickey.*keyboard-interactive|keyboard-interactive.*publickey"; then
        log_conf "MFA en SSH (publickey + keyboard-interactive)"
        MFA_SCORE=$((MFA_SCORE + 10))
    else
        log_v "  ${YELLOW}SSH no requiere multiples factores de autenticacion${NC}"
        log_v "  ${DIM}Recomendacion: AuthenticationMethods publickey,keyboard-interactive${NC}"
    fi
fi

# ══════════════════════════════════════════════════════════════
# Resumen
# ══════════════════════════════════════════════════════════════
log_head "RESUMEN"

SSO_MAX=100
MFA_MAX=100

# Cap scores
[[ $SSO_SCORE -gt $SSO_MAX ]] && SSO_SCORE=$SSO_MAX
[[ $MFA_SCORE -gt $MFA_MAX ]] && MFA_SCORE=$MFA_MAX

log_v ""
log_v "  ${BOLD}SSO Score:${NC} ${SSO_SCORE}/${SSO_MAX}"
log_v "  ${BOLD}MFA Score:${NC} ${MFA_SCORE}/${MFA_MAX}"
log_v ""

COMBINED=$(( (SSO_SCORE + MFA_SCORE) / 2 ))

if [[ $COMBINED -ge 70 ]]; then
    log_v "  ${GREEN}${BOLD}ESTADO: BUENO - SSO y MFA bien implementados${NC}"
elif [[ $COMBINED -ge 40 ]]; then
    log_v "  ${YELLOW}${BOLD}ESTADO: MEJORABLE - Se requieren mejoras en SSO/MFA${NC}"
else
    log_v "  ${RED}${BOLD}ESTADO: DEFICIENTE - SSO y MFA necesitan implementacion urgente${NC}"
fi

log_v ""
log_v "${CYAN}--- Recomendaciones ---${NC}"
if [[ $SSO_SCORE -lt 30 ]]; then
    log_v "  1. Implementar SSSD con LDAP/AD para autenticacion centralizada"
    log_v "  2. Configurar Kerberos para SSO"
fi
if [[ $MFA_SCORE -lt 30 ]]; then
    log_v "  3. Desplegar google-authenticator (TOTP) como minimo"
    log_v "  4. Considerar YubiKey/FIDO2 para cuentas privilegiadas"
    log_v "  5. Configurar AuthenticationMethods en SSH para requerir 2FA"
fi
if [[ $SSO_SCORE -ge 30 && $MFA_SCORE -ge 30 ]]; then
    log_v "  - Continuar con certificados para acceso a servicios criticos"
    log_v "  - Evaluar FIDO2/WebAuthn para autenticacion passwordless"
fi

log_v ""
log_v "Reporte: $REPORT"

ENDSCRIPT

    log_change "Creado" "/usr/local/bin/verificar-sso-mfa.sh - verificacion de SSO y MFA"
else
    log_skip "Integracion con SSO y MFA"
fi

###############################################################################
# S10: Auditoria integral Zero Trust
###############################################################################
log_section "S10: Auditoria integral Zero Trust"

if ask "Crear auditoria integral Zero Trust (/usr/local/bin/auditoria-zero-trust.sh)?"; then

    ensure_dirs /usr/local/bin /var/log/securizar /etc/cron.weekly

    safe_write_file "/usr/local/bin/auditoria-zero-trust.sh" "0755" << 'ENDSCRIPT'
#!/bin/bash
# ============================================================
# auditoria-zero-trust.sh - Auditoria integral Zero Trust
# ============================================================
# Evaluacion completa de postura Zero Trust:
#   - 5 pilares (Identidad, Dispositivos, Redes, Apps, Datos)
#   - Gap analysis contra NIST SP 800-207
#   - Cumplimiento de politica Zero Trust local
#   - Roadmap de recomendaciones priorizadas
#   - Puntuacion: BUENO / MEJORABLE / DEFICIENTE
# ============================================================
set -euo pipefail

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
BOLD="\033[1m"
DIM="\033[2m"
NC="\033[0m"

REPORT_DIR="/var/log/securizar"
FECHA=$(date +%Y%m%d-%H%M%S)
REPORT="${REPORT_DIR}/auditoria-zt-${FECHA}.log"
POLICY_FILE="/etc/securizar/zero-trust-policy.conf"
mkdir -p "$REPORT_DIR"

log_a() { echo -e "$1" | tee -a "$REPORT"; }
log_ok() { log_a "    ${GREEN}[PASS]${NC} $1"; }
log_no() { log_a "    ${RED}[FAIL]${NC} $1"; }
log_warn() { log_a "    ${YELLOW}[WARN]${NC} $1"; }
log_head() { log_a "\n${CYAN}$1${NC}"; }

# Scoring
declare -A PILLAR_SCORES
declare -A PILLAR_MAX
PILLAR_NAMES=("IDENTIDAD" "DISPOSITIVOS" "REDES" "APLICACIONES" "DATOS")
for p in "${PILLAR_NAMES[@]}"; do
    PILLAR_SCORES[$p]=0
    PILLAR_MAX[$p]=0
done

GAPS=()
ROADMAP=()

score() {
    local pillar="$1" name="$2" check="$3" weight="${4:-5}" rec="${5:-}"
    PILLAR_MAX[$pillar]=$(( ${PILLAR_MAX[$pillar]} + weight ))
    if eval "$check" 2>/dev/null; then
        PILLAR_SCORES[$pillar]=$(( ${PILLAR_SCORES[$pillar]} + weight ))
        log_ok "$name (+${weight})"
        return 0
    else
        log_no "$name (+0)"
        [[ -n "$rec" ]] && GAPS+=("[$pillar] $name: $rec")
        return 1
    fi
}

log_a "================================================================"
log_a "     AUDITORIA INTEGRAL ZERO TRUST"
log_a "     $(date "+%Y-%m-%d %H:%M:%S")"
log_a "     Host: $(hostname)"
log_a "     Kernel: $(uname -r)"
log_a "     OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"' || echo unknown)"
log_a "================================================================"

# ══════════════════════════════════════════════════════════════
# PILAR 1: IDENTIDAD
# ══════════════════════════════════════════════════════════════
log_head "══════════════════════════════════════════════"
log_head "  PILAR 1: IDENTIDAD"
log_head "══════════════════════════════════════════════"

log_a "\n  ${BOLD}1.1 Autenticacion multi-factor${NC}"
score "IDENTIDAD" "MFA en PAM (TOTP/U2F)" \
    "grep -rqs 'pam_google_authenticator\|pam_u2f' /etc/pam.d/" 10 \
    "Instalar y configurar pam_google_authenticator o pam_u2f"

score "IDENTIDAD" "MFA en SSH (AuthenticationMethods)" \
    "grep -rqsE '^\s*AuthenticationMethods\s+.*,.*' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null" 8 \
    "Configurar AuthenticationMethods publickey,keyboard-interactive"

log_a "\n  ${BOLD}1.2 Single Sign-On${NC}"
score "IDENTIDAD" "SSSD activo" \
    "systemctl is-active sssd >/dev/null 2>&1" 8 \
    "Implementar SSSD para autenticacion centralizada"

score "IDENTIDAD" "Kerberos configurado" \
    "test -f /etc/krb5.conf && grep -qsE '^\s*default_realm' /etc/krb5.conf" 5 \
    "Configurar Kerberos para SSO"

score "IDENTIDAD" "PAM LDAP/SSS integrado" \
    "grep -rqs 'pam_ldap\|pam_sss\|pam_krb5' /etc/pam.d/" 7 \
    "Integrar PAM con IdP externo (LDAP/SSSD/Kerberos)"

log_a "\n  ${BOLD}1.3 Politicas de password${NC}"
score "IDENTIDAD" "Politica de complejidad (pwquality)" \
    "test -f /etc/security/pwquality.conf && grep -qsE '^\s*minlen\s*=\s*[0-9]' /etc/security/pwquality.conf" 7 \
    "Configurar /etc/security/pwquality.conf con minlen>=12"

score "IDENTIDAD" "Envejecimiento de passwords" \
    "grep -qsE '^\s*PASS_MAX_DAYS\s+[0-9]+' /etc/login.defs && ! grep -qsE '^\s*PASS_MAX_DAYS\s+99999' /etc/login.defs" 5 \
    "Configurar PASS_MAX_DAYS en /etc/login.defs"

score "IDENTIDAD" "Bloqueo de cuentas (faillock)" \
    "grep -rqs 'pam_faillock\|pam_tally2' /etc/pam.d/" 7 \
    "Configurar pam_faillock para bloqueo tras intentos fallidos"

log_a "\n  ${BOLD}1.4 Autenticacion por certificados${NC}"
score "IDENTIDAD" "SSH CA configurado (TrustedUserCAKeys)" \
    "grep -rqs 'TrustedUserCAKeys' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null" 5 \
    "Implementar SSH Certificate Authority"

log_a "\n  ${BOLD}1.5 Controles de acceso${NC}"
score "IDENTIDAD" "Root SSH restringido" \
    "grep -qsE '^\s*PermitRootLogin\s+(no|prohibit-password)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null" 7 \
    "Configurar PermitRootLogin no en sshd_config"

score "IDENTIDAD" "Sin cuentas UID 0 adicionales" \
    "test \$(awk -F: '\$3==0' /etc/passwd | wc -l) -le 1" 5 \
    "Eliminar cuentas con UID 0 excepto root"

score "IDENTIDAD" "Sudo requiere password (sin NOPASSWD)" \
    "! grep -rqsE '^\s*[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null" 5 \
    "Eliminar reglas NOPASSWD de sudoers"

score "IDENTIDAD" "Sudo timeout corto (<=5 min)" \
    "grep -rqsE 'timestamp_timeout\s*=\s*[0-5]\b' /etc/sudoers /etc/sudoers.d/ 2>/dev/null" 5 \
    "Configurar Defaults timestamp_timeout=5"

score "IDENTIDAD" "Autenticacion continua configurada" \
    "test -x /usr/local/bin/auth-continua.sh" 3 \
    "Desplegar auth-continua.sh"

# ══════════════════════════════════════════════════════════════
# PILAR 2: DISPOSITIVOS
# ══════════════════════════════════════════════════════════════
log_head "══════════════════════════════════════════════"
log_head "  PILAR 2: DISPOSITIVOS"
log_head "══════════════════════════════════════════════"

log_a "\n  ${BOLD}2.1 Cifrado y seguridad fisica${NC}"
score "DISPOSITIVOS" "Cifrado de disco (LUKS)" \
    "lsblk -o TYPE 2>/dev/null | grep -q crypt || dmsetup ls --target crypt 2>/dev/null | grep -q ." 15 \
    "Implementar cifrado de disco con LUKS"

score "DISPOSITIVOS" "Secure Boot habilitado" \
    "mokutil --sb-state 2>/dev/null | grep -qi 'SecureBoot enabled'" 10 \
    "Habilitar Secure Boot en UEFI"

log_a "\n  ${BOLD}2.2 Proteccion del sistema${NC}"
score "DISPOSITIVOS" "Firewall activo" \
    "systemctl is-active firewalld >/dev/null 2>&1 || systemctl is-active ufw >/dev/null 2>&1 || systemctl is-active nftables >/dev/null 2>&1" 12 \
    "Activar firewall (firewalld/ufw/nftables)"

score "DISPOSITIVOS" "Monitoreo de integridad (AIDE)" \
    "command -v aide >/dev/null 2>&1 || command -v tripwire >/dev/null 2>&1" 10 \
    "Instalar AIDE o Tripwire para monitoreo de integridad"

score "DISPOSITIVOS" "Auditd activo" \
    "systemctl is-active auditd >/dev/null 2>&1" 10 \
    "Activar auditd para logging de seguridad"

score "DISPOSITIVOS" "Antivirus (ClamAV)" \
    "command -v clamscan >/dev/null 2>&1" 5 \
    "Instalar ClamAV"

log_a "\n  ${BOLD}2.3 Estado del sistema${NC}"
score "DISPOSITIVOS" "Parches al dia (no reboot pendiente)" \
    "! test -f /var/run/reboot-required" 8 \
    "Aplicar parches pendientes y reiniciar si es necesario"

score "DISPOSITIVOS" "NTP sincronizado" \
    "timedatectl 2>/dev/null | grep -qi 'synchronized: yes\|NTP.*active'" 5 \
    "Configurar sincronizacion NTP"

log_a "\n  ${BOLD}2.4 Inventario y compliance${NC}"
score "DISPOSITIVOS" "Device trust verificador disponible" \
    "test -x /usr/local/bin/verificar-device-trust.sh" 5 \
    "Desplegar verificar-device-trust.sh"

score "DISPOSITIVOS" "Inventario de dispositivos" \
    "test -f /etc/securizar/device-inventory.conf" 5 \
    "Crear inventario en /etc/securizar/device-inventory.conf"

score "DISPOSITIVOS" "Idle timeout configurado" \
    "grep -rqsE 'TMOUT=' /etc/profile /etc/profile.d/ /etc/bashrc 2>/dev/null" 5 \
    "Configurar TMOUT en /etc/profile.d/"

# ══════════════════════════════════════════════════════════════
# PILAR 3: REDES
# ══════════════════════════════════════════════════════════════
log_head "══════════════════════════════════════════════"
log_head "  PILAR 3: REDES"
log_head "══════════════════════════════════════════════"

log_a "\n  ${BOLD}3.1 Segmentacion${NC}"
score "REDES" "Firewall con reglas explicitas" \
    "iptables -L -n 2>/dev/null | grep -cE 'ACCEPT|DROP|REJECT' | grep -qv '^0$' || nft list ruleset 2>/dev/null | grep -q 'chain'" 10 \
    "Configurar reglas de firewall explicitas"

score "REDES" "Micro-segmentacion por identidad" \
    "test -f /etc/securizar/identity-network-map.conf && test -x /usr/local/bin/segmentar-por-identidad.sh" 8 \
    "Desplegar micro-segmentacion por identidad"

score "REDES" "Servicios de escucha limitados (<15)" \
    "test \$(ss -tlnp 2>/dev/null | grep -c LISTEN) -lt 15" 7 \
    "Reducir servicios de escucha innecesarios"

log_a "\n  ${BOLD}3.2 Cifrado de comunicaciones${NC}"
score "REDES" "TLS 1.3 soportado" \
    "openssl version 2>/dev/null | grep -qE '1\.[1-9]|3\.[0-9]'" 10 \
    "Actualizar OpenSSL para soporte TLS 1.3"

score "REDES" "SSH con cifrados fuertes" \
    "grep -qsE '^\s*Ciphers\s+.*aes.*gcm' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null" 8 \
    "Configurar ciphers fuertes en SSH"

score "REDES" "DNS cifrado (DoT/DoH)" \
    "grep -rqs 'DNSOverTLS' /etc/systemd/resolved.conf /etc/systemd/resolved.conf.d/ 2>/dev/null || command -v stubby >/dev/null 2>&1" 7 \
    "Configurar DNS over TLS"

score "REDES" "SSH re-key configurado" \
    "grep -rqsE '^\s*RekeyLimit' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null" 5 \
    "Configurar RekeyLimit en SSH"

log_a "\n  ${BOLD}3.3 Proteccion perimetral${NC}"
score "REDES" "VPN disponible (WireGuard/OpenVPN)" \
    "command -v wg >/dev/null 2>&1 || command -v openvpn >/dev/null 2>&1" 8 \
    "Implementar VPN para acceso remoto"

score "REDES" "Fail2ban activo" \
    "systemctl is-active fail2ban >/dev/null 2>&1" 7 \
    "Activar fail2ban"

score "REDES" "IP forwarding deshabilitado" \
    "test \$(sysctl -n net.ipv4.ip_forward 2>/dev/null) -eq 0" 5 \
    "Deshabilitar IP forwarding si no es necesario"

score "REDES" "IAP templates disponibles" \
    "test -d /etc/securizar/iap" 5 \
    "Desplegar templates de Identity-Aware Proxy"

# ══════════════════════════════════════════════════════════════
# PILAR 4: APLICACIONES
# ══════════════════════════════════════════════════════════════
log_head "══════════════════════════════════════════════"
log_head "  PILAR 4: APLICACIONES"
log_head "══════════════════════════════════════════════"

log_a "\n  ${BOLD}4.1 Control de acceso mandatorio${NC}"
score "APLICACIONES" "AppArmor o SELinux activo" \
    "command -v aa-status >/dev/null 2>&1 && aa-status 2>/dev/null | grep -q 'profiles are loaded' || getenforce 2>/dev/null | grep -qi enforcing" 15 \
    "Activar AppArmor o SELinux en modo enforce"

score "APLICACIONES" "Seccomp disponible" \
    "grep -q SECCOMP /proc/self/status 2>/dev/null" 5 \
    "Verificar soporte de Seccomp en kernel"

log_a "\n  ${BOLD}4.2 Minimo privilegio${NC}"
score "APLICACIONES" "Sin ejecutables world-writable en /usr" \
    "test \$(find /usr/bin /usr/sbin -perm -o+w -type f 2>/dev/null | head -3 | wc -l) -eq 0" 10 \
    "Corregir permisos de ejecutables world-writable"

score "APLICACIONES" "Cuentas de servicio con nologin" \
    "test \$(awk -F: '\$3>0 && \$3<1000 && \$7!~/nologin/ && \$7!~/false/' /etc/passwd 2>/dev/null | wc -l) -lt 3" 10 \
    "Cambiar shell de cuentas de servicio a /sbin/nologin"

score "APLICACIONES" "Auditor de privilegios disponible" \
    "test -x /usr/local/bin/auditar-privilegios-zt.sh" 5 \
    "Desplegar auditar-privilegios-zt.sh"

log_a "\n  ${BOLD}4.3 Integridad y verificacion${NC}"
score "APLICACIONES" "Verificacion de firmas de paquetes" \
    "grep -qsE '^\s*gpgcheck\s*=\s*1' /etc/yum.conf /etc/dnf/dnf.conf 2>/dev/null || grep -qsE 'repo_gpgcheck' /etc/zypp/zypp.conf 2>/dev/null || test -d /etc/apt/trusted.gpg.d" 10 \
    "Habilitar verificacion de firmas de paquetes"

score "APLICACIONES" "Reglas auditd para binarios sensibles" \
    "auditctl -l 2>/dev/null | grep -qE 'passwd|useradd|execve'" 8 \
    "Configurar reglas auditd para monitoreo de binarios"

score "APLICACIONES" "Application whitelisting (fapolicyd)" \
    "command -v fapolicyd >/dev/null 2>&1 || test -f /etc/fapolicyd/fapolicyd.conf" 7 \
    "Considerar fapolicyd para application whitelisting"

# ══════════════════════════════════════════════════════════════
# PILAR 5: DATOS
# ══════════════════════════════════════════════════════════════
log_head "══════════════════════════════════════════════"
log_head "  PILAR 5: DATOS"
log_head "══════════════════════════════════════════════"

log_a "\n  ${BOLD}5.1 Cifrado${NC}"
score "DATOS" "Cifrado en reposo (LUKS)" \
    "lsblk -o TYPE 2>/dev/null | grep -q crypt || dmsetup ls --target crypt 2>/dev/null | grep -q ." 15 \
    "Implementar cifrado de disco"

score "DATOS" "GPG/Age disponible para cifrado de archivos" \
    "command -v gpg >/dev/null 2>&1 || command -v age >/dev/null 2>&1" 5 \
    "Instalar GPG o age para cifrado de archivos"

log_a "\n  ${BOLD}5.2 Proteccion de datos${NC}"
score "DATOS" "Permisos de /etc/shadow restrictivos" \
    "test \$(stat -c %a /etc/shadow 2>/dev/null) -le 640" 10 \
    "chmod 640 /etc/shadow"

score "DATOS" "Umask restrictivo (027/077)" \
    "grep -qsE 'umask\s+(027|077)' /etc/profile /etc/bashrc /etc/login.defs 2>/dev/null" 8 \
    "Configurar umask 027 o 077"

score "DATOS" "/tmp montado con noexec" \
    "mount 2>/dev/null | grep '/tmp' | grep -q noexec" 8 \
    "Montar /tmp con opciones noexec,nosuid,nodev"

score "DATOS" "Politica Zero Trust configurada" \
    "test -f /etc/securizar/zero-trust-policy.conf" 5 \
    "Crear politica en /etc/securizar/zero-trust-policy.conf"

log_a "\n  ${BOLD}5.3 Logging e integridad${NC}"
score "DATOS" "Journald con Seal (integridad)" \
    "grep -qsE '^\s*Seal=yes' /etc/systemd/journald.conf" 8 \
    "Configurar Seal=yes en journald.conf"

score "DATOS" "Syslog remoto configurado" \
    "grep -rqs '@.*:514\|@@' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null" 8 \
    "Configurar envio de logs a servidor remoto"

score "DATOS" "Grabacion de sesiones disponible" \
    "test -x /usr/local/bin/grabar-sesion-privilegiada.sh" 5 \
    "Desplegar grabar-sesion-privilegiada.sh"

score "DATOS" "Reglas auditd Zero Trust" \
    "test -f /etc/audit/rules.d/99-zero-trust-sessions.rules 2>/dev/null" 5 \
    "Configurar reglas auditd para Zero Trust"

log_a "\n  ${BOLD}5.4 Clasificacion y DLP${NC}"
score "DATOS" "Politica de clasificacion de datos" \
    "test -f /etc/securizar/data-classification.conf || test -f /etc/securizar/zero-trust-policy.conf" 5 \
    "Crear politica de clasificacion de datos"

score "DATOS" "Herramientas DLP/compliance" \
    "command -v oscap >/dev/null 2>&1 || command -v openscap >/dev/null 2>&1 || test -f /etc/securizar/dlp-rules.conf" 5 \
    "Instalar OpenSCAP o configurar reglas DLP"

# ══════════════════════════════════════════════════════════════
# NIST SP 800-207 GAP ANALYSIS
# ══════════════════════════════════════════════════════════════
log_head "══════════════════════════════════════════════"
log_head "  GAP ANALYSIS - NIST SP 800-207"
log_head "══════════════════════════════════════════════"

log_a ""
log_a "  Referencia: NIST Special Publication 800-207"
log_a "  'Zero Trust Architecture' (Agosto 2020)"
log_a ""

# NIST 800-207 core tenets check
NIST_CHECKS=(
    "Todas las fuentes de datos y servicios de computacion se consideran recursos"
    "Toda comunicacion esta asegurada independientemente de la ubicacion de red"
    "El acceso a recursos individuales se concede por sesion"
    "El acceso a recursos se determina por politica dinamica"
    "La integridad y postura de seguridad de todos los activos se monitorea"
    "Autenticacion y autorizacion de recursos son dinamicas y estrictamente aplicadas"
    "La empresa recolecta informacion sobre el estado actual de la infraestructura"
)

NIST_RESULTS=(
    "test -f /etc/securizar/device-inventory.conf"
    "openssl version 2>/dev/null | grep -qE '1\.[1-9]|3\.[0-9]'"
    "grep -rqsE 'timestamp_timeout\s*=\s*[0-5]' /etc/sudoers /etc/sudoers.d/ 2>/dev/null"
    "test -f /etc/securizar/zero-trust-policy.conf"
    "test -x /usr/local/bin/verificar-device-trust.sh"
    "grep -rqs 'pam_google_authenticator\|pam_u2f\|pam_sss' /etc/pam.d/"
    "systemctl is-active auditd >/dev/null 2>&1"
)

NIST_PASS=0
NIST_TOTAL=${#NIST_CHECKS[@]}

for i in "${!NIST_CHECKS[@]}"; do
    if eval "${NIST_RESULTS[$i]}" 2>/dev/null; then
        log_ok "Tenet $((i+1)): ${NIST_CHECKS[$i]}"
        NIST_PASS=$((NIST_PASS + 1))
    else
        log_no "Tenet $((i+1)): ${NIST_CHECKS[$i]}"
    fi
done

log_a ""
log_a "  Cumplimiento NIST 800-207: ${NIST_PASS}/${NIST_TOTAL} tenets"

# ══════════════════════════════════════════════════════════════
# CUMPLIMIENTO DE POLITICA LOCAL
# ══════════════════════════════════════════════════════════════
log_head "══════════════════════════════════════════════"
log_head "  CUMPLIMIENTO DE POLITICA ZERO TRUST LOCAL"
log_head "══════════════════════════════════════════════"

POLICY_VIOLATIONS=0
if [[ -f "$POLICY_FILE" ]]; then
    log_a "  Politica: $POLICY_FILE"

    # Check key policy settings
    while IFS= read -r pline; do
        pline="${pline#"${pline%%[![:space:]]*}"}"
        [[ -z "$pline" || "$pline" == \#* ]] && continue

        PKEY="${pline%%=*}"
        PVAL="${pline#*=}"

        case "$PKEY" in
            REQUIRE_MFA)
                if [[ "$PVAL" == "yes" ]]; then
                    if ! grep -rqs "pam_google_authenticator\|pam_u2f" /etc/pam.d/ 2>/dev/null; then
                        log_no "Politica REQUIRE_MFA=yes pero MFA no configurado"
                        POLICY_VIOLATIONS=$((POLICY_VIOLATIONS + 1))
                    else
                        log_ok "Politica REQUIRE_MFA=yes cumplida"
                    fi
                fi
                ;;
            REQUIRE_FIREWALL)
                if [[ "$PVAL" == "yes" ]]; then
                    if ! systemctl is-active firewalld >/dev/null 2>&1 && \
                       ! systemctl is-active ufw >/dev/null 2>&1 && \
                       ! systemctl is-active nftables >/dev/null 2>&1; then
                        log_no "Politica REQUIRE_FIREWALL=yes pero firewall no activo"
                        POLICY_VIOLATIONS=$((POLICY_VIOLATIONS + 1))
                    else
                        log_ok "Politica REQUIRE_FIREWALL=yes cumplida"
                    fi
                fi
                ;;
            REQUIRE_DISK_ENCRYPTION)
                if [[ "$PVAL" == "yes" ]]; then
                    if ! lsblk -o TYPE 2>/dev/null | grep -q crypt && ! dmsetup ls --target crypt 2>/dev/null | grep -q .; then
                        log_no "Politica REQUIRE_DISK_ENCRYPTION=yes pero cifrado no detectado"
                        POLICY_VIOLATIONS=$((POLICY_VIOLATIONS + 1))
                    else
                        log_ok "Politica REQUIRE_DISK_ENCRYPTION=yes cumplida"
                    fi
                fi
                ;;
            REQUIRE_MAC)
                if [[ "$PVAL" == "yes" ]]; then
                    if ! command -v aa-status >/dev/null 2>&1 && ! getenforce 2>/dev/null | grep -qi enforcing; then
                        log_no "Politica REQUIRE_MAC=yes pero AppArmor/SELinux no activo"
                        POLICY_VIOLATIONS=$((POLICY_VIOLATIONS + 1))
                    else
                        log_ok "Politica REQUIRE_MAC=yes cumplida"
                    fi
                fi
                ;;
            LEAST_PRIVILEGE)
                if [[ "$PVAL" == "enforce" ]]; then
                    if grep -rqsE '^\s*[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
                        log_no "Politica LEAST_PRIVILEGE=enforce pero hay NOPASSWD en sudoers"
                        POLICY_VIOLATIONS=$((POLICY_VIOLATIONS + 1))
                    else
                        log_ok "Politica LEAST_PRIVILEGE=enforce cumplida"
                    fi
                fi
                ;;
        esac
    done < "$POLICY_FILE"

    log_a ""
    log_a "  Violaciones de politica: $POLICY_VIOLATIONS"
else
    log_a "  ${YELLOW}No se encontro politica Zero Trust local${NC}"
    log_a "  Crear con: /usr/local/bin/aplicar-politica-zt.sh"
fi

# ══════════════════════════════════════════════════════════════
# RESUMEN FINAL
# ══════════════════════════════════════════════════════════════
log_head "══════════════════════════════════════════════"
log_head "  RESUMEN FINAL"
log_head "══════════════════════════════════════════════"

log_a ""
TOTAL_SCORE=0
TOTAL_MAX=0

for p in "${PILLAR_NAMES[@]}"; do
    PSCORE=${PILLAR_SCORES[$p]}
    PMAX=${PILLAR_MAX[$p]}
    TOTAL_SCORE=$((TOTAL_SCORE + PSCORE))
    TOTAL_MAX=$((TOTAL_MAX + PMAX))

    if [[ $PMAX -gt 0 ]]; then
        PCT=$((PSCORE * 100 / PMAX))
    else
        PCT=0
    fi

    # Color by score
    if [[ $PCT -ge 70 ]]; then
        COLOR="$GREEN"
    elif [[ $PCT -ge 40 ]]; then
        COLOR="$YELLOW"
    else
        COLOR="$RED"
    fi

    # Bar chart
    BAR_LEN=$((PCT / 5))
    BAR=""
    for ((b=0; b<BAR_LEN; b++)); do BAR+="█"; done
    for ((b=BAR_LEN; b<20; b++)); do BAR+="░"; done

    log_a "  $(printf '%-15s' "$p") ${COLOR}${BAR}${NC} ${PSCORE}/${PMAX} (${PCT}%)"
done

log_a ""
if [[ $TOTAL_MAX -gt 0 ]]; then
    OVERALL_PCT=$((TOTAL_SCORE * 100 / TOTAL_MAX))
else
    OVERALL_PCT=0
fi

log_a "  ──────────────────────────────────────────"
log_a "  ${BOLD}TOTAL: ${TOTAL_SCORE}/${TOTAL_MAX} (${OVERALL_PCT}%)${NC}"
log_a ""

# Final verdict
if [[ $OVERALL_PCT -ge 70 ]]; then
    VERDICT="BUENO"
    VCOLOR="$GREEN"
    VDESC="Postura Zero Trust solida. Continuar mejorando areas identificadas."
elif [[ $OVERALL_PCT -ge 40 ]]; then
    VERDICT="MEJORABLE"
    VCOLOR="$YELLOW"
    VDESC="Postura Zero Trust en desarrollo. Se requieren mejoras en varios pilares."
else
    VERDICT="DEFICIENTE"
    VCOLOR="$RED"
    VDESC="Postura Zero Trust insuficiente. Se requieren acciones urgentes."
fi

log_a "  ${VCOLOR}${BOLD}╔══════════════════════════════════════════╗${NC}"
log_a "  ${VCOLOR}${BOLD}║  CALIFICACION: ${VERDICT}$(printf '%*s' $((20 - ${#VERDICT})) '')    ║${NC}"
log_a "  ${VCOLOR}${BOLD}╚══════════════════════════════════════════╝${NC}"
log_a ""
log_a "  $VDESC"

# ══════════════════════════════════════════════════════════════
# ROADMAP DE RECOMENDACIONES
# ══════════════════════════════════════════════════════════════
if [[ ${#GAPS[@]} -gt 0 ]]; then
    log_head "══════════════════════════════════════════════"
    log_head "  ROADMAP DE RECOMENDACIONES"
    log_head "══════════════════════════════════════════════"

    log_a ""
    log_a "  ${BOLD}Prioridad Alta (implementar inmediatamente):${NC}"
    IDX=1
    for gap in "${GAPS[@]}"; do
        if echo "$gap" | grep -qiE "IDENTIDAD.*MFA|IDENTIDAD.*root|DISPOSITIVOS.*cifrado|DISPOSITIVOS.*firewall"; then
            log_a "    ${IDX}. $gap"
            IDX=$((IDX + 1))
        fi
    done

    log_a ""
    log_a "  ${BOLD}Prioridad Media (implementar en 30 dias):${NC}"
    for gap in "${GAPS[@]}"; do
        if echo "$gap" | grep -qiE "REDES|APLICACIONES.*MAC|DATOS.*cifrado"; then
            log_a "    ${IDX}. $gap"
            IDX=$((IDX + 1))
        fi
    done

    log_a ""
    log_a "  ${BOLD}Prioridad Baja (implementar en 90 dias):${NC}"
    for gap in "${GAPS[@]}"; do
        if echo "$gap" | grep -qiE "disponible|template|clasificacion|DLP"; then
            log_a "    ${IDX}. $gap"
            IDX=$((IDX + 1))
        fi
    done
fi

# ══════════════════════════════════════════════════════════════
# HERRAMIENTAS ZERO TRUST DESPLEGADAS
# ══════════════════════════════════════════════════════════════
log_head "══════════════════════════════════════════════"
log_head "  HERRAMIENTAS ZERO TRUST DESPLEGADAS"
log_head "══════════════════════════════════════════════"
log_a ""

ZT_TOOLS=(
    "/usr/local/bin/evaluar-zero-trust.sh|Evaluacion de madurez ZT"
    "/usr/local/bin/aplicar-politica-zt.sh|Aplicacion de politica ZT"
    "/usr/local/bin/auth-continua.sh|Autenticacion continua"
    "/usr/local/bin/verificar-device-trust.sh|Verificacion de dispositivos"
    "/usr/local/bin/configurar-iap.sh|Configuracion IAP"
    "/usr/local/bin/segmentar-por-identidad.sh|Micro-segmentacion"
    "/usr/local/bin/auditar-privilegios-zt.sh|Auditoria de privilegios"
    "/usr/local/bin/gestionar-sesiones-zt.sh|Gestion de sesiones"
    "/usr/local/bin/grabar-sesion-privilegiada.sh|Grabacion de sesiones"
    "/usr/local/bin/verificar-sso-mfa.sh|Verificacion SSO/MFA"
    "/usr/local/bin/auditoria-zero-trust.sh|Auditoria integral ZT"
)

for tool_entry in "${ZT_TOOLS[@]}"; do
    TOOL_PATH="${tool_entry%%|*}"
    TOOL_DESC="${tool_entry#*|}"
    if [[ -x "$TOOL_PATH" ]]; then
        log_a "  ${GREEN}[+]${NC} $(basename "$TOOL_PATH") - $TOOL_DESC"
    else
        log_a "  ${RED}[-]${NC} $(basename "$TOOL_PATH") - $TOOL_DESC (no desplegado)"
    fi
done

log_a ""
log_a "================================================================"
log_a "  Reporte guardado en: ${REPORT}"
log_a "================================================================"

ENDSCRIPT

    log_change "Creado" "/usr/local/bin/auditoria-zero-trust.sh - auditoria integral Zero Trust"

    # ── Cron weekly ──────────────────────────────────────────
    CRON_ZT="/etc/cron.weekly/auditoria-zero-trust"
    if [[ -d /etc/cron.weekly ]]; then
        cat > "$CRON_ZT" << 'CRONEOF'
#!/bin/bash
# Auditoria semanal Zero Trust (generado por securizar)
/usr/local/bin/auditoria-zero-trust.sh > /dev/null 2>&1

# Limpieza de reportes antiguos (>90 dias)
find /var/log/securizar -name "auditoria-zt-*.log" -mtime +90 -delete 2>/dev/null || true
find /var/log/securizar -name "evaluacion-zt-*.log" -mtime +90 -delete 2>/dev/null || true
find /var/log/securizar -name "device-trust-*.log" -mtime +90 -delete 2>/dev/null || true
CRONEOF
        chmod 0755 "$CRON_ZT"
        log_change "Creado" "$CRON_ZT - auditoria semanal Zero Trust via cron"
    else
        log_skip "Cron weekly (directorio no existe)"
    fi
else
    log_skip "Auditoria integral Zero Trust"
fi

###############################################################################
# FIN
###############################################################################
log_section "MODULO 59: ZERO TRUST IDENTITY - COMPLETADO"

log_info "Herramientas Zero Trust desplegadas en /usr/local/bin/"
log_info "Configuracion en /etc/securizar/"
log_info "Logs y reportes en /var/log/securizar/"
log_info ""
log_info "Herramientas principales:"
log_info "  evaluar-zero-trust.sh       - Evaluar madurez Zero Trust"
log_info "  aplicar-politica-zt.sh      - Verificar cumplimiento de politica"
log_info "  auth-continua.sh            - Monitor de autenticacion continua"
log_info "  verificar-device-trust.sh   - Verificar confianza de dispositivos"
log_info "  configurar-iap.sh           - Configurar Identity-Aware Proxy"
log_info "  segmentar-por-identidad.sh  - Micro-segmentacion por identidad"
log_info "  auditar-privilegios-zt.sh   - Auditoria de minimo privilegio"
log_info "  gestionar-sesiones-zt.sh    - Gestion de sesiones"
log_info "  grabar-sesion-privilegiada.sh - Grabar sesiones privilegiadas"
log_info "  verificar-sso-mfa.sh        - Verificar SSO y MFA"
log_info "  auditoria-zero-trust.sh     - Auditoria integral semanal"

show_changes_summary
