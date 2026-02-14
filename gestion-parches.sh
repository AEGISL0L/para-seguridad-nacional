#!/bin/bash
# ============================================================
# gestion-parches.sh - Modulo 61: Gestion de Parches y Vulnerabilidades
# ============================================================
# Secciones:
#   S1  - Configuracion de actualizaciones automaticas
#   S2  - Escaneo de vulnerabilidades CVE
#   S3  - SBOM (Software Bill of Materials)
#   S4  - Staging y testing de parches
#   S5  - Monitoreo de advisories de seguridad
#   S6  - Dependency vulnerability scanning
#   S7  - Kernel vulnerability assessment
#   S8  - Patch compliance reporting
#   S9  - Emergency patch procedures
#   S10 - Auditoria integral de gestion de parches
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps
init_backup "patch-management"

# ── Pre-check: detectar secciones ya aplicadas ──────────────
_precheck 10
_pc 'check_file_exists /etc/securizar/patch-policy.conf'
_pc 'check_executable /usr/local/bin/escanear-cves.sh'
_pc 'check_executable /usr/local/bin/generar-sbom.sh'
_pc 'check_executable /usr/local/bin/securizar-patch-test.sh'
_pc 'check_executable /usr/local/bin/monitorear-advisories.sh'
_pc 'check_executable /usr/local/bin/escanear-dependencias.sh'
_pc 'check_executable /usr/local/bin/evaluar-kernel-vulns.sh'
_pc 'check_executable /usr/local/bin/reporte-compliance-parches.sh'
_pc 'check_executable /usr/local/bin/parche-emergencia.sh'
_pc 'check_executable /usr/local/bin/auditar-parches.sh'
_precheck_result

log_section "MODULO 61: GESTION DE PARCHES Y VULNERABILIDADES"
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

PATCH_DIR="/etc/securizar"
PATCH_BIN="/usr/local/bin"
PATCH_LIB="/var/lib/securizar"
PATCH_LOG="/var/log/securizar"

mkdir -p "$PATCH_DIR" "$PATCH_LIB/sbom" "$PATCH_LIB/patches" "$PATCH_LOG" || true

# ============================================================
# S1 - Configuracion de actualizaciones automaticas
# ============================================================
log_section "S1: Configuracion de actualizaciones automaticas"
log_info "Crea politica de parches y timer systemd para aplicar actualizaciones de seguridad automaticamente."

if check_file_exists /etc/securizar/patch-policy.conf; then
    log_already "Actualizaciones automaticas (patch-policy.conf existe)"
elif ask "Configurar actualizaciones automaticas de seguridad?"; then

    # --- Patch policy config ---
    backup_if_exists "$PATCH_DIR/patch-policy.conf"
    cat > "$PATCH_DIR/patch-policy.conf" << 'EOF'
# ============================================================
# patch-policy.conf - Politica de gestion de parches
# ============================================================
# Generado por securizar - Modulo 61

# Ventana de mantenimiento (formato cron-like para systemd)
PATCH_WINDOW_DAY="Sun"
PATCH_WINDOW_HOUR="03"
PATCH_WINDOW_MINUTE="00"

# Tipos de parches a aplicar automaticamente
AUTO_SECURITY_PATCHES="yes"
AUTO_BUGFIX_PATCHES="no"
AUTO_FEATURE_PATCHES="no"

# Reinicio automatico si es necesario
AUTO_REBOOT="no"
AUTO_REBOOT_DELAY="300"

# Notificaciones
NOTIFY_EMAIL=""
NOTIFY_ON_SUCCESS="yes"
NOTIFY_ON_FAILURE="yes"

# Retries
MAX_RETRIES="3"
RETRY_DELAY="60"

# Exclusiones (paquetes separados por coma)
EXCLUDE_PACKAGES=""

# Logs
LOG_DIR="/var/log/securizar"
LOG_RETENTION_DAYS="90"

# Staging
STAGING_ENABLED="no"
STAGING_DELAY_HOURS="24"

# Rollback
ROLLBACK_ENABLED="yes"
SNAPSHOT_BEFORE_PATCH="yes"
EOF
    chmod 0640 "$PATCH_DIR/patch-policy.conf"
    log_change "Creado" "politica de parches en $PATCH_DIR/patch-policy.conf"

    # --- Auto-patch script ---
    cat > "$PATCH_BIN/securizar-auto-patch.sh" << 'EOF'
#!/bin/bash
# securizar-auto-patch.sh - Aplica parches de seguridad automaticamente
set -euo pipefail

CONF="/etc/securizar/patch-policy.conf"
LOG_DIR="/var/log/securizar"
LOGFILE="$LOG_DIR/auto-patch-$(date +%Y%m%d-%H%M%S).log"

mkdir -p "$LOG_DIR"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGFILE"; }

if [[ -f "$CONF" ]]; then
    # shellcheck disable=SC1090
    source "$CONF"
else
    log "ERROR: No se encontro $CONF"
    exit 1
fi

log "=== Inicio de actualizacion automatica de seguridad ==="

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        case "$ID" in
            opensuse*|sles|suse) echo "suse" ;;
            debian|ubuntu|linuxmint) echo "debian" ;;
            rhel|centos|fedora|rocky|alma) echo "rhel" ;;
            arch|manjaro) echo "arch" ;;
            *) echo "unknown" ;;
        esac
    else
        echo "unknown"
    fi
}

FAMILY=$(detect_distro)
RETVAL=0

apply_patches() {
    case "$FAMILY" in
        suse)
            log "Aplicando parches de seguridad (zypper)..."
            zypper --non-interactive patch --category security 2>&1 | tee -a "$LOGFILE" || RETVAL=$?
            ;;
        debian)
            log "Aplicando parches de seguridad (apt)..."
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq 2>&1 | tee -a "$LOGFILE" || true
            apt-get upgrade -y -o Dpkg::Options::="--force-confold" --only-upgrade 2>&1 | tee -a "$LOGFILE" || RETVAL=$?
            ;;
        rhel)
            log "Aplicando parches de seguridad (yum/dnf)..."
            if command -v dnf &>/dev/null; then
                dnf upgrade --security -y 2>&1 | tee -a "$LOGFILE" || RETVAL=$?
            else
                yum update --security -y 2>&1 | tee -a "$LOGFILE" || RETVAL=$?
            fi
            ;;
        arch)
            log "Aplicando actualizaciones (pacman)..."
            pacman -Syu --noconfirm 2>&1 | tee -a "$LOGFILE" || RETVAL=$?
            ;;
        *)
            log "ERROR: Distro no soportada"
            exit 1
            ;;
    esac
    return $RETVAL
}

check_reboot_needed() {
    if [[ -f /var/run/reboot-required ]]; then
        return 0
    fi
    if command -v needs-restarting &>/dev/null; then
        needs-restarting -r &>/dev/null || return 0
    fi
    if [[ -f /boot/vmlinuz ]] && [[ "$(readlink -f /boot/vmlinuz)" != *"$(uname -r)"* ]]; then
        return 0
    fi
    return 1
}

# Record pre-patch state
log "Guardando estado pre-parche..."
case "$FAMILY" in
    suse)   rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' | sort > "$LOG_DIR/pre-patch-packages.txt" 2>/dev/null || true ;;
    debian) dpkg -l | awk '/^ii/{print $2"="$3}' | sort > "$LOG_DIR/pre-patch-packages.txt" 2>/dev/null || true ;;
    rhel)   rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' | sort > "$LOG_DIR/pre-patch-packages.txt" 2>/dev/null || true ;;
    arch)   pacman -Q | sort > "$LOG_DIR/pre-patch-packages.txt" 2>/dev/null || true ;;
esac

apply_patches
RC=$?

# Record post-patch state
case "$FAMILY" in
    suse)   rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' | sort > "$LOG_DIR/post-patch-packages.txt" 2>/dev/null || true ;;
    debian) dpkg -l | awk '/^ii/{print $2"="$3}' | sort > "$LOG_DIR/post-patch-packages.txt" 2>/dev/null || true ;;
    rhel)   rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' | sort > "$LOG_DIR/post-patch-packages.txt" 2>/dev/null || true ;;
    arch)   pacman -Q | sort > "$LOG_DIR/post-patch-packages.txt" 2>/dev/null || true ;;
esac

# Diff
if [[ -f "$LOG_DIR/pre-patch-packages.txt" ]] && [[ -f "$LOG_DIR/post-patch-packages.txt" ]]; then
    UPDATED=$(diff "$LOG_DIR/pre-patch-packages.txt" "$LOG_DIR/post-patch-packages.txt" | grep '^>' | wc -l || true)
    log "Paquetes actualizados: $UPDATED"
fi

if [[ "$RC" -eq 0 ]]; then
    log "=== Actualizacion completada exitosamente ==="
else
    log "=== Actualizacion completada con errores (rc=$RC) ==="
fi

if [[ "${AUTO_REBOOT:-no}" == "yes" ]]; then
    if check_reboot_needed; then
        log "Reinicio requerido. Programando en ${AUTO_REBOOT_DELAY:-300} segundos..."
        shutdown -r +"$(( ${AUTO_REBOOT_DELAY:-300} / 60 ))" "Reinicio por actualizacion de seguridad" || true
    fi
fi

exit $RC
EOF
    chmod 0750 "$PATCH_BIN/securizar-auto-patch.sh"
    log_change "Creado" "script de auto-parcheo en $PATCH_BIN/securizar-auto-patch.sh"

    # --- Systemd service ---
    cat > /etc/systemd/system/securizar-auto-patch.service << 'EOF'
[Unit]
Description=Securizar - Actualizacion automatica de parches de seguridad
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/securizar-auto-patch.sh
StandardOutput=journal
StandardError=journal
TimeoutStartSec=3600
EOF
    log_change "Creado" "servicio systemd securizar-auto-patch.service"

    # --- Systemd timer ---
    cat > /etc/systemd/system/securizar-auto-patch.timer << 'EOF'
[Unit]
Description=Securizar - Timer semanal para parches de seguridad

[Timer]
OnCalendar=Sun *-*-* 03:00:00
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
EOF
    log_change "Creado" "timer systemd securizar-auto-patch.timer"

    systemctl daemon-reload || true
    systemctl enable securizar-auto-patch.timer 2>/dev/null || true
    log_change "Habilitado" "timer securizar-auto-patch.timer"

else
    log_skip "Configuracion de actualizaciones automaticas"
fi

# ============================================================
# S2 - Escaneo de vulnerabilidades CVE
# ============================================================
log_section "S2: Escaneo de vulnerabilidades CVE"
log_info "Crea script que escanea paquetes instalados en busca de CVEs pendientes usando herramientas nativas."

if check_executable /usr/local/bin/escanear-cves.sh; then
    log_already "Escaner de vulnerabilidades CVE (escanear-cves.sh existe)"
elif ask "Instalar escaner de vulnerabilidades CVE?"; then

    cat > "$PATCH_BIN/escanear-cves.sh" << 'EOF'
#!/bin/bash
# escanear-cves.sh - Escanea vulnerabilidades CVE en paquetes instalados
set -euo pipefail

REPORT_DIR="/var/lib/securizar/cve-reports"
mkdir -p "$REPORT_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT="$REPORT_DIR/cve-scan-$TIMESTAMP.txt"
JSON_REPORT="$REPORT_DIR/cve-scan-$TIMESTAMP.json"

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        case "$ID" in
            opensuse*|sles|suse) echo "suse" ;;
            debian|ubuntu|linuxmint) echo "debian" ;;
            rhel|centos|fedora|rocky|alma) echo "rhel" ;;
            arch|manjaro) echo "arch" ;;
            *) echo "unknown" ;;
        esac
    else
        echo "unknown"
    fi
}

FAMILY=$(detect_distro)
TOTAL_CVES=0
CRITICAL=0
HIGH=0
MEDIUM=0
LOW=0

echo "============================================" | tee "$REPORT"
echo " Escaneo de Vulnerabilidades CVE" | tee -a "$REPORT"
echo " Fecha: $(date)" | tee -a "$REPORT"
echo " Host: $(hostname)" | tee -a "$REPORT"
echo " Kernel: $(uname -r)" | tee -a "$REPORT"
echo "============================================" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

case "$FAMILY" in
    suse)
        echo "[*] Consultando parches de seguridad pendientes (zypper)..." | tee -a "$REPORT"
        echo "" | tee -a "$REPORT"

        if zypper --non-interactive list-patches --category security 2>/dev/null | tee -a "$REPORT"; then
            TOTAL_CVES=$(zypper --non-interactive list-patches --category security 2>/dev/null | grep -c '|' || true)
            CRITICAL=$(zypper --non-interactive list-patches --category security 2>/dev/null | grep -ci 'critical' || true)
            HIGH=$(zypper --non-interactive list-patches --category security 2>/dev/null | grep -ci 'important' || true)
        fi

        echo "" | tee -a "$REPORT"
        echo "[*] CVEs conocidos en parches pendientes:" | tee -a "$REPORT"
        zypper --non-interactive list-patches --cve 2>/dev/null | tee -a "$REPORT" || true
        ;;

    debian)
        echo "[*] Consultando vulnerabilidades (debsecan/apt)..." | tee -a "$REPORT"
        echo "" | tee -a "$REPORT"

        if command -v debsecan &>/dev/null; then
            echo "--- debsecan output ---" | tee -a "$REPORT"
            debsecan 2>/dev/null | tee -a "$REPORT" || true
            TOTAL_CVES=$(debsecan 2>/dev/null | wc -l || true)
            CRITICAL=$(debsecan --suite "$(lsb_release -cs 2>/dev/null || echo stable)" 2>/dev/null | grep -ci 'high urgency' || true)
        else
            echo "[!] debsecan no instalado. Usando apt..." | tee -a "$REPORT"
            apt-get update -qq 2>/dev/null || true
            apt list --upgradable 2>/dev/null | tee -a "$REPORT" || true
            TOTAL_CVES=$(apt list --upgradable 2>/dev/null | grep -c 'security' || true)
        fi

        echo "" | tee -a "$REPORT"
        echo "[*] Paquetes con actualizaciones de seguridad:" | tee -a "$REPORT"
        apt-get -s upgrade 2>/dev/null | grep -i 'security' | tee -a "$REPORT" || true
        ;;

    rhel)
        echo "[*] Consultando advisories de seguridad (yum/dnf)..." | tee -a "$REPORT"
        echo "" | tee -a "$REPORT"

        if command -v dnf &>/dev/null; then
            echo "--- dnf updateinfo ---" | tee -a "$REPORT"
            dnf updateinfo list security 2>/dev/null | tee -a "$REPORT" || true
            TOTAL_CVES=$(dnf updateinfo list security 2>/dev/null | grep -c 'CVE' || true)
            CRITICAL=$(dnf updateinfo list security --severity Critical 2>/dev/null | wc -l || true)
            HIGH=$(dnf updateinfo list security --severity Important 2>/dev/null | wc -l || true)

            echo "" | tee -a "$REPORT"
            echo "[*] Resumen de advisories:" | tee -a "$REPORT"
            dnf updateinfo summary 2>/dev/null | tee -a "$REPORT" || true
        else
            echo "--- yum updateinfo ---" | tee -a "$REPORT"
            yum updateinfo list security 2>/dev/null | tee -a "$REPORT" || true
            TOTAL_CVES=$(yum updateinfo list security 2>/dev/null | grep -c 'CVE' || true)
        fi
        ;;

    arch)
        echo "[*] Consultando paquetes desactualizados (arch-audit/pacman)..." | tee -a "$REPORT"
        echo "" | tee -a "$REPORT"

        if command -v arch-audit &>/dev/null; then
            echo "--- arch-audit ---" | tee -a "$REPORT"
            arch-audit 2>/dev/null | tee -a "$REPORT" || true
            TOTAL_CVES=$(arch-audit 2>/dev/null | wc -l || true)
            CRITICAL=$(arch-audit 2>/dev/null | grep -ci 'critical' || true)
            HIGH=$(arch-audit 2>/dev/null | grep -ci 'high' || true)
        else
            echo "[!] arch-audit no disponible. Verificando actualizaciones..." | tee -a "$REPORT"
            checkupdates 2>/dev/null | tee -a "$REPORT" || true
            TOTAL_CVES=$(checkupdates 2>/dev/null | wc -l || true)
        fi
        ;;

    *)
        echo "[!] Distribucion no soportada para escaneo CVE" | tee -a "$REPORT"
        ;;
esac

echo "" | tee -a "$REPORT"
echo "============================================" | tee -a "$REPORT"
echo " RESUMEN" | tee -a "$REPORT"
echo "============================================" | tee -a "$REPORT"
echo "  Total vulnerabilidades encontradas: $TOTAL_CVES" | tee -a "$REPORT"
echo "  Criticas: $CRITICAL" | tee -a "$REPORT"
echo "  Altas: $HIGH" | tee -a "$REPORT"
echo "  Medias: $MEDIUM" | tee -a "$REPORT"
echo "  Bajas: $LOW" | tee -a "$REPORT"
echo "============================================" | tee -a "$REPORT"

# JSON report
cat > "$JSON_REPORT" << JSONEOF
{
  "scan_date": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "kernel": "$(uname -r)",
  "distro_family": "$FAMILY",
  "summary": {
    "total": $TOTAL_CVES,
    "critical": $CRITICAL,
    "high": $HIGH,
    "medium": $MEDIUM,
    "low": $LOW
  },
  "report_file": "$REPORT"
}
JSONEOF

echo ""
echo "Reportes guardados en:"
echo "  Texto: $REPORT"
echo "  JSON:  $JSON_REPORT"
EOF
    chmod 0750 "$PATCH_BIN/escanear-cves.sh"
    log_change "Creado" "escaner CVE en $PATCH_BIN/escanear-cves.sh"

    # Install debsecan on Debian
    case "$DISTRO_FAMILY" in
        debian)
            pkg_install debsecan || true
            log_change "Instalado" "debsecan para escaneo de vulnerabilidades Debian"
            ;;
        arch)
            pkg_install arch-audit || true
            log_change "Instalado" "arch-audit para escaneo de vulnerabilidades Arch"
            ;;
    esac

else
    log_skip "Escaneo de vulnerabilidades CVE"
fi

# ============================================================
# S3 - SBOM (Software Bill of Materials)
# ============================================================
log_section "S3: SBOM (Software Bill of Materials)"
log_info "Genera inventario completo de software instalado en formato JSON estandarizado."

if check_executable /usr/local/bin/generar-sbom.sh; then
    log_already "Generacion de SBOM (generar-sbom.sh existe)"
elif ask "Configurar generacion de SBOM?"; then

    cat > "$PATCH_BIN/generar-sbom.sh" << 'EOF'
#!/bin/bash
# generar-sbom.sh - Genera Software Bill of Materials en formato JSON
set -euo pipefail

SBOM_DIR="/var/lib/securizar/sbom"
mkdir -p "$SBOM_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
SBOM_FILE="$SBOM_DIR/sbom-$TIMESTAMP.json"

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        case "$ID" in
            opensuse*|sles|suse) echo "suse" ;;
            debian|ubuntu|linuxmint) echo "debian" ;;
            rhel|centos|fedora|rocky|alma) echo "rhel" ;;
            arch|manjaro) echo "arch" ;;
            *) echo "unknown" ;;
        esac
    else
        echo "unknown"
    fi
}

FAMILY=$(detect_distro)

echo "[*] Generando SBOM para $(hostname)..."
echo "[*] Familia de distro: $FAMILY"

# Start JSON
cat > "$SBOM_FILE" << HEADEREOF
{
  "sbom_version": "1.0",
  "generated_at": "$(date -Iseconds)",
  "generator": "securizar-sbom",
  "hostname": "$(hostname)",
  "kernel": "$(uname -r)",
  "architecture": "$(uname -m)",
  "os_family": "$FAMILY",
HEADEREOF

# OS info
if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    cat >> "$SBOM_FILE" << OSEOF
  "os_name": "${NAME:-unknown}",
  "os_version": "${VERSION_ID:-unknown}",
OSEOF
fi

echo '  "packages": [' >> "$SBOM_FILE"

TMPFILE=$(mktemp)
trap 'rm -f "$TMPFILE"' EXIT

case "$FAMILY" in
    suse|rhel)
        rpm -qa --qf '    {"name": "%{NAME}", "version": "%{VERSION}", "release": "%{RELEASE}", "arch": "%{ARCH}", "vendor": "%{VENDOR}", "install_date": "%{INSTALLTIME:date}"},\n' 2>/dev/null | sort > "$TMPFILE" || true
        ;;
    debian)
        dpkg-query -W -f '    {"name": "${Package}", "version": "${Version}", "arch": "${Architecture}", "status": "${Status}", "maintainer": "${Maintainer}"},\n' 2>/dev/null | sort > "$TMPFILE" || true
        ;;
    arch)
        pacman -Q 2>/dev/null | while IFS=' ' read -r pkg ver; do
            echo "    {\"name\": \"$pkg\", \"version\": \"$ver\"},"
        done | sort > "$TMPFILE" || true
        ;;
esac

# Remove trailing comma from last line
if [[ -s "$TMPFILE" ]]; then
    head -n -1 "$TMPFILE" >> "$SBOM_FILE"
    tail -1 "$TMPFILE" | sed 's/,$//' >> "$SBOM_FILE"
fi

echo '  ],' >> "$SBOM_FILE"

# Add system services
echo '  "services": [' >> "$SBOM_FILE"
SVCTMP=$(mktemp)
systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk '{print "    {\"name\": \""$1"\", \"state\": \"running\"},"}' | sort > "$SVCTMP" || true
if [[ -s "$SVCTMP" ]]; then
    head -n -1 "$SVCTMP" >> "$SBOM_FILE"
    tail -1 "$SVCTMP" | sed 's/,$//' >> "$SBOM_FILE"
fi
rm -f "$SVCTMP"

echo '  ],' >> "$SBOM_FILE"

# Package count
PKG_COUNT=0
case "$FAMILY" in
    suse|rhel) PKG_COUNT=$(rpm -qa 2>/dev/null | wc -l || true) ;;
    debian)    PKG_COUNT=$(dpkg -l 2>/dev/null | grep -c '^ii' || true) ;;
    arch)      PKG_COUNT=$(pacman -Q 2>/dev/null | wc -l || true) ;;
esac

cat >> "$SBOM_FILE" << FOOTEOF
  "summary": {
    "total_packages": $PKG_COUNT,
    "total_services": $(systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | wc -l || echo 0)
  }
}
FOOTEOF

echo "[*] SBOM generado: $SBOM_FILE"
echo "[*] Total paquetes: $PKG_COUNT"

# Symlink latest
ln -sf "$SBOM_FILE" "$SBOM_DIR/sbom-latest.json" || true

# Cleanup old SBOMs (keep last 30)
ls -1t "$SBOM_DIR"/sbom-2*.json 2>/dev/null | tail -n +31 | xargs rm -f 2>/dev/null || true

echo "[*] SBOM disponible en: $SBOM_DIR/sbom-latest.json"
EOF
    chmod 0750 "$PATCH_BIN/generar-sbom.sh"
    log_change "Creado" "generador SBOM en $PATCH_BIN/generar-sbom.sh"

    # Systemd timer for weekly SBOM generation
    cat > /etc/systemd/system/securizar-sbom.service << 'EOF'
[Unit]
Description=Securizar - Generacion semanal de SBOM
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/generar-sbom.sh
StandardOutput=journal
StandardError=journal
EOF

    cat > /etc/systemd/system/securizar-sbom.timer << 'EOF'
[Unit]
Description=Securizar - Timer semanal para SBOM

[Timer]
OnCalendar=Mon *-*-* 02:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload || true
    systemctl enable securizar-sbom.timer 2>/dev/null || true
    log_change "Habilitado" "timer semanal de generacion SBOM"

else
    log_skip "Generacion de SBOM"
fi

# ============================================================
# S4 - Staging y testing de parches
# ============================================================
log_section "S4: Staging y testing de parches"
log_info "Crea scripts para probar parches en modo staging y revertir si hay problemas."

if check_executable /usr/local/bin/securizar-patch-test.sh; then
    log_already "Staging y testing de parches (securizar-patch-test.sh existe)"
elif ask "Configurar staging y testing de parches?"; then

    # --- Patch test script ---
    cat > "$PATCH_BIN/securizar-patch-test.sh" << 'EOF'
#!/bin/bash
# securizar-patch-test.sh - Prueba parches en modo staging (dry-run + snapshot)
set -euo pipefail

STAGING_DIR="/var/lib/securizar/patches/staging"
LOG_DIR="/var/log/securizar"
mkdir -p "$STAGING_DIR" "$LOG_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
LOGFILE="$LOG_DIR/patch-test-$TIMESTAMP.log"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGFILE"; }

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        case "$ID" in
            opensuse*|sles|suse) echo "suse" ;;
            debian|ubuntu|linuxmint) echo "debian" ;;
            rhel|centos|fedora|rocky|alma) echo "rhel" ;;
            arch|manjaro) echo "arch" ;;
            *) echo "unknown" ;;
        esac
    else
        echo "unknown"
    fi
}

FAMILY=$(detect_distro)

usage() {
    echo "Uso: $0 [--dry-run|--apply|--status]"
    echo ""
    echo "Opciones:"
    echo "  --dry-run   Simular actualizacion sin aplicar cambios"
    echo "  --apply     Aplicar parches con snapshot previo"
    echo "  --status    Mostrar estado de parches pendientes"
    exit 1
}

MODE="${1:---dry-run}"

save_snapshot() {
    log "Guardando snapshot de paquetes..."
    local SNAP="$STAGING_DIR/snapshot-$TIMESTAMP.txt"
    case "$FAMILY" in
        suse|rhel) rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' | sort > "$SNAP" 2>/dev/null || true ;;
        debian)    dpkg -l | awk '/^ii/{print $2"="$3}' | sort > "$SNAP" 2>/dev/null || true ;;
        arch)      pacman -Q | sort > "$SNAP" 2>/dev/null || true ;;
    esac
    echo "$SNAP"
}

test_services() {
    log "Verificando servicios criticos post-parche..."
    local FAILED=0
    for svc in sshd systemd-journald systemd-networkd NetworkManager; do
        if systemctl is-active "$svc" &>/dev/null; then
            log "  [OK] $svc activo"
        elif systemctl is-enabled "$svc" &>/dev/null; then
            log "  [WARN] $svc habilitado pero no activo"
            FAILED=$((FAILED + 1))
        fi
    done

    # Test network
    if ping -c1 -W5 127.0.0.1 &>/dev/null; then
        log "  [OK] Red local funcional"
    else
        log "  [FAIL] Red local no responde"
        FAILED=$((FAILED + 1))
    fi

    # Test DNS
    if getent hosts localhost &>/dev/null; then
        log "  [OK] Resolucion DNS funcional"
    else
        log "  [WARN] Resolucion DNS con problemas"
    fi

    return $FAILED
}

case "$MODE" in
    --dry-run)
        log "=== MODO DRY-RUN: Simulando actualizacion ==="
        case "$FAMILY" in
            suse)
                log "Simulando parches (zypper)..."
                zypper --non-interactive patch --category security --dry-run 2>&1 | tee -a "$LOGFILE" || true
                ;;
            debian)
                log "Simulando actualizacion (apt)..."
                apt-get update -qq 2>/dev/null || true
                apt-get upgrade --simulate 2>&1 | tee -a "$LOGFILE" || true
                ;;
            rhel)
                log "Simulando actualizacion (dnf/yum)..."
                if command -v dnf &>/dev/null; then
                    dnf upgrade --security --assumeno 2>&1 | tee -a "$LOGFILE" || true
                else
                    yum update --security --assumeno 2>&1 | tee -a "$LOGFILE" || true
                fi
                ;;
            arch)
                log "Listando actualizaciones disponibles..."
                checkupdates 2>&1 | tee -a "$LOGFILE" || true
                ;;
        esac
        log "=== DRY-RUN completado. Revisar: $LOGFILE ==="
        ;;

    --apply)
        log "=== MODO APPLY: Aplicando parches con snapshot ==="
        SNAP=$(save_snapshot)
        log "Snapshot guardado: $SNAP"

        case "$FAMILY" in
            suse)
                zypper --non-interactive patch --category security 2>&1 | tee -a "$LOGFILE" || true
                ;;
            debian)
                export DEBIAN_FRONTEND=noninteractive
                apt-get update -qq 2>/dev/null || true
                apt-get upgrade -y -o Dpkg::Options::="--force-confold" 2>&1 | tee -a "$LOGFILE" || true
                ;;
            rhel)
                if command -v dnf &>/dev/null; then
                    dnf upgrade --security -y 2>&1 | tee -a "$LOGFILE" || true
                else
                    yum update --security -y 2>&1 | tee -a "$LOGFILE" || true
                fi
                ;;
            arch)
                pacman -Syu --noconfirm 2>&1 | tee -a "$LOGFILE" || true
                ;;
        esac

        log "Ejecutando pruebas post-parche..."
        if test_services; then
            log "=== Todos los servicios OK ==="
        else
            log "=== ATENCION: Algunos servicios fallaron. Considerar rollback. ==="
            log "  Rollback: securizar-patch-rollback.sh $SNAP"
        fi
        ;;

    --status)
        log "=== Estado de parches pendientes ==="
        case "$FAMILY" in
            suse)   zypper list-patches --category security 2>/dev/null || true ;;
            debian) apt-get update -qq 2>/dev/null || true; apt list --upgradable 2>/dev/null || true ;;
            rhel)
                if command -v dnf &>/dev/null; then
                    dnf updateinfo list security 2>/dev/null || true
                else
                    yum updateinfo list security 2>/dev/null || true
                fi
                ;;
            arch)   checkupdates 2>/dev/null || true ;;
        esac
        ;;

    *)
        usage
        ;;
esac
EOF
    chmod 0750 "$PATCH_BIN/securizar-patch-test.sh"
    log_change "Creado" "script de staging de parches en $PATCH_BIN/securizar-patch-test.sh"

    # --- Rollback script ---
    cat > "$PATCH_BIN/securizar-patch-rollback.sh" << 'EOF'
#!/bin/bash
# securizar-patch-rollback.sh - Revierte parches usando snapshot previo
set -euo pipefail

LOG_DIR="/var/log/securizar"
mkdir -p "$LOG_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
LOGFILE="$LOG_DIR/patch-rollback-$TIMESTAMP.log"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGFILE"; }

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        case "$ID" in
            opensuse*|sles|suse) echo "suse" ;;
            debian|ubuntu|linuxmint) echo "debian" ;;
            rhel|centos|fedora|rocky|alma) echo "rhel" ;;
            arch|manjaro) echo "arch" ;;
            *) echo "unknown" ;;
        esac
    else
        echo "unknown"
    fi
}

FAMILY=$(detect_distro)

SNAPSHOT="${1:-}"
if [[ -z "$SNAPSHOT" ]]; then
    echo "Uso: $0 <snapshot-file>"
    echo ""
    echo "Snapshots disponibles:"
    ls -1t /var/lib/securizar/patches/staging/snapshot-*.txt 2>/dev/null || echo "  (ninguno)"
    exit 1
fi

if [[ ! -f "$SNAPSHOT" ]]; then
    echo "ERROR: Snapshot no encontrado: $SNAPSHOT"
    exit 1
fi

log "=== Inicio de rollback desde: $SNAPSHOT ==="

# Get current packages
CURRENT_SNAP=$(mktemp)
case "$FAMILY" in
    suse|rhel) rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' | sort > "$CURRENT_SNAP" 2>/dev/null || true ;;
    debian)    dpkg -l | awk '/^ii/{print $2"="$3}' | sort > "$CURRENT_SNAP" 2>/dev/null || true ;;
    arch)      pacman -Q | sort > "$CURRENT_SNAP" 2>/dev/null || true ;;
esac

# Find changed packages
CHANGED=$(diff "$SNAPSHOT" "$CURRENT_SNAP" | grep '^>' | sed 's/^> //' || true)
REMOVED=$(diff "$SNAPSHOT" "$CURRENT_SNAP" | grep '^<' | sed 's/^< //' || true)

if [[ -z "$CHANGED" ]] && [[ -z "$REMOVED" ]]; then
    log "No hay diferencias entre el snapshot y el estado actual."
    rm -f "$CURRENT_SNAP"
    exit 0
fi

log "Paquetes cambiados desde el snapshot:"
echo "$CHANGED" | while read -r pkg; do
    [[ -n "$pkg" ]] && log "  + $pkg"
done

log "Paquetes que estaban en el snapshot pero ya no:"
echo "$REMOVED" | while read -r pkg; do
    [[ -n "$pkg" ]] && log "  - $pkg"
done

log ""
log "Para revertir manualmente:"

case "$FAMILY" in
    suse)
        log "  zypper install --oldpackage <paquete-version-anterior>"
        log "  O usar: snapper rollback (si btrfs+snapper)"
        if command -v snapper &>/dev/null; then
            log ""
            log "Snapshots de snapper disponibles:"
            snapper list 2>/dev/null | tee -a "$LOGFILE" || true
        fi
        ;;
    debian)
        log "  apt-get install <paquete>=<version-anterior>"
        log "  Las versiones anteriores deben estar en cache (/var/cache/apt/archives/)"
        if ls /var/cache/apt/archives/*.deb &>/dev/null; then
            log "  Cache de apt tiene $(ls /var/cache/apt/archives/*.deb 2>/dev/null | wc -l) paquetes"
        fi
        ;;
    rhel)
        log "  dnf history undo last"
        log "  O: yum history undo last"
        log ""
        log "Historial de transacciones:"
        if command -v dnf &>/dev/null; then
            dnf history list --reverse 2>/dev/null | tail -5 | tee -a "$LOGFILE" || true
        else
            yum history list 2>/dev/null | head -10 | tee -a "$LOGFILE" || true
        fi
        ;;
    arch)
        log "  Revisar /var/cache/pacman/pkg/ para versiones anteriores"
        log "  pacman -U /var/cache/pacman/pkg/<paquete-version>.pkg.tar.zst"
        ;;
esac

rm -f "$CURRENT_SNAP"
log "=== Rollback info completada ==="
EOF
    chmod 0750 "$PATCH_BIN/securizar-patch-rollback.sh"
    log_change "Creado" "script de rollback en $PATCH_BIN/securizar-patch-rollback.sh"

else
    log_skip "Staging y testing de parches"
fi

# ============================================================
# S5 - Monitoreo de advisories de seguridad
# ============================================================
log_section "S5: Monitoreo de advisories de seguridad"
log_info "Crea script para consultar feeds RSS de advisories de seguridad de la distribucion."

if check_executable /usr/local/bin/monitorear-advisories.sh; then
    log_already "Monitoreo de advisories (monitorear-advisories.sh existe)"
elif ask "Configurar monitoreo de advisories de seguridad?"; then

    cat > "$PATCH_BIN/monitorear-advisories.sh" << 'EOF'
#!/bin/bash
# monitorear-advisories.sh - Consulta advisories de seguridad via RSS/web
set -euo pipefail

ADVISORY_DIR="/var/lib/securizar/advisories"
mkdir -p "$ADVISORY_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT="$ADVISORY_DIR/advisories-$TIMESTAMP.txt"

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        case "$ID" in
            opensuse*|sles|suse) echo "suse" ;;
            debian|ubuntu|linuxmint) echo "debian" ;;
            rhel|centos|fedora|rocky|alma) echo "rhel" ;;
            arch|manjaro) echo "arch" ;;
            *) echo "unknown" ;;
        esac
    else
        echo "unknown"
    fi
}

FAMILY=$(detect_distro)

# RSS feed URLs per distro family
SUSE_RSS="https://www.suse.com/support/update/rss/rss.xml"
SUSE_MAIN="https://www.suse.com/support/update/"
DEBIAN_RSS="https://www.debian.org/security/dsa.rdf"
DEBIAN_DSA="https://www.debian.org/security/dsa"
RHEL_RSS="https://access.redhat.com/security/data/oval/com.redhat.rhsa-all.xml"
RHEL_MAIN="https://access.redhat.com/security/security-updates/"
ARCH_RSS="https://security.archlinux.org/advisory.atom"
ARCH_MAIN="https://security.archlinux.org/"
CVE_RECENT="https://cve.circl.lu/api/last/10"
CISA_KNOWN="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

echo "============================================" | tee "$REPORT"
echo " Monitoreo de Advisories de Seguridad" | tee -a "$REPORT"
echo " Fecha: $(date)" | tee -a "$REPORT"
echo " Host: $(hostname)" | tee -a "$REPORT"
echo " Distro: $FAMILY" | tee -a "$REPORT"
echo "============================================" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

fetch_feed() {
    local url="$1"
    local desc="$2"
    echo "[*] Consultando: $desc" | tee -a "$REPORT"
    echo "    URL: $url" | tee -a "$REPORT"

    if command -v curl &>/dev/null; then
        local content
        content=$(curl -sL --max-time 30 "$url" 2>/dev/null) || true
        if [[ -n "$content" ]]; then
            # Extract titles from RSS/XML/Atom
            echo "$content" | grep -oP '(?<=<title>)[^<]+' 2>/dev/null | head -20 | while read -r title; do
                echo "    - $title" | tee -a "$REPORT"
            done
            # Also try atom format
            echo "$content" | grep -oP '(?<=<summary[^>]*>)[^<]+' 2>/dev/null | head -10 | while read -r summary; do
                echo "    > $summary" | tee -a "$REPORT"
            done
        else
            echo "    [!] No se pudo obtener contenido" | tee -a "$REPORT"
        fi
    else
        echo "    [!] curl no disponible" | tee -a "$REPORT"
    fi
    echo "" | tee -a "$REPORT"
}

# Fetch distro-specific feeds
case "$FAMILY" in
    suse)
        fetch_feed "$SUSE_RSS" "SUSE Security Advisories"
        echo "[*] Parches de seguridad locales pendientes:" | tee -a "$REPORT"
        zypper --non-interactive list-patches --category security 2>/dev/null | head -30 | tee -a "$REPORT" || true
        ;;
    debian)
        fetch_feed "$DEBIAN_RSS" "Debian Security Advisories (DSA)"
        echo "[*] Verificando advisories locales:" | tee -a "$REPORT"
        if command -v debsecan &>/dev/null; then
            debsecan --only-fixed 2>/dev/null | head -20 | tee -a "$REPORT" || true
        fi
        ;;
    rhel)
        fetch_feed "$RHEL_RSS" "Red Hat Security Advisories (RHSA)"
        echo "[*] Advisories locales:" | tee -a "$REPORT"
        if command -v dnf &>/dev/null; then
            dnf updateinfo list security 2>/dev/null | head -20 | tee -a "$REPORT" || true
        else
            yum updateinfo list security 2>/dev/null | head -20 | tee -a "$REPORT" || true
        fi
        ;;
    arch)
        fetch_feed "$ARCH_RSS" "Arch Linux Security Advisories"
        echo "[*] Paquetes vulnerables:" | tee -a "$REPORT"
        if command -v arch-audit &>/dev/null; then
            arch-audit 2>/dev/null | head -20 | tee -a "$REPORT" || true
        fi
        ;;
esac

echo "" | tee -a "$REPORT"

# Check recent CVEs from CIRCL
echo "[*] Consultando CVEs recientes (CIRCL)..." | tee -a "$REPORT"
if command -v curl &>/dev/null; then
    cve_data=$(curl -sL --max-time 30 "$CVE_RECENT" 2>/dev/null) || true
    if [[ -n "$cve_data" ]]; then
        echo "$cve_data" | grep -oP '"id"\s*:\s*"[^"]+"' 2>/dev/null | head -10 | sed 's/"id"\s*:\s*//;s/"//g' | while read -r cve; do
            echo "    - $cve" | tee -a "$REPORT"
        done
    fi
fi

echo "" | tee -a "$REPORT"
echo "============================================" | tee -a "$REPORT"
echo " URLs de referencia:" | tee -a "$REPORT"
echo "   SUSE:   $SUSE_MAIN" | tee -a "$REPORT"
echo "   Debian: $DEBIAN_DSA" | tee -a "$REPORT"
echo "   RHEL:   $RHEL_MAIN" | tee -a "$REPORT"
echo "   Arch:   $ARCH_MAIN" | tee -a "$REPORT"
echo "   CISA:   $CISA_KNOWN" | tee -a "$REPORT"
echo "============================================" | tee -a "$REPORT"

echo ""
echo "Reporte guardado en: $REPORT"

# Symlink latest
ln -sf "$REPORT" "$ADVISORY_DIR/advisories-latest.txt" || true

# Cleanup old reports (keep 30)
ls -1t "$ADVISORY_DIR"/advisories-2*.txt 2>/dev/null | tail -n +31 | xargs rm -f 2>/dev/null || true
EOF
    chmod 0750 "$PATCH_BIN/monitorear-advisories.sh"
    log_change "Creado" "monitor de advisories en $PATCH_BIN/monitorear-advisories.sh"

    # Cron-style timer for daily advisory check
    cat > /etc/systemd/system/securizar-advisories.service << 'EOF'
[Unit]
Description=Securizar - Monitoreo diario de advisories de seguridad
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/monitorear-advisories.sh
StandardOutput=journal
StandardError=journal
TimeoutStartSec=300
EOF

    cat > /etc/systemd/system/securizar-advisories.timer << 'EOF'
[Unit]
Description=Securizar - Timer diario para advisories de seguridad

[Timer]
OnCalendar=*-*-* 08:00:00
RandomizedDelaySec=600
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload || true
    systemctl enable securizar-advisories.timer 2>/dev/null || true
    log_change "Habilitado" "timer diario de monitoreo de advisories"

else
    log_skip "Monitoreo de advisories de seguridad"
fi

# ============================================================
# S6 - Dependency vulnerability scanning
# ============================================================
log_section "S6: Dependency vulnerability scanning"
log_info "Verifica versiones de librerias criticas (OpenSSL, glibc, libcurl, etc.) contra vulnerabilidades conocidas."

if check_executable /usr/local/bin/escanear-dependencias.sh; then
    log_already "Escaneo de dependencias vulnerables (escanear-dependencias.sh existe)"
elif ask "Configurar escaneo de dependencias vulnerables?"; then

    cat > "$PATCH_BIN/escanear-dependencias.sh" << 'EOF'
#!/bin/bash
# escanear-dependencias.sh - Verifica librerias criticas contra vulns conocidas
set -euo pipefail

REPORT_DIR="/var/lib/securizar/dependency-reports"
mkdir -p "$REPORT_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT="$REPORT_DIR/dep-scan-$TIMESTAMP.txt"

# Critical libraries to check
CRITICAL_LIBS=(
    "openssl"
    "glibc"
    "libcurl"
    "libssh2"
    "zlib"
    "libxml2"
    "libpng"
    "libjpeg"
    "sqlite"
    "expat"
    "gnutls"
    "nss"
    "krb5"
    "sudo"
    "systemd"
    "dbus"
    "polkit"
    "bash"
    "openssh"
    "libgcrypt"
)

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        case "$ID" in
            opensuse*|sles|suse) echo "suse" ;;
            debian|ubuntu|linuxmint) echo "debian" ;;
            rhel|centos|fedora|rocky|alma) echo "rhel" ;;
            arch|manjaro) echo "arch" ;;
            *) echo "unknown" ;;
        esac
    else
        echo "unknown"
    fi
}

FAMILY=$(detect_distro)
WARNINGS=0
CRITICAL_COUNT=0

echo "============================================" | tee "$REPORT"
echo " Escaneo de Dependencias Criticas" | tee -a "$REPORT"
echo " Fecha: $(date)" | tee -a "$REPORT"
echo " Host: $(hostname)" | tee -a "$REPORT"
echo "============================================" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

get_pkg_version() {
    local lib="$1"
    local version=""
    case "$FAMILY" in
        suse|rhel)
            version=$(rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}\n' 2>/dev/null | grep -i "^${lib}" | head -1 || true)
            ;;
        debian)
            version=$(dpkg -l 2>/dev/null | awk '/^ii/ && $2 ~ /^(lib)?'"$lib"'/{print $2"="$3}' | head -1 || true)
            ;;
        arch)
            version=$(pacman -Q 2>/dev/null | grep -i "^${lib}" | head -1 || true)
            ;;
    esac
    echo "$version"
}

check_lib_updates() {
    local lib="$1"
    local has_update="no"
    case "$FAMILY" in
        suse)
            if zypper --non-interactive list-updates 2>/dev/null | grep -qi "$lib"; then
                has_update="yes"
            fi
            ;;
        debian)
            if apt list --upgradable 2>/dev/null | grep -qi "$lib"; then
                has_update="yes"
            fi
            ;;
        rhel)
            if command -v dnf &>/dev/null; then
                if dnf check-update 2>/dev/null | grep -qi "$lib"; then
                    has_update="yes"
                fi
            else
                if yum check-update 2>/dev/null | grep -qi "$lib"; then
                    has_update="yes"
                fi
            fi
            ;;
        arch)
            if checkupdates 2>/dev/null | grep -qi "$lib"; then
                has_update="yes"
            fi
            ;;
    esac
    echo "$has_update"
}

# Check OpenSSL specifically
echo "[*] Verificando OpenSSL..." | tee -a "$REPORT"
if command -v openssl &>/dev/null; then
    OPENSSL_VER=$(openssl version 2>/dev/null || echo "desconocido")
    echo "    Version: $OPENSSL_VER" | tee -a "$REPORT"

    # Check for known weak versions
    if echo "$OPENSSL_VER" | grep -qE '0\.(9|8)\.|1\.0\.1[^0-9]'; then
        echo "    [CRITICO] Version de OpenSSL obsoleta y vulnerable" | tee -a "$REPORT"
        CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
    elif echo "$OPENSSL_VER" | grep -qE '1\.0\.2'; then
        echo "    [ALTO] OpenSSL 1.0.2 esta en EOL" | tee -a "$REPORT"
        WARNINGS=$((WARNINGS + 1))
    elif echo "$OPENSSL_VER" | grep -qE '1\.1\.0'; then
        echo "    [ALTO] OpenSSL 1.1.0 esta en EOL" | tee -a "$REPORT"
        WARNINGS=$((WARNINGS + 1))
    else
        echo "    [OK] Version soportada" | tee -a "$REPORT"
    fi
else
    echo "    [WARN] openssl no encontrado en PATH" | tee -a "$REPORT"
    WARNINGS=$((WARNINGS + 1))
fi
echo "" | tee -a "$REPORT"

# Check glibc
echo "[*] Verificando glibc..." | tee -a "$REPORT"
GLIBC_VER=$(ldd --version 2>/dev/null | head -1 || echo "no determinada")
echo "    Version: $GLIBC_VER" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# Check libcurl
echo "[*] Verificando libcurl..." | tee -a "$REPORT"
if command -v curl &>/dev/null; then
    CURL_VER=$(curl --version 2>/dev/null | head -1 || echo "desconocido")
    echo "    Version: $CURL_VER" | tee -a "$REPORT"
else
    echo "    curl no instalado" | tee -a "$REPORT"
fi
echo "" | tee -a "$REPORT"

# Check all critical libs
echo "[*] Estado de librerias criticas:" | tee -a "$REPORT"
printf "    %-20s %-40s %-10s\n" "LIBRERIA" "VERSION" "UPDATE?" | tee -a "$REPORT"
echo "    $(printf '%.0s-' {1..72})" | tee -a "$REPORT"

for lib in "${CRITICAL_LIBS[@]}"; do
    version=$(get_pkg_version "$lib")
    if [[ -n "$version" ]]; then
        has_update=$(check_lib_updates "$lib")
        if [[ "$has_update" == "yes" ]]; then
            printf "    %-20s %-40s %-10s\n" "$lib" "$version" "[UPDATE]" | tee -a "$REPORT"
            WARNINGS=$((WARNINGS + 1))
        else
            printf "    %-20s %-40s %-10s\n" "$lib" "$version" "[OK]" | tee -a "$REPORT"
        fi
    else
        printf "    %-20s %-40s %-10s\n" "$lib" "(no instalado)" "[-]" | tee -a "$REPORT"
    fi
done

echo "" | tee -a "$REPORT"

# Check for libraries with known SUID issues
echo "[*] Verificando binarios SUID con librerias criticas..." | tee -a "$REPORT"
find /usr/bin /usr/sbin /usr/local/bin -perm -4000 -type f 2>/dev/null | while read -r binary; do
    linked_libs=$(ldd "$binary" 2>/dev/null | grep -oP '/[^\s]+' || true)
    for lib in $linked_libs; do
        if echo "$lib" | grep -qE '(libcrypt|libssl|libcurl|libssh)'; then
            echo "    SUID $binary -> $lib" | tee -a "$REPORT"
        fi
    done
done || true

echo "" | tee -a "$REPORT"
echo "============================================" | tee -a "$REPORT"
echo " RESUMEN" | tee -a "$REPORT"
echo "  Criticos: $CRITICAL_COUNT" | tee -a "$REPORT"
echo "  Advertencias: $WARNINGS" | tee -a "$REPORT"
echo "============================================" | tee -a "$REPORT"

echo ""
echo "Reporte guardado en: $REPORT"

ln -sf "$REPORT" "$REPORT_DIR/dep-scan-latest.txt" || true
ls -1t "$REPORT_DIR"/dep-scan-2*.txt 2>/dev/null | tail -n +31 | xargs rm -f 2>/dev/null || true
EOF
    chmod 0750 "$PATCH_BIN/escanear-dependencias.sh"
    log_change "Creado" "escaner de dependencias en $PATCH_BIN/escanear-dependencias.sh"

else
    log_skip "Escaneo de dependencias vulnerables"
fi

# ============================================================
# S7 - Kernel vulnerability assessment
# ============================================================
log_section "S7: Kernel vulnerability assessment"
log_info "Evalua vulnerabilidades del kernel: CPU bugs, mitigaciones activas, CVEs conocidos."

if check_executable /usr/local/bin/evaluar-kernel-vulns.sh; then
    log_already "Evaluacion de vulnerabilidades del kernel (evaluar-kernel-vulns.sh existe)"
elif ask "Configurar evaluacion de vulnerabilidades del kernel?"; then

    cat > "$PATCH_BIN/evaluar-kernel-vulns.sh" << 'EOF'
#!/bin/bash
# evaluar-kernel-vulns.sh - Evalua vulnerabilidades y mitigaciones del kernel
set -euo pipefail

REPORT_DIR="/var/lib/securizar/kernel-reports"
mkdir -p "$REPORT_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT="$REPORT_DIR/kernel-vuln-$TIMESTAMP.txt"

VULNS_FOUND=0
MITIGATIONS_ACTIVE=0
MITIGATIONS_MISSING=0

echo "============================================" | tee "$REPORT"
echo " Evaluacion de Vulnerabilidades del Kernel" | tee -a "$REPORT"
echo " Fecha: $(date)" | tee -a "$REPORT"
echo " Host: $(hostname)" | tee -a "$REPORT"
echo " Kernel: $(uname -r)" | tee -a "$REPORT"
echo " Arch: $(uname -m)" | tee -a "$REPORT"
echo "============================================" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# --- CPU vulnerabilities ---
echo "[*] Vulnerabilidades de CPU (sysfs):" | tee -a "$REPORT"
VULN_DIR="/sys/devices/system/cpu/vulnerabilities"
if [[ -d "$VULN_DIR" ]]; then
    for vuln_file in "$VULN_DIR"/*; do
        if [[ -f "$vuln_file" ]]; then
            vuln_name=$(basename "$vuln_file")
            vuln_status=$(cat "$vuln_file" 2>/dev/null || echo "unknown")
            if echo "$vuln_status" | grep -qi "not affected\|mitigation"; then
                echo "    [OK] $vuln_name: $vuln_status" | tee -a "$REPORT"
                MITIGATIONS_ACTIVE=$((MITIGATIONS_ACTIVE + 1))
            elif echo "$vuln_status" | grep -qi "vulnerable"; then
                echo "    [VULN] $vuln_name: $vuln_status" | tee -a "$REPORT"
                VULNS_FOUND=$((VULNS_FOUND + 1))
                MITIGATIONS_MISSING=$((MITIGATIONS_MISSING + 1))
            else
                echo "    [?] $vuln_name: $vuln_status" | tee -a "$REPORT"
            fi
        fi
    done
else
    echo "    [!] $VULN_DIR no disponible" | tee -a "$REPORT"
fi
echo "" | tee -a "$REPORT"

# --- Kernel boot parameters ---
echo "[*] Parametros de seguridad del kernel:" | tee -a "$REPORT"
CMDLINE=$(cat /proc/cmdline 2>/dev/null || echo "")
echo "    Linea de comandos: $CMDLINE" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# Check for important security parameters
SECURITY_PARAMS=(
    "mitigations=auto"
    "spectre_v2=on"
    "spec_store_bypass_disable=auto"
    "l1tf=flush"
    "mds=full"
    "tsx_async_abort=full"
    "nosmt"
    "kpti=on"
    "vsyscall=none"
    "debugfs=off"
    "randomize_kstack_offset=on"
    "slab_nomerge"
    "init_on_alloc=1"
    "init_on_free=1"
    "page_alloc.shuffle=1"
)

echo "    Parametros de seguridad recomendados:" | tee -a "$REPORT"
for param in "${SECURITY_PARAMS[@]}"; do
    param_name="${param%%=*}"
    if echo "$CMDLINE" | grep -q "$param_name"; then
        echo "      [OK] $param_name presente" | tee -a "$REPORT"
    else
        echo "      [--] $param_name no establecido" | tee -a "$REPORT"
    fi
done
echo "" | tee -a "$REPORT"

# --- Kernel security features ---
echo "[*] Caracteristicas de seguridad del kernel:" | tee -a "$REPORT"

# ASLR
ASLR=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo "unknown")
case "$ASLR" in
    2) echo "    [OK] ASLR: Completo (2)" | tee -a "$REPORT" ;;
    1) echo "    [WARN] ASLR: Parcial (1)" | tee -a "$REPORT"; VULNS_FOUND=$((VULNS_FOUND + 1)) ;;
    0) echo "    [VULN] ASLR: Deshabilitado (0)" | tee -a "$REPORT"; VULNS_FOUND=$((VULNS_FOUND + 1)) ;;
    *) echo "    [?] ASLR: $ASLR" | tee -a "$REPORT" ;;
esac

# KPTR restrict
KPTR=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null || echo "unknown")
case "$KPTR" in
    1|2) echo "    [OK] kptr_restrict: $KPTR" | tee -a "$REPORT" ;;
    0)   echo "    [WARN] kptr_restrict: 0 (punteros del kernel visibles)" | tee -a "$REPORT"; VULNS_FOUND=$((VULNS_FOUND + 1)) ;;
    *)   echo "    [?] kptr_restrict: $KPTR" | tee -a "$REPORT" ;;
esac

# dmesg restrict
DMESG=$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null || echo "unknown")
case "$DMESG" in
    1) echo "    [OK] dmesg_restrict: 1" | tee -a "$REPORT" ;;
    0) echo "    [WARN] dmesg_restrict: 0 (dmesg accesible por usuarios)" | tee -a "$REPORT"; VULNS_FOUND=$((VULNS_FOUND + 1)) ;;
    *) echo "    [?] dmesg_restrict: $DMESG" | tee -a "$REPORT" ;;
esac

# Yama ptrace
PTRACE=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo "unknown")
case "$PTRACE" in
    1|2|3) echo "    [OK] ptrace_scope: $PTRACE" | tee -a "$REPORT" ;;
    0)     echo "    [WARN] ptrace_scope: 0 (ptrace sin restriccion)" | tee -a "$REPORT"; VULNS_FOUND=$((VULNS_FOUND + 1)) ;;
    *)     echo "    [?] ptrace_scope: $PTRACE" | tee -a "$REPORT" ;;
esac

# Unprivileged BPF
UBPF=$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo "unknown")
case "$UBPF" in
    1|2) echo "    [OK] unprivileged_bpf_disabled: $UBPF" | tee -a "$REPORT" ;;
    0)   echo "    [WARN] unprivileged_bpf_disabled: 0" | tee -a "$REPORT"; VULNS_FOUND=$((VULNS_FOUND + 1)) ;;
    *)   echo "    [?] unprivileged_bpf_disabled: $UBPF" | tee -a "$REPORT" ;;
esac

# Unprivileged userns
UUSERNS=$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || echo "N/A")
if [[ "$UUSERNS" != "N/A" ]]; then
    case "$UUSERNS" in
        0) echo "    [OK] unprivileged_userns_clone: 0 (deshabilitado)" | tee -a "$REPORT" ;;
        1) echo "    [WARN] unprivileged_userns_clone: 1" | tee -a "$REPORT"; VULNS_FOUND=$((VULNS_FOUND + 1)) ;;
    esac
fi

echo "" | tee -a "$REPORT"

# --- LSM ---
echo "[*] Modulos de seguridad del kernel (LSM):" | tee -a "$REPORT"
LSM=$(cat /sys/kernel/security/lsm 2>/dev/null || echo "unknown")
echo "    LSMs activos: $LSM" | tee -a "$REPORT"

if echo "$LSM" | grep -qi "selinux"; then
    SELINUX_MODE=$(getenforce 2>/dev/null || echo "unknown")
    echo "    SELinux: $SELINUX_MODE" | tee -a "$REPORT"
fi
if echo "$LSM" | grep -qi "apparmor"; then
    AA_STATUS=$(aa-status --enabled 2>/dev/null && echo "habilitado" || echo "deshabilitado")
    echo "    AppArmor: $AA_STATUS" | tee -a "$REPORT"
fi
echo "" | tee -a "$REPORT"

# --- Loaded kernel modules ---
echo "[*] Modulos del kernel cargados (potencialmente inseguros):" | tee -a "$REPORT"
RISKY_MODULES=("cramfs" "freevxfs" "hfs" "hfsplus" "jffs2" "udf" "usb-storage" "dccp" "sctp" "rds" "tipc")
for mod in "${RISKY_MODULES[@]}"; do
    if lsmod 2>/dev/null | grep -q "^${mod}"; then
        echo "    [WARN] Modulo cargado: $mod" | tee -a "$REPORT"
        VULNS_FOUND=$((VULNS_FOUND + 1))
    fi
done
echo "" | tee -a "$REPORT"

# --- Kernel version check ---
echo "[*] Version del kernel:" | tee -a "$REPORT"
RUNNING=$(uname -r)
echo "    Ejecutando: $RUNNING" | tee -a "$REPORT"

# Check if there's a newer kernel installed
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        case "$ID" in
            opensuse*|sles|suse) echo "suse" ;;
            debian|ubuntu|linuxmint) echo "debian" ;;
            rhel|centos|fedora|rocky|alma) echo "rhel" ;;
            arch|manjaro) echo "arch" ;;
            *) echo "unknown" ;;
        esac
    else
        echo "unknown"
    fi
}
KFAMILY=$(detect_distro)

case "$KFAMILY" in
    suse|rhel)
        INSTALLED=$(rpm -qa kernel 2>/dev/null | sort -V | tail -1 || true)
        if [[ -n "$INSTALLED" ]]; then
            echo "    Instalado (ultimo): $INSTALLED" | tee -a "$REPORT"
        fi
        ;;
    debian)
        INSTALLED=$(dpkg -l 'linux-image-*' 2>/dev/null | awk '/^ii/{print $2}' | sort -V | tail -1 || true)
        if [[ -n "$INSTALLED" ]]; then
            echo "    Instalado (ultimo): $INSTALLED" | tee -a "$REPORT"
        fi
        ;;
    arch)
        INSTALLED=$(pacman -Q linux 2>/dev/null || true)
        if [[ -n "$INSTALLED" ]]; then
            echo "    Instalado: $INSTALLED" | tee -a "$REPORT"
        fi
        ;;
esac

# Check if reboot needed for kernel update
if [[ -f /var/run/reboot-required ]]; then
    echo "    [!] Reinicio requerido para nuevo kernel" | tee -a "$REPORT"
fi
echo "" | tee -a "$REPORT"

# --- Summary ---
echo "============================================" | tee -a "$REPORT"
echo " RESUMEN" | tee -a "$REPORT"
echo "  Vulnerabilidades encontradas: $VULNS_FOUND" | tee -a "$REPORT"
echo "  Mitigaciones activas: $MITIGATIONS_ACTIVE" | tee -a "$REPORT"
echo "  Mitigaciones faltantes: $MITIGATIONS_MISSING" | tee -a "$REPORT"

if [[ $VULNS_FOUND -eq 0 ]]; then
    echo "  Estado: EXCELENTE" | tee -a "$REPORT"
elif [[ $VULNS_FOUND -le 3 ]]; then
    echo "  Estado: BUENO (recomendaciones menores)" | tee -a "$REPORT"
elif [[ $VULNS_FOUND -le 6 ]]; then
    echo "  Estado: MEJORABLE" | tee -a "$REPORT"
else
    echo "  Estado: DEFICIENTE (accion requerida)" | tee -a "$REPORT"
fi
echo "============================================" | tee -a "$REPORT"

echo ""
echo "Reporte guardado en: $REPORT"
ln -sf "$REPORT" "$REPORT_DIR/kernel-vuln-latest.txt" || true
ls -1t "$REPORT_DIR"/kernel-vuln-2*.txt 2>/dev/null | tail -n +31 | xargs rm -f 2>/dev/null || true
EOF
    chmod 0750 "$PATCH_BIN/evaluar-kernel-vulns.sh"
    log_change "Creado" "evaluador de vulnerabilidades del kernel en $PATCH_BIN/evaluar-kernel-vulns.sh"

else
    log_skip "Evaluacion de vulnerabilidades del kernel"
fi

# ============================================================
# S8 - Patch compliance reporting
# ============================================================
log_section "S8: Patch compliance reporting"
log_info "Genera reportes de cumplimiento de parches en formato texto y HTML con scoring."

if check_executable /usr/local/bin/reporte-compliance-parches.sh; then
    log_already "Reportes de compliance (reporte-compliance-parches.sh existe)"
elif ask "Configurar reportes de compliance de parches?"; then

    cat > "$PATCH_BIN/reporte-compliance-parches.sh" << 'EOF'
#!/bin/bash
# reporte-compliance-parches.sh - Genera reporte de compliance de parches
set -euo pipefail

REPORT_DIR="/var/lib/securizar/compliance-reports"
mkdir -p "$REPORT_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
TEXT_REPORT="$REPORT_DIR/compliance-$TIMESTAMP.txt"
HTML_REPORT="$REPORT_DIR/compliance-$TIMESTAMP.html"

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        case "$ID" in
            opensuse*|sles|suse) echo "suse" ;;
            debian|ubuntu|linuxmint) echo "debian" ;;
            rhel|centos|fedora|rocky|alma) echo "rhel" ;;
            arch|manjaro) echo "arch" ;;
            *) echo "unknown" ;;
        esac
    else
        echo "unknown"
    fi
}

FAMILY=$(detect_distro)

# Scoring
SCORE=100
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNINGS=0
DETAILS=""

add_check() {
    local desc="$1"
    local result="$2"  # pass/fail/warn
    local detail="${3:-}"
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    case "$result" in
        pass)
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
            DETAILS="${DETAILS}[PASS] ${desc}\n"
            ;;
        fail)
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
            SCORE=$((SCORE - 10))
            DETAILS="${DETAILS}[FAIL] ${desc}${detail:+ - $detail}\n"
            ;;
        warn)
            WARNINGS=$((WARNINGS + 1))
            SCORE=$((SCORE - 5))
            DETAILS="${DETAILS}[WARN] ${desc}${detail:+ - $detail}\n"
            ;;
    esac
}

echo "[*] Ejecutando verificaciones de compliance..."

# Check 1: Auto-updates configured
if [[ -f /etc/securizar/patch-policy.conf ]]; then
    add_check "Politica de parches configurada" "pass"
else
    add_check "Politica de parches configurada" "fail" "No existe /etc/securizar/patch-policy.conf"
fi

# Check 2: Auto-patch timer
if systemctl is-enabled securizar-auto-patch.timer &>/dev/null; then
    add_check "Timer de auto-parcheo habilitado" "pass"
else
    add_check "Timer de auto-parcheo habilitado" "fail" "securizar-auto-patch.timer no habilitado"
fi

# Check 3: Security patches pending
PENDING=0
case "$FAMILY" in
    suse)
        PENDING=$(zypper --non-interactive list-patches --category security 2>/dev/null | grep -c '|' || true)
        ;;
    debian)
        apt-get update -qq 2>/dev/null || true
        PENDING=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst.*security' || true)
        ;;
    rhel)
        if command -v dnf &>/dev/null; then
            PENDING=$(dnf updateinfo list security 2>/dev/null | grep -c 'CVE\|RHSA' || true)
        else
            PENDING=$(yum updateinfo list security 2>/dev/null | grep -c 'CVE\|RHSA' || true)
        fi
        ;;
    arch)
        PENDING=$(checkupdates 2>/dev/null | wc -l || true)
        ;;
esac

if [[ "$PENDING" -eq 0 ]]; then
    add_check "Parches de seguridad pendientes: $PENDING" "pass"
elif [[ "$PENDING" -le 5 ]]; then
    add_check "Parches de seguridad pendientes: $PENDING" "warn" "Aplicar pronto"
else
    add_check "Parches de seguridad pendientes: $PENDING" "fail" "Demasiados parches pendientes"
fi

# Check 4: Kernel up to date
if [[ -f /var/run/reboot-required ]]; then
    add_check "Kernel actualizado (reinicio pendiente)" "warn" "Reiniciar para aplicar nuevo kernel"
else
    add_check "Kernel actualizado" "pass"
fi

# Check 5: SBOM recent
if [[ -f /var/lib/securizar/sbom/sbom-latest.json ]]; then
    SBOM_AGE=$(( ($(date +%s) - $(stat -c %Y /var/lib/securizar/sbom/sbom-latest.json 2>/dev/null || echo 0)) / 86400 ))
    if [[ "$SBOM_AGE" -le 7 ]]; then
        add_check "SBOM reciente (${SBOM_AGE} dias)" "pass"
    elif [[ "$SBOM_AGE" -le 30 ]]; then
        add_check "SBOM con ${SBOM_AGE} dias" "warn" "Regenerar SBOM"
    else
        add_check "SBOM desactualizado (${SBOM_AGE} dias)" "fail" "SBOM demasiado antiguo"
    fi
else
    add_check "SBOM disponible" "fail" "No existe SBOM. Ejecutar generar-sbom.sh"
fi

# Check 6: CVE scan recent
LATEST_CVE=$(ls -1t /var/lib/securizar/cve-reports/cve-scan-*.json 2>/dev/null | head -1 || true)
if [[ -n "$LATEST_CVE" ]] && [[ -f "$LATEST_CVE" ]]; then
    CVE_AGE=$(( ($(date +%s) - $(stat -c %Y "$LATEST_CVE" 2>/dev/null || echo 0)) / 86400 ))
    if [[ "$CVE_AGE" -le 7 ]]; then
        add_check "Escaneo CVE reciente (${CVE_AGE} dias)" "pass"
    else
        add_check "Escaneo CVE con ${CVE_AGE} dias" "warn" "Ejecutar escanear-cves.sh"
    fi
else
    add_check "Escaneo CVE disponible" "fail" "No hay escaneos CVE. Ejecutar escanear-cves.sh"
fi

# Check 7: CPU mitigations
if [[ -d /sys/devices/system/cpu/vulnerabilities ]]; then
    VULN_COUNT=0
    for vuln_file in /sys/devices/system/cpu/vulnerabilities/*; do
        if [[ -f "$vuln_file" ]]; then
            if grep -qi "vulnerable" "$vuln_file" 2>/dev/null; then
                VULN_COUNT=$((VULN_COUNT + 1))
            fi
        fi
    done
    if [[ "$VULN_COUNT" -eq 0 ]]; then
        add_check "Mitigaciones de CPU activas" "pass"
    else
        add_check "Mitigaciones de CPU" "fail" "$VULN_COUNT vulnerabilidades sin mitigar"
    fi
else
    add_check "Informacion de vulnerabilidades CPU" "warn" "No disponible"
fi

# Check 8: ASLR
ASLR=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo "0")
if [[ "$ASLR" == "2" ]]; then
    add_check "ASLR completo habilitado" "pass"
else
    add_check "ASLR" "fail" "Valor actual: $ASLR (deberia ser 2)"
fi

# Check 9: Advisory monitoring
if systemctl is-enabled securizar-advisories.timer &>/dev/null; then
    add_check "Monitoreo de advisories habilitado" "pass"
else
    add_check "Monitoreo de advisories habilitado" "warn" "Timer no configurado"
fi

# Check 10: Last patch date
LAST_PATCH_LOG=$(ls -1t /var/log/securizar/auto-patch-*.log 2>/dev/null | head -1 || true)
if [[ -n "$LAST_PATCH_LOG" ]] && [[ -f "$LAST_PATCH_LOG" ]]; then
    PATCH_AGE=$(( ($(date +%s) - $(stat -c %Y "$LAST_PATCH_LOG" 2>/dev/null || echo 0)) / 86400 ))
    if [[ "$PATCH_AGE" -le 7 ]]; then
        add_check "Ultimo parcheo: hace ${PATCH_AGE} dias" "pass"
    elif [[ "$PATCH_AGE" -le 30 ]]; then
        add_check "Ultimo parcheo: hace ${PATCH_AGE} dias" "warn" "Mas de una semana"
    else
        add_check "Ultimo parcheo: hace ${PATCH_AGE} dias" "fail" "Demasiado tiempo sin parchear"
    fi
else
    add_check "Historial de parcheo" "warn" "No hay registros de auto-parcheo"
fi

# Clamp score
[[ $SCORE -lt 0 ]] && SCORE=0

# Determine grade
GRADE=""
if [[ $SCORE -ge 90 ]]; then
    GRADE="EXCELENTE"
elif [[ $SCORE -ge 70 ]]; then
    GRADE="BUENO"
elif [[ $SCORE -ge 50 ]]; then
    GRADE="MEJORABLE"
else
    GRADE="DEFICIENTE"
fi

# --- Text report ---
{
    echo "============================================"
    echo " Reporte de Compliance de Parches"
    echo " Fecha: $(date)"
    echo " Host: $(hostname)"
    echo " Kernel: $(uname -r)"
    echo " Distro: $FAMILY"
    echo "============================================"
    echo ""
    echo " PUNTUACION: $SCORE/100 ($GRADE)"
    echo ""
    echo " Checks totales: $TOTAL_CHECKS"
    echo " Pasados: $PASSED_CHECKS"
    echo " Fallidos: $FAILED_CHECKS"
    echo " Advertencias: $WARNINGS"
    echo ""
    echo " Detalles:"
    echo -e "$DETAILS"
    echo ""
    echo "============================================"
} > "$TEXT_REPORT"

cat "$TEXT_REPORT"

# --- HTML report ---
SCORE_COLOR="green"
[[ $SCORE -lt 90 ]] && SCORE_COLOR="#cc8800"
[[ $SCORE -lt 70 ]] && SCORE_COLOR="#cc4400"
[[ $SCORE -lt 50 ]] && SCORE_COLOR="red"

cat > "$HTML_REPORT" << HTMLEOF
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Compliance de Parches - $(hostname)</title>
<style>
body { font-family: 'Segoe UI', Tahoma, sans-serif; margin: 20px; background: #f5f5f5; }
.container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
h1 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
.score { font-size: 48px; font-weight: bold; color: $SCORE_COLOR; text-align: center; margin: 20px 0; }
.grade { font-size: 24px; text-align: center; color: $SCORE_COLOR; }
.stats { display: flex; justify-content: space-around; margin: 20px 0; }
.stat { text-align: center; padding: 10px; }
.stat-value { font-size: 24px; font-weight: bold; }
.pass { color: green; }
.fail { color: red; }
.warn { color: #cc8800; }
table { width: 100%; border-collapse: collapse; margin: 20px 0; }
th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #ddd; }
th { background: #f8f9fa; }
.meta { color: #666; font-size: 0.9em; }
</style>
</head>
<body>
<div class="container">
<h1>Reporte de Compliance de Parches</h1>
<p class="meta">Host: $(hostname) | Fecha: $(date) | Kernel: $(uname -r)</p>

<div class="score">$SCORE/100</div>
<div class="grade">$GRADE</div>

<div class="stats">
<div class="stat"><div class="stat-value">$TOTAL_CHECKS</div>Checks</div>
<div class="stat"><div class="stat-value pass">$PASSED_CHECKS</div>Pasados</div>
<div class="stat"><div class="stat-value fail">$FAILED_CHECKS</div>Fallidos</div>
<div class="stat"><div class="stat-value warn">$WARNINGS</div>Advertencias</div>
</div>

<table>
<tr><th>Check</th><th>Estado</th></tr>
HTMLEOF

echo -e "$DETAILS" | while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    if echo "$line" | grep -q '^\[PASS\]'; then
        desc=$(echo "$line" | sed 's/^\[PASS\] //')
        echo "<tr><td>${desc}</td><td class=\"pass\">PASS</td></tr>" >> "$HTML_REPORT"
    elif echo "$line" | grep -q '^\[FAIL\]'; then
        desc=$(echo "$line" | sed 's/^\[FAIL\] //')
        echo "<tr><td>${desc}</td><td class=\"fail\">FAIL</td></tr>" >> "$HTML_REPORT"
    elif echo "$line" | grep -q '^\[WARN\]'; then
        desc=$(echo "$line" | sed 's/^\[WARN\] //')
        echo "<tr><td>${desc}</td><td class=\"warn\">WARN</td></tr>" >> "$HTML_REPORT"
    fi
done

cat >> "$HTML_REPORT" << HTMLEOF
</table>

<p class="meta">Generado por securizar - Modulo 61: Gestion de Parches</p>
</div>
</body>
</html>
HTMLEOF

echo ""
echo "Reportes guardados:"
echo "  Texto: $TEXT_REPORT"
echo "  HTML:  $HTML_REPORT"

ln -sf "$TEXT_REPORT" "$REPORT_DIR/compliance-latest.txt" || true
ln -sf "$HTML_REPORT" "$REPORT_DIR/compliance-latest.html" || true
ls -1t "$REPORT_DIR"/compliance-2*.txt 2>/dev/null | tail -n +31 | xargs rm -f 2>/dev/null || true
ls -1t "$REPORT_DIR"/compliance-2*.html 2>/dev/null | tail -n +31 | xargs rm -f 2>/dev/null || true
EOF
    chmod 0750 "$PATCH_BIN/reporte-compliance-parches.sh"
    log_change "Creado" "reporte de compliance en $PATCH_BIN/reporte-compliance-parches.sh"

else
    log_skip "Reportes de compliance de parches"
fi

# ============================================================
# S9 - Emergency patch procedures
# ============================================================
log_section "S9: Emergency patch procedures"
log_info "Crea script para aplicar parches de emergencia dado un CVE-ID: verifica, aplica y valida."

if check_executable /usr/local/bin/parche-emergencia.sh; then
    log_already "Procedimiento de parche de emergencia (parche-emergencia.sh existe)"
elif ask "Configurar procedimiento de parche de emergencia?"; then

    cat > "$PATCH_BIN/parche-emergencia.sh" << 'EOF'
#!/bin/bash
# parche-emergencia.sh - Aplica parche de emergencia para un CVE especifico
set -euo pipefail

LOG_DIR="/var/log/securizar"
STAGING_DIR="/var/lib/securizar/patches/staging"
mkdir -p "$LOG_DIR" "$STAGING_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
LOGFILE="$LOG_DIR/emergency-patch-$TIMESTAMP.log"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGFILE"; }

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        case "$ID" in
            opensuse*|sles|suse) echo "suse" ;;
            debian|ubuntu|linuxmint) echo "debian" ;;
            rhel|centos|fedora|rocky|alma) echo "rhel" ;;
            arch|manjaro) echo "arch" ;;
            *) echo "unknown" ;;
        esac
    else
        echo "unknown"
    fi
}

FAMILY=$(detect_distro)

usage() {
    echo "Uso: $0 <CVE-ID> [--apply|--check-only]"
    echo ""
    echo "Ejemplos:"
    echo "  $0 CVE-2024-1234              # Verifica y aplica"
    echo "  $0 CVE-2024-1234 --check-only # Solo verifica"
    echo "  $0 CVE-2024-1234 --apply      # Verifica y aplica"
    exit 1
}

CVE_ID="${1:-}"
ACTION="${2:---apply}"

if [[ -z "$CVE_ID" ]] || ! echo "$CVE_ID" | grep -qP '^CVE-\d{4}-\d{4,}$'; then
    echo "ERROR: CVE-ID invalido o no proporcionado."
    usage
fi

log "============================================"
log " PARCHE DE EMERGENCIA"
log " CVE: $CVE_ID"
log " Accion: $ACTION"
log " Fecha: $(date)"
log " Host: $(hostname)"
log "============================================"

# Phase 1: Check if CVE affects this system
log ""
log "=== FASE 1: Verificacion ==="

AFFECTED="unknown"
AFFECTED_PACKAGES=""

case "$FAMILY" in
    suse)
        log "Buscando $CVE_ID en parches disponibles (zypper)..."
        PATCH_INFO=$(zypper --non-interactive list-patches --cve "$CVE_ID" 2>/dev/null || true)
        if [[ -n "$PATCH_INFO" ]] && echo "$PATCH_INFO" | grep -q "$CVE_ID"; then
            AFFECTED="yes"
            AFFECTED_PACKAGES=$(echo "$PATCH_INFO" | grep "$CVE_ID" || true)
            log "AFECTADO: $CVE_ID encontrado en parches pendientes"
            log "$AFFECTED_PACKAGES"
        else
            log "No se encontro $CVE_ID en parches pendientes de zypper"
            AFFECTED="no"
        fi
        ;;
    debian)
        log "Buscando $CVE_ID en advisories Debian..."
        if command -v debsecan &>/dev/null; then
            SCAN_RESULT=$(debsecan 2>/dev/null | grep -i "$CVE_ID" || true)
            if [[ -n "$SCAN_RESULT" ]]; then
                AFFECTED="yes"
                AFFECTED_PACKAGES="$SCAN_RESULT"
                log "AFECTADO: $CVE_ID encontrado por debsecan"
                log "$AFFECTED_PACKAGES"
            else
                AFFECTED="no"
                log "No encontrado por debsecan"
            fi
        fi
        # Also check apt
        apt-get update -qq 2>/dev/null || true
        APT_CHECK=$(apt-get changelog --print-uris 2>/dev/null | grep -i "$CVE_ID" || true)
        if [[ -n "$APT_CHECK" ]]; then
            AFFECTED="yes"
            log "Encontrado en changelogs de apt"
        fi
        ;;
    rhel)
        log "Buscando $CVE_ID en advisories (dnf/yum)..."
        if command -v dnf &>/dev/null; then
            CVE_INFO=$(dnf updateinfo info --cve "$CVE_ID" 2>/dev/null || true)
        else
            CVE_INFO=$(yum updateinfo info --cve "$CVE_ID" 2>/dev/null || true)
        fi
        if [[ -n "$CVE_INFO" ]] && echo "$CVE_INFO" | grep -qi "update"; then
            AFFECTED="yes"
            AFFECTED_PACKAGES="$CVE_INFO"
            log "AFECTADO: $CVE_ID encontrado"
            log "$CVE_INFO"
        else
            AFFECTED="no"
            log "No encontrado en advisories locales"
        fi
        ;;
    arch)
        log "Buscando $CVE_ID en arch-audit..."
        if command -v arch-audit &>/dev/null; then
            AUDIT_RESULT=$(arch-audit 2>/dev/null | grep -i "$CVE_ID" || true)
            if [[ -n "$AUDIT_RESULT" ]]; then
                AFFECTED="yes"
                AFFECTED_PACKAGES="$AUDIT_RESULT"
                log "AFECTADO: $CVE_ID encontrado"
            else
                AFFECTED="no"
            fi
        fi
        ;;
esac

# Online lookup as fallback
if [[ "$AFFECTED" == "unknown" ]] && command -v curl &>/dev/null; then
    log "Consultando informacion online sobre $CVE_ID..."
    CVE_JSON=$(curl -sL --max-time 15 "https://cve.circl.lu/api/cve/$CVE_ID" 2>/dev/null) || true
    if [[ -n "$CVE_JSON" ]] && echo "$CVE_JSON" | grep -q '"id"'; then
        CVSS=$(echo "$CVE_JSON" | grep -oP '"cvss"\s*:\s*[\d.]+' | head -1 | grep -oP '[\d.]+' || echo "N/A")
        SUMMARY=$(echo "$CVE_JSON" | grep -oP '"summary"\s*:\s*"[^"]*"' | head -1 | sed 's/"summary"\s*:\s*"//;s/"$//' || echo "N/A")
        log "CVSS: $CVSS"
        log "Descripcion: $SUMMARY"
    fi
fi

if [[ "$AFFECTED" == "no" ]]; then
    log ""
    log "=== RESULTADO: Sistema NO afectado por $CVE_ID ==="
    log "(o no hay parche disponible aun)"
    exit 0
fi

if [[ "$ACTION" == "--check-only" ]]; then
    log ""
    log "=== VERIFICACION COMPLETADA (solo check) ==="
    log "Afectado: $AFFECTED"
    exit 0
fi

# Phase 2: Create pre-patch snapshot
log ""
log "=== FASE 2: Snapshot pre-parche ==="
SNAP="$STAGING_DIR/emergency-snapshot-$TIMESTAMP.txt"
case "$FAMILY" in
    suse|rhel) rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' | sort > "$SNAP" 2>/dev/null || true ;;
    debian)    dpkg -l | awk '/^ii/{print $2"="$3}' | sort > "$SNAP" 2>/dev/null || true ;;
    arch)      pacman -Q | sort > "$SNAP" 2>/dev/null || true ;;
esac
log "Snapshot guardado: $SNAP"

# Phase 3: Apply patch
log ""
log "=== FASE 3: Aplicacion del parche ==="
PATCH_RC=0

case "$FAMILY" in
    suse)
        log "Aplicando parche via zypper..."
        zypper --non-interactive patch --cve "$CVE_ID" 2>&1 | tee -a "$LOGFILE" || PATCH_RC=$?
        ;;
    debian)
        log "Aplicando actualizaciones de seguridad..."
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq 2>/dev/null || true
        # Try to update affected packages specifically
        if [[ -n "$AFFECTED_PACKAGES" ]]; then
            PKG_NAMES=$(echo "$AFFECTED_PACKAGES" | awk '{print $2}' | sort -u || true)
            for pkg in $PKG_NAMES; do
                apt-get install -y --only-upgrade "$pkg" 2>&1 | tee -a "$LOGFILE" || true
            done
        fi
        apt-get upgrade -y -o Dpkg::Options::="--force-confold" 2>&1 | tee -a "$LOGFILE" || PATCH_RC=$?
        ;;
    rhel)
        log "Aplicando parche via dnf/yum..."
        if command -v dnf &>/dev/null; then
            dnf upgrade --cve "$CVE_ID" -y 2>&1 | tee -a "$LOGFILE" || PATCH_RC=$?
        else
            yum update --cve "$CVE_ID" -y 2>&1 | tee -a "$LOGFILE" || PATCH_RC=$?
        fi
        ;;
    arch)
        log "Actualizando paquetes afectados..."
        pacman -Syu --noconfirm 2>&1 | tee -a "$LOGFILE" || PATCH_RC=$?
        ;;
esac

if [[ $PATCH_RC -ne 0 ]]; then
    log "ADVERTENCIA: La aplicacion del parche termino con codigo $PATCH_RC"
fi

# Phase 4: Verify
log ""
log "=== FASE 4: Verificacion post-parche ==="

# Check if CVE is still present
STILL_AFFECTED="unknown"
case "$FAMILY" in
    suse)
        if zypper --non-interactive list-patches --cve "$CVE_ID" 2>/dev/null | grep -q "$CVE_ID"; then
            STILL_AFFECTED="yes"
        else
            STILL_AFFECTED="no"
        fi
        ;;
    debian)
        if command -v debsecan &>/dev/null; then
            if debsecan 2>/dev/null | grep -qi "$CVE_ID"; then
                STILL_AFFECTED="yes"
            else
                STILL_AFFECTED="no"
            fi
        fi
        ;;
    rhel)
        if command -v dnf &>/dev/null; then
            if dnf updateinfo info --cve "$CVE_ID" 2>/dev/null | grep -qi "update"; then
                STILL_AFFECTED="yes"
            else
                STILL_AFFECTED="no"
            fi
        fi
        ;;
    arch)
        if command -v arch-audit &>/dev/null; then
            if arch-audit 2>/dev/null | grep -qi "$CVE_ID"; then
                STILL_AFFECTED="yes"
            else
                STILL_AFFECTED="no"
            fi
        fi
        ;;
esac

# Test critical services
log "Verificando servicios criticos..."
for svc in sshd systemd-journald; do
    if systemctl is-active "$svc" &>/dev/null; then
        log "  [OK] $svc"
    elif systemctl is-enabled "$svc" &>/dev/null; then
        log "  [WARN] $svc habilitado pero no activo"
    fi
done

# Check for reboot needed
if [[ -f /var/run/reboot-required ]]; then
    log "[!] Se requiere reinicio para completar el parche"
fi

log ""
log "============================================"
log " RESULTADO DEL PARCHE DE EMERGENCIA"
log "  CVE: $CVE_ID"
log "  Codigo de salida: $PATCH_RC"
if [[ "$STILL_AFFECTED" == "no" ]]; then
    log "  Estado: PARCHEADO EXITOSAMENTE"
elif [[ "$STILL_AFFECTED" == "yes" ]]; then
    log "  Estado: AUN VULNERABLE - Verificar manualmente"
else
    log "  Estado: No se pudo confirmar - Verificar manualmente"
fi
log "  Snapshot pre-parche: $SNAP"
log "  Log completo: $LOGFILE"
log "============================================"
EOF
    chmod 0750 "$PATCH_BIN/parche-emergencia.sh"
    log_change "Creado" "script de parche de emergencia en $PATCH_BIN/parche-emergencia.sh"

else
    log_skip "Procedimiento de parche de emergencia"
fi

# ============================================================
# S10 - Auditoria integral de gestion de parches
# ============================================================
log_section "S10: Auditoria integral de gestion de parches"
log_info "Ejecuta auditoria completa del sistema de gestion de parches con scoring consolidado."

if check_executable /usr/local/bin/auditar-parches.sh; then
    log_already "Auditoria integral de parches (auditar-parches.sh existe)"
elif ask "Instalar script de auditoria integral de parches?"; then

    cat > "$PATCH_BIN/auditar-parches.sh" << 'EOF'
#!/bin/bash
# auditar-parches.sh - Auditoria integral de gestion de parches
set -euo pipefail

AUDIT_DIR="/var/lib/securizar/audit-reports"
PATCH_BIN="/usr/local/bin"
mkdir -p "$AUDIT_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT="$AUDIT_DIR/patch-audit-$TIMESTAMP.txt"

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        case "$ID" in
            opensuse*|sles|suse) echo "suse" ;;
            debian|ubuntu|linuxmint) echo "debian" ;;
            rhel|centos|fedora|rocky|alma) echo "rhel" ;;
            arch|manjaro) echo "arch" ;;
            *) echo "unknown" ;;
        esac
    else
        echo "unknown"
    fi
}

FAMILY=$(detect_distro)

# Scoring
TOTAL_POINTS=0
MAX_POINTS=0
SECTION_RESULTS=""

audit_check() {
    local section="$1"
    local desc="$2"
    local points="$3"
    local result="$4"  # pass/fail/partial
    local detail="${5:-}"

    MAX_POINTS=$((MAX_POINTS + points))

    case "$result" in
        pass)
            TOTAL_POINTS=$((TOTAL_POINTS + points))
            SECTION_RESULTS="${SECTION_RESULTS}  [${points}/${points}] ${section}: ${desc}\n"
            ;;
        partial)
            local earned=$(( points / 2 ))
            TOTAL_POINTS=$((TOTAL_POINTS + earned))
            SECTION_RESULTS="${SECTION_RESULTS}  [${earned}/${points}] ${section}: ${desc}${detail:+ ($detail)}\n"
            ;;
        fail)
            SECTION_RESULTS="${SECTION_RESULTS}  [0/${points}] ${section}: ${desc}${detail:+ ($detail)}\n"
            ;;
    esac
}

{
echo "================================================================"
echo " AUDITORIA INTEGRAL DE GESTION DE PARCHES"
echo " Fecha: $(date)"
echo " Host: $(hostname)"
echo " Kernel: $(uname -r)"
echo " Distro: $FAMILY"
echo "================================================================"
echo ""

# --- A1: Patch policy ---
echo "[A1] Politica de parches"
if [[ -f /etc/securizar/patch-policy.conf ]]; then
    echo "  Politica encontrada: /etc/securizar/patch-policy.conf"
    audit_check "A1" "Politica de parches configurada" 10 "pass"
else
    echo "  No existe politica de parches"
    audit_check "A1" "Politica de parches configurada" 10 "fail" "Crear patch-policy.conf"
fi
echo ""

# --- A2: Auto-patch timer ---
echo "[A2] Automatizacion de parches"
if systemctl is-enabled securizar-auto-patch.timer &>/dev/null; then
    echo "  Timer de auto-parcheo: HABILITADO"
    if systemctl is-active securizar-auto-patch.timer &>/dev/null; then
        echo "  Estado del timer: ACTIVO"
        audit_check "A2" "Timer de auto-parcheo activo" 10 "pass"
    else
        echo "  Estado del timer: INACTIVO"
        audit_check "A2" "Timer de auto-parcheo habilitado pero inactivo" 10 "partial"
    fi
else
    echo "  Timer de auto-parcheo: NO HABILITADO"
    audit_check "A2" "Timer de auto-parcheo" 10 "fail" "Habilitar securizar-auto-patch.timer"
fi
echo ""

# --- A3: Pending security patches ---
echo "[A3] Parches de seguridad pendientes"
PENDING=0
case "$FAMILY" in
    suse)
        PENDING=$(zypper --non-interactive list-patches --category security 2>/dev/null | grep -c '|' || true)
        ;;
    debian)
        apt-get update -qq 2>/dev/null || true
        PENDING=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst.*security' || true)
        ;;
    rhel)
        if command -v dnf &>/dev/null; then
            PENDING=$(dnf updateinfo list security 2>/dev/null | grep -c 'RHSA\|CVE' || true)
        else
            PENDING=$(yum updateinfo list security 2>/dev/null | grep -c 'RHSA\|CVE' || true)
        fi
        ;;
    arch)
        PENDING=$(checkupdates 2>/dev/null | wc -l || true)
        ;;
esac
echo "  Parches pendientes: $PENDING"
if [[ "$PENDING" -eq 0 ]]; then
    audit_check "A3" "Sin parches de seguridad pendientes" 15 "pass"
elif [[ "$PENDING" -le 5 ]]; then
    audit_check "A3" "Pocos parches pendientes ($PENDING)" 15 "partial" "Aplicar pronto"
else
    audit_check "A3" "Demasiados parches pendientes ($PENDING)" 15 "fail" "Aplicar urgentemente"
fi
echo ""

# --- A4: SBOM ---
echo "[A4] Software Bill of Materials"
if [[ -f /var/lib/securizar/sbom/sbom-latest.json ]]; then
    SBOM_AGE=$(( ($(date +%s) - $(stat -c %Y /var/lib/securizar/sbom/sbom-latest.json 2>/dev/null || echo 0)) / 86400 ))
    echo "  SBOM encontrado (edad: ${SBOM_AGE} dias)"
    if [[ "$SBOM_AGE" -le 7 ]]; then
        audit_check "A4" "SBOM actualizado" 10 "pass"
    elif [[ "$SBOM_AGE" -le 30 ]]; then
        audit_check "A4" "SBOM existente pero antiguo (${SBOM_AGE}d)" 10 "partial"
    else
        audit_check "A4" "SBOM desactualizado (${SBOM_AGE}d)" 10 "fail"
    fi
else
    echo "  SBOM no encontrado"
    audit_check "A4" "SBOM generado" 10 "fail" "Ejecutar generar-sbom.sh"
fi
echo ""

# --- A5: CVE scanning ---
echo "[A5] Escaneo de CVEs"
if [[ -x "$PATCH_BIN/escanear-cves.sh" ]]; then
    LATEST_SCAN=$(ls -1t /var/lib/securizar/cve-reports/cve-scan-*.json 2>/dev/null | head -1 || true)
    if [[ -n "$LATEST_SCAN" ]]; then
        SCAN_AGE=$(( ($(date +%s) - $(stat -c %Y "$LATEST_SCAN" 2>/dev/null || echo 0)) / 86400 ))
        echo "  Script de escaneo: INSTALADO"
        echo "  Ultimo escaneo: hace ${SCAN_AGE} dias"
        if [[ "$SCAN_AGE" -le 7 ]]; then
            audit_check "A5" "Escaneo CVE reciente" 10 "pass"
        else
            audit_check "A5" "Escaneo CVE desactualizado (${SCAN_AGE}d)" 10 "partial"
        fi
    else
        echo "  Script instalado pero sin escaneos previos"
        audit_check "A5" "Escaneo CVE" 10 "partial" "Ejecutar primer escaneo"
    fi
else
    echo "  Script de escaneo CVE no instalado"
    audit_check "A5" "Escaneo CVE configurado" 10 "fail"
fi
echo ""

# --- A6: Advisory monitoring ---
echo "[A6] Monitoreo de advisories"
if systemctl is-enabled securizar-advisories.timer &>/dev/null; then
    echo "  Timer de advisories: HABILITADO"
    audit_check "A6" "Monitoreo de advisories activo" 10 "pass"
else
    if [[ -x "$PATCH_BIN/monitorear-advisories.sh" ]]; then
        echo "  Script disponible pero timer no habilitado"
        audit_check "A6" "Monitoreo de advisories" 10 "partial" "Habilitar timer"
    else
        echo "  Monitoreo de advisories no configurado"
        audit_check "A6" "Monitoreo de advisories" 10 "fail"
    fi
fi
echo ""

# --- A7: Kernel security ---
echo "[A7] Seguridad del kernel"
KERNEL_ISSUES=0

ASLR=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo "0")
if [[ "$ASLR" != "2" ]]; then
    echo "  [WARN] ASLR no esta en nivel 2 (actual: $ASLR)"
    KERNEL_ISSUES=$((KERNEL_ISSUES + 1))
fi

KPTR=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null || echo "0")
if [[ "$KPTR" == "0" ]]; then
    echo "  [WARN] kptr_restrict es 0"
    KERNEL_ISSUES=$((KERNEL_ISSUES + 1))
fi

if [[ -d /sys/devices/system/cpu/vulnerabilities ]]; then
    for vuln_file in /sys/devices/system/cpu/vulnerabilities/*; do
        if [[ -f "$vuln_file" ]] && grep -qi "vulnerable" "$vuln_file" 2>/dev/null; then
            echo "  [WARN] CPU vuln: $(basename "$vuln_file"): $(cat "$vuln_file" 2>/dev/null)"
            KERNEL_ISSUES=$((KERNEL_ISSUES + 1))
        fi
    done
fi

if [[ -f /var/run/reboot-required ]]; then
    echo "  [WARN] Reinicio pendiente para nuevo kernel"
    KERNEL_ISSUES=$((KERNEL_ISSUES + 1))
fi

if [[ $KERNEL_ISSUES -eq 0 ]]; then
    echo "  Kernel seguro"
    audit_check "A7" "Seguridad del kernel" 10 "pass"
elif [[ $KERNEL_ISSUES -le 2 ]]; then
    audit_check "A7" "Seguridad del kernel ($KERNEL_ISSUES issues)" 10 "partial"
else
    audit_check "A7" "Seguridad del kernel ($KERNEL_ISSUES issues)" 10 "fail"
fi
echo ""

# --- A8: Emergency procedures ---
echo "[A8] Procedimientos de emergencia"
if [[ -x "$PATCH_BIN/parche-emergencia.sh" ]]; then
    echo "  Script de emergencia: INSTALADO"
    audit_check "A8" "Procedimiento de emergencia disponible" 5 "pass"
else
    echo "  Script de emergencia: NO INSTALADO"
    audit_check "A8" "Procedimiento de emergencia" 5 "fail"
fi
echo ""

# --- A9: Dependency scanning ---
echo "[A9] Escaneo de dependencias"
if [[ -x "$PATCH_BIN/escanear-dependencias.sh" ]]; then
    echo "  Script de dependencias: INSTALADO"
    audit_check "A9" "Escaneo de dependencias configurado" 10 "pass"
else
    echo "  Script de dependencias: NO INSTALADO"
    audit_check "A9" "Escaneo de dependencias" 10 "fail"
fi
echo ""

# --- A10: Staging/rollback ---
echo "[A10] Staging y rollback"
HAS_STAGING="false"
HAS_ROLLBACK="false"
[[ -x "$PATCH_BIN/securizar-patch-test.sh" ]] && HAS_STAGING="true"
[[ -x "$PATCH_BIN/securizar-patch-rollback.sh" ]] && HAS_ROLLBACK="true"

if [[ "$HAS_STAGING" == "true" ]] && [[ "$HAS_ROLLBACK" == "true" ]]; then
    echo "  Staging: DISPONIBLE"
    echo "  Rollback: DISPONIBLE"
    audit_check "A10" "Staging y rollback configurados" 10 "pass"
elif [[ "$HAS_STAGING" == "true" ]] || [[ "$HAS_ROLLBACK" == "true" ]]; then
    echo "  Staging: $HAS_STAGING"
    echo "  Rollback: $HAS_ROLLBACK"
    audit_check "A10" "Staging y rollback" 10 "partial" "Falta un componente"
else
    echo "  Staging y rollback no configurados"
    audit_check "A10" "Staging y rollback" 10 "fail"
fi
echo ""

# --- Final score ---
PERCENTAGE=0
if [[ $MAX_POINTS -gt 0 ]]; then
    PERCENTAGE=$(( (TOTAL_POINTS * 100) / MAX_POINTS ))
fi

GRADE=""
if [[ $PERCENTAGE -ge 90 ]]; then
    GRADE="EXCELENTE"
elif [[ $PERCENTAGE -ge 70 ]]; then
    GRADE="BUENO"
elif [[ $PERCENTAGE -ge 50 ]]; then
    GRADE="MEJORABLE"
else
    GRADE="DEFICIENTE"
fi

echo "================================================================"
echo " RESULTADO DE LA AUDITORIA"
echo "================================================================"
echo ""
echo "  Puntuacion: $TOTAL_POINTS / $MAX_POINTS ($PERCENTAGE%)"
echo ""
echo "  Calificacion: $GRADE"
echo ""
echo "  Detalle:"
echo -e "$SECTION_RESULTS"
echo ""
echo "================================================================"
echo " ESCALA DE CALIFICACION:"
echo "   90-100%  EXCELENTE  - Gestion de parches ejemplar"
echo "   70-89%   BUENO      - Buen nivel, mejoras menores"
echo "   50-69%   MEJORABLE  - Necesita atencion en varias areas"
echo "   0-49%    DEFICIENTE - Accion urgente requerida"
echo "================================================================"

} 2>&1 | tee "$REPORT"

echo ""
echo "Reporte guardado en: $REPORT"
ln -sf "$REPORT" "$AUDIT_DIR/patch-audit-latest.txt" || true
ls -1t "$AUDIT_DIR"/patch-audit-2*.txt 2>/dev/null | tail -n +31 | xargs rm -f 2>/dev/null || true
EOF
    chmod 0750 "$PATCH_BIN/auditar-parches.sh"
    log_change "Creado" "auditor integral de parches en $PATCH_BIN/auditar-parches.sh"

else
    log_skip "Auditoria integral de gestion de parches"
fi

# ============================================================
# Resumen final
# ============================================================
show_changes_summary
