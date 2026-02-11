#!/bin/bash
# ============================================================
# gestion-parches.sh — Módulo 61: Gestión de parches
# ============================================================
# Escaneo CVE, auto-patch, SBOM, staging de actualizaciones
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/securizar-common.sh"
source "$SCRIPT_DIR/lib/securizar-distro.sh"
source "$SCRIPT_DIR/lib/securizar-pkg.sh"

CHANGES=()

show_changes_summary() {
    echo ""
    if [[ ${#CHANGES[@]} -eq 0 ]]; then
        log_info "No se realizaron cambios"
        return 0
    fi
    log_section "RESUMEN DE CAMBIOS"
    local i=1
    for change in "${CHANGES[@]}"; do
        log_info "  $i. $change"
        ((i++))
    done
    echo ""
    log_info "Total: ${#CHANGES[@]} cambios aplicados"
}

# ── Sección 1: Inventario de paquetes instalados ──
section_1() {
    log_section "1. Inventario de paquetes instalados"

    ask "¿Crear sistema de inventario de paquetes con versiones?" || { log_skip "Inventario de paquetes omitido"; return 0; }

    mkdir -p /var/log/securizar /etc/securizar/patches

    # Script de inventario
    cat > /usr/local/bin/securizar-pkg-inventory.sh << 'EOF'
#!/bin/bash
# ============================================================
# securizar-pkg-inventory.sh — Inventario de paquetes instalados
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar"
mkdir -p "$LOG_DIR"

FECHA=$(date +%Y%m%d)
HORA=$(date +%H%M%S)
OUTFILE="$LOG_DIR/pkg-inventory-${FECHA}.txt"
JSONFILE="$LOG_DIR/pkg-inventory-${FECHA}.json"

echo "========================================" > "$OUTFILE"
echo " Inventario de paquetes - $(date)" >> "$OUTFILE"
echo " Host: $(hostname)" >> "$OUTFILE"
echo "========================================" >> "$OUTFILE"
echo "" >> "$OUTFILE"

# Detectar gestor de paquetes
detect_pkg_manager() {
    if command -v rpm &>/dev/null && command -v zypper &>/dev/null; then
        echo "suse"
    elif command -v dpkg &>/dev/null && command -v apt &>/dev/null; then
        echo "debian"
    elif command -v rpm &>/dev/null && (command -v dnf &>/dev/null || command -v yum &>/dev/null); then
        echo "rhel"
    elif command -v pacman &>/dev/null; then
        echo "arch"
    else
        echo "unknown"
    fi
}

PKG_MGR=$(detect_pkg_manager)

echo "Gestor de paquetes: $PKG_MGR" >> "$OUTFILE"
echo "" >> "$OUTFILE"

TOTAL=0
echo "{" > "$JSONFILE"
echo "  \"timestamp\": \"$(date -Iseconds)\"," >> "$JSONFILE"
echo "  \"hostname\": \"$(hostname)\"," >> "$JSONFILE"
echo "  \"pkg_manager\": \"$PKG_MGR\"," >> "$JSONFILE"
echo "  \"packages\": [" >> "$JSONFILE"

FIRST=true

case "$PKG_MGR" in
    suse|rhel)
        while IFS='|' read -r name version arch repo; do
            echo "$name  $version  $arch  $repo" >> "$OUTFILE"
            if $FIRST; then
                FIRST=false
            else
                echo "," >> "$JSONFILE"
            fi
            printf '    {"name":"%s","version":"%s","arch":"%s","repo":"%s"}' \
                "$name" "$version" "$arch" "$repo" >> "$JSONFILE"
            ((TOTAL++))
        done < <(rpm -qa --queryformat '%{NAME}|%{VERSION}-%{RELEASE}|%{ARCH}|%{VENDOR}\n' | sort)
        ;;
    debian)
        while IFS='|' read -r name version arch; do
            echo "$name  $version  $arch" >> "$OUTFILE"
            if $FIRST; then
                FIRST=false
            else
                echo "," >> "$JSONFILE"
            fi
            printf '    {"name":"%s","version":"%s","arch":"%s"}' \
                "$name" "$version" "$arch" >> "$JSONFILE"
            ((TOTAL++))
        done < <(dpkg-query -W -f='${Package}|${Version}|${Architecture}\n' 2>/dev/null | sort)
        ;;
    arch)
        while IFS=' ' read -r name version; do
            echo "$name  $version" >> "$OUTFILE"
            if $FIRST; then
                FIRST=false
            else
                echo "," >> "$JSONFILE"
            fi
            printf '    {"name":"%s","version":"%s"}' \
                "$name" "$version" >> "$JSONFILE"
            ((TOTAL++))
        done < <(pacman -Q 2>/dev/null | sort)
        ;;
    *)
        echo "Gestor de paquetes no soportado" >> "$OUTFILE"
        ;;
esac

echo "" >> "$JSONFILE"
echo "  ]," >> "$JSONFILE"
echo "  \"total_packages\": $TOTAL" >> "$JSONFILE"
echo "}" >> "$JSONFILE"

echo "" >> "$OUTFILE"
echo "Total paquetes: $TOTAL" >> "$OUTFILE"
echo "Inventario generado: $OUTFILE"
echo "Inventario JSON: $JSONFILE"

# Comparar con inventario anterior si existe
PREV=$(ls -1t "$LOG_DIR"/pkg-inventory-*.txt 2>/dev/null | sed -n '2p')
if [[ -n "${PREV:-}" ]]; then
    echo ""
    echo "=== Cambios desde último inventario ==="
    ADDED=$(comm -13 <(awk '{print $1}' "$PREV" | sort) <(awk '{print $1}' "$OUTFILE" | sort) | grep -v '^$' | grep -v '^=' || true)
    REMOVED=$(comm -23 <(awk '{print $1}' "$PREV" | sort) <(awk '{print $1}' "$OUTFILE" | sort) | grep -v '^$' | grep -v '^=' || true)
    if [[ -n "$ADDED" ]]; then
        echo "Paquetes añadidos:"
        echo "$ADDED" | while read -r pkg; do echo "  + $pkg"; done
    fi
    if [[ -n "$REMOVED" ]]; then
        echo "Paquetes eliminados:"
        echo "$REMOVED" | while read -r pkg; do echo "  - $pkg"; done
    fi
    if [[ -z "$ADDED" && -z "$REMOVED" ]]; then
        echo "Sin cambios en los paquetes instalados"
    fi
fi

# Retención: mantener 30 días
find "$LOG_DIR" -name 'pkg-inventory-*.txt' -mtime +30 -delete 2>/dev/null || true
find "$LOG_DIR" -name 'pkg-inventory-*.json' -mtime +30 -delete 2>/dev/null || true
EOF
    chmod +x /usr/local/bin/securizar-pkg-inventory.sh

    # Cron diario
    cat > /etc/cron.daily/securizar-pkg-inventory << 'EOF'
#!/bin/bash
/usr/local/bin/securizar-pkg-inventory.sh >> /var/log/securizar/pkg-inventory-cron.log 2>&1
EOF
    chmod +x /etc/cron.daily/securizar-pkg-inventory

    # Ejecutar primer inventario
    log_info "Ejecutando primer inventario de paquetes..."
    /usr/local/bin/securizar-pkg-inventory.sh > /dev/null 2>&1 || true

    log_change "Sistema de inventario de paquetes configurado"
    CHANGES+=("Sección 1: Inventario de paquetes con cron diario")
}

# ── Sección 2: Escaneo de vulnerabilidades CVE ──
section_2() {
    log_section "2. Escaneo de vulnerabilidades CVE"

    ask "¿Configurar escaneo de vulnerabilidades CVE en paquetes?" || { log_skip "Escaneo CVE omitido"; return 0; }

    mkdir -p /var/log/securizar /etc/securizar/patches

    cat > /usr/local/bin/securizar-cve-scan.sh << 'EOFCVE'
#!/bin/bash
# ============================================================
# securizar-cve-scan.sh — Escaneo de vulnerabilidades CVE
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar"
mkdir -p "$LOG_DIR"

FECHA=$(date +%Y%m%d)
LOGFILE="$LOG_DIR/cve-scan-${FECHA}.log"
SEVERITY_FILTER="${1:-all}"

{
echo "=========================================="
echo " Escaneo CVE - $(date)"
echo " Host: $(hostname)"
echo " Filtro: $SEVERITY_FILTER"
echo "=========================================="
echo ""

detect_pkg_manager() {
    if command -v zypper &>/dev/null; then echo "suse"
    elif command -v apt &>/dev/null; then echo "debian"
    elif command -v dnf &>/dev/null; then echo "rhel"
    elif command -v yum &>/dev/null; then echo "rhel"
    elif command -v pacman &>/dev/null; then echo "arch"
    else echo "unknown"; fi
}

PKG_MGR=$(detect_pkg_manager)
TOTAL_CVES=0
CRITICAL=0
HIGH=0
MEDIUM=0
LOW=0

case "$PKG_MGR" in
    suse)
        echo "=== Parches de seguridad disponibles (zypper) ==="
        echo ""

        # Listar parches de seguridad
        if zypper list-patches --category security 2>/dev/null; then
            TOTAL_CVES=$(zypper list-patches --category security 2>/dev/null | grep -c '|' || echo "0")
        fi

        # Detalles de CVEs
        echo ""
        echo "=== CVEs referenciados ==="
        zypper list-patches --category security --with-optional 2>/dev/null | \
            grep -oE 'CVE-[0-9]{4}-[0-9]+' | sort -u | while read -r cve; do
            echo "  $cve"
            ((TOTAL_CVES++)) || true
        done

        # Parches por severidad
        CRITICAL=$(zypper list-patches --category security --severity critical 2>/dev/null | grep -c '|' || echo "0")
        HIGH=$(zypper list-patches --category security --severity important 2>/dev/null | grep -c '|' || echo "0")
        ;;

    debian)
        echo "=== Actualizaciones de seguridad disponibles (apt) ==="
        echo ""

        # Actualizar listas si son antiguas
        LISTS_AGE=999
        if [[ -f /var/lib/apt/lists/lock ]]; then
            LISTS_AGE=$(( ($(date +%s) - $(stat -c %Y /var/lib/apt/lists/lock)) / 3600 ))
        fi
        if [[ $LISTS_AGE -gt 24 ]]; then
            echo "[INFO] Actualizando listas de paquetes..."
            apt-get update -qq 2>/dev/null || true
        fi

        # Paquetes con actualizaciones de seguridad
        echo "Paquetes con actualizaciones de seguridad:"
        if command -v apt-get &>/dev/null; then
            apt-get -s upgrade 2>/dev/null | grep -i 'security' | head -50 || true
        fi

        echo ""
        echo "Actualizaciones pendientes:"
        apt list --upgradable 2>/dev/null | grep -i 'security\|esm\|CVE' | while read -r line; do
            echo "  $line"
            ((TOTAL_CVES++)) || true
        done

        # Buscar CVEs en changelogs de paquetes actualizables
        echo ""
        echo "=== CVEs en changelogs ==="
        apt list --upgradable 2>/dev/null | tail -n +2 | cut -d'/' -f1 | head -20 | while read -r pkg; do
            if [[ -n "$pkg" ]]; then
                CVES=$(apt-get changelog "$pkg" 2>/dev/null | grep -oE 'CVE-[0-9]{4}-[0-9]+' | sort -u | head -5)
                if [[ -n "$CVES" ]]; then
                    echo "  $pkg: $CVES"
                fi
            fi
        done
        ;;

    rhel)
        echo "=== Actualizaciones de seguridad (yum/dnf) ==="
        echo ""

        CMD="yum"
        command -v dnf &>/dev/null && CMD="dnf"

        echo "Avisos de seguridad:"
        $CMD updateinfo list security 2>/dev/null | while read -r line; do
            echo "  $line"
            ((TOTAL_CVES++)) || true
        done

        echo ""
        echo "=== CVEs pendientes ==="
        $CMD updateinfo list cves 2>/dev/null | while read -r line; do
            echo "  $line"
        done

        # Severidades
        CRITICAL=$($CMD updateinfo list security --severity Critical 2>/dev/null | grep -c '^' || echo "0")
        HIGH=$($CMD updateinfo list security --severity Important 2>/dev/null | grep -c '^' || echo "0")
        MEDIUM=$($CMD updateinfo list security --severity Moderate 2>/dev/null | grep -c '^' || echo "0")
        LOW=$($CMD updateinfo list security --severity Low 2>/dev/null | grep -c '^' || echo "0")
        ;;

    arch)
        echo "=== Verificación de seguridad (Arch Linux) ==="
        echo ""

        if command -v arch-audit &>/dev/null; then
            echo "Paquetes vulnerables (arch-audit):"
            arch-audit 2>/dev/null | while read -r line; do
                echo "  $line"
                ((TOTAL_CVES++)) || true
            done
        else
            echo "[WARN] arch-audit no instalado. Instalar con: pacman -S arch-audit"
            echo ""
            echo "Verificando actualizaciones pendientes:"
            pacman -Qu 2>/dev/null | while read -r line; do
                echo "  $line"
                ((TOTAL_CVES++)) || true
            done
        fi
        ;;

    *)
        echo "[ERROR] Gestor de paquetes no soportado"
        ;;
esac

echo ""
echo "=========================================="
echo " Resumen de escaneo CVE"
echo "=========================================="
echo " Total vulnerabilidades: $TOTAL_CVES"
echo " Críticas: $CRITICAL"
echo " Altas: $HIGH"
echo " Medias: $MEDIUM"
echo " Bajas: $LOW"
echo ""
echo " Escaneado: $(date)"
echo "=========================================="

if [[ $CRITICAL -gt 0 ]]; then
    echo ""
    echo "*** ALERTA: Hay $CRITICAL vulnerabilidades CRÍTICAS pendientes ***"
    echo "*** Ejecutar actualizaciones de seguridad lo antes posible ***"
fi
} 2>&1 | tee "$LOGFILE"

echo ""
echo "Reporte guardado en: $LOGFILE"
EOFCVE
    chmod +x /usr/local/bin/securizar-cve-scan.sh

    # Cron semanal
    cat > /etc/cron.weekly/securizar-cve-scan << 'EOF'
#!/bin/bash
/usr/local/bin/securizar-cve-scan.sh >> /var/log/securizar/cve-scan-cron.log 2>&1
EOF
    chmod +x /etc/cron.weekly/securizar-cve-scan

    log_change "Escáner CVE configurado con reporte semanal"
    CHANGES+=("Sección 2: Escaneo CVE con soporte multi-distro")
}

# ── Sección 3: Actualizaciones automáticas de seguridad ──
section_3() {
    log_section "3. Actualizaciones automáticas de seguridad"

    ask "¿Configurar actualizaciones automáticas solo de seguridad?" || { log_skip "Auto-actualizaciones omitidas"; return 0; }

    mkdir -p /etc/securizar/patches

    case "${DISTRO_FAMILY:-unknown}" in
        suse)
            log_info "Configurando actualizaciones automáticas para SUSE..."

            # Timer systemd para actualizaciones de seguridad
            cat > /etc/systemd/system/securizar-auto-patch.service << 'EOF'
[Unit]
Description=Securizar - Actualizaciones automáticas de seguridad
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/securizar-auto-patch.sh
StandardOutput=journal
StandardError=journal
TimeoutStartSec=3600
EOF

            cat > /etc/systemd/system/securizar-auto-patch.timer << 'EOF'
[Unit]
Description=Securizar - Timer para actualizaciones de seguridad (semanal)

[Timer]
OnCalendar=Sun *-*-* 03:00:00
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
EOF

            cat > /usr/local/bin/securizar-auto-patch.sh << 'EOFPATCH'
#!/bin/bash
set -euo pipefail
LOG="/var/log/securizar/auto-patch-$(date +%Y%m%d).log"
mkdir -p /var/log/securizar
{
    echo "=== Auto-patch de seguridad: $(date) ==="
    echo ""

    # Crear snapshot previo si snapper disponible
    if command -v snapper &>/dev/null; then
        SNAP_ID=$(snapper create --type pre --print-number --description "securizar-auto-patch" 2>/dev/null || echo "")
        echo "Snapshot pre-patch: $SNAP_ID"
    fi

    # Guardar estado previo
    rpm -qa --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' | sort > /var/log/securizar/pre-patch-state.txt

    echo "Aplicando parches de seguridad..."
    zypper --non-interactive patch --category security --auto-agree-with-licenses 2>&1 || true

    # Guardar estado posterior
    rpm -qa --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' | sort > /var/log/securizar/post-patch-state.txt

    # Mostrar diferencias
    echo ""
    echo "=== Paquetes actualizados ==="
    diff /var/log/securizar/pre-patch-state.txt /var/log/securizar/post-patch-state.txt || true

    # Cerrar snapshot
    if command -v snapper &>/dev/null && [[ -n "${SNAP_ID:-}" ]]; then
        snapper create --type post --pre-number "$SNAP_ID" --description "securizar-auto-patch" 2>/dev/null || true
    fi

    echo ""
    echo "Auto-patch completado: $(date)"
} 2>&1 | tee -a "$LOG"
EOFPATCH
            chmod +x /usr/local/bin/securizar-auto-patch.sh
            systemctl daemon-reload
            systemctl enable securizar-auto-patch.timer 2>/dev/null || true
            systemctl start securizar-auto-patch.timer 2>/dev/null || true
            ;;

        debian)
            log_info "Configurando unattended-upgrades para Debian/Ubuntu..."

            pkg_install unattended-upgrades 2>/dev/null || true

            mkdir -p /etc/apt/apt.conf.d

            cat > /etc/apt/apt.conf.d/50securizar-unattended << 'EOF'
// Securizar - Actualizaciones automáticas de seguridad
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};

Unattended-Upgrade::Package-Blacklist {
};

Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "false";
Unattended-Upgrade::Remove-New-Unused-Dependencies "false";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::SyslogEnable "true";
Unattended-Upgrade::SyslogFacility "daemon";
EOF

            cat > /etc/apt/apt.conf.d/20securizar-auto << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
EOF
            ;;

        rhel)
            log_info "Configurando dnf-automatic/yum-cron para RHEL/CentOS..."

            if command -v dnf &>/dev/null; then
                pkg_install dnf-automatic 2>/dev/null || true

                if [[ -f /etc/dnf/automatic.conf ]]; then
                    cp -a /etc/dnf/automatic.conf "$BACKUP_DIR/" 2>/dev/null || true
                fi

                mkdir -p /etc/dnf

                cat > /etc/dnf/automatic.conf << 'EOF'
[commands]
upgrade_type = security
random_sleep = 300
download_updates = yes
apply_updates = yes

[emitters]
system_name = securizar
emit_via = stdio

[email]
email_from = root@localhost
email_to = root
email_host = localhost
EOF
                systemctl enable dnf-automatic.timer 2>/dev/null || true
                systemctl start dnf-automatic.timer 2>/dev/null || true
            else
                pkg_install yum-cron 2>/dev/null || true
                if [[ -f /etc/yum/yum-cron.conf ]]; then
                    cp -a /etc/yum/yum-cron.conf "$BACKUP_DIR/" 2>/dev/null || true
                    sed -i 's/^update_cmd.*/update_cmd = security/' /etc/yum/yum-cron.conf
                    sed -i 's/^apply_updates.*/apply_updates = yes/' /etc/yum/yum-cron.conf
                fi
                systemctl enable yum-cron 2>/dev/null || true
                systemctl start yum-cron 2>/dev/null || true
            fi
            ;;

        arch)
            log_info "Configurando timer de actualización para Arch..."

            cat > /etc/systemd/system/securizar-auto-patch.service << 'EOF'
[Unit]
Description=Securizar - Actualizaciones automáticas
After=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'pacman -Syu --noconfirm >> /var/log/securizar/auto-patch.log 2>&1'
EOF

            cat > /etc/systemd/system/securizar-auto-patch.timer << 'EOF'
[Unit]
Description=Securizar - Timer actualizaciones semanales

[Timer]
OnCalendar=Sun *-*-* 03:00:00
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
EOF
            systemctl daemon-reload
            systemctl enable securizar-auto-patch.timer 2>/dev/null || true
            ;;

        *)
            log_warn "Distro no reconocida para auto-actualizaciones"
            ;;
    esac

    log_change "Actualizaciones automáticas de seguridad configuradas"
    CHANGES+=("Sección 3: Auto-actualizaciones de seguridad (${DISTRO_FAMILY:-unknown})")
}

# ── Sección 4: Staging de actualizaciones ──
section_4() {
    log_section "4. Staging de actualizaciones"

    ask "¿Configurar staging de parches para revisión antes de aplicar?" || { log_skip "Staging omitido"; return 0; }

    mkdir -p /var/cache/securizar/staging /var/log/securizar

    cat > /usr/local/bin/securizar-patch-staging.sh << 'EOFSTAG'
#!/bin/bash
# ============================================================
# securizar-patch-staging.sh — Descarga sin instalar para revisión
# ============================================================
set -euo pipefail

STAGING_DIR="/var/cache/securizar/staging"
LOG_DIR="/var/log/securizar"
mkdir -p "$STAGING_DIR" "$LOG_DIR"

FECHA=$(date +%Y%m%d)
REPORT="$LOG_DIR/staging-report-${FECHA}.txt"
ACTION="${1:-download}"

detect_pkg_manager() {
    if command -v zypper &>/dev/null; then echo "suse"
    elif command -v apt &>/dev/null; then echo "debian"
    elif command -v dnf &>/dev/null; then echo "rhel"
    elif command -v yum &>/dev/null; then echo "rhel"
    elif command -v pacman &>/dev/null; then echo "arch"
    else echo "unknown"; fi
}

PKG_MGR=$(detect_pkg_manager)

{
echo "=========================================="
echo " Staging de actualizaciones - $(date)"
echo " Acción: $ACTION"
echo "=========================================="
echo ""

case "$ACTION" in
    download)
        echo "Descargando actualizaciones sin instalar..."
        echo ""

        case "$PKG_MGR" in
            suse)
                zypper --non-interactive download-only patch --category security 2>&1 || true
                echo ""
                echo "Parches descargados. Revisar con:"
                echo "  zypper list-patches --category security"
                ;;
            debian)
                apt-get update -qq 2>/dev/null || true
                apt-get -d -y upgrade 2>&1 || true
                echo ""
                echo "Paquetes descargados en /var/cache/apt/archives/"
                echo "Revisar con: apt list --upgradable"
                ls -lh /var/cache/apt/archives/*.deb 2>/dev/null | tail -20 || true
                ;;
            rhel)
                CMD="yum"
                command -v dnf &>/dev/null && CMD="dnf"
                $CMD -y --downloadonly update --security 2>&1 || true
                echo ""
                echo "Paquetes descargados. Revisar con:"
                echo "  $CMD updateinfo list security"
                ;;
            arch)
                pacman -Syuw --noconfirm 2>&1 || true
                echo ""
                echo "Paquetes descargados en /var/cache/pacman/pkg/"
                ;;
        esac
        ;;

    review)
        echo "=== Actualizaciones pendientes de aplicar ==="
        echo ""

        case "$PKG_MGR" in
            suse)
                zypper list-patches --category security 2>/dev/null || true
                echo ""
                zypper list-updates 2>/dev/null || true
                ;;
            debian)
                apt list --upgradable 2>/dev/null || true
                ;;
            rhel)
                CMD="yum"
                command -v dnf &>/dev/null && CMD="dnf"
                $CMD check-update --security 2>/dev/null || true
                ;;
            arch)
                pacman -Qu 2>/dev/null || true
                ;;
        esac
        ;;

    apply)
        echo "*** Aplicando actualizaciones de staging ***"
        echo ""

        # Guardar estado previo
        echo "Guardando estado previo..."
        case "$PKG_MGR" in
            suse|rhel)
                rpm -qa --queryformat '%{NAME}-%{VERSION}-%{RELEASE}\n' | sort > "$STAGING_DIR/pre-apply.txt"
                ;;
            debian)
                dpkg-query -W -f='${Package} ${Version}\n' | sort > "$STAGING_DIR/pre-apply.txt"
                ;;
            arch)
                pacman -Q | sort > "$STAGING_DIR/pre-apply.txt"
                ;;
        esac

        case "$PKG_MGR" in
            suse)  zypper --non-interactive patch --category security --auto-agree-with-licenses 2>&1 || true ;;
            debian) apt-get -y upgrade 2>&1 || true ;;
            rhel)
                CMD="yum"
                command -v dnf &>/dev/null && CMD="dnf"
                $CMD -y update --security 2>&1 || true
                ;;
            arch)   pacman -Su --noconfirm 2>&1 || true ;;
        esac

        echo ""
        echo "Actualizaciones aplicadas."
        ;;

    *)
        echo "Uso: $0 {download|review|apply}"
        echo ""
        echo "  download  - Descargar sin instalar"
        echo "  review    - Revisar pendientes"
        echo "  apply     - Aplicar actualizaciones descargadas"
        ;;
esac

echo ""
echo "Completado: $(date)"
} 2>&1 | tee "$REPORT"

echo "Reporte: $REPORT"
EOFSTAG
    chmod +x /usr/local/bin/securizar-patch-staging.sh

    log_change "Sistema de staging de parches configurado"
    CHANGES+=("Sección 4: Staging de actualizaciones para revisión previa")
}

# ── Sección 5: Generación de SBOM ──
section_5() {
    log_section "5. Generación de SBOM (Software Bill of Materials)"

    ask "¿Configurar generación automática de SBOM?" || { log_skip "SBOM omitido"; return 0; }

    mkdir -p /var/log/securizar

    cat > /usr/local/bin/securizar-sbom-gen.sh << 'EOFSBOM'
#!/bin/bash
# ============================================================
# securizar-sbom-gen.sh — Genera SBOM en formato CycloneDX-like
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar"
mkdir -p "$LOG_DIR"

FECHA=$(date +%Y%m%d)
OUTFILE="$LOG_DIR/sbom-${FECHA}.json"

detect_pkg_manager() {
    if command -v zypper &>/dev/null; then echo "suse"
    elif command -v apt &>/dev/null; then echo "debian"
    elif command -v dnf &>/dev/null || command -v yum &>/dev/null; then echo "rhel"
    elif command -v pacman &>/dev/null; then echo "arch"
    else echo "unknown"; fi
}

PKG_MGR=$(detect_pkg_manager)

# Header CycloneDX-like
cat > "$OUTFILE" << EOFHEADER
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "metadata": {
    "timestamp": "$(date -Iseconds)",
    "tools": [
      {
        "vendor": "Securizar",
        "name": "securizar-sbom-gen",
        "version": "1.0.0"
      }
    ],
    "component": {
      "type": "operating-system",
      "name": "$(hostname)",
      "version": "$(uname -r)"
    }
  },
  "components": [
EOFHEADER

FIRST=true
TOTAL=0

emit_component() {
    local name="$1" version="$2" arch="${3:-}" repo="${4:-}" ptype="${5:-library}"
    if $FIRST; then
        FIRST=false
    else
        echo "," >> "$OUTFILE"
    fi
    cat >> "$OUTFILE" << EOFCOMP
    {
      "type": "$ptype",
      "name": "$name",
      "version": "$version",
      "purl": "pkg:$PKG_MGR/$name@$version",
      "properties": [
        {"name": "arch", "value": "$arch"},
        {"name": "repository", "value": "$repo"}
      ]
    }
EOFCOMP
    ((TOTAL++))
}

case "$PKG_MGR" in
    suse|rhel)
        while IFS='|' read -r name version arch vendor; do
            emit_component "$name" "$version" "$arch" "$vendor"
        done < <(rpm -qa --queryformat '%{NAME}|%{VERSION}-%{RELEASE}|%{ARCH}|%{VENDOR}\n' 2>/dev/null | sort)
        ;;
    debian)
        while IFS='|' read -r name version arch; do
            emit_component "$name" "$version" "$arch" ""
        done < <(dpkg-query -W -f='${Package}|${Version}|${Architecture}\n' 2>/dev/null | sort)
        ;;
    arch)
        while IFS=' ' read -r name version; do
            emit_component "$name" "$version" "" ""
        done < <(pacman -Q 2>/dev/null | sort)
        ;;
esac

# Incluir kernel modules
echo "" >> "$OUTFILE"

# Footer
cat >> "$OUTFILE" << EOFFOOTER
  ],
  "dependencies": [],
  "totalComponents": $TOTAL
}
EOFFOOTER

echo "SBOM generado: $OUTFILE"
echo "Total componentes: $TOTAL"
echo "Formato: CycloneDX 1.4 (JSON)"

# Retención 90 días
find "$LOG_DIR" -name 'sbom-*.json' -mtime +90 -delete 2>/dev/null || true

# Comparar con SBOM anterior
PREV=$(ls -1t "$LOG_DIR"/sbom-*.json 2>/dev/null | sed -n '2p')
if [[ -n "${PREV:-}" ]]; then
    echo ""
    echo "=== Cambios desde último SBOM ==="
    PREV_COUNT=$(grep -c '"name":' "$PREV" 2>/dev/null || echo "0")
    echo "SBOM anterior: $PREV_COUNT componentes"
    echo "SBOM actual: $TOTAL componentes"
    DIFF=$((TOTAL - PREV_COUNT))
    if [[ $DIFF -gt 0 ]]; then
        echo "Diferencia: +$DIFF componentes"
    elif [[ $DIFF -lt 0 ]]; then
        echo "Diferencia: $DIFF componentes"
    else
        echo "Sin cambios en el número de componentes"
    fi
fi
EOFSBOM
    chmod +x /usr/local/bin/securizar-sbom-gen.sh

    # Cron mensual
    cat > /etc/cron.monthly/securizar-sbom << 'EOF'
#!/bin/bash
/usr/local/bin/securizar-sbom-gen.sh >> /var/log/securizar/sbom-cron.log 2>&1
EOF
    chmod +x /etc/cron.monthly/securizar-sbom

    log_change "Generador de SBOM configurado con cron mensual"
    CHANGES+=("Sección 5: SBOM CycloneDX con inventario mensual")
}

# ── Sección 6: Política de rollback ──
section_6() {
    log_section "6. Política de rollback"

    ask "¿Configurar herramientas de rollback de parches?" || { log_skip "Rollback omitido"; return 0; }

    mkdir -p /var/log/securizar /etc/securizar/patches

    cat > /usr/local/bin/securizar-patch-rollback.sh << 'EOFROLL'
#!/bin/bash
# ============================================================
# securizar-patch-rollback.sh — Rollback de actualizaciones
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar"
mkdir -p "$LOG_DIR"

ACTION="${1:-status}"

detect_pkg_manager() {
    if command -v zypper &>/dev/null; then echo "suse"
    elif command -v apt &>/dev/null; then echo "debian"
    elif command -v dnf &>/dev/null || command -v yum &>/dev/null; then echo "rhel"
    elif command -v pacman &>/dev/null; then echo "arch"
    else echo "unknown"; fi
}

PKG_MGR=$(detect_pkg_manager)

case "$ACTION" in
    snapshot)
        echo "=== Creando snapshot pre-parche ==="

        # Guardar lista de paquetes con versiones
        STATE_FILE="$LOG_DIR/pre-patch-state-$(date +%Y%m%d-%H%M%S).txt"

        case "$PKG_MGR" in
            suse|rhel)
                rpm -qa --queryformat '%{NAME} %{VERSION}-%{RELEASE}.%{ARCH}\n' | sort > "$STATE_FILE"
                ;;
            debian)
                dpkg-query -W -f='${Package} ${Version}\n' | sort > "$STATE_FILE"
                ;;
            arch)
                pacman -Q | sort > "$STATE_FILE"
                ;;
        esac

        echo "Estado guardado: $STATE_FILE"

        # Snapper si disponible
        if command -v snapper &>/dev/null; then
            SNAP_ID=$(snapper create --type pre --print-number --description "securizar-pre-patch" 2>/dev/null || echo "")
            if [[ -n "$SNAP_ID" ]]; then
                echo "Snapshot snapper: #$SNAP_ID"
                echo "$SNAP_ID" > "$LOG_DIR/last-snapper-pre.txt"
            fi
        fi
        ;;

    rollback)
        echo "=== Rollback de última actualización ==="
        echo ""

        case "$PKG_MGR" in
            suse)
                if command -v snapper &>/dev/null; then
                    echo "Snapshots disponibles:"
                    snapper list | tail -10
                    echo ""
                    if [[ -f "$LOG_DIR/last-snapper-pre.txt" ]]; then
                        PRE_ID=$(cat "$LOG_DIR/last-snapper-pre.txt")
                        echo "Último snapshot pre-parche: #$PRE_ID"
                        echo "Para rollback ejecutar:"
                        echo "  snapper undochange $PRE_ID..0"
                    fi
                else
                    echo "snapper no disponible"
                    echo "Usar: zypper install -f PAQUETE=VERSION_ANTERIOR"
                fi
                ;;
            debian)
                STATE_FILE=$(ls -1t "$LOG_DIR"/pre-patch-state-*.txt 2>/dev/null | head -1)
                if [[ -n "${STATE_FILE:-}" ]]; then
                    echo "Estado previo: $STATE_FILE"
                    echo ""
                    echo "Para revertir paquetes específicos:"
                    echo "  apt install PAQUETE=VERSION"
                    echo ""
                    echo "Paquetes modificados desde snapshot:"
                    CURRENT=$(mktemp)
                    dpkg-query -W -f='${Package} ${Version}\n' | sort > "$CURRENT"
                    diff "$STATE_FILE" "$CURRENT" | grep '^[<>]' | head -20 || echo "Sin diferencias"
                    rm -f "$CURRENT"
                else
                    echo "No hay snapshots de estado previo"
                fi
                ;;
            rhel)
                CMD="yum"
                command -v dnf &>/dev/null && CMD="dnf"
                echo "Historial de transacciones:"
                $CMD history list last-5 2>/dev/null || true
                echo ""
                echo "Para rollback ejecutar:"
                echo "  $CMD history undo <ID>"
                ;;
            arch)
                if [[ -d /var/cache/pacman/pkg ]]; then
                    echo "Cache de paquetes disponible en /var/cache/pacman/pkg/"
                    echo "Para rollback: pacman -U /var/cache/pacman/pkg/PAQUETE-VERSION.pkg.tar.zst"
                fi
                ;;
        esac
        ;;

    status|*)
        echo "=== Estado de rollback ==="
        echo ""
        echo "Snapshots de estado disponibles:"
        ls -lt "$LOG_DIR"/pre-patch-state-*.txt 2>/dev/null | head -5 || echo "  Ninguno"
        echo ""

        if command -v snapper &>/dev/null; then
            echo "Snapshots snapper:"
            snapper list 2>/dev/null | tail -5 || echo "  No disponible"
        fi

        echo ""
        echo "Uso: $0 {snapshot|rollback|status}"
        echo "  snapshot  - Crear punto de restauración"
        echo "  rollback  - Revertir última actualización"
        echo "  status    - Ver puntos disponibles"
        ;;
esac
EOFROLL
    chmod +x /usr/local/bin/securizar-patch-rollback.sh

    # Crear snapshot automático antes de cada auto-patch
    if [[ -f /usr/local/bin/securizar-auto-patch.sh ]]; then
        log_info "El script de auto-patch ya incluye snapshots automáticos"
    fi

    log_change "Sistema de rollback de parches configurado"
    CHANGES+=("Sección 6: Rollback con snapper/apt/yum history")
}

# ── Sección 7: Monitoreo de paquetes huérfanos ──
section_7() {
    log_section "7. Monitoreo de paquetes huérfanos y obsoletos"

    ask "¿Configurar detección de paquetes huérfanos y obsoletos?" || { log_skip "Detección de huérfanos omitida"; return 0; }

    mkdir -p /var/log/securizar

    cat > /usr/local/bin/securizar-orphan-check.sh << 'EOFORPHAN'
#!/bin/bash
# ============================================================
# securizar-orphan-check.sh — Detecta paquetes huérfanos/obsoletos
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar"
mkdir -p "$LOG_DIR"

FECHA=$(date +%Y%m%d)
REPORT="$LOG_DIR/orphan-check-${FECHA}.txt"

detect_pkg_manager() {
    if command -v zypper &>/dev/null; then echo "suse"
    elif command -v apt &>/dev/null; then echo "debian"
    elif command -v dnf &>/dev/null || command -v yum &>/dev/null; then echo "rhel"
    elif command -v pacman &>/dev/null; then echo "arch"
    else echo "unknown"; fi
}

PKG_MGR=$(detect_pkg_manager)

{
echo "=========================================="
echo " Verificación de paquetes huérfanos"
echo " $(date) - $(hostname)"
echo "=========================================="
echo ""

ORPHANS=0
OBSOLETE=0
ISSUES=0

echo "=== Paquetes huérfanos (sin repositorio) ==="
echo ""

case "$PKG_MGR" in
    suse)
        echo "Paquetes no pertenecientes a ningún repositorio:"
        while read -r line; do
            if [[ -n "$line" ]]; then
                echo "  [HUÉRFANO] $line"
                ((ORPHANS++))
            fi
        done < <(zypper packages --orphaned 2>/dev/null | grep '^i' | awk -F'|' '{print $3}' | tr -d ' ')

        echo ""
        echo "Paquetes bloqueados (locks):"
        zypper locks 2>/dev/null || echo "  Ninguno"
        ;;

    debian)
        echo "Paquetes no referenciados en repositorios:"
        while read -r pkg; do
            if [[ -n "$pkg" ]]; then
                echo "  [HUÉRFANO] $pkg"
                ((ORPHANS++))
            fi
        done < <(apt list --installed 2>/dev/null | grep 'local\]' | cut -d'/' -f1)

        echo ""
        echo "Paquetes residuales (config sobrante):"
        dpkg -l | grep '^rc' | awk '{print "  [RESIDUAL] " $2}' || true

        echo ""
        echo "Paquetes auto-instalados innecesarios:"
        apt-get -s autoremove 2>/dev/null | grep '^Remv' | awk '{print "  [AUTO] " $2}' || true
        ;;

    rhel)
        CMD="yum"
        command -v dnf &>/dev/null && CMD="dnf"

        echo "Paquetes extras (no en repositorios):"
        $CMD list extras 2>/dev/null | tail -n +2 | while read -r line; do
            if [[ -n "$line" ]]; then
                echo "  [HUÉRFANO] $line"
                ((ORPHANS++))
            fi
        done

        echo ""
        echo "Paquetes obsoletos:"
        $CMD list obsoletes 2>/dev/null | tail -n +2 | while read -r line; do
            if [[ -n "$line" ]]; then
                echo "  [OBSOLETO] $line"
                ((OBSOLETE++))
            fi
        done

        if command -v package-cleanup &>/dev/null; then
            echo ""
            echo "Dependencias huérfanas:"
            package-cleanup --leaves 2>/dev/null | while read -r line; do
                echo "  [LEAF] $line"
            done
        fi
        ;;

    arch)
        echo "Paquetes huérfanos (sin dependencias):"
        while read -r pkg; do
            if [[ -n "$pkg" ]]; then
                echo "  [HUÉRFANO] $pkg"
                ((ORPHANS++))
            fi
        done < <(pacman -Qtdq 2>/dev/null)

        echo ""
        echo "Paquetes externos (AUR/manual):"
        pacman -Qm 2>/dev/null | while read -r line; do
            echo "  [EXTERNO] $line"
        done
        ;;
esac

echo ""
echo "=== Paquetes con soporte de seguridad expirado ==="
echo ""

# Verificar kernels antiguos
KERNEL_CURRENT=$(uname -r)
echo "Kernel actual: $KERNEL_CURRENT"
case "$PKG_MGR" in
    suse|rhel)
        rpm -qa 'kernel*' 2>/dev/null | grep -v "$KERNEL_CURRENT" | while read -r k; do
            echo "  [KERNEL ANTIGUO] $k"
        done
        ;;
    debian)
        dpkg -l 'linux-image-*' 2>/dev/null | grep '^ii' | grep -v "$KERNEL_CURRENT" | \
            awk '{print "  [KERNEL ANTIGUO] " $2}' || true
        ;;
esac

echo ""
echo "=========================================="
echo " Resumen"
echo "=========================================="
echo " Huérfanos: $ORPHANS"
echo " Obsoletos: $OBSOLETE"
echo " Verificado: $(date)"
echo "=========================================="
} 2>&1 | tee "$REPORT"

echo ""
echo "Reporte: $REPORT"
EOFORPHAN
    chmod +x /usr/local/bin/securizar-orphan-check.sh

    # Cron semanal
    cat > /etc/cron.weekly/securizar-orphan-check << 'EOF'
#!/bin/bash
/usr/local/bin/securizar-orphan-check.sh >> /var/log/securizar/orphan-cron.log 2>&1
EOF
    chmod +x /etc/cron.weekly/securizar-orphan-check

    log_change "Monitor de paquetes huérfanos/obsoletos configurado"
    CHANGES+=("Sección 7: Detección de huérfanos con cron semanal")
}

# ── Sección 8: Verificación de integridad post-parche ──
section_8() {
    log_section "8. Verificación de integridad post-parche"

    ask "¿Configurar verificación automática post-parche?" || { log_skip "Verificación post-parche omitida"; return 0; }

    mkdir -p /var/log/securizar

    cat > /usr/local/bin/securizar-post-patch-verify.sh << 'EOFVERIFY'
#!/bin/bash
# ============================================================
# securizar-post-patch-verify.sh — Verificación post-parche
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar"
mkdir -p "$LOG_DIR"

FECHA=$(date +%Y%m%d)
REPORT="$LOG_DIR/post-patch-verify-${FECHA}.txt"

PASS=0
FAIL=0
WARN=0

check() {
    local desc="$1" cmd="$2"
    if eval "$cmd" &>/dev/null; then
        echo "  [PASS] $desc"
        ((PASS++))
    else
        echo "  [FAIL] $desc"
        ((FAIL++))
    fi
}

check_warn() {
    local desc="$1" cmd="$2"
    if eval "$cmd" &>/dev/null; then
        echo "  [PASS] $desc"
        ((PASS++))
    else
        echo "  [WARN] $desc"
        ((WARN++))
    fi
}

{
echo "=========================================="
echo " Verificación post-parche - $(date)"
echo " Host: $(hostname)"
echo "=========================================="
echo ""

echo "=== 1. Servicios críticos ==="
check "SSH activo" "systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null"
check_warn "Firewall activo" "systemctl is-active firewalld 2>/dev/null || systemctl is-active ufw 2>/dev/null || iptables -L -n &>/dev/null"
check_warn "Cron activo" "systemctl is-active cron 2>/dev/null || systemctl is-active crond 2>/dev/null"
check "Systemd-journald activo" "systemctl is-active systemd-journald"
check_warn "Rsyslog activo" "systemctl is-active rsyslog 2>/dev/null"
check "D-Bus activo" "systemctl is-active dbus"

echo ""
echo "=== 2. Conectividad de red ==="
check "Interfaz de red activa" "ip link show up | grep -q 'state UP'"
check "Resolución DNS" "getent hosts cloudflare.com"
check_warn "Conectividad externa" "timeout 5 bash -c 'echo > /dev/tcp/1.1.1.1/443' 2>/dev/null"
check "Tabla de rutas" "ip route show default | grep -q 'default'"

echo ""
echo "=== 3. Sistema de archivos ==="
check "/ montado rw" "mount | grep 'on / ' | grep -q 'rw'"
check "/var accesible" "test -w /var/log"
check "/tmp accesible" "test -w /tmp"
check "Espacio en / > 5%" "test \$(df / | tail -1 | awk '{print \$5}' | tr -d '%') -lt 95"
check "Inodos en / > 5%" "test \$(df -i / | tail -1 | awk '{print \$5}' | tr -d '%') -lt 95"

echo ""
echo "=== 4. Autenticación ==="
check "/etc/passwd legible" "test -r /etc/passwd"
check "/etc/shadow protegido" "test -f /etc/shadow && test ! -r /etc/shadow || test \$(stat -c %a /etc/shadow) = '640' -o \$(stat -c %a /etc/shadow) = '600' -o \$(stat -c %a /etc/shadow) = '000'"
check "Root login funcional" "grep -q '^root:' /etc/passwd"
check_warn "PAM configurado" "test -d /etc/pam.d"

echo ""
echo "=== 5. Integridad de configuración ==="
check "/etc/fstab presente" "test -s /etc/fstab"
check "Kernel cargado" "uname -r | grep -q '[0-9]'"
check_warn "GRUB configurado" "test -f /boot/grub2/grub.cfg 2>/dev/null || test -f /boot/grub/grub.cfg 2>/dev/null || test -f /boot/efi/EFI/*/grub.cfg 2>/dev/null"

echo ""
echo "=== 6. Integridad de paquetes ==="
detect_pkg_manager() {
    if command -v zypper &>/dev/null; then echo "suse"
    elif command -v apt &>/dev/null; then echo "debian"
    elif command -v dnf &>/dev/null || command -v yum &>/dev/null; then echo "rhel"
    elif command -v pacman &>/dev/null; then echo "arch"
    else echo "unknown"; fi
}

case "$(detect_pkg_manager)" in
    suse|rhel)
        MODIFIED=$(rpm -Va 2>/dev/null | grep -c '^' || echo "0")
        if [[ $MODIFIED -lt 20 ]]; then
            echo "  [PASS] Integridad RPM: $MODIFIED archivos modificados (< 20)"
            ((PASS++))
        else
            echo "  [WARN] Integridad RPM: $MODIFIED archivos modificados"
            ((WARN++))
        fi
        ;;
    debian)
        if command -v debsums &>/dev/null; then
            MODIFIED=$(debsums -s 2>/dev/null | grep -c 'FAILED' || echo "0")
            if [[ $MODIFIED -eq 0 ]]; then
                echo "  [PASS] Integridad debsums: sin fallos"
                ((PASS++))
            else
                echo "  [WARN] Integridad debsums: $MODIFIED fallos"
                ((WARN++))
            fi
        else
            echo "  [WARN] debsums no instalado"
            ((WARN++))
        fi
        ;;
    arch)
        check_warn "Cache de pacman limpia" "pacman -Dk 2>/dev/null"
        ;;
esac

echo ""
echo "=========================================="
echo " Resumen post-parche"
echo "=========================================="
echo " PASS: $PASS"
echo " FAIL: $FAIL"
echo " WARN: $WARN"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo " *** ESTADO: PROBLEMAS DETECTADOS ***"
    echo " Revisar los fallos antes de continuar"
elif [[ $WARN -gt 3 ]]; then
    echo " ESTADO: MEJORABLE - Revisar advertencias"
else
    echo " ESTADO: SISTEMA OK"
fi

echo ""
echo " Verificado: $(date)"
echo "=========================================="
} 2>&1 | tee "$REPORT"

echo ""
echo "Reporte: $REPORT"

# Exit code basado en resultado
[[ $FAIL -eq 0 ]] && exit 0 || exit 1
EOFVERIFY
    chmod +x /usr/local/bin/securizar-post-patch-verify.sh

    log_change "Verificación post-parche configurada"
    CHANGES+=("Sección 8: Verificación de servicios y sistema post-parche")
}

# ── Sección 9: Notificación y reportes ──
section_9() {
    log_section "9. Notificación y reportes"

    ask "¿Configurar generación automática de reportes de parches?" || { log_skip "Reportes omitidos"; return 0; }

    mkdir -p /var/log/securizar

    cat > /usr/local/bin/securizar-patch-report.sh << 'EOFREPORT'
#!/bin/bash
# ============================================================
# securizar-patch-report.sh — Reporte de estado de parches
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar"
mkdir -p "$LOG_DIR"

FECHA=$(date +%Y%m%d)
FORMAT="${1:-text}"
REPORT_TXT="$LOG_DIR/patch-report-${FECHA}.txt"
REPORT_HTML="$LOG_DIR/patch-report-${FECHA}.html"

detect_pkg_manager() {
    if command -v zypper &>/dev/null; then echo "suse"
    elif command -v apt &>/dev/null; then echo "debian"
    elif command -v dnf &>/dev/null || command -v yum &>/dev/null; then echo "rhel"
    elif command -v pacman &>/dev/null; then echo "arch"
    else echo "unknown"; fi
}

PKG_MGR=$(detect_pkg_manager)

generate_text() {
    echo "=========================================="
    echo " Reporte de Gestión de Parches"
    echo " $(date) - $(hostname)"
    echo "=========================================="
    echo ""

    # 1. Estado de actualizaciones
    echo "=== 1. Actualizaciones pendientes ==="
    echo ""
    case "$PKG_MGR" in
        suse) zypper list-patches --category security 2>/dev/null | head -30 || echo "No disponible" ;;
        debian) apt list --upgradable 2>/dev/null | head -30 || echo "No disponible" ;;
        rhel)
            CMD="yum"; command -v dnf &>/dev/null && CMD="dnf"
            $CMD check-update --security 2>/dev/null | head -30 || echo "No disponible"
            ;;
        arch) pacman -Qu 2>/dev/null | head -30 || echo "No disponible" ;;
    esac

    echo ""
    echo "=== 2. Últimas actualizaciones aplicadas (30 días) ==="
    echo ""
    case "$PKG_MGR" in
        suse) zypper history 2>/dev/null | head -30 || echo "No disponible" ;;
        debian)
            grep -h 'install\|upgrade' /var/log/dpkg.log* 2>/dev/null | \
                tail -30 || echo "No disponible"
            ;;
        rhel)
            CMD="yum"; command -v dnf &>/dev/null && CMD="dnf"
            $CMD history list last-10 2>/dev/null || echo "No disponible"
            ;;
        arch) grep -h 'upgraded\|installed' /var/log/pacman.log 2>/dev/null | tail -30 || echo "No disponible" ;;
    esac

    echo ""
    echo "=== 3. Estado de SBOM ==="
    LATEST_SBOM=$(ls -1t "$LOG_DIR"/sbom-*.json 2>/dev/null | head -1)
    if [[ -n "${LATEST_SBOM:-}" ]]; then
        SBOM_DATE=$(stat -c %y "$LATEST_SBOM" 2>/dev/null | cut -d' ' -f1)
        SBOM_PKGS=$(grep -c '"name":' "$LATEST_SBOM" 2>/dev/null || echo "0")
        echo "Último SBOM: $SBOM_DATE ($SBOM_PKGS componentes)"
    else
        echo "SBOM: No generado"
    fi

    echo ""
    echo "=== 4. Estado de inventario ==="
    LATEST_INV=$(ls -1t "$LOG_DIR"/pkg-inventory-*.txt 2>/dev/null | head -1)
    if [[ -n "${LATEST_INV:-}" ]]; then
        INV_DATE=$(stat -c %y "$LATEST_INV" 2>/dev/null | cut -d' ' -f1)
        echo "Último inventario: $INV_DATE"
    else
        echo "Inventario: No generado"
    fi

    echo ""
    echo "=== 5. Paquetes huérfanos ==="
    LATEST_ORPHAN=$(ls -1t "$LOG_DIR"/orphan-check-*.txt 2>/dev/null | head -1)
    if [[ -n "${LATEST_ORPHAN:-}" ]]; then
        ORPHAN_COUNT=$(grep -c '\[HUÉRFANO\]' "$LATEST_ORPHAN" 2>/dev/null || echo "0")
        echo "Paquetes huérfanos detectados: $ORPHAN_COUNT"
    else
        echo "Verificación de huérfanos: No ejecutada"
    fi

    echo ""
    echo "=== 6. Verificación post-parche ==="
    LATEST_VERIFY=$(ls -1t "$LOG_DIR"/post-patch-verify-*.txt 2>/dev/null | head -1)
    if [[ -n "${LATEST_VERIFY:-}" ]]; then
        VERIFY_DATE=$(stat -c %y "$LATEST_VERIFY" 2>/dev/null | cut -d' ' -f1)
        PASS_COUNT=$(grep -c '\[PASS\]' "$LATEST_VERIFY" 2>/dev/null || echo "0")
        FAIL_COUNT=$(grep -c '\[FAIL\]' "$LATEST_VERIFY" 2>/dev/null || echo "0")
        echo "Última verificación: $VERIFY_DATE (PASS: $PASS_COUNT, FAIL: $FAIL_COUNT)"
    else
        echo "Verificación post-parche: No ejecutada"
    fi

    echo ""
    echo "=========================================="
    echo " Fin del reporte - $(date)"
    echo "=========================================="
}

generate_html() {
    cat << 'EOFHTML1'
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Reporte de Parches - Securizar</title>
<style>
body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }
.container { max-width: 900px; margin: auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
h2 { color: #34495e; margin-top: 25px; }
.status-ok { color: #27ae60; font-weight: bold; }
.status-warn { color: #f39c12; font-weight: bold; }
.status-fail { color: #e74c3c; font-weight: bold; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background: #3498db; color: white; }
tr:nth-child(even) { background: #f2f2f2; }
.footer { margin-top: 30px; text-align: center; color: #7f8c8d; font-size: 0.9em; }
</style>
</head>
<body>
<div class="container">
EOFHTML1

    echo "<h1>Reporte de Gestión de Parches</h1>"
    echo "<p><strong>Host:</strong> $(hostname) | <strong>Fecha:</strong> $(date)</p>"

    echo "<h2>Actualizaciones Pendientes</h2>"
    echo "<pre>"
    case "$PKG_MGR" in
        suse) zypper list-patches --category security 2>/dev/null | head -20 || echo "No disponible" ;;
        debian) apt list --upgradable 2>/dev/null | head -20 || echo "No disponible" ;;
        rhel)
            CMD="yum"; command -v dnf &>/dev/null && CMD="dnf"
            $CMD check-update --security 2>/dev/null | head -20 || echo "No disponible"
            ;;
        arch) pacman -Qu 2>/dev/null | head -20 || echo "No disponible" ;;
    esac
    echo "</pre>"

    echo "<h2>Estado General</h2>"
    echo "<table><tr><th>Componente</th><th>Estado</th><th>Última ejecución</th></tr>"

    for comp in inventario sbom huerfanos verificacion; do
        case "$comp" in
            inventario)
                F=$(ls -1t "$LOG_DIR"/pkg-inventory-*.txt 2>/dev/null | head -1)
                NAME="Inventario de paquetes"
                ;;
            sbom)
                F=$(ls -1t "$LOG_DIR"/sbom-*.json 2>/dev/null | head -1)
                NAME="SBOM"
                ;;
            huerfanos)
                F=$(ls -1t "$LOG_DIR"/orphan-check-*.txt 2>/dev/null | head -1)
                NAME="Paquetes huérfanos"
                ;;
            verificacion)
                F=$(ls -1t "$LOG_DIR"/post-patch-verify-*.txt 2>/dev/null | head -1)
                NAME="Verificación post-parche"
                ;;
        esac

        if [[ -n "${F:-}" ]]; then
            D=$(stat -c %y "$F" 2>/dev/null | cut -d' ' -f1)
            echo "<tr><td>$NAME</td><td class=\"status-ok\">Configurado</td><td>$D</td></tr>"
        else
            echo "<tr><td>$NAME</td><td class=\"status-warn\">No ejecutado</td><td>-</td></tr>"
        fi
    done
    echo "</table>"

    cat << 'EOFHTML2'
<div class="footer">
<p>Generado por Securizar - Gestión de Parches</p>
</div>
</div>
</body>
</html>
EOFHTML2
}

case "$FORMAT" in
    html)
        generate_html > "$REPORT_HTML"
        echo "Reporte HTML: $REPORT_HTML"
        ;;
    text|*)
        generate_text > "$REPORT_TXT"
        echo "Reporte texto: $REPORT_TXT"
        ;;
esac
EOFREPORT
    chmod +x /usr/local/bin/securizar-patch-report.sh

    # Cron semanal
    cat > /etc/cron.weekly/securizar-patch-report << 'EOF'
#!/bin/bash
/usr/local/bin/securizar-patch-report.sh text >> /var/log/securizar/patch-report-cron.log 2>&1
/usr/local/bin/securizar-patch-report.sh html >> /var/log/securizar/patch-report-cron.log 2>&1
EOF
    chmod +x /etc/cron.weekly/securizar-patch-report

    log_change "Sistema de reportes de parches configurado"
    CHANGES+=("Sección 9: Reportes texto/HTML con cron semanal")
}

# ── Sección 10: Auditoría de gestión de parches ──
section_10() {
    log_section "10. Auditoría de gestión de parches"

    ask "¿Configurar auditoría integral de gestión de parches?" || { log_skip "Auditoría omitida"; return 0; }

    mkdir -p /var/log/securizar

    cat > /usr/local/bin/auditoria-parches.sh << 'EOFAUDIT'
#!/bin/bash
# ============================================================
# auditoria-parches.sh — Auditoría integral de parches
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar"
mkdir -p "$LOG_DIR"

FECHA=$(date +%Y%m%d)
REPORT="$LOG_DIR/auditoria-parches-${FECHA}.txt"

SCORE=0
MAX_SCORE=0
CHECKS_PASS=0
CHECKS_FAIL=0

check_item() {
    local desc="$1" weight="$2" condition="$3"
    ((MAX_SCORE += weight))
    if eval "$condition" &>/dev/null; then
        echo "  [✓] $desc (+$weight)"
        ((SCORE += weight))
        ((CHECKS_PASS++))
    else
        echo "  [✗] $desc (0/$weight)"
        ((CHECKS_FAIL++))
    fi
}

{
echo "=========================================="
echo " Auditoría de Gestión de Parches"
echo " $(date) - $(hostname)"
echo "=========================================="
echo ""

echo "=== 1. Infraestructura de parches ==="
check_item "Script de inventario instalado" 2 "test -x /usr/local/bin/securizar-pkg-inventory.sh"
check_item "Cron de inventario activo" 1 "test -x /etc/cron.daily/securizar-pkg-inventory"
check_item "Inventario reciente (< 7 días)" 2 "find $LOG_DIR -name 'pkg-inventory-*.txt' -mtime -7 | grep -q '.'"
check_item "Escáner CVE instalado" 2 "test -x /usr/local/bin/securizar-cve-scan.sh"
check_item "Cron CVE activo" 1 "test -x /etc/cron.weekly/securizar-cve-scan"

echo ""
echo "=== 2. Actualizaciones automáticas ==="

detect_pkg_manager() {
    if command -v zypper &>/dev/null; then echo "suse"
    elif command -v apt &>/dev/null; then echo "debian"
    elif command -v dnf &>/dev/null || command -v yum &>/dev/null; then echo "rhel"
    elif command -v pacman &>/dev/null; then echo "arch"
    else echo "unknown"; fi
}

case "$(detect_pkg_manager)" in
    suse|arch)
        check_item "Timer de auto-patch activo" 3 "systemctl is-active securizar-auto-patch.timer 2>/dev/null"
        ;;
    debian)
        check_item "Unattended-upgrades configurado" 3 "test -f /etc/apt/apt.conf.d/50securizar-unattended || dpkg -l unattended-upgrades 2>/dev/null | grep -q '^ii'"
        ;;
    rhel)
        check_item "dnf-automatic/yum-cron activo" 3 "systemctl is-active dnf-automatic.timer 2>/dev/null || systemctl is-active yum-cron 2>/dev/null"
        ;;
esac

echo ""
echo "=== 3. SBOM y trazabilidad ==="
check_item "Generador SBOM instalado" 2 "test -x /usr/local/bin/securizar-sbom-gen.sh"
check_item "SBOM reciente (< 90 días)" 2 "find $LOG_DIR -name 'sbom-*.json' -mtime -90 | grep -q '.'"
check_item "Cron SBOM activo" 1 "test -x /etc/cron.monthly/securizar-sbom"

echo ""
echo "=== 4. Rollback y recuperación ==="
check_item "Script de rollback instalado" 2 "test -x /usr/local/bin/securizar-patch-rollback.sh"
check_item "Staging de parches disponible" 1 "test -x /usr/local/bin/securizar-patch-staging.sh"
if command -v snapper &>/dev/null; then
    check_item "Snapper disponible para snapshots" 2 "snapper list &>/dev/null"
fi

echo ""
echo "=== 5. Monitoreo y verificación ==="
check_item "Detector de huérfanos instalado" 1 "test -x /usr/local/bin/securizar-orphan-check.sh"
check_item "Verificación post-parche instalada" 2 "test -x /usr/local/bin/securizar-post-patch-verify.sh"
check_item "Sistema de reportes instalado" 1 "test -x /usr/local/bin/securizar-patch-report.sh"

echo ""
echo "=== 6. Estado de actualizaciones ==="
case "$(detect_pkg_manager)" in
    suse)
        PENDING=$(zypper list-patches --category security 2>/dev/null | grep -c '|' || echo "0")
        ;;
    debian)
        PENDING=$(apt list --upgradable 2>/dev/null | grep -i security | wc -l || echo "0")
        ;;
    rhel)
        CMD="yum"; command -v dnf &>/dev/null && CMD="dnf"
        PENDING=$($CMD check-update --security 2>/dev/null | grep -c '^[a-zA-Z]' || echo "0")
        ;;
    arch)
        PENDING=$(pacman -Qu 2>/dev/null | wc -l || echo "0")
        ;;
    *)
        PENDING=0
        ;;
esac

if [[ $PENDING -eq 0 ]]; then
    echo "  [✓] Sin actualizaciones de seguridad pendientes (+3)"
    ((SCORE += 3)); ((MAX_SCORE += 3)); ((CHECKS_PASS++))
elif [[ $PENDING -lt 5 ]]; then
    echo "  [~] $PENDING actualizaciones pendientes (+1/3)"
    ((SCORE += 1)); ((MAX_SCORE += 3))
else
    echo "  [✗] $PENDING actualizaciones pendientes (0/3)"
    ((MAX_SCORE += 3)); ((CHECKS_FAIL++))
fi

echo ""
echo "=========================================="
echo " RESULTADO"
echo "=========================================="

if [[ $MAX_SCORE -gt 0 ]]; then
    PCT=$((SCORE * 100 / MAX_SCORE))
else
    PCT=0
fi

echo ""
echo " Puntuación: $SCORE / $MAX_SCORE ($PCT%)"
echo " Checks: $CHECKS_PASS passed, $CHECKS_FAIL failed"
echo ""

if [[ $PCT -ge 80 ]]; then
    echo " Calificación: ██████████ BUENO"
    echo " La gestión de parches está bien configurada."
elif [[ $PCT -ge 50 ]]; then
    echo " Calificación: ██████░░░░ MEJORABLE"
    echo " Hay aspectos de la gestión de parches que mejorar."
else
    echo " Calificación: ███░░░░░░░ DEFICIENTE"
    echo " La gestión de parches necesita atención urgente."
fi

echo ""
echo " Auditado: $(date)"
echo "=========================================="
} 2>&1 | tee "$REPORT"

echo ""
echo "Reporte: $REPORT"
EOFAUDIT
    chmod +x /usr/local/bin/auditoria-parches.sh

    # Cron semanal
    cat > /etc/cron.weekly/auditoria-parches << 'EOF'
#!/bin/bash
/usr/local/bin/auditoria-parches.sh >> /var/log/securizar/auditoria-parches-cron.log 2>&1
EOF
    chmod +x /etc/cron.weekly/auditoria-parches

    log_change "Auditoría integral de parches configurada"
    CHANGES+=("Sección 10: Auditoría con scoring BUENO/MEJORABLE/DEFICIENTE")
}

# ── Main ──
main() {
    check_root
    log_section "MÓDULO 61: GESTIÓN DE PARCHES"
    for i in $(seq 1 10); do
        "section_$i"
    done
    echo ""
    show_changes_summary
}
main "$@"
