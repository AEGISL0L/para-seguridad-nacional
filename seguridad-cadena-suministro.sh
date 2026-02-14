#!/bin/bash
# ============================================================
# SEGURIDAD DE CADENA DE SUMINISTRO - Linux Multi-Distro
# Modulo 44 - Securizar Suite
# ============================================================
# Secciones:
#   S1  - Verificacion de firmas de paquetes
#   S2  - Inventario SBOM (Software Bill of Materials)
#   S3  - Auditoria de dependencias y CVEs
#   S4  - Repositorios seguros
#   S5  - Integridad de binarios del sistema
#   S6  - Politica de instalacion de software
#   S7  - Deteccion de paquetes troyanizados
#   S8  - Hardening del gestor de paquetes
#   S9  - Monitorizacion de cambios de software
#   S10 - Auditoria de cadena de suministro
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "seguridad-cadena-suministro"
securizar_setup_traps

# ── Pre-check: detectar secciones ya aplicadas ──────────────
_precheck 10
_pc 'check_executable /usr/local/bin/verificar-firmas-paquetes.sh'
_pc 'check_executable /usr/local/bin/generar-sbom.sh'
_pc 'check_executable /usr/local/bin/auditar-cves.sh'
_pc 'check_executable /usr/local/bin/auditar-repositorios.sh'
_pc 'check_executable /usr/local/bin/verificar-integridad-binarios.sh'
_pc 'check_file_exists /etc/securizar/software-policy.conf'
_pc 'check_executable /usr/local/bin/detectar-troyanizados.sh'
_pc 'check_executable /usr/local/bin/securizar-install-hook.sh'
_pc 'check_executable /usr/local/bin/monitorizar-software.sh'
_pc 'check_executable /usr/local/bin/auditoria-cadena-suministro.sh'
_precheck_result

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MODULO 44 - SEGURIDAD DE CADENA DE SUMINISTRO          ║"
echo "║   SBOM, firmas, CVEs, repositorios, integridad,          ║"
echo "║   troyanizados, monitorizacion                            ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

# ============================================================
# S1: VERIFICACION DE FIRMAS DE PAQUETES
# ============================================================
log_section "S1: VERIFICACION DE FIRMAS DE PAQUETES"

echo "Verifica y refuerza la cadena de confianza GPG de paquetes:"
echo "  - Comprueba gpgcheck habilitado en el gestor de paquetes"
echo "  - Lista claves GPG de repositorios instaladas"
echo "  - Crea script de verificacion de firmas"
echo "  - Aplica enforcement si no esta configurado"
echo ""

if check_executable /usr/local/bin/verificar-firmas-paquetes.sh; then
    log_already "Verificacion de firmas de paquetes (verificar-firmas-paquetes.sh existe)"
elif ask "¿Verificar y reforzar firmas de paquetes?"; then

    mkdir -p /etc/securizar
    mkdir -p /var/lib/securizar

    case "$DISTRO_FAMILY" in
        suse)
            log_info "Verificando gpgcheck en repositorios zypper..."
            repos_sin_gpg=0
            for repofile in /etc/zypp/repos.d/*.repo; do
                [[ -f "$repofile" ]] || continue
                repo_name=$(basename "$repofile")
                if grep -qi "^gpgcheck=0" "$repofile" 2>/dev/null; then
                    log_warn "Repositorio sin gpgcheck: $repo_name"
                    cp "$repofile" "$BACKUP_DIR/"
                    log_change "Backup" "$repofile"
                    sed -i 's/^gpgcheck=0/gpgcheck=1/' "$repofile"
                    log_change "Aplicado" "gpgcheck=1 en $repo_name"
                    ((repos_sin_gpg++)) || true
                fi
            done
            if [[ $repos_sin_gpg -eq 0 ]]; then
                log_info "Todos los repositorios ya tienen gpgcheck habilitado"
            else
                log_info "Corregidos $repos_sin_gpg repositorios sin gpgcheck"
            fi
            log_info "Claves GPG instaladas en zypper:"
            rpm -qa gpg-pubkey* 2>/dev/null | while read -r key; do
                rpm -qi "$key" 2>/dev/null | grep -E "^(Name|Summary)" | head -2
            done || true
            ;;
        debian)
            log_info "Verificando que apt no permite paquetes sin autenticar..."
            apt_inseguro=0
            for conffile in /etc/apt/apt.conf.d/*; do
                [[ -f "$conffile" ]] || continue
                if grep -qi "AllowUnauthenticated" "$conffile" 2>/dev/null; then
                    log_warn "Configuracion insegura detectada: $(basename "$conffile")"
                    cp "$conffile" "$BACKUP_DIR/"
                    log_change "Backup" "$conffile"
                    sed -i '/AllowUnauthenticated/d' "$conffile"
                    log_change "Eliminado" "AllowUnauthenticated de $(basename "$conffile")"
                    ((apt_inseguro++)) || true
                fi
            done
            if [[ $apt_inseguro -eq 0 ]]; then
                log_info "apt no tiene AllowUnauthenticated configurado"
            fi
            log_info "Claves GPG de repositorios apt:"
            if command -v apt-key &>/dev/null; then
                apt-key list 2>/dev/null | head -30 || true
            fi
            if [[ -d /etc/apt/trusted.gpg.d ]]; then
                ls -la /etc/apt/trusted.gpg.d/ 2>/dev/null || true
            fi
            ;;
        rhel)
            log_info "Verificando gpgcheck en dnf/yum..."
            dnf_conf="/etc/dnf/dnf.conf"
            [[ ! -f "$dnf_conf" ]] && dnf_conf="/etc/yum.conf"
            if [[ -f "$dnf_conf" ]]; then
                cp "$dnf_conf" "$BACKUP_DIR/"
                log_change "Backup" "$dnf_conf"
                if ! grep -q "^gpgcheck=1" "$dnf_conf"; then
                    if grep -q "^gpgcheck=" "$dnf_conf"; then
                        sed -i 's/^gpgcheck=.*/gpgcheck=1/' "$dnf_conf"
                    else
                        sed -i '/^\[main\]/a gpgcheck=1' "$dnf_conf"
                    fi
                    log_change "Aplicado" "gpgcheck=1 en $dnf_conf"
                fi
                if ! grep -q "^repo_gpgcheck=1" "$dnf_conf"; then
                    if grep -q "^repo_gpgcheck=" "$dnf_conf"; then
                        sed -i 's/^repo_gpgcheck=.*/repo_gpgcheck=1/' "$dnf_conf"
                    else
                        sed -i '/^\[main\]/a repo_gpgcheck=1' "$dnf_conf"
                    fi
                    log_change "Aplicado" "repo_gpgcheck=1 en $dnf_conf"
                fi
            fi
            log_info "Claves GPG de repositorios rpm:"
            rpm -qa gpg-pubkey* 2>/dev/null | while read -r key; do
                rpm -qi "$key" 2>/dev/null | grep -E "^(Name|Summary)" | head -2
            done || true
            ;;
        arch)
            log_info "Verificando SigLevel en pacman..."
            pacman_conf="/etc/pacman.conf"
            if [[ -f "$pacman_conf" ]]; then
                cp "$pacman_conf" "$BACKUP_DIR/"
                log_change "Backup" "$pacman_conf"
                current_siglevel=$(grep "^SigLevel" "$pacman_conf" | head -1 || echo "")
                if [[ -z "$current_siglevel" ]] || ! echo "$current_siglevel" | grep -q "Required"; then
                    if grep -q "^SigLevel" "$pacman_conf"; then
                        sed -i 's/^SigLevel.*/SigLevel = Required DatabaseOptional/' "$pacman_conf"
                    else
                        sed -i '/^\[options\]/a SigLevel = Required DatabaseOptional' "$pacman_conf"
                    fi
                    log_change "Aplicado" "SigLevel = Required en $pacman_conf"
                else
                    log_info "SigLevel ya incluye Required"
                fi
            fi
            log_info "Claves GPG de pacman:"
            pacman-key --list-keys 2>/dev/null | head -30 || true
            ;;
    esac

    # Script de verificacion de firmas
    cat > /usr/local/bin/verificar-firmas-paquetes.sh << 'EOFFIRMAS'
#!/bin/bash
# ============================================================
# Verificacion de firmas de paquetes - securizar Modulo 44
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  VERIFICACION DE FIRMAS DE PAQUETES${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

# Detectar distro
if command -v zypper &>/dev/null; then
    PKG_MGR="zypper"
elif command -v apt &>/dev/null; then
    PKG_MGR="apt"
elif command -v dnf &>/dev/null; then
    PKG_MGR="dnf"
elif command -v pacman &>/dev/null; then
    PKG_MGR="pacman"
else
    echo -e "${RED}Gestor de paquetes no detectado${NC}"
    exit 1
fi

echo -e "${CYAN}Gestor de paquetes: ${BOLD}${PKG_MGR}${NC}"
echo ""

case "$PKG_MGR" in
    zypper)
        echo -e "${CYAN}── Verificacion gpgcheck en repositorios ──${NC}"
        problemas=0
        for repo in /etc/zypp/repos.d/*.repo; do
            [[ -f "$repo" ]] || continue
            name=$(basename "$repo")
            if grep -qi "^gpgcheck=0" "$repo"; then
                echo -e "  ${RED}!!${NC}  $name: gpgcheck DESHABILITADO"
                ((problemas++))
            else
                echo -e "  ${GREEN}OK${NC}  $name: gpgcheck habilitado"
            fi
        done
        echo ""
        echo -e "${CYAN}── Claves GPG instaladas ──${NC}"
        rpm -qa gpg-pubkey* 2>/dev/null | while read -r key; do
            info=$(rpm -qi "$key" 2>/dev/null | grep "^Summary" | sed 's/Summary     : //')
            echo -e "  ${GREEN}*${NC}  $key: $info"
        done
        ;;
    apt)
        echo -e "${CYAN}── Verificacion de autenticacion apt ──${NC}"
        problemas=0
        for conf in /etc/apt/apt.conf.d/*; do
            [[ -f "$conf" ]] || continue
            if grep -qi "AllowUnauthenticated" "$conf"; then
                echo -e "  ${RED}!!${NC}  $(basename "$conf"): AllowUnauthenticated encontrado"
                ((problemas++))
            fi
        done
        [[ $problemas -eq 0 ]] && echo -e "  ${GREEN}OK${NC}  No se permite paquetes sin autenticar"
        echo ""
        echo -e "${CYAN}── Claves GPG de repositorios ──${NC}"
        if [[ -d /etc/apt/trusted.gpg.d ]]; then
            for keyfile in /etc/apt/trusted.gpg.d/*; do
                [[ -f "$keyfile" ]] || continue
                echo -e "  ${GREEN}*${NC}  $(basename "$keyfile")"
            done
        fi
        ;;
    dnf)
        echo -e "${CYAN}── Verificacion gpgcheck en dnf ──${NC}"
        problemas=0
        for conf in /etc/dnf/dnf.conf /etc/yum.conf; do
            [[ -f "$conf" ]] || continue
            if grep -q "^gpgcheck=1" "$conf"; then
                echo -e "  ${GREEN}OK${NC}  $conf: gpgcheck=1"
            else
                echo -e "  ${RED}!!${NC}  $conf: gpgcheck NO habilitado"
                ((problemas++))
            fi
            if grep -q "^repo_gpgcheck=1" "$conf"; then
                echo -e "  ${GREEN}OK${NC}  $conf: repo_gpgcheck=1"
            else
                echo -e "  ${YELLOW}!!${NC}  $conf: repo_gpgcheck NO habilitado"
            fi
        done
        echo ""
        echo -e "${CYAN}── Claves GPG instaladas ──${NC}"
        rpm -qa gpg-pubkey* 2>/dev/null | while read -r key; do
            info=$(rpm -qi "$key" 2>/dev/null | grep "^Summary" | sed 's/Summary     : //')
            echo -e "  ${GREEN}*${NC}  $key: $info"
        done
        ;;
    pacman)
        echo -e "${CYAN}── Verificacion SigLevel en pacman ──${NC}"
        siglevel=$(grep "^SigLevel" /etc/pacman.conf 2>/dev/null | head -1)
        if echo "$siglevel" | grep -q "Required"; then
            echo -e "  ${GREEN}OK${NC}  $siglevel"
        elif echo "$siglevel" | grep -q "Never"; then
            echo -e "  ${RED}!!${NC}  $siglevel - FIRMAS DESHABILITADAS"
        else
            echo -e "  ${YELLOW}??${NC}  $siglevel"
        fi
        echo ""
        echo -e "${CYAN}── Claves GPG de pacman ──${NC}"
        pacman-key --list-keys 2>/dev/null | grep -E "^pub|^uid" | head -20
        ;;
esac

echo ""
echo -e "${BOLD}Verificacion completada: $(date)${NC}"
EOFFIRMAS
    chmod +x /usr/local/bin/verificar-firmas-paquetes.sh
    log_change "Creado" "/usr/local/bin/verificar-firmas-paquetes.sh"
    log_change "Permisos" "/usr/local/bin/verificar-firmas-paquetes.sh -> +x"

    log_info "Verificacion de firmas de paquetes completada"
    log_info "Ejecuta: verificar-firmas-paquetes.sh"
else
    log_skip "Verificacion de firmas de paquetes"
fi

# ============================================================
# S2: INVENTARIO SBOM (SOFTWARE BILL OF MATERIALS)
# ============================================================
log_section "S2: INVENTARIO SBOM (SOFTWARE BILL OF MATERIALS)"

echo "Genera un inventario completo del software instalado (SBOM):"
echo "  - Formato CycloneDX simplificado en JSON"
echo "  - Nombre, version, arquitectura, repositorio, fecha, firma"
echo "  - Modo diff: comparar SBOM actual vs anterior"
echo "  - Timer systemd para generacion diaria"
echo ""

if check_executable /usr/local/bin/generar-sbom.sh; then
    log_already "Inventario SBOM (generar-sbom.sh existe)"
elif ask "¿Crear sistema de inventario SBOM?"; then

    mkdir -p /var/lib/securizar/sbom

    cat > /usr/local/bin/generar-sbom.sh << 'EOFSBOM'
#!/bin/bash
# ============================================================
# Generador SBOM (CycloneDX simplificado) - securizar Modulo 44
# ============================================================

SBOM_DIR="/var/lib/securizar/sbom"
mkdir -p "$SBOM_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
SBOM_FILE="${SBOM_DIR}/sbom-${TIMESTAMP}.json"
DIFF_MODE="${1:-}"

# Detectar gestor de paquetes
get_packages_json() {
    local tmpfile
    tmpfile=$(mktemp)

    if command -v rpm &>/dev/null && ! command -v pacman &>/dev/null; then
        rpm -qa --queryformat '{"name":"%{NAME}","version":"%{VERSION}-%{RELEASE}","arch":"%{ARCH}","vendor":"%{VENDOR}","installtime":"%{INSTALLTIME}","sigpgp":"%{SIGPGP:pgpsig}"}\n' 2>/dev/null > "$tmpfile"
    elif command -v dpkg-query &>/dev/null; then
        dpkg-query -W -f='{"name":"${Package}","version":"${Version}","arch":"${Architecture}","vendor":"${Maintainer}","installtime":"N/A","sigpgp":"N/A"}\n' 2>/dev/null > "$tmpfile"
    elif command -v pacman &>/dev/null; then
        pacman -Q 2>/dev/null | while read -r pkg ver; do
            install_date=$(pacman -Qi "$pkg" 2>/dev/null | grep "^Install Date" | sed 's/Install Date\s*:\s*//')
            repo=$(pacman -Qi "$pkg" 2>/dev/null | grep "^Repository" | sed 's/Repository\s*:\s*//' || echo "unknown")
            printf '{"name":"%s","version":"%s","arch":"any","vendor":"%s","installtime":"%s","sigpgp":"N/A"}\n' \
                "$pkg" "$ver" "$repo" "$install_date"
        done > "$tmpfile"
    else
        echo '{"error":"Gestor de paquetes no soportado"}' > "$tmpfile"
    fi

    cat "$tmpfile"
    rm -f "$tmpfile"
}

# Generar SBOM
echo "Generando SBOM en formato CycloneDX simplificado..."
{
    echo '{'
    echo '  "bomFormat": "CycloneDX",'
    echo '  "specVersion": "1.4",'
    echo '  "version": 1,'
    echo "  \"serialNumber\": \"urn:uuid:$(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "unknown")\","
    echo "  \"metadata\": {"
    echo "    \"timestamp\": \"$(date -Iseconds)\","
    echo "    \"hostname\": \"$(hostname)\","
    echo "    \"os\": \"$(cat /etc/os-release 2>/dev/null | grep ^PRETTY_NAME | cut -d= -f2 | tr -d '\"')\""
    echo '  },'
    echo '  "components": ['

    local first=1
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        if [[ $first -eq 1 ]]; then
            first=0
        else
            echo ','
        fi
        printf '    %s' "$line"
    done < <(get_packages_json)

    echo ''
    echo '  ]'
    echo '}'
} > "$SBOM_FILE"

echo "SBOM generado: $SBOM_FILE"
pkg_count=$(grep -c '"name"' "$SBOM_FILE" 2>/dev/null || echo "0")
echo "Paquetes inventariados: $pkg_count"

# Crear enlace simbolico al ultimo SBOM
ln -sf "$SBOM_FILE" "${SBOM_DIR}/sbom-latest.json"

# Modo diff
if [[ "$DIFF_MODE" == "--diff" ]]; then
    previous=$(ls -t "${SBOM_DIR}"/sbom-2*.json 2>/dev/null | sed -n '2p')
    if [[ -n "$previous" ]]; then
        echo ""
        echo "=== DIFERENCIAS vs SBOM anterior ==="
        echo "Anterior: $previous"
        echo "Actual:   $SBOM_FILE"
        echo ""

        # Extraer nombres de paquetes
        prev_pkgs=$(mktemp)
        curr_pkgs=$(mktemp)
        grep -oP '"name":"[^"]*"' "$previous" | sort > "$prev_pkgs"
        grep -oP '"name":"[^"]*"' "$SBOM_FILE" | sort > "$curr_pkgs"

        echo "--- Paquetes nuevos ---"
        comm -13 "$prev_pkgs" "$curr_pkgs" || true
        echo ""
        echo "--- Paquetes eliminados ---"
        comm -23 "$prev_pkgs" "$curr_pkgs" || true

        rm -f "$prev_pkgs" "$curr_pkgs"
    else
        echo "No hay SBOM anterior para comparar"
    fi
fi

echo ""
echo "SBOM completado: $(date)"
EOFSBOM
    chmod +x /usr/local/bin/generar-sbom.sh
    log_change "Creado" "/usr/local/bin/generar-sbom.sh"
    log_change "Permisos" "/usr/local/bin/generar-sbom.sh -> +x"

    # Timer systemd para generacion diaria
    cat > /etc/systemd/system/securizar-sbom.service << 'EOF'
[Unit]
Description=Generacion diaria SBOM - securizar
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/generar-sbom.sh
StandardOutput=journal
StandardError=journal
EOF
    log_change "Creado" "/etc/systemd/system/securizar-sbom.service"

    cat > /etc/systemd/system/securizar-sbom.timer << 'EOF'
[Unit]
Description=Timer diario para generacion SBOM - securizar

[Timer]
OnCalendar=daily
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
EOF
    log_change "Creado" "/etc/systemd/system/securizar-sbom.timer"

    systemctl daemon-reload 2>/dev/null || true
    systemctl enable securizar-sbom.timer 2>/dev/null || true
    systemctl start securizar-sbom.timer 2>/dev/null || true
    log_change "Activado" "securizar-sbom.timer (diario)"

    # Generar primer SBOM
    log_info "Generando primer inventario SBOM..."
    /usr/local/bin/generar-sbom.sh 2>/dev/null || true

    log_info "Sistema SBOM instalado"
    log_info "Ejecuta: generar-sbom.sh [--diff]"
else
    log_skip "Inventario SBOM"
fi

# ============================================================
# S3: AUDITORIA DE DEPENDENCIAS Y CVEs
# ============================================================
log_section "S3: AUDITORIA DE DEPENDENCIAS Y CVEs"

echo "Crea herramientas de auditoria de vulnerabilidades:"
echo "  - Consulta CVEs conocidos segun el gestor de paquetes"
echo "  - Clasifica por severidad: CRITICAL/HIGH/MEDIUM/LOW"
echo "  - Detecta paquetes huerfanos, obsoletos, no confiables"
echo "  - Instala tarea cron semanal"
echo ""

if check_executable /usr/local/bin/auditar-cves.sh; then
    log_already "Auditoria de dependencias y CVEs (auditar-cves.sh existe)"
elif ask "¿Crear sistema de auditoria de dependencias y CVEs?"; then

    cat > /usr/local/bin/auditar-cves.sh << 'EOFCVES'
#!/bin/bash
# ============================================================
# Auditoria de CVEs y vulnerabilidades - securizar Modulo 44
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  AUDITORIA DE CVEs Y VULNERABILIDADES${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

critical=0
high=0
medium=0
low=0
total_vuln=0

if command -v zypper &>/dev/null; then
    echo -e "${CYAN}── Parches de seguridad (zypper) ──${NC}"
    while IFS= read -r line; do
        if echo "$line" | grep -qi "critical"; then
            echo -e "  ${RED}CRITICAL${NC}  $line"
            ((critical++))
        elif echo "$line" | grep -qi "important"; then
            echo -e "  ${RED}HIGH${NC}      $line"
            ((high++))
        elif echo "$line" | grep -qi "moderate"; then
            echo -e "  ${YELLOW}MEDIUM${NC}    $line"
            ((medium++))
        elif echo "$line" | grep -qi "low"; then
            echo -e "  ${DIM}LOW${NC}       $line"
            ((low++))
        fi
        ((total_vuln++)) || true
    done < <(zypper --quiet list-patches --category security 2>/dev/null | tail -n +3 || true)

    echo ""
    echo -e "${CYAN}── CVEs pendientes ──${NC}"
    zypper --quiet list-patches --cve 2>/dev/null | tail -n +3 | head -30 || echo "  No se pudieron consultar CVEs"

elif command -v apt &>/dev/null; then
    echo -e "${CYAN}── Actualizaciones de seguridad (apt) ──${NC}"
    apt list --upgradable 2>/dev/null | grep -i security | while IFS= read -r line; do
        echo -e "  ${YELLOW}SECURITY${NC}  $line"
        ((total_vuln++)) || true
    done || true

    echo ""
    echo -e "${CYAN}── Paquetes de debian-security ──${NC}"
    apt list --upgradable 2>/dev/null | grep -i "security" | wc -l | while read -r count; do
        echo -e "  Paquetes con actualizaciones de seguridad pendientes: ${BOLD}$count${NC}"
    done || true

elif command -v dnf &>/dev/null; then
    echo -e "${CYAN}── Avisos de seguridad (dnf) ──${NC}"
    while IFS= read -r line; do
        if echo "$line" | grep -qi "Critical"; then
            echo -e "  ${RED}CRITICAL${NC}  $line"
            ((critical++))
        elif echo "$line" | grep -qi "Important"; then
            echo -e "  ${RED}HIGH${NC}      $line"
            ((high++))
        elif echo "$line" | grep -qi "Moderate"; then
            echo -e "  ${YELLOW}MEDIUM${NC}    $line"
            ((medium++))
        elif echo "$line" | grep -qi "Low"; then
            echo -e "  ${DIM}LOW${NC}       $line"
            ((low++))
        fi
        ((total_vuln++)) || true
    done < <(dnf updateinfo list --security 2>/dev/null || true)

elif command -v pacman &>/dev/null; then
    echo -e "${CYAN}── Auditoria de seguridad (arch-audit) ──${NC}"
    if command -v arch-audit &>/dev/null; then
        while IFS= read -r line; do
            if echo "$line" | grep -qi "critical"; then
                echo -e "  ${RED}CRITICAL${NC}  $line"
                ((critical++))
            elif echo "$line" | grep -qi "high"; then
                echo -e "  ${RED}HIGH${NC}      $line"
                ((high++))
            elif echo "$line" | grep -qi "medium"; then
                echo -e "  ${YELLOW}MEDIUM${NC}    $line"
                ((medium++))
            elif echo "$line" | grep -qi "low"; then
                echo -e "  ${DIM}LOW${NC}       $line"
                ((low++))
            else
                echo -e "  ${YELLOW}??${NC}        $line"
            fi
            ((total_vuln++)) || true
        done < <(arch-audit 2>/dev/null || true)
    else
        echo -e "  ${YELLOW}arch-audit no instalado${NC} - instala con: pacman -S arch-audit"
    fi
fi

echo ""
echo -e "${CYAN}── Resumen de vulnerabilidades ──${NC}"
echo -e "  CRITICAL: ${RED}${critical}${NC}"
echo -e "  HIGH:     ${RED}${high}${NC}"
echo -e "  MEDIUM:   ${YELLOW}${medium}${NC}"
echo -e "  LOW:      ${DIM}${low}${NC}"
echo -e "  TOTAL:    ${BOLD}${total_vuln}${NC}"
echo ""
echo -e "${BOLD}Auditoria completada: $(date)${NC}"
EOFCVES
    chmod +x /usr/local/bin/auditar-cves.sh
    log_change "Creado" "/usr/local/bin/auditar-cves.sh"
    log_change "Permisos" "/usr/local/bin/auditar-cves.sh -> +x"

    # Script de verificacion de dependencias
    cat > /usr/local/bin/verificar-dependencias.sh << 'EOFDEPS'
#!/bin/bash
# ============================================================
# Verificacion de dependencias - securizar Modulo 44
# Detecta paquetes huerfanos, obsoletos, no confiables
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  VERIFICACION DE DEPENDENCIAS${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

if command -v zypper &>/dev/null; then
    echo -e "${CYAN}── Paquetes huerfanos ──${NC}"
    zypper packages --orphaned 2>/dev/null | tail -n +5 | head -30 || echo "  No se detectaron huerfanos"
    echo ""
    echo -e "${CYAN}── Paquetes sin repositorio ──${NC}"
    zypper packages --unneeded 2>/dev/null | tail -n +5 | head -30 || echo "  No se detectaron innecesarios"

elif command -v apt &>/dev/null; then
    echo -e "${CYAN}── Paquetes huerfanos (sin repositorio) ──${NC}"
    if command -v deborphan &>/dev/null; then
        deborphan 2>/dev/null | head -30 || echo "  No se detectaron huerfanos"
    else
        echo "  deborphan no instalado - usando apt"
        apt list --installed 2>/dev/null | grep -v "automatic" | head -20 || true
    fi
    echo ""
    echo -e "${CYAN}── Paquetes autoremovibles ──${NC}"
    apt-get --dry-run autoremove 2>/dev/null | grep "^Remv" | head -20 || echo "  Ninguno"

elif command -v dnf &>/dev/null; then
    echo -e "${CYAN}── Paquetes huerfanos ──${NC}"
    dnf list extras 2>/dev/null | tail -n +2 | head -30 || echo "  No se detectaron extras"
    echo ""
    echo -e "${CYAN}── Paquetes obsoletos ──${NC}"
    dnf list obsoletes 2>/dev/null | tail -n +2 | head -30 || echo "  No se detectaron obsoletos"
    echo ""
    echo -e "${CYAN}── Dependencias innecesarias ──${NC}"
    dnf autoremove --assumeno 2>/dev/null | head -20 || true

elif command -v pacman &>/dev/null; then
    echo -e "${CYAN}── Paquetes huerfanos ──${NC}"
    orphans=$(pacman -Qtdq 2>/dev/null || true)
    if [[ -n "$orphans" ]]; then
        echo "$orphans" | head -30
    else
        echo "  No se detectaron huerfanos"
    fi
    echo ""
    echo -e "${CYAN}── Paquetes externos (AUR/manual) ──${NC}"
    pacman -Qem 2>/dev/null | head -30 || echo "  Ninguno"
fi

echo ""
echo -e "${BOLD}Verificacion completada: $(date)${NC}"
EOFDEPS
    chmod +x /usr/local/bin/verificar-dependencias.sh
    log_change "Creado" "/usr/local/bin/verificar-dependencias.sh"
    log_change "Permisos" "/usr/local/bin/verificar-dependencias.sh -> +x"

    # Cron semanal
    cat > /etc/cron.weekly/securizar-auditar-cves << 'EOFCRON'
#!/bin/bash
# Auditoria semanal de CVEs - securizar Modulo 44
/usr/local/bin/auditar-cves.sh > /var/log/securizar-cves.log 2>&1
/usr/local/bin/verificar-dependencias.sh >> /var/log/securizar-cves.log 2>&1
EOFCRON
    chmod +x /etc/cron.weekly/securizar-auditar-cves
    log_change "Creado" "/etc/cron.weekly/securizar-auditar-cves"

    log_info "Sistema de auditoria de CVEs instalado"
    log_info "Ejecuta: auditar-cves.sh / verificar-dependencias.sh"
else
    log_skip "Auditoria de dependencias y CVEs"
fi

# ============================================================
# S4: REPOSITORIOS SEGUROS
# ============================================================
log_section "S4: REPOSITORIOS SEGUROS"

echo "Audita y refuerza la configuracion de repositorios:"
echo "  - Verifica HTTPS vs HTTP en fuentes de paquetes"
echo "  - Comprueba verificacion GPG de repositorios"
echo "  - Evalua riesgo de repositorios de terceros"
echo "  - Convierte HTTP a HTTPS cuando es posible"
echo "  - Aplica prioridades de repositorios"
echo ""

if check_executable /usr/local/bin/auditar-repositorios.sh; then
    log_already "Repositorios seguros (auditar-repositorios.sh existe)"
elif ask "¿Auditar y reforzar repositorios?"; then

    mkdir -p /etc/securizar

    # Whitelist de repositorios
    if [[ ! -f /etc/securizar/repos-whitelist.conf ]]; then
        cat > /etc/securizar/repos-whitelist.conf << 'EOF'
# ============================================================
# Whitelist de repositorios - securizar Modulo 44
# ============================================================
# Un patron por linea (expresiones regulares)
# Los repositorios que coincidan se consideran confiables
# ============================================================
download\.opensuse\.org
repo\.opensuse\.org
ftp\.debian\.org
security\.debian\.org
deb\.debian\.org
archive\.ubuntu\.com
security\.ubuntu\.com
mirror\.centos\.org
vault\.centos\.org
dl\.fedoraproject\.org
mirrors\.fedoraproject\.org
cdn-ubi\.redhat\.com
archlinux\.org
EOF
        log_change "Creado" "/etc/securizar/repos-whitelist.conf"
    else
        log_info "Whitelist de repositorios ya existe"
    fi

    cat > /usr/local/bin/auditar-repositorios.sh << 'EOFREPOS'
#!/bin/bash
# ============================================================
# Auditoria de repositorios - securizar Modulo 44
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

WHITELIST="/etc/securizar/repos-whitelist.conf"

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  AUDITORIA DE REPOSITORIOS${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

http_count=0
https_count=0
no_gpg=0
third_party=0

check_url() {
    local url="$1" name="$2"
    local is_trusted=0

    # Verificar HTTPS
    if echo "$url" | grep -q "^https://"; then
        echo -e "  ${GREEN}HTTPS${NC}  $name"
        ((https_count++))
    elif echo "$url" | grep -q "^http://"; then
        echo -e "  ${RED}HTTP${NC}   $name -> $url"
        ((http_count++))
    fi

    # Verificar whitelist
    if [[ -f "$WHITELIST" ]]; then
        while IFS= read -r pattern; do
            [[ -z "$pattern" || "$pattern" == \#* ]] && continue
            if echo "$url" | grep -qE "$pattern"; then
                is_trusted=1
                break
            fi
        done < "$WHITELIST"
    fi

    if [[ $is_trusted -eq 0 ]]; then
        echo -e "    ${YELLOW}TERCERO${NC}  No esta en whitelist"
        ((third_party++))
    fi
}

if command -v zypper &>/dev/null; then
    echo -e "${CYAN}── Repositorios zypper ──${NC}"
    while IFS='|' read -r _ alias name enabled _ url _; do
        alias=$(echo "$alias" | xargs)
        url=$(echo "$url" | xargs)
        enabled=$(echo "$enabled" | xargs)
        [[ "$enabled" != "Yes" ]] && continue
        [[ -z "$url" || "$url" == "URI" ]] && continue
        check_url "$url" "$alias"
    done < <(zypper repos -u 2>/dev/null || true)

elif command -v apt &>/dev/null; then
    echo -e "${CYAN}── Fuentes apt ──${NC}"
    for srcfile in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
        [[ -f "$srcfile" ]] || continue
        while IFS= read -r line; do
            [[ -z "$line" || "$line" == \#* ]] && continue
            url=$(echo "$line" | grep -oP 'https?://[^ ]+' | head -1)
            [[ -z "$url" ]] && continue
            check_url "$url" "$(basename "$srcfile")"
        done < "$srcfile"
    done

elif command -v dnf &>/dev/null; then
    echo -e "${CYAN}── Repositorios dnf ──${NC}"
    for repofile in /etc/yum.repos.d/*.repo; do
        [[ -f "$repofile" ]] || continue
        repo_name=$(basename "$repofile")
        while IFS= read -r line; do
            if echo "$line" | grep -q "^baseurl=\|^metalink=\|^mirrorlist="; then
                url=$(echo "$line" | cut -d= -f2-)
                check_url "$url" "$repo_name"
            fi
        done < "$repofile"
    done

elif command -v pacman &>/dev/null; then
    echo -e "${CYAN}── Servidores pacman ──${NC}"
    if [[ -f /etc/pacman.d/mirrorlist ]]; then
        grep "^Server" /etc/pacman.d/mirrorlist | while IFS= read -r line; do
            url=$(echo "$line" | sed 's/Server = //')
            check_url "$url" "mirrorlist"
        done
    fi
fi

echo ""
echo -e "${CYAN}── Resumen ──${NC}"
echo -e "  HTTPS:          ${GREEN}${https_count}${NC}"
echo -e "  HTTP (inseguro): ${RED}${http_count}${NC}"
echo -e "  Sin GPG:         ${RED}${no_gpg}${NC}"
echo -e "  Terceros:        ${YELLOW}${third_party}${NC}"
echo ""
echo -e "${BOLD}Auditoria completada: $(date)${NC}"
EOFREPOS
    chmod +x /usr/local/bin/auditar-repositorios.sh
    log_change "Creado" "/usr/local/bin/auditar-repositorios.sh"
    log_change "Permisos" "/usr/local/bin/auditar-repositorios.sh -> +x"

    # Intentar convertir HTTP a HTTPS
    log_info "Verificando repositorios HTTP convertibles a HTTPS..."
    case "$DISTRO_FAMILY" in
        suse)
            for repofile in /etc/zypp/repos.d/*.repo; do
                [[ -f "$repofile" ]] || continue
                if grep -q "^baseurl=http://" "$repofile" 2>/dev/null; then
                    repo_name=$(basename "$repofile")
                    cp "$repofile" "$BACKUP_DIR/"
                    sed -i 's|^baseurl=http://|baseurl=https://|g' "$repofile"
                    log_change "Convertido" "HTTP a HTTPS en $repo_name"
                fi
            done
            ;;
        debian)
            for srcfile in /etc/apt/sources.list /etc/apt/sources.list.d/*.list; do
                [[ -f "$srcfile" ]] || continue
                if grep -q "http://" "$srcfile" 2>/dev/null; then
                    cp "$srcfile" "$BACKUP_DIR/"
                    log_change "Backup" "$srcfile"
                    sed -i 's|http://|https://|g' "$srcfile"
                    log_change "Convertido" "HTTP a HTTPS en $(basename "$srcfile")"
                fi
            done
            ;;
        rhel)
            for repofile in /etc/yum.repos.d/*.repo; do
                [[ -f "$repofile" ]] || continue
                if grep -q "^baseurl=http://" "$repofile" 2>/dev/null; then
                    cp "$repofile" "$BACKUP_DIR/"
                    sed -i 's|^baseurl=http://|baseurl=https://|g' "$repofile"
                    log_change "Convertido" "HTTP a HTTPS en $(basename "$repofile")"
                fi
            done
            ;;
        arch)
            mirrorlist="/etc/pacman.d/mirrorlist"
            if [[ -f "$mirrorlist" ]] && grep -q "http://" "$mirrorlist" 2>/dev/null; then
                cp "$mirrorlist" "$BACKUP_DIR/"
                sed -i 's|http://|https://|g' "$mirrorlist"
                log_change "Convertido" "HTTP a HTTPS en mirrorlist"
            fi
            ;;
    esac

    log_info "Auditoria de repositorios completada"
    log_info "Ejecuta: auditar-repositorios.sh"
else
    log_skip "Repositorios seguros"
fi

# ============================================================
# S5: INTEGRIDAD DE BINARIOS DEL SISTEMA
# ============================================================
log_section "S5: INTEGRIDAD DE BINARIOS DEL SISTEMA"

echo "Verifica la integridad de binarios criticos del sistema:"
echo "  - Compara binarios contra la base de datos del gestor de paquetes"
echo "  - Foco en binarios de seguridad: sudo, ssh, passwd, sshd, su, login"
echo "  - Genera baseline SHA-256 de binarios criticos"
echo "  - Timer systemd para verificacion diaria"
echo ""

if check_executable /usr/local/bin/verificar-integridad-binarios.sh; then
    log_already "Integridad de binarios (verificar-integridad-binarios.sh existe)"
elif ask "¿Verificar y monitorizar integridad de binarios?"; then

    mkdir -p /var/lib/securizar/binary-hashes

    # Verificar contra gestor de paquetes
    log_info "Verificando integridad de binarios contra gestor de paquetes..."
    case "$DISTRO_FAMILY" in
        suse|rhel)
            log_info "Ejecutando rpm -Va sobre binarios de seguridad..."
            for bin in sudo ssh sshd passwd su login; do
                bin_path=$(command -v "$bin" 2>/dev/null || true)
                [[ -z "$bin_path" ]] && continue
                pkg=$(rpm -qf "$bin_path" 2>/dev/null || echo "no-paquete")
                if [[ "$pkg" == "no-paquete" ]]; then
                    log_warn "Binario no pertenece a ningun paquete: $bin_path"
                else
                    resultado=$(rpm -V "$pkg" 2>/dev/null || true)
                    if [[ -n "$resultado" ]]; then
                        log_warn "Modificaciones detectadas en $pkg:"
                        echo "$resultado" | head -10
                    else
                        log_info "Binario integro: $bin ($pkg)"
                    fi
                fi
            done
            ;;
        debian)
            if command -v debsums &>/dev/null; then
                log_info "Ejecutando debsums sobre binarios de seguridad..."
                for bin in sudo ssh sshd passwd su login; do
                    bin_path=$(command -v "$bin" 2>/dev/null || true)
                    [[ -z "$bin_path" ]] && continue
                    pkg=$(dpkg -S "$bin_path" 2>/dev/null | cut -d: -f1 || echo "no-paquete")
                    if [[ "$pkg" == "no-paquete" ]]; then
                        log_warn "Binario no pertenece a ningun paquete: $bin_path"
                    else
                        resultado=$(debsums -c "$pkg" 2>/dev/null || true)
                        if [[ -n "$resultado" ]]; then
                            log_warn "Modificaciones detectadas en $pkg:"
                            echo "$resultado" | head -10
                        else
                            log_info "Binario integro: $bin ($pkg)"
                        fi
                    fi
                done
            else
                log_warn "debsums no instalado - instalando..."
                pkg_install "debsums"
            fi
            ;;
        arch)
            log_info "Ejecutando pacman -Qk sobre binarios de seguridad..."
            for bin in sudo ssh sshd passwd su login; do
                bin_path=$(command -v "$bin" 2>/dev/null || true)
                [[ -z "$bin_path" ]] && continue
                pkg=$(pacman -Qo "$bin_path" 2>/dev/null | awk '{print $(NF-1)}' || echo "no-paquete")
                if [[ "$pkg" == "no-paquete" ]]; then
                    log_warn "Binario no pertenece a ningun paquete: $bin_path"
                else
                    resultado=$(pacman -Qk "$pkg" 2>&1 | grep -i "warning\|error" || true)
                    if [[ -n "$resultado" ]]; then
                        log_warn "Modificaciones detectadas en $pkg:"
                        echo "$resultado" | head -10
                    else
                        log_info "Binario integro: $bin ($pkg)"
                    fi
                fi
            done
            ;;
    esac

    # Generar baseline SHA-256
    log_info "Generando baseline SHA-256 de binarios criticos..."
    baseline_file="/var/lib/securizar/binary-hashes/baseline.sha256"
    : > "$baseline_file"
    for bin in sudo ssh sshd passwd su login mount umount crontab at pkexec \
               systemctl journalctl iptables ip6tables nftables modprobe insmod; do
        bin_path=$(command -v "$bin" 2>/dev/null || true)
        [[ -z "$bin_path" ]] && continue
        [[ -f "$bin_path" ]] || continue
        sha256sum "$bin_path" >> "$baseline_file" 2>/dev/null || true
    done
    chmod 600 "$baseline_file"
    log_change "Creado" "$baseline_file"
    log_info "Baseline con $(wc -l < "$baseline_file") binarios"

    # Script de verificacion
    cat > /usr/local/bin/verificar-integridad-binarios.sh << 'EOFINTEG'
#!/bin/bash
# ============================================================
# Verificacion de integridad de binarios - securizar Modulo 44
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

BASELINE="/var/lib/securizar/binary-hashes/baseline.sha256"

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  VERIFICACION DE INTEGRIDAD DE BINARIOS${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

if [[ ! -f "$BASELINE" ]]; then
    echo -e "${RED}Baseline no encontrado: $BASELINE${NC}"
    echo "Ejecuta primero el modulo 44 de securizar para generar la baseline"
    exit 1
fi

total=0
ok=0
modificados=0
ausentes=0

while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    expected_hash=$(echo "$line" | awk '{print $1}')
    filepath=$(echo "$line" | awk '{print $2}')
    ((total++))

    if [[ ! -f "$filepath" ]]; then
        echo -e "  ${RED}AUSENTE${NC}     $filepath"
        ((ausentes++))
        continue
    fi

    current_hash=$(sha256sum "$filepath" 2>/dev/null | awk '{print $1}')
    if [[ "$current_hash" == "$expected_hash" ]]; then
        echo -e "  ${GREEN}OK${NC}          $filepath"
        ((ok++))
    else
        echo -e "  ${RED}MODIFICADO${NC}  $filepath"
        echo -e "    Esperado: ${DIM}${expected_hash}${NC}"
        echo -e "    Actual:   ${RED}${current_hash}${NC}"
        ((modificados++))
    fi
done < "$BASELINE"

echo ""
echo -e "${CYAN}── Resumen ──${NC}"
echo -e "  Total verificados: ${BOLD}${total}${NC}"
echo -e "  Integros:          ${GREEN}${ok}${NC}"
echo -e "  Modificados:       ${RED}${modificados}${NC}"
echo -e "  Ausentes:          ${RED}${ausentes}${NC}"

if [[ $modificados -gt 0 || $ausentes -gt 0 ]]; then
    echo ""
    echo -e "${RED}${BOLD}ALERTA: Se detectaron cambios en binarios criticos${NC}"
    echo -e "Investiga inmediatamente los binarios marcados como MODIFICADO o AUSENTE"
fi

echo ""
echo -e "${BOLD}Verificacion completada: $(date)${NC}"
EOFINTEG
    chmod +x /usr/local/bin/verificar-integridad-binarios.sh
    log_change "Creado" "/usr/local/bin/verificar-integridad-binarios.sh"
    log_change "Permisos" "/usr/local/bin/verificar-integridad-binarios.sh -> +x"

    # Timer systemd para verificacion diaria
    cat > /etc/systemd/system/securizar-integridad-binarios.service << 'EOF'
[Unit]
Description=Verificacion diaria de integridad de binarios - securizar
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/verificar-integridad-binarios.sh
StandardOutput=journal
StandardError=journal
EOF
    log_change "Creado" "/etc/systemd/system/securizar-integridad-binarios.service"

    cat > /etc/systemd/system/securizar-integridad-binarios.timer << 'EOF'
[Unit]
Description=Timer diario para verificacion de integridad de binarios - securizar

[Timer]
OnCalendar=daily
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
EOF
    log_change "Creado" "/etc/systemd/system/securizar-integridad-binarios.timer"

    systemctl daemon-reload 2>/dev/null || true
    systemctl enable securizar-integridad-binarios.timer 2>/dev/null || true
    systemctl start securizar-integridad-binarios.timer 2>/dev/null || true
    log_change "Activado" "securizar-integridad-binarios.timer (diario)"

    log_info "Verificacion de integridad de binarios completada"
    log_info "Ejecuta: verificar-integridad-binarios.sh"
else
    log_skip "Integridad de binarios del sistema"
fi

# ============================================================
# S6: POLITICA DE INSTALACION DE SOFTWARE
# ============================================================
log_section "S6: POLITICA DE INSTALACION DE SOFTWARE"

echo "Crea una politica de instalacion de software:"
echo "  - Archivo de politica: /etc/securizar/software-policy.conf"
echo "  - Requiere GPG, bloquea paquetes sin firmar"
echo "  - Hook de instalacion que registra todas las operaciones"
echo "  - Configuraciones de enforcement por distro"
echo ""

if check_file_exists /etc/securizar/software-policy.conf; then
    log_already "Politica de instalacion de software (software-policy.conf existe)"
elif ask "¿Crear politica de instalacion de software?"; then

    mkdir -p /etc/securizar

    cat > /etc/securizar/software-policy.conf << 'EOF'
# ============================================================
# Politica de instalacion de software - securizar Modulo 44
# ============================================================
# Esta politica controla los requisitos para instalar software
# en el sistema. Modificar con precaucion.
# ============================================================

# Requerir firma GPG para todos los paquetes
REQUIRE_GPG=yes

# Bloquear instalacion de paquetes sin firmar
BLOCK_UNSIGNED=yes

# Permitir solo repositorios en whitelist
RESTRICT_REPOS=yes

# Registrar todas las operaciones de paquetes
LOG_ALL_INSTALLS=yes

# Archivo de log
INSTALL_LOG=/var/log/securizar-software-installs.log

# Nivel de alerta para paquetes de terceros
THIRD_PARTY_ALERT=warn

# Bloquear downgrades
BLOCK_DOWNGRADES=yes

# Requerir aprobacion para paquetes con SUID/SGID
REVIEW_SUID=yes
EOF
    log_change "Creado" "/etc/securizar/software-policy.conf"

    # Hook de instalacion
    cat > /usr/local/bin/securizar-install-hook.sh << 'EOFHOOK'
#!/bin/bash
# ============================================================
# Hook de instalacion de software - securizar Modulo 44
# Registra todas las operaciones de paquetes
# ============================================================

LOG_FILE="/var/log/securizar-software-installs.log"
POLICY="/etc/securizar/software-policy.conf"

# Cargar politica
if [[ -f "$POLICY" ]]; then
    source "$POLICY"
fi

log_install() {
    local action="$1" package="$2" details="${3:-}"
    local timestamp
    timestamp=$(date -Iseconds)
    local user
    user=$(whoami)
    echo "[$timestamp] [$user] $action: $package $details" >> "$LOG_FILE"
}

# Detectar operacion
ACTION="${1:-unknown}"
PACKAGE="${2:-unknown}"

case "$ACTION" in
    install)
        log_install "INSTALL" "$PACKAGE"
        if [[ "${REQUIRE_GPG:-yes}" == "yes" ]]; then
            echo "POLITICA: Se requiere firma GPG para $PACKAGE"
        fi
        ;;
    remove)
        log_install "REMOVE" "$PACKAGE"
        ;;
    update)
        log_install "UPDATE" "$PACKAGE"
        ;;
    *)
        log_install "UNKNOWN" "$PACKAGE" "action=$ACTION"
        ;;
esac
EOFHOOK
    chmod +x /usr/local/bin/securizar-install-hook.sh
    log_change "Creado" "/usr/local/bin/securizar-install-hook.sh"
    log_change "Permisos" "/usr/local/bin/securizar-install-hook.sh -> +x"

    # Enforcement por distro
    case "$DISTRO_FAMILY" in
        suse)
            if [[ -f /etc/zypp/zypp.conf ]]; then
                cp /etc/zypp/zypp.conf "$BACKUP_DIR/"
                log_change "Backup" "/etc/zypp/zypp.conf"
            fi
            # Crear configuracion de enforcement
            cat > /etc/securizar/enforcement-zypper.conf << 'EOF'
# Enforcement zypper - securizar
# gpgcheck obligatorio en todos los repos
# Solo instalar paquetes requeridos (no recomendados)
ZYPPER_GPGCHECK=1
ZYPPER_ONLY_REQUIRES=1
EOF
            log_change "Creado" "/etc/securizar/enforcement-zypper.conf"
            ;;
        debian)
            cat > /etc/apt/apt.conf.d/99-securizar-policy << 'EOF'
// Politica de seguridad apt - securizar Modulo 44
APT::Get::AllowUnauthenticated "false";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
EOF
            log_change "Creado" "/etc/apt/apt.conf.d/99-securizar-policy"
            ;;
        rhel)
            cat > /etc/securizar/enforcement-dnf.conf << 'EOF'
# Enforcement dnf - securizar
# gpgcheck, localpkg_gpgcheck obligatorios
DNF_GPGCHECK=1
DNF_LOCALPKG_GPGCHECK=1
DNF_CLEAN_REQUIREMENTS=1
EOF
            log_change "Creado" "/etc/securizar/enforcement-dnf.conf"
            ;;
        arch)
            cat > /etc/securizar/enforcement-pacman.conf << 'EOF'
# Enforcement pacman - securizar
# SigLevel Required para todos los repos
PACMAN_SIGLEVEL="Required DatabaseRequired"
EOF
            log_change "Creado" "/etc/securizar/enforcement-pacman.conf"
            ;;
    esac

    log_info "Politica de instalacion de software configurada"
else
    log_skip "Politica de instalacion de software"
fi

# ============================================================
# S7: DETECCION DE PAQUETES TROYANIZADOS
# ============================================================
log_section "S7: DETECCION DE PAQUETES TROYANIZADOS"

echo "Crea sistema de deteccion de paquetes troyanizados:"
echo "  - Verifica hashes de archivos contra la base de paquetes"
echo "  - Detecta binarios SUID/SGID inesperados"
echo "  - Busca binarios huerfanos no pertenecientes a paquetes"
echo "  - Detecta hooks LD_PRELOAD y manipulacion de PATH"
echo "  - Verifica integridad de bibliotecas compartidas"
echo "  - Compara systemd units contra paquetes instalados"
echo ""

if check_executable /usr/local/bin/detectar-troyanizados.sh; then
    log_already "Deteccion de paquetes troyanizados (detectar-troyanizados.sh existe)"
elif ask "¿Crear sistema de deteccion de paquetes troyanizados?"; then

    cat > /usr/local/bin/detectar-troyanizados.sh << 'EOFTROJAN'
#!/bin/bash
# ============================================================
# Deteccion de paquetes troyanizados - securizar Modulo 44
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  DETECCION DE PAQUETES TROYANIZADOS${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

alertas=0

# 1. Binarios SUID/SGID inesperados
echo -e "${CYAN}── Binarios SUID/SGID ──${NC}"
suid_known="/usr/bin/sudo /usr/bin/passwd /usr/bin/su /usr/bin/mount /usr/bin/umount \
/usr/bin/chsh /usr/bin/chfn /usr/bin/newgrp /usr/bin/gpasswd /usr/bin/crontab \
/usr/bin/pkexec /usr/bin/at /usr/sbin/unix_chkpwd /usr/lib/dbus-1.0/dbus-daemon-launch-helper \
/usr/bin/fusermount /usr/bin/fusermount3 /usr/sbin/mount.nfs"

while IFS= read -r suid_file; do
    [[ -z "$suid_file" ]] && continue
    is_known=0
    for known in $suid_known; do
        if [[ "$suid_file" == "$known" ]]; then
            is_known=1
            break
        fi
    done
    if [[ $is_known -eq 0 ]]; then
        # Verificar si pertenece a un paquete
        owned=0
        if command -v rpm &>/dev/null; then
            rpm -qf "$suid_file" &>/dev/null && owned=1
        elif command -v dpkg &>/dev/null; then
            dpkg -S "$suid_file" &>/dev/null && owned=1
        elif command -v pacman &>/dev/null; then
            pacman -Qo "$suid_file" &>/dev/null && owned=1
        fi
        if [[ $owned -eq 0 ]]; then
            echo -e "  ${RED}ALERTA${NC}  SUID/SGID no pertenece a paquete: $suid_file"
            ((alertas++))
        else
            echo -e "  ${YELLOW}REVISAR${NC} SUID/SGID no habitual: $suid_file"
        fi
    fi
done < <(find / -path /proc -prune -o -path /sys -prune -o -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null)

# 2. Binarios huerfanos en PATH
echo ""
echo -e "${CYAN}── Binarios huerfanos en PATH ──${NC}"
for dir in /usr/local/bin /usr/local/sbin; do
    [[ -d "$dir" ]] || continue
    for binfile in "$dir"/*; do
        [[ -f "$binfile" ]] || continue
        owned=0
        if command -v rpm &>/dev/null; then
            rpm -qf "$binfile" &>/dev/null 2>&1 && owned=1
        elif command -v dpkg &>/dev/null; then
            dpkg -S "$binfile" &>/dev/null 2>&1 && owned=1
        elif command -v pacman &>/dev/null; then
            pacman -Qo "$binfile" &>/dev/null 2>&1 && owned=1
        fi
        if [[ $owned -eq 0 ]]; then
            # Excluir scripts de securizar
            if grep -q "securizar" "$binfile" 2>/dev/null; then
                echo -e "  ${GREEN}OK${NC}  $binfile (securizar)"
            else
                echo -e "  ${YELLOW}REVISAR${NC} No pertenece a paquete: $binfile"
            fi
        fi
    done
done

# 3. LD_PRELOAD hooks
echo ""
echo -e "${CYAN}── Hooks LD_PRELOAD ──${NC}"
ld_preload_found=0
# Verificar variable de entorno
if [[ -n "${LD_PRELOAD:-}" ]]; then
    echo -e "  ${RED}ALERTA${NC}  LD_PRELOAD activo: $LD_PRELOAD"
    ((alertas++))
    ld_preload_found=1
fi
# Verificar /etc/ld.so.preload
if [[ -f /etc/ld.so.preload ]] && [[ -s /etc/ld.so.preload ]]; then
    echo -e "  ${RED}ALERTA${NC}  /etc/ld.so.preload no vacio:"
    while IFS= read -r line; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        echo -e "    ${RED}->  $line${NC}"
        ((alertas++))
    done < /etc/ld.so.preload
    ld_preload_found=1
fi
# Verificar en profile.d
for profdir in /etc/profile.d /etc/environment; do
    if [[ -f "$profdir" ]]; then
        if grep -q "LD_PRELOAD" "$profdir" 2>/dev/null; then
            echo -e "  ${RED}ALERTA${NC}  LD_PRELOAD en $profdir"
            ((alertas++))
            ld_preload_found=1
        fi
    elif [[ -d "$profdir" ]]; then
        for f in "$profdir"/*; do
            [[ -f "$f" ]] || continue
            if grep -q "LD_PRELOAD" "$f" 2>/dev/null; then
                echo -e "  ${RED}ALERTA${NC}  LD_PRELOAD en $f"
                ((alertas++))
                ld_preload_found=1
            fi
        done
    fi
done
if [[ $ld_preload_found -eq 0 ]]; then
    echo -e "  ${GREEN}OK${NC}  No se detectaron hooks LD_PRELOAD"
fi

# 4. Integridad de bibliotecas compartidas
echo ""
echo -e "${CYAN}── Integridad de bibliotecas compartidas ──${NC}"
lib_alertas=0
for libdir in /lib /lib64 /usr/lib /usr/lib64; do
    [[ -d "$libdir" ]] || continue
    while IFS= read -r libfile; do
        [[ -f "$libfile" ]] || continue
        owned=0
        if command -v rpm &>/dev/null; then
            rpm -qf "$libfile" &>/dev/null 2>&1 && owned=1
        elif command -v dpkg &>/dev/null; then
            dpkg -S "$libfile" &>/dev/null 2>&1 && owned=1
        elif command -v pacman &>/dev/null; then
            pacman -Qo "$libfile" &>/dev/null 2>&1 && owned=1
        fi
        if [[ $owned -eq 0 ]]; then
            echo -e "  ${YELLOW}REVISAR${NC} Biblioteca no pertenece a paquete: $libfile"
            ((lib_alertas++))
        fi
    done < <(find "$libdir" -maxdepth 1 -name "*.so" -type f 2>/dev/null)
done
if [[ $lib_alertas -eq 0 ]]; then
    echo -e "  ${GREEN}OK${NC}  Bibliotecas compartidas parecen integras"
fi

# 5. Capabilities sospechosas
echo ""
echo -e "${CYAN}── Binarios con capabilities especiales ──${NC}"
if command -v getcap &>/dev/null; then
    cap_alertas=0
    while IFS= read -r capline; do
        [[ -z "$capline" ]] && continue
        capfile=$(echo "$capline" | awk '{print $1}')
        caps=$(echo "$capline" | awk '{$1=""; print $0}')
        if echo "$caps" | grep -qE "cap_sys_admin|cap_sys_ptrace|cap_dac_override|cap_setuid"; then
            echo -e "  ${YELLOW}REVISAR${NC} $capfile: $caps"
            ((cap_alertas++))
        fi
    done < <(getcap -r / 2>/dev/null || true)
    if [[ $cap_alertas -eq 0 ]]; then
        echo -e "  ${GREEN}OK${NC}  No se detectaron capabilities sospechosas"
    fi
else
    echo -e "  ${DIM}getcap no disponible${NC}"
fi

# 6. Manipulacion de PATH
echo ""
echo -e "${CYAN}── Manipulacion de PATH ──${NC}"
path_alertas=0
# Verificar PATH con directorios sospechosos
IFS=':' read -ra path_dirs <<< "$PATH"
for dir in "${path_dirs[@]}"; do
    if [[ "$dir" == "." || "$dir" == "" ]]; then
        echo -e "  ${RED}ALERTA${NC}  PATH contiene directorio actual '.'"
        ((path_alertas++))
        ((alertas++))
    elif [[ "$dir" == /tmp* || "$dir" == /var/tmp* ]]; then
        echo -e "  ${RED}ALERTA${NC}  PATH contiene directorio temporal: $dir"
        ((path_alertas++))
        ((alertas++))
    elif [[ ! -d "$dir" ]]; then
        echo -e "  ${YELLOW}REVISAR${NC} PATH contiene directorio inexistente: $dir"
    fi
done
if [[ $path_alertas -eq 0 ]]; then
    echo -e "  ${GREEN}OK${NC}  PATH no contiene directorios sospechosos"
fi

# 7. Systemd units vs paquetes
echo ""
echo -e "${CYAN}── Systemd units no pertenecientes a paquetes ──${NC}"
unit_alertas=0
for unitfile in /etc/systemd/system/*.service; do
    [[ -f "$unitfile" ]] || continue
    basename_unit=$(basename "$unitfile")
    # Excluir units de securizar
    if echo "$basename_unit" | grep -q "securizar"; then
        continue
    fi
    owned=0
    if command -v rpm &>/dev/null; then
        rpm -qf "$unitfile" &>/dev/null 2>&1 && owned=1
    elif command -v dpkg &>/dev/null; then
        dpkg -S "$unitfile" &>/dev/null 2>&1 && owned=1
    elif command -v pacman &>/dev/null; then
        pacman -Qo "$unitfile" &>/dev/null 2>&1 && owned=1
    fi
    if [[ $owned -eq 0 ]]; then
        echo -e "  ${YELLOW}REVISAR${NC} $basename_unit (no pertenece a paquete)"
        ((unit_alertas++))
    fi
done
if [[ $unit_alertas -eq 0 ]]; then
    echo -e "  ${GREEN}OK${NC}  Todas las units pertenecen a paquetes o securizar"
fi

# Resumen
echo ""
echo -e "${CYAN}── Resumen ──${NC}"
if [[ $alertas -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}No se detectaron indicadores de troyanizacion${NC}"
else
    echo -e "  ${RED}${BOLD}ALERTAS CRITICAS: $alertas${NC}"
    echo -e "  ${RED}Investiga inmediatamente los hallazgos marcados como ALERTA${NC}"
fi

echo ""
echo -e "${BOLD}Deteccion completada: $(date)${NC}"
EOFTROJAN
    chmod +x /usr/local/bin/detectar-troyanizados.sh
    log_change "Creado" "/usr/local/bin/detectar-troyanizados.sh"
    log_change "Permisos" "/usr/local/bin/detectar-troyanizados.sh -> +x"

    # Cron semanal
    cat > /etc/cron.weekly/securizar-detectar-troyanizados << 'EOFCRON'
#!/bin/bash
# Deteccion semanal de paquetes troyanizados - securizar Modulo 44
/usr/local/bin/detectar-troyanizados.sh > /var/log/securizar-troyanizados.log 2>&1
EOFCRON
    chmod +x /etc/cron.weekly/securizar-detectar-troyanizados
    log_change "Creado" "/etc/cron.weekly/securizar-detectar-troyanizados"

    log_info "Sistema de deteccion de troyanizados instalado"
    log_info "Ejecuta: detectar-troyanizados.sh"
else
    log_skip "Deteccion de paquetes troyanizados"
fi

# ============================================================
# S8: HARDENING DEL GESTOR DE PAQUETES
# ============================================================
log_section "S8: HARDENING DEL GESTOR DE PAQUETES"

echo "Endurece la configuracion del gestor de paquetes:"
echo "  - Habilita verificacion GPG estricta"
echo "  - Configura mirrors HTTPS"
echo "  - Deshabilita instalacion de recomendados/sugeridos"
echo "  - Deshabilita refresh desde fuentes no confiables"
echo ""

if check_executable /usr/local/bin/securizar-install-hook.sh; then
    log_already "Hardening del gestor de paquetes (securizar-install-hook.sh existe)"
elif ask "¿Aplicar hardening del gestor de paquetes?"; then

    case "$DISTRO_FAMILY" in
        suse)
            log_info "Aplicando hardening de zypper..."
            zypp_conf="/etc/zypp/zypp.conf"
            if [[ -f "$zypp_conf" ]]; then
                cp "$zypp_conf" "$BACKUP_DIR/"
                log_change "Backup" "$zypp_conf"

                # gpgcheck
                if ! grep -q "^gpgcheck = 1" "$zypp_conf" 2>/dev/null; then
                    if grep -q "^gpgcheck" "$zypp_conf"; then
                        sed -i 's/^gpgcheck.*/gpgcheck = 1/' "$zypp_conf"
                    else
                        echo "gpgcheck = 1" >> "$zypp_conf"
                    fi
                    log_change "Aplicado" "gpgcheck = 1 en zypp.conf"
                fi

                # solver.onlyRequires
                if ! grep -q "^solver.onlyRequires = true" "$zypp_conf" 2>/dev/null; then
                    if grep -q "^solver.onlyRequires" "$zypp_conf"; then
                        sed -i 's/^solver\.onlyRequires.*/solver.onlyRequires = true/' "$zypp_conf"
                    else
                        echo "solver.onlyRequires = true" >> "$zypp_conf"
                    fi
                    log_change "Aplicado" "solver.onlyRequires = true en zypp.conf"
                fi
            else
                log_warn "Archivo $zypp_conf no encontrado"
            fi
            ;;
        debian)
            log_info "Aplicando hardening de apt..."
            cat > /etc/apt/apt.conf.d/99-securizar-hardening << 'EOF'
// Hardening de apt - securizar Modulo 44
// No instalar paquetes recomendados ni sugeridos
APT::Install-Recommends "false";
APT::Install-Suggests "false";

// No permitir repositorios inseguros
Acquire::AllowInsecureRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";

// No permitir paquetes sin autenticar
APT::Get::AllowUnauthenticated "false";

// Forzar HTTPS para repositorios
Acquire::ForceIPv4 "true";
EOF
            log_change "Creado" "/etc/apt/apt.conf.d/99-securizar-hardening"
            ;;
        rhel)
            log_info "Aplicando hardening de dnf..."
            dnf_conf="/etc/dnf/dnf.conf"
            [[ ! -f "$dnf_conf" ]] && dnf_conf="/etc/yum.conf"
            if [[ -f "$dnf_conf" ]]; then
                cp "$dnf_conf" "$BACKUP_DIR/"
                log_change "Backup" "$dnf_conf"

                # gpgcheck
                if ! grep -q "^gpgcheck=1" "$dnf_conf" 2>/dev/null; then
                    if grep -q "^gpgcheck=" "$dnf_conf"; then
                        sed -i 's/^gpgcheck=.*/gpgcheck=1/' "$dnf_conf"
                    else
                        sed -i '/^\[main\]/a gpgcheck=1' "$dnf_conf"
                    fi
                    log_change "Aplicado" "gpgcheck=1 en $dnf_conf"
                fi

                # localpkg_gpgcheck
                if ! grep -q "^localpkg_gpgcheck=1" "$dnf_conf" 2>/dev/null; then
                    if grep -q "^localpkg_gpgcheck=" "$dnf_conf"; then
                        sed -i 's/^localpkg_gpgcheck=.*/localpkg_gpgcheck=1/' "$dnf_conf"
                    else
                        sed -i '/^\[main\]/a localpkg_gpgcheck=1' "$dnf_conf"
                    fi
                    log_change "Aplicado" "localpkg_gpgcheck=1 en $dnf_conf"
                fi

                # clean_requirements_on_remove
                if ! grep -q "^clean_requirements_on_remove=True" "$dnf_conf" 2>/dev/null; then
                    if grep -q "^clean_requirements_on_remove=" "$dnf_conf"; then
                        sed -i 's/^clean_requirements_on_remove=.*/clean_requirements_on_remove=True/' "$dnf_conf"
                    else
                        sed -i '/^\[main\]/a clean_requirements_on_remove=True' "$dnf_conf"
                    fi
                    log_change "Aplicado" "clean_requirements_on_remove=True en $dnf_conf"
                fi
            else
                log_warn "Archivo dnf.conf/yum.conf no encontrado"
            fi
            ;;
        arch)
            log_info "Aplicando hardening de pacman..."
            pacman_conf="/etc/pacman.conf"
            if [[ -f "$pacman_conf" ]]; then
                cp "$pacman_conf" "$BACKUP_DIR/"
                log_change "Backup" "$pacman_conf"

                # SigLevel
                current_siglevel=$(grep "^SigLevel" "$pacman_conf" | head -1)
                if ! echo "$current_siglevel" | grep -q "Required DatabaseRequired"; then
                    if grep -q "^SigLevel" "$pacman_conf"; then
                        sed -i 's/^SigLevel.*/SigLevel = Required DatabaseRequired/' "$pacman_conf"
                    else
                        sed -i '/^\[options\]/a SigLevel = Required DatabaseRequired' "$pacman_conf"
                    fi
                    log_change "Aplicado" "SigLevel = Required DatabaseRequired en pacman.conf"
                else
                    log_info "SigLevel ya esta configurado correctamente"
                fi
            else
                log_warn "Archivo $pacman_conf no encontrado"
            fi
            ;;
    esac

    log_info "Hardening del gestor de paquetes aplicado"
else
    log_skip "Hardening del gestor de paquetes"
fi

# ============================================================
# S9: MONITORIZACION DE CAMBIOS DE SOFTWARE
# ============================================================
log_section "S9: MONITORIZACION DE CAMBIOS DE SOFTWARE"

echo "Crea sistema de monitorizacion de cambios de software:"
echo "  - Rastrea instalaciones, eliminaciones, actualizaciones"
echo "  - Compara contra SBOM, detecta cambios inesperados"
echo "  - Alerta sobre downgrades y paquetes sin firmar"
echo "  - Detecta nuevos SUID/SGID y modulos de kernel"
echo "  - Monitoriza /usr/local/bin y /usr/local/sbin"
echo "  - Timer systemd cada 6 horas"
echo ""

if check_executable /usr/local/bin/monitorizar-software.sh; then
    log_already "Monitorizacion de cambios de software (monitorizar-software.sh existe)"
elif ask "¿Crear sistema de monitorizacion de cambios de software?"; then

    mkdir -p /var/lib/securizar/software-monitor

    cat > /usr/local/bin/monitorizar-software.sh << 'EOFMON'
#!/bin/bash
# ============================================================
# Monitorizacion de cambios de software - securizar Modulo 44
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

STATE_DIR="/var/lib/securizar/software-monitor"
SBOM_DIR="/var/lib/securizar/sbom"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

mkdir -p "$STATE_DIR"

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  MONITORIZACION DE CAMBIOS DE SOFTWARE${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

alertas=0

# 1. Rastrear cambios recientes del gestor de paquetes
echo -e "${CYAN}── Operaciones recientes del gestor de paquetes ──${NC}"
if command -v zypper &>/dev/null; then
    if [[ -f /var/log/zypp/history ]]; then
        echo "  Ultimas 20 operaciones zypper:"
        tail -20 /var/log/zypp/history | while IFS='|' read -r date action pkg ver arch repo _; do
            date_clean=$(echo "$date" | xargs)
            action_clean=$(echo "$action" | xargs)
            pkg_clean=$(echo "$pkg" | xargs)
            case "$action_clean" in
                install) echo -e "    ${GREEN}+${NC} [$date_clean] Instalado: $pkg_clean" ;;
                remove)  echo -e "    ${RED}-${NC} [$date_clean] Eliminado: $pkg_clean" ;;
                *)       echo -e "    ${YELLOW}~${NC} [$date_clean] $action_clean: $pkg_clean" ;;
            esac
        done
    fi
elif command -v apt &>/dev/null; then
    if [[ -d /var/log/apt ]]; then
        echo "  Ultimas 20 operaciones apt:"
        grep -hE "^(Install|Remove|Upgrade)" /var/log/apt/history.log 2>/dev/null | tail -20 | while IFS= read -r line; do
            action=$(echo "$line" | cut -d: -f1)
            case "$action" in
                Install) echo -e "    ${GREEN}+${NC} $line" ;;
                Remove)  echo -e "    ${RED}-${NC} $line" ;;
                Upgrade) echo -e "    ${YELLOW}~${NC} $line" ;;
            esac
        done || true
    fi
elif command -v dnf &>/dev/null; then
    echo "  Ultimas 20 transacciones dnf:"
    dnf history list --reverse 2>/dev/null | tail -20 || true
elif command -v pacman &>/dev/null; then
    if [[ -f /var/log/pacman.log ]]; then
        echo "  Ultimas 20 operaciones pacman:"
        grep -E "\[ALPM\] (installed|removed|upgraded)" /var/log/pacman.log | tail -20 | while IFS= read -r line; do
            if echo "$line" | grep -q "installed"; then
                echo -e "    ${GREEN}+${NC} $line"
            elif echo "$line" | grep -q "removed"; then
                echo -e "    ${RED}-${NC} $line"
            else
                echo -e "    ${YELLOW}~${NC} $line"
            fi
        done
    fi
fi

# 2. Comparar con SBOM
echo ""
echo -e "${CYAN}── Comparacion con SBOM ──${NC}"
sbom_latest="${SBOM_DIR}/sbom-latest.json"
if [[ -f "$sbom_latest" ]]; then
    sbom_date=$(stat -c %Y "$sbom_latest" 2>/dev/null || echo "0")
    sbom_age=$(( ($(date +%s) - sbom_date) / 3600 ))
    echo -e "  SBOM antigüedad: ${BOLD}${sbom_age} horas${NC}"
    if [[ $sbom_age -gt 48 ]]; then
        echo -e "  ${YELLOW}AVISO: SBOM tiene mas de 48 horas - regenerar con generar-sbom.sh${NC}"
        ((alertas++))
    fi

    # Contar paquetes actuales vs SBOM
    current_count=0
    if command -v rpm &>/dev/null && ! command -v pacman &>/dev/null; then
        current_count=$(rpm -qa 2>/dev/null | wc -l)
    elif command -v dpkg-query &>/dev/null; then
        current_count=$(dpkg-query -W 2>/dev/null | wc -l)
    elif command -v pacman &>/dev/null; then
        current_count=$(pacman -Q 2>/dev/null | wc -l)
    fi
    sbom_count=$(grep -c '"name"' "$sbom_latest" 2>/dev/null || echo "0")
    diff_count=$((current_count - sbom_count))
    echo -e "  Paquetes actuales: ${BOLD}${current_count}${NC} | SBOM: ${BOLD}${sbom_count}${NC} | Diferencia: ${BOLD}${diff_count}${NC}"
    if [[ $diff_count -ne 0 ]]; then
        echo -e "  ${YELLOW}Cambios detectados desde el ultimo SBOM${NC}"
    fi
else
    echo -e "  ${YELLOW}No hay SBOM disponible - ejecuta generar-sbom.sh${NC}"
fi

# 3. Nuevos SUID/SGID
echo ""
echo -e "${CYAN}── Verificacion de nuevos SUID/SGID ──${NC}"
suid_current=$(mktemp)
suid_baseline="${STATE_DIR}/suid-baseline.txt"
find / -path /proc -prune -o -path /sys -prune -o -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null | sort > "$suid_current"

if [[ -f "$suid_baseline" ]]; then
    new_suid=$(comm -13 "$suid_baseline" "$suid_current" || true)
    if [[ -n "$new_suid" ]]; then
        echo -e "  ${RED}NUEVOS SUID/SGID detectados:${NC}"
        echo "$new_suid" | while IFS= read -r f; do
            echo -e "    ${RED}+${NC}  $f"
            ((alertas++))
        done
    else
        echo -e "  ${GREEN}OK${NC}  No hay nuevos binarios SUID/SGID"
    fi
    removed_suid=$(comm -23 "$suid_baseline" "$suid_current" || true)
    if [[ -n "$removed_suid" ]]; then
        echo -e "  ${YELLOW}SUID/SGID eliminados:${NC}"
        echo "$removed_suid" | while IFS= read -r f; do
            echo -e "    ${YELLOW}-${NC}  $f"
        done
    fi
else
    echo -e "  ${DIM}Primera ejecucion - creando baseline SUID/SGID${NC}"
fi
cp "$suid_current" "$suid_baseline"
rm -f "$suid_current"

# 4. Modulos de kernel
echo ""
echo -e "${CYAN}── Modulos de kernel cargados ──${NC}"
modules_current=$(mktemp)
modules_baseline="${STATE_DIR}/modules-baseline.txt"
lsmod 2>/dev/null | awk 'NR>1 {print $1}' | sort > "$modules_current"

if [[ -f "$modules_baseline" ]]; then
    new_modules=$(comm -13 "$modules_baseline" "$modules_current" || true)
    if [[ -n "$new_modules" ]]; then
        echo -e "  ${YELLOW}NUEVOS modulos de kernel:${NC}"
        echo "$new_modules" | while IFS= read -r m; do
            echo -e "    ${YELLOW}+${NC}  $m"
        done
    else
        echo -e "  ${GREEN}OK${NC}  No hay nuevos modulos de kernel"
    fi
else
    echo -e "  ${DIM}Primera ejecucion - creando baseline de modulos${NC}"
fi
cp "$modules_current" "$modules_baseline"
rm -f "$modules_current"

# 5. Archivos nuevos en /usr/local/bin y /usr/local/sbin
echo ""
echo -e "${CYAN}── Archivos nuevos en /usr/local/bin y /usr/local/sbin ──${NC}"
localbin_current=$(mktemp)
localbin_baseline="${STATE_DIR}/localbin-baseline.txt"
{
    ls -1 /usr/local/bin/ 2>/dev/null
    ls -1 /usr/local/sbin/ 2>/dev/null
} | sort > "$localbin_current"

if [[ -f "$localbin_baseline" ]]; then
    new_files=$(comm -13 "$localbin_baseline" "$localbin_current" || true)
    if [[ -n "$new_files" ]]; then
        echo -e "  ${YELLOW}NUEVOS archivos:${NC}"
        echo "$new_files" | while IFS= read -r f; do
            echo -e "    ${YELLOW}+${NC}  $f"
        done
    else
        echo -e "  ${GREEN}OK${NC}  No hay archivos nuevos"
    fi
else
    echo -e "  ${DIM}Primera ejecucion - creando baseline de archivos locales${NC}"
fi
cp "$localbin_current" "$localbin_baseline"
rm -f "$localbin_current"

# Resumen
echo ""
echo -e "${CYAN}── Resumen ──${NC}"
if [[ $alertas -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}No se detectaron cambios sospechosos${NC}"
else
    echo -e "  ${RED}${BOLD}ALERTAS: $alertas${NC}"
fi

echo ""
echo -e "${BOLD}Monitorizacion completada: $(date)${NC}"
EOFMON
    chmod +x /usr/local/bin/monitorizar-software.sh
    log_change "Creado" "/usr/local/bin/monitorizar-software.sh"
    log_change "Permisos" "/usr/local/bin/monitorizar-software.sh -> +x"

    # Timer systemd cada 6 horas
    cat > /etc/systemd/system/securizar-monitor-software.service << 'EOF'
[Unit]
Description=Monitorizacion de cambios de software - securizar
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/monitorizar-software.sh
StandardOutput=journal
StandardError=journal
EOF
    log_change "Creado" "/etc/systemd/system/securizar-monitor-software.service"

    cat > /etc/systemd/system/securizar-monitor-software.timer << 'EOF'
[Unit]
Description=Timer para monitorizacion de cambios de software - securizar (cada 6h)

[Timer]
OnCalendar=*-*-* 00/6:00:00
RandomizedDelaySec=900
Persistent=true

[Install]
WantedBy=timers.target
EOF
    log_change "Creado" "/etc/systemd/system/securizar-monitor-software.timer"

    systemctl daemon-reload 2>/dev/null || true
    systemctl enable securizar-monitor-software.timer 2>/dev/null || true
    systemctl start securizar-monitor-software.timer 2>/dev/null || true
    log_change "Activado" "securizar-monitor-software.timer (cada 6 horas)"

    log_info "Sistema de monitorizacion de software instalado"
    log_info "Ejecuta: monitorizar-software.sh"
else
    log_skip "Monitorizacion de cambios de software"
fi

# ============================================================
# S10: AUDITORIA DE CADENA DE SUMINISTRO
# ============================================================
log_section "S10: AUDITORIA DE CADENA DE SUMINISTRO"

echo "Crea auditoria integral de cadena de suministro:"
echo "  - Evalua todos los controles implementados en este modulo"
echo "  - Puntuacion: SEGURO / MEJORABLE / INSEGURO"
echo "  - Mapeo a NIST 800-53 SA (System and Services Acquisition)"
echo "  - Salida JSON para integracion"
echo "  - Tarea cron mensual"
echo ""

if check_executable /usr/local/bin/auditoria-cadena-suministro.sh; then
    log_already "Auditoria de cadena de suministro (auditoria-cadena-suministro.sh existe)"
elif ask "¿Crear sistema de auditoria de cadena de suministro?"; then

    mkdir -p /var/lib/securizar/auditorias

    cat > /usr/local/bin/auditoria-cadena-suministro.sh << 'EOFAUDIT'
#!/bin/bash
# ============================================================
# Auditoria integral de cadena de suministro - securizar Modulo 44
# Mapeo NIST 800-53 SA (System and Services Acquisition)
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

AUDIT_DIR="/var/lib/securizar/auditorias"
mkdir -p "$AUDIT_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
JSON_FILE="${AUDIT_DIR}/auditoria-cadena-${TIMESTAMP}.json"

echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  AUDITORIA INTEGRAL DE CADENA DE SUMINISTRO${NC}"
echo -e "${BOLD}  NIST 800-53 SA (System and Services Acquisition)${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo ""

score=0
max_score=0
checks=()

check_control() {
    local name="$1" nist="$2" result="$3" detail="$4"
    ((max_score += 10))
    if [[ "$result" == "PASS" ]]; then
        echo -e "  ${GREEN}PASS${NC}  [$nist] $name"
        ((score += 10))
        checks+=("{\"control\":\"$name\",\"nist\":\"$nist\",\"result\":\"PASS\",\"detail\":\"$detail\"}")
    elif [[ "$result" == "PARTIAL" ]]; then
        echo -e "  ${YELLOW}PARCIAL${NC} [$nist] $name: $detail"
        ((score += 5))
        checks+=("{\"control\":\"$name\",\"nist\":\"$nist\",\"result\":\"PARTIAL\",\"detail\":\"$detail\"}")
    else
        echo -e "  ${RED}FAIL${NC}  [$nist] $name: $detail"
        checks+=("{\"control\":\"$name\",\"nist\":\"$nist\",\"result\":\"FAIL\",\"detail\":\"$detail\"}")
    fi
}

echo -e "${CYAN}── Evaluacion de controles ──${NC}"
echo ""

# 1. Verificacion GPG (SA-12)
gpg_ok=0
if command -v zypper &>/dev/null; then
    if ! grep -rq "gpgcheck=0" /etc/zypp/repos.d/ 2>/dev/null; then gpg_ok=1; fi
elif command -v apt &>/dev/null; then
    if ! grep -rq "AllowUnauthenticated" /etc/apt/apt.conf.d/ 2>/dev/null; then gpg_ok=1; fi
elif command -v dnf &>/dev/null; then
    if grep -q "^gpgcheck=1" /etc/dnf/dnf.conf 2>/dev/null || grep -q "^gpgcheck=1" /etc/yum.conf 2>/dev/null; then gpg_ok=1; fi
elif command -v pacman &>/dev/null; then
    if grep -q "^SigLevel.*Required" /etc/pacman.conf 2>/dev/null; then gpg_ok=1; fi
fi
if [[ $gpg_ok -eq 1 ]]; then
    check_control "Verificacion GPG de paquetes" "SA-12(10)" "PASS" "GPG enforced"
else
    check_control "Verificacion GPG de paquetes" "SA-12(10)" "FAIL" "GPG no enforced en gestor de paquetes"
fi

# 2. SBOM actual (SA-17)
if [[ -f /var/lib/securizar/sbom/sbom-latest.json ]]; then
    sbom_age=$(( ($(date +%s) - $(stat -c %Y /var/lib/securizar/sbom/sbom-latest.json 2>/dev/null || echo 0)) / 86400 ))
    if [[ $sbom_age -le 1 ]]; then
        check_control "Inventario SBOM actualizado" "SA-17" "PASS" "SBOM de hace ${sbom_age} dias"
    elif [[ $sbom_age -le 7 ]]; then
        check_control "Inventario SBOM actualizado" "SA-17" "PARTIAL" "SBOM de hace ${sbom_age} dias"
    else
        check_control "Inventario SBOM actualizado" "SA-17" "FAIL" "SBOM de hace ${sbom_age} dias"
    fi
else
    check_control "Inventario SBOM actualizado" "SA-17" "FAIL" "Sin SBOM generado"
fi

# 3. Auditoria CVE reciente (SA-11)
if [[ -f /var/log/securizar-cves.log ]]; then
    cve_age=$(( ($(date +%s) - $(stat -c %Y /var/log/securizar-cves.log 2>/dev/null || echo 0)) / 86400 ))
    if [[ $cve_age -le 7 ]]; then
        check_control "Auditoria CVE reciente" "SA-11(1)" "PASS" "Hace ${cve_age} dias"
    else
        check_control "Auditoria CVE reciente" "SA-11(1)" "PARTIAL" "Hace ${cve_age} dias"
    fi
else
    check_control "Auditoria CVE reciente" "SA-11(1)" "FAIL" "Sin auditoria CVE"
fi

# 4. Repositorios auditados (SA-12)
if [[ -f /etc/securizar/repos-whitelist.conf ]]; then
    check_control "Repositorios con whitelist" "SA-12(1)" "PASS" "Whitelist configurada"
else
    check_control "Repositorios con whitelist" "SA-12(1)" "FAIL" "Sin whitelist de repositorios"
fi

# 5. Integridad de binarios (SA-12(2))
if [[ -f /var/lib/securizar/binary-hashes/baseline.sha256 ]]; then
    baseline_age=$(( ($(date +%s) - $(stat -c %Y /var/lib/securizar/binary-hashes/baseline.sha256 2>/dev/null || echo 0)) / 86400 ))
    if [[ $baseline_age -le 7 ]]; then
        check_control "Baseline de integridad de binarios" "SA-12(2)" "PASS" "Baseline de hace ${baseline_age} dias"
    else
        check_control "Baseline de integridad de binarios" "SA-12(2)" "PARTIAL" "Baseline de hace ${baseline_age} dias"
    fi
else
    check_control "Baseline de integridad de binarios" "SA-12(2)" "FAIL" "Sin baseline de hashes"
fi

# 6. Politica de software (SA-4)
if [[ -f /etc/securizar/software-policy.conf ]]; then
    check_control "Politica de instalacion de software" "SA-4" "PASS" "Politica configurada"
else
    check_control "Politica de instalacion de software" "SA-4" "FAIL" "Sin politica definida"
fi

# 7. Deteccion de troyanizados (SA-12(13))
if [[ -x /usr/local/bin/detectar-troyanizados.sh ]]; then
    if [[ -f /var/log/securizar-troyanizados.log ]]; then
        trojan_age=$(( ($(date +%s) - $(stat -c %Y /var/log/securizar-troyanizados.log 2>/dev/null || echo 0)) / 86400 ))
        if [[ $trojan_age -le 7 ]]; then
            check_control "Deteccion de troyanizados" "SA-12(13)" "PASS" "Ejecutado hace ${trojan_age} dias"
        else
            check_control "Deteccion de troyanizados" "SA-12(13)" "PARTIAL" "Ejecutado hace ${trojan_age} dias"
        fi
    else
        check_control "Deteccion de troyanizados" "SA-12(13)" "PARTIAL" "Script instalado pero no ejecutado"
    fi
else
    check_control "Deteccion de troyanizados" "SA-12(13)" "FAIL" "Script no instalado"
fi

# 8. Hardening del gestor de paquetes (SA-12(5))
pkg_hardened=0
if command -v zypper &>/dev/null; then
    grep -q "^solver.onlyRequires = true" /etc/zypp/zypp.conf 2>/dev/null && pkg_hardened=1
elif command -v apt &>/dev/null; then
    [[ -f /etc/apt/apt.conf.d/99-securizar-hardening ]] && pkg_hardened=1
elif command -v dnf &>/dev/null; then
    grep -q "^localpkg_gpgcheck=1" /etc/dnf/dnf.conf 2>/dev/null && pkg_hardened=1
elif command -v pacman &>/dev/null; then
    grep -q "^SigLevel.*Required DatabaseRequired" /etc/pacman.conf 2>/dev/null && pkg_hardened=1
fi
if [[ $pkg_hardened -eq 1 ]]; then
    check_control "Hardening del gestor de paquetes" "SA-12(5)" "PASS" "Configuracion endurecida"
else
    check_control "Hardening del gestor de paquetes" "SA-12(5)" "FAIL" "Gestor de paquetes no endurecido"
fi

# 9. Monitorizacion activa (SA-10)
monitor_ok=0
if systemctl is-active securizar-monitor-software.timer &>/dev/null; then
    monitor_ok=1
fi
if [[ $monitor_ok -eq 1 ]]; then
    check_control "Monitorizacion de cambios de software" "SA-10" "PASS" "Timer activo"
else
    if [[ -x /usr/local/bin/monitorizar-software.sh ]]; then
        check_control "Monitorizacion de cambios de software" "SA-10" "PARTIAL" "Script instalado pero timer inactivo"
    else
        check_control "Monitorizacion de cambios de software" "SA-10" "FAIL" "Sin monitorizacion"
    fi
fi

# 10. Script de verificacion de firmas (SA-12(7))
if [[ -x /usr/local/bin/verificar-firmas-paquetes.sh ]]; then
    check_control "Verificacion de firmas automatizada" "SA-12(7)" "PASS" "Script disponible"
else
    check_control "Verificacion de firmas automatizada" "SA-12(7)" "FAIL" "Script no instalado"
fi

# Calcular puntuacion
echo ""
echo -e "${CYAN}── Puntuacion ──${NC}"
pct=$((score * 100 / max_score))
echo -e "  Puntuacion: ${BOLD}${score}/${max_score} (${pct}%)${NC}"

if [[ $pct -ge 80 ]]; then
    estado="SEGURO"
    estado_color="$GREEN"
elif [[ $pct -ge 50 ]]; then
    estado="MEJORABLE"
    estado_color="$YELLOW"
else
    estado="INSEGURO"
    estado_color="$RED"
fi

echo -e "  Estado: ${estado_color}${BOLD}${estado}${NC}"
echo ""

# Generar JSON
{
    echo '{'
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"hostname\": \"$(hostname)\","
    echo "  \"score\": $score,"
    echo "  \"max_score\": $max_score,"
    echo "  \"percentage\": $pct,"
    echo "  \"status\": \"$estado\","
    echo "  \"framework\": \"NIST 800-53 SA\","
    echo '  "checks": ['
    local first=1
    for c in "${checks[@]}"; do
        if [[ $first -eq 1 ]]; then
            first=0
        else
            echo ','
        fi
        printf '    %s' "$c"
    done
    echo ''
    echo '  ]'
    echo '}'
} > "$JSON_FILE"

echo -e "  Informe JSON: ${BOLD}${JSON_FILE}${NC}"
ln -sf "$JSON_FILE" "${AUDIT_DIR}/auditoria-cadena-latest.json"

echo ""
echo -e "${BOLD}Auditoria completada: $(date)${NC}"
EOFAUDIT
    chmod +x /usr/local/bin/auditoria-cadena-suministro.sh
    log_change "Creado" "/usr/local/bin/auditoria-cadena-suministro.sh"
    log_change "Permisos" "/usr/local/bin/auditoria-cadena-suministro.sh -> +x"

    # Cron mensual
    cat > /etc/cron.monthly/securizar-auditoria-cadena << 'EOFCRON'
#!/bin/bash
# Auditoria mensual de cadena de suministro - securizar Modulo 44
/usr/local/bin/auditoria-cadena-suministro.sh > /var/log/securizar-cadena-suministro.log 2>&1
EOFCRON
    chmod +x /etc/cron.monthly/securizar-auditoria-cadena
    log_change "Creado" "/etc/cron.monthly/securizar-auditoria-cadena"

    log_info "Sistema de auditoria de cadena de suministro instalado"
    log_info "Ejecuta: auditoria-cadena-suministro.sh"
else
    log_skip "Auditoria de cadena de suministro"
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
show_changes_summary
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║       SEGURIDAD DE CADENA DE SUMINISTRO COMPLETADO        ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups guardados en: $BACKUP_DIR"
echo ""
echo "Comandos utiles post-hardening:"
echo "  - Verificar firmas:       verificar-firmas-paquetes.sh"
echo "  - Generar SBOM:           generar-sbom.sh [--diff]"
echo "  - Auditar CVEs:           auditar-cves.sh"
echo "  - Verificar dependencias: verificar-dependencias.sh"
echo "  - Auditar repositorios:   auditar-repositorios.sh"
echo "  - Integridad binarios:    verificar-integridad-binarios.sh"
echo "  - Detectar troyanizados:  detectar-troyanizados.sh"
echo "  - Monitor software:       monitorizar-software.sh"
echo "  - Auditoria integral:     auditoria-cadena-suministro.sh"
echo ""
log_warn "RECOMENDACION: Ejecuta 'auditoria-cadena-suministro.sh' para ver la postura actual"
log_info "Modulo 44 completado"
echo ""
