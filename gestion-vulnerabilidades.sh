#!/bin/bash
# ============================================================
# GESTIÓN DE VULNERABILIDADES - Seguridad Avanzada
# Módulo 70 - Linux Multi-Distro (openSUSE, Debian/Ubuntu, RHEL/Fedora, Arch)
# ============================================================
# Secciones:
#   S1  - Herramientas de escaneo (Trivy, grype, OpenSCAP)
#   S2  - Escaneo de sistema
#   S3  - Escaneo de contenedores
#   S4  - OpenSCAP SCAP Guide
#   S5  - Priorización CVSS+EPSS
#   S6  - Análisis de dependencias
#   S7  - Reporting HTML/JSON
#   S8  - Verificación de parches
#   S9  - Escaneo programado
#   S10 - Auditoría de madurez
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "gestion-vulnerabilidades"
securizar_setup_traps

# ── Pre-check: detectar secciones ya aplicadas ──────────────
_precheck 11
_pc 'check_file_exists /etc/securizar/vuln-management/tools.conf'
_pc 'check_executable /usr/local/bin/securizar-vuln-system.sh'
_pc 'check_executable /usr/local/bin/securizar-vuln-containers.sh'
_pc 'check_executable /usr/local/bin/securizar-vuln-openscap.sh'
_pc 'check_executable /usr/local/bin/securizar-vuln-prioritize.sh'
_pc 'check_executable /usr/local/bin/securizar-vuln-deps.sh'
_pc 'check_executable /usr/local/bin/securizar-vuln-report.sh'
_pc 'check_executable /usr/local/bin/securizar-vuln-patch-verify.sh'
_pc 'check_executable /usr/local/bin/securizar-vuln-scheduled.sh'
_pc 'check_executable /usr/local/bin/auditoria-vuln-management.sh'
_pc 'check_executable /usr/local/bin/securizar-vuln-kernel.sh'
_precheck_result

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   GESTIÓN DE VULNERABILIDADES - Seguridad Avanzada        ║"
echo "║   Trivy, grype, SCAP, CVSS/EPSS, drift                   ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

mkdir -p /etc/securizar/vuln-management
mkdir -p /var/lib/securizar/vuln-management
mkdir -p /var/log/securizar/vuln-management

# ============================================================
# S1: HERRAMIENTAS DE ESCANEO
# ============================================================
log_section "S1: HERRAMIENTAS DE ESCANEO (TRIVY, GRYPE, OPENSCAP)"

echo "Instalación de herramientas de escaneo de vulnerabilidades:"
echo "  - Trivy: escáner universal (SO, contenedores, IaC)"
echo "  - grype: escáner de SBOMs y contenedores"
echo "  - OpenSCAP: cumplimiento y vulnerabilidades OVAL"
echo ""

if check_file_exists /etc/securizar/vuln-management/tools.conf; then
    log_already "Herramientas de escaneo configuradas"
elif ask "¿Instalar herramientas de escaneo de vulnerabilidades?"; then

    TOOLS_INSTALLED=""

    # --- Trivy ---
    if ! command -v trivy &>/dev/null; then
        log_info "Instalando Trivy..."
        case "$DISTRO_FAMILY" in
            suse)
                zypper addrepo -f https://aquasecurity.github.io/trivy-repo/rpm/releases/\$basearch/ trivy 2>/dev/null || true
                zypper --non-interactive --gpg-auto-import-keys install trivy 2>/dev/null || {
                    # Fallback: binary install
                    log_info "Intentando instalación binaria de Trivy..."
                    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin 2>/dev/null || log_warn "No se pudo instalar Trivy"
                }
                ;;
            debian)
                curl -sfL https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /usr/share/keyrings/trivy.gpg 2>/dev/null || true
                echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" > /etc/apt/sources.list.d/trivy.list 2>/dev/null
                apt-get update -qq 2>/dev/null
                apt-get install -y trivy 2>/dev/null || log_warn "No se pudo instalar Trivy"
                ;;
            rhel)
                cat > /etc/yum.repos.d/trivy.repo << 'EOFREPO'
[trivy]
name=Trivy repository
baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$basearch/
gpgcheck=0
enabled=1
EOFREPO
                dnf install -y trivy 2>/dev/null || yum install -y trivy 2>/dev/null || log_warn "No se pudo instalar Trivy"
                ;;
            arch)
                pacman -S --noconfirm trivy 2>/dev/null || log_warn "Trivy disponible en AUR: yay -S trivy"
                ;;
        esac
    fi
    if command -v trivy &>/dev/null; then
        TOOLS_INSTALLED="${TOOLS_INSTALLED}trivy "
        log_info "Trivy instalado: $(trivy --version 2>/dev/null | head -1)"
    fi

    # --- grype ---
    if ! command -v grype &>/dev/null; then
        log_info "Instalando grype..."
        curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin 2>/dev/null || log_warn "No se pudo instalar grype"
    fi
    if command -v grype &>/dev/null; then
        TOOLS_INSTALLED="${TOOLS_INSTALLED}grype "
        log_info "grype instalado: $(grype version 2>/dev/null | head -1)"
    fi

    # --- OpenSCAP ---
    if ! command -v oscap &>/dev/null; then
        log_info "Instalando OpenSCAP..."
        case "$DISTRO_FAMILY" in
            suse)   zypper --non-interactive install openscap-utils openscap-content 2>/dev/null || true ;;
            debian) apt-get install -y libopenscap8 openscap-utils 2>/dev/null || true ;;
            rhel)   dnf install -y openscap-scanner scap-security-guide 2>/dev/null || true ;;
            arch)   pacman -S --noconfirm openscap 2>/dev/null || true ;;
        esac
    fi
    if command -v oscap &>/dev/null; then
        TOOLS_INSTALLED="${TOOLS_INSTALLED}oscap "
        log_info "OpenSCAP instalado: $(oscap --version 2>/dev/null | head -1)"
    fi

    # Guardar estado de herramientas
    cat > /etc/securizar/vuln-management/tools.conf << EOFTOOLS
# Herramientas de escaneo de vulnerabilidades
# Generado por gestion-vulnerabilidades.sh - $(date -Iseconds)
TOOLS_INSTALLED="$TOOLS_INSTALLED"
SCAN_DIR="/var/lib/securizar/vuln-management"
LOG_DIR="/var/log/securizar/vuln-management"
EOFTOOLS

    chmod 644 /etc/securizar/vuln-management/tools.conf
    log_change "Creado" "/etc/securizar/vuln-management/tools.conf"
    log_info "Herramientas instaladas: $TOOLS_INSTALLED"

else
    log_skip "Herramientas de escaneo"
fi

# ============================================================
# S2: ESCANEO DE SISTEMA
# ============================================================
log_section "S2: ESCANEO DE SISTEMA"

echo "Script de escaneo de vulnerabilidades del sistema operativo."
echo "Usa Trivy (preferido) o fallback a escaneo manual de CVEs."
echo ""

if check_executable /usr/local/bin/securizar-vuln-system.sh; then
    log_already "Escaneo de sistema"
elif ask "¿Crear script de escaneo de vulnerabilidades del sistema?"; then

    cat > /usr/local/bin/securizar-vuln-system.sh << 'EOFSCAN'
#!/bin/bash
# ============================================================
# ESCANEO DE VULNERABILIDADES DEL SISTEMA
# Usa Trivy rootfs, con fallback a grype/manual
# Uso: securizar-vuln-system.sh [--json] [--severity HIGH,CRITICAL]
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

SCAN_DIR="/var/lib/securizar/vuln-management"
LOG_DIR="/var/log/securizar/vuln-management"
mkdir -p "$SCAN_DIR" "$LOG_DIR"

OUTPUT_JSON=false
SEVERITY="UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --json) OUTPUT_JSON=true; shift ;;
        --severity) SEVERITY="$2"; shift 2 ;;
        *) shift ;;
    esac
done

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT_BASE="$SCAN_DIR/system-scan-$TIMESTAMP"

echo -e "${BOLD}╔════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║   ESCANEO DE VULNERABILIDADES DEL SISTEMA  ║${NC}"
echo -e "${BOLD}╚════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${DIM}Fecha: $(date -Iseconds)${NC}"
echo -e "${DIM}Hostname: $(hostname)${NC}"
echo ""

SCANNER="none"
VULN_COUNT=0

# Intentar Trivy primero
if command -v trivy &>/dev/null; then
    SCANNER="trivy"
    echo -e "${CYAN}Escaneando con Trivy (rootfs /)...${NC}"
    echo -e "${DIM}Esto puede tardar varios minutos en la primera ejecución.${NC}"
    echo ""

    trivy rootfs / --severity "$SEVERITY" --format json -o "${REPORT_BASE}.json" 2>/dev/null || true

    if [[ -f "${REPORT_BASE}.json" ]]; then
        # Generar tabla resumen
        if command -v jq &>/dev/null; then
            echo -e "${BOLD}Resumen por severidad:${NC}"
            echo ""
            for sev in CRITICAL HIGH MEDIUM LOW UNKNOWN; do
                COUNT=$(jq -r "[.Results[]?.Vulnerabilities[]? | select(.Severity == \"$sev\")] | length" "${REPORT_BASE}.json" 2>/dev/null || echo 0)
                case "$sev" in
                    CRITICAL) COLOR="$RED" ;;
                    HIGH)     COLOR="$YELLOW" ;;
                    MEDIUM)   COLOR="$CYAN" ;;
                    *)        COLOR="$DIM" ;;
                esac
                printf "  ${COLOR}%-10s${NC} %d\n" "$sev" "$COUNT"
                VULN_COUNT=$((VULN_COUNT + COUNT))
            done
            echo ""
            echo -e "${BOLD}Total vulnerabilidades: $VULN_COUNT${NC}"

            # Top 10 críticas
            echo ""
            echo -e "${BOLD}Top 10 vulnerabilidades más críticas:${NC}"
            jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL" or .Severity == "HIGH") | "\(.VulnerabilityID) \(.Severity) \(.PkgName) \(.InstalledVersion) → \(.FixedVersion // "sin fix")"' "${REPORT_BASE}.json" 2>/dev/null | head -10 | while IFS= read -r line; do
                echo "  $line"
            done
        else
            # Sin jq, salida en texto
            trivy rootfs / --severity "$SEVERITY" 2>/dev/null | tee "${REPORT_BASE}.txt"
        fi
    fi

# Fallback a grype
elif command -v grype &>/dev/null; then
    SCANNER="grype"
    echo -e "${CYAN}Escaneando con grype (dir:/)...${NC}"
    grype dir:/ --output json > "${REPORT_BASE}.json" 2>/dev/null || true

    if [[ -f "${REPORT_BASE}.json" ]] && command -v jq &>/dev/null; then
        VULN_COUNT=$(jq '.matches | length' "${REPORT_BASE}.json" 2>/dev/null || echo 0)
        echo -e "${BOLD}Vulnerabilidades encontradas: $VULN_COUNT${NC}"
    fi

# Fallback manual
else
    SCANNER="manual"
    echo -e "${YELLOW}Ni Trivy ni grype disponibles. Escaneo manual básico.${NC}"
    echo ""

    echo -e "${CYAN}Paquetes con actualizaciones de seguridad pendientes:${NC}"
    if command -v zypper &>/dev/null; then
        zypper list-patches --category security 2>/dev/null | tee "${REPORT_BASE}.txt"
    elif command -v apt-get &>/dev/null; then
        apt-get -s upgrade 2>/dev/null | grep "^Inst" | grep -i securi | tee "${REPORT_BASE}.txt"
    elif command -v dnf &>/dev/null; then
        dnf updateinfo list security 2>/dev/null | tee "${REPORT_BASE}.txt"
    fi
fi

echo ""
echo -e "${DIM}Scanner: $SCANNER${NC}"
echo -e "${DIM}Reporte: ${REPORT_BASE}.*${NC}"

# Guardar metadata
cat > "${REPORT_BASE}.meta" << EOFMETA
scanner=$SCANNER
timestamp=$TIMESTAMP
hostname=$(hostname)
kernel=$(uname -r)
vuln_count=$VULN_COUNT
severity_filter=$SEVERITY
EOFMETA

logger -t securizar-vuln "System scan completed: scanner=$SCANNER vulns=$VULN_COUNT"
EOFSCAN

    chmod 755 /usr/local/bin/securizar-vuln-system.sh
    log_change "Creado" "/usr/local/bin/securizar-vuln-system.sh"
    log_info "Script de escaneo de sistema instalado"
    echo -e "${DIM}Uso: securizar-vuln-system.sh [--severity HIGH,CRITICAL]${NC}"

else
    log_skip "Escaneo de sistema"
fi

# ============================================================
# S3: ESCANEO DE CONTENEDORES
# ============================================================
log_section "S3: ESCANEO DE CONTENEDORES"

echo "Escaneo de imágenes Docker y Podman en busca de vulnerabilidades."
echo "Descubre automáticamente todas las imágenes locales."
echo ""

if check_executable /usr/local/bin/securizar-vuln-containers.sh; then
    log_already "Escaneo de contenedores"
elif ask "¿Crear script de escaneo de contenedores?"; then

    cat > /usr/local/bin/securizar-vuln-containers.sh << 'EOFCONT'
#!/bin/bash
# ============================================================
# ESCANEO DE VULNERABILIDADES EN CONTENEDORES
# Docker + Podman, con threshold de política
# Uso: securizar-vuln-containers.sh [--threshold CRITICAL] [--image IMAGE]
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

SCAN_DIR="/var/lib/securizar/vuln-management/containers"
mkdir -p "$SCAN_DIR"

THRESHOLD="HIGH"
TARGET_IMAGE=""
FAIL_ON_THRESHOLD=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --threshold) THRESHOLD="$2"; shift 2 ;;
        --image) TARGET_IMAGE="$2"; shift 2 ;;
        --fail) FAIL_ON_THRESHOLD=true; shift ;;
        *) shift ;;
    esac
done

echo -e "${BOLD}╔════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║   ESCANEO DE CONTENEDORES                  ║${NC}"
echo -e "${BOLD}╚════════════════════════════════════════════╝${NC}"
echo ""

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
TOTAL_IMAGES=0
TOTAL_VULNS=0
FAILED_IMAGES=0

scan_image() {
    local image="$1"
    local runtime="$2"
    local safe_name
    safe_name=$(echo "$image" | tr '/:' '_')
    local report="$SCAN_DIR/${safe_name}-${TIMESTAMP}.json"

    echo -e "  ${CYAN}Escaneando:${NC} $image ${DIM}($runtime)${NC}"
    TOTAL_IMAGES=$((TOTAL_IMAGES + 1))

    if command -v trivy &>/dev/null; then
        trivy image "$image" --severity "$THRESHOLD,CRITICAL" --format json -o "$report" 2>/dev/null
        if [[ -f "$report" ]] && command -v jq &>/dev/null; then
            local count
            count=$(jq '[.Results[]?.Vulnerabilities[]?] | length' "$report" 2>/dev/null || echo 0)
            TOTAL_VULNS=$((TOTAL_VULNS + count))
            if [[ "$count" -gt 0 ]]; then
                echo -e "    ${YELLOW}Vulnerabilidades ($THRESHOLD+): $count${NC}"
                FAILED_IMAGES=$((FAILED_IMAGES + 1))
            else
                echo -e "    ${GREEN}Sin vulnerabilidades $THRESHOLD+${NC}"
            fi
        fi
    elif command -v grype &>/dev/null; then
        grype "$image" --output json > "$report" 2>/dev/null || true
        if [[ -f "$report" ]] && command -v jq &>/dev/null; then
            local count
            count=$(jq '.matches | length' "$report" 2>/dev/null || echo 0)
            TOTAL_VULNS=$((TOTAL_VULNS + count))
            echo -e "    ${DIM}Vulnerabilidades: $count${NC}"
        fi
    else
        echo -e "    ${YELLOW}Ni trivy ni grype disponibles${NC}"
    fi
}

# Escanear imagen específica o descubrir todas
if [[ -n "$TARGET_IMAGE" ]]; then
    scan_image "$TARGET_IMAGE" "manual"
else
    # Docker images
    if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
        echo -e "${BOLD}Docker images:${NC}"
        docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -v '<none>' | while read -r img; do
            scan_image "$img" "docker"
        done
        echo ""
    fi

    # Podman images
    if command -v podman &>/dev/null; then
        echo -e "${BOLD}Podman images:${NC}"
        podman images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -v '<none>' | while read -r img; do
            scan_image "$img" "podman"
        done
        echo ""
    fi
fi

echo ""
echo -e "${BOLD}═══════════════════════════════════════${NC}"
echo -e "  Imágenes escaneadas: $TOTAL_IMAGES"
echo -e "  Vulnerabilidades totales: $TOTAL_VULNS"
echo -e "  Imágenes con $THRESHOLD+: $FAILED_IMAGES"
echo -e "${DIM}  Reportes: $SCAN_DIR/${NC}"

if [[ "$FAIL_ON_THRESHOLD" == "true" ]] && [[ "$FAILED_IMAGES" -gt 0 ]]; then
    echo -e "${RED}POLÍTICA: $FAILED_IMAGES imágenes exceden threshold $THRESHOLD${NC}"
    exit 1
fi
EOFCONT

    chmod 755 /usr/local/bin/securizar-vuln-containers.sh
    log_change "Creado" "/usr/local/bin/securizar-vuln-containers.sh"
    log_info "Script de escaneo de contenedores instalado"

else
    log_skip "Escaneo de contenedores"
fi

# ============================================================
# S4: OPENSCAP SCAP GUIDE
# ============================================================
log_section "S4: OPENSCAP SCAP GUIDE"

echo "Evaluación de cumplimiento con OpenSCAP y SCAP Security Guide."
echo "Auto-detecta el perfil SSG correcto para la distribución."
echo ""

if check_executable /usr/local/bin/securizar-vuln-openscap.sh; then
    log_already "OpenSCAP evaluación"
elif ask "¿Crear script de evaluación OpenSCAP?"; then

    cat > /usr/local/bin/securizar-vuln-openscap.sh << 'EOFSCAP'
#!/bin/bash
# ============================================================
# EVALUACIÓN OPENSCAP CON SCAP SECURITY GUIDE
# Auto-detecta perfil SSG por distribución
# Uso: securizar-vuln-openscap.sh [--profile PROFILE] [--remediate]
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

SCAN_DIR="/var/lib/securizar/vuln-management/openscap"
mkdir -p "$SCAN_DIR"

CUSTOM_PROFILE=""
REMEDIATE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile) CUSTOM_PROFILE="$2"; shift 2 ;;
        --remediate) REMEDIATE=true; shift ;;
        *) shift ;;
    esac
done

if ! command -v oscap &>/dev/null; then
    echo -e "${RED}OpenSCAP no instalado. Ejecuta el módulo S1 primero.${NC}"
    exit 1
fi

echo -e "${BOLD}╔════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║   EVALUACIÓN OPENSCAP                      ║${NC}"
echo -e "${BOLD}╚════════════════════════════════════════════╝${NC}"
echo ""

# Auto-detectar SSG datastream
SSG_DS=""
SSG_PROFILE=""

# Buscar datastream por distro
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    case "${ID:-}" in
        opensuse*|sles|sled)
            SSG_DS=$(find /usr/share/xml/scap/ssg/content/ -name "ssg-sle*-ds.xml" 2>/dev/null | sort -rV | head -1)
            SSG_PROFILE="xccdf_org.ssgproject.content_profile_cis"
            ;;
        ubuntu)
            SSG_DS=$(find /usr/share/xml/scap/ssg/content/ -name "ssg-ubuntu*-ds.xml" 2>/dev/null | sort -rV | head -1)
            SSG_PROFILE="xccdf_org.ssgproject.content_profile_cis_level1_server"
            ;;
        debian)
            SSG_DS=$(find /usr/share/xml/scap/ssg/content/ -name "ssg-debian*-ds.xml" 2>/dev/null | sort -rV | head -1)
            SSG_PROFILE="xccdf_org.ssgproject.content_profile_standard"
            ;;
        rhel|centos|rocky|alma)
            SSG_DS=$(find /usr/share/xml/scap/ssg/content/ -name "ssg-rhel*-ds.xml" 2>/dev/null | sort -rV | head -1)
            SSG_PROFILE="xccdf_org.ssgproject.content_profile_cis"
            ;;
        fedora)
            SSG_DS=$(find /usr/share/xml/scap/ssg/content/ -name "ssg-fedora-ds.xml" 2>/dev/null | head -1)
            SSG_PROFILE="xccdf_org.ssgproject.content_profile_standard"
            ;;
    esac
fi

if [[ -n "$CUSTOM_PROFILE" ]]; then
    SSG_PROFILE="$CUSTOM_PROFILE"
fi

if [[ -z "$SSG_DS" ]]; then
    echo -e "${YELLOW}No se encontró SCAP Security Guide para esta distribución.${NC}"
    echo "Instálalo con: zypper/apt/dnf install scap-security-guide"

    # Fallback: OVAL de seguridad
    echo ""
    echo -e "${CYAN}Buscando contenido OVAL alternativo...${NC}"
    OVAL_FILE=$(find /usr/share/xml/scap/ /usr/share/openscap/ -name "*.oval.xml" 2>/dev/null | head -1)
    if [[ -n "$OVAL_FILE" ]]; then
        TIMESTAMP=$(date +%Y%m%d-%H%M%S)
        echo "Evaluando: $OVAL_FILE"
        oscap oval eval --results "$SCAN_DIR/oval-results-$TIMESTAMP.xml" \
            --report "$SCAN_DIR/oval-report-$TIMESTAMP.html" \
            "$OVAL_FILE" 2>/dev/null || true
        echo -e "${DIM}Reporte: $SCAN_DIR/oval-report-$TIMESTAMP.html${NC}"
    else
        echo -e "${RED}No se encontró contenido SCAP/OVAL.${NC}"
    fi
    exit 0
fi

echo -e "${DIM}Datastream: $SSG_DS${NC}"
echo -e "${DIM}Perfil: $SSG_PROFILE${NC}"
echo ""

# Listar perfiles disponibles
echo -e "${CYAN}Perfiles disponibles:${NC}"
oscap info "$SSG_DS" 2>/dev/null | grep "Profile:" | head -10 | while read -r line; do
    echo "  $line"
done
echo ""

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RESULTS="$SCAN_DIR/scap-results-$TIMESTAMP.xml"
REPORT="$SCAN_DIR/scap-report-$TIMESTAMP.html"
ARF="$SCAN_DIR/scap-arf-$TIMESTAMP.xml"

echo -e "${CYAN}Evaluando perfil $SSG_PROFILE...${NC}"
echo ""

OSCAP_CMD="oscap xccdf eval --profile $SSG_PROFILE --results $RESULTS --report $REPORT --results-arf $ARF"

if [[ "$REMEDIATE" == "true" ]]; then
    echo -e "${YELLOW}Modo remediación activado${NC}"
    OSCAP_CMD="$OSCAP_CMD --remediate"
fi

$OSCAP_CMD "$SSG_DS" 2>/dev/null || true

# Resumen de resultados
if [[ -f "$RESULTS" ]] && command -v xmllint &>/dev/null; then
    PASS=$(grep -c 'result="pass"' "$RESULTS" 2>/dev/null || echo 0)
    FAIL=$(grep -c 'result="fail"' "$RESULTS" 2>/dev/null || echo 0)
    NOTAPPL=$(grep -c 'result="notapplicable"' "$RESULTS" 2>/dev/null || echo 0)
    TOTAL=$((PASS + FAIL))

    echo ""
    echo -e "${BOLD}Resultado de la evaluación:${NC}"
    echo -e "  ${GREEN}Pasados:${NC}    $PASS"
    echo -e "  ${RED}Fallidos:${NC}   $FAIL"
    echo -e "  ${DIM}N/A:${NC}        $NOTAPPL"
    if [[ $TOTAL -gt 0 ]]; then
        SCORE=$((PASS * 100 / TOTAL))
        echo -e "  ${BOLD}Score:${NC}      ${SCORE}%"
    fi
fi

echo ""
echo -e "${DIM}Reporte HTML: $REPORT${NC}"
echo -e "${DIM}Resultados XML: $RESULTS${NC}"
echo -e "${DIM}ARF: $ARF${NC}"

logger -t securizar-vuln "OpenSCAP evaluation completed: profile=$SSG_PROFILE"
EOFSCAP

    chmod 755 /usr/local/bin/securizar-vuln-openscap.sh
    log_change "Creado" "/usr/local/bin/securizar-vuln-openscap.sh"
    log_info "Script OpenSCAP instalado: securizar-vuln-openscap.sh"

else
    log_skip "OpenSCAP evaluación"
fi

# ============================================================
# S5: PRIORIZACIÓN CVSS+EPSS
# ============================================================
log_section "S5: PRIORIZACIÓN CVSS+EPSS"

echo "Priorización de vulnerabilidades combinando CVSS, EPSS, CISA KEV"
echo "y factor de exposición (reachability)."
echo "Fórmula: risk = CVSS*0.30 + EPSS*0.25 + KEV*0.25 + REACH*0.20"
echo ""

if check_executable /usr/local/bin/securizar-vuln-prioritize.sh; then
    log_already "Priorización de vulnerabilidades"
elif ask "¿Crear script de priorización CVSS+EPSS?"; then

    cat > /usr/local/bin/securizar-vuln-prioritize.sh << 'EOFPRIO'
#!/bin/bash
# ============================================================
# PRIORIZACIÓN DE VULNERABILIDADES
# Combina CVSS, EPSS (first.org) y CISA KEV
# Uso: securizar-vuln-prioritize.sh [CVE-LIST-FILE | CVE-ID]
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

CACHE_DIR="/var/lib/securizar/vuln-management/cache"
mkdir -p "$CACHE_DIR"

INPUT="${1:-}"

echo -e "${BOLD}╔════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║   PRIORIZACIÓN DE VULNERABILIDADES         ║${NC}"
echo -e "${BOLD}╚════════════════════════════════════════════╝${NC}"
echo ""

# Descargar CISA KEV si no existe o tiene más de 24h
KEV_FILE="$CACHE_DIR/known_exploited_vulnerabilities.json"
if [[ ! -f "$KEV_FILE" ]] || [[ $(( $(date +%s) - $(stat -c %Y "$KEV_FILE" 2>/dev/null || echo 0) )) -gt 86400 ]]; then
    echo -e "${DIM}Actualizando catálogo CISA KEV...${NC}"
    curl -sS --max-time 30 "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" \
        -o "$KEV_FILE" 2>/dev/null || echo -e "${YELLOW}No se pudo descargar CISA KEV${NC}"
fi

lookup_epss() {
    local CVE="$1"
    curl -sS --max-time 10 "https://api.first.org/data/v1/epss?cve=$CVE" 2>/dev/null | \
        grep -oP '"epss":\s*"?\K[0-9.]+' | head -1 || echo "0"
}

is_in_kev() {
    local CVE="$1"
    if [[ -f "$KEV_FILE" ]] && grep -q "$CVE" "$KEV_FILE" 2>/dev/null; then
        echo "1"
    else
        echo "0"
    fi
}

reachability_score() {
    # Determina si el servicio afectado está expuesto a la red
    # 1.0 = internet-facing, 0.5 = LAN only, 0.1 = localhost only
    local CVE="$1"
    # Verificar si hay servicios escuchando en interfaces externas
    local EXT_LISTEN
    EXT_LISTEN=$(ss -tlnp 2>/dev/null | grep -cv "127.0.0.1\|::1\|Local" || true)
    if [[ "$EXT_LISTEN" -gt 3 ]]; then
        echo "1.0"  # Muchos servicios expuestos
    elif [[ "$EXT_LISTEN" -gt 0 ]]; then
        echo "0.5"  # Algunos servicios expuestos
    else
        echo "0.1"  # Solo localhost
    fi
}

prioritize_cve() {
    local CVE="$1"
    local CVSS="${2:-0}"

    EPSS=$(lookup_epss "$CVE")
    KEV=$(is_in_kev "$CVE")
    REACH=$(reachability_score "$CVE")

    # Normalizar CVSS a 0-1
    CVSS_NORM=$(awk "BEGIN {printf \"%.2f\", $CVSS / 10}")

    # Risk score: CVSS*0.30 + EPSS*0.25 + KEV*0.25 + REACH*0.20
    RISK=$(awk "BEGIN {printf \"%.2f\", $CVSS_NORM * 0.30 + $EPSS * 0.25 + $KEV * 0.25 + $REACH * 0.20}")

    # Determinar prioridad
    PRIORITY="LOW"
    COLOR="$DIM"
    if (( $(echo "$RISK > 0.7" | bc -l 2>/dev/null || echo 0) )); then
        PRIORITY="CRITICAL"; COLOR="$RED"
    elif (( $(echo "$RISK > 0.5" | bc -l 2>/dev/null || echo 0) )); then
        PRIORITY="HIGH"; COLOR="$YELLOW"
    elif (( $(echo "$RISK > 0.3" | bc -l 2>/dev/null || echo 0) )); then
        PRIORITY="MEDIUM"; COLOR="$CYAN"
    fi

    KEV_LABEL="No"
    [[ "$KEV" == "1" ]] && KEV_LABEL="${RED}Sí${NC}"

    printf "  ${COLOR}%-16s${NC} CVSS:%-4s EPSS:%-6s KEV:%-3s Risk:%-5s ${COLOR}%s${NC}\n" \
        "$CVE" "$CVSS" "$EPSS" "$KEV_LABEL" "$RISK" "$PRIORITY"
}

if [[ -f "$INPUT" ]]; then
    echo -e "${CYAN}Procesando CVEs desde: $INPUT${NC}"
    echo ""
    printf "  ${BOLD}%-16s %-9s %-11s %-8s %-10s %s${NC}\n" "CVE" "CVSS" "EPSS" "KEV" "Risk" "Prioridad"
    echo "  ─────────────────────────────────────────────────────────────"
    while IFS=, read -r cve cvss rest; do
        [[ "$cve" == "CVE"* ]] || continue
        prioritize_cve "$cve" "${cvss:-0}"
    done < "$INPUT"
elif [[ "$INPUT" == CVE-* ]]; then
    echo -e "${CYAN}Analizando: $INPUT${NC}"
    echo ""
    prioritize_cve "$INPUT" "7.5"
else
    echo "Uso: $0 [archivo-cves.csv | CVE-YYYY-NNNNN]"
    echo ""
    echo "Formato CSV: CVE-ID,CVSS_Score"
    echo "Ejemplo: CVE-2024-1234,9.8"
fi

echo ""
echo -e "${DIM}Fuentes: CVSS (NVD), EPSS (first.org), KEV (CISA), Reachability (local)${NC}"
EOFPRIO

    chmod 755 /usr/local/bin/securizar-vuln-prioritize.sh
    log_change "Creado" "/usr/local/bin/securizar-vuln-prioritize.sh"
    log_info "Priorización CVSS+EPSS instalada"

else
    log_skip "Priorización de vulnerabilidades"
fi

# ============================================================
# S6: ANÁLISIS DE DEPENDENCIAS
# ============================================================
log_section "S6: ANÁLISIS DE DEPENDENCIAS"

echo "Análisis de librerías compartidas y dependencias del sistema."
echo "Busca CVEs en OpenSSL, glibc, curl, zlib y binarios SUID."
echo ""

if check_executable /usr/local/bin/securizar-vuln-deps.sh; then
    log_already "Análisis de dependencias"
elif ask "¿Crear script de análisis de dependencias?"; then

    cat > /usr/local/bin/securizar-vuln-deps.sh << 'EOFDEPS'
#!/bin/bash
# ============================================================
# ANÁLISIS DE DEPENDENCIAS Y LIBRERÍAS
# Busca librerías vulnerables en el sistema
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

REPORT_DIR="/var/lib/securizar/vuln-management"
REPORT="$REPORT_DIR/deps-analysis-$(date +%Y%m%d).txt"
mkdir -p "$REPORT_DIR"

echo -e "${BOLD}╔════════════════════════════════════════════╗${NC}" | tee "$REPORT"
echo -e "${BOLD}║   ANÁLISIS DE DEPENDENCIAS                 ║${NC}" | tee -a "$REPORT"
echo -e "${BOLD}╚════════════════════════════════════════════╝${NC}" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# 1. Librerías críticas y sus versiones
echo -e "${CYAN}── Librerías críticas ──${NC}" | tee -a "$REPORT"
for lib in openssl libssl libcrypto glibc libcurl zlib libz; do
    VER=""
    case "$lib" in
        openssl) VER=$(openssl version 2>/dev/null | awk '{print $2}') ;;
        glibc) VER=$(ldd --version 2>/dev/null | head -1 | grep -oP '[0-9]+\.[0-9]+$') ;;
        libcurl) VER=$(curl --version 2>/dev/null | head -1 | awk '{print $2}') ;;
        zlib|libz) VER=$(python3 -c "import zlib; print(zlib.ZLIB_RUNTIME_VERSION)" 2>/dev/null || echo "?") ;;
        *) VER=$(ldconfig -p 2>/dev/null | grep "$lib" | head -1 | grep -oP '\d+\.\d+\.\d+' || echo "?") ;;
    esac
    if [[ -n "$VER" ]] && [[ "$VER" != "?" ]]; then
        printf "  %-15s %s\n" "$lib" "$VER" | tee -a "$REPORT"
    fi
done

# 2. Binarios SUID y sus dependencias
echo "" | tee -a "$REPORT"
echo -e "${CYAN}── Binarios SUID con dependencias ──${NC}" | tee -a "$REPORT"
find /usr/bin /usr/sbin /usr/local/bin -maxdepth 1 -perm /4000 -type f 2>/dev/null | head -20 | while read -r bin; do
    DEPS=$(ldd "$bin" 2>/dev/null | grep "=>" | awk '{print $1}' | tr '\n' ' ')
    if [[ -n "$DEPS" ]]; then
        printf "  %-30s %s\n" "$(basename "$bin")" "${DEPS:0:60}" | tee -a "$REPORT"
    fi
done

# 3. Librerías huérfanas
echo "" | tee -a "$REPORT"
echo -e "${CYAN}── Librerías no empaquetadas ──${NC}" | tee -a "$REPORT"
ORPHANS=0
find /usr/local/lib -name "*.so*" -type f 2>/dev/null | head -20 | while read -r lib; do
    echo "  $(basename "$lib")" | tee -a "$REPORT"
    ORPHANS=$((ORPHANS + 1))
done
echo "  Total: $ORPHANS" | tee -a "$REPORT"

echo "" | tee -a "$REPORT"
echo -e "${DIM}Reporte: $REPORT${NC}"
EOFDEPS

    chmod 755 /usr/local/bin/securizar-vuln-deps.sh
    log_change "Creado" "/usr/local/bin/securizar-vuln-deps.sh"
    log_info "Análisis de dependencias instalado"

else
    log_skip "Análisis de dependencias"
fi

# ============================================================
# S7: REPORTING HTML/JSON
# ============================================================
log_section "S7: REPORTING HTML/JSON"

echo "Generación de reportes ejecutivos de vulnerabilidades."
echo "Formatos: HTML con CSS inline, JSON, texto."
echo ""

if check_executable /usr/local/bin/securizar-vuln-report.sh; then
    log_already "Reporting de vulnerabilidades"
elif ask "¿Crear generador de reportes de vulnerabilidades?"; then

    cat > /usr/local/bin/securizar-vuln-report.sh << 'EOFREP'
#!/bin/bash
# ============================================================
# REPORTING DE VULNERABILIDADES
# Genera reportes ejecutivos HTML/JSON/texto
# Uso: securizar-vuln-report.sh [--format html|json|text]
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

FORMAT="${1:---format}"
[[ "$FORMAT" == "--format" ]] && FORMAT="${2:-text}"
SCAN_DIR="/var/lib/securizar/vuln-management"
REPORT_DIR="$SCAN_DIR/reports"
mkdir -p "$REPORT_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

echo -e "${BOLD}=== REPORTE DE VULNERABILIDADES ===${NC}"

# Recopilar datos del último escaneo
LATEST_SCAN=$(ls -t "$SCAN_DIR"/system-scan-*.json 2>/dev/null | head -1)
LATEST_META=$(ls -t "$SCAN_DIR"/system-scan-*.meta 2>/dev/null | head -1)

TOTAL_VULNS=0 CRITICAL=0 HIGH=0 MEDIUM=0 LOW=0

if [[ -f "$LATEST_SCAN" ]] && command -v jq &>/dev/null; then
    CRITICAL=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$LATEST_SCAN" 2>/dev/null || echo 0)
    HIGH=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length' "$LATEST_SCAN" 2>/dev/null || echo 0)
    MEDIUM=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "MEDIUM")] | length' "$LATEST_SCAN" 2>/dev/null || echo 0)
    LOW=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "LOW")] | length' "$LATEST_SCAN" 2>/dev/null || echo 0)
    TOTAL_VULNS=$((CRITICAL + HIGH + MEDIUM + LOW))
fi

case "$FORMAT" in
    html)
        HTML="$REPORT_DIR/vuln-report-$TIMESTAMP.html"
        cat > "$HTML" << EOFHTML
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Reporte de Vulnerabilidades - $(hostname)</title>
<style>
body{font-family:sans-serif;margin:40px;background:#f5f5f5}
.container{max-width:900px;margin:0 auto;background:#fff;padding:30px;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,.1)}
h1{color:#333;border-bottom:2px solid #2196F3;padding-bottom:10px}
.summary{display:flex;gap:20px;margin:20px 0}
.card{flex:1;padding:15px;border-radius:6px;text-align:center;color:#fff;font-size:24px;font-weight:bold}
.critical{background:#d32f2f} .high{background:#f57c00} .medium{background:#fbc02d;color:#333} .low{background:#388e3c}
table{width:100%;border-collapse:collapse;margin-top:20px}
th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #ddd}
th{background:#2196F3;color:#fff}
.footer{margin-top:30px;color:#999;font-size:12px}
</style></head><body>
<div class="container">
<h1>Reporte de Vulnerabilidades</h1>
<p>Host: <strong>$(hostname)</strong> | Fecha: $(date -Iseconds) | Kernel: $(uname -r)</p>
<div class="summary">
<div class="card critical">$CRITICAL<br><small>CRITICAL</small></div>
<div class="card high">$HIGH<br><small>HIGH</small></div>
<div class="card medium">$MEDIUM<br><small>MEDIUM</small></div>
<div class="card low">$LOW<br><small>LOW</small></div>
</div>
<p><strong>Total: $TOTAL_VULNS vulnerabilidades</strong></p>
EOFHTML

        # Top 10 vulnerabilidades
        if [[ -f "$LATEST_SCAN" ]] && command -v jq &>/dev/null; then
            echo "<h2>Top 10 Vulnerabilidades Críticas</h2>" >> "$HTML"
            echo "<table><tr><th>CVE</th><th>Severidad</th><th>Paquete</th><th>Versión</th><th>Fix</th></tr>" >> "$HTML"
            jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL" or .Severity == "HIGH") | "<tr><td>\(.VulnerabilityID)</td><td>\(.Severity)</td><td>\(.PkgName)</td><td>\(.InstalledVersion)</td><td>\(.FixedVersion // "N/A")</td></tr>"' "$LATEST_SCAN" 2>/dev/null | head -10 >> "$HTML"
            echo "</table>" >> "$HTML"
        fi

        echo "<div class='footer'>Generado por securizar-vuln-report.sh</div></div></body></html>" >> "$HTML"
        echo -e "${GREEN}Reporte HTML: $HTML${NC}"
        ;;

    json)
        JSON="$REPORT_DIR/vuln-report-$TIMESTAMP.json"
        cat > "$JSON" << EOFJSON
{
  "report": {
    "timestamp": "$(date -Iseconds)",
    "hostname": "$(hostname)",
    "kernel": "$(uname -r)",
    "summary": {
      "total": $TOTAL_VULNS,
      "critical": $CRITICAL,
      "high": $HIGH,
      "medium": $MEDIUM,
      "low": $LOW
    },
    "scanner": "$(cat "$LATEST_META" 2>/dev/null | grep scanner | cut -d= -f2 || echo "unknown")",
    "source_scan": "$(basename "$LATEST_SCAN" 2>/dev/null || echo "none")"
  }
}
EOFJSON
        echo -e "${GREEN}Reporte JSON: $JSON${NC}"
        ;;

    *)
        echo ""
        echo "Host: $(hostname)"
        echo "Fecha: $(date -Iseconds)"
        echo ""
        echo "Resumen:"
        echo "  CRITICAL: $CRITICAL"
        echo "  HIGH:     $HIGH"
        echo "  MEDIUM:   $MEDIUM"
        echo "  LOW:      $LOW"
        echo "  Total:    $TOTAL_VULNS"
        ;;
esac
EOFREP

    chmod 755 /usr/local/bin/securizar-vuln-report.sh
    log_change "Creado" "/usr/local/bin/securizar-vuln-report.sh"
    log_info "Reporting de vulnerabilidades instalado"

else
    log_skip "Reporting de vulnerabilidades"
fi

# ============================================================
# S8: VERIFICACIÓN DE PARCHES
# ============================================================
log_section "S8: VERIFICACIÓN DE PARCHES"

echo "Re-scan post-patch y verificación de correcciones."
echo "Diff antes/después, rollback por distro si necesario."
echo ""

if check_executable /usr/local/bin/securizar-vuln-patch-verify.sh; then
    log_already "Verificación de parches"
elif ask "¿Crear script de verificación de parches?"; then

    cat > /usr/local/bin/securizar-vuln-patch-verify.sh << 'EOFPATCH'
#!/bin/bash
# ============================================================
# VERIFICACIÓN DE PARCHES
# Re-scan post-patch, diff antes/después
# Uso: securizar-vuln-patch-verify.sh [--before|--after|--diff|--rollback PKG]
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

PATCH_DIR="/var/lib/securizar/vuln-management/patches"
mkdir -p "$PATCH_DIR"

case "${1:---help}" in
    --before)
        echo -e "${BOLD}Capturando estado pre-patch...${NC}"
        SNAP="$PATCH_DIR/pre-patch-$(date +%Y%m%d-%H%M%S)"
        mkdir -p "$SNAP"

        # Lista de paquetes instalados
        case "$(command -v zypper &>/dev/null && echo suse || command -v apt &>/dev/null && echo debian || command -v dnf &>/dev/null && echo rhel || echo unknown)" in
            suse)   rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}\n' | sort > "$SNAP/packages.txt" ;;
            debian) dpkg -l | awk '/^ii/ {print $2"-"$3}' | sort > "$SNAP/packages.txt" ;;
            rhel)   rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}\n' | sort > "$SNAP/packages.txt" ;;
        esac

        # Escaneo de vulnerabilidades
        if command -v trivy &>/dev/null; then
            trivy rootfs / --severity HIGH,CRITICAL --format json -o "$SNAP/vulns.json" 2>/dev/null || true
        fi

        uname -r > "$SNAP/kernel.txt"
        echo -e "${GREEN}Estado pre-patch guardado: $SNAP${NC}"
        echo "$SNAP" > "$PATCH_DIR/latest-pre"
        ;;

    --after)
        echo -e "${BOLD}Capturando estado post-patch...${NC}"
        SNAP="$PATCH_DIR/post-patch-$(date +%Y%m%d-%H%M%S)"
        mkdir -p "$SNAP"

        case "$(command -v zypper &>/dev/null && echo suse || command -v apt &>/dev/null && echo debian || command -v dnf &>/dev/null && echo rhel || echo unknown)" in
            suse)   rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}\n' | sort > "$SNAP/packages.txt" ;;
            debian) dpkg -l | awk '/^ii/ {print $2"-"$3}' | sort > "$SNAP/packages.txt" ;;
            rhel)   rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}\n' | sort > "$SNAP/packages.txt" ;;
        esac

        if command -v trivy &>/dev/null; then
            trivy rootfs / --severity HIGH,CRITICAL --format json -o "$SNAP/vulns.json" 2>/dev/null || true
        fi

        uname -r > "$SNAP/kernel.txt"
        echo -e "${GREEN}Estado post-patch guardado: $SNAP${NC}"
        echo "$SNAP" > "$PATCH_DIR/latest-post"
        ;;

    --diff)
        PRE=$(cat "$PATCH_DIR/latest-pre" 2>/dev/null)
        POST=$(cat "$PATCH_DIR/latest-post" 2>/dev/null)
        if [[ -z "$PRE" ]] || [[ -z "$POST" ]]; then
            echo "Ejecuta --before y --after primero"
            exit 1
        fi

        echo -e "${BOLD}=== DIFF PARCHES ===${NC}"
        echo ""
        echo -e "${CYAN}Paquetes actualizados:${NC}"
        diff "$PRE/packages.txt" "$POST/packages.txt" 2>/dev/null | grep "^[<>]" | head -30

        if [[ -f "$PRE/vulns.json" ]] && [[ -f "$POST/vulns.json" ]] && command -v jq &>/dev/null; then
            BEFORE_COUNT=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL" or .Severity == "HIGH")] | length' "$PRE/vulns.json" 2>/dev/null || echo 0)
            AFTER_COUNT=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL" or .Severity == "HIGH")] | length' "$POST/vulns.json" 2>/dev/null || echo 0)
            FIXED=$((BEFORE_COUNT - AFTER_COUNT))
            echo ""
            echo -e "${CYAN}Vulnerabilidades HIGH+CRITICAL:${NC}"
            echo "  Antes: $BEFORE_COUNT"
            echo "  Después: $AFTER_COUNT"
            echo -e "  ${GREEN}Corregidas: $FIXED${NC}"
        fi
        ;;

    --rollback)
        PKG="${2:?Uso: $0 --rollback PAQUETE}"
        echo -e "${BOLD}Rollback de: $PKG${NC}"
        if command -v zypper &>/dev/null; then
            zypper install --oldpackage "$PKG" 2>/dev/null
        elif command -v apt &>/dev/null; then
            apt-get install --allow-downgrades "$PKG" 2>/dev/null
        elif command -v dnf &>/dev/null; then
            dnf downgrade "$PKG" 2>/dev/null
        fi
        ;;

    *)
        echo "Uso: $0 {--before|--after|--diff|--rollback PKG}"
        echo ""
        echo "Flujo: --before → aplicar parches → --after → --diff"
        ;;
esac
EOFPATCH

    chmod 755 /usr/local/bin/securizar-vuln-patch-verify.sh
    log_change "Creado" "/usr/local/bin/securizar-vuln-patch-verify.sh"
    log_info "Verificación de parches instalada"

else
    log_skip "Verificación de parches"
fi

# ============================================================
# S9: ESCANEO PROGRAMADO
# ============================================================
log_section "S9: ESCANEO PROGRAMADO"

echo "Escaneo semanal automático de vulnerabilidades."
echo "Drift detection: alerta en nuevos CVEs CRITICAL+KEV."
echo ""

if check_executable /usr/local/bin/securizar-vuln-scheduled.sh; then
    log_already "Escaneo programado"
elif ask "¿Configurar escaneo programado de vulnerabilidades?"; then

    cat > /usr/local/bin/securizar-vuln-scheduled.sh << 'EOFSCH'
#!/bin/bash
# ============================================================
# ESCANEO PROGRAMADO DE VULNERABILIDADES
# Timer semanal con drift detection
# ============================================================
set -euo pipefail

SCAN_DIR="/var/lib/securizar/vuln-management"
LOG="/var/log/securizar/vuln-management/scheduled-$(date +%Y%m%d).log"
mkdir -p "$(dirname "$LOG")"

echo "=== ESCANEO PROGRAMADO - $(date -Iseconds) ===" | tee "$LOG"

# Guardar conteo previo
PREV_CRITICAL=0
PREV_SCAN=$(ls -t "$SCAN_DIR"/system-scan-*.json 2>/dev/null | head -1)
if [[ -f "$PREV_SCAN" ]] && command -v jq &>/dev/null; then
    PREV_CRITICAL=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$PREV_SCAN" 2>/dev/null || echo 0)
fi

# Ejecutar escaneo
if [[ -x /usr/local/bin/securizar-vuln-system.sh ]]; then
    /usr/local/bin/securizar-vuln-system.sh --severity HIGH,CRITICAL >> "$LOG" 2>&1
fi

# Drift detection
NEW_SCAN=$(ls -t "$SCAN_DIR"/system-scan-*.json 2>/dev/null | head -1)
if [[ -f "$NEW_SCAN" ]] && command -v jq &>/dev/null; then
    NEW_CRITICAL=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$NEW_SCAN" 2>/dev/null || echo 0)

    if [[ "$NEW_CRITICAL" -gt "$PREV_CRITICAL" ]]; then
        DELTA=$((NEW_CRITICAL - PREV_CRITICAL))
        echo "ALERTA: $DELTA nuevas vulnerabilidades CRITICAL detectadas" | tee -a "$LOG"
        logger -t securizar-vuln "CRITICAL: $DELTA new critical vulnerabilities detected"
    else
        echo "Sin nuevas vulnerabilidades CRITICAL" | tee -a "$LOG"
    fi
fi

# Generar reporte si disponible
if [[ -x /usr/local/bin/securizar-vuln-report.sh ]]; then
    /usr/local/bin/securizar-vuln-report.sh --format html >> "$LOG" 2>&1
fi

echo "Escaneo programado completado" | tee -a "$LOG"
EOFSCH

    chmod 755 /usr/local/bin/securizar-vuln-scheduled.sh
    log_change "Creado" "/usr/local/bin/securizar-vuln-scheduled.sh"

    # Timer semanal
    cat > /etc/systemd/system/securizar-vuln-scan.timer << 'EOFTIMER'
[Unit]
Description=Securizar Vulnerability Scan semanal

[Timer]
OnCalendar=Sun 03:00
Persistent=true

[Install]
WantedBy=timers.target
EOFTIMER

    cat > /etc/systemd/system/securizar-vuln-scan.service << 'EOFSVC'
[Unit]
Description=Securizar Vulnerability Scan

[Service]
Type=oneshot
ExecStart=/usr/local/bin/securizar-vuln-scheduled.sh
EOFSVC

    systemctl daemon-reload
    systemctl enable securizar-vuln-scan.timer 2>/dev/null || true
    log_change "Creado" "securizar-vuln-scan.timer (semanal)"
    log_info "Escaneo programado configurado"

else
    log_skip "Escaneo programado"
fi

# ============================================================
# S10: AUDITORÍA DE MADUREZ
# ============================================================
log_section "S10: AUDITORÍA DE MADUREZ"

echo "Scoring de madurez del programa de gestión de vulnerabilidades."
echo "5 niveles: L1 (Ad-hoc) → L5 (Optimizado)."
echo ""

if check_executable /usr/local/bin/auditoria-vuln-management.sh; then
    log_already "Auditoría de madurez"
elif ask "¿Crear auditoría de madurez de gestión de vulnerabilidades?"; then

    cat > /usr/local/bin/auditoria-vuln-management.sh << 'EOFAUDIT'
#!/bin/bash
# ============================================================
# AUDITORÍA DE MADUREZ - GESTIÓN DE VULNERABILIDADES
# 5 niveles (L1-L5), scoring 0-100
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

SCORE=0; MAX=0
REPORT="/var/log/securizar/vuln-management/auditoria-madurez-$(date +%Y%m%d).txt"
mkdir -p "$(dirname "$REPORT")"

ci() {
    local d="$1" c="$2" p="${3:-1}"
    MAX=$((MAX + p))
    if eval "$c" &>/dev/null; then
        echo -e "  ${GREEN}[+$p]${NC}  $d" | tee -a "$REPORT"
        SCORE=$((SCORE + p))
    else
        echo -e "  ${RED}[  0]${NC}  $d" | tee -a "$REPORT"
    fi
}

echo -e "${BOLD}╔════════════════════════════════════════════╗${NC}" | tee "$REPORT"
echo -e "${BOLD}║   AUDITORÍA GESTIÓN DE VULNERABILIDADES    ║${NC}" | tee -a "$REPORT"
echo -e "${BOLD}╚════════════════════════════════════════════╝${NC}" | tee -a "$REPORT"
echo "Fecha: $(date -Iseconds)" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

echo -e "${CYAN}── L1: Herramientas ──${NC}" | tee -a "$REPORT"
ci "Trivy instalado" "command -v trivy" 5
ci "grype instalado" "command -v grype" 3
ci "OpenSCAP instalado" "command -v oscap" 3
ci "Config herramientas" "test -f /etc/securizar/vuln-management/tools.conf" 2

echo "" | tee -a "$REPORT"
echo -e "${CYAN}── L2: Escaneo ──${NC}" | tee -a "$REPORT"
ci "Escaneo de sistema" "test -x /usr/local/bin/securizar-vuln-system.sh" 5
ci "Escaneo contenedores" "test -x /usr/local/bin/securizar-vuln-containers.sh" 3
ci "OpenSCAP evaluación" "test -x /usr/local/bin/securizar-vuln-openscap.sh" 3

echo "" | tee -a "$REPORT"
echo -e "${CYAN}── L3: Priorización ──${NC}" | tee -a "$REPORT"
ci "CVSS+EPSS+KEV" "test -x /usr/local/bin/securizar-vuln-prioritize.sh" 5
ci "Análisis dependencias" "test -x /usr/local/bin/securizar-vuln-deps.sh" 3

echo "" | tee -a "$REPORT"
echo -e "${CYAN}── L4: Gestión ──${NC}" | tee -a "$REPORT"
ci "Reporting HTML" "test -x /usr/local/bin/securizar-vuln-report.sh" 5
ci "Verificación parches" "test -x /usr/local/bin/securizar-vuln-patch-verify.sh" 5
ci "Escaneo programado" "systemctl is-enabled securizar-vuln-scan.timer" 5

echo "" | tee -a "$REPORT"
echo -e "${CYAN}── L5: Optimización ──${NC}" | tee -a "$REPORT"
ci "Histórico de scans" "test -d /var/lib/securizar/vuln-management/reports" 3

echo "" | tee -a "$REPORT"
PCT=0; [[ $MAX -gt 0 ]] && PCT=$((SCORE * 100 / MAX))
echo -e "${BOLD}Score: $SCORE/$MAX ($PCT%)${NC}" | tee -a "$REPORT"

LEVEL="L1 (Ad-hoc)"
[[ $PCT -ge 80 ]] && LEVEL="L5 (Optimizado)"
[[ $PCT -ge 60 ]] && [[ $PCT -lt 80 ]] && LEVEL="L4 (Gestionado)"
[[ $PCT -ge 40 ]] && [[ $PCT -lt 60 ]] && LEVEL="L3 (Definido)"
[[ $PCT -ge 20 ]] && [[ $PCT -lt 40 ]] && LEVEL="L2 (Repetible)"
echo -e "${BOLD}Nivel: $LEVEL${NC}" | tee -a "$REPORT"
echo -e "${DIM}Reporte: $REPORT${NC}"
logger -t securizar-vuln "Vuln management audit: $SCORE/$MAX ($PCT%) $LEVEL"
EOFAUDIT

    chmod 755 /usr/local/bin/auditoria-vuln-management.sh
    log_change "Creado" "/usr/local/bin/auditoria-vuln-management.sh"

    # Cron semanal
    cat > /etc/cron.weekly/auditoria-vuln-management << 'EOFCRON'
#!/bin/bash
/usr/local/bin/auditoria-vuln-management.sh > /dev/null 2>&1
EOFCRON
    chmod 700 /etc/cron.weekly/auditoria-vuln-management
    log_change "Creado" "/etc/cron.weekly/auditoria-vuln-management"
    log_info "Auditoría de madurez instalada"

else
    log_skip "Auditoría de madurez"
fi

# ============================================================
# S11: DETECCIÓN DE CVEs KERNEL ESPECÍFICOS (2024-2026)
# ============================================================
log_section "S11: DETECCIÓN DE CVEs KERNEL Y SUPPLY CHAIN"

echo "Verificación directa de CVEs críticos del kernel basada en"
echo "la versión running, sin depender de scanners externos."
echo "Incluye también verificación de integridad de paquetes."
echo ""
echo "CVEs verificados:"
echo "  - CVE-2025-21756 (vsock UAF, CVSS 7.8)"
echo "  - CVE-2025-38236 (MSG_OOB kernel takeover)"
echo "  - CVE-2025-39866 (Filesystem writeback UAF)"
echo "  - CVE-2024-1086  (nf_tables UAF)"
echo "  - CVE-2022-0847  (DirtyPipe)"
echo "  - CVE-2021-4034  (PwnKit/pkexec)"
echo "  - Verificación de integridad de paquetes (supply chain)"
echo ""

if check_executable /usr/local/bin/securizar-vuln-kernel.sh; then
    log_already "Detección de CVEs kernel"
elif ask "¿Crear detector de CVEs kernel y verificación supply chain?"; then

    cat > /usr/local/bin/securizar-vuln-kernel.sh << 'EOFKERNVULN'
#!/bin/bash
# ============================================================
# DETECCIÓN DE CVEs KERNEL ESPECÍFICOS (2024-2026)
# + Verificación de integridad supply chain
# ============================================================
# Uso: securizar-vuln-kernel.sh [--json] [--fix]
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

JSON_MODE=false
FIX_MODE=false
for arg in "$@"; do
    case "$arg" in
        --json) JSON_MODE=true ;;
        --fix)  FIX_MODE=true ;;
    esac
done

RESULT_DIR="/var/log/securizar/vuln-management"
mkdir -p "$RESULT_DIR"
RESULT_FILE="$RESULT_DIR/kernel-cve-$(date +%Y%m%d-%H%M%S).txt"

VULN_COUNT=0
WARN_COUNT=0
TOTAL_CHECKS=0

echo -e "${BOLD}╔════════════════════════════════════════════════════╗${NC}" | tee "$RESULT_FILE"
echo -e "${BOLD}║   DETECCIÓN DE CVEs KERNEL Y SUPPLY CHAIN          ║${NC}" | tee -a "$RESULT_FILE"
echo -e "${BOLD}╚════════════════════════════════════════════════════╝${NC}" | tee -a "$RESULT_FILE"
echo "" | tee -a "$RESULT_FILE"

# ── Información del kernel ──
KVER=$(uname -r)
KMAJ=$(echo "$KVER" | cut -d. -f1)
KMIN=$(echo "$KVER" | cut -d. -f2)
KPAT=$(echo "$KVER" | cut -d. -f3 | cut -d- -f1)
KARCH=$(uname -m)

echo -e "${CYAN}Sistema:${NC}" | tee -a "$RESULT_FILE"
echo "  Kernel:  $KVER ($KARCH)" | tee -a "$RESULT_FILE"
echo "  Distro:  $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')" | tee -a "$RESULT_FILE"
echo "  Fecha:   $(date -Iseconds)" | tee -a "$RESULT_FILE"
echo "" | tee -a "$RESULT_FILE"

# ── Función de verificación ──
check_kernel_cve() {
    local cve="$1" desc="$2" cvss="$3" fmaj="$4" fmin="$5" fpat="$6"
    local mitigable="${7:-}"
    TOTAL_CHECKS=$((TOTAL_CHECKS+1))

    local vulnerable=false
    if [[ "$KMAJ" -lt "$fmaj" ]] || \
       [[ "$KMAJ" -eq "$fmaj" && "$KMIN" -lt "$fmin" ]] || \
       [[ "$KMAJ" -eq "$fmaj" && "$KMIN" -eq "$fmin" && "$KPAT" -lt "$fpat" ]]; then
        vulnerable=true
    fi

    if $vulnerable; then
        VULN_COUNT=$((VULN_COUNT+1))
        echo -e "  ${RED}[VULN]${NC} $cve (CVSS $cvss) - $desc" | tee -a "$RESULT_FILE"
        echo -e "         Fix: kernel >= ${fmaj}.${fmin}.${fpat}" | tee -a "$RESULT_FILE"
        if [[ -n "$mitigable" ]]; then
            echo -e "         ${YELLOW}Mitigación: $mitigable${NC}" | tee -a "$RESULT_FILE"
        fi
    else
        echo -e "  ${GREEN}[SAFE]${NC} $cve (CVSS $cvss) - $desc" | tee -a "$RESULT_FILE"
    fi
}

echo -e "${CYAN}── CVEs Kernel Críticos ──${NC}" | tee -a "$RESULT_FILE"

# Escalada de privilegios
check_kernel_cve "CVE-2025-21756" \
    "vsock use-after-free → root (T1068)" "7.8" \
    6 13 4 "Descargar módulo vsock: modprobe -r vsock"

check_kernel_cve "CVE-2025-38236" \
    "MSG_OOB UNIX socket → control total kernel" "9.0" \
    6 9 8 ""

check_kernel_cve "CVE-2025-39866" \
    "Filesystem writeback UAF" "7.5" \
    6 12 16 ""

check_kernel_cve "CVE-2024-1086" \
    "nf_tables UAF → root (netfilter)" "7.8" \
    6 7 3 "Descargar nf_tables si no se usa: modprobe -r nf_tables"

check_kernel_cve "CVE-2022-0847" \
    "DirtyPipe → escritura arbitraria (T1068)" "7.8" \
    5 16 11 ""

check_kernel_cve "CVE-2024-0193" \
    "nf_tables chain binding UAF" "7.8" \
    6 7 2 ""

check_kernel_cve "CVE-2023-32233" \
    "nf_tables batch request UAF" "7.8" \
    6 4 0 ""

# Container escapes
echo "" | tee -a "$RESULT_FILE"
echo -e "${CYAN}── CVEs Container Escape ──${NC}" | tee -a "$RESULT_FILE"

check_kernel_cve "CVE-2024-21626" \
    "runc container escape via /proc/self/fd" "8.6" \
    6 4 0 "Actualizar runc >= 1.1.12"

check_kernel_cve "CVE-2023-0386" \
    "OverlayFS escalada → container escape" "7.8" \
    6 2 0 "kernel.unprivileged_userns_clone=0"

# ── Módulos kernel peligrosos ──
echo "" | tee -a "$RESULT_FILE"
echo -e "${CYAN}── Módulos Kernel Peligrosos Cargados ──${NC}" | tee -a "$RESULT_FILE"

for MOD in vsock vmw_vsock_vmci_transport nf_tables dccp sctp rds tipc n_hdlc; do
    MOD_CLEAN=$(echo "$MOD" | tr '-' '_')
    if lsmod | grep -q "$MOD_CLEAN" 2>/dev/null; then
        WARN_COUNT=$((WARN_COUNT+1))
        echo -e "  ${YELLOW}[WARN]${NC} $MOD cargado (superficie de ataque activa)" | tee -a "$RESULT_FILE"
        if $FIX_MODE; then
            modprobe -r "$MOD" 2>/dev/null && \
                echo -e "  ${GREEN}[FIX]${NC}  $MOD descargado" | tee -a "$RESULT_FILE" || \
                echo -e "  ${RED}[ERR]${NC}  No se pudo descargar $MOD (en uso)" | tee -a "$RESULT_FILE"
        fi
    else
        echo -e "  ${GREEN}[OK]${NC}   $MOD no cargado" | tee -a "$RESULT_FILE"
    fi
done

# ── Verificación de integridad de paquetes (supply chain) ──
echo "" | tee -a "$RESULT_FILE"
echo -e "${CYAN}── Verificación Supply Chain ──${NC}" | tee -a "$RESULT_FILE"

SC_ISSUES=0
# Verificar firmas GPG de repositorios
if command -v zypper &>/dev/null; then
    UNSIGNED_REPOS=$(zypper repos -d 2>/dev/null | grep -c "No.*|.*No" || true)
    if [[ "$UNSIGNED_REPOS" -gt 0 ]]; then
        SC_ISSUES=$((SC_ISSUES+1))
        echo -e "  ${YELLOW}[WARN]${NC} $UNSIGNED_REPOS repositorio(s) sin verificación GPG" | tee -a "$RESULT_FILE"
    else
        echo -e "  ${GREEN}[OK]${NC}   Todos los repos tienen verificación GPG" | tee -a "$RESULT_FILE"
    fi
elif command -v apt-get &>/dev/null; then
    if apt-key list 2>/dev/null | grep -q "expired"; then
        SC_ISSUES=$((SC_ISSUES+1))
        echo -e "  ${YELLOW}[WARN]${NC} Claves GPG de repositorios expiradas" | tee -a "$RESULT_FILE"
    fi
fi

# Verificar integridad de paquetes instalados
echo -e "  ${DIM}Verificando integridad de paquetes...${NC}"
MODIFIED_PKGS=0
if command -v rpm &>/dev/null; then
    MODIFIED_PKGS=$(rpm -Va --nomtime 2>/dev/null | grep -cE "^..5" || true)
elif command -v debsums &>/dev/null; then
    MODIFIED_PKGS=$(debsums -c 2>/dev/null | wc -l || true)
fi

if [[ "$MODIFIED_PKGS" -gt 0 ]]; then
    SC_ISSUES=$((SC_ISSUES+1))
    echo -e "  ${RED}[VULN]${NC} $MODIFIED_PKGS archivo(s) de paquetes con checksum alterado" | tee -a "$RESULT_FILE"
    echo -e "         Posible tampering o actualización incompleta" | tee -a "$RESULT_FILE"
    if command -v rpm &>/dev/null; then
        echo -e "         Verificar: rpm -Va --nomtime | grep '^..5'" | tee -a "$RESULT_FILE"
    fi
else
    echo -e "  ${GREEN}[OK]${NC}   Integridad de paquetes verificada" | tee -a "$RESULT_FILE"
fi

# Verificar binarios SUID no estándar
SUID_COUNT=$(find /usr/bin /usr/sbin /usr/local/bin -perm -4000 -type f 2>/dev/null | \
    grep -v -E "/(su|sudo|passwd|chsh|chfn|newgrp|mount|umount|pkexec|crontab|ssh-agent)$" | wc -l || true)
if [[ "$SUID_COUNT" -gt 0 ]]; then
    SC_ISSUES=$((SC_ISSUES+1))
    echo -e "  ${YELLOW}[WARN]${NC} $SUID_COUNT binario(s) SUID no estándar encontrados" | tee -a "$RESULT_FILE"
    find /usr/bin /usr/sbin /usr/local/bin -perm -4000 -type f 2>/dev/null | \
        grep -v -E "/(su|sudo|passwd|chsh|chfn|newgrp|mount|umount|pkexec|crontab|ssh-agent)$" | \
        sed 's/^/         /' | tee -a "$RESULT_FILE"
fi

# ── Resumen ──
echo "" | tee -a "$RESULT_FILE"
echo -e "${BOLD}══════════════════════════════════════════${NC}" | tee -a "$RESULT_FILE"
echo -e "${BOLD}  RESUMEN${NC}" | tee -a "$RESULT_FILE"
echo -e "${BOLD}══════════════════════════════════════════${NC}" | tee -a "$RESULT_FILE"
echo "  CVEs verificados:    $TOTAL_CHECKS" | tee -a "$RESULT_FILE"
echo -e "  Vulnerabilidades:    ${RED}$VULN_COUNT${NC}" | tee -a "$RESULT_FILE"
echo -e "  Advertencias:        ${YELLOW}$WARN_COUNT${NC}" | tee -a "$RESULT_FILE"
echo -e "  Supply chain issues: ${YELLOW}$SC_ISSUES${NC}" | tee -a "$RESULT_FILE"

if [[ $VULN_COUNT -gt 0 ]]; then
    echo "" | tee -a "$RESULT_FILE"
    echo -e "  ${RED}${BOLD}ACCIÓN REQUERIDA: Actualizar kernel y revisar módulos${NC}" | tee -a "$RESULT_FILE"
    echo -e "  Para mitigar: $0 --fix" | tee -a "$RESULT_FILE"
fi

echo "" | tee -a "$RESULT_FILE"
echo -e "${DIM}Reporte: $RESULT_FILE${NC}"

# JSON output si se solicita
if $JSON_MODE; then
    JSON_FILE="$RESULT_DIR/kernel-cve-$(date +%Y%m%d-%H%M%S).json"
    cat > "$JSON_FILE" << EOFJSON
{
  "scan_date": "$(date -Iseconds)",
  "kernel_version": "$KVER",
  "architecture": "$KARCH",
  "total_checks": $TOTAL_CHECKS,
  "vulnerabilities": $VULN_COUNT,
  "warnings": $WARN_COUNT,
  "supply_chain_issues": $SC_ISSUES
}
EOFJSON
    echo -e "${DIM}JSON: $JSON_FILE${NC}"
fi

logger -t securizar-vuln "Kernel CVE scan: $VULN_COUNT vulns, $WARN_COUNT warns, $SC_ISSUES supply chain issues"
EOFKERNVULN

    chmod 755 /usr/local/bin/securizar-vuln-kernel.sh
    log_change "Creado" "/usr/local/bin/securizar-vuln-kernel.sh"
    log_info "Detector de CVEs kernel instalado"
    log_info "  Uso: securizar-vuln-kernel.sh [--json] [--fix]"

else
    log_skip "Detección de CVEs kernel"
fi

echo ""
show_changes_summary
log_info "Módulo de gestión de vulnerabilidades completado"
log_info "Backup en: $BACKUP_DIR"
