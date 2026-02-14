#!/bin/bash
# ============================================================
# GESTION DE SECRETOS (SECRETS MANAGEMENT) - Linux Multi-Distro
# Modulo 51 - Securizar Suite
# ============================================================
# Secciones:
#   S1  - Deteccion de secretos expuestos (Secret Scanning)
#   S2  - Gestion de secretos con HashiCorp Vault
#   S3  - Rotacion automatica de credenciales
#   S4  - Proteccion de variables de entorno
#   S5  - Gestion segura de SSH keys
#   S6  - Cifrado de secretos en reposo
#   S7  - Integracion con gestores de paquetes de secretos
#   S8  - Politicas de secretos
#   S9  - Monitorizacion de acceso a secretos
#   S10 - Auditoria integral de gestion de secretos
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps
init_backup "secrets-management"

# ── Pre-check: detectar secciones ya aplicadas ────────────
_precheck 10
_pc 'check_executable "/usr/local/bin/escanear-secretos.sh"'
_pc 'check_executable "/usr/local/bin/securizar-vault-init.sh"'
_pc 'check_executable "/usr/local/bin/rotar-credenciales.sh"'
_pc 'check_executable "/usr/local/bin/auditar-env-secrets.sh"'
_pc 'check_executable "/usr/local/bin/auditar-ssh-keys.sh"'
_pc 'check_executable "/usr/local/bin/cifrar-secretos.sh"'
_pc 'check_executable "/usr/local/bin/securizar-pass-init.sh"'
_pc 'check_executable "/usr/local/bin/validar-politica-secretos.sh"'
_pc 'check_executable "/usr/local/bin/monitorizar-acceso-secretos.sh"'
_pc 'check_executable "/usr/local/bin/auditoria-secrets.sh"'
_precheck_result

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MODULO 51 - GESTION DE SECRETOS (SECRETS MANAGEMENT)   ║"
echo "║   Scanning, Vault, rotacion, cifrado, SSH keys,           ║"
echo "║   politicas, monitorizacion, auditoria                    ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

log_section "MODULO 51: GESTION DE SECRETOS"
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

# ── Directorios base ─────────────────────────────────────────
mkdir -p /etc/securizar
mkdir -p /var/log/securizar
mkdir -p /usr/local/share/securizar

# ── Helpers comunes ──────────────────────────────────────────
generate_strong_password() {
    local length="${1:-32}"
    openssl rand -base64 "$((length * 2))" 2>/dev/null | tr -dc 'A-Za-z0-9!@#$%^&*()-_=+' | head -c "$length"
}

timestamp_id() {
    date '+%Y%m%d-%H%M%S'
}

# ============================================================
# S1: DETECCION DE SECRETOS EXPUESTOS (SECRET SCANNING)
# ============================================================
log_section "S1: Deteccion de secretos expuestos"

log_info "Instala herramientas de escaneo y crea scripts de deteccion:"
log_info "  - Instala trufflehog o gitleaks si disponible"
log_info "  - Crea wrapper /usr/local/bin/escanear-secretos.sh"
log_info "  - Crea patrones en /etc/securizar/secrets-patterns.conf"
log_info ""

if check_executable "/usr/local/bin/escanear-secretos.sh"; then
    log_already "Deteccion de secretos (escanear-secretos.sh ya instalado)"
elif ask "¿Configurar deteccion de secretos expuestos?"; then

    mkdir -p /etc/securizar
    mkdir -p /usr/local/bin

    # ── Intentar instalar herramientas de secret scanning ──────
    HAS_TRUFFLEHOG=0
    HAS_GITLEAKS=0

    if command -v trufflehog &>/dev/null; then
        HAS_TRUFFLEHOG=1
        log_info "trufflehog ya instalado: $(trufflehog --version 2>&1 | head -1 || echo 'version desconocida')"
    fi

    if command -v gitleaks &>/dev/null; then
        HAS_GITLEAKS=1
        log_info "gitleaks ya instalado: $(gitleaks version 2>&1 || echo 'version desconocida')"
    fi

    if [[ $HAS_TRUFFLEHOG -eq 0 ]] && [[ $HAS_GITLEAKS -eq 0 ]]; then
        log_warn "No se encontro trufflehog ni gitleaks en el sistema"

        if ask "¿Descargar gitleaks desde GitHub releases?"; then
            GITLEAKS_VERSION="8.18.4"
            ARCH_SUFFIX="x64"
            if [[ "$(uname -m)" == "aarch64" ]]; then
                ARCH_SUFFIX="arm64"
            fi

            GITLEAKS_URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${ARCH_SUFFIX}.tar.gz"
            GITLEAKS_TMP=$(mktemp -d)

            log_info "Descargando gitleaks v${GITLEAKS_VERSION}..."
            download_ok=0
            if command -v curl &>/dev/null; then
                curl -fsSL "$GITLEAKS_URL" -o "${GITLEAKS_TMP}/gitleaks.tar.gz" 2>/dev/null && download_ok=1 || true
            elif command -v wget &>/dev/null; then
                wget -q "$GITLEAKS_URL" -O "${GITLEAKS_TMP}/gitleaks.tar.gz" 2>/dev/null && download_ok=1 || true
            else
                log_warn "No se encontro curl ni wget para descargar gitleaks"
            fi

            if [[ $download_ok -eq 1 ]]; then
                tar xzf "${GITLEAKS_TMP}/gitleaks.tar.gz" -C "${GITLEAKS_TMP}/" 2>/dev/null || true
                if [[ -f "${GITLEAKS_TMP}/gitleaks" ]]; then
                    install -m 0755 "${GITLEAKS_TMP}/gitleaks" /usr/local/bin/gitleaks
                    HAS_GITLEAKS=1
                    log_change "Instalado" "gitleaks v${GITLEAKS_VERSION} en /usr/local/bin/gitleaks"
                else
                    log_warn "No se pudo extraer gitleaks del archivo descargado"
                fi
            else
                log_warn "No se pudo descargar gitleaks (sin conexion o URL invalida)"
            fi

            rm -rf "${GITLEAKS_TMP}" 2>/dev/null || true
        else
            log_skip "Descarga de gitleaks"
        fi
    fi

    # ── Crear archivo de patrones de secretos ──────────────────
    PATTERNS_CONF="/etc/securizar/secrets-patterns.conf"
    if [[ -f "$PATTERNS_CONF" ]]; then
        cp -a "$PATTERNS_CONF" "$BACKUP_DIR/"
        log_change "Backup" "$PATTERNS_CONF"
    fi

    cat > "$PATTERNS_CONF" << 'EOFPATTERNS'
# ============================================================
# Patrones de deteccion de secretos - securizar Modulo 51
# ============================================================
# Formato: NOMBRE_PATRON|REGEX|SEVERIDAD
# Severidades: CRITICO, ALTO, MEDIO, BAJO
# ============================================================

# AWS
AWS_ACCESS_KEY_ID|AKIA[0-9A-Z]{16}|CRITICO
AWS_SECRET_ACCESS_KEY|aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}|CRITICO
AWS_ACCOUNT_ID|aws_account_id\s*[=:]\s*[0-9]{12}|MEDIO

# Claves privadas
RSA_PRIVATE_KEY|-----BEGIN RSA PRIVATE KEY-----|CRITICO
DSA_PRIVATE_KEY|-----BEGIN DSA PRIVATE KEY-----|CRITICO
EC_PRIVATE_KEY|-----BEGIN EC PRIVATE KEY-----|CRITICO
OPENSSH_PRIVATE_KEY|-----BEGIN OPENSSH PRIVATE KEY-----|CRITICO
PGP_PRIVATE_KEY|-----BEGIN PGP PRIVATE KEY BLOCK-----|CRITICO

# Tokens y APIs genericos
GENERIC_API_KEY|(api[_-]?key|apikey)\s*[=:]\s*[A-Za-z0-9_\-]{20,}|ALTO
GENERIC_SECRET|(secret|secret_key|client_secret)\s*[=:]\s*[A-Za-z0-9_\-]{16,}|ALTO
GENERIC_TOKEN|(token|access_token|auth_token)\s*[=:]\s*[A-Za-z0-9_\-]{20,}|ALTO
GENERIC_PASSWORD|(password|passwd|pwd)\s*[=:]\s*[^\s]{8,}|ALTO

# GitHub / GitLab
GITHUB_TOKEN|gh[pousr]_[A-Za-z0-9_]{36,}|CRITICO
GITHUB_FINE_GRAINED|github_pat_[A-Za-z0-9_]{22,}|CRITICO
GITLAB_TOKEN|glpat-[A-Za-z0-9\-_]{20,}|CRITICO

# Bases de datos
MYSQL_CONNECTION|mysql://[^:]+:[^@]+@|CRITICO
POSTGRES_CONNECTION|postgres(ql)?://[^:]+:[^@]+@|CRITICO
MONGODB_CONNECTION|mongodb(\+srv)?://[^:]+:[^@]+@|CRITICO
REDIS_CONNECTION|redis://:[^@]+@|ALTO

# Cloud providers
GCP_SERVICE_ACCOUNT|"type"\s*:\s*"service_account"|ALTO
AZURE_CLIENT_SECRET|azure[_-]?client[_-]?secret\s*[=:]\s*[A-Za-z0-9_\-]{30,}|CRITICO
DIGITALOCEAN_TOKEN|dop_v1_[a-f0-9]{64}|CRITICO

# Comunicaciones
SLACK_TOKEN|xox[baprs]-[0-9]{10,}-[A-Za-z0-9]{10,}|ALTO
SLACK_WEBHOOK|https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+|ALTO
TELEGRAM_BOT_TOKEN|[0-9]+:AA[A-Za-z0-9_\-]{33}|ALTO

# JWT y Bearer
JWT_TOKEN|eyJ[A-Za-z0-9_\-]*\.eyJ[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]*|MEDIO
BEARER_TOKEN|[Bb]earer\s+[A-Za-z0-9_\-\.]{20,}|MEDIO

# Stripe / Sendgrid / Twilio
STRIPE_SECRET_KEY|sk_(live|test)_[0-9a-zA-Z]{24,}|CRITICO
SENDGRID_API_KEY|SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}|CRITICO
TWILIO_API_KEY|SK[0-9a-fA-F]{32}|ALTO

# Envfiles
DOTENV_SECRET|^[A-Z_]+(SECRET|KEY|TOKEN|PASSWORD|PASSWD|PASS|API)=[^\s]+|ALTO
EOFPATTERNS
    chmod 0640 "$PATTERNS_CONF"
    log_change "Creado" "$PATTERNS_CONF (patrones de deteccion)"

    # ── Crear wrapper de escaneo de secretos ───────────────────
    SCAN_TOOL="/usr/local/bin/escanear-secretos.sh"
    if [[ -f "$SCAN_TOOL" ]]; then
        cp -a "$SCAN_TOOL" "$BACKUP_DIR/"
        log_change "Backup" "$SCAN_TOOL existente"
    fi

    cat > "$SCAN_TOOL" << 'EOFSCAN'
#!/bin/bash
# ============================================================
# escanear-secretos.sh - Escaner de secretos expuestos
# Generado por securizar - Modulo 51
# ============================================================
# Uso: escanear-secretos.sh [--git REPO] [--fs RUTA] [--all]
# ============================================================
set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

PATTERNS_FILE="/etc/securizar/secrets-patterns.conf"
LOG_DIR="/var/log/securizar"
mkdir -p "$LOG_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT_FILE="${LOG_DIR}/secret-scan-${TIMESTAMP}.log"

SCAN_GIT=0
SCAN_FS=0
GIT_PATH=""
FS_PATHS=()
TOTAL_FINDINGS=0
CRITICO_COUNT=0
ALTO_COUNT=0
MEDIO_COUNT=0
BAJO_COUNT=0

usage() {
    echo -e "${BOLD}Uso: $0 [OPCIONES]${NC}"
    echo ""
    echo "  --git RUTA       Escanear repositorio git en RUTA"
    echo "  --fs RUTA        Escanear sistema de archivos en RUTA"
    echo "  --all            Escanear /etc, /home, /opt y repos git en /home"
    echo "  -h, --help       Mostrar esta ayuda"
    echo ""
    echo "Ejemplo: $0 --all"
    echo "Ejemplo: $0 --git /opt/myapp --fs /etc"
}

log_finding() {
    local severity="$1" source_type="$2" pattern_name="$3" file="$4"
    local line_num="${5:-N/A}"
    local color="$NC"

    ((TOTAL_FINDINGS++)) || true
    case "$severity" in
        CRITICO)  ((CRITICO_COUNT++)) || true; color="$RED" ;;
        ALTO)     ((ALTO_COUNT++)) || true; color="$YELLOW" ;;
        MEDIO)    ((MEDIO_COUNT++)) || true; color="$CYAN" ;;
        BAJO)     ((BAJO_COUNT++)) || true; color="$GREEN" ;;
    esac

    echo -e "  ${color}[${severity}]${NC} ${pattern_name} -> ${file}:${line_num}" | tee -a "$REPORT_FILE"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --git)
            SCAN_GIT=1
            GIT_PATH="${2:-}"
            shift 2 || { echo "Error: --git requiere argumento"; exit 1; }
            ;;
        --fs)
            SCAN_FS=1
            FS_PATHS+=("${2:-}")
            shift 2 || { echo "Error: --fs requiere argumento"; exit 1; }
            ;;
        --all)
            SCAN_GIT=1; SCAN_FS=1
            FS_PATHS=(/etc /home /opt)
            shift
            ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Opcion desconocida: $1"; usage; exit 1 ;;
    esac
done

if [[ $SCAN_GIT -eq 0 ]] && [[ $SCAN_FS -eq 0 ]]; then
    echo -e "${YELLOW}Nada que escanear. Usa --all para escaneo completo.${NC}"
    usage; exit 1
fi

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  ESCANER DE SECRETOS EXPUESTOS${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""
echo -e "${CYAN}Informe: ${REPORT_FILE}${NC}"
echo ""

{
    echo "# ============================================"
    echo "# Informe de escaneo de secretos"
    echo "# Fecha: $(date)"
    echo "# Host: $(hostname)"
    echo "# ============================================"
} > "$REPORT_FILE"

# ── Escaneo con gitleaks ──────────────────────────────────
scan_with_gitleaks() {
    local repo_path="$1"
    command -v gitleaks &>/dev/null || return 1

    echo -e "${CYAN}── Escaneando con gitleaks: ${repo_path} ──${NC}"
    echo "## Gitleaks: ${repo_path}" >> "$REPORT_FILE"

    local gitleaks_out
    gitleaks_out=$(mktemp)
    if gitleaks detect --source "$repo_path" --report-format json \
            --report-path "$gitleaks_out" --no-banner 2>/dev/null; then
        echo -e "  ${GREEN}OK${NC} No se encontraron secretos con gitleaks"
    else
        local count="?"
        if command -v python3 &>/dev/null; then
            count=$(python3 -c "import json; print(len(json.load(open('$gitleaks_out'))))" 2>/dev/null || echo "?")
        fi
        echo -e "  ${RED}!!${NC} gitleaks encontro ${count} secreto(s) potencial(es)"
        echo "  Hallazgos: ${count}" >> "$REPORT_FILE"
        if command -v python3 &>/dev/null; then
            python3 -c "
import json, sys
try:
    for f in json.load(open('$gitleaks_out'))[:20]:
        rule = f.get('RuleID', 'unknown')
        fp = f.get('File', 'unknown')
        line = f.get('StartLine', '?')
        print(f'  [ALTO] {rule} -> {fp}:{line}')
except: pass
" 2>/dev/null | tee -a "$REPORT_FILE" || true
        fi
        ((TOTAL_FINDINGS += ${count:-0})) 2>/dev/null || true
        ((ALTO_COUNT += ${count:-0})) 2>/dev/null || true
    fi
    rm -f "$gitleaks_out" 2>/dev/null || true
}

# ── Escaneo con trufflehog ────────────────────────────────
scan_with_trufflehog() {
    local repo_path="$1"
    command -v trufflehog &>/dev/null || return 1

    echo -e "${CYAN}── Escaneando con trufflehog: ${repo_path} ──${NC}"
    echo "## Trufflehog: ${repo_path}" >> "$REPORT_FILE"

    local th_out
    th_out=$(mktemp)
    if trufflehog filesystem "$repo_path" --json 2>/dev/null > "$th_out"; then
        local count
        count=$(wc -l < "$th_out")
        if [[ $count -eq 0 ]]; then
            echo -e "  ${GREEN}OK${NC} No se encontraron secretos con trufflehog"
        else
            echo -e "  ${RED}!!${NC} trufflehog encontro ${count} hallazgo(s)"
            echo "  Hallazgos: ${count}" >> "$REPORT_FILE"
            ((TOTAL_FINDINGS += count)) 2>/dev/null || true
            ((ALTO_COUNT += count)) 2>/dev/null || true
        fi
    else
        echo -e "  ${YELLOW}!!${NC} trufflehog fallo al escanear ${repo_path}"
    fi
    rm -f "$th_out" 2>/dev/null || true
}

# ── Escaneo basado en patrones regex ──────────────────────
scan_with_patterns() {
    local scan_path="$1" scan_label="${2:-filesystem}"

    echo -e "${CYAN}── Escaneo por patrones: ${scan_path} ──${NC}"
    echo "## Patrones regex: ${scan_path}" >> "$REPORT_FILE"

    if [[ ! -f "$PATTERNS_FILE" ]]; then
        echo -e "  ${YELLOW}!!${NC} Archivo de patrones no encontrado: ${PATTERNS_FILE}"
        return 1
    fi

    local found_any=0
    while IFS='|' read -r pattern_name regex severity; do
        [[ -z "$pattern_name" || "$pattern_name" =~ ^[[:space:]]*# ]] && continue
        pattern_name=$(echo "$pattern_name" | xargs)
        regex=$(echo "$regex" | xargs)
        severity=$(echo "$severity" | xargs)
        [[ -z "$regex" ]] && continue

        local results
        results=$(grep -rEln \
            --include="*.conf" --include="*.cfg" --include="*.yml" \
            --include="*.yaml" --include="*.json" --include="*.xml" \
            --include="*.env" --include="*.sh" --include="*.bash" \
            --include="*.py" --include="*.rb" --include="*.js" \
            --include="*.ts" --include="*.php" --include="*.properties" \
            --include="*.ini" --include="*.toml" --include="*.tf" \
            --include="*.tfvars" --include="*.service" --include="*.txt" \
            --exclude-dir=".git" --exclude-dir="node_modules" \
            --exclude-dir="__pycache__" --exclude-dir=".cache" \
            "$regex" "$scan_path" 2>/dev/null || true)

        if [[ -n "$results" ]]; then
            found_any=1
            while IFS= read -r match_file; do
                [[ -z "$match_file" ]] && continue
                log_finding "$severity" "$scan_label" "$pattern_name" "$match_file"
            done <<< "$results"
        fi
    done < "$PATTERNS_FILE"

    # Buscar archivos .env sin cifrar
    echo -e "  ${DIM}Buscando archivos .env expuestos...${NC}"
    local env_files
    env_files=$(find "$scan_path" \( -name ".env" -o -name ".env.*" -o -name "*.env" \) \
        -not -name "*.example" -not -name "*.sample" -not -name "*.template" \
        2>/dev/null || true)
    if [[ -n "$env_files" ]]; then
        while IFS= read -r env_file; do
            [[ -z "$env_file" || ! -f "$env_file" ]] && continue
            if grep -qEi '(password|secret|key|token|api)=' "$env_file" 2>/dev/null; then
                log_finding "ALTO" "envfile" "DOTENV_EXPOSED" "$env_file"
                found_any=1
            fi
        done <<< "$env_files"
    fi

    # Buscar claves privadas sueltas
    echo -e "  ${DIM}Buscando claves privadas expuestas...${NC}"
    local key_files
    key_files=$(find "$scan_path" \( -name "*.pem" -o -name "*.key" -o -name "*.p12" \
        -o -name "*.pfx" -o -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" \) \
        -not -path "*/.git/*" 2>/dev/null || true)
    if [[ -n "$key_files" ]]; then
        while IFS= read -r key_file; do
            [[ -z "$key_file" || ! -f "$key_file" ]] && continue
            local perms
            perms=$(stat -c '%a' "$key_file" 2>/dev/null || echo "???")
            if [[ "${perms:(-1)}" != "0" ]] || [[ "${perms:(-2):1}" != "0" ]]; then
                log_finding "CRITICO" "filesystem" "PRIVATE_KEY_WORLD_READABLE" "$key_file" "perms=$perms"
            else
                log_finding "MEDIO" "filesystem" "PRIVATE_KEY_FOUND" "$key_file" "perms=$perms"
            fi
            found_any=1
        done <<< "$key_files"
    fi

    if [[ $found_any -eq 0 ]]; then
        echo -e "  ${GREEN}OK${NC} No se encontraron patrones en ${scan_path}"
    fi
}

# ── Ejecutar escaneos ──────────────────────────────────────
if [[ $SCAN_GIT -eq 1 ]]; then
    echo -e "${BOLD}── ESCANEO DE REPOSITORIOS GIT ──${NC}" | tee -a "$REPORT_FILE"
    git_repos=()
    if [[ -n "$GIT_PATH" ]] && [[ -d "$GIT_PATH/.git" ]]; then
        git_repos+=("$GIT_PATH")
    else
        while IFS= read -r gitdir; do
            [[ -n "$gitdir" ]] && git_repos+=("$(dirname "$gitdir")")
        done < <(find /home /opt -maxdepth 4 -name ".git" -type d 2>/dev/null || true)
    fi

    if [[ ${#git_repos[@]} -eq 0 ]]; then
        echo -e "  ${YELLOW}!!${NC} No se encontraron repositorios git"
    else
        for repo in "${git_repos[@]}"; do
            echo -e "\n${CYAN}Repositorio: ${repo}${NC}"
            if command -v gitleaks &>/dev/null; then
                scan_with_gitleaks "$repo"
            elif command -v trufflehog &>/dev/null; then
                scan_with_trufflehog "$repo"
            fi
            scan_with_patterns "$repo" "git"
        done
    fi
fi

if [[ $SCAN_FS -eq 1 ]]; then
    echo -e "\n${BOLD}── ESCANEO DE SISTEMA DE ARCHIVOS ──${NC}" | tee -a "$REPORT_FILE"
    for fspath in "${FS_PATHS[@]}"; do
        if [[ -d "$fspath" ]]; then
            scan_with_patterns "$fspath" "filesystem"
        else
            echo -e "  ${YELLOW}!!${NC} Ruta no encontrada: $fspath"
        fi
    done
fi

# ── Resumen ────────────────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  RESUMEN DE ESCANEO DE SECRETOS${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "  Total hallazgos:  ${BOLD}${TOTAL_FINDINGS}${NC}"
echo -e "  ${RED}Criticos:${NC}         ${CRITICO_COUNT}"
echo -e "  ${YELLOW}Altos:${NC}            ${ALTO_COUNT}"
echo -e "  ${CYAN}Medios:${NC}           ${MEDIO_COUNT}"
echo -e "  ${GREEN}Bajos:${NC}            ${BAJO_COUNT}"
echo -e "  Informe: ${BOLD}${REPORT_FILE}${NC}"

{
    echo ""; echo "# RESUMEN"
    echo "Total: ${TOTAL_FINDINGS} | Criticos: ${CRITICO_COUNT} | Altos: ${ALTO_COUNT} | Medios: ${MEDIO_COUNT} | Bajos: ${BAJO_COUNT}"
} >> "$REPORT_FILE"
chmod 0600 "$REPORT_FILE"

if [[ $CRITICO_COUNT -gt 0 ]]; then exit 2
elif [[ $ALTO_COUNT -gt 0 ]]; then exit 1
fi
exit 0
EOFSCAN
    chmod +x "$SCAN_TOOL"
    log_change "Creado" "$SCAN_TOOL - escaner de secretos expuestos"
    log_change "Permisos" "$SCAN_TOOL -> +x"

    log_info "Deteccion de secretos expuestos configurada"
    log_info "Ejecuta: escanear-secretos.sh --all"
else
    log_skip "Deteccion de secretos expuestos"
fi

# ============================================================
# S2: GESTION DE SECRETOS CON HASHICORP VAULT
# ============================================================
log_section "S2: Gestion de secretos con HashiCorp Vault"

log_info "Prepara infraestructura para HashiCorp Vault:"
log_info "  - Verifica/instala vault"
log_info "  - Crea configuracion de servidor vault"
log_info "  - Crea servicio systemd para vault"
log_info "  - Crea script de inicializacion con politicas"
log_info ""

if check_executable "/usr/local/bin/securizar-vault-init.sh"; then
    log_already "HashiCorp Vault (securizar-vault-init.sh ya instalado)"
elif ask "¿Configurar infraestructura de HashiCorp Vault?"; then

    HAS_VAULT=0
    if command -v vault &>/dev/null; then
        HAS_VAULT=1
        log_info "vault ya instalado: $(vault version 2>&1 | head -1 || echo 'version desconocida')"
    else
        log_warn "HashiCorp Vault no esta instalado"
        if ask "¿Intentar instalar vault?"; then
            case "$DISTRO_FAMILY" in
                debian)
                    log_info "Configurando repositorio HashiCorp para Debian/Ubuntu..."
                    if command -v curl &>/dev/null && command -v gpg &>/dev/null; then
                        curl -fsSL https://apt.releases.hashicorp.com/gpg 2>/dev/null \
                            | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg 2>/dev/null || true
                        if [[ -f /usr/share/keyrings/hashicorp-archive-keyring.gpg ]]; then
                            local_codename=$(lsb_release -cs 2>/dev/null || echo "jammy")
                            echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com ${local_codename} main" \
                                > /etc/apt/sources.list.d/hashicorp.list
                            apt-get update -qq 2>/dev/null || true
                            DEBIAN_FRONTEND=noninteractive apt-get install -y vault 2>/dev/null && HAS_VAULT=1 || true
                        fi
                    fi
                    ;;
                rhel)
                    log_info "Configurando repositorio HashiCorp para RHEL/Fedora..."
                    cat > /etc/yum.repos.d/hashicorp.repo << 'EOFHASHIREPO'
[hashicorp]
name=HashiCorp Stable - $basearch
baseurl=https://rpm.releases.hashicorp.com/RHEL/$releasever/$basearch/stable
enabled=1
gpgcheck=1
gpgkey=https://rpm.releases.hashicorp.com/gpg
EOFHASHIREPO
                    dnf install -y vault 2>/dev/null && HAS_VAULT=1 || true
                    ;;
                suse)
                    log_info "Configurando repositorio HashiCorp para openSUSE..."
                    zypper addrepo --no-gpgcheck https://rpm.releases.hashicorp.com/RHEL/8/x86_64/stable hashicorp 2>/dev/null || true
                    zypper --non-interactive --gpg-auto-import-keys refresh hashicorp 2>/dev/null || true
                    zypper --non-interactive install vault 2>/dev/null && HAS_VAULT=1 || true
                    ;;
                arch)
                    pacman -S --noconfirm vault 2>/dev/null && HAS_VAULT=1 || true
                    ;;
            esac

            if [[ $HAS_VAULT -eq 1 ]]; then
                log_change "Instalado" "HashiCorp Vault"
            else
                log_warn "No se pudo instalar vault automaticamente"
                log_info "Instala manualmente: https://developer.hashicorp.com/vault/install"
            fi
        else
            log_skip "Instalacion de vault"
        fi
    fi

    # ── Directorios vault ──────────────────────────────────────
    mkdir -p /etc/securizar/vault/policies
    mkdir -p /var/lib/securizar/vault/data
    mkdir -p /var/log/securizar/vault

    # ── Configuracion servidor Vault ───────────────────────────
    VAULT_CFG="/etc/securizar/vault/vault-server.hcl"
    if [[ -f "$VAULT_CFG" ]]; then
        cp -a "$VAULT_CFG" "$BACKUP_DIR/"
        log_change "Backup" "$VAULT_CFG"
    fi

    cat > "$VAULT_CFG" << 'EOFVAULTCFG'
# ============================================================
# HashiCorp Vault - Configuracion del servidor
# Generado por seguridad-secrets.sh (securizar Modulo 51)
# ============================================================

storage "file" {
  path = "/var/lib/securizar/vault/data"
}

listener "tcp" {
  address     = "127.0.0.1:8200"

  # TLS - Descomentar cuando se tengan certificados
  # tls_cert_file = "/etc/securizar/vault/tls/vault-cert.pem"
  # tls_key_file  = "/etc/securizar/vault/tls/vault-key.pem"
  # tls_min_version = "tls12"

  # Sin TLS (solo localhost) mientras no haya certificados
  tls_disable = 1
}

api_addr      = "http://127.0.0.1:8200"
disable_mlock = true
ui            = true

telemetry {
  disable_hostname = true
}

log_level = "info"
log_file  = "/var/log/securizar/vault/vault.log"
EOFVAULTCFG
    chmod 0640 "$VAULT_CFG"
    log_change "Creado" "$VAULT_CFG"

    # ── Servicio systemd ───────────────────────────────────────
    VAULT_SVC="/etc/systemd/system/securizar-vault.service"
    if [[ -f "$VAULT_SVC" ]]; then
        cp -a "$VAULT_SVC" "$BACKUP_DIR/"
        log_change "Backup" "$VAULT_SVC"
    fi

    cat > "$VAULT_SVC" << 'EOFVAULTSVC'
[Unit]
Description=securizar - HashiCorp Vault Secret Server
Documentation=https://developer.hashicorp.com/vault/docs
After=network-online.target
Wants=network-online.target
ConditionFileNotEmpty=/etc/securizar/vault/vault-server.hcl

[Service]
Type=notify
User=root
Group=root
ExecStart=/usr/bin/vault server -config=/etc/securizar/vault/vault-server.hcl
ExecReload=/bin/kill --signal HUP $MAINPID
KillMode=process
KillSignal=SIGINT
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
LimitNOFILE=65536
LimitMEMLOCK=infinity
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_IPC_LOCK CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_IPC_LOCK

[Install]
WantedBy=multi-user.target
EOFVAULTSVC
    chmod 0644 "$VAULT_SVC"
    systemctl daemon-reload 2>/dev/null || true
    log_change "Creado" "$VAULT_SVC"

    # ── Script de inicializacion ───────────────────────────────
    VAULT_INIT="/usr/local/bin/securizar-vault-init.sh"
    if [[ -f "$VAULT_INIT" ]]; then
        cp -a "$VAULT_INIT" "$BACKUP_DIR/"
        log_change "Backup" "$VAULT_INIT existente"
    fi

    cat > "$VAULT_INIT" << 'EOFVAULTINIT'
#!/bin/bash
# ============================================================
# Inicializacion de HashiCorp Vault - securizar Modulo 51
# ============================================================
# Uso: securizar-vault-init.sh [--init|--unseal K1 K2 K3|
#          --setup-policies|--enable-audit|--status]
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

export VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_INIT_FILE="/etc/securizar/vault/vault-init-keys.json"
VAULT_POLICY_DIR="/etc/securizar/vault/policies"

command -v vault &>/dev/null || { echo -e "${RED}Error: vault no instalado${NC}"; exit 1; }

usage() {
    echo -e "${BOLD}Uso: $0 [OPCION]${NC}"
    echo "  --init               Inicializar vault (primera vez)"
    echo "  --unseal K1 K2 K3    Desellar vault con 3 claves"
    echo "  --setup-policies     Crear politicas admin/readonly/app-secrets"
    echo "  --enable-audit       Habilitar audit logging"
    echo "  --status             Mostrar estado de vault"
    echo "  -h, --help           Mostrar ayuda"
}

vault_init() {
    echo -e "${BOLD}── Inicializando Vault ──${NC}"
    if ! vault status &>/dev/null; then
        echo -e "${RED}No se puede conectar a Vault en ${VAULT_ADDR}${NC}"
        echo -e "${YELLOW}Inicia vault: systemctl start securizar-vault${NC}"
        exit 1
    fi
    if vault status 2>/dev/null | grep -q "Initialized.*true"; then
        echo -e "${YELLOW}Vault ya esta inicializado${NC}"
        return 0
    fi
    echo -e "${CYAN}Inicializando con 5 claves, umbral de 3...${NC}"
    mkdir -p "$(dirname "$VAULT_INIT_FILE")"
    if vault operator init -key-shares=5 -key-threshold=3 -format=json > "$VAULT_INIT_FILE" 2>/dev/null; then
        chmod 0400 "$VAULT_INIT_FILE"
        echo -e "${GREEN}Vault inicializado correctamente${NC}"
        echo -e "${RED}${BOLD}IMPORTANTE: Las claves estan en ${VAULT_INIT_FILE}${NC}"
        echo -e "${RED}${BOLD}Mueve y distribuye las claves de forma segura.${NC}"
    else
        echo -e "${RED}Error inicializando Vault${NC}"; exit 1
    fi
}

vault_unseal() {
    echo -e "${BOLD}── Desellando Vault ──${NC}"
    local keys=("$@")
    if [[ ${#keys[@]} -lt 3 ]]; then
        if [[ -f "$VAULT_INIT_FILE" ]] && command -v python3 &>/dev/null; then
            echo -e "${YELLOW}Leyendo claves del archivo de init...${NC}"
            mapfile -t keys < <(python3 -c "
import json
data = json.load(open('$VAULT_INIT_FILE'))
for k in data.get('unseal_keys_b64', [])[:3]: print(k)
" 2>/dev/null)
        fi
    fi
    if [[ ${#keys[@]} -lt 3 ]]; then
        echo -e "${RED}Se necesitan al menos 3 claves${NC}"; exit 1
    fi
    for i in 0 1 2; do
        echo -e "  Aplicando clave $((i+1))/3..."
        vault operator unseal "${keys[$i]}" 2>/dev/null || true
    done
    if vault status 2>/dev/null | grep -q "Sealed.*false"; then
        echo -e "${GREEN}Vault desellado correctamente${NC}"
    else
        echo -e "${RED}Vault sigue sellado${NC}"; exit 1
    fi
}

vault_setup_policies() {
    echo -e "${BOLD}── Configurando politicas ──${NC}"
    mkdir -p "$VAULT_POLICY_DIR"

    cat > "${VAULT_POLICY_DIR}/admin.hcl" << 'EOFPOL'
# Politica admin - acceso total
path "*" { capabilities = ["create","read","update","delete","list","sudo"] }
EOFPOL

    cat > "${VAULT_POLICY_DIR}/readonly.hcl" << 'EOFPOL'
# Politica solo lectura
path "secret/*"            { capabilities = ["read","list"] }
path "sys/health"          { capabilities = ["read"] }
path "sys/policies/acl/*"  { capabilities = ["read","list"] }
EOFPOL

    cat > "${VAULT_POLICY_DIR}/app-secrets.hcl" << 'EOFPOL'
# Politica app-secrets
path "secret/data/apps/{{identity.entity.name}}/*"     { capabilities = ["read","list"] }
path "secret/metadata/apps/{{identity.entity.name}}/*"  { capabilities = ["read","list"] }
path "secret/data/shared/*"                             { capabilities = ["read","list"] }
EOFPOL

    chmod 0640 "${VAULT_POLICY_DIR}"/*.hcl

    if vault status 2>/dev/null | grep -q "Sealed.*false"; then
        for pol_file in "${VAULT_POLICY_DIR}"/*.hcl; do
            pol_name=$(basename "$pol_file" .hcl)
            vault policy write "$pol_name" "$pol_file" 2>/dev/null && \
                echo -e "  ${GREEN}OK${NC} Politica '${pol_name}' aplicada" || \
                echo -e "  ${YELLOW}!!${NC} No se pudo aplicar '${pol_name}'"
        done
        if ! vault secrets list 2>/dev/null | grep -q "^secret/"; then
            vault secrets enable -path=secret kv-v2 2>/dev/null && \
                echo -e "  ${GREEN}OK${NC} KV v2 habilitado en secret/" || true
        fi
    else
        echo -e "${YELLOW}Vault no accesible. Politicas guardadas en ${VAULT_POLICY_DIR}${NC}"
    fi
}

vault_enable_audit() {
    echo -e "${BOLD}── Habilitando audit logging ──${NC}"
    if vault status 2>/dev/null | grep -q "Sealed.*false"; then
        mkdir -p /var/log/securizar/vault
        if ! vault audit list 2>/dev/null | grep -q "file/"; then
            vault audit enable file file_path=/var/log/securizar/vault/vault-audit.log 2>/dev/null && \
                echo -e "  ${GREEN}OK${NC} Audit log habilitado" || \
                echo -e "  ${YELLOW}!!${NC} No se pudo habilitar audit log"
        else
            echo -e "  ${GREEN}OK${NC} Audit log ya habilitado"
        fi
    else
        echo -e "${YELLOW}Vault no accesible${NC}"
    fi
}

case "${1:-}" in
    --init)            vault_init ;;
    --unseal)          shift; vault_unseal "$@" ;;
    --setup-policies)  vault_setup_policies ;;
    --enable-audit)    vault_enable_audit ;;
    --status)          vault status 2>/dev/null || echo -e "${YELLOW}No conecta a ${VAULT_ADDR}${NC}" ;;
    -h|--help|"")      usage ;;
    *)                 echo "Opcion desconocida: $1"; usage; exit 1 ;;
esac
EOFVAULTINIT
    chmod +x "$VAULT_INIT"
    log_change "Creado" "$VAULT_INIT"
    log_change "Permisos" "$VAULT_INIT -> +x"

    log_warn "Vault NO se inicia automaticamente"
    log_info "Para usar: systemctl start securizar-vault && securizar-vault-init.sh --init"
else
    log_skip "Gestion de secretos con HashiCorp Vault"
fi

# ============================================================
# S3: ROTACION AUTOMATICA DE CREDENCIALES
# ============================================================
log_section "S3: Rotacion automatica de credenciales"

log_info "Framework de rotacion de credenciales:"
log_info "  - Rotacion de SSH host keys"
log_info "  - Deteccion de certificados expirando"
log_info "  - Rotacion de passwords de bases de datos"
log_info "  - Rotacion de cuentas de servicio"
log_info ""

if check_executable "/usr/local/bin/rotar-credenciales.sh"; then
    log_already "Rotacion credenciales (rotar-credenciales.sh ya instalado)"
elif ask "¿Configurar rotacion automatica de credenciales?"; then

    mkdir -p /var/log/securizar

    # ── Politica de rotacion ───────────────────────────────────
    ROT_POLICY="/etc/securizar/rotation-policy.conf"
    if [[ -f "$ROT_POLICY" ]]; then
        cp -a "$ROT_POLICY" "$BACKUP_DIR/"
        log_change "Backup" "$ROT_POLICY"
    fi

    cat > "$ROT_POLICY" << 'EOFROTPOL'
# ============================================================
# Politica de rotacion de credenciales - securizar Modulo 51
# ============================================================

# SSH host keys - dias
SSH_HOST_KEY_ROTATION_DAYS=180

# Certificados - dias antes de expiracion
CERT_ALERT_DAYS_BEFORE=30
CERT_CRITICAL_DAYS_BEFORE=7

# Passwords de bases de datos - dias
DB_PASSWORD_ROTATION_DAYS=90

# Cuentas de servicio - dias
SERVICE_ACCOUNT_PASSWORD_DAYS=90

# Longitud de passwords generados
GENERATED_PASSWORD_LENGTH=32

# Log de rotacion
ROTATION_LOG=/var/log/securizar/credential-rotation.log

# Modulos habilitados
ROTATE_SSH_KEYS=yes
ROTATE_CERTIFICATES=yes
ROTATE_DB_PASSWORDS=yes
ROTATE_SERVICE_ACCOUNTS=yes
EOFROTPOL
    chmod 0640 "$ROT_POLICY"
    log_change "Creado" "$ROT_POLICY"

    # ── Script principal de rotacion ───────────────────────────
    ROT_TOOL="/usr/local/bin/rotar-credenciales.sh"
    if [[ -f "$ROT_TOOL" ]]; then
        cp -a "$ROT_TOOL" "$BACKUP_DIR/"
        log_change "Backup" "$ROT_TOOL existente"
    fi

    cat > "$ROT_TOOL" << 'EOFROTAR'
#!/bin/bash
# ============================================================
# Rotacion de credenciales - securizar Modulo 51
# ============================================================
# Uso: rotar-credenciales.sh [--ssh-keys] [--certs] [--db]
#      [--service] [--all] [--dry-run]
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

POLICY_FILE="/etc/securizar/rotation-policy.conf"
ROTATION_LOG="/var/log/securizar/credential-rotation.log"
DRY_RUN=0; DO_SSH=0; DO_CERTS=0; DO_DB=0; DO_SERVICE=0
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# Cargar politica
[[ -f "$POLICY_FILE" ]] && source "$POLICY_FILE"
SSH_HOST_KEY_ROTATION_DAYS="${SSH_HOST_KEY_ROTATION_DAYS:-180}"
CERT_ALERT_DAYS_BEFORE="${CERT_ALERT_DAYS_BEFORE:-30}"
CERT_CRITICAL_DAYS_BEFORE="${CERT_CRITICAL_DAYS_BEFORE:-7}"
DB_PASSWORD_ROTATION_DAYS="${DB_PASSWORD_ROTATION_DAYS:-90}"
SERVICE_ACCOUNT_PASSWORD_DAYS="${SERVICE_ACCOUNT_PASSWORD_DAYS:-90}"
GENERATED_PASSWORD_LENGTH="${GENERATED_PASSWORD_LENGTH:-32}"

mkdir -p /var/log/securizar /root/credential-rotation-backups

log_rotation() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$msg" >> "$ROTATION_LOG"
    echo -e "$msg"
}

generate_password() {
    local len="${1:-$GENERATED_PASSWORD_LENGTH}"
    openssl rand -base64 "$((len * 2))" 2>/dev/null | tr -dc 'A-Za-z0-9!@#$%^&*()-_=+' | head -c "$len"
}

usage() {
    echo -e "${BOLD}Uso: $0 [OPCIONES]${NC}"
    echo "  --ssh-keys   Rotar SSH host keys"
    echo "  --certs      Verificar certificados expirando"
    echo "  --db         Rotar passwords de bases de datos"
    echo "  --service    Auditar cuentas de servicio"
    echo "  --all        Todo lo anterior"
    echo "  --dry-run    Sin cambios reales"
    echo "  -h, --help   Ayuda"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ssh-keys) DO_SSH=1; shift ;;
        --certs)    DO_CERTS=1; shift ;;
        --db)       DO_DB=1; shift ;;
        --service)  DO_SERVICE=1; shift ;;
        --all)      DO_SSH=1; DO_CERTS=1; DO_DB=1; DO_SERVICE=1; shift ;;
        --dry-run)  DRY_RUN=1; shift ;;
        -h|--help)  usage; exit 0 ;;
        *)          echo "Opcion desconocida: $1"; usage; exit 1 ;;
    esac
done

if [[ $DO_SSH -eq 0 && $DO_CERTS -eq 0 && $DO_DB -eq 0 && $DO_SERVICE -eq 0 ]]; then
    usage; exit 1
fi

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  ROTACION DE CREDENCIALES${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
[[ $DRY_RUN -eq 1 ]] && echo -e "${YELLOW}MODO DRY-RUN${NC}"
echo ""
log_rotation "=== Inicio (dry_run=$DRY_RUN) ==="

# ── SSH host keys ──────────────────────────────────────────
if [[ $DO_SSH -eq 1 ]]; then
    echo -e "${CYAN}── SSH Host Keys ──${NC}"
    log_rotation "--- SSH Host Keys ---"
    needs_restart=0
    for keytype in ed25519 ecdsa rsa; do
        keyfile="/etc/ssh/ssh_host_${keytype}_key"
        [[ -f "$keyfile" ]] || continue
        key_age=$(( ($(date +%s) - $(stat -c %Y "$keyfile")) / 86400 ))
        if [[ $key_age -gt $SSH_HOST_KEY_ROTATION_DAYS ]]; then
            echo -e "  ${YELLOW}!!${NC} ssh_host_${keytype}_key: ${key_age}d (limite: ${SSH_HOST_KEY_ROTATION_DAYS}d)"
            if [[ $DRY_RUN -eq 0 ]]; then
                bkdir="/root/credential-rotation-backups/ssh-${TIMESTAMP}"
                mkdir -p "$bkdir"
                cp -a "$keyfile" "${bkdir}/"
                cp -a "${keyfile}.pub" "${bkdir}/" 2>/dev/null || true
                log_rotation "Backup: ${keyfile} -> ${bkdir}/"
                rm -f "$keyfile" "${keyfile}.pub"
                case "$keytype" in
                    ed25519) ssh-keygen -t ed25519 -f "$keyfile" -N "" -q ;;
                    ecdsa)   ssh-keygen -t ecdsa -b 521 -f "$keyfile" -N "" -q ;;
                    rsa)     ssh-keygen -t rsa -b 4096 -f "$keyfile" -N "" -q ;;
                esac
                chmod 0600 "$keyfile"
                chmod 0644 "${keyfile}.pub" 2>/dev/null || true
                log_rotation "Rotada: ssh_host_${keytype}_key (edad: ${key_age}d)"
                echo -e "  ${GREEN}OK${NC} ssh_host_${keytype}_key rotada"
                needs_restart=1
            else
                echo -e "  ${YELLOW}DRY-RUN${NC} Se rotaria ssh_host_${keytype}_key"
            fi
        else
            echo -e "  ${GREEN}OK${NC} ssh_host_${keytype}_key: ${key_age}d (OK)"
        fi
    done
    [[ $needs_restart -eq 1 ]] && echo -e "  ${YELLOW}!!${NC} Reinicia sshd para aplicar nuevas claves"
fi

# ── Certificados ───────────────────────────────────────────
if [[ $DO_CERTS -eq 1 ]]; then
    echo -e "\n${CYAN}── Certificados SSL/TLS ──${NC}"
    log_rotation "--- Certificados ---"
    cert_dirs=(/etc/ssl/certs /etc/pki/tls/certs /etc/letsencrypt/live /etc/ssl/private)
    certs_found=0; certs_expiring=0; certs_critical=0
    for cdir in "${cert_dirs[@]}"; do
        [[ -d "$cdir" ]] || continue
        while IFS= read -r cf; do
            [[ -f "$cf" ]] || continue
            head -1 "$cf" 2>/dev/null | grep -q "BEGIN CERTIFICATE" || continue
            ((certs_found++)) || true
            exp_date=$(openssl x509 -enddate -noout -in "$cf" 2>/dev/null | cut -d= -f2) || continue
            [[ -z "$exp_date" ]] && continue
            exp_epoch=$(date -d "$exp_date" +%s 2>/dev/null || echo "0")
            days_left=$(( (exp_epoch - $(date +%s)) / 86400 ))
            subj=$(openssl x509 -subject -noout -in "$cf" 2>/dev/null | sed 's/subject=//' | head -c 50) || true
            if [[ $days_left -lt 0 ]]; then
                echo -e "  ${RED}EXPIRADO${NC} ${cf}: hace $((days_left * -1))d"
                log_rotation "EXPIRADO: ${cf}"; ((certs_critical++)) || true
            elif [[ $days_left -lt $CERT_CRITICAL_DAYS_BEFORE ]]; then
                echo -e "  ${RED}CRITICO${NC} ${cf}: ${days_left}d restantes"
                log_rotation "CRITICO: ${cf} (${days_left}d)"; ((certs_critical++)) || true
            elif [[ $days_left -lt $CERT_ALERT_DAYS_BEFORE ]]; then
                echo -e "  ${YELLOW}ALERTA${NC} ${cf}: ${days_left}d restantes"
                log_rotation "ALERTA: ${cf} (${days_left}d)"; ((certs_expiring++)) || true
            fi
        done < <(find "$cdir" -maxdepth 2 \( -name "*.pem" -o -name "*.crt" \) 2>/dev/null)
    done
    echo -e "  Verificados: ${certs_found} | Expirando: ${certs_expiring} | Criticos: ${certs_critical}"
fi

# ── Passwords de bases de datos ────────────────────────────
if [[ $DO_DB -eq 1 ]]; then
    echo -e "\n${CYAN}── Passwords de bases de datos ──${NC}"
    log_rotation "--- Passwords DB ---"
    if command -v psql &>/dev/null || [[ -d /var/lib/pgsql ]] || [[ -d /var/lib/postgresql ]]; then
        echo -e "  ${CYAN}PostgreSQL detectado${NC}"
        new_pass=$(generate_password)
        echo -e "  ${YELLOW}!!${NC} Para rotar: sudo -u postgres psql -c \"ALTER USER postgres PASSWORD 'PASS';\""
        log_rotation "PostgreSQL: rotacion manual requerida"
    fi
    if command -v mysql &>/dev/null || command -v mariadb &>/dev/null; then
        echo -e "  ${CYAN}MySQL/MariaDB detectado${NC}"
        echo -e "  ${YELLOW}!!${NC} Para rotar: mysql -u root -p -e \"ALTER USER 'root'@'localhost' IDENTIFIED BY 'PASS';\""
        log_rotation "MySQL: rotacion manual requerida"
    fi
    if ! command -v psql &>/dev/null && ! command -v mysql &>/dev/null && ! command -v mariadb &>/dev/null; then
        echo -e "  ${GREEN}OK${NC} No se detectaron bases de datos"
    fi
fi

# ── Cuentas de servicio ────────────────────────────────────
if [[ $DO_SERVICE -eq 1 ]]; then
    echo -e "\n${CYAN}── Cuentas de servicio ──${NC}"
    log_rotation "--- Cuentas de servicio ---"
    svc_accts=()
    while IFS=: read -r user _ uid _ _ _ shell; do
        [[ -z "$user" || "$user" == "root" ]] && continue
        [[ $uid -ge 1000 ]] && continue
        case "$shell" in */nologin|*/false|"") continue ;; esac
        svc_accts+=("$user")
    done < /etc/passwd
    if [[ ${#svc_accts[@]} -eq 0 ]]; then
        echo -e "  ${GREEN}OK${NC} No hay cuentas de servicio con login activo"
    else
        for acct in "${svc_accts[@]}"; do
            last_chg=$(chage -l "$acct" 2>/dev/null | grep "Last password change" | cut -d: -f2 | xargs) || true
            echo -e "  - ${acct} (ultimo cambio: ${last_chg:-desconocido})"
            if [[ -n "$last_chg" && "$last_chg" != "never" && "$last_chg" != "password must be changed" ]]; then
                chg_epoch=$(date -d "$last_chg" +%s 2>/dev/null || echo "0")
                days_since=$(( ($(date +%s) - chg_epoch) / 86400 ))
                if [[ $days_since -gt $SERVICE_ACCOUNT_PASSWORD_DAYS ]]; then
                    echo -e "    ${YELLOW}Hace ${days_since}d - considerar rotacion${NC}"
                    log_rotation "Servicio ${acct}: password ${days_since}d"
                fi
            fi
        done
    fi
fi

log_rotation "=== Fin rotacion ==="
echo -e "\n${BOLD}Log: ${ROTATION_LOG}${NC}"
EOFROTAR
    chmod +x "$ROT_TOOL"
    log_change "Creado" "$ROT_TOOL"
    log_change "Permisos" "$ROT_TOOL -> +x"

    # ── Cron semanal ───────────────────────────────────────────
    CRON_ROT="/etc/cron.weekly/rotar-credenciales"
    if [[ -f "$CRON_ROT" ]]; then
        cp -a "$CRON_ROT" "$BACKUP_DIR/"
        log_change "Backup" "$CRON_ROT"
    fi
    cat > "$CRON_ROT" << 'EOFCRONROT'
#!/bin/bash
# Verificacion semanal de credenciales - securizar Modulo 51
/usr/local/bin/rotar-credenciales.sh --certs --service >> /var/log/securizar/credential-rotation.log 2>&1
EOFCRONROT
    chmod +x "$CRON_ROT"
    log_change "Creado" "$CRON_ROT"

    log_info "Framework de rotacion configurado"
    log_info "Ejecuta: rotar-credenciales.sh --all --dry-run"
else
    log_skip "Rotacion automatica de credenciales"
fi

# ============================================================
# S4: PROTECCION DE VARIABLES DE ENTORNO
# ============================================================
log_section "S4: Proteccion de variables de entorno"

log_info "Audita secretos en variables de entorno:"
log_info "  - Escanea /proc/*/environ para secretos en procesos"
log_info "  - Verifica .bashrc, .bash_profile, .profile"
log_info "  - Verifica Environment= en servicios systemd"
log_info ""

if check_executable "/usr/local/bin/auditar-env-secrets.sh"; then
    log_already "Proteccion env (auditar-env-secrets.sh ya instalado)"
elif ask "¿Configurar proteccion de variables de entorno?"; then

    # ── Auditar procesos actuales ──────────────────────────────
    log_info "Escaneando variables de entorno de procesos..."
    env_secrets_found=0
    for proc_env in /proc/[0-9]*/environ; do
        [[ -r "$proc_env" ]] || continue
        pid=$(echo "$proc_env" | grep -oP '/proc/\K[0-9]+')
        proc_name=$(cat "/proc/$pid/comm" 2>/dev/null || echo "desconocido")
        if tr '\0' '\n' < "$proc_env" 2>/dev/null | grep -qiE '(PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)=.+'; then
            matched_vars=$(tr '\0' '\n' < "$proc_env" 2>/dev/null | grep -iE '(PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)=' | sed 's/=.*/=***/' || true)
            if [[ -n "$matched_vars" ]]; then
                log_warn "PID $pid ($proc_name): secretos en entorno"
                while IFS= read -r var; do
                    log_warn "  $var"
                done <<< "$matched_vars"
                ((env_secrets_found++)) || true
            fi
        fi
    done
    if [[ $env_secrets_found -eq 0 ]]; then
        log_info "No se encontraron secretos en variables de entorno de procesos"
    else
        log_warn "Se encontraron $env_secrets_found procesos con secretos en entorno"
    fi

    # ── Auditar archivos de perfil ─────────────────────────────
    log_info "Verificando archivos de perfil..."
    profile_secrets=0
    for user_home in /home/* /root; do
        [[ -d "$user_home" ]] || continue
        for profile_file in .bashrc .bash_profile .profile .zshrc .zprofile; do
            fpath="${user_home}/${profile_file}"
            [[ -f "$fpath" ]] || continue
            if grep -nEi '^\s*export\s+(PASSWORD|SECRET|API_KEY|TOKEN|AWS_SECRET|PRIVATE_KEY|DB_PASS)=' "$fpath" 2>/dev/null | head -5 | grep -q .; then
                log_warn "Secretos hardcodeados en ${fpath}"
                grep -nEi '^\s*export\s+(PASSWORD|SECRET|API_KEY|TOKEN|AWS_SECRET|PRIVATE_KEY|DB_PASS)=' "$fpath" 2>/dev/null | \
                    sed 's/=.*/=***/' | while IFS= read -r line; do
                    log_warn "  $line"
                done
                ((profile_secrets++)) || true
            fi
        done
    done
    if [[ $profile_secrets -eq 0 ]]; then
        log_info "No se encontraron secretos hardcodeados en archivos de perfil"
    else
        log_warn "Se encontraron secretos en $profile_secrets archivos de perfil"
    fi

    # ── Auditar servicios systemd ──────────────────────────────
    log_info "Verificando secretos en servicios systemd..."
    systemd_secrets=0
    for svc_file in /etc/systemd/system/*.service /etc/systemd/system/*/*.service /usr/lib/systemd/system/*.service; do
        [[ -f "$svc_file" ]] || continue
        if grep -qEi '^Environment=.*(PASSWORD|SECRET|API_KEY|TOKEN)=' "$svc_file" 2>/dev/null; then
            svc_name=$(basename "$svc_file")
            log_warn "Secretos en Environment= de ${svc_name}"
            log_info "  Recomendacion: Usa EnvironmentFile= con permisos 0600"
            ((systemd_secrets++)) || true
        fi
    done
    if [[ $systemd_secrets -eq 0 ]]; then
        log_info "No se encontraron secretos en Environment= de systemd"
    else
        log_warn "Se encontraron $systemd_secrets servicios con secretos en Environment="
    fi

    # ── Crear script de auditoria ──────────────────────────────
    ENV_AUDIT="/usr/local/bin/auditar-env-secrets.sh"
    if [[ -f "$ENV_AUDIT" ]]; then
        cp -a "$ENV_AUDIT" "$BACKUP_DIR/"
        log_change "Backup" "$ENV_AUDIT existente"
    fi

    cat > "$ENV_AUDIT" << 'EOFENVAUDIT'
#!/bin/bash
# ============================================================
# auditar-env-secrets.sh - Auditoria de secretos en entorno
# Generado por securizar - Modulo 51
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  AUDITORIA DE SECRETOS EN ENTORNO${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

TOTAL_ISSUES=0
PATTERNS='(PASSWORD|PASSWD|SECRET|API_KEY|APIKEY|TOKEN|ACCESS_KEY|PRIVATE_KEY|DB_PASS|MYSQL_PWD|PGPASSWORD|AWS_SECRET)'

# 1. Procesos
echo -e "${CYAN}── 1. Variables de entorno en procesos ──${NC}"
proc_issues=0
for proc_env in /proc/[0-9]*/environ; do
    [[ -r "$proc_env" ]] || continue
    pid=$(echo "$proc_env" | grep -oP '/proc/\K[0-9]+')
    proc_name=$(cat "/proc/$pid/comm" 2>/dev/null || echo "?")
    matched=$(tr '\0' '\n' < "$proc_env" 2>/dev/null | grep -iE "^${PATTERNS}=" | sed 's/=.*/=***/' || true)
    if [[ -n "$matched" ]]; then
        echo -e "  ${YELLOW}!!${NC} PID ${pid} (${proc_name}):"
        while IFS= read -r var; do echo -e "    ${var}"; done <<< "$matched"
        ((proc_issues++)) || true
    fi
done
[[ $proc_issues -eq 0 ]] && echo -e "  ${GREEN}OK${NC} Sin secretos en procesos"
((TOTAL_ISSUES += proc_issues)) || true

# 2. Archivos de perfil
echo -e "\n${CYAN}── 2. Archivos de perfil ──${NC}"
profile_issues=0
for user_home in /home/* /root; do
    [[ -d "$user_home" ]] || continue
    for prof in .bashrc .bash_profile .profile .zshrc .zprofile; do
        fpath="${user_home}/${prof}"
        [[ -f "$fpath" ]] || continue
        results=$(grep -nEi "^\s*export\s+${PATTERNS}=" "$fpath" 2>/dev/null | sed 's/=.*/=***/' || true)
        if [[ -n "$results" ]]; then
            echo -e "  ${YELLOW}!!${NC} ${fpath}:"
            while IFS= read -r line; do echo -e "    ${line}"; done <<< "$results"
            ((profile_issues++)) || true
        fi
    done
done
[[ $profile_issues -eq 0 ]] && echo -e "  ${GREEN}OK${NC} Sin secretos en perfiles"
((TOTAL_ISSUES += profile_issues)) || true

# 3. Servicios systemd
echo -e "\n${CYAN}── 3. Servicios systemd ──${NC}"
svc_issues=0
for svc_file in /etc/systemd/system/*.service /etc/systemd/system/*/*.service /usr/lib/systemd/system/*.service; do
    [[ -f "$svc_file" ]] || continue
    results=$(grep -nEi "^Environment=.*${PATTERNS}=" "$svc_file" 2>/dev/null | sed 's/=.*/=***/' || true)
    if [[ -n "$results" ]]; then
        echo -e "  ${YELLOW}!!${NC} $(basename "$svc_file"):"
        while IFS= read -r line; do echo -e "    ${line}"; done <<< "$results"
        echo -e "    ${CYAN}Recomendacion: Usa EnvironmentFile= con chmod 0600${NC}"
        ((svc_issues++)) || true
    fi
done
[[ $svc_issues -eq 0 ]] && echo -e "  ${GREEN}OK${NC} Sin secretos en systemd"
((TOTAL_ISSUES += svc_issues)) || true

# 4. Cron jobs
echo -e "\n${CYAN}── 4. Cron jobs ──${NC}"
cron_issues=0
for crondir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron/crontabs; do
    [[ -d "$crondir" ]] || continue
    for cronfile in "${crondir}"/*; do
        [[ -f "$cronfile" ]] || continue
        results=$(grep -nEi "${PATTERNS}=" "$cronfile" 2>/dev/null | sed 's/=.*/=***/' || true)
        if [[ -n "$results" ]]; then
            echo -e "  ${YELLOW}!!${NC} ${cronfile}:"
            while IFS= read -r line; do echo -e "    ${line}"; done <<< "$results"
            ((cron_issues++)) || true
        fi
    done
done
[[ $cron_issues -eq 0 ]] && echo -e "  ${GREEN}OK${NC} Sin secretos en cron"
((TOTAL_ISSUES += cron_issues)) || true

# Resumen
echo ""
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "  Total problemas: ${BOLD}${TOTAL_ISSUES}${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
if [[ $TOTAL_ISSUES -gt 0 ]]; then
    echo -e "\n${YELLOW}Recomendaciones:${NC}"
    echo "  1. Usa un gestor de secretos (Vault, pass, SOPS)"
    echo "  2. Usa EnvironmentFile= en systemd con permisos 0600"
    echo "  3. Nunca exportes secretos en .bashrc/.profile"
fi
echo -e "\n${BOLD}Completado: $(date)${NC}"
EOFENVAUDIT
    chmod +x "$ENV_AUDIT"
    log_change "Creado" "$ENV_AUDIT"
    log_change "Permisos" "$ENV_AUDIT -> +x"

    log_info "Proteccion de variables de entorno configurada"
    log_info "Ejecuta: auditar-env-secrets.sh"
else
    log_skip "Proteccion de variables de entorno"
fi

# ============================================================
# S5: GESTION SEGURA DE SSH KEYS
# ============================================================
log_section "S5: Gestion segura de SSH keys"

log_info "Audita y refuerza la gestion de claves SSH:"
log_info "  - Audita claves en /home/*/.ssh/ y /root/.ssh/"
log_info "  - Verifica tipos, tamanos y proteccion de passphrase"
log_info "  - Verifica authorized_keys y agent forwarding"
log_info "  - Ofrece reemplazar claves debiles por ed25519"
log_info ""

if check_executable "/usr/local/bin/auditar-ssh-keys.sh"; then
    log_already "SSH keys (auditar-ssh-keys.sh ya instalado)"
elif ask "¿Configurar gestion segura de SSH keys?"; then

    # ── Auditar todas las claves SSH ───────────────────────────
    log_info "Auditando claves SSH del sistema..."
    weak_keys=0
    no_passphrase=0
    total_keys=0

    for user_home in /root /home/*; do
        [[ -d "${user_home}/.ssh" ]] || continue
        user=$(basename "$user_home")

        for key_file in "${user_home}/.ssh"/id_*; do
            [[ -f "$key_file" ]] || continue
            [[ "$key_file" == *.pub ]] && continue
            ((total_keys++)) || true

            key_type="desconocido"
            key_bits="?"
            if [[ -f "${key_file}.pub" ]]; then
                key_info=$(ssh-keygen -l -f "${key_file}.pub" 2>/dev/null || echo "? ? ? ?")
                key_bits=$(echo "$key_info" | awk '{print $1}')
                key_type=$(echo "$key_info" | awk '{print $NF}' | tr -d '()')
            fi

            # Verificar tipo y tamano
            is_weak=0
            case "$key_type" in
                DSA)
                    log_warn "  Usuario $user: ${key_file} - DSA (INSEGURO, obsoleto)"
                    is_weak=1; ((weak_keys++)) || true
                    ;;
                RSA)
                    if [[ "$key_bits" -lt 2048 ]] 2>/dev/null; then
                        log_warn "  Usuario $user: ${key_file} - RSA ${key_bits} bits (minimo 2048)"
                        is_weak=1; ((weak_keys++)) || true
                    elif [[ "$key_bits" -lt 4096 ]] 2>/dev/null; then
                        log_info "  Usuario $user: ${key_file} - RSA ${key_bits} bits (recomendado 4096)"
                    else
                        log_info "  Usuario $user: ${key_file} - RSA ${key_bits} bits (OK)"
                    fi
                    ;;
                ED25519|ECDSA)
                    log_info "  Usuario $user: ${key_file} - ${key_type} ${key_bits} bits (OK)"
                    ;;
                *)
                    log_warn "  Usuario $user: ${key_file} - tipo desconocido: ${key_type}"
                    ;;
            esac

            # Verificar passphrase (intentar leer sin passphrase)
            if ssh-keygen -y -P "" -f "$key_file" &>/dev/null; then
                log_warn "  ${key_file} - SIN passphrase"
                ((no_passphrase++)) || true
            fi

            # Verificar permisos
            key_perms=$(stat -c '%a' "$key_file" 2>/dev/null || echo "???")
            if [[ "$key_perms" != "600" && "$key_perms" != "400" ]]; then
                log_warn "  ${key_file} - permisos inseguros: $key_perms (deberia ser 600)"
            fi
        done

        # ── Verificar authorized_keys ──────────────────────────
        auth_keys="${user_home}/.ssh/authorized_keys"
        if [[ -f "$auth_keys" ]]; then
            auth_perms=$(stat -c '%a' "$auth_keys" 2>/dev/null || echo "???")
            if [[ "$auth_perms" != "600" && "$auth_perms" != "644" && "$auth_perms" != "400" ]]; then
                log_warn "  ${auth_keys} - permisos inseguros: $auth_perms"
            fi

            # Verificar entradas overly permissive
            if grep -q 'no-port-forwarding\|no-agent-forwarding\|no-X11-forwarding' "$auth_keys" 2>/dev/null; then
                log_info "  ${auth_keys} - tiene restricciones (bien)"
            fi

            # Contar entradas
            auth_count=$(grep -cE '^(ssh-|ecdsa-)' "$auth_keys" 2>/dev/null || echo "0")
            log_info "  ${auth_keys} - ${auth_count} clave(s) autorizadas"

            # Buscar entradas con from="*" (overly permissive)
            if grep -q 'from="\*"' "$auth_keys" 2>/dev/null; then
                log_warn "  ${auth_keys} - contiene from=\"*\" (sin restriccion de origen)"
            fi
        fi
    done

    log_info "Claves SSH auditadas: $total_keys total, $weak_keys debiles, $no_passphrase sin passphrase"

    # ── Verificar SSH agent forwarding ─────────────────────────
    log_info "Verificando configuracion de SSH agent forwarding..."
    sshd_config="/etc/ssh/sshd_config"
    if [[ -f "$sshd_config" ]]; then
        if grep -qE '^\s*AllowAgentForwarding\s+yes' "$sshd_config" 2>/dev/null; then
            log_warn "SSH agent forwarding esta habilitado en sshd_config"
            log_info "Recomendacion: Deshabilitar si no es necesario (AllowAgentForwarding no)"
        else
            log_info "SSH agent forwarding: deshabilitado o no explicitamente habilitado"
        fi
    fi

    # ── Ofrecer reemplazar claves debiles ──────────────────────
    if [[ $weak_keys -gt 0 ]]; then
        if ask "¿Generar claves ed25519 para reemplazar claves debiles?"; then
            for user_home in /root /home/*; do
                [[ -d "${user_home}/.ssh" ]] || continue
                user=$(basename "$user_home")

                for key_file in "${user_home}/.ssh"/id_*; do
                    [[ -f "$key_file" ]] || continue
                    [[ "$key_file" == *.pub ]] && continue

                    key_type="unknown"
                    if [[ -f "${key_file}.pub" ]]; then
                        key_type=$(ssh-keygen -l -f "${key_file}.pub" 2>/dev/null | awk '{print $NF}' | tr -d '()') || true
                    fi

                    needs_replace=0
                    case "$key_type" in
                        DSA) needs_replace=1 ;;
                        RSA)
                            bits=$(ssh-keygen -l -f "${key_file}.pub" 2>/dev/null | awk '{print $1}') || true
                            [[ "$bits" -lt 2048 ]] 2>/dev/null && needs_replace=1
                            ;;
                    esac

                    if [[ $needs_replace -eq 1 ]]; then
                        # Backup
                        backup_ts=$(date +%Y%m%d-%H%M%S)
                        cp -a "$key_file" "${key_file}.weak-backup-${backup_ts}"
                        [[ -f "${key_file}.pub" ]] && cp -a "${key_file}.pub" "${key_file}.pub.weak-backup-${backup_ts}"
                        log_change "Backup" "${key_file} -> ${key_file}.weak-backup-${backup_ts}"

                        # Generar nueva clave ed25519
                        new_key="${user_home}/.ssh/id_ed25519"
                        if [[ ! -f "$new_key" ]]; then
                            ssh-keygen -t ed25519 -f "$new_key" -N "" -C "${user}@$(hostname)-$(date +%Y%m%d)" -q
                            if [[ "$user" != "root" ]]; then
                                chown "${user}:${user}" "$new_key" "${new_key}.pub" 2>/dev/null || true
                            fi
                            chmod 0600 "$new_key"
                            log_change "Creado" "${new_key} (ed25519 para reemplazar ${key_type})"
                            log_info "  Nueva clave ed25519 generada para $user"
                        else
                            log_info "  ${new_key} ya existe, no se sobreescribe"
                        fi
                    fi
                done
            done
        else
            log_skip "Generacion de claves ed25519"
        fi
    fi

    # ── Crear script de auditoria de SSH keys ──────────────────
    SSH_AUDIT="/usr/local/bin/auditar-ssh-keys.sh"
    if [[ -f "$SSH_AUDIT" ]]; then
        cp -a "$SSH_AUDIT" "$BACKUP_DIR/"
        log_change "Backup" "$SSH_AUDIT existente"
    fi

    cat > "$SSH_AUDIT" << 'EOFSSHAUDIT'
#!/bin/bash
# ============================================================
# auditar-ssh-keys.sh - Auditoria de claves SSH
# Generado por securizar - Modulo 51
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  AUDITORIA DE CLAVES SSH${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

total_keys=0; weak_keys=0; no_pass=0; bad_perms=0

# 1. Claves de usuario
echo -e "${CYAN}── 1. Claves SSH de usuarios ──${NC}"
for user_home in /root /home/*; do
    [[ -d "${user_home}/.ssh" ]] || continue
    user=$(basename "$user_home")

    for kf in "${user_home}/.ssh"/id_*; do
        [[ -f "$kf" && "$kf" != *.pub ]] || continue
        ((total_keys++)) || true

        ktype="?"; kbits="?"
        if [[ -f "${kf}.pub" ]]; then
            kinfo=$(ssh-keygen -l -f "${kf}.pub" 2>/dev/null || echo "? ? ? ?")
            kbits=$(echo "$kinfo" | awk '{print $1}')
            ktype=$(echo "$kinfo" | awk '{print $NF}' | tr -d '()')
        fi

        status="${GREEN}OK${NC}"
        notes=""
        case "$ktype" in
            DSA) status="${RED}INSEGURO${NC}"; notes="DSA obsoleto"; ((weak_keys++)) || true ;;
            RSA)
                if [[ "$kbits" -lt 2048 ]] 2>/dev/null; then
                    status="${RED}DEBIL${NC}"; notes="RSA <2048"; ((weak_keys++)) || true
                elif [[ "$kbits" -lt 4096 ]] 2>/dev/null; then
                    status="${YELLOW}ACEPTABLE${NC}"; notes="RSA ${kbits} (rec. 4096)"
                else
                    notes="RSA ${kbits}"
                fi
                ;;
            ED25519) notes="ed25519 (moderno)" ;;
            ECDSA) notes="ECDSA ${kbits}" ;;
        esac

        # Passphrase
        if ssh-keygen -y -P "" -f "$kf" &>/dev/null; then
            notes="${notes}, SIN passphrase"
            ((no_pass++)) || true
        fi

        # Permisos
        kperms=$(stat -c '%a' "$kf" 2>/dev/null || echo "???")
        if [[ "$kperms" != "600" && "$kperms" != "400" ]]; then
            notes="${notes}, perms=$kperms"
            ((bad_perms++)) || true
        fi

        echo -e "  [${status}] ${user}: $(basename "$kf") - ${notes}"
    done

    # authorized_keys
    akf="${user_home}/.ssh/authorized_keys"
    if [[ -f "$akf" ]]; then
        acount=$(grep -cE '^(ssh-|ecdsa-)' "$akf" 2>/dev/null || echo "0")
        aperms=$(stat -c '%a' "$akf" 2>/dev/null || echo "???")
        echo -e "  ${DIM}${user}: authorized_keys (${acount} claves, perms=${aperms})${NC}"
    fi
done

# 2. Host keys
echo -e "\n${CYAN}── 2. Host keys (/etc/ssh/) ──${NC}"
for hk in /etc/ssh/ssh_host_*_key; do
    [[ -f "$hk" ]] || continue
    hktype=$(echo "$hk" | grep -oP 'ssh_host_\K[^_]+')
    hkage=$(( ($(date +%s) - $(stat -c %Y "$hk")) / 86400 ))
    hkperms=$(stat -c '%a' "$hk" 2>/dev/null || echo "???")
    if [[ -f "${hk}.pub" ]]; then
        hkbits=$(ssh-keygen -l -f "${hk}.pub" 2>/dev/null | awk '{print $1}') || true
    else
        hkbits="?"
    fi
    echo -e "  ${hktype}: ${hkbits} bits, edad ${hkage}d, perms=${hkperms}"
done

# 3. Configuracion sshd
echo -e "\n${CYAN}── 3. Configuracion SSH ──${NC}"
sshd_cfg="/etc/ssh/sshd_config"
if [[ -f "$sshd_cfg" ]]; then
    agent_fwd=$(grep -iE '^\s*AllowAgentForwarding' "$sshd_cfg" 2>/dev/null | tail -1 || echo "no explicito")
    pubkey_auth=$(grep -iE '^\s*PubkeyAuthentication' "$sshd_cfg" 2>/dev/null | tail -1 || echo "no explicito")
    pass_auth=$(grep -iE '^\s*PasswordAuthentication' "$sshd_cfg" 2>/dev/null | tail -1 || echo "no explicito")
    echo -e "  Agent forwarding: ${agent_fwd}"
    echo -e "  Pubkey auth:      ${pubkey_auth}"
    echo -e "  Password auth:    ${pass_auth}"
fi

# Resumen
echo ""
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "  Total claves: ${BOLD}${total_keys}${NC}"
echo -e "  Debiles:      ${weak_keys}"
echo -e "  Sin passphrase: ${no_pass}"
echo -e "  Permisos malos: ${bad_perms}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"

if [[ $weak_keys -gt 0 || $no_pass -gt 0 ]]; then
    echo -e "\n${YELLOW}Recomendaciones:${NC}"
    [[ $weak_keys -gt 0 ]] && echo "  - Reemplazar claves debiles por ed25519: ssh-keygen -t ed25519"
    [[ $no_pass -gt 0 ]] && echo "  - Agregar passphrase: ssh-keygen -p -f CLAVE"
    [[ $bad_perms -gt 0 ]] && echo "  - Corregir permisos: chmod 600 CLAVE"
fi
echo -e "\n${BOLD}Completado: $(date)${NC}"
EOFSSHAUDIT
    chmod +x "$SSH_AUDIT"
    log_change "Creado" "$SSH_AUDIT"
    log_change "Permisos" "$SSH_AUDIT -> +x"

    log_info "Gestion segura de SSH keys configurada"
    log_info "Ejecuta: auditar-ssh-keys.sh"
else
    log_skip "Gestion segura de SSH keys"
fi

# ============================================================
# S6: CIFRADO DE SECRETOS EN REPOSO
# ============================================================
log_section "S6: Cifrado de secretos en reposo"

log_info "Cifrado de archivos sensibles con age/gpg:"
log_info "  - Detecta archivos .env y configs con passwords sin cifrar"
log_info "  - Crea herramienta de cifrado /usr/local/bin/cifrar-secretos.sh"
log_info "  - Usa age (preferido) o gpg como fallback"
log_info "  - Configura clave age en /etc/securizar/secrets-key.txt"
log_info ""

if check_executable "/usr/local/bin/cifrar-secretos.sh"; then
    log_already "Cifrado secretos (cifrar-secretos.sh ya instalado)"
elif ask "¿Configurar cifrado de secretos en reposo?"; then

    # ── Detectar herramientas de cifrado ───────────────────────
    HAS_AGE=0
    HAS_GPG=0

    if command -v age &>/dev/null; then
        HAS_AGE=1
        log_info "age ya instalado: $(age --version 2>&1 | head -1 || echo 'version desconocida')"
    fi

    if command -v gpg &>/dev/null || command -v gpg2 &>/dev/null; then
        HAS_GPG=1
        log_info "gpg disponible"
    fi

    if [[ $HAS_AGE -eq 0 ]]; then
        log_warn "age no esta instalado"
        if ask "¿Intentar instalar age?"; then
            case "$DISTRO_FAMILY" in
                debian) DEBIAN_FRONTEND=noninteractive apt-get install -y age 2>/dev/null && HAS_AGE=1 || true ;;
                rhel)   dnf install -y age 2>/dev/null && HAS_AGE=1 || true ;;
                suse)   zypper --non-interactive install age 2>/dev/null && HAS_AGE=1 || true ;;
                arch)   pacman -S --noconfirm age 2>/dev/null && HAS_AGE=1 || true ;;
            esac
            if [[ $HAS_AGE -eq 1 ]]; then
                log_change "Instalado" "age (cifrado moderno)"
            else
                log_warn "No se pudo instalar age. Se usara gpg como fallback."
            fi
        else
            log_skip "Instalacion de age"
        fi
    fi

    # ── Configurar clave age ───────────────────────────────────
    AGE_KEY_FILE="/etc/securizar/secrets-key.txt"
    if [[ $HAS_AGE -eq 1 ]]; then
        if [[ ! -f "$AGE_KEY_FILE" ]]; then
            log_info "Generando clave age..."
            age-keygen -o "$AGE_KEY_FILE" 2>/dev/null || true
            if [[ -f "$AGE_KEY_FILE" ]]; then
                chmod 0400 "$AGE_KEY_FILE"
                chown root:root "$AGE_KEY_FILE"
                log_change "Creado" "$AGE_KEY_FILE (clave age, permisos 0400)"
                AGE_PUBKEY=$(grep "public key:" "$AGE_KEY_FILE" 2>/dev/null | awk '{print $NF}')
                log_info "Clave publica age: $AGE_PUBKEY"
            fi
        else
            log_info "Clave age ya existe: $AGE_KEY_FILE"
            AGE_PUBKEY=$(grep "public key:" "$AGE_KEY_FILE" 2>/dev/null | awk '{print $NF}')
        fi
    fi

    # ── Detectar archivos sin cifrar ───────────────────────────
    log_info "Buscando archivos con secretos sin cifrar..."
    unencrypted_found=0

    for search_dir in /etc /opt /home; do
        [[ -d "$search_dir" ]] || continue
        # Buscar .env files
        while IFS= read -r envf; do
            [[ -z "$envf" || ! -f "$envf" ]] && continue
            if grep -qEi '(password|secret|key|token)=' "$envf" 2>/dev/null; then
                log_warn "Archivo sin cifrar con secretos: $envf"
                ((unencrypted_found++)) || true
            fi
        done < <(find "$search_dir" -maxdepth 3 \( -name ".env" -o -name ".env.*" \) \
            -not -name "*.example" -not -name "*.enc" 2>/dev/null || true)
    done

    if [[ $unencrypted_found -eq 0 ]]; then
        log_info "No se encontraron archivos .env sin cifrar con secretos"
    else
        log_warn "Se encontraron $unencrypted_found archivos sin cifrar con secretos"
    fi

    # ── Crear herramienta de cifrado ───────────────────────────
    ENCRYPT_TOOL="/usr/local/bin/cifrar-secretos.sh"
    if [[ -f "$ENCRYPT_TOOL" ]]; then
        cp -a "$ENCRYPT_TOOL" "$BACKUP_DIR/"
        log_change "Backup" "$ENCRYPT_TOOL existente"
    fi

    cat > "$ENCRYPT_TOOL" << 'EOFENCRYPT'
#!/bin/bash
# ============================================================
# cifrar-secretos.sh - Cifrado de archivos sensibles
# Generado por securizar - Modulo 51
# ============================================================
# Uso: cifrar-secretos.sh encrypt ARCHIVO [ARCHIVO2...]
#      cifrar-secretos.sh decrypt ARCHIVO.enc [ARCHIVO2.enc...]
#      cifrar-secretos.sh scan DIRECTORIO
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

AGE_KEY="/etc/securizar/secrets-key.txt"
ENCRYPT_BACKEND=""

# Detectar backend
if command -v age &>/dev/null && [[ -f "$AGE_KEY" ]]; then
    ENCRYPT_BACKEND="age"
    AGE_PUBKEY=$(grep "public key:" "$AGE_KEY" 2>/dev/null | awk '{print $NF}')
elif command -v gpg &>/dev/null || command -v gpg2 &>/dev/null; then
    ENCRYPT_BACKEND="gpg"
    GPG_CMD=$(command -v gpg2 2>/dev/null || command -v gpg 2>/dev/null)
else
    echo -e "${RED}Error: No se encontro age ni gpg${NC}"
    exit 1
fi

usage() {
    echo -e "${BOLD}Uso: $0 COMANDO ARCHIVOS...${NC}"
    echo ""
    echo "  encrypt ARCHIVO...     Cifrar archivos (genera .enc)"
    echo "  decrypt ARCHIVO.enc... Descifrar archivos"
    echo "  scan DIRECTORIO        Buscar archivos sin cifrar con secretos"
    echo ""
    echo -e "Backend: ${BOLD}${ENCRYPT_BACKEND}${NC}"
}

do_encrypt() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        echo -e "  ${RED}Error: $file no existe${NC}"; return 1
    fi
    local outfile="${file}.enc"

    case "$ENCRYPT_BACKEND" in
        age)
            if age -r "$AGE_PUBKEY" -o "$outfile" "$file" 2>/dev/null; then
                chmod 0600 "$outfile"
                echo -e "  ${GREEN}OK${NC} ${file} -> ${outfile} (age)"
                # Borrar original de forma segura
                if command -v shred &>/dev/null; then
                    shred -u "$file" 2>/dev/null || rm -f "$file"
                else
                    rm -f "$file"
                fi
                echo -e "  ${GREEN}OK${NC} Original eliminado: ${file}"
            else
                echo -e "  ${RED}Error cifrando: $file${NC}"; return 1
            fi
            ;;
        gpg)
            if $GPG_CMD --batch --yes --symmetric --cipher-algo AES256 \
                    --output "$outfile" "$file" 2>/dev/null; then
                chmod 0600 "$outfile"
                echo -e "  ${GREEN}OK${NC} ${file} -> ${outfile} (gpg)"
                if command -v shred &>/dev/null; then
                    shred -u "$file" 2>/dev/null || rm -f "$file"
                else
                    rm -f "$file"
                fi
                echo -e "  ${GREEN}OK${NC} Original eliminado: ${file}"
            else
                echo -e "  ${RED}Error cifrando: $file${NC}"; return 1
            fi
            ;;
    esac
}

do_decrypt() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        echo -e "  ${RED}Error: $file no existe${NC}"; return 1
    fi
    local outfile="${file%.enc}"
    if [[ "$outfile" == "$file" ]]; then
        outfile="${file}.dec"
    fi

    case "$ENCRYPT_BACKEND" in
        age)
            if age -d -i "$AGE_KEY" -o "$outfile" "$file" 2>/dev/null; then
                chmod 0600 "$outfile"
                echo -e "  ${GREEN}OK${NC} ${file} -> ${outfile} (age)"
            else
                echo -e "  ${RED}Error descifrando: $file${NC}"; return 1
            fi
            ;;
        gpg)
            if $GPG_CMD --batch --yes --decrypt --output "$outfile" "$file" 2>/dev/null; then
                chmod 0600 "$outfile"
                echo -e "  ${GREEN}OK${NC} ${file} -> ${outfile} (gpg)"
            else
                echo -e "  ${RED}Error descifrando: $file${NC}"; return 1
            fi
            ;;
    esac
}

do_scan() {
    local scan_dir="$1"
    echo -e "${CYAN}Escaneando ${scan_dir} por archivos sin cifrar con secretos...${NC}"
    local found=0
    while IFS= read -r f; do
        [[ -z "$f" || ! -f "$f" ]] && continue
        if grep -qEi '(password|secret|api_key|token|private_key)=' "$f" 2>/dev/null; then
            echo -e "  ${YELLOW}!!${NC} $f"
            ((found++)) || true
        fi
    done < <(find "$scan_dir" -maxdepth 4 -type f \
        \( -name "*.env" -o -name ".env" -o -name ".env.*" -o -name "*.conf" \
           -o -name "*.cfg" -o -name "*.ini" -o -name "*.properties" \) \
        -not -name "*.enc" -not -name "*.gpg" -not -name "*.age" \
        -not -path "*/.git/*" 2>/dev/null || true)
    if [[ $found -eq 0 ]]; then
        echo -e "  ${GREEN}OK${NC} No se encontraron archivos sin cifrar con secretos"
    else
        echo -e "  ${YELLOW}${found} archivos encontrados sin cifrar${NC}"
    fi
}

case "${1:-}" in
    encrypt)
        shift
        [[ $# -eq 0 ]] && { echo "Especifica archivos a cifrar"; exit 1; }
        echo -e "${BOLD}Cifrando archivos (backend: ${ENCRYPT_BACKEND})...${NC}"
        for f in "$@"; do do_encrypt "$f"; done
        ;;
    decrypt)
        shift
        [[ $# -eq 0 ]] && { echo "Especifica archivos a descifrar"; exit 1; }
        echo -e "${BOLD}Descifrando archivos (backend: ${ENCRYPT_BACKEND})...${NC}"
        for f in "$@"; do do_decrypt "$f"; done
        ;;
    scan)
        do_scan "${2:-.}"
        ;;
    -h|--help|"")
        usage
        ;;
    *)
        echo "Comando desconocido: $1"; usage; exit 1
        ;;
esac
EOFENCRYPT
    chmod +x "$ENCRYPT_TOOL"
    log_change "Creado" "$ENCRYPT_TOOL"
    log_change "Permisos" "$ENCRYPT_TOOL -> +x"

    log_info "Cifrado de secretos en reposo configurado"
    log_info "Ejecuta: cifrar-secretos.sh encrypt ARCHIVO"
    log_info "Ejecuta: cifrar-secretos.sh scan /etc"
else
    log_skip "Cifrado de secretos en reposo"
fi

# ============================================================
# S7: INTEGRACION CON GESTORES DE PAQUETES DE SECRETOS
# ============================================================
log_section "S7: Integracion con gestores de paquetes de secretos"

log_info "Detecta y configura gestores de secretos:"
log_info "  - pass (standard unix password manager)"
log_info "  - gopass (pass compatible con extensiones)"
log_info "  - SOPS (Secrets OPerationS para YAML/JSON)"
log_info "  - Crea script de inicializacion de pass"
log_info ""

if check_executable "/usr/local/bin/securizar-pass-init.sh"; then
    log_already "Gestores secretos (securizar-pass-init.sh ya instalado)"
elif ask "¿Configurar integracion con gestores de secretos?"; then

    # ── Detectar herramientas existentes ───────────────────────
    HAS_PASS=0; HAS_GOPASS=0; HAS_SOPS=0

    if command -v pass &>/dev/null; then
        HAS_PASS=1
        log_info "pass instalado: $(pass version 2>&1 | head -1 || echo 'version desconocida')"
    else
        log_info "pass no detectado"
        if ask "¿Instalar pass (standard unix password manager)?"; then
            case "$DISTRO_FAMILY" in
                debian) DEBIAN_FRONTEND=noninteractive apt-get install -y pass 2>/dev/null && HAS_PASS=1 || true ;;
                rhel)   dnf install -y pass 2>/dev/null && HAS_PASS=1 || true ;;
                suse)   zypper --non-interactive install password-store 2>/dev/null && HAS_PASS=1 || true ;;
                arch)   pacman -S --noconfirm pass 2>/dev/null && HAS_PASS=1 || true ;;
            esac
            [[ $HAS_PASS -eq 1 ]] && log_change "Instalado" "pass (password manager)" || log_warn "No se pudo instalar pass"
        else
            log_skip "Instalacion de pass"
        fi
    fi

    if command -v gopass &>/dev/null; then
        HAS_GOPASS=1
        log_info "gopass instalado: $(gopass version 2>&1 | head -1 || echo 'version desconocida')"
    else
        log_info "gopass no detectado"
    fi

    if command -v sops &>/dev/null; then
        HAS_SOPS=1
        log_info "sops instalado: $(sops --version 2>&1 || echo 'version desconocida')"
    else
        log_info "sops no detectado"
        if ask "¿Descargar sops desde GitHub releases?"; then
            SOPS_VERSION="3.8.1"
            SOPS_ARCH="amd64"
            [[ "$(uname -m)" == "aarch64" ]] && SOPS_ARCH="arm64"
            SOPS_URL="https://github.com/getsops/sops/releases/download/v${SOPS_VERSION}/sops-v${SOPS_VERSION}.linux.${SOPS_ARCH}"

            dl_ok=0
            if command -v curl &>/dev/null; then
                curl -fsSL "$SOPS_URL" -o /usr/local/bin/sops 2>/dev/null && dl_ok=1 || true
            elif command -v wget &>/dev/null; then
                wget -q "$SOPS_URL" -O /usr/local/bin/sops 2>/dev/null && dl_ok=1 || true
            fi
            if [[ $dl_ok -eq 1 ]] && [[ -f /usr/local/bin/sops ]]; then
                chmod +x /usr/local/bin/sops
                HAS_SOPS=1
                log_change "Instalado" "sops v${SOPS_VERSION} en /usr/local/bin/sops"
            else
                log_warn "No se pudo descargar sops"
            fi
        else
            log_skip "Descarga de sops"
        fi
    fi

    # ── Crear script de inicializacion de pass ─────────────────
    PASS_INIT="/usr/local/bin/securizar-pass-init.sh"
    if [[ -f "$PASS_INIT" ]]; then
        cp -a "$PASS_INIT" "$BACKUP_DIR/"
        log_change "Backup" "$PASS_INIT existente"
    fi

    cat > "$PASS_INIT" << 'EOFPASSINIT'
#!/bin/bash
# ============================================================
# securizar-pass-init.sh - Inicializar password store
# Generado por securizar - Modulo 51
# ============================================================
# Uso: securizar-pass-init.sh [--generate-gpg-key] [--init]
#      securizar-pass-init.sh --import-key KEYFILE
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

GPG_CMD=$(command -v gpg2 2>/dev/null || command -v gpg 2>/dev/null || echo "")

if [[ -z "$GPG_CMD" ]]; then
    echo -e "${RED}Error: gpg no instalado${NC}"; exit 1
fi

if ! command -v pass &>/dev/null; then
    echo -e "${RED}Error: pass no instalado${NC}"; exit 1
fi

usage() {
    echo -e "${BOLD}Uso: $0 [OPCION]${NC}"
    echo "  --generate-gpg-key   Generar nueva clave GPG para pass"
    echo "  --init               Inicializar password store con clave existente"
    echo "  --import-key FILE    Importar clave GPG desde archivo"
    echo "  --status             Mostrar estado de pass"
    echo "  -h, --help           Ayuda"
}

generate_gpg_key() {
    echo -e "${BOLD}── Generando clave GPG ──${NC}"
    local gpg_name="securizar-secrets"
    local gpg_email="securizar@$(hostname)"

    # Generar clave batch
    local batch_file
    batch_file=$(mktemp)
    cat > "$batch_file" << EOFBATCH
%no-protection
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
Name-Real: ${gpg_name}
Name-Email: ${gpg_email}
Expire-Date: 2y
%commit
EOFBATCH

    if $GPG_CMD --batch --gen-key "$batch_file" 2>/dev/null; then
        rm -f "$batch_file"
        local gpg_id
        gpg_id=$($GPG_CMD --list-keys --keyid-format long "$gpg_email" 2>/dev/null | grep "^pub" | head -1 | awk -F'/' '{print $2}' | awk '{print $1}')
        echo -e "${GREEN}Clave GPG generada: ${gpg_id}${NC}"
        echo -e "${CYAN}Email: ${gpg_email}${NC}"
        echo "$gpg_id"
    else
        rm -f "$batch_file"
        echo -e "${RED}Error generando clave GPG${NC}"; return 1
    fi
}

init_pass() {
    echo -e "${BOLD}── Inicializando password store ──${NC}"
    local gpg_id="${1:-}"

    if [[ -z "$gpg_id" ]]; then
        # Buscar clave GPG existente
        gpg_id=$($GPG_CMD --list-secret-keys --keyid-format long 2>/dev/null | grep "^sec" | head -1 | awk -F'/' '{print $2}' | awk '{print $1}')
    fi

    if [[ -z "$gpg_id" ]]; then
        echo -e "${YELLOW}No se encontro clave GPG. Genera una primero con --generate-gpg-key${NC}"
        return 1
    fi

    echo -e "${CYAN}Usando clave GPG: ${gpg_id}${NC}"
    if pass init "$gpg_id" 2>/dev/null; then
        echo -e "${GREEN}Password store inicializado${NC}"
        echo -e "${CYAN}Usa 'pass insert nombre/secreto' para agregar secretos${NC}"
    else
        echo -e "${RED}Error inicializando pass${NC}"; return 1
    fi
}

pass_status() {
    echo -e "${BOLD}── Estado de password store ──${NC}"
    if [[ -d "${PASSWORD_STORE_DIR:-$HOME/.password-store}" ]]; then
        local store_dir="${PASSWORD_STORE_DIR:-$HOME/.password-store}"
        local count
        count=$(find "$store_dir" -name "*.gpg" 2>/dev/null | wc -l)
        echo -e "  Directorio: ${store_dir}"
        echo -e "  Secretos almacenados: ${count}"
        local gpg_id_file="${store_dir}/.gpg-id"
        if [[ -f "$gpg_id_file" ]]; then
            echo -e "  GPG ID: $(cat "$gpg_id_file")"
        fi
    else
        echo -e "  ${YELLOW}Password store no inicializado${NC}"
    fi
}

case "${1:-}" in
    --generate-gpg-key)
        gpg_id=$(generate_gpg_key)
        if [[ -n "$gpg_id" ]]; then
            echo -e "\n${CYAN}Ahora ejecuta: $0 --init${NC}"
        fi
        ;;
    --init)
        init_pass "${2:-}"
        ;;
    --import-key)
        if [[ -z "${2:-}" ]]; then echo "Especifica archivo de clave"; exit 1; fi
        $GPG_CMD --import "$2" 2>/dev/null && echo -e "${GREEN}Clave importada${NC}" || echo -e "${RED}Error importando${NC}"
        ;;
    --status)
        pass_status
        ;;
    -h|--help|"")
        usage
        ;;
    *)
        echo "Opcion desconocida: $1"; usage; exit 1
        ;;
esac
EOFPASSINIT
    chmod +x "$PASS_INIT"
    log_change "Creado" "$PASS_INIT"
    log_change "Permisos" "$PASS_INIT -> +x"

    # ── Resumen de herramientas disponibles ────────────────────
    log_info "Herramientas de gestion de secretos detectadas:"
    [[ $HAS_PASS -eq 1 ]] && log_info "  - pass: DISPONIBLE" || log_info "  - pass: no instalado"
    [[ $HAS_GOPASS -eq 1 ]] && log_info "  - gopass: DISPONIBLE" || log_info "  - gopass: no instalado"
    [[ $HAS_SOPS -eq 1 ]] && log_info "  - sops: DISPONIBLE" || log_info "  - sops: no instalado"

    log_info "Ejecuta: securizar-pass-init.sh --generate-gpg-key && securizar-pass-init.sh --init"
else
    log_skip "Integracion con gestores de paquetes de secretos"
fi

# ============================================================
# S8: POLITICAS DE SECRETOS
# ============================================================
log_section "S8: Politicas de secretos"

log_info "Configura politicas de gestion de secretos:"
log_info "  - Crea /etc/securizar/secrets-policy.conf"
log_info "  - Longitud minima, caracteres especiales, edad maxima"
log_info "  - Tipos de clave permitidos, patrones prohibidos"
log_info "  - Crea validador /usr/local/bin/validar-politica-secretos.sh"
log_info ""

if check_executable "/usr/local/bin/validar-politica-secretos.sh"; then
    log_already "Politicas secretos (validar-politica-secretos.sh ya instalado)"
elif ask "¿Configurar politicas de secretos?"; then

    # ── Archivo de politicas ───────────────────────────────────
    SEC_POLICY="/etc/securizar/secrets-policy.conf"
    if [[ -f "$SEC_POLICY" ]]; then
        cp -a "$SEC_POLICY" "$BACKUP_DIR/"
        log_change "Backup" "$SEC_POLICY"
    fi

    cat > "$SEC_POLICY" << 'EOFSECPOL'
# ============================================================
# Politica de gestion de secretos - securizar Modulo 51
# ============================================================

# === Requisitos de passwords/secretos ===
MIN_PASSWORD_LENGTH=16
REQUIRE_SPECIAL_CHARS=yes
REQUIRE_UPPERCASE=yes
REQUIRE_LOWERCASE=yes
REQUIRE_DIGITS=yes

# === Edades maximas (dias) ===
MAX_KEY_AGE_DAYS=90
MAX_CERT_AGE_DAYS=365
MAX_DB_PASSWORD_AGE_DAYS=90
MAX_SERVICE_TOKEN_AGE_DAYS=30

# === Tipos de clave SSH permitidos ===
ALLOWED_KEY_TYPES="ed25519 ecdsa rsa4096"

# === Permisos de archivos de secretos ===
MAX_SECRET_FILE_PERMS=0600
REQUIRED_SECRET_OWNER=root

# === Patrones prohibidos (passwords debiles comunes) ===
BANNED_PATTERNS="password
123456
qwerty
admin
root
letmein
welcome
monkey
dragon
master
changeme
trustno1
abc123
password1
Pa\$\$w0rd"

# === Auditoria ===
AUDIT_SECRET_ACCESS=yes
SCAN_FREQUENCY=weekly
AUDIT_LOG_RETENTION_DAYS=365

# === Almacenamiento ===
REQUIRE_ENCRYPTED_STORAGE=yes
FORBID_PLAINTEXT_SECRETS=yes

# === Cumplimiento ===
COMPLIANCE_FRAMEWORK=CIS
MIN_COMPLIANCE_SCORE=70
EOFSECPOL
    chmod 0640 "$SEC_POLICY"
    log_change "Creado" "$SEC_POLICY"

    # ── Crear validador de politica ────────────────────────────
    POL_VALIDATOR="/usr/local/bin/validar-politica-secretos.sh"
    if [[ -f "$POL_VALIDATOR" ]]; then
        cp -a "$POL_VALIDATOR" "$BACKUP_DIR/"
        log_change "Backup" "$POL_VALIDATOR existente"
    fi

    cat > "$POL_VALIDATOR" << 'EOFVALIDATOR'
#!/bin/bash
# ============================================================
# validar-politica-secretos.sh - Valida estado vs politica
# Generado por securizar - Modulo 51
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

POLICY_FILE="/etc/securizar/secrets-policy.conf"
if [[ ! -f "$POLICY_FILE" ]]; then
    echo -e "${RED}Error: Politica no encontrada: ${POLICY_FILE}${NC}"; exit 1
fi

# Cargar politica
source "$POLICY_FILE"
MIN_PASSWORD_LENGTH="${MIN_PASSWORD_LENGTH:-16}"
MAX_KEY_AGE_DAYS="${MAX_KEY_AGE_DAYS:-90}"
MAX_CERT_AGE_DAYS="${MAX_CERT_AGE_DAYS:-365}"
ALLOWED_KEY_TYPES="${ALLOWED_KEY_TYPES:-ed25519 ecdsa rsa4096}"
MAX_SECRET_FILE_PERMS="${MAX_SECRET_FILE_PERMS:-0600}"

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  VALIDACION DE POLITICA DE SECRETOS${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

score=0; total=0; issues=()

check_pass() { ((total++)) || true; ((score++)) || true; echo -e "  ${GREEN}[OK]${NC} $1"; }
check_fail() { ((total++)) || true; echo -e "  ${RED}[XX]${NC} $1"; issues+=("$1"); }
check_warn() { ((total++)) || true; echo -e "  ${YELLOW}[!!]${NC} $1"; issues+=("$1"); }

# 1. Claves SSH
echo -e "${CYAN}── 1. Claves SSH ──${NC}"
for user_home in /root /home/*; do
    [[ -d "${user_home}/.ssh" ]] || continue
    user=$(basename "$user_home")
    for kf in "${user_home}/.ssh"/id_*; do
        [[ -f "$kf" && "$kf" != *.pub ]] || continue
        ktype="?"; kbits="?"
        if [[ -f "${kf}.pub" ]]; then
            ki=$(ssh-keygen -l -f "${kf}.pub" 2>/dev/null || echo "? ? ? ?")
            kbits=$(echo "$ki" | awk '{print $1}')
            ktype=$(echo "$ki" | awk '{print $NF}' | tr -d '()')
        fi

        # Verificar tipo permitido
        type_ok=0
        for at in $ALLOWED_KEY_TYPES; do
            case "$at" in
                ed25519) [[ "$ktype" == "ED25519" ]] && type_ok=1 ;;
                ecdsa)   [[ "$ktype" == "ECDSA" ]] && type_ok=1 ;;
                rsa4096) [[ "$ktype" == "RSA" && "$kbits" -ge 4096 ]] 2>/dev/null && type_ok=1 ;;
                rsa)     [[ "$ktype" == "RSA" && "$kbits" -ge 2048 ]] 2>/dev/null && type_ok=1 ;;
            esac
        done
        if [[ $type_ok -eq 1 ]]; then
            check_pass "${user}: $(basename "$kf") - ${ktype} ${kbits}bits (tipo permitido)"
        else
            check_fail "${user}: $(basename "$kf") - ${ktype} ${kbits}bits (tipo NO permitido)"
        fi

        # Verificar edad
        kage=$(( ($(date +%s) - $(stat -c %Y "$kf")) / 86400 ))
        if [[ $kage -le $MAX_KEY_AGE_DAYS ]]; then
            check_pass "${user}: $(basename "$kf") - edad ${kage}d (max ${MAX_KEY_AGE_DAYS}d)"
        else
            check_fail "${user}: $(basename "$kf") - edad ${kage}d EXCEDE max ${MAX_KEY_AGE_DAYS}d"
        fi

        # Verificar permisos
        kperms=$(stat -c '%a' "$kf" 2>/dev/null || echo "777")
        max_p="${MAX_SECRET_FILE_PERMS#0}"
        if [[ "$kperms" -le "$max_p" ]] 2>/dev/null; then
            check_pass "${user}: $(basename "$kf") - permisos $kperms (max ${MAX_SECRET_FILE_PERMS})"
        else
            check_fail "${user}: $(basename "$kf") - permisos $kperms EXCEDE max ${MAX_SECRET_FILE_PERMS}"
        fi
    done
done

# 2. Certificados
echo -e "\n${CYAN}── 2. Certificados ──${NC}"
cert_dirs=(/etc/ssl/certs /etc/pki/tls/certs /etc/letsencrypt/live)
certs_checked=0
for cdir in "${cert_dirs[@]}"; do
    [[ -d "$cdir" ]] || continue
    while IFS= read -r cf; do
        [[ -f "$cf" ]] || continue
        head -1 "$cf" 2>/dev/null | grep -q "BEGIN CERTIFICATE" || continue
        exp_date=$(openssl x509 -enddate -noout -in "$cf" 2>/dev/null | cut -d= -f2) || continue
        [[ -z "$exp_date" ]] && continue
        exp_epoch=$(date -d "$exp_date" +%s 2>/dev/null || echo "0")
        days_left=$(( (exp_epoch - $(date +%s)) / 86400 ))
        ((certs_checked++)) || true

        if [[ $days_left -lt 0 ]]; then
            check_fail "Cert EXPIRADO: $cf"
        elif [[ $days_left -lt 30 ]]; then
            check_warn "Cert expira en ${days_left}d: $cf"
        else
            check_pass "Cert OK (${days_left}d restantes): $(basename "$cf")"
        fi
    done < <(find "$cdir" -maxdepth 2 \( -name "*.pem" -o -name "*.crt" \) 2>/dev/null | head -20)
done
[[ $certs_checked -eq 0 ]] && echo -e "  ${DIM}No se encontraron certificados para validar${NC}"

# 3. Archivos sensibles sin cifrar
echo -e "\n${CYAN}── 3. Archivos sin cifrar ──${NC}"
unencrypted=0
for sd in /etc /opt /home; do
    [[ -d "$sd" ]] || continue
    while IFS= read -r ef; do
        [[ -z "$ef" || ! -f "$ef" ]] && continue
        if grep -qEi '(password|secret|api_key|token)=' "$ef" 2>/dev/null; then
            ((unencrypted++)) || true
        fi
    done < <(find "$sd" -maxdepth 3 \( -name ".env" -o -name ".env.*" \) -not -name "*.enc" -not -name "*.example" 2>/dev/null || true)
done
if [[ $unencrypted -eq 0 ]]; then
    check_pass "No hay archivos .env sin cifrar con secretos"
else
    check_fail "${unencrypted} archivos .env sin cifrar con secretos"
fi

# 4. Secretos en entorno
echo -e "\n${CYAN}── 4. Secretos en variables de entorno ──${NC}"
env_procs=0
for pe in /proc/[0-9]*/environ; do
    [[ -r "$pe" ]] || continue
    if tr '\0' '\n' < "$pe" 2>/dev/null | grep -qiE '(PASSWORD|SECRET|API_KEY|TOKEN)=.+' 2>/dev/null; then
        ((env_procs++)) || true
    fi
done
if [[ $env_procs -eq 0 ]]; then
    check_pass "No hay procesos con secretos en entorno"
else
    check_warn "${env_procs} procesos con secretos en entorno"
fi

# 5. Secretos en systemd
echo -e "\n${CYAN}── 5. Secretos en servicios systemd ──${NC}"
sd_issues=0
for sf in /etc/systemd/system/*.service /usr/lib/systemd/system/*.service; do
    [[ -f "$sf" ]] || continue
    if grep -qEi '^Environment=.*(PASSWORD|SECRET|API_KEY|TOKEN)=' "$sf" 2>/dev/null; then
        ((sd_issues++)) || true
    fi
done
if [[ $sd_issues -eq 0 ]]; then
    check_pass "No hay secretos inline en servicios systemd"
else
    check_fail "${sd_issues} servicios con secretos en Environment="
fi

# 6. Herramientas de cifrado
echo -e "\n${CYAN}── 6. Herramientas disponibles ──${NC}"
command -v age &>/dev/null && check_pass "age disponible" || check_warn "age no instalado"
(command -v gpg &>/dev/null || command -v gpg2 &>/dev/null) && check_pass "gpg disponible" || check_warn "gpg no instalado"
command -v pass &>/dev/null && check_pass "pass disponible" || echo -e "  ${DIM}pass no instalado${NC}"

# ── Resumen ────────────────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════════════════════════════${NC}"
pct=0
[[ $total -gt 0 ]] && pct=$((score * 100 / total))
if [[ $pct -ge 80 ]]; then
    echo -e "${GREEN}${BOLD}  PUNTUACION: ${score}/${total} (${pct}%) - BUENO${NC}"
elif [[ $pct -ge 50 ]]; then
    echo -e "${YELLOW}${BOLD}  PUNTUACION: ${score}/${total} (${pct}%) - MEJORABLE${NC}"
else
    echo -e "${RED}${BOLD}  PUNTUACION: ${score}/${total} (${pct}%) - DEFICIENTE${NC}"
fi
echo -e "${BOLD}══════════════════════════════════════════${NC}"

if [[ ${#issues[@]} -gt 0 ]]; then
    echo -e "\n${YELLOW}Problemas detectados:${NC}"
    for iss in "${issues[@]}"; do echo -e "  - $iss"; done
fi

echo -e "\n${BOLD}Completado: $(date)${NC}"
EOFVALIDATOR
    chmod +x "$POL_VALIDATOR"
    log_change "Creado" "$POL_VALIDATOR"
    log_change "Permisos" "$POL_VALIDATOR -> +x"

    log_info "Politicas de secretos configuradas"
    log_info "Ejecuta: validar-politica-secretos.sh"
else
    log_skip "Politicas de secretos"
fi

# ============================================================
# S9: MONITORIZACION DE ACCESO A SECRETOS
# ============================================================
log_section "S9: Monitorizacion de acceso a secretos"

log_info "Configura monitorizacion de acceso a archivos sensibles:"
log_info "  - Reglas auditd para /etc/shadow, /etc/ssl/private, SSH keys"
log_info "  - Vigila rutas de vault si esta instalado"
log_info "  - Crea analizador de logs de acceso"
log_info ""

if check_executable "/usr/local/bin/monitorizar-acceso-secretos.sh"; then
    log_already "Monitorizacion secretos (monitorizar-acceso-secretos.sh ya instalado)"
elif ask "¿Configurar monitorizacion de acceso a secretos?"; then

    # ── Reglas auditd ──────────────────────────────────────────
    if command -v auditctl &>/dev/null; then
        log_info "Configurando reglas auditd para archivos de secretos..."

        AUDIT_RULES_FILE="/etc/audit/rules.d/securizar-secrets.rules"
        if [[ -f "$AUDIT_RULES_FILE" ]]; then
            cp -a "$AUDIT_RULES_FILE" "$BACKUP_DIR/"
            log_change "Backup" "$AUDIT_RULES_FILE"
        fi

        mkdir -p /etc/audit/rules.d

        cat > "$AUDIT_RULES_FILE" << 'EOFAUDITRULES'
## ============================================================
## Reglas auditd para monitorizacion de secretos
## Generado por securizar Modulo 51
## ============================================================

## Acceso a /etc/shadow
-w /etc/shadow -p rwa -k secrets_shadow
-w /etc/gshadow -p rwa -k secrets_shadow

## Acceso a claves SSL/TLS privadas
-w /etc/ssl/private/ -p rwa -k secrets_tls
-w /etc/pki/tls/private/ -p rwa -k secrets_tls

## Acceso a claves SSH
-w /etc/ssh/ssh_host_ed25519_key -p rwa -k secrets_ssh_host
-w /etc/ssh/ssh_host_ecdsa_key -p rwa -k secrets_ssh_host
-w /etc/ssh/ssh_host_rsa_key -p rwa -k secrets_ssh_host

## Acceso a authorized_keys
-w /root/.ssh/authorized_keys -p rwa -k secrets_auth_keys

## Acceso a configuracion de securizar
-w /etc/securizar/ -p rwa -k secrets_securizar

## Vault (si instalado)
-w /var/lib/securizar/vault/ -p rwa -k secrets_vault
-w /etc/securizar/vault/ -p rwa -k secrets_vault_config

## Archivos de credenciales de bases de datos
-w /root/.pgpass -p rwa -k secrets_db
-w /root/.my.cnf -p rwa -k secrets_db
-w /root/.mongorc.js -p rwa -k secrets_db

## Password store
-w /root/.password-store/ -p rwa -k secrets_pass_store

## Age key file
-w /etc/securizar/secrets-key.txt -p rwa -k secrets_age_key
EOFAUDITRULES
        chmod 0640 "$AUDIT_RULES_FILE"
        log_change "Creado" "$AUDIT_RULES_FILE"

        # Cargar reglas
        if augenrules --load 2>/dev/null; then
            log_change "Aplicado" "Reglas auditd para secretos cargadas"
        elif auditctl -R "$AUDIT_RULES_FILE" 2>/dev/null; then
            log_change "Aplicado" "Reglas auditd cargadas via auditctl"
        else
            log_warn "No se pudieron cargar las reglas auditd. Reinicia auditd manualmente."
        fi
    else
        log_warn "auditctl no disponible. Instala auditd para monitorizacion de acceso."
        if ask "¿Instalar auditd?"; then
            case "$DISTRO_FAMILY" in
                debian) DEBIAN_FRONTEND=noninteractive apt-get install -y auditd 2>/dev/null || true ;;
                rhel)   dnf install -y audit 2>/dev/null || true ;;
                suse)   zypper --non-interactive install audit 2>/dev/null || true ;;
                arch)   pacman -S --noconfirm audit 2>/dev/null || true ;;
            esac
            if command -v auditctl &>/dev/null; then
                log_change "Instalado" "auditd"
                log_info "Vuelve a ejecutar este modulo para configurar las reglas"
            else
                log_warn "No se pudo instalar auditd"
            fi
        else
            log_skip "Instalacion de auditd"
        fi
    fi

    # ── Crear analizador de logs de acceso ─────────────────────
    MON_TOOL="/usr/local/bin/monitorizar-acceso-secretos.sh"
    if [[ -f "$MON_TOOL" ]]; then
        cp -a "$MON_TOOL" "$BACKUP_DIR/"
        log_change "Backup" "$MON_TOOL existente"
    fi

    cat > "$MON_TOOL" << 'EOFMONITOR'
#!/bin/bash
# ============================================================
# monitorizar-acceso-secretos.sh - Analiza logs de acceso
# Generado por securizar - Modulo 51
# ============================================================
# Uso: monitorizar-acceso-secretos.sh [--last-24h] [--last-7d] [--all]
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

PERIOD="${1:---last-24h}"
ALERTS=0

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  MONITORIZACION DE ACCESO A SECRETOS${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

if ! command -v ausearch &>/dev/null; then
    echo -e "${RED}Error: ausearch no disponible. Instala auditd.${NC}"
    exit 1
fi

# Determinar parametros de busqueda
SEARCH_ARGS=""
case "$PERIOD" in
    --last-24h) SEARCH_ARGS="-ts recent"; echo -e "${CYAN}Periodo: ultimas 24 horas${NC}" ;;
    --last-7d)  SEARCH_ARGS="-ts $(date -d '7 days ago' '+%m/%d/%Y' 2>/dev/null || echo 'recent')"; echo -e "${CYAN}Periodo: ultimos 7 dias${NC}" ;;
    --all)      SEARCH_ARGS=""; echo -e "${CYAN}Periodo: todos los registros${NC}" ;;
    *)          echo "Uso: $0 [--last-24h|--last-7d|--all]"; exit 1 ;;
esac
echo ""

# ── 1. Acceso a /etc/shadow ───────────────────────────────
echo -e "${CYAN}── 1. Acceso a /etc/shadow ──${NC}"
shadow_events=$(ausearch -k secrets_shadow $SEARCH_ARGS 2>/dev/null | grep -c "^type=SYSCALL" || echo "0")
if [[ "$shadow_events" -gt 0 ]]; then
    echo -e "  ${YELLOW}!!${NC} ${shadow_events} evento(s) de acceso a /etc/shadow"
    # Mostrar usuarios que accedieron
    ausearch -k secrets_shadow $SEARCH_ARGS 2>/dev/null | grep "^type=SYSCALL" | \
        grep -oP 'uid=\K[0-9]+' | sort -u | while read -r uid; do
        uname=$(getent passwd "$uid" 2>/dev/null | cut -d: -f1 || echo "uid=$uid")
        echo -e "    Usuario: ${uname}"
    done
    ((ALERTS += shadow_events)) || true
else
    echo -e "  ${GREEN}OK${NC} Sin accesos a /etc/shadow"
fi

# ── 2. Acceso a claves TLS ────────────────────────────────
echo -e "\n${CYAN}── 2. Acceso a claves TLS privadas ──${NC}"
tls_events=$(ausearch -k secrets_tls $SEARCH_ARGS 2>/dev/null | grep -c "^type=SYSCALL" || echo "0")
if [[ "$tls_events" -gt 0 ]]; then
    echo -e "  ${YELLOW}!!${NC} ${tls_events} evento(s) de acceso a claves TLS"
    ausearch -k secrets_tls $SEARCH_ARGS 2>/dev/null | grep "^type=SYSCALL" | tail -5 | while IFS= read -r line; do
        exe=$(echo "$line" | grep -oP 'exe="\K[^"]+' || echo "?")
        echo -e "    Proceso: ${exe}"
    done
    ((ALERTS += tls_events)) || true
else
    echo -e "  ${GREEN}OK${NC} Sin accesos a claves TLS"
fi

# ── 3. Acceso a claves SSH host ───────────────────────────
echo -e "\n${CYAN}── 3. Acceso a SSH host keys ──${NC}"
ssh_events=$(ausearch -k secrets_ssh_host $SEARCH_ARGS 2>/dev/null | grep -c "^type=SYSCALL" || echo "0")
if [[ "$ssh_events" -gt 0 ]]; then
    echo -e "  ${YELLOW}!!${NC} ${ssh_events} evento(s) de acceso a SSH host keys"
    ((ALERTS += ssh_events)) || true
else
    echo -e "  ${GREEN}OK${NC} Sin accesos inusuales a SSH host keys"
fi

# ── 4. Acceso a authorized_keys ───────────────────────────
echo -e "\n${CYAN}── 4. Acceso a authorized_keys ──${NC}"
ak_events=$(ausearch -k secrets_auth_keys $SEARCH_ARGS 2>/dev/null | grep -c "^type=SYSCALL" || echo "0")
if [[ "$ak_events" -gt 0 ]]; then
    echo -e "  ${YELLOW}!!${NC} ${ak_events} evento(s) de acceso a authorized_keys"
    ((ALERTS += ak_events)) || true
else
    echo -e "  ${GREEN}OK${NC} Sin accesos a authorized_keys"
fi

# ── 5. Acceso a vault ─────────────────────────────────────
echo -e "\n${CYAN}── 5. Acceso a vault ──${NC}"
vault_events=$(ausearch -k secrets_vault $SEARCH_ARGS 2>/dev/null | grep -c "^type=SYSCALL" || echo "0")
vault_cfg_events=$(ausearch -k secrets_vault_config $SEARCH_ARGS 2>/dev/null | grep -c "^type=SYSCALL" || echo "0")
total_vault=$((vault_events + vault_cfg_events))
if [[ $total_vault -gt 0 ]]; then
    echo -e "  ${YELLOW}!!${NC} ${total_vault} evento(s) de acceso a vault (data: ${vault_events}, config: ${vault_cfg_events})"
    ((ALERTS += total_vault)) || true
else
    echo -e "  ${GREEN}OK${NC} Sin accesos a vault"
fi

# ── 6. Acceso a DB credentials ────────────────────────────
echo -e "\n${CYAN}── 6. Acceso a credenciales DB ──${NC}"
db_events=$(ausearch -k secrets_db $SEARCH_ARGS 2>/dev/null | grep -c "^type=SYSCALL" || echo "0")
if [[ "$db_events" -gt 0 ]]; then
    echo -e "  ${YELLOW}!!${NC} ${db_events} evento(s) de acceso a credenciales DB"
    ((ALERTS += db_events)) || true
else
    echo -e "  ${GREEN}OK${NC} Sin accesos a credenciales DB"
fi

# ── 7. Deteccion de acceso fuera de horario ────────────────
echo -e "\n${CYAN}── 7. Acceso fuera de horario laboral (20:00-06:00) ──${NC}"
off_hours=0
for key in secrets_shadow secrets_tls secrets_ssh_host secrets_vault; do
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        ev_time=$(echo "$line" | grep -oP 'time->\K[^ ]+' || echo "")
        if [[ -n "$ev_time" ]]; then
            hour=$(date -d "$ev_time" '+%H' 2>/dev/null || echo "12")
            if [[ "$hour" -ge 20 || "$hour" -lt 6 ]] 2>/dev/null; then
                ((off_hours++)) || true
            fi
        fi
    done < <(ausearch -k "$key" $SEARCH_ARGS 2>/dev/null | grep "^type=SYSCALL" || true)
done
if [[ $off_hours -gt 0 ]]; then
    echo -e "  ${RED}!!${NC} ${off_hours} accesos a secretos fuera de horario laboral"
    ((ALERTS += off_hours)) || true
else
    echo -e "  ${GREEN}OK${NC} Sin accesos fuera de horario"
fi

# ── Resumen ────────────────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════════════════════════════${NC}"
if [[ $ALERTS -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}  Sin alertas de acceso a secretos${NC}"
else
    echo -e "${YELLOW}${BOLD}  ${ALERTS} evento(s) de acceso detectados${NC}"
fi
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "\n${BOLD}Completado: $(date)${NC}"
EOFMONITOR
    chmod +x "$MON_TOOL"
    log_change "Creado" "$MON_TOOL"
    log_change "Permisos" "$MON_TOOL -> +x"

    log_info "Monitorizacion de acceso a secretos configurada"
    log_info "Ejecuta: monitorizar-acceso-secretos.sh --last-24h"
else
    log_skip "Monitorizacion de acceso a secretos"
fi

# ============================================================
# S10: AUDITORIA INTEGRAL DE GESTION DE SECRETOS
# ============================================================
log_section "S10: Auditoria integral de gestion de secretos"

log_info "Crea herramienta de auditoria completa:"
log_info "  - Verifica estado de todas las secciones"
log_info "  - Busca secretos en git history, Docker, cron"
log_info "  - Verifica expiracion de certificados"
log_info "  - Genera informe con puntuacion BUENO/MEJORABLE/DEFICIENTE"
log_info ""

if check_executable "/usr/local/bin/auditoria-secrets.sh"; then
    log_already "Auditoria secretos (auditoria-secrets.sh ya instalado)"
elif ask "¿Crear auditoria integral de gestion de secretos?"; then

    AUDIT_TOOL="/usr/local/bin/auditoria-secrets.sh"
    if [[ -f "$AUDIT_TOOL" ]]; then
        cp -a "$AUDIT_TOOL" "$BACKUP_DIR/"
        log_change "Backup" "$AUDIT_TOOL existente"
    fi

    cat > "$AUDIT_TOOL" << 'EOFAUDIT'
#!/bin/bash
# ============================================================
# auditoria-secrets.sh - Auditoria integral de secretos
# Generado por securizar - Modulo 51
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

LOG_DIR="/var/log/securizar"
mkdir -p "$LOG_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT_FILE="${LOG_DIR}/auditoria-secrets-${TIMESTAMP}.log"

score=0; total=0; issues=()

check_pass() { ((total++)) || true; ((score++)) || true; echo -e "  ${GREEN}[OK]${NC} $1"; echo "[OK] $1" >> "$REPORT_FILE"; }
check_fail() { ((total++)) || true; echo -e "  ${RED}[XX]${NC} $1"; echo "[FAIL] $1" >> "$REPORT_FILE"; issues+=("$1"); }
check_warn() { ((total++)) || true; echo -e "  ${YELLOW}[!!]${NC} $1"; echo "[WARN] $1" >> "$REPORT_FILE"; issues+=("$1"); }

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  AUDITORIA INTEGRAL DE SECRETOS${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""
echo -e "${CYAN}Informe: ${REPORT_FILE}${NC}"
echo ""

{
    echo "============================================================"
    echo "AUDITORIA INTEGRAL DE GESTION DE SECRETOS"
    echo "Fecha: $(date)"
    echo "Host: $(hostname)"
    echo "============================================================"
    echo ""
} > "$REPORT_FILE"

# ── 1. Herramientas de escaneo ─────────────────────────────
echo -e "${CYAN}── 1. Herramientas de escaneo de secretos ──${NC}"
echo "=== Herramientas ===" >> "$REPORT_FILE"
(command -v gitleaks &>/dev/null || command -v trufflehog &>/dev/null) && \
    check_pass "Scanner de secretos disponible (gitleaks/trufflehog)" || \
    check_warn "No hay scanner de secretos instalado"
[[ -f /etc/securizar/secrets-patterns.conf ]] && \
    check_pass "Patrones de deteccion configurados" || \
    check_fail "Patrones de deteccion no configurados"
[[ -x /usr/local/bin/escanear-secretos.sh ]] && \
    check_pass "escanear-secretos.sh disponible" || \
    check_warn "escanear-secretos.sh no instalado"

# ── 2. Vault ───────────────────────────────────────────────
echo -e "\n${CYAN}── 2. HashiCorp Vault ──${NC}"
echo "=== Vault ===" >> "$REPORT_FILE"
if command -v vault &>/dev/null; then
    check_pass "Vault instalado"
    if vault status 2>/dev/null | grep -q "Sealed.*false"; then
        check_pass "Vault desellado y operativo"
    elif vault status 2>/dev/null | grep -q "Sealed.*true"; then
        check_warn "Vault sellado (necesita desellado)"
    else
        check_warn "Vault no accesible"
    fi
else
    check_warn "Vault no instalado"
fi

# ── 3. Rotacion de credenciales ────────────────────────────
echo -e "\n${CYAN}── 3. Rotacion de credenciales ──${NC}"
echo "=== Rotacion ===" >> "$REPORT_FILE"
[[ -f /etc/securizar/rotation-policy.conf ]] && \
    check_pass "Politica de rotacion configurada" || \
    check_fail "Sin politica de rotacion"
[[ -x /usr/local/bin/rotar-credenciales.sh ]] && \
    check_pass "rotar-credenciales.sh disponible" || \
    check_warn "rotar-credenciales.sh no instalado"
# Verificar host keys
for kt in ed25519 ecdsa rsa; do
    kf="/etc/ssh/ssh_host_${kt}_key"
    [[ -f "$kf" ]] || continue
    kage=$(( ($(date +%s) - $(stat -c %Y "$kf")) / 86400 ))
    if [[ $kage -le 180 ]]; then
        check_pass "SSH host key ${kt}: ${kage}d (OK)"
    else
        check_warn "SSH host key ${kt}: ${kage}d (considerar rotacion)"
    fi
done

# ── 4. Variables de entorno ────────────────────────────────
echo -e "\n${CYAN}── 4. Proteccion de variables de entorno ──${NC}"
echo "=== Variables entorno ===" >> "$REPORT_FILE"
env_procs=0
for pe in /proc/[0-9]*/environ; do
    [[ -r "$pe" ]] || continue
    if tr '\0' '\n' < "$pe" 2>/dev/null | grep -qiE '(PASSWORD|SECRET|API_KEY|TOKEN)=.+' 2>/dev/null; then
        ((env_procs++)) || true
    fi
done
[[ $env_procs -eq 0 ]] && check_pass "Sin secretos en entorno de procesos" || \
    check_warn "${env_procs} procesos con secretos en entorno"

# ── 5. SSH keys ────────────────────────────────────────────
echo -e "\n${CYAN}── 5. Claves SSH ──${NC}"
echo "=== SSH Keys ===" >> "$REPORT_FILE"
weak_ssh=0; total_ssh=0
for uh in /root /home/*; do
    for kf in "${uh}/.ssh"/id_*; do
        [[ -f "$kf" && "$kf" != *.pub ]] || continue
        ((total_ssh++)) || true
        if [[ -f "${kf}.pub" ]]; then
            kt=$(ssh-keygen -l -f "${kf}.pub" 2>/dev/null | awk '{print $NF}' | tr -d '()') || true
            kb=$(ssh-keygen -l -f "${kf}.pub" 2>/dev/null | awk '{print $1}') || true
            case "$kt" in
                DSA) ((weak_ssh++)) || true ;;
                RSA) [[ "$kb" -lt 2048 ]] 2>/dev/null && ((weak_ssh++)) || true ;;
            esac
        fi
    done
done
if [[ $total_ssh -eq 0 ]]; then
    echo -e "  ${DIM}No se encontraron claves SSH de usuario${NC}"
elif [[ $weak_ssh -eq 0 ]]; then
    check_pass "Todas las claves SSH cumplen requisitos (${total_ssh} total)"
else
    check_fail "${weak_ssh}/${total_ssh} claves SSH debiles"
fi

# ── 6. Cifrado ─────────────────────────────────────────────
echo -e "\n${CYAN}── 6. Cifrado de secretos en reposo ──${NC}"
echo "=== Cifrado ===" >> "$REPORT_FILE"
(command -v age &>/dev/null || command -v gpg &>/dev/null) && \
    check_pass "Herramienta de cifrado disponible" || \
    check_fail "Sin herramienta de cifrado"
[[ -f /etc/securizar/secrets-key.txt ]] && \
    check_pass "Clave age configurada" || \
    check_warn "Clave age no configurada"

# ── 7. Secretos en git ─────────────────────────────────────
echo -e "\n${CYAN}── 7. Secretos en repositorios git ──${NC}"
echo "=== Git ===" >> "$REPORT_FILE"
git_issues=0
while IFS= read -r gitdir; do
    [[ -z "$gitdir" ]] && continue
    repo=$(dirname "$gitdir")
    # Buscar secretos en ultimo commit
    if git -C "$repo" log -1 --diff-filter=A --name-only 2>/dev/null | \
        grep -qE '\.(env|pem|key|p12|pfx)$' 2>/dev/null; then
        ((git_issues++)) || true
    fi
done < <(find /home /opt -maxdepth 4 -name ".git" -type d 2>/dev/null || true)
[[ $git_issues -eq 0 ]] && check_pass "Sin archivos sensibles en commits recientes de git" || \
    check_warn "${git_issues} repos con posibles secretos en git"

# ── 8. Secretos en Docker ──────────────────────────────────
echo -e "\n${CYAN}── 8. Secretos en Docker ──${NC}"
echo "=== Docker ===" >> "$REPORT_FILE"
if command -v docker &>/dev/null; then
    docker_issues=0
    while IFS= read -r img; do
        [[ -z "$img" ]] && continue
        # Verificar ENV del imagen
        if docker inspect "$img" 2>/dev/null | grep -qiE '"(PASSWORD|SECRET|API_KEY|TOKEN)=' 2>/dev/null; then
            echo -e "  ${YELLOW}!!${NC} Imagen ${img}: secretos en ENV"
            ((docker_issues++)) || true
        fi
    done < <(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | head -20 || true)
    [[ $docker_issues -eq 0 ]] && check_pass "Sin secretos en imagenes Docker" || \
        check_warn "${docker_issues} imagenes con posibles secretos"
else
    echo -e "  ${DIM}Docker no instalado${NC}"
fi

# ── 9. Secretos en cron ────────────────────────────────────
echo -e "\n${CYAN}── 9. Secretos en cron jobs ──${NC}"
echo "=== Cron ===" >> "$REPORT_FILE"
cron_issues=0
for cdir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron/crontabs; do
    [[ -d "$cdir" ]] || continue
    for cf in "${cdir}"/*; do
        [[ -f "$cf" ]] || continue
        if grep -qEi '(PASSWORD|SECRET|API_KEY|TOKEN)=' "$cf" 2>/dev/null; then
            ((cron_issues++)) || true
        fi
    done
done
[[ $cron_issues -eq 0 ]] && check_pass "Sin secretos en cron jobs" || \
    check_fail "${cron_issues} cron jobs con secretos"

# ── 10. Certificados ───────────────────────────────────────
echo -e "\n${CYAN}── 10. Certificados ──${NC}"
echo "=== Certificados ===" >> "$REPORT_FILE"
cert_issues=0
for cdir in /etc/ssl/certs /etc/pki/tls/certs /etc/letsencrypt/live; do
    [[ -d "$cdir" ]] || continue
    while IFS= read -r cf; do
        [[ -f "$cf" ]] || continue
        head -1 "$cf" 2>/dev/null | grep -q "BEGIN CERTIFICATE" || continue
        exp_date=$(openssl x509 -enddate -noout -in "$cf" 2>/dev/null | cut -d= -f2) || continue
        [[ -z "$exp_date" ]] && continue
        exp_epoch=$(date -d "$exp_date" +%s 2>/dev/null || echo "0")
        days_left=$(( (exp_epoch - $(date +%s)) / 86400 ))
        if [[ $days_left -lt 0 ]]; then
            check_fail "Cert EXPIRADO: $(basename "$cf")"
            ((cert_issues++)) || true
        elif [[ $days_left -lt 30 ]]; then
            check_warn "Cert expira en ${days_left}d: $(basename "$cf")"
            ((cert_issues++)) || true
        fi
    done < <(find "$cdir" -maxdepth 2 \( -name "*.pem" -o -name "*.crt" \) 2>/dev/null | head -30)
done
[[ $cert_issues -eq 0 ]] && check_pass "Certificados vigentes"

# ── Puntuacion final ───────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════════════════════════════${NC}"
pct=0
[[ $total -gt 0 ]] && pct=$((score * 100 / total))
if [[ $pct -ge 80 ]]; then
    grade="BUENO"
    echo -e "${GREEN}${BOLD}  PUNTUACION: ${score}/${total} (${pct}%) - ${grade}${NC}"
elif [[ $pct -ge 50 ]]; then
    grade="MEJORABLE"
    echo -e "${YELLOW}${BOLD}  PUNTUACION: ${score}/${total} (${pct}%) - ${grade}${NC}"
else
    grade="DEFICIENTE"
    echo -e "${RED}${BOLD}  PUNTUACION: ${score}/${total} (${pct}%) - ${grade}${NC}"
fi
echo -e "${BOLD}══════════════════════════════════════════${NC}"

{
    echo ""
    echo "============================================================"
    echo "RESUMEN: ${score}/${total} (${pct}%) - ${grade}"
    echo "============================================================"
    if [[ ${#issues[@]} -gt 0 ]]; then
        echo ""
        echo "Problemas:"
        for iss in "${issues[@]}"; do echo "  - $iss"; done
    fi
} >> "$REPORT_FILE"
chmod 0600 "$REPORT_FILE"

if [[ ${#issues[@]} -gt 0 ]]; then
    echo -e "\n${YELLOW}Problemas detectados:${NC}"
    for iss in "${issues[@]}"; do echo -e "  - $iss"; done
fi

echo ""
echo -e "  Informe: ${BOLD}${REPORT_FILE}${NC}"
echo -e "\n${BOLD}Completado: $(date)${NC}"

# Enlace al ultimo informe
ln -sf "$REPORT_FILE" "${LOG_DIR}/auditoria-secrets-latest.log" 2>/dev/null || true
EOFAUDIT
    chmod +x "$AUDIT_TOOL"
    log_change "Creado" "$AUDIT_TOOL"
    log_change "Permisos" "$AUDIT_TOOL -> +x"

    # ── Cron semanal de auditoria ──────────────────────────────
    CRON_AUDIT="/etc/cron.weekly/auditoria-secrets"
    if [[ -f "$CRON_AUDIT" ]]; then
        cp -a "$CRON_AUDIT" "$BACKUP_DIR/"
        log_change "Backup" "$CRON_AUDIT"
    fi
    cat > "$CRON_AUDIT" << 'EOFCRONAUDIT'
#!/bin/bash
# Auditoria semanal de gestion de secretos - securizar Modulo 51
/usr/local/bin/auditoria-secrets.sh >> /var/log/securizar/auditoria-secrets-cron.log 2>&1
EOFCRONAUDIT
    chmod +x "$CRON_AUDIT"
    log_change "Creado" "$CRON_AUDIT"

    log_info "Auditoria integral de secretos configurada"
    log_info "Ejecuta: auditoria-secrets.sh"
else
    log_skip "Auditoria integral de gestion de secretos"
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
show_changes_summary
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     GESTION DE SECRETOS (MODULO 51) COMPLETADO            ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups guardados en: $BACKUP_DIR"
echo ""
echo "Comandos utiles post-hardening:"
echo "  - Escanear secretos:      escanear-secretos.sh --all"
echo "  - Iniciar vault:          securizar-vault-init.sh --init"
echo "  - Rotar credenciales:     rotar-credenciales.sh --all --dry-run"
echo "  - Auditar entorno:        auditar-env-secrets.sh"
echo "  - Auditar SSH keys:       auditar-ssh-keys.sh"
echo "  - Cifrar archivos:        cifrar-secretos.sh encrypt ARCHIVO"
echo "  - Iniciar pass:           securizar-pass-init.sh --generate-gpg-key"
echo "  - Validar politica:       validar-politica-secretos.sh"
echo "  - Monitorizar acceso:     monitorizar-acceso-secretos.sh --last-24h"
echo "  - Auditoria completa:     auditoria-secrets.sh"
echo ""
log_warn "RECOMENDACION: Ejecuta 'auditoria-secrets.sh' para ver la postura actual"
log_info "Modulo 51 completado"
