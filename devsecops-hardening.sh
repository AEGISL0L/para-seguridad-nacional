#!/bin/bash
# ============================================================
# devsecops-hardening.sh - Modulo 62: DevSecOps Hardening
# ============================================================
# Secciones:
#   S1  - Git repository security
#   S2  - CI/CD pipeline hardening
#   S3  - Container image scanning
#   S4  - SAST (Static Application Security Testing)
#   S5  - Secrets detection in code
#   S6  - Artifact repository security
#   S7  - Code signing and verification
#   S8  - Development environment isolation
#   S9  - Pre-commit security hooks
#   S10 - Auditoria integral DevSecOps
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps
init_backup "devsecops"

# ── Pre-check: detectar secciones ya aplicadas ──────────────
_precheck 10
_pc 'check_file_exists /etc/securizar/devsecops-policy.conf'
_pc 'check_executable /usr/local/bin/auditar-cicd.sh'
_pc 'check_executable /usr/local/bin/escanear-imagenes-contenedor.sh'
_pc 'check_executable /usr/local/bin/sast-scanner.sh'
_pc 'check_executable /usr/local/bin/detectar-secretos-codigo.sh'
_pc 'check_executable /usr/local/bin/auditar-artefactos.sh'
_pc 'check_executable /usr/local/bin/verificar-firmas-codigo.sh'
_pc 'check_executable /usr/local/bin/crear-sandbox-dev.sh'
_pc 'check_executable /usr/local/bin/instalar-precommit-hooks.sh'
_pc 'check_executable /usr/local/bin/auditar-devsecops.sh'
_precheck_result

log_section "MODULO 62: DEVSECOPS HARDENING"
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

# ============================================================
# S1 - Git repository security
# ============================================================
log_section "S1: Git repository security"
log_info "Configura politicas de seguridad para repositorios Git: permisos, hooks globales y auditoria de configuracion."

if check_file_exists /etc/securizar/devsecops-policy.conf; then
    log_already "Git repository security (devsecops-policy.conf existe)"
elif ask "Aplicar hardening de repositorios Git?"; then

    mkdir -p /etc/securizar /usr/local/bin

    # --- Policy config ---
    log_info "Creando archivo de politicas DevSecOps..."
    cat > /etc/securizar/devsecops-policy.conf << 'EOF'
# =============================================================
# devsecops-policy.conf - Politicas DevSecOps
# =============================================================

# --- Git ---
GIT_REQUIRE_SIGNED_COMMITS=true
GIT_ENFORCE_BRANCH_PROTECTION=true
GIT_MAX_FILE_SIZE_MB=10
GIT_FORBIDDEN_EXTENSIONS=".exe .dll .so .dylib .bin .jar .war .ear .zip .tar.gz .7z"
GIT_SCAN_SECRETS_ON_PUSH=true

# --- CI/CD ---
CICD_REQUIRE_PIPELINE_APPROVAL=true
CICD_MAX_BUILD_TIMEOUT_MINUTES=60
CICD_ENFORCE_LEAST_PRIVILEGE=true
CICD_BLOCK_SELF_HOSTED_ON_PUBLIC=true

# --- Container ---
CONTAINER_MAX_CVE_CRITICAL=0
CONTAINER_MAX_CVE_HIGH=5
CONTAINER_REQUIRE_BASE_IMAGE_DIGEST=true
CONTAINER_ENFORCE_NON_ROOT=true

# --- SAST ---
SAST_FAIL_ON_HIGH=true
SAST_FAIL_ON_CRITICAL=true
SAST_SCAN_TIMEOUT_MINUTES=30

# --- Secrets ---
SECRETS_BLOCK_ON_DETECT=true
SECRETS_SCAN_HISTORY=true
SECRETS_ALLOWED_PATTERNS_FILE=/etc/securizar/secret-allowlist.conf

# --- Artifacts ---
ARTIFACT_REQUIRE_CHECKSUM=true
ARTIFACT_REQUIRE_SIGNATURE=true
ARTIFACT_RETENTION_DAYS=90

# --- Code Signing ---
CODESIGN_REQUIRE_GPG=true
CODESIGN_MIN_KEY_BITS=4096
CODESIGN_REQUIRE_EXPIRY=true

# --- Sandbox ---
SANDBOX_ENABLE_FIREJAIL=true
SANDBOX_RESTRICT_NETWORK=false
SANDBOX_RESTRICT_HOME=true
EOF
    log_change "Creado" "/etc/securizar/devsecops-policy.conf"

    # --- Git repo scanner ---
    log_info "Creando script de auditoria de repositorios Git..."
    cat > /usr/local/bin/securizar-git-repos.sh << 'GITEOF'
#!/bin/bash
# ============================================================
# securizar-git-repos.sh - Auditoria y hardening de repos Git
# ============================================================
set -euo pipefail

POLICY_FILE="/etc/securizar/devsecops-policy.conf"
[[ -f "$POLICY_FILE" ]] && source "$POLICY_FILE"

REPORT_DIR="/var/log/securizar/devsecops"
mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/git-repos-$(date +%Y%m%d-%H%M%S).log"
SCORE=0
TOTAL=0
ISSUES=()

log_check() {
    local status="$1" desc="$2"
    ((TOTAL++))
    if [[ "$status" == "PASS" ]]; then
        ((SCORE++))
        echo "[PASS] $desc" >> "$REPORT"
    else
        echo "[FAIL] $desc" >> "$REPORT"
        ISSUES+=("$desc")
    fi
}

echo "=== Auditoria de Repositorios Git ===" >> "$REPORT"
echo "Fecha: $(date)" >> "$REPORT"
echo "========================================" >> "$REPORT"

SCAN_PATHS=("/home" "/opt" "/srv" "/var/lib")
[[ "${1:-}" != "" ]] && SCAN_PATHS=("$1")

REPOS_FOUND=0

for base_path in "${SCAN_PATHS[@]}"; do
    [[ -d "$base_path" ]] || continue
    while IFS= read -r git_dir; do
        repo_dir="$(dirname "$git_dir")"
        ((REPOS_FOUND++))
        echo "" >> "$REPORT"
        echo "--- Repo: $repo_dir ---" >> "$REPORT"

        # Check: .git directory permissions
        git_perms=$(stat -c '%a' "$git_dir" 2>/dev/null || echo "000")
        if [[ "$git_perms" -le 750 ]]; then
            log_check "PASS" "$repo_dir: .git permisos restrictivos ($git_perms)"
        else
            log_check "FAIL" "$repo_dir: .git permisos demasiado abiertos ($git_perms)"
            chmod 750 "$git_dir" 2>/dev/null || true
        fi

        # Check: hooks directory
        hooks_dir="$git_dir/hooks"
        if [[ -d "$hooks_dir" ]]; then
            hooks_perms=$(stat -c '%a' "$hooks_dir" 2>/dev/null || echo "000")
            if [[ "$hooks_perms" -le 750 ]]; then
                log_check "PASS" "$repo_dir: hooks permisos correctos ($hooks_perms)"
            else
                log_check "FAIL" "$repo_dir: hooks permisos abiertos ($hooks_perms)"
                chmod 750 "$hooks_dir" 2>/dev/null || true
            fi
        fi

        # Check: config file not world-readable
        config_file="$git_dir/config"
        if [[ -f "$config_file" ]]; then
            cfg_perms=$(stat -c '%a' "$config_file" 2>/dev/null || echo "000")
            if [[ "$cfg_perms" -le 640 ]]; then
                log_check "PASS" "$repo_dir: config permisos correctos ($cfg_perms)"
            else
                log_check "FAIL" "$repo_dir: config permisos abiertos ($cfg_perms)"
                chmod 640 "$config_file" 2>/dev/null || true
            fi
        fi

        # Check: no credentials stored in config
        if grep -qiE '(password|token|secret)\s*=' "$config_file" 2>/dev/null; then
            log_check "FAIL" "$repo_dir: credenciales detectadas en config"
        else
            log_check "PASS" "$repo_dir: sin credenciales en config"
        fi

        # Check: .gitignore exists
        if [[ -f "$repo_dir/.gitignore" ]]; then
            log_check "PASS" "$repo_dir: .gitignore presente"
        else
            log_check "FAIL" "$repo_dir: falta .gitignore"
        fi

        # Check: large files
        large_files=0
        max_size=$((${GIT_MAX_FILE_SIZE_MB:-10} * 1024 * 1024))
        while IFS= read -r tracked_file; do
            [[ -f "$repo_dir/$tracked_file" ]] || continue
            fsize=$(stat -c '%s' "$repo_dir/$tracked_file" 2>/dev/null || echo "0")
            if [[ "$fsize" -gt "$max_size" ]]; then
                ((large_files++))
                echo "  [WARN] Archivo grande: $tracked_file ($(( fsize / 1024 / 1024 ))MB)" >> "$REPORT"
            fi
        done < <(cd "$repo_dir" && git ls-files 2>/dev/null || true)
        if [[ "$large_files" -eq 0 ]]; then
            log_check "PASS" "$repo_dir: sin archivos excesivamente grandes"
        else
            log_check "FAIL" "$repo_dir: $large_files archivo(s) superan ${GIT_MAX_FILE_SIZE_MB:-10}MB"
        fi

        # Check: forbidden extensions
        forbidden_found=0
        for ext in ${GIT_FORBIDDEN_EXTENSIONS:-".exe .dll .so .bin"}; do
            count=$(cd "$repo_dir" && git ls-files "*${ext}" 2>/dev/null | wc -l || echo "0")
            if [[ "$count" -gt 0 ]]; then
                ((forbidden_found += count))
                echo "  [WARN] Extension prohibida $ext: $count archivo(s)" >> "$REPORT"
            fi
        done
        if [[ "$forbidden_found" -eq 0 ]]; then
            log_check "PASS" "$repo_dir: sin extensiones prohibidas"
        else
            log_check "FAIL" "$repo_dir: $forbidden_found archivo(s) con extensiones prohibidas"
        fi

    done < <(find "$base_path" -maxdepth 5 -name ".git" -type d 2>/dev/null || true)
done

echo "" >> "$REPORT"
echo "========================================" >> "$REPORT"
echo "Repositorios analizados: $REPOS_FOUND" >> "$REPORT"
echo "Puntuacion: $SCORE / $TOTAL" >> "$REPORT"
if [[ "$TOTAL" -gt 0 ]]; then
    PCT=$(( SCORE * 100 / TOTAL ))
    echo "Porcentaje: ${PCT}%" >> "$REPORT"
fi

if [[ "${#ISSUES[@]}" -gt 0 ]]; then
    echo "" >> "$REPORT"
    echo "=== PROBLEMAS DETECTADOS ===" >> "$REPORT"
    for issue in "${ISSUES[@]}"; do
        echo "  - $issue" >> "$REPORT"
    done
fi

echo ""
echo "Auditoria completada. Reporte: $REPORT"
echo "Repos analizados: $REPOS_FOUND | Score: $SCORE/$TOTAL"
GITEOF
    chmod 755 /usr/local/bin/securizar-git-repos.sh
    log_change "Creado" "/usr/local/bin/securizar-git-repos.sh"

    # Global git template hooks directory
    mkdir -p /etc/git-templates/hooks
    chmod 750 /etc/git-templates/hooks

    # Set global git template directory
    git config --system init.templateDir /etc/git-templates 2>/dev/null || true
    log_change "Configurado" "git template directory global en /etc/git-templates"

    log_change "Aplicado" "hardening de repositorios Git"

else
    log_skip "Git repository security"
fi

# ============================================================
# S2 - CI/CD pipeline hardening
# ============================================================
log_section "S2: CI/CD pipeline hardening"
log_info "Audita y asegura herramientas CI/CD instaladas: Jenkins, GitLab Runner, GitHub Actions runner, etc."

if check_executable /usr/local/bin/auditar-cicd.sh; then
    log_already "CI/CD pipeline hardening (auditar-cicd.sh existe)"
elif ask "Aplicar hardening de pipelines CI/CD?"; then

    cat > /usr/local/bin/auditar-cicd.sh << 'CICDEOF'
#!/bin/bash
# ============================================================
# auditar-cicd.sh - Auditoria de seguridad CI/CD
# ============================================================
set -euo pipefail

REPORT_DIR="/var/log/securizar/devsecops"
mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/cicd-audit-$(date +%Y%m%d-%H%M%S).log"
SCORE=0
TOTAL=0
ISSUES=()

log_check() {
    local status="$1" desc="$2"
    ((TOTAL++))
    if [[ "$status" == "PASS" ]]; then
        ((SCORE++))
        echo "[PASS] $desc" >> "$REPORT"
    else
        echo "[FAIL] $desc" >> "$REPORT"
        ISSUES+=("$desc")
    fi
}

echo "=== Auditoria CI/CD ===" >> "$REPORT"
echo "Fecha: $(date)" >> "$REPORT"
echo "========================================" >> "$REPORT"

# --- Detect Jenkins ---
echo "" >> "$REPORT"
echo "--- Jenkins ---" >> "$REPORT"
JENKINS_FOUND=false
if systemctl is-active --quiet jenkins 2>/dev/null; then
    JENKINS_FOUND=true
    echo "Jenkins: ACTIVO" >> "$REPORT"

    # Check Jenkins runs as non-root
    jenkins_user=$(ps -eo user,comm 2>/dev/null | awk '/[j]enkins/{print $1; exit}' || echo "unknown")
    if [[ "$jenkins_user" != "root" && "$jenkins_user" != "unknown" ]]; then
        log_check "PASS" "Jenkins ejecuta como usuario no-root ($jenkins_user)"
    else
        log_check "FAIL" "Jenkins ejecuta como root o no determinado ($jenkins_user)"
    fi

    # Check Jenkins home permissions
    jenkins_home="/var/lib/jenkins"
    if [[ -d "$jenkins_home" ]]; then
        jh_perms=$(stat -c '%a' "$jenkins_home" 2>/dev/null || echo "777")
        if [[ "$jh_perms" -le 750 ]]; then
            log_check "PASS" "Jenkins home permisos restrictivos ($jh_perms)"
        else
            log_check "FAIL" "Jenkins home permisos abiertos ($jh_perms)"
        fi
    fi

    # Check JNLP port
    if [[ -f "$jenkins_home/config.xml" ]]; then
        if grep -q '<slaveAgentPort>-1</slaveAgentPort>' "$jenkins_home/config.xml" 2>/dev/null; then
            log_check "PASS" "Puerto JNLP deshabilitado"
        elif grep -q '<slaveAgentPort>0</slaveAgentPort>' "$jenkins_home/config.xml" 2>/dev/null; then
            log_check "FAIL" "Puerto JNLP aleatorio (deberia estar deshabilitado o fijo)"
        else
            log_check "FAIL" "Puerto JNLP posiblemente habilitado"
        fi

        # Check security realm
        if grep -q '<securityRealm' "$jenkins_home/config.xml" 2>/dev/null; then
            log_check "PASS" "Security realm configurado"
        else
            log_check "FAIL" "Security realm no configurado"
        fi

        # Check CSRF protection
        if grep -q '<crumbIssuer' "$jenkins_home/config.xml" 2>/dev/null; then
            log_check "PASS" "Proteccion CSRF habilitada"
        else
            log_check "FAIL" "Proteccion CSRF no detectada"
        fi
    fi

    # Check CLI over remoting
    if [[ -f "$jenkins_home/jenkins.CLI.xml" ]]; then
        if grep -q '<enabled>false</enabled>' "$jenkins_home/jenkins.CLI.xml" 2>/dev/null; then
            log_check "PASS" "CLI remoting deshabilitado"
        else
            log_check "FAIL" "CLI remoting posiblemente habilitado"
        fi
    fi
else
    echo "Jenkins: NO DETECTADO" >> "$REPORT"
fi

# --- Detect GitLab Runner ---
echo "" >> "$REPORT"
echo "--- GitLab Runner ---" >> "$REPORT"
GITLAB_RUNNER_FOUND=false
if command -v gitlab-runner &>/dev/null; then
    GITLAB_RUNNER_FOUND=true
    echo "GitLab Runner: INSTALADO" >> "$REPORT"
    gitlab-runner --version >> "$REPORT" 2>/dev/null || true

    # Check runner config
    runner_config="/etc/gitlab-runner/config.toml"
    if [[ -f "$runner_config" ]]; then
        cfg_perms=$(stat -c '%a' "$runner_config" 2>/dev/null || echo "777")
        if [[ "$cfg_perms" -le 600 ]]; then
            log_check "PASS" "GitLab Runner config permisos restrictivos ($cfg_perms)"
        else
            log_check "FAIL" "GitLab Runner config permisos abiertos ($cfg_perms)"
            chmod 600 "$runner_config" 2>/dev/null || true
        fi

        # Check if using Docker executor with privileged
        if grep -q 'privileged = true' "$runner_config" 2>/dev/null; then
            log_check "FAIL" "GitLab Runner usa modo privileged (inseguro)"
        else
            log_check "PASS" "GitLab Runner no usa modo privileged"
        fi

        # Check concurrent limit
        if grep -q '^concurrent' "$runner_config" 2>/dev/null; then
            log_check "PASS" "Limite de concurrencia configurado"
        else
            log_check "FAIL" "Limite de concurrencia no configurado"
        fi
    fi

    # Check runner runs as non-root
    runner_user=$(ps -eo user,comm 2>/dev/null | awk '/gitlab-runner/{print $1; exit}' || echo "unknown")
    if [[ "$runner_user" != "root" && "$runner_user" != "unknown" ]]; then
        log_check "PASS" "GitLab Runner ejecuta como no-root ($runner_user)"
    elif [[ "$runner_user" == "unknown" ]]; then
        echo "  [INFO] No se pudo determinar usuario de GitLab Runner" >> "$REPORT"
    else
        log_check "FAIL" "GitLab Runner ejecuta como root"
    fi
else
    echo "GitLab Runner: NO DETECTADO" >> "$REPORT"
fi

# --- Detect GitHub Actions Runner ---
echo "" >> "$REPORT"
echo "--- GitHub Actions Runner ---" >> "$REPORT"
GH_RUNNER_FOUND=false
if pgrep -f "actions-runner" &>/dev/null || [[ -d "/opt/actions-runner" ]]; then
    GH_RUNNER_FOUND=true
    echo "GitHub Actions Runner: DETECTADO" >> "$REPORT"

    runner_dir="/opt/actions-runner"
    if [[ -d "$runner_dir" ]]; then
        rd_perms=$(stat -c '%a' "$runner_dir" 2>/dev/null || echo "777")
        if [[ "$rd_perms" -le 750 ]]; then
            log_check "PASS" "Actions Runner directorio permisos correctos ($rd_perms)"
        else
            log_check "FAIL" "Actions Runner directorio permisos abiertos ($rd_perms)"
        fi

        rd_owner=$(stat -c '%U' "$runner_dir" 2>/dev/null || echo "unknown")
        if [[ "$rd_owner" != "root" ]]; then
            log_check "PASS" "Actions Runner propiedad de usuario no-root ($rd_owner)"
        else
            log_check "FAIL" "Actions Runner propiedad de root"
        fi
    fi
else
    echo "GitHub Actions Runner: NO DETECTADO" >> "$REPORT"
fi

# --- Detect Drone CI ---
echo "" >> "$REPORT"
echo "--- Drone CI ---" >> "$REPORT"
if systemctl is-active --quiet drone 2>/dev/null || docker ps --format '{{.Names}}' 2>/dev/null | grep -qi drone; then
    echo "Drone CI: DETECTADO" >> "$REPORT"
    log_check "PASS" "Drone CI detectado - verificar manualmente configuracion"
else
    echo "Drone CI: NO DETECTADO" >> "$REPORT"
fi

# --- General CI/CD checks ---
echo "" >> "$REPORT"
echo "--- Verificaciones generales ---" >> "$REPORT"

# Check for .env files in common CI directories
env_files_found=0
for cidir in /var/lib/jenkins /etc/gitlab-runner /opt/actions-runner /opt/drone; do
    if [[ -d "$cidir" ]]; then
        count=$(find "$cidir" -name "*.env" -o -name ".env" 2>/dev/null | wc -l || echo "0")
        env_files_found=$((env_files_found + count))
    fi
done
if [[ "$env_files_found" -eq 0 ]]; then
    log_check "PASS" "Sin archivos .env expuestos en directorios CI/CD"
else
    log_check "FAIL" "$env_files_found archivo(s) .env encontrados en directorios CI/CD"
fi

# Check for world-readable credential files
cred_exposed=0
for cred_pattern in "credentials" "secrets" "token" "password"; do
    while IFS= read -r cfile; do
        cperms=$(stat -c '%a' "$cfile" 2>/dev/null || echo "000")
        if [[ "${cperms: -1}" != "0" ]]; then
            ((cred_exposed++))
            echo "  [WARN] Archivo sensible world-readable: $cfile ($cperms)" >> "$REPORT"
        fi
    done < <(find /var/lib/jenkins /etc/gitlab-runner /opt/actions-runner 2>/dev/null -maxdepth 3 -iname "*${cred_pattern}*" -type f 2>/dev/null || true)
done
if [[ "$cred_exposed" -eq 0 ]]; then
    log_check "PASS" "Sin archivos de credenciales world-readable"
else
    log_check "FAIL" "$cred_exposed archivo(s) de credenciales world-readable"
fi

# Summary
echo "" >> "$REPORT"
echo "========================================" >> "$REPORT"
echo "Puntuacion: $SCORE / $TOTAL" >> "$REPORT"
if [[ "$TOTAL" -gt 0 ]]; then
    PCT=$(( SCORE * 100 / TOTAL ))
    echo "Porcentaje: ${PCT}%" >> "$REPORT"
fi

if [[ "${#ISSUES[@]}" -gt 0 ]]; then
    echo "" >> "$REPORT"
    echo "=== PROBLEMAS DETECTADOS ===" >> "$REPORT"
    for issue in "${ISSUES[@]}"; do
        echo "  - $issue" >> "$REPORT"
    done
fi

echo ""
echo "Auditoria CI/CD completada. Reporte: $REPORT"
echo "Score: $SCORE/$TOTAL"
[[ "$JENKINS_FOUND" == "true" ]] && echo "  Jenkins: detectado"
[[ "$GITLAB_RUNNER_FOUND" == "true" ]] && echo "  GitLab Runner: detectado"
[[ "$GH_RUNNER_FOUND" == "true" ]] && echo "  GitHub Actions Runner: detectado"
CICDEOF
    chmod 755 /usr/local/bin/auditar-cicd.sh
    log_change "Creado" "/usr/local/bin/auditar-cicd.sh"

    log_change "Aplicado" "hardening de pipelines CI/CD"

else
    log_skip "CI/CD pipeline hardening"
fi

# ============================================================
# S3 - Container image scanning
# ============================================================
log_section "S3: Container image scanning"
log_info "Instala y configura Trivy para escaneo de vulnerabilidades en imagenes de contenedores."

if check_executable /usr/local/bin/escanear-imagenes-contenedor.sh; then
    log_already "Container image scanning (escanear-imagenes-contenedor.sh existe)"
elif ask "Configurar escaneo de imagenes de contenedores?"; then

    # Install Trivy if not present
    if ! command -v trivy &>/dev/null; then
        log_info "Instalando Trivy..."
        case "$DISTRO_FAMILY" in
            debian)
                apt-get install -y wget apt-transport-https gnupg lsb-release 2>/dev/null || true
                wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /usr/share/keyrings/trivy.gpg 2>/dev/null || true
                echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc 2>/dev/null || echo stable) main" > /etc/apt/sources.list.d/trivy.list 2>/dev/null || true
                apt-get update -qq 2>/dev/null || true
                apt-get install -y trivy 2>/dev/null || true
                ;;
            rhel)
                cat > /etc/yum.repos.d/trivy.repo << 'TRIVYREPO'
[trivy]
name=Trivy repository
baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$basearch/
gpgcheck=0
enabled=1
TRIVYREPO
                yum install -y trivy 2>/dev/null || dnf install -y trivy 2>/dev/null || true
                ;;
            suse)
                zypper addrepo --no-gpgcheck https://aquasecurity.github.io/trivy-repo/rpm/releases/x86_64/ trivy 2>/dev/null || true
                zypper --non-interactive install trivy 2>/dev/null || true
                ;;
            arch)
                pacman -S --noconfirm trivy 2>/dev/null || true
                ;;
        esac
        if command -v trivy &>/dev/null; then
            log_change "Instalado" "Trivy"
        else
            log_info "Trivy no pudo ser instalado automaticamente; el script wrapper funcionara cuando se instale manualmente"
        fi
    else
        log_info "Trivy ya esta instalado"
    fi

    cat > /usr/local/bin/escanear-imagenes-contenedor.sh << 'CONTAINEREOF'
#!/bin/bash
# ============================================================
# escanear-imagenes-contenedor.sh - Escaneo de imagenes
# ============================================================
set -euo pipefail

POLICY_FILE="/etc/securizar/devsecops-policy.conf"
[[ -f "$POLICY_FILE" ]] && source "$POLICY_FILE"

MAX_CRITICAL="${CONTAINER_MAX_CVE_CRITICAL:-0}"
MAX_HIGH="${CONTAINER_MAX_CVE_HIGH:-5}"

REPORT_DIR="/var/log/securizar/devsecops"
mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/container-scan-$(date +%Y%m%d-%H%M%S).log"

echo "=== Escaneo de Imagenes de Contenedores ===" >> "$REPORT"
echo "Fecha: $(date)" >> "$REPORT"
echo "=============================================" >> "$REPORT"

usage() {
    echo "Uso: $0 [--all | imagen1 imagen2 ...]"
    echo "  --all    Escanea todas las imagenes locales"
    echo "  imagen   Nombre de imagen(es) especifica(s)"
    exit 1
}

if ! command -v trivy &>/dev/null; then
    echo "[ERROR] Trivy no esta instalado. Instalar con:"
    echo "  https://aquasecurity.github.io/trivy/"
    exit 1
fi

IMAGES=()
if [[ "${1:-}" == "--all" ]]; then
    if command -v docker &>/dev/null; then
        while IFS= read -r img; do
            [[ -n "$img" ]] && IMAGES+=("$img")
        done < <(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -v '<none>' || true)
    fi
    if command -v podman &>/dev/null; then
        while IFS= read -r img; do
            [[ -n "$img" ]] && IMAGES+=("$img")
        done < <(podman images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -v '<none>' || true)
    fi
elif [[ $# -gt 0 ]]; then
    IMAGES=("$@")
else
    usage
fi

if [[ ${#IMAGES[@]} -eq 0 ]]; then
    echo "No se encontraron imagenes para escanear."
    exit 0
fi

TOTAL_IMAGES=${#IMAGES[@]}
PASSED=0
FAILED=0

for image in "${IMAGES[@]}"; do
    echo "" >> "$REPORT"
    echo "--- Imagen: $image ---" >> "$REPORT"
    echo "[*] Escaneando: $image"

    scan_output=$(trivy image --severity CRITICAL,HIGH --format json "$image" 2>/dev/null || echo "{}")

    critical_count=$(echo "$scan_output" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    results = data.get('Results', [])
    count = 0
    for r in results:
        for v in r.get('Vulnerabilities', []):
            if v.get('Severity') == 'CRITICAL':
                count += 1
    print(count)
except:
    print(0)
" 2>/dev/null || echo "0")

    high_count=$(echo "$scan_output" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    results = data.get('Results', [])
    count = 0
    for r in results:
        for v in r.get('Vulnerabilities', []):
            if v.get('Severity') == 'HIGH':
                count += 1
    print(count)
except:
    print(0)
" 2>/dev/null || echo "0")

    echo "  CRITICAL: $critical_count (max: $MAX_CRITICAL)" >> "$REPORT"
    echo "  HIGH: $high_count (max: $MAX_HIGH)" >> "$REPORT"

    verdict="PASS"
    if [[ "$critical_count" -gt "$MAX_CRITICAL" ]]; then
        verdict="FAIL"
    fi
    if [[ "$high_count" -gt "$MAX_HIGH" ]]; then
        verdict="FAIL"
    fi

    echo "  Veredicto: $verdict" >> "$REPORT"
    if [[ "$verdict" == "PASS" ]]; then
        ((PASSED++))
        echo "  [PASS] $image"
    else
        ((FAILED++))
        echo "  [FAIL] $image (CRITICAL=$critical_count, HIGH=$high_count)"
    fi

    # Check if running as non-root
    if command -v docker &>/dev/null; then
        user_check=$(docker inspect --format '{{.Config.User}}' "$image" 2>/dev/null || echo "")
        if [[ -n "$user_check" && "$user_check" != "root" && "$user_check" != "0" ]]; then
            echo "  [PASS] Imagen configurada para usuario no-root ($user_check)" >> "$REPORT"
        else
            echo "  [WARN] Imagen sin usuario no-root configurado" >> "$REPORT"
        fi
    fi

    # Save full scan
    trivy image --severity CRITICAL,HIGH "$image" >> "$REPORT" 2>/dev/null || true
done

echo "" >> "$REPORT"
echo "=============================================" >> "$REPORT"
echo "Total imagenes: $TOTAL_IMAGES" >> "$REPORT"
echo "Aprobadas: $PASSED" >> "$REPORT"
echo "Fallidas: $FAILED" >> "$REPORT"

echo ""
echo "Escaneo completado. Reporte: $REPORT"
echo "Imagenes: $TOTAL_IMAGES | Aprobadas: $PASSED | Fallidas: $FAILED"
exit $FAILED
CONTAINEREOF
    chmod 755 /usr/local/bin/escanear-imagenes-contenedor.sh
    log_change "Creado" "/usr/local/bin/escanear-imagenes-contenedor.sh"

    log_change "Aplicado" "escaneo de imagenes de contenedores"

else
    log_skip "Container image scanning"
fi

# ============================================================
# S4 - SAST (Static Application Security Testing)
# ============================================================
log_section "S4: SAST (Static Application Security Testing)"
log_info "Configura herramientas de analisis estatico: bandit (Python), npm audit (Node), gosec (Go), cppcheck (C/C++)."

if check_executable /usr/local/bin/sast-scanner.sh; then
    log_already "SAST (sast-scanner.sh existe)"
elif ask "Configurar herramientas SAST?"; then

    # Install SAST tools based on what's available
    log_info "Instalando herramientas SAST disponibles..."

    # cppcheck is commonly available
    pkg_install cppcheck || true

    # bandit via pip
    if command -v pip3 &>/dev/null; then
        pip3 install bandit 2>/dev/null || true
        if command -v bandit &>/dev/null; then
            log_change "Instalado" "bandit (Python SAST)"
        fi
    fi

    # shellcheck
    pkg_install shellcheck || true

    cat > /usr/local/bin/sast-scanner.sh << 'SASTEOF'
#!/bin/bash
# ============================================================
# sast-scanner.sh - Analisis estatico de seguridad multi-lenguaje
# ============================================================
set -euo pipefail

POLICY_FILE="/etc/securizar/devsecops-policy.conf"
[[ -f "$POLICY_FILE" ]] && source "$POLICY_FILE"

REPORT_DIR="/var/log/securizar/devsecops"
mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/sast-$(date +%Y%m%d-%H%M%S).log"
TOTAL_ISSUES=0

echo "=== SAST Scanner ===" >> "$REPORT"
echo "Fecha: $(date)" >> "$REPORT"
echo "========================================" >> "$REPORT"

TARGET="${1:-.}"
if [[ ! -d "$TARGET" ]]; then
    echo "[ERROR] Directorio no encontrado: $TARGET"
    exit 1
fi

echo "Directorio objetivo: $(realpath "$TARGET")" >> "$REPORT"
echo ""

# --- Python: Bandit ---
scan_python() {
    local dir="$1"
    echo "" >> "$REPORT"
    echo "--- Python (Bandit) ---" >> "$REPORT"

    py_files=$(find "$dir" -name "*.py" -type f 2>/dev/null | wc -l || echo "0")
    if [[ "$py_files" -eq 0 ]]; then
        echo "  Sin archivos Python detectados" >> "$REPORT"
        return
    fi
    echo "  Archivos Python: $py_files" >> "$REPORT"

    if ! command -v bandit &>/dev/null; then
        echo "  [SKIP] bandit no instalado (pip3 install bandit)" >> "$REPORT"
        return
    fi

    echo "[*] Escaneando Python con bandit..."
    bandit_output=$(bandit -r "$dir" -f json --severity-level medium 2>/dev/null || echo '{"results":[]}')

    high_count=$(echo "$bandit_output" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(len([r for r in data.get('results', []) if r.get('issue_severity') == 'HIGH']))
except:
    print(0)
" 2>/dev/null || echo "0")

    medium_count=$(echo "$bandit_output" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(len([r for r in data.get('results', []) if r.get('issue_severity') == 'MEDIUM']))
except:
    print(0)
" 2>/dev/null || echo "0")

    echo "  HIGH: $high_count | MEDIUM: $medium_count" >> "$REPORT"
    TOTAL_ISSUES=$((TOTAL_ISSUES + high_count + medium_count))

    # Append detailed results
    bandit -r "$dir" --severity-level medium 2>/dev/null >> "$REPORT" || true
}

# --- Node.js: npm audit ---
scan_nodejs() {
    local dir="$1"
    echo "" >> "$REPORT"
    echo "--- Node.js (npm audit) ---" >> "$REPORT"

    pkg_files=$(find "$dir" -name "package.json" -not -path "*/node_modules/*" -type f 2>/dev/null | wc -l || echo "0")
    if [[ "$pkg_files" -eq 0 ]]; then
        echo "  Sin proyectos Node.js detectados" >> "$REPORT"
        return
    fi
    echo "  Proyectos Node.js: $pkg_files" >> "$REPORT"

    if ! command -v npm &>/dev/null; then
        echo "  [SKIP] npm no instalado" >> "$REPORT"
        return
    fi

    echo "[*] Escaneando Node.js con npm audit..."
    while IFS= read -r pkg_json; do
        pkg_dir=$(dirname "$pkg_json")
        echo "  Proyecto: $pkg_dir" >> "$REPORT"
        if [[ -f "$pkg_dir/package-lock.json" ]] || [[ -f "$pkg_dir/npm-shrinkwrap.json" ]]; then
            audit_out=$(cd "$pkg_dir" && npm audit --json 2>/dev/null || echo '{}')
            vulns=$(echo "$audit_out" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    meta = data.get('metadata', {}).get('vulnerabilities', {})
    h = meta.get('high', 0)
    c = meta.get('critical', 0)
    print(f'{c},{h}')
except:
    print('0,0')
" 2>/dev/null || echo "0,0")
            crit=${vulns%%,*}
            high=${vulns##*,}
            echo "    CRITICAL: $crit | HIGH: $high" >> "$REPORT"
            TOTAL_ISSUES=$((TOTAL_ISSUES + crit + high))
        else
            echo "    [SKIP] Sin lockfile" >> "$REPORT"
        fi
    done < <(find "$dir" -name "package.json" -not -path "*/node_modules/*" -type f 2>/dev/null || true)
}

# --- Go: gosec ---
scan_go() {
    local dir="$1"
    echo "" >> "$REPORT"
    echo "--- Go (gosec) ---" >> "$REPORT"

    go_files=$(find "$dir" -name "*.go" -type f 2>/dev/null | wc -l || echo "0")
    if [[ "$go_files" -eq 0 ]]; then
        echo "  Sin archivos Go detectados" >> "$REPORT"
        return
    fi
    echo "  Archivos Go: $go_files" >> "$REPORT"

    if ! command -v gosec &>/dev/null; then
        echo "  [SKIP] gosec no instalado (go install github.com/securego/gosec/v2/cmd/gosec@latest)" >> "$REPORT"
        return
    fi

    echo "[*] Escaneando Go con gosec..."
    gosec_output=$(gosec -fmt json "$dir/..." 2>/dev/null || echo '{"Issues":[]}')
    issue_count=$(echo "$gosec_output" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(len(data.get('Issues', [])))
except:
    print(0)
" 2>/dev/null || echo "0")
    echo "  Issues: $issue_count" >> "$REPORT"
    TOTAL_ISSUES=$((TOTAL_ISSUES + issue_count))
    gosec "$dir/..." >> "$REPORT" 2>/dev/null || true
}

# --- C/C++: cppcheck ---
scan_cpp() {
    local dir="$1"
    echo "" >> "$REPORT"
    echo "--- C/C++ (cppcheck) ---" >> "$REPORT"

    cpp_files=$(find "$dir" \( -name "*.c" -o -name "*.cpp" -o -name "*.h" -o -name "*.hpp" \) -type f 2>/dev/null | wc -l || echo "0")
    if [[ "$cpp_files" -eq 0 ]]; then
        echo "  Sin archivos C/C++ detectados" >> "$REPORT"
        return
    fi
    echo "  Archivos C/C++: $cpp_files" >> "$REPORT"

    if ! command -v cppcheck &>/dev/null; then
        echo "  [SKIP] cppcheck no instalado" >> "$REPORT"
        return
    fi

    echo "[*] Escaneando C/C++ con cppcheck..."
    cppcheck_out=$(cppcheck --enable=warning,security --error-exitcode=0 --xml "$dir" 2>&1 || true)
    error_count=$(echo "$cppcheck_out" | grep -c '<error ' 2>/dev/null || echo "0")
    echo "  Errores/warnings: $error_count" >> "$REPORT"
    TOTAL_ISSUES=$((TOTAL_ISSUES + error_count))
    echo "$cppcheck_out" >> "$REPORT"
}

# --- Shell: shellcheck ---
scan_shell() {
    local dir="$1"
    echo "" >> "$REPORT"
    echo "--- Shell (shellcheck) ---" >> "$REPORT"

    sh_files=$(find "$dir" \( -name "*.sh" -o -name "*.bash" \) -type f 2>/dev/null | wc -l || echo "0")
    if [[ "$sh_files" -eq 0 ]]; then
        echo "  Sin archivos Shell detectados" >> "$REPORT"
        return
    fi
    echo "  Archivos Shell: $sh_files" >> "$REPORT"

    if ! command -v shellcheck &>/dev/null; then
        echo "  [SKIP] shellcheck no instalado" >> "$REPORT"
        return
    fi

    echo "[*] Escaneando Shell con shellcheck..."
    sc_issues=0
    while IFS= read -r shfile; do
        issues=$(shellcheck -f gcc "$shfile" 2>/dev/null | grep -c ':' || echo "0")
        if [[ "$issues" -gt 0 ]]; then
            sc_issues=$((sc_issues + issues))
            echo "  $shfile: $issues issues" >> "$REPORT"
            shellcheck -f gcc "$shfile" >> "$REPORT" 2>/dev/null || true
        fi
    done < <(find "$dir" \( -name "*.sh" -o -name "*.bash" \) -type f 2>/dev/null || true)
    echo "  Total issues: $sc_issues" >> "$REPORT"
    TOTAL_ISSUES=$((TOTAL_ISSUES + sc_issues))
}

# Run all scanners
scan_python "$TARGET"
scan_nodejs "$TARGET"
scan_go "$TARGET"
scan_cpp "$TARGET"
scan_shell "$TARGET"

# Summary
echo "" >> "$REPORT"
echo "========================================" >> "$REPORT"
echo "Total issues detectados: $TOTAL_ISSUES" >> "$REPORT"

echo ""
echo "SAST completado. Reporte: $REPORT"
echo "Total issues: $TOTAL_ISSUES"

if [[ "${SAST_FAIL_ON_HIGH:-true}" == "true" && "$TOTAL_ISSUES" -gt 0 ]]; then
    exit 1
fi
SASTEOF
    chmod 755 /usr/local/bin/sast-scanner.sh
    log_change "Creado" "/usr/local/bin/sast-scanner.sh"

    log_change "Aplicado" "herramientas SAST configuradas"

else
    log_skip "SAST (Static Application Security Testing)"
fi

# ============================================================
# S5 - Secrets detection in code
# ============================================================
log_section "S5: Secrets detection in code"
log_info "Configura deteccion de secretos en codigo fuente: API keys, tokens, passwords, claves privadas."

if check_executable /usr/local/bin/detectar-secretos-codigo.sh; then
    log_already "Secrets detection in code (detectar-secretos-codigo.sh existe)"
elif ask "Configurar deteccion de secretos en codigo?"; then

    # Create secret patterns config
    cat > /etc/securizar/secret-patterns.conf << 'PATEOF'
# =============================================================
# secret-patterns.conf - Patrones de deteccion de secretos
# =============================================================
# Formato: NOMBRE_PATRON:::REGEX
# Lineas que comienzan con # son comentarios

# --- API Keys ---
AWS_ACCESS_KEY:::AKIA[0-9A-Z]{16}
AWS_SECRET_KEY:::['\"][0-9a-zA-Z/+]{40}['\"]
GOOGLE_API_KEY:::AIza[0-9A-Za-z\-_]{35}
GOOGLE_OAUTH_ID:::[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com
SLACK_TOKEN:::xox[bpors]-[0-9a-zA-Z]{10,48}
SLACK_WEBHOOK:::https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[0-9a-zA-Z]{24}
GITHUB_TOKEN:::[gG][iI][tT][hH][uU][bB].*['\"][0-9a-zA-Z]{35,40}['\"]
GITHUB_PAT:::ghp_[0-9a-zA-Z]{36}
GITLAB_TOKEN:::glpat-[0-9a-zA-Z\-_]{20}
STRIPE_KEY:::sk_live_[0-9a-zA-Z]{24,}
STRIPE_KEY_TEST:::sk_test_[0-9a-zA-Z]{24,}
HEROKU_API_KEY:::[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}
MAILGUN_KEY:::key-[0-9a-zA-Z]{32}
TWILIO_SID:::AC[0-9a-f]{32}
SENDGRID_KEY:::SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}
AZURE_SUBSCRIPTION:::['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]

# --- Private Keys ---
RSA_PRIVATE_KEY:::-----BEGIN RSA PRIVATE KEY-----
DSA_PRIVATE_KEY:::-----BEGIN DSA PRIVATE KEY-----
EC_PRIVATE_KEY:::-----BEGIN EC PRIVATE KEY-----
OPENSSH_PRIVATE_KEY:::-----BEGIN OPENSSH PRIVATE KEY-----
PGP_PRIVATE_KEY:::-----BEGIN PGP PRIVATE KEY BLOCK-----
GENERIC_PRIVATE_KEY:::-----BEGIN PRIVATE KEY-----

# --- Passwords and Secrets ---
PASSWORD_ASSIGN:::(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]
SECRET_ASSIGN:::(?i)(secret|api_key|apikey|api_secret)\s*[=:]\s*['\"][^'\"]{4,}['\"]
TOKEN_ASSIGN:::(?i)(token|access_token|auth_token)\s*[=:]\s*['\"][^'\"]{4,}['\"]
DB_CONNECTION:::(?i)(mysql|postgres|mongodb|redis)://[^:]+:[^@]+@

# --- Certificates ---
PKCS12_FILE:::\.p12$|\.pfx$
KEYSTORE_FILE:::\.jks$|\.keystore$
PEM_FILE:::\.pem$
KEY_FILE:::\.key$

# --- JWT ---
JWT_TOKEN:::eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]+

# --- Generic high-entropy strings (base64-like) ---
HIGH_ENTROPY_BASE64:::['\"][A-Za-z0-9+/]{40,}={0,2}['\"]
PATEOF
    chmod 644 /etc/securizar/secret-patterns.conf
    log_change "Creado" "/etc/securizar/secret-patterns.conf"

    # Create allowlist file
    if [[ ! -f /etc/securizar/secret-allowlist.conf ]]; then
        cat > /etc/securizar/secret-allowlist.conf << 'ALLOWEOF'
# =============================================================
# secret-allowlist.conf - Falsos positivos conocidos
# =============================================================
# Un patron por linea (regex). Lineas que coincidan se ignoraran.
# Ejemplo:
# EXAMPLE_KEY
# test_token_placeholder
ALLOWEOF
        chmod 644 /etc/securizar/secret-allowlist.conf
        log_change "Creado" "/etc/securizar/secret-allowlist.conf"
    fi

    cat > /usr/local/bin/detectar-secretos-codigo.sh << 'SECRETEOF'
#!/bin/bash
# ============================================================
# detectar-secretos-codigo.sh - Deteccion de secretos en codigo
# ============================================================
set -euo pipefail

PATTERNS_FILE="/etc/securizar/secret-patterns.conf"
ALLOWLIST_FILE="/etc/securizar/secret-allowlist.conf"
REPORT_DIR="/var/log/securizar/devsecops"
mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/secrets-$(date +%Y%m%d-%H%M%S).log"
SECRETS_FOUND=0

echo "=== Deteccion de Secretos en Codigo ===" >> "$REPORT"
echo "Fecha: $(date)" >> "$REPORT"
echo "=========================================" >> "$REPORT"

TARGET="${1:-.}"
SCAN_HISTORY="${2:-false}"

if [[ ! -d "$TARGET" ]]; then
    echo "[ERROR] Directorio no encontrado: $TARGET"
    exit 1
fi

echo "Directorio: $(realpath "$TARGET")" >> "$REPORT"

if [[ ! -f "$PATTERNS_FILE" ]]; then
    echo "[ERROR] Archivo de patrones no encontrado: $PATTERNS_FILE"
    exit 1
fi

# Load allowlist
ALLOWLIST_PATTERNS=()
if [[ -f "$ALLOWLIST_FILE" ]]; then
    while IFS= read -r line; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        ALLOWLIST_PATTERNS+=("$line")
    done < "$ALLOWLIST_FILE"
fi

is_allowed() {
    local text="$1"
    for pattern in "${ALLOWLIST_PATTERNS[@]}"; do
        if echo "$text" | grep -qP "$pattern" 2>/dev/null; then
            return 0
        fi
    done
    return 1
}

# Excluded directories and file types
EXCLUDE_DIRS=("node_modules" ".git" "__pycache__" ".venv" "venv" "vendor" ".tox" "dist" "build" ".eggs")
EXCLUDE_EXTENSIONS=("png" "jpg" "jpeg" "gif" "ico" "svg" "woff" "woff2" "ttf" "eot" "mp3" "mp4" "avi" "pdf" "pyc" "class" "o" "so" "dll")

build_find_excludes() {
    local excludes=""
    for d in "${EXCLUDE_DIRS[@]}"; do
        excludes="$excludes -not -path '*/$d/*'"
    done
    for e in "${EXCLUDE_EXTENSIONS[@]}"; do
        excludes="$excludes -not -name '*.$e'"
    done
    echo "$excludes"
}

echo "[*] Escaneando archivos en: $TARGET"

# Scan current files
while IFS= read -r pattern_line; do
    [[ -z "$pattern_line" || "$pattern_line" == \#* ]] && continue

    pattern_name="${pattern_line%%:::*}"
    pattern_regex="${pattern_line##*:::}"

    [[ -z "$pattern_regex" ]] && continue

    while IFS= read -r file; do
        [[ -f "$file" ]] || continue
        # Skip binary files
        file_type=$(file -b --mime-type "$file" 2>/dev/null || echo "unknown")
        [[ "$file_type" == application/octet-stream ]] && continue
        [[ "$file_type" == image/* ]] && continue

        matches=$(grep -nP "$pattern_regex" "$file" 2>/dev/null || true)
        if [[ -n "$matches" ]]; then
            while IFS= read -r match; do
                if ! is_allowed "$match"; then
                    ((SECRETS_FOUND++))
                    echo "[SECRET] $pattern_name" >> "$REPORT"
                    echo "  Archivo: $file" >> "$REPORT"
                    echo "  Linea: $match" >> "$REPORT"
                    echo "" >> "$REPORT"
                fi
            done <<< "$matches"
        fi
    done < <(eval "find '$TARGET' -type f ${EXCLUDE_DIRS[*]/#/-not -path '*/} " 2>/dev/null | head -10000 || find "$TARGET" -type f 2>/dev/null | head -10000)

done < "$PATTERNS_FILE"

# Scan git history if requested
if [[ "$SCAN_HISTORY" == "true" || "$SCAN_HISTORY" == "--history" ]]; then
    echo "" >> "$REPORT"
    echo "--- Historial Git ---" >> "$REPORT"

    if [[ -d "$TARGET/.git" ]]; then
        echo "[*] Escaneando historial git..."
        while IFS= read -r pattern_line; do
            [[ -z "$pattern_line" || "$pattern_line" == \#* ]] && continue
            pattern_name="${pattern_line%%:::*}"
            pattern_regex="${pattern_line##*:::}"
            [[ -z "$pattern_regex" ]] && continue

            # Only scan text-friendly patterns in git log
            case "$pattern_name" in
                *FILE*|*ENTROPY*) continue ;;
            esac

            git_matches=$(cd "$TARGET" && git log -p --all -S "$pattern_regex" --pickaxe-regex 2>/dev/null | head -200 || true)
            if [[ -n "$git_matches" ]]; then
                ((SECRETS_FOUND++))
                echo "[HISTORY-SECRET] $pattern_name encontrado en historial git" >> "$REPORT"
                echo "$git_matches" | head -20 >> "$REPORT"
                echo "" >> "$REPORT"
            fi
        done < "$PATTERNS_FILE"
    else
        echo "  No es un repositorio git" >> "$REPORT"
    fi
fi

echo "" >> "$REPORT"
echo "=========================================" >> "$REPORT"
echo "Total secretos detectados: $SECRETS_FOUND" >> "$REPORT"

echo ""
echo "Escaneo completado. Reporte: $REPORT"
echo "Secretos encontrados: $SECRETS_FOUND"

if [[ "$SECRETS_FOUND" -gt 0 ]]; then
    echo "[ALERTA] Se encontraron secretos expuestos. Revisar reporte."
    exit 1
fi
SECRETEOF
    chmod 755 /usr/local/bin/detectar-secretos-codigo.sh
    log_change "Creado" "/usr/local/bin/detectar-secretos-codigo.sh"

    log_change "Aplicado" "deteccion de secretos en codigo"

else
    log_skip "Secrets detection in code"
fi

# ============================================================
# S6 - Artifact repository security
# ============================================================
log_section "S6: Artifact repository security"
log_info "Audita repositorios de artefactos: Nexus, Artifactory, registros de paquetes locales."

if check_executable /usr/local/bin/auditar-artefactos.sh; then
    log_already "Artifact repository security (auditar-artefactos.sh existe)"
elif ask "Configurar auditoria de repositorios de artefactos?"; then

    cat > /usr/local/bin/auditar-artefactos.sh << 'ARTEOF'
#!/bin/bash
# ============================================================
# auditar-artefactos.sh - Auditoria de repositorios de artefactos
# ============================================================
set -euo pipefail

POLICY_FILE="/etc/securizar/devsecops-policy.conf"
[[ -f "$POLICY_FILE" ]] && source "$POLICY_FILE"

REPORT_DIR="/var/log/securizar/devsecops"
mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/artifacts-$(date +%Y%m%d-%H%M%S).log"
SCORE=0
TOTAL=0
ISSUES=()

log_check() {
    local status="$1" desc="$2"
    ((TOTAL++))
    if [[ "$status" == "PASS" ]]; then
        ((SCORE++))
        echo "[PASS] $desc" >> "$REPORT"
    else
        echo "[FAIL] $desc" >> "$REPORT"
        ISSUES+=("$desc")
    fi
}

echo "=== Auditoria de Repositorios de Artefactos ===" >> "$REPORT"
echo "Fecha: $(date)" >> "$REPORT"
echo "=================================================" >> "$REPORT"

# --- Nexus Repository Manager ---
echo "" >> "$REPORT"
echo "--- Nexus Repository Manager ---" >> "$REPORT"
NEXUS_FOUND=false
if systemctl is-active --quiet nexus 2>/dev/null; then
    NEXUS_FOUND=true
    echo "Nexus: ACTIVO" >> "$REPORT"

    nexus_home="/opt/sonatype/nexus"
    nexus_data="/opt/sonatype/sonatype-work"
    [[ -d "/opt/nexus" ]] && nexus_home="/opt/nexus"

    # Check Nexus runs as non-root
    nexus_user=$(ps -eo user,comm 2>/dev/null | awk '/[n]exus|[j]ava.*nexus/{print $1; exit}' || echo "unknown")
    if [[ "$nexus_user" != "root" && "$nexus_user" != "unknown" ]]; then
        log_check "PASS" "Nexus ejecuta como no-root ($nexus_user)"
    else
        log_check "FAIL" "Nexus ejecuta como root o no determinado"
    fi

    # Check data directory permissions
    if [[ -d "$nexus_data" ]]; then
        nd_perms=$(stat -c '%a' "$nexus_data" 2>/dev/null || echo "777")
        if [[ "$nd_perms" -le 750 ]]; then
            log_check "PASS" "Nexus data permisos correctos ($nd_perms)"
        else
            log_check "FAIL" "Nexus data permisos abiertos ($nd_perms)"
        fi
    fi

    # Check if HTTPS is configured
    if [[ -f "$nexus_home/etc/nexus-default.properties" ]]; then
        if grep -q 'application-port-ssl' "$nexus_home/etc/nexus-default.properties" 2>/dev/null; then
            log_check "PASS" "Nexus SSL configurado"
        else
            log_check "FAIL" "Nexus SSL no configurado"
        fi
    fi
elif docker ps --format '{{.Names}}' 2>/dev/null | grep -qi nexus; then
    NEXUS_FOUND=true
    echo "Nexus: DETECTADO (Docker)" >> "$REPORT"
    log_check "PASS" "Nexus detectado en Docker"
else
    echo "Nexus: NO DETECTADO" >> "$REPORT"
fi

# --- JFrog Artifactory ---
echo "" >> "$REPORT"
echo "--- JFrog Artifactory ---" >> "$REPORT"
ARTIFACTORY_FOUND=false
if systemctl is-active --quiet artifactory 2>/dev/null; then
    ARTIFACTORY_FOUND=true
    echo "Artifactory: ACTIVO" >> "$REPORT"

    art_user=$(ps -eo user,comm 2>/dev/null | awk '/[a]rtifactory/{print $1; exit}' || echo "unknown")
    if [[ "$art_user" != "root" && "$art_user" != "unknown" ]]; then
        log_check "PASS" "Artifactory ejecuta como no-root ($art_user)"
    else
        log_check "FAIL" "Artifactory ejecuta como root o no determinado"
    fi
elif docker ps --format '{{.Names}}' 2>/dev/null | grep -qi artifactory; then
    ARTIFACTORY_FOUND=true
    echo "Artifactory: DETECTADO (Docker)" >> "$REPORT"
else
    echo "Artifactory: NO DETECTADO" >> "$REPORT"
fi

# --- Docker Registry ---
echo "" >> "$REPORT"
echo "--- Docker Registry ---" >> "$REPORT"
REGISTRY_FOUND=false
if docker ps --format '{{.Names}}' 2>/dev/null | grep -qi registry; then
    REGISTRY_FOUND=true
    echo "Docker Registry: DETECTADO" >> "$REPORT"

    # Check if registry uses TLS
    registry_port=$(docker port "$(docker ps --format '{{.Names}}' 2>/dev/null | grep -i registry | head -1)" 2>/dev/null | head -1 || echo "")
    if [[ -n "$registry_port" ]]; then
        echo "  Puerto: $registry_port" >> "$REPORT"
    fi
elif systemctl is-active --quiet docker-registry 2>/dev/null; then
    REGISTRY_FOUND=true
    echo "Docker Registry: ACTIVO (servicio)" >> "$REPORT"
else
    echo "Docker Registry: NO DETECTADO" >> "$REPORT"
fi

# --- Package Manager Security ---
echo "" >> "$REPORT"
echo "--- Seguridad de gestores de paquetes ---" >> "$REPORT"

# Check pip config
if [[ -f /etc/pip.conf ]]; then
    if grep -qi 'require-hashes\s*=\s*true' /etc/pip.conf 2>/dev/null; then
        log_check "PASS" "pip configurado con require-hashes"
    else
        log_check "FAIL" "pip sin require-hashes"
    fi
    if grep -qi 'trusted-host' /etc/pip.conf 2>/dev/null; then
        log_check "FAIL" "pip tiene trusted-host configurado (menos seguro)"
    else
        log_check "PASS" "pip sin trusted-host (usa verificacion SSL)"
    fi
else
    echo "  pip: sin configuracion global (/etc/pip.conf)" >> "$REPORT"
fi

# Check npm config
if [[ -f /etc/npmrc ]]; then
    if grep -qi 'strict-ssl=false' /etc/npmrc 2>/dev/null; then
        log_check "FAIL" "npm strict-ssl deshabilitado"
    else
        log_check "PASS" "npm strict-ssl habilitado"
    fi
else
    echo "  npm: sin configuracion global (/etc/npmrc)" >> "$REPORT"
fi

# Check for private registries with authentication
echo "" >> "$REPORT"
echo "--- Archivos de autenticacion ---" >> "$REPORT"
auth_files=("/root/.npmrc" "/root/.pypirc" "/root/.docker/config.json" "/root/.m2/settings.xml")
for af in "${auth_files[@]}"; do
    if [[ -f "$af" ]]; then
        af_perms=$(stat -c '%a' "$af" 2>/dev/null || echo "777")
        if [[ "$af_perms" -le 600 ]]; then
            log_check "PASS" "$af permisos correctos ($af_perms)"
        else
            log_check "FAIL" "$af permisos abiertos ($af_perms)"
            chmod 600 "$af" 2>/dev/null || true
        fi
    fi
done

# Check home directories for auth files
for user_home in /home/*; do
    [[ -d "$user_home" ]] || continue
    username=$(basename "$user_home")
    for af_name in ".npmrc" ".pypirc" ".docker/config.json" ".m2/settings.xml"; do
        af_path="$user_home/$af_name"
        if [[ -f "$af_path" ]]; then
            af_perms=$(stat -c '%a' "$af_path" 2>/dev/null || echo "777")
            if [[ "$af_perms" -le 600 ]]; then
                log_check "PASS" "$af_path permisos correctos ($af_perms)"
            else
                log_check "FAIL" "$af_path permisos abiertos ($af_perms)"
                chmod 600 "$af_path" 2>/dev/null || true
            fi
        fi
    done
done

# Summary
echo "" >> "$REPORT"
echo "=================================================" >> "$REPORT"
echo "Puntuacion: $SCORE / $TOTAL" >> "$REPORT"
if [[ "$TOTAL" -gt 0 ]]; then
    PCT=$(( SCORE * 100 / TOTAL ))
    echo "Porcentaje: ${PCT}%" >> "$REPORT"
fi

if [[ "${#ISSUES[@]}" -gt 0 ]]; then
    echo "" >> "$REPORT"
    echo "=== PROBLEMAS DETECTADOS ===" >> "$REPORT"
    for issue in "${ISSUES[@]}"; do
        echo "  - $issue" >> "$REPORT"
    done
fi

echo ""
echo "Auditoria de artefactos completada. Reporte: $REPORT"
echo "Score: $SCORE/$TOTAL"
[[ "$NEXUS_FOUND" == "true" ]] && echo "  Nexus: detectado"
[[ "$ARTIFACTORY_FOUND" == "true" ]] && echo "  Artifactory: detectado"
[[ "$REGISTRY_FOUND" == "true" ]] && echo "  Docker Registry: detectado"
ARTEOF
    chmod 755 /usr/local/bin/auditar-artefactos.sh
    log_change "Creado" "/usr/local/bin/auditar-artefactos.sh"

    log_change "Aplicado" "auditoria de repositorios de artefactos"

else
    log_skip "Artifact repository security"
fi

# ============================================================
# S7 - Code signing and verification
# ============================================================
log_section "S7: Code signing and verification"
log_info "Configura verificacion de firmas GPG en commits y tags, y validacion de integridad de codigo."

if check_executable /usr/local/bin/verificar-firmas-codigo.sh; then
    log_already "Code signing and verification (verificar-firmas-codigo.sh existe)"
elif ask "Configurar verificacion de firmas de codigo?"; then

    # Ensure GPG is installed
    if ! command -v gpg &>/dev/null; then
        pkg_install gnupg2 || pkg_install gnupg || true
    fi

    cat > /usr/local/bin/verificar-firmas-codigo.sh << 'SIGNEOF'
#!/bin/bash
# ============================================================
# verificar-firmas-codigo.sh - Verificacion de firmas de codigo
# ============================================================
set -euo pipefail

POLICY_FILE="/etc/securizar/devsecops-policy.conf"
[[ -f "$POLICY_FILE" ]] && source "$POLICY_FILE"

REPORT_DIR="/var/log/securizar/devsecops"
mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/code-signing-$(date +%Y%m%d-%H%M%S).log"
SCORE=0
TOTAL=0
ISSUES=()

log_check() {
    local status="$1" desc="$2"
    ((TOTAL++))
    if [[ "$status" == "PASS" ]]; then
        ((SCORE++))
        echo "[PASS] $desc" >> "$REPORT"
    else
        echo "[FAIL] $desc" >> "$REPORT"
        ISSUES+=("$desc")
    fi
}

echo "=== Verificacion de Firmas de Codigo ===" >> "$REPORT"
echo "Fecha: $(date)" >> "$REPORT"
echo "==========================================" >> "$REPORT"

TARGET="${1:-.}"

if [[ ! -d "$TARGET/.git" ]]; then
    echo "[ERROR] $TARGET no es un repositorio git"
    exit 1
fi

cd "$TARGET"

echo "Repositorio: $(realpath "$TARGET")" >> "$REPORT"
echo "" >> "$REPORT"

# --- Check GPG availability ---
echo "--- GPG ---" >> "$REPORT"
if command -v gpg &>/dev/null; then
    gpg_version=$(gpg --version 2>/dev/null | head -1 || echo "desconocida")
    echo "GPG: $gpg_version" >> "$REPORT"
    log_check "PASS" "GPG disponible"
else
    log_check "FAIL" "GPG no instalado"
    echo "GPG es necesario para verificar firmas."
    exit 1
fi

# --- Check git signing configuration ---
echo "" >> "$REPORT"
echo "--- Configuracion de firmas Git ---" >> "$REPORT"

signing_key=$(git config --get user.signingkey 2>/dev/null || echo "")
if [[ -n "$signing_key" ]]; then
    log_check "PASS" "Clave de firma configurada: $signing_key"
else
    log_check "FAIL" "Sin clave de firma configurada (user.signingkey)"
fi

commit_sign=$(git config --get commit.gpgsign 2>/dev/null || echo "false")
if [[ "$commit_sign" == "true" ]]; then
    log_check "PASS" "Firma automatica de commits habilitada"
else
    log_check "FAIL" "Firma automatica de commits deshabilitada"
fi

tag_sign=$(git config --get tag.gpgsign 2>/dev/null || echo "false")
if [[ "$tag_sign" == "true" ]]; then
    log_check "PASS" "Firma automatica de tags habilitada"
else
    log_check "FAIL" "Firma automatica de tags deshabilitada"
fi

# --- Verify recent commits ---
echo "" >> "$REPORT"
echo "--- Ultimos 50 commits ---" >> "$REPORT"

total_commits=0
signed_commits=0
unsigned_commits=0

while IFS= read -r commit_line; do
    [[ -z "$commit_line" ]] && continue
    ((total_commits++))

    commit_hash="${commit_line%% *}"
    sig_status=$(git log --format='%G?' -1 "$commit_hash" 2>/dev/null || echo "N")

    case "$sig_status" in
        G)
            ((signed_commits++))
            echo "  [SIGNED-GOOD] $commit_line" >> "$REPORT"
            ;;
        U)
            ((signed_commits++))
            echo "  [SIGNED-UNTRUSTED] $commit_line" >> "$REPORT"
            ;;
        B)
            echo "  [SIGNED-BAD] $commit_line" >> "$REPORT"
            ;;
        E)
            echo "  [SIGNED-EXPIRED] $commit_line" >> "$REPORT"
            ;;
        N)
            ((unsigned_commits++))
            echo "  [UNSIGNED] $commit_line" >> "$REPORT"
            ;;
        *)
            ((unsigned_commits++))
            echo "  [UNKNOWN] $commit_line" >> "$REPORT"
            ;;
    esac
done < <(git log --oneline -50 2>/dev/null || true)

echo "" >> "$REPORT"
echo "Total commits analizados: $total_commits" >> "$REPORT"
echo "Firmados: $signed_commits" >> "$REPORT"
echo "Sin firma: $unsigned_commits" >> "$REPORT"

if [[ "$total_commits" -gt 0 ]]; then
    sign_pct=$(( signed_commits * 100 / total_commits ))
    echo "Porcentaje firmados: ${sign_pct}%" >> "$REPORT"
    if [[ "$sign_pct" -ge 80 ]]; then
        log_check "PASS" "80%+ de commits estan firmados (${sign_pct}%)"
    else
        log_check "FAIL" "Menos del 80% de commits estan firmados (${sign_pct}%)"
    fi
fi

# --- Verify tags ---
echo "" >> "$REPORT"
echo "--- Tags ---" >> "$REPORT"
total_tags=0
signed_tags=0

while IFS= read -r tag; do
    [[ -z "$tag" ]] && continue
    ((total_tags++))
    if git tag -v "$tag" &>/dev/null; then
        ((signed_tags++))
        echo "  [SIGNED] $tag" >> "$REPORT"
    else
        echo "  [UNSIGNED] $tag" >> "$REPORT"
    fi
done < <(git tag -l 2>/dev/null | tail -20 || true)

echo "Total tags: $total_tags | Firmados: $signed_tags" >> "$REPORT"

# --- Check GPG key strength ---
echo "" >> "$REPORT"
echo "--- Claves GPG ---" >> "$REPORT"

min_bits="${CODESIGN_MIN_KEY_BITS:-4096}"

while IFS= read -r key_line; do
    [[ -z "$key_line" ]] && continue
    if [[ "$key_line" =~ ^pub ]]; then
        key_info="$key_line"
        # Extract key size
        if [[ "$key_line" =~ ([0-9]{3,5}) ]]; then
            key_bits="${BASH_REMATCH[1]}"
            if [[ "$key_bits" -ge "$min_bits" ]]; then
                log_check "PASS" "Clave GPG con $key_bits bits (min: $min_bits)"
            else
                log_check "FAIL" "Clave GPG con $key_bits bits (min: $min_bits)"
            fi
        fi
        echo "  $key_line" >> "$REPORT"
    fi
done < <(gpg --list-keys --keyid-format long 2>/dev/null || true)

# Summary
echo "" >> "$REPORT"
echo "==========================================" >> "$REPORT"
echo "Puntuacion: $SCORE / $TOTAL" >> "$REPORT"
if [[ "$TOTAL" -gt 0 ]]; then
    PCT=$(( SCORE * 100 / TOTAL ))
    echo "Porcentaje: ${PCT}%" >> "$REPORT"
fi

if [[ "${#ISSUES[@]}" -gt 0 ]]; then
    echo "" >> "$REPORT"
    echo "=== PROBLEMAS DETECTADOS ===" >> "$REPORT"
    for issue in "${ISSUES[@]}"; do
        echo "  - $issue" >> "$REPORT"
    done
fi

echo ""
echo "Verificacion completada. Reporte: $REPORT"
echo "Score: $SCORE/$TOTAL"
echo "Commits firmados: $signed_commits/$total_commits | Tags firmados: $signed_tags/$total_tags"
SIGNEOF
    chmod 755 /usr/local/bin/verificar-firmas-codigo.sh
    log_change "Creado" "/usr/local/bin/verificar-firmas-codigo.sh"

    # Configure global git signing recommendation
    log_info "Recomendacion: configurar firma GPG globalmente con:"
    log_info "  git config --global commit.gpgsign true"
    log_info "  git config --global tag.gpgsign true"

    log_change "Aplicado" "verificacion de firmas de codigo"

else
    log_skip "Code signing and verification"
fi

# ============================================================
# S8 - Development environment isolation
# ============================================================
log_section "S8: Development environment isolation"
log_info "Configura aislamiento de entornos de desarrollo con Firejail para IDEs y herramientas."

if check_executable /usr/local/bin/crear-sandbox-dev.sh; then
    log_already "Development environment isolation (crear-sandbox-dev.sh existe)"
elif ask "Configurar aislamiento de entornos de desarrollo?"; then

    # Install firejail if available
    if ! command -v firejail &>/dev/null; then
        log_info "Instalando firejail..."
        pkg_install firejail || true
    fi

    if command -v firejail &>/dev/null; then
        log_change "Disponible" "firejail instalado"
    else
        log_info "Firejail no disponible; se creara script wrapper igualmente"
    fi

    cat > /usr/local/bin/crear-sandbox-dev.sh << 'SANDBOXEOF'
#!/bin/bash
# ============================================================
# crear-sandbox-dev.sh - Sandbox para entornos de desarrollo
# ============================================================
set -euo pipefail

POLICY_FILE="/etc/securizar/devsecops-policy.conf"
[[ -f "$POLICY_FILE" ]] && source "$POLICY_FILE"

FIREJAIL_PROFILE_DIR="/etc/firejail"
CUSTOM_PROFILE_DIR="/etc/securizar/firejail-profiles"
mkdir -p "$CUSTOM_PROFILE_DIR"

usage() {
    echo "Uso: $0 [--setup | --run <app> | --list | --status]"
    echo ""
    echo "  --setup    Crear perfiles de firejail para IDEs"
    echo "  --run      Ejecutar aplicacion en sandbox"
    echo "  --list     Listar perfiles disponibles"
    echo "  --status   Mostrar sandboxes activos"
    exit 1
}

setup_profiles() {
    echo "[*] Creando perfiles de sandbox para desarrollo..."

    # --- VSCode ---
    cat > "$CUSTOM_PROFILE_DIR/vscode-dev.profile" << 'VSCODEPROF'
# Firejail profile for VSCode development
include /etc/firejail/default.profile

# Restrict access
blacklist /etc/shadow
blacklist /etc/gshadow
blacklist /root/.ssh/id_*
blacklist /root/.gnupg/private-keys*

# Allow development directories
noblacklist ${HOME}/projects
noblacklist ${HOME}/workspace
noblacklist ${HOME}/.config/Code
noblacklist ${HOME}/.vscode

# Network access (needed for extensions)
# Comment out to restrict network
# net none

# Restrict system access
noroot
caps.drop all
seccomp
nonewprivs
nogroups

# Filesystem restrictions
read-only /etc
read-only /usr
tmpfs /tmp

# Allow writing to specific dirs
read-write ${HOME}/projects
read-write ${HOME}/workspace
read-write ${HOME}/.config/Code
read-write ${HOME}/.vscode
read-write /tmp
VSCODEPROF
    echo "  [OK] Perfil VSCode creado"

    # --- JetBrains IDEs ---
    cat > "$CUSTOM_PROFILE_DIR/jetbrains-dev.profile" << 'JETPROF'
# Firejail profile for JetBrains IDEs
include /etc/firejail/default.profile

blacklist /etc/shadow
blacklist /etc/gshadow
blacklist /root/.ssh/id_*
blacklist /root/.gnupg/private-keys*

noblacklist ${HOME}/projects
noblacklist ${HOME}/workspace
noblacklist ${HOME}/.config/JetBrains
noblacklist ${HOME}/.java
noblacklist ${HOME}/.gradle
noblacklist ${HOME}/.m2

noroot
caps.drop all
seccomp
nonewprivs

read-only /etc
read-only /usr

read-write ${HOME}/projects
read-write ${HOME}/workspace
read-write ${HOME}/.config/JetBrains
read-write ${HOME}/.java
read-write ${HOME}/.gradle
read-write ${HOME}/.m2
read-write /tmp
JETPROF
    echo "  [OK] Perfil JetBrains creado"

    # --- Node.js development ---
    cat > "$CUSTOM_PROFILE_DIR/nodejs-dev.profile" << 'NODEPROF'
# Firejail profile for Node.js development
include /etc/firejail/default.profile

blacklist /etc/shadow
blacklist /etc/gshadow
blacklist /root/.ssh/id_*

noblacklist ${HOME}/projects
noblacklist ${HOME}/.npm
noblacklist ${HOME}/.nvm
noblacklist ${HOME}/.config/yarn

noroot
caps.drop all
seccomp
nonewprivs

read-only /etc
read-only /usr

read-write ${HOME}/projects
read-write ${HOME}/.npm
read-write ${HOME}/.nvm
read-write ${HOME}/.config/yarn
read-write /tmp
NODEPROF
    echo "  [OK] Perfil Node.js creado"

    # --- Python development ---
    cat > "$CUSTOM_PROFILE_DIR/python-dev.profile" << 'PYPROF'
# Firejail profile for Python development
include /etc/firejail/default.profile

blacklist /etc/shadow
blacklist /etc/gshadow
blacklist /root/.ssh/id_*

noblacklist ${HOME}/projects
noblacklist ${HOME}/.local/lib/python*
noblacklist ${HOME}/.cache/pip
noblacklist ${HOME}/.virtualenvs

noroot
caps.drop all
seccomp
nonewprivs

read-only /etc
read-only /usr

read-write ${HOME}/projects
read-write ${HOME}/.local
read-write ${HOME}/.cache/pip
read-write ${HOME}/.virtualenvs
read-write /tmp
PYPROF
    echo "  [OK] Perfil Python creado"

    # --- Generic untrusted code runner ---
    cat > "$CUSTOM_PROFILE_DIR/untrusted-code.profile" << 'UNTRUSTEDPROF'
# Firejail profile for running untrusted code
include /etc/firejail/default.profile

blacklist /etc/shadow
blacklist /etc/gshadow
blacklist /root
blacklist ${HOME}/.ssh
blacklist ${HOME}/.gnupg
blacklist ${HOME}/.aws
blacklist ${HOME}/.azure
blacklist ${HOME}/.gcloud
blacklist ${HOME}/.kube
blacklist ${HOME}/.docker

# Very restrictive
net none
noroot
caps.drop all
seccomp
nonewprivs
nogroups
nosound
nodvd
notv
no3d

# Minimal filesystem
private
private-tmp
private-dev

# Only allow current directory
whitelist ${HOME}/sandbox
read-write ${HOME}/sandbox
UNTRUSTEDPROF
    echo "  [OK] Perfil untrusted-code creado"

    echo ""
    echo "Perfiles creados en: $CUSTOM_PROFILE_DIR"
}

run_sandbox() {
    local app="$1"
    shift

    if ! command -v firejail &>/dev/null; then
        echo "[ERROR] Firejail no esta instalado"
        exit 1
    fi

    # Find profile
    local profile=""
    case "$app" in
        code|vscode)    profile="$CUSTOM_PROFILE_DIR/vscode-dev.profile" ;;
        idea|pycharm|webstorm|goland|clion)
                        profile="$CUSTOM_PROFILE_DIR/jetbrains-dev.profile" ;;
        node|npm|npx)   profile="$CUSTOM_PROFILE_DIR/nodejs-dev.profile" ;;
        python|python3|pip|pip3)
                        profile="$CUSTOM_PROFILE_DIR/python-dev.profile" ;;
        untrusted)      profile="$CUSTOM_PROFILE_DIR/untrusted-code.profile" ;;
        *)
            if [[ -f "$CUSTOM_PROFILE_DIR/${app}.profile" ]]; then
                profile="$CUSTOM_PROFILE_DIR/${app}.profile"
            elif [[ -f "$FIREJAIL_PROFILE_DIR/${app}.profile" ]]; then
                profile="$FIREJAIL_PROFILE_DIR/${app}.profile"
            else
                echo "[WARN] Sin perfil especifico para $app, usando default"
                profile=""
            fi
            ;;
    esac

    echo "[*] Ejecutando $app en sandbox..."
    if [[ -n "$profile" && -f "$profile" ]]; then
        echo "  Perfil: $profile"
        firejail --profile="$profile" "$app" "$@"
    else
        firejail "$app" "$@"
    fi
}

list_profiles() {
    echo "=== Perfiles de Sandbox Disponibles ==="
    echo ""
    echo "--- Personalizados ---"
    if [[ -d "$CUSTOM_PROFILE_DIR" ]]; then
        for pf in "$CUSTOM_PROFILE_DIR"/*.profile; do
            [[ -f "$pf" ]] || continue
            echo "  $(basename "$pf" .profile)"
        done
    fi
    echo ""
    echo "--- Sistema (firejail) ---"
    if [[ -d "$FIREJAIL_PROFILE_DIR" ]]; then
        ls "$FIREJAIL_PROFILE_DIR"/*.profile 2>/dev/null | while read -r pf; do
            echo "  $(basename "$pf" .profile)"
        done | head -30
        total=$(ls "$FIREJAIL_PROFILE_DIR"/*.profile 2>/dev/null | wc -l || echo "0")
        echo "  ... ($total perfiles total)"
    fi
}

show_status() {
    echo "=== Sandboxes Activos ==="
    if command -v firejail &>/dev/null; then
        firejail --list 2>/dev/null || echo "  Sin sandboxes activos"
    else
        echo "  Firejail no instalado"
    fi
}

case "${1:-}" in
    --setup)    setup_profiles ;;
    --run)
        shift
        [[ $# -eq 0 ]] && usage
        run_sandbox "$@"
        ;;
    --list)     list_profiles ;;
    --status)   show_status ;;
    *)          usage ;;
esac
SANDBOXEOF
    chmod 755 /usr/local/bin/crear-sandbox-dev.sh
    log_change "Creado" "/usr/local/bin/crear-sandbox-dev.sh"

    # Create initial profiles
    mkdir -p /etc/securizar/firejail-profiles
    /usr/local/bin/crear-sandbox-dev.sh --setup 2>/dev/null || true
    log_change "Creados" "perfiles de firejail para IDEs en /etc/securizar/firejail-profiles"

    log_change "Aplicado" "aislamiento de entornos de desarrollo"

else
    log_skip "Development environment isolation"
fi

# ============================================================
# S9 - Pre-commit security hooks
# ============================================================
log_section "S9: Pre-commit security hooks"
log_info "Instala hooks de pre-commit para deteccion de secretos, linting de seguridad y validacion automatica."

if check_executable /usr/local/bin/instalar-precommit-hooks.sh; then
    log_already "Pre-commit security hooks (instalar-precommit-hooks.sh existe)"
elif ask "Configurar pre-commit security hooks?"; then

    # Install pre-commit if available
    if command -v pip3 &>/dev/null && ! command -v pre-commit &>/dev/null; then
        pip3 install pre-commit 2>/dev/null || true
        if command -v pre-commit &>/dev/null; then
            log_change "Instalado" "pre-commit framework"
        fi
    fi

    cat > /usr/local/bin/instalar-precommit-hooks.sh << 'PRECOMMITEOF'
#!/bin/bash
# ============================================================
# instalar-precommit-hooks.sh - Instalacion de pre-commit hooks
# ============================================================
set -euo pipefail

TEMPLATE_DIR="/etc/securizar/precommit-templates"
mkdir -p "$TEMPLATE_DIR"

usage() {
    echo "Uso: $0 [--install <repo_dir> | --template | --global | --uninstall <repo_dir>]"
    echo ""
    echo "  --install <dir>   Instalar hooks en un repositorio"
    echo "  --template        Mostrar template .pre-commit-config.yaml"
    echo "  --global          Instalar hooks globalmente via git templates"
    echo "  --uninstall <dir> Desinstalar hooks de un repositorio"
    exit 1
}

create_template() {
    cat > "$TEMPLATE_DIR/.pre-commit-config.yaml" << 'YAMLEOF'
# .pre-commit-config.yaml - Security-focused pre-commit hooks
# Instalar: pre-commit install
# Ejecutar manualmente: pre-commit run --all-files

repos:
  # --- Pre-commit hooks generales ---
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: check-added-large-files
        args: ['--maxkb=1024']
      - id: check-case-conflict
      - id: check-merge-conflict
      - id: check-symlinks
      - id: check-yaml
      - id: check-json
      - id: check-toml
      - id: check-xml
      - id: detect-private-key
      - id: end-of-file-fixer
      - id: trailing-whitespace
      - id: check-executables-have-shebangs
      - id: no-commit-to-branch
        args: ['--branch', 'main', '--branch', 'master', '--branch', 'production']

  # --- Deteccion de secretos ---
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
        exclude: 'package-lock\.json|yarn\.lock|go\.sum'

  # --- Seguridad Python ---
  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.7
    hooks:
      - id: bandit
        args: ['-c', 'pyproject.toml']
        additional_dependencies: ['bandit[toml]']
        exclude: 'tests/'

  # --- Linting Shell ---
  - repo: https://github.com/shellcheck-py/shellcheck-py
    rev: v0.9.0.6
    hooks:
      - id: shellcheck
        args: ['--severity=warning']

  # --- Seguridad Dockerfiles ---
  - repo: https://github.com/hadolint/hadolint
    rev: v2.12.0
    hooks:
      - id: hadolint
        args: ['--failure-threshold', 'warning']

  # --- Terraform security ---
  - repo: https://github.com/antonbabenko/pre-commit-terraform
    rev: v1.86.0
    hooks:
      - id: terraform_tfsec

  # --- YAML lint ---
  - repo: https://github.com/adrienverge/yamllint
    rev: v1.33.0
    hooks:
      - id: yamllint
        args: ['-d', '{extends: relaxed, rules: {line-length: {max: 200}}}']

  # --- Commit message format ---
  - repo: https://github.com/compilerla/conventional-pre-commit
    rev: v3.1.0
    hooks:
      - id: conventional-pre-commit
        stages: [commit-msg]
YAMLEOF

    echo "Template creado en: $TEMPLATE_DIR/.pre-commit-config.yaml"
}

install_hooks() {
    local repo_dir="$1"

    if [[ ! -d "$repo_dir/.git" ]]; then
        echo "[ERROR] $repo_dir no es un repositorio git"
        exit 1
    fi

    echo "[*] Instalando pre-commit hooks en: $repo_dir"

    # Copy template if no config exists
    if [[ ! -f "$repo_dir/.pre-commit-config.yaml" ]]; then
        if [[ -f "$TEMPLATE_DIR/.pre-commit-config.yaml" ]]; then
            cp "$TEMPLATE_DIR/.pre-commit-config.yaml" "$repo_dir/.pre-commit-config.yaml"
            echo "  [OK] Template copiado"
        else
            create_template
            cp "$TEMPLATE_DIR/.pre-commit-config.yaml" "$repo_dir/.pre-commit-config.yaml"
            echo "  [OK] Template creado y copiado"
        fi
    else
        echo "  [INFO] .pre-commit-config.yaml ya existe"
    fi

    # Install pre-commit hooks
    if command -v pre-commit &>/dev/null; then
        cd "$repo_dir"
        pre-commit install 2>/dev/null || true
        pre-commit install --hook-type commit-msg 2>/dev/null || true
        echo "  [OK] Hooks instalados via pre-commit"
    else
        # Manual hook installation as fallback
        echo "  [WARN] pre-commit no disponible, instalando hook manual"
        local hook_file="$repo_dir/.git/hooks/pre-commit"
        cat > "$hook_file" << 'HOOKEOF'
#!/bin/bash
# Pre-commit hook - Security checks
set -euo pipefail

echo "[pre-commit] Ejecutando verificaciones de seguridad..."

# Check for secrets
SECRETS_PATTERNS=(
    'AKIA[0-9A-Z]{16}'
    '-----BEGIN.*PRIVATE KEY-----'
    'ghp_[0-9a-zA-Z]{36}'
    'glpat-[0-9a-zA-Z\-_]{20}'
    'sk_live_[0-9a-zA-Z]{24,}'
)

STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)
FOUND_SECRETS=0

for file in $STAGED_FILES; do
    [[ -f "$file" ]] || continue
    for pattern in "${SECRETS_PATTERNS[@]}"; do
        if grep -qP "$pattern" "$file" 2>/dev/null; then
            echo "[ALERT] Posible secreto en: $file (patron: $pattern)"
            ((FOUND_SECRETS++))
        fi
    done
done

# Check for large files
MAX_SIZE=$((1024 * 1024))  # 1MB
for file in $STAGED_FILES; do
    [[ -f "$file" ]] || continue
    fsize=$(stat -c '%s' "$file" 2>/dev/null || echo "0")
    if [[ "$fsize" -gt "$MAX_SIZE" ]]; then
        echo "[WARN] Archivo grande: $file ($(( fsize / 1024 ))KB)"
    fi
done

# Check for debug statements
for file in $STAGED_FILES; do
    [[ -f "$file" ]] || continue
    case "$file" in
        *.py)
            if grep -nP '(import pdb|pdb\.set_trace|breakpoint\(\))' "$file" 2>/dev/null; then
                echo "[WARN] Debug statement en: $file"
            fi
            ;;
        *.js|*.ts)
            if grep -nP '(console\.log|debugger)' "$file" 2>/dev/null; then
                echo "[INFO] console.log/debugger en: $file"
            fi
            ;;
    esac
done

if [[ "$FOUND_SECRETS" -gt 0 ]]; then
    echo ""
    echo "[BLOQUEADO] Se detectaron $FOUND_SECRETS posibles secretos."
    echo "Usa 'git commit --no-verify' para saltear (no recomendado)."
    exit 1
fi

echo "[pre-commit] Verificaciones completadas."
HOOKEOF
        chmod 755 "$hook_file"
        echo "  [OK] Hook manual instalado"
    fi
}

install_global() {
    echo "[*] Configurando hooks globales..."

    local global_hooks="/etc/git-templates/hooks"
    mkdir -p "$global_hooks"

    cat > "$global_hooks/pre-commit" << 'GLOBALHOOKEOF'
#!/bin/bash
# Global pre-commit hook - Secret detection
set -euo pipefail

STAGED=$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null || true)
[[ -z "$STAGED" ]] && exit 0

for file in $STAGED; do
    [[ -f "$file" ]] || continue
    if grep -qPl '(AKIA[0-9A-Z]{16}|-----BEGIN.*PRIVATE KEY-----|ghp_[0-9a-zA-Z]{36})' "$file" 2>/dev/null; then
        echo "[GLOBAL-HOOK] Posible secreto detectado en: $file"
        echo "Commit bloqueado. Usa --no-verify para saltear."
        exit 1
    fi
done
GLOBALHOOKEOF
    chmod 755 "$global_hooks/pre-commit"

    git config --system init.templateDir /etc/git-templates 2>/dev/null || true
    echo "[OK] Hooks globales configurados en /etc/git-templates"
    echo "     Nuevos repos usaran estos hooks automaticamente."
}

uninstall_hooks() {
    local repo_dir="$1"
    if [[ -f "$repo_dir/.git/hooks/pre-commit" ]]; then
        rm -f "$repo_dir/.git/hooks/pre-commit"
        echo "[OK] Pre-commit hook eliminado de $repo_dir"
    fi
    if command -v pre-commit &>/dev/null; then
        cd "$repo_dir" && pre-commit uninstall 2>/dev/null || true
        echo "[OK] pre-commit desinstalado"
    fi
}

case "${1:-}" in
    --install)
        shift
        [[ $# -eq 0 ]] && usage
        install_hooks "$1"
        ;;
    --template)
        create_template
        cat "$TEMPLATE_DIR/.pre-commit-config.yaml"
        ;;
    --global)
        install_global
        ;;
    --uninstall)
        shift
        [[ $# -eq 0 ]] && usage
        uninstall_hooks "$1"
        ;;
    *)
        usage
        ;;
esac
PRECOMMITEOF
    chmod 755 /usr/local/bin/instalar-precommit-hooks.sh
    log_change "Creado" "/usr/local/bin/instalar-precommit-hooks.sh"

    # Create the template
    mkdir -p /etc/securizar/precommit-templates
    /usr/local/bin/instalar-precommit-hooks.sh --template > /dev/null 2>&1 || true
    log_change "Creado" "/etc/securizar/precommit-templates/.pre-commit-config.yaml"

    # Install global hooks
    /usr/local/bin/instalar-precommit-hooks.sh --global 2>/dev/null || true
    log_change "Configurados" "hooks de pre-commit globales"

    log_change "Aplicado" "pre-commit security hooks"

else
    log_skip "Pre-commit security hooks"
fi

# ============================================================
# S10 - Auditoria integral DevSecOps
# ============================================================
log_section "S10: Auditoria integral DevSecOps"
log_info "Herramienta de auditoria integral que evalua todos los aspectos DevSecOps y genera un scoring global."

if check_executable /usr/local/bin/auditar-devsecops.sh; then
    log_already "Auditoria integral DevSecOps (auditar-devsecops.sh existe)"
elif ask "Crear herramienta de auditoria integral DevSecOps?"; then

    cat > /usr/local/bin/auditar-devsecops.sh << 'AUDITEOF'
#!/bin/bash
# ============================================================
# auditar-devsecops.sh - Auditoria integral DevSecOps
# ============================================================
set -euo pipefail

POLICY_FILE="/etc/securizar/devsecops-policy.conf"
[[ -f "$POLICY_FILE" ]] && source "$POLICY_FILE"

REPORT_DIR="/var/log/securizar/devsecops"
mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/audit-integral-$(date +%Y%m%d-%H%M%S).log"
SCORE=0
TOTAL=0
CATEGORIES=()
CAT_SCORES=()
CAT_TOTALS=()

log_check() {
    local status="$1" desc="$2"
    ((TOTAL++))
    ((CAT_TOTAL_CURRENT++))
    if [[ "$status" == "PASS" ]]; then
        ((SCORE++))
        ((CAT_SCORE_CURRENT++))
        echo "  [PASS] $desc" | tee -a "$REPORT"
    else
        echo "  [FAIL] $desc" | tee -a "$REPORT"
    fi
}

start_category() {
    local name="$1"
    CATEGORIES+=("$name")
    CAT_SCORE_CURRENT=0
    CAT_TOTAL_CURRENT=0
    echo "" >> "$REPORT"
    echo "=== $name ===" >> "$REPORT"
    echo ""
    echo "=== $name ==="
}

end_category() {
    CAT_SCORES+=("$CAT_SCORE_CURRENT")
    CAT_TOTALS+=("$CAT_TOTAL_CURRENT")
}

echo "============================================================" >> "$REPORT"
echo " AUDITORIA INTEGRAL DevSecOps" >> "$REPORT"
echo " Fecha: $(date)" >> "$REPORT"
echo " Host: $(hostname)" >> "$REPORT"
echo "============================================================" >> "$REPORT"

echo ""
echo "============================================================"
echo " AUDITORIA INTEGRAL DevSecOps"
echo "============================================================"
echo ""

# ---- Cat 1: Herramientas de seguridad instaladas ----
start_category "1. Herramientas de Seguridad"

command -v git &>/dev/null && log_check "PASS" "git instalado" || log_check "FAIL" "git no instalado"
command -v gpg &>/dev/null && log_check "PASS" "gpg instalado" || log_check "FAIL" "gpg no instalado"
command -v trivy &>/dev/null && log_check "PASS" "trivy instalado" || log_check "FAIL" "trivy no instalado"
command -v bandit &>/dev/null && log_check "PASS" "bandit instalado" || log_check "FAIL" "bandit no instalado"
command -v shellcheck &>/dev/null && log_check "PASS" "shellcheck instalado" || log_check "FAIL" "shellcheck no instalado"
command -v cppcheck &>/dev/null && log_check "PASS" "cppcheck instalado" || log_check "FAIL" "cppcheck no instalado"
command -v firejail &>/dev/null && log_check "PASS" "firejail instalado" || log_check "FAIL" "firejail no instalado"
command -v pre-commit &>/dev/null && log_check "PASS" "pre-commit instalado" || log_check "FAIL" "pre-commit no instalado"

end_category

# ---- Cat 2: Configuracion Git global ----
start_category "2. Configuracion Git Global"

template_dir=$(git config --system init.templateDir 2>/dev/null || echo "")
if [[ -n "$template_dir" ]]; then
    log_check "PASS" "Template dir configurado: $template_dir"
else
    log_check "FAIL" "Template dir no configurado"
fi

if [[ -f "/etc/git-templates/hooks/pre-commit" ]]; then
    log_check "PASS" "Hook global pre-commit presente"
else
    log_check "FAIL" "Hook global pre-commit ausente"
fi

global_sign=$(git config --system commit.gpgsign 2>/dev/null || echo "false")
if [[ "$global_sign" == "true" ]]; then
    log_check "PASS" "Firma global de commits habilitada"
else
    log_check "FAIL" "Firma global de commits deshabilitada"
fi

end_category

# ---- Cat 3: Politicas y configuracion ----
start_category "3. Politicas DevSecOps"

if [[ -f "/etc/securizar/devsecops-policy.conf" ]]; then
    log_check "PASS" "Archivo de politicas presente"
    pol_perms=$(stat -c '%a' "/etc/securizar/devsecops-policy.conf" 2>/dev/null || echo "777")
    if [[ "$pol_perms" -le 644 ]]; then
        log_check "PASS" "Permisos de politicas correctos ($pol_perms)"
    else
        log_check "FAIL" "Permisos de politicas abiertos ($pol_perms)"
    fi
else
    log_check "FAIL" "Archivo de politicas ausente"
fi

if [[ -f "/etc/securizar/secret-patterns.conf" ]]; then
    log_check "PASS" "Patrones de secretos configurados"
else
    log_check "FAIL" "Patrones de secretos ausentes"
fi

if [[ -f "/etc/securizar/secret-allowlist.conf" ]]; then
    log_check "PASS" "Allowlist de secretos configurada"
else
    log_check "FAIL" "Allowlist de secretos ausente"
fi

end_category

# ---- Cat 4: Scripts de auditoria ----
start_category "4. Scripts de Auditoria"

scripts=(
    "/usr/local/bin/securizar-git-repos.sh"
    "/usr/local/bin/auditar-cicd.sh"
    "/usr/local/bin/escanear-imagenes-contenedor.sh"
    "/usr/local/bin/sast-scanner.sh"
    "/usr/local/bin/detectar-secretos-codigo.sh"
    "/usr/local/bin/auditar-artefactos.sh"
    "/usr/local/bin/verificar-firmas-codigo.sh"
    "/usr/local/bin/crear-sandbox-dev.sh"
    "/usr/local/bin/instalar-precommit-hooks.sh"
    "/usr/local/bin/auditar-devsecops.sh"
)

for script in "${scripts[@]}"; do
    if [[ -f "$script" && -x "$script" ]]; then
        log_check "PASS" "$(basename "$script") presente y ejecutable"
    elif [[ -f "$script" ]]; then
        log_check "FAIL" "$(basename "$script") presente pero no ejecutable"
    else
        log_check "FAIL" "$(basename "$script") ausente"
    fi
done

end_category

# ---- Cat 5: CI/CD Security ----
start_category "5. Seguridad CI/CD"

# Jenkins
if systemctl is-active --quiet jenkins 2>/dev/null; then
    jenkins_user=$(ps -eo user,comm 2>/dev/null | awk '/[j]enkins/{print $1; exit}' || echo "root")
    if [[ "$jenkins_user" != "root" ]]; then
        log_check "PASS" "Jenkins ejecuta como no-root"
    else
        log_check "FAIL" "Jenkins ejecuta como root"
    fi
else
    echo "  [INFO] Jenkins no activo" | tee -a "$REPORT"
fi

# GitLab Runner
if command -v gitlab-runner &>/dev/null; then
    runner_cfg="/etc/gitlab-runner/config.toml"
    if [[ -f "$runner_cfg" ]]; then
        cfg_perms=$(stat -c '%a' "$runner_cfg" 2>/dev/null || echo "777")
        if [[ "$cfg_perms" -le 600 ]]; then
            log_check "PASS" "GitLab Runner config seguro ($cfg_perms)"
        else
            log_check "FAIL" "GitLab Runner config abierto ($cfg_perms)"
        fi
        if grep -q 'privileged = true' "$runner_cfg" 2>/dev/null; then
            log_check "FAIL" "GitLab Runner en modo privileged"
        else
            log_check "PASS" "GitLab Runner sin modo privileged"
        fi
    fi
else
    echo "  [INFO] GitLab Runner no instalado" | tee -a "$REPORT"
fi

# Check for exposed CI env files
exposed_env=0
for d in /var/lib/jenkins /etc/gitlab-runner /opt/actions-runner; do
    [[ -d "$d" ]] || continue
    count=$(find "$d" -name ".env" -o -name "*.env" 2>/dev/null | wc -l || echo "0")
    exposed_env=$((exposed_env + count))
done
if [[ "$exposed_env" -eq 0 ]]; then
    log_check "PASS" "Sin archivos .env expuestos en CI/CD"
else
    log_check "FAIL" "$exposed_env archivos .env expuestos"
fi

end_category

# ---- Cat 6: Container Security ----
start_category "6. Seguridad de Contenedores"

if command -v docker &>/dev/null || command -v podman &>/dev/null; then
    log_check "PASS" "Runtime de contenedores disponible"

    if command -v trivy &>/dev/null; then
        log_check "PASS" "Trivy disponible para escaneo"
    else
        log_check "FAIL" "Trivy no disponible para escaneo"
    fi

    # Check Docker daemon config
    if [[ -f /etc/docker/daemon.json ]]; then
        if grep -q '"userns-remap"' /etc/docker/daemon.json 2>/dev/null; then
            log_check "PASS" "Docker user namespace remapping configurado"
        else
            log_check "FAIL" "Docker user namespace remapping no configurado"
        fi
        if grep -q '"no-new-privileges"' /etc/docker/daemon.json 2>/dev/null; then
            log_check "PASS" "Docker no-new-privileges configurado"
        else
            log_check "FAIL" "Docker no-new-privileges no configurado"
        fi
    else
        echo "  [INFO] /etc/docker/daemon.json no encontrado" | tee -a "$REPORT"
    fi
else
    echo "  [INFO] Sin runtime de contenedores" | tee -a "$REPORT"
fi

end_category

# ---- Cat 7: Sandbox y aislamiento ----
start_category "7. Aislamiento de Desarrollo"

if command -v firejail &>/dev/null; then
    log_check "PASS" "Firejail disponible"
    if [[ -d /etc/securizar/firejail-profiles ]]; then
        profile_count=$(ls /etc/securizar/firejail-profiles/*.profile 2>/dev/null | wc -l || echo "0")
        if [[ "$profile_count" -gt 0 ]]; then
            log_check "PASS" "$profile_count perfiles de sandbox configurados"
        else
            log_check "FAIL" "Sin perfiles de sandbox personalizados"
        fi
    else
        log_check "FAIL" "Directorio de perfiles de sandbox ausente"
    fi
else
    log_check "FAIL" "Firejail no disponible"
fi

# Check if /tmp is mounted noexec (good for dev isolation)
if mount | grep -q '/tmp.*noexec' 2>/dev/null; then
    log_check "PASS" "/tmp montado con noexec"
else
    log_check "FAIL" "/tmp sin noexec"
fi

end_category

# ---- Cat 8: Precommit hooks ----
start_category "8. Pre-commit Hooks"

if [[ -f /etc/securizar/precommit-templates/.pre-commit-config.yaml ]]; then
    log_check "PASS" "Template pre-commit disponible"
else
    log_check "FAIL" "Template pre-commit ausente"
fi

if [[ -f /etc/git-templates/hooks/pre-commit ]]; then
    log_check "PASS" "Hook global pre-commit instalado"
    if [[ -x /etc/git-templates/hooks/pre-commit ]]; then
        log_check "PASS" "Hook global pre-commit ejecutable"
    else
        log_check "FAIL" "Hook global pre-commit no ejecutable"
    fi
else
    log_check "FAIL" "Hook global pre-commit no instalado"
fi

end_category

# ============================================================
# RESUMEN FINAL
# ============================================================
echo "" >> "$REPORT"
echo "============================================================" >> "$REPORT"
echo " RESUMEN DE AUDITORIA" >> "$REPORT"
echo "============================================================" >> "$REPORT"

echo ""
echo "============================================================"
echo " RESUMEN DE AUDITORIA"
echo "============================================================"
echo ""

total_categories=${#CATEGORIES[@]}
for i in $(seq 0 $((total_categories - 1))); do
    cat_name="${CATEGORIES[$i]}"
    cat_score="${CAT_SCORES[$i]}"
    cat_total="${CAT_TOTALS[$i]}"
    if [[ "$cat_total" -gt 0 ]]; then
        cat_pct=$(( cat_score * 100 / cat_total ))
    else
        cat_pct=0
    fi

    # Color indicator
    if [[ "$cat_pct" -ge 80 ]]; then
        indicator="[OK]"
    elif [[ "$cat_pct" -ge 50 ]]; then
        indicator="[--]"
    else
        indicator="[!!]"
    fi

    line="$indicator $cat_name: $cat_score/$cat_total (${cat_pct}%)"
    echo "$line" | tee -a "$REPORT"
done

echo "" | tee -a "$REPORT"

if [[ "$TOTAL" -gt 0 ]]; then
    GLOBAL_PCT=$(( SCORE * 100 / TOTAL ))
else
    GLOBAL_PCT=0
fi

echo "------------------------------------------------------------" | tee -a "$REPORT"
echo " PUNTUACION GLOBAL: $SCORE / $TOTAL (${GLOBAL_PCT}%)" | tee -a "$REPORT"
echo "------------------------------------------------------------" | tee -a "$REPORT"

# Rating
if [[ "$GLOBAL_PCT" -ge 90 ]]; then
    rating="A - Excelente"
elif [[ "$GLOBAL_PCT" -ge 80 ]]; then
    rating="B - Bueno"
elif [[ "$GLOBAL_PCT" -ge 70 ]]; then
    rating="C - Aceptable"
elif [[ "$GLOBAL_PCT" -ge 50 ]]; then
    rating="D - Necesita mejoras"
else
    rating="F - Critico"
fi

echo " Rating: $rating" | tee -a "$REPORT"
echo "------------------------------------------------------------" | tee -a "$REPORT"

echo "" | tee -a "$REPORT"
echo "Reporte completo: $REPORT" | tee -a "$REPORT"
AUDITEOF
    chmod 755 /usr/local/bin/auditar-devsecops.sh
    log_change "Creado" "/usr/local/bin/auditar-devsecops.sh"

    log_change "Aplicado" "auditoria integral DevSecOps"

else
    log_skip "Auditoria integral DevSecOps"
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
show_changes_summary
