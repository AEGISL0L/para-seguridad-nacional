#!/bin/bash
# ============================================================
# mac-selinux-apparmor.sh - Modulo 71: Control de Acceso Obligatorio
# ============================================================
# Secciones:
#   S1  - Deteccion y estado MAC (SELinux vs AppArmor vs ninguno)
#   S2  - Activar modo enforcing
#   S3  - Politicas de red (booleans, network rules)
#   S4  - Confinamiento de servicios criticos
#   S5  - Proteccion de ficheros sensibles
#   S6  - Politicas para contenedores
#   S7  - Auditoria de denegaciones
#   S8  - Politicas personalizadas
#   S9  - Hardening MLS/MCS
#   S10 - Auditoria integral MAC
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "mac-security"
securizar_setup_traps

# ── Pre-check: detectar secciones ya aplicadas ──────────────
_precheck 10
_pc 'check_executable /usr/local/bin/securizar-mac-status.sh'
_pc 'check_executable /usr/local/bin/securizar-mac-enforce.sh'
_pc 'check_file_exists /etc/securizar/mac/network-policy.conf'
_pc 'check_executable /usr/local/bin/securizar-mac-confine.sh'
_pc 'check_executable /usr/local/bin/securizar-mac-fileprotect.sh'
_pc 'check_file_exists /etc/securizar/mac/container-policy.conf'
_pc 'check_executable /usr/local/bin/securizar-mac-audit.sh'
_pc 'check_executable /usr/local/bin/securizar-mac-custom.sh'
_pc 'check_file_exists /etc/securizar/mac/mls-policy.conf'
_pc 'check_executable /usr/local/bin/auditoria-mac-completa.sh'
_precheck_result

log_section "MODULO 71: CONTROL DE ACCESO OBLIGATORIO"
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

MAC_DIR="/etc/securizar/mac"
MAC_BIN="/usr/local/bin"
MAC_LOG="/var/log/securizar/mac"

mkdir -p "$MAC_DIR" "$MAC_LOG" || true

# Helper: detectar MAC activo
detect_mac_system() {
    if command -v getenforce &>/dev/null && [[ "$(getenforce 2>/dev/null)" != "" ]]; then
        echo "selinux"
    elif command -v aa-status &>/dev/null || [[ -d /sys/module/apparmor ]]; then
        echo "apparmor"
    else
        echo "none"
    fi
}

MAC_SYSTEM=$(detect_mac_system)

# ============================================================
# S1: DETECCION Y ESTADO MAC
# ============================================================
log_section "S1: Deteccion y estado MAC (SELinux vs AppArmor)"

log_info "Detecta el sistema MAC activo y reporta su estado actual."
log_info "  - SELinux: getenforce, sestatus, politicas"
log_info "  - AppArmor: aa-status, perfiles cargados"
log_info ""

if check_executable /usr/local/bin/securizar-mac-status.sh; then
    log_already "Deteccion MAC (securizar-mac-status.sh existe)"
elif ask "Crear herramienta de deteccion y estado MAC?"; then

    cat > "$MAC_BIN/securizar-mac-status.sh" << 'EOFMACSTATUS'
#!/bin/bash
# ============================================================
# securizar-mac-status.sh - Estado del sistema MAC
# ============================================================
set -euo pipefail

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
BOLD="\033[1m"
DIM="\033[2m"
NC="\033[0m"

LOG_DIR="/var/log/securizar/mac"
mkdir -p "$LOG_DIR"
REPORT="$LOG_DIR/mac-status-$(date +%Y%m%d-%H%M%S).log"

log_r() { echo -e "$1" | tee -a "$REPORT"; }

log_r "${BOLD}=============================================${NC}"
log_r "  ESTADO DEL SISTEMA MAC"
log_r "  Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
log_r "  Host: $(hostname)"
log_r "${BOLD}=============================================${NC}"
log_r ""

# Detectar sistema MAC
MAC_TYPE="none"
SCORE=0
MAX=0

# --- SELinux ---
log_r "${CYAN}=== SELinux ===${NC}"
MAX=$((MAX + 5))
if command -v getenforce &>/dev/null; then
    SE_MODE=$(getenforce 2>/dev/null || echo "Unknown")
    log_r "  Estado: $SE_MODE"
    if [[ "$SE_MODE" == "Enforcing" ]]; then
        log_r "  ${GREEN}[OK]${NC} SELinux en modo Enforcing"
        SCORE=$((SCORE + 3))
        MAC_TYPE="selinux"
    elif [[ "$SE_MODE" == "Permissive" ]]; then
        log_r "  ${YELLOW}[!!]${NC} SELinux en modo Permissive (no bloquea)"
        SCORE=$((SCORE + 1))
        MAC_TYPE="selinux"
    else
        log_r "  ${RED}[--]${NC} SELinux deshabilitado"
    fi

    if command -v sestatus &>/dev/null; then
        log_r ""
        log_r "  Detalles sestatus:"
        sestatus 2>/dev/null | while IFS= read -r line; do
            log_r "    $line"
        done
        SCORE=$((SCORE + 1))
    fi

    # Politica cargada
    if [[ -f /etc/selinux/config ]]; then
        policy=$(grep -E '^SELINUXTYPE=' /etc/selinux/config 2>/dev/null | cut -d= -f2)
        log_r "  Politica: ${policy:-desconocida}"
        SCORE=$((SCORE + 1))
    fi
else
    log_r "  ${DIM}SELinux no disponible en este sistema${NC}"
fi

log_r ""

# --- AppArmor ---
log_r "${CYAN}=== AppArmor ===${NC}"
MAX=$((MAX + 5))
if command -v aa-status &>/dev/null || [[ -d /sys/module/apparmor ]]; then
    if [[ -f /sys/module/apparmor/parameters/enabled ]]; then
        enabled=$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)
        if [[ "$enabled" == "Y" ]]; then
            log_r "  ${GREEN}[OK]${NC} AppArmor habilitado en el kernel"
            SCORE=$((SCORE + 2))
            [[ "$MAC_TYPE" == "none" ]] && MAC_TYPE="apparmor"
        else
            log_r "  ${RED}[--]${NC} AppArmor modulo cargado pero deshabilitado"
        fi
    fi

    if command -v aa-status &>/dev/null; then
        log_r ""
        enforce_count=$(aa-status 2>/dev/null | grep -c "enforce" || echo "0")
        complain_count=$(aa-status 2>/dev/null | grep -c "complain" || echo "0")
        total_profiles=$(aa-status 2>/dev/null | grep "profiles are loaded" | awk '{print $1}' || echo "0")
        log_r "  Perfiles cargados: ${total_profiles:-0}"
        log_r "  En enforce: ${enforce_count}"
        log_r "  En complain: ${complain_count}"
        [[ "${enforce_count:-0}" -gt 0 ]] && SCORE=$((SCORE + 2))
        [[ "${total_profiles:-0}" -gt 0 ]] && SCORE=$((SCORE + 1))
    fi
else
    log_r "  ${DIM}AppArmor no disponible en este sistema${NC}"
fi

log_r ""

# --- Resumen ---
log_r "${BOLD}=============================================${NC}"
log_r "  Sistema MAC activo: ${BOLD}${MAC_TYPE}${NC}"
PCT=0
[[ $MAX -gt 0 ]] && PCT=$((SCORE * 100 / MAX))
if [[ $PCT -ge 70 ]]; then
    log_r "  ${GREEN}Puntuacion: ${SCORE}/${MAX} (${PCT}%) - BUENO${NC}"
elif [[ $PCT -ge 40 ]]; then
    log_r "  ${YELLOW}Puntuacion: ${SCORE}/${MAX} (${PCT}%) - MEJORABLE${NC}"
else
    log_r "  ${RED}Puntuacion: ${SCORE}/${MAX} (${PCT}%) - DEFICIENTE${NC}"
fi

if [[ "$MAC_TYPE" == "none" ]]; then
    log_r ""
    log_r "  ${YELLOW}RECOMENDACION: Habilitar AppArmor o SELinux${NC}"
    log_r "  - openSUSE/Debian/Ubuntu: AppArmor (preinstalado normalmente)"
    log_r "  - RHEL/Fedora/CentOS: SELinux (preinstalado normalmente)"
fi

log_r "${BOLD}=============================================${NC}"
log_r "Reporte: $REPORT"
EOFMACSTATUS
    chmod +x "$MAC_BIN/securizar-mac-status.sh"
    log_change "Creado" "$MAC_BIN/securizar-mac-status.sh"

else
    log_skip "Deteccion y estado MAC"
fi

# ============================================================
# S2: ACTIVAR MODO ENFORCING
# ============================================================
log_section "S2: Activar modo enforcing"

log_info "Pasa el sistema MAC a modo enforcing:"
log_info "  - SELinux: setenforce 1, SELINUX=enforcing en config"
log_info "  - AppArmor: aa-enforce para todos los perfiles"
log_info ""

if check_executable /usr/local/bin/securizar-mac-enforce.sh; then
    log_already "Modo enforcing (securizar-mac-enforce.sh existe)"
elif ask "Crear script para activar modo enforcing?"; then

    cat > "$MAC_BIN/securizar-mac-enforce.sh" << 'EOFENFORCE'
#!/bin/bash
# ============================================================
# securizar-mac-enforce.sh - Activar modo enforcing
# ============================================================
set -euo pipefail

echo "=== Activar modo enforcing MAC ==="
echo "Fecha: $(date)"
echo ""

# Detectar MAC
if command -v getenforce &>/dev/null && [[ "$(getenforce 2>/dev/null)" != "" ]]; then
    echo "Sistema MAC detectado: SELinux"
    CURRENT=$(getenforce)
    echo "  Modo actual: $CURRENT"

    if [[ "$CURRENT" != "Enforcing" ]]; then
        echo "  Activando enforcing..."
        setenforce 1 2>/dev/null && echo "  [OK] setenforce 1 aplicado" || echo "  [!!] No se pudo aplicar setenforce"

        # Persistir en config
        if [[ -f /etc/selinux/config ]]; then
            sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
            echo "  [OK] /etc/selinux/config -> SELINUX=enforcing"
        fi
    else
        echo "  [OK] Ya esta en modo Enforcing"
    fi

elif command -v aa-enforce &>/dev/null; then
    echo "Sistema MAC detectado: AppArmor"

    # Listar perfiles en complain y enforce
    echo "  Poniendo todos los perfiles en modo enforce..."
    profile_dir="/etc/apparmor.d"
    if [[ -d "$profile_dir" ]]; then
        enforced=0
        for profile in "$profile_dir"/*; do
            [[ -f "$profile" ]] || continue
            basename_p=$(basename "$profile")
            # Saltar abstractions, tunables, etc
            [[ "$basename_p" == abstractions ]] && continue
            [[ "$basename_p" == tunables ]] && continue
            [[ "$basename_p" == local ]] && continue
            [[ "$basename_p" == disable ]] && continue
            [[ "$basename_p" == force-complain ]] && continue
            aa-enforce "$profile" 2>/dev/null && ((enforced++)) || true
        done
        echo "  [OK] $enforced perfiles puestos en enforce"
    fi

    # Verificar resultado
    if command -v aa-status &>/dev/null; then
        echo ""
        echo "  Estado actual:"
        aa-status 2>/dev/null | head -5
    fi
else
    echo "[!!] No se detecto SELinux ni AppArmor"
    echo "     Instala uno de los dos sistemas MAC"
fi

echo ""
echo "Completado: $(date)"
EOFENFORCE
    chmod +x "$MAC_BIN/securizar-mac-enforce.sh"
    log_change "Creado" "$MAC_BIN/securizar-mac-enforce.sh"

else
    log_skip "Activar modo enforcing"
fi

# ============================================================
# S3: POLITICAS DE RED
# ============================================================
log_section "S3: Politicas de red MAC"

log_info "Configura politicas de red del sistema MAC:"
log_info "  - SELinux: booleans de red (httpd_can_network_connect, etc)"
log_info "  - AppArmor: restricciones de red en perfiles"
log_info ""

if check_file_exists /etc/securizar/mac/network-policy.conf; then
    log_already "Politicas de red MAC (network-policy.conf existe)"
elif ask "Configurar politicas de red MAC?"; then

    cat > "$MAC_DIR/network-policy.conf" << 'EOFNETPOL'
# ============================================================
# network-policy.conf - Politicas de red MAC
# ============================================================
# Generado por securizar - Modulo 71

# === SELinux: Booleans de red recomendados ===
# Formato: BOOLEAN=VALUE  (on/off)
# Desactivar acceso de red innecesario para servicios

# httpd/nginx
httpd_can_network_connect=off
httpd_can_network_connect_db=off
httpd_can_sendmail=off

# FTP
ftpd_connect_all_unreserved=off
ftpd_connect_db=off

# Samba
samba_export_all_rw=off
samba_share_nfs=off

# NFS
nfs_export_all_ro=off
nfs_export_all_rw=off

# General
deny_ptrace=on
selinuxuser_ping=on

# === AppArmor: plantilla de reglas de red ===
# Incluir en perfiles de AppArmor:
#   network inet stream,
#   network inet dgram,
#   deny network raw,
#   deny network packet,

# Servicios que NO deben tener acceso de red:
# /usr/bin/at
# /usr/bin/crontab
# /usr/sbin/cupsd (salvo impresion de red)
EOFNETPOL
    chmod 0640 "$MAC_DIR/network-policy.conf"
    log_change "Creado" "$MAC_DIR/network-policy.conf"

    # Aplicar booleans de SELinux si disponible
    if command -v setsebool &>/dev/null && [[ "$MAC_SYSTEM" == "selinux" ]]; then
        log_info "Aplicando booleans de SELinux..."
        while IFS='=' read -r bool val; do
            [[ "$bool" =~ ^#.*$ ]] && continue
            [[ -z "$bool" ]] && continue
            setsebool -P "$bool" "$val" 2>/dev/null && \
                log_change "SELinux" "Boolean $bool=$val" || true
        done < <(grep -E '^[a-z].*=' "$MAC_DIR/network-policy.conf" | head -20)
    fi

else
    log_skip "Politicas de red MAC"
fi

# ============================================================
# S4: CONFINAMIENTO DE SERVICIOS CRITICOS
# ============================================================
log_section "S4: Confinamiento de servicios criticos"

log_info "Verifica y refuerza confinamiento MAC de servicios:"
log_info "  - sshd, nginx, apache, postfix, named, mysql, postgres"
log_info "  - Crea perfiles si no existen"
log_info ""

if check_executable /usr/local/bin/securizar-mac-confine.sh; then
    log_already "Confinamiento de servicios (securizar-mac-confine.sh existe)"
elif ask "Crear herramienta de confinamiento de servicios?"; then

    cat > "$MAC_BIN/securizar-mac-confine.sh" << 'EOFCONFINE'
#!/bin/bash
# ============================================================
# securizar-mac-confine.sh - Confinamiento de servicios criticos
# ============================================================
set -euo pipefail

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BOLD="\033[1m"
NC="\033[0m"

LOG_DIR="/var/log/securizar/mac"
mkdir -p "$LOG_DIR"
REPORT="$LOG_DIR/confine-$(date +%Y%m%d-%H%M%S).log"

log_r() { echo -e "$1" | tee -a "$REPORT"; }

SERVICES=(sshd nginx apache2 httpd postfix named mysqld postgres redis-server)
SCORE=0
TOTAL=0

log_r "${BOLD}=== Confinamiento de servicios criticos ===${NC}"
log_r "Fecha: $(date)"
log_r ""

# Detectar MAC
if command -v getenforce &>/dev/null && [[ "$(getenforce 2>/dev/null)" != "" ]]; then
    log_r "Sistema: SELinux"
    log_r ""

    for svc in "${SERVICES[@]}"; do
        bin_path=$(command -v "$svc" 2>/dev/null || which "$svc" 2>/dev/null || true)
        [[ -z "$bin_path" ]] && continue
        TOTAL=$((TOTAL + 1))

        # Verificar contexto SELinux
        context=$(ls -Z "$bin_path" 2>/dev/null | awk '{print $1}' || echo "unknown")
        if [[ "$context" != *"unconfined"* ]] && [[ "$context" != "unknown" ]]; then
            log_r "  ${GREEN}[OK]${NC} $svc ($bin_path) -> $context"
            SCORE=$((SCORE + 1))
        else
            log_r "  ${YELLOW}[!!]${NC} $svc ($bin_path) -> SIN CONFINAR ($context)"
        fi
    done

elif command -v aa-status &>/dev/null; then
    log_r "Sistema: AppArmor"
    log_r ""

    aa_profiles=$(aa-status 2>/dev/null || true)

    for svc in "${SERVICES[@]}"; do
        bin_path=$(command -v "$svc" 2>/dev/null || which "$svc" 2>/dev/null || true)
        [[ -z "$bin_path" ]] && continue
        TOTAL=$((TOTAL + 1))

        if echo "$aa_profiles" | grep -q "$bin_path"; then
            mode="enforce"
            echo "$aa_profiles" | grep "$bin_path" | grep -q "complain" && mode="complain"
            if [[ "$mode" == "enforce" ]]; then
                log_r "  ${GREEN}[OK]${NC} $svc ($bin_path) -> enforce"
                SCORE=$((SCORE + 1))
            else
                log_r "  ${YELLOW}[!!]${NC} $svc ($bin_path) -> complain (no bloquea)"
            fi
        else
            log_r "  ${RED}[--]${NC} $svc ($bin_path) -> SIN PERFIL"
        fi
    done
else
    log_r "${RED}[!!] No se detecto sistema MAC${NC}"
fi

log_r ""
PCT=0
[[ $TOTAL -gt 0 ]] && PCT=$((SCORE * 100 / TOTAL))
log_r "${BOLD}Servicios confinados: ${SCORE}/${TOTAL} (${PCT}%)${NC}"
log_r "Reporte: $REPORT"
EOFCONFINE
    chmod +x "$MAC_BIN/securizar-mac-confine.sh"
    log_change "Creado" "$MAC_BIN/securizar-mac-confine.sh"

else
    log_skip "Confinamiento de servicios"
fi

# ============================================================
# S5: PROTECCION DE FICHEROS SENSIBLES
# ============================================================
log_section "S5: Proteccion de ficheros sensibles"

log_info "Verifica contextos/perfiles MAC de ficheros criticos:"
log_info "  - /etc/shadow, /etc/passwd, /etc/ssh/, /etc/ssl/private"
log_info "  - SELinux: restorecon, file contexts"
log_info "  - AppArmor: hat profiles para rutas sensibles"
log_info ""

if check_executable /usr/local/bin/securizar-mac-fileprotect.sh; then
    log_already "Proteccion de ficheros (securizar-mac-fileprotect.sh existe)"
elif ask "Crear herramienta de proteccion de ficheros sensibles?"; then

    cat > "$MAC_BIN/securizar-mac-fileprotect.sh" << 'EOFFILEPROTECT'
#!/bin/bash
# ============================================================
# securizar-mac-fileprotect.sh - Proteccion MAC de ficheros sensibles
# ============================================================
set -euo pipefail

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BOLD="\033[1m"
NC="\033[0m"

LOG_DIR="/var/log/securizar/mac"
mkdir -p "$LOG_DIR"
REPORT="$LOG_DIR/fileprotect-$(date +%Y%m%d-%H%M%S).log"

log_r() { echo -e "$1" | tee -a "$REPORT"; }

SENSITIVE_FILES=(
    /etc/shadow
    /etc/gshadow
    /etc/passwd
    /etc/group
    /etc/sudoers
    /etc/ssh/sshd_config
    /etc/ssl/private
    /etc/securizar
)

SCORE=0
TOTAL=0

log_r "${BOLD}=== Proteccion MAC de ficheros sensibles ===${NC}"
log_r "Fecha: $(date)"
log_r ""

if command -v getenforce &>/dev/null && [[ "$(getenforce 2>/dev/null)" != "" ]]; then
    log_r "Sistema: SELinux"
    log_r ""

    for f in "${SENSITIVE_FILES[@]}"; do
        [[ -e "$f" ]] || continue
        TOTAL=$((TOTAL + 1))

        context=$(ls -dZ "$f" 2>/dev/null | awk '{print $1}' || echo "unknown")
        # Verificar contexto correcto
        if [[ "$context" != *"unlabeled"* ]] && [[ "$context" != "unknown" ]]; then
            log_r "  ${GREEN}[OK]${NC} $f -> $context"
            SCORE=$((SCORE + 1))
        else
            log_r "  ${YELLOW}[!!]${NC} $f -> contexto incorrecto: $context"
            # Intentar restaurar
            restorecon -v "$f" 2>/dev/null && \
                log_r "       restorecon aplicado" || true
        fi
    done

elif command -v aa-status &>/dev/null; then
    log_r "Sistema: AppArmor"
    log_r ""

    for f in "${SENSITIVE_FILES[@]}"; do
        [[ -e "$f" ]] || continue
        TOTAL=$((TOTAL + 1))

        # Verificar permisos unix como complemento
        perms=$(stat -c '%a' "$f" 2>/dev/null || echo "???")
        owner=$(stat -c '%U:%G' "$f" 2>/dev/null || echo "???")

        if [[ "$perms" =~ ^[0-6][04][0]$ ]] || [[ -d "$f" ]]; then
            log_r "  ${GREEN}[OK]${NC} $f (perms=$perms owner=$owner)"
            SCORE=$((SCORE + 1))
        else
            log_r "  ${YELLOW}[!!]${NC} $f (perms=$perms owner=$owner) - revisar permisos"
        fi
    done
fi

log_r ""
PCT=0
[[ $TOTAL -gt 0 ]] && PCT=$((SCORE * 100 / TOTAL))
log_r "${BOLD}Ficheros protegidos: ${SCORE}/${TOTAL} (${PCT}%)${NC}"
log_r "Reporte: $REPORT"
EOFFILEPROTECT
    chmod +x "$MAC_BIN/securizar-mac-fileprotect.sh"
    log_change "Creado" "$MAC_BIN/securizar-mac-fileprotect.sh"

else
    log_skip "Proteccion de ficheros sensibles"
fi

# ============================================================
# S6: POLITICAS PARA CONTENEDORES
# ============================================================
log_section "S6: Politicas MAC para contenedores"

log_info "Configura politicas MAC para contenedores:"
log_info "  - SELinux: container_t, docker booleans"
log_info "  - AppArmor: perfiles docker/podman"
log_info ""

if check_file_exists /etc/securizar/mac/container-policy.conf; then
    log_already "Politicas de contenedores (container-policy.conf existe)"
elif ask "Configurar politicas MAC para contenedores?"; then

    cat > "$MAC_DIR/container-policy.conf" << 'EOFCONTPOL'
# ============================================================
# container-policy.conf - Politicas MAC para contenedores
# ============================================================
# Generado por securizar - Modulo 71

# === SELinux: Booleans de contenedores ===
# container_connect_any=off         # contenedores no conectan a cualquier puerto
# container_manage_cgroup=on        # permitir gestion de cgroups
# container_use_cephfs=off          # no usar CephFS
# virt_sandbox_use_all_caps=off     # no dar todas las caps
# virt_sandbox_use_netlink=off      # restringir netlink

# === AppArmor: Perfiles de contenedores ===
# Docker usa por defecto: docker-default
# Podman usa por defecto: containers-default-0.X.X
#
# Para reforzar:
# 1. Crear perfil personalizado en /etc/apparmor.d/containers/
# 2. Cargar: apparmor_parser -r -W /etc/apparmor.d/containers/mi-perfil
# 3. Usar: docker run --security-opt apparmor=mi-perfil ...
#    o:    podman run --security-opt apparmor=mi-perfil ...

# === Recomendaciones generales ===
# - Usar contenedores rootless siempre que sea posible
# - No usar --privileged
# - No usar --security-opt label=disable
# - Auditar denegaciones periodicamente
# - Mantener perfiles actualizados
EOFCONTPOL
    chmod 0640 "$MAC_DIR/container-policy.conf"
    log_change "Creado" "$MAC_DIR/container-policy.conf"

    # Aplicar booleans de SELinux para contenedores
    if command -v setsebool &>/dev/null && [[ "$MAC_SYSTEM" == "selinux" ]]; then
        setsebool -P container_manage_cgroup on 2>/dev/null && \
            log_change "SELinux" "container_manage_cgroup=on" || true
        setsebool -P virt_sandbox_use_all_caps off 2>/dev/null && \
            log_change "SELinux" "virt_sandbox_use_all_caps=off" || true
    fi

else
    log_skip "Politicas de contenedores"
fi

# ============================================================
# S7: AUDITORIA DE DENEGACIONES
# ============================================================
log_section "S7: Auditoria de denegaciones MAC"

log_info "Crea herramienta para analizar denegaciones MAC:"
log_info "  - SELinux: AVC denials en audit.log, audit2allow"
log_info "  - AppArmor: DENIED en syslog/kern.log, aa-logprof"
log_info ""

if check_executable /usr/local/bin/securizar-mac-audit.sh; then
    log_already "Auditoria de denegaciones (securizar-mac-audit.sh existe)"
elif ask "Crear herramienta de auditoria de denegaciones MAC?"; then

    cat > "$MAC_BIN/securizar-mac-audit.sh" << 'EOFMACAUDIT'
#!/bin/bash
# ============================================================
# securizar-mac-audit.sh - Auditoria de denegaciones MAC
# ============================================================
set -euo pipefail

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
BOLD="\033[1m"
NC="\033[0m"

HOURS="${1:-24}"
LOG_DIR="/var/log/securizar/mac"
mkdir -p "$LOG_DIR"
REPORT="$LOG_DIR/denials-$(date +%Y%m%d-%H%M%S).log"

log_r() { echo -e "$1" | tee -a "$REPORT"; }

log_r "${BOLD}=== Auditoria de denegaciones MAC (ultimas ${HOURS}h) ===${NC}"
log_r "Fecha: $(date)"
log_r ""

TOTAL_DENIALS=0

# --- SELinux ---
if command -v getenforce &>/dev/null && [[ "$(getenforce 2>/dev/null)" != "" ]]; then
    log_r "${CYAN}=== SELinux AVC Denials ===${NC}"

    AUDIT_LOG="/var/log/audit/audit.log"
    if [[ -f "$AUDIT_LOG" ]]; then
        # Contar denegaciones recientes
        if command -v ausearch &>/dev/null; then
            denials=$(ausearch -m avc -ts "today" 2>/dev/null | grep -c "denied" || echo "0")
        else
            denials=$(grep -c "avc:.*denied" "$AUDIT_LOG" 2>/dev/null || echo "0")
        fi
        TOTAL_DENIALS=$((TOTAL_DENIALS + denials))
        log_r "  Denegaciones encontradas: $denials"

        if [[ "$denials" -gt 0 ]]; then
            log_r ""
            log_r "  Top 10 denegaciones:"
            if command -v ausearch &>/dev/null; then
                ausearch -m avc -ts "today" 2>/dev/null | \
                    grep "denied" | \
                    sed 's/.*{/  {/' | \
                    sort | uniq -c | sort -rn | head -10 | \
                    while IFS= read -r line; do log_r "    $line"; done
            fi

            # Sugerencia audit2allow
            if command -v audit2allow &>/dev/null; then
                log_r ""
                log_r "  ${YELLOW}Para generar reglas de correccion:${NC}"
                log_r "    ausearch -m avc -ts today | audit2allow -M mi_modulo"
                log_r "    semodule -i mi_modulo.pp"
            fi
        fi
    else
        log_r "  ${DIM}$AUDIT_LOG no encontrado${NC}"
    fi
fi

# --- AppArmor ---
if command -v aa-status &>/dev/null || [[ -d /sys/module/apparmor ]]; then
    log_r ""
    log_r "${CYAN}=== AppArmor DENIED ===${NC}"

    # Buscar en journal o syslog
    if command -v journalctl &>/dev/null; then
        denials=$(journalctl -k --since "${HOURS} hours ago" 2>/dev/null | grep -c "DENIED" || echo "0")
    elif [[ -f /var/log/syslog ]]; then
        denials=$(grep -c "DENIED" /var/log/syslog 2>/dev/null || echo "0")
    elif [[ -f /var/log/kern.log ]]; then
        denials=$(grep -c "DENIED" /var/log/kern.log 2>/dev/null || echo "0")
    else
        denials=0
    fi
    TOTAL_DENIALS=$((TOTAL_DENIALS + denials))
    log_r "  Denegaciones encontradas: $denials"

    if [[ "$denials" -gt 0 ]]; then
        log_r ""
        log_r "  Top 10 perfiles con denegaciones:"
        if command -v journalctl &>/dev/null; then
            journalctl -k --since "${HOURS} hours ago" 2>/dev/null | \
                grep "DENIED" | \
                grep -oP 'profile="[^"]*"' | \
                sort | uniq -c | sort -rn | head -10 | \
                while IFS= read -r line; do log_r "    $line"; done
        fi

        if command -v aa-logprof &>/dev/null; then
            log_r ""
            log_r "  ${YELLOW}Para ajustar perfiles:${NC}"
            log_r "    aa-logprof"
        fi
    fi
fi

log_r ""
log_r "${BOLD}Total denegaciones: ${TOTAL_DENIALS}${NC}"
if [[ "$TOTAL_DENIALS" -eq 0 ]]; then
    log_r "${GREEN}Sin denegaciones en las ultimas ${HOURS}h${NC}"
elif [[ "$TOTAL_DENIALS" -lt 10 ]]; then
    log_r "${YELLOW}Pocas denegaciones - revisar si son esperadas${NC}"
else
    log_r "${RED}Multiples denegaciones - revisar perfiles/politicas${NC}"
fi
log_r "Reporte: $REPORT"
EOFMACAUDIT
    chmod +x "$MAC_BIN/securizar-mac-audit.sh"
    log_change "Creado" "$MAC_BIN/securizar-mac-audit.sh"

    # Cron semanal
    cat > /etc/cron.weekly/securizar-mac-audit << 'EOFCRON'
#!/bin/bash
/usr/local/bin/securizar-mac-audit.sh 168 > /dev/null 2>&1
EOFCRON
    chmod 700 /etc/cron.weekly/securizar-mac-audit
    log_change "Creado" "/etc/cron.weekly/securizar-mac-audit"

else
    log_skip "Auditoria de denegaciones"
fi

# ============================================================
# S8: POLITICAS PERSONALIZADAS
# ============================================================
log_section "S8: Politicas personalizadas"

log_info "Crea plantillas y herramientas para politicas MAC custom:"
log_info "  - SELinux: modulos .te/.pp"
log_info "  - AppArmor: abstractions personalizadas"
log_info ""

if check_executable /usr/local/bin/securizar-mac-custom.sh; then
    log_already "Politicas personalizadas (securizar-mac-custom.sh existe)"
elif ask "Crear herramienta de politicas personalizadas?"; then

    mkdir -p "$MAC_DIR/templates"

    # Plantilla SELinux .te
    cat > "$MAC_DIR/templates/mi_modulo.te" << 'EOFSETE'
# ============================================================
# Plantilla de modulo SELinux
# Uso: checkmodule -M -m -o mi_modulo.mod mi_modulo.te
#      semodule_package -o mi_modulo.pp -m mi_modulo.mod
#      semodule -i mi_modulo.pp
# ============================================================
module mi_modulo 1.0;

require {
    type httpd_t;
    type httpd_sys_content_t;
    class file { read open getattr };
    class dir { search };
}

# Permitir a httpd leer contenido
allow httpd_t httpd_sys_content_t:file { read open getattr };
allow httpd_t httpd_sys_content_t:dir search;
EOFSETE
    log_change "Creado" "$MAC_DIR/templates/mi_modulo.te"

    # Plantilla AppArmor profile
    cat > "$MAC_DIR/templates/mi_perfil_apparmor" << 'EOFAAPROF'
# ============================================================
# Plantilla de perfil AppArmor
# Instalar en: /etc/apparmor.d/usr.local.bin.mi_app
# Cargar: apparmor_parser -r -W /etc/apparmor.d/usr.local.bin.mi_app
# ============================================================
#include <tunables/global>

/usr/local/bin/mi_app {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  # Acceso al binario
  /usr/local/bin/mi_app mr,

  # Configuracion
  /etc/mi_app/ r,
  /etc/mi_app/** r,

  # Logs
  /var/log/mi_app/ rw,
  /var/log/mi_app/** rw,

  # Temporal
  /tmp/mi_app_* rw,

  # Red (descomentar segun necesidad)
  # network inet stream,
  # network inet dgram,

  # Denegar todo lo demas implicitamente
}
EOFAAPROF
    log_change "Creado" "$MAC_DIR/templates/mi_perfil_apparmor"

    # Script helper
    cat > "$MAC_BIN/securizar-mac-custom.sh" << 'EOFCUSTOM'
#!/bin/bash
# ============================================================
# securizar-mac-custom.sh - Crear politicas MAC personalizadas
# ============================================================
set -euo pipefail

echo "=== Creacion de politicas MAC personalizadas ==="
echo ""
echo "Plantillas disponibles en /etc/securizar/mac/templates/:"
echo ""

if [[ -d /etc/securizar/mac/templates ]]; then
    ls -la /etc/securizar/mac/templates/
fi

echo ""
echo "=== SELinux ==="
echo "  1. Editar plantilla:  vi /etc/securizar/mac/templates/mi_modulo.te"
echo "  2. Compilar:          checkmodule -M -m -o mod.mod mod.te"
echo "  3. Empaquetar:        semodule_package -o mod.pp -m mod.mod"
echo "  4. Instalar:          semodule -i mod.pp"
echo "  5. Verificar:         semodule -l | grep mi_modulo"
echo ""
echo "  Desde AVC denials:"
echo "    ausearch -m avc -ts today | audit2allow -M mi_fix"
echo "    semodule -i mi_fix.pp"
echo ""
echo "=== AppArmor ==="
echo "  1. Copiar plantilla:  cp /etc/securizar/mac/templates/mi_perfil_apparmor \\"
echo "                            /etc/apparmor.d/usr.local.bin.mi_app"
echo "  2. Editar perfil:     vi /etc/apparmor.d/usr.local.bin.mi_app"
echo "  3. Cargar:            apparmor_parser -r -W /etc/apparmor.d/usr.local.bin.mi_app"
echo "  4. Verificar:         aa-status | grep mi_app"
echo ""
echo "  Generar perfil auto:  aa-genprof /usr/local/bin/mi_app"
echo "  Ajustar desde logs:   aa-logprof"
EOFCUSTOM
    chmod +x "$MAC_BIN/securizar-mac-custom.sh"
    log_change "Creado" "$MAC_BIN/securizar-mac-custom.sh"

else
    log_skip "Politicas personalizadas"
fi

# ============================================================
# S9: HARDENING MLS/MCS
# ============================================================
log_section "S9: Hardening MLS/MCS"

log_info "Multi-Level/Category Security hardening:"
log_info "  - SELinux: politica MLS, categorias para usuarios"
log_info "  - Documentacion de niveles de sensibilidad"
log_info ""

if check_file_exists /etc/securizar/mac/mls-policy.conf; then
    log_already "Politica MLS/MCS (mls-policy.conf existe)"
elif ask "Configurar politica MLS/MCS?"; then

    cat > "$MAC_DIR/mls-policy.conf" << 'EOFMLS'
# ============================================================
# mls-policy.conf - Configuracion MLS/MCS
# ============================================================
# Generado por securizar - Modulo 71

# === Multi-Category Security (MCS) ===
# MCS permite aislar procesos usando categorias SELinux.
# Cada contenedor/VM recibe una categoria unica (c1, c2, etc.)
# Esto previene acceso entre contenedores incluso del mismo tipo.

# Categorias predefinidas:
# c0-c255    : Categorias disponibles (por defecto en SELinux targeted)
# s0         : Nivel de sensibilidad base
# s0:c0,c1   : Nivel base con categorias 0 y 1

# === Asignacion recomendada ===
# Servicios criticos:     s0:c100-c199
# Contenedores:           s0:c200-c255  (auto-asignado por runtimes)
# Usuarios normales:      s0:c0-c49
# Usuarios privilegiados: s0:c50-c99

# === Multi-Level Security (MLS) ===
# MLS requiere politica 'mls' (no 'targeted')
# Niveles: s0 (unclassified) < s1 (confidential) < s2 (secret) < s3 (top secret)
# ATENCION: Cambiar a MLS requiere relabeling completo del filesystem
# y es una operacion compleja. Solo usar en entornos que lo requieran.

# === Estado actual ===
# Para verificar: sestatus | grep "Loaded policy"
# targeted = MCS habilitado
# mls = MLS completo

# === Comandos utiles ===
# semanage login -l                    # Ver asignaciones de login
# semanage user -l                     # Ver usuarios SELinux
# chcat -l -- +c100 usuario            # Asignar categoria
# runcon -l s0:c100 /bin/bash          # Ejecutar con categoria
EOFMLS
    chmod 0640 "$MAC_DIR/mls-policy.conf"
    log_change "Creado" "$MAC_DIR/mls-policy.conf"

else
    log_skip "Hardening MLS/MCS"
fi

# ============================================================
# S10: AUDITORIA INTEGRAL MAC
# ============================================================
log_section "S10: Auditoria integral MAC"

log_info "Crea herramienta de auditoria integral del sistema MAC."
log_info ""

if check_executable /usr/local/bin/auditoria-mac-completa.sh; then
    log_already "Auditoria integral (auditoria-mac-completa.sh existe)"
elif ask "Crear herramienta de auditoria integral MAC?"; then

    cat > "$MAC_BIN/auditoria-mac-completa.sh" << 'EOFAUDIT'
#!/bin/bash
# ============================================================
# auditoria-mac-completa.sh - Auditoria integral MAC
# ============================================================
set -euo pipefail

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
BOLD="\033[1m"
DIM="\033[2m"
NC="\033[0m"

LOG_DIR="/var/log/securizar/mac"
mkdir -p "$LOG_DIR"
REPORT="$LOG_DIR/audit-integral-$(date +%Y%m%d-%H%M%S).log"

SCORE=0
MAX=0

check() {
    local desc="$1" result="$2"
    MAX=$((MAX + 1))
    if [[ "$result" -eq 0 ]]; then
        echo -e "  ${GREEN}[OK]${NC} $desc" | tee -a "$REPORT"
        SCORE=$((SCORE + 1))
    else
        echo -e "  ${YELLOW}[!!]${NC} $desc" | tee -a "$REPORT"
    fi
}

echo -e "${BOLD}=============================================" | tee "$REPORT"
echo -e "  AUDITORIA INTEGRAL MAC" | tee -a "$REPORT"
echo -e "  $(date '+%Y-%m-%d %H:%M:%S') - $(hostname)" | tee -a "$REPORT"
echo -e "=============================================${NC}" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# 1. Sistema MAC detectado
echo -e "${CYAN}=== 1. Sistema MAC ===${NC}" | tee -a "$REPORT"
if command -v getenforce &>/dev/null && [[ "$(getenforce 2>/dev/null)" != "" ]]; then
    check "SELinux disponible" 0
    mode=$(getenforce 2>/dev/null)
    check "SELinux en Enforcing" "$([[ "$mode" == "Enforcing" ]]; echo $?)"
elif command -v aa-status &>/dev/null; then
    check "AppArmor disponible" 0
    enabled=$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null || echo "N")
    check "AppArmor habilitado" "$([[ "$enabled" == "Y" ]]; echo $?)"
    enforce=$(aa-status 2>/dev/null | grep -c "enforce" || echo "0")
    check "Perfiles en enforce (>0)" "$([[ "$enforce" -gt 0 ]]; echo $?)"
else
    check "Sistema MAC activo" 1
fi

# 2. Herramientas securizar
echo "" | tee -a "$REPORT"
echo -e "${CYAN}=== 2. Herramientas securizar ===${NC}" | tee -a "$REPORT"
check "securizar-mac-status.sh" "$([[ -x /usr/local/bin/securizar-mac-status.sh ]]; echo $?)"
check "securizar-mac-enforce.sh" "$([[ -x /usr/local/bin/securizar-mac-enforce.sh ]]; echo $?)"
check "securizar-mac-confine.sh" "$([[ -x /usr/local/bin/securizar-mac-confine.sh ]]; echo $?)"
check "securizar-mac-fileprotect.sh" "$([[ -x /usr/local/bin/securizar-mac-fileprotect.sh ]]; echo $?)"
check "securizar-mac-audit.sh" "$([[ -x /usr/local/bin/securizar-mac-audit.sh ]]; echo $?)"
check "securizar-mac-custom.sh" "$([[ -x /usr/local/bin/securizar-mac-custom.sh ]]; echo $?)"

# 3. Configuracion
echo "" | tee -a "$REPORT"
echo -e "${CYAN}=== 3. Configuracion ===${NC}" | tee -a "$REPORT"
check "network-policy.conf" "$([[ -f /etc/securizar/mac/network-policy.conf ]]; echo $?)"
check "container-policy.conf" "$([[ -f /etc/securizar/mac/container-policy.conf ]]; echo $?)"
check "mls-policy.conf" "$([[ -f /etc/securizar/mac/mls-policy.conf ]]; echo $?)"
check "Plantillas de politicas" "$([[ -d /etc/securizar/mac/templates ]]; echo $?)"

# 4. Denegaciones recientes
echo "" | tee -a "$REPORT"
echo -e "${CYAN}=== 4. Denegaciones recientes ===${NC}" | tee -a "$REPORT"
denials=0
if [[ -f /var/log/audit/audit.log ]]; then
    denials=$(grep -c "avc:.*denied" /var/log/audit/audit.log 2>/dev/null || echo "0")
fi
if command -v journalctl &>/dev/null; then
    aa_denials=$(journalctl -k --since "24 hours ago" 2>/dev/null | grep -c "DENIED" || echo "0")
    denials=$((denials + aa_denials))
fi
check "Pocas denegaciones (<50 en 24h)" "$([[ "$denials" -lt 50 ]]; echo $?)"
echo -e "  ${DIM}Denegaciones encontradas: $denials${NC}" | tee -a "$REPORT"

# Resumen
echo "" | tee -a "$REPORT"
echo -e "${BOLD}=============================================${NC}" | tee -a "$REPORT"
PCT=0
[[ $MAX -gt 0 ]] && PCT=$((SCORE * 100 / MAX))

if [[ $PCT -ge 80 ]]; then
    echo -e "  ${GREEN}${BOLD}PUNTUACION: ${SCORE}/${MAX} (${PCT}%) - BUENO${NC}" | tee -a "$REPORT"
elif [[ $PCT -ge 50 ]]; then
    echo -e "  ${YELLOW}${BOLD}PUNTUACION: ${SCORE}/${MAX} (${PCT}%) - MEJORABLE${NC}" | tee -a "$REPORT"
else
    echo -e "  ${RED}${BOLD}PUNTUACION: ${SCORE}/${MAX} (${PCT}%) - DEFICIENTE${NC}" | tee -a "$REPORT"
fi
echo -e "${BOLD}=============================================${NC}" | tee -a "$REPORT"
echo -e "${DIM}Reporte: $REPORT${NC}" | tee -a "$REPORT"
logger -t securizar-mac "MAC audit: $SCORE/$MAX ($PCT%)"
EOFAUDIT
    chmod +x "$MAC_BIN/auditoria-mac-completa.sh"
    log_change "Creado" "$MAC_BIN/auditoria-mac-completa.sh"

    # Cron semanal
    cat > /etc/cron.weekly/auditoria-mac << 'EOFCRON'
#!/bin/bash
/usr/local/bin/auditoria-mac-completa.sh > /dev/null 2>&1
EOFCRON
    chmod 700 /etc/cron.weekly/auditoria-mac
    log_change "Creado" "/etc/cron.weekly/auditoria-mac"

else
    log_skip "Auditoria integral MAC"
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
show_changes_summary
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   CONTROL DE ACCESO OBLIGATORIO (MODULO 71) COMPLETADO   ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Sistema MAC detectado: $MAC_SYSTEM"
log_info "Backups guardados en: $BACKUP_DIR"
echo ""
echo "Comandos disponibles:"
echo "  - Estado MAC:       securizar-mac-status.sh"
echo "  - Activar enforce:  securizar-mac-enforce.sh"
echo "  - Confinar svcs:    securizar-mac-confine.sh"
echo "  - Proteger ficheros:securizar-mac-fileprotect.sh"
echo "  - Denegaciones:     securizar-mac-audit.sh [horas]"
echo "  - Politicas custom: securizar-mac-custom.sh"
echo "  - Auditoria:        auditoria-mac-completa.sh"
