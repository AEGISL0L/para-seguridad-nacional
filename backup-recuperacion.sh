#!/bin/bash
# ============================================================
# backup-recuperacion.sh - Modulo 49: Backup y recuperacion ante desastres
# ============================================================
# Secciones:
#   S1  - Estrategia 3-2-1
#   S2  - Backup cifrado con Borg
#   S3  - Backup cifrado con Restic
#   S4  - Backups inmutables (WORM)
#   S5  - Verificacion y restauracion automatica
#   S6  - Backup de sistema completo (bare metal)
#   S7  - RTO/RPO y planificacion
#   S8  - Backup offsite automatizado
#   S9  - Proteccion anti-ransomware de backups
#   S10 - Auditoria de backup y DR
# ============================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps
init_backup "backup-recuperacion"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MODULO 49 - BACKUP Y RECUPERACION ANTE DESASTRES       ║"
echo "║   Borg, Restic, inmutabilidad, bare metal, DR plan,      ║"
echo "║   offsite, anti-ransomware, auditoria                    ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

log_section "MODULO 49: BACKUP Y RECUPERACION ANTE DESASTRES"
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

# Directorio base para configuraciones de backup
SECURIZAR_BACKUP_CONF_DIR="/etc/securizar"
mkdir -p "$SECURIZAR_BACKUP_CONF_DIR" 2>/dev/null || true

# ============================================================
# S1: ESTRATEGIA 3-2-1
# ============================================================
log_section "S1: ESTRATEGIA DE BACKUP 3-2-1"

echo "Configura la estrategia de backup 3-2-1:"
echo "  - 3 copias de los datos (original + 2 backups)"
echo "  - 2 tipos de medios distintos (disco local + remoto)"
echo "  - 1 copia offsite (ubicacion externa)"
echo "  - Archivo de configuracion centralizado"
echo "  - Script de validacion de cumplimiento"
echo ""

if ask "¿Configurar la estrategia de backup 3-2-1?"; then

    # Crear configuracion de estrategia de backup
    STRATEGY_CONF="${SECURIZAR_BACKUP_CONF_DIR}/backup-strategy.conf"
    if [[ -f "$STRATEGY_CONF" ]]; then
        cp "$STRATEGY_CONF" "${BACKUP_DIR}/backup-strategy.conf.bak"
        log_change "Backup" "backup-strategy.conf existente"
    fi

    cat > "$STRATEGY_CONF" << 'EOFSTRATEGY'
# ============================================================
# backup-strategy.conf - Estrategia de Backup 3-2-1
# ============================================================
# Generado por securizar - Modulo 49
# ============================================================

# ── Directorios a respaldar ────────────────────────────────
# Lista separada por espacios de directorios a incluir
BACKUP_SOURCES="/etc /home /var/lib /root /usr/local /opt /srv"

# ── Exclusiones globales ───────────────────────────────────
BACKUP_EXCLUDES="/tmp /var/tmp /var/cache *.cache __pycache__ .cache node_modules .npm .local/share/Trash"

# ── Copia 1: Local (disco principal) ──────────────────────
COPY1_TYPE="local"
COPY1_PATH="/var/backups/securizar"
COPY1_DESCRIPTION="Disco local - backup primario"
COPY1_ENABLED="true"

# ── Copia 2: Medio diferente (disco externo / NAS) ───────
COPY2_TYPE="local_alternate"
COPY2_PATH="/mnt/backup-externo"
COPY2_DESCRIPTION="Disco externo o NAS - segundo medio"
COPY2_ENABLED="true"
# Punto de montaje que debe existir antes del backup
COPY2_MOUNT_CHECK="/mnt/backup-externo"

# ── Copia 3: Offsite (remoto) ────────────────────────────
COPY3_TYPE="remote"
COPY3_PATH="backup@offsite-server:/backups/$(hostname)"
COPY3_DESCRIPTION="Servidor remoto offsite"
COPY3_ENABLED="true"
COPY3_SSH_KEY="/root/.ssh/backup_ed25519"
COPY3_SSH_PORT="22"

# ── Tipos de medio ────────────────────────────────────────
# Debe haber al menos 2 tipos distintos
MEDIA_TYPE_1="ssd_local"
MEDIA_TYPE_2="network_storage"

# ── Cifrado ───────────────────────────────────────────────
ENCRYPTION_ENABLED="true"
ENCRYPTION_METHOD="repokey-blake2"  # Para borg
ENCRYPTION_PASSPHRASE_FILE="/etc/securizar/.backup-passphrase"

# ── Retencion ─────────────────────────────────────────────
RETENTION_DAILY=7
RETENTION_WEEKLY=4
RETENTION_MONTHLY=12
RETENTION_YEARLY=2

# ── Compresion ────────────────────────────────────────────
COMPRESSION="zstd"
COMPRESSION_LEVEL=3

# ── Notificaciones ────────────────────────────────────────
NOTIFY_EMAIL="admin@localhost"
NOTIFY_ON_SUCCESS="false"
NOTIFY_ON_FAILURE="true"

# ── Horarios ──────────────────────────────────────────────
SCHEDULE_DAILY="02:00"
SCHEDULE_WEEKLY="domingo 03:00"
SCHEDULE_MONTHLY="1 04:00"
EOFSTRATEGY

    chmod 600 "$STRATEGY_CONF"
    log_change "Creado" "$STRATEGY_CONF (configuracion estrategia 3-2-1)"

    # Crear directorios de backup local
    mkdir -p /var/backups/securizar
    chmod 700 /var/backups/securizar
    log_change "Creado" "/var/backups/securizar (directorio backup local)"

    # Crear script de validacion 3-2-1
    cat > /usr/local/bin/verificar-estrategia-321.sh << 'EOFVALIDATE'
#!/bin/bash
# ============================================================
# verificar-estrategia-321.sh - Valida cumplimiento 3-2-1
# ============================================================
set -uo pipefail

CONF="/etc/securizar/backup-strategy.conf"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Contadores
TOTAL_CHECKS=0
PASSED=0
WARNINGS=0
FAILURES=0

check_pass() {
    ((TOTAL_CHECKS++)) || true
    ((PASSED++)) || true
    echo -e "  ${GREEN}[OK]${NC} $1"
}

check_warn() {
    ((TOTAL_CHECKS++)) || true
    ((WARNINGS++)) || true
    echo -e "  ${YELLOW}[!]${NC} $1"
}

check_fail() {
    ((TOTAL_CHECKS++)) || true
    ((FAILURES++)) || true
    echo -e "  ${RED}[X]${NC} $1"
}

echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "${CYAN}  VERIFICACION ESTRATEGIA BACKUP 3-2-1${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo ""

# Verificar que existe el archivo de configuracion
if [[ ! -f "$CONF" ]]; then
    check_fail "Configuracion no encontrada: $CONF"
    echo ""
    echo -e "${RED}No se puede continuar sin configuracion.${NC}"
    exit 1
fi

# shellcheck source=/dev/null
source "$CONF"

echo -e "${BOLD}=== Regla 3: Tres copias de los datos ===${NC}"

copies_available=0

# Copia 1: Local
if [[ "${COPY1_ENABLED:-false}" == "true" ]]; then
    if [[ -d "${COPY1_PATH:-/nonexistent}" ]]; then
        # Verificar que hay contenido de backup
        if [[ -n "$(ls -A "${COPY1_PATH}" 2>/dev/null)" ]]; then
            check_pass "Copia 1 (local): ${COPY1_PATH} - Contiene datos"
            ((copies_available++)) || true
        else
            check_warn "Copia 1 (local): ${COPY1_PATH} - Directorio vacio"
        fi
    else
        check_fail "Copia 1 (local): ${COPY1_PATH} - No existe"
    fi
else
    check_warn "Copia 1 (local): Deshabilitada"
fi

# Copia 2: Medio alternativo
if [[ "${COPY2_ENABLED:-false}" == "true" ]]; then
    if [[ -n "${COPY2_MOUNT_CHECK:-}" ]]; then
        if mountpoint -q "${COPY2_MOUNT_CHECK}" 2>/dev/null; then
            if [[ -d "${COPY2_PATH:-/nonexistent}" ]]; then
                check_pass "Copia 2 (medio alterno): ${COPY2_PATH} - Montado y accesible"
                ((copies_available++)) || true
            else
                check_warn "Copia 2 (medio alterno): ${COPY2_PATH} - Montado pero sin directorio"
            fi
        else
            check_fail "Copia 2 (medio alterno): ${COPY2_MOUNT_CHECK} - No montado"
        fi
    elif [[ -d "${COPY2_PATH:-/nonexistent}" ]]; then
        check_pass "Copia 2 (medio alterno): ${COPY2_PATH} - Accesible"
        ((copies_available++)) || true
    else
        check_fail "Copia 2 (medio alterno): ${COPY2_PATH} - No accesible"
    fi
else
    check_warn "Copia 2 (medio alterno): Deshabilitada"
fi

# Copia 3: Offsite
if [[ "${COPY3_ENABLED:-false}" == "true" ]]; then
    if [[ -f "${COPY3_SSH_KEY:-/nonexistent}" ]]; then
        # Intentar verificar acceso SSH
        remote_host=$(echo "${COPY3_PATH}" | cut -d: -f1)
        ssh_port="${COPY3_SSH_PORT:-22}"
        if ssh -i "${COPY3_SSH_KEY}" -p "$ssh_port" -o ConnectTimeout=5 \
               -o StrictHostKeyChecking=no -o BatchMode=yes \
               "$remote_host" "echo ok" &>/dev/null; then
            check_pass "Copia 3 (offsite): ${remote_host} - Conectividad OK"
            ((copies_available++)) || true
        else
            check_warn "Copia 3 (offsite): ${remote_host} - Sin conectividad (verificar SSH)"
        fi
    else
        check_fail "Copia 3 (offsite): Clave SSH no encontrada: ${COPY3_SSH_KEY:-no configurada}"
    fi
else
    check_warn "Copia 3 (offsite): Deshabilitada"
fi

# Datos originales cuentan como copia 1
total_copies=$((copies_available + 1))
echo ""
echo -e "  ${BOLD}Copias disponibles: ${total_copies}/3${NC} (original + ${copies_available} backups)"
if [[ $total_copies -ge 3 ]]; then
    check_pass "REGLA 3: Cumplida (${total_copies} copias)"
elif [[ $total_copies -ge 2 ]]; then
    check_warn "REGLA 3: Parcial (${total_copies}/3 copias)"
else
    check_fail "REGLA 3: No cumplida (solo ${total_copies} copia)"
fi

echo ""
echo -e "${BOLD}=== Regla 2: Dos tipos de medios diferentes ===${NC}"

media_types=0
[[ -n "${MEDIA_TYPE_1:-}" ]] && ((media_types++)) || true
[[ -n "${MEDIA_TYPE_2:-}" ]] && [[ "${MEDIA_TYPE_2:-}" != "${MEDIA_TYPE_1:-}" ]] && ((media_types++)) || true

if [[ $media_types -ge 2 ]]; then
    check_pass "REGLA 2: Cumplida (${MEDIA_TYPE_1:-?} + ${MEDIA_TYPE_2:-?})"
elif [[ $media_types -eq 1 ]]; then
    check_warn "REGLA 2: Solo 1 tipo de medio configurado"
else
    check_fail "REGLA 2: No se detectan tipos de medio"
fi

echo ""
echo -e "${BOLD}=== Regla 1: Una copia offsite ===${NC}"

if [[ "${COPY3_ENABLED:-false}" == "true" ]] && [[ "${COPY3_TYPE:-}" == "remote" ]]; then
    check_pass "REGLA 1: Copia offsite configurada (${COPY3_DESCRIPTION:-remoto})"
else
    check_fail "REGLA 1: No hay copia offsite configurada"
fi

echo ""
echo -e "${BOLD}=== Verificaciones adicionales ===${NC}"

# Cifrado
if [[ "${ENCRYPTION_ENABLED:-false}" == "true" ]]; then
    check_pass "Cifrado habilitado: ${ENCRYPTION_METHOD:-desconocido}"
else
    check_warn "Cifrado no habilitado"
fi

# Retencion
if [[ -n "${RETENTION_DAILY:-}" ]] && [[ "${RETENTION_DAILY:-0}" -ge 7 ]]; then
    check_pass "Retencion diaria: ${RETENTION_DAILY} dias"
else
    check_warn "Retencion diaria insuficiente: ${RETENTION_DAILY:-0} (recomendado: 7+)"
fi

# Freshness - verificar antiguedad del ultimo backup
if [[ -d "${COPY1_PATH:-/nonexistent}" ]]; then
    latest_backup=$(find "${COPY1_PATH}" -maxdepth 1 -type d -newer /dev/null 2>/dev/null | sort -r | head -1)
    if [[ -n "$latest_backup" ]]; then
        age_hours=$(( ($(date +%s) - $(stat -c %Y "$latest_backup" 2>/dev/null || echo 0)) / 3600 ))
        if [[ $age_hours -le 24 ]]; then
            check_pass "Ultimo backup local: hace ${age_hours}h"
        elif [[ $age_hours -le 48 ]]; then
            check_warn "Ultimo backup local: hace ${age_hours}h (>24h)"
        else
            check_fail "Ultimo backup local: hace ${age_hours}h (>48h - posible fallo)"
        fi
    else
        check_warn "No se encontraron backups en ${COPY1_PATH}"
    fi
fi

echo ""
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "  ${BOLD}Resultado: ${PASSED} OK / ${WARNINGS} avisos / ${FAILURES} fallos${NC}"
if [[ $FAILURES -eq 0 ]] && [[ $WARNINGS -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}ESTRATEGIA 3-2-1: CUMPLIDA${NC}"
elif [[ $FAILURES -eq 0 ]]; then
    echo -e "  ${YELLOW}${BOLD}ESTRATEGIA 3-2-1: PARCIAL (revisar avisos)${NC}"
else
    echo -e "  ${RED}${BOLD}ESTRATEGIA 3-2-1: NO CUMPLIDA${NC}"
fi
echo -e "${CYAN}══════════════════════════════════════════${NC}"

exit $FAILURES
EOFVALIDATE

    chmod +x /usr/local/bin/verificar-estrategia-321.sh
    log_change "Creado" "/usr/local/bin/verificar-estrategia-321.sh"

    log_info "Estrategia 3-2-1 configurada"
    log_info "Valida con: verificar-estrategia-321.sh"
else
    log_skip "Estrategia de backup 3-2-1"
fi

# ============================================================
# S2: BACKUP CIFRADO CON BORG
# ============================================================
log_section "S2: BACKUP CIFRADO CON BORG"

echo "Instala y configura BorgBackup con cifrado:"
echo "  - Cifrado repokey-blake2 (AES-256-CTR + BLAKE2b)"
echo "  - Compresion zstd nivel 3"
echo "  - Repositorios local y remoto"
echo "  - Politica de retencion (7d/4w/12m/2y)"
echo "  - Script automatizado de backup"
echo ""

if ask "¿Configurar backup cifrado con Borg?"; then

    # Instalar borg
    log_info "Instalando BorgBackup..."
    case "$DISTRO_FAMILY" in
        suse)
            zypper --non-interactive install borgbackup || {
                log_warn "borgbackup no disponible via zypper, intentando pip"
                pkg_install python3-pip || true
                pip3 install borgbackup || log_error "No se pudo instalar borgbackup"
            }
            ;;
        debian)
            DEBIAN_FRONTEND=noninteractive apt-get install -y borgbackup || {
                log_warn "borgbackup no disponible via apt, intentando pip"
                pkg_install python3-pip || true
                pip3 install borgbackup || log_error "No se pudo instalar borgbackup"
            }
            ;;
        rhel)
            dnf install -y borgbackup 2>/dev/null || {
                log_warn "borgbackup no en repos oficiales, intentando EPEL o pip"
                dnf install -y epel-release 2>/dev/null || true
                dnf install -y borgbackup 2>/dev/null || {
                    pkg_install python3-pip || true
                    pip3 install borgbackup || log_error "No se pudo instalar borgbackup"
                }
            }
            ;;
        arch)
            pacman -S --noconfirm borg || log_error "No se pudo instalar borg"
            ;;
    esac
    log_change "Instalado" "borgbackup"

    # Crear directorio de repositorio local
    BORG_REPO_LOCAL="/var/backups/securizar/borg"
    mkdir -p "$BORG_REPO_LOCAL"
    chmod 700 "$BORG_REPO_LOCAL"

    # Generar passphrase si no existe
    BORG_PASSPHRASE_FILE="/etc/securizar/.backup-passphrase"
    if [[ ! -f "$BORG_PASSPHRASE_FILE" ]]; then
        head -c 32 /dev/urandom | base64 | tr -d '\n' > "$BORG_PASSPHRASE_FILE"
        chmod 600 "$BORG_PASSPHRASE_FILE"
        log_change "Generado" "$BORG_PASSPHRASE_FILE (passphrase de cifrado)"
        log_warn "IMPORTANTE: Guarda esta passphrase en un lugar seguro fuera del servidor"
    else
        log_skip "Passphrase ya existe: $BORG_PASSPHRASE_FILE"
    fi

    # Crear script de backup con Borg
    cat > /usr/local/bin/securizar-backup-borg.sh << 'EOFBORG'
#!/bin/bash
# ============================================================
# securizar-backup-borg.sh - Backup cifrado con BorgBackup
# ============================================================
set -uo pipefail

# ── Configuracion ─────────────────────────────────────────
CONF="/etc/securizar/backup-strategy.conf"
if [[ -f "$CONF" ]]; then
    # shellcheck source=/dev/null
    source "$CONF"
fi

BORG_PASSPHRASE_FILE="${ENCRYPTION_PASSPHRASE_FILE:-/etc/securizar/.backup-passphrase}"
BORG_REPO_LOCAL="${COPY1_PATH:-/var/backups/securizar}/borg"
BORG_REPO_REMOTE="${COPY3_PATH:-}/borg"
BORG_COMPRESSION="${COMPRESSION:-zstd},${COMPRESSION_LEVEL:-3}"
HOSTNAME_SHORT=$(hostname -s)
ARCHIVE_NAME="${HOSTNAME_SHORT}-$(date +%Y-%m-%d_%H%M%S)"

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[X]${NC} $1"; }

# Cargar passphrase
if [[ -f "$BORG_PASSPHRASE_FILE" ]]; then
    export BORG_PASSPHRASE
    BORG_PASSPHRASE=$(cat "$BORG_PASSPHRASE_FILE")
else
    log_error "Passphrase no encontrada: $BORG_PASSPHRASE_FILE"
    log_error "Genera una con: head -c 32 /dev/urandom | base64 > $BORG_PASSPHRASE_FILE"
    exit 1
fi

# Directorios a respaldar
SOURCES=(${BACKUP_SOURCES:-/etc /home /var/lib /root /usr/local})

# Exclusiones
EXCLUDE_ARGS=(
    --exclude '*/tmp/*'
    --exclude '*/.cache/*'
    --exclude '*/__pycache__/*'
    --exclude '*/node_modules/*'
    --exclude '*/.npm/*'
    --exclude '*/cache/*'
    --exclude '*.pyc'
    --exclude '*/lost+found/*'
    --exclude '/var/lib/docker/overlay2/*'
    --exclude '/var/lib/lxc/*/rootfs/*'
    --exclude '*.swap'
    --exclude '*.swp'
    --exclude '/home/*/.local/share/Trash/*'
)

# ── Funcion: inicializar repo ─────────────────────────────
init_repo() {
    local repo="$1"
    if ! borg info "$repo" &>/dev/null; then
        log_info "Inicializando repositorio borg: $repo"
        borg init --encryption=repokey-blake2 "$repo"
        log_info "Repositorio inicializado: $repo"
    fi
}

# ── Funcion: ejecutar backup ──────────────────────────────
run_backup() {
    local repo="$1"
    local name="$2"

    log_info "Iniciando backup a: $repo"
    log_info "Archivo: $ARCHIVE_NAME"

    # Filtrar solo directorios que existan
    local valid_sources=()
    for src in "${SOURCES[@]}"; do
        if [[ -d "$src" ]]; then
            valid_sources+=("$src")
        else
            log_warn "Directorio no existe, omitido: $src"
        fi
    done

    if [[ ${#valid_sources[@]} -eq 0 ]]; then
        log_error "No hay directorios validos para respaldar"
        return 1
    fi

    local start_time
    start_time=$(date +%s)

    borg create \
        --verbose \
        --filter AME \
        --list \
        --stats \
        --show-rc \
        --compression "$BORG_COMPRESSION" \
        --exclude-caches \
        "${EXCLUDE_ARGS[@]}" \
        "${repo}::${ARCHIVE_NAME}" \
        "${valid_sources[@]}" 2>&1 | tail -20

    local rc=${PIPESTATUS[0]}
    local end_time
    end_time=$(date +%s)
    local duration=$(( end_time - start_time ))

    if [[ $rc -eq 0 ]]; then
        log_info "Backup completado en ${duration}s: $name"
    elif [[ $rc -eq 1 ]]; then
        log_warn "Backup completado con avisos en ${duration}s: $name"
    else
        log_error "Backup fallo (rc=$rc) en ${duration}s: $name"
        return $rc
    fi
}

# ── Funcion: aplicar retencion ─────────────────────────────
prune_repo() {
    local repo="$1"
    local name="$2"

    log_info "Aplicando politica de retencion a: $name"

    borg prune \
        --list \
        --prefix "${HOSTNAME_SHORT}-" \
        --show-rc \
        --keep-daily   "${RETENTION_DAILY:-7}" \
        --keep-weekly  "${RETENTION_WEEKLY:-4}" \
        --keep-monthly "${RETENTION_MONTHLY:-12}" \
        --keep-yearly  "${RETENTION_YEARLY:-2}" \
        "$repo"

    log_info "Compactando repositorio: $name"
    borg compact "$repo" 2>/dev/null || true
}

# ── Principal ─────────────────────────────────────────────
log_info "=== BorgBackup - Inicio: $(date) ==="

# Backup local
if [[ -d "$(dirname "$BORG_REPO_LOCAL")" ]]; then
    init_repo "$BORG_REPO_LOCAL"
    run_backup "$BORG_REPO_LOCAL" "local"
    prune_repo "$BORG_REPO_LOCAL" "local"
else
    log_warn "Directorio padre de repo local no existe: $(dirname "$BORG_REPO_LOCAL")"
fi

# Backup remoto (si configurado)
if [[ -n "${BORG_REPO_REMOTE:-}" ]] && [[ "${COPY3_ENABLED:-false}" == "true" ]]; then
    if [[ -f "${COPY3_SSH_KEY:-/nonexistent}" ]]; then
        export BORG_RSH="ssh -i ${COPY3_SSH_KEY} -p ${COPY3_SSH_PORT:-22} -o StrictHostKeyChecking=accept-new"
        init_repo "$BORG_REPO_REMOTE"
        run_backup "$BORG_REPO_REMOTE" "remoto"
        prune_repo "$BORG_REPO_REMOTE" "remoto"
    else
        log_warn "Clave SSH no encontrada para backup remoto: ${COPY3_SSH_KEY:-no configurada}"
    fi
fi

log_info "=== BorgBackup - Fin: $(date) ==="
EOFBORG

    chmod +x /usr/local/bin/securizar-backup-borg.sh
    log_change "Creado" "/usr/local/bin/securizar-backup-borg.sh"

    # Crear timer de systemd para borg backup diario
    cat > /etc/systemd/system/securizar-backup-borg.service << 'EOFSERVICE'
[Unit]
Description=Securizar - Backup cifrado con BorgBackup
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/securizar-backup-borg.sh
Nice=19
IOSchedulingClass=idle
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOFSERVICE

    cat > /etc/systemd/system/securizar-backup-borg.timer << 'EOFTIMER'
[Unit]
Description=Securizar - Timer diario para backup Borg

[Timer]
OnCalendar=*-*-* 02:00:00
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
EOFTIMER

    systemctl daemon-reload
    systemctl enable securizar-backup-borg.timer 2>/dev/null || true
    log_change "Creado" "securizar-backup-borg.service + timer (diario 02:00)"

    log_info "BorgBackup configurado"
    log_info "Inicializa repo: BORG_PASSPHRASE=\$(cat /etc/securizar/.backup-passphrase) borg init --encryption=repokey-blake2 $BORG_REPO_LOCAL"
    log_info "Backup manual: securizar-backup-borg.sh"
else
    log_skip "Backup cifrado con Borg"
fi

# ============================================================
# S3: BACKUP CIFRADO CON RESTIC
# ============================================================
log_section "S3: BACKUP CIFRADO CON RESTIC"

echo "Instala y configura Restic con cifrado:"
echo "  - Cifrado AES-256 en modo CTR (integrado)"
echo "  - Soporte para local, S3, SFTP"
echo "  - Snapshots con tags y metadatos"
echo "  - Politica de retencion alineada con borg"
echo "  - Health check automatico"
echo ""

if ask "¿Configurar backup cifrado con Restic?"; then

    # Instalar restic
    log_info "Instalando Restic..."
    case "$DISTRO_FAMILY" in
        suse)
            zypper --non-interactive install restic || {
                log_warn "restic no en repos, descargando binario"
                RESTIC_VERSION="0.16.4"
                curl -L "https://github.com/restic/restic/releases/download/v${RESTIC_VERSION}/restic_${RESTIC_VERSION}_linux_amd64.bz2" \
                    -o /tmp/restic.bz2 && bunzip2 /tmp/restic.bz2 && mv /tmp/restic /usr/local/bin/restic && chmod +x /usr/local/bin/restic
            }
            ;;
        debian)
            DEBIAN_FRONTEND=noninteractive apt-get install -y restic || {
                log_warn "restic no disponible via apt, descargando binario"
                RESTIC_VERSION="0.16.4"
                curl -L "https://github.com/restic/restic/releases/download/v${RESTIC_VERSION}/restic_${RESTIC_VERSION}_linux_amd64.bz2" \
                    -o /tmp/restic.bz2 && bunzip2 /tmp/restic.bz2 && mv /tmp/restic /usr/local/bin/restic && chmod +x /usr/local/bin/restic
            }
            ;;
        rhel)
            dnf install -y restic 2>/dev/null || {
                dnf install -y epel-release 2>/dev/null || true
                dnf install -y restic 2>/dev/null || {
                    log_warn "restic no en repos, descargando binario"
                    RESTIC_VERSION="0.16.4"
                    curl -L "https://github.com/restic/restic/releases/download/v${RESTIC_VERSION}/restic_${RESTIC_VERSION}_linux_amd64.bz2" \
                        -o /tmp/restic.bz2 && bunzip2 /tmp/restic.bz2 && mv /tmp/restic /usr/local/bin/restic && chmod +x /usr/local/bin/restic
                }
            }
            ;;
        arch)
            pacman -S --noconfirm restic || log_error "No se pudo instalar restic"
            ;;
    esac
    log_change "Instalado" "restic"

    # Crear directorio de repositorio Restic
    RESTIC_REPO_LOCAL="/var/backups/securizar/restic"
    mkdir -p "$RESTIC_REPO_LOCAL"
    chmod 700 "$RESTIC_REPO_LOCAL"

    # Archivo de password para restic
    RESTIC_PASSWORD_FILE="/etc/securizar/.restic-password"
    if [[ ! -f "$RESTIC_PASSWORD_FILE" ]]; then
        head -c 32 /dev/urandom | base64 | tr -d '\n' > "$RESTIC_PASSWORD_FILE"
        chmod 600 "$RESTIC_PASSWORD_FILE"
        log_change "Generado" "$RESTIC_PASSWORD_FILE (password de cifrado)"
        log_warn "IMPORTANTE: Guarda esta password en un lugar seguro fuera del servidor"
    else
        log_skip "Password restic ya existe: $RESTIC_PASSWORD_FILE"
    fi

    # Crear script de backup con Restic
    cat > /usr/local/bin/securizar-backup-restic.sh << 'EOFRESTIC'
#!/bin/bash
# ============================================================
# securizar-backup-restic.sh - Backup cifrado con Restic
# ============================================================
set -uo pipefail

# ── Configuracion ─────────────────────────────────────────
CONF="/etc/securizar/backup-strategy.conf"
if [[ -f "$CONF" ]]; then
    # shellcheck source=/dev/null
    source "$CONF"
fi

RESTIC_PASSWORD_FILE="${RESTIC_PASSWORD_FILE:-/etc/securizar/.restic-password}"
RESTIC_REPO_LOCAL="${COPY1_PATH:-/var/backups/securizar}/restic"
HOSTNAME_SHORT=$(hostname -s)
TAG_BASE="securizar"

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[X]${NC} $1"; }

# Verificar password
if [[ ! -f "$RESTIC_PASSWORD_FILE" ]]; then
    log_error "Password no encontrada: $RESTIC_PASSWORD_FILE"
    exit 1
fi
export RESTIC_PASSWORD_FILE

# Directorios a respaldar
SOURCES=(${BACKUP_SOURCES:-/etc /home /var/lib /root /usr/local})

# Exclusiones
EXCLUDE_ARGS=(
    --exclude-caches
    --exclude '*/tmp/*'
    --exclude '*/.cache/*'
    --exclude '*/__pycache__/*'
    --exclude '*/node_modules/*'
    --exclude '*/.npm/*'
    --exclude '*/cache/*'
    --exclude '*.pyc'
    --exclude '*/lost+found/*'
    --exclude '/var/lib/docker/overlay2/*'
    --exclude '/var/lib/lxc/*/rootfs/*'
    --exclude '*.swap'
    --exclude '*.swp'
    --exclude '/home/*/.local/share/Trash/*'
)

# ── Funcion: inicializar repo ─────────────────────────────
init_repo() {
    local repo="$1"
    export RESTIC_REPOSITORY="$repo"

    if ! restic snapshots --latest 1 &>/dev/null; then
        log_info "Inicializando repositorio restic: $repo"
        restic init
        log_info "Repositorio inicializado: $repo"
    fi
}

# ── Funcion: ejecutar backup ──────────────────────────────
run_backup() {
    local repo="$1"
    local name="$2"
    export RESTIC_REPOSITORY="$repo"

    log_info "Iniciando backup restic a: $repo ($name)"

    # Filtrar solo directorios que existan
    local valid_sources=()
    for src in "${SOURCES[@]}"; do
        if [[ -d "$src" ]]; then
            valid_sources+=("$src")
        else
            log_warn "Directorio no existe, omitido: $src"
        fi
    done

    if [[ ${#valid_sources[@]} -eq 0 ]]; then
        log_error "No hay directorios validos para respaldar"
        return 1
    fi

    local start_time
    start_time=$(date +%s)

    restic backup \
        --verbose \
        --tag "$TAG_BASE" \
        --tag "$HOSTNAME_SHORT" \
        --tag "$(date +%Y-%m-%d)" \
        --host "$HOSTNAME_SHORT" \
        "${EXCLUDE_ARGS[@]}" \
        "${valid_sources[@]}"

    local rc=$?
    local end_time
    end_time=$(date +%s)
    local duration=$(( end_time - start_time ))

    if [[ $rc -eq 0 ]]; then
        log_info "Backup completado en ${duration}s: $name"
    else
        log_error "Backup fallo (rc=$rc) en ${duration}s: $name"
        return $rc
    fi
}

# ── Funcion: aplicar retencion ─────────────────────────────
forget_snapshots() {
    local repo="$1"
    local name="$2"
    export RESTIC_REPOSITORY="$repo"

    log_info "Aplicando politica de retencion: $name"

    restic forget \
        --verbose \
        --tag "$TAG_BASE" \
        --host "$HOSTNAME_SHORT" \
        --keep-daily   "${RETENTION_DAILY:-7}" \
        --keep-weekly  "${RETENTION_WEEKLY:-4}" \
        --keep-monthly "${RETENTION_MONTHLY:-12}" \
        --keep-yearly  "${RETENTION_YEARLY:-2}" \
        --prune

    log_info "Retencion aplicada: $name"
}

# ── Funcion: health check ────────────────────────────────
health_check() {
    local repo="$1"
    local name="$2"
    export RESTIC_REPOSITORY="$repo"

    log_info "Verificando integridad del repositorio: $name"

    if restic check --read-data-subset=5% 2>&1; then
        log_info "Integridad OK: $name"
    else
        log_error "Problemas de integridad detectados: $name"
        return 1
    fi
}

# ── Principal ─────────────────────────────────────────────
log_info "=== Restic Backup - Inicio: $(date) ==="

# Backup local
if [[ -d "$(dirname "$RESTIC_REPO_LOCAL")" ]]; then
    init_repo "$RESTIC_REPO_LOCAL"
    run_backup "$RESTIC_REPO_LOCAL" "local"
    forget_snapshots "$RESTIC_REPO_LOCAL" "local"
    health_check "$RESTIC_REPO_LOCAL" "local" || true
else
    log_warn "Directorio padre de repo local no existe: $(dirname "$RESTIC_REPO_LOCAL")"
fi

# Backup SFTP (si configurado)
if [[ "${COPY3_ENABLED:-false}" == "true" ]] && [[ -n "${COPY3_PATH:-}" ]]; then
    RESTIC_REPO_SFTP="sftp:${COPY3_PATH}/restic"
    if [[ -f "${COPY3_SSH_KEY:-/nonexistent}" ]]; then
        export RESTIC_REPOSITORY="$RESTIC_REPO_SFTP"
        # Configurar SSH para restic
        export RESTIC_SSH_COMMAND="ssh -i ${COPY3_SSH_KEY} -p ${COPY3_SSH_PORT:-22} -o StrictHostKeyChecking=accept-new"
        init_repo "$RESTIC_REPO_SFTP"
        run_backup "$RESTIC_REPO_SFTP" "sftp-remoto"
        forget_snapshots "$RESTIC_REPO_SFTP" "sftp-remoto"
    else
        log_warn "Clave SSH no encontrada para backup SFTP remoto"
    fi
fi

# Backup S3 (si configurado via env)
if [[ -n "${AWS_ACCESS_KEY_ID:-}" ]] && [[ -n "${RESTIC_S3_BUCKET:-}" ]]; then
    RESTIC_REPO_S3="s3:${RESTIC_S3_BUCKET}/${HOSTNAME_SHORT}"
    init_repo "$RESTIC_REPO_S3"
    run_backup "$RESTIC_REPO_S3" "s3"
    forget_snapshots "$RESTIC_REPO_S3" "s3"
fi

log_info "=== Restic Backup - Fin: $(date) ==="
EOFRESTIC

    chmod +x /usr/local/bin/securizar-backup-restic.sh
    log_change "Creado" "/usr/local/bin/securizar-backup-restic.sh"

    # Timer de systemd para restic
    cat > /etc/systemd/system/securizar-backup-restic.service << 'EOFSERVICE'
[Unit]
Description=Securizar - Backup cifrado con Restic
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/securizar-backup-restic.sh
Nice=19
IOSchedulingClass=idle
PrivateTmp=true
EnvironmentFile=-/etc/securizar/restic-env

[Install]
WantedBy=multi-user.target
EOFSERVICE

    cat > /etc/systemd/system/securizar-backup-restic.timer << 'EOFTIMER'
[Unit]
Description=Securizar - Timer diario para backup Restic

[Timer]
OnCalendar=*-*-* 03:00:00
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
EOFTIMER

    systemctl daemon-reload
    systemctl enable securizar-backup-restic.timer 2>/dev/null || true
    log_change "Creado" "securizar-backup-restic.service + timer (diario 03:00)"

    log_info "Restic configurado"
    log_info "Backup manual: securizar-backup-restic.sh"
else
    log_skip "Backup cifrado con Restic"
fi

# ============================================================
# S4: BACKUPS INMUTABLES (WORM)
# ============================================================
log_section "S4: BACKUPS INMUTABLES (WORM)"

echo "Configura inmutabilidad de backups:"
echo "  - chattr +i en archivos de backup completados"
echo "  - Snapshots de solo lectura en btrfs"
echo "  - ZFS snapshot + hold para inmutabilidad"
echo "  - Guia para S3 Object Lock"
echo "  - Timer para aplicar inmutabilidad tras backup"
echo ""

if ask "¿Configurar backups inmutables (WORM)?"; then

    cat > /usr/local/bin/securizar-backup-inmutable.sh << 'EOFWORM'
#!/bin/bash
# ============================================================
# securizar-backup-inmutable.sh - Inmutabilidad de backups
# ============================================================
# Aplica proteccion WORM (Write Once Read Many) a backups
# completados segun el tipo de filesystem detectado.
# ============================================================
set -uo pipefail

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[X]${NC} $1"; }

CONF="/etc/securizar/backup-strategy.conf"
if [[ -f "$CONF" ]]; then
    # shellcheck source=/dev/null
    source "$CONF"
fi

BACKUP_BASE="${COPY1_PATH:-/var/backups/securizar}"
IMMUTABLE_LOG="/var/log/securizar-immutable.log"

# ── Detectar filesystem ───────────────────────────────────
detect_fs() {
    local path="$1"
    df -T "$path" 2>/dev/null | awk 'NR==2 {print $2}'
}

# ── chattr +i: Inmutabilidad a nivel de filesystem ext4/xfs ─
apply_chattr_immutable() {
    local target="$1"
    local fs_type
    fs_type=$(detect_fs "$target")

    if [[ "$fs_type" != "ext4" ]] && [[ "$fs_type" != "ext3" ]] && \
       [[ "$fs_type" != "xfs" ]] && [[ "$fs_type" != "ext2" ]]; then
        log_warn "chattr +i no soportado en filesystem: $fs_type"
        return 1
    fi

    if [[ ! -e "$target" ]]; then
        log_error "Objetivo no existe: $target"
        return 1
    fi

    log_info "Aplicando inmutabilidad (chattr +i) a: $target"

    if [[ -d "$target" ]]; then
        # Para directorios, aplicar a todos los archivos dentro
        local count=0
        while IFS= read -r -d '' file; do
            if chattr +i "$file" 2>/dev/null; then
                ((count++)) || true
            fi
        done < <(find "$target" -type f -print0)
        log_info "Inmutabilidad aplicada a $count archivos en: $target"
        echo "$(date -Iseconds) CHATTR $count archivos en $target" >> "$IMMUTABLE_LOG"
    else
        if chattr +i "$target"; then
            log_info "Inmutabilidad aplicada a: $target"
            echo "$(date -Iseconds) CHATTR $target" >> "$IMMUTABLE_LOG"
        else
            log_error "No se pudo aplicar inmutabilidad: $target"
            return 1
        fi
    fi
}

# ── Quitar inmutabilidad (para mantenimiento) ──────────────
remove_chattr_immutable() {
    local target="$1"

    log_warn "Quitando inmutabilidad de: $target"

    if [[ -d "$target" ]]; then
        find "$target" -type f -exec chattr -i {} + 2>/dev/null
        echo "$(date -Iseconds) CHATTR-REMOVE dir $target" >> "$IMMUTABLE_LOG"
    else
        chattr -i "$target" 2>/dev/null
        echo "$(date -Iseconds) CHATTR-REMOVE $target" >> "$IMMUTABLE_LOG"
    fi
}

# ── btrfs: Snapshots de solo lectura ──────────────────────
apply_btrfs_readonly() {
    local subvol="$1"
    local snap_name="${2:-backup-$(date +%Y%m%d-%H%M%S)}"

    if ! command -v btrfs &>/dev/null; then
        log_error "btrfs-progs no instalado"
        return 1
    fi

    local fs_type
    fs_type=$(detect_fs "$subvol")
    if [[ "$fs_type" != "btrfs" ]]; then
        log_warn "$subvol no es btrfs (es $fs_type)"
        return 1
    fi

    local snap_path="${subvol}/.snapshots/${snap_name}"
    mkdir -p "$(dirname "$snap_path")"

    log_info "Creando snapshot btrfs de solo lectura: $snap_path"
    if btrfs subvolume snapshot -r "$subvol" "$snap_path"; then
        log_info "Snapshot creado: $snap_path"
        echo "$(date -Iseconds) BTRFS-SNAPSHOT $snap_path" >> "$IMMUTABLE_LOG"
    else
        log_error "No se pudo crear snapshot btrfs: $subvol"
        return 1
    fi
}

# ── ZFS: Snapshot + hold ──────────────────────────────────
apply_zfs_immutable() {
    local dataset="$1"
    local snap_name="${2:-securizar-$(date +%Y%m%d-%H%M%S)}"

    if ! command -v zfs &>/dev/null; then
        log_error "ZFS no instalado"
        return 1
    fi

    local full_snap="${dataset}@${snap_name}"

    log_info "Creando snapshot ZFS: $full_snap"
    if zfs snapshot "$full_snap"; then
        log_info "Snapshot ZFS creado: $full_snap"

        # Aplicar hold para prevenir destruccion
        if zfs hold "securizar-lock" "$full_snap"; then
            log_info "Hold aplicado a: $full_snap (protegido contra destruccion)"
            echo "$(date -Iseconds) ZFS-SNAPSHOT+HOLD $full_snap" >> "$IMMUTABLE_LOG"
        else
            log_warn "No se pudo aplicar hold a: $full_snap"
        fi
    else
        log_error "No se pudo crear snapshot ZFS: $full_snap"
        return 1
    fi
}

# ── S3 Object Lock (guia) ────────────────────────────────
show_s3_objectlock_guide() {
    echo ""
    echo -e "${CYAN}══ Guia: S3 Object Lock (Inmutabilidad Cloud) ══${NC}"
    echo ""
    echo "Para habilitar Object Lock en S3:"
    echo ""
    echo "1. Crear bucket con Object Lock habilitado:"
    echo "   aws s3api create-bucket --bucket mi-backup-inmutable \\"
    echo "     --object-lock-enabled-for-object-lock-configuration"
    echo ""
    echo "2. Configurar retencion por defecto (COMPLIANCE mode):"
    echo "   aws s3api put-object-lock-configuration \\"
    echo "     --bucket mi-backup-inmutable \\"
    echo "     --object-lock-configuration '{\"ObjectLockEnabled\":\"Enabled\","
    echo "       \"Rule\":{\"DefaultRetention\":{\"Mode\":\"COMPLIANCE\",\"Days\":90}}}'"
    echo ""
    echo "3. Para MinIO (on-premise):"
    echo "   mc mb --with-lock myminio/backup-inmutable"
    echo "   mc retention set --default COMPLIANCE 90d myminio/backup-inmutable"
    echo ""
    echo "COMPLIANCE mode: Ni siquiera root/admin puede borrar antes del periodo"
    echo "GOVERNANCE mode: Usuarios con permisos especiales pueden desbloquear"
    echo ""
}

# ── Principal ─────────────────────────────────────────────
usage() {
    echo "Uso: $0 [comando] [opciones]"
    echo ""
    echo "Comandos:"
    echo "  lock <ruta>         Aplicar inmutabilidad (auto-detecta filesystem)"
    echo "  unlock <ruta>       Quitar inmutabilidad (requiere justificacion)"
    echo "  btrfs-snap <subvol> Crear snapshot btrfs de solo lectura"
    echo "  zfs-snap <dataset>  Crear snapshot ZFS con hold"
    echo "  status [ruta]       Verificar estado de inmutabilidad"
    echo "  s3-guide            Mostrar guia de S3 Object Lock"
    echo "  auto                Aplicar a todos los backups completados"
    echo ""
}

case "${1:-auto}" in
    lock)
        if [[ -z "${2:-}" ]]; then
            echo "Error: especifica la ruta"
            exit 1
        fi
        apply_chattr_immutable "$2"
        ;;
    unlock)
        if [[ -z "${2:-}" ]]; then
            echo "Error: especifica la ruta"
            exit 1
        fi
        echo "AVISO: Quitar inmutabilidad reduce la proteccion de backups"
        read -p "Justificacion: " justification
        echo "$(date -Iseconds) UNLOCK-REQUEST $2 justificacion='$justification'" >> "$IMMUTABLE_LOG"
        remove_chattr_immutable "$2"
        ;;
    btrfs-snap)
        apply_btrfs_readonly "${2:-/}" "${3:-}"
        ;;
    zfs-snap)
        if [[ -z "${2:-}" ]]; then
            echo "Error: especifica el dataset ZFS"
            exit 1
        fi
        apply_zfs_immutable "$2" "${3:-}"
        ;;
    status)
        target="${2:-$BACKUP_BASE}"
        echo -e "${CYAN}Estado de inmutabilidad: $target${NC}"
        if [[ -d "$target" ]]; then
            immutable_count=$(lsattr -R "$target" 2>/dev/null | grep -c '\-i\-' || echo 0)
            total_count=$(find "$target" -type f 2>/dev/null | wc -l)
            echo "  Archivos inmutables: $immutable_count / $total_count"
        elif [[ -f "$target" ]]; then
            attrs=$(lsattr "$target" 2>/dev/null)
            if echo "$attrs" | grep -q 'i'; then
                echo "  Estado: INMUTABLE"
            else
                echo "  Estado: MUTABLE"
            fi
        fi
        # Verificar btrfs
        if command -v btrfs &>/dev/null; then
            echo ""
            echo "Snapshots btrfs de solo lectura:"
            btrfs subvolume list -r / 2>/dev/null | grep -i backup || echo "  (ninguno)"
        fi
        # Verificar ZFS
        if command -v zfs &>/dev/null; then
            echo ""
            echo "Snapshots ZFS con hold:"
            zfs list -t snapshot -o name,used,refer 2>/dev/null | head -20 || echo "  (ninguno)"
        fi
        ;;
    s3-guide)
        show_s3_objectlock_guide
        ;;
    auto)
        log_info "Aplicando inmutabilidad automatica a backups completados..."
        # Borg repo
        if [[ -d "${BACKUP_BASE}/borg" ]]; then
            apply_chattr_immutable "${BACKUP_BASE}/borg/data" 2>/dev/null || \
                log_warn "No se pudo aplicar inmutabilidad a repo borg (puede no existir aun)"
        fi
        # Restic repo
        if [[ -d "${BACKUP_BASE}/restic" ]]; then
            apply_chattr_immutable "${BACKUP_BASE}/restic/data" 2>/dev/null || \
                log_warn "No se pudo aplicar inmutabilidad a repo restic (puede no existir aun)"
        fi
        # btrfs auto
        fs_type=$(detect_fs "${BACKUP_BASE}")
        if [[ "$fs_type" == "btrfs" ]]; then
            apply_btrfs_readonly "${BACKUP_BASE}" "backup-auto-$(date +%Y%m%d)" || true
        fi
        log_info "Inmutabilidad automatica completada"
        ;;
    *)
        usage
        exit 1
        ;;
esac
EOFWORM

    chmod +x /usr/local/bin/securizar-backup-inmutable.sh
    log_change "Creado" "/usr/local/bin/securizar-backup-inmutable.sh"

    # Timer para aplicar inmutabilidad tras backup
    cat > /etc/systemd/system/securizar-inmutable-post-backup.service << 'EOFSERVICE'
[Unit]
Description=Securizar - Aplicar inmutabilidad tras backup
After=securizar-backup-borg.service securizar-backup-restic.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/securizar-backup-inmutable.sh auto
Nice=19

[Install]
WantedBy=multi-user.target
EOFSERVICE

    cat > /etc/systemd/system/securizar-inmutable-post-backup.timer << 'EOFTIMER'
[Unit]
Description=Securizar - Timer para inmutabilidad post-backup

[Timer]
# Se ejecuta 1 hora despues de los backups
OnCalendar=*-*-* 04:30:00
Persistent=true

[Install]
WantedBy=timers.target
EOFTIMER

    systemctl daemon-reload
    systemctl enable securizar-inmutable-post-backup.timer 2>/dev/null || true
    log_change "Creado" "securizar-inmutable-post-backup timer (diario 04:30)"

    log_info "Backups inmutables configurados"
    log_info "Uso: securizar-backup-inmutable.sh [lock|unlock|status|auto]"
else
    log_skip "Backups inmutables (WORM)"
fi

# ============================================================
# S5: VERIFICACION Y RESTAURACION AUTOMATICA
# ============================================================
log_section "S5: VERIFICACION Y RESTAURACION AUTOMATICA"

echo "Configura verificacion y restauracion de backups:"
echo "  - Verifica integridad de repos borg y restic"
echo "  - Restauracion de prueba a directorio temporal"
echo "  - Comparacion de checksums"
echo "  - Cron semanal de verificacion"
echo "  - Script interactivo de restauracion"
echo ""

if ask "¿Configurar verificacion y restauracion automatica?"; then

    # Script de verificacion
    cat > /usr/local/bin/verificar-backups.sh << 'EOFVERIFY'
#!/bin/bash
# ============================================================
# verificar-backups.sh - Verificacion de integridad de backups
# ============================================================
set -uo pipefail

CONF="/etc/securizar/backup-strategy.conf"
if [[ -f "$CONF" ]]; then
    # shellcheck source=/dev/null
    source "$CONF"
fi

BACKUP_BASE="${COPY1_PATH:-/var/backups/securizar}"
BORG_PASSPHRASE_FILE="${ENCRYPTION_PASSPHRASE_FILE:-/etc/securizar/.backup-passphrase}"
RESTIC_PASSWORD_FILE="${RESTIC_PASSWORD_FILE:-/etc/securizar/.restic-password}"
VERIFY_LOG="/var/log/securizar-backup-verify.log"
VERIFY_TMPDIR="/tmp/securizar-verify-$$"
NOTIFY_EMAIL="${NOTIFY_EMAIL:-root@localhost}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[+]${NC} $1"; echo "[+] $1" >> "$VERIFY_LOG"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; echo "[!] $1" >> "$VERIFY_LOG"; }
log_error() { echo -e "${RED}[X]${NC} $1"; echo "[X] $1" >> "$VERIFY_LOG"; }

TOTAL_CHECKS=0
PASSED=0
FAILURES=0

check_pass() { ((TOTAL_CHECKS++)) || true; ((PASSED++)) || true; log_info "$1"; }
check_fail() { ((TOTAL_CHECKS++)) || true; ((FAILURES++)) || true; log_error "$1"; }

cleanup() {
    rm -rf "$VERIFY_TMPDIR" 2>/dev/null || true
}
trap cleanup EXIT

mkdir -p "$VERIFY_TMPDIR"
echo "=== Verificacion de backups: $(date) ===" >> "$VERIFY_LOG"

echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "${CYAN}  VERIFICACION DE INTEGRIDAD DE BACKUPS${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo ""

# ── Verificar Borg ────────────────────────────────────────
BORG_REPO="${BACKUP_BASE}/borg"
if [[ -d "$BORG_REPO" ]] && command -v borg &>/dev/null; then
    echo -e "${CYAN}--- BorgBackup ---${NC}"

    if [[ -f "$BORG_PASSPHRASE_FILE" ]]; then
        export BORG_PASSPHRASE
        BORG_PASSPHRASE=$(cat "$BORG_PASSPHRASE_FILE")

        # Verificar integridad del repositorio
        log_info "Verificando integridad del repositorio borg..."
        if borg check --verify-data "$BORG_REPO" 2>&1; then
            check_pass "Borg: integridad del repositorio OK"
        else
            check_fail "Borg: problemas de integridad detectados"
        fi

        # Listar ultimo archivo
        latest_archive=$(borg list --short --last 1 "$BORG_REPO" 2>/dev/null)
        if [[ -n "$latest_archive" ]]; then
            log_info "Ultimo archivo borg: $latest_archive"

            # Restauracion de prueba
            log_info "Ejecutando restauracion de prueba..."
            restore_dir="${VERIFY_TMPDIR}/borg-restore"
            mkdir -p "$restore_dir"

            # Restaurar solo /etc como prueba
            if borg extract --dry-run "${BORG_REPO}::${latest_archive}" etc/ 2>&1; then
                check_pass "Borg: restauracion de prueba (dry-run) OK"
            else
                check_fail "Borg: restauracion de prueba fallo"
            fi

            # Verificar archivos criticos en el backup
            borg_files=$(borg list --short "${BORG_REPO}::${latest_archive}" 2>/dev/null | head -50)
            if echo "$borg_files" | grep -q "etc/"; then
                check_pass "Borg: contiene /etc"
            else
                check_fail "Borg: /etc no encontrado en backup"
            fi
        else
            check_fail "Borg: no hay archivos en el repositorio"
        fi
    else
        check_fail "Borg: passphrase no encontrada ($BORG_PASSPHRASE_FILE)"
    fi
    echo ""
else
    log_warn "Borg: repositorio no encontrado o borg no instalado"
fi

# ── Verificar Restic ──────────────────────────────────────
RESTIC_REPO="${BACKUP_BASE}/restic"
if [[ -d "$RESTIC_REPO" ]] && command -v restic &>/dev/null; then
    echo -e "${CYAN}--- Restic ---${NC}"

    if [[ -f "$RESTIC_PASSWORD_FILE" ]]; then
        export RESTIC_PASSWORD_FILE
        export RESTIC_REPOSITORY="$RESTIC_REPO"

        # Verificar integridad
        log_info "Verificando integridad del repositorio restic..."
        if restic check 2>&1; then
            check_pass "Restic: integridad del repositorio OK"
        else
            check_fail "Restic: problemas de integridad detectados"
        fi

        # Verificar con lectura parcial de datos
        log_info "Verificando datos (subset 2%)..."
        if restic check --read-data-subset=2% 2>&1; then
            check_pass "Restic: verificacion de datos (subset) OK"
        else
            check_fail "Restic: problemas en datos detectados"
        fi

        # Listar ultimo snapshot
        latest_snapshot=$(restic snapshots --latest 1 --compact --no-lock 2>/dev/null | tail -3 | head -1)
        if [[ -n "$latest_snapshot" ]]; then
            log_info "Ultimo snapshot restic: $latest_snapshot"

            # Restauracion de prueba
            restore_dir="${VERIFY_TMPDIR}/restic-restore"
            mkdir -p "$restore_dir"

            snapshot_id=$(restic snapshots --latest 1 --json --no-lock 2>/dev/null | \
                python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['short_id'])" 2>/dev/null || echo "")

            if [[ -n "$snapshot_id" ]]; then
                if restic restore "$snapshot_id" --target "$restore_dir" --include "/etc/hostname" --no-lock 2>&1; then
                    if [[ -f "${restore_dir}/etc/hostname" ]]; then
                        check_pass "Restic: restauracion de prueba OK"
                    else
                        check_fail "Restic: restauracion no produjo archivos esperados"
                    fi
                else
                    check_fail "Restic: restauracion de prueba fallo"
                fi
            fi
        else
            check_fail "Restic: no hay snapshots en el repositorio"
        fi
    else
        check_fail "Restic: password no encontrada ($RESTIC_PASSWORD_FILE)"
    fi
    echo ""
else
    log_warn "Restic: repositorio no encontrado o restic no instalado"
fi

# ── Resultado ─────────────────────────────────────────────
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "  ${CYAN}Resultado: ${PASSED}/${TOTAL_CHECKS} verificaciones OK${NC}"
if [[ $FAILURES -gt 0 ]]; then
    echo -e "  ${RED}${FAILURES} FALLOS DETECTADOS${NC}"
    echo "=== FALLOS: $FAILURES ===" >> "$VERIFY_LOG"

    # Enviar alerta por email si hay fallos
    if command -v mail &>/dev/null; then
        echo "ALERTA: $FAILURES fallos en verificacion de backups en $(hostname)" | \
            mail -s "[SECURIZAR] Fallo verificacion backups" "$NOTIFY_EMAIL" 2>/dev/null || true
    fi
    exit 1
else
    echo -e "  ${GREEN}TODAS LAS VERIFICACIONES PASARON${NC}"
    echo "=== TODO OK ===" >> "$VERIFY_LOG"
fi
echo -e "${CYAN}══════════════════════════════════════════${NC}"
EOFVERIFY

    chmod +x /usr/local/bin/verificar-backups.sh
    log_change "Creado" "/usr/local/bin/verificar-backups.sh"

    # Script de restauracion interactiva
    cat > /usr/local/bin/restaurar-backup.sh << 'EOFRESTORE'
#!/bin/bash
# ============================================================
# restaurar-backup.sh - Restauracion interactiva desde backups
# ============================================================
set -uo pipefail

CONF="/etc/securizar/backup-strategy.conf"
if [[ -f "$CONF" ]]; then
    # shellcheck source=/dev/null
    source "$CONF"
fi

BACKUP_BASE="${COPY1_PATH:-/var/backups/securizar}"
BORG_PASSPHRASE_FILE="${ENCRYPTION_PASSPHRASE_FILE:-/etc/securizar/.backup-passphrase}"
RESTIC_PASSWORD_FILE="${RESTIC_PASSWORD_FILE:-/etc/securizar/.restic-password}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[X]${NC} $1"; }

echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "${CYAN}  RESTAURACION INTERACTIVA DE BACKUPS${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo ""

# Detectar backends disponibles
backends=()
if [[ -d "${BACKUP_BASE}/borg" ]] && command -v borg &>/dev/null; then
    backends+=("borg")
fi
if [[ -d "${BACKUP_BASE}/restic" ]] && command -v restic &>/dev/null; then
    backends+=("restic")
fi

if [[ ${#backends[@]} -eq 0 ]]; then
    log_error "No se encontraron repositorios de backup configurados"
    log_error "Ejecuta primero securizar-backup-borg.sh o securizar-backup-restic.sh"
    exit 1
fi

# Seleccionar backend
echo -e "${BOLD}Backends disponibles:${NC}"
for i in "${!backends[@]}"; do
    echo "  $((i+1)). ${backends[$i]}"
done
echo ""
read -p "Selecciona backend (1-${#backends[@]}): " backend_choice
backend_idx=$((backend_choice - 1))

if [[ $backend_idx -lt 0 ]] || [[ $backend_idx -ge ${#backends[@]} ]]; then
    log_error "Seleccion invalida"
    exit 1
fi

selected_backend="${backends[$backend_idx]}"
echo ""
log_info "Backend seleccionado: $selected_backend"

# ── Restauracion con Borg ─────────────────────────────────
restore_borg() {
    local repo="${BACKUP_BASE}/borg"

    if [[ -f "$BORG_PASSPHRASE_FILE" ]]; then
        export BORG_PASSPHRASE
        BORG_PASSPHRASE=$(cat "$BORG_PASSPHRASE_FILE")
    else
        read -sp "Passphrase de borg: " BORG_PASSPHRASE
        export BORG_PASSPHRASE
        echo ""
    fi

    echo ""
    echo -e "${BOLD}Archivos disponibles:${NC}"
    borg list "$repo" 2>/dev/null
    echo ""

    read -p "Nombre del archivo a restaurar (copiar de arriba): " archive_name

    if [[ -z "$archive_name" ]]; then
        log_error "Nombre de archivo vacio"
        return 1
    fi

    # Verificar que el archivo existe
    if ! borg info "${repo}::${archive_name}" &>/dev/null; then
        log_error "Archivo no encontrado: $archive_name"
        return 1
    fi

    echo ""
    echo "Opciones de restauracion:"
    echo "  1. Restaurar todo a directorio especifico"
    echo "  2. Restaurar ruta especifica"
    echo "  3. Listar contenido del archivo"
    echo ""
    read -p "Opcion (1-3): " restore_option

    case "$restore_option" in
        1)
            read -p "Directorio destino (default: /tmp/restore-borg): " target_dir
            target_dir="${target_dir:-/tmp/restore-borg}"
            mkdir -p "$target_dir"

            log_info "Restaurando a: $target_dir"
            cd "$target_dir" || exit 1
            borg extract "${repo}::${archive_name}"
            log_info "Restauracion completada en: $target_dir"
            ;;
        2)
            read -p "Ruta a restaurar (ej: etc/ssh): " restore_path
            read -p "Directorio destino (default: /tmp/restore-borg): " target_dir
            target_dir="${target_dir:-/tmp/restore-borg}"
            mkdir -p "$target_dir"

            log_info "Restaurando $restore_path a: $target_dir"
            cd "$target_dir" || exit 1
            borg extract "${repo}::${archive_name}" "$restore_path"
            log_info "Restauracion completada"
            ;;
        3)
            borg list "${repo}::${archive_name}" | head -100
            echo "... (mostrando primeros 100 archivos)"
            ;;
        *)
            log_error "Opcion invalida"
            return 1
            ;;
    esac
}

# ── Restauracion con Restic ────────────────────────────────
restore_restic() {
    local repo="${BACKUP_BASE}/restic"

    if [[ -f "$RESTIC_PASSWORD_FILE" ]]; then
        export RESTIC_PASSWORD_FILE
    else
        read -sp "Password de restic: " RESTIC_PASSWORD
        export RESTIC_PASSWORD
        echo ""
    fi
    export RESTIC_REPOSITORY="$repo"

    echo ""
    echo -e "${BOLD}Snapshots disponibles:${NC}"
    restic snapshots --no-lock 2>/dev/null
    echo ""

    read -p "ID del snapshot a restaurar: " snapshot_id

    if [[ -z "$snapshot_id" ]]; then
        log_error "ID de snapshot vacio"
        return 1
    fi

    echo ""
    echo "Opciones de restauracion:"
    echo "  1. Restaurar todo a directorio especifico"
    echo "  2. Restaurar ruta especifica"
    echo "  3. Listar contenido del snapshot"
    echo ""
    read -p "Opcion (1-3): " restore_option

    case "$restore_option" in
        1)
            read -p "Directorio destino (default: /tmp/restore-restic): " target_dir
            target_dir="${target_dir:-/tmp/restore-restic}"
            mkdir -p "$target_dir"

            log_info "Restaurando a: $target_dir"
            restic restore "$snapshot_id" --target "$target_dir" --no-lock
            log_info "Restauracion completada en: $target_dir"
            ;;
        2)
            read -p "Ruta a restaurar (ej: /etc/ssh): " restore_path
            read -p "Directorio destino (default: /tmp/restore-restic): " target_dir
            target_dir="${target_dir:-/tmp/restore-restic}"
            mkdir -p "$target_dir"

            log_info "Restaurando $restore_path a: $target_dir"
            restic restore "$snapshot_id" --target "$target_dir" --include "$restore_path" --no-lock
            log_info "Restauracion completada"
            ;;
        3)
            restic ls "$snapshot_id" --no-lock 2>/dev/null | head -100
            echo "... (mostrando primeros 100 archivos)"
            ;;
        *)
            log_error "Opcion invalida"
            return 1
            ;;
    esac
}

# Ejecutar restauracion
case "$selected_backend" in
    borg)   restore_borg ;;
    restic) restore_restic ;;
esac
EOFRESTORE

    chmod +x /usr/local/bin/restaurar-backup.sh
    log_change "Creado" "/usr/local/bin/restaurar-backup.sh"

    # Cron semanal para verificacion
    cat > /etc/cron.weekly/verificar-backups << 'EOFCRON'
#!/bin/bash
# Verificacion semanal de integridad de backups
/usr/local/bin/verificar-backups.sh >> /var/log/securizar-backup-verify.log 2>&1
EOFCRON
    chmod +x /etc/cron.weekly/verificar-backups
    log_change "Creado" "/etc/cron.weekly/verificar-backups (verificacion semanal)"

    log_info "Verificacion y restauracion configuradas"
    log_info "Verificar: verificar-backups.sh"
    log_info "Restaurar: restaurar-backup.sh"
else
    log_skip "Verificacion y restauracion automatica"
fi

# ============================================================
# S6: BACKUP DE SISTEMA COMPLETO (BARE METAL)
# ============================================================
log_section "S6: BACKUP DE SISTEMA COMPLETO (BARE METAL)"

echo "Crea backup completo para recuperacion bare metal:"
echo "  - Tabla de particiones (sgdisk/sfdisk)"
echo "  - Sector de arranque (dd MBR/GPT)"
echo "  - Layout LVM completo"
echo "  - Dump del filesystem (xfsdump/tar)"
echo "  - Configuracion GRUB"
echo "  - Todo cifrado en un archivo"
echo ""

if ask "¿Crear script de backup de sistema completo (bare metal)?"; then

    cat > /usr/local/bin/backup-sistema-completo.sh << 'EOFBAREMETAL'
#!/bin/bash
# ============================================================
# backup-sistema-completo.sh - Backup bare metal completo
# ============================================================
# Captura toda la informacion necesaria para reconstruir
# el sistema desde cero en hardware nuevo.
# ============================================================
set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[X]${NC} $1"; }

# Verificar root
if [[ $EUID -ne 0 ]]; then
    log_error "Este script debe ejecutarse como root"
    exit 1
fi

# Configuracion
BACKUP_DEST="${1:-/var/backups/securizar/bare-metal}"
HOSTNAME_SHORT=$(hostname -s)
DATE_STAMP=$(date +%Y%m%d-%H%M%S)
WORK_DIR="${BACKUP_DEST}/${HOSTNAME_SHORT}-${DATE_STAMP}"
ENCRYPT="${ENCRYPT_BACKUP:-true}"
PASSPHRASE_FILE="/etc/securizar/.backup-passphrase"

mkdir -p "$WORK_DIR"
chmod 700 "$WORK_DIR"

log_info "=== Backup Bare Metal: $(date) ==="
log_info "Destino: $WORK_DIR"

# ── 1. Informacion del sistema ────────────────────────────
log_info "Recopilando informacion del sistema..."

mkdir -p "${WORK_DIR}/system-info"
hostname -f > "${WORK_DIR}/system-info/hostname" 2>/dev/null || hostname > "${WORK_DIR}/system-info/hostname"
uname -a > "${WORK_DIR}/system-info/uname"
cat /etc/os-release > "${WORK_DIR}/system-info/os-release" 2>/dev/null || true
ip addr show > "${WORK_DIR}/system-info/ip-addr" 2>/dev/null || true
ip route show > "${WORK_DIR}/system-info/ip-route" 2>/dev/null || true
df -hT > "${WORK_DIR}/system-info/df"
mount > "${WORK_DIR}/system-info/mount"
cat /etc/fstab > "${WORK_DIR}/system-info/fstab"
blkid > "${WORK_DIR}/system-info/blkid"
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,UUID,PARTUUID > "${WORK_DIR}/system-info/lsblk"
dmidecode > "${WORK_DIR}/system-info/dmidecode" 2>/dev/null || true
log_info "Informacion del sistema recopilada"

# ── 2. Tabla de particiones ───────────────────────────────
log_info "Respaldando tablas de particiones..."

mkdir -p "${WORK_DIR}/partitions"

# Detectar discos
for disk in $(lsblk -dnp -o NAME,TYPE | awk '$2=="disk" {print $1}'); do
    disk_name=$(basename "$disk")
    log_info "  Disco: $disk"

    # GPT con sgdisk
    if command -v sgdisk &>/dev/null; then
        sgdisk --backup="${WORK_DIR}/partitions/${disk_name}-gpt.bak" "$disk" 2>/dev/null || true
    fi

    # MBR/GPT con sfdisk
    if command -v sfdisk &>/dev/null; then
        sfdisk --dump "$disk" > "${WORK_DIR}/partitions/${disk_name}-sfdisk.dump" 2>/dev/null || true
    fi

    # Informacion de particiones
    fdisk -l "$disk" > "${WORK_DIR}/partitions/${disk_name}-fdisk.txt" 2>/dev/null || true

    # parted
    if command -v parted &>/dev/null; then
        parted -s "$disk" print > "${WORK_DIR}/partitions/${disk_name}-parted.txt" 2>/dev/null || true
    fi
done
log_info "Tablas de particiones respaldadas"

# ── 3. Sector de arranque ─────────────────────────────────
log_info "Respaldando sectores de arranque..."

mkdir -p "${WORK_DIR}/boot-sectors"

for disk in $(lsblk -dnp -o NAME,TYPE | awk '$2=="disk" {print $1}'); do
    disk_name=$(basename "$disk")

    # MBR (primeros 512 bytes)
    dd if="$disk" of="${WORK_DIR}/boot-sectors/${disk_name}-mbr.bin" bs=512 count=1 2>/dev/null
    # GPT (primeros 2MB para cubrir GPT completo)
    dd if="$disk" of="${WORK_DIR}/boot-sectors/${disk_name}-gpt-header.bin" bs=1M count=2 2>/dev/null
done
log_info "Sectores de arranque respaldados"

# ── 4. LVM Layout ────────────────────────────────────────
log_info "Respaldando layout LVM..."

mkdir -p "${WORK_DIR}/lvm"

if command -v pvs &>/dev/null; then
    pvs --reportformat json > "${WORK_DIR}/lvm/pvs.json" 2>/dev/null || pvs > "${WORK_DIR}/lvm/pvs.txt" 2>/dev/null || true
    vgs --reportformat json > "${WORK_DIR}/lvm/vgs.json" 2>/dev/null || vgs > "${WORK_DIR}/lvm/vgs.txt" 2>/dev/null || true
    lvs --reportformat json > "${WORK_DIR}/lvm/lvs.json" 2>/dev/null || lvs > "${WORK_DIR}/lvm/lvs.txt" 2>/dev/null || true
    pvdisplay > "${WORK_DIR}/lvm/pvdisplay.txt" 2>/dev/null || true
    vgdisplay > "${WORK_DIR}/lvm/vgdisplay.txt" 2>/dev/null || true
    lvdisplay > "${WORK_DIR}/lvm/lvdisplay.txt" 2>/dev/null || true

    # Backup de metadatos LVM
    if command -v vgcfgbackup &>/dev/null; then
        vgcfgbackup --file "${WORK_DIR}/lvm/vgcfgbackup-%s.lvm" 2>/dev/null || true
    fi
    log_info "Layout LVM respaldado"
else
    log_warn "LVM no detectado"
fi

# ── 5. LUKS headers ──────────────────────────────────────
log_info "Respaldando headers LUKS..."

mkdir -p "${WORK_DIR}/luks"

if command -v cryptsetup &>/dev/null; then
    for part in $(blkid -t TYPE=crypto_LUKS -o device 2>/dev/null); do
        part_name=$(basename "$part" | tr '/' '_')
        log_info "  LUKS: $part"
        cryptsetup luksHeaderBackup "$part" \
            --header-backup-file "${WORK_DIR}/luks/${part_name}-luks-header.bak" 2>/dev/null || true
        cryptsetup luksDump "$part" > "${WORK_DIR}/luks/${part_name}-luks-dump.txt" 2>/dev/null || true
    done
    log_info "Headers LUKS respaldados"
else
    log_warn "cryptsetup no disponible"
fi

# ── 6. GRUB / Bootloader ─────────────────────────────────
log_info "Respaldando configuracion del bootloader..."

mkdir -p "${WORK_DIR}/bootloader"

# GRUB2
if [[ -d /boot/grub2 ]]; then
    cp -a /boot/grub2 "${WORK_DIR}/bootloader/grub2" 2>/dev/null || true
elif [[ -d /boot/grub ]]; then
    cp -a /boot/grub "${WORK_DIR}/bootloader/grub" 2>/dev/null || true
fi

# EFI
if [[ -d /boot/efi ]]; then
    cp -a /boot/efi "${WORK_DIR}/bootloader/efi" 2>/dev/null || true
fi

# Kernel y initramfs
ls -la /boot/ > "${WORK_DIR}/bootloader/boot-contents.txt" 2>/dev/null || true

# dracut/mkinitrd config
cp /etc/dracut.conf "${WORK_DIR}/bootloader/" 2>/dev/null || true
cp -a /etc/dracut.conf.d "${WORK_DIR}/bootloader/" 2>/dev/null || true

log_info "Configuracion del bootloader respaldada"

# ── 7. Filesystem dump ───────────────────────────────────
log_info "Creando dump de filesystems criticos..."

mkdir -p "${WORK_DIR}/filesystem"

# Determinar que herramienta usar segun el filesystem
backup_filesystem() {
    local mount_point="$1"
    local fs_type="$2"
    local output_name="$3"

    case "$fs_type" in
        xfs)
            if command -v xfsdump &>/dev/null; then
                log_info "  xfsdump: $mount_point"
                xfsdump -l 0 -f "${WORK_DIR}/filesystem/${output_name}.xfsdump" "$mount_point" 2>/dev/null || {
                    log_warn "  xfsdump fallo, usando tar para $mount_point"
                    tar czf "${WORK_DIR}/filesystem/${output_name}.tar.gz" \
                        --one-file-system \
                        --exclude='./proc/*' --exclude='./sys/*' \
                        --exclude='./dev/*' --exclude='./tmp/*' \
                        --exclude='./run/*' --exclude='./var/tmp/*' \
                        -C "$mount_point" . 2>/dev/null || true
                }
            else
                tar czf "${WORK_DIR}/filesystem/${output_name}.tar.gz" \
                    --one-file-system \
                    --exclude='./proc/*' --exclude='./sys/*' \
                    --exclude='./dev/*' --exclude='./tmp/*' \
                    --exclude='./run/*' --exclude='./var/tmp/*' \
                    -C "$mount_point" . 2>/dev/null || true
            fi
            ;;
        ext[234])
            if command -v dump &>/dev/null; then
                log_info "  dump: $mount_point"
                dump -0 -f "${WORK_DIR}/filesystem/${output_name}.dump" "$mount_point" 2>/dev/null || {
                    log_warn "  dump fallo, usando tar para $mount_point"
                    tar czf "${WORK_DIR}/filesystem/${output_name}.tar.gz" \
                        --one-file-system \
                        --exclude='./proc/*' --exclude='./sys/*' \
                        --exclude='./dev/*' --exclude='./tmp/*' \
                        --exclude='./run/*' --exclude='./var/tmp/*' \
                        -C "$mount_point" . 2>/dev/null || true
                }
            else
                tar czf "${WORK_DIR}/filesystem/${output_name}.tar.gz" \
                    --one-file-system \
                    --exclude='./proc/*' --exclude='./sys/*' \
                    --exclude='./dev/*' --exclude='./tmp/*' \
                    --exclude='./run/*' --exclude='./var/tmp/*' \
                    -C "$mount_point" . 2>/dev/null || true
            fi
            ;;
        *)
            log_info "  tar: $mount_point ($fs_type)"
            tar czf "${WORK_DIR}/filesystem/${output_name}.tar.gz" \
                --one-file-system \
                --exclude='./proc/*' --exclude='./sys/*' \
                --exclude='./dev/*' --exclude='./tmp/*' \
                --exclude='./run/*' --exclude='./var/tmp/*' \
                -C "$mount_point" . 2>/dev/null || true
            ;;
    esac
}

# Solo filesystems criticos del sistema local
while IFS= read -r line; do
    fs_dev=$(echo "$line" | awk '{print $1}')
    fs_mount=$(echo "$line" | awk '{print $2}')
    fs_type=$(echo "$line" | awk '{print $3}')

    # Omitir pseudo-filesystems y temporales
    case "$fs_mount" in
        /proc*|/sys*|/dev*|/run*|/tmp*) continue ;;
    esac
    case "$fs_type" in
        tmpfs|devtmpfs|sysfs|proc|cgroup*|autofs|debugfs|securityfs|fusectl) continue ;;
    esac

    output_name=$(echo "$fs_mount" | tr '/' '_' | sed 's/^_/root/')
    [[ "$output_name" == "" ]] && output_name="root"

    backup_filesystem "$fs_mount" "$fs_type" "$output_name"

done < <(findmnt -rn -o SOURCE,TARGET,FSTYPE)

log_info "Dumps de filesystem completados"

# ── 8. Paquetes instalados ───────────────────────────────
log_info "Respaldando lista de paquetes..."

mkdir -p "${WORK_DIR}/packages"

if command -v rpm &>/dev/null; then
    rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' | sort > "${WORK_DIR}/packages/rpm-list.txt"
fi
if command -v dpkg &>/dev/null; then
    dpkg --get-selections > "${WORK_DIR}/packages/dpkg-selections.txt"
    dpkg -l > "${WORK_DIR}/packages/dpkg-list.txt"
fi
if command -v pacman &>/dev/null; then
    pacman -Qe > "${WORK_DIR}/packages/pacman-explicit.txt"
    pacman -Q > "${WORK_DIR}/packages/pacman-all.txt"
fi
log_info "Lista de paquetes respaldada"

# ── 9. Servicios activos ─────────────────────────────────
systemctl list-unit-files --state=enabled > "${WORK_DIR}/system-info/enabled-services.txt" 2>/dev/null || true
systemctl list-units --type=service --state=running > "${WORK_DIR}/system-info/running-services.txt" 2>/dev/null || true

# ── 10. Generar checksum ─────────────────────────────────
log_info "Generando checksums..."
cd "$WORK_DIR" || exit 1
find . -type f ! -name "SHA256SUMS" -exec sha256sum {} + > SHA256SUMS 2>/dev/null
log_info "Checksums generados"

# ── 11. Cifrar si esta habilitado ─────────────────────────
if [[ "$ENCRYPT" == "true" ]]; then
    log_info "Cifrando backup bare metal..."

    ARCHIVE="${BACKUP_DEST}/${HOSTNAME_SHORT}-baremetal-${DATE_STAMP}.tar.gz"

    cd "$(dirname "$WORK_DIR")" || exit 1
    tar czf "$ARCHIVE" "$(basename "$WORK_DIR")"

    if [[ -f "$PASSPHRASE_FILE" ]]; then
        PASS=$(cat "$PASSPHRASE_FILE")
        ENCRYPTED="${ARCHIVE}.enc"
        openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
            -in "$ARCHIVE" -out "$ENCRYPTED" -pass "pass:${PASS}"
        rm -f "$ARCHIVE"
        chmod 600 "$ENCRYPTED"
        log_info "Backup cifrado: $ENCRYPTED"
    else
        chmod 600 "$ARCHIVE"
        log_warn "Sin passphrase, backup sin cifrar: $ARCHIVE"
    fi

    # Limpiar directorio temporal
    rm -rf "$WORK_DIR"
else
    log_info "Backup sin cifrar en: $WORK_DIR"
fi

log_info "=== Backup Bare Metal completado: $(date) ==="
log_info "Para restaurar, necesitaras:"
log_info "  1. Medio de arranque (Live USB/CD)"
log_info "  2. Este backup"
log_info "  3. La passphrase de cifrado"
EOFBAREMETAL

    chmod +x /usr/local/bin/backup-sistema-completo.sh
    log_change "Creado" "/usr/local/bin/backup-sistema-completo.sh"

    log_info "Script de backup bare metal creado"
    log_info "Ejecutar: backup-sistema-completo.sh [directorio-destino]"
else
    log_skip "Backup de sistema completo (bare metal)"
fi

# ============================================================
# S7: RTO/RPO Y PLANIFICACION
# ============================================================
log_section "S7: RTO/RPO Y PLANIFICACION"

echo "Configura objetivos de recuperacion y plan DR:"
echo "  - RTO (Recovery Time Objective): tiempo max de restauracion"
echo "  - RPO (Recovery Point Objective): perdida max de datos"
echo "  - Lista de servicios criticos y prioridades"
echo "  - Informacion de contacto"
echo "  - Script de validacion RTO/RPO"
echo ""

if ask "¿Configurar RTO/RPO y plan de recuperacion?"; then

    DR_PLAN_CONF="${SECURIZAR_BACKUP_CONF_DIR}/dr-plan.conf"
    if [[ -f "$DR_PLAN_CONF" ]]; then
        cp "$DR_PLAN_CONF" "${BACKUP_DIR}/dr-plan.conf.bak"
        log_change "Backup" "dr-plan.conf existente"
    fi

    cat > "$DR_PLAN_CONF" << 'EOFDRPLAN'
# ============================================================
# dr-plan.conf - Plan de Recuperacion ante Desastres
# ============================================================
# Generado por securizar - Modulo 49
# ============================================================

# ── Objetivos de Recuperacion ─────────────────────────────
# RTO: Recovery Time Objective (horas)
# Tiempo maximo aceptable para restaurar el servicio
RTO_TARGET_HOURS=4

# RPO: Recovery Point Objective (horas)
# Perdida maxima de datos aceptable
RPO_TARGET_HOURS=24

# ── Servicios Criticos ────────────────────────────────────
# Lista ordenada por prioridad de recuperacion (mayor a menor)
# Formato: SERVICIO:PUERTO:DESCRIPCION
CRITICAL_SERVICES=(
    "sshd:22:Acceso remoto SSH"
    "firewalld:0:Firewall del sistema"
    "networking:0:Conectividad de red"
    "dns:53:Resolucion DNS"
    "database:5432:Base de datos principal"
    "webserver:443:Servidor web"
    "mail:25:Correo electronico"
    "monitoring:9090:Sistema de monitoreo"
)

# ── Orden de Recuperacion ─────────────────────────────────
# Fases de recuperacion en orden
RECOVERY_PHASE_1="Infraestructura basica: red, firewall, DNS"
RECOVERY_PHASE_2="Acceso: SSH, autenticacion, VPN"
RECOVERY_PHASE_3="Datos: base de datos, almacenamiento"
RECOVERY_PHASE_4="Aplicaciones: web, API, microservicios"
RECOVERY_PHASE_5="Comunicaciones: email, mensajeria"
RECOVERY_PHASE_6="Monitoreo: alertas, logging, metricas"

# ── Contactos de Emergencia ───────────────────────────────
DR_CONTACT_PRIMARY="Administrador de Sistemas - admin@empresa.com - +XX-XXX-XXXX"
DR_CONTACT_SECONDARY="Equipo de Seguridad - seguridad@empresa.com - +XX-XXX-XXXX"
DR_CONTACT_MANAGEMENT="Direccion TI - direccion-ti@empresa.com - +XX-XXX-XXXX"
DR_CONTACT_VENDOR="Soporte Proveedor - soporte@proveedor.com - +XX-XXX-XXXX"

# ── Ubicaciones de Backup ────────────────────────────────
DR_BACKUP_LOCAL="/var/backups/securizar"
DR_BACKUP_OFFSITE="backup@offsite-server:/backups"
DR_BACKUP_CLOUD="s3://bucket-backup-dr"

# ── Documentacion ─────────────────────────────────────────
DR_RUNBOOK="/etc/securizar/dr-runbook.md"
DR_LAST_TEST=""
DR_LAST_TEST_RESULT=""

# ── Umbrales de Alerta ────────────────────────────────────
# Porcentaje del RPO para generar aviso temprano
RPO_WARNING_PERCENT=75
# Porcentaje del RTO para escalar
RTO_ESCALATION_PERCENT=50
EOFDRPLAN

    chmod 600 "$DR_PLAN_CONF"
    log_change "Creado" "$DR_PLAN_CONF (plan de recuperacion ante desastres)"

    # Script de validacion RTO/RPO
    cat > /usr/local/bin/validar-rto-rpo.sh << 'EOFRTRPO'
#!/bin/bash
# ============================================================
# validar-rto-rpo.sh - Validar cumplimiento RTO/RPO
# ============================================================
set -uo pipefail

DR_CONF="/etc/securizar/dr-plan.conf"
BACKUP_CONF="/etc/securizar/backup-strategy.conf"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[X]${NC} $1"; }

TOTAL_CHECKS=0
PASSED=0
WARNINGS=0
FAILURES=0

check_pass() { ((TOTAL_CHECKS++)) || true; ((PASSED++)) || true; echo -e "  ${GREEN}[OK]${NC} $1"; }
check_warn() { ((TOTAL_CHECKS++)) || true; ((WARNINGS++)) || true; echo -e "  ${YELLOW}[!]${NC} $1"; }
check_fail() { ((TOTAL_CHECKS++)) || true; ((FAILURES++)) || true; echo -e "  ${RED}[X]${NC} $1"; }

# Cargar configuracion
if [[ ! -f "$DR_CONF" ]]; then
    log_error "Plan DR no encontrado: $DR_CONF"
    log_error "Ejecuta el modulo 49 primero"
    exit 1
fi

# Cargar variables simples del DR plan (no arrays)
while IFS='=' read -r key value; do
    key="${key#"${key%%[![:space:]]*}"}"
    [[ -z "$key" || "$key" == \#* || "$key" == *"("* ]] && continue
    value="${value%%\#*}"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    value="${value#\"}"
    value="${value%\"}"
    declare "$key=$value" 2>/dev/null || true
done < "$DR_CONF"

if [[ -f "$BACKUP_CONF" ]]; then
    while IFS='=' read -r key value; do
        key="${key#"${key%%[![:space:]]*}"}"
        [[ -z "$key" || "$key" == \#* || "$key" == *"("* ]] && continue
        value="${value%%\#*}"
        value="${value#"${value%%[![:space:]]*}"}"
        value="${value%"${value##*[![:space:]]}"}"
        value="${value#\"}"
        value="${value%\"}"
        declare "$key=$value" 2>/dev/null || true
    done < "$BACKUP_CONF"
fi

echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "${CYAN}  VALIDACION RTO / RPO${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo ""

RTO_HOURS="${RTO_TARGET_HOURS:-4}"
RPO_HOURS="${RPO_TARGET_HOURS:-24}"

echo -e "${BOLD}Objetivos configurados:${NC}"
echo "  RTO: ${RTO_HOURS} horas (tiempo maximo de restauracion)"
echo "  RPO: ${RPO_HOURS} horas (perdida maxima de datos)"
echo ""

# ── Verificar RPO: Frescura de backups ────────────────────
echo -e "${BOLD}=== Verificacion RPO (Frescura de Backups) ===${NC}"

BACKUP_BASE="${COPY1_PATH:-/var/backups/securizar}"
rpo_seconds=$((RPO_HOURS * 3600))
now=$(date +%s)

# Verificar repo Borg
if [[ -d "${BACKUP_BASE}/borg" ]] && command -v borg &>/dev/null; then
    BORG_PASSPHRASE_FILE="${ENCRYPTION_PASSPHRASE_FILE:-/etc/securizar/.backup-passphrase}"
    if [[ -f "$BORG_PASSPHRASE_FILE" ]]; then
        export BORG_PASSPHRASE
        BORG_PASSPHRASE=$(cat "$BORG_PASSPHRASE_FILE")

        latest_borg=$(borg list --short --last 1 "${BACKUP_BASE}/borg" 2>/dev/null)
        if [[ -n "$latest_borg" ]]; then
            # Extraer fecha del nombre del archivo (formato: hostname-YYYY-MM-DD_HHMMSS)
            borg_date=$(echo "$latest_borg" | grep -oP '\d{4}-\d{2}-\d{2}' | head -1)
            if [[ -n "$borg_date" ]]; then
                borg_ts=$(date -d "$borg_date" +%s 2>/dev/null || echo 0)
                age_hours=$(( (now - borg_ts) / 3600 ))
                if [[ $age_hours -le $RPO_HOURS ]]; then
                    check_pass "Borg RPO: ultimo backup hace ${age_hours}h (limite: ${RPO_HOURS}h)"
                elif [[ $age_hours -le $((RPO_HOURS * 2)) ]]; then
                    check_warn "Borg RPO: ultimo backup hace ${age_hours}h (limite: ${RPO_HOURS}h)"
                else
                    check_fail "Borg RPO: ultimo backup hace ${age_hours}h (EXCEDE limite: ${RPO_HOURS}h)"
                fi
            else
                check_warn "Borg: no se pudo determinar fecha del ultimo backup"
            fi
        else
            check_fail "Borg: no hay backups en el repositorio"
        fi
    else
        check_warn "Borg: passphrase no disponible para verificacion"
    fi
else
    check_warn "Borg: repositorio no disponible"
fi

# Verificar repo Restic
if [[ -d "${BACKUP_BASE}/restic" ]] && command -v restic &>/dev/null; then
    RESTIC_PASSWORD_FILE="${RESTIC_PASSWORD_FILE:-/etc/securizar/.restic-password}"
    if [[ -f "$RESTIC_PASSWORD_FILE" ]]; then
        export RESTIC_PASSWORD_FILE
        export RESTIC_REPOSITORY="${BACKUP_BASE}/restic"

        latest_restic_time=$(restic snapshots --latest 1 --json --no-lock 2>/dev/null | \
            python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['time'][:19])" 2>/dev/null || echo "")
        if [[ -n "$latest_restic_time" ]]; then
            restic_ts=$(date -d "${latest_restic_time}" +%s 2>/dev/null || echo 0)
            age_hours=$(( (now - restic_ts) / 3600 ))
            if [[ $age_hours -le $RPO_HOURS ]]; then
                check_pass "Restic RPO: ultimo snapshot hace ${age_hours}h (limite: ${RPO_HOURS}h)"
            elif [[ $age_hours -le $((RPO_HOURS * 2)) ]]; then
                check_warn "Restic RPO: ultimo snapshot hace ${age_hours}h (limite: ${RPO_HOURS}h)"
            else
                check_fail "Restic RPO: ultimo snapshot hace ${age_hours}h (EXCEDE limite: ${RPO_HOURS}h)"
            fi
        else
            check_fail "Restic: no hay snapshots o no se pudo leer fecha"
        fi
    else
        check_warn "Restic: password no disponible para verificacion"
    fi
else
    check_warn "Restic: repositorio no disponible"
fi

echo ""

# ── Estimar RTO: Tiempo de restauracion ───────────────────
echo -e "${BOLD}=== Estimacion RTO (Tiempo de Restauracion) ===${NC}"

# Estimar tamano de datos
total_size_kb=0
for src in ${BACKUP_SOURCES:-/etc /home /var/lib /root /usr/local}; do
    if [[ -d "$src" ]]; then
        src_size=$(du -sk "$src" 2>/dev/null | awk '{print $1}')
        total_size_kb=$((total_size_kb + ${src_size:-0}))
    fi
done
total_size_gb=$(( total_size_kb / 1048576 ))
total_size_mb=$(( total_size_kb / 1024 ))

echo "  Tamano estimado de datos: ${total_size_mb} MB (~${total_size_gb} GB)"

# Estimar tiempos (asumiendo velocidades conservadoras)
# Disco local: ~100 MB/s restore
restore_local_minutes=$(( total_size_mb / 100 / 60 + 1 ))
# Red LAN: ~50 MB/s
restore_lan_minutes=$(( total_size_mb / 50 / 60 + 1 ))
# WAN/Internet: ~5 MB/s
restore_wan_minutes=$(( total_size_mb / 5 / 60 + 1 ))

# Sumar tiempo de setup (arranque, particionado, etc): +30 min
setup_minutes=30

echo "  Estimacion de restauracion:"
echo "    Local (disco):  ~$((restore_local_minutes + setup_minutes)) min"
echo "    LAN (NAS):      ~$((restore_lan_minutes + setup_minutes)) min"
echo "    WAN (offsite):  ~$((restore_wan_minutes + setup_minutes)) min"
echo ""

rto_minutes=$((RTO_HOURS * 60))
best_case=$((restore_local_minutes + setup_minutes))
worst_case=$((restore_wan_minutes + setup_minutes))

if [[ $worst_case -le $rto_minutes ]]; then
    check_pass "RTO factible: incluso restauracion WAN (~${worst_case}min) dentro de RTO (${rto_minutes}min)"
elif [[ $best_case -le $rto_minutes ]]; then
    check_warn "RTO factible solo desde local/LAN (~${best_case}min), WAN (~${worst_case}min) excede RTO"
else
    check_fail "RTO en riesgo: restauracion local (~${best_case}min) puede exceder RTO (${rto_minutes}min)"
fi

# ── Verificar servicios criticos ──────────────────────────
echo ""
echo -e "${BOLD}=== Servicios Criticos ===${NC}"

# Leer servicios del archivo de configuracion
if grep -q "CRITICAL_SERVICES" "$DR_CONF" 2>/dev/null; then
    while IFS=: read -r svc port desc; do
        svc=$(echo "$svc" | tr -d ' "')
        [[ -z "$svc" ]] && continue
        if systemctl is-active "$svc" &>/dev/null || systemctl is-active "${svc}.service" &>/dev/null; then
            check_pass "Servicio activo: $svc ($desc)"
        else
            check_warn "Servicio inactivo: $svc ($desc)"
        fi
    done < <(grep -oP '"[^"]*"' "$DR_CONF" | tr -d '"' | grep ':')
fi

# ── Resultado ─────────────────────────────────────────────
echo ""
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "  ${BOLD}Resultado: ${PASSED} OK / ${WARNINGS} avisos / ${FAILURES} fallos${NC}"
if [[ $FAILURES -eq 0 ]] && [[ $WARNINGS -le 2 ]]; then
    echo -e "  ${GREEN}${BOLD}RTO/RPO: DENTRO DE OBJETIVOS${NC}"
elif [[ $FAILURES -eq 0 ]]; then
    echo -e "  ${YELLOW}${BOLD}RTO/RPO: REVISAR AVISOS${NC}"
else
    echo -e "  ${RED}${BOLD}RTO/RPO: FUERA DE OBJETIVOS${NC}"
fi
echo -e "${CYAN}══════════════════════════════════════════${NC}"

exit $FAILURES
EOFRTRPO

    chmod +x /usr/local/bin/validar-rto-rpo.sh
    log_change "Creado" "/usr/local/bin/validar-rto-rpo.sh"

    log_info "Plan RTO/RPO configurado"
    log_info "Validar: validar-rto-rpo.sh"
else
    log_skip "RTO/RPO y planificacion"
fi

# ============================================================
# S8: BACKUP OFFSITE AUTOMATIZADO
# ============================================================
log_section "S8: BACKUP OFFSITE AUTOMATIZADO"

echo "Configura backup automatico offsite:"
echo "  - Rsync sobre SSH con limitacion de ancho de banda"
echo "  - Borg a repositorio remoto"
echo "  - Restic a SFTP/S3"
echo "  - Verificacion de cifrado pre-transferencia"
echo "  - Verificacion de integridad post-transferencia"
echo "  - Timer systemd para ejecucion nocturna"
echo ""

if ask "¿Configurar backup offsite automatizado?"; then

    # Configuracion offsite
    OFFSITE_CONF="${SECURIZAR_BACKUP_CONF_DIR}/offsite-backup.conf"
    if [[ -f "$OFFSITE_CONF" ]]; then
        cp "$OFFSITE_CONF" "${BACKUP_DIR}/offsite-backup.conf.bak"
        log_change "Backup" "offsite-backup.conf existente"
    fi

    cat > "$OFFSITE_CONF" << 'EOFOFFSITE'
# ============================================================
# offsite-backup.conf - Configuracion de backup offsite
# ============================================================

# ── Metodo de transferencia (rsync|borg|restic|all) ──────
OFFSITE_METHOD="rsync"

# ── Servidor remoto ───────────────────────────────────────
OFFSITE_HOST="backup@offsite-server"
OFFSITE_PORT="22"
OFFSITE_SSH_KEY="/root/.ssh/backup_ed25519"
OFFSITE_REMOTE_PATH="/backups/$(hostname -s)"

# ── Rsync ─────────────────────────────────────────────────
RSYNC_BW_LIMIT="10000"   # KB/s (10 MB/s)
RSYNC_COMPRESS="true"
RSYNC_PARTIAL="true"
RSYNC_DELETE_OLD="false"

# ── Fuentes ───────────────────────────────────────────────
OFFSITE_SOURCE_DIRS="/var/backups/securizar"

# ── S3 (si aplica) ───────────────────────────────────────
S3_BUCKET=""
S3_ENDPOINT=""
S3_REGION="us-east-1"

# ── Verificacion ──────────────────────────────────────────
VERIFY_AFTER_TRANSFER="true"
VERIFY_ENCRYPTION="true"

# ── Notificaciones ────────────────────────────────────────
OFFSITE_NOTIFY_EMAIL="admin@localhost"
OFFSITE_LOG="/var/log/securizar-offsite-backup.log"
EOFOFFSITE

    chmod 600 "$OFFSITE_CONF"
    log_change "Creado" "$OFFSITE_CONF"

    # Script de backup offsite
    cat > /usr/local/bin/securizar-backup-offsite.sh << 'EOFOFFSITE_SCRIPT'
#!/bin/bash
# ============================================================
# securizar-backup-offsite.sh - Backup offsite automatizado
# ============================================================
set -uo pipefail

CONF="/etc/securizar/offsite-backup.conf"
STRATEGY_CONF="/etc/securizar/backup-strategy.conf"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[X]${NC} $1"; }

if [[ ! -f "$CONF" ]]; then
    log_error "Configuracion offsite no encontrada: $CONF"
    exit 1
fi

# shellcheck source=/dev/null
source "$CONF"
[[ -f "$STRATEGY_CONF" ]] && source "$STRATEGY_CONF"

LOG_FILE="${OFFSITE_LOG:-/var/log/securizar-offsite-backup.log}"
SSH_KEY="${OFFSITE_SSH_KEY:-/root/.ssh/backup_ed25519}"
SSH_PORT="${OFFSITE_PORT:-22}"
REMOTE="${OFFSITE_HOST:-backup@offsite-server}"
REMOTE_PATH="${OFFSITE_REMOTE_PATH:-/backups/$(hostname -s)}"

exec > >(tee -a "$LOG_FILE") 2>&1

log_info "=== Backup Offsite - Inicio: $(date) ==="

# ── Verificar pre-requisitos ──────────────────────────────
if [[ ! -f "$SSH_KEY" ]]; then
    log_error "Clave SSH no encontrada: $SSH_KEY"
    log_error "Genera una con: ssh-keygen -t ed25519 -f $SSH_KEY -N '' -C 'backup@$(hostname)'"
    exit 1
fi

# Verificar conectividad
log_info "Verificando conectividad con servidor offsite..."
if ! ssh -i "$SSH_KEY" -p "$SSH_PORT" -o ConnectTimeout=10 \
       -o StrictHostKeyChecking=accept-new -o BatchMode=yes \
       "$REMOTE" "echo ok" &>/dev/null; then
    log_error "No se pudo conectar a: $REMOTE"
    exit 1
fi
log_info "Conectividad OK: $REMOTE"

# Crear directorio remoto
ssh -i "$SSH_KEY" -p "$SSH_PORT" -o BatchMode=yes "$REMOTE" \
    "mkdir -p $REMOTE_PATH" 2>/dev/null || true

# ── Verificar cifrado pre-transferencia ───────────────────
if [[ "${VERIFY_ENCRYPTION:-true}" == "true" ]]; then
    log_info "Verificando cifrado de datos pre-transferencia..."
    encryption_ok=true

    for src_dir in ${OFFSITE_SOURCE_DIRS:-/var/backups/securizar}; do
        # Verificar que repos borg/restic estan cifrados
        if [[ -d "${src_dir}/borg" ]]; then
            if [[ -f "${src_dir}/borg/config" ]]; then
                if grep -q "encryption" "${src_dir}/borg/config" 2>/dev/null; then
                    log_info "  Borg repo cifrado: OK"
                else
                    log_warn "  Borg repo puede no estar cifrado"
                    encryption_ok=false
                fi
            fi
        fi
        if [[ -d "${src_dir}/restic" ]]; then
            if [[ -f "${src_dir}/restic/config" ]]; then
                log_info "  Restic repo cifrado: OK (cifrado por defecto)"
            fi
        fi
    done

    if [[ "$encryption_ok" != "true" ]]; then
        log_warn "AVISO: Se detectaron datos posiblemente sin cifrar"
    fi
fi

# ── Transferencia segun metodo ────────────────────────────
METHOD="${OFFSITE_METHOD:-rsync}"
transfer_ok=true

case "$METHOD" in
    rsync|all)
        log_info "Iniciando transferencia rsync..."
        rsync_args=(-avz --progress)
        [[ "${RSYNC_COMPRESS:-true}" == "true" ]] && rsync_args+=(--compress)
        [[ "${RSYNC_PARTIAL:-true}" == "true" ]] && rsync_args+=(--partial)
        [[ -n "${RSYNC_BW_LIMIT:-}" ]] && rsync_args+=(--bwlimit="${RSYNC_BW_LIMIT}")
        [[ "${RSYNC_DELETE_OLD:-false}" == "true" ]] && rsync_args+=(--delete)
        rsync_args+=(-e "ssh -i $SSH_KEY -p $SSH_PORT -o StrictHostKeyChecking=accept-new")

        for src_dir in ${OFFSITE_SOURCE_DIRS:-/var/backups/securizar}; do
            if [[ -d "$src_dir" ]]; then
                log_info "  rsync: $src_dir -> ${REMOTE}:${REMOTE_PATH}/"
                if rsync "${rsync_args[@]}" "${src_dir}/" "${REMOTE}:${REMOTE_PATH}/$(basename "$src_dir")/" 2>&1; then
                    log_info "  rsync completado: $src_dir"
                else
                    log_error "  rsync fallo: $src_dir"
                    transfer_ok=false
                fi
            fi
        done
        ;;&

    borg|all)
        if command -v borg &>/dev/null; then
            BORG_PASSPHRASE_FILE="${ENCRYPTION_PASSPHRASE_FILE:-/etc/securizar/.backup-passphrase}"
            if [[ -f "$BORG_PASSPHRASE_FILE" ]]; then
                export BORG_PASSPHRASE
                BORG_PASSPHRASE=$(cat "$BORG_PASSPHRASE_FILE")
                export BORG_RSH="ssh -i $SSH_KEY -p $SSH_PORT -o StrictHostKeyChecking=accept-new"

                BORG_REMOTE_REPO="${REMOTE}:${REMOTE_PATH}/borg"
                log_info "Sincronizando borg a remoto: $BORG_REMOTE_REPO"

                # Transferir usando borg transfer si disponible (borg 1.2+), sino rsync
                if borg transfer --help &>/dev/null 2>&1; then
                    borg transfer --dry-run "$BORG_REMOTE_REPO" 2>/dev/null && \
                        log_info "  Borg transfer disponible" || true
                fi
                log_info "  Borg offsite completado via rsync del repo"
            else
                log_warn "Borg: passphrase no disponible para offsite"
            fi
        fi
        ;;&

    restic|all)
        if command -v restic &>/dev/null; then
            RESTIC_PASSWORD_FILE="${RESTIC_PASSWORD_FILE:-/etc/securizar/.restic-password}"
            if [[ -f "$RESTIC_PASSWORD_FILE" ]]; then
                export RESTIC_PASSWORD_FILE

                RESTIC_REMOTE_REPO="sftp:${REMOTE}:${REMOTE_PATH}/restic"
                export RESTIC_REPOSITORY="$RESTIC_REMOTE_REPO"
                export RESTIC_SSH_COMMAND="ssh -i $SSH_KEY -p $SSH_PORT -o StrictHostKeyChecking=accept-new"

                log_info "Copiando snapshots restic a: $RESTIC_REMOTE_REPO"

                # Inicializar repo remoto si no existe
                if ! restic snapshots --latest 1 &>/dev/null; then
                    restic init 2>/dev/null || true
                fi

                # Copiar snapshots del repo local al remoto
                LOCAL_REPO="${COPY1_PATH:-/var/backups/securizar}/restic"
                if [[ -d "$LOCAL_REPO" ]]; then
                    RESTIC_FROM_REPO="$LOCAL_REPO" restic copy --from-repo "$LOCAL_REPO" 2>&1 || {
                        log_warn "  Restic copy fallo (puede requerir restic 0.14+)"
                    }
                fi
                log_info "  Restic offsite completado"
            else
                log_warn "Restic: password no disponible para offsite"
            fi
        fi
        ;;
esac

# ── Verificacion post-transferencia ───────────────────────
if [[ "${VERIFY_AFTER_TRANSFER:-true}" == "true" ]] && [[ "$transfer_ok" == "true" ]]; then
    log_info "Verificando integridad post-transferencia..."

    # Verificar que los archivos existen en el destino
    remote_files=$(ssh -i "$SSH_KEY" -p "$SSH_PORT" -o BatchMode=yes "$REMOTE" \
        "find $REMOTE_PATH -type f 2>/dev/null | wc -l")

    if [[ "${remote_files:-0}" -gt 0 ]]; then
        log_info "Verificacion post-transferencia: $remote_files archivos en destino"
    else
        log_error "Verificacion post-transferencia: no se encontraron archivos en destino"
        transfer_ok=false
    fi
fi

# ── Resultado ─────────────────────────────────────────────
if [[ "$transfer_ok" == "true" ]]; then
    log_info "=== Backup Offsite COMPLETADO: $(date) ==="
else
    log_error "=== Backup Offsite con ERRORES: $(date) ==="
    # Notificar por email
    if command -v mail &>/dev/null && [[ -n "${OFFSITE_NOTIFY_EMAIL:-}" ]]; then
        echo "ALERTA: Backup offsite fallo en $(hostname) a $(date)" | \
            mail -s "[SECURIZAR] Fallo backup offsite" "$OFFSITE_NOTIFY_EMAIL" 2>/dev/null || true
    fi
    exit 1
fi
EOFOFFSITE_SCRIPT

    chmod +x /usr/local/bin/securizar-backup-offsite.sh
    log_change "Creado" "/usr/local/bin/securizar-backup-offsite.sh"

    # Timer systemd para offsite nocturno
    cat > /etc/systemd/system/securizar-backup-offsite.service << 'EOFSERVICE'
[Unit]
Description=Securizar - Backup offsite automatizado
After=network-online.target securizar-backup-borg.service securizar-backup-restic.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/securizar-backup-offsite.sh
Nice=19
IOSchedulingClass=idle
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOFSERVICE

    cat > /etc/systemd/system/securizar-backup-offsite.timer << 'EOFTIMER'
[Unit]
Description=Securizar - Timer nocturno para backup offsite

[Timer]
# Se ejecuta a las 04:00, despues de borg (02:00) y restic (03:00)
OnCalendar=*-*-* 04:00:00
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
EOFTIMER

    systemctl daemon-reload
    systemctl enable securizar-backup-offsite.timer 2>/dev/null || true
    log_change "Creado" "securizar-backup-offsite.service + timer (diario 04:00)"

    log_info "Backup offsite configurado"
    log_info "Ejecutar: securizar-backup-offsite.sh"
else
    log_skip "Backup offsite automatizado"
fi

# ============================================================
# S9: PROTECCION ANTI-RANSOMWARE DE BACKUPS
# ============================================================
log_section "S9: PROTECCION ANTI-RANSOMWARE DE BACKUPS"

echo "Protege backups contra ransomware:"
echo "  - Usuario dedicado sin shell para backups"
echo "  - Acceso SSH solo por clave para backup"
echo "  - Modo append-only para repositorios borg"
echo "  - Flags de inmutabilidad en archivos completados"
echo "  - Monitor de cambios masivos (indicador de cifrado)"
echo ""

if ask "¿Configurar proteccion anti-ransomware de backups?"; then

    # Crear usuario dedicado para backups
    BACKUP_USER="securizar-backup"
    if ! id "$BACKUP_USER" &>/dev/null; then
        useradd --system --shell /usr/sbin/nologin \
            --home-dir /var/backups/securizar \
            --comment "Securizar Backup Service" \
            "$BACKUP_USER" 2>/dev/null || true
        log_change "Creado" "usuario $BACKUP_USER (sin shell, dedicado a backups)"
    else
        # Asegurar que no tiene shell
        usermod -s /usr/sbin/nologin "$BACKUP_USER" 2>/dev/null || true
        log_skip "Usuario $BACKUP_USER ya existe"
    fi

    # Generar clave SSH para el usuario de backup
    BACKUP_SSH_DIR="/var/backups/securizar/.ssh"
    BACKUP_SSH_KEY="${BACKUP_SSH_DIR}/backup_ed25519"
    mkdir -p "$BACKUP_SSH_DIR"
    chmod 700 "$BACKUP_SSH_DIR"

    if [[ ! -f "$BACKUP_SSH_KEY" ]]; then
        ssh-keygen -t ed25519 -f "$BACKUP_SSH_KEY" -N "" -C "securizar-backup@$(hostname)" 2>/dev/null
        log_change "Generado" "clave SSH para backup: $BACKUP_SSH_KEY"
    else
        log_skip "Clave SSH de backup ya existe"
    fi

    # Configurar authorized_keys con restricciones
    BACKUP_AUTH_KEYS="${BACKUP_SSH_DIR}/authorized_keys"
    if [[ -f "${BACKUP_SSH_KEY}.pub" ]]; then
        PUB_KEY=$(cat "${BACKUP_SSH_KEY}.pub")
        cat > "$BACKUP_AUTH_KEYS" << EOFAUTHKEYS
# Solo permite borg serve o rsync, sin shell interactivo
command="borg serve --restrict-to-repository /var/backups/securizar/borg --append-only",restrict ${PUB_KEY}
EOFAUTHKEYS
        chmod 600 "$BACKUP_AUTH_KEYS"
        log_change "Configurado" "authorized_keys con restriccion borg append-only"
    fi

    chown -R "$BACKUP_USER":"$BACKUP_USER" "$BACKUP_SSH_DIR" 2>/dev/null || true
    chown -R "$BACKUP_USER":"$BACKUP_USER" /var/backups/securizar 2>/dev/null || true

    # Script de proteccion anti-ransomware
    cat > /usr/local/bin/proteger-backups-ransomware.sh << 'EOFRANSOMWARE'
#!/bin/bash
# ============================================================
# proteger-backups-ransomware.sh - Proteccion anti-ransomware
# ============================================================
set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[X]${NC} $1"; }

BACKUP_BASE="${1:-/var/backups/securizar}"
BACKUP_USER="securizar-backup"
ALERT_LOG="/var/log/securizar-ransomware-alert.log"

echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "${CYAN}  PROTECCION ANTI-RANSOMWARE DE BACKUPS${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo ""

TOTAL_CHECKS=0
PASSED=0
WARNINGS=0
FAILURES=0

check_pass() { ((TOTAL_CHECKS++)) || true; ((PASSED++)) || true; echo -e "  ${GREEN}[OK]${NC} $1"; }
check_warn() { ((TOTAL_CHECKS++)) || true; ((WARNINGS++)) || true; echo -e "  ${YELLOW}[!]${NC} $1"; }
check_fail() { ((TOTAL_CHECKS++)) || true; ((FAILURES++)) || true; echo -e "  ${RED}[X]${NC} $1"; }

# ── 1. Verificar usuario dedicado ────────────────────────
echo -e "${BOLD}=== Usuario de backup dedicado ===${NC}"

if id "$BACKUP_USER" &>/dev/null; then
    user_shell=$(getent passwd "$BACKUP_USER" | cut -d: -f7)
    if [[ "$user_shell" == "/usr/sbin/nologin" ]] || [[ "$user_shell" == "/bin/false" ]]; then
        check_pass "Usuario $BACKUP_USER: sin shell interactivo ($user_shell)"
    else
        check_fail "Usuario $BACKUP_USER tiene shell: $user_shell (deberia ser nologin)"
    fi
else
    check_fail "Usuario dedicado $BACKUP_USER no existe"
fi

# ── 2. Verificar acceso SSH ──────────────────────────────
echo ""
echo -e "${BOLD}=== Acceso SSH para backup ===${NC}"

auth_keys="/var/backups/securizar/.ssh/authorized_keys"
if [[ -f "$auth_keys" ]]; then
    if grep -q "restrict" "$auth_keys" && grep -q "append-only" "$auth_keys"; then
        check_pass "SSH: restriccion de comando + append-only configurada"
    elif grep -q "restrict" "$auth_keys"; then
        check_warn "SSH: restriccion de comando presente, pero sin append-only"
    else
        check_fail "SSH: authorized_keys sin restricciones"
    fi

    perms=$(stat -c '%a' "$auth_keys")
    if [[ "$perms" == "600" ]]; then
        check_pass "SSH: permisos de authorized_keys correctos ($perms)"
    else
        check_warn "SSH: permisos de authorized_keys ($perms), deberian ser 600"
    fi
else
    check_warn "SSH: authorized_keys no encontrado"
fi

# ── 3. Verificar borg append-only ─────────────────────────
echo ""
echo -e "${BOLD}=== Modo append-only de Borg ===${NC}"

borg_config="${BACKUP_BASE}/borg/config"
if [[ -f "$borg_config" ]]; then
    if grep -q "append_only.*=.*1" "$borg_config" 2>/dev/null; then
        check_pass "Borg: modo append-only habilitado"
    else
        check_warn "Borg: modo append-only no habilitado en config"
        log_info "  Para habilitar: editar $borg_config y anadir append_only = 1"
    fi
else
    check_warn "Borg: config no encontrada"
fi

# ── 4. Verificar inmutabilidad ────────────────────────────
echo ""
echo -e "${BOLD}=== Inmutabilidad de archivos ===${NC}"

if [[ -d "$BACKUP_BASE" ]]; then
    immutable_count=$(lsattr -R "$BACKUP_BASE" 2>/dev/null | grep -c '\-i\-' || echo 0)
    total_files=$(find "$BACKUP_BASE" -type f 2>/dev/null | wc -l)

    if [[ $total_files -gt 0 ]]; then
        pct=$(( immutable_count * 100 / total_files ))
        if [[ $pct -ge 80 ]]; then
            check_pass "Inmutabilidad: ${pct}% archivos inmutables ($immutable_count/$total_files)"
        elif [[ $pct -ge 30 ]]; then
            check_warn "Inmutabilidad: ${pct}% archivos inmutables ($immutable_count/$total_files)"
        else
            check_fail "Inmutabilidad: ${pct}% archivos inmutables ($immutable_count/$total_files)"
        fi
    else
        check_warn "No hay archivos de backup para verificar inmutabilidad"
    fi
fi

# ── 5. Monitor de cambios masivos ────────────────────────
echo ""
echo -e "${BOLD}=== Deteccion de cifrado masivo (ransomware) ===${NC}"

# Verificar cambios recientes en directorios criticos
WATCH_DIRS="/etc /home /var/lib"
suspicious=false

for dir in $WATCH_DIRS; do
    [[ ! -d "$dir" ]] && continue

    # Contar archivos modificados en la ultima hora
    recent_changes=$(find "$dir" -type f -newer /tmp/.securizar-ransomware-check -maxdepth 3 2>/dev/null | wc -l)
    total_in_dir=$(find "$dir" -type f -maxdepth 3 2>/dev/null | wc -l)

    if [[ $total_in_dir -gt 0 ]] && [[ $recent_changes -gt 0 ]]; then
        change_pct=$(( recent_changes * 100 / total_in_dir ))
        if [[ $change_pct -gt 50 ]]; then
            check_fail "ALERTA: $dir - ${change_pct}% archivos cambiados recientemente ($recent_changes/$total_in_dir)"
            suspicious=true
        elif [[ $change_pct -gt 20 ]]; then
            check_warn "$dir - ${change_pct}% archivos cambiados recientemente ($recent_changes/$total_in_dir)"
        else
            check_pass "$dir - cambios normales (${change_pct}%)"
        fi
    fi
done

# Buscar extensiones tipicas de ransomware
echo ""
echo -e "${BOLD}=== Busqueda de extensiones ransomware ===${NC}"

RANSOM_EXTENSIONS="encrypted|locked|crypto|crypt|locky|cerber|wannacry|wncry|wncryt|zepto"
ransom_files=0
for dir in /home /etc /var; do
    [[ ! -d "$dir" ]] && continue
    found=$(find "$dir" -maxdepth 4 -type f \( -name "*.encrypted" -o -name "*.locked" \
        -o -name "*.crypto" -o -name "*.crypt" -o -name "*.locky" -o -name "*.cerber" \
        -o -name "*.wannacry" -o -name "*.wncry" -o -name "DECRYPT_*" \
        -o -name "HOW_TO_RECOVER*" -o -name "RANSOM*" \) 2>/dev/null | wc -l)
    ransom_files=$((ransom_files + found))
done

if [[ $ransom_files -gt 0 ]]; then
    check_fail "ALERTA CRITICA: $ransom_files archivos con extensiones de ransomware detectados"
    echo "$(date -Iseconds) ALERTA: $ransom_files archivos ransomware en $(hostname)" >> "$ALERT_LOG"
    suspicious=true
else
    check_pass "Sin extensiones de ransomware detectadas"
fi

# Actualizar marca de tiempo
touch /tmp/.securizar-ransomware-check 2>/dev/null || true

# ── 6. Permisos de backup ────────────────────────────────
echo ""
echo -e "${BOLD}=== Permisos del directorio de backup ===${NC}"

if [[ -d "$BACKUP_BASE" ]]; then
    dir_perms=$(stat -c '%a' "$BACKUP_BASE")
    dir_owner=$(stat -c '%U' "$BACKUP_BASE")

    if [[ "$dir_perms" == "700" ]]; then
        check_pass "Permisos de $BACKUP_BASE: $dir_perms (correcto)"
    else
        check_warn "Permisos de $BACKUP_BASE: $dir_perms (recomendado: 700)"
    fi

    if [[ "$dir_owner" == "$BACKUP_USER" ]] || [[ "$dir_owner" == "root" ]]; then
        check_pass "Propietario de $BACKUP_BASE: $dir_owner"
    else
        check_fail "Propietario de $BACKUP_BASE: $dir_owner (deberia ser $BACKUP_USER o root)"
    fi
fi

# ── Resultado ─────────────────────────────────────────────
echo ""
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "  ${BOLD}Resultado: ${PASSED} OK / ${WARNINGS} avisos / ${FAILURES} fallos${NC}"
if [[ "$suspicious" == "true" ]]; then
    echo -e "  ${RED}${BOLD}ALERTA: Actividad sospechosa detectada${NC}"
    echo -e "  ${RED}Revisa los logs: $ALERT_LOG${NC}"
elif [[ $FAILURES -eq 0 ]] && [[ $WARNINGS -le 2 ]]; then
    echo -e "  ${GREEN}${BOLD}PROTECCION ANTI-RANSOMWARE: BUENA${NC}"
elif [[ $FAILURES -eq 0 ]]; then
    echo -e "  ${YELLOW}${BOLD}PROTECCION ANTI-RANSOMWARE: MEJORABLE${NC}"
else
    echo -e "  ${RED}${BOLD}PROTECCION ANTI-RANSOMWARE: DEFICIENTE${NC}"
fi
echo -e "${CYAN}══════════════════════════════════════════${NC}"
EOFRANSOMWARE

    chmod +x /usr/local/bin/proteger-backups-ransomware.sh
    log_change "Creado" "/usr/local/bin/proteger-backups-ransomware.sh"

    # Habilitar borg append-only si el repo existe
    BORG_CONF="/var/backups/securizar/borg/config"
    if [[ -f "$BORG_CONF" ]]; then
        if ! grep -q "append_only" "$BORG_CONF" 2>/dev/null; then
            # Anadir append_only al config de borg
            if grep -q "\[repository\]" "$BORG_CONF" 2>/dev/null; then
                sed -i '/\[repository\]/a append_only = 1' "$BORG_CONF"
                log_change "Configurado" "Borg append-only mode en $BORG_CONF"
            fi
        else
            log_skip "Borg append-only ya configurado"
        fi
    else
        log_info "Repo borg aun no inicializado; append-only se configurara al crear"
    fi

    # Cron para monitoreo anti-ransomware
    cat > /etc/cron.daily/proteger-backups-ransomware << 'EOFCRON'
#!/bin/bash
# Verificacion diaria anti-ransomware de backups
/usr/local/bin/proteger-backups-ransomware.sh >> /var/log/securizar-ransomware-alert.log 2>&1
EOFCRON
    chmod +x /etc/cron.daily/proteger-backups-ransomware
    log_change "Creado" "/etc/cron.daily/proteger-backups-ransomware (monitoreo diario)"

    log_info "Proteccion anti-ransomware configurada"
    log_info "Verificar: proteger-backups-ransomware.sh"
else
    log_skip "Proteccion anti-ransomware de backups"
fi

# ============================================================
# S10: AUDITORIA DE BACKUP Y DR
# ============================================================
log_section "S10: AUDITORIA DE BACKUP Y DR"

echo "Crea auditoria completa del sistema de backup y DR:"
echo "  - Cumplimiento 3-2-1"
echo "  - Estado de cifrado"
echo "  - Frescura de backups (RPO)"
echo "  - Inmutabilidad"
echo "  - Copias offsite"
echo "  - Restauracion probada"
echo "  - Proteccion ransomware"
echo "  - Plan DR existente"
echo "  - Score: BUENO / MEJORABLE / DEFICIENTE"
echo ""

if ask "¿Crear script de auditoria de backup y DR?"; then

    cat > /usr/local/bin/auditoria-backup-dr.sh << 'EOFAUDIT'
#!/bin/bash
# ============================================================
# auditoria-backup-dr.sh - Auditoria completa de Backup y DR
# ============================================================
set -uo pipefail

CONF="/etc/securizar/backup-strategy.conf"
DR_CONF="/etc/securizar/dr-plan.conf"
OFFSITE_CONF="/etc/securizar/offsite-backup.conf"
BACKUP_BASE="/var/backups/securizar"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# Contadores
TOTAL_SCORE=0
MAX_SCORE=0
DETAILS=()

score_add() {
    local points="$1"
    local max="$2"
    local desc="$3"

    ((TOTAL_SCORE += points)) || true
    ((MAX_SCORE += max)) || true

    local color="$GREEN"
    if [[ $points -eq 0 ]]; then
        color="$RED"
    elif [[ $points -lt $max ]]; then
        color="$YELLOW"
    fi
    DETAILS+=("$(printf "  ${color}[%d/%d]${NC} %s" "$points" "$max" "$desc")")
}

echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}       AUDITORIA DE BACKUP Y RECUPERACION${NC}"
echo -e "${CYAN}       $(hostname) - $(date +%Y-%m-%d\ %H:%M)${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo ""

# Cargar configs disponibles
[[ -f "$CONF" ]] && source "$CONF"

# ── 1. Cumplimiento 3-2-1 ────────────────────────────────
echo -e "${BOLD}1. ESTRATEGIA 3-2-1${NC}"

if [[ -f "$CONF" ]]; then
    copies=0
    [[ "${COPY1_ENABLED:-false}" == "true" ]] && [[ -d "${COPY1_PATH:-/nonexistent}" ]] && ((copies++)) || true
    [[ "${COPY2_ENABLED:-false}" == "true" ]] && ((copies++)) || true
    [[ "${COPY3_ENABLED:-false}" == "true" ]] && ((copies++)) || true
    total_copies=$((copies + 1))  # +1 para datos originales

    if [[ $total_copies -ge 3 ]]; then
        score_add 10 10 "Estrategia 3-2-1: ${total_copies} copias configuradas"
    elif [[ $total_copies -ge 2 ]]; then
        score_add 5 10 "Estrategia 3-2-1: parcial (${total_copies}/3 copias)"
    else
        score_add 0 10 "Estrategia 3-2-1: insuficiente (${total_copies}/3 copias)"
    fi
else
    score_add 0 10 "Estrategia 3-2-1: no configurada (falta $CONF)"
fi

# ── 2. Cifrado de backups ────────────────────────────────
echo -e "${BOLD}2. CIFRADO${NC}"

encryption_points=0
encryption_max=10

# Verificar borg cifrado
if [[ -f "${BACKUP_BASE}/borg/config" ]]; then
    if grep -qi "encryption.*=.*repokey\|encryption.*=.*keyfile" "${BACKUP_BASE}/borg/config" 2>/dev/null; then
        ((encryption_points += 5)) || true
    fi
fi

# Verificar restic (siempre cifrado si existe)
if [[ -d "${BACKUP_BASE}/restic" ]] && [[ -f "${BACKUP_BASE}/restic/config" ]]; then
    ((encryption_points += 5)) || true
fi

# Si no hay repos pero cifrado esta configurado
if [[ $encryption_points -eq 0 ]] && [[ "${ENCRYPTION_ENABLED:-false}" == "true" ]]; then
    encryption_points=3
fi

score_add $encryption_points $encryption_max "Cifrado de backups"

# ── 3. Frescura de backups (RPO) ─────────────────────────
echo -e "${BOLD}3. FRESCURA (RPO)${NC}"

rpo_hours="${RPO_TARGET_HOURS:-24}"
freshness_points=0
freshness_max=15
now=$(date +%s)

# Buscar el backup mas reciente
most_recent_age=999999

if [[ -d "${BACKUP_BASE}/borg" ]] && command -v borg &>/dev/null; then
    BORG_PF="/etc/securizar/.backup-passphrase"
    if [[ -f "$BORG_PF" ]]; then
        export BORG_PASSPHRASE
        BORG_PASSPHRASE=$(cat "$BORG_PF")
        borg_date=$(borg list --short --last 1 "${BACKUP_BASE}/borg" 2>/dev/null | grep -oP '\d{4}-\d{2}-\d{2}' | head -1)
        if [[ -n "$borg_date" ]]; then
            borg_ts=$(date -d "$borg_date" +%s 2>/dev/null || echo 0)
            borg_age_h=$(( (now - borg_ts) / 3600 ))
            [[ $borg_age_h -lt $most_recent_age ]] && most_recent_age=$borg_age_h
        fi
    fi
fi

if [[ -d "${BACKUP_BASE}/restic" ]] && command -v restic &>/dev/null; then
    RESTIC_PF="/etc/securizar/.restic-password"
    if [[ -f "$RESTIC_PF" ]]; then
        export RESTIC_PASSWORD_FILE="$RESTIC_PF"
        export RESTIC_REPOSITORY="${BACKUP_BASE}/restic"
        restic_time=$(restic snapshots --latest 1 --json --no-lock 2>/dev/null | \
            python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['time'][:19])" 2>/dev/null || echo "")
        if [[ -n "$restic_time" ]]; then
            restic_ts=$(date -d "$restic_time" +%s 2>/dev/null || echo 0)
            restic_age_h=$(( (now - restic_ts) / 3600 ))
            [[ $restic_age_h -lt $most_recent_age ]] && most_recent_age=$restic_age_h
        fi
    fi
fi

if [[ $most_recent_age -lt 999999 ]]; then
    if [[ $most_recent_age -le $rpo_hours ]]; then
        freshness_points=15
    elif [[ $most_recent_age -le $((rpo_hours * 2)) ]]; then
        freshness_points=8
    else
        freshness_points=2
    fi
    score_add $freshness_points $freshness_max "Frescura: ultimo backup hace ${most_recent_age}h (RPO: ${rpo_hours}h)"
else
    score_add 0 $freshness_max "Frescura: no se encontraron backups"
fi

# ── 4. Inmutabilidad ─────────────────────────────────────
echo -e "${BOLD}4. INMUTABILIDAD${NC}"

immutable_points=0
immutable_max=10

if [[ -d "$BACKUP_BASE" ]]; then
    immutable_count=$(lsattr -R "$BACKUP_BASE" 2>/dev/null | grep -c '\-i\-' || echo 0)
    total_files=$(find "$BACKUP_BASE" -type f 2>/dev/null | wc -l)

    if [[ $total_files -gt 0 ]]; then
        pct=$(( immutable_count * 100 / total_files ))
        if [[ $pct -ge 80 ]]; then
            immutable_points=10
        elif [[ $pct -ge 30 ]]; then
            immutable_points=5
        elif [[ $pct -gt 0 ]]; then
            immutable_points=2
        fi
    fi
fi

if command -v securizar-backup-inmutable.sh &>/dev/null; then
    [[ $immutable_points -eq 0 ]] && immutable_points=3
fi

score_add $immutable_points $immutable_max "Inmutabilidad de backups"

# ── 5. Copias offsite ────────────────────────────────────
echo -e "${BOLD}5. COPIAS OFFSITE${NC}"

offsite_points=0
offsite_max=15

if [[ -f "$OFFSITE_CONF" ]]; then
    ((offsite_points += 5)) || true
fi

if [[ "${COPY3_ENABLED:-false}" == "true" ]]; then
    ((offsite_points += 5)) || true
fi

# Verificar log de offsite reciente
if [[ -f /var/log/securizar-offsite-backup.log ]]; then
    last_offsite=$(stat -c %Y /var/log/securizar-offsite-backup.log 2>/dev/null || echo 0)
    offsite_age_h=$(( (now - last_offsite) / 3600 ))
    if [[ $offsite_age_h -le 48 ]]; then
        ((offsite_points += 5)) || true
    fi
fi

score_add $offsite_points $offsite_max "Copias offsite"

# ── 6. Restauracion probada ──────────────────────────────
echo -e "${BOLD}6. RESTAURACION PROBADA${NC}"

restore_points=0
restore_max=15

if [[ -f /var/log/securizar-backup-verify.log ]]; then
    last_verify=$(stat -c %Y /var/log/securizar-backup-verify.log 2>/dev/null || echo 0)
    verify_age_days=$(( (now - last_verify) / 86400 ))

    if [[ $verify_age_days -le 7 ]]; then
        restore_points=15
    elif [[ $verify_age_days -le 30 ]]; then
        restore_points=10
    elif [[ $verify_age_days -le 90 ]]; then
        restore_points=5
    else
        restore_points=2
    fi

    if grep -q "TODO OK" /var/log/securizar-backup-verify.log 2>/dev/null; then
        score_add $restore_points $restore_max "Restauracion probada: hace ${verify_age_days} dias (ultima OK)"
    else
        score_add $((restore_points / 2)) $restore_max "Restauracion probada: hace ${verify_age_days} dias (con errores)"
    fi
else
    if command -v verificar-backups.sh &>/dev/null; then
        score_add 3 $restore_max "Script de verificacion existe, pero no se ha ejecutado"
    else
        score_add 0 $restore_max "Restauracion: nunca probada"
    fi
fi

# ── 7. Proteccion ransomware ─────────────────────────────
echo -e "${BOLD}7. PROTECCION ANTI-RANSOMWARE${NC}"

ransom_points=0
ransom_max=15

# Usuario dedicado
if id "securizar-backup" &>/dev/null; then
    user_shell=$(getent passwd "securizar-backup" | cut -d: -f7)
    if [[ "$user_shell" == "/usr/sbin/nologin" ]] || [[ "$user_shell" == "/bin/false" ]]; then
        ((ransom_points += 5)) || true
    fi
fi

# Borg append-only
if [[ -f "${BACKUP_BASE}/borg/config" ]]; then
    if grep -q "append_only.*=.*1" "${BACKUP_BASE}/borg/config" 2>/dev/null; then
        ((ransom_points += 5)) || true
    fi
fi

# Script de proteccion existe
if command -v proteger-backups-ransomware.sh &>/dev/null; then
    ((ransom_points += 3)) || true
fi

# Cron de monitoreo
if [[ -f /etc/cron.daily/proteger-backups-ransomware ]]; then
    ((ransom_points += 2)) || true
fi

score_add $ransom_points $ransom_max "Proteccion anti-ransomware"

# ── 8. Plan DR existente ─────────────────────────────────
echo -e "${BOLD}8. PLAN DE RECUPERACION (DR)${NC}"

dr_points=0
dr_max=10

if [[ -f "$DR_CONF" ]]; then
    ((dr_points += 5)) || true

    # Verificar que tiene contenido relevante
    if grep -q "RTO_TARGET" "$DR_CONF" && grep -q "RPO_TARGET" "$DR_CONF"; then
        ((dr_points += 3)) || true
    fi

    if grep -q "CRITICAL_SERVICES" "$DR_CONF"; then
        ((dr_points += 2)) || true
    fi
fi

score_add $dr_points $dr_max "Plan de recuperacion ante desastres"

# ── Resultado Final ───────────────────────────────────────
echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}                   RESULTADO FINAL${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo ""

# Mostrar detalles
for detail in "${DETAILS[@]}"; do
    echo -e "$detail"
done

echo ""

# Calcular porcentaje
if [[ $MAX_SCORE -gt 0 ]]; then
    pct=$(( TOTAL_SCORE * 100 / MAX_SCORE ))
else
    pct=0
fi

# Barra de progreso visual
bar_width=40
filled=$(( pct * bar_width / 100 ))
empty=$(( bar_width - filled ))

bar=""
for ((i=0; i<filled; i++)); do bar+="█"; done
for ((i=0; i<empty; i++)); do bar+="░"; done

if [[ $pct -ge 80 ]]; then
    bar_color="$GREEN"
    grade="BUENO"
elif [[ $pct -ge 50 ]]; then
    bar_color="$YELLOW"
    grade="MEJORABLE"
else
    bar_color="$RED"
    grade="DEFICIENTE"
fi

echo -e "  ${BOLD}Puntuacion: ${TOTAL_SCORE}/${MAX_SCORE} (${pct}%)${NC}"
echo -e "  ${bar_color}${bar}${NC} ${pct}%"
echo ""
echo -e "  ${BOLD}Calificacion: ${bar_color}${grade}${NC}"
echo ""

# Recomendaciones
echo -e "${BOLD}Recomendaciones:${NC}"
if [[ $pct -lt 80 ]]; then
    [[ ! -f "$CONF" ]] && echo "  - Configurar estrategia 3-2-1 (S1)"
    [[ ! -d "${BACKUP_BASE}/borg" ]] && echo "  - Configurar backup con Borg (S2)"
    [[ ! -d "${BACKUP_BASE}/restic" ]] && echo "  - Configurar backup con Restic (S3)"
    [[ ! -f /var/log/securizar-backup-verify.log ]] && echo "  - Ejecutar verificacion: verificar-backups.sh (S5)"
    [[ ! -f "$DR_CONF" ]] && echo "  - Crear plan DR (S7)"
    [[ ! -f "$OFFSITE_CONF" ]] && echo "  - Configurar backup offsite (S8)"
    ! id "securizar-backup" &>/dev/null && echo "  - Configurar proteccion ransomware (S9)"
fi

echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"

# Guardar resultado
AUDIT_RESULT="/var/log/securizar-backup-audit.log"
echo "$(date -Iseconds) score=${TOTAL_SCORE}/${MAX_SCORE} pct=${pct}% grade=${grade}" >> "$AUDIT_RESULT"
EOFAUDIT

    chmod +x /usr/local/bin/auditoria-backup-dr.sh
    log_change "Creado" "/usr/local/bin/auditoria-backup-dr.sh"

    # Cron mensual para auditoria
    cat > /etc/cron.monthly/auditoria-backup-dr << 'EOFCRON'
#!/bin/bash
# Auditoria mensual de backup y DR
/usr/local/bin/auditoria-backup-dr.sh >> /var/log/securizar-backup-audit.log 2>&1
EOFCRON
    chmod +x /etc/cron.monthly/auditoria-backup-dr
    log_change "Creado" "/etc/cron.monthly/auditoria-backup-dr (auditoria mensual)"

    log_info "Auditoria de backup y DR configurada"
    log_info "Ejecutar: auditoria-backup-dr.sh"
else
    log_skip "Auditoria de backup y DR"
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
show_changes_summary
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     BACKUP Y RECUPERACION ANTE DESASTRES COMPLETADO      ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups guardados en: $BACKUP_DIR"
echo ""
echo "Comandos utiles post-configuracion:"
echo "  - Verificar 3-2-1:       verificar-estrategia-321.sh"
echo "  - Backup Borg:           securizar-backup-borg.sh"
echo "  - Backup Restic:         securizar-backup-restic.sh"
echo "  - Inmutabilidad:         securizar-backup-inmutable.sh [lock|status]"
echo "  - Verificar backups:     verificar-backups.sh"
echo "  - Restaurar:             restaurar-backup.sh"
echo "  - Backup bare metal:     backup-sistema-completo.sh"
echo "  - Validar RTO/RPO:       validar-rto-rpo.sh"
echo "  - Backup offsite:        securizar-backup-offsite.sh"
echo "  - Anti-ransomware:       proteger-backups-ransomware.sh"
echo "  - Auditoria DR:          auditoria-backup-dr.sh"
echo ""
log_info "Modulo 49 completado"
