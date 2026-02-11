#!/bin/bash
# ============================================================
# SEGURIDAD DE CONTENEDORES - Linux Multi-Distro
# Módulo 40: Hardening de Docker, Podman, Kubernetes
# ============================================================
# Secciones:
#   S1  - Hardening del daemon Docker/Podman
#   S2  - Restricciones de runtime (seccomp, AppArmor, capabilities)
#   S3  - Seguridad de imágenes
#   S4  - Aislamiento de red de contenedores
#   S5  - Seguridad de almacenamiento
#   S6  - Seguridad de registro (registry)
#   S7  - Contenedores sin root (rootless)
#   S8  - Monitorización de contenedores
#   S9  - Seguridad Kubernetes básica (si kubectl presente)
#   S10 - Auditoría de seguridad de contenedores
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   SEGURIDAD DE CONTENEDORES - Módulo 40                   ║"
echo "║   Docker, Podman, Kubernetes hardening                     ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Detectar motores de contenedores disponibles
HAS_DOCKER=0
HAS_PODMAN=0
HAS_KUBECTL=0
command -v docker &>/dev/null && HAS_DOCKER=1
command -v podman &>/dev/null && HAS_PODMAN=1
command -v kubectl &>/dev/null && HAS_KUBECTL=1

if [[ $HAS_DOCKER -eq 0 ]] && [[ $HAS_PODMAN -eq 0 ]]; then
    log_warn "No se detectó Docker ni Podman en el sistema."
    log_warn "Las secciones se configurarán igualmente para uso futuro."
fi

[[ $HAS_DOCKER -eq 1 ]] && log_info "Docker detectado: $(docker --version 2>/dev/null || echo 'versión desconocida')"
[[ $HAS_PODMAN -eq 1 ]] && log_info "Podman detectado: $(podman --version 2>/dev/null || echo 'versión desconocida')"
[[ $HAS_KUBECTL -eq 1 ]] && log_info "kubectl detectado: $(kubectl version --client --short 2>/dev/null || echo 'versión desconocida')"

mkdir -p /etc/securizar

# ============================================================
# S1: Hardening del daemon Docker/Podman
# ============================================================
log_section "S1: HARDENING DEL DAEMON DOCKER/PODMAN"

echo "Configura el daemon de contenedores con opciones de seguridad:"
echo "  - Deshabilitar comunicación inter-contenedores (icc)"
echo "  - Activar no-new-privileges y user namespace remapping"
echo "  - Logging seguro vía journald"
echo "  - Driver overlay2 y ulimits restrictivos"
echo ""

if ask "¿Configurar hardening del daemon Docker/Podman?"; then
    # --- Docker ---
    if [[ $HAS_DOCKER -eq 1 ]] || ask "¿Docker no detectado. Crear config igualmente?"; then
        mkdir -p /etc/docker
        DAEMON_JSON="/etc/docker/daemon.json"

        if [[ -f "$DAEMON_JSON" ]]; then
            # Backup antes de modificar
            cp "$DAEMON_JSON" "${DAEMON_JSON}.bak.$(date +%Y%m%d-%H%M%S)"
            log_change "Backup" "${DAEMON_JSON} -> ${DAEMON_JSON}.bak.*"
            log_warn "daemon.json existente respaldado. Se sobreescribirá con config segura."
        fi

        cat > "$DAEMON_JSON" << 'EOFDAEMON'
{
    "icc": false,
    "no-new-privileges": true,
    "userns-remap": "default",
    "live-restore": true,
    "userland-proxy": false,
    "log-driver": "journald",
    "storage-driver": "overlay2",
    "default-ulimits": {
        "nofile": {
            "Name": "nofile",
            "Hard": 65536,
            "Soft": 32768
        }
    }
}
EOFDAEMON

        chmod 644 "$DAEMON_JSON"
        log_change "Creado" "$DAEMON_JSON (hardened)"
        log_info "Docker daemon configurado con seguridad reforzada"

        # Reiniciar Docker si está activo
        if systemctl is-active docker &>/dev/null; then
            log_warn "Docker está activo. Reinicia manualmente: systemctl restart docker"
        fi
    fi

    # --- Podman ---
    if [[ $HAS_PODMAN -eq 1 ]]; then
        mkdir -p /etc/containers
        PODMAN_CONF="/etc/containers/containers.conf"

        if [[ -f "$PODMAN_CONF" ]]; then
            cp "$PODMAN_CONF" "${PODMAN_CONF}.bak.$(date +%Y%m%d-%H%M%S)"
            log_change "Backup" "${PODMAN_CONF} -> ${PODMAN_CONF}.bak.*"
        fi

        cat > "$PODMAN_CONF" << 'EOFPODMAN'
# Configuración de seguridad para Podman
# Generado por seguridad-contenedores.sh

[containers]
# No permitir nuevos privilegios
no_new_privileges = true

# Logging
log_driver = "journald"

# Ulimits por defecto
default_ulimits = [
  "nofile=32768:65536"
]

# Deshabilitar label (si no hay SELinux/AppArmor)
# label = false

[engine]
# Usar cgroup v2
cgroup_manager = "systemd"

# Runtime seguro
runtime = "crun"

[network]
# Driver de red por defecto
network_backend = "netavark"
EOFPODMAN

        chmod 644 "$PODMAN_CONF"
        log_change "Creado" "$PODMAN_CONF (hardened)"
        log_info "Podman configurado con seguridad reforzada"
    fi
else
    log_skip "Hardening del daemon Docker/Podman"
fi

# ============================================================
# S2: Restricciones de runtime (seccomp, AppArmor, capabilities)
# ============================================================
log_section "S2: RESTRICCIONES DE RUNTIME (SECCOMP, APPARMOR, CAPABILITIES)"

echo "Crea perfiles de seguridad para limitar syscalls y accesos:"
echo "  - Perfil seccomp estricto (bloquea syscalls peligrosas)"
echo "  - Perfil AppArmor para contenedores"
echo "  - Wrapper docker run con flags de seguridad"
echo ""

if ask "¿Crear perfiles de restricción de runtime?"; then
    mkdir -p /etc/securizar

    # --- Perfil seccomp estricto ---
    cat > /etc/securizar/docker-seccomp-strict.json << 'EOFSECCOMP'
{
    "defaultAction": "SCMP_ACT_ERRNO",
    "archMap": [
        { "architecture": "SCMP_ARCH_X86_64", "subArchitectures": ["SCMP_ARCH_X86", "SCMP_ARCH_X32"] },
        { "architecture": "SCMP_ARCH_AARCH64", "subArchitectures": ["SCMP_ARCH_ARM"] }
    ],
    "syscalls": [
        {
            "names": [
                "accept", "accept4", "access", "alarm", "bind", "brk",
                "capget", "capset", "chdir", "chmod", "chown", "chown32",
                "clock_getres", "clock_gettime", "clock_nanosleep", "clone",
                "close", "connect", "copy_file_range", "creat", "dup", "dup2",
                "dup3", "epoll_create", "epoll_create1", "epoll_ctl",
                "epoll_pwait", "epoll_wait", "eventfd", "eventfd2",
                "execve", "execveat", "exit", "exit_group", "faccessat",
                "fadvise64", "fallocate", "fanotify_mark", "fchdir",
                "fchmod", "fchmodat", "fchown", "fchown32", "fchownat",
                "fcntl", "fcntl64", "fdatasync", "fgetxattr", "flistxattr",
                "flock", "fork", "fstat", "fstat64", "fstatat64",
                "fstatfs", "fstatfs64", "fsync", "ftruncate", "ftruncate64",
                "futex", "futimesat", "getcpu", "getcwd", "getdents",
                "getdents64", "getegid", "getegid32", "geteuid",
                "geteuid32", "getgid", "getgid32", "getgroups",
                "getgroups32", "getitimer", "getpeername", "getpgid",
                "getpgrp", "getpid", "getppid", "getpriority",
                "getrandom", "getresgid", "getresgid32", "getresuid",
                "getresuid32", "getrlimit", "getrusage", "getsid",
                "getsockname", "getsockopt", "gettid", "gettimeofday",
                "getuid", "getuid32", "getxattr", "inotify_add_watch",
                "inotify_init", "inotify_init1", "inotify_rm_watch",
                "io_cancel", "io_destroy", "io_getevents", "io_setup",
                "io_submit", "ioctl", "kill", "lchown", "lchown32",
                "lgetxattr", "link", "linkat", "listen", "listxattr",
                "llistxattr", "lseek", "lstat", "lstat64", "madvise",
                "memfd_create", "mincore", "mkdir", "mkdirat", "mknod",
                "mknodat", "mlock", "mlock2", "mlockall", "mmap",
                "mmap2", "mount", "mprotect", "mq_getsetattr",
                "mq_notify", "mq_open", "mq_timedreceive",
                "mq_timedsend", "mq_unlink", "mremap", "msgctl",
                "msgget", "msgrcv", "msgsnd", "msync", "munlock",
                "munlockall", "munmap", "nanosleep", "newfstatat",
                "open", "openat", "pause", "pipe", "pipe2", "poll",
                "ppoll", "prctl", "pread64", "preadv", "preadv2",
                "prlimit64", "pselect6", "pwrite64", "pwritev",
                "pwritev2", "read", "readahead", "readlink",
                "readlinkat", "readv", "recvfrom", "recvmmsg",
                "recvmsg", "rename", "renameat", "renameat2",
                "restart_syscall", "rmdir", "rt_sigaction",
                "rt_sigpending", "rt_sigprocmask", "rt_sigqueueinfo",
                "rt_sigreturn", "rt_sigsuspend", "rt_sigtimedwait",
                "rt_tgsigqueueinfo", "sched_getaffinity",
                "sched_getattr", "sched_getparam",
                "sched_get_priority_max", "sched_get_priority_min",
                "sched_getscheduler", "sched_setaffinity",
                "sched_setattr", "sched_setparam",
                "sched_setscheduler", "sched_yield", "seccomp",
                "select", "semctl", "semget", "semop", "semtimedop",
                "sendfile", "sendfile64", "sendmmsg", "sendmsg",
                "sendto", "set_robust_list", "set_thread_area",
                "set_tid_address", "setfsgid", "setfsgid32",
                "setfsuid", "setfsuid32", "setgid", "setgid32",
                "setgroups", "setgroups32", "setitimer", "setpgid",
                "setpriority", "setregid", "setregid32", "setresgid",
                "setresgid32", "setresuid", "setresuid32", "setreuid",
                "setreuid32", "setrlimit", "setsid", "setsockopt",
                "setuid", "setuid32", "shmat", "shmctl", "shmdt",
                "shmget", "shutdown", "sigaltstack", "signalfd",
                "signalfd4", "socket", "socketpair", "splice",
                "stat", "stat64", "statfs", "statfs64", "statx",
                "symlink", "symlinkat", "sync", "sync_file_range",
                "syncfs", "sysinfo", "tee", "tgkill", "time",
                "timer_create", "timer_delete", "timer_getoverrun",
                "timer_gettime", "timer_settime", "timerfd_create",
                "timerfd_gettime", "timerfd_settime", "times",
                "tkill", "truncate", "truncate64", "ugetrlimit",
                "umask", "uname", "unlink", "unlinkat", "utime",
                "utimensat", "utimes", "vfork", "vmsplice", "wait4",
                "waitid", "waitpid", "write", "writev"
            ],
            "action": "SCMP_ACT_ALLOW"
        },
        {
            "names": [
                "keyctl", "ptrace", "kexec_load", "kexec_file_load",
                "reboot", "mount", "umount", "umount2", "swapon",
                "swapoff", "pivot_root", "acct", "init_module",
                "finit_module", "delete_module", "unshare",
                "userfaultfd", "perf_event_open", "bpf",
                "lookup_dcookie", "add_key", "request_key",
                "move_pages", "mbind", "set_mempolicy",
                "get_mempolicy", "syslog", "kcmp",
                "process_vm_readv", "process_vm_writev",
                "create_module", "query_module",
                "get_kernel_syms", "nfsservctl",
                "personality", "vm86", "vm86old",
                "modify_ldt", "ioperm", "iopl",
                "clock_settime", "settimeofday",
                "stime", "adjtimex", "clock_adjtime"
            ],
            "action": "SCMP_ACT_ERRNO",
            "comment": "Syscalls peligrosas bloqueadas explícitamente"
        }
    ]
}
EOFSECCOMP

    chmod 644 /etc/securizar/docker-seccomp-strict.json
    log_change "Creado" "/etc/securizar/docker-seccomp-strict.json"

    # --- Perfil AppArmor ---
    if command -v apparmor_parser &>/dev/null; then
        cat > /etc/apparmor.d/securizar-container-default << 'EOFAPPARMOR'
#include <tunables/global>

profile securizar-container-default flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  network,
  capability,
  file,

  # Denegar acceso a archivos sensibles del host
  deny /etc/shadow r,
  deny /etc/sudoers r,
  deny /etc/ssh/** rwl,
  deny /proc/sys/kernel/** w,
  deny /sys/firmware/** r,
  deny /sys/kernel/security/** r,

  # Denegar montajes
  deny mount,
  deny umount,

  # Denegar ptrace a otros procesos
  deny ptrace (readby, tracedby),

  # Permitir señales dentro del contenedor
  signal (send, receive) peer=securizar-container-default,

  # Denegar escritura en /proc y /sys
  deny /proc/** w,
  deny /sys/** w,

  # Permitir lectura limitada de /proc
  /proc/*/attr/current r,
  /proc/*/maps r,
  /proc/*/status r,
  /proc/*/fd/** rw,
}
EOFAPPARMOR

        chmod 644 /etc/apparmor.d/securizar-container-default
        log_change "Creado" "/etc/apparmor.d/securizar-container-default"

        apparmor_parser -r /etc/apparmor.d/securizar-container-default 2>/dev/null && \
            log_info "Perfil AppArmor cargado en el kernel" || \
            log_warn "No se pudo cargar el perfil AppArmor (cargar manualmente)"
    else
        log_warn "AppArmor no disponible. Perfil AppArmor omitido."
    fi

    # --- Wrapper docker run seguro ---
    cat > /usr/local/bin/securizar-docker-run.sh << 'EOFWRAPPER'
#!/bin/bash
# ============================================================
# Wrapper seguro para docker run
# Añade flags de seguridad automáticamente
# Uso: securizar-docker-run.sh <imagen> [argumentos...]
# ============================================================

if [[ $# -eq 0 ]]; then
    echo "Uso: securizar-docker-run.sh <imagen> [argumentos...]"
    echo ""
    echo "Flags de seguridad aplicados automáticamente:"
    echo "  --cap-drop=ALL            Eliminar todas las capabilities"
    echo "  --security-opt=no-new-privileges  Sin escalada de privilegios"
    echo "  --read-only               Sistema de archivos de solo lectura"
    echo "  --tmpfs /tmp              Tmpfs para /tmp"
    echo "  --pids-limit=256          Límite de procesos"
    echo "  --memory=512m             Límite de memoria"
    echo "  --cpus=1                  Límite de CPU"
    echo ""
    echo "Variables de entorno:"
    echo "  SECURIZAR_CAPS='NET_BIND_SERVICE'  Capabilities adicionales"
    echo "  SECURIZAR_WRITABLE=1               Deshabilitar --read-only"
    echo "  SECURIZAR_SECCOMP=/path/to/profile Perfil seccomp personalizado"
    exit 1
fi

IMAGE="$1"
shift

SECURITY_ARGS=(
    --cap-drop=ALL
    --security-opt=no-new-privileges
    --pids-limit=256
    --memory=512m
    --cpus=1
    --tmpfs /tmp:rw,noexec,nosuid,size=64m
)

# Capabilities adicionales si se especifican
if [[ -n "${SECURIZAR_CAPS:-}" ]]; then
    IFS=',' read -ra CAPS <<< "$SECURIZAR_CAPS"
    for cap in "${CAPS[@]}"; do
        SECURITY_ARGS+=(--cap-add="$cap")
    done
fi

# Read-only por defecto
if [[ "${SECURIZAR_WRITABLE:-0}" != "1" ]]; then
    SECURITY_ARGS+=(--read-only)
fi

# Perfil seccomp
SECCOMP="${SECURIZAR_SECCOMP:-/etc/securizar/docker-seccomp-strict.json}"
if [[ -f "$SECCOMP" ]]; then
    SECURITY_ARGS+=(--security-opt "seccomp=$SECCOMP")
fi

# Perfil AppArmor si existe
if [[ -f /etc/apparmor.d/securizar-container-default ]]; then
    SECURITY_ARGS+=(--security-opt "apparmor=securizar-container-default")
fi

echo "[securizar] Ejecutando con flags de seguridad:"
echo "[securizar]   ${SECURITY_ARGS[*]}"
echo ""

exec docker run "${SECURITY_ARGS[@]}" "$IMAGE" "$@"
EOFWRAPPER

    chmod +x /usr/local/bin/securizar-docker-run.sh
    log_change "Creado" "/usr/local/bin/securizar-docker-run.sh"
    log_change "Permisos" "/usr/local/bin/securizar-docker-run.sh -> +x"
    log_info "Wrapper seguro instalado: securizar-docker-run.sh"
else
    log_skip "Restricciones de runtime"
fi

# ============================================================
# S3: Seguridad de imágenes
# ============================================================
log_section "S3: SEGURIDAD DE IMÁGENES"

echo "Herramientas de análisis y políticas de imágenes:"
echo "  - Escáner de imágenes locales (tags, antigüedad, vulnerabilidades)"
echo "  - Política de registros permitidos"
echo "  - Docker Content Trust (firmas de imágenes)"
echo ""

if ask "¿Configurar seguridad de imágenes?"; then
    # --- Escáner de imágenes ---
    cat > /usr/local/bin/escanear-imagenes.sh << 'EOFSCAN'
#!/bin/bash
# ============================================================
# Escáner de seguridad de imágenes de contenedores
# Analiza tags, antigüedad, tamaño y vulnerabilidades
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  ESCÁNER DE IMÁGENES DE CONTENEDORES${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

# Detectar runtime
RUNTIME=""
if command -v docker &>/dev/null; then
    RUNTIME="docker"
elif command -v podman &>/dev/null; then
    RUNTIME="podman"
else
    echo -e "${RED}[X] No se detectó Docker ni Podman${NC}"
    exit 1
fi

echo -e "Runtime: ${CYAN}${RUNTIME}${NC}"
echo ""

WARN_COUNT=0
TOTAL=0

# Listar imágenes
echo -e "${CYAN}── Análisis de imágenes locales ──${NC}"
echo ""

while IFS= read -r line; do
    [[ "$line" == "REPOSITORY"* ]] && continue
    [[ -z "$line" ]] && continue

    REPO=$(echo "$line" | awk '{print $1}')
    TAG=$(echo "$line" | awk '{print $2}')
    IMAGE_ID=$(echo "$line" | awk '{print $3}')
    CREATED=$(echo "$line" | awk '{print $4, $5, $6}')
    SIZE=$(echo "$line" | awk '{print $NF}')
    ((TOTAL++))

    echo -e "  ${BOLD}${REPO}:${TAG}${NC} (${DIM}${IMAGE_ID}${NC})"

    # Verificar tag :latest
    if [[ "$TAG" == "latest" ]]; then
        echo -e "    ${YELLOW}[!] Usa tag :latest (no recomendado para producción)${NC}"
        ((WARN_COUNT++))
    fi

    # Verificar antigüedad
    if echo "$CREATED" | grep -qiE "month|year"; then
        echo -e "    ${YELLOW}[!] Imagen antigua: ${CREATED}${NC}"
        ((WARN_COUNT++))
    fi

    # Tamaño
    echo -e "    ${DIM}Tamaño: ${SIZE} | Creada: ${CREATED}${NC}"
    echo ""

done < <($RUNTIME images --format "table {{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.CreatedSince}}\t{{.Size}}" 2>/dev/null)

# Trivy
echo ""
echo -e "${CYAN}── Escaneo de vulnerabilidades ──${NC}"
if command -v trivy &>/dev/null; then
    echo -e "  ${GREEN}[+]${NC} Trivy disponible: $(trivy --version 2>/dev/null | head -1)"
    echo ""
    $RUNTIME images --format "{{.Repository}}:{{.Tag}}" 2>/dev/null | \
        grep -v "<none>" | while read -r img; do
        echo -e "  Escaneando ${BOLD}${img}${NC}..."
        trivy image --severity HIGH,CRITICAL --quiet "$img" 2>/dev/null || \
            echo -e "    ${YELLOW}No se pudo escanear${NC}"
        echo ""
    done
else
    echo -e "  ${YELLOW}[!] Trivy no instalado${NC}"
    echo "  Instalar: https://aquasecurity.github.io/trivy/"
    echo "    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin"
fi

echo ""
echo -e "${BOLD}Resumen: ${TOTAL} imágenes analizadas, ${WARN_COUNT} advertencias${NC}"
EOFSCAN

    chmod +x /usr/local/bin/escanear-imagenes.sh
    log_change "Creado" "/usr/local/bin/escanear-imagenes.sh"
    log_change "Permisos" "/usr/local/bin/escanear-imagenes.sh -> +x"

    # --- Política de registros ---
    cat > /etc/securizar/docker-image-policy.conf << 'EOFPOLICY'
# Política de imágenes de contenedores
# Generado por seguridad-contenedores.sh
#
# Registros permitidos (uno por línea)
# Imágenes solo deben descargarse de estos registros
docker.io
ghcr.io
registry.access.redhat.com
registry.opensuse.org
gcr.io
quay.io

# Reglas:
# - No usar tag :latest en producción
# - Preferir imágenes oficiales y verificadas
# - Escanear con trivy antes de desplegar
# - Actualizar imágenes base al menos mensualmente
EOFPOLICY

    chmod 644 /etc/securizar/docker-image-policy.conf
    log_change "Creado" "/etc/securizar/docker-image-policy.conf"

    # --- Docker Content Trust ---
    if ! grep -q "DOCKER_CONTENT_TRUST" /etc/environment 2>/dev/null; then
        echo "DOCKER_CONTENT_TRUST=1" >> /etc/environment
        log_change "Configurado" "DOCKER_CONTENT_TRUST=1 en /etc/environment"
        log_info "Docker Content Trust habilitado globalmente"
    else
        log_info "Docker Content Trust ya configurado en /etc/environment"
    fi
else
    log_skip "Seguridad de imágenes"
fi

# ============================================================
# S4: Aislamiento de red de contenedores
# ============================================================
log_section "S4: AISLAMIENTO DE RED DE CONTENEDORES"

echo "Configura restricciones de red para contenedores:"
echo "  - Red interna personalizada"
echo "  - Reglas iptables para egress"
echo "  - Script de auditoría de redes"
echo ""

if ask "¿Configurar aislamiento de red de contenedores?"; then
    # --- Red interna ---
    if [[ $HAS_DOCKER -eq 1 ]]; then
        if ! docker network ls 2>/dev/null | grep -q "securizar-internal"; then
            docker network create \
                --internal \
                --driver bridge \
                --subnet=172.20.0.0/24 \
                --opt com.docker.network.bridge.enable_icc=false \
                securizar-internal 2>/dev/null && \
                log_change "Creado" "Red Docker 'securizar-internal' (interna, sin ICC)" || \
                log_warn "No se pudo crear red interna (Docker no activo?)"
        else
            log_info "Red 'securizar-internal' ya existe"
        fi
    fi

    # --- Script de auditoría de redes ---
    cat > /usr/local/bin/auditar-red-contenedores.sh << 'EOFNETAUDIT'
#!/bin/bash
# ============================================================
# Auditoría de red de contenedores
# Muestra redes, conexiones, puertos y riesgos
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  AUDITORÍA DE RED DE CONTENEDORES${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

RUNTIME=""
if command -v docker &>/dev/null; then
    RUNTIME="docker"
elif command -v podman &>/dev/null; then
    RUNTIME="podman"
else
    echo -e "${RED}[X] No se detectó Docker ni Podman${NC}"
    exit 1
fi

WARN_COUNT=0

# 1. Redes y contenedores conectados
echo -e "${CYAN}── Redes de contenedores ──${NC}"
$RUNTIME network ls 2>/dev/null | while IFS= read -r line; do
    echo "  $line"
done
echo ""

# 2. Contenedores con red host (peligroso)
echo -e "${CYAN}── Contenedores con red host (peligroso) ──${NC}"
HOST_NET=$($RUNTIME ps --format "{{.Names}} {{.ID}}" 2>/dev/null | while read -r name cid; do
    NET=$($RUNTIME inspect --format '{{.HostConfig.NetworkMode}}' "$cid" 2>/dev/null)
    if [[ "$NET" == "host" ]]; then
        echo "$name"
    fi
done)
if [[ -n "$HOST_NET" ]]; then
    echo "$HOST_NET" | while read -r c; do
        echo -e "  ${RED}[!] $c usa NetworkMode=host${NC}"
        ((WARN_COUNT++))
    done
else
    echo -e "  ${GREEN}[OK]${NC} Ningún contenedor usa red host"
fi
echo ""

# 3. Puertos expuestos a 0.0.0.0
echo -e "${CYAN}── Puertos expuestos a 0.0.0.0 (todas las interfaces) ──${NC}"
$RUNTIME ps --format "{{.Names}}\t{{.Ports}}" 2>/dev/null | while IFS=$'\t' read -r name ports; do
    if echo "$ports" | grep -q "0.0.0.0:"; then
        echo -e "  ${YELLOW}[!] ${name}: ${ports}${NC}"
    fi
done
echo ""

# 4. Mapeo de puertos completo
echo -e "${CYAN}── Mapeo de puertos ──${NC}"
$RUNTIME ps --format "table {{.Names}}\t{{.Ports}}" 2>/dev/null | while IFS= read -r line; do
    echo "  $line"
done

echo ""
echo -e "${BOLD}Auditoría completada: $(date)${NC}"
EOFNETAUDIT

    chmod +x /usr/local/bin/auditar-red-contenedores.sh
    log_change "Creado" "/usr/local/bin/auditar-red-contenedores.sh"
    log_change "Permisos" "/usr/local/bin/auditar-red-contenedores.sh -> +x"
    log_info "Script de auditoría de red instalado"
else
    log_skip "Aislamiento de red de contenedores"
fi

# ============================================================
# S5: Seguridad de almacenamiento
# ============================================================
log_section "S5: SEGURIDAD DE ALMACENAMIENTO"

echo "Audita y restringe montajes de volúmenes peligrosos:"
echo "  - Detectar bind mounts a /etc, /proc, /sys, docker.sock"
echo "  - Política de montajes prohibidos"
echo "  - Propagación de montaje restrictiva"
echo ""

if ask "¿Configurar seguridad de almacenamiento?"; then
    # --- Auditar montajes peligrosos actuales ---
    if [[ $HAS_DOCKER -eq 1 ]] && systemctl is-active docker &>/dev/null; then
        log_info "Auditando montajes de contenedores activos..."
        DANGEROUS_MOUNTS=("/etc" "/var/run/docker.sock" "/proc" "/sys" "/root" "/boot")

        docker ps -q 2>/dev/null | while read -r cid; do
            CNAME=$(docker inspect --format '{{.Name}}' "$cid" 2>/dev/null | sed 's|^/||')
            MOUNTS=$(docker inspect --format '{{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}' "$cid" 2>/dev/null)
            for dangerous in "${DANGEROUS_MOUNTS[@]}"; do
                if echo "$MOUNTS" | grep -q "$dangerous"; then
                    log_warn "Contenedor '$CNAME' monta ruta peligrosa: $dangerous"
                fi
            done
        done
    fi

    # --- Política de montajes ---
    cat > /etc/securizar/docker-mount-policy.conf << 'EOFMOUNT'
# Política de montajes de contenedores
# Generado por seguridad-contenedores.sh
#
# Rutas PROHIBIDAS para bind mount en contenedores:
/etc/shadow
/etc/passwd
/etc/sudoers
/etc/ssh
/var/run/docker.sock
/proc/sysrq-trigger
/proc/kcore
/sys/firmware
/sys/kernel
/root
/boot
/dev/mem
/dev/kmem

# Recomendaciones:
# - Usar volúmenes nombrados en lugar de bind mounts
# - Montar con :ro cuando sea posible
# - Nunca montar el socket de Docker dentro de un contenedor
# - Usar --mount type=tmpfs para datos temporales
# - Propagación de montaje: rprivate (por defecto seguro)
EOFMOUNT

    chmod 644 /etc/securizar/docker-mount-policy.conf
    log_change "Creado" "/etc/securizar/docker-mount-policy.conf"
    log_info "Política de montajes instalada"

    # --- Propagación de montaje restrictiva ---
    if [[ $HAS_DOCKER -eq 1 ]] && [[ -f /etc/docker/daemon.json ]]; then
        log_info "Propagación de montaje por defecto: rprivate (segura por defecto en Docker)"
    fi
else
    log_skip "Seguridad de almacenamiento"
fi

# ============================================================
# S6: Seguridad de registro (registry)
# ============================================================
log_section "S6: SEGURIDAD DE REGISTRO (REGISTRY)"

echo "Audita y asegura la configuración de registros:"
echo "  - Verificar registros inseguros"
echo "  - Estructura de certificados para registros privados"
echo "  - Script de auditoría de registros"
echo ""

if ask "¿Configurar seguridad de registros?"; then
    # --- Estructura de certificados ---
    mkdir -p /etc/docker/certs.d
    log_change "Creado" "/etc/docker/certs.d/ (estructura para certificados)"

    # --- Verificar registros inseguros ---
    if [[ -f /etc/docker/daemon.json ]]; then
        if grep -q "insecure-registries" /etc/docker/daemon.json 2>/dev/null; then
            log_warn "Se detectaron registros inseguros en /etc/docker/daemon.json"
            log_warn "Elimina 'insecure-registries' para forzar TLS"
        else
            log_info "No hay registros inseguros en daemon.json"
        fi
    fi

    if [[ -f /etc/containers/registries.conf ]]; then
        if grep -qiE "insecure.*=.*true|^location.*http://" /etc/containers/registries.conf 2>/dev/null; then
            log_warn "Se detectaron registros inseguros en /etc/containers/registries.conf"
        else
            log_info "No hay registros inseguros en registries.conf"
        fi
    fi

    # --- Script auditoría de registros ---
    cat > /usr/local/bin/auditar-registros.sh << 'EOFREG'
#!/bin/bash
# ============================================================
# Auditoría de registros de contenedores
# Verifica TLS, certificados y registros inseguros
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  AUDITORÍA DE REGISTROS DE CONTENEDORES${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

# 1. Docker daemon.json
echo -e "${CYAN}── Configuración Docker ──${NC}"
if [[ -f /etc/docker/daemon.json ]]; then
    if grep -q "insecure-registries" /etc/docker/daemon.json; then
        echo -e "  ${RED}[!] Registros inseguros detectados:${NC}"
        grep "insecure-registries" /etc/docker/daemon.json
    else
        echo -e "  ${GREEN}[OK]${NC} Sin registros inseguros en daemon.json"
    fi
else
    echo -e "  ${YELLOW}[--]${NC} /etc/docker/daemon.json no existe"
fi
echo ""

# 2. Podman registries.conf
echo -e "${CYAN}── Configuración Podman ──${NC}"
if [[ -f /etc/containers/registries.conf ]]; then
    INSECURE=$(grep -ciE "insecure.*=.*true" /etc/containers/registries.conf 2>/dev/null || echo 0)
    if [[ "$INSECURE" -gt 0 ]]; then
        echo -e "  ${RED}[!] $INSECURE registros inseguros en registries.conf${NC}"
    else
        echo -e "  ${GREEN}[OK]${NC} Sin registros inseguros en registries.conf"
    fi
else
    echo -e "  ${YELLOW}[--]${NC} /etc/containers/registries.conf no existe"
fi
echo ""

# 3. Certificados de registros
echo -e "${CYAN}── Certificados de registros ──${NC}"
if [[ -d /etc/docker/certs.d ]]; then
    CERT_DIRS=$(find /etc/docker/certs.d -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
    if [[ "$CERT_DIRS" -gt 0 ]]; then
        echo -e "  ${GREEN}[OK]${NC} $CERT_DIRS registros con certificados configurados:"
        find /etc/docker/certs.d -mindepth 1 -maxdepth 1 -type d 2>/dev/null | while read -r d; do
            echo "    $(basename "$d")"
        done
    else
        echo -e "  ${YELLOW}[--]${NC} Sin certificados de registros configurados"
    fi
else
    echo -e "  ${YELLOW}[--]${NC} /etc/docker/certs.d no existe"
fi
echo ""

# 4. Docker Content Trust
echo -e "${CYAN}── Docker Content Trust ──${NC}"
if grep -q "DOCKER_CONTENT_TRUST=1" /etc/environment 2>/dev/null; then
    echo -e "  ${GREEN}[OK]${NC} DOCKER_CONTENT_TRUST habilitado"
else
    echo -e "  ${YELLOW}[!] DOCKER_CONTENT_TRUST no habilitado${NC}"
fi

echo ""
echo -e "${BOLD}Auditoría completada: $(date)${NC}"
EOFREG

    chmod +x /usr/local/bin/auditar-registros.sh
    log_change "Creado" "/usr/local/bin/auditar-registros.sh"
    log_change "Permisos" "/usr/local/bin/auditar-registros.sh -> +x"
    log_info "Script de auditoría de registros instalado"
else
    log_skip "Seguridad de registros"
fi

# ============================================================
# S7: Contenedores sin root (rootless)
# ============================================================
log_section "S7: CONTENEDORES SIN ROOT (ROOTLESS)"

echo "Configura el entorno para contenedores sin privilegios:"
echo "  - subuid/subgid para user namespaces"
echo "  - User namespace remapping en Docker"
echo "  - loginctl enable-linger para usuarios de contenedores"
echo "  - Guía de migración a rootless"
echo ""

if ask "¿Configurar contenedores rootless?"; then
    REAL_USER="${SUDO_USER:-$USER}"

    # --- subuid/subgid ---
    if [[ -f /etc/subuid ]]; then
        if ! grep -q "^${REAL_USER}:" /etc/subuid 2>/dev/null; then
            echo "${REAL_USER}:100000:65536" >> /etc/subuid
            log_change "Configurado" "/etc/subuid para $REAL_USER"
        else
            log_info "$REAL_USER ya tiene entrada en /etc/subuid"
        fi
    else
        echo "${REAL_USER}:100000:65536" > /etc/subuid
        log_change "Creado" "/etc/subuid para $REAL_USER"
    fi

    if [[ -f /etc/subgid ]]; then
        if ! grep -q "^${REAL_USER}:" /etc/subgid 2>/dev/null; then
            echo "${REAL_USER}:100000:65536" >> /etc/subgid
            log_change "Configurado" "/etc/subgid para $REAL_USER"
        else
            log_info "$REAL_USER ya tiene entrada en /etc/subgid"
        fi
    else
        echo "${REAL_USER}:100000:65536" > /etc/subgid
        log_change "Creado" "/etc/subgid para $REAL_USER"
    fi

    # --- Entrada dockremap para Docker userns-remap ---
    if ! grep -q "^dockremap:" /etc/subuid 2>/dev/null; then
        echo "dockremap:100000:65536" >> /etc/subuid
        echo "dockremap:100000:65536" >> /etc/subgid
        log_change "Configurado" "dockremap en subuid/subgid (userns-remap)"
    fi

    # --- loginctl enable-linger ---
    if command -v loginctl &>/dev/null; then
        loginctl enable-linger "$REAL_USER" 2>/dev/null && \
            log_change "Aplicado" "loginctl enable-linger $REAL_USER" || \
            log_warn "No se pudo habilitar linger para $REAL_USER"
    fi

    # --- Script de migración ---
    cat > /usr/local/bin/migrar-rootless.sh << 'EOFMIGRATE'
#!/bin/bash
# ============================================================
# Guía de migración a contenedores rootless
# Ejecutar como usuario normal (NO root)
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  MIGRACIÓN A CONTENEDORES ROOTLESS${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

if [[ $EUID -eq 0 ]]; then
    echo -e "${RED}[X] NO ejecutar como root. Usar usuario normal.${NC}"
    exit 1
fi

USER_NAME=$(whoami)
echo -e "Usuario: ${CYAN}${USER_NAME}${NC}"
echo ""

# 1. Verificar requisitos
echo -e "${CYAN}── 1. Verificación de requisitos ──${NC}"

# subuid/subgid
if grep -q "^${USER_NAME}:" /etc/subuid 2>/dev/null; then
    echo -e "  ${GREEN}[OK]${NC} subuid configurado"
else
    echo -e "  ${RED}[X]${NC} Falta entrada en /etc/subuid"
    echo "       Ejecutar como root: echo '${USER_NAME}:100000:65536' >> /etc/subuid"
fi

if grep -q "^${USER_NAME}:" /etc/subgid 2>/dev/null; then
    echo -e "  ${GREEN}[OK]${NC} subgid configurado"
else
    echo -e "  ${RED}[X]${NC} Falta entrada en /etc/subgid"
fi

# Kernel namespaces
if [[ -f /proc/sys/kernel/unprivileged_userns_clone ]]; then
    USERNS=$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null)
    if [[ "$USERNS" == "1" ]]; then
        echo -e "  ${GREEN}[OK]${NC} User namespaces sin privilegios habilitados"
    else
        echo -e "  ${RED}[X]${NC} User namespaces deshabilitados"
        echo "       Ejecutar como root: sysctl -w kernel.unprivileged_userns_clone=1"
    fi
else
    echo -e "  ${GREEN}[OK]${NC} User namespaces soportados por el kernel"
fi

echo ""

# 2. Docker rootless
echo -e "${CYAN}── 2. Docker rootless ──${NC}"
if command -v dockerd-rootless-setuptool.sh &>/dev/null; then
    echo -e "  ${GREEN}[OK]${NC} dockerd-rootless-setuptool.sh disponible"
    echo "  Para instalar Docker rootless:"
    echo "    dockerd-rootless-setuptool.sh install"
else
    echo -e "  ${YELLOW}[!]${NC} dockerd-rootless no disponible"
    echo "  Instalar: https://docs.docker.com/engine/security/rootless/"
fi
echo ""

# 3. Podman rootless
echo -e "${CYAN}── 3. Podman rootless ──${NC}"
if command -v podman &>/dev/null; then
    echo -e "  ${GREEN}[OK]${NC} Podman instalado (rootless por defecto)"
    echo "  Verificar: podman info --format '{{.Host.Security.Rootless}}'"
    ROOTLESS=$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null || echo "desconocido")
    echo -e "  Estado rootless: ${BOLD}${ROOTLESS}${NC}"
else
    echo -e "  ${YELLOW}[!]${NC} Podman no instalado"
fi
echo ""

# 4. Linger
echo -e "${CYAN}── 4. Linger (persistencia de servicios) ──${NC}"
if loginctl show-user "$USER_NAME" 2>/dev/null | grep -q "Linger=yes"; then
    echo -e "  ${GREEN}[OK]${NC} Linger habilitado para $USER_NAME"
else
    echo -e "  ${YELLOW}[!]${NC} Linger no habilitado"
    echo "  Ejecutar como root: loginctl enable-linger $USER_NAME"
fi

echo ""
echo -e "${BOLD}Migración completada: $(date)${NC}"
EOFMIGRATE

    chmod +x /usr/local/bin/migrar-rootless.sh
    log_change "Creado" "/usr/local/bin/migrar-rootless.sh"
    log_change "Permisos" "/usr/local/bin/migrar-rootless.sh -> +x"
    log_info "Script de migración rootless instalado"
else
    log_skip "Contenedores rootless"
fi

# ============================================================
# S8: Monitorización de contenedores
# ============================================================
log_section "S8: MONITORIZACIÓN DE CONTENEDORES"

echo "Script de monitorización que detecta:"
echo "  - Uso de recursos (CPU, memoria, PIDs)"
echo "  - Contenedores ejecutando como root"
echo "  - Contenedores sin límites de recursos"
echo "  - Contenedores obsoletos (>30 días)"
echo "  - Timer systemd para verificación periódica"
echo ""

if ask "¿Instalar monitorización de contenedores?"; then
    cat > /usr/local/bin/monitorizar-contenedores.sh << 'EOFMON'
#!/bin/bash
# ============================================================
# Monitorización de seguridad de contenedores
# Detecta riesgos en contenedores activos
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[X] Ejecutar como root${NC}"
    exit 1
fi

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  MONITORIZACIÓN DE CONTENEDORES${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

RUNTIME=""
if command -v docker &>/dev/null; then
    RUNTIME="docker"
elif command -v podman &>/dev/null; then
    RUNTIME="podman"
else
    echo -e "${RED}[X] No se detectó Docker ni Podman${NC}"
    exit 1
fi

WARN=0
TOTAL=0

# 1. Uso de recursos
echo -e "${CYAN}── Uso de recursos ──${NC}"
$RUNTIME stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.PIDs}}" 2>/dev/null || \
    echo -e "  ${YELLOW}Sin contenedores activos${NC}"
echo ""

# 2. Verificación de seguridad por contenedor
echo -e "${CYAN}── Análisis de seguridad ──${NC}"
echo ""

$RUNTIME ps -q 2>/dev/null | while read -r cid; do
    [[ -z "$cid" ]] && continue
    ((TOTAL++))

    CNAME=$($RUNTIME inspect --format '{{.Name}}' "$cid" 2>/dev/null | sed 's|^/||')
    echo -e "  ${BOLD}${CNAME}${NC} (${DIM}${cid:0:12}${NC})"

    # Verificar si corre como root
    USER=$($RUNTIME inspect --format '{{.Config.User}}' "$cid" 2>/dev/null)
    if [[ -z "$USER" ]] || [[ "$USER" == "root" ]] || [[ "$USER" == "0" ]]; then
        echo -e "    ${RED}[!] Ejecuta como root${NC}"
        ((WARN++))
    else
        echo -e "    ${GREEN}[OK]${NC} Usuario: $USER"
    fi

    # Verificar límites de recursos
    MEM_LIMIT=$($RUNTIME inspect --format '{{.HostConfig.Memory}}' "$cid" 2>/dev/null)
    if [[ "$MEM_LIMIT" == "0" ]] || [[ -z "$MEM_LIMIT" ]]; then
        echo -e "    ${YELLOW}[!] Sin límite de memoria${NC}"
        ((WARN++))
    fi

    CPU_LIMIT=$($RUNTIME inspect --format '{{.HostConfig.NanoCpus}}' "$cid" 2>/dev/null)
    if [[ "$CPU_LIMIT" == "0" ]] || [[ -z "$CPU_LIMIT" ]]; then
        echo -e "    ${YELLOW}[!] Sin límite de CPU${NC}"
    fi

    PID_LIMIT=$($RUNTIME inspect --format '{{.HostConfig.PidsLimit}}' "$cid" 2>/dev/null)
    if [[ "$PID_LIMIT" == "0" ]] || [[ "$PID_LIMIT" == "-1" ]] || [[ -z "$PID_LIMIT" ]]; then
        echo -e "    ${YELLOW}[!] Sin límite de PIDs${NC}"
    fi

    # Verificar healthcheck
    HC=$($RUNTIME inspect --format '{{.State.Health.Status}}' "$cid" 2>/dev/null)
    if [[ -n "$HC" ]] && [[ "$HC" != "<no value>" ]]; then
        if [[ "$HC" == "healthy" ]]; then
            echo -e "    ${GREEN}[OK]${NC} Health: $HC"
        else
            echo -e "    ${YELLOW}[!] Health: $HC${NC}"
        fi
    else
        echo -e "    ${DIM}-- Sin HEALTHCHECK definido${NC}"
    fi

    # Verificar antigüedad
    STARTED=$($RUNTIME inspect --format '{{.State.StartedAt}}' "$cid" 2>/dev/null)
    if [[ -n "$STARTED" ]]; then
        START_EPOCH=$(date -d "$STARTED" +%s 2>/dev/null || echo 0)
        NOW_EPOCH=$(date +%s)
        DAYS_RUNNING=$(( (NOW_EPOCH - START_EPOCH) / 86400 ))
        if [[ $DAYS_RUNNING -gt 30 ]]; then
            echo -e "    ${YELLOW}[!] Ejecutando desde hace ${DAYS_RUNNING} días (>30)${NC}"
        fi
    fi

    # Privilegiado
    PRIV=$($RUNTIME inspect --format '{{.HostConfig.Privileged}}' "$cid" 2>/dev/null)
    if [[ "$PRIV" == "true" ]]; then
        echo -e "    ${RED}[!!] CONTENEDOR PRIVILEGIADO${NC}"
        ((WARN++))
    fi

    echo ""
done

echo -e "${BOLD}Monitorización completada: $(date)${NC}"
echo -e "Advertencias: ${WARN}"
EOFMON

    chmod +x /usr/local/bin/monitorizar-contenedores.sh
    log_change "Creado" "/usr/local/bin/monitorizar-contenedores.sh"
    log_change "Permisos" "/usr/local/bin/monitorizar-contenedores.sh -> +x"

    # --- Timer systemd ---
    cat > /etc/systemd/system/monitorizar-contenedores.service << 'EOFSVC'
[Unit]
Description=Monitorización de seguridad de contenedores
After=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/monitorizar-contenedores.sh
StandardOutput=journal
StandardError=journal
EOFSVC

    cat > /etc/systemd/system/monitorizar-contenedores.timer << 'EOFTMR'
[Unit]
Description=Monitorización periódica de contenedores

[Timer]
OnCalendar=*-*-* *:00:00
Persistent=true
RandomizedDelaySec=120

[Install]
WantedBy=timers.target
EOFTMR

    log_change "Creado" "/etc/systemd/system/monitorizar-contenedores.service"
    log_change "Creado" "/etc/systemd/system/monitorizar-contenedores.timer"

    systemctl daemon-reload 2>/dev/null
    systemctl enable monitorizar-contenedores.timer 2>/dev/null && \
        log_change "Servicio" "monitorizar-contenedores.timer enable" || \
        log_warn "No se pudo habilitar el timer"
    systemctl start monitorizar-contenedores.timer 2>/dev/null || true
    log_info "Timer de monitorización de contenedores activado (cada hora)"
else
    log_skip "Monitorización de contenedores"
fi

# ============================================================
# S9: Seguridad Kubernetes básica (si kubectl presente)
# ============================================================
log_section "S9: SEGURIDAD KUBERNETES BÁSICA"

if [[ $HAS_KUBECTL -eq 0 ]]; then
    log_info "kubectl no detectado. Sección N/A."
    log_skip "Seguridad Kubernetes (kubectl no disponible)"
else
    echo "Auditoría de seguridad de Kubernetes:"
    echo "  - Pod Security Standards"
    echo "  - RBAC: ClusterRoleBindings a cluster-admin"
    echo "  - Pods como root, privilegiados, hostNetwork"
    echo "  - Uso de ServiceAccount por defecto"
    echo ""

    if ask "¿Crear script de auditoría de Kubernetes?"; then
        cat > /usr/local/bin/auditar-kubernetes.sh << 'EOFK8S'
#!/bin/bash
# ============================================================
# Auditoría de seguridad de Kubernetes
# Verifica configuraciones de riesgo en el cluster
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

if ! command -v kubectl &>/dev/null; then
    echo -e "${RED}[X] kubectl no disponible${NC}"
    exit 1
fi

if ! kubectl cluster-info &>/dev/null 2>&1; then
    echo -e "${RED}[X] No se pudo conectar al cluster de Kubernetes${NC}"
    exit 1
fi

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  AUDITORÍA DE SEGURIDAD KUBERNETES${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

WARN=0

# 1. ClusterRoleBindings a cluster-admin
echo -e "${CYAN}── ClusterRoleBindings a cluster-admin ──${NC}"
CRB=$(kubectl get clusterrolebindings -o json 2>/dev/null | \
    python3 -c "
import sys,json
data=json.load(sys.stdin)
for item in data.get('items',[]):
    ref=item.get('roleRef',{})
    if ref.get('name')=='cluster-admin':
        subjects=item.get('subjects',[])
        for s in subjects:
            print(f\"  {item['metadata']['name']}: {s.get('kind','?')}/{s.get('name','?')} ({s.get('namespace','cluster-wide')})\")
" 2>/dev/null || kubectl get clusterrolebindings -o wide 2>/dev/null | grep cluster-admin)

if [[ -n "$CRB" ]]; then
    echo -e "${YELLOW}$CRB${NC}"
    ((WARN++))
else
    echo -e "  ${GREEN}[OK]${NC} Sin bindings extra a cluster-admin"
fi
echo ""

# 2. Pods privilegiados
echo -e "${CYAN}── Pods privilegiados ──${NC}"
PRIV_PODS=$(kubectl get pods --all-namespaces -o json 2>/dev/null | \
    python3 -c "
import sys,json
data=json.load(sys.stdin)
for item in data.get('items',[]):
    ns=item['metadata']['namespace']
    name=item['metadata']['name']
    for c in item.get('spec',{}).get('containers',[]):
        sc=c.get('securityContext',{})
        if sc.get('privileged'):
            print(f'  {ns}/{name} ({c[\"name\"]})')
" 2>/dev/null)

if [[ -n "$PRIV_PODS" ]]; then
    echo -e "${RED}[!] Pods privilegiados:${NC}"
    echo "$PRIV_PODS"
    ((WARN++))
else
    echo -e "  ${GREEN}[OK]${NC} Sin pods privilegiados"
fi
echo ""

# 3. Pods como root
echo -e "${CYAN}── Pods ejecutando como root ──${NC}"
ROOT_PODS=$(kubectl get pods --all-namespaces -o json 2>/dev/null | \
    python3 -c "
import sys,json
data=json.load(sys.stdin)
for item in data.get('items',[]):
    ns=item['metadata']['namespace']
    name=item['metadata']['name']
    for c in item.get('spec',{}).get('containers',[]):
        sc=c.get('securityContext',{})
        if sc.get('runAsUser')==0 or (sc.get('runAsNonRoot') is False):
            print(f'  {ns}/{name} ({c[\"name\"]})')
" 2>/dev/null)

if [[ -n "$ROOT_PODS" ]]; then
    echo -e "${YELLOW}[!] Pods como root:${NC}"
    echo "$ROOT_PODS"
    ((WARN++))
else
    echo -e "  ${GREEN}[OK]${NC} Sin pods explícitamente como root"
fi
echo ""

# 4. Pods con hostNetwork
echo -e "${CYAN}── Pods con hostNetwork ──${NC}"
HOST_PODS=$(kubectl get pods --all-namespaces -o json 2>/dev/null | \
    python3 -c "
import sys,json
data=json.load(sys.stdin)
for item in data.get('items',[]):
    if item.get('spec',{}).get('hostNetwork'):
        print(f\"  {item['metadata']['namespace']}/{item['metadata']['name']}\")
" 2>/dev/null)

if [[ -n "$HOST_PODS" ]]; then
    echo -e "${YELLOW}[!] Pods con hostNetwork:${NC}"
    echo "$HOST_PODS"
    ((WARN++))
else
    echo -e "  ${GREEN}[OK]${NC} Sin pods con hostNetwork"
fi
echo ""

# 5. ServiceAccount por defecto
echo -e "${CYAN}── Pods con ServiceAccount por defecto ──${NC}"
DEFAULT_SA=$(kubectl get pods --all-namespaces -o json 2>/dev/null | \
    python3 -c "
import sys,json
data=json.load(sys.stdin)
for item in data.get('items',[]):
    sa=item.get('spec',{}).get('serviceAccountName','default')
    if sa=='default':
        ns=item['metadata']['namespace']
        if ns not in ('kube-system','kube-public','kube-node-lease'):
            print(f\"  {ns}/{item['metadata']['name']}\")
" 2>/dev/null)

if [[ -n "$DEFAULT_SA" ]]; then
    echo -e "${YELLOW}[!] Pods con ServiceAccount 'default':${NC}"
    echo "$DEFAULT_SA"
    ((WARN++))
else
    echo -e "  ${GREEN}[OK]${NC} Todos los pods usan ServiceAccount dedicado"
fi
echo ""

# 6. Pod Security Standards
echo -e "${CYAN}── Pod Security Standards ──${NC}"
kubectl get namespaces --show-labels 2>/dev/null | \
    grep -E "pod-security" || \
    echo -e "  ${YELLOW}[!] No se detectaron labels de Pod Security Standards${NC}"
echo ""

echo -e "${BOLD}Auditoría completada: $(date)${NC}"
echo -e "Advertencias: ${WARN}"
EOFK8S

        chmod +x /usr/local/bin/auditar-kubernetes.sh
        log_change "Creado" "/usr/local/bin/auditar-kubernetes.sh"
        log_change "Permisos" "/usr/local/bin/auditar-kubernetes.sh -> +x"
        log_info "Script de auditoría Kubernetes instalado"
    else
        log_skip "Auditoría Kubernetes"
    fi
fi

# ============================================================
# S10: Auditoría de seguridad de contenedores
# ============================================================
log_section "S10: AUDITORÍA DE SEGURIDAD DE CONTENEDORES"

echo "Script de auditoría integral basado en CIS Docker Benchmark:"
echo "  - Daemon, runtime, imágenes, red, volúmenes, registros"
echo "  - Puntuación: SEGURO / MEJORABLE / INSEGURO"
echo "  - Cron semanal automático"
echo ""

if ask "¿Crear auditoría integral de contenedores?"; then
    cat > /usr/local/bin/auditoria-contenedores.sh << 'EOFAUDIT'
#!/bin/bash
# ============================================================
# Auditoría integral de seguridad de contenedores
# Basado en CIS Docker Benchmark
# Puntuación: SEGURO / MEJORABLE / INSEGURO
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

REPORT_DIR="/var/lib/securizar/auditorias"
mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/contenedores-$(date +%Y%m%d-%H%M%S).txt"

PASS=0
FAIL=0
WARN=0
INFO=0

check_pass() { echo -e "  ${GREEN}[OK]${NC}   $1"; echo "  [OK]   $1" >> "$REPORT"; ((PASS++)); }
check_fail() { echo -e "  ${RED}[FAIL]${NC} $1"; echo "  [FAIL] $1" >> "$REPORT"; ((FAIL++)); }
check_warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; echo "  [WARN] $1" >> "$REPORT"; ((WARN++)); }
check_info() { echo -e "  ${DIM}[INFO]${NC} $1"; echo "  [INFO] $1" >> "$REPORT"; ((INFO++)); }

echo -e "${BOLD}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║   AUDITORÍA DE SEGURIDAD DE CONTENEDORES                  ║${NC}"
echo -e "${BOLD}║   Basado en CIS Docker Benchmark                          ║${NC}"
echo -e "${BOLD}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Fecha: $(date -Iseconds)" | tee "$REPORT"
echo "Host: $(hostname)" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

RUNTIME=""
if command -v docker &>/dev/null; then
    RUNTIME="docker"
elif command -v podman &>/dev/null; then
    RUNTIME="podman"
else
    echo "No se detectó Docker ni Podman" | tee -a "$REPORT"
    echo "Reporte: $REPORT"
    exit 0
fi

# ── 1. CONFIGURACIÓN DEL DAEMON ──
echo "=== 1. CONFIGURACIÓN DEL DAEMON ===" | tee -a "$REPORT"

if [[ -f /etc/docker/daemon.json ]]; then
    check_pass "daemon.json existe"

    # ICC
    if grep -q '"icc".*false' /etc/docker/daemon.json 2>/dev/null; then
        check_pass "ICC deshabilitado"
    else
        check_fail "ICC no deshabilitado (icc: false)"
    fi

    # no-new-privileges
    if grep -q '"no-new-privileges".*true' /etc/docker/daemon.json 2>/dev/null; then
        check_pass "no-new-privileges habilitado"
    else
        check_fail "no-new-privileges no habilitado"
    fi

    # userns-remap
    if grep -q '"userns-remap"' /etc/docker/daemon.json 2>/dev/null; then
        check_pass "User namespace remapping configurado"
    else
        check_warn "User namespace remapping no configurado"
    fi

    # live-restore
    if grep -q '"live-restore".*true' /etc/docker/daemon.json 2>/dev/null; then
        check_pass "Live restore habilitado"
    else
        check_warn "Live restore no habilitado"
    fi

    # Registros inseguros
    if grep -q "insecure-registries" /etc/docker/daemon.json 2>/dev/null; then
        check_fail "Registros inseguros configurados"
    else
        check_pass "Sin registros inseguros"
    fi

    # Log driver
    if grep -q '"log-driver"' /etc/docker/daemon.json 2>/dev/null; then
        check_pass "Log driver configurado"
    else
        check_warn "Log driver no especificado"
    fi
else
    check_fail "daemon.json no existe"
fi
echo "" | tee -a "$REPORT"

# ── 2. RUNTIME ──
echo "=== 2. RUNTIME ===" | tee -a "$REPORT"

# Seccomp
if [[ -f /etc/securizar/docker-seccomp-strict.json ]]; then
    check_pass "Perfil seccomp estricto disponible"
else
    check_warn "Sin perfil seccomp personalizado"
fi

# AppArmor
if [[ -f /etc/apparmor.d/securizar-container-default ]]; then
    check_pass "Perfil AppArmor para contenedores disponible"
else
    check_info "Sin perfil AppArmor personalizado"
fi

# Contenedores privilegiados
if [[ "$RUNTIME" == "docker" ]] || [[ "$RUNTIME" == "podman" ]]; then
    PRIV_COUNT=$($RUNTIME ps -q 2>/dev/null | while read -r cid; do
        $RUNTIME inspect --format '{{.HostConfig.Privileged}}' "$cid" 2>/dev/null
    done | grep -c "true" || echo 0)
    if [[ "$PRIV_COUNT" -gt 0 ]]; then
        check_fail "$PRIV_COUNT contenedores privilegiados activos"
    else
        check_pass "Sin contenedores privilegiados activos"
    fi
fi
echo "" | tee -a "$REPORT"

# ── 3. IMÁGENES ──
echo "=== 3. IMÁGENES ===" | tee -a "$REPORT"

LATEST_COUNT=$($RUNTIME images --format "{{.Tag}}" 2>/dev/null | grep -c "^latest$" || echo 0)
if [[ "$LATEST_COUNT" -gt 0 ]]; then
    check_warn "$LATEST_COUNT imágenes con tag :latest"
else
    check_pass "Sin imágenes con tag :latest"
fi

# Docker Content Trust
if grep -q "DOCKER_CONTENT_TRUST=1" /etc/environment 2>/dev/null; then
    check_pass "Docker Content Trust habilitado"
else
    check_warn "Docker Content Trust no habilitado"
fi

# Trivy
if command -v trivy &>/dev/null; then
    check_pass "Trivy disponible para escaneo de vulnerabilidades"
else
    check_warn "Trivy no instalado (escaneo de vulnerabilidades no disponible)"
fi
echo "" | tee -a "$REPORT"

# ── 4. RED ──
echo "=== 4. RED ===" | tee -a "$REPORT"

HOST_NET_COUNT=$($RUNTIME ps -q 2>/dev/null | while read -r cid; do
    $RUNTIME inspect --format '{{.HostConfig.NetworkMode}}' "$cid" 2>/dev/null
done | grep -c "^host$" || echo 0)

if [[ "$HOST_NET_COUNT" -gt 0 ]]; then
    check_fail "$HOST_NET_COUNT contenedores con red host"
else
    check_pass "Sin contenedores con red host"
fi
echo "" | tee -a "$REPORT"

# ── 5. VOLÚMENES ──
echo "=== 5. VOLÚMENES ===" | tee -a "$REPORT"

if [[ -f /etc/securizar/docker-mount-policy.conf ]]; then
    check_pass "Política de montajes configurada"
else
    check_warn "Sin política de montajes"
fi

SOCK_MOUNT=$($RUNTIME ps -q 2>/dev/null | while read -r cid; do
    $RUNTIME inspect --format '{{range .Mounts}}{{.Source}} {{end}}' "$cid" 2>/dev/null
done | grep -c "docker.sock" || echo 0)

if [[ "$SOCK_MOUNT" -gt 0 ]]; then
    check_fail "Docker socket montado en $SOCK_MOUNT contenedores"
else
    check_pass "Docker socket no expuesto a contenedores"
fi
echo "" | tee -a "$REPORT"

# ── 6. REGISTROS ──
echo "=== 6. REGISTROS ===" | tee -a "$REPORT"

if [[ -d /etc/docker/certs.d ]]; then
    check_pass "Directorio de certificados de registros existe"
else
    check_info "Sin directorio de certificados de registros"
fi

if [[ -f /etc/securizar/docker-image-policy.conf ]]; then
    check_pass "Política de registros configurada"
else
    check_warn "Sin política de registros"
fi
echo "" | tee -a "$REPORT"

# ── PUNTUACIÓN ──
TOTAL=$((PASS + FAIL + WARN))
if [[ $TOTAL -eq 0 ]]; then
    SCORE=0
else
    SCORE=$(( (PASS * 100) / TOTAL ))
fi

echo "════════════════════════════════════════════" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"
echo "Resultado: $PASS OK | $WARN advertencias | $FAIL fallos (de $TOTAL)" | tee -a "$REPORT"
echo "Puntuación: ${SCORE}%" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

if [[ $SCORE -ge 80 ]] && [[ $FAIL -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}Estado: SEGURO${NC}" | tee -a "$REPORT"
elif [[ $SCORE -ge 50 ]]; then
    echo -e "${YELLOW}${BOLD}Estado: MEJORABLE${NC}" | tee -a "$REPORT"
else
    echo -e "${RED}${BOLD}Estado: INSEGURO${NC}" | tee -a "$REPORT"
fi

echo "" | tee -a "$REPORT"
echo "Reporte guardado: $REPORT"
EOFAUDIT

    chmod +x /usr/local/bin/auditoria-contenedores.sh
    log_change "Creado" "/usr/local/bin/auditoria-contenedores.sh"
    log_change "Permisos" "/usr/local/bin/auditoria-contenedores.sh -> +x"

    # --- Cron semanal ---
    cat > /etc/cron.weekly/auditoria-contenedores << 'EOFCRON'
#!/bin/bash
# Auditoría semanal de seguridad de contenedores
/usr/local/bin/auditoria-contenedores.sh > /var/log/auditoria-contenedores-latest.txt 2>&1
# Alertar si estado es INSEGURO
if grep -q "INSEGURO" /var/log/auditoria-contenedores-latest.txt 2>/dev/null; then
    logger -t auditoria-contenedores "ALERTA: Estado de seguridad de contenedores INSEGURO"
fi
EOFCRON

    chmod 700 /etc/cron.weekly/auditoria-contenedores
    log_change "Creado" "/etc/cron.weekly/auditoria-contenedores"
    log_change "Permisos" "/etc/cron.weekly/auditoria-contenedores -> 700"
    log_info "Auditoría semanal de contenedores programada en cron.weekly"
else
    log_skip "Auditoría de seguridad de contenedores"
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
echo ""
echo -e "${BOLD}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║   RESUMEN - Seguridad de Contenedores                     ║${NC}"
echo -e "${BOLD}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${BOLD}Motor de contenedores:${NC}"
[[ $HAS_DOCKER -eq 1 ]] && echo -e "  ${GREEN}[OK]${NC} Docker" || echo -e "  ${YELLOW}[--]${NC} Docker no detectado"
[[ $HAS_PODMAN -eq 1 ]] && echo -e "  ${GREEN}[OK]${NC} Podman" || echo -e "  ${YELLOW}[--]${NC} Podman no detectado"
[[ $HAS_KUBECTL -eq 1 ]] && echo -e "  ${GREEN}[OK]${NC} kubectl" || echo -e "  ${YELLOW}[--]${NC} kubectl no detectado"
echo ""

echo -e "${BOLD}Scripts instalados:${NC}"
for script in \
    /usr/local/bin/securizar-docker-run.sh \
    /usr/local/bin/escanear-imagenes.sh \
    /usr/local/bin/auditar-red-contenedores.sh \
    /usr/local/bin/auditar-registros.sh \
    /usr/local/bin/migrar-rootless.sh \
    /usr/local/bin/monitorizar-contenedores.sh \
    /usr/local/bin/auditar-kubernetes.sh \
    /usr/local/bin/auditoria-contenedores.sh; do
    if [[ -x "$script" ]]; then
        echo -e "  ${GREEN}[OK]${NC} $(basename "$script")"
    else
        echo -e "  ${YELLOW}[--]${NC} $(basename "$script") no instalado"
    fi
done
echo ""

echo -e "${BOLD}Configuraciones:${NC}"
[[ -f /etc/docker/daemon.json ]] && echo -e "  ${GREEN}[OK]${NC} /etc/docker/daemon.json" || echo -e "  ${YELLOW}[--]${NC} daemon.json"
[[ -f /etc/securizar/docker-seccomp-strict.json ]] && echo -e "  ${GREEN}[OK]${NC} Perfil seccomp estricto" || echo -e "  ${YELLOW}[--]${NC} Perfil seccomp"
[[ -f /etc/securizar/docker-image-policy.conf ]] && echo -e "  ${GREEN}[OK]${NC} Política de imágenes" || echo -e "  ${YELLOW}[--]${NC} Política de imágenes"
[[ -f /etc/securizar/docker-mount-policy.conf ]] && echo -e "  ${GREEN}[OK]${NC} Política de montajes" || echo -e "  ${YELLOW}[--]${NC} Política de montajes"
echo ""

echo -e "${BOLD}Uso rápido:${NC}"
echo -e "  ${DIM}Docker seguro:${NC}     securizar-docker-run.sh <imagen>"
echo -e "  ${DIM}Escanear imágenes:${NC} escanear-imagenes.sh"
echo -e "  ${DIM}Auditar red:${NC}       auditar-red-contenedores.sh"
echo -e "  ${DIM}Auditar registros:${NC} auditar-registros.sh"
echo -e "  ${DIM}Migrar rootless:${NC}   migrar-rootless.sh"
echo -e "  ${DIM}Monitorizar:${NC}       monitorizar-contenedores.sh"
echo -e "  ${DIM}Auditar K8s:${NC}       auditar-kubernetes.sh"
echo -e "  ${DIM}Auditoría CIS:${NC}     auditoria-contenedores.sh"
echo ""
show_changes_summary
log_info "Módulo de seguridad de contenedores completado"
