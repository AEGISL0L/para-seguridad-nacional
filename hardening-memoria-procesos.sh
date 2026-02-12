#!/bin/bash
# ============================================================
# hardening-memoria-procesos.sh — Módulo 67: Hardening de Memoria y Procesos
# ============================================================
# ASLR, W^X, seccomp, cgroups v2, namespaces, ptrace, coredumps
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/securizar-common.sh"

require_root
securizar_setup_traps
init_backup "hardening-memoria-procesos"

# ── Sección 1: Hardened memory allocator ──
section_1() {
    log_section "1. Hardened memory allocator"

    if [[ -f /etc/securizar/mem-hardening/config.conf ]]; then
        log_already "Memory hardening configurado (/etc/securizar/mem-hardening/config.conf existe)"; return 0
    fi
    ask "¿Verificar y configurar hardening del alocador de memoria?" || { log_skip "Memory allocator omitido"; return 0; }

    mkdir -p /etc/securizar/mem-hardening /var/log/securizar/mem-hardening

    cat > /usr/local/bin/securizar-mem-allocator.sh << 'EOFALLOCATOR'
#!/bin/bash
# ============================================================
# securizar-mem-allocator.sh — Verificar hardening del alocador
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar/mem-hardening"
mkdir -p "$LOG_DIR"
REPORT="$LOG_DIR/allocator-$(date +%Y%m%d).txt"

{
echo "=========================================="
echo " Hardened Memory Allocator"
echo " $(date) - $(hostname)"
echo "=========================================="
echo ""

echo "=== Parámetros de arranque ==="
CMDLINE=$(cat /proc/cmdline)
ALLOC_PARAMS=(
    "init_on_alloc:Inicializar memoria al alocar"
    "init_on_free:Inicializar memoria al liberar"
    "slab_nomerge:Evitar merge de slabs"
    "slub_debug:Flags de debug SLUB"
    "page_alloc.shuffle:Randomizar alocación de páginas"
    "hardened_usercopy:Validar copias user-kernel"
)

for entry in "${ALLOC_PARAMS[@]}"; do
    param="${entry%%:*}"
    desc="${entry#*:}"
    if echo "$CMDLINE" | grep -qoP "${param}(=\S+)?"; then
        VAL=$(echo "$CMDLINE" | grep -oP "${param}(=\S+)?" || echo "$param")
        echo "  [OK] $VAL ($desc)"
    else
        echo "  [--] $param no configurado ($desc)"
    fi
done

echo ""
echo "=== Configuración del kernel ==="
CONFIG="/boot/config-$(uname -r)"
if [[ -f "$CONFIG" ]]; then
    OPTS=(
        CONFIG_HARDENED_USERCOPY
        CONFIG_INIT_ON_ALLOC_DEFAULT_ON
        CONFIG_INIT_ON_FREE_DEFAULT_ON
        CONFIG_SLAB_FREELIST_HARDENED
        CONFIG_SLAB_FREELIST_RANDOM
        CONFIG_SHUFFLE_PAGE_ALLOCATOR
        CONFIG_FORTIFY_SOURCE
        CONFIG_STACKPROTECTOR_STRONG
    )
    for opt in "${OPTS[@]}"; do
        VAL=$(grep "^${opt}=" "$CONFIG" 2>/dev/null || echo "${opt} no definido")
        if echo "$VAL" | grep -q "=y"; then
            echo "  [OK] $VAL"
        else
            echo "  [--] $VAL"
        fi
    done
else
    echo "  [INFO] Config del kernel no accesible en $CONFIG"
fi

echo ""
echo "=== Recomendaciones GRUB ==="
echo "  init_on_alloc=1 init_on_free=1 slab_nomerge page_alloc.shuffle=1"
echo "  slub_debug=FZP (para detección de corrupciones - impacto rendimiento)"

echo ""
echo "Completado: $(date)"
} 2>&1 | tee "$REPORT"
EOFALLOCATOR
    chmod +x /usr/local/bin/securizar-mem-allocator.sh

    # Archivo de configuración marker
    cat > /etc/securizar/mem-hardening/config.conf << 'EOF'
# Securizar — Hardening de Memoria y Procesos
# Configurado: fecha de instalación
# Módulo 67 aplicado
SECURIZAR_MEM_HARDENING=1
EOF

    log_change "Verificador de hardening de memoria instalado"
    log_change "Aplicado" "Sección 1: Verificación init_on_alloc, slab_nomerge, hardened_usercopy"
}

# ── Sección 2: Stack protection ──
section_2() {
    log_section "2. Stack protection"

    if check_executable /usr/local/bin/securizar-mem-stack.sh; then
        log_already "Stack protection (securizar-mem-stack.sh existe)"; return 0
    fi
    ask "¿Verificar protección de stack (SSP, CET, shadow stacks)?" || { log_skip "Stack protection omitido"; return 0; }

    mkdir -p /var/log/securizar/mem-hardening

    cat > /usr/local/bin/securizar-mem-stack.sh << 'EOFSTACK'
#!/bin/bash
# ============================================================
# securizar-mem-stack.sh — Verificar protección de stack
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar/mem-hardening"
mkdir -p "$LOG_DIR"
REPORT="$LOG_DIR/stack-$(date +%Y%m%d).txt"

{
echo "=========================================="
echo " Stack Protection"
echo " $(date) - $(hostname)"
echo "=========================================="
echo ""

echo "=== Stack Smashing Protector (SSP) ==="
echo "  Verificando binarios del sistema..."

SSP_COUNT=0
NO_SSP_COUNT=0
CHECKED=0

for bin in /usr/bin/ssh /usr/sbin/sshd /usr/bin/sudo /usr/bin/passwd /usr/sbin/auditd; do
    if [[ -x "$bin" ]]; then
        ((CHECKED++))
        if readelf -s "$bin" 2>/dev/null | grep -q '__stack_chk_fail'; then
            echo "  [OK] $bin — SSP habilitado"
            ((SSP_COUNT++))
        else
            echo "  [!!] $bin — SSP NO detectado"
            ((NO_SSP_COUNT++))
        fi
    fi
done
echo "  Con SSP: $SSP_COUNT / $CHECKED binarios verificados"

echo ""
echo "=== Control-flow Enforcement Technology (CET) ==="
if grep -q 'cet' /proc/cpuinfo 2>/dev/null; then
    echo "  [OK] CPU soporta CET"
    if grep -q 'shstk' /proc/cpuinfo 2>/dev/null; then
        echo "  [OK] Shadow Stack (SHSTK) soportado"
    fi
    if grep -q 'ibt' /proc/cpuinfo 2>/dev/null; then
        echo "  [OK] Indirect Branch Tracking (IBT) soportado"
    fi
else
    echo "  [INFO] CPU no soporta CET (requiere Intel 11th Gen+ / AMD Zen 3+)"
fi

CONFIG="/boot/config-$(uname -r)"
if [[ -f "$CONFIG" ]]; then
    for opt in CONFIG_X86_KERNEL_IBT CONFIG_X86_USER_SHADOW_STACK; do
        VAL=$(grep "^${opt}=" "$CONFIG" 2>/dev/null || echo "${opt} no definido")
        if echo "$VAL" | grep -q "=y"; then
            echo "  [OK] $VAL"
        else
            echo "  [--] $VAL"
        fi
    done
fi

echo ""
echo "=== Kernel Stack Protection ==="
if [[ -f "$CONFIG" ]]; then
    for opt in CONFIG_STACKPROTECTOR CONFIG_STACKPROTECTOR_STRONG \
               CONFIG_GCC_PLUGIN_STACKLEAK CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT; do
        VAL=$(grep "^${opt}=" "$CONFIG" 2>/dev/null || echo "${opt} no definido")
        if echo "$VAL" | grep -q "=y"; then
            echo "  [OK] $VAL"
        else
            echo "  [--] $VAL"
        fi
    done
fi

echo ""
echo "Completado: $(date)"
} 2>&1 | tee "$REPORT"
EOFSTACK
    chmod +x /usr/local/bin/securizar-mem-stack.sh

    log_change "Verificador de stack protection instalado"
    log_change "Aplicado" "Sección 2: Detección SSP, CET/IBT/SHSTK, kernel stack protection"
}

# ── Sección 3: User namespace restriction ──
section_3() {
    log_section "3. User namespace restriction"

    if check_executable /usr/local/bin/securizar-mem-userns.sh; then
        log_already "User namespace restriction (securizar-mem-userns.sh existe)"; return 0
    fi
    ask "¿Restringir user namespaces no privilegiados?" || { log_skip "User namespace restriction omitida"; return 0; }

    mkdir -p /var/log/securizar/mem-hardening

    # Aplicar sysctl
    local SYSCTL_FILE="/etc/sysctl.d/90-securizar-userns.conf"
    backup_if_exists "$SYSCTL_FILE"

    cat > "$SYSCTL_FILE" << 'EOF'
# Securizar — Restricción de user namespaces
# Deshabilitar user namespaces no privilegiados (previene varios container escapes)
# NOTA: Puede afectar a Flatpak, Podman rootless, Chrome sandbox
kernel.unprivileged_userns_clone = 0
# Limitar máximo de user namespaces (alternativa menos restrictiva)
# user.max_user_namespaces = 0
EOF
    # Solo aplicar si el parámetro existe en el kernel
    if sysctl -n kernel.unprivileged_userns_clone &>/dev/null; then
        sysctl -p "$SYSCTL_FILE" 2>/dev/null || true
    fi

    cat > /usr/local/bin/securizar-mem-userns.sh << 'EOFUSERNS'
#!/bin/bash
# ============================================================
# securizar-mem-userns.sh — Auditar uso de user namespaces
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar/mem-hardening"
mkdir -p "$LOG_DIR"
REPORT="$LOG_DIR/userns-$(date +%Y%m%d).txt"

{
echo "=========================================="
echo " User Namespace Restriction"
echo " $(date) - $(hostname)"
echo "=========================================="
echo ""

echo "=== Estado actual ==="
USERNS_CLONE=$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo "N/A")
echo "  kernel.unprivileged_userns_clone = $USERNS_CLONE"
if [[ "$USERNS_CLONE" == "0" ]]; then
    echo "  [OK] User namespaces no privilegiados deshabilitados"
elif [[ "$USERNS_CLONE" == "1" ]]; then
    echo "  [!!] User namespaces no privilegiados HABILITADOS"
fi

MAX_USERNS=$(cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo "N/A")
echo "  user.max_user_namespaces = $MAX_USERNS"

echo ""
echo "=== Procesos usando user namespaces ==="
USERNS_PROCS=0
for pid_dir in /proc/[0-9]*; do
    pid=$(basename "$pid_dir")
    [[ ! -f "$pid_dir/status" ]] && continue

    USERNS_ID=$(readlink "$pid_dir/ns/user" 2>/dev/null || continue)
    INIT_USERNS=$(readlink /proc/1/ns/user 2>/dev/null || continue)

    if [[ "$USERNS_ID" != "$INIT_USERNS" ]]; then
        CMDLINE=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null | head -c 80)
        USER=$(stat -c '%U' "$pid_dir" 2>/dev/null || echo "?")
        echo "  PID $pid [$USER]: $CMDLINE"
        ((USERNS_PROCS++))
    fi
done

if [[ $USERNS_PROCS -eq 0 ]]; then
    echo "  Ningún proceso en user namespace separado"
else
    echo ""
    echo "  Total: $USERNS_PROCS procesos en user namespaces"
fi

echo ""
echo "=== Impacto de restricción ==="
echo "  Aplicaciones afectadas por unprivileged_userns_clone=0:"
for app in flatpak podman chrome chromium firefox-esr; do
    if command -v "$app" &>/dev/null; then
        echo "  [!] $app (puede requerir ajustes)"
    fi
done

echo ""
echo "Completado: $(date)"
} 2>&1 | tee "$REPORT"
EOFUSERNS
    chmod +x /usr/local/bin/securizar-mem-userns.sh

    log_change "Restricción de user namespaces aplicada"
    log_change "Aplicado" "Sección 3: unprivileged_userns_clone=0, auditoría de userns"
}

# ── Sección 4: Cgroups v2 resource isolation ──
section_4() {
    log_section "4. Cgroups v2 resource isolation"

    if check_executable /usr/local/bin/securizar-mem-cgroups.sh; then
        log_already "Cgroups v2 (securizar-mem-cgroups.sh existe)"; return 0
    fi
    ask "¿Configurar aislamiento de recursos con cgroups v2 para servicios críticos?" || { log_skip "Cgroups v2 omitido"; return 0; }

    mkdir -p /var/log/securizar/mem-hardening /etc/securizar/mem-hardening

    # Crear drop-ins para servicios críticos
    local SERVICES=("sshd" "auditd" "rsyslog" "systemd-journald" "systemd-resolved")

    for svc in "${SERVICES[@]}"; do
        local svc_file="${svc}.service"
        if systemctl cat "$svc_file" &>/dev/null; then
            local DROPIN_DIR="/etc/systemd/system/${svc_file}.d"
            local DROPIN_FILE="$DROPIN_DIR/securizar-resource-limits.conf"

            if [[ -f "$DROPIN_FILE" ]]; then
                continue
            fi

            mkdir -p "$DROPIN_DIR"

            case "$svc" in
                sshd)
                    cat > "$DROPIN_FILE" << 'EOF'
[Service]
# Securizar — Aislamiento de recursos sshd
MemoryMax=512M
MemoryHigh=384M
CPUQuota=80%
TasksMax=100
EOF
                    ;;
                auditd)
                    cat > "$DROPIN_FILE" << 'EOF'
[Service]
# Securizar — Aislamiento de recursos auditd
MemoryMax=256M
MemoryHigh=192M
CPUQuota=50%
TasksMax=20
EOF
                    ;;
                *)
                    cat > "$DROPIN_FILE" << 'EOF'
[Service]
# Securizar — Aislamiento de recursos genérico
MemoryMax=256M
MemoryHigh=192M
CPUQuota=60%
TasksMax=50
EOF
                    ;;
            esac
        fi
    done

    systemctl daemon-reload 2>/dev/null || true

    # Script de verificación
    cat > /usr/local/bin/securizar-mem-cgroups.sh << 'EOFCGROUPS'
#!/bin/bash
# ============================================================
# securizar-mem-cgroups.sh — Verificar cgroups v2 resource isolation
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar/mem-hardening"
mkdir -p "$LOG_DIR"
REPORT="$LOG_DIR/cgroups-$(date +%Y%m%d).txt"

{
echo "=========================================="
echo " Cgroups v2 Resource Isolation"
echo " $(date) - $(hostname)"
echo "=========================================="
echo ""

echo "=== Cgroups versión ==="
if [[ -f /sys/fs/cgroup/cgroup.controllers ]]; then
    echo "  [OK] Cgroups v2 (unified) activo"
    echo "  Controllers: $(cat /sys/fs/cgroup/cgroup.controllers)"
elif [[ -d /sys/fs/cgroup/memory ]]; then
    echo "  [INFO] Cgroups v1 (legacy) — considerar migrar a v2"
else
    echo "  [WARN] No se detectó cgroups"
fi

echo ""
echo "=== Servicios con límites de recursos ==="
SERVICES=("sshd" "auditd" "rsyslog" "systemd-journald" "systemd-resolved")

for svc in "${SERVICES[@]}"; do
    SVC_FILE="${svc}.service"
    if systemctl cat "$SVC_FILE" &>/dev/null; then
        MEMORY_MAX=$(systemctl show "$SVC_FILE" -p MemoryMax --value 2>/dev/null || echo "N/A")
        CPU_QUOTA=$(systemctl show "$SVC_FILE" -p CPUQuota --value 2>/dev/null || echo "N/A")
        TASKS_MAX=$(systemctl show "$SVC_FILE" -p TasksMax --value 2>/dev/null || echo "N/A")

        if [[ "$MEMORY_MAX" != "infinity" && "$MEMORY_MAX" != "N/A" ]]; then
            echo "  [OK] $svc: MemoryMax=$MEMORY_MAX CPUQuota=$CPU_QUOTA TasksMax=$TASKS_MAX"
        else
            echo "  [--] $svc: sin límites de recursos"
        fi
    fi
done

echo ""
echo "=== Uso actual de recursos por servicio ==="
for svc in "${SERVICES[@]}"; do
    if systemctl is-active "${svc}.service" &>/dev/null; then
        MEM_CUR=$(systemctl show "${svc}.service" -p MemoryCurrent --value 2>/dev/null || echo "N/A")
        echo "  $svc: MemoryCurrent=$MEM_CUR"
    fi
done

echo ""
echo "Completado: $(date)"
} 2>&1 | tee "$REPORT"
EOFCGROUPS
    chmod +x /usr/local/bin/securizar-mem-cgroups.sh

    log_change "Aislamiento de recursos cgroups v2 configurado"
    log_change "Aplicado" "Sección 4: MemoryMax, CPUQuota, TasksMax para sshd, auditd, etc."
}

# ── Sección 5: Seccomp-BPF profiles avanzados ──
section_5() {
    log_section "5. Seccomp-BPF profiles avanzados"

    if check_executable /usr/local/bin/securizar-mem-seccomp.sh; then
        log_already "Seccomp avanzado (securizar-mem-seccomp.sh existe)"; return 0
    fi
    ask "¿Generar perfiles seccomp personalizados para servicios?" || { log_skip "Seccomp avanzado omitido"; return 0; }

    mkdir -p /etc/securizar/mem-hardening/seccomp /var/log/securizar/mem-hardening

    # Script generador de perfiles seccomp
    cat > /usr/local/bin/securizar-mem-seccomp.sh << 'EOFSECCOMP'
#!/bin/bash
# ============================================================
# securizar-mem-seccomp.sh — Generar/verificar perfiles seccomp
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar/mem-hardening"
SECCOMP_DIR="/etc/securizar/mem-hardening/seccomp"
mkdir -p "$LOG_DIR" "$SECCOMP_DIR"
ACTION="${1:-status}"
TARGET="${2:-}"

case "$ACTION" in
    status)
        {
        echo "=========================================="
        echo " Seccomp-BPF Profiles"
        echo " $(date) - $(hostname)"
        echo "=========================================="
        echo ""

        echo "=== Procesos con seccomp activo ==="
        SECCOMP_COUNT=0
        NO_SECCOMP_COUNT=0

        for pid_dir in /proc/[0-9]*; do
            pid=$(basename "$pid_dir")
            [[ ! -f "$pid_dir/status" ]] && continue

            SECCOMP_MODE=$(grep '^Seccomp:' "$pid_dir/status" 2>/dev/null | awk '{print $2}' || continue)
            if [[ "$SECCOMP_MODE" -gt 0 ]]; then
                ((SECCOMP_COUNT++))
            else
                CMDLINE=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null | head -c 60 || true)
                if [[ -n "$CMDLINE" ]]; then
                    ((NO_SECCOMP_COUNT++))
                fi
            fi
        done

        echo "  Con seccomp: $SECCOMP_COUNT procesos"
        echo "  Sin seccomp: $NO_SECCOMP_COUNT procesos"

        echo ""
        echo "=== Servicios críticos sin seccomp ==="
        CRITICAL=("nginx" "apache2" "httpd" "postgresql" "redis-server" "mysqld" "mariadbd")
        for svc in "${CRITICAL[@]}"; do
            PIDS=$(pgrep -x "$svc" 2>/dev/null || true)
            if [[ -n "$PIDS" ]]; then
                for pid in $PIDS; do
                    SECCOMP_MODE=$(grep '^Seccomp:' "/proc/$pid/status" 2>/dev/null | awk '{print $2}' || echo "0")
                    if [[ "$SECCOMP_MODE" -eq 0 ]]; then
                        echo "  [!!] $svc (PID $pid) — sin seccomp"
                    else
                        echo "  [OK] $svc (PID $pid) — seccomp mode $SECCOMP_MODE"
                    fi
                done
            fi
        done

        echo ""
        echo "=== Perfiles securizar disponibles ==="
        if ls "$SECCOMP_DIR"/*.json &>/dev/null; then
            for profile in "$SECCOMP_DIR"/*.json; do
                echo "  $(basename "$profile")"
            done
        else
            echo "  Ningún perfil generado aún"
            echo "  Generar: $0 generate <servicio>"
        fi

        echo ""
        echo "Completado: $(date)"
        } 2>&1 | tee "$LOG_DIR/seccomp-$(date +%Y%m%d).txt"
        ;;

    generate)
        if [[ -z "$TARGET" ]]; then
            echo "Uso: $0 generate <nombre_proceso>"
            echo "  Ejemplo: $0 generate nginx"
            exit 1
        fi

        PID=$(pgrep -x "$TARGET" -n 2>/dev/null || true)
        if [[ -z "$PID" ]]; then
            echo "[WARN] Proceso '$TARGET' no encontrado. Debe estar corriendo."
            exit 1
        fi

        echo "=== Generando perfil seccomp para $TARGET (PID $PID) ==="
        echo "  Tracing syscalls por 30 segundos..."

        TRACE_FILE=$(mktemp)
        timeout 30 strace -f -p "$PID" -e trace=all -c 2>"$TRACE_FILE" || true

        # Extraer syscalls
        SYSCALLS=$(grep -oP '^\s+[\d.]+\s+[\d.]+\s+\d+\s+\d+\s+\d+\s+\K\S+' "$TRACE_FILE" 2>/dev/null | sort -u || true)

        if [[ -z "$SYSCALLS" ]]; then
            echo "[INFO] No se capturaron syscalls. Usando perfil base."
            SYSCALLS="read write open close stat fstat lstat poll lseek mmap mprotect munmap brk ioctl access pipe select sched_yield mremap msync mincore madvise shmget shmat shmctl dup dup2 pause nanosleep getitimer alarm setitimer getpid sendfile socket connect accept sendto recvfrom sendmsg recvmsg shutdown bind listen getsockname getpeername socketpair setsockopt getsockopt clone fork vfork execve exit wait4 kill uname fcntl flock fsync fdatasync truncate getdents getcwd chdir mkdir rmdir creat link unlink readlink chmod fchmod chown fchown lchown umask gettimeofday getrlimit getuid getgid geteuid getegid setuid setgid getgroups setgroups getresuid getresgid sigaltstack statfs fstatfs sysinfo times getpgid setpgid setsid getpriority setpriority sched_setparam sched_getparam sched_setscheduler sched_getscheduler sched_get_priority_max sched_get_priority_min rt_sigaction rt_sigprocmask rt_sigreturn rt_sigsuspend pread64 pwrite64 getcpu exit_group epoll_create epoll_ctl epoll_wait set_tid_address clock_gettime clock_getres clock_nanosleep set_robust_list get_robust_list epoll_create1 pipe2 eventfd2 accept4 signalfd4 timerfd_create timerfd_settime timerfd_gettime getrandom"
        fi

        # Generar JSON
        PROFILE="$SECCOMP_DIR/${TARGET}-seccomp.json"
        {
            echo "{"
            echo "  \"defaultAction\": \"SCMP_ACT_LOG\","
            echo "  \"architectures\": [\"SCMP_ARCH_X86_64\"],"
            echo "  \"syscalls\": ["
            echo "    {"
            echo "      \"names\": ["
            FIRST=true
            for sc in $SYSCALLS; do
                if $FIRST; then
                    echo -n "        \"$sc\""
                    FIRST=false
                else
                    echo ","
                    echo -n "        \"$sc\""
                fi
            done
            echo ""
            echo "      ],"
            echo "      \"action\": \"SCMP_ACT_ALLOW\""
            echo "    }"
            echo "  ]"
            echo "}"
        } > "$PROFILE"

        rm -f "$TRACE_FILE"
        echo "[OK] Perfil generado: $PROFILE"
        echo "  NOTA: defaultAction=SCMP_ACT_LOG (audit mode)"
        echo "  Cambiar a SCMP_ACT_ERRNO para enforcement"
        ;;

    *)
        echo "Uso: $0 {status|generate <proceso>}"
        echo ""
        echo "  status            — Ver estado seccomp de procesos"
        echo "  generate <proc>   — Generar perfil seccomp desde strace"
        ;;
esac
EOFSECCOMP
    chmod +x /usr/local/bin/securizar-mem-seccomp.sh

    log_change "Generador de perfiles seccomp-BPF instalado"
    log_change "Aplicado" "Sección 5: Perfiles seccomp custom con strace, audit mode"
}

# ── Sección 6: ASLR y PIE enforcement ──
section_6() {
    log_section "6. ASLR y PIE enforcement"

    if check_executable /usr/local/bin/securizar-mem-aslr.sh; then
        log_already "ASLR/PIE (securizar-mem-aslr.sh existe)"; return 0
    fi
    ask "¿Verificar y enforcer ASLR máximo y PIE en binarios del sistema?" || { log_skip "ASLR/PIE omitido"; return 0; }

    mkdir -p /var/log/securizar/mem-hardening

    # Asegurar ASLR=2
    local SYSCTL_FILE="/etc/sysctl.d/90-securizar-aslr.conf"
    backup_if_exists "$SYSCTL_FILE"

    cat > "$SYSCTL_FILE" << 'EOF'
# Securizar — ASLR y protección de memoria
kernel.randomize_va_space = 2
# Mínimo de dirección mmap (previene NULL-pointer dereference exploits)
vm.mmap_min_addr = 65536
EOF
    sysctl -p "$SYSCTL_FILE" 2>/dev/null || true

    cat > /usr/local/bin/securizar-mem-aslr.sh << 'EOFASLR'
#!/bin/bash
# ============================================================
# securizar-mem-aslr.sh — Verificar ASLR y PIE
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar/mem-hardening"
mkdir -p "$LOG_DIR"
REPORT="$LOG_DIR/aslr-$(date +%Y%m%d).txt"

{
echo "=========================================="
echo " ASLR y PIE Enforcement"
echo " $(date) - $(hostname)"
echo "=========================================="
echo ""

echo "=== ASLR ==="
ASLR=$(sysctl -n kernel.randomize_va_space 2>/dev/null || echo "N/A")
case "$ASLR" in
    2) echo "  [OK] ASLR = 2 (máximo: stack + mmap + brk)" ;;
    1) echo "  [!!] ASLR = 1 (parcial: solo stack + mmap)" ;;
    0) echo "  [!!] ASLR = 0 (DESACTIVADO)" ;;
    *) echo "  [??] ASLR = $ASLR" ;;
esac

MMAP_MIN=$(sysctl -n vm.mmap_min_addr 2>/dev/null || echo "N/A")
echo "  vm.mmap_min_addr = $MMAP_MIN"
if [[ "$MMAP_MIN" -ge 65536 ]] 2>/dev/null; then
    echo "  [OK] mmap_min_addr >= 65536"
else
    echo "  [!!] mmap_min_addr < 65536 (riesgo NULL-pointer exploits)"
fi

# mmap_rnd_bits
MMAP_RND=$(cat /proc/sys/vm/mmap_rnd_bits 2>/dev/null || echo "N/A")
MMAP_RND_COMPAT=$(cat /proc/sys/vm/mmap_rnd_compat_bits 2>/dev/null || echo "N/A")
echo "  vm.mmap_rnd_bits = $MMAP_RND"
echo "  vm.mmap_rnd_compat_bits = $MMAP_RND_COMPAT"

echo ""
echo "=== Binarios sin PIE en /usr/bin y /usr/sbin ==="
NO_PIE=0
CHECKED=0
for dir in /usr/bin /usr/sbin; do
    for bin in "$dir"/*; do
        [[ ! -x "$bin" || ! -f "$bin" ]] && continue
        # Solo verificar ELF
        if file "$bin" 2>/dev/null | grep -q "ELF"; then
            ((CHECKED++))
            if ! file "$bin" 2>/dev/null | grep -q "pie\|PIE\|shared object"; then
                if readelf -h "$bin" 2>/dev/null | grep -q "EXEC"; then
                    echo "  [!!] NO-PIE: $bin"
                    ((NO_PIE++))
                fi
            fi
        fi
    done
done
echo ""
echo "  Binarios ELF verificados: $CHECKED"
echo "  Sin PIE: $NO_PIE"

if [[ $NO_PIE -eq 0 ]]; then
    echo "  [OK] Todos los binarios verificados son PIE"
fi

echo ""
echo "Completado: $(date)"
} 2>&1 | tee "$REPORT"
EOFASLR
    chmod +x /usr/local/bin/securizar-mem-aslr.sh

    log_change "ASLR=2 y verificador PIE instalados"
    log_change "Aplicado" "Sección 6: ASLR máximo, mmap_min_addr=65536, detección binarios no-PIE"
}

# ── Sección 7: W^X estricto ──
section_7() {
    log_section "7. W^X estricto"

    if check_executable /usr/local/bin/securizar-mem-wxstrict.sh; then
        log_already "W^X estricto (securizar-mem-wxstrict.sh existe)"; return 0
    fi
    ask "¿Verificar y enforcer W^X (noexec) en particiones temporales?" || { log_skip "W^X omitido"; return 0; }

    mkdir -p /var/log/securizar/mem-hardening

    cat > /usr/local/bin/securizar-mem-wxstrict.sh << 'EOFWX'
#!/bin/bash
# ============================================================
# securizar-mem-wxstrict.sh — Verificar W^X y noexec mounts
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar/mem-hardening"
mkdir -p "$LOG_DIR"
REPORT="$LOG_DIR/wx-strict-$(date +%Y%m%d).txt"

{
echo "=========================================="
echo " W^X Estricto — Separación Write/Execute"
echo " $(date) - $(hostname)"
echo "=========================================="
echo ""

echo "=== Montajes con noexec ==="
PATHS_TO_CHECK=("/tmp" "/dev/shm" "/var/tmp" "/home")
ISSUES=0

for mount_path in "${PATHS_TO_CHECK[@]}"; do
    if mountpoint -q "$mount_path" 2>/dev/null; then
        MOUNT_OPTS=$(findmnt -n -o OPTIONS "$mount_path" 2>/dev/null || echo "")
        if echo "$MOUNT_OPTS" | grep -q "noexec"; then
            echo "  [OK] $mount_path — noexec"
        else
            echo "  [!!] $mount_path — SIN noexec"
            ((ISSUES++))
        fi

        # Verificar nosuid y nodev también
        if echo "$MOUNT_OPTS" | grep -q "nosuid"; then
            echo "       nosuid: OK"
        else
            echo "       [!] nosuid: falta"
        fi

        if echo "$MOUNT_OPTS" | grep -q "nodev"; then
            echo "       nodev: OK"
        else
            echo "       [!] nodev: falta"
        fi
    else
        echo "  [--] $mount_path — no es punto de montaje separado"
        echo "       Considerar añadir partición/tmpfs con noexec"
    fi
done

echo ""
echo "=== /dev/shm específico ==="
SHM_OPTS=$(findmnt -n -o OPTIONS /dev/shm 2>/dev/null || echo "N/A")
echo "  Opciones: $SHM_OPTS"
if ! echo "$SHM_OPTS" | grep -q "noexec"; then
    echo "  [WARN] /dev/shm sin noexec — frecuente vector de ataque"
    echo "  Añadir a /etc/fstab:"
    echo "  tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0"
fi

echo ""
echo "=== Verificar executable stack ==="
NO_EXECSTACK=0
EXECSTACK=0
for bin in /usr/bin/ssh /usr/sbin/sshd /usr/bin/sudo /usr/sbin/nginx /usr/sbin/apache2; do
    if [[ -x "$bin" ]]; then
        if readelf -l "$bin" 2>/dev/null | grep -q "GNU_STACK.*RWE"; then
            echo "  [!!] $bin — executable stack"
            ((EXECSTACK++))
        else
            ((NO_EXECSTACK++))
        fi
    fi
done
echo "  Binarios sin execstack: $NO_EXECSTACK"
echo "  Binarios con execstack: $EXECSTACK"

echo ""
echo "=== Recomendaciones fstab ==="
echo "  /tmp:     tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,size=2G 0 0"
echo "  /dev/shm: tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0"
echo "  /var/tmp: Bind mount con noexec o partición separada"

echo ""
echo "Issues detectados: $ISSUES"
echo "Completado: $(date)"
} 2>&1 | tee "$REPORT"
EOFWX
    chmod +x /usr/local/bin/securizar-mem-wxstrict.sh

    log_change "Verificador W^X estricto instalado"
    log_change "Aplicado" "Sección 7: noexec en /tmp, /dev/shm, /var/tmp; detección executable stack"
}

# ── Sección 8: Control ptrace y debugging ──
section_8() {
    log_section "8. Control ptrace y debugging"

    if check_executable /usr/local/bin/securizar-mem-ptrace.sh; then
        log_already "Ptrace control (securizar-mem-ptrace.sh existe)"; return 0
    fi
    ask "¿Restringir ptrace y debugging de procesos?" || { log_skip "Ptrace control omitido"; return 0; }

    mkdir -p /var/log/securizar/mem-hardening

    # Aplicar sysctl
    local SYSCTL_FILE="/etc/sysctl.d/90-securizar-ptrace.conf"
    backup_if_exists "$SYSCTL_FILE"

    cat > "$SYSCTL_FILE" << 'EOF'
# Securizar — Restricción ptrace
# 0=normal, 1=solo padre, 2=solo admin, 3=ningún proceso
kernel.yama.ptrace_scope = 2
# Core pattern seguro (no writable por usuario)
kernel.core_pattern = |/bin/false
# Deshabilitar suid_dumpable
fs.suid_dumpable = 0
EOF
    sysctl -p "$SYSCTL_FILE" 2>/dev/null || true

    cat > /usr/local/bin/securizar-mem-ptrace.sh << 'EOFPTRACE'
#!/bin/bash
# ============================================================
# securizar-mem-ptrace.sh — Verificar restricciones ptrace
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar/mem-hardening"
mkdir -p "$LOG_DIR"
REPORT="$LOG_DIR/ptrace-$(date +%Y%m%d).txt"

{
echo "=========================================="
echo " Control ptrace y Debugging"
echo " $(date) - $(hostname)"
echo "=========================================="
echo ""

echo "=== YAMA ptrace_scope ==="
PTRACE=$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null || echo "N/A")
case "$PTRACE" in
    0) echo "  [!!] ptrace_scope = 0 (cualquier proceso puede tracear)" ;;
    1) echo "  [OK] ptrace_scope = 1 (solo proceso padre)" ;;
    2) echo "  [OK] ptrace_scope = 2 (solo admin/CAP_SYS_PTRACE)" ;;
    3) echo "  [OK] ptrace_scope = 3 (totalmente deshabilitado)" ;;
    *) echo "  [??] ptrace_scope = $PTRACE" ;;
esac

echo ""
echo "=== Core pattern ==="
CORE_PATTERN=$(sysctl -n kernel.core_pattern 2>/dev/null || echo "N/A")
echo "  core_pattern = $CORE_PATTERN"
if echo "$CORE_PATTERN" | grep -q "false\|/dev/null"; then
    echo "  [OK] Coredumps redirigidos a /bin/false"
elif echo "$CORE_PATTERN" | grep -q "systemd-coredump"; then
    echo "  [INFO] Manejado por systemd-coredump (verificar Storage=none)"
else
    echo "  [!!] Core pattern puede filtrar datos sensibles"
fi

echo ""
echo "=== suid_dumpable ==="
SUID_DUMP=$(sysctl -n fs.suid_dumpable 2>/dev/null || echo "N/A")
if [[ "$SUID_DUMP" == "0" ]]; then
    echo "  [OK] suid_dumpable = 0 (no dump procesos SUID)"
else
    echo "  [!!] suid_dumpable = $SUID_DUMP (riesgo de filtración)"
fi

echo ""
echo "=== Herramientas de debug accesibles ==="
for tool in strace ltrace gdb ptrace; do
    if command -v "$tool" &>/dev/null; then
        PERMS=$(stat -c '%a %U:%G' "$(command -v "$tool")" 2>/dev/null || echo "N/A")
        echo "  $tool: $PERMS"
    fi
done

echo ""
echo "Completado: $(date)"
} 2>&1 | tee "$REPORT"
EOFPTRACE
    chmod +x /usr/local/bin/securizar-mem-ptrace.sh

    log_change "Restricción ptrace aplicada"
    log_change "Aplicado" "Sección 8: ptrace_scope=2, core_pattern seguro, suid_dumpable=0"
}

# ── Sección 9: Coredump sanitization ──
section_9() {
    log_section "9. Coredump sanitization"

    if check_executable /usr/local/bin/securizar-mem-coredump.sh; then
        log_already "Coredump sanitization (securizar-mem-coredump.sh existe)"; return 0
    fi
    ask "¿Deshabilitar coredumps para prevenir filtración de datos sensibles?" || { log_skip "Coredump sanitization omitida"; return 0; }

    mkdir -p /var/log/securizar/mem-hardening

    # Deshabilitar coredumps via limits.conf
    local LIMITS_FILE="/etc/security/limits.d/99-securizar-coredump.conf"
    backup_if_exists "$LIMITS_FILE"

    cat > "$LIMITS_FILE" << 'EOF'
# Securizar — Deshabilitar coredumps
* hard core 0
* soft core 0
EOF

    # Configurar systemd-coredump si existe
    local COREDUMP_CONF="/etc/systemd/coredump.conf.d"
    mkdir -p "$COREDUMP_CONF"

    cat > "$COREDUMP_CONF/securizar.conf" << 'EOF'
[Coredump]
# Securizar — Deshabilitar almacenamiento de coredumps
Storage=none
ProcessSizeMax=0
EOF

    systemctl daemon-reload 2>/dev/null || true

    cat > /usr/local/bin/securizar-mem-coredump.sh << 'EOFCOREDUMP'
#!/bin/bash
# ============================================================
# securizar-mem-coredump.sh — Verificar coredump sanitization
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar/mem-hardening"
mkdir -p "$LOG_DIR"
REPORT="$LOG_DIR/coredump-$(date +%Y%m%d).txt"

{
echo "=========================================="
echo " Coredump Sanitization"
echo " $(date) - $(hostname)"
echo "=========================================="
echo ""

echo "=== Limits ==="
HARD_CORE=$(ulimit -Hc 2>/dev/null || echo "N/A")
SOFT_CORE=$(ulimit -Sc 2>/dev/null || echo "N/A")
echo "  ulimit hard core: $HARD_CORE"
echo "  ulimit soft core: $SOFT_CORE"
if [[ "$HARD_CORE" == "0" ]]; then
    echo "  [OK] Coredumps deshabilitados (hard limit)"
else
    echo "  [!!] Coredumps permitidos (hard limit = $HARD_CORE)"
fi

echo ""
echo "=== limits.d ==="
if [[ -f /etc/security/limits.d/99-securizar-coredump.conf ]]; then
    echo "  [OK] /etc/security/limits.d/99-securizar-coredump.conf presente"
else
    echo "  [!!] Configuración limits.d no encontrada"
fi

echo ""
echo "=== systemd-coredump ==="
if [[ -f /etc/systemd/coredump.conf.d/securizar.conf ]]; then
    echo "  [OK] systemd-coredump: Storage=none configurado"
    grep -v '^#' /etc/systemd/coredump.conf.d/securizar.conf | grep -v '^$'
else
    echo "  [INFO] No hay configuración securizar de coredump"
fi

echo ""
echo "=== sysctl ==="
SUID_DUMP=$(sysctl -n fs.suid_dumpable 2>/dev/null || echo "N/A")
CORE_PATTERN=$(sysctl -n kernel.core_pattern 2>/dev/null || echo "N/A")
echo "  fs.suid_dumpable = $SUID_DUMP"
echo "  kernel.core_pattern = $CORE_PATTERN"

echo ""
echo "=== Coredumps existentes ==="
CORE_FILES=$(find /var/lib/systemd/coredump/ -name "core.*" 2>/dev/null | wc -l || echo "0")
echo "  Archivos coredump en systemd: $CORE_FILES"
if [[ $CORE_FILES -gt 0 ]]; then
    echo "  [!!] Hay coredumps almacenados — considerar limpiar"
    echo "  Limpiar: coredumpctl remove"
fi

echo ""
echo "Completado: $(date)"
} 2>&1 | tee "$REPORT"
EOFCOREDUMP
    chmod +x /usr/local/bin/securizar-mem-coredump.sh

    log_change "Coredump sanitization aplicada"
    log_change "Aplicado" "Sección 9: ulimit core=0, systemd Storage=none, ProcessSizeMax=0"
}

# ── Sección 10: Monitorización integridad procesos ──
section_10() {
    log_section "10. Monitorización integridad procesos"

    if check_executable /usr/local/bin/auditoria-mem-procesos.sh; then
        log_already "Auditoría procesos (auditoria-mem-procesos.sh existe)"; return 0
    fi
    ask "¿Instalar auditoría integral de integridad de procesos?" || { log_skip "Auditoría procesos omitida"; return 0; }

    mkdir -p /var/log/securizar/mem-hardening

    cat > /usr/local/bin/auditoria-mem-procesos.sh << 'EOFAUDIT'
#!/bin/bash
# ============================================================
# auditoria-mem-procesos.sh — Auditoría integral memoria/procesos
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar/mem-hardening"
mkdir -p "$LOG_DIR"
REPORT="$LOG_DIR/auditoria-procesos-$(date +%Y%m%d).txt"

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
echo " Auditoría de Memoria y Procesos"
echo " $(date) - $(hostname)"
echo "=========================================="
echo ""

echo "=== 1. Memory Allocator ==="
check_item "ASLR = 2 (máximo)" 3 "test $(sysctl -n kernel.randomize_va_space) -eq 2"
check_item "mmap_min_addr >= 65536" 2 "test $(sysctl -n vm.mmap_min_addr) -ge 65536"
check_item "Config memoria securizar" 1 "test -f /etc/securizar/mem-hardening/config.conf"

echo ""
echo "=== 2. Stack Protection ==="
check_item "Verificador de stack instalado" 1 "test -x /usr/local/bin/securizar-mem-stack.sh"

echo ""
echo "=== 3. User Namespaces ==="
check_item "unprivileged_userns_clone = 0" 2 "test $(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo 1) -eq 0"

echo ""
echo "=== 4. Cgroups v2 ==="
check_item "Cgroups v2 activo" 2 "test -f /sys/fs/cgroup/cgroup.controllers"
check_item "Verificador cgroups instalado" 1 "test -x /usr/local/bin/securizar-mem-cgroups.sh"

echo ""
echo "=== 5. Seccomp ==="
check_item "Generador seccomp instalado" 1 "test -x /usr/local/bin/securizar-mem-seccomp.sh"

echo ""
echo "=== 6. ASLR/PIE ==="
check_item "Verificador ASLR/PIE instalado" 1 "test -x /usr/local/bin/securizar-mem-aslr.sh"

echo ""
echo "=== 7. W^X ==="
check_item "Verificador W^X instalado" 1 "test -x /usr/local/bin/securizar-mem-wxstrict.sh"
check_item "/tmp noexec" 2 "findmnt -n -o OPTIONS /tmp 2>/dev/null | grep -q noexec"
check_item "/dev/shm noexec" 2 "findmnt -n -o OPTIONS /dev/shm 2>/dev/null | grep -q noexec"

echo ""
echo "=== 8. Ptrace ==="
check_item "ptrace_scope >= 2" 3 "test $(sysctl -n kernel.yama.ptrace_scope 2>/dev/null || echo 0) -ge 2"
check_item "suid_dumpable = 0" 2 "test $(sysctl -n fs.suid_dumpable) -eq 0"

echo ""
echo "=== 9. Coredumps ==="
check_item "Coredumps deshabilitados (limits)" 2 "test -f /etc/security/limits.d/99-securizar-coredump.conf"
check_item "systemd-coredump Storage=none" 2 "test -f /etc/systemd/coredump.conf.d/securizar.conf"

echo ""
echo "=== 10. Anomalías en procesos ==="
# Detectar binarios sin PIE en paths del sistema
NO_PIE=$(find /usr/sbin -maxdepth 1 -type f -executable 2>/dev/null | head -20 | while read -r bin; do
    if file "$bin" 2>/dev/null | grep -q "ELF" && readelf -h "$bin" 2>/dev/null | grep -q "EXEC"; then
        echo "1"
    fi
done | wc -l)
if [[ $NO_PIE -eq 0 ]]; then
    echo "  [✓] Sin binarios NO-PIE en /usr/sbin (sample) (+1)"
    ((SCORE++)); ((MAX_SCORE++)); ((CHECKS_PASS++))
else
    echo "  [✗] $NO_PIE binarios NO-PIE detectados en /usr/sbin (0/1)"
    ((MAX_SCORE++)); ((CHECKS_FAIL++))
fi

# Detectar procesos setuid inesperados
SUID_UNEXPECTED=$(find /usr/local -type f -perm -4000 2>/dev/null | wc -l)
if [[ $SUID_UNEXPECTED -eq 0 ]]; then
    echo "  [✓] Sin binarios SUID en /usr/local (+1)"
    ((SCORE++)); ((MAX_SCORE++)); ((CHECKS_PASS++))
else
    echo "  [✗] $SUID_UNEXPECTED binarios SUID en /usr/local (0/1)"
    ((MAX_SCORE++)); ((CHECKS_FAIL++))
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
    echo " Calificación: ██████████ EXCELENTE"
    echo " La protección de memoria y procesos es robusta."
elif [[ $PCT -ge 60 ]]; then
    echo " Calificación: ███████░░░ BUENO"
    echo " Buena base de protección con áreas de mejora."
elif [[ $PCT -ge 40 ]]; then
    echo " Calificación: █████░░░░░ MEJORABLE"
    echo " Múltiples protecciones ausentes."
else
    echo " Calificación: ███░░░░░░░ DEFICIENTE"
    echo " Protección de memoria y procesos insuficiente."
fi

echo ""
echo " Auditado: $(date)"
echo "=========================================="
} 2>&1 | tee "$REPORT"

echo "Reporte: $REPORT"
EOFAUDIT
    chmod +x /usr/local/bin/auditoria-mem-procesos.sh

    # Cron semanal
    cat > /etc/cron.weekly/securizar-mem-audit << 'EOF'
#!/bin/bash
/usr/local/bin/auditoria-mem-procesos.sh >> /var/log/securizar/mem-hardening/audit-cron.log 2>&1
EOF
    chmod +x /etc/cron.weekly/securizar-mem-audit

    log_change "Auditoría integral de memoria y procesos instalada"
    log_change "Aplicado" "Sección 10: Scoring ASLR, W^X, ptrace, coredumps, PIE, SUID"
}

# ── Main ──
main() {
    log_section "MÓDULO 67: HARDENING DE MEMORIA Y PROCESOS"

    # ── Pre-check: detectar secciones ya aplicadas ──────────────
    _precheck 10
    _pc 'test -f /etc/securizar/mem-hardening/config.conf'
    _pc 'check_executable /usr/local/bin/securizar-mem-stack.sh'
    _pc 'check_executable /usr/local/bin/securizar-mem-userns.sh'
    _pc 'check_executable /usr/local/bin/securizar-mem-cgroups.sh'
    _pc 'check_executable /usr/local/bin/securizar-mem-seccomp.sh'
    _pc 'check_executable /usr/local/bin/securizar-mem-aslr.sh'
    _pc 'check_executable /usr/local/bin/securizar-mem-wxstrict.sh'
    _pc 'check_executable /usr/local/bin/securizar-mem-ptrace.sh'
    _pc 'check_executable /usr/local/bin/securizar-mem-coredump.sh'
    _pc 'check_executable /usr/local/bin/auditoria-mem-procesos.sh'
    _precheck_result

    for i in $(seq 1 10); do
        "section_$i"
    done
    echo ""
    show_changes_summary
}
main "$@"
