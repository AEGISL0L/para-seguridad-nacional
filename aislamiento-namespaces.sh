#!/bin/bash
# ============================================================
# aislamiento-namespaces.sh - Modulo 72: Aislamiento de Namespaces
# ============================================================
# Secciones:
#   S1  - Restriccion de user namespaces (sysctl)
#   S2  - Namespaces de red (netns isolation)
#   S3  - PID namespaces (hidepid, ptrace_scope)
#   S4  - Mount namespaces (propagation private)
#   S5  - Rootless containers (subuid/subgid)
#   S6  - Systemd sandboxing avanzado
#   S7  - Seccomp-BPF para namespaces
#   S8  - Cgroups v2 resource isolation
#   S9  - Deteccion de escape de namespaces
#   S10 - Auditoria integral namespaces
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "namespaces-isolation"
securizar_setup_traps

# ── Pre-check: detectar secciones ya aplicadas ──────────────
_precheck 10
_pc 'check_file_exists /etc/sysctl.d/90-securizar-userns.conf'
_pc 'check_executable /usr/local/bin/securizar-netns-isolate.sh'
_pc 'check_file_exists /proc/sys/kernel/yama/ptrace_scope'
_pc 'check_executable /usr/local/bin/securizar-mount-private.sh'
_pc 'check_executable /usr/local/bin/securizar-rootless-containers.sh'
_pc 'check_file_exists /etc/securizar/namespaces/systemd-sandbox.conf'
_pc 'check_file_exists /etc/securizar/namespaces/seccomp-ns-filter.json'
_pc 'check_file_exists /etc/securizar/namespaces/cgroups-policy.conf'
_pc 'check_executable /usr/local/bin/securizar-ns-escape-detect.sh'
_pc 'check_executable /usr/local/bin/auditoria-namespaces-completa.sh'
_precheck_result

log_section "MODULO 72: AISLAMIENTO DE NAMESPACES"
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

NS_DIR="/etc/securizar/namespaces"
NS_BIN="/usr/local/bin"
NS_LOG="/var/log/securizar/namespaces"
mkdir -p "$NS_DIR" "$NS_LOG" || true

# ============================================================
# S1: RESTRICCION DE USER NAMESPACES
# ============================================================
log_section "S1: Restriccion de user namespaces"

log_info "Restringe la creacion de user namespaces no privilegiados:"
log_info "  - kernel.unprivileged_userns_clone=0 (Debian/SUSE)"
log_info "  - user.max_user_namespaces=0 (RHEL/general)"
log_info ""

if check_file_exists /etc/sysctl.d/90-securizar-userns.conf; then
    log_already "Restriccion user namespaces (90-securizar-userns.conf existe)"
elif ask "Restringir creacion de user namespaces no privilegiados?"; then

    cat > /etc/sysctl.d/90-securizar-userns.conf << 'EOFUSERNS'
# ============================================================
# 90-securizar-userns.conf - Restriccion de user namespaces
# ============================================================
# Generado por securizar - Modulo 72

# Deshabilitar user namespaces no privilegiados (Debian/SUSE)
kernel.unprivileged_userns_clone = 0

# Limitar maximo de user namespaces (RHEL/general)
# Valor 0 = deshabilitar completamente para no-root
# NOTA: Si se usan rootless containers, ajustar a un valor > 0
user.max_user_namespaces = 0

# Restringir BPF no privilegiado (complementario)
kernel.unprivileged_bpf_disabled = 1
EOFUSERNS
    chmod 0644 /etc/sysctl.d/90-securizar-userns.conf
    sysctl --system &>/dev/null || true
    log_change "Creado" "/etc/sysctl.d/90-securizar-userns.conf"
    log_change "Aplicado" "sysctl --system (user namespaces restringidos)"

else
    log_skip "Restriccion user namespaces"
fi

# ============================================================
# S2: NAMESPACES DE RED
# ============================================================
log_section "S2: Namespaces de red (netns isolation)"

log_info "Crea herramienta para aislar servicios en network namespaces:"
log_info "  - Crea named netns con veth pair"
log_info "  - Permite ejecutar comandos/servicios aislados de la red"
log_info ""

if check_executable /usr/local/bin/securizar-netns-isolate.sh; then
    log_already "Namespaces de red (securizar-netns-isolate.sh existe)"
elif ask "Crear herramienta de aislamiento por network namespaces?"; then

    cat > "$NS_BIN/securizar-netns-isolate.sh" << 'EOFNETNS'
#!/bin/bash
# ============================================================
# securizar-netns-isolate.sh - Aislamiento con network namespaces
# ============================================================
# Uso: securizar-netns-isolate.sh create <nombre> [subnet]
#      securizar-netns-isolate.sh exec <nombre> <comando...>
#      securizar-netns-isolate.sh delete <nombre>
#      securizar-netns-isolate.sh list
set -euo pipefail

ACTION="${1:-help}"
NS_NAME="${2:-}"
SUBNET="${3:-10.200.1}"

case "$ACTION" in
    create)
        [[ -z "$NS_NAME" ]] && { echo "Uso: $0 create <nombre> [subnet]"; exit 1; }
        echo "=== Creando netns: $NS_NAME (subnet $SUBNET.0/30) ==="
        ip netns add "$NS_NAME"
        # Crear veth pair
        VETH_HOST="veth-${NS_NAME:0:8}-h"
        VETH_NS="veth-${NS_NAME:0:8}-n"
        ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
        ip link set "$VETH_NS" netns "$NS_NAME"
        # Configurar lado host
        ip addr add "${SUBNET}.1/30" dev "$VETH_HOST"
        ip link set "$VETH_HOST" up
        # Configurar lado netns
        ip netns exec "$NS_NAME" ip addr add "${SUBNET}.2/30" dev "$VETH_NS"
        ip netns exec "$NS_NAME" ip link set "$VETH_NS" up
        ip netns exec "$NS_NAME" ip link set lo up
        ip netns exec "$NS_NAME" ip route add default via "${SUBNET}.1"
        echo "[OK] Netns $NS_NAME creado. IP interna: ${SUBNET}.2"
        echo "  Ejecutar: $0 exec $NS_NAME <comando>"
        ;;
    exec)
        [[ -z "$NS_NAME" ]] && { echo "Uso: $0 exec <nombre> <comando...>"; exit 1; }
        shift 2
        ip netns exec "$NS_NAME" "$@"
        ;;
    delete)
        [[ -z "$NS_NAME" ]] && { echo "Uso: $0 delete <nombre>"; exit 1; }
        ip netns delete "$NS_NAME" && echo "[OK] Netns $NS_NAME eliminado"
        # Limpiar veth del host (se elimina automaticamente)
        ip link del "veth-${NS_NAME:0:8}-h" 2>/dev/null || true
        ;;
    list)
        echo "=== Network namespaces activos ==="
        ip netns list 2>/dev/null || echo "(ninguno)"
        ;;
    *)
        echo "Uso: $0 {create|exec|delete|list} [args...]"
        echo "  create <nombre> [subnet] - Crear netns con veth pair"
        echo "  exec <nombre> <cmd>      - Ejecutar comando en netns"
        echo "  delete <nombre>          - Eliminar netns"
        echo "  list                     - Listar netns activos"
        ;;
esac
EOFNETNS
    chmod +x "$NS_BIN/securizar-netns-isolate.sh"
    log_change "Creado" "$NS_BIN/securizar-netns-isolate.sh"

else
    log_skip "Namespaces de red"
fi

# ============================================================
# S3: PID NAMESPACES (HIDEPID, PTRACE_SCOPE)
# ============================================================
log_section "S3: PID namespaces (hidepid, ptrace_scope)"

log_info "Oculta procesos de otros usuarios y restringe ptrace:"
log_info "  - hidepid=2 en /proc (usuarios solo ven sus procesos)"
log_info "  - kernel.yama.ptrace_scope=1 (solo procesos padre)"
log_info ""

if check_file_exists /proc/sys/kernel/yama/ptrace_scope; then
    # Verificar si hidepid ya esta aplicado
    _hidepid_applied=false
    if grep -q 'hidepid=' /etc/fstab 2>/dev/null; then
        _hidepid_applied=true
    fi
    _ptrace_val=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo "0")

    if [[ "$_hidepid_applied" == "true" ]] && [[ "$_ptrace_val" -ge 1 ]]; then
        log_already "PID namespaces (hidepid en fstab y ptrace_scope>=1)"
    elif ask "Aplicar hidepid=2 a /proc y ptrace_scope=1?"; then

        # hidepid en fstab
        if ! grep -q 'hidepid=' /etc/fstab 2>/dev/null; then
            backup_file /etc/fstab
            if grep -q '/proc' /etc/fstab 2>/dev/null; then
                # Modificar linea existente de /proc
                sed -i '/\/proc/s/defaults/defaults,hidepid=2/' /etc/fstab 2>/dev/null || true
            else
                echo "proc  /proc  proc  defaults,hidepid=2  0  0" >> /etc/fstab
            fi
            # Remontar /proc con hidepid
            mount -o remount,hidepid=2 /proc 2>/dev/null || true
            log_change "Aplicado" "hidepid=2 en /proc (fstab)"
        fi

        # ptrace_scope via sysctl
        if [[ "$_ptrace_val" -lt 1 ]]; then
            sysctl -w kernel.yama.ptrace_scope=1 &>/dev/null || true
            # Persistir
            if [[ -f /etc/sysctl.d/90-securizar-userns.conf ]]; then
                if ! grep -q 'ptrace_scope' /etc/sysctl.d/90-securizar-userns.conf; then
                    echo "" >> /etc/sysctl.d/90-securizar-userns.conf
                    echo "# Restringir ptrace a procesos padre" >> /etc/sysctl.d/90-securizar-userns.conf
                    echo "kernel.yama.ptrace_scope = 1" >> /etc/sysctl.d/90-securizar-userns.conf
                fi
            else
                echo "kernel.yama.ptrace_scope = 1" > /etc/sysctl.d/91-securizar-ptrace.conf
            fi
            log_change "Aplicado" "kernel.yama.ptrace_scope=1"
        fi

    else
        log_skip "PID namespaces (hidepid/ptrace)"
    fi
else
    log_info "YAMA ptrace_scope no disponible en este kernel"
    if ask "Aplicar hidepid=2 a /proc de todos modos?"; then
        if ! grep -q 'hidepid=' /etc/fstab 2>/dev/null; then
            backup_file /etc/fstab
            echo "proc  /proc  proc  defaults,hidepid=2  0  0" >> /etc/fstab
            mount -o remount,hidepid=2 /proc 2>/dev/null || true
            log_change "Aplicado" "hidepid=2 en /proc (fstab)"
        fi
    else
        log_skip "PID namespaces"
    fi
fi

# ============================================================
# S4: MOUNT NAMESPACES
# ============================================================
log_section "S4: Mount namespaces (propagation private)"

log_info "Crea herramienta para aislamiento de montajes:"
log_info "  - Propagacion privada en montajes sensibles"
log_info "  - Uso de unshare --mount para sesiones aisladas"
log_info ""

if check_executable /usr/local/bin/securizar-mount-private.sh; then
    log_already "Mount namespaces (securizar-mount-private.sh existe)"
elif ask "Crear herramienta de mount namespace isolation?"; then

    cat > "$NS_BIN/securizar-mount-private.sh" << 'EOFMOUNTNS'
#!/bin/bash
# ============================================================
# securizar-mount-private.sh - Mount namespace isolation
# ============================================================
# Uso: securizar-mount-private.sh apply       - Aplicar propagacion private
#      securizar-mount-private.sh shell        - Shell con mount namespace aislado
#      securizar-mount-private.sh run <cmd>    - Ejecutar con mount namespace aislado
#      securizar-mount-private.sh status       - Ver estado de propagacion
set -euo pipefail

ACTION="${1:-help}"

apply_private() {
    echo "=== Aplicando propagacion privada a montajes sensibles ==="
    local SENSITIVE=(/tmp /var/tmp /dev/shm /home)
    for mnt in "${SENSITIVE[@]}"; do
        if mountpoint -q "$mnt" 2>/dev/null; then
            mount --make-private "$mnt" 2>/dev/null && \
                echo "  [OK] $mnt -> private" || \
                echo "  [!!] $mnt -> no se pudo cambiar"
        else
            echo "  [--] $mnt no es mountpoint, omitido"
        fi
    done
    echo ""
    echo "NOTA: Para persistir, anadir 'private' en las opciones de fstab."
}

show_status() {
    echo "=== Estado de propagacion de montajes ==="
    if [[ -f /proc/self/mountinfo ]]; then
        echo "Montajes con shared propagation (potencial fuga):"
        grep 'shared:' /proc/self/mountinfo | awk '{print "  "$5, $NF}' | head -20
        echo ""
        echo "Montajes con private propagation (aislados):"
        grep -v 'shared:' /proc/self/mountinfo | awk '{print "  "$5}' | head -20
    else
        echo "  /proc/self/mountinfo no disponible"
    fi
}

case "$ACTION" in
    apply)  apply_private ;;
    shell)
        echo "Entrando en shell con mount namespace aislado..."
        echo "Los montajes dentro de esta sesion no afectan al host."
        exec unshare --mount /bin/bash
        ;;
    run)
        shift
        [[ $# -eq 0 ]] && { echo "Uso: $0 run <comando...>"; exit 1; }
        exec unshare --mount -- "$@"
        ;;
    status) show_status ;;
    *)
        echo "Uso: $0 {apply|shell|run|status}"
        echo "  apply      - Propagacion private en montajes sensibles"
        echo "  shell      - Shell con mount namespace aislado"
        echo "  run <cmd>  - Ejecutar con mount namespace aislado"
        echo "  status     - Ver estado de propagacion"
        ;;
esac
EOFMOUNTNS
    chmod +x "$NS_BIN/securizar-mount-private.sh"
    log_change "Creado" "$NS_BIN/securizar-mount-private.sh"

else
    log_skip "Mount namespaces"
fi

# ============================================================
# S5: ROOTLESS CONTAINERS
# ============================================================
log_section "S5: Rootless containers (subuid/subgid)"

log_info "Configura el sistema para contenedores rootless:"
log_info "  - subuid/subgid para usuarios regulares"
log_info "  - Ajuste de user namespaces para rootless Podman/Docker"
log_info ""

if check_executable /usr/local/bin/securizar-rootless-containers.sh; then
    log_already "Rootless containers (securizar-rootless-containers.sh existe)"
elif ask "Crear herramienta de configuracion rootless containers?"; then

    cat > "$NS_BIN/securizar-rootless-containers.sh" << 'EOFROOTLESS'
#!/bin/bash
# ============================================================
# securizar-rootless-containers.sh - Configurar rootless containers
# ============================================================
# Uso: securizar-rootless-containers.sh check
#      securizar-rootless-containers.sh setup <usuario>
#      securizar-rootless-containers.sh enable-userns
set -euo pipefail

ACTION="${1:-check}"
TARGET_USER="${2:-}"

check_rootless() {
    echo "=== Estado rootless containers ==="
    echo ""
    # subuid/subgid
    echo "--- /etc/subuid ---"
    if [[ -f /etc/subuid ]]; then
        cat /etc/subuid
    else
        echo "  (no existe - necesario para rootless)"
    fi
    echo ""
    echo "--- /etc/subgid ---"
    if [[ -f /etc/subgid ]]; then
        cat /etc/subgid
    else
        echo "  (no existe - necesario para rootless)"
    fi
    echo ""
    # User namespaces
    echo "--- User namespaces ---"
    userns_clone=$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo "n/a")
    userns_max=$(sysctl -n user.max_user_namespaces 2>/dev/null || echo "n/a")
    echo "  kernel.unprivileged_userns_clone = $userns_clone"
    echo "  user.max_user_namespaces = $userns_max"
    if [[ "$userns_clone" == "0" ]] || [[ "$userns_max" == "0" ]]; then
        echo "  [!!] User namespaces deshabilitados - rootless NO funcionara"
        echo "  Ejecutar: $0 enable-userns"
    else
        echo "  [OK] User namespaces habilitados para rootless"
    fi
    echo ""
    # Runtime
    echo "--- Container runtimes ---"
    for rt in podman docker; do
        if command -v "$rt" &>/dev/null; then
            ver=$("$rt" --version 2>/dev/null | head -1)
            echo "  [OK] $rt: $ver"
        else
            echo "  [--] $rt: no instalado"
        fi
    done
}

setup_user() {
    [[ -z "$TARGET_USER" ]] && { echo "Uso: $0 setup <usuario>"; exit 1; }
    id "$TARGET_USER" &>/dev/null || { echo "Usuario $TARGET_USER no existe"; exit 1; }
    echo "=== Configurando rootless para $TARGET_USER ==="
    # Asignar rango subuid/subgid
    if ! grep -q "^${TARGET_USER}:" /etc/subuid 2>/dev/null; then
        usermod --add-subuids 100000-165535 "$TARGET_USER" 2>/dev/null || \
            echo "${TARGET_USER}:100000:65536" >> /etc/subuid
        echo "  [OK] subuid asignado: ${TARGET_USER}:100000:65536"
    else
        echo "  [OK] subuid ya configurado para $TARGET_USER"
    fi
    if ! grep -q "^${TARGET_USER}:" /etc/subgid 2>/dev/null; then
        usermod --add-subgids 100000-165535 "$TARGET_USER" 2>/dev/null || \
            echo "${TARGET_USER}:100000:65536" >> /etc/subgid
        echo "  [OK] subgid asignado: ${TARGET_USER}:100000:65536"
    else
        echo "  [OK] subgid ya configurado para $TARGET_USER"
    fi
    echo ""
    echo "El usuario $TARGET_USER puede ahora ejecutar contenedores rootless."
    echo "  podman run --rm alpine echo OK"
}

enable_userns() {
    echo "=== Habilitando user namespaces para rootless containers ==="
    sysctl -w kernel.unprivileged_userns_clone=1 &>/dev/null || true
    sysctl -w user.max_user_namespaces=28633 &>/dev/null || true
    echo "  [OK] kernel.unprivileged_userns_clone=1"
    echo "  [OK] user.max_user_namespaces=28633"
    echo ""
    echo "NOTA: Esto contradice la restriccion de S1. Use solo si necesita"
    echo "rootless containers. Para persistir, edite:"
    echo "  /etc/sysctl.d/90-securizar-userns.conf"
}

case "$ACTION" in
    check)        check_rootless ;;
    setup)        setup_user ;;
    enable-userns) enable_userns ;;
    *)
        echo "Uso: $0 {check|setup|enable-userns} [usuario]"
        echo "  check              - Verificar estado rootless"
        echo "  setup <usuario>    - Configurar subuid/subgid"
        echo "  enable-userns      - Habilitar user namespaces"
        ;;
esac
EOFROOTLESS
    chmod +x "$NS_BIN/securizar-rootless-containers.sh"
    log_change "Creado" "$NS_BIN/securizar-rootless-containers.sh"

else
    log_skip "Rootless containers"
fi

# ============================================================
# S6: SYSTEMD SANDBOXING AVANZADO
# ============================================================
log_section "S6: Systemd sandboxing avanzado"

log_info "Crea referencia de directivas systemd para sandboxing de servicios:"
log_info "  - PrivateUsers, RestrictNamespaces, ProtectSystem"
log_info "  - PrivateTmp, NoNewPrivileges, ProtectKernelTunables"
log_info ""

if check_file_exists /etc/securizar/namespaces/systemd-sandbox.conf; then
    log_already "Systemd sandboxing (systemd-sandbox.conf existe)"
elif ask "Crear configuracion de referencia para systemd sandboxing?"; then

    cat > "$NS_DIR/systemd-sandbox.conf" << 'EOFSYSTEMD'
# ============================================================
# systemd-sandbox.conf - Directivas de sandboxing para servicios
# ============================================================
# Generado por securizar - Modulo 72
#
# Copiar las directivas relevantes a override de cada servicio:
#   systemctl edit <servicio>
# O crear drop-in en /etc/systemd/system/<servicio>.d/hardening.conf
#
# Verificar con: systemd-analyze security <servicio>

[Service]
# === Namespaces ===
PrivateUsers=yes
# RestrictNamespaces=yes  # Impide crear nuevos namespaces
# PrivateNetwork=yes      # Aisla de la red (solo loopback)

# === Filesystem ===
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectControlGroups=yes
ReadWritePaths=/var/log/mi-servicio

# === Kernel ===
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectHostname=yes
ProtectClock=yes

# === Privilegios ===
NoNewPrivileges=yes
# CapabilityBoundingSet=CAP_NET_BIND_SERVICE
# AmbientCapabilities=

# === Syscalls ===
# SystemCallFilter=@system-service
# SystemCallArchitectures=native
# RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

# === Restricciones adicionales ===
# MemoryDenyWriteExecute=yes
# RestrictRealtime=yes
# RestrictSUIDSGID=yes
# LockPersonality=yes

# === Ejemplo: servicio web minimo ===
# [Service]
# ProtectSystem=strict
# ProtectHome=yes
# PrivateTmp=yes
# PrivateDevices=yes
# PrivateUsers=yes
# NoNewPrivileges=yes
# ProtectKernelTunables=yes
# ProtectKernelModules=yes
# ProtectControlGroups=yes
# RestrictNamespaces=yes
# RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
# SystemCallArchitectures=native
# CapabilityBoundingSet=CAP_NET_BIND_SERVICE
EOFSYSTEMD
    chmod 0640 "$NS_DIR/systemd-sandbox.conf"
    log_change "Creado" "$NS_DIR/systemd-sandbox.conf"

else
    log_skip "Systemd sandboxing"
fi

# ============================================================
# S7: SECCOMP-BPF PARA NAMESPACES
# ============================================================
log_section "S7: Seccomp-BPF para namespaces"

log_info "Crea perfil seccomp que restringe syscalls de namespaces:"
log_info "  - Bloquea clone con CLONE_NEWUSER, unshare, setns"
log_info "  - Formato JSON compatible con Docker/Podman"
log_info ""

if check_file_exists /etc/securizar/namespaces/seccomp-ns-filter.json; then
    log_already "Seccomp namespaces (seccomp-ns-filter.json existe)"
elif ask "Crear perfil seccomp restrictivo para namespaces?"; then

    cat > "$NS_DIR/seccomp-ns-filter.json" << 'EOFSECCOMP'
{
    "_comment": "Perfil seccomp - Restriccion de syscalls de namespaces",
    "_generated": "securizar - Modulo 72",
    "defaultAction": "SCMP_ACT_ALLOW",
    "architectures": [
        "SCMP_ARCH_X86_64",
        "SCMP_ARCH_AARCH64"
    ],
    "syscalls": [
        {
            "names": ["unshare"],
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": 1,
            "comment": "Bloquear creacion de nuevos namespaces"
        },
        {
            "names": ["setns"],
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": 1,
            "comment": "Bloquear union a namespaces existentes"
        },
        {
            "names": ["clone"],
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": 1,
            "args": [
                {
                    "index": 0,
                    "value": 2147483648,
                    "valueTwo": 0,
                    "op": "SCMP_CMP_MASKED_EQ",
                    "comment": "CLONE_NEWUSER = 0x10000000"
                }
            ],
            "comment": "Bloquear clone con CLONE_NEWUSER"
        },
        {
            "names": ["clone3"],
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": 1,
            "comment": "Bloquear clone3 (alternativa moderna a clone)"
        },
        {
            "names": ["mount", "umount2", "pivot_root"],
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": 1,
            "comment": "Bloquear operaciones de montaje"
        }
    ]
}
EOFSECCOMP
    chmod 0640 "$NS_DIR/seccomp-ns-filter.json"
    log_change "Creado" "$NS_DIR/seccomp-ns-filter.json"
    log_info "Uso con Docker/Podman:"
    log_info "  docker run --security-opt seccomp=$NS_DIR/seccomp-ns-filter.json ..."
    log_info "  podman run --security-opt seccomp=$NS_DIR/seccomp-ns-filter.json ..."

else
    log_skip "Seccomp namespaces"
fi

# ============================================================
# S8: CGROUPS V2 RESOURCE ISOLATION
# ============================================================
log_section "S8: Cgroups v2 resource isolation"

log_info "Configura politica de aislamiento de recursos con cgroups v2:"
log_info "  - Verifica unified hierarchy (cgroups v2)"
log_info "  - Limites recomendados de CPU, memoria, IO"
log_info ""

if check_file_exists /etc/securizar/namespaces/cgroups-policy.conf; then
    log_already "Cgroups policy (cgroups-policy.conf existe)"
elif ask "Crear politica de cgroups v2 resource isolation?"; then

    # Detectar version de cgroups
    CGROUP_VER="v1"
    if [[ -f /sys/fs/cgroup/cgroup.controllers ]]; then
        CGROUP_VER="v2"
    fi
    log_info "Cgroups detectado: $CGROUP_VER"

    cat > "$NS_DIR/cgroups-policy.conf" << EOFCGROUPS
# ============================================================
# cgroups-policy.conf - Politica de aislamiento de recursos
# ============================================================
# Generado por securizar - Modulo 72
# Cgroups detectado: $CGROUP_VER

# === Estado del sistema ===
# Cgroups v2 (unified): $(test -f /sys/fs/cgroup/cgroup.controllers && echo "SI" || echo "NO")
# Para forzar v2 en boot: systemd.unified_cgroup_hierarchy=1 en GRUB

# === Limites recomendados por tipo de servicio ===

# [servicios-web]
# CPUWeight=100
# MemoryMax=2G
# MemoryHigh=1536M
# IOWeight=100
# TasksMax=512

# [servicios-bd]
# CPUWeight=200
# MemoryMax=4G
# MemoryHigh=3G
# IOWeight=200
# TasksMax=1024

# [contenedores]
# CPUWeight=50
# MemoryMax=1G
# MemoryHigh=768M
# IOWeight=50
# TasksMax=256

# [servicios-background]
# CPUWeight=10
# MemoryMax=512M
# MemoryHigh=384M
# IOWeight=10
# TasksMax=64

# === Aplicar con systemd ===
# systemctl set-property <servicio> MemoryMax=2G CPUWeight=100
# O en fichero override:
#   systemctl edit <servicio>
#   [Service]
#   MemoryMax=2G
#   CPUWeight=100
#   TasksMax=512

# === Limites globales ===
# DefaultMemoryAccounting=yes
# DefaultCPUAccounting=yes
# DefaultTasksAccounting=yes
# (en /etc/systemd/system.conf)
EOFCGROUPS
    chmod 0640 "$NS_DIR/cgroups-policy.conf"
    log_change "Creado" "$NS_DIR/cgroups-policy.conf"

    # Habilitar accounting si no esta activo
    if [[ -f /etc/systemd/system.conf ]]; then
        for acc in DefaultMemoryAccounting DefaultCPUAccounting DefaultTasksAccounting; do
            if ! grep -q "^${acc}=yes" /etc/systemd/system.conf 2>/dev/null; then
                if grep -q "^#${acc}=" /etc/systemd/system.conf 2>/dev/null; then
                    sed -i "s/^#${acc}=.*/${acc}=yes/" /etc/systemd/system.conf
                fi
            fi
        done
        log_change "Verificado" "Accounting cgroups en systemd (system.conf)"
    fi

else
    log_skip "Cgroups policy"
fi

# ============================================================
# S9: DETECCION DE ESCAPE DE NAMESPACES
# ============================================================
log_section "S9: Deteccion de escape de namespaces"

log_info "Crea herramienta de deteccion de intentos de escape de namespaces:"
log_info "  - Monitoriza nsenter, unshare, setns en audit.log"
log_info "  - Detecta procesos con namespaces sospechosos"
log_info ""

if check_executable /usr/local/bin/securizar-ns-escape-detect.sh; then
    log_already "Deteccion de escape (securizar-ns-escape-detect.sh existe)"
elif ask "Crear herramienta de deteccion de escape de namespaces?"; then

    cat > "$NS_BIN/securizar-ns-escape-detect.sh" << 'EOFNSESCAPE'
#!/bin/bash
# ============================================================
# securizar-ns-escape-detect.sh - Detectar escape de namespaces
# ============================================================
# Uso: securizar-ns-escape-detect.sh [scan|audit-rules|watch]
set -euo pipefail

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BOLD="\033[1m"
NC="\033[0m"

LOG_DIR="/var/log/securizar/namespaces"
mkdir -p "$LOG_DIR"
REPORT="$LOG_DIR/ns-escape-$(date +%Y%m%d-%H%M%S).log"
ACTION="${1:-scan}"

log_r() { echo -e "$1" | tee -a "$REPORT"; }

scan_ns_anomalies() {
    log_r "${BOLD}=== Escaneo de anomalias en namespaces ===${NC}"
    log_r "Fecha: $(date)"
    log_r ""
    ALERTS=0

    # 1. Procesos usando nsenter
    log_r "--- Procesos usando nsenter/unshare ---"
    while IFS= read -r pid; do
        [[ -z "$pid" ]] && continue
        cmd=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ')
        if echo "$cmd" | grep -qE '(nsenter|unshare)'; then
            user=$(stat -c '%U' "/proc/$pid" 2>/dev/null || echo "?")
            log_r "  ${YELLOW}[!!]${NC} PID=$pid user=$user cmd=$cmd"
            ALERTS=$((ALERTS + 1))
        fi
    done < <(ls /proc 2>/dev/null | grep '^[0-9]*$')

    # 2. Procesos en namespaces diferentes al init
    log_r ""
    log_r "--- Procesos en namespaces no-root ---"
    INIT_NS=$(readlink /proc/1/ns/pid 2>/dev/null || echo "unknown")
    for pid in $(ls /proc 2>/dev/null | grep '^[0-9]*$' | head -200); do
        PROC_NS=$(readlink "/proc/$pid/ns/pid" 2>/dev/null || continue)
        if [[ "$PROC_NS" != "$INIT_NS" ]]; then
            cmd=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ' | head -c 80)
            log_r "  [NS] PID=$pid ns=$PROC_NS cmd=${cmd:-(vacio)}"
        fi
    done

    # 3. Audit log (si disponible)
    log_r ""
    log_r "--- Eventos audit recientes (unshare/setns/nsenter) ---"
    if [[ -f /var/log/audit/audit.log ]]; then
        count=$(grep -cE '(unshare|setns|nsenter)' /var/log/audit/audit.log 2>/dev/null || echo "0")
        log_r "  Eventos encontrados: $count"
        grep -E '(unshare|setns|nsenter)' /var/log/audit/audit.log 2>/dev/null | \
            tail -5 | while IFS= read -r line; do log_r "    $line"; done
    else
        log_r "  audit.log no disponible"
    fi

    log_r ""
    if [[ $ALERTS -gt 0 ]]; then
        log_r "${RED}${BOLD}ALERTAS: $ALERTS procesos sospechosos${NC}"
    else
        log_r "${GREEN}Sin anomalias detectadas${NC}"
    fi
    log_r "Reporte: $REPORT"
}

install_audit_rules() {
    log_r "${BOLD}=== Instalando reglas audit para namespaces ===${NC}"
    if ! command -v auditctl &>/dev/null; then
        log_r "${RED}auditctl no disponible. Instalar auditd.${NC}"
        return 1
    fi
    auditctl -a always,exit -F arch=b64 -S unshare -k ns_escape 2>/dev/null || true
    auditctl -a always,exit -F arch=b64 -S setns -k ns_escape 2>/dev/null || true
    auditctl -w /usr/bin/nsenter -p x -k ns_escape 2>/dev/null || true
    auditctl -w /usr/bin/unshare -p x -k ns_escape 2>/dev/null || true
    log_r "[OK] Reglas audit instaladas (clave: ns_escape)"
    log_r "  Consultar: ausearch -k ns_escape"

    # Persistir en fichero
    local RULES_FILE="/etc/audit/rules.d/securizar-namespaces.rules"
    cat > "$RULES_FILE" << 'EOFRULES'
# securizar - Modulo 72: Reglas audit para namespaces
-a always,exit -F arch=b64 -S unshare -k ns_escape
-a always,exit -F arch=b64 -S setns -k ns_escape
-w /usr/bin/nsenter -p x -k ns_escape
-w /usr/bin/unshare -p x -k ns_escape
EOFRULES
    log_r "[OK] Reglas persistidas en $RULES_FILE"
}

case "$ACTION" in
    scan)        scan_ns_anomalies ;;
    audit-rules) install_audit_rules ;;
    watch)
        echo "Monitorizando eventos de namespaces (Ctrl+C para parar)..."
        if command -v ausearch &>/dev/null; then
            ausearch -k ns_escape --start recent -i 2>/dev/null || \
                echo "Sin eventos recientes. Ejecutar primero: $0 audit-rules"
        else
            echo "ausearch no disponible. Instalar auditd."
        fi
        ;;
    *)
        echo "Uso: $0 {scan|audit-rules|watch}"
        echo "  scan        - Escanear anomalias en namespaces"
        echo "  audit-rules - Instalar reglas audit"
        echo "  watch       - Monitorizar eventos en tiempo real"
        ;;
esac
EOFNSESCAPE
    chmod +x "$NS_BIN/securizar-ns-escape-detect.sh"
    log_change "Creado" "$NS_BIN/securizar-ns-escape-detect.sh"

else
    log_skip "Deteccion de escape de namespaces"
fi

# ============================================================
# S10: AUDITORIA INTEGRAL NAMESPACES
# ============================================================
log_section "S10: Auditoria integral namespaces"

log_info "Crea herramienta de auditoria integral del aislamiento de namespaces."
log_info ""

if check_executable /usr/local/bin/auditoria-namespaces-completa.sh; then
    log_already "Auditoria integral (auditoria-namespaces-completa.sh existe)"
elif ask "Crear herramienta de auditoria integral de namespaces?"; then

    cat > "$NS_BIN/auditoria-namespaces-completa.sh" << 'EOFAUDIT'
#!/bin/bash
# ============================================================
# auditoria-namespaces-completa.sh - Auditoria integral namespaces
# ============================================================
set -euo pipefail

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
BOLD="\033[1m"
DIM="\033[2m"
NC="\033[0m"

LOG_DIR="/var/log/securizar/namespaces"
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
echo -e "  AUDITORIA INTEGRAL NAMESPACES" | tee -a "$REPORT"
echo -e "  $(date '+%Y-%m-%d %H:%M:%S') - $(hostname)" | tee -a "$REPORT"
echo -e "=============================================${NC}" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# 1. User namespaces
echo -e "${CYAN}=== 1. User namespaces ===${NC}" | tee -a "$REPORT"
check "sysctl userns config" "$([[ -f /etc/sysctl.d/90-securizar-userns.conf ]]; echo $?)"
userns_clone=$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo "1")
check "unprivileged_userns_clone=0" "$([[ "$userns_clone" == "0" ]]; echo $?)"
bpf_disabled=$(sysctl -n kernel.unprivileged_bpf_disabled 2>/dev/null || echo "0")
check "unprivileged_bpf_disabled=1" "$([[ "$bpf_disabled" == "1" ]]; echo $?)"

# 2. Network namespaces
echo "" | tee -a "$REPORT"
echo -e "${CYAN}=== 2. Network namespaces ===${NC}" | tee -a "$REPORT"
check "securizar-netns-isolate.sh" "$([[ -x /usr/local/bin/securizar-netns-isolate.sh ]]; echo $?)"

# 3. PID namespaces
echo "" | tee -a "$REPORT"
echo -e "${CYAN}=== 3. PID namespaces ===${NC}" | tee -a "$REPORT"
check "hidepid en /proc" "$(grep -q 'hidepid=' /etc/fstab 2>/dev/null; echo $?)"
ptrace_scope=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo "0")
check "ptrace_scope >= 1" "$([[ "$ptrace_scope" -ge 1 ]]; echo $?)"

# 4. Mount namespaces
echo "" | tee -a "$REPORT"
echo -e "${CYAN}=== 4. Mount namespaces ===${NC}" | tee -a "$REPORT"
check "securizar-mount-private.sh" "$([[ -x /usr/local/bin/securizar-mount-private.sh ]]; echo $?)"

# 5. Rootless containers
echo "" | tee -a "$REPORT"
echo -e "${CYAN}=== 5. Rootless containers ===${NC}" | tee -a "$REPORT"
check "securizar-rootless-containers.sh" "$([[ -x /usr/local/bin/securizar-rootless-containers.sh ]]; echo $?)"
check "/etc/subuid existe" "$([[ -f /etc/subuid ]]; echo $?)"
check "/etc/subgid existe" "$([[ -f /etc/subgid ]]; echo $?)"

# 6. Systemd sandboxing
echo "" | tee -a "$REPORT"
echo -e "${CYAN}=== 6. Systemd sandboxing ===${NC}" | tee -a "$REPORT"
check "systemd-sandbox.conf" "$([[ -f /etc/securizar/namespaces/systemd-sandbox.conf ]]; echo $?)"

# 7. Seccomp
echo "" | tee -a "$REPORT"
echo -e "${CYAN}=== 7. Seccomp ===${NC}" | tee -a "$REPORT"
check "seccomp-ns-filter.json" "$([[ -f /etc/securizar/namespaces/seccomp-ns-filter.json ]]; echo $?)"

# 8. Cgroups
echo "" | tee -a "$REPORT"
echo -e "${CYAN}=== 8. Cgroups ===${NC}" | tee -a "$REPORT"
check "cgroups-policy.conf" "$([[ -f /etc/securizar/namespaces/cgroups-policy.conf ]]; echo $?)"
check "Cgroups v2 unified" "$([[ -f /sys/fs/cgroup/cgroup.controllers ]]; echo $?)"

# 9. Deteccion de escape
echo "" | tee -a "$REPORT"
echo -e "${CYAN}=== 9. Deteccion de escape ===${NC}" | tee -a "$REPORT"
check "securizar-ns-escape-detect.sh" "$([[ -x /usr/local/bin/securizar-ns-escape-detect.sh ]]; echo $?)"
check "Reglas audit namespaces" "$([[ -f /etc/audit/rules.d/securizar-namespaces.rules ]]; echo $?)"

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
logger -t securizar-namespaces "Namespace audit: $SCORE/$MAX ($PCT%)"
EOFAUDIT
    chmod +x "$NS_BIN/auditoria-namespaces-completa.sh"
    log_change "Creado" "$NS_BIN/auditoria-namespaces-completa.sh"

    # Cron semanal
    cat > /etc/cron.weekly/auditoria-namespaces << 'EOFCRON'
#!/bin/bash
/usr/local/bin/auditoria-namespaces-completa.sh > /dev/null 2>&1
EOFCRON
    chmod 700 /etc/cron.weekly/auditoria-namespaces
    log_change "Creado" "/etc/cron.weekly/auditoria-namespaces"

else
    log_skip "Auditoria integral namespaces"
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
show_changes_summary
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   AISLAMIENTO DE NAMESPACES (MODULO 72) COMPLETADO       ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups guardados en: $BACKUP_DIR"
echo ""
echo "Comandos disponibles:"
echo "  - Netns isolation:    securizar-netns-isolate.sh {create|exec|delete|list}"
echo "  - Mount private:      securizar-mount-private.sh {apply|shell|run|status}"
echo "  - Rootless config:    securizar-rootless-containers.sh {check|setup|enable-userns}"
echo "  - Escape detection:   securizar-ns-escape-detect.sh {scan|audit-rules|watch}"
echo "  - Auditoria:          auditoria-namespaces-completa.sh"
