#!/bin/bash
# ============================================================
# seguridad-virtualizacion.sh - Modulo 57: Seguridad de Virtualizacion
# ============================================================
# Secciones:
#   S1  - Deteccion de entorno de virtualizacion
#   S2  - Hardening de KVM/QEMU host
#   S3  - Hardening de libvirt
#   S4  - Aislamiento de VMs (network)
#   S5  - Seguridad de almacenamiento de VMs
#   S6  - Hardening de VMs guests (plantillas)
#   S7  - Contenedores systemd-nspawn y LXC
#   S8  - Proteccion contra escape de VM
#   S9  - Monitorizacion de VMs
#   S10 - Auditoria integral de virtualizacion
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps
init_backup "virtualization-security"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MODULO 57 - SEGURIDAD DE VIRTUALIZACION                ║"
echo "║   KVM/QEMU, libvirt, nspawn, LXC, VMware, Xen            ║"
echo "║   Aislamiento, almacenamiento, escape, monitorizacion     ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

log_section "MODULO 57: SEGURIDAD DE VIRTUALIZACION"
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

# ── Pre-check rapido ────────────────────────────────────
_precheck 10
_pc check_file_exists /etc/securizar/virt-environment.conf
_pc true  # S2: hardening KVM/QEMU (depende de entorno, siempre re-evaluar)
_pc check_executable /usr/local/bin/securizar-libvirt.sh
_pc check_dir_exists /etc/securizar/vm-templates
_pc check_executable /usr/local/bin/auditar-storage-vm.sh
_pc check_dir_exists /etc/securizar/vm-templates
_pc check_executable /usr/local/bin/auditar-contenedores-locales.sh
_pc check_executable /usr/local/bin/verificar-escape-vm.sh
_pc check_executable /usr/local/bin/monitorizar-vms.sh
_pc check_executable /usr/local/bin/auditar-virtualizacion.sh
_precheck_result

# ── Variables globales del modulo ───────────────────────────
VIRT_CONF_DIR="/etc/securizar"
VIRT_ENV_CONF="${VIRT_CONF_DIR}/virt-environment.conf"
VIRT_LOG_DIR="/var/log/securizar/vm-monitor"
VIRT_TEMPLATES_DIR="${VIRT_CONF_DIR}/vm-templates"

# ── Helpers de deteccion ────────────────────────────────────

# Detectar si estamos en un entorno virtualizado y de que tipo
detect_virt_type() {
    local vtype="none"
    if command -v systemd-detect-virt &>/dev/null; then
        vtype=$(systemd-detect-virt 2>/dev/null || echo "none")
    fi
    echo "$vtype"
}

# Detectar si estamos en host o guest
detect_host_or_guest() {
    local role="unknown"
    local vtype
    vtype=$(detect_virt_type)
    if [[ "$vtype" == "none" ]]; then
        role="host"
    else
        role="guest"
    fi
    echo "$role"
}

# Verificar si KVM esta disponible
kvm_available() {
    [[ -e /dev/kvm ]] || lsmod 2>/dev/null | grep -q 'kvm' || \
        command -v qemu-system-x86_64 &>/dev/null || \
        command -v qemu-kvm &>/dev/null
}

# Verificar si libvirt esta instalado
libvirt_available() {
    command -v virsh &>/dev/null || \
        systemctl list-unit-files 2>/dev/null | grep -q 'libvirtd' || \
        [[ -d /etc/libvirt ]]
}

# Verificar si systemd-nspawn esta en uso
nspawn_available() {
    command -v systemd-nspawn &>/dev/null || \
        command -v machinectl &>/dev/null || \
        [[ -d /var/lib/machines ]]
}

# Verificar si LXC esta instalado
lxc_available() {
    command -v lxc-ls &>/dev/null || command -v lxc &>/dev/null || \
        [[ -d /var/lib/lxc ]] || [[ -d /var/snap/lxd ]]
}

# Backup seguro de archivo
safe_backup() {
    local file="$1"
    if [[ -f "$file" ]]; then
        local basename
        basename=$(basename "$file")
        cp -a "$file" "${BACKUP_DIR}/${basename}.$(date +%s).bak" 2>/dev/null || true
    fi
}

# Asegurar valor en archivo de configuracion (key = value)
ensure_config_value() {
    local file="$1"
    local key="$2"
    local value="$3"
    local separator="${4:- = }"

    if [[ ! -f "$file" ]]; then
        echo "${key}${separator}${value}" >> "$file"
        return
    fi

    if grep -qE "^\s*#?\s*${key}\s*=" "$file" 2>/dev/null; then
        sed -i "s|^\s*#\?\s*${key}\s*=.*|${key}${separator}${value}|" "$file"
    else
        echo "${key}${separator}${value}" >> "$file"
    fi
}

# Asegurar valor en archivo de configuracion (key value sin =)
ensure_config_value_space() {
    local file="$1"
    local key="$2"
    local value="$3"

    if [[ ! -f "$file" ]]; then
        echo "${key} ${value}" >> "$file"
        return
    fi

    if grep -qE "^\s*#?\s*${key}\s" "$file" 2>/dev/null; then
        sed -i "s|^\s*#\?\s*${key}\s.*|${key} ${value}|" "$file"
    else
        echo "${key} ${value}" >> "$file"
    fi
}


###############################################################################
# S1: DETECCION DE ENTORNO DE VIRTUALIZACION
###############################################################################
log_section "S1: Deteccion de entorno de virtualizacion"

detect_virtualization_environment() {
    log_info "Detectando entorno de virtualizacion..."

    # Crear directorio de configuracion
    mkdir -p "$VIRT_CONF_DIR" 2>/dev/null || true

    local virt_type="none"
    local virt_role="unknown"
    local hypervisor="none"
    local cpu_virt_features=""
    local iommu_support="no"

    # --- Metodo 1: systemd-detect-virt ---
    if command -v systemd-detect-virt &>/dev/null; then
        virt_type=$(systemd-detect-virt 2>/dev/null || echo "none")
        log_info "systemd-detect-virt: $virt_type"

        local virt_vm virt_container
        virt_vm=$(systemd-detect-virt --vm 2>/dev/null || echo "none")
        virt_container=$(systemd-detect-virt --container 2>/dev/null || echo "none")
        log_info "  VM detectada: $virt_vm"
        log_info "  Contenedor detectado: $virt_container"
    else
        log_warn "systemd-detect-virt no disponible"
    fi

    # --- Metodo 2: dmidecode ---
    if command -v dmidecode &>/dev/null; then
        local dmi_manufacturer dmi_product
        dmi_manufacturer=$(dmidecode -s system-manufacturer 2>/dev/null || echo "unknown")
        dmi_product=$(dmidecode -s system-product-name 2>/dev/null || echo "unknown")
        log_info "DMI Fabricante: $dmi_manufacturer"
        log_info "DMI Producto: $dmi_product"

        case "$dmi_manufacturer" in
            *QEMU*|*KVM*)        hypervisor="kvm" ;;
            *VMware*)            hypervisor="vmware" ;;
            *VirtualBox*|*innotek*) hypervisor="virtualbox" ;;
            *Xen*)               hypervisor="xen" ;;
            *Microsoft*)
                if [[ "$dmi_product" == *"Virtual Machine"* ]]; then
                    hypervisor="hyper-v"
                fi
                ;;
        esac

        if [[ "$hypervisor" != "none" ]]; then
            log_info "Hypervisor detectado via DMI: $hypervisor"
        fi
    else
        log_warn "dmidecode no disponible, omitiendo deteccion DMI"
    fi

    # --- Metodo 3: /proc/cpuinfo ---
    if [[ -f /proc/cpuinfo ]]; then
        if grep -qi 'hypervisor' /proc/cpuinfo 2>/dev/null; then
            log_info "/proc/cpuinfo indica entorno virtualizado (flag hypervisor presente)"
            if [[ "$hypervisor" == "none" ]]; then
                hypervisor="unknown-hypervisor"
            fi
        fi

        # Detectar features de CPU para virtualizacion
        local cpu_flags
        cpu_flags=$(grep -m1 '^flags' /proc/cpuinfo 2>/dev/null | cut -d: -f2 || echo "")

        if echo "$cpu_flags" | grep -qw 'vmx' 2>/dev/null; then
            cpu_virt_features="${cpu_virt_features}VT-x "
            log_info "CPU soporta Intel VT-x (vmx)"
        fi
        if echo "$cpu_flags" | grep -qw 'svm' 2>/dev/null; then
            cpu_virt_features="${cpu_virt_features}AMD-V "
            log_info "CPU soporta AMD-V (svm)"
        fi
        if echo "$cpu_flags" | grep -qw 'ept' 2>/dev/null; then
            cpu_virt_features="${cpu_virt_features}EPT "
        fi
        if echo "$cpu_flags" | grep -qw 'npt' 2>/dev/null; then
            cpu_virt_features="${cpu_virt_features}NPT "
        fi
    fi

    # --- Metodo 4: lscpu para detalle ---
    if command -v lscpu &>/dev/null; then
        local lscpu_hyp
        lscpu_hyp=$(lscpu 2>/dev/null | grep -i 'hypervisor vendor' | awk -F: '{print $2}' | xargs || echo "")
        if [[ -n "$lscpu_hyp" ]]; then
            log_info "lscpu hypervisor vendor: $lscpu_hyp"
            if [[ "$hypervisor" == "none" || "$hypervisor" == "unknown-hypervisor" ]]; then
                case "$lscpu_hyp" in
                    *KVM*)       hypervisor="kvm" ;;
                    *VMware*)    hypervisor="vmware" ;;
                    *Xen*)       hypervisor="xen" ;;
                    *Microsoft*) hypervisor="hyper-v" ;;
                esac
            fi
        fi

        local virt_type_lscpu
        virt_type_lscpu=$(lscpu 2>/dev/null | grep -i 'virtualization type' | awk -F: '{print $2}' | xargs || echo "")
        if [[ -n "$virt_type_lscpu" ]]; then
            log_info "Tipo de virtualizacion (lscpu): $virt_type_lscpu"
        fi
    fi

    # --- Metodo 5: Detectar contenedores ---
    if [[ -f /.dockerenv ]]; then
        log_info "Entorno Docker detectado (/.dockerenv presente)"
        virt_type="docker"
    elif grep -q 'lxc' /proc/1/cgroup 2>/dev/null; then
        log_info "Entorno LXC detectado (/proc/1/cgroup)"
        virt_type="lxc"
    elif grep -q '/machine.slice' /proc/1/cgroup 2>/dev/null; then
        log_info "Entorno systemd-nspawn detectado (/proc/1/cgroup)"
        virt_type="systemd-nspawn"
    fi

    # --- Determinar rol (host / guest) ---
    if [[ "$virt_type" == "none" ]] && [[ "$hypervisor" == "none" ]]; then
        virt_role="host"
        log_info "Sistema detectado como: HOST (bare-metal)"
    elif [[ "$virt_type" != "none" ]]; then
        virt_role="guest"
        log_info "Sistema detectado como: GUEST (virtualizado: $virt_type)"
    else
        virt_role="guest"
        log_info "Sistema detectado como: GUEST (hypervisor: $hypervisor)"
    fi

    # --- IOMMU / VT-d / AMD-Vi ---
    if [[ -d /sys/class/iommu ]] && [[ -n "$(ls -A /sys/class/iommu/ 2>/dev/null)" ]]; then
        iommu_support="yes"
        log_info "IOMMU activo en el sistema (VT-d/AMD-Vi)"
    else
        if grep -qE 'intel_iommu=on|amd_iommu=on' /proc/cmdline 2>/dev/null; then
            iommu_support="cmdline-enabled"
            log_info "IOMMU habilitado en cmdline del kernel"
        else
            log_warn "IOMMU no detectado - recomendado para passthrough seguro"
        fi
    fi

    # --- Modulos de kernel de virtualizacion cargados ---
    log_info "Modulos de virtualizacion cargados:"
    local kvm_loaded="no"
    for mod in kvm kvm_intel kvm_amd vboxdrv vmw_vmci xen_blkfront virtio_pci; do
        if lsmod 2>/dev/null | grep -qw "$mod"; then
            log_info "  - $mod: cargado"
            if [[ "$mod" == "kvm" || "$mod" == "kvm_intel" || "$mod" == "kvm_amd" ]]; then
                kvm_loaded="yes"
            fi
        fi
    done

    # --- Detectar VMs en ejecucion si somos host ---
    local running_vms=0
    if [[ "$virt_role" == "host" ]] && command -v virsh &>/dev/null; then
        running_vms=$(virsh list --state-running 2>/dev/null | grep -c 'running' || echo "0")
        log_info "VMs en ejecucion (libvirt): $running_vms"
    fi

    # --- Detectar contenedores en ejecucion ---
    local running_containers=0
    if command -v machinectl &>/dev/null; then
        running_containers=$(machinectl list --no-legend 2>/dev/null | wc -l || echo "0")
        if [[ "$running_containers" -gt 0 ]]; then
            log_info "Contenedores nspawn activos: $running_containers"
        fi
    fi
    if command -v lxc-ls &>/dev/null; then
        local lxc_running
        lxc_running=$(lxc-ls --running 2>/dev/null | wc -w || echo "0")
        if [[ "$lxc_running" -gt 0 ]]; then
            log_info "Contenedores LXC activos: $lxc_running"
            running_containers=$((running_containers + lxc_running))
        fi
    fi

    # --- Guardar configuracion detectada ---
    if check_file_exists "$VIRT_ENV_CONF"; then
        log_already "Entorno de virtualizacion ($VIRT_ENV_CONF existe)"
    elif ask "Guardar informacion del entorno de virtualizacion en $VIRT_ENV_CONF?"; then
        mkdir -p "$VIRT_CONF_DIR"
        cat > "$VIRT_ENV_CONF" <<VEOF
# Entorno de virtualizacion detectado por securizar
# Generado: $(date -Iseconds)
# Sistema: $DISTRO_NAME ($DISTRO_FAMILY)

VIRT_TYPE="$virt_type"
VIRT_ROLE="$virt_role"
HYPERVISOR="$hypervisor"
CPU_VIRT_FEATURES="$cpu_virt_features"
IOMMU_SUPPORT="$iommu_support"
KVM_LOADED="$kvm_loaded"
RUNNING_VMS="$running_vms"
RUNNING_CONTAINERS="$running_containers"
VEOF
        chmod 600 "$VIRT_ENV_CONF"
        log_change "Creado" "$VIRT_ENV_CONF con datos del entorno"
    else
        log_skip "Guardar configuracion de entorno de virtualizacion"
    fi

    # --- Recomendaciones basadas en deteccion ---
    log_info "--- Resumen del entorno ---"
    log_info "  Tipo: $virt_type | Rol: $virt_role | Hypervisor: $hypervisor"
    log_info "  CPU features: ${cpu_virt_features:-ninguna detectada}"
    log_info "  IOMMU: $iommu_support | KVM: $kvm_loaded"

    if [[ "$virt_role" == "host" ]]; then
        if [[ "$kvm_loaded" == "yes" ]]; then
            log_info "Este es un host KVM - se aplicaran hardening de KVM/QEMU y libvirt"
        fi
        if [[ "$iommu_support" == "no" ]]; then
            log_warn "Recomendacion: habilitar IOMMU (intel_iommu=on / amd_iommu=on) para passthrough seguro"
        fi
        if [[ -z "$cpu_virt_features" ]]; then
            log_warn "No se detectaron extensiones de virtualizacion de CPU"
        fi
    elif [[ "$virt_role" == "guest" ]]; then
        log_info "Este sistema es un guest - se aplicaran recomendaciones especificas de guest"
    fi
}

detect_virtualization_environment


###############################################################################
# S2: HARDENING DE KVM/QEMU HOST
###############################################################################
log_section "S2: Hardening de KVM/QEMU host"

harden_kvm_qemu() {
    log_info "Verificando entorno KVM/QEMU..."

    # Verificar si KVM/QEMU esta instalado
    local qemu_installed=false
    if command -v qemu-system-x86_64 &>/dev/null || \
       command -v qemu-kvm &>/dev/null || \
       command -v qemu-system-aarch64 &>/dev/null; then
        qemu_installed=true
        local qemu_version
        qemu_version=$(qemu-system-x86_64 --version 2>/dev/null | head -1 || \
                       qemu-kvm --version 2>/dev/null | head -1 || echo "desconocida")
        log_info "QEMU instalado: $qemu_version"
    fi

    if ! $qemu_installed && ! [[ -e /dev/kvm ]]; then
        log_info "KVM/QEMU no detectado en este sistema"
        log_skip "Hardening KVM/QEMU - no instalado"
        return 0
    fi

    # --- Verificar paquetes relacionados ---
    log_info "Verificando paquetes KVM/QEMU..."
    local pkg_list=""
    case "$DISTRO_FAMILY" in
        suse)
            pkg_list="qemu-kvm qemu-tools libvirt libvirt-client virt-manager"
            ;;
        debian)
            pkg_list="qemu-kvm qemu-utils libvirt-daemon-system libvirt-clients virtinst"
            ;;
        rhel)
            pkg_list="qemu-kvm qemu-img libvirt libvirt-client virt-install"
            ;;
        arch)
            pkg_list="qemu-full libvirt virt-manager"
            ;;
    esac

    for pkg in $pkg_list; do
        if command -v rpm &>/dev/null && rpm -q "$pkg" &>/dev/null; then
            log_info "  Paquete instalado: $pkg"
        elif command -v dpkg &>/dev/null && dpkg -l "$pkg" 2>/dev/null | grep -q '^ii'; then
            log_info "  Paquete instalado: $pkg"
        elif command -v pacman &>/dev/null && pacman -Q "$pkg" &>/dev/null; then
            log_info "  Paquete instalado: $pkg"
        fi
    done

    # --- Hardening de /etc/libvirt/qemu.conf ---
    local qemu_conf="/etc/libvirt/qemu.conf"
    if [[ -f "$qemu_conf" ]]; then
        log_info "Archivo de configuracion QEMU encontrado: $qemu_conf"

        if check_file_contains "$qemu_conf" 'vnc_tls.*=.*1'; then
            log_already "Hardening de $qemu_conf (vnc_tls ya configurado)"
        elif ask "Aplicar hardening a $qemu_conf?"; then
            safe_backup "$qemu_conf"

            # VNC TLS
            local current_vnc_tls
            current_vnc_tls=$(grep -E '^\s*vnc_tls\s*=' "$qemu_conf" 2>/dev/null | tail -1 || echo "")
            if [[ "$current_vnc_tls" != *"1"* ]]; then
                ensure_config_value "$qemu_conf" "vnc_tls" "1"
                log_change "Configurado" "vnc_tls = 1 en $qemu_conf"
            else
                log_info "vnc_tls ya habilitado"
            fi

            # VNC TLS x509 verify
            local current_vnc_verify
            current_vnc_verify=$(grep -E '^\s*vnc_tls_x509_verify\s*=' "$qemu_conf" 2>/dev/null | tail -1 || echo "")
            if [[ "$current_vnc_verify" != *"1"* ]]; then
                ensure_config_value "$qemu_conf" "vnc_tls_x509_verify" "1"
                log_change "Configurado" "vnc_tls_x509_verify = 1 en $qemu_conf"
            else
                log_info "vnc_tls_x509_verify ya habilitado"
            fi

            # SPICE TLS
            local current_spice_tls
            current_spice_tls=$(grep -E '^\s*spice_tls\s*=' "$qemu_conf" 2>/dev/null | tail -1 || echo "")
            if [[ "$current_spice_tls" != *"1"* ]]; then
                ensure_config_value "$qemu_conf" "spice_tls" "1"
                log_change "Configurado" "spice_tls = 1 en $qemu_conf"
            else
                log_info "spice_tls ya habilitado"
            fi

            # Security driver
            local current_sec_driver
            current_sec_driver=$(grep -E '^\s*security_driver\s*=' "$qemu_conf" 2>/dev/null | tail -1 || echo "")
            if [[ -z "$current_sec_driver" ]]; then
                # Detectar cual usar
                local sec_driver_val=""
                if command -v aa-status &>/dev/null; then
                    sec_driver_val='"apparmor"'
                    log_info "AppArmor detectado - usando como security driver"
                elif command -v getenforce &>/dev/null; then
                    sec_driver_val='"selinux"'
                    log_info "SELinux detectado - usando como security driver"
                else
                    sec_driver_val='"none"'
                    log_warn "Ni AppArmor ni SELinux detectados - security_driver=none"
                fi
                ensure_config_value "$qemu_conf" "security_driver" "$sec_driver_val"
                log_change "Configurado" "security_driver = $sec_driver_val en $qemu_conf"
            else
                log_info "security_driver ya configurado: $current_sec_driver"
            fi

            # User/group restrictions
            local current_user
            current_user=$(grep -E '^\s*user\s*=' "$qemu_conf" 2>/dev/null | tail -1 || echo "")
            if [[ -z "$current_user" || "$current_user" == *"root"* ]]; then
                # Verificar que el usuario qemu/libvirt-qemu existe
                local qemu_user="root"
                local qemu_group="root"
                if id "libvirt-qemu" &>/dev/null; then
                    qemu_user='"libvirt-qemu"'
                    qemu_group='"libvirt-qemu"'
                elif id "qemu" &>/dev/null; then
                    qemu_user='"qemu"'
                    qemu_group='"qemu"'
                else
                    log_warn "No se encontro usuario qemu/libvirt-qemu, manteniendo root"
                    qemu_user='"root"'
                    qemu_group='"root"'
                fi
                ensure_config_value "$qemu_conf" "user" "$qemu_user"
                ensure_config_value "$qemu_conf" "group" "$qemu_group"
                log_change "Configurado" "user = $qemu_user, group = $qemu_group en $qemu_conf"
            else
                log_info "user/group ya configurados: $current_user"
            fi

            # cgroup_device_acl restrictions
            local current_cgroup
            current_cgroup=$(grep -E '^\s*cgroup_device_acl\s*=' "$qemu_conf" 2>/dev/null | tail -1 || echo "")
            if [[ -z "$current_cgroup" ]]; then
                cat >> "$qemu_conf" <<'CGEOF'

# Restriccion de dispositivos cgroup (securizar)
cgroup_device_acl = [
    "/dev/null", "/dev/full", "/dev/zero",
    "/dev/random", "/dev/urandom",
    "/dev/ptmx", "/dev/kvm",
    "/dev/rtc", "/dev/hpet",
    "/dev/vfio/vfio"
]
CGEOF
                log_change "Configurado" "cgroup_device_acl restrictivo en $qemu_conf"
            else
                log_info "cgroup_device_acl ya configurado"
            fi

            # Deshabilitar remember_owner (seguridad)
            ensure_config_value "$qemu_conf" "remember_owner" "0"
            log_change "Configurado" "remember_owner = 0 en $qemu_conf"

            # Deshabilitar allow_disk_format_probing
            ensure_config_value "$qemu_conf" "allow_disk_format_probing" "0"
            log_change "Configurado" "allow_disk_format_probing = 0 (previene ataques de formato)"

            # nographics_allow_host_audio
            ensure_config_value "$qemu_conf" "nographics_allow_host_audio" "0"
            log_change "Configurado" "nographics_allow_host_audio = 0"

        else
            log_skip "Hardening de $qemu_conf"
        fi
    else
        log_info "Archivo $qemu_conf no encontrado"
        log_skip "Hardening de qemu.conf - archivo no existe"
    fi

    # --- Permisos de /dev/kvm ---
    if [[ -e /dev/kvm ]]; then
        local kvm_perms kvm_owner kvm_group_name
        kvm_perms=$(stat -c '%a' /dev/kvm 2>/dev/null || echo "unknown")
        kvm_owner=$(stat -c '%U' /dev/kvm 2>/dev/null || echo "unknown")
        kvm_group_name=$(stat -c '%G' /dev/kvm 2>/dev/null || echo "unknown")
        log_info "/dev/kvm: permisos=$kvm_perms, propietario=$kvm_owner:$kvm_group_name"

        if [[ "$kvm_perms" != "660" ]]; then
            if ask "Corregir permisos de /dev/kvm a 660 (root:kvm)?"; then
                # Asegurar que grupo kvm existe
                if ! getent group kvm &>/dev/null; then
                    groupadd kvm 2>/dev/null || true
                    log_change "Creado" "grupo kvm"
                fi
                chmod 660 /dev/kvm
                chown root:kvm /dev/kvm
                log_change "Permisos" "/dev/kvm -> 660 root:kvm"
            else
                log_skip "Correccion de permisos de /dev/kvm"
            fi
        else
            log_info "/dev/kvm tiene permisos correctos (660)"
        fi

        # Crear regla udev para persistencia
        local udev_kvm="/etc/udev/rules.d/65-kvm.rules"
        if [[ ! -f "$udev_kvm" ]]; then
            if ask "Crear regla udev para persistir permisos de /dev/kvm?"; then
                cat > "$udev_kvm" <<'UEOF'
# Regla udev para /dev/kvm - securizar modulo 57
KERNEL=="kvm", GROUP="kvm", MODE="0660"
UEOF
                chmod 644 "$udev_kvm"
                log_change "Creado" "$udev_kvm para permisos persistentes de /dev/kvm"
            else
                log_skip "Regla udev para /dev/kvm"
            fi
        else
            log_info "Regla udev para /dev/kvm ya existe: $udev_kvm"
        fi
    else
        log_info "/dev/kvm no existe en este sistema"
    fi

    # --- Deshabilitar features innecesarias de QEMU ---
    log_info "Verificando features de QEMU deshabilitables..."

    # Verificar si qemu-guest-agent esta corriendo innecesariamente en host
    if [[ "$(detect_host_or_guest)" == "host" ]]; then
        if systemctl is-active qemu-guest-agent &>/dev/null; then
            log_warn "qemu-guest-agent corriendo en HOST - deberia estar solo en guests"
            if ask "Deshabilitar qemu-guest-agent en host?"; then
                systemctl stop qemu-guest-agent 2>/dev/null || true
                systemctl disable qemu-guest-agent 2>/dev/null || true
                log_change "Deshabilitado" "qemu-guest-agent en host (solo necesario en guests)"
            else
                log_skip "Deshabilitar qemu-guest-agent en host"
            fi
        fi
    fi

    # Verificar nested virtualization
    local nested_file=""
    if [[ -f /sys/module/kvm_intel/parameters/nested ]]; then
        nested_file="/sys/module/kvm_intel/parameters/nested"
    elif [[ -f /sys/module/kvm_amd/parameters/nested ]]; then
        nested_file="/sys/module/kvm_amd/parameters/nested"
    fi

    if [[ -n "$nested_file" ]]; then
        local nested_val
        nested_val=$(cat "$nested_file" 2>/dev/null || echo "N")
        if [[ "$nested_val" == "Y" || "$nested_val" == "1" ]]; then
            log_warn "Virtualizacion anidada (nested) habilitada: $nested_file = $nested_val"
            log_warn "La virtualizacion anidada aumenta la superficie de ataque"
            if ask "Deshabilitar virtualizacion anidada?"; then
                # Crear modprobe config para persistencia
                local modprobe_kvm="/etc/modprobe.d/kvm-securizar.conf"
                if [[ "$nested_file" == *"intel"* ]]; then
                    echo "options kvm_intel nested=0" > "$modprobe_kvm"
                else
                    echo "options kvm_amd nested=0" > "$modprobe_kvm"
                fi
                chmod 644 "$modprobe_kvm"
                log_change "Configurado" "Deshabilitada virtualizacion anidada en $modprobe_kvm"
                log_warn "Requiere reinicio o recarga del modulo kvm para tomar efecto"
            else
                log_skip "Deshabilitar virtualizacion anidada"
            fi
        else
            log_info "Virtualizacion anidada deshabilitada (correcto)"
        fi
    fi

    # --- Verificar QEMU con seccomp ---
    log_info "Verificando soporte seccomp en QEMU..."
    if command -v qemu-system-x86_64 &>/dev/null; then
        local qemu_help
        qemu_help=$(qemu-system-x86_64 -sandbox help 2>&1 || echo "")
        if echo "$qemu_help" | grep -qi 'sandbox\|seccomp' 2>/dev/null; then
            log_info "QEMU soporta sandbox/seccomp"
        else
            log_warn "QEMU podria no soportar sandbox seccomp"
        fi
    fi
}

harden_kvm_qemu


###############################################################################
# S3: HARDENING DE LIBVIRT
###############################################################################
log_section "S3: Hardening de libvirt"

harden_libvirt() {
    log_info "Verificando configuracion de libvirt..."

    if ! libvirt_available; then
        log_info "libvirt no esta instalado en este sistema"
        log_skip "Hardening de libvirt - no instalado"
        return 0
    fi

    local libvirtd_conf="/etc/libvirt/libvirtd.conf"

    if [[ ! -f "$libvirtd_conf" ]]; then
        log_warn "Archivo $libvirtd_conf no encontrado"
        log_skip "Hardening de libvirtd.conf - archivo no existe"
        return 0
    fi

    # --- Backup ---
    safe_backup "$libvirtd_conf"
    log_info "Backup de $libvirtd_conf realizado"

    if check_file_contains "$libvirtd_conf" 'listen_tls.*=.*1'; then
        log_already "Hardening de $libvirtd_conf (listen_tls ya configurado)"
    elif ask "Aplicar hardening a $libvirtd_conf?"; then

        # --- TLS para conexiones remotas ---
        log_info "Configurando TLS para conexiones remotas..."

        local current_listen_tls
        current_listen_tls=$(grep -E '^\s*listen_tls\s*=' "$libvirtd_conf" 2>/dev/null | tail -1 || echo "")
        if [[ "$current_listen_tls" != *"1"* ]]; then
            ensure_config_value "$libvirtd_conf" "listen_tls" "1"
            log_change "Configurado" "listen_tls = 1 en $libvirtd_conf"
        else
            log_info "listen_tls ya habilitado"
        fi

        # Deshabilitar TCP sin TLS
        local current_listen_tcp
        current_listen_tcp=$(grep -E '^\s*listen_tcp\s*=' "$libvirtd_conf" 2>/dev/null | tail -1 || echo "")
        if [[ "$current_listen_tcp" != *"0"* ]]; then
            ensure_config_value "$libvirtd_conf" "listen_tcp" "0"
            log_change "Configurado" "listen_tcp = 0 (deshabilitar TCP sin cifrar)"
        else
            log_info "listen_tcp ya deshabilitado"
        fi

        # Configurar certificados TLS
        local tls_dir="/etc/pki/libvirt"
        if [[ -d "$tls_dir" ]]; then
            log_info "Directorio de certificados TLS existe: $tls_dir"
        else
            log_warn "Directorio $tls_dir no existe - TLS no funcionara sin certificados"
            if ask "Crear directorio de certificados TLS $tls_dir?"; then
                mkdir -p "$tls_dir/private"
                chmod 700 "$tls_dir/private"
                chmod 755 "$tls_dir"
                log_change "Creado" "$tls_dir para certificados TLS de libvirt"
            else
                log_skip "Crear directorio de certificados TLS"
            fi
        fi

        ensure_config_value "$libvirtd_conf" "tls_no_sanity_certificate" "0"
        ensure_config_value "$libvirtd_conf" "tls_no_verify_certificate" "0"
        log_change "Configurado" "Verificacion estricta de certificados TLS"

        # --- Restriccion de acceso Unix socket ---
        log_info "Configurando restricciones de acceso via Unix socket..."

        local priv_group
        priv_group=$(get_privileged_group)

        # Grupo del socket
        local current_sock_group
        current_sock_group=$(grep -E '^\s*unix_sock_group\s*=' "$libvirtd_conf" 2>/dev/null | tail -1 || echo "")
        if [[ -z "$current_sock_group" ]]; then
            # Usar grupo libvirt si existe, si no el grupo privilegiado
            local sock_group="libvirt"
            if ! getent group libvirt &>/dev/null; then
                sock_group="$priv_group"
            fi
            ensure_config_value "$libvirtd_conf" "unix_sock_group" "\"${sock_group}\""
            log_change "Configurado" "unix_sock_group = \"${sock_group}\""
        else
            log_info "unix_sock_group ya configurado: $current_sock_group"
        fi

        # Permisos de lectura del socket
        local current_ro_perms
        current_ro_perms=$(grep -E '^\s*unix_sock_ro_perms\s*=' "$libvirtd_conf" 2>/dev/null | tail -1 || echo "")
        if [[ -z "$current_ro_perms" || "$current_ro_perms" == *"0777"* ]]; then
            ensure_config_value "$libvirtd_conf" "unix_sock_ro_perms" "\"0770\""
            log_change "Configurado" "unix_sock_ro_perms = \"0770\""
        else
            log_info "unix_sock_ro_perms ya configurado: $current_ro_perms"
        fi

        # Permisos de escritura del socket
        local current_rw_perms
        current_rw_perms=$(grep -E '^\s*unix_sock_rw_perms\s*=' "$libvirtd_conf" 2>/dev/null | tail -1 || echo "")
        if [[ -z "$current_rw_perms" || "$current_rw_perms" == *"0777"* ]]; then
            ensure_config_value "$libvirtd_conf" "unix_sock_rw_perms" "\"0770\""
            log_change "Configurado" "unix_sock_rw_perms = \"0770\""
        else
            log_info "unix_sock_rw_perms ya configurado: $current_rw_perms"
        fi

        # Directorio del socket
        ensure_config_value "$libvirtd_conf" "unix_sock_dir" "\"/var/run/libvirt\""
        log_change "Configurado" "unix_sock_dir = /var/run/libvirt"

        # --- Audit logging ---
        log_info "Configurando audit logging..."

        local current_audit_level
        current_audit_level=$(grep -E '^\s*audit_level\s*=' "$libvirtd_conf" 2>/dev/null | tail -1 || echo "")
        if [[ "$current_audit_level" != *"2"* ]]; then
            ensure_config_value "$libvirtd_conf" "audit_level" "2"
            log_change "Configurado" "audit_level = 2 (auditar todas las operaciones)"
        else
            log_info "audit_level ya en 2"
        fi

        local current_audit_logging
        current_audit_logging=$(grep -E '^\s*audit_logging\s*=' "$libvirtd_conf" 2>/dev/null | tail -1 || echo "")
        if [[ "$current_audit_logging" != *"1"* ]]; then
            ensure_config_value "$libvirtd_conf" "audit_logging" "1"
            log_change "Configurado" "audit_logging = 1 (habilitar logging de auditoria)"
        else
            log_info "audit_logging ya habilitado"
        fi

        # --- Log level y outputs ---
        ensure_config_value "$libvirtd_conf" "log_level" "3"
        ensure_config_value "$libvirtd_conf" "log_outputs" "\"3:syslog:libvirtd 3:file:/var/log/libvirt/libvirtd.log\""
        log_change "Configurado" "log_level = 3 y outputs a syslog + archivo"

        # --- max_clients y rate limiting ---
        ensure_config_value "$libvirtd_conf" "max_clients" "20"
        ensure_config_value "$libvirtd_conf" "max_queued_clients" "5"
        ensure_config_value "$libvirtd_conf" "max_anonymous_clients" "5"
        ensure_config_value "$libvirtd_conf" "min_workers" "5"
        ensure_config_value "$libvirtd_conf" "max_workers" "20"
        ensure_config_value "$libvirtd_conf" "max_client_requests" "5"
        log_change "Configurado" "Limites de clientes y workers en libvirtd"

        # --- Deshabilitar autenticacion none ---
        local current_auth_unix_ro
        current_auth_unix_ro=$(grep -E '^\s*auth_unix_ro\s*=' "$libvirtd_conf" 2>/dev/null | tail -1 || echo "")
        if [[ -z "$current_auth_unix_ro" || "$current_auth_unix_ro" == *"none"* ]]; then
            ensure_config_value "$libvirtd_conf" "auth_unix_ro" "\"polkit\""
            log_change "Configurado" "auth_unix_ro = \"polkit\" (requiere autenticacion)"
        else
            log_info "auth_unix_ro ya configurado: $current_auth_unix_ro"
        fi

        local current_auth_unix_rw
        current_auth_unix_rw=$(grep -E '^\s*auth_unix_rw\s*=' "$libvirtd_conf" 2>/dev/null | tail -1 || echo "")
        if [[ -z "$current_auth_unix_rw" || "$current_auth_unix_rw" == *"none"* ]]; then
            ensure_config_value "$libvirtd_conf" "auth_unix_rw" "\"polkit\""
            log_change "Configurado" "auth_unix_rw = \"polkit\" (requiere autenticacion)"
        else
            log_info "auth_unix_rw ya configurado: $current_auth_unix_rw"
        fi

    else
        log_skip "Hardening de $libvirtd_conf"
    fi

    # --- Polkit rules para gestion de VMs ---
    log_info "Configurando reglas polkit para libvirt..."
    local polkit_dir=""
    if [[ -d /etc/polkit-1/rules.d ]]; then
        polkit_dir="/etc/polkit-1/rules.d"
    elif [[ -d /usr/share/polkit-1/rules.d ]]; then
        polkit_dir="/usr/share/polkit-1/rules.d"
    fi

    if [[ -n "$polkit_dir" ]]; then
        local polkit_rule="${polkit_dir}/50-libvirt-securizar.rules"
        if [[ ! -f "$polkit_rule" ]]; then
            if ask "Crear regla polkit para restringir gestion de VMs a grupo libvirt?"; then
                local priv_grp
                priv_grp=$(get_privileged_group)
                cat > "$polkit_rule" <<PKEOF
// Regla polkit para libvirt - securizar modulo 57
// Permite gestion de VMs solo a usuarios del grupo libvirt o $priv_grp
polkit.addRule(function(action, subject) {
    if (action.id.indexOf("org.libvirt.") === 0) {
        if (subject.isInGroup("libvirt") || subject.isInGroup("$priv_grp")) {
            return polkit.Result.YES;
        }
        return polkit.Result.AUTH_ADMIN;
    }
});
PKEOF
                chmod 644 "$polkit_rule"
                log_change "Creado" "$polkit_rule para restringir acceso a libvirt"
            else
                log_skip "Regla polkit para libvirt"
            fi
        else
            log_info "Regla polkit para libvirt ya existe: $polkit_rule"
        fi
    else
        log_warn "Directorio polkit rules.d no encontrado"
        log_skip "Reglas polkit para libvirt"
    fi

    # --- Script de verificacion de libvirt ---
    local libvirt_script="/usr/local/bin/securizar-libvirt.sh"
    if check_executable "$libvirt_script"; then
        log_already "Script de verificacion de libvirt ($libvirt_script existe)"
    elif ask "Crear script de verificacion de libvirt en $libvirt_script?"; then
        cat > "$libvirt_script" <<'LVEOF'
#!/bin/bash
# ============================================================
# securizar-libvirt.sh - Verificacion de seguridad de libvirt
# Generado por securizar modulo 57
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo "=== Verificacion de seguridad de libvirt ==="
echo "Fecha: $(date -Iseconds)"
echo ""

ISSUES=0
CHECKS=0

check_pass() { ((CHECKS++)); echo -e "${GREEN}[PASS]${NC} $1"; }
check_fail() { ((CHECKS++)); ((ISSUES++)); echo -e "${RED}[FAIL]${NC} $1"; }
check_warn() { ((CHECKS++)); echo -e "${YELLOW}[WARN]${NC} $1"; }

# Verificar servicio
if systemctl is-active libvirtd &>/dev/null; then
    check_pass "Servicio libvirtd activo"
else
    check_warn "Servicio libvirtd no activo"
fi

# Verificar configuracion
CONF="/etc/libvirt/libvirtd.conf"
if [[ -f "$CONF" ]]; then
    # listen_tcp deshabilitado
    if grep -qE '^\s*listen_tcp\s*=\s*0' "$CONF" 2>/dev/null; then
        check_pass "TCP sin cifrar deshabilitado"
    elif grep -qE '^\s*listen_tcp\s*=\s*1' "$CONF" 2>/dev/null; then
        check_fail "TCP sin cifrar HABILITADO - riesgo de seguridad"
    else
        check_pass "listen_tcp no configurado (por defecto deshabilitado)"
    fi

    # Audit logging
    if grep -qE '^\s*audit_level\s*=\s*2' "$CONF" 2>/dev/null; then
        check_pass "Audit level = 2 (completo)"
    else
        check_warn "Audit level no configurado a nivel completo (2)"
    fi

    # Auth polkit
    if grep -qE '^\s*auth_unix_rw\s*=\s*"polkit"' "$CONF" 2>/dev/null; then
        check_pass "Autenticacion polkit para escritura"
    elif grep -qE '^\s*auth_unix_rw\s*=\s*"none"' "$CONF" 2>/dev/null; then
        check_fail "Autenticacion NONE para escritura - riesgo critico"
    else
        check_warn "auth_unix_rw no configurado explicitamente"
    fi

    # Socket permissions
    if grep -qE '^\s*unix_sock_rw_perms\s*=\s*"0770"' "$CONF" 2>/dev/null; then
        check_pass "Permisos de socket RW restrictivos (0770)"
    elif grep -qE '^\s*unix_sock_rw_perms\s*=\s*"0777"' "$CONF" 2>/dev/null; then
        check_fail "Permisos de socket RW abiertos (0777)"
    else
        check_warn "unix_sock_rw_perms no configurado explicitamente"
    fi

    # TLS
    if grep -qE '^\s*listen_tls\s*=\s*1' "$CONF" 2>/dev/null; then
        check_pass "TLS habilitado para conexiones remotas"
    else
        check_warn "TLS no habilitado para conexiones remotas"
    fi
else
    check_warn "Archivo $CONF no encontrado"
fi

# Verificar QEMU conf
QEMU_CONF="/etc/libvirt/qemu.conf"
if [[ -f "$QEMU_CONF" ]]; then
    if grep -qE '^\s*security_driver\s*=\s*"(apparmor|selinux)"' "$QEMU_CONF" 2>/dev/null; then
        check_pass "Security driver configurado (MAC)"
    elif grep -qE '^\s*security_driver\s*=\s*"none"' "$QEMU_CONF" 2>/dev/null; then
        check_fail "Security driver = none - sin MAC"
    else
        check_warn "security_driver no configurado explicitamente"
    fi

    if grep -qE '^\s*vnc_tls\s*=\s*1' "$QEMU_CONF" 2>/dev/null; then
        check_pass "VNC TLS habilitado"
    else
        check_warn "VNC TLS no habilitado"
    fi
else
    check_warn "Archivo $QEMU_CONF no encontrado"
fi

# Verificar VMs en ejecucion
if command -v virsh &>/dev/null; then
    echo ""
    echo "=== VMs en ejecucion ==="
    virsh list --all 2>/dev/null || echo "No se pudo listar VMs"

    # Verificar redes
    echo ""
    echo "=== Redes libvirt ==="
    virsh net-list --all 2>/dev/null || echo "No se pudo listar redes"
fi

echo ""
echo "=== Resumen ==="
echo -e "Verificaciones: $CHECKS | Problemas: ${RED}${ISSUES}${NC}"

if [[ $ISSUES -eq 0 ]]; then
    echo -e "${GREEN}Sin problemas de seguridad detectados${NC}"
elif [[ $ISSUES -le 2 ]]; then
    echo -e "${YELLOW}Algunos ajustes recomendados${NC}"
else
    echo -e "${RED}Se requieren correcciones de seguridad${NC}"
fi

exit $ISSUES
LVEOF
        chmod +x "$libvirt_script"
        log_change "Creado" "$libvirt_script"
    else
        log_skip "Script de verificacion de libvirt"
    fi

    # --- Directorio de logs de libvirt ---
    if [[ ! -d /var/log/libvirt ]]; then
        mkdir -p /var/log/libvirt
        chmod 750 /var/log/libvirt
        log_change "Creado" "/var/log/libvirt con permisos 750"
    fi

    # --- Verificar que libvirtd use socket activation (systemd) ---
    log_info "Verificando activacion por socket de libvirtd..."
    if systemctl list-unit-files 'libvirtd.socket' &>/dev/null 2>&1; then
        if systemctl is-enabled libvirtd.socket &>/dev/null; then
            log_info "libvirtd.socket habilitado (activacion por socket - correcto)"
        else
            log_info "libvirtd.socket disponible pero no habilitado"
            if ask "Habilitar activacion por socket de libvirtd (mas seguro)?"; then
                systemctl enable libvirtd.socket 2>/dev/null || true
                log_change "Habilitado" "libvirtd.socket para activacion por socket"
            else
                log_skip "Activacion por socket de libvirtd"
            fi
        fi
    fi
}

harden_libvirt


###############################################################################
# S4: AISLAMIENTO DE VMS (NETWORK)
###############################################################################
log_section "S4: Aislamiento de VMs (network)"

harden_vm_networking() {
    log_info "Auditando aislamiento de red de VMs..."

    if ! command -v virsh &>/dev/null; then
        log_info "virsh no disponible - omitiendo auditoria de red de VMs"
        log_skip "Aislamiento de red de VMs - virsh no disponible"
        return 0
    fi

    # --- Listar redes de libvirt ---
    log_info "Redes de libvirt configuradas:"
    local nets
    nets=$(virsh net-list --all --name 2>/dev/null || echo "")

    if [[ -z "$nets" ]]; then
        log_info "No hay redes de libvirt configuradas"
        log_skip "Auditoria de redes - no hay redes configuradas"
    else
        local net_count=0
        local default_net_active=false
        local insecure_nets=""

        while IFS= read -r net_name; do
            [[ -z "$net_name" ]] && continue
            ((net_count++))

            local net_active net_autostart net_persistent net_bridge
            net_active=$(virsh net-info "$net_name" 2>/dev/null | grep -i 'active' | awk '{print $2}' || echo "unknown")
            net_autostart=$(virsh net-info "$net_name" 2>/dev/null | grep -i 'autostart' | awk '{print $2}' || echo "unknown")
            net_persistent=$(virsh net-info "$net_name" 2>/dev/null | grep -i 'persistent' | awk '{print $2}' || echo "unknown")
            net_bridge=$(virsh net-info "$net_name" 2>/dev/null | grep -i 'bridge' | awk '{print $2}' || echo "none")

            log_info "  Red: $net_name | Activa: $net_active | Autostart: $net_autostart | Bridge: $net_bridge"

            # Obtener XML para analisis detallado
            local net_xml
            net_xml=$(virsh net-dumpxml "$net_name" 2>/dev/null || echo "")

            if [[ -n "$net_xml" ]]; then
                # Verificar tipo de red
                if echo "$net_xml" | grep -q '<forward mode=.nat.' 2>/dev/null; then
                    log_warn "  Red '$net_name' usa NAT - menor aislamiento"
                    if [[ "$net_name" == "default" ]]; then
                        default_net_active=true
                    fi
                    insecure_nets="${insecure_nets}${net_name}(NAT) "
                elif echo "$net_xml" | grep -q '<forward mode=.route.' 2>/dev/null; then
                    log_info "  Red '$net_name' usa routing"
                elif echo "$net_xml" | grep -q '<forward mode=.bridge.' 2>/dev/null; then
                    log_info "  Red '$net_name' usa bridge"
                elif echo "$net_xml" | grep -q '<forward mode=.open.' 2>/dev/null; then
                    log_warn "  Red '$net_name' usa modo open - sin restricciones"
                    insecure_nets="${insecure_nets}${net_name}(OPEN) "
                elif ! echo "$net_xml" | grep -q '<forward' 2>/dev/null; then
                    log_info "  Red '$net_name' es aislada (sin forward - correcto para segmentacion)"
                fi

                # Verificar DHCP
                if echo "$net_xml" | grep -q '<dhcp>' 2>/dev/null; then
                    log_info "  Red '$net_name' tiene DHCP habilitado"
                fi

                # Verificar DNS
                if echo "$net_xml" | grep -q '<dns>' 2>/dev/null; then
                    log_info "  Red '$net_name' tiene DNS integrado"
                fi
            fi
        done <<< "$nets"

        log_info "Total de redes: $net_count"

        # --- VMs en red default (menos segura) ---
        if $default_net_active; then
            log_warn "Red 'default' (NAT) activa - verificando VMs conectadas..."

            local vms_on_default=0
            local all_vms
            all_vms=$(virsh list --all --name 2>/dev/null || echo "")

            while IFS= read -r vm_name; do
                [[ -z "$vm_name" ]] && continue
                local vm_xml
                vm_xml=$(virsh dumpxml "$vm_name" 2>/dev/null || echo "")
                if echo "$vm_xml" | grep -q "network='default'" 2>/dev/null; then
                    log_warn "  VM '$vm_name' conectada a red default (NAT)"
                    ((vms_on_default++))
                fi
            done <<< "$all_vms"

            if [[ $vms_on_default -gt 0 ]]; then
                log_warn "$vms_on_default VM(s) en red default - considerar migrar a red aislada o bridge"
            fi
        fi
    fi

    # --- Verificar nwfilter rules ---
    log_info "Verificando nwfilter rules de libvirt..."
    local nwfilters
    nwfilters=$(virsh nwfilter-list 2>/dev/null || echo "")

    if [[ -n "$nwfilters" ]]; then
        local nwf_count
        nwf_count=$(echo "$nwfilters" | grep -c 'UUID' || echo "0")
        log_info "nwfilters disponibles: $nwf_count"

        # Verificar filtros de seguridad basicos
        local basic_filters="clean-traffic no-mac-spoofing no-ip-spoofing no-arp-spoofing"
        for filter in $basic_filters; do
            if virsh nwfilter-list 2>/dev/null | grep -q "$filter"; then
                log_info "  nwfilter disponible: $filter"
            else
                log_warn "  nwfilter basico no disponible: $filter"
            fi
        done
    else
        log_warn "No hay nwfilters configurados o virsh nwfilter-list fallo"
    fi

    # --- Verificar macvtap/macbridge ---
    log_info "Verificando interfaces macvtap/macbridge..."
    if ip link show type macvtap 2>/dev/null | grep -q 'macvtap'; then
        log_info "Interfaces macvtap detectadas:"
        ip link show type macvtap 2>/dev/null | grep 'macvtap' | while read -r line; do
            log_info "  $line"
        done
    fi

    if ip link show type macvlan 2>/dev/null | grep -q 'macvlan'; then
        log_info "Interfaces macvlan detectadas"
    fi

    # --- Verificar bridge networking ---
    if command -v brctl &>/dev/null || command -v bridge &>/dev/null; then
        log_info "Bridges de red:"
        if command -v bridge &>/dev/null; then
            bridge link show 2>/dev/null | while IFS= read -r line; do
                log_info "  $line"
            done
        elif command -v brctl &>/dev/null; then
            brctl show 2>/dev/null | while IFS= read -r line; do
                log_info "  $line"
            done
        fi
    fi

    # --- Verificar iptables/nftables para VMs ---
    log_info "Verificando reglas de firewall para trafico de VMs..."
    if command -v iptables &>/dev/null; then
        local fwd_rules
        fwd_rules=$(iptables -L FORWARD -n 2>/dev/null | grep -c -v '^Chain\|^target\|^$' || echo "0")
        log_info "Reglas FORWARD en iptables: $fwd_rules"

        if [[ "$fwd_rules" -eq 0 ]]; then
            log_warn "Sin reglas FORWARD - trafico entre VMs no filtrado"
        fi
    fi

    if command -v nft &>/dev/null; then
        local nft_forward
        nft_forward=$(nft list chain inet filter forward 2>/dev/null | grep -c 'rule' || echo "0")
        if [[ "$nft_forward" -gt 0 ]]; then
            log_info "Reglas nftables forward: $nft_forward"
        fi
    fi

    # --- Crear templates de red aislada ---
    if check_file_exists "${VIRT_TEMPLATES_DIR}/isolated-network.xml"; then
        log_already "Templates de red aislada (isolated-network.xml existe)"
    elif ask "Crear templates de red aislada para VMs?"; then
        mkdir -p "${VIRT_TEMPLATES_DIR}"

        # Template de red aislada
        cat > "${VIRT_TEMPLATES_DIR}/isolated-network.xml" <<'INETEOF'
<!--
  Red aislada para VMs - securizar modulo 57
  Las VMs en esta red solo pueden comunicarse entre si
  Sin acceso a la red del host ni a internet
  Uso: virsh net-define /etc/securizar/vm-templates/isolated-network.xml
-->
<network>
  <name>isolated-secure</name>
  <bridge name="virbr-isol" stp="on" delay="0"/>
  <!-- Sin <forward> = red completamente aislada -->
  <ip address="10.99.0.1" netmask="255.255.255.0">
    <dhcp>
      <range start="10.99.0.2" end="10.99.0.254"/>
    </dhcp>
  </ip>
</network>
INETEOF
        log_change "Creado" "${VIRT_TEMPLATES_DIR}/isolated-network.xml"

        # Template de red con bridge
        cat > "${VIRT_TEMPLATES_DIR}/bridged-network.xml" <<'BNETEOF'
<!--
  Red bridged para VMs - securizar modulo 57
  Las VMs obtienen IP de la red fisica
  Requiere un bridge existente (ej: br0)
  Uso: virsh net-define /etc/securizar/vm-templates/bridged-network.xml
-->
<network>
  <name>bridged-secure</name>
  <forward mode="bridge"/>
  <bridge name="br0"/>
</network>
BNETEOF
        log_change "Creado" "${VIRT_TEMPLATES_DIR}/bridged-network.xml"

        # Template de nwfilter restrictivo
        cat > "${VIRT_TEMPLATES_DIR}/secure-nwfilter.xml" <<'NFEOF'
<!--
  nwfilter restrictivo para VMs - securizar modulo 57
  Previene: MAC spoofing, IP spoofing, ARP spoofing, DHCP spoofing
  Uso: virsh nwfilter-define /etc/securizar/vm-templates/secure-nwfilter.xml
-->
<filter name="securizar-clean-traffic" chain="root">
  <uuid/>
  <filterref filter="no-mac-spoofing"/>
  <filterref filter="no-ip-spoofing"/>
  <filterref filter="no-arp-spoofing"/>
  <filterref filter="allow-dhcp"/>
  <filterref filter="allow-arp"/>
  <filterref filter="allow-ipv4"/>
  <rule action="drop" direction="inout" priority="1000">
    <all/>
  </rule>
</filter>
NFEOF
        log_change "Creado" "${VIRT_TEMPLATES_DIR}/secure-nwfilter.xml"

        chmod -R 600 "${VIRT_TEMPLATES_DIR}"/*.xml 2>/dev/null || true
        chmod 750 "${VIRT_TEMPLATES_DIR}"
    else
        log_skip "Templates de red aislada"
    fi
}

harden_vm_networking


###############################################################################
# S5: SEGURIDAD DE ALMACENAMIENTO DE VMS
###############################################################################
log_section "S5: Seguridad de almacenamiento de VMs"

harden_vm_storage() {
    log_info "Auditando seguridad de almacenamiento de VMs..."

    if ! command -v virsh &>/dev/null; then
        log_info "virsh no disponible - verificacion parcial de almacenamiento"
    fi

    # --- Listar storage pools ---
    local pools_found=false
    if command -v virsh &>/dev/null; then
        log_info "Storage pools de libvirt:"
        local pools
        pools=$(virsh pool-list --all --name 2>/dev/null || echo "")

        if [[ -n "$pools" ]]; then
            pools_found=true
            while IFS= read -r pool_name; do
                [[ -z "$pool_name" ]] && continue

                local pool_active pool_path pool_type
                pool_active=$(virsh pool-info "$pool_name" 2>/dev/null | grep -i 'state' | awk '{print $2}' || echo "unknown")
                pool_path=$(virsh pool-dumpxml "$pool_name" 2>/dev/null | grep '<path>' | sed 's|.*<path>\(.*\)</path>.*|\1|' || echo "unknown")
                pool_type=$(virsh pool-info "$pool_name" 2>/dev/null | grep -i 'type' | awk '{print $2}' || echo "unknown")

                log_info "  Pool: $pool_name | Tipo: $pool_type | Estado: $pool_active | Path: $pool_path"

                # Verificar permisos del directorio del pool
                if [[ -d "$pool_path" ]]; then
                    local dir_perms dir_owner dir_group
                    dir_perms=$(stat -c '%a' "$pool_path" 2>/dev/null || echo "unknown")
                    dir_owner=$(stat -c '%U' "$pool_path" 2>/dev/null || echo "unknown")
                    dir_group=$(stat -c '%G' "$pool_path" 2>/dev/null || echo "unknown")
                    log_info "    Permisos: $dir_perms ($dir_owner:$dir_group)"

                    if [[ "${dir_perms:2:1}" =~ [1-7] ]]; then
                        log_warn "    Directorio del pool $pool_name accesible por 'others' ($dir_perms)"
                    fi
                fi
            done <<< "$pools"
        else
            log_info "No hay storage pools configurados"
        fi
    fi

    # --- Verificar imagenes de disco ---
    log_info "Verificando imagenes de disco de VMs..."

    local image_dirs="/var/lib/libvirt/images /var/lib/virt/images /home/virt /srv/virt"
    local total_images=0
    local insecure_images=0
    local unencrypted_images=0

    for img_dir in $image_dirs; do
        if [[ -d "$img_dir" ]]; then
            log_info "Escaneando directorio: $img_dir"

            # Verificar permisos del directorio
            local dperms
            dperms=$(stat -c '%a' "$img_dir" 2>/dev/null || echo "unknown")
            if [[ "${dperms:2:1}" =~ [1-7] ]]; then
                log_warn "  Directorio $img_dir accesible por 'others' (permisos: $dperms)"
                if ask "Corregir permisos de $img_dir a 710?"; then
                    chmod 710 "$img_dir"
                    log_change "Permisos" "$img_dir -> 710"
                else
                    log_skip "Correccion de permisos de $img_dir"
                fi
            fi

            # Escanear archivos de imagen
            while IFS= read -r img_file; do
                [[ -z "$img_file" ]] && continue
                ((total_images++))

                local fperms fowner fsize
                fperms=$(stat -c '%a' "$img_file" 2>/dev/null || echo "unknown")
                fowner=$(stat -c '%U:%G' "$img_file" 2>/dev/null || echo "unknown")
                fsize=$(stat -c '%s' "$img_file" 2>/dev/null || echo "0")
                local fsize_human
                fsize_human=$(numfmt --to=iec "$fsize" 2>/dev/null || echo "${fsize}B")

                log_info "  Imagen: $(basename "$img_file") ($fsize_human) permisos=$fperms owner=$fowner"

                # Verificar permisos inseguros
                if [[ "${fperms:2:1}" =~ [4-7] ]]; then
                    log_warn "    INSEGURO: Imagen legible por 'others' ($fperms)"
                    ((insecure_images++))
                fi
                if [[ "$fperms" != "600" && "$fperms" != "640" && "$fperms" != "660" ]]; then
                    log_warn "    Permisos no optimos ($fperms) - recomendado 600 o 640"
                fi

                # Verificar formato y cifrado
                if command -v qemu-img &>/dev/null; then
                    local img_info
                    img_info=$(qemu-img info "$img_file" 2>/dev/null || echo "")

                    if [[ -n "$img_info" ]]; then
                        local fmt
                        fmt=$(echo "$img_info" | grep 'file format:' | awk '{print $3}' || echo "unknown")
                        log_info "    Formato: $fmt"

                        # Verificar cifrado
                        if echo "$img_info" | grep -qi 'encrypted\|encryption' 2>/dev/null; then
                            if echo "$img_info" | grep -qi 'encrypted: yes\|encryption:' 2>/dev/null; then
                                log_info "    Cifrado: SI"
                            else
                                log_info "    Cifrado: NO"
                                ((unencrypted_images++))
                            fi
                        else
                            log_info "    Cifrado: NO detectado"
                            ((unencrypted_images++))
                        fi

                        # Verificar backing file chain
                        local backing
                        backing=$(echo "$img_info" | grep 'backing file:' | awk '{print $3}' || echo "")
                        if [[ -n "$backing" ]]; then
                            log_info "    Backing file: $backing"
                            if [[ ! -f "$backing" ]]; then
                                log_warn "    BACKING FILE NO ENCONTRADO: $backing"
                            fi
                        fi
                    fi
                fi
            done < <(find "$img_dir" -maxdepth 2 -type f \( -name "*.qcow2" -o -name "*.raw" -o -name "*.qed" -o -name "*.vmdk" -o -name "*.vdi" -o -name "*.vhd" -o -name "*.vhdx" -o -name "*.img" \) 2>/dev/null)
        fi
    done

    log_info "Imagenes de disco encontradas: $total_images"
    if [[ $insecure_images -gt 0 ]]; then
        log_warn "Imagenes con permisos inseguros: $insecure_images"
    fi
    if [[ $unencrypted_images -gt 0 ]]; then
        log_warn "Imagenes sin cifrado detectado: $unencrypted_images"
        log_info "Recomendacion: usar LUKS-encrypted qcow2 para datos sensibles"
        log_info "  Crear: qemu-img create -f qcow2 --object secret,id=sec0,data=PASS -o encrypt.format=luks,encrypt.key-secret=sec0 disk.qcow2 20G"
    fi

    # --- Corregir permisos de imagenes inseguras ---
    if [[ $insecure_images -gt 0 ]]; then
        if ask "Corregir permisos de imagenes inseguras a 600?"; then
            for img_dir in $image_dirs; do
                if [[ -d "$img_dir" ]]; then
                    while IFS= read -r img_file; do
                        [[ -z "$img_file" ]] && continue
                        local cur_perms
                        cur_perms=$(stat -c '%a' "$img_file" 2>/dev/null || echo "000")
                        if [[ "${cur_perms:2:1}" =~ [4-7] ]]; then
                            chmod 600 "$img_file"
                            log_change "Permisos" "$(basename "$img_file") -> 600"
                        fi
                    done < <(find "$img_dir" -maxdepth 2 -type f \( -name "*.qcow2" -o -name "*.raw" -o -name "*.qed" -o -name "*.vmdk" -o -name "*.vdi" -o -name "*.img" \) 2>/dev/null)
                fi
            done
        else
            log_skip "Correccion de permisos de imagenes de disco"
        fi
    fi

    # --- Verificar ISOs world-readable ---
    log_info "Verificando ISOs accesibles..."
    local iso_dirs="/var/lib/libvirt/images /var/lib/libvirt/boot /home/iso /srv/iso /tmp"
    for iso_dir in $iso_dirs; do
        if [[ -d "$iso_dir" ]]; then
            while IFS= read -r iso_file; do
                [[ -z "$iso_file" ]] && continue
                local iso_perms
                iso_perms=$(stat -c '%a' "$iso_file" 2>/dev/null || echo "000")
                if [[ "${iso_perms:2:1}" =~ [4-7] ]]; then
                    log_warn "ISO world-readable: $iso_file ($iso_perms)"
                fi
            done < <(find "$iso_dir" -maxdepth 2 -type f -name "*.iso" 2>/dev/null)
        fi
    done

    # --- Script de auditoria de storage ---
    local storage_script="/usr/local/bin/auditar-storage-vm.sh"
    if check_executable "$storage_script"; then
        log_already "Script de auditoria de almacenamiento ($storage_script existe)"
    elif ask "Crear script de auditoria de almacenamiento en $storage_script?"; then
        cat > "$storage_script" <<'STEOF'
#!/bin/bash
# ============================================================
# auditar-storage-vm.sh - Auditoria de almacenamiento de VMs
# Generado por securizar modulo 57
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

LOG_DIR="/var/log/securizar/vm-monitor"
mkdir -p "$LOG_DIR" 2>/dev/null || true
REPORT="$LOG_DIR/storage-audit-$(date +%Y%m%d-%H%M%S).log"

echo "=== Auditoria de almacenamiento de VMs ===" | tee "$REPORT"
echo "Fecha: $(date -Iseconds)" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

ISSUES=0
TOTAL=0

report() { echo "$1" | tee -a "$REPORT"; }
report_pass() { ((TOTAL++)); report "[PASS] $1"; }
report_fail() { ((TOTAL++)); ((ISSUES++)); report "[FAIL] $1"; }
report_warn() { ((TOTAL++)); report "[WARN] $1"; }

# --- Storage pools ---
if command -v virsh &>/dev/null; then
    report "=== Storage Pools ==="
    virsh pool-list --all 2>/dev/null | tee -a "$REPORT"
    echo "" | tee -a "$REPORT"

    # Verificar cada pool
    for pool in $(virsh pool-list --all --name 2>/dev/null); do
        [[ -z "$pool" ]] && continue
        pool_path=$(virsh pool-dumpxml "$pool" 2>/dev/null | grep '<path>' | sed 's|.*<path>\(.*\)</path>.*|\1|' || echo "")
        if [[ -n "$pool_path" ]] && [[ -d "$pool_path" ]]; then
            dperms=$(stat -c '%a' "$pool_path" 2>/dev/null || echo "???")
            if [[ "${dperms:2:1}" =~ [0] ]]; then
                report_pass "Pool '$pool' ($pool_path): permisos $dperms OK"
            else
                report_fail "Pool '$pool' ($pool_path): permisos $dperms (accesible por others)"
            fi
        fi
    done
fi

# --- Imagenes de disco ---
report ""
report "=== Imagenes de disco ==="
IMAGE_DIRS="/var/lib/libvirt/images /var/lib/virt/images /home/virt /srv/virt"

for dir in $IMAGE_DIRS; do
    [[ -d "$dir" ]] || continue
    report "Directorio: $dir"

    while IFS= read -r img; do
        [[ -z "$img" ]] && continue
        perms=$(stat -c '%a' "$img" 2>/dev/null || echo "???")
        owner=$(stat -c '%U:%G' "$img" 2>/dev/null || echo "???")
        size=$(du -h "$img" 2>/dev/null | awk '{print $1}' || echo "???")

        if [[ "$perms" == "600" || "$perms" == "640" ]]; then
            report_pass "$(basename "$img"): permisos=$perms owner=$owner size=$size"
        elif [[ "${perms:2:1}" =~ [4-7] ]]; then
            report_fail "$(basename "$img"): permisos=$perms (world-readable!) owner=$owner size=$size"
        else
            report_warn "$(basename "$img"): permisos=$perms owner=$owner size=$size"
        fi

        # Verificar backing chain
        if command -v qemu-img &>/dev/null; then
            backing=$(qemu-img info "$img" 2>/dev/null | grep 'backing file:' | awk '{print $3}' || echo "")
            if [[ -n "$backing" ]]; then
                if [[ -f "$backing" ]]; then
                    report "  Backing: $backing (existe)"
                else
                    report_fail "  Backing: $backing (NO ENCONTRADO - chain roto!)"
                fi
            fi
        fi
    done < <(find "$dir" -maxdepth 3 -type f \( -name "*.qcow2" -o -name "*.raw" -o -name "*.vmdk" -o -name "*.img" \) 2>/dev/null)
done

# --- Snapshots ---
report ""
report "=== Snapshots de VMs ==="
if command -v virsh &>/dev/null; then
    for vm in $(virsh list --all --name 2>/dev/null); do
        [[ -z "$vm" ]] && continue
        snaps=$(virsh snapshot-list "$vm" --name 2>/dev/null || echo "")
        if [[ -n "$snaps" ]]; then
            report "VM: $vm"
            while IFS= read -r snap; do
                [[ -z "$snap" ]] && continue
                snap_info=$(virsh snapshot-info "$vm" "$snap" 2>/dev/null || echo "")
                snap_date=$(echo "$snap_info" | grep 'Creation time' | sed 's/Creation time:\s*//' || echo "desconocida")
                report "  Snapshot: $snap (creado: $snap_date)"

                # Detectar snapshots antiguos (> 90 dias)
                snap_ts=$(date -d "$snap_date" +%s 2>/dev/null || echo "0")
                now_ts=$(date +%s)
                if [[ "$snap_ts" -gt 0 ]]; then
                    age_days=$(( (now_ts - snap_ts) / 86400 ))
                    if [[ $age_days -gt 90 ]]; then
                        report_warn "  Snapshot '$snap' tiene $age_days dias (>90 - considerar limpiar)"
                    fi
                fi
            done <<< "$snaps"
        fi
    done
fi

# --- Resumen ---
report ""
report "=== Resumen ==="
report "Total verificaciones: $TOTAL"
report "Problemas: $ISSUES"

if [[ $ISSUES -eq 0 ]]; then
    report "Estado: BUENO - Sin problemas de almacenamiento"
elif [[ $ISSUES -le 3 ]]; then
    report "Estado: MEJORABLE - Algunos ajustes recomendados"
else
    report "Estado: DEFICIENTE - Se requieren correcciones"
fi

echo ""
echo -e "${CYAN}Reporte guardado en: $REPORT${NC}"
exit $ISSUES
STEOF
        chmod +x "$storage_script"
        log_change "Creado" "$storage_script"
    else
        log_skip "Script de auditoria de almacenamiento"
    fi
}

harden_vm_storage


###############################################################################
# S6: HARDENING DE VMS GUESTS (PLANTILLAS)
###############################################################################
log_section "S6: Hardening de VMs guests (plantillas)"

create_vm_security_templates() {
    log_info "Creando plantillas de seguridad para nuevas VMs..."

    if check_file_exists "${VIRT_TEMPLATES_DIR}/secure-domain-template.xml"; then
        log_already "Plantillas de seguridad de VM (secure-domain-template.xml existe)"
    elif ask "Crear plantillas de seguridad de VM en $VIRT_TEMPLATES_DIR?"; then
        mkdir -p "$VIRT_TEMPLATES_DIR"

        # --- Template XML de dominio seguro ---
        cat > "${VIRT_TEMPLATES_DIR}/secure-domain-template.xml" <<'DOMEOF'
<!--
  Plantilla de dominio seguro para VMs - securizar modulo 57
  Aplicar a nuevas VMs o como referencia de hardening
  Personalizar: nombre, uuid, discos, interfaces segun necesidad
-->
<domain type="kvm">
  <name>CAMBIAR-NOMBRE-VM</name>
  <memory unit="GiB">2</memory>
  <currentMemory unit="GiB">2</currentMemory>
  <vcpu placement="static">2</vcpu>

  <!-- CPU: habilitar mitigaciones Spectre/Meltdown -->
  <cpu mode="host-passthrough" check="none" migratable="on">
    <feature policy="require" name="spec-ctrl"/>
    <feature policy="require" name="ssbd"/>
    <feature policy="require" name="md-clear"/>
    <feature policy="require" name="stibp"/>
    <feature policy="disable" name="pdpe1gb"/>
  </cpu>

  <!-- OS: firmware readonly UEFI -->
  <os>
    <type arch="x86_64" machine="pc-q35-6.2">hvm</type>
    <loader readonly="yes" type="pflash">/usr/share/OVMF/OVMF_CODE.fd</loader>
    <nvram>/var/lib/libvirt/qemu/nvram/CAMBIAR-NOMBRE-VM_VARS.fd</nvram>
    <boot dev="hd"/>
  </os>

  <!-- Features de seguridad -->
  <features>
    <acpi/>
    <apic/>
    <vmport state="off"/>
    <smm state="on"/>
    <ioapic driver="qemu"/>
  </features>

  <!-- Clock -->
  <clock offset="utc">
    <timer name="rtc" tickpolicy="catchup"/>
    <timer name="pit" tickpolicy="delay"/>
    <timer name="hpet" present="no"/>
  </clock>

  <!-- Power management seguro -->
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>

  <!-- PM -->
  <pm>
    <suspend-to-mem enabled="no"/>
    <suspend-to-disk enabled="no"/>
  </pm>

  <devices>
    <!-- Controlador virtio-scsi para discos -->
    <controller type="scsi" index="0" model="virtio-scsi">
      <address type="pci"/>
    </controller>

    <!-- Disco principal (modificar path) -->
    <disk type="file" device="disk">
      <driver name="qemu" type="qcow2" discard="unmap"/>
      <source file="/var/lib/libvirt/images/CAMBIAR-NOMBRE-VM.qcow2"/>
      <target dev="sda" bus="scsi"/>
    </disk>

    <!-- Interface de red con nwfilter -->
    <interface type="network">
      <source network="isolated-secure"/>
      <model type="virtio"/>
      <filterref filter="clean-traffic"/>
    </interface>

    <!-- Consola serial (sin grafico) -->
    <serial type="pty">
      <target port="0"/>
    </serial>
    <console type="pty">
      <target type="serial" port="0"/>
    </console>

    <!-- VNC con password (si se necesita grafico) -->
    <graphics type="vnc" port="-1" autoport="yes" listen="127.0.0.1">
      <listen type="address" address="127.0.0.1"/>
    </graphics>

    <!-- Video minimalista -->
    <video>
      <model type="qxl" ram="65536" vram="65536" vgamem="16384" heads="1"/>
    </video>

    <!-- Deshabilitado: memballoon (evitar info leaks) -->
    <memballoon model="none"/>

    <!-- RNG para entropia -->
    <rng model="virtio">
      <backend model="random">/dev/urandom</backend>
    </rng>

    <!-- NO incluir (deshabilitar):
      - USB controller/redirector (superficie de ataque)
      - Sound device (innecesario en servidor)
      - Tablet/input devices no esenciales
      - Channel spicevmc
      - TPM emulado (a menos que se necesite)
    -->
  </devices>

  <!-- Perfil de seguridad SELinux/AppArmor -->
  <seclabel type="dynamic" model="dac" relabel="yes">
    <label>+107:+107</label>
    <imagelabel>+107:+107</imagelabel>
  </seclabel>
</domain>
DOMEOF
        log_change "Creado" "${VIRT_TEMPLATES_DIR}/secure-domain-template.xml"

        # --- Template minimalista para servidor ---
        cat > "${VIRT_TEMPLATES_DIR}/server-minimal-template.xml" <<'SRVEOF'
<!--
  Plantilla minimalista para servidor - securizar modulo 57
  Sin graficos, USB, sonido - solo consola serial y red
  Maxima reduccion de superficie de ataque
-->
<domain type="kvm">
  <name>CAMBIAR-NOMBRE-SERVER</name>
  <memory unit="GiB">1</memory>
  <currentMemory unit="GiB">1</currentMemory>
  <vcpu placement="static">1</vcpu>

  <cpu mode="host-passthrough" check="none" migratable="on">
    <feature policy="require" name="spec-ctrl"/>
    <feature policy="require" name="ssbd"/>
    <feature policy="require" name="md-clear"/>
  </cpu>

  <os>
    <type arch="x86_64" machine="pc-q35-6.2">hvm</type>
    <boot dev="hd"/>
  </os>

  <features>
    <acpi/>
    <apic/>
    <vmport state="off"/>
  </features>

  <clock offset="utc"/>

  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>

  <pm>
    <suspend-to-mem enabled="no"/>
    <suspend-to-disk enabled="no"/>
  </pm>

  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>

    <disk type="file" device="disk">
      <driver name="qemu" type="qcow2" discard="unmap"/>
      <source file="/var/lib/libvirt/images/CAMBIAR-NOMBRE-SERVER.qcow2"/>
      <target dev="vda" bus="virtio"/>
    </disk>

    <interface type="network">
      <source network="isolated-secure"/>
      <model type="virtio"/>
      <filterref filter="clean-traffic"/>
    </interface>

    <serial type="pty">
      <target port="0"/>
    </serial>
    <console type="pty">
      <target type="serial" port="0"/>
    </console>

    <!-- Sin graficos, sin USB, sin sonido -->
    <memballoon model="none"/>

    <rng model="virtio">
      <backend model="random">/dev/urandom</backend>
    </rng>
  </devices>
</domain>
SRVEOF
        log_change "Creado" "${VIRT_TEMPLATES_DIR}/server-minimal-template.xml"

        # --- Template de CPU hardening (fragmento para virt-xml) ---
        cat > "${VIRT_TEMPLATES_DIR}/cpu-security-features.txt" <<'CPUEOF'
# CPU security features para aplicar a VMs existentes
# Uso con virt-xml:
#   virt-xml VM_NAME --edit --cpu mode=host-passthrough,feature.policy=require,feature.name=spec-ctrl
#   virt-xml VM_NAME --edit --cpu feature.policy=require,feature.name=ssbd
#   virt-xml VM_NAME --edit --cpu feature.policy=require,feature.name=md-clear
#
# Features de mitigacion Spectre/Meltdown/MDS:
#   spec-ctrl  - Spectre v2 mitigation (IBRS/IBPB)
#   ssbd       - Speculative Store Bypass Disable (Spectre v4)
#   md-clear   - MDS/TAA mitigation (VERW)
#   stibp      - Single Thread Indirect Branch Predictors
#   pdpe1gb    - Deshabilitar 1GB hugepages (puede mejorar aislamiento)
#
# Features a deshabilitar:
#   tsx-ctrl   - TSX control (si hay vulnerabilidades TSX conocidas)
#
# Verificar en guest: cat /proc/cpuinfo | grep -E 'spec_ctrl|ssbd|md_clear'
# Verificar mitigaciones: cat /sys/devices/system/cpu/vulnerabilities/*
CPUEOF
        log_change "Creado" "${VIRT_TEMPLATES_DIR}/cpu-security-features.txt"

        # --- Template de dispositivos a deshabilitar ---
        cat > "${VIRT_TEMPLATES_DIR}/disable-devices.txt" <<'DEVEOF'
# Dispositivos a deshabilitar para VMs de servidor - securizar modulo 57
# Uso con virt-xml para eliminar dispositivos:
#
# Deshabilitar USB:
#   virt-xml VM_NAME --remove-device --controller type=usb
#   virt-xml VM_NAME --remove-device --redirdev type=spicevmc
#
# Deshabilitar sonido:
#   virt-xml VM_NAME --remove-device --sound model=ich6
#   virt-xml VM_NAME --remove-device --sound model=ich9
#
# Deshabilitar tablet (input absoluto):
#   virt-xml VM_NAME --remove-device --input type=tablet
#
# Deshabilitar memballoon (info leak):
#   virt-xml VM_NAME --edit --memballoon model=none
#
# Deshabilitar channel (spice):
#   virt-xml VM_NAME --remove-device --channel target.type=spicevmc
#
# Verificar dispositivos actuales:
#   virsh dumpxml VM_NAME | grep -E '<(usb|sound|input|memballoon|channel|redirdev)'
DEVEOF
        log_change "Creado" "${VIRT_TEMPLATES_DIR}/disable-devices.txt"

        chmod -R 600 "${VIRT_TEMPLATES_DIR}"/*.xml "${VIRT_TEMPLATES_DIR}"/*.txt 2>/dev/null || true
        chmod 750 "${VIRT_TEMPLATES_DIR}"

    else
        log_skip "Plantillas de seguridad de VM"
    fi

    # --- Verificar VMs existentes contra buenas practicas ---
    if command -v virsh &>/dev/null; then
        log_info "Verificando VMs existentes contra plantilla de seguridad..."

        local all_vms
        all_vms=$(virsh list --all --name 2>/dev/null || echo "")

        while IFS= read -r vm_name; do
            [[ -z "$vm_name" ]] && continue
            log_info "Analizando VM: $vm_name"

            local vm_xml
            vm_xml=$(virsh dumpxml "$vm_name" 2>/dev/null || echo "")
            if [[ -z "$vm_xml" ]]; then
                log_warn "  No se pudo obtener XML de $vm_name"
                continue
            fi

            # Verificar CPU mitigations
            if echo "$vm_xml" | grep -q 'name="spec-ctrl"' 2>/dev/null; then
                log_info "  spec-ctrl: habilitado"
            else
                log_warn "  spec-ctrl: NO habilitado (mitigacion Spectre v2)"
            fi

            if echo "$vm_xml" | grep -q 'name="ssbd"' 2>/dev/null; then
                log_info "  ssbd: habilitado"
            else
                log_warn "  ssbd: NO habilitado (mitigacion Spectre v4)"
            fi

            if echo "$vm_xml" | grep -q 'name="md-clear"' 2>/dev/null; then
                log_info "  md-clear: habilitado"
            else
                log_warn "  md-clear: NO habilitado (mitigacion MDS/TAA)"
            fi

            # Verificar memballoon
            if echo "$vm_xml" | grep -q 'memballoon model="none"' 2>/dev/null; then
                log_info "  memballoon: deshabilitado (correcto)"
            elif echo "$vm_xml" | grep -q 'memballoon' 2>/dev/null; then
                log_warn "  memballoon: habilitado (posible info leak)"
            fi

            # Verificar USB
            if echo "$vm_xml" | grep -q '<controller type="usb"' 2>/dev/null; then
                local usb_count
                usb_count=$(echo "$vm_xml" | grep -c '<controller type="usb"' || echo "0")
                log_warn "  USB controllers: $usb_count (considerar eliminar si no se necesitan)"
            else
                log_info "  USB: no presente (correcto para servidor)"
            fi

            # Verificar sonido
            if echo "$vm_xml" | grep -q '<sound' 2>/dev/null; then
                log_warn "  Sound: presente (innecesario para servidor)"
            fi

            # Verificar VNC binding
            if echo "$vm_xml" | grep -q "listen.*0.0.0.0" 2>/dev/null; then
                log_warn "  VNC/SPICE escuchando en 0.0.0.0 (deberia ser 127.0.0.1)"
            fi

            # Verificar nwfilter
            if echo "$vm_xml" | grep -q '<filterref' 2>/dev/null; then
                log_info "  nwfilter: aplicado"
            else
                log_warn "  nwfilter: NO aplicado (sin filtrado de red)"
            fi

        done <<< "$all_vms"
    fi
}

create_vm_security_templates


###############################################################################
# S7: CONTENEDORES SYSTEMD-NSPAWN Y LXC
###############################################################################
log_section "S7: Contenedores systemd-nspawn y LXC"

harden_containers() {
    log_info "Verificando seguridad de contenedores locales..."

    local containers_found=false

    # ==============================
    # SYSTEMD-NSPAWN
    # ==============================
    if nspawn_available; then
        log_info "=== systemd-nspawn detectado ==="
        containers_found=true

        # Listar maquinas
        if command -v machinectl &>/dev/null; then
            log_info "Maquinas nspawn registradas:"
            machinectl list --no-legend 2>/dev/null | while IFS= read -r line; do
                log_info "  $line"
            done

            local nspawn_count
            nspawn_count=$(machinectl list --no-legend 2>/dev/null | wc -l || echo "0")
            log_info "Total maquinas nspawn: $nspawn_count"
        fi

        # Verificar configuraciones en /etc/systemd/nspawn/
        local nspawn_conf_dir="/etc/systemd/nspawn"
        if [[ -d "$nspawn_conf_dir" ]]; then
            log_info "Verificando configuraciones nspawn en $nspawn_conf_dir..."

            while IFS= read -r conf_file; do
                [[ -z "$conf_file" ]] && continue
                local conf_name
                conf_name=$(basename "$conf_file")
                log_info "  Configuracion: $conf_name"

                # Verificar --private-network
                if grep -qi 'PrivateNetwork\s*=\s*true\|PrivateNetwork\s*=\s*yes' "$conf_file" 2>/dev/null; then
                    log_info "    PrivateNetwork: habilitado (correcto)"
                else
                    log_warn "    PrivateNetwork: NO habilitado (recomendado para aislamiento)"
                fi

                # Verificar --read-only
                if grep -qi 'ReadOnly\s*=\s*true\|ReadOnly\s*=\s*yes' "$conf_file" 2>/dev/null; then
                    log_info "    ReadOnly: habilitado"
                else
                    log_info "    ReadOnly: no habilitado"
                fi

                # Verificar PrivateDevices
                if grep -qi 'PrivateDevices\s*=\s*true\|PrivateDevices\s*=\s*yes' "$conf_file" 2>/dev/null; then
                    log_info "    PrivateDevices: habilitado (correcto)"
                else
                    log_warn "    PrivateDevices: NO habilitado"
                fi

                # Verificar ProtectSystem
                if grep -qi 'ProtectSystem\s*=' "$conf_file" 2>/dev/null; then
                    local protect_val
                    protect_val=$(grep -i 'ProtectSystem' "$conf_file" | head -1 | awk -F= '{print $2}' | xargs || echo "")
                    log_info "    ProtectSystem: $protect_val"
                else
                    log_warn "    ProtectSystem: NO configurado"
                fi

                # Verificar ProtectHome
                if grep -qi 'ProtectHome\s*=' "$conf_file" 2>/dev/null; then
                    local protect_home_val
                    protect_home_val=$(grep -i 'ProtectHome' "$conf_file" | head -1 | awk -F= '{print $2}' | xargs || echo "")
                    log_info "    ProtectHome: $protect_home_val"
                else
                    log_warn "    ProtectHome: NO configurado"
                fi

                # Verificar Capability
                if grep -qi 'Capability\s*=\|DropCapability\s*=' "$conf_file" 2>/dev/null; then
                    local cap_val
                    cap_val=$(grep -iE 'Capability|DropCapability' "$conf_file" || echo "")
                    log_info "    Capabilities: $cap_val"
                else
                    log_warn "    Capabilities: NO restringidas"
                fi

            done < <(find "$nspawn_conf_dir" -name "*.nspawn" -type f 2>/dev/null)
        else
            log_info "Directorio $nspawn_conf_dir no existe"
        fi

        # Verificar maquinas en /var/lib/machines
        if [[ -d /var/lib/machines ]]; then
            local machine_count
            machine_count=$(ls -1 /var/lib/machines/ 2>/dev/null | wc -l || echo "0")
            log_info "Imagenes en /var/lib/machines: $machine_count"

            # Verificar permisos
            local machines_perms
            machines_perms=$(stat -c '%a' /var/lib/machines 2>/dev/null || echo "unknown")
            if [[ "$machines_perms" != "700" && "$machines_perms" != "750" ]]; then
                log_warn "/var/lib/machines tiene permisos $machines_perms (recomendado 700)"
                if ask "Corregir permisos de /var/lib/machines a 700?"; then
                    chmod 700 /var/lib/machines
                    log_change "Permisos" "/var/lib/machines -> 700"
                else
                    log_skip "Correccion de permisos de /var/lib/machines"
                fi
            else
                log_info "/var/lib/machines permisos correctos ($machines_perms)"
            fi
        fi

        # Crear template nspawn seguro
        if ask "Crear template de configuracion nspawn segura?"; then
            mkdir -p "$nspawn_conf_dir" 2>/dev/null || true
            cat > "${VIRT_TEMPLATES_DIR}/secure-container.nspawn" <<'NSEOF'
# Template de contenedor nspawn seguro - securizar modulo 57
# Copiar a /etc/systemd/nspawn/NOMBRE.nspawn

[Exec]
# Deshabilitar capabilities peligrosas
DropCapability=CAP_SYS_ADMIN CAP_NET_ADMIN CAP_SYS_RAWIO CAP_SYS_PTRACE CAP_SYS_MODULE CAP_MKNOD CAP_AUDIT_CONTROL CAP_AUDIT_WRITE
# Entorno aislado
PrivateUsers=yes
NoNewPrivileges=yes

[Files]
# Proteccion del sistema de archivos
ReadOnly=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
TemporaryFileSystem=/tmp:mode=1777
TemporaryFileSystem=/var:mode=755
Bind=/var/log

[Network]
# Red aislada
Private=yes
VirtualEthernet=yes
NSEOF
            log_change "Creado" "${VIRT_TEMPLATES_DIR}/secure-container.nspawn"
        else
            log_skip "Template nspawn seguro"
        fi
    fi

    # ==============================
    # LXC
    # ==============================
    if lxc_available; then
        log_info "=== LXC detectado ==="
        containers_found=true

        # Listar contenedores
        if command -v lxc-ls &>/dev/null; then
            log_info "Contenedores LXC:"
            local lxc_all
            lxc_all=$(lxc-ls -f 2>/dev/null || echo "")
            if [[ -n "$lxc_all" ]]; then
                echo "$lxc_all" | while IFS= read -r line; do
                    log_info "  $line"
                done
            else
                log_info "  No hay contenedores LXC"
            fi
        elif command -v lxc &>/dev/null; then
            log_info "Contenedores LXC (snap):"
            lxc list 2>/dev/null | while IFS= read -r line; do
                log_info "  $line"
            done
        fi

        # Verificar configuraciones LXC
        local lxc_conf_dirs="/etc/lxc /var/lib/lxc"
        for lxc_dir in $lxc_conf_dirs; do
            if [[ -d "$lxc_dir" ]]; then
                log_info "Verificando configuraciones en $lxc_dir..."

                while IFS= read -r lxc_conf; do
                    [[ -z "$lxc_conf" ]] && continue
                    local container_name
                    container_name=$(echo "$lxc_conf" | sed 's|.*/lxc/\([^/]*\)/.*|\1|' || basename "$(dirname "$lxc_conf")")
                    log_info "  Contenedor: $container_name ($lxc_conf)"

                    # Verificar AppArmor profile
                    if grep -q 'lxc.apparmor.profile' "$lxc_conf" 2>/dev/null; then
                        local aa_profile
                        aa_profile=$(grep 'lxc.apparmor.profile' "$lxc_conf" | head -1 | awk -F= '{print $2}' | xargs || echo "")
                        if [[ "$aa_profile" == "unconfined" ]]; then
                            log_warn "    AppArmor: unconfined (INSEGURO)"
                        else
                            log_info "    AppArmor: $aa_profile"
                        fi
                    else
                        log_warn "    AppArmor: NO configurado"
                    fi

                    # Verificar cap.drop
                    if grep -q 'lxc.cap.drop' "$lxc_conf" 2>/dev/null; then
                        local caps_dropped
                        caps_dropped=$(grep 'lxc.cap.drop' "$lxc_conf" | wc -l || echo "0")
                        log_info "    Capabilities dropped: $caps_dropped entradas"
                    else
                        log_warn "    lxc.cap.drop: NO configurado (contenedor con todas las capabilities)"
                    fi

                    # Verificar cgroup limits
                    if grep -q 'lxc.cgroup' "$lxc_conf" 2>/dev/null; then
                        log_info "    cgroup limits: configurados"
                        grep 'lxc.cgroup' "$lxc_conf" 2>/dev/null | while IFS= read -r cg_line; do
                            log_info "      $cg_line"
                        done
                    else
                        log_warn "    cgroup limits: NO configurados (sin limites de recursos)"
                    fi

                    # Verificar contenedor no privilegiado
                    if grep -q 'lxc.idmap' "$lxc_conf" 2>/dev/null; then
                        log_info "    Contenedor: no privilegiado (idmap configurado - correcto)"
                    else
                        log_warn "    Contenedor: posiblemente privilegiado (sin idmap)"
                        log_warn "    Recomendacion: usar contenedores no privilegiados"
                    fi

                    # Verificar restricciones de red
                    if grep -q 'lxc.net' "$lxc_conf" 2>/dev/null; then
                        local net_type
                        net_type=$(grep 'lxc.net.0.type' "$lxc_conf" 2>/dev/null | awk -F= '{print $2}' | xargs || echo "no definido")
                        log_info "    Red tipo: $net_type"
                    fi

                done < <(find "$lxc_dir" -name "config" -type f 2>/dev/null)
            fi
        done

        # Verificar configuracion global LXC
        local lxc_default_conf="/etc/lxc/default.conf"
        if [[ -f "$lxc_default_conf" ]]; then
            log_info "Configuracion global LXC: $lxc_default_conf"

            if ! grep -q 'lxc.apparmor.profile' "$lxc_default_conf" 2>/dev/null; then
                log_warn "  AppArmor no configurado en defaults"
                if ask "Agregar perfil AppArmor por defecto a LXC?"; then
                    safe_backup "$lxc_default_conf"
                    echo "lxc.apparmor.profile = generated" >> "$lxc_default_conf"
                    log_change "Configurado" "lxc.apparmor.profile = generated en $lxc_default_conf"
                else
                    log_skip "AppArmor por defecto en LXC"
                fi
            fi

            if ! grep -q 'lxc.cap.drop' "$lxc_default_conf" 2>/dev/null; then
                log_warn "  cap.drop no configurado en defaults"
                if ask "Agregar cap.drop por defecto a LXC?"; then
                    safe_backup "$lxc_default_conf"
                    cat >> "$lxc_default_conf" <<'LCEOF'

# Capabilities peligrosas a eliminar - securizar modulo 57
lxc.cap.drop = mac_admin mac_override sys_time sys_module sys_rawio
LCEOF
                    log_change "Configurado" "lxc.cap.drop en $lxc_default_conf"
                else
                    log_skip "cap.drop por defecto en LXC"
                fi
            fi
        fi
    fi

    if ! $containers_found; then
        log_info "No se detectaron contenedores systemd-nspawn ni LXC"
        log_skip "Hardening de contenedores - ninguno detectado"
    fi

    # --- Script de auditoria de contenedores ---
    local cont_script="/usr/local/bin/auditar-contenedores-locales.sh"
    if check_executable "$cont_script"; then
        log_already "Script de auditoria de contenedores ($cont_script existe)"
    elif ask "Crear script de auditoria de contenedores en $cont_script?"; then
        cat > "$cont_script" <<'CTEOF'
#!/bin/bash
# ============================================================
# auditar-contenedores-locales.sh - Auditoria de contenedores
# Generado por securizar modulo 57
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

LOG_DIR="/var/log/securizar/vm-monitor"
mkdir -p "$LOG_DIR" 2>/dev/null || true
REPORT="$LOG_DIR/containers-audit-$(date +%Y%m%d-%H%M%S).log"

echo "=== Auditoria de contenedores locales ===" | tee "$REPORT"
echo "Fecha: $(date -Iseconds)" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

ISSUES=0
CHECKS=0

check_pass() { ((CHECKS++)); echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$REPORT"; }
check_fail() { ((CHECKS++)); ((ISSUES++)); echo -e "${RED}[FAIL]${NC} $1" | tee -a "$REPORT"; }
check_warn() { ((CHECKS++)); echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$REPORT"; }

# === systemd-nspawn ===
echo "=== systemd-nspawn ===" | tee -a "$REPORT"
if command -v machinectl &>/dev/null; then
    echo "Maquinas registradas:" | tee -a "$REPORT"
    machinectl list 2>/dev/null | tee -a "$REPORT"

    # Verificar configuraciones
    if [[ -d /etc/systemd/nspawn ]]; then
        for conf in /etc/systemd/nspawn/*.nspawn; do
            [[ -f "$conf" ]] || continue
            name=$(basename "$conf" .nspawn)
            echo "" | tee -a "$REPORT"
            echo "Container: $name" | tee -a "$REPORT"

            if grep -qi 'Private\s*=\s*yes\|PrivateNetwork\s*=\s*yes' "$conf" 2>/dev/null; then
                check_pass "$name: Red privada habilitada"
            else
                check_warn "$name: Red privada NO habilitada"
            fi

            if grep -qi 'PrivateDevices\s*=\s*yes' "$conf" 2>/dev/null; then
                check_pass "$name: PrivateDevices habilitado"
            else
                check_warn "$name: PrivateDevices NO habilitado"
            fi

            if grep -qi 'DropCapability\s*=' "$conf" 2>/dev/null; then
                check_pass "$name: Capabilities restringidas"
            else
                check_fail "$name: Capabilities NO restringidas"
            fi

            if grep -qi 'PrivateUsers\s*=\s*yes' "$conf" 2>/dev/null; then
                check_pass "$name: PrivateUsers habilitado (no privilegiado)"
            else
                check_warn "$name: PrivateUsers NO habilitado"
            fi
        done
    fi
else
    echo "systemd-nspawn no disponible" | tee -a "$REPORT"
fi

# === LXC ===
echo "" | tee -a "$REPORT"
echo "=== LXC ===" | tee -a "$REPORT"
if command -v lxc-ls &>/dev/null; then
    echo "Contenedores LXC:" | tee -a "$REPORT"
    lxc-ls -f 2>/dev/null | tee -a "$REPORT"

    for conf in /var/lib/lxc/*/config; do
        [[ -f "$conf" ]] || continue
        name=$(echo "$conf" | sed 's|.*/lxc/\([^/]*\)/config|\1|')
        echo "" | tee -a "$REPORT"
        echo "Container LXC: $name" | tee -a "$REPORT"

        if grep -q 'lxc.apparmor.profile' "$conf" 2>/dev/null; then
            profile=$(grep 'lxc.apparmor.profile' "$conf" | head -1 | awk -F= '{print $2}' | xargs)
            if [[ "$profile" == "unconfined" ]]; then
                check_fail "$name: AppArmor unconfined"
            else
                check_pass "$name: AppArmor profile = $profile"
            fi
        else
            check_warn "$name: Sin perfil AppArmor"
        fi

        if grep -q 'lxc.cap.drop' "$conf" 2>/dev/null; then
            check_pass "$name: Capabilities restringidas (cap.drop)"
        else
            check_fail "$name: Sin restriccion de capabilities"
        fi

        if grep -q 'lxc.idmap' "$conf" 2>/dev/null; then
            check_pass "$name: No privilegiado (idmap)"
        else
            check_warn "$name: Posiblemente privilegiado (sin idmap)"
        fi

        if grep -q 'lxc.cgroup' "$conf" 2>/dev/null; then
            check_pass "$name: cgroup limits configurados"
        else
            check_warn "$name: Sin cgroup limits"
        fi
    done
elif command -v lxc &>/dev/null; then
    echo "LXD contenedores:" | tee -a "$REPORT"
    lxc list 2>/dev/null | tee -a "$REPORT"
else
    echo "LXC no disponible" | tee -a "$REPORT"
fi

# === Resumen ===
echo "" | tee -a "$REPORT"
echo "=== Resumen ===" | tee -a "$REPORT"
echo "Total verificaciones: $CHECKS" | tee -a "$REPORT"
echo "Problemas: $ISSUES" | tee -a "$REPORT"

if [[ $ISSUES -eq 0 ]]; then
    echo -e "${GREEN}Estado: BUENO${NC}" | tee -a "$REPORT"
elif [[ $ISSUES -le 3 ]]; then
    echo -e "${YELLOW}Estado: MEJORABLE${NC}" | tee -a "$REPORT"
else
    echo -e "${RED}Estado: DEFICIENTE${NC}" | tee -a "$REPORT"
fi

echo ""
echo -e "${CYAN}Reporte guardado en: $REPORT${NC}"
exit $ISSUES
CTEOF
        chmod +x "$cont_script"
        log_change "Creado" "$cont_script"
    else
        log_skip "Script de auditoria de contenedores"
    fi
}

harden_containers


###############################################################################
# S8: PROTECCION CONTRA ESCAPE DE VM
###############################################################################
log_section "S8: Proteccion contra escape de VM"

protect_vm_escape() {
    log_info "Verificando protecciones contra escape de VM..."

    # --- Verificar version del kernel ---
    local kernel_version
    kernel_version=$(uname -r 2>/dev/null || echo "unknown")
    log_info "Version del kernel: $kernel_version"

    # Lista de CVEs conocidos de escape de VM por kernel
    # Esta lista se debe actualizar periodicamente
    local kernel_major kernel_minor
    kernel_major=$(echo "$kernel_version" | cut -d. -f1 || echo "0")
    kernel_minor=$(echo "$kernel_version" | cut -d. -f2 || echo "0")

    log_info "Verificando CVEs conocidos de escape de VM..."

    # CVE-2020-2732: KVM nested vmx
    # CVE-2021-22555: netfilter (usable para escape)
    # CVE-2022-0185: fs context (usable para container escape)
    # CVE-2023-2156: ipv6 rpl (escape potencial)
    # CVE-2024-1086: nf_tables (container escape)

    local kernel_cve_issues=0
    if [[ "$kernel_major" -lt 5 ]]; then
        log_warn "Kernel $kernel_version es muy antiguo - multiples CVEs de escape potenciales"
        ((kernel_cve_issues++))
    elif [[ "$kernel_major" -eq 5 && "$kernel_minor" -lt 15 ]]; then
        log_warn "Kernel 5.x anterior a 5.15 - revisar CVEs conocidos"
        ((kernel_cve_issues++))
    elif [[ "$kernel_major" -eq 5 && "$kernel_minor" -ge 15 ]] || [[ "$kernel_major" -ge 6 ]]; then
        log_info "Kernel $kernel_version - version razonablemente reciente"
    fi

    # Verificar si hay actualizaciones pendientes del kernel
    local kernel_update_available=false
    case "$DISTRO_FAMILY" in
        suse)
            if zypper list-updates 2>/dev/null | grep -qi 'kernel'; then
                kernel_update_available=true
            fi
            ;;
        debian)
            if apt list --upgradable 2>/dev/null | grep -qi 'linux-image'; then
                kernel_update_available=true
            fi
            ;;
        rhel)
            if yum check-update kernel 2>/dev/null | grep -qi 'kernel'; then
                kernel_update_available=true
            fi
            ;;
        arch)
            if pacman -Qu 2>/dev/null | grep -qi 'linux'; then
                kernel_update_available=true
            fi
            ;;
    esac

    if $kernel_update_available; then
        log_warn "Actualizacion de kernel disponible - INSTALAR para corregir posibles CVEs"
    else
        log_info "No hay actualizaciones de kernel pendientes"
    fi

    # --- Verificar IOMMU ---
    log_info "Verificando IOMMU para device passthrough seguro..."
    local iommu_active=false

    if [[ -d /sys/class/iommu ]] && [[ -n "$(ls -A /sys/class/iommu/ 2>/dev/null)" ]]; then
        iommu_active=true
        log_info "IOMMU activo: SI"

        # Verificar grupos IOMMU
        if [[ -d /sys/kernel/iommu_groups ]]; then
            local iommu_groups
            iommu_groups=$(ls -1 /sys/kernel/iommu_groups/ 2>/dev/null | wc -l || echo "0")
            log_info "Grupos IOMMU: $iommu_groups"
        fi
    else
        log_warn "IOMMU NO activo"

        # Verificar si esta en cmdline pero no activo
        if grep -qE 'intel_iommu=on|amd_iommu=on' /proc/cmdline 2>/dev/null; then
            log_info "IOMMU habilitado en cmdline pero podria no estar activo"
        else
            log_warn "Recomendacion: agregar intel_iommu=on o amd_iommu=on al GRUB"
            if ask "Agregar IOMMU al cmdline de GRUB?"; then
                local grub_default="/etc/default/grub"
                if [[ -f "$grub_default" ]]; then
                    safe_backup "$grub_default"

                    # Detectar tipo de CPU
                    local iommu_param="intel_iommu=on"
                    if grep -q 'AuthenticAMD' /proc/cpuinfo 2>/dev/null; then
                        iommu_param="amd_iommu=on"
                    fi

                    local current_cmdline
                    current_cmdline=$(grep '^GRUB_CMDLINE_LINUX=' "$grub_default" | sed 's/GRUB_CMDLINE_LINUX="//' | sed 's/"$//' || echo "")
                    if ! echo "$current_cmdline" | grep -q 'iommu=on' 2>/dev/null; then
                        sed -i "s|^GRUB_CMDLINE_LINUX=\"|GRUB_CMDLINE_LINUX=\"${iommu_param} iommu=pt |" "$grub_default"
                        log_change "Configurado" "$iommu_param iommu=pt en GRUB"
                        log_warn "Ejecutar update-grub / grub2-mkconfig y reiniciar para aplicar"
                    fi
                else
                    log_warn "Archivo $grub_default no encontrado"
                fi
            else
                log_skip "Configurar IOMMU en GRUB"
            fi
        fi
    fi

    # --- Verificar restricciones de virtualizacion anidada ---
    log_info "Verificando restricciones de virtualizacion anidada..."
    local nested_file=""
    if [[ -f /sys/module/kvm_intel/parameters/nested ]]; then
        nested_file="/sys/module/kvm_intel/parameters/nested"
    elif [[ -f /sys/module/kvm_amd/parameters/nested ]]; then
        nested_file="/sys/module/kvm_amd/parameters/nested"
    fi

    if [[ -n "$nested_file" ]]; then
        local nested_val
        nested_val=$(cat "$nested_file" 2>/dev/null || echo "N")
        if [[ "$nested_val" == "Y" || "$nested_val" == "1" ]]; then
            log_warn "Virtualizacion anidada HABILITADA - aumenta superficie de ataque para escape"
        else
            log_info "Virtualizacion anidada deshabilitada (correcto)"
        fi
    fi

    # --- Verificar version de QEMU y CVEs conocidos ---
    log_info "Verificando version de QEMU..."
    if command -v qemu-system-x86_64 &>/dev/null; then
        local qemu_full_version
        qemu_full_version=$(qemu-system-x86_64 --version 2>/dev/null | head -1 || echo "unknown")
        log_info "QEMU version: $qemu_full_version"

        local qemu_ver
        qemu_ver=$(echo "$qemu_full_version" | grep -oP '\d+\.\d+' | head -1 || echo "0.0")
        local qemu_major qemu_minor
        qemu_major=$(echo "$qemu_ver" | cut -d. -f1 || echo "0")
        qemu_minor=$(echo "$qemu_ver" | cut -d. -f2 || echo "0")

        # CVEs conocidos de QEMU
        # CVE-2020-14364: USB OHCI controller (qemu < 5.1)
        # CVE-2021-3416: network device (qemu < 6.0)
        # CVE-2022-0216: virtio-net (escape potential)
        # CVE-2023-3354: VNC TLS (info leak)
        # CVE-2024-3446: virtio-net (escape)

        if [[ "$qemu_major" -lt 6 ]]; then
            log_warn "QEMU $qemu_ver es antiguo - multiples CVEs conocidos de escape"
        elif [[ "$qemu_major" -eq 6 ]]; then
            log_warn "QEMU 6.x - considerar actualizar a version mas reciente"
        elif [[ "$qemu_major" -ge 7 ]]; then
            log_info "QEMU $qemu_ver - version razonablemente reciente"
        fi
    elif command -v qemu-kvm &>/dev/null; then
        local qemu_kvm_ver
        qemu_kvm_ver=$(qemu-kvm --version 2>/dev/null | head -1 || echo "unknown")
        log_info "qemu-kvm version: $qemu_kvm_ver"
    fi

    # --- Verificar seccomp filter para QEMU ---
    log_info "Verificando seccomp filter para QEMU..."

    local qemu_conf="/etc/libvirt/qemu.conf"
    if [[ -f "$qemu_conf" ]]; then
        if grep -qE '^\s*seccomp_sandbox\s*=\s*1' "$qemu_conf" 2>/dev/null; then
            log_info "seccomp sandbox habilitado en qemu.conf"
        elif grep -qE '^\s*seccomp_sandbox\s*=\s*0' "$qemu_conf" 2>/dev/null; then
            log_warn "seccomp sandbox DESHABILITADO en qemu.conf"
            if ask "Habilitar seccomp sandbox para QEMU?"; then
                safe_backup "$qemu_conf"
                ensure_config_value "$qemu_conf" "seccomp_sandbox" "1"
                log_change "Configurado" "seccomp_sandbox = 1 en $qemu_conf"
            else
                log_skip "seccomp sandbox para QEMU"
            fi
        else
            log_info "seccomp_sandbox no configurado explicitamente (por defecto suele estar activo)"
            if ask "Configurar seccomp_sandbox = 1 explicitamente en qemu.conf?"; then
                safe_backup "$qemu_conf"
                ensure_config_value "$qemu_conf" "seccomp_sandbox" "1"
                log_change "Configurado" "seccomp_sandbox = 1 en $qemu_conf"
            else
                log_skip "Configurar seccomp_sandbox explicitamente"
            fi
        fi
    fi

    # --- Verificar namespaces de QEMU ---
    log_info "Verificando aislamiento de namespaces para QEMU..."
    if [[ -f "$qemu_conf" ]]; then
        if grep -qE '^\s*namespaces\s*=' "$qemu_conf" 2>/dev/null; then
            log_info "Namespaces configurados en qemu.conf"
        else
            log_info "Namespaces no configurados explicitamente en qemu.conf"
        fi
    fi

    # --- Monitorizar logs de libvirt ---
    log_info "Verificando logs de libvirt para eventos sospechosos..."
    local libvirt_log_dir="/var/log/libvirt"
    if [[ -d "$libvirt_log_dir" ]]; then
        local suspicious_count=0

        # Buscar errores criticos, crashes, segfaults
        for logfile in "$libvirt_log_dir"/*.log "$libvirt_log_dir"/qemu/*.log; do
            [[ -f "$logfile" ]] || continue
            local crashes segfaults
            crashes=$(grep -ci 'crash\|segfault\|SIGSEGV\|SIGABRT\|core dump' "$logfile" 2>/dev/null || echo "0")
            if [[ "$crashes" -gt 0 ]]; then
                log_warn "  $logfile: $crashes eventos sospechosos (crash/segfault)"
                suspicious_count=$((suspicious_count + crashes))
            fi
        done

        if [[ $suspicious_count -gt 0 ]]; then
            log_warn "Total eventos sospechosos en logs: $suspicious_count"
            log_warn "Revisar logs en $libvirt_log_dir para posibles intentos de escape"
        else
            log_info "Sin eventos sospechosos en logs de libvirt"
        fi
    else
        log_info "Directorio de logs de libvirt no encontrado"
    fi

    # --- Verificar sysctl de seguridad para VMs ---
    log_info "Verificando sysctl de seguridad relevantes para VMs..."

    local kptr_restrict
    kptr_restrict=$(sysctl -n kernel.kptr_restrict 2>/dev/null || echo "unknown")
    if [[ "$kptr_restrict" == "2" ]]; then
        log_info "kernel.kptr_restrict = 2 (correcto - oculta punteros del kernel)"
    elif [[ "$kptr_restrict" == "1" ]]; then
        log_info "kernel.kptr_restrict = 1 (parcial - solo root ve punteros)"
    else
        log_warn "kernel.kptr_restrict = $kptr_restrict (deberia ser 2)"
    fi

    local dmesg_restrict
    dmesg_restrict=$(sysctl -n kernel.dmesg_restrict 2>/dev/null || echo "unknown")
    if [[ "$dmesg_restrict" == "1" ]]; then
        log_info "kernel.dmesg_restrict = 1 (correcto)"
    else
        log_warn "kernel.dmesg_restrict = $dmesg_restrict (deberia ser 1)"
    fi

    local perf_event
    perf_event=$(sysctl -n kernel.perf_event_paranoid 2>/dev/null || echo "unknown")
    if [[ "$perf_event" -ge 2 ]] 2>/dev/null; then
        log_info "kernel.perf_event_paranoid = $perf_event (correcto)"
    else
        log_warn "kernel.perf_event_paranoid = $perf_event (deberia ser >= 2)"
    fi

    local unprivileged_bpf
    unprivileged_bpf=$(sysctl -n kernel.unprivileged_bpf_disabled 2>/dev/null || echo "unknown")
    if [[ "$unprivileged_bpf" == "1" ]]; then
        log_info "kernel.unprivileged_bpf_disabled = 1 (correcto)"
    else
        log_warn "kernel.unprivileged_bpf_disabled = $unprivileged_bpf (deberia ser 1)"
    fi

    local unprivileged_userns
    unprivileged_userns=$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo "not_present")
    if [[ "$unprivileged_userns" == "0" ]]; then
        log_info "kernel.unprivileged_userns_clone = 0 (correcto - reduce escape vectors)"
    elif [[ "$unprivileged_userns" != "not_present" ]]; then
        log_warn "kernel.unprivileged_userns_clone = $unprivileged_userns (considerar 0 para servidores)"
    fi

    # --- Script de verificacion de escape ---
    local escape_script="/usr/local/bin/verificar-escape-vm.sh"
    if check_executable "$escape_script"; then
        log_already "Script de verificacion de escape de VM ($escape_script existe)"
    elif ask "Crear script de verificacion de escape de VM en $escape_script?"; then
        cat > "$escape_script" <<'ESCEOF'
#!/bin/bash
# ============================================================
# verificar-escape-vm.sh - Verificacion de protecciones contra escape de VM
# Generado por securizar modulo 57
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

LOG_DIR="/var/log/securizar/vm-monitor"
mkdir -p "$LOG_DIR" 2>/dev/null || true
REPORT="$LOG_DIR/escape-check-$(date +%Y%m%d-%H%M%S).log"

echo "=== Verificacion de proteccion contra escape de VM ===" | tee "$REPORT"
echo "Fecha: $(date -Iseconds)" | tee -a "$REPORT"
echo "Kernel: $(uname -r)" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

ISSUES=0
CHECKS=0

check_pass() { ((CHECKS++)); echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$REPORT"; }
check_fail() { ((CHECKS++)); ((ISSUES++)); echo -e "${RED}[FAIL]${NC} $1" | tee -a "$REPORT"; }
check_warn() { ((CHECKS++)); echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$REPORT"; }

# --- Kernel ---
echo "=== Kernel ===" | tee -a "$REPORT"
KERNEL_VER=$(uname -r | cut -d- -f1)
MAJOR=$(echo "$KERNEL_VER" | cut -d. -f1)
MINOR=$(echo "$KERNEL_VER" | cut -d. -f2)

if [[ "$MAJOR" -ge 6 ]]; then
    check_pass "Kernel $KERNEL_VER (6.x+ - reciente)"
elif [[ "$MAJOR" -eq 5 && "$MINOR" -ge 15 ]]; then
    check_pass "Kernel $KERNEL_VER (5.15+ - LTS reciente)"
elif [[ "$MAJOR" -eq 5 ]]; then
    check_warn "Kernel $KERNEL_VER (5.x anterior a 5.15)"
else
    check_fail "Kernel $KERNEL_VER (antiguo - multiples CVEs)"
fi

# --- IOMMU ---
echo "" | tee -a "$REPORT"
echo "=== IOMMU ===" | tee -a "$REPORT"
if [[ -d /sys/class/iommu ]] && [[ -n "$(ls -A /sys/class/iommu/ 2>/dev/null)" ]]; then
    check_pass "IOMMU activo"
else
    check_fail "IOMMU NO activo"
fi

# --- Nested virtualization ---
echo "" | tee -a "$REPORT"
echo "=== Nested Virtualization ===" | tee -a "$REPORT"
for f in /sys/module/kvm_intel/parameters/nested /sys/module/kvm_amd/parameters/nested; do
    if [[ -f "$f" ]]; then
        val=$(cat "$f" 2>/dev/null || echo "?")
        if [[ "$val" == "N" || "$val" == "0" ]]; then
            check_pass "Nested virtualization deshabilitada ($f)"
        else
            check_warn "Nested virtualization HABILITADA ($f = $val)"
        fi
    fi
done

# --- QEMU version ---
echo "" | tee -a "$REPORT"
echo "=== QEMU ===" | tee -a "$REPORT"
if command -v qemu-system-x86_64 &>/dev/null; then
    QEMU_VER=$(qemu-system-x86_64 --version 2>/dev/null | head -1 || echo "unknown")
    echo "Version: $QEMU_VER" | tee -a "$REPORT"
    QEMU_NUM=$(echo "$QEMU_VER" | grep -oP '\d+\.\d+' | head -1 || echo "0.0")
    QEMU_MAJ=$(echo "$QEMU_NUM" | cut -d. -f1)
    if [[ "$QEMU_MAJ" -ge 7 ]]; then
        check_pass "QEMU $QEMU_NUM (reciente)"
    elif [[ "$QEMU_MAJ" -ge 6 ]]; then
        check_warn "QEMU $QEMU_NUM (considerar actualizar)"
    else
        check_fail "QEMU $QEMU_NUM (antiguo - CVEs conocidos de escape)"
    fi
fi

# --- Seccomp ---
echo "" | tee -a "$REPORT"
echo "=== Seccomp ===" | tee -a "$REPORT"
QEMU_CONF="/etc/libvirt/qemu.conf"
if [[ -f "$QEMU_CONF" ]]; then
    if grep -qE '^\s*seccomp_sandbox\s*=\s*1' "$QEMU_CONF" 2>/dev/null; then
        check_pass "seccomp sandbox habilitado"
    elif grep -qE '^\s*seccomp_sandbox\s*=\s*0' "$QEMU_CONF" 2>/dev/null; then
        check_fail "seccomp sandbox DESHABILITADO"
    else
        check_warn "seccomp sandbox no configurado explicitamente"
    fi
fi

# --- Sysctl ---
echo "" | tee -a "$REPORT"
echo "=== Sysctl de seguridad ===" | tee -a "$REPORT"

val=$(sysctl -n kernel.kptr_restrict 2>/dev/null || echo "?")
if [[ "$val" -ge 1 ]] 2>/dev/null; then
    check_pass "kptr_restrict = $val"
else
    check_fail "kptr_restrict = $val (deberia ser >= 1)"
fi

val=$(sysctl -n kernel.dmesg_restrict 2>/dev/null || echo "?")
if [[ "$val" == "1" ]]; then
    check_pass "dmesg_restrict = 1"
else
    check_warn "dmesg_restrict = $val"
fi

val=$(sysctl -n kernel.perf_event_paranoid 2>/dev/null || echo "?")
if [[ "$val" -ge 2 ]] 2>/dev/null; then
    check_pass "perf_event_paranoid = $val"
else
    check_warn "perf_event_paranoid = $val (deberia ser >= 2)"
fi

val=$(sysctl -n kernel.unprivileged_bpf_disabled 2>/dev/null || echo "?")
if [[ "$val" == "1" ]]; then
    check_pass "unprivileged_bpf_disabled = 1"
else
    check_warn "unprivileged_bpf_disabled = $val"
fi

# --- CPU vulnerabilities ---
echo "" | tee -a "$REPORT"
echo "=== Vulnerabilidades de CPU ===" | tee -a "$REPORT"
if [[ -d /sys/devices/system/cpu/vulnerabilities ]]; then
    for vuln_file in /sys/devices/system/cpu/vulnerabilities/*; do
        [[ -f "$vuln_file" ]] || continue
        vuln_name=$(basename "$vuln_file")
        vuln_status=$(cat "$vuln_file" 2>/dev/null || echo "unknown")
        if echo "$vuln_status" | grep -qi 'not affected\|mitigat' 2>/dev/null; then
            check_pass "$vuln_name: $vuln_status"
        elif echo "$vuln_status" | grep -qi 'vulnerable' 2>/dev/null; then
            check_fail "$vuln_name: $vuln_status"
        else
            check_warn "$vuln_name: $vuln_status"
        fi
    done
fi

# --- Logs sospechosos ---
echo "" | tee -a "$REPORT"
echo "=== Logs de libvirt ===" | tee -a "$REPORT"
LIBVIRT_LOG="/var/log/libvirt"
if [[ -d "$LIBVIRT_LOG" ]]; then
    suspicious=0
    for logf in "$LIBVIRT_LOG"/*.log "$LIBVIRT_LOG"/qemu/*.log; do
        [[ -f "$logf" ]] || continue
        cnt=$(grep -ci 'crash\|segfault\|SIGSEGV\|SIGABRT\|core dump' "$logf" 2>/dev/null || echo "0")
        if [[ "$cnt" -gt 0 ]]; then
            check_warn "$(basename "$logf"): $cnt eventos sospechosos"
            suspicious=$((suspicious + cnt))
        fi
    done
    if [[ $suspicious -eq 0 ]]; then
        check_pass "Sin eventos sospechosos en logs"
    fi
else
    echo "Directorio de logs no encontrado" | tee -a "$REPORT"
fi

# --- Resumen ---
echo "" | tee -a "$REPORT"
echo "=== Resumen ===" | tee -a "$REPORT"
echo "Total verificaciones: $CHECKS" | tee -a "$REPORT"
echo "Problemas: $ISSUES" | tee -a "$REPORT"

if [[ $ISSUES -eq 0 ]]; then
    echo -e "${GREEN}Estado: BUENO - Protecciones contra escape adecuadas${NC}" | tee -a "$REPORT"
elif [[ $ISSUES -le 3 ]]; then
    echo -e "${YELLOW}Estado: MEJORABLE${NC}" | tee -a "$REPORT"
else
    echo -e "${RED}Estado: DEFICIENTE - Se requieren correcciones urgentes${NC}" | tee -a "$REPORT"
fi

echo ""
echo -e "${CYAN}Reporte guardado en: $REPORT${NC}"
exit $ISSUES
ESCEOF
        chmod +x "$escape_script"
        log_change "Creado" "$escape_script"
    else
        log_skip "Script de verificacion de escape de VM"
    fi
}

protect_vm_escape


###############################################################################
# S9: MONITORIZACION DE VMS
###############################################################################
log_section "S9: Monitorizacion de VMs"

setup_vm_monitoring() {
    log_info "Configurando monitorizacion de VMs..."

    # Crear directorio de logs
    if [[ ! -d "$VIRT_LOG_DIR" ]]; then
        mkdir -p "$VIRT_LOG_DIR"
        chmod 750 "$VIRT_LOG_DIR"
        log_change "Creado" "$VIRT_LOG_DIR para logs de monitorizacion"
    fi

    # --- Script de monitorizacion ---
    local monitor_script="/usr/local/bin/monitorizar-vms.sh"
    if check_executable "$monitor_script"; then
        log_already "Script de monitorizacion de VMs ($monitor_script existe)"
    elif ask "Crear script de monitorizacion de VMs en $monitor_script?"; then
        cat > "$monitor_script" <<'MONEOF'
#!/bin/bash
# ============================================================
# monitorizar-vms.sh - Monitorizacion de seguridad de VMs
# Generado por securizar modulo 57
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

LOG_DIR="/var/log/securizar/vm-monitor"
mkdir -p "$LOG_DIR" 2>/dev/null || true
REPORT="$LOG_DIR/vm-monitor-$(date +%Y%m%d-%H%M%S).log"
TIMESTAMP=$(date -Iseconds)

# Modo silencioso para cron
QUIET="${1:-}"

log() {
    if [[ "$QUIET" != "--quiet" ]]; then
        echo -e "$1"
    fi
    echo "$1" | sed 's/\x1b\[[0-9;]*m//g' >> "$REPORT"
}

log "=== Monitorizacion de VMs ==="
log "Fecha: $TIMESTAMP"
log "Host: $(hostname)"
log ""

# ===========================
# INVENTARIO DE VMs
# ===========================
log "=== INVENTARIO DE VMs ==="

if ! command -v virsh &>/dev/null; then
    log "virsh no disponible - inventario limitado"
else
    # Listar todas las VMs
    vm_list=$(virsh list --all 2>/dev/null || echo "")
    log "$vm_list"
    log ""

    total_vms=$(virsh list --all --name 2>/dev/null | grep -c '.' || echo "0")
    running_vms=$(virsh list --state-running --name 2>/dev/null | grep -c '.' || echo "0")
    stopped_vms=$((total_vms - running_vms))

    log "Total VMs: $total_vms (Corriendo: $running_vms, Detenidas: $stopped_vms)"
    log ""

    # ===========================
    # POSTURA DE SEGURIDAD POR VM
    # ===========================
    log "=== POSTURA DE SEGURIDAD POR VM ==="

    for vm in $(virsh list --all --name 2>/dev/null); do
        [[ -z "$vm" ]] && continue
        log ""
        log "--- VM: $vm ---"

        vm_state=$(virsh domstate "$vm" 2>/dev/null || echo "unknown")
        log "  Estado: $vm_state"

        if [[ "$vm_state" == "running" ]]; then
            # CPU y memoria
            vm_info=$(virsh dominfo "$vm" 2>/dev/null || echo "")
            cpu_count=$(echo "$vm_info" | grep 'CPU(s)' | awk '{print $2}' || echo "?")
            max_mem=$(echo "$vm_info" | grep 'Max memory' | awk '{print $3, $4}' || echo "?")
            used_mem=$(echo "$vm_info" | grep 'Used memory' | awk '{print $3, $4}' || echo "?")
            log "  CPUs: $cpu_count | Memoria max: $max_mem | Memoria usada: $used_mem"

            # CPU stats
            cpu_time=$(virsh cpu-stats "$vm" --total 2>/dev/null | grep 'cpu_time' | awk '{print $2}' || echo "?")
            log "  CPU time total: $cpu_time"

            # Block stats
            log "  Discos:"
            for dev in $(virsh domblklist "$vm" --details 2>/dev/null | awk 'NR>2 && $1!="" {print $3}'); do
                [[ -z "$dev" ]] && continue
                blk_info=$(virsh domblkinfo "$vm" "$dev" 2>/dev/null || echo "")
                capacity=$(echo "$blk_info" | grep 'Capacity' | awk '{print $2}' || echo "?")
                allocation=$(echo "$blk_info" | grep 'Allocation' | awk '{print $2}' || echo "?")
                log "    $dev: capacidad=$(numfmt --to=iec "$capacity" 2>/dev/null || echo "${capacity}B") usado=$(numfmt --to=iec "$allocation" 2>/dev/null || echo "${allocation}B")"
            done

            # Network stats
            log "  Interfaces de red:"
            for iface in $(virsh domiflist "$vm" 2>/dev/null | awk 'NR>2 && $1!="" {print $1}'); do
                [[ -z "$iface" ]] && continue
                if_stats=$(virsh domifstat "$vm" "$iface" 2>/dev/null || echo "")
                rx_bytes=$(echo "$if_stats" | grep 'rx_bytes' | awk '{print $2}' || echo "0")
                tx_bytes=$(echo "$if_stats" | grep 'tx_bytes' | awk '{print $2}' || echo "0")
                rx_human=$(numfmt --to=iec "$rx_bytes" 2>/dev/null || echo "${rx_bytes}B")
                tx_human=$(numfmt --to=iec "$tx_bytes" 2>/dev/null || echo "${tx_bytes}B")
                log "    $iface: RX=$rx_human TX=$tx_human"
            done

            # Guest agent status
            ga_status="no disponible"
            if virsh qemu-agent-command "$vm" '{"execute":"guest-ping"}' &>/dev/null; then
                ga_status="activo"
            fi
            log "  Guest agent: $ga_status"
        fi

        # Security posture
        vm_xml=$(virsh dumpxml "$vm" 2>/dev/null || echo "")
        sec_score=0
        sec_max=7

        # Check security features
        if echo "$vm_xml" | grep -q 'name="spec-ctrl"'; then ((sec_score++)); fi
        if echo "$vm_xml" | grep -q 'name="ssbd"'; then ((sec_score++)); fi
        if echo "$vm_xml" | grep -q 'name="md-clear"'; then ((sec_score++)); fi
        if echo "$vm_xml" | grep -q 'memballoon model="none"'; then ((sec_score++)); fi
        if echo "$vm_xml" | grep -q '<filterref'; then ((sec_score++)); fi
        if ! echo "$vm_xml" | grep -q '<sound'; then ((sec_score++)); fi
        if ! echo "$vm_xml" | grep -q 'listen.*0.0.0.0'; then ((sec_score++)); fi

        if [[ $sec_score -ge 6 ]]; then
            log "  Seguridad: ${sec_score}/${sec_max} - BUENO"
        elif [[ $sec_score -ge 4 ]]; then
            log "  Seguridad: ${sec_score}/${sec_max} - MEJORABLE"
        else
            log "  Seguridad: ${sec_score}/${sec_max} - DEFICIENTE"
        fi
    done

    # ===========================
    # SNAPSHOTS
    # ===========================
    log ""
    log "=== SNAPSHOTS ==="

    stale_snapshots=0
    for vm in $(virsh list --all --name 2>/dev/null); do
        [[ -z "$vm" ]] && continue
        snaps=$(virsh snapshot-list "$vm" --name 2>/dev/null || echo "")
        [[ -z "$snaps" ]] && continue

        log "VM: $vm"
        while IFS= read -r snap; do
            [[ -z "$snap" ]] && continue
            snap_info=$(virsh snapshot-info "$vm" "$snap" 2>/dev/null || echo "")
            snap_date=$(echo "$snap_info" | grep 'Creation time' | sed 's/Creation time:\s*//' || echo "")
            snap_ts=$(date -d "$snap_date" +%s 2>/dev/null || echo "0")
            now_ts=$(date +%s)

            if [[ "$snap_ts" -gt 0 ]]; then
                age_days=$(( (now_ts - snap_ts) / 86400 ))
                if [[ $age_days -gt 90 ]]; then
                    log "  STALE: $snap ($age_days dias) - $snap_date"
                    ((stale_snapshots++))
                elif [[ $age_days -gt 30 ]]; then
                    log "  OLD: $snap ($age_days dias) - $snap_date"
                else
                    log "  OK: $snap ($age_days dias) - $snap_date"
                fi
            else
                log "  $snap - fecha: $snap_date"
            fi
        done <<< "$snaps"
    done

    if [[ $stale_snapshots -gt 0 ]]; then
        log ""
        log "ATENCION: $stale_snapshots snapshots con mas de 90 dias"
        log "Los snapshots antiguos desperdician espacio y pueden ser riesgo de seguridad"
    fi

    # ===========================
    # REDES
    # ===========================
    log ""
    log "=== REDES DE VMs ==="
    virsh net-list --all 2>/dev/null | while IFS= read -r line; do
        log "  $line"
    done

    # ===========================
    # STORAGE POOLS
    # ===========================
    log ""
    log "=== STORAGE POOLS ==="
    virsh pool-list --all 2>/dev/null | while IFS= read -r line; do
        log "  $line"
    done

    # ===========================
    # RECURSOS DEL HOST
    # ===========================
    log ""
    log "=== RECURSOS DEL HOST ==="
    log "  CPU: $(nproc 2>/dev/null || echo '?') cores"
    log "  RAM: $(free -h 2>/dev/null | awk '/^Mem:/{print $2}' || echo '?') total, $(free -h 2>/dev/null | awk '/^Mem:/{print $3}' || echo '?') usado"
    log "  Swap: $(free -h 2>/dev/null | awk '/^Swap:/{print $2}' || echo '?') total"

    # Espacio en disco de pools
    for pool_path in /var/lib/libvirt/images /var/lib/virt; do
        if [[ -d "$pool_path" ]]; then
            df_info=$(df -h "$pool_path" 2>/dev/null | tail -1 || echo "")
            log "  Disco $pool_path: $df_info"
        fi
    done
fi

# ===========================
# CONTENEDORES
# ===========================
log ""
log "=== CONTENEDORES ==="
if command -v machinectl &>/dev/null; then
    nspawn_list=$(machinectl list --no-legend 2>/dev/null || echo "")
    if [[ -n "$nspawn_list" ]]; then
        log "systemd-nspawn:"
        echo "$nspawn_list" | while IFS= read -r line; do
            log "  $line"
        done
    fi
fi

if command -v lxc-ls &>/dev/null; then
    lxc_list=$(lxc-ls -f 2>/dev/null || echo "")
    if [[ -n "$lxc_list" ]]; then
        log "LXC:"
        echo "$lxc_list" | while IFS= read -r line; do
            log "  $line"
        done
    fi
fi

log ""
log "=== Fin del reporte ==="
log "Reporte guardado en: $REPORT"

# Limpiar reportes antiguos (> 30 dias)
find "$LOG_DIR" -name "vm-monitor-*.log" -mtime +30 -delete 2>/dev/null || true
MONEOF
        chmod +x "$monitor_script"
        log_change "Creado" "$monitor_script"
    else
        log_skip "Script de monitorizacion de VMs"
    fi

    # --- Timer systemd para ejecucion periodica ---
    if ask "Crear timer systemd para monitorizacion periodica de VMs?"; then
        local timer_service="/etc/systemd/system/securizar-vm-monitor.service"
        local timer_timer="/etc/systemd/system/securizar-vm-monitor.timer"

        cat > "$timer_service" <<'SVCEOF'
[Unit]
Description=Securizar - Monitorizacion de VMs
After=libvirtd.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/monitorizar-vms.sh --quiet
Nice=10
IOSchedulingClass=idle
SVCEOF
        log_change "Creado" "$timer_service"

        cat > "$timer_timer" <<'TMEOF'
[Unit]
Description=Timer para monitorizacion de VMs (cada 6 horas)

[Timer]
OnCalendar=*-*-* 00/6:00:00
RandomizedDelaySec=300
Persistent=true

[Install]
WantedBy=timers.target
TMEOF
        log_change "Creado" "$timer_timer"

        systemctl daemon-reload 2>/dev/null || true
        systemctl enable securizar-vm-monitor.timer 2>/dev/null || true
        systemctl start securizar-vm-monitor.timer 2>/dev/null || true
        log_change "Habilitado" "Timer securizar-vm-monitor (cada 6 horas)"
    else
        log_skip "Timer systemd para monitorizacion de VMs"
    fi

    # --- Rotacion de logs ---
    local logrotate_conf="/etc/logrotate.d/securizar-vm-monitor"
    if [[ ! -f "$logrotate_conf" ]]; then
        if ask "Crear configuracion de logrotate para logs de VM?"; then
            cat > "$logrotate_conf" <<'LREOF'
/var/log/securizar/vm-monitor/*.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 640 root root
}
LREOF
            chmod 644 "$logrotate_conf"
            log_change "Creado" "$logrotate_conf"
        else
            log_skip "Logrotate para logs de VM"
        fi
    else
        log_info "Logrotate para VM monitor ya existe"
    fi
}

setup_vm_monitoring


###############################################################################
# S10: AUDITORIA INTEGRAL DE VIRTUALIZACION
###############################################################################
log_section "S10: Auditoria integral de virtualizacion"

setup_virt_audit() {
    log_info "Configurando auditoria integral de virtualizacion..."

    # --- Script de auditoria completa ---
    local audit_script="/usr/local/bin/auditar-virtualizacion.sh"
    if check_executable "$audit_script"; then
        log_already "Script de auditoria integral ($audit_script existe)"
    elif ask "Crear script de auditoria integral en $audit_script?"; then
        cat > "$audit_script" <<'AUDEOF'
#!/bin/bash
# ============================================================
# auditar-virtualizacion.sh - Auditoria integral de virtualizacion
# Generado por securizar modulo 57
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

FECHA=$(date +%Y%m%d-%H%M%S)
LOG_DIR="/var/log/securizar"
mkdir -p "$LOG_DIR" 2>/dev/null || true
REPORT="$LOG_DIR/auditoria-virt-${FECHA}.log"

TOTAL_CHECKS=0
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_WARN=0

# Score categories
SCORE_HYPERVISOR=0
SCORE_HYPERVISOR_MAX=0
SCORE_VM=0
SCORE_VM_MAX=0
SCORE_NETWORK=0
SCORE_NETWORK_MAX=0
SCORE_STORAGE=0
SCORE_STORAGE_MAX=0
SCORE_ESCAPE=0
SCORE_ESCAPE_MAX=0

report() { echo "$1" | tee -a "$REPORT"; }

check_pass() {
    local category="$1"
    local msg="$2"
    ((TOTAL_CHECKS++))
    ((TOTAL_PASS++))
    eval "((SCORE_${category}++))"
    eval "((SCORE_${category}_MAX++))"
    report "[PASS] $msg"
}

check_fail() {
    local category="$1"
    local msg="$2"
    ((TOTAL_CHECKS++))
    ((TOTAL_FAIL++))
    eval "((SCORE_${category}_MAX++))"
    report "[FAIL] $msg"
}

check_warn() {
    local category="$1"
    local msg="$2"
    ((TOTAL_CHECKS++))
    ((TOTAL_WARN++))
    eval "((SCORE_${category}_MAX++))"
    report "[WARN] $msg"
}

report "╔═══════════════════════════════════════════════════════════╗"
report "║   AUDITORIA INTEGRAL DE VIRTUALIZACION                    ║"
report "║   Generado por securizar modulo 57                        ║"
report "╚═══════════════════════════════════════════════════════════╝"
report ""
report "Fecha: $(date -Iseconds)"
report "Host: $(hostname)"
report "Kernel: $(uname -r)"
report "Distro: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"' || echo 'unknown')"
report ""

# ===========================
# A. EVALUACION DEL HYPERVISOR
# ===========================
report "══════════════════════════════════════════"
report "  A. EVALUACION DEL HYPERVISOR"
report "══════════════════════════════════════════"

# A1. Deteccion de entorno
vtype=$(systemd-detect-virt 2>/dev/null || echo "none")
if [[ "$vtype" == "none" ]]; then
    report "Rol: HOST (bare-metal)"
else
    report "Rol: GUEST (virtualizado: $vtype)"
fi

# A2. KVM/QEMU
if [[ -e /dev/kvm ]]; then
    check_pass "HYPERVISOR" "/dev/kvm disponible"

    kvm_perms=$(stat -c '%a' /dev/kvm 2>/dev/null || echo "???")
    if [[ "$kvm_perms" == "660" ]]; then
        check_pass "HYPERVISOR" "/dev/kvm permisos correctos ($kvm_perms)"
    else
        check_fail "HYPERVISOR" "/dev/kvm permisos incorrectos ($kvm_perms, deberia ser 660)"
    fi
fi

# A3. QEMU config
QEMU_CONF="/etc/libvirt/qemu.conf"
if [[ -f "$QEMU_CONF" ]]; then
    if grep -qE '^\s*security_driver\s*=\s*"(apparmor|selinux)"' "$QEMU_CONF" 2>/dev/null; then
        check_pass "HYPERVISOR" "Security driver MAC configurado"
    elif grep -qE '^\s*security_driver\s*=\s*"none"' "$QEMU_CONF" 2>/dev/null; then
        check_fail "HYPERVISOR" "Security driver = none"
    else
        check_warn "HYPERVISOR" "Security driver no configurado explicitamente"
    fi

    if grep -qE '^\s*vnc_tls\s*=\s*1' "$QEMU_CONF" 2>/dev/null; then
        check_pass "HYPERVISOR" "VNC TLS habilitado"
    else
        check_warn "HYPERVISOR" "VNC TLS no habilitado"
    fi

    if grep -qE '^\s*seccomp_sandbox\s*=\s*1' "$QEMU_CONF" 2>/dev/null; then
        check_pass "HYPERVISOR" "Seccomp sandbox habilitado"
    else
        check_warn "HYPERVISOR" "Seccomp sandbox no configurado"
    fi
fi

# A4. Libvirt config
LIBVIRT_CONF="/etc/libvirt/libvirtd.conf"
if [[ -f "$LIBVIRT_CONF" ]]; then
    if grep -qE '^\s*listen_tcp\s*=\s*0' "$LIBVIRT_CONF" 2>/dev/null || ! grep -qE '^\s*listen_tcp\s*=\s*1' "$LIBVIRT_CONF" 2>/dev/null; then
        check_pass "HYPERVISOR" "TCP sin cifrar deshabilitado"
    else
        check_fail "HYPERVISOR" "TCP sin cifrar habilitado"
    fi

    if grep -qE '^\s*audit_level\s*=\s*2' "$LIBVIRT_CONF" 2>/dev/null; then
        check_pass "HYPERVISOR" "Audit level completo (2)"
    else
        check_warn "HYPERVISOR" "Audit level no configurado a nivel completo"
    fi

    if grep -qE '^\s*auth_unix_rw\s*=\s*"polkit"' "$LIBVIRT_CONF" 2>/dev/null; then
        check_pass "HYPERVISOR" "Autenticacion polkit para escritura"
    elif grep -qE '^\s*auth_unix_rw\s*=\s*"none"' "$LIBVIRT_CONF" 2>/dev/null; then
        check_fail "HYPERVISOR" "Autenticacion none para escritura"
    else
        check_warn "HYPERVISOR" "Autenticacion no configurada explicitamente"
    fi

    if grep -qE '^\s*unix_sock_rw_perms\s*=\s*"0770"' "$LIBVIRT_CONF" 2>/dev/null; then
        check_pass "HYPERVISOR" "Socket permisos restrictivos (0770)"
    elif grep -qE '^\s*unix_sock_rw_perms\s*=\s*"0777"' "$LIBVIRT_CONF" 2>/dev/null; then
        check_fail "HYPERVISOR" "Socket permisos abiertos (0777)"
    else
        check_warn "HYPERVISOR" "Socket permisos no configurados explicitamente"
    fi
fi

# ===========================
# B. AUDITORIA POR VM
# ===========================
report ""
report "══════════════════════════════════════════"
report "  B. AUDITORIA POR VM"
report "══════════════════════════════════════════"

if command -v virsh &>/dev/null; then
    for vm in $(virsh list --all --name 2>/dev/null); do
        [[ -z "$vm" ]] && continue
        report ""
        report "--- VM: $vm ---"

        vm_xml=$(virsh dumpxml "$vm" 2>/dev/null || echo "")
        [[ -z "$vm_xml" ]] && continue

        # CPU mitigations
        if echo "$vm_xml" | grep -q 'name="spec-ctrl"'; then
            check_pass "VM" "$vm: spec-ctrl habilitado"
        else
            check_fail "VM" "$vm: spec-ctrl NO habilitado"
        fi

        if echo "$vm_xml" | grep -q 'name="ssbd"'; then
            check_pass "VM" "$vm: ssbd habilitado"
        else
            check_fail "VM" "$vm: ssbd NO habilitado"
        fi

        if echo "$vm_xml" | grep -q 'name="md-clear"'; then
            check_pass "VM" "$vm: md-clear habilitado"
        else
            check_warn "VM" "$vm: md-clear NO habilitado"
        fi

        # memballoon
        if echo "$vm_xml" | grep -q 'memballoon model="none"'; then
            check_pass "VM" "$vm: memballoon deshabilitado"
        else
            check_warn "VM" "$vm: memballoon habilitado"
        fi

        # nwfilter
        if echo "$vm_xml" | grep -q '<filterref'; then
            check_pass "VM" "$vm: nwfilter aplicado"
        else
            check_fail "VM" "$vm: sin nwfilter"
        fi

        # VNC binding
        if echo "$vm_xml" | grep -q 'listen.*0.0.0.0'; then
            check_fail "VM" "$vm: VNC/SPICE en 0.0.0.0"
        else
            check_pass "VM" "$vm: VNC/SPICE binding seguro"
        fi

        # USB
        if echo "$vm_xml" | grep -q '<controller type="usb"'; then
            check_warn "VM" "$vm: USB controller presente"
        else
            check_pass "VM" "$vm: sin USB controller"
        fi
    done
else
    report "virsh no disponible - auditoria de VMs omitida"
fi

# ===========================
# C. VERIFICACION DE AISLAMIENTO DE RED
# ===========================
report ""
report "══════════════════════════════════════════"
report "  C. AISLAMIENTO DE RED"
report "══════════════════════════════════════════"

if command -v virsh &>/dev/null; then
    for net in $(virsh net-list --all --name 2>/dev/null); do
        [[ -z "$net" ]] && continue
        net_xml=$(virsh net-dumpxml "$net" 2>/dev/null || echo "")

        if [[ "$net" == "default" ]] && echo "$net_xml" | grep -q '<forward mode=.nat.'; then
            check_warn "NETWORK" "Red 'default' NAT activa (menos segura)"
        fi

        if ! echo "$net_xml" | grep -q '<forward'; then
            check_pass "NETWORK" "Red '$net' aislada"
        fi

        if echo "$net_xml" | grep -q '<forward mode=.open.'; then
            check_fail "NETWORK" "Red '$net' en modo open (sin restricciones)"
        fi
    done

    # Verificar nwfilters basicos
    for filter in clean-traffic no-mac-spoofing no-ip-spoofing no-arp-spoofing; do
        if virsh nwfilter-list 2>/dev/null | grep -q "$filter"; then
            check_pass "NETWORK" "nwfilter '$filter' disponible"
        else
            check_warn "NETWORK" "nwfilter '$filter' no disponible"
        fi
    done

    # Firewall FORWARD rules
    if command -v iptables &>/dev/null; then
        fwd_rules=$(iptables -L FORWARD -n 2>/dev/null | grep -c -v '^Chain\|^target\|^$' || echo "0")
        if [[ "$fwd_rules" -gt 0 ]]; then
            check_pass "NETWORK" "Reglas FORWARD en iptables: $fwd_rules"
        else
            check_warn "NETWORK" "Sin reglas FORWARD en iptables"
        fi
    fi
fi

# ===========================
# D. SEGURIDAD DE ALMACENAMIENTO
# ===========================
report ""
report "══════════════════════════════════════════"
report "  D. SEGURIDAD DE ALMACENAMIENTO"
report "══════════════════════════════════════════"

IMAGE_DIRS="/var/lib/libvirt/images /var/lib/virt/images /home/virt /srv/virt"
for dir in $IMAGE_DIRS; do
    [[ -d "$dir" ]] || continue

    dir_perms=$(stat -c '%a' "$dir" 2>/dev/null || echo "???")
    if [[ "${dir_perms:2:1}" =~ [0] ]]; then
        check_pass "STORAGE" "Directorio $dir: permisos $dir_perms (no accesible por others)"
    else
        check_fail "STORAGE" "Directorio $dir: permisos $dir_perms (accesible por others)"
    fi

    while IFS= read -r img; do
        [[ -z "$img" ]] && continue
        perms=$(stat -c '%a' "$img" 2>/dev/null || echo "???")
        if [[ "$perms" == "600" || "$perms" == "640" ]]; then
            check_pass "STORAGE" "$(basename "$img"): permisos $perms"
        elif [[ "${perms:2:1}" =~ [4-7] ]]; then
            check_fail "STORAGE" "$(basename "$img"): permisos $perms (world-readable)"
        else
            check_warn "STORAGE" "$(basename "$img"): permisos $perms"
        fi
    done < <(find "$dir" -maxdepth 2 -type f \( -name "*.qcow2" -o -name "*.raw" -o -name "*.vmdk" -o -name "*.img" \) 2>/dev/null)
done

# ===========================
# E. PROTECCION CONTRA ESCAPE
# ===========================
report ""
report "══════════════════════════════════════════"
report "  E. PROTECCION CONTRA ESCAPE"
report "══════════════════════════════════════════"

# IOMMU
if [[ -d /sys/class/iommu ]] && [[ -n "$(ls -A /sys/class/iommu/ 2>/dev/null)" ]]; then
    check_pass "ESCAPE" "IOMMU activo"
else
    check_fail "ESCAPE" "IOMMU no activo"
fi

# Nested
for f in /sys/module/kvm_intel/parameters/nested /sys/module/kvm_amd/parameters/nested; do
    if [[ -f "$f" ]]; then
        val=$(cat "$f" 2>/dev/null || echo "?")
        if [[ "$val" == "N" || "$val" == "0" ]]; then
            check_pass "ESCAPE" "Nested virtualization deshabilitada"
        else
            check_warn "ESCAPE" "Nested virtualization habilitada"
        fi
    fi
done

# Sysctl
for param_check in "kernel.kptr_restrict:1" "kernel.dmesg_restrict:1" "kernel.perf_event_paranoid:2" "kernel.unprivileged_bpf_disabled:1"; do
    param=$(echo "$param_check" | cut -d: -f1)
    expected=$(echo "$param_check" | cut -d: -f2)
    actual=$(sysctl -n "$param" 2>/dev/null || echo "?")
    if [[ "$actual" -ge "$expected" ]] 2>/dev/null; then
        check_pass "ESCAPE" "$param = $actual"
    else
        check_warn "ESCAPE" "$param = $actual (recomendado >= $expected)"
    fi
done

# CPU vulnerabilities
if [[ -d /sys/devices/system/cpu/vulnerabilities ]]; then
    for vuln_file in /sys/devices/system/cpu/vulnerabilities/*; do
        [[ -f "$vuln_file" ]] || continue
        vuln_name=$(basename "$vuln_file")
        vuln_status=$(cat "$vuln_file" 2>/dev/null || echo "unknown")
        if echo "$vuln_status" | grep -qi 'not affected\|mitigat'; then
            check_pass "ESCAPE" "CPU $vuln_name: mitigado"
        elif echo "$vuln_status" | grep -qi 'vulnerable'; then
            check_fail "ESCAPE" "CPU $vuln_name: VULNERABLE ($vuln_status)"
        fi
    done
fi

# ===========================
# RESUMEN Y SCORE
# ===========================
report ""
report "══════════════════════════════════════════"
report "  RESUMEN DE AUDITORIA"
report "══════════════════════════════════════════"
report ""
report "Total verificaciones: $TOTAL_CHECKS"
report "  Correctas: $TOTAL_PASS"
report "  Advertencias: $TOTAL_WARN"
report "  Fallidas: $TOTAL_FAIL"
report ""

# Calculate overall percentage
overall_score=0
overall_max=$((SCORE_HYPERVISOR_MAX + SCORE_VM_MAX + SCORE_NETWORK_MAX + SCORE_STORAGE_MAX + SCORE_ESCAPE_MAX))
overall_pass=$((SCORE_HYPERVISOR + SCORE_VM + SCORE_NETWORK + SCORE_STORAGE + SCORE_ESCAPE))

if [[ $overall_max -gt 0 ]]; then
    overall_score=$(( (overall_pass * 100) / overall_max ))
fi

report "Scores por categoria:"
if [[ $SCORE_HYPERVISOR_MAX -gt 0 ]]; then
    report "  Hypervisor: ${SCORE_HYPERVISOR}/${SCORE_HYPERVISOR_MAX}"
fi
if [[ $SCORE_VM_MAX -gt 0 ]]; then
    report "  VMs: ${SCORE_VM}/${SCORE_VM_MAX}"
fi
if [[ $SCORE_NETWORK_MAX -gt 0 ]]; then
    report "  Red: ${SCORE_NETWORK}/${SCORE_NETWORK_MAX}"
fi
if [[ $SCORE_STORAGE_MAX -gt 0 ]]; then
    report "  Almacenamiento: ${SCORE_STORAGE}/${SCORE_STORAGE_MAX}"
fi
if [[ $SCORE_ESCAPE_MAX -gt 0 ]]; then
    report "  Escape protection: ${SCORE_ESCAPE}/${SCORE_ESCAPE_MAX}"
fi
report ""
report "Score global: ${overall_pass}/${overall_max} (${overall_score}%)"
report ""

if [[ $overall_score -ge 80 ]]; then
    report "╔═══════════════════════════════════════════╗"
    report "║   RESULTADO: BUENO (${overall_score}%)                  ║"
    report "╚═══════════════════════════════════════════╝"
elif [[ $overall_score -ge 50 ]]; then
    report "╔═══════════════════════════════════════════╗"
    report "║   RESULTADO: MEJORABLE (${overall_score}%)              ║"
    report "╚═══════════════════════════════════════════╝"
else
    report "╔═══════════════════════════════════════════╗"
    report "║   RESULTADO: DEFICIENTE (${overall_score}%)             ║"
    report "╚═══════════════════════════════════════════╝"
fi

report ""
report "Reporte guardado en: $REPORT"

# Limpiar reportes antiguos (> 90 dias)
find "$LOG_DIR" -name "auditoria-virt-*.log" -mtime +90 -delete 2>/dev/null || true
AUDEOF
        chmod +x "$audit_script"
        log_change "Creado" "$audit_script"
    else
        log_skip "Script de auditoria integral"
    fi

    # --- Cron semanal ---
    local cron_audit="/etc/cron.weekly/auditoria-virtualizacion"
    if ask "Crear tarea cron semanal para auditoria de virtualizacion?"; then
        cat > "$cron_audit" <<'CREOF'
#!/bin/bash
# Auditoria semanal de virtualizacion - securizar modulo 57
# Se ejecuta via cron.weekly

LOG_DIR="/var/log/securizar"
mkdir -p "$LOG_DIR" 2>/dev/null || true

# Ejecutar auditoria
if [[ -x /usr/local/bin/auditar-virtualizacion.sh ]]; then
    /usr/local/bin/auditar-virtualizacion.sh > /dev/null 2>&1 || true
fi

# Ejecutar monitorizacion
if [[ -x /usr/local/bin/monitorizar-vms.sh ]]; then
    /usr/local/bin/monitorizar-vms.sh --quiet > /dev/null 2>&1 || true
fi

# Ejecutar verificacion de escape
if [[ -x /usr/local/bin/verificar-escape-vm.sh ]]; then
    /usr/local/bin/verificar-escape-vm.sh > /dev/null 2>&1 || true
fi

# Verificar almacenamiento
if [[ -x /usr/local/bin/auditar-storage-vm.sh ]]; then
    /usr/local/bin/auditar-storage-vm.sh > /dev/null 2>&1 || true
fi

# Verificar contenedores
if [[ -x /usr/local/bin/auditar-contenedores-locales.sh ]]; then
    /usr/local/bin/auditar-contenedores-locales.sh > /dev/null 2>&1 || true
fi

# Limpiar logs antiguos (> 90 dias)
find "$LOG_DIR" -name "auditoria-virt-*.log" -mtime +90 -delete 2>/dev/null || true
find "$LOG_DIR/vm-monitor" -name "*.log" -mtime +90 -delete 2>/dev/null || true
CREOF
        chmod +x "$cron_audit"
        log_change "Creado" "$cron_audit (auditoria semanal)"
    else
        log_skip "Cron semanal de auditoria"
    fi

    # --- Resumen final del modulo ---
    log_info ""
    log_info "=== Scripts creados por el modulo 57 ==="
    local scripts_list=(
        "/usr/local/bin/securizar-libvirt.sh"
        "/usr/local/bin/auditar-storage-vm.sh"
        "/usr/local/bin/auditar-contenedores-locales.sh"
        "/usr/local/bin/verificar-escape-vm.sh"
        "/usr/local/bin/monitorizar-vms.sh"
        "/usr/local/bin/auditar-virtualizacion.sh"
    )
    for s in "${scripts_list[@]}"; do
        if [[ -x "$s" ]]; then
            log_info "  [OK] $s"
        else
            log_info "  [--] $s (no creado)"
        fi
    done

    log_info ""
    log_info "=== Archivos de configuracion ==="
    if [[ -f "$VIRT_ENV_CONF" ]]; then
        log_info "  [OK] $VIRT_ENV_CONF"
    fi
    if [[ -d "$VIRT_TEMPLATES_DIR" ]]; then
        log_info "  [OK] $VIRT_TEMPLATES_DIR/"
        for tmpl in "$VIRT_TEMPLATES_DIR"/*; do
            [[ -f "$tmpl" ]] && log_info "       $(basename "$tmpl")"
        done
    fi

    log_info ""
    log_info "=== Automatizacion ==="
    if [[ -f "/etc/cron.weekly/auditoria-virtualizacion" ]]; then
        log_info "  [OK] Cron semanal: /etc/cron.weekly/auditoria-virtualizacion"
    fi
    if systemctl is-enabled securizar-vm-monitor.timer &>/dev/null 2>&1; then
        log_info "  [OK] Timer systemd: securizar-vm-monitor.timer (cada 6 horas)"
    fi
}

setup_virt_audit


###############################################################################
# RESUMEN FINAL
###############################################################################
log_section "MODULO 57 COMPLETADO"
log_info "Seguridad de virtualizacion configurada"
log_info "Distro: $DISTRO_NAME ($DISTRO_FAMILY)"
log_info "Backup en: $BACKUP_DIR"

show_changes_summary
