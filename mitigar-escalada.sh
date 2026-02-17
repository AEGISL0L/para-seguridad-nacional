#!/bin/bash
# ============================================================
# MITIGACIÓN DE ESCALADA DE PRIVILEGIOS - TA0004
# Linux Multi-Distro (openSUSE, Debian/Ubuntu, RHEL/Fedora, Arch)
# ============================================================
# Técnicas MITRE ATT&CK cubiertas:
#   T1548 - Abuse Elevation Control Mechanism (SUID/SGID)
#   T1068 - Exploitation for Privilege Escalation
#   T1134 - Access Token Manipulation (capabilities)
#   T1055 - Process Injection
#   T1053 - Scheduled Task/Job (privesc via cron)
#   T1611 - Escape to Host (container escape)
#   T1078 - Valid Accounts (abuso de sudo)
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "mitigar-escalada"
securizar_setup_traps

_precheck 8
_pc true  # S1: auditoría SUID/SGID (detección)
_pc true  # S2: auditoría capabilities (detección)
_pc 'check_file_exists /etc/sudoers.d/99-hardening'
_pc 'check_file_exists /etc/sysctl.d/99-anti-privesc.conf'
_pc 'check_file_exists /etc/audit/rules.d/privesc-injection.rules'
_pc true  # S6: auditoría cron privesc (detección)
_pc true  # S7: archivos world-writable (detección)
_pc 'check_executable /usr/local/bin/detectar-escalada.sh'
_precheck_result

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MITIGACIÓN DE ESCALADA DE PRIVILEGIOS - TA0004          ║"
echo "║   Prevenir elevación no autorizada de privilegios          ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# ============================================================
log_section "1. AUDITORÍA DE BINARIOS SUID/SGID (T1548)"
# ============================================================

echo "Buscando binarios con SUID/SGID..."
echo ""

echo -e "${BOLD}Binarios SUID (ejecutar como propietario):${NC}"
SUID_COUNT=0
SUID_SUSPECT=0

# SUID esperados del sistema
KNOWN_SUIDS="/usr/bin/su /usr/bin/sudo /usr/bin/passwd /usr/bin/chfn /usr/bin/chsh /usr/bin/newgrp /usr/bin/gpasswd /usr/bin/mount /usr/bin/umount /usr/bin/fusermount /usr/bin/fusermount3 /usr/bin/pkexec /usr/bin/crontab /usr/sbin/unix_chkpwd /usr/lib/polkit-1/polkit-agent-helper-1 /usr/libexec/polkit-agent-helper-1"

find / -perm -4000 -type f 2>/dev/null | sort | while read -r suid_bin; do
    OWNER=$(stat -c "%U" "$suid_bin" 2>/dev/null)
    PERMS=$(stat -c "%a" "$suid_bin" 2>/dev/null)
    PKG=$(pkg_query_file "$suid_bin"2>/dev/null || echo "SIN PAQUETE")

    if echo "$KNOWN_SUIDS" | grep -q "$suid_bin"; then
        echo -e "  ${GREEN}●${NC} $suid_bin ($PERMS, $OWNER) - $PKG"
    elif [[ "$PKG" == "SIN PAQUETE" ]]; then
        echo -e "  ${RED}●${NC} $suid_bin ($PERMS, $OWNER) - ${RED}SIN PAQUETE${NC}"
    else
        echo -e "  ${YELLOW}●${NC} $suid_bin ($PERMS, $OWNER) - $PKG"
    fi
done

echo ""
echo -e "${BOLD}Binarios SGID (ejecutar como grupo):${NC}"
find / -perm -2000 -type f 2>/dev/null | sort | while read -r sgid_bin; do
    OWNER=$(stat -c "%U:%G" "$sgid_bin" 2>/dev/null)
    PKG=$(pkg_query_file "$sgid_bin"2>/dev/null || echo "SIN PAQUETE")
    if [[ "$PKG" == "SIN PAQUETE" ]]; then
        echo -e "  ${RED}●${NC} $sgid_bin ($OWNER) - ${RED}SIN PAQUETE${NC}"
    else
        echo -e "  ${DIM}$sgid_bin ($OWNER) - $PKG${NC}"
    fi
done

echo ""
if ask "¿Eliminar SUID innecesarios? (se mostrará lista para confirmar)"; then
    # Lista de SUID frecuentemente innecesarios
    REMOVABLE_SUIDS=("/usr/bin/chfn" "/usr/bin/chsh" "/usr/bin/newgrp")

    for candidate in "${REMOVABLE_SUIDS[@]}"; do
        if [[ -f "$candidate" ]] && [[ -u "$candidate" ]]; then
            echo -e "  ¿Eliminar SUID de $candidate?"
            if ask "    ¿Confirmar?"; then
                chmod u-s "$candidate"
                log_change "Permisos" "$candidate -> u-s"
                log_info "SUID eliminado de $candidate"
            else
                log_skip "SUID de $candidate"
            fi
        fi
    done
else
    log_skip "Eliminar SUID innecesarios"
fi

# ============================================================
log_section "2. CAPABILITIES DEL SISTEMA (T1134)"
# ============================================================

echo "Auditando binarios con capabilities..."
echo ""

if command -v getcap &>/dev/null; then
    echo -e "${BOLD}Binarios con capabilities:${NC}"
    CAP_COUNT=0

    getcap -r / 2>/dev/null | while read -r line; do
        BIN=$(echo "$line" | awk '{print $1}')
        CAPS=$(echo "$line" | awk '{print $2}')
        PKG=$(pkg_query_file "$BIN"2>/dev/null || echo "SIN PAQUETE")

        # Capabilities peligrosas
        if echo "$CAPS" | grep -qE "cap_setuid|cap_setgid|cap_dac_override|cap_sys_admin|cap_sys_ptrace|cap_net_admin"; then
            echo -e "  ${RED}●${NC} $BIN → $CAPS ($PKG)"
        else
            echo -e "  ${YELLOW}●${NC} $BIN → $CAPS ($PKG)"
        fi
        CAP_COUNT=$((CAP_COUNT + 1))
    done

    echo ""
    if ask "¿Eliminar capabilities innecesarias?"; then
        # Capabilities que raramente se necesitan
        DANGEROUS_CAPS=("cap_setuid" "cap_setgid" "cap_dac_override" "cap_sys_admin")

        getcap -r / 2>/dev/null | while read -r line; do
            BIN=$(echo "$line" | awk '{print $1}')
            CAPS=$(echo "$line" | awk '{print $2}')
            PKG=$(pkg_query_file "$BIN"2>/dev/null || echo "SIN PAQUETE")

            for dcap in "${DANGEROUS_CAPS[@]}"; do
                if echo "$CAPS" | grep -q "$dcap" && [[ "$PKG" == "SIN PAQUETE" ]]; then
                    echo -e "  ${RED}●${NC} $BIN tiene $dcap (sin paquete)"
                    if ask "    ¿Eliminar capabilities de $BIN?"; then
                        setcap -r "$BIN" 2>/dev/null || true
                        log_change "Permisos" "$BIN -> capabilities removed"
                        log_info "Capabilities eliminadas de $BIN"
                    else
                        log_skip "Capabilities de $BIN"
                    fi
                fi
            done
        done
    else
        log_skip "Eliminar capabilities innecesarias"
    fi
else
    log_warn "getcap no disponible - no se pueden auditar capabilities"
fi

# ============================================================
log_section "3. HARDENING DE SUDO (T1078)"
# ============================================================

echo "Verificando configuración de sudo..."
echo ""

# No modificamos sudoers directamente, pero verificamos
if [[ -f /etc/sudoers ]]; then
    echo -e "${BOLD}Configuración de sudoers:${NC}"

    # Usuarios con sudo sin contraseña
    NOPASSWD=$(grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#" || true)
    if [[ -n "$NOPASSWD" ]]; then
        log_warn "Reglas NOPASSWD detectadas:"
        echo "$NOPASSWD" | sed 's/^/    /'
    else
        echo -e "  ${GREEN}OK${NC} No hay reglas NOPASSWD"
    fi

    # Usuarios con ALL=(ALL)
    ALL_RULES=$(grep -rE "ALL.*ALL.*ALL" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#" || true)
    if [[ -n "$ALL_RULES" ]]; then
        echo ""
        echo -e "  ${YELLOW}Reglas con acceso total:${NC}"
        echo "$ALL_RULES" | sed 's/^/    /'
    fi

    # Grupo wheel
    echo ""
    echo -e "${BOLD}Miembros del grupo wheel (sudo):${NC}"
    getent group wheel 2>/dev/null | cut -d: -f4 | tr ',' '\n' | while read -r user; do
        [[ -z "$user" ]] && continue
        echo -e "  ● $user"
    done
fi

echo ""
if check_file_exists /etc/sudoers.d/99-hardening; then
    log_already "Hardening de sudo (99-hardening)"
elif ask "¿Crear configuración de sudo segura en sudoers.d/?"; then
    mkdir -p /etc/sudoers.d
    install -m 440 /dev/null /etc/sudoers.d/99-hardening
    cat > /etc/sudoers.d/99-hardening << 'EOF'
# ============================================================
# HARDENING SUDO - T1078 (TA0004)
# ============================================================

# Requerir contraseña siempre (sin caché)
Defaults timestamp_timeout=5

# Logging completo
Defaults logfile="/var/log/sudo.log"
Defaults log_input, log_output
Defaults iolog_dir="/var/log/sudo-io/%{seq}"

# Proteger contra manipulación de PATH
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults env_reset
Defaults env_clean

# No permitir editar archivos del sistema con sudoedit bypass
Defaults !visiblepw

# Limitar intentos
Defaults passwd_tries=3

# Mostrar alerta en intentos fallidos
Defaults insults
Defaults mail_badpass
EOF

    log_change "Creado" "/etc/sudoers.d/99-hardening"
    # Verificar sintaxis
    if visudo -c -f /etc/sudoers.d/99-hardening 2>/dev/null; then
        chmod 440 /etc/sudoers.d/99-hardening
        log_change "Permisos" "/etc/sudoers.d/99-hardening -> 440"
        log_info "Hardening de sudo aplicado"
    else
        log_error "Error de sintaxis en sudoers - eliminando"
        rm -f /etc/sudoers.d/99-hardening
    fi
else
    log_skip "Configuración de sudo segura"
fi

# ============================================================
log_section "4. PROTECCIÓN CONTRA EXPLOITS DE KERNEL (T1068)"
# ============================================================

echo "Verificando protecciones contra exploits de kernel..."
echo ""

KERNEL_PROTECTIONS=(
    "kernel.randomize_va_space:2:ASLR máximo"
    "kernel.kptr_restrict:2:Ocultar punteros kernel"
    "kernel.dmesg_restrict:1:Restringir dmesg"
    "kernel.yama.ptrace_scope:2:Restringir ptrace"
    "kernel.perf_event_paranoid:3:Restringir perf"
    "kernel.unprivileged_bpf_disabled:1:Deshabilitar BPF no-root"
    "kernel.kexec_load_disabled:1:Deshabilitar kexec"
    "vm.mmap_min_addr:65536:Proteger mmap bajo"
    "fs.suid_dumpable:0:Sin core dumps SUID"
    "fs.protected_symlinks:1:Proteger symlinks"
    "fs.protected_hardlinks:1:Proteger hardlinks"
    "fs.protected_fifos:2:Proteger FIFOs"
    "fs.protected_regular:2:Proteger archivos regulares"
    "kernel.modules_disabled:0:Módulos (verificar)"
)

KERNEL_ISSUES=0

for entry in "${KERNEL_PROTECTIONS[@]}"; do
    IFS=':' read -r param expected desc <<< "$entry"
    actual=$(sysctl -n "$param" 2>/dev/null || echo "N/A")
    if [[ "$actual" == "N/A" ]]; then
        echo -e "  ${DIM}--${NC} $desc ($param no disponible)"
    elif [[ "$actual" == "$expected" ]] || ([[ "$actual" =~ ^[0-9]+$ ]] && [[ "$actual" -ge "$expected" ]]); then
        echo -e "  ${GREEN}OK${NC} $desc ($param = $actual)"
    else
        echo -e "  ${YELLOW}!!${NC} $desc ($param = $actual, recomendado: $expected)"
        KERNEL_ISSUES=$((KERNEL_ISSUES + 1))
    fi
done

if [[ $KERNEL_ISSUES -gt 0 ]]; then
    echo ""
    if check_file_exists /etc/sysctl.d/99-anti-privesc.conf; then
        log_already "Protecciones de kernel (99-anti-privesc.conf)"
    elif ask "¿Aplicar protecciones de kernel faltantes?"; then
        cat > /etc/sysctl.d/99-anti-privesc.conf << 'EOF'
# ============================================================
# ANTI-ESCALADA DE PRIVILEGIOS - T1068 (TA0004)
# ============================================================

kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 2
kernel.perf_event_paranoid = 3
kernel.unprivileged_bpf_disabled = 1
kernel.kexec_load_disabled = 1

vm.mmap_min_addr = 65536
fs.suid_dumpable = 0
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# Restringir userfaultfd (explotado en muchos CVEs)
vm.unprivileged_userfaultfd = 0

# Restringir namespaces no privilegiados (anti container escape)
# NOTA: Puede afectar a Flatpak/Firefox sandbox
# Descomentar solo si no se usan:
# kernel.unprivileged_userns_clone = 0
EOF

        log_change "Creado" "/etc/sysctl.d/99-anti-privesc.conf"
        /usr/sbin/sysctl --system > /dev/null 2>&1 || true
        log_change "Aplicado" "sysctl --system"
        log_info "Protecciones de kernel aplicadas"
    else
        log_skip "Protecciones de kernel faltantes"
    fi
fi

# ============================================================
log_section "5. PREVENCIÓN DE INYECCIÓN DE PROCESOS (T1055)"
# ============================================================

echo "Verificando protecciones contra inyección de procesos..."
echo ""

# ptrace scope (ya verificado pero recordar)
PTRACE=$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null || echo "0")
echo -e "  ptrace_scope: $PTRACE (recomendado: >= 2)"

# seccomp
if [[ -f /proc/sys/kernel/seccomp/actions_avail ]]; then
    echo -e "  ${GREEN}OK${NC} seccomp disponible: $(cat /proc/sys/kernel/seccomp/actions_avail)"
fi

# Verificar si hay procesos con ptrace adjunto
echo ""
echo -e "${BOLD}Procesos con ptrace activo:${NC}"
PTRACED=0
for pid_dir in /proc/[0-9]*; do
    [[ -f "$pid_dir/status" ]] || continue
    TRACER=$(grep "^TracerPid:" "$pid_dir/status" 2>/dev/null | awk '{print $2}')
    if [[ "$TRACER" -gt 0 ]]; then
        PID=$(basename "$pid_dir")
        PROC_NAME=$(cat "$pid_dir/comm" 2>/dev/null || echo "?")
        TRACER_NAME=$(cat "/proc/$TRACER/comm" 2>/dev/null || echo "?")
        echo -e "  ${YELLOW}●${NC} PID $PID ($PROC_NAME) trazado por PID $TRACER ($TRACER_NAME)"
        PTRACED=$((PTRACED + 1))
    fi
done
[[ $PTRACED -eq 0 ]] && echo -e "  ${GREEN}OK${NC} No hay procesos siendo trazados"

echo ""
if check_file_exists /etc/audit/rules.d/privesc-injection.rules; then
    log_already "Reglas de auditoría para inyección de procesos (privesc-injection.rules)"
elif ask "¿Configurar reglas de auditoría para inyección de procesos?"; then
    if command -v auditctl &>/dev/null; then
        mkdir -p /etc/audit/rules.d
        cat > /etc/audit/rules.d/privesc-injection.rules << 'EOF'
# Monitoreo de inyección de procesos - T1055
-a always,exit -F arch=b64 -S ptrace -k process_injection
-a always,exit -F arch=b64 -S process_vm_readv -k process_injection
-a always,exit -F arch=b64 -S process_vm_writev -k process_injection

# Monitoreo de cambios de privilegios
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k priv_change
-a always,exit -F arch=b64 -S setresuid -S setresgid -k priv_change

# Monitoreo de uso de sudo/su
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/sudo -k priv_sudo
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/su -k priv_su
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/pkexec -k priv_pkexec
EOF
        log_change "Creado" "/etc/audit/rules.d/privesc-injection.rules"
        augenrules --load 2>/dev/null || true
        log_change "Aplicado" "augenrules --load"
        log_info "Monitoreo de inyección de procesos configurado"
    fi
else
    log_skip "Reglas de auditoría para inyección de procesos"
fi

# ============================================================
log_section "6. AUDITORÍA DE CRON COMO VECTOR DE PRIVESC (T1053)"
# ============================================================

echo "Verificando tareas cron como vector de escalada..."
echo ""

# Buscar scripts de cron escribibles por no-root
echo -e "${BOLD}Scripts cron ejecutados como root pero escribibles:${NC}"
CRON_ISSUES=0

for cron_dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    [[ -d "$cron_dir" ]] || continue
    for script in "$cron_dir"/*; do
        [[ -f "$script" ]] || continue
        PERMS=$(stat -c "%a" "$script" 2>/dev/null)
        OWNER=$(stat -c "%U" "$script" 2>/dev/null)

        # Verificar si es escribible por grupo u otros
        if [[ "${PERMS:1:1}" =~ [2367] ]] || [[ "${PERMS:2:1}" =~ [2367] ]]; then
            echo -e "  ${RED}●${NC} $script (permisos: $PERMS, owner: $OWNER) - ESCRIBIBLE"
            CRON_ISSUES=$((CRON_ISSUES + 1))
        fi
    done
done

if [[ $CRON_ISSUES -gt 0 ]]; then
    if ask "¿Corregir permisos de scripts cron?"; then
        for cron_dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
            [[ -d "$cron_dir" ]] || continue
            chmod 700 "$cron_dir"
            log_change "Permisos" "$cron_dir -> 700"
            for script in "$cron_dir"/*; do
                [[ -f "$script" ]] || continue
                chmod 700 "$script"
            done
        done
        log_info "Permisos de scripts cron corregidos a 700"
    else
        log_skip "Corregir permisos de scripts cron"
    fi
else
    echo -e "  ${GREEN}OK${NC} No hay scripts cron con permisos inseguros"
fi

# Buscar scripts referenciados en crontab que sean escribibles
echo ""
echo -e "${BOLD}Archivos referenciados en crontabs escribibles por otros:${NC}"
grep -rh "^[^#]" /etc/crontab /etc/cron.d/* /var/spool/cron/tabs/* 2>/dev/null | \
    grep -oP '(/[^\s]+)' | sort -u | while read -r ref_file; do
    if [[ -f "$ref_file" ]]; then
        PERMS=$(stat -c "%a" "$ref_file" 2>/dev/null)
        if [[ "${PERMS:2:1}" =~ [2367] ]]; then
            echo -e "  ${RED}●${NC} $ref_file ($PERMS) - escribible por otros"
        fi
    fi
done || echo -e "  ${GREEN}OK${NC} Sin archivos referenciados inseguros"

# ============================================================
log_section "7. ARCHIVOS WORLD-WRITABLE (T1548)"
# ============================================================

echo "Buscando archivos world-writable en directorios del sistema..."
echo ""

echo -e "${BOLD}Archivos world-writable (excluyendo /tmp y /proc):${NC}"
WW_COUNT=0
find /usr /etc /var/lib /opt -xdev -type f -perm -0002 2>/dev/null | head -30 | while read -r ww_file; do
    OWNER=$(stat -c "%U:%G" "$ww_file" 2>/dev/null)
    echo -e "  ${RED}●${NC} $ww_file ($OWNER)"
    WW_COUNT=$((WW_COUNT + 1))
done

echo ""
echo -e "${BOLD}Directorios world-writable sin sticky bit:${NC}"
find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | grep -vE "^/(proc|sys|dev)" | head -20 | while read -r ww_dir; do
    echo -e "  ${RED}●${NC} $ww_dir"
done || echo -e "  ${GREEN}OK${NC} Todos los directorios world-writable tienen sticky bit"

if ask "¿Corregir archivos y directorios world-writable?"; then
    # Añadir sticky bit a directorios world-writable
    find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | grep -vE "^/(proc|sys|dev)" | while read -r ww_dir; do
        chmod +t "$ww_dir" 2>/dev/null || true
        log_change "Permisos" "$ww_dir -> +t"
        log_info "Sticky bit añadido a $ww_dir"
    done

    # Quitar world-writable de archivos en directorios del sistema
    find /usr /etc /var/lib /opt -xdev -type f -perm -0002 2>/dev/null | while read -r ww_file; do
        chmod o-w "$ww_file" 2>/dev/null || true
    done
    log_info "Permisos world-writable corregidos"
else
    log_skip "Corregir archivos y directorios world-writable"
fi

# ============================================================
log_section "8. SCRIPT DE DETECCIÓN DE ESCALADA"
# ============================================================

if check_executable /usr/local/bin/detectar-escalada.sh; then
    log_already "Script de detección de escalada (/usr/local/bin/detectar-escalada.sh)"
elif ask "¿Crear script de detección periódica de vectores de escalada?"; then
    cat > /usr/local/bin/detectar-escalada.sh << 'ESCEOF'
#!/bin/bash
# ============================================================
# DETECTOR DE VECTORES DE ESCALADA - TA0004
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

LOGFILE="/var/log/detectar-escalada-$(date +%Y%m%d).log"

echo "============================================================" | tee "$LOGFILE"
echo " DETECCIÓN DE ESCALADA DE PRIVILEGIOS - $(date)" | tee -a "$LOGFILE"
echo "============================================================" | tee -a "$LOGFILE"

ALERTS=0

# 1. SUID nuevos (últimos 7 días)
echo -e "${CYAN}[1/5] Binarios SUID recientes:${NC}" | tee -a "$LOGFILE"
find / -perm -4000 -type f -mtime -7 2>/dev/null | while read -r f; do
    if command -v rpm &>/dev/null; then
        PKG=$(rpm -qf "$f" 2>/dev/null || echo "SIN PAQUETE")
    elif command -v dpkg &>/dev/null; then
        PKG=$(dpkg -S "$f" 2>/dev/null | cut -d: -f1 || echo "SIN PAQUETE")
    elif command -v pacman &>/dev/null; then
        PKG=$(pacman -Qo "$f" 2>/dev/null | awk '{print $5}' || echo "SIN PAQUETE")
    else
        PKG="SIN PAQUETE"
    fi
    echo -e "  ${YELLOW}[!]${NC} $f - $PKG" | tee -a "$LOGFILE"
    ALERTS=$((ALERTS + 1))
done

# 2. Capabilities nuevas
echo -e "${CYAN}[2/5] Capabilities peligrosas:${NC}" | tee -a "$LOGFILE"
getcap -r / 2>/dev/null | grep -E "cap_setuid|cap_sys_admin|cap_dac_override" | while read -r line; do
    echo -e "  ${RED}[!]${NC} $line" | tee -a "$LOGFILE"
    ALERTS=$((ALERTS + 1))
done

# 3. Kernel protections
echo -e "${CYAN}[3/5] Protecciones de kernel:${NC}" | tee -a "$LOGFILE"
PTRACE=$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null || echo "0")
ASLR=$(sysctl -n kernel.randomize_va_space 2>/dev/null || echo "0")
[[ "$PTRACE" -lt 2 ]] && echo -e "  ${YELLOW}[!]${NC} ptrace_scope=$PTRACE (rec: 2)" | tee -a "$LOGFILE" && ALERTS=$((ALERTS+1))
[[ "$ASLR" -lt 2 ]] && echo -e "  ${YELLOW}[!]${NC} ASLR=$ASLR (rec: 2)" | tee -a "$LOGFILE" && ALERTS=$((ALERTS+1))

# 4. World-writable en PATH
echo -e "${CYAN}[4/5] Directorios PATH escribibles:${NC}" | tee -a "$LOGFILE"
IFS=':' read -ra PDIRS <<< "$PATH"
for d in "${PDIRS[@]}"; do
    if [[ -d "$d" ]] && [[ $(stat -c "%a" "$d" 2>/dev/null) == *7 ]]; then
        echo -e "  ${RED}[!]${NC} $d escribible" | tee -a "$LOGFILE"
        ALERTS=$((ALERTS + 1))
    fi
done

# 5. Sudoers NOPASSWD
echo -e "${CYAN}[5/5] Sudo NOPASSWD:${NC}" | tee -a "$LOGFILE"
grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#" | while read -r line; do
    echo -e "  ${YELLOW}[!]${NC} $line" | tee -a "$LOGFILE"
    ALERTS=$((ALERTS + 1))
done

echo "" | tee -a "$LOGFILE"
echo "Alertas: $ALERTS" | tee -a "$LOGFILE"
ESCEOF

    log_change "Creado" "/usr/local/bin/detectar-escalada.sh"
    chmod +x /usr/local/bin/detectar-escalada.sh
    log_change "Permisos" "/usr/local/bin/detectar-escalada.sh -> +x"
    log_info "Script creado: /usr/local/bin/detectar-escalada.sh"

    if check_executable /etc/cron.weekly/detectar-escalada; then
        log_already "Detección semanal de escalada (cron)"
    elif ask "¿Programar detección semanal de vectores de escalada?"; then
        cat > /etc/cron.weekly/detectar-escalada << 'WEOF'
#!/bin/bash
/usr/local/bin/detectar-escalada.sh > /dev/null 2>&1
WEOF
        log_change "Creado" "/etc/cron.weekly/detectar-escalada"
        chmod +x /etc/cron.weekly/detectar-escalada
        log_change "Permisos" "/etc/cron.weekly/detectar-escalada -> +x"
        log_info "Detección semanal programada"
    else
        log_skip "Programar detección semanal de escalada"
    fi
else
    log_skip "Script de detección de vectores de escalada"
fi

# ============================================================
# RESUMEN
# ============================================================
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║    MITIGACIÓN ESCALADA COMPLETADA (TA0004)                 ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "Técnicas mitigadas:"
echo "  T1548 - SUID/SGID Abuse       → Auditoría + eliminación"
echo "  T1134 - Capabilities           → Auditoría + limpieza"
echo "  T1078 - Valid Accounts (sudo)  → Hardening sudoers"
echo "  T1068 - Kernel Exploits        → Protecciones sysctl"
echo "  T1055 - Process Injection      → ptrace + auditd"
echo "  T1053 - Cron Privesc           → Permisos + monitoreo"
echo "  World-writable                 → Corrección de permisos"
echo ""

show_changes_summary

log_info "Backups en: $BACKUP_DIR"
