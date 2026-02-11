#!/bin/bash
# ============================================================
# MENÚ INTERACTIVO DE SECURIZACIÓN - Linux Multi-Distro
# ============================================================
# Orquesta los 56 scripts de hardening con protecciones:
#   - NO modifica PAM (/etc/pam.d/su intacto)
#   - NO limita recursos (sin TMOUT readonly)
#   - NO bloquea al usuario (sshd activo, sin chattr +i)
# ============================================================

set -euo pipefail

# ── Cargar biblioteca compartida ───────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

# ── Session tracking ───────────────────────────────────────────
declare -A MOD_RUN=()
SESSION_START=$(date +%s)

# ── Override logging con versiones mejoradas (Unicode + tee) ──
LOGFILE="/var/log/securizar-menu-$(date +%Y%m%d-%H%M%S).log"

log_info()  { echo -e "  ${GREEN}✓${NC} $1" | tee -a "$LOGFILE"; }
log_warn()  { echo -e "  ${YELLOW}⚠${NC} $1" | tee -a "$LOGFILE"; }
log_error() { echo -e "  ${RED}✗${NC} $1" | tee -a "$LOGFILE"; }
log_section() {
    echo "" | tee -a "$LOGFILE"
    echo -e "  ${CYAN}━━ $1 ━━${NC}" | tee -a "$LOGFILE"
    echo "" | tee -a "$LOGFILE"
}

ask() {
    echo ""
    read -rp "$(echo -e "  ${CYAN}❯${NC} $1 ${DIM}[s/N]:${NC} ")" resp
    [[ "$resp" =~ ^[sS]$ ]]
}

# ── Funciones UI ─────────────────────────────────────────────
TERM_WIDTH=$(tput cols 2>/dev/null || echo 70)
[[ $TERM_WIDTH -gt 80 ]] && TERM_WIDTH=80

_hr() {
    local char="${1:-─}"
    local width="${2:-$TERM_WIDTH}"
    printf '%*s' "$width" '' | tr ' ' "$char"
}

_center() {
    local text="$1"
    local width="${2:-$TERM_WIDTH}"
    local clean
    clean=$(echo -e "$text" | sed 's/\x1b\[[0-9;]*m//g')
    local pad=$(( (width - ${#clean}) / 2 ))
    [[ $pad -lt 0 ]] && pad=0
    printf '%*s' "$pad" ''
    echo -e "$text"
}

_status_dot() {
    local file="$1"
    if [[ -f "$file" ]]; then
        echo -e "${GREEN}●${NC}"
    else
        echo -e "${DIM}○${NC}"
    fi
}

_svc_status() {
    local svc="$1"
    if systemctl is-active "$svc" &>/dev/null; then
        echo -e "${GREEN}●${NC}"
    elif systemctl is-enabled "$svc" &>/dev/null 2>&1; then
        echo -e "${YELLOW}◐${NC}"
    else
        echo -e "${DIM}○${NC}"
    fi
}

_progress_bar() {
    local current=$1
    local total=$2
    local width=30
    local filled=$(( current * width / total ))
    local empty=$(( width - filled ))
    local pct=$(( current * 100 / total ))
    local bar=""
    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=0; i<empty; i++)); do bar+="░"; done
    echo -e "  ${DIM}[${NC}${CYAN}${bar}${NC}${DIM}]${NC} ${BOLD}${pct}%${NC}"
}

_draw_header() {
    clear 2>/dev/null || true
    echo ""
    echo -e "${CYAN}"
    _center "███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗███████╗ █████╗ ██████╗"
    _center "██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══███╔╝██╔══██╗██╔══██╗"
    _center "███████╗█████╗  ██║     ██║   ██║██████╔╝██║  ███╔╝ ███████║██████╔╝"
    _center "╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║ ███╔╝  ██╔══██║██╔══██╗"
    _center "███████║███████╗╚██████╗╚██████╔╝██║  ██║██║███████╗██║  ██║██║  ██║"
    _center "╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝"
    echo -e "${NC}"
    _center "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    _center "${DIM}Hardening Suite · Linux Multi-Distro${NC}"
    echo ""
}

_draw_sysinfo() {
    local hostname kernel uptime_str user date_str
    hostname=$(hostname 2>/dev/null || echo "localhost")
    kernel=$(uname -r 2>/dev/null || echo "?")
    uptime_str=$(uptime -p 2>/dev/null | sed 's/up //' || echo "?")
    user="${SUDO_USER:-$USER}"
    date_str=$(date '+%d/%m/%Y %H:%M')

    local run_count=0
    for _k in "${!MOD_RUN[@]}"; do [[ "${MOD_RUN[$_k]}" == "1" ]] && ((run_count++)) || true; done

    echo -e "  ${DIM}╭─────────────────────────────────────────────────────────────────╮${NC}"
    printf "  ${DIM}│${NC}  %-12s ${DIM}·${NC} %-20s ${DIM}·${NC} %-8s ${DIM}·${NC} %-14s  ${DIM}│${NC}\n" "$hostname" "$kernel" "$user" "$date_str"
    printf "  ${DIM}│${NC}  ${DIM}Uptime:${NC} %-16s  ${DIM}Log:${NC} activo    ${DIM}Módulos:${NC} ${GREEN}%d${NC}${DIM}/56${NC}     ${DIM}│${NC}\n" "$uptime_str" "$run_count"
    echo -e "  ${DIM}╰─────────────────────────────────────────────────────────────────╯${NC}"
}

_draw_footer() {
    echo ""
    echo -e "  ${DIM}─────────────────────────────────────────────────────────────────${NC}"
    echo -e "  ${GREEN}✓${NC} ${DIM}sin PAM${NC}  ${GREEN}✓${NC} ${DIM}sin TMOUT${NC}  ${GREEN}✓${NC} ${DIM}sin lockout${NC}  ${GREEN}✓${NC} ${DIM}sshd activo${NC}"
    echo ""
}

# ── UI extendido ───────────────────────────────────────────────
_draw_header_compact() {
    clear 2>/dev/null || true
    echo ""
    echo -e "  ${CYAN}${BOLD}SECURIZAR${NC} ${DIM}· Hardening Suite · Linux Multi-Distro${NC}"
    echo -e "  ${DIM}$(_hr '─' $((TERM_WIDTH - 4)))${NC}"
    echo ""
}

_breadcrumb() {
    echo -e "  ${DIM}$1${NC}"
    echo ""
}

_pause() {
    echo ""
    echo -e "  ${DIM}─────────────────────────────────────────────────────────────────${NC}"
    echo -ne "  ${DIM}Presiona Enter para continuar...${NC} "
    read -r _
}

_mod_icon() {
    local n=$1
    if [[ "${MOD_RUN[$n]:-}" == "1" ]]; then
        echo -e "${GREEN}✓${NC}"
    elif [[ -n "${MOD_FILES[$n]:-}" ]] && [[ ! -f "$SCRIPT_DIR/${MOD_FILES[$n]}" ]]; then
        echo -e "${RED}!${NC}"
    else
        echo -e "${DIM}○${NC}"
    fi
}

_show_module_entry() {
    local n=$1
    local icon
    icon="$(_mod_icon "$n")"
    local tag=""
    [[ -n "${MOD_TAGS[$n]:-}" ]] && tag=" ${BG_YELLOW} ${MOD_TAGS[$n]} ${NC}"
    printf "  %b  ${WHITE}%2d${NC}  ${BOLD}%-28s${NC}%b  ${DIM}%s${NC}\n" \
        "$icon" "$n" "${MOD_NAMES[$n]}" "$tag" "${MOD_DESCS[$n]}"
}

_cat_dots() {
    local total=$1 done_count=$2 i
    for ((i=0; i<done_count; i++)); do printf "${GREEN}●${NC}"; done
    for ((i=done_count; i<total; i++)); do printf "${DIM}○${NC}"; done
}

_exec_module() {
    local n=$1
    echo ""
    echo -e "  ${CYAN}━━${NC} ${BOLD}Módulo ${n}: ${MOD_NAMES[$n]}${NC} ${CYAN}━━${NC}"
    [[ -n "${MOD_TAGS[$n]:-}" ]] && echo -e "  ${BG_YELLOW} ${MOD_TAGS[$n]} ${NC} ${DIM}Versión segura · sin riesgos de lockout${NC}"
    echo ""

    reset_changes
    local rc=0
    ${MOD_FUNCS[$n]} || rc=$?
    show_changes_summary
    MOD_RUN[$n]=1
    echo ""
    if [[ $rc -eq 0 ]]; then
        echo -e "  ${GREEN}✓${NC} ${BOLD}Módulo ${n}${NC} completado correctamente"
    else
        echo -e "  ${YELLOW}⚠${NC} ${BOLD}Módulo ${n}${NC} completado con advertencias (código: $rc)"
    fi
    _pause
}

_run_category() {
    local label=$1 start=$2 end=$3
    local count=$(( end - start + 1 ))

    echo ""
    echo -e "  ${BG_CYAN} ${label} ${NC}"
    echo -e "  ${DIM}Se ejecutarán ${count} módulos secuencialmente${NC}"

    if ! ask "¿Continuar con todos los módulos de esta categoría?"; then
        return 0
    fi

    local ok=0 fail=0
    for ((n=start; n<=end; n++)); do
        echo ""
        _progress_bar $((n - start + 1)) "$count"
        echo -e "  ${CYAN}▶${NC} ${BOLD}${MOD_NAMES[$n]}${NC}"
        echo ""

        if ${MOD_FUNCS[$n]}; then
            MOD_RUN[$n]=1
            echo -e "  ${GREEN}✓${NC} Completado"
            ((ok++)) || true
        else
            MOD_RUN[$n]=1
            echo -e "  ${RED}✗${NC} Falló"
            ((fail++)) || true
        fi
    done

    echo ""
    _progress_bar "$count" "$count"
    echo ""
    if [[ $fail -eq 0 ]]; then
        echo -e "  ${GREEN}✓${NC} ${BOLD}Todos completados${NC} ($ok/$count)"
    else
        echo -e "  ${YELLOW}⚠${NC} ${GREEN}$ok OK${NC} · ${RED}$fail fallidos${NC}"
    fi
}

_show_help() {
    _draw_header_compact
    echo -e "  ${BOLD}Navegación${NC}"
    echo ""
    echo -e "    ${WHITE}b${NC}  ${DIM}Hardening Base (10 módulos)${NC}"
    echo -e "    ${WHITE}p${NC}  ${DIM}Securización Proactiva (8 módulos)${NC}"
    echo -e "    ${WHITE}m${NC}  ${DIM}Mitigaciones MITRE ATT&CK (12 módulos)${NC}"
    echo -e "    ${WHITE}o${NC}  ${DIM}Operaciones de Seguridad (6 módulos)${NC}"
    echo -e "    ${WHITE}i${NC}  ${DIM}Inteligencia (2 módulos)${NC}"
    echo -e "    ${WHITE}x${NC}  ${DIM}Avanzado (18 módulos)${NC}"
    echo -e "    ${WHITE}a${NC}  ${DIM}Aplicar todos los módulos${NC}"
    echo -e "    ${WHITE}v${NC}  ${DIM}Verificación proactiva (64 checks)${NC}"
    echo ""
    echo -e "  ${BOLD}Acceso directo${NC}"
    echo ""
    echo -e "    ${WHITE}1-56${NC}  ${DIM}Ejecutar módulo por número desde cualquier menú${NC}"
    echo ""
    echo -e "  ${BOLD}En sub-menús${NC}"
    echo ""
    echo -e "    ${WHITE}N${NC}     ${DIM}Ejecutar módulo N${NC}"
    echo -e "    ${WHITE}t${NC}     ${DIM}Ejecutar todos en la categoría${NC}"
    echo -e "    ${WHITE}b${NC}     ${DIM}Volver al menú principal${NC}"
    echo ""
    echo -e "  ${BOLD}General${NC}"
    echo ""
    echo -e "    ${WHITE}?${NC}     ${DIM}Mostrar esta ayuda${NC}"
    echo -e "    ${WHITE}q${NC}     ${DIM}Salir de Securizar${NC}"
    echo ""
    _pause
}

_exit_securizar() {
    local elapsed=$(( $(date +%s) - SESSION_START ))
    local mins=$((elapsed / 60))
    local secs=$((elapsed % 60))
    local run_count=0
    for _k in "${!MOD_RUN[@]}"; do [[ "${MOD_RUN[$_k]}" == "1" ]] && ((run_count++)) || true; done

    echo ""
    echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${DIM}Sesión finalizada${NC} ${DIM}·${NC} ${WHITE}${run_count}${NC} ${DIM}módulos ejecutados${NC} ${DIM}·${NC} ${DIM}${mins}m ${secs}s${NC}"
    echo -e "  ${DIM}Log:${NC} ${DIM}${LOGFILE}${NC}"
    echo ""
    echo -e "  ${GREEN}✓${NC} ${DIM}sin PAM · sin TMOUT · sin lockout · sshd activo${NC}"
    echo ""
    exit 0
}

# ── Verificar root ───────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    log_error "Este script debe ejecutarse como root: sudo bash $0"
    exit 1
fi

# ── Directorio base ─────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Backup ───────────────────────────────────────────────────
BACKUP_DIR="/root/securizar-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Guardar hash de PAM para verificación posterior
PAM_SU_HASH=""
if [[ -f /etc/pam.d/su ]]; then
    PAM_SU_HASH=$(sha256sum /etc/pam.d/su 2>/dev/null | awk '{print $1}')
fi

# ============================================================
# MÓDULO 1: hardening-opensuse.sh (SEGURO - delegado)
# ============================================================
mod_01_opensuse() {
    log_section "MÓDULO 1: Hardening openSUSE base"
    local script="$SCRIPT_DIR/hardening-opensuse.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 1 completado"
        else
            log_warn "Módulo 1 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 2: hardening-seguro.sh (SEGURO - delegado)
# ============================================================
mod_02_seguro() {
    log_section "MÓDULO 2: Hardening seguro"
    local script="$SCRIPT_DIR/hardening-seguro.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 2 completado"
        else
            log_warn "Módulo 2 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 3: hardening-final.sh (SEGURO - delegado)
# ============================================================
mod_03_final() {
    log_section "MÓDULO 3: Hardening final"
    local script="$SCRIPT_DIR/hardening-final.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 3 completado"
        else
            log_warn "Módulo 3 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 4: hardening-externo.sh (SEGURO - delegado)
# ============================================================
mod_04_externo() {
    log_section "MÓDULO 4: Hardening externo"
    local script="$SCRIPT_DIR/hardening-externo.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 4 completado"
        else
            log_warn "Módulo 4 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 5: hardening-extremo SEGURO (INLINE)
# Secciones incluidas: 3-9
# Secciones ELIMINADAS:
#   1 - Deshabilita sshd (LOCKOUT)
#   2 - Firewall DROP ultra-restrictivo (LOCKOUT)
#  10 - chattr +i en passwd/shadow/sudoers (LOCKOUT)
# ============================================================
mod_05_extremo_seguro() {
    log_section "MÓDULO 5: Hardening extremo (versión SEGURA)"
    log_warn "Secciones peligrosas ELIMINADAS:"
    log_warn "  - Deshabilitar sshd (evita lockout)"
    log_warn "  - Firewall DROP ultra-restrictivo (evita lockout)"
    log_warn "  - chattr +i en archivos críticos (evita lockout)"
    echo ""

    # ── Sección 3: Bloquear módulos de red innecesarios ──
    log_info "3. Bloqueando módulos de red innecesarios..."

    cat > /etc/modprobe.d/network-hardening.conf << 'EOF'
# Bloquear protocolos de red peligrosos
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
install n-hdlc /bin/false
install ax25 /bin/false
install netrom /bin/false
install x25 /bin/false
install rose /bin/false
install decnet /bin/false
install econet /bin/false
install af_802154 /bin/false
install ipx /bin/false
install appletalk /bin/false
install psnap /bin/false
install p8023 /bin/false
install p8022 /bin/false
install can /bin/false
install atm /bin/false
EOF
    log_change "Creado" "/etc/modprobe.d/network-hardening.conf"

    # ── Sección 4: Kernel paranoid mode ──
    log_info "4. Activando modo paranoico del kernel..."

    cat > /etc/sysctl.d/99-paranoid-max.conf << 'EOF'
# MÁXIMA SEGURIDAD - MODO PARANOICO

# Memoria
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3
kernel.yama.ptrace_scope = 3
kernel.unprivileged_bpf_disabled = 1
kernel.kexec_load_disabled = 1
kernel.sysrq = 0

# Core dumps deshabilitados
kernel.core_pattern = |/bin/false
fs.suid_dumpable = 0

# Protección de archivos
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# Red - Máxima restricción
net.ipv4.ip_forward = 0
net.ipv4.conf.all.forwarding = 0
net.ipv6.conf.all.forwarding = 0

net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.icmp_echo_ignore_all = 1

net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 3

net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# BPF hardening
net.core.bpf_jit_harden = 2

# Memoria
vm.mmap_min_addr = 65536
vm.swappiness = 10
EOF
    log_change "Creado" "/etc/sysctl.d/99-paranoid-max.conf"

    /usr/sbin/sysctl --system > /dev/null 2>&1 || true
    log_change "Aplicado" "sysctl --system"
    log_info "   Kernel en modo paranoico máximo"

    # ── Sección 5: Bloquear USB ──
    if ask "¿Bloquear TODOS los dispositivos USB nuevos?"; then
        log_info "5. Bloqueando USB..."

        if ! command -v usbguard &>/dev/null; then
            pkg_install usbguard 2>/dev/null || true
        fi

        if command -v usbguard &>/dev/null; then
            cat > /etc/usbguard/rules.conf << 'EOF'
# Bloquear TODOS los dispositivos USB por defecto
# Solo los dispositivos listados explícitamente serán permitidos
EOF
            usbguard generate-policy >> /etc/usbguard/rules.conf 2>/dev/null || true
            systemctl enable --now usbguard 2>/dev/null || true
            log_info "   USBGuard activo - USB nuevos bloqueados"
        fi

        echo "install usb-storage /bin/false" >> /etc/modprobe.d/network-hardening.conf
        rmmod usb_storage 2>/dev/null || true
        log_change "Modificado" "/etc/modprobe.d/network-hardening.conf (usb-storage)"
    else
        log_skip "bloqueo de dispositivos USB"
    fi

    # ── Sección 6: Deshabilitar usuarios innecesarios ──
    log_info "6. Bloqueando shells de usuarios del sistema..."

    for user in daemon bin sys sync games man lp mail news uucp proxy www-data backup list irc gnats nobody; do
        usermod -s /usr/sbin/nologin "$user" 2>/dev/null || true
    done
    log_change "Usuario" "shells de usuarios del sistema bloqueadas (/usr/sbin/nologin)"

    # ── Sección 7: Permisos ultra-restrictivos ──
    log_info "7. Aplicando permisos ultra-restrictivos..."

    chmod u-s /usr/bin/wall 2>/dev/null || true
    chmod u-s /usr/bin/write 2>/dev/null || true
    chmod u-s /usr/bin/chage 2>/dev/null || true
    chmod u-s /usr/bin/chfn 2>/dev/null || true
    chmod u-s /usr/bin/chsh 2>/dev/null || true
    log_change "Permisos" "SUID removido de wall, write, chage, chfn, chsh"

    chmod 600 /etc/shadow
    chmod 600 /etc/gshadow
    chmod 600 /etc/ssh/sshd_config 2>/dev/null || true
    chmod 700 /root
    chmod 700 /boot
    log_change "Permisos" "restrictivos en shadow, gshadow, sshd_config, /root, /boot"

    # ── Sección 8: Monitoreo en tiempo real ──
    log_info "8. Configurando monitoreo en tiempo real..."

    cat > /usr/local/bin/security-monitor.sh << 'EOFMONITOR'
#!/bin/bash
# Monitor de seguridad en tiempo real

LOG="/var/log/security-monitor.log"

log_alert() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ALERTA: $1" >> "$LOG"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ALERTA: $1"
}

while true; do
    # Verificar conexiones nuevas
    CONNECTIONS=$(ss -tnp state established 2>/dev/null | grep -v "127.0.0.1" | wc -l)
    if [[ $CONNECTIONS -gt 50 ]]; then
        log_alert "Muchas conexiones establecidas: $CONNECTIONS"
    fi

    # Verificar puertos escuchando
    LISTENING=$(ss -tlnp 2>/dev/null | grep -v "127.0.0.1" | grep -v "::1" | wc -l)
    if [[ $LISTENING -gt 0 ]]; then
        log_alert "Puertos abiertos detectados: $(ss -tlnp | grep -v '127.0.0.1')"
    fi

    # Verificar usuarios logueados
    USERS=$(who | wc -l)
    if [[ $USERS -gt 2 ]]; then
        log_alert "Múltiples usuarios logueados: $(who)"
    fi

    # Verificar procesos sospechosos
    for proc in nc ncat netcat nmap masscan hydra john; do
        if pgrep -x "$proc" > /dev/null 2>&1; then
            log_alert "Proceso sospechoso detectado: $proc"
            pkill -9 "$proc" 2>/dev/null
        fi
    done

    # Verificar archivos modificados en /etc
    MODIFIED=$(find /etc -mmin -5 -type f 2>/dev/null | wc -l)
    if [[ $MODIFIED -gt 10 ]]; then
        log_alert "Muchos archivos modificados en /etc: $MODIFIED"
    fi

    sleep 30
done
EOFMONITOR
    chmod +x /usr/local/bin/security-monitor.sh
    log_change "Creado" "/usr/local/bin/security-monitor.sh"

    cat > /etc/systemd/system/security-monitor.service << 'EOF'
[Unit]
Description=Security Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/security-monitor.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    log_change "Creado" "/etc/systemd/system/security-monitor.service"

    systemctl daemon-reload
    systemctl enable --now security-monitor.service 2>/dev/null || true
    log_change "Servicio" "security-monitor.service habilitado e iniciado"
    log_info "   Monitor de seguridad activo"

    # ── Sección 9: Alarma de intrusión ──
    log_info "9. Configurando alarma de intrusión..."

    cat > /usr/local/bin/intrusion-alarm.sh << 'EOFALARM'
#!/bin/bash
# Alarma de intrusión - ejecutar cuando se detecte acceso no autorizado

for i in {1..5}; do
    echo -e '\a'
    sleep 0.5
done

wall "
=====================================================================
  ALERTA DE INTRUSION DETECTADA
  Se ha detectado actividad sospechosa en el sistema.
  Verificar inmediatamente.
  $(date)
=====================================================================
"

echo "[$(date)] INTRUSION DETECTADA" >> /var/log/intrusion.log
EOFALARM
    chmod +x /usr/local/bin/intrusion-alarm.sh
    log_change "Creado" "/usr/local/bin/intrusion-alarm.sh"

    log_info "Módulo 5 (extremo seguro) completado"
}

# ============================================================
# MÓDULO 6: hardening-paranoico SEGURO (INLINE)
# Secciones incluidas: 1-3, 6-16
# Secciones ELIMINADAS:
#   4 - TMOUT=900 readonly (LIMITA RECURSOS)
#   5 - Modifica /etc/pam.d/su (MODIFICA PAM)
# ============================================================
mod_06_paranoico_seguro() {
    log_section "MÓDULO 6: Hardening paranoico (versión SEGURA)"
    log_warn "Secciones peligrosas ELIMINADAS:"
    log_warn "  - TMOUT=900 readonly (evita limitar recursos)"
    log_warn "  - Modificar /etc/pam.d/su (evita modificar PAM)"
    echo ""

    local PBACKUP_DIR="/root/hardening-paranoico-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$PBACKUP_DIR"
    log_info "Backups en: $PBACKUP_DIR"

    # ── Sección 1: Kernel hardening extremo ──
    log_section "1. KERNEL HARDENING EXTREMO"

    if ask "¿Aplicar hardening extremo del kernel?"; then
        cat > /etc/sysctl.d/99-paranoid.conf << 'EOF'
# ===========================================
# KERNEL HARDENING PARANOICO
# ===========================================

# --- Protección de memoria ---
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3
kernel.yama.ptrace_scope = 2
kernel.unprivileged_bpf_disabled = 1
kernel.kexec_load_disabled = 1

# --- Deshabilitar SysRq (magic keys) ---
kernel.sysrq = 0

# --- Core dumps deshabilitados ---
kernel.core_pattern = |/bin/false
fs.suid_dumpable = 0

# --- Protección de archivos ---
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# --- Red IPv4 ---
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# --- Red IPv6 (restringir) ---
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# --- User namespaces (comentado - puede romper algunas apps) ---
# kernel.unprivileged_userns_clone = 0
EOF
        log_change "Creado" "/etc/sysctl.d/99-paranoid.conf"

        /usr/sbin/sysctl --system > /dev/null 2>&1 || true
        log_change "Aplicado" "sysctl --system"
        log_info "Kernel hardening extremo aplicado"
        log_warn "ptrace_scope=2 puede afectar debuggers (gdb, strace)"
    else
        log_skip "hardening extremo del kernel"
    fi

    # ── Sección 2: Blacklist de módulos peligrosos ──
    log_section "2. BLACKLIST DE MÓDULOS PELIGROSOS"

    echo "Módulos que se pueden bloquear:"
    echo "  - firewire (DMA attacks)"
    echo "  - thunderbolt (DMA attacks)"
    echo "  - bluetooth (si no lo usas)"
    echo "  - cramfs, freevxfs, jffs2, hfs, hfsplus, udf (filesystems raros)"
    echo ""

    if ask "¿Bloquear módulos peligrosos (NO incluye USB)?"; then
        cat > /etc/modprobe.d/paranoid-blacklist.conf << 'EOF'
# Bloquear protocolos de red obsoletos/peligrosos
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false

# Bloquear DMA attack vectors
install firewire-core /bin/false
install firewire-ohci /bin/false
install firewire-sbp2 /bin/false
install thunderbolt /bin/false

# Bloquear filesystems raros
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install udf /bin/false
install squashfs /bin/false
EOF
        log_change "Creado" "/etc/modprobe.d/paranoid-blacklist.conf"

        log_info "Módulos peligrosos bloqueados"
    else
        log_skip "bloqueo de módulos peligrosos"
    fi

    if ask "¿Bloquear Bluetooth también?"; then
        cat >> /etc/modprobe.d/paranoid-blacklist.conf << 'EOF'

# Bloquear Bluetooth
install bluetooth /bin/false
install btusb /bin/false
EOF
        log_change "Modificado" "/etc/modprobe.d/paranoid-blacklist.conf (bluetooth)"
        systemctl stop bluetooth 2>/dev/null || true
        systemctl disable bluetooth 2>/dev/null || true
        log_change "Servicio" "bluetooth deshabilitado"
        log_info "Bluetooth bloqueado"
    else
        log_skip "bloqueo de Bluetooth"
    fi

    # ── Sección 3: Deshabilitar core dumps ──
    log_section "3. DESHABILITAR CORE DUMPS"

    if ask "¿Deshabilitar core dumps completamente?"; then
        cp /etc/security/limits.conf "$PBACKUP_DIR/" 2>/dev/null || true
        if ! grep -q "hard core 0" /etc/security/limits.conf; then
            echo "* hard core 0" >> /etc/security/limits.conf
            echo "* soft core 0" >> /etc/security/limits.conf
        fi
        log_change "Modificado" "/etc/security/limits.conf (core dumps)"

        mkdir -p /etc/systemd/coredump.conf.d/
        cat > /etc/systemd/coredump.conf.d/disable.conf << 'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
        log_change "Creado" "/etc/systemd/coredump.conf.d/disable.conf"

        echo "ulimit -c 0" > /etc/profile.d/disable-coredump.sh
        log_change "Creado" "/etc/profile.d/disable-coredump.sh"

        log_info "Core dumps deshabilitados"
    else
        log_skip "deshabilitar core dumps"
    fi

    # ── SECCIÓN 4 ELIMINADA: TMOUT=900 readonly (LIMITA RECURSOS) ──
    log_warn "Sección 4 (TMOUT) OMITIDA: evita limitar recursos del usuario"

    # ── SECCIÓN 5 ELIMINADA: Modificar /etc/pam.d/su (MODIFICA PAM) ──
    log_warn "Sección 5 (PAM su) OMITIDA: evita modificar configuración PAM"

    # ── Sección 6: Restringir cron ──
    log_section "6. RESTRINGIR CRON"

    if ask "¿Restringir cron solo a root y tu usuario?"; then
        echo "root" > /etc/cron.allow
        echo "${SUDO_USER:-root}" >> /etc/cron.allow
        chmod 600 /etc/cron.allow
        rm -f /etc/cron.deny 2>/dev/null || true
        log_change "Creado" "/etc/cron.allow"

        echo "root" > /etc/at.allow
        echo "${SUDO_USER:-root}" >> /etc/at.allow
        chmod 600 /etc/at.allow
        rm -f /etc/at.deny 2>/dev/null || true
        log_change "Creado" "/etc/at.allow"

        log_info "cron/at restringido a root y ${SUDO_USER:-root}"
    else
        log_skip "restricción de cron/at"
    fi

    # ── Sección 7: Banner de advertencia legal ──
    log_section "7. BANNER DE ADVERTENCIA LEGAL"

    if ask "¿Agregar banner de advertencia legal?"; then
        BANNER="
=====================================================================
  SISTEMA PRIVADO - ACCESO NO AUTORIZADO PROHIBIDO

  Este sistema es de uso exclusivo para usuarios autorizados.
  Toda actividad es monitoreada y registrada.
  El acceso no autorizado esta prohibido y sera perseguido
  conforme a la legislacion aplicable.
=====================================================================
"
        echo "$BANNER" > /etc/issue
        log_change "Creado" "/etc/issue"
        echo "$BANNER" > /etc/issue.net
        log_change "Creado" "/etc/issue.net"

        echo "$BANNER" > /etc/ssh/banner
        log_change "Creado" "/etc/ssh/banner"
        if [[ -f /etc/ssh/sshd_config ]]; then
            if ! grep -q "^Banner" /etc/ssh/sshd_config; then
                echo "Banner /etc/ssh/banner" >> /etc/ssh/sshd_config
            fi
        fi

        log_info "Banner legal configurado"
    else
        log_skip "banner de advertencia legal"
    fi

    # ── Sección 8: Permisos restrictivos ──
    log_section "8. PERMISOS RESTRICTIVOS"

    if ask "¿Aplicar permisos restrictivos a archivos del sistema?"; then
        chmod 600 /etc/shadow 2>/dev/null || true
        chmod 600 /etc/gshadow 2>/dev/null || true
        chmod 644 /etc/passwd 2>/dev/null || true
        chmod 644 /etc/group 2>/dev/null || true
        log_change "Permisos" "shadow, gshadow, passwd, group"

        chmod 700 /etc/crontab 2>/dev/null || true
        chmod 700 /etc/cron.d 2>/dev/null || true
        chmod 700 /etc/cron.daily 2>/dev/null || true
        chmod 700 /etc/cron.hourly 2>/dev/null || true
        chmod 700 /etc/cron.weekly 2>/dev/null || true
        chmod 700 /etc/cron.monthly 2>/dev/null || true
        log_change "Permisos" "crontab, cron.d, cron.daily, cron.hourly, cron.weekly, cron.monthly"

        chmod 700 /etc/ssh 2>/dev/null || true
        chmod 600 /etc/ssh/sshd_config 2>/dev/null || true
        chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null || true
        log_change "Permisos" "/etc/ssh, sshd_config, ssh_host_*_key"

        chmod 600 "$GRUB_CFG" 2>/dev/null || true
        log_change "Permisos" "$GRUB_CFG"

        log_info "Permisos restrictivos aplicados"
    else
        log_skip "permisos restrictivos"
    fi

    # ── Sección 9: Proteger GRUB con contraseña ──
    log_section "9. PROTEGER GRUB CON CONTRASEÑA"

    echo "Esto previene que alguien edite parámetros del kernel en boot"
    if ask "¿Proteger GRUB con contraseña?"; then
        echo ""
        echo "Introduce una contraseña para GRUB:"
        grub_set_password
        log_change "Aplicado" "proteccion GRUB con contraseña"

        log_info "GRUB protegido con contraseña"
        log_warn "Necesitarás esta contraseña para editar entradas de GRUB"
    else
        log_skip "protección GRUB con contraseña"
    fi

    # ── Sección 10: Instalar herramientas de seguridad ──
    log_section "10. INSTALAR HERRAMIENTAS DE SEGURIDAD"

    echo "Herramientas disponibles:"
    echo "  - aide: Verificador de integridad de archivos"
    echo "  - rkhunter: Detector de rootkits"
    echo "  - lynis: Auditor de seguridad"
    echo ""

    if ask "¿Instalar AIDE (verificador de integridad)?"; then
        if pkg_install aide; then
            log_info "Inicializando base de datos AIDE..."
            aide --init
            mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null || true
            log_info "AIDE instalado. Ejecutar: aide --check"
        fi
    else
        log_skip "instalación de AIDE"
    fi

    if ask "¿Instalar rkhunter (detector de rootkits)?"; then
        if pkg_install rkhunter; then
            rkhunter --update 2>/dev/null || true
            rkhunter --propupd 2>/dev/null || true
            log_info "rkhunter instalado. Ejecutar: rkhunter --check"
        fi
    else
        log_skip "instalación de rkhunter"
    fi

    if ask "¿Instalar lynis (auditor de seguridad)?"; then
        if pkg_install lynis; then
            log_info "lynis instalado. Ejecutar: lynis audit system"
        fi
    else
        log_skip "instalación de lynis"
    fi

    # ── Sección 11: Firewall paranoico ──
    log_section "11. FIREWALL PARANOICO"

    if ask "¿Configurar firewall en modo paranoico (DROP por defecto)?"; then
        systemctl enable --now firewalld 2>/dev/null || true
        log_change "Servicio" "firewalld habilitado e iniciado"

        fw_set_default_zone drop
        log_change "Aplicado" "zona por defecto: drop"

        fw_add_service dhcpv6-client work
        fw_add_service dns work

        fw_add_icmp_block echo-request
        log_change "Aplicado" "ICMP block: echo-request"
        fw_add_icmp_block timestamp-request
        log_change "Aplicado" "ICMP block: timestamp-request"
        fw_add_icmp_block timestamp-reply
        log_change "Aplicado" "ICMP block: timestamp-reply"

        fw_set_log_denied all
        log_change "Aplicado" "log-denied: all"

        fw_reload

        log_info "Firewall configurado en modo paranoico"
        log_warn "Zona por defecto: DROP (bloquea todo lo no explícito)"
    else
        log_skip "firewall paranoico"
    fi

    # ── Sección 12: CUPS restringir ──
    log_section "12. CUPS - RESTRINGIR"

    if systemctl is-active cups &>/dev/null; then
        echo "CUPS está activo (impresión)"
        if ask "¿Restringir CUPS solo a localhost?"; then
            cp /etc/cups/cupsd.conf "$PBACKUP_DIR/" 2>/dev/null || true

            sed -i 's/^Listen.*/Listen localhost:631/' /etc/cups/cupsd.conf 2>/dev/null || true
            sed -i 's/^Port.*/# Port 631/' /etc/cups/cupsd.conf 2>/dev/null || true
            sed -i 's/^Browsing.*/Browsing Off/' /etc/cups/cupsd.conf 2>/dev/null || true
            log_change "Modificado" "/etc/cups/cupsd.conf (localhost only)"

            systemctl restart cups || true
            log_change "Servicio" "cups reiniciado"
            log_info "CUPS restringido a localhost"
        else
            log_skip "restricción de CUPS a localhost"
        fi

        if ask "¿Deshabilitar CUPS completamente (no podrás imprimir)?"; then
            systemctl stop cups 2>/dev/null || true
            systemctl disable cups 2>/dev/null || true
            log_change "Servicio" "cups deshabilitado"
            log_info "CUPS deshabilitado"
        else
            log_skip "deshabilitar CUPS"
        fi
    fi

    # ── Sección 13: Umask restrictivo ──
    log_section "13. UMASK RESTRICTIVO"

    if ask "¿Configurar umask restrictivo (027)?"; then
        if ! grep -q "umask 027" /etc/profile; then
            echo "umask 027" >> /etc/profile
        fi

        if [[ -f /etc/bashrc ]] && ! grep -q "umask 027" /etc/bashrc; then
            echo "umask 027" >> /etc/bashrc
        fi

        sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs 2>/dev/null || true
        log_change "Modificado" "umask 027 en /etc/profile, /etc/bashrc, /etc/login.defs"

        log_info "umask configurado a 027 (archivos: 640, directorios: 750)"
    else
        log_skip "umask restrictivo"
    fi

    # ── Sección 14: Deshabilitar USB storage ──
    log_section "14. DESHABILITAR USB STORAGE (OPCIONAL)"

    log_warn "CUIDADO: Esto impedirá usar memorias USB"
    if ask "¿Bloquear almacenamiento USB (memorias, discos externos)?"; then
        echo "install usb-storage /bin/false" >> /etc/modprobe.d/paranoid-blacklist.conf
        rmmod usb_storage 2>/dev/null || true
        log_change "Modificado" "/etc/modprobe.d/paranoid-blacklist.conf (usb-storage)"
        log_info "USB storage bloqueado"
    else
        log_skip "bloqueo de USB storage"
    fi

    # ── Sección 15: Auditoría avanzada ──
    log_section "15. AUDITORÍA AVANZADA"

    if systemctl is-active auditd &>/dev/null; then
        if ask "¿Configurar reglas de auditoría paranoicas?"; then
            cat > /etc/audit/rules.d/99-paranoid.rules << 'EOF'
# Eliminar reglas anteriores
-D

# Buffer grande
-b 8192

# Fallar si no puede auditar
-f 1

# Monitorear cambios en usuarios y grupos
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Monitorear sudoers
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Monitorear cambios en PAM
-w /etc/pam.d/ -p wa -k pam

# Monitorear SSH
-w /etc/ssh/sshd_config -p wa -k sshd

# Monitorear cron
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# Monitorear logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
-w /var/run/utmp -p wa -k logins

# Monitorear hora del sistema
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change

# Monitorear cambios en red
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-w /etc/hostname -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale

# Monitorear módulos del kernel
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# Monitorear montajes
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

# Monitorear borrado de archivos
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

# Monitorear uso de sudo
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k privilege_escalation

# Monitorear acceso a archivos sensibles
-w /etc/passwd -p r -k passwd_read
-w /etc/shadow -p r -k shadow_read

# Hacer reglas inmutables (requiere reboot para cambiar)
-e 2
EOF
            log_change "Creado" "/etc/audit/rules.d/99-paranoid.rules"

            augenrules --load 2>/dev/null || service auditd restart
            log_info "Auditoría paranoica configurada"
            log_warn "Reglas inmutables: requiere reboot para modificar"
        else
            log_skip "reglas de auditoría paranoicas"
        fi
    fi

    # ── Sección 16: Fail2ban agresivo ──
    log_section "16. FAIL2BAN AGRESIVO"

    if command -v fail2ban-client &>/dev/null; then
        if ask "¿Configurar fail2ban en modo agresivo?"; then
            cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 24h
findtime = 10m
maxretry = 3
ignoreip = 127.0.0.1/8 ::1
banaction = firewallcmd-rich-rules[actiontype=<multiport>]
banaction_allports = firewallcmd-rich-rules[actiontype=<allports>]

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/secure
maxretry = 3
bantime = 48h

[sshd-ddos]
enabled = true
port = ssh
filter = sshd-ddos
logpath = /var/log/secure
maxretry = 2
bantime = 72h
EOF
            log_change "Creado" "/etc/fail2ban/jail.local"

            systemctl restart fail2ban || true
            log_change "Servicio" "fail2ban reiniciado"
            log_info "fail2ban configurado en modo agresivo"
            log_info "  - Ban general: 24h, SSH: 48h, DDoS: 72h"
        else
            log_skip "fail2ban agresivo"
        fi
    else
        log_warn "fail2ban no instalado. Instálalo primero."
    fi

    log_info "Módulo 6 (paranoico seguro) completado"
}

# ============================================================
# MÓDULO 7: contramedidas-mesh.sh (SEGURO - delegado)
# ============================================================
mod_07_mesh() {
    log_section "MÓDULO 7: Contramedidas mesh"
    local script="$SCRIPT_DIR/contramedidas-mesh.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 7 completado"
        else
            log_warn "Módulo 7 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 8: contramedidas-avanzadas.sh (SEGURO - delegado)
# ============================================================
mod_08_avanzadas() {
    log_section "MÓDULO 8: Contramedidas avanzadas"
    local script="$SCRIPT_DIR/contramedidas-avanzadas.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 8 completado"
        else
            log_warn "Módulo 8 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 9: proteger-privacidad.sh (SEGURO - delegado)
# ============================================================
mod_09_privacidad() {
    log_section "MÓDULO 9: Proteger privacidad"
    local script="$SCRIPT_DIR/proteger-privacidad.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 9 completado"
        else
            log_warn "Módulo 9 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 10: aplicar-banner-total.sh (SEGURO - delegado)
# ============================================================
mod_10_banners() {
    log_section "MÓDULO 10: Aplicar banners"
    local script="$SCRIPT_DIR/aplicar-banner-total.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 10 completado"
        else
            log_warn "Módulo 10 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 11: hardening-kernel-boot.sh (SEGURO - delegado)
# ============================================================
mod_11_kernel_boot() {
    log_section "MÓDULO 11: Kernel boot y Secure Boot"
    local script="$SCRIPT_DIR/hardening-kernel-boot.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 11 completado"
        else
            log_warn "Módulo 11 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 12: hardening-servicios-systemd.sh (SEGURO - delegado)
# ============================================================
mod_12_servicios_systemd() {
    log_section "MÓDULO 12: Sandboxing de servicios systemd"
    local script="$SCRIPT_DIR/hardening-servicios-systemd.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 12 completado"
        else
            log_warn "Módulo 12 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 13: hardening-cuentas.sh (SEGURO - delegado)
# ============================================================
mod_13_cuentas() {
    log_section "MÓDULO 13: Seguridad de cuentas"
    local script="$SCRIPT_DIR/hardening-cuentas.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 13 completado"
        else
            log_warn "Módulo 13 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 14: proteger-red-avanzado.sh (SEGURO - delegado)
# ============================================================
mod_14_red_avanzada() {
    log_section "MÓDULO 14: Red avanzada (IDS/DoT/VPN)"
    local script="$SCRIPT_DIR/proteger-red-avanzado.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 14 completado"
        else
            log_warn "Módulo 14 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 15: automatizar-seguridad.sh (SEGURO - delegado)
# ============================================================
mod_15_automatizacion() {
    log_section "MÓDULO 15: Automatización de seguridad"
    local script="$SCRIPT_DIR/automatizar-seguridad.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 15 completado"
        else
            log_warn "Módulo 15 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 16: sandbox-aplicaciones.sh (SEGURO - delegado)
# ============================================================
mod_16_sandbox() {
    log_section "MÓDULO 16: Sandboxing de aplicaciones"
    local script="$SCRIPT_DIR/sandbox-aplicaciones.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 16 completado"
        else
            log_warn "Módulo 16 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 17: auditoria-externa.sh (SEGURO - delegado)
# ============================================================
mod_17_auditoria_externa() {
    log_section "MÓDULO 17: Auditoría externa (reconocimiento TA0043)"
    local script="$SCRIPT_DIR/auditoria-externa.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 17 completado"
        else
            log_warn "Módulo 17 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 18: inteligencia-amenazas.sh (SEGURO - delegado)
# ============================================================
mod_18_threat_intel() {
    log_section "MÓDULO 18: Inteligencia de amenazas (IoC feeds M1019)"
    local script="$SCRIPT_DIR/inteligencia-amenazas.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 18 completado"
        else
            log_warn "Módulo 18 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 19: mitigar-acceso-inicial.sh (SEGURO - delegado)
# ============================================================
mod_19_acceso_inicial() {
    log_section "MÓDULO 19: Mitigación acceso inicial (TA0001)"
    local script="$SCRIPT_DIR/mitigar-acceso-inicial.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 19 completado"
        else
            log_warn "Módulo 19 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 20: mitigar-ejecucion.sh (SEGURO - delegado)
# ============================================================
mod_20_ejecucion() {
    log_section "MÓDULO 20: Mitigación ejecución (TA0002)"
    local script="$SCRIPT_DIR/mitigar-ejecucion.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 20 completado"
        else
            log_warn "Módulo 20 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 21: mitigar-persistencia.sh (SEGURO - delegado)
# ============================================================
mod_21_persistencia() {
    log_section "MÓDULO 21: Mitigación persistencia (TA0003)"
    local script="$SCRIPT_DIR/mitigar-persistencia.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 21 completado"
        else
            log_warn "Módulo 21 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 22: mitigar-escalada.sh (SEGURO - delegado)
# ============================================================
mod_22_escalada() {
    log_section "MÓDULO 22: Mitigación escalada de privilegios (TA0004)"
    local script="$SCRIPT_DIR/mitigar-escalada.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 22 completado"
        else
            log_warn "Módulo 22 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 23: mitigar-impacto.sh (SEGURO - delegado)
# ============================================================
mod_23_impacto() {
    log_section "MÓDULO 23: Mitigación de impacto (TA0040)"
    local script="$SCRIPT_DIR/mitigar-impacto.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 23 completado"
        else
            log_warn "Módulo 23 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 24: mitigar-evasion.sh (SEGURO - delegado)
# ============================================================
mod_24_evasion() {
    log_section "MÓDULO 24: Mitigación de evasión de defensas (TA0005)"
    local script="$SCRIPT_DIR/mitigar-evasion.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 24 completado"
        else
            log_warn "Módulo 24 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 25: mitigar-credenciales.sh (SEGURO - delegado)
# ============================================================
mod_25_credenciales() {
    log_section "MÓDULO 25: Mitigación de acceso a credenciales (TA0006)"
    local script="$SCRIPT_DIR/mitigar-credenciales.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 25 completado"
        else
            log_warn "Módulo 25 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 26: mitigar-descubrimiento.sh (SEGURO - delegado)
# ============================================================
mod_26_descubrimiento() {
    log_section "MÓDULO 26: Mitigación de descubrimiento (TA0007)"
    local script="$SCRIPT_DIR/mitigar-descubrimiento.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 26 completado"
        else
            log_warn "Módulo 26 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 27: mitigar-movimiento-lateral.sh (SEGURO - delegado)
# ============================================================
mod_27_movimiento_lateral() {
    log_section "MÓDULO 27: Mitigación de movimiento lateral (TA0008)"
    local script="$SCRIPT_DIR/mitigar-movimiento-lateral.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 27 completado"
        else
            log_warn "Módulo 27 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 28: mitigar-recoleccion.sh (SEGURO - delegado)
# ============================================================
mod_28_recoleccion() {
    log_section "MÓDULO 28: Mitigación de recolección (TA0009)"
    local script="$SCRIPT_DIR/mitigar-recoleccion.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 28 completado"
        else
            log_warn "Módulo 28 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 29: mitigar-exfiltracion.sh (SEGURO - delegado)
# ============================================================
mod_29_exfiltracion() {
    log_section "MÓDULO 29: Mitigación de exfiltración (TA0010)"
    local script="$SCRIPT_DIR/mitigar-exfiltracion.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 29 completado"
        else
            log_warn "Módulo 29 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 30: mitigar-comando-control.sh (SEGURO - delegado)
# ============================================================
mod_30_comando_control() {
    log_section "MÓDULO 30: Mitigación de comando y control (TA0011)"
    local script="$SCRIPT_DIR/mitigar-comando-control.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 30 completado"
        else
            log_warn "Módulo 30 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

mod_31_respuesta_incidentes() {
    log_section "MÓDULO 31: Respuesta a incidentes"
    local script="$SCRIPT_DIR/respuesta-incidentes.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 31 completado"
        else
            log_warn "Módulo 31 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

mod_32_monitorizar() {
    log_section "MÓDULO 32: Monitorización continua"
    local script="$SCRIPT_DIR/monitorizar-continuo.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 32 completado"
        else
            log_warn "Módulo 32 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

mod_33_reportes() {
    log_section "MÓDULO 33: Reportes de seguridad"
    local script="$SCRIPT_DIR/reportar-seguridad.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 33 completado"
        else
            log_warn "Módulo 33 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

mod_34_cazar_amenazas() {
    log_section "MÓDULO 34: Caza de amenazas"
    local script="$SCRIPT_DIR/cazar-amenazas.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 34 completado"
        else
            log_warn "Módulo 34 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

mod_35_automatizar_respuesta() {
    log_section "MÓDULO 35: Automatización de respuesta"
    local script="$SCRIPT_DIR/automatizar-respuesta.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 35 completado"
        else
            log_warn "Módulo 35 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

mod_36_validar_controles() {
    log_section "MÓDULO 36: Validación de controles"
    local script="$SCRIPT_DIR/validar-controles.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 36 completado"
        else
            log_warn "Módulo 36 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 37: ciberinteligencia.sh (delegado)
# ============================================================
mod_37_ciberinteligencia() {
    log_section "MÓDULO 37: Ciberinteligencia proactiva"
    local script="$SCRIPT_DIR/ciberinteligencia.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 37 completado"
        else
            log_warn "Módulo 37 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 38: proteger-contra-isp.sh (delegado)
# ============================================================
mod_38_proteger_isp() {
    log_section "MÓDULO 38: Protección contra espionaje ISP"
    local script="$SCRIPT_DIR/proteger-contra-isp.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 38 completado"
        else
            log_warn "Módulo 38 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 39: hardening-criptografico.sh (delegado)
# ============================================================
mod_39_hardening_crypto() {
    log_section "MÓDULO 39: Hardening criptográfico"
    local script="$SCRIPT_DIR/hardening-criptografico.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 39 completado"
        else
            log_warn "Módulo 39 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 40: seguridad-contenedores.sh (delegado)
# ============================================================
mod_40_contenedores() {
    log_section "MÓDULO 40: Seguridad de contenedores"
    local script="$SCRIPT_DIR/seguridad-contenedores.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 40 completado"
        else
            log_warn "Módulo 40 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 41: cumplimiento-cis.sh (delegado)
# ============================================================
mod_41_cumplimiento_cis() {
    log_section "MÓDULO 41: Cumplimiento CIS Benchmarks"
    local script="$SCRIPT_DIR/cumplimiento-cis.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 41 completado"
        else
            log_warn "Módulo 41 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 42: seguridad-email.sh (delegado)
# ============================================================
mod_42_seguridad_email() {
    log_section "MÓDULO 42: Seguridad de email"
    local script="$SCRIPT_DIR/seguridad-email.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 42 completado"
        else
            log_warn "Módulo 42 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 43: logging-centralizado.sh (delegado)
# ============================================================
mod_43_logging_centralizado() {
    log_section "MÓDULO 43: Logging centralizado y SIEM"
    local script="$SCRIPT_DIR/logging-centralizado.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 43 completado"
        else
            log_warn "Módulo 43 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 44: seguridad-cadena-suministro.sh (delegado)
# ============================================================
mod_44_cadena_suministro() {
    log_section "MÓDULO 44: Seguridad de cadena de suministro"
    local script="$SCRIPT_DIR/seguridad-cadena-suministro.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 44 completado"
        else
            log_warn "Módulo 44 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 45: segmentacion-red-zt.sh (delegado)
# ============================================================
mod_45_segmentacion_zt() {
    log_section "MÓDULO 45: Segmentación de red y Zero Trust"
    local script="$SCRIPT_DIR/segmentacion-red-zt.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 45 completado"
        else
            log_warn "Módulo 45 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 46: forense-avanzado.sh (delegado)
# ============================================================
mod_46_forense_avanzado() {
    log_section "MÓDULO 46: Forense avanzado"
    local script="$SCRIPT_DIR/forense-avanzado.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 46 completado"
        else
            log_warn "Módulo 46 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# MÓDULO 47: kernel-livepatch.sh (delegado)
# ============================================================
mod_47_kernel_livepatch() {
    log_section "MÓDULO 47: Kernel live patching"
    local script="$SCRIPT_DIR/kernel-livepatch.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 47 completado"
        else
            log_warn "Módulo 47 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

mod_48_seguridad_bases_datos() {
    log_section "MÓDULO 48: Seguridad de bases de datos"
    local script="$SCRIPT_DIR/seguridad-bases-datos.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 48 completado"
        else
            log_warn "Módulo 48 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

mod_49_backup_recuperacion() {
    log_section "MÓDULO 49: Backup y recuperación ante desastres"
    local script="$SCRIPT_DIR/backup-recuperacion.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 49 completado"
        else
            log_warn "Módulo 49 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

mod_50_seguridad_web() {
    log_section "MÓDULO 50: Seguridad de aplicaciones web"
    local script="$SCRIPT_DIR/seguridad-web.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 50 completado"
        else
            log_warn "Módulo 50 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ── MÓDULO 51: seguridad-secrets.sh (delegado) ──
mod_51_secrets_management() {
    log_section "MÓDULO 51: Gestión de secretos"
    local script="$SCRIPT_DIR/seguridad-secrets.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 51 completado"
        else
            log_warn "Módulo 51 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ── MÓDULO 52: seguridad-cloud.sh (delegado) ──
mod_52_seguridad_cloud() {
    log_section "MÓDULO 52: Seguridad cloud"
    local script="$SCRIPT_DIR/seguridad-cloud.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 52 completado"
        else
            log_warn "Módulo 52 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ── MÓDULO 53: seguridad-ldap-ad.sh (delegado) ──
mod_53_seguridad_ldap() {
    log_section "MÓDULO 53: LDAP y Active Directory"
    local script="$SCRIPT_DIR/seguridad-ldap-ad.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 53 completado"
        else
            log_warn "Módulo 53 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

mod_54_cumplimiento_normativo() {
    log_section "MÓDULO 54: Cumplimiento normativo"
    local script="$SCRIPT_DIR/cumplimiento-normativo.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 54 completado"
        else
            log_warn "Módulo 54 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

mod_55_deception_tech() {
    log_section "MÓDULO 55: Tecnología de engaño"
    local script="$SCRIPT_DIR/tecnologia-engano.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 55 completado"
        else
            log_warn "Módulo 55 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

mod_56_seguridad_wireless() {
    log_section "MÓDULO 56: Seguridad wireless"
    local script="$SCRIPT_DIR/seguridad-wireless.sh"
    if [[ -f "$script" ]]; then
        local rc=0
        bash "$script" || rc=$?
        if [[ $rc -eq 0 ]]; then
            log_info "Módulo 56 completado"
        else
            log_warn "Módulo 56 terminó con código $rc"
        fi
        return $rc
    else
        log_error "No encontrado: $script"
        return 1
    fi
}

# ============================================================
# REGISTRO DE MÓDULOS (metadata para sub-menús)
# ============================================================
declare -a MOD_NAMES=() MOD_DESCS=() MOD_FUNCS=() MOD_FILES=() MOD_TAGS=()

MOD_NAMES[1]="Hardening openSUSE base";       MOD_DESCS[1]="Kernel, SSH, firewall, MFA, ClamAV";    MOD_FUNCS[1]="mod_01_opensuse";           MOD_FILES[1]="hardening-opensuse.sh";           MOD_TAGS[1]=""
MOD_NAMES[2]="Hardening seguro";               MOD_DESCS[2]="Archivos, procesos, AIDE, SSH keys";    MOD_FUNCS[2]="mod_02_seguro";             MOD_FILES[2]="hardening-seguro.sh";             MOD_TAGS[2]=""
MOD_NAMES[3]="Hardening final";                MOD_DESCS[3]="Auditd, sysctl, firewall, updates";     MOD_FUNCS[3]="mod_03_final";              MOD_FILES[3]="hardening-final.sh";              MOD_TAGS[3]=""
MOD_NAMES[4]="Hardening externo";              MOD_DESCS[4]="Banners, honeypot, DNS, VPN";           MOD_FUNCS[4]="mod_04_externo";            MOD_FILES[4]="hardening-externo.sh";            MOD_TAGS[4]=""
MOD_NAMES[5]="Hardening extremo";              MOD_DESCS[5]="USB, kernel, red (sin lockout)";        MOD_FUNCS[5]="mod_05_extremo_seguro";     MOD_FILES[5]="";                                MOD_TAGS[5]="SEGURO"
MOD_NAMES[6]="Hardening paranoico";            MOD_DESCS[6]="Core dumps, GRUB, audit (sin PAM)";     MOD_FUNCS[6]="mod_06_paranoico_seguro";   MOD_FILES[6]="";                                MOD_TAGS[6]="SEGURO"
MOD_NAMES[7]="Contramedidas mesh";             MOD_DESCS[7]="WiFi, Bluetooth, IoT mesh";             MOD_FUNCS[7]="mod_07_mesh";               MOD_FILES[7]="contramedidas-mesh.sh";           MOD_TAGS[7]=""
MOD_NAMES[8]="Contramedidas avanzadas";        MOD_DESCS[8]="TEMPEST, acústico, side-channel";       MOD_FUNCS[8]="mod_08_avanzadas";          MOD_FILES[8]="contramedidas-avanzadas.sh";      MOD_TAGS[8]=""
MOD_NAMES[9]="Proteger privacidad";            MOD_DESCS[9]="VNC, cámara, DNS leaks, Tor";           MOD_FUNCS[9]="mod_09_privacidad";         MOD_FILES[9]="proteger-privacidad.sh";          MOD_TAGS[9]=""
MOD_NAMES[10]="Aplicar banners";               MOD_DESCS[10]="MOTD, issue, SSH, GDM, Firefox";       MOD_FUNCS[10]="mod_10_banners";           MOD_FILES[10]="aplicar-banner-total.sh";        MOD_TAGS[10]=""
MOD_NAMES[11]="Kernel boot y Secure Boot";     MOD_DESCS[11]="GRUB cmdline, firmas, lockdown";       MOD_FUNCS[11]="mod_11_kernel_boot";       MOD_FILES[11]="hardening-kernel-boot.sh";       MOD_TAGS[11]=""
MOD_NAMES[12]="Sandboxing de servicios";       MOD_DESCS[12]="Drop-ins systemd para servicios";      MOD_FUNCS[12]="mod_12_servicios_systemd"; MOD_FILES[12]="hardening-servicios-systemd.sh"; MOD_TAGS[12]=""
MOD_NAMES[13]="Seguridad de cuentas";          MOD_DESCS[13]="Contraseñas, faillock, UID=0";         MOD_FUNCS[13]="mod_13_cuentas";           MOD_FILES[13]="hardening-cuentas.sh";           MOD_TAGS[13]=""
MOD_NAMES[14]="Red avanzada";                  MOD_DESCS[14]="Suricata IDS, DoT, VPN, ARP";          MOD_FUNCS[14]="mod_14_red_avanzada";      MOD_FILES[14]="proteger-red-avanzado.sh";       MOD_TAGS[14]=""
MOD_NAMES[15]="Automatización";                MOD_DESCS[15]="AIDE, rkhunter, lynis, digest";        MOD_FUNCS[15]="mod_15_automatizacion";    MOD_FILES[15]="automatizar-seguridad.sh";       MOD_TAGS[15]=""
MOD_NAMES[16]="Sandboxing de aplicaciones";    MOD_DESCS[16]="Firejail, bubblewrap, perfiles";       MOD_FUNCS[16]="mod_16_sandbox";           MOD_FILES[16]="sandbox-aplicaciones.sh";        MOD_TAGS[16]=""
MOD_NAMES[17]="Auditoría externa";             MOD_DESCS[17]="TA0043 reconocimiento, Shodan";        MOD_FUNCS[17]="mod_17_auditoria_externa"; MOD_FILES[17]="auditoria-externa.sh";           MOD_TAGS[17]=""
MOD_NAMES[18]="Inteligencia de amenazas";      MOD_DESCS[18]="M1019 IoC feeds, ipset, Suricata";     MOD_FUNCS[18]="mod_18_threat_intel";      MOD_FILES[18]="inteligencia-amenazas.sh";       MOD_TAGS[18]=""
MOD_NAMES[19]="Acceso inicial";                MOD_DESCS[19]="TA0001 SSH, exploits, phishing";       MOD_FUNCS[19]="mod_19_acceso_inicial";    MOD_FILES[19]="mitigar-acceso-inicial.sh";      MOD_TAGS[19]=""
MOD_NAMES[20]="Ejecución";                     MOD_DESCS[20]="TA0002 AppArmor, noexec, intérpretes"; MOD_FUNCS[20]="mod_20_ejecucion";         MOD_FILES[20]="mitigar-ejecucion.sh";           MOD_TAGS[20]=""
MOD_NAMES[21]="Persistencia";                  MOD_DESCS[21]="TA0003 cron, systemd, auth, PATH";     MOD_FUNCS[21]="mod_21_persistencia";      MOD_FILES[21]="mitigar-persistencia.sh";        MOD_TAGS[21]=""
MOD_NAMES[22]="Escalada de privilegios";       MOD_DESCS[22]="TA0004 SUID, sudo, ptrace, kernel";    MOD_FUNCS[22]="mod_22_escalada";          MOD_FILES[22]="mitigar-escalada.sh";            MOD_TAGS[22]=""
MOD_NAMES[23]="Impacto";                       MOD_DESCS[23]="TA0040 ransomware, backups, recovery";  MOD_FUNCS[23]="mod_23_impacto";           MOD_FILES[23]="mitigar-impacto.sh";             MOD_TAGS[23]=""
MOD_NAMES[24]="Evasión de defensas";           MOD_DESCS[24]="TA0005 logs, rootkits, LOLBins";        MOD_FUNCS[24]="mod_24_evasion";           MOD_FILES[24]="mitigar-evasion.sh";             MOD_TAGS[24]=""
MOD_NAMES[25]="Acceso a credenciales";         MOD_DESCS[25]="TA0006 dumping, brute force, MITM";     MOD_FUNCS[25]="mod_25_credenciales";      MOD_FILES[25]="mitigar-credenciales.sh";        MOD_TAGS[25]=""
MOD_NAMES[26]="Descubrimiento";                MOD_DESCS[26]="TA0007 portscan, procesos, red";        MOD_FUNCS[26]="mod_26_descubrimiento";    MOD_FILES[26]="mitigar-descubrimiento.sh";      MOD_TAGS[26]=""
MOD_NAMES[27]="Movimiento lateral";            MOD_DESCS[27]="TA0008 SSH, SMB, segmentación";         MOD_FUNCS[27]="mod_27_movimiento_lateral"; MOD_FILES[27]="mitigar-movimiento-lateral.sh"; MOD_TAGS[27]=""
MOD_NAMES[28]="Recolección";                   MOD_DESCS[28]="TA0009 datos, USB, staging, captura";   MOD_FUNCS[28]="mod_28_recoleccion";       MOD_FILES[28]="mitigar-recoleccion.sh";         MOD_TAGS[28]=""
MOD_NAMES[29]="Exfiltración";                  MOD_DESCS[29]="TA0010 DNS tunnel, cloud, tráfico";     MOD_FUNCS[29]="mod_29_exfiltracion";      MOD_FILES[29]="mitigar-exfiltracion.sh";        MOD_TAGS[29]=""
MOD_NAMES[30]="Comando y control";             MOD_DESCS[30]="TA0011 C2, beaconing, proxy, DGA";      MOD_FUNCS[30]="mod_30_comando_control";   MOD_FILES[30]="mitigar-comando-control.sh";     MOD_TAGS[30]=""
MOD_NAMES[31]="Respuesta a incidentes";        MOD_DESCS[31]="IR, forense, playbooks, contención";    MOD_FUNCS[31]="mod_31_respuesta_incidentes"; MOD_FILES[31]="respuesta-incidentes.sh";      MOD_TAGS[31]=""
MOD_NAMES[32]="Monitorización continua";       MOD_DESCS[32]="Dashboard, correlación, baseline";      MOD_FUNCS[32]="mod_32_monitorizar";       MOD_FILES[32]="monitorizar-continuo.sh";        MOD_TAGS[32]=""
MOD_NAMES[33]="Reportes de seguridad";         MOD_DESCS[33]="MITRE report, Navigator, compliance";   MOD_FUNCS[33]="mod_33_reportes";          MOD_FILES[33]="reportar-seguridad.sh";          MOD_TAGS[33]=""
MOD_NAMES[34]="Caza de amenazas";              MOD_DESCS[34]="UEBA, hunting, T1098, anomalías red";   MOD_FUNCS[34]="mod_34_cazar_amenazas";    MOD_FILES[34]="cazar-amenazas.sh";              MOD_TAGS[34]=""
MOD_NAMES[35]="Automatización de respuesta";   MOD_DESCS[35]="SOAR, auto-bloqueo, notificación";      MOD_FUNCS[35]="mod_35_automatizar_respuesta"; MOD_FILES[35]="automatizar-respuesta.sh";   MOD_TAGS[35]=""
MOD_NAMES[36]="Validación de controles";       MOD_DESCS[36]="Purple team, simulación, scoring";      MOD_FUNCS[36]="mod_36_validar_controles"; MOD_FILES[36]="validar-controles.sh";           MOD_TAGS[36]=""
MOD_NAMES[37]="Ciberinteligencia proactiva";   MOD_DESCS[37]="IoC enrich, red, DNS, superficie, SOAR"; MOD_FUNCS[37]="mod_37_ciberinteligencia";  MOD_FILES[37]="ciberinteligencia.sh";           MOD_TAGS[37]=""
MOD_NAMES[38]="Protección contra ISP";        MOD_DESCS[38]="Kill switch, DNS leak, ECH, DPI, NTS"; MOD_FUNCS[38]="mod_38_proteger_isp";       MOD_FILES[38]="proteger-contra-isp.sh";         MOD_TAGS[38]=""
MOD_NAMES[39]="Hardening criptográfico";      MOD_DESCS[39]="SSH, TLS, certificados, LUKS, NTS";    MOD_FUNCS[39]="mod_39_hardening_crypto";   MOD_FILES[39]="hardening-criptografico.sh";     MOD_TAGS[39]=""
MOD_NAMES[40]="Seguridad de contenedores";    MOD_DESCS[40]="Docker, Podman, seccomp, K8s, CIS";    MOD_FUNCS[40]="mod_40_contenedores";       MOD_FILES[40]="seguridad-contenedores.sh";      MOD_TAGS[40]=""
MOD_NAMES[41]="Cumplimiento CIS";             MOD_DESCS[41]="CIS Benchmark, NIST 800-53, scoring";  MOD_FUNCS[41]="mod_41_cumplimiento_cis";   MOD_FILES[41]="cumplimiento-cis.sh";            MOD_TAGS[41]=""
MOD_NAMES[42]="Seguridad de email";           MOD_DESCS[42]="SPF, DKIM, DMARC, TLS, anti-relay";   MOD_FUNCS[42]="mod_42_seguridad_email";    MOD_FILES[42]="seguridad-email.sh";             MOD_TAGS[42]=""
MOD_NAMES[43]="Logging centralizado";         MOD_DESCS[43]="rsyslog TLS, SIEM, correlación, forense"; MOD_FUNCS[43]="mod_43_logging_centralizado"; MOD_FILES[43]="logging-centralizado.sh";    MOD_TAGS[43]=""
MOD_NAMES[44]="Cadena de suministro";         MOD_DESCS[44]="SBOM, CVEs, firmas, integridad";       MOD_FUNCS[44]="mod_44_cadena_suministro";  MOD_FILES[44]="seguridad-cadena-suministro.sh"; MOD_TAGS[44]=""
MOD_NAMES[45]="Segmentación de red";          MOD_DESCS[45]="Zonas, microseg, Zero Trust, ZT";      MOD_FUNCS[45]="mod_45_segmentacion_zt";    MOD_FILES[45]="segmentacion-red-zt.sh";         MOD_TAGS[45]=""
MOD_NAMES[46]="Forense avanzado";             MOD_DESCS[46]="Memoria, disco, timeline, custodia";   MOD_FUNCS[46]="mod_46_forense_avanzado";   MOD_FILES[46]="forense-avanzado.sh";            MOD_TAGS[46]=""
MOD_NAMES[47]="Kernel live patching";         MOD_DESCS[47]="Livepatch, CVEs, exploits, módulos";   MOD_FUNCS[47]="mod_47_kernel_livepatch";   MOD_FILES[47]="kernel-livepatch.sh";            MOD_TAGS[47]=""
MOD_NAMES[48]="Seguridad de bases de datos"; MOD_DESCS[48]="PostgreSQL, MySQL, Redis, MongoDB";    MOD_FUNCS[48]="mod_48_seguridad_bases_datos"; MOD_FILES[48]="seguridad-bases-datos.sh";    MOD_TAGS[48]=""
MOD_NAMES[49]="Backup y recuperación";       MOD_DESCS[49]="3-2-1, borg, restic, inmutable, DR";   MOD_FUNCS[49]="mod_49_backup_recuperacion";MOD_FILES[49]="backup-recuperacion.sh";         MOD_TAGS[49]=""
MOD_NAMES[50]="Seguridad web";              MOD_DESCS[50]="WAF, ModSecurity, headers, TLS, DDoS"; MOD_FUNCS[50]="mod_50_seguridad_web";      MOD_FILES[50]="seguridad-web.sh";               MOD_TAGS[50]=""
MOD_NAMES[51]="Gestión de secretos";       MOD_DESCS[51]="Vault, rotación, escaneo, SSH keys";  MOD_FUNCS[51]="mod_51_secrets_management"; MOD_FILES[51]="seguridad-secrets.sh";            MOD_TAGS[51]=""
MOD_NAMES[52]="Seguridad cloud";           MOD_DESCS[52]="AWS, Azure, GCP, IAM, postura";       MOD_FUNCS[52]="mod_52_seguridad_cloud";    MOD_FILES[52]="seguridad-cloud.sh";              MOD_TAGS[52]=""
MOD_NAMES[53]="LDAP y Active Directory";   MOD_DESCS[53]="LDAP TLS, FreeIPA, sssd, Kerberos";   MOD_FUNCS[53]="mod_53_seguridad_ldap";     MOD_FILES[53]="seguridad-ldap-ad.sh";            MOD_TAGS[53]=""
MOD_NAMES[54]="Cumplimiento normativo";    MOD_DESCS[54]="PCI-DSS, HIPAA, GDPR, SOC2, ISO27001"; MOD_FUNCS[54]="mod_54_cumplimiento_normativo"; MOD_FILES[54]="cumplimiento-normativo.sh";  MOD_TAGS[54]=""
MOD_NAMES[55]="Tecnología de engaño";      MOD_DESCS[55]="Honeypots, honeytokens, decoys, canary"; MOD_FUNCS[55]="mod_55_deception_tech";      MOD_FILES[55]="tecnologia-engano.sh";           MOD_TAGS[55]=""
MOD_NAMES[56]="Seguridad wireless";        MOD_DESCS[56]="WPA3, RADIUS, rogue AP, 802.1X";     MOD_FUNCS[56]="mod_56_seguridad_wireless"; MOD_FILES[56]="seguridad-wireless.sh";           MOD_TAGS[56]=""

# ============================================================
# APLICAR TODO SEGURO
# ============================================================
aplicar_todo_seguro() {
    echo ""
    echo -e "  ${BG_GREEN} APLICAR TODO SEGURO ${NC}"
    echo ""
    echo -e "  Se ejecutarán ${BOLD}56 módulos${NC} de hardening secuencialmente."
    echo -e "  Los scripts peligrosos se ejecutan en versión ${YELLOW}SEGURA${NC}."
    echo -e "  Incluye mitigaciones MITRE: ${CYAN}TA0043, TA0001-TA0011, TA0040${NC}."
    echo ""
    echo -e "  ${DIM}Categorías:${NC}"
    echo -e "    ${BLUE}1-10${NC}  ${DIM}Hardening Base${NC}"
    echo -e "    ${MAGENTA}11-18${NC} ${DIM}Securización Proactiva${NC}"
    echo -e "    ${RED}19-30${NC} ${DIM}Mitigaciones MITRE ATT&CK${NC}"
    echo -e "    ${GREEN}31-36${NC} ${DIM}Operaciones de Seguridad${NC}"
    echo -e "    ${CYAN}37-38${NC} ${DIM}Inteligencia${NC}"
    echo -e "    ${YELLOW}39-56${NC} ${DIM}Avanzado${NC}"

    if ! ask "¿Continuar con la aplicación de TODOS los módulos?"; then
        log_info "Operación cancelada por el usuario"
        return 0
    fi

    local failed=0
    local succeeded=0
    local total=56

    for num in $(seq 1 56); do
        echo ""
        echo -e "  ${DIM}─────────────────────────────────────────────────────────────────${NC}"
        _progress_bar "$num" "$total"
        echo -e "  ${CYAN}▶${NC} ${BOLD}Módulo ${num}/${total}:${NC} ${MOD_NAMES[$num]}"
        echo -e "  ${DIM}─────────────────────────────────────────────────────────────────${NC}"
        echo ""

        if ${MOD_FUNCS[$num]}; then
            MOD_RUN[$num]=1
            echo ""
            echo -e "  ${GREEN}✓${NC} ${BOLD}${MOD_NAMES[$num]}${NC} completado"
            ((succeeded++)) || true
        else
            MOD_RUN[$num]=1
            echo ""
            echo -e "  ${RED}✗${NC} ${BOLD}${MOD_NAMES[$num]}${NC} falló"
            ((failed++)) || true
        fi
    done

    echo ""
    echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    _progress_bar "$total" "$total"
    echo ""

    if [[ $failed -eq 0 ]]; then
        echo -e "  ${GREEN}✓${NC} ${BOLD}Todos los módulos completados exitosamente${NC} ($succeeded/$total)"
    else
        echo -e "  ${YELLOW}⚠${NC} ${GREEN}$succeeded OK${NC} · ${RED}$failed fallidos${NC}"
    fi

    echo ""
    echo -e "  ${CYAN}◆${NC} Ejecutando verificación proactiva..."
    echo ""
    verificacion_proactiva
}

# ============================================================
# VERIFICACIÓN PROACTIVA
# ============================================================
verificacion_proactiva() {
    # ── Mapping: check → módulos que lo corrigen ──
    declare -A _CHECK_FIX=(
        [1]="1 3"   [2]="1 3"    [3]="1 5"   [4]="1 3"   [5]="14"
        [6]="2 13"  [7]="6"      [8]="13"    [9]="1"     [10]="13"
        [11]="2"    [12]="5 6"   [13]="2 15" [14]="15 32" [15]="11"
        [16]="12"   [17]="13"    [18]="14"   [19]="15"   [20]="16"
        [21]="4 17" [22]="1 19"  [23]="1"    [24]="15"   [25]="18"
        [26]="19"   [27]="20"    [28]="21"   [29]="22"   [30]="23"
        [31]="24"   [32]="25"    [33]="26"   [34]="27"   [35]="28"
        [36]="29"   [37]="30"    [38]="31"   [39]="32"   [40]="33"
        [41]="34"   [42]="35"    [43]="36"   [44]="37"
        [45]="36"
        [46]="38"
        [47]="39"
        [48]="40"
        [49]="41"
        [50]="42"
        [51]="43"
        [52]="44"
        [53]="45"
        [54]="46"
        [55]="47"
        [56]="48"
        [57]="49"
        [58]="50"
        [59]="51"
        [60]="52"
        [61]="53"
        [62]="54"
        [63]="55"
        [64]="56"
    )
    declare -A _CHECK_TITLE=(
        [1]="Kernel"           [2]="Servicios seguridad"  [3]="Serv. innecesarios"
        [4]="Firewall"         [5]="Puertos/red"          [6]="Permisos archivos"
        [7]="PAM"              [8]="Sesión TMOUT"          [9]="SSH"
        [10]="Sudo"            [11]="Inmutabilidad"       [12]="Módulos kernel"
        [13]="Herramientas"    [14]="Scripts monitoreo"   [15]="Boot/Secure Boot"
        [16]="Sandbox systemd" [17]="Cuentas"             [18]="Red avanzada"
        [19]="Automatización"  [20]="Sandbox apps"        [21]="Exposición externa"
        [22]="MFA SSH"         [23]="ClamAV"              [24]="OpenSCAP"
        [25]="IoC feeds"       [26]="TA0001 Acceso"       [27]="TA0002 Ejecución"
        [28]="TA0003 Persist." [29]="TA0004 Escalada"     [30]="TA0040 Impacto"
        [31]="TA0005 Evasión"  [32]="TA0006 Credenc."     [33]="TA0007 Descubrim."
        [34]="TA0008 Lateral"  [35]="TA0009 Recolecc."    [36]="TA0010 Exfiltr."
        [37]="TA0011 C2"       [38]="Resp. incidentes"    [39]="Monitorización"
        [40]="Reportes"        [41]="Threat hunting"      [42]="SOAR"
        [43]="Purple team"     [44]="Ciberinteligencia"
        [45]="Validación MSF"
        [46]="Protección ISP"
        [47]="Criptografía"
        [48]="Contenedores"
        [49]="Cumplim. CIS"
        [50]="Seguridad email"
        [51]="Logging SIEM"
        [52]="Cadena suminist."
        [53]="Segment. red ZT"
        [54]="Forense avanz."
        [55]="Kernel livepatch"
        [56]="Bases de datos"
        [57]="Backup y DR"
        [58]="Seguridad web"
        [59]="Gestión secretos"
        [60]="Seguridad cloud"
        [61]="LDAP/AD"
        [62]="Cumplim. normativo"
        [63]="Tecnol. engaño"
        [64]="Wireless"
    )
    declare -A FAILED_CHECKS=()
    declare -A _SECTION_FAILS=()

    _mark_section() {
        if [[ ${_CUR_CHECK:-0} -gt 0 ]]; then
            local _sec_fails=$(( ${warnings:-0} - ${_pre_warnings:-0} ))
            if [[ $_sec_fails -gt 0 ]]; then
                FAILED_CHECKS[$_CUR_CHECK]=1
                _SECTION_FAILS[$_CUR_CHECK]=$_sec_fails
            fi
        fi
        _CUR_CHECK=${1:-0}
        _pre_warnings=${warnings:-0}
    }

    # ── Pesos por sección: CRITICAL=3, HIGH=2, MEDIUM=1 ──
    declare -A _SECTION_WEIGHT=(
        [1]=3  [2]=2  [3]=1  [4]=3  [5]=2  [6]=3  [7]=3  [8]=1  [9]=3  [10]=3
        [11]=2 [12]=1 [13]=2 [14]=1 [15]=2 [16]=1 [17]=3 [18]=2 [19]=1 [20]=1
        [21]=2 [22]=2 [23]=2 [24]=1 [25]=2 [26]=3 [27]=2 [28]=2 [29]=3 [30]=2
        [31]=2 [32]=3 [33]=1 [34]=1 [35]=1 [36]=1 [37]=2 [38]=2 [39]=2 [40]=1
        [41]=1 [42]=2 [43]=1 [44]=1 [45]=1
        [46]=2
        [47]=2 [48]=1 [49]=2
        [50]=2 [51]=2 [52]=2
        [53]=2 [54]=2 [55]=2
        [56]=2 [57]=3 [58]=2
        [59]=2 [60]=1 [61]=2
        [62]=2 [63]=1 [64]=1
    )

    _vp_ok() {
        local _w=${_SECTION_WEIGHT[$_CUR_CHECK]:-1}
        _score_earned=$(( _score_earned + _w ))
        _score_max=$(( _score_max + _w ))
        checks_ok=$(( checks_ok + 1 ))
    }

    _vp_fail() {
        local _w=${_SECTION_WEIGHT[$_CUR_CHECK]:-1}
        _score_max=$(( _score_max + _w ))
        warnings=$(( warnings + 1 ))
        case $_w in
            3) _crit_fails=$(( _crit_fails + 1 )) ;;
            2) _high_fails=$(( _high_fails + 1 )) ;;
            *) _med_fails=$(( _med_fails + 1 )) ;;
        esac
    }

    _vp_na() {
        _na_count=$(( _na_count + 1 ))
    }

    # Helper: check executable exists (path, ok_msg, fail_msg)
    _vp_xcheck() {
        if [[ -x "$1" ]]; then
            echo -e "  ${GREEN}OK${NC}  $2"
            _vp_ok
        else
            echo -e "  ${YELLOW}!!${NC}  $3"
            _vp_fail
        fi
    }

    # Helper: check file exists (path, ok_msg, fail_msg)
    _vp_fcheck() {
        if [[ -f "$1" ]]; then
            echo -e "  ${GREEN}OK${NC}  $2"
            _vp_ok
        else
            echo -e "  ${YELLOW}!!${NC}  $3"
            _vp_fail
        fi
    }

    # Helper: check file exists AND contains pattern (path, pattern, ok_msg, fail_msg)
    _vp_fcheck_contains() {
        if [[ -f "$1" ]] && grep -q "$2" "$1" 2>/dev/null; then
            echo -e "  ${GREEN}OK${NC}  $3"
            _vp_ok
        else
            echo -e "  ${YELLOW}!!${NC}  $4"
            _vp_fail
        fi
    }

    # Helper: check systemd service is active (svc_name, ok_msg, fail_msg)
    _vp_svc_check() {
        if systemctl is-active "$1" &>/dev/null; then
            echo -e "  ${GREEN}OK${NC}  $2"
            _vp_ok
        else
            echo -e "  ${YELLOW}!!${NC}  $3"
            _vp_fail
        fi
    }

    # Helper: check sysctl param (param, expected, ok_msg, fail_msg)
    # Passes if actual == expected or actual >= expected (for numeric values)
    _vp_sysctl_check() {
        local _actual
        _actual=$(sysctl -n "$1" 2>/dev/null || echo "N/A")
        if [[ "$_actual" == "$2" ]]; then
            echo -e "  ${GREEN}OK${NC}  $3"
            _vp_ok
        elif [[ "$_actual" =~ ^[0-9]+$ ]] && [[ "$2" =~ ^[0-9]+$ ]] && [[ "$_actual" -ge "$2" ]]; then
            echo -e "  ${GREEN}OK${NC}  $3"
            _vp_ok
        else
            echo -e "  ${YELLOW}!!${NC}  $4 (actual: $_actual)"
            _vp_fail
        fi
    }

    # Helper: check group exists (group, ok_msg, fail_msg)
    _vp_group_check() {
        if getent group "$1" &>/dev/null; then
            echo -e "  ${GREEN}OK${NC}  $2"
            _vp_ok
        else
            echo -e "  ${YELLOW}!!${NC}  $3"
            _vp_fail
        fi
    }

    # Helper: check file permission (path, expected_perm, ok_msg, fail_msg)
    _vp_perm_check() {
        local _actual
        _actual=$(stat -c "%a" "$1" 2>/dev/null || echo "???")
        if [[ "$_actual" == "$2" ]]; then
            echo -e "  ${GREEN}OK${NC}  $3"
            _vp_ok
        else
            echo -e "  ${YELLOW}!!${NC}  $4 (actual: $_actual, esperado: $2)"
            _vp_fail
        fi
    }

    local _score_file="/var/lib/securizar/score-history.dat"
    local _prev_score=-1
    # Cargar último score persistido si existe
    if [[ -f "$_score_file" ]]; then
        _prev_score=$(tail -1 "$_score_file" 2>/dev/null | cut -d: -f2 || echo "-1")
        [[ "$_prev_score" =~ ^[0-9]+$ ]] || _prev_score=-1
    fi

    while true; do

    echo ""
    echo -e "  ${BG_CYAN} VERIFICACIÓN PROACTIVA DE SEGURIDAD ${NC}"
    local _ctx_info="48 categorías"
    [[ $_IS_CONTAINER -eq 1 ]] && _ctx_info+=" · contenedor" \
        || { [[ $_IS_VM -eq 1 ]] && _ctx_info+=" · VM"; }
    [[ $_IS_SERVER -eq 1 ]] && _ctx_info+=" · servidor"
    echo -e "  ${DIM}Auditoría completa del sistema · ${_ctx_info}${NC}"
    echo ""

    local warnings=0
    local checks_ok=0
    local _score_earned=0 _score_max=0
    local _crit_fails=0 _high_fails=0 _med_fails=0 _na_count=0
    local _CUR_CHECK=0 _pre_warnings=0
    for _k in "${!FAILED_CHECKS[@]}"; do unset "FAILED_CHECKS[$_k]"; done
    for _k in "${!_SECTION_FAILS[@]}"; do unset "_SECTION_FAILS[$_k]"; done

    # ── Detección de contexto ──
    local _IS_VM=0 _IS_SERVER=0 _IS_CONTAINER=0 _HAS_PHYSICAL_USB=1
    if command -v systemd-detect-virt &>/dev/null; then
        local _virt_type
        _virt_type=$(systemd-detect-virt 2>/dev/null || echo "none")
        case "$_virt_type" in
            docker|podman|lxc|lxc-libvirt|systemd-nspawn|openvz)
                _IS_CONTAINER=1; _IS_VM=1; _HAS_PHYSICAL_USB=0 ;;
            none) ;;
            *)  _IS_VM=1; _HAS_PHYSICAL_USB=0 ;;
        esac
    fi
    if [[ -z "${DISPLAY:-}" ]] && [[ -z "${WAYLAND_DISPLAY:-}" ]]; then
        _IS_SERVER=1
    fi

    # ── 1. Kernel ──
    _mark_section 1
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[1/64] PARÁMETROS DE KERNEL${NC}"
    local kernel_params=(
        "kernel.randomize_va_space:2:ASLR"
        "kernel.kptr_restrict:2:Ocultar punteros kernel"
        "kernel.dmesg_restrict:1:Restringir dmesg"
        "kernel.yama.ptrace_scope:2:Restringir ptrace"
        "net.ipv4.tcp_syncookies:1:SYN cookies"
        "net.ipv4.conf.all.rp_filter:1:Reverse path filter"
        "net.ipv4.conf.all.accept_redirects:0:Rechazar redirects"
        "net.ipv4.conf.all.send_redirects:0:No enviar redirects"
        "net.ipv4.conf.all.accept_source_route:0:Rechazar source route"
        "net.ipv4.icmp_echo_ignore_broadcasts:1:Ignorar ICMP broadcast"
        "fs.suid_dumpable:0:Sin core dumps SUID"
    )

    for param_entry in "${kernel_params[@]}"; do
        local param="${param_entry%%:*}"
        local rest="${param_entry#*:}"
        local expected="${rest%%:*}" desc="${rest#*:}"
        _vp_sysctl_check "$param" "$expected" \
            "$desc ($param)" "$desc ($param, esperado: $expected)"
    done

    # ── 2. Servicios activos ──
    echo ""
    _mark_section 2
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[2/64] SERVICIOS DE SEGURIDAD${NC}"
    local sec_services=("firewalld" "fail2ban" "auditd")
    for svc in "${sec_services[@]}"; do
        _vp_svc_check "$svc" "$svc activo" "$svc NO activo"
    done

    # USBGuard (opcional, N/A en VMs)
    if [[ $_IS_VM -eq 1 ]]; then
        echo -e "  ${DIM}--${NC}  usbguard N/A (máquina virtual)"
        _vp_na
    elif command -v usbguard &>/dev/null; then
        _vp_svc_check usbguard "usbguard activo" "usbguard instalado pero NO activo"
    fi

    # ── 3. Servicios deshabilitados ──
    echo ""
    _mark_section 3
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[3/64] SERVICIOS INNECESARIOS${NC}"
    local bad_services=("cups" "avahi-daemon" "bluetooth" "ModemManager")
    for svc in "${bad_services[@]}"; do
        # Bluetooth N/A en servidores
        if [[ "$svc" == "bluetooth" ]] && [[ $_IS_SERVER -eq 1 ]]; then
            echo -e "  ${DIM}--${NC}  $svc N/A (servidor sin GUI)"
            _vp_na
            continue
        fi
        # Inverse logic: active = bad, inactive = good
        if systemctl is-active "$svc" &>/dev/null; then
            echo -e "  ${YELLOW}!!${NC}  $svc aún activo"
            _vp_fail
        else
            echo -e "  ${GREEN}OK${NC}  $svc inactivo"
            _vp_ok
        fi
    done

    # ── 4. Firewall ──
    echo ""
    _mark_section 4
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[4/64] FIREWALL${NC}"
    if fw_is_active; then
        local default_zone
        default_zone=$(fw_get_default_zone 2>/dev/null || echo "desconocida")
        echo -e "  ${GREEN}OK${NC}  Firewall activo ($FW_BACKEND, zona: $default_zone)"
        _vp_ok

        local log_denied
        log_denied=$(fw_get_log_denied 2>/dev/null || echo "off")
        if [[ "$log_denied" != "off" ]]; then
            echo -e "  ${GREEN}OK${NC}  Log de paquetes rechazados: $log_denied"
            _vp_ok
        else
            echo -e "  ${YELLOW}!!${NC}  Log de paquetes rechazados: deshabilitado"
            _vp_fail
        fi

        echo "  Reglas activas:"
        fw_list_all 2>/dev/null | head -20 | sed 's/^/    /' || true
    else
        echo -e "  ${RED}XX${NC}  Firewall NO activo"
        _vp_fail
    fi

    # ── 5. Red ──
    echo ""
    _mark_section 5
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[5/64] PUERTOS Y CONEXIONES DE RED${NC}"
    # Evaluar puertos externos contra set esperado
    local _expected_ports=" 22 80 443 9090 "
    local _unexpected=0 _port_list=""
    while IFS= read -r _line; do
        local _port
        _port=$(echo "$_line" | awk '{print $4}' | rev | cut -d: -f1 | rev)
        [[ -z "$_port" ]] && continue
        if [[ "$_expected_ports" != *" $_port "* ]]; then
            _unexpected=$(( _unexpected + 1 ))
            _port_list+=" $_port"
        fi
    done < <(ss -tlnp 2>/dev/null | tail -n +2 | grep -vE "127\.|::1|\*:|\[::\]:")
    if [[ $_unexpected -eq 0 ]]; then
        echo -e "  ${GREEN}OK${NC}  Sin puertos inesperados expuestos externamente"
        _vp_ok
    else
        echo -e "  ${YELLOW}!!${NC}  $_unexpected puerto(s) inesperado(s):${_port_list}"
        _vp_fail
    fi
    echo "  Conexiones activas (no localhost):"
    ss -tnp state established 2>/dev/null | grep -v "127.0.0.1" | head -20 | sed 's/^/    /' || echo "    (ninguna)"

    # ── 6. Permisos de archivos ──
    echo ""
    _mark_section 6
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[6/64] PERMISOS DE ARCHIVOS CRÍTICOS${NC}"
    local file_checks=(
        "/etc/passwd:644"
        "/etc/shadow:600"
        "/etc/sudoers:440"
        "/etc/ssh/sshd_config:600"
    )

    for fc in "${file_checks[@]}"; do
        local fpath="${fc%%:*}" expected_perm="${fc#*:}"
        [[ -f "$fpath" ]] && _vp_perm_check "$fpath" "$expected_perm" \
            "$fpath permisos correctos" "$fpath permisos incorrectos"
    done

    [[ -f "$GRUB_CFG" ]] && _vp_perm_check "$GRUB_CFG" "600" \
        "$GRUB_CFG permisos correctos" "$GRUB_CFG permisos incorrectos"

    # ── 7. PAM intacto ──
    echo ""
    _mark_section 7
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[7/64] PAM INTACTO${NC}"
    if [[ -f /etc/pam.d/su ]]; then
        local current_hash
        current_hash=$(sha256sum /etc/pam.d/su 2>/dev/null | awk '{print $1}')
        if [[ -n "$PAM_SU_HASH" && "$current_hash" == "$PAM_SU_HASH" ]]; then
            echo -e "  ${GREEN}OK${NC}  /etc/pam.d/su NO fue modificado (hash intacto)"
            _vp_ok
        elif [[ -z "$PAM_SU_HASH" ]]; then
            echo -e "  ${GREEN}OK${NC}  /etc/pam.d/su existe (sin hash de referencia previo)"
            _vp_ok
        else
            echo -e "  ${RED}XX${NC}  /etc/pam.d/su FUE MODIFICADO (hash cambió)"
            _vp_fail
        fi
    else
        echo -e "  ${GREEN}OK${NC}  /etc/pam.d/su no existe (no fue creado)"
        _vp_ok
    fi

    # ── 8. Sesión TMOUT (usabilidad) ──
    echo ""
    _mark_section 8
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[8/64] SESIÓN TMOUT (USABILIDAD)${NC}"
    echo -e "  ${DIM}Verifica que TMOUT no esté forzado como readonly (bloquea sesiones)${NC}"
    if [[ -f /etc/profile.d/timeout.sh ]]; then
        if grep -q "readonly TMOUT" /etc/profile.d/timeout.sh 2>/dev/null; then
            echo -e "  ${RED}XX${NC}  TMOUT readonly detectado en /etc/profile.d/timeout.sh"
            _vp_fail
        else
            echo -e "  ${GREEN}OK${NC}  /etc/profile.d/timeout.sh existe sin readonly (flexible)"
            _vp_ok
        fi
    else
        echo -e "  ${GREEN}OK${NC}  No hay TMOUT forzado en /etc/profile.d/"
        _vp_ok
    fi

    # ── 9. Acceso SSH ──
    echo ""
    _mark_section 9
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[9/64] ACCESO SSH${NC}"
    if systemctl is-masked "$SSH_SERVICE_NAME" &>/dev/null; then
        echo -e "  ${RED}XX${NC}  $SSH_SERVICE_NAME está ENMASCARADO (no se puede iniciar)"
        _vp_fail
    elif systemctl is-active "$SSH_SERVICE_NAME" &>/dev/null; then
        echo -e "  ${GREEN}OK${NC}  $SSH_SERVICE_NAME activo y accesible"
        _vp_ok
    elif systemctl is-enabled "$SSH_SERVICE_NAME" &>/dev/null; then
        echo -e "  ${YELLOW}!!${NC}  $SSH_SERVICE_NAME habilitado pero no activo"
        _vp_fail
    else
        echo -e "  ${YELLOW}!!${NC}  $SSH_SERVICE_NAME no activo ni habilitado"
        _vp_fail
    fi

    # ── 10. Acceso sudo ──
    echo ""
    _mark_section 10
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[10/64] ACCESO SUDO${NC}"
    local current_user="${SUDO_USER:-$USER}"
    if id -nG "$current_user" 2>/dev/null | grep -qw "wheel"; then
        echo -e "  ${GREEN}OK${NC}  $current_user pertenece al grupo wheel"
        _vp_ok
    else
        echo -e "  ${YELLOW}!!${NC}  $current_user NO pertenece al grupo wheel"
        _vp_fail
    fi

    if [[ -f /etc/sudoers ]]; then
        if visudo -c &>/dev/null; then
            echo -e "  ${GREEN}OK${NC}  /etc/sudoers sintácticamente correcto"
            _vp_ok
        else
            echo -e "  ${RED}XX${NC}  /etc/sudoers tiene errores de sintaxis"
            _vp_fail
        fi
    fi

    # ── 11. Sin inmutabilidad ──
    echo ""
    _mark_section 11
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[11/64] SIN INMUTABILIDAD EN ARCHIVOS CRÍTICOS${NC}"
    local immutable_files=("/etc/passwd" "/etc/shadow" "/etc/sudoers")
    for f in "${immutable_files[@]}"; do
        if [[ -f "$f" ]]; then
            local attrs
            attrs=$(lsattr "$f" 2>/dev/null | awk '{print $1}')
            if [[ "$attrs" == *"i"* ]]; then
                echo -e "  ${RED}XX${NC}  $f tiene flag INMUTABLE (chattr +i)"
                _vp_fail
            else
                echo -e "  ${GREEN}OK${NC}  $f modificable (sin chattr +i)"
                _vp_ok
            fi
        fi
    done

    # ── 12. Módulos bloqueados ──
    echo ""
    _mark_section 12
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[12/64] MÓDULOS BLOQUEADOS${NC}"
    if [[ $_IS_CONTAINER -eq 1 ]]; then
        echo -e "  ${DIM}--${NC}  Módulos kernel N/A (contenedor, kernel del host)"
        _vp_na
    else
        local _mod_blocked=0
        if ls /etc/modprobe.d/*.conf &>/dev/null; then
            for conf in /etc/modprobe.d/*.conf; do
                local mods
                mods=$(grep -c "install .* /bin/false" "$conf" 2>/dev/null || echo 0)
                [[ "$mods" -gt 0 ]] && _mod_blocked=$((_mod_blocked + mods))
            done
        fi
        if [[ $_mod_blocked -gt 0 ]]; then
            echo -e "  ${GREEN}OK${NC}  $_mod_blocked módulos bloqueados en modprobe.d"
            _vp_ok
        else
            echo -e "  ${YELLOW}!!${NC}  No hay módulos bloqueados en modprobe.d"
            _vp_fail
        fi
    fi

    # ── 13. Herramientas instaladas ──
    echo ""
    _mark_section 13
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[13/64] HERRAMIENTAS DE SEGURIDAD${NC}"
    local _sec_tools=("aide:AIDE" "rkhunter:rkhunter" "lynis:lynis" "fail2ban-client:fail2ban")
    for _st in "${_sec_tools[@]}"; do
        local _cmd="${_st%%:*}" _name="${_st#*:}"
        if command -v "$_cmd" &>/dev/null; then
            echo -e "  ${GREEN}OK${NC}  $_name instalado"
            _vp_ok
        else
            echo -e "  ${YELLOW}!!${NC}  $_name NO instalado"
            _vp_fail
        fi
    done

    # ── 14. Scripts de monitoreo ──
    echo ""
    _mark_section 14
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[14/64] SCRIPTS DE MONITOREO${NC}"
    local _mon_count
    _mon_count=$(ls /usr/local/bin/*.sh 2>/dev/null | wc -l || echo 0)
    if [[ "$_mon_count" -gt 0 ]]; then
        echo -e "  ${GREEN}OK${NC}  $_mon_count scripts de seguridad encontrados en /usr/local/bin/"
        _vp_ok
    else
        echo -e "  ${YELLOW}!!${NC}  No hay scripts en /usr/local/bin/"
        _vp_fail
    fi

    # ── 15. Parámetros de arranque ──
    echo ""
    _mark_section 15
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[15/64] PARÁMETROS DE ARRANQUE${NC}"
    if [[ -f /proc/cmdline ]]; then
        local cmdline
        cmdline=$(cat /proc/cmdline 2>/dev/null)
        local boot_params=("init_on_alloc" "lockdown")
        for param in "${boot_params[@]}"; do
            if echo "$cmdline" | grep -qE "(^| )${param}(=| |$)"; then
                echo -e "  ${GREEN}OK${NC}  $param presente en cmdline"
                _vp_ok
            else
                echo -e "  ${YELLOW}!!${NC}  $param NO presente en cmdline"
                _vp_fail
            fi
        done
    fi

    # Secure Boot (N/A en VMs)
    if [[ $_IS_VM -eq 1 ]]; then
        echo -e "  ${DIM}--${NC}  Secure Boot N/A (máquina virtual)"
        _vp_na
    elif command -v mokutil &>/dev/null; then
        if mokutil --sb-state 2>&1 | grep -qi "enabled"; then
            echo -e "  ${GREEN}OK${NC}  Secure Boot habilitado"
            _vp_ok
        else
            echo -e "  ${YELLOW}!!${NC}  Secure Boot NO habilitado"
            _vp_fail
        fi
    else
        echo -e "  ${YELLOW}!!${NC}  mokutil no disponible (no se puede verificar Secure Boot)"
        _vp_fail
    fi

    # ── 16. Sandboxing systemd ──
    echo ""
    _mark_section 16
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[16/64] SANDBOXING SYSTEMD${NC}"
    local dropin_services=("$SSH_SERVICE_NAME" "fail2ban" "firewalld")
    for svc in "${dropin_services[@]}"; do
        _vp_fcheck "/etc/systemd/system/${svc}.service.d/hardening.conf" \
            "Drop-in de $svc presente" "Drop-in de $svc NO encontrado"
    done

    # ── 17. Cuentas ──
    echo ""
    _mark_section 17
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[17/64] SEGURIDAD DE CUENTAS${NC}"
    # PASS_MAX_DAYS
    if [[ -f /etc/login.defs ]]; then
        local max_days
        max_days=$(grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
        if [[ -n "$max_days" ]] && [[ "$max_days" -le 90 ]]; then
            echo -e "  ${GREEN}OK${NC}  PASS_MAX_DAYS = $max_days"
            _vp_ok
        else
            echo -e "  ${YELLOW}!!${NC}  PASS_MAX_DAYS = ${max_days:-no configurado} (recomendado: <= 90)"
            _vp_fail
        fi
    fi

    # Cuentas sin contraseña
    local empty_pass=0
    while IFS=: read -r username pass _; do
        [[ -z "$pass" ]] && empty_pass=$(( empty_pass + 1 ))
    done < <(cat /etc/shadow 2>/dev/null)
    if [[ $empty_pass -eq 0 ]]; then
        echo -e "  ${GREEN}OK${NC}  Sin cuentas sin contraseña"
        _vp_ok
    else
        echo -e "  ${YELLOW}!!${NC}  $empty_pass cuenta(s) sin contraseña"
        _vp_fail
    fi

    # UID=0 extra
    local uid0_count=0
    while IFS=: read -r username _ uid _ _ _ _; do
        [[ "$uid" -eq 0 ]] && [[ "$username" != "root" ]] && uid0_count=$(( uid0_count + 1 ))
    done < <(cat /etc/passwd 2>/dev/null)
    if [[ $uid0_count -eq 0 ]]; then
        echo -e "  ${GREEN}OK${NC}  Solo root tiene UID=0"
        _vp_ok
    else
        echo -e "  ${RED}XX${NC}  $uid0_count cuenta(s) extra con UID=0"
        _vp_fail
    fi

    # ── 18. Red avanzada ──
    echo ""
    _mark_section 18
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[18/64] RED AVANZADA${NC}"
    # Suricata
    _vp_svc_check suricata "Suricata IDS activo" "Suricata IDS NO activo"

    # DNS over TLS
    _vp_fcheck /etc/systemd/resolved.conf.d/dns-over-tls.conf \
        "DNS over TLS configurado" "DNS over TLS NO configurado"

    # WireGuard (N/A si no existe /etc/wireguard)
    if [[ ! -d /etc/wireguard ]]; then
        echo -e "  ${DIM}--${NC}  WireGuard N/A (sin /etc/wireguard)"
        _vp_na
    elif [[ -f /etc/wireguard/wg0.conf ]]; then
        echo -e "  ${GREEN}OK${NC}  WireGuard configurado (plantilla)"
        _vp_ok
    else
        echo -e "  ${YELLOW}!!${NC}  WireGuard NO configurado"
        _vp_fail
    fi

    # arpwatch
    _vp_svc_check arpwatch "arpwatch activo" "arpwatch NO activo"

    # ── 19. Automatización ──
    echo ""
    _mark_section 19
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[19/64] AUTOMATIZACIÓN DE SEGURIDAD${NC}"
    local cron_jobs=(
        "/etc/cron.daily/aide-check:AIDE diario"
        "/etc/cron.daily/zypper-security-update:Parches automáticos"
        "/etc/cron.daily/rkhunter-check:rkhunter diario"
        "/etc/cron.weekly/lynis-audit:lynis semanal"
        "/etc/cron.daily/seguridad-resumen:Digest diario"
    )
    for cj in "${cron_jobs[@]}"; do
        local cpath="${cj%%:*}" cdesc="${cj#*:}"
        _vp_fcheck "$cpath" "$cdesc ($cpath)" "$cdesc NO configurado"
    done

    # ── 20. Sandboxing de apps ──
    echo ""
    _mark_section 20
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[20/64] SANDBOXING DE APLICACIONES${NC}"
    # Firejail
    if command -v firejail &>/dev/null; then
        echo -e "  ${GREEN}OK${NC}  Firejail instalado"
        _vp_ok

        # Verificar si firecfg fue aplicado
        local fj_symlinks
        fj_symlinks=$(ls -la /usr/local/bin/ 2>/dev/null | grep -c "firejail" || echo 0)
        if [[ "$fj_symlinks" -gt 0 ]]; then
            echo -e "  ${GREEN}OK${NC}  firecfg activo ($fj_symlinks symlinks)"
            _vp_ok
        else
            echo -e "  ${YELLOW}!!${NC}  firecfg no aplicado"
            _vp_fail
        fi
    else
        echo -e "  ${YELLOW}!!${NC}  Firejail NO instalado ${DIM}(1 sub-check omitido)${NC}"
        _vp_fail
    fi

    # bubblewrap
    if command -v bwrap &>/dev/null; then
        echo -e "  ${GREEN}OK${NC}  bubblewrap instalado"
        _vp_ok
    else
        echo -e "  ${YELLOW}!!${NC}  bubblewrap NO instalado"
        _vp_fail
    fi

    # ── 21. Auditoría de reconocimiento ──
    echo ""
    _mark_section 21
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[21/64] EXPOSICIÓN EXTERNA (RECONOCIMIENTO TA0043)${NC}"

    # Puertos expuestos externamente
    local ext_ports
    ext_ports=$(ss -tlnp 2>/dev/null | tail -n +2 | grep -vE "127\.|::1" | wc -l || echo 0)
    if [[ "$ext_ports" -eq 0 ]]; then
        echo -e "  ${GREEN}OK${NC}  Sin puertos TCP expuestos externamente"
        _vp_ok
    else
        echo -e "  ${YELLOW}!!${NC}  $ext_ports puerto(s) TCP expuestos externamente"
        _vp_fail
    fi

    # TCP timestamps (0 = deshabilitado = deseado)
    _vp_sysctl_check net.ipv4.tcp_timestamps "0" \
        "TCP timestamps deshabilitados (anti-fingerprinting)" \
        "TCP timestamps habilitados (fingerprinting posible)"

    # Banners no filtran info
    local banner_leak=0
    for bf in /etc/issue /etc/issue.net; do
        if [[ -f "$bf" ]] && grep -qiE "suse|leap|linux.*[0-9]" "$bf" 2>/dev/null; then
            banner_leak=1
        fi
    done
    if [[ $banner_leak -eq 0 ]]; then
        echo -e "  ${GREEN}OK${NC}  Banners no filtran información del OS"
        _vp_ok
    else
        echo -e "  ${YELLOW}!!${NC}  Banners filtran información del sistema operativo"
        _vp_fail
    fi

    # Script de auditoría periódica
    _vp_xcheck /usr/local/bin/auditoria-reconocimiento.sh \
        "Script de auditoría de reconocimiento instalado" "Script de auditoría de reconocimiento NO instalado"
    _vp_xcheck /etc/cron.weekly/auditoria-reconocimiento \
        "Auditoría semanal de reconocimiento programada" "Auditoría semanal de reconocimiento NO programada"

    # ── 22. MFA SSH (MITRE T1133 - M1032) ──
    echo ""
    _mark_section 22
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[22/64] MFA PARA SSH (T1133)${NC}"
    _vp_fcheck_contains /etc/ssh/sshd_config.d/91-mfa.conf \
        "AuthenticationMethods publickey,password" \
        "MFA SSH activo (publickey + password)" \
        "MFA SSH NO configurado"
    _vp_xcheck /usr/local/bin/generar-llave-fido2.sh \
        "Script generador de llaves FIDO2 disponible" "Script generador de llaves FIDO2 NO instalado"

    # ── 23. ClamAV (MITRE T1566 - M1049) ──
    echo ""
    _mark_section 23
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[23/64] CLAMAV ANTIMALWARE (T1566)${NC}"
    if command -v clamscan &>/dev/null; then
        echo -e "  ${GREEN}OK${NC}  ClamAV instalado"
        _vp_ok

        # Verificar firmas actualizadas
        if [[ -f /var/lib/clamav/main.cvd ]] || [[ -f /var/lib/clamav/main.cld ]]; then
            echo -e "  ${GREEN}OK${NC}  Base de datos de firmas presente"
            _vp_ok
        else
            echo -e "  ${YELLOW}!!${NC}  Base de datos de firmas NO encontrada"
            _vp_fail
        fi

        # freshclam automático
        _vp_svc_check clamav-freshclam \
            "Actualización automática de firmas activa" \
            "Actualización automática de firmas NO activa"

        # Cron de escaneo
        _vp_xcheck /etc/cron.daily/clamav-scan \
            "Escaneo diario programado" "Escaneo diario NO programado"
    else
        echo -e "  ${YELLOW}!!${NC}  ClamAV NO instalado ${DIM}(3 sub-checks omitidos)${NC}"
        _vp_fail
    fi

    # ── 24. OpenSCAP (MITRE T1195 - M1016) ──
    echo ""
    _mark_section 24
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[24/64] OPENSCAP AUDITORÍA (T1195)${NC}"
    if command -v oscap &>/dev/null; then
        echo -e "  ${GREEN}OK${NC}  OpenSCAP instalado"
        _vp_ok

        # Verificar SCAP Security Guide
        if pkg_is_installed scap-security-guide 2>&1; then
            echo -e "  ${GREEN}OK${NC}  SCAP Security Guide instalado"
            _vp_ok
        else
            echo -e "  ${YELLOW}!!${NC}  SCAP Security Guide NO instalado"
            _vp_fail
        fi

        # Script de auditoría
        _vp_xcheck /usr/local/bin/openscap-auditar.sh \
            "Script de auditoría OpenSCAP disponible" "Script de auditoría OpenSCAP NO instalado"
        # Cron semanal
        _vp_xcheck /etc/cron.weekly/openscap-audit \
            "Auditoría semanal programada" "Auditoría semanal NO programada"

        # Reportes existentes
        local scap_reports
        scap_reports=$(ls /var/log/openscap/reports/*.html 2>/dev/null | wc -l || echo 0)
        if [[ "$scap_reports" -gt 0 ]]; then
            echo -e "  ${GREEN}OK${NC}  $scap_reports reporte(s) HTML disponible(s)"
            _vp_ok
        else
            echo -e "  ${YELLOW}!!${NC}  Sin reportes de auditoría generados aún"
            _vp_fail
        fi
    else
        echo -e "  ${YELLOW}!!${NC}  OpenSCAP NO instalado ${DIM}(4 sub-checks omitidos)${NC}"
        _vp_fail
    fi

    # ── 25. Inteligencia de amenazas (MITRE TA0042 - M1019) ──
    echo ""
    _mark_section 25
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[25/64] INTELIGENCIA DE AMENAZAS (M1019 IoC Feeds)${NC}"

    # Directorio de IoC
    if [[ -d /etc/threat-intelligence ]]; then
        echo -e "  ${GREEN}OK${NC}  Directorio de IoC configurado"
        _vp_ok

        # Feeds de IPs descargados
        if [[ -f /etc/threat-intelligence/lists/malicious-ips.txt ]]; then
            local ioc_ips
            ioc_ips=$(wc -l < /etc/threat-intelligence/lists/malicious-ips.txt 2>/dev/null || echo 0)
            echo -e "  ${GREEN}OK${NC}  Feeds de IPs maliciosas: $ioc_ips IPs"
            _vp_ok
        else
            echo -e "  ${YELLOW}!!${NC}  Feeds de IPs maliciosas NO descargados"
            _vp_fail
        fi

        # ipset activo
        if command -v ipset &>/dev/null && ipset list threat-intel-ips &>/dev/null 2>&1; then
            local ipset_count
            ipset_count=$(ipset list threat-intel-ips 2>/dev/null | grep -cE "^[0-9]{1,3}\." || echo 0)
            echo -e "  ${GREEN}OK${NC}  Bloqueo ipset activo: $ipset_count IPs bloqueadas"
            _vp_ok
        else
            echo -e "  ${YELLOW}!!${NC}  Bloqueo ipset NO activo"
            _vp_fail
        fi

        # Herramienta de consulta
        _vp_xcheck /usr/local/bin/ioc-lookup.sh \
            "Herramienta ioc-lookup.sh disponible" "Herramienta ioc-lookup.sh NO instalada"
        # Cron de actualización
        _vp_xcheck /etc/cron.daily/threat-intel-update \
            "Actualización diaria de IoC programada" "Actualización diaria de IoC NO programada"
    else
        echo -e "  ${YELLOW}!!${NC}  Directorio de IoC NO configurado ${DIM}(4 sub-checks omitidos)${NC}"
        _vp_fail
    fi

    # ── 26. Acceso Inicial (TA0001) ──
    echo ""
    _mark_section 26
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[26/64] ACCESO INICIAL (TA0001)${NC}"

    # SSH hardening modular
    _vp_fcheck /etc/ssh/sshd_config.d/01-acceso-inicial.conf \
        "Hardening SSH avanzado aplicado (sshd_config.d/)" "Hardening SSH avanzado NO aplicado"

    # USBGuard (N/A en VMs)
    if [[ $_IS_VM -eq 1 ]]; then
        echo -e "  ${DIM}--${NC}  USBGuard N/A (máquina virtual)"
        _vp_na
    elif systemctl is-active usbguard &>/dev/null; then
        echo -e "  ${GREEN}OK${NC}  USBGuard activo (control de hardware)"
        _vp_ok
    elif command -v usbguard &>/dev/null; then
        echo -e "  ${YELLOW}!!${NC}  USBGuard instalado pero NO activo"
        _vp_fail
    else
        echo -e "  ${YELLOW}!!${NC}  USBGuard NO instalado"
        _vp_fail
    fi

    # Core dumps deshabilitados
    _vp_fcheck /etc/systemd/coredump.conf.d/disable.conf \
        "Core dumps deshabilitados (anti-exploit)" "Core dumps NO deshabilitados"

    # ── 27. Ejecución (TA0002) ──
    echo ""
    _mark_section 27
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[27/64] EJECUCIÓN (TA0002)${NC}"

    # AppArmor activo (T1059 - M1038)
    if command -v aa-status &>/dev/null && aa-status --enabled 2>/dev/null; then
        local aa_enforced
        aa_enforced=$(aa-status 2>/dev/null | grep "profiles are in enforce mode" | awk '{print $1}' || echo "0")
        echo -e "  ${GREEN}OK${NC}  AppArmor activo ($aa_enforced perfiles enforce)"
        _vp_ok
    else
        echo -e "  ${YELLOW}!!${NC}  AppArmor NO activo"
        _vp_fail
    fi

    # noexec en montajes temporales (T1204 - M1038)
    if [[ $_IS_CONTAINER -eq 1 ]]; then
        echo -e "  ${DIM}--${NC}  noexec montajes N/A (contenedor, el host controla montajes)"
        _vp_na
    else
        local noexec_ok=0
        for nmp in /tmp /var/tmp /dev/shm; do
            if mountpoint -q "$nmp" 2>/dev/null && mount | grep " on $nmp " | grep -q "noexec" 2>/dev/null; then
                noexec_ok=$((noexec_ok + 1))
            fi
        done
        if [[ $noexec_ok -ge 2 ]]; then
            echo -e "  ${GREEN}OK${NC}  noexec en montajes temporales ($noexec_ok/3)"
            _vp_ok
        else
            echo -e "  ${YELLOW}!!${NC}  noexec incompleto en montajes temporales ($noexec_ok/3)"
            _vp_fail
        fi
    fi

    # LD_PRELOAD restringido (T1129 - M1044)
    _vp_fcheck /etc/profile.d/restrict-ld-env.sh \
        "LD_PRELOAD/LD_LIBRARY_PATH restringido" "LD_PRELOAD NO restringido"

    # Bash restringido por grupo (T1059.004 - M1038)
    if getent group shell-users &>/dev/null; then
        _vp_perm_check /bin/bash "750" \
            "/bin/bash restringido a grupo shell-users" \
            "Grupo shell-users existe pero bash no restringido"
    else
        echo -e "  ${YELLOW}!!${NC}  Bash no restringido (grupo shell-users no existe)"
        _vp_fail
    fi

    # Intérpretes restringidos (T1059 - M1038)
    _vp_group_check interp-users \
        "Intérpretes restringidos a grupo interp-users" \
        "Intérpretes NO restringidos (grupo interp-users no existe)"

    # cron.allow
    _vp_fcheck /etc/cron.allow \
        "/etc/cron.allow presente (acceso restringido)" "/etc/cron.allow NO presente"

    # Reglas de auditoría de ejecución
    _vp_fcheck /etc/audit/rules.d/98-ld-preload.rules \
        "Auditoría de LD_PRELOAD configurada" "Auditoría de LD_PRELOAD NO configurada"

    # Monitor de ejecución
    _vp_xcheck /usr/local/bin/monitor-ejecucion.sh \
        "Script monitor-ejecucion.sh instalado" "Script monitor-ejecucion.sh NO instalado"

    # ── 28. Persistencia (TA0003) ──
    echo ""
    _mark_section 28
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[28/64] PERSISTENCIA (TA0003)${NC}"

    # Reglas auditd de persistencia
    local persist_rules=0
    for rfile in /etc/audit/rules.d/persistence-*.rules; do
        [[ -f "$rfile" ]] && persist_rules=$((persist_rules + 1))
    done
    if [[ $persist_rules -ge 3 ]]; then
        echo -e "  ${GREEN}OK${NC}  Monitoreo de persistencia configurado ($persist_rules conjuntos de reglas)"
        _vp_ok
    else
        echo -e "  ${YELLOW}!!${NC}  Monitoreo de persistencia incompleto ($persist_rules/4 reglas)"
        _vp_fail
    fi

    # Script de detección
    _vp_xcheck /usr/local/bin/detectar-persistencia.sh \
        "Script de detección de persistencia instalado" "Script de detección de persistencia NO instalado"
    _vp_xcheck /etc/cron.daily/detectar-persistencia \
        "Detección diaria de persistencia programada" "Detección diaria de persistencia NO programada"

    # ── 29. Escalada de Privilegios (TA0004) ──
    echo ""
    _mark_section 29
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[29/64] ESCALADA DE PRIVILEGIOS (TA0004)${NC}"

    _vp_fcheck /etc/sysctl.d/99-anti-privesc.conf \
        "Protecciones kernel anti-escalada aplicadas" "Protecciones kernel anti-escalada NO aplicadas"
    _vp_fcheck /etc/sudoers.d/99-hardening \
        "Hardening de sudo aplicado" "Hardening de sudo NO aplicado"
    _vp_xcheck /usr/local/bin/detectar-escalada.sh \
        "Script de detección de escalada instalado" "Script de detección de escalada NO instalado"
    _vp_fcheck /etc/audit/rules.d/privesc-injection.rules \
        "Monitoreo de inyección de procesos configurado" "Monitoreo de inyección de procesos NO configurado"

    # ── 30. Impacto (TA0040) ──
    echo ""
    _mark_section 30
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[30/64] IMPACTO (TA0040)${NC}"

    # Backups offsite (T1486/T1561 - M1053)
    if [[ -f /etc/backup-offsite/config ]] && [[ -x /usr/local/bin/backup-offsite.sh ]]; then
        echo -e "  ${GREEN}OK${NC}  Backups offsite automáticos configurados"
        _vp_ok
    else
        echo -e "  ${YELLOW}!!${NC}  Backups offsite NO configurados"
        _vp_fail
    fi

    # ClamAV anti-ransomware (T1486 - M1049)
    _vp_xcheck /usr/local/bin/clamav-antiransomware.sh \
        "ClamAV anti-ransomware configurado" "ClamAV anti-ransomware NO configurado"

    # Protección snapshots/backups (T1490 - M1053)
    _vp_xcheck /usr/local/bin/verificar-backups.sh \
        "Protección de snapshots/backups configurada" "Protección de snapshots/backups NO configurada"

    # Monitoreo de impacto (T1485/T1486/T1489)
    if [[ -x /usr/local/bin/detectar-impacto.sh ]] && [[ -f /etc/audit/rules.d/impact-detection.rules ]]; then
        echo -e "  ${GREEN}OK${NC}  Monitoreo de actividad de impacto configurado"
        _vp_ok
    else
        echo -e "  ${YELLOW}!!${NC}  Monitoreo de actividad de impacto NO configurado"
        _vp_fail
    fi

    # ── 31. Evasión de Defensas (TA0005) ──
    echo ""
    _mark_section 31
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[31/64] EVASIÓN DE DEFENSAS (TA0005)${NC}"

    _vp_fcheck /etc/audit/rules.d/60-log-protection.rules \
        "Protección de logs contra manipulación" "Protección de logs NO configurada"
    _vp_xcheck /usr/local/bin/detectar-masquerading.sh \
        "Detección de masquerading configurada" "Detección de masquerading NO configurada"
    _vp_fcheck /etc/systemd/system/watchdog-seguridad.timer \
        "Watchdog de herramientas de seguridad activo" "Watchdog de herramientas NO configurado"

    # ── 32. Acceso a Credenciales (TA0006) ──
    echo ""
    _mark_section 32
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[32/64] ACCESO A CREDENCIALES (TA0006)${NC}"

    _vp_fcheck /etc/sysctl.d/91-credential-protection.conf \
        "Protección contra credential dumping" "Protección contra credential dumping NO configurada"
    _vp_fcheck /etc/security/faillock.conf \
        "Protección contra fuerza bruta (faillock)" "Protección contra fuerza bruta NO configurada"
    _vp_xcheck /usr/local/bin/buscar-credenciales.sh \
        "Escaneo de credenciales expuestas configurado" "Escaneo de credenciales expuestas NO configurado"

    # ── 33. Descubrimiento (TA0007) ──
    echo ""
    _mark_section 33
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[33/64] DESCUBRIMIENTO (TA0007)${NC}"
    _vp_xcheck /usr/local/bin/detectar-portscan.sh \
        "Detección de port scanning configurada" "Detección de port scanning NO configurada"
    _vp_fcheck /etc/audit/rules.d/63-discovery.rules \
        "Auditoría de reconocimiento interno configurada" "Auditoría de reconocimiento interno NO configurada"

    # ── 34. Movimiento Lateral (TA0008) ──
    echo ""
    _mark_section 34
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[34/64] MOVIMIENTO LATERAL (TA0008)${NC}"
    _vp_fcheck /etc/ssh/sshd_config.d/06-lateral-movement.conf \
        "Hardening SSH anti movimiento lateral" "Hardening SSH anti lateral NO configurado"
    _vp_xcheck /usr/local/bin/detectar-lateral.sh \
        "Detección de movimiento lateral configurada" "Detección de movimiento lateral NO configurada"

    # ── 35. Recolección (TA0009) ──
    echo ""
    _mark_section 35
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[35/64] RECOLECCIÓN (TA0009)${NC}"
    _vp_fcheck /etc/audit/rules.d/65-collection.rules \
        "Auditoría de recolección de datos configurada" "Auditoría de recolección NO configurada"
    _vp_xcheck /usr/local/bin/detectar-staging.sh \
        "Detección de data staging configurada" "Detección de data staging NO configurada"

    # ── 36. Exfiltración (TA0010) ──
    echo ""
    _mark_section 36
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[36/64] EXFILTRACIÓN (TA0010)${NC}"
    _vp_xcheck /usr/local/bin/detectar-exfiltracion.sh \
        "Detección de exfiltración configurada" "Detección de exfiltración NO configurada"
    _vp_xcheck /usr/local/bin/detectar-dns-tunnel.sh \
        "Detección de DNS tunneling configurada" "Detección de DNS tunneling NO configurada"

    # ── 37. Comando y Control (TA0011) ──
    echo ""
    _mark_section 37
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[37/64] COMANDO Y CONTROL (TA0011)${NC}"
    _vp_xcheck /usr/local/bin/detectar-beaconing.sh \
        "Detección de C2 beaconing configurada" \
        "Detección de C2 beaconing NO configurada"
    _vp_xcheck /usr/local/bin/detectar-tunneling.sh \
        "Detección de proxy/tunneling configurada" \
        "Detección de proxy/tunneling NO configurada"
    _vp_fcheck /etc/audit/rules.d/67-command-control.rules \
        "Auditoría de herramientas C2 configurada" \
        "Auditoría de herramientas C2 NO configurada"

    # ── 38. Respuesta a Incidentes ──
    echo ""
    _mark_section 38
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[38/64] RESPUESTA A INCIDENTES${NC}"
    _vp_xcheck /usr/local/bin/ir-recolectar-forense.sh \
        "Toolkit forense instalado" "Toolkit forense NO instalado"
    _vp_xcheck /usr/local/bin/ir-responder.sh \
        "Playbooks de contención instalados" "Playbooks de contención NO instalados"
    _vp_xcheck /usr/local/bin/ir-timeline.sh \
        "Generador de timeline instalado" "Generador de timeline NO instalado"

    # ── 39. Monitorización Continua ──
    echo ""
    _mark_section 39
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[39/64] MONITORIZACIÓN CONTINUA${NC}"
    _vp_xcheck /usr/local/bin/security-dashboard.sh \
        "Dashboard de seguridad instalado" "Dashboard de seguridad NO instalado"
    _vp_xcheck /usr/local/bin/correlacionar-alertas.sh \
        "Correlación de alertas instalada" "Correlación de alertas NO instalada"
    _vp_xcheck /usr/local/bin/security-healthcheck.sh \
        "Health check de controles instalado" "Health check de controles NO instalado"

    # ── 40. Reportes de Seguridad ──
    echo ""
    _mark_section 40
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[40/64] REPORTES DE SEGURIDAD${NC}"
    _vp_xcheck /usr/local/bin/reporte-mitre.sh \
        "Reporte MITRE ATT&CK instalado" "Reporte MITRE ATT&CK NO instalado"
    _vp_xcheck /usr/local/bin/exportar-navigator.sh \
        "Exportador ATT&CK Navigator instalado" "Exportador ATT&CK Navigator NO instalado"
    _vp_xcheck /usr/local/bin/reporte-cumplimiento.sh \
        "Reporte de cumplimiento instalado" "Reporte de cumplimiento NO instalado"

    # ── 41. Caza de amenazas ──
    echo ""
    _mark_section 41
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[41/64] CAZA DE AMENAZAS (UEBA / THREAT HUNTING)${NC}"
    _vp_xcheck /usr/local/bin/ueba-crear-baseline.sh \
        "Sistema UEBA de baseline instalado" "Sistema UEBA NO instalado"
    _vp_xcheck /usr/local/bin/cazar-amenazas.sh \
        "Playbooks de caza de amenazas instalados" "Playbooks de caza NO instalados"
    _vp_xcheck /usr/local/bin/detectar-persistencia-avanzada.sh \
        "Detección T1098 persistencia avanzada instalada" "Detección T1098 NO instalada"

    # ── 42. Automatización de respuesta ──
    echo ""
    _mark_section 42
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[42/64] AUTOMATIZACIÓN DE RESPUESTA (SOAR)${NC}"
    _vp_xcheck /usr/local/bin/soar-responder.sh \
        "Motor SOAR de respuesta automática instalado" "Motor SOAR NO instalado"
    _vp_xcheck /usr/local/bin/soar-gestionar-bloqueos.sh \
        "Gestión de bloqueos SOAR instalada" "Gestión de bloqueos SOAR NO instalada"
    _vp_xcheck /usr/local/bin/soar-notificar.sh \
        "Notificaciones SOAR instaladas" "Notificaciones SOAR NO instaladas"

    # ── 43. Validación de controles ──
    echo ""
    _mark_section 43
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[43/64] VALIDACIÓN DE CONTROLES (PURPLE TEAM)${NC}"
    _vp_xcheck /usr/local/bin/simular-ataques.sh \
        "Simulador ATT&CK seguro instalado" "Simulador ATT&CK NO instalado"
    _vp_xcheck /usr/local/bin/reporte-validacion.sh \
        "Reporte de validación Purple Team instalado" "Reporte de validación NO instalado"
    _vp_xcheck /usr/local/bin/validar-endpoint.sh \
        "Validador de endpoint instalado" "Validador de endpoint NO instalado"

    # ── 44. Ciberinteligencia proactiva ──
    echo ""
    _mark_section 44
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[44/64] CIBERINTELIGENCIA PROACTIVA${NC}"
    _vp_xcheck /usr/local/bin/ciberint-enriquecer-ioc.sh \
        "Motor de enriquecimiento IoC instalado" "Motor de enriquecimiento IoC NO instalado"
    _vp_xcheck /usr/local/bin/ciberint-red-inteligente.sh \
        "Inteligencia de red proactiva instalada" "Inteligencia de red NO instalada"
    _vp_xcheck /usr/local/bin/ciberint-dns-inteligencia.sh \
        "Inteligencia DNS instalada" "Inteligencia DNS NO instalada"
    _vp_xcheck /usr/local/bin/ciberint-superficie-ataque.sh \
        "Monitorización de superficie instalada" "Monitorización de superficie NO instalada"
    _vp_xcheck /usr/local/bin/ciberint-soar-bridge.sh \
        "Bridge SOAR de ciberinteligencia instalado" "Bridge SOAR de ciberinteligencia NO instalado"

    CIBERINT_TIMERS=0
    for _t in ciberint-red ciberint-dns ciberint-superficie ciberint-alerta-temprana ciberint-reporte-diario ciberint-soar-bridge; do
        systemctl is-enabled "${_t}.timer" &>/dev/null && CIBERINT_TIMERS=$(( CIBERINT_TIMERS + 1 ))
    done
    if [[ $CIBERINT_TIMERS -ge 4 ]]; then
        echo -e "  ${GREEN}OK${NC}  Timers de ciberinteligencia activos: $CIBERINT_TIMERS/6"
        _vp_ok
    else
        echo -e "  ${YELLOW}!!${NC}  Timers de ciberinteligencia: solo $CIBERINT_TIMERS/6 activos"
        _vp_fail
    fi

    # ── 45. Validación ofensiva (Metasploit) ──
    echo ""
    _mark_section 45
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[45/64] VALIDACIÓN OFENSIVA (METASPLOIT)${NC}"
    if command -v msfconsole &>/dev/null; then
        echo -e "  ${GREEN}OK${NC}  msfconsole disponible"
        _vp_ok
    else
        echo -e "  ${YELLOW}!!${NC}  msfconsole NO disponible (opcional)"
        _vp_fail
    fi
    _vp_xcheck /usr/local/bin/validar-metasploit.sh \
        "Validador ofensivo Metasploit instalado" "Validador ofensivo Metasploit NO instalado"

    # ── 46. Protección ISP ──
    echo ""
    _mark_section 46
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[46/64] PROTECCIÓN CONTRA ISP${NC}"

    # Kill switch VPN
    _vp_fcheck /etc/securizar/vpn-killswitch.sh \
        "Kill switch VPN instalado" "Kill switch VPN NO instalado"

    # DNS leak prevention
    _vp_fcheck_contains /etc/systemd/resolved.conf.d/02-isp-dns-leak-prevention.conf "DNSOverTLS=yes" \
        "DNS-over-TLS estricto configurado" "DNS-over-TLS estricto NO configurado"

    # NTS (chrony)
    if systemctl is-active chronyd &>/dev/null; then
        echo -e "  ${GREEN}OK${NC}  chronyd activo con NTS"
        _vp_ok
    elif [[ -f /etc/chrony.d/securizar-nts.conf ]]; then
        echo -e "  ${YELLOW}!!${NC}  NTS configurado pero chronyd no activo"
        _vp_fail
    else
        echo -e "  ${YELLOW}!!${NC}  NTS NO configurado"
        _vp_fail
    fi

    # Auditoría ISP
    _vp_xcheck /usr/local/bin/auditoria-isp.sh \
        "Auditoría ISP instalada" "Auditoría ISP NO instalada"

    # ── 47. Hardening criptográfico ──
    echo ""
    _mark_section 47
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[47/64] HARDENING CRIPTOGRÁFICO${NC}"

    _vp_fcheck /etc/ssh/sshd_config.d/99-securizar-crypto.conf \
        "SSH crypto hardened" "SSH crypto NO hardened"
    _vp_xcheck /usr/local/bin/auditoria-criptografica.sh \
        "Auditoría criptográfica instalada" "Auditoría criptográfica NO instalada"
    _vp_fcheck /etc/modprobe.d/securizar-crypto-blacklist.conf \
        "Blacklist crypto kernel activa" "Blacklist crypto kernel NO activa"

    # ── 48. Seguridad de contenedores ──
    echo ""
    _mark_section 48
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[48/64] SEGURIDAD DE CONTENEDORES${NC}"

    if command -v docker &>/dev/null || command -v podman &>/dev/null; then
        _vp_fcheck /etc/docker/daemon.json \
            "Docker daemon.json hardened" "Docker daemon.json NO hardened"
        _vp_xcheck /usr/local/bin/auditoria-contenedores.sh \
            "Auditoría de contenedores instalada" "Auditoría de contenedores NO instalada"
    else
        echo -e "  ${DIM}--${NC}  Docker/Podman no instalados (N/A)"
        _vp_na
    fi

    # ── 49. Cumplimiento CIS ──
    echo ""
    _mark_section 49
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[49/64] CUMPLIMIENTO CIS BENCHMARKS${NC}"

    _vp_xcheck /usr/local/bin/cis-scoring.sh \
        "Motor de puntuación CIS instalado" "Motor de puntuación CIS NO instalado"
    _vp_xcheck /usr/local/bin/reporte-cumplimiento-cis.sh \
        "Generador de informes CIS instalado" "Generador de informes CIS NO instalado"
    _vp_fcheck /etc/sysctl.d/99-securizar-cis-network.conf \
        "Hardening red CIS aplicado" "Hardening red CIS NO aplicado"

    # ── 50. Seguridad de email ──
    echo ""
    _mark_section 50
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[50/64] SEGURIDAD DE EMAIL${NC}"

    if command -v postfix &>/dev/null || [[ -f /etc/postfix/main.cf ]]; then
        _vp_xcheck /usr/local/bin/auditoria-email.sh \
            "Auditoría de email instalada" "Auditoría de email NO instalada"
        _vp_xcheck /usr/local/bin/verificar-spf.sh \
            "Verificador SPF instalado" "Verificador SPF NO instalado"
        _vp_xcheck /usr/local/bin/verificar-dmarc.sh \
            "Verificador DMARC instalado" "Verificador DMARC NO instalado"
    else
        echo -e "  ${DIM}--${NC}  Postfix no instalado (N/A)"
        _vp_na
    fi

    # ── 51. Logging centralizado ──
    echo ""
    _mark_section 51
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[51/64] LOGGING CENTRALIZADO Y SIEM${NC}"

    _vp_fcheck /etc/rsyslog.d/01-securizar-hardening.conf \
        "rsyslog hardened" "rsyslog NO hardened"
    _vp_xcheck /usr/local/bin/correlacionar-eventos.sh \
        "Correlación de eventos instalada" "Correlación de eventos NO instalada"
    _vp_xcheck /usr/local/bin/auditoria-logging.sh \
        "Auditoría de logging instalada" "Auditoría de logging NO instalada"

    # ── 52. Cadena de suministro ──
    echo ""
    _mark_section 52
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[52/64] CADENA DE SUMINISTRO${NC}"

    _vp_xcheck /usr/local/bin/generar-sbom.sh \
        "Generador SBOM instalado" "Generador SBOM NO instalado"
    _vp_xcheck /usr/local/bin/auditar-cves.sh \
        "Auditoría CVE instalada" "Auditoría CVE NO instalada"
    _vp_xcheck /usr/local/bin/detectar-troyanizados.sh \
        "Detector de paquetes troyanizados instalado" "Detector de troyanizados NO instalado"

    # ── 53. Segmentación de red y Zero Trust ──
    echo ""
    _mark_section 53
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[53/64] SEGMENTACIÓN DE RED Y ZERO TRUST${NC}"

    _vp_fcheck /etc/securizar/zonas-red.conf \
        "Zonas de red definidas" "Zonas de red NO definidas"
    _vp_xcheck /usr/local/bin/validar-segmentacion.sh \
        "Validación de segmentación instalada" "Validación de segmentación NO instalada"
    _vp_xcheck /usr/local/bin/auditoria-segmentacion-zt.sh \
        "Auditoría de segmentación ZT instalada" "Auditoría de segmentación ZT NO instalada"

    # ── 54. Forense avanzado ──
    echo ""
    _mark_section 54
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[54/64] FORENSE AVANZADO${NC}"

    _vp_xcheck /usr/local/bin/forense-recopilar-todo.sh \
        "Kit forense completo instalado" "Kit forense completo NO instalado"
    _vp_xcheck /usr/local/bin/forense-timeline.sh \
        "Constructor de timeline instalado" "Constructor de timeline NO instalado"
    _vp_xcheck /usr/local/bin/forense-custodia.sh \
        "Cadena de custodia instalada" "Cadena de custodia NO instalada"

    # ── 55. Kernel live patching ──
    echo ""
    _mark_section 55
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[55/64] KERNEL LIVE PATCHING${NC}"

    _vp_xcheck /usr/local/bin/auditar-kernel.sh \
        "Auditoría de kernel instalada" "Auditoría de kernel NO instalada"
    _vp_fcheck /etc/sysctl.d/99-securizar-kernel-exploit.conf \
        "Sysctl anti-exploit activo" "Sysctl anti-exploit NO configurado"
    _vp_xcheck /usr/local/bin/auditoria-livepatch.sh \
        "Auditoría livepatch instalada" "Auditoría livepatch NO instalada"

    # ── 56. Bases de datos ──
    echo ""
    _mark_section 56
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[56/64] BASES DE DATOS${NC}"

    _vp_xcheck /usr/local/bin/auditar-mysql.sh \
        "Auditoría MySQL instalada" "Auditoría MySQL NO instalada"
    _vp_xcheck /usr/local/bin/auditar-redis.sh \
        "Auditoría Redis instalada" "Auditoría Redis NO instalada"
    _vp_xcheck /usr/local/bin/auditar-mongodb.sh \
        "Auditoría MongoDB instalada" "Auditoría MongoDB NO instalada"

    # ── 57. Backup y DR ──
    echo ""
    _mark_section 57
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[57/64] BACKUP Y DR${NC}"

    _vp_xcheck /usr/local/bin/securizar-backup-borg.sh \
        "Backup Borg configurado" "Backup Borg NO configurado"
    _vp_xcheck /usr/local/bin/verificar-estrategia-321.sh \
        "Verificador estrategia 3-2-1 instalado" "Verificador estrategia 3-2-1 NO instalado"
    _vp_fcheck /etc/securizar/backup-strategy.conf \
        "Estrategia de backup configurada" "Estrategia de backup NO configurada"

    # ── 58. Seguridad web ──
    echo ""
    _mark_section 58
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[58/64] SEGURIDAD WEB${NC}"

    _vp_xcheck /usr/local/bin/verificar-headers-seguridad.sh \
        "Verificador de headers instalado" "Verificador de headers NO instalado"
    _vp_xcheck /usr/local/bin/auditar-seguridad-web.sh \
        "Auditoría web instalada" "Auditoría web NO instalada"

    # ── 59. Gestión de secretos ──
    echo ""
    _mark_section 59
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[59/64] GESTIÓN DE SECRETOS${NC}"

    _vp_xcheck /usr/local/bin/escanear-secretos.sh \
        "Escáner de secretos instalado" "Escáner de secretos NO instalado"
    _vp_xcheck /usr/local/bin/rotar-credenciales.sh \
        "Rotador de credenciales instalado" "Rotador de credenciales NO instalado"
    _vp_fcheck /etc/securizar/secrets-policy.conf \
        "Política de secretos configurada" "Política de secretos NO configurada"

    # ── 60. Seguridad cloud ──
    echo ""
    _mark_section 60
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[60/64] SEGURIDAD CLOUD${NC}"

    _vp_xcheck /usr/local/bin/auditar-cloud-iam.sh \
        "Auditoría IAM cloud instalada" "Auditoría IAM cloud NO instalada"
    _vp_xcheck /usr/local/bin/evaluar-postura-cloud.sh \
        "Evaluador postura cloud instalado" "Evaluador postura cloud NO instalado"

    # ── 61. LDAP y Active Directory ──
    echo ""
    _mark_section 61
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[61/64] LDAP Y ACTIVE DIRECTORY${NC}"

    _vp_xcheck /usr/local/bin/auditar-ldap-seguridad.sh \
        "Auditoría LDAP instalada" "Auditoría LDAP NO instalada"
    _vp_xcheck /usr/local/bin/verificar-kerberos.sh \
        "Verificador Kerberos instalado" "Verificador Kerberos NO instalado"

    # ── 62. Cumplimiento normativo ──
    echo ""
    _mark_section 62
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[62/64] CUMPLIMIENTO NORMATIVO${NC}"

    _vp_xcheck /usr/local/bin/evaluar-pci-dss.sh \
        "Evaluador PCI-DSS instalado" "Evaluador PCI-DSS NO instalado"
    _vp_xcheck /usr/local/bin/evaluar-gdpr.sh \
        "Evaluador GDPR instalado" "Evaluador GDPR NO instalado"
    _vp_fcheck /etc/securizar/compliance-framework.conf \
        "Framework de cumplimiento configurado" "Framework de cumplimiento NO configurado"

    # ── 63. Tecnología de engaño ──
    echo ""
    _mark_section 63
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[63/64] TECNOLOGÍA DE ENGAÑO${NC}"

    _vp_xcheck /usr/local/bin/gestionar-honeypots.sh \
        "Gestor de honeypots instalado" "Gestor de honeypots NO instalado"
    _vp_xcheck /usr/local/bin/generar-honeytokens.sh \
        "Generador de honeytokens instalado" "Generador de honeytokens NO instalado"

    # ── 64. Seguridad wireless ──
    echo ""
    _mark_section 64
    echo -e "  ${CYAN}┌─${NC} ${BOLD}[64/64] SEGURIDAD WIRELESS${NC}"

    _vp_xcheck /usr/local/bin/auditar-wireless.sh \
        "Auditoría wireless instalada" "Auditoría wireless NO instalada"
    _vp_xcheck /usr/local/bin/detectar-rogue-ap.sh \
        "Detector de rogue AP instalado" "Detector de rogue AP NO instalado"

    # ── Finalizar último check ──
    _mark_section 0

    # ── Resumen ponderado ──
    local total=$((checks_ok + warnings))
    local wscore=0
    if [[ $_score_max -gt 0 ]]; then
        wscore=$(( _score_earned * 100 / _score_max ))
    fi

    echo ""
    echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    # Score visual
    local score_color="$RED"
    local score_label="CRÍTICO"
    local score_bg="$BG_RED"
    if [[ $wscore -ge 90 ]]; then
        score_color="$GREEN"; score_label="EXCELENTE"; score_bg="$BG_GREEN"
    elif [[ $wscore -ge 70 ]]; then
        score_color="$GREEN"; score_label="BUENO"; score_bg="$BG_GREEN"
    elif [[ $wscore -ge 50 ]]; then
        score_color="$YELLOW"; score_label="PARCIAL"; score_bg="$BG_YELLOW"
    elif [[ $wscore -ge 30 ]]; then
        score_color="$YELLOW"; score_label="BAJO"; score_bg="$BG_YELLOW"
    fi

    _center "${score_bg} PUNTUACIÓN: ${wscore}% (ponderada) ${NC}"
    echo ""
    _center "${score_color}${BOLD}${score_label}${NC}"
    echo ""

    # Progress bar del score
    local bar_width=40
    local bar_filled=$(( wscore * bar_width / 100 ))
    local bar_empty=$(( bar_width - bar_filled ))
    local bar_str=""
    for ((bi=0; bi<bar_filled; bi++)); do bar_str+="█"; done
    for ((bi=0; bi<bar_empty; bi++)); do bar_str+="░"; done
    _center "${score_color}${bar_str}${NC}"
    echo ""

    # Delta tracking
    if [[ $_prev_score -ge 0 ]]; then
        local _delta=$(( wscore - _prev_score ))
        if [[ $_delta -gt 0 ]]; then
            _center "${GREEN}Cambio: +${_delta}%${NC}"
        elif [[ $_delta -eq 0 ]]; then
            _center "${DIM}= sin cambios${NC}"
        else
            _center "${RED}Cambio: ${_delta}%${NC}"
        fi
        echo ""
    fi

    # Tendencia: mostrar últimos 3 scores si hay historial
    if [[ -f "$_score_file" ]]; then
        local _trend=""
        while IFS=: read -r _ts _sc; do
            [[ "$_sc" =~ ^[0-9]+$ ]] && _trend+="${_sc}% → "
        done < <(tail -3 "$_score_file" 2>/dev/null)
        _trend+="${wscore}%"
        _center "${DIM}Tendencia: ${_trend}${NC}"
        echo ""
    fi

    _prev_score=$wscore

    # Persistir score para tracking entre ejecuciones
    mkdir -p /var/lib/securizar 2>/dev/null || true
    echo "$(date +%s):$wscore" >> "$_score_file" 2>/dev/null || true

    echo -e "    ${GREEN}●${NC} Checks OK:     ${GREEN}${BOLD}$checks_ok${NC}"
    echo -e "    ${YELLOW}●${NC} Advertencias:  ${YELLOW}${BOLD}$warnings${NC}"
    if [[ $_na_count -gt 0 ]]; then
        echo -e "    ${DIM}●${NC} N/A omitidos:  ${DIM}$_na_count${NC}"
    fi
    echo -e "    ${DIM}Total verificaciones: $total | Peso: ${_score_earned}/${_score_max}${NC}"
    echo ""

    # Desglose por severidad
    if [[ $warnings -gt 0 ]]; then
        echo -e "    ${DIM}Desglose advertencias:${NC}"
        [[ $_crit_fails -gt 0 ]] && echo -e "      ${RED}●${NC} Críticos (x3): ${RED}${BOLD}$_crit_fails${NC}"
        [[ $_high_fails -gt 0 ]] && echo -e "      ${YELLOW}●${NC} Altos (x2):    ${YELLOW}${BOLD}$_high_fails${NC}"
        [[ $_med_fails -gt 0 ]]  && echo -e "      ${DIM}●${NC} Medios (x1):   ${DIM}$_med_fails${NC}"
        echo ""

        # Top categorías fallidas (hasta 5, por peso descendente)
        echo -e "    ${DIM}Prioridad de remediación:${NC}"
        local _top_sorted=""
        for _fk in ${!FAILED_CHECKS[@]}; do
            _top_sorted+="${_SECTION_WEIGHT[$_fk]:-1}:$_fk "
        done
        local _top_i=0
        for _te in $(echo "$_top_sorted" | tr ' ' '\n' | sort -t: -k1 -rn -k2 -n); do
            [[ $_top_i -ge 5 ]] && break
            local _tk="${_te#*:}" _tw="${_te%%:*}"
            local _tc="$DIM"
            case $_tw in 3) _tc="$RED" ;; 2) _tc="$YELLOW" ;; esac
            printf "      ${_tc}%d.${NC} [%s] %s\n" "$((_top_i+1))" "${_CHECK_TITLE[$_tk]:-?}" "(check $_tk)"
            _top_i=$(( _top_i + 1 ))
        done
        echo ""
    fi

    if [[ $warnings -eq 0 ]]; then
        _center "${GREEN}${BOLD}Sistema completamente securizado${NC}"
    elif [[ $_crit_fails -gt 0 ]]; then
        _center "${RED}Sistema requiere atención inmediata ($_crit_fails fallos críticos)${NC}"
    elif [[ $warnings -le 5 ]]; then
        _center "${GREEN}Sistema bien securizado (ajustes menores pendientes)${NC}"
    elif [[ $warnings -le 15 ]]; then
        _center "${YELLOW}Sistema parcialmente securizado${NC}"
    else
        _center "${YELLOW}Sistema necesita más hardening${NC}"
    fi

    echo ""
    echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${DIM}Log: $LOGFILE${NC}"

    # ── 100% → fin ──
    if [[ $wscore -eq 100 ]]; then
        echo ""
        _center "${GREEN}${BOLD}Sistema completamente securizado${NC}"
        break
    fi

    # ── Plan de remediación ──
    echo ""
    echo -e "  ${BG_YELLOW} PLAN DE REMEDIACIÓN ${NC}"
    echo ""

    # Recopilar módulos necesarios, ordenar por severidad descendente
    declare -A _NEEDED_MODS=()
    local _sorted_fails=""
    for _chk in ${!FAILED_CHECKS[@]}; do
        local _w=${_SECTION_WEIGHT[$_chk]:-1}
        _sorted_fails+="$_w:$_chk "
    done
    for _entry in $(echo "$_sorted_fails" | tr ' ' '\n' | sort -t: -k1 -rn -k2 -n); do
        local _chk="${_entry#*:}"
        local _w="${_entry%%:*}"
        local _mods="${_CHECK_FIX[$_chk]:-}"
        [[ -z "$_mods" ]] && continue
        local _sev_label="${DIM}MEDIO${NC}" _sev_color="$DIM"
        case $_w in
            3) _sev_label="${RED}CRÍT${NC}"; _sev_color="$RED" ;;
            2) _sev_label="${YELLOW}ALTO${NC}"; _sev_color="$YELLOW" ;;
        esac
        local _sf=${_SECTION_FAILS[$_chk]:-1}
        printf "    [${_sev_label}] ${_sev_color}Check %2d${NC} %-22s ${DIM}(%d fallo(s))${NC} → Módulos:" "$_chk" "(${_CHECK_TITLE[$_chk]:-?})" "$_sf"
        for _m in $_mods; do
            printf " ${CYAN}%d${NC}" "$_m"
            _NEEDED_MODS[$_m]=1
        done
        echo ""
    done

    # Si no hay módulos que sugerir, salir
    if [[ ${#_NEEDED_MODS[@]} -eq 0 ]]; then
        echo ""
        echo -e "  ${DIM}No hay módulos de remediación aplicables.${NC}"
        break
    fi

    # Estimar impacto: puntos recuperables por la remediación
    local _impact_pts=0
    declare -A _impact_seen=()
    for _chk in ${!FAILED_CHECKS[@]}; do
        local _fix_mods="${_CHECK_FIX[$_chk]:-}"
        for _m in $_fix_mods; do
            if [[ -n "${_NEEDED_MODS[$_m]:-}" ]] && [[ -z "${_impact_seen[$_chk]:-}" ]]; then
                _impact_pts=$(( _impact_pts + ${_SECTION_WEIGHT[$_chk]:-1} * ${_SECTION_FAILS[$_chk]:-1} ))
                _impact_seen[$_chk]=1
                break
            fi
        done
    done
    for _k in "${!_impact_seen[@]}"; do unset "_impact_seen[$_k]"; done

    echo ""
    echo -e "  ${BOLD}Módulos a ejecutar (${#_NEEDED_MODS[@]}):${NC}"
    echo ""
    for _m in $(echo "${!_NEEDED_MODS[@]}" | tr ' ' '\n' | sort -n); do
        printf "    ${CYAN}%2d${NC}  %s  ${DIM}(%s)${NC}\n" "$_m" "${MOD_NAMES[$_m]:-?}" "${MOD_DESCS[$_m]:-}"
    done
    echo ""
    if [[ $_score_max -gt 0 ]]; then
        local _new_est=$(( (_score_earned + _impact_pts) * 100 / _score_max ))
        [[ $_new_est -gt 100 ]] && _new_est=100
        echo -e "  ${DIM}Impacto estimado: ~${_impact_pts} puntos recuperables (${wscore}% → ~${_new_est}%)${NC}"
        echo ""
    fi

    if ! ask "¿Ejecutar estos módulos para mejorar la puntuación?"; then
        break
    fi

    # ── Ejecutar módulos de remediación ──
    echo ""
    local _mod_i=0
    local _mod_total=${#_NEEDED_MODS[@]}
    for _m in $(echo "${!_NEEDED_MODS[@]}" | tr ' ' '\n' | sort -n); do
        _mod_i=$(( _mod_i + 1 ))
        echo ""
        echo -e "  ${DIM}─────────────────────────────────────────────────────────────────${NC}"
        echo -e "  ${CYAN}▶${NC} ${BOLD}Módulo ${_m} (${_mod_i}/${_mod_total}):${NC} ${MOD_NAMES[$_m]}"
        echo -e "  ${DIM}─────────────────────────────────────────────────────────────────${NC}"
        echo ""
        ${MOD_FUNCS[$_m]} || true
        MOD_RUN[$_m]=1
    done

    # Limpiar para la siguiente iteración
    for _k in "${!_NEEDED_MODS[@]}"; do unset "_NEEDED_MODS[$_k]"; done

    echo ""
    echo -e "  ${CYAN}◆${NC} Re-ejecutando verificación proactiva..."
    echo ""

    done  # while true
}

# ============================================================
# SUB-MENÚS
# ============================================================

submenu_base() {
    while true; do
        _draw_header_compact
        _breadcrumb "Securizar ${DIM}❯${NC} ${BOLD}Hardening Base"

        echo -e "  ${DIM}Módulos fundamentales de securización del sistema${NC}"
        echo ""
        local n
        for n in 1 2 3 4 5 6 7 8 9 10; do
            _show_module_entry "$n"
        done

        echo ""
        echo -e "  ${DIM}─────────────────────────────────────────────────────────────────${NC}"
        echo -e "  ${WHITE}t${NC} ${DIM}Todos${NC}    ${WHITE}b${NC} ${DIM}Volver${NC}    ${WHITE}q${NC} ${DIM}Salir${NC}    ${WHITE}?${NC} ${DIM}Ayuda${NC}"
        echo ""
        echo -ne "  ${BOLD}❯${NC} "
        read -r opt

        case "$opt" in
            10)       _exec_module 10 ;;
            [1-9])    _exec_module "$opt" ;;
            t|T)      _run_category "Hardening Base" 1 10 ; _pause ;;
            b|B|0)    return ;;
            q|Q)      _exit_securizar ;;
            "?")      _show_help ;;
            "")       continue ;;
            *)
                if [[ "$opt" =~ ^[0-9]+$ ]] && [[ "$opt" -ge 1 ]] && [[ "$opt" -le 56 ]]; then
                    _exec_module "$opt"
                else
                    echo -e "  ${RED}✗${NC} Opción no válida"; sleep 0.5
                fi
                ;;
        esac
    done
}

submenu_proactiva() {
    while true; do
        _draw_header_compact
        _breadcrumb "Securizar ${DIM}❯${NC} ${BOLD}Securización Proactiva"

        echo -e "  ${DIM}Módulos avanzados de protección proactiva${NC}"
        echo ""
        local n
        for n in 11 12 13 14 15 16 17 18; do
            _show_module_entry "$n"
        done

        echo ""
        echo -e "  ${DIM}─────────────────────────────────────────────────────────────────${NC}"
        echo -e "  ${WHITE}t${NC} ${DIM}Todos${NC}    ${WHITE}b${NC} ${DIM}Volver${NC}    ${WHITE}q${NC} ${DIM}Salir${NC}    ${WHITE}?${NC} ${DIM}Ayuda${NC}"
        echo ""
        echo -ne "  ${BOLD}❯${NC} "
        read -r opt

        case "$opt" in
            1[1-8])   _exec_module "$opt" ;;
            t|T)      _run_category "Securización Proactiva" 11 18 ; _pause ;;
            b|B|0)    return ;;
            q|Q)      _exit_securizar ;;
            "?")      _show_help ;;
            "")       continue ;;
            *)
                if [[ "$opt" =~ ^[0-9]+$ ]] && [[ "$opt" -ge 1 ]] && [[ "$opt" -le 56 ]]; then
                    _exec_module "$opt"
                else
                    echo -e "  ${RED}✗${NC} Opción no válida"; sleep 0.5
                fi
                ;;
        esac
    done
}

submenu_mitre() {
    while true; do
        _draw_header_compact
        _breadcrumb "Securizar ${DIM}❯${NC} ${BOLD}Mitigaciones MITRE ATT&CK"

        echo -e "  ${DIM}Defensa contra tácticas específicas del framework MITRE${NC}"
        echo ""
        local n
        for n in 19 20 21 22 23 24 25 26 27 28 29 30; do
            _show_module_entry "$n"
        done

        echo ""
        echo -e "  ${DIM}─────────────────────────────────────────────────────────────────${NC}"
        echo -e "  ${WHITE}t${NC} ${DIM}Todos${NC}    ${WHITE}b${NC} ${DIM}Volver${NC}    ${WHITE}q${NC} ${DIM}Salir${NC}    ${WHITE}?${NC} ${DIM}Ayuda${NC}"
        echo ""
        echo -ne "  ${BOLD}❯${NC} "
        read -r opt

        case "$opt" in
            19|20|21|22|23|24|25|26|27|28|29|30) _exec_module "$opt" ;;
            t|T)         _run_category "Mitigaciones MITRE ATT&CK" 19 30 ; _pause ;;
            b|B|0)       return ;;
            q|Q)         _exit_securizar ;;
            "?")         _show_help ;;
            "")          continue ;;
            *)
                if [[ "$opt" =~ ^[0-9]+$ ]] && [[ "$opt" -ge 1 ]] && [[ "$opt" -le 56 ]]; then
                    _exec_module "$opt"
                else
                    echo -e "  ${RED}✗${NC} Opción no válida"; sleep 0.5
                fi
                ;;
        esac
    done
}

submenu_operaciones() {
    while true; do
        _draw_header_compact
        _breadcrumb "Securizar ${DIM}❯${NC} ${BOLD}Operaciones de Seguridad"

        echo -e "  ${DIM}IR, monitorización, reportes, hunting, SOAR, purple team${NC}"
        echo ""
        local n
        for n in 31 32 33 34 35 36; do
            _show_module_entry "$n"
        done

        echo ""
        echo -e "  ${DIM}─────────────────────────────────────────────────────────────────${NC}"
        echo -e "  ${WHITE}t${NC} ${DIM}Todos${NC}    ${WHITE}b${NC} ${DIM}Volver${NC}    ${WHITE}q${NC} ${DIM}Salir${NC}    ${WHITE}?${NC} ${DIM}Ayuda${NC}"
        echo ""
        echo -ne "  ${BOLD}❯${NC} "
        read -r opt

        case "$opt" in
            3[1-6]) _exec_module "$opt" ;;
            t|T)         _run_category "Operaciones de Seguridad" 31 36 ; _pause ;;
            b|B|0)       return ;;
            q|Q)         _exit_securizar ;;
            "?")         _show_help ;;
            "")          continue ;;
            *)
                if [[ "$opt" =~ ^[0-9]+$ ]] && [[ "$opt" -ge 1 ]] && [[ "$opt" -le 56 ]]; then
                    _exec_module "$opt"
                else
                    echo -e "  ${RED}✗${NC} Opción no válida"; sleep 0.5
                fi
                ;;
        esac
    done
}

submenu_inteligencia() {
    while true; do
        _draw_header_compact
        _breadcrumb "Securizar ${DIM}❯${NC} ${BOLD}Inteligencia"

        echo -e "  ${DIM}Ciberinteligencia proactiva, protección ISP, enriquecimiento IoC${NC}"
        echo ""
        local n
        for n in 37 38; do
            _show_module_entry "$n"
        done

        echo ""
        echo -e "  ${DIM}─────────────────────────────────────────────────────────────────${NC}"
        echo -e "  ${WHITE}t${NC} ${DIM}Todos${NC}    ${WHITE}b${NC} ${DIM}Volver${NC}    ${WHITE}q${NC} ${DIM}Salir${NC}    ${WHITE}?${NC} ${DIM}Ayuda${NC}"
        echo ""
        echo -ne "  ${BOLD}❯${NC} "
        read -r opt

        case "$opt" in
            37|38)       _exec_module "$opt" ;;
            t|T)         _run_category "Inteligencia" 37 38 ; _pause ;;
            b|B|0)       return ;;
            q|Q)         _exit_securizar ;;
            "?")         _show_help ;;
            "")          continue ;;
            *)
                if [[ "$opt" =~ ^[0-9]+$ ]] && [[ "$opt" -ge 1 ]] && [[ "$opt" -le 56 ]]; then
                    _exec_module "$opt"
                else
                    echo -e "  ${RED}✗${NC} Opción no válida"; sleep 0.5
                fi
                ;;
        esac
    done
}

submenu_avanzado() {
    while true; do
        _draw_header_compact
        _breadcrumb "Securizar ${DIM}❯${NC} ${BOLD}Avanzado"

        echo -e "  ${DIM}Criptografía, contenedores, CIS, email, logging, supply chain, red, forense, kernel,${NC}"
        echo -e "  ${DIM}BBDD, backup, web, secretos, cloud, LDAP, compliance, deception, wireless${NC}"
        echo ""
        local n
        for n in 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56; do
            _show_module_entry "$n"
        done

        echo ""
        echo -e "  ${DIM}─────────────────────────────────────────────────────────────────${NC}"
        echo -e "  ${WHITE}t${NC} ${DIM}Todos${NC}    ${WHITE}b${NC} ${DIM}Volver${NC}    ${WHITE}q${NC} ${DIM}Salir${NC}    ${WHITE}?${NC} ${DIM}Ayuda${NC}"
        echo ""
        echo -ne "  ${BOLD}❯${NC} "
        read -r opt

        case "$opt" in
            39|40|41|42|43|44|45|46|47|48|49|50|51|52|53|54|55|56) _exec_module "$opt" ;;
            t|T)         _run_category "Avanzado" 39 56 ; _pause ;;
            b|B|0)       return ;;
            q|Q)         _exit_securizar ;;
            "?")         _show_help ;;
            "")          continue ;;
            *)
                if [[ "$opt" =~ ^[0-9]+$ ]] && [[ "$opt" -ge 1 ]] && [[ "$opt" -le 56 ]]; then
                    _exec_module "$opt"
                else
                    echo -e "  ${RED}✗${NC} Opción no válida"; sleep 0.5
                fi
                ;;
        esac
    done
}

# ============================================================
# MENÚ PRINCIPAL
# ============================================================
menu_principal() {
    while true; do
        _draw_header
        _draw_sysinfo
        echo ""

        # Count module progress per category
        local base_done=0 pro_done=0 mitre_done=0 ops_done=0
        local _n
        for _n in 1 2 3 4 5 6 7 8 9 10; do [[ "${MOD_RUN[$_n]:-}" == "1" ]] && ((base_done++)) || true; done
        for _n in 11 12 13 14 15 16 17 18; do [[ "${MOD_RUN[$_n]:-}" == "1" ]] && ((pro_done++)) || true; done
        for _n in 19 20 21 22 23 24 25 26 27 28 29 30; do [[ "${MOD_RUN[$_n]:-}" == "1" ]] && ((mitre_done++)) || true; done
        for _n in 31 32 33 34 35 36; do [[ "${MOD_RUN[$_n]:-}" == "1" ]] && ((ops_done++)) || true; done

        echo -e "  ${BOLD}Módulos${NC}"
        echo ""
        printf "    ${CYAN}b${NC}   ${BOLD}Hardening Base${NC}              ${DIM}10 módulos${NC}   "
        _cat_dots 10 "$base_done"
        echo ""
        printf "    ${CYAN}p${NC}   ${BOLD}Securización Proactiva${NC}       ${DIM}8 módulos${NC}   "
        _cat_dots 8 "$pro_done"
        echo ""
        printf "    ${CYAN}m${NC}   ${BOLD}Mitigaciones MITRE ATT&CK${NC}   ${DIM}12 módulos${NC}  "
        _cat_dots 12 "$mitre_done"
        echo ""
        printf "    ${CYAN}o${NC}   ${BOLD}Operaciones de Seguridad${NC}     ${DIM}6 módulos${NC}   "
        _cat_dots 6 "$ops_done"
        echo ""

        local intel_done=0
        for _n in 37 38; do [[ "${MOD_RUN[$_n]:-}" == "1" ]] && ((intel_done++)) || true; done
        printf "    ${CYAN}i${NC}   ${BOLD}Inteligencia${NC}                 ${DIM}2 módulos${NC}   "
        _cat_dots 2 "$intel_done"
        echo ""

        local avz_done=0
        for _n in 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56; do [[ "${MOD_RUN[$_n]:-}" == "1" ]] && ((avz_done++)) || true; done
        printf "    ${YELLOW}x${NC}   ${BOLD}Avanzado${NC}                     ${DIM}18 módulos${NC}  "
        _cat_dots 18 "$avz_done"
        echo ""

        echo ""
        echo -e "  ${BOLD}Acciones${NC}"
        echo ""
        echo -e "    ${GREEN}a${NC}   ${GREEN}${BOLD}Aplicar TODO seguro${NC}          ${DIM}56 módulos secuenciales${NC}"
        echo -e "    ${CYAN}v${NC}   ${CYAN}${BOLD}Verificación proactiva${NC}       ${DIM}64 checks de seguridad${NC}"

        _draw_footer

        echo -e "    ${DIM}q${NC}   ${DIM}Salir${NC}                        ${DIM}?  Ayuda · 1-56  Acceso directo${NC}"
        echo ""
        echo -ne "  ${BOLD}❯${NC} "
        read -r opcion

        # Direct module number access (1-56)
        if [[ "$opcion" =~ ^[0-9]+$ ]] && [[ "$opcion" -ge 1 ]] && [[ "$opcion" -le 56 ]]; then
            _exec_module "$opcion"
            continue
        fi

        case "$opcion" in
            b|B)    submenu_base ;;
            p|P)    submenu_proactiva ;;
            m|M)    submenu_mitre ;;
            o|O)    submenu_operaciones ;;
            i|I)    submenu_inteligencia ;;
            x|X)    submenu_avanzado ;;
            a|A)    aplicar_todo_seguro ; _pause ;;
            v|V)    verificacion_proactiva ; _pause ;;
            "?")    _show_help ;;
            q|Q|0)  _exit_securizar ;;
            "")     continue ;;
            *)      echo -e "  ${RED}✗${NC} Opción no válida: $opcion"; sleep 0.5 ;;
        esac
    done
}

# ============================================================
# INICIO
# ============================================================
{
    echo "Securizar-menu iniciado - $(date)"
    echo "Directorio de scripts: $SCRIPT_DIR"
    echo "Backup en: $BACKUP_DIR"
    echo "Log en: $LOGFILE"
} >> "$LOGFILE"

# Init animation
printf "  ${CYAN}⠋${NC} ${DIM}Inicializando...${NC}"
sleep 0.15
printf "\r  ${CYAN}⠹${NC} ${DIM}Verificando sistema...${NC}"
sleep 0.15
printf "\r  ${CYAN}⠧${NC} ${DIM}Cargando módulos...${NC}   "
sleep 0.15
printf "\r                                     \r"

menu_principal
