#!/bin/bash
# ============================================================
# HARDENING PARANOICO - Linux Multi-Distro
# ============================================================
# ADVERTENCIA: Medidas agresivas de seguridad
# Ejecutar como root: sudo bash hardening-paranoico.sh
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "hardening-paranoico"
securizar_setup_traps

# ── Pre-check: salida temprana si todo aplicado ──
_precheck 23
_pc check_file_exists /etc/sysctl.d/99-paranoid.conf
_pc check_file_exists /etc/modprobe.d/paranoid-blacklist.conf
_pc check_file_exists /etc/systemd/coredump.conf.d/disable.conf
_pc check_file_exists /etc/profile.d/timeout.sh
_pc true  # S5: restringir su (seguridad PAM, siempre re-evaluar)
_pc check_file_exists /etc/cron.allow
_pc check_file_contains /etc/issue "ACCESO NO AUTORIZADO PROHIBIDO"
_pc check_perm /etc/shadow "600"
_pc true  # S9: GRUB password (interactivo)
_pc true  # S10: herramientas de seguridad (multiples installs opcionales)
_pc true  # S11: firewall paranoico (condicional)
_pc true  # S12: CUPS restringir (condicional)
_pc true  # S12b: LAN isolation (condicional, nftables only)
_pc check_file_contains /etc/login.defs "UMASK 027"
_pc true  # S14: USB storage (opcional con ask)
_pc check_file_exists /etc/audit/rules.d/99-paranoid.rules
_pc check_file_contains /etc/fail2ban/jail.local "bantime = 48h"
_pc check_file_exists /etc/sysctl.d/99-paranoid-interfaces.conf
_pc true  # S18: faillock (condicional)
_pc true  # S19: user namespaces limit (condicional)
_pc true  # S20: crypto policy FUTURE (condicional)
_pc true  # S21: OBEX/geoclue/captive portal (condicional)
_pc true  # S22: mount options hardening (condicional)
_precheck_result

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     HARDENING PARANOICO - Linux Multi-Distro              ║"
echo "║     ADVERTENCIA: Medidas de seguridad agresivas           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups en: $BACKUP_DIR"

# ============================================================
log_section "1. KERNEL HARDENING EXTREMO"
# ============================================================

if check_file_exists /etc/sysctl.d/99-paranoid.conf; then
    log_already "Hardening extremo del kernel"
elif ask "¿Aplicar hardening extremo del kernel?"; then
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
net.ipv4.tcp_sack = 0
net.ipv4.tcp_rfc1337 = 1

# --- ARP hardening ---
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2

# --- Red IPv6 (deshabilitar completamente) ---
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
EOF
    log_change "Creado" "/etc/sysctl.d/99-paranoid.conf"

    /usr/sbin/sysctl --system > /dev/null 2>&1 || true
    log_change "Aplicado" "sysctl --system"
    log_info "Kernel hardening extremo aplicado"
    log_warn "ptrace_scope=2 puede afectar debuggers (gdb, strace)"
else
    log_skip "Hardening extremo del kernel"
fi

# ============================================================
log_section "2. BLACKLIST DE MÓDULOS PELIGROSOS"
# ============================================================

echo "Módulos que se pueden bloquear:"
echo "  - firewire (DMA attacks)"
echo "  - thunderbolt (DMA attacks)"
echo "  - bluetooth (si no lo usas)"
echo "  - cramfs, freevxfs, jffs2, hfs, hfsplus, udf (filesystems raros)"
echo ""

if check_file_exists /etc/modprobe.d/paranoid-blacklist.conf; then
    log_already "Módulos peligrosos bloqueados"
elif ask "¿Bloquear módulos peligrosos (NO incluye USB)?"; then
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
    log_skip "Bloqueo de modulos peligrosos"
fi

if ask "¿Bloquear Bluetooth también?"; then
    cat >> /etc/modprobe.d/paranoid-blacklist.conf << 'EOF'

# Bloquear Bluetooth
install bluetooth /bin/false
install btusb /bin/false
EOF
    log_change "Modificado" "/etc/modprobe.d/paranoid-blacklist.conf"
    systemctl stop bluetooth 2>/dev/null || true
    log_change "Servicio" "bluetooth stop"
    systemctl disable bluetooth 2>/dev/null || true
    log_change "Servicio" "bluetooth disable"
    log_info "Bluetooth bloqueado"
else
    log_skip "Bloqueo de Bluetooth"
fi

# ============================================================
log_section "3. DESHABILITAR CORE DUMPS"
# ============================================================

if check_file_exists /etc/systemd/coredump.conf.d/disable.conf; then
    log_already "Core dumps deshabilitados"
elif ask "¿Deshabilitar core dumps completamente?"; then
    # limits.conf
    cp /etc/security/limits.conf "$BACKUP_DIR/" 2>/dev/null || true
    log_change "Backup" "/etc/security/limits.conf"
    if ! grep -q "hard core 0" /etc/security/limits.conf; then
        echo "* hard core 0" >> /etc/security/limits.conf
        echo "* soft core 0" >> /etc/security/limits.conf
        log_change "Modificado" "/etc/security/limits.conf"
    fi

    # systemd
    mkdir -p /etc/systemd/coredump.conf.d/
    log_change "Creado" "/etc/systemd/coredump.conf.d/"
    cat > /etc/systemd/coredump.conf.d/disable.conf << 'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
    log_change "Creado" "/etc/systemd/coredump.conf.d/disable.conf"

    # Profile
    echo "ulimit -c 0" > /etc/profile.d/disable-coredump.sh
    log_change "Creado" "/etc/profile.d/disable-coredump.sh"

    log_info "Core dumps deshabilitados"
else
    log_skip "Deshabilitar core dumps"
fi

# ============================================================
log_section "4. TIMEOUTS DE SESIÓN"
# ============================================================

if check_file_exists /etc/profile.d/timeout.sh; then
    log_already "Timeout automático de sesiones"
elif ask "¿Configurar timeout automático de sesiones (15 min)?"; then
    cat > /etc/profile.d/timeout.sh << 'EOF'
# Auto-logout después de 15 minutos de inactividad
TMOUT=900
export TMOUT
EOF
    log_change "Creado" "/etc/profile.d/timeout.sh"

    log_info "Timeout de sesión: 15 minutos"
else
    log_skip "Timeout automatico de sesiones"
fi

# ============================================================
log_section "5. RESTRINGIR ACCESO A SU"
# ============================================================

# ── SECCIÓN ELIMINADA: Modificar /etc/pam.d/su ──
# Motivo: modificar PAM puede causar lockout del sistema.
# Para restringir 'su' al grupo wheel, configurar manualmente:
#   Descomentar 'auth required pam_wheel.so use_uid' en /etc/pam.d/su
log_warn "S5: Restringir 'su' al grupo wheel - OMITIDO (protección PAM)"
log_warn "  Para aplicar manualmente: descomentar pam_wheel.so en /etc/pam.d/su"
log_skip "Restringir su al grupo wheel (protección PAM)"

# ============================================================
log_section "6. RESTRINGIR CRON"
# ============================================================

if check_file_exists /etc/cron.allow; then
    log_already "Restricción de cron"
elif ask "¿Restringir cron solo a root y tu usuario?"; then
    echo "root" > /etc/cron.allow
    echo "${SUDO_USER:-root}" >> /etc/cron.allow
    log_change "Creado" "/etc/cron.allow"
    chmod 600 /etc/cron.allow
    log_change "Permisos" "/etc/cron.allow -> 600"
    rm -f /etc/cron.deny 2>/dev/null || true

    # at también
    echo "root" > /etc/at.allow
    echo "${SUDO_USER:-root}" >> /etc/at.allow
    log_change "Creado" "/etc/at.allow"
    chmod 600 /etc/at.allow
    log_change "Permisos" "/etc/at.allow -> 600"
    rm -f /etc/at.deny 2>/dev/null || true

    log_info "cron/at restringido a root y ${SUDO_USER:-root}"
else
    log_skip "Restringir cron/at"
fi

# ============================================================
log_section "7. BANNER DE ADVERTENCIA LEGAL"
# ============================================================

if check_file_contains /etc/issue "ACCESO NO AUTORIZADO PROHIBIDO"; then
    log_already "Banner de advertencia legal"
elif ask "¿Agregar banner de advertencia legal?"; then
    BANNER="
╔═══════════════════════════════════════════════════════════════════╗
║  SISTEMA PRIVADO - ACCESO NO AUTORIZADO PROHIBIDO                 ║
║                                                                   ║
║  Este sistema es de uso exclusivo para usuarios autorizados.      ║
║  Toda actividad es monitoreada y registrada.                      ║
║  El acceso no autorizado está prohibido y será perseguido         ║
║  conforme a la legislación aplicable.                             ║
╚═══════════════════════════════════════════════════════════════════╝
"
    echo "$BANNER" > /etc/issue
    log_change "Creado" "/etc/issue"
    echo "$BANNER" > /etc/issue.net
    log_change "Creado" "/etc/issue.net"

    # SSH banner
    echo "$BANNER" > /etc/ssh/banner
    log_change "Creado" "/etc/ssh/banner"
    if [[ -f /etc/ssh/sshd_config ]]; then
        if ! grep -q "^Banner" /etc/ssh/sshd_config; then
            echo "Banner /etc/ssh/banner" >> /etc/ssh/sshd_config
            log_change "Modificado" "/etc/ssh/sshd_config"
        fi
    fi

    log_info "Banner legal configurado"
else
    log_skip "Banner de advertencia legal"
fi

# ============================================================
log_section "8. PERMISOS RESTRICTIVOS"
# ============================================================

if check_perm /etc/shadow "600"; then
    log_already "Permisos restrictivos a archivos del sistema"
elif ask "¿Aplicar permisos restrictivos a archivos del sistema?"; then
    # Archivos de configuración críticos
    chmod 600 /etc/shadow 2>/dev/null || true
    log_change "Permisos" "/etc/shadow -> 600"
    chmod 600 /etc/gshadow 2>/dev/null || true
    log_change "Permisos" "/etc/gshadow -> 600"
    chmod 644 /etc/passwd 2>/dev/null || true
    log_change "Permisos" "/etc/passwd -> 644"
    chmod 644 /etc/group 2>/dev/null || true
    log_change "Permisos" "/etc/group -> 644"

    # Crontabs
    chmod 700 /etc/crontab 2>/dev/null || true
    log_change "Permisos" "/etc/crontab -> 700"
    chmod 700 /etc/cron.d 2>/dev/null || true
    log_change "Permisos" "/etc/cron.d -> 700"
    chmod 700 /etc/cron.daily 2>/dev/null || true
    log_change "Permisos" "/etc/cron.daily -> 700"
    chmod 700 /etc/cron.hourly 2>/dev/null || true
    log_change "Permisos" "/etc/cron.hourly -> 700"
    chmod 700 /etc/cron.weekly 2>/dev/null || true
    log_change "Permisos" "/etc/cron.weekly -> 700"
    chmod 700 /etc/cron.monthly 2>/dev/null || true
    log_change "Permisos" "/etc/cron.monthly -> 700"

    # SSH
    chmod 700 /etc/ssh 2>/dev/null || true
    log_change "Permisos" "/etc/ssh -> 700"
    chmod 600 /etc/ssh/sshd_config 2>/dev/null || true
    log_change "Permisos" "/etc/ssh/sshd_config -> 600"
    chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null || true
    log_change "Permisos" "/etc/ssh/ssh_host_*_key -> 600"

    # GRUB (si existe)
    chmod 600 "$GRUB_CFG" 2>/dev/null || true
    log_change "Permisos" "$GRUB_CFG -> 600"

    log_info "Permisos restrictivos aplicados"
else
    log_skip "Permisos restrictivos a archivos del sistema"
fi

# ============================================================
log_section "9. PROTEGER GRUB CON CONTRASEÑA"
# ============================================================

echo "Esto previene que alguien edite parámetros del kernel en boot"
if ask "¿Proteger GRUB con contraseña?"; then
    echo ""
    echo "Introduce una contraseña para GRUB:"
    grub_set_password

    log_info "GRUB protegido con contraseña"
    log_warn "Necesitarás esta contraseña para editar entradas de GRUB"
else
    log_skip "Proteger GRUB con contrasena"
fi

# ============================================================
log_section "10. INSTALAR HERRAMIENTAS DE SEGURIDAD"
# ============================================================

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
    log_skip "Instalar AIDE"
fi

if ask "¿Instalar rkhunter (detector de rootkits)?"; then
    if pkg_install rkhunter; then
        rkhunter --update 2>/dev/null || true
        rkhunter --propupd 2>/dev/null || true
        log_info "rkhunter instalado. Ejecutar: rkhunter --check"
    fi
else
    log_skip "Instalar rkhunter"
fi

if ask "¿Instalar lynis (auditor de seguridad)?"; then
    if pkg_install lynis; then
        log_info "lynis instalado. Ejecutar: lynis audit system"
    fi
else
    log_skip "Instalar lynis"
fi

# ============================================================
log_section "11. FIREWALL PARANOICO"
# ============================================================

if ask "¿Configurar firewall en modo paranoico (DROP por defecto)?"; then
    # Detectar conflicto firewalld↔nftables
    # Si nftables es el backend elegido, firewalld DEBE estar masked
    if [[ "$FW_BACKEND" == "nftables" ]]; then
        log_info "Backend: nftables directo (sin firewalld)"
        fw_fix_firewalld_conflict 2>/dev/null || true
        systemctl enable --now nftables 2>/dev/null || true
        log_change "Servicio" "nftables enable --now"
    else
        # firewalld como frontend
        # NOTA: Si luego se migra a nftables directo, ejecutar:
        #   systemctl mask firewalld && systemctl enable nftables
        systemctl enable --now firewalld 2>/dev/null || true
        log_change "Servicio" "firewalld enable --now"
    fi

    # Zona drop como default para interfaces no confiables
    fw_set_default_zone drop 2>/dev/null || true

    # Solo permitir lo esencial en la zona de trabajo
    fw_add_service dhcpv6-client work
    fw_add_service dns work

    # Bloquear ICMP excepto los necesarios
    fw_add_icmp_block echo-request 2>/dev/null || true
    fw_add_icmp_block timestamp-request 2>/dev/null || true
    fw_add_icmp_block timestamp-reply 2>/dev/null || true

    # Logging de paquetes rechazados
    fw_set_log_denied all 2>/dev/null || true

    fw_reload 2>/dev/null || true

    log_info "Firewall configurado en modo paranoico"
    log_warn "Zona por defecto: DROP (bloquea todo lo no explícito)"
    if [[ "$FW_BACKEND" == "nftables" ]]; then
        log_warn "firewalld masked para evitar conflicto al boot"
    fi
else
    log_skip "Firewall en modo paranoico"
fi

# ── Verificación de conflicto firewalld↔nftables ──
if [[ "$FW_BACKEND" == "nftables" ]]; then
    if ! fw_check_firewalld_conflict 2>/dev/null; then
        log_warn "CRITICO: firewalld puede desactivar nftables al boot"
        if ask "¿Resolver conflicto firewalld↔nftables automáticamente?"; then
            fw_fix_firewalld_conflict
            log_info "Conflicto resuelto: firewalld masked"
        fi
    fi
fi

# ============================================================
log_section "12. CUPS - RESTRINGIR"
# ============================================================

if systemctl is-active cups &>/dev/null; then
    echo "CUPS está activo (impresión)"
    if ask "¿Restringir CUPS solo a localhost?"; then
        cp /etc/cups/cupsd.conf "$BACKUP_DIR/" 2>/dev/null || true
        log_change "Backup" "/etc/cups/cupsd.conf"

        # Asegurar que solo escuche en localhost
        sed -i 's/^Listen.*/Listen localhost:631/' /etc/cups/cupsd.conf 2>/dev/null || true
        log_change "Modificado" "/etc/cups/cupsd.conf"
        sed -i 's/^Port.*/# Port 631/' /etc/cups/cupsd.conf 2>/dev/null || true
        log_change "Modificado" "/etc/cups/cupsd.conf"

        # Deshabilitar browsing
        sed -i 's/^Browsing.*/Browsing Off/' /etc/cups/cupsd.conf 2>/dev/null || true
        log_change "Modificado" "/etc/cups/cupsd.conf"

        systemctl restart cups || true
        log_change "Servicio" "cups restart"
        log_info "CUPS restringido a localhost"
    else
        log_skip "Restringir CUPS a localhost"
    fi

    if ask "¿Deshabilitar CUPS completamente (no podrás imprimir)?"; then
        for _cups_unit in cups.service cups.socket cups-browsed.service; do
            systemctl stop "$_cups_unit" 2>/dev/null || true
            systemctl disable "$_cups_unit" 2>/dev/null || true
            log_change "Servicio" "$_cups_unit stop+disable"
        done
        log_info "CUPS deshabilitado completamente (servicio + socket)"
    else
        log_skip "Deshabilitar CUPS completamente"
    fi
fi

# ── LLDP: filtra OS/kernel/hostname/MAC a la red ──
if systemctl is-active lldpd &>/dev/null; then
    log_warn "lldpd activo - transmite info del sistema (OS, kernel, MAC) a toda la red"
    if ask "¿Deshabilitar lldpd? (recomendado en estaciones de trabajo)"; then
        systemctl stop lldpd 2>/dev/null || true
        systemctl disable lldpd 2>/dev/null || true
        log_change "Servicio" "lldpd stop+disable"
        log_info "lldpd deshabilitado (ya no filtra info del sistema)"
    fi
fi

# ============================================================
log_section "12b. AISLAMIENTO LAN (TRIPLE PROTECCIÓN)"
# ============================================================

echo "Aísla tu máquina de TODOS los dispositivos de la red local."
echo "Solo permite tráfico hacia el router (DNS/DHCP) e internet."
echo ""
echo "Triple protección:"
echo "  Capa 1: Bloqueo por MAC (inmutable, no se puede evadir)"
echo "  Capa 2: Bloqueo por IP (defensa en profundidad)"
echo "  Capa 3: Bloqueo de subred completa (atrapa dispositivos nuevos)"
echo ""

if [[ "$FW_BACKEND" == "nftables" ]]; then
    if nft list ruleset 2>/dev/null | grep -q "bloqueo-LAN-completo"; then
        log_already "Aislamiento LAN activo (triple proteccion)"
    elif ask "¿Aislar de TODOS los dispositivos LAN (triple proteccion)?"; then
        # Auto-detectar gateway, interfaz y subred
        local_iface=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
        local_gw=$(ip route | grep default | awk '{print $3}' | head -1)
        local_iface="${local_iface:-$(ls /sys/class/net/ 2>/dev/null | grep -v lo | head -1)}"
        local_ip_cidr=$(ip -o -4 addr show "$local_iface" 2>/dev/null | awk '{print $4}' | head -1)
        local_ip="${local_ip_cidr%/*}"
        local_subnet_cidr="${local_ip%.*}.0/24"

        if [[ -z "$local_gw" ]]; then
            log_error "No se pudo detectar el gateway. Verifica la conexion de red."
            log_skip "Aislamiento LAN"
        else
            echo ""
            echo "  Interfaz: ${local_iface:-desconocida}"
            echo "  IP local: ${local_ip:-desconocida}"
            echo "  Gateway:  $local_gw"
            echo "  Subred:   $local_subnet_cidr"
            echo ""

            # Descubrir dispositivos en la LAN via tabla ARP
            echo "Dispositivos en tabla ARP (se bloquearan por MAC e IP):"
            _dev_count=0
            while IFS=' ' read -r _d_ip _d_type _d_mac _rest; do
                # Saltar gateway, nuestra IP, e incompletos
                [[ "$_d_ip" == "$local_gw" ]] && continue
                [[ "$_d_ip" == "$local_ip" ]] && continue
                [[ "$_d_mac" == "(incomplete)" || -z "$_d_mac" ]] && continue
                echo "  $_d_ip ($_d_mac)"

                # Capa 1: Bloqueo por MAC (INPUT + OUTPUT)
                nft insert rule inet filter input ether saddr "$_d_mac" drop comment "MAC-block-${_d_ip}" 2>/dev/null || true
                nft insert rule inet filter output ether daddr "$_d_mac" drop comment "MAC-block-out-${_d_ip}" 2>/dev/null || true

                # Capa 2: Bloqueo por IP (INPUT + OUTPUT)
                nft insert rule inet filter input ip saddr "$_d_ip" drop comment "IP-block-${_d_ip}" 2>/dev/null || true
                nft insert rule inet filter output ip daddr "$_d_ip" drop comment "IP-block-out-${_d_ip}" 2>/dev/null || true

                ((_dev_count++)) || true
            done < <(arp -n 2>/dev/null | tail -n +2)
            echo ""
            log_change "nftables" "Capa 1+2: $_dev_count dispositivos bloqueados por MAC+IP"

            # Capa 3: Bloqueo de subred completa (atrapa nuevos dispositivos)
            nft add rule inet filter input ip saddr "$local_gw" accept comment "router-permitido" 2>/dev/null || true
            nft add rule inet filter input ip saddr "$local_subnet_cidr" drop comment "bloqueo-LAN-completo" 2>/dev/null || true
            log_change "nftables" "Capa 3 INPUT: LAN $local_subnet_cidr bloqueada, solo router $local_gw permitido"

            nft add rule inet filter output ip daddr "$local_gw" tcp dport 53 accept comment "router-DNS-tcp" 2>/dev/null || true
            nft add rule inet filter output ip daddr "$local_gw" udp dport 53 accept comment "router-DNS-udp" 2>/dev/null || true
            nft add rule inet filter output ip daddr "$local_gw" udp dport 67 accept comment "router-DHCP" 2>/dev/null || true
            nft add rule inet filter output ip daddr "$local_subnet_cidr" drop comment "bloqueo-LAN-salida" 2>/dev/null || true
            log_change "nftables" "Capa 3 OUTPUT: LAN bloqueada, solo router DNS/DHCP"

            # Bloquear multicast/broadcast
            nft add rule inet filter output ip daddr 224.0.0.0/4 drop comment "multicast" 2>/dev/null || true
            nft add rule inet filter output ip daddr 255.255.255.255 drop comment "broadcast" 2>/dev/null || true
            log_change "nftables" "OUTPUT: multicast/broadcast bloqueado"

            # Persistir reglas (openSUSE y Debian paths)
            nft list ruleset > /etc/nftables/rules/main.nft 2>/dev/null \
                || nft list ruleset > /etc/nftables.conf 2>/dev/null || true
            log_change "nftables" "Reglas persistidas"

            _total_rules=$(nft list ruleset 2>/dev/null | grep -c "drop\|reject" || echo "?")
            log_info "Triple aislamiento LAN activo ($_total_rules reglas)"
            log_info "  Capa 1: $_dev_count dispositivos bloqueados por MAC"
            log_info "  Capa 2: $_dev_count dispositivos bloqueados por IP"
            log_info "  Capa 3: Subred $local_subnet_cidr completa bloqueada"
            log_info "  Permitido: router ($local_gw) DNS/DHCP + internet"
        fi
    else
        log_skip "Aislamiento LAN"
    fi
else
    log_info "Aislamiento LAN requiere backend nftables (actual: $FW_BACKEND)"
fi

# ============================================================
log_section "13. UMASK RESTRICTIVO"
# ============================================================

if check_file_contains /etc/login.defs "UMASK 027"; then
    log_already "Umask restrictivo (027)"
elif ask "¿Configurar umask restrictivo (027)?"; then
    # /etc/profile
    if ! grep -q "umask 027" /etc/profile; then
        echo "umask 027" >> /etc/profile
        log_change "Modificado" "/etc/profile"
    fi

    # /etc/bashrc
    if [[ -f /etc/bashrc ]] && ! grep -q "umask 027" /etc/bashrc; then
        echo "umask 027" >> /etc/bashrc
        log_change "Modificado" "/etc/bashrc"
    fi

    # login.defs
    sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs 2>/dev/null || true
    log_change "Modificado" "/etc/login.defs"

    log_info "umask configurado a 027 (archivos: 640, directorios: 750)"
else
    log_skip "Umask restrictivo"
fi

# ============================================================
log_section "14. DESHABILITAR USB STORAGE (OPCIONAL)"
# ============================================================

log_warn "CUIDADO: Esto impedirá usar memorias USB"
if ask "¿Bloquear almacenamiento USB (memorias, discos externos)?"; then
    echo "install usb-storage /bin/false" >> /etc/modprobe.d/paranoid-blacklist.conf
    log_change "Modificado" "/etc/modprobe.d/paranoid-blacklist.conf"
    rmmod usb_storage 2>/dev/null || true
    log_info "USB storage bloqueado"
else
    log_skip "Bloquear almacenamiento USB"
fi

# ============================================================
log_section "15. AUDITORÍA AVANZADA"
# ============================================================

if systemctl is-active auditd &>/dev/null; then
    if check_file_exists /etc/audit/rules.d/99-paranoid.rules; then
        log_already "Reglas de auditoría paranoicas"
    elif ask "¿Configurar reglas de auditoría paranoicas?"; then
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
        log_change "Aplicado" "augenrules --load"
        log_info "Auditoría paranoica configurada"
        log_warn "Reglas inmutables: requiere reboot para modificar"
    else
        log_skip "Reglas de auditoria paranoicas"
    fi
fi

# ============================================================
log_section "16. FAIL2BAN AGRESIVO"
# ============================================================

if command -v fail2ban-client &>/dev/null; then
    if check_file_contains /etc/fail2ban/jail.local "bantime = 48h"; then
        log_already "Fail2ban en modo agresivo"
    elif ask "¿Configurar fail2ban en modo agresivo?"; then
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
        log_change "Servicio" "fail2ban restart"
        log_info "fail2ban configurado en modo agresivo"
        log_info "  - Ban general: 24h, SSH: 48h, DDoS: 72h"
    else
        log_skip "Configurar fail2ban agresivo"
    fi
else
    log_warn "fail2ban no instalado. Instálalo primero."
fi

# ============================================================
log_section "17. HARDENING POR INTERFAZ (IPv6 + rp_filter)"
# ============================================================

if check_file_exists /etc/sysctl.d/99-paranoid-interfaces.conf; then
    log_already "Hardening per-interface (IPv6 disable + rp_filter strict)"
elif ask "¿Deshabilitar IPv6 y forzar rp_filter strict en todas las interfaces?"; then
    _iface_conf="/etc/sysctl.d/99-paranoid-interfaces.conf"
    cat > "$_iface_conf" << 'EOFHDR'
# Per-interface hardening: IPv6 disable + rp_filter strict
# Generado por hardening-paranoico.sh
# IPv6 link-local permite RA spoofing / NDP attacks
# rp_filter loose permite IP spoofing
EOFHDR
    for _iface in $(ls /sys/class/net/ 2>/dev/null | grep -v lo); do
        cat >> "$_iface_conf" << EOF
net.ipv6.conf.${_iface}.disable_ipv6 = 1
net.ipv4.conf.${_iface}.rp_filter = 2
EOF
    done
    chmod 600 "$_iface_conf"
    /usr/sbin/sysctl --system > /dev/null 2>&1 || true
    log_change "Creado" "$_iface_conf"
    log_info "IPv6 deshabilitado y rp_filter strict en todas las interfaces"
else
    log_skip "Hardening per-interface"
fi

# ============================================================
log_section "18. FAILLOCK - PROTECCION CONTRA FUERZA BRUTA"
# ============================================================

echo "Bloquea cuentas tras intentos fallidos de login local."
echo "  - 5 intentos fallidos -> bloqueo 15 minutos"
echo ""

if grep -rq "pam_faillock" /etc/pam.d/ 2>/dev/null; then
    log_already "Faillock configurado en PAM"
elif ask "¿Configurar faillock contra fuerza bruta en login local?"; then
    cat > /etc/security/faillock.conf << 'EOF'
# Faillock - proteccion contra fuerza bruta
deny = 5
unlock_time = 900
fail_interval = 900
even_deny_root
root_unlock_time = 900
EOF
    log_change "Creado" "/etc/security/faillock.conf"
    # Insertar en PAM auth (antes de pam_unix)
    for _pam_file in /etc/pam.d/common-auth /etc/pam.d/system-auth; do
        if [[ -f "$_pam_file" ]] && ! grep -q "pam_faillock" "$_pam_file"; then
            cp "$_pam_file" "$BACKUP_DIR/" 2>/dev/null || true
            sed -i '/pam_unix.so/i auth    required    pam_faillock.so preauth' "$_pam_file"
            sed -i '/pam_unix.so/a auth    [default=die] pam_faillock.so authfail' "$_pam_file"
            log_change "Modificado" "$_pam_file (faillock)"
        fi
    done
    for _pam_file in /etc/pam.d/common-account /etc/pam.d/system-account; do
        if [[ -f "$_pam_file" ]] && ! grep -q "pam_faillock" "$_pam_file"; then
            echo "account required pam_faillock.so" >> "$_pam_file"
            log_change "Modificado" "$_pam_file (faillock account)"
        fi
    done
    log_info "Faillock: 5 intentos -> bloqueo 15min (incluye root)"
else
    log_skip "Faillock proteccion fuerza bruta"
fi

# ============================================================
log_section "19. LIMITAR USER NAMESPACES"
# ============================================================

echo "User namespaces permiten escalada de privilegios"
echo "(CVE-2022-0185, CVE-2023-2163, CVE-2024-1086)."
echo "Reducir max_user_namespaces limita este vector de ataque."
echo ""

_current_userns=$(cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo "0")
if [[ "$_current_userns" -le 256 ]]; then
    log_already "User namespaces limitados ($_current_userns)"
elif ask "¿Limitar user namespaces a 0? (puede afectar Flatpak/containers)"; then
    echo "user.max_user_namespaces = 0" > /etc/sysctl.d/99-userns-limit.conf
    chmod 600 /etc/sysctl.d/99-userns-limit.conf
    /usr/sbin/sysctl -w user.max_user_namespaces=0 > /dev/null 2>&1 || true
    log_change "Creado" "/etc/sysctl.d/99-userns-limit.conf"
    log_info "User namespaces limitados a 0 (proteccion contra escalada)"
    log_warn "Si usas Flatpak/Podman, cambia a 256 en vez de 0"
else
    log_skip "Limitar user namespaces"
fi

# ============================================================
log_section "20. CRYPTO POLICY FUTURE"
# ============================================================

echo "La política FUTURE fuerza:"
echo "  - TLS mínimo 1.3 (DEFAULT permite 1.2)"
echo "  - RSA mínimo 3072 bits"
echo "  - SHA-1 deshabilitado completamente"
echo ""

if command -v update-crypto-policies &>/dev/null; then
    _current_policy=$(update-crypto-policies --show 2>/dev/null || echo "UNKNOWN")
    if [[ "$_current_policy" == "FUTURE" ]]; then
        log_already "Crypto policy FUTURE"
    elif ask "¿Aplicar política criptográfica FUTURE (TLS 1.3 mínimo)?"; then
        update-crypto-policies --set FUTURE 2>/dev/null
        log_change "Aplicado" "crypto-policies FUTURE"
        log_info "Política FUTURE activa. TLS 1.3+ obligatorio."
        log_warn "Algunos sitios antiguos (solo TLS 1.2) pueden fallar"
        log_warn "Revertir: update-crypto-policies --set DEFAULT"
    else
        log_skip "Crypto policy FUTURE"
    fi
else
    log_info "update-crypto-policies no disponible en esta distro"
fi

# ============================================================
log_section "21. DESHABILITAR SERVICIOS DE TRACKING"
# ============================================================

echo "Servicios que filtran información innecesariamente:"
echo "  - OBEX (Bluetooth file transfer en user-space)"
echo "  - Geoclue (geolocalización WiFi/IP)"
echo "  - Captive portal checks (revelan actividad al ISP)"
echo ""

if ask "¿Deshabilitar OBEX, Geoclue y captive portal checks?"; then
    # OBEX: Mask en user-space para todos los usuarios
    for _user_home in /home/*; do
        _user=$(basename "$_user_home")
        _uid=$(id -u "$_user" 2>/dev/null || continue)
        if [[ -d "/run/user/$_uid" ]]; then
            su - "$_user" -c "XDG_RUNTIME_DIR=/run/user/$_uid systemctl --user mask obex.service" 2>/dev/null || true
            su - "$_user" -c "XDG_RUNTIME_DIR=/run/user/$_uid systemctl --user stop obex.service" 2>/dev/null || true
        fi
    done
    killall obexd 2>/dev/null || true
    log_change "Servicio" "obex.service masked (user-space)"

    # Geoclue: Deshabilitar autostart
    if [[ -f /etc/xdg/autostart/geoclue-demo-agent.desktop ]]; then
        if ! grep -q "Hidden=true" /etc/xdg/autostart/geoclue-demo-agent.desktop; then
            echo "Hidden=true" >> /etc/xdg/autostart/geoclue-demo-agent.desktop
        fi
    fi
    killall -f "geoclue-2.0/demos/agent" 2>/dev/null || true
    log_change "Servicio" "geoclue-demo-agent deshabilitado"

    # Captive portal: NetworkManager
    mkdir -p /etc/NetworkManager/conf.d
    cat > /etc/NetworkManager/conf.d/99-no-captive-portal.conf << 'EOF'
[connectivity]
enabled=false
EOF
    log_change "Creado" "/etc/NetworkManager/conf.d/99-no-captive-portal.conf"

    log_info "OBEX, Geoclue y captive portal deshabilitados"
    log_info "Para Firefox captive portal: about:config -> network.captive-portal-service.enabled = false"
else
    log_skip "Deshabilitar servicios de tracking"
fi

# ============================================================
log_section "22. HARDENING DE MOUNT OPTIONS"
# ============================================================

echo "Añade restricciones a /home y /boot/efi:"
echo "  /home:     nosuid,nodev (previene SUID/device files)"
echo "  /boot/efi: nosuid,nodev,noexec (solo firmware)"
echo ""

_fstab_modified=0
if grep -q "nosuid" /etc/fstab 2>/dev/null && grep -q "/home.*nosuid" /etc/fstab 2>/dev/null; then
    log_already "Mount options endurecidos en fstab"
elif ask "¿Endurecer mount options en fstab (/home, /boot/efi)?"; then
    cp /etc/fstab "$BACKUP_DIR/" 2>/dev/null || true
    log_change "Backup" "/etc/fstab"

    # /home: añadir nosuid,nodev
    if grep -q "/home.*btrfs" /etc/fstab && ! grep -q "/home.*nosuid" /etc/fstab; then
        sed -i '/\/home.*btrfs/ s/subvol=\(.*\)/subvol=\1,nosuid,nodev/' /etc/fstab
        _fstab_modified=1
        log_change "Modificado" "/etc/fstab (/home +nosuid,nodev)"
    fi

    # /boot/efi: añadir nosuid,nodev,noexec
    if grep -q "/boot/efi" /etc/fstab && ! grep -q "/boot/efi.*nosuid" /etc/fstab; then
        sed -i '/\/boot\/efi/ s/utf8/utf8,nosuid,nodev,noexec/' /etc/fstab
        _fstab_modified=1
        log_change "Modificado" "/etc/fstab (/boot/efi +nosuid,nodev,noexec)"
    fi

    if [[ $_fstab_modified -eq 1 ]]; then
        log_info "Mount options endurecidos. Aplicar con: mount -o remount /home"
        log_warn "Cambios se aplican completamente tras reboot"
    else
        log_info "fstab no requiere cambios (layout no estándar o ya endurecido)"
    fi
else
    log_skip "Hardening de mount options"
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
show_changes_summary
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║          HARDENING PARANOICO COMPLETADO                   ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups guardados en: $BACKUP_DIR"
echo ""
echo "Comandos útiles post-hardening:"
echo "  - Verificar integridad:  aide --check"
echo "  - Buscar rootkits:       rkhunter --check"
echo "  - Auditoría completa:    lynis audit system"
echo "  - Ver logs de audit:     ausearch -k identity"
echo "  - Ver bans de fail2ban:  fail2ban-client status sshd"
echo ""
log_warn "RECOMENDACIÓN: Reinicia el sistema para aplicar todos los cambios"
echo ""
