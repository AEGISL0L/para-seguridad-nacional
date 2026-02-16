#!/bin/bash
# ============================================================
# HARDENING EXTREMO - MÁXIMA SEGURIDAD
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps

# ── Pre-check: salida temprana si todo aplicado ──
_precheck 10
_pc true  # S1: deshabilitar servicios de red (depende de estado runtime)
_pc true  # S2: firewall ultra-restrictivo (depende de estado runtime)
_pc check_file_exists /etc/modprobe.d/network-hardening.conf
_pc check_file_exists /etc/sysctl.d/99-paranoid-max.conf
_pc true  # S5: bloquear USB (opcional con ask)
_pc true  # S6: deshabilitar usuarios (siempre re-evaluar)
_pc check_perm /etc/shadow "600"
_pc check_executable /usr/local/bin/security-monitor.sh
_pc check_executable /usr/local/bin/intrusion-alarm.sh
_pc true  # S10: inmutabilidad archivos (opcional con ask)
_precheck_result

log_info "1. Deshabilitando servicios de red..."

SERVICES="sshd cups cups.socket cups-browsed lldpd avahi-daemon bluetooth ModemManager"
for svc in $SERVICES; do
    if systemctl is-active "$svc" &>/dev/null; then
        systemctl stop "$svc" 2>/dev/null || true
        log_change "Servicio" "$svc stop"
        systemctl disable "$svc" 2>/dev/null || true
        log_change "Servicio" "$svc disable"
        systemctl mask "$svc" 2>/dev/null || true
        log_change "Servicio" "$svc mask"
        log_info "   $svc deshabilitado y enmascarado"
    fi
done

# ============================================================
# 2. FIREWALL ULTRA-RESTRICTIVO
# ============================================================
log_info "2. Configurando firewall ultra-restrictivo..."

# Zona drop por defecto
fw_set_default_zone drop 2>/dev/null || true

# Solo permitir tráfico saliente esencial
fw_add_rich_rule 'rule family="ipv4" destination address="1.1.1.1" port port="53" protocol="udp" accept' drop
fw_add_rich_rule 'rule family="ipv4" destination address="9.9.9.9" port port="53" protocol="udp" accept' drop

# Permitir HTTPS saliente (navegación)
fw_add_rich_rule 'rule family="ipv4" destination NOT address="192.168.0.0/16" port port="443" protocol="tcp" accept' drop
fw_add_rich_rule 'rule family="ipv4" destination NOT address="10.0.0.0/8" port port="443" protocol="tcp" accept' drop

# DHCP para red local
fw_add_service dhcpv6-client drop

# Logging máximo
fw_set_log_denied all 2>/dev/null || true

fw_reload 2>/dev/null || true
log_info "   Firewall: DROP por defecto, solo DNS y HTTPS permitidos"

# ============================================================
# 3. BLOQUEAR TODOS LOS MÓDULOS DE RED INNECESARIOS
# ============================================================
log_info "3. Bloqueando módulos de red innecesarios..."

if check_file_exists /etc/modprobe.d/network-hardening.conf; then
    log_already "Módulos de red innecesarios bloqueados"
else
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
fi

# ============================================================
# 4. KERNEL PARANOID MODE
# ============================================================
log_info "4. Activando modo paranoico del kernel..."

if check_file_exists /etc/sysctl.d/99-paranoid-max.conf; then
    log_already "Modo paranoico del kernel"
else
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
fi

# ============================================================
# 5. BLOQUEAR USB POR DEFECTO
# ============================================================
if ask "¿Bloquear TODOS los dispositivos USB nuevos?"; then
    log_info "5. Bloqueando USB..."

    # USBGuard
    if ! command -v usbguard &>/dev/null; then
        pkg_install usbguard
    fi

    if command -v usbguard &>/dev/null; then
        # Política: bloquear todo por defecto
        cat > /etc/usbguard/rules.conf << 'EOF'
# Bloquear TODOS los dispositivos USB por defecto
# Solo los dispositivos listados explícitamente serán permitidos
EOF
        log_change "Creado" "/etc/usbguard/rules.conf"
        # Añadir dispositivos actuales como permitidos
        usbguard generate-policy >> /etc/usbguard/rules.conf 2>/dev/null || true

        systemctl enable --now usbguard 2>/dev/null || true
        log_change "Servicio" "usbguard enable --now"
        log_info "   USBGuard activo - USB nuevos bloqueados"
    fi

    # Bloquear almacenamiento USB
    echo "install usb-storage /bin/false" >> /etc/modprobe.d/network-hardening.conf
    log_change "Modificado" "/etc/modprobe.d/network-hardening.conf"
    rmmod usb_storage 2>/dev/null || true
else
    log_skip "Bloqueo de dispositivos USB"
fi

# ============================================================
# 6. DESHABILITAR USUARIOS INNECESARIOS
# ============================================================
log_info "6. Bloqueando shells de usuarios del sistema..."

# Bloquear shell de usuarios del sistema
for user in daemon bin sys sync games man lp mail news uucp proxy www-data backup list irc gnats nobody; do
    usermod -s /usr/sbin/nologin "$user" 2>/dev/null || true
    log_change "Usuario" "$user shell -> /usr/sbin/nologin"
done

# ============================================================
# 7. PERMISOS ULTRA-RESTRICTIVOS
# ============================================================
log_info "7. Aplicando permisos ultra-restrictivos..."

if check_perm /etc/shadow "600"; then
    log_already "Permisos ultra-restrictivos"
else
# Binarios SUID - solo los esenciales
chmod u-s /usr/bin/wall 2>/dev/null || true
log_change "Permisos" "/usr/bin/wall -> u-s"
chmod u-s /usr/bin/write 2>/dev/null || true
log_change "Permisos" "/usr/bin/write -> u-s"
chmod u-s /usr/bin/chage 2>/dev/null || true
log_change "Permisos" "/usr/bin/chage -> u-s"
chmod u-s /usr/bin/chfn 2>/dev/null || true
log_change "Permisos" "/usr/bin/chfn -> u-s"
chmod u-s /usr/bin/chsh 2>/dev/null || true
log_change "Permisos" "/usr/bin/chsh -> u-s"

# Archivos críticos
chmod 600 /etc/shadow
log_change "Permisos" "/etc/shadow -> 600"
chmod 600 /etc/gshadow
log_change "Permisos" "/etc/gshadow -> 600"
chmod 600 /etc/ssh/sshd_config 2>/dev/null || true
log_change "Permisos" "/etc/ssh/sshd_config -> 600"
chmod 700 /root
log_change "Permisos" "/root -> 700"
chmod 700 /boot
log_change "Permisos" "/boot -> 700"
fi

# ============================================================
# 8. MONITOREO EN TIEMPO REAL
# ============================================================
log_info "8. Configurando monitoreo en tiempo real..."

if check_executable /usr/local/bin/security-monitor.sh; then
    log_already "Monitoreo en tiempo real"
else
# Script de monitoreo
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
log_change "Creado" "/usr/local/bin/security-monitor.sh"
chmod +x /usr/local/bin/security-monitor.sh
log_change "Permisos" "/usr/local/bin/security-monitor.sh -> +x"

# Servicio systemd
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
log_change "Aplicado" "systemctl daemon-reload"
systemctl enable --now security-monitor.service 2>/dev/null || true
log_change "Servicio" "security-monitor enable --now"
log_info "   Monitor de seguridad activo"
fi

# ============================================================
# 9. ALARMA DE INTRUSIÓN
# ============================================================
log_info "9. Configurando alarma de intrusión..."

if check_executable /usr/local/bin/intrusion-alarm.sh; then
    log_already "Alarma de intrusión"
else
cat > /usr/local/bin/intrusion-alarm.sh << 'EOFALARM'
#!/bin/bash
# Alarma de intrusión - ejecutar cuando se detecte acceso no autorizado

# Sonido de alarma (requiere speaker)
for i in {1..5}; do
    echo -e '\a'
    sleep 0.5
done

# Notificación en todas las terminales
wall "
╔═══════════════════════════════════════════════════════════════╗
║  ⚠️⚠️⚠️  ALERTA DE INTRUSIÓN DETECTADA  ⚠️⚠️⚠️                    ║
║                                                               ║
║  Se ha detectado actividad sospechosa en el sistema.          ║
║  Verificar inmediatamente.                                    ║
║                                                               ║
║  $(date)                                        ║
╚═══════════════════════════════════════════════════════════════╝
"

# Log
echo "[$(date)] INTRUSIÓN DETECTADA" >> /var/log/intrusion.log
EOFALARM
log_change "Creado" "/usr/local/bin/intrusion-alarm.sh"
chmod +x /usr/local/bin/intrusion-alarm.sh
log_change "Permisos" "/usr/local/bin/intrusion-alarm.sh -> +x"
fi

# ============================================================
# 10. INMUTABILIDAD DE ARCHIVOS CRÍTICOS
# ============================================================
# ── SECCIÓN ELIMINADA: chattr +i en passwd/shadow/sudoers ──
# Motivo: hacer inmutables estos archivos causa lockout del sistema
# (useradd, passwd, visudo, etc. dejan de funcionar).
# Para aplicar manualmente: chattr +i /etc/passwd /etc/shadow /etc/sudoers
log_warn "S10: Inmutabilidad de archivos críticos - OMITIDO (riesgo de lockout)"
log_warn "  Para aplicar manualmente: chattr +i /etc/passwd /etc/shadow /etc/sudoers"
log_skip "Archivos criticos inmutables (protección lockout)"

# ============================================================
# RESUMEN
# ============================================================
show_changes_summary
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║         HARDENING EXTREMO COMPLETADO                      ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "Estado:"
echo "  ✓ Servicios de red deshabilitados"
echo "  ✓ Firewall DROP (solo DNS/HTTPS saliente)"
echo "  ✓ Módulos de red peligrosos bloqueados"
echo "  ✓ Kernel en modo paranoico máximo"
echo "  ✓ IPv6 deshabilitado"
echo "  ✓ ICMP bloqueado completamente"
echo "  ✓ Monitor de seguridad activo"
echo "  ✓ Alarma de intrusión configurada"
echo ""
echo "Comandos útiles:"
echo "  Ver monitor: journalctl -fu security-monitor"
echo "  Ver alertas: tail -f /var/log/security-monitor.log"
echo "  Alarma manual: /usr/local/bin/intrusion-alarm.sh"
