#!/bin/bash
# ============================================================
# HARDENING EXTREMO - MÁXIMA SEGURIDAD
# ============================================================


set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
log_info "1. Deshabilitando servicios de red..."

SERVICES="sshd cups avahi-daemon bluetooth ModemManager"
for svc in $SERVICES; do
    if systemctl is-active "$svc" &>/dev/null; then
        systemctl stop "$svc" 2>/dev/null || true
        systemctl disable "$svc" 2>/dev/null || true
        systemctl mask "$svc" 2>/dev/null || true
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

# ============================================================
# 4. KERNEL PARANOID MODE
# ============================================================
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

/usr/sbin/sysctl --system > /dev/null 2>&1
log_info "   Kernel en modo paranoico máximo"

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
        # Añadir dispositivos actuales como permitidos
        usbguard generate-policy >> /etc/usbguard/rules.conf 2>/dev/null || true

        systemctl enable --now usbguard 2>/dev/null || true
        log_info "   USBGuard activo - USB nuevos bloqueados"
    fi

    # Bloquear almacenamiento USB
    echo "install usb-storage /bin/false" >> /etc/modprobe.d/network-hardening.conf
    rmmod usb_storage 2>/dev/null || true
fi

# ============================================================
# 6. DESHABILITAR USUARIOS INNECESARIOS
# ============================================================
log_info "6. Bloqueando shells de usuarios del sistema..."

# Bloquear shell de usuarios del sistema
for user in daemon bin sys sync games man lp mail news uucp proxy www-data backup list irc gnats nobody; do
    usermod -s /usr/sbin/nologin "$user" 2>/dev/null || true
done

# ============================================================
# 7. PERMISOS ULTRA-RESTRICTIVOS
# ============================================================
log_info "7. Aplicando permisos ultra-restrictivos..."

# Binarios SUID - solo los esenciales
chmod u-s /usr/bin/wall 2>/dev/null || true
chmod u-s /usr/bin/write 2>/dev/null || true
chmod u-s /usr/bin/chage 2>/dev/null || true
chmod u-s /usr/bin/chfn 2>/dev/null || true
chmod u-s /usr/bin/chsh 2>/dev/null || true

# Archivos críticos
chmod 600 /etc/shadow
chmod 600 /etc/gshadow
chmod 600 /etc/ssh/sshd_config 2>/dev/null || true
chmod 700 /root
chmod 700 /boot

# ============================================================
# 8. MONITOREO EN TIEMPO REAL
# ============================================================
log_info "8. Configurando monitoreo en tiempo real..."

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
chmod +x /usr/local/bin/security-monitor.sh

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

systemctl daemon-reload
systemctl enable --now security-monitor.service 2>/dev/null || true
log_info "   Monitor de seguridad activo"

# ============================================================
# 9. ALARMA DE INTRUSIÓN
# ============================================================
log_info "9. Configurando alarma de intrusión..."

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
chmod +x /usr/local/bin/intrusion-alarm.sh

# ============================================================
# 10. INMUTABILIDAD DE ARCHIVOS CRÍTICOS
# ============================================================
if ask "¿Hacer inmutables los archivos críticos? (requiere chattr -i para modificar)"; then
    log_info "10. Haciendo archivos críticos inmutables..."

    chattr +i /etc/passwd 2>/dev/null || true
    chattr +i /etc/shadow 2>/dev/null || true
    chattr +i /etc/group 2>/dev/null || true
    chattr +i /etc/gshadow 2>/dev/null || true
    chattr +i /etc/sudoers 2>/dev/null || true

    log_warn "   Archivos inmutables. Para modificar: chattr -i <archivo>"
fi

# ============================================================
# RESUMEN
# ============================================================
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
