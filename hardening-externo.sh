#!/bin/bash
# ============================================================
# HARDENING CONTRA VECTORES DE ATAQUE EXTERNOS
# Linux Multi-Distro (openSUSE, Debian/Ubuntu, RHEL/Fedora, Arch)
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "hardening-externo"
securizar_setup_traps
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   HARDENING CONTRA VECTORES DE ATAQUE EXTERNOS            ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# ============================================================
log_section "1. BANNER DE ADVERTENCIA DISUASIVO"
# ============================================================

BANNER='
    ══════════════════════════════════════════════════════════════════
    ██╗    ██╗ █████╗ ██████╗ ███╗   ██╗██╗███╗   ██╗ ██████╗
    ██║    ██║██╔══██╗██╔══██╗████╗  ██║██║████╗  ██║██╔════╝
    ██║ █╗ ██║███████║██████╔╝██╔██╗ ██║██║██╔██╗ ██║██║  ███╗
    ██║███╗██║██╔══██║██╔══██╗██║╚██╗██║██║██║╚██╗██║██║   ██║
    ╚███╔███╔╝██║  ██║██║  ██║██║ ╚████║██║██║ ╚████║╚██████╔╝
     ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝
    ══════════════════════════════════════════════════════════════════

    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
    ▓                                                                ▓
    ▓   SISTEMA PRIVADO DE ALTA SEGURIDAD                            ▓
    ▓   ACCESO ESTRICTAMENTE RESTRINGIDO                             ▓
    ▓                                                                ▓
    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓

    ADVERTENCIA LEGAL:

    Este sistema informático es propiedad PRIVADA y está protegido
    por la legislación vigente en materia de delitos informáticos.

    ● El acceso NO AUTORIZADO está PROHIBIDO
    ● Todas las conexiones son MONITOREADAS y REGISTRADAS
    ● Las direcciones IP son capturadas y almacenadas
    ● Se tomarán acciones legales contra intrusos

    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    NOTIFICACIÓN ESPECÍFICA:

    ██  SEQUOIA: ACCESO PERMANENTEMENTE DENEGADO  ██

    Cualquier intento de acceso por parte de "Sequoia" o entidades
    asociadas será considerado como intrusión maliciosa y se
    procederá con denuncia inmediata ante las autoridades competentes.

    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    Si has llegado aquí por error, DESCONÉCTATE INMEDIATAMENTE.

    Código Penal - Delitos Informáticos:
    Art. 197 bis, 264, 264 bis CP (España)
    Ley Orgánica de Protección de Datos (LOPD/RGPD)

    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓

'

echo "Banner de advertencia actualizado:"
echo "$BANNER" | head -20
echo "..."
echo ""

if ask "¿Aplicar este banner disuasivo?"; then
    echo "$BANNER" > /etc/issue
    echo "$BANNER" > /etc/issue.net
    echo "$BANNER" > /etc/motd

    # SSH banner
    mkdir -p /etc/ssh
    echo "$BANNER" > /etc/ssh/banner

    if [[ -f /etc/ssh/sshd_config ]]; then
        if ! grep -q "^Banner /etc/ssh/banner" /etc/ssh/sshd_config; then
            echo "Banner /etc/ssh/banner" >> /etc/ssh/sshd_config
        fi
        systemctl reload "$SSH_SERVICE_NAME" 2>/dev/null || true
    fi

    log_info "Banner disuasivo aplicado en /etc/issue, /etc/issue.net, /etc/motd, SSH"
fi

# ============================================================
log_section "2. DNS SEGURO (DoT/DoH)"
# ============================================================

echo "DNS actual:"
cat /etc/resolv.conf | grep nameserver
echo ""
echo "Opciones de DNS seguro:"
echo "  1. Cloudflare (1.1.1.1) - Rápido, privado"
echo "  2. Quad9 (9.9.9.9) - Bloquea malware"
echo "  3. Google (8.8.8.8) - Confiable"
echo ""

if ask "¿Configurar DNS seguros (Cloudflare + Quad9)?"; then
    # Configurar en NetworkManager para que persista
    CONN_NAME=$(nmcli -t -f NAME con show --active | head -1)
    if [[ -n "$CONN_NAME" ]]; then
        nmcli con mod "$CONN_NAME" ipv4.dns "1.1.1.1 9.9.9.9"
        nmcli con mod "$CONN_NAME" ipv4.ignore-auto-dns yes
        nmcli con down "$CONN_NAME" && nmcli con up "$CONN_NAME"
        log_info "DNS configurado: 1.1.1.1 (Cloudflare) + 9.9.9.9 (Quad9)"
    else
        log_warn "No se pudo detectar conexión activa, configura DNS manualmente"
    fi
fi

# ============================================================
log_section "3. FIREWALL - BLOQUEO GEOGRÁFICO Y LISTAS NEGRAS"
# ============================================================

if fw_is_active &>/dev/null; then
    log_info "Firewalld activo"

    if ask "¿Configurar firewall en modo estricto (DROP por defecto)?"; then
        # Zona drop como default
        fw_set_default_zone drop 2>/dev/null || true

        # Crear zona personalizada para trabajo
        fw_new_zone trusted-work 2>/dev/null || true
        fw_add_service dhcpv6-client trusted-work

        # Logging de intentos bloqueados (comando separado, no usa --permanent)
        fw_set_log_denied all 2>/dev/null || true

        fw_reload 2>/dev/null || true
        log_info "Firewall: zona por defecto DROP, logging habilitado"
    fi

    if ask "¿Bloquear rangos de IP sospechosos y escaneos?"; then
        # Bloquear direcciones inválidas/reservadas
        fw_add_rich_rule 'rule family="ipv4" source address="0.0.0.0/8" log prefix="INVALID-SRC " drop' drop
        fw_add_rich_rule 'rule family="ipv4" source address="224.0.0.0/4" log prefix="MULTICAST " drop' drop
        fw_add_rich_rule 'rule family="ipv4" source address="240.0.0.0/4" log prefix="RESERVED " drop' drop

        # Limitar conexiones nuevas (anti-flood)
        fw_add_rich_rule 'rule family="ipv4" service name="ssh" limit value="3/m" accept' drop

        fw_reload
        log_info "Reglas anti-escaneo y anti-flood aplicadas"
    fi
else
    log_warn "Firewalld no está activo"
fi

# ============================================================
log_section "4. PROTECCIÓN CONTRA ATAQUES DE RED"
# ============================================================

if ask "¿Aplicar protecciones avanzadas contra ataques de red?"; then
    cat > /etc/sysctl.d/99-network-hardening.conf << 'EOF'
# ================================================
# PROTECCIÓN CONTRA ATAQUES DE RED
# ================================================

# --- Anti SYN Flood ---
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 3

# --- Anti Smurf ---
net.ipv4.icmp_echo_ignore_broadcasts = 1

# --- Anti IP Spoofing ---
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# --- Ignorar ICMP redirects (MITM) ---
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# --- No enviar redirects ---
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# --- Ignorar source routing ---
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# --- Log paquetes sospechosos ---
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# --- TCP timestamps (fingerprinting) ---
net.ipv4.tcp_timestamps = 0

# --- Ignorar respuestas ICMP falsas ---
net.ipv4.icmp_ignore_bogus_error_responses = 1

# --- Limitar respuestas ICMP ---
net.ipv4.icmp_ratelimit = 100
net.ipv4.icmp_ratemask = 88089

# --- IPv6 Router Advertisements (MITM) ---
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# --- Protección contra TIME-WAIT assassination ---
net.ipv4.tcp_rfc1337 = 1

# --- Conexiones huérfanas ---
net.ipv4.tcp_orphan_retries = 2
net.ipv4.tcp_max_orphans = 65536

# --- Rango de puertos efímeros más amplio ---
net.ipv4.ip_local_port_range = 32768 65535
EOF

    /usr/sbin/sysctl --system > /dev/null 2>&1
    log_info "Protecciones de red aplicadas"
fi

# ============================================================
log_section "5. BLOQUEAR WIFI INSEGUROS"
# ============================================================

echo "Redes WiFi visibles:"
nmcli -f SSID,SECURITY dev wifi list 2>/dev/null | head -10
echo ""

if ask "¿Deshabilitar conexión automática a redes abiertas?"; then
    # Deshabilitar auto-connect a redes sin contraseña
    for conn in $(nmcli -t -f NAME,TYPE con show | grep wireless | cut -d: -f1); do
        SEC=$(nmcli -t -f 802-11-wireless-security.key-mgmt con show "$conn" 2>/dev/null)
        if [[ -z "$SEC" || "$SEC" == *"none"* ]]; then
            nmcli con mod "$conn" connection.autoconnect no 2>/dev/null || true
            log_warn "Auto-connect deshabilitado para red abierta: $conn"
        fi
    done
    log_info "Redes WiFi abiertas no se conectarán automáticamente"
fi

# ============================================================
log_section "6. BLOQUEAR IPv6 (si no lo usas)"
# ============================================================

echo "IPv6 puede ser vector de ataque si no está bien configurado"
if ask "¿Deshabilitar IPv6 completamente?"; then
    cat > /etc/sysctl.d/99-disable-ipv6.conf << 'EOF'
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
    /usr/sbin/sysctl --system > /dev/null 2>&1
    log_info "IPv6 deshabilitado"
fi

# ============================================================
log_section "7. HOSTS - BLOQUEAR DOMINIOS MALICIOSOS"
# ============================================================

if ask "¿Agregar bloqueo de dominios maliciosos conocidos en /etc/hosts?"; then
    cp /etc/hosts "$BACKUP_DIR/"

    cat >> /etc/hosts << 'EOF'

# ================================================
# BLOQUEO DE DOMINIOS MALICIOSOS
# ================================================
# Telemetría y tracking
0.0.0.0 telemetry.microsoft.com
0.0.0.0 vortex.data.microsoft.com
0.0.0.0 settings-win.data.microsoft.com
0.0.0.0 watson.telemetry.microsoft.com

# Dominios de malware conocidos (ejemplos)
0.0.0.0 malware.com
0.0.0.0 phishing-site.com

# Bloqueo personalizado
0.0.0.0 sequoia.com
0.0.0.0 www.sequoia.com
0.0.0.0 sequoiacap.com
0.0.0.0 www.sequoiacap.com
EOF

    log_info "Dominios maliciosos bloqueados en /etc/hosts"
fi

# ============================================================
log_section "8. PROTECCIÓN MAC ADDRESS"
# ============================================================

echo "La MAC address puede usarse para tracking"
if ask "¿Habilitar MAC address aleatorio para WiFi?"; then
    CONN_NAME=$(nmcli -t -f NAME,TYPE con show --active | grep wireless | cut -d: -f1)
    if [[ -n "$CONN_NAME" ]]; then
        nmcli con mod "$CONN_NAME" wifi.cloned-mac-address random
        nmcli con mod "$CONN_NAME" ethernet.cloned-mac-address random 2>/dev/null || true
        log_info "MAC aleatorio habilitado para: $CONN_NAME"
        log_warn "Reconecta a la red para aplicar"
    fi

    # Para nuevas conexiones
    mkdir -p /etc/NetworkManager/conf.d/
    cat > /etc/NetworkManager/conf.d/99-random-mac.conf << 'EOF'
[device]
wifi.scan-rand-mac-address=yes

[connection]
wifi.cloned-mac-address=random
ethernet.cloned-mac-address=random
EOF

    systemctl reload NetworkManager 2>/dev/null || true
    log_info "MAC aleatorio configurado para futuras conexiones"
fi

# ============================================================
log_section "9. REGLAS ANTI-DDoS"
# ============================================================

if ask "¿Agregar reglas anti-DDoS básicas?"; then
    # Usando rich rules (compatibles con nftables backend)

    # Limitar conexiones SSH (3 por minuto)
    fw_add_rich_rule 'rule family="ipv4" service name="ssh" limit value="3/m" log prefix="SSH-LIMIT " accept'

    # Limitar ICMP echo (ping) - 1 por segundo
    fw_add_rich_rule 'rule family="ipv4" protocol value="icmp" limit value="1/s" accept'

    # Bloquear ping excesivo
    fw_add_icmp_block echo-request 2>/dev/null || true

    # Log de paquetes rechazados
    fw_set_log_denied all 2>/dev/null || true

    fw_reload 2>/dev/null || true
    log_info "Reglas anti-DDoS aplicadas (rate limiting)"
fi

# ============================================================
log_section "10. MONITOREO DE CONEXIONES"
# ============================================================

if ask "¿Crear script de monitoreo de conexiones sospechosas?"; then
    cat > /usr/local/bin/monitor-conexiones.sh << 'EOF'
#!/bin/bash
# Monitor de conexiones sospechosas

echo "=== CONEXIONES ACTIVAS ==="
ss -tunap 2>/dev/null | grep -v "127.0.0.1" | grep -v "::1"

echo ""
echo "=== CONEXIONES ESTABLECIDAS ==="
ss -tunap state established 2>/dev/null | grep -v "127.0.0.1"

echo ""
echo "=== INTENTOS DE CONEXIÓN RECIENTES (auth.log) ==="
journalctl -u sshd --since "1 hour ago" 2>/dev/null | grep -iE "failed|invalid|disconnect" | tail -20

echo ""
echo "=== IPs BLOQUEADAS POR FAIL2BAN ==="
fail2ban-client status sshd 2>/dev/null | grep "Banned IP" || echo "fail2ban no activo"

echo ""
echo "=== PAQUETES DROPPED (últimos 100) ==="
journalctl -k --since "1 hour ago" 2>/dev/null | grep -i "dropped" | tail -10
EOF

    chmod +x /usr/local/bin/monitor-conexiones.sh
    log_info "Script creado: /usr/local/bin/monitor-conexiones.sh"
fi

# ============================================================
log_section "11. FAIL2BAN - JAILS ADICIONALES"
# ============================================================

if command -v fail2ban-client &>/dev/null; then
    if ask "¿Configurar fail2ban con jails adicionales?"; then
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
bantime = 1w

[sshd-ddos]
enabled = true
port = ssh
filter = sshd-ddos
logpath = /var/log/secure
maxretry = 2
bantime = 4w

[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
bantime = 1y
findtime = 1d
maxretry = 3
EOF

        systemctl restart fail2ban
        log_info "fail2ban configurado: SSH 1 semana, DDoS 4 semanas, Reincidentes 1 año"
    fi
fi

# ============================================================
# RESUMEN
# ============================================================
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║    HARDENING EXTERNO COMPLETADO                           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "Verificar estado:"
echo "  - Ver conexiones:     /usr/local/bin/monitor-conexiones.sh"
echo "  - Ver firewall:       sudo fw_list_all"
echo "  - Ver fail2ban:       sudo fail2ban-client status"
echo "  - Ver logs:           journalctl -f"
echo ""
log_info "Backups en: $BACKUP_DIR"
