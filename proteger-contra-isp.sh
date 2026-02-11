#!/bin/bash
# ============================================================
# PROTECCIÓN CONTRA ESPIONAJE ISP - Módulo 38
# Linux Multi-Distro (openSUSE, Debian/Ubuntu, RHEL/Fedora, Arch)
# ============================================================
# Protege contra vigilancia a nivel de ISP:
#   - Kill switch VPN (nftables/iptables/firewalld DROP si cae la VPN)
#   - Prevención de fugas DNS (modo estricto DoT + DNSSEC)
#   - ECH (Encrypted Client Hello) oculta SNI
#   - Prevención de fugas WebRTC
#   - Evasión de DPI (obfs4 / stunnel)
#   - Hardening de privacidad del navegador
#   - HTTPS-Only enforcement
#   - NTP con NTS (Network Time Security)
#   - Ofuscación de patrones de tráfico
#   - Auditoría de metadatos ISP
#
# Secciones:
#   S1  - VPN Kill Switch
#   S2  - Prevención de fugas DNS
#   S3  - ECH (Encrypted Client Hello)
#   S4  - Prevención de fugas WebRTC
#   S5  - Evasión de DPI
#   S6  - Hardening de privacidad del navegador
#   S7  - HTTPS-Only enforcement
#   S8  - NTP con NTS (Network Time Security)
#   S9  - Ofuscación de patrones de tráfico
#   S10 - Auditoría de metadatos ISP
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps

# ── Variables ────────────────────────────────────────────────
ISP_CONF_DIR="/etc/securizar"
ISP_BIN_DIR="/usr/local/bin"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   PROTECCIÓN CONTRA ESPIONAJE ISP - Módulo 38             ║"
echo "║   Kill switch, DNS leak, ECH, DPI, NTS, auditoría         ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

echo "Capacidades que se instalarán:"
echo ""
echo -e "  ${CYAN}S1${NC}  VPN Kill Switch (nftables/firewalld, no tráfico sin VPN)"
echo -e "  ${CYAN}S2${NC}  Prevención de fugas DNS (DoT estricto, DNSSEC)"
echo -e "  ${CYAN}S3${NC}  ECH (Encrypted Client Hello, oculta SNI)"
echo -e "  ${CYAN}S4${NC}  Prevención de fugas WebRTC"
echo -e "  ${CYAN}S5${NC}  Evasión de DPI (obfs4 / stunnel)"
echo -e "  ${CYAN}S6${NC}  Hardening de privacidad del navegador"
echo -e "  ${CYAN}S7${NC}  HTTPS-Only enforcement"
echo -e "  ${CYAN}S8${NC}  NTP con NTS (Network Time Security)"
echo -e "  ${CYAN}S9${NC}  Ofuscación de patrones de tráfico"
echo -e "  ${CYAN}S10${NC} Auditoría de metadatos ISP"
echo ""

mkdir -p "$ISP_CONF_DIR"

# ============================================================
# S1 — VPN KILL SWITCH
# ============================================================
log_section "S1: VPN KILL SWITCH"

echo "Crea reglas firewall que bloquean TODO tráfico si la VPN cae."
echo "Permite: loopback, LAN, DHCP, interfaces VPN (wg0/tun0)."
echo "Compatible con nftables, iptables y firewalld."
echo ""

if ask "¿Configurar VPN Kill Switch?"; then

    # Script para activar kill switch (multi-backend)
    cat > "${ISP_CONF_DIR}/vpn-killswitch.sh" << 'KILLSWITCH_ON'
#!/bin/bash
# VPN Kill Switch - Activar
# Bloquea todo tráfico que no pase por VPN (wg0/tun0)
set -euo pipefail

if command -v nft &>/dev/null; then
    # ── nftables (openSUSE, sistemas modernos) ──
    nft delete table inet securizar_ks 2>/dev/null || true
    nft add table inet securizar_ks
    nft add chain inet securizar_ks output '{ type filter hook output priority 0; policy accept; }'

    # Permitir loopback
    nft add rule inet securizar_ks output oifname "lo" accept
    # Permitir LAN (RFC1918)
    nft add rule inet securizar_ks output ip daddr 10.0.0.0/8 accept
    nft add rule inet securizar_ks output ip daddr 172.16.0.0/12 accept
    nft add rule inet securizar_ks output ip daddr 192.168.0.0/16 accept
    # Permitir DHCP
    nft add rule inet securizar_ks output udp dport 67-68 accept
    # Permitir DNS local (stubby DoT)
    nft add rule inet securizar_ks output tcp dport 853 accept
    # Permitir interfaces VPN
    nft add rule inet securizar_ks output oifname "wg0" accept
    nft add rule inet securizar_ks output oifname "tun0" accept
    nft add rule inet securizar_ks output oifname "tun*" accept
    # Permitir conexiones establecidas
    nft add rule inet securizar_ks output ct state established,related accept
    # DROP todo lo demás
    nft add rule inet securizar_ks output drop

    echo "[+] VPN Kill Switch ACTIVADO via nftables"

elif command -v iptables &>/dev/null; then
    # ── iptables (sistemas legacy) ──
    CHAIN="SECURIZAR_KS"
    iptables -D OUTPUT -j "$CHAIN" 2>/dev/null || true
    iptables -F "$CHAIN" 2>/dev/null || true
    iptables -X "$CHAIN" 2>/dev/null || true
    iptables -N "$CHAIN"
    iptables -A "$CHAIN" -o lo -j ACCEPT
    iptables -A "$CHAIN" -d 10.0.0.0/8 -j ACCEPT
    iptables -A "$CHAIN" -d 172.16.0.0/12 -j ACCEPT
    iptables -A "$CHAIN" -d 192.168.0.0/16 -j ACCEPT
    iptables -A "$CHAIN" -p udp --dport 67:68 -j ACCEPT
    iptables -A "$CHAIN" -p tcp --dport 853 -j ACCEPT
    iptables -A "$CHAIN" -o wg0 -j ACCEPT
    iptables -A "$CHAIN" -o tun0 -j ACCEPT
    iptables -A "$CHAIN" -o tun+ -j ACCEPT
    iptables -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A "$CHAIN" -j DROP
    iptables -I OUTPUT -j "$CHAIN"
    echo "[+] VPN Kill Switch ACTIVADO via iptables"

elif command -v firewall-cmd &>/dev/null; then
    # ── firewalld ──
    firewall-cmd --set-default-zone=drop 2>/dev/null || true
    firewall-cmd --add-rich-rule='rule family="ipv4" destination address="10.0.0.0/8" accept' --permanent 2>/dev/null || true
    firewall-cmd --add-rich-rule='rule family="ipv4" destination address="172.16.0.0/12" accept' --permanent 2>/dev/null || true
    firewall-cmd --add-rich-rule='rule family="ipv4" destination address="192.168.0.0/16" accept' --permanent 2>/dev/null || true
    firewall-cmd --add-rich-rule='rule family="ipv4" port port="853" protocol="tcp" accept' --permanent 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
    echo "[+] VPN Kill Switch ACTIVADO via firewalld (zona drop)"
else
    echo "[!] No se encontró nftables, iptables ni firewalld"
    exit 1
fi
KILLSWITCH_ON
    chmod 700 "${ISP_CONF_DIR}/vpn-killswitch.sh"
    log_change "Creado" "${ISP_CONF_DIR}/vpn-killswitch.sh (multi-backend)"

    # Script para desactivar kill switch (multi-backend)
    cat > "${ISP_CONF_DIR}/vpn-killswitch-off.sh" << 'KILLSWITCH_OFF'
#!/bin/bash
# VPN Kill Switch - Desactivar
set -euo pipefail

if command -v nft &>/dev/null; then
    nft delete table inet securizar_ks 2>/dev/null || true
    echo "[+] VPN Kill Switch DESACTIVADO (nftables)"
elif command -v iptables &>/dev/null; then
    CHAIN="SECURIZAR_KS"
    iptables -D OUTPUT -j "$CHAIN" 2>/dev/null || true
    iptables -F "$CHAIN" 2>/dev/null || true
    iptables -X "$CHAIN" 2>/dev/null || true
    echo "[+] VPN Kill Switch DESACTIVADO (iptables)"
elif command -v firewall-cmd &>/dev/null; then
    firewall-cmd --set-default-zone=public 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
    echo "[+] VPN Kill Switch DESACTIVADO (firewalld → zona public)"
fi

echo "[+] Tráfico normal restaurado"
KILLSWITCH_OFF
    chmod 700 "${ISP_CONF_DIR}/vpn-killswitch-off.sh"
    log_change "Creado" "${ISP_CONF_DIR}/vpn-killswitch-off.sh (multi-backend)"

    # Hook NetworkManager dispatcher
    if [[ -d /etc/NetworkManager/dispatcher.d ]]; then
        cat > /etc/NetworkManager/dispatcher.d/99-vpn-killswitch << 'NM_HOOK'
#!/bin/bash
# NetworkManager dispatcher: activa kill switch cuando VPN sube,
# desactiva cuando VPN baja
IFACE="$1"
ACTION="$2"

case "$ACTION" in
    vpn-up)
        /etc/securizar/vpn-killswitch.sh 2>/dev/null || true
        ;;
    vpn-down)
        /etc/securizar/vpn-killswitch-off.sh 2>/dev/null || true
        ;;
esac
NM_HOOK
        chmod 755 /etc/NetworkManager/dispatcher.d/99-vpn-killswitch
        log_change "Creado" "/etc/NetworkManager/dispatcher.d/99-vpn-killswitch"
        log_info "Hook NetworkManager instalado: kill switch automático con VPN"
    else
        log_warn "NetworkManager dispatcher.d no encontrado; hook no instalado"
    fi

    log_info "VPN Kill Switch configurado"
else
    log_skip "VPN Kill Switch"
fi

# ============================================================
# S2 — PREVENCIÓN DE FUGAS DNS (DNS-over-TLS con unbound)
# ============================================================
log_section "S2: PREVENCIÓN DE FUGAS DNS"

echo "Configura unbound como resolvedor DNS local con DNS-over-TLS (DoT, puerto 853)."
echo "El ISP bloquea puerto 53 hacia DNS externos (1.1.1.1, 9.9.9.9)."
echo "Unbound cifra las consultas por el puerto 853, que el ISP no puede bloquear."
echo "Incluye DNSSEC, cache local y desactiva mDNS/LLMNR."
echo ""

if ask "¿Configurar DNS cifrado con unbound (DNS-over-TLS)?"; then

    # ── Instalar unbound si no está ──
    if ! command -v unbound &>/dev/null; then
        if command -v zypper &>/dev/null; then
            zypper install -y unbound 2>/dev/null || log_warn "No se pudo instalar unbound via zypper"
        elif command -v apt-get &>/dev/null; then
            apt-get install -y unbound 2>/dev/null || log_warn "No se pudo instalar unbound via apt"
        elif command -v dnf &>/dev/null; then
            dnf install -y unbound 2>/dev/null || log_warn "No se pudo instalar unbound via dnf"
        elif command -v pacman &>/dev/null; then
            pacman -S --noconfirm unbound 2>/dev/null || log_warn "No se pudo instalar unbound via pacman"
        fi
    fi

    if ! command -v unbound &>/dev/null; then
        log_warn "unbound no se pudo instalar. Sección S2 omitida."
    else

    # ── Obtener ancla DNSSEC ──
    # unbound-anchor genera formato correcto en /var/lib/unbound/root.key
    if command -v unbound-anchor &>/dev/null; then
        mkdir -p /var/lib/unbound
        unbound-anchor -a /var/lib/unbound/root.key 2>/dev/null || true
        chown unbound:unbound /var/lib/unbound/root.key 2>/dev/null || true
        log_change "DNSSEC" "Ancla de confianza actualizada (/var/lib/unbound/root.key)"
    fi

    # ── Configurar unbound para DoT estricto ──
    # Backup de configuración original
    cp /etc/unbound/unbound.conf /etc/unbound/unbound.conf.bak-securizar 2>/dev/null || true

    cat > /etc/unbound/unbound.conf << 'UNBOUND_CONF'
# ============================================================
# Securizar Módulo 38 - DNS-over-TLS con unbound
# Todas las consultas DNS se cifran por el puerto 853
# El ISP NO puede ver ni interceptar las consultas
# ============================================================

server:
    # Escuchar en localhost (todas las apps del sistema usan esto)
    interface: 127.0.0.1
    interface: ::1
    port: 53

    # Acceso solo desde localhost
    access-control: 127.0.0.0/8 allow
    access-control: ::1/128 allow
    access-control: 0.0.0.0/0 refuse
    access-control: ::/0 refuse

    # No ejecutar como root
    username: "unbound"
    directory: "/etc/unbound"
    chroot: ""

    # DNSSEC: validar firmas criptográficas de respuestas DNS
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    val-clean-additional: yes

    # Cache para rendimiento (evita consultas repetidas al ISP)
    cache-min-ttl: 300
    cache-max-ttl: 86400
    msg-cache-size: 50m
    rrset-cache-size: 100m
    key-cache-size: 50m
    neg-cache-size: 10m
    prefetch: yes
    prefetch-key: yes

    # Privacidad: minimizar datos enviados al DNS upstream
    qname-minimisation: yes
    qname-minimisation-strict: no
    minimal-responses: yes
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-below-nxdomain: yes
    harden-referral-path: yes

    # Rendimiento
    num-threads: 2
    so-reuseport: yes
    infra-cache-numhosts: 10000

    # Desactivar IPv6 si no hay conectividad IPv6
    do-ip6: no

    # TLS para conexiones upstream (DoT)
    tls-cert-bundle: "/etc/ssl/ca-bundle.pem"

    # Logs mínimos (privacidad)
    verbosity: 1
    log-queries: no
    log-replies: no
    logfile: "/var/log/unbound/unbound.log"
    use-syslog: no

# ── DNS-over-TLS: servidores upstream cifrados (puerto 853) ──
forward-zone:
    name: "."
    # SOLO TLS: si falla TLS, falla la consulta (nunca plaintext)
    forward-tls-upstream: yes

    # Cloudflare (privacidad, sin logs, rápido)
    forward-addr: 1.1.1.1@853#cloudflare-dns.com
    forward-addr: 1.0.0.1@853#cloudflare-dns.com

    # Quad9 (bloqueo de malware + privacidad)
    forward-addr: 9.9.9.9@853#dns.quad9.net
    forward-addr: 149.112.112.112@853#dns.quad9.net

    # Google DNS (respaldo)
    forward-addr: 8.8.8.8@853#dns.google
    forward-addr: 8.8.4.4@853#dns.google
UNBOUND_CONF
    log_change "Creado" "/etc/unbound/unbound.conf (DoT estricto, DNSSEC, cache)"

    # ── Crear directorio de log ──
    mkdir -p /var/log/unbound
    chown unbound:unbound /var/log/unbound 2>/dev/null || true

    # ── Verificar configuración antes de iniciar ──
    if unbound-checkconf /etc/unbound/unbound.conf &>/dev/null; then
        log_info "Configuración de unbound válida"
    else
        log_warn "Error en configuración de unbound:"
        unbound-checkconf /etc/unbound/unbound.conf 2>&1 | sed 's/^/    /' || true
    fi

    # ── Activar servicio unbound ──
    systemctl enable unbound 2>/dev/null || true
    systemctl restart unbound 2>/dev/null || true
    log_change "Servicio" "unbound habilitado e iniciado"

    # ── Configurar DNS del sistema para usar unbound ──
    dns_configured=false

    if command -v nmcli &>/dev/null; then
        active_conn=$(nmcli -t -f NAME con show --active 2>/dev/null | head -1)
        if [[ -n "$active_conn" ]]; then
            # Backup DNS anterior
            current_dns=$(nmcli -t -f ipv4.dns con show "$active_conn" 2>/dev/null || echo "")
            echo "# Backup DNS anterior: $current_dns" > "${ISP_CONF_DIR}/dns-backup.conf"
            echo "# Conexión: $active_conn" >> "${ISP_CONF_DIR}/dns-backup.conf"
            echo "# Fecha: $(date)" >> "${ISP_CONF_DIR}/dns-backup.conf"
            log_change "Backup" "DNS anterior guardado en ${ISP_CONF_DIR}/dns-backup.conf"

            # Apuntar DNS a unbound local
            nmcli con modify "$active_conn" ipv4.dns "127.0.0.1" 2>/dev/null || true
            nmcli con modify "$active_conn" ipv4.dns-priority -1 2>/dev/null || true
            nmcli con modify "$active_conn" ipv4.ignore-auto-dns yes 2>/dev/null || true

            # Si dnsmasq es plugin de NM, configurar reenvío a unbound
            nm_dns=$(grep -r "dns=" /etc/NetworkManager/ 2>/dev/null | grep -o "dns=.*" | head -1 || echo "")
            if [[ "$nm_dns" == *"dnsmasq"* ]]; then
                mkdir -p /etc/NetworkManager/dnsmasq.d
                cat > /etc/NetworkManager/dnsmasq.d/securizar-dot.conf << 'DNSMASQ_CONF'
# Securizar Módulo 38 - Reenviar DNS a unbound (DoT)
no-resolv
server=127.0.0.1#53
cache-size=0
DNSMASQ_CONF
                log_change "dnsmasq" "Configurado para reenviar a unbound"
            fi

            # Aplicar cambios (reconectar)
            nmcli con down "$active_conn" 2>/dev/null || true
            sleep 2
            nmcli con up "$active_conn" 2>/dev/null || true
            log_change "NetworkManager" "DNS redirigido a unbound (127.0.0.1 → DoT puerto 853)"
            dns_configured=true
        fi
    fi

    if [[ "$dns_configured" != "true" ]]; then
        # Fallback: modificar resolv.conf
        cp /etc/resolv.conf /etc/resolv.conf.bak-securizar 2>/dev/null || true
        cat > /etc/resolv.conf << 'RESOLV_CONF'
# Securizar Módulo 38 - DNS via unbound (DoT cifrado)
nameserver 127.0.0.1
options edns0 trust-ad
RESOLV_CONF
        chattr +i /etc/resolv.conf 2>/dev/null || true
        log_change "resolv.conf" "Forzado a usar unbound, archivo inmutable"
    fi

    # ── Desactivar mDNS y LLMNR (fugas en red local) ──
    if systemctl is-active avahi-daemon &>/dev/null; then
        systemctl stop avahi-daemon 2>/dev/null || true
        systemctl disable avahi-daemon 2>/dev/null || true
        log_change "avahi-daemon" "Desactivado (prevención fuga mDNS)"
    fi

    # ── Permitir puerto 853 saliente en firewall ──
    if command -v firewall-cmd &>/dev/null; then
        firewall-cmd --add-rich-rule='rule family="ipv4" port port="853" protocol="tcp" accept' --permanent 2>/dev/null || true
        firewall-cmd --add-rich-rule='rule family="ipv6" port port="853" protocol="tcp" accept' --permanent 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
        log_change "Firewall" "Puerto 853 (DoT) saliente permitido"
    elif command -v nft &>/dev/null; then
        nft add table inet securizar-dot 2>/dev/null || true
        nft flush table inet securizar-dot 2>/dev/null || true
        nft add chain inet securizar-dot output '{ type filter hook output priority 0; policy accept; }' 2>/dev/null || true
        nft add rule inet securizar-dot output tcp dport 853 accept 2>/dev/null || true
        log_change "Firewall" "Puerto 853 (DoT) saliente permitido via nftables"
    fi

    # ── Eliminar tabla nftables antigua que bloqueaba puerto 53 ──
    if command -v nft &>/dev/null; then
        if nft list tables 2>/dev/null | grep -q "securizar-dns"; then
            nft delete table inet securizar-dns 2>/dev/null || true
            log_change "Firewall" "Eliminada tabla nftables securizar-dns (obsoleta)"
        fi
    fi

    # ── Verificar que unbound funciona ──
    sleep 2
    if ss -tlnp 2>/dev/null | grep -q "unbound" || ss -ulnp 2>/dev/null | grep -q "unbound"; then
        log_info "unbound escuchando en 127.0.0.1:53"

        # Test rápido de resolución
        if nslookup example.com 127.0.0.1 &>/dev/null; then
            log_info "Resolución DNS via DoT funcionando correctamente"
        else
            log_warn "unbound activo pero la resolución falla. Verifica: sudo unbound-checkconf"
        fi
    else
        log_warn "unbound no parece estar escuchando. Verifica con: systemctl status unbound"
    fi

    # ── Script de verificación de DNS cifrado ──
    cat > "${ISP_BIN_DIR}/detectar-dns-leak.sh" << 'DNS_LEAK'
#!/bin/bash
# Detectar fugas DNS - verifica que las consultas usan DNS-over-TLS via unbound
set -euo pipefail

echo "╔═══════════════════════════════════════════════╗"
echo "║   DETECCIÓN DE FUGAS DNS                      ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

# Verificar unbound
echo "=== Estado de unbound (DNS-over-TLS) ==="
if systemctl is-active unbound &>/dev/null; then
    echo "  [OK] unbound activo"
    if ss -tlnp 2>/dev/null | grep -q "unbound"; then
        echo "  [OK] Escuchando en 127.0.0.1:53"
    else
        echo "  [!!] unbound activo pero NO escucha en puerto 53"
    fi
    # Verificar DoT configurado
    if grep -q "forward-tls-upstream: yes" /etc/unbound/unbound.conf 2>/dev/null; then
        echo "  [OK] DNS-over-TLS (DoT) habilitado"
    else
        echo "  [!!] DoT NO configurado en unbound"
    fi
    # Verificar DNSSEC
    if grep -q "auto-trust-anchor-file" /etc/unbound/unbound.conf 2>/dev/null; then
        echo "  [OK] DNSSEC habilitado"
    else
        echo "  [--] DNSSEC no configurado"
    fi
else
    echo "  [!!] unbound NO activo - DNS NO cifrado!"
    echo "       Ejecuta: sudo systemctl start unbound"
fi
echo ""

# Verificar resolv.conf
echo "=== Configuración DNS actual ==="
if [[ -f /etc/resolv.conf ]]; then
    grep "^nameserver" /etc/resolv.conf | while read -r line; do
        ns=$(echo "$line" | awk '{print $2}')
        if [[ "$ns" == "127.0.0.1" || "$ns" == "::1" || "$ns" == "127.0.0.53" ]]; then
            echo "  [OK] $line (local/unbound)"
        else
            echo "  [!!] $line (DNS externo sin cifrar - FUGA!)"
        fi
    done
else
    echo "  [!!] /etc/resolv.conf no encontrado"
fi
echo ""

# Test de resolución via DoT
echo "=== Test de resolución DNS (via unbound/DoT) ==="
for domain in example.com cloudflare.com opensuse.org; do
    if result=$(nslookup "$domain" 127.0.0.1 2>&1); then
        ip=$(echo "$result" | grep -A1 "Name:" | grep "Address:" | head -1 | awk '{print $2}')
        echo "  [OK] $domain -> ${ip:-resuelto} (via unbound/DoT)"
    else
        echo "  [!!] $domain -> FALLO"
    fi
done
echo ""

# Comprobar conexiones TLS a puerto 853
echo "=== Conexiones DNS-over-TLS activas (puerto 853) ==="
dot_conns=$(ss -tnp 2>/dev/null | grep ":853" || true)
if [[ -n "$dot_conns" ]]; then
    echo "$dot_conns" | sed 's/^/  /'
    echo "  [OK] Conexiones DoT detectadas - DNS cifrado"
else
    echo "  [--] Sin conexiones DoT activas (se crean bajo demanda)"
fi
echo ""

# Verificar que NO hay fugas al puerto 53 externo
echo "=== Verificacion de fugas (puerto 53 plaintext) ==="
plain_dns=$(ss -tnp 2>/dev/null | grep ":53 " | grep -v "127\." || true)
if [[ -n "$plain_dns" ]]; then
    echo "$plain_dns" | sed 's/^/  /'
    echo "  [!!] FUGA DNS DETECTADA - conexiones sin cifrar al puerto 53"
else
    echo "  [OK] Sin conexiones DNS plaintext al exterior"
fi
echo ""

# Cache stats
echo "=== Cache de unbound ==="
unbound-control stats_noreset 2>/dev/null | grep -E "total.num|cache.count" | sed 's/^/  /' || echo "  (unbound-control no disponible)"
echo ""

echo "Si todo muestra [OK], tu DNS esta cifrado y el ISP NO puede ver tus consultas."
DNS_LEAK
    chmod 755 "${ISP_BIN_DIR}/detectar-dns-leak.sh"
    log_change "Creado" "${ISP_BIN_DIR}/detectar-dns-leak.sh"

    # ── Script para restaurar DNS original ──
    cat > "${ISP_BIN_DIR}/restaurar-dns-isp.sh" << 'DNS_RESTORE'
#!/bin/bash
# Restaurar DNS original (deshacer proteccion DoT)
set -euo pipefail
echo "Restaurando DNS original..."
if [[ -f /etc/securizar/dns-backup.conf ]]; then
    echo "Configuracion anterior:"
    cat /etc/securizar/dns-backup.conf
fi
echo ""
# Detener unbound
systemctl stop unbound 2>/dev/null || true
systemctl disable unbound 2>/dev/null || true
echo "[+] unbound detenido"
# Restaurar NetworkManager
active_conn=$(nmcli -t -f NAME con show --active 2>/dev/null | head -1)
if [[ -n "$active_conn" ]]; then
    nmcli con modify "$active_conn" ipv4.dns "" 2>/dev/null || true
    nmcli con modify "$active_conn" ipv4.ignore-auto-dns no 2>/dev/null || true
    nmcli con down "$active_conn" && sleep 2 && nmcli con up "$active_conn"
    echo "[+] NetworkManager restaurado"
fi
# Restaurar resolv.conf
if [[ -f /etc/resolv.conf.bak-securizar ]]; then
    chattr -i /etc/resolv.conf 2>/dev/null || true
    cp /etc/resolv.conf.bak-securizar /etc/resolv.conf
    echo "[+] resolv.conf restaurado"
fi
echo ""
echo "DNS restaurado. Ahora usa el DNS del router/ISP (sin cifrar)."
DNS_RESTORE
    chmod 755 "${ISP_BIN_DIR}/restaurar-dns-isp.sh"
    log_change "Creado" "${ISP_BIN_DIR}/restaurar-dns-isp.sh (restaurar DNS original)"

    log_info "DNS-over-TLS configurado con unbound (puerto 853, cifrado, DNSSEC, ISP no puede interceptar)"

    fi  # cierre del if ! command -v unbound
else
    log_skip "Prevención de fugas DNS"
fi

# ============================================================
# S3 — ECH (ENCRYPTED CLIENT HELLO)
# ============================================================
log_section "S3: ECH (ENCRYPTED CLIENT HELLO)"

echo "Oculta el campo SNI (Server Name Indication) al ISP."
echo "Configura Firefox para usar ECH + DNS-over-HTTPS."
echo "Sin ECH, el ISP ve qué dominios visitas aunque uses HTTPS."
echo ""

if ask "¿Configurar ECH en Firefox?"; then

    # Buscar perfiles de Firefox
    FF_PROFILES_FOUND=0
    for ff_dir in /home/*/.mozilla/firefox/*.default* /root/.mozilla/firefox/*.default*; do
        [[ -d "$ff_dir" ]] || continue
        FF_PROFILES_FOUND=1

        # Crear/actualizar user.js
        cat >> "${ff_dir}/user.js" << 'ECH_JS'

// === Securizar M38 S3: ECH (Encrypted Client Hello) ===
// Oculta SNI al ISP
user_pref("network.dns.echconfig.enabled", true);
user_pref("network.dns.use_https_rr_as_altsvc", true);

// DNS-over-HTTPS necesario para ECH (modo 3 = solo DoH)
user_pref("network.trr.mode", 3);
user_pref("network.trr.uri", "https://cloudflare-dns.com/dns-query");
user_pref("network.trr.custom_uri", "https://cloudflare-dns.com/dns-query");
ECH_JS
        log_change "Modificado" "${ff_dir}/user.js (ECH)"
    done

    if [[ $FF_PROFILES_FOUND -eq 0 ]]; then
        log_warn "No se encontraron perfiles de Firefox"
    else
        log_info "ECH configurado en perfiles de Firefox"
    fi
else
    log_skip "ECH (Encrypted Client Hello)"
fi

# ============================================================
# S4 — PREVENCIÓN DE FUGAS WebRTC
# ============================================================
log_section "S4: PREVENCIÓN DE FUGAS WebRTC"

echo "WebRTC puede filtrar tu IP real incluso con VPN activa."
echo "Desactiva WebRTC en Firefox y añade restricciones."
echo ""

if ask "¿Desactivar WebRTC en Firefox?"; then

    FF_PROFILES_FOUND=0
    for ff_dir in /home/*/.mozilla/firefox/*.default* /root/.mozilla/firefox/*.default*; do
        [[ -d "$ff_dir" ]] || continue
        FF_PROFILES_FOUND=1

        cat >> "${ff_dir}/user.js" << 'WEBRTC_JS'

// === Securizar M38 S4: Prevención fugas WebRTC ===
user_pref("media.peerconnection.enabled", false);
user_pref("media.peerconnection.ice.default_address_only", true);
user_pref("media.peerconnection.ice.no_host", true);
user_pref("media.peerconnection.ice.proxy_only_if_behind_proxy", true);
user_pref("media.navigator.enabled", false);
WEBRTC_JS
        log_change "Modificado" "${ff_dir}/user.js (WebRTC off)"
    done

    if [[ $FF_PROFILES_FOUND -eq 0 ]]; then
        log_warn "No se encontraron perfiles de Firefox"
    else
        log_info "WebRTC desactivado en Firefox"
    fi
else
    log_skip "Prevención de fugas WebRTC"
fi

# ============================================================
# S5 — EVASIÓN DE DPI (DEEP PACKET INSPECTION)
# ============================================================
log_section "S5: EVASIÓN DE DPI"

echo "El ISP puede identificar tráfico VPN/Tor mediante DPI."
echo ""
echo "  A) obfs4proxy: ofusca Tor para parecer tráfico normal"
echo "  B) stunnel: envuelve VPN en TLS (parece HTTPS)"
echo ""

if ask "¿Configurar evasión de DPI?"; then

    echo ""
    echo "Opciones:"
    echo "  1) Tor bridges con obfs4 (recomendado si usas Tor)"
    echo "  2) stunnel para envolver VPN en TLS"
    echo "  3) Ambos"
    echo ""
    read -rp "  Opción [1/2/3]: " dpi_opt
    dpi_opt="${dpi_opt:-1}"

    if [[ "$dpi_opt" == "1" ]] || [[ "$dpi_opt" == "3" ]]; then
        echo ""
        echo "Instalando obfs4proxy..."
        pkg_install obfs4proxy 2>/dev/null || log_warn "obfs4proxy no disponible en repositorios"

        if command -v obfs4proxy &>/dev/null; then
            # Configurar Tor bridges
            mkdir -p /etc/tor/torrc.d
            cat > /etc/tor/torrc.d/bridges.conf << 'BRIDGES_CONF'
# Securizar M38 S5: Tor bridges con obfs4
# Descomenta y añade bridges reales de https://bridges.torproject.org
UseBridges 1
ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy

# Ejemplo (reemplazar con bridges reales):
# Bridge obfs4 IP:PORT FINGERPRINT cert=CERT iat-mode=0
BRIDGES_CONF
            log_change "Creado" "/etc/tor/torrc.d/bridges.conf"
            log_info "obfs4proxy configurado (añadir bridges de bridges.torproject.org)"
        fi
    fi

    if [[ "$dpi_opt" == "2" ]] || [[ "$dpi_opt" == "3" ]]; then
        echo ""
        echo "Instalando stunnel..."
        pkg_install stunnel 2>/dev/null || log_warn "stunnel no disponible en repositorios"

        if command -v stunnel &>/dev/null || command -v stunnel4 &>/dev/null; then
            cat > "${ISP_CONF_DIR}/stunnel-vpn-wrap.conf" << 'STUNNEL_CONF'
; Securizar M38 S5: stunnel - Envolver VPN en TLS
; Esto hace que el tráfico VPN parezca HTTPS al ISP
;
; PLANTILLA: Ajustar IP/puerto del servidor VPN real
; Uso: stunnel /etc/securizar/stunnel-vpn-wrap.conf

pid = /var/run/stunnel-vpn.pid
setuid = nobody
setgid = nogroup

[vpn-wrap]
client = yes
accept = 127.0.0.1:1194
; Cambiar por la IP:puerto de tu servidor stunnel remoto
connect = TU_SERVIDOR_VPN:443
TIMEOUTconnect = 10
TIMEOUTclose = 0
STUNNEL_CONF
            log_change "Creado" "${ISP_CONF_DIR}/stunnel-vpn-wrap.conf"
            log_info "stunnel plantilla creada (editar IP del servidor)"
        fi
    fi

    log_info "Evasión de DPI configurada"
else
    log_skip "Evasión de DPI"
fi

# ============================================================
# S6 — HARDENING DE PRIVACIDAD DEL NAVEGADOR
# ============================================================
log_section "S6: HARDENING DE PRIVACIDAD DEL NAVEGADOR"

echo "Configura Firefox con máxima privacidad:"
echo "  - Telemetría desactivada"
echo "  - Tracking protection estricto"
echo "  - Prefetch, speculative connections off"
echo "  - Referrer trimming, Pocket off, geolocation off"
echo ""

if ask "¿Aplicar hardening de privacidad en Firefox?"; then

    FF_PROFILES_FOUND=0
    for ff_dir in /home/*/.mozilla/firefox/*.default* /root/.mozilla/firefox/*.default*; do
        [[ -d "$ff_dir" ]] || continue
        FF_PROFILES_FOUND=1

        cat >> "${ff_dir}/user.js" << 'PRIVACY_JS'

// === Securizar M38 S6: Hardening de privacidad ===

// Telemetría off
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.archive.enabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("browser.ping-centre.telemetry", false);
user_pref("browser.newtabpage.activity-stream.feeds.telemetry", false);
user_pref("browser.newtabpage.activity-stream.telemetry", false);

// Tracking protection estricto
user_pref("privacy.trackingprotection.enabled", true);
user_pref("privacy.trackingprotection.socialtracking.enabled", true);
user_pref("privacy.trackingprotection.cryptomining.enabled", true);
user_pref("privacy.trackingprotection.fingerprinting.enabled", true);

// Prefetch off (evita que el ISP vea resoluciones anticipadas)
user_pref("network.prefetch-next", false);
user_pref("network.dns.disablePrefetch", true);
user_pref("network.dns.disablePrefetchFromHTTPS", true);
user_pref("network.predictor.enabled", false);
user_pref("network.predictor.enable-prefetch", false);

// Speculative connections off
user_pref("network.http.speculative-parallel-limit", 0);
user_pref("browser.places.speculativeConnect.enabled", false);

// Referrer trimming
user_pref("network.http.referer.XOriginPolicy", 2);
user_pref("network.http.referer.XOriginTrimmingPolicy", 2);

// Pocket off
user_pref("extensions.pocket.enabled", false);

// Geolocation off
user_pref("geo.enabled", false);
user_pref("geo.wifi.uri", "");

// Safe browsing sin Google
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);
user_pref("browser.safebrowsing.downloads.enabled", false);
user_pref("browser.safebrowsing.downloads.remote.enabled", false);

// Resist fingerprinting
user_pref("privacy.resistFingerprinting", true);
user_pref("privacy.resistFingerprinting.block_mozAddonManager", true);

// First party isolation
user_pref("privacy.firstparty.isolate", true);
PRIVACY_JS
        log_change "Modificado" "${ff_dir}/user.js (privacidad)"
    done

    if [[ $FF_PROFILES_FOUND -eq 0 ]]; then
        log_warn "No se encontraron perfiles de Firefox"
    else
        log_info "Hardening de privacidad aplicado en Firefox"
    fi
else
    log_skip "Hardening de privacidad del navegador"
fi

# ============================================================
# S7 — HTTPS-ONLY ENFORCEMENT
# ============================================================
log_section "S7: HTTPS-ONLY ENFORCEMENT"

echo "Fuerza HTTPS en todo el tráfico web."
echo "Bloquea mixed content y activa HSTS."
echo ""

if ask "¿Configurar HTTPS-Only en Firefox?"; then

    FF_PROFILES_FOUND=0
    for ff_dir in /home/*/.mozilla/firefox/*.default* /root/.mozilla/firefox/*.default*; do
        [[ -d "$ff_dir" ]] || continue
        FF_PROFILES_FOUND=1

        cat >> "${ff_dir}/user.js" << 'HTTPS_JS'

// === Securizar M38 S7: HTTPS-Only ===
user_pref("dom.security.https_only_mode", true);
user_pref("dom.security.https_only_mode_ever_enabled", true);
user_pref("dom.security.https_only_mode_send_http_background_request", false);
user_pref("security.mixed_content.block_active_content", true);
user_pref("security.mixed_content.block_display_content", true);
user_pref("network.stricttransportsecurity.preloadlist", true);
user_pref("dom.security.https_first", true);
HTTPS_JS
        log_change "Modificado" "${ff_dir}/user.js (HTTPS-Only)"
    done

    if [[ $FF_PROFILES_FOUND -eq 0 ]]; then
        log_warn "No se encontraron perfiles de Firefox"
    fi

    # Script de detección de HTTP inseguro
    cat > "${ISP_BIN_DIR}/detectar-http-inseguro.sh" << 'HTTP_DETECT'
#!/bin/bash
# Detectar conexiones HTTP activas (no cifradas)
set -euo pipefail

echo "=== Conexiones HTTP inseguras activas ==="
echo ""

# Buscar conexiones al puerto 80 (HTTP)
http_conns=$(ss -tnp state established 2>/dev/null | grep ':80 ' || true)

if [[ -n "$http_conns" ]]; then
    echo "[!] Conexiones HTTP (sin cifrar) detectadas:"
    echo "$http_conns" | sed 's/^/    /'
    echo ""
    echo "Estas conexiones son visibles para el ISP."
else
    echo "[+] No se detectaron conexiones HTTP inseguras."
fi

echo ""

# Buscar conexiones HTTPS (443)
https_conns=$(ss -tnp state established 2>/dev/null | grep ':443 ' || true)
echo "[i] Conexiones HTTPS activas: $(echo "$https_conns" | grep -c ':443' 2>/dev/null || echo 0)"
HTTP_DETECT
    chmod 755 "${ISP_BIN_DIR}/detectar-http-inseguro.sh"
    log_change "Creado" "${ISP_BIN_DIR}/detectar-http-inseguro.sh"

    log_info "HTTPS-Only enforcement configurado"
else
    log_skip "HTTPS-Only enforcement"
fi

# ============================================================
# S8 — NTP CON NTS (NETWORK TIME SECURITY)
# ============================================================
log_section "S8: NTP CON NTS (NETWORK TIME SECURITY)"

echo "NTP sin cifrar permite al ISP manipular tu reloj."
echo "NTS añade autenticación criptográfica a la sincronización."
echo "Se usa chrony con servidores NTS."
echo ""

if ask "¿Configurar NTP con NTS?"; then

    pkg_install chrony 2>/dev/null || log_warn "chrony no disponible"

    if command -v chronyd &>/dev/null; then
        # Desactivar systemd-timesyncd
        systemctl stop systemd-timesyncd 2>/dev/null || true
        systemctl disable systemd-timesyncd 2>/dev/null || true
        systemctl mask systemd-timesyncd 2>/dev/null || true
        log_change "Servicio" "systemd-timesyncd desactivado y enmascarado"

        # Configurar chrony con NTS
        mkdir -p /etc/chrony.d
        cat > /etc/chrony.d/securizar-nts.conf << 'NTS_CONF'
# Securizar M38 S8: NTP con NTS (Network Time Security)
# Servidores con soporte NTS verificado

server time.cloudflare.com iburst nts
server nts.netnod.se iburst nts
server ptbtime1.ptb.de iburst nts
server ntppool1.time.nl iburst nts

# Directorio para cookies NTS
ntsdumpdir /var/lib/chrony

# Límites de seguridad
minsources 2
maxchange 100 1 0
makestep 0.1 3
NTS_CONF
        log_change "Creado" "/etc/chrony.d/securizar-nts.conf"

        # Habilitar y reiniciar chrony
        systemctl enable chronyd 2>/dev/null || true
        systemctl restart chronyd 2>/dev/null || true
        log_change "Servicio" "chronyd habilitado y reiniciado"

        # Verificar NTS
        sleep 2
        if chronyc -n authdata 2>/dev/null | grep -q "NTS"; then
            log_info "NTS activo y funcionando"
        else
            log_warn "NTS configurado pero verificación pendiente (puede tardar)"
        fi
    else
        log_warn "chrony no instalado, NTS no configurado"
    fi
else
    log_skip "NTP con NTS"
fi

# ============================================================
# S9 — OFUSCACIÓN DE PATRONES DE TRÁFICO
# ============================================================
log_section "S9: OFUSCACIÓN DE PATRONES DE TRÁFICO"

echo "El ISP puede analizar patrones de tráfico (timing, volumen)"
echo "aunque esté cifrado. Este servicio genera tráfico de cobertura"
echo "con intervalos aleatorios y tamaños variables."
echo ""
echo "  - Intervalos: 30-120s con jitter aleatorio"
echo "  - Tamaño: 1K-64K bytes variables"
echo "  - Límites: CPUQuota=5%, MemoryMax=64M"
echo ""

if ask "¿Configurar ofuscación de patrones de tráfico?"; then

    # Script de padding de tráfico
    cat > "${ISP_BIN_DIR}/securizar-traffic-pad.sh" << 'TRAFFIC_PAD'
#!/bin/bash
# Ofuscación de patrones de tráfico - Securizar M38 S9
# Genera tráfico de cobertura con intervalos y tamaños aleatorios
set -euo pipefail

# Destinos HTTPS diversos y legítimos (CDNs, APIs públicas)
TARGETS=(
    "https://www.cloudflare.com/cdn-cgi/trace"
    "https://www.google.com/generate_204"
    "https://detectportal.firefox.com/canonical.html"
    "https://connectivity-check.ubuntu.com"
    "https://cloudflare-dns.com/dns-query?name=example.com&type=A"
    "https://dns.google/resolve?name=example.com&type=A"
)

# Rango de intervalos (segundos)
MIN_INTERVAL=30
MAX_INTERVAL=120

# Rango de bytes para descargar
MIN_BYTES=1024
MAX_BYTES=65536

rand_range() {
    local min=$1 max=$2
    echo $(( RANDOM % (max - min + 1) + min ))
}

while true; do
    # Seleccionar destino aleatorio
    idx=$(( RANDOM % ${#TARGETS[@]} ))
    target="${TARGETS[$idx]}"

    # Tamaño aleatorio
    bytes=$(rand_range $MIN_BYTES $MAX_BYTES)

    # Hacer request silenciosa con timeout
    curl -s -o /dev/null --max-time 10 --range "0-${bytes}" "$target" 2>/dev/null || true

    # Intervalo aleatorio con jitter
    interval=$(rand_range $MIN_INTERVAL $MAX_INTERVAL)
    # Añadir jitter de ±20%
    jitter=$(( interval * (RANDOM % 40 - 20) / 100 ))
    sleep_time=$(( interval + jitter ))
    [[ $sleep_time -lt 10 ]] && sleep_time=10

    sleep "$sleep_time"
done
TRAFFIC_PAD
    chmod 755 "${ISP_BIN_DIR}/securizar-traffic-pad.sh"
    log_change "Creado" "${ISP_BIN_DIR}/securizar-traffic-pad.sh"

    # Servicio systemd con límites de recursos
    cat > /etc/systemd/system/securizar-traffic-pad.service << 'TRAFFIC_SVC'
[Unit]
Description=Securizar - Ofuscación de patrones de tráfico ISP
Documentation=man:securizar(8)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/securizar-traffic-pad.sh
Restart=on-failure
RestartSec=60

# Límites de recursos
CPUQuota=5%
MemoryMax=64M
MemoryHigh=32M

# Seguridad
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes

# Usuario no privilegiado
DynamicUser=yes

[Install]
WantedBy=multi-user.target
TRAFFIC_SVC
    log_change "Creado" "/etc/systemd/system/securizar-traffic-pad.service"

    systemctl daemon-reload
    systemctl enable securizar-traffic-pad.service 2>/dev/null || true
    systemctl start securizar-traffic-pad.service 2>/dev/null || true
    log_change "Servicio" "securizar-traffic-pad habilitado e iniciado"

    log_info "Ofuscación de patrones de tráfico activa"
else
    log_skip "Ofuscación de patrones de tráfico"
fi

# ============================================================
# S10 — AUDITORÍA DE METADATOS ISP
# ============================================================
log_section "S10: AUDITORÍA DE METADATOS ISP"

echo "Crea un script de auditoría que verifica:"
echo "  VPN, kill switch, DNS leaks, IPv6, NTS, ECH, WebRTC,"
echo "  HTTPS-only, traffic padding"
echo "Produce puntuación: BUENO / MEJORABLE / DEFICIENTE"
echo ""

if ask "¿Instalar auditoría de metadatos ISP?"; then

    cat > "${ISP_BIN_DIR}/auditoria-isp.sh" << 'ISP_AUDIT'
#!/bin/bash
# ============================================================
# Auditoría de protección contra espionaje ISP
# Securizar Módulo 38 - S10
# ============================================================
set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

score=0
max_score=0
issues=()

check() {
    local name="$1"
    local result="$2"  # 0=pass, 1=fail
    local detail="${3:-}"
    max_score=$((max_score + 1))

    if [[ "$result" -eq 0 ]]; then
        score=$((score + 1))
        echo -e "  ${GREEN}[OK]${NC}  $name"
    else
        echo -e "  ${RED}[!!]${NC}  $name"
        [[ -n "$detail" ]] && echo -e "        ${DIM}$detail${NC}"
        issues+=("$name")
    fi
}

echo ""
echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}${BOLD}  AUDITORÍA DE PROTECCIÓN CONTRA ISP${NC}"
echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "  ${DIM}$(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo ""

# 1. VPN activa
echo -e "${BOLD}── VPN ──${NC}"
vpn_fail=1
for iface in wg0 tun0; do
    if ip link show "$iface" &>/dev/null; then
        vpn_fail=0
        break
    fi
done
check "Interfaz VPN activa (wg0/tun0)" $vpn_fail "No se detectó interfaz VPN"

# 2. Kill switch
echo ""
echo -e "${BOLD}── Kill Switch ──${NC}"
ks_fail=1
if nft list table inet securizar_ks &>/dev/null 2>&1; then
    ks_fail=0
elif iptables -L SECURIZAR_KS -n &>/dev/null 2>&1; then
    ks_fail=0
elif firewall-cmd --get-default-zone 2>/dev/null | grep -q "drop"; then
    ks_fail=0
fi
check "Kill switch VPN activo" $ks_fail "Ejecutar: /etc/securizar/vpn-killswitch.sh"

# 3. DNS
echo ""
echo -e "${BOLD}── DNS ──${NC}"
# unbound activo (DNS-over-TLS)
dot_fail=1
if systemctl is-active unbound &>/dev/null; then
    if grep -q "forward-tls-upstream: yes" /etc/unbound/unbound.conf 2>/dev/null; then
        dot_fail=0
    fi
fi
check "DNS-over-TLS (unbound) activo" $dot_fail "Ejecutar: sudo systemctl start unbound"

# DNS apunta a unbound (local)
dns_local_fail=1
if grep -qE "^nameserver\s+127\.0\.0\.1" /etc/resolv.conf 2>/dev/null; then
    dns_local_fail=0
elif nmcli -t -f ipv4.dns con show "$(nmcli -t -f NAME con show --active 2>/dev/null | head -1)" 2>/dev/null | grep -q "127.0.0.1"; then
    dns_local_fail=0
fi
check "DNS apunta a unbound (127.0.0.1)" $dns_local_fail "DNS no redirigido a unbound local"

# DNSSEC via unbound
dnssec_fail=1
if [[ -f /etc/unbound/unbound.conf ]]; then
    if grep -q "auto-trust-anchor-file" /etc/unbound/unbound.conf 2>/dev/null; then
        dnssec_fail=0
    fi
fi
check "DNSSEC habilitado (unbound)" $dnssec_fail "DNSSEC no configurado en unbound"

# 4. IPv6
echo ""
echo -e "${BOLD}── IPv6 ──${NC}"
ipv6_fail=0
if [[ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ]]; then
    disabled=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo "0")
    if [[ "$disabled" != "1" ]]; then
        # IPv6 habilitado - verificar si hay dirección pública
        if ip -6 addr show scope global 2>/dev/null | grep -q "inet6"; then
            ipv6_fail=1
        fi
    fi
fi
check "IPv6 sin exposición pública" $ipv6_fail "IPv6 global detectada (posible fuga)"

# 5. NTS
echo ""
echo -e "${BOLD}── NTP/NTS ──${NC}"
nts_fail=1
if systemctl is-active chronyd &>/dev/null; then
    if chronyc -n authdata 2>/dev/null | grep -q "NTS"; then
        nts_fail=0
    fi
fi
check "NTS (Network Time Security) activo" $nts_fail "Usar chrony con servidores NTS"

# 6. ECH
echo ""
echo -e "${BOLD}── Navegador ──${NC}"
ech_fail=1
for ff_dir in /home/*/.mozilla/firefox/*.default* /root/.mozilla/firefox/*.default*; do
    [[ -f "${ff_dir}/user.js" ]] || continue
    if grep -q "echconfig.enabled.*true" "${ff_dir}/user.js" 2>/dev/null; then
        ech_fail=0
        break
    fi
done
check "ECH (Encrypted Client Hello)" $ech_fail "SNI visible al ISP"

# 7. WebRTC
webrtc_fail=1
for ff_dir in /home/*/.mozilla/firefox/*.default* /root/.mozilla/firefox/*.default*; do
    [[ -f "${ff_dir}/user.js" ]] || continue
    if grep -q "peerconnection.enabled.*false" "${ff_dir}/user.js" 2>/dev/null; then
        webrtc_fail=0
        break
    fi
done
check "WebRTC desactivado" $webrtc_fail "WebRTC puede filtrar IP real"

# 8. HTTPS-Only
https_fail=1
for ff_dir in /home/*/.mozilla/firefox/*.default* /root/.mozilla/firefox/*.default*; do
    [[ -f "${ff_dir}/user.js" ]] || continue
    if grep -q "https_only_mode.*true" "${ff_dir}/user.js" 2>/dev/null; then
        https_fail=0
        break
    fi
done
check "HTTPS-Only mode" $https_fail "Tráfico HTTP visible al ISP"

# 9. Traffic padding
echo ""
echo -e "${BOLD}── Tráfico ──${NC}"
pad_fail=1
if systemctl is-active securizar-traffic-pad.service &>/dev/null; then
    pad_fail=0
fi
check "Traffic padding activo" $pad_fail "Patrones de tráfico expuestos"

# ── Puntuación ──
echo ""
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
echo ""

pct=0
if [[ $max_score -gt 0 ]]; then
    pct=$(( score * 100 / max_score ))
fi

if [[ $pct -ge 80 ]]; then
    label="BUENO"
    color="$GREEN"
elif [[ $pct -ge 50 ]]; then
    label="MEJORABLE"
    color="$YELLOW"
else
    label="DEFICIENTE"
    color="$RED"
fi

echo -e "  Puntuación: ${color}${BOLD}${score}/${max_score}${NC} (${color}${pct}%${NC})"
echo -e "  Nivel: ${color}${BOLD}${label}${NC}"
echo ""

if [[ ${#issues[@]} -gt 0 ]]; then
    echo -e "  ${YELLOW}Puntos a mejorar:${NC}"
    for issue in "${issues[@]}"; do
        echo -e "    ${DIM}•${NC} $issue"
    done
    echo ""
fi

echo -e "  ${DIM}Ejecutar: sudo bash /ruta/securizar/proteger-contra-isp.sh${NC}"
echo ""

exit 0
ISP_AUDIT
    chmod 755 "${ISP_BIN_DIR}/auditoria-isp.sh"
    log_change "Creado" "${ISP_BIN_DIR}/auditoria-isp.sh"

    # Cron semanal
    mkdir -p /etc/cron.weekly
    cat > /etc/cron.weekly/auditoria-isp << 'CRON_ISP'
#!/bin/bash
# Auditoría semanal de protección ISP - Securizar M38
/usr/local/bin/auditoria-isp.sh > /var/log/auditoria-isp-$(date +%Y%m%d).log 2>&1
# Mantener solo últimos 12 reportes
ls -t /var/log/auditoria-isp-*.log 2>/dev/null | tail -n +13 | xargs rm -f 2>/dev/null || true
CRON_ISP
    chmod 755 /etc/cron.weekly/auditoria-isp
    log_change "Creado" "/etc/cron.weekly/auditoria-isp"

    log_info "Auditoría de metadatos ISP instalada (semanal)"
else
    log_skip "Auditoría de metadatos ISP"
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MÓDULO 38 COMPLETADO                                    ║"
echo "╠═══════════════════════════════════════════════════════════╣"
echo "║                                                           ║"
echo "║   Herramientas instaladas:                                ║"
echo "║     • /etc/securizar/vpn-killswitch.sh      (kill switch) ║"
echo "║     • /usr/local/bin/detectar-dns-leak.sh    (DNS leaks)  ║"
echo "║     • /usr/local/bin/detectar-http-inseguro.sh (HTTP)     ║"
echo "║     • /usr/local/bin/securizar-traffic-pad.sh  (padding)  ║"
echo "║     • /usr/local/bin/auditoria-isp.sh        (auditoría)  ║"
echo "║                                                           ║"
echo "║   Ejecutar auditoría: auditoria-isp.sh                   ║"
echo "║                                                           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

log_info "Módulo 38 - Protección contra espionaje ISP completado"
