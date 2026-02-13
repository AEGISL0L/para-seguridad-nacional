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

ISP_SECTION="${1:-all}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps

# ── Variables ────────────────────────────────────────────────
ISP_CONF_DIR="/etc/securizar"
ISP_BIN_DIR="/usr/local/bin"

# ── Verificación exhaustiva ──────────────────────────────────
_isp_verificacion_exhaustiva() {
    local ok=0 total=23
    local _r

    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║   VERIFICACIÓN EXHAUSTIVA - Protección contra ISP            ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""

    # ── VPN (5 checks) ──
    echo -e "  ${BOLD}[VPN]${NC}"

    _r="!!"; [[ -f /etc/securizar/vpn-killswitch.sh ]] && _r="OK" && ((ok++))
    echo -e "    ${_r} Script kill switch existe"

    _r="!!"; [[ -f /etc/securizar/vpn-killswitch-off.sh ]] && _r="OK" && ((ok++))
    echo -e "    ${_r} Script kill switch OFF existe"

    _r="!!"
    if command -v nft &>/dev/null && nft list ruleset 2>/dev/null | grep -q 'securizar-vpn-killswitch' 2>/dev/null; then
        _r="OK"; ((ok++))
    elif iptables -S 2>/dev/null | grep -q 'securizar-vpn' 2>/dev/null; then
        _r="OK"; ((ok++))
    fi
    echo -e "    ${_r} Kill switch ACTIVO (nft/iptables)"

    _r="!!"
    if systemctl is-enabled securizar-vpn-killswitch.service &>/dev/null; then
        _r="OK"; ((ok++))
    fi
    echo -e "    ${_r} Servicio kill switch habilitado"

    _r="!!"
    if ip link show 2>/dev/null | grep -qE '(wg0|tun0|proton0|nordlynx)'; then
        _r="OK"; ((ok++))
    fi
    echo -e "    ${_r} Interfaz VPN activa"
    echo ""

    # ── DNS (5 checks) ──
    echo -e "  ${BOLD}[DNS]${NC}"

    _r="!!"
    if systemctl is-active unbound &>/dev/null; then
        _r="OK"; ((ok++))
    fi
    echo -e "    ${_r} Unbound activo"

    _r="!!"
    if [[ -f /etc/unbound/unbound.conf.d/securizar-dot.conf ]] && grep -q 'forward-tls-upstream' /etc/unbound/unbound.conf.d/securizar-dot.conf 2>/dev/null; then
        _r="OK"; ((ok++))
    elif [[ -f /etc/unbound/unbound.conf ]] && grep -q 'forward-tls-upstream' /etc/unbound/unbound.conf 2>/dev/null; then
        _r="OK"; ((ok++))
    fi
    echo -e "    ${_r} DNS-over-TLS (forward-tls-upstream)"

    _r="!!"
    if [[ -f /etc/unbound/unbound.conf.d/securizar-dot.conf ]] && grep -q 'val-clean-additional\|auto-trust-anchor-file' /etc/unbound/unbound.conf.d/securizar-dot.conf 2>/dev/null; then
        _r="OK"; ((ok++))
    elif [[ -f /etc/unbound/unbound.conf ]] && grep -q 'auto-trust-anchor-file' /etc/unbound/unbound.conf 2>/dev/null; then
        _r="OK"; ((ok++))
    fi
    echo -e "    ${_r} DNSSEC habilitado"

    _r="!!"
    if grep -q '^nameserver 127\.0\.0\.1' /etc/resolv.conf 2>/dev/null; then
        _r="OK"; ((ok++))
    fi
    echo -e "    ${_r} resolv.conf apunta a 127.0.0.1"

    _r="!!"
    if ! systemctl is-active avahi-daemon &>/dev/null; then
        _r="OK"; ((ok++))
    fi
    echo -e "    ${_r} avahi-daemon inactivo"
    echo ""

    # ── Privacidad (2 checks) ──
    echo -e "  ${BOLD}[Privacidad]${NC}"

    _r="!!"
    if [[ -f /etc/NetworkManager/conf.d/91-securizar-mac.conf ]] || \
       [[ -f /etc/NetworkManager/conf.d/99-securizar-mac.conf ]]; then
        _r="OK"; ((ok++))
    fi
    echo -e "    ${_r} MAC randomización configurada"

    _r="!!"
    if [[ -f /etc/sysctl.d/99-securizar-ipv6.conf ]] && \
       sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null | grep -q '1'; then
        _r="OK"; ((ok++))
    fi
    echo -e "    ${_r} IPv6 deshabilitado"
    echo ""

    # ── Red (3 checks) ──
    echo -e "  ${BOLD}[Red]${NC}"

    _r="!!"
    if command -v obfs4proxy &>/dev/null; then
        _r="OK"; ((ok++))
    fi
    echo -e "    ${_r} obfs4proxy disponible"

    _r="!!"
    if systemctl is-active securizar-traffic-pad.service &>/dev/null; then
        _r="OK"; ((ok++))
    fi
    echo -e "    ${_r} Traffic padding activo"

    _r="!!"
    if command -v nft &>/dev/null && nft list ruleset 2>/dev/null | grep -q '853' 2>/dev/null; then
        _r="OK"; ((ok++))
    elif command -v firewall-cmd &>/dev/null && firewall-cmd --list-ports 2>/dev/null | grep -q '853' 2>/dev/null; then
        _r="OK"; ((ok++))
    elif iptables -S 2>/dev/null | grep -q '853' 2>/dev/null; then
        _r="OK"; ((ok++))
    fi
    echo -e "    ${_r} Puerto 853 (DoT) en firewall"
    echo ""

    # ── Tiempo (2 checks) ──
    echo -e "  ${BOLD}[Tiempo]${NC}"

    _r="!!"
    if [[ -f /etc/chrony.d/securizar-nts.conf ]] && systemctl is-active chronyd &>/dev/null; then
        _r="OK"; ((ok++))
    fi
    echo -e "    ${_r} Chrony NTS activo"

    _r="!!"
    if ! systemctl is-active systemd-timesyncd &>/dev/null; then
        _r="OK"; ((ok++))
    fi
    echo -e "    ${_r} timesyncd inactivo"
    echo ""

    # ── Navegador (3 checks) ──
    echo -e "  ${BOLD}[Navegador]${NC}"

    local _ff_found=0 _ech=0 _webrtc=0 _https=0
    for ff_dir in /home/*/.mozilla/firefox/*.default* /root/.mozilla/firefox/*.default*; do
        [[ -f "${ff_dir}/user.js" ]] || continue
        _ff_found=1
        grep -q 'network.dns.echconfig.enabled.*true' "${ff_dir}/user.js" 2>/dev/null && _ech=1
        grep -q 'media.peerconnection.enabled.*false' "${ff_dir}/user.js" 2>/dev/null && _webrtc=1
        grep -q 'dom.security.https_only_mode.*true' "${ff_dir}/user.js" 2>/dev/null && _https=1
    done

    _r="!!"; [[ $_ech -eq 1 ]] && _r="OK" && ((ok++))
    echo -e "    ${_r} ECH (Encrypted Client Hello)"

    _r="!!"; [[ $_webrtc -eq 1 ]] && _r="OK" && ((ok++))
    echo -e "    ${_r} WebRTC desactivado"

    _r="!!"; [[ $_https -eq 1 ]] && _r="OK" && ((ok++))
    echo -e "    ${_r} HTTPS-Only mode"
    echo ""

    # ── Herramientas (3 checks) ──
    echo -e "  ${BOLD}[Herramientas]${NC}"

    _r="!!"; [[ -x /usr/local/bin/auditoria-isp.sh ]] && _r="OK" && ((ok++))
    echo -e "    ${_r} auditoria-isp.sh"

    _r="!!"; [[ -x /usr/local/bin/detectar-dns-leak.sh ]] && _r="OK" && ((ok++))
    echo -e "    ${_r} detectar-dns-leak.sh"

    _r="!!"; [[ -x /usr/local/bin/detectar-http-inseguro.sh ]] && _r="OK" && ((ok++))
    echo -e "    ${_r} detectar-http-inseguro.sh"
    echo ""

    # ── Scoring ──
    echo "  ─────────────────────────────────────────"
    local nivel
    if [[ $ok -ge 20 ]]; then
        nivel="EXCELENTE"
    elif [[ $ok -ge 15 ]]; then
        nivel="BUENO"
    elif [[ $ok -ge 10 ]]; then
        nivel="MEJORABLE"
    else
        nivel="DEFICIENTE"
    fi
    echo -e "  Resultado: ${BOLD}${ok}/${total} OK${NC} — ${nivel}"
    echo ""
}

# ── Handler --verify ─────────────────────────────────────────
if [[ "$ISP_SECTION" == "--verify" ]]; then
    _isp_verificacion_exhaustiva
    exit 0
fi

# ── Pre-check: detectar secciones ya aplicadas ──────────────
if [[ "$ISP_SECTION" == "all" ]]; then
_precheck 10
_pc 'check_file_exists /etc/securizar/vpn-killswitch.sh && check_file_exists /etc/systemd/system/securizar-vpn-killswitch.service && check_file_exists /etc/sysctl.d/99-securizar-ipv6.conf'
_pc 'check_service_enabled unbound'
_pc true  # S3 - ECH Firefox (perfiles dinámicos)
_pc true  # S4 - WebRTC Firefox (perfiles dinámicos)
_pc true  # S5 - DPI evasion (opción interactiva)
_pc true  # S6 - privacidad navegador (perfiles dinámicos)
_pc true  # S7 - HTTPS-only (perfiles dinámicos)
_pc 'check_file_exists /etc/chrony.d/securizar-nts.conf'
_pc 'check_service_enabled securizar-traffic-pad.service'
_pc 'check_executable /usr/local/bin/auditoria-isp.sh'
_precheck_result
fi  # all - precheck

mkdir -p "$ISP_CONF_DIR"

if [[ "$ISP_SECTION" == "all" ]]; then
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
fi  # all - banner

if [[ "$ISP_SECTION" == "all" || "$ISP_SECTION" == "S1" ]]; then
# ============================================================
# S1 — VPN KILL SWITCH
# ============================================================
log_section "S1: VPN KILL SWITCH"

echo "Crea reglas firewall que bloquean TODO tráfico si la VPN cae."
echo "Permite: loopback, LAN, DHCP, interfaces VPN (wg0/tun0/proton0)."
echo "Compatible con nftables, iptables y firewalld."
echo ""

if check_file_exists /etc/securizar/vpn-killswitch.sh; then
    log_already "VPN Kill Switch (scripts ya creados)"
elif ask "¿Configurar VPN Kill Switch?"; then

    # Script para activar kill switch (multi-backend)
    cat > "${ISP_CONF_DIR}/vpn-killswitch.sh" << 'KILLSWITCH_ON'
#!/bin/bash
# VPN Kill Switch - Activar
# Bloquea todo tráfico que no pase por VPN (wg0/tun0/proton0)
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
    # Permitir interfaces WireGuard (ProtonVPN, Mullvad, etc.)
    nft add rule inet securizar_ks output oifname "proton*" accept
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
    # WireGuard (ProtonVPN, Mullvad, etc.)
    iptables -A "$CHAIN" -o proton+ -j ACCEPT
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
# Soporta: OpenVPN (vpn-up/vpn-down), WireGuard/ProtonVPN (up/down en iface VPN)
IFACE="$1"
ACTION="$2"

case "$ACTION" in
    vpn-up)
        /etc/securizar/vpn-killswitch.sh 2>/dev/null || true
        ;;
    vpn-down)
        /etc/securizar/vpn-killswitch-off.sh 2>/dev/null || true
        ;;
    up)
        # WireGuard (ProtonVPN, Mullvad, etc.)
        case "$IFACE" in proton*|wg*|mullvad*|nordlynx*)
            /etc/securizar/vpn-killswitch.sh 2>/dev/null || true
        esac
        ;;
    down)
        case "$IFACE" in proton*|wg*|mullvad*|nordlynx*)
            /etc/securizar/vpn-killswitch-off.sh 2>/dev/null || true
        esac
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

# ── S1 post: Auto-activar kill switch si VPN ya conectada ──
if [[ -f "${ISP_CONF_DIR}/vpn-killswitch.sh" ]]; then
    _ks_active=false
    if command -v nft &>/dev/null; then
        nft list table inet securizar_ks &>/dev/null 2>&1 && _ks_active=true
    elif command -v iptables &>/dev/null; then
        iptables -L SECURIZAR_KS &>/dev/null 2>&1 && _ks_active=true
    fi

    if [[ "$_ks_active" == "true" ]]; then
        log_already "Kill switch activo (reglas firewall presentes)"
    else
        for _ks_iface in proton0 proton1 wg0 tun0 tun1 mullvad-wg nordlynx; do
            if ip link show "$_ks_iface" &>/dev/null 2>&1; then
                if ask "VPN $_ks_iface detectada pero kill switch NO activo. ¿Activar ahora?"; then
                    bash "${ISP_CONF_DIR}/vpn-killswitch.sh" 2>/dev/null && \
                        log_change "Kill switch" "Activado (VPN $_ks_iface detectada)" || \
                        log_warn "Kill switch: fallo al activar"
                else
                    log_skip "Activación kill switch"
                fi
                break
            fi
        done
    fi
fi

# ── S1 post: Persistencia systemd para kill switch en arranque ──
if [[ -f "${ISP_CONF_DIR}/vpn-killswitch.sh" ]]; then
    if [[ -f /etc/systemd/system/securizar-vpn-killswitch.service ]]; then
        log_already "Kill switch persistencia (securizar-vpn-killswitch.service)"
    elif ask "¿Crear servicio systemd para kill switch en arranque?"; then
        cat > /etc/systemd/system/securizar-vpn-killswitch.service << 'KS_SVC'
[Unit]
Description=Securizar - VPN Kill Switch (persistencia en arranque)
After=network-online.target NetworkManager.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/bin/bash -c 'for i in proton0 proton1 wg0 tun0 tun1 mullvad-wg nordlynx; do ip link show "$i" 2>/dev/null && exit 0; done; exit 1'
ExecStart=/etc/securizar/vpn-killswitch.sh
ExecStop=/etc/securizar/vpn-killswitch-off.sh
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
KS_SVC
        systemctl daemon-reload
        systemctl enable securizar-vpn-killswitch.service 2>/dev/null || true
        log_change "Creado" "/etc/systemd/system/securizar-vpn-killswitch.service (boot persistence)"
    else
        log_skip "Kill switch persistencia systemd"
    fi
fi

# ── S1 extra: MAC randomización (anti-tracking por ISP/AP) ──
if [[ -d /etc/NetworkManager/conf.d ]]; then
    if [[ -f /etc/NetworkManager/conf.d/91-securizar-mac.conf ]]; then
        log_already "MAC randomización (91-securizar-mac.conf)"
    elif ask "¿Configurar MAC randomización? (anti-tracking WiFi/Ethernet)"; then
        cat > /etc/NetworkManager/conf.d/91-securizar-mac.conf << 'MAC_CONF'
# Securizar M38 S1: MAC randomización
# stable = misma MAC por sesión, cambia cada reinicio
[device]
wifi.scan-rand-mac-address=yes

[connection]
wifi.cloned-mac-address=stable
ethernet.cloned-mac-address=stable
connection.stable-id=${CONNECTION}/${BOOT}
MAC_CONF
        nmcli general reload conf 2>/dev/null || true
        log_change "Creado" "/etc/NetworkManager/conf.d/91-securizar-mac.conf (MAC stable per-boot)"
    else
        log_skip "MAC randomización"
    fi
fi

# ── S1 extra: Deshabilitar IPv6 persistente (anti-leak) ──
if [[ -f /etc/sysctl.d/99-securizar-ipv6.conf ]]; then
    log_already "IPv6 deshabilitado persistente (99-securizar-ipv6.conf)"
elif ask "¿Deshabilitar IPv6 persistente? (previene fugas fuera de VPN)"; then
    cat > /etc/sysctl.d/99-securizar-ipv6.conf << 'IPV6_CONF'
# Securizar M38 S1: Deshabilitar IPv6 (prevención de fugas)
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
IPV6_CONF
    sysctl -p /etc/sysctl.d/99-securizar-ipv6.conf 2>/dev/null || true
    log_change "Creado" "/etc/sysctl.d/99-securizar-ipv6.conf (IPv6 deshabilitado persistente)"
else
    log_skip "IPv6 deshabilitado persistente"
fi
fi  # S1

if [[ "$ISP_SECTION" == "all" || "$ISP_SECTION" == "S2" ]]; then
# ============================================================
# S2 — PREVENCIÓN DE FUGAS DNS (DNS-over-TLS con unbound)
# ============================================================
log_section "S2: PREVENCIÓN DE FUGAS DNS"

echo "Configura unbound como resolvedor DNS local con DNS-over-TLS (DoT, puerto 853)."
echo "El ISP bloquea puerto 53 hacia DNS externos (1.1.1.1, 9.9.9.9)."
echo "Unbound cifra las consultas por el puerto 853, que el ISP no puede bloquear."
echo "Incluye DNSSEC, cache local y desactiva mDNS/LLMNR."
echo ""

if check_service_enabled unbound; then
    log_already "DNS cifrado con unbound (servicio habilitado)"
elif ask "¿Configurar DNS cifrado con unbound (DNS-over-TLS)?"; then

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

    # ── Verificar que unbound funciona (con warm-up DoT) ──
    sleep 3
    if ss -tlnp 2>/dev/null | grep -q "unbound" || ss -ulnp 2>/dev/null | grep -q "unbound"; then
        log_info "unbound escuchando en 127.0.0.1:53"

        # Warm-up: forzar handshake TLS con upstream DoT
        nslookup example.com 127.0.0.1 &>/dev/null || true
        sleep 2

        # Verificación con reintentos
        _unbound_ok=false
        for _dns_try in 1 2 3; do
            if nslookup example.com 127.0.0.1 &>/dev/null; then
                log_info "Resolución DNS via DoT funcionando correctamente"
                _unbound_ok=true
                break
            fi
            [[ $_dns_try -lt 3 ]] && sleep 2
        done
        if [[ "$_unbound_ok" != "true" ]]; then
            log_warn "unbound activo pero resolución lenta (DoT handshake inicial ~5-10s es normal)"
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

    # ── Override global DNS de NM: forzar unbound sobre VPN comerciales ──
    # ProtonVPN fuerza DNS 10.2.0.1 via NM con prioridad -1500,
    # bypaseando unbound. [global-dns] sobreescribe CUALQUIER DNS de
    # conexión, incluida VPN. NM >= 1.2 (2016+).
    # Cadena resultante: App → unbound (cache+DNSSEC) → DoT:853 → túnel VPN → Cloudflare/Quad9
    if [[ -d /etc/NetworkManager/conf.d ]]; then
        cat > /etc/NetworkManager/conf.d/90-securizar-dns.conf << 'NM_DNS_GLOBAL'
# Securizar M38 S2: Forzar DNS a unbound (DoT+DNSSEC)
# Sobreescribe DNS de VPN comerciales (ProtonVPN, Mullvad, etc.)
# App → unbound (cache+DNSSEC) → DoT:853 → túnel VPN → Cloudflare/Quad9

[global-dns]
searches=
options=edns0 trust-ad

[global-dns-domain-*]
servers=127.0.0.1
NM_DNS_GLOBAL
        log_change "Creado" "/etc/NetworkManager/conf.d/90-securizar-dns.conf (override global DNS)"

        # Recargar NM para aplicar inmediatamente
        nmcli general reload dns 2>/dev/null || \
            systemctl reload NetworkManager 2>/dev/null || true
        log_info "DNS global forzado a unbound: ProtonVPN/Mullvad ya no pueden sobreescribir"
    fi

    # ── NM dispatcher: respaldo para forzar unbound tras VPN up ──
    # Belt-and-suspenders: si global-dns no basta, el dispatcher
    # reescribe resolv.conf con reintentos tras VPN up.
    if [[ -d /etc/NetworkManager/dispatcher.d ]]; then
        cat > /etc/NetworkManager/dispatcher.d/98-securizar-dns-vpn << 'DNS_HOOK'
#!/bin/bash
# Respaldo: forzar DNS via unbound cuando VPN sube (ProtonVPN, Mullvad, etc.)
# El mecanismo principal es /etc/NetworkManager/conf.d/90-securizar-dns.conf
# Este dispatcher actúa como respaldo con reintentos por si la VPN
# sobreescribe resolv.conf después de NM.
IFACE="$1"
ACTION="$2"

is_vpn_event() {
    case "$ACTION" in vpn-up|vpn-down) return 0 ;; esac
    case "$IFACE" in proton*|wg*|mullvad*|nordlynx*|tun*) return 0 ;; esac
    return 1
}

is_vpn_event || exit 0

force_unbound_dns() {
    if ss -tlnp 2>/dev/null | grep -q "127.0.0.1:53.*unbound"; then
        printf '%s\n' "# Securizar - DNS via unbound (DoT+DNSSEC)" \
                      "nameserver 127.0.0.1" \
                      "options edns0 trust-ad" > /etc/resolv.conf
        return 0
    fi
    return 1
}

case "$ACTION" in
    vpn-up|up)
        # Intento inmediato
        force_unbound_dns

        # Reintento tras 3s: VPNs comerciales pueden escribir resolv.conf
        # después del dispatcher (race condition)
        (
            sleep 3
            if ! grep -q "^nameserver 127.0.0.1" /etc/resolv.conf 2>/dev/null; then
                force_unbound_dns && \
                    logger -t securizar-dns "VPN $IFACE: DNS re-forzado a unbound (reintento)"
            fi
        ) &
        logger -t securizar-dns "VPN $IFACE up: DNS forzado a unbound (127.0.0.1)"
        ;;
    vpn-down|down)
        logger -t securizar-dns "VPN $IFACE down: NetworkManager restaurará DNS"
        ;;
esac
DNS_HOOK
        chmod 755 /etc/NetworkManager/dispatcher.d/98-securizar-dns-vpn
        log_change "Creado" "/etc/NetworkManager/dispatcher.d/98-securizar-dns-vpn (respaldo con reintentos)"
        log_info "Hook DNS-VPN instalado: doble protección contra override de VPN comerciales"
    fi

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
# Eliminar override global DNS
rm -f /etc/NetworkManager/conf.d/90-securizar-dns.conf
rm -f /etc/NetworkManager/dispatcher.d/98-securizar-dns-vpn
echo "[+] Override DNS global y dispatcher eliminados"
# Restaurar NetworkManager
active_conn=$(nmcli -t -f NAME con show --active 2>/dev/null | head -1)
if [[ -n "$active_conn" ]]; then
    nmcli con modify "$active_conn" ipv4.dns "" 2>/dev/null || true
    nmcli con modify "$active_conn" ipv4.ignore-auto-dns no 2>/dev/null || true
    nmcli general reload dns 2>/dev/null || true
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
fi  # S2

if [[ "$ISP_SECTION" == "all" || "$ISP_SECTION" == "S3" ]]; then
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
fi  # S3

if [[ "$ISP_SECTION" == "all" || "$ISP_SECTION" == "S4" ]]; then
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
fi  # S4

if [[ "$ISP_SECTION" == "all" || "$ISP_SECTION" == "S5" ]]; then
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
fi  # S5

if [[ "$ISP_SECTION" == "all" || "$ISP_SECTION" == "S6" ]]; then
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
fi  # S6

if [[ "$ISP_SECTION" == "all" || "$ISP_SECTION" == "S7" ]]; then
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
fi  # S7

if [[ "$ISP_SECTION" == "all" || "$ISP_SECTION" == "S8" ]]; then
# ============================================================
# S8 — NTP CON NTS (NETWORK TIME SECURITY)
# ============================================================
log_section "S8: NTP CON NTS (NETWORK TIME SECURITY)"

echo "NTP sin cifrar permite al ISP manipular tu reloj."
echo "NTS añade autenticación criptográfica a la sincronización."
echo "Se usa chrony con servidores NTS."
echo ""

if check_file_exists /etc/chrony.d/securizar-nts.conf; then
    log_already "NTP con NTS (chrony NTS ya configurado)"
elif ask "¿Configurar NTP con NTS?"; then

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

        # Verificar NTS (handshake NTS-KE puede tardar 5-10s)
        _nts_ok=false
        for _nts_try in 1 2 3; do
            sleep 3
            if chronyc -n authdata 2>/dev/null | grep -q "NTS"; then
                _nts_ok=true
                nts_sources=$(chronyc -n authdata 2>/dev/null | grep -c "NTS" || echo "0")
                log_info "NTS activo y funcionando ($nts_sources fuentes verificadas)"
                break
            fi
        done
        if [[ "$_nts_ok" != "true" ]]; then
            log_warn "NTS configurado pero verificación pendiente (NTS-KE handshake puede tardar)"
            log_info "Verificar manualmente: chronyc -n authdata | grep NTS"
        fi
    else
        log_warn "chrony no instalado, NTS no configurado"
    fi
else
    log_skip "NTP con NTS"
fi
fi  # S8

if [[ "$ISP_SECTION" == "all" || "$ISP_SECTION" == "S9" ]]; then
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

if check_service_enabled securizar-traffic-pad.service; then
    log_already "Ofuscación de tráfico (servicio habilitado)"
elif ask "¿Configurar ofuscación de patrones de tráfico?"; then

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
fi  # S9

if [[ "$ISP_SECTION" == "all" || "$ISP_SECTION" == "S10" ]]; then
# ============================================================
# S10 — AUDITORÍA DE METADATOS ISP
# ============================================================
log_section "S10: AUDITORÍA DE METADATOS ISP"

echo "Crea un script de auditoría parametrizable que verifica:"
echo "  VPN, kill switch, DNS leaks, IPv6, NTS, ECH, WebRTC,"
echo "  HTTPS-only, traffic padding, MAC, mDNS, DPI, HTTP leaks"
echo "Configuración: /etc/securizar/auditoria-isp.conf"
echo "Reportes:      /var/lib/securizar/auditoria-isp/"
echo "Uso:           auditoria-isp.sh [--report] [--quiet] [--help]"
echo "Produce puntuación ponderada: BUENO / MEJORABLE / DEFICIENTE"
echo ""

if check_executable /usr/local/bin/auditoria-isp.sh; then
    log_already "Auditoría ISP (script ya instalado)"
elif ask "¿Instalar auditoría de metadatos ISP?"; then

    # ── Directorios de reportes ──
    mkdir -p /var/lib/securizar/auditoria-isp
    mkdir -p /var/log/securizar

    # ── Configuración parametrizable ──
    if [[ ! -f /etc/securizar/auditoria-isp.conf ]]; then
        cat > /etc/securizar/auditoria-isp.conf << 'ISP_CONF'
# ============================================================
# Configuración de Auditoría ISP - Securizar Módulo 38
# ============================================================
# Editar para ajustar a tu entorno. Reaplicar módulo no sobreescribe.

# === Interfaces VPN a detectar (separadas por espacio) ===
VPN_INTERFACES="wg0 tun0 tun1 proton0 mullvad-wg nordlynx"

# === Procesos VPN esperados ===
VPN_PROCESSES="openvpn wireguard wg-quick"

# === DNS ===
DNS_LOCAL_ADDR="127.0.0.1"
DNS_SERVICE="unbound"
DNS_CONF="/etc/unbound/unbound.conf"
DNS_DOT_PORT=853

# === Kill Switch ===
KS_NFT_TABLE="securizar_ks"
KS_IPT_CHAIN="SECURIZAR_KS"

# === NTP/NTS ===
NTS_SERVICE="chronyd"

# === Traffic Padding ===
PAD_SERVICE="securizar-traffic-pad.service"

# === Firefox (globs de perfiles, separados por espacio) ===
FF_PROFILE_DIRS="/home/*/.mozilla/firefox/*.default* /root/.mozilla/firefox/*.default*"

# === Reportes ===
REPORT_DIR="/var/lib/securizar/auditoria-isp"
REPORT_RETENTION=30
LOG_FILE="/var/log/securizar/auditoria-isp.log"

# === Umbrales de puntuación (porcentaje) ===
THRESHOLD_GOOD=80
THRESHOLD_FAIR=50

# === Checks opcionales (yes/no) ===
CHECK_EXTERNAL_IP=no
EXTERNAL_IP_URL="https://api.ipify.org"
CHECK_MAC_RANDOM=yes
CHECK_MDNS=yes
CHECK_DPI=yes
CHECK_HTTP_LEAKS=yes
CHECK_TOR=no

# === Pesos por categoría (1-5) ===
WEIGHT_VPN=3
WEIGHT_DNS=3
WEIGHT_NETWORK=2
WEIGHT_BROWSER=2
WEIGHT_TRAFFIC=2
ISP_CONF
        chmod 640 /etc/securizar/auditoria-isp.conf
        log_change "Creado" "/etc/securizar/auditoria-isp.conf"
    else
        log_already "Configuración auditoria-isp.conf ya existe"
    fi

    # ── Script de auditoría ──
    cat > "${ISP_BIN_DIR}/auditoria-isp.sh" << 'ISP_AUDIT'
#!/bin/bash
# ============================================================
# Auditoría de protección contra espionaje ISP
# Securizar Módulo 38 - S10
# ============================================================
# Parametrizable via /etc/securizar/auditoria-isp.conf
# Uso: auditoria-isp.sh [--report] [--quiet] [--section SEC] [--help]
# ============================================================
set -euo pipefail

# ── Colores ──
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── Valores por defecto (sobreescritos por conf) ──
VPN_INTERFACES="wg0 tun0 tun1 proton0 mullvad-wg nordlynx"
VPN_PROCESSES="openvpn wireguard wg-quick"
DNS_LOCAL_ADDR="127.0.0.1"
DNS_SERVICE="unbound"
DNS_CONF="/etc/unbound/unbound.conf"
DNS_DOT_PORT=853
KS_NFT_TABLE="securizar_ks"
KS_IPT_CHAIN="SECURIZAR_KS"
NTS_SERVICE="chronyd"
PAD_SERVICE="securizar-traffic-pad.service"
FF_PROFILE_DIRS="/home/*/.mozilla/firefox/*.default* /root/.mozilla/firefox/*.default*"
REPORT_DIR="/var/lib/securizar/auditoria-isp"
REPORT_RETENTION=30
LOG_FILE="/var/log/securizar/auditoria-isp.log"
THRESHOLD_GOOD=80
THRESHOLD_FAIR=50
CHECK_EXTERNAL_IP=no
EXTERNAL_IP_URL="https://api.ipify.org"
CHECK_MAC_RANDOM=yes
CHECK_MDNS=yes
CHECK_DPI=yes
CHECK_HTTP_LEAKS=yes
CHECK_TOR=no
WEIGHT_VPN=3
WEIGHT_DNS=3
WEIGHT_NETWORK=2
WEIGHT_BROWSER=2
WEIGHT_TRAFFIC=2

# ── Cargar configuración ──
CONF_FILE="/etc/securizar/auditoria-isp.conf"
if [[ -f "$CONF_FILE" ]]; then
    while IFS= read -r _line; do
        _line="${_line#"${_line%%[![:space:]]*}"}"
        [[ -z "$_line" || "$_line" == \#* ]] && continue
        if [[ "$_line" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then
            eval "$_line"
        fi
    done < "$CONF_FILE"
fi

# ── Argumentos CLI ──
OPT_REPORT=0
OPT_QUIET=0
OPT_SECTION="all"
OPT_HELP=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --report|-r)  OPT_REPORT=1; shift ;;
        --quiet|-q)   OPT_QUIET=1; shift ;;
        --section|-s) OPT_SECTION="${2:-all}"; shift 2 ;;
        --help|-h)    OPT_HELP=1; shift ;;
        *) shift ;;
    esac
done

if [[ $OPT_HELP -eq 1 ]]; then
    echo "Uso: auditoria-isp.sh [OPCIONES]"
    echo ""
    echo "  --report, -r        Guardar reporte en $REPORT_DIR"
    echo "  --quiet, -q         Salida mínima (para cron)"
    echo "  --section, -s SEC   Solo ejecutar sección: vpn dns net browser traffic"
    echo "  --help, -h          Mostrar esta ayuda"
    echo ""
    echo "Configuración: $CONF_FILE"
    exit 0
fi

# ── Motor de auditoría ──
declare -a _check_names=()
declare -a _check_results=()
declare -a _check_details=()
declare -a _check_weights=()
declare -a _check_categories=()
issues=()

audit_check() {
    local category="$1" weight="$2" name="$3" result="$4" detail="${5:-}"
    _check_names+=("$name")
    _check_results+=("$result")
    _check_details+=("$detail")
    _check_weights+=("$weight")
    _check_categories+=("$category")

    if [[ $OPT_QUIET -eq 0 ]]; then
        if [[ "$result" -eq 0 ]]; then
            echo -e "  ${GREEN}[OK]${NC}  $name"
        else
            echo -e "  ${RED}[!!]${NC}  $name"
            [[ -n "$detail" ]] && echo -e "        ${DIM}$detail${NC}"
        fi
    fi
    [[ "$result" -ne 0 ]] && issues+=("$name|$detail")
}

section_header() {
    [[ $OPT_QUIET -eq 0 ]] && echo "" && echo -e "${BOLD}── $1 ──${NC}"
}

# ── Helpers para Firefox ──
ff_pref_exists() {
    local pref="$1" value="${2:-}"
    # shellcheck disable=SC2086
    for ff_dir in $FF_PROFILE_DIRS; do
        [[ -f "${ff_dir}/user.js" ]] || continue
        if [[ -n "$value" ]]; then
            grep -q "${pref}.*${value}" "${ff_dir}/user.js" 2>/dev/null && return 0
        else
            grep -q "$pref" "${ff_dir}/user.js" 2>/dev/null && return 0
        fi
    done
    return 1
}

# ── Cabecera ──
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
if [[ $OPT_QUIET -eq 0 ]]; then
    echo ""
    echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}  AUDITORÍA DE PROTECCIÓN CONTRA ISP${NC}"
    echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════════════${NC}"
    echo -e "  ${DIM}${TIMESTAMP}${NC}"
    echo -e "  ${DIM}Conf: ${CONF_FILE}${NC}"
fi

# ═══════════════════════════════════════════════════════════════
# CATEGORÍA: VPN (peso: WEIGHT_VPN)
# ═══════════════════════════════════════════════════════════════
if [[ "$OPT_SECTION" == "all" || "$OPT_SECTION" == "vpn" ]]; then
    section_header "VPN"

    # C1: Interfaz VPN activa
    vpn_fail=1
    vpn_iface_found=""
    for iface in $VPN_INTERFACES; do
        if ip link show "$iface" &>/dev/null; then
            vpn_fail=0
            vpn_iface_found="$iface"
            break
        fi
    done
    if [[ $vpn_fail -eq 0 ]]; then
        audit_check "vpn" "$WEIGHT_VPN" "Interfaz VPN activa ($vpn_iface_found)" 0
    else
        audit_check "vpn" "$WEIGHT_VPN" "Interfaz VPN activa" 1 \
            "No detectada. Interfaces buscadas: $VPN_INTERFACES"
    fi

    # C2: Proceso VPN ejecutándose
    vpn_proc_fail=1
    vpn_proc_found=""
    for proc in $VPN_PROCESSES; do
        if pgrep -x "$proc" &>/dev/null; then
            vpn_proc_fail=0
            vpn_proc_found="$proc"
            break
        fi
    done
    if [[ $vpn_proc_fail -eq 0 ]]; then
        audit_check "vpn" "$WEIGHT_VPN" "Proceso VPN activo ($vpn_proc_found)" 0
    else
        audit_check "vpn" "$WEIGHT_VPN" "Proceso VPN activo" 1 \
            "No detectado. Procesos buscados: $VPN_PROCESSES"
    fi

    # C3: Kill switch
    ks_fail=1
    ks_backend=""
    if nft list table inet "$KS_NFT_TABLE" &>/dev/null 2>&1; then
        ks_fail=0; ks_backend="nftables"
    elif iptables -L "$KS_IPT_CHAIN" -n &>/dev/null 2>&1; then
        ks_fail=0; ks_backend="iptables"
    elif command -v firewall-cmd &>/dev/null && \
         firewall-cmd --get-default-zone 2>/dev/null | grep -q "drop"; then
        ks_fail=0; ks_backend="firewalld"
    fi
    if [[ $ks_fail -eq 0 ]]; then
        audit_check "vpn" "$WEIGHT_VPN" "Kill switch VPN activo ($ks_backend)" 0
    else
        audit_check "vpn" "$WEIGHT_VPN" "Kill switch VPN activo" 1 \
            "Ejecutar: sudo /etc/securizar/vpn-killswitch.sh"
    fi
fi

# ═══════════════════════════════════════════════════════════════
# CATEGORÍA: DNS (peso: WEIGHT_DNS)
# ═══════════════════════════════════════════════════════════════
if [[ "$OPT_SECTION" == "all" || "$OPT_SECTION" == "dns" ]]; then
    section_header "DNS"

    # C4: DNS cifrado activo
    dot_fail=1
    if systemctl is-active "$DNS_SERVICE" &>/dev/null; then
        if [[ -f "$DNS_CONF" ]] && grep -q "forward-tls-upstream: yes" "$DNS_CONF" 2>/dev/null; then
            dot_fail=0
        fi
    fi
    if [[ $dot_fail -eq 0 ]]; then
        audit_check "dns" "$WEIGHT_DNS" "DNS-over-TLS ($DNS_SERVICE) activo" 0
    else
        audit_check "dns" "$WEIGHT_DNS" "DNS-over-TLS ($DNS_SERVICE) activo" 1 \
            "Ejecutar: sudo systemctl start $DNS_SERVICE"
    fi

    # C5: DNS apunta a resolvedor local
    dns_local_fail=1
    dns_source=""
    if grep -qE "^nameserver\s+${DNS_LOCAL_ADDR}" /etc/resolv.conf 2>/dev/null; then
        dns_local_fail=0; dns_source="resolv.conf"
    elif command -v nmcli &>/dev/null; then
        active_conn=$(nmcli -t -f NAME con show --active 2>/dev/null | head -1)
        if [[ -n "$active_conn" ]] && \
           nmcli -t -f ipv4.dns con show "$active_conn" 2>/dev/null | grep -q "$DNS_LOCAL_ADDR"; then
            dns_local_fail=0; dns_source="NetworkManager"
        fi
    fi
    if [[ $dns_local_fail -eq 0 ]]; then
        audit_check "dns" "$WEIGHT_DNS" "DNS local ($DNS_LOCAL_ADDR via $dns_source)" 0
    else
        audit_check "dns" "$WEIGHT_DNS" "DNS apunta a resolvedor local ($DNS_LOCAL_ADDR)" 1 \
            "DNS no redirigido a $DNS_SERVICE local"
    fi

    # C6: DNSSEC
    dnssec_fail=1
    if [[ -f "$DNS_CONF" ]] && grep -q "auto-trust-anchor-file" "$DNS_CONF" 2>/dev/null; then
        dnssec_fail=0
    fi
    audit_check "dns" "$WEIGHT_DNS" "DNSSEC habilitado" $dnssec_fail \
        "Añadir auto-trust-anchor-file a $DNS_CONF"

    # C7: Sin fugas DNS plaintext (puerto 53 saliente)
    dns_leak_fail=0
    plain_dns=$(ss -tnp 2>/dev/null | grep ":53 " | grep -v "127\.\|::1" || true)
    if [[ -n "$plain_dns" ]]; then
        dns_leak_fail=1
    fi
    audit_check "dns" "$WEIGHT_DNS" "Sin fugas DNS plaintext (puerto 53)" $dns_leak_fail \
        "Conexiones DNS sin cifrar detectadas al exterior"
fi

# ═══════════════════════════════════════════════════════════════
# CATEGORÍA: RED (peso: WEIGHT_NETWORK)
# ═══════════════════════════════════════════════════════════════
if [[ "$OPT_SECTION" == "all" || "$OPT_SECTION" == "net" ]]; then
    section_header "Red"

    # C8: IPv6 sin exposición pública
    ipv6_fail=0
    if [[ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ]]; then
        ipv6_disabled=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo "0")
        if [[ "$ipv6_disabled" != "1" ]]; then
            if ip -6 addr show scope global 2>/dev/null | grep -q "inet6"; then
                ipv6_fail=1
            fi
        fi
    fi
    audit_check "net" "$WEIGHT_NETWORK" "IPv6 sin exposición pública" $ipv6_fail \
        "IPv6 global detectada (posible fuga fuera de VPN)"

    # C9: NTS activo
    nts_fail=1
    nts_detail=""
    if systemctl is-active "$NTS_SERVICE" &>/dev/null; then
        nts_count=$(chronyc -n authdata 2>/dev/null | grep -c "NTS" || echo "0")
        if [[ "$nts_count" -gt 0 ]]; then
            nts_fail=0
            nts_detail="$nts_count fuentes NTS"
        fi
    fi
    if [[ $nts_fail -eq 0 ]]; then
        audit_check "net" "$WEIGHT_NETWORK" "NTS activo ($nts_detail)" 0
    else
        audit_check "net" "$WEIGHT_NETWORK" "NTS (Network Time Security) activo" 1 \
            "Usar chrony con servidores NTS: sudo systemctl start $NTS_SERVICE"
    fi

    # C10: MAC randomización (opcional)
    if [[ "$CHECK_MAC_RANDOM" == "yes" ]]; then
        mac_fail=1
        if command -v nmcli &>/dev/null; then
            wifi_mac=$(nmcli -t -f 802-11-wireless.cloned-mac-address con show --active 2>/dev/null | head -1 || true)
            eth_mac=$(nmcli -t -f 802-3-ethernet.cloned-mac-address con show --active 2>/dev/null | head -1 || true)
            if [[ "$wifi_mac" == *"random"* || "$wifi_mac" == *"stable"* || \
                  "$eth_mac" == *"random"* || "$eth_mac" == *"stable"* ]]; then
                mac_fail=0
            fi
        fi
        # También comprobar en NM conf global
        if [[ $mac_fail -eq 1 ]] && grep -rq "wifi.cloned-mac-address=random\|wifi.cloned-mac-address=stable" \
             /etc/NetworkManager/ 2>/dev/null; then
            mac_fail=0
        fi
        audit_check "net" "$WEIGHT_NETWORK" "MAC randomización configurada" $mac_fail \
            "nmcli con modify CONN wifi.cloned-mac-address random"
    fi

    # C11: mDNS/LLMNR desactivado (opcional)
    if [[ "$CHECK_MDNS" == "yes" ]]; then
        mdns_fail=0
        if systemctl is-active avahi-daemon &>/dev/null 2>&1; then
            mdns_fail=1
        fi
        if [[ -f /etc/systemd/resolved.conf ]] && \
           ! grep -q "^LLMNR=no" /etc/systemd/resolved.conf 2>/dev/null; then
            if systemctl is-active systemd-resolved &>/dev/null 2>&1; then
                # resolved activo sin LLMNR desactivado
                if resolvectl status 2>/dev/null | grep -qi "LLMNR.*yes"; then
                    mdns_fail=1
                fi
            fi
        fi
        audit_check "net" "$WEIGHT_NETWORK" "mDNS/LLMNR desactivado" $mdns_fail \
            "avahi-daemon activo o LLMNR habilitado (fuga en red local)"
    fi
fi

# ═══════════════════════════════════════════════════════════════
# CATEGORÍA: NAVEGADOR (peso: WEIGHT_BROWSER)
# ═══════════════════════════════════════════════════════════════
if [[ "$OPT_SECTION" == "all" || "$OPT_SECTION" == "browser" ]]; then
    section_header "Navegador"

    # C12: ECH
    ech_fail=1
    ff_pref_exists "echconfig.enabled" "true" && ech_fail=0
    audit_check "browser" "$WEIGHT_BROWSER" "ECH (Encrypted Client Hello)" $ech_fail \
        "SNI visible al ISP. Configurar network.dns.echconfig.enabled=true"

    # C13: WebRTC desactivado
    webrtc_fail=1
    ff_pref_exists "peerconnection.enabled" "false" && webrtc_fail=0
    audit_check "browser" "$WEIGHT_BROWSER" "WebRTC desactivado" $webrtc_fail \
        "WebRTC puede filtrar IP real. Configurar media.peerconnection.enabled=false"

    # C14: HTTPS-Only
    https_fail=1
    ff_pref_exists "https_only_mode" "true" && https_fail=0
    audit_check "browser" "$WEIGHT_BROWSER" "HTTPS-Only mode" $https_fail \
        "Tráfico HTTP visible al ISP. Configurar dom.security.https_only_mode=true"

    # C15: Privacidad hardening (telemetría + fingerprint resistance)
    priv_fail=1
    if ff_pref_exists "resistFingerprinting" "true" && \
       ff_pref_exists "toolkit.telemetry.enabled" "false"; then
        priv_fail=0
    fi
    audit_check "browser" "$WEIGHT_BROWSER" "Fingerprint resistance + telemetría off" $priv_fail \
        "Configurar privacy.resistFingerprinting=true, toolkit.telemetry.enabled=false"
fi

# ═══════════════════════════════════════════════════════════════
# CATEGORÍA: TRÁFICO (peso: WEIGHT_TRAFFIC)
# ═══════════════════════════════════════════════════════════════
if [[ "$OPT_SECTION" == "all" || "$OPT_SECTION" == "traffic" ]]; then
    section_header "Tráfico"

    # C16: Traffic padding activo
    pad_fail=1
    if systemctl is-active "$PAD_SERVICE" &>/dev/null; then
        pad_fail=0
    fi
    audit_check "traffic" "$WEIGHT_TRAFFIC" "Traffic padding activo ($PAD_SERVICE)" $pad_fail \
        "Patrones de tráfico expuestos al ISP"

    # C17: Sin conexiones HTTP activas (opcional)
    if [[ "$CHECK_HTTP_LEAKS" == "yes" ]]; then
        http_fail=0
        http_count=$(ss -tnp state established 2>/dev/null | grep -c ":80 " || echo "0")
        if [[ "$http_count" -gt 0 ]]; then
            http_fail=1
        fi
        audit_check "traffic" "$WEIGHT_TRAFFIC" "Sin conexiones HTTP activas ($http_count)" $http_fail \
            "Conexiones HTTP (sin cifrar) visibles al ISP"
    fi

    # C18: DPI evasión configurada (opcional)
    if [[ "$CHECK_DPI" == "yes" ]]; then
        dpi_fail=1
        if command -v obfs4proxy &>/dev/null; then
            dpi_fail=0
        elif command -v stunnel &>/dev/null || command -v stunnel4 &>/dev/null; then
            dpi_fail=0
        elif [[ -f /etc/tor/torrc.d/bridges.conf ]]; then
            dpi_fail=0
        elif [[ -f /etc/securizar/stunnel-vpn-wrap.conf ]]; then
            dpi_fail=0
        fi
        audit_check "traffic" "$WEIGHT_TRAFFIC" "DPI evasión configurada" $dpi_fail \
            "Instalar obfs4proxy o stunnel para ofuscar tráfico VPN/Tor"
    fi

    # C19: Tor disponible (opcional)
    if [[ "$CHECK_TOR" == "yes" ]]; then
        tor_fail=1
        if command -v tor &>/dev/null && systemctl is-active tor &>/dev/null 2>&1; then
            tor_fail=0
        fi
        audit_check "traffic" "$WEIGHT_TRAFFIC" "Tor activo" $tor_fail \
            "Tor no detectado. Instalar: sudo zypper install tor"
    fi

    # C20: IP externa (opcional - requiere internet)
    if [[ "$CHECK_EXTERNAL_IP" == "yes" ]]; then
        ext_ip_fail=1
        ext_ip=$(curl -s --max-time 5 "$EXTERNAL_IP_URL" 2>/dev/null || true)
        if [[ -n "$ext_ip" ]] && [[ "$ext_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            # IP obtenida, verificar si es diferente a la IP del gateway local
            gw_iface=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
            local_ip=$(ip -4 addr show "$gw_iface" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1 || true)
            if [[ -n "$local_ip" ]] && [[ "$ext_ip" != "$local_ip" ]]; then
                ext_ip_fail=0
            elif [[ -z "$local_ip" ]]; then
                ext_ip_fail=0  # No se puede comparar, asumimos VPN
            fi
        fi
        if [[ $ext_ip_fail -eq 0 ]]; then
            audit_check "traffic" "$WEIGHT_TRAFFIC" "IP externa enmascarada ($ext_ip)" 0
        else
            audit_check "traffic" "$WEIGHT_TRAFFIC" "IP externa enmascarada" 1 \
                "IP $ext_ip coincide con IP local - sin VPN activa"
        fi
    fi
fi

# ═══════════════════════════════════════════════════════════════
# PUNTUACIÓN PONDERADA
# ═══════════════════════════════════════════════════════════════
total_weighted=0
pass_weighted=0
total_checks=${#_check_names[@]}

for i in $(seq 0 $((total_checks - 1))); do
    w=${_check_weights[$i]}
    total_weighted=$((total_weighted + w))
    if [[ "${_check_results[$i]}" -eq 0 ]]; then
        pass_weighted=$((pass_weighted + w))
    fi
done

pct=0
if [[ $total_weighted -gt 0 ]]; then
    pct=$(( pass_weighted * 100 / total_weighted ))
fi

pass_count=0
fail_count=0
for r in "${_check_results[@]}"; do
    if [[ "$r" -eq 0 ]]; then
        pass_count=$((pass_count + 1))
    else
        fail_count=$((fail_count + 1))
    fi
done

if [[ $pct -ge $THRESHOLD_GOOD ]]; then
    label="BUENO"
    color="$GREEN"
elif [[ $pct -ge $THRESHOLD_FAIR ]]; then
    label="MEJORABLE"
    color="$YELLOW"
else
    label="DEFICIENTE"
    color="$RED"
fi

if [[ $OPT_QUIET -eq 0 ]]; then
    echo ""
    echo -e "${BOLD}══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Checks: ${GREEN}${pass_count} OK${NC} / ${RED}${fail_count} FAIL${NC} / ${total_checks} total"
    echo -e "  Puntuación ponderada: ${color}${BOLD}${pass_weighted}/${total_weighted}${NC} (${color}${pct}%${NC})"
    echo -e "  Nivel: ${color}${BOLD}${label}${NC}"
    echo ""

    if [[ ${#issues[@]} -gt 0 ]]; then
        echo -e "  ${YELLOW}Puntos a mejorar:${NC}"
        for issue in "${issues[@]}"; do
            IFS='|' read -r iname idetail <<< "$issue"
            echo -e "    ${RED}•${NC} $iname"
            [[ -n "$idetail" ]] && echo -e "      ${DIM}$idetail${NC}"
        done
        echo ""
    fi

    # Resumen por categoría
    echo -e "  ${CYAN}Desglose por categoría:${NC}"
    for cat in vpn dns net browser traffic; do
        cat_pass=0; cat_total=0; cat_w_pass=0; cat_w_total=0
        for i in $(seq 0 $((total_checks - 1))); do
            [[ "${_check_categories[$i]}" != "$cat" ]] && continue
            w=${_check_weights[$i]}
            cat_w_total=$((cat_w_total + w))
            cat_total=$((cat_total + 1))
            if [[ "${_check_results[$i]}" -eq 0 ]]; then
                cat_pass=$((cat_pass + 1))
                cat_w_pass=$((cat_w_pass + w))
            fi
        done
        [[ $cat_total -eq 0 ]] && continue
        cat_pct=$(( cat_w_pass * 100 / cat_w_total ))
        if [[ $cat_pct -ge $THRESHOLD_GOOD ]]; then cat_c="$GREEN"
        elif [[ $cat_pct -ge $THRESHOLD_FAIR ]]; then cat_c="$YELLOW"
        else cat_c="$RED"
        fi
        printf "    %-12s ${cat_c}%3d%%${NC}  (%d/%d checks)\n" "$cat" "$cat_pct" "$cat_pass" "$cat_total"
    done
    echo ""
    echo -e "  ${DIM}Conf: ${CONF_FILE}${NC}"
    echo ""
fi

# ── Guardar reporte ──
if [[ $OPT_REPORT -eq 1 ]]; then
    mkdir -p "$REPORT_DIR"
    report_file="${REPORT_DIR}/auditoria-isp-$(date +%Y%m%d-%H%M%S).txt"
    {
        echo "AUDITORÍA DE PROTECCIÓN CONTRA ISP"
        echo "Fecha: $TIMESTAMP"
        echo "Nivel: $label ($pct%)"
        echo "Checks: ${pass_count}/${total_checks} OK"
        echo "Puntuación ponderada: ${pass_weighted}/${total_weighted}"
        echo ""
        echo "=== RESULTADOS ==="
        for i in $(seq 0 $((total_checks - 1))); do
            if [[ "${_check_results[$i]}" -eq 0 ]]; then
                echo "  [OK]  ${_check_names[$i]}"
            else
                echo "  [!!]  ${_check_names[$i]}"
                [[ -n "${_check_details[$i]}" ]] && echo "        ${_check_details[$i]}"
            fi
        done
        echo ""
        echo "=== CATEGORÍAS ==="
        for cat in vpn dns net browser traffic; do
            cat_pass=0; cat_total=0
            for i in $(seq 0 $((total_checks - 1))); do
                [[ "${_check_categories[$i]}" != "$cat" ]] && continue
                cat_total=$((cat_total + 1))
                [[ "${_check_results[$i]}" -eq 0 ]] && cat_pass=$((cat_pass + 1))
            done
            [[ $cat_total -eq 0 ]] && continue
            printf "  %-12s %d/%d\n" "$cat" "$cat_pass" "$cat_total"
        done
    } > "$report_file"
    chmod 640 "$report_file"
    [[ $OPT_QUIET -eq 0 ]] && echo -e "  ${GREEN}Reporte:${NC} $report_file"

    # Rotación de reportes antiguos
    if [[ -d "$REPORT_DIR" ]]; then
        ls -t "$REPORT_DIR"/auditoria-isp-*.txt 2>/dev/null | \
            tail -n "+$((REPORT_RETENTION + 1))" | xargs rm -f 2>/dev/null || true
    fi
fi

# ── Log ──
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
echo "${TIMESTAMP} nivel=${label} pct=${pct} ok=${pass_count}/${total_checks} weighted=${pass_weighted}/${total_weighted}" \
    >> "$LOG_FILE" 2>/dev/null || true

# Código de salida refleja nivel
if [[ $pct -ge $THRESHOLD_GOOD ]]; then
    exit 0
elif [[ $pct -ge $THRESHOLD_FAIR ]]; then
    exit 1
else
    exit 2
fi
ISP_AUDIT
    chmod 755 "${ISP_BIN_DIR}/auditoria-isp.sh"
    log_change "Creado" "${ISP_BIN_DIR}/auditoria-isp.sh"

    # Cron semanal (usa --report --quiet para salida mínima + reporte persistente)
    mkdir -p /etc/cron.weekly
    cat > /etc/cron.weekly/auditoria-isp << 'CRON_ISP'
#!/bin/bash
# Auditoría semanal de protección ISP - Securizar M38
# Genera reporte en /var/lib/securizar/auditoria-isp/ (rotación automática)
/usr/local/bin/auditoria-isp.sh --report --quiet 2>/dev/null
rc=$?
# Alertar si nivel es DEFICIENTE (exit code 2)
if [[ $rc -eq 2 ]]; then
    logger -t securizar-isp "ALERTA: Auditoría ISP nivel DEFICIENTE"
fi
CRON_ISP
    chmod 755 /etc/cron.weekly/auditoria-isp
    log_change "Creado" "/etc/cron.weekly/auditoria-isp (semanal, --report --quiet)"

    log_info "Auditoría de metadatos ISP instalada (20 checks, parametrizable)"
    log_info "Configuración: /etc/securizar/auditoria-isp.conf"
    log_info "Uso: auditoria-isp.sh [--report] [--quiet] [--section vpn|dns|net|browser|traffic]"
else
    log_skip "Auditoría de metadatos ISP"
fi
fi  # S10

if [[ "$ISP_SECTION" == "all" ]]; then
# ============================================================
# RESUMEN FINAL
# ============================================================
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   MÓDULO 38 COMPLETADO                                      ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║                                                              ║"
echo "║   Herramientas instaladas:                                   ║"
echo "║     • /etc/securizar/vpn-killswitch.sh       (kill switch)   ║"
echo "║     • /usr/local/bin/detectar-dns-leak.sh    (DNS leaks)     ║"
echo "║     • /usr/local/bin/detectar-http-inseguro.sh (HTTP)        ║"
echo "║     • /usr/local/bin/securizar-traffic-pad.sh  (padding)     ║"
echo "║     • /usr/local/bin/auditoria-isp.sh         (20 checks)   ║"
echo "║     • /etc/securizar/auditoria-isp.conf      (configuración)║"
echo "║                                                              ║"
echo "║   Auditoría: auditoria-isp.sh [--report] [--quiet]          ║"
echo "║   Secciones: --section vpn|dns|net|browser|traffic           ║"
echo "║   Reportes:  /var/lib/securizar/auditoria-isp/               ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

log_info "Módulo 38 - Protección contra espionaje ISP completado"
show_changes_summary
fi  # all - resumen final
