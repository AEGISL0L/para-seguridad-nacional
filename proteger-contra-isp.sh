#!/bin/bash
# ============================================================
# PROTECCIÓN CONTRA ESPIONAJE ISP - Módulo 38
# Linux Multi-Distro (openSUSE, Debian/Ubuntu, RHEL/Fedora, Arch)
# ============================================================
# Protege contra vigilancia a nivel de ISP:
#   - Kill switch VPN (nftables/iptables/firewalld DROP si cae la VPN)
#   - Prevención de fugas DNS (DoT/DoH auto-fallback + DNSSEC)
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
#   S11 - Cloudflare WARP + Gateway (perimetro anti-ISP)
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

# ── Helpers DNS dual-mode ────────────────────────────────────
_test_dot_port() {
    # Intenta TLS handshake con Cloudflare y Quad9 en puerto 853
    local _target
    for _target in 1.1.1.1 9.9.9.9; do
        if timeout 5 bash -c "echo | openssl s_client -connect ${_target}:853 2>/dev/null" | grep -q "CONNECTED"; then
            return 0
        fi
    done
    return 1
}

_detect_dns_resolver() {
    if systemctl is-active unbound &>/dev/null; then echo "unbound"
    elif systemctl is-active dnscrypt-proxy &>/dev/null; then echo "dnscrypt-proxy"
    else echo "none"; fi
}

# ── Verificación exhaustiva ──────────────────────────────────
_isp_verificacion_exhaustiva() {
    local ok=0 total=40
    local _r _dns_resolver
    _dns_resolver=$(_detect_dns_resolver)

    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║   VERIFICACIÓN EXHAUSTIVA - Protección contra ISP            ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""

    # ── VPN (6 checks) ──
    echo -e "  ${BOLD}[VPN]${NC}"

    _r="!!"
    if [[ -f /etc/securizar/vpn-killswitch.sh ]]; then _r="OK"; ((ok++)) || true; fi
    echo -e "    ${_r} Script kill switch existe"

    _r="!!"
    if [[ -f /etc/securizar/vpn-killswitch-off.sh ]]; then _r="OK"; ((ok++)) || true; fi
    echo -e "    ${_r} Script kill switch OFF existe"

    _r="!!"
    if command -v nft &>/dev/null && nft list table inet securizar_ks &>/dev/null 2>&1; then
        _r="OK"; ((ok++)) || true
    elif iptables -L SECURIZAR_KS -n &>/dev/null 2>&1; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} Kill switch ACTIVO (nft/iptables)"

    _r="!!"
    if systemctl is-enabled securizar-vpn-killswitch.service &>/dev/null; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} Servicio kill switch habilitado"

    _r="!!"
    if ip link show 2>/dev/null | grep -qE '(wg[0-9]|tun[0-9]|tap[0-9]|proton[0-9]|mullvad|nordlynx|CloudflareWARP)' || \
       { command -v wg &>/dev/null && wg show interfaces 2>/dev/null | grep -q .; }; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} Interfaz VPN activa"

    # Persistencia kill switch: reglas sobreviven restart de NetworkManager
    _r="!!"
    if systemctl is-enabled securizar-vpn-killswitch.service &>/dev/null; then
        local _ks_wants=""
        _ks_wants=$(systemctl show securizar-vpn-killswitch.service -p WantedBy --value 2>/dev/null || true)
        if [[ "$_ks_wants" == *"multi-user.target"* ]] || [[ "$_ks_wants" == *"network-online.target"* ]]; then
            # Verificar que el servicio no depende de NM (debe cargar antes o independiente)
            local _ks_after=""
            _ks_after=$(systemctl show securizar-vpn-killswitch.service -p After --value 2>/dev/null || true)
            if [[ "$_ks_after" != *"NetworkManager"* ]] || \
               [[ -f /etc/systemd/system/securizar-vpn-killswitch.service ]]; then
                _r="OK"; ((ok++)) || true
            fi
        fi
    fi
    echo -e "    ${_r} Kill switch persiste tras restart NM"
    echo ""

    # ── DNS (7 checks) ──
    echo -e "  ${BOLD}[DNS]${NC} (modo: ${_dns_resolver})"

    _r="!!"
    if [[ "$_dns_resolver" != "none" ]]; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} DNS cifrado activo (unbound o dnscrypt-proxy)"

    _r="!!"
    if [[ "$_dns_resolver" == "unbound" ]]; then
        if [[ -f /etc/unbound/unbound.conf.d/securizar-dot.conf ]] && grep -q 'forward-tls-upstream' /etc/unbound/unbound.conf.d/securizar-dot.conf 2>/dev/null; then
            _r="OK"; ((ok++)) || true
        elif [[ -f /etc/unbound/unbound.conf ]] && grep -q 'forward-tls-upstream' /etc/unbound/unbound.conf 2>/dev/null; then
            _r="OK"; ((ok++)) || true
        fi
    elif [[ "$_dns_resolver" == "dnscrypt-proxy" ]]; then
        if [[ -f /etc/dnscrypt-proxy/dnscrypt-proxy.toml ]] && grep -q 'doh_servers.*true' /etc/dnscrypt-proxy/dnscrypt-proxy.toml 2>/dev/null; then
            _r="OK"; ((ok++)) || true
        fi
    fi
    echo -e "    ${_r} DoT o DoH configurado"

    _r="!!"
    if [[ "$_dns_resolver" == "unbound" ]]; then
        if [[ -f /etc/unbound/unbound.conf.d/securizar-dot.conf ]] && grep -q 'val-clean-additional\|auto-trust-anchor-file' /etc/unbound/unbound.conf.d/securizar-dot.conf 2>/dev/null; then
            _r="OK"; ((ok++)) || true
        elif [[ -f /etc/unbound/unbound.conf ]] && grep -q 'auto-trust-anchor-file' /etc/unbound/unbound.conf 2>/dev/null; then
            _r="OK"; ((ok++)) || true
        fi
    elif [[ "$_dns_resolver" == "dnscrypt-proxy" ]]; then
        if [[ -f /etc/dnscrypt-proxy/dnscrypt-proxy.toml ]] && grep -q 'require_dnssec.*true' /etc/dnscrypt-proxy/dnscrypt-proxy.toml 2>/dev/null; then
            _r="OK"; ((ok++)) || true
        fi
    fi
    echo -e "    ${_r} DNSSEC habilitado"

    _r="!!"
    if grep -q '^nameserver 127\.0\.0\.1' /etc/resolv.conf 2>/dev/null; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} resolv.conf apunta a 127.0.0.1"

    _r="!!"
    if ! systemctl is-active avahi-daemon &>/dev/null; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} avahi-daemon inactivo"

    _r="!!"
    if systemctl is-enabled securizar-dns-fallback-monitor.timer &>/dev/null; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} Monitor fallback DNS activo"

    # DNS real-time: verificar que consultas DNS pasan por resolver cifrado
    _r="!!"
    if [[ "$_dns_resolver" != "none" ]]; then
        if command -v dig &>/dev/null; then
            local _dig_server=""
            _dig_server=$(dig +short +timeout=3 +tries=1 cloudflare.com @127.0.0.1 2>/dev/null | head -1 || true)
            if [[ -n "$_dig_server" ]]; then
                _r="OK"; ((ok++)) || true
            fi
        elif command -v nslookup &>/dev/null; then
            if nslookup cloudflare.com 127.0.0.1 &>/dev/null; then
                _r="OK"; ((ok++)) || true
            fi
        else
            # Sin dig ni nslookup: verificar que el puerto responde
            if timeout 3 bash -c 'echo > /dev/tcp/127.0.0.1/53' 2>/dev/null; then
                _r="OK"; ((ok++)) || true
            fi
        fi
    fi
    echo -e "    ${_r} DNS resolver responde en localhost"
    echo ""

    # ── Privacidad (4 checks) ──
    echo -e "  ${BOLD}[Privacidad]${NC}"

    _r="!!"
    if [[ -f /etc/NetworkManager/conf.d/91-securizar-mac.conf ]] || \
       [[ -f /etc/NetworkManager/conf.d/99-securizar-mac.conf ]]; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} MAC randomización configurada"

    _r="!!"
    if [[ -f /etc/sysctl.d/99-securizar-ipv6.conf ]] && \
       sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null | grep -q '1'; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} IPv6 deshabilitado (sysctl)"

    # IPv6 real: verificar TODAS las interfaces no-loopback
    _r="!!"
    local _ipv6_leak=0
    while IFS= read -r _iface; do
        _iface="${_iface%%:*}"
        _iface="${_iface##* }"
        [[ "$_iface" == "lo" ]] && continue
        local _ipv6_val=""
        _ipv6_val=$(sysctl -n "net.ipv6.conf.${_iface}.disable_ipv6" 2>/dev/null || echo "0")
        if [[ "$_ipv6_val" != "1" ]]; then
            _ipv6_leak=1
            break
        fi
    done < <(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' || true)
    if [[ $_ipv6_leak -eq 0 ]]; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} IPv6 deshabilitado en TODAS las interfaces"

    # mDNS/LLMNR leak: verificar que no se resuelve por multicast
    _r="!!"
    local _mdns_leak=0
    if systemctl is-active avahi-daemon &>/dev/null; then
        _mdns_leak=1
    fi
    # Verificar que systemd-resolved no usa mDNS/LLMNR
    if systemctl is-active systemd-resolved &>/dev/null; then
        local _resolved_mdns=""
        _resolved_mdns=$(resolvectl mdns 2>/dev/null | grep -i 'yes' || true)
        local _resolved_llmnr=""
        _resolved_llmnr=$(resolvectl llmnr 2>/dev/null | grep -i 'yes' || true)
        if [[ -n "$_resolved_mdns" ]] || [[ -n "$_resolved_llmnr" ]]; then
            _mdns_leak=1
        fi
    fi
    # Verificar que no hay sockets escuchando en puertos mDNS/LLMNR
    if ss -ulnp 2>/dev/null | grep -qE ':5353\b|:5355\b'; then
        _mdns_leak=1
    fi
    if [[ $_mdns_leak -eq 0 ]]; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} Sin fugas mDNS/LLMNR (5353/5355)"
    echo ""

    # ── Red (3 checks) ──
    echo -e "  ${BOLD}[Red]${NC}"

    _r="!!"
    if command -v obfs4proxy &>/dev/null; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} obfs4proxy disponible"

    _r="!!"
    if systemctl is-active securizar-traffic-pad.service &>/dev/null; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} Traffic padding activo"

    _r="!!"
    if [[ "$_dns_resolver" == "unbound" ]]; then
        if command -v nft &>/dev/null && nft list table inet securizar_ks 2>/dev/null | grep -q '853'; then
            _r="OK"; ((ok++)) || true
        elif command -v firewall-cmd &>/dev/null && firewall-cmd --list-ports 2>/dev/null | grep -q '853' 2>/dev/null; then
            _r="OK"; ((ok++)) || true
        elif iptables -L SECURIZAR_KS -n 2>/dev/null | grep -q '853'; then
            _r="OK"; ((ok++)) || true
        fi
        echo -e "    ${_r} Puerto 853 (DoT) en firewall"
    elif [[ "$_dns_resolver" == "dnscrypt-proxy" ]]; then
        if command -v nft &>/dev/null && nft list table inet securizar_ks 2>/dev/null | grep -q '443'; then
            _r="OK"; ((ok++)) || true
        elif iptables -L SECURIZAR_KS -n 2>/dev/null | grep -q '443'; then
            _r="OK"; ((ok++)) || true
        fi
        echo -e "    ${_r} Firewall DoH (443 a resolvers)"
    else
        if command -v nft &>/dev/null && nft list table inet securizar_ks 2>/dev/null | grep -q '853'; then
            _r="OK"; ((ok++)) || true
        fi
        echo -e "    ${_r} Puerto DNS en firewall"
    fi
    echo ""

    # ── Tiempo (2 checks) ──
    echo -e "  ${BOLD}[Tiempo]${NC}"

    _r="!!"
    if [[ -f /etc/chrony.d/securizar-nts.conf ]] && systemctl is-active chronyd &>/dev/null; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} Chrony NTS activo"

    _r="!!"
    if ! systemctl is-active systemd-timesyncd &>/dev/null; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} timesyncd inactivo"
    echo ""

    # ── Navegador (4 checks) ──
    echo -e "  ${BOLD}[Navegador]${NC}"

    local _ff_found=0 _ech=0 _webrtc=0 _https=0
    # Rutas estándar
    for ff_dir in /home/*/.mozilla/firefox/*.default* /root/.mozilla/firefox/*.default*; do
        [[ -f "${ff_dir}/user.js" ]] || continue
        _ff_found=1
        grep -q 'network.dns.echconfig.enabled.*true' "${ff_dir}/user.js" 2>/dev/null && _ech=1 || true
        grep -q 'media.peerconnection.enabled.*false' "${ff_dir}/user.js" 2>/dev/null && _webrtc=1 || true
        grep -q 'dom.security.https_only_mode.*true' "${ff_dir}/user.js" 2>/dev/null && _https=1 || true
    done
    # Snap Firefox
    for ff_dir in /home/*/snap/firefox/common/.mozilla/firefox/*.default*; do
        [[ -f "${ff_dir}/user.js" ]] || continue
        _ff_found=1
        grep -q 'network.dns.echconfig.enabled.*true' "${ff_dir}/user.js" 2>/dev/null && _ech=1 || true
        grep -q 'media.peerconnection.enabled.*false' "${ff_dir}/user.js" 2>/dev/null && _webrtc=1 || true
        grep -q 'dom.security.https_only_mode.*true' "${ff_dir}/user.js" 2>/dev/null && _https=1 || true
    done
    # Flatpak Firefox
    for ff_dir in /home/*/.var/app/org.mozilla.firefox/.mozilla/firefox/*.default*; do
        [[ -f "${ff_dir}/user.js" ]] || continue
        _ff_found=1
        grep -q 'network.dns.echconfig.enabled.*true' "${ff_dir}/user.js" 2>/dev/null && _ech=1 || true
        grep -q 'media.peerconnection.enabled.*false' "${ff_dir}/user.js" 2>/dev/null && _webrtc=1 || true
        grep -q 'dom.security.https_only_mode.*true' "${ff_dir}/user.js" 2>/dev/null && _https=1 || true
    done

    _r="!!"
    if [[ $_ech -eq 1 ]]; then _r="OK"; ((ok++)) || true; fi
    echo -e "    ${_r} ECH (Encrypted Client Hello)"

    _r="!!"
    if [[ $_webrtc -eq 1 ]]; then _r="OK"; ((ok++)) || true; fi
    echo -e "    ${_r} WebRTC desactivado"

    _r="!!"
    if [[ $_https -eq 1 ]]; then _r="OK"; ((ok++)) || true; fi
    echo -e "    ${_r} HTTPS-Only mode"

    # Perfiles Firefox detectados
    _r="!!"
    if [[ $_ff_found -eq 1 ]]; then _r="OK"; ((ok++)) || true; fi
    echo -e "    ${_r} Perfiles Firefox detectados (estándar/Snap/Flatpak)"
    echo ""

    # ── WARP (3 checks, solo si WARP está instalado) ──
    if command -v warp-cli &>/dev/null; then
        echo -e "  ${BOLD}[WARP]${NC}"

        _r="OK"; ((ok++)) || true
        echo -e "    ${_r} warp-cli instalado"

        _r="!!"
        if systemctl is-enabled warp-svc &>/dev/null; then _r="OK"; ((ok++)) || true; fi
        echo -e "    ${_r} warp-svc habilitado"

        _r="!!"
        if warp-cli status 2>/dev/null | grep -qi 'connected'; then _r="OK"; ((ok++)) || true; fi
        echo -e "    ${_r} WARP conectado"
        echo ""
    else
        # WARP no instalado: reducir total (no penalizar)
        ((total -= 3)) || true
    fi

    # ── Herramientas (3 checks) ──
    echo -e "  ${BOLD}[Herramientas]${NC}"

    _r="!!"
    if [[ -x /usr/local/bin/auditoria-isp.sh ]]; then _r="OK"; ((ok++)) || true; fi
    echo -e "    ${_r} auditoria-isp.sh"

    _r="!!"
    if [[ -x /usr/local/bin/detectar-dns-leak.sh ]]; then _r="OK"; ((ok++)) || true; fi
    echo -e "    ${_r} detectar-dns-leak.sh"

    _r="!!"
    if [[ -x /usr/local/bin/detectar-http-inseguro.sh ]]; then _r="OK"; ((ok++)) || true; fi
    echo -e "    ${_r} detectar-http-inseguro.sh"
    echo ""

    # ── Integración cross-section (4 checks) ──
    echo -e "  ${BOLD}[Integración]${NC}"

    # VPN + Kill switch + DNS: la tríada fundamental
    _r="!!"
    local _vpn_ok=0 _ks_ok=0 _dns_ok=0
    if ip link show 2>/dev/null | grep -qE '(wg[0-9]|tun[0-9]|tap[0-9]|proton[0-9]|mullvad|nordlynx|CloudflareWARP)' || \
       { command -v wg &>/dev/null && wg show interfaces 2>/dev/null | grep -q .; }; then
        _vpn_ok=1
    fi
    if command -v nft &>/dev/null && nft list table inet securizar_ks &>/dev/null 2>&1; then
        _ks_ok=1
    elif iptables -L SECURIZAR_KS -n &>/dev/null 2>&1; then
        _ks_ok=1
    fi
    if [[ "$_dns_resolver" != "none" ]]; then _dns_ok=1; fi
    if [[ $_vpn_ok -eq 1 ]] && [[ $_ks_ok -eq 1 ]] && [[ $_dns_ok -eq 1 ]]; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} Tríada VPN + Kill switch + DNS cifrado"

    # Kill switch + IPv6 disabled: no bypass posible
    _r="!!"
    if [[ $_ks_ok -eq 1 ]] && \
       sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null | grep -q '1'; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} Kill switch + IPv6 deshabilitado (sin bypass)"

    # DNS cifrado + resolv.conf local: no DNS leak posible
    _r="!!"
    if [[ $_dns_ok -eq 1 ]] && grep -q '^nameserver 127\.0\.0\.1' /etc/resolv.conf 2>/dev/null; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} DNS cifrado + resolv.conf local (sin DNS leak)"

    # Firewall bloquea DNS externo (puerto 53 saliente solo a localhost)
    _r="!!"
    if command -v nft &>/dev/null && nft list table inet securizar_ks &>/dev/null 2>&1; then
        local _nft_ks=""
        _nft_ks=$(nft list table inet securizar_ks 2>/dev/null) || true
        if echo "$_nft_ks" | grep -qE 'dport 53.*(drop|reject)'; then
            _r="OK"; ((ok++)) || true
        fi
    elif iptables -L SECURIZAR_KS -n 2>/dev/null | grep -qE 'dpt:53.*(DROP|REJECT)'; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} Firewall bloquea DNS externo (puerto 53)"
    echo ""

    # ── Scoring ──
    echo "  ─────────────────────────────────────────"
    local nivel color
    if [[ $ok -ge $((total * 90 / 100)) ]]; then
        nivel="EXCELENTE"; color="${GREEN}"
    elif [[ $ok -ge $((total * 65 / 100)) ]]; then
        nivel="BUENO"; color="${CYAN}"
    elif [[ $ok -ge $((total * 40 / 100)) ]]; then
        nivel="MEJORABLE"; color="${YELLOW}"
    else
        nivel="DEFICIENTE"; color="${RED}"
    fi
    local pct=0
    [[ $total -gt 0 ]] && pct=$((ok * 100 / total)) || true
    echo -e "  Resultado: ${BOLD}${ok}/${total} OK${NC} (${pct}%) — ${color}${BOLD}${nivel}${NC}"

    # Resumen de brechas críticas
    local _gaps=0
    echo ""
    if [[ $_vpn_ok -eq 0 ]]; then
        echo -e "  ${RED}▸${NC} ${BOLD}Sin VPN activa${NC} — todo el tráfico es visible al ISP"
        ((_gaps++)) || true
    fi
    if [[ $_ks_ok -eq 0 ]] && [[ $_vpn_ok -eq 1 ]]; then
        echo -e "  ${RED}▸${NC} ${BOLD}VPN sin kill switch${NC} — tráfico se filtra si cae la VPN"
        ((_gaps++)) || true
    fi
    if [[ $_dns_ok -eq 0 ]]; then
        echo -e "  ${RED}▸${NC} ${BOLD}Sin DNS cifrado${NC} — el ISP ve cada dominio que visitas"
        ((_gaps++)) || true
    fi
    if [[ $_ipv6_leak -eq 1 ]]; then
        echo -e "  ${YELLOW}▸${NC} ${BOLD}IPv6 activo en alguna interfaz${NC} — posible bypass de VPN"
        ((_gaps++)) || true
    fi
    if [[ $_mdns_leak -eq 1 ]]; then
        echo -e "  ${YELLOW}▸${NC} ${BOLD}mDNS/LLMNR activo${NC} — dominios .local visibles al ISP"
        ((_gaps++)) || true
    fi
    if [[ $_ff_found -eq 0 ]]; then
        echo -e "  ${YELLOW}▸${NC} ${BOLD}Sin perfiles Firefox${NC} — protecciones de navegador no verificables"
        ((_gaps++)) || true
    fi
    if [[ $_gaps -eq 0 ]]; then
        echo -e "  ${GREEN}▸${NC} Sin brechas críticas detectadas"
    fi
    echo ""
}

# ── Handler --verify ─────────────────────────────────────────
if [[ "$ISP_SECTION" == "--verify" ]]; then
    _isp_verificacion_exhaustiva
    exit 0
fi

# ── Pre-check: detectar secciones ya aplicadas ──────────────
if [[ "$ISP_SECTION" == "all" ]]; then
_precheck 11
_pc 'check_file_exists /etc/securizar/vpn-killswitch.sh && check_file_exists /etc/systemd/system/securizar-vpn-killswitch.service && check_file_exists /etc/sysctl.d/99-securizar-ipv6.conf'
_pc 'check_service_enabled unbound || check_service_enabled dnscrypt-proxy'
_pc true  # S3 - ECH Firefox (perfiles dinámicos)
_pc true  # S4 - WebRTC Firefox (perfiles dinámicos)
_pc true  # S5 - DPI evasion (opción interactiva)
_pc true  # S6 - privacidad navegador (perfiles dinámicos)
_pc true  # S7 - HTTPS-only (perfiles dinámicos)
_pc 'check_file_exists /etc/chrony.d/securizar-nts.conf'
_pc 'check_service_enabled securizar-traffic-pad.service'
_pc 'check_executable /usr/local/bin/auditoria-isp.sh'
_pc 'command -v warp-cli &>/dev/null && systemctl is-enabled warp-svc &>/dev/null'
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
echo -e "  ${CYAN}S2${NC}  Prevención de fugas DNS (DoT/DoH auto, DNSSEC)"
echo -e "  ${CYAN}S3${NC}  ECH (Encrypted Client Hello, oculta SNI)"
echo -e "  ${CYAN}S4${NC}  Prevención de fugas WebRTC"
echo -e "  ${CYAN}S5${NC}  Evasión de DPI (obfs4 / stunnel)"
echo -e "  ${CYAN}S6${NC}  Hardening de privacidad del navegador"
echo -e "  ${CYAN}S7${NC}  HTTPS-Only enforcement"
echo -e "  ${CYAN}S8${NC}  NTP con NTS (Network Time Security)"
echo -e "  ${CYAN}S9${NC}  Ofuscación de patrones de tráfico"
echo -e "  ${CYAN}S10${NC} Auditoría de metadatos ISP"
echo -e "  ${CYAN}S11${NC} Cloudflare WARP + Gateway (perímetro anti-ISP)"
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
# Bloquea todo tráfico que no pase por VPN
# Auto-detecta endpoints VPN para permitir reconexión
set -euo pipefail

# ── Debug logging ──
_KS_LOG="/var/log/securizar/debug.log"
mkdir -p /var/log/securizar 2>/dev/null || true
_dbg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] killswitch-on: $*" >> "$_KS_LOG" 2>/dev/null || true; }
_dbg "=== ACTIVACION kill switch ==="
_dbg "PID=$$ UID=$(id -u) invocado_por=$(ps -o comm= $PPID 2>/dev/null || echo desconocido)"

# ── Detectar endpoints VPN para permitir reconexión ──
_vpn_endpoints=()
# WireGuard: endpoints desde interfaces activas
if command -v wg &>/dev/null; then
    while IFS= read -r _ep; do
        [[ -n "$_ep" ]] && _vpn_endpoints+=("$_ep")
    done < <(wg show all endpoints 2>/dev/null | awk '{print $2}' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
fi
# WireGuard: config files
for _wgcf in /etc/wireguard/*.conf; do
    [[ -f "$_wgcf" ]] || continue
    while IFS= read -r _ep; do
        [[ -n "$_ep" ]] && _vpn_endpoints+=("$_ep")
    done < <(grep -oP 'Endpoint\s*=\s*\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$_wgcf" 2>/dev/null || true)
done
# OpenVPN: config files
for _ovcf in /etc/openvpn/*.conf /etc/openvpn/client/*.conf /etc/openvpn/*.ovpn; do
    [[ -f "$_ovcf" ]] || continue
    while IFS= read -r _ep; do
        [[ -n "$_ep" ]] && _vpn_endpoints+=("$_ep")
    done < <(grep -oP '^remote\s+\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$_ovcf" 2>/dev/null || true)
done
# ProtonVPN configs
for _pvcf in /etc/protonvpn/*.conf /usr/share/protonvpn/wireguard/*.conf; do
    [[ -f "$_pvcf" ]] || continue
    while IFS= read -r _ep; do
        [[ -n "$_ep" ]] && _vpn_endpoints+=("$_ep")
    done < <(grep -oP 'Endpoint\s*=\s*\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$_pvcf" 2>/dev/null || true)
done
# Endpoints manuales
if [[ -f /etc/securizar/vpn-endpoints.conf ]]; then
    while IFS= read -r _ep; do
        _ep="${_ep%%#*}"; _ep="${_ep// /}"
        [[ -n "$_ep" ]] && _vpn_endpoints+=("$_ep")
    done < /etc/securizar/vpn-endpoints.conf
fi
# Deduplicar
if [[ ${#_vpn_endpoints[@]} -gt 0 ]]; then
    readarray -t _vpn_endpoints < <(printf '%s\n' "${_vpn_endpoints[@]}" | sort -u)
fi
_dbg "Endpoints detectados: ${#_vpn_endpoints[@]} → ${_vpn_endpoints[*]:-ninguno}"
_dbg "Fuentes: wg_activo=$(command -v wg &>/dev/null && wg show interfaces 2>/dev/null | wc -w || echo 0) wg_conf=$(ls /etc/wireguard/*.conf 2>/dev/null | wc -l) ovpn_conf=$(ls /etc/openvpn/*.conf /etc/openvpn/client/*.conf 2>/dev/null | wc -l) pvpn_conf=$(ls /etc/protonvpn/*.conf /usr/share/protonvpn/wireguard/*.conf 2>/dev/null | wc -l) manual=$(test -f /etc/securizar/vpn-endpoints.conf && grep -cv '^#\|^$' /etc/securizar/vpn-endpoints.conf 2>/dev/null || echo 0)"
_dbg "Backends: nft=$(command -v nft &>/dev/null && echo si || echo no) iptables=$(command -v iptables &>/dev/null && echo si || echo no) firewalld=$(command -v firewall-cmd &>/dev/null && echo si || echo no)"
_dbg "Interfaces VPN actuales: $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -E 'wg|tun|tap|proton|mullvad|nordlynx|WARP' | tr '\n' ' ' || true)"

if command -v nft &>/dev/null; then
    # ── nftables (openSUSE, sistemas modernos) ──
    nft delete table inet securizar_ks 2>/dev/null || true
    nft add table inet securizar_ks
    nft add chain inet securizar_ks output '{ type filter hook output priority 0; policy accept; }'

    # Permitir loopback
    nft add rule inet securizar_ks output oifname "lo" accept
    # Permitir conexiones establecidas (primero para rendimiento)
    nft add rule inet securizar_ks output ct state established,related accept
    # Bloquear DNS plano a destinos externos (fuerza DNS cifrado via resolver local)
    nft add rule inet securizar_ks output ip daddr != 127.0.0.1 udp dport 53 drop
    nft add rule inet securizar_ks output ip daddr != 127.0.0.1 tcp dport 53 drop
    # Permitir LAN (RFC1918) - solo puertos esenciales
    _LAN="{10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16}"
    nft add rule inet securizar_ks output ip daddr $_LAN meta l4proto icmp accept
    nft add rule inet securizar_ks output ip daddr $_LAN tcp dport '{ 22, 80, 443, 445, 631, 5900, 8080, 9090 }' accept
    nft add rule inet securizar_ks output ip daddr $_LAN udp dport '{ 123, 137-138, 443, 5353 }' accept
    # Permitir DHCP
    nft add rule inet securizar_ks output udp dport 67-68 accept
    # Permitir DNS cifrado DoT (puerto 853) a resolvers conocidos
    nft add rule inet securizar_ks output ip daddr { 1.1.1.1, 1.0.0.1, 9.9.9.9, 149.112.112.112, 8.8.8.8, 8.8.4.4 } tcp dport 853 accept
    # Permitir DoH a resolvers DNS conocidos (puerto 443)
    nft add rule inet securizar_ks output ip daddr { 1.1.1.1, 1.0.0.1, 9.9.9.9, 149.112.112.112, 8.8.8.8, 8.8.4.4 } tcp dport 443 accept
    # Permitir endpoints VPN (permite reconexión si VPN cae)
    for _ep in "${_vpn_endpoints[@]}"; do
        [[ -n "$_ep" ]] && nft add rule inet securizar_ks output ip daddr "$_ep" accept 2>/dev/null || true
    done
    # Permitir Cloudflare WARP (UDP 2408 a edge)
    nft add rule inet securizar_ks output ip daddr 162.159.192.0/24 udp dport 2408 accept 2>/dev/null || true
    nft add rule inet securizar_ks output ip daddr 162.159.193.0/24 udp dport 2408 accept 2>/dev/null || true
    # Permitir interfaces VPN (todas las variantes conocidas)
    for _vif in wg tun tap proton mullvad nordlynx; do
        nft add rule inet securizar_ks output oifname "${_vif}*" accept 2>/dev/null || true
    done
    nft add rule inet securizar_ks output oifname "CloudflareWARP" accept
    # DROP todo lo demás
    nft add rule inet securizar_ks output drop

    _dbg "nftables: tabla securizar_ks creada, $(nft list chain inet securizar_ks output 2>/dev/null | grep -c 'accept\|drop') reglas"
    echo "[+] VPN Kill Switch ACTIVADO via nftables (${#_vpn_endpoints[@]} endpoints VPN permitidos)"

elif command -v iptables &>/dev/null; then
    # ── iptables (sistemas legacy) ──
    CHAIN="SECURIZAR_KS"
    iptables -D OUTPUT -j "$CHAIN" 2>/dev/null || true
    iptables -F "$CHAIN" 2>/dev/null || true
    iptables -X "$CHAIN" 2>/dev/null || true
    iptables -N "$CHAIN"
    iptables -A "$CHAIN" -o lo -j ACCEPT
    iptables -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    # Bloquear DNS plano a destinos externos
    iptables -A "$CHAIN" ! -d 127.0.0.1 -p udp --dport 53 -j DROP
    iptables -A "$CHAIN" ! -d 127.0.0.1 -p tcp --dport 53 -j DROP
    # LAN (RFC1918) - solo puertos esenciales
    for _lan in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
        iptables -A "$CHAIN" -d "$_lan" -p icmp -j ACCEPT
        iptables -A "$CHAIN" -d "$_lan" -p tcp -m multiport --dports 22,80,443,445,631,5900,8080,9090 -j ACCEPT
        iptables -A "$CHAIN" -d "$_lan" -p udp -m multiport --dports 123,137,138,443,5353 -j ACCEPT
    done
    iptables -A "$CHAIN" -p udp --dport 67:68 -j ACCEPT
    # DoT (puerto 853) a resolvers conocidos
    for _dot_ip in 1.1.1.1 1.0.0.1 9.9.9.9 149.112.112.112 8.8.8.8 8.8.4.4; do
        iptables -A "$CHAIN" -d "$_dot_ip" -p tcp --dport 853 -j ACCEPT
    done
    # Permitir DoH a resolvers DNS conocidos (puerto 443)
    for _doh_ip in 1.1.1.1 1.0.0.1 9.9.9.9 149.112.112.112 8.8.8.8 8.8.4.4; do
        iptables -A "$CHAIN" -d "$_doh_ip" -p tcp --dport 443 -j ACCEPT
    done
    # Permitir endpoints VPN (reconexión)
    for _ep in "${_vpn_endpoints[@]}"; do
        [[ -n "$_ep" ]] && iptables -A "$CHAIN" -d "$_ep" -j ACCEPT 2>/dev/null || true
    done
    # Permitir WARP endpoints (UDP 2408)
    iptables -A "$CHAIN" -d 162.159.192.0/24 -p udp --dport 2408 -j ACCEPT 2>/dev/null || true
    iptables -A "$CHAIN" -d 162.159.193.0/24 -p udp --dport 2408 -j ACCEPT 2>/dev/null || true
    # Permitir interfaces VPN
    for _vif in wg tun tap proton mullvad nordlynx; do
        iptables -A "$CHAIN" -o "${_vif}+" -j ACCEPT 2>/dev/null || true
    done
    iptables -A "$CHAIN" -o CloudflareWARP -j ACCEPT
    iptables -A "$CHAIN" -j DROP
    iptables -I OUTPUT -j "$CHAIN"
    _dbg "iptables: cadena SECURIZAR_KS creada, $(iptables -L SECURIZAR_KS 2>/dev/null | grep -c 'ACCEPT\|DROP') reglas"
    echo "[+] VPN Kill Switch ACTIVADO via iptables (${#_vpn_endpoints[@]} endpoints VPN permitidos)"

elif command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
    # ── firewalld (solo si servicio activo, no masked/stopped) ──
    # Añadir reglas a zona drop ANTES de cambiarla a default (previene lockdown)
    _fw_ok=0
    _fw_total=0
    _fw_add() {
        ((_fw_total++)) || true
        if firewall-cmd --zone=drop --add-rich-rule="$1" --permanent 2>/dev/null; then
            ((_fw_ok++)) || true
        fi
    }
    # Bloquear DNS plano a destinos externos
    _fw_add 'rule family="ipv4" destination NOT address="127.0.0.1" port port="53" protocol="udp" drop'
    _fw_add 'rule family="ipv4" destination NOT address="127.0.0.1" port port="53" protocol="tcp" drop'
    # LAN (RFC1918) - solo puertos esenciales
    for _lan in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
        _fw_add "rule family=\"ipv4\" destination address=\"${_lan}\" protocol value=\"icmp\" accept"
        for _port in 22 80 443 445 631 5900 8080 9090; do
            _fw_add "rule family=\"ipv4\" destination address=\"${_lan}\" port port=\"${_port}\" protocol=\"tcp\" accept"
        done
        for _port in 123 137 138 443 5353; do
            _fw_add "rule family=\"ipv4\" destination address=\"${_lan}\" port port=\"${_port}\" protocol=\"udp\" accept"
        done
    done
    # DHCP
    _fw_add 'rule family="ipv4" port port="67-68" protocol="udp" accept'
    # DoT (puerto 853) a resolvers conocidos
    for _dot_ip in 1.1.1.1 1.0.0.1 9.9.9.9 149.112.112.112 8.8.8.8 8.8.4.4; do
        _fw_add "rule family=\"ipv4\" destination address=\"${_dot_ip}\" port port=\"853\" protocol=\"tcp\" accept"
    done
    for _doh_ip in 1.1.1.1 1.0.0.1 9.9.9.9 149.112.112.112 8.8.8.8 8.8.4.4; do
        _fw_add "rule family=\"ipv4\" destination address=\"${_doh_ip}\" port port=\"443\" protocol=\"tcp\" accept"
    done
    # Endpoints VPN (reconexión)
    for _ep in "${_vpn_endpoints[@]}"; do
        [[ -n "$_ep" ]] || continue
        firewall-cmd --zone=drop --add-rich-rule="rule family=\"ipv4\" destination address=\"${_ep}\" accept" --permanent 2>/dev/null || true
    done
    # WARP endpoints
    firewall-cmd --zone=drop --add-rich-rule='rule family="ipv4" destination address="162.159.192.0/24" port port="2408" protocol="udp" accept' --permanent 2>/dev/null || true
    firewall-cmd --zone=drop --add-rich-rule='rule family="ipv4" destination address="162.159.193.0/24" port port="2408" protocol="udp" accept' --permanent 2>/dev/null || true
    # Verificar reglas críticas ANTES de cambiar zona
    if [[ $_fw_ok -lt 5 ]]; then
        _dbg "ABORT firewalld: solo $_fw_ok/$_fw_total reglas criticas aplicadas en zona drop"
        echo "[!] ABORTANDO: solo $_fw_ok/$_fw_total reglas aplicadas en zona drop"
        echo "[!] Zona default NO cambiada (sigue: $(firewall-cmd --get-default-zone 2>/dev/null))"
        exit 1
    fi
    firewall-cmd --reload 2>/dev/null || true
    firewall-cmd --set-default-zone=drop 2>/dev/null || true
    _dbg "firewalld: zona default=$(firewall-cmd --get-default-zone 2>/dev/null) reglas=$_fw_ok/$_fw_total endpoints=${#_vpn_endpoints[@]}"
    echo "[+] VPN Kill Switch ACTIVADO via firewalld (zona drop, $_fw_ok/$_fw_total reglas, ${#_vpn_endpoints[@]} endpoints VPN)"
else
    _dbg "ERROR: ningun backend de firewall disponible (nft/iptables/firewalld)"
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

_KS_LOG="/var/log/securizar/debug.log"
mkdir -p /var/log/securizar 2>/dev/null || true
_dbg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] killswitch-off: $*" >> "$_KS_LOG" 2>/dev/null || true; }
_dbg "=== DESACTIVACION kill switch ==="
_dbg "PID=$$ UID=$(id -u) invocado_por=$(ps -o comm= $PPID 2>/dev/null || echo desconocido)"

if command -v nft &>/dev/null; then
    nft delete table inet securizar_ks 2>/dev/null || true
    _dbg "nftables: tabla securizar_ks eliminada"
    echo "[+] VPN Kill Switch DESACTIVADO (nftables)"
elif command -v iptables &>/dev/null; then
    CHAIN="SECURIZAR_KS"
    iptables -D OUTPUT -j "$CHAIN" 2>/dev/null || true
    iptables -F "$CHAIN" 2>/dev/null || true
    iptables -X "$CHAIN" 2>/dev/null || true
    _dbg "iptables: cadena SECURIZAR_KS eliminada"
    echo "[+] VPN Kill Switch DESACTIVADO (iptables)"
elif command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
    _dbg "firewalld: restaurando zona default a public"
    firewall-cmd --set-default-zone=public 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
    _dbg "firewalld: zona default=$(firewall-cmd --get-default-zone 2>/dev/null)"
    echo "[+] VPN Kill Switch DESACTIVADO (firewalld → zona public)"
fi

_dbg "desactivacion completada"
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

logger -t securizar-nm-ks "dispatch: iface=$IFACE action=$ACTION"

# Desactivar IPv6 en cualquier interfaz que suba (previene bypass VPN)
if [[ "$ACTION" == "up" || "$ACTION" == "vpn-up" ]] && [[ -n "$IFACE" ]]; then
    sysctl -q -w "net.ipv6.conf.${IFACE}.disable_ipv6=1" 2>/dev/null || true
fi

case "$ACTION" in
    vpn-up)
        /etc/securizar/vpn-killswitch.sh 2>/dev/null || true
        ;;
    vpn-down)
        /etc/securizar/vpn-killswitch-off.sh 2>/dev/null || true
        ;;
    up)
        # WireGuard, ProtonVPN, Mullvad, OpenVPN, WARP, etc.
        case "$IFACE" in proton*|wg*|mullvad*|nordlynx*|CloudflareWARP*|tun*|tap*)
            /etc/securizar/vpn-killswitch.sh 2>/dev/null || true
        esac
        ;;
    down)
        case "$IFACE" in proton*|wg*|mullvad*|nordlynx*|CloudflareWARP*|tun*|tap*)
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

    # ── Crear plantilla de endpoints VPN manuales ──
    if [[ ! -f "${ISP_CONF_DIR}/vpn-endpoints.conf" ]]; then
        cat > "${ISP_CONF_DIR}/vpn-endpoints.conf" << 'VPN_EP_CONF'
# Securizar M38 S1: Endpoints VPN manuales
# Añade IPs de tus servidores VPN (una por línea)
# El kill switch permitirá tráfico a estas IPs para reconexión
# Se auto-detectan endpoints de /etc/wireguard/*.conf y /etc/openvpn/*.conf
# Usa este archivo solo para endpoints que no se auto-detecten
#
# Ejemplos:
# 185.159.157.1
# 198.51.100.42
VPN_EP_CONF
        chmod 640 "${ISP_CONF_DIR}/vpn-endpoints.conf"
        log_change "Creado" "${ISP_CONF_DIR}/vpn-endpoints.conf (plantilla endpoints VPN)"
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
        _ks_found=false
        _ks_iface=""
        for _iname in proton0 proton1 wg0 wg1 tun0 tun1 mullvad-wg nordlynx CloudflareWARP; do
            if ip link show "$_iname" &>/dev/null 2>&1; then
                _ks_found=true; _ks_iface="$_iname"; break
            fi
        done
        # Detección dinámica: WireGuard con nombre no estándar
        if [[ "$_ks_found" != "true" ]] && command -v wg &>/dev/null; then
            _ks_iface=$(wg show interfaces 2>/dev/null | awk '{print $1}')
            [[ -n "$_ks_iface" ]] && _ks_found=true
        fi
        # Detección dinámica: interfaces punto-a-punto (usuario decide)
        if [[ "$_ks_found" != "true" ]]; then
            _ks_iface=$(ip -o link show 2>/dev/null | grep -i 'POINTOPOINT' | awk -F': ' '{print $2}' | grep -v '^lo$' | head -1) || true
            [[ -n "$_ks_iface" ]] && _ks_found=true
        fi
        if [[ "$_ks_found" == "true" ]]; then
            if ask "VPN $_ks_iface detectada pero kill switch NO activo. ¿Activar ahora?"; then
                bash "${ISP_CONF_DIR}/vpn-killswitch.sh" 2>/dev/null && \
                    log_change "Kill switch" "Activado (VPN $_ks_iface detectada)" || \
                    log_warn "Kill switch: fallo al activar"
            else
                log_skip "Activación kill switch"
            fi
        fi
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
ExecStartPre=/bin/bash -c 'for i in proton0 proton1 wg0 wg1 tun0 tun1 mullvad-wg nordlynx CloudflareWARP; do ip link show "$i" 2>/dev/null && exit 0; done; command -v wg &>/dev/null && wg show interfaces 2>/dev/null | grep -q . && exit 0; exit 1'
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

# ── S1 post: Watchdog de interfaces VPN (independiente de NetworkManager) ──
# ProtonVPN CLI, wg-quick, etc. crean interfaces sin pasar por NM.
# Este watchdog detecta proton0/wg0/tun0 y activa/desactiva el kill switch.
if [[ -f "${ISP_CONF_DIR}/vpn-killswitch.sh" ]]; then
    if [[ -f /etc/systemd/system/securizar-vpn-watchdog.service ]]; then
        log_already "Watchdog VPN (securizar-vpn-watchdog)"
    elif ask "¿Crear watchdog VPN? (detecta VPN fuera de NetworkManager: ProtonVPN CLI, wg-quick, etc.)"; then

        cat > "${ISP_BIN_DIR}/vpn-watchdog.sh" << 'VPN_WATCHDOG'
#!/bin/bash
# Watchdog de interfaces VPN - Securizar M38 S1
# Detecta interfaces VPN que aparecen/desaparecen sin pasar por NetworkManager
# Ejecutado cada 10s por securizar-vpn-watchdog.timer
set -euo pipefail

_WD_LOG="/var/log/securizar/debug.log"
mkdir -p /var/log/securizar 2>/dev/null || true
_dbg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] vpn-watchdog: $*" >> "$_WD_LOG" 2>/dev/null || true; }

STATE_FILE="/run/securizar-vpn-watchdog.state"
VPN_IFACES="proton0 proton1 wg0 wg1 tun0 tun1 mullvad-wg nordlynx CloudflareWARP"

# Detectar si alguna interfaz VPN existe
vpn_up=false
vpn_iface=""
for iface in $VPN_IFACES; do
    if ip link show "$iface" &>/dev/null 2>&1; then
        vpn_up=true
        vpn_iface="$iface"
        break
    fi
done
# Deteccion dinamica: interfaces WireGuard con nombre no estandar
if [[ "$vpn_up" == "false" ]] && command -v wg &>/dev/null; then
    _wg_iface=$(wg show interfaces 2>/dev/null | awk '{print $1}')
    if [[ -n "$_wg_iface" ]]; then
        vpn_up=true
        vpn_iface="$_wg_iface"
    fi
fi

# Leer estado anterior
prev_state="unknown"
[[ -f "$STATE_FILE" ]] && prev_state=$(cat "$STATE_FILE" 2>/dev/null || echo "unknown")

# Determinar nuevo estado
if [[ "$vpn_up" == "true" ]]; then
    new_state="up"
else
    new_state="down"
fi

# Solo loguear y actuar cuando hay cambio de estado
if [[ "$new_state" == "$prev_state" ]]; then
    # Sin cambio: no loguear nada (evita spam en debug.log)
    exit 0
fi

_dbg "transicion: $prev_state -> $new_state (iface=${vpn_iface:-ninguna})"

if [[ "$new_state" == "up" ]]; then
    # VPN acaba de subir → activar kill switch
    if /etc/securizar/vpn-killswitch.sh 2>/dev/null; then
        _dbg "kill switch activado OK"
        logger -t securizar-vpn-watchdog "Kill switch ACTIVADO (interfaz $vpn_iface detectada)"
    else
        _dbg "kill switch FALLO al activar (exit=$?)"
        logger -t securizar-vpn-watchdog "Kill switch: fallo al activar para $vpn_iface"
    fi
else
    # VPN acaba de caer → desactivar kill switch
    if /etc/securizar/vpn-killswitch-off.sh 2>/dev/null; then
        _dbg "kill switch desactivado OK"
        logger -t securizar-vpn-watchdog "Kill switch DESACTIVADO (VPN caida)"
    else
        _dbg "kill switch FALLO al desactivar (exit=$?)"
        logger -t securizar-vpn-watchdog "Kill switch: fallo al desactivar"
    fi
fi
echo "$new_state" > "$STATE_FILE"
VPN_WATCHDOG
        chmod 755 "${ISP_BIN_DIR}/vpn-watchdog.sh"
        log_change "Creado" "${ISP_BIN_DIR}/vpn-watchdog.sh"

        cat > /etc/systemd/system/securizar-vpn-watchdog.service << 'WD_SVC'
[Unit]
Description=Securizar - Watchdog VPN (detecta interfaces sin NM)
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/vpn-watchdog.sh
ProtectHome=yes
PrivateTmp=yes
WD_SVC

        cat > /etc/systemd/system/securizar-vpn-watchdog.timer << 'WD_TIMER'
[Unit]
Description=Securizar - Timer watchdog VPN (cada 10s)

[Timer]
OnBootSec=15
OnUnitActiveSec=10
AccuracySec=3

[Install]
WantedBy=timers.target
WD_TIMER
        systemctl daemon-reload
        systemctl enable securizar-vpn-watchdog.timer 2>/dev/null || true
        systemctl start securizar-vpn-watchdog.timer 2>/dev/null || true
        log_change "Creado" "securizar-vpn-watchdog.timer (check cada 10s, detecta VPN sin NM)"
        log_info "ProtonVPN CLI, wg-quick, Mullvad CLI serán detectados automáticamente"
    else
        log_skip "Watchdog VPN"
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
else
    # Detectar si la red depende de IPv6 (previene lockdown en redes IPv6-only)
    _ipv6_safe_to_disable=true
    _has_ipv4_gw=false
    if ip -4 route show default 2>/dev/null | grep -q 'default'; then
        _has_ipv4_gw=true
    fi
    if [[ "$_has_ipv4_gw" != "true" ]]; then
        _ipv6_safe_to_disable=false
        log_warn "No se detectó gateway IPv4. Tu red podría ser IPv6-only."
        log_warn "Deshabilitar IPv6 podría causar pérdida total de conectividad."
    fi

    if [[ "$_ipv6_safe_to_disable" == "true" ]]; then
        _ipv6_prompt="¿Deshabilitar IPv6 persistente? (previene fugas fuera de VPN)"
    else
        _ipv6_prompt="¿Deshabilitar IPv6? (RIESGO: no se detectó IPv4, posible lockdown)"
    fi

    if ask "$_ipv6_prompt"; then
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
fi
fi  # S1

if [[ "$ISP_SECTION" == "all" || "$ISP_SECTION" == "S2" ]]; then
# ============================================================
# S2 — PREVENCIÓN DE FUGAS DNS (DoT con unbound / DoH con dnscrypt-proxy)
# ============================================================
log_section "S2: PREVENCIÓN DE FUGAS DNS"

echo "Configura DNS cifrado local con auto-detección del mejor protocolo:"
echo "  - DoT (DNS-over-TLS, puerto 853) via unbound: preferido si no bloqueado"
echo "  - DoH (DNS-over-HTTPS, puerto 443) via dnscrypt-proxy: fallback si ISP bloquea 853"
echo "Incluye DNSSEC, cache local, monitor de fallback automático y desactiva mDNS/LLMNR."
echo ""

DNS_MODE=""

if check_service_enabled unbound || check_service_enabled dnscrypt-proxy; then
    log_already "DNS cifrado ($(_detect_dns_resolver) activo)"
elif ask "¿Configurar DNS cifrado (DoT o DoH automático)?"; then

    # ── Detectar si puerto 853 está accesible ──
    log_info "Probando accesibilidad del puerto 853 (DoT)..."
    if _test_dot_port; then
        DNS_MODE="dot"
        log_info "Puerto 853 accesible → modo DoT (unbound)"
    else
        DNS_MODE="doh"
        log_warn "Puerto 853 BLOQUEADO → modo DoH (dnscrypt-proxy, puerto 443)"
    fi

    # ════════════════════════════════════════════════════════════
    # RAMA DoT: unbound (puerto 853)
    # ════════════════════════════════════════════════════════════
    if [[ "$DNS_MODE" == "dot" ]]; then

    # ── Instalar unbound si no está ──
    if ! command -v unbound &>/dev/null; then
        pkg_install "unbound" || true
    fi

    if ! command -v unbound &>/dev/null; then
        log_warn "unbound no se pudo instalar. Intentando fallback a DoH..."
        DNS_MODE="doh"
    else

    # Detener dnscrypt-proxy si estaba corriendo (cambio de modo)
    if systemctl is-active dnscrypt-proxy &>/dev/null; then
        systemctl stop dnscrypt-proxy 2>/dev/null || true
        systemctl disable dnscrypt-proxy 2>/dev/null || true
        log_change "dnscrypt-proxy" "Detenido (cambiando a modo DoT)"
    fi

    # ── Obtener ancla DNSSEC ──
    if command -v unbound-anchor &>/dev/null; then
        mkdir -p /var/lib/unbound
        unbound-anchor -a /var/lib/unbound/root.key 2>/dev/null || true
        chown unbound:unbound /var/lib/unbound/root.key 2>/dev/null || true
        log_change "DNSSEC" "Ancla de confianza actualizada (/var/lib/unbound/root.key)"
    fi

    # ── Configurar unbound para DoT estricto ──
    cp /etc/unbound/unbound.conf /etc/unbound/unbound.conf.bak-securizar 2>/dev/null || true

    # Auto-detectar ruta del bundle de certificados TLS (varía por distro)
    _tls_cert_bundle=""
    for _certpath in /etc/ssl/ca-bundle.pem /etc/ssl/certs/ca-certificates.crt \
                     /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem \
                     /usr/share/ca-certificates/mozilla/cacert.pem; do
        if [[ -f "$_certpath" ]]; then
            _tls_cert_bundle="$_certpath"
            break
        fi
    done
    if [[ -z "$_tls_cert_bundle" ]]; then
        _tls_cert_bundle="/etc/ssl/ca-bundle.pem"
        log_warn "Bundle de certificados TLS no encontrado, usando default: $_tls_cert_bundle"
    fi

    cat > /etc/unbound/unbound.conf << UNBOUND_CONF
# ============================================================
# Securizar Módulo 38 - DNS-over-TLS con unbound
# Todas las consultas DNS se cifran por el puerto 853
# El ISP NO puede ver ni interceptar las consultas
# ============================================================

server:
    interface: 127.0.0.1
    interface: ::1
    port: 53

    access-control: 127.0.0.0/8 allow
    access-control: ::1/128 allow
    access-control: 0.0.0.0/0 refuse
    access-control: ::/0 refuse

    username: "unbound"
    directory: "/etc/unbound"
    chroot: ""  # Desactivado: systemd sandboxing (hardening.conf) es superior

    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    val-clean-additional: yes

    cache-min-ttl: 300
    cache-max-ttl: 86400
    msg-cache-size: 50m
    rrset-cache-size: 100m
    key-cache-size: 50m
    neg-cache-size: 10m
    prefetch: yes
    prefetch-key: yes

    # Protección DNS rebinding (bloquea respuestas con IPs privadas)
    private-address: 10.0.0.0/8
    private-address: 172.16.0.0/12
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: fd00::/8
    private-address: fe80::/10
    private-address: 127.0.0.0/8
    private-address: ::ffff:0:0/96

    qname-minimisation: yes
    qname-minimisation-strict: no
    aggressive-nsec: yes
    deny-any: yes
    minimal-responses: yes
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-below-nxdomain: yes
    harden-referral-path: yes
    harden-large-queries: yes
    harden-algo-downgrade: yes

    # Resiliencia: servir respuestas expiradas si upstream falla
    serve-expired: yes
    serve-expired-ttl: 86400
    serve-expired-reply-ttl: 30
    serve-expired-client-timeout: 1800

    # Extended DNS Errors (RFC 8914)
    ede: yes

    unwanted-reply-threshold: 10000

    num-threads: 2
    so-reuseport: yes
    infra-cache-numhosts: 10000

    do-ip6: no

    tls-cert-bundle: "${_tls_cert_bundle}"

    verbosity: 1
    log-queries: no
    log-replies: no
    logfile: "/var/log/unbound/unbound.log"
    use-syslog: no

remote-control:
    control-enable: yes
    control-interface: 127.0.0.1
    server-key-file: "/etc/unbound/unbound_server.key"
    server-cert-file: "/etc/unbound/unbound_server.pem"
    control-key-file: "/etc/unbound/unbound_control.key"
    control-cert-file: "/etc/unbound/unbound_control.pem"

forward-zone:
    name: "."
    forward-tls-upstream: yes

    forward-addr: 1.1.1.1@853#cloudflare-dns.com
    forward-addr: 1.0.0.1@853#cloudflare-dns.com

    forward-addr: 9.9.9.9@853#dns.quad9.net
    forward-addr: 149.112.112.112@853#dns.quad9.net

    forward-addr: 8.8.8.8@853#dns.google
    forward-addr: 8.8.4.4@853#dns.google
UNBOUND_CONF
    log_change "Creado" "/etc/unbound/unbound.conf (DoT estricto, DNSSEC, hardened)"

    mkdir -p /var/log/unbound
    chown unbound:unbound /var/log/unbound 2>/dev/null || true

    # Systemd sandboxing para unbound
    mkdir -p /etc/systemd/system/unbound.service.d
    cat > /etc/systemd/system/unbound.service.d/hardening.conf << 'UNBOUND_HARDENING'
[Service]
# Filesystem
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=/var/lib/unbound /var/log/unbound /run/unbound
UMask=0077

# Kernel
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes

# Process isolation
ProtectProc=invisible
ProcSubset=pid
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
RestrictNamespaces=yes

# Network: unbound needs AF_INET for DNS, AF_UNIX for control socket, AF_NETLINK for routing
RestrictAddressFamilies=AF_INET AF_UNIX AF_NETLINK

# Capabilities: only what unbound actually needs (no chroot, no DAC override)
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID

# Syscalls: block dangerous groups unbound never needs
SystemCallArchitectures=native
SystemCallFilter=~@clock @cpu-emulation @debug @module @mount @obsolete @reboot @swap @raw-io

# NoNewPrivileges incompatible con SELinux named_cache_t transition en ExecStartPre
RemoveIPC=yes
UNBOUND_HARDENING
    log_change "Creado" "unbound hardening (systemd sandbox, score 2.1)"
    systemctl daemon-reload 2>/dev/null || true

    if unbound-checkconf /etc/unbound/unbound.conf &>/dev/null; then
        log_info "Configuración de unbound válida"
    else
        log_warn "Error en configuración de unbound:"
        unbound-checkconf /etc/unbound/unbound.conf 2>&1 | sed 's/^/    /' || true
    fi

    systemctl enable unbound 2>/dev/null || true
    systemctl restart unbound 2>/dev/null || true
    # Verificar que unbound arrancó; restaurar backup si falló
    sleep 2
    if systemctl is-active unbound &>/dev/null; then
        log_change "Servicio" "unbound habilitado e iniciado"
    else
        log_warn "unbound no arrancó con nueva configuración"
        if [[ -f /etc/unbound/unbound.conf.bak-securizar ]]; then
            cp /etc/unbound/unbound.conf.bak-securizar /etc/unbound/unbound.conf
            systemctl restart unbound 2>/dev/null || true
            if systemctl is-active unbound &>/dev/null; then
                log_warn "Restaurada configuración anterior de unbound (funcional)"
            else
                log_warn "unbound no arranca ni con configuración anterior"
            fi
        fi
    fi

    fi  # cierre del if ! command -v unbound (DoT)
    fi  # cierre del if DNS_MODE == dot

    # ════════════════════════════════════════════════════════════
    # RAMA DoH: dnscrypt-proxy (puerto 443)
    # ════════════════════════════════════════════════════════════
    if [[ "$DNS_MODE" == "doh" ]]; then

    # ── Instalar dnscrypt-proxy ──
    if ! command -v dnscrypt-proxy &>/dev/null; then
        pkg_install "dnscrypt-proxy" || true
    fi

    if ! command -v dnscrypt-proxy &>/dev/null; then
        log_warn "dnscrypt-proxy no se pudo instalar. Sección S2 omitida."
        DNS_MODE=""
    else

    # Detener systemd-resolved si ocupa :53 (NO deshabilitar aún — fallback seguro)
    _resolved_was_active=false
    if ss -tlnp 2>/dev/null | grep -q ":53.*systemd-resolve"; then
        _resolved_was_active=true
        systemctl stop systemd-resolved 2>/dev/null || true
        log_change "systemd-resolved" "Detenido temporalmente (liberando puerto 53)"
    fi

    # Detener unbound si estaba corriendo (cambio de modo)
    if systemctl is-active unbound &>/dev/null; then
        systemctl stop unbound 2>/dev/null || true
        systemctl disable unbound 2>/dev/null || true
        log_change "unbound" "Detenido (cambiando a modo DoH)"
    fi

    # ── Configurar dnscrypt-proxy ──
    mkdir -p /etc/dnscrypt-proxy
    cat > /etc/dnscrypt-proxy/dnscrypt-proxy.toml << 'DNSCRYPT_CONF'
# ============================================================
# Securizar Módulo 38 - DNS-over-HTTPS con dnscrypt-proxy
# Tráfico DNS cifrado por puerto 443 (indistinguible de HTTPS)
# Fallback automático cuando ISP bloquea puerto 853 (DoT)
# ============================================================

listen_addresses = ['127.0.0.1:53', '[::1]:53']
max_clients = 250

# Servidores DoH confiables
server_names = ['cloudflare', 'google', 'quad9-dnscrypt-ip4-filter-pri']

# Protocolos habilitados
doh_servers = true
dnscrypt_servers = true
odoh_servers = false

# Requisitos de seguridad
require_dnssec = true
require_nolog = true
require_nofilter = false

# IPv6
ipv6_servers = false
block_ipv6 = true

# Bootstrap: resolvers por IP directa (no necesitan DNS previo)
bootstrap_resolvers = ['1.1.1.1:53', '9.9.9.9:53']
netprobe_address = '1.1.1.1:443'
netprobe_timeout = 30

# Timeouts
timeout = 5000
keepalive = 30

# Cache
cache = true
cache_size = 4096
cache_min_ttl = 300
cache_max_ttl = 86400
cache_neg_min_ttl = 60
cache_neg_max_ttl = 600

# Logging mínimo (privacidad)
log_level = 2
log_file = '/var/log/dnscrypt-proxy/dnscrypt-proxy.log'
use_syslog = false

# Listas de resolvers (auto-actualización)
[sources]
  [sources.'public-resolvers']
  urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md', 'https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md']
  cache_file = '/var/cache/dnscrypt-proxy/public-resolvers.md'
  minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
  refresh_delay = 72
  prefix = ''

  [sources.'relays']
  urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/relays.md', 'https://download.dnscrypt.info/resolvers-list/v3/relays.md']
  cache_file = '/var/cache/dnscrypt-proxy/relays.md'
  minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
  refresh_delay = 72
  prefix = ''

# DNS anónimo via relays (oculta IP origen al resolver)
[anonymized_dns]
routes = [
    { server_name='cloudflare', via=['anon-cs-fr', 'anon-cs-de'] },
    { server_name='quad9-dnscrypt-ip4-filter-pri', via=['anon-scaleway-fr', 'anon-cs-nl'] }
]
DNSCRYPT_CONF
    log_change "Creado" "/etc/dnscrypt-proxy/dnscrypt-proxy.toml (DoH, DNSSEC, cache, relays anónimos)"

    # ── Crear directorios ──
    mkdir -p /var/log/dnscrypt-proxy
    mkdir -p /var/cache/dnscrypt-proxy

    # ── Activar servicio ──
    systemctl enable dnscrypt-proxy 2>/dev/null || true
    systemctl restart dnscrypt-proxy 2>/dev/null || true
    # Verificar que dnscrypt-proxy escucha antes de deshabilitar systemd-resolved
    sleep 2
    if ss -tlnp 2>/dev/null | grep -q ":53.*dnscrypt"; then
        if [[ "${_resolved_was_active:-false}" == "true" ]]; then
            systemctl disable systemd-resolved 2>/dev/null || true
        fi
        log_change "Servicio" "dnscrypt-proxy verificado en :53 (DoH puerto 443)"
    else
        log_warn "dnscrypt-proxy no escucha en :53"
        if [[ "${_resolved_was_active:-false}" == "true" ]]; then
            log_warn "Reactivando systemd-resolved como fallback DNS"
            systemctl start systemd-resolved 2>/dev/null || true
        fi
    fi

    fi  # cierre del if ! command -v dnscrypt-proxy
    fi  # cierre del if DNS_MODE == doh

    # ════════════════════════════════════════════════════════════
    # BLOQUE COMPARTIDO (ambas ramas, si DNS_MODE fue configurado)
    # ════════════════════════════════════════════════════════════
    if [[ -n "$DNS_MODE" ]]; then

    # ── Guardar modo DNS actual ──
    cat > "${ISP_CONF_DIR}/dns-mode.conf" << EOF_DNS_MODE
# Securizar M38 S2 - Modo DNS configurado
DNS_MODE=${DNS_MODE}
CONFIGURED_AT=$(date -Iseconds)
EOF_DNS_MODE
    log_change "Creado" "${ISP_CONF_DIR}/dns-mode.conf (modo: ${DNS_MODE})"

    # ── Configurar DNS del sistema ──
    dns_configured=false

    if command -v nmcli &>/dev/null; then
        active_conn=$(nmcli -t -f NAME con show --active 2>/dev/null | head -1)
        if [[ -n "$active_conn" ]]; then
            current_dns=$(nmcli -t -f ipv4.dns con show "$active_conn" 2>/dev/null || echo "")
            echo "# Backup DNS anterior: $current_dns" > "${ISP_CONF_DIR}/dns-backup.conf"
            echo "# Conexión: $active_conn" >> "${ISP_CONF_DIR}/dns-backup.conf"
            echo "# Fecha: $(date)" >> "${ISP_CONF_DIR}/dns-backup.conf"
            log_change "Backup" "DNS anterior guardado en ${ISP_CONF_DIR}/dns-backup.conf"

            nmcli con modify "$active_conn" ipv4.dns "127.0.0.1" 2>/dev/null || true
            nmcli con modify "$active_conn" ipv4.dns-priority -1 2>/dev/null || true
            nmcli con modify "$active_conn" ipv4.ignore-auto-dns yes 2>/dev/null || true

            nm_dns=$(grep -r "dns=" /etc/NetworkManager/ 2>/dev/null | grep -o "dns=.*" | head -1 || echo "")
            if [[ "$nm_dns" == *"dnsmasq"* ]]; then
                mkdir -p /etc/NetworkManager/dnsmasq.d
                cat > /etc/NetworkManager/dnsmasq.d/securizar-dot.conf << 'DNSMASQ_CONF'
# Securizar Módulo 38 - Reenviar DNS a resolver local
no-resolv
server=127.0.0.1#53
cache-size=0
DNSMASQ_CONF
                log_change "dnsmasq" "Configurado para reenviar a resolver local"
            fi

            # Aplicar cambios DNS sin desconexión completa (previene lockdown)
            nmcli general reload conf 2>/dev/null || true
            sleep 1
            # Si resolv.conf no apunta a local, reaplicar conexión
            if ! grep -q '^nameserver 127.0.0.1' /etc/resolv.conf 2>/dev/null; then
                nmcli con up "$active_conn" 2>/dev/null || true
            fi
            log_change "NetworkManager" "DNS redirigido a 127.0.0.1 (modo ${DNS_MODE})"
            dns_configured=true
        fi
    fi

    if [[ "$dns_configured" != "true" ]]; then
        cp /etc/resolv.conf /etc/resolv.conf.bak-securizar 2>/dev/null || true
        cat > /etc/resolv.conf << 'RESOLV_CONF'
# Securizar Módulo 38 - DNS cifrado local (DoT/DoH)
nameserver 127.0.0.1
options edns0 trust-ad
RESOLV_CONF
        # Solo hacer inmutable si el resolver local responde (previene lockdown)
        sleep 2
        if nslookup example.com 127.0.0.1 &>/dev/null; then
            chattr +i /etc/resolv.conf 2>/dev/null || true
            log_change "resolv.conf" "Forzado a resolver local, inmutable (DNS verificado)"
        else
            log_warn "DNS local no responde aún. resolv.conf NO inmutable (se puede corregir)"
            log_warn "  Cuando funcione, ejecuta: sudo chattr +i /etc/resolv.conf"
        fi
    fi

    # ── Desactivar mDNS y LLMNR ──
    if systemctl is-active avahi-daemon &>/dev/null; then
        systemctl stop avahi-daemon 2>/dev/null || true
        systemctl disable avahi-daemon 2>/dev/null || true
        log_change "avahi-daemon" "Desactivado (prevención fuga mDNS)"
    fi

    # ── Firewall: según modo DNS ──
    # Si el kill switch (S1) ya está activo, sus reglas ya cubren DoT/DoH → skip
    _ks_dns_skip=false
    if command -v nft &>/dev/null && nft list table inet securizar_ks &>/dev/null 2>&1; then
        _ks_dns_skip=true
    elif command -v iptables &>/dev/null && iptables -L SECURIZAR_KS &>/dev/null 2>&1; then
        _ks_dns_skip=true
    elif command -v firewall-cmd &>/dev/null && [[ "$(firewall-cmd --get-default-zone 2>/dev/null)" == "drop" ]]; then
        _ks_dns_skip=true
    fi
    if [[ "$_ks_dns_skip" == "true" ]]; then
        log_already "Firewall DNS (reglas ya presentes en kill switch S1)"
    elif [[ "$DNS_MODE" == "dot" ]]; then
        if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
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
    elif [[ "$DNS_MODE" == "doh" ]]; then
        if command -v nft &>/dev/null; then
            nft delete table inet securizar-doh 2>/dev/null || true
            nft add table inet securizar-doh
            nft add chain inet securizar-doh output '{ type filter hook output priority 0; policy accept; }'
            nft add rule inet securizar-doh output ip daddr '{ 1.1.1.1, 1.0.0.1, 9.9.9.9, 149.112.112.112, 8.8.8.8, 8.8.4.4 }' tcp dport 443 accept
            log_change "Firewall" "DoH (443) a resolvers DNS permitido via nftables (tabla securizar-doh)"
        elif command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
            for _doh_ip in 1.1.1.1 1.0.0.1 9.9.9.9 149.112.112.112 8.8.8.8 8.8.4.4; do
                firewall-cmd --add-rich-rule="rule family=\"ipv4\" destination address=\"${_doh_ip}\" port port=\"443\" protocol=\"tcp\" accept" --permanent 2>/dev/null || true
            done
            firewall-cmd --reload 2>/dev/null || true
            log_change "Firewall" "DoH (443) a resolvers DNS permitido via firewalld"
        fi
    fi

    # ── Eliminar tabla nftables antigua ──
    if command -v nft &>/dev/null; then
        if nft list tables 2>/dev/null | grep -q "securizar-dns"; then
            nft delete table inet securizar-dns 2>/dev/null || true
            log_change "Firewall" "Eliminada tabla nftables securizar-dns (obsoleta)"
        fi
    fi

    # ── Verificar resolución DNS (agnóstico al resolver) ──
    sleep 3
    _resolver_name=$(_detect_dns_resolver)
    if ss -tlnp 2>/dev/null | grep -q ":53 "; then
        log_info "${_resolver_name} escuchando en 127.0.0.1:53"

        # Warm-up
        nslookup example.com 127.0.0.1 &>/dev/null || true
        sleep 2

        _dns_ok=false
        for _dns_try in 1 2 3; do
            if nslookup example.com 127.0.0.1 &>/dev/null; then
                log_info "Resolución DNS via ${DNS_MODE^^} funcionando correctamente"
                _dns_ok=true
                break
            fi
            [[ $_dns_try -lt 3 ]] && sleep 2
        done
        if [[ "$_dns_ok" != "true" ]]; then
            log_warn "${_resolver_name} activo pero resolución lenta (handshake inicial es normal)"
        fi
    else
        log_warn "${_resolver_name} no parece estar escuchando. Verifica con: systemctl status ${_resolver_name}"
    fi

    # ── Monitor de fallback DNS (DoT ↔ DoH automático) ──
    cat > "${ISP_BIN_DIR}/dns-fallback-monitor.sh" << 'DNS_MONITOR'
#!/bin/bash
# Monitor de fallback DNS: cambia automáticamente entre DoT (unbound) y DoH (dnscrypt-proxy)
# Ejecutado cada 5 min por securizar-dns-fallback-monitor.timer
set -euo pipefail

_DM_LOG="/var/log/securizar/debug.log"
mkdir -p /var/log/securizar 2>/dev/null || true
_dbg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] dns-monitor: $*" >> "$_DM_LOG" 2>/dev/null || true; }
_dbg "=== Ciclo monitor DNS ==="

CONF="/etc/securizar/dns-mode.conf"
[[ -f "$CONF" ]] || { _dbg "SKIP: $CONF no existe"; exit 0; }
source "$CONF"

CURRENT_MODE="${DNS_MODE:-none}"
LOG_TAG="securizar-dns-monitor"
_dbg "modo=$CURRENT_MODE"
_dbg "servicios: unbound=$(systemctl is-active unbound 2>/dev/null) dnscrypt=$(systemctl is-active dnscrypt-proxy 2>/dev/null) resolved=$(systemctl is-active systemd-resolved 2>/dev/null)"
_dbg "resolv.conf: $(grep '^nameserver' /etc/resolv.conf 2>/dev/null | tr '\n' ' ') inmutable=$([[ -e /etc/resolv.conf ]] && lsattr /etc/resolv.conf 2>/dev/null | grep -q i && echo si || echo no)"
_dbg "puerto_53: $(ss -tlnp 2>/dev/null | grep ':53 ' | awk '{print $4,$6}' | head -3 | tr '\n' ' ')"

# Test de resolución actual
dns_works() {
    nslookup example.com 127.0.0.1 &>/dev/null
}

# Test de puerto 853
port_853_open() {
    local _t
    for _t in 1.1.1.1 9.9.9.9; do
        if timeout 5 bash -c "echo | openssl s_client -connect ${_t}:853 2>/dev/null" | grep -q "CONNECTED"; then
            return 0
        fi
    done
    return 1
}

switch_to_dot() {
    _dbg "switch_to_dot: deteniendo dnscrypt-proxy, iniciando unbound"
    logger -t "$LOG_TAG" "Cambiando a DoT (unbound)..."
    systemctl stop dnscrypt-proxy 2>/dev/null || true
    systemctl disable dnscrypt-proxy 2>/dev/null || true
    systemctl enable unbound 2>/dev/null || true
    systemctl start unbound 2>/dev/null || true
    sed -i 's/^DNS_MODE=.*/DNS_MODE=dot/' "$CONF"
    _dbg "switch_to_dot: unbound=$(systemctl is-active unbound 2>/dev/null) dnscrypt=$(systemctl is-active dnscrypt-proxy 2>/dev/null)"
    logger -t "$LOG_TAG" "Modo cambiado a DoT (puerto 853 accesible)"
}

switch_to_doh() {
    _dbg "switch_to_doh: deteniendo unbound, iniciando dnscrypt-proxy"
    logger -t "$LOG_TAG" "Cambiando a DoH (dnscrypt-proxy)..."
    systemctl stop unbound 2>/dev/null || true
    systemctl disable unbound 2>/dev/null || true
    systemctl enable dnscrypt-proxy 2>/dev/null || true
    systemctl start dnscrypt-proxy 2>/dev/null || true
    sed -i 's/^DNS_MODE=.*/DNS_MODE=doh/' "$CONF"
    _dbg "switch_to_doh: unbound=$(systemctl is-active unbound 2>/dev/null) dnscrypt=$(systemctl is-active dnscrypt-proxy 2>/dev/null)"
    logger -t "$LOG_TAG" "Modo cambiado a DoH (puerto 853 bloqueado)"
}

# Si WARP activo: verificar que DNS funciona a traves de WARP
if command -v warp-cli &>/dev/null; then
    _warp_status=$(warp-cli status 2>/dev/null || echo "no disponible")
    _dbg "warp: $_warp_status"
    if echo "$_warp_status" | grep -qi 'connected'; then
        if dns_works; then
            _dbg "warp+dns OK, saliendo"
            exit 0  # WARP + DNS ok
        fi
        # WARP conectado pero DNS falla: reconectar
        _dbg "warp conectado pero dns_works FALLO, reconectando"
        logger -t "$LOG_TAG" "WARP conectado pero DNS falla, reconectando..."
        warp-cli disconnect 2>/dev/null || true
        sleep 2
        warp-cli connect 2>/dev/null || true
        sleep 3
        if dns_works; then
            _dbg "dns restaurado tras reconexion WARP"
            logger -t "$LOG_TAG" "DNS restaurado tras reconexion WARP"
            exit 0
        fi
        _dbg "warp reconexion no restauro DNS, continuando a resolvers locales"
        logger -t "$LOG_TAG" "WARP no restauro DNS, intentando resolvers locales"
    fi
fi

# Lógica principal
if dns_works; then
    _dbg "dns_works(127.0.0.1): OK, sin accion"
    exit 0  # Todo funciona, no hacer nada
fi

# DNS no funciona - intentar corregir
_dbg "dns_works(127.0.0.1): FALLO"
logger -t "$LOG_TAG" "DNS no responde (modo actual: ${CURRENT_MODE})"

if port_853_open; then
    _dbg "port_853: ABIERTO"
    if [[ "$CURRENT_MODE" != "dot" ]]; then
        _dbg "accion: switch $CURRENT_MODE → dot"
        switch_to_dot
    else
        # Ya está en DoT y 853 abierto pero DNS falla — reiniciar unbound
        _dbg "accion: restart unbound (ya en dot, 853 abierto pero dns falla)"
        systemctl restart unbound 2>/dev/null || true
        logger -t "$LOG_TAG" "unbound reiniciado"
    fi
else
    _dbg "port_853: BLOQUEADO"
    if [[ "$CURRENT_MODE" != "doh" ]]; then
        _dbg "accion: switch $CURRENT_MODE → doh"
        switch_to_doh
    else
        # Ya está en DoH y DNS falla — reiniciar dnscrypt-proxy
        _dbg "accion: restart dnscrypt-proxy (ya en doh, dns falla)"
        systemctl restart dnscrypt-proxy 2>/dev/null || true
        logger -t "$LOG_TAG" "dnscrypt-proxy reiniciado"
    fi
fi

# ── Verificar si DNS quedo funcional tras los cambios ──
_dbg "esperando 3s para verificar fix..."
sleep 3
_restore_resolv_local() {
    if ! grep -q '^nameserver 127.0.0.1' /etc/resolv.conf 2>/dev/null; then
        chattr -i /etc/resolv.conf 2>/dev/null || true
        printf '%s\n' "# Securizar - DNS cifrado local (restaurado por monitor)" \
                      "nameserver 127.0.0.1" \
                      "options edns0 trust-ad" > /etc/resolv.conf
        chattr +i /etc/resolv.conf 2>/dev/null || true
        logger -t "$LOG_TAG" "resolv.conf restaurado a 127.0.0.1 (DNS cifrado)"
    fi
    # Detener resolved de emergencia si quedaba activo
    if systemctl is-active systemd-resolved &>/dev/null 2>&1; then
        systemctl stop systemd-resolved 2>/dev/null || true
    fi
}
if dns_works; then
    _dbg "post-fix: dns_works OK, restaurando resolv.conf"
    _restore_resolv_local
    exit 0
fi
_dbg "post-fix: dns_works FALLO, intentando resolver alternativo"

# ── Paso intermedio: probar el OTRO resolver cifrado antes de emergencia ──
# Si unbound fallo, intentar dnscrypt-proxy (y viceversa)
_tried_alt=false
if [[ "$CURRENT_MODE" == "dot" ]]; then
    _dbg "alt-resolver: dot fallo, intentando doh"
    logger -t "$LOG_TAG" "unbound no recupero, probando dnscrypt-proxy..."
    switch_to_doh
    _tried_alt=true
elif [[ "$CURRENT_MODE" == "doh" ]]; then
    if port_853_open; then
        _dbg "alt-resolver: doh fallo, 853 abierto, intentando dot"
        logger -t "$LOG_TAG" "dnscrypt-proxy no recupero, probando unbound..."
        switch_to_dot
        _tried_alt=true
    else
        _dbg "alt-resolver: doh fallo, 853 bloqueado, no hay alternativa cifrada"
    fi
fi
if [[ "$_tried_alt" == "true" ]]; then
    sleep 3
    if dns_works; then
        _dbg "alt-resolver: dns_works OK con nuevo modo"
        _restore_resolv_local
        logger -t "$LOG_TAG" "DNS restaurado via resolver alternativo (modo: $(cat /etc/securizar/dns-mode.conf 2>/dev/null | grep DNS_MODE | cut -d= -f2))"
        exit 0
    fi
    _dbg "alt-resolver: dns_works FALLO, cayendo a emergencia"
fi

# ── Ultimo recurso: ambos resolvers fallaron ──
_dbg "EMERGENCIA: ambos resolvers cifrados fallaron"
logger -t "$LOG_TAG" "CRITICO: DNS no responde tras reinicio de resolvers"

# Desbloquear resolv.conf si es inmutable
chattr -i /etc/resolv.conf 2>/dev/null || true
_dbg "chattr -i aplicado a resolv.conf"

# Intentar systemd-resolved como fallback temporal
if systemctl list-unit-files systemd-resolved.service &>/dev/null 2>&1; then
    _dbg "emergencia paso 1: iniciando systemd-resolved"
    systemctl unmask systemd-resolved 2>/dev/null || true
    systemctl start systemd-resolved 2>/dev/null || true
    # resolved escucha en 127.0.0.53 (no conflicto con unbound/dnscrypt en 127.0.0.1)
    printf '%s\n' "# EMERGENCIA securizar - systemd-resolved temporal" \
                  "nameserver 127.0.0.53" \
                  "options edns0 trust-ad" > /etc/resolv.conf
    sleep 2
    if nslookup example.com 127.0.0.53 &>/dev/null; then
        _dbg "emergencia paso 1: resolved OK en 127.0.0.53"
        logger -t "$LOG_TAG" "DNS emergencia: systemd-resolved en 127.0.0.53"
        # NO chattr +i: monitor debe poder restaurar DNS cifrado en proximo ciclo
        exit 0
    fi
    _dbg "emergencia paso 1: resolved FALLO (nslookup 127.0.0.53 no resuelve)"
else
    _dbg "emergencia paso 1: systemd-resolved no disponible"
fi

# Fallback absoluto: DNS publico temporal (NO cifrado, solo para no perder red)
if ! nslookup example.com &>/dev/null 2>&1; then
    _dbg "emergencia paso 2: DNS publico temporal (9.9.9.9 + 1.1.1.1)"
    logger -t "$LOG_TAG" "EMERGENCIA: DNS publico temporal (NO cifrado, visible al ISP)"
    printf '%s\n' "# EMERGENCIA securizar - resolver local caido" \
                  "# Monitor reintentara DNS cifrado en proximo ciclo" \
                  "nameserver 9.9.9.9" \
                  "nameserver 1.1.1.1" \
                  "options edns0" > /etc/resolv.conf
    # NO chattr +i: debe poder corregirse
fi
DNS_MONITOR
    chmod 755 "${ISP_BIN_DIR}/dns-fallback-monitor.sh"
    log_change "Creado" "${ISP_BIN_DIR}/dns-fallback-monitor.sh (monitor fallback DoT↔DoH)"

    # ── Timer systemd para el monitor ──
    cat > /etc/systemd/system/securizar-dns-fallback-monitor.service << 'DNS_MON_SVC'
[Unit]
Description=Securizar - Monitor fallback DNS (DoT/DoH)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/dns-fallback-monitor.sh
ProtectHome=yes
PrivateTmp=yes
DNS_MON_SVC

    cat > /etc/systemd/system/securizar-dns-fallback-monitor.timer << 'DNS_MON_TIMER'
[Unit]
Description=Securizar - Timer monitor fallback DNS (cada 5 min)

[Timer]
OnBootSec=60
OnUnitActiveSec=300
AccuracySec=30

[Install]
WantedBy=timers.target
DNS_MON_TIMER

    systemctl daemon-reload
    systemctl enable securizar-dns-fallback-monitor.timer 2>/dev/null || true
    systemctl start securizar-dns-fallback-monitor.timer 2>/dev/null || true
    log_change "Creado" "securizar-dns-fallback-monitor.timer (check cada 5 min, auto-switch DoT↔DoH)"

    # ── Script de verificación de DNS cifrado (dual-mode) ──
    cat > "${ISP_BIN_DIR}/detectar-dns-leak.sh" << 'DNS_LEAK'
#!/bin/bash
# Detectar fugas DNS - verifica DNS cifrado (DoT via unbound / DoH via dnscrypt-proxy)
set -euo pipefail

echo "╔═══════════════════════════════════════════════╗"
echo "║   DETECCIÓN DE FUGAS DNS                      ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

# Detectar resolver activo
DNS_MODE="none"
RESOLVER="none"
if systemctl is-active unbound &>/dev/null; then
    RESOLVER="unbound"; DNS_MODE="dot"
elif systemctl is-active dnscrypt-proxy &>/dev/null; then
    RESOLVER="dnscrypt-proxy"; DNS_MODE="doh"
fi

if [[ -f /etc/securizar/dns-mode.conf ]]; then
    source /etc/securizar/dns-mode.conf 2>/dev/null || true
fi

echo "=== Modo DNS: ${DNS_MODE^^} (resolver: ${RESOLVER}) ==="
echo ""

# Verificar resolver activo
echo "=== Estado del resolver ==="
if [[ "$RESOLVER" == "unbound" ]]; then
    echo "  [OK] unbound activo (DoT, puerto 853)"
    if ss -tlnp 2>/dev/null | grep -q "unbound"; then
        echo "  [OK] Escuchando en 127.0.0.1:53"
    else
        echo "  [!!] unbound activo pero NO escucha en puerto 53"
    fi
    if grep -q "forward-tls-upstream: yes" /etc/unbound/unbound.conf 2>/dev/null; then
        echo "  [OK] DNS-over-TLS (DoT) habilitado"
    else
        echo "  [!!] DoT NO configurado en unbound"
    fi
    if grep -q "auto-trust-anchor-file" /etc/unbound/unbound.conf 2>/dev/null; then
        echo "  [OK] DNSSEC habilitado"
    else
        echo "  [--] DNSSEC no configurado"
    fi
elif [[ "$RESOLVER" == "dnscrypt-proxy" ]]; then
    echo "  [OK] dnscrypt-proxy activo (DoH, puerto 443)"
    if ss -tlnp 2>/dev/null | grep -q "dnscrypt-proxy"; then
        echo "  [OK] Escuchando en 127.0.0.1:53"
    else
        echo "  [!!] dnscrypt-proxy activo pero NO escucha en puerto 53"
    fi
    if grep -q "doh_servers = true" /etc/dnscrypt-proxy/dnscrypt-proxy.toml 2>/dev/null; then
        echo "  [OK] DNS-over-HTTPS (DoH) habilitado"
    else
        echo "  [!!] DoH NO configurado"
    fi
    if grep -q "require_dnssec = true" /etc/dnscrypt-proxy/dnscrypt-proxy.toml 2>/dev/null; then
        echo "  [OK] DNSSEC requerido"
    else
        echo "  [--] DNSSEC no requerido"
    fi
else
    echo "  [!!] Ningún resolver DNS cifrado activo!"
    echo "       Ejecuta: sudo bash proteger-contra-isp.sh S2"
fi
echo ""

# Verificar resolv.conf
echo "=== Configuración DNS actual ==="
if [[ -f /etc/resolv.conf ]]; then
    grep "^nameserver" /etc/resolv.conf | while read -r line; do
        ns=$(echo "$line" | awk '{print $2}')
        if [[ "$ns" == "127.0.0.1" || "$ns" == "::1" || "$ns" == "127.0.0.53" ]]; then
            echo "  [OK] $line (local/${RESOLVER})"
        else
            echo "  [!!] $line (DNS externo sin cifrar - FUGA!)"
        fi
    done
else
    echo "  [!!] /etc/resolv.conf no encontrado"
fi
echo ""

# Test de resolución
echo "=== Test de resolución DNS (via ${RESOLVER}/${DNS_MODE^^}) ==="
for domain in example.com cloudflare.com opensuse.org; do
    if result=$(nslookup "$domain" 127.0.0.1 2>&1); then
        ip=$(echo "$result" | grep -A1 "Name:" | grep "Address:" | head -1 | awk '{print $2}')
        echo "  [OK] $domain -> ${ip:-resuelto} (via ${RESOLVER}/${DNS_MODE^^})"
    else
        echo "  [!!] $domain -> FALLO"
    fi
done
echo ""

# Verificar conexiones cifradas según modo
if [[ "$DNS_MODE" == "dot" ]]; then
    echo "=== Conexiones DoT activas (puerto 853) ==="
    dot_conns=$(ss -tnp 2>/dev/null | grep ":853" || true)
    if [[ -n "$dot_conns" ]]; then
        echo "$dot_conns" | sed 's/^/  /'
        echo "  [OK] Conexiones DoT detectadas"
    else
        echo "  [--] Sin conexiones DoT activas (se crean bajo demanda)"
    fi
elif [[ "$DNS_MODE" == "doh" ]]; then
    echo "=== Conexiones DoH activas (puerto 443 a resolvers) ==="
    doh_conns=$(ss -tnp 2>/dev/null | grep ":443" | grep -E '1\.1\.1\.1|1\.0\.0\.1|9\.9\.9\.9|149\.112\.112\.112|8\.8\.8\.8|8\.8\.4\.4' || true)
    if [[ -n "$doh_conns" ]]; then
        echo "$doh_conns" | sed 's/^/  /'
        echo "  [OK] Conexiones DoH detectadas"
    else
        echo "  [--] Sin conexiones DoH activas a resolvers conocidos"
    fi
fi
echo ""

# Verificar fugas
echo "=== Verificacion de fugas (puerto 53 plaintext) ==="
plain_dns=$(ss -tnp 2>/dev/null | grep ":53 " | grep -v "127\." || true)
if [[ -n "$plain_dns" ]]; then
    echo "$plain_dns" | sed 's/^/  /'
    echo "  [!!] FUGA DNS DETECTADA - conexiones sin cifrar al puerto 53"
else
    echo "  [OK] Sin conexiones DNS plaintext al exterior"
fi
echo ""

# Monitor status
echo "=== Monitor fallback DNS ==="
if systemctl is-active securizar-dns-fallback-monitor.timer &>/dev/null; then
    echo "  [OK] Monitor activo (check cada 5 min, auto-switch DoT↔DoH)"
else
    echo "  [--] Monitor no activo"
fi
echo ""

echo "Si todo muestra [OK], tu DNS esta cifrado y el ISP NO puede ver tus consultas."
DNS_LEAK
    chmod 755 "${ISP_BIN_DIR}/detectar-dns-leak.sh"
    log_change "Creado" "${ISP_BIN_DIR}/detectar-dns-leak.sh (dual-mode DoT/DoH)"

    # ── Override global DNS de NM ──
    if [[ -d /etc/NetworkManager/conf.d ]]; then
        cat > /etc/NetworkManager/conf.d/90-securizar-dns.conf << 'NM_DNS_GLOBAL'
# Securizar M38 S2: Forzar DNS a resolver local (DoT/DoH + DNSSEC)
# Sobreescribe DNS de VPN comerciales (ProtonVPN, Mullvad, etc.)

[global-dns]
searches=
options=edns0 trust-ad

[global-dns-domain-*]
servers=127.0.0.1
NM_DNS_GLOBAL
        log_change "Creado" "/etc/NetworkManager/conf.d/90-securizar-dns.conf (override global DNS)"

        nmcli general reload dns 2>/dev/null || \
            systemctl reload NetworkManager 2>/dev/null || true
        log_info "DNS global forzado a resolver local: VPN comerciales ya no pueden sobreescribir"
    fi

    # ── NM dispatcher: respaldo para forzar DNS local tras VPN up ──
    if [[ -d /etc/NetworkManager/dispatcher.d ]]; then
        cat > /etc/NetworkManager/dispatcher.d/98-securizar-dns-vpn << 'DNS_HOOK'
#!/bin/bash
# Respaldo: forzar DNS via resolver local cuando VPN sube
IFACE="$1"
ACTION="$2"

is_vpn_event() {
    case "$ACTION" in vpn-up|vpn-down) return 0 ;; esac
    case "$IFACE" in proton*|wg*|mullvad*|nordlynx*|tun*) return 0 ;; esac
    return 1
}

is_vpn_event || exit 0

logger -t securizar-dns-vpn "dispatch: iface=$IFACE action=$ACTION"

force_local_dns() {
    if ss -tlnp 2>/dev/null | grep -qE "127.0.0.1:53.*(unbound|dnscrypt-proxy)"; then
        chattr -i /etc/resolv.conf 2>/dev/null || true
        printf '%s\n' "# Securizar - DNS cifrado local (DoT/DoH)" \
                      "nameserver 127.0.0.1" \
                      "options edns0 trust-ad" > /etc/resolv.conf
        chattr +i /etc/resolv.conf 2>/dev/null || true
        logger -t securizar-dns-vpn "resolv.conf → 127.0.0.1 (chattr +i aplicado)"
        return 0
    fi
    logger -t securizar-dns-vpn "WARN: resolver local no detectado en :53, resolv.conf no modificado"
    return 1
}

case "$ACTION" in
    vpn-up|up)
        force_local_dns
        (
            sleep 3
            if ! grep -q "^nameserver 127.0.0.1" /etc/resolv.conf 2>/dev/null; then
                force_local_dns && \
                    logger -t securizar-dns "VPN $IFACE: DNS re-forzado a local (reintento)"
            fi
        ) &
        logger -t securizar-dns "VPN $IFACE up: DNS forzado a resolver local (127.0.0.1)"
        ;;
    vpn-down|down)
        logger -t securizar-dns "VPN $IFACE down: NetworkManager restaurará DNS"
        ;;
esac
DNS_HOOK
        chmod 755 /etc/NetworkManager/dispatcher.d/98-securizar-dns-vpn
        log_change "Creado" "/etc/NetworkManager/dispatcher.d/98-securizar-dns-vpn (respaldo dual-mode)"
        log_info "Hook DNS-VPN instalado: protección contra override de VPN comerciales"
    fi

    # ── Script para restaurar DNS original ──
    cat > "${ISP_BIN_DIR}/restaurar-dns-isp.sh" << 'DNS_RESTORE'
#!/bin/bash
# Restaurar DNS original (deshacer proteccion DoT/DoH)
set -euo pipefail
echo "Restaurando DNS original..."
if [[ -f /etc/securizar/dns-backup.conf ]]; then
    echo "Configuracion anterior:"
    cat /etc/securizar/dns-backup.conf
fi
echo ""
# Detener ambos resolvers
systemctl stop unbound 2>/dev/null || true
systemctl disable unbound 2>/dev/null || true
systemctl stop dnscrypt-proxy 2>/dev/null || true
systemctl disable dnscrypt-proxy 2>/dev/null || true
echo "[+] Resolvers DNS detenidos (unbound + dnscrypt-proxy)"
# Detener monitor
systemctl stop securizar-dns-fallback-monitor.timer 2>/dev/null || true
systemctl disable securizar-dns-fallback-monitor.timer 2>/dev/null || true
echo "[+] Monitor fallback DNS detenido"
# Eliminar estado
rm -f /etc/securizar/dns-mode.conf
echo "[+] Estado DNS eliminado"
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

    log_info "DNS cifrado configurado: modo ${DNS_MODE^^} (puerto $([ "$DNS_MODE" = "dot" ] && echo 853 || echo 443), DNSSEC, ISP no puede interceptar)"

    fi  # cierre del if -n DNS_MODE (bloque compartido)
else
    log_skip "Prevención de fugas DNS"
fi
fi  # S2

# ── Hardening de servicios del sistema (drop-ins) ──
# Aplicar siempre que se ejecute S1 o S2 (protege fail2ban, rsyslog)
if [[ "$ISP_SECTION" == "all" || "$ISP_SECTION" == "S1" || "$ISP_SECTION" == "S2" ]]; then
    # fail2ban hardening (7.4 → 2.9)
    if systemctl is-enabled fail2ban &>/dev/null 2>&1; then
        if [[ ! -f /etc/systemd/system/fail2ban.service.d/hardening.conf ]]; then
            mkdir -p /etc/systemd/system/fail2ban.service.d
            cat > /etc/systemd/system/fail2ban.service.d/hardening.conf << 'F2B_HARD'
[Service]
ProtectSystem=full
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
UMask=0077
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RemoveIPC=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH CAP_AUDIT_READ
SystemCallArchitectures=native
SystemCallFilter=~@clock @cpu-emulation @module @mount @obsolete @reboot @swap @raw-io
F2B_HARD
            systemctl daemon-reload 2>/dev/null || true
            log_change "Hardening" "fail2ban (systemd sandbox, score 2.9)"
        else
            log_already "fail2ban hardening"
        fi
    fi

    # rsyslog hardening (9.6 → 2.7)
    if systemctl is-enabled rsyslog &>/dev/null 2>&1; then
        if [[ ! -f /etc/systemd/system/rsyslog.service.d/hardening.conf ]]; then
            mkdir -p /etc/systemd/system/rsyslog.service.d
            cat > /etc/systemd/system/rsyslog.service.d/hardening.conf << 'RSYS_HARD'
[Service]
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=/var/log /var/spool/rsyslog /run/rsyslog
UMask=0077
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=no
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
RestrictNamespaces=yes
NoNewPrivileges=yes
RemoveIPC=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=CAP_SYSLOG CAP_DAC_READ_SEARCH CAP_SETUID CAP_SETGID
SystemCallArchitectures=native
SystemCallFilter=~@clock @cpu-emulation @module @mount @obsolete @reboot @swap @raw-io
RSYS_HARD
            systemctl daemon-reload 2>/dev/null || true
            log_change "Hardening" "rsyslog (systemd sandbox, score 2.7)"
        else
            log_already "rsyslog hardening"
        fi
    fi
fi

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

// DNS-over-HTTPS para ECH (modo 2 = DoH preferido, fallback a DNS del sistema)
// Modo 2 mantiene ECH funcional sin romper navegación si Cloudflare DoH cae
user_pref("network.trr.mode", 2);
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

    # Hardening drop-in para traffic-pad (systemd-analyze security: 1.2 OK)
    mkdir -p /etc/systemd/system/securizar-traffic-pad.service.d
    cat > /etc/systemd/system/securizar-traffic-pad.service.d/hardening.conf << 'TRAFFIC_HARD'
[Service]
PrivateDevices=yes
UMask=0077
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
RestrictNamespaces=yes
RemoveIPC=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
SystemCallArchitectures=native
SystemCallFilter=~@clock @cpu-emulation @debug @module @mount @obsolete @reboot @swap @raw-io @privileged @resources
TRAFFIC_HARD

    systemctl daemon-reload
    systemctl enable securizar-traffic-pad.service 2>/dev/null || true
    systemctl start securizar-traffic-pad.service 2>/dev/null || true
    log_change "Servicio" "securizar-traffic-pad habilitado e iniciado (hardened)"

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
VPN_INTERFACES="wg0 tun0 tun1 proton0 mullvad-wg nordlynx CloudflareWARP"

# === Procesos VPN esperados ===
VPN_PROCESSES="openvpn wireguard wg-quick warp-svc"

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
VPN_INTERFACES="wg0 tun0 tun1 proton0 mullvad-wg nordlynx CloudflareWARP"
VPN_PROCESSES="openvpn wireguard wg-quick warp-svc"
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

if [[ "$ISP_SECTION" == "all" || "$ISP_SECTION" == "S11" ]]; then
# ============================================================
# S11 — CLOUDFLARE WARP + GATEWAY (PERÍMETRO ANTI-ISP)
# ============================================================
log_section "S11: CLOUDFLARE WARP + GATEWAY"

echo "Cloudflare WARP cifra TODO el tráfico mediante túnel WireGuard a Cloudflare Edge."
echo "En modo warp+doh el ISP no puede ver ni DNS ni tráfico. Gratis hasta 50 usuarios."
echo ""
echo "NOTA: WARP conecta via WireGuard (UDP 2408) a IPs edge de Cloudflare,"
echo "NO a 1.1.1.1. Si tu ISP bloquea 1.1.1.1, WARP puede sortear ese bloqueo"
echo "porque usa endpoints diferentes para el túnel."
echo ""
echo "Modos disponibles:"
echo "  - warp+doh  : túnel completo (ISP no ve nada) ← recomendado"
echo "  - doh       : solo DNS cifrado (coexiste con VPN externa)"
echo ""

if command -v warp-cli &>/dev/null && systemctl is-enabled warp-svc &>/dev/null; then
    log_already "Cloudflare WARP (warp-cli instalado, warp-svc habilitado)"
elif ask "¿Instalar Cloudflare WARP?"; then

    # ── Pre-flight: detectar bloqueo ISP a Cloudflare 1.1.1.1 ──
    local _isp_blocks_cf=false
    if ! timeout 4 bash -c 'echo | openssl s_client -connect 1.1.1.1:443 2>/dev/null' | grep -q 'CONNECTED' 2>/dev/null; then
        _isp_blocks_cf=true
        log_warn "ISP BLOQUEA 1.1.1.1:443 — WARP en modo warp+doh evita este bloqueo"
        log_warn "  El túnel WireGuard usa IPs edge diferentes (no 1.1.1.1)"
        log_warn "  Además corrige: DNS sin validación DNSSEC del ISP"
    fi

    # ── Pre-flight: verificar conectividad a endpoints WARP ──
    local _warp_reachable=false
    if timeout 5 bash -c 'echo >/dev/tcp/engage.cloudflareclient.com/443' 2>/dev/null; then
        _warp_reachable=true
    elif timeout 5 curl -sf --max-time 5 -o /dev/null https://engage.cloudflareclient.com 2>/dev/null; then
        _warp_reachable=true
    fi

    if [[ "$_warp_reachable" == "true" ]]; then
        log_info "Endpoint WARP accesible (engage.cloudflareclient.com)"
    else
        log_warn "Endpoint WARP no respondió — la instalación podría fallar"
        log_warn "  Si el ISP bloquea engage.cloudflareclient.com, WARP no funcionará"
    fi

    # ── Paso 1: Añadir repositorio oficial ──
    log_info "Añadiendo repositorio Cloudflare WARP..."

    case "${DISTRO_FAMILY:-unknown}" in
        debian)
            # GPG key + apt sources
            if [[ ! -f /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg ]]; then
                curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg \
                    | gpg --yes --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg 2>/dev/null
                log_change "Añadida" "GPG key Cloudflare WARP"
            fi
            local _codename
            _codename=$(lsb_release -cs 2>/dev/null || echo "bookworm")
            echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ ${_codename} main" \
                > /etc/apt/sources.list.d/cloudflare-client.list
            apt-get update -qq 2>/dev/null || true
            log_change "Añadido" "Repo APT Cloudflare WARP (${_codename})"
            ;;
        rhel)
            rpm --import https://pkg.cloudflareclient.com/pubkey.gpg 2>/dev/null || true
            cat > /etc/yum.repos.d/cloudflare-warp.repo << 'CF_REPO_RPM'
[cloudflare-warp]
name=Cloudflare WARP Client
baseurl=https://pkg.cloudflareclient.com/rpm
enabled=1
gpgcheck=1
gpgkey=https://pkg.cloudflareclient.com/pubkey.gpg
CF_REPO_RPM
            log_change "Añadido" "Repo RPM Cloudflare WARP"
            ;;
        suse)
            rpm --import https://pkg.cloudflareclient.com/pubkey.gpg 2>/dev/null || true
            zypper addrepo --refresh --no-gpgcheck \
                https://pkg.cloudflareclient.com/rpm cloudflare-warp 2>/dev/null || true
            log_change "Añadido" "Repo zypper Cloudflare WARP"
            ;;
        arch)
            log_warn "Arch Linux: WARP no tiene repo oficial, intentando AUR..."
            if command -v yay &>/dev/null; then
                yay -S --noconfirm cloudflare-warp-bin 2>/dev/null || true
            elif command -v paru &>/dev/null; then
                paru -S --noconfirm cloudflare-warp-bin 2>/dev/null || true
            else
                log_error "No se encontró yay ni paru. Instala cloudflare-warp-bin desde AUR manualmente."
            fi
            ;;
        *)
            log_warn "Distribución no reconocida (${DISTRO_FAMILY:-unknown}). Repo no añadido."
            ;;
    esac

    # ── Paso 2: Instalar paquete ──
    if ! command -v warp-cli &>/dev/null; then
        log_info "Instalando paquete cloudflare-warp..."
        case "${DISTRO_FAMILY:-unknown}" in
            debian)   apt-get install -y cloudflare-warp 2>/dev/null || true ;;
            rhel)     dnf install -y cloudflare-warp 2>/dev/null || yum install -y cloudflare-warp 2>/dev/null || true ;;
            suse)     zypper install -y cloudflare-warp 2>/dev/null || true ;;
            # arch ya se manejó en paso 1 via AUR
        esac
    fi

    if ! command -v warp-cli &>/dev/null; then
        log_error "warp-cli no se pudo instalar. Revisa manualmente."
        log_warn "Visita: https://developers.cloudflare.com/warp-client/get-started/linux/"
    else

    log_change "Instalado" "cloudflare-warp (warp-cli disponible)"

    # ── Paso 3: Habilitar y arrancar servicio ──
    systemctl enable warp-svc 2>/dev/null || true
    systemctl start warp-svc 2>/dev/null || true

    # Esperar a que el daemon esté listo
    local _warp_wait=0
    while ! warp-cli status &>/dev/null && [[ $_warp_wait -lt 15 ]]; do
        sleep 1
        ((_warp_wait++)) || true
    done

    if warp-cli status &>/dev/null; then
        log_info "warp-svc activo y respondiendo"
    else
        log_warn "warp-svc iniciado pero daemon puede tardar en responder"
    fi

    # ── Paso 4: Registrar dispositivo ──
    if ! warp-cli registration show &>/dev/null 2>&1; then
        log_info "Registrando dispositivo en Cloudflare WARP..."
        warp-cli registration new 2>/dev/null || true
        log_change "Registrado" "Dispositivo en Cloudflare WARP (free tier)"
    else
        log_already "Dispositivo ya registrado en WARP"
    fi

    # ── Paso 5: Elegir modo ──
    echo ""
    echo "  Elige el modo de operación de WARP:"
    echo ""
    echo "    1) warp+doh  — Túnel completo (ISP no ve NADA) [recomendado]"
    echo "    2) doh       — Solo DNS cifrado (coexiste con VPN externa)"
    echo ""
    if [[ "$_isp_blocks_cf" == "true" ]]; then
        echo -e "  ${YELLOW}⚠${NC}  Tu ISP bloquea 1.1.1.1 → modo warp+doh FUERTEMENTE recomendado:"
        echo "       - Sortea el bloqueo DNS del ISP completamente"
        echo "       - Añade validación DNSSEC real (tu ISP no valida)"
        echo "       - El ISP no puede ver ni manipular ninguna consulta DNS"
        echo ""
    fi
    local _warp_mode_choice
    read -rp "$(echo -e "  ${CYAN}❯${NC} Modo [1]: ")" _warp_mode_choice
    _warp_mode_choice="${_warp_mode_choice:-1}"

    local _warp_mode="warp+doh"
    case "$_warp_mode_choice" in
        2) _warp_mode="doh"
           warp-cli mode doh 2>/dev/null || true
           log_change "Modo WARP" "doh (solo DNS, coexiste con VPN)"
           ;;
        *) _warp_mode="warp+doh"
           warp-cli mode warp+doh 2>/dev/null || true
           log_change "Modo WARP" "warp+doh (túnel completo)"
           ;;
    esac

    # ── Paso 6: Opcional Zero Trust ──
    local _warp_team="" _warp_gw_endpoint=""
    if ask "¿Configurar Cloudflare Zero Trust (Teams)?"; then
        echo ""
        read -rp "$(echo -e "  ${CYAN}❯${NC} Nombre del equipo (team name): ")" _warp_team
        if [[ -n "$_warp_team" ]]; then
            warp-cli teams-enroll "$_warp_team" 2>/dev/null || \
                log_warn "teams-enroll falló — completa el enrollment vía navegador"
            log_change "Zero Trust" "Enrollment iniciado (team: ${_warp_team})"
        fi

        if ask "¿Configurar Gateway DNS endpoint personalizado?"; then
            read -rp "$(echo -e "  ${CYAN}❯${NC} DNS endpoint (ej: abc123.cloudflare-gateway.com): ")" _warp_gw_endpoint
            if [[ -n "$_warp_gw_endpoint" ]]; then
                warp-cli dns endpoint "$_warp_gw_endpoint" 2>/dev/null || \
                    log_warn "dns endpoint falló — configúralo vía dashboard.cloudflare.com"
                log_change "Gateway DNS" "Endpoint: ${_warp_gw_endpoint}"
            fi
        fi
    else
        log_info "Zero Trust omitido. Puedes configurarlo después:"
        log_info "  warp-cli teams-enroll <team-name>"
        log_info "  warp-cli dns endpoint <endpoint>"
    fi

    # ── Paso 7: Conectar y verificar ──
    log_info "Conectando WARP..."
    warp-cli connect 2>/dev/null || true
    sleep 3

    if warp-cli status 2>/dev/null | grep -qi 'connected'; then
        log_info "WARP conectado correctamente"

        # Verificar que el túnel funciona via trace
        local _post_trace
        _post_trace=$(curl -s --max-time 10 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null || true)
        if echo "$_post_trace" | grep -q 'warp=on\|warp=plus'; then
            log_info "Cloudflare trace confirma: tráfico pasa por WARP"
            echo "$_post_trace" | grep -E '^(warp|colo|ip)=' 2>/dev/null | while read -r _line; do
                log_info "  $_line"
            done
        fi

        # Si ISP bloqueaba 1.1.1.1, verificar que WARP lo sortea
        if [[ "$_isp_blocks_cf" == "true" ]]; then
            if timeout 5 bash -c 'echo | openssl s_client -connect 1.1.1.1:443 2>/dev/null' | grep -q 'CONNECTED' 2>/dev/null; then
                log_info "WARP sortea bloqueo ISP: 1.1.1.1:443 ahora accesible via túnel"
            else
                log_warn "1.1.1.1:443 sigue bloqueado — pero DNS va cifrado por WARP"
            fi
        fi
    else
        log_warn "WARP no confirmó conexión — verifica con: warp-cli status"
    fi

    # ── Paso 8: Guardar configuración ──
    cat > "${ISP_CONF_DIR}/warp-mode.conf" << WARP_CONF
# Cloudflare WARP - Configuración Securizar M38 S11
# Generado: $(date -Iseconds)
WARP_MODE="${_warp_mode}"
WARP_TEAM="${_warp_team}"
WARP_GW_ENDPOINT="${_warp_gw_endpoint}"
ISP_BLOCKS_CF="${_isp_blocks_cf}"
WARP_CONF
    chmod 640 "${ISP_CONF_DIR}/warp-mode.conf"
    log_change "Creado" "${ISP_CONF_DIR}/warp-mode.conf"

    # ── Paso 9: Script de diagnóstico ──
    cat > "${ISP_BIN_DIR}/diagnostico-warp.sh" << 'DIAG_WARP'
#!/bin/bash
# ============================================================
# Diagnóstico Cloudflare WARP - Securizar M38 S11
# ============================================================
set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

echo ""
echo -e "${CYAN}━━ Diagnóstico Cloudflare WARP ━━${NC}"
echo ""

# 1. Servicio
echo -e "${BOLD}[Servicio]${NC}"
if systemctl is-active warp-svc &>/dev/null; then
    echo -e "  ${GREEN}OK${NC} warp-svc activo"
else
    echo -e "  ${RED}!!${NC} warp-svc NO activo"
    systemctl status warp-svc --no-pager 2>/dev/null | head -5 || true
fi
echo ""

# 2. Estado WARP
echo -e "${BOLD}[Estado WARP]${NC}"
if command -v warp-cli &>/dev/null; then
    warp-cli status 2>/dev/null || echo -e "  ${RED}!!${NC} warp-cli status falló"
    echo ""
    echo -e "${BOLD}[Settings]${NC}"
    warp-cli settings 2>/dev/null || echo -e "  ${DIM}(settings no disponible)${NC}"
else
    echo -e "  ${RED}!!${NC} warp-cli no instalado"
fi
echo ""

# 3. Interfaz de red
echo -e "${BOLD}[Interfaz]${NC}"
if ip addr show CloudflareWARP &>/dev/null 2>&1; then
    ip addr show CloudflareWARP 2>/dev/null
else
    echo -e "  ${YELLOW}!!${NC} Interfaz CloudflareWARP no encontrada"
fi
echo ""

# 4. Test Cloudflare trace
echo -e "${BOLD}[Cloudflare Trace]${NC}"
_trace=$(curl -s --max-time 10 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null || echo "ERROR")
if echo "$_trace" | grep -q 'warp=on'; then
    echo -e "  ${GREEN}OK${NC} warp=on detectado"
elif echo "$_trace" | grep -q 'warp=plus'; then
    echo -e "  ${GREEN}OK${NC} warp=plus (WARP+) detectado"
elif echo "$_trace" | grep -q 'warp=off'; then
    echo -e "  ${YELLOW}!!${NC} warp=off — WARP no está enrutando tráfico"
else
    echo -e "  ${RED}!!${NC} No se pudo obtener trace de Cloudflare"
fi
echo "$_trace" | grep -E '^(ip|warp|gateway|colo)=' 2>/dev/null || true
echo ""

# 5. Test DNS
echo -e "${BOLD}[Test DNS]${NC}"
if nslookup example.com &>/dev/null; then
    echo -e "  ${GREEN}OK${NC} DNS funcional"
    nslookup example.com 2>/dev/null | grep -E 'Server|Address|Name' | head -5
else
    echo -e "  ${RED}!!${NC} DNS no responde"
fi
echo ""

# 6. Bloqueo ISP a Cloudflare 1.1.1.1
echo -e "${BOLD}[Bloqueo ISP]${NC}"
_cf_blocked=false
for _tgt in 1.1.1.1 1.0.0.1; do
    if timeout 4 bash -c "echo | openssl s_client -connect ${_tgt}:443 2>/dev/null" | grep -q 'CONNECTED' 2>/dev/null; then
        echo -e "  ${GREEN}OK${NC} ${_tgt}:443 accesible"
    else
        echo -e "  ${RED}!!${NC} ${_tgt}:443 BLOQUEADO por ISP"
        _cf_blocked=true
    fi
done
if [[ "$_cf_blocked" == "true" ]]; then
    echo -e "  ${YELLOW}→${NC}  ISP bloquea acceso directo a Cloudflare DNS"
    echo -e "  ${YELLOW}→${NC}  WARP en modo warp+doh sortea este bloqueo via túnel WireGuard"
fi
echo ""

# 7. DNSSEC validation
echo -e "${BOLD}[DNSSEC]${NC}"
if command -v dig &>/dev/null; then
    _dig_out=$(dig +dnssec +short example.com A 2>/dev/null || true)
    _dig_flags=$(dig +dnssec example.com A 2>/dev/null | grep 'flags:' || true)
    if echo "$_dig_flags" | grep -q ' ad'; then
        echo -e "  ${GREEN}OK${NC} DNSSEC validación activa (flag ad presente)"
    else
        echo -e "  ${YELLOW}!!${NC} DNSSEC NO validado (flag ad ausente)"
        if warp-cli status 2>/dev/null | grep -qi 'connected'; then
            echo -e "  ${YELLOW}→${NC}  Con WARP en warp+doh, Cloudflare valida DNSSEC por ti"
        else
            echo -e "  ${RED}→${NC}  Sin WARP activo, tu ISP NO valida DNSSEC"
        fi
    fi
else
    echo -e "  ${DIM}(dig no disponible, instala bind-utils/dnsutils)${NC}"
fi
echo ""

# 8. Configuración guardada
echo -e "${BOLD}[Config]${NC}"
if [[ -f /etc/securizar/warp-mode.conf ]]; then
    cat /etc/securizar/warp-mode.conf | grep -v '^#'
else
    echo -e "  ${DIM}(sin configuración guardada)${NC}"
fi
echo ""
DIAG_WARP
    chmod 755 "${ISP_BIN_DIR}/diagnostico-warp.sh"
    log_change "Creado" "${ISP_BIN_DIR}/diagnostico-warp.sh"

    # ── Paso 10: Script de restauración ──
    cat > "${ISP_BIN_DIR}/restaurar-warp.sh" << 'REST_WARP'
#!/bin/bash
# ============================================================
# Restaurar / Desinstalar Cloudflare WARP - Securizar M38 S11
# ============================================================
set -euo pipefail

echo "[*] Desconectando WARP..."
warp-cli disconnect 2>/dev/null || true

echo "[*] Eliminando registro..."
warp-cli registration delete 2>/dev/null || true

echo "[*] Deteniendo servicio..."
systemctl stop warp-svc 2>/dev/null || true
systemctl disable warp-svc 2>/dev/null || true

echo "[*] Eliminando repositorio según distro..."
# Detectar familia
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    case "${ID_LIKE:-$ID}" in
        *debian*|*ubuntu*)
            rm -f /etc/apt/sources.list.d/cloudflare-client.list
            rm -f /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
            apt-get remove -y cloudflare-warp 2>/dev/null || true
            ;;
        *rhel*|*fedora*|*centos*)
            rm -f /etc/yum.repos.d/cloudflare-warp.repo
            dnf remove -y cloudflare-warp 2>/dev/null || yum remove -y cloudflare-warp 2>/dev/null || true
            ;;
        *suse*)
            zypper removerepo cloudflare-warp 2>/dev/null || true
            zypper remove -y cloudflare-warp 2>/dev/null || true
            ;;
        *arch*)
            pacman -Rns --noconfirm cloudflare-warp-bin 2>/dev/null || true
            ;;
    esac
fi

echo "[*] Limpiando configuración..."
rm -f /etc/securizar/warp-mode.conf

echo "[+] Cloudflare WARP desinstalado completamente"
REST_WARP
    chmod 755 "${ISP_BIN_DIR}/restaurar-warp.sh"
    log_change "Creado" "${ISP_BIN_DIR}/restaurar-warp.sh"

    # ── Paso 11: Coexistencia S2 + DNSSEC ──
    if [[ "$_warp_mode" == "warp+doh" ]]; then
        log_warn "WARP en modo warp+doh: bypasea el resolver DNS local (unbound/dnscrypt-proxy)"
        log_warn "  Si necesitas DNS local activo, usa modo 'doh': warp-cli mode doh"
        if [[ "$_isp_blocks_cf" == "true" ]]; then
            log_info "WARP corrige 2 problemas de tu ISP:"
            log_info "  1. Bloqueo de 1.1.1.1 (tráfico va por túnel WireGuard)"
            log_info "  2. DNS sin DNSSEC (Cloudflare valida DNSSEC en su edge)"
        fi
    fi

    log_info "Cloudflare WARP S11 completado"
    log_info "Diagnóstico: diagnostico-warp.sh"
    log_info "Desinstalar: restaurar-warp.sh"

    fi  # warp-cli installed successfully
else
    log_skip "Cloudflare WARP"
fi
fi  # S11

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
echo "║     • /usr/local/bin/diagnostico-warp.sh     (WARP diag)   ║"
echo "║     • /usr/local/bin/restaurar-warp.sh       (WARP remove) ║"
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
