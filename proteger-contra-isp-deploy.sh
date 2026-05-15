#!/bin/bash
# ============================================================
# PROTECCIÓN CONTRA ESPIONAJE ISP — DEPLOY VPS DEBIAN
# ============================================================
# Versión optimizada para servidores VPS Debian (sin escritorio).
# Eliminado: Tor, Cloudflare WARP, obfs4proxy, stunnel, Firefox,
#            MAC randomization, NetworkManager hooks.
#
# Protege contra vigilancia a nivel de ISP en un VPS:
#   - Kill switch VPN (nftables, protección SSH integrada)
#   - Prevención de fugas DNS (DoT via unbound + DNSSEC)
#   - NTP con NTS (Network Time Security)
#   - Ofuscación de patrones de tráfico
#   - Deshabilitación de IPv6
#   - Hardening de servicios (systemd sandbox)
#   - Auditoría de metadatos ISP
#
# Secciones:
#   S1  - VPN Kill Switch (nftables)
#   S2  - Prevención de fugas DNS (unbound DoT)
#   S3  - NTP con NTS (chrony)
#   S4  - Ofuscación de patrones de tráfico
#   S5  - Auditoría de metadatos ISP
# ============================================================

set -euo pipefail

ISP_SECTION="${1:-all}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps

# ── Validar que estamos en Debian/Ubuntu ────────────────────
if [[ "${DISTRO_FAMILY:-}" != "debian" ]]; then
    log_error "Este script está optimizado para Debian/Ubuntu."
    log_error "Distribución detectada: ${DISTRO_FAMILY:-desconocida} (${DISTRO_ID:-})"
    log_info  "Para multi-distro usa: proteger-contra-isp.sh"
    exit 1
fi

# ── Validar nftables disponible ─────────────────────────────
if ! command -v nft &>/dev/null; then
    log_info "nftables no encontrado, instalando..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y nftables >/dev/null 2>&1 || true
    if ! command -v nft &>/dev/null; then
        log_error "nftables no se pudo instalar. Requerido para el kill switch."
        exit 1
    fi
fi

# ── Variables ────────────────────────────────────────────────
ISP_CONF_DIR="/etc/securizar"
ISP_BIN_DIR="/usr/local/bin"

# ── Detectar IP SSH activa (para proteger acceso) ───────────
_detect_ssh_source_ip() {
    # Obtiene la IP desde la que está conectada la sesión SSH actual
    local _ssh_ip=""
    if [[ -n "${SSH_CLIENT:-}" ]]; then
        _ssh_ip="${SSH_CLIENT%% *}"
    elif [[ -n "${SSH_CONNECTION:-}" ]]; then
        _ssh_ip="${SSH_CONNECTION%% *}"
    fi
    echo "$_ssh_ip"
}

_detect_ssh_port() {
    local _port
    _port=$(ss -tlnp 2>/dev/null | grep -oP ':\K(22|[0-9]+)(?=\s)' | head -1)
    if [[ -z "$_port" ]]; then
        _port=$(grep -oP '^\s*Port\s+\K[0-9]+' /etc/ssh/sshd_config 2>/dev/null | head -1)
    fi
    echo "${_port:-22}"
}

# ── Helpers DNS ─────────────────────────────────────────────
_detect_dns_resolver() {
    if systemctl is-active unbound &>/dev/null; then echo "unbound"
    else echo "none"; fi
}

# ── Verificación exhaustiva ─────────────────────────────────
_isp_verificacion_exhaustiva() {
    local ok=0 total=20
    local _r _dns_resolver
    _dns_resolver=$(_detect_dns_resolver)

    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║   VERIFICACIÓN — Protección ISP (VPS Debian)                 ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""

    # ── VPN (5 checks) ──
    echo -e "  ${BOLD}[VPN]${NC}"

    _r="!!"
    if [[ -f /etc/securizar/vpn-killswitch.sh ]]; then _r="OK"; ((ok++)) || true; fi
    echo -e "    ${_r} Script kill switch existe"

    _r="!!"
    if [[ -f /etc/securizar/vpn-killswitch-off.sh ]]; then _r="OK"; ((ok++)) || true; fi
    echo -e "    ${_r} Script kill switch OFF existe"

    _r="!!"
    if nft list table inet securizar_ks &>/dev/null 2>&1; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} Kill switch ACTIVO (nftables)"

    _r="!!"
    if systemctl is-enabled securizar-vpn-killswitch.service &>/dev/null; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} Servicio kill switch habilitado"

    _r="!!"
    if ip link show 2>/dev/null | grep -qE '(wg[0-9]|tun[0-9]|tap[0-9])' || \
       { command -v wg &>/dev/null && wg show interfaces 2>/dev/null | grep -q .; }; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} Interfaz VPN activa"
    echo ""

    # ── DNS (6 checks) ──
    echo -e "  ${BOLD}[DNS]${NC} (modo: ${_dns_resolver})"

    _r="!!"
    if [[ "$_dns_resolver" != "none" ]]; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} DNS cifrado activo (unbound)"

    _r="!!"
    if [[ -f /etc/unbound/unbound.conf ]] && grep -q 'forward-tls-upstream' /etc/unbound/unbound.conf 2>/dev/null; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} DoT configurado (unbound)"

    _r="!!"
    if [[ -f /etc/unbound/unbound.conf ]] && grep -q 'auto-trust-anchor-file' /etc/unbound/unbound.conf 2>/dev/null; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} DNSSEC habilitado"

    _r="!!"
    if grep -q '^nameserver 127\.0\.0\.1' /etc/resolv.conf 2>/dev/null; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} resolv.conf apunta a 127.0.0.1"

    _r="!!"
    if [[ "$_dns_resolver" != "none" ]]; then
        if command -v dig &>/dev/null; then
            local _dig_server=""
            _dig_server=$(dig +short +timeout=3 +tries=1 cloudflare.com @127.0.0.1 2>/dev/null | head -1 || true)
            if [[ -n "$_dig_server" ]]; then
                _r="OK"; ((ok++)) || true
            fi
        elif timeout 3 bash -c 'echo > /dev/tcp/127.0.0.1/53' 2>/dev/null; then
            _r="OK"; ((ok++)) || true
        fi
    fi
    echo -e "    ${_r} DNS resolver responde en localhost"
    echo ""

    # ── Red (4 checks) ──
    echo -e "  ${BOLD}[Red]${NC}"

    _r="!!"
    if [[ -f /etc/sysctl.d/99-securizar-ipv6.conf ]] && \
       sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null | grep -q '1'; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} IPv6 deshabilitado (sysctl)"

    _r="!!"
    if nft list table inet securizar_ks 2>/dev/null | grep -q '853'; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} Puerto 853 (DoT) permitido en firewall"

    _r="!!"
    if systemctl is-active securizar-traffic-pad.service &>/dev/null; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} Traffic padding activo"

    _r="!!"
    if ! systemctl is-active avahi-daemon &>/dev/null; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} avahi-daemon inactivo"
    echo ""

    # ── Tiempo (2 checks) ──
    echo -e "  ${BOLD}[Tiempo]${NC}"

    _r="!!"
    if [[ -f /etc/chrony/conf.d/securizar-nts.conf ]] && systemctl is-active chronyd &>/dev/null; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} Chrony NTS activo"

    _r="!!"
    if ! systemctl is-active systemd-timesyncd &>/dev/null; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} timesyncd inactivo"
    echo ""

    # ── Herramientas (2 checks) ──
    echo -e "  ${BOLD}[Herramientas]${NC}"

    _r="!!"
    if [[ -x /usr/local/bin/auditoria-isp.sh ]]; then _r="OK"; ((ok++)) || true; fi
    echo -e "    ${_r} auditoria-isp.sh"

    _r="!!"
    if [[ -x /usr/local/bin/detectar-dns-leak.sh ]]; then _r="OK"; ((ok++)) || true; fi
    echo -e "    ${_r} detectar-dns-leak.sh"
    echo ""

    # ── Integración (3 checks) ──
    echo -e "  ${BOLD}[Integración]${NC}"

    _r="!!"
    local _vpn_ok=0 _ks_ok=0 _dns_ok=0
    if ip link show 2>/dev/null | grep -qE '(wg[0-9]|tun[0-9]|tap[0-9])' || \
       { command -v wg &>/dev/null && wg show interfaces 2>/dev/null | grep -q .; }; then
        _vpn_ok=1
    fi
    if nft list table inet securizar_ks &>/dev/null 2>&1; then _ks_ok=1; fi
    if [[ "$_dns_resolver" != "none" ]]; then _dns_ok=1; fi
    if [[ $_vpn_ok -eq 1 ]] && [[ $_ks_ok -eq 1 ]] && [[ $_dns_ok -eq 1 ]]; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} Tríada VPN + Kill switch + DNS cifrado"

    _r="!!"
    if [[ $_ks_ok -eq 1 ]] && sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null | grep -q '1'; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} Kill switch + IPv6 deshabilitado (sin bypass)"

    _r="!!"
    if [[ $_dns_ok -eq 1 ]] && grep -q '^nameserver 127\.0\.0\.1' /etc/resolv.conf 2>/dev/null; then
        _r="OK"; ((ok++)) || true
    fi
    echo -e "    ${_r} DNS cifrado + resolv.conf local (sin DNS leak)"
    echo ""

    # ── Scoring ──
    echo "  ─────────────────────────────────────────"
    local nivel color pct=0
    if [[ $ok -ge $((total * 90 / 100)) ]]; then
        nivel="EXCELENTE"; color="${GREEN}"
    elif [[ $ok -ge $((total * 65 / 100)) ]]; then
        nivel="BUENO"; color="${CYAN}"
    elif [[ $ok -ge $((total * 40 / 100)) ]]; then
        nivel="MEJORABLE"; color="${YELLOW}"
    else
        nivel="DEFICIENTE"; color="${RED}"
    fi
    [[ $total -gt 0 ]] && pct=$((ok * 100 / total)) || true
    echo -e "  Resultado: ${BOLD}${ok}/${total} OK${NC} (${pct}%) — ${color}${BOLD}${nivel}${NC}"

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
        echo -e "  ${RED}▸${NC} ${BOLD}Sin DNS cifrado${NC} — el ISP ve cada dominio que consultas"
        ((_gaps++)) || true
    fi
    if [[ $_gaps -eq 0 ]]; then
        echo -e "  ${GREEN}▸${NC} Sin brechas críticas detectadas"
    fi
    echo ""
}

# ── Handler --verify ────────────────────────────────────────
if [[ "$ISP_SECTION" == "--verify" ]]; then
    _isp_verificacion_exhaustiva
    exit 0
fi

# ── Pre-check ───────────────────────────────────────────────
if [[ "$ISP_SECTION" == "all" ]]; then
_precheck 5
_pc 'check_file_exists /etc/securizar/vpn-killswitch.sh && check_file_exists /etc/systemd/system/securizar-vpn-killswitch.service && check_file_exists /etc/sysctl.d/99-securizar-ipv6.conf'
_pc 'check_service_enabled unbound'
_pc 'check_file_exists /etc/chrony/conf.d/securizar-nts.conf'
_pc 'check_service_enabled securizar-traffic-pad.service'
_pc 'check_executable /usr/local/bin/auditoria-isp.sh'
_precheck_result
fi

mkdir -p "$ISP_CONF_DIR"

if [[ "$ISP_SECTION" == "all" ]]; then
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   PROTECCIÓN CONTRA ISP — VPS DEBIAN                      ║"
echo "║   Kill switch, DNS leak, NTS, padding, auditoría           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

echo "Capacidades que se instalarán:"
echo ""
echo -e "  ${CYAN}S1${NC}  VPN Kill Switch (nftables, protección SSH)"
echo -e "  ${CYAN}S2${NC}  Prevención de fugas DNS (unbound DoT, DNSSEC)"
echo -e "  ${CYAN}S3${NC}  NTP con NTS (Network Time Security)"
echo -e "  ${CYAN}S4${NC}  Ofuscación de patrones de tráfico"
echo -e "  ${CYAN}S5${NC}  Auditoría de metadatos ISP"
echo ""
fi

if [[ "$ISP_SECTION" == "all" || "$ISP_SECTION" == "S1" ]]; then
# ============================================================
# S1 — VPN KILL SWITCH (nftables, optimizado VPS Debian)
# ============================================================
log_section "S1: VPN KILL SWITCH"

echo "Crea reglas nftables que bloquean TODO tráfico si la VPN cae."
echo "Protege acceso SSH actual para evitar lockout del VPS."
echo "Permite: loopback, LAN, DHCP, SSH, interfaces VPN."
echo ""

if check_file_exists /etc/securizar/vpn-killswitch.sh; then
    log_already "VPN Kill Switch (scripts ya creados)"
elif ask "¿Configurar VPN Kill Switch?"; then

    _SSH_PORT=$(_detect_ssh_port)
    _SSH_SRC=$(_detect_ssh_source_ip)
    log_info "SSH detectado: puerto ${_SSH_PORT}, IP origen: ${_SSH_SRC:-cualquiera}"

    # Script para activar kill switch
    cat > "${ISP_CONF_DIR}/vpn-killswitch.sh" << 'KILLSWITCH_ON'
#!/bin/bash
# VPN Kill Switch - Activar (nftables, VPS Debian)
# Bloquea todo tráfico que no pase por VPN.
# Protege SSH para evitar lockout.
set -euo pipefail

_KS_LOG="/var/log/securizar/debug.log"
mkdir -p /var/log/securizar 2>/dev/null || true
_dbg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] killswitch-on: $*" >> "$_KS_LOG" 2>/dev/null || true; }
_dbg "=== ACTIVACION kill switch ==="
_dbg "PID=$$ UID=$(id -u) invocado_por=$(ps -o comm= $PPID 2>/dev/null || echo desconocido)"

# ── Detectar puerto SSH ──
_SSH_PORT=$(ss -tlnp 2>/dev/null | grep -oP ':\K(22|[0-9]+)(?=\s)' | head -1)
_SSH_PORT="${_SSH_PORT:-22}"

# ── Detectar endpoints VPN para permitir reconexión ──
_vpn_endpoints=()
if command -v wg &>/dev/null; then
    while IFS= read -r _ep; do
        [[ -n "$_ep" ]] && _vpn_endpoints+=("$_ep")
    done < <(wg show all endpoints 2>/dev/null | awk '{print $2}' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
fi
for _wgcf in /etc/wireguard/*.conf; do
    [[ -f "$_wgcf" ]] || continue
    while IFS= read -r _ep; do
        [[ -n "$_ep" ]] && _vpn_endpoints+=("$_ep")
    done < <(grep -oP 'Endpoint\s*=\s*\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$_wgcf" 2>/dev/null || true)
done
for _ovcf in /etc/openvpn/*.conf /etc/openvpn/client/*.conf /etc/openvpn/*.ovpn; do
    [[ -f "$_ovcf" ]] || continue
    while IFS= read -r _ep; do
        [[ -n "$_ep" ]] && _vpn_endpoints+=("$_ep")
    done < <(grep -oP '^remote\s+\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$_ovcf" 2>/dev/null || true)
done
if [[ -f /etc/securizar/vpn-endpoints.conf ]]; then
    while IFS= read -r _ep; do
        _ep="${_ep%%#*}"; _ep="${_ep// /}"
        [[ -n "$_ep" ]] && _vpn_endpoints+=("$_ep")
    done < /etc/securizar/vpn-endpoints.conf
fi
if [[ ${#_vpn_endpoints[@]} -gt 0 ]]; then
    readarray -t _vpn_endpoints < <(printf '%s\n' "${_vpn_endpoints[@]}" | sort -u)
fi
_dbg "Endpoints: ${#_vpn_endpoints[@]} → ${_vpn_endpoints[*]:-ninguno}"
_dbg "Interfaces VPN: $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -E 'wg|tun|tap' | tr '\n' ' ' || true)"

# ── nftables ──
nft delete table inet securizar_ks 2>/dev/null || true
nft add table inet securizar_ks
nft add chain inet securizar_ks input  '{ type filter hook input  priority 0; policy accept; }'
nft add chain inet securizar_ks output '{ type filter hook output priority 0; policy accept; }'

# INPUT: proteger SSH (permitir siempre, previene lockout)
nft add rule inet securizar_ks input tcp dport "$_SSH_PORT" accept

# OUTPUT: loopback
nft add rule inet securizar_ks output oifname "lo" accept
# OUTPUT: conexiones establecidas
nft add rule inet securizar_ks output ct state established,related accept
# OUTPUT: bloquear DNS plano externo (forzar resolver local)
nft add rule inet securizar_ks output ip daddr != 127.0.0.1 udp dport 53 counter log prefix '"DNS-LEAK-UDP: "' drop
nft add rule inet securizar_ks output ip daddr != 127.0.0.1 tcp dport 53 counter log prefix '"DNS-LEAK-TCP: "' drop
# OUTPUT: permitir SSH saliente (para el propio servidor)
nft add rule inet securizar_ks output tcp dport "$_SSH_PORT" accept
# OUTPUT: LAN (RFC1918)
_LAN="{10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16}"
nft add rule inet securizar_ks output ip daddr $_LAN meta l4proto icmp accept
nft add rule inet securizar_ks output ip daddr $_LAN tcp dport '{ 22, 80, 443, 8080, 9090 }' accept
nft add rule inet securizar_ks output ip daddr $_LAN udp dport '{ 123 }' accept
# OUTPUT: DHCP
nft add rule inet securizar_ks output udp dport 67-68 accept
# OUTPUT: DNS cifrado DoT
nft add rule inet securizar_ks output ip daddr { 1.1.1.1, 1.0.0.1, 9.9.9.9, 149.112.112.112, 194.242.2.4 } tcp dport 853 accept
# OUTPUT: DNS cifrado DoH (para resolvers que también ofrecen 443)
nft add rule inet securizar_ks output ip daddr { 1.1.1.1, 1.0.0.1, 9.9.9.9, 149.112.112.112, 194.242.2.4 } tcp dport 443 accept
# OUTPUT: endpoints VPN
for _ep in "${_vpn_endpoints[@]}"; do
    [[ -n "$_ep" ]] && nft add rule inet securizar_ks output ip daddr "$_ep" accept 2>/dev/null || true
done
# OUTPUT: interfaces VPN
for _vif in wg tun tap; do
    nft add rule inet securizar_ks output oifname "${_vif}*" accept 2>/dev/null || true
done
# OUTPUT: DROP todo lo demás
nft add rule inet securizar_ks output drop

_dbg "nftables: tabla securizar_ks creada, $(nft list chain inet securizar_ks output 2>/dev/null | grep -c 'accept\|drop') reglas output, SSH puerto $_SSH_PORT protegido"
echo "[+] VPN Kill Switch ACTIVADO via nftables (${#_vpn_endpoints[@]} endpoints, SSH:${_SSH_PORT} protegido)"
KILLSWITCH_ON
    chmod 700 "${ISP_CONF_DIR}/vpn-killswitch.sh"
    log_change "Creado" "${ISP_CONF_DIR}/vpn-killswitch.sh (nftables, SSH-safe)"

    # Script para desactivar kill switch
    cat > "${ISP_CONF_DIR}/vpn-killswitch-off.sh" << 'KILLSWITCH_OFF'
#!/bin/bash
# VPN Kill Switch - Desactivar (nftables, VPS Debian)
set -euo pipefail

_KS_LOG="/var/log/securizar/debug.log"
mkdir -p /var/log/securizar 2>/dev/null || true
_dbg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] killswitch-off: $*" >> "$_KS_LOG" 2>/dev/null || true; }
_dbg "=== DESACTIVACION kill switch ==="
_dbg "PID=$$ UID=$(id -u) invocado_por=$(ps -o comm= $PPID 2>/dev/null || echo desconocido)"

nft delete table inet securizar_ks 2>/dev/null || true
_dbg "nftables: tabla securizar_ks eliminada"
echo "[+] VPN Kill Switch DESACTIVADO (nftables)"
echo "[+] Tráfico normal restaurado"
KILLSWITCH_OFF
    chmod 700 "${ISP_CONF_DIR}/vpn-killswitch-off.sh"
    log_change "Creado" "${ISP_CONF_DIR}/vpn-killswitch-off.sh"

    # Plantilla de endpoints VPN manuales
    if [[ ! -f "${ISP_CONF_DIR}/vpn-endpoints.conf" ]]; then
        cat > "${ISP_CONF_DIR}/vpn-endpoints.conf" << 'VPN_EP_CONF'
# Securizar Deploy S1: Endpoints VPN manuales
# Añade IPs de tus servidores VPN (una por línea)
# El kill switch permitirá tráfico a estas IPs para reconexión
# Se auto-detectan endpoints de /etc/wireguard/*.conf y /etc/openvpn/*.conf
#
# Ejemplos:
# 185.159.157.1
# 198.51.100.42
VPN_EP_CONF
        chmod 640 "${ISP_CONF_DIR}/vpn-endpoints.conf"
        log_change "Creado" "${ISP_CONF_DIR}/vpn-endpoints.conf"
    fi

    log_info "VPN Kill Switch configurado"
else
    log_skip "VPN Kill Switch"
fi

# ── S1 post: Auto-activar kill switch si VPN ya conectada ──
if [[ -f "${ISP_CONF_DIR}/vpn-killswitch.sh" ]]; then
    _ks_active=false
    nft list table inet securizar_ks &>/dev/null 2>&1 && _ks_active=true

    if [[ "$_ks_active" == "true" ]]; then
        log_already "Kill switch activo (reglas nftables presentes)"
    else
        _ks_found=false
        _ks_iface=""
        for _iname in wg0 wg1 tun0 tun1; do
            if ip link show "$_iname" &>/dev/null 2>&1; then
                _ks_found=true; _ks_iface="$_iname"; break
            fi
        done
        if [[ "$_ks_found" != "true" ]] && command -v wg &>/dev/null; then
            _ks_iface=$(wg show interfaces 2>/dev/null | awk '{print $1}')
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

# ── S1 post: Persistencia systemd ──
if [[ -f "${ISP_CONF_DIR}/vpn-killswitch.sh" ]]; then
    if [[ -f /etc/systemd/system/securizar-vpn-killswitch.service ]]; then
        log_already "Kill switch persistencia (securizar-vpn-killswitch.service)"
    elif ask "¿Crear servicio systemd para kill switch en arranque?"; then
        cat > /etc/systemd/system/securizar-vpn-killswitch.service << 'KS_SVC'
[Unit]
Description=Securizar - VPN Kill Switch (persistencia en arranque)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/bin/bash -c 'for i in wg0 wg1 tun0 tun1; do ip link show "$i" 2>/dev/null && exit 0; done; command -v wg &>/dev/null && wg show interfaces 2>/dev/null | grep -q . && exit 0; exit 1'
ExecStart=/etc/securizar/vpn-killswitch.sh
ExecStop=/etc/securizar/vpn-killswitch-off.sh
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
KS_SVC
        systemctl daemon-reload
        systemctl enable securizar-vpn-killswitch.service 2>/dev/null || true
        log_change "Creado" "/etc/systemd/system/securizar-vpn-killswitch.service"
    else
        log_skip "Kill switch persistencia systemd"
    fi
fi

# ── S1 post: Watchdog VPN ──
if [[ -f "${ISP_CONF_DIR}/vpn-killswitch.sh" ]]; then
    if [[ -f /etc/systemd/system/securizar-vpn-watchdog.service ]]; then
        log_already "Watchdog VPN (securizar-vpn-watchdog)"
    elif ask "¿Crear watchdog VPN? (detecta caída/reconexión de la VPN)"; then

        cat > "${ISP_BIN_DIR}/vpn-watchdog.sh" << 'VPN_WATCHDOG'
#!/bin/bash
# Watchdog de interfaces VPN - Deploy VPS Debian
set -euo pipefail

_WD_LOG="/var/log/securizar/debug.log"
mkdir -p /var/log/securizar 2>/dev/null || true
_dbg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] vpn-watchdog: $*" >> "$_WD_LOG" 2>/dev/null || true; }

STATE_FILE="/run/securizar-vpn-watchdog.state"
VPN_IFACES="wg0 wg1 tun0 tun1"

vpn_up=false
vpn_iface=""
for iface in $VPN_IFACES; do
    if ip link show "$iface" &>/dev/null 2>&1; then
        vpn_up=true; vpn_iface="$iface"; break
    fi
done
if [[ "$vpn_up" == "false" ]] && command -v wg &>/dev/null; then
    _wg_iface=$(wg show interfaces 2>/dev/null | awk '{print $1}')
    if [[ -n "$_wg_iface" ]]; then
        vpn_up=true; vpn_iface="$_wg_iface"
    fi
fi

prev_state="unknown"
[[ -f "$STATE_FILE" ]] && prev_state=$(cat "$STATE_FILE" 2>/dev/null || echo "unknown")

new_state="down"
[[ "$vpn_up" == "true" ]] && new_state="up"

[[ "$new_state" == "$prev_state" ]] && exit 0

_dbg "transicion: $prev_state -> $new_state (iface=${vpn_iface:-ninguna})"

if [[ "$new_state" == "up" ]]; then
    if /etc/securizar/vpn-killswitch.sh 2>/dev/null; then
        _dbg "kill switch activado OK"
        logger -t securizar-vpn-watchdog "Kill switch ACTIVADO ($vpn_iface)"
    else
        _dbg "kill switch FALLO al activar"
        logger -t securizar-vpn-watchdog "Kill switch: fallo al activar para $vpn_iface"
    fi
else
    if /etc/securizar/vpn-killswitch-off.sh 2>/dev/null; then
        _dbg "kill switch desactivado OK"
        logger -t securizar-vpn-watchdog "Kill switch DESACTIVADO (VPN caida)"
    else
        _dbg "kill switch FALLO al desactivar"
    fi
fi
echo "$new_state" > "$STATE_FILE"
VPN_WATCHDOG
        chmod 755 "${ISP_BIN_DIR}/vpn-watchdog.sh"
        log_change "Creado" "${ISP_BIN_DIR}/vpn-watchdog.sh"

        cat > /etc/systemd/system/securizar-vpn-watchdog.service << 'WD_SVC'
[Unit]
Description=Securizar - Watchdog VPN
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
        log_change "Creado" "securizar-vpn-watchdog.timer (check cada 10s)"
    else
        log_skip "Watchdog VPN"
    fi
fi

# ── S1 extra: Deshabilitar IPv6 persistente ──
if [[ -f /etc/sysctl.d/99-securizar-ipv6.conf ]]; then
    log_already "IPv6 deshabilitado persistente (99-securizar-ipv6.conf)"
else
    _ipv6_safe_to_disable=true
    if ! ip -4 route show default 2>/dev/null | grep -q 'default'; then
        _ipv6_safe_to_disable=false
        log_warn "No se detectó gateway IPv4. Tu red podría ser IPv6-only."
    fi

    if [[ "$_ipv6_safe_to_disable" == "true" ]]; then
        _ipv6_prompt="¿Deshabilitar IPv6 persistente? (previene fugas fuera de VPN)"
    else
        _ipv6_prompt="¿Deshabilitar IPv6? (RIESGO: no se detectó IPv4, posible lockdown)"
    fi

    if ask "$_ipv6_prompt"; then
        cat > /etc/sysctl.d/99-securizar-ipv6.conf << 'IPV6_CONF'
# Securizar Deploy S1: Deshabilitar IPv6 (prevención de fugas)
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
IPV6_CONF
        sysctl -p /etc/sysctl.d/99-securizar-ipv6.conf 2>/dev/null || true
        log_change "Creado" "/etc/sysctl.d/99-securizar-ipv6.conf"
    else
        log_skip "IPv6 deshabilitado persistente"
    fi
fi
fi  # S1

if [[ "$ISP_SECTION" == "all" || "$ISP_SECTION" == "S2" ]]; then
# ============================================================
# S2 — PREVENCIÓN DE FUGAS DNS (unbound DoT + DNSSEC)
# ============================================================
log_section "S2: PREVENCIÓN DE FUGAS DNS"

echo "Configura DNS cifrado local via DNS-over-TLS (unbound)."
echo "Incluye DNSSEC, cache local y hardening systemd."
echo ""

if check_service_enabled unbound; then
    log_already "DNS cifrado ($(_detect_dns_resolver) activo)"
elif ask "¿Configurar DNS cifrado (unbound DoT)?"; then

    if ! command -v unbound &>/dev/null; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y unbound dns-root-data 2>/dev/null || true
    fi

    if ! command -v unbound &>/dev/null; then
        log_error "unbound no se pudo instalar. Sección S2 omitida."
    else

    # Ancla DNSSEC
    if command -v unbound-anchor &>/dev/null; then
        mkdir -p /var/lib/unbound
        unbound-anchor -a /var/lib/unbound/root.key 2>/dev/null || true
        chown unbound:unbound /var/lib/unbound/root.key 2>/dev/null || true
        log_change "DNSSEC" "Ancla de confianza actualizada"
    fi

    cp /etc/unbound/unbound.conf /etc/unbound/unbound.conf.bak-securizar 2>/dev/null || true

    # Ruta del bundle de certificados TLS (Debian)
    _tls_cert_bundle="/etc/ssl/certs/ca-certificates.crt"
    if [[ ! -f "$_tls_cert_bundle" ]]; then
        for _certpath in /etc/ssl/cert.pem /etc/ssl/ca-bundle.pem; do
            if [[ -f "$_certpath" ]]; then _tls_cert_bundle="$_certpath"; break; fi
        done
    fi

    cat > /etc/unbound/unbound.conf << UNBOUND_CONF
# ============================================================
# Securizar Deploy - DNS-over-TLS con unbound (VPS Debian)
# Consultas DNS cifradas por puerto 853 — ISP no puede ver/interceptar
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
    chroot: ""

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

    # Protección DNS rebinding
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

    serve-expired: yes
    serve-expired-ttl: 86400
    serve-expired-reply-ttl: 30
    serve-expired-client-timeout: 1800

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

    forward-addr: 194.242.2.4@853#base.dns.mullvad.net
UNBOUND_CONF
    log_change "Creado" "/etc/unbound/unbound.conf (DoT, DNSSEC, hardened)"

    mkdir -p /var/log/unbound
    chown unbound:unbound /var/log/unbound 2>/dev/null || true

    # Systemd sandboxing para unbound
    mkdir -p /etc/systemd/system/unbound.service.d
    cat > /etc/systemd/system/unbound.service.d/hardening.conf << 'UNBOUND_HARDENING'
[Service]
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=/var/lib/unbound /var/log/unbound /run/unbound
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
MemoryDenyWriteExecute=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_INET AF_UNIX AF_NETLINK
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID
SystemCallArchitectures=native
SystemCallFilter=~@clock @cpu-emulation @debug @module @mount @obsolete @reboot @swap @raw-io
RemoveIPC=yes
UNBOUND_HARDENING
    log_change "Creado" "unbound hardening (systemd sandbox)"
    systemctl daemon-reload 2>/dev/null || true

    if unbound-checkconf /etc/unbound/unbound.conf &>/dev/null; then
        log_info "Configuración de unbound válida"
    else
        log_warn "Error en configuración de unbound:"
        unbound-checkconf /etc/unbound/unbound.conf 2>&1 | sed 's/^/    /' || true
    fi

    systemctl enable unbound 2>/dev/null || true
    systemctl restart unbound 2>/dev/null || true
    sleep 2
    if systemctl is-active unbound &>/dev/null; then
        log_change "Servicio" "unbound habilitado e iniciado"
    else
        log_warn "unbound no arrancó con nueva configuración"
        if [[ -f /etc/unbound/unbound.conf.bak-securizar ]]; then
            cp /etc/unbound/unbound.conf.bak-securizar /etc/unbound/unbound.conf
            systemctl restart unbound 2>/dev/null || true
            if systemctl is-active unbound &>/dev/null; then
                log_warn "Restaurada configuración anterior de unbound"
            fi
        fi
    fi

    fi  # cierre if unbound instalado

    # ── Configurar resolv.conf (VPS sin NetworkManager) ──
    cp /etc/resolv.conf /etc/resolv.conf.bak-securizar 2>/dev/null || true
    cat > /etc/resolv.conf << 'RESOLV_CONF'
# Securizar Deploy - DNS cifrado local (unbound DoT)
nameserver 127.0.0.1
options edns0 trust-ad
RESOLV_CONF
    sleep 2
    if nslookup example.com 127.0.0.1 &>/dev/null 2>&1; then
        chattr +i /etc/resolv.conf 2>/dev/null || true
        log_change "resolv.conf" "Forzado a resolver local, inmutable"
    else
        log_warn "DNS local no responde aún. resolv.conf NO inmutable."
        log_warn "  Cuando funcione: sudo chattr +i /etc/resolv.conf"
    fi

    # ── Desactivar avahi/mDNS si existe ──
    if systemctl is-active avahi-daemon &>/dev/null; then
        systemctl stop avahi-daemon 2>/dev/null || true
        systemctl disable avahi-daemon 2>/dev/null || true
        log_change "avahi-daemon" "Desactivado (prevención fuga mDNS)"
    fi

    # ── Firewall: permitir DoT (si kill switch no lo cubre) ──
    _ks_dns_skip=false
    nft list table inet securizar_ks &>/dev/null 2>&1 && _ks_dns_skip=true
    if [[ "$_ks_dns_skip" == "true" ]]; then
        log_already "Firewall DNS (reglas presentes en kill switch S1)"
    else
        nft add table inet securizar_dot 2>/dev/null || true
        nft flush table inet securizar_dot 2>/dev/null || true
        nft add chain inet securizar_dot output '{ type filter hook output priority 0; policy accept; }' 2>/dev/null || true
        nft add rule inet securizar_dot output tcp dport 853 accept 2>/dev/null || true
        log_change "Firewall" "Puerto 853 (DoT) saliente permitido"
    fi

    # ── Eliminar tablas nftables obsoletas ──
    for _old_table in securizar-dns securizar-doh; do
        if nft list tables 2>/dev/null | grep -q "$_old_table"; then
            nft delete table inet "$_old_table" 2>/dev/null || true
            log_change "Firewall" "Eliminada tabla nftables $_old_table (obsoleta)"
        fi
    done

    # ── Verificar resolución DNS ──
    sleep 3
    if ss -tlnp 2>/dev/null | grep -q ":53 "; then
        log_info "unbound escuchando en 127.0.0.1:53"
        nslookup example.com 127.0.0.1 &>/dev/null || true
        sleep 2
        _dns_ok=false
        for _dns_try in 1 2 3; do
            if nslookup example.com 127.0.0.1 &>/dev/null; then
                log_info "Resolución DNS via DoT funcionando"
                _dns_ok=true
                break
            fi
            [[ $_dns_try -lt 3 ]] && sleep 2
        done
        if [[ "$_dns_ok" != "true" ]]; then
            log_warn "unbound activo pero resolución lenta (normal en primer handshake)"
        fi
    else
        log_warn "unbound no escucha. Verificar: systemctl status unbound"
    fi

    # ── Script de verificación DNS ──
    cat > "${ISP_BIN_DIR}/detectar-dns-leak.sh" << 'DNS_LEAK'
#!/bin/bash
# Detectar fugas DNS - VPS Debian (unbound DoT)
set -euo pipefail

echo "╔═══════════════════════════════════════════════╗"
echo "║   DETECCIÓN DE FUGAS DNS (VPS Debian)          ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

echo "=== Estado de unbound ==="
if systemctl is-active unbound &>/dev/null; then
    echo "  [OK] unbound activo (DoT, puerto 853)"
    ss -tlnp 2>/dev/null | grep -q "unbound" && echo "  [OK] Escuchando en 127.0.0.1:53" || echo "  [!!] NO escucha en :53"
    grep -q "forward-tls-upstream: yes" /etc/unbound/unbound.conf 2>/dev/null && echo "  [OK] DoT habilitado" || echo "  [!!] DoT NO configurado"
    grep -q "auto-trust-anchor-file" /etc/unbound/unbound.conf 2>/dev/null && echo "  [OK] DNSSEC habilitado" || echo "  [--] DNSSEC no configurado"
else
    echo "  [!!] unbound NO activo!"
fi
echo ""

echo "=== Configuración DNS actual ==="
if [[ -f /etc/resolv.conf ]]; then
    grep "^nameserver" /etc/resolv.conf | while read -r line; do
        ns=$(echo "$line" | awk '{print $2}')
        if [[ "$ns" == "127.0.0.1" || "$ns" == "::1" ]]; then
            echo "  [OK] $line (local/unbound)"
        else
            echo "  [!!] $line (DNS externo sin cifrar - FUGA!)"
        fi
    done
fi
echo ""

echo "=== Test de resolución DNS ==="
for domain in example.com cloudflare.com debian.org; do
    if result=$(nslookup "$domain" 127.0.0.1 2>&1); then
        ip=$(echo "$result" | grep -A1 "Name:" | grep "Address:" | head -1 | awk '{print $2}')
        echo "  [OK] $domain -> ${ip:-resuelto} (via unbound/DoT)"
    else
        echo "  [!!] $domain -> FALLO"
    fi
done
echo ""

echo "=== Verificación de fugas (puerto 53 plaintext) ==="
plain_dns=$(ss -tnp 2>/dev/null | grep ":53 " | grep -v "127\." || true)
if [[ -n "$plain_dns" ]]; then
    echo "$plain_dns" | sed 's/^/  /'
    echo "  [!!] FUGA DNS DETECTADA"
else
    echo "  [OK] Sin conexiones DNS plaintext al exterior"
fi
echo ""
DNS_LEAK
    chmod 755 "${ISP_BIN_DIR}/detectar-dns-leak.sh"
    log_change "Creado" "${ISP_BIN_DIR}/detectar-dns-leak.sh"

    # ── Script restaurar DNS original ──
    cat > "${ISP_BIN_DIR}/restaurar-dns-isp.sh" << 'DNS_RESTORE'
#!/bin/bash
# Restaurar DNS original (deshacer DoT) - VPS Debian
set -euo pipefail
echo "Restaurando DNS original..."
systemctl stop unbound 2>/dev/null || true
systemctl disable unbound 2>/dev/null || true
echo "[+] unbound detenido"
if [[ -f /etc/resolv.conf.bak-securizar ]]; then
    chattr -i /etc/resolv.conf 2>/dev/null || true
    cp /etc/resolv.conf.bak-securizar /etc/resolv.conf
    echo "[+] resolv.conf restaurado"
fi
echo ""
echo "DNS restaurado. Ahora usa el DNS del ISP (sin cifrar)."
DNS_RESTORE
    chmod 755 "${ISP_BIN_DIR}/restaurar-dns-isp.sh"
    log_change "Creado" "${ISP_BIN_DIR}/restaurar-dns-isp.sh"

    log_info "DNS cifrado configurado: unbound DoT"
else
    log_skip "Prevención de fugas DNS"
fi

# ── Hardening de servicios ──
if [[ "$ISP_SECTION" == "all" || "$ISP_SECTION" == "S1" || "$ISP_SECTION" == "S2" ]]; then
    # fail2ban hardening
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
            log_change "Hardening" "fail2ban (systemd sandbox)"
        else
            log_already "fail2ban hardening"
        fi
    fi

    # rsyslog hardening
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
            log_change "Hardening" "rsyslog (systemd sandbox)"
        else
            log_already "rsyslog hardening"
        fi
    fi
fi
fi  # S2

if [[ "$ISP_SECTION" == "all" || "$ISP_SECTION" == "S3" ]]; then
# ============================================================
# S3 — NTP CON NTS (NETWORK TIME SECURITY)
# ============================================================
log_section "S3: NTP CON NTS"

echo "NTP sin cifrar permite al ISP manipular tu reloj."
echo "NTS añade autenticación criptográfica a la sincronización."
echo ""

# Debian usa /etc/chrony/conf.d/ (no /etc/chrony.d/)
_chrony_confdir="/etc/chrony/conf.d"
# Fallback si estructura es diferente
[[ -d /etc/chrony.d ]] && ! [[ -d "$_chrony_confdir" ]] && _chrony_confdir="/etc/chrony.d"

if [[ -f "${_chrony_confdir}/securizar-nts.conf" ]]; then
    log_already "NTP con NTS (chrony NTS ya configurado)"
elif ask "¿Configurar NTP con NTS?"; then

    DEBIAN_FRONTEND=noninteractive apt-get install -y chrony 2>/dev/null || log_warn "chrony no disponible"

    if command -v chronyd &>/dev/null; then
        systemctl stop systemd-timesyncd 2>/dev/null || true
        systemctl disable systemd-timesyncd 2>/dev/null || true
        systemctl mask systemd-timesyncd 2>/dev/null || true
        log_change "Servicio" "systemd-timesyncd desactivado"

        mkdir -p "$_chrony_confdir"
        cat > "${_chrony_confdir}/securizar-nts.conf" << 'NTS_CONF'
# Securizar Deploy S3: NTP con NTS (Network Time Security)
server time.cloudflare.com iburst nts
server nts.netnod.se iburst nts
server ptbtime1.ptb.de iburst nts
server ntppool1.time.nl iburst nts

ntsdumpdir /var/lib/chrony

minsources 2
maxchange 100 1 0
makestep 0.1 3
NTS_CONF
        log_change "Creado" "${_chrony_confdir}/securizar-nts.conf"

        systemctl enable chronyd 2>/dev/null || true
        systemctl restart chronyd 2>/dev/null || true
        log_change "Servicio" "chronyd habilitado y reiniciado"

        _nts_ok=false
        for _nts_try in 1 2 3; do
            sleep 3
            if chronyc -n authdata 2>/dev/null | grep -q "NTS"; then
                _nts_ok=true
                nts_sources=$(chronyc -n authdata 2>/dev/null | grep -c "NTS" || echo "0")
                log_info "NTS activo ($nts_sources fuentes verificadas)"
                break
            fi
        done
        if [[ "$_nts_ok" != "true" ]]; then
            log_warn "NTS configurado pero verificación pendiente"
            log_info "Verificar: chronyc -n authdata | grep NTS"
        fi
    else
        log_warn "chrony no instalado"
    fi
else
    log_skip "NTP con NTS"
fi
fi  # S3

if [[ "$ISP_SECTION" == "all" || "$ISP_SECTION" == "S4" ]]; then
# ============================================================
# S4 — OFUSCACIÓN DE PATRONES DE TRÁFICO
# ============================================================
log_section "S4: OFUSCACIÓN DE PATRONES DE TRÁFICO"

echo "Genera tráfico de cobertura con intervalos y tamaños aleatorios"
echo "para dificultar análisis de patrones por el ISP."
echo "  Intervalos: 30-120s con jitter | Tamaño: 1K-64K bytes"
echo "  Límites: CPUQuota=5%, MemoryMax=64M"
echo ""

if check_service_enabled securizar-traffic-pad.service; then
    log_already "Ofuscación de tráfico (servicio habilitado)"
elif ask "¿Configurar ofuscación de patrones de tráfico?"; then

    cat > "${ISP_BIN_DIR}/securizar-traffic-pad.sh" << 'TRAFFIC_PAD'
#!/bin/bash
# Ofuscación de patrones de tráfico - VPS Debian
set -euo pipefail

TARGETS=(
    "https://www.cloudflare.com/cdn-cgi/trace"
    "https://www.google.com/generate_204"
    "https://detectportal.firefox.com/canonical.html"
    "https://connectivity-check.ubuntu.com"
    "https://cloudflare-dns.com/dns-query?name=example.com&type=A"
    "https://dns.mullvad.net/dns-query?name=example.com&type=A"
)

MIN_INTERVAL=30
MAX_INTERVAL=120
MIN_BYTES=1024
MAX_BYTES=65536

rand_range() {
    local min=$1 max=$2
    echo $(( RANDOM % (max - min + 1) + min ))
}

while true; do
    idx=$(( RANDOM % ${#TARGETS[@]} ))
    target="${TARGETS[$idx]}"
    bytes=$(rand_range $MIN_BYTES $MAX_BYTES)
    curl -s -o /dev/null --max-time 10 --range "0-${bytes}" "$target" 2>/dev/null || true
    interval=$(rand_range $MIN_INTERVAL $MAX_INTERVAL)
    jitter=$(( interval * (RANDOM % 40 - 20) / 100 ))
    sleep_time=$(( interval + jitter ))
    [[ $sleep_time -lt 10 ]] && sleep_time=10
    sleep "$sleep_time"
done
TRAFFIC_PAD
    chmod 755 "${ISP_BIN_DIR}/securizar-traffic-pad.sh"
    log_change "Creado" "${ISP_BIN_DIR}/securizar-traffic-pad.sh"

    cat > /etc/systemd/system/securizar-traffic-pad.service << 'TRAFFIC_SVC'
[Unit]
Description=Securizar - Ofuscación de patrones de tráfico ISP
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/securizar-traffic-pad.sh
Restart=on-failure
RestartSec=60

CPUQuota=5%
MemoryMax=64M
MemoryHigh=32M

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
UMask=0077
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectClock=yes
ProtectHostname=yes
ProtectControlGroups=yes
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

DynamicUser=yes

[Install]
WantedBy=multi-user.target
TRAFFIC_SVC

    systemctl daemon-reload
    systemctl enable securizar-traffic-pad.service 2>/dev/null || true
    systemctl start securizar-traffic-pad.service 2>/dev/null || true
    log_change "Servicio" "securizar-traffic-pad habilitado (hardened)"

    log_info "Ofuscación de patrones de tráfico activa"
else
    log_skip "Ofuscación de patrones de tráfico"
fi
fi  # S4

if [[ "$ISP_SECTION" == "all" || "$ISP_SECTION" == "S5" ]]; then
# ============================================================
# S5 — AUDITORÍA DE METADATOS ISP
# ============================================================
log_section "S5: AUDITORÍA DE METADATOS ISP"

echo "Script de auditoría parametrizable (VPN, DNS, IPv6, NTS, padding)."
echo "Configuración: /etc/securizar/auditoria-isp.conf"
echo "Uso: auditoria-isp.sh [--report] [--quiet] [--help]"
echo ""

if check_executable /usr/local/bin/auditoria-isp.sh; then
    log_already "Auditoría ISP (script ya instalado)"
elif ask "¿Instalar auditoría de metadatos ISP?"; then

    mkdir -p /var/lib/securizar/auditoria-isp
    mkdir -p /var/log/securizar

    if [[ ! -f /etc/securizar/auditoria-isp.conf ]]; then
        cat > /etc/securizar/auditoria-isp.conf << 'ISP_CONF'
# ============================================================
# Auditoría ISP - Securizar Deploy VPS Debian
# ============================================================

VPN_INTERFACES="wg0 wg1 tun0 tun1"
VPN_PROCESSES="openvpn wireguard wg-quick"
DNS_LOCAL_ADDR="127.0.0.1"
DNS_SERVICE="unbound"
DNS_CONF="/etc/unbound/unbound.conf"
DNS_DOT_PORT=853
KS_NFT_TABLE="securizar_ks"
NTS_SERVICE="chronyd"
PAD_SERVICE="securizar-traffic-pad.service"
REPORT_DIR="/var/lib/securizar/auditoria-isp"
REPORT_RETENTION=30
LOG_FILE="/var/log/securizar/auditoria-isp.log"
THRESHOLD_GOOD=80
THRESHOLD_FAIR=50
CHECK_EXTERNAL_IP=no
EXTERNAL_IP_URL="https://api.ipify.org"
CHECK_MDNS=yes
CHECK_HTTP_LEAKS=yes
WEIGHT_VPN=3
WEIGHT_DNS=3
WEIGHT_NETWORK=2
WEIGHT_TRAFFIC=2
ISP_CONF
        chmod 640 /etc/securizar/auditoria-isp.conf
        log_change "Creado" "/etc/securizar/auditoria-isp.conf"
    else
        log_already "Configuración auditoria-isp.conf ya existe"
    fi

    cat > "${ISP_BIN_DIR}/auditoria-isp.sh" << 'ISP_AUDIT'
#!/bin/bash
# ============================================================
# Auditoría ISP - Securizar Deploy VPS Debian
# ============================================================
set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# Valores por defecto
VPN_INTERFACES="wg0 wg1 tun0 tun1"
VPN_PROCESSES="openvpn wireguard wg-quick"
DNS_LOCAL_ADDR="127.0.0.1"
DNS_SERVICE="unbound"
DNS_CONF="/etc/unbound/unbound.conf"
DNS_DOT_PORT=853
KS_NFT_TABLE="securizar_ks"
NTS_SERVICE="chronyd"
PAD_SERVICE="securizar-traffic-pad.service"
REPORT_DIR="/var/lib/securizar/auditoria-isp"
REPORT_RETENTION=30
LOG_FILE="/var/log/securizar/auditoria-isp.log"
THRESHOLD_GOOD=80
THRESHOLD_FAIR=50
CHECK_EXTERNAL_IP=no
EXTERNAL_IP_URL="https://api.ipify.org"
CHECK_MDNS=yes
CHECK_HTTP_LEAKS=yes
WEIGHT_VPN=3
WEIGHT_DNS=3
WEIGHT_NETWORK=2
WEIGHT_TRAFFIC=2

CONF_FILE="/etc/securizar/auditoria-isp.conf"
if [[ -f "$CONF_FILE" ]]; then
    while IFS= read -r _line; do
        _line="${_line#"${_line%%[![:space:]]*}"}"
        [[ -z "$_line" || "$_line" == \#* ]] && continue
        if [[ "$_line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
            declare "${BASH_REMATCH[1]}=${BASH_REMATCH[2]}"
        fi
    done < "$CONF_FILE"
fi

OPT_REPORT=0; OPT_QUIET=0; OPT_SECTION="all"; OPT_HELP=0
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
    echo "Uso: auditoria-isp.sh [--report] [--quiet] [--section vpn|dns|net|traffic] [--help]"
    echo "Conf: $CONF_FILE"
    exit 0
fi

declare -a _check_names=() _check_results=() _check_details=() _check_weights=() _check_categories=()
issues=()

audit_check() {
    local category="$1" weight="$2" name="$3" result="$4" detail="${5:-}"
    _check_names+=("$name"); _check_results+=("$result")
    _check_details+=("$detail"); _check_weights+=("$weight"); _check_categories+=("$category")
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

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
if [[ $OPT_QUIET -eq 0 ]]; then
    echo ""
    echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}  AUDITORÍA ISP (VPS Debian)${NC}"
    echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════════════${NC}"
    echo -e "  ${DIM}${TIMESTAMP}${NC}"
fi

# ── VPN ──
if [[ "$OPT_SECTION" == "all" || "$OPT_SECTION" == "vpn" ]]; then
    section_header "VPN"

    vpn_fail=1; vpn_iface_found=""
    for iface in $VPN_INTERFACES; do
        if ip link show "$iface" &>/dev/null; then vpn_fail=0; vpn_iface_found="$iface"; break; fi
    done
    if [[ $vpn_fail -eq 0 ]]; then
        audit_check "vpn" "$WEIGHT_VPN" "Interfaz VPN activa ($vpn_iface_found)" 0
    else
        audit_check "vpn" "$WEIGHT_VPN" "Interfaz VPN activa" 1 "Interfaces buscadas: $VPN_INTERFACES"
    fi

    vpn_proc_fail=1; vpn_proc_found=""
    for proc in $VPN_PROCESSES; do
        if pgrep -x "$proc" &>/dev/null; then vpn_proc_fail=0; vpn_proc_found="$proc"; break; fi
    done
    if [[ $vpn_proc_fail -eq 0 ]]; then
        audit_check "vpn" "$WEIGHT_VPN" "Proceso VPN activo ($vpn_proc_found)" 0
    else
        audit_check "vpn" "$WEIGHT_VPN" "Proceso VPN activo" 1 "Procesos buscados: $VPN_PROCESSES"
    fi

    ks_fail=1
    if nft list table inet "$KS_NFT_TABLE" &>/dev/null 2>&1; then ks_fail=0; fi
    if [[ $ks_fail -eq 0 ]]; then
        audit_check "vpn" "$WEIGHT_VPN" "Kill switch VPN activo (nftables)" 0
    else
        audit_check "vpn" "$WEIGHT_VPN" "Kill switch VPN activo" 1 "sudo /etc/securizar/vpn-killswitch.sh"
    fi
fi

# ── DNS ──
if [[ "$OPT_SECTION" == "all" || "$OPT_SECTION" == "dns" ]]; then
    section_header "DNS"

    dot_fail=1
    if systemctl is-active "$DNS_SERVICE" &>/dev/null; then
        [[ -f "$DNS_CONF" ]] && grep -q "forward-tls-upstream: yes" "$DNS_CONF" 2>/dev/null && dot_fail=0
    fi
    audit_check "dns" "$WEIGHT_DNS" "DNS cifrado activo" $dot_fail "sudo systemctl start $DNS_SERVICE"

    dns_local_fail=1
    grep -qE "^nameserver\s+${DNS_LOCAL_ADDR}" /etc/resolv.conf 2>/dev/null && dns_local_fail=0
    audit_check "dns" "$WEIGHT_DNS" "DNS local ($DNS_LOCAL_ADDR)" $dns_local_fail "resolv.conf no apunta a localhost"

    dnssec_fail=1
    if [[ -f "$DNS_CONF" ]] && grep -q "auto-trust-anchor-file" "$DNS_CONF" 2>/dev/null; then dnssec_fail=0; fi
    audit_check "dns" "$WEIGHT_DNS" "DNSSEC habilitado" $dnssec_fail

    dns_leak_fail=0
    plain_dns=$(ss -tnp 2>/dev/null | grep ":53 " | grep -v "127\.\|::1" || true)
    [[ -n "$plain_dns" ]] && dns_leak_fail=1
    audit_check "dns" "$WEIGHT_DNS" "Sin fugas DNS plaintext" $dns_leak_fail "Conexiones DNS sin cifrar"
fi

# ── RED ──
if [[ "$OPT_SECTION" == "all" || "$OPT_SECTION" == "net" ]]; then
    section_header "Red"

    ipv6_fail=0
    if [[ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ]]; then
        ipv6_disabled=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo "0")
        if [[ "$ipv6_disabled" != "1" ]] && ip -6 addr show scope global 2>/dev/null | grep -q "inet6"; then
            ipv6_fail=1
        fi
    fi
    audit_check "net" "$WEIGHT_NETWORK" "IPv6 sin exposición pública" $ipv6_fail "IPv6 global detectada"

    nts_fail=1
    if systemctl is-active "$NTS_SERVICE" &>/dev/null; then
        nts_count=$(chronyc -n authdata 2>/dev/null | grep -c "NTS" || echo "0")
        [[ "$nts_count" -gt 0 ]] && nts_fail=0
    fi
    audit_check "net" "$WEIGHT_NETWORK" "NTS activo" $nts_fail "sudo systemctl start $NTS_SERVICE"

    if [[ "$CHECK_MDNS" == "yes" ]]; then
        mdns_fail=0
        systemctl is-active avahi-daemon &>/dev/null 2>&1 && mdns_fail=1
        audit_check "net" "$WEIGHT_NETWORK" "mDNS/LLMNR desactivado" $mdns_fail "avahi-daemon activo"
    fi
fi

# ── TRÁFICO ──
if [[ "$OPT_SECTION" == "all" || "$OPT_SECTION" == "traffic" ]]; then
    section_header "Tráfico"

    pad_fail=1
    systemctl is-active "$PAD_SERVICE" &>/dev/null && pad_fail=0
    audit_check "traffic" "$WEIGHT_TRAFFIC" "Traffic padding activo" $pad_fail "Patrones expuestos al ISP"

    if [[ "$CHECK_HTTP_LEAKS" == "yes" ]]; then
        http_fail=0
        http_count=$(ss -tnp state established 2>/dev/null | grep -c ":80 " || echo "0")
        [[ "$http_count" -gt 0 ]] && http_fail=1
        audit_check "traffic" "$WEIGHT_TRAFFIC" "Sin conexiones HTTP ($http_count)" $http_fail "HTTP visible al ISP"
    fi

    if [[ "$CHECK_EXTERNAL_IP" == "yes" ]]; then
        ext_ip_fail=1
        ext_ip=$(curl -s --max-time 5 "$EXTERNAL_IP_URL" 2>/dev/null || true)
        if [[ -n "$ext_ip" ]] && [[ "$ext_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            gw_iface=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
            local_ip=$(ip -4 addr show "$gw_iface" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1 || true)
            if [[ -n "$local_ip" ]] && [[ "$ext_ip" != "$local_ip" ]]; then ext_ip_fail=0
            elif [[ -z "$local_ip" ]]; then ext_ip_fail=0; fi
        fi
        if [[ $ext_ip_fail -eq 0 ]]; then
            audit_check "traffic" "$WEIGHT_TRAFFIC" "IP externa enmascarada ($ext_ip)" 0
        else
            audit_check "traffic" "$WEIGHT_TRAFFIC" "IP externa enmascarada" 1 "IP $ext_ip = IP local"
        fi
    fi
fi

# ── PUNTUACIÓN ──
total_weighted=0; pass_weighted=0; total_checks=${#_check_names[@]}
for i in $(seq 0 $((total_checks - 1))); do
    w=${_check_weights[$i]}
    total_weighted=$((total_weighted + w))
    [[ "${_check_results[$i]}" -eq 0 ]] && pass_weighted=$((pass_weighted + w))
done
pct=0; [[ $total_weighted -gt 0 ]] && pct=$(( pass_weighted * 100 / total_weighted ))

pass_count=0; fail_count=0
for r in "${_check_results[@]}"; do
    [[ "$r" -eq 0 ]] && pass_count=$((pass_count + 1)) || fail_count=$((fail_count + 1))
done

if [[ $pct -ge $THRESHOLD_GOOD ]]; then label="BUENO"; color="$GREEN"
elif [[ $pct -ge $THRESHOLD_FAIR ]]; then label="MEJORABLE"; color="$YELLOW"
else label="DEFICIENTE"; color="$RED"; fi

if [[ $OPT_QUIET -eq 0 ]]; then
    echo ""
    echo -e "${BOLD}══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Checks: ${GREEN}${pass_count} OK${NC} / ${RED}${fail_count} FAIL${NC} / ${total_checks} total"
    echo -e "  Puntuación: ${color}${BOLD}${pass_weighted}/${total_weighted}${NC} (${color}${pct}%${NC})"
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

    echo -e "  ${CYAN}Desglose:${NC}"
    for cat in vpn dns net traffic; do
        cat_pass=0; cat_total=0; cat_w_pass=0; cat_w_total=0
        for i in $(seq 0 $((total_checks - 1))); do
            [[ "${_check_categories[$i]}" != "$cat" ]] && continue
            w=${_check_weights[$i]}; cat_w_total=$((cat_w_total + w)); cat_total=$((cat_total + 1))
            [[ "${_check_results[$i]}" -eq 0 ]] && { cat_pass=$((cat_pass + 1)); cat_w_pass=$((cat_w_pass + w)); }
        done
        [[ $cat_total -eq 0 ]] && continue
        cat_pct=$(( cat_w_pass * 100 / cat_w_total ))
        if [[ $cat_pct -ge $THRESHOLD_GOOD ]]; then cat_c="$GREEN"
        elif [[ $cat_pct -ge $THRESHOLD_FAIR ]]; then cat_c="$YELLOW"
        else cat_c="$RED"; fi
        printf "    %-12s ${cat_c}%3d%%${NC}  (%d/%d)\n" "$cat" "$cat_pct" "$cat_pass" "$cat_total"
    done
    echo ""
fi

if [[ $OPT_REPORT -eq 1 ]]; then
    mkdir -p "$REPORT_DIR"
    report_file="${REPORT_DIR}/auditoria-isp-$(date +%Y%m%d-%H%M%S).txt"
    {
        echo "AUDITORÍA ISP (VPS Debian)"
        echo "Fecha: $TIMESTAMP"
        echo "Nivel: $label ($pct%)"
        echo "Checks: ${pass_count}/${total_checks} OK"
        echo "Puntuación: ${pass_weighted}/${total_weighted}"
        echo ""
        for i in $(seq 0 $((total_checks - 1))); do
            if [[ "${_check_results[$i]}" -eq 0 ]]; then echo "  [OK]  ${_check_names[$i]}"
            else echo "  [!!]  ${_check_names[$i]}"; [[ -n "${_check_details[$i]}" ]] && echo "        ${_check_details[$i]}"; fi
        done
    } > "$report_file"
    chmod 640 "$report_file"
    [[ $OPT_QUIET -eq 0 ]] && echo -e "  ${GREEN}Reporte:${NC} $report_file"
    ls -t "$REPORT_DIR"/auditoria-isp-*.txt 2>/dev/null | tail -n "+$((REPORT_RETENTION + 1))" | xargs rm -f 2>/dev/null || true
fi

mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
echo "${TIMESTAMP} nivel=${label} pct=${pct} ok=${pass_count}/${total_checks} weighted=${pass_weighted}/${total_weighted}" >> "$LOG_FILE" 2>/dev/null || true

if [[ $pct -ge $THRESHOLD_GOOD ]]; then exit 0
elif [[ $pct -ge $THRESHOLD_FAIR ]]; then exit 1
else exit 2; fi
ISP_AUDIT
    chmod 755 "${ISP_BIN_DIR}/auditoria-isp.sh"
    log_change "Creado" "${ISP_BIN_DIR}/auditoria-isp.sh"

    mkdir -p /etc/cron.weekly
    cat > /etc/cron.weekly/auditoria-isp << 'CRON_ISP'
#!/bin/bash
# Auditoría semanal ISP - Securizar Deploy
/usr/local/bin/auditoria-isp.sh --report --quiet 2>/dev/null
rc=$?
[[ $rc -eq 2 ]] && logger -t securizar-isp "ALERTA: Auditoría ISP nivel DEFICIENTE"
CRON_ISP
    chmod 755 /etc/cron.weekly/auditoria-isp
    log_change "Creado" "/etc/cron.weekly/auditoria-isp (semanal)"

    log_info "Auditoría ISP instalada"
else
    log_skip "Auditoría de metadatos ISP"
fi
fi  # S5

if [[ "$ISP_SECTION" == "all" ]]; then
# ============================================================
# RESUMEN FINAL
# ============================================================
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   DEPLOY VPS DEBIAN — COMPLETADO                            ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║                                                              ║"
echo "║   Herramientas instaladas:                                   ║"
echo "║     • /etc/securizar/vpn-killswitch.sh       (kill switch)   ║"
echo "║     • /etc/securizar/vpn-killswitch-off.sh   (kill switch)   ║"
echo "║     • /usr/local/bin/detectar-dns-leak.sh    (DNS leaks)     ║"
echo "║     • /usr/local/bin/restaurar-dns-isp.sh    (restaurar DNS) ║"
echo "║     • /usr/local/bin/securizar-traffic-pad.sh  (padding)     ║"
echo "║     • /usr/local/bin/auditoria-isp.sh         (auditoría)    ║"
echo "║                                                              ║"
echo "║   Verificar: sudo bash $0 --verify              ║"
echo "║   Auditoría: auditoria-isp.sh [--report] [--quiet]          ║"
echo "║   DNS leak:  detectar-dns-leak.sh                            ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

log_info "Deploy VPS Debian — Protección contra ISP completado"
show_changes_summary
fi
