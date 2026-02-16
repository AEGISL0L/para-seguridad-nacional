#!/bin/bash
# Deploy: override DNS global + dispatcher mejorado (dual-mode DoT/DoH)
# Uso: sudo bash deploy-dns-fix.sh
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Ejecutar con sudo"; exit 1; }

# Detectar resolver activo
RESOLVER="none"
DNS_MODE="none"
if systemctl is-active unbound &>/dev/null; then
    RESOLVER="unbound"; DNS_MODE="dot"
elif systemctl is-active dnscrypt-proxy &>/dev/null; then
    RESOLVER="dnscrypt-proxy"; DNS_MODE="doh"
fi

echo "[*] Resolver detectado: ${RESOLVER} (modo: ${DNS_MODE})"
echo ""

# 1. Override global DNS de NM
cat > /etc/NetworkManager/conf.d/90-securizar-dns.conf << 'NM_DNS_GLOBAL'
# Securizar M38 S2: Forzar DNS a resolver local (DoT/DoH + DNSSEC)
# Sobreescribe DNS de VPN comerciales (ProtonVPN, Mullvad, etc.)

[global-dns]
searches=
options=edns0 trust-ad

[global-dns-domain-*]
servers=127.0.0.1
NM_DNS_GLOBAL
echo "[+] Creado /etc/NetworkManager/conf.d/90-securizar-dns.conf"

# 2. Dispatcher con reintentos (dual-mode)
cat > /etc/NetworkManager/dispatcher.d/98-securizar-dns-vpn << 'DNS_HOOK'
#!/bin/bash
IFACE="$1"
ACTION="$2"

is_vpn_event() {
    case "$ACTION" in vpn-up|vpn-down) return 0 ;; esac
    case "$IFACE" in proton*|wg*|mullvad*|nordlynx*|tun*) return 0 ;; esac
    return 1
}

is_vpn_event || exit 0

force_local_dns() {
    if ss -tlnp 2>/dev/null | grep -qE "127.0.0.1:53.*(unbound|dnscrypt-proxy)"; then
        printf '%s\n' "# Securizar - DNS cifrado local (DoT/DoH)" \
                      "nameserver 127.0.0.1" \
                      "options edns0 trust-ad" > /etc/resolv.conf
        return 0
    fi
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
echo "[+] Creado /etc/NetworkManager/dispatcher.d/98-securizar-dns-vpn"

# 3. Recargar NM
nmcli general reload dns 2>/dev/null || systemctl reload NetworkManager 2>/dev/null || true
echo "[+] NetworkManager recargado"

# 4. Verificar
echo ""
echo "=== resolv.conf ==="
cat /etc/resolv.conf
echo ""
echo "=== Resolver DNS en :53 (modo: ${DNS_MODE}) ==="
ss -tlnp 2>/dev/null | grep ":53 " || echo "(no escuchando en :53)"
echo ""
echo "Reconecta ProtonVPN y verifica con: cat /etc/resolv.conf"
