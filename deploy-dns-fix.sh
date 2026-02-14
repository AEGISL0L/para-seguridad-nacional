#!/bin/bash
# Deploy: override DNS global + dispatcher mejorado
# Uso: sudo bash deploy-dns-fix.sh
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Ejecutar con sudo"; exit 1; }

# 1. Override global DNS de NM
cat > /etc/NetworkManager/conf.d/90-securizar-dns.conf << 'NM_DNS_GLOBAL'
# Securizar M38 S2: Forzar DNS a unbound (DoT+DNSSEC)
# Sobreescribe DNS de VPN comerciales (ProtonVPN, Mullvad, etc.)

[global-dns]
searches=
options=edns0 trust-ad

[global-dns-domain-*]
servers=127.0.0.1
NM_DNS_GLOBAL
echo "[+] Creado /etc/NetworkManager/conf.d/90-securizar-dns.conf"

# 2. Dispatcher con reintentos
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
        force_unbound_dns
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
echo "[+] Creado /etc/NetworkManager/dispatcher.d/98-securizar-dns-vpn"

# 3. Recargar NM
nmcli general reload dns 2>/dev/null || systemctl reload NetworkManager 2>/dev/null || true
echo "[+] NetworkManager recargado"

# 4. Verificar
echo ""
echo "=== resolv.conf ==="
cat /etc/resolv.conf
echo ""
echo "=== unbound ==="
ss -tlnp 2>/dev/null | grep ":53 " || echo "(no escuchando en :53)"
echo ""
echo "Reconecta ProtonVPN y verifica con: cat /etc/resolv.conf"
