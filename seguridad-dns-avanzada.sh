#!/bin/bash
# ============================================================
# seguridad-dns-avanzada.sh - Modulo 65: Seguridad DNS Avanzada
# ============================================================
# Secciones:
#   S1  - Validacion DNSSEC
#   S2  - DNS-over-TLS estricto
#   S3  - DNS-over-HTTPS (DoH)
#   S4  - Hardening de Unbound resolver
#   S5  - DNS Sinkhole y RPZ (Response Policy Zones)
#   S6  - Deteccion de DNS tunneling
#   S7  - Proteccion contra cache poisoning
#   S8  - Split-horizon DNS
#   S9  - Monitorizacion DNS
#   S10 - Auditoria DNS avanzada
# ============================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"
require_root
securizar_setup_traps
init_backup "dns-security"

# ── Pre-check: detectar secciones ya aplicadas ──────────────
_precheck 10
_pc 'check_file_exists /etc/securizar/dns-security-policy.conf'
_pc 'check_file_exists /usr/local/bin/verificar-dot.sh'
_pc 'check_file_exists /etc/securizar/dns/doh-setup.conf'
_pc 'check_file_contains /etc/unbound/unbound.conf.d/securizar.conf "harden-glue" 2>/dev/null || check_file_contains /etc/unbound/conf.d/securizar.conf "harden-glue" 2>/dev/null'
_pc 'check_file_exists /usr/local/bin/actualizar-dns-blocklist.sh'
_pc 'check_file_exists /usr/local/bin/detectar-dns-tunneling.sh'
_pc 'check_file_exists /usr/local/bin/test-cache-poisoning.sh'
_pc 'check_file_exists /etc/securizar/split-dns-zones.conf'
_pc 'check_file_exists /usr/local/bin/monitorear-dns.sh'
_pc 'check_file_exists /usr/local/bin/auditar-dns-avanzado.sh'
_precheck_result

log_section "MODULO 65: SEGURIDAD DNS AVANZADA"
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

# ── Directorios de trabajo ───────────────────────────────────
mkdir -p /etc/securizar/dns
mkdir -p /usr/local/bin
mkdir -p /var/log/securizar

# ── Deteccion de componentes DNS ─────────────────────────────
HAS_RESOLVED=false
HAS_UNBOUND=false
HAS_STUBBY=false
HAS_SURICATA=false

if systemctl is-active systemd-resolved &>/dev/null 2>&1; then
    HAS_RESOLVED=true
    log_info "systemd-resolved detectado y activo"
fi

if command -v unbound &>/dev/null; then
    HAS_UNBOUND=true
    log_info "Unbound detectado: $(unbound -V 2>&1 | head -1 || echo 'version desconocida')"
fi

if command -v stubby &>/dev/null; then
    HAS_STUBBY=true
    log_info "Stubby detectado"
fi

if command -v suricata &>/dev/null; then
    HAS_SURICATA=true
    log_info "Suricata detectado: $(suricata -V 2>&1 | head -1 || echo 'version desconocida')"
fi

log_info "Firewall backend: $FW_BACKEND"

# ============================================================
# S1: VALIDACION DNSSEC
# ============================================================
log_section "S1: VALIDACION DNSSEC"

echo "Configura validacion DNSSEC para proteger contra"
echo "respuestas DNS falsificadas:"
echo "  - DNSSEC=yes en systemd-resolved"
echo "  - Trust anchors del root"
echo "  - Script de verificacion /usr/local/bin/verificar-dnssec.sh"
echo "  - Politica en /etc/securizar/dns-security-policy.conf"
echo ""

if check_file_exists /etc/securizar/dns-security-policy.conf; then
    log_already "Validacion DNSSEC (dns-security-policy.conf existe)"
elif ask "Aplicar validacion DNSSEC?"; then

    # --- systemd-resolved DNSSEC ---
    RESOLVED_CONF="/etc/systemd/resolved.conf"
    if [[ -f "$RESOLVED_CONF" ]]; then
        cp "$RESOLVED_CONF" "$BACKUP_DIR/resolved.conf.bak"
        log_change "Backup" "$RESOLVED_CONF"

        # Habilitar DNSSEC
        if grep -q "^DNSSEC=" "$RESOLVED_CONF" 2>/dev/null; then
            sed -i 's/^DNSSEC=.*/DNSSEC=yes/' "$RESOLVED_CONF"
        elif grep -q "^#DNSSEC=" "$RESOLVED_CONF" 2>/dev/null; then
            sed -i 's/^#DNSSEC=.*/DNSSEC=yes/' "$RESOLVED_CONF"
        else
            echo "DNSSEC=yes" >> "$RESOLVED_CONF"
        fi
        log_change "Configurado" "DNSSEC=yes en $RESOLVED_CONF"

        # Habilitar cache
        if grep -q "^Cache=" "$RESOLVED_CONF" 2>/dev/null; then
            sed -i 's/^Cache=.*/Cache=yes/' "$RESOLVED_CONF"
        elif grep -q "^#Cache=" "$RESOLVED_CONF" 2>/dev/null; then
            sed -i 's/^#Cache=.*/Cache=yes/' "$RESOLVED_CONF"
        else
            echo "Cache=yes" >> "$RESOLVED_CONF"
        fi
        log_change "Configurado" "Cache=yes en $RESOLVED_CONF"
    else
        mkdir -p /etc/systemd
        cat > "$RESOLVED_CONF" << 'EOF'
[Resolve]
DNSSEC=yes
Cache=yes
DNSStubListener=yes
EOF
        log_change "Creado" "$RESOLVED_CONF con DNSSEC habilitado"
    fi

    # --- Trust anchors ---
    TRUST_ANCHOR_DIR="/etc/dnssec-trust-anchors.d"
    mkdir -p "$TRUST_ANCHOR_DIR"
    if [[ ! -f "$TRUST_ANCHOR_DIR/root.key" ]]; then
        # Intentar copiar del sistema
        if [[ -f /usr/share/dns/root.key ]]; then
            cp /usr/share/dns/root.key "$TRUST_ANCHOR_DIR/root.key"
            log_change "Copiado" "root trust anchor a $TRUST_ANCHOR_DIR/root.key"
        elif [[ -f /etc/unbound/root.key ]]; then
            cp /etc/unbound/root.key "$TRUST_ANCHOR_DIR/root.key"
            log_change "Copiado" "root trust anchor desde unbound"
        else
            log_warn "Trust anchor root.key no encontrado en el sistema"
            log_info "Se descargara al ejecutar verificar-dnssec.sh"
        fi
    else
        log_info "Trust anchor root.key ya existe"
    fi

    # --- Script de verificacion DNSSEC ---
    cat > /usr/local/bin/verificar-dnssec.sh << 'EOF'
#!/bin/bash
# ============================================================
# verificar-dnssec.sh - Verifica estado de DNSSEC
# Generado por securizar - Modulo 65
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

LOGFILE="/var/log/securizar/dnssec-check.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
SCORE=0
TOTAL=0

check_result() {
    local desc="$1" result="$2"
    ((TOTAL++)) || true
    if [[ "$result" == "PASS" ]]; then
        echo -e "${GREEN}[PASS]${NC} $desc"
        echo "$TIMESTAMP [PASS] $desc" >> "$LOGFILE"
        ((SCORE++)) || true
    elif [[ "$result" == "WARN" ]]; then
        echo -e "${YELLOW}[WARN]${NC} $desc"
        echo "$TIMESTAMP [WARN] $desc" >> "$LOGFILE"
    else
        echo -e "${RED}[FAIL]${NC} $desc"
        echo "$TIMESTAMP [FAIL] $desc" >> "$LOGFILE"
    fi
}

echo -e "${CYAN}=== Verificacion DNSSEC ===${NC}"
echo "$TIMESTAMP === Inicio verificacion DNSSEC ===" >> "$LOGFILE"

# 1. Verificar resolucion DNSSEC con dig
if command -v dig &>/dev/null; then
    # Test dominio firmado con DNSSEC
    DNSSEC_OUT=$(dig +dnssec +short dnssec.works A 2>/dev/null || true)
    if [[ -n "$DNSSEC_OUT" ]]; then
        check_result "Resolucion DNSSEC (dnssec.works)" "PASS"
    else
        check_result "Resolucion DNSSEC (dnssec.works)" "FAIL"
    fi

    # Test dominio con DNSSEC roto (debe fallar)
    FAIL_OUT=$(dig +dnssec +short fail01.dnssec.works A 2>/dev/null || true)
    if [[ -z "$FAIL_OUT" ]]; then
        check_result "Rechazo de DNSSEC invalido (fail01.dnssec.works)" "PASS"
    else
        check_result "Rechazo de DNSSEC invalido (fail01.dnssec.works)" "FAIL"
    fi

    # Verificar flag AD (Authenticated Data)
    AD_FLAG=$(dig +dnssec example.com A 2>/dev/null | grep -c "flags.*ad" || true)
    if [[ "$AD_FLAG" -gt 0 ]]; then
        check_result "Flag AD presente en respuestas DNSSEC" "PASS"
    else
        check_result "Flag AD presente en respuestas DNSSEC" "WARN"
    fi
else
    echo -e "${YELLOW}[WARN]${NC} dig no disponible, instalando dnsutils..."
    check_result "dig disponible para verificacion" "FAIL"
fi

# 2. Verificar systemd-resolved DNSSEC
if systemctl is-active systemd-resolved &>/dev/null 2>&1; then
    DNSSEC_STATUS=$(resolvectl status 2>/dev/null | grep -i "DNSSEC" | head -1 || true)
    if echo "$DNSSEC_STATUS" | grep -qi "yes\|allow-downgrade"; then
        check_result "systemd-resolved DNSSEC habilitado: $DNSSEC_STATUS" "PASS"
    else
        check_result "systemd-resolved DNSSEC: $DNSSEC_STATUS" "FAIL"
    fi
fi

# 3. Verificar trust anchors
if [[ -f /etc/dnssec-trust-anchors.d/root.key ]]; then
    check_result "Trust anchor root.key presente" "PASS"
elif [[ -f /usr/share/dns/root.key ]]; then
    check_result "Trust anchor root.key en /usr/share/dns" "PASS"
else
    check_result "Trust anchor root.key presente" "FAIL"
fi

# 4. Verificar unbound DNSSEC si esta instalado
if command -v unbound-anchor &>/dev/null; then
    if unbound-anchor -v 2>/dev/null; then
        check_result "Unbound trust anchor actualizado" "PASS"
    else
        check_result "Unbound trust anchor actualizado" "WARN"
    fi
fi

echo ""
echo -e "${CYAN}Puntuacion DNSSEC: ${SCORE}/${TOTAL}${NC}"
echo "$TIMESTAMP Puntuacion DNSSEC: ${SCORE}/${TOTAL}" >> "$LOGFILE"

if [[ $TOTAL -gt 0 ]]; then
    PCT=$(( SCORE * 100 / TOTAL ))
    if [[ $PCT -ge 80 ]]; then
        echo -e "${GREEN}Estado: BUENO ($PCT%)${NC}"
    elif [[ $PCT -ge 50 ]]; then
        echo -e "${YELLOW}Estado: MEJORABLE ($PCT%)${NC}"
    else
        echo -e "${RED}Estado: CRITICO ($PCT%)${NC}"
    fi
fi
EOF
    chmod 755 /usr/local/bin/verificar-dnssec.sh
    log_change "Creado" "/usr/local/bin/verificar-dnssec.sh"

    # --- Politica de seguridad DNS ---
    cat > /etc/securizar/dns-security-policy.conf << 'EOF'
# ============================================================
# dns-security-policy.conf - Politica de seguridad DNS
# Generado por securizar - Modulo 65
# ============================================================

# --- DNSSEC ---
DNSSEC_ENABLED=yes
DNSSEC_TRUST_ANCHOR_AUTO_UPDATE=yes
DNSSEC_VALIDATION_MODE=strict

# --- DNS-over-TLS ---
DOT_ENABLED=yes
DOT_MODE=strict
DOT_PRIMARY_SERVER="1.1.1.1#cloudflare-dns.com"
DOT_SECONDARY_SERVER="8.8.8.8#dns.google"
DOT_TERTIARY_SERVER="9.9.9.9#dns.quad9.net"

# --- DNS-over-HTTPS ---
DOH_ENABLED=no
DOH_PROXY_PORT=3053
DOH_UPSTREAM="https://cloudflare-dns.com/dns-query"

# --- Unbound ---
UNBOUND_ENABLED=yes
UNBOUND_LISTEN_ADDR="127.0.0.1"
UNBOUND_LISTEN_PORT=53
UNBOUND_HIDE_IDENTITY=yes
UNBOUND_HIDE_VERSION=yes
UNBOUND_QNAME_MINIMIZATION=yes
UNBOUND_AGGRESSIVE_NSEC=yes
UNBOUND_RATE_LIMIT=1000

# --- Sinkhole / RPZ ---
SINKHOLE_ENABLED=yes
SINKHOLE_UPDATE_INTERVAL=daily
SINKHOLE_BLOCKLIST_SOURCES="abusech,stevenblack,phishtank"
SINKHOLE_WHITELIST="/etc/securizar/dns/whitelist.conf"

# --- DNS Tunneling Detection ---
TUNNEL_DETECTION_ENABLED=yes
TUNNEL_ENTROPY_THRESHOLD=3.5
TUNNEL_MAX_LABEL_LENGTH=50
TUNNEL_ALERT_EMAIL=""

# --- Cache Poisoning Protection ---
CACHE_POISON_PROTECTION=yes
SOURCE_PORT_RANDOMIZATION=yes
DNS_COOKIES_ENABLED=yes
MAX_CACHE_TTL=86400

# --- Split-Horizon ---
SPLIT_HORIZON_ENABLED=no
SPLIT_DNS_CONFIG="/etc/securizar/split-dns-zones.conf"

# --- Monitoring ---
DNS_MONITORING_ENABLED=yes
DNS_MONITOR_INTERVAL=300
DNS_ALERT_THRESHOLD_MS=2000
DNS_HIJACK_DETECTION=yes
EOF
    chmod 640 /etc/securizar/dns-security-policy.conf
    log_change "Creado" "/etc/securizar/dns-security-policy.conf"

    # Reiniciar resolved si activo
    if [[ "$HAS_RESOLVED" == true ]]; then
        systemctl restart systemd-resolved 2>/dev/null || true
        log_change "Reiniciado" "systemd-resolved con DNSSEC habilitado"
    fi

else
    log_skip "Validacion DNSSEC"
fi

# ============================================================
# S2: DNS-OVER-TLS ESTRICTO
# ============================================================
log_section "S2: DNS-OVER-TLS ESTRICTO"

echo "Configura DNS-over-TLS para cifrar consultas DNS:"
echo "  - DNSOverTLS=yes en systemd-resolved"
echo "  - Servidores: Cloudflare (1.1.1.1), Google (8.8.8.8), Quad9 (9.9.9.9)"
echo "  - Bloqueo de puerto 53 saliente (DNS sin cifrar)"
echo "  - Script de verificacion DoT"
echo ""

if check_file_exists /usr/local/bin/verificar-dot.sh; then
    log_already "DNS-over-TLS estricto (verificar-dot.sh existe)"
elif ask "Aplicar DNS-over-TLS estricto?"; then

    RESOLVED_CONF="/etc/systemd/resolved.conf"

    if [[ -f "$RESOLVED_CONF" ]]; then
        # Backup si no se hizo en S1
        if [[ ! -f "$BACKUP_DIR/resolved.conf.bak" ]]; then
            cp "$RESOLVED_CONF" "$BACKUP_DIR/resolved.conf.bak"
            log_change "Backup" "$RESOLVED_CONF"
        fi

        # Habilitar DNS-over-TLS
        if grep -q "^DNSOverTLS=" "$RESOLVED_CONF" 2>/dev/null; then
            sed -i 's/^DNSOverTLS=.*/DNSOverTLS=yes/' "$RESOLVED_CONF"
        elif grep -q "^#DNSOverTLS=" "$RESOLVED_CONF" 2>/dev/null; then
            sed -i 's/^#DNSOverTLS=.*/DNSOverTLS=yes/' "$RESOLVED_CONF"
        else
            echo "DNSOverTLS=yes" >> "$RESOLVED_CONF"
        fi
        log_change "Configurado" "DNSOverTLS=yes en $RESOLVED_CONF"

        # Configurar servidores DNS con TLS
        DOT_SERVERS="1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com 8.8.8.8#dns.google 8.8.4.4#dns.google 9.9.9.9#dns.quad9.net"
        if grep -q "^DNS=" "$RESOLVED_CONF" 2>/dev/null; then
            sed -i "s/^DNS=.*/DNS=$DOT_SERVERS/" "$RESOLVED_CONF"
        elif grep -q "^#DNS=" "$RESOLVED_CONF" 2>/dev/null; then
            sed -i "s/^#DNS=.*/DNS=$DOT_SERVERS/" "$RESOLVED_CONF"
        else
            echo "DNS=$DOT_SERVERS" >> "$RESOLVED_CONF"
        fi
        log_change "Configurado" "Servidores DoT: Cloudflare, Google, Quad9"

        # Configurar FallbackDNS tambien con TLS
        FALLBACK_SERVERS="1.0.0.1#cloudflare-dns.com 8.8.4.4#dns.google 149.112.112.112#dns.quad9.net"
        if grep -q "^FallbackDNS=" "$RESOLVED_CONF" 2>/dev/null; then
            sed -i "s/^FallbackDNS=.*/FallbackDNS=$FALLBACK_SERVERS/" "$RESOLVED_CONF"
        elif grep -q "^#FallbackDNS=" "$RESOLVED_CONF" 2>/dev/null; then
            sed -i "s/^#FallbackDNS=.*/FallbackDNS=$FALLBACK_SERVERS/" "$RESOLVED_CONF"
        else
            echo "FallbackDNS=$FALLBACK_SERVERS" >> "$RESOLVED_CONF"
        fi
        log_change "Configurado" "FallbackDNS con DoT"
    else
        mkdir -p /etc/systemd
        cat > "$RESOLVED_CONF" << 'EOF'
[Resolve]
DNS=1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com 8.8.8.8#dns.google 8.8.4.4#dns.google 9.9.9.9#dns.quad9.net
FallbackDNS=1.0.0.1#cloudflare-dns.com 8.8.4.4#dns.google 149.112.112.112#dns.quad9.net
DNSSEC=yes
DNSOverTLS=yes
Cache=yes
DNSStubListener=yes
EOF
        log_change "Creado" "$RESOLVED_CONF con DoT completo"
    fi

    # --- Bloquear puerto 53 saliente (DNS sin cifrar) ---
    if ask "Bloquear puerto 53 saliente (DNS sin cifrar) en firewall?"; then
        case "$FW_BACKEND" in
            firewalld)
                # Regla directa para bloquear DNS saliente no cifrado
                firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 0 \
                    -p tcp --dport 53 -j DROP 2>/dev/null || true
                firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 0 \
                    -p udp --dport 53 -j DROP 2>/dev/null || true
                # Permitir al resolver local
                firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 0 \
                    -p udp --dport 53 -d 127.0.0.1 -j ACCEPT 2>/dev/null || true
                firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 0 \
                    -p tcp --dport 53 -d 127.0.0.1 -j ACCEPT 2>/dev/null || true
                fw_reload
                ;;
            ufw)
                # Permitir DNS local primero, luego bloquear saliente
                ufw allow out to 127.0.0.1 port 53 2>/dev/null || true
                ufw deny out 53 2>/dev/null || true
                ;;
            nftables)
                nft add table inet securizar-dns 2>/dev/null || true
                nft add chain inet securizar-dns output '{ type filter hook output priority 0 ; policy accept ; }' 2>/dev/null || true
                nft add rule inet securizar-dns output ip daddr 127.0.0.1 udp dport 53 accept 2>/dev/null || true
                nft add rule inet securizar-dns output ip daddr 127.0.0.1 tcp dport 53 accept 2>/dev/null || true
                nft add rule inet securizar-dns output udp dport 53 drop 2>/dev/null || true
                nft add rule inet securizar-dns output tcp dport 53 drop 2>/dev/null || true
                ;;
            iptables)
                iptables -A OUTPUT -d 127.0.0.1 -p udp --dport 53 -j ACCEPT 2>/dev/null || true
                iptables -A OUTPUT -d 127.0.0.1 -p tcp --dport 53 -j ACCEPT 2>/dev/null || true
                iptables -A OUTPUT -p udp --dport 53 -j DROP 2>/dev/null || true
                iptables -A OUTPUT -p tcp --dport 53 -j DROP 2>/dev/null || true
                ;;
        esac
        log_change "Firewall" "Bloqueado puerto 53 saliente (DNS sin cifrar)"
    else
        log_skip "Bloqueo de puerto 53 saliente"
    fi

    # --- Script de verificacion DoT ---
    cat > /usr/local/bin/verificar-dot.sh << 'EOF'
#!/bin/bash
# ============================================================
# verificar-dot.sh - Verifica DNS-over-TLS
# Generado por securizar - Modulo 65
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}=== Verificacion DNS-over-TLS ===${NC}"

# 1. Verificar configuracion resolved
if [[ -f /etc/systemd/resolved.conf ]]; then
    DOT_CFG=$(grep "^DNSOverTLS=" /etc/systemd/resolved.conf 2>/dev/null || echo "no configurado")
    echo -e "Configuracion: $DOT_CFG"
    if echo "$DOT_CFG" | grep -qi "yes"; then
        echo -e "${GREEN}[PASS]${NC} DNSOverTLS habilitado"
    else
        echo -e "${RED}[FAIL]${NC} DNSOverTLS no habilitado"
    fi
fi

# 2. Verificar con resolvectl
if command -v resolvectl &>/dev/null; then
    echo ""
    echo "Estado de resolvectl:"
    resolvectl status 2>/dev/null | grep -iE "DNS|TLS|DNSSEC" || true
fi

# 3. Test de conectividad TLS al puerto 853
echo ""
echo "Test de conectividad DoT (puerto 853):"
for server in 1.1.1.1 8.8.8.8 9.9.9.9; do
    if timeout 5 bash -c "echo | openssl s_client -connect ${server}:853 2>/dev/null" | grep -q "CONNECTED"; then
        echo -e "${GREEN}[PASS]${NC} $server:853 - Conexion TLS exitosa"
    else
        echo -e "${RED}[FAIL]${NC} $server:853 - Sin conexion TLS"
    fi
done

# 4. Verificar que puerto 53 saliente esta bloqueado
echo ""
echo "Test de bloqueo puerto 53 saliente:"
if timeout 3 bash -c "echo | nc -u -w2 1.1.1.1 53" &>/dev/null; then
    echo -e "${YELLOW}[WARN]${NC} Puerto 53/UDP saliente NO bloqueado"
else
    echo -e "${GREEN}[PASS]${NC} Puerto 53/UDP saliente bloqueado o inaccesible"
fi

# 5. Captura de trafico DNS (requiere tcpdump)
if command -v tcpdump &>/dev/null; then
    echo ""
    echo "Capturando trafico DNS por 5 segundos..."
    PCAP_TMP=$(mktemp /tmp/dns-check-XXXXXX.pcap)
    timeout 5 tcpdump -i any -c 50 port 53 -w "$PCAP_TMP" 2>/dev/null &
    TCPDUMP_PID=$!
    # Generar trafico DNS
    dig +short example.com A &>/dev/null || true
    dig +short google.com A &>/dev/null || true
    wait "$TCPDUMP_PID" 2>/dev/null || true
    PKT_COUNT=$(tcpdump -r "$PCAP_TMP" 2>/dev/null | wc -l || echo "0")
    rm -f "$PCAP_TMP"
    if [[ "$PKT_COUNT" -eq 0 ]]; then
        echo -e "${GREEN}[PASS]${NC} Sin trafico DNS en texto plano detectado"
    else
        echo -e "${YELLOW}[WARN]${NC} Se detectaron $PKT_COUNT paquetes DNS en texto plano"
    fi
fi
EOF
    chmod 755 /usr/local/bin/verificar-dot.sh
    log_change "Creado" "/usr/local/bin/verificar-dot.sh"

    # Reiniciar resolved
    if [[ "$HAS_RESOLVED" == true ]]; then
        systemctl restart systemd-resolved 2>/dev/null || true
        log_change "Reiniciado" "systemd-resolved con DoT habilitado"
    fi

else
    log_skip "DNS-over-TLS estricto"
fi

# ============================================================
# S3: DNS-OVER-HTTPS (DoH)
# ============================================================
log_section "S3: DNS-OVER-HTTPS (DoH)"

echo "Configura DNS-over-HTTPS para cifrar consultas via HTTPS:"
echo "  - Proxy DoH local"
echo "  - Stubby como resolver DoT/DoH"
echo "  - Configuracion para navegadores"
echo ""

if check_file_exists /etc/securizar/dns/doh-setup.conf; then
    log_already "DNS-over-HTTPS (doh-setup.conf existe)"
elif ask "Configurar DNS-over-HTTPS?"; then

    # --- Instalar Stubby si no existe ---
    if [[ "$HAS_STUBBY" == false ]]; then
        log_info "Stubby no detectado, intentando instalar..."
        if pkg_install "stubby" 2>/dev/null; then
            HAS_STUBBY=true
            log_change "Instalado" "Stubby resolver"
        else
            log_warn "No se pudo instalar Stubby via gestor de paquetes"
        fi
    fi

    if [[ "$HAS_STUBBY" == true ]]; then
        STUBBY_CONF="/etc/stubby/stubby.yml"
        if [[ -f "$STUBBY_CONF" ]]; then
            cp "$STUBBY_CONF" "$BACKUP_DIR/stubby.yml.bak"
            log_change "Backup" "$STUBBY_CONF"
        fi

        mkdir -p /etc/stubby
        cat > "$STUBBY_CONF" << 'EOF'
# ============================================================
# stubby.yml - Configuracion de Stubby para DoT/DoH
# Generado por securizar - Modulo 65
# ============================================================

resolution_type: GETDNS_RESOLUTION_STUB

dns_transport_list:
  - GETDNS_TRANSPORT_TLS

tls_authentication: GETDNS_AUTHENTICATION_REQUIRED

tls_query_padding_blocksize: 128

edns_client_subnet_private: 1

round_robin_upstreams: 1

idle_timeout: 10000

listen_addresses:
  - 127.0.0.1@8053
  - 0::1@8053

upstream_recursive_servers:
  # Cloudflare DNS
  - address_data: 1.1.1.1
    tls_auth_name: "cloudflare-dns.com"
    tls_port: 853
  - address_data: 1.0.0.1
    tls_auth_name: "cloudflare-dns.com"
    tls_port: 853
  # Google DNS
  - address_data: 8.8.8.8
    tls_auth_name: "dns.google"
    tls_port: 853
  - address_data: 8.8.4.4
    tls_auth_name: "dns.google"
    tls_port: 853
  # Quad9
  - address_data: 9.9.9.9
    tls_auth_name: "dns.quad9.net"
    tls_port: 853
  - address_data: 149.112.112.112
    tls_auth_name: "dns.quad9.net"
    tls_port: 853
EOF
        chmod 644 "$STUBBY_CONF"
        log_change "Configurado" "Stubby con DoT estricto en $STUBBY_CONF"

        # Habilitar y arrancar Stubby
        systemctl enable stubby 2>/dev/null || true
        systemctl restart stubby 2>/dev/null || true
        log_change "Habilitado" "servicio stubby"
    fi

    # --- Configuracion DoH proxy con cloudflared (informativa) ---
    DOH_INFO="/etc/securizar/dns/doh-setup.conf"
    cat > "$DOH_INFO" << 'EOF'
# ============================================================
# doh-setup.conf - Guia de configuracion DoH
# Generado por securizar - Modulo 65
# ============================================================

# Para configurar un proxy DoH completo con cloudflared:
#
# 1. Instalar cloudflared:
#    curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o /usr/local/bin/cloudflared
#    chmod +x /usr/local/bin/cloudflared
#
# 2. Crear servicio systemd:
#    cloudflared proxy-dns --port 3053 --upstream https://cloudflare-dns.com/dns-query
#
# 3. Configurar como resolver:
#    Apuntar DNS local a 127.0.0.1:3053

# --- Configuracion de navegadores ---
# Firefox: about:config -> network.trr.mode = 2 (DoH preferente)
#          network.trr.uri = https://cloudflare-dns.com/dns-query
#
# Chrome:  chrome://settings/security -> Usar DNS seguro
#          Seleccionar Cloudflare (1.1.1.1) o Google (8.8.8.8)
#
# Brave:   brave://settings/security -> DNS seguro
#
# Edge:    edge://settings/privacy -> Usar DNS seguro

DOH_PROXY_LISTEN="127.0.0.1:3053"
DOH_UPSTREAM_PRIMARY="https://cloudflare-dns.com/dns-query"
DOH_UPSTREAM_SECONDARY="https://dns.google/dns-query"
DOH_UPSTREAM_TERTIARY="https://dns.quad9.net/dns-query"
EOF
    chmod 644 "$DOH_INFO"
    log_change "Creado" "Guia DoH en $DOH_INFO"

    # --- Script cloudflared systemd unit (preparado) ---
    cat > /etc/securizar/dns/cloudflared-doh.service << 'EOF'
# ============================================================
# cloudflared-doh.service - Proxy DoH con cloudflared
# Copiar a /etc/systemd/system/ tras instalar cloudflared
# Generado por securizar - Modulo 65
# ============================================================
[Unit]
Description=Cloudflared DoH Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=/usr/local/bin/cloudflared proxy-dns \
    --port 3053 \
    --upstream https://cloudflare-dns.com/dns-query \
    --upstream https://dns.google/dns-query
Restart=on-failure
RestartSec=10
LimitNOFILE=65536
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/log

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 /etc/securizar/dns/cloudflared-doh.service
    log_change "Creado" "Plantilla systemd para cloudflared DoH proxy"

else
    log_skip "DNS-over-HTTPS"
fi

# ============================================================
# S4: HARDENING DE UNBOUND RESOLVER
# ============================================================
log_section "S4: HARDENING DE UNBOUND RESOLVER"

echo "Instala y configura Unbound como resolver local seguro:"
echo "  - Control de acceso (solo localhost)"
echo "  - Ocultar identidad y version"
echo "  - QNAME minimization (RFC 7816)"
echo "  - Aggressive NSEC (RFC 8198)"
echo "  - Rate limiting"
echo "  - Configuracion en /etc/unbound/unbound.conf.d/securizar.conf"
echo ""

if check_file_contains /etc/unbound/unbound.conf.d/securizar.conf "harden-glue" 2>/dev/null || check_file_contains /etc/unbound/conf.d/securizar.conf "harden-glue" 2>/dev/null; then
    log_already "Hardening de Unbound resolver (securizar.conf existe)"
elif ask "Aplicar hardening de Unbound resolver?"; then

    # Instalar Unbound si no existe
    if [[ "$HAS_UNBOUND" == false ]]; then
        log_info "Unbound no detectado, instalando..."
        if pkg_install "unbound" 2>/dev/null; then
            HAS_UNBOUND=true
            log_change "Instalado" "Unbound resolver"
        else
            log_warn "No se pudo instalar Unbound"
        fi
    fi

    if [[ "$HAS_UNBOUND" == true ]]; then

        # Backup configuracion existente
        UNBOUND_CONF="/etc/unbound/unbound.conf"
        UNBOUND_CONF_D="/etc/unbound/unbound.conf.d"
        if [[ -f "$UNBOUND_CONF" ]]; then
            cp "$UNBOUND_CONF" "$BACKUP_DIR/unbound.conf.bak"
            log_change "Backup" "$UNBOUND_CONF"
        fi

        mkdir -p "$UNBOUND_CONF_D"

        # Asegurar que unbound.conf incluye conf.d
        if [[ -f "$UNBOUND_CONF" ]]; then
            if ! grep -q "include.*unbound.conf.d" "$UNBOUND_CONF" 2>/dev/null; then
                echo "" >> "$UNBOUND_CONF"
                echo "include: \"$UNBOUND_CONF_D/*.conf\"" >> "$UNBOUND_CONF"
                log_change "Configurado" "include de $UNBOUND_CONF_D en unbound.conf"
            fi
        fi

        # Descargar root hints si no existen
        ROOT_HINTS="/etc/unbound/root.hints"
        if [[ ! -f "$ROOT_HINTS" ]] || [[ $(find "$ROOT_HINTS" -mtime +90 2>/dev/null | wc -l) -gt 0 ]]; then
            if command -v wget &>/dev/null; then
                wget -q -O "$ROOT_HINTS" https://www.internic.net/domain/named.cache 2>/dev/null || true
            elif command -v curl &>/dev/null; then
                curl -sS -o "$ROOT_HINTS" https://www.internic.net/domain/named.cache 2>/dev/null || true
            fi
            if [[ -f "$ROOT_HINTS" ]] && [[ -s "$ROOT_HINTS" ]]; then
                log_change "Actualizado" "Root hints: $ROOT_HINTS"
            else
                log_warn "No se pudieron descargar root hints"
            fi
        else
            log_info "Root hints actualizados: $ROOT_HINTS"
        fi

        # Actualizar trust anchor
        if command -v unbound-anchor &>/dev/null; then
            unbound-anchor -a /etc/unbound/root.key 2>/dev/null || true
            log_change "Actualizado" "Unbound trust anchor"
        fi

        # Crear configuracion de hardening
        cat > "$UNBOUND_CONF_D/securizar.conf" << 'EOF'
# ============================================================
# securizar.conf - Hardening de Unbound
# Generado por securizar - Modulo 65
# ============================================================

server:
    # --- Interfaces de escucha ---
    interface: 127.0.0.1
    interface: ::1
    port: 53

    # --- Control de acceso ---
    access-control: 0.0.0.0/0 refuse
    access-control: ::0/0 refuse
    access-control: 127.0.0.0/8 allow
    access-control: ::1/128 allow
    access-control: 10.0.0.0/8 allow
    access-control: 172.16.0.0/12 allow
    access-control: 192.168.0.0/16 allow

    # --- Ocultar identidad y version ---
    hide-identity: yes
    hide-version: yes
    identity: "dns"
    version: "0"

    # --- QNAME Minimization (RFC 7816) ---
    qname-minimisation: yes
    qname-minimisation-strict: no

    # --- Aggressive NSEC (RFC 8198) ---
    aggressive-nsec: yes

    # --- DNSSEC ---
    auto-trust-anchor-file: "/etc/unbound/root.key"
    val-clean-additional: yes
    val-permissive-mode: no
    val-log-level: 1

    # --- Root hints ---
    root-hints: "/etc/unbound/root.hints"

    # --- Cache ---
    cache-min-ttl: 300
    cache-max-ttl: 86400
    cache-max-negative-ttl: 900
    infra-cache-numhosts: 10000
    msg-cache-size: 64m
    rrset-cache-size: 128m
    key-cache-size: 32m
    neg-cache-size: 16m

    # --- Rate limiting ---
    ratelimit: 1000
    ratelimit-size: 4m
    ratelimit-slabs: 4
    ip-ratelimit: 100
    ip-ratelimit-size: 4m
    ip-ratelimit-slabs: 4

    # --- Rendimiento ---
    num-threads: 2
    msg-cache-slabs: 4
    rrset-cache-slabs: 4
    infra-cache-slabs: 4
    key-cache-slabs: 4
    so-reuseport: yes
    so-rcvbuf: 4m
    so-sndbuf: 4m
    outgoing-range: 8192
    num-queries-per-thread: 4096

    # --- Seguridad ---
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-below-nxdomain: yes
    harden-referral-path: yes
    harden-algo-downgrade: yes
    harden-large-queries: yes
    harden-short-bufsize: yes
    use-caps-for-id: yes
    unwanted-reply-threshold: 10000000

    # --- Privacidad ---
    do-not-query-localhost: no
    prefetch: yes
    prefetch-key: yes
    deny-any: yes
    rrset-roundrobin: yes
    minimal-responses: yes

    # --- Logging ---
    verbosity: 1
    log-queries: no
    log-replies: no
    log-local-actions: yes
    log-servfail: yes
    logfile: "/var/log/unbound/unbound.log"
    use-syslog: no
    val-log-level: 1

    # --- Limites de red ---
    edns-buffer-size: 1232
    max-udp-size: 4096
    outgoing-num-tcp: 100
    incoming-num-tcp: 100

    # --- Proteccion contra rebinding DNS ---
    private-address: 10.0.0.0/8
    private-address: 172.16.0.0/12
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: fd00::/8
    private-address: fe80::/10

    # --- Chroot (seguridad adicional) ---
    # chroot: "/etc/unbound"
    # username: "unbound"

    # --- TLS upstream (DNS-over-TLS a forwarders) ---
    # Descomentar para usar Unbound como forwarder DoT
    # tls-cert-bundle: "/etc/ssl/certs/ca-certificates.crt"

# --- Forward zone (opcional - descomentar para usar) ---
# forward-zone:
#     name: "."
#     forward-tls-upstream: yes
#     forward-addr: 1.1.1.1@853#cloudflare-dns.com
#     forward-addr: 1.0.0.1@853#cloudflare-dns.com
#     forward-addr: 8.8.8.8@853#dns.google
#     forward-addr: 9.9.9.9@853#dns.quad9.net
EOF
        chmod 644 "$UNBOUND_CONF_D/securizar.conf"
        log_change "Creado" "$UNBOUND_CONF_D/securizar.conf"

        # Crear directorio de logs
        mkdir -p /var/log/unbound
        if id unbound &>/dev/null; then
            chown unbound:unbound /var/log/unbound
        fi
        log_change "Creado" "/var/log/unbound"

        # Verificar configuracion
        if unbound-checkconf &>/dev/null 2>&1; then
            log_info "Configuracion de Unbound verificada correctamente"
            systemctl enable unbound 2>/dev/null || true
            systemctl restart unbound 2>/dev/null || true
            log_change "Habilitado" "servicio unbound"
        else
            log_warn "Errores en configuracion de Unbound:"
            unbound-checkconf 2>&1 | head -10 || true
            log_warn "Revise $UNBOUND_CONF_D/securizar.conf"
        fi

        # Logrotate para unbound
        cat > /etc/logrotate.d/unbound-securizar << 'EOF'
/var/log/unbound/unbound.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 unbound unbound
    postrotate
        /usr/sbin/unbound-control log_reopen 2>/dev/null || true
    endscript
}
EOF
        chmod 644 /etc/logrotate.d/unbound-securizar
        log_change "Creado" "Logrotate para Unbound"
    else
        log_warn "Unbound no disponible, omitiendo hardening"
    fi

else
    log_skip "Hardening de Unbound resolver"
fi

# ============================================================
# S5: DNS SINKHOLE Y RPZ (RESPONSE POLICY ZONES)
# ============================================================
log_section "S5: DNS SINKHOLE Y RPZ"

echo "Configura DNS sinkhole con listas de bloqueo:"
echo "  - Blocklists: abuse.ch, PhishTank, Steven Black"
echo "  - Script de actualizacion /usr/local/bin/actualizar-dns-blocklist.sh"
echo "  - Cron diario de actualizacion"
echo "  - Soporte de whitelist"
echo ""

if check_file_exists /usr/local/bin/actualizar-dns-blocklist.sh; then
    log_already "DNS sinkhole y RPZ (actualizar-dns-blocklist.sh existe)"
elif ask "Configurar DNS sinkhole y RPZ?"; then

    # Crear directorios
    mkdir -p /etc/securizar/dns/blocklists
    mkdir -p /etc/securizar/dns/rpz

    # --- Whitelist ---
    WHITELIST="/etc/securizar/dns/whitelist.conf"
    if [[ ! -f "$WHITELIST" ]]; then
        cat > "$WHITELIST" << 'EOF'
# ============================================================
# whitelist.conf - Dominios excluidos del sinkhole
# Generado por securizar - Modulo 65
# ============================================================
# Un dominio por linea. Lineas vacias y comentarios (#) se ignoran.
# Ejemplo:
# example.com
# *.example.org
#
# Dominios criticos que no deben bloquearse:
localhost
localhost.localdomain
EOF
        chmod 644 "$WHITELIST"
        log_change "Creado" "Whitelist DNS: $WHITELIST"
    else
        log_info "Whitelist DNS ya existe: $WHITELIST"
    fi

    # --- Script de actualizacion de blocklists ---
    cat > /usr/local/bin/actualizar-dns-blocklist.sh << 'EOF'
#!/bin/bash
# ============================================================
# actualizar-dns-blocklist.sh - Actualiza blocklists DNS
# Generado por securizar - Modulo 65
# ============================================================
set -euo pipefail

BLOCKLIST_DIR="/etc/securizar/dns/blocklists"
RPZ_DIR="/etc/securizar/dns/rpz"
WHITELIST="/etc/securizar/dns/whitelist.conf"
LOGFILE="/var/log/securizar/dns-blocklist-update.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
COMBINED_LIST="$BLOCKLIST_DIR/combined-blocklist.txt"
RPZ_ZONE="$RPZ_DIR/blocklist.rpz"
TEMP_DIR=$(mktemp -d /tmp/dns-blocklist-XXXXXX)

cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

log_msg() {
    echo "$TIMESTAMP $1" >> "$LOGFILE"
    echo "$1"
}

mkdir -p "$BLOCKLIST_DIR" "$RPZ_DIR" "$(dirname "$LOGFILE")"

log_msg "=== Inicio actualizacion de blocklists DNS ==="

TOTAL_DOMAINS=0
SOURCES_OK=0
SOURCES_FAIL=0

# --- Funcion para descargar lista ---
download_list() {
    local name="$1"
    local url="$2"
    local output="$TEMP_DIR/$name.txt"

    if command -v curl &>/dev/null; then
        if curl -sS --max-time 60 -o "$output" "$url" 2>/dev/null; then
            local count
            count=$(wc -l < "$output")
            log_msg "  [OK] $name: $count lineas descargadas"
            ((SOURCES_OK++)) || true
            return 0
        fi
    elif command -v wget &>/dev/null; then
        if wget -q --timeout=60 -O "$output" "$url" 2>/dev/null; then
            local count
            count=$(wc -l < "$output")
            log_msg "  [OK] $name: $count lineas descargadas"
            ((SOURCES_OK++)) || true
            return 0
        fi
    fi
    log_msg "  [FAIL] $name: no se pudo descargar"
    ((SOURCES_FAIL++)) || true
    return 1
}

# --- Descargar listas ---
log_msg "Descargando blocklists..."

# Steven Black hosts (unified hosts)
download_list "stevenblack" \
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" || true

# abuse.ch URLhaus
download_list "abusech-urlhaus" \
    "https://urlhaus.abuse.ch/downloads/hostfile/" || true

# PhishTank (via phishing domains list)
download_list "phishtank" \
    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt" || true

# Malware domains
download_list "malwaredomains" \
    "https://raw.githubusercontent.com/stamparm/blackbook/master/blackbook.txt" || true

# Abuse.ch Feodo Tracker
download_list "feodotracker" \
    "https://feodotracker.abuse.ch/downloads/domainblocklist.txt" || true

# --- Procesar y combinar listas ---
log_msg "Procesando listas..."

# Extraer dominios de todas las listas descargadas
: > "$TEMP_DIR/all-domains.txt"

for file in "$TEMP_DIR"/*.txt; do
    [[ -f "$file" ]] || continue
    # Extraer dominios: quitar comentarios, IPs, y lineas vacias
    grep -vE '^\s*#|^\s*$|^!|^@' "$file" 2>/dev/null | \
        sed -E 's/^(0\.0\.0\.0|127\.0\.0\.1)\s+//; s/\s*#.*$//' | \
        grep -oE '[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}' | \
        tr '[:upper:]' '[:lower:]' >> "$TEMP_DIR/all-domains.txt" || true
done

# Eliminar duplicados y localhost
sort -u "$TEMP_DIR/all-domains.txt" | \
    grep -vE '^localhost$|^localhost\.localdomain$' > "$TEMP_DIR/unique-domains.txt"

# --- Aplicar whitelist ---
if [[ -f "$WHITELIST" ]]; then
    WHITELIST_CLEAN=$(grep -vE '^\s*#|^\s*$' "$WHITELIST" | sed 's/^\*\.//' || true)
    if [[ -n "$WHITELIST_CLEAN" ]]; then
        WHITELIST_PATTERN=$(echo "$WHITELIST_CLEAN" | paste -sd'|' | sed 's/\./\\./g')
        grep -vE "$WHITELIST_PATTERN" "$TEMP_DIR/unique-domains.txt" > "$TEMP_DIR/filtered-domains.txt" || true
        REMOVED=$(( $(wc -l < "$TEMP_DIR/unique-domains.txt") - $(wc -l < "$TEMP_DIR/filtered-domains.txt") ))
        log_msg "Whitelist aplicada: $REMOVED dominios excluidos"
        mv "$TEMP_DIR/filtered-domains.txt" "$TEMP_DIR/unique-domains.txt"
    fi
fi

TOTAL_DOMAINS=$(wc -l < "$TEMP_DIR/unique-domains.txt")
log_msg "Total dominios unicos: $TOTAL_DOMAINS"

# --- Generar lista combinada ---
cp "$TEMP_DIR/unique-domains.txt" "$COMBINED_LIST"
chmod 644 "$COMBINED_LIST"

# --- Generar zona RPZ para Unbound ---
{
    echo "; ============================================================"
    echo "; RPZ blocklist para Unbound"
    echo "; Generado por securizar - Modulo 65"
    echo "; Fecha: $TIMESTAMP"
    echo "; Dominios: $TOTAL_DOMAINS"
    echo "; ============================================================"
    echo ""
    while IFS= read -r domain; do
        [[ -z "$domain" ]] && continue
        echo "local-zone: \"$domain\" always_nxdomain"
    done < "$TEMP_DIR/unique-domains.txt"
} > "$RPZ_ZONE"
chmod 644 "$RPZ_ZONE"

# --- Generar hosts file format ---
{
    echo "# ============================================================"
    echo "# Hosts blocklist"
    echo "# Generado por securizar - Modulo 65"
    echo "# Fecha: $TIMESTAMP"
    echo "# Dominios: $TOTAL_DOMAINS"
    echo "# ============================================================"
    while IFS= read -r domain; do
        [[ -z "$domain" ]] && continue
        echo "0.0.0.0 $domain"
    done < "$TEMP_DIR/unique-domains.txt"
} > "$BLOCKLIST_DIR/hosts-blocklist.txt"
chmod 644 "$BLOCKLIST_DIR/hosts-blocklist.txt"

# --- Recargar Unbound si usa RPZ ---
if command -v unbound-control &>/dev/null; then
    if [[ -f /etc/unbound/unbound.conf.d/securizar-rpz.conf ]]; then
        unbound-control reload 2>/dev/null || true
        log_msg "Unbound recargado con nueva blocklist"
    fi
fi

log_msg "=== Actualizacion completada ==="
log_msg "Fuentes OK: $SOURCES_OK | Fuentes fallidas: $SOURCES_FAIL | Dominios: $TOTAL_DOMAINS"
EOF
    chmod 755 /usr/local/bin/actualizar-dns-blocklist.sh
    log_change "Creado" "/usr/local/bin/actualizar-dns-blocklist.sh"

    # --- Unbound RPZ include config ---
    if [[ "$HAS_UNBOUND" == true ]]; then
        UNBOUND_RPZ_CONF="/etc/unbound/unbound.conf.d/securizar-rpz.conf"
        cat > "$UNBOUND_RPZ_CONF" << 'EOF'
# ============================================================
# securizar-rpz.conf - RPZ blocklist para Unbound
# Generado por securizar - Modulo 65
# ============================================================
# Incluir blocklist RPZ generada por actualizar-dns-blocklist.sh
server:
    include: "/etc/securizar/dns/rpz/blocklist.rpz"
EOF
        chmod 644 "$UNBOUND_RPZ_CONF"
        log_change "Creado" "$UNBOUND_RPZ_CONF"
    fi

    # --- Cron diario ---
    CRON_BLOCKLIST="/etc/cron.daily/securizar-dns-blocklist"
    cat > "$CRON_BLOCKLIST" << 'EOF'
#!/bin/bash
# Actualizacion diaria de blocklists DNS - securizar Modulo 65
/usr/local/bin/actualizar-dns-blocklist.sh >> /var/log/securizar/dns-blocklist-update.log 2>&1
EOF
    chmod 755 "$CRON_BLOCKLIST"
    log_change "Creado" "Cron diario: $CRON_BLOCKLIST"

    # Ejecutar primera actualizacion
    if ask "Ejecutar primera descarga de blocklists ahora?"; then
        /usr/local/bin/actualizar-dns-blocklist.sh || true
        log_change "Ejecutado" "Primera descarga de blocklists DNS"
    else
        log_skip "Primera descarga de blocklists"
    fi

else
    log_skip "DNS sinkhole y RPZ"
fi

# ============================================================
# S6: DETECCION DE DNS TUNNELING
# ============================================================
log_section "S6: DETECCION DE DNS TUNNELING"

echo "Configura deteccion de tuneles DNS:"
echo "  - Script /usr/local/bin/detectar-dns-tunneling.sh"
echo "  - Deteccion de dominios de alta entropia"
echo "  - Deteccion de queries TXT/NULL sospechosas"
echo "  - Deteccion de herramientas iodine/dnscat2"
echo "  - Reglas Suricata para DNS tunneling"
echo ""

if check_file_exists /usr/local/bin/detectar-dns-tunneling.sh; then
    log_already "Deteccion de DNS tunneling (detectar-dns-tunneling.sh existe)"
elif ask "Configurar deteccion de DNS tunneling?"; then

    # --- Script de deteccion de DNS tunneling ---
    cat > /usr/local/bin/detectar-dns-tunneling.sh << 'EOF'
#!/bin/bash
# ============================================================
# detectar-dns-tunneling.sh - Detecta tuneles DNS
# Generado por securizar - Modulo 65
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

LOGFILE="/var/log/securizar/dns-tunneling.log"
ALERT_LOG="/var/log/securizar/dns-tunneling-alerts.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
ENTROPY_THRESHOLD="${DNS_TUNNEL_ENTROPY_THRESHOLD:-3.5}"
MAX_LABEL_LENGTH="${DNS_TUNNEL_MAX_LABEL:-50}"
ALERT_COUNT=0

mkdir -p "$(dirname "$LOGFILE")"

log_alert() {
    local msg="$1"
    ((ALERT_COUNT++)) || true
    echo -e "${RED}[ALERTA]${NC} $msg"
    echo "$TIMESTAMP [ALERTA] $msg" >> "$ALERT_LOG"
    echo "$TIMESTAMP [ALERTA] $msg" >> "$LOGFILE"
}

log_ok() {
    echo -e "${GREEN}[OK]${NC} $1"
    echo "$TIMESTAMP [OK] $1" >> "$LOGFILE"
}

log_check() {
    echo -e "${CYAN}[CHECK]${NC} $1"
    echo "$TIMESTAMP [CHECK] $1" >> "$LOGFILE"
}

# --- Funcion para calcular entropia de Shannon ---
calculate_entropy() {
    local string="$1"
    python3 -c "
import math, collections, sys
s = sys.argv[1]
if not s:
    print(0.0)
    sys.exit(0)
freq = collections.Counter(s)
length = len(s)
entropy = -sum((count/length) * math.log2(count/length) for count in freq.values())
print(f'{entropy:.2f}')
" "$string" 2>/dev/null || echo "0.0"
}

echo -e "${CYAN}${BOLD}=== Deteccion de DNS Tunneling ===${NC}"
echo "$TIMESTAMP === Inicio deteccion DNS tunneling ===" >> "$LOGFILE"

# --- 1. Detectar herramientas de tunneling instaladas ---
log_check "Buscando herramientas de DNS tunneling instaladas..."

TUNNEL_TOOLS=("iodine" "iodined" "dnscat2" "dnscat" "dns2tcp" "dns2tcpc" "dns2tcpd" "ozymandns" "heyoka" "tuns")
for tool in "${TUNNEL_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        log_alert "Herramienta de DNS tunneling encontrada: $tool ($(which "$tool"))"
    fi
    # Buscar en procesos activos
    if pgrep -x "$tool" &>/dev/null; then
        log_alert "Proceso de DNS tunneling activo: $tool (PID: $(pgrep -x "$tool" | head -1))"
    fi
done

# Buscar en PATH comunes
for dir in /usr/local/bin /usr/bin /opt /tmp /var/tmp; do
    for tool in iodine dnscat dns2tcp; do
        if [[ -f "$dir/$tool" ]] || [[ -f "$dir/${tool}d" ]]; then
            log_alert "Binario de tunneling encontrado: $dir/$tool"
        fi
    done
done

# --- 2. Analizar queries DNS recientes (si hay logs) ---
log_check "Analizando queries DNS recientes..."

DNS_LOG_SOURCES=(
    "/var/log/unbound/unbound.log"
    "/var/log/named/query.log"
    "/var/log/syslog"
    "/var/log/messages"
)

ANALYZED_QUERIES=0
SUSPICIOUS_QUERIES=0

for log_source in "${DNS_LOG_SOURCES[@]}"; do
    [[ -f "$log_source" ]] || continue
    log_check "Analizando: $log_source"

    # Extraer dominios consultados (ultimas 1000 lineas)
    DOMAINS=$(tail -1000 "$log_source" 2>/dev/null | \
        grep -oE '[a-zA-Z0-9]([a-zA-Z0-9.-]{10,})\.[a-zA-Z]{2,}' | \
        sort -u | head -500 || true)

    while IFS= read -r domain; do
        [[ -z "$domain" ]] && continue
        ((ANALYZED_QUERIES++)) || true

        # Verificar longitud de labels
        LONGEST_LABEL=$(echo "$domain" | tr '.' '\n' | awk '{ print length }' | sort -rn | head -1)
        if [[ "${LONGEST_LABEL:-0}" -gt "$MAX_LABEL_LENGTH" ]]; then
            log_alert "Label DNS extremadamente largo ($LONGEST_LABEL chars): $domain"
            ((SUSPICIOUS_QUERIES++)) || true
            continue
        fi

        # Verificar entropia (dominios con datos codificados tienen alta entropia)
        FIRST_LABEL=$(echo "$domain" | cut -d. -f1)
        if [[ ${#FIRST_LABEL} -gt 20 ]]; then
            ENTROPY=$(calculate_entropy "$FIRST_LABEL")
            if command -v python3 &>/dev/null; then
                IS_HIGH=$(python3 -c "print('yes' if float('$ENTROPY') > float('$ENTROPY_THRESHOLD') else 'no')" 2>/dev/null || echo "no")
                if [[ "$IS_HIGH" == "yes" ]]; then
                    log_alert "Alta entropia ($ENTROPY) en query DNS: $domain"
                    ((SUSPICIOUS_QUERIES++)) || true
                fi
            fi
        fi

        # Verificar longitud total excesiva
        if [[ ${#domain} -gt 150 ]]; then
            log_alert "Query DNS excesivamente largo (${#domain} chars): ${domain:0:80}..."
            ((SUSPICIOUS_QUERIES++)) || true
        fi
    done <<< "$DOMAINS"
done

# --- 3. Detectar queries TXT/NULL sospechosas ---
log_check "Buscando queries TXT/NULL sospechosas..."

for log_source in "${DNS_LOG_SOURCES[@]}"; do
    [[ -f "$log_source" ]] || continue
    TXT_COUNT=$(tail -5000 "$log_source" 2>/dev/null | grep -ciE "type.*TXT|qtype.*TXT|type=TXT" || true)
    NULL_COUNT=$(tail -5000 "$log_source" 2>/dev/null | grep -ciE "type.*NULL|qtype.*NULL|type=NULL|type=10" || true)

    if [[ "${TXT_COUNT:-0}" -gt 100 ]]; then
        log_alert "Alto volumen de queries TXT ($TXT_COUNT) en $log_source"
    fi
    if [[ "${NULL_COUNT:-0}" -gt 10 ]]; then
        log_alert "Queries tipo NULL detectadas ($NULL_COUNT) en $log_source - posible tunneling"
    fi
done

# --- 4. Verificar trafico DNS anomalo con ss/netstat ---
log_check "Verificando conexiones DNS anomalas..."

if command -v ss &>/dev/null; then
    # Conexiones DNS a puertos no estandar
    ANOMALOUS=$(ss -tunp 2>/dev/null | grep -E ":53\s" | grep -v "127.0.0.1\|::1" | wc -l || true)
    if [[ "${ANOMALOUS:-0}" -gt 50 ]]; then
        log_alert "Alto numero de conexiones DNS externas: $ANOMALOUS"
    else
        log_ok "Conexiones DNS externas normales: $ANOMALOUS"
    fi
fi

# --- 5. Verificar interfaces TUN/TAP sospechosas (iodine) ---
log_check "Verificando interfaces de red sospechosas..."

if ip link show 2>/dev/null | grep -qE "dns[0-9]+|tun[0-9]+" 2>/dev/null; then
    SUSPECT_IFACE=$(ip link show 2>/dev/null | grep -oE "dns[0-9]+|tun[0-9]+" | head -5)
    for iface in $SUSPECT_IFACE; do
        log_alert "Interfaz sospechosa (posible tunnel DNS): $iface"
    done
else
    log_ok "Sin interfaces de tunneling sospechosas"
fi

# --- Resumen ---
echo ""
echo -e "${CYAN}=== Resumen ===${NC}"
echo -e "Queries analizadas: $ANALYZED_QUERIES"
echo -e "Queries sospechosas: $SUSPICIOUS_QUERIES"
echo -e "Alertas totales: $ALERT_COUNT"

if [[ $ALERT_COUNT -gt 0 ]]; then
    echo -e "${RED}${BOLD}Se detectaron $ALERT_COUNT alertas de posible tunneling DNS${NC}"
    echo -e "Revise: $ALERT_LOG"
else
    echo -e "${GREEN}No se detectaron indicios de DNS tunneling${NC}"
fi

echo "$TIMESTAMP === Fin deteccion: $ALERT_COUNT alertas ===" >> "$LOGFILE"
EOF
    chmod 755 /usr/local/bin/detectar-dns-tunneling.sh
    log_change "Creado" "/usr/local/bin/detectar-dns-tunneling.sh"

    # --- Reglas Suricata para DNS tunneling ---
    if [[ "$HAS_SURICATA" == true ]]; then
        SURICATA_RULES_DIR="/etc/suricata/rules"
        mkdir -p "$SURICATA_RULES_DIR"

        cat > "$SURICATA_RULES_DIR/securizar-dns-tunneling.rules" << 'EOF'
# ============================================================
# securizar-dns-tunneling.rules - Reglas Suricata para DNS tunneling
# Generado por securizar - Modulo 65
# ============================================================

# Detectar iodine DNS tunnel
alert dns any any -> any any (msg:"SECURIZAR - Posible iodine DNS tunnel (dominio largo)"; dns.query; content:"."; pcre:"/^[a-z0-9]{52,}\./i"; sid:6500001; rev:1; classtype:policy-violation;)

# Detectar dnscat2
alert dns any any -> any any (msg:"SECURIZAR - Posible dnscat2 tunnel"; dns.query; content:"dnscat"; nocase; sid:6500002; rev:1; classtype:policy-violation;)

# Queries TXT excesivamente grandes
alert dns any any -> any any (msg:"SECURIZAR - Query DNS TXT grande (posible tunneling)"; dns.query; content:"|00 10|"; dsize:>512; sid:6500003; rev:1; classtype:policy-violation;)

# Queries NULL (tipo 10) - usado por tunneling
alert dns any any -> any any (msg:"SECURIZAR - Query DNS tipo NULL (posible tunneling)"; dns.query; content:"|00 0a|"; sid:6500004; rev:1; classtype:policy-violation;)

# Alto volumen de queries a un mismo dominio
alert dns any any -> any any (msg:"SECURIZAR - Alto volumen DNS a mismo dominio"; dns.query; threshold:type both, track by_src, count 100, seconds 60; sid:6500005; rev:1; classtype:policy-violation;)

# Dominios con entropia alta (labels base32/base64)
alert dns any any -> any any (msg:"SECURIZAR - Subdominio largo sospechoso (tunneling)"; dns.query; pcre:"/^[a-z0-9+\/=-]{40,}\./i"; sid:6500006; rev:1; classtype:policy-violation;)

# Respuestas DNS TXT grandes
alert dns any any -> any any (msg:"SECURIZAR - Respuesta DNS TXT grande"; dns.query; content:"|00 10|"; dsize:>1024; sid:6500007; rev:1; classtype:policy-violation;)

# Detectar dns2tcp
alert dns any any -> any any (msg:"SECURIZAR - Posible dns2tcp tunnel"; dns.query; pcre:"/^[a-f0-9]{32,}\./i"; threshold:type both, track by_src, count 50, seconds 30; sid:6500008; rev:1; classtype:policy-violation;)

# NXDOMAIN excesivo (indicador de tunneling fallido)
alert dns any any -> any any (msg:"SECURIZAR - NXDOMAIN excesivo (posible tunneling)"; dns.query; threshold:type both, track by_src, count 200, seconds 60; sid:6500009; rev:1; classtype:policy-violation;)
EOF
        chmod 644 "$SURICATA_RULES_DIR/securizar-dns-tunneling.rules"
        log_change "Creado" "$SURICATA_RULES_DIR/securizar-dns-tunneling.rules"

        # Verificar si las reglas estan incluidas en suricata.yaml
        SURICATA_YAML="/etc/suricata/suricata.yaml"
        if [[ -f "$SURICATA_YAML" ]]; then
            if ! grep -q "securizar-dns-tunneling.rules" "$SURICATA_YAML" 2>/dev/null; then
                log_warn "Agregue manualmente a $SURICATA_YAML:"
                log_warn "  rule-files: - securizar-dns-tunneling.rules"
            fi
        fi
    else
        log_info "Suricata no detectado - reglas IDS guardadas como referencia"
        mkdir -p /etc/securizar/dns/suricata-rules
        cat > /etc/securizar/dns/suricata-rules/dns-tunneling.rules << 'EOF'
# Reglas Suricata para DNS tunneling (referencia)
# Instale Suricata y copie a /etc/suricata/rules/
alert dns any any -> any any (msg:"SECURIZAR - Posible iodine DNS tunnel"; dns.query; pcre:"/^[a-z0-9]{52,}\./i"; sid:6500001; rev:1;)
alert dns any any -> any any (msg:"SECURIZAR - Posible dnscat2 tunnel"; dns.query; content:"dnscat"; nocase; sid:6500002; rev:1;)
alert dns any any -> any any (msg:"SECURIZAR - Query DNS TXT grande"; dns.query; content:"|00 10|"; dsize:>512; sid:6500003; rev:1;)
alert dns any any -> any any (msg:"SECURIZAR - Query DNS tipo NULL"; dns.query; content:"|00 0a|"; sid:6500004; rev:1;)
alert dns any any -> any any (msg:"SECURIZAR - Alto volumen DNS"; dns.query; threshold:type both, track by_src, count 100, seconds 60; sid:6500005; rev:1;)
alert dns any any -> any any (msg:"SECURIZAR - Subdominio largo sospechoso"; dns.query; pcre:"/^[a-z0-9+\/=-]{40,}\./i"; sid:6500006; rev:1;)
EOF
        chmod 644 /etc/securizar/dns/suricata-rules/dns-tunneling.rules
        log_change "Creado" "Reglas Suricata de referencia en /etc/securizar/dns/suricata-rules/"
    fi

else
    log_skip "Deteccion de DNS tunneling"
fi

# ============================================================
# S7: PROTECCION CONTRA CACHE POISONING
# ============================================================
log_section "S7: PROTECCION CONTRA CACHE POISONING"

echo "Configura protecciones contra envenenamiento de cache DNS:"
echo "  - Randomizacion de puertos origen"
echo "  - Entropia de TXID"
echo "  - DNS Cookies (RFC 7873)"
echo "  - Max TTL en cache"
echo "  - Script de test"
echo ""

if check_file_exists /usr/local/bin/test-cache-poisoning.sh; then
    log_already "Proteccion contra cache poisoning (test-cache-poisoning.sh existe)"
elif ask "Aplicar proteccion contra cache poisoning?"; then

    # --- Sysctl para randomizacion de puertos ---
    SYSCTL_DNS="/etc/sysctl.d/90-securizar-dns.conf"
    if [[ -f "$SYSCTL_DNS" ]]; then
        cp "$SYSCTL_DNS" "$BACKUP_DIR/90-securizar-dns.conf.bak"
        log_change "Backup" "$SYSCTL_DNS"
    fi

    cat > "$SYSCTL_DNS" << 'EOF'
# ============================================================
# 90-securizar-dns.conf - Proteccion DNS contra cache poisoning
# Generado por securizar - Modulo 65
# ============================================================

# Randomizacion de puertos efimeros (source port randomization)
net.ipv4.ip_local_port_range = 32768 60999

# Proteccion contra IP spoofing (reverse path filtering)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignorar ICMP redirects (prevenir MITM DNS)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# IPv6 equivalentes
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Proteger contra ataques basados en fragmentacion
net.ipv4.ipfrag_high_thresh = 262144
net.ipv4.ipfrag_low_thresh = 196608

# Deshabilitar TCP timestamps (evita filtrar uptime del sistema)
net.ipv4.tcp_timestamps = 0
EOF
    chmod 644 "$SYSCTL_DNS"
    sysctl -p "$SYSCTL_DNS" 2>/dev/null || true
    log_change "Aplicado" "Sysctl DNS anti-poisoning: $SYSCTL_DNS"

    # --- Configuracion de Unbound para cache poisoning protection ---
    if [[ "$HAS_UNBOUND" == true ]]; then
        UNBOUND_POISON_CONF="/etc/unbound/unbound.conf.d/securizar-poison-protect.conf"
        cat > "$UNBOUND_POISON_CONF" << 'EOF'
# ============================================================
# securizar-poison-protect.conf - Anti cache poisoning para Unbound
# Generado por securizar - Modulo 65
# ============================================================
server:
    # 0x20 bit encoding (randomiza mayusculas/minusculas en queries)
    use-caps-for-id: yes

    # Limitar TTL en cache para reducir ventana de envenenamiento
    cache-max-ttl: 86400
    cache-min-ttl: 300
    cache-max-negative-ttl: 900

    # Glue hardening - evitar glue records fuera de zona
    harden-glue: yes

    # Rechazar respuestas sin DNSSEC si se esperaba
    harden-dnssec-stripped: yes

    # Hardening de referral path
    harden-referral-path: yes

    # Threshold alto para detectar unwanted replies (posible poisoning)
    unwanted-reply-threshold: 10000000

    # Limitar tamanio de respuestas grandes (anti-amplificacion)
    harden-large-queries: yes
    harden-short-bufsize: yes

    # EDNS buffer size reducido (RFC 8020)
    edns-buffer-size: 1232

    # Cookies DNS - soporte experimental
    # edns-tcp-keepalive: yes

    # Prefetch activo para mantener cache fresca
    prefetch: yes
    prefetch-key: yes

    # Rechazar respuestas below NXDOMAIN
    harden-below-nxdomain: yes

    # Algoritmo downgrade hardening
    harden-algo-downgrade: yes
EOF
        chmod 644 "$UNBOUND_POISON_CONF"
        log_change "Creado" "$UNBOUND_POISON_CONF"

        # Recargar Unbound si esta corriendo
        if systemctl is-active unbound &>/dev/null 2>&1; then
            unbound-control reload 2>/dev/null || systemctl restart unbound 2>/dev/null || true
            log_change "Recargado" "Unbound con proteccion anti-poisoning"
        fi
    fi

    # --- Script de test de cache poisoning ---
    cat > /usr/local/bin/test-cache-poisoning.sh << 'EOF'
#!/bin/bash
# ============================================================
# test-cache-poisoning.sh - Test de proteccion contra cache poisoning
# Generado por securizar - Modulo 65
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SCORE=0
TOTAL=0

check() {
    local desc="$1" result="$2"
    ((TOTAL++)) || true
    if [[ "$result" == "PASS" ]]; then
        echo -e "${GREEN}[PASS]${NC} $desc"
        ((SCORE++)) || true
    elif [[ "$result" == "WARN" ]]; then
        echo -e "${YELLOW}[WARN]${NC} $desc"
    else
        echo -e "${RED}[FAIL]${NC} $desc"
    fi
}

echo -e "${CYAN}=== Test de Proteccion contra Cache Poisoning ===${NC}"
echo ""

# 1. Source port randomization
PORTS=$(cat /proc/sys/net/ipv4/ip_local_port_range 2>/dev/null || echo "0 0")
LOW_PORT=$(echo "$PORTS" | awk '{print $1}')
HIGH_PORT=$(echo "$PORTS" | awk '{print $2}')
PORT_RANGE=$(( HIGH_PORT - LOW_PORT ))
if [[ $PORT_RANGE -ge 16000 ]]; then
    check "Rango de puertos efimeros: $LOW_PORT-$HIGH_PORT ($PORT_RANGE puertos)" "PASS"
else
    check "Rango de puertos efimeros limitado: $LOW_PORT-$HIGH_PORT ($PORT_RANGE puertos)" "FAIL"
fi

# 2. Reverse path filtering
RPF=$(cat /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null || echo "0")
if [[ "$RPF" == "1" ]]; then
    check "Reverse path filtering (rp_filter=1)" "PASS"
else
    check "Reverse path filtering deshabilitado (rp_filter=$RPF)" "FAIL"
fi

# 3. ICMP redirects deshabilitados
REDIR=$(cat /proc/sys/net/ipv4/conf/all/accept_redirects 2>/dev/null || echo "1")
if [[ "$REDIR" == "0" ]]; then
    check "ICMP redirects deshabilitados" "PASS"
else
    check "ICMP redirects habilitados" "FAIL"
fi

# 4. DNSSEC activo
if command -v dig &>/dev/null; then
    AD_FLAG=$(dig +dnssec +short dnssec.works A 2>/dev/null | wc -l || true)
    if [[ "${AD_FLAG:-0}" -gt 0 ]]; then
        check "DNSSEC validacion activa" "PASS"
    else
        check "DNSSEC validacion no activa" "WARN"
    fi
fi

# 5. Verificar 0x20 encoding en Unbound
if [[ -f /etc/unbound/unbound.conf.d/securizar.conf ]]; then
    if grep -q "use-caps-for-id: yes" /etc/unbound/unbound.conf.d/securizar.conf 2>/dev/null || \
       grep -q "use-caps-for-id: yes" /etc/unbound/unbound.conf.d/securizar-poison-protect.conf 2>/dev/null; then
        check "0x20 bit encoding (use-caps-for-id) habilitado" "PASS"
    else
        check "0x20 bit encoding no habilitado" "FAIL"
    fi
fi

# 6. Verificar harden-glue
if command -v unbound-control &>/dev/null; then
    if unbound-control get_option harden-glue 2>/dev/null | grep -q "yes"; then
        check "Unbound harden-glue habilitado" "PASS"
    else
        check "Unbound harden-glue" "WARN"
    fi
fi

# 7. Test TXID entropy con multiples consultas
if command -v dig &>/dev/null; then
    TXIDS=""
    for i in $(seq 1 10); do
        TXID=$(dig +noall +comments example.com 2>/dev/null | grep -oP 'id: \K\d+' || true)
        TXIDS="$TXIDS $TXID"
    done
    UNIQUE_TXIDS=$(echo "$TXIDS" | tr ' ' '\n' | sort -u | grep -c '[0-9]' || true)
    if [[ "$UNIQUE_TXIDS" -ge 8 ]]; then
        check "TXID entropy: $UNIQUE_TXIDS/10 IDs unicos" "PASS"
    elif [[ "$UNIQUE_TXIDS" -ge 5 ]]; then
        check "TXID entropy: $UNIQUE_TXIDS/10 IDs unicos" "WARN"
    else
        check "TXID entropy baja: $UNIQUE_TXIDS/10 IDs unicos" "FAIL"
    fi
fi

# 8. DNS multi-resolver: comparar respuestas de distintos resolvers
if command -v dig &>/dev/null; then
    TEST_DOMAIN="example.com"
    RESOLVERS="1.1.1.1 8.8.8.8 9.9.9.9"
    DNS_ANSWERS=""
    for resolver in $RESOLVERS; do
        ans=$(dig +short +time=3 +tries=1 "$TEST_DOMAIN" A "@$resolver" 2>/dev/null | sort | head -5 | tr '\n' ',' || true)
        DNS_ANSWERS="$DNS_ANSWERS|$resolver:$ans"
    done
    # Extraer solo las IPs de respuesta (sin el resolver prefix) para comparar
    UNIQUE_ANSWERS=$(echo "$DNS_ANSWERS" | tr '|' '\n' | grep ':' | cut -d: -f2 | sort -u | grep -c '[0-9]' || true)
    if [[ "$UNIQUE_ANSWERS" -le 1 ]]; then
        check "DNS multi-resolver consistente ($TEST_DOMAIN)" "PASS"
    else
        check "DNS multi-resolver INCONSISTENTE: $UNIQUE_ANSWERS respuestas distintas (posible manipulacion upstream)" "FAIL"
    fi
fi

# 9. TTL anomaly: detectar TTL sospechoso
if command -v dig &>/dev/null; then
    TEST_TTL=$(dig +noall +answer example.com A 2>/dev/null | awk '{print $2}' | head -1 || true)
    if [[ -n "$TEST_TTL" ]] && [[ "$TEST_TTL" =~ ^[0-9]+$ ]]; then
        if [[ "$TEST_TTL" -gt 86400 ]]; then
            check "TTL anomalo: $TEST_TTL > 86400 (posible poisoning persistente)" "FAIL"
        elif [[ "$TEST_TTL" -lt 10 ]]; then
            check "TTL anomalo: $TEST_TTL < 10 (posible fast-flux)" "WARN"
        else
            check "TTL razonable: $TEST_TTL" "PASS"
        fi
    fi
fi

# 10. DNS rebinding protection (Unbound private-address)
if command -v unbound-control &>/dev/null; then
    PRIV_ADDR=$(unbound-control get_option private-address 2>/dev/null || true)
    if [[ -n "$PRIV_ADDR" ]]; then
        check "Unbound private-address configurado (proteccion DNS rebinding)" "PASS"
    else
        check "Unbound private-address no configurado (vulnerable a DNS rebinding)" "FAIL"
    fi
fi

echo ""
echo -e "${CYAN}Puntuacion: ${SCORE}/${TOTAL}${NC}"
if [[ $TOTAL -gt 0 ]]; then
    PCT=$(( SCORE * 100 / TOTAL ))
    if [[ $PCT -ge 80 ]]; then
        echo -e "${GREEN}Proteccion anti-poisoning: BUENA ($PCT%)${NC}"
    elif [[ $PCT -ge 50 ]]; then
        echo -e "${YELLOW}Proteccion anti-poisoning: MEJORABLE ($PCT%)${NC}"
    else
        echo -e "${RED}Proteccion anti-poisoning: INSUFICIENTE ($PCT%)${NC}"
    fi
fi
EOF
    chmod 755 /usr/local/bin/test-cache-poisoning.sh
    log_change "Creado" "/usr/local/bin/test-cache-poisoning.sh"

else
    log_skip "Proteccion contra cache poisoning"
fi

# ============================================================
# S8: SPLIT-HORIZON DNS
# ============================================================
log_section "S8: SPLIT-HORIZON DNS"

echo "Configura split-horizon DNS para separar vistas:"
echo "  - Zonas internas vs externas"
echo "  - Vistas VPN"
echo "  - Plantillas Unbound"
echo "  - Configuracion en /etc/securizar/split-dns-zones.conf"
echo ""

if check_file_exists /etc/securizar/split-dns-zones.conf; then
    log_already "Split-horizon DNS (split-dns-zones.conf existe)"
elif ask "Configurar split-horizon DNS?"; then

    # --- Configuracion de zonas split-horizon ---
    SPLIT_DNS_CONF="/etc/securizar/split-dns-zones.conf"
    if [[ -f "$SPLIT_DNS_CONF" ]]; then
        cp "$SPLIT_DNS_CONF" "$BACKUP_DIR/split-dns-zones.conf.bak"
        log_change "Backup" "$SPLIT_DNS_CONF"
    fi

    cat > "$SPLIT_DNS_CONF" << 'EOF'
# ============================================================
# split-dns-zones.conf - Configuracion Split-Horizon DNS
# Generado por securizar - Modulo 65
# ============================================================
#
# Formato:
#   ZONE:<nombre_zona>:<tipo>:<redes>:<servidor_upstream>
#
# Tipos: internal, external, vpn
# Redes: CIDR separados por comas
# Servidor upstream: IP#hostname o IP@port
#
# Ejemplos:
# ZONE:empresa.local:internal:10.0.0.0/8,172.16.0.0/12:127.0.0.1
# ZONE:empresa.com:external:0.0.0.0/0:1.1.1.1#cloudflare-dns.com
# ZONE:vpn.empresa.com:vpn:10.8.0.0/24:10.8.0.1

# --- Zona interna (redes privadas) ---
ZONE:internal.local:internal:10.0.0.0/8,172.16.0.0/12,192.168.0.0/16:127.0.0.1

# --- Zona externa (todo lo demas) ---
ZONE:external:external:0.0.0.0/0:1.1.1.1#cloudflare-dns.com

# --- Zona VPN (ejemplo) ---
# ZONE:vpn.internal:vpn:10.8.0.0/24:10.8.0.1

# --- Configuracion global ---
SPLIT_DNS_DEFAULT_VIEW=external
SPLIT_DNS_LOG_QUERIES=no
SPLIT_DNS_CACHE_PER_VIEW=yes
EOF
    chmod 640 "$SPLIT_DNS_CONF"
    log_change "Creado" "$SPLIT_DNS_CONF"

    # --- Plantilla Unbound para split-horizon ---
    if [[ "$HAS_UNBOUND" == true ]]; then
        UNBOUND_SPLIT_CONF="/etc/unbound/unbound.conf.d/securizar-split-dns.conf"
        cat > "$UNBOUND_SPLIT_CONF" << 'EOF'
# ============================================================
# securizar-split-dns.conf - Split-Horizon DNS para Unbound
# Generado por securizar - Modulo 65
# ============================================================
# Unbound implementa split-horizon via access-control-view
# y forward-zone con condiciones.

# --- Vista interna ---
# Redes internas resuelven dominios .internal.local localmente
server:
    # Definir vista interna
    access-control-view: 10.0.0.0/8 "internal"
    access-control-view: 172.16.0.0/12 "internal"
    access-control-view: 192.168.0.0/16 "internal"

# --- Vista interna ---
view:
    name: "internal"
    view-first: yes
    local-zone: "internal.local." static
    # Agregar registros internos aqui:
    # local-data: "server1.internal.local. A 10.0.0.10"
    # local-data: "db.internal.local. A 10.0.0.20"
    # local-data: "mail.internal.local. A 10.0.0.30"

    # Zonas privadas que no deben resolverse externamente
    local-zone: "10.in-addr.arpa." nodefault
    local-zone: "16.172.in-addr.arpa." nodefault
    local-zone: "168.192.in-addr.arpa." nodefault

# --- Vista VPN (ejemplo - descomentar para usar) ---
# view:
#     name: "vpn"
#     view-first: yes
#     local-zone: "vpn.internal." static
#     local-data: "gateway.vpn.internal. A 10.8.0.1"

# --- Forward zone para dominios internos ---
# forward-zone:
#     name: "internal.local"
#     forward-addr: 10.0.0.1
#     forward-no-cache: no

# --- Forward zone para todo lo demas (vista externa) ---
forward-zone:
    name: "."
    forward-tls-upstream: yes
    forward-addr: 1.1.1.1@853#cloudflare-dns.com
    forward-addr: 8.8.8.8@853#dns.google
    forward-addr: 9.9.9.9@853#dns.quad9.net
EOF
        chmod 644 "$UNBOUND_SPLIT_CONF"
        log_change "Creado" "$UNBOUND_SPLIT_CONF"

        # Verificar configuracion
        if unbound-checkconf &>/dev/null 2>&1; then
            log_info "Configuracion split-horizon verificada"
        else
            log_warn "Errores en configuracion split-horizon. Revise $UNBOUND_SPLIT_CONF"
            log_warn "Puede ser necesario ajustar vistas y zonas"
        fi
    else
        log_warn "Unbound no disponible. La configuracion split-horizon requiere Unbound"
        log_info "Configuracion guardada en $SPLIT_DNS_CONF para uso futuro"
    fi

    # --- Script generador de configuracion split-dns ---
    cat > /usr/local/bin/generar-split-dns.sh << 'EOF'
#!/bin/bash
# ============================================================
# generar-split-dns.sh - Genera configuracion Unbound desde split-dns-zones.conf
# Generado por securizar - Modulo 65
# ============================================================
set -euo pipefail

SPLIT_CONF="/etc/securizar/split-dns-zones.conf"
OUTPUT="/etc/unbound/unbound.conf.d/securizar-split-dns-generated.conf"

if [[ ! -f "$SPLIT_CONF" ]]; then
    echo "Error: $SPLIT_CONF no encontrado"
    exit 1
fi

echo "Generando configuracion split-DNS desde $SPLIT_CONF..."

{
    echo "# ============================================================"
    echo "# securizar-split-dns-generated.conf"
    echo "# Generado automaticamente por generar-split-dns.sh"
    echo "# Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "# ============================================================"
    echo ""
    echo "server:"

    # Procesar zonas internas para access-control-view
    while IFS=: read -r prefix name type networks upstream; do
        [[ "$prefix" != "ZONE" ]] && continue
        [[ -z "$name" ]] && continue

        if [[ "$type" == "internal" || "$type" == "vpn" ]]; then
            IFS=',' read -ra NET_ARRAY <<< "$networks"
            for net in "${NET_ARRAY[@]}"; do
                echo "    access-control-view: $net \"$type\""
            done
        fi
    done < <(grep "^ZONE:" "$SPLIT_CONF")

    echo ""

    # Generar vistas
    while IFS=: read -r prefix name type networks upstream; do
        [[ "$prefix" != "ZONE" ]] && continue
        [[ -z "$name" ]] && continue

        if [[ "$type" == "internal" || "$type" == "vpn" ]]; then
            echo "view:"
            echo "    name: \"$type\""
            echo "    view-first: yes"
            echo "    local-zone: \"$name.\" static"
            echo ""
        fi
    done < <(grep "^ZONE:" "$SPLIT_CONF")

    # Forward zones
    while IFS=: read -r prefix name type networks upstream; do
        [[ "$prefix" != "ZONE" ]] && continue
        [[ -z "$name" || -z "$upstream" ]] && continue

        if [[ "$type" == "external" ]]; then
            echo "forward-zone:"
            echo "    name: \".\""
            echo "    forward-tls-upstream: yes"
            echo "    forward-addr: $upstream"
            echo ""
        fi
    done < <(grep "^ZONE:" "$SPLIT_CONF")

} > "$OUTPUT"

chmod 644 "$OUTPUT"
echo "Configuracion generada: $OUTPUT"

if command -v unbound-checkconf &>/dev/null; then
    if unbound-checkconf 2>/dev/null; then
        echo "Verificacion OK"
    else
        echo "AVISO: Errores en la configuracion generada"
    fi
fi
EOF
    chmod 755 /usr/local/bin/generar-split-dns.sh
    log_change "Creado" "/usr/local/bin/generar-split-dns.sh"

else
    log_skip "Split-horizon DNS"
fi

# ============================================================
# S9: MONITORIZACION DNS
# ============================================================
log_section "S9: MONITORIZACION DNS"

echo "Configura monitorizacion continua de DNS:"
echo "  - Script /usr/local/bin/monitorear-dns.sh"
echo "  - Tiempos de resolucion"
echo "  - Alertas de fallos"
echo "  - Deteccion de hijacking DNS"
echo "  - Servicio systemd"
echo ""

if check_file_exists /usr/local/bin/monitorear-dns.sh; then
    log_already "Monitorizacion DNS (monitorear-dns.sh existe)"
elif ask "Configurar monitorizacion DNS?"; then

    # --- Script de monitorizacion DNS ---
    cat > /usr/local/bin/monitorear-dns.sh << 'EOF'
#!/bin/bash
# ============================================================
# monitorear-dns.sh - Monitorizacion continua de DNS
# Generado por securizar - Modulo 65
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

LOGFILE="/var/log/securizar/dns-monitor.log"
ALERT_LOG="/var/log/securizar/dns-monitor-alerts.log"
POLICY_CONF="/etc/securizar/dns-security-policy.conf"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Cargar politica si existe
MONITOR_INTERVAL=300
ALERT_THRESHOLD_MS=2000
HIJACK_DETECTION=yes

if [[ -f "$POLICY_CONF" ]]; then
    MONITOR_INTERVAL=$(grep "^DNS_MONITOR_INTERVAL=" "$POLICY_CONF" 2>/dev/null | cut -d= -f2 || echo "300")
    ALERT_THRESHOLD_MS=$(grep "^DNS_ALERT_THRESHOLD_MS=" "$POLICY_CONF" 2>/dev/null | cut -d= -f2 || echo "2000")
    HIJACK_DETECTION=$(grep "^DNS_HIJACK_DETECTION=" "$POLICY_CONF" 2>/dev/null | cut -d= -f2 || echo "yes")
fi

mkdir -p "$(dirname "$LOGFILE")" "$(dirname "$ALERT_LOG")"

MODE="${1:-once}"

log_msg() {
    echo "$TIMESTAMP $1" >> "$LOGFILE"
}

log_alert_msg() {
    local msg="$1"
    echo "$TIMESTAMP [ALERTA] $msg" >> "$ALERT_LOG"
    echo "$TIMESTAMP [ALERTA] $msg" >> "$LOGFILE"
    # Enviar a syslog
    logger -t securizar-dns-monitor "ALERTA: $msg" 2>/dev/null || true
}

# --- Dominios de test ---
TEST_DOMAINS=(
    "example.com"
    "google.com"
    "cloudflare.com"
    "quad9.net"
    "github.com"
)

# --- IPs conocidas para deteccion de hijacking ---
declare -A KNOWN_IPS
KNOWN_IPS["example.com"]="93.184.216.34"
KNOWN_IPS["one.one.one.one"]="1.1.1.1"

# --- Funcion de test de resolucion ---
test_resolution() {
    local domain="$1"
    local start_ms end_ms elapsed_ms result_ip

    if command -v dig &>/dev/null; then
        start_ms=$(date +%s%N)
        result_ip=$(dig +short +time=5 +tries=1 "$domain" A 2>/dev/null | head -1 || true)
        end_ms=$(date +%s%N)
        elapsed_ms=$(( (end_ms - start_ms) / 1000000 ))
    elif command -v nslookup &>/dev/null; then
        start_ms=$(date +%s%N)
        result_ip=$(nslookup "$domain" 2>/dev/null | grep -A1 "Name:" | grep "Address:" | awk '{print $2}' | head -1 || true)
        end_ms=$(date +%s%N)
        elapsed_ms=$(( (end_ms - start_ms) / 1000000 ))
    elif command -v host &>/dev/null; then
        start_ms=$(date +%s%N)
        result_ip=$(host -t A "$domain" 2>/dev/null | grep "has address" | awk '{print $NF}' | head -1 || true)
        end_ms=$(date +%s%N)
        elapsed_ms=$(( (end_ms - start_ms) / 1000000 ))
    else
        echo "ERROR:0:no_resolver"
        return
    fi

    if [[ -z "$result_ip" ]]; then
        echo "FAIL:0:no_response"
    else
        echo "OK:${elapsed_ms}:${result_ip}"
    fi
}

# --- Ejecutar checks ---
run_checks() {
    local total_tests=0
    local failed_tests=0
    local slow_tests=0
    local hijack_alerts=0

    log_msg "=== Inicio monitorizacion DNS ==="

    for domain in "${TEST_DOMAINS[@]}"; do
        ((total_tests++)) || true
        RESULT=$(test_resolution "$domain")
        STATUS=$(echo "$RESULT" | cut -d: -f1)
        TIME_MS=$(echo "$RESULT" | cut -d: -f2)
        IP=$(echo "$RESULT" | cut -d: -f3)

        if [[ "$STATUS" == "FAIL" ]]; then
            ((failed_tests++)) || true
            log_msg "[FAIL] $domain - Sin respuesta"
            log_alert_msg "Fallo de resolucion DNS: $domain"
            if [[ "$MODE" == "once" ]]; then
                echo -e "${RED}[FAIL]${NC} $domain - Sin respuesta"
            fi
        elif [[ "$STATUS" == "ERROR" ]]; then
            log_msg "[ERROR] $domain - Sin resolver DNS disponible"
            if [[ "$MODE" == "once" ]]; then
                echo -e "${RED}[ERROR]${NC} $domain - Sin resolver disponible"
            fi
        else
            # Verificar tiempo
            if [[ "$TIME_MS" -gt "$ALERT_THRESHOLD_MS" ]]; then
                ((slow_tests++)) || true
                log_msg "[SLOW] $domain - ${TIME_MS}ms (umbral: ${ALERT_THRESHOLD_MS}ms) -> $IP"
                log_alert_msg "Resolucion DNS lenta: $domain (${TIME_MS}ms)"
                if [[ "$MODE" == "once" ]]; then
                    echo -e "${YELLOW}[SLOW]${NC} $domain - ${TIME_MS}ms -> $IP"
                fi
            else
                log_msg "[OK] $domain - ${TIME_MS}ms -> $IP"
                if [[ "$MODE" == "once" ]]; then
                    echo -e "${GREEN}[OK]${NC} $domain - ${TIME_MS}ms -> $IP"
                fi
            fi

            # Deteccion de hijacking
            if [[ "$HIJACK_DETECTION" == "yes" ]]; then
                EXPECTED_IP="${KNOWN_IPS[$domain]:-}"
                if [[ -n "$EXPECTED_IP" && "$IP" != "$EXPECTED_IP" ]]; then
                    ((hijack_alerts++)) || true
                    log_alert_msg "POSIBLE HIJACKING DNS: $domain resuelve a $IP (esperado: $EXPECTED_IP)"
                    if [[ "$MODE" == "once" ]]; then
                        echo -e "${RED}[HIJACK]${NC} $domain -> $IP (esperado: $EXPECTED_IP)"
                    fi
                fi
            fi
        fi
    done

    # --- Verificar resolver local ---
    RESOLVER_STATUS="OK"
    if [[ -f /etc/resolv.conf ]]; then
        NAMESERVERS=$(grep "^nameserver" /etc/resolv.conf | awk '{print $2}')
        for ns in $NAMESERVERS; do
            if ! timeout 3 dig +short @"$ns" example.com A &>/dev/null; then
                RESOLVER_STATUS="FAIL"
                log_alert_msg "Nameserver inaccesible: $ns"
                if [[ "$MODE" == "once" ]]; then
                    echo -e "${RED}[FAIL]${NC} Nameserver inaccesible: $ns"
                fi
            fi
        done
    fi

    log_msg "Resumen: total=$total_tests fallos=$failed_tests lentos=$slow_tests hijacking=$hijack_alerts resolver=$RESOLVER_STATUS"

    if [[ "$MODE" == "once" ]]; then
        echo ""
        echo -e "${CYAN}Resumen: $total_tests tests | $failed_tests fallos | $slow_tests lentos | $hijack_alerts hijack${NC}"
    fi
}

# --- Modo de ejecucion ---
case "$MODE" in
    once)
        echo -e "${CYAN}=== Monitorizacion DNS ===${NC}"
        run_checks
        ;;
    daemon)
        log_msg "Modo daemon iniciado (intervalo: ${MONITOR_INTERVAL}s)"
        while true; do
            run_checks
            sleep "$MONITOR_INTERVAL"
        done
        ;;
    *)
        echo "Uso: $0 [once|daemon]"
        echo "  once   - Ejecuta una sola vez (por defecto)"
        echo "  daemon - Ejecuta en bucle continuo"
        exit 1
        ;;
esac
EOF
    chmod 755 /usr/local/bin/monitorear-dns.sh
    log_change "Creado" "/usr/local/bin/monitorear-dns.sh"

    # --- Servicio systemd para monitorizacion ---
    cat > /etc/systemd/system/securizar-dns-monitor.service << 'EOF'
[Unit]
Description=Securizar DNS Monitor - Modulo 65
After=network-online.target
Wants=network-online.target
Documentation=man:securizar(8)

[Service]
Type=simple
ExecStart=/usr/local/bin/monitorear-dns.sh daemon
Restart=on-failure
RestartSec=30
User=root
StandardOutput=journal
StandardError=journal
SyslogIdentifier=securizar-dns-monitor

# Hardening del servicio
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/log/securizar

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 /etc/systemd/system/securizar-dns-monitor.service
    log_change "Creado" "Servicio systemd securizar-dns-monitor"

    # Timer para ejecucion periodica (alternativa al daemon)
    cat > /etc/systemd/system/securizar-dns-monitor.timer << 'EOF'
[Unit]
Description=Timer para monitorizacion DNS - securizar Modulo 65

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s

[Install]
WantedBy=timers.target
EOF
    chmod 644 /etc/systemd/system/securizar-dns-monitor.timer

    # Crear servicio oneshot para el timer
    cat > /etc/systemd/system/securizar-dns-monitor-check.service << 'EOF'
[Unit]
Description=Securizar DNS Monitor Check - Modulo 65
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/monitorear-dns.sh once
User=root
StandardOutput=journal
StandardError=journal
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/log/securizar
EOF
    chmod 644 /etc/systemd/system/securizar-dns-monitor-check.service

    systemctl daemon-reload 2>/dev/null || true

    if ask "Habilitar servicio de monitorizacion DNS?"; then
        systemctl enable securizar-dns-monitor.timer 2>/dev/null || true
        systemctl start securizar-dns-monitor.timer 2>/dev/null || true
        log_change "Habilitado" "Timer securizar-dns-monitor"
    else
        log_skip "Habilitacion del servicio de monitorizacion DNS"
    fi

    # Logrotate
    cat > /etc/logrotate.d/securizar-dns-monitor << 'EOF'
/var/log/securizar/dns-monitor.log
/var/log/securizar/dns-monitor-alerts.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}
EOF
    chmod 644 /etc/logrotate.d/securizar-dns-monitor
    log_change "Creado" "Logrotate para DNS monitor"

else
    log_skip "Monitorizacion DNS"
fi

# ============================================================
# S10: AUDITORIA DNS AVANZADA
# ============================================================
log_section "S10: AUDITORIA DNS AVANZADA"

echo "Configura auditoria completa de seguridad DNS:"
echo "  - Script /usr/local/bin/auditar-dns-avanzado.sh"
echo "  - Sistema de puntuacion"
echo "  - Cron semanal"
echo ""

if check_file_exists /usr/local/bin/auditar-dns-avanzado.sh; then
    log_already "Auditoria DNS avanzada (auditar-dns-avanzado.sh existe)"
elif ask "Configurar auditoria DNS avanzada?"; then

    # --- Script de auditoria DNS ---
    cat > /usr/local/bin/auditar-dns-avanzado.sh << 'EOF'
#!/bin/bash
# ============================================================
# auditar-dns-avanzado.sh - Auditoria completa de seguridad DNS
# Generado por securizar - Modulo 65
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

LOGFILE="/var/log/securizar/dns-audit.log"
REPORT="/var/log/securizar/dns-audit-report-$(date +%Y%m%d).txt"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

SCORE=0
TOTAL=0
CATEGORY_SCORES=()

mkdir -p "$(dirname "$LOGFILE")"

# --- Funciones ---
check() {
    local category="$1" desc="$2" result="$3" weight="${4:-1}"
    ((TOTAL += weight)) || true
    if [[ "$result" == "PASS" ]]; then
        echo -e "${GREEN}[PASS]${NC} [$category] $desc"
        echo "[PASS] [$category] $desc" >> "$REPORT"
        ((SCORE += weight)) || true
    elif [[ "$result" == "WARN" ]]; then
        echo -e "${YELLOW}[WARN]${NC} [$category] $desc"
        echo "[WARN] [$category] $desc" >> "$REPORT"
        local half=$(( weight / 2 ))
        ((SCORE += half)) || true
    else
        echo -e "${RED}[FAIL]${NC} [$category] $desc"
        echo "[FAIL] [$category] $desc" >> "$REPORT"
    fi
}

section() {
    echo ""
    echo -e "${CYAN}${BOLD}--- $1 ---${NC}"
    echo "" >> "$REPORT"
    echo "--- $1 ---" >> "$REPORT"
}

# --- Inicio ---
{
    echo "============================================================"
    echo "AUDITORIA DE SEGURIDAD DNS AVANZADA"
    echo "Fecha: $TIMESTAMP"
    echo "Host: $(hostname -f 2>/dev/null || hostname)"
    echo "============================================================"
} > "$REPORT"

echo -e "${CYAN}${BOLD}============================================================${NC}"
echo -e "${CYAN}${BOLD}  AUDITORIA DE SEGURIDAD DNS AVANZADA${NC}"
echo -e "${CYAN}${BOLD}  Fecha: $TIMESTAMP${NC}"
echo -e "${CYAN}${BOLD}============================================================${NC}"

# ============================================================
# Categoria 1: DNSSEC
# ============================================================
section "1. VALIDACION DNSSEC"

# 1.1 DNSSEC habilitado en resolved
if [[ -f /etc/systemd/resolved.conf ]]; then
    if grep -q "^DNSSEC=yes" /etc/systemd/resolved.conf 2>/dev/null; then
        check "DNSSEC" "systemd-resolved DNSSEC=yes" "PASS" 2
    elif grep -q "^DNSSEC=allow-downgrade" /etc/systemd/resolved.conf 2>/dev/null; then
        check "DNSSEC" "systemd-resolved DNSSEC=allow-downgrade" "WARN" 2
    else
        check "DNSSEC" "systemd-resolved DNSSEC habilitado" "FAIL" 2
    fi
else
    check "DNSSEC" "systemd-resolved.conf existe" "FAIL" 2
fi

# 1.2 Trust anchors
if [[ -f /etc/dnssec-trust-anchors.d/root.key ]] || \
   [[ -f /usr/share/dns/root.key ]] || \
   [[ -f /etc/unbound/root.key ]]; then
    check "DNSSEC" "Trust anchor root.key presente" "PASS" 1
else
    check "DNSSEC" "Trust anchor root.key presente" "FAIL" 1
fi

# 1.3 Test de validacion real
if command -v dig &>/dev/null; then
    DNSSEC_VALID=$(dig +dnssec +short dnssec.works A 2>/dev/null || true)
    if [[ -n "$DNSSEC_VALID" ]]; then
        check "DNSSEC" "Validacion DNSSEC funcional (dnssec.works)" "PASS" 2
    else
        check "DNSSEC" "Validacion DNSSEC funcional" "FAIL" 2
    fi

    DNSSEC_FAIL=$(dig +dnssec +short fail01.dnssec.works A 2>/dev/null || true)
    if [[ -z "$DNSSEC_FAIL" ]]; then
        check "DNSSEC" "Rechazo DNSSEC invalido (fail01.dnssec.works)" "PASS" 2
    else
        check "DNSSEC" "Rechazo DNSSEC invalido" "FAIL" 2
    fi
fi

# 1.4 Script de verificacion existe
if [[ -x /usr/local/bin/verificar-dnssec.sh ]]; then
    check "DNSSEC" "Script verificar-dnssec.sh presente" "PASS" 1
else
    check "DNSSEC" "Script verificar-dnssec.sh presente" "FAIL" 1
fi

# ============================================================
# Categoria 2: DNS-over-TLS
# ============================================================
section "2. DNS-OVER-TLS"

# 2.1 DoT habilitado
if [[ -f /etc/systemd/resolved.conf ]]; then
    if grep -q "^DNSOverTLS=yes" /etc/systemd/resolved.conf 2>/dev/null; then
        check "DoT" "DNSOverTLS=yes en resolved.conf" "PASS" 2
    elif grep -q "^DNSOverTLS=opportunistic" /etc/systemd/resolved.conf 2>/dev/null; then
        check "DoT" "DNSOverTLS=opportunistic (no estricto)" "WARN" 2
    else
        check "DoT" "DNSOverTLS habilitado" "FAIL" 2
    fi
fi

# 2.2 Servidores DoT configurados
if [[ -f /etc/systemd/resolved.conf ]]; then
    DNS_LINE=$(grep "^DNS=" /etc/systemd/resolved.conf 2>/dev/null || true)
    if echo "$DNS_LINE" | grep -q "#" 2>/dev/null; then
        check "DoT" "Servidores DNS con hostname TLS configurados" "PASS" 1
    else
        check "DoT" "Servidores DNS con hostname TLS" "FAIL" 1
    fi
fi

# 2.3 Conectividad DoT
for server in 1.1.1.1 8.8.8.8 9.9.9.9; do
    if timeout 5 bash -c "echo | openssl s_client -connect ${server}:853 2>/dev/null" | grep -q "CONNECTED" 2>/dev/null; then
        check "DoT" "Conectividad TLS a $server:853" "PASS" 1
        break
    fi
done

# 2.4 Puerto 53 saliente bloqueado
P53_BLOCKED=false
case "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" in
    *)
        if command -v iptables &>/dev/null; then
            if iptables -L OUTPUT -n 2>/dev/null | grep -q "dpt:53.*DROP" 2>/dev/null; then
                P53_BLOCKED=true
            fi
        fi
        if command -v nft &>/dev/null; then
            if nft list ruleset 2>/dev/null | grep -q "dport 53 drop" 2>/dev/null; then
                P53_BLOCKED=true
            fi
        fi
        ;;
esac
if [[ "$P53_BLOCKED" == true ]]; then
    check "DoT" "Puerto 53 saliente bloqueado" "PASS" 2
else
    check "DoT" "Puerto 53 saliente bloqueado" "WARN" 2
fi

# ============================================================
# Categoria 3: DNS-over-HTTPS
# ============================================================
section "3. DNS-OVER-HTTPS"

if command -v stubby &>/dev/null; then
    check "DoH" "Stubby resolver instalado" "PASS" 1
    if systemctl is-active stubby &>/dev/null 2>&1; then
        check "DoH" "Stubby activo" "PASS" 1
    else
        check "DoH" "Stubby activo" "WARN" 1
    fi
else
    check "DoH" "Stubby resolver instalado" "WARN" 1
fi

if [[ -f /etc/securizar/dns/doh-setup.conf ]]; then
    check "DoH" "Configuracion DoH documentada" "PASS" 1
else
    check "DoH" "Configuracion DoH documentada" "FAIL" 1
fi

# ============================================================
# Categoria 4: Unbound
# ============================================================
section "4. UNBOUND RESOLVER"

if command -v unbound &>/dev/null; then
    check "Unbound" "Unbound instalado" "PASS" 1

    if systemctl is-active unbound &>/dev/null 2>&1; then
        check "Unbound" "Unbound activo" "PASS" 1
    else
        check "Unbound" "Unbound activo" "FAIL" 1
    fi

    UNBOUND_SEC="/etc/unbound/unbound.conf.d/securizar.conf"
    if [[ -f "$UNBOUND_SEC" ]]; then
        check "Unbound" "Configuracion securizar presente" "PASS" 1

        if grep -q "hide-identity: yes" "$UNBOUND_SEC" 2>/dev/null; then
            check "Unbound" "hide-identity habilitado" "PASS" 1
        else
            check "Unbound" "hide-identity habilitado" "FAIL" 1
        fi

        if grep -q "hide-version: yes" "$UNBOUND_SEC" 2>/dev/null; then
            check "Unbound" "hide-version habilitado" "PASS" 1
        else
            check "Unbound" "hide-version habilitado" "FAIL" 1
        fi

        if grep -q "qname-minimisation: yes" "$UNBOUND_SEC" 2>/dev/null; then
            check "Unbound" "QNAME minimization habilitado" "PASS" 2
        else
            check "Unbound" "QNAME minimization habilitado" "FAIL" 2
        fi

        if grep -q "aggressive-nsec: yes" "$UNBOUND_SEC" 2>/dev/null; then
            check "Unbound" "Aggressive NSEC habilitado" "PASS" 1
        else
            check "Unbound" "Aggressive NSEC habilitado" "FAIL" 1
        fi

        if grep -q "use-caps-for-id: yes" "$UNBOUND_SEC" 2>/dev/null; then
            check "Unbound" "0x20 encoding habilitado" "PASS" 1
        else
            check "Unbound" "0x20 encoding habilitado" "FAIL" 1
        fi

        if grep -q "harden-glue: yes" "$UNBOUND_SEC" 2>/dev/null; then
            check "Unbound" "harden-glue habilitado" "PASS" 1
        else
            check "Unbound" "harden-glue habilitado" "FAIL" 1
        fi

        if grep -q "ratelimit:" "$UNBOUND_SEC" 2>/dev/null; then
            check "Unbound" "Rate limiting configurado" "PASS" 1
        else
            check "Unbound" "Rate limiting configurado" "FAIL" 1
        fi
    else
        check "Unbound" "Configuracion securizar presente" "FAIL" 1
    fi
else
    check "Unbound" "Unbound instalado" "FAIL" 1
fi

# ============================================================
# Categoria 5: DNS Sinkhole / RPZ
# ============================================================
section "5. DNS SINKHOLE / RPZ"

if [[ -x /usr/local/bin/actualizar-dns-blocklist.sh ]]; then
    check "Sinkhole" "Script de actualizacion presente" "PASS" 1
else
    check "Sinkhole" "Script de actualizacion presente" "FAIL" 1
fi

if [[ -f /etc/securizar/dns/blocklists/combined-blocklist.txt ]]; then
    BLOCK_COUNT=$(wc -l < /etc/securizar/dns/blocklists/combined-blocklist.txt 2>/dev/null || echo "0")
    if [[ "$BLOCK_COUNT" -gt 1000 ]]; then
        check "Sinkhole" "Blocklist activa: $BLOCK_COUNT dominios" "PASS" 2
    elif [[ "$BLOCK_COUNT" -gt 0 ]]; then
        check "Sinkhole" "Blocklist reducida: $BLOCK_COUNT dominios" "WARN" 2
    else
        check "Sinkhole" "Blocklist vacia" "FAIL" 2
    fi
else
    check "Sinkhole" "Blocklist presente" "FAIL" 2
fi

if [[ -f /etc/cron.daily/securizar-dns-blocklist ]]; then
    check "Sinkhole" "Cron de actualizacion diario" "PASS" 1
else
    check "Sinkhole" "Cron de actualizacion diario" "FAIL" 1
fi

if [[ -f /etc/securizar/dns/whitelist.conf ]]; then
    check "Sinkhole" "Whitelist configurada" "PASS" 1
else
    check "Sinkhole" "Whitelist configurada" "WARN" 1
fi

# ============================================================
# Categoria 6: DNS Tunneling Detection
# ============================================================
section "6. DETECCION DNS TUNNELING"

if [[ -x /usr/local/bin/detectar-dns-tunneling.sh ]]; then
    check "Tunneling" "Script de deteccion presente" "PASS" 1
else
    check "Tunneling" "Script de deteccion presente" "FAIL" 1
fi

# Verificar herramientas de tunneling
for tool in iodine iodined dnscat2 dns2tcp; do
    if command -v "$tool" &>/dev/null; then
        check "Tunneling" "Herramienta $tool NO instalada" "FAIL" 2
    fi
done

if command -v suricata &>/dev/null; then
    if [[ -f /etc/suricata/rules/securizar-dns-tunneling.rules ]]; then
        check "Tunneling" "Reglas Suricata para DNS tunneling" "PASS" 2
    else
        check "Tunneling" "Reglas Suricata para DNS tunneling" "FAIL" 2
    fi
elif [[ -f /etc/securizar/dns/suricata-rules/dns-tunneling.rules ]]; then
    check "Tunneling" "Reglas Suricata (referencia, IDS no instalado)" "WARN" 2
else
    check "Tunneling" "Reglas IDS para DNS tunneling" "FAIL" 2
fi

# ============================================================
# Categoria 7: Cache Poisoning Protection
# ============================================================
section "7. PROTECCION CACHE POISONING"

# Source port randomization
PORTS=$(cat /proc/sys/net/ipv4/ip_local_port_range 2>/dev/null || echo "0 0")
LOW_PORT=$(echo "$PORTS" | awk '{print $1}')
HIGH_PORT=$(echo "$PORTS" | awk '{print $2}')
PORT_RANGE=$(( HIGH_PORT - LOW_PORT ))
if [[ $PORT_RANGE -ge 16000 ]]; then
    check "Poisoning" "Rango de puertos efimeros amplio ($PORT_RANGE)" "PASS" 2
else
    check "Poisoning" "Rango de puertos efimeros ($PORT_RANGE)" "FAIL" 2
fi

# Reverse path filtering
RPF=$(cat /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null || echo "0")
if [[ "$RPF" == "1" ]]; then
    check "Poisoning" "Reverse path filtering activo" "PASS" 1
else
    check "Poisoning" "Reverse path filtering activo" "FAIL" 1
fi

# ICMP redirects
REDIR=$(cat /proc/sys/net/ipv4/conf/all/accept_redirects 2>/dev/null || echo "1")
if [[ "$REDIR" == "0" ]]; then
    check "Poisoning" "ICMP redirects deshabilitados" "PASS" 1
else
    check "Poisoning" "ICMP redirects deshabilitados" "FAIL" 1
fi

if [[ -f /etc/sysctl.d/90-securizar-dns.conf ]]; then
    check "Poisoning" "Sysctl anti-poisoning configurado" "PASS" 1
else
    check "Poisoning" "Sysctl anti-poisoning configurado" "FAIL" 1
fi

if [[ -x /usr/local/bin/test-cache-poisoning.sh ]]; then
    check "Poisoning" "Script de test presente" "PASS" 1
else
    check "Poisoning" "Script de test presente" "FAIL" 1
fi

# ============================================================
# Categoria 8: Split-Horizon
# ============================================================
section "8. SPLIT-HORIZON DNS"

if [[ -f /etc/securizar/split-dns-zones.conf ]]; then
    check "Split-DNS" "Configuracion de zonas presente" "PASS" 1
else
    check "Split-DNS" "Configuracion de zonas presente" "WARN" 1
fi

if [[ -f /etc/unbound/unbound.conf.d/securizar-split-dns.conf ]]; then
    check "Split-DNS" "Configuracion Unbound split-DNS" "PASS" 1
else
    check "Split-DNS" "Configuracion Unbound split-DNS" "WARN" 1
fi

if [[ -x /usr/local/bin/generar-split-dns.sh ]]; then
    check "Split-DNS" "Generador de configuracion presente" "PASS" 1
else
    check "Split-DNS" "Generador de configuracion presente" "WARN" 1
fi

# ============================================================
# Categoria 9: Monitorizacion
# ============================================================
section "9. MONITORIZACION DNS"

if [[ -x /usr/local/bin/monitorear-dns.sh ]]; then
    check "Monitor" "Script de monitorizacion presente" "PASS" 1
else
    check "Monitor" "Script de monitorizacion presente" "FAIL" 1
fi

if systemctl is-active securizar-dns-monitor.timer &>/dev/null 2>&1; then
    check "Monitor" "Timer de monitorizacion activo" "PASS" 2
elif systemctl is-enabled securizar-dns-monitor.timer &>/dev/null 2>&1; then
    check "Monitor" "Timer de monitorizacion habilitado" "WARN" 2
else
    check "Monitor" "Timer de monitorizacion" "FAIL" 2
fi

if [[ -f /etc/logrotate.d/securizar-dns-monitor ]]; then
    check "Monitor" "Logrotate configurado" "PASS" 1
else
    check "Monitor" "Logrotate configurado" "FAIL" 1
fi

# ============================================================
# Categoria 10: Politica general
# ============================================================
section "10. POLITICA Y CONFIGURACION GENERAL"

if [[ -f /etc/securizar/dns-security-policy.conf ]]; then
    check "Politica" "Politica de seguridad DNS presente" "PASS" 1
else
    check "Politica" "Politica de seguridad DNS presente" "FAIL" 1
fi

# Verificar resolv.conf no tiene servidores publicos sin cifrar
if [[ -f /etc/resolv.conf ]]; then
    PUBLIC_UNENCRYPTED=false
    while IFS= read -r line; do
        ns=$(echo "$line" | awk '{print $2}')
        case "$ns" in
            127.*|::1|10.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|192.168.*) ;;
            *)
                PUBLIC_UNENCRYPTED=true
                ;;
        esac
    done < <(grep "^nameserver" /etc/resolv.conf 2>/dev/null)
    if [[ "$PUBLIC_UNENCRYPTED" == false ]]; then
        check "Politica" "resolv.conf solo usa resolvers locales" "PASS" 2
    else
        check "Politica" "resolv.conf contiene resolvers publicos directos" "WARN" 2
    fi
fi

# Verificar permisos de archivos de configuracion
for f in /etc/securizar/dns-security-policy.conf /etc/securizar/split-dns-zones.conf; do
    if [[ -f "$f" ]]; then
        PERMS=$(stat -c '%a' "$f" 2>/dev/null || echo "777")
        if [[ "${PERMS:2:1}" =~ [0145] ]]; then
            check "Politica" "Permisos seguros en $f ($PERMS)" "PASS" 1
        else
            check "Politica" "Permisos inseguros en $f ($PERMS)" "FAIL" 1
        fi
    fi
done

# ============================================================
# RESUMEN FINAL
# ============================================================
echo ""
echo -e "${CYAN}${BOLD}============================================================${NC}"
echo -e "${CYAN}${BOLD}  RESUMEN DE AUDITORIA DNS${NC}"
echo -e "${CYAN}${BOLD}============================================================${NC}"

if [[ $TOTAL -gt 0 ]]; then
    PCT=$(( SCORE * 100 / TOTAL ))
else
    PCT=0
fi

echo -e "${BOLD}Puntuacion: ${SCORE}/${TOTAL} (${PCT}%)${NC}"
echo "" >> "$REPORT"
echo "============================================================" >> "$REPORT"
echo "PUNTUACION FINAL: ${SCORE}/${TOTAL} (${PCT}%)" >> "$REPORT"

if [[ $PCT -ge 90 ]]; then
    GRADE="A"
    echo -e "${GREEN}${BOLD}Calificacion: A - Excelente${NC}"
    echo "Calificacion: A - Excelente" >> "$REPORT"
elif [[ $PCT -ge 80 ]]; then
    GRADE="B"
    echo -e "${GREEN}Calificacion: B - Bueno${NC}"
    echo "Calificacion: B - Bueno" >> "$REPORT"
elif [[ $PCT -ge 70 ]]; then
    GRADE="C"
    echo -e "${YELLOW}Calificacion: C - Aceptable${NC}"
    echo "Calificacion: C - Aceptable" >> "$REPORT"
elif [[ $PCT -ge 50 ]]; then
    GRADE="D"
    echo -e "${YELLOW}${BOLD}Calificacion: D - Mejorable${NC}"
    echo "Calificacion: D - Mejorable" >> "$REPORT"
else
    GRADE="F"
    echo -e "${RED}${BOLD}Calificacion: F - Insuficiente${NC}"
    echo "Calificacion: F - Insuficiente" >> "$REPORT"
fi

echo ""
echo -e "Reporte completo: ${CYAN}$REPORT${NC}"
echo "Reporte generado: $REPORT" >> "$LOGFILE"
echo "============================================================" >> "$REPORT"
echo "Fin de auditoria: $(date '+%Y-%m-%d %H:%M:%S')" >> "$REPORT"
EOF
    chmod 755 /usr/local/bin/auditar-dns-avanzado.sh
    log_change "Creado" "/usr/local/bin/auditar-dns-avanzado.sh"

    # --- Cron semanal ---
    CRON_AUDIT="/etc/cron.weekly/securizar-dns-audit"
    cat > "$CRON_AUDIT" << 'EOF'
#!/bin/bash
# Auditoria semanal de seguridad DNS - securizar Modulo 65
/usr/local/bin/auditar-dns-avanzado.sh >> /var/log/securizar/dns-audit.log 2>&1
EOF
    chmod 755 "$CRON_AUDIT"
    log_change "Creado" "Cron semanal: $CRON_AUDIT"

else
    log_skip "Auditoria DNS avanzada"
fi

# ============================================================
# RESUMEN FINAL DEL MODULO
# ============================================================
log_section "MODULO 65 COMPLETADO"

log_info "Seguridad DNS avanzada configurada"
log_info "Scripts de verificacion:"
log_info "  - /usr/local/bin/verificar-dnssec.sh"
log_info "  - /usr/local/bin/verificar-dot.sh"
log_info "  - /usr/local/bin/actualizar-dns-blocklist.sh"
log_info "  - /usr/local/bin/detectar-dns-tunneling.sh"
log_info "  - /usr/local/bin/test-cache-poisoning.sh"
log_info "  - /usr/local/bin/generar-split-dns.sh"
log_info "  - /usr/local/bin/monitorear-dns.sh"
log_info "  - /usr/local/bin/auditar-dns-avanzado.sh"
log_info ""
log_info "Configuraciones:"
log_info "  - /etc/securizar/dns-security-policy.conf"
log_info "  - /etc/securizar/split-dns-zones.conf"
log_info "  - /etc/securizar/dns/whitelist.conf"
log_info ""
log_info "Para ejecutar auditoria completa:"
log_info "  sudo auditar-dns-avanzado.sh"

show_changes_summary
