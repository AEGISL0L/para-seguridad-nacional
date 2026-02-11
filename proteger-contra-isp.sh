#!/bin/bash
# ============================================================
# PROTECCIÓN CONTRA ESPIONAJE ISP - Módulo 38
# Linux Multi-Distro (openSUSE, Debian/Ubuntu, RHEL/Fedora, Arch)
# ============================================================
# Protege contra vigilancia a nivel de ISP:
#   - Kill switch VPN (iptables DROP si cae la VPN)
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
echo -e "  ${CYAN}S1${NC}  VPN Kill Switch (iptables, no tráfico sin VPN)"
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

echo "Crea reglas iptables que bloquean TODO tráfico si la VPN cae."
echo "Permite: loopback, LAN, DHCP, interfaces VPN (wg0/tun0)."
echo ""

if ask "¿Configurar VPN Kill Switch?"; then

    # Script para activar kill switch
    cat > "${ISP_CONF_DIR}/vpn-killswitch.sh" << 'KILLSWITCH_ON'
#!/bin/bash
# VPN Kill Switch - Activar
# Bloquea todo tráfico que no pase por VPN (wg0/tun0)
set -euo pipefail

CHAIN="SECURIZAR_KS"

# Limpiar cadena previa si existe
iptables -D OUTPUT -j "$CHAIN" 2>/dev/null || true
iptables -F "$CHAIN" 2>/dev/null || true
iptables -X "$CHAIN" 2>/dev/null || true

# Crear cadena
iptables -N "$CHAIN"

# Permitir loopback
iptables -A "$CHAIN" -o lo -j ACCEPT

# Permitir LAN (RFC1918)
iptables -A "$CHAIN" -d 10.0.0.0/8 -j ACCEPT
iptables -A "$CHAIN" -d 172.16.0.0/12 -j ACCEPT
iptables -A "$CHAIN" -d 192.168.0.0/16 -j ACCEPT

# Permitir DHCP
iptables -A "$CHAIN" -p udp --dport 67:68 -j ACCEPT

# Permitir interfaz VPN
iptables -A "$CHAIN" -o wg0 -j ACCEPT
iptables -A "$CHAIN" -o tun0 -j ACCEPT
iptables -A "$CHAIN" -o tun+ -j ACCEPT

# Permitir conexiones ya establecidas
iptables -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# DROP todo lo demás
iptables -A "$CHAIN" -j DROP

# Insertar en OUTPUT
iptables -I OUTPUT -j "$CHAIN"

echo "[+] VPN Kill Switch ACTIVADO - tráfico sin VPN bloqueado"
KILLSWITCH_ON
    chmod 700 "${ISP_CONF_DIR}/vpn-killswitch.sh"
    log_change "Creado" "${ISP_CONF_DIR}/vpn-killswitch.sh"

    # Script para desactivar kill switch
    cat > "${ISP_CONF_DIR}/vpn-killswitch-off.sh" << 'KILLSWITCH_OFF'
#!/bin/bash
# VPN Kill Switch - Desactivar
set -euo pipefail

CHAIN="SECURIZAR_KS"

iptables -D OUTPUT -j "$CHAIN" 2>/dev/null || true
iptables -F "$CHAIN" 2>/dev/null || true
iptables -X "$CHAIN" 2>/dev/null || true

echo "[+] VPN Kill Switch DESACTIVADO - tráfico normal restaurado"
KILLSWITCH_OFF
    chmod 700 "${ISP_CONF_DIR}/vpn-killswitch-off.sh"
    log_change "Creado" "${ISP_CONF_DIR}/vpn-killswitch-off.sh"

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
# S2 — PREVENCIÓN DE FUGAS DNS
# ============================================================
log_section "S2: PREVENCIÓN DE FUGAS DNS"

echo "Refuerza DNS-over-TLS a modo ESTRICTO con DNSSEC."
echo "Bloquea puerto 53 saliente excepto por VPN/localhost."
echo "Desactiva mDNS y LLMNR."
echo ""

if ask "¿Configurar prevención de fugas DNS?"; then

    # Configurar resolved en modo estricto
    mkdir -p /etc/systemd/resolved.conf.d
    cat > /etc/systemd/resolved.conf.d/02-isp-dns-leak-prevention.conf << 'DNS_CONF'
# Securizar Módulo 38 - Prevención de fugas DNS ISP
[Resolve]
# DNS-over-TLS estricto (falla si no hay TLS, no cae a plaintext)
DNSOverTLS=yes
DNSSEC=yes

# Servidores DNS con soporte DoT
DNS=1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com 9.9.9.9#dns.quad9.net
FallbackDNS=8.8.8.8#dns.google 8.8.4.4#dns.google

# Desactivar protocolos de descubrimiento local (fugas)
MulticastDNS=no
LLMNR=no

# Dominios: usar DoT para todo
Domains=~.
DNS_CONF
    log_change "Creado" "/etc/systemd/resolved.conf.d/02-isp-dns-leak-prevention.conf"

    # Reiniciar resolved
    systemctl restart systemd-resolved 2>/dev/null || true
    log_change "Servicio" "systemd-resolved reiniciado"

    # Bloquear puerto 53 saliente excepto VPN/localhost
    if ! iptables -C OUTPUT -o lo -p udp --dport 53 -j ACCEPT 2>/dev/null; then
        iptables -A OUTPUT -o lo -p udp --dport 53 -j ACCEPT
        iptables -A OUTPUT -o lo -p tcp --dport 53 -j ACCEPT
    fi
    # Permitir DNS por VPN
    for vpn_iface in wg0 tun0; do
        if ! iptables -C OUTPUT -o "$vpn_iface" -p udp --dport 53 -j ACCEPT 2>/dev/null; then
            iptables -A OUTPUT -o "$vpn_iface" -p udp --dport 53 -j ACCEPT 2>/dev/null || true
            iptables -A OUTPUT -o "$vpn_iface" -p tcp --dport 53 -j ACCEPT 2>/dev/null || true
        fi
    done
    # Bloquear DNS plaintext saliente en el resto de interfaces
    if ! iptables -C OUTPUT -p udp --dport 53 -j REJECT 2>/dev/null; then
        iptables -A OUTPUT -p udp --dport 53 -j REJECT
        iptables -A OUTPUT -p tcp --dport 53 -j REJECT
    fi
    log_change "Firewall" "Puerto 53 saliente bloqueado (excepto lo/VPN)"

    # Detectar nameservers ISP
    if [[ -f /etc/resolv.conf ]]; then
        local_ns=$(grep -E '^nameserver' /etc/resolv.conf 2>/dev/null | grep -vE '127\.|::1' || true)
        if [[ -n "$local_ns" ]]; then
            log_warn "Nameservers posiblemente del ISP detectados en /etc/resolv.conf:"
            echo "$local_ns" | sed 's/^/    /'
            echo "  Se recomienda que apunten a 127.0.0.53 (systemd-resolved)"
        fi
    fi

    # Script de detección de fugas DNS
    cat > "${ISP_BIN_DIR}/detectar-dns-leak.sh" << 'DNS_LEAK'
#!/bin/bash
# Detectar fugas DNS - comprueba que las consultas usan DoT
set -euo pipefail

echo "=== Detección de fugas DNS ==="
echo ""

# Verificar resolved
if systemctl is-active systemd-resolved &>/dev/null; then
    echo "[+] systemd-resolved activo"
    resolvectl status 2>/dev/null | grep -E 'DNS Server|DNSOverTLS|DNSSEC' | sed 's/^/    /'
else
    echo "[!] systemd-resolved NO activo"
fi

echo ""

# Verificar que puerto 53 está bloqueado
echo "=== Reglas iptables puerto 53 ==="
iptables -L OUTPUT -n -v 2>/dev/null | grep -E ':53|dpt:53' | sed 's/^/    /' || echo "    (sin reglas)"

echo ""

# Test de resolución
echo "=== Test de resolución DNS ==="
for domain in example.com cloudflare.com; do
    if result=$(resolvectl query "$domain" 2>&1); then
        echo "[+] $domain: resuelve correctamente vía DoT"
    else
        echo "[!] $domain: fallo en resolución"
    fi
done

echo ""

# Comprobar conexiones DNS activas
echo "=== Conexiones DNS activas (puerto 53/853) ==="
ss -tnp 2>/dev/null | grep -E ':53 |:853 ' | sed 's/^/    /' || echo "    (ninguna)"

echo ""
echo "Si ves conexiones al puerto 53 (no 853), hay fuga DNS."
DNS_LEAK
    chmod 755 "${ISP_BIN_DIR}/detectar-dns-leak.sh"
    log_change "Creado" "${ISP_BIN_DIR}/detectar-dns-leak.sh"

    log_info "Prevención de fugas DNS configurada (modo estricto)"
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
if iptables -L SECURIZAR_KS -n &>/dev/null; then
    ks_fail=0
fi
check "Kill switch VPN activo" $ks_fail "Ejecutar: /etc/securizar/vpn-killswitch.sh"

# 3. DNS
echo ""
echo -e "${BOLD}── DNS ──${NC}"
# DoT estricto
dot_fail=1
if [[ -f /etc/systemd/resolved.conf.d/02-isp-dns-leak-prevention.conf ]]; then
    if grep -q "DNSOverTLS=yes" /etc/systemd/resolved.conf.d/02-isp-dns-leak-prevention.conf 2>/dev/null; then
        dot_fail=0
    fi
fi
check "DNS-over-TLS estricto" $dot_fail "Falta configuración DoT estricta"

# Puerto 53 bloqueado
p53_fail=1
if iptables -L OUTPUT -n 2>/dev/null | grep -q "REJECT.*dpt:53"; then
    p53_fail=0
fi
check "Puerto 53 saliente bloqueado" $p53_fail "DNS plaintext puede fugarse"

# DNSSEC
dnssec_fail=1
if [[ -f /etc/systemd/resolved.conf.d/02-isp-dns-leak-prevention.conf ]]; then
    if grep -q "DNSSEC=yes" /etc/systemd/resolved.conf.d/02-isp-dns-leak-prevention.conf 2>/dev/null; then
        dnssec_fail=0
    fi
fi
check "DNSSEC habilitado" $dnssec_fail "DNSSEC no configurado"

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
