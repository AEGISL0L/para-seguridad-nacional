#!/bin/bash
# ============================================================
# PROTECCIÓN DE RED AVANZADA - Linux Multi-Distro
# ============================================================
# Secciones:
#   S1 - Suricata IDS (detección de intrusiones)
#   S2 - Cron semanal suricata-update
#   S3 - DNS over TLS (systemd-resolved)
#   S4 - WireGuard (plantilla, NO activar)
#   S5 - arpwatch + sysctl ARP
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "proteger-red-avanzado"
securizar_setup_traps
log_section "S1: SURICATA IDS (DETECCIÓN DE INTRUSIONES)"

echo "Suricata es un motor IDS/IPS de alto rendimiento."
echo "Se configurará en modo IDS (solo detección, sin bloqueo)."
echo "Logs en formato EVE JSON para análisis."
echo ""

if ask "¿Instalar y configurar Suricata IDS?"; then
    # Instalar suricata
    if ! command -v suricata &>/dev/null; then
        log_info "Instalando Suricata..."
        pkg_install suricata || {
            log_error "No se pudo instalar Suricata. Verifica los repositorios."
            case "$DISTRO_FAMILY" in
                suse)   log_warn "Intenta: zypper addrepo https://download.opensuse.org/repositories/security/ security" ;;
                debian) log_warn "Intenta: apt-get update && apt-get install suricata" ;;
                rhel)   log_warn "Intenta: dnf install epel-release && dnf install suricata" ;;
                arch)   log_warn "Intenta: pacman -S suricata" ;;
            esac
        }
    fi

    if command -v suricata &>/dev/null; then
        # Detectar interfaz activa
        IFACE=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
        if [[ -z "$IFACE" ]]; then
            IFACE=$(ip -o link show up 2>/dev/null | awk -F': ' '{print $2}' | grep -v lo | head -1)
        fi
        log_info "Interfaz detectada: ${IFACE:-ninguna}"

        # Backup config original
        cp /etc/suricata/suricata.yaml "$BACKUP_DIR/" 2>/dev/null || true
        log_change "Backup" "/etc/suricata/suricata.yaml"

        # Configurar interfaz en suricata
        if [[ -n "$IFACE" ]] && [[ -f /etc/suricata/suricata.yaml ]]; then
            # Actualizar interfaz en af-packet
            sed -i "s/- interface: eth0/- interface: $IFACE/" /etc/suricata/suricata.yaml 2>/dev/null || true
            sed -i "s/interface: eth0/interface: $IFACE/" /etc/suricata/suricata.yaml 2>/dev/null || true
            log_change "Modificado" "/etc/suricata/suricata.yaml (interface: $IFACE)"
            log_info "Interfaz configurada: $IFACE"
        fi

        # Descargar reglas ET Open
        log_info "Descargando reglas ET Open..."
        if command -v suricata-update &>/dev/null; then
            suricata-update 2>/dev/null || log_warn "Error descargando reglas (se reintentará)"
        else
            # Descargar manualmente
            mkdir -p /var/lib/suricata/rules
            if command -v wget &>/dev/null; then
                wget -q "https://rules.emergingthreats.net/open/suricata-6.0/emerging.rules.tar.gz" -O /tmp/emerging.rules.tar.gz 2>/dev/null && \
                tar xzf /tmp/emerging.rules.tar.gz -C /var/lib/suricata/rules/ 2>/dev/null && \
                rm -f /tmp/emerging.rules.tar.gz
                log_info "Reglas ET Open descargadas"
            else
                log_warn "wget no disponible. Instala reglas manualmente: suricata-update"
            fi
        fi

        # Habilitar y arrancar
        systemctl enable suricata 2>/dev/null || true
        log_change "Servicio" "suricata enable"
        systemctl start suricata 2>/dev/null || log_warn "Suricata no pudo arrancar. Revisa la configuración."
        log_change "Servicio" "suricata start"
        log_info "Suricata configurado en modo IDS"

        # Script de alertas
        cat > /usr/local/bin/suricata-alertas.sh << 'EOFSURI'
#!/bin/bash
# ============================================================
# Visualizador de alertas Suricata
# Uso: sudo suricata-alertas.sh [N]  (N = últimas N alertas, default 20)
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

N=${1:-20}
EVE_LOG="/var/log/suricata/eve.json"

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  ALERTAS DE SURICATA IDS${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

if [[ ! -f "$EVE_LOG" ]]; then
    echo -e "${YELLOW}No se encontró $EVE_LOG${NC}"
    echo "Suricata puede no estar generando logs aún."
    exit 1
fi

# Estado de suricata
if systemctl is-active suricata &>/dev/null; then
    echo -e "  Estado: ${GREEN}ACTIVO${NC}"
else
    echo -e "  Estado: ${RED}INACTIVO${NC}"
fi

echo ""
echo -e "${CYAN}── Últimas $N alertas ──${NC}"

if command -v jq &>/dev/null; then
    grep '"event_type":"alert"' "$EVE_LOG" | tail -"$N" | jq -r '"\(.timestamp) | \(.alert.severity) | \(.src_ip):\(.src_port) -> \(.dest_ip):\(.dest_port) | \(.alert.signature)"' 2>/dev/null
else
    grep '"event_type":"alert"' "$EVE_LOG" | tail -"$N"
fi

echo ""
echo -e "${CYAN}── Resumen ──${NC}"
total_alerts=$(grep -c '"event_type":"alert"' "$EVE_LOG" 2>/dev/null || echo 0)
echo "  Total alertas en log: $total_alerts"

# Top 5 firmas
echo ""
echo -e "${CYAN}── Top 5 firmas ──${NC}"
if command -v jq &>/dev/null; then
    grep '"event_type":"alert"' "$EVE_LOG" | jq -r '.alert.signature' 2>/dev/null | sort | uniq -c | sort -rn | head -5 | while read count sig; do
        echo "  $count  $sig"
    done
else
    if command -v zypper &>/dev/null; then
        echo "  Instala jq para análisis detallado: zypper install jq"
    elif command -v apt-get &>/dev/null; then
        echo "  Instala jq para análisis detallado: apt-get install jq"
    elif command -v dnf &>/dev/null; then
        echo "  Instala jq para análisis detallado: dnf install jq"
    elif command -v pacman &>/dev/null; then
        echo "  Instala jq para análisis detallado: pacman -S jq"
    fi
fi

echo ""
echo -e "${BOLD}Consulta completada: $(date)${NC}"
EOFSURI

        chmod +x /usr/local/bin/suricata-alertas.sh
        log_change "Creado" "/usr/local/bin/suricata-alertas.sh"
        log_change "Permisos" "/usr/local/bin/suricata-alertas.sh -> +x"
        log_info "Script creado: /usr/local/bin/suricata-alertas.sh"
    fi
else
    log_skip "Instalar y configurar Suricata IDS"
fi

# ============================================================
# S2: Cron semanal suricata-update
# ============================================================
log_section "S2: ACTUALIZACIÓN SEMANAL DE REGLAS SURICATA"

if command -v suricata-update &>/dev/null || command -v suricata &>/dev/null; then
    if ask "¿Crear cron semanal para actualizar reglas de Suricata?"; then
        cat > /etc/cron.weekly/suricata-update << 'EOFSUPDATE'
#!/bin/bash
# Actualización semanal de reglas Suricata
LOG="/var/log/suricata-update-$(date +%Y%m%d).log"

echo "=== Suricata Update - $(date) ===" > "$LOG"

if command -v suricata-update &>/dev/null; then
    suricata-update >> "$LOG" 2>&1
    RESULT=$?
    if [[ $RESULT -eq 0 ]]; then
        echo "OK: Reglas actualizadas" >> "$LOG"
        # Recargar suricata
        systemctl reload suricata 2>/dev/null || systemctl restart suricata 2>/dev/null
        echo "Suricata recargado" >> "$LOG"
    else
        echo "ERROR: Falló la actualización (código: $RESULT)" >> "$LOG"
    fi
else
    echo "suricata-update no disponible" >> "$LOG"
fi

find /var/log -name "suricata-update-*.log" -mtime +60 -delete 2>/dev/null
EOFSUPDATE

        chmod 700 /etc/cron.weekly/suricata-update
        log_change "Creado" "/etc/cron.weekly/suricata-update"
        log_change "Permisos" "/etc/cron.weekly/suricata-update -> 700"
        log_info "Cron semanal creado: /etc/cron.weekly/suricata-update"
    else
        log_skip "Cron semanal para actualizar reglas Suricata"
    fi
else
    log_warn "Suricata no instalado. Instálalo primero en S1."
fi

# ============================================================
# S3: DNS over TLS con systemd-resolved
# ============================================================
log_section "S3: DNS OVER TLS"

echo "DNS over TLS cifra las consultas DNS para evitar espionaje."
echo "Servidores:"
echo "  - Cloudflare: 1.1.1.1#cloudflare-dns.com, 1.0.0.1#cloudflare-dns.com"
echo "  - Quad9:      9.9.9.9#dns.quad9.net, 149.112.112.112#dns.quad9.net"
echo ""

if ask "¿Configurar DNS over TLS con systemd-resolved?"; then
    # Backup configuración actual
    cp /etc/systemd/resolved.conf "$BACKUP_DIR/" 2>/dev/null || true
    log_change "Backup" "/etc/systemd/resolved.conf"

    mkdir -p /etc/systemd/resolved.conf.d/
    log_change "Creado" "/etc/systemd/resolved.conf.d/"

    cat > /etc/systemd/resolved.conf.d/dns-over-tls.conf << 'EOF'
[Resolve]
# DNS over TLS - generado por proteger-red-avanzado.sh
DNS=1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com 9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net
FallbackDNS=8.8.8.8 8.8.4.4
DNSOverTLS=opportunistic
DNSSEC=allow-downgrade
Domains=~.
EOF

    log_change "Creado" "/etc/systemd/resolved.conf.d/dns-over-tls.conf"
    log_info "Configuración de DNS over TLS creada"

    # Configurar NetworkManager para delegar DNS a systemd-resolved
    if systemctl is-active NetworkManager &>/dev/null; then
        mkdir -p /etc/NetworkManager/conf.d/
        log_change "Creado" "/etc/NetworkManager/conf.d/"

        cat > /etc/NetworkManager/conf.d/dns-resolved.conf << 'EOF'
[main]
dns=systemd-resolved
EOF
        log_change "Creado" "/etc/NetworkManager/conf.d/dns-resolved.conf"

        log_info "NetworkManager configurado para delegar DNS a systemd-resolved"
    fi

    # Habilitar y reiniciar systemd-resolved
    systemctl enable systemd-resolved 2>/dev/null || true
    log_change "Servicio" "systemd-resolved enable"
    systemctl restart systemd-resolved 2>/dev/null || true
    log_change "Servicio" "systemd-resolved restart"

    # Verificar que funciona
    if systemctl is-active systemd-resolved &>/dev/null; then
        log_info "systemd-resolved activo con DNS over TLS"
        # Mostrar estado
        resolvectl status 2>/dev/null | head -20 || true
    else
        log_warn "systemd-resolved no pudo arrancar"
    fi

    log_warn "Reinicia NetworkManager para aplicar: systemctl restart NetworkManager"
else
    log_skip "Configurar DNS over TLS"
fi

# ============================================================
# S4: WireGuard (plantilla, NO activar)
# ============================================================
log_section "S4: WIREGUARD VPN (PLANTILLA)"

echo "WireGuard es una VPN moderna, rápida y segura."
echo "Se instalará y generará una plantilla de configuración."
echo -e "${YELLOW}NO se activará la VPN automáticamente.${NC}"
echo ""

if ask "¿Instalar WireGuard y generar plantilla?"; then
    # Instalar wireguard-tools
    if ! command -v wg &>/dev/null; then
        log_info "Instalando wireguard-tools..."
        pkg_install wireguard-tools || {
            log_error "No se pudo instalar wireguard-tools"
        }
    fi

    if command -v wg &>/dev/null; then
        # Generar keypair
        mkdir -p /etc/wireguard
        chmod 700 /etc/wireguard
        log_change "Creado" "/etc/wireguard/"
        log_change "Permisos" "/etc/wireguard -> 700"

        if [[ ! -f /etc/wireguard/privatekey ]]; then
            wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey
            chmod 600 /etc/wireguard/privatekey
            chmod 644 /etc/wireguard/publickey
            log_change "Creado" "/etc/wireguard/privatekey"
            log_change "Permisos" "/etc/wireguard/privatekey -> 600"
            log_change "Creado" "/etc/wireguard/publickey"
            log_change "Permisos" "/etc/wireguard/publickey -> 644"
            log_info "Keypair generado"
        else
            log_info "Keypair ya existe"
        fi

        PRIVKEY=$(cat /etc/wireguard/privatekey)
        PUBKEY=$(cat /etc/wireguard/publickey)

        # Crear plantilla de configuración
        cat > /etc/wireguard/wg0.conf << EOFWG
# ============================================================
# WireGuard VPN - Plantilla de configuración
# Generado por proteger-red-avanzado.sh
# ============================================================
# INSTRUCCIONES:
# 1. Completa los campos marcados con <...>
# 2. Activa con: wg-quick up wg0
# 3. Para arranque automático: systemctl enable wg-quick@wg0
# ============================================================

[Interface]
PrivateKey = $PRIVKEY
Address = <TU_IP_VPN>/24
# Ejemplo: Address = 10.0.0.2/24
DNS = 1.1.1.1, 9.9.9.9
# Puerto de escucha (opcional, para servidor)
# ListenPort = 51820

[Peer]
PublicKey = <CLAVE_PUBLICA_DEL_SERVIDOR>
# Ejemplo: PublicKey = abc123...=
Endpoint = <IP_SERVIDOR>:51820
AllowedIPs = 0.0.0.0/0, ::/0
# Para solo rutar tráfico específico:
# AllowedIPs = 10.0.0.0/24
PersistentKeepalive = 25
EOFWG

        chmod 600 /etc/wireguard/wg0.conf
        log_change "Creado" "/etc/wireguard/wg0.conf"
        log_change "Permisos" "/etc/wireguard/wg0.conf -> 600"
        log_info "Plantilla creada: /etc/wireguard/wg0.conf"
        log_info "Tu clave pública: $PUBKEY"
        echo ""
        log_warn "La VPN NO está activada. Edita wg0.conf y activa con:"
        log_warn "  wg-quick up wg0"
        log_warn "  systemctl enable wg-quick@wg0  (para arranque automático)"
    fi
else
    log_skip "Instalar WireGuard y generar plantilla"
fi

# ============================================================
# S5: arpwatch + protección ARP
# ============================================================
log_section "S5: PROTECCIÓN ARP"

echo "arpwatch monitoriza cambios en tablas ARP (detección de ARP spoofing)."
echo "Se configurarán también parámetros sysctl de protección ARP."
echo ""

if ask "¿Instalar arpwatch y configurar protección ARP?"; then
    # Instalar arpwatch
    if ! command -v arpwatch &>/dev/null; then
        log_info "Instalando arpwatch..."
        pkg_install arpwatch || {
            log_error "No se pudo instalar arpwatch"
        }
    fi

    if command -v arpwatch &>/dev/null; then
        # Detectar interfaz
        IFACE=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
        if [[ -n "$IFACE" ]]; then
            # Configurar arpwatch para la interfaz
            if [[ -f /etc/sysconfig/arpwatch ]]; then
                cp /etc/sysconfig/arpwatch "$BACKUP_DIR/" 2>/dev/null || true
                log_change "Backup" "/etc/sysconfig/arpwatch"
                sed -i "s/^ARPWATCH_INTERFACE=.*/ARPWATCH_INTERFACE=\"$IFACE\"/" /etc/sysconfig/arpwatch 2>/dev/null || true
                log_change "Modificado" "/etc/sysconfig/arpwatch (ARPWATCH_INTERFACE=$IFACE)"
            fi

            systemctl enable arpwatch 2>/dev/null || true
            log_change "Servicio" "arpwatch enable"
            systemctl start arpwatch 2>/dev/null || true
            log_change "Servicio" "arpwatch start"
            log_info "arpwatch habilitado en interfaz $IFACE"
        else
            log_warn "No se detectó interfaz de red"
        fi
    fi

    # Sysctl ARP protection
    log_info "Configurando protección ARP via sysctl..."
    cat > /etc/sysctl.d/99-arp-protection.conf << 'EOF'
# Protección ARP - generado por proteger-red-avanzado.sh

# arp_announce: usar la mejor dirección local como fuente
# 2 = siempre usar la mejor dirección local
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.default.arp_announce = 2

# arp_ignore: responder solo si la dirección destino es local
# 1 = responder solo si la dirección está configurada en la interfaz
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.default.arp_ignore = 1
EOF

    log_change "Creado" "/etc/sysctl.d/99-arp-protection.conf"
    /usr/sbin/sysctl --system > /dev/null 2>&1
    log_change "Aplicado" "sysctl --system"
    log_info "Protección ARP aplicada (arp_announce=2, arp_ignore=1)"

    # Script de verificación ARP
    cat > /usr/local/bin/verificar-arp.sh << 'EOFARP'
#!/bin/bash
# ============================================================
# Verificación de protección ARP
# Uso: sudo verificar-arp.sh
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  VERIFICACIÓN DE PROTECCIÓN ARP${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

# 1. Estado de arpwatch
echo -e "${CYAN}── Estado de arpwatch ──${NC}"
if systemctl is-active arpwatch &>/dev/null; then
    echo -e "  ${GREEN}OK${NC}  arpwatch activo"
else
    echo -e "  ${YELLOW}!!${NC}  arpwatch NO activo"
fi

# 2. Parámetros ARP
echo ""
echo -e "${CYAN}── Parámetros ARP del kernel ──${NC}"
for param in net.ipv4.conf.all.arp_announce net.ipv4.conf.all.arp_ignore; do
    val=$(sysctl -n "$param" 2>/dev/null || echo "N/A")
    echo -e "  $param = $val"
done

# 3. Tabla ARP actual
echo ""
echo -e "${CYAN}── Tabla ARP actual ──${NC}"
ip neigh show 2>/dev/null | while read -r line; do
    if echo "$line" | grep -q "STALE\|FAILED"; then
        echo -e "  ${YELLOW}$line${NC}"
    else
        echo -e "  $line"
    fi
done

# 4. Posibles duplicados (ARP spoofing)
echo ""
echo -e "${CYAN}── Verificación de duplicados ARP ──${NC}"
duplicados=$(ip neigh show 2>/dev/null | awk '{print $5}' | sort | uniq -d)
if [[ -n "$duplicados" ]]; then
    echo -e "  ${RED}ALERTA: MACs duplicadas detectadas (posible ARP spoofing):${NC}"
    echo "$duplicados" | while read mac; do
        echo -e "  ${RED}  $mac${NC}"
        ip neigh show 2>/dev/null | grep "$mac"
    done
else
    echo -e "  ${GREEN}OK${NC}  No se detectaron MACs duplicadas"
fi

# 5. Logs de arpwatch
echo ""
echo -e "${CYAN}── Últimos eventos de arpwatch ──${NC}"
if [[ -f /var/log/messages ]]; then
    grep "arpwatch" /var/log/messages 2>/dev/null | tail -10 || echo "  Sin eventos recientes"
else
    journalctl -u arpwatch --no-pager -n 10 2>/dev/null || echo "  Sin eventos recientes"
fi

echo ""
echo -e "${BOLD}Verificación completada: $(date)${NC}"
EOFARP

    chmod +x /usr/local/bin/verificar-arp.sh
    log_change "Creado" "/usr/local/bin/verificar-arp.sh"
    log_change "Permisos" "/usr/local/bin/verificar-arp.sh -> +x"
    log_info "Script creado: /usr/local/bin/verificar-arp.sh"
else
    log_skip "Instalar arpwatch y configurar protección ARP"
fi

echo ""
show_changes_summary
log_info "Protección de red avanzada completada"
log_info "Backup en: $BACKUP_DIR"
