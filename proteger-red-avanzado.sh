#!/bin/bash
# ============================================================
# PROTECCIÓN DE RED AVANZADA - Linux Multi-Distro
# ============================================================
# Secciones:
#   S1  - Suricata IDS (detección de intrusiones)
#   S2  - Cron semanal suricata-update
#   S3  - DNS over TLS (systemd-resolved)
#   S4  - WireGuard (plantilla, NO activar)
#   S5  - arpwatch + sysctl ARP
#   S6  - Forense de red (tcpdump ring buffer)
#   S7  - Zeek/Suricata avanzado (custom rules)
#   S8  - DNS sinkhole (abuse.ch, PhishTank)
#   S9  - Baseline de tráfico de red
#   S10 - Auditoría de red avanzada
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "proteger-red-avanzado"
securizar_setup_traps

# ── Pre-check: detectar secciones ya aplicadas ──────────────
_precheck 10
_pc 'check_service_enabled suricata'
_pc 'check_file_exists /etc/cron.weekly/suricata-update'
_pc 'check_file_exists /etc/systemd/resolved.conf.d/dns-over-tls.conf'
_pc 'check_file_exists /etc/wireguard/wg0.conf'
_pc 'check_file_exists /etc/sysctl.d/99-arp-protection.conf'
_pc 'check_executable /usr/local/bin/captura-forense-red.sh'
_pc 'check_executable /usr/local/bin/configurar-ids-avanzado.sh'
_pc 'check_executable /usr/local/bin/dns-sinkhole.sh'
_pc 'check_executable /usr/local/bin/baseline-red.sh'
_pc 'check_executable /usr/local/bin/auditoria-red-avanzada.sh'
_precheck_result

log_section "S1: SURICATA IDS (DETECCIÓN DE INTRUSIONES)"

echo "Suricata es un motor IDS/IPS de alto rendimiento."
echo "Se configurará en modo IDS (solo detección, sin bloqueo)."
echo "Logs en formato EVE JSON para análisis."
echo ""

if check_service_enabled suricata; then
    log_already "Suricata IDS (servicio habilitado)"
elif ask "¿Instalar y configurar Suricata IDS?"; then
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
    if check_file_exists /etc/cron.weekly/suricata-update; then
        log_already "Cron semanal suricata-update (ya existe)"
    elif ask "¿Crear cron semanal para actualizar reglas de Suricata?"; then
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

if check_file_exists /etc/systemd/resolved.conf.d/dns-over-tls.conf; then
    log_already "DNS over TLS (configuración ya existe)"
elif ask "¿Configurar DNS over TLS con systemd-resolved?"; then
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

if check_file_exists /etc/wireguard/wg0.conf; then
    log_already "WireGuard plantilla (wg0.conf ya existe)"
elif ask "¿Instalar WireGuard y generar plantilla?"; then
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

if check_file_exists /etc/sysctl.d/99-arp-protection.conf; then
    log_already "Protección ARP (sysctl ya configurado)"
elif ask "¿Instalar arpwatch y configurar protección ARP?"; then
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
    /usr/sbin/sysctl --system > /dev/null 2>&1 || true
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

# ============================================================
# S6: FORENSE DE RED (TCPDUMP RING BUFFER)
# ============================================================
log_section "S6: FORENSE DE RED (CAPTURA CONTINUA)"

echo "Captura continua de tráfico con tcpdump en ring buffer."
echo "Mantiene las últimas 24 capturas de 100MB para análisis forense."
echo ""

if check_executable /usr/local/bin/captura-forense-red.sh; then
    log_already "Captura forense de red"
elif ask "¿Configurar captura forense de red con ring buffer?"; then

    mkdir -p /var/lib/securizar/network-forensics
    chmod 700 /var/lib/securizar/network-forensics
    log_change "Creado" "/var/lib/securizar/network-forensics/"

    cat > /usr/local/bin/captura-forense-red.sh << 'EOFCAPTURE'
#!/bin/bash
# ============================================================
# CAPTURA FORENSE DE RED - Ring Buffer
# Mantiene últimas 24 capturas de 100MB rotativas
# Uso: captura-forense-red.sh [start|stop|status]
# ============================================================

CAPTURE_DIR="/var/lib/securizar/network-forensics"
PIDFILE="/var/run/securizar-netcapture.pid"
MAX_FILES=24
MAX_SIZE_MB=100

case "${1:-status}" in
    start)
        if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
            echo "Captura ya activa (PID $(cat "$PIDFILE"))"
            exit 0
        fi

        IFACE=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
        if [[ -z "$IFACE" ]]; then
            echo "No se detectó interfaz de red"
            exit 1
        fi

        echo "Iniciando captura en $IFACE (ring: ${MAX_FILES}x${MAX_SIZE_MB}MB)"
        tcpdump -i "$IFACE" \
            -w "$CAPTURE_DIR/capture-%Y%m%d-%H%M%S.pcap" \
            -W "$MAX_FILES" -C "$MAX_SIZE_MB" \
            -G 3600 -Z root \
            -n -s 0 \
            'not port 22' \
            &>/dev/null &
        echo $! > "$PIDFILE"
        chmod 600 "$PIDFILE"
        echo "Captura iniciada (PID $!)"
        logger -t securizar-netcapture "Ring buffer capture started on $IFACE"
        ;;
    stop)
        if [[ -f "$PIDFILE" ]]; then
            kill "$(cat "$PIDFILE")" 2>/dev/null
            rm -f "$PIDFILE"
            echo "Captura detenida"
            logger -t securizar-netcapture "Ring buffer capture stopped"
        else
            echo "No hay captura activa"
        fi
        ;;
    status)
        if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
            echo "Estado: ACTIVO (PID $(cat "$PIDFILE"))"
        else
            echo "Estado: INACTIVO"
        fi
        PCAP_COUNT=$(find "$CAPTURE_DIR" -name "*.pcap" 2>/dev/null | wc -l)
        PCAP_SIZE=$(du -sh "$CAPTURE_DIR" 2>/dev/null | awk '{print $1}')
        echo "Capturas: $PCAP_COUNT archivos ($PCAP_SIZE)"
        ls -lt "$CAPTURE_DIR"/*.pcap 2>/dev/null | head -5
        ;;
    *)
        echo "Uso: $0 {start|stop|status}"
        ;;
esac
EOFCAPTURE

    chmod 755 /usr/local/bin/captura-forense-red.sh
    log_change "Creado" "/usr/local/bin/captura-forense-red.sh"

    # Servicio systemd para arranque automático
    cat > /etc/systemd/system/securizar-netcapture.service << 'EOFSVC'
[Unit]
Description=Securizar Network Forensic Capture
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
ExecStart=/usr/local/bin/captura-forense-red.sh start
ExecStop=/usr/local/bin/captura-forense-red.sh stop
PIDFile=/var/run/securizar-netcapture.pid
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOFSVC

    systemctl daemon-reload
    log_change "Creado" "/etc/systemd/system/securizar-netcapture.service"
    log_info "Captura forense de red configurada (no activada por defecto)"
    echo -e "${DIM}Activar: systemctl enable --now securizar-netcapture${NC}"

else
    log_skip "Captura forense de red"
fi

# ============================================================
# S7: ZEEK/SURICATA AVANZADO (CUSTOM RULES)
# ============================================================
log_section "S7: ZEEK/SURICATA AVANZADO (CUSTOM RULES)"

echo "Reglas personalizadas de Suricata para detección avanzada:"
echo "  - IMDS SSRF detection (cloud)"
echo "  - DNS tunneling"
echo "  - TLS anomalías"
echo "  - Correlación con community-id"
echo ""

if check_executable /usr/local/bin/configurar-ids-avanzado.sh; then
    log_already "IDS avanzado configurado"
elif ask "¿Crear reglas personalizadas de Suricata/Zeek?"; then

    cat > /usr/local/bin/configurar-ids-avanzado.sh << 'EOFIDS'
#!/bin/bash
# ============================================================
# CONFIGURACIÓN IDS AVANZADA
# Reglas custom de Suricata + local.zeek (si disponible)
# ============================================================

set -euo pipefail

SURICATA_RULES="/var/lib/suricata/rules"
ZEEK_SITE="/opt/zeek/share/zeek/site"

echo "╔════════════════════════════════════════════╗"
echo "║   CONFIGURACIÓN IDS AVANZADA               ║"
echo "╚════════════════════════════════════════════╝"
echo ""

# --- Suricata custom rules ---
if command -v suricata &>/dev/null; then
    echo "Instalando reglas Suricata personalizadas..."
    mkdir -p "$SURICATA_RULES"

    cat > "$SURICATA_RULES/securizar-custom.rules" << 'EOFRULES'
# ============================================================
# REGLAS SECURIZAR - Detección avanzada
# ============================================================

# IMDS SSRF Detection (AWS/Azure/GCP metadata)
alert http any any -> 169.254.169.254 any (msg:"SECURIZAR IMDS Access Attempt"; flow:to_server,established; content:"169.254.169.254"; http_host; classtype:attempted-recon; sid:9000001; rev:1;)
alert http any any -> [fd00:ec2::254] any (msg:"SECURIZAR IMDS IPv6 Access"; flow:to_server,established; classtype:attempted-recon; sid:9000002; rev:1;)

# DNS Tunneling Detection
alert dns any any -> any any (msg:"SECURIZAR DNS Tunnel - Long Query"; dns.query; content:"."; pcre:"/^[a-zA-Z0-9]{50,}\./"; classtype:policy-violation; sid:9000010; rev:1;)
alert dns any any -> any any (msg:"SECURIZAR DNS Tunnel - TXT Record Exfil"; dns.query; dns_query; content:"|00 10|"; classtype:policy-violation; sid:9000011; rev:1;)

# TLS Anomalies
alert tls any any -> any any (msg:"SECURIZAR Self-signed cert to external"; flow:to_server,established; tls.cert_subject; content:"CN=localhost"; classtype:policy-violation; sid:9000020; rev:1;)

# Reverse Shell Detection
alert tcp any any -> any any (msg:"SECURIZAR Potential Reverse Shell - bash"; flow:established; content:"/bin/bash"; content:"-i"; classtype:trojan-activity; sid:9000030; rev:1;)
alert tcp any any -> any any (msg:"SECURIZAR Potential Reverse Shell - python"; flow:established; content:"import socket"; content:"subprocess"; classtype:trojan-activity; sid:9000031; rev:1;)

# Crypto Mining
alert tls any any -> any any (msg:"SECURIZAR Crypto Mining Pool TLS"; flow:to_server,established; tls.sni; content:"pool."; classtype:policy-violation; sid:9000040; rev:1;)
alert tcp any any -> any any (msg:"SECURIZAR Stratum Mining Protocol"; flow:established; content:"mining.subscribe"; classtype:policy-violation; sid:9000041; rev:1;)

# C2 Beaconing patterns
alert http any any -> any any (msg:"SECURIZAR Potential C2 User-Agent"; flow:to_server,established; http.user_agent; content:"Mozilla/4.0"; pcre:"/^Mozilla\/4\.0$/"; classtype:trojan-activity; sid:9000050; rev:1;)
EOFRULES

    # Añadir reglas custom al yaml si no están
    SURICATA_YAML="/etc/suricata/suricata.yaml"
    if [[ -f "$SURICATA_YAML" ]]; then
        if ! grep -q "securizar-custom.rules" "$SURICATA_YAML" 2>/dev/null; then
            echo "  - securizar-custom.rules" >> "$SURICATA_YAML"
            echo "Reglas añadidas a suricata.yaml"
        fi
    fi

    echo "[+] Reglas Suricata custom instaladas: $SURICATA_RULES/securizar-custom.rules"
    systemctl reload suricata 2>/dev/null || systemctl restart suricata 2>/dev/null || true
fi

# --- Zeek local.zeek ---
if command -v zeek &>/dev/null || [[ -d "$ZEEK_SITE" ]]; then
    echo ""
    echo "Configurando Zeek..."
    mkdir -p "$ZEEK_SITE"

    cat > "$ZEEK_SITE/securizar-detect.zeek" << 'EOFZEEK'
# Securizar - Detección custom Zeek
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl

# Alertar en DNS queries sospechosamente largas (tunneling)
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if ( |query| > 60 )
        {
        NOTICE([$note=DNS::External_Name,
                $msg=fmt("Long DNS query (possible tunnel): %s", query),
                $conn=c,
                $identifier=cat(c$id$orig_h)]);
        }
    }

# Alertar en conexiones a IPs de metadata cloud
event new_connection(c: connection)
    {
    if ( c$id$resp_h == 169.254.169.254 )
        {
        NOTICE([$note=Conn::Content_Gap,
                $msg=fmt("IMDS access from %s", c$id$orig_h),
                $conn=c]);
        }
    }
EOFZEEK

    echo "[+] Zeek scripts custom instalados: $ZEEK_SITE/securizar-detect.zeek"
fi

echo ""
echo "Configuración IDS avanzada completada."
EOFIDS

    chmod 755 /usr/local/bin/configurar-ids-avanzado.sh
    log_change "Creado" "/usr/local/bin/configurar-ids-avanzado.sh"
    log_info "Script IDS avanzado instalado"

else
    log_skip "IDS avanzado"
fi

# ============================================================
# S8: DNS SINKHOLE
# ============================================================
log_section "S8: DNS SINKHOLE"

echo "Bloqueo de dominios maliciosos mediante DNS sinkhole."
echo "Fuentes: abuse.ch URLhaus, PhishTank, threat feeds."
echo "Ref: módulo 63 (DNS avanzado) para RPZ completo."
echo ""

if check_executable /usr/local/bin/dns-sinkhole.sh; then
    log_already "DNS sinkhole"
elif ask "¿Configurar DNS sinkhole con listas de bloqueo?"; then

    cat > /usr/local/bin/dns-sinkhole.sh << 'EOFSINKHOLE'
#!/bin/bash
# ============================================================
# DNS SINKHOLE - Bloqueo de dominios maliciosos
# Fuentes: abuse.ch, PhishTank, securizar threat feeds
# Uso: dns-sinkhole.sh [update|status|add DOMAIN|remove DOMAIN]
# ============================================================

set -euo pipefail

SINKHOLE_DIR="/etc/securizar/dns-sinkhole"
HOSTS_BLOCK="/etc/securizar/dns-sinkhole/blocked-domains.conf"
CUSTOM_BLOCK="$SINKHOLE_DIR/custom-blocked.conf"
LOG="/var/log/securizar/dns-sinkhole.log"

mkdir -p "$SINKHOLE_DIR" "$(dirname "$LOG")"

case "${1:-status}" in
    update)
        echo "=== Actualizando listas DNS sinkhole ===" | tee -a "$LOG"
        echo "Fecha: $(date -Iseconds)" | tee -a "$LOG"

        TEMP_LIST=$(mktemp)

        # Abuse.ch URLhaus domains
        echo "Descargando abuse.ch URLhaus..." | tee -a "$LOG"
        curl -sS --max-time 30 "https://urlhaus.abuse.ch/downloads/hostfile/" 2>/dev/null | \
            grep "^127.0.0.1" | awk '{print $2}' >> "$TEMP_LIST" 2>/dev/null || true

        # Abuse.ch SSL blacklist
        echo "Descargando abuse.ch SSL blacklist..." | tee -a "$LOG"
        curl -sS --max-time 30 "https://sslbl.abuse.ch/blacklist/sslblacklist.csv" 2>/dev/null | \
            grep -v "^#" | cut -d',' -f2 | grep -v "^$" >> "$TEMP_LIST" 2>/dev/null || true

        # Disconnect.me malware
        echo "Descargando Disconnect.me malware..." | tee -a "$LOG"
        curl -sS --max-time 30 "https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt" 2>/dev/null | \
            grep -v "^#" >> "$TEMP_LIST" 2>/dev/null || true

        # Deduplicar y formatear
        sort -u "$TEMP_LIST" | grep -v "^$" | grep -v "^#" > "$HOSTS_BLOCK"
        DOMAIN_COUNT=$(wc -l < "$HOSTS_BLOCK")
        echo "Dominios bloqueados: $DOMAIN_COUNT" | tee -a "$LOG"

        # Añadir custom blocks
        if [[ -f "$CUSTOM_BLOCK" ]]; then
            cat "$CUSTOM_BLOCK" >> "$HOSTS_BLOCK"
            CUSTOM_COUNT=$(wc -l < "$CUSTOM_BLOCK")
            echo "Dominios custom: $CUSTOM_COUNT" | tee -a "$LOG"
        fi

        rm -f "$TEMP_LIST"

        # Aplicar a /etc/hosts (opción ligera)
        HOSTS_MARKER="# === SECURIZAR DNS SINKHOLE ==="
        if grep -q "$HOSTS_MARKER" /etc/hosts 2>/dev/null; then
            # Limpiar entradas anteriores
            sed -i "/$HOSTS_MARKER/,/# === END SINKHOLE ===/d" /etc/hosts
        fi

        echo "$HOSTS_MARKER" >> /etc/hosts
        while IFS= read -r domain; do
            [[ -z "$domain" ]] && continue
            echo "0.0.0.0 $domain" >> /etc/hosts
        done < "$HOSTS_BLOCK"
        echo "# === END SINKHOLE ===" >> /etc/hosts

        # Aplicar a Unbound si disponible
        if command -v unbound-control &>/dev/null && systemctl is-active unbound &>/dev/null; then
            echo "Aplicando a Unbound RPZ..." | tee -a "$LOG"
            RPZ_FILE="/etc/unbound/local.d/sinkhole.conf"
            echo "server:" > "$RPZ_FILE"
            while IFS= read -r domain; do
                [[ -z "$domain" ]] && continue
                echo "    local-zone: \"$domain\" always_nxdomain" >> "$RPZ_FILE"
            done < <(head -5000 "$HOSTS_BLOCK")
            unbound-control reload 2>/dev/null || true
        fi

        logger -t securizar-sinkhole "DNS sinkhole updated: $DOMAIN_COUNT domains"
        echo "Actualización completada." | tee -a "$LOG"
        ;;

    status)
        echo "╔════════════════════════════════════╗"
        echo "║   DNS SINKHOLE - Estado            ║"
        echo "╚════════════════════════════════════╝"
        if [[ -f "$HOSTS_BLOCK" ]]; then
            echo "  Dominios bloqueados: $(wc -l < "$HOSTS_BLOCK")"
            echo "  Última actualización: $(stat -c %y "$HOSTS_BLOCK" 2>/dev/null | cut -d. -f1)"
        else
            echo "  No configurado. Ejecuta: $0 update"
        fi
        if [[ -f "$CUSTOM_BLOCK" ]]; then
            echo "  Dominios custom: $(wc -l < "$CUSTOM_BLOCK")"
        fi
        ;;

    add)
        DOMAIN="${2:-}"
        if [[ -z "$DOMAIN" ]]; then
            echo "Uso: $0 add <dominio>"
            exit 1
        fi
        echo "$DOMAIN" >> "$CUSTOM_BLOCK"
        echo "0.0.0.0 $DOMAIN" >> /etc/hosts
        echo "Dominio añadido: $DOMAIN"
        logger -t securizar-sinkhole "Domain added: $DOMAIN"
        ;;

    remove)
        DOMAIN="${2:-}"
        if [[ -z "$DOMAIN" ]]; then
            echo "Uso: $0 remove <dominio>"
            exit 1
        fi
        sed -i "/^${DOMAIN}$/d" "$CUSTOM_BLOCK" 2>/dev/null
        sed -i "/0.0.0.0 ${DOMAIN}$/d" /etc/hosts 2>/dev/null
        echo "Dominio eliminado: $DOMAIN"
        logger -t securizar-sinkhole "Domain removed: $DOMAIN"
        ;;

    *)
        echo "Uso: $0 {update|status|add DOMAIN|remove DOMAIN}"
        ;;
esac
EOFSINKHOLE

    chmod 755 /usr/local/bin/dns-sinkhole.sh
    log_change "Creado" "/usr/local/bin/dns-sinkhole.sh"
    log_info "DNS sinkhole instalado: dns-sinkhole.sh"
    echo -e "${DIM}Inicializar: dns-sinkhole.sh update${NC}"

else
    log_skip "DNS sinkhole"
fi

# ============================================================
# S9: BASELINE DE TRÁFICO DE RED
# ============================================================
log_section "S9: BASELINE DE TRÁFICO DE RED"

echo "Aprende patrones normales de tráfico y alerta en anomalías:"
echo "  - IPs destino habituales vs nuevas"
echo "  - Puertos en escucha esperados vs nuevos"
echo "  - Volumen de tráfico por interfaz (alerta en 3x)"
echo ""

if check_executable /usr/local/bin/baseline-red.sh; then
    log_already "Baseline de red"
elif ask "¿Configurar baseline de tráfico de red?"; then

    cat > /usr/local/bin/baseline-red.sh << 'EOFBASELINE'
#!/bin/bash
# ============================================================
# BASELINE DE TRÁFICO DE RED
# Aprende patrones normales y detecta anomalías
# Uso: baseline-red.sh [learn|check|status]
# ============================================================

set -euo pipefail

BASELINE_DIR="/var/lib/securizar/network-baseline"
mkdir -p "$BASELINE_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

case "${1:-status}" in
    learn)
        echo -e "${BOLD}=== Aprendiendo baseline de red ===${NC}"
        TIMESTAMP=$(date +%Y%m%d-%H%M%S)

        # 1. Puertos en escucha
        ss -tlnp 2>/dev/null | awk 'NR>1 {print $4}' | sort -u > "$BASELINE_DIR/listeners.baseline"
        echo "  Puertos en escucha: $(wc -l < "$BASELINE_DIR/listeners.baseline")"

        # 2. IPs destino habituales (conexiones establecidas)
        ss -tn state established 2>/dev/null | awk 'NR>1 {print $5}' | cut -d: -f1 | sort -u > "$BASELINE_DIR/destinations.baseline"
        echo "  IPs destino: $(wc -l < "$BASELINE_DIR/destinations.baseline")"

        # 3. Volumen de tráfico por interfaz
        cat /proc/net/dev 2>/dev/null | awk 'NR>2 {gsub(/:/, "", $1); print $1, $2, $10}' > "$BASELINE_DIR/traffic-volume.baseline"
        echo "  Interfaces capturadas: $(wc -l < "$BASELINE_DIR/traffic-volume.baseline")"

        # 4. Servicios DNS activos
        cat /etc/resolv.conf 2>/dev/null | grep "^nameserver" | awk '{print $2}' > "$BASELINE_DIR/dns-servers.baseline"

        echo ""
        echo -e "${GREEN}Baseline capturada: $TIMESTAMP${NC}"
        echo "$TIMESTAMP" > "$BASELINE_DIR/last-learn"
        logger -t securizar-baseline "Network baseline learned"
        ;;

    check)
        if [[ ! -f "$BASELINE_DIR/listeners.baseline" ]]; then
            echo -e "${YELLOW}No hay baseline. Ejecuta: $0 learn${NC}"
            exit 1
        fi

        ALERTS=0
        echo -e "${BOLD}=== Verificando contra baseline ===${NC}"
        echo ""

        # 1. Nuevos puertos en escucha
        echo -e "${CYAN}Puertos en escucha:${NC}"
        CURRENT_LISTENERS=$(mktemp)
        ss -tlnp 2>/dev/null | awk 'NR>1 {print $4}' | sort -u > "$CURRENT_LISTENERS"
        NEW_LISTENERS=$(comm -13 "$BASELINE_DIR/listeners.baseline" "$CURRENT_LISTENERS")
        if [[ -n "$NEW_LISTENERS" ]]; then
            echo -e "  ${RED}ALERTA: Nuevos puertos en escucha:${NC}"
            echo "$NEW_LISTENERS" | while read -r port; do
                PROC=$(ss -tlnp | grep "$port" | grep -oP 'users:\(\("\K[^"]+' || echo "?")
                echo -e "    ${RED}$port${NC} ($PROC)"
            done
            ALERTS=$((ALERTS + 1))
        else
            echo -e "  ${GREEN}OK${NC} Sin nuevos puertos"
        fi
        rm -f "$CURRENT_LISTENERS"

        # 2. Nuevas IPs destino
        echo ""
        echo -e "${CYAN}IPs destino:${NC}"
        CURRENT_DEST=$(mktemp)
        ss -tn state established 2>/dev/null | awk 'NR>1 {print $5}' | cut -d: -f1 | sort -u > "$CURRENT_DEST"
        NEW_DEST=$(comm -13 "$BASELINE_DIR/destinations.baseline" "$CURRENT_DEST" | head -20)
        if [[ -n "$NEW_DEST" ]]; then
            NEW_COUNT=$(echo "$NEW_DEST" | wc -l)
            echo -e "  ${YELLOW}$NEW_COUNT nuevas IPs destino:${NC}"
            echo "$NEW_DEST" | head -10 | while read -r ip; do
                echo -e "    ${YELLOW}$ip${NC}"
            done
            if [[ "$NEW_COUNT" -gt 10 ]]; then
                echo -e "    ${DIM}...y $((NEW_COUNT - 10)) más${NC}"
            fi
        else
            echo -e "  ${GREEN}OK${NC} Sin nuevos destinos"
        fi
        rm -f "$CURRENT_DEST"

        # 3. Volumen de tráfico (alertar si 3x baseline)
        echo ""
        echo -e "${CYAN}Volumen de tráfico:${NC}"
        while read -r iface rx_base tx_base; do
            CURRENT_RX=$(awk -v i="$iface:" '$1==i {print $2}' /proc/net/dev 2>/dev/null || echo 0)
            if [[ "$rx_base" -gt 0 ]] && [[ "$CURRENT_RX" -gt $((rx_base * 3)) ]]; then
                echo -e "  ${RED}ALERTA: $iface RX triplicado (baseline: $rx_base, actual: $CURRENT_RX)${NC}"
                ALERTS=$((ALERTS + 1))
            else
                echo -e "  ${GREEN}OK${NC} $iface dentro de rango normal"
            fi
        done < "$BASELINE_DIR/traffic-volume.baseline"

        echo ""
        if [[ "$ALERTS" -gt 0 ]]; then
            echo -e "${RED}$ALERTS alertas detectadas${NC}"
            logger -t securizar-baseline "Network anomalies detected: $ALERTS alerts"
        else
            echo -e "${GREEN}Sin anomalías detectadas${NC}"
        fi
        ;;

    status)
        echo -e "${BOLD}=== Estado de Baseline de Red ===${NC}"
        if [[ -f "$BASELINE_DIR/last-learn" ]]; then
            echo "  Último aprendizaje: $(cat "$BASELINE_DIR/last-learn")"
            echo "  Puertos baseline: $(wc -l < "$BASELINE_DIR/listeners.baseline" 2>/dev/null || echo 0)"
            echo "  IPs destino baseline: $(wc -l < "$BASELINE_DIR/destinations.baseline" 2>/dev/null || echo 0)"
        else
            echo "  No hay baseline. Ejecuta: $0 learn"
        fi
        ;;

    *)
        echo "Uso: $0 {learn|check|status}"
        ;;
esac
EOFBASELINE

    chmod 755 /usr/local/bin/baseline-red.sh
    log_change "Creado" "/usr/local/bin/baseline-red.sh"
    log_info "Baseline de red instalado: baseline-red.sh"
    echo -e "${DIM}Aprender baseline: baseline-red.sh learn${NC}"
    echo -e "${DIM}Verificar anomalías: baseline-red.sh check${NC}"

else
    log_skip "Baseline de red"
fi

# ============================================================
# S10: AUDITORÍA DE RED AVANZADA
# ============================================================
log_section "S10: AUDITORÍA DE RED AVANZADA"

echo "Auditoría automatizada de todos los controles de red avanzada."
echo "Scoring de 30 puntos con verificación de cada componente."
echo ""

if check_executable /usr/local/bin/auditoria-red-avanzada.sh; then
    log_already "Auditoría de red avanzada"
elif ask "¿Crear auditoría de red avanzada?"; then

    cat > /usr/local/bin/auditoria-red-avanzada.sh << 'EOFAUDIT'
#!/bin/bash
# ============================================================
# AUDITORÍA DE RED AVANZADA
# Scoring de controles de red (30 puntos máximo)
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

SCORE=0
MAX_SCORE=0
REPORT="/var/log/securizar/auditoria-red-avanzada-$(date +%Y%m%d).txt"
mkdir -p "$(dirname "$REPORT")"

check_item() {
    local desc="$1"
    local cmd="$2"
    local points="${3:-1}"
    MAX_SCORE=$((MAX_SCORE + points))

    if eval "$cmd" &>/dev/null; then
        echo -e "  ${GREEN}[+$points]${NC}  $desc" | tee -a "$REPORT"
        SCORE=$((SCORE + points))
    else
        echo -e "  ${RED}[ 0]${NC}  $desc" | tee -a "$REPORT"
    fi
}

echo -e "${BOLD}╔════════════════════════════════════════════╗${NC}" | tee "$REPORT"
echo -e "${BOLD}║   AUDITORÍA DE RED AVANZADA                ║${NC}" | tee -a "$REPORT"
echo -e "${BOLD}╚════════════════════════════════════════════╝${NC}" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"
echo "Fecha: $(date -Iseconds)" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

echo -e "${CYAN}── IDS/IPS ──${NC}" | tee -a "$REPORT"
check_item "Suricata instalado" "command -v suricata" 3
check_item "Suricata activo" "systemctl is-active suricata" 3
check_item "Reglas custom securizar" "test -f /var/lib/suricata/rules/securizar-custom.rules" 2
check_item "Suricata-update cron" "test -f /etc/cron.weekly/suricata-update" 1

echo "" | tee -a "$REPORT"
echo -e "${CYAN}── DNS Seguro ──${NC}" | tee -a "$REPORT"
check_item "DNS over TLS configurado" "test -f /etc/systemd/resolved.conf.d/dns-over-tls.conf" 2
check_item "DNS sinkhole activo" "test -f /etc/securizar/dns-sinkhole/blocked-domains.conf" 2

echo "" | tee -a "$REPORT"
echo -e "${CYAN}── Monitorización ──${NC}" | tee -a "$REPORT"
check_item "arpwatch activo" "systemctl is-active arpwatch" 2
check_item "Protección ARP sysctl" "test -f /etc/sysctl.d/99-arp-protection.conf" 1
check_item "Captura forense configurada" "test -x /usr/local/bin/captura-forense-red.sh" 2
check_item "Baseline de red aprendida" "test -f /var/lib/securizar/network-baseline/listeners.baseline" 2

echo "" | tee -a "$REPORT"
echo -e "${CYAN}── VPN ──${NC}" | tee -a "$REPORT"
check_item "WireGuard configurado" "test -f /etc/wireguard/wg0.conf" 2

echo "" | tee -a "$REPORT"
echo -e "${BOLD}═══════════════════════════════════════${NC}" | tee -a "$REPORT"
PERCENT=0
if [[ $MAX_SCORE -gt 0 ]]; then
    PERCENT=$((SCORE * 100 / MAX_SCORE))
fi
echo -e "${BOLD}  Score: $SCORE/$MAX_SCORE ($PERCENT%)${NC}" | tee -a "$REPORT"

if [[ $PERCENT -ge 80 ]]; then
    echo -e "  ${GREEN}Nivel: EXCELENTE${NC}" | tee -a "$REPORT"
elif [[ $PERCENT -ge 60 ]]; then
    echo -e "  ${GREEN}Nivel: BUENO${NC}" | tee -a "$REPORT"
elif [[ $PERCENT -ge 40 ]]; then
    echo -e "  ${YELLOW}Nivel: PARCIAL${NC}" | tee -a "$REPORT"
else
    echo -e "  ${RED}Nivel: BAJO${NC}" | tee -a "$REPORT"
fi

echo "" | tee -a "$REPORT"
echo -e "${DIM}Reporte: $REPORT${NC}"
logger -t securizar-audit "Network audit: $SCORE/$MAX_SCORE ($PERCENT%)"
EOFAUDIT

    chmod 755 /usr/local/bin/auditoria-red-avanzada.sh
    log_change "Creado" "/usr/local/bin/auditoria-red-avanzada.sh"

    # Cron semanal
    cat > /etc/cron.weekly/auditoria-red-avanzada << 'EOFCRON'
#!/bin/bash
/usr/local/bin/auditoria-red-avanzada.sh > /dev/null 2>&1
EOFCRON
    chmod 700 /etc/cron.weekly/auditoria-red-avanzada
    log_change "Creado" "/etc/cron.weekly/auditoria-red-avanzada"
    log_info "Auditoría de red avanzada instalada"

else
    log_skip "Auditoría de red avanzada"
fi

echo ""
show_changes_summary
log_info "Protección de red avanzada completada"
log_info "Backup en: $BACKUP_DIR"
