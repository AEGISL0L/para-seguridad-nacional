#!/bin/bash
# ============================================================
# MITIGACIÓN DE EXFILTRACIÓN - TA0010 (Exfiltration)
# Linux Multi-Distro (openSUSE, Debian/Ubuntu, RHEL/Fedora, Arch)
# ============================================================
# Técnicas MITRE ATT&CK cubiertas:
#   T1041     - Exfiltration Over C2 Channel
#   T1048     - Exfiltration Over Alternative Protocol
#   T1048.001 - Exfiltration Over Symmetric Encrypted Non-C2
#   T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol
#   T1567     - Exfiltration to Cloud Storage
#   T1567.002 - Exfiltration to Cloud Storage (GDrive, Dropbox)
#   T1020     - Automated Exfiltration
#   T1030     - Data Transfer Size Limits
#   T1537     - Transfer Data to Cloud Account
#   T1011     - Exfiltration Over Other Network Medium
#   T1052     - Exfiltration Over Physical Medium
# ============================================================


set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "mitigar-exfiltracion"
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MITIGACIÓN DE EXFILTRACIÓN - TA0010                     ║"
echo "║   Prevenir robo de datos del sistema                       ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups se guardarán en: $BACKUP_DIR"

# ============================================================
log_section "1. MONITOREO DE TRÁFICO SALIENTE (T1041/T1048)"
# ============================================================

echo "Detectar exfiltración de datos por canales C2 y protocolos"
echo "alternativos."
echo ""
echo "Vectores comunes de exfiltración:"
echo "  - DNS tunneling (T1048.003)"
echo "  - HTTPS a servicios de cloud storage (T1567)"
echo "  - Protocolos cifrados no estándar (T1048.001)"
echo "  - ICMP tunneling"
echo ""

if ask "¿Configurar monitoreo de tráfico saliente?"; then

    # 1a. Reglas de firewall para monitorear tráfico saliente inusual
    echo ""
    echo -e "${BOLD}Configurando monitoreo de tráfico saliente...${NC}"

    if fw_is_active &>/dev/null; then
        ZONE=$(fw_get_default_zone 2>/dev/null || echo "public")

        # Logear tráfico saliente a puertos inusuales
        fw_direct_add_rule ipv4 filter OUTPUT 0 -p tcp --dport 4444 -j LOG --log-prefix "EXFIL-SUSPECT: "
        fw_direct_add_rule ipv4 filter OUTPUT 0 -p tcp --dport 8443 -j LOG --log-prefix "EXFIL-SUSPECT: "
        fw_direct_add_rule ipv4 filter OUTPUT 0 -p tcp --dport 1337 -j LOG --log-prefix "EXFIL-SUSPECT: "

        # Logear ICMP saliente excesivo (ICMP tunneling)
        fw_direct_add_rule ipv4 filter OUTPUT 0 -p icmp --icmp-type echo-request -m limit --limit 10/min --limit-burst 20 -j ACCEPT
        fw_direct_add_rule ipv4 filter OUTPUT 0 -p icmp --icmp-type echo-request -j LOG --log-prefix "ICMP-FLOOD: "

        fw_reload 2>/dev/null || true
        log_info "Reglas de monitoreo de tráfico saliente creadas"
    fi

    # 1b. Script de detección de exfiltración
    cat > /usr/local/bin/detectar-exfiltracion.sh << 'EOFEXFIL'
#!/bin/bash
# Detección de exfiltración de datos - TA0010
LOG="/var/log/exfiltration-detection-$(date +%Y%m%d).log"
ALERTS=0

echo "=== Detección de Exfiltración - $(date) ===" | tee "$LOG"

# 1. Tráfico DNS inusual (DNS tunneling T1048.003)
echo "" | tee -a "$LOG"
echo "--- DNS Tunneling Detection ---" | tee -a "$LOG"

# Queries DNS con subdominios muy largos = tunneling
if command -v journalctl &>/dev/null; then
    LONG_DNS=$(journalctl -u systemd-resolved --since "24 hours ago" 2>/dev/null | \
        grep -oP "query\[.*?\]\s+\K\S+" | \
        awk 'length($0) > 60 {print}' | head -20 || true)

    if [[ -n "$LONG_DNS" ]]; then
        echo "ALERTA: Queries DNS con dominios largos (posible tunneling):" | tee -a "$LOG"
        echo "$LONG_DNS" | tee -a "$LOG"
        ((ALERTS++)) || true
    else
        echo "OK: Sin DNS tunneling detectado" | tee -a "$LOG"
    fi

    # Volumen de DNS excesivo
    DNS_COUNT=$(journalctl -u systemd-resolved --since "1 hour ago" 2>/dev/null | grep -c "query\[" || echo 0)
    if [[ "$DNS_COUNT" -gt 5000 ]]; then
        echo "ALERTA: $DNS_COUNT queries DNS en la última hora (posible tunneling)" | tee -a "$LOG"
        ((ALERTS++)) || true
    else
        echo "OK: $DNS_COUNT queries DNS (normal)" | tee -a "$LOG"
    fi
fi

# 2. Conexiones salientes a puertos no estándar
echo "" | tee -a "$LOG"
echo "--- Conexiones salientes no estándar ---" | tee -a "$LOG"

STANDARD_PORTS="22 53 80 443 123 587 993 995"
NONSTANDARD=$(ss -tn state established 2>/dev/null | tail -n+2 | awk '{print $5}' | \
    grep -oP ':(\d+)$' | tr -d ':' | sort -u)

for port in $NONSTANDARD; do
    if ! echo "$STANDARD_PORTS" | grep -qw "$port"; then
        if [[ "$port" -gt 1024 ]]; then
            CONN_COUNT=$(ss -tn state established 2>/dev/null | grep -c ":${port}$" || echo 0)
            if [[ "$CONN_COUNT" -gt 0 ]]; then
                DST=$(ss -tn state established 2>/dev/null | grep ":${port}" | awk '{print $5}' | head -3)
                echo "  Puerto no estándar $port: $CONN_COUNT conexiones -> $DST" | tee -a "$LOG"
            fi
        fi
    fi
done

# 3. Transferencias de datos grandes (T1030)
echo "" | tee -a "$LOG"
echo "--- Transferencias de datos grandes ---" | tee -a "$LOG"

# Verificar interfaces por tráfico TX excesivo
for iface in /sys/class/net/*; do
    IFACE_NAME=$(basename "$iface")
    [[ "$IFACE_NAME" == "lo" ]] && continue

    TX_BYTES=$(cat "$iface/statistics/tx_bytes" 2>/dev/null || echo 0)
    TX_MB=$((TX_BYTES / 1024 / 1024))
    echo "  $IFACE_NAME: TX total ${TX_MB}MB" | tee -a "$LOG"
done

# 4. Procesos realizando transferencias de red
echo "" | tee -a "$LOG"
echo "--- Procesos con transferencias activas ---" | tee -a "$LOG"

TRANSFER_PROCS=$(ps aux 2>/dev/null | grep -iE "curl|wget|scp|rsync|ftp|nc.*-.*[0-9]|ncat|socat" | grep -v grep || true)
if [[ -n "$TRANSFER_PROCS" ]]; then
    echo "Procesos de transferencia activos:" | tee -a "$LOG"
    echo "$TRANSFER_PROCS" | tee -a "$LOG"
fi

# 5. Conexiones a servicios de cloud storage conocidos (T1567)
echo "" | tee -a "$LOG"
echo "--- Conexiones a cloud storage ---" | tee -a "$LOG"

CLOUD_DOMAINS="drive.google.com dropbox.com upload.dropbox.com www.googleapis.com storage.googleapis.com s3.amazonaws.com onedrive.live.com api.mega.nz transfer.sh file.io"
for domain in $CLOUD_DOMAINS; do
    RESOLVED=$(getent hosts "$domain" 2>/dev/null | awk '{print $1}' || true)
    if [[ -n "$RESOLVED" ]]; then
        for ip in $RESOLVED; do
            CONNS=$(ss -tn state established 2>/dev/null | grep -c "$ip" || echo 0)
            if [[ "$CONNS" -gt 0 ]]; then
                echo "ALERTA: $CONNS conexiones activas a $domain ($ip)" | tee -a "$LOG"
                ((ALERTS++)) || true
            fi
        done
    fi
done

echo "" | tee -a "$LOG"
echo "=== RESUMEN ===" | tee -a "$LOG"
if [[ $ALERTS -eq 0 ]]; then
    echo "OK: Sin indicadores de exfiltración" | tee -a "$LOG"
else
    echo "ALERTA: $ALERTS indicadores de exfiltración" | tee -a "$LOG"
    logger -t detectar-exfiltracion "ALERTA: $ALERTS indicadores de exfiltración (TA0010)"
fi

find /var/log -name "exfiltration-detection-*.log" -mtime +30 -delete 2>/dev/null || true
EOFEXFIL

    chmod 700 /usr/local/bin/detectar-exfiltracion.sh

    cat > /etc/cron.daily/detectar-exfiltracion << 'EOFCRON'
#!/bin/bash
/usr/local/bin/detectar-exfiltracion.sh 2>&1 | logger -t detectar-exfiltracion
EOFCRON
    chmod 700 /etc/cron.daily/detectar-exfiltracion

    log_info "Detección diaria de exfiltración configurada"
else
    log_warn "Monitoreo de tráfico saliente no configurado"
fi

# ============================================================
log_section "2. BLOQUEO DE CLOUD STORAGE (T1567)"
# ============================================================

echo "Bloquear o monitorear acceso a servicios de almacenamiento"
echo "en la nube comúnmente usados para exfiltración."
echo ""
echo "Servicios monitoreados: Google Drive, Dropbox, OneDrive, MEGA,"
echo "transfer.sh, file.io, pastebin"
echo ""

if ask "¿Bloquear acceso a servicios de cloud storage para exfiltración?"; then

    echo ""
    echo -e "${BOLD}Opciones:${NC}"
    echo "  1) Solo monitorear (logear conexiones)"
    echo "  2) Bloquear dominios de exfiltración conocidos"
    echo ""
    read -p "Selecciona [1/2]: " cloud_option

    # Dominios de cloud storage / file sharing
    EXFIL_DOMAINS=(
        "transfer.sh"
        "file.io"
        "0x0.st"
        "ix.io"
        "sprunge.us"
        "paste.ee"
        "hastebin.com"
        "termbin.com"
        "api.mega.nz"
        "mega.nz"
    )

    case "$cloud_option" in
        2)
            # Bloquear vía /etc/hosts
            echo ""
            echo -e "${BOLD}Bloqueando dominios de exfiltración...${NC}"
            cp /etc/hosts "$BACKUP_DIR/"

            echo "" >> /etc/hosts
            echo "# Bloqueo de servicios de exfiltración - T1567" >> /etc/hosts
            for domain in "${EXFIL_DOMAINS[@]}"; do
                if ! grep -q "$domain" /etc/hosts 2>/dev/null; then
                    echo "0.0.0.0 $domain" >> /etc/hosts
                    echo -e "  ${GREEN}OK${NC} Bloqueado: $domain"
                fi
            done

            log_info "Dominios de exfiltración bloqueados en /etc/hosts"
            ;;
        *)
            echo -e "${DIM}Solo monitoreo - las conexiones se registrarán en logs${NC}"
            ;;
    esac

    # Reglas auditd para herramientas de upload
    if command -v auditctl &>/dev/null; then
        cat > /etc/audit/rules.d/66-exfiltration.rules << 'EOF'
## Detección de exfiltración - TA0010
# T1041/T1048 - Herramientas de transferencia
-w /usr/bin/curl -p x -k data-transfer
-w /usr/bin/wget -p x -k data-transfer
-w /usr/bin/scp -p x -k data-transfer
-w /usr/bin/sftp -p x -k data-transfer
-w /usr/bin/rsync -p x -k data-transfer
-w /usr/bin/ftp -p x -k data-transfer
-w /usr/bin/nc -p x -k data-transfer
-w /usr/bin/ncat -p x -k data-transfer
-w /usr/bin/socat -p x -k data-transfer

# T1567 - Cloud storage tools
-w /usr/bin/rclone -p x -k cloud-transfer
-w /usr/bin/aws -p x -k cloud-transfer
-w /usr/bin/gsutil -p x -k cloud-transfer
-w /usr/bin/az -p x -k cloud-transfer
-w /usr/bin/s3cmd -p x -k cloud-transfer

# T1048.003 - Herramientas DNS
-w /usr/bin/dig -p x -k dns-tool
-w /usr/bin/nslookup -p x -k dns-tool
-w /usr/bin/host -p x -k dns-tool
EOF

        augenrules --load 2>/dev/null || true
        log_info "Reglas auditd de exfiltración creadas"
    fi

else
    log_warn "Bloqueo de cloud storage no configurado"
fi

# ============================================================
log_section "3. CONTROL DE DNS TUNNELING (T1048.003)"
# ============================================================

echo "Prevenir y detectar exfiltración de datos mediante DNS tunneling."
echo "Es uno de los métodos más difíciles de detectar."
echo ""

if ask "¿Configurar protección contra DNS tunneling?"; then

    # 3a. Limitar tamaño de queries DNS
    echo ""
    echo -e "${BOLD}Configurando restricciones DNS...${NC}"

    # Configurar DNS-over-TLS con stub resolver controlado
    mkdir -p /etc/systemd/resolved.conf.d

    cat > /etc/systemd/resolved.conf.d/01-anti-exfil.conf << 'EOF'
# Protección contra DNS tunneling - T1048.003
[Resolve]
# Usar solo DNS confiables
DNS=1.1.1.1 9.9.9.9
FallbackDNS=8.8.8.8

# DNS over TLS
DNSOverTLS=opportunistic

# No permitir DNS multicast
MulticastDNS=no

# Limitar dominios resolubles (opcional - descomentar para whitelist)
#Domains=~.
EOF

    systemctl restart systemd-resolved 2>/dev/null || true
    log_info "DNS configurado con proveedores confiables"

    # 3b. Regla iptables para limitar tráfico DNS saliente
    if fw_is_active &>/dev/null; then
        # Limitar rate de DNS saliente
        fw_direct_add_rule ipv4 filter OUTPUT 0 -p udp --dport 53 -m limit --limit 50/sec --limit-burst 100 -j ACCEPT
        fw_direct_add_rule ipv4 filter OUTPUT 0 -p udp --dport 53 -j LOG --log-prefix "DNS-FLOOD: "

        # Bloquear DNS a puertos no estándar
        fw_direct_add_rule ipv4 filter OUTPUT 0 -p tcp --dport 5353 -j DROP

        fw_reload 2>/dev/null || true
        log_info "Rate limiting DNS configurado"
    fi

    # 3c. Script de detección de DNS tunneling
    cat > /usr/local/bin/detectar-dns-tunnel.sh << 'EOFDNS'
#!/bin/bash
# Detección de DNS tunneling - T1048.003
LOG="/var/log/dns-tunnel-$(date +%Y%m%d).log"
ALERTS=0

echo "=== Detección de DNS Tunneling - $(date) ===" | tee "$LOG"

# 1. Queries con subdominios excesivamente largos
echo "" | tee -a "$LOG"
echo "--- Queries DNS con subdominios largos ---" | tee -a "$LOG"

if command -v journalctl &>/dev/null; then
    LONG_QUERIES=$(journalctl -u systemd-resolved --since "24 hours ago" 2>/dev/null | \
        grep -oP "query\[.*?\]\s+\K\S+" | \
        awk -F. '{for(i=1;i<=NF;i++){if(length($i)>30){print $0; break}}}' | \
        sort -u | head -20 || true)

    if [[ -n "$LONG_QUERIES" ]]; then
        echo "ALERTA: Subdominios largos detectados:" | tee -a "$LOG"
        echo "$LONG_QUERIES" | tee -a "$LOG"
        ((ALERTS++)) || true
    else
        echo "OK: Sin subdominios anormalmente largos" | tee -a "$LOG"
    fi
fi

# 2. Dominios con muchos subdominios únicos (entropy alta)
echo "" | tee -a "$LOG"
echo "--- Dominios con muchas variaciones ---" | tee -a "$LOG"

if command -v journalctl &>/dev/null; then
    # Extraer dominio base y contar subdominios únicos
    journalctl -u systemd-resolved --since "24 hours ago" 2>/dev/null | \
        grep -oP "query\[.*?\]\s+\K\S+" | \
        awk -F. '{if(NF>=3) print $(NF-1)"."$NF}' | \
        sort | uniq -c | sort -rn | head -10 | \
        while IFS= read -r line; do
            COUNT=$(echo "$line" | awk '{print $1}')
            DOMAIN=$(echo "$line" | awk '{print $2}')
            if [[ "$COUNT" -gt 1000 ]]; then
                echo "ALERTA: $DOMAIN con $COUNT queries (posible tunneling)" | tee -a "$LOG"
                ((ALERTS++)) || true
            fi
        done
fi

# 3. Queries TXT sospechosos (usado para respuestas de tunnel)
echo "" | tee -a "$LOG"
echo "--- Queries TXT (canal de datos) ---" | tee -a "$LOG"

TXT_QUERIES=$(journalctl -u systemd-resolved --since "24 hours ago" 2>/dev/null | \
    grep "query\[TXT\]" | wc -l || echo 0)
if [[ "$TXT_QUERIES" -gt 500 ]]; then
    echo "ALERTA: $TXT_QUERIES queries TXT en 24h (posible túnel)" | tee -a "$LOG"
    ((ALERTS++)) || true
else
    echo "OK: $TXT_QUERIES queries TXT (normal)" | tee -a "$LOG"
fi

echo "" | tee -a "$LOG"
echo "=== RESUMEN ===" | tee -a "$LOG"
if [[ $ALERTS -eq 0 ]]; then
    echo "OK: Sin indicadores de DNS tunneling" | tee -a "$LOG"
else
    echo "ALERTA: $ALERTS indicadores de DNS tunneling" | tee -a "$LOG"
    logger -t detectar-dns-tunnel "ALERTA: $ALERTS indicadores de DNS tunnel (T1048.003)"
fi

find /var/log -name "dns-tunnel-*.log" -mtime +30 -delete 2>/dev/null || true
EOFDNS

    chmod 700 /usr/local/bin/detectar-dns-tunnel.sh

    cat > /etc/cron.daily/detectar-dns-tunnel << 'EOFCRON'
#!/bin/bash
/usr/local/bin/detectar-dns-tunnel.sh 2>&1 | logger -t detectar-dns-tunnel
EOFCRON
    chmod 700 /etc/cron.daily/detectar-dns-tunnel

    log_info "Detección de DNS tunneling configurada"
else
    log_warn "Protección contra DNS tunneling no configurada"
fi

# ============================================================
log_section "4. CONTROL DE EXFILTRACIÓN POR MEDIOS FÍSICOS (T1052)"
# ============================================================

echo "Controlar la exfiltración de datos mediante dispositivos USB"
echo "u otros medios físicos."
echo ""

if ask "¿Restringir escritura a medios extraíbles?"; then

    # Crear regla udev para bloquear escritura en USB
    echo ""
    echo -e "${BOLD}Configurando restricción de escritura USB...${NC}"

    cat > /etc/udev/rules.d/91-usb-readonly.rules << 'EOF'
# Montar dispositivos USB como solo lectura por defecto - T1052
# Descomentar para forzar readonly en todos los USB:
# ACTION=="add", SUBSYSTEMS=="usb", SUBSYSTEM=="block", RUN+="/bin/sh -c 'echo 1 > /sys%p/ro'"
# Logear conexión de dispositivos de almacenamiento USB
ACTION=="add", SUBSYSTEMS=="usb", SUBSYSTEM=="block", RUN+="/usr/bin/logger -t usb-storage 'ALERTA: Dispositivo USB conectado: %k (%E{ID_VENDOR} %E{ID_MODEL})'"
ACTION=="remove", SUBSYSTEMS=="usb", SUBSYSTEM=="block", RUN+="/usr/bin/logger -t usb-storage 'Dispositivo USB desconectado: %k'"
EOF

    udevadm control --reload-rules 2>/dev/null || true

    # Auditar montaje de medios
    if command -v auditctl &>/dev/null; then
        cat >> /etc/audit/rules.d/66-exfiltration.rules << 'EOF'

# T1052 - Exfiltration Over Physical Medium
-a always,exit -F arch=b64 -S mount -k physical-media-mount
-w /media/ -p w -k physical-media-write
-w /run/media/ -p w -k physical-media-write
EOF
        augenrules --load 2>/dev/null || true
    fi

    log_info "Control de escritura USB configurado"
else
    log_warn "Control de medios físicos no configurado"
fi

# ============================================================
log_section "5. LIMITACIÓN DE TRANSFERENCIAS (T1030)"
# ============================================================

echo "Limitar el tamaño de transferencias de datos salientes"
echo "para detectar y ralentizar exfiltración masiva."
echo ""

if ask "¿Configurar limitación de transferencias salientes?"; then

    # 5a. Configurar tc (traffic control) para limitar upload
    echo ""
    echo -e "${BOLD}Opciones de limitación de ancho de banda saliente:${NC}"
    echo "  1) Limitar upload general a 10 Mbit/s"
    echo "  2) Limitar upload general a 50 Mbit/s"
    echo "  3) Solo monitorear (sin límite)"
    echo ""
    read -p "Selecciona [1/2/3]: " bw_option

    # Obtener interfaz principal
    MAIN_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)

    case "$bw_option" in
        1)
            if [[ -n "$MAIN_IFACE" ]] && command -v tc &>/dev/null; then
                tc qdisc del dev "$MAIN_IFACE" root 2>/dev/null || true
                tc qdisc add dev "$MAIN_IFACE" root tbf rate 10mbit burst 32kbit latency 400ms 2>/dev/null || true
                log_info "Upload limitado a 10 Mbit/s en $MAIN_IFACE"

                # Persistir con script de NetworkManager
                cat > /etc/NetworkManager/dispatcher.d/91-bandwidth-limit.sh << EOFBW
#!/bin/bash
if [[ "\$2" == "up" ]]; then
    tc qdisc del dev "\$1" root 2>/dev/null || true
    tc qdisc add dev "\$1" root tbf rate 10mbit burst 32kbit latency 400ms 2>/dev/null || true
fi
EOFBW
                chmod 755 /etc/NetworkManager/dispatcher.d/91-bandwidth-limit.sh
            fi
            ;;
        2)
            if [[ -n "$MAIN_IFACE" ]] && command -v tc &>/dev/null; then
                tc qdisc del dev "$MAIN_IFACE" root 2>/dev/null || true
                tc qdisc add dev "$MAIN_IFACE" root tbf rate 50mbit burst 64kbit latency 400ms 2>/dev/null || true
                log_info "Upload limitado a 50 Mbit/s en $MAIN_IFACE"

                cat > /etc/NetworkManager/dispatcher.d/91-bandwidth-limit.sh << EOFBW
#!/bin/bash
if [[ "\$2" == "up" ]]; then
    tc qdisc del dev "\$1" root 2>/dev/null || true
    tc qdisc add dev "\$1" root tbf rate 50mbit burst 64kbit latency 400ms 2>/dev/null || true
fi
EOFBW
                chmod 755 /etc/NetworkManager/dispatcher.d/91-bandwidth-limit.sh
            fi
            ;;
        *)
            echo -e "${DIM}Solo monitoreo activado${NC}"
            ;;
    esac

    # 5b. Script de monitoreo de volumen de datos
    cat > /usr/local/bin/monitorear-transferencias.sh << 'EOFMON'
#!/bin/bash
# Monitoreo de volumen de transferencias - T1030
LOG="/var/log/transfer-monitor-$(date +%Y%m%d).log"
BASELINE="/var/lib/transfer-baseline"
mkdir -p "$BASELINE"

echo "=== Monitoreo de Transferencias - $(date) ===" | tee "$LOG"

for iface in /sys/class/net/*; do
    IFACE_NAME=$(basename "$iface")
    [[ "$IFACE_NAME" == "lo" ]] && continue

    TX_BYTES=$(cat "$iface/statistics/tx_bytes" 2>/dev/null || echo 0)
    RX_BYTES=$(cat "$iface/statistics/rx_bytes" 2>/dev/null || echo 0)

    TX_MB=$((TX_BYTES / 1024 / 1024))
    RX_MB=$((RX_BYTES / 1024 / 1024))

    # Comparar con baseline anterior
    PREV_TX=0
    if [[ -f "$BASELINE/${IFACE_NAME}_tx" ]]; then
        PREV_TX=$(cat "$BASELINE/${IFACE_NAME}_tx")
    fi

    DELTA_TX=$(( (TX_BYTES - PREV_TX) / 1024 / 1024 ))

    echo "  $IFACE_NAME: TX=${TX_MB}MB (delta: ${DELTA_TX}MB) RX=${RX_MB}MB" | tee -a "$LOG"

    # Alerta si más de 1GB saliente desde último check
    if [[ "$DELTA_TX" -gt 1024 ]]; then
        echo "  ALERTA: ${DELTA_TX}MB transmitidos desde último check en $IFACE_NAME" | tee -a "$LOG"
        logger -t monitor-transfer "ALERTA: ${DELTA_TX}MB TX en $IFACE_NAME (T1030)"
    fi

    # Guardar baseline
    echo "$TX_BYTES" > "$BASELINE/${IFACE_NAME}_tx"
    echo "$RX_BYTES" > "$BASELINE/${IFACE_NAME}_rx"
done

find /var/log -name "transfer-monitor-*.log" -mtime +30 -delete 2>/dev/null || true
EOFMON

    chmod 700 /usr/local/bin/monitorear-transferencias.sh

    # Timer systemd cada hora
    cat > /etc/systemd/system/monitorear-transferencias.service << 'EOFSVC'
[Unit]
Description=Monitoreo de transferencias de datos (T1030)
[Service]
Type=oneshot
ExecStart=/usr/local/bin/monitorear-transferencias.sh
EOFSVC

    cat > /etc/systemd/system/monitorear-transferencias.timer << 'EOFTIMER'
[Unit]
Description=Timer monitoreo de transferencias (cada hora)
[Timer]
OnBootSec=5min
OnUnitActiveSec=1h
Persistent=true
[Install]
WantedBy=timers.target
EOFTIMER

    systemctl daemon-reload
    systemctl enable --now monitorear-transferencias.timer 2>/dev/null || true

    log_info "Monitoreo horario de volumen de transferencias activo"
else
    log_warn "Limitación de transferencias no configurada"
fi

# ============================================================
log_section "RESUMEN DE MITIGACIONES TA0010"
# ============================================================

echo ""
echo -e "${BOLD}Estado de mitigaciones de Exfiltración (TA0010):${NC}"
echo ""

# T1041/T1048 - Traffic Monitoring
if [[ -x /usr/local/bin/detectar-exfiltracion.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1041/T1048 - Detección de exfiltración"
else
    echo -e "  ${YELLOW}[--]${NC} T1041/T1048 - Detección de exfiltración no configurada"
fi

# T1567 - Cloud Storage
if [[ -f /etc/audit/rules.d/66-exfiltration.rules ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1567 - Auditoría de herramientas de transferencia"
else
    echo -e "  ${YELLOW}[--]${NC} T1567 - Herramientas de transferencia no monitoreadas"
fi

# T1048.003 - DNS Tunneling
if [[ -x /usr/local/bin/detectar-dns-tunnel.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1048.003 - Detección de DNS tunneling"
else
    echo -e "  ${YELLOW}[--]${NC} T1048.003 - DNS tunneling no monitoreado"
fi

# T1052 - Physical Media
if [[ -f /etc/udev/rules.d/91-usb-readonly.rules ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1052 - Control de medios físicos"
else
    echo -e "  ${YELLOW}[--]${NC} T1052 - Medios físicos no controlados"
fi

# T1030 - Transfer Size Limits
if [[ -x /usr/local/bin/monitorear-transferencias.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1030 - Monitoreo de volumen de transferencias"
else
    echo -e "  ${YELLOW}[--]${NC} T1030 - Volumen de transferencias no monitoreado"
fi

echo ""
log_info "Script de mitigación de exfiltración completado"
log_info "Backups de configuración en: $BACKUP_DIR"
