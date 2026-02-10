#!/bin/bash
# ============================================================
# MITIGACIÓN DE COMANDO Y CONTROL - TA0011 (Command and Control)
# Linux Multi-Distro (openSUSE, Debian/Ubuntu, RHEL/Fedora, Arch)
# ============================================================
# Técnicas MITRE ATT&CK cubiertas:
#   T1071     - Application Layer Protocol
#   T1071.001 - Web Protocols (HTTP/HTTPS C2)
#   T1071.004 - DNS (DNS C2)
#   T1573     - Encrypted Channel
#   T1573.001 - Symmetric Cryptography
#   T1573.002 - Asymmetric Cryptography
#   T1105     - Ingress Tool Transfer
#   T1090     - Proxy
#   T1090.001 - Internal Proxy
#   T1090.002 - External Proxy
#   T1572     - Protocol Tunneling
#   T1571     - Non-Standard Port
#   T1132     - Data Encoding (C2 encoding)
#   T1568     - Dynamic Resolution (DGA)
#   T1095     - Non-Application Layer Protocol (ICMP C2)
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "mitigar-comando-control"
securizar_setup_traps
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MITIGACIÓN DE COMANDO Y CONTROL - TA0011                ║"
echo "║   Detectar y bloquear canales C2 del atacante              ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups se guardarán en: $BACKUP_DIR"

# ============================================================
log_section "1. BLOQUEO DE PUERTOS NO ESTÁNDAR (T1571)"
# ============================================================

echo "Bloquear conexiones salientes a puertos no estándar."
echo "Muchos frameworks C2 usan puertos como 4444, 8080, 1337, etc."
echo ""
echo "Puertos estándar permitidos: 80, 443, 53, 22, 123, 587, 993"
echo ""

if ask "¿Restringir tráfico saliente a puertos estándar?"; then

    if fw_is_active &>/dev/null; then
        echo ""
        echo -e "${BOLD}Configurando whitelist de puertos salientes...${NC}"

        # Puertos salientes permitidos
        ALLOWED_PORTS="22 53 80 123 443 587 993 995 853 8080"

        # Logear tráfico a puertos C2 conocidos
        C2_PORTS="4444 5555 6666 7777 8888 9999 1234 1337 31337 12345 54321 6667 6668 6669"

        for port in $C2_PORTS; do
            fw_direct_add_rule ipv4 filter OUTPUT 0 \
                -p tcp --dport "$port" -j LOG --log-prefix "C2-PORT-$port: " 2>/dev/null || true
            fw_direct_add_rule ipv4 filter OUTPUT 0 \
                -p tcp --dport "$port" -j DROP 2>/dev/null || true
        done

        fw_reload 2>/dev/null || true
        log_info "Puertos C2 conocidos bloqueados y logeados"

        echo ""
        echo -e "${DIM}Puertos bloqueados: $C2_PORTS${NC}"
        echo -e "${DIM}Para permitir un puerto: firewall-cmd --permanent --direct --remove-rule ipv4 filter OUTPUT 0 -p tcp --dport <port> -j DROP${NC}"
    else
        log_warn "firewalld no disponible"
    fi

else
    log_skip "Restricción de puertos salientes no aplicada"
    log_warn "Restricción de puertos salientes no aplicada"
fi

# ============================================================
log_section "2. DETECCIÓN DE C2 POR PROTOCOLO WEB (T1071.001)"
# ============================================================

echo "Detectar tráfico C2 oculto en HTTP/HTTPS."
echo "Frameworks como Cobalt Strike, Metasploit, Sliver usan"
echo "HTTP/HTTPS para comunicación C2."
echo ""

if ask "¿Configurar detección de C2 sobre HTTP/HTTPS?"; then

    # 2a. Configurar Suricata si está disponible
    if command -v suricata &>/dev/null; then
        echo ""
        echo -e "${BOLD}Añadiendo reglas Suricata para C2...${NC}"

        SURICATA_RULES="/etc/suricata/rules/local-c2.rules"
        mkdir -p /etc/suricata/rules
        log_change "Creado" "/etc/suricata/rules/"

        cat > "$SURICATA_RULES" << 'EOF'
# Detección de C2 sobre HTTP - T1071.001

# Cobalt Strike - Beacon default
alert http any any -> any any (msg:"C2 - Posible Cobalt Strike Beacon"; content:"GET"; http_method; content:"/pixel"; http_uri; sid:9000001; rev:1;)
alert http any any -> any any (msg:"C2 - Posible Cobalt Strike malleable"; content:"GET"; http_method; pcre:"/\/[a-zA-Z0-9]{4}$/U"; flow:to_server,established; threshold:type threshold, track by_src, count 10, seconds 60; sid:9000002; rev:1;)

# Meterpreter HTTP stager
alert http any any -> any any (msg:"C2 - Posible Meterpreter HTTP stager"; content:"GET"; http_method; content:"/"; http_uri; pcre:"/^\/[A-Za-z0-9_-]{4,8}$/U"; flow:to_server,established; threshold:type threshold, track by_src, count 5, seconds 30; sid:9000003; rev:1;)

# Sliver C2
alert http any any -> any any (msg:"C2 - Posible Sliver implant"; content:"POST"; http_method; content:"application/octet-stream"; http_header; flow:to_server,established; threshold:type threshold, track by_src, count 5, seconds 60; sid:9000004; rev:1;)

# Generic C2 beaconing (conexiones periódicas regulares)
alert tcp any any -> any 443 (msg:"C2 - Posible beaconing HTTPS"; flow:to_server,established; threshold:type threshold, track by_src, count 60, seconds 3600; sid:9000005; rev:1;)

# Reverse shell patterns
alert tcp any any -> any any (msg:"C2 - Posible reverse shell bash"; content:"|2f 62 69 6e 2f|"; content:"|73 68|"; within:20; sid:9000006; rev:1;)
alert tcp any any -> any any (msg:"C2 - Posible reverse shell python"; content:"import socket"; content:"subprocess"; within:200; sid:9000007; rev:1;)
EOF

        log_change "Creado" "$SURICATA_RULES"
        # Incluir reglas locales en suricata
        if [[ -f /etc/suricata/suricata.yaml ]]; then
            if ! grep -q "local-c2.rules" /etc/suricata/suricata.yaml 2>/dev/null; then
                echo "  - rules/local-c2.rules" >> /etc/suricata/suricata.yaml
                log_change "Modificado" "/etc/suricata/suricata.yaml"
                log_info "Reglas C2 añadidas a Suricata"
            fi
        fi

        systemctl reload suricata 2>/dev/null || true
        log_change "Servicio" "suricata reload"
    else
        echo -e "  ${YELLOW}!!${NC} Suricata no instalado (recomendado para detección de C2)"
    fi

    # 2b. Script de detección de beaconing
    cat > /usr/local/bin/detectar-beaconing.sh << 'EOFBEACON'
#!/bin/bash
# Detección de C2 beaconing - T1071.001
LOG="/var/log/beaconing-detection-$(date +%Y%m%d).log"
ALERTS=0

echo "=== Detección de C2 Beaconing - $(date) ===" | tee "$LOG"

# 1. Conexiones HTTPS persistentes a la misma IP
echo "" | tee -a "$LOG"
echo "--- Conexiones HTTPS persistentes ---" | tee -a "$LOG"

PERSISTENT=$(ss -tn state established 2>/dev/null | awk '{print $5}' | \
    grep ":443$" | grep -oP "^[^:]*" | \
    sort | uniq -c | sort -rn | head -20)

if [[ -n "$PERSISTENT" ]]; then
    echo "$PERSISTENT" | tee -a "$LOG"
    while IFS= read -r line; do
        COUNT=$(echo "$line" | awk '{print $1}')
        IP=$(echo "$line" | awk '{print $2}')
        if [[ "$COUNT" -gt 10 ]]; then
            # Verificar si es un servicio conocido
            REVERSE=$(host "$IP" 2>/dev/null | grep "domain name pointer" | awk '{print $NF}' || echo "N/A")
            echo "  NOTA: $IP ($REVERSE) con $COUNT conexiones" | tee -a "$LOG"
        fi
    done <<< "$PERSISTENT"
fi

# 2. Detección de intervalos regulares (beaconing)
echo "" | tee -a "$LOG"
echo "--- Patrones de beaconing en logs ---" | tee -a "$LOG"

# Buscar en logs de Suricata
if [[ -f /var/log/suricata/fast.log ]]; then
    C2_ALERTS=$(grep -c "C2 -\|beaconing\|Beacon" /var/log/suricata/fast.log 2>/dev/null || echo 0)
    if [[ "$C2_ALERTS" -gt 0 ]]; then
        echo "ALERTA: $C2_ALERTS alertas C2 en Suricata" | tee -a "$LOG"
        grep "C2 -" /var/log/suricata/fast.log 2>/dev/null | tail -10 | tee -a "$LOG"
        ((ALERTS++)) || true
    fi
fi

# 3. Conexiones a IPs sin reverse DNS (sospechoso para C2)
echo "" | tee -a "$LOG"
echo "--- IPs sin reverse DNS ---" | tee -a "$LOG"

ESTABLISHED_IPS=$(ss -tn state established 2>/dev/null | awk '{print $5}' | \
    grep -oP "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | sort -u)

NO_DNS_COUNT=0
for ip in $ESTABLISHED_IPS; do
    # Saltar redes privadas
    if echo "$ip" | grep -qP "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)"; then
        continue
    fi
    RDNS=$(host "$ip" 2>/dev/null | grep "domain name pointer" || true)
    if [[ -z "$RDNS" ]]; then
        ((NO_DNS_COUNT++)) || true
        if [[ $NO_DNS_COUNT -le 10 ]]; then
            echo "  Sin rDNS: $ip" | tee -a "$LOG"
        fi
    fi
done
echo "  Total IPs públicas sin rDNS: $NO_DNS_COUNT" | tee -a "$LOG"

if [[ "$NO_DNS_COUNT" -gt 20 ]]; then
    echo "ALERTA: Muchas conexiones a IPs sin reverse DNS" | tee -a "$LOG"
    ((ALERTS++)) || true
fi

# 4. Procesos C2/RAT conocidos
echo "" | tee -a "$LOG"
echo "--- Herramientas C2/RAT conocidas ---" | tee -a "$LOG"

C2_TOOLS=$(ps aux 2>/dev/null | grep -iE "meterpreter|beacon|sliver|covenant|empire|pupy|quasar|njrat|cobalt|havoc|mythic|poshc2|villain" | grep -v grep || true)
if [[ -n "$C2_TOOLS" ]]; then
    echo "ALERTA: Herramientas C2/RAT detectadas:" | tee -a "$LOG"
    echo "$C2_TOOLS" | tee -a "$LOG"
    ((ALERTS++)) || true
    logger -t detectar-beaconing "ALERTA CRÍTICA: Herramientas C2/RAT activas"
else
    echo "OK: Sin herramientas C2 conocidas" | tee -a "$LOG"
fi

echo "" | tee -a "$LOG"
echo "=== RESUMEN ===" | tee -a "$LOG"
if [[ $ALERTS -eq 0 ]]; then
    echo "OK: Sin indicadores de C2 beaconing" | tee -a "$LOG"
else
    echo "ALERTA: $ALERTS indicadores de C2 detectados" | tee -a "$LOG"
    logger -t detectar-beaconing "ALERTA: $ALERTS indicadores de C2 (T1071)"
fi

find /var/log -name "beaconing-detection-*.log" -mtime +30 -delete 2>/dev/null || true
EOFBEACON

    log_change "Creado" "/usr/local/bin/detectar-beaconing.sh"
    chmod 700 /usr/local/bin/detectar-beaconing.sh
    log_change "Permisos" "/usr/local/bin/detectar-beaconing.sh -> 700"

    cat > /etc/cron.daily/detectar-beaconing << 'EOFCRON'
#!/bin/bash
/usr/local/bin/detectar-beaconing.sh 2>&1 | logger -t detectar-beaconing
EOFCRON
    log_change "Creado" "/etc/cron.daily/detectar-beaconing"
    chmod 700 /etc/cron.daily/detectar-beaconing
    log_change "Permisos" "/etc/cron.daily/detectar-beaconing -> 700"

    log_info "Detección de C2 beaconing configurada"
else
    log_skip "Detección de C2 HTTP/HTTPS no configurada"
    log_warn "Detección de C2 HTTP/HTTPS no configurada"
fi

# ============================================================
log_section "3. DETECCIÓN DE INGRESS TOOL TRANSFER (T1105)"
# ============================================================

echo "Detectar y controlar la descarga de herramientas del atacante."
echo "Después de obtener acceso, atacantes descargan herramientas"
echo "adicionales (escalada, C2, exfiltración)."
echo ""

if ask "¿Configurar control de descarga de herramientas?"; then

    # 3a. Auditoría de descarga de binarios
    if command -v auditctl &>/dev/null; then
        mkdir -p /etc/audit/rules.d
        cat > /etc/audit/rules.d/67-command-control.rules << 'EOF'
## Detección de Command and Control - TA0011
# T1105 - Ingress Tool Transfer
-w /usr/bin/curl -p x -k tool-download
-w /usr/bin/wget -p x -k tool-download
-w /usr/bin/fetch -p x -k tool-download

# Monitorear creación de ejecutables en /tmp
-a always,exit -F arch=b64 -S creat -S open -S openat -F dir=/tmp -F perm=x -k tmp-executable
-a always,exit -F arch=b64 -S creat -S open -S openat -F dir=/var/tmp -F perm=x -k tmp-executable
-a always,exit -F arch=b64 -S creat -S open -S openat -F dir=/dev/shm -F perm=x -k tmp-executable

# Monitorear chmod +x en rutas temporales
-a always,exit -F arch=b64 -S chmod -S fchmod -F dir=/tmp -k tmp-chmod-exec
-a always,exit -F arch=b64 -S chmod -S fchmod -F dir=/var/tmp -k tmp-chmod-exec
-a always,exit -F arch=b64 -S chmod -S fchmod -F dir=/dev/shm -k tmp-chmod-exec
EOF

        log_change "Creado" "/etc/audit/rules.d/67-command-control.rules"
        augenrules --load 2>/dev/null || true
        log_change "Aplicado" "augenrules --load"
        log_info "Reglas auditd para transferencia de herramientas creadas"
    fi

    # 3b. Montar /tmp, /var/tmp, /dev/shm con noexec
    echo ""
    echo -e "${BOLD}Verificando particiones temporales...${NC}"

    for tmpdir in "/tmp" "/var/tmp" "/dev/shm"; do
        MOUNT_OPTS=$(mount 2>/dev/null | grep " $tmpdir " | grep -oP '\(.*?\)')
        if [[ -n "$MOUNT_OPTS" ]]; then
            if ! echo "$MOUNT_OPTS" | grep -q "noexec"; then
                echo -e "  ${YELLOW}!!${NC} $tmpdir montado SIN noexec ($MOUNT_OPTS)"
                if ask "  ¿Remontar $tmpdir con noexec?"; then
                    mount -o remount,noexec,nosuid,nodev "$tmpdir" 2>/dev/null && \
                        log_info "$tmpdir remontado con noexec" || \
                        log_warn "No se pudo remontar $tmpdir"
                    log_change "Aplicado" "mount -o remount,noexec,nosuid,nodev $tmpdir"
                else
                    log_skip "Remontar $tmpdir con noexec"
                fi
            else
                echo -e "  ${GREEN}OK${NC} $tmpdir tiene noexec"
            fi
        fi
    done

    # 3c. Script de detección de herramientas descargadas
    cat > /usr/local/bin/detectar-tool-transfer.sh << 'EOFTOOL'
#!/bin/bash
# Detección de ingress tool transfer - T1105
LOG="/var/log/tool-transfer-$(date +%Y%m%d).log"
ALERTS=0

echo "=== Detección de Tool Transfer - $(date) ===" | tee "$LOG"

# 1. Binarios recientes en /tmp
echo "" | tee -a "$LOG"
echo "--- Binarios recientes en rutas temporales ---" | tee -a "$LOG"

for tmpdir in /tmp /var/tmp /dev/shm; do
    BINS=$(find "$tmpdir" -maxdepth 3 -type f -executable -mtime -1 2>/dev/null || true)
    if [[ -n "$BINS" ]]; then
        echo "ALERTA: Ejecutables recientes en $tmpdir:" | tee -a "$LOG"
        while IFS= read -r bin; do
            SIZE=$(du -h "$bin" 2>/dev/null | awk '{print $1}')
            TYPE=$(file -b "$bin" 2>/dev/null | head -c 80)
            echo "  $bin ($SIZE) - $TYPE" | tee -a "$LOG"
            ((ALERTS++)) || true
        done <<< "$BINS"
    fi
done

# 2. Archivos ELF en directorios no estándar
echo "" | tee -a "$LOG"
echo "--- ELFs en directorios no estándar ---" | tee -a "$LOG"

SUSPECT_ELFS=$(find /tmp /var/tmp /dev/shm /home -maxdepth 3 -type f -exec file {} \; 2>/dev/null | grep "ELF" | head -20 || true)
if [[ -n "$SUSPECT_ELFS" ]]; then
    echo "ALERTA: Archivos ELF sospechosos:" | tee -a "$LOG"
    echo "$SUSPECT_ELFS" | tee -a "$LOG"
    ((ALERTS++)) || true
else
    echo "OK: Sin ELFs en rutas temporales" | tee -a "$LOG"
fi

# 3. Eventos auditd de descarga recientes
echo "" | tee -a "$LOG"
echo "--- Eventos de descarga recientes ---" | tee -a "$LOG"

if command -v ausearch &>/dev/null; then
    DL_COUNT=$(ausearch -k tool-download -ts recent 2>/dev/null | grep -c "type=SYSCALL" || echo 0)
    if [[ "$DL_COUNT" -gt 20 ]]; then
        echo "ALERTA: $DL_COUNT descargas recientes (curl/wget)" | tee -a "$LOG"
        ((ALERTS++)) || true
    else
        echo "OK: $DL_COUNT descargas recientes" | tee -a "$LOG"
    fi

    EXEC_COUNT=$(ausearch -k tmp-executable -ts recent 2>/dev/null | grep -c "type=SYSCALL" || echo 0)
    if [[ "$EXEC_COUNT" -gt 5 ]]; then
        echo "ALERTA: $EXEC_COUNT ejecutables creados en /tmp" | tee -a "$LOG"
        ((ALERTS++)) || true
    else
        echo "OK: $EXEC_COUNT ejecutables en /tmp (normal)" | tee -a "$LOG"
    fi
fi

echo "" | tee -a "$LOG"
echo "=== RESUMEN ===" | tee -a "$LOG"
if [[ $ALERTS -eq 0 ]]; then
    echo "OK: Sin indicadores de tool transfer" | tee -a "$LOG"
else
    echo "ALERTA: $ALERTS indicadores de tool transfer" | tee -a "$LOG"
    logger -t detectar-tool-transfer "ALERTA: $ALERTS indicadores de tool transfer (T1105)"
fi

find /var/log -name "tool-transfer-*.log" -mtime +30 -delete 2>/dev/null || true
EOFTOOL

    log_change "Creado" "/usr/local/bin/detectar-tool-transfer.sh"
    chmod 700 /usr/local/bin/detectar-tool-transfer.sh
    log_change "Permisos" "/usr/local/bin/detectar-tool-transfer.sh -> 700"

    cat > /etc/cron.daily/detectar-tool-transfer << 'EOFCRON'
#!/bin/bash
/usr/local/bin/detectar-tool-transfer.sh 2>&1 | logger -t detectar-tool-transfer
EOFCRON
    log_change "Creado" "/etc/cron.daily/detectar-tool-transfer"
    chmod 700 /etc/cron.daily/detectar-tool-transfer
    log_change "Permisos" "/etc/cron.daily/detectar-tool-transfer -> 700"

    log_info "Detección de tool transfer configurada"
else
    log_skip "Control de descarga de herramientas no configurado"
    log_warn "Control de descarga de herramientas no configurado"
fi

# ============================================================
log_section "4. DETECCIÓN DE PROXY Y TUNNELING (T1090/T1572)"
# ============================================================

echo "Detectar uso de proxies y túneles para ocultar tráfico C2."
echo ""
echo "Técnicas detectadas:"
echo "  - T1090: Uso de proxies internos/externos"
echo "  - T1572: Protocol tunneling (SSH, DNS, ICMP)"
echo ""

if ask "¿Configurar detección de proxies y túneles?"; then

    cat > /usr/local/bin/detectar-tunneling.sh << 'EOFTUNNEL'
#!/bin/bash
# Detección de proxy/tunneling - T1090/T1572
LOG="/var/log/tunneling-detection-$(date +%Y%m%d).log"
ALERTS=0

echo "=== Detección de Proxy/Tunneling - $(date) ===" | tee "$LOG"

# 1. Proxies activos
echo "" | tee -a "$LOG"
echo "--- Herramientas de proxy activas ---" | tee -a "$LOG"

PROXY_PROCS=$(ps aux 2>/dev/null | grep -iE "proxychains|chisel|ligolo|ngrok|frp|rathole|bore|cloudflared|socat.*LISTEN|ssh.*-D|ssh.*-R|ssh.*-L" | grep -v grep || true)
if [[ -n "$PROXY_PROCS" ]]; then
    echo "ALERTA: Proxies/túneles activos:" | tee -a "$LOG"
    echo "$PROXY_PROCS" | tee -a "$LOG"
    ((ALERTS++)) || true
    logger -t detectar-tunneling "ALERTA: Herramientas de proxy detectadas"
else
    echo "OK: Sin proxies detectados" | tee -a "$LOG"
fi

# 2. SSH tunnels activos
echo "" | tee -a "$LOG"
echo "--- SSH tunnels activos ---" | tee -a "$LOG"

SSH_TUNNELS=$(ps aux 2>/dev/null | grep -E "ssh.*-[DLR]" | grep -v grep || true)
if [[ -n "$SSH_TUNNELS" ]]; then
    echo "ALERTA: Túneles SSH activos:" | tee -a "$LOG"
    echo "$SSH_TUNNELS" | tee -a "$LOG"
    ((ALERTS++)) || true
else
    echo "OK: Sin túneles SSH" | tee -a "$LOG"
fi

# 3. Puertos SOCKS/proxy en escucha
echo "" | tee -a "$LOG"
echo "--- Puertos de proxy en escucha ---" | tee -a "$LOG"

SOCKS_PORTS="1080 3128 8080 8888 9050 9051"
for port in $SOCKS_PORTS; do
    LISTENING=$(ss -tlnp 2>/dev/null | grep ":$port " || true)
    if [[ -n "$LISTENING" ]]; then
        PROC=$(echo "$LISTENING" | grep -oP 'users:\(\(".*?"' | head -1)
        echo "ALERTA: Puerto proxy $port en escucha: $PROC" | tee -a "$LOG"
        ((ALERTS++)) || true
    fi
done

# 4. Variables de entorno de proxy
echo "" | tee -a "$LOG"
echo "--- Variables de proxy ---" | tee -a "$LOG"

for var in http_proxy https_proxy socks_proxy all_proxy HTTP_PROXY HTTPS_PROXY; do
    VALUE=$(printenv "$var" 2>/dev/null || true)
    if [[ -n "$VALUE" ]]; then
        echo "  $var=$VALUE" | tee -a "$LOG"
    fi
done

# 5. Configuración de proxychains
echo "" | tee -a "$LOG"
echo "--- Proxychains config ---" | tee -a "$LOG"

for conf in /etc/proxychains.conf /etc/proxychains4.conf; do
    if [[ -f "$conf" ]]; then
        echo "ALERTA: $conf existe" | tee -a "$LOG"
        grep -v "^#\|^$" "$conf" 2>/dev/null | tail -5 | tee -a "$LOG"
        ((ALERTS++)) || true
    fi
done

# 6. Tráfico ICMP sospechoso (ICMP tunneling T1095)
echo "" | tee -a "$LOG"
echo "--- ICMP sospechoso ---" | tee -a "$LOG"

if command -v journalctl &>/dev/null; then
    ICMP_FLOOD=$(journalctl --since "1 hour ago" 2>/dev/null | grep -c "ICMP-FLOOD" || echo 0)
    if [[ "$ICMP_FLOOD" -gt 0 ]]; then
        echo "ALERTA: $ICMP_FLOOD eventos ICMP flood (posible tunneling)" | tee -a "$LOG"
        ((ALERTS++)) || true
    else
        echo "OK: Sin ICMP flood detectado" | tee -a "$LOG"
    fi
fi

echo "" | tee -a "$LOG"
echo "=== RESUMEN ===" | tee -a "$LOG"
if [[ $ALERTS -eq 0 ]]; then
    echo "OK: Sin indicadores de proxy/tunneling" | tee -a "$LOG"
else
    echo "ALERTA: $ALERTS indicadores de proxy/tunneling" | tee -a "$LOG"
    logger -t detectar-tunneling "ALERTA: $ALERTS indicadores de tunnel/proxy (T1090/T1572)"
fi

find /var/log -name "tunneling-detection-*.log" -mtime +30 -delete 2>/dev/null || true
EOFTUNNEL

    log_change "Creado" "/usr/local/bin/detectar-tunneling.sh"
    chmod 700 /usr/local/bin/detectar-tunneling.sh
    log_change "Permisos" "/usr/local/bin/detectar-tunneling.sh -> 700"

    # Auditd para proxies
    if command -v auditctl &>/dev/null; then
        mkdir -p /etc/audit/rules.d
        cat >> /etc/audit/rules.d/67-command-control.rules << 'EOF'

# T1090/T1572 - Proxy/Tunneling
-w /usr/bin/proxychains -p x -k proxy-tool
-w /usr/bin/proxychains4 -p x -k proxy-tool
-w /usr/bin/socat -p x -k proxy-tool
-w /usr/bin/chisel -p x -k tunnel-tool
-w /etc/proxychains.conf -p rwa -k proxy-config
-w /etc/proxychains4.conf -p rwa -k proxy-config
EOF
        log_change "Modificado" "/etc/audit/rules.d/67-command-control.rules"
        augenrules --load 2>/dev/null || true
        log_change "Aplicado" "augenrules --load"
    fi

    cat > /etc/cron.daily/detectar-tunneling << 'EOFCRON'
#!/bin/bash
/usr/local/bin/detectar-tunneling.sh 2>&1 | logger -t detectar-tunneling
EOFCRON
    log_change "Creado" "/etc/cron.daily/detectar-tunneling"
    chmod 700 /etc/cron.daily/detectar-tunneling
    log_change "Permisos" "/etc/cron.daily/detectar-tunneling -> 700"

    log_info "Detección de proxy/tunneling configurada"
else
    log_skip "Detección de proxy/tunneling no configurada"
    log_warn "Detección de proxy/tunneling no configurada"
fi

# ============================================================
log_section "5. DETECCIÓN DE DGA (T1568)"
# ============================================================

echo "Detectar Domain Generation Algorithms (DGA)."
echo "Malware avanzado genera dominios aleatorios para localizar"
echo "servidores C2, evitando bloqueos estáticos."
echo ""

if ask "¿Configurar detección de DGA?"; then

    cat > /usr/local/bin/detectar-dga.sh << 'EOFDGA'
#!/bin/bash
# Detección de Domain Generation Algorithms - T1568
LOG="/var/log/dga-detection-$(date +%Y%m%d).log"
ALERTS=0

echo "=== Detección de DGA - $(date) ===" | tee "$LOG"

# Analizar queries DNS buscando patrones de DGA
echo "" | tee -a "$LOG"
echo "--- Dominios con patrón DGA ---" | tee -a "$LOG"

if command -v journalctl &>/dev/null; then
    # Extraer dominios únicos de DNS
    DOMAINS=$(journalctl -u systemd-resolved --since "24 hours ago" 2>/dev/null | \
        grep -oP "query\[.*?\]\s+\K[a-zA-Z0-9.-]+" | sort -u)

    DGA_COUNT=0
    while IFS= read -r domain; do
        [[ -z "$domain" ]] && continue

        # Extraer el segundo nivel del dominio
        SLD=$(echo "$domain" | awk -F. '{if(NF>=2) print $(NF-1)}')
        [[ -z "$SLD" ]] && continue

        # Heurísticas de DGA:
        # 1. Longitud > 15 caracteres
        # 2. Alto ratio de consonantes
        # 3. Pocos caracteres de diccionario

        LEN=${#SLD}
        if [[ "$LEN" -gt 15 ]]; then
            # Contar consonantes
            CONSONANTS=$(echo "$SLD" | tr -cd 'bcdfghjklmnpqrstvwxyz' | wc -c)
            VOWELS=$(echo "$SLD" | tr -cd 'aeiou' | wc -c)
            DIGITS=$(echo "$SLD" | tr -cd '0-9' | wc -c)

            # Si >70% consonantes o tiene mezcla de números
            if [[ "$VOWELS" -gt 0 ]]; then
                RATIO=$((CONSONANTS * 100 / (CONSONANTS + VOWELS)))
            else
                RATIO=100
            fi

            if [[ "$RATIO" -gt 75 ]] || [[ "$DIGITS" -gt 3 ]]; then
                ((DGA_COUNT++)) || true
                if [[ $DGA_COUNT -le 20 ]]; then
                    echo "  Sospechoso: $domain (consonantes: ${RATIO}%, dígitos: $DIGITS)" | tee -a "$LOG"
                fi
            fi
        fi
    done <<< "$DOMAINS"

    if [[ "$DGA_COUNT" -gt 10 ]]; then
        echo "ALERTA: $DGA_COUNT dominios con patrón DGA detectados" | tee -a "$LOG"
        ((ALERTS++)) || true
        logger -t detectar-dga "ALERTA: $DGA_COUNT dominios DGA (T1568)"
    else
        echo "OK: $DGA_COUNT dominios sospechosos (normal)" | tee -a "$LOG"
    fi
fi

echo "" | tee -a "$LOG"
echo "=== RESUMEN ===" | tee -a "$LOG"
if [[ $ALERTS -eq 0 ]]; then
    echo "OK: Sin indicadores de DGA" | tee -a "$LOG"
else
    echo "ALERTA: $ALERTS indicadores de DGA" | tee -a "$LOG"
fi

find /var/log -name "dga-detection-*.log" -mtime +30 -delete 2>/dev/null || true
EOFDGA

    log_change "Creado" "/usr/local/bin/detectar-dga.sh"
    chmod 700 /usr/local/bin/detectar-dga.sh
    log_change "Permisos" "/usr/local/bin/detectar-dga.sh -> 700"

    cat > /etc/cron.daily/detectar-dga << 'EOFCRON'
#!/bin/bash
/usr/local/bin/detectar-dga.sh 2>&1 | logger -t detectar-dga
EOFCRON
    log_change "Creado" "/etc/cron.daily/detectar-dga"
    chmod 700 /etc/cron.daily/detectar-dga
    log_change "Permisos" "/etc/cron.daily/detectar-dga -> 700"

    log_info "Detección de DGA configurada"
else
    log_skip "Detección de DGA no configurada"
    log_warn "Detección de DGA no configurada"
fi

# ============================================================
log_section "6. DETECCIÓN CONSOLIDADA DE C2 (TA0011)"
# ============================================================

echo "Script consolidado que ejecuta todas las detecciones C2."
echo ""

if ask "¿Crear script de detección consolidada de C2?"; then

    cat > /usr/local/bin/detectar-c2-completo.sh << 'EOFC2'
#!/bin/bash
# Detección consolidada de C2 - TA0011
echo "========================================="
echo " DETECCIÓN COMPLETA DE C2 - TA0011"
echo " $(date)"
echo "========================================="

TOTAL_ALERTS=0

# Ejecutar todas las detecciones
for script in detectar-beaconing.sh detectar-tunneling.sh detectar-dga.sh detectar-tool-transfer.sh; do
    if [[ -x "/usr/local/bin/$script" ]]; then
        echo ""
        echo ">>> Ejecutando $script..."
        /usr/local/bin/"$script" 2>/dev/null
    fi
done

echo ""
echo "========================================="
echo " DETECCIÓN C2 COMPLETADA"
echo "========================================="
EOFC2

    log_change "Creado" "/usr/local/bin/detectar-c2-completo.sh"
    chmod 700 /usr/local/bin/detectar-c2-completo.sh
    log_change "Permisos" "/usr/local/bin/detectar-c2-completo.sh -> 700"
    log_info "Script consolidado: /usr/local/bin/detectar-c2-completo.sh"
else
    log_skip "Script consolidado C2 no creado"
    log_warn "Script consolidado no creado"
fi

# ============================================================
log_section "RESUMEN DE MITIGACIONES TA0011"
# ============================================================

echo ""
echo -e "${BOLD}Estado de mitigaciones de Comando y Control (TA0011):${NC}"
echo ""

# T1571 - Non-Standard Port
if fw_is_active &>/dev/null && fw_direct_get_all_rules 2>/dev/null | grep -q "C2-PORT"; then
    echo -e "  ${GREEN}[OK]${NC} T1571 - Bloqueo de puertos C2 no estándar"
else
    echo -e "  ${YELLOW}[--]${NC} T1571 - Puertos C2 no bloqueados"
fi

# T1071.001 - Web Protocols C2
if [[ -x /usr/local/bin/detectar-beaconing.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1071.001 - Detección de C2 beaconing"
else
    echo -e "  ${YELLOW}[--]${NC} T1071.001 - Detección de beaconing no configurada"
fi

# T1105 - Ingress Tool Transfer
if [[ -x /usr/local/bin/detectar-tool-transfer.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1105 - Detección de tool transfer"
else
    echo -e "  ${YELLOW}[--]${NC} T1105 - Tool transfer no monitoreado"
fi

# T1090/T1572 - Proxy/Tunneling
if [[ -x /usr/local/bin/detectar-tunneling.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1090/T1572 - Detección de proxy/tunneling"
else
    echo -e "  ${YELLOW}[--]${NC} T1090/T1572 - Proxy/tunneling no monitoreado"
fi

# T1568 - DGA
if [[ -x /usr/local/bin/detectar-dga.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1568 - Detección de DGA"
else
    echo -e "  ${YELLOW}[--]${NC} T1568 - DGA no monitoreado"
fi

# C2 Complete
if [[ -x /usr/local/bin/detectar-c2-completo.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} TA0011 - Script consolidado de detección C2"
else
    echo -e "  ${YELLOW}[--]${NC} TA0011 - Script consolidado no creado"
fi

show_changes_summary

echo ""
log_info "Script de mitigación de comando y control completado"
log_info "Backups de configuración en: $BACKUP_DIR"
