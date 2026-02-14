#!/bin/bash
# ============================================================
# AUDITORÍA EXTERNA - ¿Qué ve un atacante desde fuera?
# Linux Multi-Distro (openSUSE, Debian/Ubuntu, RHEL/Fedora, Arch)
# ============================================================
# Mitigaciones MITRE ATT&CK:
#   T1593 - Search Open Websites (M1056)
#   T1596 - Search Technical Databases (M1056)
#   T1595 - Active Scanning (verificación)
#   T1592 - Gather Victim Host Info (verificación)
#   T1590 - Gather Network Info (verificación)
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps

# ── Pre-check: detectar secciones ya aplicadas ────────────
_precheck 12
_pc true  # S1: deteccion puertos (siempre re-evaluar)
_pc true  # S2: fuga de banners (siempre re-evaluar)
_pc true  # S3: fingerprinting SO (siempre re-evaluar)
_pc true  # S4: exposicion DNS (siempre re-evaluar)
_pc true  # S5: info servicios web (siempre re-evaluar)
_pc true  # S6: SNMP/gestion expuestos (siempre re-evaluar)
_pc true  # S7: exposicion publica (siempre re-evaluar)
_pc true  # S8: metadatos/archivos publicos (siempre re-evaluar)
_pc true  # S9: proteccion de red (siempre re-evaluar)
_pc true  # S10: certificados SSL/TLS (siempre re-evaluar)
_pc 'check_executable "/usr/local/bin/auditoria-reconocimiento.sh"'
_pc 'check_file_exists "/etc/cron.weekly/auditoria-reconocimiento"'
_precheck_result

REPORT_DIR="/root/auditoria-externa-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$REPORT_DIR"
REPORT_FILE="$REPORT_DIR/informe-reconocimiento.txt"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   AUDITORÍA EXTERNA - PERSPECTIVA DEL ATACANTE           ║"
echo "║   ¿Qué información puede obtener un adversario?          ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Informe se guardará en: $REPORT_FILE"
echo ""

{
    echo "============================================================"
    echo " INFORME DE AUDITORÍA EXTERNA - RECONOCIMIENTO (TA0043)"
    echo " Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
    echo " Host: $(hostname)"
    echo "============================================================"
    echo ""
} > "$REPORT_FILE"

warnings=0
checks_ok=0

# ============================================================
log_section "1. PUERTOS EXPUESTOS (perspectiva externa)"
# ============================================================
# T1595 - Active Scanning: verificar qué puertos son visibles

echo "Analizando puertos que escuchan en TODAS las interfaces..."
echo ""

# Puertos escuchando en todas las interfaces (no solo localhost)
EXPOSED_PORTS=$(ss -tlnp 2>/dev/null | tail -n +2)
EXTERNAL_PORTS=""
LOCALHOST_ONLY=""

while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    local_addr=$(echo "$line" | awk '{print $4}')
    # Puertos en 0.0.0.0, ::, o IP específica (no 127.0.0.1/::1)
    if echo "$local_addr" | grep -qE "^(0\.0\.0\.0|::|\*|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):" && \
       ! echo "$local_addr" | grep -qE "^(127\.|::1)"; then
        EXTERNAL_PORTS+="$line"$'\n'
    else
        LOCALHOST_ONLY+="$line"$'\n'
    fi
done <<< "$EXPOSED_PORTS"

if [[ -n "$EXTERNAL_PORTS" ]]; then
    echo -e "${RED}[!] Puertos accesibles desde el exterior:${NC}"
    echo "$EXTERNAL_PORTS" | while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        port=$(echo "$line" | awk '{print $4}' | rev | cut -d: -f1 | rev)
        process=$(echo "$line" | awk '{print $6}')
        echo -e "  ${RED}●${NC} Puerto ${BOLD}$port${NC} - $process"
    done
    ((warnings++)) || true
else
    echo -e "  ${GREEN}OK${NC} No hay puertos expuestos a todas las interfaces"
    ((checks_ok++))
fi

if [[ -n "$LOCALHOST_ONLY" ]]; then
    echo ""
    echo -e "  ${GREEN}●${NC} Puertos solo en localhost (seguros):"
    echo "$LOCALHOST_ONLY" | while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        port=$(echo "$line" | awk '{print $4}' | rev | cut -d: -f1 | rev)
        echo -e "    ${DIM}$port (solo local)${NC}"
    done
fi

# Puertos UDP
UDP_PORTS=$(ss -ulnp 2>/dev/null | tail -n +2 | grep -vE "127\.|::1" || true)
if [[ -n "$UDP_PORTS" ]]; then
    echo ""
    echo -e "${YELLOW}[!] Puertos UDP expuestos:${NC}"
    echo "$UDP_PORTS" | while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        port=$(echo "$line" | awk '{print $4}' | rev | cut -d: -f1 | rev)
        process=$(echo "$line" | awk '{print $6}')
        echo -e "  ${YELLOW}●${NC} UDP $port - $process"
    done
    ((warnings++)) || true
fi

# Puertos de alto riesgo
HIGH_RISK_PORTS="21 23 25 53 69 110 111 135 139 143 161 389 445 512 513 514 873 1433 1521 2049 3306 3389 5432 5900 6379 8080 8443 9200 11211 27017"
echo ""
echo "Verificando puertos de alto riesgo..."
FOUND_HIGH_RISK=0
for hr_port in $HIGH_RISK_PORTS; do
    if ss -tlnp 2>/dev/null | grep -qE ":${hr_port}\b" && \
       ! ss -tlnp 2>/dev/null | grep -E ":${hr_port}\b" | grep -qE "127\.|::1"; then
        service_name=""
        case $hr_port in
            21) service_name="FTP" ;;
            23) service_name="Telnet" ;;
            25) service_name="SMTP" ;;
            53) service_name="DNS" ;;
            69) service_name="TFTP" ;;
            110) service_name="POP3" ;;
            111) service_name="RPC" ;;
            135) service_name="MSRPC" ;;
            139) service_name="NetBIOS" ;;
            143) service_name="IMAP" ;;
            161) service_name="SNMP" ;;
            389) service_name="LDAP" ;;
            445) service_name="SMB" ;;
            512|513|514) service_name="R-Services" ;;
            873) service_name="rsync" ;;
            1433) service_name="MSSQL" ;;
            1521) service_name="Oracle" ;;
            2049) service_name="NFS" ;;
            3306) service_name="MySQL" ;;
            3389) service_name="RDP" ;;
            5432) service_name="PostgreSQL" ;;
            5900) service_name="VNC" ;;
            6379) service_name="Redis" ;;
            8080) service_name="HTTP-Alt" ;;
            8443) service_name="HTTPS-Alt" ;;
            9200) service_name="Elasticsearch" ;;
            11211) service_name="Memcached" ;;
            27017) service_name="MongoDB" ;;
        esac
        log_error "Puerto de ALTO RIESGO expuesto: $hr_port ($service_name)"
        FOUND_HIGH_RISK=1
    fi
done
if [[ $FOUND_HIGH_RISK -eq 0 ]]; then
    echo -e "  ${GREEN}OK${NC} No hay puertos de alto riesgo expuestos"
    ((checks_ok++))
else
    ((warnings++)) || true
fi

{
    echo "1. PUERTOS EXPUESTOS"
    echo "--------------------"
    echo "Puertos TCP externos:"
    echo "$EXTERNAL_PORTS"
    echo "Puertos UDP externos:"
    echo "$UDP_PORTS"
    echo ""
} >> "$REPORT_FILE"

# ============================================================
log_section "2. FUGA DE INFORMACIÓN EN BANNERS"
# ============================================================
# T1592 - Gather Victim Host Info: verificar qué revelan los banners

echo "Verificando banners de servicios..."
echo ""

# SSH banner
BANNER_ISSUES=0
if command -v sshd &>/dev/null && ss -tlnp 2>/dev/null | grep -q ":22\b"; then
    SSH_BANNER=$(echo "" | timeout 3 nc -w2 127.0.0.1 22 2>/dev/null | head -1 || echo "N/A")
    if [[ "$SSH_BANNER" != "N/A" && -n "$SSH_BANNER" ]]; then
        echo -e "  Banner SSH: ${BOLD}$SSH_BANNER${NC}"
        # Verificar si revela versión de OS
        if echo "$SSH_BANNER" | grep -qiE "ubuntu|debian|centos|suse|fedora|rhel"; then
            log_warn "El banner SSH revela el sistema operativo"
            BANNER_ISSUES=1
        fi
        # Verificar si revela versión exacta de OpenSSH
        if echo "$SSH_BANNER" | grep -qoP "OpenSSH_\d+\.\d+p\d+"; then
            log_warn "El banner SSH revela la versión exacta de OpenSSH"
            BANNER_ISSUES=1
        fi
    else
        echo -e "  ${GREEN}OK${NC} Banner SSH no accesible o vacío"
    fi
else
    echo -e "  ${DIM}SSH no escucha en puerto 22${NC}"
fi

# /etc/issue, /etc/issue.net
for issue_file in /etc/issue /etc/issue.net; do
    if [[ -f "$issue_file" ]]; then
        issue_content=$(cat "$issue_file" 2>/dev/null)
        if echo "$issue_content" | grep -qiE "suse|leap|tumbleweed|linux.*[0-9]+\.[0-9]+|kernel"; then
            log_warn "$issue_file revela información del sistema operativo"
            BANNER_ISSUES=1
        elif echo "$issue_content" | grep -qiE "WARNING|ADVERTENCIA|PRIVADO|authorized|PROHIBIDO"; then
            echo -e "  ${GREEN}OK${NC} $issue_file tiene banner disuasivo (sin info de OS)"
        fi
    fi
done

# /etc/motd
if [[ -f /etc/motd ]]; then
    motd_content=$(cat /etc/motd 2>/dev/null)
    if echo "$motd_content" | grep -qiE "suse|leap|welcome.*to|kernel.*[0-9]"; then
        log_warn "/etc/motd revela información del sistema"
        BANNER_ISSUES=1
    fi
fi

if [[ $BANNER_ISSUES -eq 0 ]]; then
    echo -e "  ${GREEN}OK${NC} Los banners no filtran información del sistema"
    ((checks_ok++))
else
    ((warnings++)) || true
fi

{
    echo "2. BANNERS DE SERVICIOS"
    echo "-----------------------"
    echo "SSH: $SSH_BANNER"
    echo "issue: $(head -3 /etc/issue 2>/dev/null || echo 'N/A')"
    echo "issue.net: $(head -3 /etc/issue.net 2>/dev/null || echo 'N/A')"
    echo ""
} >> "$REPORT_FILE"

# ============================================================
log_section "3. FINGERPRINTING DE SISTEMA OPERATIVO"
# ============================================================
# T1592 - Gather Victim Host Info: OS fingerprinting

echo "Verificando vectores de fingerprinting..."
echo ""

FP_ISSUES=0

# TCP timestamps (usado por nmap para fingerprinting)
TCP_TS=$(sysctl -n net.ipv4.tcp_timestamps 2>/dev/null || echo "1")
if [[ "$TCP_TS" == "0" ]]; then
    echo -e "  ${GREEN}OK${NC} TCP timestamps deshabilitados (anti-fingerprinting)"
    ((checks_ok++))
else
    log_warn "TCP timestamps habilitados - permite fingerprinting remoto de OS"
    FP_ISSUES=1
    ((warnings++)) || true
fi

# ICMP responses
ICMP_BROADCAST=$(sysctl -n net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null || echo "0")
if [[ "$ICMP_BROADCAST" == "1" ]]; then
    echo -e "  ${GREEN}OK${NC} ICMP broadcast ignorado"
    ((checks_ok++))
else
    log_warn "ICMP broadcast respondido - facilita descubrimiento de host"
    FP_ISSUES=1
    ((warnings++)) || true
fi

# dmesg restringido
DMESG_RESTRICT=$(sysctl -n kernel.dmesg_restrict 2>/dev/null || echo "0")
if [[ "$DMESG_RESTRICT" == "1" ]]; then
    echo -e "  ${GREEN}OK${NC} dmesg restringido (no accesible sin root)"
    ((checks_ok++))
else
    log_warn "dmesg accesible para usuarios normales - filtra info de kernel"
    FP_ISSUES=1
    ((warnings++)) || true
fi

# kernel.version oculto
KPTR=$(sysctl -n kernel.kptr_restrict 2>/dev/null || echo "0")
if [[ "$KPTR" -ge 1 ]]; then
    echo -e "  ${GREEN}OK${NC} Punteros de kernel ofuscados (kptr_restrict=$KPTR)"
    ((checks_ok++))
else
    log_warn "Punteros de kernel visibles - filtra layout de memoria"
    ((warnings++)) || true
fi

# /proc/version accesible
if [[ -r /proc/version ]]; then
    PROC_VERSION=$(cat /proc/version 2>/dev/null)
    echo -e "  ${YELLOW}[i]${NC} /proc/version: ${DIM}${PROC_VERSION:0:70}...${NC}"
fi

{
    echo "3. FINGERPRINTING"
    echo "-----------------"
    echo "TCP timestamps: $TCP_TS"
    echo "ICMP broadcast ignore: $ICMP_BROADCAST"
    echo "dmesg_restrict: $DMESG_RESTRICT"
    echo "kptr_restrict: $KPTR"
    echo ""
} >> "$REPORT_FILE"

# ============================================================
log_section "4. EXPOSICIÓN DNS"
# ============================================================
# T1590 - Gather Network Info: DNS exposure

echo "Verificando exposición de información DNS..."
echo ""

DNS_ISSUES=0

# Resolver activo
if [[ -f /etc/resolv.conf ]]; then
    DNS_SERVERS=$(grep "^nameserver" /etc/resolv.conf | awk '{print $2}')
    echo -e "  Servidores DNS configurados:"
    for dns in $DNS_SERVERS; do
        if echo "$dns" | grep -qE "^(1\.1\.1\.1|1\.0\.0\.1|9\.9\.9\.9|149\.112\.112\.112|8\.8\.8\.8|8\.8\.4\.4)$"; then
            echo -e "    ${GREEN}●${NC} $dns (proveedor seguro)"
        elif echo "$dns" | grep -qE "^(127\.|::1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)"; then
            echo -e "    ${YELLOW}●${NC} $dns (local/privado)"
        else
            echo -e "    ${RED}●${NC} $dns (ISP/desconocido - puede registrar consultas)"
            DNS_ISSUES=1
        fi
    done
fi

# DNS over TLS
if [[ -f /etc/systemd/resolved.conf.d/dns-over-tls.conf ]] || \
   [[ -f /etc/systemd/resolved.conf ]] && grep -q "DNSOverTLS=yes" /etc/systemd/resolved.conf 2>/dev/null; then
    echo -e "  ${GREEN}OK${NC} DNS over TLS configurado"
    ((checks_ok++))
else
    log_warn "DNS over TLS NO configurado - consultas DNS visibles en la red"
    DNS_ISSUES=1
    ((warnings++)) || true
fi

# Hostname revelador
HOSTNAME=$(hostname 2>/dev/null)
if echo "$HOSTNAME" | grep -qiE "servidor|server|prod|database|db|web|api|admin|backup|dev|staging"; then
    log_warn "El hostname '$HOSTNAME' revela la función del sistema"
    DNS_ISSUES=1
    ((warnings++)) || true
else
    echo -e "  ${GREEN}OK${NC} Hostname no revela función del sistema: $HOSTNAME"
    ((checks_ok++))
fi

{
    echo "4. DNS"
    echo "------"
    echo "Servidores: $DNS_SERVERS"
    echo "Hostname: $HOSTNAME"
    echo ""
} >> "$REPORT_FILE"

# ============================================================
log_section "5. INFORMACIÓN EN SERVICIOS WEB"
# ============================================================
# T1592 - Gather Victim Host Info: HTTP header leaks

echo "Verificando servicios web y cabeceras HTTP..."
echo ""

WEB_ISSUES=0

# Buscar servidores web escuchando
for port in 80 443 8080 8443; do
    if ss -tlnp 2>/dev/null | grep -qE ":${port}\b"; then
        echo -e "  ${YELLOW}●${NC} Servicio web detectado en puerto $port"

        if command -v curl &>/dev/null; then
            # Obtener cabeceras
            HEADERS=$(curl -sI -m5 "http://127.0.0.1:${port}/" 2>/dev/null || true)
            if [[ -n "$HEADERS" ]]; then
                # Server header
                SERVER_HEADER=$(echo "$HEADERS" | grep -i "^Server:" | head -1)
                if [[ -n "$SERVER_HEADER" ]]; then
                    echo -e "    Cabecera Server: ${BOLD}$SERVER_HEADER${NC}"
                    if echo "$SERVER_HEADER" | grep -qiE "apache|nginx|iis|tomcat|[0-9]+\.[0-9]+"; then
                        log_warn "La cabecera Server revela software/versión"
                        WEB_ISSUES=1
                    fi
                fi

                # X-Powered-By
                POWERED=$(echo "$HEADERS" | grep -i "^X-Powered-By:" | head -1)
                if [[ -n "$POWERED" ]]; then
                    log_warn "Cabecera X-Powered-By presente: $POWERED"
                    WEB_ISSUES=1
                fi

                # X-AspNet-Version o similar
                ASPNET=$(echo "$HEADERS" | grep -i "^X-AspNet\|^X-Runtime\|^X-Version" | head -1)
                if [[ -n "$ASPNET" ]]; then
                    log_warn "Cabecera de framework presente: $ASPNET"
                    WEB_ISSUES=1
                fi
            fi
        fi
    fi
done

if [[ $WEB_ISSUES -eq 0 ]]; then
    echo -e "  ${GREEN}OK${NC} No se detectan fugas de información en cabeceras HTTP"
    ((checks_ok++))
else
    ((warnings++)) || true
fi

{
    echo "5. SERVICIOS WEB"
    echo "-----------------"
    echo "Cabeceras analizadas"
    echo ""
} >> "$REPORT_FILE"

# ============================================================
log_section "6. SNMP / SERVICIOS DE GESTIÓN EXPUESTOS"
# ============================================================
# T1596 - Search Technical Databases: management services

echo "Verificando servicios de gestión expuestos..."
echo ""

MGMT_ISSUES=0

# SNMP
if ss -ulnp 2>/dev/null | grep -qE ":161\b"; then
    log_error "SNMP expuesto (puerto 161) - puede filtrar toda la configuración del sistema"
    MGMT_ISSUES=1
    ((warnings++)) || true
else
    echo -e "  ${GREEN}OK${NC} SNMP no expuesto"
    ((checks_ok++))
fi

# IPMI
if ss -ulnp 2>/dev/null | grep -qE ":623\b"; then
    log_error "IPMI expuesto (puerto 623) - acceso remoto de gestión"
    MGMT_ISSUES=1
    ((warnings++)) || true
fi

# Telnet
if ss -tlnp 2>/dev/null | grep -qE ":23\b"; then
    log_error "Telnet expuesto (puerto 23) - credenciales en texto plano"
    MGMT_ISSUES=1
    ((warnings++)) || true
fi

# FTP
if ss -tlnp 2>/dev/null | grep -qE ":21\b"; then
    log_warn "FTP expuesto (puerto 21) - considerar SFTP en su lugar"
    MGMT_ISSUES=1
    ((warnings++)) || true
fi

# RPC
if ss -tlnp 2>/dev/null | grep -qE ":111\b"; then
    log_warn "RPC portmapper expuesto (puerto 111)"
    MGMT_ISSUES=1
    ((warnings++)) || true
fi

if [[ $MGMT_ISSUES -eq 0 ]]; then
    echo -e "  ${GREEN}OK${NC} No hay servicios de gestión peligrosos expuestos"
    ((checks_ok++))
fi

{
    echo "6. SERVICIOS DE GESTIÓN"
    echo "-----------------------"
    echo "SNMP: $(ss -ulnp 2>/dev/null | grep ':161' || echo 'no expuesto')"
    echo ""
} >> "$REPORT_FILE"

# ============================================================
log_section "7. VERIFICACIÓN DE EXPOSICIÓN PÚBLICA (Shodan/Censys)"
# ============================================================
# T1593 - Search Open Websites + T1596 - Search Technical Databases

echo "Verificando exposición en motores de búsqueda de infraestructura..."
echo ""

# Obtener IP pública
PUBLIC_IP=""
if command -v curl &>/dev/null; then
    PUBLIC_IP=$(curl -s -m10 https://api.ipify.org 2>/dev/null || \
                curl -s -m10 https://ifconfig.me 2>/dev/null || \
                curl -s -m10 https://icanhazip.com 2>/dev/null || \
                echo "")
fi

if [[ -n "$PUBLIC_IP" && "$PUBLIC_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo -e "  IP pública detectada: ${BOLD}$PUBLIC_IP${NC}"
    echo ""

    # Consulta Shodan (API pública sin key, info limitada)
    echo -e "  ${CYAN}▸${NC} Consultando Shodan..."
    SHODAN_RESULT=$(curl -s -m15 "https://internetdb.shodan.io/$PUBLIC_IP" 2>/dev/null || echo "")

    if [[ -n "$SHODAN_RESULT" && "$SHODAN_RESULT" != *"No information"* && "$SHODAN_RESULT" != *"error"* ]]; then
        # Parsear puertos de Shodan
        SHODAN_PORTS=$(echo "$SHODAN_RESULT" | grep -oP '"ports":\s*\[\K[^\]]+' 2>/dev/null || echo "")
        SHODAN_VULNS=$(echo "$SHODAN_RESULT" | grep -oP '"vulns":\s*\[\K[^\]]+' 2>/dev/null || echo "")
        SHODAN_HOSTNAMES=$(echo "$SHODAN_RESULT" | grep -oP '"hostnames":\s*\[\K[^\]]+' 2>/dev/null || echo "")
        SHODAN_CPES=$(echo "$SHODAN_RESULT" | grep -oP '"cpes":\s*\[\K[^\]]+' 2>/dev/null || echo "")

        if [[ -n "$SHODAN_PORTS" ]]; then
            log_warn "Shodan conoce puertos abiertos: $SHODAN_PORTS"
            ((warnings++)) || true
        else
            echo -e "  ${GREEN}OK${NC} Shodan no reporta puertos abiertos"
            ((checks_ok++))
        fi

        if [[ -n "$SHODAN_VULNS" ]]; then
            log_error "Shodan reporta vulnerabilidades: $SHODAN_VULNS"
            ((warnings++)) || true
        fi

        if [[ -n "$SHODAN_HOSTNAMES" ]]; then
            log_warn "Shodan conoce hostnames: $SHODAN_HOSTNAMES"
            ((warnings++)) || true
        fi

        if [[ -n "$SHODAN_CPES" ]]; then
            log_warn "Shodan identifica software (CPE): $SHODAN_CPES"
            ((warnings++)) || true
        fi
    else
        echo -e "  ${GREEN}OK${NC} IP no encontrada en Shodan InternetDB"
        ((checks_ok++))
    fi

    echo ""

    # Verificación de DNS inverso
    echo -e "  ${CYAN}▸${NC} Verificando DNS inverso..."
    REVERSE_DNS=""
    if command -v dig &>/dev/null; then
        REVERSE_DNS=$(dig +short -x "$PUBLIC_IP" 2>/dev/null | head -1 || echo "")
    elif command -v host &>/dev/null; then
        REVERSE_DNS=$(host "$PUBLIC_IP" 2>/dev/null | grep "domain name pointer" | awk '{print $NF}' | head -1 || echo "")
    elif command -v nslookup &>/dev/null; then
        REVERSE_DNS=$(nslookup "$PUBLIC_IP" 2>/dev/null | grep "name = " | awk '{print $NF}' | head -1 || echo "")
    fi

    if [[ -n "$REVERSE_DNS" ]]; then
        echo -e "  DNS inverso: ${BOLD}$REVERSE_DNS${NC}"
        if echo "$REVERSE_DNS" | grep -qiE "servidor|server|host|vps|cloud|dedicated"; then
            log_warn "DNS inverso revela tipo de infraestructura"
            ((warnings++)) || true
        fi
    else
        echo -e "  ${GREEN}OK${NC} Sin DNS inverso (menor exposición)"
        ((checks_ok++))
    fi

    # Verificación de geolocalización pública
    echo ""
    echo -e "  ${CYAN}▸${NC} Verificando geolocalización pública..."
    GEO_INFO=$(curl -s -m10 "https://ipinfo.io/$PUBLIC_IP/json" 2>/dev/null || echo "")
    if [[ -n "$GEO_INFO" ]]; then
        GEO_CITY=$(echo "$GEO_INFO" | grep -oP '"city":\s*"\K[^"]+' 2>/dev/null || echo "N/A")
        GEO_ORG=$(echo "$GEO_INFO" | grep -oP '"org":\s*"\K[^"]+' 2>/dev/null || echo "N/A")
        GEO_COUNTRY=$(echo "$GEO_INFO" | grep -oP '"country":\s*"\K[^"]+' 2>/dev/null || echo "N/A")
        echo -e "  Ubicación pública: $GEO_CITY, $GEO_COUNTRY"
        echo -e "  Organización/ISP: $GEO_ORG"
        echo -e "  ${DIM}(Esta información es visible para cualquier atacante)${NC}"
    fi

else
    if [[ -z "$PUBLIC_IP" ]]; then
        echo -e "  ${DIM}No se pudo obtener la IP pública (sin acceso a internet o red interna)${NC}"
    else
        echo -e "  ${DIM}IP detectada no es IPv4 válida: $PUBLIC_IP${NC}"
    fi
    echo -e "  ${DIM}Las verificaciones de Shodan/Censys requieren conectividad${NC}"
fi

{
    echo "7. EXPOSICIÓN PÚBLICA"
    echo "---------------------"
    echo "IP pública: ${PUBLIC_IP:-N/A}"
    echo "Shodan: $SHODAN_RESULT"
    echo "DNS inverso: ${REVERSE_DNS:-N/A}"
    echo ""
} >> "$REPORT_FILE"

# ============================================================
log_section "8. METADATOS Y ARCHIVOS PÚBLICOS"
# ============================================================
# T1593 - Search Open Websites: información pública accidentalmente expuesta

echo "Verificando exposición accidental de archivos..."
echo ""

META_ISSUES=0

# Verificar si hay servidores web con archivos sensibles
for port in 80 443 8080 8443; do
    if ss -tlnp 2>/dev/null | grep -qE ":${port}\b" && command -v curl &>/dev/null; then
        # Rutas sensibles comunes
        SENSITIVE_PATHS=(".env" ".git/config" "robots.txt" ".htaccess" "server-status" "phpinfo.php" "wp-login.php" "admin/" ".svn/entries" "backup/" "debug/" "info.php")

        for spath in "${SENSITIVE_PATHS[@]}"; do
            HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -m3 "http://127.0.0.1:${port}/${spath}" 2>/dev/null || echo "000")
            if [[ "$HTTP_CODE" == "200" ]]; then
                log_warn "Archivo/ruta accesible en puerto $port: /$spath (HTTP 200)"
                META_ISSUES=1
            fi
        done
    fi
done

# Archivos de backup/configuración en DocumentRoots comunes
for webroot in /var/www /srv/www /var/www/html /srv/www/htdocs; do
    if [[ -d "$webroot" ]]; then
        SENSITIVE_FILES=$(find "$webroot" -maxdepth 3 \( -name "*.bak" -o -name "*.old" -o -name "*.sql" -o -name "*.tar.gz" -o -name "*.zip" -o -name ".env" -o -name "*.log" -o -name "*.conf" \) -type f 2>/dev/null | head -10)
        if [[ -n "$SENSITIVE_FILES" ]]; then
            log_warn "Archivos sensibles en $webroot:"
            echo "$SENSITIVE_FILES" | while IFS= read -r sf; do
                echo -e "    ${RED}●${NC} $sf"
            done
            META_ISSUES=1
        fi
    fi
done

if [[ $META_ISSUES -eq 0 ]]; then
    echo -e "  ${GREEN}OK${NC} No se detectan archivos sensibles expuestos"
    ((checks_ok++))
else
    ((warnings++)) || true
fi

{
    echo "8. METADATOS Y ARCHIVOS"
    echo "-----------------------"
    echo "Verificado: rutas sensibles en servidores web"
    echo ""
} >> "$REPORT_FILE"

# ============================================================
log_section "9. PROTECCIÓN DE RED (anti-escaneo)"
# ============================================================
# T1595 - Active Scanning: verificar defensas contra escaneo

echo "Verificando defensas contra escaneo activo..."
echo ""

SCAN_ISSUES=0

# Firewall activo
if fw_is_active &>/dev/null; then
    DEFAULT_ZONE=$(fw_get_default_zone 2>/dev/null || echo "desconocida")
    echo -e "  ${GREEN}OK${NC} Firewall activo (zona: $DEFAULT_ZONE)"
    ((checks_ok++))

    if [[ "$DEFAULT_ZONE" == "drop" || "$DEFAULT_ZONE" == "block" ]]; then
        echo -e "  ${GREEN}OK${NC} Zona por defecto es restrictiva: $DEFAULT_ZONE"
        ((checks_ok++))
    else
        log_warn "Zona por defecto no es DROP/block: $DEFAULT_ZONE"
        SCAN_ISSUES=1
        ((warnings++)) || true
    fi

    # Log de paquetes rechazados
    LOG_DENIED=$(fw_get_log_denied 2>/dev/null || echo "off")
    if [[ "$LOG_DENIED" != "off" ]]; then
        echo -e "  ${GREEN}OK${NC} Logging de paquetes rechazados: $LOG_DENIED"
        ((checks_ok++))
    else
        log_warn "No se registran paquetes rechazados"
        SCAN_ISSUES=1
        ((warnings++)) || true
    fi
elif command -v nft &>/dev/null && nft list ruleset 2>/dev/null | grep -q "chain"; then
    echo -e "  ${GREEN}OK${NC} nftables activo con reglas"
    ((checks_ok++))
elif command -v iptables &>/dev/null && iptables -L 2>/dev/null | grep -q "DROP\|REJECT"; then
    echo -e "  ${GREEN}OK${NC} iptables con reglas de filtrado"
    ((checks_ok++))
else
    log_error "No se detecta firewall activo"
    SCAN_ISSUES=1
    ((warnings++)) || true
fi

# SYN cookies
SYNCOOKIES=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo "0")
if [[ "$SYNCOOKIES" == "1" ]]; then
    echo -e "  ${GREEN}OK${NC} SYN cookies habilitados (anti SYN flood)"
    ((checks_ok++))
else
    log_warn "SYN cookies deshabilitados"
    SCAN_ISSUES=1
    ((warnings++)) || true
fi

# Source routing rechazado
SRC_ROUTE=$(sysctl -n net.ipv4.conf.all.accept_source_route 2>/dev/null || echo "1")
if [[ "$SRC_ROUTE" == "0" ]]; then
    echo -e "  ${GREEN}OK${NC} Source routing rechazado"
    ((checks_ok++))
else
    log_warn "Source routing aceptado"
    SCAN_ISSUES=1
    ((warnings++)) || true
fi

# Log martians
LOG_MARTIANS=$(sysctl -n net.ipv4.conf.all.log_martians 2>/dev/null || echo "0")
if [[ "$LOG_MARTIANS" == "1" ]]; then
    echo -e "  ${GREEN}OK${NC} Paquetes martianos se registran"
    ((checks_ok++))
else
    log_warn "Paquetes con direcciones inválidas no se registran"
    SCAN_ISSUES=1
    ((warnings++)) || true
fi

# fail2ban
if systemctl is-active fail2ban &>/dev/null; then
    JAILS=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*:\s*//')
    echo -e "  ${GREEN}OK${NC} fail2ban activo - jails: ${JAILS:-ninguno}"
    ((checks_ok++))
else
    log_warn "fail2ban no activo - sin protección contra fuerza bruta"
    SCAN_ISSUES=1
    ((warnings++)) || true
fi

{
    echo "9. DEFENSAS ANTI-ESCANEO"
    echo "------------------------"
    echo "Firewall: $(systemctl is-active firewalld 2>/dev/null || echo 'inactivo')"
    echo "SYN cookies: $SYNCOOKIES"
    echo "fail2ban: $(systemctl is-active fail2ban 2>/dev/null || echo 'inactivo')"
    echo ""
} >> "$REPORT_FILE"

# ============================================================
log_section "10. CERTIFICADOS SSL/TLS"
# ============================================================
# T1592 - Gather Victim Host Info: certificate leaks

echo "Verificando certificados SSL/TLS..."
echo ""

CERT_ISSUES=0

for port in 443 8443 993 995 465 587; do
    if ss -tlnp 2>/dev/null | grep -qE ":${port}\b"; then
        if command -v openssl &>/dev/null; then
            CERT_INFO=$(echo | timeout 5 openssl s_client -connect "127.0.0.1:${port}" 2>/dev/null || echo "")
            if [[ -n "$CERT_INFO" ]]; then
                CERT_SUBJECT=$(echo "$CERT_INFO" | openssl x509 -noout -subject 2>/dev/null || echo "")
                CERT_ISSUER=$(echo "$CERT_INFO" | openssl x509 -noout -issuer 2>/dev/null || echo "")
                CERT_DATES=$(echo "$CERT_INFO" | openssl x509 -noout -dates 2>/dev/null || echo "")

                echo -e "  Puerto $port:"
                [[ -n "$CERT_SUBJECT" ]] && echo -e "    Subject: $CERT_SUBJECT"
                [[ -n "$CERT_ISSUER" ]] && echo -e "    Issuer: $CERT_ISSUER"

                # Verificar si el CN revela hostname interno
                if echo "$CERT_SUBJECT" | grep -qiE "localhost|internal|intranet|\.local|\.lan"; then
                    log_warn "Certificado en puerto $port revela nombre interno"
                    CERT_ISSUES=1
                fi

                # Verificar expiración
                if [[ -n "$CERT_DATES" ]]; then
                    NOT_AFTER=$(echo "$CERT_DATES" | grep "notAfter" | cut -d= -f2)
                    if [[ -n "$NOT_AFTER" ]]; then
                        EXPIRY_EPOCH=$(date -d "$NOT_AFTER" +%s 2>/dev/null || echo "0")
                        NOW_EPOCH=$(date +%s)
                        if [[ $EXPIRY_EPOCH -lt $NOW_EPOCH ]]; then
                            log_error "Certificado en puerto $port EXPIRADO"
                            CERT_ISSUES=1
                        fi
                    fi
                fi
            fi
        fi
    fi
done

if [[ $CERT_ISSUES -eq 0 ]]; then
    echo -e "  ${GREEN}OK${NC} Certificados SSL/TLS sin fugas de información"
    ((checks_ok++))
else
    ((warnings++)) || true
fi

{
    echo "10. CERTIFICADOS SSL/TLS"
    echo "------------------------"
    echo "Verificados puertos: 443, 8443, 993, 995, 465, 587"
    echo ""
} >> "$REPORT_FILE"

# ============================================================
log_section "11. CREAR SCRIPT DE AUDITORÍA PERIÓDICA"
# ============================================================

if check_executable "/usr/local/bin/auditoria-reconocimiento.sh"; then
    log_already "Auditoria periodica (auditoria-reconocimiento.sh ya instalado)"
elif ask "¿Crear script de auditoría externa periódica en /usr/local/bin/?"; then
    cat > /usr/local/bin/auditoria-reconocimiento.sh << 'AUDIT_EOF'
#!/bin/bash
# ============================================================
# AUDITORÍA PERIÓDICA DE RECONOCIMIENTO - TA0043
# Ejecutar periódicamente para verificar exposición externa
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

LOGFILE="/var/log/auditoria-reconocimiento-$(date +%Y%m%d).log"

echo "============================================================" | tee "$LOGFILE"
echo " AUDITORÍA DE RECONOCIMIENTO - $(date)" | tee -a "$LOGFILE"
echo "============================================================" | tee -a "$LOGFILE"
echo "" | tee -a "$LOGFILE"

ISSUES=0

# 1. Puertos expuestos (no localhost)
echo -e "${CYAN}[1/6] Puertos expuestos:${NC}" | tee -a "$LOGFILE"
EXPOSED=$(ss -tlnp 2>/dev/null | tail -n +2 | grep -vE "127\.|::1" || true)
if [[ -n "$EXPOSED" ]]; then
    echo "$EXPOSED" | tee -a "$LOGFILE"
    ISSUES=$((ISSUES + 1))
else
    echo -e "  ${GREEN}OK${NC} Sin puertos expuestos externamente" | tee -a "$LOGFILE"
fi

echo "" | tee -a "$LOGFILE"

# 2. UDP expuestos
echo -e "${CYAN}[2/6] Puertos UDP expuestos:${NC}" | tee -a "$LOGFILE"
UDP_EXP=$(ss -ulnp 2>/dev/null | tail -n +2 | grep -vE "127\.|::1" || true)
if [[ -n "$UDP_EXP" ]]; then
    echo "$UDP_EXP" | tee -a "$LOGFILE"
    ISSUES=$((ISSUES + 1))
else
    echo -e "  ${GREEN}OK${NC} Sin puertos UDP expuestos" | tee -a "$LOGFILE"
fi

echo "" | tee -a "$LOGFILE"

# 3. Verificación Shodan
echo -e "${CYAN}[3/6] Consulta Shodan InternetDB:${NC}" | tee -a "$LOGFILE"
PUBLIC_IP=$(curl -s -m10 https://api.ipify.org 2>/dev/null || echo "")
if [[ -n "$PUBLIC_IP" && "$PUBLIC_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    SHODAN=$(curl -s -m15 "https://internetdb.shodan.io/$PUBLIC_IP" 2>/dev/null || echo "")
    if [[ -n "$SHODAN" && "$SHODAN" != *"No information"* && "$SHODAN" != *"error"* ]]; then
        S_PORTS=$(echo "$SHODAN" | grep -oP '"ports":\s*\[\K[^\]]+' 2>/dev/null || echo "ninguno")
        S_VULNS=$(echo "$SHODAN" | grep -oP '"vulns":\s*\[\K[^\]]+' 2>/dev/null || echo "ninguna")
        echo -e "  IP: $PUBLIC_IP" | tee -a "$LOGFILE"
        echo -e "  Puertos: $S_PORTS" | tee -a "$LOGFILE"
        echo -e "  Vulnerabilidades: $S_VULNS" | tee -a "$LOGFILE"
        [[ "$S_PORTS" != "ninguno" ]] && ISSUES=$((ISSUES + 1))
        [[ "$S_VULNS" != "ninguna" ]] && ISSUES=$((ISSUES + 1))
    else
        echo -e "  ${GREEN}OK${NC} No encontrado en Shodan" | tee -a "$LOGFILE"
    fi
else
    echo -e "  ${DIM}Sin IP pública detectada${NC}" | tee -a "$LOGFILE"
fi

echo "" | tee -a "$LOGFILE"

# 4. TCP fingerprinting
echo -e "${CYAN}[4/6] Anti-fingerprinting:${NC}" | tee -a "$LOGFILE"
TCP_TS=$(sysctl -n net.ipv4.tcp_timestamps 2>/dev/null || echo "?")
DMESG=$(sysctl -n kernel.dmesg_restrict 2>/dev/null || echo "?")
echo -e "  TCP timestamps: $TCP_TS (recomendado: 0)" | tee -a "$LOGFILE"
echo -e "  dmesg_restrict: $DMESG (recomendado: 1)" | tee -a "$LOGFILE"
[[ "$TCP_TS" != "0" ]] && ISSUES=$((ISSUES + 1))
[[ "$DMESG" != "1" ]] && ISSUES=$((ISSUES + 1))

echo "" | tee -a "$LOGFILE"

# 5. Banners
echo -e "${CYAN}[5/6] Banners:${NC}" | tee -a "$LOGFILE"
for f in /etc/issue /etc/issue.net; do
    if [[ -f "$f" ]] && grep -qiE "suse|leap|linux.*[0-9]" "$f" 2>/dev/null; then
        echo -e "  ${YELLOW}[!]${NC} $f filtra información del OS" | tee -a "$LOGFILE"
        ISSUES=$((ISSUES + 1))
    else
        echo -e "  ${GREEN}OK${NC} $f seguro" | tee -a "$LOGFILE"
    fi
done

echo "" | tee -a "$LOGFILE"

# 6. Firewall
echo -e "${CYAN}[6/6] Firewall:${NC}" | tee -a "$LOGFILE"
if systemctl is-active firewalld &>/dev/null; then
    ZONE=$(fw_get_default_zone 2>/dev/null)
    echo -e "  ${GREEN}OK${NC} firewalld activo (zona: $ZONE)" | tee -a "$LOGFILE"
    [[ "$ZONE" != "drop" && "$ZONE" != "block" ]] && ISSUES=$((ISSUES + 1))
else
    echo -e "  ${RED}[X]${NC} Firewall NO activo" | tee -a "$LOGFILE"
    ISSUES=$((ISSUES + 1))
fi

echo "" | tee -a "$LOGFILE"
echo "============================================================" | tee -a "$LOGFILE"
if [[ $ISSUES -eq 0 ]]; then
    echo -e "${GREEN}RESULTADO: Sin problemas de exposición detectados${NC}" | tee -a "$LOGFILE"
else
    echo -e "${YELLOW}RESULTADO: $ISSUES problema(s) de exposición detectado(s)${NC}" | tee -a "$LOGFILE"
fi
echo "Log: $LOGFILE" | tee -a "$LOGFILE"
AUDIT_EOF

    chmod +x /usr/local/bin/auditoria-reconocimiento.sh
    log_info "Script creado: /usr/local/bin/auditoria-reconocimiento.sh"
fi

# ============================================================
log_section "12. PROGRAMAR AUDITORÍA PERIÓDICA"
# ============================================================

if check_file_exists "/etc/cron.weekly/auditoria-reconocimiento"; then
    log_already "Cron semanal auditoria (ya programado)"
elif ask "¿Programar auditoría semanal de reconocimiento (cron)?"; then
    cat > /etc/cron.weekly/auditoria-reconocimiento << 'CRON_EOF'
#!/bin/bash
# Auditoría semanal de reconocimiento (TA0043)
/usr/local/bin/auditoria-reconocimiento.sh > /dev/null 2>&1
CRON_EOF
    chmod +x /etc/cron.weekly/auditoria-reconocimiento
    log_info "Auditoría semanal programada en /etc/cron.weekly/"
fi

# ============================================================
# RESUMEN Y PUNTUACIÓN
# ============================================================
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║    AUDITORÍA DE RECONOCIMIENTO COMPLETADA                 ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

total=$((checks_ok + warnings))
score=0
if [[ $total -gt 0 ]]; then
    score=$(( checks_ok * 100 / total ))
fi

if [[ $score -ge 80 ]]; then
    echo -e "  Puntuación: ${GREEN}${BOLD}${score}%${NC} - Buena protección contra reconocimiento"
elif [[ $score -ge 50 ]]; then
    echo -e "  Puntuación: ${YELLOW}${BOLD}${score}%${NC} - Protección parcial"
else
    echo -e "  Puntuación: ${RED}${BOLD}${score}%${NC} - Exposición significativa"
fi

echo ""
echo -e "  ${GREEN}●${NC} Checks OK:     ${GREEN}${BOLD}$checks_ok${NC}"
echo -e "  ${YELLOW}●${NC} Advertencias:  ${YELLOW}${BOLD}$warnings${NC}"
echo ""

echo "Acciones recomendadas:"
echo "  - Ejecutar auditoría periódica: /usr/local/bin/auditoria-reconocimiento.sh"
echo "  - Verificar en Shodan: https://www.shodan.io/host/$PUBLIC_IP"
echo "  - Verificar en Censys: https://search.censys.io/hosts/$PUBLIC_IP"
echo "  - Verificar en GreyNoise: https://viz.greynoise.io/ip/$PUBLIC_IP"
echo ""
echo "Informe completo en: $REPORT_FILE"
log_info "Backup/reportes en: $REPORT_DIR"
show_changes_summary
