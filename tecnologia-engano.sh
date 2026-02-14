#!/bin/bash
# ============================================================
# tecnologia-engano.sh - Modulo 55: Tecnologia de Engano
# ============================================================
# Secciones:
#   S1  - Honeypots de Red (puertos trampa)
#   S2  - Honey Tokens (credenciales canario)
#   S3  - Honey Files (documentos senuelo)
#   S4  - Honey Users (cuentas canario)
#   S5  - Honey Directories (directorios trampa)
#   S6  - Honey DNS (registros DNS canario)
#   S7  - Deception Network Services (servicios falsos)
#   S8  - Sistema de Alertas de Deception
#   S9  - Dashboard de Deception
#   S10 - Auditoria Integral de Deception
# ============================================================

set -euo pipefail

DECEPTION_SECTION="${1:-all}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"
source "${SCRIPT_DIR}/lib/securizar-firewall.sh"

require_root
securizar_setup_traps
init_backup "deception-tech"

if [[ "$DECEPTION_SECTION" == "all" ]]; then
    echo ""
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║   MODULO 55 - TECNOLOGIA DE ENGANO (DECEPTION TECH)      ║"
    echo "║   Honeypots, tokens, honey files, honey users, DNS        ║"
    echo "║   Servicios falsos, alertas, dashboard, auditoria          ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo ""

    log_section "MODULO 55: TECNOLOGIA DE ENGANO"
    log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

    # ── Pre-check rapido ────────────────────────────────────
    _precheck 10
    _pc check_executable /usr/local/bin/gestionar-honeypots.sh
    _pc check_executable /usr/local/bin/generar-honeytokens.sh
    _pc check_executable /usr/local/bin/desplegar-honeyfiles.sh
    _pc check_executable /usr/local/bin/gestionar-honey-users.sh
    _pc check_file_exists /etc/securizar/honeydirs.conf
    _pc check_executable /usr/local/bin/configurar-honey-dns.sh
    _pc check_executable /usr/local/bin/gestionar-servicios-decoy.sh
    _pc check_executable /usr/local/bin/alertar-deception.sh
    _pc check_executable /usr/local/bin/dashboard-deception.sh
    _pc check_executable /usr/local/bin/auditoria-deception.sh
    _precheck_result
fi

# ── Directorios base ─────────────────────────────────────────
DECEPTION_CONF_DIR="/etc/securizar/deception"
DECEPTION_LOG_DIR="/var/log/securizar/honeypot"
DECEPTION_WEB_LOG="/var/log/securizar/decoy-web.log"
DECEPTION_ALERT_LOG="/var/log/securizar/deception-alerts.log"

mkdir -p /etc/securizar
mkdir -p "$DECEPTION_CONF_DIR"
mkdir -p "$DECEPTION_LOG_DIR"
mkdir -p "${DECEPTION_LOG_DIR}/pcap"
mkdir -p /var/log/securizar

if [[ "$DECEPTION_SECTION" == "all" ]]; then
# ── Deteccion de despliegue previo ─────────────────────────────
# Comprobar si ya existe un despliegue para evitar duplicados al re-ejecutar
DECEPTION_EXISTING=0
DECEPTION_EXISTING_SUMMARY=""

# Honeypots de red (S1)
_hp_running=0
for _hp_port in 2222 2323 2121 4445 3390 3307; do
    if systemctl is-active "securizar-honeypot@${_hp_port}.service" &>/dev/null; then
        ((_hp_running++)) || true
    fi
done
if [[ $_hp_running -gt 0 ]]; then
    DECEPTION_EXISTING=1
    DECEPTION_EXISTING_SUMMARY+="  - Honeypots de red: ${_hp_running} servicios activos\n"
fi

# Honeytokens (S2)
if [[ -f /etc/securizar/honeytokens.conf ]] && grep -q '^HONEYTOKEN|' /etc/securizar/honeytokens.conf 2>/dev/null; then
    _ht_count=$(grep -c '^HONEYTOKEN|' /etc/securizar/honeytokens.conf 2>/dev/null || echo 0)
    DECEPTION_EXISTING=1
    DECEPTION_EXISTING_SUMMARY+="  - Honeytokens: ${_ht_count} tokens inventariados\n"
fi

# Honeyfiles (S3)
if [[ -f /etc/securizar/honeyfiles.conf ]] && grep -q '^HONEYFILE|' /etc/securizar/honeyfiles.conf 2>/dev/null; then
    _hf_count=$(grep -c '^HONEYFILE|' /etc/securizar/honeyfiles.conf 2>/dev/null || echo 0)
    DECEPTION_EXISTING=1
    DECEPTION_EXISTING_SUMMARY+="  - Honeyfiles: ${_hf_count} ficheros inventariados\n"
fi

# Honey users (S4)
if [[ -f /etc/securizar/honeyusers.conf ]] && grep -q '^HONEYUSER|' /etc/securizar/honeyusers.conf 2>/dev/null; then
    _hu_count=$(grep -c '^HONEYUSER|' /etc/securizar/honeyusers.conf 2>/dev/null || echo 0)
    DECEPTION_EXISTING=1
    DECEPTION_EXISTING_SUMMARY+="  - Honey users: ${_hu_count} cuentas\n"
fi

# Honey dirs (S5)
if [[ -f /etc/securizar/honeydirs.conf ]] && grep -q '^HONEYDIR|' /etc/securizar/honeydirs.conf 2>/dev/null; then
    _hd_count=$(grep -c '^HONEYDIR|' /etc/securizar/honeydirs.conf 2>/dev/null || echo 0)
    DECEPTION_EXISTING=1
    DECEPTION_EXISTING_SUMMARY+="  - Honey dirs: ${_hd_count} directorios\n"
fi

# Honey DNS (S6)
if grep -q "# BEGIN SECURIZAR HONEY DNS" /etc/hosts 2>/dev/null; then
    DECEPTION_EXISTING=1
    DECEPTION_EXISTING_SUMMARY+="  - Honey DNS: entradas activas en /etc/hosts\n"
fi

# Decoy services (S7)
_ds_running=0
for _ds_svc in securizar-decoy-web securizar-decoy-api; do
    if systemctl is-active "${_ds_svc}.service" &>/dev/null; then
        ((_ds_running++)) || true
    fi
done
if [[ $_ds_running -gt 0 ]]; then
    DECEPTION_EXISTING=1
    DECEPTION_EXISTING_SUMMARY+="  - Servicios decoy: ${_ds_running} activos\n"
fi

# Firewall rules (S1)
_fw_rules=0
case "${FW_BACKEND:-none}" in
    nftables)
        if nft list table inet securizar-deception &>/dev/null; then
            _fw_rules=1
            DECEPTION_EXISTING_SUMMARY+="  - Firewall: tabla nftables securizar-deception\n"
        fi ;;
    iptables)
        if iptables -t nat -L PREROUTING -n 2>/dev/null | grep -q 'REDIRECT.*honeypot\|REDIRECT.*222[2-3]\|REDIRECT.*2121\|REDIRECT.*4445\|REDIRECT.*3390\|REDIRECT.*3307'; then
            _fw_rules=1
            DECEPTION_EXISTING_SUMMARY+="  - Firewall: reglas iptables REDIRECT\n"
        fi ;;
esac
if [[ $_fw_rules -eq 1 ]]; then
    DECEPTION_EXISTING=1
fi

# PCAP tcpdump procesos huerfanos
_pcap_pids=0
for _pcap_pid_file in "${DECEPTION_CONF_DIR}"/honeypot-*-pcap.pid; do
    [[ -f "$_pcap_pid_file" ]] || continue
    _pcap_pid=$(cat "$_pcap_pid_file" 2>/dev/null || echo "")
    if [[ -n "$_pcap_pid" ]] && kill -0 "$_pcap_pid" 2>/dev/null; then
        ((_pcap_pids++)) || true
    fi
done
if [[ $_pcap_pids -gt 0 ]]; then
    DECEPTION_EXISTING_SUMMARY+="  - PCAP: ${_pcap_pids} procesos tcpdump activos\n"
fi

# Mostrar resumen si hay despliegue previo
if [[ "$DECEPTION_EXISTING" -eq 1 ]]; then
    echo ""
    echo -e "${YELLOW}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}${BOLD}║  DESPLIEGUE PREVIO DETECTADO                              ║${NC}"
    echo -e "${YELLOW}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}Se han detectado componentes de deception ya desplegados:${NC}"
    echo -e "$DECEPTION_EXISTING_SUMMARY"
    echo -e "${CYAN}Al responder 'sí' a cada sección, los componentes existentes se${NC}"
    echo -e "${CYAN}actualizarán in-place (servicios reiniciados, scripts sobrescritos,${NC}"
    echo -e "${CYAN}inventarios regenerados). No se crearán duplicados.${NC}"
    echo ""
    log_info "Modo actualizacion: componentes existentes seran actualizados"
fi

# Limpiar variables temporales de deteccion
unset _hp_running _ht_count _hf_count _hu_count _hd_count _ds_running _fw_rules _pcap_pids _pcap_pid _pcap_pid_file
fi  # DECEPTION_SECTION == all (deteccion)

# ── Helper: generar ID unico de token ────────────────────────
generate_token_id() {
    local prefix="${1:-TKN}"
    echo "${prefix}-$(date +%Y%m%d)-$(openssl rand -hex 4 2>/dev/null || head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
}

# ── Helper: log forense con formato admisible como evidencia ──
# Genera lineas de log con:
#   - Timestamp ISO 8601 UTC con milisegundos
#   - Session ID unico por conexion
#   - FQDN del host
#   - Formato key=value estructurado
#   - Hash SHA-256 de la linea anterior (cadena anti-tampering)
FORENSIC_PREV_HASH="0000000000000000000000000000000000000000000000000000000000000000"
FORENSIC_HOSTNAME="$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo unknown)"

forensic_timestamp() {
    date -u '+%Y-%m-%dT%H:%M:%S.%3NZ'
}

forensic_session_id() {
    openssl rand -hex 8 2>/dev/null || head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n'
}

forensic_log() {
    local log_file="$1"
    shift
    local fields="$*"
    local ts
    ts="$(forensic_timestamp)"
    local line="timestamp=${ts} host=${FORENSIC_HOSTNAME} prev_hash=${FORENSIC_PREV_HASH} ${fields}"
    echo "$line" >> "$log_file"
    FORENSIC_PREV_HASH="$(echo -n "$line" | sha256sum 2>/dev/null | cut -d' ' -f1 || echo "nohash")"
}

# ── Helper: generar credenciales falsas convincentes ─────────
generate_fake_aws_key() {
    # Formato realista de AWS key ID (AKIA + 16 chars)
    local key_id="AKIA$(openssl rand -hex 8 2>/dev/null | tr '[:lower:]' '[:upper:]')"
    local secret_key
    secret_key="$(openssl rand -base64 30 2>/dev/null | tr -dc 'A-Za-z0-9+/' | head -c 40)"
    echo "${key_id}|${secret_key}"
}

generate_fake_password() {
    openssl rand -base64 18 2>/dev/null | tr -dc 'A-Za-z0-9!@#$%' | head -c 24
}

generate_fake_ssh_key() {
    local keyfile="$1"
    local token_id="$2"
    # Create a fake but convincing RSA private key header
    cat > "$keyfile" << EOFKEY
-----BEGIN OPENSSH PRIVATE KEY-----
$(openssl rand -base64 48 2>/dev/null || head -c 64 /dev/urandom | base64)
$(openssl rand -base64 48 2>/dev/null || head -c 64 /dev/urandom | base64)
$(openssl rand -base64 48 2>/dev/null || head -c 64 /dev/urandom | base64)
$(openssl rand -base64 48 2>/dev/null || head -c 64 /dev/urandom | base64)
$(openssl rand -base64 48 2>/dev/null || head -c 64 /dev/urandom | base64)
# CANARY-TOKEN: ${token_id}
-----END OPENSSH PRIVATE KEY-----
EOFKEY
    chmod 600 "$keyfile"
}

if [[ "$DECEPTION_SECTION" == "all" || "$DECEPTION_SECTION" == "S1" ]]; then
# ============================================================
# S1: HONEYPOTS DE RED (PUERTOS TRAMPA)
# ============================================================
log_section "S1: HONEYPOTS DE RED (PUERTOS TRAMPA)"

log_info "Honeypots de red con listeners en puertos comunes de ataque:"
log_info "  - SSH (2222), Telnet (2323), FTP (2121)"
log_info "  - SMB (4445), RDP (3390), MySQL (3307)"
log_info "  - Logging de conexiones, alertas via syslog"
log_info "  - Servicios systemd con template unit"
log_info ""

if check_executable /usr/local/bin/gestionar-honeypots.sh; then
    log_already "Honeypots de red (gestionar-honeypots.sh existe)"
elif ask "¿Desplegar honeypots de red (puertos trampa)?"; then

    # Verificar disponibilidad de ncat o socat
    HONEYPOT_LISTENER=""
    if command -v ncat &>/dev/null; then
        HONEYPOT_LISTENER="ncat"
        log_info "Usando ncat como listener de honeypot"
    elif command -v socat &>/dev/null; then
        HONEYPOT_LISTENER="socat"
        log_info "Usando socat como listener de honeypot"
    else
        log_warn "Ni ncat ni socat encontrados - instalando nmap/socat..."
        if ask "¿Instalar herramientas de red necesarias (ncat/socat)?"; then
            pkg_install nmap socat || true
            if command -v ncat &>/dev/null; then
                HONEYPOT_LISTENER="ncat"
            elif command -v socat &>/dev/null; then
                HONEYPOT_LISTENER="socat"
            else
                log_error "No se pudo instalar ncat ni socat - honeypots no disponibles"
                HONEYPOT_LISTENER=""
            fi
        else
            log_skip "Instalacion de herramientas de red para honeypots"
        fi
    fi

    if [[ -n "$HONEYPOT_LISTENER" ]]; then

        # Crear script de gestion de honeypots
        log_info "Creando /usr/local/bin/gestionar-honeypots.sh..."
        cat > /usr/local/bin/gestionar-honeypots.sh << 'EOFHONEYPOT'
#!/bin/bash
# ============================================================
# gestionar-honeypots.sh - Gestion de honeypots de red
# Parte de securizar Modulo 55 - Tecnologia de Engano
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar/honeypot"
CONF_DIR="/etc/securizar/deception"
ALERT_SCRIPT="/usr/local/bin/alertar-deception.sh"

mkdir -p "$LOG_DIR"

usage() {
    echo "Uso: $0 {start|stop|status|list|add-port|remove-port}"
    echo ""
    echo "Comandos:"
    echo "  start [puerto]     - Iniciar honeypot(s)"
    echo "  stop [puerto]      - Detener honeypot(s)"
    echo "  status             - Ver estado de todos los honeypots"
    echo "  list               - Listar puertos configurados"
    echo "  add-port PUERTO    - Agregar un puerto honeypot"
    echo "  remove-port PUERTO - Eliminar un puerto honeypot"
    echo "  logs [puerto]      - Ver logs de conexiones"
    exit 1
}

# Puertos honeypot por defecto
DEFAULT_PORTS="2222 2323 2121 4445 3390 3307"

# Nombres de servicios asociados a cada puerto
port_service_name() {
    case "$1" in
        2222) echo "SSH-Honeypot" ;;
        2323) echo "Telnet-Honeypot" ;;
        2121) echo "FTP-Honeypot" ;;
        4445) echo "SMB-Honeypot" ;;
        3390) echo "RDP-Honeypot" ;;
        3307) echo "MySQL-Honeypot" ;;
        *)    echo "Custom-Honeypot-$1" ;;
    esac
}

# Banner falso segun el puerto
port_banner() {
    case "$1" in
        2222) echo "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1" ;;
        2323) echo "Welcome to Microsoft Telnet Service" ;;
        2121) echo "220 ProFTPD 1.3.5e Server (Debian)" ;;
        4445) echo "SMB Server ready" ;;
        3390) echo "" ;;
        3307) echo "5.7.38-0ubuntu0.18.04.1" ;;
        *)    echo "Service ready" ;;
    esac
}

# Log una conexion honeypot (formato forense)
log_honeypot_connection() {
    local port="$1"
    local src_ip="$2"
    local data="${3:-}"
    local src_port="${4:-0}"
    local timestamp
    timestamp="$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')"
    local service_name
    service_name="$(port_service_name "$port")"
    local session_id
    session_id="$(openssl rand -hex 8 2>/dev/null || echo "nosid")"

    # Metadatos de red mejorados
    local mac_src="unknown"
    if [[ "$src_ip" != "unknown" ]] && command -v arp &>/dev/null; then
        mac_src="$(arp -n "$src_ip" 2>/dev/null | awk '/ether/{print $3}' | head -1)"
        [[ -z "$mac_src" ]] && mac_src="unknown"
    fi
    local data_length=${#data}
    local payload_hex=""
    if [[ -n "$data" ]]; then
        payload_hex="$(echo -n "$data" | xxd -p 2>/dev/null | head -c 512 || echo "")"
    fi
    local payload_sha256=""
    if [[ -n "$data" ]]; then
        payload_sha256="$(echo -n "$data" | sha256sum 2>/dev/null | cut -d' ' -f1 || echo "")"
    fi

    local log_file="${LOG_DIR}/honeypot-${port}.log"
    local log_line="timestamp=${timestamp} session_id=${session_id} src_ip=${src_ip} src_port=${src_port} dst_port=${port} protocol=tcp mac_src=${mac_src} service=${service_name} data_length=${data_length} payload_sha256=${payload_sha256} payload_hex=${payload_hex} data=${data}"
    echo "$log_line" >> "$log_file"

    # Syslog
    logger -t "securizar-honeypot" -p auth.warning \
        "HONEYPOT CONNECTION: session=${session_id} port=${port} src=${src_ip}:${src_port} service=${service_name} mac=${mac_src}"

    # Alerta centralizada
    if [[ -x "$ALERT_SCRIPT" ]]; then
        "$ALERT_SCRIPT" "WARNING" "HONEYPOT" \
            "Conexion honeypot detectada: ${src_ip}:${src_port} -> puerto ${port} (${service_name}) session=${session_id}" &
    fi
}

# Iniciar listener en un puerto
start_honeypot_port() {
    local port="$1"
    local banner
    banner="$(port_banner "$port")"
    local pid_file="${CONF_DIR}/honeypot-${port}.pid"

    if [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
        echo "[!] Honeypot en puerto ${port} ya esta activo (PID: $(cat "$pid_file"))"
        return 0
    fi

    local listener_cmd=""
    if command -v ncat &>/dev/null; then
        # ncat listener con logging
        ncat -l -k -p "$port" -c "
            SRC=\$(echo \$NCAT_REMOTE_ADDR 2>/dev/null || echo unknown)
            SRC_PORT=\$(echo \$NCAT_REMOTE_PORT 2>/dev/null || echo 0)
            SID=\$(openssl rand -hex 8 2>/dev/null || echo nosid)
            TS=\$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')
            echo '${banner}'
            read -t 5 DATA || DATA=''
            DLEN=\${#DATA}
            PHASH=\$(echo -n \"\${DATA}\" | sha256sum 2>/dev/null | cut -d' ' -f1 || echo '')
            PHEX=\$(echo -n \"\${DATA}\" | xxd -p 2>/dev/null | head -c 512 || echo '')
            MAC=\$(arp -n \"\${SRC}\" 2>/dev/null | awk '/ether/{print \$3}' | head -1)
            [[ -z \"\${MAC}\" ]] && MAC=unknown
            echo \"timestamp=\${TS} session_id=\${SID} src_ip=\${SRC} src_port=\${SRC_PORT} dst_port=${port} protocol=tcp mac_src=\${MAC} service=$(port_service_name "$port") data_length=\${DLEN} payload_sha256=\${PHASH} payload_hex=\${PHEX} data=\${DATA}\" >> ${LOG_DIR}/honeypot-${port}.log
            logger -t securizar-honeypot -p auth.warning \"HONEYPOT: session=\${SID} port=${port} src=\${SRC}:\${SRC_PORT} mac=\${MAC}\"
            if [[ -x ${ALERT_SCRIPT} ]]; then
                ${ALERT_SCRIPT} WARNING HONEYPOT \"Conexion: \${SRC}:\${SRC_PORT} -> ${port} session=\${SID}\" &
            fi
        " &
        local hp_pid=$!
    elif command -v socat &>/dev/null; then
        # socat listener con logging
        socat TCP-LISTEN:"${port}",reuseaddr,fork \
            SYSTEM:"
                SRC=\$(echo \$SOCAT_PEERADDR 2>/dev/null || echo unknown)
                SRC_PORT=\$(echo \$SOCAT_PEERPORT 2>/dev/null || echo 0)
                SID=\$(openssl rand -hex 8 2>/dev/null || echo nosid)
                TS=\$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')
                echo '${banner}'
                read -t 5 DATA || DATA=''
                DLEN=\${#DATA}
                PHASH=\$(echo -n \"\${DATA}\" | sha256sum 2>/dev/null | cut -d' ' -f1 || echo '')
                PHEX=\$(echo -n \"\${DATA}\" | xxd -p 2>/dev/null | head -c 512 || echo '')
                MAC=\$(arp -n \"\${SRC}\" 2>/dev/null | awk '/ether/{print \$3}' | head -1)
                [[ -z \"\${MAC}\" ]] && MAC=unknown
                echo \"timestamp=\${TS} session_id=\${SID} src_ip=\${SRC} src_port=\${SRC_PORT} dst_port=${port} protocol=tcp mac_src=\${MAC} service=$(port_service_name "$port") data_length=\${DLEN} payload_sha256=\${PHASH} payload_hex=\${PHEX} data=\${DATA}\" >> ${LOG_DIR}/honeypot-${port}.log
                logger -t securizar-honeypot -p auth.warning \"HONEYPOT: session=\${SID} port=${port} src=\${SRC}:\${SRC_PORT} mac=\${MAC}\"
                if [[ -x ${ALERT_SCRIPT} ]]; then
                    ${ALERT_SCRIPT} WARNING HONEYPOT \"Conexion: \${SRC}:\${SRC_PORT} -> ${port} session=\${SID}\" &
                fi
            " &
        local hp_pid=$!
    else
        echo "[X] No se encontro ncat ni socat"
        return 1
    fi

    echo "$hp_pid" > "$pid_file"
    echo "[+] Honeypot iniciado en puerto ${port} (PID: ${hp_pid})"

    # Captura PCAP forense por puerto
    if command -v tcpdump &>/dev/null; then
        local pcap_dir="${LOG_DIR}/pcap"
        mkdir -p "$pcap_dir"
        tcpdump -i any -n -w "${pcap_dir}/honeypot-${port}-%Y%m%d-%H%M%S.pcap" \
            -G 3600 -Z root "port ${port}" &>/dev/null &
        local pcap_pid=$!
        echo "$pcap_pid" > "${CONF_DIR}/honeypot-${port}-pcap.pid"
        echo "[+] Captura PCAP iniciada para puerto ${port} (PID: ${pcap_pid})"
    fi
}

# Detener un honeypot
stop_honeypot_port() {
    local port="$1"
    local pid_file="${CONF_DIR}/honeypot-${port}.pid"

    if [[ -f "$pid_file" ]]; then
        local pid
        pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            echo "[+] Honeypot en puerto ${port} detenido (PID: ${pid})"
        else
            echo "[!] Proceso ${pid} ya no existe"
        fi
        rm -f "$pid_file"
    else
        echo "[!] No hay honeypot registrado en puerto ${port}"
    fi

    # Detener captura PCAP asociada
    local pcap_pid_file="${CONF_DIR}/honeypot-${port}-pcap.pid"
    if [[ -f "$pcap_pid_file" ]]; then
        local pcap_pid
        pcap_pid=$(cat "$pcap_pid_file")
        kill "$pcap_pid" 2>/dev/null || true
        rm -f "$pcap_pid_file"
        echo "[+] Captura PCAP del puerto ${port} detenida"
    fi
}

# Estado de todos los honeypots
show_status() {
    echo ""
    echo "═══════════════════════════════════════════"
    echo "  ESTADO DE HONEYPOTS"
    echo "═══════════════════════════════════════════"
    echo ""

    local active=0
    local inactive=0

    for pid_file in "${CONF_DIR}"/honeypot-*.pid; do
        [[ -f "$pid_file" ]] || continue
        local port
        port=$(basename "$pid_file" | sed 's/honeypot-//;s/\.pid//')
        local pid
        pid=$(cat "$pid_file")
        local service_name
        service_name="$(port_service_name "$port")"

        if kill -0 "$pid" 2>/dev/null; then
            echo "  [ACTIVO]   Puerto ${port} (${service_name}) - PID ${pid}"
            ((active++)) || true
        else
            echo "  [INACTIVO] Puerto ${port} (${service_name}) - PID ${pid} (proceso muerto)"
            ((inactive++)) || true
        fi
    done

    if [[ $active -eq 0 && $inactive -eq 0 ]]; then
        echo "  No hay honeypots configurados"
    fi

    echo ""
    echo "  Activos: ${active} | Inactivos: ${inactive}"

    # Estadisticas de conexiones
    echo ""
    echo "  Conexiones recientes (ultimas 24h):"
    local total_connections=0
    for logfile in "${LOG_DIR}"/honeypot-*.log; do
        [[ -f "$logfile" ]] || continue
        local port
        port=$(basename "$logfile" | sed 's/honeypot-//;s/\.log//')
        local count
        count=$(awk -v cutoff="$(date -d '24 hours ago' '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" \
            '$0 >= "["cutoff {c++} END{print c+0}' "$logfile" 2>/dev/null || echo "0")
        if [[ "$count" -gt 0 ]]; then
            echo "    Puerto ${port}: ${count} conexiones"
            total_connections=$((total_connections + count))
        fi
    done
    if [[ $total_connections -eq 0 ]]; then
        echo "    Sin conexiones en las ultimas 24h"
    fi
    echo ""
}

# Ver logs
show_logs() {
    local port="${1:-}"
    if [[ -n "$port" ]]; then
        local logfile="${LOG_DIR}/honeypot-${port}.log"
        if [[ -f "$logfile" ]]; then
            echo "=== Logs de honeypot puerto ${port} ==="
            tail -50 "$logfile"
        else
            echo "[!] No hay logs para puerto ${port}"
        fi
    else
        echo "=== Ultimas conexiones a todos los honeypots ==="
        for logfile in "${LOG_DIR}"/honeypot-*.log; do
            [[ -f "$logfile" ]] || continue
            echo "--- $(basename "$logfile") ---"
            tail -10 "$logfile"
            echo ""
        done
    fi
}

# Main
case "${1:-}" in
    start)
        if [[ -n "${2:-}" ]]; then
            start_honeypot_port "$2"
        else
            for port in $DEFAULT_PORTS; do
                start_honeypot_port "$port"
            done
        fi
        ;;
    stop)
        if [[ -n "${2:-}" ]]; then
            stop_honeypot_port "$2"
        else
            for pid_file in "${CONF_DIR}"/honeypot-*.pid; do
                [[ -f "$pid_file" ]] || continue
                local_port=$(basename "$pid_file" | sed 's/honeypot-//;s/\.pid//')
                stop_honeypot_port "$local_port"
            done
        fi
        ;;
    status)
        show_status
        ;;
    list)
        echo "Puertos honeypot por defecto: $DEFAULT_PORTS"
        echo ""
        echo "Honeypots activos:"
        for pid_file in "${CONF_DIR}"/honeypot-*.pid; do
            [[ -f "$pid_file" ]] || continue
            echo "  - $(basename "$pid_file" | sed 's/honeypot-//;s/\.pid//')"
        done
        ;;
    add-port)
        [[ -z "${2:-}" ]] && { echo "[X] Especifica un puerto"; exit 1; }
        start_honeypot_port "$2"
        ;;
    remove-port)
        [[ -z "${2:-}" ]] && { echo "[X] Especifica un puerto"; exit 1; }
        stop_honeypot_port "$2"
        ;;
    logs)
        show_logs "${2:-}"
        ;;
    *)
        usage
        ;;
esac
EOFHONEYPOT
        chmod +x /usr/local/bin/gestionar-honeypots.sh
        log_change "Creado" "/usr/local/bin/gestionar-honeypots.sh"

        # Crear template unit de systemd para honeypots
        log_info "Creando template unit securizar-honeypot@.service..."
        cat > /etc/systemd/system/securizar-honeypot@.service << 'EOFSVCTEMPLATE'
[Unit]
Description=Securizar Honeypot en puerto %i
Documentation=man:securizar(8)
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/gestionar-honeypots.sh start %i
ExecStop=/usr/local/bin/gestionar-honeypots.sh stop %i
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=securizar-honeypot-%i

# Seguridad del servicio
ProtectSystem=strict
ReadWritePaths=/var/log/securizar /etc/securizar/deception
ProtectHome=yes
PrivateTmp=yes
AmbientCapabilities=CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOFSVCTEMPLATE
        log_change "Creado" "/etc/systemd/system/securizar-honeypot@.service (template unit)"

        # Habilitar honeypots en los puertos por defecto
        if ask "¿Habilitar e iniciar honeypots en puertos por defecto (2222,2323,2121,4445,3390,3307)?"; then
            systemctl daemon-reload || true
            for hp_port in 2222 2323 2121 4445 3390 3307; do
                # Limpiar PCAP tcpdump huerfano antes de (re)iniciar
                _pcap_pidfile="${DECEPTION_CONF_DIR}/honeypot-${hp_port}-pcap.pid"
                if [[ -f "$_pcap_pidfile" ]]; then
                    _old_pcap=$(cat "$_pcap_pidfile" 2>/dev/null || echo "")
                    if [[ -n "$_old_pcap" ]]; then
                        kill "$_old_pcap" 2>/dev/null || true
                    fi
                    rm -f "$_pcap_pidfile"
                fi

                systemctl enable "securizar-honeypot@${hp_port}.service" 2>/dev/null || true
                if systemctl is-active "securizar-honeypot@${hp_port}.service" &>/dev/null; then
                    systemctl restart "securizar-honeypot@${hp_port}.service" 2>/dev/null || true
                    log_change "Reiniciado" "Honeypot en puerto ${hp_port} (actualizado)"
                else
                    systemctl start "securizar-honeypot@${hp_port}.service" 2>/dev/null || true
                    log_change "Habilitado" "Honeypot en puerto ${hp_port}"
                fi
            done
        else
            log_skip "Activacion de honeypots en puertos por defecto"
        fi

        # Reglas de firewall opcionales para redireccion (multi-backend)
        if ask "¿Configurar redireccion de puertos reales a honeypots (${FW_BACKEND})?"; then
            log_info "Configurando reglas de redireccion (backend: ${FW_BACKEND})..."

            # Mapa: puerto real -> puerto honeypot
            declare -A REDIRECT_MAP=(
                [22]=2222
                [23]=2323
                [21]=2121
                [445]=4445
                [3389]=3390
                [3306]=3307
            )

            for real_port in "${!REDIRECT_MAP[@]}"; do
                hp_port="${REDIRECT_MAP[$real_port]}"

                # Solo redirigir si el puerto real no tiene un servicio real activo
                if ss -tlnp 2>/dev/null | grep -q ":${real_port} " ; then
                    log_warn "Puerto ${real_port} tiene servicio activo - no se redirige a honeypot"
                else
                    case "$FW_BACKEND" in
                        nftables)
                            nft add table inet securizar-deception 2>/dev/null || true
                            nft add chain inet securizar-deception prerouting \
                                '{ type nat hook prerouting priority dstnat; policy accept; }' 2>/dev/null || true
                            # Evitar regla duplicada: comprobar si ya existe
                            if ! nft list chain inet securizar-deception prerouting 2>/dev/null \
                                    | grep -q "dport ${real_port} redirect to :${hp_port}"; then
                                nft add rule inet securizar-deception prerouting \
                                    tcp dport "$real_port" redirect to :"$hp_port" 2>/dev/null || true
                            fi
                            ;;
                        firewalld)
                            firewall-cmd --permanent \
                                --add-forward-port="port=${real_port}:proto=tcp:toport=${hp_port}" 2>/dev/null || true
                            ;;
                        iptables)
                            if ! iptables -t nat -C PREROUTING -p tcp --dport "$real_port" \
                                -j REDIRECT --to-port "$hp_port" 2>/dev/null; then
                                iptables -t nat -A PREROUTING -p tcp --dport "$real_port" \
                                    -j REDIRECT --to-port "$hp_port" 2>/dev/null || true
                            fi
                            ;;
                        *)
                            log_warn "Backend de firewall '${FW_BACKEND}' no soporta redireccion"
                            continue
                            ;;
                    esac
                    log_change "Redirigido" "Puerto ${real_port} -> ${hp_port} (honeypot, via ${FW_BACKEND})"
                fi
            done

            # Persistir reglas segun backend
            case "$FW_BACKEND" in
                nftables)
                    nft list ruleset > /etc/nftables-securizar-deception.conf 2>/dev/null || true
                    log_change "Persistidas" "Reglas nftables de redireccion a honeypots"
                    ;;
                firewalld)
                    firewall-cmd --reload 2>/dev/null || true
                    log_change "Persistidas" "Reglas firewalld de redireccion a honeypots"
                    ;;
                iptables)
                    case "$DISTRO_FAMILY" in
                        suse)   iptables-save > /etc/sysconfig/iptables 2>/dev/null || true ;;
                        debian)
                            if command -v netfilter-persistent &>/dev/null; then
                                netfilter-persistent save 2>/dev/null || true
                            elif [[ -d /etc/iptables ]]; then
                                iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
                            fi
                            ;;
                        rhel)   iptables-save > /etc/sysconfig/iptables 2>/dev/null || true ;;
                        arch)   iptables-save > /etc/iptables/iptables.rules 2>/dev/null || true ;;
                    esac
                    log_change "Persistidas" "Reglas iptables de redireccion a honeypots"
                    ;;
            esac
        else
            log_skip "Redireccion de puertos a honeypots"
        fi

        log_info "Honeypots de red configurados"
        log_info "Gestionar: gestionar-honeypots.sh {start|stop|status|logs}"
    fi
else
    log_skip "Honeypots de red (puertos trampa)"
fi
fi  # S1

if [[ "$DECEPTION_SECTION" == "all" || "$DECEPTION_SECTION" == "S2" ]]; then
# ============================================================
# S2: HONEY TOKENS (CREDENCIALES CANARIO)
# ============================================================
log_section "S2: HONEY TOKENS (CREDENCIALES CANARIO)"

log_info "Honey tokens - credenciales falsas monitorizadas:"
log_info "  - Fake AWS credentials en ubicaciones clave"
log_info "  - Fake SSH keys en ubicaciones senuelo"
log_info "  - Fake database credentials"
log_info "  - Fake .env files con canary tokens"
log_info "  - Monitorizacion via auditd"
log_info ""

if check_executable /usr/local/bin/generar-honeytokens.sh; then
    log_already "Honey tokens (generar-honeytokens.sh existe)"
elif ask "¿Desplegar honey tokens (credenciales canario)?"; then

    HONEYTOKENS_CONF="/etc/securizar/honeytokens.conf"
    HONEYTOKENS_INVENTORY=()

    # Crear script generador de honeytokens
    log_info "Creando /usr/local/bin/generar-honeytokens.sh..."
    cat > /usr/local/bin/generar-honeytokens.sh << 'EOFHONEYTOKENS'
#!/bin/bash
# ============================================================
# generar-honeytokens.sh - Generacion y despliegue de honey tokens
# Parte de securizar Modulo 55 - Tecnologia de Engano
# ============================================================
set -euo pipefail

CONF_DIR="/etc/securizar/deception"
INVENTORY="/etc/securizar/honeytokens.conf"
LOG_DIR="/var/log/securizar/honeypot"
ALERT_SCRIPT="/usr/local/bin/alertar-deception.sh"

mkdir -p "$CONF_DIR" "$LOG_DIR"

usage() {
    echo "Uso: $0 {deploy|list|verify|remove|rotate}"
    echo ""
    echo "Comandos:"
    echo "  deploy    - Desplegar todos los honeytokens"
    echo "  list      - Listar honeytokens desplegados"
    echo "  verify    - Verificar que los honeytokens estan intactos"
    echo "  remove    - Eliminar todos los honeytokens"
    echo "  rotate    - Rotar (regenerar) todos los honeytokens"
    exit 1
}

generate_token_id() {
    local prefix="${1:-TKN}"
    echo "${prefix}-$(date +%Y%m%d)-$(openssl rand -hex 4 2>/dev/null || head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
}

# Desplegar fake AWS credentials
deploy_aws_tokens() {
    echo "[+] Desplegando fake AWS credentials..."

    # En /root
    local token_id
    token_id="$(generate_token_id AWS)"
    local fake_key_data
    local key_id="AKIA$(openssl rand -hex 8 2>/dev/null | tr '[:lower:]' '[:upper:]')"
    local secret_key
    secret_key="$(openssl rand -base64 30 2>/dev/null | tr -dc 'A-Za-z0-9+/' | head -c 40)"

    mkdir -p /root/.aws
    cat > /root/.aws/credentials.bak << EOFAWS
# AWS credentials backup - DO NOT DELETE
# Last rotated: $(date '+%Y-%m-%d')
[default]
aws_access_key_id = ${key_id}
aws_secret_access_key = ${secret_key}
# CANARY: ${token_id}
[production]
aws_access_key_id = AKIA$(openssl rand -hex 8 2>/dev/null | tr '[:lower:]' '[:upper:]')
aws_secret_access_key = $(openssl rand -base64 30 2>/dev/null | tr -dc 'A-Za-z0-9+/' | head -c 40)
EOFAWS
    chmod 600 /root/.aws/credentials.bak
    echo "HONEYTOKEN|${token_id}|AWS_CREDS|/root/.aws/credentials.bak|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$INVENTORY"

    # En cada home de usuario normal
    while IFS=: read -r username _ uid _ _ homedir _; do
        [[ "$uid" -ge 1000 && "$uid" -lt 65534 ]] || continue
        [[ -d "$homedir" ]] || continue
        token_id="$(generate_token_id AWS)"
        local u_key_id="AKIA$(openssl rand -hex 8 2>/dev/null | tr '[:lower:]' '[:upper:]')"
        local u_secret
        u_secret="$(openssl rand -base64 30 2>/dev/null | tr -dc 'A-Za-z0-9+/' | head -c 40)"

        mkdir -p "${homedir}/.aws"
        cat > "${homedir}/.aws/credentials.bak" << EOFUSERAWS
# AWS credentials backup
[default]
aws_access_key_id = ${u_key_id}
aws_secret_access_key = ${u_secret}
# CANARY: ${token_id}
EOFUSERAWS
        chmod 600 "${homedir}/.aws/credentials.bak"
        chown "${username}:${username}" "${homedir}/.aws" "${homedir}/.aws/credentials.bak" 2>/dev/null || true
        echo "HONEYTOKEN|${token_id}|AWS_CREDS|${homedir}/.aws/credentials.bak|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$INVENTORY"
    done < /etc/passwd
}

# Desplegar fake SSH keys
deploy_ssh_tokens() {
    echo "[+] Desplegando fake SSH keys..."

    local token_id
    token_id="$(generate_token_id SSH)"

    # Fake SSH key en /root
    local keyfile="/root/.ssh/id_rsa.bak"
    mkdir -p /root/.ssh
    cat > "$keyfile" << EOFSSHKEY
-----BEGIN OPENSSH PRIVATE KEY-----
$(openssl rand -base64 48 2>/dev/null)
$(openssl rand -base64 48 2>/dev/null)
$(openssl rand -base64 48 2>/dev/null)
$(openssl rand -base64 48 2>/dev/null)
$(openssl rand -base64 48 2>/dev/null)
$(openssl rand -base64 48 2>/dev/null)
# CANARY: ${token_id}
-----END OPENSSH PRIVATE KEY-----
EOFSSHKEY
    chmod 600 "$keyfile"
    echo "HONEYTOKEN|${token_id}|SSH_KEY|${keyfile}|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$INVENTORY"

    # Fake SSH key en /tmp (comun en ataques)
    token_id="$(generate_token_id SSH)"
    cat > /tmp/.id_rsa_backup << EOFSSHTMP
-----BEGIN RSA PRIVATE KEY-----
$(openssl rand -base64 48 2>/dev/null)
$(openssl rand -base64 48 2>/dev/null)
$(openssl rand -base64 48 2>/dev/null)
$(openssl rand -base64 48 2>/dev/null)
# CANARY: ${token_id}
-----END RSA PRIVATE KEY-----
EOFSSHTMP
    chmod 600 /tmp/.id_rsa_backup
    echo "HONEYTOKEN|${token_id}|SSH_KEY|/tmp/.id_rsa_backup|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$INVENTORY"
}

# Desplegar fake database credentials
deploy_db_tokens() {
    echo "[+] Desplegando fake database credentials..."

    local token_id
    token_id="$(generate_token_id DB)"

    cat > /etc/securizar/decoy-db.conf << EOFDBCONF
# Database connection configuration - PRODUCTION
# Last updated: $(date '+%Y-%m-%d')
# WARNING: Contains production credentials

[mysql-primary]
host = db-primary.internal
port = 3306
username = root
password = $(openssl rand -base64 18 2>/dev/null | tr -dc 'A-Za-z0-9' | head -c 24)
database = production_main

[postgresql-analytics]
host = analytics-db.internal
port = 5432
username = analytics_admin
password = $(openssl rand -base64 18 2>/dev/null | tr -dc 'A-Za-z0-9' | head -c 24)
database = analytics_prod

[redis-cache]
host = redis-cluster.internal
port = 6379
auth = $(openssl rand -base64 18 2>/dev/null | tr -dc 'A-Za-z0-9' | head -c 32)

# CANARY: ${token_id}
EOFDBCONF
    chmod 600 /etc/securizar/decoy-db.conf
    echo "HONEYTOKEN|${token_id}|DB_CREDS|/etc/securizar/decoy-db.conf|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$INVENTORY"
}

# Desplegar fake .env files
deploy_env_tokens() {
    echo "[+] Desplegando fake .env files..."

    local token_id
    token_id="$(generate_token_id ENV)"

    # En /var/www si existe
    if [[ -d /var/www ]]; then
        cat > /var/www/.env.bak << EOFENVWWW
# Production environment - DO NOT DELETE
APP_ENV=production
APP_KEY=base64:$(openssl rand -base64 32 2>/dev/null)
DB_HOST=db-primary.internal
DB_PORT=3306
DB_DATABASE=production_app
DB_USERNAME=app_prod
DB_PASSWORD=$(openssl rand -base64 18 2>/dev/null | tr -dc 'A-Za-z0-9' | head -c 24)
REDIS_HOST=redis-cluster.internal
REDIS_PASSWORD=$(openssl rand -base64 18 2>/dev/null | tr -dc 'A-Za-z0-9' | head -c 32)
MAIL_PASSWORD=$(openssl rand -base64 12 2>/dev/null | tr -dc 'A-Za-z0-9' | head -c 16)
AWS_ACCESS_KEY_ID=AKIA$(openssl rand -hex 8 2>/dev/null | tr '[:lower:]' '[:upper:]')
AWS_SECRET_ACCESS_KEY=$(openssl rand -base64 30 2>/dev/null | tr -dc 'A-Za-z0-9+/' | head -c 40)
STRIPE_SECRET_KEY=sk_live_$(openssl rand -hex 24 2>/dev/null)
# CANARY: ${token_id}
EOFENVWWW
        chmod 600 /var/www/.env.bak
        echo "HONEYTOKEN|${token_id}|ENV_FILE|/var/www/.env.bak|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$INVENTORY"
    fi

    # En /opt
    token_id="$(generate_token_id ENV)"
    mkdir -p /opt/app-config
    cat > /opt/app-config/.env.production << EOFENVOPT
# Production config backup
DATABASE_URL=postgresql://admin:$(openssl rand -base64 18 2>/dev/null | tr -dc 'A-Za-z0-9' | head -c 20)@db.internal:5432/prod
SECRET_KEY=$(openssl rand -hex 32 2>/dev/null)
API_TOKEN=$(openssl rand -hex 24 2>/dev/null)
# CANARY: ${token_id}
EOFENVOPT
    chmod 600 /opt/app-config/.env.production
    echo "HONEYTOKEN|${token_id}|ENV_FILE|/opt/app-config/.env.production|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$INVENTORY"
}

# Listar honeytokens
list_tokens() {
    echo ""
    echo "═══════════════════════════════════════════"
    echo "  HONEY TOKENS DESPLEGADOS"
    echo "═══════════════════════════════════════════"
    echo ""

    if [[ ! -f "$INVENTORY" ]]; then
        echo "  No hay honeytokens desplegados"
        return 0
    fi

    local count=0
    while IFS='|' read -r type token_id kind path timestamp; do
        [[ "$type" == "HONEYTOKEN" ]] || continue
        local status="OK"
        if [[ ! -f "$path" ]]; then
            status="FALTA"
        fi
        printf "  %-12s %-20s %-40s [%s]\n" "$kind" "$token_id" "$path" "$status"
        ((count++)) || true
    done < "$INVENTORY"

    echo ""
    echo "  Total: ${count} honeytokens"
    echo ""
}

# Verificar integridad
verify_tokens() {
    echo "[+] Verificando integridad de honeytokens..."
    local ok=0
    local missing=0

    if [[ ! -f "$INVENTORY" ]]; then
        echo "[!] No hay inventario de honeytokens"
        return 1
    fi

    while IFS='|' read -r type token_id kind path timestamp; do
        [[ "$type" == "HONEYTOKEN" ]] || continue
        if [[ -f "$path" ]]; then
            echo "  [OK] ${kind}: ${path}"
            ((ok++)) || true
        else
            echo "  [!!] ${kind}: ${path} - ARCHIVO FALTA (posible acceso malicioso)"
            ((missing++)) || true
            logger -t "securizar-honeytoken" -p auth.crit \
                "HONEYTOKEN MISSING: ${token_id} type=${kind} path=${path}"
        fi
    done < "$INVENTORY"

    echo ""
    echo "  Intactos: ${ok} | Faltantes: ${missing}"
    [[ $missing -eq 0 ]]
}

# Eliminar todos
remove_tokens() {
    echo "[+] Eliminando honeytokens..."
    if [[ ! -f "$INVENTORY" ]]; then
        echo "[!] No hay inventario"
        return 0
    fi

    while IFS='|' read -r type token_id kind path timestamp; do
        [[ "$type" == "HONEYTOKEN" ]] || continue
        if [[ -f "$path" ]]; then
            rm -f "$path"
            echo "  Eliminado: ${path}"
        fi
    done < "$INVENTORY"

    rm -f "$INVENTORY"
    echo "[+] Todos los honeytokens eliminados"
}

# Rotar tokens
rotate_tokens() {
    echo "[+] Rotando honeytokens..."
    remove_tokens
    deploy_aws_tokens
    deploy_ssh_tokens
    deploy_db_tokens
    deploy_env_tokens
    echo "[+] Honeytokens rotados exitosamente"
}

# Main
case "${1:-}" in
    deploy)
        : > "$INVENTORY"  # Reset inventory
        deploy_aws_tokens
        deploy_ssh_tokens
        deploy_db_tokens
        deploy_env_tokens
        echo ""
        echo "[+] Honeytokens desplegados exitosamente"
        list_tokens
        ;;
    list)    list_tokens ;;
    verify)  verify_tokens ;;
    remove)  remove_tokens ;;
    rotate)  rotate_tokens ;;
    *)       usage ;;
esac
EOFHONEYTOKENS
    chmod +x /usr/local/bin/generar-honeytokens.sh
    log_change "Creado" "/usr/local/bin/generar-honeytokens.sh"

    # Desplegar honeytokens iniciales
    if ask "¿Desplegar honeytokens ahora?"; then
        # Inicializar inventario
        cat > "$HONEYTOKENS_CONF" << EOFINVENTORY
# ============================================================
# Inventario de Honey Tokens - securizar Modulo 55
# Formato: HONEYTOKEN|TOKEN_ID|TIPO|RUTA|FECHA
# NO EDITAR MANUALMENTE
# ============================================================
EOFINVENTORY
        chmod 600 "$HONEYTOKENS_CONF"

        # Desplegar fake AWS credentials en /root
        aws_token_id="$(generate_token_id AWS)"
        aws_key_id="AKIA$(openssl rand -hex 8 2>/dev/null | tr '[:lower:]' '[:upper:]')"
        aws_secret="$(openssl rand -base64 30 2>/dev/null | tr -dc 'A-Za-z0-9+/' | head -c 40)"

        mkdir -p /root/.aws
        cat > /root/.aws/credentials.bak << EOFAWSCREDS
# AWS credentials backup - DO NOT DELETE
# Last rotated: $(date '+%Y-%m-%d')
[default]
aws_access_key_id = ${aws_key_id}
aws_secret_access_key = ${aws_secret}
[production]
aws_access_key_id = AKIA$(openssl rand -hex 8 2>/dev/null | tr '[:lower:]' '[:upper:]')
aws_secret_access_key = $(openssl rand -base64 30 2>/dev/null | tr -dc 'A-Za-z0-9+/' | head -c 40)
# CANARY: ${aws_token_id}
EOFAWSCREDS
        chmod 600 /root/.aws/credentials.bak
        echo "HONEYTOKEN|${aws_token_id}|AWS_CREDS|/root/.aws/credentials.bak|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$HONEYTOKENS_CONF"
        log_change "Desplegado" "Honeytoken AWS: /root/.aws/credentials.bak (${aws_token_id})"

        # Desplegar en homes de usuarios normales
        while IFS=: read -r username _ uid _ _ homedir _; do
            [[ "$uid" -ge 1000 && "$uid" -lt 65534 ]] || continue
            [[ -d "$homedir" ]] || continue

            u_token_id="$(generate_token_id AWS)"
            mkdir -p "${homedir}/.aws"
            cat > "${homedir}/.aws/credentials.bak" << EOFUAWS
[default]
aws_access_key_id = AKIA$(openssl rand -hex 8 2>/dev/null | tr '[:lower:]' '[:upper:]')
aws_secret_access_key = $(openssl rand -base64 30 2>/dev/null | tr -dc 'A-Za-z0-9+/' | head -c 40)
# CANARY: ${u_token_id}
EOFUAWS
            chmod 600 "${homedir}/.aws/credentials.bak"
            chown "${username}:${username}" "${homedir}/.aws" "${homedir}/.aws/credentials.bak" 2>/dev/null || true
            echo "HONEYTOKEN|${u_token_id}|AWS_CREDS|${homedir}/.aws/credentials.bak|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$HONEYTOKENS_CONF"
            log_change "Desplegado" "Honeytoken AWS: ${homedir}/.aws/credentials.bak"
        done < /etc/passwd

        # Desplegar fake SSH key en /root
        ssh_token_id="$(generate_token_id SSH)"
        generate_fake_ssh_key "/root/.ssh/id_rsa.bak" "$ssh_token_id"
        echo "HONEYTOKEN|${ssh_token_id}|SSH_KEY|/root/.ssh/id_rsa.bak|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$HONEYTOKENS_CONF"
        log_change "Desplegado" "Honeytoken SSH: /root/.ssh/id_rsa.bak (${ssh_token_id})"

        # Fake SSH key en /tmp
        ssh_token_id="$(generate_token_id SSH)"
        generate_fake_ssh_key "/tmp/.id_rsa_backup" "$ssh_token_id"
        echo "HONEYTOKEN|${ssh_token_id}|SSH_KEY|/tmp/.id_rsa_backup|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$HONEYTOKENS_CONF"
        log_change "Desplegado" "Honeytoken SSH: /tmp/.id_rsa_backup"

        # Desplegar fake DB credentials
        db_token_id="$(generate_token_id DB)"
        cat > /etc/securizar/decoy-db.conf << EOFDBCREDS
# Database connection configuration - PRODUCTION
# Last updated: $(date '+%Y-%m-%d')
[mysql-primary]
host = db-primary.internal
port = 3306
username = root
password = $(generate_fake_password)
database = production_main

[postgresql-analytics]
host = analytics-db.internal
port = 5432
username = analytics_admin
password = $(generate_fake_password)
database = analytics_prod

[redis-cache]
host = redis-cluster.internal
port = 6379
auth = $(generate_fake_password)

# CANARY: ${db_token_id}
EOFDBCREDS
        chmod 600 /etc/securizar/decoy-db.conf
        echo "HONEYTOKEN|${db_token_id}|DB_CREDS|/etc/securizar/decoy-db.conf|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$HONEYTOKENS_CONF"
        log_change "Desplegado" "Honeytoken DB: /etc/securizar/decoy-db.conf (${db_token_id})"

        # Desplegar fake .env
        env_token_id="$(generate_token_id ENV)"
        if [[ -d /var/www ]]; then
            cat > /var/www/.env.bak << EOFENVBAK
APP_ENV=production
APP_KEY=base64:$(openssl rand -base64 32 2>/dev/null)
DB_HOST=db-primary.internal
DB_PASSWORD=$(generate_fake_password)
REDIS_PASSWORD=$(generate_fake_password)
AWS_ACCESS_KEY_ID=AKIA$(openssl rand -hex 8 2>/dev/null | tr '[:lower:]' '[:upper:]')
AWS_SECRET_ACCESS_KEY=$(openssl rand -base64 30 2>/dev/null | tr -dc 'A-Za-z0-9+/' | head -c 40)
STRIPE_SECRET_KEY=sk_live_$(openssl rand -hex 24 2>/dev/null)
# CANARY: ${env_token_id}
EOFENVBAK
            chmod 600 /var/www/.env.bak
            echo "HONEYTOKEN|${env_token_id}|ENV_FILE|/var/www/.env.bak|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$HONEYTOKENS_CONF"
            log_change "Desplegado" "Honeytoken ENV: /var/www/.env.bak"
        fi

        env_token_id="$(generate_token_id ENV)"
        mkdir -p /opt/app-config
        cat > /opt/app-config/.env.production << EOFENVPROD
DATABASE_URL=postgresql://admin:$(generate_fake_password)@db.internal:5432/prod
SECRET_KEY=$(openssl rand -hex 32 2>/dev/null)
API_TOKEN=$(openssl rand -hex 24 2>/dev/null)
# CANARY: ${env_token_id}
EOFENVPROD
        chmod 600 /opt/app-config/.env.production
        echo "HONEYTOKEN|${env_token_id}|ENV_FILE|/opt/app-config/.env.production|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$HONEYTOKENS_CONF"
        log_change "Desplegado" "Honeytoken ENV: /opt/app-config/.env.production"

        log_info "Honeytokens desplegados exitosamente"
    else
        log_skip "Despliegue inicial de honeytokens"
    fi

    # Configurar monitorizacion via auditd
    if ask "¿Configurar monitorizacion de honeytokens via auditd?"; then
        if command -v auditctl &>/dev/null; then
            log_info "Configurando reglas de auditd para honeytokens..."

            AUDIT_RULES_FILE="/etc/audit/rules.d/99-honeytokens.rules"
            if [[ -f "$AUDIT_RULES_FILE" ]]; then
                cp -a "$AUDIT_RULES_FILE" "$BACKUP_DIR/"
            fi

            # Generar reglas solo para paths que existen
            {
                echo "## Securizar Modulo 55 - Monitorizacion de Honeytokens"
                echo "## Auto-generated: solo paths existentes"
                echo ""
                for _ht_path in /root/.aws/credentials.bak /root/.ssh/id_rsa.bak /tmp/.id_rsa_backup /etc/securizar/decoy-db.conf /opt/app-config/.env.production /var/www/.env.bak; do
                    [[ -f "$_ht_path" ]] && echo "-w $_ht_path -p rwa -k honeytoken-$(basename "$_ht_path" | tr '.' '-')"
                done
                # Reglas por usuario
                while IFS=: read -r username _ uid _ _ homedir _; do
                    [[ "$uid" -ge 1000 && "$uid" -lt 65534 ]] || continue
                    [[ -d "$homedir" ]] || continue
                    [[ -f "${homedir}/.aws/credentials.bak" ]] && echo "-w ${homedir}/.aws/credentials.bak -p rwa -k honeytoken-aws"
                done < /etc/passwd
            } > "$AUDIT_RULES_FILE"

            chmod 640 "$AUDIT_RULES_FILE"

            # Recargar reglas
            augenrules --load 2>/dev/null || auditctl -R "$AUDIT_RULES_FILE" 2>/dev/null || true
            log_change "Configurado" "Reglas auditd para honeytokens: $AUDIT_RULES_FILE"
        else
            log_warn "auditd no disponible - honeytokens no tendran monitorizacion automatica"
            log_info "Instala auditd y ejecuta este modulo de nuevo"
        fi
    else
        log_skip "Monitorizacion auditd de honeytokens"
    fi

    # Registrar en honey-registry centralizado (para honey-monitor.sh)
    if [[ -f "$HONEYTOKENS_CONF" ]]; then
        while IFS=: read -r _ru _ _ruid _ _ _rhome _; do
            [[ "$_ruid" -ge 1000 && "$_ruid" -lt 65534 ]] || continue
            [[ -d "$_rhome" ]] || continue
            _CENTRAL_REG="$_rhome/.config/securizar/honey-registry.conf"
            mkdir -p "$(dirname "$_CENTRAL_REG")"
            while IFS='|' read -r _ht_tag _tid _ttype _tpath _tts; do
                [[ "$_ht_tag" == "HONEYTOKEN" ]] || continue
                [[ -f "$_tpath" ]] || continue
                # No duplicar si ya existe en registry
                if [[ -f "$_CENTRAL_REG" ]] && grep -q "$_tpath" "$_CENTRAL_REG" 2>/dev/null; then
                    continue
                fi
                echo "${_tid}|${_tpath}|${_ttype}|$(date +%Y-%m-%d)|Mod55 honeytoken" >> "$_CENTRAL_REG"
            done < "$HONEYTOKENS_CONF"
            chown "$_ru:$(id -gn "$_ru" 2>/dev/null || echo "$_ru")" "$_CENTRAL_REG" 2>/dev/null || true
        done < /etc/passwd
        log_info "Tokens registrados en honey-registry centralizado"
    fi

    log_info "Honey tokens configurados"
    log_info "Gestionar: generar-honeytokens.sh {deploy|list|verify|rotate}"
else
    log_skip "Honey tokens (credenciales canario)"
fi
fi  # S2

if [[ "$DECEPTION_SECTION" == "all" || "$DECEPTION_SECTION" == "S3" ]]; then
# ============================================================
# S3: HONEY FILES (DOCUMENTOS SENUELO)
# ============================================================
log_section "S3: HONEY FILES (DOCUMENTOS SENUELO)"

log_info "Honey files - documentos senuelo monitorizados:"
log_info "  - /root/passwords.xlsx.txt (archivo de contrasenas falso)"
log_info "  - /root/backup-keys.txt (claves de backup falsas)"
log_info "  - /var/www/html/.htpasswd.bak (credenciales web falsas)"
log_info "  - /tmp/.ssh_config (config SSH falso)"
log_info "  - Documentos financieros falsos en homes de usuario"
log_info ""

if check_executable /usr/local/bin/desplegar-honeyfiles.sh; then
    log_already "Honey files (desplegar-honeyfiles.sh existe)"
elif ask "¿Desplegar honey files (documentos senuelo)?"; then

    HONEYFILES_INVENTORY="/etc/securizar/honeyfiles.conf"
    cat > "$HONEYFILES_INVENTORY" << EOFHFINV
# ============================================================
# Inventario de Honey Files - securizar Modulo 55
# Formato: HONEYFILE|TOKEN_ID|TIPO|RUTA|FECHA
# NO EDITAR MANUALMENTE
# ============================================================
EOFHFINV
    chmod 600 "$HONEYFILES_INVENTORY"

    # Crear script de gestion
    log_info "Creando /usr/local/bin/desplegar-honeyfiles.sh..."
    cat > /usr/local/bin/desplegar-honeyfiles.sh << 'EOFHONEYFILES'
#!/bin/bash
# ============================================================
# desplegar-honeyfiles.sh - Gestion de honey files
# Parte de securizar Modulo 55 - Tecnologia de Engano
# ============================================================
set -euo pipefail

INVENTORY="/etc/securizar/honeyfiles.conf"
LOG_DIR="/var/log/securizar/honeypot"
ALERT_SCRIPT="/usr/local/bin/alertar-deception.sh"

mkdir -p "$LOG_DIR"

usage() {
    echo "Uso: $0 {deploy|list|verify|remove}"
    echo ""
    echo "Comandos:"
    echo "  deploy  - Desplegar todos los honey files"
    echo "  list    - Listar honey files desplegados"
    echo "  verify  - Verificar integridad de honey files"
    echo "  remove  - Eliminar todos los honey files"
    exit 1
}

generate_token_id() {
    local prefix="${1:-HF}"
    echo "${prefix}-$(date +%Y%m%d)-$(openssl rand -hex 4 2>/dev/null || head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
}

deploy_all() {
    echo "[+] Desplegando honey files..."

    # /root/passwords.xlsx.txt
    local token_id
    token_id="$(generate_token_id HF)"
    cat > /root/passwords.xlsx.txt << 'EOFPWD'
Company Password Database - CONFIDENTIAL
=========================================
Last updated: 2025-01-15

System          | Username      | Password
----------------|---------------|---------------------------
VPN Gateway     | admin         | Pr0d_VPN!2025_Secure
AWS Console     | ops-admin     | CloudMgr#4521!prod
Database Primary| dba_root      | DB@dmin_Pr0d#2025
Jenkins CI      | ci-admin      | J3nk1ns!BuildS3rv3r
Grafana         | admin         | M0n1t0r#Gr4f4n4!25
GitLab          | root          | G1tL4b_4dm1n!Pr0d
Kubernetes      | cluster-admin | K8s_Cl5tr#Pr0d!2025
EOFPWD
    chmod 600 /root/passwords.xlsx.txt
    echo "HONEYFILE|${token_id}|PASSWORDS|/root/passwords.xlsx.txt|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$INVENTORY"
    echo "  Desplegado: /root/passwords.xlsx.txt"

    # /root/backup-keys.txt
    token_id="$(generate_token_id HF)"
    cat > /root/backup-keys.txt << EOFBKPKEYS
# Backup Encryption Keys - CRITICAL
# Generated: $(date '+%Y-%m-%d')

Master Backup Key: $(openssl rand -hex 32 2>/dev/null)
Recovery Key 1:    $(openssl rand -hex 32 2>/dev/null)
Recovery Key 2:    $(openssl rand -hex 32 2>/dev/null)

LUKS Passphrase: $(openssl rand -base64 24 2>/dev/null)
Vault Unseal Key 1: $(openssl rand -base64 32 2>/dev/null)
Vault Unseal Key 2: $(openssl rand -base64 32 2>/dev/null)
Vault Unseal Key 3: $(openssl rand -base64 32 2>/dev/null)
Root Token: hvs.$(openssl rand -hex 24 2>/dev/null)

# CANARY: ${token_id}
EOFBKPKEYS
    chmod 600 /root/backup-keys.txt
    echo "HONEYFILE|${token_id}|BACKUP_KEYS|/root/backup-keys.txt|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$INVENTORY"
    echo "  Desplegado: /root/backup-keys.txt"

    # /var/www/html/.htpasswd.bak
    if [[ -d /var/www/html ]] || [[ -d /var/www ]]; then
        token_id="$(generate_token_id HF)"
        mkdir -p /var/www/html
        cat > /var/www/html/.htpasswd.bak << EOFHTPASSWD
# Apache htpasswd backup - $(date '+%Y-%m-%d')
admin:\$apr1\$$(openssl rand -hex 4 2>/dev/null)\$$(openssl rand -base64 16 2>/dev/null | tr -dc 'A-Za-z0-9./' | head -c 22)
webmaster:\$apr1\$$(openssl rand -hex 4 2>/dev/null)\$$(openssl rand -base64 16 2>/dev/null | tr -dc 'A-Za-z0-9./' | head -c 22)
deploy:\$apr1\$$(openssl rand -hex 4 2>/dev/null)\$$(openssl rand -base64 16 2>/dev/null | tr -dc 'A-Za-z0-9./' | head -c 22)
# CANARY: ${token_id}
EOFHTPASSWD
        chmod 600 /var/www/html/.htpasswd.bak
        echo "HONEYFILE|${token_id}|HTPASSWD|/var/www/html/.htpasswd.bak|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$INVENTORY"
        echo "  Desplegado: /var/www/html/.htpasswd.bak"
    fi

    # /tmp/.ssh_config
    token_id="$(generate_token_id HF)"
    cat > /tmp/.ssh_config << EOFSSHCONF
# SSH config backup
# Last modified: $(date '+%Y-%m-%d')

Host production-bastion
    HostName 10.0.1.50
    User admin
    IdentityFile ~/.ssh/prod_key
    Port 22

Host database-primary
    HostName 10.0.2.10
    User dba
    ProxyJump production-bastion
    IdentityFile ~/.ssh/db_key

Host kubernetes-master
    HostName 10.0.3.5
    User cluster-admin
    ProxyJump production-bastion

Host backup-server
    HostName 10.0.4.100
    User backup-admin
    IdentityFile ~/.ssh/backup_key

# CANARY: ${token_id}
EOFSSHCONF
    chmod 600 /tmp/.ssh_config
    echo "HONEYFILE|${token_id}|SSH_CONFIG|/tmp/.ssh_config|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$INVENTORY"
    echo "  Desplegado: /tmp/.ssh_config"

    # bank-accounts.csv en homes de usuario
    while IFS=: read -r username _ uid _ _ homedir _; do
        [[ "$uid" -ge 1000 && "$uid" -lt 65534 ]] || continue
        [[ -d "$homedir" ]] || continue

        token_id="$(generate_token_id HF)"
        mkdir -p "${homedir}/Documents" 2>/dev/null || continue
        cat > "${homedir}/Documents/bank-accounts.csv" << EOFBANK
"Account Name","Bank","Account Number","Routing Number","Balance","Notes"
"Corporate Operations","First National","$(shuf -i 100000000-999999999 -n 1 2>/dev/null || echo 123456789)","$(shuf -i 100000000-999999999 -n 1 2>/dev/null || echo 987654321)","\$125,430.00","Primary operations account"
"Payroll","Chase","$(shuf -i 100000000-999999999 -n 1 2>/dev/null || echo 234567890)","$(shuf -i 100000000-999999999 -n 1 2>/dev/null || echo 876543210)","\$89,200.00","Bi-weekly payroll"
"Emergency Fund","Wells Fargo","$(shuf -i 100000000-999999999 -n 1 2>/dev/null || echo 345678901)","$(shuf -i 100000000-999999999 -n 1 2>/dev/null || echo 765432109)","\$250,000.00","Emergency reserve"
"Investment","Vanguard","$(shuf -i 100000000-999999999 -n 1 2>/dev/null || echo 456789012)","N/A","\$1,200,000.00","Long term investments"
EOFBANK
        chmod 600 "${homedir}/Documents/bank-accounts.csv"
        chown "${username}:${username}" "${homedir}/Documents" "${homedir}/Documents/bank-accounts.csv" 2>/dev/null || true
        echo "HONEYFILE|${token_id}|FINANCIAL|${homedir}/Documents/bank-accounts.csv|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$INVENTORY"
        echo "  Desplegado: ${homedir}/Documents/bank-accounts.csv"
    done < /etc/passwd

    echo "[+] Honey files desplegados exitosamente"
}

list_files() {
    echo ""
    echo "═══════════════════════════════════════════"
    echo "  HONEY FILES DESPLEGADOS"
    echo "═══════════════════════════════════════════"
    echo ""

    if [[ ! -f "$INVENTORY" ]]; then
        echo "  No hay honey files desplegados"
        return 0
    fi

    local count=0
    while IFS='|' read -r type token_id kind path timestamp; do
        [[ "$type" == "HONEYFILE" ]] || continue
        local status="OK"
        if [[ ! -f "$path" ]]; then
            status="FALTA"
        fi
        printf "  %-14s %-20s %-45s [%s]\n" "$kind" "$token_id" "$path" "$status"
        ((count++)) || true
    done < "$INVENTORY"

    echo ""
    echo "  Total: ${count} honey files"
    echo ""
}

verify_files() {
    echo "[+] Verificando honey files..."
    local ok=0
    local missing=0

    if [[ ! -f "$INVENTORY" ]]; then
        echo "[!] No hay inventario de honey files"
        return 1
    fi

    while IFS='|' read -r type token_id kind path timestamp; do
        [[ "$type" == "HONEYFILE" ]] || continue
        if [[ -f "$path" ]]; then
            echo "  [OK]     ${kind}: ${path}"
            ((ok++)) || true
        else
            echo "  [FALTA]  ${kind}: ${path} - POSIBLE ACCESO MALICIOSO"
            ((missing++)) || true
            logger -t "securizar-honeyfile" -p auth.crit \
                "HONEYFILE MISSING: ${token_id} type=${kind} path=${path}"
        fi
    done < "$INVENTORY"

    echo ""
    echo "  Intactos: ${ok} | Faltantes: ${missing}"
}

remove_files() {
    echo "[+] Eliminando honey files..."
    if [[ ! -f "$INVENTORY" ]]; then
        echo "[!] No hay inventario"
        return 0
    fi

    while IFS='|' read -r type token_id kind path timestamp; do
        [[ "$type" == "HONEYFILE" ]] || continue
        if [[ -f "$path" ]]; then
            rm -f "$path"
            echo "  Eliminado: ${path}"
        fi
    done < "$INVENTORY"

    rm -f "$INVENTORY"
    echo "[+] Todos los honey files eliminados"
}

case "${1:-}" in
    deploy)  deploy_all ;;
    list)    list_files ;;
    verify)  verify_files ;;
    remove)  remove_files ;;
    *)       usage ;;
esac
EOFHONEYFILES
    chmod +x /usr/local/bin/desplegar-honeyfiles.sh
    log_change "Creado" "/usr/local/bin/desplegar-honeyfiles.sh"

    # Desplegar honey files
    if ask "¿Desplegar honey files ahora?"; then

        # /root/passwords.xlsx.txt
        hf_token_id="$(generate_token_id HF)"
        cat > /root/passwords.xlsx.txt << 'EOFPWDFILE'
Company Password Database - CONFIDENTIAL
=========================================
Last updated: 2025-01-15

System          | Username      | Password
----------------|---------------|---------------------------
VPN Gateway     | admin         | Pr0d_VPN!2025_Secure
AWS Console     | ops-admin     | CloudMgr#4521!prod
Database Primary| dba_root      | DB@dmin_Pr0d#2025
Jenkins CI      | ci-admin      | J3nk1ns!BuildS3rv3r
Grafana         | admin         | M0n1t0r#Gr4f4n4!25
EOFPWDFILE
        chmod 600 /root/passwords.xlsx.txt
        echo "HONEYFILE|${hf_token_id}|PASSWORDS|/root/passwords.xlsx.txt|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$HONEYFILES_INVENTORY"
        log_change "Desplegado" "Honey file: /root/passwords.xlsx.txt"

        # /root/backup-keys.txt
        hf_token_id="$(generate_token_id HF)"
        cat > /root/backup-keys.txt << EOFBKKEYS
# Backup Encryption Keys - CRITICAL
Master Backup Key: $(openssl rand -hex 32 2>/dev/null)
Recovery Key 1:    $(openssl rand -hex 32 2>/dev/null)
LUKS Passphrase:   $(openssl rand -base64 24 2>/dev/null)
Vault Unseal Key:  $(openssl rand -base64 32 2>/dev/null)
Root Token: hvs.$(openssl rand -hex 24 2>/dev/null)
# CANARY: ${hf_token_id}
EOFBKKEYS
        chmod 600 /root/backup-keys.txt
        echo "HONEYFILE|${hf_token_id}|BACKUP_KEYS|/root/backup-keys.txt|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$HONEYFILES_INVENTORY"
        log_change "Desplegado" "Honey file: /root/backup-keys.txt"

        # /var/www/html/.htpasswd.bak
        if [[ -d /var/www ]] || [[ -d /var/www/html ]]; then
            hf_token_id="$(generate_token_id HF)"
            mkdir -p /var/www/html
            cat > /var/www/html/.htpasswd.bak << EOFHTPWD
admin:\$apr1\$xR9z\$fakehash1234567890abcdef
webmaster:\$apr1\$yQ8x\$fakehash0987654321fedcba
# CANARY: ${hf_token_id}
EOFHTPWD
            chmod 600 /var/www/html/.htpasswd.bak
            echo "HONEYFILE|${hf_token_id}|HTPASSWD|/var/www/html/.htpasswd.bak|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$HONEYFILES_INVENTORY"
            log_change "Desplegado" "Honey file: /var/www/html/.htpasswd.bak"
        fi

        # /tmp/.ssh_config
        hf_token_id="$(generate_token_id HF)"
        cat > /tmp/.ssh_config << EOFSSHCFG
Host production-bastion
    HostName 10.0.1.50
    User admin
    IdentityFile ~/.ssh/prod_key
Host database-primary
    HostName 10.0.2.10
    User dba
    ProxyJump production-bastion
# CANARY: ${hf_token_id}
EOFSSHCFG
        chmod 600 /tmp/.ssh_config
        echo "HONEYFILE|${hf_token_id}|SSH_CONFIG|/tmp/.ssh_config|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$HONEYFILES_INVENTORY"
        log_change "Desplegado" "Honey file: /tmp/.ssh_config"

        # bank-accounts.csv en homes
        while IFS=: read -r username _ uid _ _ homedir _; do
            [[ "$uid" -ge 1000 && "$uid" -lt 65534 ]] || continue
            [[ -d "$homedir" ]] || continue
            hf_token_id="$(generate_token_id HF)"
            mkdir -p "${homedir}/Documents" 2>/dev/null || continue
            cat > "${homedir}/Documents/bank-accounts.csv" << 'EOFBANKACC'
"Account Name","Bank","Account Number","Balance"
"Corporate Ops","First National","987654321","$125,430.00"
"Payroll","Chase","123456789","$89,200.00"
"Emergency","Wells Fargo","567890123","$250,000.00"
EOFBANKACC
            chmod 600 "${homedir}/Documents/bank-accounts.csv"
            chown "${username}:${username}" "${homedir}/Documents" "${homedir}/Documents/bank-accounts.csv" 2>/dev/null || true
            echo "HONEYFILE|${hf_token_id}|FINANCIAL|${homedir}/Documents/bank-accounts.csv|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$HONEYFILES_INVENTORY"
            log_change "Desplegado" "Honey file: ${homedir}/Documents/bank-accounts.csv"
        done < /etc/passwd

        log_info "Honey files desplegados exitosamente"
    else
        log_skip "Despliegue inicial de honey files"
    fi

    # Configurar monitorizacion con auditd
    if ask "¿Configurar monitorizacion de honey files via auditd?"; then
        if command -v auditctl &>/dev/null; then
            log_info "Configurando reglas de auditd para honey files..."

            AUDIT_HF_RULES="/etc/audit/rules.d/99-honeyfiles.rules"
            if [[ -f "$AUDIT_HF_RULES" ]]; then
                cp -a "$AUDIT_HF_RULES" "$BACKUP_DIR/"
            fi

            # Generar reglas solo para paths que existen
            {
                echo "## Securizar Modulo 55 - Monitorizacion Forense de Honey Files"
                echo "## Auto-generated: solo paths existentes"
                echo ""
                declare -A _hf_map=( [/root/passwords.xlsx.txt]=honeyfile-passwords [/root/backup-keys.txt]=honeyfile-keys [/var/www/html/.htpasswd.bak]=honeyfile-htpasswd [/tmp/.ssh_config]=honeyfile-sshconfig )
                for _hf_path in "${!_hf_map[@]}"; do
                    [[ -f "$_hf_path" ]] || continue
                    _hf_key="${_hf_map[$_hf_path]}"
                    echo "-a always,exit -F arch=b64 -S open,openat,read,readv -F path=$_hf_path -F perm=r -k $_hf_key"
                    echo "-w $_hf_path -p wa -k ${_hf_key}-write"
                done
                # Documentos financieros por usuario
                while IFS=: read -r username _ uid _ _ homedir _; do
                    [[ "$uid" -ge 1000 && "$uid" -lt 65534 ]] || continue
                    [[ -f "${homedir}/Documents/bank-accounts.csv" ]] && echo "-a always,exit -F arch=b64 -S open,openat,read,readv -F path=${homedir}/Documents/bank-accounts.csv -F perm=r -k honeyfile-financial"
                done < /etc/passwd
            } > "$AUDIT_HF_RULES"

            chmod 640 "$AUDIT_HF_RULES"
            augenrules --load 2>/dev/null || auditctl -R "$AUDIT_HF_RULES" 2>/dev/null || true
            log_change "Configurado" "Reglas auditd para honey files: $AUDIT_HF_RULES"
        else
            log_warn "auditd no disponible - honey files no tendran monitorizacion automatica"
        fi
    else
        log_skip "Monitorizacion auditd de honey files"
    fi

    log_info "Honey files configurados"
    log_info "Gestionar: desplegar-honeyfiles.sh {deploy|list|verify|remove}"
else
    log_skip "Honey files (documentos senuelo)"
fi
fi  # S3

if [[ "$DECEPTION_SECTION" == "all" || "$DECEPTION_SECTION" == "S4" ]]; then
# ============================================================
# S4: HONEY USERS (CUENTAS CANARIO)
# ============================================================
log_section "S4: HONEY USERS (CUENTAS CANARIO)"

log_info "Honey users - cuentas senuelo monitorizadas:"
log_info "  - admin_backup (administrador falso)"
log_info "  - oracle (DBA falso)"
log_info "  - svc_jenkins (cuenta de servicio falsa)"
log_info "  - Shells invalidos, cuentas bloqueadas"
log_info "  - Monitorizacion de intentos de autenticacion"
log_info ""

if check_executable /usr/local/bin/gestionar-honey-users.sh; then
    log_already "Honey users (gestionar-honey-users.sh existe)"
elif ask "¿Crear honey users (cuentas canario)?"; then

    HONEYUSERS_CONF="/etc/securizar/honeyusers.conf"
    cat > "$HONEYUSERS_CONF" << EOFHUCONF
# ============================================================
# Inventario de Honey Users - securizar Modulo 55
# Formato: HONEYUSER|NOMBRE|DESCRIPCION|FECHA
# NO EDITAR MANUALMENTE
# ============================================================
EOFHUCONF
    chmod 600 "$HONEYUSERS_CONF"

    # Crear script de gestion
    log_info "Creando /usr/local/bin/gestionar-honey-users.sh..."
    cat > /usr/local/bin/gestionar-honey-users.sh << 'EOFHONEYUSERS'
#!/bin/bash
# ============================================================
# gestionar-honey-users.sh - Gestion de honey users
# Parte de securizar Modulo 55 - Tecnologia de Engano
# ============================================================
set -euo pipefail

CONF="/etc/securizar/honeyusers.conf"
ALERT_SCRIPT="/usr/local/bin/alertar-deception.sh"

# Honey users definidos
HONEY_USERS=("admin_backup" "oracle" "svc_jenkins")
HONEY_DESCRIPTIONS=(
    "Fake backup administrator"
    "Fake Oracle database admin"
    "Fake Jenkins CI service account"
)

usage() {
    echo "Uso: $0 {create|remove|status|check-auth}"
    echo ""
    echo "Comandos:"
    echo "  create      - Crear todas las cuentas canario"
    echo "  remove      - Eliminar todas las cuentas canario"
    echo "  status      - Ver estado de las cuentas canario"
    echo "  check-auth  - Verificar intentos de autenticacion recientes"
    exit 1
}

create_honey_users() {
    echo "[+] Creando honey users..."

    for i in "${!HONEY_USERS[@]}"; do
        local user="${HONEY_USERS[$i]}"
        local desc="${HONEY_DESCRIPTIONS[$i]}"

        if id "$user" &>/dev/null; then
            echo "[!] Usuario '$user' ya existe - verificando configuracion"
        else
            # Crear usuario con shell invalido y sin home funcional
            useradd -r -s /usr/sbin/nologin -M \
                -c "HONEYUSER - ${desc}" \
                "$user" 2>/dev/null || true
            echo "[+] Creado: $user ($desc)"
        fi

        # Bloquear la cuenta
        passwd -l "$user" 2>/dev/null || usermod -L "$user" 2>/dev/null || true

        # Asegurar shell invalido
        usermod -s /usr/sbin/nologin "$user" 2>/dev/null || \
            chsh -s /usr/sbin/nologin "$user" 2>/dev/null || true

        # Registrar en inventario
        echo "HONEYUSER|${user}|${desc}|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$CONF"
    done

    echo "[+] Honey users creados exitosamente"
}

remove_honey_users() {
    echo "[+] Eliminando honey users..."

    for user in "${HONEY_USERS[@]}"; do
        if id "$user" &>/dev/null; then
            userdel "$user" 2>/dev/null || true
            echo "  Eliminado: $user"
        else
            echo "  No existe: $user"
        fi
    done

    # Limpiar inventario
    if [[ -f "$CONF" ]]; then
        grep -v "^HONEYUSER|" "$CONF" > "${CONF}.tmp" 2>/dev/null || true
        mv "${CONF}.tmp" "$CONF" 2>/dev/null || true
    fi

    echo "[+] Honey users eliminados"
}

show_status() {
    echo ""
    echo "═══════════════════════════════════════════"
    echo "  ESTADO DE HONEY USERS"
    echo "═══════════════════════════════════════════"
    echo ""

    for i in "${!HONEY_USERS[@]}"; do
        local user="${HONEY_USERS[$i]}"
        local desc="${HONEY_DESCRIPTIONS[$i]}"

        if id "$user" &>/dev/null; then
            local shell
            shell=$(getent passwd "$user" | cut -d: -f7)
            local locked="NO"
            if passwd -S "$user" 2>/dev/null | grep -qE '^[^ ]+ L'; then
                locked="SI"
            elif [[ "$(getent shadow "$user" 2>/dev/null | cut -d: -f2)" == "!"* ]]; then
                locked="SI"
            fi
            printf "  [EXISTE]   %-16s %-35s Shell: %-20s Bloqueado: %s\n" \
                "$user" "$desc" "$shell" "$locked"
        else
            printf "  [NO EXISTE] %-16s %-35s\n" "$user" "$desc"
        fi
    done
    echo ""
}

check_auth_attempts() {
    echo ""
    echo "═══════════════════════════════════════════"
    echo "  INTENTOS DE AUTENTICACION A HONEY USERS"
    echo "═══════════════════════════════════════════"
    echo ""

    local found=0

    for user in "${HONEY_USERS[@]}"; do
        echo "--- ${user} ---"

        # Buscar en auth.log / secure / journal
        local auth_log=""
        if [[ -f /var/log/auth.log ]]; then
            auth_log="/var/log/auth.log"
        elif [[ -f /var/log/secure ]]; then
            auth_log="/var/log/secure"
        fi

        if [[ -n "$auth_log" ]]; then
            local attempts
            attempts=$(grep -c "$user" "$auth_log" 2>/dev/null || echo "0")
            if [[ "$attempts" -gt 0 ]]; then
                echo "  [!!] ${attempts} intentos encontrados en ${auth_log}:"
                grep "$user" "$auth_log" 2>/dev/null | tail -5
                found=1
                # Alertar
                if [[ -x "$ALERT_SCRIPT" ]]; then
                    "$ALERT_SCRIPT" "CRITICAL" "HONEYUSER" \
                        "Intento de autenticacion a honey user: ${user} (${attempts} intentos)" &
                fi
            else
                echo "  Sin intentos detectados"
            fi
        fi

        # Buscar en journal
        if command -v journalctl &>/dev/null; then
            local jcount
            jcount=$(journalctl --since "7 days ago" 2>/dev/null | grep -c "$user" 2>/dev/null || echo "0")
            if [[ "$jcount" -gt 0 ]]; then
                echo "  [!!] ${jcount} entradas en journal (ultimos 7 dias):"
                journalctl --since "7 days ago" 2>/dev/null | grep "$user" | tail -5
                found=1
            fi
        fi

        # Buscar en auditd
        if command -v ausearch &>/dev/null; then
            local audit_count
            audit_count=$(ausearch -m USER_AUTH -sv no 2>/dev/null | grep -c "$user" 2>/dev/null || echo "0")
            if [[ "$audit_count" -gt 0 ]]; then
                echo "  [!!] ${audit_count} intentos fallidos en audit log:"
                ausearch -m USER_AUTH -sv no 2>/dev/null | grep "$user" | tail -5
                found=1
            fi
        fi

        echo ""
    done

    if [[ $found -eq 0 ]]; then
        echo "  No se detectaron intentos de autenticacion a honey users"
    fi
    echo ""
}

case "${1:-}" in
    create)     create_honey_users ;;
    remove)     remove_honey_users ;;
    status)     show_status ;;
    check-auth) check_auth_attempts ;;
    *)          usage ;;
esac
EOFHONEYUSERS
    chmod +x /usr/local/bin/gestionar-honey-users.sh
    log_change "Creado" "/usr/local/bin/gestionar-honey-users.sh"

    # Crear las cuentas canario
    if ask "¿Crear las cuentas canario ahora (admin_backup, oracle, svc_jenkins)?"; then

        for honey_user in admin_backup oracle svc_jenkins; do
            case "$honey_user" in
                admin_backup) honey_desc="Fake backup administrator" ;;
                oracle)       honey_desc="Fake Oracle database admin" ;;
                svc_jenkins)  honey_desc="Fake Jenkins CI service account" ;;
            esac

            if id "$honey_user" &>/dev/null; then
                log_warn "Usuario '$honey_user' ya existe - verificando configuracion"
            else
                useradd -r -s /usr/sbin/nologin -M \
                    -c "HONEYUSER - ${honey_desc}" \
                    "$honey_user" 2>/dev/null || true
                log_change "Creado" "Honey user: $honey_user ($honey_desc)"
            fi

            # Bloquear
            passwd -l "$honey_user" 2>/dev/null || usermod -L "$honey_user" 2>/dev/null || true
            usermod -s /usr/sbin/nologin "$honey_user" 2>/dev/null || true

            echo "HONEYUSER|${honey_user}|${honey_desc}|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$HONEYUSERS_CONF"
        done

        log_info "Cuentas canario creadas y bloqueadas"
    else
        log_skip "Creacion de cuentas canario"
    fi

    # Configurar auditd para honey users
    if ask "¿Configurar monitorizacion auditd de intentos de autenticacion a honey users?"; then
        if command -v auditctl &>/dev/null; then
            AUDIT_HU_RULES="/etc/audit/rules.d/99-honeyusers.rules"
            if [[ -f "$AUDIT_HU_RULES" ]]; then
                cp -a "$AUDIT_HU_RULES" "$BACKUP_DIR/"
            fi

            # Generar reglas solo para paths que existen
            {
                echo "## Securizar Modulo 55 - Monitorizacion de Honey Users"
                echo "## Auto-generated: solo paths existentes"
                echo ""
                for _hu_bin in /usr/bin/su /usr/bin/sudo; do
                    [[ -f "$_hu_bin" ]] && echo "-w $_hu_bin -p x -k honeyuser-$(basename "$_hu_bin")"
                done
                echo "-w /etc/passwd -p wa -k honeyuser-passwd-change"
                echo "-w /etc/shadow -p rwa -k honeyuser-shadow-access"
                for _hu_log in /var/log/auth.log /var/log/secure; do
                    [[ -f "$_hu_log" ]] && echo "-w $_hu_log -p wa -k honeyuser-auth-log"
                done
                echo "-a always,exit -F arch=b64 -S execve -F uid=0 -C auid!=uid -k honeyuser-priv-escalation"
            } > "$AUDIT_HU_RULES"

            chmod 640 "$AUDIT_HU_RULES"
            augenrules --load 2>/dev/null || auditctl -R "$AUDIT_HU_RULES" 2>/dev/null || true
            log_change "Configurado" "Reglas auditd para honey users: $AUDIT_HU_RULES"
        else
            log_warn "auditd no disponible - honey users no tendran monitorizacion de auditd"
        fi
    else
        log_skip "Monitorizacion auditd de honey users"
    fi

    # Configurar PAM alertas para honey users
    if ask "¿Configurar alertas PAM para intentos de login a honey users?"; then
        PAM_ALERT_SCRIPT="/usr/local/bin/pam-honeyuser-alert.sh"
        cat > "$PAM_ALERT_SCRIPT" << 'EOFPAMALERT'
#!/bin/bash
# PAM alert script para honey users
# Se ejecuta en cada intento de autenticacion

HONEY_USERS="admin_backup oracle svc_jenkins"
ALERT_SCRIPT="/usr/local/bin/alertar-deception.sh"
LOG_FILE="/var/log/securizar/honeyuser-auth.log"

mkdir -p /var/log/securizar

# PAM pasa el nombre de usuario en PAM_USER
TARGET_USER="${PAM_USER:-${1:-}}"

for hu in $HONEY_USERS; do
    if [[ "$TARGET_USER" == "$hu" ]]; then
        timestamp="$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')"
        src="${PAM_RHOST:-local}"
        tty="${PAM_TTY:-unknown}"
        service="${PAM_SERVICE:-unknown}"

        # Log
        echo "[${timestamp}] HONEY_USER_AUTH: user=${hu} src=${src} tty=${tty} service=${service}" >> "$LOG_FILE"

        # Syslog
        logger -t "securizar-honeyuser" -p auth.crit \
            "HONEY USER AUTH ATTEMPT: user=${hu} src=${src} service=${service}"

        # Alerta centralizada
        if [[ -x "$ALERT_SCRIPT" ]]; then
            "$ALERT_SCRIPT" "CRITICAL" "HONEYUSER" \
                "Intento de autenticacion a honey user: ${hu} desde ${src} via ${service}" &
        fi
        break
    fi
done

exit 0
EOFPAMALERT
        chmod +x "$PAM_ALERT_SCRIPT"
        log_change "Creado" "$PAM_ALERT_SCRIPT"
        log_info "Script de alerta PAM creado"
        log_info "Para activar, agrega a /etc/pam.d/common-auth (o similar):"
        log_info "  auth optional pam_exec.so /usr/local/bin/pam-honeyuser-alert.sh"
    else
        log_skip "Alertas PAM para honey users"
    fi

    log_info "Honey users configurados"
    log_info "Gestionar: gestionar-honey-users.sh {create|remove|status|check-auth}"
else
    log_skip "Honey users (cuentas canario)"
fi
fi  # S4

if [[ "$DECEPTION_SECTION" == "all" || "$DECEPTION_SECTION" == "S5" ]]; then
# ============================================================
# S5: HONEY DIRECTORIES (DIRECTORIOS TRAMPA)
# ============================================================
log_section "S5: HONEY DIRECTORIES (DIRECTORIOS TRAMPA)"

log_info "Honey directories - directorios trampa monitorizados:"
log_info "  - /opt/backup-data/ (ubicacion de backup falsa)"
log_info "  - /var/lib/vault-keys/ (datos de vault falsos)"
log_info "  - /etc/securizar/.admin-keys/ (claves admin falsas)"
log_info "  - /root/.bitcoin/ (wallet crypto falso)"
log_info ""

if check_file_exists /etc/securizar/honeydirs.conf; then
    log_already "Honey directories (honeydirs.conf existe)"
elif ask "¿Desplegar honey directories (directorios trampa)?"; then

    HONEYDIRS_CONF="/etc/securizar/honeydirs.conf"
    cat > "$HONEYDIRS_CONF" << EOFHDCONF
# ============================================================
# Inventario de Honey Directories - securizar Modulo 55
# Formato: HONEYDIR|TOKEN_ID|RUTA|DESCRIPCION|FECHA
# NO EDITAR MANUALMENTE
# ============================================================
EOFHDCONF
    chmod 600 "$HONEYDIRS_CONF"

    # Crear script de gestion
    log_info "Creando /usr/local/bin/gestionar-honeydirs.sh..."
    cat > /usr/local/bin/gestionar-honeydirs.sh << 'EOFHONEYDIRS'
#!/bin/bash
# ============================================================
# gestionar-honeydirs.sh - Gestion de honey directories
# Parte de securizar Modulo 55 - Tecnologia de Engano
# ============================================================
set -euo pipefail

CONF="/etc/securizar/honeydirs.conf"
LOG_DIR="/var/log/securizar/honeypot"
ALERT_SCRIPT="/usr/local/bin/alertar-deception.sh"

mkdir -p "$LOG_DIR"

usage() {
    echo "Uso: $0 {deploy|list|verify|remove|monitor}"
    echo ""
    echo "Comandos:"
    echo "  deploy   - Crear y poblar directorios trampa"
    echo "  list     - Listar directorios trampa"
    echo "  verify   - Verificar integridad"
    echo "  remove   - Eliminar directorios trampa"
    echo "  monitor  - Monitorizar acceso en tiempo real (inotifywait)"
    exit 1
}

generate_token_id() {
    local prefix="${1:-HD}"
    echo "${prefix}-$(date +%Y%m%d)-$(openssl rand -hex 4 2>/dev/null || head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
}

deploy_all() {
    echo "[+] Desplegando honey directories..."

    # /opt/backup-data/
    local token_id
    token_id="$(generate_token_id HD)"
    mkdir -p /opt/backup-data
    cat > /opt/backup-data/README.txt << 'EOFBKPREADME'
BACKUP DATA DIRECTORY
=====================
This directory contains encrypted backup archives.
Contact: backup-admin@company.internal
Last full backup: 2025-01-10
EOFBKPREADME

    # Archivos falsos convincentes
    openssl rand -out /opt/backup-data/full-backup-20250110.tar.gz.enc 4096 2>/dev/null || \
        dd if=/dev/urandom of=/opt/backup-data/full-backup-20250110.tar.gz.enc bs=1024 count=4 2>/dev/null || true
    openssl rand -out /opt/backup-data/db-dump-20250112.sql.enc 2048 2>/dev/null || \
        dd if=/dev/urandom of=/opt/backup-data/db-dump-20250112.sql.enc bs=1024 count=2 2>/dev/null || true
    cat > /opt/backup-data/backup-manifest.json << 'EOFJSON'
{
  "backups": [
    {"file": "full-backup-20250110.tar.gz.enc", "type": "full", "size": "4.2GB", "encryption": "AES-256-GCM"},
    {"file": "db-dump-20250112.sql.enc", "type": "database", "size": "850MB", "encryption": "AES-256-GCM"}
  ],
  "encryption_key_id": "backup-master-key-2025",
  "retention_days": 90
}
EOFJSON
    chmod 700 /opt/backup-data
    echo "HONEYDIR|${token_id}|/opt/backup-data|Fake backup location|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$CONF"
    echo "  Desplegado: /opt/backup-data/"

    # /var/lib/vault-keys/
    token_id="$(generate_token_id HD)"
    mkdir -p /var/lib/vault-keys
    cat > /var/lib/vault-keys/unseal-keys.json << EOFVAULT
{
  "keys": [
    "$(openssl rand -base64 44 2>/dev/null)",
    "$(openssl rand -base64 44 2>/dev/null)",
    "$(openssl rand -base64 44 2>/dev/null)",
    "$(openssl rand -base64 44 2>/dev/null)",
    "$(openssl rand -base64 44 2>/dev/null)"
  ],
  "keys_base64": [
    "$(openssl rand -base64 44 2>/dev/null)",
    "$(openssl rand -base64 44 2>/dev/null)",
    "$(openssl rand -base64 44 2>/dev/null)"
  ],
  "root_token": "hvs.$(openssl rand -hex 24 2>/dev/null)"
}
EOFVAULT
    cat > /var/lib/vault-keys/vault-config.hcl << 'EOFVHCL'
storage "consul" {
  address = "127.0.0.1:8500"
  path    = "vault/"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 0
  tls_cert_file = "/opt/vault/tls/vault.crt"
  tls_key_file  = "/opt/vault/tls/vault.key"
}

seal "awskms" {
  region     = "us-east-1"
  kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/fake-key-id"
}
EOFVHCL
    chmod 700 /var/lib/vault-keys
    echo "HONEYDIR|${token_id}|/var/lib/vault-keys|Fake vault data|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$CONF"
    echo "  Desplegado: /var/lib/vault-keys/"

    # /etc/securizar/.admin-keys/
    token_id="$(generate_token_id HD)"
    mkdir -p /etc/securizar/.admin-keys
    openssl rand -base64 32 2>/dev/null > /etc/securizar/.admin-keys/master.key || true
    openssl rand -base64 32 2>/dev/null > /etc/securizar/.admin-keys/recovery.key || true
    cat > /etc/securizar/.admin-keys/key-inventory.txt << EOFKEYS
# Admin Key Inventory - CLASSIFIED
master.key     - Master encryption key (AES-256)
recovery.key   - Disaster recovery key
Last rotation: $(date '+%Y-%m-%d')
Next rotation: $(date -d '+90 days' '+%Y-%m-%d' 2>/dev/null || date '+%Y-%m-%d')
EOFKEYS
    chmod 700 /etc/securizar/.admin-keys
    echo "HONEYDIR|${token_id}|/etc/securizar/.admin-keys|Fake admin keys|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$CONF"
    echo "  Desplegado: /etc/securizar/.admin-keys/"

    # /root/.bitcoin/
    token_id="$(generate_token_id HD)"
    mkdir -p /root/.bitcoin
    cat > /root/.bitcoin/wallet.dat.bak << EOFBTC
# Bitcoin Core wallet backup
# DO NOT DELETE - Contains private keys
# Backup date: $(date '+%Y-%m-%d')
# Wallet balance: 2.45 BTC
EOFBTC
    openssl rand -out /root/.bitcoin/wallet.dat 8192 2>/dev/null || \
        dd if=/dev/urandom of=/root/.bitcoin/wallet.dat bs=1024 count=8 2>/dev/null || true
    cat > /root/.bitcoin/bitcoin.conf << 'EOFBTCCONF'
rpcuser=bitcoinrpc
rpcpassword=5xtremelySafePassw0rd!
rpcallowip=127.0.0.1
server=1
txindex=1
EOFBTCCONF
    chmod 700 /root/.bitcoin
    echo "HONEYDIR|${token_id}|/root/.bitcoin|Fake crypto wallet|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$CONF"
    echo "  Desplegado: /root/.bitcoin/"

    echo "[+] Honey directories desplegados exitosamente"
}

list_dirs() {
    echo ""
    echo "═══════════════════════════════════════════"
    echo "  HONEY DIRECTORIES DESPLEGADOS"
    echo "═══════════════════════════════════════════"
    echo ""

    if [[ ! -f "$CONF" ]]; then
        echo "  No hay honey directories desplegados"
        return 0
    fi

    local count=0
    while IFS='|' read -r type token_id path desc timestamp; do
        [[ "$type" == "HONEYDIR" ]] || continue
        local status="OK"
        if [[ ! -d "$path" ]]; then
            status="FALTA"
        fi
        local file_count=0
        if [[ -d "$path" ]]; then
            file_count=$(find "$path" -type f 2>/dev/null | wc -l)
        fi
        printf "  %-20s %-35s %-10s Archivos: %s\n" "$token_id" "$path" "[$status]" "$file_count"
        ((count++)) || true
    done < "$CONF"

    echo ""
    echo "  Total: ${count} honey directories"
    echo ""
}

verify_dirs() {
    echo "[+] Verificando honey directories..."
    local ok=0
    local missing=0

    if [[ ! -f "$CONF" ]]; then
        echo "[!] No hay inventario"
        return 1
    fi

    while IFS='|' read -r type token_id path desc timestamp; do
        [[ "$type" == "HONEYDIR" ]] || continue
        if [[ -d "$path" ]]; then
            echo "  [OK]    ${path} (${desc})"
            ((ok++)) || true
        else
            echo "  [FALTA] ${path} (${desc}) - POSIBLE ACCESO MALICIOSO"
            ((missing++)) || true
            logger -t "securizar-honeydir" -p auth.crit \
                "HONEYDIR MISSING: ${token_id} path=${path}"
        fi
    done < "$CONF"

    echo ""
    echo "  Intactos: ${ok} | Faltantes: ${missing}"
}

remove_dirs() {
    echo "[+] Eliminando honey directories..."
    if [[ ! -f "$CONF" ]]; then
        echo "[!] No hay inventario"
        return 0
    fi

    while IFS='|' read -r type token_id path desc timestamp; do
        [[ "$type" == "HONEYDIR" ]] || continue
        if [[ -d "$path" ]]; then
            rm -rf "$path"
            echo "  Eliminado: ${path}"
        fi
    done < "$CONF"

    rm -f "$CONF"
    echo "[+] Honey directories eliminados"
}

monitor_dirs() {
    if ! command -v inotifywait &>/dev/null; then
        echo "[X] inotifywait no disponible (instala inotify-tools)"
        exit 1
    fi

    echo "[+] Monitorizando honey directories en tiempo real..."
    echo "    Presiona Ctrl+C para detener"
    echo ""

    local dirs=()
    if [[ -f "$CONF" ]]; then
        while IFS='|' read -r type token_id path desc timestamp; do
            [[ "$type" == "HONEYDIR" ]] || continue
            [[ -d "$path" ]] && dirs+=("$path")
        done < "$CONF"
    fi

    if [[ ${#dirs[@]} -eq 0 ]]; then
        echo "[!] No hay directorios que monitorizar"
        exit 1
    fi

    inotifywait -m -r -e access,open,modify,delete,move \
        --format '%T %w%f %e' --timefmt '%Y-%m-%dT%H:%M:%S' \
        "${dirs[@]}" 2>/dev/null | while read -r timestamp path event; do
        echo "[ALERTA] ${timestamp} ${event}: ${path}"
        logger -t "securizar-honeydir" -p auth.warning \
            "HONEYDIR ACCESS: path=${path} event=${event}"
        if [[ -x "$ALERT_SCRIPT" ]]; then
            "$ALERT_SCRIPT" "WARNING" "HONEYDIR" \
                "Acceso a honey directory: ${path} (${event})" &
        fi
    done
}

case "${1:-}" in
    deploy)  deploy_all ;;
    list)    list_dirs ;;
    verify)  verify_dirs ;;
    remove)  remove_dirs ;;
    monitor) monitor_dirs ;;
    *)       usage ;;
esac
EOFHONEYDIRS
    chmod +x /usr/local/bin/gestionar-honeydirs.sh
    log_change "Creado" "/usr/local/bin/gestionar-honeydirs.sh"

    # Desplegar honey directories
    if ask "¿Desplegar honey directories ahora?"; then

        # /opt/backup-data/
        hd_token_id="$(generate_token_id HD)"
        mkdir -p /opt/backup-data
        cat > /opt/backup-data/README.txt << 'EOFBKRM'
BACKUP DATA DIRECTORY
=====================
Contains encrypted backup archives.
Contact: backup-admin@company.internal
Last full backup: 2025-01-10
EOFBKRM
        openssl rand -out /opt/backup-data/full-backup-20250110.tar.gz.enc 4096 2>/dev/null || true
        openssl rand -out /opt/backup-data/db-dump-20250112.sql.enc 2048 2>/dev/null || true
        cat > /opt/backup-data/backup-manifest.json << 'EOFJSONMF'
{
  "backups": [
    {"file": "full-backup-20250110.tar.gz.enc", "type": "full", "size": "4.2GB"},
    {"file": "db-dump-20250112.sql.enc", "type": "database", "size": "850MB"}
  ],
  "encryption_key_id": "backup-master-key-2025"
}
EOFJSONMF
        chmod 700 /opt/backup-data
        echo "HONEYDIR|${hd_token_id}|/opt/backup-data|Fake backup location|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$HONEYDIRS_CONF"
        log_change "Desplegado" "Honey dir: /opt/backup-data/"

        # /var/lib/vault-keys/
        hd_token_id="$(generate_token_id HD)"
        mkdir -p /var/lib/vault-keys
        cat > /var/lib/vault-keys/unseal-keys.json << EOFVAULTKEYS
{
  "keys": ["$(openssl rand -base64 44 2>/dev/null)","$(openssl rand -base64 44 2>/dev/null)","$(openssl rand -base64 44 2>/dev/null)"],
  "root_token": "hvs.$(openssl rand -hex 24 2>/dev/null)"
}
EOFVAULTKEYS
        chmod 700 /var/lib/vault-keys
        echo "HONEYDIR|${hd_token_id}|/var/lib/vault-keys|Fake vault data|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$HONEYDIRS_CONF"
        log_change "Desplegado" "Honey dir: /var/lib/vault-keys/"

        # /etc/securizar/.admin-keys/
        hd_token_id="$(generate_token_id HD)"
        mkdir -p /etc/securizar/.admin-keys
        openssl rand -base64 32 2>/dev/null > /etc/securizar/.admin-keys/master.key || true
        openssl rand -base64 32 2>/dev/null > /etc/securizar/.admin-keys/recovery.key || true
        cat > /etc/securizar/.admin-keys/key-inventory.txt << 'EOFKEYINV'
# Admin Key Inventory - CLASSIFIED
master.key     - Master encryption key (AES-256)
recovery.key   - Disaster recovery key
EOFKEYINV
        chmod 700 /etc/securizar/.admin-keys
        echo "HONEYDIR|${hd_token_id}|/etc/securizar/.admin-keys|Fake admin keys|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$HONEYDIRS_CONF"
        log_change "Desplegado" "Honey dir: /etc/securizar/.admin-keys/"

        # /root/.bitcoin/
        hd_token_id="$(generate_token_id HD)"
        mkdir -p /root/.bitcoin
        openssl rand -out /root/.bitcoin/wallet.dat 8192 2>/dev/null || true
        cat > /root/.bitcoin/wallet.dat.bak << 'EOFBTCWALLET'
# Bitcoin Core wallet backup
# DO NOT DELETE - Contains private keys
# Wallet balance: 2.45 BTC
EOFBTCWALLET
        cat > /root/.bitcoin/bitcoin.conf << 'EOFBTCCFG'
rpcuser=bitcoinrpc
rpcpassword=5xtremelySafePassw0rd!
server=1
EOFBTCCFG
        chmod 700 /root/.bitcoin
        echo "HONEYDIR|${hd_token_id}|/root/.bitcoin|Fake crypto wallet|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$HONEYDIRS_CONF"
        log_change "Desplegado" "Honey dir: /root/.bitcoin/"

        log_info "Honey directories desplegados"
    else
        log_skip "Despliegue de honey directories"
    fi

    # Monitorizar con auditd
    if ask "¿Configurar monitorizacion auditd de honey directories?"; then
        if command -v auditctl &>/dev/null; then
            AUDIT_HD_RULES="/etc/audit/rules.d/99-honeydirs.rules"
            if [[ -f "$AUDIT_HD_RULES" ]]; then
                cp -a "$AUDIT_HD_RULES" "$BACKUP_DIR/"
            fi

            # Generar reglas solo para directorios que existen
            {
                echo "## Securizar Modulo 55 - Monitorizacion Forense de Honey Directories"
                echo "## Auto-generated: solo paths existentes"
                echo ""
                declare -A _hd_map=( [/opt/backup-data/]=honeydir-backup [/var/lib/vault-keys/]=honeydir-vault [/etc/securizar/.admin-keys/]=honeydir-adminkeys [/root/.bitcoin/]=honeydir-bitcoin )
                for _hd_dir in "${!_hd_map[@]}"; do
                    [[ -d "$_hd_dir" ]] || continue
                    _hd_key="${_hd_map[$_hd_dir]}"
                    echo "-a always,exit -F arch=b64 -S open,openat -F dir=$_hd_dir -F perm=r -k ${_hd_key}-read"
                    echo "-w $_hd_dir -p wa -k ${_hd_key}-write"
                done
            } > "$AUDIT_HD_RULES"
            chmod 640 "$AUDIT_HD_RULES"
            augenrules --load 2>/dev/null || auditctl -R "$AUDIT_HD_RULES" 2>/dev/null || true
            log_change "Configurado" "Reglas auditd para honey directories: $AUDIT_HD_RULES"
        else
            log_warn "auditd no disponible para monitorizacion de honey directories"
        fi
    else
        log_skip "Monitorizacion auditd de honey directories"
    fi

    # Monitorizacion en tiempo real
    if ask "¿Instalar inotify-tools para monitorizacion en tiempo real?"; then
        if ! command -v inotifywait &>/dev/null; then
            pkg_install inotify-tools || true
        fi
        if command -v inotifywait &>/dev/null; then
            log_change "Disponible" "inotifywait para monitorizacion de honey directories"
            # Comprobar monitor forense centralizado
            _HONEY_MON=""
            for _hm_path in /home/*/.config/securizar/honey-monitor.sh; do
                [[ -f "$_hm_path" ]] && _HONEY_MON="$_hm_path" && break
            done
            if [[ -n "$_HONEY_MON" ]]; then
                log_info "Monitor forense centralizado disponible: $_HONEY_MON"
                log_info "  Iniciar daemon: bash $_HONEY_MON watchd"
                log_info "  Ver evidencia:  bash $_HONEY_MON evidence"
            else
                log_info "Ejecutar: gestionar-honeydirs.sh monitor"
            fi
        else
            log_warn "No se pudo instalar inotify-tools"
        fi
    else
        log_skip "Instalacion de inotify-tools"
    fi

    log_info "Honey directories configurados"
    log_info "Gestionar: gestionar-honeydirs.sh {deploy|list|verify|remove|monitor}"
else
    log_skip "Honey directories (directorios trampa)"
fi
fi  # S5

if [[ "$DECEPTION_SECTION" == "all" || "$DECEPTION_SECTION" == "S6" ]]; then
# ============================================================
# S6: HONEY DNS (REGISTROS DNS CANARIO)
# ============================================================
log_section "S6: HONEY DNS (REGISTROS DNS CANARIO)"

log_info "Honey DNS - registros DNS canario:"
log_info "  - admin-panel.internal -> IP de honeypot"
log_info "  - vpn-gateway.internal -> IP de honeypot"
log_info "  - database-primary.internal -> IP de honeypot"
log_info "  - Entradas /etc/hosts como alternativa"
log_info ""

if check_executable /usr/local/bin/configurar-honey-dns.sh; then
    log_already "Honey DNS (configurar-honey-dns.sh existe)"
elif ask "¿Configurar honey DNS (registros DNS canario)?"; then

    # Crear script de gestion
    log_info "Creando /usr/local/bin/configurar-honey-dns.sh..."
    cat > /usr/local/bin/configurar-honey-dns.sh << 'EOFHONEYDNS'
#!/bin/bash
# ============================================================
# configurar-honey-dns.sh - Gestion de honey DNS
# Parte de securizar Modulo 55 - Tecnologia de Engano
# ============================================================
set -euo pipefail

CONF="/etc/securizar/deception/honeydns.conf"
ALERT_SCRIPT="/usr/local/bin/alertar-deception.sh"
LOG_DIR="/var/log/securizar/honeypot"

mkdir -p "$(dirname "$CONF")" "$LOG_DIR"

# Honey DNS entries
declare -A HONEY_DNS_ENTRIES=(
    [admin-panel.internal]="Panel de administracion falso"
    [vpn-gateway.internal]="Gateway VPN falso"
    [database-primary.internal]="Base de datos primaria falsa"
    [jenkins-ci.internal]="Servidor Jenkins CI falso"
    [gitlab.internal]="Servidor GitLab falso"
    [vault.internal]="HashiCorp Vault falso"
    [kubernetes-api.internal]="API Kubernetes falsa"
    [monitoring.internal]="Sistema de monitoreo falso"
)

usage() {
    echo "Uso: $0 {deploy|remove|status|check-resolutions}"
    echo ""
    echo "Comandos:"
    echo "  deploy             - Desplegar registros DNS canario"
    echo "  remove             - Eliminar registros DNS canario"
    echo "  status             - Ver registros desplegados"
    echo "  check-resolutions  - Verificar intentos de resolucion"
    exit 1
}

get_honeypot_ip() {
    # Usar una IP local no enrutable como destino
    # Preferir la IP del honeypot si existe, o 127.0.0.2 (localhost alternativo)
    local honeypot_ip="127.0.0.2"

    # Si hay una interfaz dummy configurada, usarla
    if ip addr show dev dummy0 2>/dev/null | grep -q 'inet '; then
        honeypot_ip=$(ip addr show dev dummy0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 | head -1)
    fi

    echo "$honeypot_ip"
}

deploy_dns() {
    echo "[+] Desplegando honey DNS..."

    local honeypot_ip
    honeypot_ip="$(get_honeypot_ip)"

    # Verificar si hay un DNS server local
    local has_local_dns=0
    if systemctl is-active named &>/dev/null || systemctl is-active bind9 &>/dev/null; then
        has_local_dns=1
        echo "[+] DNS server local detectado (BIND)"
    elif systemctl is-active dnsmasq &>/dev/null; then
        has_local_dns=1
        echo "[+] DNS server local detectado (dnsmasq)"
    elif systemctl is-active unbound &>/dev/null; then
        has_local_dns=1
        echo "[+] DNS server local detectado (unbound)"
    fi

    if [[ $has_local_dns -eq 1 ]]; then
        echo "[+] Configurando registros en DNS local..."

        # Para dnsmasq
        if systemctl is-active dnsmasq &>/dev/null; then
            local dnsmasq_conf="/etc/dnsmasq.d/honey-dns.conf"
            echo "# Securizar Modulo 55 - Honey DNS entries" > "$dnsmasq_conf"
            for hostname in "${!HONEY_DNS_ENTRIES[@]}"; do
                echo "address=/${hostname}/${honeypot_ip}" >> "$dnsmasq_conf"
            done
            systemctl reload dnsmasq 2>/dev/null || systemctl restart dnsmasq 2>/dev/null || true
            echo "[+] Registros honey DNS agregados a dnsmasq"
        fi

        # Para BIND
        if systemctl is-active named &>/dev/null || systemctl is-active bind9 &>/dev/null; then
            echo "[!] Para BIND, agregar registros manualmente a la zona internal"
            echo "    Ejemplo: admin-panel.internal. IN A ${honeypot_ip}"
        fi

        # Para unbound
        if systemctl is-active unbound &>/dev/null; then
            local unbound_conf="/etc/unbound/unbound.conf.d/honey-dns.conf"
            mkdir -p /etc/unbound/unbound.conf.d 2>/dev/null || true
            echo "# Securizar Modulo 55 - Honey DNS entries" > "$unbound_conf"
            echo "server:" >> "$unbound_conf"
            for hostname in "${!HONEY_DNS_ENTRIES[@]}"; do
                echo "    local-data: \"${hostname}. IN A ${honeypot_ip}\"" >> "$unbound_conf"
            done
            systemctl reload unbound 2>/dev/null || systemctl restart unbound 2>/dev/null || true
            echo "[+] Registros honey DNS agregados a unbound"
        fi
    fi

    # Siempre agregar a /etc/hosts como fallback
    echo "[+] Agregando entradas honey DNS a /etc/hosts..."

    # Marcar inicio de seccion
    if ! grep -q "# BEGIN SECURIZAR HONEY DNS" /etc/hosts 2>/dev/null; then
        {
            echo ""
            echo "# BEGIN SECURIZAR HONEY DNS - Modulo 55"
            for hostname in "${!HONEY_DNS_ENTRIES[@]}"; do
                local desc="${HONEY_DNS_ENTRIES[$hostname]}"
                echo "${honeypot_ip}  ${hostname}  # HoneyDNS: ${desc}"
            done
            echo "# END SECURIZAR HONEY DNS"
        } >> /etc/hosts
        echo "[+] Entradas agregadas a /etc/hosts"
    else
        echo "[!] Entradas honey DNS ya existen en /etc/hosts"
    fi

    # Guardar configuracion
    : > "$CONF"
    for hostname in "${!HONEY_DNS_ENTRIES[@]}"; do
        echo "HONEYDNS|${hostname}|${honeypot_ip}|${HONEY_DNS_ENTRIES[$hostname]}|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" >> "$CONF"
    done

    echo "[+] Honey DNS desplegado (IP: ${honeypot_ip})"
}

remove_dns() {
    echo "[+] Eliminando honey DNS..."

    # Limpiar /etc/hosts
    if grep -q "# BEGIN SECURIZAR HONEY DNS" /etc/hosts 2>/dev/null; then
        sed -i '/# BEGIN SECURIZAR HONEY DNS/,/# END SECURIZAR HONEY DNS/d' /etc/hosts
        echo "[+] Entradas eliminadas de /etc/hosts"
    fi

    # Limpiar dnsmasq
    rm -f /etc/dnsmasq.d/honey-dns.conf 2>/dev/null || true
    systemctl reload dnsmasq 2>/dev/null || true

    # Limpiar unbound
    rm -f /etc/unbound/unbound.conf.d/honey-dns.conf 2>/dev/null || true
    systemctl reload unbound 2>/dev/null || true

    rm -f "$CONF"
    echo "[+] Honey DNS eliminado"
}

show_status() {
    echo ""
    echo "═══════════════════════════════════════════"
    echo "  HONEY DNS - REGISTROS DESPLEGADOS"
    echo "═══════════════════════════════════════════"
    echo ""

    if [[ ! -f "$CONF" ]]; then
        echo "  No hay registros honey DNS desplegados"
        return 0
    fi

    local count=0
    while IFS='|' read -r type hostname ip desc timestamp; do
        [[ "$type" == "HONEYDNS" ]] || continue
        printf "  %-35s -> %-15s  (%s)\n" "$hostname" "$ip" "$desc"
        ((count++)) || true
    done < "$CONF"

    echo ""
    echo "  Total: ${count} registros DNS canario"

    # Verificar en /etc/hosts
    echo ""
    if grep -q "SECURIZAR HONEY DNS" /etc/hosts 2>/dev/null; then
        echo "  /etc/hosts: Entradas presentes"
    else
        echo "  /etc/hosts: Sin entradas honey DNS"
    fi
    echo ""
}

check_resolutions() {
    echo ""
    echo "═══════════════════════════════════════════"
    echo "  INTENTOS DE RESOLUCION HONEY DNS"
    echo "═══════════════════════════════════════════"
    echo ""

    local found=0

    # Buscar en query logs de DNS
    for logfile in /var/log/named/queries.log /var/log/dnsmasq.log /var/log/unbound.log; do
        if [[ -f "$logfile" ]]; then
            echo "  --- $logfile ---"
            for hostname in "${!HONEY_DNS_ENTRIES[@]}"; do
                local count
                count=$(grep -c "$hostname" "$logfile" 2>/dev/null || echo "0")
                if [[ "$count" -gt 0 ]]; then
                    echo "  [!!] ${hostname}: ${count} consultas detectadas"
                    grep "$hostname" "$logfile" 2>/dev/null | tail -3
                    found=1
                fi
            done
        fi
    done

    # Buscar en syslog
    local syslog=""
    if [[ -f /var/log/syslog ]]; then
        syslog="/var/log/syslog"
    elif [[ -f /var/log/messages ]]; then
        syslog="/var/log/messages"
    fi

    if [[ -n "$syslog" ]]; then
        for hostname in "${!HONEY_DNS_ENTRIES[@]}"; do
            local count
            count=$(grep -c "$hostname" "$syslog" 2>/dev/null || echo "0")
            if [[ "$count" -gt 0 ]]; then
                echo "  [!!] ${hostname} en syslog: ${count} menciones"
                found=1
            fi
        done
    fi

    if [[ $found -eq 0 ]]; then
        echo "  No se detectaron intentos de resolucion a honey DNS"
    fi
    echo ""
}

case "${1:-}" in
    deploy)            deploy_dns ;;
    remove)            remove_dns ;;
    status)            show_status ;;
    check-resolutions) check_resolutions ;;
    *)                 usage ;;
esac
EOFHONEYDNS
    chmod +x /usr/local/bin/configurar-honey-dns.sh
    log_change "Creado" "/usr/local/bin/configurar-honey-dns.sh"

    # Desplegar honey DNS
    if ask "¿Desplegar registros honey DNS ahora?"; then
        HONEYPOT_IP="127.0.0.2"

        # Backup de /etc/hosts
        cp -a /etc/hosts "$BACKUP_DIR/"
        log_change "Backup" "/etc/hosts"

        # Agregar entradas a /etc/hosts
        if ! grep -q "# BEGIN SECURIZAR HONEY DNS" /etc/hosts 2>/dev/null; then
            cat >> /etc/hosts << EOFHOSTS

# BEGIN SECURIZAR HONEY DNS - Modulo 55
${HONEYPOT_IP}  admin-panel.internal       # HoneyDNS: Panel de administracion falso
${HONEYPOT_IP}  vpn-gateway.internal       # HoneyDNS: Gateway VPN falso
${HONEYPOT_IP}  database-primary.internal  # HoneyDNS: Base de datos primaria falsa
${HONEYPOT_IP}  jenkins-ci.internal        # HoneyDNS: Servidor Jenkins falso
${HONEYPOT_IP}  gitlab.internal            # HoneyDNS: Servidor GitLab falso
${HONEYPOT_IP}  vault.internal             # HoneyDNS: HashiCorp Vault falso
${HONEYPOT_IP}  kubernetes-api.internal    # HoneyDNS: API Kubernetes falsa
${HONEYPOT_IP}  monitoring.internal        # HoneyDNS: Sistema de monitoreo falso
# END SECURIZAR HONEY DNS
EOFHOSTS
            log_change "Configurado" "Honey DNS en /etc/hosts (8 entradas -> ${HONEYPOT_IP})"
        else
            log_info "Entradas honey DNS ya existen en /etc/hosts"
        fi

        # Guardar config
        cat > "${DECEPTION_CONF_DIR}/honeydns.conf" << EOFDNSCONF
HONEYDNS|admin-panel.internal|${HONEYPOT_IP}|Panel admin falso|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')
HONEYDNS|vpn-gateway.internal|${HONEYPOT_IP}|VPN gateway falso|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')
HONEYDNS|database-primary.internal|${HONEYPOT_IP}|DB primaria falsa|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')
HONEYDNS|jenkins-ci.internal|${HONEYPOT_IP}|Jenkins CI falso|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')
HONEYDNS|gitlab.internal|${HONEYPOT_IP}|GitLab falso|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')
HONEYDNS|vault.internal|${HONEYPOT_IP}|Vault falso|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')
HONEYDNS|kubernetes-api.internal|${HONEYPOT_IP}|K8s API falsa|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')
HONEYDNS|monitoring.internal|${HONEYPOT_IP}|Monitoreo falso|$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')
EOFDNSCONF
        chmod 600 "${DECEPTION_CONF_DIR}/honeydns.conf"

        # Configurar DNS local si existe
        if systemctl is-active dnsmasq &>/dev/null; then
            dnsmasq_honey="/etc/dnsmasq.d/honey-dns.conf"
            if [[ -f "$dnsmasq_honey" ]]; then
                cp -a "$dnsmasq_honey" "$BACKUP_DIR/"
            fi
            cat > "$dnsmasq_honey" << EOFDNSMASQ
# Securizar Modulo 55 - Honey DNS entries
address=/admin-panel.internal/${HONEYPOT_IP}
address=/vpn-gateway.internal/${HONEYPOT_IP}
address=/database-primary.internal/${HONEYPOT_IP}
address=/jenkins-ci.internal/${HONEYPOT_IP}
address=/gitlab.internal/${HONEYPOT_IP}
address=/vault.internal/${HONEYPOT_IP}
address=/kubernetes-api.internal/${HONEYPOT_IP}
address=/monitoring.internal/${HONEYPOT_IP}
EOFDNSMASQ
            systemctl reload dnsmasq 2>/dev/null || true
            log_change "Configurado" "Honey DNS en dnsmasq"
        fi

        log_info "Honey DNS desplegado"
    else
        log_skip "Despliegue de honey DNS"
    fi

    log_info "Honey DNS configurado"
    log_info "Gestionar: configurar-honey-dns.sh {deploy|remove|status|check-resolutions}"
else
    log_skip "Honey DNS (registros DNS canario)"
fi
fi  # S6

if [[ "$DECEPTION_SECTION" == "all" || "$DECEPTION_SECTION" == "S7" ]]; then
# ============================================================
# S7: DECEPTION NETWORK SERVICES (SERVICIOS FALSOS)
# ============================================================
log_section "S7: DECEPTION NETWORK SERVICES (SERVICIOS FALSOS)"

log_info "Servicios de red falsos para deception:"
log_info "  - Fake admin panel (login HTML en puerto no estandar)"
log_info "  - Fake API endpoint que registra peticiones"
log_info "  - Servicio systemd: securizar-decoy-web.service"
log_info "  - Logging a /var/log/securizar/decoy-web.log"
log_info ""

if check_executable /usr/local/bin/gestionar-servicios-decoy.sh; then
    log_already "Deception network services (gestionar-servicios-decoy.sh existe)"
elif ask "¿Desplegar servicios de red falsos (deception services)?"; then

    # Crear script de gestion de servicios decoy
    log_info "Creando /usr/local/bin/gestionar-servicios-decoy.sh..."
    cat > /usr/local/bin/gestionar-servicios-decoy.sh << 'EOFDECOYSVC'
#!/bin/bash
# ============================================================
# gestionar-servicios-decoy.sh - Gestion de servicios de red falsos
# Parte de securizar Modulo 55 - Tecnologia de Engano
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar"
WEB_LOG="${LOG_DIR}/decoy-web.log"
DECOY_PORT="${DECOY_WEB_PORT:-8888}"
DECOY_API_PORT="${DECOY_API_PORT:-9999}"
ALERT_SCRIPT="/usr/local/bin/alertar-deception.sh"
DECOY_WEB_DIR="/var/lib/securizar/decoy-web"

mkdir -p "$LOG_DIR" "$DECOY_WEB_DIR"

usage() {
    echo "Uso: $0 {start|stop|status|start-api|stop-api}"
    echo ""
    echo "Comandos:"
    echo "  start     - Iniciar panel admin falso (puerto ${DECOY_PORT})"
    echo "  stop      - Detener panel admin falso"
    echo "  start-api - Iniciar API endpoint falso (puerto ${DECOY_API_PORT})"
    echo "  stop-api  - Detener API endpoint falso"
    echo "  status    - Ver estado de servicios decoy"
    exit 1
}

create_fake_admin_panel() {
    # Crear pagina HTML de login falsa
    cat > "${DECOY_WEB_DIR}/index.html" << 'EOFHTML'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel - Login</title>
    <style>
        body { font-family: Arial, sans-serif; background: #1a1a2e; color: #eee;
               display: flex; justify-content: center; align-items: center;
               min-height: 100vh; margin: 0; }
        .login-box { background: #16213e; padding: 40px; border-radius: 8px;
                     box-shadow: 0 4px 20px rgba(0,0,0,0.3); width: 350px; }
        h2 { text-align: center; color: #0f3460; margin-bottom: 30px; }
        .logo { text-align: center; font-size: 2em; margin-bottom: 20px; }
        input { width: 100%; padding: 12px; margin: 8px 0 16px 0; border: 1px solid #333;
                border-radius: 4px; background: #0f3460; color: #eee; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #e94560; color: white; border: none;
                 border-radius: 4px; cursor: pointer; font-size: 16px; }
        button:hover { background: #c23152; }
        .footer { text-align: center; margin-top: 20px; font-size: 0.8em; color: #666; }
    </style>
</head>
<body>
    <div class="login-box">
        <div class="logo">&#128274;</div>
        <h2 style="color: #e94560;">Admin Panel</h2>
        <form method="POST" action="/login">
            <label>Username</label>
            <input type="text" name="username" placeholder="Enter username" required>
            <label>Password</label>
            <input type="password" name="password" placeholder="Enter password" required>
            <button type="submit">Sign In</button>
        </form>
        <div class="footer">
            Internal use only. Unauthorized access is prohibited.<br>
            &copy; 2025 IT Administration
        </div>
    </div>
</body>
</html>
EOFHTML

    # Crear script Python para el servidor web decoy
    cat > "${DECOY_WEB_DIR}/decoy-server.py" << 'EOFPYTHON'
#!/usr/bin/env python3
"""
Decoy web server - Securizar Modulo 55
Logs all requests and login attempts
"""
import http.server
import json
import os
import sys
import datetime
import urllib.parse
import subprocess

LOG_FILE = os.environ.get("DECOY_WEB_LOG", "/var/log/securizar/decoy-web.log")
ALERT_SCRIPT = "/usr/local/bin/alertar-deception.sh"
WEB_DIR = os.path.dirname(os.path.abspath(__file__))

class DecoyHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def log_request_details(self, method, extra=""):
        timestamp = (lambda t: t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z")(datetime.datetime.utcnow())
        client_ip = self.client_address[0]
        path = self.path
        user_agent = self.headers.get("User-Agent", "unknown")

        log_line = (
            f"[{timestamp}] METHOD={method} SRC={client_ip} "
            f"PATH={path} UA={user_agent} {extra}\n"
        )

        with open(LOG_FILE, "a") as f:
            f.write(log_line)

        # Syslog
        os.system(
            f'logger -t securizar-decoy-web -p auth.warning '
            f'"DECOY_WEB: {method} from {client_ip} path={path}"'
        )

        # Alert
        if os.path.isfile(ALERT_SCRIPT) and os.access(ALERT_SCRIPT, os.X_OK):
            try:
                subprocess.Popen(
                    [ALERT_SCRIPT, "WARNING", "DECOY_WEB",
                     f"Acceso decoy web: {client_ip} {method} {path}"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            except Exception:
                pass

    def do_GET(self):
        self.log_request_details("GET")
        if self.path == "/" or self.path == "/login":
            self.path = "/index.html"
        super().do_GET()

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length).decode("utf-8", errors="replace")

        # Parse login attempts
        parsed = urllib.parse.parse_qs(post_data)
        username = parsed.get("username", [""])[0]
        password = parsed.get("password", [""])[0]

        self.log_request_details(
            "POST",
            f"LOGIN_ATTEMPT user={username} pass_length={len(password)}"
        )

        # Always return "invalid credentials"
        self.send_response(401)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        response = """
        <html><body style="background:#1a1a2e;color:#e94560;font-family:Arial;text-align:center;padding:50px;">
        <h2>Authentication Failed</h2>
        <p>Invalid username or password. This attempt has been logged.</p>
        <a href="/" style="color:#0f3460;">Try again</a>
        </body></html>
        """
        self.wfile.write(response.encode())

    def do_HEAD(self):
        self.log_request_details("HEAD")
        super().do_HEAD()

    def log_message(self, format, *args):
        """Suppress default logging to stderr"""
        pass

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8888
    server = http.server.HTTPServer(("0.0.0.0", port), DecoyHandler)
    print(f"Decoy web server running on port {port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
EOFPYTHON
    chmod +x "${DECOY_WEB_DIR}/decoy-server.py"
}

# Crear script Python para API endpoint falso
create_fake_api() {
    cat > "${DECOY_WEB_DIR}/decoy-api.py" << 'EOFAPI'
#!/usr/bin/env python3
"""
Decoy API server - Securizar Modulo 55
Logs all API requests
"""
import http.server
import json
import os
import sys
import datetime
import subprocess

LOG_FILE = os.environ.get("DECOY_API_LOG", "/var/log/securizar/decoy-api.log")
ALERT_SCRIPT = "/usr/local/bin/alertar-deception.sh"

class DecoyAPIHandler(http.server.BaseHTTPRequestHandler):
    def log_api_request(self, method, body=""):
        timestamp = (lambda t: t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z")(datetime.datetime.utcnow())
        client_ip = self.client_address[0]
        path = self.path
        auth_header = self.headers.get("Authorization", "none")
        api_key = self.headers.get("X-API-Key", "none")

        log_line = (
            f"[{timestamp}] METHOD={method} SRC={client_ip} PATH={path} "
            f"AUTH={auth_header} API_KEY={api_key} BODY={body[:200]}\n"
        )

        with open(LOG_FILE, "a") as f:
            f.write(log_line)

        os.system(
            f'logger -t securizar-decoy-api -p auth.warning '
            f'"DECOY_API: {method} from {client_ip} path={path}"'
        )

        if os.path.isfile(ALERT_SCRIPT) and os.access(ALERT_SCRIPT, os.X_OK):
            try:
                subprocess.Popen(
                    [ALERT_SCRIPT, "WARNING", "DECOY_API",
                     f"Acceso decoy API: {client_ip} {method} {path}"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            except Exception:
                pass

    def send_json(self, status, data):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Request-ID", os.urandom(8).hex())
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())

    def do_GET(self):
        self.log_api_request("GET")

        if self.path == "/api/v1/health":
            self.send_json(200, {"status": "healthy", "version": "2.4.1"})
        elif self.path == "/api/v1/users":
            self.send_json(401, {"error": "Authentication required", "code": "AUTH_REQUIRED"})
        elif self.path.startswith("/api/"):
            self.send_json(403, {"error": "Insufficient permissions", "code": "FORBIDDEN"})
        else:
            self.send_json(404, {"error": "Not found", "code": "NOT_FOUND"})

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace")
        self.log_api_request("POST", body)
        self.send_json(401, {"error": "Invalid credentials", "code": "AUTH_FAILED"})

    def do_PUT(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace")
        self.log_api_request("PUT", body)
        self.send_json(403, {"error": "Forbidden", "code": "FORBIDDEN"})

    def do_DELETE(self):
        self.log_api_request("DELETE")
        self.send_json(403, {"error": "Forbidden", "code": "FORBIDDEN"})

    def log_message(self, format, *args):
        pass

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9999
    server = http.server.HTTPServer(("0.0.0.0", port), DecoyAPIHandler)
    print(f"Decoy API server running on port {port}")
    try:
        server.serve_forever()
    except Exception:
        server.server_close()
EOFAPI
    chmod +x "${DECOY_WEB_DIR}/decoy-api.py"
}

start_web() {
    create_fake_admin_panel
    echo "[+] Iniciando panel admin falso en puerto ${DECOY_PORT}..."

    if command -v python3 &>/dev/null; then
        python3 "${DECOY_WEB_DIR}/decoy-server.py" "$DECOY_PORT" &
        local pid=$!
        echo "$pid" > /run/securizar-decoy-web.pid
        echo "[+] Decoy web panel iniciado (PID: ${pid}, Puerto: ${DECOY_PORT})"
    else
        echo "[X] Python3 no disponible - no se puede iniciar el panel decoy"
        exit 1
    fi
}

stop_web() {
    local pid_file="/run/securizar-decoy-web.pid"
    if [[ -f "$pid_file" ]]; then
        local pid
        pid=$(cat "$pid_file")
        kill "$pid" 2>/dev/null || true
        rm -f "$pid_file"
        echo "[+] Decoy web panel detenido"
    else
        echo "[!] No hay proceso decoy web registrado"
    fi
}

start_api() {
    create_fake_api
    echo "[+] Iniciando API endpoint falso en puerto ${DECOY_API_PORT}..."

    if command -v python3 &>/dev/null; then
        python3 "${DECOY_WEB_DIR}/decoy-api.py" "$DECOY_API_PORT" &
        local pid=$!
        echo "$pid" > /run/securizar-decoy-api.pid
        echo "[+] Decoy API iniciado (PID: ${pid}, Puerto: ${DECOY_API_PORT})"
    else
        echo "[X] Python3 no disponible"
        exit 1
    fi
}

stop_api() {
    local pid_file="/run/securizar-decoy-api.pid"
    if [[ -f "$pid_file" ]]; then
        local pid
        pid=$(cat "$pid_file")
        kill "$pid" 2>/dev/null || true
        rm -f "$pid_file"
        echo "[+] Decoy API detenido"
    else
        echo "[!] No hay proceso decoy API registrado"
    fi
}

show_status() {
    echo ""
    echo "═══════════════════════════════════════════"
    echo "  SERVICIOS DECOY"
    echo "═══════════════════════════════════════════"
    echo ""

    # Web panel
    local web_pid_file="/run/securizar-decoy-web.pid"
    if [[ -f "$web_pid_file" ]] && kill -0 "$(cat "$web_pid_file")" 2>/dev/null; then
        echo "  [ACTIVO]   Panel Admin (puerto ${DECOY_PORT}) - PID $(cat "$web_pid_file")"
    else
        echo "  [INACTIVO] Panel Admin (puerto ${DECOY_PORT})"
    fi

    # API endpoint
    local api_pid_file="/run/securizar-decoy-api.pid"
    if [[ -f "$api_pid_file" ]] && kill -0 "$(cat "$api_pid_file")" 2>/dev/null; then
        echo "  [ACTIVO]   API Endpoint (puerto ${DECOY_API_PORT}) - PID $(cat "$api_pid_file")"
    else
        echo "  [INACTIVO] API Endpoint (puerto ${DECOY_API_PORT})"
    fi

    # Logs recientes
    echo ""
    echo "  Ultimas conexiones web:"
    if [[ -f "$WEB_LOG" ]]; then
        tail -5 "$WEB_LOG" | while read -r line; do
            echo "    $line"
        done
    else
        echo "    Sin conexiones registradas"
    fi

    echo ""
    echo "  Ultimas conexiones API:"
    local api_log="${LOG_DIR}/decoy-api.log"
    if [[ -f "$api_log" ]]; then
        tail -5 "$api_log" | while read -r line; do
            echo "    $line"
        done
    else
        echo "    Sin conexiones registradas"
    fi
    echo ""
}

case "${1:-}" in
    start)     start_web ;;
    stop)      stop_web ;;
    start-api) start_api ;;
    stop-api)  stop_api ;;
    status)    show_status ;;
    *)         usage ;;
esac
EOFDECOYSVC
    chmod +x /usr/local/bin/gestionar-servicios-decoy.sh
    log_change "Creado" "/usr/local/bin/gestionar-servicios-decoy.sh"

    # Crear servicio systemd para el web panel decoy
    log_info "Creando securizar-decoy-web.service..."
    mkdir -p /var/lib/securizar/decoy-web

    cat > /etc/systemd/system/securizar-decoy-web.service << 'EOFSVCWEB'
[Unit]
Description=Securizar Decoy Web Panel - Modulo 55
Documentation=man:securizar(8)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/gestionar-servicios-decoy.sh start
ExecStop=/usr/local/bin/gestionar-servicios-decoy.sh stop
Restart=on-failure
RestartSec=15
Environment=DECOY_WEB_PORT=8888
StandardOutput=journal
StandardError=journal
SyslogIdentifier=securizar-decoy-web

# Seguridad
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/log/securizar /var/lib/securizar /run
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOFSVCWEB
    log_change "Creado" "/etc/systemd/system/securizar-decoy-web.service"

    # Crear servicio systemd para el API endpoint decoy
    cat > /etc/systemd/system/securizar-decoy-api.service << 'EOFSVCAPI'
[Unit]
Description=Securizar Decoy API Endpoint - Modulo 55
Documentation=man:securizar(8)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/gestionar-servicios-decoy.sh start-api
ExecStop=/usr/local/bin/gestionar-servicios-decoy.sh stop-api
Restart=on-failure
RestartSec=15
Environment=DECOY_API_PORT=9999
StandardOutput=journal
StandardError=journal
SyslogIdentifier=securizar-decoy-api

# Seguridad
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/log/securizar /var/lib/securizar /run
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOFSVCAPI
    log_change "Creado" "/etc/systemd/system/securizar-decoy-api.service"

    # Crear el contenido web falso ahora
    if ask "¿Crear e iniciar el panel admin falso y API decoy?"; then
        mkdir -p /var/lib/securizar/decoy-web

        # Crear la pagina HTML del panel falso
        cat > /var/lib/securizar/decoy-web/index.html << 'EOFHTML2'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Panel - Login</title>
    <style>
        body { font-family: Arial, sans-serif; background: #1a1a2e; color: #eee;
               display: flex; justify-content: center; align-items: center;
               min-height: 100vh; margin: 0; }
        .login-box { background: #16213e; padding: 40px; border-radius: 8px;
                     box-shadow: 0 4px 20px rgba(0,0,0,0.3); width: 350px; }
        h2 { text-align: center; color: #e94560; }
        input { width: 100%; padding: 12px; margin: 8px 0 16px 0; border: 1px solid #333;
                border-radius: 4px; background: #0f3460; color: #eee; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #e94560; color: white; border: none;
                 border-radius: 4px; cursor: pointer; font-size: 16px; }
        .footer { text-align: center; margin-top: 20px; font-size: 0.8em; color: #666; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Admin Panel</h2>
        <form method="POST" action="/login">
            <label>Username</label>
            <input type="text" name="username" placeholder="Enter username" required>
            <label>Password</label>
            <input type="password" name="password" placeholder="Enter password" required>
            <button type="submit">Sign In</button>
        </form>
        <div class="footer">Internal use only. Unauthorized access prohibited.</div>
    </div>
</body>
</html>
EOFHTML2
        log_change "Creado" "/var/lib/securizar/decoy-web/index.html (panel admin falso)"

        # Habilitar servicios
        systemctl daemon-reload || true
        if command -v python3 &>/dev/null; then
            systemctl enable securizar-decoy-web.service 2>/dev/null || true
            if systemctl is-active securizar-decoy-web.service &>/dev/null; then
                systemctl restart securizar-decoy-web.service 2>/dev/null || true
                log_change "Reiniciado" "securizar-decoy-web.service (puerto 8888, actualizado)"
            else
                systemctl start securizar-decoy-web.service 2>/dev/null || true
                log_change "Habilitado" "securizar-decoy-web.service (puerto 8888)"
            fi

            systemctl enable securizar-decoy-api.service 2>/dev/null || true
            if systemctl is-active securizar-decoy-api.service &>/dev/null; then
                systemctl restart securizar-decoy-api.service 2>/dev/null || true
                log_change "Reiniciado" "securizar-decoy-api.service (puerto 9999, actualizado)"
            else
                systemctl start securizar-decoy-api.service 2>/dev/null || true
                log_change "Habilitado" "securizar-decoy-api.service (puerto 9999)"
            fi
        else
            log_warn "Python3 no disponible - servicios decoy no se pueden iniciar"
        fi
    else
        log_skip "Creacion e inicio de servicios decoy"
    fi

    log_info "Servicios de red falsos configurados"
    log_info "Gestionar: gestionar-servicios-decoy.sh {start|stop|start-api|stop-api|status}"
else
    log_skip "Deception network services (servicios falsos)"
fi
fi  # S7

if [[ "$DECEPTION_SECTION" == "all" || "$DECEPTION_SECTION" == "S8" ]]; then
# ============================================================
# S8: SISTEMA DE ALERTAS DE DECEPTION
# ============================================================
log_section "S8: SISTEMA DE ALERTAS DE DECEPTION"

log_info "Sistema centralizado de alertas de deception:"
log_info "  - Monitorizacion de todos los logs de deception"
log_info "  - Canales: syslog, journal, email, webhook"
log_info "  - Niveles de severidad: INFO, WARNING, CRITICAL"
log_info "  - Correlacion de eventos multiples"
log_info "  - Rate limiting para evitar fatiga de alertas"
log_info ""

if check_executable /usr/local/bin/alertar-deception.sh; then
    log_already "Sistema de alertas de deception (alertar-deception.sh existe)"
elif ask "¿Configurar sistema centralizado de alertas de deception?"; then

    # Crear configuracion de alertas
    log_info "Creando /etc/securizar/deception-alerts.conf..."
    cat > /etc/securizar/deception-alerts.conf << 'EOFALERTCONF'
# ============================================================
# Configuracion de alertas de deception - securizar Modulo 55
# ============================================================

# Canales de alerta habilitados (syslog siempre activo)
ALERT_SYSLOG=1
ALERT_JOURNAL=1
ALERT_EMAIL=0
ALERT_WEBHOOK=0

# Configuracion de email (si ALERT_EMAIL=1)
ALERT_EMAIL_TO="security@company.internal"
ALERT_EMAIL_FROM="securizar@$(hostname -f 2>/dev/null || echo localhost)"
ALERT_EMAIL_SUBJECT_PREFIX="[SECURIZAR-DECEPTION]"

# Configuracion de webhook (si ALERT_WEBHOOK=1)
ALERT_WEBHOOK_URL=""
ALERT_WEBHOOK_METHOD="POST"
ALERT_WEBHOOK_HEADERS="Content-Type: application/json"

# Rate limiting (segundos entre alertas del mismo tipo)
ALERT_RATE_LIMIT=60

# Umbral de correlacion: N eventos del mismo IP en M minutos = CRITICAL
ALERT_CORRELATION_THRESHOLD=3
ALERT_CORRELATION_WINDOW_MINUTES=10

# Nivel minimo de alerta (INFO, WARNING, CRITICAL)
ALERT_MIN_LEVEL="INFO"

# Log de alertas
ALERT_LOG_FILE="/var/log/securizar/deception-alerts.log"

# Directorio de estado (rate limiting, correlacion)
ALERT_STATE_DIR="/var/lib/securizar/deception-state"
EOFALERTCONF
    chmod 600 /etc/securizar/deception-alerts.conf
    log_change "Creado" "/etc/securizar/deception-alerts.conf"

    # Crear script de alertas centralizado
    log_info "Creando /usr/local/bin/alertar-deception.sh..."
    cat > /usr/local/bin/alertar-deception.sh << 'EOFALERTSCRIPT'
#!/bin/bash
# ============================================================
# alertar-deception.sh - Sistema centralizado de alertas
# Parte de securizar Modulo 55 - Tecnologia de Engano
# ============================================================
# Uso: alertar-deception.sh NIVEL TIPO "Mensaje"
#   NIVEL: INFO, WARNING, CRITICAL
#   TIPO: HONEYPOT, HONEYTOKEN, HONEYFILE, HONEYUSER, HONEYDIR, HONEYDNS, DECOY_WEB, DECOY_API
# ============================================================
set -euo pipefail

CONF="/etc/securizar/deception-alerts.conf"
DEFAULT_LOG="/var/log/securizar/deception-alerts.log"
DEFAULT_STATE_DIR="/var/lib/securizar/deception-state"

# Cargar configuracion
if [[ -f "$CONF" ]]; then
    # shellcheck source=/dev/null
    source "$CONF"
fi

ALERT_LOG="${ALERT_LOG_FILE:-$DEFAULT_LOG}"
STATE_DIR="${ALERT_STATE_DIR:-$DEFAULT_STATE_DIR}"
RATE_LIMIT="${ALERT_RATE_LIMIT:-60}"
CORR_THRESHOLD="${ALERT_CORRELATION_THRESHOLD:-3}"
CORR_WINDOW="${ALERT_CORRELATION_WINDOW_MINUTES:-10}"
MIN_LEVEL="${ALERT_MIN_LEVEL:-INFO}"

mkdir -p "$(dirname "$ALERT_LOG")" "$STATE_DIR"

# Argumentos
LEVEL="${1:-WARNING}"
TYPE="${2:-UNKNOWN}"
MESSAGE="${3:-Sin mensaje}"

# Nivel numerico para comparacion
level_to_num() {
    case "$1" in
        INFO)     echo 1 ;;
        WARNING)  echo 2 ;;
        CRITICAL) echo 3 ;;
        *)        echo 1 ;;
    esac
}

LEVEL_NUM=$(level_to_num "$LEVEL")
MIN_LEVEL_NUM=$(level_to_num "$MIN_LEVEL")

# Verificar nivel minimo
if [[ $LEVEL_NUM -lt $MIN_LEVEL_NUM ]]; then
    exit 0
fi

TIMESTAMP="$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')"
HOSTNAME="$(hostname 2>/dev/null || echo unknown)"

# Rate limiting
RATE_KEY="${TYPE}_$(echo "$MESSAGE" | md5sum 2>/dev/null | cut -d' ' -f1 || echo "nohash")"
RATE_FILE="${STATE_DIR}/rate_${RATE_KEY}"

if [[ -f "$RATE_FILE" ]]; then
    LAST_ALERT=$(cat "$RATE_FILE" 2>/dev/null || echo "0")
    NOW=$(date +%s)
    DIFF=$((NOW - LAST_ALERT))
    if [[ $DIFF -lt $RATE_LIMIT ]]; then
        # Rate limited - registrar silenciosamente
        echo "[${TIMESTAMP}] RATE_LIMITED level=${LEVEL} type=${TYPE} msg=${MESSAGE}" >> "$ALERT_LOG"
        exit 0
    fi
fi
date +%s > "$RATE_FILE"

# Correlacion de IP (extraer IP del mensaje si existe)
SRC_IP=""
if [[ "$MESSAGE" =~ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
    SRC_IP="${BASH_REMATCH[1]}"
fi

if [[ -n "$SRC_IP" ]]; then
    IP_FILE="${STATE_DIR}/ip_${SRC_IP//\./_}"
    echo "${TIMESTAMP}" >> "$IP_FILE"

    # Contar eventos recientes de esta IP
    CUTOFF=$(date -d "${CORR_WINDOW} minutes ago" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "")
    if [[ -n "$CUTOFF" ]]; then
        IP_COUNT=$(awk -v cutoff="$CUTOFF" '$0 >= cutoff' "$IP_FILE" 2>/dev/null | wc -l)
        if [[ $IP_COUNT -ge $CORR_THRESHOLD ]]; then
            LEVEL="CRITICAL"
            LEVEL_NUM=3
            MESSAGE="${MESSAGE} [CORRELACION: ${IP_COUNT} eventos de ${SRC_IP} en ${CORR_WINDOW}m]"
        fi
    fi

    # Limpiar entradas antiguas (>24h)
    if [[ -f "$IP_FILE" ]]; then
        YESTERDAY=$(date -d '24 hours ago' '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "")
        if [[ -n "$YESTERDAY" ]]; then
            awk -v cutoff="$YESTERDAY" '$0 >= cutoff' "$IP_FILE" > "${IP_FILE}.tmp" 2>/dev/null || true
            mv "${IP_FILE}.tmp" "$IP_FILE" 2>/dev/null || true
        fi
    fi
fi

# Formato de alerta
ALERT_LINE="[${TIMESTAMP}] [${LEVEL}] [${TYPE}] HOST=${HOSTNAME} ${MESSAGE}"

# Canal 1: Log file (siempre)
echo "$ALERT_LINE" >> "$ALERT_LOG"

# Canal 2: Syslog
if [[ "${ALERT_SYSLOG:-1}" == "1" ]]; then
    case "$LEVEL" in
        INFO)     SYSLOG_PRI="auth.info" ;;
        WARNING)  SYSLOG_PRI="auth.warning" ;;
        CRITICAL) SYSLOG_PRI="auth.crit" ;;
        *)        SYSLOG_PRI="auth.notice" ;;
    esac
    logger -t "securizar-deception" -p "$SYSLOG_PRI" "$ALERT_LINE"
fi

# Canal 3: Journal (systemd)
if [[ "${ALERT_JOURNAL:-1}" == "1" ]] && command -v systemd-cat &>/dev/null; then
    local_priority="warning"
    case "$LEVEL" in
        INFO)     local_priority="info" ;;
        WARNING)  local_priority="warning" ;;
        CRITICAL) local_priority="crit" ;;
    esac
    echo "$ALERT_LINE" | systemd-cat -t "securizar-deception" -p "$local_priority" 2>/dev/null || true
fi

# Canal 4: Email
if [[ "${ALERT_EMAIL:-0}" == "1" ]]; then
    EMAIL_TO="${ALERT_EMAIL_TO:-root}"
    EMAIL_FROM="${ALERT_EMAIL_FROM:-securizar@localhost}"
    EMAIL_SUBJ="${ALERT_EMAIL_SUBJECT_PREFIX:-[DECEPTION]} [${LEVEL}] ${TYPE}"

    if command -v mail &>/dev/null; then
        echo -e "Alerta de Deception Technology\n\nNivel: ${LEVEL}\nTipo: ${TYPE}\nHostname: ${HOSTNAME}\nFecha: ${TIMESTAMP}\n\nDetalle:\n${MESSAGE}\n\n---\nSecurizar Modulo 55" | \
            mail -s "$EMAIL_SUBJ" -r "$EMAIL_FROM" "$EMAIL_TO" 2>/dev/null || true
    elif command -v sendmail &>/dev/null; then
        {
            echo "From: ${EMAIL_FROM}"
            echo "To: ${EMAIL_TO}"
            echo "Subject: ${EMAIL_SUBJ}"
            echo ""
            echo "Alerta de Deception Technology"
            echo ""
            echo "Nivel: ${LEVEL}"
            echo "Tipo: ${TYPE}"
            echo "Hostname: ${HOSTNAME}"
            echo "Fecha: ${TIMESTAMP}"
            echo ""
            echo "Detalle:"
            echo "${MESSAGE}"
        } | sendmail "$EMAIL_TO" 2>/dev/null || true
    fi
fi

# Canal 5: Webhook
if [[ "${ALERT_WEBHOOK:-0}" == "1" ]] && [[ -n "${ALERT_WEBHOOK_URL:-}" ]]; then
    if command -v curl &>/dev/null; then
        PAYLOAD=$(cat << EOFJSONPAYLOAD
{
    "timestamp": "${TIMESTAMP}",
    "level": "${LEVEL}",
    "type": "${TYPE}",
    "hostname": "${HOSTNAME}",
    "message": "${MESSAGE}",
    "source": "securizar-deception"
}
EOFJSONPAYLOAD
)
        curl -s -X "${ALERT_WEBHOOK_METHOD:-POST}" \
            -H "${ALERT_WEBHOOK_HEADERS:-Content-Type: application/json}" \
            -d "$PAYLOAD" \
            "${ALERT_WEBHOOK_URL}" \
            --max-time 10 \
            -o /dev/null 2>/dev/null || true
    fi
fi

# Salida a consola si es CRITICAL
if [[ "$LEVEL" == "CRITICAL" ]]; then
    echo -e "\033[0;31m[!!!] DECEPTION ALERT: ${ALERT_LINE}\033[0m" >&2
fi

exit 0
EOFALERTSCRIPT
    chmod +x /usr/local/bin/alertar-deception.sh
    log_change "Creado" "/usr/local/bin/alertar-deception.sh"

    # Crear directorio de estado
    mkdir -p /var/lib/securizar/deception-state
    chmod 700 /var/lib/securizar/deception-state

    # Crear script de analisis periodico de logs
    log_info "Creando servicio de analisis periodico..."
    cat > /usr/local/bin/analizar-deception-logs.sh << 'EOFANALYZE'
#!/bin/bash
# ============================================================
# analizar-deception-logs.sh - Analisis periodico de logs de deception
# Parte de securizar Modulo 55 - Tecnologia de Engano
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar"
ALERT_LOG="${LOG_DIR}/deception-alerts.log"
HONEYPOT_LOG_DIR="${LOG_DIR}/honeypot"
ALERT_SCRIPT="/usr/local/bin/alertar-deception.sh"
REPORT_FILE="${LOG_DIR}/deception-analysis-$(date +%Y%m%d-%H%M%S).log"

mkdir -p "$LOG_DIR"

echo "═══════════════════════════════════════════════════"
echo "  ANALISIS DE LOGS DE DECEPTION"
echo "  Fecha: $(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')"
echo "═══════════════════════════════════════════════════"
echo ""

total_events=0
critical_events=0
warning_events=0
unique_ips=0

# Analizar honeypot logs
echo "--- Honeypots ---"
for logfile in "${HONEYPOT_LOG_DIR}"/honeypot-*.log; do
    [[ -f "$logfile" ]] || continue
    port=$(basename "$logfile" | sed 's/honeypot-//;s/\.log//')
    count=$(wc -l < "$logfile" 2>/dev/null || echo "0")
    recent=$(awk -v cutoff="$(date -d '24 hours ago' '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo '2000-01-01')" \
        '$0 >= "["cutoff {c++} END{print c+0}' "$logfile" 2>/dev/null || echo "0")
    echo "  Puerto ${port}: ${count} total, ${recent} ultimas 24h"
    total_events=$((total_events + count))
done

# Analizar log de alertas
echo ""
echo "--- Alertas ---"
if [[ -f "$ALERT_LOG" ]]; then
    critical_events=$(grep -c "\[CRITICAL\]" "$ALERT_LOG" 2>/dev/null || echo "0")
    warning_events=$(grep -c "\[WARNING\]" "$ALERT_LOG" 2>/dev/null || echo "0")
    info_events=$(grep -c "\[INFO\]" "$ALERT_LOG" 2>/dev/null || echo "0")
    rate_limited=$(grep -c "RATE_LIMITED" "$ALERT_LOG" 2>/dev/null || echo "0")

    echo "  CRITICAL: ${critical_events}"
    echo "  WARNING:  ${warning_events}"
    echo "  INFO:     ${info_events}"
    echo "  Rate limited: ${rate_limited}"

    # IPs unicas
    unique_ips=$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$ALERT_LOG" 2>/dev/null | sort -u | wc -l || echo "0")
    echo "  IPs unicas: ${unique_ips}"

    # Top 5 IPs
    echo ""
    echo "  Top 5 IPs atacantes:"
    grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$ALERT_LOG" 2>/dev/null | \
        sort | uniq -c | sort -rn | head -5 | while read -r cnt ip; do
        echo "    ${ip}: ${cnt} eventos"
    done
fi

# Analizar logs de web decoy
echo ""
echo "--- Servicios Decoy ---"
if [[ -f "${LOG_DIR}/decoy-web.log" ]]; then
    web_count=$(wc -l < "${LOG_DIR}/decoy-web.log" 2>/dev/null || echo "0")
    login_attempts=$(grep -c "LOGIN_ATTEMPT" "${LOG_DIR}/decoy-web.log" 2>/dev/null || echo "0")
    echo "  Web panel: ${web_count} peticiones, ${login_attempts} intentos de login"
fi
if [[ -f "${LOG_DIR}/decoy-api.log" ]]; then
    api_count=$(wc -l < "${LOG_DIR}/decoy-api.log" 2>/dev/null || echo "0")
    echo "  API endpoint: ${api_count} peticiones"
fi

# Resumen
echo ""
echo "═══════════════════════════════════════════════════"
echo "  RESUMEN"
echo "═══════════════════════════════════════════════════"
echo "  Total eventos: ${total_events}"
echo "  Alertas criticas: ${critical_events}"
echo "  IPs unicas: ${unique_ips}"

# Generar alerta si hay eventos criticos recientes
if [[ $critical_events -gt 0 ]] && [[ -x "$ALERT_SCRIPT" ]]; then
    "$ALERT_SCRIPT" "CRITICAL" "ANALYSIS" \
        "Analisis periodico: ${critical_events} alertas criticas, ${unique_ips} IPs unicas" || true
fi

# Guardar reporte
{
    echo "ANALISIS DE DECEPTION LOGS"
    echo "Fecha: $(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')"
    echo "Hostname: $(hostname)"
    echo ""
    echo "Total eventos: ${total_events}"
    echo "Alertas CRITICAL: ${critical_events}"
    echo "Alertas WARNING: ${warning_events}"
    echo "IPs unicas: ${unique_ips}"
} > "$REPORT_FILE"
chmod 600 "$REPORT_FILE"
echo ""
echo "Reporte guardado en: ${REPORT_FILE}"
EOFANALYZE
    chmod +x /usr/local/bin/analizar-deception-logs.sh
    log_change "Creado" "/usr/local/bin/analizar-deception-logs.sh"

    # Crear timer de systemd para analisis periodico
    cat > /etc/systemd/system/securizar-deception-analysis.service << 'EOFSVCANALYSIS'
[Unit]
Description=Securizar Deception Log Analysis
Documentation=man:securizar(8)

[Service]
Type=oneshot
ExecStart=/usr/local/bin/analizar-deception-logs.sh
StandardOutput=journal
StandardError=journal
SyslogIdentifier=securizar-deception-analysis
EOFSVCANALYSIS

    cat > /etc/systemd/system/securizar-deception-analysis.timer << 'EOFTIMER'
[Unit]
Description=Securizar Deception Analysis Timer (cada 6h)

[Timer]
OnCalendar=*-*-* 00/6:00:00
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
EOFTIMER

    systemctl daemon-reload 2>/dev/null || true

    if ask "¿Habilitar analisis periodico cada 6 horas?"; then
        systemctl enable securizar-deception-analysis.timer 2>/dev/null || true
        systemctl start securizar-deception-analysis.timer 2>/dev/null || true
        log_change "Habilitado" "Timer de analisis de deception (cada 6h)"
    else
        log_skip "Timer de analisis periodico"
    fi

    log_change "Creado" "/etc/systemd/system/securizar-deception-analysis.service"
    log_change "Creado" "/etc/systemd/system/securizar-deception-analysis.timer"

    log_info "Sistema de alertas de deception configurado"
    log_info "Alerta manual: alertar-deception.sh NIVEL TIPO 'Mensaje'"
    log_info "Analisis: analizar-deception-logs.sh"
else
    log_skip "Sistema de alertas de deception"
fi
fi  # S8

if [[ "$DECEPTION_SECTION" == "all" || "$DECEPTION_SECTION" == "S9" ]]; then
# ============================================================
# S9: DASHBOARD DE DECEPTION
# ============================================================
log_section "S9: DASHBOARD DE DECEPTION"

log_info "Dashboard de deception y reportes automatizados:"
log_info "  - Vista interactiva CLI de estado"
log_info "  - Estadisticas por tipo de senuelo"
log_info "  - Top IPs atacantes"
log_info "  - Reportes automatizados"
log_info ""

if check_executable /usr/local/bin/dashboard-deception.sh; then
    log_already "Dashboard de deception (dashboard-deception.sh existe)"
elif ask "¿Crear dashboard de deception e informes?"; then

    # Dashboard interactivo
    log_info "Creando /usr/local/bin/dashboard-deception.sh..."
    cat > /usr/local/bin/dashboard-deception.sh << 'EOFDASHBOARD'
#!/bin/bash
# ============================================================
# dashboard-deception.sh - Dashboard de deception technology
# Parte de securizar Modulo 55 - Tecnologia de Engano
# ============================================================
set -euo pipefail

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

LOG_DIR="/var/log/securizar"
CONF_DIR="/etc/securizar"
DECEPTION_CONF_DIR="/etc/securizar/deception"
HONEYPOT_LOG_DIR="${LOG_DIR}/honeypot"

# Periodo de analisis
PERIOD="${1:-24h}"
case "$PERIOD" in
    24h)  PERIOD_LABEL="Ultimas 24 horas" ; PERIOD_SECONDS=86400 ;;
    7d)   PERIOD_LABEL="Ultimos 7 dias"   ; PERIOD_SECONDS=604800 ;;
    30d)  PERIOD_LABEL="Ultimos 30 dias"  ; PERIOD_SECONDS=2592000 ;;
    all)  PERIOD_LABEL="Todo el historial"; PERIOD_SECONDS=0 ;;
    *)    PERIOD_LABEL="Ultimas 24 horas" ; PERIOD_SECONDS=86400 ;;
esac

clear 2>/dev/null || true

echo -e "${BOLD}${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║           DASHBOARD DE DECEPTION TECHNOLOGY                   ║"
echo "║           securizar Modulo 55                                 ║"
echo "╠═══════════════════════════════════════════════════════════════╣"
echo -e "║  Host: $(hostname)$(printf '%*s' $((38 - ${#HOSTNAME})) '')                  ║"
echo "║  Fecha: $(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')                              ║"
echo -e "║  Periodo: ${PERIOD_LABEL}$(printf '%*s' $((38 - ${#PERIOD_LABEL})) '')             ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Honeypots ────────────────────────────────────────────────
echo -e "${BOLD}${CYAN}┌── HONEYPOTS DE RED ──────────────────────────────────────┐${NC}"

active_honeypots=0
total_hp_connections=0

shopt -s nullglob
for pid_file in "${DECEPTION_CONF_DIR}"/honeypot-*.pid; do
    [[ -f "$pid_file" ]] || continue
    port=$(basename "$pid_file" | sed 's/honeypot-//;s/\.pid//')
    pid=$(cat "$pid_file" 2>/dev/null || echo "0")

    status_icon="${RED}[X]${NC}"
    if kill -0 "$pid" 2>/dev/null; then
        status_icon="${GREEN}[OK]${NC}"
        ((active_honeypots++)) || true
    fi

    connections=0
    logfile="${HONEYPOT_LOG_DIR}/honeypot-${port}.log"
    if [[ -f "$logfile" ]]; then
        connections=$(wc -l < "$logfile" 2>/dev/null || echo "0")
        total_hp_connections=$((total_hp_connections + connections))
    fi

    # Nombre del servicio
    case "$port" in
        2222) svc_name="SSH" ;;
        2323) svc_name="Telnet" ;;
        2121) svc_name="FTP" ;;
        4445) svc_name="SMB" ;;
        3390) svc_name="RDP" ;;
        3307) svc_name="MySQL" ;;
        *)    svc_name="Custom" ;;
    esac

    echo -e "${CYAN}│${NC}  ${status_icon} Puerto ${port} (${svc_name})  Conexiones: ${connections}"
done
shopt -u nullglob

if [[ $active_honeypots -eq 0 ]]; then
    # Verificar servicios systemd
    for hp_port in 2222 2323 2121 4445 3390 3307; do
        if systemctl is-active "securizar-honeypot@${hp_port}.service" &>/dev/null; then
            echo -e "${CYAN}│${NC}  ${GREEN}[OK]${NC} Puerto ${hp_port} (systemd)"
            ((active_honeypots++)) || true
        fi
    done
fi

if [[ $active_honeypots -eq 0 ]]; then
    echo -e "${CYAN}│${NC}  ${DIM}No hay honeypots activos${NC}"
fi

echo -e "${CYAN}│${NC}  ${BOLD}Total: ${active_honeypots} activos | ${total_hp_connections} conexiones${NC}"
echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
echo ""

# ── Honey Tokens ─────────────────────────────────────────────
echo -e "${BOLD}${CYAN}┌── HONEY TOKENS ──────────────────────────────────────────┐${NC}"

token_count=0
token_missing=0
if [[ -f "${CONF_DIR}/honeytokens.conf" ]]; then
    while IFS='|' read -r type token_id kind path timestamp; do
        [[ "$type" == "HONEYTOKEN" ]] || continue
        ((token_count++)) || true
        if [[ ! -f "$path" ]]; then
            ((token_missing++)) || true
            echo -e "${CYAN}│${NC}  ${RED}[FALTA]${NC} ${kind}: ${path}"
        fi
    done < "${CONF_DIR}/honeytokens.conf"
fi

if [[ $token_count -gt 0 ]]; then
    intact=$((token_count - token_missing))
    echo -e "${CYAN}│${NC}  Desplegados: ${token_count} | Intactos: ${GREEN}${intact}${NC} | Faltantes: ${RED}${token_missing}${NC}"
else
    echo -e "${CYAN}│${NC}  ${DIM}No hay honeytokens desplegados${NC}"
fi
echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
echo ""

# ── Honey Files ──────────────────────────────────────────────
echo -e "${BOLD}${CYAN}┌── HONEY FILES ───────────────────────────────────────────┐${NC}"

hf_count=0
hf_missing=0
if [[ -f "${CONF_DIR}/honeyfiles.conf" ]]; then
    while IFS='|' read -r type token_id kind path timestamp; do
        [[ "$type" == "HONEYFILE" ]] || continue
        ((hf_count++)) || true
        if [[ ! -f "$path" ]]; then
            ((hf_missing++)) || true
            echo -e "${CYAN}│${NC}  ${RED}[FALTA]${NC} ${kind}: ${path}"
        fi
    done < "${CONF_DIR}/honeyfiles.conf"
fi

if [[ $hf_count -gt 0 ]]; then
    hf_intact=$((hf_count - hf_missing))
    echo -e "${CYAN}│${NC}  Desplegados: ${hf_count} | Intactos: ${GREEN}${hf_intact}${NC} | Faltantes: ${RED}${hf_missing}${NC}"
else
    echo -e "${CYAN}│${NC}  ${DIM}No hay honey files desplegados${NC}"
fi
echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
echo ""

# ── Honey Users ──────────────────────────────────────────────
echo -e "${BOLD}${CYAN}┌── HONEY USERS ───────────────────────────────────────────┐${NC}"

hu_active=0
hu_missing=0
for hu in admin_backup oracle svc_jenkins; do
    if id "$hu" &>/dev/null; then
        ((hu_active++)) || true
        local_locked="?"
        if passwd -S "$hu" 2>/dev/null | grep -qE '^[^ ]+ L'; then
            local_locked="Bloqueado"
        fi
        echo -e "${CYAN}│${NC}  ${GREEN}[OK]${NC} ${hu} (${local_locked})"
    else
        ((hu_missing++)) || true
    fi
done

echo -e "${CYAN}│${NC}  Activos: ${GREEN}${hu_active}${NC} | No creados: ${hu_missing}"
echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
echo ""

# ── Honey Directories ───────────────────────────────────────
echo -e "${BOLD}${CYAN}┌── HONEY DIRECTORIES ─────────────────────────────────────┐${NC}"

hd_count=0
hd_missing=0
if [[ -f "${CONF_DIR}/honeydirs.conf" ]]; then
    while IFS='|' read -r type token_id path desc timestamp; do
        [[ "$type" == "HONEYDIR" ]] || continue
        ((hd_count++)) || true
        if [[ ! -d "$path" ]]; then
            ((hd_missing++)) || true
            echo -e "${CYAN}│${NC}  ${RED}[FALTA]${NC} ${path}"
        fi
    done < "${CONF_DIR}/honeydirs.conf"
fi

if [[ $hd_count -gt 0 ]]; then
    hd_intact=$((hd_count - hd_missing))
    echo -e "${CYAN}│${NC}  Desplegados: ${hd_count} | Intactos: ${GREEN}${hd_intact}${NC} | Faltantes: ${RED}${hd_missing}${NC}"
else
    echo -e "${CYAN}│${NC}  ${DIM}No hay honey directories desplegados${NC}"
fi
echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
echo ""

# ── Alertas Recientes ────────────────────────────────────────
echo -e "${BOLD}${CYAN}┌── ALERTAS RECIENTES ─────────────────────────────────────┐${NC}"

ALERT_LOG="${LOG_DIR}/deception-alerts.log"
if [[ -f "$ALERT_LOG" ]]; then
    total_alerts=$(wc -l < "$ALERT_LOG" 2>/dev/null || echo "0")
    critical_count=$(grep -c "\[CRITICAL\]" "$ALERT_LOG" 2>/dev/null || echo "0")
    warning_count=$(grep -c "\[WARNING\]" "$ALERT_LOG" 2>/dev/null || echo "0")
    info_count=$(grep -c "\[INFO\]" "$ALERT_LOG" 2>/dev/null || echo "0")

    echo -e "${CYAN}│${NC}  Total: ${total_alerts} | ${RED}CRITICAL: ${critical_count}${NC} | ${YELLOW}WARNING: ${warning_count}${NC} | INFO: ${info_count}"
    echo -e "${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}  ${BOLD}Ultimas 5 alertas:${NC}"
    tail -5 "$ALERT_LOG" 2>/dev/null | while read -r line; do
        if echo "$line" | grep -q "CRITICAL"; then
            echo -e "${CYAN}│${NC}  ${RED}${line}${NC}"
        elif echo "$line" | grep -q "WARNING"; then
            echo -e "${CYAN}│${NC}  ${YELLOW}${line}${NC}"
        else
            echo -e "${CYAN}│${NC}  ${line}"
        fi
    done
else
    echo -e "${CYAN}│${NC}  ${DIM}Sin alertas registradas${NC}"
fi
echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
echo ""

# ── Top IPs Atacantes ────────────────────────────────────────
echo -e "${BOLD}${CYAN}┌── TOP IPS ATACANTES ─────────────────────────────────────┐${NC}"

if [[ -f "$ALERT_LOG" ]]; then
    top_ips=$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$ALERT_LOG" 2>/dev/null | \
        sort | uniq -c | sort -rn | head -10)
    if [[ -n "$top_ips" ]]; then
        echo "$top_ips" | while read -r cnt ip; do
            bar=""
            for ((i=0; i<cnt && i<30; i++)); do bar+="█"; done
            printf "${CYAN}│${NC}  %-16s %5d %s\n" "$ip" "$cnt" "$bar"
        done
    else
        echo -e "${CYAN}│${NC}  ${DIM}Sin IPs registradas${NC}"
    fi
else
    echo -e "${CYAN}│${NC}  ${DIM}Sin datos de IPs${NC}"
fi
echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
echo ""

# ── Servicios Decoy ──────────────────────────────────────────
echo -e "${BOLD}${CYAN}┌── SERVICIOS DECOY ───────────────────────────────────────┐${NC}"

# Web panel
web_status="${RED}INACTIVO${NC}"
if systemctl is-active securizar-decoy-web.service &>/dev/null; then
    web_status="${GREEN}ACTIVO${NC}"
elif [[ -f /run/securizar-decoy-web.pid ]] && kill -0 "$(cat /run/securizar-decoy-web.pid 2>/dev/null)" 2>/dev/null; then
    web_status="${GREEN}ACTIVO${NC}"
fi
echo -e "${CYAN}│${NC}  Panel Admin (8888): ${web_status}"

# API endpoint
api_status="${RED}INACTIVO${NC}"
if systemctl is-active securizar-decoy-api.service &>/dev/null; then
    api_status="${GREEN}ACTIVO${NC}"
elif [[ -f /run/securizar-decoy-api.pid ]] && kill -0 "$(cat /run/securizar-decoy-api.pid 2>/dev/null)" 2>/dev/null; then
    api_status="${GREEN}ACTIVO${NC}"
fi
echo -e "${CYAN}│${NC}  API Endpoint (9999): ${api_status}"

# Stats
web_reqs=0
api_reqs=0
[[ -f "${LOG_DIR}/decoy-web.log" ]] && web_reqs=$(wc -l < "${LOG_DIR}/decoy-web.log" 2>/dev/null || echo "0")
[[ -f "${LOG_DIR}/decoy-api.log" ]] && api_reqs=$(wc -l < "${LOG_DIR}/decoy-api.log" 2>/dev/null || echo "0")
echo -e "${CYAN}│${NC}  Peticiones web: ${web_reqs} | API: ${api_reqs}"

echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
echo ""

# ── Resumen General ──────────────────────────────────────────
echo -e "${BOLD}${CYAN}┌── RESUMEN GENERAL ───────────────────────────────────────┐${NC}"
total_decoys=$((token_count + hf_count + hu_active + hd_count + active_honeypots))
total_events_all=$((total_hp_connections + web_reqs + api_reqs))
echo -e "${CYAN}│${NC}  Elementos de deception desplegados: ${BOLD}${total_decoys}${NC}"
echo -e "${CYAN}│${NC}  Eventos totales capturados: ${BOLD}${total_events_all}${NC}"
echo -e "${CYAN}│${NC}  Alertas criticas: ${RED}${BOLD}${critical_count:-0}${NC}"
echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
echo ""
echo -e "${DIM}Uso: dashboard-deception.sh [24h|7d|30d|all]${NC}"
EOFDASHBOARD
    chmod +x /usr/local/bin/dashboard-deception.sh
    log_change "Creado" "/usr/local/bin/dashboard-deception.sh"

    # Crear script de informes automatizados
    log_info "Creando /usr/local/bin/informe-deception.sh..."
    cat > /usr/local/bin/informe-deception.sh << 'EOFINFORME'
#!/bin/bash
# ============================================================
# informe-deception.sh - Informes automatizados de deception
# Parte de securizar Modulo 55 - Tecnologia de Engano
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar"
CONF_DIR="/etc/securizar"
REPORT_DIR="${LOG_DIR}/informes-deception"
REPORT_FILE="${REPORT_DIR}/informe-deception-$(date +%Y%m%d-%H%M%S).txt"

mkdir -p "$REPORT_DIR"

PERIOD="${1:-7d}"
case "$PERIOD" in
    24h)  PERIOD_LABEL="Ultimas 24 horas" ;;
    7d)   PERIOD_LABEL="Ultimos 7 dias" ;;
    30d)  PERIOD_LABEL="Ultimos 30 dias" ;;
    *)    PERIOD_LABEL="Periodo: $PERIOD" ;;
esac

{
    echo "============================================================"
    echo "  INFORME DE DECEPTION TECHNOLOGY"
    echo "  securizar Modulo 55"
    echo "============================================================"
    echo ""
    echo "Hostname: $(hostname)"
    echo "Fecha: $(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')"
    echo "Periodo: ${PERIOD_LABEL}"
    echo ""

    # Honeypots
    echo "--- HONEYPOTS DE RED ---"
    active=0
    for pid_file in /etc/securizar/deception/honeypot-*.pid; do
        [[ -f "$pid_file" ]] || continue
        port=$(basename "$pid_file" | sed 's/honeypot-//;s/\.pid//')
        pid=$(cat "$pid_file" 2>/dev/null || echo "0")
        status="INACTIVO"
        if kill -0 "$pid" 2>/dev/null; then
            status="ACTIVO"
            ((active++)) || true
        fi
        connections=0
        logfile="${LOG_DIR}/honeypot/honeypot-${port}.log"
        [[ -f "$logfile" ]] && connections=$(wc -l < "$logfile" 2>/dev/null || echo "0")
        echo "  Puerto ${port}: ${status} (${connections} conexiones)"
    done
    echo "  Activos: ${active}"
    echo ""

    # Tokens
    echo "--- HONEY TOKENS ---"
    tk_total=0
    tk_ok=0
    if [[ -f "${CONF_DIR}/honeytokens.conf" ]]; then
        while IFS='|' read -r type token_id kind path timestamp; do
            [[ "$type" == "HONEYTOKEN" ]] || continue
            ((tk_total++)) || true
            status="FALTA"
            if [[ -f "$path" ]]; then
                status="OK"
                ((tk_ok++)) || true
            fi
            echo "  ${kind} ${path}: ${status}"
        done < "${CONF_DIR}/honeytokens.conf"
    fi
    echo "  Total: ${tk_total} | Intactos: ${tk_ok}"
    echo ""

    # Files
    echo "--- HONEY FILES ---"
    hf_total=0
    hf_ok=0
    if [[ -f "${CONF_DIR}/honeyfiles.conf" ]]; then
        while IFS='|' read -r type token_id kind path timestamp; do
            [[ "$type" == "HONEYFILE" ]] || continue
            ((hf_total++)) || true
            status="FALTA"
            if [[ -f "$path" ]]; then
                status="OK"
                ((hf_ok++)) || true
            fi
            echo "  ${kind} ${path}: ${status}"
        done < "${CONF_DIR}/honeyfiles.conf"
    fi
    echo "  Total: ${hf_total} | Intactos: ${hf_ok}"
    echo ""

    # Users
    echo "--- HONEY USERS ---"
    for hu in admin_backup oracle svc_jenkins; do
        if id "$hu" &>/dev/null; then
            echo "  ${hu}: EXISTE (bloqueado)"
        else
            echo "  ${hu}: NO EXISTE"
        fi
    done
    echo ""

    # Directories
    echo "--- HONEY DIRECTORIES ---"
    hd_total=0
    hd_ok=0
    if [[ -f "${CONF_DIR}/honeydirs.conf" ]]; then
        while IFS='|' read -r type token_id path desc timestamp; do
            [[ "$type" == "HONEYDIR" ]] || continue
            ((hd_total++)) || true
            status="FALTA"
            if [[ -d "$path" ]]; then
                status="OK"
                ((hd_ok++)) || true
            fi
            echo "  ${path}: ${status} (${desc})"
        done < "${CONF_DIR}/honeydirs.conf"
    fi
    echo "  Total: ${hd_total} | Intactos: ${hd_ok}"
    echo ""

    # Alertas
    echo "--- ALERTAS ---"
    alert_log="${LOG_DIR}/deception-alerts.log"
    if [[ -f "$alert_log" ]]; then
        total_alerts=$(wc -l < "$alert_log" 2>/dev/null || echo "0")
        critical=$(grep -c "\[CRITICAL\]" "$alert_log" 2>/dev/null || echo "0")
        warning=$(grep -c "\[WARNING\]" "$alert_log" 2>/dev/null || echo "0")
        echo "  Total: ${total_alerts}"
        echo "  CRITICAL: ${critical}"
        echo "  WARNING: ${warning}"
        echo ""
        echo "  Top 10 IPs:"
        grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$alert_log" 2>/dev/null | \
            sort | uniq -c | sort -rn | head -10 | while read -r cnt ip; do
            echo "    ${ip}: ${cnt} eventos"
        done
    else
        echo "  Sin alertas registradas"
    fi
    echo ""

    # Servicios decoy
    echo "--- SERVICIOS DECOY ---"
    web_status="INACTIVO"
    api_status="INACTIVO"
    systemctl is-active securizar-decoy-web.service &>/dev/null && web_status="ACTIVO"
    systemctl is-active securizar-decoy-api.service &>/dev/null && api_status="ACTIVO"
    echo "  Web Panel: ${web_status}"
    echo "  API Endpoint: ${api_status}"
    web_reqs=0
    api_reqs=0
    [[ -f "${LOG_DIR}/decoy-web.log" ]] && web_reqs=$(wc -l < "${LOG_DIR}/decoy-web.log" 2>/dev/null || echo "0")
    [[ -f "${LOG_DIR}/decoy-api.log" ]] && api_reqs=$(wc -l < "${LOG_DIR}/decoy-api.log" 2>/dev/null || echo "0")
    echo "  Peticiones web: ${web_reqs}"
    echo "  Peticiones API: ${api_reqs}"
    echo ""

    echo "============================================================"
    echo "  FIN DEL INFORME"
    echo "============================================================"

} | tee "$REPORT_FILE"

chmod 600 "$REPORT_FILE"
echo ""
echo "Informe guardado en: ${REPORT_FILE}"
EOFINFORME
    chmod +x /usr/local/bin/informe-deception.sh
    log_change "Creado" "/usr/local/bin/informe-deception.sh"

    log_info "Dashboard y reportes de deception configurados"
    log_info "Dashboard: dashboard-deception.sh [24h|7d|30d|all]"
    log_info "Informe: informe-deception.sh [24h|7d|30d]"
else
    log_skip "Dashboard de deception e informes"
fi
fi  # S9

if [[ "$DECEPTION_SECTION" == "all" || "$DECEPTION_SECTION" == "S10" ]]; then
# ============================================================
# S10: AUDITORIA INTEGRAL DE DECEPTION
# ============================================================
log_section "S10: AUDITORIA INTEGRAL DE DECEPTION"

log_info "Auditoria integral del sistema de deception:"
log_info "  - Verificacion de todos los elementos desplegados"
log_info "  - Estado de honeypots, tokens, files, users"
log_info "  - Puntuacion de cobertura"
log_info "  - Rating: BUENO/MEJORABLE/DEFICIENTE"
log_info ""

if check_executable /usr/local/bin/auditoria-deception.sh; then
    log_already "Auditoria integral de deception (auditoria-deception.sh existe)"
elif ask "¿Crear sistema de auditoria integral de deception?"; then

    log_info "Creando /usr/local/bin/auditoria-deception.sh..."
    cat > /usr/local/bin/auditoria-deception.sh << 'EOFAUDIT'
#!/bin/bash
# ============================================================
# auditoria-deception.sh - Auditoria integral de deception
# Parte de securizar Modulo 55 - Tecnologia de Engano
# ============================================================
set -euo pipefail

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

LOG_DIR="/var/log/securizar"
CONF_DIR="/etc/securizar"
DECEPTION_CONF_DIR="/etc/securizar/deception"
REPORT_FILE="${LOG_DIR}/auditoria-deception-$(date +%Y%m%d-%H%M%S).log"

mkdir -p "$LOG_DIR"

total_checks=0
total_score=0

check_pass() {
    local desc="$1"
    ((total_checks++)) || true
    ((total_score++)) || true
    echo -e "  ${GREEN}[PASS]${NC} ${desc}"
}

check_fail() {
    local desc="$1"
    ((total_checks++)) || true
    echo -e "  ${RED}[FAIL]${NC} ${desc}"
}

check_warn() {
    local desc="$1"
    ((total_checks++)) || true
    echo -e "  ${YELLOW}[WARN]${NC} ${desc}"
}

echo ""
echo -e "${BOLD}${CYAN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     AUDITORIA INTEGRAL DE DECEPTION TECHNOLOGY            ║"
echo "║     securizar Modulo 55                                   ║"
echo "╠═══════════════════════════════════════════════════════════╣"
echo "║  Host: $(hostname)"
echo "║  Fecha: $(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── 1. Verificar honeypots ────────────────────────────────────
echo -e "${BOLD}1. HONEYPOTS DE RED${NC}"
echo ""

hp_active=0
hp_total=0

# Verificar template unit
if [[ -f /etc/systemd/system/securizar-honeypot@.service ]]; then
    check_pass "Template unit securizar-honeypot@.service existe"
else
    check_fail "Template unit securizar-honeypot@.service no encontrada"
fi

# Verificar script
if [[ -x /usr/local/bin/gestionar-honeypots.sh ]]; then
    check_pass "Script gestionar-honeypots.sh presente y ejecutable"
else
    check_fail "Script gestionar-honeypots.sh no encontrado"
fi

# Verificar honeypots activos
for hp_port in 2222 2323 2121 4445 3390 3307; do
    ((hp_total++)) || true
    pid_file="${DECEPTION_CONF_DIR}/honeypot-${hp_port}.pid"
    if [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file" 2>/dev/null)" 2>/dev/null; then
        check_pass "Honeypot puerto ${hp_port}: ACTIVO"
        ((hp_active++)) || true
    elif systemctl is-active "securizar-honeypot@${hp_port}.service" &>/dev/null; then
        check_pass "Honeypot puerto ${hp_port}: ACTIVO (systemd)"
        ((hp_active++)) || true
    else
        check_fail "Honeypot puerto ${hp_port}: INACTIVO"
    fi
done

# Verificar logs
if [[ -d "${LOG_DIR}/honeypot" ]]; then
    check_pass "Directorio de logs de honeypot existe"
else
    check_fail "Directorio de logs de honeypot no existe"
fi

echo ""

# ── 2. Verificar honeytokens ─────────────────────────────────
echo -e "${BOLD}2. HONEY TOKENS${NC}"
echo ""

tk_total=0
tk_ok=0

if [[ -x /usr/local/bin/generar-honeytokens.sh ]]; then
    check_pass "Script generar-honeytokens.sh presente y ejecutable"
else
    check_fail "Script generar-honeytokens.sh no encontrado"
fi

if [[ -f "${CONF_DIR}/honeytokens.conf" ]]; then
    check_pass "Inventario de honeytokens existe"

    while IFS='|' read -r type token_id kind path timestamp; do
        [[ "$type" == "HONEYTOKEN" ]] || continue
        ((tk_total++)) || true
        if [[ -f "$path" ]]; then
            check_pass "Token ${kind} (${token_id}): ${path} intacto"
            ((tk_ok++)) || true
        else
            check_fail "Token ${kind} (${token_id}): ${path} FALTA"
        fi
    done < "${CONF_DIR}/honeytokens.conf"
else
    check_fail "Inventario de honeytokens no encontrado"
fi

# Verificar reglas de auditd
if [[ -f /etc/audit/rules.d/99-honeytokens.rules ]]; then
    check_pass "Reglas auditd para honeytokens configuradas"
else
    check_warn "Reglas auditd para honeytokens no encontradas"
fi

echo ""

# ── 3. Verificar honey files ─────────────────────────────────
echo -e "${BOLD}3. HONEY FILES${NC}"
echo ""

hf_total=0
hf_ok=0

if [[ -x /usr/local/bin/desplegar-honeyfiles.sh ]]; then
    check_pass "Script desplegar-honeyfiles.sh presente y ejecutable"
else
    check_fail "Script desplegar-honeyfiles.sh no encontrado"
fi

if [[ -f "${CONF_DIR}/honeyfiles.conf" ]]; then
    check_pass "Inventario de honey files existe"

    while IFS='|' read -r type token_id kind path timestamp; do
        [[ "$type" == "HONEYFILE" ]] || continue
        ((hf_total++)) || true
        if [[ -f "$path" ]]; then
            check_pass "File ${kind}: ${path} intacto"
            ((hf_ok++)) || true
        else
            check_fail "File ${kind}: ${path} FALTA"
        fi
    done < "${CONF_DIR}/honeyfiles.conf"
else
    check_fail "Inventario de honey files no encontrado"
fi

if [[ -f /etc/audit/rules.d/99-honeyfiles.rules ]]; then
    check_pass "Reglas auditd para honey files configuradas"
else
    check_warn "Reglas auditd para honey files no encontradas"
fi

echo ""

# ── 4. Verificar honey users ─────────────────────────────────
echo -e "${BOLD}4. HONEY USERS${NC}"
echo ""

hu_total=0
hu_ok=0

if [[ -x /usr/local/bin/gestionar-honey-users.sh ]]; then
    check_pass "Script gestionar-honey-users.sh presente y ejecutable"
else
    check_fail "Script gestionar-honey-users.sh no encontrado"
fi

for hu in admin_backup oracle svc_jenkins; do
    ((hu_total++)) || true
    if id "$hu" &>/dev/null; then
        # Verificar que esta bloqueado
        local_shell=$(getent passwd "$hu" 2>/dev/null | cut -d: -f7)
        if [[ "$local_shell" == "/usr/sbin/nologin" ]] || [[ "$local_shell" == "/bin/false" ]]; then
            check_pass "Honey user ${hu}: existe, shell nologin"
            ((hu_ok++)) || true
        else
            check_warn "Honey user ${hu}: existe pero shell=${local_shell} (deberia ser nologin)"
        fi
    else
        check_fail "Honey user ${hu}: no existe"
    fi
done

if [[ -f /etc/audit/rules.d/99-honeyusers.rules ]]; then
    check_pass "Reglas auditd para honey users configuradas"
else
    check_warn "Reglas auditd para honey users no encontradas"
fi

echo ""

# ── 5. Verificar honey directories ───────────────────────────
echo -e "${BOLD}5. HONEY DIRECTORIES${NC}"
echo ""

hd_total=0
hd_ok=0

if [[ -x /usr/local/bin/gestionar-honeydirs.sh ]]; then
    check_pass "Script gestionar-honeydirs.sh presente y ejecutable"
else
    check_fail "Script gestionar-honeydirs.sh no encontrado"
fi

if [[ -f "${CONF_DIR}/honeydirs.conf" ]]; then
    check_pass "Inventario de honey directories existe"

    while IFS='|' read -r type token_id path desc timestamp; do
        [[ "$type" == "HONEYDIR" ]] || continue
        ((hd_total++)) || true
        if [[ -d "$path" ]]; then
            file_count=$(find "$path" -type f 2>/dev/null | wc -l)
            if [[ $file_count -gt 0 ]]; then
                check_pass "Directorio ${path}: existe con ${file_count} archivos"
                ((hd_ok++)) || true
            else
                check_warn "Directorio ${path}: existe pero vacio"
            fi
        else
            check_fail "Directorio ${path}: FALTA"
        fi
    done < "${CONF_DIR}/honeydirs.conf"
else
    check_fail "Inventario de honey directories no encontrado"
fi

if [[ -f /etc/audit/rules.d/99-honeydirs.rules ]]; then
    check_pass "Reglas auditd para honey directories configuradas"
else
    check_warn "Reglas auditd para honey directories no encontradas"
fi

echo ""

# ── 6. Verificar honey DNS ───────────────────────────────────
echo -e "${BOLD}6. HONEY DNS${NC}"
echo ""

if [[ -x /usr/local/bin/configurar-honey-dns.sh ]]; then
    check_pass "Script configurar-honey-dns.sh presente y ejecutable"
else
    check_fail "Script configurar-honey-dns.sh no encontrado"
fi

if grep -q "SECURIZAR HONEY DNS" /etc/hosts 2>/dev/null; then
    dns_count=$(grep -c "HoneyDNS:" /etc/hosts 2>/dev/null || echo "0")
    check_pass "Entradas honey DNS en /etc/hosts: ${dns_count} registros"
else
    check_fail "No hay entradas honey DNS en /etc/hosts"
fi

if [[ -f "${DECEPTION_CONF_DIR}/honeydns.conf" ]]; then
    check_pass "Configuracion honey DNS presente"
else
    check_fail "Configuracion honey DNS no encontrada"
fi

echo ""

# ── 7. Verificar servicios decoy ─────────────────────────────
echo -e "${BOLD}7. SERVICIOS DECOY${NC}"
echo ""

if [[ -x /usr/local/bin/gestionar-servicios-decoy.sh ]]; then
    check_pass "Script gestionar-servicios-decoy.sh presente y ejecutable"
else
    check_fail "Script gestionar-servicios-decoy.sh no encontrado"
fi

if [[ -f /etc/systemd/system/securizar-decoy-web.service ]]; then
    check_pass "Service unit securizar-decoy-web.service existe"
    if systemctl is-active securizar-decoy-web.service &>/dev/null; then
        check_pass "Servicio decoy web: ACTIVO"
    else
        check_warn "Servicio decoy web: INACTIVO"
    fi
else
    check_fail "Service unit securizar-decoy-web.service no encontrada"
fi

if [[ -f /etc/systemd/system/securizar-decoy-api.service ]]; then
    check_pass "Service unit securizar-decoy-api.service existe"
    if systemctl is-active securizar-decoy-api.service &>/dev/null; then
        check_pass "Servicio decoy API: ACTIVO"
    else
        check_warn "Servicio decoy API: INACTIVO"
    fi
else
    check_fail "Service unit securizar-decoy-api.service no encontrada"
fi

echo ""

# ── 8. Verificar sistema de alertas ──────────────────────────
echo -e "${BOLD}8. SISTEMA DE ALERTAS${NC}"
echo ""

if [[ -x /usr/local/bin/alertar-deception.sh ]]; then
    check_pass "Script alertar-deception.sh presente y ejecutable"
else
    check_fail "Script alertar-deception.sh no encontrado"
fi

if [[ -f /etc/securizar/deception-alerts.conf ]]; then
    check_pass "Configuracion de alertas presente"
else
    check_fail "Configuracion de alertas no encontrada"
fi

if [[ -x /usr/local/bin/analizar-deception-logs.sh ]]; then
    check_pass "Script de analisis de logs presente"
else
    check_fail "Script de analisis de logs no encontrado"
fi

if systemctl is-enabled securizar-deception-analysis.timer &>/dev/null; then
    check_pass "Timer de analisis periodico habilitado"
else
    check_warn "Timer de analisis periodico no habilitado"
fi

echo ""

# ── 9. Verificar dashboard e informes ────────────────────────
echo -e "${BOLD}9. DASHBOARD E INFORMES${NC}"
echo ""

if [[ -x /usr/local/bin/dashboard-deception.sh ]]; then
    check_pass "Dashboard de deception presente y ejecutable"
else
    check_fail "Dashboard de deception no encontrado"
fi

if [[ -x /usr/local/bin/informe-deception.sh ]]; then
    check_pass "Script de informes presente y ejecutable"
else
    check_fail "Script de informes no encontrado"
fi

echo ""

# ══════════════════════════════════════════
# RESUMEN DE AUDITORIA
# ══════════════════════════════════════════
echo ""
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  RESUMEN DE AUDITORIA DE DECEPTION${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo ""

# Estadisticas por categoria
echo -e "  ${BOLD}Por categoria:${NC}"
echo "    Honeypots activos:      ${hp_active}/${hp_total}"
echo "    Honeytokens intactos:   ${tk_ok}/${tk_total}"
echo "    Honey files intactos:   ${hf_ok}/${hf_total}"
echo "    Honey users activos:    ${hu_ok}/${hu_total}"
echo "    Honey dirs intactos:    ${hd_ok}/${hd_total}"
echo ""

# Puntuacion global
if [[ $total_checks -gt 0 ]]; then
    global_pct=$((total_score * 100 / total_checks))

    if [[ $global_pct -ge 80 ]]; then
        rating="BUENO"
        rating_color="$GREEN"
    elif [[ $global_pct -ge 50 ]]; then
        rating="MEJORABLE"
        rating_color="$YELLOW"
    else
        rating="DEFICIENTE"
        rating_color="$RED"
    fi

    echo -e "  ${BOLD}PUNTUACION GLOBAL: ${rating_color}${total_score}/${total_checks} (${global_pct}%) - ${rating}${NC}"
else
    echo -e "  ${YELLOW}No se realizaron verificaciones${NC}"
fi

echo ""

# Guardar reporte
{
    echo "AUDITORIA INTEGRAL DE DECEPTION TECHNOLOGY"
    echo "securizar Modulo 55"
    echo "Fecha: $(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')"
    echo "Hostname: $(hostname)"
    echo ""
    echo "Honeypots: ${hp_active}/${hp_total}"
    echo "Honeytokens: ${tk_ok}/${tk_total}"
    echo "Honey files: ${hf_ok}/${hf_total}"
    echo "Honey users: ${hu_ok}/${hu_total}"
    echo "Honey dirs: ${hd_ok}/${hd_total}"
    echo ""
    if [[ $total_checks -gt 0 ]]; then
        echo "GLOBAL: ${total_score}/${total_checks} ($((total_score * 100 / total_checks))%) - ${rating:-N/A}"
    fi
} > "$REPORT_FILE"
chmod 600 "$REPORT_FILE"

echo "Reporte guardado en: $REPORT_FILE"
echo ""
EOFAUDIT
    chmod +x /usr/local/bin/auditoria-deception.sh
    log_change "Creado" "/usr/local/bin/auditoria-deception.sh"

    # Programar auditoria semanal
    if ask "¿Programar auditoria semanal de deception?"; then
        cat > /etc/cron.weekly/auditoria-deception << 'EOFCRONAUDIT'
#!/bin/bash
# Auditoria semanal de deception technology - securizar Modulo 55
/usr/local/bin/auditoria-deception.sh >> /var/log/securizar/auditoria-deception-semanal.log 2>&1
EOFCRONAUDIT
        chmod +x /etc/cron.weekly/auditoria-deception
        log_change "Creado" "/etc/cron.weekly/auditoria-deception (auditoria semanal)"
    else
        log_skip "Cron de auditoria semanal de deception"
    fi

    log_info "Sistema de auditoria integral de deception instalado"
    log_info "Ejecuta: auditoria-deception.sh"
else
    log_skip "Auditoria integral de deception"
fi
fi  # S10

# ============================================================
# RESUMEN FINAL
# ============================================================
show_changes_summary

if [[ "$DECEPTION_SECTION" == "all" ]]; then
    echo ""
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║     TECNOLOGIA DE ENGANO (DECEPTION) COMPLETADO           ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo ""
    log_info "Backups guardados en: $BACKUP_DIR"
    echo ""
    echo "Comandos utiles post-configuracion:"
    echo "  - Gestionar honeypots:    gestionar-honeypots.sh {start|stop|status|logs}"
    echo "  - Gestionar tokens:       generar-honeytokens.sh {deploy|list|verify|rotate}"
    echo "  - Gestionar honey files:  desplegar-honeyfiles.sh {deploy|list|verify|remove}"
    echo "  - Gestionar honey users:  gestionar-honey-users.sh {create|remove|status|check-auth}"
    echo "  - Gestionar honey dirs:   gestionar-honeydirs.sh {deploy|list|verify|monitor}"
    echo "  - Configurar honey DNS:   configurar-honey-dns.sh {deploy|remove|status}"
    echo "  - Servicios decoy:        gestionar-servicios-decoy.sh {start|stop|status}"
    echo "  - Alertas deception:      alertar-deception.sh NIVEL TIPO 'Mensaje'"
    echo "  - Analisis de logs:       analizar-deception-logs.sh"
    echo "  - Dashboard:              dashboard-deception.sh [24h|7d|30d|all]"
    echo "  - Informe:                informe-deception.sh [24h|7d|30d]"
    echo "  - Auditoria completa:     auditoria-deception.sh"
    echo ""
    echo "Monitor forense centralizado (inotifywait + captura evidencia):"
    echo "  - honey-monitor.sh watchd       (daemon con captura forense)"
    echo "  - honey-monitor.sh evidence     (ver paquetes de evidencia)"
    echo "  - honey-monitor.sh audit-setup  (reglas auditd centralizadas)"
    echo ""
    log_info "Modulo 55 completado"
fi
