#!/bin/bash
# ============================================================
# auditoria-red-wireshark.sh - Modulo 66: Auditoria de Red con Wireshark
# ============================================================
# Secciones:
#   S1  - Instalacion de Wireshark y tshark
#   S2  - Configuracion de permisos (grupo wireshark)
#   S3  - Perfiles de captura para auditoria de seguridad
#   S4  - Filtros de captura predefinidos (security-focused)
#   S5  - Scripts de captura automatizada
#   S6  - Analisis de protocolos inseguros
#   S7  - Deteccion de anomalias de red
#   S8  - Exportacion y reportes de auditoria
#   S9  - Integracion con Suricata/IDS
#   S10 - Politica de retencion y rotacion de capturas
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps
init_backup "auditoria-red-wireshark"

# ── Pre-check: detectar secciones ya aplicadas ──────────────
_precheck 10
_pc 'check_executable /usr/bin/tshark || check_executable /usr/local/bin/tshark'
_pc 'check_dir_exists /etc/securizar/wireshark-profiles && test -n "$(ls /etc/securizar/wireshark-profiles/ 2>/dev/null)"'
_pc 'check_dir_exists /etc/securizar/wireshark-profiles'
_pc 'check_file_exists /etc/securizar/wireshark-filters/capture-filters.txt'
_pc 'check_executable /usr/local/bin/auditoria-red-captura.sh'
_pc 'true'
_pc 'check_executable /usr/local/bin/auditoria-red-anomalias.sh'
_pc 'check_executable /usr/local/bin/auditoria-red-reporte.sh'
_pc 'check_executable /usr/local/bin/auditoria-red-correlacion.sh'
_pc 'check_file_exists /etc/securizar/auditoria-red-policy.conf'
_precheck_result

AUDIT_SECTION="${1:-all}"

log_section "MODULO 66: AUDITORIA DE RED CON WIRESHARK"
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

# ── Directorios de trabajo ──────────────────────────────────
CAPTURE_DIR="/var/lib/securizar/capturas-red"
REPORT_DIR="/var/lib/securizar/reportes-red"
FILTER_DIR="/etc/securizar/wireshark-filters"
PROFILE_DIR="/etc/securizar/wireshark-profiles"

mkdir -p "$CAPTURE_DIR" "$REPORT_DIR" "$FILTER_DIR" "$PROFILE_DIR"
chmod 750 "$CAPTURE_DIR" "$REPORT_DIR"

# ── Detectar interfaz de red principal ──────────────────────
detect_main_interface() {
    local iface
    iface=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
    if [[ -z "$iface" ]]; then
        iface=$(ip -o link show up 2>/dev/null | awk -F': ' '{print $2}' | grep -v lo | head -1)
    fi
    if [[ -z "$iface" ]]; then
        iface=$(ls /sys/class/net/ 2>/dev/null | grep -v lo | head -1)
    fi
    echo "${iface:-eth0}"
}

MAIN_IFACE=$(detect_main_interface)
log_info "Interfaz principal detectada: $MAIN_IFACE"

# ============================================================
# S1: INSTALACION DE WIRESHARK Y TSHARK
# ============================================================
if [[ "$AUDIT_SECTION" == "all" || "$AUDIT_SECTION" == "S1" ]]; then
log_section "S1: INSTALACION DE WIRESHARK Y TSHARK"

echo "Wireshark es el analizador de protocolos de red mas utilizado del mundo."
echo "tshark es su version de linea de comandos, ideal para servidores y automatizacion."
echo "Se instalaran ambos para auditoria completa de trafico de red."
echo ""

if check_executable /usr/bin/tshark || check_executable /usr/local/bin/tshark; then
    log_already "Wireshark y tshark (tshark ya instalado)"
elif ask "¿Instalar Wireshark y tshark para auditoria de red?"; then
    TSHARK_INSTALLED=0
    WIRESHARK_INSTALLED=0

    # Verificar si ya estan instalados
    if command -v tshark &>/dev/null; then
        TSHARK_INSTALLED=1
        log_info "tshark ya instalado: $(tshark --version 2>/dev/null | head -1)"
    fi
    if command -v wireshark &>/dev/null; then
        WIRESHARK_INSTALLED=1
        log_info "wireshark ya instalado: $(wireshark --version 2>/dev/null | head -1)"
    fi

    if [[ $TSHARK_INSTALLED -eq 0 ]] || [[ $WIRESHARK_INSTALLED -eq 0 ]]; then
        log_info "Instalando Wireshark y herramientas..."

        case "$DISTRO_FAMILY" in
            suse)
                pkg_install wireshark || {
                    log_warn "Paquete wireshark no disponible, intentando wireshark-ui-qt..."
                    pkg_install wireshark-ui-qt || true
                }
                # tshark viene con el paquete wireshark en openSUSE
                if ! command -v tshark &>/dev/null; then
                    pkg_install tshark 2>/dev/null || true
                fi
                ;;
            debian)
                # En Debian/Ubuntu, configurar DEBIAN_FRONTEND para evitar prompts
                DEBIAN_FRONTEND=noninteractive pkg_install wireshark-common || true
                pkg_install tshark || true
                pkg_install wireshark || true
                ;;
            rhel)
                pkg_install wireshark || true
                pkg_install wireshark-cli 2>/dev/null || true
                ;;
            arch)
                pkg_install wireshark-qt || true
                pkg_install wireshark-cli || true
                ;;
            *)
                log_warn "Distro no reconocida. Intenta instalar wireshark manualmente."
                ;;
        esac

        # Verificar instalacion
        if command -v tshark &>/dev/null; then
            TSHARK_INSTALLED=1
            log_info "tshark instalado correctamente: $(tshark --version 2>/dev/null | head -1)"
            log_change "Instalado" "tshark"
        else
            log_error "No se pudo instalar tshark"
        fi
        if command -v wireshark &>/dev/null; then
            WIRESHARK_INSTALLED=1
            log_info "wireshark instalado correctamente"
            log_change "Instalado" "wireshark"
        fi
    fi

    # Instalar herramientas complementarias
    log_info "Verificando herramientas complementarias..."
    for tool in capinfos editcap mergecap reordercap; do
        if command -v "$tool" &>/dev/null; then
            log_info "$tool disponible"
        else
            log_warn "$tool no encontrado (incluido normalmente con wireshark)"
        fi
    done

    # Instalar tcpdump como alternativa ligera
    if ! command -v tcpdump &>/dev/null; then
        if ask "¿Instalar tcpdump como herramienta de captura complementaria?"; then
            pkg_install tcpdump || log_warn "No se pudo instalar tcpdump"
            if command -v tcpdump &>/dev/null; then
                log_info "tcpdump instalado"
                log_change "Instalado" "tcpdump"
            fi
        fi
    else
        log_info "tcpdump ya disponible"
    fi
else
    log_info "Instalacion omitida por el usuario"
fi

fi

# ============================================================
# S2: CONFIGURACION DE PERMISOS (GRUPO WIRESHARK)
# ============================================================
if [[ "$AUDIT_SECTION" == "all" || "$AUDIT_SECTION" == "S2" ]]; then
log_section "S2: CONFIGURACION DE PERMISOS"

echo "Para capturar trafico sin ser root, se configura el grupo 'wireshark'."
echo "Solo los usuarios de este grupo podran realizar capturas de red."
echo "Esto sigue el principio de minimo privilegio."
echo ""

if getent group wireshark &>/dev/null; then
    log_already "Permisos de captura (grupo wireshark existe)"
elif ask "¿Configurar permisos de captura con grupo wireshark?"; then
    # Crear grupo wireshark si no existe
    if ! getent group wireshark &>/dev/null; then
        groupadd wireshark 2>/dev/null || true
        log_info "Grupo wireshark creado"
        log_change "Creado" "grupo wireshark"
    else
        log_info "Grupo wireshark ya existe"
    fi

    # Configurar dumpcap con capabilities
    DUMPCAP_PATH=""
    for path in /usr/bin/dumpcap /usr/sbin/dumpcap /usr/lib/wireshark/dumpcap /usr/lib64/wireshark/dumpcap; do
        if [[ -f "$path" ]]; then
            DUMPCAP_PATH="$path"
            break
        fi
    done

    if [[ -n "$DUMPCAP_PATH" ]]; then
        # Backup permisos originales
        local_perms=$(stat -c '%a:%U:%G' "$DUMPCAP_PATH" 2>/dev/null || echo "desconocido")
        log_info "Permisos actuales de dumpcap: $local_perms"

        # Asignar grupo y permisos
        chgrp wireshark "$DUMPCAP_PATH" 2>/dev/null || true
        chmod 750 "$DUMPCAP_PATH" 2>/dev/null || true
        log_change "Permisos" "$DUMPCAP_PATH (750, grupo wireshark)"

        # Establecer capabilities en vez de SUID
        if command -v setcap &>/dev/null; then
            setcap 'cap_net_raw,cap_net_admin=eip' "$DUMPCAP_PATH" 2>/dev/null || {
                log_warn "No se pudieron establecer capabilities. Se necesita SUID como alternativa."
                chmod u+s "$DUMPCAP_PATH" 2>/dev/null || true
            }
            # Verificar capabilities
            _getcap=$(command -v getcap 2>/dev/null || echo /usr/sbin/getcap)
            if [[ -x "$_getcap" ]]; then
                caps=$("$_getcap" "$DUMPCAP_PATH" 2>/dev/null || echo "ninguna")
                log_info "Capabilities de dumpcap: $caps"
            fi
            log_change "Capabilities" "$DUMPCAP_PATH (cap_net_raw,cap_net_admin)"
        else
            log_warn "setcap no disponible, usando SUID bit"
            chmod u+s "$DUMPCAP_PATH" 2>/dev/null || true
            log_change "SUID" "$DUMPCAP_PATH"
        fi
    else
        log_warn "dumpcap no encontrado. Permisos no configurados."
    fi

    # Mostrar usuarios actuales del grupo wireshark
    ws_members=$(getent group wireshark 2>/dev/null | cut -d: -f4)
    if [[ -n "$ws_members" ]]; then
        log_info "Miembros actuales del grupo wireshark: $ws_members"
    else
        log_warn "El grupo wireshark no tiene miembros."
        echo "Para agregar un usuario al grupo wireshark:"
        echo "  usermod -aG wireshark <usuario>"
        echo "  (el usuario debe cerrar sesion y volver a entrar)"
    fi

    # Permisos del directorio de capturas
    chown root:wireshark "$CAPTURE_DIR" 2>/dev/null || true
    chmod 770 "$CAPTURE_DIR" 2>/dev/null || true
    log_change "Permisos" "$CAPTURE_DIR (770, grupo wireshark)"
else
    log_info "Configuracion de permisos omitida"
fi

fi

# ============================================================
# S3: PERFILES DE CAPTURA PARA AUDITORIA DE SEGURIDAD
# ============================================================
if [[ "$AUDIT_SECTION" == "all" || "$AUDIT_SECTION" == "S3" ]]; then
log_section "S3: PERFILES DE CAPTURA PARA AUDITORIA"

echo "Se crearan perfiles de captura optimizados para diferentes escenarios"
echo "de auditoria de seguridad."
echo ""

if check_dir_exists /etc/securizar/wireshark-profiles && [[ -n "$(ls /etc/securizar/wireshark-profiles/*.conf 2>/dev/null)" ]]; then
    log_already "Perfiles de captura (perfiles ya existen en wireshark-profiles/)"
elif ask "¿Crear perfiles de captura para auditoria?"; then

    # Perfil 1: Captura general de seguridad
    cat > "$PROFILE_DIR/captura-seguridad-general.conf" << 'EOFPROF'
# Perfil: Captura general de seguridad
# Uso: Auditoria general de trafico de red
CAPTURE_DURATION=300
CAPTURE_FILESIZE=100000
CAPTURE_RING_BUFFER=5
CAPTURE_FILTER="not port 22"
DISPLAY_FILTER=""
SNAP_LEN=0
DESCRIPTION="Captura completa de trafico (excluyendo SSH propio)"
EOFPROF
    log_info "Perfil creado: captura-seguridad-general"

    # Perfil 2: Deteccion de protocolos inseguros
    cat > "$PROFILE_DIR/protocolos-inseguros.conf" << 'EOFPROF'
# Perfil: Deteccion de protocolos inseguros
# Uso: Identificar trafico sin cifrar
CAPTURE_DURATION=600
CAPTURE_FILESIZE=50000
CAPTURE_RING_BUFFER=3
CAPTURE_FILTER="port 21 or port 23 or port 80 or port 110 or port 143 or port 25 or port 161 or port 69 or port 513 or port 514"
DISPLAY_FILTER=""
SNAP_LEN=256
DESCRIPTION="Detectar FTP, Telnet, HTTP, POP3, IMAP, SMTP, SNMP, TFTP sin cifrar"
EOFPROF
    log_info "Perfil creado: protocolos-inseguros"

    # Perfil 3: Analisis DNS
    cat > "$PROFILE_DIR/analisis-dns.conf" << 'EOFPROF'
# Perfil: Analisis de trafico DNS
# Uso: Detectar tunneling DNS, dominios sospechosos
CAPTURE_DURATION=600
CAPTURE_FILESIZE=50000
CAPTURE_RING_BUFFER=3
CAPTURE_FILTER="port 53"
DISPLAY_FILTER=""
SNAP_LEN=0
DESCRIPTION="Captura de trafico DNS para analisis de anomalias"
EOFPROF
    log_info "Perfil creado: analisis-dns"

    # Perfil 4: Deteccion de escaneos
    cat > "$PROFILE_DIR/deteccion-escaneos.conf" << 'EOFPROF'
# Perfil: Deteccion de escaneos de red
# Uso: Identificar nmap, masscan, etc.
CAPTURE_DURATION=300
CAPTURE_FILESIZE=100000
CAPTURE_RING_BUFFER=5
CAPTURE_FILTER="tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst) != 0"
DISPLAY_FILTER=""
SNAP_LEN=96
DESCRIPTION="Detectar escaneos SYN/FIN/RST"
EOFPROF
    log_info "Perfil creado: deteccion-escaneos"

    # Perfil 5: Trafico lateral (interno)
    cat > "$PROFILE_DIR/trafico-lateral.conf" << 'EOFPROF'
# Perfil: Movimiento lateral
# Uso: Detectar actividad lateral interna sospechosa
CAPTURE_DURATION=600
CAPTURE_FILESIZE=100000
CAPTURE_RING_BUFFER=5
CAPTURE_FILTER="net 10.0.0.0/8 or net 172.16.0.0/12 or net 192.168.0.0/16"
DISPLAY_FILTER=""
SNAP_LEN=256
DESCRIPTION="Monitorizar trafico interno para movimiento lateral"
EOFPROF
    log_info "Perfil creado: trafico-lateral"

    # Perfil 6: Exfiltracion de datos
    cat > "$PROFILE_DIR/exfiltracion.conf" << 'EOFPROF'
# Perfil: Deteccion de exfiltracion
# Uso: Identificar transferencias grandes salientes
CAPTURE_DURATION=3600
CAPTURE_FILESIZE=200000
CAPTURE_RING_BUFFER=3
CAPTURE_FILTER="(dst net not 10.0.0.0/8 and dst net not 172.16.0.0/12 and dst net not 192.168.0.0/16) and (greater 1400)"
DISPLAY_FILTER=""
SNAP_LEN=128
DESCRIPTION="Detectar paquetes grandes salientes (posible exfiltracion)"
EOFPROF
    log_info "Perfil creado: exfiltracion"

    chmod 640 "$PROFILE_DIR"/*.conf 2>/dev/null || true
    log_change "Perfiles" "$PROFILE_DIR/ (6 perfiles de auditoria)"
else
    log_info "Creacion de perfiles omitida"
fi

fi

# ============================================================
# S4: FILTROS DE CAPTURA PREDEFINIDOS
# ============================================================
if [[ "$AUDIT_SECTION" == "all" || "$AUDIT_SECTION" == "S4" ]]; then
log_section "S4: FILTROS DE CAPTURA PREDEFINIDOS"

echo "Se instalaran filtros de captura y display optimizados para"
echo "deteccion de amenazas y auditoria de seguridad."
echo ""

if check_file_exists /etc/securizar/wireshark-filters/capture-filters.txt; then
    log_already "Filtros de captura predefinidos (capture-filters.txt existe)"
elif ask "¿Instalar filtros de captura predefinidos?"; then

    # Filtros de captura (BPF)
    cat > "$FILTER_DIR/capture-filters.txt" << 'EOFCF'
# ============================================================
# Filtros de captura BPF para auditoria de seguridad
# Uso con tshark: tshark -f "$(cat filtro)"
# ============================================================

# --- Protocolos inseguros (texto plano) ---
# FTP (21), Telnet (23), HTTP (80), POP3 (110), IMAP (143), SMTP (25)
INSECURE_PROTOS=port 21 or port 23 or port 80 or port 110 or port 143 or port 25

# --- DNS (incluye DNS over TCP) ---
DNS_ALL=port 53

# --- Escaneos de puertos (SYN sin ACK) ---
PORT_SCAN=tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0

# --- ARP (ataques ARP spoofing) ---
ARP_TRAFFIC=arp

# --- ICMP (tunneling, escaneo) ---
ICMP_ALL=icmp or icmp6

# --- DHCP (rogue DHCP) ---
DHCP_TRAFFIC=port 67 or port 68

# --- SMB/CIFS (movimiento lateral) ---
SMB_TRAFFIC=port 445 or port 139

# --- Trafico no RFC1918 saliente (exfiltracion) ---
OUTBOUND_EXTERNAL=dst net not 10.0.0.0/8 and dst net not 172.16.0.0/12 and dst net not 192.168.0.0/16 and dst net not 127.0.0.0/8

# --- Paquetes grandes (>1400 bytes, posible exfiltracion) ---
LARGE_PACKETS=greater 1400

# --- Trafico TOR (puertos comunes) ---
TOR_TRAFFIC=port 9001 or port 9030 or port 9050 or port 9051 or port 9150

# --- VPN no autorizada ---
UNAUTHORIZED_VPN=port 1194 or port 1723 or port 500 or port 4500

# --- Base de datos expuesta ---
DB_EXPOSED=port 3306 or port 5432 or port 1433 or port 27017 or port 6379

# --- IPv6 Router Advertisement (RA spoofing) ---
IPV6_RA=icmp6 and ip6[40] == 134

# --- Gratuitous ARP (sender IP == target IP) ---
GARP=arp and arp[14:4] == arp[24:4]
EOFCF
    log_info "Filtros de captura BPF instalados"

    # Filtros de display (Wireshark display filters)
    cat > "$FILTER_DIR/display-filters.txt" << 'EOFDF'
# ============================================================
# Filtros de display para Wireshark/tshark
# Uso con tshark: tshark -Y "filtro"
# ============================================================

# --- Credenciales en texto plano ---
CLEARTEXT_CREDS=ftp.request.command == "USER" or ftp.request.command == "PASS" or http.authorization or http.cookie or smtp.req.parameter contains "AUTH"

# --- HTTP con datos sensibles ---
HTTP_SENSITIVE=http.request.method == "POST" or http.authorization or http.cookie

# --- DNS sospechoso (consultas largas = posible tunneling) ---
DNS_SUSPICIOUS=dns.qry.name.len > 50

# --- DNS a servidores no autorizados ---
DNS_UNAUTHORIZED=dns and not ip.dst == 1.1.1.1 and not ip.dst == 8.8.8.8 and not ip.dst == 9.9.9.9

# --- TLS con SNI (Server Name Indication) ---
TLS_SNI=tls.handshake.extensions_server_name

# --- Certificados TLS expirados o auto-firmados ---
TLS_CERT_ISSUES=tls.handshake.type == 11

# --- TCP retransmisiones (problemas de red) ---
TCP_RETRANS=tcp.analysis.retransmission

# --- TCP resets (posible escaneo o bloqueo) ---
TCP_RESETS=tcp.flags.reset == 1

# --- ARP duplicados (posible spoofing) ---
ARP_DUPLICATE=arp.duplicate-address-detected

# --- ICMP unreachable (reconocimiento) ---
ICMP_UNREACHABLE=icmp.type == 3

# --- Paquetes malformados ---
MALFORMED=_ws.malformed

# --- Beaconing (conexiones periodicas = posible C2) ---
# Nota: usar estadisticas de tshark para detectar intervalos regulares

# --- NBNS/LLMNR (ataques de envenenamiento) ---
NBNS_LLMNR=nbns or llmnr or mdns

# --- Gratuitous ARP (posible ARP poisoning) ---
ARP_GRATUITOUS=arp.isgratuitous == 1

# --- DHCP starvation (exceso de DHCP Discover) ---
DHCP_STARVATION=dhcp.option.dhcp == 1

# --- Rogue DHCP server (DHCP Offer de fuentes inesperadas) ---
DHCP_ROGUE=dhcp.option.dhcp == 2

# --- LLMNR poisoning (respuestas LLMNR = posible Responder) ---
LLMNR_POISONING=llmnr and dns.flags.response == 1

# --- mDNS poisoning (respuestas mDNS excesivas) ---
MDNS_POISONING=mdns and dns.flags.response == 1

# --- IPv6 Router Advertisement spoofing ---
IPV6_RA_SPOOF=icmpv6.type == 134
EOFDF
    log_info "Filtros de display instalados"

    chmod 644 "$FILTER_DIR"/*.txt 2>/dev/null || true
    log_change "Filtros" "$FILTER_DIR/ (filtros BPF y display)"
else
    log_info "Instalacion de filtros omitida"
fi

fi

# ============================================================
# S5: SCRIPTS DE CAPTURA AUTOMATIZADA
# ============================================================
if [[ "$AUDIT_SECTION" == "all" || "$AUDIT_SECTION" == "S5" ]]; then
log_section "S5: SCRIPTS DE CAPTURA AUTOMATIZADA"

echo "Se creara un script de captura automatizada que puede ejecutarse"
echo "periodicamente o bajo demanda para auditoria de red."
echo ""

if check_executable /usr/local/bin/auditoria-red-captura.sh; then
    log_already "Scripts de captura automatizada (auditoria-red-captura.sh existe)"
elif ask "¿Crear scripts de captura automatizada?"; then

    # Script principal de captura de auditoria
    cat > /usr/local/bin/auditoria-red-captura.sh << 'EOFCAP'
#!/bin/bash
# ============================================================
# auditoria-red-captura.sh - Captura automatizada de red
# ============================================================
# Uso: auditoria-red-captura.sh [perfil] [interfaz] [duracion_seg]
# Perfiles: general, inseguros, dns, escaneos, lateral, exfiltracion
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

CAPTURE_DIR="/var/lib/securizar/capturas-red"
PROFILE_DIR="/etc/securizar/wireshark-profiles"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# Parametros
PERFIL="${1:-general}"
IFACE="${2:-$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)}"
DURACION="${3:-300}"

[[ -z "$IFACE" ]] && IFACE=$(ls /sys/class/net/ 2>/dev/null | grep -v lo | head -1)
IFACE="${IFACE:-eth0}"

# Verificar tshark
if ! command -v tshark &>/dev/null; then
    echo -e "${RED}[!] tshark no instalado. Ejecuta el modulo 66 de securizar.${NC}"
    exit 1
fi

# Verificar permisos
if [[ $EUID -ne 0 ]] && ! groups 2>/dev/null | grep -qw wireshark; then
    echo -e "${RED}[!] Necesitas ser root o pertenecer al grupo wireshark${NC}"
    exit 1
fi

# Mapear perfil a archivo de configuracion
PROFILE_FILE=""
case "$PERFIL" in
    general)       PROFILE_FILE="$PROFILE_DIR/captura-seguridad-general.conf" ;;
    inseguros)     PROFILE_FILE="$PROFILE_DIR/protocolos-inseguros.conf" ;;
    dns)           PROFILE_FILE="$PROFILE_DIR/analisis-dns.conf" ;;
    escaneos)      PROFILE_FILE="$PROFILE_DIR/deteccion-escaneos.conf" ;;
    lateral)       PROFILE_FILE="$PROFILE_DIR/trafico-lateral.conf" ;;
    exfiltracion)  PROFILE_FILE="$PROFILE_DIR/exfiltracion.conf" ;;
    *)
        echo -e "${RED}[!] Perfil desconocido: $PERFIL${NC}"
        echo "Perfiles disponibles: general, inseguros, dns, escaneos, lateral, exfiltracion"
        exit 1
        ;;
esac

# Cargar perfil
CAPTURE_FILTER=""
SNAP_LEN=0
DESCRIPTION=""
if [[ -f "$PROFILE_FILE" ]]; then
    while IFS='=' read -r key value; do
        key="${key%%#*}"
        key="${key// /}"
        [[ -z "$key" ]] && continue
        # Quitar comillas del valor
        value="${value#\"}"
        value="${value%\"}"
        value="${value#\'}"
        value="${value%\'}"
        case "$key" in
            CAPTURE_FILTER) CAPTURE_FILTER="$value" ;;
            SNAP_LEN)       SNAP_LEN="$value" ;;
            DESCRIPTION)    DESCRIPTION="$value" ;;
        esac
    done < "$PROFILE_FILE"
fi

# Nombre del archivo de captura
OUTPUT_FILE="$CAPTURE_DIR/auditoria-${PERFIL}-${IFACE}-${TIMESTAMP}.pcapng"

echo ""
echo -e "${CYAN}━━ Captura de auditoria de red ━━${NC}"
echo ""
echo -e "  Perfil:    ${GREEN}$PERFIL${NC}"
echo -e "  Interfaz:  ${GREEN}$IFACE${NC}"
echo -e "  Duracion:  ${GREEN}${DURACION}s${NC}"
echo -e "  Archivo:   ${GREEN}$OUTPUT_FILE${NC}"
[[ -n "$DESCRIPTION" ]] && echo -e "  Desc:      ${YELLOW}$DESCRIPTION${NC}"
[[ -n "$CAPTURE_FILTER" ]] && echo -e "  Filtro:    ${YELLOW}$CAPTURE_FILTER${NC}"
echo ""

# Construir comando tshark
TSHARK_CMD=(tshark -i "$IFACE" -w "$OUTPUT_FILE" -a "duration:$DURACION")

if [[ -n "$CAPTURE_FILTER" ]]; then
    TSHARK_CMD+=(-f "$CAPTURE_FILTER")
fi

if [[ "$SNAP_LEN" -gt 0 ]]; then
    TSHARK_CMD+=(-s "$SNAP_LEN")
fi

echo -e "${CYAN}[*] Iniciando captura...${NC}"
echo -e "${YELLOW}[*] Presiona Ctrl+C para detener antes de tiempo${NC}"
echo ""

"${TSHARK_CMD[@]}" 2>/dev/null || true

echo ""

# Estadisticas post-captura
if [[ -f "$OUTPUT_FILE" ]]; then
    local_size=$(du -h "$OUTPUT_FILE" 2>/dev/null | awk '{print $1}')
    echo -e "${GREEN}[+] Captura completada: $OUTPUT_FILE ($local_size)${NC}"

    if command -v capinfos &>/dev/null; then
        echo ""
        echo -e "${CYAN}━━ Estadisticas de captura ━━${NC}"
        capinfos -c -d -u -s "$OUTPUT_FILE" 2>/dev/null || true
    fi

    # Resumen rapido de protocolos
    echo ""
    echo -e "${CYAN}━━ Top 10 protocolos ━━${NC}"
    tshark -r "$OUTPUT_FILE" -q -z io,phs 2>/dev/null | head -30 || true

    # Permisos restrictivos
    chmod 640 "$OUTPUT_FILE" 2>/dev/null || true
    chgrp wireshark "$OUTPUT_FILE" 2>/dev/null || true
else
    echo -e "${RED}[!] No se genero archivo de captura${NC}"
fi
EOFCAP
    chmod 750 /usr/local/bin/auditoria-red-captura.sh
    log_info "Script de captura creado: /usr/local/bin/auditoria-red-captura.sh"
    log_change "Creado" "/usr/local/bin/auditoria-red-captura.sh"

    # Script de analisis rapido de una captura
    cat > /usr/local/bin/auditoria-red-analisis.sh << 'EOFANA'
#!/bin/bash
# ============================================================
# auditoria-red-analisis.sh - Analisis de seguridad de capturas
# ============================================================
# Uso: auditoria-red-analisis.sh <archivo.pcapng> [reporte_salida]
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

PCAP_FILE="${1:-}"
REPORT_DIR="/var/lib/securizar/reportes-red"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT_FILE="${2:-$REPORT_DIR/analisis-red-${TIMESTAMP}.txt}"

if [[ -z "$PCAP_FILE" ]]; then
    echo -e "${RED}Uso: $0 <archivo.pcapng> [reporte_salida]${NC}"
    echo ""
    echo "Archivos disponibles:"
    ls -lt /var/lib/securizar/capturas-red/*.pcapng 2>/dev/null | head -10 || echo "  (ninguno)"
    exit 1
fi

if [[ ! -f "$PCAP_FILE" ]]; then
    echo -e "${RED}[!] Archivo no encontrado: $PCAP_FILE${NC}"
    exit 1
fi

if ! command -v tshark &>/dev/null; then
    echo -e "${RED}[!] tshark no instalado${NC}"
    exit 1
fi

mkdir -p "$REPORT_DIR"

echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  ANALISIS DE SEGURIDAD DE CAPTURA DE RED${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  Archivo: ${GREEN}$PCAP_FILE${NC}"
echo -e "  Reporte: ${GREEN}$REPORT_FILE${NC}"
echo ""

{
echo "============================================================"
echo "REPORTE DE AUDITORIA DE RED"
echo "Fecha: $(date)"
echo "Archivo: $PCAP_FILE"
echo "============================================================"
echo ""

# 1. Informacion general
echo "--- INFORMACION GENERAL ---"
if command -v capinfos &>/dev/null; then
    capinfos "$PCAP_FILE" 2>/dev/null || true
fi
echo ""

# 2. Protocolos detectados
echo "--- JERARQUIA DE PROTOCOLOS ---"
tshark -r "$PCAP_FILE" -q -z io,phs 2>/dev/null || true
echo ""

# 3. Conversaciones IP (top 20)
echo "--- TOP 20 CONVERSACIONES IP ---"
tshark -r "$PCAP_FILE" -q -z conv,ip 2>/dev/null | head -25 || true
echo ""

# 4. Endpoints (top 20)
echo "--- TOP 20 ENDPOINTS ---"
tshark -r "$PCAP_FILE" -q -z endpoints,ip 2>/dev/null | head -25 || true
echo ""

# 5. Protocolos inseguros detectados
echo "--- PROTOCOLOS INSEGUROS DETECTADOS ---"
for proto_port in "21:FTP" "23:Telnet" "80:HTTP" "110:POP3" "143:IMAP" "25:SMTP" "161:SNMP" "69:TFTP" "513:rlogin" "514:rsh"; do
    port="${proto_port%%:*}"
    name="${proto_port##*:}"
    count=$(tshark -r "$PCAP_FILE" -Y "tcp.port == $port or udp.port == $port" 2>/dev/null | wc -l || echo "0")
    if [[ "$count" -gt 0 ]]; then
        echo "  [!] $name (puerto $port): $count paquetes"
    fi
done
echo ""

# 6. DNS sospechoso
echo "--- ANALISIS DNS ---"
echo "Consultas DNS unicas (top 30):"
tshark -r "$PCAP_FILE" -Y "dns.qry.name" -T fields -e dns.qry.name 2>/dev/null | sort | uniq -c | sort -rn | head -30 || true
echo ""
echo "Consultas DNS largas (posible tunneling, >50 chars):"
tshark -r "$PCAP_FILE" -Y "dns.qry.name.len > 50" -T fields -e dns.qry.name -e ip.src 2>/dev/null | head -20 || true
echo ""

# 7. Conexiones a puertos no estandar
echo "--- PUERTOS DE DESTINO INUSUALES (top 20) ---"
tshark -r "$PCAP_FILE" -Y "tcp" -T fields -e tcp.dstport 2>/dev/null | sort -n | uniq -c | sort -rn | head -20 || true
echo ""

# 8. User-Agents HTTP
echo "--- USER-AGENTS HTTP ---"
tshark -r "$PCAP_FILE" -Y "http.user_agent" -T fields -e http.user_agent 2>/dev/null | sort | uniq -c | sort -rn | head -20 || true
echo ""

# 9. Credenciales en texto plano
echo "--- POSIBLES CREDENCIALES EN TEXTO PLANO ---"
echo "FTP USER/PASS:"
tshark -r "$PCAP_FILE" -Y 'ftp.request.command == "USER" or ftp.request.command == "PASS"' -T fields -e ftp.request.command -e ftp.request.arg 2>/dev/null | head -10 || true
echo ""
echo "HTTP Authorization headers:"
tshark -r "$PCAP_FILE" -Y "http.authorization" -T fields -e ip.src -e http.host -e http.authorization 2>/dev/null | head -10 || true
echo ""

# 10. TCP RSTs y retransmisiones
echo "--- PROBLEMAS TCP ---"
rst_count=$(tshark -r "$PCAP_FILE" -Y "tcp.flags.reset == 1" 2>/dev/null | wc -l || echo "0")
retrans_count=$(tshark -r "$PCAP_FILE" -Y "tcp.analysis.retransmission" 2>/dev/null | wc -l || echo "0")
echo "  TCP RSTs: $rst_count"
echo "  Retransmisiones: $retrans_count"
echo ""

# 11. ARP anomalias
echo "--- ANOMALIAS ARP ---"
arp_count=$(tshark -r "$PCAP_FILE" -Y "arp" 2>/dev/null | wc -l || echo "0")
echo "  Paquetes ARP totales: $arp_count"
tshark -r "$PCAP_FILE" -Y "arp.duplicate-address-detected" -T fields -e arp.src.proto_ipv4 -e arp.src.hw_mac 2>/dev/null | head -10 || true
echo ""

# 12. TLS/SSL
echo "--- ANALISIS TLS ---"
echo "Versiones TLS detectadas:"
tshark -r "$PCAP_FILE" -Y "tls.handshake.type == 1" -T fields -e tls.handshake.version 2>/dev/null | sort | uniq -c | sort -rn | head -10 || true
echo ""
echo "SNI (Server Name Indication) - top 20:"
tshark -r "$PCAP_FILE" -Y "tls.handshake.extensions_server_name" -T fields -e tls.handshake.extensions_server_name 2>/dev/null | sort | uniq -c | sort -rn | head -20 || true
echo ""

echo "============================================================"
echo "FIN DEL REPORTE"
echo "============================================================"
} | tee "$REPORT_FILE"

chmod 640 "$REPORT_FILE" 2>/dev/null || true
echo ""
echo -e "${GREEN}[+] Reporte guardado en: $REPORT_FILE${NC}"
EOFANA
    chmod 750 /usr/local/bin/auditoria-red-analisis.sh
    log_info "Script de analisis creado: /usr/local/bin/auditoria-red-analisis.sh"
    log_change "Creado" "/usr/local/bin/auditoria-red-analisis.sh"

    # Wrapper simple para listar capturas
    cat > /usr/local/bin/auditoria-red-listar.sh << 'EOFLIST'
#!/bin/bash
# Lista capturas de red disponibles
CYAN='\033[0;36m'
GREEN='\033[0;32m'
DIM='\033[2m'
NC='\033[0m'
CAPTURE_DIR="/var/lib/securizar/capturas-red"

echo ""
echo -e "${CYAN}━━ Capturas de red disponibles ━━${NC}"
echo ""

if [[ -d "$CAPTURE_DIR" ]]; then
    shopt -s nullglob
    files=("$CAPTURE_DIR"/*.pcapng "$CAPTURE_DIR"/*.pcap)
    shopt -u nullglob
    if [[ ${#files[@]} -eq 0 ]]; then
        echo -e "  ${DIM}No hay capturas disponibles${NC}"
    else
        for f in "${files[@]}"; do
            size=$(du -h "$f" 2>/dev/null | awk '{print $1}')
            date_mod=$(stat -c '%y' "$f" 2>/dev/null | cut -d. -f1)
            echo -e "  ${GREEN}$(basename "$f")${NC}  ${DIM}($size, $date_mod)${NC}"
        done
    fi
else
    echo -e "  ${DIM}Directorio de capturas no existe${NC}"
fi
echo ""
EOFLIST
    chmod 750 /usr/local/bin/auditoria-red-listar.sh
    log_info "Script de listado creado: /usr/local/bin/auditoria-red-listar.sh"
    log_change "Creado" "/usr/local/bin/auditoria-red-listar.sh"
else
    log_info "Scripts de captura automatizada omitidos"
fi

fi

# ============================================================
# S6: ANALISIS DE PROTOCOLOS INSEGUROS
# ============================================================
if [[ "$AUDIT_SECTION" == "all" || "$AUDIT_SECTION" == "S6" ]]; then
log_section "S6: ANALISIS DE PROTOCOLOS INSEGUROS"

echo "Se realizara un analisis en tiempo real para detectar protocolos"
echo "inseguros (sin cifrar) activos en la red."
echo ""

if false; then
    : # S6 es deteccion en vivo, siempre re-evaluar
elif ask "¿Ejecutar analisis rapido de protocolos inseguros? (10 segundos)"; then
    if command -v tshark &>/dev/null; then
        echo ""
        echo -e "  ${CYAN}Capturando trafico durante 10 segundos...${NC}"

        TEMP_PCAP=$(mktemp /tmp/securizar-proto-XXXXXX.pcapng)

        # Captura corta para analisis
        tshark -i "$MAIN_IFACE" -a duration:10 \
            -f "port 21 or port 23 or port 80 or port 110 or port 143 or port 25 or port 161 or port 69" \
            -w "$TEMP_PCAP" 2>/dev/null || true

        if [[ -f "$TEMP_PCAP" ]] && [[ -s "$TEMP_PCAP" ]]; then
            INSECURE_COUNT=$(tshark -r "$TEMP_PCAP" 2>/dev/null | wc -l || echo "0")
            if [[ "$INSECURE_COUNT" -gt 0 ]]; then
                log_warn "Detectados $INSECURE_COUNT paquetes en protocolos inseguros"
                echo ""
                echo -e "  ${YELLOW}Desglose:${NC}"
                for proto_port in "21:FTP" "23:Telnet" "80:HTTP" "110:POP3" "143:IMAP" "25:SMTP" "161:SNMP" "69:TFTP"; do
                    port="${proto_port%%:*}"
                    name="${proto_port##*:}"
                    count=$(tshark -r "$TEMP_PCAP" -Y "tcp.port == $port or udp.port == $port" 2>/dev/null | wc -l || echo "0")
                    if [[ "$count" -gt 0 ]]; then
                        echo -e "    ${RED}[!]${NC} $name (puerto $port): $count paquetes"
                    fi
                done
            else
                log_info "No se detectaron protocolos inseguros activos"
            fi
        else
            log_info "No se capturo trafico inseguro (posiblemente red bien configurada)"
        fi

        rm -f "$TEMP_PCAP" 2>/dev/null || true
    else
        log_warn "tshark no disponible. Instala Wireshark primero (seccion S1)."
    fi
else
    log_info "Analisis de protocolos inseguros omitido"
fi

fi

# ============================================================
# S7: DETECCION DE ANOMALIAS DE RED
# ============================================================
if [[ "$AUDIT_SECTION" == "all" || "$AUDIT_SECTION" == "S7" ]]; then
log_section "S7: DETECCION DE ANOMALIAS DE RED"

echo "Se creara un script de deteccion de anomalias de red que puede"
echo "ejecutarse periodicamente como tarea cron."
echo ""

if check_executable /usr/local/bin/auditoria-red-anomalias.sh; then
    log_already "Deteccion de anomalias de red (auditoria-red-anomalias.sh existe)"
elif ask "¿Crear script de deteccion de anomalias de red?"; then

    cat > /usr/local/bin/auditoria-red-anomalias.sh << 'EOFANOM'
#!/bin/bash
# ============================================================
# auditoria-red-anomalias.sh - Deteccion de anomalias de red
# ============================================================
# Uso: auditoria-red-anomalias.sh [interfaz] [duracion_seg]
# Ejecutar como cron para monitorizacion continua
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

IFACE="${1:-$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)}"
DURACION="${2:-60}"
[[ -z "$IFACE" ]] && IFACE=$(ls /sys/class/net/ 2>/dev/null | grep -v lo | head -1)
IFACE="${IFACE:-eth0}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
ALERT_LOG="/var/log/securizar-red-anomalias.log"
TEMP_PCAP=$(mktemp /tmp/securizar-anomalias-XXXXXX.pcapng)
ALERTS=0

log_alert() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [ALERTA] $1"
    echo "$msg" >> "$ALERT_LOG"
    echo -e "  ${RED}[!]${NC} $1"
    ((ALERTS++)) || true
}

log_ok() {
    echo -e "  ${GREEN}[+]${NC} $1"
}

cleanup() {
    rm -f "$TEMP_PCAP" 2>/dev/null || true
}
trap cleanup EXIT

if ! command -v tshark &>/dev/null; then
    echo -e "${RED}[!] tshark requerido${NC}"
    exit 1
fi

echo ""
echo -e "${CYAN}━━ Deteccion de anomalias de red ━━${NC}"
echo -e "  Interfaz: $IFACE | Duracion: ${DURACION}s"
echo ""

# Captura
tshark -i "$IFACE" -a "duration:$DURACION" -w "$TEMP_PCAP" 2>/dev/null || true

if [[ ! -s "$TEMP_PCAP" ]]; then
    echo -e "${YELLOW}[*] Sin trafico capturado${NC}"
    exit 0
fi

TOTAL_PKTS=$(tshark -r "$TEMP_PCAP" 2>/dev/null | wc -l || echo "0")
echo -e "  Paquetes capturados: ${BOLD}$TOTAL_PKTS${NC}"
echo ""

# Check 1: ARP flooding
ARP_COUNT=$(tshark -r "$TEMP_PCAP" -Y "arp" 2>/dev/null | wc -l || echo "0")
if [[ "$ARP_COUNT" -gt 100 ]]; then
    log_alert "ARP flooding detectado: $ARP_COUNT paquetes ARP en ${DURACION}s"
else
    log_ok "ARP normal: $ARP_COUNT paquetes"
fi

# Check 2: ARP spoofing (IP duplicadas con MACs diferentes)
ARP_DUP=$(tshark -r "$TEMP_PCAP" -Y "arp.duplicate-address-detected" 2>/dev/null | wc -l || echo "0")
if [[ "$ARP_DUP" -gt 0 ]]; then
    log_alert "Posible ARP spoofing: $ARP_DUP direcciones duplicadas"
fi

# Check 3: Port scan (muchos SYN sin ACK desde misma IP)
SCAN_IPS=$(tshark -r "$TEMP_PCAP" -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" \
    -T fields -e ip.src 2>/dev/null | sort | uniq -c | sort -rn | \
    awk '$1 > 50 {print $2 " (" $1 " SYNs)"}' || true)
if [[ -n "$SCAN_IPS" ]]; then
    log_alert "Posible escaneo de puertos desde: $SCAN_IPS"
else
    log_ok "No se detectaron escaneos de puertos"
fi

# Check 4: DNS tunneling (consultas >50 chars)
DNS_TUNNEL=$(tshark -r "$TEMP_PCAP" -Y "dns.qry.name.len > 50" 2>/dev/null | wc -l || echo "0")
if [[ "$DNS_TUNNEL" -gt 5 ]]; then
    log_alert "Posible DNS tunneling: $DNS_TUNNEL consultas DNS largas"
else
    log_ok "DNS normal"
fi

# Check 5: Trafico a puertos sospechosos (TOR, C2 comunes)
SUSPICIOUS_PORTS=$(tshark -r "$TEMP_PCAP" \
    -Y "tcp.dstport == 4444 or tcp.dstport == 5555 or tcp.dstport == 1337 or tcp.dstport == 31337 or tcp.dstport == 9001" \
    2>/dev/null | wc -l || echo "0")
if [[ "$SUSPICIOUS_PORTS" -gt 0 ]]; then
    log_alert "Trafico a puertos sospechosos detectado: $SUSPICIOUS_PORTS paquetes"
else
    log_ok "Sin trafico a puertos sospechosos"
fi

# Check 6: ICMP excesivo (posible tunneling)
ICMP_COUNT=$(tshark -r "$TEMP_PCAP" -Y "icmp" 2>/dev/null | wc -l || echo "0")
if [[ "$ICMP_COUNT" -gt 200 ]]; then
    log_alert "ICMP excesivo: $ICMP_COUNT paquetes (posible tunneling)"
else
    log_ok "ICMP normal: $ICMP_COUNT paquetes"
fi

# Check 7: NBNS/LLMNR (vulnerables a poisoning)
NBNS_COUNT=$(tshark -r "$TEMP_PCAP" -Y "nbns or llmnr" 2>/dev/null | wc -l || echo "0")
if [[ "$NBNS_COUNT" -gt 0 ]]; then
    log_alert "NBNS/LLMNR activo: $NBNS_COUNT paquetes (vulnerable a poisoning)"
fi

# Check 8: Gratuitous ARP (posible spoofing)
GARP_COUNT=$(tshark -r "$TEMP_PCAP" -Y "arp.isgratuitous == 1" 2>/dev/null | wc -l || echo "0")
if [[ "$GARP_COUNT" -gt 5 ]]; then
    log_alert "Gratuitous ARP excesivo: $GARP_COUNT paquetes (posible ARP poisoning activo)"
else
    log_ok "Gratuitous ARP normal: $GARP_COUNT paquetes"
fi

# Check 9: DHCP starvation (exceso de DHCP Discover)
DHCP_DISCOVER=$(tshark -r "$TEMP_PCAP" -Y "dhcp.option.dhcp == 1" 2>/dev/null | wc -l || echo "0")
if [[ "$DHCP_DISCOVER" -gt 50 ]]; then
    log_alert "Posible DHCP starvation: $DHCP_DISCOVER Discover en ${DURACION}s"
else
    log_ok "DHCP Discover normal: $DHCP_DISCOVER"
fi

# Check 10: Rogue DHCP server (multiples servidores DHCP respondiendo)
DHCP_SERVERS=$(tshark -r "$TEMP_PCAP" -Y "dhcp.option.dhcp == 2" -T fields -e ip.src 2>/dev/null | sort -u | grep -c '[0-9]' || true)
if [[ "$DHCP_SERVERS" -gt 1 ]]; then
    DHCP_SRV_LIST=$(tshark -r "$TEMP_PCAP" -Y "dhcp.option.dhcp == 2" -T fields -e ip.src 2>/dev/null | sort -u | tr '\n' ' ')
    log_alert "Multiples servidores DHCP detectados ($DHCP_SERVERS): $DHCP_SRV_LIST (posible rogue DHCP)"
else
    log_ok "Servidores DHCP: $DHCP_SERVERS"
fi

# Check 11: LLMNR/mDNS responses (posible Responder/poisoner activo)
LLMNR_RESP=$(tshark -r "$TEMP_PCAP" -Y "llmnr and dns.flags.response == 1" 2>/dev/null | wc -l || echo "0")
MDNS_RESP=$(tshark -r "$TEMP_PCAP" -Y "mdns and dns.flags.response == 1" 2>/dev/null | wc -l || echo "0")
if [[ "$LLMNR_RESP" -gt 10 ]]; then
    LLMNR_SRC=$(tshark -r "$TEMP_PCAP" -Y "llmnr and dns.flags.response == 1" -T fields -e ip.src 2>/dev/null | sort | uniq -c | sort -rn | head -3)
    log_alert "LLMNR responses excesivas: $LLMNR_RESP (posible poisoner activo: $LLMNR_SRC)"
fi
if [[ "$MDNS_RESP" -gt 50 ]]; then
    log_alert "mDNS responses excesivas: $MDNS_RESP (posible mDNS poisoning)"
else
    log_ok "LLMNR/mDNS responses: LLMNR=$LLMNR_RESP, mDNS=$MDNS_RESP"
fi

# Check 12: Protocolos inseguros
for proto_port in "21:FTP" "23:Telnet" "110:POP3" "143:IMAP"; do
    port="${proto_port%%:*}"
    name="${proto_port##*:}"
    count=$(tshark -r "$TEMP_PCAP" -Y "tcp.port == $port" 2>/dev/null | wc -l || echo "0")
    if [[ "$count" -gt 0 ]]; then
        log_alert "Protocolo inseguro activo: $name ($count paquetes)"
    fi
done

# Check 13: Spotify Connect broadcast (UDP 57621 - descubrimiento)
SPOTIFY_COUNT=$(tshark -r "$TEMP_PCAP" -Y "udp.port == 57621" 2>/dev/null | wc -l || echo "0")
if [[ "$SPOTIFY_COUNT" -gt 0 ]]; then
    SPOTIFY_SRCS=$(tshark -r "$TEMP_PCAP" -Y "udp.port == 57621" -T fields -e ip.src 2>/dev/null | sort -u | tr '\n' ' ')
    log_alert "Spotify Connect broadcast: $SPOTIFY_COUNT paquetes desde: $SPOTIFY_SRCS (expone dispositivos en LAN)"
else
    log_ok "Sin Spotify Connect broadcasts"
fi

# Check 14: Google Cast / Chromecast (puertos 8008, 8009, 8443)
CAST_COUNT=$(tshark -r "$TEMP_PCAP" -Y "tcp.port == 8008 or tcp.port == 8009 or tcp.port == 8443" 2>/dev/null | wc -l || echo "0")
if [[ "$CAST_COUNT" -gt 0 ]]; then
    CAST_SRCS=$(tshark -r "$TEMP_PCAP" -Y "tcp.port == 8008 or tcp.port == 8009 or tcp.port == 8443" -T fields -e ip.src 2>/dev/null | sort -u | tr '\n' ' ')
    log_alert "Google Cast activo: $CAST_COUNT paquetes (dispositivos: $CAST_SRCS). API eureka_info expuesta sin auth en :8008"
else
    log_ok "Sin trafico Google Cast"
fi

# Check 15: SSDP/UPnP broadcast (239.255.255.250 / UDP 1900)
SSDP_COUNT=$(tshark -r "$TEMP_PCAP" -Y "udp.dstport == 1900 or ip.dst == 239.255.255.250" 2>/dev/null | wc -l || echo "0")
if [[ "$SSDP_COUNT" -gt 0 ]]; then
    SSDP_SRCS=$(tshark -r "$TEMP_PCAP" -Y "udp.dstport == 1900" -T fields -e ip.src 2>/dev/null | sort -u | tr '\n' ' ')
    log_alert "SSDP/UPnP broadcast: $SSDP_COUNT paquetes desde: $SSDP_SRCS (superficie de ataque IoT)"
else
    log_ok "Sin SSDP/UPnP broadcasts"
fi

# Check 16: DHCP device identification (detecta dispositivos por vendor/hostname)
DHCP_DEVICES=$(tshark -r "$TEMP_PCAP" -Y "dhcp" -T fields -e dhcp.option.hostname -e dhcp.option.vendor_class_id -e eth.src 2>/dev/null | sort -u | grep -v "^$" || true)
if [[ -n "$DHCP_DEVICES" ]]; then
    echo -e "  ${YELLOW}[i]${NC} Dispositivos detectados via DHCP:"
    while IFS=$'\t' read -r hostname vendor mac; do
        [[ -z "$hostname" && -z "$vendor" ]] && continue
        local eol_warn=""
        # Detectar dispositivos EOL por vendor class
        # Android: versiones <= 12 ya no reciben parches de seguridad regulares
        if echo "$vendor" | grep -qiP "android.*([0-9]|1[0-2])\." 2>/dev/null; then
            local _av
            _av=$(echo "$vendor" | grep -oP '[Aa]ndroid.*?(\d+)' | grep -oP '\d+$')
            [[ -n "$_av" && "$_av" -le 12 ]] && eol_warn=" [EOL - Android $_av sin parches]"
        fi
        # Huawei EMUI: versiones < 12 son EOL
        if echo "$vendor" | grep -qiP "EMUI.*(9|8|[0-7])\." 2>/dev/null; then
            eol_warn=" [EOL - EMUI antiguo sin parches]"
        fi
        # Windows: detectar versiones antiguas via DHCP vendor class
        if echo "$vendor" | grep -qi "MSFT 5\.0" 2>/dev/null; then
            eol_warn=" [EOL - Windows 2000/XP]"
        elif echo "$vendor" | grep -qi "MSFT 5\.0\|win.*xp\|win.*2003" 2>/dev/null; then
            eol_warn=" [EOL - Windows XP/2003]"
        fi
        # Dispositivos IoT genéricos (firmware antiguo)
        if echo "$hostname" | grep -qiP "^(ESP|Tasmota|Tuya|Sonoff|Shelly)" 2>/dev/null; then
            eol_warn="${eol_warn:+$eol_warn }[IoT - verificar firmware]"
        fi
        echo -e "      MAC=$mac Hostname=${hostname:--} Vendor=${vendor:--}${eol_warn}"
    done <<< "$DHCP_DEVICES"
fi

# Check 17: MAC randomization detection (LAA bit set = locally administered)
RANDOM_MACS=$(tshark -r "$TEMP_PCAP" -T fields -e eth.src 2>/dev/null | sort -u | while read -r mac; do
    [[ -z "$mac" ]] && continue
    # Bit 1 del primer octeto = locally administered (randomizado)
    first_octet=$((16#${mac%%:*}))
    if (( first_octet & 2 )); then
        echo "$mac"
    fi
done | sort -u || true)
if [[ -n "$RANDOM_MACS" ]]; then
    mac_count=$(echo "$RANDOM_MACS" | wc -l)
    echo -e "  ${YELLOW}[i]${NC} MACs randomizadas detectadas ($mac_count): dispositivos ocultan hardware MAC"
    echo "$RANDOM_MACS" | while read -r rmac; do
        echo -e "      $rmac (locally administered)"
    done
fi

# Check 18: SNMP exposure (UDP 161/162 - info del sistema expuesta)
SNMP_COUNT=$(tshark -r "$TEMP_PCAP" -Y "snmp" 2>/dev/null | wc -l || echo "0")
if [[ "$SNMP_COUNT" -gt 0 ]]; then
    SNMP_SRCS=$(tshark -r "$TEMP_PCAP" -Y "snmp" -T fields -e ip.src 2>/dev/null | sort -u | tr '\n' ' ')
    log_alert "SNMP expuesto: $SNMP_COUNT paquetes (dispositivos: $SNMP_SRCS). Puede filtrar info del sistema"
else
    log_ok "Sin trafico SNMP"
fi

# Check 19: Captive portal checks (revelan actividad de red al ISP)
CAPTIVE_COUNT=$(tshark -r "$TEMP_PCAP" -Y "dns.qry.name contains \"captive\" or dns.qry.name contains \"conncheck\" or dns.qry.name contains \"detectportal\" or dns.qry.name contains \"connectivity-check\" or dns.qry.name contains \"nmcheck\"" 2>/dev/null | wc -l || echo "0")
if [[ "$CAPTIVE_COUNT" -gt 0 ]]; then
    CAPTIVE_DOMAINS=$(tshark -r "$TEMP_PCAP" -Y "dns.qry.name contains \"captive\" or dns.qry.name contains \"conncheck\" or dns.qry.name contains \"detectportal\" or dns.qry.name contains \"connectivity-check\"" -T fields -e dns.qry.name 2>/dev/null | sort -u | tr '\n' ' ')
    log_alert "Captive portal checks detectados ($CAPTIVE_COUNT paquetes): $CAPTIVE_DOMAINS"
    echo "    -> Deshabilitar en NM: /etc/NetworkManager/conf.d/99-no-captive-portal.conf"
    echo "    -> Firefox: about:config -> network.captive-portal-service.enabled = false"
else
    log_ok "Sin captive portal checks"
fi

# Check 20: SNI plaintext (dominios visibles para el ISP en handshake TLS)
SNI_DOMAINS=$(tshark -r "$TEMP_PCAP" -Y "tls.handshake.type == 1" -T fields -e tls.handshake.extensions_server_name 2>/dev/null | sort | uniq -c | sort -rn | head -10)
if [[ -n "$SNI_DOMAINS" ]]; then
    SNI_COUNT=$(echo "$SNI_DOMAINS" | wc -l)
    echo -e "  ${YELLOW}[!] SNI plaintext: $SNI_COUNT dominios visibles para el ISP:${NC}"
    echo "$SNI_DOMAINS" | while read -r _cnt _domain; do
        [[ -z "$_domain" ]] && continue
        echo "      $_cnt conexiones -> $_domain"
    done
    echo "    -> Mitigar con ECH (Encrypted Client Hello) o VPN/Tor"
    ALERTS=$((ALERTS + 1))
else
    log_ok "Sin SNI plaintext detectado (o sin handshakes TLS en captura)"
fi

# Resumen
echo ""
echo -e "${CYAN}━━ Resumen ━━${NC}"
if [[ $ALERTS -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}Sin anomalias detectadas${NC}"
else
    echo -e "  ${RED}${BOLD}$ALERTS anomalias detectadas${NC}"
    echo -e "  Log completo: $ALERT_LOG"
fi
echo ""
EOFANOM
    chmod 750 /usr/local/bin/auditoria-red-anomalias.sh
    log_info "Script de anomalias creado: /usr/local/bin/auditoria-red-anomalias.sh"
    log_change "Creado" "/usr/local/bin/auditoria-red-anomalias.sh"

    # Tarea cron opcional
    if ask "¿Configurar cron diario para deteccion de anomalias?"; then
        cat > /etc/cron.d/securizar-auditoria-red << 'EOFCRON'
# Auditoria de red automatizada - securizar modulo 66
# Ejecuta deteccion de anomalias cada 6 horas (captura de 120 segundos)
0 */6 * * * root /usr/local/bin/auditoria-red-anomalias.sh "" 120 >/dev/null 2>&1
EOFCRON
        chmod 644 /etc/cron.d/securizar-auditoria-red
        log_info "Cron de anomalias configurado: cada 6 horas"
        log_change "Creado" "/etc/cron.d/securizar-auditoria-red"
    fi
else
    log_info "Script de anomalias omitido"
fi

fi

# ============================================================
# S8: EXPORTACION Y REPORTES DE AUDITORIA
# ============================================================
if [[ "$AUDIT_SECTION" == "all" || "$AUDIT_SECTION" == "S8" ]]; then
log_section "S8: EXPORTACION Y REPORTES"

echo "Se creara un script de generacion de reportes de auditoria"
echo "de red en formato texto y CSV."
echo ""

if check_executable /usr/local/bin/auditoria-red-reporte.sh; then
    log_already "Reportes de auditoria de red (auditoria-red-reporte.sh existe)"
elif ask "¿Crear script de reportes de auditoria de red?"; then

    cat > /usr/local/bin/auditoria-red-reporte.sh << 'EOFREP'
#!/bin/bash
# ============================================================
# auditoria-red-reporte.sh - Generacion de reportes de auditoria
# ============================================================
# Uso: auditoria-red-reporte.sh [captura.pcapng]
#      Sin argumento: genera reporte consolidado de todas las capturas
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

CAPTURE_DIR="/var/lib/securizar/capturas-red"
REPORT_DIR="/var/lib/securizar/reportes-red"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

mkdir -p "$REPORT_DIR"

if ! command -v tshark &>/dev/null; then
    echo -e "${RED}[!] tshark requerido${NC}"
    exit 1
fi

if [[ -n "${1:-}" ]] && [[ -f "$1" ]]; then
    # Reporte de una captura individual
    /usr/local/bin/auditoria-red-analisis.sh "$1" "$REPORT_DIR/reporte-${TIMESTAMP}.txt"
    exit 0
fi

# Reporte consolidado
REPORT="$REPORT_DIR/reporte-consolidado-${TIMESTAMP}.txt"

echo ""
echo -e "${CYAN}━━ Generando reporte consolidado de auditoria de red ━━${NC}"
echo ""

{
echo "============================================================"
echo "REPORTE CONSOLIDADO DE AUDITORIA DE RED"
echo "Fecha: $(date)"
echo "Host: $(hostname)"
echo "============================================================"
echo ""

# Listar capturas analizadas
echo "--- CAPTURAS DISPONIBLES ---"
shopt -s nullglob
files=("$CAPTURE_DIR"/*.pcapng "$CAPTURE_DIR"/*.pcap)
shopt -u nullglob

if [[ ${#files[@]} -eq 0 ]]; then
    echo "  No hay capturas disponibles"
else
    for f in "${files[@]}"; do
        size=$(du -h "$f" 2>/dev/null | awk '{print $1}')
        echo "  $(basename "$f") ($size)"
    done
fi
echo ""

# Estado de interfaces
echo "--- INTERFACES DE RED ---"
ip -br addr 2>/dev/null || ip addr show 2>/dev/null
echo ""

# Conexiones activas
echo "--- CONEXIONES ACTIVAS (LISTEN + ESTABLISHED) ---"
ss -tuanp 2>/dev/null | head -50 || netstat -tuanp 2>/dev/null | head -50 || true
echo ""

# Puertos en escucha
echo "--- PUERTOS EN ESCUCHA ---"
ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || true
echo ""

# Log de anomalias
echo "--- ULTIMAS ANOMALIAS DETECTADAS ---"
if [[ -f /var/log/securizar-red-anomalias.log ]]; then
    tail -50 /var/log/securizar-red-anomalias.log
else
    echo "  Sin log de anomalias"
fi
echo ""

# Resumen de cada captura
if [[ ${#files[@]} -gt 0 ]]; then
    echo "--- RESUMEN POR CAPTURA ---"
    for f in "${files[@]}"; do
        echo ""
        echo ">> $(basename "$f")"
        if command -v capinfos &>/dev/null; then
            capinfos -c -d -u "$f" 2>/dev/null || true
        fi
        echo "Protocolos:"
        tshark -r "$f" -q -z io,phs 2>/dev/null | head -15 || true
        echo ""
    done
fi

echo "============================================================"
echo "FIN DEL REPORTE CONSOLIDADO"
echo "============================================================"
} | tee "$REPORT"

chmod 640 "$REPORT" 2>/dev/null || true
echo ""
echo -e "${GREEN}[+] Reporte consolidado: $REPORT${NC}"
EOFREP
    chmod 750 /usr/local/bin/auditoria-red-reporte.sh
    log_info "Script de reportes creado: /usr/local/bin/auditoria-red-reporte.sh"
    log_change "Creado" "/usr/local/bin/auditoria-red-reporte.sh"

    # Exportar a CSV
    cat > /usr/local/bin/auditoria-red-csv.sh << 'EOFCSV'
#!/bin/bash
# ============================================================
# auditoria-red-csv.sh - Exportar captura a CSV para analisis
# ============================================================
# Uso: auditoria-red-csv.sh <archivo.pcapng> [campos]
# ============================================================

set -euo pipefail

PCAP="${1:-}"
FIELDS="${2:-frame.time,ip.src,ip.dst,tcp.srcport,tcp.dstport,udp.srcport,udp.dstport,frame.protocols,frame.len}"
REPORT_DIR="/var/lib/securizar/reportes-red"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

if [[ -z "$PCAP" ]] || [[ ! -f "$PCAP" ]]; then
    echo "Uso: $0 <archivo.pcapng> [campos_tshark]"
    echo "Campos por defecto: $FIELDS"
    exit 1
fi

if ! command -v tshark &>/dev/null; then
    echo "[!] tshark requerido"
    exit 1
fi

OUTPUT="$REPORT_DIR/export-$(basename "$PCAP" .pcapng)-${TIMESTAMP}.csv"
mkdir -p "$REPORT_DIR"

# Header
echo "$FIELDS" | tr ',' '\t' > "$OUTPUT"

# Data
tshark -r "$PCAP" -T fields $(echo "$FIELDS" | sed 's/,/ -e /g; s/^/-e /') -E separator=, -E quote=d 2>/dev/null >> "$OUTPUT" || true

chmod 640 "$OUTPUT" 2>/dev/null || true
echo "[+] CSV exportado: $OUTPUT ($(wc -l < "$OUTPUT") lineas)"
EOFCSV
    chmod 750 /usr/local/bin/auditoria-red-csv.sh
    log_info "Script CSV creado: /usr/local/bin/auditoria-red-csv.sh"
    log_change "Creado" "/usr/local/bin/auditoria-red-csv.sh"
else
    log_info "Scripts de reportes omitidos"
fi

fi

# ============================================================
# S9: INTEGRACION CON SURICATA/IDS
# ============================================================
if [[ "$AUDIT_SECTION" == "all" || "$AUDIT_SECTION" == "S9" ]]; then
log_section "S9: INTEGRACION CON SURICATA/IDS"

echo "Se configurara la integracion entre Wireshark/tshark y Suricata"
echo "para correlacionar capturas con alertas del IDS."
echo ""

if check_executable /usr/local/bin/auditoria-red-correlacion.sh; then
    log_already "Integracion con Suricata (auditoria-red-correlacion.sh existe)"
elif ask "¿Configurar integracion con Suricata?"; then
    if command -v suricata &>/dev/null; then
        log_info "Suricata detectado"

        # Script de correlacion
        cat > /usr/local/bin/auditoria-red-correlacion.sh << 'EOFCORR'
#!/bin/bash
# ============================================================
# auditoria-red-correlacion.sh - Correlacion Wireshark + Suricata
# ============================================================
# Uso: auditoria-red-correlacion.sh [captura.pcapng]
# Analiza una captura contra las reglas de Suricata
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PCAP="${1:-}"
REPORT_DIR="/var/lib/securizar/reportes-red"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

if [[ -z "$PCAP" ]] || [[ ! -f "$PCAP" ]]; then
    echo "Uso: $0 <archivo.pcapng>"
    exit 1
fi

echo ""
echo -e "${CYAN}━━ Correlacion Wireshark + Suricata ━━${NC}"
echo -e "  Captura: $PCAP"
echo ""

SURICATA_LOG_DIR=$(mktemp -d /tmp/securizar-suricata-XXXXXX)
REPORT="$REPORT_DIR/correlacion-${TIMESTAMP}.txt"

# Ejecutar Suricata contra la captura
if command -v suricata &>/dev/null; then
    echo -e "${CYAN}[*] Procesando captura con Suricata...${NC}"
    suricata -r "$PCAP" -l "$SURICATA_LOG_DIR" --set outputs.0.eve-log.filename=eve.json 2>/dev/null || true

    EVE_FILE="$SURICATA_LOG_DIR/eve.json"
    if [[ -f "$EVE_FILE" ]]; then
        ALERT_COUNT=$(grep -c '"event_type":"alert"' "$EVE_FILE" 2>/dev/null || echo "0")
        echo -e "  Alertas Suricata: ${BOLD}$ALERT_COUNT${NC}"

        {
        echo "============================================================"
        echo "CORRELACION WIRESHARK + SURICATA"
        echo "Fecha: $(date)"
        echo "Captura: $PCAP"
        echo "Alertas: $ALERT_COUNT"
        echo "============================================================"
        echo ""

        if [[ "$ALERT_COUNT" -gt 0 ]]; then
            echo "--- ALERTAS SURICATA ---"
            grep '"event_type":"alert"' "$EVE_FILE" 2>/dev/null | \
                python3 -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line)
        a = e.get('alert', {})
        print(f\"  [{a.get('severity','-')}] {a.get('signature','?')} | {e.get('src_ip','?')}:{e.get('src_port','?')} -> {e.get('dest_ip','?')}:{e.get('dest_port','?')}\")
    except: pass
" 2>/dev/null || grep '"event_type":"alert"' "$EVE_FILE"
        else
            echo "Sin alertas detectadas"
        fi
        echo ""
        echo "============================================================"
        } | tee "$REPORT"

        chmod 640 "$REPORT" 2>/dev/null || true
        echo ""
        echo -e "${GREEN}[+] Reporte: $REPORT${NC}"
    else
        echo -e "${YELLOW}[*] Suricata no genero eventos${NC}"
    fi

    rm -rf "$SURICATA_LOG_DIR" 2>/dev/null || true
else
    echo -e "${YELLOW}[*] Suricata no instalado. Ejecuta el modulo 14 primero.${NC}"
fi
EOFCORR
        chmod 750 /usr/local/bin/auditoria-red-correlacion.sh
        log_info "Script de correlacion creado: /usr/local/bin/auditoria-red-correlacion.sh"
        log_change "Creado" "/usr/local/bin/auditoria-red-correlacion.sh"
    else
        log_warn "Suricata no instalado. Ejecuta el modulo 14 (Red avanzada) primero."
        log_info "La integracion se puede configurar despues con el modulo 14."
    fi
else
    log_info "Integracion con Suricata omitida"
fi

fi

# ============================================================
# S10: POLITICA DE RETENCION Y ROTACION DE CAPTURAS
# ============================================================
if [[ "$AUDIT_SECTION" == "all" || "$AUDIT_SECTION" == "S10" ]]; then
log_section "S10: POLITICA DE RETENCION Y ROTACION"

echo "Se configurara la rotacion automatica de capturas de red"
echo "para evitar llenar el disco y cumplir con politicas de retencion."
echo ""

if check_file_exists /etc/securizar/auditoria-red-policy.conf; then
    log_already "Politica de retencion de capturas (auditoria-red-policy.conf existe)"
elif ask "¿Configurar politica de retencion de capturas?"; then

    # Script de rotacion
    cat > /usr/local/bin/auditoria-red-rotacion.sh << 'EOFROT'
#!/bin/bash
# ============================================================
# auditoria-red-rotacion.sh - Rotacion de capturas de red
# ============================================================
# Elimina capturas antiguas segun politica de retencion
# ============================================================

set -euo pipefail

CAPTURE_DIR="/var/lib/securizar/capturas-red"
REPORT_DIR="/var/lib/securizar/reportes-red"

# Politica: dias de retencion
CAPTURE_RETENTION_DAYS="${1:-30}"
REPORT_RETENTION_DAYS="${2:-90}"

# Espacio maximo en MB para capturas
MAX_CAPTURE_SIZE_MB="${3:-5000}"

echo "[*] Politica de retencion:"
echo "    Capturas: $CAPTURE_RETENTION_DAYS dias"
echo "    Reportes: $REPORT_RETENTION_DAYS dias"
echo "    Espacio max capturas: ${MAX_CAPTURE_SIZE_MB}MB"

# Rotar capturas por edad
if [[ -d "$CAPTURE_DIR" ]]; then
    OLD_CAPTURES=$(find "$CAPTURE_DIR" -name "*.pcapng" -o -name "*.pcap" -mtime +"$CAPTURE_RETENTION_DAYS" 2>/dev/null | wc -l || echo "0")
    if [[ "$OLD_CAPTURES" -gt 0 ]]; then
        find "$CAPTURE_DIR" -name "*.pcapng" -o -name "*.pcap" -mtime +"$CAPTURE_RETENTION_DAYS" -delete 2>/dev/null || true
        echo "[+] Eliminadas $OLD_CAPTURES capturas antiguas (>$CAPTURE_RETENTION_DAYS dias)"
    fi

    # Verificar espacio total
    CURRENT_SIZE_MB=$(du -sm "$CAPTURE_DIR" 2>/dev/null | awk '{print $1}' || echo "0")
    if [[ "$CURRENT_SIZE_MB" -gt "$MAX_CAPTURE_SIZE_MB" ]]; then
        echo "[!] Espacio de capturas ($CURRENT_SIZE_MB MB) excede limite (${MAX_CAPTURE_SIZE_MB}MB)"
        echo "[*] Eliminando capturas mas antiguas..."
        while [[ "$CURRENT_SIZE_MB" -gt "$MAX_CAPTURE_SIZE_MB" ]]; do
            OLDEST=$(ls -t "$CAPTURE_DIR"/*.pcapng "$CAPTURE_DIR"/*.pcap 2>/dev/null | tail -1)
            if [[ -n "$OLDEST" ]] && [[ -f "$OLDEST" ]]; then
                rm -f "$OLDEST"
                echo "    Eliminado: $(basename "$OLDEST")"
            else
                break
            fi
            CURRENT_SIZE_MB=$(du -sm "$CAPTURE_DIR" 2>/dev/null | awk '{print $1}' || echo "0")
        done
    fi
fi

# Rotar reportes por edad
if [[ -d "$REPORT_DIR" ]]; then
    OLD_REPORTS=$(find "$REPORT_DIR" -name "*.txt" -o -name "*.csv" -mtime +"$REPORT_RETENTION_DAYS" 2>/dev/null | wc -l || echo "0")
    if [[ "$OLD_REPORTS" -gt 0 ]]; then
        find "$REPORT_DIR" \( -name "*.txt" -o -name "*.csv" \) -mtime +"$REPORT_RETENTION_DAYS" -delete 2>/dev/null || true
        echo "[+] Eliminados $OLD_REPORTS reportes antiguos (>$REPORT_RETENTION_DAYS dias)"
    fi
fi

echo "[+] Rotacion completada"
EOFROT
    chmod 750 /usr/local/bin/auditoria-red-rotacion.sh
    log_info "Script de rotacion creado: /usr/local/bin/auditoria-red-rotacion.sh"
    log_change "Creado" "/usr/local/bin/auditoria-red-rotacion.sh"

    # Cron semanal de rotacion
    cat > /etc/cron.d/securizar-rotacion-capturas << 'EOFCRON'
# Rotacion semanal de capturas de red - securizar modulo 66
# Politica: capturas 30 dias, reportes 90 dias, max 5GB
0 3 * * 0 root /usr/local/bin/auditoria-red-rotacion.sh 30 90 5000 >/dev/null 2>&1
EOFCRON
    chmod 644 /etc/cron.d/securizar-rotacion-capturas
    log_info "Cron de rotacion configurado: domingos a las 3:00"
    log_change "Creado" "/etc/cron.d/securizar-rotacion-capturas"

    # Configuracion de politica
    cat > /etc/securizar/auditoria-red-policy.conf << 'EOFPOL'
# ============================================================
# Politica de auditoria de red - securizar modulo 66
# ============================================================

# Retencion de capturas (dias)
CAPTURE_RETENTION_DAYS=30

# Retencion de reportes (dias)
REPORT_RETENTION_DAYS=90

# Espacio maximo para capturas (MB)
MAX_CAPTURE_SIZE_MB=5000

# Interfaz de captura por defecto (vacio = autodetectar)
DEFAULT_INTERFACE=

# Duracion por defecto de capturas (segundos)
DEFAULT_CAPTURE_DURATION=300

# Perfiles habilitados para captura automatizada
ENABLED_PROFILES="general,inseguros,dns"

# Notificar anomalias por email (vacio = deshabilitado)
ALERT_EMAIL=

# Nivel de severidad minimo para alertas (1=bajo, 2=medio, 3=alto)
ALERT_MIN_SEVERITY=2
EOFPOL
    chmod 640 /etc/securizar/auditoria-red-policy.conf
    log_info "Politica de auditoria creada: /etc/securizar/auditoria-red-policy.conf"
    log_change "Creado" "/etc/securizar/auditoria-red-policy.conf"
else
    log_info "Politica de retencion omitida"
fi

fi

# ============================================================
# RESUMEN FINAL
# ============================================================
if [[ "$AUDIT_SECTION" == "all" ]]; then
log_section "RESUMEN DEL MODULO 66"

echo ""
echo -e "  ${BOLD}Herramientas de auditoria de red instaladas:${NC}"
echo ""

# Verificar estado final
for cmd in tshark wireshark dumpcap capinfos editcap tcpdump; do
    if command -v "$cmd" &>/dev/null; then
        echo -e "    ${GREEN}+${NC} $cmd: $(command -v "$cmd")"
    else
        echo -e "    ${YELLOW}-${NC} $cmd: no instalado"
    fi
done

echo ""
echo -e "  ${BOLD}Scripts creados:${NC}"
echo ""
for script in auditoria-red-captura auditoria-red-analisis auditoria-red-listar \
              auditoria-red-anomalias auditoria-red-reporte auditoria-red-csv \
              auditoria-red-correlacion auditoria-red-rotacion; do
    if [[ -x "/usr/local/bin/${script}.sh" ]]; then
        echo -e "    ${GREEN}+${NC} ${script}.sh"
    fi
done

echo ""
echo -e "  ${BOLD}Uso rapido:${NC}"
echo ""
echo -e "    ${CYAN}auditoria-red-captura.sh general${NC}      Captura general de 5 min"
echo -e "    ${CYAN}auditoria-red-captura.sh inseguros${NC}    Detectar protocolos inseguros"
echo -e "    ${CYAN}auditoria-red-captura.sh dns${NC}          Analizar trafico DNS"
echo -e "    ${CYAN}auditoria-red-analisis.sh <pcap>${NC}      Analizar una captura"
echo -e "    ${CYAN}auditoria-red-anomalias.sh${NC}            Deteccion de anomalias"
echo -e "    ${CYAN}auditoria-red-reporte.sh${NC}              Reporte consolidado"
echo -e "    ${CYAN}auditoria-red-listar.sh${NC}               Listar capturas"
echo ""

log_info "Modulo 66 completado"
fi
show_changes_summary
