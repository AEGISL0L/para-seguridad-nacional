#!/bin/bash
# ============================================================
# auditoria-red-infraestructura.sh - Modulo 67: Auditoria de Infraestructura de Red
# ============================================================
# Secciones:
#   S1  - Instalacion de herramientas de auditoria (nmap, testssl, nbtscan)
#   S2  - Descubrimiento y mapeado de red
#   S3  - Auditoria de puertos y servicios
#   S4  - Auditoria TLS/SSL (testssl.sh)
#   S5  - Auditoria de seguridad SNMP
#   S6  - Auditoria de configuracion de red (rutas, ARP, interfaces)
#   S7  - Inventario de servicios y control de versiones
#   S8  - Linea base de red y deteccion de drift
#   S9  - Automatizacion de auditorias periodicas
#   S10 - Puntuacion y reporte consolidado de auditoria
# ============================================================

set -euo pipefail

# Asegurar que /usr/local/bin esté en PATH (compilaciones desde fuente)
[[ ":$PATH:" == *":/usr/local/bin:"* ]] || export PATH="/usr/local/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps
init_backup "auditoria-red-infra"

# ── Pre-check: detectar secciones ya aplicadas ──────────────
_precheck 10
_pc 'check_executable /usr/bin/nmap || check_executable /usr/local/bin/nmap'
_pc 'check_executable /usr/local/bin/auditoria-red-descubrimiento.sh'
_pc 'check_executable /usr/local/bin/auditoria-red-puertos.sh'
_pc 'check_executable /usr/local/bin/auditoria-red-tls.sh'
_pc 'check_executable /usr/local/bin/auditoria-red-snmp.sh'
_pc 'check_executable /usr/local/bin/auditoria-red-config.sh'
_pc 'check_executable /usr/local/bin/auditoria-red-inventario.sh'
_pc 'check_executable /usr/local/bin/auditoria-red-baseline.sh'
_pc 'check_executable /usr/local/bin/auditoria-red-programada.sh'
_pc 'check_executable /usr/local/bin/auditoria-red-reporte-global.sh'
_precheck_result

log_section "MODULO 67: AUDITORIA DE INFRAESTRUCTURA DE RED"
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

# ── Directorios de trabajo ──────────────────────────────────
AUDIT_DIR="/var/lib/securizar/auditoria-red"
BASELINE_DIR="/var/lib/securizar/auditoria-red/baseline"
SCAN_DIR="/var/lib/securizar/auditoria-red/scans"
REPORT_DIR="/var/lib/securizar/auditoria-red/reportes"
CONF_DIR="/etc/securizar/auditoria-red"
TOOLS_DIR="/usr/local/bin"

mkdir -p "$AUDIT_DIR" "$BASELINE_DIR" "$SCAN_DIR" "$REPORT_DIR" "$CONF_DIR"
chmod 750 "$AUDIT_DIR" "$BASELINE_DIR" "$SCAN_DIR" "$REPORT_DIR"
chmod 750 "$CONF_DIR"

# ── Detectar interfaz y subred principal ────────────────────
detect_main_interface() {
    local iface
    iface=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
    if [[ -z "$iface" ]]; then
        iface=$(ip -o link show up 2>/dev/null | awk -F': ' '{print $2}' | grep -v lo | head -1)
    fi
    echo "${iface:-eth0}"
}

detect_main_subnet() {
    local iface="$1"
    ip -o -4 addr show "$iface" 2>/dev/null | awk '{print $4}' | head -1
}

MAIN_IFACE=$(detect_main_interface)
MAIN_SUBNET=$(detect_main_subnet "$MAIN_IFACE")
log_info "Interfaz principal: $MAIN_IFACE"
log_info "Subred principal: ${MAIN_SUBNET:-desconocida}"

# ── Sección selectiva ────────────────────────────────────────
AUDIT_SECTION="${1:-all}"

# ============================================================
# S1: INSTALACION DE HERRAMIENTAS DE AUDITORIA
# ============================================================
if [[ "$AUDIT_SECTION" == "all" || "$AUDIT_SECTION" == "S1" ]]; then
log_section "S1: INSTALACION DE HERRAMIENTAS DE AUDITORIA"

echo "Instala herramientas esenciales para auditoria de infraestructura de red:"
echo "  - nmap: escaner de puertos, servicios y OS fingerprinting"
echo "  - nbtscan: descubrimiento NetBIOS en la red local"
echo "  - testssl.sh: auditoria de configuracion TLS/SSL"
echo "  - arp-scan: descubrimiento L2 de hosts en la LAN"
echo "  - ncat/socat: utilidades de conexion para testing"
echo ""

if check_executable /usr/bin/nmap || check_executable /usr/local/bin/nmap; then
    log_already "Herramientas de auditoria de red (nmap ya instalado)"
elif ask "Instalar herramientas de auditoria de red?"; then

    # ── Helper: compilar desde fuente ──
    _build_from_source() {
        local name="$1" url="$2" configure_opts="${3:-}"
        local build_dir build_log rc=0
        build_dir=$(mktemp -d)
        build_log="${build_dir}/build.log"

        log_info "Descargando $name desde fuente..."
        if ! curl -fL --progress-bar "$url" -o "${build_dir}/src.tar.bz2" && \
           ! wget --progress=bar:force "$url" -O "${build_dir}/src.tar.bz2"; then
            log_warn "No se pudo descargar $name"
            rm -rf "$build_dir"
            return 1
        fi

        log_info "Descomprimiendo $name..."
        cd "$build_dir"
        tar xf src.tar.bz2 2>/dev/null || tar xzf src.tar.bz2 2>/dev/null || {
            log_warn "No se pudo descomprimir $name"
            cd /; rm -rf "$build_dir"; return 1
        }
        cd "${name}"* 2>/dev/null || cd "$(ls -d */ | head -1)" 2>/dev/null || {
            log_warn "No se encontró directorio de fuentes de $name"
            cd /; rm -rf "$build_dir"; return 1
        }

        # Evitar que make intente regenerar archivos autotools (timestamp mismatch)
        find . -name 'aclocal.m4' -o -name 'configure' -o -name 'Makefile.in' \
               -o -name 'config.h.in' | xargs touch 2>/dev/null || true

        log_info "Ejecutando configure..."
        ./configure $configure_opts >> "$build_log" 2>&1 || rc=$?
        if [[ $rc -ne 0 ]]; then
            log_warn "configure falló (rc=$rc). Últimas 15 líneas:"
            tail -15 "$build_log" 2>/dev/null
            cd /
            log_warn "Build dir conservado en: $build_dir"
            return 1
        fi

        local njobs
        njobs=$(nproc 2>/dev/null || echo 2)
        log_info "Compilando (make -j${njobs})... esto puede tardar unos minutos"
        make -j"$njobs" >> "$build_log" 2>&1 || rc=$?
        if [[ $rc -ne 0 ]]; then
            log_warn "make falló (rc=$rc). Últimas 20 líneas:"
            tail -20 "$build_log" 2>/dev/null
            cd /
            log_warn "Build dir conservado en: $build_dir"
            return 1
        fi

        log_info "Instalando (make install)..."
        make install >> "$build_log" 2>&1 || rc=$?
        if [[ $rc -ne 0 ]]; then
            log_warn "make install falló (rc=$rc). Últimas 20 líneas:"
            tail -20 "$build_log" 2>/dev/null
            cd /
            log_warn "Build dir conservado en: $build_dir"
            return 1
        fi

        cd /
        rm -rf "$build_dir"
        return 0
    }

    # ── nmap ──
    if command -v nmap &>/dev/null; then
        log_info "nmap ya instalado: $(nmap --version 2>/dev/null | head -1)"
    else
        log_info "Instalando nmap..."
        if ! pkg_install nmap 2>/dev/null; then
            log_info "nmap no en repos; compilando desde fuente..."
            # Instalar dependencias de compilacion
            case "$DISTRO_FAMILY" in
                suse)   pkg_install gcc-c++ make automake autoconf libpcap-devel libopenssl-devel 2>/dev/null || true ;;
                debian) pkg_install g++ make automake autoconf libpcap-dev libssl-dev 2>/dev/null || true ;;
                redhat) pkg_install gcc-c++ make automake autoconf libpcap-devel openssl-devel 2>/dev/null || true ;;
                arch)   pkg_install gcc make automake autoconf libpcap openssl 2>/dev/null || true ;;
            esac

            NMAP_VER="7.95"
            if _build_from_source "nmap" \
                "https://nmap.org/dist/nmap-${NMAP_VER}.tar.bz2" \
                "--without-zenmap --without-ndiff --without-nping"; then
                hash -r 2>/dev/null || true
                log_change "Compilado" "nmap ${NMAP_VER} desde fuente"
            else
                log_warn "No se pudo compilar nmap; instalar manualmente"
            fi
        fi
        hash -r 2>/dev/null || true
        if command -v nmap &>/dev/null; then
            log_change "Instalado" "nmap $(nmap --version 2>/dev/null | head -1)"
        fi
    fi

    # ── nbtscan ──
    if command -v nbtscan &>/dev/null; then
        log_info "nbtscan ya instalado"
    else
        log_info "Instalando nbtscan..."
        if ! pkg_install nbtscan 2>/dev/null; then
            log_info "nbtscan no en repos; compilando desde fuente..."
            nbtscan_dir=$(mktemp -d)
            nbtscan_ok=false
            NBTSCAN_URL="https://github.com/resurrecting-open-source-projects/nbtscan/archive/refs/tags/1.7.2.tar.gz"

            log_info "Descargando nbtscan 1.7.2..."
            if curl -fL --progress-bar "$NBTSCAN_URL" -o "${nbtscan_dir}/nbtscan.tar.gz" || \
               wget --progress=bar:force "$NBTSCAN_URL" -O "${nbtscan_dir}/nbtscan.tar.gz"; then

                # Verificar que la descarga no esté vacía
                if [[ -s "${nbtscan_dir}/nbtscan.tar.gz" ]]; then
                    cd "$nbtscan_dir"
                    tar xzf nbtscan.tar.gz
                    cd nbtscan-1.7.2 2>/dev/null || cd "$(ls -d */ | head -1)" 2>/dev/null

                    log_info "Generando configure (autogen.sh)..."
                    if [[ -f autogen.sh ]]; then
                        bash autogen.sh >> "${nbtscan_dir}/build.log" 2>&1 || true
                    fi

                    if [[ -f configure ]]; then
                        log_info "Ejecutando configure..."
                        ./configure >> "${nbtscan_dir}/build.log" 2>&1 || true
                    fi

                    log_info "Compilando nbtscan..."
                    if [[ -f Makefile ]] && make >> "${nbtscan_dir}/build.log" 2>&1; then
                        if [[ -f src/nbtscan ]]; then
                            cp -f src/nbtscan /usr/local/bin/nbtscan && chmod +x /usr/local/bin/nbtscan
                            nbtscan_ok=true
                        elif [[ -f nbtscan ]]; then
                            cp -f nbtscan /usr/local/bin/nbtscan && chmod +x /usr/local/bin/nbtscan
                            nbtscan_ok=true
                        fi
                    else
                        log_warn "make falló. Últimas 10 líneas:"
                        tail -10 "${nbtscan_dir}/build.log" 2>/dev/null
                    fi
                else
                    log_warn "Descarga vacía"
                fi
            else
                log_warn "No se pudo descargar nbtscan"
            fi

            cd /
            if $nbtscan_ok; then
                hash -r 2>/dev/null || true
                rm -rf "$nbtscan_dir"
                log_change "Compilado" "nbtscan 1.7.2 desde fuente"
            else
                log_warn "No se pudo compilar nbtscan. Build dir: $nbtscan_dir"
            fi
        fi
        hash -r 2>/dev/null || true
        if command -v nbtscan &>/dev/null; then
            log_change "Instalado" "nbtscan ($(nbtscan 2>&1 | head -1))"
        fi
    fi

    # ── arp-scan ──
    if command -v arp-scan &>/dev/null; then
        log_info "arp-scan ya instalado"
    else
        log_info "Instalando arp-scan..."
        pkg_install arp-scan || log_warn "arp-scan no disponible en repos"
        command -v arp-scan &>/dev/null && log_change "Instalado" "arp-scan"
    fi

    # ── testssl.sh ──
    if [[ -x /usr/local/bin/testssl.sh ]] || command -v testssl.sh &>/dev/null || command -v testssl &>/dev/null; then
        log_info "testssl.sh ya disponible"
    else
        log_info "Instalando testssl.sh..."
        TESTSSL_PKG_OK=false

        # Intentar desde paquete (nombre varia por distro)
        case "$DISTRO_FAMILY" in
            suse)   pkg_install testssl.sh 2>/dev/null && TESTSSL_PKG_OK=true || true ;;
            debian) pkg_install testssl.sh 2>/dev/null && TESTSSL_PKG_OK=true || true ;;
            redhat) pkg_install testssl  2>/dev/null && TESTSSL_PKG_OK=true || true ;;
            arch)   pkg_install testssl.sh 2>/dev/null && TESTSSL_PKG_OK=true || true ;;
        esac

        if ! $TESTSSL_PKG_OK; then
            # Instalar desde repositorio oficial via git
            if command -v git &>/dev/null; then
                TESTSSL_TMP=$(mktemp -d)
                if git clone --depth 1 https://github.com/drwetter/testssl.sh.git "$TESTSSL_TMP/testssl" 2>/dev/null; then
                    cp "$TESTSSL_TMP/testssl/testssl.sh" /usr/local/bin/testssl.sh
                    chmod +x /usr/local/bin/testssl.sh
                    mkdir -p /usr/local/share/testssl
                    cp -r "$TESTSSL_TMP/testssl/etc/" /usr/local/share/testssl/ 2>/dev/null || true
                    log_change "Instalado" "testssl.sh desde repositorio oficial"
                else
                    log_warn "No se pudo clonar testssl.sh; instalar manualmente"
                fi
                rm -rf "$TESTSSL_TMP"
            else
                log_warn "git no disponible; instalar testssl.sh manualmente"
            fi
        fi
    fi

    # ── socat (utilidad de testing) ──
    if ! command -v socat &>/dev/null; then
        pkg_install socat || log_warn "No se pudo instalar socat"
        command -v socat &>/dev/null && log_change "Instalado" "socat"
    fi

    # ── net-snmp-utils (para S5: auditoria SNMP) ──
    if ! command -v snmpget &>/dev/null; then
        case "$DISTRO_FAMILY" in
            suse)   pkg_install net-snmp 2>/dev/null || true ;;
            debian) pkg_install snmp 2>/dev/null || true ;;
            redhat) pkg_install net-snmp-utils 2>/dev/null || true ;;
            arch)   pkg_install net-snmp 2>/dev/null || true ;;
        esac
        command -v snmpget &>/dev/null && log_change "Instalado" "snmp-utils"
    fi

    log_info "Herramientas de auditoria verificadas"
else
    log_skip "Instalacion de herramientas de auditoria"
fi
fi # S1

# ============================================================
# S2: DESCUBRIMIENTO Y MAPEADO DE RED
# ============================================================
if [[ "$AUDIT_SECTION" == "all" || "$AUDIT_SECTION" == "S2" ]]; then
log_section "S2: DESCUBRIMIENTO Y MAPEADO DE RED"

echo "Crea scripts de descubrimiento y mapeado de la red:"
echo "  - Descubrimiento de hosts activos (ARP, ICMP, TCP)"
echo "  - Fingerprinting de sistemas operativos"
echo "  - Mapeado de topologia de red"
echo "  - Inventario de dispositivos por MAC vendor"
echo "  - Escaneo NetBIOS/SMB"
echo ""

if check_executable /usr/local/bin/auditoria-red-descubrimiento.sh; then
    log_already "Scripts de descubrimiento de red (auditoria-red-descubrimiento.sh existe)"
elif ask "Crear scripts de descubrimiento de red?"; then

    # ── Script principal de descubrimiento ──
    cat > "${TOOLS_DIR}/auditoria-red-descubrimiento.sh" << 'ENDSCRIPT'
#!/bin/bash
# auditoria-red-descubrimiento.sh - Descubrimiento y mapeado de red
# Uso: auditoria-red-descubrimiento.sh [subred] [--full|--quick|--stealth]
set -euo pipefail
[[ ":$PATH:" == *":/usr/local/bin:"* ]] || export PATH="/usr/local/bin:$PATH"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

SCAN_DIR="/var/lib/securizar/auditoria-red/scans"
mkdir -p "$SCAN_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# Detectar subred si no se especifica
detect_subnet() {
    local iface
    iface=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
    [[ -z "$iface" ]] && iface=$(ip -o link show up 2>/dev/null | awk -F': ' '{print $2}' | grep -v lo | head -1)
    ip -o -4 addr show "${iface:-eth0}" 2>/dev/null | awk '{print $4}' | head -1
}

SUBNET="${1:-$(detect_subnet)}"
MODE="${2:---full}"

if [[ -z "$SUBNET" ]]; then
    echo -e "${RED}Error: no se pudo detectar la subred. Especifique manualmente.${NC}"
    echo "Uso: $0 <subred/cidr> [--full|--quick|--stealth]"
    exit 1
fi

echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  DESCUBRIMIENTO DE RED: $SUBNET${NC}"
echo -e "${BOLD}  Modo: ${MODE}  |  $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
echo ""

OUTFILE="${SCAN_DIR}/discovery-${TIMESTAMP}"

# Fase 1: Descubrimiento ARP (L2 - solo red local)
echo -e "${CYAN}[1/5] Descubrimiento ARP (capa 2)...${NC}"
if command -v arp-scan &>/dev/null; then
    arp-scan --localnet --interface="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)" 2>/dev/null | tee "${OUTFILE}-arp.txt" || true
    echo ""
fi

# Fase 2: Descubrimiento nmap (multi-tecnica)
echo -e "${CYAN}[2/5] Descubrimiento de hosts activos (nmap)...${NC}"
if ! command -v nmap &>/dev/null; then
    echo -e "${RED}nmap no instalado. Ejecute primero S1 del modulo.${NC}"
    exit 1
fi

case "$MODE" in
    --quick)
        nmap -sn -T4 --max-retries 1 "$SUBNET" -oA "${OUTFILE}-hosts" 2>/dev/null
        ;;
    --stealth)
        nmap -sn -PE -PP -PM -T2 "$SUBNET" -oA "${OUTFILE}-hosts" 2>/dev/null
        ;;
    --full|*)
        nmap -sn -PE -PP -PM -PS22,80,443,445 -PA80,443 -T3 "$SUBNET" -oA "${OUTFILE}-hosts" 2>/dev/null
        ;;
esac

# Extraer lista de hosts vivos
LIVE_HOSTS="${OUTFILE}-live.txt"
grep "Host:" "${OUTFILE}-hosts.gnmap" 2>/dev/null | grep "Status: Up" | awk '{print $2}' | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n > "$LIVE_HOSTS"
TOTAL_HOSTS=$(wc -l < "$LIVE_HOSTS")
echo -e "${GREEN}Hosts activos encontrados: $TOTAL_HOSTS${NC}"
echo ""

# Fase 3: Fingerprinting de OS (solo en modo full)
if [[ "$MODE" == "--full" ]] && [[ $TOTAL_HOSTS -gt 0 ]] && [[ $TOTAL_HOSTS -le 256 ]]; then
    echo -e "${CYAN}[3/5] Fingerprinting de sistemas operativos...${NC}"
    nmap -O --osscan-guess -T3 -iL "$LIVE_HOSTS" -oA "${OUTFILE}-os" 2>/dev/null || true
    echo ""
else
    echo -e "${YELLOW}[3/5] Fingerprinting de OS omitido (modo: $MODE, hosts: $TOTAL_HOSTS)${NC}"
fi

# Fase 4: NetBIOS/SMB
echo -e "${CYAN}[4/5] Escaneo NetBIOS/SMB...${NC}"
if command -v nbtscan &>/dev/null && [[ $TOTAL_HOSTS -gt 0 ]]; then
    nbtscan -r "$SUBNET" 2>/dev/null | tee "${OUTFILE}-netbios.txt" || true
    echo ""
else
    echo -e "${YELLOW}[4/5] nbtscan no disponible o sin hosts${NC}"
fi

# Fase 5: Inventario consolidado con MAC vendor
echo -e "${CYAN}[5/5] Generando inventario consolidado...${NC}"
{
    echo "# Inventario de Red - $SUBNET - $(date '+%Y-%m-%d %H:%M:%S')"
    echo "# Modo: $MODE | Hosts activos: $TOTAL_HOSTS"
    echo "#"
    echo "# IP | MAC | Vendor | Hostname | OS (estimado)"
    echo "# ─────────────────────────────────────────────────"
    if [[ -f "${OUTFILE}-hosts.xml" ]]; then
        # Parsear XML de nmap para extraer info consolidada
        local_ip=""
        while IFS= read -r ip; do
            mac=$(grep -A5 "addr=\"$ip\"" "${OUTFILE}-hosts.xml" 2>/dev/null | grep 'addrtype="mac"' | sed 's/.*addr="\([^"]*\)".*/\1/' | head -1)
            vendor=$(grep -A5 "addr=\"$ip\"" "${OUTFILE}-hosts.xml" 2>/dev/null | grep 'addrtype="mac"' | sed 's/.*vendor="\([^"]*\)".*/\1/' | head -1)
            hostname=$(grep -B2 "addr=\"$ip\"" "${OUTFILE}-hosts.xml" 2>/dev/null | grep 'hostname' | sed 's/.*name="\([^"]*\)".*/\1/' | head -1)
            os_guess=""
            if [[ -f "${OUTFILE}-os.xml" ]]; then
                os_guess=$(grep -A20 "addr=\"$ip\"" "${OUTFILE}-os.xml" 2>/dev/null | grep 'osmatch name' | head -1 | sed 's/.*name="\([^"]*\)".*/\1/')
            fi
            echo "$ip | ${mac:--} | ${vendor:--} | ${hostname:--} | ${os_guess:--}"
        done < "$LIVE_HOSTS"
    fi
} > "${OUTFILE}-inventario.txt"

echo -e "${GREEN}Inventario generado: ${OUTFILE}-inventario.txt${NC}"
echo ""

# Resumen
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  RESUMEN DE DESCUBRIMIENTO${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "  Subred escaneada: ${CYAN}$SUBNET${NC}"
echo -e "  Hosts activos:    ${GREEN}$TOTAL_HOSTS${NC}"
echo -e "  Archivos:"
for f in "${OUTFILE}"-*.txt "${OUTFILE}"-*.xml "${OUTFILE}"-*.gnmap; do
    [[ -f "$f" ]] && echo -e "    ${GREEN}+${NC} $f"
done
echo ""
echo -e "  Para auditar puertos: ${CYAN}auditoria-red-puertos.sh $SUBNET${NC}"
ENDSCRIPT
    chmod +x "${TOOLS_DIR}/auditoria-red-descubrimiento.sh"
    log_change "Creado" "${TOOLS_DIR}/auditoria-red-descubrimiento.sh"

    log_info "Script de descubrimiento de red creado"
else
    log_skip "Scripts de descubrimiento de red"
fi
fi # S2

# ============================================================
# S3: AUDITORIA DE PUERTOS Y SERVICIOS
# ============================================================
if [[ "$AUDIT_SECTION" == "all" || "$AUDIT_SECTION" == "S3" ]]; then
log_section "S3: AUDITORIA DE PUERTOS Y SERVICIOS"

echo "Crea scripts de auditoria de puertos y servicios:"
echo "  - Escaneo de puertos TCP/UDP con deteccion de version"
echo "  - Comparacion con linea base de puertos autorizados"
echo "  - Deteccion de servicios no autorizados"
echo "  - Banners y fingerprinting de servicios"
echo "  - Reporte de puertos peligrosos (FTP, Telnet, RDP, etc.)"
echo ""

if check_executable /usr/local/bin/auditoria-red-puertos.sh; then
    log_already "Scripts de auditoria de puertos (auditoria-red-puertos.sh existe)"
elif ask "Crear scripts de auditoria de puertos y servicios?"; then

    # ── Politica de puertos autorizados ──
    if [[ ! -f "${CONF_DIR}/puertos-autorizados.conf" ]]; then
        cat > "${CONF_DIR}/puertos-autorizados.conf" << 'EOFCONF'
# Politica de puertos autorizados
# Formato: puerto/protocolo  servicio  estado  comentario
# estado: autorizado | monitorizado | prohibido
#
# Puertos comunes autorizados (ajustar segun entorno)
22/tcp      ssh         autorizado      Acceso remoto seguro
80/tcp      http        monitorizado    Redirigir a HTTPS si es posible
443/tcp     https       autorizado      Trafico web cifrado
53/tcp      dns         autorizado      Resolucion DNS
53/udp      dns         autorizado      Resolucion DNS
123/udp     ntp         autorizado      Sincronizacion horaria

# Puertos tipicamente prohibidos en servidores
21/tcp      ftp         prohibido       Protocolo inseguro sin cifrado
23/tcp      telnet      prohibido       Protocolo inseguro sin cifrado
25/tcp      smtp        monitorizado    Solo si es servidor de correo
69/udp      tftp        prohibido       Sin autenticacion
110/tcp     pop3        prohibido       Usar POP3S (995)
143/tcp     imap        prohibido       Usar IMAPS (993)
161/udp     snmp        monitorizado    Solo SNMPv3
445/tcp     smb         monitorizado    Solo si es necesario
3306/tcp    mysql       monitorizado    No exponer externamente
3389/tcp    rdp         prohibido       No exponer en Linux
5432/tcp    postgresql  monitorizado    No exponer externamente
6379/tcp    redis       prohibido       Sin autenticacion por defecto
27017/tcp   mongodb     prohibido       Sin autenticacion por defecto
EOFCONF
        chmod 640 "${CONF_DIR}/puertos-autorizados.conf"
        log_change "Creado" "${CONF_DIR}/puertos-autorizados.conf"
    else
        log_info "Politica de puertos ya existe: ${CONF_DIR}/puertos-autorizados.conf"
    fi

    # ── Script de auditoria de puertos ──
    cat > "${TOOLS_DIR}/auditoria-red-puertos.sh" << 'ENDSCRIPT'
#!/bin/bash
# auditoria-red-puertos.sh - Auditoria de puertos y servicios
# Uso: auditoria-red-puertos.sh [target] [--top1000|--full|--custom <ports>]
set -euo pipefail
[[ ":$PATH:" == *":/usr/local/bin:"* ]] || export PATH="/usr/local/bin:$PATH"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

SCAN_DIR="/var/lib/securizar/auditoria-red/scans"
CONF_DIR="/etc/securizar/auditoria-red"
POLICY="${CONF_DIR}/puertos-autorizados.conf"
mkdir -p "$SCAN_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

TARGET="${1:-localhost}"
SCAN_MODE="${2:---top1000}"
CUSTOM_PORTS="${3:-}"

echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  AUDITORIA DE PUERTOS Y SERVICIOS${NC}"
echo -e "${BOLD}  Objetivo: $TARGET  |  Modo: $SCAN_MODE${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
echo ""

OUTFILE="${SCAN_DIR}/ports-${TARGET//\//-}-${TIMESTAMP}"

if ! command -v nmap &>/dev/null; then
    echo -e "${RED}Error: nmap no instalado${NC}"
    exit 1
fi

# Fase 1: Escaneo TCP
echo -e "${CYAN}[1/4] Escaneo TCP con deteccion de version...${NC}"
case "$SCAN_MODE" in
    --full)
        nmap -sS -sV -p- --open -T3 -O --version-intensity 5 "$TARGET" -oA "${OUTFILE}-tcp" 2>/dev/null
        ;;
    --custom)
        if [[ -z "$CUSTOM_PORTS" ]]; then
            echo -e "${RED}Error: especifique puertos con --custom <puertos>${NC}"
            exit 1
        fi
        nmap -sS -sV -p "$CUSTOM_PORTS" --open -T3 "$TARGET" -oA "${OUTFILE}-tcp" 2>/dev/null
        ;;
    --top1000|*)
        nmap -sS -sV --top-ports 1000 --open -T3 "$TARGET" -oA "${OUTFILE}-tcp" 2>/dev/null
        ;;
esac
echo ""

# Fase 2: Escaneo UDP (top 100 puertos mas comunes)
echo -e "${CYAN}[2/4] Escaneo UDP (top 100)...${NC}"
nmap -sU --top-ports 100 --open -T3 "$TARGET" -oA "${OUTFILE}-udp" 2>/dev/null || true
echo ""

# Fase 3: Comparar con politica de puertos autorizados
echo -e "${CYAN}[3/4] Comparacion con politica de puertos autorizados...${NC}"
VIOLATIONS=0
WARNINGS=0
{
    echo "# Auditoria de puertos - $TARGET - $(date '+%Y-%m-%d %H:%M:%S')"
    echo "# ─────────────────────────────────────────────────"
    echo ""
    echo "## Puertos abiertos detectados:"
    echo ""

    # Parsear puertos abiertos del gnmap
    for gnmap_file in "${OUTFILE}"-tcp.gnmap "${OUTFILE}"-udp.gnmap; do
        [[ -f "$gnmap_file" ]] || continue
        grep "Ports:" "$gnmap_file" 2>/dev/null | while IFS= read -r line; do
            # Extraer puertos del formato gnmap
            echo "$line" | tr ',' '\n' | grep -oP '\d+/open/[^/]*/[^/]*/[^/]*' | while IFS='/' read -r port state proto _ service _rest; do
                status="desconocido"
                policy_status=""

                if [[ -f "$POLICY" ]]; then
                    policy_line=$(grep -E "^${port}/${proto}" "$POLICY" 2>/dev/null | head -1)
                    if [[ -n "$policy_line" ]]; then
                        policy_status=$(echo "$policy_line" | awk '{print $3}')
                    fi
                fi

                case "$policy_status" in
                    autorizado)
                        echo -e "  ${GREEN}[OK]${NC}    ${port}/${proto} (${service}) - Autorizado"
                        ;;
                    monitorizado)
                        echo -e "  ${YELLOW}[WARN]${NC}  ${port}/${proto} (${service}) - Monitorizado"
                        ((WARNINGS++)) || true
                        ;;
                    prohibido)
                        echo -e "  ${RED}[FAIL]${NC}  ${port}/${proto} (${service}) - PROHIBIDO"
                        ((VIOLATIONS++)) || true
                        ;;
                    *)
                        echo -e "  ${YELLOW}[????]${NC}  ${port}/${proto} (${service}) - Sin politica definida"
                        ((WARNINGS++)) || true
                        ;;
                esac
            done
        done
    done

    echo ""
    echo "## Resumen de cumplimiento:"
    echo "  Violaciones: $VIOLATIONS"
    echo "  Advertencias: $WARNINGS"

} | tee "${OUTFILE}-auditoria.txt"
echo ""

# Fase 4: Deteccion de servicios peligrosos
echo -e "${CYAN}[4/4] Deteccion de servicios potencialmente peligrosos...${NC}"
{
    echo ""
    echo "## Servicios peligrosos detectados:"
    echo ""
    DANGEROUS=0

    for gnmap_file in "${OUTFILE}"-tcp.gnmap "${OUTFILE}"-udp.gnmap; do
        [[ -f "$gnmap_file" ]] || continue

        # FTP sin TLS
        if grep -qi "21/open" "$gnmap_file" 2>/dev/null; then
            echo -e "  ${RED}[!]${NC} FTP (21/tcp) - Texto plano, credenciales expuestas"
            ((DANGEROUS++)) || true
        fi
        # Telnet
        if grep -qi "23/open" "$gnmap_file" 2>/dev/null; then
            echo -e "  ${RED}[!]${NC} Telnet (23/tcp) - Sin cifrado, reemplazar por SSH"
            ((DANGEROUS++)) || true
        fi
        # SNMP v1/v2
        if grep -qi "161/open" "$gnmap_file" 2>/dev/null; then
            echo -e "  ${YELLOW}[!]${NC} SNMP (161/udp) - Verificar que sea SNMPv3"
            ((DANGEROUS++)) || true
        fi
        # Redis sin auth
        if grep -qi "6379/open" "$gnmap_file" 2>/dev/null; then
            echo -e "  ${RED}[!]${NC} Redis (6379/tcp) - Sin autenticacion por defecto"
            ((DANGEROUS++)) || true
        fi
        # MongoDB sin auth
        if grep -qi "27017/open" "$gnmap_file" 2>/dev/null; then
            echo -e "  ${RED}[!]${NC} MongoDB (27017/tcp) - Sin autenticacion por defecto"
            ((DANGEROUS++)) || true
        fi
        # RDP
        if grep -qi "3389/open" "$gnmap_file" 2>/dev/null; then
            echo -e "  ${RED}[!]${NC} RDP (3389/tcp) - No deberia estar en Linux"
            ((DANGEROUS++)) || true
        fi
        # HTTP sin HTTPS
        if grep -qi "80/open" "$gnmap_file" 2>/dev/null; then
            echo -e "  ${YELLOW}[!]${NC} HTTP (80/tcp) - Verificar redireccion a HTTPS"
            ((DANGEROUS++)) || true
        fi
    done

    if [[ $DANGEROUS -eq 0 ]]; then
        echo -e "  ${GREEN}Ningun servicio peligroso detectado${NC}"
    fi
} | tee -a "${OUTFILE}-auditoria.txt"

echo ""
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  RESUMEN${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "  Resultados: ${CYAN}${OUTFILE}-auditoria.txt${NC}"
echo -e "  nmap TCP:   ${CYAN}${OUTFILE}-tcp.xml${NC}"
echo -e "  nmap UDP:   ${CYAN}${OUTFILE}-udp.xml${NC}"
echo ""
ENDSCRIPT
    chmod +x "${TOOLS_DIR}/auditoria-red-puertos.sh"
    log_change "Creado" "${TOOLS_DIR}/auditoria-red-puertos.sh"

    log_info "Script de auditoria de puertos creado"
else
    log_skip "Scripts de auditoria de puertos"
fi
fi # S3

# ============================================================
# S4: AUDITORIA TLS/SSL (testssl.sh)
# ============================================================
if [[ "$AUDIT_SECTION" == "all" || "$AUDIT_SECTION" == "S4" ]]; then
log_section "S4: AUDITORIA TLS/SSL"

echo "Crea scripts de auditoria TLS/SSL para servicios de red:"
echo "  - Verificacion de certificados (caducidad, cadena, CN/SAN)"
echo "  - Evaluacion de cipher suites (debiles, obsoletos)"
echo "  - Deteccion de vulnerabilidades (POODLE, BEAST, Heartbleed, ROBOT)"
echo "  - Verificacion de protocolos (SSLv2, SSLv3, TLS 1.0/1.1 -> prohibidos)"
echo "  - Auditoria masiva de multiples endpoints"
echo "  - Politica de cumplimiento TLS"
echo ""

if check_executable /usr/local/bin/auditoria-red-tls.sh; then
    log_already "Scripts de auditoria TLS/SSL (auditoria-red-tls.sh existe)"
elif ask "Crear scripts de auditoria TLS/SSL?"; then

    # ── Politica TLS ──
    if [[ ! -f "${CONF_DIR}/politica-tls.conf" ]]; then
        cat > "${CONF_DIR}/politica-tls.conf" << 'EOFCONF'
# Politica de seguridad TLS/SSL
# Referencia: Mozilla Modern / NIST SP 800-52r2

# Protocolos permitidos
TLS_MIN_VERSION=1.2
TLS_PREFERRED_VERSION=1.3

# Protocolos prohibidos
PROHIBIDO_SSLv2=true
PROHIBIDO_SSLv3=true
PROHIBIDO_TLS10=true
PROHIBIDO_TLS11=true

# Cipher suites minimas aceptables (TLS 1.2)
# Rechazar: RC4, DES, 3DES, MD5, export, NULL, anon
CIPHER_BLACKLIST="RC4|DES|3DES|MD5|EXPORT|NULL|anon|SEED|IDEA|CAMELLIA"

# Certificados
CERT_MIN_KEY_BITS_RSA=2048
CERT_MIN_KEY_BITS_EC=256
CERT_MAX_VALIDITY_DAYS=398
CERT_WARN_EXPIRY_DAYS=30

# HSTS
REQUIRE_HSTS=true
HSTS_MIN_AGE=31536000

# Vulnerabilidades criticas (deben estar ausentes)
CHECK_HEARTBLEED=true
CHECK_CCS_INJECTION=true
CHECK_POODLE=true
CHECK_ROBOT=true
CHECK_BEAST=true
CHECK_CRIME=true
CHECK_BREACH=true
CHECK_TICKETBLEED=true
CHECK_LUCKY13=true
CHECK_RENEGOTIATION=true
EOFCONF
        chmod 640 "${CONF_DIR}/politica-tls.conf"
        log_change "Creado" "${CONF_DIR}/politica-tls.conf"
    fi

    # ── Script de auditoria TLS ──
    cat > "${TOOLS_DIR}/auditoria-red-tls.sh" << 'ENDSCRIPT'
#!/bin/bash
# auditoria-red-tls.sh - Auditoria TLS/SSL de endpoints
# Uso: auditoria-red-tls.sh <host[:puerto]> [--full|--quick|--cert-only]
#      auditoria-red-tls.sh --batch <archivo_endpoints>
set -euo pipefail
[[ ":$PATH:" == *":/usr/local/bin:"* ]] || export PATH="/usr/local/bin:$PATH"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

REPORT_DIR="/var/lib/securizar/auditoria-red/reportes"
CONF_DIR="/etc/securizar/auditoria-red"
POLICY="${CONF_DIR}/politica-tls.conf"
mkdir -p "$REPORT_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# Cargar politica
TLS_MIN_VERSION="1.2"
CERT_WARN_EXPIRY_DAYS=30
CERT_MAX_VALIDITY_DAYS=398
CERT_MIN_KEY_BITS_RSA=2048
[[ -f "$POLICY" ]] && source "$POLICY"

audit_single_host() {
    local TARGET="$1"
    local MODE="${2:---full}"
    local HOST PORT

    # Separar host:puerto
    if [[ "$TARGET" == *:* ]]; then
        HOST="${TARGET%%:*}"
        PORT="${TARGET##*:}"
    else
        HOST="$TARGET"
        PORT=443
    fi

    local OUTFILE="${REPORT_DIR}/tls-${HOST}-${PORT}-${TIMESTAMP}"
    local SCORE=100
    local ISSUES=0

    echo -e "${BOLD}── Auditando: ${HOST}:${PORT} ──${NC}"
    echo ""

    # 1. Verificar conectividad
    if ! timeout 5 bash -c "echo | openssl s_client -connect ${HOST}:${PORT} 2>/dev/null" | grep -q "BEGIN CERTIFICATE"; then
        echo -e "${RED}  No se pudo establecer conexion TLS con ${HOST}:${PORT}${NC}"
        return 1
    fi

    # 2. Informacion del certificado
    echo -e "${CYAN}  [Certificado]${NC}"
    local CERT_INFO
    CERT_INFO=$(echo | openssl s_client -connect "${HOST}:${PORT}" -servername "$HOST" 2>/dev/null || true)
    local CERT_PEM
    CERT_PEM=$(echo "$CERT_INFO" | openssl x509 2>/dev/null || true)

    if [[ -n "$CERT_PEM" ]]; then
        local SUBJECT ISSUER NOT_AFTER NOT_BEFORE KEY_TYPE KEY_BITS SAN
        SUBJECT=$(echo "$CERT_PEM" | openssl x509 -noout -subject 2>/dev/null | sed 's/subject=//' || true)
        ISSUER=$(echo "$CERT_PEM" | openssl x509 -noout -issuer 2>/dev/null | sed 's/issuer=//' || true)
        NOT_AFTER=$(echo "$CERT_PEM" | openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//' || true)
        NOT_BEFORE=$(echo "$CERT_PEM" | openssl x509 -noout -startdate 2>/dev/null | sed 's/notBefore=//' || true)
        KEY_TYPE=$(echo "$CERT_PEM" | openssl x509 -noout -text 2>/dev/null | grep "Public Key Algorithm" | awk '{print $NF}' || true)
        KEY_BITS=$(echo "$CERT_PEM" | openssl x509 -noout -text 2>/dev/null | grep "Public-Key:" | grep -oP '\d+' || true)
        SAN=$(echo "$CERT_PEM" | openssl x509 -noout -ext subjectAltName 2>/dev/null | grep -v "Subject Alternative" | tr -d ' ' || true)

        echo -e "    Subject:  $SUBJECT"
        echo -e "    Issuer:   $ISSUER"
        echo -e "    Valido:   $NOT_BEFORE -> $NOT_AFTER"
        echo -e "    Clave:    $KEY_TYPE ($KEY_BITS bits)"
        [[ -n "$SAN" ]] && echo -e "    SAN:      $SAN"

        # Verificar caducidad
        local EXPIRY_EPOCH
        EXPIRY_EPOCH=$(date -d "$NOT_AFTER" +%s 2>/dev/null || echo 0)
        local NOW_EPOCH
        NOW_EPOCH=$(date +%s)
        local DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

        if [[ $DAYS_LEFT -lt 0 ]]; then
            echo -e "    ${RED}[FAIL] Certificado CADUCADO hace $((DAYS_LEFT * -1)) dias${NC}"
            SCORE=$((SCORE - 40))
            ((ISSUES++)) || true
        elif [[ $DAYS_LEFT -lt $CERT_WARN_EXPIRY_DAYS ]]; then
            echo -e "    ${YELLOW}[WARN] Caduca en $DAYS_LEFT dias${NC}"
            SCORE=$((SCORE - 10))
            ((ISSUES++)) || true
        else
            echo -e "    ${GREEN}[OK] Caduca en $DAYS_LEFT dias${NC}"
        fi

        # Verificar tamano de clave
        if [[ "$KEY_TYPE" == *rsa* ]] && [[ ${KEY_BITS:-0} -lt $CERT_MIN_KEY_BITS_RSA ]]; then
            echo -e "    ${RED}[FAIL] Clave RSA demasiado corta: ${KEY_BITS} < ${CERT_MIN_KEY_BITS_RSA}${NC}"
            SCORE=$((SCORE - 20))
            ((ISSUES++)) || true
        fi

        # Verificar cadena de confianza
        local VERIFY_RESULT
        VERIFY_RESULT=$(echo | openssl s_client -connect "${HOST}:${PORT}" -servername "$HOST" 2>&1 | grep "Verify return code:" || true)
        if echo "$VERIFY_RESULT" | grep -q "0 (ok)"; then
            echo -e "    ${GREEN}[OK] Cadena de confianza valida${NC}"
        else
            echo -e "    ${RED}[FAIL] Cadena de confianza: $VERIFY_RESULT${NC}"
            SCORE=$((SCORE - 25))
            ((ISSUES++)) || true
        fi
    fi
    echo ""

    # 3. Protocolos soportados
    echo -e "${CYAN}  [Protocolos]${NC}"
    for proto in ssl2 ssl3 tls1 tls1_1 tls1_2 tls1_3; do
        local PROTO_RESULT
        PROTO_RESULT=$(echo | timeout 5 openssl s_client -connect "${HOST}:${PORT}" -servername "$HOST" -"${proto}" 2>&1 || true)
        local PROTO_NAME
        case "$proto" in
            ssl2)   PROTO_NAME="SSLv2"   ;;
            ssl3)   PROTO_NAME="SSLv3"   ;;
            tls1)   PROTO_NAME="TLS 1.0" ;;
            tls1_1) PROTO_NAME="TLS 1.1" ;;
            tls1_2) PROTO_NAME="TLS 1.2" ;;
            tls1_3) PROTO_NAME="TLS 1.3" ;;
        esac

        if echo "$PROTO_RESULT" | grep -q "BEGIN CERTIFICATE\|Protocol.*:.*${proto}"; then
            case "$proto" in
                ssl2|ssl3|tls1|tls1_1)
                    echo -e "    ${RED}[FAIL] ${PROTO_NAME}: HABILITADO (deberia estar deshabilitado)${NC}"
                    SCORE=$((SCORE - 15))
                    ((ISSUES++)) || true
                    ;;
                tls1_2|tls1_3)
                    echo -e "    ${GREEN}[OK]   ${PROTO_NAME}: habilitado${NC}"
                    ;;
            esac
        else
            case "$proto" in
                ssl2|ssl3|tls1|tls1_1)
                    echo -e "    ${GREEN}[OK]   ${PROTO_NAME}: deshabilitado${NC}"
                    ;;
                tls1_2)
                    echo -e "    ${YELLOW}[WARN] ${PROTO_NAME}: no disponible${NC}"
                    ;;
                tls1_3)
                    echo -e "    ${YELLOW}[INFO] ${PROTO_NAME}: no disponible${NC}"
                    ;;
            esac
        fi
    done
    echo ""

    # 4. testssl.sh (si disponible y modo full)
    if [[ "$MODE" == "--full" ]]; then
        local TESTSSL_BIN=""
        for candidate in testssl.sh testssl /usr/local/bin/testssl.sh; do
            if command -v "$candidate" &>/dev/null; then
                TESTSSL_BIN="$candidate"
                break
            fi
        done

        if [[ -n "$TESTSSL_BIN" ]]; then
            echo -e "${CYAN}  [testssl.sh - Auditoria profunda]${NC}"
            "$TESTSSL_BIN" --quiet --color 0 --csvfile "${OUTFILE}-testssl.csv" \
                --jsonfile "${OUTFILE}-testssl.json" \
                "${HOST}:${PORT}" 2>/dev/null | while IFS= read -r line; do
                echo "    $line"
            done
            echo ""
        fi
    fi

    # 5. Puntuacion
    [[ $SCORE -lt 0 ]] && SCORE=0
    local GRADE
    if [[ $SCORE -ge 90 ]]; then
        GRADE="${GREEN}A${NC}"
    elif [[ $SCORE -ge 80 ]]; then
        GRADE="${GREEN}B${NC}"
    elif [[ $SCORE -ge 60 ]]; then
        GRADE="${YELLOW}C${NC}"
    elif [[ $SCORE -ge 40 ]]; then
        GRADE="${RED}D${NC}"
    else
        GRADE="${RED}F${NC}"
    fi

    echo -e "  ${BOLD}Puntuacion: ${SCORE}/100 (Grado: ${GRADE}${BOLD})  |  Problemas: ${ISSUES}${NC}"
    echo ""

    # Guardar reporte
    {
        echo "Auditoria TLS/SSL - ${HOST}:${PORT} - $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Puntuacion: ${SCORE}/100 | Problemas: ${ISSUES}"
    } > "${OUTFILE}-summary.txt"
}

# ── Main ──
if [[ "${1:-}" == "--batch" ]]; then
    BATCH_FILE="${2:-}"
    if [[ -z "$BATCH_FILE" ]] || [[ ! -f "$BATCH_FILE" ]]; then
        echo -e "${RED}Error: archivo de endpoints no encontrado${NC}"
        echo "Uso: $0 --batch <archivo>"
        echo "Formato: un endpoint por linea (host:puerto)"
        exit 1
    fi
    echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  AUDITORIA TLS MASIVA${NC}"
    echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
    echo ""
    while IFS= read -r endpoint; do
        [[ -z "$endpoint" ]] && continue
        [[ "$endpoint" == \#* ]] && continue
        audit_single_host "$endpoint" "--quick" || true
    done < "$BATCH_FILE"
elif [[ -n "${1:-}" ]]; then
    echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  AUDITORIA TLS/SSL${NC}"
    echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
    echo ""
    audit_single_host "$1" "${2:---full}"
else
    echo "Uso: $0 <host[:puerto]> [--full|--quick|--cert-only]"
    echo "      $0 --batch <archivo_endpoints>"
    echo ""
    echo "Ejemplos:"
    echo "  $0 example.com                 Auditoria completa del puerto 443"
    echo "  $0 mail.example.com:993        Auditar IMAPS"
    echo "  $0 example.com --quick         Solo certificado y protocolos"
    echo "  $0 --batch endpoints.txt       Auditar multiples endpoints"
    exit 0
fi
ENDSCRIPT
    chmod +x "${TOOLS_DIR}/auditoria-red-tls.sh"
    log_change "Creado" "${TOOLS_DIR}/auditoria-red-tls.sh"

    log_info "Script de auditoria TLS/SSL creado"
else
    log_skip "Scripts de auditoria TLS/SSL"
fi
fi # S4

# ============================================================
# S5: AUDITORIA DE SEGURIDAD SNMP
# ============================================================
if [[ "$AUDIT_SECTION" == "all" || "$AUDIT_SECTION" == "S5" ]]; then
log_section "S5: AUDITORIA DE SEGURIDAD SNMP"

echo "Audita la seguridad del protocolo SNMP en la red:"
echo "  - Deteccion de agentes SNMP activos"
echo "  - Verificacion de community strings por defecto (public/private)"
echo "  - Identificacion de SNMPv1/v2c (inseguros) vs SNMPv3"
echo "  - Enumeracion de informacion expuesta via SNMP"
echo "  - Recomendaciones de hardening SNMP"
echo ""

if check_executable /usr/local/bin/auditoria-red-snmp.sh; then
    log_already "Scripts de auditoria SNMP (auditoria-red-snmp.sh existe)"
elif ask "Crear scripts de auditoria SNMP?"; then

    cat > "${TOOLS_DIR}/auditoria-red-snmp.sh" << 'ENDSCRIPT'
#!/bin/bash
# auditoria-red-snmp.sh - Auditoria de seguridad SNMP
# Uso: auditoria-red-snmp.sh [target/subred]
set -euo pipefail
[[ ":$PATH:" == *":/usr/local/bin:"* ]] || export PATH="/usr/local/bin:$PATH"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

SCAN_DIR="/var/lib/securizar/auditoria-red/scans"
mkdir -p "$SCAN_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
    # Detectar subred local
    local_iface=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
    TARGET=$(ip -o -4 addr show "${local_iface:-eth0}" 2>/dev/null | awk '{print $4}' | head -1)
fi

if [[ -z "$TARGET" ]]; then
    echo -e "${RED}Error: especifique un objetivo (IP, rango o subred CIDR)${NC}"
    exit 1
fi

OUTFILE="${SCAN_DIR}/snmp-${TARGET//\//-}-${TIMESTAMP}"

echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  AUDITORIA DE SEGURIDAD SNMP${NC}"
echo -e "${BOLD}  Objetivo: $TARGET  |  $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
echo ""

ISSUES=0
CRITICAL=0

# Fase 1: Descubrimiento de agentes SNMP
echo -e "${CYAN}[1/4] Descubrimiento de agentes SNMP (161/udp)...${NC}"
if command -v nmap &>/dev/null; then
    nmap -sU -p 161 --open -T3 "$TARGET" -oG "${OUTFILE}-discovery.gnmap" 2>/dev/null
    SNMP_HOSTS=$(grep "161/open" "${OUTFILE}-discovery.gnmap" 2>/dev/null | awk '{print $2}' | sort -u)
    SNMP_COUNT=$(echo "$SNMP_HOSTS" | grep -c . 2>/dev/null || echo 0)
    echo -e "${GREEN}  Agentes SNMP detectados: $SNMP_COUNT${NC}"
else
    echo -e "${RED}  nmap no disponible; no se puede escanear${NC}"
    SNMP_HOSTS=""
    SNMP_COUNT=0
fi
echo ""

if [[ $SNMP_COUNT -eq 0 ]]; then
    echo -e "${GREEN}  No se detectaron agentes SNMP expuestos${NC}"
    echo ""
    echo "Resultado: PASS - Sin SNMP expuesto" > "${OUTFILE}-resultado.txt"
    exit 0
fi

# Fase 2: Test de community strings por defecto
echo -e "${CYAN}[2/4] Verificacion de community strings por defecto...${NC}"
DEFAULT_COMMUNITIES=("public" "private" "community" "admin" "manager" "snmpd" "default" "test" "monitor" "read" "write" "ILMI")

{
    echo "# Auditoria SNMP - $TARGET - $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""
    echo "## Community strings por defecto:"
    echo ""

    for host in $SNMP_HOSTS; do
        echo "  Host: $host"
        for comm in "${DEFAULT_COMMUNITIES[@]}"; do
            if command -v snmpget &>/dev/null; then
                RESULT=$(timeout 3 snmpget -v2c -c "$comm" "$host" 1.3.6.1.2.1.1.1.0 2>&1 || true)
                if echo "$RESULT" | grep -qv "Timeout\|No Response\|Error\|Unknown"; then
                    echo -e "    ${RED}[CRITICO] Community string '$comm' FUNCIONA${NC}"
                    echo "    Respuesta: $(echo "$RESULT" | head -1)"
                    ((CRITICAL++)) || true
                    ((ISSUES++)) || true
                fi
            elif command -v nmap &>/dev/null; then
                RESULT=$(nmap -sU -p 161 --script snmp-brute --script-args "snmp-brute.communitiesdb=-,snmplist=$comm" "$host" 2>/dev/null || true)
                if echo "$RESULT" | grep -qi "Valid credentials"; then
                    echo -e "    ${RED}[CRITICO] Community string '$comm' FUNCIONA${NC}"
                    ((CRITICAL++)) || true
                    ((ISSUES++)) || true
                fi
            fi
        done
        echo ""
    done
} | tee "${OUTFILE}-communities.txt"
echo ""

# Fase 3: Deteccion de version SNMP
echo -e "${CYAN}[3/4] Deteccion de versiones SNMP...${NC}"
{
    echo ""
    echo "## Versiones SNMP detectadas:"
    echo ""

    for host in $SNMP_HOSTS; do
        echo "  Host: $host"

        # Test SNMPv1
        if command -v snmpget &>/dev/null; then
            V1_RESULT=$(timeout 3 snmpget -v1 -c public "$host" 1.3.6.1.2.1.1.1.0 2>&1 || true)
            if echo "$V1_RESULT" | grep -qv "Timeout\|No Response\|Error"; then
                echo -e "    ${RED}[FAIL] SNMPv1 acepta conexiones (sin cifrado ni autenticacion)${NC}"
                ((ISSUES++)) || true
            fi

            V2_RESULT=$(timeout 3 snmpget -v2c -c public "$host" 1.3.6.1.2.1.1.1.0 2>&1 || true)
            if echo "$V2_RESULT" | grep -qv "Timeout\|No Response\|Error"; then
                echo -e "    ${YELLOW}[WARN] SNMPv2c acepta conexiones (sin cifrado)${NC}"
                ((ISSUES++)) || true
            fi
        fi

        # Test con nmap script
        if command -v nmap &>/dev/null; then
            nmap -sU -p 161 --script snmp-info "$host" 2>/dev/null | grep -E "enterprise|engineID|snmpEngineBoots" | while IFS= read -r line; do
                echo "    Info: $line"
            done
        fi
        echo ""
    done
} | tee -a "${OUTFILE}-communities.txt"
echo ""

# Fase 4: Enumeracion de informacion expuesta
echo -e "${CYAN}[4/4] Enumeracion de informacion expuesta...${NC}"
{
    echo ""
    echo "## Informacion expuesta via SNMP:"
    echo ""

    for host in $SNMP_HOSTS; do
        echo "  Host: $host"
        if command -v snmpwalk &>/dev/null; then
            # Intentar con community "public"
            WALK_RESULT=$(timeout 10 snmpwalk -v2c -c public "$host" 1.3.6.1.2.1.1 2>&1 || true)
            if echo "$WALK_RESULT" | grep -qv "Timeout\|No Response\|Error"; then
                echo "    [!] Informacion del sistema accesible con 'public':"
                echo "$WALK_RESULT" | head -10 | while IFS= read -r line; do
                    echo "      $line"
                done
                TOTAL_OIDS=$(echo "$WALK_RESULT" | wc -l)
                echo "      ... ($TOTAL_OIDS OIDs accesibles en system tree)"
                ((ISSUES++)) || true
            fi
        elif command -v nmap &>/dev/null; then
            nmap -sU -p 161 --script snmp-sysdescr "$host" 2>/dev/null | grep -A5 "snmp-sysdescr" | while IFS= read -r line; do
                echo "    $line"
            done
        fi
        echo ""
    done
} | tee -a "${OUTFILE}-communities.txt"

echo ""
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  RESUMEN SNMP${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "  Agentes SNMP: ${CYAN}$SNMP_COUNT${NC}"
echo -e "  Problemas criticos: ${RED}$CRITICAL${NC}"
echo -e "  Problemas totales: ${YELLOW}$ISSUES${NC}"
echo ""
echo -e "  ${BOLD}Recomendaciones:${NC}"
echo -e "    1. Migrar a SNMPv3 con autenticacion (authPriv)"
echo -e "    2. Cambiar community strings por defecto"
echo -e "    3. Restringir acceso SNMP por IP (ACLs)"
echo -e "    4. Deshabilitar SNMP si no es necesario"
echo -e "    5. Limitar OIDs accesibles (views)"
echo ""
echo -e "  Reporte: ${CYAN}${OUTFILE}-communities.txt${NC}"
ENDSCRIPT
    chmod +x "${TOOLS_DIR}/auditoria-red-snmp.sh"
    log_change "Creado" "${TOOLS_DIR}/auditoria-red-snmp.sh"

    log_info "Script de auditoria SNMP creado"
else
    log_skip "Scripts de auditoria SNMP"
fi
fi # S5

# ============================================================
# S6: AUDITORIA DE CONFIGURACION DE RED
# ============================================================
if [[ "$AUDIT_SECTION" == "all" || "$AUDIT_SECTION" == "S6" ]]; then
log_section "S6: AUDITORIA DE CONFIGURACION DE RED"

echo "Audita la configuracion de red del sistema:"
echo "  - Interfaces de red y estado"
echo "  - Tabla de rutas (rutas sospechosas, default gateways)"
echo "  - Tabla ARP (detectar anomalias, duplicados)"
echo "  - Parametros sysctl de red (IP forwarding, source routing)"
echo "  - Resolucion DNS configurada"
echo "  - Reglas de firewall activas"
echo ""

if check_executable /usr/local/bin/auditoria-red-config.sh; then
    log_already "Scripts de auditoria de configuracion de red (auditoria-red-config.sh existe)"
elif ask "Crear scripts de auditoria de configuracion de red?"; then

    cat > "${TOOLS_DIR}/auditoria-red-config.sh" << 'ENDSCRIPT'
#!/bin/bash
# auditoria-red-config.sh - Auditoria de configuracion de red del sistema
# Uso: auditoria-red-config.sh [--full|--quick]
set -euo pipefail
[[ ":$PATH:" == *":/usr/local/bin:"* ]] || export PATH="/usr/local/bin:$PATH"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

REPORT_DIR="/var/lib/securizar/auditoria-red/reportes"
mkdir -p "$REPORT_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
MODE="${1:---full}"
OUTFILE="${REPORT_DIR}/config-${TIMESTAMP}.txt"

SCORE=100
ISSUES=0

echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  AUDITORIA DE CONFIGURACION DE RED${NC}"
echo -e "${BOLD}  Host: $(hostname)  |  $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
echo ""

{
    echo "# Auditoria de configuracion de red - $(hostname)"
    echo "# Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "# ─────────────────────────────────────────────────"
    echo ""

    # ── 1. Interfaces de red ──
    echo -e "${CYAN}[1/7] Interfaces de red${NC}"
    echo "## 1. Interfaces de red"
    echo ""
    ip -br addr show 2>/dev/null | while IFS= read -r line; do
        iface=$(echo "$line" | awk '{print $1}')
        state=$(echo "$line" | awk '{print $2}')
        addrs=$(echo "$line" | awk '{$1=$2=""; print $0}' | xargs)

        if [[ "$state" == "UP" ]]; then
            echo -e "    ${GREEN}[UP]${NC}   $iface: $addrs"
        elif [[ "$state" == "DOWN" ]]; then
            echo -e "    ${YELLOW}[DOWN]${NC} $iface: $addrs"
        else
            echo -e "    [${state}] $iface: $addrs"
        fi
        echo "  $state  $iface  $addrs"
    done
    echo ""

    # Verificar modo promiscuo
    PROMISC_IFACES=$(ip link show 2>/dev/null | grep -i "PROMISC" | awk -F': ' '{print $2}' || true)
    if [[ -n "$PROMISC_IFACES" ]]; then
        echo -e "    ${RED}[WARN] Interfaces en modo promiscuo: $PROMISC_IFACES${NC}"
        echo "  [WARN] Interfaces en modo promiscuo: $PROMISC_IFACES"
        SCORE=$((SCORE - 5))
        ((ISSUES++)) || true
    fi
    echo ""

    # ── 2. Tabla de rutas ──
    echo -e "${CYAN}[2/7] Tabla de rutas${NC}"
    echo "## 2. Tabla de rutas"
    echo ""
    ip route show 2>/dev/null | while IFS= read -r line; do
        echo "  $line"
        echo -e "    $line"
    done
    echo ""

    # Detectar multiples default gateways
    DGW_COUNT=$(ip route show default 2>/dev/null | wc -l)
    if [[ $DGW_COUNT -gt 1 ]]; then
        echo -e "    ${YELLOW}[WARN] Multiples default gateways ($DGW_COUNT) - posible misconfiguracion${NC}"
        echo "  [WARN] Multiples default gateways: $DGW_COUNT"
        SCORE=$((SCORE - 5))
        ((ISSUES++)) || true
    elif [[ $DGW_COUNT -eq 0 ]]; then
        echo -e "    ${RED}[FAIL] Sin default gateway configurado${NC}"
        echo "  [FAIL] Sin default gateway"
        SCORE=$((SCORE - 10))
        ((ISSUES++)) || true
    fi

    # Detectar rutas hacia redes privadas inusuales
    if ip route show 2>/dev/null | grep -E "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)" | grep -qv default 2>/dev/null; then
        EXTRA_ROUTES=$(ip route show 2>/dev/null | grep -cE "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)" || true)
        echo -e "    ${YELLOW}[INFO] Rutas a redes privadas adicionales: $EXTRA_ROUTES${NC}"
    fi
    echo ""

    # ── 3. Tabla ARP ──
    echo -e "${CYAN}[3/7] Tabla ARP${NC}"
    echo "## 3. Tabla ARP"
    echo ""
    ip neigh show 2>/dev/null | while IFS= read -r line; do
        state=$(echo "$line" | awk '{print $NF}')
        case "$state" in
            REACHABLE|PERMANENT) echo -e "    ${GREEN}[$state]${NC} $line" ;;
            STALE)               echo -e "    ${YELLOW}[$state]${NC} $line" ;;
            FAILED|INCOMPLETE)   echo -e "    ${RED}[$state]${NC} $line" ;;
            *)                   echo -e "    [$state] $line" ;;
        esac
        echo "  $line"
    done
    echo ""

    # Detectar MACs duplicadas (posible ARP spoofing)
    DUPLICATE_MACS=$(ip neigh show 2>/dev/null | awk '{print $5}' | sort | uniq -d | grep -v "^$" || true)
    if [[ -n "$DUPLICATE_MACS" ]]; then
        echo -e "    ${RED}[CRITICO] MACs duplicadas detectadas (posible ARP spoofing):${NC}"
        echo "  [CRITICO] MACs duplicadas detectadas:"
        for mac in $DUPLICATE_MACS; do
            echo -e "      ${RED}$mac -> $(ip neigh show 2>/dev/null | grep "$mac" | awk '{print $1}' | tr '\n' ' ')${NC}"
            echo "    $mac -> $(ip neigh show 2>/dev/null | grep "$mac" | awk '{print $1}' | tr '\n' ' ')"
        done
        SCORE=$((SCORE - 20))
        ((ISSUES++)) || true
    fi
    echo ""

    # ── 3b. Servicios de descubrimiento (superficie de poisoning) ──
    echo -e "${CYAN}[3b/7] Servicios de descubrimiento de red${NC}"
    echo "## 3b. Servicios de descubrimiento (mDNS/LLMNR)"
    echo ""

    # Verificar avahi-daemon (mDNS - superficie de poisoning)
    if systemctl is-active avahi-daemon &>/dev/null 2>&1; then
        echo -e "    ${YELLOW}[WARN]${NC} avahi-daemon activo (superficie de mDNS poisoning)"
        echo "  [WARN] avahi-daemon activo (mDNS poisoning surface)"
        SCORE=$((SCORE - 5))
        ((ISSUES++)) || true
    else
        echo -e "    ${GREEN}[OK]${NC}   avahi-daemon no activo"
        echo "  [OK] avahi-daemon no activo"
    fi

    # Verificar LLMNR en systemd-resolved
    if systemctl is-active systemd-resolved &>/dev/null 2>&1; then
        LLMNR_STATUS=$(resolvectl llmnr 2>/dev/null | head -1 || busctl get-property org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager LLMNR 2>/dev/null || echo "")
        if echo "$LLMNR_STATUS" | grep -qi "yes\|true" 2>/dev/null; then
            echo -e "    ${YELLOW}[WARN]${NC} LLMNR habilitado en systemd-resolved (vulnerable a poisoning)"
            echo "  [WARN] LLMNR habilitado en systemd-resolved"
            SCORE=$((SCORE - 5))
            ((ISSUES++)) || true
        else
            echo -e "    ${GREEN}[OK]${NC}   LLMNR deshabilitado o no disponible"
            echo "  [OK] LLMNR deshabilitado"
        fi
    fi
    echo ""

    # ── 4. Parametros sysctl de red ──
    echo -e "${CYAN}[4/7] Parametros de seguridad de red (sysctl)${NC}"
    echo "## 4. Parametros sysctl de red"
    echo ""

    declare -A SYSCTL_CHECKS=(
        ["net.ipv4.ip_forward"]="0|IP forwarding (debe estar 0 salvo routers)"
        ["net.ipv4.conf.all.accept_source_route"]="0|Source routing (debe estar deshabilitado)"
        ["net.ipv4.conf.all.accept_redirects"]="0|ICMP redirects (debe estar deshabilitado)"
        ["net.ipv4.conf.all.send_redirects"]="0|Enviar ICMP redirects (debe estar deshabilitado)"
        ["net.ipv4.conf.all.rp_filter"]="1|Reverse path filtering (debe estar habilitado)"
        ["net.ipv4.conf.all.log_martians"]="1|Log paquetes marcianos (debe estar habilitado)"
        ["net.ipv4.icmp_echo_ignore_broadcasts"]="1|Ignorar ICMP broadcast (smurf protection)"
        ["net.ipv4.icmp_ignore_bogus_error_responses"]="1|Ignorar respuestas ICMP bogus"
        ["net.ipv4.tcp_syncookies"]="1|SYN cookies (proteccion SYN flood)"
        ["net.ipv6.conf.all.accept_ra"]="0|IPv6 Router Advertisements (cuidado con MITM)"
        ["net.ipv6.conf.all.accept_source_route"]="0|IPv6 source routing"
        ["net.ipv4.conf.all.arp_announce"]="2|ARP announce (usar mejor direccion local)"
        ["net.ipv4.conf.all.arp_ignore"]="1|ARP ignore (responder solo en interfaz correcta)"
        ["net.ipv4.conf.all.arp_accept"]="0|ARP accept (rechazar gratuitous ARP)"
        ["net.ipv6.conf.all.accept_redirects"]="0|IPv6 ICMP redirects (prevenir MITM)"
        ["net.ipv6.conf.default.accept_ra"]="0|IPv6 RA default (prevenir RA spoofing)"
    )

    for param in "${!SYSCTL_CHECKS[@]}"; do
        IFS='|' read -r expected desc <<< "${SYSCTL_CHECKS[$param]}"
        current=$(sysctl -n "$param" 2>/dev/null || echo "N/A")

        if [[ "$current" == "$expected" ]]; then
            echo -e "    ${GREEN}[OK]${NC}   $param = $current ($desc)"
            echo "  [OK] $param = $current"
        elif [[ "$current" == "N/A" ]]; then
            echo -e "    ${YELLOW}[N/A]${NC}  $param (parametro no disponible)"
            echo "  [N/A] $param"
        else
            echo -e "    ${RED}[FAIL]${NC} $param = $current (esperado: $expected) - $desc"
            echo "  [FAIL] $param = $current (esperado: $expected)"
            SCORE=$((SCORE - 5))
            ((ISSUES++)) || true
        fi
    done
    echo ""

    # ── 5. Resolucion DNS ──
    echo -e "${CYAN}[5/7] Configuracion DNS${NC}"
    echo "## 5. Configuracion DNS"
    echo ""

    # /etc/resolv.conf
    if [[ -f /etc/resolv.conf ]]; then
        echo "  /etc/resolv.conf:"
        grep -v "^#" /etc/resolv.conf | grep -v "^$" | while IFS= read -r line; do
            echo "    $line"
        done
        echo ""

        # Verificar si usa DNS cifrado
        # Detectar si hay VPN activa (los DNS dentro del tunel van cifrados)
        VPN_IFACES=""
        for _vtype in tun wireguard; do
            _vi=$(ip -o link show type "$_vtype" 2>/dev/null | awk -F': ' '{print $2}' || true)
            [[ -n "$_vi" ]] && VPN_IFACES="$VPN_IFACES $_vi"
        done
        # Fallback: detectar por nombre de interfaz conocido
        _vi_name=$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -iE "^(proton|wg|tun|vpn|mullvad|nord|ipv6leak)" || true)
        for _vn in $_vi_name; do
            [[ " $VPN_IFACES " == *" $_vn "* ]] || VPN_IFACES="$VPN_IFACES $_vn"
        done
        VPN_IFACES=$(echo "$VPN_IFACES" | xargs)
        VPN_NETS=""
        for viface in $VPN_IFACES; do
            VPN_NETS="$VPN_NETS $(ip -o -4 addr show "$viface" 2>/dev/null | awk '{print $4}' | sed 's|/.*||')"
        done

        DNS_SERVERS=$(grep "^nameserver" /etc/resolv.conf | awk '{print $2}')
        for dns in $DNS_SERVERS; do
            if [[ "$dns" == "127.0.0.53" ]]; then
                echo -e "    ${GREEN}[OK]${NC} Usando stub resolver local (systemd-resolved)"
            elif [[ "$dns" == "127.0.0.1" ]] || [[ "$dns" == "::1" ]]; then
                echo -e "    ${GREEN}[OK]${NC} Usando resolver local"
            elif [[ "$dns" =~ ^10\. ]] || [[ "$dns" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]] || [[ "$dns" =~ ^192\.168\. ]] || [[ "$dns" =~ ^fd ]] || [[ "$dns" =~ ^2a07:b944 ]]; then
                # DNS en rango privado o VPN (ProtonVPN, Mullvad, etc.)
                vpn_match=false
                for vnet in $VPN_NETS; do
                    dns_prefix=$(echo "$dns" | cut -d. -f1-2)
                    vnet_prefix=$(echo "$vnet" | cut -d. -f1-2)
                    [[ "$dns_prefix" == "$vnet_prefix" ]] && vpn_match=true
                done
                if $vpn_match || [[ -n "$VPN_IFACES" ]]; then
                    echo -e "    ${GREEN}[OK]${NC} DNS via VPN: $dns (cifrado por tunel)"
                else
                    echo -e "    ${YELLOW}[INFO]${NC} DNS en red privada: $dns"
                fi
            else
                echo -e "    ${YELLOW}[WARN]${NC} DNS externo directo: $dns (sin cifrado confirmado)"
            fi
        done
    fi

    # systemd-resolved
    if command -v resolvectl &>/dev/null; then
        echo ""
        echo "  Estado de systemd-resolved:"
        resolvectl status 2>/dev/null | head -20 | while IFS= read -r line; do
            echo "    $line"
        done

        # Verificar DNSSEC
        if resolvectl status 2>/dev/null | grep -qi "DNSSEC.*yes"; then
            echo -e "    ${GREEN}[OK]${NC} DNSSEC habilitado"
        else
            echo -e "    ${YELLOW}[WARN]${NC} DNSSEC no habilitado"
            SCORE=$((SCORE - 5))
            ((ISSUES++)) || true
        fi

        # Verificar DoT
        if resolvectl status 2>/dev/null | grep -qi "DNSOverTLS.*yes\|DNSOverTLS.*opportunistic"; then
            echo -e "    ${GREEN}[OK]${NC} DNS-over-TLS habilitado"
        else
            echo -e "    ${YELLOW}[WARN]${NC} DNS-over-TLS no habilitado"
            SCORE=$((SCORE - 3))
            ((ISSUES++)) || true
        fi
    fi
    echo ""

    # ── 6. Firewall ──
    echo -e "${CYAN}[6/7] Estado del firewall${NC}"
    echo "## 6. Estado del firewall"
    echo ""

    FW_ACTIVE=false
    if command -v firewall-cmd &>/dev/null && firewall-cmd --state &>/dev/null 2>&1; then
        FW_ACTIVE=true
        echo -e "    ${GREEN}[OK]${NC} firewalld activo"
        echo "  Backend: firewalld"
        echo "  Zona por defecto: $(firewall-cmd --get-default-zone 2>/dev/null)"
        echo "  Servicios:"
        firewall-cmd --list-all 2>/dev/null | grep -E "services:|ports:|rich rules:" | while IFS= read -r line; do
            echo "    $line"
        done
    elif command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        FW_ACTIVE=true
        echo -e "    ${GREEN}[OK]${NC} ufw activo"
        echo "  Backend: ufw"
        ufw status numbered 2>/dev/null | head -20 | while IFS= read -r line; do
            echo "    $line"
        done
    elif command -v nft &>/dev/null && nft list ruleset 2>/dev/null | grep -q "table"; then
        FW_ACTIVE=true
        echo -e "    ${GREEN}[OK]${NC} nftables con reglas activas"
        echo "  Backend: nftables"
        nft list tables 2>/dev/null | while IFS= read -r line; do
            echo "    $line"
        done
    elif command -v iptables &>/dev/null; then
        RULES_COUNT=$(iptables -S 2>/dev/null | grep -cv "^-P" || echo 0)
        if [[ $RULES_COUNT -gt 0 ]]; then
            FW_ACTIVE=true
            echo -e "    ${GREEN}[OK]${NC} iptables con $RULES_COUNT reglas"
            echo "  Backend: iptables"
        fi
    fi

    if ! $FW_ACTIVE; then
        echo -e "    ${RED}[FAIL]${NC} Ningun firewall activo detectado"
        echo "  [FAIL] Sin firewall activo"
        SCORE=$((SCORE - 20))
        ((ISSUES++)) || true
    fi
    echo ""

    # ── 7. Conexiones activas sospechosas ──
    echo -e "${CYAN}[7/7] Conexiones activas${NC}"
    echo "## 7. Conexiones activas"
    echo ""

    # Puertos en LISTEN
    echo "  Puertos en escucha:"
    ss -tlnp 2>/dev/null | tail -n +2 | while IFS= read -r line; do
        local_addr=$(echo "$line" | awk '{print $4}')
        process=$(echo "$line" | awk '{print $6}')
        # Detectar binds a 0.0.0.0 (todos las interfaces)
        if echo "$local_addr" | grep -q "^0.0.0.0:\|^\*:\|^\[::\]:"; then
            echo -e "    ${YELLOW}[WARN]${NC} $local_addr (bind global) - $process"
        else
            echo -e "    ${GREEN}[OK]${NC}   $local_addr - $process"
        fi
        echo "  $local_addr | $process"
    done
    echo ""

    # Conexiones ESTABLISHED hacia IPs externas
    echo "  Conexiones establecidas (top 10 destinos):"
    ss -tnp state established 2>/dev/null | tail -n +2 | awk '{print $4}' | \
        sed 's/:[0-9]*$//' | sort | uniq -c | sort -rn | head -10 | while IFS= read -r line; do
        echo "    $line"
    done
    echo ""

    # ── Puntuacion ──
    [[ $SCORE -lt 0 ]] && SCORE=0
    echo ""
    echo "## Puntuacion de configuracion de red"
    echo "  Puntuacion: $SCORE/100"
    echo "  Problemas: $ISSUES"

} 2>&1 | tee "$OUTFILE"

# Mostrar puntuacion final
echo ""
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
if [[ $SCORE -ge 80 ]]; then
    echo -e "  Puntuacion: ${GREEN}${SCORE}/100${NC} | Problemas: $ISSUES"
elif [[ $SCORE -ge 60 ]]; then
    echo -e "  Puntuacion: ${YELLOW}${SCORE}/100${NC} | Problemas: $ISSUES"
else
    echo -e "  Puntuacion: ${RED}${SCORE}/100${NC} | Problemas: $ISSUES"
fi
echo -e "  Reporte: ${CYAN}$OUTFILE${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
ENDSCRIPT
    chmod +x "${TOOLS_DIR}/auditoria-red-config.sh"
    log_change "Creado" "${TOOLS_DIR}/auditoria-red-config.sh"

    log_info "Script de auditoria de configuracion de red creado"
else
    log_skip "Scripts de auditoria de configuracion de red"
fi
fi # S6

# ============================================================
# S7: INVENTARIO DE SERVICIOS Y CONTROL DE VERSIONES
# ============================================================
if [[ "$AUDIT_SECTION" == "all" || "$AUDIT_SECTION" == "S7" ]]; then
log_section "S7: INVENTARIO DE SERVICIOS Y CONTROL DE VERSIONES"

echo "Crea un sistema de inventario de servicios de red:"
echo "  - Inventario de servicios expuestos con versiones exactas"
echo "  - Deteccion de versiones vulnerables conocidas"
echo "  - Comparacion con inventario aprobado"
echo "  - Deteccion de servicios shadow IT (no documentados)"
echo "  - Alertas de servicios nuevos o modificados"
echo ""

if check_executable /usr/local/bin/auditoria-red-inventario.sh; then
    log_already "Scripts de inventario de servicios (auditoria-red-inventario.sh existe)"
elif ask "Crear scripts de inventario de servicios?"; then

    # ── Inventario de servicios aprobados ──
    if [[ ! -f "${CONF_DIR}/servicios-aprobados.conf" ]]; then
        cat > "${CONF_DIR}/servicios-aprobados.conf" << 'EOFCONF'
# Inventario de servicios de red aprobados
# Formato: puerto/proto  servicio  version_min  responsable  notas
#
# Ejemplo (ajustar segun el entorno):
22/tcp    OpenSSH     8.0     sysadmin    Acceso remoto
443/tcp   nginx       1.18    webteam     Proxy inverso
# 80/tcp    nginx       1.18    webteam     Redireccion a HTTPS
# 3306/tcp  MariaDB     10.5    dba         Solo local
# 5432/tcp  PostgreSQL  13.0    dba         Solo red interna
EOFCONF
        chmod 640 "${CONF_DIR}/servicios-aprobados.conf"
        log_change "Creado" "${CONF_DIR}/servicios-aprobados.conf"
    fi

    # ── Script de inventario ──
    cat > "${TOOLS_DIR}/auditoria-red-inventario.sh" << 'ENDSCRIPT'
#!/bin/bash
# auditoria-red-inventario.sh - Inventario de servicios de red y control de versiones
# Uso: auditoria-red-inventario.sh [target] [--compare|--scan-only]
set -euo pipefail
[[ ":$PATH:" == *":/usr/local/bin:"* ]] || export PATH="/usr/local/bin:$PATH"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

SCAN_DIR="/var/lib/securizar/auditoria-red/scans"
BASELINE_DIR="/var/lib/securizar/auditoria-red/baseline"
CONF_DIR="/etc/securizar/auditoria-red"
APPROVED="${CONF_DIR}/servicios-aprobados.conf"
mkdir -p "$SCAN_DIR" "$BASELINE_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

TARGET="${1:-localhost}"
MODE="${2:---compare}"

echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  INVENTARIO DE SERVICIOS DE RED${NC}"
echo -e "${BOLD}  Objetivo: $TARGET  |  $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
echo ""

if ! command -v nmap &>/dev/null; then
    echo -e "${RED}Error: nmap no instalado${NC}"
    exit 1
fi

OUTFILE="${SCAN_DIR}/inventario-${TARGET//\//-}-${TIMESTAMP}"

# Fase 1: Escaneo de servicios con deteccion de version
echo -e "${CYAN}[1/3] Escaneo de servicios con deteccion de version...${NC}"
nmap -sV --version-intensity 7 --top-ports 1000 --open -T3 "$TARGET" \
    -oA "${OUTFILE}" 2>/dev/null

# Parsear resultados a formato de inventario
echo ""
echo -e "${CYAN}[2/3] Generando inventario...${NC}"
{
    echo "# Inventario de servicios - $TARGET - $(date '+%Y-%m-%d %H:%M:%S')"
    echo "# Puerto | Servicio | Version | Producto | Info extra"
    echo "# ─────────────────────────────────────────────────"

    if [[ -f "${OUTFILE}.gnmap" ]]; then
        grep "Ports:" "${OUTFILE}.gnmap" 2>/dev/null | while IFS= read -r line; do
            echo "$line" | tr ',' '\n' | grep -oP '\d+/open/[^/]*/[^/]*/[^/]*/[^/]*/[^/]*' | while IFS='/' read -r port state proto _ign service _ign2 version; do
                echo "$port/$proto | $service | ${version:--}"
            done
        done
    fi
} | tee "${OUTFILE}-inventario.txt"
echo ""

# Fase 2: Comparar con servicios aprobados
if [[ "$MODE" == "--compare" ]] && [[ -f "$APPROVED" ]]; then
    echo -e "${CYAN}[3/3] Comparacion con inventario aprobado...${NC}"
    echo ""

    SHADOW_SERVICES=0
    VERSION_ISSUES=0

    if [[ -f "${OUTFILE}.gnmap" ]]; then
        grep "Ports:" "${OUTFILE}.gnmap" 2>/dev/null | while IFS= read -r line; do
            echo "$line" | tr ',' '\n' | grep -oP '\d+/open/[^/]*/[^/]*/[^/]*/[^/]*/[^/]*' | while IFS='/' read -r port _state proto _ign service _ign2 version; do
                approved_line=$(grep -E "^${port}/${proto}" "$APPROVED" 2>/dev/null | head -1)
                if [[ -n "$approved_line" ]]; then
                    approved_ver=$(echo "$approved_line" | awk '{print $3}')
                    echo -e "  ${GREEN}[OK]${NC}       ${port}/${proto} (${service} ${version:-?}) - en inventario aprobado"
                else
                    echo -e "  ${RED}[SHADOW]${NC}   ${port}/${proto} (${service} ${version:-?}) - NO en inventario aprobado"
                    ((SHADOW_SERVICES++)) || true
                fi
            done
        done
    fi

    echo ""
    if [[ $SHADOW_SERVICES -gt 0 ]]; then
        echo -e "  ${RED}Servicios shadow IT detectados: $SHADOW_SERVICES${NC}"
    else
        echo -e "  ${GREEN}Todos los servicios estan en el inventario aprobado${NC}"
    fi
else
    echo -e "${YELLOW}[3/3] Comparacion omitida (--scan-only o sin inventario aprobado)${NC}"
fi

# Guardar como baseline si no existe
LATEST_BASELINE="${BASELINE_DIR}/servicios-${TARGET//\//-}-latest.txt"
if [[ ! -f "$LATEST_BASELINE" ]]; then
    cp "${OUTFILE}-inventario.txt" "$LATEST_BASELINE"
    echo ""
    echo -e "${GREEN}Baseline inicial guardada: $LATEST_BASELINE${NC}"
else
    # Comparar con baseline anterior
    echo ""
    echo -e "${CYAN}Comparacion con baseline anterior:${NC}"
    DIFF_RESULT=$(diff "$LATEST_BASELINE" "${OUTFILE}-inventario.txt" 2>/dev/null || true)
    if [[ -z "$DIFF_RESULT" ]]; then
        echo -e "  ${GREEN}Sin cambios respecto a la baseline${NC}"
    else
        echo -e "  ${YELLOW}Cambios detectados:${NC}"
        echo "$DIFF_RESULT" | head -20
        # Actualizar baseline
        cp "${OUTFILE}-inventario.txt" "$LATEST_BASELINE"
        echo ""
        echo -e "  ${YELLOW}Baseline actualizada${NC}"
    fi
fi

echo ""
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "  Inventario: ${CYAN}${OUTFILE}-inventario.txt${NC}"
echo -e "  nmap XML:   ${CYAN}${OUTFILE}.xml${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
ENDSCRIPT
    chmod +x "${TOOLS_DIR}/auditoria-red-inventario.sh"
    log_change "Creado" "${TOOLS_DIR}/auditoria-red-inventario.sh"

    log_info "Script de inventario de servicios creado"
else
    log_skip "Scripts de inventario de servicios"
fi
fi # S7

# ============================================================
# S8: LINEA BASE DE RED Y DETECCION DE DRIFT
# ============================================================
if [[ "$AUDIT_SECTION" == "all" || "$AUDIT_SECTION" == "S8" ]]; then
log_section "S8: LINEA BASE DE RED Y DETECCION DE DRIFT"

echo "Establece una linea base del estado de la red y detecta desviaciones:"
echo "  - Snapshot de puertos abiertos, rutas, ARP, interfaces"
echo "  - Comparacion periodica contra baseline"
echo "  - Alertas de drift (nuevos puertos, rutas cambiadas, hosts nuevos)"
echo "  - Historico de cambios en la red"
echo ""

if check_executable /usr/local/bin/auditoria-red-baseline.sh; then
    log_already "Sistema de baseline y drift (auditoria-red-baseline.sh existe)"
elif ask "Crear sistema de baseline y deteccion de drift?"; then

    cat > "${TOOLS_DIR}/auditoria-red-baseline.sh" << 'ENDSCRIPT'
#!/bin/bash
# auditoria-red-baseline.sh - Gestion de baseline de red y deteccion de drift
# Uso: auditoria-red-baseline.sh --capture           Capturar baseline
#      auditoria-red-baseline.sh --compare            Comparar con baseline
#      auditoria-red-baseline.sh --history             Ver historial de cambios
set -euo pipefail
[[ ":$PATH:" == *":/usr/local/bin:"* ]] || export PATH="/usr/local/bin:$PATH"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

BASELINE_DIR="/var/lib/securizar/auditoria-red/baseline"
HISTORY_DIR="/var/lib/securizar/auditoria-red/baseline/history"
mkdir -p "$BASELINE_DIR" "$HISTORY_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

ACTION="${1:---compare}"

capture_baseline() {
    local PREFIX="${BASELINE_DIR}/baseline-${TIMESTAMP}"
    local LATEST="${BASELINE_DIR}/latest"

    echo -e "${BOLD}Capturando baseline de red...${NC}"
    echo ""

    # 1. Puertos en escucha locales
    echo -e "  ${CYAN}[1/6]${NC} Puertos en escucha..."
    ss -tlnp 2>/dev/null | tail -n +2 | awk '{print $4, $6}' | sort > "${PREFIX}-listening.txt"
    ss -ulnp 2>/dev/null | tail -n +2 | awk '{print $4, $6}' | sort >> "${PREFIX}-listening.txt"

    # 2. Interfaces y direcciones IP
    echo -e "  ${CYAN}[2/6]${NC} Interfaces y direcciones..."
    ip -br addr show 2>/dev/null | sort > "${PREFIX}-interfaces.txt"

    # 3. Tabla de rutas
    echo -e "  ${CYAN}[3/6]${NC} Tabla de rutas..."
    ip route show 2>/dev/null | sort > "${PREFIX}-routes.txt"

    # 4. Tabla ARP
    echo -e "  ${CYAN}[4/6]${NC} Tabla ARP..."
    ip neigh show 2>/dev/null | awk '{print $1, $5, $NF}' | sort > "${PREFIX}-arp.txt"

    # 5. Parametros sysctl de red
    echo -e "  ${CYAN}[5/6]${NC} Parametros sysctl..."
    for param in net.ipv4.ip_forward net.ipv4.conf.all.accept_source_route \
        net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects \
        net.ipv4.conf.all.rp_filter net.ipv4.conf.all.log_martians \
        net.ipv4.tcp_syncookies net.ipv6.conf.all.accept_ra; do
        echo "$param=$(sysctl -n "$param" 2>/dev/null || echo 'N/A')"
    done | sort > "${PREFIX}-sysctl.txt"

    # 6. Reglas de firewall
    echo -e "  ${CYAN}[6/6]${NC} Reglas de firewall..."
    {
        if command -v firewall-cmd &>/dev/null && firewall-cmd --state &>/dev/null 2>&1; then
            firewall-cmd --list-all-zones 2>/dev/null
        elif command -v ufw &>/dev/null; then
            ufw status verbose 2>/dev/null
        elif command -v nft &>/dev/null; then
            nft list ruleset 2>/dev/null
        elif command -v iptables &>/dev/null; then
            iptables -S 2>/dev/null
        fi
    } > "${PREFIX}-firewall.txt"

    # Actualizar symlink a latest
    for suffix in listening interfaces routes arp sysctl firewall; do
        ln -sf "${PREFIX}-${suffix}.txt" "${LATEST}-${suffix}.txt"
    done

    # Metadatos
    {
        echo "timestamp=$TIMESTAMP"
        echo "date=$(date '+%Y-%m-%d %H:%M:%S')"
        echo "hostname=$(hostname)"
        echo "kernel=$(uname -r)"
    } > "${PREFIX}-meta.txt"
    ln -sf "${PREFIX}-meta.txt" "${LATEST}-meta.txt"

    echo ""
    echo -e "${GREEN}Baseline capturada: ${PREFIX}-*.txt${NC}"
    echo -e "Archivos:"
    for f in "${PREFIX}"-*.txt; do
        echo -e "  ${GREEN}+${NC} $(basename "$f") ($(wc -l < "$f") entradas)"
    done
}

compare_baseline() {
    local LATEST="${BASELINE_DIR}/latest"
    local DRIFTS=0

    # Verificar que existe baseline
    if [[ ! -f "${LATEST}-listening.txt" ]]; then
        echo -e "${RED}No hay baseline capturada. Ejecute primero: $0 --capture${NC}"
        exit 1
    fi

    echo -e "${BOLD}Comparando estado actual con baseline...${NC}"
    echo ""

    local CURRENT_PREFIX="${BASELINE_DIR}/current-${TIMESTAMP}"

    # Capturar estado actual
    ss -tlnp 2>/dev/null | tail -n +2 | awk '{print $4, $6}' | sort > "${CURRENT_PREFIX}-listening.txt"
    ss -ulnp 2>/dev/null | tail -n +2 | awk '{print $4, $6}' | sort >> "${CURRENT_PREFIX}-listening.txt"
    ip -br addr show 2>/dev/null | sort > "${CURRENT_PREFIX}-interfaces.txt"
    ip route show 2>/dev/null | sort > "${CURRENT_PREFIX}-routes.txt"
    ip neigh show 2>/dev/null | awk '{print $1, $5, $NF}' | sort > "${CURRENT_PREFIX}-arp.txt"

    for param in net.ipv4.ip_forward net.ipv4.conf.all.accept_source_route \
        net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects \
        net.ipv4.conf.all.rp_filter net.ipv4.conf.all.log_martians \
        net.ipv4.tcp_syncookies net.ipv6.conf.all.accept_ra; do
        echo "$param=$(sysctl -n "$param" 2>/dev/null || echo 'N/A')"
    done | sort > "${CURRENT_PREFIX}-sysctl.txt"

    # Comparar cada componente
    for component in listening interfaces routes sysctl; do
        local BASELINE_FILE="${LATEST}-${component}.txt"
        local CURRENT_FILE="${CURRENT_PREFIX}-${component}.txt"

        local COMPONENT_NAME
        case "$component" in
            listening)  COMPONENT_NAME="Puertos en escucha" ;;
            interfaces) COMPONENT_NAME="Interfaces de red" ;;
            routes)     COMPONENT_NAME="Tabla de rutas" ;;
            sysctl)     COMPONENT_NAME="Parametros sysctl" ;;
        esac

        if [[ ! -f "$BASELINE_FILE" ]]; then
            echo -e "  ${YELLOW}[SKIP]${NC} $COMPONENT_NAME: sin baseline"
            continue
        fi

        DIFF_OUTPUT=$(diff "$BASELINE_FILE" "$CURRENT_FILE" 2>/dev/null || true)

        if [[ -z "$DIFF_OUTPUT" ]]; then
            echo -e "  ${GREEN}[OK]${NC}   $COMPONENT_NAME: sin cambios"
        else
            echo -e "  ${RED}[DRIFT]${NC} $COMPONENT_NAME: cambios detectados"
            ((DRIFTS++)) || true

            # Mostrar cambios
            ADDED=$(echo "$DIFF_OUTPUT" | grep "^>" | wc -l)
            REMOVED=$(echo "$DIFF_OUTPUT" | grep "^<" | wc -l)
            echo -e "         ${GREEN}+$ADDED nuevos${NC} / ${RED}-$REMOVED eliminados${NC}"

            # Nuevos elementos
            echo "$DIFF_OUTPUT" | grep "^>" | head -5 | while IFS= read -r line; do
                echo -e "         ${GREEN}  $line${NC}"
            done

            # Elementos eliminados
            echo "$DIFF_OUTPUT" | grep "^<" | head -5 | while IFS= read -r line; do
                echo -e "         ${RED}  $line${NC}"
            done
        fi
    done

    echo ""

    # ARP - comparacion especial (muy volatile)
    ARP_NEW=$(comm -13 "${LATEST}-arp.txt" "${CURRENT_PREFIX}-arp.txt" 2>/dev/null | wc -l)
    ARP_GONE=$(comm -23 "${LATEST}-arp.txt" "${CURRENT_PREFIX}-arp.txt" 2>/dev/null | wc -l)
    if [[ $ARP_NEW -gt 0 ]] || [[ $ARP_GONE -gt 0 ]]; then
        echo -e "  ${YELLOW}[INFO]${NC} Tabla ARP: +$ARP_NEW nuevos / -$ARP_GONE desaparecidos (normal si es dinamica)"
    else
        echo -e "  ${GREEN}[OK]${NC}   Tabla ARP: sin cambios significativos"
    fi

    # Guardar drift en historial
    if [[ $DRIFTS -gt 0 ]]; then
        {
            echo "# Drift detectado - $(date '+%Y-%m-%d %H:%M:%S')"
            echo "# Componentes afectados: $DRIFTS"
            for component in listening interfaces routes sysctl; do
                DIFF_OUTPUT=$(diff "${LATEST}-${component}.txt" "${CURRENT_PREFIX}-${component}.txt" 2>/dev/null || true)
                if [[ -n "$DIFF_OUTPUT" ]]; then
                    echo ""
                    echo "## $component:"
                    echo "$DIFF_OUTPUT"
                fi
            done
        } > "${HISTORY_DIR}/drift-${TIMESTAMP}.txt"
        echo ""
        echo -e "${YELLOW}Drift registrado: ${HISTORY_DIR}/drift-${TIMESTAMP}.txt${NC}"
    fi

    # Limpieza de archivos temporales
    rm -f "${CURRENT_PREFIX}"-*.txt

    echo ""
    echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
    if [[ $DRIFTS -eq 0 ]]; then
        echo -e "  ${GREEN}Estado de red CONFORME con la baseline${NC}"
    else
        echo -e "  ${RED}$DRIFTS componentes con DRIFT detectado${NC}"
    fi
    echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
}

show_history() {
    echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  HISTORIAL DE DRIFT DE RED${NC}"
    echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
    echo ""

    local COUNT=0
    for f in "${HISTORY_DIR}"/drift-*.txt; do
        [[ -f "$f" ]] || continue
        ((COUNT++)) || true
        echo -e "${CYAN}$(basename "$f")${NC}"
        head -3 "$f" | while IFS= read -r line; do
            echo "  $line"
        done
        echo ""
    done

    if [[ $COUNT -eq 0 ]]; then
        echo -e "  ${GREEN}Sin registros de drift${NC}"
    else
        echo -e "  Total de drifts registrados: ${YELLOW}$COUNT${NC}"
    fi
}

# ── Main ──
case "$ACTION" in
    --capture|-c)  capture_baseline ;;
    --compare|-d)  compare_baseline ;;
    --history|-h)  show_history ;;
    *)
        echo "Uso: $0 [--capture|--compare|--history]"
        echo ""
        echo "  --capture   Capturar baseline del estado actual de la red"
        echo "  --compare   Comparar estado actual con la baseline"
        echo "  --history   Ver historial de drifts detectados"
        ;;
esac
ENDSCRIPT
    chmod +x "${TOOLS_DIR}/auditoria-red-baseline.sh"
    log_change "Creado" "${TOOLS_DIR}/auditoria-red-baseline.sh"

    log_info "Sistema de baseline y drift creado"
else
    log_skip "Sistema de baseline y drift"
fi
fi # S8

# ============================================================
# S9: AUTOMATIZACION DE AUDITORIAS PERIODICAS
# ============================================================
if [[ "$AUDIT_SECTION" == "all" || "$AUDIT_SECTION" == "S9" ]]; then
log_section "S9: AUTOMATIZACION DE AUDITORIAS PERIODICAS"

echo "Configura auditorias de red automatizadas via cron/timer:"
echo "  - Auditoria diaria de configuracion de red"
echo "  - Comparacion semanal contra baseline"
echo "  - Escaneo mensual de puertos e inventario"
echo "  - Auditoria trimestral TLS/SSL completa"
echo "  - Notificaciones por email o syslog"
echo ""

if check_executable /usr/local/bin/auditoria-red-programada.sh; then
    log_already "Auditorias periodicas (auditoria-red-programada.sh existe)"
elif ask "Configurar auditorias periodicas automatizadas?"; then

    # ── Script orquestador de auditorias ──
    cat > "${TOOLS_DIR}/auditoria-red-programada.sh" << 'ENDSCRIPT'
#!/bin/bash
# auditoria-red-programada.sh - Orquestador de auditorias periodicas
# Uso: auditoria-red-programada.sh [diaria|semanal|mensual|trimestral|completa]
set -euo pipefail
[[ ":$PATH:" == *":/usr/local/bin:"* ]] || export PATH="/usr/local/bin:$PATH"

LOG_FILE="/var/log/securizar/auditoria-red.log"
REPORT_DIR="/var/lib/securizar/auditoria-red/reportes"
CONF_DIR="/etc/securizar/auditoria-red"
mkdir -p "$(dirname "$LOG_FILE")" "$REPORT_DIR"

TIPO="${1:-diaria}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

# Cargar configuracion
ALERT_EMAIL=""
SCAN_SUBNET=""
TLS_ENDPOINTS=""
[[ -f "${CONF_DIR}/auditoria-programada.conf" ]] && source "${CONF_DIR}/auditoria-programada.conf"

# Detectar subred si no esta configurada
if [[ -z "$SCAN_SUBNET" ]]; then
    local_iface=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
    SCAN_SUBNET=$(ip -o -4 addr show "${local_iface:-eth0}" 2>/dev/null | awk '{print $4}' | head -1)
fi

REPORT_FILE="${REPORT_DIR}/auditoria-${TIPO}-${TIMESTAMP}.txt"

run_diaria() {
    log "=== AUDITORIA DIARIA ==="

    # 1. Verificar configuracion de red
    log "Ejecutando auditoria de configuracion..."
    if [[ -x /usr/local/bin/auditoria-red-config.sh ]]; then
        /usr/local/bin/auditoria-red-config.sh --quick >> "$REPORT_FILE" 2>&1
    fi

    # 2. Comparar baseline
    log "Comparando con baseline..."
    if [[ -x /usr/local/bin/auditoria-red-baseline.sh ]]; then
        /usr/local/bin/auditoria-red-baseline.sh --compare >> "$REPORT_FILE" 2>&1
    fi

    log "Auditoria diaria completada: $REPORT_FILE"
}

run_semanal() {
    log "=== AUDITORIA SEMANAL ==="

    # Incluir auditoria diaria
    run_diaria

    # 3. Inventario de servicios
    log "Ejecutando inventario de servicios..."
    if [[ -x /usr/local/bin/auditoria-red-inventario.sh ]] && [[ -n "$SCAN_SUBNET" ]]; then
        /usr/local/bin/auditoria-red-inventario.sh "$SCAN_SUBNET" --compare >> "$REPORT_FILE" 2>&1
    fi

    # 4. Auditoria SNMP
    log "Ejecutando auditoria SNMP..."
    if [[ -x /usr/local/bin/auditoria-red-snmp.sh ]] && [[ -n "$SCAN_SUBNET" ]]; then
        /usr/local/bin/auditoria-red-snmp.sh "$SCAN_SUBNET" >> "$REPORT_FILE" 2>&1
    fi

    log "Auditoria semanal completada: $REPORT_FILE"
}

run_mensual() {
    log "=== AUDITORIA MENSUAL ==="

    # Incluir auditoria semanal
    run_semanal

    # 5. Escaneo completo de puertos
    log "Ejecutando escaneo completo de puertos..."
    if [[ -x /usr/local/bin/auditoria-red-puertos.sh ]] && [[ -n "$SCAN_SUBNET" ]]; then
        /usr/local/bin/auditoria-red-puertos.sh "$SCAN_SUBNET" --top1000 >> "$REPORT_FILE" 2>&1
    fi

    # 6. Descubrimiento de red
    log "Ejecutando descubrimiento de red..."
    if [[ -x /usr/local/bin/auditoria-red-descubrimiento.sh ]] && [[ -n "$SCAN_SUBNET" ]]; then
        /usr/local/bin/auditoria-red-descubrimiento.sh "$SCAN_SUBNET" --full >> "$REPORT_FILE" 2>&1
    fi

    # Actualizar baseline
    log "Actualizando baseline..."
    if [[ -x /usr/local/bin/auditoria-red-baseline.sh ]]; then
        /usr/local/bin/auditoria-red-baseline.sh --capture >> "$REPORT_FILE" 2>&1
    fi

    log "Auditoria mensual completada: $REPORT_FILE"
}

run_trimestral() {
    log "=== AUDITORIA TRIMESTRAL ==="

    # Incluir auditoria mensual
    run_mensual

    # 7. Auditoria TLS completa
    log "Ejecutando auditoria TLS..."
    if [[ -x /usr/local/bin/auditoria-red-tls.sh ]]; then
        if [[ -n "$TLS_ENDPOINTS" ]] && [[ -f "$TLS_ENDPOINTS" ]]; then
            /usr/local/bin/auditoria-red-tls.sh --batch "$TLS_ENDPOINTS" >> "$REPORT_FILE" 2>&1
        else
            log "Sin archivo de endpoints TLS configurado"
        fi
    fi

    log "Auditoria trimestral completada: $REPORT_FILE"
}

run_completa() {
    log "=== AUDITORIA COMPLETA ==="
    run_trimestral
    log "Auditoria completa finalizada: $REPORT_FILE"
}

# Ejecutar tipo solicitado
case "$TIPO" in
    diaria)      run_diaria ;;
    semanal)     run_semanal ;;
    mensual)     run_mensual ;;
    trimestral)  run_trimestral ;;
    completa)    run_completa ;;
    *)
        echo "Uso: $0 [diaria|semanal|mensual|trimestral|completa]"
        exit 1
        ;;
esac

# Enviar notificacion si hay email configurado
if [[ -n "$ALERT_EMAIL" ]] && command -v mail &>/dev/null; then
    DRIFT_COUNT=$(grep -ci "DRIFT\|FAIL\|CRITICO\|SHADOW" "$REPORT_FILE" 2>/dev/null || echo 0)
    if [[ $DRIFT_COUNT -gt 0 ]]; then
        mail -s "[Securizar] Auditoria de red ${TIPO}: $DRIFT_COUNT problemas" "$ALERT_EMAIL" < "$REPORT_FILE"
        log "Notificacion enviada a $ALERT_EMAIL ($DRIFT_COUNT problemas)"
    fi
fi
ENDSCRIPT
    chmod +x "${TOOLS_DIR}/auditoria-red-programada.sh"
    log_change "Creado" "${TOOLS_DIR}/auditoria-red-programada.sh"

    # ── Configuracion de programacion ──
    if [[ ! -f "${CONF_DIR}/auditoria-programada.conf" ]]; then
        cat > "${CONF_DIR}/auditoria-programada.conf" << EOFCONF
# Configuracion de auditorias programadas
# Modificar segun el entorno

# Subred a escanear (auto-detectada si vacia)
SCAN_SUBNET="${MAIN_SUBNET:-}"

# Archivo con endpoints TLS a auditar (uno por linea: host:puerto)
TLS_ENDPOINTS="${CONF_DIR}/tls-endpoints.txt"

# Email para notificaciones (vacio = deshabilitado)
ALERT_EMAIL=

# Retencion de reportes (dias)
REPORT_RETENTION_DAYS=90
EOFCONF
        chmod 640 "${CONF_DIR}/auditoria-programada.conf"
        log_change "Creado" "${CONF_DIR}/auditoria-programada.conf"
    fi

    # ── Crear archivo de endpoints TLS de ejemplo ──
    if [[ ! -f "${CONF_DIR}/tls-endpoints.txt" ]]; then
        cat > "${CONF_DIR}/tls-endpoints.txt" << 'EOFCONF'
# Endpoints TLS a auditar (uno por linea)
# Formato: host:puerto
# Ejemplo:
# webserver.local:443
# mailserver.local:993
# ldap.local:636
EOFCONF
        chmod 640 "${CONF_DIR}/tls-endpoints.txt"
    fi

    # ── Cron / systemd timer ──
    echo ""
    echo "Configurando programacion de auditorias..."

    if command -v systemctl &>/dev/null; then
        # Preferir systemd timers
        cat > /etc/systemd/system/securizar-auditoria-red-diaria.service << 'EOFSVC'
[Unit]
Description=Securizar - Auditoria de red diaria
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/auditoria-red-programada.sh diaria
Nice=19
IOSchedulingClass=idle
EOFSVC

        cat > /etc/systemd/system/securizar-auditoria-red-diaria.timer << 'EOFTMR'
[Unit]
Description=Securizar - Auditoria de red diaria (timer)

[Timer]
OnCalendar=*-*-* 02:30:00
RandomizedDelaySec=900
Persistent=true

[Install]
WantedBy=timers.target
EOFTMR

        cat > /etc/systemd/system/securizar-auditoria-red-semanal.service << 'EOFSVC'
[Unit]
Description=Securizar - Auditoria de red semanal
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/auditoria-red-programada.sh semanal
Nice=19
IOSchedulingClass=idle
EOFSVC

        cat > /etc/systemd/system/securizar-auditoria-red-semanal.timer << 'EOFTMR'
[Unit]
Description=Securizar - Auditoria de red semanal (timer)

[Timer]
OnCalendar=Sun *-*-* 03:00:00
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
EOFTMR

        cat > /etc/systemd/system/securizar-auditoria-red-mensual.service << 'EOFSVC'
[Unit]
Description=Securizar - Auditoria de red mensual
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/auditoria-red-programada.sh mensual
Nice=19
IOSchedulingClass=idle
EOFSVC

        cat > /etc/systemd/system/securizar-auditoria-red-mensual.timer << 'EOFTMR'
[Unit]
Description=Securizar - Auditoria de red mensual (timer)

[Timer]
OnCalendar=*-*-01 04:00:00
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
EOFTMR

        systemctl daemon-reload
        systemctl enable --now securizar-auditoria-red-diaria.timer 2>/dev/null || true
        systemctl enable --now securizar-auditoria-red-semanal.timer 2>/dev/null || true
        systemctl enable --now securizar-auditoria-red-mensual.timer 2>/dev/null || true

        log_change "Creado" "systemd timers para auditorias de red (diaria/semanal/mensual)"
        log_info "Timers activados:"
        log_info "  - Diaria: 02:30 cada dia"
        log_info "  - Semanal: domingos 03:00"
        log_info "  - Mensual: dia 1 a las 04:00"
    else
        # Fallback a cron
        CRON_FILE="/etc/cron.d/securizar-auditoria-red"
        cat > "$CRON_FILE" << 'EOFCRON'
# Securizar - Auditorias de red programadas
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Diaria a las 02:30
30 2 * * *   root  /usr/local/bin/auditoria-red-programada.sh diaria >/dev/null 2>&1

# Semanal los domingos a las 03:00
0  3 * * 0   root  /usr/local/bin/auditoria-red-programada.sh semanal >/dev/null 2>&1

# Mensual el dia 1 a las 04:00
0  4 1 * *   root  /usr/local/bin/auditoria-red-programada.sh mensual >/dev/null 2>&1
EOFCRON
        chmod 644 "$CRON_FILE"
        log_change "Creado" "$CRON_FILE"
    fi

    log_info "Auditorias periodicas configuradas"
else
    log_skip "Auditorias periodicas automatizadas"
fi
fi # S9

# ============================================================
# S10: PUNTUACION Y REPORTE CONSOLIDADO DE AUDITORIA
# ============================================================
if [[ "$AUDIT_SECTION" == "all" || "$AUDIT_SECTION" == "S10" ]]; then
log_section "S10: PUNTUACION Y REPORTE CONSOLIDADO"

echo "Crea un sistema de puntuacion y reporte consolidado:"
echo "  - Reporte HTML/texto con resultados de todas las auditorias"
echo "  - Puntuacion global de seguridad de red (0-100)"
echo "  - Tendencias historicas"
echo "  - Recomendaciones priorizadas"
echo "  - Exportacion para integracion con SIEM"
echo ""

if check_executable /usr/local/bin/auditoria-red-reporte-global.sh; then
    log_already "Sistema de reporte consolidado (auditoria-red-reporte-global.sh existe)"
elif ask "Crear sistema de reporte consolidado?"; then

    cat > "${TOOLS_DIR}/auditoria-red-reporte-global.sh" << 'ENDSCRIPT'
#!/bin/bash
# auditoria-red-reporte-global.sh - Reporte consolidado de auditoria de red
# Uso: auditoria-red-reporte-global.sh [--text|--json|--html]
set -euo pipefail
[[ ":$PATH:" == *":/usr/local/bin:"* ]] || export PATH="/usr/local/bin:$PATH"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

REPORT_DIR="/var/lib/securizar/auditoria-red/reportes"
SCAN_DIR="/var/lib/securizar/auditoria-red/scans"
BASELINE_DIR="/var/lib/securizar/auditoria-red/baseline"
HISTORY_DIR="/var/lib/securizar/auditoria-red/baseline/history"
mkdir -p "$REPORT_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
FORMAT="${1:---text}"
OUTFILE="${REPORT_DIR}/global-${TIMESTAMP}"

TOTAL_SCORE=0
TOTAL_CHECKS=0
TOTAL_PASS=0
TOTAL_WARN=0
TOTAL_FAIL=0

add_check() {
    local result="$1"  # pass/warn/fail
    local weight="${2:-1}"
    ((TOTAL_CHECKS++)) || true
    case "$result" in
        pass) TOTAL_SCORE=$((TOTAL_SCORE + weight * 10)); ((TOTAL_PASS++)) || true ;;
        warn) TOTAL_SCORE=$((TOTAL_SCORE + weight * 5)); ((TOTAL_WARN++)) || true ;;
        fail) ((TOTAL_FAIL++)) || true ;;
    esac
}

echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  REPORTE GLOBAL DE AUDITORIA DE RED${NC}"
echo -e "${BOLD}  Host: $(hostname)  |  $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
echo ""

{
    echo "=========================================================="
    echo " REPORTE GLOBAL DE AUDITORIA DE INFRAESTRUCTURA DE RED"
    echo " Host: $(hostname)"
    echo " Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
    echo " Kernel: $(uname -r)"
    echo "=========================================================="
    echo ""

    # ── 1. Herramientas disponibles ──
    echo "## 1. Herramientas de auditoria"
    echo ""
    for tool in nmap tshark testssl.sh arp-scan nbtscan snmpwalk snmpget socat suricata; do
        if command -v "$tool" &>/dev/null; then
            echo -e "  ${GREEN}[OK]${NC} $tool: $(command -v "$tool")"
            echo "  [OK] $tool"
            add_check "pass"
        else
            echo -e "  ${YELLOW}[-]${NC}  $tool: no instalado"
            echo "  [-]  $tool"
            add_check "warn"
        fi
    done
    echo ""

    # ── 2. Estado del firewall ──
    echo "## 2. Firewall"
    echo ""
    FW_OK=false
    if command -v firewall-cmd &>/dev/null && firewall-cmd --state &>/dev/null 2>&1; then
        echo -e "  ${GREEN}[OK]${NC} firewalld activo"
        FW_OK=true
        add_check "pass" 3
    elif command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        echo -e "  ${GREEN}[OK]${NC} ufw activo"
        FW_OK=true
        add_check "pass" 3
    elif command -v nft &>/dev/null && nft list ruleset 2>/dev/null | grep -q "table"; then
        echo -e "  ${GREEN}[OK]${NC} nftables activo"
        FW_OK=true
        add_check "pass" 3
    fi
    if ! $FW_OK; then
        echo -e "  ${RED}[FAIL]${NC} Sin firewall activo"
        add_check "fail" 3
    fi
    echo ""

    # ── 3. Parametros de seguridad de red ──
    echo "## 3. Parametros sysctl de red"
    echo ""
    declare -A CHECKS=(
        ["net.ipv4.ip_forward"]="0"
        ["net.ipv4.conf.all.accept_source_route"]="0"
        ["net.ipv4.conf.all.accept_redirects"]="0"
        ["net.ipv4.conf.all.rp_filter"]="1"
        ["net.ipv4.tcp_syncookies"]="1"
        ["net.ipv4.conf.all.log_martians"]="1"
    )
    for param in "${!CHECKS[@]}"; do
        current=$(sysctl -n "$param" 2>/dev/null || echo "N/A")
        expected="${CHECKS[$param]}"
        if [[ "$current" == "$expected" ]]; then
            echo -e "  ${GREEN}[OK]${NC} $param = $current"
            add_check "pass" 2
        else
            echo -e "  ${RED}[FAIL]${NC} $param = $current (esperado: $expected)"
            add_check "fail" 2
        fi
    done
    echo ""

    # ── 4. Puertos en escucha ──
    echo "## 4. Puertos en escucha"
    echo ""
    LISTEN_COUNT=$(ss -tlnp 2>/dev/null | tail -n +2 | wc -l)
    GLOBAL_BINDS=$(ss -tlnp 2>/dev/null | tail -n +2 | awk '{print $4}' | grep -c "^0.0.0.0:\|^\*:\|^\[::\]:" 2>/dev/null) || GLOBAL_BINDS=0
    echo "  Total puertos TCP en escucha: $LISTEN_COUNT"
    echo "  Binds globales (0.0.0.0/*): $GLOBAL_BINDS"
    if [[ $GLOBAL_BINDS -gt 5 ]]; then
        echo -e "  ${YELLOW}[WARN]${NC} Demasiados servicios en bind global"
        add_check "warn" 2
    else
        add_check "pass" 2
    fi
    echo ""

    # ── 5. Baseline drift ──
    echo "## 5. Estado de baseline"
    echo ""
    if [[ -f "${BASELINE_DIR}/latest-listening.txt" ]]; then
        echo -e "  ${GREEN}[OK]${NC} Baseline configurada"
        add_check "pass" 2

        DRIFT_COUNT=$(ls "${HISTORY_DIR}"/drift-*.txt 2>/dev/null | wc -l)
        RECENT_DRIFTS=$(find "${HISTORY_DIR}" -name "drift-*.txt" -mtime -7 2>/dev/null | wc -l)
        echo "  Drifts totales registrados: $DRIFT_COUNT"
        echo "  Drifts ultimos 7 dias: $RECENT_DRIFTS"
        if [[ $RECENT_DRIFTS -gt 3 ]]; then
            echo -e "  ${YELLOW}[WARN]${NC} Muchos drifts recientes - revisar estabilidad"
            add_check "warn"
        else
            add_check "pass"
        fi
    else
        echo -e "  ${YELLOW}[WARN]${NC} Sin baseline configurada"
        echo "  Ejecute: auditoria-red-baseline.sh --capture"
        add_check "warn" 2
    fi
    echo ""

    # ── 6. Auditorias programadas ──
    echo "## 6. Auditorias programadas"
    echo ""
    TIMERS_OK=0
    for timer in securizar-auditoria-red-diaria securizar-auditoria-red-semanal securizar-auditoria-red-mensual; do
        if systemctl is-enabled "${timer}.timer" &>/dev/null 2>&1; then
            echo -e "  ${GREEN}[OK]${NC} ${timer}: habilitado"
            ((TIMERS_OK++)) || true
        fi
    done
    if [[ $TIMERS_OK -ge 2 ]]; then
        add_check "pass" 2
    elif [[ -f /etc/cron.d/securizar-auditoria-red ]]; then
        echo -e "  ${GREEN}[OK]${NC} Cron de auditorias configurado"
        add_check "pass" 2
    else
        echo -e "  ${YELLOW}[WARN]${NC} Sin auditorias programadas"
        add_check "warn" 2
    fi
    echo ""

    # ── 7. Ultimo reporte ──
    echo "## 7. Reportes recientes"
    echo ""
    LATEST_REPORT=$(ls -t "${REPORT_DIR}"/auditoria-*.txt 2>/dev/null | head -1)
    if [[ -n "$LATEST_REPORT" ]]; then
        echo "  Ultimo reporte: $(basename "$LATEST_REPORT")"
        echo "  Fecha: $(stat -c '%y' "$LATEST_REPORT" 2>/dev/null | cut -d. -f1)"
        add_check "pass"
    else
        echo -e "  ${YELLOW}[INFO]${NC} Sin reportes de auditoria previos"
        add_check "warn"
    fi
    echo ""

    # ── Puntuacion global ──
    if [[ $TOTAL_CHECKS -gt 0 ]]; then
        MAX_SCORE=$((TOTAL_CHECKS * 10))
        # Ajustar por pesos ya aplicados
        PERCENTAGE=$((TOTAL_SCORE * 100 / MAX_SCORE))
        [[ $PERCENTAGE -gt 100 ]] && PERCENTAGE=100
    else
        PERCENTAGE=0
    fi

    echo "=========================================================="
    echo " PUNTUACION GLOBAL DE SEGURIDAD DE RED"
    echo "=========================================================="
    echo ""
    echo "  Checks realizados: $TOTAL_CHECKS"
    echo "  Pasados:   $TOTAL_PASS"
    echo "  Warnings:  $TOTAL_WARN"
    echo "  Fallidos:  $TOTAL_FAIL"
    echo ""
    echo "  Puntuacion: $PERCENTAGE/100"
    echo ""

    if [[ $PERCENTAGE -ge 80 ]]; then
        GRADE="A"
        echo -e "  ${GREEN}Grado: $GRADE - Buena postura de seguridad de red${NC}"
    elif [[ $PERCENTAGE -ge 60 ]]; then
        GRADE="B"
        echo -e "  ${YELLOW}Grado: $GRADE - Postura aceptable, hay mejoras posibles${NC}"
    elif [[ $PERCENTAGE -ge 40 ]]; then
        GRADE="C"
        echo -e "  ${YELLOW}Grado: $GRADE - Mejoras necesarias${NC}"
    else
        GRADE="D"
        echo -e "  ${RED}Grado: $GRADE - Postura deficiente, accion urgente${NC}"
    fi
    echo ""

    # ── Recomendaciones ──
    echo "## Recomendaciones priorizadas:"
    echo ""
    RECO=1
    if ! $FW_OK; then
        echo "  $RECO. [CRITICO] Activar un firewall (firewalld, ufw o nftables)"
        ((RECO++)) || true
    fi
    if [[ ! -f "${BASELINE_DIR}/latest-listening.txt" ]]; then
        echo "  $RECO. [ALTA] Capturar baseline de red: auditoria-red-baseline.sh --capture"
        ((RECO++)) || true
    fi
    if [[ $GLOBAL_BINDS -gt 5 ]]; then
        echo "  $RECO. [MEDIA] Reducir servicios con bind global (0.0.0.0)"
        ((RECO++)) || true
    fi
    if [[ $TIMERS_OK -lt 2 ]] && [[ ! -f /etc/cron.d/securizar-auditoria-red ]]; then
        echo "  $RECO. [MEDIA] Configurar auditorias periodicas automatizadas"
        ((RECO++)) || true
    fi
    if [[ $RECO -eq 1 ]]; then
        echo "  Sin recomendaciones criticas. Mantener las auditorias periodicas."
    fi

} 2>&1 | tee "${OUTFILE}.txt"

# ── Exportacion JSON para SIEM ──
if [[ "$FORMAT" == "--json" ]]; then
    cat > "${OUTFILE}.json" << EOFJSON
{
  "timestamp": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "kernel": "$(uname -r)",
  "audit_type": "network_infrastructure",
  "score": $PERCENTAGE,
  "grade": "$GRADE",
  "checks_total": $TOTAL_CHECKS,
  "checks_pass": $TOTAL_PASS,
  "checks_warn": $TOTAL_WARN,
  "checks_fail": $TOTAL_FAIL,
  "firewall_active": $FW_OK,
  "listening_ports_tcp": $LISTEN_COUNT,
  "global_binds": $GLOBAL_BINDS,
  "baseline_configured": $(test -f "${BASELINE_DIR}/latest-listening.txt" && echo true || echo false)
}
EOFJSON
    echo ""
    echo -e "${GREEN}JSON exportado: ${OUTFILE}.json${NC}"
fi

echo ""
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "  Reporte: ${CYAN}${OUTFILE}.txt${NC}"
[[ "$FORMAT" == "--json" ]] && echo -e "  JSON:    ${CYAN}${OUTFILE}.json${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
ENDSCRIPT
    chmod +x "${TOOLS_DIR}/auditoria-red-reporte-global.sh"
    log_change "Creado" "${TOOLS_DIR}/auditoria-red-reporte-global.sh"

    # ── Script de limpieza de reportes antiguos ──
    cat > "${TOOLS_DIR}/auditoria-red-limpieza.sh" << 'ENDSCRIPT'
#!/bin/bash
# auditoria-red-limpieza.sh - Limpieza de reportes y scans antiguos
set -euo pipefail
[[ ":$PATH:" == *":/usr/local/bin:"* ]] || export PATH="/usr/local/bin:$PATH"

CONF_DIR="/etc/securizar/auditoria-red"
REPORT_RETENTION_DAYS=90
[[ -f "${CONF_DIR}/auditoria-programada.conf" ]] && source "${CONF_DIR}/auditoria-programada.conf"

echo "Limpiando archivos de auditoria con mas de ${REPORT_RETENTION_DAYS} dias..."

for dir in /var/lib/securizar/auditoria-red/reportes /var/lib/securizar/auditoria-red/scans \
           /var/lib/securizar/auditoria-red/baseline/history; do
    if [[ -d "$dir" ]]; then
        COUNT=$(find "$dir" -type f -mtime "+${REPORT_RETENTION_DAYS}" 2>/dev/null | wc -l)
        if [[ $COUNT -gt 0 ]]; then
            find "$dir" -type f -mtime "+${REPORT_RETENTION_DAYS}" -delete 2>/dev/null
            echo "  $dir: $COUNT archivos eliminados"
        fi
    fi
done
echo "Limpieza completada"
ENDSCRIPT
    chmod +x "${TOOLS_DIR}/auditoria-red-limpieza.sh"
    log_change "Creado" "${TOOLS_DIR}/auditoria-red-limpieza.sh"

    log_info "Sistema de reporte consolidado creado"
else
    log_skip "Sistema de reporte consolidado"
fi
fi # S10

# ============================================================
# RESUMEN FINAL
# ============================================================
log_section "RESUMEN DEL MODULO 67"

echo ""
echo -e "  ${BOLD}Herramientas de auditoria de infraestructura de red:${NC}"
echo ""

for cmd in nmap arp-scan nbtscan testssl.sh socat snmpwalk; do
    if command -v "$cmd" &>/dev/null; then
        echo -e "    ${GREEN}+${NC} $cmd: $(command -v "$cmd")"
    else
        echo -e "    ${YELLOW}-${NC} $cmd: no instalado"
    fi
done

echo ""
echo -e "  ${BOLD}Scripts creados:${NC}"
echo ""
for script in auditoria-red-descubrimiento auditoria-red-puertos auditoria-red-tls \
              auditoria-red-snmp auditoria-red-config auditoria-red-inventario \
              auditoria-red-baseline auditoria-red-programada auditoria-red-reporte-global \
              auditoria-red-limpieza; do
    if [[ -x "/usr/local/bin/${script}.sh" ]]; then
        echo -e "    ${GREEN}+${NC} ${script}.sh"
    fi
done

echo ""
echo -e "  ${BOLD}Configuraciones:${NC}"
echo ""
for conf in puertos-autorizados.conf politica-tls.conf servicios-aprobados.conf \
            auditoria-programada.conf tls-endpoints.txt; do
    if [[ -f "${CONF_DIR}/${conf}" ]]; then
        echo -e "    ${GREEN}+${NC} ${CONF_DIR}/${conf}"
    fi
done

echo ""
echo -e "  ${BOLD}Uso rapido:${NC}"
echo ""
echo -e "    ${CYAN}auditoria-red-descubrimiento.sh${NC}            Descubrir hosts en la red"
echo -e "    ${CYAN}auditoria-red-puertos.sh localhost${NC}          Auditar puertos locales"
echo -e "    ${CYAN}auditoria-red-tls.sh example.com${NC}            Auditar TLS de un endpoint"
echo -e "    ${CYAN}auditoria-red-snmp.sh 192.168.1.0/24${NC}       Auditar SNMP en la subred"
echo -e "    ${CYAN}auditoria-red-config.sh${NC}                     Auditar configuracion de red"
echo -e "    ${CYAN}auditoria-red-inventario.sh localhost${NC}       Inventario de servicios"
echo -e "    ${CYAN}auditoria-red-baseline.sh --capture${NC}         Capturar baseline"
echo -e "    ${CYAN}auditoria-red-baseline.sh --compare${NC}         Detectar drift"
echo -e "    ${CYAN}auditoria-red-reporte-global.sh${NC}             Reporte consolidado"
echo -e "    ${CYAN}auditoria-red-programada.sh completa${NC}        Auditoria completa"
echo ""

show_changes_summary
