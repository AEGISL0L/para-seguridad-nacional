#!/bin/bash
# ============================================================
# CIBERINTELIGENCIA PROACTIVA - Modulo 37
# Linux Multi-Distro (openSUSE, Debian/Ubuntu, RHEL/Fedora, Arch)
# ============================================================
# Convierte la suite Securizar de reactiva a proactiva:
#   - Enriquecimiento multi-fuente de IoC
#   - Inteligencia de red en tiempo real
#   - Inteligencia DNS (DGA, tunneling, NRD)
#   - Monitorizacion de superficie de ataque
#   - Alertas tempranas y CVE monitoring
#   - Informes de inteligencia automatizados
#   - Monitorizacion de credenciales expuestas
#   - Integracion SOAR
#
# Secciones:
#   S1 - Motor de Enriquecimiento de IoC
#   S2 - Inteligencia de Red Proactiva
#   S3 - Inteligencia DNS
#   S4 - Auto-Monitorizacion de Superficie de Ataque
#   S5 - Sistema de Alerta Temprana
#   S6 - Informes de Inteligencia Automatizados
#   S7 - Monitorizacion de Credenciales Expuestas
#   S8 - Integracion con SOAR y Monitorizacion Existente
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps

# ── Variables ────────────────────────────────────────────────
CIBERINT_BASE="/var/lib/ciberinteligencia"
CIBERINT_LIB_DIR="/usr/local/lib/ciberinteligencia"
CIBERINT_BIN="/usr/local/bin"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   CIBERINTELIGENCIA PROACTIVA - Modulo 37                 ║"
echo "║   Inteligencia de amenazas activa y automatizada          ║"
echo "║   16 scripts, 6 timers systemd, crons                    ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

echo "Capacidades que se instalaran:"
echo ""
echo -e "  ${CYAN}S1${NC} Motor de Enriquecimiento de IoC (multi-fuente, scoring 0-100)"
echo -e "  ${CYAN}S2${NC} Inteligencia de Red Proactiva (GeoIP, correlacion)"
echo -e "  ${CYAN}S3${NC} Inteligencia DNS (DGA, tunneling, NRD)"
echo -e "  ${CYAN}S4${NC} Monitorizacion de Superficie de Ataque (cambios)"
echo -e "  ${CYAN}S5${NC} Sistema de Alerta Temprana (retroactive matching, CVE)"
echo -e "  ${CYAN}S6${NC} Informes de Inteligencia (diario/semanal)"
echo -e "  ${CYAN}S7${NC} Monitorizacion de Credenciales Expuestas"
echo -e "  ${CYAN}S8${NC} Integracion SOAR y Monitorizacion"
echo ""

# ============================================================
# DEPENDENCIAS
# ============================================================
log_section "DEPENDENCIAS"

echo "Se verificaran/instalaran: curl, jq, openssl, bc, bind-utils/dnsutils"
echo ""

DEPS_NEEDED=""
for dep in curl jq openssl bc; do
    if command -v "$dep" &>/dev/null; then
        echo -e "  ${GREEN}OK${NC}  $dep ya instalado"
    else
        echo -e "  ${YELLOW}--${NC}  $dep no encontrado"
        DEPS_NEEDED+=" $dep"
    fi
done

# dig puede estar en bind-utils o dnsutils
if command -v dig &>/dev/null; then
    echo -e "  ${GREEN}OK${NC}  dig ya instalado"
else
    echo -e "  ${YELLOW}--${NC}  dig no encontrado"
    # Intentar nombre de paquete segun distro
    if command -v zypper &>/dev/null; then
        DEPS_NEEDED+=" bind-utils"
    elif command -v apt-get &>/dev/null; then
        DEPS_NEEDED+=" dnsutils"
    else
        DEPS_NEEDED+=" bind-utils"
    fi
fi

if [[ -n "$DEPS_NEEDED" ]]; then
    echo ""
    if ask "Instalar dependencias faltantes:${DEPS_NEEDED}?"; then
        pkg_install $DEPS_NEEDED || {
            log_error "Error instalando dependencias. Verifica repositorios."
        }
        log_info "Dependencias instaladas"
    else
        log_skip "Dependencias faltantes:${DEPS_NEEDED}"
    fi
else
    log_info "Todas las dependencias presentes"
fi

# ============================================================
# ESTRUCTURA DE DIRECTORIOS
# ============================================================
log_section "ESTRUCTURA DE DIRECTORIOS"

echo "Se creara la estructura de datos de ciberinteligencia:"
echo "  $CIBERINT_BASE/"
echo "  ├── cache/{ioc,dns,geoip,cve}"
echo "  ├── config/"
echo "  ├── data/{attack-surface,reports,alerts,credentials}"
echo "  └── log/"
echo ""

if ask "Crear estructura de directorios?"; then
    mkdir -p "$CIBERINT_BASE"/cache/{ioc,dns,geoip,cve}
    mkdir -p "$CIBERINT_BASE"/config
    mkdir -p "$CIBERINT_BASE"/data/{attack-surface,reports,alerts,credentials}
    mkdir -p "$CIBERINT_BASE"/log
    mkdir -p "$CIBERINT_LIB_DIR"
    log_change "Creado" "$CIBERINT_BASE/ (estructura completa)"

    # Permisos restrictivos
    chmod 750 "$CIBERINT_BASE"
    log_change "Permisos" "$CIBERINT_BASE -> 750"
    chmod 700 "$CIBERINT_BASE/config"
    log_change "Permisos" "$CIBERINT_BASE/config -> 700"
    chmod 750 "$CIBERINT_BASE/data"
    log_change "Permisos" "$CIBERINT_BASE/data -> 750"

    # Crear historial de conexiones
    touch "$CIBERINT_BASE/data/connection-history.log"
    chmod 640 "$CIBERINT_BASE/data/connection-history.log"
    log_change "Permisos" "$CIBERINT_BASE/data/connection-history.log -> 640"

    log_info "Estructura de directorios creada"
else
    log_skip "Estructura de directorios de ciberinteligencia"
fi

# ============================================================
# CONFIGURACION BASE
# ============================================================
log_section "CONFIGURACION"

if [[ ! -f "$CIBERINT_BASE/config/ciberint.conf" ]]; then
    echo "Se creara la configuracion base..."
    echo ""

    cat > "$CIBERINT_BASE/config/ciberint.conf" << 'EOFCONF'
# ============================================================
# Ciberinteligencia Proactiva - Configuracion principal
# ============================================================

# TTL de cache en segundos (default: 24h)
CIBERINT_CACHE_TTL=86400

# Umbral para enriquecer IPs (0-100, default: 30)
CIBERINT_ENRICH_THRESHOLD=30

# Umbral para generar alertas (0-100, default: 50)
CIBERINT_ALERT_THRESHOLD=50

# Umbral para auto-bloqueo SOAR (0-100, default: 75)
CIBERINT_BLOCK_THRESHOLD=75

# Rate limit entre consultas API (ms, default: 1500)
CIBERINT_RATE_LIMIT_MS=1500

# Dominios propios para monitorizar superficie de ataque (separados por espacio)
CIBERINT_OWN_DOMAINS=""

# IPs propias para monitorizar (separados por espacio)
CIBERINT_OWN_IPS=""

# Puertos propios a monitorizar en Shodan InternetDB
CIBERINT_EXPECTED_PORTS="22 80 443"

# Email para notificaciones (opcional)
CIBERINT_NOTIFY_EMAIL=""

# Directorio de reportes
CIBERINT_REPORTS_DIR="/var/lib/ciberinteligencia/data/reports"

# Dias de retencion historial de conexiones
CIBERINT_HISTORY_DAYS=90
EOFCONF

    chmod 640 "$CIBERINT_BASE/config/ciberint.conf"
    log_change "Creado" "$CIBERINT_BASE/config/ciberint.conf"
    log_change "Permisos" "$CIBERINT_BASE/config/ciberint.conf -> 640"
    log_info "Configuracion base creada"
fi

if [[ ! -f "$CIBERINT_BASE/config/api-keys.conf" ]]; then
    cat > "$CIBERINT_BASE/config/api-keys.conf" << 'EOFKEYS'
# Claves API opcionales para enriquecimiento
# Formato: SERVICIO=clave
# Descomenta y rellena las que tengas disponibles:
#ABUSEIPDB=tu-clave-aqui
#VIRUSTOTAL=tu-clave-aqui
EOFKEYS
    chmod 600 "$CIBERINT_BASE/config/api-keys.conf"
    log_change "Creado" "$CIBERINT_BASE/config/api-keys.conf"
    log_change "Permisos" "$CIBERINT_BASE/config/api-keys.conf -> 600"
    log_info "Fichero de claves API creado (editar para activar servicios)"
fi

if [[ ! -f "$CIBERINT_BASE/config/high-risk-countries.conf" ]]; then
    cat > "$CIBERINT_BASE/config/high-risk-countries.conf" << 'EOFHR'
# Paises de alto riesgo para scoring (+5 puntos)
# Codigos ISO 3166-1 alpha-2, uno por linea
CN
RU
KP
IR
EOFHR
    chmod 640 "$CIBERINT_BASE/config/high-risk-countries.conf"
    log_change "Creado" "$CIBERINT_BASE/config/high-risk-countries.conf"
    log_change "Permisos" "$CIBERINT_BASE/config/high-risk-countries.conf -> 640"
fi

if [[ ! -f "$CIBERINT_BASE/config/scoring-weights.conf" ]]; then
    cat > "$CIBERINT_BASE/config/scoring-weights.conf" << 'EOFSW'
# Pesos de scoring para enriquecimiento de IoC
WEIGHT_FEED_LOCAL=40
WEIGHT_PORT_SUSPICIOUS=5
WEIGHT_CVE=10
WEIGHT_ABUSEIPDB_MAX=20
WEIGHT_VT_PER_ENGINE=3
WEIGHT_VT_MAX=20
WEIGHT_DATACENTER_ASN=10
WEIGHT_HIGH_RISK_COUNTRY=5
WEIGHT_EXTRA_FEED=5
EOFSW
    chmod 640 "$CIBERINT_BASE/config/scoring-weights.conf"
    log_change "Creado" "$CIBERINT_BASE/config/scoring-weights.conf"
    log_change "Permisos" "$CIBERINT_BASE/config/scoring-weights.conf -> 640"
fi

# ============================================================
# INSTALAR BIBLIOTECA COMPARTIDA
# ============================================================
log_section "BIBLIOTECA COMPARTIDA"

echo "Instalando biblioteca en $CIBERINT_LIB_DIR/"
cp "${SCRIPT_DIR}/lib/ciberint-lib.sh" "$CIBERINT_LIB_DIR/ciberint-lib.sh"
log_change "Creado" "$CIBERINT_LIB_DIR/ciberint-lib.sh"
chmod 644 "$CIBERINT_LIB_DIR/ciberint-lib.sh"
log_change "Permisos" "$CIBERINT_LIB_DIR/ciberint-lib.sh -> 644"
log_info "Biblioteca compartida instalada"

# ============================================================
# S1: MOTOR DE ENRIQUECIMIENTO DE IoC
# ============================================================
log_section "S1: MOTOR DE ENRIQUECIMIENTO DE IoC"

echo "Instala el script de enriquecimiento multi-fuente para IPs/dominios."
echo "Fuentes: Shodan InternetDB, ip-api.com, ipinfo.io, AbuseIPDB, VirusTotal"
echo "Scoring compuesto 0-100 con cache TTL 24h"
echo ""

if ask "Instalar motor de enriquecimiento de IoC?"; then

cat > "$CIBERINT_BIN/ciberint-enriquecer-ioc.sh" << 'EOFS1'
#!/bin/bash
# ============================================================
# ciberint-enriquecer-ioc.sh - Enriquecimiento multi-fuente de IoC
# Uso: ciberint-enriquecer-ioc.sh <IP|dominio> [--json] [--no-cache]
# ============================================================
set -uo pipefail

source /usr/local/lib/ciberinteligencia/ciberint-lib.sh

INDICATOR="${1:-}"
FLAG_JSON=0
FLAG_NOCACHE=0

for arg in "$@"; do
    case "$arg" in
        --json)     FLAG_JSON=1 ;;
        --no-cache) FLAG_NOCACHE=1 ;;
    esac
done

if [[ -z "$INDICATOR" || "$INDICATOR" == --* ]]; then
    echo "Uso: ciberint-enriquecer-ioc.sh <IP|dominio> [--json] [--no-cache]"
    exit 1
fi

# Cargar pesos
source "$CIBERINT_WEIGHTS" 2>/dev/null || true
WEIGHT_FEED_LOCAL="${WEIGHT_FEED_LOCAL:-40}"
WEIGHT_PORT_SUSPICIOUS="${WEIGHT_PORT_SUSPICIOUS:-5}"
WEIGHT_CVE="${WEIGHT_CVE:-10}"
WEIGHT_ABUSEIPDB_MAX="${WEIGHT_ABUSEIPDB_MAX:-20}"
WEIGHT_VT_PER_ENGINE="${WEIGHT_VT_PER_ENGINE:-3}"
WEIGHT_VT_MAX="${WEIGHT_VT_MAX:-20}"
WEIGHT_DATACENTER_ASN="${WEIGHT_DATACENTER_ASN:-10}"
WEIGHT_HIGH_RISK_COUNTRY="${WEIGHT_HIGH_RISK_COUNTRY:-5}"
WEIGHT_EXTRA_FEED="${WEIGHT_EXTRA_FEED:-5}"

# Si es dominio, resolver a IP
TARGET_IP="$INDICATOR"
TARGET_TYPE="ip"
if ! ciberint_is_valid_ip "$INDICATOR"; then
    TARGET_TYPE="domain"
    TARGET_IP=$(dig +short "$INDICATOR" A 2>/dev/null | head -1)
    if [[ -z "$TARGET_IP" ]] || ! ciberint_is_valid_ip "$TARGET_IP"; then
        echo "No se pudo resolver $INDICATOR a una IP valida"
        exit 1
    fi
fi

# Cache check
CACHE_KEY=$(echo "$TARGET_IP" | tr '.' '_')
if [[ $FLAG_NOCACHE -eq 0 ]]; then
    cached=$(ciberint_cache_get "ioc" "$CACHE_KEY" 2>/dev/null) && {
        echo "$cached"
        exit 0
    }
fi

# ── Recopilar datos ──────────────────────────────────────────
SCORE=0
DETAILS=""
FEEDS_MATCHED=""
SHODAN_PORTS=""
SHODAN_CVES=""
COUNTRY="??"
ASN="??"
ORG="??"
IS_DATACENTER=0

# 1. Feeds locales
FEED_HIT=0
if [[ -f "$IOC_LISTS_DIR/malicious-ips.txt" ]]; then
    if grep -qF "$TARGET_IP" "$IOC_LISTS_DIR/malicious-ips.txt" 2>/dev/null; then
        SCORE=$(( SCORE + WEIGHT_FEED_LOCAL ))
        FEEDS_MATCHED+="malicious-ips "
        FEED_HIT=1
    fi
fi

# Feeds adicionales
EXTRA_FEEDS=0
if [[ -d "$IOC_LISTS_DIR" ]]; then
    for feed in "$IOC_LISTS_DIR"/*.txt; do
        [[ ! -f "$feed" ]] && continue
        fname=$(basename "$feed")
        [[ "$fname" == "malicious-ips.txt" ]] && continue
        if grep -qF "$TARGET_IP" "$feed" 2>/dev/null; then
            FEEDS_MATCHED+="$fname "
            EXTRA_FEEDS=$(( EXTRA_FEEDS + 1 ))
        fi
    done
    SCORE=$(( SCORE + EXTRA_FEEDS * WEIGHT_EXTRA_FEED ))
fi

# 2. ipsets activos
if command -v ipset &>/dev/null; then
    for setname in $(ipset list -n 2>/dev/null); do
        if ipset test "$setname" "$TARGET_IP" 2>/dev/null; then
            [[ $FEED_HIT -eq 0 ]] && SCORE=$(( SCORE + WEIGHT_FEED_LOCAL ))
            FEEDS_MATCHED+="ipset:$setname "
            break
        fi
    done
fi

# 3. Shodan InternetDB (sin clave, sin limites estrictos)
SHODAN_DATA=$(ciberint_api_get "https://internetdb.shodan.io/$TARGET_IP" 2>/dev/null) || SHODAN_DATA=""
if [[ -n "$SHODAN_DATA" ]] && echo "$SHODAN_DATA" | jq -e '.ip' &>/dev/null; then
    SHODAN_PORTS=$(echo "$SHODAN_DATA" | jq -r '.ports // [] | .[]' 2>/dev/null | tr '\n' ',' | sed 's/,$//')
    SHODAN_CVES=$(echo "$SHODAN_DATA" | jq -r '.vulns // [] | .[]' 2>/dev/null | tr '\n' ',' | sed 's/,$//')

    # Puertos sospechosos (+5 por puerto no estandar)
    SUSPICIOUS_PORTS="4444 5555 6666 7777 8888 9999 1337 31337 12345 54321 6667 6697 4443 8443 8080 3389"
    IFS=',' read -ra port_arr <<< "$SHODAN_PORTS"
    for p in "${port_arr[@]}"; do
        for sp in $SUSPICIOUS_PORTS; do
            if [[ "$p" == "$sp" ]]; then
                SCORE=$(( SCORE + WEIGHT_PORT_SUSPICIOUS ))
                break
            fi
        done
    done

    # CVEs (+10 por CVE, max 30)
    CVE_COUNT=$(echo "$SHODAN_CVES" | tr ',' '\n' | grep -c "CVE-" 2>/dev/null || echo 0)
    CVE_SCORE=$(( CVE_COUNT * WEIGHT_CVE ))
    [[ $CVE_SCORE -gt 30 ]] && CVE_SCORE=30
    SCORE=$(( SCORE + CVE_SCORE ))
fi

# 4. ip-api.com (sin clave, 45/min)
IPAPI_DATA=$(ciberint_api_get "http://ip-api.com/json/$TARGET_IP?fields=country,countryCode,isp,org,as,hosting" 2>/dev/null) || IPAPI_DATA=""
if [[ -n "$IPAPI_DATA" ]] && echo "$IPAPI_DATA" | jq -e '.countryCode' &>/dev/null; then
    COUNTRY=$(echo "$IPAPI_DATA" | jq -r '.countryCode // "??"' 2>/dev/null)
    ASN=$(echo "$IPAPI_DATA" | jq -r '.as // "??"' 2>/dev/null | awk '{print $1}')
    ORG=$(echo "$IPAPI_DATA" | jq -r '.org // "??"' 2>/dev/null)
    IS_DATACENTER=$(echo "$IPAPI_DATA" | jq -r '.hosting // false' 2>/dev/null)

    # Datacenter/hosting ASN (+10)
    if [[ "$IS_DATACENTER" == "true" ]]; then
        SCORE=$(( SCORE + WEIGHT_DATACENTER_ASN ))
    fi

    # Pais alto riesgo (+5)
    if ciberint_is_high_risk_country "$COUNTRY"; then
        SCORE=$(( SCORE + WEIGHT_HIGH_RISK_COUNTRY ))
    fi
fi

# 5. AbuseIPDB (opcional, con clave)
ABUSEIPDB_SCORE=0
ABUSEIPDB_KEY=$(ciberint_get_api_key "ABUSEIPDB" 2>/dev/null) || ABUSEIPDB_KEY=""
if [[ -n "$ABUSEIPDB_KEY" ]]; then
    ABUSE_DATA=$(curl -sS --max-time 10 \
        -H "Key: $ABUSEIPDB_KEY" -H "Accept: application/json" \
        "https://api.abuseipdb.com/api/v2/check?ipAddress=$TARGET_IP&maxAgeInDays=90" 2>/dev/null) || ABUSE_DATA=""
    if [[ -n "$ABUSE_DATA" ]]; then
        ABUSEIPDB_SCORE=$(echo "$ABUSE_DATA" | jq -r '.data.abuseConfidenceScore // 0' 2>/dev/null)
        # Escalar de 0-100 a 0-WEIGHT_ABUSEIPDB_MAX
        ABUSE_WEIGHTED=$(( ABUSEIPDB_SCORE * WEIGHT_ABUSEIPDB_MAX / 100 ))
        SCORE=$(( SCORE + ABUSE_WEIGHTED ))
    fi
fi

# 6. VirusTotal (opcional, con clave)
VT_POSITIVES=0
VT_KEY=$(ciberint_get_api_key "VIRUSTOTAL" 2>/dev/null) || VT_KEY=""
if [[ -n "$VT_KEY" ]]; then
    VT_DATA=$(curl -sS --max-time 10 \
        -H "x-apikey: $VT_KEY" \
        "https://www.virustotal.com/api/v3/ip_addresses/$TARGET_IP" 2>/dev/null) || VT_DATA=""
    if [[ -n "$VT_DATA" ]]; then
        VT_POSITIVES=$(echo "$VT_DATA" | jq '[.data.attributes.last_analysis_results | to_entries[] | select(.value.category == "malicious")] | length' 2>/dev/null || echo 0)
        VT_WEIGHTED=$(( VT_POSITIVES * WEIGHT_VT_PER_ENGINE ))
        [[ $VT_WEIGHTED -gt $WEIGHT_VT_MAX ]] && VT_WEIGHTED=$WEIGHT_VT_MAX
        SCORE=$(( SCORE + VT_WEIGHTED ))
    fi
fi

# Cap score
[[ $SCORE -gt 100 ]] && SCORE=100

SEVERITY=$(ciberint_severity "$SCORE")

# ── Resultado ────────────────────────────────────────────────
RESULT=$(cat << EOFRESULT
{
  "indicator": "$INDICATOR",
  "ip": "$TARGET_IP",
  "type": "$TARGET_TYPE",
  "score": $SCORE,
  "severity": "$SEVERITY",
  "country": "$COUNTRY",
  "asn": "$ASN",
  "org": "$ORG",
  "is_datacenter": $( [[ "$IS_DATACENTER" == "true" ]] && echo "true" || echo "false" ),
  "feeds_matched": "$FEEDS_MATCHED",
  "shodan_ports": "$SHODAN_PORTS",
  "shodan_cves": "$SHODAN_CVES",
  "abuseipdb_score": $ABUSEIPDB_SCORE,
  "vt_positives": $VT_POSITIVES,
  "timestamp": "$(date -Iseconds)"
}
EOFRESULT
)

# Cache result
ciberint_cache_set "ioc" "$CACHE_KEY" "$RESULT"

if [[ $FLAG_JSON -eq 1 ]]; then
    echo "$RESULT"
else
    echo ""
    echo -e "${CYAN}══ Enriquecimiento IoC: $INDICATOR ══${NC}"
    echo ""
    printf "  %-18s %s\n" "IP:" "$TARGET_IP"
    printf "  %-18s %s\n" "Tipo:" "$TARGET_TYPE"
    printf "  %-18s %s\n" "Pais:" "$COUNTRY"
    printf "  %-18s %s\n" "ASN:" "$ASN"
    printf "  %-18s %s\n" "Organizacion:" "$ORG"
    printf "  %-18s %s\n" "Datacenter:" "$IS_DATACENTER"
    echo ""
    printf "  %-18s %s\n" "Feeds IoC:" "${FEEDS_MATCHED:-ninguno}"
    printf "  %-18s %s\n" "Puertos Shodan:" "${SHODAN_PORTS:-ninguno}"
    printf "  %-18s %s\n" "CVEs Shodan:" "${SHODAN_CVES:-ninguno}"
    printf "  %-18s %s\n" "AbuseIPDB:" "$ABUSEIPDB_SCORE%"
    printf "  %-18s %s\n" "VT positivos:" "$VT_POSITIVES"
    echo ""

    # Score visual
    local_color="$GREEN"
    [[ $SCORE -ge 26 ]] && local_color="$YELLOW"
    [[ $SCORE -ge 51 ]] && local_color='\033[0;31m'
    [[ $SCORE -ge 76 ]] && local_color='\033[1;31m'

    echo -e "  SCORE: ${local_color}${BOLD}$SCORE/100${NC} [$SEVERITY]"

    # Barra visual
    local bar=""
    for ((i=0; i<SCORE; i+=5)); do bar+="█"; done
    for ((i=SCORE; i<100; i+=5)); do bar+="░"; done
    echo -e "  ${local_color}${bar}${NC}"
    echo ""
fi

# Alerta si supera umbral
if [[ $SCORE -ge $CIBERINT_ALERT_THRESHOLD ]]; then
    ciberint_alert "$SEVERITY" "enriquecer-ioc" \
        "IoC $INDICATOR score=$SCORE" \
        "IP=$TARGET_IP Country=$COUNTRY ASN=$ASN Feeds=$FEEDS_MATCHED CVEs=$SHODAN_CVES"
fi
EOFS1

chmod 755 "$CIBERINT_BIN/ciberint-enriquecer-ioc.sh"
log_change "Creado" "$CIBERINT_BIN/ciberint-enriquecer-ioc.sh"
log_change "Permisos" "$CIBERINT_BIN/ciberint-enriquecer-ioc.sh -> 755"
log_info "S1: Motor de enriquecimiento instalado"

else
    log_skip "Motor de enriquecimiento de IoC (S1)"
fi  # S1

# ============================================================
# S2: INTELIGENCIA DE RED PROACTIVA
# ============================================================
log_section "S2: INTELIGENCIA DE RED PROACTIVA"

echo "Analiza conexiones activas cruzando con GeoIP, feeds IoC y enriquecimiento."
echo "Scripts: ciberint-red-inteligente.sh, ciberint-geoip-update.sh"
echo "Timer: cada 15 minutos"
echo ""

if ask "Instalar inteligencia de red proactiva?"; then

# ── ciberint-red-inteligente.sh ──
cat > "$CIBERINT_BIN/ciberint-red-inteligente.sh" << 'EOFS2A'
#!/bin/bash
# ============================================================
# ciberint-red-inteligente.sh - Inteligencia de red proactiva
# Analiza conexiones activas contra GeoIP, feeds, enriquecimiento
# ============================================================
set -uo pipefail

source /usr/local/lib/ciberinteligencia/ciberint-lib.sh

LOG_FILE="$CIBERINT_LOG/red-inteligente.log"
HISTORY_FILE="$CIBERINT_DATA/connection-history.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Recoger conexiones ESTABLISHED
declare -A SEEN_IPS
ALERTS_GENERATED=0

echo ""
echo -e "${CYAN}══ Inteligencia de Red - $TIMESTAMP ══${NC}"
echo ""
printf "  ${BOLD}%-16s %-7s %-20s %-4s %-8s %-12s %-6s %-10s${NC}\n" \
    "IP" "PUERTO" "PROCESO" "PAIS" "ASN" "FEEDS" "SCORE" "VEREDICTO"
echo -e "  ${DIM}──────────────────────────────────────────────────────────────────────────────────${NC}"

while IFS= read -r line; do
    # Parsear ss output: State Recv-Q Send-Q Local:Port Peer:Port Process
    PEER=$(echo "$line" | awk '{print $5}')
    PROCESS=$(echo "$line" | awk '{print $6}' | sed 's/users:(("\(.*\)",.*/\1/' | head -c 18)

    # Extraer IP y puerto
    REMOTE_IP=$(echo "$PEER" | rev | cut -d: -f2- | rev)
    REMOTE_PORT=$(echo "$PEER" | rev | cut -d: -f1 | rev)

    # Limpiar brackets IPv6-mapped
    REMOTE_IP="${REMOTE_IP#\[}"
    REMOTE_IP="${REMOTE_IP%\]}"
    REMOTE_IP="${REMOTE_IP#::ffff:}"

    # Validar y saltar privadas
    ciberint_is_valid_ip "$REMOTE_IP" || continue
    ciberint_is_private_ip "$REMOTE_IP" && continue

    # Deduplicar
    [[ -n "${SEEN_IPS[$REMOTE_IP]:-}" ]] && continue
    SEEN_IPS[$REMOTE_IP]=1

    # Historial
    echo "$TIMESTAMP $REMOTE_IP $REMOTE_PORT $PROCESS" >> "$HISTORY_FILE" 2>/dev/null

    # GeoIP
    COUNTRY=$(ciberint_geoip_lookup "$REMOTE_IP" 2>/dev/null || echo "??")

    # Feed check rapido
    FEED_HIT=""
    if [[ -f "$IOC_LISTS_DIR/malicious-ips.txt" ]]; then
        grep -qF "$REMOTE_IP" "$IOC_LISTS_DIR/malicious-ips.txt" 2>/dev/null && FEED_HIT="IoC"
    fi

    # Score rapido local
    SCORE=$(ciberint_score_ip "$REMOTE_IP" 2>/dev/null || echo "0")

    # Si score > umbral, enriquecer con S1
    ASN_SHORT="--"
    if [[ $SCORE -ge $CIBERINT_ENRICH_THRESHOLD ]]; then
        ENRICH=$("$CIBERINT_BIN/ciberint-enriquecer-ioc.sh" "$REMOTE_IP" --json 2>/dev/null) || ENRICH=""
        if [[ -n "$ENRICH" ]]; then
            SCORE=$(echo "$ENRICH" | jq -r '.score // 0' 2>/dev/null)
            ASN_SHORT=$(echo "$ENRICH" | jq -r '.asn // "--"' 2>/dev/null | head -c 8)
            COUNTRY=$(echo "$ENRICH" | jq -r '.country // "??"' 2>/dev/null)
            FEED_HIT=$(echo "$ENRICH" | jq -r '.feeds_matched // ""' 2>/dev/null | head -c 10)
        fi
    fi

    SEVERITY=$(ciberint_severity "$SCORE")
    VEREDICTO="$SEVERITY"

    # Color segun severidad
    case "$SEVERITY" in
        CRITICAL) COLOR='\033[1;31m' ;;
        HIGH)     COLOR='\033[0;31m' ;;
        MEDIUM)   COLOR="$YELLOW" ;;
        *)        COLOR="$DIM" ;;
    esac

    printf "  %-16s %-7s %-20s %-4s %-8s %-12s ${COLOR}%-6s %-10s${NC}\n" \
        "$REMOTE_IP" "$REMOTE_PORT" "${PROCESS:-?}" "$COUNTRY" "$ASN_SHORT" \
        "${FEED_HIT:---}" "$SCORE" "$VEREDICTO"

    # Alertas
    if [[ $SCORE -ge $CIBERINT_ALERT_THRESHOLD ]]; then
        ciberint_alert "$SEVERITY" "red-inteligente" \
            "Conexion sospechosa $REMOTE_IP:$REMOTE_PORT ($PROCESS)" \
            "Score=$SCORE Country=$COUNTRY ASN=$ASN_SHORT"
        ALERTS_GENERATED=$(( ALERTS_GENERATED + 1 ))
    fi

done < <(ss -tnp state established 2>/dev/null | tail -n +2)

echo ""
echo -e "  ${DIM}IPs analizadas: ${#SEEN_IPS[@]} | Alertas: $ALERTS_GENERATED${NC}"

# Limpiar historial viejo
if [[ -f "$HISTORY_FILE" ]]; then
    CUTOFF=$(date -d "-${CIBERINT_HISTORY_DAYS:-90} days" '+%Y-%m-%d' 2>/dev/null || date '+%Y-%m-%d')
    awk -v cutoff="$CUTOFF" '$1 >= cutoff' "$HISTORY_FILE" > "${HISTORY_FILE}.tmp" 2>/dev/null && \
        mv "${HISTORY_FILE}.tmp" "$HISTORY_FILE" 2>/dev/null || true
fi

ciberint_log "INFO" "Red inteligente: ${#SEEN_IPS[@]} IPs, $ALERTS_GENERATED alertas"
EOFS2A

chmod 755 "$CIBERINT_BIN/ciberint-red-inteligente.sh"
log_change "Creado" "$CIBERINT_BIN/ciberint-red-inteligente.sh"
log_change "Permisos" "$CIBERINT_BIN/ciberint-red-inteligente.sh -> 755"

# ── ciberint-geoip-update.sh ──
cat > "$CIBERINT_BIN/ciberint-geoip-update.sh" << 'EOFS2B'
#!/bin/bash
# ============================================================
# ciberint-geoip-update.sh - Actualizar base GeoIP local
# Descarga db-ip.com country lite CSV (gratuita, mensual)
# ============================================================
set -uo pipefail

source /usr/local/lib/ciberinteligencia/ciberint-lib.sh

GEOIP_DIR="$CIBERINT_CACHE/geoip"
GEOIP_CSV="$GEOIP_DIR/dbip-country-lite.csv"
mkdir -p "$GEOIP_DIR"

# Determinar URL con fecha actual
YEAR=$(date +%Y)
MONTH=$(date +%m)
URL="https://download.db-ip.com/free/dbip-country-lite-${YEAR}-${MONTH}.csv.gz"

echo "Descargando base GeoIP: $URL"

TMP_GZ=$(mktemp /tmp/geoip-XXXXXX.csv.gz)
if curl -sS --max-time 120 -o "$TMP_GZ" "$URL" 2>/dev/null; then
    if gunzip -c "$TMP_GZ" > "$GEOIP_CSV" 2>/dev/null; then
        LINES=$(wc -l < "$GEOIP_CSV")
        echo "GeoIP actualizado: $LINES registros"
        ciberint_log "INFO" "GeoIP actualizado: $LINES registros"
    else
        echo "Error descomprimiendo GeoIP"
        ciberint_log "ERROR" "Error descomprimiendo GeoIP"
    fi
else
    echo "Error descargando GeoIP"
    ciberint_log "ERROR" "Error descargando GeoIP desde $URL"
fi

rm -f "$TMP_GZ"
EOFS2B

chmod 755 "$CIBERINT_BIN/ciberint-geoip-update.sh"
log_change "Creado" "$CIBERINT_BIN/ciberint-geoip-update.sh"
log_change "Permisos" "$CIBERINT_BIN/ciberint-geoip-update.sh -> 755"

# ── ciberint-conexiones-historico.sh (para S5) ──
cat > "$CIBERINT_BIN/ciberint-conexiones-historico.sh" << 'EOFS2C'
#!/bin/bash
# ============================================================
# ciberint-conexiones-historico.sh - Consultar historial de conexiones
# Uso: ciberint-conexiones-historico.sh [--ip IP] [--days N] [--stats]
# ============================================================
set -uo pipefail

source /usr/local/lib/ciberinteligencia/ciberint-lib.sh

HISTORY_FILE="$CIBERINT_DATA/connection-history.log"
[[ ! -f "$HISTORY_FILE" ]] && echo "Sin historial de conexiones" && exit 0

SEARCH_IP=""
DAYS=90
MODE="list"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ip)    SEARCH_IP="$2"; shift 2 ;;
        --days)  DAYS="$2"; shift 2 ;;
        --stats) MODE="stats"; shift ;;
        *)       shift ;;
    esac
done

CUTOFF=$(date -d "-$DAYS days" '+%Y-%m-%d' 2>/dev/null || date '+%Y-%m-%d')

if [[ "$MODE" == "stats" ]]; then
    echo -e "${CYAN}══ Estadisticas de conexiones (ultimos $DAYS dias) ══${NC}"
    echo ""
    echo "Top 20 IPs por frecuencia:"
    awk -v cutoff="$CUTOFF" '$1 >= cutoff {print $2}' "$HISTORY_FILE" | \
        sort | uniq -c | sort -rn | head -20 | \
        awk '{printf "  %6d  %s\n", $1, $2}'
    echo ""
    echo "Total registros: $(awk -v cutoff="$CUTOFF" '$1 >= cutoff' "$HISTORY_FILE" | wc -l)"
elif [[ -n "$SEARCH_IP" ]]; then
    echo -e "${CYAN}══ Historial para $SEARCH_IP ══${NC}"
    grep -F "$SEARCH_IP" "$HISTORY_FILE" | awk -v cutoff="$CUTOFF" '$1 >= cutoff' | tail -50
else
    echo -e "${CYAN}══ Ultimas 50 conexiones ══${NC}"
    tail -50 "$HISTORY_FILE"
fi
EOFS2C

chmod 755 "$CIBERINT_BIN/ciberint-conexiones-historico.sh"
log_change "Creado" "$CIBERINT_BIN/ciberint-conexiones-historico.sh"
log_change "Permisos" "$CIBERINT_BIN/ciberint-conexiones-historico.sh -> 755"

# Timer systemd: cada 15 min
cat > /etc/systemd/system/ciberint-red.service << EOFSVC
[Unit]
Description=Ciberinteligencia - Inteligencia de Red Proactiva
After=network.target

[Service]
Type=oneshot
ExecStart=$CIBERINT_BIN/ciberint-red-inteligente.sh
StandardOutput=append:$CIBERINT_BASE/log/red-inteligente.log
StandardError=append:$CIBERINT_BASE/log/red-inteligente.log
EOFSVC

cat > /etc/systemd/system/ciberint-red.timer << 'EOFTMR'
[Unit]
Description=Ciberinteligencia - Red cada 15 minutos

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
Persistent=true

[Install]
WantedBy=timers.target
EOFTMR

log_change "Creado" "/etc/systemd/system/ciberint-red.service"
log_change "Creado" "/etc/systemd/system/ciberint-red.timer"

systemctl daemon-reload
log_change "Aplicado" "systemctl daemon-reload"
systemctl enable --now ciberint-red.timer 2>/dev/null || true
log_change "Servicio" "ciberint-red.timer enable+start"

# Cron mensual para GeoIP
cat > /etc/cron.monthly/ciberint-geoip-update << EOFCRON
#!/bin/bash
$CIBERINT_BIN/ciberint-geoip-update.sh >> $CIBERINT_BASE/log/geoip-update.log 2>&1
EOFCRON
chmod 700 /etc/cron.monthly/ciberint-geoip-update
log_change "Creado" "/etc/cron.monthly/ciberint-geoip-update"
log_change "Permisos" "/etc/cron.monthly/ciberint-geoip-update -> 700"

log_info "S2: Inteligencia de red instalada (timer 15min + GeoIP mensual)"

# Descarga inicial GeoIP
echo ""
if ask "Descargar base GeoIP ahora? (recomendado)"; then
    "$CIBERINT_BIN/ciberint-geoip-update.sh" || true
else
    log_skip "Descarga inicial de base GeoIP"
fi

else
    log_skip "Inteligencia de red proactiva (S2)"
fi  # S2

# ============================================================
# S3: INTELIGENCIA DNS
# ============================================================
log_section "S3: INTELIGENCIA DNS"

echo "Deteccion avanzada de DGA, tunneling DNS y dominios recien registrados."
echo "Scripts: ciberint-dns-inteligencia.sh, ciberint-dga-avanzado.sh, ciberint-nrd-monitor.sh"
echo "Timer: cada 30 minutos"
echo ""

if ask "Instalar inteligencia DNS?"; then

# ── ciberint-dga-avanzado.sh ──
cat > "$CIBERINT_BIN/ciberint-dga-avanzado.sh" << 'EOFS3A'
#!/bin/bash
# ============================================================
# ciberint-dga-avanzado.sh - Deteccion avanzada de DGA
# Uso: ciberint-dga-avanzado.sh <dominio>
# Retorna score DGA 0-100 y veredicto
# ============================================================
set -uo pipefail

source /usr/local/lib/ciberinteligencia/ciberint-lib.sh

DOMAIN="${1:-}"
[[ -z "$DOMAIN" ]] && echo "Uso: ciberint-dga-avanzado.sh <dominio>" && exit 1

# Extraer solo la parte del hostname (sin TLD)
HOSTNAME=$(echo "$DOMAIN" | awk -F. '{
    if (NF >= 2) print $(NF-1)
    else print $0
}')
TLD=$(echo "$DOMAIN" | awk -F. '{print $NF}')

SCORE=0

# 1. Entropia Shannon (0-30 pts)
ENTROPY=$(ciberint_entropy "$HOSTNAME")
# Dominios normales: 2.5-3.5, DGA: 3.8-4.5+
ENT_SCORE=$(echo "$ENTROPY" | awk '{
    if ($1 >= 4.2) print 30
    else if ($1 >= 4.0) print 25
    else if ($1 >= 3.8) print 20
    else if ($1 >= 3.5) print 10
    else if ($1 >= 3.2) print 5
    else print 0
}')
SCORE=$(( SCORE + ENT_SCORE ))

# 2. Ratio consonantes/vocales (0-15 pts)
CONSONANTS=$(echo "$HOSTNAME" | tr -cd 'bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ' | wc -c)
VOWELS=$(echo "$HOSTNAME" | tr -cd 'aeiouAEIOU' | wc -c)
[[ $VOWELS -eq 0 ]] && VOWELS=1
RATIO=$(awk "BEGIN{printf \"%.2f\", $CONSONANTS/$VOWELS}")
CV_SCORE=$(echo "$RATIO" | awk '{
    if ($1 >= 5.0) print 15
    else if ($1 >= 4.0) print 12
    else if ($1 >= 3.0) print 8
    else if ($1 >= 2.5) print 4
    else print 0
}')
SCORE=$(( SCORE + CV_SCORE ))

# 3. Longitud del hostname (0-10 pts)
HLEN=${#HOSTNAME}
if [[ $HLEN -ge 20 ]]; then
    SCORE=$(( SCORE + 10 ))
elif [[ $HLEN -ge 15 ]]; then
    SCORE=$(( SCORE + 7 ))
elif [[ $HLEN -ge 12 ]]; then
    SCORE=$(( SCORE + 3 ))
fi

# 4. Analisis de bigramas (0-15 pts)
# Bigramas poco frecuentes en ingles
RARE_BIGRAMS="qx qz xz zx jq qj vx xv zq qk kq jx xj wq qw zj jz"
BIGRAM_HITS=0
for ((i=0; i<${#HOSTNAME}-1; i++)); do
    bg="${HOSTNAME:$i:2}"
    bg_lower=$(echo "$bg" | tr '[:upper:]' '[:lower:]')
    for rb in $RARE_BIGRAMS; do
        [[ "$bg_lower" == "$rb" ]] && BIGRAM_HITS=$(( BIGRAM_HITS + 1 )) && break
    done
done
BG_SCORE=$(( BIGRAM_HITS * 5 ))
[[ $BG_SCORE -gt 15 ]] && BG_SCORE=15
SCORE=$(( SCORE + BG_SCORE ))

# 5. Numeros en el dominio (0-10 pts)
DIGIT_COUNT=$(echo "$HOSTNAME" | tr -cd '0-9' | wc -c)
DIGIT_RATIO=$(awk "BEGIN{printf \"%.2f\", $DIGIT_COUNT/${#HOSTNAME}}")
DIGIT_SCORE=$(echo "$DIGIT_RATIO" | awk '{
    if ($1 >= 0.5) print 10
    else if ($1 >= 0.3) print 7
    else if ($1 >= 0.2) print 3
    else print 0
}')
SCORE=$(( SCORE + DIGIT_SCORE ))

# 6. TLD abusado (0-10 pts)
ABUSED_TLDS="top xyz buzz tk ml ga cf gq info pw cc"
TLD_SCORE=0
for atld in $ABUSED_TLDS; do
    if [[ "$TLD" == "$atld" ]]; then
        TLD_SCORE=10
        break
    fi
done
SCORE=$(( SCORE + TLD_SCORE ))

# Cap
[[ $SCORE -gt 100 ]] && SCORE=100

SEVERITY=$(ciberint_severity "$SCORE")

echo "$SCORE $SEVERITY $ENTROPY $RATIO $HLEN $TLD $DOMAIN"
EOFS3A

chmod 755 "$CIBERINT_BIN/ciberint-dga-avanzado.sh"
log_change "Creado" "$CIBERINT_BIN/ciberint-dga-avanzado.sh"
log_change "Permisos" "$CIBERINT_BIN/ciberint-dga-avanzado.sh -> 755"

# ── ciberint-nrd-monitor.sh ──
cat > "$CIBERINT_BIN/ciberint-nrd-monitor.sh" << 'EOFS3B'
#!/bin/bash
# ============================================================
# ciberint-nrd-monitor.sh - Monitor de dominios recien registrados
# Cruza NRDs contra queries DNS del sistema
# ============================================================
set -uo pipefail

source /usr/local/lib/ciberinteligencia/ciberint-lib.sh

NRD_DIR="$CIBERINT_CACHE/dns"
NRD_FILE="$NRD_DIR/nrd-list.txt"
mkdir -p "$NRD_DIR"

# Descargar feed NRD si es necesario (TTL 24h)
if [[ ! -f "$NRD_FILE" ]] || [[ $(( $(date +%s) - $(stat -c %Y "$NRD_FILE" 2>/dev/null || echo 0) )) -gt 86400 ]]; then
    echo "Actualizando feed de dominios recien registrados..."
    # Usamos el feed de whoisds.com (gratuito, ultimas 24h)
    NRD_DATE=$(date -d "yesterday" '+%Y-%m-%d' 2>/dev/null || date '+%Y-%m-%d')
    TMP_NRD=$(mktemp)
    curl -sS --max-time 60 "https://whoisds.com/newly-registered-domains/${NRD_DATE}/${NRD_DATE}.zip" \
        -o "${TMP_NRD}.zip" 2>/dev/null && \
    unzip -p "${TMP_NRD}.zip" > "$NRD_FILE" 2>/dev/null || {
        # Fallback: lista vacia si no se puede descargar
        touch "$NRD_FILE"
        ciberint_log "WARN" "No se pudo descargar feed NRD"
    }
    rm -f "${TMP_NRD}" "${TMP_NRD}.zip" 2>/dev/null
fi

NRD_COUNT=$(wc -l < "$NRD_FILE" 2>/dev/null || echo 0)
echo "NRDs cargados: $NRD_COUNT"

# Buscar matches contra queries DNS recientes del journal
MATCHES=0
if command -v journalctl &>/dev/null; then
    # Extraer dominios consultados en las ultimas 6h
    journalctl -u systemd-resolved --since "6 hours ago" --no-pager 2>/dev/null | \
        grep -oP 'query\[.*?\]\s+\K[a-zA-Z0-9.-]+' 2>/dev/null | \
        sort -u | while read -r queried_domain; do
            if grep -qiF "$queried_domain" "$NRD_FILE" 2>/dev/null; then
                echo "NRD MATCH: $queried_domain"
                MATCHES=$(( MATCHES + 1 ))
                ciberint_alert "MEDIUM" "nrd-monitor" \
                    "Query a dominio recien registrado: $queried_domain" \
                    "Dominio en lista NRD del dia"
            fi
        done
fi

echo "Matches NRD encontrados: $MATCHES"
EOFS3B

chmod 755 "$CIBERINT_BIN/ciberint-nrd-monitor.sh"
log_change "Creado" "$CIBERINT_BIN/ciberint-nrd-monitor.sh"
log_change "Permisos" "$CIBERINT_BIN/ciberint-nrd-monitor.sh -> 755"

# ── ciberint-dns-inteligencia.sh ──
cat > "$CIBERINT_BIN/ciberint-dns-inteligencia.sh" << 'EOFS3C'
#!/bin/bash
# ============================================================
# ciberint-dns-inteligencia.sh - Inteligencia DNS completa
# DGA, tunneling, NRD, queries anomalas
# ============================================================
set -uo pipefail

source /usr/local/lib/ciberinteligencia/ciberint-lib.sh

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
ALERTS_GENERATED=0
DGA_BIN="$CIBERINT_BIN/ciberint-dga-avanzado.sh"
NRD_BIN="$CIBERINT_BIN/ciberint-nrd-monitor.sh"

echo ""
echo -e "${CYAN}══ Inteligencia DNS - $TIMESTAMP ══${NC}"
echo ""

# ── 1. Analisis DGA de queries recientes ──
echo -e "${BOLD}[1/3] Analisis DGA${NC}"
echo ""

DGA_SUSPECTS=0
if command -v journalctl &>/dev/null; then
    journalctl -u systemd-resolved --since "30 minutes ago" --no-pager 2>/dev/null | \
        grep -oP 'query\[.*?\]\s+\K[a-zA-Z0-9.-]+' 2>/dev/null | \
        sort -u | while read -r domain; do
            # Saltar dominios conocidos/cortos
            [[ ${#domain} -lt 8 ]] && continue
            RESULT=$("$DGA_BIN" "$domain" 2>/dev/null) || continue
            DGA_SCORE=$(echo "$RESULT" | awk '{print $1}')
            DGA_SEV=$(echo "$RESULT" | awk '{print $2}')

            if [[ $DGA_SCORE -ge 40 ]]; then
                echo -e "  ${YELLOW}DGA${NC} score=$DGA_SCORE [$DGA_SEV] $domain"
                DGA_SUSPECTS=$(( DGA_SUSPECTS + 1 ))
                if [[ $DGA_SCORE -ge 60 ]]; then
                    ciberint_alert "$DGA_SEV" "dns-dga" \
                        "Posible DGA: $domain (score=$DGA_SCORE)" \
                        "Entropia alta, patron sospechoso"
                    ALERTS_GENERATED=$(( ALERTS_GENERATED + 1 ))
                fi
            fi
        done
fi
echo -e "  ${DIM}Dominios sospechosos DGA: $DGA_SUSPECTS${NC}"
echo ""

# ── 2. Deteccion de tunneling DNS ──
echo -e "${BOLD}[2/3] Deteccion de tunneling DNS${NC}"
echo ""

TUNNEL_SUSPECTS=0
if command -v journalctl &>/dev/null; then
    # Queries con subdominios muy largos = posible tunneling
    journalctl -u systemd-resolved --since "30 minutes ago" --no-pager 2>/dev/null | \
        grep -oP 'query\[.*?\]\s+\K[a-zA-Z0-9.-]+' 2>/dev/null | \
        sort | uniq -c | sort -rn | head -20 | while read -r count domain; do
            # Tunneling: subdominios largos + alta frecuencia
            TOTAL_LEN=${#domain}
            LABELS=$(echo "$domain" | tr '.' '\n' | wc -l)
            MAX_LABEL=$(echo "$domain" | tr '.' '\n' | awk '{print length}' | sort -rn | head -1)

            TUNNEL_SCORE=0
            [[ $TOTAL_LEN -gt 50 ]] && TUNNEL_SCORE=$(( TUNNEL_SCORE + 20 ))
            [[ $MAX_LABEL -gt 30 ]] && TUNNEL_SCORE=$(( TUNNEL_SCORE + 20 ))
            [[ $LABELS -gt 5 ]] && TUNNEL_SCORE=$(( TUNNEL_SCORE + 15 ))
            [[ $count -gt 50 ]] && TUNNEL_SCORE=$(( TUNNEL_SCORE + 15 ))
            [[ $count -gt 100 ]] && TUNNEL_SCORE=$(( TUNNEL_SCORE + 15 ))

            if [[ $TUNNEL_SCORE -ge 30 ]]; then
                echo -e "  ${YELLOW}TUNNEL${NC} score=$TUNNEL_SCORE freq=$count len=$TOTAL_LEN $domain"
                TUNNEL_SUSPECTS=$(( TUNNEL_SUSPECTS + 1 ))
                if [[ $TUNNEL_SCORE -ge 50 ]]; then
                    ciberint_alert "HIGH" "dns-tunnel" \
                        "Posible DNS tunneling: $domain (score=$TUNNEL_SCORE, freq=$count)" \
                        "Longitud=$TOTAL_LEN Labels=$LABELS MaxLabel=$MAX_LABEL"
                    ALERTS_GENERATED=$(( ALERTS_GENERATED + 1 ))
                fi
            fi
        done
fi
echo -e "  ${DIM}Sospechosos tunneling: $TUNNEL_SUSPECTS${NC}"
echo ""

# ── 3. Dominios recien registrados ──
echo -e "${BOLD}[3/3] Dominios recien registrados (NRD)${NC}"
echo ""
"$NRD_BIN" 2>/dev/null || echo "  NRD monitor no disponible"
echo ""

# ── Resumen ──
echo -e "${DIM}──────────────────────────────────────${NC}"
echo -e "  ${DIM}DGA sospechosos: $DGA_SUSPECTS | Tunneling: $TUNNEL_SUSPECTS | Alertas: $ALERTS_GENERATED${NC}"

ciberint_log "INFO" "DNS inteligencia: DGA=$DGA_SUSPECTS Tunnel=$TUNNEL_SUSPECTS Alertas=$ALERTS_GENERATED"
EOFS3C

chmod 755 "$CIBERINT_BIN/ciberint-dns-inteligencia.sh"
log_change "Creado" "$CIBERINT_BIN/ciberint-dns-inteligencia.sh"
log_change "Permisos" "$CIBERINT_BIN/ciberint-dns-inteligencia.sh -> 755"

# Timer: cada 30 min
cat > /etc/systemd/system/ciberint-dns.service << EOFSVC
[Unit]
Description=Ciberinteligencia - Inteligencia DNS
After=network.target

[Service]
Type=oneshot
ExecStart=$CIBERINT_BIN/ciberint-dns-inteligencia.sh
StandardOutput=append:$CIBERINT_BASE/log/dns-inteligencia.log
StandardError=append:$CIBERINT_BASE/log/dns-inteligencia.log
EOFSVC

cat > /etc/systemd/system/ciberint-dns.timer << 'EOFTMR'
[Unit]
Description=Ciberinteligencia - DNS cada 30 minutos

[Timer]
OnBootSec=10min
OnUnitActiveSec=30min
Persistent=true

[Install]
WantedBy=timers.target
EOFTMR

log_change "Creado" "/etc/systemd/system/ciberint-dns.service"
log_change "Creado" "/etc/systemd/system/ciberint-dns.timer"

systemctl daemon-reload
log_change "Aplicado" "systemctl daemon-reload"
systemctl enable --now ciberint-dns.timer 2>/dev/null || true
log_change "Servicio" "ciberint-dns.timer enable+start"

log_info "S3: Inteligencia DNS instalada (timer 30min)"

else
    log_skip "Inteligencia DNS (S3)"
fi  # S3

# ============================================================
# S4: AUTO-MONITORIZACION DE SUPERFICIE DE ATAQUE
# ============================================================
log_section "S4: MONITORIZACION DE SUPERFICIE DE ATAQUE"

echo "Snapshots periodicos de la superficie de ataque con deteccion de cambios."
echo "Puertos, certificados SSL, DNS, headers HTTP, Shodan, CT logs."
echo "Timer: cada 6h + diario 06:00"
echo ""

if ask "Instalar monitorizacion de superficie de ataque?"; then

# ── ciberint-superficie-ataque.sh ──
cat > "$CIBERINT_BIN/ciberint-superficie-ataque.sh" << 'EOFS4A'
#!/bin/bash
# ============================================================
# ciberint-superficie-ataque.sh - Snapshot de superficie de ataque
# ============================================================
set -uo pipefail

source /usr/local/lib/ciberinteligencia/ciberint-lib.sh

SURFACE_DIR="$CIBERINT_DATA/attack-surface"
TIMESTAMP=$(date '+%Y%m%d-%H%M%S')
SNAP_DIR="$SURFACE_DIR/snap-$TIMESTAMP"
LATEST_LINK="$SURFACE_DIR/latest"
COMPARAR_BIN="$CIBERINT_BIN/ciberint-superficie-comparar.sh"

mkdir -p "$SNAP_DIR"

echo ""
echo -e "${CYAN}══ Superficie de Ataque - Snapshot $TIMESTAMP ══${NC}"
echo ""

# 1. Puertos abiertos
echo -e "${BOLD}[1/6] Puertos abiertos${NC}"
ss -tlnp 2>/dev/null | tail -n +2 | awk '{print $4, $6}' | sort > "$SNAP_DIR/ports.txt"
PORTS_COUNT=$(wc -l < "$SNAP_DIR/ports.txt")
echo "  $PORTS_COUNT puertos escuchando"

# 2. Certificados SSL
echo -e "${BOLD}[2/6] Certificados SSL${NC}"
CERT_COUNT=0
for port in 443 8443 993 995 465 587; do
    if ss -tlnp 2>/dev/null | grep -q ":$port "; then
        CERT_INFO=$(echo | timeout 5 openssl s_client -connect "localhost:$port" -servername localhost 2>/dev/null | \
            openssl x509 -noout -subject -dates -issuer 2>/dev/null)
        if [[ -n "$CERT_INFO" ]]; then
            echo "$port: $CERT_INFO" >> "$SNAP_DIR/certs.txt"
            CERT_COUNT=$(( CERT_COUNT + 1 ))
        fi
    fi
done
echo "  $CERT_COUNT certificados encontrados"

# 3. Registros DNS (si hay dominios configurados)
echo -e "${BOLD}[3/6] Registros DNS${NC}"
source "$CIBERINT_CONFIG/ciberint.conf" 2>/dev/null || true
DNS_COUNT=0
if [[ -n "${CIBERINT_OWN_DOMAINS:-}" ]]; then
    for domain in $CIBERINT_OWN_DOMAINS; do
        echo "--- $domain ---" >> "$SNAP_DIR/dns.txt"
        for rtype in A AAAA MX NS TXT CNAME; do
            dig +short "$domain" "$rtype" 2>/dev/null >> "$SNAP_DIR/dns.txt"
        done
        DNS_COUNT=$(( DNS_COUNT + 1 ))
    done
fi
echo "  $DNS_COUNT dominios consultados"

# 4. Headers HTTP
echo -e "${BOLD}[4/6] Headers HTTP${NC}"
HEADER_COUNT=0
for port in 80 443 8080 8443; do
    if ss -tlnp 2>/dev/null | grep -q ":$port "; then
        PROTO="http"
        [[ $port -eq 443 || $port -eq 8443 ]] && PROTO="https"
        curl -sI --max-time 5 --insecure "${PROTO}://localhost:${port}/" >> "$SNAP_DIR/headers.txt" 2>/dev/null
        HEADER_COUNT=$(( HEADER_COUNT + 1 ))
    fi
done
echo "  $HEADER_COUNT servicios HTTP analizados"

# 5. Shodan InternetDB (IPs propias)
echo -e "${BOLD}[5/6] Vista Shodan${NC}"
SHODAN_COUNT=0
if [[ -n "${CIBERINT_OWN_IPS:-}" ]]; then
    for ip in $CIBERINT_OWN_IPS; do
        SHODAN_DATA=$(curl -sS --max-time 10 "https://internetdb.shodan.io/$ip" 2>/dev/null)
        if [[ -n "$SHODAN_DATA" ]]; then
            echo "$SHODAN_DATA" >> "$SNAP_DIR/shodan.json"
            SHODAN_COUNT=$(( SHODAN_COUNT + 1 ))
        fi
    done
fi
echo "  $SHODAN_COUNT IPs consultadas en Shodan"

# 6. CT Logs (certificados emitidos para dominios propios)
echo -e "${BOLD}[6/6] Certificate Transparency${NC}"
CT_COUNT=0
if [[ -n "${CIBERINT_OWN_DOMAINS:-}" ]]; then
    for domain in $CIBERINT_OWN_DOMAINS; do
        CT_DATA=$(curl -sS --max-time 15 "https://crt.sh/?q=%25.${domain}&output=json" 2>/dev/null | \
            jq -r '.[0:20] | .[] | "\(.id) \(.name_value) \(.not_before)"' 2>/dev/null)
        if [[ -n "$CT_DATA" ]]; then
            echo "$CT_DATA" >> "$SNAP_DIR/ct-logs.txt"
            CT_COUNT=$(( CT_COUNT + 1 ))
        fi
    done
fi
echo "  $CT_COUNT dominios en CT logs"

# Actualizar enlace al ultimo snapshot
ln -sfn "$SNAP_DIR" "$LATEST_LINK"

echo ""
echo -e "${DIM}Snapshot guardado: $SNAP_DIR${NC}"

# Comparar con snapshot anterior si existe
PREV_SNAP=""
SNAP_LIST=$(ls -d "$SURFACE_DIR"/snap-* 2>/dev/null | sort | tail -2)
SNAP_COUNT=$(echo "$SNAP_LIST" | wc -l)
if [[ $SNAP_COUNT -ge 2 ]]; then
    PREV_SNAP=$(echo "$SNAP_LIST" | head -1)
    echo ""
    echo -e "${BOLD}Comparando con snapshot anterior...${NC}"
    "$COMPARAR_BIN" "$PREV_SNAP" "$SNAP_DIR" 2>/dev/null || true
fi

# Limpiar snapshots viejos (mantener ultimos 30)
ls -dt "$SURFACE_DIR"/snap-* 2>/dev/null | tail -n +31 | xargs rm -rf 2>/dev/null || true

ciberint_log "INFO" "Superficie: snapshot $TIMESTAMP (ports=$PORTS_COUNT certs=$CERT_COUNT)"
EOFS4A

chmod 755 "$CIBERINT_BIN/ciberint-superficie-ataque.sh"
log_change "Creado" "$CIBERINT_BIN/ciberint-superficie-ataque.sh"
log_change "Permisos" "$CIBERINT_BIN/ciberint-superficie-ataque.sh -> 755"

# ── ciberint-superficie-comparar.sh ──
cat > "$CIBERINT_BIN/ciberint-superficie-comparar.sh" << 'EOFS4B'
#!/bin/bash
# ============================================================
# ciberint-superficie-comparar.sh - Comparar snapshots de superficie
# Uso: ciberint-superficie-comparar.sh <snap-anterior> <snap-nuevo>
# ============================================================
set -uo pipefail

source /usr/local/lib/ciberinteligencia/ciberint-lib.sh

PREV="${1:-}"
CURR="${2:-}"

if [[ -z "$PREV" || -z "$CURR" ]]; then
    echo "Uso: ciberint-superficie-comparar.sh <snap-anterior> <snap-nuevo>"
    exit 1
fi

CHANGES=0

echo ""
echo -e "${CYAN}══ Cambios en Superficie de Ataque ══${NC}"
echo ""

# 1. Puertos nuevos
if [[ -f "$PREV/ports.txt" && -f "$CURR/ports.txt" ]]; then
    NEW_PORTS=$(comm -13 <(sort "$PREV/ports.txt") <(sort "$CURR/ports.txt") 2>/dev/null)
    REMOVED_PORTS=$(comm -23 <(sort "$PREV/ports.txt") <(sort "$CURR/ports.txt") 2>/dev/null)

    if [[ -n "$NEW_PORTS" ]]; then
        echo -e "  ${RED}CRITICAL${NC} Puertos NUEVOS detectados:"
        echo "$NEW_PORTS" | while read -r line; do
            echo -e "    ${RED}+${NC} $line"
        done
        CHANGES=$(( CHANGES + 1 ))
        ciberint_alert "CRITICAL" "superficie" \
            "Nuevos puertos abiertos detectados" \
            "$NEW_PORTS"
    fi

    if [[ -n "$REMOVED_PORTS" ]]; then
        echo -e "  ${GREEN}INFO${NC} Puertos cerrados:"
        echo "$REMOVED_PORTS" | while read -r line; do
            echo -e "    ${GREEN}-${NC} $line"
        done
    fi
fi

# 2. Certificados - expiracion
if [[ -f "$CURR/certs.txt" ]]; then
    while IFS= read -r line; do
        NOT_AFTER=$(echo "$line" | grep -oP 'notAfter=\K.*' 2>/dev/null)
        if [[ -n "$NOT_AFTER" ]]; then
            EXPIRY=$(date -d "$NOT_AFTER" +%s 2>/dev/null || echo 0)
            NOW=$(date +%s)
            DAYS_LEFT=$(( (EXPIRY - NOW) / 86400 ))

            if [[ $DAYS_LEFT -lt 7 ]]; then
                echo -e "  ${RED}CRITICAL${NC} Certificado expira en $DAYS_LEFT dias: $line"
                CHANGES=$(( CHANGES + 1 ))
                ciberint_alert "CRITICAL" "superficie-cert" \
                    "Certificado expira en $DAYS_LEFT dias" "$line"
            elif [[ $DAYS_LEFT -lt 30 ]]; then
                echo -e "  ${YELLOW}HIGH${NC} Certificado expira en $DAYS_LEFT dias: $line"
                CHANGES=$(( CHANGES + 1 ))
                ciberint_alert "HIGH" "superficie-cert" \
                    "Certificado expira en $DAYS_LEFT dias" "$line"
            fi
        fi
    done < "$CURR/certs.txt"
fi

# 3. Cambios DNS
if [[ -f "$PREV/dns.txt" && -f "$CURR/dns.txt" ]]; then
    DNS_DIFF=$(diff "$PREV/dns.txt" "$CURR/dns.txt" 2>/dev/null) || true
    if [[ -n "$DNS_DIFF" ]]; then
        echo -e "  ${YELLOW}HIGH${NC} Cambios en registros DNS detectados"
        echo "$DNS_DIFF" | head -10
        CHANGES=$(( CHANGES + 1 ))
        ciberint_alert "HIGH" "superficie-dns" \
            "Cambio en registros DNS" "$DNS_DIFF"
    fi
fi

# 4. Vulnerabilidades Shodan nuevas
if [[ -f "$PREV/shodan.json" && -f "$CURR/shodan.json" ]]; then
    PREV_VULNS=$(jq -r '.vulns[]?' "$PREV/shodan.json" 2>/dev/null | sort -u)
    CURR_VULNS=$(jq -r '.vulns[]?' "$CURR/shodan.json" 2>/dev/null | sort -u)
    NEW_VULNS=$(comm -13 <(echo "$PREV_VULNS") <(echo "$CURR_VULNS") 2>/dev/null)

    if [[ -n "$NEW_VULNS" ]]; then
        echo -e "  ${YELLOW}HIGH${NC} Nuevas vulnerabilidades en Shodan:"
        echo "$NEW_VULNS" | while read -r vuln; do
            echo -e "    ${RED}+${NC} $vuln"
        done
        CHANGES=$(( CHANGES + 1 ))
        ciberint_alert "HIGH" "superficie-vuln" \
            "Nuevas vulnerabilidades detectadas en Shodan" "$NEW_VULNS"
    fi
fi

# 5. Nuevos certificados CT
if [[ -f "$PREV/ct-logs.txt" && -f "$CURR/ct-logs.txt" ]]; then
    NEW_CT=$(comm -13 <(sort "$PREV/ct-logs.txt") <(sort "$CURR/ct-logs.txt") 2>/dev/null)
    if [[ -n "$NEW_CT" ]]; then
        echo -e "  ${CYAN}MEDIUM${NC} Nuevos certificados en CT logs:"
        echo "$NEW_CT" | head -5 | while read -r ct; do
            echo "    + $ct"
        done
        CHANGES=$(( CHANGES + 1 ))
        ciberint_alert "MEDIUM" "superficie-ct" \
            "Nuevos certificados detectados en CT logs" "$NEW_CT"
    fi
fi

if [[ $CHANGES -eq 0 ]]; then
    echo -e "  ${GREEN}OK${NC} Sin cambios detectados"
fi

echo ""
echo -e "${DIM}Cambios totales: $CHANGES${NC}"
EOFS4B

chmod 755 "$CIBERINT_BIN/ciberint-superficie-comparar.sh"
log_change "Creado" "$CIBERINT_BIN/ciberint-superficie-comparar.sh"
log_change "Permisos" "$CIBERINT_BIN/ciberint-superficie-comparar.sh -> 755"

# Timer: cada 6h
cat > /etc/systemd/system/ciberint-superficie.service << EOFSVC
[Unit]
Description=Ciberinteligencia - Superficie de Ataque
After=network.target

[Service]
Type=oneshot
ExecStart=$CIBERINT_BIN/ciberint-superficie-ataque.sh
StandardOutput=append:$CIBERINT_BASE/log/superficie.log
StandardError=append:$CIBERINT_BASE/log/superficie.log
EOFSVC

cat > /etc/systemd/system/ciberint-superficie.timer << 'EOFTMR'
[Unit]
Description=Ciberinteligencia - Superficie cada 6h y diario 06:00

[Timer]
OnBootSec=15min
OnUnitActiveSec=6h
OnCalendar=*-*-* 06:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOFTMR

log_change "Creado" "/etc/systemd/system/ciberint-superficie.service"
log_change "Creado" "/etc/systemd/system/ciberint-superficie.timer"

systemctl daemon-reload
log_change "Aplicado" "systemctl daemon-reload"
systemctl enable --now ciberint-superficie.timer 2>/dev/null || true
log_change "Servicio" "ciberint-superficie.timer enable+start"

log_info "S4: Monitorizacion de superficie instalada (timer 6h + 06:00)"

else
    log_skip "Monitorizacion de superficie de ataque (S4)"
fi  # S4

# ============================================================
# S5: SISTEMA DE ALERTA TEMPRANA
# ============================================================
log_section "S5: SISTEMA DE ALERTA TEMPRANA"

echo "Retroactive matching contra historial, CVE monitoring via OSV.dev."
echo "Scripts: ciberint-alerta-temprana.sh, ciberint-cve-monitor.sh"
echo "Timer: diario 04:30 + cron.daily CVE"
echo ""

if ask "Instalar sistema de alerta temprana?"; then

# ── ciberint-alerta-temprana.sh ──
cat > "$CIBERINT_BIN/ciberint-alerta-temprana.sh" << 'EOFS5A'
#!/bin/bash
# ============================================================
# ciberint-alerta-temprana.sh - Retroactive matching
# Compara feeds actualizados contra historial de conexiones
# ============================================================
set -uo pipefail

source /usr/local/lib/ciberinteligencia/ciberint-lib.sh

HISTORY_FILE="$CIBERINT_DATA/connection-history.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

echo ""
echo -e "${CYAN}══ Alerta Temprana - Retroactive Matching $TIMESTAMP ══${NC}"
echo ""

[[ ! -f "$HISTORY_FILE" ]] && echo "Sin historial de conexiones" && exit 0

# Obtener IPs unicas del historial
HISTORY_IPS=$(awk '{print $2}' "$HISTORY_FILE" 2>/dev/null | sort -u)
TOTAL_IPS=$(echo "$HISTORY_IPS" | wc -l)
MATCHES=0

echo "Verificando $TOTAL_IPS IPs historicas contra feeds actuales..."
echo ""

# Verificar contra cada feed
for feed in "$IOC_LISTS_DIR"/*.txt; do
    [[ ! -f "$feed" ]] && continue
    FNAME=$(basename "$feed")

    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        if grep -qF "$ip" "$feed" 2>/dev/null; then
            # Buscar cuando se conecto
            CONNECTIONS=$(grep -F "$ip" "$HISTORY_FILE" | head -5)
            echo -e "  ${RED}RETRO-MATCH${NC} $ip encontrada en $FNAME"
            echo "$CONNECTIONS" | while read -r line; do
                echo -e "    ${DIM}$line${NC}"
            done

            ciberint_alert "HIGH" "alerta-temprana" \
                "Retroactive match: $ip ahora en feed $FNAME" \
                "IP previamente conectada ahora aparece como maliciosa"

            MATCHES=$(( MATCHES + 1 ))
        fi
    done <<< "$HISTORY_IPS"
done

echo ""
if [[ $MATCHES -gt 0 ]]; then
    echo -e "${RED}${BOLD}$MATCHES retroactive matches encontrados${NC}"
    echo -e "${DIM}Revisa alertas en $CIBERINT_ALERTS/${NC}"
else
    echo -e "${GREEN}OK${NC} Sin retroactive matches"
fi

ciberint_log "INFO" "Alerta temprana: $MATCHES retro-matches de $TOTAL_IPS IPs historicas"
EOFS5A

chmod 755 "$CIBERINT_BIN/ciberint-alerta-temprana.sh"
log_change "Creado" "$CIBERINT_BIN/ciberint-alerta-temprana.sh"
log_change "Permisos" "$CIBERINT_BIN/ciberint-alerta-temprana.sh -> 755"

# ── ciberint-cve-monitor.sh ──
cat > "$CIBERINT_BIN/ciberint-cve-monitor.sh" << 'EOFS5B'
#!/bin/bash
# ============================================================
# ciberint-cve-monitor.sh - Monitor CVE para paquetes instalados
# Consulta OSV.dev (API gratuita sin clave)
# ============================================================
set -uo pipefail

source /usr/local/lib/ciberinteligencia/ciberint-lib.sh

CVE_CACHE="$CIBERINT_CACHE/cve"
CVE_REPORT="$CIBERINT_DATA/reports/cve-report-$(date +%Y%m%d).txt"
mkdir -p "$CVE_CACHE" "$CIBERINT_DATA/reports"

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

echo ""
echo -e "${CYAN}══ CVE Monitor - $TIMESTAMP ══${NC}"
echo ""

# Obtener paquetes instalados con version
declare -A PACKAGES

if command -v rpm &>/dev/null; then
    # RPM-based (openSUSE, RHEL, Fedora)
    while IFS= read -r line; do
        name=$(echo "$line" | rev | cut -d'-' -f3- | rev)
        version=$(echo "$line" | rev | cut -d'-' -f1-2 | rev)
        PACKAGES["$name"]="$version"
    done < <(rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}\n' 2>/dev/null | head -200)
elif command -v dpkg-query &>/dev/null; then
    # Debian/Ubuntu
    while IFS='|' read -r name version; do
        PACKAGES["$name"]="$version"
    done < <(dpkg-query -W -f='${Package}|${Version}\n' 2>/dev/null | head -200)
fi

TOTAL_PKGS=${#PACKAGES[@]}
echo "Paquetes a verificar: $TOTAL_PKGS (muestra)"
echo ""

VULNS_FOUND=0
CRITICAL_VULNS=0

{
    echo "CVE Monitor Report - $TIMESTAMP"
    echo "================================="
    echo ""

    for pkg in "${!PACKAGES[@]}"; do
        ver="${PACKAGES[$pkg]}"

        # Cache check
        CACHE_KEY="${pkg}_${ver//[^a-zA-Z0-9]/_}"
        cached=$(ciberint_cache_get "cve" "$CACHE_KEY" 604800 2>/dev/null) && {
            if [[ "$cached" != "clean" ]]; then
                echo "$cached"
                VULNS_FOUND=$(( VULNS_FOUND + 1 ))
            fi
            continue
        }

        # Consultar OSV.dev
        RESPONSE=$(curl -sS --max-time 10 -X POST \
            -H "Content-Type: application/json" \
            -d "{\"package\":{\"name\":\"$pkg\",\"ecosystem\":\"Linux\"},\"version\":\"$ver\"}" \
            "https://api.osv.dev/v1/query" 2>/dev/null) || continue

        VULN_COUNT=$(echo "$RESPONSE" | jq '.vulns | length' 2>/dev/null || echo 0)

        if [[ "$VULN_COUNT" -gt 0 ]]; then
            VULN_SUMMARY=$(echo "$RESPONSE" | jq -r '.vulns[] | "\(.id) \(.summary // "N/A" | .[0:60])"' 2>/dev/null)
            RESULT="PKG: $pkg ($ver) - $VULN_COUNT vulnerabilidades:\n$VULN_SUMMARY"
            echo -e "$RESULT"
            echo ""
            ciberint_cache_set "cve" "$CACHE_KEY" "$RESULT"
            VULNS_FOUND=$(( VULNS_FOUND + 1 ))

            # Verificar severidad
            HAS_CRITICAL=$(echo "$RESPONSE" | jq '[.vulns[].severity[]? | select(.score >= 9.0)] | length' 2>/dev/null || echo 0)
            if [[ "$HAS_CRITICAL" -gt 0 ]]; then
                CRITICAL_VULNS=$(( CRITICAL_VULNS + 1 ))
                ciberint_alert "CRITICAL" "cve-monitor" \
                    "CVE critico en $pkg ($ver)" \
                    "$VULN_SUMMARY"
            fi
        else
            ciberint_cache_set "cve" "$CACHE_KEY" "clean"
        fi

        # Rate limit
        sleep 0.5
    done

    echo ""
    echo "Resumen: $VULNS_FOUND paquetes vulnerables, $CRITICAL_VULNS criticos"
} | tee "$CVE_REPORT"

echo ""
echo -e "${DIM}Reporte guardado: $CVE_REPORT${NC}"

ciberint_log "INFO" "CVE monitor: $VULNS_FOUND vulnerables, $CRITICAL_VULNS criticos"
EOFS5B

chmod 755 "$CIBERINT_BIN/ciberint-cve-monitor.sh"
log_change "Creado" "$CIBERINT_BIN/ciberint-cve-monitor.sh"
log_change "Permisos" "$CIBERINT_BIN/ciberint-cve-monitor.sh -> 755"

# Timer: diario 04:30
cat > /etc/systemd/system/ciberint-alerta-temprana.service << EOFSVC
[Unit]
Description=Ciberinteligencia - Alerta Temprana
After=network.target

[Service]
Type=oneshot
ExecStart=$CIBERINT_BIN/ciberint-alerta-temprana.sh
StandardOutput=append:$CIBERINT_BASE/log/alerta-temprana.log
StandardError=append:$CIBERINT_BASE/log/alerta-temprana.log
EOFSVC

cat > /etc/systemd/system/ciberint-alerta-temprana.timer << 'EOFTMR'
[Unit]
Description=Ciberinteligencia - Alerta Temprana diario 04:30

[Timer]
OnCalendar=*-*-* 04:30:00
Persistent=true

[Install]
WantedBy=timers.target
EOFTMR

log_change "Creado" "/etc/systemd/system/ciberint-alerta-temprana.service"
log_change "Creado" "/etc/systemd/system/ciberint-alerta-temprana.timer"

systemctl daemon-reload
log_change "Aplicado" "systemctl daemon-reload"
systemctl enable --now ciberint-alerta-temprana.timer 2>/dev/null || true
log_change "Servicio" "ciberint-alerta-temprana.timer enable+start"

# Cron diario CVE
cat > /etc/cron.daily/ciberint-cve-monitor << EOFCRON
#!/bin/bash
$CIBERINT_BIN/ciberint-cve-monitor.sh >> $CIBERINT_BASE/log/cve-monitor.log 2>&1
EOFCRON
chmod 700 /etc/cron.daily/ciberint-cve-monitor
log_change "Creado" "/etc/cron.daily/ciberint-cve-monitor"
log_change "Permisos" "/etc/cron.daily/ciberint-cve-monitor -> 700"

log_info "S5: Sistema de alerta temprana instalado (timer 04:30 + CVE diario)"

else
    log_skip "Sistema de alerta temprana (S5)"
fi  # S5

# ============================================================
# S6: INFORMES DE INTELIGENCIA AUTOMATIZADOS
# ============================================================
log_section "S6: INFORMES DE INTELIGENCIA"

echo "Generacion automatica de informes diarios y semanales."
echo "Scripts: ciberint-reporte-diario.sh, ciberint-reporte-semanal.sh"
echo "Timer: diario 07:00, semanal via cron"
echo ""

if ask "Instalar informes de inteligencia automatizados?"; then

# ── ciberint-reporte-diario.sh ──
cat > "$CIBERINT_BIN/ciberint-reporte-diario.sh" << 'EOFS6A'
#!/bin/bash
# ============================================================
# ciberint-reporte-diario.sh - Informe diario de inteligencia
# ============================================================
set -uo pipefail

source /usr/local/lib/ciberinteligencia/ciberint-lib.sh

REPORT_DIR="$CIBERINT_DATA/reports"
mkdir -p "$REPORT_DIR"
DATE=$(date '+%Y-%m-%d')
REPORT="$REPORT_DIR/diario-${DATE}.txt"
HISTORY_FILE="$CIBERINT_DATA/connection-history.log"

{
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  INFORME DIARIO DE CIBERINTELIGENCIA                      ║"
echo "║  Fecha: $DATE                                       ║"
echo "║  Sistema: $(hostname)                                      ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# ── Resumen ejecutivo ──
echo "== RESUMEN EJECUTIVO =="
echo ""

# Alertas del dia
ALERT_COUNT=0
CRITICAL_COUNT=0
HIGH_COUNT=0
if [[ -d "$CIBERINT_ALERTS" ]]; then
    for alert_file in "$CIBERINT_ALERTS"/*.json; do
        [[ ! -f "$alert_file" ]] && continue
        ALERT_DATE=$(jq -r '.timestamp // ""' "$alert_file" 2>/dev/null | cut -dT -f1)
        [[ "$ALERT_DATE" != "$DATE" ]] && continue
        ALERT_COUNT=$(( ALERT_COUNT + 1 ))
        SEV=$(jq -r '.severity // ""' "$alert_file" 2>/dev/null)
        [[ "$SEV" == "CRITICAL" ]] && CRITICAL_COUNT=$(( CRITICAL_COUNT + 1 ))
        [[ "$SEV" == "HIGH" ]] && HIGH_COUNT=$(( HIGH_COUNT + 1 ))
    done
fi
echo "Alertas totales hoy:  $ALERT_COUNT"
echo "  CRITICAL:           $CRITICAL_COUNT"
echo "  HIGH:               $HIGH_COUNT"
echo ""

# ── Top 10 conexiones sospechosas ──
echo "== TOP 10 CONEXIONES SOSPECHOSAS (hoy) =="
echo ""
if [[ -f "$HISTORY_FILE" ]]; then
    awk -v date="$DATE" '$1 == date {print $2}' "$HISTORY_FILE" | \
        sort | uniq -c | sort -rn | head -10 | \
        while read -r count ip; do
            # Score rapido
            score=$(ciberint_score_ip "$ip" 2>/dev/null || echo "0")
            severity=$(ciberint_severity "$score")
            printf "  %5d conexiones  %-16s  Score: %3d [%s]\n" "$count" "$ip" "$score" "$severity"
        done
else
    echo "  Sin datos de conexiones"
fi
echo ""

# ── Anomalias DNS ──
echo "== ANOMALIAS DNS =="
echo ""
DNS_ALERTS=$(find "$CIBERINT_ALERTS" -name "*.json" -newer "$REPORT_DIR/.last-daily" 2>/dev/null | \
    xargs grep -l '"source": "dns-' 2>/dev/null | wc -l)
echo "Alertas DNS hoy: $DNS_ALERTS"
echo ""

# ── Alertas tempranas ──
echo "== ALERTAS TEMPRANAS =="
echo ""
RETRO_ALERTS=$(find "$CIBERINT_ALERTS" -name "*.json" -newer "$REPORT_DIR/.last-daily" 2>/dev/null | \
    xargs grep -l '"source": "alerta-temprana"' 2>/dev/null | wc -l)
echo "Retroactive matches: $RETRO_ALERTS"
echo ""

# ── Cambios en superficie ──
echo "== CAMBIOS EN SUPERFICIE DE ATAQUE =="
echo ""
SURFACE_ALERTS=$(find "$CIBERINT_ALERTS" -name "*.json" -newer "$REPORT_DIR/.last-daily" 2>/dev/null | \
    xargs grep -l '"source": "superficie' 2>/dev/null | wc -l)
echo "Cambios detectados: $SURFACE_ALERTS"
echo ""

# ── Acciones SOAR ──
echo "== ACCIONES SOAR EJECUTADAS =="
echo ""
if [[ -f "$CIBERINT_LOG/soar-bridge.log" ]]; then
    grep "$DATE" "$CIBERINT_LOG/soar-bridge.log" 2>/dev/null | tail -10 || echo "  Sin acciones"
else
    echo "  Sin acciones"
fi
echo ""

# ── Recomendaciones ──
echo "== RECOMENDACIONES PRIORIZADAS =="
echo ""
if [[ $CRITICAL_COUNT -gt 0 ]]; then
    echo "  [URGENTE] Revisar $CRITICAL_COUNT alertas CRITICAL en $CIBERINT_ALERTS/"
fi
if [[ $HIGH_COUNT -gt 0 ]]; then
    echo "  [ALTO] Revisar $HIGH_COUNT alertas HIGH"
fi
if [[ $RETRO_ALERTS -gt 0 ]]; then
    echo "  [ALTO] Investigar $RETRO_ALERTS retroactive matches"
fi
if [[ $SURFACE_ALERTS -gt 0 ]]; then
    echo "  [MEDIO] Verificar $SURFACE_ALERTS cambios en superficie"
fi
[[ $ALERT_COUNT -eq 0 ]] && echo "  Sin alertas. Sistema en estado nominal."
echo ""
echo "──────────────────────────────────────────────────────"
echo "Generado por: Securizar - Ciberinteligencia Proactiva"
echo "Fecha: $(date '+%Y-%m-%d %H:%M:%S')"

} > "$REPORT" 2>/dev/null

# Marcar ultimo reporte
touch "$REPORT_DIR/.last-daily"

# Enviar por email si configurado
source "$CIBERINT_CONFIG/ciberint.conf" 2>/dev/null || true
if [[ -n "${CIBERINT_NOTIFY_EMAIL:-}" ]] && command -v mail &>/dev/null; then
    mail -s "[CiberInt] Informe diario $(hostname) $DATE" \
        "$CIBERINT_NOTIFY_EMAIL" < "$REPORT" 2>/dev/null || true
fi

echo "Informe diario generado: $REPORT"
ciberint_log "INFO" "Reporte diario generado: $REPORT"
EOFS6A

chmod 755 "$CIBERINT_BIN/ciberint-reporte-diario.sh"
log_change "Creado" "$CIBERINT_BIN/ciberint-reporte-diario.sh"
log_change "Permisos" "$CIBERINT_BIN/ciberint-reporte-diario.sh -> 755"

# ── ciberint-reporte-semanal.sh ──
cat > "$CIBERINT_BIN/ciberint-reporte-semanal.sh" << 'EOFS6B'
#!/bin/bash
# ============================================================
# ciberint-reporte-semanal.sh - Informe semanal de inteligencia
# Tendencias, comparacion semana-sobre-semana, persistentes
# ============================================================
set -uo pipefail

source /usr/local/lib/ciberinteligencia/ciberint-lib.sh

REPORT_DIR="$CIBERINT_DATA/reports"
mkdir -p "$REPORT_DIR"
DATE=$(date '+%Y-%m-%d')
WEEK=$(date '+%Y-W%V')
REPORT="$REPORT_DIR/semanal-${WEEK}.txt"
HISTORY_FILE="$CIBERINT_DATA/connection-history.log"

WEEK_START=$(date -d "7 days ago" '+%Y-%m-%d' 2>/dev/null || date '+%Y-%m-%d')

{
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  INFORME SEMANAL DE CIBERINTELIGENCIA                     ║"
echo "║  Semana: $WEEK ($WEEK_START a $DATE)           ║"
echo "║  Sistema: $(hostname)                                      ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# ── Tendencias 7 dias ──
echo "== TENDENCIAS ULTIMOS 7 DIAS =="
echo ""
echo "Alertas por dia (barras):"
for i in $(seq 6 -1 0); do
    DAY=$(date -d "$i days ago" '+%Y-%m-%d' 2>/dev/null || date '+%Y-%m-%d')
    DAY_SHORT=$(date -d "$i days ago" '+%a' 2>/dev/null || echo "???")
    COUNT=0
    if [[ -d "$CIBERINT_ALERTS" ]]; then
        COUNT=$(find "$CIBERINT_ALERTS" -name "*.json" -exec grep -l "\"timestamp\": \"$DAY" {} \; 2>/dev/null | wc -l)
    fi
    BAR=""
    for ((b=0; b<COUNT && b<40; b++)); do BAR+="█"; done
    printf "  %s %s  %3d %s\n" "$DAY" "$DAY_SHORT" "$COUNT" "$BAR"
done
echo ""

# ── Conexiones por pais ──
echo "== DISTRIBUCION GEOGRAFICA (top 15) =="
echo ""
if [[ -f "$HISTORY_FILE" ]]; then
    awk -v start="$WEEK_START" '$1 >= start {print $2}' "$HISTORY_FILE" | \
        sort -u | while read -r ip; do
            country=$(ciberint_geoip_lookup "$ip" 2>/dev/null || echo "??")
            echo "$country"
        done | sort | uniq -c | sort -rn | head -15 | \
        while read -r count country; do
            BAR=""
            for ((b=0; b<count && b<30; b++)); do BAR+="█"; done
            printf "  %-4s %4d %s\n" "$country" "$count" "$BAR"
        done
fi
echo ""

# ── Amenazas persistentes ──
echo "== AMENAZAS PERSISTENTES (IPs en multiples dias) =="
echo ""
if [[ -f "$HISTORY_FILE" ]]; then
    awk -v start="$WEEK_START" '$1 >= start {print $1, $2}' "$HISTORY_FILE" | \
        sort -u | awk '{print $2}' | sort | uniq -c | sort -rn | \
        awk '$1 >= 3 {print $2, $1}' | head -10 | \
        while read -r ip days; do
            score=$(ciberint_score_ip "$ip" 2>/dev/null || echo "0")
            severity=$(ciberint_severity "$score")
            printf "  %-16s  %d dias  Score: %3d [%s]\n" "$ip" "$days" "$score" "$severity"
        done
fi
echo ""

# ── Comparacion semana-sobre-semana ──
echo "== COMPARACION SEMANA-SOBRE-SEMANA =="
echo ""
PREV_WEEK_START=$(date -d "14 days ago" '+%Y-%m-%d' 2>/dev/null || date '+%Y-%m-%d')
THIS_WEEK_CONNS=0
PREV_WEEK_CONNS=0
if [[ -f "$HISTORY_FILE" ]]; then
    THIS_WEEK_CONNS=$(awk -v start="$WEEK_START" '$1 >= start' "$HISTORY_FILE" | wc -l)
    PREV_WEEK_CONNS=$(awk -v start="$PREV_WEEK_START" -v end="$WEEK_START" '$1 >= start && $1 < end' "$HISTORY_FILE" | wc -l)
fi
echo "Conexiones esta semana:     $THIS_WEEK_CONNS"
echo "Conexiones semana anterior: $PREV_WEEK_CONNS"
if [[ $PREV_WEEK_CONNS -gt 0 ]]; then
    CHANGE=$(( (THIS_WEEK_CONNS - PREV_WEEK_CONNS) * 100 / PREV_WEEK_CONNS ))
    echo "Cambio: ${CHANGE}%"
fi
echo ""

echo "──────────────────────────────────────────────────────"
echo "Generado por: Securizar - Ciberinteligencia Proactiva"
echo "Fecha: $(date '+%Y-%m-%d %H:%M:%S')"

} > "$REPORT" 2>/dev/null

# Email
source "$CIBERINT_CONFIG/ciberint.conf" 2>/dev/null || true
if [[ -n "${CIBERINT_NOTIFY_EMAIL:-}" ]] && command -v mail &>/dev/null; then
    mail -s "[CiberInt] Informe semanal $(hostname) $WEEK" \
        "$CIBERINT_NOTIFY_EMAIL" < "$REPORT" 2>/dev/null || true
fi

echo "Informe semanal generado: $REPORT"
ciberint_log "INFO" "Reporte semanal generado: $REPORT"
EOFS6B

chmod 755 "$CIBERINT_BIN/ciberint-reporte-semanal.sh"
log_change "Creado" "$CIBERINT_BIN/ciberint-reporte-semanal.sh"
log_change "Permisos" "$CIBERINT_BIN/ciberint-reporte-semanal.sh -> 755"

# Timer diario 07:00
cat > /etc/systemd/system/ciberint-reporte-diario.service << EOFSVC
[Unit]
Description=Ciberinteligencia - Reporte Diario
After=network.target

[Service]
Type=oneshot
ExecStart=$CIBERINT_BIN/ciberint-reporte-diario.sh
StandardOutput=append:$CIBERINT_BASE/log/reportes.log
StandardError=append:$CIBERINT_BASE/log/reportes.log
EOFSVC

cat > /etc/systemd/system/ciberint-reporte-diario.timer << 'EOFTMR'
[Unit]
Description=Ciberinteligencia - Reporte diario 07:00

[Timer]
OnCalendar=*-*-* 07:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOFTMR

log_change "Creado" "/etc/systemd/system/ciberint-reporte-diario.service"
log_change "Creado" "/etc/systemd/system/ciberint-reporte-diario.timer"

systemctl daemon-reload
log_change "Aplicado" "systemctl daemon-reload"
systemctl enable --now ciberint-reporte-diario.timer 2>/dev/null || true
log_change "Servicio" "ciberint-reporte-diario.timer enable+start"

# Cron semanal
cat > /etc/cron.weekly/ciberint-reporte-semanal << EOFCRON
#!/bin/bash
$CIBERINT_BIN/ciberint-reporte-semanal.sh >> $CIBERINT_BASE/log/reportes.log 2>&1
EOFCRON
chmod 700 /etc/cron.weekly/ciberint-reporte-semanal
log_change "Creado" "/etc/cron.weekly/ciberint-reporte-semanal"
log_change "Permisos" "/etc/cron.weekly/ciberint-reporte-semanal -> 700"

log_info "S6: Informes de inteligencia instalados (timer diario 07:00 + semanal)"

else
    log_skip "Informes de inteligencia automatizados (S6)"
fi  # S6

# ============================================================
# S7: MONITORIZACION DE CREDENCIALES EXPUESTAS
# ============================================================
log_section "S7: MONITORIZACION DE CREDENCIALES EXPUESTAS"

echo "Verificacion HIBP, escaneo de secretos locales."
echo "Scripts: ciberint-credenciales-expuestas.sh, ciberint-secretos-locales.sh"
echo "Cron: semanal"
echo ""

if ask "Instalar monitorizacion de credenciales?"; then

# ── ciberint-credenciales-expuestas.sh ──
cat > "$CIBERINT_BIN/ciberint-credenciales-expuestas.sh" << 'EOFS7A'
#!/bin/bash
# ============================================================
# ciberint-credenciales-expuestas.sh - HIBP password check
# Usa k-anonymity (solo primeros 5 chars del hash SHA1)
# ============================================================
set -uo pipefail

source /usr/local/lib/ciberinteligencia/ciberint-lib.sh

CRED_DIR="$CIBERINT_DATA/credentials"
mkdir -p "$CRED_DIR"
REPORT="$CRED_DIR/hibp-check-$(date +%Y%m%d).txt"

echo ""
echo -e "${CYAN}══ Verificacion de Credenciales Expuestas ══${NC}"
echo ""

# Funcion: verificar password contra HIBP
check_hibp_password() {
    local password="$1"
    local sha1
    sha1=$(echo -n "$password" | sha1sum | awk '{print toupper($1)}')
    local prefix="${sha1:0:5}"
    local suffix="${sha1:5}"

    local response
    response=$(curl -sS --max-time 10 "https://api.pwnedpasswords.com/range/$prefix" 2>/dev/null) || return 2

    local count
    count=$(echo "$response" | grep -i "^$suffix:" | cut -d: -f2 | tr -d '\r')

    if [[ -n "$count" ]]; then
        echo "$count"
        return 0
    fi
    echo "0"
    return 1
}

EXPOSED=0
CHECKED=0

{
echo "HIBP Password Check Report - $(date)"
echo "======================================="
echo ""

# Verificar passwords comunes del sistema
# Extraer usuarios con shell valida
while IFS=: read -r user _ uid _ _ home shell; do
    [[ "$shell" == */nologin ]] && continue
    [[ "$shell" == */false ]] && continue
    [[ $uid -lt 500 && "$user" != "root" ]] && continue

    CHECKED=$(( CHECKED + 1 ))

    # Verificar si el usuario tiene password (no locked)
    SHADOW_ENTRY=$(getent shadow "$user" 2>/dev/null | cut -d: -f2)
    [[ -z "$SHADOW_ENTRY" || "$SHADOW_ENTRY" == "!" || "$SHADOW_ENTRY" == "*" || "$SHADOW_ENTRY" == "!!" ]] && continue

    # Verificar patrones comunes (no la password real - verificamos patrones predecibles)
    COMMON_PASSWORDS="password 123456 admin root $user ${user}123 ${user}2024 ${user}2025 changeme"
    for test_pwd in $COMMON_PASSWORDS; do
        HIBP_COUNT=$(check_hibp_password "$test_pwd" 2>/dev/null) || continue
        if [[ "$HIBP_COUNT" -gt 0 && "$HIBP_COUNT" != "0" ]]; then
            # Verificar si la password del usuario coincide con esta
            HASH_ALGO=$(echo "$SHADOW_ENTRY" | cut -d'$' -f2)
            SALT=$(echo "$SHADOW_ENTRY" | cut -d'$' -f3)
            if [[ -n "$HASH_ALGO" && -n "$SALT" ]]; then
                TEST_HASH=$(openssl passwd -"$HASH_ALGO" -salt "$SALT" "$test_pwd" 2>/dev/null || echo "NOMATCH")
                if [[ "$TEST_HASH" == "$SHADOW_ENTRY" ]]; then
                    echo "EXPOSED: usuario '$user' usa password vista $HIBP_COUNT veces en breaches"
                    EXPOSED=$(( EXPOSED + 1 ))
                    ciberint_alert "CRITICAL" "credenciales" \
                        "Usuario $user usa password expuesta en breaches ($HIBP_COUNT veces)" \
                        "Cambio de password urgente requerido"
                fi
            fi
        fi
    done
done < /etc/passwd

echo ""
echo "Usuarios verificados: $CHECKED"
echo "Credenciales expuestas: $EXPOSED"

} > "$REPORT" 2>/dev/null

cat "$REPORT"
ciberint_log "INFO" "HIBP check: $CHECKED usuarios, $EXPOSED expuestos"
EOFS7A

chmod 755 "$CIBERINT_BIN/ciberint-credenciales-expuestas.sh"
log_change "Creado" "$CIBERINT_BIN/ciberint-credenciales-expuestas.sh"
log_change "Permisos" "$CIBERINT_BIN/ciberint-credenciales-expuestas.sh -> 755"

# ── ciberint-secretos-locales.sh ──
cat > "$CIBERINT_BIN/ciberint-secretos-locales.sh" << 'EOFS7B'
#!/bin/bash
# ============================================================
# ciberint-secretos-locales.sh - Escaneo de secretos locales
# Busca claves API, tokens, private keys, credenciales
# ============================================================
set -uo pipefail

source /usr/local/lib/ciberinteligencia/ciberint-lib.sh

CRED_DIR="$CIBERINT_DATA/credentials"
mkdir -p "$CRED_DIR"
REPORT="$CRED_DIR/secretos-$(date +%Y%m%d).txt"

echo ""
echo -e "${CYAN}══ Escaneo de Secretos Locales ══${NC}"
echo ""

FINDINGS=0

{
echo "Escaneo de Secretos Locales - $(date)"
echo "======================================="
echo ""

# 1. Claves privadas SSH con permisos laxos
echo "== CLAVES SSH =="
find /home /root -name "id_*" -not -name "*.pub" 2>/dev/null | while read -r keyfile; do
    PERMS=$(stat -c '%a' "$keyfile" 2>/dev/null)
    OWNER=$(stat -c '%U' "$keyfile" 2>/dev/null)
    if [[ "$PERMS" != "600" && "$PERMS" != "400" ]]; then
        echo "WARN: Clave SSH con permisos $PERMS: $keyfile (owner: $OWNER)"
        FINDINGS=$(( FINDINGS + 1 ))
    fi
done
echo ""

# 2. Archivos .env con credenciales
echo "== ARCHIVOS .env =="
find /home /opt /srv /var/www -name ".env" -type f 2>/dev/null | while read -r envfile; do
    SECRETS=$(grep -ciE '(password|secret|key|token|api_key)=' "$envfile" 2>/dev/null || echo 0)
    if [[ "$SECRETS" -gt 0 ]]; then
        echo "WARN: $envfile contiene $SECRETS posibles secretos"
        FINDINGS=$(( FINDINGS + 1 ))
    fi
done
echo ""

# 3. Credenciales AWS
echo "== CREDENCIALES AWS =="
find /home /root -path "*/.aws/credentials" 2>/dev/null | while read -r awsfile; do
    PERMS=$(stat -c '%a' "$awsfile" 2>/dev/null)
    echo "ENCONTRADO: $awsfile (permisos: $PERMS)"
    if [[ "$PERMS" != "600" ]]; then
        echo "  WARN: Permisos demasiado abiertos"
        FINDINGS=$(( FINDINGS + 1 ))
    fi
done
echo ""

# 4. Tokens y API keys en bash history
echo "== SECRETOS EN BASH HISTORY =="
find /home /root -name ".bash_history" 2>/dev/null | while read -r histfile; do
    OWNER=$(stat -c '%U' "$histfile" 2>/dev/null)
    # Buscar patrones de API keys/tokens (sin mostrar el valor)
    HITS=$(grep -ciE '(api[_-]?key|token|secret|password|bearer|authorization)' "$histfile" 2>/dev/null || echo 0)
    if [[ "$HITS" -gt 0 ]]; then
        echo "WARN: $histfile ($OWNER) contiene $HITS lineas con posibles credenciales"
        FINDINGS=$(( FINDINGS + 1 ))
    fi
done
echo ""

# 5. Variables de entorno con secretos
echo "== VARIABLES DE ENTORNO (procesos activos) =="
for proc_env in /proc/*/environ; do
    [[ ! -r "$proc_env" ]] && continue
    PID=$(echo "$proc_env" | cut -d/ -f3)
    PROC_NAME=$(cat "/proc/$PID/comm" 2>/dev/null || echo "?")
    HITS=$(tr '\0' '\n' < "$proc_env" 2>/dev/null | \
        grep -ciE '(password|secret|api_key|token|private_key)=' 2>/dev/null || echo 0)
    if [[ "$HITS" -gt 0 ]]; then
        echo "WARN: PID $PID ($PROC_NAME) tiene $HITS vars con posibles secretos"
        FINDINGS=$(( FINDINGS + 1 ))
    fi
done
echo ""

# 6. Private keys fuera de .ssh
echo "== CLAVES PRIVADAS SUELTAS =="
find /home /opt /srv /tmp /var -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "*.pfx" 2>/dev/null | \
    grep -v ".ssh" | while read -r keyfile; do
        PERMS=$(stat -c '%a' "$keyfile" 2>/dev/null)
        echo "ENCONTRADO: $keyfile (permisos: $PERMS)"
        FINDINGS=$(( FINDINGS + 1 ))
    done
echo ""

echo "Total hallazgos: $FINDINGS"

} > "$REPORT" 2>/dev/null

cat "$REPORT"

if [[ $FINDINGS -gt 0 ]]; then
    ciberint_alert "MEDIUM" "secretos-locales" \
        "Escaneo de secretos: $FINDINGS hallazgos" \
        "Ver reporte: $REPORT"
fi

ciberint_log "INFO" "Secretos locales: $FINDINGS hallazgos"
EOFS7B

chmod 755 "$CIBERINT_BIN/ciberint-secretos-locales.sh"
log_change "Creado" "$CIBERINT_BIN/ciberint-secretos-locales.sh"
log_change "Permisos" "$CIBERINT_BIN/ciberint-secretos-locales.sh -> 755"

# Cron semanal
cat > /etc/cron.weekly/ciberint-credenciales << EOFCRON
#!/bin/bash
$CIBERINT_BIN/ciberint-credenciales-expuestas.sh >> $CIBERINT_BASE/log/credenciales.log 2>&1
$CIBERINT_BIN/ciberint-secretos-locales.sh >> $CIBERINT_BASE/log/secretos.log 2>&1
EOFCRON
chmod 700 /etc/cron.weekly/ciberint-credenciales
log_change "Creado" "/etc/cron.weekly/ciberint-credenciales"
log_change "Permisos" "/etc/cron.weekly/ciberint-credenciales -> 700"

log_info "S7: Monitorizacion de credenciales instalada (cron semanal)"

else
    log_skip "Monitorizacion de credenciales expuestas (S7)"
fi  # S7

# ============================================================
# S8: INTEGRACION SOAR Y MONITORIZACION
# ============================================================
log_section "S8: INTEGRACION SOAR"

echo "Bridge entre alertas de ciberinteligencia y el sistema SOAR existente."
echo "Auto-bloqueo para CRITICAL, cola SOAR para HIGH, notificacion para MEDIUM."
echo "Timer: cada 10 minutos"
echo ""

if ask "Instalar integracion SOAR?"; then

# ── ciberint-soar-bridge.sh ──
cat > "$CIBERINT_BIN/ciberint-soar-bridge.sh" << 'EOFS8'
#!/bin/bash
# ============================================================
# ciberint-soar-bridge.sh - Bridge Ciberinteligencia -> SOAR
# Lee alertas y las procesa segun severidad
# ============================================================
set -uo pipefail

source /usr/local/lib/ciberinteligencia/ciberint-lib.sh

PROCESSED_DIR="$CIBERINT_ALERTS/.processed"
mkdir -p "$PROCESSED_DIR"
SOAR_RESPONDER="/usr/local/bin/soar-responder.sh"
SOAR_COLA="/var/lib/securizar-soar/cola"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

PROCESSED=0
BLOCKED=0
QUEUED=0
NOTIFIED=0

for alert_file in "$CIBERINT_ALERTS"/*.json; do
    [[ ! -f "$alert_file" ]] && continue
    ALERT_ID=$(basename "$alert_file" .json)

    # Saltar ya procesadas
    [[ -f "$PROCESSED_DIR/$ALERT_ID" ]] && continue

    SEVERITY=$(jq -r '.severity // "LOW"' "$alert_file" 2>/dev/null)
    SUBJECT=$(jq -r '.subject // "N/A"' "$alert_file" 2>/dev/null)
    DETAILS=$(jq -r '.details // ""' "$alert_file" 2>/dev/null)
    SOURCE=$(jq -r '.source // ""' "$alert_file" 2>/dev/null)

    case "$SEVERITY" in
        CRITICAL)
            # Auto-bloqueo via soar-responder
            if [[ -x "$SOAR_RESPONDER" ]]; then
                # Extraer IP si es posible
                IP=$(echo "$DETAILS" | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1)
                if [[ -n "$IP" ]]; then
                    "$SOAR_RESPONDER" block "$IP" "CiberInt auto-block: $SUBJECT" 2>/dev/null || true
                    BLOCKED=$(( BLOCKED + 1 ))
                fi
            fi
            # Tambien encolar
            if [[ -d "$SOAR_COLA" ]]; then
                cp "$alert_file" "$SOAR_COLA/" 2>/dev/null || true
                QUEUED=$(( QUEUED + 1 ))
            fi
            ;;
        HIGH)
            # Cola SOAR
            if [[ -d "$SOAR_COLA" ]]; then
                cp "$alert_file" "$SOAR_COLA/" 2>/dev/null || true
                QUEUED=$(( QUEUED + 1 ))
            fi
            ;;
        MEDIUM)
            # Solo notificacion
            source "$CIBERINT_CONFIG/ciberint.conf" 2>/dev/null || true
            if [[ -n "${CIBERINT_NOTIFY_EMAIL:-}" ]] && command -v mail &>/dev/null; then
                echo "$SUBJECT - $DETAILS" | \
                    mail -s "[CiberInt] [$SEVERITY] $SUBJECT" \
                    "$CIBERINT_NOTIFY_EMAIL" 2>/dev/null || true
            fi
            NOTIFIED=$(( NOTIFIED + 1 ))
            ;;
    esac

    # Marcar como procesada
    touch "$PROCESSED_DIR/$ALERT_ID"
    PROCESSED=$(( PROCESSED + 1 ))
done

if [[ $PROCESSED -gt 0 ]]; then
    ciberint_log "INFO" "SOAR bridge: $PROCESSED alertas (blocked=$BLOCKED queued=$QUEUED notified=$NOTIFIED)"
fi

# Limpiar alertas procesadas antiguas (>7 dias)
find "$CIBERINT_ALERTS" -name "*.json" -mtime +7 -delete 2>/dev/null || true
find "$PROCESSED_DIR" -mtime +7 -delete 2>/dev/null || true
EOFS8

chmod 755 "$CIBERINT_BIN/ciberint-soar-bridge.sh"
log_change "Creado" "$CIBERINT_BIN/ciberint-soar-bridge.sh"
log_change "Permisos" "$CIBERINT_BIN/ciberint-soar-bridge.sh -> 755"

# Timer: cada 10 min
cat > /etc/systemd/system/ciberint-soar-bridge.service << EOFSVC
[Unit]
Description=Ciberinteligencia - SOAR Bridge
After=network.target

[Service]
Type=oneshot
ExecStart=$CIBERINT_BIN/ciberint-soar-bridge.sh
StandardOutput=append:$CIBERINT_BASE/log/soar-bridge.log
StandardError=append:$CIBERINT_BASE/log/soar-bridge.log
EOFSVC

cat > /etc/systemd/system/ciberint-soar-bridge.timer << 'EOFTMR'
[Unit]
Description=Ciberinteligencia - SOAR Bridge cada 10 minutos

[Timer]
OnBootSec=3min
OnUnitActiveSec=10min
Persistent=true

[Install]
WantedBy=timers.target
EOFTMR

log_change "Creado" "/etc/systemd/system/ciberint-soar-bridge.service"
log_change "Creado" "/etc/systemd/system/ciberint-soar-bridge.timer"

systemctl daemon-reload
log_change "Aplicado" "systemctl daemon-reload"
systemctl enable --now ciberint-soar-bridge.timer 2>/dev/null || true
log_change "Servicio" "ciberint-soar-bridge.timer enable+start"

log_info "S8: Integracion SOAR instalada (timer 10min)"

else
    log_skip "Integracion SOAR (S8)"
fi  # S8

# ============================================================
# RESUMEN FINAL
# ============================================================
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║    CIBERINTELIGENCIA PROACTIVA - INSTALACION COMPLETADA    ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

echo -e "  ${CYAN}── Estado de componentes ──${NC}"
echo ""

# S1: Enriquecimiento
if [[ -x "$CIBERINT_BIN/ciberint-enriquecer-ioc.sh" ]]; then
    echo -e "  ${GREEN}OK${NC}  S1: Motor de enriquecimiento de IoC"
else
    echo -e "  ${YELLOW}--${NC}  S1: Motor de enriquecimiento no instalado"
fi

# S2: Red inteligente
if [[ -x "$CIBERINT_BIN/ciberint-red-inteligente.sh" ]]; then
    echo -e "  ${GREEN}OK${NC}  S2: Inteligencia de red proactiva"
else
    echo -e "  ${YELLOW}--${NC}  S2: Inteligencia de red no instalada"
fi

# S3: DNS
if [[ -x "$CIBERINT_BIN/ciberint-dns-inteligencia.sh" ]]; then
    echo -e "  ${GREEN}OK${NC}  S3: Inteligencia DNS"
else
    echo -e "  ${YELLOW}--${NC}  S3: Inteligencia DNS no instalada"
fi

# S4: Superficie
if [[ -x "$CIBERINT_BIN/ciberint-superficie-ataque.sh" ]]; then
    echo -e "  ${GREEN}OK${NC}  S4: Monitorizacion de superficie"
else
    echo -e "  ${YELLOW}--${NC}  S4: Monitorizacion de superficie no instalada"
fi

# S5: Alerta temprana
if [[ -x "$CIBERINT_BIN/ciberint-alerta-temprana.sh" ]]; then
    echo -e "  ${GREEN}OK${NC}  S5: Sistema de alerta temprana"
else
    echo -e "  ${YELLOW}--${NC}  S5: Alerta temprana no instalada"
fi

# S6: Informes
if [[ -x "$CIBERINT_BIN/ciberint-reporte-diario.sh" ]]; then
    echo -e "  ${GREEN}OK${NC}  S6: Informes de inteligencia"
else
    echo -e "  ${YELLOW}--${NC}  S6: Informes no instalados"
fi

# S7: Credenciales
if [[ -x "$CIBERINT_BIN/ciberint-credenciales-expuestas.sh" ]]; then
    echo -e "  ${GREEN}OK${NC}  S7: Monitorizacion de credenciales"
else
    echo -e "  ${YELLOW}--${NC}  S7: Credenciales no instaladas"
fi

# S8: SOAR
if [[ -x "$CIBERINT_BIN/ciberint-soar-bridge.sh" ]]; then
    echo -e "  ${GREEN}OK${NC}  S8: Integracion SOAR"
else
    echo -e "  ${YELLOW}--${NC}  S8: SOAR no instalado"
fi

echo ""

# Timers activos
echo -e "  ${CYAN}── Timers systemd ──${NC}"
echo ""
ACTIVE_TIMERS=0
for timer in ciberint-red ciberint-dns ciberint-superficie ciberint-alerta-temprana ciberint-reporte-diario ciberint-soar-bridge; do
    if systemctl is-enabled "${timer}.timer" &>/dev/null; then
        echo -e "  ${GREEN}OK${NC}  ${timer}.timer activo"
        ACTIVE_TIMERS=$(( ACTIVE_TIMERS + 1 ))
    else
        echo -e "  ${YELLOW}--${NC}  ${timer}.timer no activo"
    fi
done

echo ""

# Scripts instalados
SCRIPTS_INSTALLED=0
for script in ciberint-enriquecer-ioc.sh ciberint-red-inteligente.sh ciberint-geoip-update.sh \
    ciberint-dns-inteligencia.sh ciberint-dga-avanzado.sh ciberint-nrd-monitor.sh \
    ciberint-superficie-ataque.sh ciberint-superficie-comparar.sh \
    ciberint-alerta-temprana.sh ciberint-cve-monitor.sh ciberint-conexiones-historico.sh \
    ciberint-reporte-diario.sh ciberint-reporte-semanal.sh \
    ciberint-credenciales-expuestas.sh ciberint-secretos-locales.sh \
    ciberint-soar-bridge.sh; do
    [[ -x "$CIBERINT_BIN/$script" ]] && SCRIPTS_INSTALLED=$(( SCRIPTS_INSTALLED + 1 ))
done

echo -e "  ${CYAN}── Resumen ──${NC}"
echo ""
echo -e "  Scripts instalados:    ${BOLD}$SCRIPTS_INSTALLED/16${NC}"
echo -e "  Timers activos:        ${BOLD}$ACTIVE_TIMERS/6${NC}"
echo -e "  Base de datos:         ${BOLD}$CIBERINT_BASE${NC}"
echo -e "  Biblioteca:            ${BOLD}$CIBERINT_LIB_DIR${NC}"
echo ""
echo "Herramientas de uso directo:"
echo "  ciberint-enriquecer-ioc.sh <IP|dominio>   - Enriquecer indicador"
echo "  ciberint-red-inteligente.sh                - Analizar conexiones activas"
echo "  ciberint-dns-inteligencia.sh               - Analisis DNS"
echo "  ciberint-superficie-ataque.sh              - Snapshot superficie"
echo "  ciberint-cve-monitor.sh                    - Verificar CVEs"
echo "  ciberint-conexiones-historico.sh --stats    - Estadisticas conexiones"
echo "  ciberint-dga-avanzado.sh <dominio>         - Analisis DGA"
echo ""
echo "Configuracion: $CIBERINT_BASE/config/"
echo "  ciberint.conf       - Configuracion principal"
echo "  api-keys.conf       - Claves API opcionales (AbuseIPDB, VirusTotal)"
echo ""

show_changes_summary
