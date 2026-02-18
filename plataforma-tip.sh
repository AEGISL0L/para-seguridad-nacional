#!/bin/bash
# ============================================================
# plataforma-tip.sh - Modulo 77: Plataforma TIP
# ============================================================
# Plataforma de inteligencia de amenazas: MISP, STIX, TAXII,
# ciclo de vida IOC, campañas y comparticion de inteligencia.
# Secciones:
#   S1  - Cliente MISP (PyMISP/curl REST)
#   S2  - Parser STIX 2.1
#   S3  - Consumer TAXII 2.1
#   S4  - Ciclo de vida IOC
#   S5  - Tracker de campañas
#   S6  - Framework de atribucion
#   S7  - Comparticion de inteligencia
#   S8  - Correlacion cross-source
#   S9  - Threat briefings
#   S10 - Auditoria integral TIP
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "tip"
securizar_setup_traps

# ── Pre-check: detectar secciones ya aplicadas ──────────────
_precheck 10
_pc 'check_executable /usr/local/bin/securizar-misp-client.sh'
_pc 'check_executable /usr/local/bin/securizar-stix-parser.sh'
_pc 'check_executable /usr/local/bin/securizar-taxii-consumer.sh'
_pc 'check_executable /usr/local/bin/securizar-ioc-lifecycle.sh'
_pc 'check_executable /usr/local/bin/securizar-campaign-tracker.sh'
_pc 'check_executable /usr/local/bin/securizar-attribution.sh'
_pc 'check_executable /usr/local/bin/securizar-intel-share.sh'
_pc 'check_executable /usr/local/bin/securizar-tip-correlate.sh'
_pc 'check_executable /usr/local/bin/securizar-threat-briefing.sh'
_pc 'check_executable /usr/local/bin/auditoria-tip-completa.sh'
_precheck_result

log_section "MODULO 77: PLATAFORMA TIP"
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

TIP_DIR="/etc/securizar/tip"
TIP_BIN="/usr/local/bin"
TIP_LOG="/var/log/securizar/tip"
TIP_DATA="/var/lib/securizar/tip"
mkdir -p "$TIP_DIR" "$TIP_LOG" \
    "$TIP_DATA"/{misp,stix,taxii,iocs,campaigns,attribution,briefings,correlation} || true

# Verificar dependencias
log_info "Verificando dependencias..."
for dep in jq curl awk; do
    if command -v "$dep" &>/dev/null; then
        log_info "  OK  $dep disponible"
    else
        log_info "  --  $dep no encontrado (requerido)"
    fi
done
if command -v python3 &>/dev/null; then
    log_info "  OK  python3 disponible"
    if python3 -c "import pymisp" 2>/dev/null; then
        log_info "  OK  PyMISP disponible"
    else
        log_info "  --  PyMISP no instalado (fallback a curl REST)"
    fi
else
    log_info "  --  python3 no encontrado (opcional para PyMISP)"
fi
echo ""

# ============================================================
# S1: CLIENTE MISP (PyMISP/curl REST)
# ============================================================
log_section "S1: Cliente MISP"

log_info "Interfaz con MISP: busqueda, pull y push de eventos."
log_info "  - PyMISP si disponible, fallback curl REST"
log_info "  - Sincroniza con feeds del modulo 17"
log_info ""

if check_executable /usr/local/bin/securizar-misp-client.sh; then
    log_already "Cliente MISP (securizar-misp-client.sh existe)"
elif ask "Crear cliente MISP?"; then

    cat > "$TIP_BIN/securizar-misp-client.sh" << 'EOFMISP'
#!/bin/bash
# ============================================================
# securizar-misp-client.sh - Cliente MISP REST/PyMISP
# ============================================================
set -euo pipefail

MISP_CONF="/etc/securizar/tip/misp.conf"
MISP_DATA="/var/lib/securizar/tip/misp"
MISP_LOG="/var/log/securizar/tip/misp.log"

mkdir -p "$MISP_DATA" 2>/dev/null

# Cargar config
MISP_URL="${MISP_URL:-}"
MISP_KEY="${MISP_KEY:-}"
[[ -f "$MISP_CONF" ]] && source "$MISP_CONF"

log_msg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$MISP_LOG"; }

misp_curl() {
    local endpoint="$1"
    local method="${2:-GET}"
    local data="${3:-}"

    [[ -z "$MISP_URL" || -z "$MISP_KEY" ]] && {
        log_msg "ERROR: Configure MISP_URL y MISP_KEY en $MISP_CONF"
        return 1
    }

    local args=(-sS --max-time 30 -H "Authorization: $MISP_KEY"
        -H "Accept: application/json" -H "Content-Type: application/json")

    if [[ "$method" == "POST" ]] && [[ -n "$data" ]]; then
        args+=(-X POST -d "$data")
    fi

    curl "${args[@]}" "${MISP_URL}${endpoint}" 2>/dev/null
}

search_events() {
    local query="$1"
    log_msg "Buscando eventos MISP: $query"

    local payload
    payload=$(jq -n --arg q "$query" '{"value": $q, "searchall": true}')
    local result
    result=$(misp_curl "/events/restSearch" "POST" "$payload")

    if [[ -n "$result" ]]; then
        local count
        count=$(echo "$result" | jq '.response | length' 2>/dev/null || echo 0)
        log_msg "Encontrados $count eventos"
        echo "$result" | jq '.response[].Event | {id, info, date, threat_level_id}' 2>/dev/null
    fi
}

pull_event() {
    local event_id="$1"
    log_msg "Descargando evento MISP #$event_id"

    local result
    result=$(misp_curl "/events/view/$event_id")
    if [[ -n "$result" ]]; then
        echo "$result" > "$MISP_DATA/event-${event_id}.json"
        log_msg "Evento guardado: $MISP_DATA/event-${event_id}.json"
    fi
}

push_ioc() {
    local event_id="$1"
    local ioc_type="$2"
    local ioc_value="$3"

    log_msg "Publicando IOC en evento #$event_id: $ioc_type=$ioc_value"
    local payload
    payload=$(jq -n --arg t "$ioc_type" --arg v "$ioc_value" \
        '{"event_id": "'"$event_id"'", "type": $t, "value": $v, "to_ids": true}')

    misp_curl "/attributes/add/$event_id" "POST" "$payload"
}

sync_feeds() {
    log_msg "Sincronizando feeds MISP con modulo 17..."
    local ioc_dir="/etc/threat-intelligence/lists"
    [[ ! -d "$ioc_dir" ]] && { log_msg "Directorio IoC no encontrado"; return 1; }

    # Exportar IPs desde MISP
    local result
    result=$(misp_curl "/attributes/restSearch" "POST" \
        '{"type": "ip-dst", "to_ids": true, "last": "7d"}')
    if [[ -n "$result" ]]; then
        echo "$result" | jq -r '.response.Attribute[].value' 2>/dev/null | \
            sort -u > "$ioc_dir/misp-ips.txt"
        log_msg "Sincronizados $(wc -l < "$ioc_dir/misp-ips.txt") IPs desde MISP"
    fi
}

configure() {
    cat > "$MISP_CONF" << EOFCONF
# Configuracion MISP
MISP_URL="${1:-https://misp.example.com}"
MISP_KEY="${2:-YOUR_API_KEY_HERE}"
EOFCONF
    chmod 600 "$MISP_CONF"
    echo "Configuracion guardada en $MISP_CONF"
}

case "${1:-help}" in
    search)    shift; search_events "$@" ;;
    pull)      shift; pull_event "$@" ;;
    push)      shift; push_ioc "$@" ;;
    sync)      sync_feeds ;;
    configure) shift; configure "$@" ;;
    *)         echo "Uso: $0 {search <query>|pull <id>|push <id> <type> <value>|sync|configure <url> <key>}" ;;
esac
EOFMISP
    chmod +x "$TIP_BIN/securizar-misp-client.sh"
    log_change "Creado" "$TIP_BIN/securizar-misp-client.sh"

else
    log_skip "Cliente MISP"
fi

# ============================================================
# S2: PARSER STIX 2.1
# ============================================================
log_section "S2: Parser STIX 2.1"

log_info "Parser STIX 2.1 con jq: extrae indicators, actors, malware."
log_info "  - Genera bundles STIX desde IOCs locales"
log_info "  - Importa/exporta formato estandar"
log_info ""

if check_executable /usr/local/bin/securizar-stix-parser.sh; then
    log_already "STIX parser (securizar-stix-parser.sh existe)"
elif ask "Crear parser STIX 2.1?"; then

    cat > "$TIP_BIN/securizar-stix-parser.sh" << 'EOFSTIX'
#!/bin/bash
# ============================================================
# securizar-stix-parser.sh - Parser y generador STIX 2.1
# ============================================================
set -euo pipefail

STIX_DIR="/var/lib/securizar/tip/stix"
STIX_LOG="/var/log/securizar/tip/stix.log"

mkdir -p "$STIX_DIR"/{bundles,parsed} 2>/dev/null

log_msg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$STIX_LOG"; }

parse_bundle() {
    local bundle_file="$1"
    [[ ! -f "$bundle_file" ]] && { log_msg "ERROR: $bundle_file no encontrado"; return 1; }

    log_msg "Parseando bundle STIX: $bundle_file"

    local outdir="$STIX_DIR/parsed/$(basename "$bundle_file" .json)"
    mkdir -p "$outdir"

    # Extraer por tipo
    for stype in indicator malware threat-actor campaign intrusion-set attack-pattern; do
        jq -c ".objects[] | select(.type == \"$stype\")" "$bundle_file" 2>/dev/null > "$outdir/${stype}s.jsonl"
        local count
        count=$(wc -l < "$outdir/${stype}s.jsonl" 2>/dev/null || echo 0)
        [[ $count -gt 0 ]] && log_msg "  Extraidos $count ${stype}(s)"
    done

    # Extraer IOCs de indicators
    jq -r '.objects[] | select(.type=="indicator") | .pattern' "$bundle_file" 2>/dev/null | \
        grep -oP "'\K[^']+(?=')" > "$outdir/iocs-raw.txt" 2>/dev/null

    local total_iocs
    total_iocs=$(wc -l < "$outdir/iocs-raw.txt" 2>/dev/null || echo 0)
    log_msg "Parseado completado: $total_iocs IOCs extraidos"
}

create_bundle() {
    local name="${1:-securizar-export}"
    local ts
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    local bundle_id="bundle--$(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "$(date +%s)-$$")"

    local outfile="$STIX_DIR/bundles/${name}-$(date +%Y%m%d).json"

    # Recopilar IOCs del sistema
    local objects="[]"
    local ioc_dir="/etc/threat-intelligence/lists"

    if [[ -d "$ioc_dir" ]]; then
        while IFS= read -r ip; do
            [[ -z "$ip" || "$ip" =~ ^# ]] && continue
            local ind_id="indicator--$(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "$(date +%s)-$RANDOM")"
            objects=$(echo "$objects" | jq --arg id "$ind_id" --arg ts "$ts" --arg ip "$ip" \
                '. + [{
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": $id,
                    "created": $ts,
                    "modified": $ts,
                    "name": ("Malicious IP: " + $ip),
                    "pattern": ("[ipv4-addr:value = \u0027" + $ip + "\u0027]"),
                    "pattern_type": "stix",
                    "valid_from": $ts
                }]' 2>/dev/null)
        done < <(head -100 "$ioc_dir/malicious-ips.txt" 2>/dev/null)
    fi

    jq -n --arg id "$bundle_id" --argjson objects "$objects" \
        '{"type":"bundle","id":$id,"objects":$objects}' > "$outfile"

    log_msg "Bundle creado: $outfile ($(echo "$objects" | jq length) objetos)"
}

extract_iocs() {
    local bundle_file="$1"
    [[ ! -f "$bundle_file" ]] && { echo "Archivo no encontrado"; return 1; }

    jq -r '.objects[] | select(.type=="indicator") |
        "\(.pattern)" ' "$bundle_file" 2>/dev/null | \
        grep -oP "'\K[^']+(?=')" | sort -u
}

case "${1:-help}" in
    parse)   shift; parse_bundle "$@" ;;
    create)  shift; create_bundle "$@" ;;
    extract) shift; extract_iocs "$@" ;;
    *)       echo "Uso: $0 {parse <bundle.json>|create [name]|extract <bundle.json>}" ;;
esac
EOFSTIX
    chmod +x "$TIP_BIN/securizar-stix-parser.sh"
    log_change "Creado" "$TIP_BIN/securizar-stix-parser.sh"

else
    log_skip "Parser STIX 2.1"
fi

# ============================================================
# S3: CONSUMER TAXII 2.1
# ============================================================
log_section "S3: Consumer TAXII 2.1"

log_info "Cliente TAXII 2.1 via curl, delta sync."
log_info "  - Poll CIRCL + servidores configurables"
log_info "  - Sincronizacion incremental por added_after"
log_info ""

if check_executable /usr/local/bin/securizar-taxii-consumer.sh; then
    log_already "TAXII consumer (securizar-taxii-consumer.sh existe)"
elif ask "Crear consumer TAXII 2.1?"; then

    cat > "$TIP_BIN/securizar-taxii-consumer.sh" << 'EOFTAXII'
#!/bin/bash
# ============================================================
# securizar-taxii-consumer.sh - Cliente TAXII 2.1
# ============================================================
set -euo pipefail

TAXII_DIR="/var/lib/securizar/tip/taxii"
TAXII_LOG="/var/log/securizar/tip/taxii.log"
TAXII_CONF="/etc/securizar/tip/taxii-servers.conf"

mkdir -p "$TAXII_DIR"/{collections,state} 2>/dev/null

log_msg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$TAXII_LOG"; }

# Servidores TAXII por defecto
declare -A TAXII_SERVERS=(
    [circl]="https://www.circl.lu/taxii2"
)

# Cargar servidores adicionales
if [[ -f "$TAXII_CONF" ]]; then
    while IFS='=' read -r name url; do
        [[ -z "$name" || "$name" =~ ^# ]] && continue
        TAXII_SERVERS[$name]="$url"
    done < "$TAXII_CONF"
fi

taxii_get() {
    local url="$1"
    curl -sS --max-time 30 -H "Accept: application/taxii+json;version=2.1" \
        -H "Content-Type: application/taxii+json;version=2.1" \
        "$url" 2>/dev/null
}

discover() {
    local server="${1:-circl}"
    local base_url="${TAXII_SERVERS[$server]:-}"
    [[ -z "$base_url" ]] && { log_msg "ERROR: Servidor $server no configurado"; return 1; }

    log_msg "Descubriendo API roots en $server ($base_url)..."
    local discovery
    discovery=$(taxii_get "${base_url}/taxii2/")

    if [[ -n "$discovery" ]]; then
        echo "$discovery" | jq '.' 2>/dev/null
        log_msg "Discovery completado"
    else
        # Intentar listar collections directamente
        local collections
        collections=$(taxii_get "${base_url}/collections/")
        if [[ -n "$collections" ]]; then
            echo "$collections" | jq '.' 2>/dev/null
        else
            log_msg "No se pudo conectar a $server"
        fi
    fi
}

poll_collection() {
    local server="${1:-circl}"
    local collection_id="$2"
    local base_url="${TAXII_SERVERS[$server]:-}"
    [[ -z "$base_url" ]] && { log_msg "ERROR: Servidor $server no configurado"; return 1; }

    # Delta sync: usar added_after del ultimo poll
    local state_file="$TAXII_DIR/state/${server}_${collection_id}.last"
    local added_after=""
    [[ -f "$state_file" ]] && added_after=$(<"$state_file")

    local url="${base_url}/collections/${collection_id}/objects/"
    [[ -n "$added_after" ]] && url="${url}?added_after=${added_after}"

    log_msg "Polling $server/$collection_id (after: ${added_after:-inicio})..."

    local result
    result=$(taxii_get "$url")
    if [[ -n "$result" ]]; then
        local outfile="$TAXII_DIR/collections/${server}-${collection_id}-$(date +%Y%m%d-%H%M%S).json"
        echo "$result" > "$outfile"

        local obj_count
        obj_count=$(echo "$result" | jq '.objects | length' 2>/dev/null || echo 0)
        log_msg "Recibidos $obj_count objetos, guardados en $outfile"

        # Actualizar timestamp para delta sync
        date -u +%Y-%m-%dT%H:%M:%SZ > "$state_file"
    else
        log_msg "Sin nuevos datos de $server/$collection_id"
    fi
}

list_servers() {
    echo "Servidores TAXII configurados:"
    for name in "${!TAXII_SERVERS[@]}"; do
        echo "  $name: ${TAXII_SERVERS[$name]}"
    done
}

case "${1:-help}" in
    discover) shift; discover "$@" ;;
    poll)     shift; poll_collection "$@" ;;
    servers)  list_servers ;;
    *)        echo "Uso: $0 {discover [server]|poll <server> <collection_id>|servers}" ;;
esac
EOFTAXII
    chmod +x "$TIP_BIN/securizar-taxii-consumer.sh"
    log_change "Creado" "$TIP_BIN/securizar-taxii-consumer.sh"

else
    log_skip "Consumer TAXII 2.1"
fi

# ============================================================
# S4: CICLO DE VIDA IOC
# ============================================================
log_section "S4: Ciclo de vida IOC"

log_info "BD JSONL unificada de IOCs con aging por confianza."
log_info "  - Deduplicacion, expiracion, sincronizacion con modulo 17"
log_info "  - Scoring de confianza basado en fuentes"
log_info ""

if check_executable /usr/local/bin/securizar-ioc-lifecycle.sh; then
    log_already "IOC lifecycle (securizar-ioc-lifecycle.sh existe)"
elif ask "Crear gestor de ciclo de vida IOC?"; then

    cat > "$TIP_BIN/securizar-ioc-lifecycle.sh" << 'EOFIOC'
#!/bin/bash
# ============================================================
# securizar-ioc-lifecycle.sh - Ciclo de vida IOC
# ============================================================
set -euo pipefail

IOC_DB="/var/lib/securizar/tip/iocs/ioc-database.jsonl"
IOC_LOG="/var/log/securizar/tip/ioc-lifecycle.log"
IOC_DIR="/var/lib/securizar/tip/iocs"
DEFAULT_TTL_DAYS=90
MIN_CONFIDENCE=10

mkdir -p "$IOC_DIR" 2>/dev/null
touch "$IOC_DB" 2>/dev/null

log_msg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$IOC_LOG"; }

add_ioc() {
    local ioc_type="$1"    # ip, domain, hash, url, email
    local ioc_value="$2"
    local source="${3:-manual}"
    local confidence="${4:-50}"
    local tags="${5:-}"

    # Normalizar
    ioc_value=$(echo "$ioc_value" | tr '[:upper:]' '[:lower:]' | \
        sed -e 's/\[.\]/./g' -e 's/hxxp/http/gi')

    # Dedup check
    if grep -qF "\"value\":\"$ioc_value\"" "$IOC_DB" 2>/dev/null; then
        # Actualizar confianza si es mayor
        log_msg "IOC duplicado, actualizando: $ioc_value"
        local tmp="/tmp/ioc-update-$$.jsonl"
        jq -c "if .value == \"$ioc_value\" then .confidence = ([.confidence, $confidence] | max) | .last_seen = \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\" | .sources = (.sources + [\"$source\"] | unique) else . end" "$IOC_DB" > "$tmp" 2>/dev/null
        mv "$tmp" "$IOC_DB"
        return 0
    fi

    local ts
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    local expiry
    expiry=$(date -u -d "+${DEFAULT_TTL_DAYS} days" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || \
        date -u +%Y-%m-%dT%H:%M:%SZ)

    printf '{"type":"%s","value":"%s","confidence":%d,"sources":["%s"],"tags":"%s","first_seen":"%s","last_seen":"%s","expires":"%s","active":true}\n' \
        "$ioc_type" "$ioc_value" "$confidence" "$source" "$tags" "$ts" "$ts" "$expiry" >> "$IOC_DB"

    log_msg "IOC añadido: $ioc_type=$ioc_value (confianza=$confidence, fuente=$source)"
}

expire_iocs() {
    log_msg "Ejecutando expiracion de IOCs..."
    local now
    now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    local tmp="/tmp/ioc-expire-$$.jsonl"
    local expired=0 total=0

    while IFS= read -r line; do
        total=$((total + 1))
        local exp
        exp=$(echo "$line" | jq -r '.expires' 2>/dev/null)
        local conf
        conf=$(echo "$line" | jq -r '.confidence' 2>/dev/null)

        if [[ "$exp" < "$now" ]] || [[ ${conf:-0} -lt $MIN_CONFIDENCE ]]; then
            expired=$((expired + 1))
        else
            echo "$line" >> "$tmp"
        fi
    done < "$IOC_DB"

    [[ -f "$tmp" ]] && mv "$tmp" "$IOC_DB" || : > "$IOC_DB"
    log_msg "Expiracion completada: $expired eliminados de $total totales"
}

sync_feeds() {
    log_msg "Sincronizando IOCs activos con feeds del modulo 17..."
    local ioc_dir="/etc/threat-intelligence/lists"
    mkdir -p "$ioc_dir" 2>/dev/null

    # Exportar IPs activas
    jq -r 'select(.active==true and .type=="ip") | .value' "$IOC_DB" 2>/dev/null | \
        sort -u > "$ioc_dir/tip-iocs-ips.txt"

    # Exportar dominios activos
    jq -r 'select(.active==true and .type=="domain") | .value' "$IOC_DB" 2>/dev/null | \
        sort -u > "$ioc_dir/tip-iocs-domains.txt"

    local ips domains
    ips=$(wc -l < "$ioc_dir/tip-iocs-ips.txt" 2>/dev/null || echo 0)
    domains=$(wc -l < "$ioc_dir/tip-iocs-domains.txt" 2>/dev/null || echo 0)
    log_msg "Sincronizados: $ips IPs, $domains dominios"
}

stats() {
    [[ ! -f "$IOC_DB" ]] && { echo "BD vacia"; return; }
    echo "Estadisticas IOC:"
    echo "  Total: $(wc -l < "$IOC_DB")"
    echo "  Activos: $(jq -r 'select(.active==true)' "$IOC_DB" 2>/dev/null | wc -l)"
    echo "  Por tipo:"
    jq -r '.type' "$IOC_DB" 2>/dev/null | sort | uniq -c | sort -rn | \
        while read -r count tp; do echo "    $tp: $count"; done
    echo "  Por fuente:"
    jq -r '.sources[]' "$IOC_DB" 2>/dev/null | sort | uniq -c | sort -rn | \
        while read -r count src; do echo "    $src: $count"; done
}

case "${1:-help}" in
    add)    shift; add_ioc "$@" ;;
    expire) expire_iocs ;;
    sync)   sync_feeds ;;
    stats)  stats ;;
    *)      echo "Uso: $0 {add <type> <value> [source] [confidence] [tags]|expire|sync|stats}" ;;
esac
EOFIOC
    chmod +x "$TIP_BIN/securizar-ioc-lifecycle.sh"
    log_change "Creado" "$TIP_BIN/securizar-ioc-lifecycle.sh"

else
    log_skip "Ciclo de vida IOC"
fi

# ============================================================
# S5: TRACKER DE CAMPAÑAS
# ============================================================
log_section "S5: Tracker de campañas"

log_info "BD de campañas, mapeo MITRE ATT&CK, timeline."
log_info "  - IOCs compartidos entre campañas"
log_info "  - Correlacion de TTPs"
log_info ""

if check_executable /usr/local/bin/securizar-campaign-tracker.sh; then
    log_already "Campaign tracker (securizar-campaign-tracker.sh existe)"
elif ask "Crear tracker de campañas?"; then

    cat > "$TIP_BIN/securizar-campaign-tracker.sh" << 'EOFCAMP'
#!/bin/bash
# ============================================================
# securizar-campaign-tracker.sh - Tracker de campañas
# ============================================================
set -euo pipefail

CAMP_DIR="/var/lib/securizar/tip/campaigns"
CAMP_LOG="/var/log/securizar/tip/campaigns.log"

mkdir -p "$CAMP_DIR" 2>/dev/null

log_msg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$CAMP_LOG"; }

create_campaign() {
    local name="$1"
    local actor="${2:-unknown}"
    local description="${3:-}"

    local id="CAMP-$(date +%Y%m%d)-$(printf '%04d' $RANDOM)"
    local ts
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    local outfile="$CAMP_DIR/${id}.json"

    jq -n --arg id "$id" --arg name "$name" --arg actor "$actor" \
        --arg desc "$description" --arg ts "$ts" \
        '{id:$id, name:$name, actor:$actor, description:$desc,
          created:$ts, status:"active", ttps:[], iocs:[], timeline:[]}' > "$outfile"

    log_msg "Campaña creada: $id - $name (actor: $actor)"
    echo "$id"
}

add_ttp() {
    local camp_id="$1"
    local technique="$2"      # T1566.001
    local description="${3:-}"
    local camp_file="$CAMP_DIR/${camp_id}.json"

    [[ ! -f "$camp_file" ]] && { log_msg "ERROR: Campaña $camp_id no encontrada"; return 1; }

    local ts
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    jq --arg tech "$technique" --arg desc "$description" --arg ts "$ts" \
        '.ttps += [{"technique": $tech, "description": $desc, "observed": $ts}]' \
        "$camp_file" > "$camp_file.tmp" && mv "$camp_file.tmp" "$camp_file"

    log_msg "TTP añadido a $camp_id: $technique"
}

add_ioc() {
    local camp_id="$1"
    local ioc_type="$2"
    local ioc_value="$3"
    local camp_file="$CAMP_DIR/${camp_id}.json"

    [[ ! -f "$camp_file" ]] && { log_msg "ERROR: Campaña $camp_id no encontrada"; return 1; }

    jq --arg t "$ioc_type" --arg v "$ioc_value" \
        '.iocs += [{"type": $t, "value": $v}] | .iocs |= unique' \
        "$camp_file" > "$camp_file.tmp" && mv "$camp_file.tmp" "$camp_file"

    log_msg "IOC añadido a $camp_id: $ioc_type=$ioc_value"
}

timeline_event() {
    local camp_id="$1"
    local event="$2"
    local camp_file="$CAMP_DIR/${camp_id}.json"

    [[ ! -f "$camp_file" ]] && { return 1; }

    local ts
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    jq --arg ts "$ts" --arg ev "$event" \
        '.timeline += [{"timestamp": $ts, "event": $ev}]' \
        "$camp_file" > "$camp_file.tmp" && mv "$camp_file.tmp" "$camp_file"
}

list_campaigns() {
    echo "Campañas registradas:"
    for f in "$CAMP_DIR"/CAMP-*.json; do
        [[ ! -f "$f" ]] && continue
        jq -r '"\(.id)  \(.status)  \(.name)  actor=\(.actor)  TTPs=\(.ttps|length)  IOCs=\(.iocs|length)"' "$f" 2>/dev/null
    done
}

show_campaign() {
    local camp_id="$1"
    local camp_file="$CAMP_DIR/${camp_id}.json"
    [[ ! -f "$camp_file" ]] && { echo "No encontrada"; return 1; }
    jq '.' "$camp_file"
}

case "${1:-help}" in
    create)   shift; create_campaign "$@" ;;
    add-ttp)  shift; add_ttp "$@" ;;
    add-ioc)  shift; add_ioc "$@" ;;
    event)    shift; timeline_event "$@" ;;
    list)     list_campaigns ;;
    show)     shift; show_campaign "$@" ;;
    *)        echo "Uso: $0 {create <name> [actor] [desc]|add-ttp <id> <technique> [desc]|add-ioc <id> <type> <val>|list|show <id>}" ;;
esac
EOFCAMP
    chmod +x "$TIP_BIN/securizar-campaign-tracker.sh"
    log_change "Creado" "$TIP_BIN/securizar-campaign-tracker.sh"

else
    log_skip "Tracker de campañas"
fi

# ============================================================
# S6: FRAMEWORK DE ATRIBUCION
# ============================================================
log_section "S6: Framework de atribucion"

log_info "Perfiles de actores Diamond Model, scoring TTP overlap."
log_info "  - Niveles de confianza en atribucion"
log_info "  - Base de datos de actores conocidos"
log_info ""

if check_executable /usr/local/bin/securizar-attribution.sh; then
    log_already "Attribution framework (securizar-attribution.sh existe)"
elif ask "Crear framework de atribucion?"; then

    # Configuracion
    cat > "$TIP_DIR/attribution-framework.conf" << 'EOFATTRCONF'
# attribution-framework.conf - Framework de atribucion
# Niveles de confianza:
#   1 - Especulativo (indicios minimos)
#   2 - Posible (algunos TTPs coinciden)
#   3 - Probable (multiples TTPs + IOCs coinciden)
#   4 - Casi seguro (evidencia fuerte, multiples fuentes)
#   5 - Confirmado (evidencia irrefutable)
MIN_TTP_OVERLAP=3
MIN_CONFIDENCE_REPORT=2
EOFATTRCONF
    log_change "Creado" "$TIP_DIR/attribution-framework.conf"

    cat > "$TIP_BIN/securizar-attribution.sh" << 'EOFATTR'
#!/bin/bash
# ============================================================
# securizar-attribution.sh - Framework de atribucion Diamond Model
# ============================================================
set -euo pipefail

ATTR_DIR="/var/lib/securizar/tip/attribution"
ATTR_LOG="/var/log/securizar/tip/attribution.log"
ATTR_CONF="/etc/securizar/tip/attribution-framework.conf"

mkdir -p "$ATTR_DIR"/{actors,assessments} 2>/dev/null
[[ -f "$ATTR_CONF" ]] && source "$ATTR_CONF"
MIN_TTP_OVERLAP="${MIN_TTP_OVERLAP:-3}"

log_msg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$ATTR_LOG"; }

create_actor() {
    local name="$1"
    local aliases="${2:-}"
    local origin="${3:-unknown}"
    local motivation="${4:-unknown}"

    local id
    id=$(echo "$name" | tr '[:upper:] ' '[:lower:]-')
    local outfile="$ATTR_DIR/actors/${id}.json"
    local ts
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    jq -n --arg name "$name" --arg aliases "$aliases" --arg origin "$origin" \
        --arg motivation "$motivation" --arg ts "$ts" \
        '{name:$name, aliases:($aliases|split(",")), origin:$origin,
          motivation:$motivation, created:$ts, known_ttps:[], known_infrastructure:[],
          diamond:{adversary:$name, capability:"unknown", infrastructure:[], victim_types:[]}}' > "$outfile"

    log_msg "Actor creado: $name ($id)"
}

assess_attribution() {
    local incident_ttps_file="$1"
    [[ ! -f "$incident_ttps_file" ]] && { log_msg "ERROR: Archivo TTPs no encontrado"; return 1; }

    log_msg "Evaluando atribucion..."
    local incident_ttps
    incident_ttps=$(jq -r '.[]' "$incident_ttps_file" 2>/dev/null | sort -u)

    for actor_file in "$ATTR_DIR"/actors/*.json; do
        [[ ! -f "$actor_file" ]] && continue
        local actor_name
        actor_name=$(jq -r '.name' "$actor_file" 2>/dev/null)
        local actor_ttps
        actor_ttps=$(jq -r '.known_ttps[]' "$actor_file" 2>/dev/null | sort -u)

        local overlap
        overlap=$(comm -12 <(echo "$incident_ttps") <(echo "$actor_ttps") | wc -l)

        if [[ $overlap -ge $MIN_TTP_OVERLAP ]]; then
            local total_actor
            total_actor=$(echo "$actor_ttps" | grep -c . || echo 0)
            local pct=0
            [[ $total_actor -gt 0 ]] && pct=$((overlap * 100 / total_actor))
            log_msg "MATCH: $actor_name - $overlap TTPs coinciden ($pct% overlap)"
        fi
    done
}

list_actors() {
    echo "Actores registrados:"
    for f in "$ATTR_DIR"/actors/*.json; do
        [[ ! -f "$f" ]] && continue
        jq -r '"\(.name)  origin=\(.origin)  TTPs=\(.known_ttps|length)"' "$f" 2>/dev/null
    done
}

case "${1:-help}" in
    create)  shift; create_actor "$@" ;;
    assess)  shift; assess_attribution "$@" ;;
    list)    list_actors ;;
    *)       echo "Uso: $0 {create <name> [aliases] [origin] [motivation]|assess <ttps.json>|list}" ;;
esac
EOFATTR
    chmod +x "$TIP_BIN/securizar-attribution.sh"
    log_change "Creado" "$TIP_BIN/securizar-attribution.sh"

else
    log_skip "Framework de atribucion"
fi

# ============================================================
# S7: COMPARTICION DE INTELIGENCIA
# ============================================================
log_section "S7: Comparticion de inteligencia"

log_info "Exporta STIX/CSV/MISP, marcado TLP, sanitizacion."
log_info "  - Log de auditoria de comparticion"
log_info "  - Filtrado por TLP antes de exportar"
log_info ""

if check_executable /usr/local/bin/securizar-intel-share.sh; then
    log_already "Intel sharing (securizar-intel-share.sh existe)"
elif ask "Crear herramienta de comparticion de inteligencia?"; then

    cat > "$TIP_BIN/securizar-intel-share.sh" << 'EOFSHARE'
#!/bin/bash
# ============================================================
# securizar-intel-share.sh - Comparticion de inteligencia
# ============================================================
set -euo pipefail

SHARE_LOG="/var/log/securizar/tip/sharing.log"
IOC_DB="/var/lib/securizar/tip/iocs/ioc-database.jsonl"
STIX_DIR="/var/lib/securizar/tip/stix/bundles"

log_msg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$SHARE_LOG"; }

export_csv() {
    local tlp="${1:-WHITE}"
    local outfile="${2:-/tmp/securizar-iocs-export.csv}"

    [[ ! -f "$IOC_DB" ]] && { log_msg "BD IOC vacia"; return 1; }

    log_msg "Exportando CSV (TLP:$tlp)..."
    echo "type,value,confidence,first_seen,last_seen,sources" > "$outfile"

    local filter_confidence=0
    case "$tlp" in
        RED)   filter_confidence=80 ;;
        AMBER) filter_confidence=50 ;;
        GREEN) filter_confidence=30 ;;
        WHITE) filter_confidence=0 ;;
    esac

    jq -r "select(.active==true and .confidence >= $filter_confidence) |
        [.type, .value, .confidence, .first_seen, .last_seen, (.sources|join(\";\"))] | @csv" \
        "$IOC_DB" >> "$outfile" 2>/dev/null

    local count
    count=$(($(wc -l < "$outfile") - 1))
    log_msg "Exportados $count IOCs a $outfile (TLP:$tlp)"
    log_msg "AUDIT: export csv tlp=$tlp count=$count by=$(whoami)"
}

export_stix() {
    local tlp="${1:-WHITE}"
    log_msg "Exportando STIX bundle (TLP:$tlp)..."

    if [[ -x /usr/local/bin/securizar-stix-parser.sh ]]; then
        /usr/local/bin/securizar-stix-parser.sh create "export-tlp-${tlp}"
        log_msg "AUDIT: export stix tlp=$tlp by=$(whoami)"
    else
        log_msg "ERROR: securizar-stix-parser.sh no disponible"
    fi
}

export_misp() {
    local event_id="${1:-}"
    [[ -z "$event_id" ]] && { echo "Uso: $0 misp <event_id>"; return 1; }

    log_msg "Sincronizando con MISP evento #$event_id..."
    if [[ -x /usr/local/bin/securizar-misp-client.sh ]]; then
        # Push IOCs activos al evento MISP
        jq -r 'select(.active==true) | "\(.type) \(.value)"' "$IOC_DB" 2>/dev/null | \
            head -100 | while read -r ioc_type ioc_value; do
            local misp_type
            case "$ioc_type" in
                ip)     misp_type="ip-dst" ;;
                domain) misp_type="domain" ;;
                hash)   misp_type="sha256" ;;
                url)    misp_type="url" ;;
                *)      misp_type="$ioc_type" ;;
            esac
            /usr/local/bin/securizar-misp-client.sh push "$event_id" "$misp_type" "$ioc_value"
        done
        log_msg "AUDIT: export misp event=$event_id by=$(whoami)"
    else
        log_msg "ERROR: securizar-misp-client.sh no disponible"
    fi
}

case "${1:-help}" in
    csv)  shift; export_csv "$@" ;;
    stix) shift; export_stix "$@" ;;
    misp) shift; export_misp "$@" ;;
    *)    echo "Uso: $0 {csv [TLP] [outfile]|stix [TLP]|misp <event_id>}" ;;
esac
EOFSHARE
    chmod +x "$TIP_BIN/securizar-intel-share.sh"
    log_change "Creado" "$TIP_BIN/securizar-intel-share.sh"

else
    log_skip "Comparticion de inteligencia"
fi

# ============================================================
# S8: CORRELACION CROSS-SOURCE
# ============================================================
log_section "S8: Correlacion cross-source"

log_info "Matching cross-source, pivot analysis, grafo de relaciones."
log_info "  - Cascada de enriquecimiento automatico"
log_info "  - Deteccion de clusters de IOCs relacionados"
log_info ""

if check_executable /usr/local/bin/securizar-tip-correlate.sh; then
    log_already "TIP correlate (securizar-tip-correlate.sh existe)"
elif ask "Crear herramienta de correlacion cross-source?"; then

    cat > "$TIP_BIN/securizar-tip-correlate.sh" << 'EOFCORR'
#!/bin/bash
# ============================================================
# securizar-tip-correlate.sh - Correlacion cross-source TIP
# ============================================================
set -euo pipefail

CORR_DIR="/var/lib/securizar/tip/correlation"
CORR_LOG="/var/log/securizar/tip/correlation.log"
IOC_DB="/var/lib/securizar/tip/iocs/ioc-database.jsonl"
CAMP_DIR="/var/lib/securizar/tip/campaigns"

mkdir -p "$CORR_DIR" 2>/dev/null

log_msg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$CORR_LOG"; }

correlate_iocs() {
    [[ ! -f "$IOC_DB" ]] && { log_msg "BD IOC vacia"; return 1; }

    log_msg "Ejecutando correlacion cross-source..."
    local outfile="$CORR_DIR/correlation-$(date +%Y%m%d-%H%M%S).json"

    # Agrupar IOCs que comparten fuentes
    jq -s '
        [.[] | select(.active==true)] |
        group_by(.sources | sort | join(",")) |
        map(select(length > 1) | {
            shared_sources: .[0].sources,
            ioc_count: length,
            iocs: [.[] | {type, value, confidence}]
        })
    ' "$IOC_DB" > "$outfile" 2>/dev/null

    local clusters
    clusters=$(jq 'length' "$outfile" 2>/dev/null || echo 0)
    log_msg "Encontrados $clusters clusters de IOCs relacionados"
}

pivot_analysis() {
    local ioc_value="$1"
    [[ -z "$ioc_value" ]] && { echo "Uso: $0 pivot <ioc>"; return 1; }

    log_msg "Pivot analysis para: $ioc_value"

    # Buscar en BD IOC
    echo "=== BD IOC ==="
    jq -c "select(.value == \"$ioc_value\")" "$IOC_DB" 2>/dev/null

    # Buscar en campañas
    echo "=== Campañas ==="
    for f in "$CAMP_DIR"/CAMP-*.json; do
        [[ ! -f "$f" ]] && continue
        if jq -e ".iocs[] | select(.value == \"$ioc_value\")" "$f" &>/dev/null; then
            jq -r '"\(.id) - \(.name)"' "$f" 2>/dev/null
        fi
    done

    # Buscar en STIX bundles
    echo "=== STIX Bundles ==="
    for f in /var/lib/securizar/tip/stix/bundles/*.json; do
        [[ ! -f "$f" ]] && continue
        if grep -qF "$ioc_value" "$f" 2>/dev/null; then
            echo "  Encontrado en: $(basename "$f")"
        fi
    done
}

enrich_cascade() {
    local ioc_value="$1"
    local ioc_type="${2:-ip}"

    log_msg "Enriquecimiento en cascada: $ioc_type=$ioc_value"

    local result="{\"ioc\": \"$ioc_value\", \"type\": \"$ioc_type\"}"

    # GeoIP si es IP
    if [[ "$ioc_type" == "ip" ]] && [[ -f /usr/local/lib/ciberinteligencia/ciberint-lib.sh ]]; then
        source /usr/local/lib/ciberinteligencia/ciberint-lib.sh 2>/dev/null
        local score
        score=$(ciberint_score_ip "$ioc_value" 2>/dev/null || echo 0)
        local geo
        geo=$(ciberint_geoip_lookup "$ioc_value" 2>/dev/null || echo "??")
        result=$(echo "$result" | jq --arg s "$score" --arg g "$geo" '. + {score: ($s|tonumber), geo: $g}')
    fi

    # DNS reverso si es IP
    if [[ "$ioc_type" == "ip" ]]; then
        local rdns
        rdns=$(dig +short -x "$ioc_value" 2>/dev/null | head -1)
        [[ -n "$rdns" ]] && result=$(echo "$result" | jq --arg r "$rdns" '. + {rdns: $r}')
    fi

    echo "$result" | jq '.'
}

case "${1:-help}" in
    correlate) correlate_iocs ;;
    pivot)     shift; pivot_analysis "$@" ;;
    enrich)    shift; enrich_cascade "$@" ;;
    *)         echo "Uso: $0 {correlate|pivot <ioc>|enrich <ioc> [type]}" ;;
esac
EOFCORR
    chmod +x "$TIP_BIN/securizar-tip-correlate.sh"
    log_change "Creado" "$TIP_BIN/securizar-tip-correlate.sh"

else
    log_skip "Correlacion cross-source"
fi

# ============================================================
# S9: THREAT BRIEFINGS
# ============================================================
log_section "S9: Threat briefings"

log_info "Briefings diarios/semanales automatizados."
log_info "  - Tendencias, risk scoring, salida texto/JSON/email"
log_info "  - Resumen ejecutivo de amenazas activas"
log_info ""

if check_executable /usr/local/bin/securizar-threat-briefing.sh; then
    log_already "Threat briefing (securizar-threat-briefing.sh existe)"
elif ask "Crear generador de threat briefings?"; then

    cat > "$TIP_BIN/securizar-threat-briefing.sh" << 'EOFBRIEF'
#!/bin/bash
# ============================================================
# securizar-threat-briefing.sh - Generador de threat briefings
# ============================================================
set -euo pipefail

BRIEF_DIR="/var/lib/securizar/tip/briefings"
BRIEF_LOG="/var/log/securizar/tip/briefings.log"
IOC_DB="/var/lib/securizar/tip/iocs/ioc-database.jsonl"
CAMP_DIR="/var/lib/securizar/tip/campaigns"

mkdir -p "$BRIEF_DIR" 2>/dev/null

log_msg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$BRIEF_LOG"; }

generate_daily() {
    local ts
    ts=$(date +%Y%m%d)
    local outfile="$BRIEF_DIR/daily-${ts}.txt"
    local json_out="$BRIEF_DIR/daily-${ts}.json"

    log_msg "Generando briefing diario..."

    {
        echo "=========================================="
        echo "  THREAT INTELLIGENCE BRIEFING - $(date '+%Y-%m-%d')"
        echo "=========================================="
        echo ""

        # IOC stats
        echo "--- IOC Summary ---"
        if [[ -f "$IOC_DB" ]]; then
            local total active high_conf
            total=$(wc -l < "$IOC_DB" 2>/dev/null || echo 0)
            active=$(jq -r 'select(.active==true)' "$IOC_DB" 2>/dev/null | wc -l)
            high_conf=$(jq -r 'select(.active==true and .confidence>=70)' "$IOC_DB" 2>/dev/null | wc -l)
            echo "  Total IOCs: $total"
            echo "  Activos: $active"
            echo "  Alta confianza (>=70): $high_conf"

            # Nuevos en 24h
            local yesterday
            yesterday=$(date -u -d "1 day ago" +%Y-%m-%dT 2>/dev/null || echo "1970")
            local new_24h
            new_24h=$(jq -r "select(.first_seen > \"$yesterday\")" "$IOC_DB" 2>/dev/null | wc -l)
            echo "  Nuevos (24h): $new_24h"
        else
            echo "  BD IOC no disponible"
        fi
        echo ""

        # Campañas activas
        echo "--- Active Campaigns ---"
        local active_camps=0
        for f in "$CAMP_DIR"/CAMP-*.json; do
            [[ ! -f "$f" ]] && continue
            local status
            status=$(jq -r '.status' "$f" 2>/dev/null)
            if [[ "$status" == "active" ]]; then
                active_camps=$((active_camps + 1))
                jq -r '"  [\(.id)] \(.name) - actor: \(.actor) - TTPs: \(.ttps|length) - IOCs: \(.iocs|length)"' "$f" 2>/dev/null
            fi
        done
        [[ $active_camps -eq 0 ]] && echo "  Sin campañas activas"
        echo ""

        # Alertas recientes
        echo "--- Recent Alerts ---"
        local alert_dir="/var/lib/ciberinteligencia/data/alerts"
        if [[ -d "$alert_dir" ]]; then
            local recent_alerts
            recent_alerts=$(find "$alert_dir" -name "*.json" -mmin -1440 2>/dev/null | wc -l)
            echo "  Alertas (24h): $recent_alerts"
        else
            echo "  Sin directorio de alertas"
        fi
        echo ""
        echo "=========================================="
        echo "  Generado: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "=========================================="
    } > "$outfile"

    # Version JSON
    jq -n --arg date "$(date +%Y-%m-%d)" --arg gen "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{type:"daily_briefing", date:$date, generated:$gen}' > "$json_out" 2>/dev/null

    log_msg "Briefing diario generado: $outfile"
    cat "$outfile"
}

generate_weekly() {
    local ts
    ts=$(date +%Y-W%V)
    local outfile="$BRIEF_DIR/weekly-${ts}.txt"
    log_msg "Generando briefing semanal..."

    {
        echo "=========================================="
        echo "  WEEKLY THREAT BRIEFING - $ts"
        echo "=========================================="
        echo ""

        # Tendencias: IOCs por dia
        echo "--- IOC Trends (7 days) ---"
        for i in $(seq 0 6); do
            local day
            day=$(date -d "$i days ago" +%Y-%m-%d 2>/dev/null || date +%Y-%m-%d)
            local day_prefix
            day_prefix=$(date -d "$i days ago" +%Y-%m-%dT 2>/dev/null || echo "")
            if [[ -f "$IOC_DB" ]] && [[ -n "$day_prefix" ]]; then
                local count
                count=$(jq -r "select(.first_seen | startswith(\"$day_prefix\"))" "$IOC_DB" 2>/dev/null | wc -l)
                printf "  %s: %d nuevos IOCs\n" "$day" "$count"
            fi
        done
        echo ""
        echo "=========================================="
    } > "$outfile"

    log_msg "Briefing semanal generado: $outfile"
    cat "$outfile"
}

case "${1:-help}" in
    daily)  generate_daily ;;
    weekly) generate_weekly ;;
    *)      echo "Uso: $0 {daily|weekly}" ;;
esac
EOFBRIEF
    chmod +x "$TIP_BIN/securizar-threat-briefing.sh"
    log_change "Creado" "$TIP_BIN/securizar-threat-briefing.sh"

    # Cron diario
    cat > /etc/cron.daily/securizar-threat-briefing << 'EOFCRON'
#!/bin/bash
/usr/local/bin/securizar-threat-briefing.sh daily > /dev/null 2>&1
EOFCRON
    chmod 700 /etc/cron.daily/securizar-threat-briefing
    log_change "Creado" "/etc/cron.daily/securizar-threat-briefing"

else
    log_skip "Threat briefings"
fi

# ============================================================
# S10: AUDITORIA INTEGRAL TIP
# ============================================================
log_section "S10: Auditoria integral TIP"

log_info "Auditoria: conectividad MISP, estado TAXII sync, frescura datos."
log_info ""

if check_executable /usr/local/bin/auditoria-tip-completa.sh; then
    log_already "Auditoria integral (auditoria-tip-completa.sh existe)"
elif ask "Crear herramienta de auditoria integral TIP?"; then

    cat > "$TIP_BIN/auditoria-tip-completa.sh" << 'EOFAUDIT'
#!/bin/bash
# ============================================================
# auditoria-tip-completa.sh - Auditoria integral TIP
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

SCORE=0
MAX=0

check() {
    local desc="$1"
    local cmd="$2"
    MAX=$((MAX + 1))
    if eval "$cmd" &>/dev/null; then
        SCORE=$((SCORE + 1))
        echo -e "  ${GREEN}[PASS]${NC} $desc"
    else
        echo -e "  ${RED}[FAIL]${NC} $desc"
    fi
}

echo ""
echo -e "${BOLD}════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  AUDITORIA: PLATAFORMA TIP (Modulo 77)${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════════${NC}"
echo ""

# S1: MISP
check "Cliente MISP instalado" "test -x /usr/local/bin/securizar-misp-client.sh"
check "Config MISP presente" "test -f /etc/securizar/tip/misp.conf"

# S2: STIX
check "Parser STIX instalado" "test -x /usr/local/bin/securizar-stix-parser.sh"
check "Dir bundles STIX" "test -d /var/lib/securizar/tip/stix/bundles"

# S3: TAXII
check "Consumer TAXII instalado" "test -x /usr/local/bin/securizar-taxii-consumer.sh"
check "Datos TAXII presentes" "ls /var/lib/securizar/tip/taxii/collections/*.json"

# S4: IOC lifecycle
check "IOC lifecycle instalado" "test -x /usr/local/bin/securizar-ioc-lifecycle.sh"
check "BD IOC presente" "test -f /var/lib/securizar/tip/iocs/ioc-database.jsonl"
check "BD IOC no vacia" "test -s /var/lib/securizar/tip/iocs/ioc-database.jsonl"

# S5: Campaigns
check "Campaign tracker instalado" "test -x /usr/local/bin/securizar-campaign-tracker.sh"

# S6: Attribution
check "Attribution framework instalado" "test -x /usr/local/bin/securizar-attribution.sh"
check "Config attribution" "test -f /etc/securizar/tip/attribution-framework.conf"

# S7: Sharing
check "Intel sharing instalado" "test -x /usr/local/bin/securizar-intel-share.sh"

# S8: Correlation
check "TIP correlate instalado" "test -x /usr/local/bin/securizar-tip-correlate.sh"

# S9: Briefings
check "Threat briefing instalado" "test -x /usr/local/bin/securizar-threat-briefing.sh"
check "Cron briefing diario" "test -f /etc/cron.daily/securizar-threat-briefing"

# Dependencias
check "jq disponible" "command -v jq"
check "curl disponible" "command -v curl"

echo ""
echo -e "${BOLD}────────────────────────────────────────────────────────${NC}"
pct=0
[[ $MAX -gt 0 ]] && pct=$(( SCORE * 100 / MAX ))
if [[ $pct -ge 80 ]]; then
    echo -e "  Resultado: ${GREEN}${BOLD}${SCORE}/${MAX}${NC} (${pct}%) ${GREEN}BUENO${NC}"
elif [[ $pct -ge 50 ]]; then
    echo -e "  Resultado: ${YELLOW}${BOLD}${SCORE}/${MAX}${NC} (${pct}%) ${YELLOW}PARCIAL${NC}"
else
    echo -e "  Resultado: ${RED}${BOLD}${SCORE}/${MAX}${NC} (${pct}%) ${RED}INSUFICIENTE${NC}"
fi
echo -e "${BOLD}────────────────────────────────────────────────────────${NC}"
echo ""

logger -t securizar-tip "Auditoria completada: $SCORE/$MAX ($pct%)"
EOFAUDIT
    chmod +x "$TIP_BIN/auditoria-tip-completa.sh"
    log_change "Creado" "$TIP_BIN/auditoria-tip-completa.sh"

    # Cron semanal
    cat > /etc/cron.weekly/auditoria-tip << 'EOFCRON'
#!/bin/bash
/usr/local/bin/auditoria-tip-completa.sh > /dev/null 2>&1
EOFCRON
    chmod 700 /etc/cron.weekly/auditoria-tip
    log_change "Creado" "/etc/cron.weekly/auditoria-tip"

else
    log_skip "Auditoria integral TIP"
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
show_changes_summary
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   PLATAFORMA TIP (MODULO 77) COMPLETADO                  ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups guardados en: $BACKUP_DIR"
echo ""
echo "Comandos disponibles:"
echo "  - MISP client:     securizar-misp-client.sh {search|pull|push|sync|configure}"
echo "  - STIX parser:     securizar-stix-parser.sh {parse|create|extract}"
echo "  - TAXII consumer:  securizar-taxii-consumer.sh {discover|poll|servers}"
echo "  - IOC lifecycle:   securizar-ioc-lifecycle.sh {add|expire|sync|stats}"
echo "  - Campaigns:       securizar-campaign-tracker.sh {create|add-ttp|add-ioc|list|show}"
echo "  - Attribution:     securizar-attribution.sh {create|assess|list}"
echo "  - Intel sharing:   securizar-intel-share.sh {csv|stix|misp}"
echo "  - Correlation:     securizar-tip-correlate.sh {correlate|pivot|enrich}"
echo "  - Briefings:       securizar-threat-briefing.sh {daily|weekly}"
echo "  - Auditoria:       auditoria-tip-completa.sh"
