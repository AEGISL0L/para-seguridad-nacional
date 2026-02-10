#!/bin/bash
# ============================================================
# ciberint-lib.sh - Biblioteca compartida de Ciberinteligencia
# ============================================================
# Funciones reutilizables para todos los scripts del modulo 37.
# Uso:
#   source /usr/local/lib/ciberinteligencia/ciberint-lib.sh
# ============================================================

[[ -n "${_CIBERINT_LIB_LOADED:-}" ]] && return 0
_CIBERINT_LIB_LOADED=1

# ── Directorios base ─────────────────────────────────────────
CIBERINT_BASE="/var/lib/ciberinteligencia"
CIBERINT_CACHE="$CIBERINT_BASE/cache"
CIBERINT_CONFIG="$CIBERINT_BASE/config"
CIBERINT_DATA="$CIBERINT_BASE/data"
CIBERINT_LOG="$CIBERINT_BASE/log"
CIBERINT_ALERTS="$CIBERINT_DATA/alerts"
IOC_LISTS_DIR="/etc/threat-intelligence/lists"

# ── Colores ──────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── Configuracion ────────────────────────────────────────────
CIBERINT_CONF="$CIBERINT_CONFIG/ciberint.conf"
CIBERINT_API_KEYS="$CIBERINT_CONFIG/api-keys.conf"
CIBERINT_HIGH_RISK="$CIBERINT_CONFIG/high-risk-countries.conf"
CIBERINT_WEIGHTS="$CIBERINT_CONFIG/scoring-weights.conf"

# Cargar configuracion si existe
if [[ -f "$CIBERINT_CONF" ]]; then
    # shellcheck source=/dev/null
    source "$CIBERINT_CONF"
fi

# Defaults
CIBERINT_CACHE_TTL="${CIBERINT_CACHE_TTL:-86400}"       # 24h
CIBERINT_ENRICH_THRESHOLD="${CIBERINT_ENRICH_THRESHOLD:-30}"
CIBERINT_ALERT_THRESHOLD="${CIBERINT_ALERT_THRESHOLD:-50}"
CIBERINT_BLOCK_THRESHOLD="${CIBERINT_BLOCK_THRESHOLD:-75}"
CIBERINT_RATE_LIMIT_MS="${CIBERINT_RATE_LIMIT_MS:-1500}" # 1.5s entre consultas API

# ── Logging ──────────────────────────────────────────────────
ciberint_log() {
    local level="$1"; shift
    local msg="$*"
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$ts] [$level] $msg" >> "$CIBERINT_LOG/ciberint.log" 2>/dev/null
    case "$level" in
        INFO)  echo -e "${GREEN}[+]${NC} $msg" ;;
        WARN)  echo -e "${YELLOW}[!]${NC} $msg" ;;
        ERROR) echo -e "${RED}[X]${NC} $msg" ;;
        *)     echo -e "${DIM}[-]${NC} $msg" ;;
    esac
}

# ── Cache con TTL ────────────────────────────────────────────
ciberint_cache_get() {
    local namespace="$1"  # ioc, dns, geoip, cve
    local key="$2"
    local ttl="${3:-$CIBERINT_CACHE_TTL}"
    local cache_file="$CIBERINT_CACHE/$namespace/$key"

    [[ ! -f "$cache_file" ]] && return 1

    local file_age
    file_age=$(( $(date +%s) - $(stat -c %Y "$cache_file" 2>/dev/null || echo 0) ))
    if [[ $file_age -gt $ttl ]]; then
        rm -f "$cache_file"
        return 1
    fi

    cat "$cache_file"
    return 0
}

ciberint_cache_set() {
    local namespace="$1"
    local key="$2"
    local value="$3"
    local cache_dir="$CIBERINT_CACHE/$namespace"

    mkdir -p "$cache_dir" 2>/dev/null
    echo "$value" > "$cache_dir/$key"
}

# ── GeoIP lookup (CSV local) ────────────────────────────────
ciberint_geoip_lookup() {
    local ip="$1"
    local geoip_csv="$CIBERINT_CACHE/geoip/dbip-country-lite.csv"

    [[ ! -f "$geoip_csv" ]] && echo "??" && return 1

    local ip_int
    ip_int=$(ciberint_ip_to_int "$ip") || { echo "??"; return 1; }

    # Binary-style search via awk on the sorted CSV
    awk -F',' -v target="$ip_int" '
    function ip2int(ip,    a, n) {
        n = split(ip, a, ".")
        if (n != 4) return 0
        return a[1]*16777216 + a[2]*65536 + a[3]*256 + a[4]
    }
    {
        start = ip2int($1)
        end   = ip2int($2)
        if (target >= start && target <= end) {
            print $3
            exit
        }
    }
    ' "$geoip_csv" 2>/dev/null || echo "??"
}

# ── IP a entero ──────────────────────────────────────────────
ciberint_ip_to_int() {
    local ip="$1"
    local a b c d
    IFS='.' read -r a b c d <<< "$ip"
    [[ -z "$a" || -z "$b" || -z "$c" || -z "$d" ]] && return 1
    echo $(( a * 16777216 + b * 65536 + c * 256 + d ))
}

# ── Scoring compuesto 0-100 ─────────────────────────────────
ciberint_score_ip() {
    local ip="$1"
    local score=0

    # 1. Feeds locales (+40)
    if [[ -f "$IOC_LISTS_DIR/malicious-ips.txt" ]]; then
        if grep -qF "$ip" "$IOC_LISTS_DIR/malicious-ips.txt" 2>/dev/null; then
            score=$(( score + 40 ))
        fi
    fi

    # 2. Membership en ipsets activos (+40)
    if command -v ipset &>/dev/null; then
        for setname in $(ipset list -n 2>/dev/null); do
            if ipset test "$setname" "$ip" 2>/dev/null; then
                score=$(( score + 40 ))
                break
            fi
        done
    fi

    # 3. Feeds adicionales (+5 por cada feed extra)
    local feed_count=0
    if [[ -d "$IOC_LISTS_DIR" ]]; then
        for feed in "$IOC_LISTS_DIR"/*.txt; do
            [[ ! -f "$feed" ]] && continue
            [[ "$feed" == */malicious-ips.txt ]] && continue
            if grep -qF "$ip" "$feed" 2>/dev/null; then
                feed_count=$(( feed_count + 1 ))
            fi
        done
        score=$(( score + feed_count * 5 ))
    fi

    # Cap at 100
    [[ $score -gt 100 ]] && score=100
    echo "$score"
}

# ── Severidad ────────────────────────────────────────────────
ciberint_severity() {
    local score="$1"
    if [[ $score -ge 76 ]]; then
        echo "CRITICAL"
    elif [[ $score -ge 51 ]]; then
        echo "HIGH"
    elif [[ $score -ge 26 ]]; then
        echo "MEDIUM"
    else
        echo "LOW"
    fi
}

# ── Generar alerta ───────────────────────────────────────────
ciberint_alert() {
    local severity="$1"
    local source="$2"
    local subject="$3"
    local details="$4"
    local ts
    ts=$(date '+%Y-%m-%dT%H:%M:%S%z')
    local alert_id
    alert_id="CIBERINT-$(date +%s)-$$"

    mkdir -p "$CIBERINT_ALERTS" 2>/dev/null

    cat > "$CIBERINT_ALERTS/${alert_id}.json" << EOFALERT
{
  "id": "${alert_id}",
  "timestamp": "${ts}",
  "severity": "${severity}",
  "source": "${source}",
  "subject": "${subject}",
  "details": "${details}"
}
EOFALERT

    ciberint_log "WARN" "ALERTA [$severity] [$source] $subject"
}

# ── API GET con rate limiting ────────────────────────────────
_CIBERINT_LAST_API_CALL=0

ciberint_api_get() {
    local url="$1"
    local timeout="${2:-10}"

    # Rate limiting
    local now
    now=$(date +%s%N 2>/dev/null || date +%s)
    now=${now:0:13}  # ms
    local last=${_CIBERINT_LAST_API_CALL:-0}
    local diff=$(( now - last ))
    if [[ $diff -lt $CIBERINT_RATE_LIMIT_MS ]]; then
        local wait_ms=$(( CIBERINT_RATE_LIMIT_MS - diff ))
        sleep "$(awk "BEGIN{printf \"%.2f\", $wait_ms/1000}")"
    fi

    local result
    result=$(curl -sS --max-time "$timeout" --connect-timeout 5 \
        -H "User-Agent: Securizar-CiberInt/1.0" \
        "$url" 2>/dev/null) || return 1

    _CIBERINT_LAST_API_CALL=$(date +%s%N 2>/dev/null || date +%s)
    _CIBERINT_LAST_API_CALL=${_CIBERINT_LAST_API_CALL:0:13}

    echo "$result"
}

# ── Entropia Shannon (via awk) ───────────────────────────────
ciberint_entropy() {
    local str="$1"
    echo "$str" | awk '{
        n = length($0)
        if (n == 0) { print 0; exit }
        for (i = 1; i <= n; i++) {
            c = substr($0, i, 1)
            freq[c]++
        }
        entropy = 0
        for (c in freq) {
            p = freq[c] / n
            if (p > 0) entropy -= p * (log(p) / log(2))
        }
        printf "%.4f\n", entropy
    }'
}

# ── Validar IP ───────────────────────────────────────────────
ciberint_is_valid_ip() {
    local ip="$1"
    [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
    local IFS='.'
    local -a octets
    read -ra octets <<< "$ip"
    for o in "${octets[@]}"; do
        [[ $o -gt 255 ]] && return 1
    done
    return 0
}

# ── Es IP privada ────────────────────────────────────────────
ciberint_is_private_ip() {
    local ip="$1"
    local a b
    IFS='.' read -r a b _ _ <<< "$ip"
    [[ "$a" -eq 10 ]] && return 0
    [[ "$a" -eq 172 && "$b" -ge 16 && "$b" -le 31 ]] && return 0
    [[ "$a" -eq 192 && "$b" -eq 168 ]] && return 0
    [[ "$a" -eq 127 ]] && return 0
    return 1
}

# ── Paises de alto riesgo ────────────────────────────────────
ciberint_is_high_risk_country() {
    local country="$1"
    local hr_file="$CIBERINT_HIGH_RISK"

    if [[ -f "$hr_file" ]]; then
        grep -qiF "$country" "$hr_file" 2>/dev/null && return 0
    fi
    return 1
}

# ── Cargar claves API opcionales ─────────────────────────────
ciberint_get_api_key() {
    local service="$1"
    [[ ! -f "$CIBERINT_API_KEYS" ]] && return 1
    local key
    key=$(grep "^${service}=" "$CIBERINT_API_KEYS" 2>/dev/null | head -1 | cut -d'=' -f2-)
    [[ -z "$key" ]] && return 1
    echo "$key"
}

# ── Timestamp legible ────────────────────────────────────────
ciberint_ts() {
    date '+%Y-%m-%d %H:%M:%S'
}

# ── Asegurar directorios base ────────────────────────────────
ciberint_ensure_dirs() {
    mkdir -p "$CIBERINT_CACHE"/{ioc,dns,geoip,cve} 2>/dev/null
    mkdir -p "$CIBERINT_CONFIG" 2>/dev/null
    mkdir -p "$CIBERINT_DATA"/{attack-surface,reports,alerts,credentials} 2>/dev/null
    mkdir -p "$CIBERINT_LOG" 2>/dev/null
}
