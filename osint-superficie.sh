#!/bin/bash
# ============================================================
# osint-superficie.sh - Modulo 78: OSINT y Superficie de Ataque
# ============================================================
# OSINT y monitorizacion de superficie de ataque de activos
# propios: CT logs, subdominios, fugas, WHOIS, vendor risk.
# Secciones:
#   S1  - Monitor de Certificate Transparency
#   S2  - Enumeracion pDNS
#   S3  - Monitor WHOIS
#   S4  - Descubrimiento de subdominios
#   S5  - Descubrimiento cloud
#   S6  - Fingerprinting tecnologico
#   S7  - Deteccion de fugas de codigo
#   S8  - Superficie de ingenieria social
#   S9  - Riesgo de terceros (vendors)
#   S10 - Auditoria integral OSINT
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "osint"
securizar_setup_traps

# ── Pre-check: detectar secciones ya aplicadas ──────────────
_precheck 10
_pc 'check_executable /usr/local/bin/securizar-ct-monitor.sh'
_pc 'check_executable /usr/local/bin/securizar-pdns-enum.sh'
_pc 'check_executable /usr/local/bin/securizar-whois-monitor.sh'
_pc 'check_executable /usr/local/bin/securizar-subdomain-discover.sh'
_pc 'check_executable /usr/local/bin/securizar-cloud-discover.sh'
_pc 'check_executable /usr/local/bin/securizar-tech-fingerprint.sh'
_pc 'check_executable /usr/local/bin/securizar-code-leak-detect.sh'
_pc 'check_executable /usr/local/bin/securizar-se-surface.sh'
_pc 'check_executable /usr/local/bin/securizar-vendor-risk.sh'
_pc 'check_executable /usr/local/bin/auditoria-osint-completa.sh'
_precheck_result

log_section "MODULO 78: OSINT Y SUPERFICIE DE ATAQUE"
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

OSINT_DIR="/etc/securizar/osint"
OSINT_BIN="/usr/local/bin"
OSINT_LOG="/var/log/securizar/osint"
OSINT_DATA="/var/lib/securizar/osint"
mkdir -p "$OSINT_DIR" "$OSINT_LOG" \
    "$OSINT_DATA"/{ct-logs,pdns,whois,subdomains,cloud,techstack,leaks,soceng,vendors} || true

# Verificar dependencias
log_info "Verificando dependencias..."
for dep in curl jq dig openssl whois; do
    if command -v "$dep" &>/dev/null; then
        log_info "  OK  $dep disponible"
    else
        log_info "  --  $dep no encontrado"
    fi
done
for dep in exiftool; do
    if command -v "$dep" &>/dev/null; then
        log_info "  OK  $dep disponible (opcional)"
    else
        log_info "  --  $dep no encontrado (opcional)"
    fi
done
echo ""

# ============================================================
# S1: MONITOR DE CERTIFICATE TRANSPARENCY
# ============================================================
log_section "S1: Monitor de Certificate Transparency"

log_info "Polling crt.sh API, delta certs conocidos."
log_info "  - Alerta emisiones inesperadas"
log_info "  - Historial de certificados por dominio"
log_info ""

if check_executable /usr/local/bin/securizar-ct-monitor.sh; then
    log_already "CT monitor (securizar-ct-monitor.sh existe)"
elif ask "Crear monitor de Certificate Transparency?"; then

    cat > "$OSINT_BIN/securizar-ct-monitor.sh" << 'EOFCT'
#!/bin/bash
# ============================================================
# securizar-ct-monitor.sh - Monitor de Certificate Transparency
# ============================================================
set -euo pipefail

CT_DIR="/var/lib/securizar/osint/ct-logs"
CT_LOG="/var/log/securizar/osint/ct.log"

mkdir -p "$CT_DIR" 2>/dev/null

log_msg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$CT_LOG"; }

monitor_domain() {
    local domain="$1"
    [[ -z "$domain" ]] && { echo "Uso: $0 monitor <domain>"; return 1; }

    log_msg "Consultando CT logs para $domain..."

    local result
    result=$(curl -sS --max-time 30 \
        "https://crt.sh/?q=%25.${domain}&output=json" 2>/dev/null)

    if [[ -z "$result" ]] || [[ "$result" == "null" ]]; then
        log_msg "Sin resultados de crt.sh para $domain"
        return 0
    fi

    local current="$CT_DIR/${domain}-$(date +%Y%m%d).json"
    echo "$result" > "$current"

    local cert_count
    cert_count=$(echo "$result" | jq 'length' 2>/dev/null || echo 0)
    log_msg "Encontrados $cert_count certificados para $domain"

    # Delta con snapshot anterior
    local previous
    previous=$(ls -t "$CT_DIR"/${domain}-*.json 2>/dev/null | grep -v "$(date +%Y%m%d)" | head -1)

    if [[ -n "$previous" ]] && [[ -f "$previous" ]]; then
        local prev_ids current_ids
        prev_ids=$(jq -r '.[].id' "$previous" 2>/dev/null | sort -u)
        current_ids=$(echo "$result" | jq -r '.[].id' 2>/dev/null | sort -u)

        local new_certs
        new_certs=$(comm -13 <(echo "$prev_ids") <(echo "$current_ids") | wc -l)
        if [[ $new_certs -gt 0 ]]; then
            log_msg "ALERTA: $new_certs nuevos certificados detectados para $domain"
            comm -13 <(echo "$prev_ids") <(echo "$current_ids") | while read -r cert_id; do
                local cn issuer
                cn=$(echo "$result" | jq -r ".[] | select(.id==$cert_id) | .common_name" 2>/dev/null | head -1)
                issuer=$(echo "$result" | jq -r ".[] | select(.id==$cert_id) | .issuer_name" 2>/dev/null | head -1)
                log_msg "  NUEVO CERT: id=$cert_id CN=$cn issuer=$issuer"
            done
        fi
    fi

    # Listar subdominios unicos desde CT
    echo "$result" | jq -r '.[].name_value' 2>/dev/null | tr ',' '\n' | \
        sed 's/^\*\.//' | sort -u > "$CT_DIR/${domain}-subdomains.txt"
    local sub_count
    sub_count=$(wc -l < "$CT_DIR/${domain}-subdomains.txt" 2>/dev/null || echo 0)
    log_msg "Subdominios unicos desde CT: $sub_count"
}

list_certs() {
    local domain="$1"
    local latest
    latest=$(ls -t "$CT_DIR"/${domain}-*.json 2>/dev/null | head -1)
    [[ -z "$latest" ]] && { echo "Sin datos para $domain"; return 1; }

    echo "Certificados recientes para $domain:"
    jq -r '.[] | "\(.not_before) | \(.common_name) | \(.issuer_name)"' "$latest" 2>/dev/null | \
        head -20
}

case "${1:-help}" in
    monitor) shift; monitor_domain "$@" ;;
    list)    shift; list_certs "$@" ;;
    *)       echo "Uso: $0 {monitor <domain>|list <domain>}" ;;
esac
EOFCT
    chmod +x "$OSINT_BIN/securizar-ct-monitor.sh"
    log_change "Creado" "$OSINT_BIN/securizar-ct-monitor.sh"

else
    log_skip "Monitor de Certificate Transparency"
fi

# ============================================================
# S2: ENUMERACION pDNS
# ============================================================
log_section "S2: Enumeracion pDNS"

log_info "Consulta fuentes pDNS (HackerTarget, etc.)."
log_info "  - Historial A/MX/NS/CNAME por dominio"
log_info ""

if check_executable /usr/local/bin/securizar-pdns-enum.sh; then
    log_already "pDNS enum (securizar-pdns-enum.sh existe)"
elif ask "Crear herramienta de enumeracion pDNS?"; then

    cat > "$OSINT_BIN/securizar-pdns-enum.sh" << 'EOFPDNSE'
#!/bin/bash
# ============================================================
# securizar-pdns-enum.sh - Enumeracion passive DNS
# ============================================================
set -euo pipefail

PDNS_DIR="/var/lib/securizar/osint/pdns"
PDNS_LOG="/var/log/securizar/osint/pdns.log"

mkdir -p "$PDNS_DIR" 2>/dev/null

log_msg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$PDNS_LOG"; }

enum_domain() {
    local domain="$1"
    [[ -z "$domain" ]] && { echo "Uso: $0 enum <domain>"; return 1; }

    local outfile="$PDNS_DIR/${domain}-$(date +%Y%m%d).json"
    log_msg "Enumerando DNS para $domain..."

    local results="{\"domain\":\"$domain\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"

    # Registros A
    local a_records
    a_records=$(dig +short A "$domain" 2>/dev/null | sort -u | jq -R . | jq -s '.')
    results=$(echo "$results" | jq --argjson a "$a_records" '. + {a_records: $a}')

    # Registros MX
    local mx_records
    mx_records=$(dig +short MX "$domain" 2>/dev/null | sort | jq -R . | jq -s '.')
    results=$(echo "$results" | jq --argjson mx "$mx_records" '. + {mx_records: $mx}')

    # Registros NS
    local ns_records
    ns_records=$(dig +short NS "$domain" 2>/dev/null | sort | jq -R . | jq -s '.')
    results=$(echo "$results" | jq --argjson ns "$ns_records" '. + {ns_records: $ns}')

    # Registros TXT
    local txt_records
    txt_records=$(dig +short TXT "$domain" 2>/dev/null | jq -R . | jq -s '.')
    results=$(echo "$results" | jq --argjson txt "$txt_records" '. + {txt_records: $txt}')

    # HackerTarget DNS lookup
    local ht_result
    ht_result=$(curl -sS --max-time 15 \
        "https://api.hackertarget.com/dnslookup/?q=${domain}" 2>/dev/null)
    if [[ -n "$ht_result" ]] && ! echo "$ht_result" | grep -q "error"; then
        results=$(echo "$results" | jq --arg ht "$ht_result" '. + {hackertarget: $ht}')
    fi

    echo "$results" | jq '.' > "$outfile"
    log_msg "Enumeracion guardada: $outfile"

    # Delta check
    local previous
    previous=$(ls -t "$PDNS_DIR"/${domain}-*.json 2>/dev/null | grep -v "$(date +%Y%m%d)" | head -1)
    if [[ -n "$previous" ]] && [[ -f "$previous" ]]; then
        local prev_a curr_a
        prev_a=$(jq -r '.a_records[]' "$previous" 2>/dev/null | sort)
        curr_a=$(jq -r '.a_records[]' "$outfile" 2>/dev/null | sort)
        if [[ "$prev_a" != "$curr_a" ]]; then
            log_msg "ALERTA: Cambio en registros A para $domain"
        fi
    fi
}

case "${1:-help}" in
    enum) shift; enum_domain "$@" ;;
    *)    echo "Uso: $0 {enum <domain>}" ;;
esac
EOFPDNSE
    chmod +x "$OSINT_BIN/securizar-pdns-enum.sh"
    log_change "Creado" "$OSINT_BIN/securizar-pdns-enum.sh"

else
    log_skip "Enumeracion pDNS"
fi

# ============================================================
# S3: MONITOR WHOIS
# ============================================================
log_section "S3: Monitor WHOIS"

log_info "Snapshots WHOIS, delta registrar/NS/expiracion."
log_info "  - Alertas ante cambios de registrar o nameservers"
log_info ""

if check_executable /usr/local/bin/securizar-whois-monitor.sh; then
    log_already "WHOIS monitor (securizar-whois-monitor.sh existe)"
elif ask "Crear monitor WHOIS?"; then

    cat > "$OSINT_BIN/securizar-whois-monitor.sh" << 'EOFWHOIS'
#!/bin/bash
# ============================================================
# securizar-whois-monitor.sh - Monitor WHOIS
# ============================================================
set -euo pipefail

WHOIS_DIR="/var/lib/securizar/osint/whois"
WHOIS_LOG="/var/log/securizar/osint/whois.log"

mkdir -p "$WHOIS_DIR" 2>/dev/null

log_msg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$WHOIS_LOG"; }

snapshot() {
    local domain="$1"
    [[ -z "$domain" ]] && { echo "Uso: $0 snapshot <domain>"; return 1; }

    if ! command -v whois &>/dev/null; then
        log_msg "ERROR: whois no disponible"
        return 1
    fi

    log_msg "Capturando WHOIS para $domain..."
    local raw
    raw=$(whois "$domain" 2>/dev/null)

    local outfile="$WHOIS_DIR/${domain}-$(date +%Y%m%d).txt"
    echo "$raw" > "$outfile"

    # Extraer campos clave
    local registrar nameservers expiry
    registrar=$(echo "$raw" | grep -i "registrar:" | head -1 | sed 's/.*: *//')
    nameservers=$(echo "$raw" | grep -i "name server:" | awk '{print $NF}' | sort -u | tr '\n' ',' | sed 's/,$//')
    expiry=$(echo "$raw" | grep -iE "expir|paid-till" | head -1 | sed 's/.*: *//')

    local json_file="$WHOIS_DIR/${domain}-$(date +%Y%m%d).json"
    jq -n --arg d "$domain" --arg r "$registrar" --arg ns "$nameservers" \
        --arg e "$expiry" --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{domain:$d, registrar:$r, nameservers:$ns, expiry:$e, captured:$ts}' > "$json_file"

    log_msg "WHOIS snapshot guardado: $json_file"
    log_msg "  Registrar: $registrar"
    log_msg "  NS: $nameservers"
    log_msg "  Expiry: $expiry"
}

check_delta() {
    local domain="$1"
    [[ -z "$domain" ]] && { echo "Uso: $0 check <domain>"; return 1; }

    local files
    files=$(ls -t "$WHOIS_DIR"/${domain}-*.json 2>/dev/null | head -2)
    local count
    count=$(echo "$files" | grep -c . || echo 0)
    [[ $count -lt 2 ]] && { log_msg "Se necesitan al menos 2 snapshots para comparar"; return 1; }

    local current previous
    current=$(echo "$files" | head -1)
    previous=$(echo "$files" | tail -1)

    local curr_reg prev_reg curr_ns prev_ns
    curr_reg=$(jq -r '.registrar' "$current" 2>/dev/null)
    prev_reg=$(jq -r '.registrar' "$previous" 2>/dev/null)
    curr_ns=$(jq -r '.nameservers' "$current" 2>/dev/null)
    prev_ns=$(jq -r '.nameservers' "$previous" 2>/dev/null)

    local changes=0
    if [[ "$curr_reg" != "$prev_reg" ]]; then
        log_msg "ALERTA: Cambio de registrar para $domain: $prev_reg -> $curr_reg"
        changes=$((changes + 1))
    fi
    if [[ "$curr_ns" != "$prev_ns" ]]; then
        log_msg "ALERTA: Cambio de nameservers para $domain: $prev_ns -> $curr_ns"
        changes=$((changes + 1))
    fi
    [[ $changes -eq 0 ]] && log_msg "Sin cambios WHOIS para $domain"
}

case "${1:-help}" in
    snapshot) shift; snapshot "$@" ;;
    check)    shift; check_delta "$@" ;;
    *)        echo "Uso: $0 {snapshot <domain>|check <domain>}" ;;
esac
EOFWHOIS
    chmod +x "$OSINT_BIN/securizar-whois-monitor.sh"
    log_change "Creado" "$OSINT_BIN/securizar-whois-monitor.sh"

else
    log_skip "Monitor WHOIS"
fi

# ============================================================
# S4: DESCUBRIMIENTO DE SUBDOMINIOS
# ============================================================
log_section "S4: Descubrimiento de subdominios"

log_info "Multi-fuente: CT+pDNS+brute+WebArchive+zone transfer."
log_info "  - Tracking delta de subdominios conocidos"
log_info ""

if check_executable /usr/local/bin/securizar-subdomain-discover.sh; then
    log_already "Subdomain discover (securizar-subdomain-discover.sh existe)"
elif ask "Crear herramienta de descubrimiento de subdominios?"; then

    cat > "$OSINT_BIN/securizar-subdomain-discover.sh" << 'EOFSUB'
#!/bin/bash
# ============================================================
# securizar-subdomain-discover.sh - Descubrimiento de subdominios
# ============================================================
set -euo pipefail

SUB_DIR="/var/lib/securizar/osint/subdomains"
SUB_LOG="/var/log/securizar/osint/subdomains.log"

mkdir -p "$SUB_DIR" 2>/dev/null

log_msg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$SUB_LOG"; }

BRUTE_WORDLIST="/usr/share/dict/words"
COMMON_SUBS="www mail ftp smtp pop imap ns1 ns2 dns mx webmail remote vpn admin api dev staging test beta app portal cdn static assets media img images docs blog shop store api-v2 grafana prometheus kibana jenkins gitlab ci cd"

discover() {
    local domain="$1"
    [[ -z "$domain" ]] && { echo "Uso: $0 discover <domain>"; return 1; }

    local outfile="$SUB_DIR/${domain}-$(date +%Y%m%d).txt"
    local tmpfile="/tmp/subs-$$-all.txt"
    : > "$tmpfile"

    log_msg "Descubriendo subdominios para $domain..."

    # Fuente 1: Certificate Transparency
    log_msg "  [CT] Consultando crt.sh..."
    local ct_result
    ct_result=$(curl -sS --max-time 30 \
        "https://crt.sh/?q=%25.${domain}&output=json" 2>/dev/null)
    if [[ -n "$ct_result" ]] && [[ "$ct_result" != "null" ]]; then
        echo "$ct_result" | jq -r '.[].name_value' 2>/dev/null | \
            tr ',' '\n' | sed 's/^\*\.//' | grep -F "$domain" >> "$tmpfile"
    fi

    # Fuente 2: HackerTarget
    log_msg "  [HT] Consultando HackerTarget..."
    local ht_result
    ht_result=$(curl -sS --max-time 15 \
        "https://api.hackertarget.com/hostsearch/?q=${domain}" 2>/dev/null)
    if [[ -n "$ht_result" ]] && ! echo "$ht_result" | grep -q "error"; then
        echo "$ht_result" | cut -d',' -f1 >> "$tmpfile"
    fi

    # Fuente 3: Zone transfer attempt
    log_msg "  [AXFR] Intentando zone transfer..."
    for ns in $(dig +short NS "$domain" 2>/dev/null); do
        dig @"$ns" "$domain" AXFR +short 2>/dev/null | \
            grep -oP "[a-zA-Z0-9._-]+\.${domain}" >> "$tmpfile" 2>/dev/null
    done

    # Fuente 4: Common subdomains bruteforce
    log_msg "  [BRUTE] Probando subdominios comunes..."
    for sub in $COMMON_SUBS; do
        local fqdn="${sub}.${domain}"
        if dig +short A "$fqdn" 2>/dev/null | grep -qP '\d+\.\d+\.\d+\.\d+'; then
            echo "$fqdn" >> "$tmpfile"
        fi
    done

    # Consolidar y dedup
    sort -u "$tmpfile" | grep -F "$domain" > "$outfile"
    rm -f "$tmpfile"

    local total
    total=$(wc -l < "$outfile" 2>/dev/null || echo 0)
    log_msg "Total subdominios descubiertos: $total"

    # Delta check
    local previous
    previous=$(ls -t "$SUB_DIR"/${domain}-*.txt 2>/dev/null | grep -v "$(date +%Y%m%d)" | head -1)
    if [[ -n "$previous" ]] && [[ -f "$previous" ]]; then
        local new_subs
        new_subs=$(comm -13 "$previous" "$outfile" | wc -l)
        if [[ $new_subs -gt 0 ]]; then
            log_msg "ALERTA: $new_subs subdominios nuevos detectados:"
            comm -13 "$previous" "$outfile" | while read -r sub; do
                log_msg "  NUEVO: $sub"
            done
        fi
    fi

    cat "$outfile"
}

case "${1:-help}" in
    discover) shift; discover "$@" ;;
    *)        echo "Uso: $0 {discover <domain>}" ;;
esac
EOFSUB
    chmod +x "$OSINT_BIN/securizar-subdomain-discover.sh"
    log_change "Creado" "$OSINT_BIN/securizar-subdomain-discover.sh"

else
    log_skip "Descubrimiento de subdominios"
fi

# ============================================================
# S5: DESCUBRIMIENTO CLOUD
# ============================================================
log_section "S5: Descubrimiento cloud"

log_info "Probing S3/Azure/GCS, deteccion buckets publicos."
log_info "  - Dangling CNAMEs (subdomain takeover)"
log_info ""

if check_executable /usr/local/bin/securizar-cloud-discover.sh; then
    log_already "Cloud discover (securizar-cloud-discover.sh existe)"
elif ask "Crear herramienta de descubrimiento cloud?"; then

    cat > "$OSINT_BIN/securizar-cloud-discover.sh" << 'EOFCLOUD'
#!/bin/bash
# ============================================================
# securizar-cloud-discover.sh - Descubrimiento cloud
# ============================================================
set -euo pipefail

CLOUD_DIR="/var/lib/securizar/osint/cloud"
CLOUD_LOG="/var/log/securizar/osint/cloud.log"

mkdir -p "$CLOUD_DIR" 2>/dev/null

log_msg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$CLOUD_LOG"; }

CLOUD_PATTERNS=(
    "s3.amazonaws.com"
    "blob.core.windows.net"
    "storage.googleapis.com"
    "cloudfront.net"
    "azurewebsites.net"
    "herokuapp.com"
    "github.io"
    "pages.dev"
)

check_buckets() {
    local org_name="$1"
    [[ -z "$org_name" ]] && { echo "Uso: $0 buckets <org-name>"; return 1; }

    log_msg "Verificando buckets cloud para $org_name..."
    local outfile="$CLOUD_DIR/${org_name}-buckets-$(date +%Y%m%d).txt"
    local found=0

    local variations=("$org_name" "${org_name}-backup" "${org_name}-dev" "${org_name}-staging"
        "${org_name}-prod" "${org_name}-data" "${org_name}-logs" "${org_name}-assets"
        "${org_name}-static" "${org_name}-media")

    for bucket in "${variations[@]}"; do
        # S3
        local status
        status=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 5 \
            "https://${bucket}.s3.amazonaws.com/" 2>/dev/null || echo "000")
        if [[ "$status" != "404" ]] && [[ "$status" != "000" ]]; then
            found=$((found + 1))
            echo "S3: ${bucket} (HTTP $status)" | tee -a "$outfile"
            log_msg "ENCONTRADO: S3 bucket ${bucket} (HTTP $status)"
        fi

        # GCS
        status=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 5 \
            "https://storage.googleapis.com/${bucket}/" 2>/dev/null || echo "000")
        if [[ "$status" != "404" ]] && [[ "$status" != "000" ]]; then
            found=$((found + 1))
            echo "GCS: ${bucket} (HTTP $status)" | tee -a "$outfile"
            log_msg "ENCONTRADO: GCS bucket ${bucket} (HTTP $status)"
        fi
    done

    log_msg "Verificacion completada: $found buckets encontrados"
}

check_dangling_cnames() {
    local domain="$1"
    [[ -z "$domain" ]] && { echo "Uso: $0 dangling <domain>"; return 1; }

    local subdomain_file="/var/lib/securizar/osint/subdomains/${domain}-$(date +%Y%m%d).txt"
    [[ ! -f "$subdomain_file" ]] && {
        log_msg "Sin lista de subdominios, ejecute securizar-subdomain-discover.sh primero"
        return 1
    }

    log_msg "Verificando dangling CNAMEs para $domain..."
    local dangling=0

    while IFS= read -r sub; do
        [[ -z "$sub" ]] && continue
        local cname
        cname=$(dig +short CNAME "$sub" 2>/dev/null | head -1)
        [[ -z "$cname" ]] && continue

        # Verificar si el CNAME apunta a servicio cloud que no responde
        for pattern in "${CLOUD_PATTERNS[@]}"; do
            if echo "$cname" | grep -qF "$pattern"; then
                local status
                status=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 5 \
                    "https://${sub}/" 2>/dev/null || echo "000")
                if [[ "$status" == "404" ]] || [[ "$status" == "000" ]]; then
                    dangling=$((dangling + 1))
                    log_msg "TAKEOVER POSIBLE: $sub -> $cname (HTTP $status)"
                fi
                break
            fi
        done
    done < "$subdomain_file"

    log_msg "Verificacion dangling CNAMEs: $dangling posibles takeover"
}

case "${1:-help}" in
    buckets)  shift; check_buckets "$@" ;;
    dangling) shift; check_dangling_cnames "$@" ;;
    *)        echo "Uso: $0 {buckets <org-name>|dangling <domain>}" ;;
esac
EOFCLOUD
    chmod +x "$OSINT_BIN/securizar-cloud-discover.sh"
    log_change "Creado" "$OSINT_BIN/securizar-cloud-discover.sh"

else
    log_skip "Descubrimiento cloud"
fi

# ============================================================
# S6: FINGERPRINTING TECNOLOGICO
# ============================================================
log_section "S6: Fingerprinting tecnologico"

log_info "Headers HTTP, TLS versions, probing /robots.txt."
log_info "  - Cross-referencia con CVEs conocidos"
log_info ""

if check_executable /usr/local/bin/securizar-tech-fingerprint.sh; then
    log_already "Tech fingerprint (securizar-tech-fingerprint.sh existe)"
elif ask "Crear herramienta de fingerprinting tecnologico?"; then

    cat > "$OSINT_BIN/securizar-tech-fingerprint.sh" << 'EOFTECH'
#!/bin/bash
# ============================================================
# securizar-tech-fingerprint.sh - Fingerprinting tecnologico
# ============================================================
set -euo pipefail

TECH_DIR="/var/lib/securizar/osint/techstack"
TECH_LOG="/var/log/securizar/osint/techstack.log"

mkdir -p "$TECH_DIR" 2>/dev/null

log_msg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$TECH_LOG"; }

fingerprint() {
    local target="$1"
    [[ -z "$target" ]] && { echo "Uso: $0 scan <host>"; return 1; }

    log_msg "Fingerprinting tecnologico: $target"
    local outfile="$TECH_DIR/${target}-$(date +%Y%m%d).json"
    local result="{\"target\":\"$target\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"

    # HTTP headers
    local headers
    headers=$(curl -sS -I --max-time 10 "https://${target}/" 2>/dev/null)
    if [[ -n "$headers" ]]; then
        local server x_powered powered_by
        server=$(echo "$headers" | grep -i "^server:" | head -1 | sed 's/[Ss]erver: *//' | tr -d '\r')
        x_powered=$(echo "$headers" | grep -i "^x-powered-by:" | head -1 | sed 's/[Xx]-[Pp]owered-[Bb]y: *//' | tr -d '\r')
        result=$(echo "$result" | jq --arg s "$server" --arg xp "$x_powered" \
            '. + {server: $s, x_powered_by: $xp}')
    fi

    # TLS version
    local tls_info
    tls_info=$(echo | timeout 5 openssl s_client -connect "${target}:443" 2>/dev/null | \
        grep "Protocol" | head -1 | awk '{print $NF}')
    [[ -n "$tls_info" ]] && result=$(echo "$result" | jq --arg tls "$tls_info" '. + {tls_version: $tls}')

    # Robots.txt
    local robots
    robots=$(curl -sS --max-time 5 "https://${target}/robots.txt" 2>/dev/null | head -20)
    if [[ -n "$robots" ]] && ! echo "$robots" | grep -qiE "404|not found"; then
        local disallow_count
        disallow_count=$(echo "$robots" | grep -ci "disallow" || echo 0)
        result=$(echo "$result" | jq --arg dc "$disallow_count" '. + {robots_disallow_count: ($dc|tonumber)}')
    fi

    # Security headers check
    local security_headers=0
    for hdr in "strict-transport-security" "content-security-policy" "x-content-type-options" \
        "x-frame-options" "x-xss-protection"; do
        if echo "$headers" | grep -qi "^${hdr}:"; then
            security_headers=$((security_headers + 1))
        fi
    done
    result=$(echo "$result" | jq --arg sh "$security_headers" '. + {security_headers_count: ($sh|tonumber)}')

    echo "$result" | jq '.' > "$outfile"
    log_msg "Fingerprint guardado: $outfile"
    jq '.' "$outfile"
}

case "${1:-help}" in
    scan) shift; fingerprint "$@" ;;
    *)    echo "Uso: $0 {scan <host>}" ;;
esac
EOFTECH
    chmod +x "$OSINT_BIN/securizar-tech-fingerprint.sh"
    log_change "Creado" "$OSINT_BIN/securizar-tech-fingerprint.sh"

else
    log_skip "Fingerprinting tecnologico"
fi

# ============================================================
# S7: DETECCION DE FUGAS DE CODIGO
# ============================================================
log_section "S7: Deteccion de fugas de codigo"

log_info "GitHub dorks, Pastebin, HIBP API, alertas de fugas."
log_info "  - Rate-limited para respetar limites de API"
log_info ""

if check_executable /usr/local/bin/securizar-code-leak-detect.sh; then
    log_already "Code leak detect (securizar-code-leak-detect.sh existe)"
elif ask "Crear detector de fugas de codigo?"; then

    cat > "$OSINT_BIN/securizar-code-leak-detect.sh" << 'EOFLEAK'
#!/bin/bash
# ============================================================
# securizar-code-leak-detect.sh - Deteccion de fugas de codigo
# ============================================================
set -euo pipefail

LEAK_DIR="/var/lib/securizar/osint/leaks"
LEAK_LOG="/var/log/securizar/osint/leaks.log"

mkdir -p "$LEAK_DIR" 2>/dev/null

log_msg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LEAK_LOG"; }

github_dork() {
    local org_name="$1"
    [[ -z "$org_name" ]] && { echo "Uso: $0 github <org>"; return 1; }

    log_msg "Buscando fugas en GitHub para $org_name..."
    local outfile="$LEAK_DIR/${org_name}-github-$(date +%Y%m%d).txt"

    # Dorks comunes (sin autenticacion, limitado)
    local dorks=(
        "\"$org_name\" password"
        "\"$org_name\" secret"
        "\"$org_name\" api_key"
        "\"$org_name\" token"
        "\"$org_name\" private_key"
    )

    for dork in "${dorks[@]}"; do
        local encoded
        encoded=$(echo "$dork" | jq -sRr @uri)
        local result
        result=$(curl -sS --max-time 15 -H "Accept: application/vnd.github.v3+json" \
            "https://api.github.com/search/code?q=${encoded}" 2>/dev/null)

        local total
        total=$(echo "$result" | jq '.total_count // 0' 2>/dev/null)
        if [[ ${total:-0} -gt 0 ]]; then
            log_msg "ALERTA: GitHub dork '$dork' -> $total resultados"
            echo "Dork: $dork -> $total resultados" >> "$outfile"
        fi

        # Rate limiting
        sleep 3
    done

    log_msg "Busqueda GitHub completada"
}

check_hibp() {
    local email_domain="$1"
    [[ -z "$email_domain" ]] && { echo "Uso: $0 hibp <email-domain>"; return 1; }

    log_msg "Consultando HIBP para dominio $email_domain..."

    local result
    result=$(curl -sS --max-time 15 \
        -H "User-Agent: Securizar-OSINT/1.0" \
        "https://haveibeenpwned.com/api/v3/breaches" 2>/dev/null)

    if [[ -n "$result" ]]; then
        local relevant
        relevant=$(echo "$result" | jq -r ".[] | select(.Domain == \"$email_domain\") | .Name" 2>/dev/null)
        if [[ -n "$relevant" ]]; then
            log_msg "ALERTA: Dominio $email_domain aparece en breaches: $relevant"
        else
            log_msg "Dominio $email_domain no encontrado directamente en HIBP breaches"
        fi
    fi
}

scan_pastebin() {
    local keyword="$1"
    [[ -z "$keyword" ]] && { echo "Uso: $0 paste <keyword>"; return 1; }

    log_msg "Buscando '$keyword' en pastes publicos..."
    # Nota: Pastebin limita severamente el scraping
    # Usamos Google dork como alternativa
    local result
    result=$(curl -sS --max-time 15 \
        "https://www.google.com/search?q=site:pastebin.com+%22${keyword}%22&num=5" 2>/dev/null)

    local matches
    matches=$(echo "$result" | grep -co "pastebin.com" || echo 0)
    log_msg "Referencias encontradas en Pastebin via Google: $matches"
}

case "${1:-help}" in
    github) shift; github_dork "$@" ;;
    hibp)   shift; check_hibp "$@" ;;
    paste)  shift; scan_pastebin "$@" ;;
    *)      echo "Uso: $0 {github <org>|hibp <email-domain>|paste <keyword>}" ;;
esac
EOFLEAK
    chmod +x "$OSINT_BIN/securizar-code-leak-detect.sh"
    log_change "Creado" "$OSINT_BIN/securizar-code-leak-detect.sh"

else
    log_skip "Deteccion de fugas de codigo"
fi

# ============================================================
# S8: SUPERFICIE DE INGENIERIA SOCIAL
# ============================================================
log_section "S8: Superficie de ingenieria social"

log_info "Email harvesting check, metadata docs, SPF/DMARC/DKIM."
log_info "  - Verificacion de controles anti-phishing"
log_info ""

if check_executable /usr/local/bin/securizar-se-surface.sh; then
    log_already "SE surface (securizar-se-surface.sh existe)"
elif ask "Crear herramienta de superficie de ingenieria social?"; then

    cat > "$OSINT_BIN/securizar-se-surface.sh" << 'EOFSE'
#!/bin/bash
# ============================================================
# securizar-se-surface.sh - Superficie de ingenieria social
# ============================================================
set -euo pipefail

SE_DIR="/var/lib/securizar/osint/soceng"
SE_LOG="/var/log/securizar/osint/soceng.log"

mkdir -p "$SE_DIR" 2>/dev/null

log_msg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$SE_LOG"; }

check_email_security() {
    local domain="$1"
    [[ -z "$domain" ]] && { echo "Uso: $0 email <domain>"; return 1; }

    log_msg "Verificando seguridad email para $domain..."
    local outfile="$SE_DIR/${domain}-email-$(date +%Y%m%d).json"
    local result="{\"domain\":\"$domain\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
    local score=0
    local max=5

    # SPF
    local spf
    spf=$(dig +short TXT "$domain" 2>/dev/null | grep "v=spf" | head -1)
    if [[ -n "$spf" ]]; then
        score=$((score + 1))
        result=$(echo "$result" | jq --arg s "$spf" '. + {spf: $s, spf_present: true}')
        log_msg "  SPF: PRESENTE - $spf"

        # Verificar -all vs ~all
        if echo "$spf" | grep -q "\-all"; then
            score=$((score + 1))
            log_msg "  SPF: Hard fail (-all) configurado"
        else
            log_msg "  SPF: WARN - No usa hard fail (-all)"
        fi
    else
        result=$(echo "$result" | jq '. + {spf_present: false}')
        log_msg "  SPF: AUSENTE"
    fi

    # DMARC
    local dmarc
    dmarc=$(dig +short TXT "_dmarc.${domain}" 2>/dev/null | grep "v=DMARC" | head -1)
    if [[ -n "$dmarc" ]]; then
        score=$((score + 1))
        result=$(echo "$result" | jq --arg d "$dmarc" '. + {dmarc: $d, dmarc_present: true}')
        log_msg "  DMARC: PRESENTE - $dmarc"
    else
        result=$(echo "$result" | jq '. + {dmarc_present: false}')
        log_msg "  DMARC: AUSENTE"
    fi

    # DKIM (verificar selector comun)
    local dkim_found=false
    for selector in default google dkim mail s1 s2 selector1 selector2; do
        local dkim
        dkim=$(dig +short TXT "${selector}._domainkey.${domain}" 2>/dev/null | grep "v=DKIM" | head -1)
        if [[ -n "$dkim" ]]; then
            score=$((score + 1))
            dkim_found=true
            result=$(echo "$result" | jq --arg sel "$selector" '. + {dkim_selector: $sel, dkim_present: true}')
            log_msg "  DKIM: PRESENTE (selector=$selector)"
            break
        fi
    done
    if [[ "$dkim_found" == "false" ]]; then
        result=$(echo "$result" | jq '. + {dkim_present: false}')
        log_msg "  DKIM: No encontrado (selectores comunes)"
    fi

    # MTA-STS
    local mta_sts
    mta_sts=$(dig +short TXT "_mta-sts.${domain}" 2>/dev/null | head -1)
    if [[ -n "$mta_sts" ]]; then
        score=$((score + 1))
        log_msg "  MTA-STS: PRESENTE"
    else
        log_msg "  MTA-STS: AUSENTE"
    fi

    result=$(echo "$result" | jq --arg s "$score" --arg m "$max" '. + {score: ($s|tonumber), max: ($m|tonumber)}')
    echo "$result" | jq '.' > "$outfile"
    log_msg "Score email security: $score/$max"
}

check_metadata() {
    local url="$1"
    [[ -z "$url" ]] && { echo "Uso: $0 metadata <url-or-file>"; return 1; }

    if ! command -v exiftool &>/dev/null; then
        log_msg "WARN: exiftool no disponible para analisis de metadata"
        return 1
    fi

    if [[ -f "$url" ]]; then
        log_msg "Analizando metadata de archivo local: $url"
        exiftool "$url" 2>/dev/null | grep -iE "author|creator|producer|company|email"
    else
        log_msg "Descargando y analizando metadata: $url"
        local tmpfile="/tmp/meta-analysis-$$"
        curl -sS --max-time 15 -o "$tmpfile" "$url" 2>/dev/null
        if [[ -f "$tmpfile" ]]; then
            exiftool "$tmpfile" 2>/dev/null | grep -iE "author|creator|producer|company|email"
            rm -f "$tmpfile"
        fi
    fi
}

case "${1:-help}" in
    email)    shift; check_email_security "$@" ;;
    metadata) shift; check_metadata "$@" ;;
    *)        echo "Uso: $0 {email <domain>|metadata <url-or-file>}" ;;
esac
EOFSE
    chmod +x "$OSINT_BIN/securizar-se-surface.sh"
    log_change "Creado" "$OSINT_BIN/securizar-se-surface.sh"

else
    log_skip "Superficie de ingenieria social"
fi

# ============================================================
# S9: RIESGO DE TERCEROS (VENDORS)
# ============================================================
log_section "S9: Riesgo de terceros (vendors)"

log_info "Inventario vendors, DNS/TLS/headers check, risk score."
log_info "  - Evaluacion automatizada de postura de seguridad"
log_info ""

if check_executable /usr/local/bin/securizar-vendor-risk.sh; then
    log_already "Vendor risk (securizar-vendor-risk.sh existe)"
elif ask "Crear herramienta de riesgo de terceros?"; then

    # Configuracion
    cat > "$OSINT_DIR/third-party-risk.conf" << 'EOFVRCONF'
# third-party-risk.conf - Inventario de vendors/terceros
# Formato: nombre|dominio|criticidad(1-5)|categoria
# Ejemplo:
# cloudprovider|cloud.example.com|5|infraestructura
# emailservice|mail.example.com|4|comunicaciones
EOFVRCONF
    log_change "Creado" "$OSINT_DIR/third-party-risk.conf"

    cat > "$OSINT_BIN/securizar-vendor-risk.sh" << 'EOFVENDOR'
#!/bin/bash
# ============================================================
# securizar-vendor-risk.sh - Evaluacion de riesgo de terceros
# ============================================================
set -euo pipefail

VENDOR_DIR="/var/lib/securizar/osint/vendors"
VENDOR_LOG="/var/log/securizar/osint/vendors.log"
VENDOR_CONF="/etc/securizar/osint/third-party-risk.conf"

mkdir -p "$VENDOR_DIR" 2>/dev/null

log_msg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$VENDOR_LOG"; }

assess_vendor() {
    local vendor_name="$1"
    local vendor_domain="$2"
    local criticality="${3:-3}"

    [[ -z "$vendor_domain" ]] && { echo "Uso: $0 assess <name> <domain> [criticality]"; return 1; }

    log_msg "Evaluando vendor: $vendor_name ($vendor_domain, criticidad=$criticality)"
    local score=0
    local max=10

    # 1. DNS responde
    if dig +short A "$vendor_domain" 2>/dev/null | grep -qP '\d+\.\d+\.\d+\.\d+'; then
        score=$((score + 1))
    fi

    # 2. HTTPS disponible
    local http_status
    http_status=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 \
        "https://${vendor_domain}/" 2>/dev/null || echo "000")
    [[ "$http_status" =~ ^(200|301|302)$ ]] && score=$((score + 1))

    # 3. TLS valido
    local tls_valid=false
    if echo | timeout 5 openssl s_client -connect "${vendor_domain}:443" -verify_return_error 2>/dev/null | \
        grep -q "Verify return code: 0"; then
        score=$((score + 2))
        tls_valid=true
    fi

    # 4. Security headers
    local headers
    headers=$(curl -sS -I --max-time 10 "https://${vendor_domain}/" 2>/dev/null)
    for hdr in "strict-transport-security" "content-security-policy" "x-content-type-options"; do
        if echo "$headers" | grep -qi "^${hdr}:"; then
            score=$((score + 1))
        fi
    done

    # 5. SPF presente
    local spf
    spf=$(dig +short TXT "$vendor_domain" 2>/dev/null | grep "v=spf")
    [[ -n "$spf" ]] && score=$((score + 1))

    # 6. DMARC presente
    local dmarc
    dmarc=$(dig +short TXT "_dmarc.${vendor_domain}" 2>/dev/null | grep "v=DMARC")
    [[ -n "$dmarc" ]] && score=$((score + 1))

    local pct=0
    [[ $max -gt 0 ]] && pct=$((score * 100 / max))

    # Risk score compuesto (inverso: menor = mas riesgo)
    local risk_score=$((100 - pct))
    # Ponderar por criticidad
    local weighted_risk=$(( risk_score * criticality / 5 ))

    local outfile="$VENDOR_DIR/${vendor_name}-$(date +%Y%m%d).json"
    jq -n --arg name "$vendor_name" --arg dom "$vendor_domain" \
        --arg score "$score" --arg max "$max" --arg risk "$weighted_risk" \
        --arg crit "$criticality" --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{vendor:$name, domain:$dom, security_score:($score|tonumber),
          max_score:($max|tonumber), criticality:($crit|tonumber),
          weighted_risk:($risk|tonumber), assessed:$ts}' > "$outfile"

    log_msg "Vendor $vendor_name: security=$score/$max risk_weighted=$weighted_risk"
}

assess_all() {
    [[ ! -f "$VENDOR_CONF" ]] && { log_msg "Sin inventario de vendors"; return 1; }

    log_msg "Evaluando todos los vendors..."
    while IFS='|' read -r name domain crit category; do
        [[ -z "$name" || "$name" =~ ^# ]] && continue
        assess_vendor "$name" "$domain" "$crit"
        sleep 2  # Rate limiting
    done < "$VENDOR_CONF"
}

report() {
    echo "Reporte de riesgo de terceros:"
    echo "=============================="
    for f in "$VENDOR_DIR"/*-$(date +%Y%m%d).json; do
        [[ ! -f "$f" ]] && continue
        jq -r '"  \(.vendor): security=\(.security_score)/\(.max_score) risk_weighted=\(.weighted_risk) crit=\(.criticality)"' "$f" 2>/dev/null
    done | sort -t= -k3 -rn
}

case "${1:-help}" in
    assess)     shift; assess_vendor "$@" ;;
    assess-all) assess_all ;;
    report)     report ;;
    *)          echo "Uso: $0 {assess <name> <domain> [crit]|assess-all|report}" ;;
esac
EOFVENDOR
    chmod +x "$OSINT_BIN/securizar-vendor-risk.sh"
    log_change "Creado" "$OSINT_BIN/securizar-vendor-risk.sh"

else
    log_skip "Riesgo de terceros (vendors)"
fi

# ============================================================
# S10: AUDITORIA INTEGRAL OSINT
# ============================================================
log_section "S10: Auditoria integral OSINT"

log_info "Auditoria: herramientas + configs + frescura + completitud."
log_info ""

if check_executable /usr/local/bin/auditoria-osint-completa.sh; then
    log_already "Auditoria integral (auditoria-osint-completa.sh existe)"
elif ask "Crear herramienta de auditoria integral OSINT?"; then

    cat > "$OSINT_BIN/auditoria-osint-completa.sh" << 'EOFAUDIT'
#!/bin/bash
# ============================================================
# auditoria-osint-completa.sh - Auditoria integral OSINT
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
echo -e "${BOLD}  AUDITORIA: OSINT Y SUPERFICIE DE ATAQUE (Modulo 78)${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════════${NC}"
echo ""

# S1: CT Monitor
check "CT monitor instalado" "test -x /usr/local/bin/securizar-ct-monitor.sh"
check "Datos CT presentes" "ls /var/lib/securizar/osint/ct-logs/*.json"

# S2: pDNS enum
check "pDNS enum instalado" "test -x /usr/local/bin/securizar-pdns-enum.sh"

# S3: WHOIS monitor
check "WHOIS monitor instalado" "test -x /usr/local/bin/securizar-whois-monitor.sh"

# S4: Subdomain discovery
check "Subdomain discover instalado" "test -x /usr/local/bin/securizar-subdomain-discover.sh"
check "Datos subdominios presentes" "ls /var/lib/securizar/osint/subdomains/*.txt"

# S5: Cloud discovery
check "Cloud discover instalado" "test -x /usr/local/bin/securizar-cloud-discover.sh"

# S6: Tech fingerprint
check "Tech fingerprint instalado" "test -x /usr/local/bin/securizar-tech-fingerprint.sh"

# S7: Code leak detection
check "Code leak detect instalado" "test -x /usr/local/bin/securizar-code-leak-detect.sh"

# S8: SE surface
check "SE surface instalado" "test -x /usr/local/bin/securizar-se-surface.sh"

# S9: Vendor risk
check "Vendor risk instalado" "test -x /usr/local/bin/securizar-vendor-risk.sh"
check "Config vendor risk" "test -f /etc/securizar/osint/third-party-risk.conf"

# Dependencias
check "curl disponible" "command -v curl"
check "jq disponible" "command -v jq"
check "dig disponible" "command -v dig"
check "openssl disponible" "command -v openssl"
check "whois disponible" "command -v whois"

echo ""
echo -e "${BOLD}────────────────────────────────────────────────────────${NC}"
local pct=0
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

logger -t securizar-osint "Auditoria completada: $SCORE/$MAX ($pct%)"
EOFAUDIT
    chmod +x "$OSINT_BIN/auditoria-osint-completa.sh"
    log_change "Creado" "$OSINT_BIN/auditoria-osint-completa.sh"

    # Cron semanal
    cat > /etc/cron.weekly/auditoria-osint << 'EOFCRON'
#!/bin/bash
/usr/local/bin/auditoria-osint-completa.sh > /dev/null 2>&1
EOFCRON
    chmod 700 /etc/cron.weekly/auditoria-osint
    log_change "Creado" "/etc/cron.weekly/auditoria-osint"

else
    log_skip "Auditoria integral OSINT"
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
show_changes_summary
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   OSINT Y SUPERFICIE DE ATAQUE (MODULO 78) COMPLETADO   ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups guardados en: $BACKUP_DIR"
echo ""
echo "Comandos disponibles:"
echo "  - CT monitor:     securizar-ct-monitor.sh {monitor|list} <domain>"
echo "  - pDNS enum:      securizar-pdns-enum.sh {enum} <domain>"
echo "  - WHOIS monitor:  securizar-whois-monitor.sh {snapshot|check} <domain>"
echo "  - Subdominios:    securizar-subdomain-discover.sh {discover} <domain>"
echo "  - Cloud discover: securizar-cloud-discover.sh {buckets|dangling}"
echo "  - Tech fingerpr:  securizar-tech-fingerprint.sh {scan} <host>"
echo "  - Code leaks:     securizar-code-leak-detect.sh {github|hibp|paste}"
echo "  - SE surface:     securizar-se-surface.sh {email|metadata}"
echo "  - Vendor risk:    securizar-vendor-risk.sh {assess|assess-all|report}"
echo "  - Auditoria:      auditoria-osint-completa.sh"
