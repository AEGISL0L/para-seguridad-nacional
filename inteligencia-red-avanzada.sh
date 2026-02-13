#!/bin/bash
# ============================================================
# inteligencia-red-avanzada.sh - Modulo 76: Inteligencia de Red
# ============================================================
# Inteligencia de trafico de red: deteccion de C2, exfiltracion
# y anomalias mediante analisis pasivo y activo.
# Secciones:
#   S1  - JA3/JA4 TLS fingerprinting
#   S2  - Deteccion de beaconing C2
#   S3  - Passive DNS collector
#   S4  - Deteccion de anomalias de protocolo
#   S5  - Encrypted Traffic Analysis (ETA)
#   S6  - Monitor de rutas BGP
#   S7  - Colector NetFlow/ss sampling
#   S8  - Deteccion de exfiltracion
#   S9  - Forense de red (pcap + cadena custodia)
#   S10 - Auditoria integral inteligencia de red
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "netint"
securizar_setup_traps

# ── Pre-check: detectar secciones ya aplicadas ──────────────
_precheck 10
_pc 'check_executable /usr/local/bin/securizar-ja3-fingerprint.sh'
_pc 'check_executable /usr/local/bin/securizar-beacon-detect.sh'
_pc 'check_executable /usr/local/bin/securizar-pdns-collector.sh'
_pc 'check_executable /usr/local/bin/securizar-proto-anomaly.sh'
_pc 'check_executable /usr/local/bin/securizar-eta-analyzer.sh'
_pc 'check_executable /usr/local/bin/securizar-route-monitor.sh'
_pc 'check_executable /usr/local/bin/securizar-netflow-collector.sh'
_pc 'check_executable /usr/local/bin/securizar-exfil-detect.sh'
_pc 'check_executable /usr/local/bin/securizar-netforensics.sh'
_pc 'check_executable /usr/local/bin/auditoria-netint-completa.sh'
_precheck_result

log_section "MODULO 76: INTELIGENCIA DE RED AVANZADA"
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

NETINT_DIR="/etc/securizar/netint"
NETINT_BIN="/usr/local/bin"
NETINT_LOG="/var/log/securizar/netint"
NETINT_DATA="/var/lib/securizar/netint"
mkdir -p "$NETINT_DIR" "$NETINT_LOG" "$NETINT_DATA"/{ja3db,pdns,flows,pcaps,baselines} || true

# Verificar dependencias
log_info "Verificando dependencias..."
for dep in jq curl ss; do
    if command -v "$dep" &>/dev/null; then
        log_info "  OK  $dep disponible"
    else
        log_info "  --  $dep no encontrado (requerido)"
    fi
done
for dep in tshark tcpdump conntrack softflowd sqlite3; do
    if command -v "$dep" &>/dev/null; then
        log_info "  OK  $dep disponible"
    else
        log_info "  --  $dep no encontrado (opcional)"
    fi
done
echo ""

# ============================================================
# S1: JA3/JA4 TLS FINGERPRINTING
# ============================================================
log_section "S1: JA3/JA4 TLS fingerprinting"

log_info "Captura fingerprints JA3/JA4 de handshakes TLS via tshark."
log_info "  - Compara contra BD de abuse.ch (JA3 Fingerprint List)"
log_info "  - Genera alertas para fingerprints conocidos de malware"
log_info ""

if check_executable /usr/local/bin/securizar-ja3-fingerprint.sh; then
    log_already "JA3 fingerprinting (securizar-ja3-fingerprint.sh existe)"
elif ask "Crear herramienta de JA3/JA4 fingerprinting?"; then

    cat > "$NETINT_BIN/securizar-ja3-fingerprint.sh" << 'EOFJA3'
#!/bin/bash
# ============================================================
# securizar-ja3-fingerprint.sh - JA3/JA4 TLS fingerprinting
# ============================================================
set -euo pipefail

JA3_DB="/var/lib/securizar/netint/ja3db"
JA3_LOG="/var/log/securizar/netint/ja3.log"
JA3_MALWARE_LIST="$JA3_DB/ja3-malware.csv"
CAPTURE_IFACE="${1:-any}"
CAPTURE_DURATION="${2:-60}"

mkdir -p "$JA3_DB" 2>/dev/null

log_msg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$JA3_LOG"; }

update_ja3_db() {
    log_msg "Actualizando BD JA3 desde abuse.ch..."
    local tmp="/tmp/ja3-feed-$$.csv"
    if curl -sS --max-time 30 -o "$tmp" \
        "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv" 2>/dev/null; then
        local count
        count=$(grep -cv '^#' "$tmp" 2>/dev/null || echo 0)
        if [[ $count -gt 0 ]]; then
            mv "$tmp" "$JA3_MALWARE_LIST"
            log_msg "BD actualizada: $count fingerprints maliciosos"
        else
            rm -f "$tmp"
            log_msg "WARN: descarga vacia, manteniendo BD anterior"
        fi
    else
        rm -f "$tmp"
        log_msg "ERROR: no se pudo descargar feed JA3"
    fi
}

capture_ja3() {
    if ! command -v tshark &>/dev/null; then
        log_msg "ERROR: tshark no disponible, instale wireshark-cli"
        return 1
    fi

    log_msg "Capturando JA3 en $CAPTURE_IFACE durante ${CAPTURE_DURATION}s..."
    local outfile="$JA3_DB/capture-$(date +%Y%m%d-%H%M%S).jsonl"

    timeout "$CAPTURE_DURATION" tshark -i "$CAPTURE_IFACE" -Y "tls.handshake.type==1" \
        -T fields -e ip.src -e ip.dst -e tcp.dstport \
        -e tls.handshake.ja3 -e tls.handshake.ja3_full \
        -e tls.handshake.extensions_server_name \
        -E separator='|' 2>/dev/null | while IFS='|' read -r src dst port ja3 ja3_full sni; do
        [[ -z "$ja3" ]] && continue
        printf '{"ts":"%s","src":"%s","dst":"%s","port":"%s","ja3":"%s","sni":"%s"}\n' \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$src" "$dst" "$port" "$ja3" "$sni" >> "$outfile"
    done

    [[ -f "$outfile" ]] && log_msg "Capturados $(wc -l < "$outfile") fingerprints en $outfile"
}

check_malicious() {
    [[ ! -f "$JA3_MALWARE_LIST" ]] && { log_msg "Sin BD malware, ejecute: $0 update"; return 1; }

    local latest
    latest=$(ls -t "$JA3_DB"/capture-*.jsonl 2>/dev/null | head -1)
    [[ -z "$latest" ]] && { log_msg "Sin capturas, ejecute: $0 capture"; return 1; }

    local hits=0
    while IFS= read -r line; do
        local ja3
        ja3=$(echo "$line" | grep -oP '"ja3":"[^"]*"' | cut -d'"' -f4)
        [[ -z "$ja3" ]] && continue
        if grep -qF "$ja3" "$JA3_MALWARE_LIST" 2>/dev/null; then
            hits=$((hits + 1))
            log_msg "ALERTA: JA3 malicioso detectado: $ja3 - $line"
        fi
    done < "$latest"

    log_msg "Analisis completado: $hits coincidencias maliciosas"
}

case "${1:-help}" in
    update)  update_ja3_db ;;
    capture) shift; capture_ja3 "$@" ;;
    check)   check_malicious ;;
    *)       echo "Uso: $0 {update|capture [iface] [secs]|check}" ;;
esac
EOFJA3
    chmod +x "$NETINT_BIN/securizar-ja3-fingerprint.sh"
    log_change "Creado" "$NETINT_BIN/securizar-ja3-fingerprint.sh"

    # Cron diario para actualizar BD
    cat > /etc/cron.daily/securizar-ja3-update << 'EOFCRON'
#!/bin/bash
/usr/local/bin/securizar-ja3-fingerprint.sh update > /dev/null 2>&1
EOFCRON
    chmod 700 /etc/cron.daily/securizar-ja3-update
    log_change "Creado" "/etc/cron.daily/securizar-ja3-update"

else
    log_skip "JA3/JA4 TLS fingerprinting"
fi

# ============================================================
# S2: DETECCION DE BEACONING C2
# ============================================================
log_section "S2: Deteccion de beaconing C2"

log_info "Muestrea conexiones con ss cada 5 minutos."
log_info "  - Analiza jitter ratio (< 0.15 indica beaconing)"
log_info "  - Cross-referencia con scoring de IPs (ciberint_score_ip)"
log_info ""

if check_executable /usr/local/bin/securizar-beacon-detect.sh; then
    log_already "Beacon detection (securizar-beacon-detect.sh existe)"
elif ask "Crear herramienta de deteccion de beaconing?"; then

    cat > "$NETINT_BIN/securizar-beacon-detect.sh" << 'EOFBEACON'
#!/bin/bash
# ============================================================
# securizar-beacon-detect.sh - Deteccion de beaconing C2
# ============================================================
set -euo pipefail

BEACON_DIR="/var/lib/securizar/netint/baselines"
BEACON_LOG="/var/log/securizar/netint/beacon.log"
SAMPLE_INTERVAL=300
MIN_SAMPLES=6
JITTER_THRESHOLD="0.15"

mkdir -p "$BEACON_DIR" 2>/dev/null

log_msg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$BEACON_LOG"; }

sample_connections() {
    local outfile="$BEACON_DIR/conn-samples-$(date +%Y%m%d).jsonl"
    local ts
    ts=$(date +%s)

    ss -tun state established 2>/dev/null | awk 'NR>1 {print $4, $5}' | while read -r local remote; do
        local rip rport
        rip=$(echo "$remote" | rev | cut -d: -f2- | rev)
        rport=$(echo "$remote" | rev | cut -d: -f1 | rev)
        [[ "$rip" =~ ^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.) ]] && continue
        printf '{"ts":%d,"remote_ip":"%s","remote_port":"%s","local":"%s"}\n' \
            "$ts" "$rip" "$rport" "$local" >> "$outfile"
    done

    log_msg "Muestreo completado, datos en $outfile"
}

analyze_beaconing() {
    local datafile="$BEACON_DIR/conn-samples-$(date +%Y%m%d).jsonl"
    [[ ! -f "$datafile" ]] && { log_msg "Sin datos de hoy, recopile muestras primero"; return 1; }

    log_msg "Analizando patrones de beaconing..."

    # Agrupar por IP remota y analizar intervalos
    local tmpdir="/tmp/beacon-analysis-$$"
    mkdir -p "$tmpdir"

    # Extraer IPs unicas con sus timestamps
    jq -r '[.ts, .remote_ip] | @tsv' "$datafile" 2>/dev/null | sort -k2,2 -k1,1n | \
    awk '{print >> "'"$tmpdir"'/"$2".times"}'

    local alerts=0
    for ipfile in "$tmpdir"/*.times 2>/dev/null; do
        [[ ! -f "$ipfile" ]] && continue
        local ip
        ip=$(basename "$ipfile" .times)
        local count
        count=$(wc -l < "$ipfile")
        [[ $count -lt $MIN_SAMPLES ]] && continue

        # Calcular intervalos y jitter
        local result
        result=$(awk '
        {times[NR]=$1}
        END {
            if (NR < 3) {print "SKIP"; exit}
            n=0; sum=0
            for (i=2; i<=NR; i++) {
                intervals[++n] = times[i] - times[i-1]
                sum += intervals[n]
            }
            mean = sum / n
            if (mean == 0) {print "SKIP"; exit}
            variance = 0
            for (i=1; i<=n; i++) variance += (intervals[i]-mean)^2
            stddev = sqrt(variance/n)
            jitter = stddev / mean
            printf "%.4f %.0f %d", jitter, mean, n
        }' "$ipfile")

        [[ "$result" == "SKIP" ]] && continue
        local jitter mean nint
        read -r jitter mean nint <<< "$result"

        if awk "BEGIN{exit !($jitter < $JITTER_THRESHOLD)}" 2>/dev/null; then
            alerts=$((alerts + 1))
            log_msg "ALERTA BEACONING: IP=$ip jitter=$jitter intervalo_medio=${mean}s muestras=$nint"
        fi
    done

    rm -rf "$tmpdir"
    log_msg "Analisis completado: $alerts alertas de beaconing"
}

daemon_mode() {
    log_msg "Iniciando daemon de muestreo (cada ${SAMPLE_INTERVAL}s)..."
    while true; do
        sample_connections
        sleep "$SAMPLE_INTERVAL"
    done
}

case "${1:-help}" in
    sample)  sample_connections ;;
    analyze) analyze_beaconing ;;
    daemon)  daemon_mode ;;
    *)       echo "Uso: $0 {sample|analyze|daemon}" ;;
esac
EOFBEACON
    chmod +x "$NETINT_BIN/securizar-beacon-detect.sh"
    log_change "Creado" "$NETINT_BIN/securizar-beacon-detect.sh"

else
    log_skip "Deteccion de beaconing C2"
fi

# ============================================================
# S3: PASSIVE DNS COLLECTOR
# ============================================================
log_section "S3: Passive DNS collector"

log_info "Captura DNS pasiva continua via tcpdump."
log_info "  - BD pDNS local con historial de resoluciones"
log_info "  - Deteccion de NXD floods, DGA y dominios de alta entropia"
log_info ""

if check_executable /usr/local/bin/securizar-pdns-collector.sh; then
    log_already "Passive DNS (securizar-pdns-collector.sh existe)"
elif ask "Crear colector de DNS pasiva?"; then

    cat > "$NETINT_BIN/securizar-pdns-collector.sh" << 'EOFPDNS'
#!/bin/bash
# ============================================================
# securizar-pdns-collector.sh - Passive DNS collector
# ============================================================
set -euo pipefail

PDNS_DIR="/var/lib/securizar/netint/pdns"
PDNS_LOG="/var/log/securizar/netint/pdns.log"
CAPTURE_IFACE="${2:-any}"
ENTROPY_THRESHOLD="3.8"
NXD_THRESHOLD=50

mkdir -p "$PDNS_DIR" 2>/dev/null

log_msg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$PDNS_LOG"; }

calc_entropy() {
    echo "$1" | awk '{
        n = length($0); if (n==0){print 0; exit}
        for(i=1;i<=n;i++) freq[substr($0,i,1)]++
        e=0; for(c in freq){p=freq[c]/n; if(p>0) e -= p*(log(p)/log(2))}
        printf "%.4f\n", e
    }'
}

capture_dns() {
    if ! command -v tcpdump &>/dev/null; then
        log_msg "ERROR: tcpdump no disponible"
        return 1
    fi

    local outfile="$PDNS_DIR/pdns-$(date +%Y%m%d).jsonl"
    log_msg "Capturando DNS en $CAPTURE_IFACE..."

    tcpdump -i "$CAPTURE_IFACE" -nn -l port 53 2>/dev/null | while IFS= read -r line; do
        local domain
        domain=$(echo "$line" | grep -oP '(A|AAAA|CNAME|MX|NS|TXT)\?\s+\K[^ ]+' | sed 's/\.$//')
        [[ -z "$domain" ]] && continue

        local ts
        ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
        local ip_answer=""
        if echo "$line" | grep -q ' A '; then
            ip_answer=$(echo "$line" | grep -oP '\d+\.\d+\.\d+\.\d+' | tail -1)
        fi

        printf '{"ts":"%s","domain":"%s","answer":"%s","type":"query"}\n' \
            "$ts" "$domain" "$ip_answer" >> "$outfile"
    done
}

analyze_dga() {
    local datafile="$PDNS_DIR/pdns-$(date +%Y%m%d).jsonl"
    [[ ! -f "$datafile" ]] && { log_msg "Sin datos pDNS de hoy"; return 1; }

    log_msg "Analizando dominios DGA..."
    local dga_count=0

    jq -r '.domain' "$datafile" 2>/dev/null | sort -u | while IFS= read -r domain; do
        [[ -z "$domain" ]] && continue
        # Extraer SLD (second-level domain)
        local sld
        sld=$(echo "$domain" | awk -F. '{if(NF>=2) print $(NF-1); else print $0}')
        local entropy
        entropy=$(calc_entropy "$sld")

        if awk "BEGIN{exit !($entropy > $ENTROPY_THRESHOLD)}" 2>/dev/null; then
            dga_count=$((dga_count + 1))
            log_msg "DGA SOSPECHOSO: $domain (entropia=$entropy)"
        fi
    done

    # Detectar NXD floods
    local nxd_count
    nxd_count=$(jq -r 'select(.answer=="") | .domain' "$datafile" 2>/dev/null | wc -l)
    if [[ $nxd_count -gt $NXD_THRESHOLD ]]; then
        log_msg "ALERTA NXD: $nxd_count consultas sin respuesta (posible DGA/tunneling)"
    fi

    log_msg "Analisis DGA completado"
}

stats() {
    local datafile="$PDNS_DIR/pdns-$(date +%Y%m%d).jsonl"
    [[ ! -f "$datafile" ]] && { echo "Sin datos"; return; }
    local total domains
    total=$(wc -l < "$datafile")
    domains=$(jq -r '.domain' "$datafile" 2>/dev/null | sort -u | wc -l)
    echo "Registros hoy: $total | Dominios unicos: $domains"
}

case "${1:-help}" in
    capture) capture_dns ;;
    analyze) analyze_dga ;;
    stats)   stats ;;
    *)       echo "Uso: $0 {capture [iface]|analyze|stats}" ;;
esac
EOFPDNS
    chmod +x "$NETINT_BIN/securizar-pdns-collector.sh"
    log_change "Creado" "$NETINT_BIN/securizar-pdns-collector.sh"

else
    log_skip "Passive DNS collector"
fi

# ============================================================
# S4: DETECCION DE ANOMALIAS DE PROTOCOLO
# ============================================================
log_section "S4: Deteccion de anomalias de protocolo"

log_info "Detecta HTTP en puertos no-80, DNS tunneling, protocolos inesperados."
log_info "  - Verifica tráfico por puerto vs protocolo esperado"
log_info "  - Alertas para protocolos sospechosos"
log_info ""

if check_executable /usr/local/bin/securizar-proto-anomaly.sh; then
    log_already "Proto anomaly (securizar-proto-anomaly.sh existe)"
elif ask "Crear detector de anomalias de protocolo?"; then

    cat > "$NETINT_BIN/securizar-proto-anomaly.sh" << 'EOFPROTO'
#!/bin/bash
# ============================================================
# securizar-proto-anomaly.sh - Deteccion de anomalias de protocolo
# ============================================================
set -euo pipefail

PROTO_LOG="/var/log/securizar/netint/proto-anomaly.log"
PROTO_DIR="/var/lib/securizar/netint/baselines"
mkdir -p "$PROTO_DIR" 2>/dev/null

log_msg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$PROTO_LOG"; }

# Puertos esperados por servicio
declare -A EXPECTED_PORTS=(
    [80]="http" [443]="https" [53]="dns" [22]="ssh"
    [25]="smtp" [465]="smtps" [993]="imaps" [143]="imap"
    [3306]="mysql" [5432]="postgres" [6379]="redis"
)

scan_anomalies() {
    log_msg "Escaneando anomalias de protocolo..."
    local alerts=0

    # Detectar DNS en puertos no-53
    local dns_non53
    dns_non53=$(ss -tunp 2>/dev/null | awk '$1=="udp" && $5!~/:53$/ && $5~/:/' | \
        grep -i "named\|dnsmasq\|unbound" 2>/dev/null | wc -l)
    if [[ $dns_non53 -gt 0 ]]; then
        alerts=$((alerts + 1))
        log_msg "ALERTA: $dns_non53 procesos DNS en puertos no-53"
    fi

    # Detectar conexiones salientes a puertos DNS no-estandar
    ss -tun state established 2>/dev/null | awk 'NR>1{print $5}' | while read -r remote; do
        local port
        port=$(echo "$remote" | rev | cut -d: -f1 | rev)
        local ip
        ip=$(echo "$remote" | rev | cut -d: -f2- | rev)

        # HTTP en puertos altos (posible tunneling)
        if [[ "$port" -gt 1024 ]] && [[ "$port" -ne 8080 ]] && [[ "$port" -ne 8443 ]]; then
            # Verificar si hay muchas conexiones al mismo puerto alto
            local count
            count=$(ss -tun state established "dst $ip:$port" 2>/dev/null | wc -l)
            if [[ $count -gt 5 ]]; then
                log_msg "SOSPECHOSO: $count conexiones a $ip:$port (puerto alto)"
            fi
        fi
    done

    # Detectar posible DNS tunneling (conexiones largas a puerto 53)
    ss -tun state established 2>/dev/null | awk '$5~/:53$/{print $5}' | sort -u | while read -r dest; do
        log_msg "INFO: Conexion TCP persistente a DNS: $dest (posible tunneling)"
    done

    log_msg "Escaneo completado: $alerts anomalias detectadas"
}

baseline() {
    log_msg "Generando baseline de protocolos..."
    ss -tunlp 2>/dev/null | awk 'NR>1{print $1, $5, $7}' | sort > "$PROTO_DIR/proto-baseline-$(date +%Y%m%d).txt"
    log_msg "Baseline guardado"
}

diff_baseline() {
    local latest
    latest=$(ls -t "$PROTO_DIR"/proto-baseline-*.txt 2>/dev/null | head -1)
    [[ -z "$latest" ]] && { log_msg "Sin baseline, ejecute: $0 baseline"; return 1; }

    local current="/tmp/proto-current-$$.txt"
    ss -tunlp 2>/dev/null | awk 'NR>1{print $1, $5, $7}' | sort > "$current"

    local new_services
    new_services=$(comm -13 "$latest" "$current" | wc -l)
    if [[ $new_services -gt 0 ]]; then
        log_msg "ALERTA: $new_services servicios nuevos desde ultimo baseline:"
        comm -13 "$latest" "$current" | while read -r line; do
            log_msg "  NUEVO: $line"
        done
    else
        log_msg "Sin cambios respecto al baseline"
    fi
    rm -f "$current"
}

case "${1:-help}" in
    scan)     scan_anomalies ;;
    baseline) baseline ;;
    diff)     diff_baseline ;;
    *)        echo "Uso: $0 {scan|baseline|diff}" ;;
esac
EOFPROTO
    chmod +x "$NETINT_BIN/securizar-proto-anomaly.sh"
    log_change "Creado" "$NETINT_BIN/securizar-proto-anomaly.sh"

else
    log_skip "Deteccion de anomalias de protocolo"
fi

# ============================================================
# S5: ENCRYPTED TRAFFIC ANALYSIS (ETA)
# ============================================================
log_section "S5: Encrypted Traffic Analysis (ETA)"

log_info "Metadata TLS sin descifrar: certs self-signed, cipher anomalias."
log_info "  - Detecta certificados auto-firmados en conexiones salientes"
log_info "  - Identifica cipher suites debiles o inusuales"
log_info ""

if check_executable /usr/local/bin/securizar-eta-analyzer.sh; then
    log_already "ETA analyzer (securizar-eta-analyzer.sh existe)"
elif ask "Crear analizador de trafico cifrado (ETA)?"; then

    cat > "$NETINT_BIN/securizar-eta-analyzer.sh" << 'EOFETA'
#!/bin/bash
# ============================================================
# securizar-eta-analyzer.sh - Encrypted Traffic Analysis
# ============================================================
set -euo pipefail

ETA_LOG="/var/log/securizar/netint/eta.log"
ETA_DIR="/var/lib/securizar/netint/baselines"
mkdir -p "$ETA_DIR" 2>/dev/null

log_msg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$ETA_LOG"; }

WEAK_CIPHERS="RC4|DES-CBC3|NULL|EXPORT|anon"

scan_tls_endpoints() {
    log_msg "Analizando endpoints TLS activos..."
    local alerts=0

    ss -tun state established 2>/dev/null | awk 'NR>1{print $5}' | \
        grep -E ':(443|8443|993|995|465)$' | sort -u | head -50 | while read -r remote; do
        local ip port
        ip=$(echo "$remote" | rev | cut -d: -f2- | rev)
        port=$(echo "$remote" | rev | cut -d: -f1 | rev)

        # Verificar certificado
        local cert_info
        cert_info=$(echo | timeout 5 openssl s_client -connect "$ip:$port" 2>/dev/null)
        [[ -z "$cert_info" ]] && continue

        # Self-signed check
        local issuer subject
        issuer=$(echo "$cert_info" | openssl x509 -noout -issuer 2>/dev/null | sed 's/issuer=//')
        subject=$(echo "$cert_info" | openssl x509 -noout -subject 2>/dev/null | sed 's/subject=//')
        if [[ "$issuer" == "$subject" ]] && [[ -n "$issuer" ]]; then
            alerts=$((alerts + 1))
            log_msg "ALERTA: Cert self-signed en $ip:$port - $subject"
        fi

        # Verificar cipher debil
        local cipher
        cipher=$(echo "$cert_info" | grep "Cipher" | head -1 | awk '{print $NF}')
        if echo "$cipher" | grep -qiE "$WEAK_CIPHERS"; then
            alerts=$((alerts + 1))
            log_msg "ALERTA: Cipher debil en $ip:$port - $cipher"
        fi

        # Verificar expiración
        local expiry
        expiry=$(echo "$cert_info" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
        if [[ -n "$expiry" ]]; then
            local exp_epoch
            exp_epoch=$(date -d "$expiry" +%s 2>/dev/null || echo 0)
            local now
            now=$(date +%s)
            if [[ $exp_epoch -lt $now ]] && [[ $exp_epoch -gt 0 ]]; then
                log_msg "ALERTA: Cert expirado en $ip:$port - $expiry"
            fi
        fi
    done

    log_msg "Analisis ETA completado: $alerts alertas"
}

scan_cipher_suites() {
    log_msg "Verificando cipher suites del sistema..."
    if command -v openssl &>/dev/null; then
        local weak
        weak=$(openssl ciphers -v 2>/dev/null | grep -ciE "$WEAK_CIPHERS")
        log_msg "Cipher suites debiles habilitados: $weak"
    fi
}

case "${1:-help}" in
    scan)    scan_tls_endpoints ;;
    ciphers) scan_cipher_suites ;;
    *)       echo "Uso: $0 {scan|ciphers}" ;;
esac
EOFETA
    chmod +x "$NETINT_BIN/securizar-eta-analyzer.sh"
    log_change "Creado" "$NETINT_BIN/securizar-eta-analyzer.sh"

else
    log_skip "Encrypted Traffic Analysis (ETA)"
fi

# ============================================================
# S6: MONITOR DE RUTAS BGP
# ============================================================
log_section "S6: Monitor de rutas BGP"

log_info "Baseline de tabla de rutas, deteccion de cambios."
log_info "  - Consulta RIPE RIS para deteccion de hijacks"
log_info "  - Alertas delta en cambios de rutas"
log_info ""

if check_executable /usr/local/bin/securizar-route-monitor.sh; then
    log_already "Route monitor (securizar-route-monitor.sh existe)"
elif ask "Crear monitor de rutas BGP?"; then

    # Configuracion base
    cat > "$NETINT_DIR/bgp-monitor.conf" << 'EOFBGPCONF'
# bgp-monitor.conf - Configuracion del monitor de rutas
# Prefijos propios a monitorizar (uno por linea)
# Ejemplo: 203.0.113.0/24
# MONITORED_PREFIXES=()
# Intervalo de chequeo en segundos
CHECK_INTERVAL=3600
# Habilitar consulta RIPE RIS
RIPE_RIS_ENABLED=true
EOFBGPCONF
    log_change "Creado" "$NETINT_DIR/bgp-monitor.conf"

    cat > "$NETINT_BIN/securizar-route-monitor.sh" << 'EOFROUTE'
#!/bin/bash
# ============================================================
# securizar-route-monitor.sh - Monitor de rutas BGP
# ============================================================
set -euo pipefail

ROUTE_DIR="/var/lib/securizar/netint/baselines"
ROUTE_LOG="/var/log/securizar/netint/route.log"
ROUTE_CONF="/etc/securizar/netint/bgp-monitor.conf"

mkdir -p "$ROUTE_DIR" 2>/dev/null
[[ -f "$ROUTE_CONF" ]] && source "$ROUTE_CONF"

log_msg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$ROUTE_LOG"; }

baseline() {
    local outfile="$ROUTE_DIR/routes-$(date +%Y%m%d-%H%M%S).txt"
    ip route show 2>/dev/null | sort > "$outfile"
    log_msg "Baseline de rutas guardado: $(wc -l < "$outfile") entradas"
}

check_delta() {
    local latest
    latest=$(ls -t "$ROUTE_DIR"/routes-*.txt 2>/dev/null | head -1)
    [[ -z "$latest" ]] && { log_msg "Sin baseline, ejecute: $0 baseline"; return 1; }

    local current="/tmp/routes-current-$$.txt"
    ip route show 2>/dev/null | sort > "$current"

    local added removed
    added=$(comm -13 "$latest" "$current" | wc -l)
    removed=$(comm -23 "$latest" "$current" | wc -l)

    if [[ $added -gt 0 ]] || [[ $removed -gt 0 ]]; then
        log_msg "ALERTA: Cambios en tabla de rutas: +$added -$removed"
        comm -13 "$latest" "$current" | while read -r line; do
            log_msg "  NUEVA: $line"
        done
        comm -23 "$latest" "$current" | while read -r line; do
            log_msg "  ELIMINADA: $line"
        done
    else
        log_msg "Sin cambios en tabla de rutas"
    fi
    rm -f "$current"
}

query_ripe_ris() {
    local prefix="${1:-}"
    [[ -z "$prefix" ]] && { echo "Uso: $0 ris <prefix>"; return 1; }

    log_msg "Consultando RIPE RIS para $prefix..."
    local result
    result=$(curl -sS --max-time 15 \
        "https://stat.ripe.net/data/routing-status/data.json?resource=$prefix" 2>/dev/null)

    if [[ -n "$result" ]] && command -v jq &>/dev/null; then
        local status
        status=$(echo "$result" | jq -r '.data.status // "unknown"' 2>/dev/null)
        local visibility
        visibility=$(echo "$result" | jq -r '.data.visibility.v4_full_table // 0' 2>/dev/null)
        log_msg "Prefijo $prefix: estado=$status visibilidad=$visibility"
    else
        log_msg "No se pudo consultar RIPE RIS para $prefix"
    fi
}

case "${1:-help}" in
    baseline) baseline ;;
    check)    check_delta ;;
    ris)      shift; query_ripe_ris "$@" ;;
    *)        echo "Uso: $0 {baseline|check|ris <prefix>}" ;;
esac
EOFROUTE
    chmod +x "$NETINT_BIN/securizar-route-monitor.sh"
    log_change "Creado" "$NETINT_BIN/securizar-route-monitor.sh"

else
    log_skip "Monitor de rutas BGP"
fi

# ============================================================
# S7: COLECTOR NETFLOW/SS SAMPLING
# ============================================================
log_section "S7: Colector NetFlow/ss sampling"

log_info "Softflowd si disponible, fallback ss sampling."
log_info "  - Baseline estadistico con alertas 3-sigma"
log_info "  - Deteccion de flujos anomalos"
log_info ""

if check_executable /usr/local/bin/securizar-netflow-collector.sh; then
    log_already "NetFlow collector (securizar-netflow-collector.sh existe)"
elif ask "Crear colector NetFlow/ss sampling?"; then

    cat > "$NETINT_BIN/securizar-netflow-collector.sh" << 'EOFFLOW'
#!/bin/bash
# ============================================================
# securizar-netflow-collector.sh - NetFlow/ss sampling collector
# ============================================================
set -euo pipefail

FLOW_DIR="/var/lib/securizar/netint/flows"
FLOW_LOG="/var/log/securizar/netint/flows.log"
BASELINE_DIR="/var/lib/securizar/netint/baselines"
SIGMA_MULTIPLIER=3

mkdir -p "$FLOW_DIR" "$BASELINE_DIR" 2>/dev/null

log_msg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$FLOW_LOG"; }

collect_sample() {
    local outfile="$FLOW_DIR/sample-$(date +%Y%m%d-%H%M%S).jsonl"
    local ts
    ts=$(date +%s)

    local total_conn=0 total_rx=0 total_tx=0

    ss -tun state established -o 2>/dev/null | awk 'NR>1{print $4, $5}' | while read -r local remote; do
        total_conn=$((total_conn + 1))
        local rip
        rip=$(echo "$remote" | rev | cut -d: -f2- | rev)
        local rport
        rport=$(echo "$remote" | rev | cut -d: -f1 | rev)
        printf '{"ts":%d,"local":"%s","remote_ip":"%s","remote_port":"%s"}\n' \
            "$ts" "$local" "$rip" "$rport" >> "$outfile"
    done

    # Resumen por interfaz
    local summary="$FLOW_DIR/summary-$(date +%Y%m%d).jsonl"
    local conn_count
    conn_count=$(ss -tun state established 2>/dev/null | tail -n +2 | wc -l)
    printf '{"ts":%d,"connections":%d}\n' "$ts" "$conn_count" >> "$summary"

    log_msg "Muestra recopilada: $conn_count conexiones activas"
}

build_baseline() {
    local summary_file="$FLOW_DIR/summary-$(date +%Y%m%d).jsonl"
    [[ ! -f "$summary_file" ]] && { log_msg "Sin datos de hoy"; return 1; }

    local stats
    stats=$(jq -s '
        [.[].connections] |
        {count: length, mean: (add/length),
         stddev: (pow(map(. - (add/length)) | map(.*.) | add / length; 0.5))}
    ' "$summary_file" 2>/dev/null)

    echo "$stats" > "$BASELINE_DIR/flow-baseline.json"
    log_msg "Baseline generado: $stats"
}

check_anomaly() {
    local baseline_file="$BASELINE_DIR/flow-baseline.json"
    [[ ! -f "$baseline_file" ]] && { log_msg "Sin baseline"; return 1; }

    local mean stddev
    mean=$(jq -r '.mean' "$baseline_file" 2>/dev/null)
    stddev=$(jq -r '.stddev' "$baseline_file" 2>/dev/null)

    local current
    current=$(ss -tun state established 2>/dev/null | tail -n +2 | wc -l)

    local upper
    upper=$(awk "BEGIN{printf \"%.0f\", $mean + $SIGMA_MULTIPLIER * $stddev}")

    if [[ $current -gt $upper ]]; then
        log_msg "ALERTA 3-SIGMA: $current conexiones (umbral=$upper, media=$mean, sigma=$stddev)"
    else
        log_msg "Normal: $current conexiones (umbral=$upper)"
    fi
}

case "${1:-help}" in
    collect)  collect_sample ;;
    baseline) build_baseline ;;
    check)    check_anomaly ;;
    *)        echo "Uso: $0 {collect|baseline|check}" ;;
esac
EOFFLOW
    chmod +x "$NETINT_BIN/securizar-netflow-collector.sh"
    log_change "Creado" "$NETINT_BIN/securizar-netflow-collector.sh"

else
    log_skip "Colector NetFlow/ss sampling"
fi

# ============================================================
# S8: DETECCION DE EXFILTRACION
# ============================================================
log_section "S8: Deteccion de exfiltracion"

log_info "Detecta transferencias >100MB, DNS exfil (labels >30 chars)."
log_info "  - Slow exfil: tracking acumulativo por destino"
log_info "  - Alertas para patrones de exfiltracion conocidos"
log_info ""

if check_executable /usr/local/bin/securizar-exfil-detect.sh; then
    log_already "Exfil detection (securizar-exfil-detect.sh existe)"
elif ask "Crear detector de exfiltracion?"; then

    cat > "$NETINT_BIN/securizar-exfil-detect.sh" << 'EOFEXFIL'
#!/bin/bash
# ============================================================
# securizar-exfil-detect.sh - Deteccion de exfiltracion
# ============================================================
set -euo pipefail

EXFIL_LOG="/var/log/securizar/netint/exfil.log"
EXFIL_DIR="/var/lib/securizar/netint/baselines"
LARGE_TRANSFER_MB=100
DNS_LABEL_THRESHOLD=30
SLOW_EXFIL_MB=500
SLOW_EXFIL_WINDOW=86400

mkdir -p "$EXFIL_DIR" 2>/dev/null

log_msg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$EXFIL_LOG"; }

check_large_transfers() {
    log_msg "Verificando transferencias grandes..."

    # Verificar via /proc/net/tcp para bytes transferidos
    if command -v conntrack &>/dev/null; then
        conntrack -L 2>/dev/null | awk -v thresh="$((LARGE_TRANSFER_MB * 1048576))" '
        /ESTABLISHED/ {
            for(i=1;i<=NF;i++) {
                if($i ~ /^bytes=/) {
                    split($i,a,"=")
                    if(a[2]+0 > thresh) print $0
                }
            }
        }' | while read -r line; do
            log_msg "ALERTA TRANSFERENCIA GRANDE: $line"
        done
    else
        # Fallback: monitorizar interfaces
        local iface
        for iface in /sys/class/net/*/statistics/tx_bytes; do
            [[ ! -f "$iface" ]] && continue
            local name tx_bytes
            name=$(echo "$iface" | cut -d/ -f5)
            [[ "$name" == "lo" ]] && continue
            tx_bytes=$(<"$iface")
            local prev_file="$EXFIL_DIR/tx-${name}.prev"
            if [[ -f "$prev_file" ]]; then
                local prev delta_mb
                prev=$(<"$prev_file")
                delta_mb=$(( (tx_bytes - prev) / 1048576 ))
                if [[ $delta_mb -gt $LARGE_TRANSFER_MB ]]; then
                    log_msg "ALERTA: $name transmitio ${delta_mb}MB desde ultimo check"
                fi
            fi
            echo "$tx_bytes" > "$prev_file"
        done
    fi
}

check_dns_exfil() {
    log_msg "Verificando exfiltracion DNS..."
    local pdns_file="/var/lib/securizar/netint/pdns/pdns-$(date +%Y%m%d).jsonl"
    [[ ! -f "$pdns_file" ]] && { log_msg "Sin datos pDNS de hoy"; return 0; }

    local suspicious=0
    jq -r '.domain' "$pdns_file" 2>/dev/null | while IFS= read -r domain; do
        # Verificar longitud de labels
        local max_label
        max_label=$(echo "$domain" | tr '.' '\n' | awk '{print length}' | sort -rn | head -1)
        if [[ ${max_label:-0} -gt $DNS_LABEL_THRESHOLD ]]; then
            suspicious=$((suspicious + 1))
            log_msg "DNS EXFIL SOSPECHOSO: $domain (label=${max_label} chars)"
        fi
    done

    log_msg "Verificacion DNS exfil completada"
}

check_slow_exfil() {
    log_msg "Verificando exfiltracion lenta acumulativa..."
    local tracker="$EXFIL_DIR/slow-exfil-tracker.jsonl"
    local now
    now=$(date +%s)
    local cutoff=$((now - SLOW_EXFIL_WINDOW))

    # Limpiar entradas antiguas
    if [[ -f "$tracker" ]]; then
        local tmp="/tmp/exfil-clean-$$.jsonl"
        jq -c "select(.ts > $cutoff)" "$tracker" > "$tmp" 2>/dev/null
        mv "$tmp" "$tracker"
    fi

    # Acumular por destino
    if [[ -f "$tracker" ]]; then
        jq -s 'group_by(.dst) | .[] | {dst: .[0].dst, total_mb: ([.[].bytes] | add / 1048576)}' \
            "$tracker" 2>/dev/null | jq -c "select(.total_mb > $SLOW_EXFIL_MB)" | while read -r line; do
            local dst total
            dst=$(echo "$line" | jq -r '.dst')
            total=$(echo "$line" | jq -r '.total_mb')
            log_msg "ALERTA SLOW EXFIL: ${total}MB acumulados hacia $dst en 24h"
        done
    fi
}

case "${1:-help}" in
    transfers) check_large_transfers ;;
    dns)       check_dns_exfil ;;
    slow)      check_slow_exfil ;;
    all)       check_large_transfers; check_dns_exfil; check_slow_exfil ;;
    *)         echo "Uso: $0 {transfers|dns|slow|all}" ;;
esac
EOFEXFIL
    chmod +x "$NETINT_BIN/securizar-exfil-detect.sh"
    log_change "Creado" "$NETINT_BIN/securizar-exfil-detect.sh"

else
    log_skip "Deteccion de exfiltracion"
fi

# ============================================================
# S9: FORENSE DE RED (PCAP + CADENA CUSTODIA)
# ============================================================
log_section "S9: Forense de red (pcap + cadena custodia)"

log_info "Captura pcap con cadena de custodia, hash SHA-256."
log_info "  - Metadata JSON, rotacion automatica"
log_info "  - Almacenamiento forense con integridad verificable"
log_info ""

if check_executable /usr/local/bin/securizar-netforensics.sh; then
    log_already "Net forensics (securizar-netforensics.sh existe)"
elif ask "Crear herramienta de forense de red?"; then

    cat > "$NETINT_BIN/securizar-netforensics.sh" << 'EOFFORENSICS'
#!/bin/bash
# ============================================================
# securizar-netforensics.sh - Forense de red con cadena custodia
# ============================================================
set -euo pipefail

PCAP_DIR="/var/lib/securizar/netint/pcaps"
FORENSICS_LOG="/var/log/securizar/netint/forensics.log"
MAX_PCAP_SIZE_MB=100
MAX_PCAPS=50
CAPTURE_IFACE="${3:-any}"

mkdir -p "$PCAP_DIR" 2>/dev/null

log_msg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$FORENSICS_LOG"; }

capture() {
    local duration="${1:-300}"
    local label="${2:-manual}"

    if ! command -v tcpdump &>/dev/null; then
        log_msg "ERROR: tcpdump no disponible"
        return 1
    fi

    local ts
    ts=$(date +%Y%m%d-%H%M%S)
    local pcap_file="$PCAP_DIR/capture-${label}-${ts}.pcap"
    local meta_file="$PCAP_DIR/capture-${label}-${ts}.meta.json"

    log_msg "Iniciando captura: $pcap_file (${duration}s, iface=$CAPTURE_IFACE)"

    local operator
    operator=$(whoami)
    local hostname_val
    hostname_val=$(hostname)

    # Captura
    timeout "$duration" tcpdump -i "$CAPTURE_IFACE" -w "$pcap_file" \
        -c 1000000 2>/dev/null &
    local pid=$!
    wait $pid 2>/dev/null || true

    if [[ ! -f "$pcap_file" ]]; then
        log_msg "ERROR: No se genero archivo pcap"
        return 1
    fi

    # Hash de integridad
    local hash
    hash=$(sha256sum "$pcap_file" | awk '{print $1}')
    local size
    size=$(stat -c %s "$pcap_file" 2>/dev/null || echo 0)

    # Metadata de cadena de custodia
    cat > "$meta_file" << EOFMETA
{
  "file": "$(basename "$pcap_file")",
  "sha256": "$hash",
  "size_bytes": $size,
  "capture_start": "$ts",
  "duration_seconds": $duration,
  "interface": "$CAPTURE_IFACE",
  "operator": "$operator",
  "hostname": "$hostname_val",
  "label": "$label",
  "chain_of_custody": [
    {"action": "captured", "by": "$operator", "at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)", "hash": "$hash"}
  ]
}
EOFMETA

    chmod 600 "$pcap_file" "$meta_file"
    log_msg "Captura completada: $pcap_file ($size bytes, SHA256=$hash)"
}

verify() {
    local pcap_file="$1"
    local meta_file="${pcap_file%.pcap}.meta.json"

    [[ ! -f "$pcap_file" ]] && { echo "Archivo no encontrado: $pcap_file"; return 1; }
    [[ ! -f "$meta_file" ]] && { echo "Metadata no encontrada: $meta_file"; return 1; }

    local stored_hash current_hash
    stored_hash=$(jq -r '.sha256' "$meta_file" 2>/dev/null)
    current_hash=$(sha256sum "$pcap_file" | awk '{print $1}')

    if [[ "$stored_hash" == "$current_hash" ]]; then
        echo "INTEGRIDAD OK: Hash coincide ($current_hash)"
    else
        echo "INTEGRIDAD COMPROMETIDA: stored=$stored_hash actual=$current_hash"
        return 1
    fi
}

rotate() {
    local count
    count=$(find "$PCAP_DIR" -name "*.pcap" 2>/dev/null | wc -l)
    if [[ $count -gt $MAX_PCAPS ]]; then
        local to_remove=$((count - MAX_PCAPS))
        log_msg "Rotando: eliminando $to_remove capturas antiguas"
        ls -t "$PCAP_DIR"/*.pcap 2>/dev/null | tail -n "$to_remove" | while read -r f; do
            rm -f "$f" "${f%.pcap}.meta.json"
            log_msg "Eliminado: $(basename "$f")"
        done
    fi
}

list_captures() {
    echo "Capturas disponibles:"
    for meta in "$PCAP_DIR"/*.meta.json; do
        [[ ! -f "$meta" ]] && continue
        local file size label
        file=$(jq -r '.file' "$meta" 2>/dev/null)
        size=$(jq -r '.size_bytes' "$meta" 2>/dev/null)
        label=$(jq -r '.label' "$meta" 2>/dev/null)
        printf "  %-45s %10s bytes  [%s]\n" "$file" "$size" "$label"
    done
}

case "${1:-help}" in
    capture) shift; capture "$@" ;;
    verify)  shift; verify "$@" ;;
    rotate)  rotate ;;
    list)    list_captures ;;
    *)       echo "Uso: $0 {capture [secs] [label] [iface]|verify <pcap>|rotate|list}" ;;
esac
EOFFORENSICS
    chmod +x "$NETINT_BIN/securizar-netforensics.sh"
    log_change "Creado" "$NETINT_BIN/securizar-netforensics.sh"

else
    log_skip "Forense de red"
fi

# ============================================================
# S10: AUDITORIA INTEGRAL INTELIGENCIA DE RED
# ============================================================
log_section "S10: Auditoria integral inteligencia de red"

log_info "Crea herramienta de auditoria integral del sistema netint."
log_info ""

if check_executable /usr/local/bin/auditoria-netint-completa.sh; then
    log_already "Auditoria integral (auditoria-netint-completa.sh existe)"
elif ask "Crear herramienta de auditoria integral de inteligencia de red?"; then

    cat > "$NETINT_BIN/auditoria-netint-completa.sh" << 'EOFAUDIT'
#!/bin/bash
# ============================================================
# auditoria-netint-completa.sh - Auditoria integral netint
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
echo -e "${BOLD}  AUDITORIA: INTELIGENCIA DE RED AVANZADA (Modulo 76)${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════════${NC}"
echo ""

# S1: JA3
check "JA3 fingerprinting instalado" "test -x /usr/local/bin/securizar-ja3-fingerprint.sh"
check "BD JA3 malware presente" "test -f /var/lib/securizar/netint/ja3db/ja3-malware.csv"
check "Cron actualizacion JA3" "test -f /etc/cron.daily/securizar-ja3-update"

# S2: Beaconing
check "Detector beaconing instalado" "test -x /usr/local/bin/securizar-beacon-detect.sh"
check "Datos muestreo beaconing" "ls /var/lib/securizar/netint/baselines/conn-samples-*.jsonl"

# S3: Passive DNS
check "Colector pDNS instalado" "test -x /usr/local/bin/securizar-pdns-collector.sh"
check "Datos pDNS presentes" "ls /var/lib/securizar/netint/pdns/pdns-*.jsonl"

# S4: Protocol anomaly
check "Detector anomalias protocolo" "test -x /usr/local/bin/securizar-proto-anomaly.sh"

# S5: ETA
check "Analizador ETA instalado" "test -x /usr/local/bin/securizar-eta-analyzer.sh"

# S6: Route monitor
check "Monitor rutas instalado" "test -x /usr/local/bin/securizar-route-monitor.sh"
check "Config BGP monitor" "test -f /etc/securizar/netint/bgp-monitor.conf"
check "Baseline rutas presente" "ls /var/lib/securizar/netint/baselines/routes-*.txt"

# S7: NetFlow
check "Colector NetFlow instalado" "test -x /usr/local/bin/securizar-netflow-collector.sh"
check "Baseline flujos presente" "test -f /var/lib/securizar/netint/baselines/flow-baseline.json"

# S8: Exfiltracion
check "Detector exfiltracion instalado" "test -x /usr/local/bin/securizar-exfil-detect.sh"

# S9: Forensics
check "Forense red instalado" "test -x /usr/local/bin/securizar-netforensics.sh"
check "Directorio pcaps" "test -d /var/lib/securizar/netint/pcaps"

# Dependencias
check "tshark disponible" "command -v tshark"
check "tcpdump disponible" "command -v tcpdump"
check "jq disponible" "command -v jq"
check "openssl disponible" "command -v openssl"

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

logger -t securizar-netint "Auditoria completada: $SCORE/$MAX ($pct%)"
EOFAUDIT
    chmod +x "$NETINT_BIN/auditoria-netint-completa.sh"
    log_change "Creado" "$NETINT_BIN/auditoria-netint-completa.sh"

    # Cron semanal
    cat > /etc/cron.weekly/auditoria-netint << 'EOFCRON'
#!/bin/bash
/usr/local/bin/auditoria-netint-completa.sh > /dev/null 2>&1
EOFCRON
    chmod 700 /etc/cron.weekly/auditoria-netint
    log_change "Creado" "/etc/cron.weekly/auditoria-netint"

else
    log_skip "Auditoria integral inteligencia de red"
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
show_changes_summary
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   INTELIGENCIA DE RED (MODULO 76) COMPLETADO             ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups guardados en: $BACKUP_DIR"
echo ""
echo "Comandos disponibles:"
echo "  - JA3 fingerprint:  securizar-ja3-fingerprint.sh {update|capture|check}"
echo "  - Beaconing:        securizar-beacon-detect.sh {sample|analyze|daemon}"
echo "  - Passive DNS:      securizar-pdns-collector.sh {capture|analyze|stats}"
echo "  - Proto anomaly:    securizar-proto-anomaly.sh {scan|baseline|diff}"
echo "  - ETA analyzer:     securizar-eta-analyzer.sh {scan|ciphers}"
echo "  - Route monitor:    securizar-route-monitor.sh {baseline|check|ris}"
echo "  - NetFlow:          securizar-netflow-collector.sh {collect|baseline|check}"
echo "  - Exfil detect:     securizar-exfil-detect.sh {transfers|dns|slow|all}"
echo "  - Net forensics:    securizar-netforensics.sh {capture|verify|rotate|list}"
echo "  - Auditoria:        auditoria-netint-completa.sh"
