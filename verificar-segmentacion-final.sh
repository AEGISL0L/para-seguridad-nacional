#!/bin/bash
# ============================================================
# verificar-segmentacion-final.sh - Verificación exhaustiva de segmentación
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[0;33m'; CYN='\033[0;36m'; RST='\033[0m'
ok=0; warn=0; fail=0

pass() { echo -e "  ${GRN}[OK]${RST} $1"; ((ok++)); }
adv()  { echo -e "  ${YEL}[!!]${RST} $1"; ((warn++)); }
err()  { echo -e "  ${RED}[XX]${RST} $1"; ((fail++)); }

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   VERIFICACIÓN EXHAUSTIVA - SEGMENTACIÓN DE RED          ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# ── 1. TABLA NFTABLES ──────────────────────────────────────
echo -e "${CYN}═══ 1. TABLA NFTABLES ═══${RST}"

if ! command -v nft &>/dev/null; then
    err "nft no encontrado en PATH"
else
    pass "nft disponible: $(which nft)"
fi

if nft list table inet securizar_zonas &>/dev/null; then
    pass "Tabla inet securizar_zonas cargada en kernel"
else
    err "Tabla inet securizar_zonas NO cargada"
fi

# Contar cadenas
n_chains=$(nft list table inet securizar_zonas 2>/dev/null | grep -c '^\s*chain ')
if [[ $n_chains -ge 15 ]]; then
    pass "Cadenas: $n_chains (esperado >=15)"
else
    err "Cadenas: $n_chains (esperado >=15)"
fi

# Verificar cada cadena esperada
for chain in antispoof ipv6_filter icmp_filter syn_flood_protect \
             zona_input zona_forward zona_output \
             trusted_input internal_input dmz_input restricted_input \
             trusted_forward internal_forward dmz_forward restricted_forward \
             politicas_forward; do
    if nft list chain inet securizar_zonas "$chain" &>/dev/null; then
        pass "Cadena $chain existe"
    else
        err "Cadena $chain NO existe"
    fi
done

# ── 2. SETS ────────────────────────────────────────────────
echo ""
echo -e "${CYN}═══ 2. SETS ═══${RST}"

for s in trusted_nets internal_nets dmz_nets restricted_nets bogon_nets \
         blocklist_ips blocklist_nets port_scanners ssh_bruteforce; do
    if nft list set inet securizar_zonas "$s" &>/dev/null; then
        elems=$(nft list set inet securizar_zonas "$s" 2>/dev/null | grep -c 'elements')
        if [[ "$s" =~ ^(blocklist_ips|blocklist_nets|port_scanners|ssh_bruteforce)$ ]]; then
            pass "Set $s existe (dinámico)"
        else
            pass "Set $s existe (con elementos)"
        fi
    else
        err "Set $s NO existe"
    fi
done

# ── 3. REGLAS DEFENSIVAS ───────────────────────────────────
echo ""
echo -e "${CYN}═══ 3. REGLAS DEFENSIVAS ═══${RST}"

TABLE=$(nft list table inet securizar_zonas 2>/dev/null)

# Antispoof
echo "$TABLE" | grep -q '@bogon_nets.*drop' && pass "Antispoof: bogon_nets activo" || err "Antispoof: bogon_nets falta"
echo "$TABLE" | grep -q '127.0.0.0/8.*drop' && pass "Antispoof: loopback fuera de lo" || err "Antispoof: loopback falta"
echo "$TABLE" | grep -q '255.255.255.255.*drop' && pass "Antispoof: broadcast src" || err "Antispoof: broadcast falta"

# IPv6 filter
echo "$TABLE" | grep -q 'meta nfproto ipv6 jump ipv6_filter' && pass "IPv6 filter: jump activo en zona_input" || err "IPv6 filter: jump falta"

# ICMP filter
echo "$TABLE" | grep -q 'icmp type.*destination-unreachable.*accept' && pass "ICMP: PMTUD (dest-unreachable) permitido" || err "ICMP: PMTUD falta"
echo "$TABLE" | grep -q 'echo-request.*limit rate' && pass "ICMP: echo-request con rate-limit" || err "ICMP: echo-request sin rate-limit"

# SYN flood
echo "$TABLE" | grep -q 'limit rate 25/second' && pass "SYN flood: 25/s burst 50 activo" || err "SYN flood: protección falta"

# Invalid state
n_invalid=$(echo "$TABLE" | grep -c 'ct state invalid.*counter.*drop')
if [[ $n_invalid -ge 2 ]]; then
    pass "Invalid state: drop en input + forward ($n_invalid reglas)"
else
    adv "Invalid state: solo $n_invalid reglas (esperado >=2)"
fi

# Blocklist
n_blocklist=$(echo "$TABLE" | grep -c '@blocklist_ips.*drop\|@blocklist_nets.*drop')
if [[ $n_blocklist -ge 4 ]]; then
    pass "Blocklist: $n_blocklist reglas (input saddr + forward saddr/daddr)"
else
    adv "Blocklist: solo $n_blocklist reglas (esperado >=4)"
fi

# Port scanners
echo "$TABLE" | grep -q '@port_scanners.*drop' && pass "Port scanners: bloqueo activo en zona_input" || err "Port scanners: bloqueo falta"
echo "$TABLE" | grep -q 'update @port_scanners' && pass "Port scanners: detección en cadenas de zona" || err "Port scanners: detección falta"

# SSH bruteforce
echo "$TABLE" | grep -q '@ssh_bruteforce.*limit rate' && pass "SSH bruteforce: rate-limit per-IP activo" || err "SSH bruteforce: protección falta"

# Output chain
echo "$TABLE" | grep -q 'securizar-zonas-egress' && pass "Output: log egress activo" || err "Output: log egress falta"
n_out_bl=$(echo "$TABLE" | grep -A50 'chain zona_output' | grep -c '@blocklist.*drop')
if [[ $n_out_bl -ge 2 ]]; then
    pass "Output: blocklist egress activa ($n_out_bl reglas)"
else
    adv "Output: blocklist egress incompleta ($n_out_bl reglas)"
fi

# Politicas forward
echo "$TABLE" | grep -q 'jump politicas_forward' && pass "Políticas dinámicas: jump activo en zona_forward" || err "Políticas dinámicas: jump falta"

# Rate-limited logs
n_ratelimit=$(echo "$TABLE" | grep -c 'limit rate.*log prefix')
if [[ $n_ratelimit -ge 5 ]]; then
    pass "Logs con rate-limit: $n_ratelimit reglas"
else
    adv "Logs con rate-limit: solo $n_ratelimit (esperado >=5)"
fi

# Counters en drops
n_counter_drop=$(echo "$TABLE" | grep -c 'counter.*drop')
if [[ $n_counter_drop -ge 10 ]]; then
    pass "Counters en drops: $n_counter_drop reglas"
else
    adv "Counters en drops: solo $n_counter_drop (esperado >=10)"
fi

# ── 4. POLÍTICAS DE CADENA ─────────────────────────────────
echo ""
echo -e "${CYN}═══ 4. POLÍTICAS DE CADENA ═══${RST}"

# Verificar policy y priority por cadena (extraer del TABLE con awk)
check_chain_policy() {
    local chain="$1" expected="$2"
    echo "$TABLE" | awk "/chain $chain \{/,/\}/" | grep -q "policy $expected" \
        && pass "$chain: policy $expected" || err "$chain: policy incorrecta"
}
check_chain_policy zona_input accept
check_chain_policy zona_forward drop
check_chain_policy zona_output accept
check_chain_policy antispoof accept

# Prioridades
echo "$TABLE" | awk '/chain antispoof \{/,/\}/' | grep -q 'priority raw' \
    && pass "antispoof: priority raw (-300)" || adv "antispoof: priority no es raw"
echo "$TABLE" | awk '/chain zona_input \{/,/\}/' | grep -q 'priority.*filter.*-.*10' \
    && pass "zona_input: priority filter - 10" || adv "zona_input: priority inesperada"

# ── 5. SYSCTL RED ──────────────────────────────────────────
echo ""
echo -e "${CYN}═══ 5. SYSCTL RED ═══${RST}"

check_sysctl() {
    local key="$1" expected="$2" desc="$3"
    local val
    val=$(sysctl -n "$key" 2>/dev/null)
    if [[ "$val" == "$expected" ]]; then
        pass "$desc: $key = $val"
    else
        err "$desc: $key = $val (esperado $expected)"
    fi
}

check_sysctl net.ipv4.icmp_echo_ignore_all      0 "ICMP delegado a nftables"
check_sysctl net.ipv4.icmp_echo_ignore_broadcasts 1 "Smurf protection"
check_sysctl net.ipv4.conf.all.rp_filter         1 "Reverse path filter"
check_sysctl net.ipv4.conf.default.rp_filter     1 "Reverse path filter (default)"
check_sysctl net.ipv4.tcp_syncookies             1 "SYN cookies"
check_sysctl net.ipv4.ip_forward                 0 "IP forwarding deshabilitado"
check_sysctl net.ipv6.conf.all.disable_ipv6      1 "IPv6 deshabilitado"
check_sysctl net.ipv4.conf.all.accept_redirects  0 "Redirects rechazados"
check_sysctl net.ipv4.conf.all.send_redirects    0 "No enviar redirects"
check_sysctl net.ipv4.conf.all.accept_source_route 0 "Source routing rechazado"
check_sysctl net.ipv4.conf.all.log_martians      1 "Log martians"
check_sysctl net.ipv4.tcp_rfc1337                1 "TIME-WAIT assassination"

# ARP (informativo)
arp_ann=$(sysctl -n net.ipv4.conf.all.arp_announce 2>/dev/null)
arp_ign=$(sysctl -n net.ipv4.conf.all.arp_ignore 2>/dev/null)
if [[ "$arp_ann" == "2" && "$arp_ign" == "1" ]]; then
    pass "ARP protection: announce=$arp_ann ignore=$arp_ign"
else
    adv "ARP protection: announce=$arp_ann ignore=$arp_ign (recomendado 2/1)"
fi

# ── 6. FICHEROS EN DISCO ──────────────────────────────────
echo ""
echo -e "${CYN}═══ 6. FICHEROS EN DISCO ═══${RST}"

check_file() {
    local path="$1" desc="$2"
    if [[ -f "$path" ]]; then
        pass "$desc: $path"
    else
        err "$desc falta: $path"
    fi
}

check_file /etc/nftables.d/securizar-zonas.nft       "Reglas nftables"
check_file /etc/securizar/zonas-red.conf              "Definición de zonas"
check_file /etc/securizar/politicas-interzona.conf    "Políticas inter-zona"
check_file /etc/sysctl.d/99-securizar-zonas.conf      "Override sysctl ICMP"
check_file /usr/local/bin/aplicar-politicas-zona.sh   "Script políticas"
check_file /usr/local/bin/validar-segmentacion.sh     "Script validación"
check_file /usr/local/bin/monitorizar-trafico-zonas.sh "Script monitorización"

# Idempotencia del .nft
if grep -q 'delete table inet securizar_zonas' /etc/nftables.d/securizar-zonas.nft 2>/dev/null; then
    pass "Fichero .nft es idempotente (delete+create)"
else
    err "Fichero .nft NO es idempotente"
fi

# Idempotencia del script de políticas
if grep -q 'flush chain' /usr/local/bin/aplicar-politicas-zona.sh 2>/dev/null; then
    pass "Script políticas es idempotente (flush antes de add)"
else
    err "Script políticas NO es idempotente"
fi

# nftables habilitado en arranque
if systemctl is-enabled nftables &>/dev/null; then
    pass "nftables habilitado en arranque"
else
    adv "nftables NO habilitado en arranque"
fi

# ── 7. CONTADORES ACTIVOS ─────────────────────────────────
echo ""
echo -e "${CYN}═══ 7. CONTADORES ACTIVOS ═══${RST}"

echo "  Paquetes procesados por cadenas defensivas:"
for chain in antispoof ipv6_filter icmp_filter syn_flood_protect zona_output; do
    pkts=$(nft list chain inet securizar_zonas "$chain" 2>/dev/null \
           | grep -oP 'packets \K[0-9]+' | awk '{s+=$1}END{print s+0}')
    printf "    %-22s %s paquetes\n" "$chain:" "$pkts"
done

# Sets dinámicos
echo ""
echo "  Elementos en sets dinámicos:"
for s in port_scanners ssh_bruteforce blocklist_ips blocklist_nets; do
    elems=$(nft list set inet securizar_zonas "$s" 2>/dev/null \
            | grep -oP 'elements = \{[^}]*\}' | tr ',' '\n' | grep -c '[0-9]')
    printf "    %-22s %s elementos\n" "$s:" "${elems:-0}"
done

# ── RESUMEN ────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════"
total=$((ok + warn + fail))
echo -e "  ${GRN}OK: $ok${RST}  ${YEL}AVISO: $warn${RST}  ${RED}FALLO: $fail${RST}  (total: $total checks)"

if [[ $fail -eq 0 && $warn -eq 0 ]]; then
    echo -e "  ${GRN}ESTADO: ÓPTIMO — Todas las verificaciones pasadas${RST}"
elif [[ $fail -eq 0 ]]; then
    echo -e "  ${YEL}ESTADO: BUENO — Sin fallos, $warn avisos menores${RST}"
else
    echo -e "  ${RED}ESTADO: REQUIERE ATENCIÓN — $fail fallos detectados${RST}"
fi
echo "══════════════════════════════════════════"
echo ""
