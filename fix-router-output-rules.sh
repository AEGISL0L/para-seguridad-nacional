#!/bin/bash
# ============================================================
# fix-router-output-rules.sh
# Corrige reglas de firewall del router (192.168.1.1)
# Mueve bloqueos de INPUT (inefectivos) a OUTPUT (correcto)
# ============================================================
set -euo pipefail

# ── Colores ──────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC}    $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $1"; }
fail() { echo -e "${RED}[FAIL]${NC}  $1"; }
info() { echo -e "        $1"; }

ROUTER_IP="192.168.1.1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NFT_CONF="/etc/nftables.d/securizar-zonas.nft"
SRC_SCRIPT="${SCRIPT_DIR}/segmentacion-red-zt.sh"
BACKUP_DIR="/tmp/fix-router-$(date +%Y%m%d-%H%M%S)"

# ── Verificar root ───────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "Este script requiere root. Ejecuta: sudo $0"
    exit 1
fi

echo "============================================================"
echo " Corrección: reglas OUTPUT para bloqueo admin router"
echo " Router: ${ROUTER_IP}"
echo "============================================================"
echo ""

mkdir -p "$BACKUP_DIR"

# ============================================================
# PASO 1: Aplicar reglas nftables en runtime
# ============================================================
echo "── Paso 1: Aplicar reglas nftables en runtime ──"

# Verificar que la tabla y cadena existen
if ! nft list chain inet securizar_zonas zona_output &>/dev/null; then
    fail "No existe la cadena inet securizar_zonas zona_output"
    exit 1
fi

# Guardar estado actual
nft list chain inet securizar_zonas zona_output > "$BACKUP_DIR/zona_output_antes.nft"
ok "Backup de cadena actual en $BACKUP_DIR/zona_output_antes.nft"

# Verificar si las reglas ya existen
if nft list chain inet securizar_zonas zona_output | grep -q "ROUTER-ADMIN-BLOCK"; then
    warn "Las reglas de OUTPUT del router ya existen en runtime. Saltando."
else
    # Obtener handle de la regla blocklist_nets (insertamos después)
    HANDLE=$(nft -a list chain inet securizar_zonas zona_output | \
        grep '@blocklist_nets' | grep -oP 'handle \K[0-9]+' | head -1)

    if [[ -z "$HANDLE" ]]; then
        # Fallback: obtener handle de blocklist_ips
        HANDLE=$(nft -a list chain inet securizar_zonas zona_output | \
            grep '@blocklist_ips' | grep -oP 'handle \K[0-9]+' | head -1)
    fi

    if [[ -z "$HANDLE" ]]; then
        fail "No se encontró handle de referencia en zona_output"
        exit 1
    fi

    # Insertar reglas DESPUÉS de blocklist_nets (en orden inverso por ser add after)
    nft add rule inet securizar_zonas zona_output position "$HANDLE" \
        ip daddr "$ROUTER_IP" udp dport 53 counter log prefix '"ROUTER-DNS-BLOCK: "' drop
    nft add rule inet securizar_zonas zona_output position "$HANDLE" \
        ip daddr "$ROUTER_IP" tcp dport 53 counter log prefix '"ROUTER-DNS-BLOCK: "' drop
    nft add rule inet securizar_zonas zona_output position "$HANDLE" \
        ip daddr "$ROUTER_IP" tcp dport '{ 80, 443, 8080 }' counter log prefix '"ROUTER-ADMIN-BLOCK: "' reject with icmp port-unreachable

    ok "3 reglas insertadas en zona_output (runtime)"
fi

# ============================================================
# PASO 2: Actualizar configuración nftables permanente
# ============================================================
echo ""
echo "── Paso 2: Actualizar $NFT_CONF ──"

if [[ ! -f "$NFT_CONF" ]]; then
    fail "No existe $NFT_CONF"
    exit 1
fi

cp "$NFT_CONF" "$BACKUP_DIR/securizar-zonas.nft.bak"
ok "Backup en $BACKUP_DIR/securizar-zonas.nft.bak"

if grep -q "ROUTER-ADMIN-BLOCK" "$NFT_CONF"; then
    warn "Las reglas del router ya existen en $NFT_CONF. Saltando."
else
    # Insertar después de la línea blocklist_nets
    sed -i '/ip daddr @blocklist_nets counter drop/a\
\
        # Bloquear acceso saliente al admin del router\
        ip daddr 192.168.1.1 tcp dport { 80, 443, 8080 } counter log prefix "ROUTER-ADMIN-BLOCK: " reject with icmp port-unreachable\
        ip daddr 192.168.1.1 tcp dport 53 counter log prefix "ROUTER-DNS-BLOCK: " drop\
        ip daddr 192.168.1.1 udp dport 53 counter log prefix "ROUTER-DNS-BLOCK: " drop' "$NFT_CONF"

    # Validar sintaxis del archivo modificado
    if nft -c -f "$NFT_CONF" 2>/dev/null; then
        ok "Archivo $NFT_CONF actualizado y validado"
    else
        fail "Error de sintaxis en $NFT_CONF - restaurando backup"
        cp "$BACKUP_DIR/securizar-zonas.nft.bak" "$NFT_CONF"
        exit 1
    fi
fi

# ============================================================
# PASO 3: Actualizar script fuente
# ============================================================
echo ""
echo "── Paso 3: Actualizar $SRC_SCRIPT ──"

if [[ ! -f "$SRC_SCRIPT" ]]; then
    warn "No se encontró $SRC_SCRIPT - saltar actualización del fuente"
else
    cp "$SRC_SCRIPT" "$BACKUP_DIR/segmentacion-red-zt.sh.bak"
    ok "Backup en $BACKUP_DIR/segmentacion-red-zt.sh.bak"

    if grep -q "ROUTER-ADMIN-BLOCK" "$SRC_SCRIPT"; then
        warn "Las reglas del router ya existen en el script fuente. Saltando."
    else
        sed -i '/ip daddr @blocklist_nets counter drop/a\
\
        # Bloquear acceso saliente al admin del router\
        ip daddr 192.168.1.1 tcp dport { 80, 443, 8080 } counter log prefix "ROUTER-ADMIN-BLOCK: " reject with icmp port-unreachable\
        ip daddr 192.168.1.1 tcp dport 53 counter log prefix "ROUTER-DNS-BLOCK: " drop\
        ip daddr 192.168.1.1 udp dport 53 counter log prefix "ROUTER-DNS-BLOCK: " drop' "$SRC_SCRIPT"
        ok "Script fuente actualizado"
    fi
fi

# ============================================================
# PASO 4: Limpiar reglas inefectivas de firewalld (INPUT)
# ============================================================
echo ""
echo "── Paso 4: Limpiar rich rules inefectivas de firewalld ──"

REMOVED=0

declare -a STALE_RULES=(
    'rule family="ipv4" destination address="192.168.1.1" port port="80" protocol="tcp" reject'
    'rule family="ipv4" destination address="192.168.1.1" port port="443" protocol="tcp" reject'
    'rule family="ipv4" destination address="192.168.1.1" port port="8080" protocol="tcp" reject'
    'rule family="ipv4" destination address="192.168.1.1" port port="53" protocol="udp" drop'
)

for rule in "${STALE_RULES[@]}"; do
    if firewall-cmd --query-rich-rule="$rule" 2>/dev/null; then
        firewall-cmd --permanent --remove-rich-rule="$rule" 2>/dev/null && \
            ok "Eliminada rich rule: ...$(echo "$rule" | grep -oP 'port="\K[^"]+' | head -1)..." && \
            ((REMOVED++)) || true
    else
        info "No encontrada (ya limpia): ...$(echo "$rule" | grep -oP 'port="\K[^"]+' | head -1)..."
    fi
done

if [[ $REMOVED -gt 0 ]]; then
    firewall-cmd --reload 2>/dev/null && ok "firewalld recargado" || warn "Error al recargar firewalld"
else
    info "No había rich rules inefectivas que limpiar"
fi

# ============================================================
# PASO 5: Verificación
# ============================================================
echo ""
echo "── Paso 5: Verificación ──"

# Verificar reglas en OUTPUT
echo ""
echo "  Cadena zona_output actual:"
nft list chain inet securizar_zonas zona_output | grep -E "192.168.1.1|blocklist" | while read -r line; do
    echo "    $line"
done

echo ""

# Test de conectividad (deben fallar)
ERRORS=0

echo "  Probando bloqueos:"
if curl --connect-timeout 2 -s -o /dev/null "http://${ROUTER_IP}" 2>/dev/null; then
    fail "HTTP al router (${ROUTER_IP}:80) - ACCESIBLE (no bloqueado)"
    ((ERRORS++))
else
    ok "HTTP al router (${ROUTER_IP}:80) - BLOQUEADO"
fi

if curl --connect-timeout 2 -sk -o /dev/null "https://${ROUTER_IP}" 2>/dev/null; then
    fail "HTTPS al router (${ROUTER_IP}:443) - ACCESIBLE (no bloqueado)"
    ((ERRORS++))
else
    ok "HTTPS al router (${ROUTER_IP}:443) - BLOQUEADO"
fi

if curl --connect-timeout 2 -s -o /dev/null "http://${ROUTER_IP}:8080" 2>/dev/null; then
    fail "HNAP al router (${ROUTER_IP}:8080) - ACCESIBLE (no bloqueado)"
    ((ERRORS++))
else
    ok "HNAP al router (${ROUTER_IP}:8080) - BLOQUEADO"
fi

if dig +time=2 +tries=1 "@${ROUTER_IP}" google.com &>/dev/null; then
    fail "DNS al router (${ROUTER_IP}:53) - ACCESIBLE (no bloqueado)"
    ((ERRORS++))
else
    ok "DNS al router (${ROUTER_IP}:53) - BLOQUEADO"
fi

# Verificar que el tráfico legítimo sigue funcionando
echo ""
echo "  Probando tráfico legítimo:"
if dig +time=3 +tries=1 @1.1.1.1 google.com &>/dev/null; then
    ok "DNS a 1.1.1.1 - FUNCIONA"
else
    warn "DNS a 1.1.1.1 - no responde (puede ser VPN/red)"
fi

if curl --connect-timeout 3 -s -o /dev/null "https://www.google.com" 2>/dev/null; then
    ok "HTTPS saliente - FUNCIONA"
else
    warn "HTTPS saliente - no responde (puede ser VPN/red)"
fi

# ============================================================
# Resumen
# ============================================================
echo ""
echo "============================================================"
if [[ $ERRORS -eq 0 ]]; then
    echo -e " ${GREEN}CORRECCIÓN COMPLETADA EXITOSAMENTE${NC}"
else
    echo -e " ${RED}COMPLETADO CON ${ERRORS} VERIFICACIONES FALLIDAS${NC}"
fi
echo ""
echo " Backups en: $BACKUP_DIR"
echo "============================================================"
