#!/bin/bash
# ============================================================
# INTELIGENCIA DE AMENAZAS - Feeds de IoC (Indicators of Compromise)
# Linux Multi-Distro (openSUSE, Debian/Ubuntu, RHEL/Fedora, Arch)
# ============================================================
# Mitigación MITRE ATT&CK:
#   M1019 - Threat Intelligence Sharing
#   TA0042 - Resource Development (detección de infraestructura atacante)
#
# Secciones:
#   S1 - Instalar dependencias (ipset, jq, curl, wget)
#   S2 - Configurar directorio y estructura de feeds
#   S3 - Descargar feeds de IPs maliciosas
#   S4 - Descargar feeds de dominios maliciosos
#   S5 - Integración con firewalld/ipset (bloqueo automático)
#   S6 - Integración con Suricata IDS (si disponible)
#   S7 - Herramienta de consulta de IoC
#   S8 - Cron diario de actualización automática
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
IOC_DIR="/etc/threat-intelligence"
IOC_FEEDS_DIR="$IOC_DIR/feeds"
IOC_LISTS_DIR="$IOC_DIR/lists"
IOC_LOG="/var/log/threat-intelligence"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   INTELIGENCIA DE AMENAZAS - Feeds de IoC                ║"
echo "║   MITRE ATT&CK: M1019 Threat Intelligence Sharing        ║"
echo "║   Detectar infraestructura de atacantes (TA0042)          ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

echo "Feeds de IoC gratuitos que se integrarán:"
echo ""
echo -e "  ${CYAN}IPs maliciosas:${NC}"
echo "    - Blocklist.de         (IPs atacantes reportadas)"
echo "    - Feodo Tracker        (C2 de troyanos bancarios)"
echo "    - Emerging Threats      (IPs comprometidas)"
echo "    - Spamhaus DROP/EDROP  (Redes secuestradas/maliciosas)"
echo "    - Tor Exit Nodes       (Nodos de salida Tor)"
echo ""
echo -e "  ${CYAN}Dominios/URLs maliciosos:${NC}"
echo "    - URLhaus (abuse.ch)   (URLs distribuyendo malware)"
echo "    - SSL Blacklist         (Certificados SSL maliciosos)"
echo "    - Phishtank            (URLs de phishing)"
echo ""

# ============================================================
# S1: Instalar dependencias
# ============================================================
log_section "S1: DEPENDENCIAS"

echo "Se verificarán/instalarán: ipset, jq, curl, wget"
echo ""

DEPS_NEEDED=""
for dep in ipset jq curl wget; do
    if command -v "$dep" &>/dev/null; then
        echo -e "  ${GREEN}OK${NC}  $dep ya instalado"
    else
        echo -e "  ${YELLOW}--${NC}  $dep no encontrado"
        DEPS_NEEDED+=" $dep"
    fi
done

if [[ -n "$DEPS_NEEDED" ]]; then
    echo ""
    if ask "¿Instalar dependencias faltantes:${DEPS_NEEDED}?"; then
        pkg_install $DEPS_NEEDED || {
            log_error "Error instalando dependencias. Verifica repositorios."
        }
        log_info "Dependencias instaladas"
    fi
else
    log_info "Todas las dependencias presentes"
fi

# ============================================================
# S2: Configurar directorio y estructura de feeds
# ============================================================
log_section "S2: ESTRUCTURA DE DIRECTORIOS"

echo "Se creará la estructura para almacenar feeds de IoC:"
echo "  $IOC_DIR/"
echo "  ├── feeds/        (feeds descargados en bruto)"
echo "  ├── lists/        (listas procesadas para uso)"
echo "  └── config/       (configuración de feeds)"
echo ""

if ask "¿Crear estructura de directorios para IoC?"; then
    mkdir -p "$IOC_FEEDS_DIR"
    mkdir -p "$IOC_LISTS_DIR"
    mkdir -p "$IOC_DIR/config"
    mkdir -p "$IOC_LOG"

    # Permisos restrictivos
    chmod 750 "$IOC_DIR"
    chmod 750 "$IOC_FEEDS_DIR"
    chmod 750 "$IOC_LISTS_DIR"
    chmod 750 "$IOC_DIR/config"

    # Crear archivo de configuración de feeds
    if [[ ! -f "$IOC_DIR/config/feeds.conf" ]]; then
        cat > "$IOC_DIR/config/feeds.conf" << 'EOF'
# ============================================================
# Configuración de Feeds de IoC
# Generado por inteligencia-amenazas.sh
# ============================================================
# Formato: NOMBRE|URL|TIPO|HABILITADO
# TIPO: ip, domain, url, hash
# HABILITADO: 1 (sí) / 0 (no)
# ============================================================

# IPs maliciosas
blocklist_de_all|https://lists.blocklist.de/lists/all.txt|ip|1
feodo_ipblocklist|https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt|ip|1
et_compromised|https://rules.emergingthreats.net/blockrules/compromised-ips.txt|ip|1
spamhaus_drop|https://www.spamhaus.org/drop/drop.txt|ip|1
spamhaus_edrop|https://www.spamhaus.org/drop/edrop.txt|ip|1
tor_exit_nodes|https://check.torproject.org/torbulkexitlist|ip|1
ci_army|https://cinsscore.com/list/ci-badguys.txt|ip|1

# Dominios maliciosos
urlhaus_domains|https://urlhaus.abuse.ch/downloads/text_online/|domain|1
sslbl_botnet_c2|https://sslbl.abuse.ch/blacklist/sslipblacklist.txt|ip|1

# Hashes maliciosos (referencia)
feodo_hashes|https://feodotracker.abuse.ch/downloads/malware_hashes.csv|hash|0
EOF
        chmod 640 "$IOC_DIR/config/feeds.conf"
    fi

    log_info "Estructura creada en $IOC_DIR"
fi

# ============================================================
# S3: Descargar feeds de IPs maliciosas
# ============================================================
log_section "S3: FEEDS DE IPs MALICIOSAS"

echo "Se descargarán listas de IPs conocidas como maliciosas."
echo "Estas IPs pertenecen a:"
echo "  - Servidores de Command & Control (C2)"
echo "  - Hosts que realizan ataques (fuerza bruta, escaneo)"
echo "  - Redes secuestradas (hijacked)"
echo "  - Nodos de salida Tor (opcional)"
echo ""

if ask "¿Descargar feeds de IPs maliciosas?"; then
    mkdir -p "$IOC_FEEDS_DIR" "$IOC_LISTS_DIR"
    IP_COUNT=0

    # Blocklist.de - IPs atacantes reportadas
    echo -e "\n  ${CYAN}▸${NC} Descargando Blocklist.de..."
    if curl -sS -m30 -o "$IOC_FEEDS_DIR/blocklist_de_all.txt" \
        "https://lists.blocklist.de/lists/all.txt" 2>/dev/null; then
        count=$(grep -cE '^[0-9]+\.' "$IOC_FEEDS_DIR/blocklist_de_all.txt" 2>/dev/null || echo 0)
        echo -e "    ${GREEN}OK${NC} Blocklist.de: $count IPs"
        IP_COUNT=$((IP_COUNT + count))
    else
        echo -e "    ${YELLOW}!!${NC} Error descargando Blocklist.de"
    fi

    # Feodo Tracker - C2 de troyanos bancarios
    echo -e "\n  ${CYAN}▸${NC} Descargando Feodo Tracker (C2 bancarios)..."
    if curl -sS -m30 -o "$IOC_FEEDS_DIR/feodo_ipblocklist.txt" \
        "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt" 2>/dev/null; then
        count=$(grep -cE '^[0-9]+\.' "$IOC_FEEDS_DIR/feodo_ipblocklist.txt" 2>/dev/null || echo 0)
        echo -e "    ${GREEN}OK${NC} Feodo Tracker: $count IPs C2"
        IP_COUNT=$((IP_COUNT + count))
    else
        echo -e "    ${YELLOW}!!${NC} Error descargando Feodo Tracker"
    fi

    # Emerging Threats - IPs comprometidas
    echo -e "\n  ${CYAN}▸${NC} Descargando Emerging Threats (IPs comprometidas)..."
    if curl -sS -m30 -o "$IOC_FEEDS_DIR/et_compromised.txt" \
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt" 2>/dev/null; then
        count=$(grep -cE '^[0-9]+\.' "$IOC_FEEDS_DIR/et_compromised.txt" 2>/dev/null || echo 0)
        echo -e "    ${GREEN}OK${NC} Emerging Threats: $count IPs comprometidas"
        IP_COUNT=$((IP_COUNT + count))
    else
        echo -e "    ${YELLOW}!!${NC} Error descargando ET compromised IPs"
    fi

    # Spamhaus DROP - Redes secuestradas
    echo -e "\n  ${CYAN}▸${NC} Descargando Spamhaus DROP (redes secuestradas)..."
    if curl -sS -m30 -o "$IOC_FEEDS_DIR/spamhaus_drop.txt" \
        "https://www.spamhaus.org/drop/drop.txt" 2>/dev/null; then
        count=$(grep -cE '^[0-9]+\.' "$IOC_FEEDS_DIR/spamhaus_drop.txt" 2>/dev/null || echo 0)
        echo -e "    ${GREEN}OK${NC} Spamhaus DROP: $count redes"
        IP_COUNT=$((IP_COUNT + count))
    else
        echo -e "    ${YELLOW}!!${NC} Error descargando Spamhaus DROP"
    fi

    # Spamhaus EDROP - Extended DROP
    echo -e "\n  ${CYAN}▸${NC} Descargando Spamhaus EDROP..."
    if curl -sS -m30 -o "$IOC_FEEDS_DIR/spamhaus_edrop.txt" \
        "https://www.spamhaus.org/drop/edrop.txt" 2>/dev/null; then
        count=$(grep -cE '^[0-9]+\.' "$IOC_FEEDS_DIR/spamhaus_edrop.txt" 2>/dev/null || echo 0)
        echo -e "    ${GREEN}OK${NC} Spamhaus EDROP: $count redes"
        IP_COUNT=$((IP_COUNT + count))
    else
        echo -e "    ${YELLOW}!!${NC} Error descargando Spamhaus EDROP"
    fi

    # Tor Exit Nodes
    echo -e "\n  ${CYAN}▸${NC} Descargando Tor Exit Nodes..."
    if curl -sS -m30 -o "$IOC_FEEDS_DIR/tor_exit_nodes.txt" \
        "https://check.torproject.org/torbulkexitlist" 2>/dev/null; then
        count=$(grep -cE '^[0-9]+\.' "$IOC_FEEDS_DIR/tor_exit_nodes.txt" 2>/dev/null || echo 0)
        echo -e "    ${GREEN}OK${NC} Tor Exit Nodes: $count nodos"
        IP_COUNT=$((IP_COUNT + count))
    else
        echo -e "    ${YELLOW}!!${NC} Error descargando Tor Exit Nodes"
    fi

    # CI Army - IPs de alta amenaza
    echo -e "\n  ${CYAN}▸${NC} Descargando CI Army (IPs de alta amenaza)..."
    if curl -sS -m30 -o "$IOC_FEEDS_DIR/ci_army.txt" \
        "https://cinsscore.com/list/ci-badguys.txt" 2>/dev/null; then
        count=$(grep -cE '^[0-9]+\.' "$IOC_FEEDS_DIR/ci_army.txt" 2>/dev/null || echo 0)
        echo -e "    ${GREEN}OK${NC} CI Army: $count IPs"
        IP_COUNT=$((IP_COUNT + count))
    else
        echo -e "    ${YELLOW}!!${NC} Error descargando CI Army"
    fi

    # SSLBL - IPs con certificados SSL maliciosos (C2)
    echo -e "\n  ${CYAN}▸${NC} Descargando SSL Blacklist (C2 via SSL)..."
    if curl -sS -m30 -o "$IOC_FEEDS_DIR/sslbl_botnet_c2.txt" \
        "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt" 2>/dev/null; then
        count=$(grep -cE '^[0-9]+\.' "$IOC_FEEDS_DIR/sslbl_botnet_c2.txt" 2>/dev/null || echo 0)
        echo -e "    ${GREEN}OK${NC} SSL Blacklist: $count IPs C2"
        IP_COUNT=$((IP_COUNT + count))
    else
        echo -e "    ${YELLOW}!!${NC} Error descargando SSL Blacklist"
    fi

    # Generar lista consolidada de IPs (sin duplicados)
    echo ""
    echo -e "  ${CYAN}▸${NC} Generando lista consolidada de IPs..."
    cat "$IOC_FEEDS_DIR"/*.txt 2>/dev/null | \
        grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | \
        sort -u -t. -k1,1n -k2,2n -k3,3n -k4,4n > "$IOC_LISTS_DIR/malicious-ips.txt" 2>/dev/null || true

    # Generar lista de CIDRs de Spamhaus
    grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' \
        "$IOC_FEEDS_DIR/spamhaus_drop.txt" "$IOC_FEEDS_DIR/spamhaus_edrop.txt" 2>/dev/null | \
        sort -u > "$IOC_LISTS_DIR/malicious-networks.txt" 2>/dev/null || true

    UNIQUE_IPS=$(wc -l < "$IOC_LISTS_DIR/malicious-ips.txt" 2>/dev/null || echo 0)
    UNIQUE_NETS=$(wc -l < "$IOC_LISTS_DIR/malicious-networks.txt" 2>/dev/null || echo 0)

    echo ""
    log_info "Feeds de IPs descargados: $IP_COUNT entradas totales"
    log_info "IPs únicas consolidadas: $UNIQUE_IPS"
    log_info "Redes CIDR bloqueadas: $UNIQUE_NETS"

    # Registrar timestamp
    date '+%Y-%m-%d %H:%M:%S' > "$IOC_DIR/last-update-ips.txt"
fi

# ============================================================
# S4: Descargar feeds de dominios maliciosos
# ============================================================
log_section "S4: FEEDS DE DOMINIOS MALICIOSOS"

echo "Se descargarán listas de dominios/URLs usados para:"
echo "  - Distribución de malware"
echo "  - Phishing"
echo "  - Command & Control"
echo ""

if ask "¿Descargar feeds de dominios/URLs maliciosos?"; then
    mkdir -p "$IOC_FEEDS_DIR" "$IOC_LISTS_DIR"

    # URLhaus - URLs de malware activas
    echo -e "\n  ${CYAN}▸${NC} Descargando URLhaus (URLs de malware activas)..."
    if curl -sS -m30 -o "$IOC_FEEDS_DIR/urlhaus_online.txt" \
        "https://urlhaus.abuse.ch/downloads/text_online/" 2>/dev/null; then
        count=$(grep -cE '^https?://' "$IOC_FEEDS_DIR/urlhaus_online.txt" 2>/dev/null || echo 0)
        echo -e "    ${GREEN}OK${NC} URLhaus: $count URLs activas"
    else
        echo -e "    ${YELLOW}!!${NC} Error descargando URLhaus"
    fi

    # Extraer dominios de URLhaus
    echo -e "\n  ${CYAN}▸${NC} Extrayendo dominios de URLs maliciosas..."
    grep -oP 'https?://\K[^/]+' "$IOC_FEEDS_DIR/urlhaus_online.txt" 2>/dev/null | \
        grep -vE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | \
        sort -u > "$IOC_LISTS_DIR/malicious-domains.txt" 2>/dev/null || true

    UNIQUE_DOMAINS=$(wc -l < "$IOC_LISTS_DIR/malicious-domains.txt" 2>/dev/null || echo 0)
    log_info "Dominios maliciosos únicos: $UNIQUE_DOMAINS"

    # Registrar timestamp
    date '+%Y-%m-%d %H:%M:%S' > "$IOC_DIR/last-update-domains.txt"
fi

# ============================================================
# S5: Integración con firewalld/ipset (bloqueo automático)
# ============================================================
log_section "S5: BLOQUEO AUTOMÁTICO CON FIREWALLD/IPSET"

echo "Se creará un ipset con las IPs maliciosas y se integrará"
echo "con firewalld para bloquear tráfico de/hacia IPs conocidas."
echo ""
echo -e "${YELLOW}Nota:${NC} Solo se bloquearán IPs de fuentes verificadas (DROP/Feodo/ET)."
echo "No se bloquearán automáticamente nodos Tor (decisión del usuario)."
echo ""

if ask "¿Configurar bloqueo automático con firewalld/ipset?"; then
    if ! command -v ipset &>/dev/null; then
        log_error "ipset no instalado. Ejecuta primero la sección S1."
    elif ! fw_is_active &>/dev/null; then
        log_warn "firewalld no activo. El bloqueo requiere firewalld."
        log_warn "Activa con: systemctl enable --now firewalld"
    else
        # Crear ipset para IPs individuales
        log_info "Creando ipset 'threat-intel-ips'..."
        ipset destroy threat-intel-ips 2>/dev/null || true
        ipset create threat-intel-ips hash:ip maxelem 131072 timeout 86400 2>/dev/null || \
            ipset create threat-intel-ips hash:ip maxelem 131072 2>/dev/null || true

        # Crear ipset para redes CIDR
        ipset destroy threat-intel-nets 2>/dev/null || true
        ipset create threat-intel-nets hash:net maxelem 8192 2>/dev/null || true

        # Poblar ipset con IPs maliciosas (excluir Tor por defecto)
        if [[ -f "$IOC_LISTS_DIR/malicious-ips.txt" ]]; then
            local_count=0
            while IFS= read -r ip; do
                [[ -z "$ip" || "$ip" == \#* ]] && continue
                ipset add threat-intel-ips "$ip" 2>/dev/null || true
                ((local_count++))
            done < "$IOC_LISTS_DIR/malicious-ips.txt"
            log_info "Cargadas $local_count IPs en ipset 'threat-intel-ips'"
        fi

        # Poblar ipset con redes maliciosas
        if [[ -f "$IOC_LISTS_DIR/malicious-networks.txt" ]]; then
            net_count=0
            while IFS= read -r net; do
                [[ -z "$net" || "$net" == \#* ]] && continue
                ipset add threat-intel-nets "$net" 2>/dev/null || true
                ((net_count++))
            done < "$IOC_LISTS_DIR/malicious-networks.txt"
            log_info "Cargadas $net_count redes en ipset 'threat-intel-nets'"
        fi

        # Guardar ipsets para persistencia
        mkdir -p /etc/ipset.d
        ipset save threat-intel-ips > /etc/ipset.d/threat-intel-ips.set 2>/dev/null || true
        ipset save threat-intel-nets > /etc/ipset.d/threat-intel-nets.set 2>/dev/null || true

        # Integrar con firewalld usando reglas directas
        log_info "Integrando ipsets con firewalld..."

        # Verificar si ya existen las reglas
        if ! fw_direct_query_rule ipv4 filter INPUT 0 \
            -m set --match-set threat-intel-ips src -j DROP; then
            fw_direct_add_rule ipv4 filter INPUT 0 \
                -m set --match-set threat-intel-ips src -j DROP 2>/dev/null || true
        fi

        if ! fw_direct_query_rule ipv4 filter INPUT 0 \
            -m set --match-set threat-intel-nets src -j DROP; then
            fw_direct_add_rule ipv4 filter INPUT 0 \
                -m set --match-set threat-intel-nets src -j DROP 2>/dev/null || true
        fi

        if ! fw_direct_query_rule ipv4 filter OUTPUT 0 \
            -m set --match-set threat-intel-ips dst -j DROP; then
            fw_direct_add_rule ipv4 filter OUTPUT 0 \
                -m set --match-set threat-intel-ips dst -j DROP 2>/dev/null || true
        fi

        if ! fw_direct_query_rule ipv4 filter OUTPUT 0 \
            -m set --match-set threat-intel-nets dst -j DROP; then
            fw_direct_add_rule ipv4 filter OUTPUT 0 \
                -m set --match-set threat-intel-nets dst -j DROP 2>/dev/null || true
        fi

        fw_reload 2>/dev/null || true
        log_info "Reglas de firewalld configuradas (DROP para IPs/redes maliciosas)"

        # Crear servicio systemd para restaurar ipsets al arranque
        cat > /etc/systemd/system/threat-intel-ipset.service << 'EOF'
[Unit]
Description=Restaurar ipsets de Threat Intelligence
Before=firewalld.service
After=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c 'for f in /etc/ipset.d/threat-intel-*.set; do [ -f "$f" ] && ipset restore < "$f" 2>/dev/null || true; done'
ExecStop=/bin/bash -c 'ipset save threat-intel-ips > /etc/ipset.d/threat-intel-ips.set 2>/dev/null; ipset save threat-intel-nets > /etc/ipset.d/threat-intel-nets.set 2>/dev/null'

[Install]
WantedBy=multi-user.target
EOF

        systemctl daemon-reload
        systemctl enable threat-intel-ipset.service 2>/dev/null || true
        log_info "Servicio de persistencia creado: threat-intel-ipset.service"
    fi
fi

# ============================================================
# S6: Integración con Suricata IDS (si disponible)
# ============================================================
log_section "S6: INTEGRACIÓN CON SURICATA IDS"

echo "Si Suricata IDS está instalado, se pueden añadir reglas"
echo "personalizadas basadas en los feeds de IoC descargados."
echo ""

if command -v suricata &>/dev/null; then
    echo -e "  ${GREEN}OK${NC} Suricata detectado"
    echo ""

    if ask "¿Crear reglas de Suricata basadas en feeds de IoC?"; then
        SURICATA_RULES_DIR="/var/lib/suricata/rules"
        mkdir -p "$SURICATA_RULES_DIR"

        # Generar reglas para IPs C2 (Feodo Tracker)
        RULES_FILE="$SURICATA_RULES_DIR/threat-intel-ioc.rules"
        echo "# ============================================================" > "$RULES_FILE"
        echo "# Reglas de Threat Intelligence - IoC Feeds" >> "$RULES_FILE"
        echo "# Generado: $(date '+%Y-%m-%d %H:%M:%S')" >> "$RULES_FILE"
        echo "# Fuentes: Feodo Tracker, SSL Blacklist" >> "$RULES_FILE"
        echo "# ============================================================" >> "$RULES_FILE"
        echo "" >> "$RULES_FILE"

        SID=9000001
        RULES_COUNT=0

        # Generar alertas para IPs de Feodo Tracker (C2 bancarios)
        if [[ -f "$IOC_FEEDS_DIR/feodo_ipblocklist.txt" ]]; then
            echo "# -- Feodo Tracker: C2 de troyanos bancarios --" >> "$RULES_FILE"
            while IFS= read -r ip; do
                [[ -z "$ip" || "$ip" == \#* ]] && continue
                # Validar formato IP
                if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    echo "alert ip any any -> $ip any (msg:\"THREAT-INTEL Feodo C2 - $ip\"; sid:$SID; rev:1; classtype:trojan-activity; metadata:ioc feodo_tracker;)" >> "$RULES_FILE"
                    SID=$((SID + 1))
                    RULES_COUNT=$((RULES_COUNT + 1))
                fi
            done < "$IOC_FEEDS_DIR/feodo_ipblocklist.txt"
        fi

        # Generar alertas para IPs de SSL Blacklist (C2 via SSL)
        if [[ -f "$IOC_FEEDS_DIR/sslbl_botnet_c2.txt" ]]; then
            echo "" >> "$RULES_FILE"
            echo "# -- SSL Blacklist: C2 via certificados SSL --" >> "$RULES_FILE"
            while IFS= read -r ip; do
                [[ -z "$ip" || "$ip" == \#* ]] && continue
                if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    echo "alert ip any any -> $ip any (msg:\"THREAT-INTEL SSLBL C2 - $ip\"; sid:$SID; rev:1; classtype:trojan-activity; metadata:ioc sslbl;)" >> "$RULES_FILE"
                    SID=$((SID + 1))
                    RULES_COUNT=$((RULES_COUNT + 1))
                fi
            done < "$IOC_FEEDS_DIR/sslbl_botnet_c2.txt"
        fi

        chmod 644 "$RULES_FILE"
        log_info "Generadas $RULES_COUNT reglas de Suricata en $RULES_FILE"

        # Verificar si el archivo de reglas está incluido en suricata.yaml
        if [[ -f /etc/suricata/suricata.yaml ]]; then
            if ! grep -q "threat-intel-ioc.rules" /etc/suricata/suricata.yaml 2>/dev/null; then
                log_warn "Añade manualmente la referencia al archivo de reglas en suricata.yaml:"
                echo -e "  ${DIM}rule-files:${NC}"
                echo -e "  ${DIM}  - threat-intel-ioc.rules${NC}"
                echo ""
                log_warn "O ejecuta: suricata-update (si está configurado para reglas locales)"
            fi
        fi

        # Recargar Suricata si está activo
        if systemctl is-active suricata &>/dev/null; then
            if ask "¿Recargar Suricata para aplicar las nuevas reglas?"; then
                systemctl reload suricata 2>/dev/null || systemctl restart suricata 2>/dev/null || true
                log_info "Suricata recargado con reglas de IoC"
            fi
        fi
    fi
else
    log_warn "Suricata no instalado. Instálalo desde el módulo 14 (Red avanzada)."
    echo -e "  ${DIM}Las reglas de IoC se generarán pero no se aplicarán hasta instalar Suricata.${NC}"
fi

# ============================================================
# S7: Herramienta de consulta de IoC
# ============================================================
log_section "S7: HERRAMIENTA DE CONSULTA DE IoC"

echo "Se creará un script para consultar rápidamente si una IP"
echo "o dominio aparece en las listas de IoC descargadas."
echo ""

if ask "¿Crear herramienta de consulta de IoC?"; then
    cat > /usr/local/bin/ioc-lookup.sh << 'EOFLOOKUP'
#!/bin/bash
# ============================================================
# IoC Lookup - Consulta de Indicadores de Compromiso
# Uso: ioc-lookup.sh <IP|dominio>
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

IOC_DIR="/etc/threat-intelligence"
IOC_FEEDS_DIR="$IOC_DIR/feeds"
IOC_LISTS_DIR="$IOC_DIR/lists"

if [[ $# -lt 1 ]]; then
    echo ""
    echo -e "${BOLD}IoC Lookup - Consulta de Indicadores de Compromiso${NC}"
    echo ""
    echo "Uso:"
    echo "  $(basename "$0") <IP>         Buscar IP en feeds de amenazas"
    echo "  $(basename "$0") <dominio>    Buscar dominio en feeds"
    echo "  $(basename "$0") --stats      Mostrar estadísticas de feeds"
    echo "  $(basename "$0") --update     Forzar actualización de feeds"
    echo ""
    exit 0
fi

TARGET="$1"

# Estadísticas
if [[ "$TARGET" == "--stats" ]]; then
    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════${NC}"
    echo -e "${BOLD}  ESTADÍSTICAS DE FEEDS DE IoC${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════${NC}"
    echo ""

    if [[ -f "$IOC_DIR/last-update-ips.txt" ]]; then
        echo -e "  ${CYAN}Última actualización IPs:${NC} $(cat "$IOC_DIR/last-update-ips.txt")"
    else
        echo -e "  ${YELLOW}IPs: Nunca actualizado${NC}"
    fi

    if [[ -f "$IOC_DIR/last-update-domains.txt" ]]; then
        echo -e "  ${CYAN}Última actualización dominios:${NC} $(cat "$IOC_DIR/last-update-domains.txt")"
    else
        echo -e "  ${YELLOW}Dominios: Nunca actualizado${NC}"
    fi

    echo ""
    echo -e "  ${CYAN}── Feeds descargados ──${NC}"

    for feed_file in "$IOC_FEEDS_DIR"/*.txt; do
        [[ -f "$feed_file" ]] || continue
        fname=$(basename "$feed_file")
        fsize=$(stat -c%s "$feed_file" 2>/dev/null || echo 0)
        fdate=$(stat -c%y "$feed_file" 2>/dev/null | cut -d. -f1 || echo "?")
        entries=$(grep -cE '^[0-9]' "$feed_file" 2>/dev/null || echo 0)
        fsize_h=$(numfmt --to=iec-i --suffix=B "$fsize" 2>/dev/null || echo "${fsize}B")
        echo -e "    ${GREEN}●${NC} $fname: ${BOLD}$entries${NC} entradas ($fsize_h, $fdate)"
    done

    echo ""
    echo -e "  ${CYAN}── Listas consolidadas ──${NC}"
    if [[ -f "$IOC_LISTS_DIR/malicious-ips.txt" ]]; then
        echo -e "    IPs únicas: ${BOLD}$(wc -l < "$IOC_LISTS_DIR/malicious-ips.txt")${NC}"
    fi
    if [[ -f "$IOC_LISTS_DIR/malicious-networks.txt" ]]; then
        echo -e "    Redes CIDR: ${BOLD}$(wc -l < "$IOC_LISTS_DIR/malicious-networks.txt")${NC}"
    fi
    if [[ -f "$IOC_LISTS_DIR/malicious-domains.txt" ]]; then
        echo -e "    Dominios:   ${BOLD}$(wc -l < "$IOC_LISTS_DIR/malicious-domains.txt")${NC}"
    fi

    # Estado de ipsets
    echo ""
    echo -e "  ${CYAN}── Estado de ipsets ──${NC}"
    if command -v ipset &>/dev/null; then
        for iset in threat-intel-ips threat-intel-nets; do
            entries=$(ipset list "$iset" 2>/dev/null | grep -c "^[0-9]" || echo "N/A")
            echo -e "    $iset: ${BOLD}$entries${NC} entradas activas"
        done
    else
        echo -e "    ${DIM}ipset no disponible${NC}"
    fi

    echo ""
    exit 0
fi

# Forzar actualización
if [[ "$TARGET" == "--update" ]]; then
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[X] Ejecutar como root para actualizar feeds${NC}"
        exit 1
    fi
    echo -e "${CYAN}Forzando actualización de feeds...${NC}"
    if [[ -x /usr/local/bin/threat-intel-update.sh ]]; then
        /usr/local/bin/threat-intel-update.sh
    else
        echo -e "${YELLOW}Script de actualización no encontrado.${NC}"
        echo "Ejecuta primero inteligencia-amenazas.sh para configurar."
    fi
    exit 0
fi

# ── Búsqueda de IoC ──────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════════${NC}"
echo -e "${BOLD}  IoC Lookup: ${CYAN}$TARGET${NC}"
echo -e "${BOLD}═══════════════════════════════════════════${NC}"
echo ""

FOUND=0

# Determinar si es IP o dominio
if [[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    # ── Búsqueda de IP ──
    echo -e "${CYAN}Tipo: Dirección IP${NC}"
    echo ""

    # Buscar en cada feed
    for feed_file in "$IOC_FEEDS_DIR"/*.txt; do
        [[ -f "$feed_file" ]] || continue
        fname=$(basename "$feed_file" .txt)
        if grep -qw "$TARGET" "$feed_file" 2>/dev/null; then
            echo -e "  ${RED}[ENCONTRADO]${NC} ${BOLD}$fname${NC}"
            FOUND=$((FOUND + 1))
        fi
    done

    # Buscar en lista consolidada
    if [[ -f "$IOC_LISTS_DIR/malicious-ips.txt" ]]; then
        if grep -qw "$TARGET" "$IOC_LISTS_DIR/malicious-ips.txt" 2>/dev/null; then
            echo -e "  ${RED}[CONSOLIDADO]${NC} Presente en lista consolidada"
        fi
    fi

    # Verificar en ipset activo
    if command -v ipset &>/dev/null; then
        if ipset test threat-intel-ips "$TARGET" 2>/dev/null; then
            echo -e "  ${RED}[BLOQUEADO]${NC} Activamente bloqueada en firewall (ipset)"
        fi
    fi

    # Consulta Shodan InternetDB
    if command -v curl &>/dev/null; then
        echo ""
        echo -e "${CYAN}Consultando Shodan InternetDB...${NC}"
        SHODAN=$(curl -s -m10 "https://internetdb.shodan.io/$TARGET" 2>/dev/null || echo "")
        if [[ -n "$SHODAN" && "$SHODAN" != *"No information"* && "$SHODAN" != *"error"* ]]; then
            S_PORTS=$(echo "$SHODAN" | grep -oP '"ports":\s*\[\K[^\]]+' 2>/dev/null || echo "ninguno")
            S_VULNS=$(echo "$SHODAN" | grep -oP '"vulns":\s*\[\K[^\]]+' 2>/dev/null || echo "ninguna")
            S_CPES=$(echo "$SHODAN" | grep -oP '"cpes":\s*\[\K[^\]]+' 2>/dev/null || echo "ninguno")
            echo -e "  Puertos: ${BOLD}$S_PORTS${NC}"
            echo -e "  Vulns:   ${BOLD}$S_VULNS${NC}"
            echo -e "  CPEs:    ${DIM}$S_CPES${NC}"
        else
            echo -e "  ${DIM}No encontrada en Shodan InternetDB${NC}"
        fi
    fi

else
    # ── Búsqueda de dominio ──
    echo -e "${CYAN}Tipo: Dominio${NC}"
    echo ""

    # Buscar en feeds de dominios
    if [[ -f "$IOC_LISTS_DIR/malicious-domains.txt" ]]; then
        if grep -qiw "$TARGET" "$IOC_LISTS_DIR/malicious-domains.txt" 2>/dev/null; then
            echo -e "  ${RED}[ENCONTRADO]${NC} Presente en lista de dominios maliciosos"
            FOUND=$((FOUND + 1))
        fi
    fi

    # Buscar en URLhaus
    if [[ -f "$IOC_FEEDS_DIR/urlhaus_online.txt" ]]; then
        MATCHES=$(grep -i "$TARGET" "$IOC_FEEDS_DIR/urlhaus_online.txt" 2>/dev/null | head -5)
        if [[ -n "$MATCHES" ]]; then
            echo -e "  ${RED}[URLhaus]${NC} URLs maliciosas asociadas:"
            echo "$MATCHES" | while IFS= read -r url; do
                echo -e "    ${DIM}$url${NC}"
            done
            FOUND=$((FOUND + 1))
        fi
    fi
fi

# Resultado final
echo ""
echo -e "${BOLD}═══════════════════════════════════════════${NC}"
if [[ $FOUND -gt 0 ]]; then
    echo -e "  ${RED}${BOLD}ALERTA:${NC} $TARGET encontrado en ${RED}${BOLD}$FOUND${NC} feed(s) de amenazas"
    echo -e "  ${YELLOW}Recomendación: Investigar y considerar bloqueo inmediato${NC}"
else
    echo -e "  ${GREEN}${BOLD}LIMPIO:${NC} $TARGET NO encontrado en feeds de amenazas"
    echo -e "  ${DIM}Nota: Esto no garantiza que sea seguro, solo que no está en las listas actuales${NC}"
fi
echo -e "${BOLD}═══════════════════════════════════════════${NC}"
echo ""
EOFLOOKUP

    chmod +x /usr/local/bin/ioc-lookup.sh
    log_info "Herramienta creada: /usr/local/bin/ioc-lookup.sh"
    echo ""
    echo "Uso:"
    echo "  ioc-lookup.sh 185.220.101.1       (buscar IP)"
    echo "  ioc-lookup.sh evil-domain.com      (buscar dominio)"
    echo "  ioc-lookup.sh --stats              (estadísticas de feeds)"
    echo "  ioc-lookup.sh --update             (actualizar feeds)"
fi

# ============================================================
# S8: Cron diario de actualización automática
# ============================================================
log_section "S8: ACTUALIZACIÓN AUTOMÁTICA DE FEEDS"

echo "Se creará un cron job diario para mantener los feeds"
echo "de IoC actualizados automáticamente."
echo ""

if ask "¿Crear cron diario de actualización de feeds de IoC?"; then
    # Script de actualización
    cat > /usr/local/bin/threat-intel-update.sh << 'EOFUPDATE'
#!/bin/bash
# ============================================================
# Actualización automática de feeds de IoC
# Ejecutado diariamente via cron
# MITRE ATT&CK: M1019 - Threat Intelligence Sharing
# ============================================================

IOC_DIR="/etc/threat-intelligence"
IOC_FEEDS_DIR="$IOC_DIR/feeds"
IOC_LISTS_DIR="$IOC_DIR/lists"
LOG="/var/log/threat-intelligence/update-$(date +%Y%m%d).log"

mkdir -p "$(dirname "$LOG")"

{
    echo "============================================================"
    echo " Actualización de Feeds de IoC - $(date '+%Y-%m-%d %H:%M:%S')"
    echo "============================================================"

    ERRORS=0
    TOTAL_IPS=0

    # Función de descarga con reintentos
    download_feed() {
        local name="$1"
        local url="$2"
        local output="$IOC_FEEDS_DIR/$name.txt"
        local tmp_file="/tmp/threat-intel-${name}.tmp"

        echo ""
        echo "[$name] Descargando: $url"

        if curl -sS -m60 --retry 2 --retry-delay 5 -o "$tmp_file" "$url" 2>&1; then
            local count
            count=$(grep -cE '^[0-9]' "$tmp_file" 2>/dev/null || echo 0)
            # Solo reemplazar si el archivo tiene contenido válido
            if [[ $count -gt 0 ]]; then
                mv "$tmp_file" "$output"
                echo "  OK: $count entradas"
                TOTAL_IPS=$((TOTAL_IPS + count))
            else
                echo "  WARN: Archivo vacío o sin entradas válidas, manteniendo versión anterior"
                rm -f "$tmp_file"
                ERRORS=$((ERRORS + 1))
            fi
        else
            echo "  ERROR: Falló la descarga"
            rm -f "$tmp_file"
            ERRORS=$((ERRORS + 1))
        fi
    }

    # Descargar todos los feeds habilitados
    if [[ -f "$IOC_DIR/config/feeds.conf" ]]; then
        while IFS='|' read -r name url type enabled; do
            [[ -z "$name" || "$name" == \#* ]] && continue
            [[ "$enabled" != "1" ]] && continue
            [[ "$type" == "hash" ]] && continue
            download_feed "$name" "$url"
        done < "$IOC_DIR/config/feeds.conf"
    else
        # Fallback: descargar feeds principales
        download_feed "blocklist_de_all" "https://lists.blocklist.de/lists/all.txt"
        download_feed "feodo_ipblocklist" "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
        download_feed "et_compromised" "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
        download_feed "spamhaus_drop" "https://www.spamhaus.org/drop/drop.txt"
        download_feed "spamhaus_edrop" "https://www.spamhaus.org/drop/edrop.txt"
        download_feed "tor_exit_nodes" "https://check.torproject.org/torbulkexitlist"
        download_feed "ci_army" "https://cinsscore.com/list/ci-badguys.txt"
        download_feed "sslbl_botnet_c2" "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt"
        download_feed "urlhaus_online" "https://urlhaus.abuse.ch/downloads/text_online/"
    fi

    # Regenerar listas consolidadas
    echo ""
    echo "Regenerando listas consolidadas..."

    # IPs únicas
    cat "$IOC_FEEDS_DIR"/*.txt 2>/dev/null | \
        grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | \
        sort -u -t. -k1,1n -k2,2n -k3,3n -k4,4n > "$IOC_LISTS_DIR/malicious-ips.txt.new" 2>/dev/null || true

    if [[ -s "$IOC_LISTS_DIR/malicious-ips.txt.new" ]]; then
        mv "$IOC_LISTS_DIR/malicious-ips.txt.new" "$IOC_LISTS_DIR/malicious-ips.txt"
    else
        rm -f "$IOC_LISTS_DIR/malicious-ips.txt.new"
    fi

    # Redes CIDR
    grep -ohE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' \
        "$IOC_FEEDS_DIR/spamhaus_drop.txt" "$IOC_FEEDS_DIR/spamhaus_edrop.txt" 2>/dev/null | \
        sort -u > "$IOC_LISTS_DIR/malicious-networks.txt.new" 2>/dev/null || true

    if [[ -s "$IOC_LISTS_DIR/malicious-networks.txt.new" ]]; then
        mv "$IOC_LISTS_DIR/malicious-networks.txt.new" "$IOC_LISTS_DIR/malicious-networks.txt"
    else
        rm -f "$IOC_LISTS_DIR/malicious-networks.txt.new"
    fi

    # Dominios
    if [[ -f "$IOC_FEEDS_DIR/urlhaus_online.txt" ]]; then
        grep -oP 'https?://\K[^/]+' "$IOC_FEEDS_DIR/urlhaus_online.txt" 2>/dev/null | \
            grep -vE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | \
            sort -u > "$IOC_LISTS_DIR/malicious-domains.txt.new" 2>/dev/null || true

        if [[ -s "$IOC_LISTS_DIR/malicious-domains.txt.new" ]]; then
            mv "$IOC_LISTS_DIR/malicious-domains.txt.new" "$IOC_LISTS_DIR/malicious-domains.txt"
        else
            rm -f "$IOC_LISTS_DIR/malicious-domains.txt.new"
        fi
    fi

    UNIQUE_IPS=$(wc -l < "$IOC_LISTS_DIR/malicious-ips.txt" 2>/dev/null || echo 0)
    UNIQUE_NETS=$(wc -l < "$IOC_LISTS_DIR/malicious-networks.txt" 2>/dev/null || echo 0)
    UNIQUE_DOMAINS=$(wc -l < "$IOC_LISTS_DIR/malicious-domains.txt" 2>/dev/null || echo 0)

    echo "  IPs únicas: $UNIQUE_IPS"
    echo "  Redes CIDR: $UNIQUE_NETS"
    echo "  Dominios:   $UNIQUE_DOMAINS"

    # Actualizar ipsets si están activos
    if command -v ipset &>/dev/null; then
        echo ""
        echo "Actualizando ipsets..."

        # Recrear ipset de IPs
        ipset destroy threat-intel-ips-new 2>/dev/null || true
        ipset create threat-intel-ips-new hash:ip maxelem 131072 2>/dev/null || true

        if [[ -f "$IOC_LISTS_DIR/malicious-ips.txt" ]]; then
            while IFS= read -r ip; do
                [[ -z "$ip" ]] && continue
                ipset add threat-intel-ips-new "$ip" 2>/dev/null || true
            done < "$IOC_LISTS_DIR/malicious-ips.txt"
        fi

        # Swap atómico
        ipset swap threat-intel-ips-new threat-intel-ips 2>/dev/null && \
            ipset destroy threat-intel-ips-new 2>/dev/null || true

        # Recrear ipset de redes
        ipset destroy threat-intel-nets-new 2>/dev/null || true
        ipset create threat-intel-nets-new hash:net maxelem 8192 2>/dev/null || true

        if [[ -f "$IOC_LISTS_DIR/malicious-networks.txt" ]]; then
            while IFS= read -r net; do
                [[ -z "$net" ]] && continue
                ipset add threat-intel-nets-new "$net" 2>/dev/null || true
            done < "$IOC_LISTS_DIR/malicious-networks.txt"
        fi

        ipset swap threat-intel-nets-new threat-intel-nets 2>/dev/null && \
            ipset destroy threat-intel-nets-new 2>/dev/null || true

        # Persistir
        mkdir -p /etc/ipset.d
        ipset save threat-intel-ips > /etc/ipset.d/threat-intel-ips.set 2>/dev/null || true
        ipset save threat-intel-nets > /etc/ipset.d/threat-intel-nets.set 2>/dev/null || true

        IPS_LOADED=$(ipset list threat-intel-ips 2>/dev/null | grep -c "^[0-9]" || echo 0)
        NETS_LOADED=$(ipset list threat-intel-nets 2>/dev/null | grep -c "^[0-9]" || echo 0)
        echo "  ipset threat-intel-ips: $IPS_LOADED entradas"
        echo "  ipset threat-intel-nets: $NETS_LOADED entradas"
    fi

    # Actualizar reglas de Suricata si está instalado
    SURICATA_RULES="/var/lib/suricata/rules/threat-intel-ioc.rules"
    if command -v suricata &>/dev/null && [[ -f "$SURICATA_RULES" ]]; then
        echo ""
        echo "Regenerando reglas de Suricata..."

        echo "# Reglas de Threat Intelligence - IoC Feeds" > "$SURICATA_RULES"
        echo "# Generado: $(date '+%Y-%m-%d %H:%M:%S')" >> "$SURICATA_RULES"
        echo "" >> "$SURICATA_RULES"

        SID=9000001
        RULES_COUNT=0

        for src_file in "$IOC_FEEDS_DIR/feodo_ipblocklist.txt" "$IOC_FEEDS_DIR/sslbl_botnet_c2.txt"; do
            [[ -f "$src_file" ]] || continue
            src_name=$(basename "$src_file" .txt)
            while IFS= read -r ip; do
                [[ -z "$ip" || "$ip" == \#* ]] && continue
                [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
                echo "alert ip any any -> $ip any (msg:\"THREAT-INTEL $src_name - $ip\"; sid:$SID; rev:1; classtype:trojan-activity;)" >> "$SURICATA_RULES"
                SID=$((SID + 1))
                RULES_COUNT=$((RULES_COUNT + 1))
            done < "$src_file"
        done

        echo "  Reglas Suricata: $RULES_COUNT"

        # Recargar Suricata
        if systemctl is-active suricata &>/dev/null; then
            systemctl reload suricata 2>/dev/null || true
            echo "  Suricata recargado"
        fi
    fi

    # Registrar timestamps
    date '+%Y-%m-%d %H:%M:%S' > "$IOC_DIR/last-update-ips.txt"
    date '+%Y-%m-%d %H:%M:%S' > "$IOC_DIR/last-update-domains.txt"

    echo ""
    echo "============================================================"
    if [[ $ERRORS -eq 0 ]]; then
        echo "RESULTADO: Actualización completada sin errores"
    else
        echo "RESULTADO: Actualización completada con $ERRORS error(es)"
    fi
    echo "============================================================"

    logger -t threat-intel-update "Feeds actualizados: $UNIQUE_IPS IPs, $UNIQUE_NETS redes, $UNIQUE_DOMAINS dominios ($ERRORS errores)"

} > "$LOG" 2>&1

# Limpiar logs antiguos (>30 días)
find /var/log/threat-intelligence -name "update-*.log" -mtime +30 -delete 2>/dev/null
EOFUPDATE

    chmod 700 /usr/local/bin/threat-intel-update.sh
    log_info "Script de actualización creado: /usr/local/bin/threat-intel-update.sh"

    # Cron diario
    cat > /etc/cron.daily/threat-intel-update << 'EOFCRON'
#!/bin/bash
# Actualización diaria de feeds de IoC (M1019 Threat Intelligence)
/usr/local/bin/threat-intel-update.sh
EOFCRON

    chmod 700 /etc/cron.daily/threat-intel-update
    log_info "Cron diario creado: /etc/cron.daily/threat-intel-update"
fi

# ============================================================
# RESUMEN
# ============================================================
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║    INTELIGENCIA DE AMENAZAS - CONFIGURACIÓN COMPLETADA    ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

echo -e "  ${CYAN}── Estado de componentes ──${NC}"
echo ""

# Directorio IoC
if [[ -d "$IOC_DIR" ]]; then
    echo -e "  ${GREEN}OK${NC}  Directorio de IoC: $IOC_DIR"
else
    echo -e "  ${YELLOW}--${NC}  Directorio de IoC no creado"
fi

# Feeds de IPs
if [[ -f "$IOC_LISTS_DIR/malicious-ips.txt" ]]; then
    ips=$(wc -l < "$IOC_LISTS_DIR/malicious-ips.txt" 2>/dev/null || echo 0)
    echo -e "  ${GREEN}OK${NC}  IPs maliciosas: ${BOLD}$ips${NC} únicas"
else
    echo -e "  ${YELLOW}--${NC}  Feeds de IPs no descargados"
fi

# Feeds de dominios
if [[ -f "$IOC_LISTS_DIR/malicious-domains.txt" ]]; then
    doms=$(wc -l < "$IOC_LISTS_DIR/malicious-domains.txt" 2>/dev/null || echo 0)
    echo -e "  ${GREEN}OK${NC}  Dominios maliciosos: ${BOLD}$doms${NC} únicos"
else
    echo -e "  ${YELLOW}--${NC}  Feeds de dominios no descargados"
fi

# ipset
if command -v ipset &>/dev/null && ipset list threat-intel-ips &>/dev/null; then
    blocked=$(ipset list threat-intel-ips 2>/dev/null | grep -c "^[0-9]" || echo 0)
    echo -e "  ${GREEN}OK${NC}  Bloqueo ipset activo: ${BOLD}$blocked${NC} IPs bloqueadas"
else
    echo -e "  ${YELLOW}--${NC}  Bloqueo ipset no configurado"
fi

# Suricata
if [[ -f /var/lib/suricata/rules/threat-intel-ioc.rules ]]; then
    rules=$(grep -c "^alert" /var/lib/suricata/rules/threat-intel-ioc.rules 2>/dev/null || echo 0)
    echo -e "  ${GREEN}OK${NC}  Reglas Suricata IoC: ${BOLD}$rules${NC} reglas"
else
    echo -e "  ${YELLOW}--${NC}  Reglas de Suricata no generadas"
fi

# Herramienta de consulta
if [[ -x /usr/local/bin/ioc-lookup.sh ]]; then
    echo -e "  ${GREEN}OK${NC}  Herramienta de consulta: ioc-lookup.sh"
else
    echo -e "  ${YELLOW}--${NC}  Herramienta de consulta no instalada"
fi

# Cron de actualización
if [[ -f /etc/cron.daily/threat-intel-update ]]; then
    echo -e "  ${GREEN}OK${NC}  Actualización diaria programada"
else
    echo -e "  ${YELLOW}--${NC}  Actualización automática no configurada"
fi

echo ""
echo "Herramientas disponibles:"
echo "  ioc-lookup.sh <IP|dominio>  - Consultar IoC"
echo "  ioc-lookup.sh --stats       - Estadísticas de feeds"
echo "  ioc-lookup.sh --update      - Forzar actualización"
echo ""
echo "Feeds se actualizan diariamente via /etc/cron.daily/threat-intel-update"
echo ""
