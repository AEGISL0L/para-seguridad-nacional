#!/bin/bash
# ============================================================
# seguridad-iot.sh — Módulo 64: Seguridad IoT
# ============================================================
# MQTT, CoAP, firmware, segmentación de dispositivos IoT
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/securizar-common.sh"
source "$SCRIPT_DIR/lib/securizar-distro.sh"
source "$SCRIPT_DIR/lib/securizar-pkg.sh"

CHANGES=()

show_changes_summary() {
    echo ""
    if [[ ${#CHANGES[@]} -eq 0 ]]; then
        log_info "No se realizaron cambios"
        return 0
    fi
    log_section "RESUMEN DE CAMBIOS"
    local i=1
    for change in "${CHANGES[@]}"; do
        log_info "  $i. $change"
        ((i++))
    done
    echo ""
    log_info "Total: ${#CHANGES[@]} cambios aplicados"
}

# ── Sección 1: Descubrimiento de dispositivos IoT ──
section_1() {
    log_section "1. Descubrimiento de dispositivos IoT"

    ask "¿Configurar descubrimiento automático de dispositivos IoT en la red?" || { log_skip "Descubrimiento IoT omitido"; return 0; }

    mkdir -p /var/log/securizar/iot /etc/securizar/iot

    cat > /usr/local/bin/securizar-iot-discovery.sh << 'EOFDISCOVERY'
#!/bin/bash
# ============================================================
# securizar-iot-discovery.sh — Descubrimiento de dispositivos IoT
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar/iot"
mkdir -p "$LOG_DIR"

FECHA=$(date +%Y%m%d)
INVENTORY="$LOG_DIR/iot-inventory-${FECHA}.json"
REPORT="$LOG_DIR/iot-discovery-${FECHA}.txt"

# Puertos comunes IoT
IOT_PORTS="80,443,1883,5683,8080,8443,8883,1900,5353,6668,9100,502,47808"

# Redes a escanear (autodetectar)
NETWORKS=()
while read -r net; do
    [[ -n "$net" ]] && NETWORKS+=("$net")
done < <(ip -4 route show scope link 2>/dev/null | awk '{print $1}' | grep -v '^169\.254')

if [[ ${#NETWORKS[@]} -eq 0 ]]; then
    echo "No se detectaron redes locales"
    exit 1
fi

{
echo "=========================================="
echo " Descubrimiento de dispositivos IoT"
echo " $(date) - $(hostname)"
echo "=========================================="
echo ""

# Inicializar JSON
echo "{" > "$INVENTORY"
echo "  \"timestamp\": \"$(date -Iseconds)\"," >> "$INVENTORY"
echo "  \"hostname\": \"$(hostname)\"," >> "$INVENTORY"
echo "  \"devices\": [" >> "$INVENTORY"

FIRST=true
TOTAL=0
IOT_COUNT=0

for NETWORK in "${NETWORKS[@]}"; do
    echo "=== Red: $NETWORK ==="
    echo ""

    # Método 1: ARP scan
    if command -v arp-scan &>/dev/null; then
        echo "--- arp-scan ---"
        while IFS=$'\t' read -r ip mac vendor; do
            [[ -z "$ip" || "$ip" == "Interface"* || "$ip" == "Starting"* || "$ip" == "Ending"* ]] && continue
            [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue

            echo "  $ip  $mac  ${vendor:-unknown}"

            # Detectar puertos IoT
            IOT_OPEN=""
            if command -v nmap &>/dev/null; then
                IOT_OPEN=$(nmap -sT -p "$IOT_PORTS" --open -T4 --max-retries 1 "$ip" 2>/dev/null | \
                           grep '^[0-9].*open' | awk '{print $1}' | tr '\n' ',' | sed 's/,$//')
            fi

            IS_IOT="false"
            if [[ -n "$IOT_OPEN" ]]; then
                # Tiene puertos IoT abiertos
                if echo "$IOT_OPEN" | grep -qE '1883|5683|8883|502|47808'; then
                    IS_IOT="true"
                    ((IOT_COUNT++))
                fi
            fi

            # Clasificación por vendor OUI
            VENDOR_LOWER=$(echo "${vendor:-}" | tr '[:upper:]' '[:lower:]')
            IOT_VENDORS="espressif|raspberry|arduino|tuya|shenzhen|sonoff|xiaomi|tp-link|hikvision|dahua|ring|nest|philips hue|wemo|belkin|broadlink|ezviz"
            if echo "$VENDOR_LOWER" | grep -qiE "$IOT_VENDORS"; then
                IS_IOT="true"
                if ! echo "$IOT_OPEN" | grep -qE '1883|5683|8883|502|47808'; then
                    ((IOT_COUNT++))
                fi
            fi

            # Añadir a JSON
            if $FIRST; then FIRST=false; else echo "," >> "$INVENTORY"; fi
            cat >> "$INVENTORY" << EOFJSON
    {
      "ip": "$ip",
      "mac": "$mac",
      "vendor": "${vendor:-unknown}",
      "iot_ports": "${IOT_OPEN:-none}",
      "is_iot": $IS_IOT
    }
EOFJSON
            ((TOTAL++))
        done < <(arp-scan "$NETWORK" 2>/dev/null | grep -E '^[0-9]+\.')

    # Método 2: nmap si no hay arp-scan
    elif command -v nmap &>/dev/null; then
        echo "--- nmap discovery ---"
        nmap -sn "$NETWORK" 2>/dev/null | grep -B2 'Host is up' | grep 'Nmap scan' | \
            awk '{print $5}' | while read -r ip; do
            [[ -z "$ip" ]] && continue
            echo "  Host: $ip"

            MAC=$(arp -n "$ip" 2>/dev/null | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -1 || echo "unknown")

            if $FIRST; then FIRST=false; else echo "," >> "$INVENTORY"; fi
            cat >> "$INVENTORY" << EOFJSON2
    {
      "ip": "$ip",
      "mac": "$MAC",
      "vendor": "unknown",
      "is_iot": false
    }
EOFJSON2
            ((TOTAL++))
        done

    else
        echo "[WARN] Ni arp-scan ni nmap disponibles"
        echo "Instalar: nmap o arp-scan"

        # Fallback: tabla ARP
        echo ""
        echo "--- Tabla ARP (fallback) ---"
        ip neigh show 2>/dev/null | while read -r line; do
            IP=$(echo "$line" | awk '{print $1}')
            MAC=$(echo "$line" | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' || echo "unknown")
            STATE=$(echo "$line" | awk '{print $NF}')
            [[ "$STATE" == "FAILED" ]] && continue
            echo "  $IP  $MAC  $STATE"
            ((TOTAL++))
        done
    fi

    echo ""
done

# Cerrar JSON
echo "" >> "$INVENTORY"
echo "  ]," >> "$INVENTORY"
echo "  \"total_devices\": $TOTAL," >> "$INVENTORY"
echo "  \"iot_devices\": $IOT_COUNT" >> "$INVENTORY"
echo "}" >> "$INVENTORY"

echo "=========================================="
echo " Resumen"
echo "=========================================="
echo " Total dispositivos: $TOTAL"
echo " Identificados como IoT: $IOT_COUNT"
echo " Inventario: $INVENTORY"
echo "=========================================="
} 2>&1 | tee "$REPORT"

# Retención 90 días
find "$LOG_DIR" -name 'iot-inventory-*.json' -mtime +90 -delete 2>/dev/null || true
find "$LOG_DIR" -name 'iot-discovery-*.txt' -mtime +90 -delete 2>/dev/null || true
EOFDISCOVERY
    chmod +x /usr/local/bin/securizar-iot-discovery.sh

    # Cron semanal
    cat > /etc/cron.weekly/securizar-iot-discovery << 'EOF'
#!/bin/bash
/usr/local/bin/securizar-iot-discovery.sh >> /var/log/securizar/iot/discovery-cron.log 2>&1
EOF
    chmod +x /etc/cron.weekly/securizar-iot-discovery

    log_change "Descubrimiento de dispositivos IoT configurado"
    CHANGES+=("Sección 1: Descubrimiento IoT con arp-scan/nmap y clasificación por vendor")
}

# ── Sección 2: Segmentación de red para IoT ──
section_2() {
    log_section "2. Segmentación de red para IoT"

    ask "¿Configurar reglas de firewall para segmentar red IoT?" || { log_skip "Segmentación IoT omitida"; return 0; }

    mkdir -p /etc/securizar/iot

    # Configuración de red IoT
    cat > /etc/securizar/iot/iot-network.conf << 'EOF'
# Securizar — Configuración de red IoT
# ======================================

# Subred IoT (VLAN o segmento dedicado)
IOT_SUBNET="192.168.100.0/24"

# Interfaz del segmento IoT (bridge, VLAN, etc.)
IOT_INTERFACE="br-iot"

# Puertos permitidos de IoT a Internet
IOT_ALLOWED_OUTBOUND_PORTS="443,8883,123"

# Puertos permitidos de IoT a LAN
IOT_ALLOWED_LAN_PORTS=""

# Permitir IoT a DNS local
IOT_ALLOW_DNS="true"

# Bloquear IoT-to-IoT (microsegmentación)
IOT_BLOCK_LATERAL="false"
EOF

    # Script de segmentación
    cat > /usr/local/bin/securizar-iot-segment.sh << 'EOFSEGMENT'
#!/bin/bash
# ============================================================
# securizar-iot-segment.sh — Reglas de firewall para red IoT
# ============================================================
set -euo pipefail

CONFIG="/etc/securizar/iot/iot-network.conf"

if [[ ! -f "$CONFIG" ]]; then
    echo "Error: $CONFIG no encontrado"
    exit 1
fi

source "$CONFIG"

ACTION="${1:-status}"
CHAIN="SECURIZAR_IOT"

case "$ACTION" in
    apply)
        echo "=== Aplicando segmentación IoT ==="
        echo ""
        echo "Subred IoT: $IOT_SUBNET"
        echo "Interfaz: $IOT_INTERFACE"
        echo ""

        # Verificar que iptables está disponible
        if ! command -v iptables &>/dev/null; then
            echo "Error: iptables no disponible"
            exit 1
        fi

        # Crear cadena dedicada
        iptables -N "$CHAIN" 2>/dev/null || iptables -F "$CHAIN"

        # Permitir tráfico establecido
        iptables -A "$CHAIN" -m state --state ESTABLISHED,RELATED -j ACCEPT

        # Permitir DNS si configurado
        if [[ "${IOT_ALLOW_DNS:-true}" == "true" ]]; then
            iptables -A "$CHAIN" -s "$IOT_SUBNET" -p udp --dport 53 -j ACCEPT
            iptables -A "$CHAIN" -s "$IOT_SUBNET" -p tcp --dport 53 -j ACCEPT
            echo "[OK] DNS permitido para IoT"
        fi

        # Puertos de IoT a Internet
        if [[ -n "${IOT_ALLOWED_OUTBOUND_PORTS:-}" ]]; then
            IFS=',' read -ra PORTS <<< "$IOT_ALLOWED_OUTBOUND_PORTS"
            for port in "${PORTS[@]}"; do
                iptables -A "$CHAIN" -s "$IOT_SUBNET" -p tcp --dport "$port" -j ACCEPT
                echo "[OK] IoT → Internet puerto $port/tcp permitido"
            done
        fi

        # Puertos de IoT a LAN
        if [[ -n "${IOT_ALLOWED_LAN_PORTS:-}" ]]; then
            IFS=',' read -ra PORTS <<< "$IOT_ALLOWED_LAN_PORTS"
            for port in "${PORTS[@]}"; do
                iptables -A "$CHAIN" -s "$IOT_SUBNET" -p tcp --dport "$port" -j ACCEPT
                echo "[OK] IoT → LAN puerto $port/tcp permitido"
            done
        fi

        # Bloquear IoT → LAN (todo lo demás)
        # Detectar subredes LAN
        while read -r lan_net; do
            [[ -z "$lan_net" ]] && continue
            [[ "$lan_net" == "$IOT_SUBNET" ]] && continue
            iptables -A "$CHAIN" -s "$IOT_SUBNET" -d "$lan_net" -j DROP
            echo "[OK] IoT → $lan_net BLOQUEADO"
        done < <(ip -4 route show scope link 2>/dev/null | awk '{print $1}')

        # Bloquear lateral si configurado
        if [[ "${IOT_BLOCK_LATERAL:-false}" == "true" ]]; then
            iptables -A "$CHAIN" -s "$IOT_SUBNET" -d "$IOT_SUBNET" -j DROP
            echo "[OK] IoT → IoT lateral BLOQUEADO"
        fi

        # Log de tráfico bloqueado
        iptables -A "$CHAIN" -s "$IOT_SUBNET" -j LOG --log-prefix "SECURIZAR_IOT_DROP: " --log-level 4
        iptables -A "$CHAIN" -s "$IOT_SUBNET" -j DROP

        # Insertar cadena en FORWARD
        iptables -D FORWARD -j "$CHAIN" 2>/dev/null || true
        iptables -I FORWARD 1 -j "$CHAIN"

        echo ""
        echo "Segmentación IoT aplicada."
        ;;

    remove)
        echo "=== Eliminando reglas de segmentación IoT ==="
        iptables -D FORWARD -j "$CHAIN" 2>/dev/null || true
        iptables -F "$CHAIN" 2>/dev/null || true
        iptables -X "$CHAIN" 2>/dev/null || true
        echo "Reglas eliminadas."
        ;;

    status)
        echo "=== Estado de segmentación IoT ==="
        echo ""
        if iptables -L "$CHAIN" -n -v 2>/dev/null; then
            echo ""
            echo "Cadena $CHAIN activa."
        else
            echo "Cadena $CHAIN no configurada."
        fi
        echo ""
        echo "Configuración: $CONFIG"
        ;;

    *)
        echo "Uso: $0 {apply|remove|status}"
        ;;
esac
EOFSEGMENT
    chmod +x /usr/local/bin/securizar-iot-segment.sh

    log_change "Reglas de segmentación de red IoT configuradas"
    CHANGES+=("Sección 2: Segmentación de red IoT con iptables")
}

# ── Sección 3: Hardening MQTT ──
section_3() {
    log_section "3. Hardening MQTT"

    ask "¿Configurar hardening del protocolo MQTT?" || { log_skip "Hardening MQTT omitido"; return 0; }

    mkdir -p /etc/securizar/iot/templates

    # Template de configuración segura de Mosquitto
    cat > /etc/securizar/iot/templates/mosquitto-secure.conf << 'EOFMOSQ'
# ============================================================
# Securizar — Configuración segura de Mosquitto MQTT
# ============================================================

# Listener principal con TLS
listener 8883
protocol mqtt

# Certificados TLS
cafile /etc/mosquitto/ca_certificates/ca.crt
certfile /etc/mosquitto/certs/server.crt
keyfile /etc/mosquitto/certs/server.key

# TLS versión mínima
tls_version tlsv1.2

# Deshabilitar acceso anónimo
allow_anonymous false

# Archivo de passwords
password_file /etc/mosquitto/passwd

# ACL por usuario/topic
acl_file /etc/mosquitto/acl

# Limitar conexiones
max_connections 100

# Tamaño máximo de mensaje (256KB)
message_size_limit 262144

# Limitar inflight messages
max_inflight_messages 20
max_queued_messages 1000

# Logging
log_dest syslog
log_type error
log_type warning
log_type notice
log_type subscribe
log_type unsubscribe
connection_messages true
log_timestamp true

# Persistencia
persistence true
persistence_location /var/lib/mosquitto/

# Listener sin TLS solo en localhost (opcional, para debug)
# listener 1883 127.0.0.1
# protocol mqtt
EOFMOSQ

    # ACL template
    cat > /etc/securizar/iot/templates/mosquitto-acl.conf << 'EOFACL'
# Securizar — ACL de MQTT
# Formato: topic [read|write|readwrite] <topic-pattern>
# Usuarios bajo user <username>

# Admin tiene acceso total
user admin
topic readwrite #

# Sensores solo publican a su topic
user sensor1
topic write sensors/sensor1/#
topic read commands/sensor1/#

# Dashboard puede leer todo
user dashboard
topic read sensors/#
topic read status/#

# Pattern: cada usuario puede publicar bajo su propio nombre
pattern readwrite users/%u/#
EOFACL

    # Script de hardening
    cat > /usr/local/bin/securizar-mqtt-harden.sh << 'EOFMQTT'
#!/bin/bash
# ============================================================
# securizar-mqtt-harden.sh — Hardening de MQTT
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar/iot"
mkdir -p "$LOG_DIR"

REPORT="$LOG_DIR/mqtt-harden-$(date +%Y%m%d).txt"

ISSUES=0
PASS=0

{
echo "=========================================="
echo " Hardening MQTT - $(date)"
echo "=========================================="
echo ""

# Detectar Mosquitto
if command -v mosquitto &>/dev/null || systemctl is-active mosquitto &>/dev/null 2>&1; then
    echo "=== Mosquitto detectado ==="

    CONF="/etc/mosquitto/mosquitto.conf"
    CONF_D="/etc/mosquitto/conf.d"

    # Verificar configuración
    if [[ -f "$CONF" ]]; then
        echo "Configuración: $CONF"

        # Anónimo
        if grep -qE '^\s*allow_anonymous\s+true' "$CONF" "$CONF_D"/*.conf 2>/dev/null; then
            echo "  [FAIL] Acceso anónimo habilitado"
            ((ISSUES++))
        elif grep -qE '^\s*allow_anonymous\s+false' "$CONF" "$CONF_D"/*.conf 2>/dev/null; then
            echo "  [PASS] Acceso anónimo deshabilitado"
            ((PASS++))
        else
            echo "  [WARN] allow_anonymous no configurado explícitamente"
            ((ISSUES++))
        fi

        # Password file
        if grep -qE '^\s*password_file' "$CONF" "$CONF_D"/*.conf 2>/dev/null; then
            echo "  [PASS] Autenticación por password configurada"
            ((PASS++))
        else
            echo "  [FAIL] Sin autenticación por password"
            ((ISSUES++))
        fi

        # TLS
        if grep -qE '^\s*listener\s+8883' "$CONF" "$CONF_D"/*.conf 2>/dev/null; then
            echo "  [PASS] Listener TLS (8883) configurado"
            ((PASS++))
        else
            echo "  [WARN] Sin listener TLS configurado"
            ((ISSUES++))
        fi

        if grep -qE '^\s*certfile' "$CONF" "$CONF_D"/*.conf 2>/dev/null; then
            echo "  [PASS] Certificado TLS configurado"
            ((PASS++))
        fi

        # ACL
        if grep -qE '^\s*acl_file' "$CONF" "$CONF_D"/*.conf 2>/dev/null; then
            echo "  [PASS] ACL configuradas"
            ((PASS++))
        else
            echo "  [WARN] Sin ACL configuradas"
            ((ISSUES++))
        fi

        # Límites
        if grep -qE '^\s*max_connections' "$CONF" "$CONF_D"/*.conf 2>/dev/null; then
            echo "  [PASS] Límite de conexiones configurado"
            ((PASS++))
        else
            echo "  [WARN] Sin límite de conexiones"
            ((ISSUES++))
        fi

        # Listener en 1883 accesible externamente
        if grep -qE '^\s*listener\s+1883\s*$' "$CONF" "$CONF_D"/*.conf 2>/dev/null; then
            echo "  [FAIL] Listener sin TLS (1883) accesible externamente"
            ((ISSUES++))
        fi
    else
        echo "  [WARN] Archivo de configuración no encontrado"
    fi
else
    echo "[INFO] Mosquitto no instalado"
    echo ""
    echo "Template de configuración segura disponible en:"
    echo "  /etc/securizar/iot/templates/mosquitto-secure.conf"
    echo "  /etc/securizar/iot/templates/mosquitto-acl.conf"
fi

echo ""

# Verificar puertos MQTT abiertos
echo "=== Puertos MQTT en escucha ==="
ss -tlnp 2>/dev/null | grep -E ':1883|:8883' || echo "  Ninguno"

echo ""
echo "=========================================="
echo " Resumen: PASS=$PASS, ISSUES=$ISSUES"
echo "=========================================="
} 2>&1 | tee "$REPORT"
EOFMQTT
    chmod +x /usr/local/bin/securizar-mqtt-harden.sh

    # Configuración de hardening MQTT
    cat > /etc/securizar/iot/mqtt-hardening.conf << 'EOF'
# Securizar — Política de hardening MQTT
REQUIRE_TLS=true
REQUIRE_AUTH=true
REQUIRE_ACL=true
MAX_CONNECTIONS=100
MAX_MESSAGE_SIZE=262144
MIN_TLS_VERSION=tlsv1.2
ALLOW_ANONYMOUS=false
EOF

    log_change "Hardening MQTT configurado con templates y escáner"
    CHANGES+=("Sección 3: Hardening MQTT con TLS, ACL y autenticación")
}

# ── Sección 4: Hardening CoAP ──
section_4() {
    log_section "4. Hardening CoAP"

    ask "¿Configurar hardening del protocolo CoAP?" || { log_skip "Hardening CoAP omitido"; return 0; }

    mkdir -p /etc/securizar/iot /var/log/securizar/iot

    cat > /usr/local/bin/securizar-coap-harden.sh << 'EOFCOAP'
#!/bin/bash
# ============================================================
# securizar-coap-harden.sh — Hardening de CoAP
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar/iot"
mkdir -p "$LOG_DIR"

REPORT="$LOG_DIR/coap-harden-$(date +%Y%m%d).txt"
ACTION="${1:-audit}"

{
echo "=========================================="
echo " Hardening CoAP - $(date)"
echo " Acción: $ACTION"
echo "=========================================="
echo ""

case "$ACTION" in
    audit)
        echo "=== Auditoría de servicios CoAP ==="
        echo ""

        # Verificar puertos CoAP
        echo "Puertos CoAP en escucha:"
        COAP_LISTEN=$(ss -ulnp 2>/dev/null | grep -E ':5683|:5684' || true)
        if [[ -n "$COAP_LISTEN" ]]; then
            echo "$COAP_LISTEN"

            # Verificar DTLS (5684)
            if echo "$COAP_LISTEN" | grep -q ':5684'; then
                echo "  [PASS] CoAPS (DTLS) en puerto 5684"
            fi
            if echo "$COAP_LISTEN" | grep -q ':5683'; then
                echo "  [WARN] CoAP sin cifrar en puerto 5683"
            fi
        else
            echo "  Ningún servicio CoAP detectado"
        fi

        echo ""
        echo "=== Verificación de tráfico CoAP ==="
        # Verificar reglas de firewall
        if iptables -L -n 2>/dev/null | grep -qE '5683|5684'; then
            echo "  [PASS] Reglas de firewall para CoAP existentes"
        else
            echo "  [WARN] Sin reglas de firewall específicas para CoAP"
        fi
        ;;

    restrict)
        echo "=== Restringiendo acceso CoAP ==="
        echo ""

        IOT_CONFIG="/etc/securizar/iot/iot-network.conf"
        IOT_SUBNET="192.168.100.0/24"
        if [[ -f "$IOT_CONFIG" ]]; then
            source "$IOT_CONFIG"
        fi

        # Solo permitir CoAP desde subred IoT
        iptables -D INPUT -p udp --dport 5683 -j DROP 2>/dev/null || true
        iptables -D INPUT -p udp --dport 5684 -j DROP 2>/dev/null || true

        # Permitir CoAPS (DTLS) desde IoT
        iptables -A INPUT -s "$IOT_SUBNET" -p udp --dport 5684 -j ACCEPT
        echo "[OK] CoAPS (5684) permitido desde $IOT_SUBNET"

        # Bloquear CoAP sin cifrar desde red
        iptables -A INPUT -p udp --dport 5683 -j LOG --log-prefix "SECURIZAR_COAP_BLOCK: "
        iptables -A INPUT -p udp --dport 5683 -j DROP
        echo "[OK] CoAP sin cifrar (5683) bloqueado"

        echo ""
        echo "Reglas aplicadas."
        ;;

    *)
        echo "Uso: $0 {audit|restrict}"
        echo ""
        echo "  audit    - Auditar servicios CoAP"
        echo "  restrict - Aplicar restricciones de firewall"
        ;;
esac

echo ""
echo "Completado: $(date)"
} 2>&1 | tee "$REPORT"
EOFCOAP
    chmod +x /usr/local/bin/securizar-coap-harden.sh

    log_change "Hardening CoAP configurado"
    CHANGES+=("Sección 4: Hardening CoAP con restricciones DTLS y firewall")
}

# ── Sección 5: Validación de firmware ──
section_5() {
    log_section "5. Validación de firmware"

    ask "¿Configurar verificación de integridad de firmware IoT?" || { log_skip "Validación de firmware omitida"; return 0; }

    mkdir -p /etc/securizar/iot /var/log/securizar/iot

    cat > /usr/local/bin/securizar-firmware-check.sh << 'EOFFW'
#!/bin/bash
# ============================================================
# securizar-firmware-check.sh — Verificación de firmware IoT
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar/iot"
mkdir -p "$LOG_DIR"

FECHA=$(date +%Y%m%d)
REPORT="$LOG_DIR/firmware-audit-${FECHA}.log"
WHITELIST="/etc/securizar/iot/firmware-whitelist.conf"

{
echo "=========================================="
echo " Verificación de firmware IoT"
echo " $(date) - $(hostname)"
echo "=========================================="
echo ""

# 1. Verificar firmware del propio host
echo "=== Firmware del sistema ==="

# BIOS/UEFI
if command -v dmidecode &>/dev/null; then
    BIOS_VENDOR=$(dmidecode -s bios-vendor 2>/dev/null || echo "unknown")
    BIOS_VERSION=$(dmidecode -s bios-version 2>/dev/null || echo "unknown")
    BIOS_DATE=$(dmidecode -s bios-release-date 2>/dev/null || echo "unknown")
    echo "  BIOS: $BIOS_VENDOR $BIOS_VERSION ($BIOS_DATE)"
fi

# fwupd si disponible
if command -v fwupdmgr &>/dev/null; then
    echo ""
    echo "=== Actualizaciones de firmware (fwupd) ==="
    fwupdmgr get-updates 2>/dev/null | head -20 || echo "  Sin actualizaciones o fwupd no configurado"

    echo ""
    echo "Dispositivos con firmware gestionado:"
    fwupdmgr get-devices 2>/dev/null | grep -E 'Name|Version|UpdateState' | head -30 || true
else
    echo ""
    echo "[INFO] fwupd no instalado — considerar instalar para gestión de firmware"
fi

# 2. Verificar Secure Boot
echo ""
echo "=== Secure Boot ==="
if command -v mokutil &>/dev/null; then
    SB_STATE=$(mokutil --sb-state 2>/dev/null || echo "unknown")
    echo "  Estado: $SB_STATE"
    if echo "$SB_STATE" | grep -qi "enabled"; then
        echo "  [PASS] Secure Boot habilitado"
    else
        echo "  [WARN] Secure Boot no habilitado"
    fi
elif [[ -d /sys/firmware/efi ]]; then
    if [[ -f /sys/firmware/efi/efivars/SecureBoot-* ]]; then
        echo "  [INFO] Sistema UEFI con EFI vars"
    fi
else
    echo "  [INFO] Sistema legacy BIOS (sin Secure Boot)"
fi

# 3. Verificar contra whitelist
echo ""
echo "=== Whitelist de firmware ==="
if [[ -f "$WHITELIST" ]]; then
    echo "Whitelist: $WHITELIST"
    ENTRIES=$(grep -cv '^#\|^$' "$WHITELIST" 2>/dev/null || echo "0")
    echo "Entradas: $ENTRIES"
else
    echo "[INFO] No existe whitelist de firmware"
    echo "Crear: $WHITELIST"
fi

# 4. Verificar módulos de kernel (firmware embebido)
echo ""
echo "=== Módulos de kernel con firmware ==="
MODULES_WITH_FW=0
for mod_path in /sys/module/*/firmware_class 2>/dev/null; do
    MOD_NAME=$(echo "$mod_path" | cut -d'/' -f4)
    echo "  Módulo: $MOD_NAME"
    ((MODULES_WITH_FW++))
done
if [[ $MODULES_WITH_FW -eq 0 ]]; then
    # Alternativa
    ls /lib/firmware/ 2>/dev/null | head -10 | while read -r fw; do
        echo "  Firmware: $fw"
    done
fi

# 5. Verificar integridad de firmware files
echo ""
echo "=== Integridad de archivos de firmware ==="
FW_DIR="/lib/firmware"
if [[ -d "$FW_DIR" ]]; then
    FW_COUNT=$(find "$FW_DIR" -type f 2>/dev/null | wc -l || echo "0")
    echo "  Archivos de firmware: $FW_COUNT"

    # Verificar permisos
    WORLD_WRITABLE=$(find "$FW_DIR" -type f -perm -o+w 2>/dev/null | head -5)
    if [[ -n "$WORLD_WRITABLE" ]]; then
        echo "  [FAIL] Firmware con permisos de escritura global:"
        echo "$WORLD_WRITABLE" | while read -r f; do echo "    $f"; done
    else
        echo "  [PASS] Sin firmware con permisos inseguros"
    fi
fi

echo ""
echo "Completado: $(date)"
} 2>&1 | tee "$REPORT"

echo "Reporte: $REPORT"
EOFFW
    chmod +x /usr/local/bin/securizar-firmware-check.sh

    # Whitelist template
    cat > /etc/securizar/iot/firmware-whitelist.conf << 'EOF'
# Securizar — Whitelist de firmware IoT
# ======================================
# Formato: vendor:model:version_min:hash_sha256
# Líneas con # son comentarios
#
# Ejemplo:
# espressif:esp32:4.4.0:sha256_hash_aqui
# raspberry:rpi4:2024.01:sha256_hash_aqui
EOF

    log_change "Sistema de validación de firmware configurado"
    CHANGES+=("Sección 5: Validación de firmware con whitelist y fwupd")
}

# ── Sección 6: Monitoreo de tráfico IoT ──
section_6() {
    log_section "6. Monitoreo de tráfico IoT"

    ask "¿Configurar monitoreo continuo de tráfico IoT?" || { log_skip "Monitoreo IoT omitido"; return 0; }

    mkdir -p /var/log/securizar/iot /etc/securizar/iot

    cat > /usr/local/bin/securizar-iot-monitor.sh << 'EOFMON'
#!/bin/bash
# ============================================================
# securizar-iot-monitor.sh — Monitoreo de tráfico IoT
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar/iot"
mkdir -p "$LOG_DIR"

CONFIG="/etc/securizar/iot/iot-network.conf"
IOT_SUBNET="192.168.100.0/24"
if [[ -f "$CONFIG" ]]; then
    source "$CONFIG"
fi

ACTION="${1:-snapshot}"
REPORT="$LOG_DIR/iot-traffic-$(date +%Y%m%d-%H%M%S).log"

case "$ACTION" in
    snapshot)
        {
        echo "=========================================="
        echo " Snapshot de tráfico IoT - $(date)"
        echo " Subred: $IOT_SUBNET"
        echo "=========================================="
        echo ""

        # Conexiones activas desde/hacia subred IoT
        echo "=== Conexiones activas ==="
        ss -tnp 2>/dev/null | grep -E "$(echo "$IOT_SUBNET" | cut -d'/' -f1 | cut -d'.' -f1-3)" || echo "  Sin conexiones detectadas"

        echo ""
        echo "=== Tráfico por IP (conntrack) ==="
        if command -v conntrack &>/dev/null; then
            conntrack -L 2>/dev/null | grep -E "$(echo "$IOT_SUBNET" | cut -d'/' -f1 | cut -d'.' -f1-3)" | \
                awk '{print $4, $5, $6}' | sort | uniq -c | sort -rn | head -20 || true
        fi

        # Estadísticas de firewall
        echo ""
        echo "=== Estadísticas de firewall IoT ==="
        iptables -L SECURIZAR_IOT -n -v 2>/dev/null || echo "  Cadena SECURIZAR_IOT no configurada"

        # Tráfico por interfaz
        echo ""
        echo "=== Tráfico por interfaz ==="
        for iface in $(ip link show 2>/dev/null | grep -oP '^\d+: \K[^:@]+'); do
            RX=$(cat "/sys/class/net/$iface/statistics/rx_bytes" 2>/dev/null || echo "0")
            TX=$(cat "/sys/class/net/$iface/statistics/tx_bytes" 2>/dev/null || echo "0")
            if [[ $RX -gt 0 || $TX -gt 0 ]]; then
                RX_MB=$((RX / 1048576))
                TX_MB=$((TX / 1048576))
                echo "  $iface: RX=${RX_MB}MB TX=${TX_MB}MB"
            fi
        done

        echo ""
        echo "Completado: $(date)"
        } 2>&1 | tee "$REPORT"
        echo "Reporte: $REPORT"
        ;;

    capture)
        DURATION="${2:-60}"
        echo "Capturando tráfico IoT durante ${DURATION}s..."

        if command -v tcpdump &>/dev/null; then
            PCAP="$LOG_DIR/iot-capture-$(date +%Y%m%d-%H%M%S).pcap"
            timeout "$DURATION" tcpdump -i any net "$IOT_SUBNET" -w "$PCAP" -c 10000 2>/dev/null || true
            echo "Captura: $PCAP"
            echo "Paquetes: $(tcpdump -r "$PCAP" 2>/dev/null | wc -l || echo 0)"
        else
            echo "tcpdump no disponible"
            exit 1
        fi
        ;;

    anomalies)
        {
        echo "=========================================="
        echo " Detección de anomalías IoT - $(date)"
        echo "=========================================="
        echo ""

        ANOMALIES=0

        # 1. Alto volumen desde un dispositivo IoT
        echo "=== Alto volumen de tráfico ==="
        if command -v conntrack &>/dev/null; then
            IOT_NET_PREFIX=$(echo "$IOT_SUBNET" | cut -d'/' -f1 | cut -d'.' -f1-3)
            conntrack -L 2>/dev/null | grep "src=$IOT_NET_PREFIX" | \
                awk -F'src=' '{print $2}' | awk '{print $1}' | sort | uniq -c | sort -rn | \
                while read -r count ip; do
                    if [[ $count -gt 100 ]]; then
                        echo "  [ANOMALÍA] $ip: $count conexiones activas"
                        ((ANOMALIES++)) || true
                    fi
                done
        fi

        # 2. Destinos inusuales
        echo ""
        echo "=== Destinos inusuales ==="
        if command -v conntrack &>/dev/null; then
            conntrack -L 2>/dev/null | grep "src=$IOT_NET_PREFIX" | \
                grep -oP 'dst=\K[0-9.]+' | sort | uniq -c | sort -rn | head -10 | \
                while read -r count dst; do
                    echo "  $dst: $count conexiones"
                done
        fi

        # 3. Puertos inusuales
        echo ""
        echo "=== Puertos de destino inusuales ==="
        ss -tnp 2>/dev/null | grep "$IOT_NET_PREFIX" | awk '{print $5}' | \
            grep -oP ':\K[0-9]+$' | sort | uniq -c | sort -rn | head -10 | \
            while read -r count port; do
                case "$port" in
                    80|443|8883|1883|5683|53|123) ;; # Normales para IoT
                    *)
                        echo "  [WARN] Puerto $port: $count conexiones (inusual para IoT)"
                        ((ANOMALIES++)) || true
                        ;;
                esac
            done

        echo ""
        echo "Anomalías detectadas: $ANOMALIES"
        } 2>&1 | tee "$REPORT"
        ;;

    *)
        echo "Uso: $0 {snapshot|capture [segundos]|anomalies}"
        ;;
esac
EOFMON
    chmod +x /usr/local/bin/securizar-iot-monitor.sh

    # Servicio systemd para monitoreo continuo
    cat > /etc/systemd/system/securizar-iot-monitor.service << 'EOF'
[Unit]
Description=Securizar - Monitoreo de tráfico IoT
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/securizar-iot-monitor.sh anomalies
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/securizar-iot-monitor.timer << 'EOF'
[Unit]
Description=Securizar - Timer de monitoreo IoT (cada hora)

[Timer]
OnCalendar=*:00:00
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable securizar-iot-monitor.timer 2>/dev/null || true

    log_change "Monitoreo de tráfico IoT configurado"
    CHANGES+=("Sección 6: Monitoreo de tráfico IoT con detección de anomalías")
}

# ── Sección 7: Control de acceso IoT ──
section_7() {
    log_section "7. Control de acceso IoT"

    ask "¿Configurar control de acceso por MAC para dispositivos IoT?" || { log_skip "Control de acceso IoT omitido"; return 0; }

    mkdir -p /etc/securizar/iot /var/log/securizar/iot

    # Lista de dispositivos permitidos
    cat > /etc/securizar/iot/iot-allowed-devices.conf << 'EOF'
# Securizar — Dispositivos IoT autorizados
# ==========================================
# Formato: MAC|Nombre|Tipo|Notas
# MAC en formato xx:xx:xx:xx:xx:xx
#
# Ejemplo:
# aa:bb:cc:dd:ee:ff|Sensor Temperatura|ESP32|Sala principal
# 11:22:33:44:55:66|Cámara Entrada|Hikvision|IP: 192.168.100.10
EOF

    cat > /usr/local/bin/securizar-iot-access.sh << 'EOFACCESS'
#!/bin/bash
# ============================================================
# securizar-iot-access.sh — Control de acceso IoT por MAC
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar/iot"
mkdir -p "$LOG_DIR"

ALLOWED="/etc/securizar/iot/iot-allowed-devices.conf"
ACTION="${1:-check}"
IOT_CONFIG="/etc/securizar/iot/iot-network.conf"
IOT_SUBNET="192.168.100.0/24"
if [[ -f "$IOT_CONFIG" ]]; then
    source "$IOT_CONFIG"
fi

REPORT="$LOG_DIR/iot-access-$(date +%Y%m%d).txt"

case "$ACTION" in
    check)
        {
        echo "=========================================="
        echo " Control de acceso IoT - $(date)"
        echo "=========================================="
        echo ""

        if [[ ! -f "$ALLOWED" ]]; then
            echo "[ERROR] Lista de dispositivos no encontrada: $ALLOWED"
            exit 1
        fi

        # Cargar MACs permitidas
        declare -A ALLOWED_MACS
        while IFS='|' read -r mac name tipo notas; do
            [[ -z "$mac" || "$mac" =~ ^# ]] && continue
            mac_lower=$(echo "$mac" | tr '[:upper:]' '[:lower:]')
            ALLOWED_MACS["$mac_lower"]="$name"
        done < "$ALLOWED"

        echo "Dispositivos autorizados: ${#ALLOWED_MACS[@]}"
        echo ""

        # Escanear red
        UNKNOWN=0
        KNOWN=0

        IOT_NET_PREFIX=$(echo "$IOT_SUBNET" | cut -d'/' -f1 | cut -d'.' -f1-3)

        echo "=== Dispositivos detectados ==="
        ip neigh show 2>/dev/null | while read -r line; do
            IP=$(echo "$line" | awk '{print $1}')
            MAC=$(echo "$line" | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' || echo "")
            STATE=$(echo "$line" | awk '{print $NF}')

            [[ -z "$MAC" || "$STATE" == "FAILED" ]] && continue

            # Solo IoT subnet
            if [[ "$IP" == "$IOT_NET_PREFIX"* ]]; then
                mac_lower=$(echo "$MAC" | tr '[:upper:]' '[:lower:]')
                NAME="${ALLOWED_MACS[$mac_lower]:-}"

                if [[ -n "$NAME" ]]; then
                    echo "  [OK] $IP ($MAC) — $NAME"
                    ((KNOWN++)) || true
                else
                    echo "  [DESCONOCIDO] $IP ($MAC) — NO AUTORIZADO"
                    ((UNKNOWN++)) || true

                    # Log del dispositivo desconocido
                    echo "$(date -Iseconds) UNKNOWN_DEVICE ip=$IP mac=$MAC" >> "$LOG_DIR/unknown-devices.log"
                fi
            fi
        done

        echo ""
        echo "Conocidos: $KNOWN"
        echo "Desconocidos: $UNKNOWN"

        if [[ $UNKNOWN -gt 0 ]]; then
            echo ""
            echo "*** ALERTA: Dispositivos no autorizados en la red IoT ***"
        fi
        } 2>&1 | tee "$REPORT"
        ;;

    add)
        MAC="${2:-}"
        NAME="${3:-Dispositivo}"
        TYPE="${4:-unknown}"

        if [[ -z "$MAC" ]]; then
            echo "Uso: $0 add <MAC> [nombre] [tipo]"
            exit 1
        fi

        echo "$MAC|$NAME|$TYPE|Añadido $(date +%Y-%m-%d)" >> "$ALLOWED"
        echo "Dispositivo añadido: $MAC ($NAME)"
        ;;

    block)
        MAC="${2:-}"
        if [[ -z "$MAC" ]]; then
            echo "Uso: $0 block <MAC>"
            exit 1
        fi
        # Bloquear por MAC con ebtables si disponible
        if command -v ebtables &>/dev/null; then
            ebtables -A INPUT -s "$MAC" -j DROP 2>/dev/null || true
            ebtables -A FORWARD -s "$MAC" -j DROP 2>/dev/null || true
            echo "Dispositivo bloqueado: $MAC"
        else
            echo "ebtables no disponible. Bloqueo manual por iptables:"
            echo "  iptables -A INPUT -m mac --mac-source $MAC -j DROP"
        fi
        ;;

    *)
        echo "Uso: $0 {check|add|block} [argumentos]"
        echo ""
        echo "  check           - Verificar dispositivos en la red"
        echo "  add MAC [name]  - Añadir dispositivo a whitelist"
        echo "  block MAC       - Bloquear dispositivo"
        ;;
esac
EOFACCESS
    chmod +x /usr/local/bin/securizar-iot-access.sh

    log_change "Control de acceso IoT por MAC configurado"
    CHANGES+=("Sección 7: Control de acceso IoT con whitelist de MACs")
}

# ── Sección 8: Protección de protocolos IoT legacy ──
section_8() {
    log_section "8. Protección de protocolos IoT legacy"

    ask "¿Bloquear protocolos legacy inseguros en el segmento IoT?" || { log_skip "Protección legacy omitida"; return 0; }

    mkdir -p /var/log/securizar/iot

    cat > /usr/local/bin/securizar-iot-legacy.sh << 'EOFLEGACY'
#!/bin/bash
# ============================================================
# securizar-iot-legacy.sh — Detecta y bloquea protocolos inseguros
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar/iot"
mkdir -p "$LOG_DIR"

IOT_CONFIG="/etc/securizar/iot/iot-network.conf"
IOT_SUBNET="192.168.100.0/24"
if [[ -f "$IOT_CONFIG" ]]; then
    source "$IOT_CONFIG"
fi

ACTION="${1:-audit}"
REPORT="$LOG_DIR/iot-legacy-$(date +%Y%m%d).txt"

LEGACY_PORTS="21 23 69 80 161 502 1883 5683 20000"

{
echo "=========================================="
echo " Protocolos legacy IoT - $(date)"
echo " Subred IoT: $IOT_SUBNET"
echo "=========================================="
echo ""

case "$ACTION" in
    audit)
        echo "=== Escaneo de protocolos inseguros ==="
        echo ""

        INSECURE=0

        for port in $LEGACY_PORTS; do
            DESC=""
            case "$port" in
                21) DESC="FTP (transferencia sin cifrar)" ;;
                23) DESC="Telnet (acceso sin cifrar)" ;;
                69) DESC="TFTP (transferencia trivial)" ;;
                80) DESC="HTTP (web sin cifrar)" ;;
                161) DESC="SNMP v1/v2c (comunidad en texto plano)" ;;
                502) DESC="Modbus (sin autenticación nativa)" ;;
                1883) DESC="MQTT (sin TLS)" ;;
                5683) DESC="CoAP (sin DTLS)" ;;
                20000) DESC="DNP3 (SCADA sin cifrar)" ;;
            esac

            # Verificar si hay tráfico en estos puertos desde IoT
            LISTENERS=$(ss -tlnp 2>/dev/null | grep ":${port} " || true)
            if [[ -n "$LISTENERS" ]]; then
                echo "  [DETECTADO] Puerto $port ($DESC)"
                echo "    $LISTENERS"
                ((INSECURE++))
            fi
        done

        # Verificar conexiones desde subred IoT
        echo ""
        echo "=== Conexiones legacy desde IoT ==="
        IOT_PREFIX=$(echo "$IOT_SUBNET" | cut -d'/' -f1 | cut -d'.' -f1-3)
        for port in $LEGACY_PORTS; do
            CONNS=$(ss -tnp 2>/dev/null | grep "$IOT_PREFIX" | grep ":${port}" | wc -l || echo "0")
            if [[ $CONNS -gt 0 ]]; then
                echo "  Puerto $port: $CONNS conexiones activas"
            fi
        done

        echo ""
        echo "Protocolos inseguros detectados: $INSECURE"
        ;;

    block)
        echo "=== Bloqueando protocolos legacy en IoT ==="
        echo ""

        CHAIN="SECURIZAR_IOT_LEGACY"
        iptables -N "$CHAIN" 2>/dev/null || iptables -F "$CHAIN"

        for port in 21 23 69 161 502 20000; do
            DESC=""
            case "$port" in
                21) DESC="FTP" ;; 23) DESC="Telnet" ;; 69) DESC="TFTP" ;;
                161) DESC="SNMP" ;; 502) DESC="Modbus" ;; 20000) DESC="DNP3" ;;
            esac

            iptables -A "$CHAIN" -s "$IOT_SUBNET" -p tcp --dport "$port" -j LOG \
                --log-prefix "IOT_LEGACY_BLOCK: " --log-level 4
            iptables -A "$CHAIN" -s "$IOT_SUBNET" -p tcp --dport "$port" -j DROP
            iptables -A "$CHAIN" -s "$IOT_SUBNET" -p udp --dport "$port" -j DROP

            echo "[OK] $DESC (puerto $port) bloqueado desde IoT"
        done

        # Insertar en FORWARD
        iptables -D FORWARD -j "$CHAIN" 2>/dev/null || true
        iptables -I FORWARD -j "$CHAIN"

        echo ""
        echo "Protocolos legacy bloqueados."
        ;;

    *)
        echo "Uso: $0 {audit|block}"
        echo ""
        echo "  audit - Detectar protocolos inseguros"
        echo "  block - Bloquear protocolos legacy desde IoT"
        ;;
esac

echo ""
echo "Completado: $(date)"
} 2>&1 | tee "$REPORT"
EOFLEGACY
    chmod +x /usr/local/bin/securizar-iot-legacy.sh

    log_change "Protección contra protocolos legacy IoT configurada"
    CHANGES+=("Sección 8: Detección y bloqueo de FTP/Telnet/SNMP/Modbus en IoT")
}

# ── Sección 9: Gestión de actualizaciones IoT ──
section_9() {
    log_section "9. Gestión de actualizaciones IoT"

    ask "¿Configurar seguimiento de actualizaciones de firmware IoT?" || { log_skip "Actualizaciones IoT omitidas"; return 0; }

    mkdir -p /var/log/securizar/iot /etc/securizar/iot

    cat > /usr/local/bin/securizar-iot-updates.sh << 'EOFUPDATES'
#!/bin/bash
# ============================================================
# securizar-iot-updates.sh — Gestión de actualizaciones IoT
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar/iot"
mkdir -p "$LOG_DIR"

REGISTRY="/etc/securizar/iot/iot-firmware-registry.conf"
REPORT="$LOG_DIR/iot-updates-$(date +%Y%m%d).log"
ACTION="${1:-status}"

case "$ACTION" in
    status)
        {
        echo "=========================================="
        echo " Estado de firmware IoT - $(date)"
        echo "=========================================="
        echo ""

        if [[ ! -f "$REGISTRY" ]]; then
            echo "[INFO] Registro de firmware no encontrado"
            echo "Crear: $REGISTRY"
            echo ""
            echo "Formato: DEVICE_ID|NAME|VENDOR|CURRENT_VERSION|LAST_CHECK|NOTES"
            exit 0
        fi

        echo "=== Dispositivos registrados ==="
        TOTAL=0
        OUTDATED=0

        while IFS='|' read -r did name vendor version last_check notes; do
            [[ -z "$did" || "$did" =~ ^# ]] && continue
            ((TOTAL++))

            echo ""
            echo "  Dispositivo: $name ($did)"
            echo "  Vendor: $vendor"
            echo "  Firmware: $version"
            echo "  Último check: ${last_check:-nunca}"
            echo "  Notas: ${notes:-}"

            # Verificar antigüedad del check
            if [[ -n "$last_check" ]]; then
                LAST_EPOCH=$(date -d "$last_check" +%s 2>/dev/null || echo "0")
                NOW_EPOCH=$(date +%s)
                DAYS_AGO=$(( (NOW_EPOCH - LAST_EPOCH) / 86400 ))
                if [[ $DAYS_AGO -gt 90 ]]; then
                    echo "  [WARN] Último check hace $DAYS_AGO días (> 90)"
                    ((OUTDATED++))
                fi
            else
                echo "  [WARN] Nunca verificado"
                ((OUTDATED++))
            fi
        done < "$REGISTRY"

        echo ""
        echo "=========================================="
        echo " Total dispositivos: $TOTAL"
        echo " Necesitan revisión: $OUTDATED"
        echo "=========================================="
        } 2>&1 | tee "$REPORT"
        ;;

    add)
        DID="${2:-}"
        NAME="${3:-}"
        VENDOR="${4:-}"
        VERSION="${5:-}"

        if [[ -z "$DID" || -z "$NAME" ]]; then
            echo "Uso: $0 add <device_id> <nombre> [vendor] [version]"
            exit 1
        fi

        if [[ ! -f "$REGISTRY" ]]; then
            echo "# Securizar — Registro de firmware IoT" > "$REGISTRY"
            echo "# Formato: DEVICE_ID|NAME|VENDOR|VERSION|LAST_CHECK|NOTES" >> "$REGISTRY"
        fi

        echo "$DID|$NAME|${VENDOR:-unknown}|${VERSION:-unknown}|$(date +%Y-%m-%d)|Registrado" >> "$REGISTRY"
        echo "Dispositivo registrado: $NAME ($DID)"
        ;;

    update)
        DID="${2:-}"
        NEW_VERSION="${3:-}"

        if [[ -z "$DID" || -z "$NEW_VERSION" ]]; then
            echo "Uso: $0 update <device_id> <nueva_version>"
            exit 1
        fi

        if [[ -f "$REGISTRY" ]]; then
            # Actualizar versión y fecha
            sed -i "s|^$DID|.*|$DID|" "$REGISTRY" 2>/dev/null || true
            echo "Versión actualizada: $DID → $NEW_VERSION"
            echo "$(date -Iseconds) UPDATE device=$DID version=$NEW_VERSION" >> "$LOG_DIR/iot-updates.log"
        fi
        ;;

    *)
        echo "Uso: $0 {status|add|update}"
        echo ""
        echo "  status                          - Ver estado de firmware"
        echo "  add <id> <nombre> [vendor] [v]  - Registrar dispositivo"
        echo "  update <id> <version>           - Actualizar versión"
        ;;
esac
EOFUPDATES
    chmod +x /usr/local/bin/securizar-iot-updates.sh

    # Cron mensual
    cat > /etc/cron.monthly/securizar-iot-updates << 'EOF'
#!/bin/bash
/usr/local/bin/securizar-iot-updates.sh status >> /var/log/securizar/iot/updates-cron.log 2>&1
EOF
    chmod +x /etc/cron.monthly/securizar-iot-updates

    log_change "Gestión de actualizaciones de firmware IoT configurada"
    CHANGES+=("Sección 9: Registro y seguimiento de firmware IoT")
}

# ── Sección 10: Auditoría de seguridad IoT ──
section_10() {
    log_section "10. Auditoría de seguridad IoT"

    ask "¿Configurar auditoría integral de seguridad IoT?" || { log_skip "Auditoría IoT omitida"; return 0; }

    mkdir -p /var/log/securizar/iot

    cat > /usr/local/bin/auditoria-iot.sh << 'EOFAUDIT'
#!/bin/bash
# ============================================================
# auditoria-iot.sh — Auditoría integral de seguridad IoT
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar/iot"
mkdir -p "$LOG_DIR"

FECHA=$(date +%Y%m%d)
REPORT="$LOG_DIR/auditoria-iot-${FECHA}.txt"

SCORE=0
MAX_SCORE=0
CHECKS_PASS=0
CHECKS_FAIL=0

check_item() {
    local desc="$1" weight="$2" condition="$3"
    ((MAX_SCORE += weight))
    if eval "$condition" &>/dev/null; then
        echo "  [✓] $desc (+$weight)"
        ((SCORE += weight))
        ((CHECKS_PASS++))
    else
        echo "  [✗] $desc (0/$weight)"
        ((CHECKS_FAIL++))
    fi
}

{
echo "=========================================="
echo " Auditoría de Seguridad IoT"
echo " $(date) - $(hostname)"
echo "=========================================="
echo ""

echo "=== 1. Descubrimiento e inventario ==="
check_item "Script de descubrimiento instalado" 2 "test -x /usr/local/bin/securizar-iot-discovery.sh"
check_item "Cron de descubrimiento activo" 1 "test -x /etc/cron.weekly/securizar-iot-discovery"
check_item "Inventario reciente (< 30 días)" 2 "find $LOG_DIR -name 'iot-inventory-*.json' -mtime -30 | grep -q '.'"

echo ""
echo "=== 2. Segmentación de red ==="
check_item "Script de segmentación instalado" 2 "test -x /usr/local/bin/securizar-iot-segment.sh"
check_item "Configuración de red IoT" 2 "test -f /etc/securizar/iot/iot-network.conf"
check_item "Cadena SECURIZAR_IOT activa" 3 "iptables -L SECURIZAR_IOT -n 2>/dev/null | grep -q 'Chain'"

echo ""
echo "=== 3. MQTT ==="
check_item "Hardening MQTT configurado" 2 "test -x /usr/local/bin/securizar-mqtt-harden.sh"
check_item "Política MQTT definida" 1 "test -f /etc/securizar/iot/mqtt-hardening.conf"
check_item "Template Mosquitto seguro" 1 "test -f /etc/securizar/iot/templates/mosquitto-secure.conf"

echo ""
echo "=== 4. CoAP ==="
check_item "Hardening CoAP configurado" 1 "test -x /usr/local/bin/securizar-coap-harden.sh"

echo ""
echo "=== 5. Firmware ==="
check_item "Verificador de firmware instalado" 2 "test -x /usr/local/bin/securizar-firmware-check.sh"
check_item "Whitelist de firmware" 1 "test -f /etc/securizar/iot/firmware-whitelist.conf"

echo ""
echo "=== 6. Monitoreo de tráfico ==="
check_item "Monitor de tráfico IoT instalado" 2 "test -x /usr/local/bin/securizar-iot-monitor.sh"
check_item "Timer de monitoreo activo" 2 "systemctl is-active securizar-iot-monitor.timer 2>/dev/null || test -f /etc/systemd/system/securizar-iot-monitor.timer"

echo ""
echo "=== 7. Control de acceso ==="
check_item "Control de acceso IoT instalado" 2 "test -x /usr/local/bin/securizar-iot-access.sh"
check_item "Lista de dispositivos autorizados" 2 "test -f /etc/securizar/iot/iot-allowed-devices.conf"

echo ""
echo "=== 8. Protocolos legacy ==="
check_item "Detector de protocolos legacy" 2 "test -x /usr/local/bin/securizar-iot-legacy.sh"

echo ""
echo "=== 9. Actualizaciones ==="
check_item "Gestor de actualizaciones IoT" 1 "test -x /usr/local/bin/securizar-iot-updates.sh"
check_item "Cron de verificación mensual" 1 "test -x /etc/cron.monthly/securizar-iot-updates"

echo ""
echo "=========================================="
echo " RESULTADO"
echo "=========================================="

if [[ $MAX_SCORE -gt 0 ]]; then
    PCT=$((SCORE * 100 / MAX_SCORE))
else
    PCT=0
fi

echo ""
echo " Puntuación: $SCORE / $MAX_SCORE ($PCT%)"
echo " Checks: $CHECKS_PASS passed, $CHECKS_FAIL failed"
echo ""

if [[ $PCT -ge 80 ]]; then
    echo " Calificación: ██████████ BUENO"
    echo " La seguridad IoT está bien configurada."
elif [[ $PCT -ge 50 ]]; then
    echo " Calificación: ██████░░░░ MEJORABLE"
    echo " Hay aspectos de seguridad IoT que mejorar."
else
    echo " Calificación: ███░░░░░░░ DEFICIENTE"
    echo " La seguridad IoT necesita atención urgente."
fi

echo ""
echo " Auditado: $(date)"
echo "=========================================="
} 2>&1 | tee "$REPORT"

echo "Reporte: $REPORT"
EOFAUDIT
    chmod +x /usr/local/bin/auditoria-iot.sh

    # Cron semanal
    cat > /etc/cron.weekly/auditoria-iot << 'EOF'
#!/bin/bash
/usr/local/bin/auditoria-iot.sh >> /var/log/securizar/iot/auditoria-cron.log 2>&1
EOF
    chmod +x /etc/cron.weekly/auditoria-iot

    log_change "Auditoría integral de seguridad IoT configurada"
    CHANGES+=("Sección 10: Auditoría IoT con scoring BUENO/MEJORABLE/DEFICIENTE")
}

# ── Main ──
main() {
    check_root
    log_section "MÓDULO 64: SEGURIDAD IoT"
    for i in $(seq 1 10); do
        "section_$i"
    done
    echo ""
    show_changes_summary
}
main "$@"
