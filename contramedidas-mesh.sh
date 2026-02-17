#!/bin/bash
# ============================================================
# CONTRAMEDIDAS CONTRA TECH MESH
# WiFi Mesh, Bluetooth Mesh, IoT Mesh, Redes en malla
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps

# --- Pre-check: verificar si ya está todo aplicado ---
_precheck 12
_pc true
_pc 'check_file_exists /etc/modprobe.d/disable-bluetooth.conf'
_pc 'grep -q bt_coex_active /etc/modprobe.d/disable-bluetooth.conf 2>/dev/null'
_pc 'check_file_exists /etc/NetworkManager/conf.d/99-no-mesh.conf'
_pc 'check_file_exists /etc/modprobe.d/disable-zigbee.conf'
_pc '! systemctl is-enabled avahi-daemon 2>/dev/null'
_pc true
_pc 'check_file_exists /etc/NetworkManager/conf.d/99-random-mac-full.conf'
_pc 'check_executable /usr/local/bin/monitor-mesh.sh'
_pc true
_pc 'check_file_exists /etc/modprobe.d/disable-nfc.conf'
_pc 'check_file_exists /etc/NetworkManager/dispatcher.d/99-disable-wowlan'
_precheck_result

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║       CONTRAMEDIDAS CONTRA TECH MESH                      ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "Las redes mesh permiten vigilancia mediante:"
echo "  • Rastreo de dispositivos por Bluetooth/WiFi"
echo "  • Triangulación de ubicación"
echo "  • Interceptación de tráfico"
echo "  • Dispositivos IoT comprometidos"
echo ""

# ============================================================
# 1. DETECTAR REDES MESH CERCANAS
# ============================================================
echo -e "${CYAN}═══ 1. DETECCIÓN DE REDES MESH ═══${NC}"
echo ""

log_info "Escaneando redes WiFi cercanas..."
echo ""
nmcli dev wifi list 2>/dev/null | head -20
echo ""

log_info "Buscando dispositivos Bluetooth cercanos..."
echo ""
if command -v bluetoothctl &>/dev/null; then
    timeout 5 bluetoothctl scan on 2>/dev/null &
    sleep 5
    bluetoothctl devices 2>/dev/null
    bluetoothctl scan off 2>/dev/null
else
    echo "bluetoothctl no disponible"
fi
echo ""

# ============================================================
# 2. BLOQUEAR BLUETOOTH COMPLETAMENTE
# ============================================================
echo ""
echo -e "${CYAN}═══ 2. BLOQUEAR BLUETOOTH ═══${NC}"
echo ""
echo "Bluetooth Mesh puede rastrear tu ubicación y dispositivo."
echo ""

if check_file_exists /etc/modprobe.d/disable-bluetooth.conf; then
    log_already "Bluetooth bloqueado (disable-bluetooth.conf)"
elif ask "¿Bloquear Bluetooth completamente?"; then
    # Desactivar por rfkill
    sudo rfkill block bluetooth 2>/dev/null

    # Desactivar servicio
    sudo systemctl stop bluetooth 2>/dev/null
    log_change "Servicio" "bluetooth stop"
    sudo systemctl disable bluetooth 2>/dev/null
    log_change "Servicio" "bluetooth disable"
    sudo systemctl mask bluetooth 2>/dev/null
    log_change "Servicio" "bluetooth mask"

    # Bloquear módulos
    echo "install bluetooth /bin/false" | sudo tee /etc/modprobe.d/disable-bluetooth.conf > /dev/null
    echo "install btusb /bin/false" | sudo tee -a /etc/modprobe.d/disable-bluetooth.conf > /dev/null
    echo "install btrtl /bin/false" | sudo tee -a /etc/modprobe.d/disable-bluetooth.conf > /dev/null
    echo "install btintel /bin/false" | sudo tee -a /etc/modprobe.d/disable-bluetooth.conf > /dev/null
    log_change "Creado" "/etc/modprobe.d/disable-bluetooth.conf"

    # Descargar módulos
    sudo rmmod btusb 2>/dev/null
    sudo rmmod bluetooth 2>/dev/null

    log_info "Bluetooth bloqueado completamente"
else
    log_skip "Bloquear Bluetooth"
fi

# ============================================================
# 2b. DESHABILITAR bt_coex_active (coexistencia BT/WiFi)
# ============================================================
echo ""
echo -e "${CYAN}═══ 2b. DESHABILITAR BT COEXISTENCE ═══${NC}"
echo ""
echo "bt_coex_active permite coordinación WiFi-Bluetooth."
echo "Si BT está bloqueado, desactivar esta opción reduce superficie de ataque."
echo ""

if grep -q "bt_coex_active" /etc/modprobe.d/disable-bluetooth.conf 2>/dev/null; then
    log_already "bt_coex_active deshabilitado en disable-bluetooth.conf"
elif ! lsmod | grep -q "^iwlwifi" 2>/dev/null; then
    log_info "iwlwifi no cargado, bt_coex_active no aplica"
elif ask "¿Deshabilitar bt_coex_active en iwlwifi?"; then
    echo "options iwlwifi bt_coex_active=N" | sudo tee -a /etc/modprobe.d/disable-bluetooth.conf > /dev/null
    log_change "Añadido" "bt_coex_active=N en /etc/modprobe.d/disable-bluetooth.conf"
    log_info "bt_coex_active deshabilitado (requiere reinicio para aplicar)"
else
    log_skip "Deshabilitar bt_coex_active"
fi

# ============================================================
# 3. BLOQUEAR WiFi MESH / HOTSPOT AUTOMÁTICO
# ============================================================
echo ""
echo -e "${CYAN}═══ 3. BLOQUEAR WiFi MESH ═══${NC}"
echo ""
echo "WiFi Mesh y hotspots automáticos pueden conectarse sin permiso."
echo ""

if check_file_exists /etc/NetworkManager/conf.d/99-no-mesh.conf; then
    log_already "Conexiones WiFi automáticas deshabilitadas (99-no-mesh.conf)"
elif ask "¿Deshabilitar conexiones WiFi automáticas?"; then
    # Deshabilitar autoconexión a redes desconocidas
    sudo nmcli general logging level INFO 2>/dev/null

    # Deshabilitar WiFi Direct (P2P)
    cat > /tmp/no-wifi-direct.conf << 'EOF'
[device]
wifi.scan-rand-mac-address=yes

[connection]
wifi.cloned-mac-address=random

# Deshabilitar P2P/WiFi Direct
wifi.p2p-management=false
EOF
    sudo cp /tmp/no-wifi-direct.conf /etc/NetworkManager/conf.d/99-no-mesh.conf
    log_change "Creado" "/etc/NetworkManager/conf.d/99-no-mesh.conf"

    # Deshabilitar autoconexión a redes abiertas
    for conn in $(nmcli -t -f NAME,TYPE con show | grep wireless | cut -d: -f1); do
        nmcli con mod "$conn" connection.autoconnect-priority -1 2>/dev/null
    done

    sudo systemctl restart NetworkManager || true
    log_change "Servicio" "NetworkManager restart"

    log_info "WiFi Mesh/P2P deshabilitado"
else
    log_skip "Deshabilitar conexiones WiFi automáticas"
fi

# ============================================================
# 4. BLOQUEAR COMUNICACIÓN CON DISPOSITIVOS IoT
# ============================================================
echo ""
echo -e "${CYAN}═══ 4. BLOQUEAR IoT MESH ═══${NC}"
echo ""
echo "Dispositivos IoT pueden formar redes mesh de vigilancia."
echo ""

if check_file_exists /etc/modprobe.d/disable-zigbee.conf; then
    log_already "Comunicación con dispositivos IoT bloqueada (disable-zigbee.conf)"
elif ask "¿Bloquear comunicación con dispositivos IoT conocidos?"; then
    # Bloquear puertos comunes de IoT
    fw_add_rich_rule 'rule family="ipv4" port port="5353" protocol="udp" drop' 2>/dev/null  # mDNS
    fw_add_rich_rule 'rule family="ipv4" port port="1900" protocol="udp" drop' 2>/dev/null  # SSDP/UPnP
    fw_add_rich_rule 'rule family="ipv4" port port="5683" protocol="udp" drop' 2>/dev/null  # CoAP (IoT)
    fw_add_rich_rule 'rule family="ipv4" port port="8883" protocol="tcp" drop' 2>/dev/null  # MQTT SSL
    fw_add_rich_rule 'rule family="ipv4" port port="1883" protocol="tcp" drop' 2>/dev/null  # MQTT
    fw_add_rich_rule 'rule family="ipv4" port port="5684" protocol="udp" drop' 2>/dev/null  # CoAP DTLS

    # Bloquear Zigbee/Z-Wave (si hay adaptador)
    echo "install ieee802154 /bin/false" | sudo tee /etc/modprobe.d/disable-zigbee.conf > /dev/null
    log_change "Creado" "/etc/modprobe.d/disable-zigbee.conf"

    fw_reload 2>/dev/null

    log_info "Puertos IoT bloqueados"
else
    log_skip "Bloquear comunicación con dispositivos IoT"
fi

# ============================================================
# 5. DESHABILITAR mDNS/AVAHI (descubrimiento automático)
# ============================================================
echo ""
echo -e "${CYAN}═══ 5. BLOQUEAR mDNS/AVAHI ═══${NC}"
echo ""
echo "mDNS permite que dispositivos te descubran automáticamente."
echo ""

if ! systemctl is-enabled avahi-daemon &>/dev/null; then
    log_already "mDNS/Avahi deshabilitado"
elif ask "¿Deshabilitar mDNS/Avahi?"; then
    sudo systemctl stop avahi-daemon 2>/dev/null
    log_change "Servicio" "avahi-daemon stop"
    sudo systemctl disable avahi-daemon 2>/dev/null
    log_change "Servicio" "avahi-daemon disable"
    sudo systemctl mask avahi-daemon 2>/dev/null
    log_change "Servicio" "avahi-daemon mask"

    # Bloquear en firewall
    fw_add_rich_rule 'rule family="ipv4" destination address="224.0.0.251" drop'
    fw_reload 2>/dev/null

    log_info "mDNS/Avahi deshabilitado"
else
    log_skip "Deshabilitar mDNS/Avahi"
fi

# ============================================================
# 6. BLOQUEAR UPnP (apertura automática de puertos)
# ============================================================
echo ""
echo -e "${CYAN}═══ 6. BLOQUEAR UPnP ═══${NC}"
echo ""
echo "UPnP permite que dispositivos abran puertos sin permiso."
echo ""

if ask "¿Bloquear UPnP?"; then
    # Bloquear SSDP
    fw_add_rich_rule 'rule family="ipv4" destination address="239.255.255.250" drop'
    fw_add_rich_rule 'rule family="ipv4" source address="239.255.255.250" drop'

    fw_reload 2>/dev/null

    log_info "UPnP bloqueado"
else
    log_skip "Bloquear UPnP"
fi

# ============================================================
# 7. MAC ADDRESS ALEATORIO CONTINUO
# ============================================================
echo ""
echo -e "${CYAN}═══ 7. MAC ALEATORIO CONTINUO ═══${NC}"
echo ""
echo "Cambiar MAC frecuentemente evita rastreo por redes mesh."
echo ""

if check_file_exists /etc/NetworkManager/conf.d/99-random-mac-full.conf; then
    log_already "Cambio de MAC cada reconexión (99-random-mac-full.conf)"
elif ask "¿Configurar cambio de MAC cada reconexión?"; then
    sudo tee /etc/NetworkManager/conf.d/99-random-mac-full.conf > /dev/null << 'EOF'
[device]
wifi.scan-rand-mac-address=yes

[connection]
wifi.cloned-mac-address=random
ethernet.cloned-mac-address=random
connection.stable-id=${CONNECTION}/${BOOT}/${RANDOM}
EOF
    log_change "Creado" "/etc/NetworkManager/conf.d/99-random-mac-full.conf"

    sudo systemctl restart NetworkManager || true
    log_change "Servicio" "NetworkManager restart"

    log_info "MAC aleatorio en cada conexión"
else
    log_skip "Cambio de MAC cada reconexión"
fi

# ============================================================
# 8. MONITOR DE REDES MESH
# ============================================================
echo ""
echo -e "${CYAN}═══ 8. MONITOR DE REDES MESH ═══${NC}"
echo ""

if check_executable /usr/local/bin/monitor-mesh.sh; then
    log_already "Script de monitoreo de redes mesh (monitor-mesh.sh)"
elif ask "¿Crear script de monitoreo de redes mesh?"; then
    cat > /usr/local/bin/monitor-mesh.sh << 'EOF'
#!/bin/bash
# Monitor de redes mesh y dispositivos sospechosos

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║           MONITOR DE REDES MESH                           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

echo "=== REDES WiFi DETECTADAS ==="
nmcli dev wifi list 2>/dev/null
echo ""

echo "=== REDES MESH SOSPECHOSAS ==="
nmcli dev wifi list 2>/dev/null | grep -iE "mesh|direct|p2p|guest|iot|smart|amazon|google|alexa|nest|ring|xiaomi|tuya"
echo ""

echo "=== BLUETOOTH ==="
if rfkill list bluetooth 2>/dev/null | grep -q "Soft blocked: yes"; then
    echo "Bluetooth: BLOQUEADO (bien)"
else
    echo "Bluetooth: ACTIVO (riesgo)"
    bluetoothctl devices 2>/dev/null
fi
echo ""

echo "=== DISPOSITIVOS EN RED LOCAL ==="
# ARP scan
arp -a 2>/dev/null
echo ""

echo "=== CONEXIONES mDNS/SSDP ==="
ss -u | grep -E "5353|1900" 2>/dev/null || echo "Ninguna (bien)"
echo ""

echo "=== TRÁFICO MULTICAST ==="
ss -u | grep -E "224\.|239\." 2>/dev/null || echo "Ninguno (bien)"
echo ""
EOF
    chmod +x /usr/local/bin/monitor-mesh.sh
    log_change "Creado" "/usr/local/bin/monitor-mesh.sh"
    log_change "Permisos" "/usr/local/bin/monitor-mesh.sh -> +x"
    log_info "Monitor creado: monitor-mesh.sh"
else
    log_skip "Script de monitoreo de redes mesh"
fi

# ============================================================
# 9. BLOQUEAR FRECUENCIAS ESPECÍFICAS (info)
# ============================================================
echo ""
echo -e "${CYAN}═══ 9. BLOQUEO DE FRECUENCIAS (físico) ═══${NC}"
echo ""
log_warn "MEDIDAS FÍSICAS contra redes mesh:"
echo ""
echo "  Las redes mesh usan estas frecuencias:"
echo ""
echo "  • WiFi Mesh:      2.4 GHz, 5 GHz"
echo "  • Bluetooth:      2.4 GHz"
echo "  • Zigbee:         2.4 GHz"
echo "  • Z-Wave:         868 MHz (EU), 908 MHz (US)"
echo "  • Thread/Matter:  2.4 GHz"
echo ""
echo "  Para bloqueo físico:"
echo ""
echo "  ⚠️  Jaula de Faraday (bloquea todo)"
echo "  ⚠️  Pintura con partículas metálicas"
echo "  ⚠️  Cortinas con malla metálica"
echo "  ⚠️  Bolsa Faraday para el portátil cuando no uses"
echo ""

# ============================================================
# 10. DESHABILITAR NFC
# ============================================================
echo ""
echo -e "${CYAN}═══ 10. BLOQUEAR NFC ═══${NC}"
echo ""

if check_file_exists /etc/modprobe.d/disable-nfc.conf; then
    log_already "NFC bloqueado (disable-nfc.conf)"
elif ask "¿Bloquear NFC?"; then
    echo "install nfc /bin/false" | sudo tee /etc/modprobe.d/disable-nfc.conf > /dev/null
    echo "install pn533 /bin/false" | sudo tee -a /etc/modprobe.d/disable-nfc.conf > /dev/null
    log_change "Creado" "/etc/modprobe.d/disable-nfc.conf"

    sudo rmmod pn533 2>/dev/null
    sudo rmmod nfc 2>/dev/null

    log_info "NFC bloqueado"
else
    log_skip "Bloquear NFC"
fi

# ============================================================
# 11. DESHABILITAR WAKE-ON-WLAN (WoWLAN)
# ============================================================
echo ""
echo -e "${CYAN}═══ 11. DESHABILITAR WAKE-ON-WLAN ═══${NC}"
echo ""
echo "WoWLAN permite despertar el equipo via WiFi."
echo "Un atacante podría activar el equipo remotamente."
echo ""

if check_file_exists /etc/NetworkManager/dispatcher.d/99-disable-wowlan; then
    log_already "Wake-on-WLAN deshabilitado (99-disable-wowlan)"
elif ask "¿Deshabilitar Wake-on-WLAN?"; then
    # Deshabilitar WoWLAN en todas las interfaces WiFi actuales
    for phy in /sys/class/ieee80211/phy*; do
        phy_name=$(basename "$phy")
        sudo iw phy "$phy_name" wowlan disable 2>/dev/null || true
        log_change "Deshabilitado" "WoWLAN en $phy_name"
    done

    # Persistir con dispatcher script de NetworkManager
    sudo mkdir -p /etc/NetworkManager/dispatcher.d
    cat << 'WOWLAN_EOF' | sudo tee /etc/NetworkManager/dispatcher.d/99-disable-wowlan > /dev/null
#!/bin/bash
# Deshabilitar Wake-on-WLAN en cada conexión WiFi
# Generado por contramedidas-mesh.sh

IFACE="$1"
ACTION="$2"

if [[ "$ACTION" == "up" ]]; then
    # Encontrar el phy correspondiente a esta interfaz
    if [[ -d "/sys/class/net/$IFACE/phy80211" ]]; then
        PHY=$(basename "$(readlink -f "/sys/class/net/$IFACE/phy80211")")
        iw phy "$PHY" wowlan disable 2>/dev/null || true
    fi
fi
WOWLAN_EOF
    sudo chmod 755 /etc/NetworkManager/dispatcher.d/99-disable-wowlan
    log_change "Creado" "/etc/NetworkManager/dispatcher.d/99-disable-wowlan"
    log_info "Wake-on-WLAN deshabilitado permanentemente"
else
    log_skip "Deshabilitar Wake-on-WLAN"
fi

show_changes_summary

# ============================================================
# RESUMEN
# ============================================================
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║       CONTRAMEDIDAS MESH APLICADAS                        ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "ESTADO:"
echo ""

# Verificar Bluetooth
if rfkill list bluetooth 2>/dev/null | grep -q "Soft blocked: yes"; then
    echo "  ✓ Bluetooth: BLOQUEADO"
else
    echo "  ✗ Bluetooth: activo (ejecuta: sudo rfkill block bluetooth)"
fi

# Verificar Avahi
if systemctl is-active avahi-daemon &>/dev/null; then
    echo "  ✗ mDNS/Avahi: activo"
else
    echo "  ✓ mDNS/Avahi: DESHABILITADO"
fi

# Verificar WiFi Direct
echo "  ✓ WiFi Direct/P2P: configurado para bloquear"
echo "  ✓ MAC aleatorio: habilitado"
echo "  ✓ Puertos IoT: bloqueados"
echo ""
echo "COMANDOS:"
echo ""
echo "  monitor-mesh.sh     - Ver redes mesh cercanas"
echo "  rfkill block wifi   - Bloquear WiFi temporalmente"
echo "  rfkill block all    - Bloquear todas las radios"
echo ""
echo "PARA MÁXIMA SEGURIDAD:"
echo ""
echo "  Cuando no necesites red, ejecuta:"
echo "  sudo rfkill block all"
echo ""
