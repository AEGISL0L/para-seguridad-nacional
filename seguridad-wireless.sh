#!/bin/bash
# ============================================================
# seguridad-wireless.sh - Modulo 56: Seguridad Wireless Empresarial
# ============================================================
# Secciones:
#   S1  - Auditoria de interfaces wireless
#   S2  - Hardening de NetworkManager WiFi
#   S3  - Configuracion WPA3 Enterprise (802.1X)
#   S4  - FreeRADIUS server setup (802.1X authenticator)
#   S5  - Deteccion de rogue APs (puntos de acceso no autorizados)
#   S6  - Proteccion contra ataques wireless
#   S7  - Bluetooth security hardening
#   S8  - Wireless monitoring continuo
#   S9  - Politicas de seguridad wireless
#   S10 - Auditoria integral de seguridad wireless
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps
init_backup "wireless-security"

log_section "MODULO 56: SEGURIDAD WIRELESS EMPRESARIAL"
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

# ── Helpers de deteccion wireless ──────────────────────────

# Detectar interfaces wireless disponibles
detect_wireless_interfaces() {
    local ifaces=()
    local iface
    # Metodo 1: /sys/class/net/*/wireless
    for iface in /sys/class/net/*/wireless; do
        if [[ -d "$iface" ]]; then
            local name
            name=$(basename "$(dirname "$iface")")
            ifaces+=("$name")
        fi
    done
    # Metodo 2: iw dev (si disponible)
    if [[ ${#ifaces[@]} -eq 0 ]] && command -v iw &>/dev/null; then
        while IFS= read -r line; do
            if [[ "$line" =~ Interface ]]; then
                local ifname
                ifname=$(echo "$line" | awk '{print $2}')
                ifaces+=("$ifname")
            fi
        done < <(iw dev 2>/dev/null || true)
    fi
    # Metodo 3: iwconfig (legacy)
    if [[ ${#ifaces[@]} -eq 0 ]] && command -v iwconfig &>/dev/null; then
        while IFS= read -r line; do
            if [[ "$line" =~ ^[a-z] ]] && ! [[ "$line" =~ "no wireless" ]]; then
                local ifname
                ifname=$(echo "$line" | awk '{print $1}')
                ifaces+=("$ifname")
            fi
        done < <(iwconfig 2>/dev/null || true)
    fi
    # Devolver interfaces unicas
    printf '%s\n' "${ifaces[@]}" 2>/dev/null | sort -u
}

# Detectar si el sistema es un servidor (sin escritorio)
is_server_system() {
    # Sin display manager ni escritorio => servidor
    if ! command -v Xorg &>/dev/null && \
       ! command -v wayland &>/dev/null && \
       ! systemctl is-active gdm &>/dev/null && \
       ! systemctl is-active sddm &>/dev/null && \
       ! systemctl is-active lightdm &>/dev/null && \
       [[ -z "${DISPLAY:-}" ]] && [[ -z "${WAYLAND_DISPLAY:-}" ]]; then
        return 0
    fi
    return 1
}

# Obtener driver de una interfaz wireless
get_wireless_driver() {
    local iface="$1"
    local driver_link="/sys/class/net/${iface}/device/driver"
    if [[ -L "$driver_link" ]]; then
        basename "$(readlink -f "$driver_link")" 2>/dev/null || echo "desconocido"
    else
        echo "desconocido"
    fi
}

# Obtener chipset de una interfaz wireless
get_wireless_chipset() {
    local iface="$1"
    local device_path="/sys/class/net/${iface}/device"
    if [[ -f "${device_path}/vendor" ]] && [[ -f "${device_path}/device" ]]; then
        local vendor device_id
        vendor=$(cat "${device_path}/vendor" 2>/dev/null || echo "????")
        device_id=$(cat "${device_path}/device" 2>/dev/null || echo "????")
        echo "${vendor}:${device_id}"
    elif command -v lspci &>/dev/null; then
        lspci 2>/dev/null | grep -i "network\|wireless\|wifi" | head -1 || echo "desconocido"
    else
        echo "desconocido"
    fi
}

# Verificar capacidad de modo monitor
check_monitor_mode() {
    local iface="$1"
    if command -v iw &>/dev/null; then
        iw phy "$(cat /sys/class/net/"${iface}"/phy80211/name 2>/dev/null || echo "phy0")" info 2>/dev/null | \
            grep -q "monitor" && return 0
    fi
    return 1
}

# Verificar capacidad de modo AP
check_ap_mode() {
    local iface="$1"
    if command -v iw &>/dev/null; then
        iw phy "$(cat /sys/class/net/"${iface}"/phy80211/name 2>/dev/null || echo "phy0")" info 2>/dev/null | \
            grep -q "AP" && return 0
    fi
    return 1
}

# Obtener modulos kernel wireless cargados
get_wireless_modules() {
    lsmod 2>/dev/null | grep -iE 'iwl|ath|rt2|rtl|b43|brcm|mt76|mwl|wl|cfg80211|mac80211' | awk '{print $1}' || true
}

# Directorio de configuracion securizar
mkdir -p /etc/securizar
mkdir -p /var/log/securizar

# ============================================================
# S1: AUDITORIA DE INTERFACES WIRELESS
# ============================================================
log_section "S1: AUDITORIA DE INTERFACES WIRELESS"

log_info "Auditoria de interfaces wireless:"
log_info "  - Deteccion de interfaces: iw dev, iwconfig, /sys/class/net"
log_info "  - Driver, chipset, capacidades (monitor, AP)"
log_info "  - Evaluacion: wireless necesario (servidor vs escritorio)"
log_info "  - Opcion: deshabilitar wireless en servidores"
log_info "  - Script: /usr/local/bin/auditar-wireless.sh"

if ask "¿Realizar auditoria de interfaces wireless?"; then

    # Instalar herramientas wireless si no estan
    if ! command -v iw &>/dev/null; then
        log_warn "iw no encontrado - instalando herramientas wireless..."
        case "$DISTRO_FAMILY" in
            suse)   zypper --non-interactive install iw wireless-tools || true ;;
            debian) DEBIAN_FRONTEND=noninteractive apt-get install -y iw wireless-tools || true ;;
            rhel)   dnf install -y iw wireless-tools || true ;;
            arch)   pacman -S --noconfirm iw wireless_tools || true ;;
        esac
        log_change "Instalado" "herramientas wireless (iw, wireless-tools)"
    fi

    # Instalar rfkill si no esta
    if ! command -v rfkill &>/dev/null; then
        case "$DISTRO_FAMILY" in
            suse)   zypper --non-interactive install util-linux || true ;;
            debian) DEBIAN_FRONTEND=noninteractive apt-get install -y rfkill || true ;;
            rhel)   dnf install -y util-linux || true ;;
            arch)   pacman -S --noconfirm util-linux || true ;;
        esac
        log_change "Instalado" "rfkill"
    fi

    # Enumerar interfaces wireless
    log_info "Detectando interfaces wireless..."
    WIRELESS_IFACES=()
    while IFS= read -r wif; do
        [[ -n "$wif" ]] && WIRELESS_IFACES+=("$wif")
    done < <(detect_wireless_interfaces)

    if [[ ${#WIRELESS_IFACES[@]} -eq 0 ]]; then
        log_info "No se detectaron interfaces wireless en el sistema"
        log_info "Verificando modulos kernel wireless cargados..."
        local loaded_modules
        loaded_modules=$(get_wireless_modules)
        if [[ -n "$loaded_modules" ]]; then
            log_warn "Modulos wireless cargados sin interfaces activas:"
            while IFS= read -r mod; do
                log_warn "  - $mod"
            done <<< "$loaded_modules"
        else
            log_info "No hay modulos wireless cargados - sistema sin hardware wireless"
        fi
    else
        log_info "Interfaces wireless detectadas: ${#WIRELESS_IFACES[@]}"
        for wif in "${WIRELESS_IFACES[@]}"; do
            local driver chipset has_monitor has_ap
            driver=$(get_wireless_driver "$wif")
            chipset=$(get_wireless_chipset "$wif")
            has_monitor="No"
            has_ap="No"
            if check_monitor_mode "$wif" 2>/dev/null; then
                has_monitor="Si"
            fi
            if check_ap_mode "$wif" 2>/dev/null; then
                has_ap="Si"
            fi
            log_info "  Interfaz: $wif"
            log_info "    Driver:       $driver"
            log_info "    Chipset:      $chipset"
            log_info "    Modo monitor: $has_monitor"
            log_info "    Modo AP:      $has_ap"

            # Estado de la interfaz
            local state
            state=$(cat "/sys/class/net/${wif}/operstate" 2>/dev/null || echo "desconocido")
            log_info "    Estado:       $state"

            # Direccion MAC
            local mac
            mac=$(cat "/sys/class/net/${wif}/address" 2>/dev/null || echo "desconocida")
            log_info "    MAC:          $mac"
        done
        log_change "Auditado" "interfaces wireless: ${WIRELESS_IFACES[*]}"
    fi

    # Evaluar si wireless es necesario
    if is_server_system; then
        log_warn "Sistema detectado como SERVIDOR - wireless normalmente no es necesario"
        if [[ ${#WIRELESS_IFACES[@]} -gt 0 ]]; then
            if ask "¿Deshabilitar wireless en este servidor (rfkill + blacklist modulos)?"; then
                # rfkill block wifi
                if command -v rfkill &>/dev/null; then
                    rfkill block wifi 2>/dev/null || true
                    log_change "Bloqueado" "wireless via rfkill block wifi"
                fi

                # Blacklist de modulos wireless
                local blacklist_file="/etc/modprobe.d/securizar-no-wireless.conf"
                if [[ -f "$blacklist_file" ]]; then
                    cp -a "$blacklist_file" "$BACKUP_DIR/"
                fi
                cat > "$blacklist_file" << 'EOFBLACKLIST'
# ============================================================
# securizar - Modulo 56: Wireless deshabilitado en servidor
# Generado automaticamente - no editar manualmente
# ============================================================
# Intel wireless
blacklist iwlwifi
blacklist iwlmvm
blacklist iwldvm
# Atheros
blacklist ath9k
blacklist ath9k_htc
blacklist ath10k_pci
blacklist ath10k_core
blacklist ath11k
blacklist ath11k_pci
# Realtek
blacklist rtl8xxxu
blacklist rtl8192ce
blacklist rtl8192cu
blacklist rtl8192de
blacklist rtl8192ee
blacklist rtl8723be
blacklist rtl8821ae
blacklist rtlwifi
blacklist rtw88_pci
blacklist rtw88_usb
blacklist rtw89_pci
# Broadcom
blacklist brcmfmac
blacklist brcmsmac
blacklist b43
blacklist b43legacy
blacklist wl
# MediaTek
blacklist mt7601u
blacklist mt76x0u
blacklist mt76x2u
blacklist mt7921e
# Ralink
blacklist rt2800pci
blacklist rt2800usb
blacklist rt2x00lib
# Generic 802.11
blacklist cfg80211
blacklist mac80211
EOFBLACKLIST
                chmod 644 "$blacklist_file"
                log_change "Creado" "$blacklist_file (blacklist modulos wireless)"

                # Descargar modulos cargados
                local loaded_mods
                loaded_mods=$(get_wireless_modules)
                if [[ -n "$loaded_mods" ]]; then
                    while IFS= read -r mod; do
                        modprobe -r "$mod" 2>/dev/null || true
                        log_change "Descargado" "modulo kernel: $mod"
                    done <<< "$loaded_mods"
                fi
                log_info "Wireless deshabilitado en servidor. Reboot recomendado para aplicar blacklist."
            else
                log_skip "deshabilitar wireless en servidor"
            fi
        fi
    else
        log_info "Sistema con escritorio detectado - wireless puede ser necesario"
    fi

    # Crear script de auditoria wireless
    log_info "Creando script /usr/local/bin/auditar-wireless.sh..."
    cat > /usr/local/bin/auditar-wireless.sh << 'EOFAUDITWIFI'
#!/bin/bash
# ============================================================
# auditar-wireless.sh - Auditoria de interfaces wireless
# Generado por securizar - Modulo 56
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  AUDITORIA DE INTERFACES WIRELESS${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""
echo -e "${DIM}Fecha: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo ""

# Detectar interfaces wireless
echo -e "${CYAN}[1] Interfaces wireless detectadas:${NC}"
iface_count=0
for wdir in /sys/class/net/*/wireless; do
    if [[ -d "$wdir" ]]; then
        iface=$(basename "$(dirname "$wdir")")
        ((iface_count++))
        echo -e "  ${GREEN}[+]${NC} Interfaz: ${BOLD}${iface}${NC}"
        # Driver
        if [[ -L "/sys/class/net/${iface}/device/driver" ]]; then
            drv=$(basename "$(readlink -f "/sys/class/net/${iface}/device/driver")")
            echo -e "      Driver:  $drv"
        fi
        # Estado
        state=$(cat "/sys/class/net/${iface}/operstate" 2>/dev/null || echo "?")
        echo -e "      Estado:  $state"
        # MAC
        mac=$(cat "/sys/class/net/${iface}/address" 2>/dev/null || echo "?")
        echo -e "      MAC:     $mac"
        # Capacidades
        if command -v iw &>/dev/null; then
            phy=$(cat "/sys/class/net/${iface}/phy80211/name" 2>/dev/null || echo "phy0")
            if iw phy "$phy" info 2>/dev/null | grep -q "monitor"; then
                echo -e "      Monitor: ${YELLOW}Si (riesgo si no es necesario)${NC}"
            else
                echo -e "      Monitor: ${GREEN}No${NC}"
            fi
            if iw phy "$phy" info 2>/dev/null | grep -q "AP"; then
                echo -e "      AP:      ${YELLOW}Si${NC}"
            else
                echo -e "      AP:      No"
            fi
            # Bandas soportadas
            bands=$(iw phy "$phy" info 2>/dev/null | grep -c "Band" || echo "0")
            echo -e "      Bandas:  $bands"
        fi
        echo ""
    fi
done
if [[ $iface_count -eq 0 ]]; then
    echo -e "  ${GREEN}[+]${NC} No se detectaron interfaces wireless"
    # Verificar si hay modulos cargados
    if command -v iw &>/dev/null; then
        iw_devs=$(iw dev 2>/dev/null | grep -c "Interface" || echo "0")
        if [[ "$iw_devs" -gt 0 ]]; then
            echo -e "  ${YELLOW}[!]${NC} iw reporta $iw_devs interfaces (revisar manualmente)"
        fi
    fi
fi
echo ""

# rfkill status
echo -e "${CYAN}[2] Estado rfkill:${NC}"
if command -v rfkill &>/dev/null; then
    rfkill list 2>/dev/null | while IFS= read -r line; do
        echo "  $line"
    done
else
    echo -e "  ${YELLOW}[!]${NC} rfkill no disponible"
fi
echo ""

# Modulos wireless cargados
echo -e "${CYAN}[3] Modulos wireless cargados en kernel:${NC}"
mods=$(lsmod 2>/dev/null | grep -iE 'iwl|ath|rt2|rtl|b43|brcm|mt76|wl|cfg80211|mac80211' | awk '{print $1}')
if [[ -n "$mods" ]]; then
    while IFS= read -r m; do
        echo -e "  ${YELLOW}[!]${NC} $m"
    done <<< "$mods"
else
    echo -e "  ${GREEN}[+]${NC} No hay modulos wireless cargados"
fi
echo ""

# Blacklists existentes
echo -e "${CYAN}[4] Blacklists de modulos wireless:${NC}"
if ls /etc/modprobe.d/*wireless* /etc/modprobe.d/*wifi* 2>/dev/null | head -5; then
    true
else
    echo -e "  ${DIM}No hay blacklists wireless en /etc/modprobe.d/${NC}"
fi
echo ""

# Redes WiFi conocidas (NetworkManager)
echo -e "${CYAN}[5] Redes WiFi guardadas (NetworkManager):${NC}"
nm_conns="/etc/NetworkManager/system-connections"
if [[ -d "$nm_conns" ]]; then
    wifi_count=0
    for conn in "$nm_conns"/*; do
        if [[ -f "$conn" ]] && grep -q "type=wifi" "$conn" 2>/dev/null; then
            ssid=$(grep "^ssid=" "$conn" 2>/dev/null | cut -d= -f2-)
            security=$(grep "^key-mgmt=" "$conn" 2>/dev/null | cut -d= -f2- || echo "open")
            echo -e "  - SSID: ${BOLD}${ssid:-?}${NC} | Seguridad: ${security:-open}"
            ((wifi_count++))
        fi
    done
    if [[ $wifi_count -eq 0 ]]; then
        echo -e "  ${GREEN}[+]${NC} No hay redes WiFi guardadas"
    fi
else
    echo -e "  ${DIM}NetworkManager no encontrado${NC}"
fi
echo ""

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  Auditoria wireless completada${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
EOFAUDITWIFI
    chmod +x /usr/local/bin/auditar-wireless.sh
    log_change "Creado" "/usr/local/bin/auditar-wireless.sh"

else
    log_skip "auditoria de interfaces wireless"
fi

# ============================================================
# S2: HARDENING DE NETWORKMANAGER WIFI
# ============================================================
log_section "S2: HARDENING DE NETWORKMANAGER WIFI"

log_info "Hardening de configuracion WiFi en NetworkManager:"
log_info "  - Deshabilitar auto-connect a redes abiertas"
log_info "  - MAC randomization en escaneo (wifi.scan-rand-mac-address=yes)"
log_info "  - MAC clonado aleatorio por conexion"
log_info "  - Requerir PMF/802.11w (pmf=2)"
log_info "  - Preferir WPA3-SAE sobre WPA2"
log_info "  - Purgar perfiles de redes abiertas guardadas"

if ask "¿Aplicar hardening de NetworkManager WiFi?"; then

    NM_CONF_DIR="/etc/NetworkManager/conf.d"
    NM_CONN_DIR="/etc/NetworkManager/system-connections"

    if [[ -d "/etc/NetworkManager" ]]; then
        mkdir -p "$NM_CONF_DIR"

        # Backup de config existente si existe
        if [[ -f "${NM_CONF_DIR}/99-securizar-wifi.conf" ]]; then
            cp -a "${NM_CONF_DIR}/99-securizar-wifi.conf" "$BACKUP_DIR/"
            log_change "Backup" "${NM_CONF_DIR}/99-securizar-wifi.conf"
        fi

        # Crear configuracion de hardening WiFi
        cat > "${NM_CONF_DIR}/99-securizar-wifi.conf" << 'EOFNMWIFI'
# ============================================================
# NetworkManager WiFi hardening - securizar Modulo 56
# Generado automaticamente - no editar manualmente
# ============================================================

[device]
# MAC randomization durante escaneo WiFi
wifi.scan-rand-mac-address=yes

[connection]
# MAC aleatorio por conexion (proteccion de privacidad)
wifi.cloned-mac-address=random
# Timeouts de conexion seguros
connection.auth-retries=3

[connectivity]
# Deshabilitar comprobacion de conectividad (evita leak de info)
enabled=false

[main]
# No auto-conectar a redes WiFi abiertas
no-auto-default=*
EOFNMWIFI
        chmod 644 "${NM_CONF_DIR}/99-securizar-wifi.conf"
        log_change "Creado" "${NM_CONF_DIR}/99-securizar-wifi.conf"

        # Verificar y modificar perfiles de conexion existentes
        if [[ -d "$NM_CONN_DIR" ]]; then
            local open_networks=0
            local total_wifi=0

            for conn_file in "$NM_CONN_DIR"/*; do
                [[ -f "$conn_file" ]] || continue
                if grep -q "type=wifi" "$conn_file" 2>/dev/null || \
                   grep -q "type=802-11-wireless" "$conn_file" 2>/dev/null; then
                    ((total_wifi++)) || true

                    local conn_name
                    conn_name=$(basename "$conn_file")

                    # Detectar redes abiertas (sin key-mgmt o key-mgmt=none)
                    if ! grep -q "key-mgmt=" "$conn_file" 2>/dev/null || \
                       grep -q "key-mgmt=none" "$conn_file" 2>/dev/null; then
                        ((open_networks++)) || true
                        log_warn "Red abierta detectada: $conn_name"
                    fi

                    # Verificar si tiene PMF habilitado
                    if ! grep -q "pmf=" "$conn_file" 2>/dev/null; then
                        log_info "  Conexion sin PMF: $conn_name"
                    fi
                fi
            done

            log_info "Total conexiones WiFi guardadas: $total_wifi"
            log_info "Redes abiertas detectadas: $open_networks"

            # Purgar redes abiertas
            if [[ $open_networks -gt 0 ]]; then
                if ask "¿Eliminar $open_networks perfiles de redes WiFi abiertas?"; then
                    for conn_file in "$NM_CONN_DIR"/*; do
                        [[ -f "$conn_file" ]] || continue
                        if grep -q "type=wifi" "$conn_file" 2>/dev/null || \
                           grep -q "type=802-11-wireless" "$conn_file" 2>/dev/null; then
                            if ! grep -q "key-mgmt=" "$conn_file" 2>/dev/null || \
                               grep -q "key-mgmt=none" "$conn_file" 2>/dev/null; then
                                local conn_name
                                conn_name=$(basename "$conn_file")
                                cp -a "$conn_file" "$BACKUP_DIR/"
                                rm -f "$conn_file"
                                log_change "Eliminado" "perfil de red abierta: $conn_name"
                            fi
                        fi
                    done
                else
                    log_skip "eliminar perfiles de redes abiertas"
                fi
            fi

            # Agregar PMF a conexiones WiFi existentes que no lo tengan
            if ask "¿Forzar PMF (802.11w) en todas las conexiones WiFi existentes?"; then
                for conn_file in "$NM_CONN_DIR"/*; do
                    [[ -f "$conn_file" ]] || continue
                    if grep -q "type=wifi" "$conn_file" 2>/dev/null || \
                       grep -q "type=802-11-wireless" "$conn_file" 2>/dev/null; then
                        # Solo si tiene seguridad y no tiene PMF
                        if grep -q "key-mgmt=" "$conn_file" 2>/dev/null && \
                           ! grep -q "pmf=" "$conn_file" 2>/dev/null; then
                            cp -a "$conn_file" "$BACKUP_DIR/"
                            # Agregar pmf=2 (requerido) en la seccion de seguridad
                            if grep -q "\[wifi-security\]" "$conn_file" 2>/dev/null || \
                               grep -q "\[802-11-wireless-security\]" "$conn_file" 2>/dev/null; then
                                sed -i '/\[wifi-security\]/a pmf=2' "$conn_file" 2>/dev/null || \
                                sed -i '/\[802-11-wireless-security\]/a pmf=2' "$conn_file" 2>/dev/null || true
                            else
                                cat >> "$conn_file" << 'EOFPMF'

[wifi-security]
pmf=2
EOFPMF
                            fi
                            local conn_name
                            conn_name=$(basename "$conn_file")
                            log_change "Configurado" "PMF=2 (requerido) en: $conn_name"
                        fi
                    fi
                done
            else
                log_skip "forzar PMF en conexiones WiFi existentes"
            fi
        fi

        # Recargar NetworkManager si esta activo
        if systemctl is-active NetworkManager &>/dev/null; then
            systemctl reload NetworkManager 2>/dev/null || \
                systemctl restart NetworkManager 2>/dev/null || true
            log_change "Recargado" "NetworkManager con nueva configuracion WiFi"
        fi

    else
        log_warn "NetworkManager no encontrado en /etc/NetworkManager"
        log_info "Si usa otro gestor de red (systemd-networkd, wpa_supplicant directo),"
        log_info "configure manualmente las opciones de seguridad wireless."
    fi

else
    log_skip "hardening de NetworkManager WiFi"
fi

# ============================================================
# S3: CONFIGURACION WPA3 ENTERPRISE (802.1X)
# ============================================================
log_section "S3: CONFIGURACION WPA3 ENTERPRISE (802.1X)"

log_info "Plantillas de configuracion WPA3 Enterprise:"
log_info "  - EAP-TLS (autenticacion por certificado, mas seguro)"
log_info "  - EAP-PEAP (con MSCHAPv2, mas simple)"
log_info "  - EAP-TTLS (autenticacion interna flexible)"
log_info "  - wpa_supplicant.conf templates"
log_info "  - Guia de colocacion de certificados"

if ask "¿Crear plantillas de configuracion WPA3 Enterprise?"; then

    WIFI_ENTERPRISE_DIR="/etc/securizar/wifi-enterprise"
    mkdir -p "$WIFI_ENTERPRISE_DIR"
    chmod 700 "$WIFI_ENTERPRISE_DIR"

    # Instalar ca-certificates si no esta
    if ! command -v update-ca-certificates &>/dev/null && \
       ! command -v update-ca-trust &>/dev/null; then
        log_info "Instalando ca-certificates..."
        case "$DISTRO_FAMILY" in
            suse)   zypper --non-interactive install ca-certificates || true ;;
            debian) DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates || true ;;
            rhel)   dnf install -y ca-certificates || true ;;
            arch)   pacman -S --noconfirm ca-certificates || true ;;
        esac
        log_change "Instalado" "ca-certificates"
    fi

    # Template: EAP-TLS NetworkManager profile
    cat > "${WIFI_ENTERPRISE_DIR}/nm-eap-tls.nmconnection" << 'EOFEAPTLS'
# ============================================================
# NetworkManager: WPA3 Enterprise EAP-TLS (Certificado)
# Generado por securizar - Modulo 56
# ============================================================
# Copiar a /etc/NetworkManager/system-connections/ y adaptar
# chmod 600 este archivo despues de configurar

[connection]
id=Enterprise-EAP-TLS
uuid=CAMBIAR-UUID-AQUI
type=wifi
autoconnect=true

[wifi]
ssid=NOMBRE-RED-ENTERPRISE
mode=infrastructure
# MAC aleatorio por conexion
cloned-mac-address=random

[wifi-security]
key-mgmt=wpa-eap
# PMF requerido (802.11w)
pmf=2
# Preferir WPA3
proto=rsn
group=ccmp
pairwise=ccmp

[802-1x]
eap=tls
identity=usuario@empresa.com
# Certificado CA del servidor RADIUS
ca-cert=/etc/securizar/wifi-enterprise/certs/ca.pem
# Certificado del cliente
client-cert=/etc/securizar/wifi-enterprise/certs/client.pem
# Clave privada del cliente
private-key=/etc/securizar/wifi-enterprise/certs/client-key.pem
private-key-password=CAMBIAR-PASSWORD-AQUI
# Verificacion del nombre del servidor RADIUS
altsubject-matches=DNS:radius.empresa.com
# Fase 2 no necesaria con TLS puro
domain-suffix-match=empresa.com

[ipv4]
method=auto

[ipv6]
method=auto
addr-gen-mode=stable-privacy
EOFEAPTLS
    chmod 600 "${WIFI_ENTERPRISE_DIR}/nm-eap-tls.nmconnection"
    log_change "Creado" "${WIFI_ENTERPRISE_DIR}/nm-eap-tls.nmconnection"

    # Template: EAP-PEAP NetworkManager profile
    cat > "${WIFI_ENTERPRISE_DIR}/nm-eap-peap.nmconnection" << 'EOFEAPPEAP'
# ============================================================
# NetworkManager: WPA3 Enterprise EAP-PEAP (MSCHAPv2)
# Generado por securizar - Modulo 56
# ============================================================
# Copiar a /etc/NetworkManager/system-connections/ y adaptar
# chmod 600 este archivo despues de configurar
# NOTA: EAP-TLS es preferible. Use PEAP solo si no dispone de PKI

[connection]
id=Enterprise-EAP-PEAP
uuid=CAMBIAR-UUID-AQUI
type=wifi
autoconnect=true

[wifi]
ssid=NOMBRE-RED-ENTERPRISE
mode=infrastructure
cloned-mac-address=random

[wifi-security]
key-mgmt=wpa-eap
pmf=2
proto=rsn
group=ccmp
pairwise=ccmp

[802-1x]
eap=peap
identity=usuario@empresa.com
# Certificado CA del servidor RADIUS
ca-cert=/etc/securizar/wifi-enterprise/certs/ca.pem
# Verificacion del nombre del servidor RADIUS
altsubject-matches=DNS:radius.empresa.com
domain-suffix-match=empresa.com
# Fase 2: MSCHAPv2
phase2-auth=mschapv2
# Guardar password (cifrado en keyring)
password-flags=0

[ipv4]
method=auto

[ipv6]
method=auto
addr-gen-mode=stable-privacy
EOFEAPPEAP
    chmod 600 "${WIFI_ENTERPRISE_DIR}/nm-eap-peap.nmconnection"
    log_change "Creado" "${WIFI_ENTERPRISE_DIR}/nm-eap-peap.nmconnection"

    # Template: EAP-TTLS NetworkManager profile
    cat > "${WIFI_ENTERPRISE_DIR}/nm-eap-ttls.nmconnection" << 'EOFEAPTTLS'
# ============================================================
# NetworkManager: WPA3 Enterprise EAP-TTLS
# Generado por securizar - Modulo 56
# ============================================================
# Copiar a /etc/NetworkManager/system-connections/ y adaptar
# chmod 600 este archivo despues de configurar

[connection]
id=Enterprise-EAP-TTLS
uuid=CAMBIAR-UUID-AQUI
type=wifi
autoconnect=true

[wifi]
ssid=NOMBRE-RED-ENTERPRISE
mode=infrastructure
cloned-mac-address=random

[wifi-security]
key-mgmt=wpa-eap
pmf=2
proto=rsn
group=ccmp
pairwise=ccmp

[802-1x]
eap=ttls
identity=usuario@empresa.com
# Certificado CA del servidor RADIUS
ca-cert=/etc/securizar/wifi-enterprise/certs/ca.pem
# Verificacion del nombre del servidor RADIUS
altsubject-matches=DNS:radius.empresa.com
domain-suffix-match=empresa.com
# Autenticacion interna: PAP, MSCHAP, MSCHAPv2 o EAP-*
phase2-auth=mschapv2
# Anonimato del outer identity
anonymous-identity=anonymous@empresa.com
password-flags=0

[ipv4]
method=auto

[ipv6]
method=auto
addr-gen-mode=stable-privacy
EOFEAPTTLS
    chmod 600 "${WIFI_ENTERPRISE_DIR}/nm-eap-ttls.nmconnection"
    log_change "Creado" "${WIFI_ENTERPRISE_DIR}/nm-eap-ttls.nmconnection"

    # Template: wpa_supplicant.conf para Enterprise WiFi
    cat > "${WIFI_ENTERPRISE_DIR}/wpa_supplicant-enterprise.conf" << 'EOFWPASUP'
# ============================================================
# wpa_supplicant.conf - Configuracion WPA3 Enterprise
# Generado por securizar - Modulo 56
# ============================================================
# Usar con: wpa_supplicant -c /etc/securizar/wifi-enterprise/wpa_supplicant-enterprise.conf -i wlan0
# Adaptar segun sus necesidades

ctrl_interface=/var/run/wpa_supplicant
ctrl_interface_group=0
update_config=0

# Deshabilitar escaneo de redes abiertas
ap_scan=1

# Preferir WPA3
pmf=2

# ── Red EAP-TLS (mas seguro) ──────────────────────────────
network={
    ssid="NOMBRE-RED-ENTERPRISE"
    key_mgmt=WPA-EAP WPA-EAP-SHA256 SAE
    eap=TLS
    identity="usuario@empresa.com"
    ca_cert="/etc/securizar/wifi-enterprise/certs/ca.pem"
    client_cert="/etc/securizar/wifi-enterprise/certs/client.pem"
    private_key="/etc/securizar/wifi-enterprise/certs/client-key.pem"
    private_key_passwd="CAMBIAR-PASSWORD"
    # Verificacion del servidor
    domain_suffix_match="empresa.com"
    # Requerir PMF
    ieee80211w=2
    # Prioridad alta
    priority=10
    # Deshabilitar PMKID caching (prevencion de ataques)
    disable_pmksa_caching=1
}

# ── Red EAP-PEAP (alternativa) ────────────────────────────
#network={
#    ssid="NOMBRE-RED-PEAP"
#    key_mgmt=WPA-EAP WPA-EAP-SHA256
#    eap=PEAP
#    identity="usuario@empresa.com"
#    anonymous_identity="anonymous@empresa.com"
#    password="CAMBIAR-PASSWORD"
#    ca_cert="/etc/securizar/wifi-enterprise/certs/ca.pem"
#    phase2="auth=MSCHAPV2"
#    domain_suffix_match="empresa.com"
#    ieee80211w=2
#    priority=5
#    disable_pmksa_caching=1
#}

# ── Red EAP-TTLS ──────────────────────────────────────────
#network={
#    ssid="NOMBRE-RED-TTLS"
#    key_mgmt=WPA-EAP WPA-EAP-SHA256
#    eap=TTLS
#    identity="usuario@empresa.com"
#    anonymous_identity="anonymous@empresa.com"
#    password="CAMBIAR-PASSWORD"
#    ca_cert="/etc/securizar/wifi-enterprise/certs/ca.pem"
#    phase2="auth=MSCHAPV2"
#    domain_suffix_match="empresa.com"
#    ieee80211w=2
#    priority=5
#    disable_pmksa_caching=1
#}
EOFWPASUP
    chmod 600 "${WIFI_ENTERPRISE_DIR}/wpa_supplicant-enterprise.conf"
    log_change "Creado" "${WIFI_ENTERPRISE_DIR}/wpa_supplicant-enterprise.conf"

    # Guia de colocacion de certificados
    mkdir -p "${WIFI_ENTERPRISE_DIR}/certs"
    chmod 700 "${WIFI_ENTERPRISE_DIR}/certs"

    cat > "${WIFI_ENTERPRISE_DIR}/certs/README-certificados.txt" << 'EOFCERTGUIDE'
# ============================================================
# Guia de colocacion de certificados WiFi Enterprise
# Generado por securizar - Modulo 56
# ============================================================

Estructura de directorios:
  /etc/securizar/wifi-enterprise/certs/
    |-- ca.pem              # Certificado CA del servidor RADIUS
    |-- client.pem          # Certificado del cliente (EAP-TLS)
    |-- client-key.pem      # Clave privada del cliente (EAP-TLS)
    |-- server-ca.pem       # CA alternativo si se usan multiples

Instrucciones:
  1. Obtener el certificado CA de su departamento de TI
  2. Para EAP-TLS: solicitar certificado de cliente firmado por la CA
  3. Colocar los archivos en este directorio
  4. Permisos: chmod 600 para archivos de clave privada
  5. Permisos: chmod 644 para certificados CA publicos

Generacion de certificado de cliente (ejemplo con OpenSSL):
  # Generar clave privada
  openssl genrsa -aes256 -out client-key.pem 4096

  # Generar CSR (Certificate Signing Request)
  openssl req -new -key client-key.pem -out client.csr \
      -subj "/CN=usuario@empresa.com/O=Empresa/C=ES"

  # Enviar client.csr al administrador de la CA para firma
  # El administrador devolvera client.pem (certificado firmado)

Verificacion:
  # Verificar que el certificado del cliente es valido contra la CA
  openssl verify -CAfile ca.pem client.pem

  # Ver detalles del certificado
  openssl x509 -in client.pem -text -noout

  # Verificar que clave privada coincide con certificado
  openssl x509 -noout -modulus -in client.pem | openssl md5
  openssl rsa -noout -modulus -in client-key.pem | openssl md5
  # Ambos deben dar el mismo hash
EOFCERTGUIDE
    chmod 644 "${WIFI_ENTERPRISE_DIR}/certs/README-certificados.txt"
    log_change "Creado" "${WIFI_ENTERPRISE_DIR}/certs/README-certificados.txt"

    log_info "Plantillas WPA3 Enterprise creadas en: $WIFI_ENTERPRISE_DIR"
    log_info "Adapte los archivos con sus credenciales y certificados."

else
    log_skip "plantillas WPA3 Enterprise"
fi

# ============================================================
# S4: FREERADIUS SERVER SETUP (802.1X AUTHENTICATOR)
# ============================================================
log_section "S4: FREERADIUS SERVER SETUP (802.1X AUTHENTICATOR)"

log_info "Configuracion de servidor FreeRADIUS para 802.1X:"
log_info "  - Instalacion de FreeRADIUS"
log_info "  - Templates: radiusd.conf, clients.conf, users, EAP"
log_info "  - Script de generacion de certificados"
log_info "  - Hardening systemd override"
log_info "  - Script: /usr/local/bin/securizar-radius-setup.sh"

if ask "¿Configurar plantillas de servidor FreeRADIUS?"; then

    RADIUS_CONF_DIR="/etc/securizar/freeradius"
    mkdir -p "$RADIUS_CONF_DIR"
    chmod 700 "$RADIUS_CONF_DIR"

    # Verificar si FreeRADIUS esta instalado
    if command -v radiusd &>/dev/null || command -v freeradius &>/dev/null; then
        log_info "FreeRADIUS ya esta instalado en el sistema"
    else
        log_warn "FreeRADIUS no esta instalado"
        if ask "¿Instalar FreeRADIUS?"; then
            case "$DISTRO_FAMILY" in
                suse)   zypper --non-interactive install freeradius-server freeradius-server-utils || true ;;
                debian) DEBIAN_FRONTEND=noninteractive apt-get install -y freeradius freeradius-utils || true ;;
                rhel)   dnf install -y freeradius freeradius-utils || true ;;
                arch)   pacman -S --noconfirm freeradius || true ;;
            esac
            log_change "Instalado" "FreeRADIUS"
        else
            log_skip "instalacion de FreeRADIUS"
        fi
    fi

    # Template: radiusd.conf
    cat > "${RADIUS_CONF_DIR}/radiusd.conf.template" << 'EOFRADIUSD'
# ============================================================
# radiusd.conf - Configuracion FreeRADIUS hardened
# Generado por securizar - Modulo 56
# ============================================================
# TEMPLATE - Adaptar antes de usar en produccion
# Copiar a /etc/raddb/radiusd.conf o /etc/freeradius/3.0/radiusd.conf
# ============================================================

prefix = /usr
exec_prefix = /usr
sysconfdir = /etc
localstatedir = /var
sbindir = ${exec_prefix}/sbin
logdir = /var/log/freeradius
raddbdir = /etc/raddb
radacctdir = ${logdir}/radacct
run_dir = ${localstatedir}/run/radiusd

# ── Seguridad: usuario no-root ────────────────────────────
name = radiusd
user = radiusd
group = radiusd

# ── Logging seguro ────────────────────────────────────────
log {
    destination = files
    file = ${logdir}/radius.log
    syslog_facility = daemon
    # Log de autenticacion (para auditoria)
    auth = yes
    auth_badpass = yes
    auth_goodpass = no
    # Log completo de solicitudes
    stripped_names = no
}

# ── TLS global ────────────────────────────────────────────
security {
    # Restringir acceso al directorio de configuracion
    allow_core_dumps = no
    max_attributes = 200
    reject_delay = 1
    status_server = yes
    # Limitar solicitudes simultaneas
    max_requests = 16384
}

# ── Thread pool ───────────────────────────────────────────
thread pool {
    start_servers = 5
    max_servers = 32
    min_spare_servers = 3
    max_spare_servers = 10
    max_requests_per_server = 0
    auto_limit_acct = no
}

# ── Modulos ───────────────────────────────────────────────
instantiate {
}

# Incluir modulos
$INCLUDE ${confdir}/mods-enabled/

# Incluir sites
$INCLUDE ${confdir}/sites-enabled/

# Incluir clients
$INCLUDE ${confdir}/clients.conf
EOFRADIUSD
    chmod 640 "${RADIUS_CONF_DIR}/radiusd.conf.template"
    log_change "Creado" "${RADIUS_CONF_DIR}/radiusd.conf.template"

    # Template: clients.conf
    cat > "${RADIUS_CONF_DIR}/clients.conf.template" << 'EOFCLIENTS'
# ============================================================
# clients.conf - APs y NAS autorizados
# Generado por securizar - Modulo 56
# ============================================================
# TEMPLATE - Agregar sus APs y switches autorizados
# ============================================================

# Localhost (para testing)
client localhost {
    ipaddr = 127.0.0.1
    proto = *
    secret = CAMBIAR-SECRET-LOCALHOST
    require_message_authenticator = yes
    nas_type = other
    limit {
        max_connections = 16
        lifetime = 0
        idle_timeout = 30
    }
}

# ── Ejemplo: Access Point 1 ──────────────────────────────
#client ap-oficina-1 {
#    ipaddr = 192.168.1.10
#    secret = CAMBIAR-SECRET-AP1
#    require_message_authenticator = yes
#    nas_type = cisco
#    shortname = ap-oficina-1
#}

# ── Ejemplo: Access Point 2 ──────────────────────────────
#client ap-oficina-2 {
#    ipaddr = 192.168.1.11
#    secret = CAMBIAR-SECRET-AP2
#    require_message_authenticator = yes
#    nas_type = other
#    shortname = ap-oficina-2
#}

# ── Ejemplo: Switch con 802.1X ───────────────────────────
#client switch-core {
#    ipaddr = 192.168.1.1
#    secret = CAMBIAR-SECRET-SWITCH
#    require_message_authenticator = yes
#    nas_type = cisco
#    shortname = switch-core
#}

# ── Ejemplo: Subred de APs ───────────────────────────────
#client ap-subnet {
#    ipaddr = 192.168.1.0/24
#    secret = CAMBIAR-SECRET-SUBNET
#    require_message_authenticator = yes
#    nas_type = other
#    shortname = ap-subnet
#}
EOFCLIENTS
    chmod 640 "${RADIUS_CONF_DIR}/clients.conf.template"
    log_change "Creado" "${RADIUS_CONF_DIR}/clients.conf.template"

    # Template: users file
    cat > "${RADIUS_CONF_DIR}/users.template" << 'EOFUSERS'
# ============================================================
# users - Usuarios FreeRADIUS
# Generado por securizar - Modulo 56
# ============================================================
# TEMPLATE - Adaptar antes de usar en produccion
# Para EAP-TLS no se necesitan entradas aqui (autenticacion por cert)
# ============================================================

# ── Politica por defecto: rechazar ────────────────────────
# Usuarios no reconocidos son rechazados
DEFAULT Auth-Type := Reject
    Reply-Message = "Acceso denegado: usuario no autorizado"

# ── Ejemplo: Usuario EAP-PEAP/TTLS ───────────────────────
#usuario1  Cleartext-Password := "CAMBIAR-PASSWORD"
#    Reply-Message = "Bienvenido %{User-Name}",
#    Tunnel-Type = VLAN,
#    Tunnel-Medium-Type = IEEE-802,
#    Tunnel-Private-Group-Id = 10

# ── Ejemplo: Grupo de administradores ────────────────────
#admin1  Cleartext-Password := "CAMBIAR-PASSWORD"
#    Reply-Message = "Admin: %{User-Name}",
#    Tunnel-Type = VLAN,
#    Tunnel-Medium-Type = IEEE-802,
#    Tunnel-Private-Group-Id = 1

# ── Ejemplo: Invitados (VLAN restringida) ────────────────
#guest1  Cleartext-Password := "CAMBIAR-PASSWORD"
#    Reply-Message = "Invitado: %{User-Name}",
#    Session-Timeout = 3600,
#    Tunnel-Type = VLAN,
#    Tunnel-Medium-Type = IEEE-802,
#    Tunnel-Private-Group-Id = 99
EOFUSERS
    chmod 640 "${RADIUS_CONF_DIR}/users.template"
    log_change "Creado" "${RADIUS_CONF_DIR}/users.template"

    # Template: EAP module configuration
    cat > "${RADIUS_CONF_DIR}/eap.template" << 'EOFEAPMOD'
# ============================================================
# eap - Modulo EAP para FreeRADIUS (hardened)
# Generado por securizar - Modulo 56
# ============================================================
# TEMPLATE - Copiar a /etc/raddb/mods-enabled/eap
# ============================================================

eap {
    # Tipo EAP por defecto: TLS (mas seguro)
    default_eap_type = tls

    # Tiempo de vida del handler EAP
    timer_expire = 60

    # No ignorar tipos EAP desconocidos
    ignore_unknown_eap_types = no

    # Cisco AP workaround
    cisco_accounting_username_bug = no

    # Maximo de sesiones EAP
    max_sessions = ${max_requests}

    # ── TLS (autenticacion por certificado) ───────────────
    tls-config tls-common {
        # Certificados del servidor RADIUS
        private_key_password = CAMBIAR-PASSWORD-KEY
        private_key_file = /etc/raddb/certs/server.key
        certificate_file = /etc/raddb/certs/server.pem
        ca_file = /etc/raddb/certs/ca.pem
        ca_path = /etc/raddb/certs

        # Verificacion de certificados de cliente
        check_crl = yes
        # ca_crls = /etc/raddb/certs/crl.pem

        # Opciones TLS seguras
        cipher_list = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
        cipher_server_preference = yes

        # TLS minimo 1.2 (deshabilitar versiones inseguras)
        tls_min_version = "1.2"
        tls_max_version = "1.3"

        # Tamano de fragmento EAP
        fragment_size = 1024

        # Cache de sesiones TLS
        cache {
            enable = yes
            lifetime = 24
            name = "EAP module"
            max_entries = 255
            persist_dir = /var/log/freeradius/tlscache
        }

        # OCSP para verificacion en tiempo real de certificados
        ocsp {
            enable = no
            override_cert_url = yes
            url = "http://ocsp.empresa.com/"
            # use_nonce = yes
            # timeout = 0
            # softfail = no
        }
    }

    # ── TLS ───────────────────────────────────────────────
    tls {
        tls = tls-common
    }

    # ── PEAP ──────────────────────────────────────────────
    peap {
        tls = tls-common
        default_eap_type = mschapv2
        copy_request_to_tunnel = no
        use_tunneled_reply = yes
        # Requerir client cert en PEAP (opcional, mas seguro)
        # require_client_cert = yes
        virtual_server = "inner-tunnel"
    }

    # ── TTLS ──────────────────────────────────────────────
    ttls {
        tls = tls-common
        default_eap_type = mschapv2
        copy_request_to_tunnel = no
        use_tunneled_reply = yes
        virtual_server = "inner-tunnel"
    }

    # ── MSCHAPv2 (inner method) ───────────────────────────
    mschapv2 {
    }

    # ── Metodos deshabilitados (inseguros) ────────────────
    # NO habilitar: md5, leap, gtc sin tunnel
}
EOFEAPMOD
    chmod 640 "${RADIUS_CONF_DIR}/eap.template"
    log_change "Creado" "${RADIUS_CONF_DIR}/eap.template"

    # Script de generacion de certificados RADIUS
    cat > "${RADIUS_CONF_DIR}/generar-certs-radius.sh" << 'EOFGENCERTS'
#!/bin/bash
# ============================================================
# generar-certs-radius.sh - Generacion de certificados RADIUS
# Generado por securizar - Modulo 56
# ============================================================
# Ejecutar como root para generar PKI de prueba/desarrollo
# Para produccion: usar una CA corporativa
# ============================================================

set -euo pipefail

CERT_DIR="${1:-/etc/raddb/certs}"
DAYS=3650
KEY_SIZE=4096
COUNTRY="ES"
STATE="Madrid"
CITY="Madrid"
ORG="Empresa"
OU="IT-Security"
CA_CN="RADIUS-CA"
SERVER_CN="radius.empresa.com"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  GENERACION DE CERTIFICADOS RADIUS${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[X] Ejecutar como root${NC}"
    exit 1
fi

mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

echo -e "${GREEN}[+]${NC} Directorio de certificados: $CERT_DIR"

# 1. Generar CA
echo -e "${GREEN}[+]${NC} Generando CA (${KEY_SIZE} bits, ${DAYS} dias)..."
openssl genrsa -aes256 -passout pass:securizar-ca-temp -out ca.key $KEY_SIZE
openssl req -new -x509 -days $DAYS -key ca.key -passin pass:securizar-ca-temp \
    -out ca.pem \
    -subj "/C=${COUNTRY}/ST=${STATE}/L=${CITY}/O=${ORG}/OU=${OU}/CN=${CA_CN}"
echo -e "${GREEN}[+]${NC} CA generada: ca.pem, ca.key"

# 2. Generar certificado del servidor RADIUS
echo -e "${GREEN}[+]${NC} Generando certificado del servidor..."
openssl genrsa -aes256 -passout pass:securizar-server-temp -out server.key $KEY_SIZE
openssl req -new -key server.key -passin pass:securizar-server-temp \
    -out server.csr \
    -subj "/C=${COUNTRY}/ST=${STATE}/L=${CITY}/O=${ORG}/OU=${OU}/CN=${SERVER_CN}"

# Extensiones para el certificado del servidor
cat > server-ext.cnf << 'EOFEXT'
[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = radius.empresa.com
DNS.2 = radius
EOFEXT

openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key \
    -passin pass:securizar-ca-temp \
    -CAcreateserial -out server.pem -days $DAYS \
    -extfile server-ext.cnf -extensions v3_req
echo -e "${GREEN}[+]${NC} Certificado del servidor: server.pem, server.key"

# 3. Generar certificado de cliente ejemplo
echo -e "${GREEN}[+]${NC} Generando certificado de cliente ejemplo..."
openssl genrsa -aes256 -passout pass:securizar-client-temp -out client.key $KEY_SIZE
openssl req -new -key client.key -passin pass:securizar-client-temp \
    -out client.csr \
    -subj "/C=${COUNTRY}/ST=${STATE}/L=${CITY}/O=${ORG}/OU=${OU}/CN=usuario@empresa.com"
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key \
    -passin pass:securizar-ca-temp \
    -CAcreateserial -out client.pem -days 365

echo -e "${GREEN}[+]${NC} Certificado del cliente: client.pem, client.key"

# 4. Generar DH parameters
echo -e "${GREEN}[+]${NC} Generando parametros DH (puede tardar)..."
openssl dhparam -out dh.pem 2048

# 5. Permisos
chmod 600 *.key
chmod 644 *.pem
rm -f *.csr *.cnf *.srl

echo ""
echo -e "${YELLOW}[!]${NC} IMPORTANTE: Cambie las passwords de las claves para produccion"
echo -e "${YELLOW}[!]${NC} Passwords temporales: securizar-ca-temp, securizar-server-temp, securizar-client-temp"
echo -e "${YELLOW}[!]${NC} Use: openssl rsa -aes256 -in server.key -out server-new.key"
echo ""
echo -e "${GREEN}[+]${NC} Certificados generados correctamente en: $CERT_DIR"
EOFGENCERTS
    chmod 700 "${RADIUS_CONF_DIR}/generar-certs-radius.sh"
    log_change "Creado" "${RADIUS_CONF_DIR}/generar-certs-radius.sh"

    # Systemd override para FreeRADIUS hardening
    local radius_service=""
    if systemctl list-unit-files 2>/dev/null | grep -q "freeradius"; then
        radius_service="freeradius"
    elif systemctl list-unit-files 2>/dev/null | grep -q "radiusd"; then
        radius_service="radiusd"
    fi

    if [[ -n "$radius_service" ]]; then
        local override_dir="/etc/systemd/system/${radius_service}.service.d"
        mkdir -p "$override_dir"

        if [[ -f "${override_dir}/securizar-hardening.conf" ]]; then
            cp -a "${override_dir}/securizar-hardening.conf" "$BACKUP_DIR/"
        fi

        cat > "${override_dir}/securizar-hardening.conf" << 'EOFRADOVR'
# ============================================================
# FreeRADIUS systemd hardening - securizar Modulo 56
# ============================================================

[Service]
# Proteccion del sistema de archivos
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/freeradius /var/run/radiusd /tmp

# Proteccion de kernel
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes

# Proteccion de red (solo necesita red para RADIUS)
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

# No permitir escalada de privilegios
NoNewPrivileges=yes

# Espacio de nombres privado
PrivateTmp=yes
PrivateDevices=yes

# Restringir syscalls
SystemCallFilter=@system-service
SystemCallFilter=~@mount @reboot @swap @clock @module @debug @raw-io

# Memoria
MemoryDenyWriteExecute=yes

# Limitar capacidades
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_DAC_OVERRIDE
AmbientCapabilities=CAP_NET_BIND_SERVICE
EOFRADOVR
        chmod 644 "${override_dir}/securizar-hardening.conf"
        systemctl daemon-reload 2>/dev/null || true
        log_change "Creado" "${override_dir}/securizar-hardening.conf"
    else
        log_info "FreeRADIUS no tiene servicio systemd - override no creado"
        log_info "Plantilla disponible en ${RADIUS_CONF_DIR}/"
    fi

    # Script principal: securizar-radius-setup.sh
    cat > /usr/local/bin/securizar-radius-setup.sh << 'EOFRADIUSSETUP'
#!/bin/bash
# ============================================================
# securizar-radius-setup.sh - Setup FreeRADIUS con seguridad
# Generado por securizar - Modulo 56
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  SETUP FREERADIUS SEGURO${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[X] Ejecutar como root${NC}"
    exit 1
fi

TEMPLATE_DIR="/etc/securizar/freeradius"
if [[ ! -d "$TEMPLATE_DIR" ]]; then
    echo -e "${RED}[X] No se encuentran templates en $TEMPLATE_DIR${NC}"
    echo -e "${RED}[X] Ejecute primero seguridad-wireless.sh${NC}"
    exit 1
fi

# Detectar directorio de configuracion FreeRADIUS
RADDB=""
for d in /etc/raddb /etc/freeradius/3.0 /etc/freeradius; do
    if [[ -d "$d" ]]; then
        RADDB="$d"
        break
    fi
done

if [[ -z "$RADDB" ]]; then
    echo -e "${RED}[X] FreeRADIUS no encontrado. Instalar primero.${NC}"
    exit 1
fi

echo -e "${GREEN}[+]${NC} Directorio FreeRADIUS: $RADDB"

# Verificar si el servicio esta disponible
RADIUS_SVC=""
if systemctl list-unit-files 2>/dev/null | grep -q "freeradius"; then
    RADIUS_SVC="freeradius"
elif systemctl list-unit-files 2>/dev/null | grep -q "radiusd"; then
    RADIUS_SVC="radiusd"
fi

echo ""
echo -e "${CYAN}Pasos disponibles:${NC}"
echo "  1) Generar certificados de prueba"
echo "  2) Copiar templates de configuracion"
echo "  3) Verificar configuracion actual"
echo "  4) Iniciar servicio en modo debug"
echo "  5) Test de autenticacion local"
echo "  q) Salir"
echo ""

read -p "Seleccione una opcion: " opt

case "$opt" in
    1)
        echo -e "${GREEN}[+]${NC} Generando certificados..."
        if [[ -f "${TEMPLATE_DIR}/generar-certs-radius.sh" ]]; then
            bash "${TEMPLATE_DIR}/generar-certs-radius.sh" "${RADDB}/certs"
        else
            echo -e "${RED}[X] Script de generacion no encontrado${NC}"
        fi
        ;;
    2)
        echo -e "${GREEN}[+]${NC} Copiando templates a $RADDB..."
        BACKUP="/root/radius-backup-$(date +%Y%m%d-%H%M%S)"
        mkdir -p "$BACKUP"
        # Backup configs existentes
        for f in radiusd.conf clients.conf; do
            [[ -f "${RADDB}/${f}" ]] && cp -a "${RADDB}/${f}" "$BACKUP/"
        done
        echo -e "${GREEN}[+]${NC} Backup en: $BACKUP"
        echo -e "${YELLOW}[!]${NC} Los templates son EJEMPLOS. Revise y adapte antes de usar."
        echo -e "${YELLOW}[!]${NC} Templates disponibles en: $TEMPLATE_DIR/"
        ls -la "$TEMPLATE_DIR/"
        ;;
    3)
        echo -e "${GREEN}[+]${NC} Verificando configuracion..."
        if command -v radiusd &>/dev/null; then
            radiusd -XC 2>&1 | tail -20
        elif command -v freeradius &>/dev/null; then
            freeradius -XC 2>&1 | tail -20
        else
            echo -e "${RED}[X] Binario de FreeRADIUS no encontrado${NC}"
        fi
        ;;
    4)
        echo -e "${GREEN}[+]${NC} Iniciando FreeRADIUS en modo debug..."
        echo -e "${YELLOW}[!]${NC} Ctrl+C para detener"
        if [[ -n "$RADIUS_SVC" ]]; then
            systemctl stop "$RADIUS_SVC" 2>/dev/null || true
        fi
        if command -v radiusd &>/dev/null; then
            radiusd -X
        elif command -v freeradius &>/dev/null; then
            freeradius -X
        fi
        ;;
    5)
        echo -e "${GREEN}[+]${NC} Test de autenticacion local..."
        if command -v radtest &>/dev/null; then
            read -p "Usuario: " test_user
            read -s -p "Password: " test_pass
            echo ""
            read -p "Secret (default: testing123): " test_secret
            test_secret="${test_secret:-testing123}"
            radtest "$test_user" "$test_pass" localhost 0 "$test_secret"
        else
            echo -e "${RED}[X] radtest no disponible (instalar freeradius-utils)${NC}"
        fi
        ;;
    q|Q)
        echo -e "${GREEN}[+]${NC} Saliendo."
        ;;
    *)
        echo -e "${YELLOW}[!]${NC} Opcion no reconocida"
        ;;
esac
EOFRADIUSSETUP
    chmod +x /usr/local/bin/securizar-radius-setup.sh
    log_change "Creado" "/usr/local/bin/securizar-radius-setup.sh"

    log_info "Plantillas FreeRADIUS creadas en: $RADIUS_CONF_DIR"

else
    log_skip "configuracion de FreeRADIUS"
fi

# ============================================================
# S5: DETECCION DE ROGUE APs
# ============================================================
log_section "S5: DETECCION DE ROGUE APs (PUNTOS DE ACCESO NO AUTORIZADOS)"

log_info "Sistema de deteccion de puntos de acceso no autorizados:"
log_info "  - Escaneo de APs cercanos (iw dev scan)"
log_info "  - Comparacion contra whitelist de APs autorizados"
log_info "  - Deteccion: evil twin, rogue AP, redes abiertas"
log_info "  - Deteccion de ataques de deautenticacion"
log_info "  - Timer systemd para escaneo periodico"

if ask "¿Crear sistema de deteccion de rogue APs?"; then

    AP_WHITELIST="/etc/securizar/ap-whitelist.conf"
    ROGUE_LOG_DIR="/var/log/securizar/rogue-ap"
    mkdir -p "$ROGUE_LOG_DIR"
    chmod 750 "$ROGUE_LOG_DIR"

    # Crear whitelist de APs ejemplo
    if [[ ! -f "$AP_WHITELIST" ]]; then
        cat > "$AP_WHITELIST" << 'EOFWHITELIST'
# ============================================================
# ap-whitelist.conf - APs autorizados
# Generado por securizar - Modulo 56
# ============================================================
# Formato: BSSID|SSID|CANAL|SEGURIDAD
# Ejemplo: AA:BB:CC:DD:EE:FF|MiRedCorporativa|6|WPA3
# Lineas que comienzan con # son comentarios
# ============================================================

# Agregar aqui sus APs autorizados:
# AA:BB:CC:DD:EE:FF|RedOficina|1|WPA3-Enterprise
# AA:BB:CC:DD:EE:00|RedOficina|6|WPA3-Enterprise
# AA:BB:CC:DD:EE:01|RedOficina|11|WPA3-Enterprise
# AA:BB:CC:DD:EE:02|RedInvitados|36|WPA3-SAE
EOFWHITELIST
        chmod 640 "$AP_WHITELIST"
        log_change "Creado" "$AP_WHITELIST"
    else
        log_info "Whitelist de APs ya existe: $AP_WHITELIST"
    fi

    # Script de deteccion de rogue APs
    cat > /usr/local/bin/detectar-rogue-ap.sh << 'EOFROGUEAP'
#!/bin/bash
# ============================================================
# detectar-rogue-ap.sh - Deteccion de APs no autorizados
# Generado por securizar - Modulo 56
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

WHITELIST="/etc/securizar/ap-whitelist.conf"
LOG_DIR="/var/log/securizar/rogue-ap"
LOG_FILE="${LOG_DIR}/scan-$(date +%Y%m%d-%H%M%S).log"
ALERT_FILE="${LOG_DIR}/alertas.log"

mkdir -p "$LOG_DIR"

# Modo silencioso (para cron/timer)
SILENT="${1:-}"

_log() {
    local msg="$1"
    echo "$msg" >> "$LOG_FILE"
    if [[ "$SILENT" != "--silent" ]]; then
        echo -e "$msg"
    fi
}

_alert() {
    local msg="$1"
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$ts] ALERTA: $msg" >> "$ALERT_FILE"
    _log "${RED}[ALERTA]${NC} $msg"
    # Enviar alerta a syslog
    logger -t "securizar-rogue-ap" -p auth.warning "ALERTA: $msg" 2>/dev/null || true
}

_log "${BOLD}══════════════════════════════════════════${NC}"
_log "${BOLD}  DETECCION DE ROGUE APs${NC}"
_log "${BOLD}══════════════════════════════════════════${NC}"
_log "${DIM}Fecha: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
_log ""

# Verificar permisos
if [[ $EUID -ne 0 ]]; then
    _log "${RED}[X] Ejecutar como root para escanear WiFi${NC}"
    exit 1
fi

# Verificar herramientas
if ! command -v iw &>/dev/null; then
    _log "${RED}[X] iw no encontrado - instalar iw${NC}"
    exit 1
fi

# Detectar interfaz wireless
WIFI_IFACE=""
for wdir in /sys/class/net/*/wireless; do
    if [[ -d "$wdir" ]]; then
        WIFI_IFACE=$(basename "$(dirname "$wdir")")
        break
    fi
done

if [[ -z "$WIFI_IFACE" ]]; then
    _log "${YELLOW}[!]${NC} No se detectaron interfaces wireless"
    _log "${YELLOW}[!]${NC} No se puede escanear sin interfaz WiFi"
    exit 0
fi

_log "${GREEN}[+]${NC} Interfaz wireless: $WIFI_IFACE"
_log ""

# Cargar whitelist
declare -A WHITELIST_BSSID
declare -A WHITELIST_SSID
if [[ -f "$WHITELIST" ]]; then
    while IFS='|' read -r bssid ssid canal seguridad; do
        [[ -z "$bssid" || "$bssid" == \#* ]] && continue
        bssid=$(echo "$bssid" | tr '[:upper:]' '[:lower:]' | xargs)
        WHITELIST_BSSID["$bssid"]="${ssid}|${canal}|${seguridad}"
        WHITELIST_SSID["${ssid:-unknown}"]=1
    done < "$WHITELIST"
    _log "${GREEN}[+]${NC} Whitelist cargada: ${#WHITELIST_BSSID[@]} APs autorizados"
else
    _log "${YELLOW}[!]${NC} No hay whitelist ($WHITELIST) - todos los APs se reportaran"
fi
_log ""

# Escanear APs
_log "${CYAN}[*] Escaneando APs cercanos...${NC}"
SCAN_DATA=$(iw dev "$WIFI_IFACE" scan 2>/dev/null || true)

if [[ -z "$SCAN_DATA" ]]; then
    _log "${YELLOW}[!]${NC} No se pudo completar el escaneo"
    _log "${YELLOW}[!]${NC} Puede requerir que la interfaz este UP: ip link set $WIFI_IFACE up"
    exit 1
fi

# Parsear resultados del escaneo
total_aps=0
rogue_aps=0
evil_twins=0
open_networks=0

current_bssid=""
current_ssid=""
current_freq=""
current_signal=""
current_security=""

process_ap() {
    [[ -z "$current_bssid" ]] && return
    ((total_aps++)) || true

    local bssid_lower
    bssid_lower=$(echo "$current_bssid" | tr '[:upper:]' '[:lower:]')

    local is_authorized=0
    local is_open=0
    local is_evil_twin=0

    # Verificar seguridad
    if [[ -z "$current_security" ]] || [[ "$current_security" == "open" ]]; then
        is_open=1
        ((open_networks++)) || true
    fi

    # Verificar contra whitelist
    if [[ -n "${WHITELIST_BSSID[$bssid_lower]+x}" ]]; then
        is_authorized=1
    fi

    # Detectar evil twin: SSID conocido pero BSSID desconocido
    if [[ -n "$current_ssid" ]] && [[ -n "${WHITELIST_SSID[$current_ssid]+x}" ]] && [[ $is_authorized -eq 0 ]]; then
        is_evil_twin=1
        ((evil_twins++)) || true
    fi

    # Reportar
    if [[ $is_evil_twin -eq 1 ]]; then
        _alert "EVIL TWIN detectado: SSID='$current_ssid' BSSID=$current_bssid Signal=$current_signal"
    elif [[ $is_authorized -eq 0 ]]; then
        ((rogue_aps++)) || true
        if [[ $is_open -eq 1 ]]; then
            _alert "RED ABIERTA no autorizada: SSID='$current_ssid' BSSID=$current_bssid Signal=$current_signal"
        else
            _log "${YELLOW}[!]${NC} AP desconocido: SSID='${current_ssid:-<oculto>}' BSSID=$current_bssid Freq=$current_freq Signal=$current_signal Sec=$current_security"
        fi
    else
        _log "${GREEN}[+]${NC} AP autorizado: SSID='${current_ssid:-<oculto>}' BSSID=$current_bssid"
    fi
}

while IFS= read -r line; do
    if [[ "$line" =~ ^BSS\ ([0-9a-fA-F:]+) ]]; then
        process_ap
        current_bssid="${BASH_REMATCH[1]}"
        current_ssid=""
        current_freq=""
        current_signal=""
        current_security=""
    elif [[ "$line" =~ SSID:\ (.+) ]]; then
        current_ssid="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ freq:\ ([0-9]+) ]]; then
        current_freq="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ signal:\ (.+) ]]; then
        current_signal="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ (WPA|RSN|WEP) ]]; then
        if [[ "$line" =~ WPA2 ]] || [[ "$line" =~ RSN ]]; then
            current_security="WPA2/WPA3"
        elif [[ "$line" =~ WPA ]]; then
            current_security="WPA"
        elif [[ "$line" =~ WEP ]]; then
            current_security="WEP-INSEGURO"
        fi
    fi
done <<< "$SCAN_DATA"
process_ap  # Procesar ultimo AP

_log ""
_log "${BOLD}── Resumen ──────────────────────────────${NC}"
_log "  Total APs detectados:    $total_aps"
_log "  APs no autorizados:      $rogue_aps"
_log "  Evil twins detectados:   $evil_twins"
_log "  Redes abiertas:          $open_networks"
_log ""

if [[ $evil_twins -gt 0 ]]; then
    _log "${RED}${BOLD}[!!!] EVIL TWIN(S) DETECTADO(S) - RIESGO CRITICO${NC}"
elif [[ $rogue_aps -gt 5 ]]; then
    _log "${YELLOW}[!] Multiples APs desconocidos - revisar entorno wireless${NC}"
elif [[ $rogue_aps -eq 0 ]] && [[ $evil_twins -eq 0 ]]; then
    _log "${GREEN}[+] Entorno wireless limpio${NC}"
fi

_log ""
_log "${DIM}Log guardado en: $LOG_FILE${NC}"
EOFROGUEAP
    chmod +x /usr/local/bin/detectar-rogue-ap.sh
    log_change "Creado" "/usr/local/bin/detectar-rogue-ap.sh"

    # Systemd timer para escaneo periodico
    cat > /etc/systemd/system/securizar-rogue-ap.service << 'EOFRAPSVC'
[Unit]
Description=Securizar - Deteccion de Rogue APs
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/detectar-rogue-ap.sh --silent
StandardOutput=journal
StandardError=journal
# Hardening
NoNewPrivileges=yes
ProtectHome=yes
PrivateTmp=yes
EOFRAPSVC
    chmod 644 /etc/systemd/system/securizar-rogue-ap.service
    log_change "Creado" "/etc/systemd/system/securizar-rogue-ap.service"

    cat > /etc/systemd/system/securizar-rogue-ap.timer << 'EOFRAPTIMER'
[Unit]
Description=Securizar - Escaneo periodico de rogue APs

[Timer]
OnBootSec=5min
OnUnitActiveSec=1h
RandomizedDelaySec=5min
Persistent=true

[Install]
WantedBy=timers.target
EOFRAPTIMER
    chmod 644 /etc/systemd/system/securizar-rogue-ap.timer
    log_change "Creado" "/etc/systemd/system/securizar-rogue-ap.timer"

    if ask "¿Activar timer de escaneo periodico de rogue APs?"; then
        systemctl daemon-reload 2>/dev/null || true
        systemctl enable securizar-rogue-ap.timer 2>/dev/null || true
        systemctl start securizar-rogue-ap.timer 2>/dev/null || true
        log_change "Activado" "securizar-rogue-ap.timer (escaneo cada 1h)"
    else
        log_skip "activar timer de escaneo de rogue APs"
    fi

else
    log_skip "deteccion de rogue APs"
fi

# ============================================================
# S6: PROTECCION CONTRA ATAQUES WIRELESS
# ============================================================
log_section "S6: PROTECCION CONTRA ATAQUES WIRELESS"

log_info "Proteccion contra ataques wireless conocidos:"
log_info "  - KRACK: verificar wpa_supplicant parcheado"
log_info "  - DragonBlood (WPA3): actualizar wpa_supplicant"
log_info "  - Deauth: habilitar 802.11w/PMF"
log_info "  - PMKID: deshabilitar PMKID caching"
log_info "  - Evil twin: certificate pinning para enterprise"
log_info "  - Script: /usr/local/bin/verificar-protecciones-wifi.sh"

if ask "¿Verificar y aplicar protecciones contra ataques wireless?"; then

    # Verificar version de wpa_supplicant
    if command -v wpa_supplicant &>/dev/null; then
        local wpa_version
        wpa_version=$(wpa_supplicant -v 2>&1 | head -1 || echo "desconocida")
        log_info "wpa_supplicant version: $wpa_version"

        # Extraer numero de version
        local ver_num
        ver_num=$(echo "$wpa_version" | grep -oP 'v\K[0-9.]+' || echo "0.0")

        # KRACK: parcheado desde wpa_supplicant 2.7+
        if [[ "$(echo "$ver_num" | cut -d. -f1)" -ge 2 ]] && \
           [[ "$(echo "$ver_num" | cut -d. -f2)" -ge 7 ]]; then
            log_info "KRACK: wpa_supplicant $ver_num es >= 2.7 (parcheado)"
        else
            log_warn "KRACK: wpa_supplicant $ver_num puede ser vulnerable"
            log_warn "  Actualice wpa_supplicant a version 2.7 o superior"
            if ask "¿Actualizar wpa_supplicant?"; then
                case "$DISTRO_FAMILY" in
                    suse)   zypper --non-interactive update wpa_supplicant || true ;;
                    debian) DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade wpasupplicant || true ;;
                    rhel)   dnf update -y wpa_supplicant || true ;;
                    arch)   pacman -S --noconfirm wpa_supplicant || true ;;
                esac
                log_change "Actualizado" "wpa_supplicant"
            else
                log_skip "actualizar wpa_supplicant"
            fi
        fi

        # DragonBlood (WPA3): parcheado en 2.9+
        if [[ "$(echo "$ver_num" | cut -d. -f1)" -ge 2 ]] && \
           [[ "$(echo "$ver_num" | cut -d. -f2)" -ge 9 ]]; then
            log_info "DragonBlood: wpa_supplicant $ver_num es >= 2.9 (parcheado)"
        else
            log_warn "DragonBlood: wpa_supplicant $ver_num puede ser vulnerable a ataques WPA3"
            log_warn "  Actualice a la version mas reciente disponible"
        fi
    else
        log_warn "wpa_supplicant no encontrado en el sistema"
    fi

    # Verificar configuracion de wpa_supplicant global
    local wpa_conf=""
    for f in /etc/wpa_supplicant/wpa_supplicant.conf /etc/wpa_supplicant.conf; do
        if [[ -f "$f" ]]; then
            wpa_conf="$f"
            break
        fi
    done

    if [[ -n "$wpa_conf" ]]; then
        cp -a "$wpa_conf" "$BACKUP_DIR/"
        log_change "Backup" "$wpa_conf"

        # Deshabilitar PMKID caching
        if ! grep -q "disable_pmksa_caching" "$wpa_conf" 2>/dev/null; then
            log_info "Agregando disable_pmksa_caching=1 a wpa_supplicant.conf..."
            # Agregar al inicio del archivo (configuracion global)
            if grep -q "^ctrl_interface" "$wpa_conf"; then
                sed -i '/^ctrl_interface/a disable_pmksa_caching=1' "$wpa_conf"
            else
                sed -i '1i disable_pmksa_caching=1' "$wpa_conf"
            fi
            log_change "Configurado" "wpa_supplicant: disable_pmksa_caching=1 (proteccion PMKID)"
        else
            log_info "disable_pmksa_caching ya configurado en wpa_supplicant.conf"
        fi

        # Habilitar PMF global
        if ! grep -q "^pmf=" "$wpa_conf" 2>/dev/null; then
            if grep -q "^ctrl_interface" "$wpa_conf"; then
                sed -i '/^ctrl_interface/a pmf=2' "$wpa_conf"
            else
                sed -i '1i pmf=2' "$wpa_conf"
            fi
            log_change "Configurado" "wpa_supplicant: pmf=2 (802.11w requerido)"
        else
            log_info "PMF ya configurado globalmente en wpa_supplicant.conf"
        fi

        # Deshabilitar auto-scan de redes abiertas
        if ! grep -q "^autoscan=" "$wpa_conf" 2>/dev/null; then
            # No agregar autoscan - dejarlo manual es mas seguro
            log_info "wpa_supplicant: sin autoscan configurado (mas seguro)"
        fi
    else
        log_info "No hay wpa_supplicant.conf global - NetworkManager gestiona la configuracion"
    fi

    # Crear script de verificacion de protecciones
    cat > /usr/local/bin/verificar-protecciones-wifi.sh << 'EOFVERIFWIFI'
#!/bin/bash
# ============================================================
# verificar-protecciones-wifi.sh - Verificar protecciones WiFi
# Generado por securizar - Modulo 56
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  VERIFICACION DE PROTECCIONES WIFI${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""
echo -e "${DIM}Fecha: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo ""

score=0
total=0

check() {
    local desc="$1" result="$2"
    ((total++))
    if [[ "$result" == "OK" ]]; then
        echo -e "  ${GREEN}[OK]${NC} $desc"
        ((score++))
    elif [[ "$result" == "WARN" ]]; then
        echo -e "  ${YELLOW}[!!]${NC} $desc"
    else
        echo -e "  ${RED}[XX]${NC} $desc"
    fi
}

# 1. Version wpa_supplicant
echo -e "${CYAN}[1] Version de wpa_supplicant:${NC}"
if command -v wpa_supplicant &>/dev/null; then
    ver=$(wpa_supplicant -v 2>&1 | head -1)
    ver_num=$(echo "$ver" | grep -oP 'v\K[0-9.]+' || echo "0.0")
    major=$(echo "$ver_num" | cut -d. -f1)
    minor=$(echo "$ver_num" | cut -d. -f2)

    echo -e "  Version: $ver"

    if [[ "$major" -ge 2 ]] && [[ "$minor" -ge 10 ]]; then
        check "KRACK (CVE-2017-13077): parcheado" "OK"
        check "DragonBlood (CVE-2019-9494): parcheado" "OK"
        check "FragAttacks (CVE-2020-24586): parcheado" "OK"
    elif [[ "$major" -ge 2 ]] && [[ "$minor" -ge 9 ]]; then
        check "KRACK: parcheado" "OK"
        check "DragonBlood: parcheado" "OK"
        check "FragAttacks: verificar parche del distribuidor" "WARN"
    elif [[ "$major" -ge 2 ]] && [[ "$minor" -ge 7 ]]; then
        check "KRACK: parcheado" "OK"
        check "DragonBlood: VULNERABLE - actualizar" "FAIL"
    else
        check "KRACK: VULNERABLE - actualizar urgente" "FAIL"
        check "DragonBlood: VULNERABLE" "FAIL"
    fi
else
    check "wpa_supplicant: no encontrado" "WARN"
fi
echo ""

# 2. PMF / 802.11w
echo -e "${CYAN}[2] PMF (802.11w) - Proteccion contra deautenticacion:${NC}"
pmf_ok=0
# Verificar en wpa_supplicant.conf
for f in /etc/wpa_supplicant/wpa_supplicant.conf /etc/wpa_supplicant.conf; do
    if [[ -f "$f" ]]; then
        if grep -q "pmf=2" "$f" 2>/dev/null || grep -q "ieee80211w=2" "$f" 2>/dev/null; then
            check "PMF requerido en $f" "OK"
            pmf_ok=1
        elif grep -q "pmf=1" "$f" 2>/dev/null || grep -q "ieee80211w=1" "$f" 2>/dev/null; then
            check "PMF opcional en $f (deberia ser requerido=2)" "WARN"
        else
            check "PMF no configurado en $f" "FAIL"
        fi
    fi
done
# Verificar en NetworkManager
nm_conf="/etc/NetworkManager/conf.d/99-securizar-wifi.conf"
if [[ -f "$nm_conf" ]]; then
    check "Configuracion securizar NM presente" "OK"
    pmf_ok=1
fi
if [[ $pmf_ok -eq 0 ]]; then
    check "PMF no configurado en ninguna ubicacion" "FAIL"
fi
echo ""

# 3. PMKID caching
echo -e "${CYAN}[3] PMKID caching (proteccion contra captura de PMKID):${NC}"
pmkid_disabled=0
for f in /etc/wpa_supplicant/wpa_supplicant.conf /etc/wpa_supplicant.conf; do
    if [[ -f "$f" ]] && grep -q "disable_pmksa_caching=1" "$f" 2>/dev/null; then
        check "PMKID caching deshabilitado en $f" "OK"
        pmkid_disabled=1
    fi
done
if [[ $pmkid_disabled -eq 0 ]]; then
    check "PMKID caching no deshabilitado (riesgo de ataque PMKID)" "WARN"
fi
echo ""

# 4. MAC randomization
echo -e "${CYAN}[4] MAC address randomization:${NC}"
if [[ -f "/etc/NetworkManager/conf.d/99-securizar-wifi.conf" ]]; then
    if grep -q "scan-rand-mac-address=yes" "/etc/NetworkManager/conf.d/99-securizar-wifi.conf" 2>/dev/null; then
        check "MAC randomization en escaneo" "OK"
    fi
    if grep -q "cloned-mac-address=random" "/etc/NetworkManager/conf.d/99-securizar-wifi.conf" 2>/dev/null; then
        check "MAC aleatorio por conexion" "OK"
    fi
else
    check "MAC randomization no configurada en NetworkManager" "WARN"
fi
echo ""

# 5. Redes abiertas guardadas
echo -e "${CYAN}[5] Redes WiFi abiertas guardadas:${NC}"
nm_conns="/etc/NetworkManager/system-connections"
open_count=0
if [[ -d "$nm_conns" ]]; then
    for conn in "$nm_conns"/*; do
        [[ -f "$conn" ]] || continue
        if grep -q "type=wifi" "$conn" 2>/dev/null; then
            if ! grep -q "key-mgmt=" "$conn" 2>/dev/null || \
               grep -q "key-mgmt=none" "$conn" 2>/dev/null; then
                ((open_count++)) || true
            fi
        fi
    done
fi
if [[ $open_count -eq 0 ]]; then
    check "Sin redes abiertas guardadas" "OK"
else
    check "$open_count red(es) abierta(s) guardada(s) - eliminar" "FAIL"
fi
echo ""

# 6. rfkill (wireless bloqueado en servidores)
echo -e "${CYAN}[6] Estado rfkill wireless:${NC}"
if command -v rfkill &>/dev/null; then
    wifi_blocked=$(rfkill list wifi 2>/dev/null | grep -c "Soft blocked: yes" || echo "0")
    if [[ "$wifi_blocked" -gt 0 ]]; then
        check "WiFi bloqueado via rfkill" "OK"
    else
        # Solo warn en servidores
        if ! command -v Xorg &>/dev/null && [[ -z "${DISPLAY:-}" ]]; then
            check "WiFi NO bloqueado (servidor sin display)" "WARN"
        else
            check "WiFi activo (estacion de trabajo)" "OK"
        fi
    fi
else
    check "rfkill no disponible" "WARN"
fi
echo ""

# Resumen
echo -e "${BOLD}══════════════════════════════════════════${NC}"
pct=0
if [[ $total -gt 0 ]]; then
    pct=$(( (score * 100) / total ))
fi
if [[ $pct -ge 80 ]]; then
    echo -e "  Puntuacion: ${GREEN}${BOLD}${score}/${total} (${pct}%)${NC}"
    echo -e "  Estado: ${GREEN}${BOLD}BUENO${NC}"
elif [[ $pct -ge 50 ]]; then
    echo -e "  Puntuacion: ${YELLOW}${BOLD}${score}/${total} (${pct}%)${NC}"
    echo -e "  Estado: ${YELLOW}${BOLD}MEJORABLE${NC}"
else
    echo -e "  Puntuacion: ${RED}${BOLD}${score}/${total} (${pct}%)${NC}"
    echo -e "  Estado: ${RED}${BOLD}DEFICIENTE${NC}"
fi
echo -e "${BOLD}══════════════════════════════════════════${NC}"
EOFVERIFWIFI
    chmod +x /usr/local/bin/verificar-protecciones-wifi.sh
    log_change "Creado" "/usr/local/bin/verificar-protecciones-wifi.sh"

else
    log_skip "proteccion contra ataques wireless"
fi

# ============================================================
# S7: BLUETOOTH SECURITY HARDENING
# ============================================================
log_section "S7: BLUETOOTH SECURITY HARDENING"

log_info "Hardening de seguridad Bluetooth:"
log_info "  - Auditar estado Bluetooth"
log_info "  - Deshabilitar en servidores (rfkill + blacklist)"
log_info "  - discoverable=false, pairable=false"
log_info "  - DiscoverableTimeout, Secure Simple Pairing"
log_info "  - Deshabilitar legacy pairing"
log_info "  - Verificar parches BlueBorne y KNOB"
log_info "  - Script: /usr/local/bin/securizar-bluetooth.sh"

if ask "¿Aplicar hardening de Bluetooth?"; then

    # Verificar presencia de hardware Bluetooth
    local bt_present=0
    if command -v bluetoothctl &>/dev/null; then
        bt_present=1
    elif [[ -d /sys/class/bluetooth ]]; then
        bt_present=1
    elif command -v hciconfig &>/dev/null && hciconfig -a 2>/dev/null | grep -q "hci"; then
        bt_present=1
    elif lsmod 2>/dev/null | grep -q "bluetooth\|btusb"; then
        bt_present=1
    fi

    if [[ $bt_present -eq 0 ]]; then
        log_info "No se detecto hardware Bluetooth en el sistema"
    else
        log_info "Hardware Bluetooth detectado"

        # En servidores: deshabilitar Bluetooth
        if is_server_system; then
            log_warn "Sistema detectado como SERVIDOR - Bluetooth normalmente no es necesario"
            if ask "¿Deshabilitar Bluetooth en este servidor?"; then
                # rfkill block bluetooth
                if command -v rfkill &>/dev/null; then
                    rfkill block bluetooth 2>/dev/null || true
                    log_change "Bloqueado" "Bluetooth via rfkill"
                fi

                # Blacklist modulos Bluetooth
                local bt_blacklist="/etc/modprobe.d/securizar-no-bluetooth.conf"
                if [[ -f "$bt_blacklist" ]]; then
                    cp -a "$bt_blacklist" "$BACKUP_DIR/"
                fi
                cat > "$bt_blacklist" << 'EOFBTBLACKLIST'
# ============================================================
# securizar - Modulo 56: Bluetooth deshabilitado en servidor
# Generado automaticamente - no editar manualmente
# ============================================================
blacklist bluetooth
blacklist btusb
blacklist btrtl
blacklist btbcm
blacklist btintel
blacklist btmtk
blacklist btmrvl
blacklist bnep
blacklist hidp
blacklist rfcomm
blacklist hci_uart
EOFBTBLACKLIST
                chmod 644 "$bt_blacklist"
                log_change "Creado" "$bt_blacklist"

                # Deshabilitar servicio bluetooth
                if systemctl is-enabled bluetooth &>/dev/null; then
                    systemctl disable bluetooth 2>/dev/null || true
                    systemctl stop bluetooth 2>/dev/null || true
                    log_change "Deshabilitado" "servicio bluetooth"
                fi

                # Descargar modulos
                for mod in bnep hidp rfcomm btusb bluetooth; do
                    modprobe -r "$mod" 2>/dev/null || true
                done
                log_change "Descargados" "modulos kernel Bluetooth"

            else
                log_skip "deshabilitar Bluetooth en servidor"
            fi
        else
            # Estacion de trabajo: hardening de Bluetooth
            log_info "Aplicando hardening de Bluetooth para estacion de trabajo..."

            local bt_main_conf="/etc/bluetooth/main.conf"
            if [[ -f "$bt_main_conf" ]]; then
                cp -a "$bt_main_conf" "$BACKUP_DIR/"
                log_change "Backup" "$bt_main_conf"

                # Deshabilitar descubrimiento por defecto
                if grep -q "^#\?Discoverable\s*=" "$bt_main_conf"; then
                    sed -i 's/^#\?Discoverable\s*=.*/Discoverable = false/' "$bt_main_conf"
                else
                    sed -i '/^\[General\]/a Discoverable = false' "$bt_main_conf" 2>/dev/null || \
                        echo "Discoverable = false" >> "$bt_main_conf"
                fi
                log_change "Configurado" "Bluetooth: Discoverable = false"

                # Deshabilitar pairing por defecto
                if grep -q "^#\?Pairable\s*=" "$bt_main_conf"; then
                    sed -i 's/^#\?Pairable\s*=.*/Pairable = false/' "$bt_main_conf"
                else
                    sed -i '/^\[General\]/a Pairable = false' "$bt_main_conf" 2>/dev/null || \
                        echo "Pairable = false" >> "$bt_main_conf"
                fi
                log_change "Configurado" "Bluetooth: Pairable = false"

                # DiscoverableTimeout = 0 (si se activa manualmente, nunca timeout infinito)
                if grep -q "^#\?DiscoverableTimeout\s*=" "$bt_main_conf"; then
                    sed -i 's/^#\?DiscoverableTimeout\s*=.*/DiscoverableTimeout = 30/' "$bt_main_conf"
                else
                    sed -i '/^\[General\]/a DiscoverableTimeout = 30' "$bt_main_conf" 2>/dev/null || \
                        echo "DiscoverableTimeout = 30" >> "$bt_main_conf"
                fi
                log_change "Configurado" "Bluetooth: DiscoverableTimeout = 30 (segundos)"

                # PairableTimeout
                if grep -q "^#\?PairableTimeout\s*=" "$bt_main_conf"; then
                    sed -i 's/^#\?PairableTimeout\s*=.*/PairableTimeout = 60/' "$bt_main_conf"
                else
                    sed -i '/^\[General\]/a PairableTimeout = 60' "$bt_main_conf" 2>/dev/null || \
                        echo "PairableTimeout = 60" >> "$bt_main_conf"
                fi
                log_change "Configurado" "Bluetooth: PairableTimeout = 60 (segundos)"

                # Nombre del dispositivo generico (no revelar hostname)
                if grep -q "^#\?Name\s*=" "$bt_main_conf"; then
                    sed -i 's/^#\?Name\s*=.*/Name = Device/' "$bt_main_conf"
                else
                    sed -i '/^\[General\]/a Name = Device' "$bt_main_conf" 2>/dev/null || \
                        echo "Name = Device" >> "$bt_main_conf"
                fi
                log_change "Configurado" "Bluetooth: Name = Device (sin revelar hostname)"

                # Forzar Secure Connections (BT 4.1+)
                if grep -q "^#\?JustWorksRepairing\s*=" "$bt_main_conf"; then
                    sed -i 's/^#\?JustWorksRepairing\s*=.*/JustWorksRepairing = never/' "$bt_main_conf"
                else
                    sed -i '/^\[General\]/a JustWorksRepairing = never' "$bt_main_conf" 2>/dev/null || \
                        echo "JustWorksRepairing = never" >> "$bt_main_conf"
                fi
                log_change "Configurado" "Bluetooth: JustWorksRepairing = never"

                # Privacy mode (para randomizar direccion BT)
                if grep -q "^#\?Privacy\s*=" "$bt_main_conf"; then
                    sed -i 's/^#\?Privacy\s*=.*/Privacy = device/' "$bt_main_conf"
                else
                    sed -i '/^\[General\]/a Privacy = device' "$bt_main_conf" 2>/dev/null || \
                        echo "Privacy = device" >> "$bt_main_conf"
                fi
                log_change "Configurado" "Bluetooth: Privacy = device (address randomization)"

                # Reiniciar bluetooth
                if systemctl is-active bluetooth &>/dev/null; then
                    systemctl restart bluetooth 2>/dev/null || true
                    log_change "Reiniciado" "servicio bluetooth con nueva configuracion"
                fi
            else
                log_warn "No se encontro /etc/bluetooth/main.conf"
                log_info "Bluetooth puede no estar instalado o usar configuracion diferente"
            fi
        fi

        # Verificar parches de seguridad Bluetooth
        log_info "Verificando parches de vulnerabilidades Bluetooth..."

        # BlueBorne (CVE-2017-1000251): parcheado en kernel 4.14+
        local kernel_major kernel_minor
        kernel_major=$(uname -r | cut -d. -f1)
        kernel_minor=$(uname -r | cut -d. -f2)
        if [[ "$kernel_major" -gt 4 ]] || { [[ "$kernel_major" -eq 4 ]] && [[ "$kernel_minor" -ge 14 ]]; }; then
            log_info "BlueBorne (CVE-2017-1000251): kernel $(uname -r) parcheado"
        else
            log_warn "BlueBorne (CVE-2017-1000251): kernel $(uname -r) puede ser vulnerable"
            log_warn "  Actualice el kernel a 4.14 o superior"
        fi

        # KNOB (CVE-2019-9506): parcheado en kernel 5.2+
        if [[ "$kernel_major" -gt 5 ]] || { [[ "$kernel_major" -eq 5 ]] && [[ "$kernel_minor" -ge 2 ]]; }; then
            log_info "KNOB (CVE-2019-9506): kernel $(uname -r) parcheado"
        else
            log_warn "KNOB (CVE-2019-9506): kernel $(uname -r) puede ser vulnerable"
            log_warn "  Actualice el kernel a 5.2 o superior"
        fi

        # BLURtooth (CVE-2020-15802)
        if [[ "$kernel_major" -ge 6 ]] || { [[ "$kernel_major" -eq 5 ]] && [[ "$kernel_minor" -ge 10 ]]; }; then
            log_info "BLURtooth (CVE-2020-15802): kernel $(uname -r) parcheado"
        else
            log_warn "BLURtooth (CVE-2020-15802): kernel $(uname -r) puede ser vulnerable"
        fi
    fi

    # Crear script de hardening Bluetooth
    cat > /usr/local/bin/securizar-bluetooth.sh << 'EOFBTSCRIPT'
#!/bin/bash
# ============================================================
# securizar-bluetooth.sh - Hardening Bluetooth
# Generado por securizar - Modulo 56
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  SECURIZAR BLUETOOTH${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[X] Ejecutar como root${NC}"
    exit 1
fi

echo -e "${CYAN}[1] Estado del hardware Bluetooth:${NC}"
if command -v rfkill &>/dev/null; then
    rfkill list bluetooth 2>/dev/null || echo "  Sin dispositivos Bluetooth"
else
    echo "  rfkill no disponible"
fi
echo ""

echo -e "${CYAN}[2] Servicio Bluetooth:${NC}"
if systemctl is-active bluetooth &>/dev/null; then
    echo -e "  Estado: ${GREEN}activo${NC}"
elif systemctl is-enabled bluetooth &>/dev/null; then
    echo -e "  Estado: ${YELLOW}habilitado pero inactivo${NC}"
else
    echo -e "  Estado: ${DIM}deshabilitado${NC}"
fi
echo ""

echo -e "${CYAN}[3] Configuracion Bluetooth (/etc/bluetooth/main.conf):${NC}"
bt_conf="/etc/bluetooth/main.conf"
if [[ -f "$bt_conf" ]]; then
    for param in Discoverable Pairable DiscoverableTimeout PairableTimeout Name Privacy JustWorksRepairing; do
        val=$(grep "^${param}\s*=" "$bt_conf" 2>/dev/null | cut -d= -f2- | xargs || echo "no configurado")
        case "$param" in
            Discoverable)
                if [[ "$val" == "false" ]]; then
                    echo -e "  ${GREEN}[OK]${NC} $param = $val"
                else
                    echo -e "  ${RED}[XX]${NC} $param = $val (deberia ser false)"
                fi
                ;;
            Pairable)
                if [[ "$val" == "false" ]]; then
                    echo -e "  ${GREEN}[OK]${NC} $param = $val"
                else
                    echo -e "  ${RED}[XX]${NC} $param = $val (deberia ser false)"
                fi
                ;;
            Privacy)
                if [[ "$val" == "device" ]] || [[ "$val" == "network" ]]; then
                    echo -e "  ${GREEN}[OK]${NC} $param = $val"
                else
                    echo -e "  ${YELLOW}[!!]${NC} $param = $val (recomendado: device)"
                fi
                ;;
            *)
                echo -e "  ${DIM}$param = $val${NC}"
                ;;
        esac
    done
else
    echo -e "  ${YELLOW}[!]${NC} $bt_conf no encontrado"
fi
echo ""

echo -e "${CYAN}[4] Dispositivos emparejados:${NC}"
if command -v bluetoothctl &>/dev/null; then
    paired=$(bluetoothctl paired-devices 2>/dev/null || true)
    if [[ -n "$paired" ]]; then
        echo "$paired" | while IFS= read -r line; do
            echo -e "  ${YELLOW}[!]${NC} $line"
        done
    else
        echo -e "  ${GREEN}[+]${NC} Sin dispositivos emparejados"
    fi
else
    echo -e "  ${DIM}bluetoothctl no disponible${NC}"
fi
echo ""

echo -e "${CYAN}[5] Modulos Bluetooth cargados:${NC}"
bt_mods=$(lsmod 2>/dev/null | grep -iE 'bluetooth|btusb|btrtl|btbcm|btintel|bnep|hidp|rfcomm' | awk '{print $1}')
if [[ -n "$bt_mods" ]]; then
    while IFS= read -r m; do
        echo -e "  ${YELLOW}[!]${NC} $m"
    done <<< "$bt_mods"
else
    echo -e "  ${GREEN}[+]${NC} Sin modulos Bluetooth cargados"
fi
echo ""

echo -e "${CYAN}[6] Vulnerabilidades conocidas:${NC}"
kernel_major=$(uname -r | cut -d. -f1)
kernel_minor=$(uname -r | cut -d. -f2)

if [[ "$kernel_major" -gt 4 ]] || { [[ "$kernel_major" -eq 4 ]] && [[ "$kernel_minor" -ge 14 ]]; }; then
    echo -e "  ${GREEN}[OK]${NC} BlueBorne (CVE-2017-1000251): parcheado"
else
    echo -e "  ${RED}[XX]${NC} BlueBorne (CVE-2017-1000251): posiblemente vulnerable"
fi

if [[ "$kernel_major" -gt 5 ]] || { [[ "$kernel_major" -eq 5 ]] && [[ "$kernel_minor" -ge 2 ]]; }; then
    echo -e "  ${GREEN}[OK]${NC} KNOB (CVE-2019-9506): parcheado"
else
    echo -e "  ${RED}[XX]${NC} KNOB (CVE-2019-9506): posiblemente vulnerable"
fi

if [[ "$kernel_major" -ge 6 ]] || { [[ "$kernel_major" -eq 5 ]] && [[ "$kernel_minor" -ge 10 ]]; }; then
    echo -e "  ${GREEN}[OK]${NC} BLURtooth (CVE-2020-15802): parcheado"
else
    echo -e "  ${YELLOW}[!!]${NC} BLURtooth (CVE-2020-15802): verificar parche"
fi
echo ""

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  Hardening Bluetooth completado${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
EOFBTSCRIPT
    chmod +x /usr/local/bin/securizar-bluetooth.sh
    log_change "Creado" "/usr/local/bin/securizar-bluetooth.sh"

else
    log_skip "hardening de Bluetooth"
fi

# ============================================================
# S8: WIRELESS MONITORING CONTINUO
# ============================================================
log_section "S8: WIRELESS MONITORING CONTINUO"

log_info "Sistema de monitoreo wireless continuo:"
log_info "  - Monitoreo del entorno wireless"
log_info "  - Baseline de senal (deteccion de jamming)"
log_info "  - Utilizacion de canales"
log_info "  - Deteccion de nuevos APs"
log_info "  - Tracking de asociacion de clientes"
log_info "  - Servicio systemd: securizar-wireless-monitor.service"
log_info "  - Alertas: nuevos APs, cambios de senal, deauth floods"

if ask "¿Crear sistema de monitoreo wireless continuo?"; then

    MONITOR_LOG_DIR="/var/log/securizar/wireless-monitor"
    mkdir -p "$MONITOR_LOG_DIR"
    chmod 750 "$MONITOR_LOG_DIR"

    # Script de monitoreo wireless
    cat > /usr/local/bin/monitorizar-wireless.sh << 'EOFMONWIFI'
#!/bin/bash
# ============================================================
# monitorizar-wireless.sh - Monitoreo wireless continuo
# Generado por securizar - Modulo 56
# ============================================================

set -euo pipefail

LOG_DIR="/var/log/securizar/wireless-monitor"
BASELINE_FILE="${LOG_DIR}/ap-baseline.dat"
PREVIOUS_SCAN="${LOG_DIR}/last-scan.dat"
ALERT_LOG="${LOG_DIR}/alertas.log"
SCAN_LOG="${LOG_DIR}/scan-$(date +%Y%m%d).log"
WHITELIST="/etc/securizar/ap-whitelist.conf"
POLICY_FILE="/etc/securizar/wireless-policy.conf"

# Intervalo entre escaneos (segundos)
SCAN_INTERVAL=3600
# Leer de politica si existe
if [[ -f "$POLICY_FILE" ]]; then
    source "$POLICY_FILE" 2>/dev/null || true
fi

mkdir -p "$LOG_DIR"

# ── Funciones de logging ──────────────────────────────────
log_monitor() {
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$ts] $1" >> "$SCAN_LOG"
    logger -t "securizar-wireless-monitor" "$1" 2>/dev/null || true
}

alert() {
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$ts] ALERTA: $1" >> "$ALERT_LOG"
    log_monitor "ALERTA: $1"
    logger -t "securizar-wireless-monitor" -p auth.warning "ALERTA: $1" 2>/dev/null || true
}

# ── Detectar interfaz wireless ────────────────────────────
detect_iface() {
    local iface=""
    for wdir in /sys/class/net/*/wireless; do
        if [[ -d "$wdir" ]]; then
            iface=$(basename "$(dirname "$wdir")")
            break
        fi
    done
    echo "$iface"
}

# ── Escanear APs ─────────────────────────────────────────
scan_aps() {
    local iface="$1"
    local scan_data
    scan_data=$(iw dev "$iface" scan 2>/dev/null || true)
    if [[ -z "$scan_data" ]]; then
        return 1
    fi

    # Parsear y generar lista de APs: BSSID|SSID|FREQ|SIGNAL|SECURITY
    local current_bssid="" current_ssid="" current_freq="" current_signal="" current_security="open"

    while IFS= read -r line; do
        if [[ "$line" =~ ^BSS\ ([0-9a-fA-F:]+) ]]; then
            if [[ -n "$current_bssid" ]]; then
                echo "${current_bssid}|${current_ssid}|${current_freq}|${current_signal}|${current_security}"
            fi
            current_bssid="${BASH_REMATCH[1]}"
            current_ssid=""
            current_freq=""
            current_signal=""
            current_security="open"
        elif [[ "$line" =~ SSID:\ (.+) ]]; then
            current_ssid="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ freq:\ ([0-9]+) ]]; then
            current_freq="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ signal:\ (.+) ]]; then
            current_signal="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ (WPA|RSN) ]]; then
            current_security="WPA"
        fi
    done <<< "$scan_data"
    # Ultimo AP
    if [[ -n "$current_bssid" ]]; then
        echo "${current_bssid}|${current_ssid}|${current_freq}|${current_signal}|${current_security}"
    fi
}

# ── Cargar whitelist ──────────────────────────────────────
declare -A WL_BSSID
load_whitelist() {
    WL_BSSID=()
    if [[ -f "$WHITELIST" ]]; then
        while IFS='|' read -r bssid ssid canal seg; do
            [[ -z "$bssid" || "$bssid" == \#* ]] && continue
            bssid=$(echo "$bssid" | tr '[:upper:]' '[:lower:]' | xargs)
            WL_BSSID["$bssid"]=1
        done < "$WHITELIST"
    fi
}

# ── Comparar con baseline ────────────────────────────────
compare_with_baseline() {
    local scan_file="$1"

    if [[ ! -f "$BASELINE_FILE" ]]; then
        log_monitor "Sin baseline previo - creando baseline inicial"
        cp "$scan_file" "$BASELINE_FILE"
        return
    fi

    # Detectar nuevos APs
    while IFS='|' read -r bssid ssid freq signal security; do
        [[ -z "$bssid" ]] && continue
        bssid_lower=$(echo "$bssid" | tr '[:upper:]' '[:lower:]')
        if ! grep -qi "$bssid_lower" "$BASELINE_FILE" 2>/dev/null; then
            if [[ -n "${WL_BSSID[$bssid_lower]+x}" ]]; then
                log_monitor "Nuevo AP autorizado: SSID='$ssid' BSSID=$bssid"
            else
                alert "NUEVO AP no autorizado: SSID='$ssid' BSSID=$bssid Signal=$signal"
            fi
        fi
    done < "$scan_file"

    # Detectar APs desaparecidos (posible jamming)
    while IFS='|' read -r bssid ssid freq signal security; do
        [[ -z "$bssid" ]] && continue
        bssid_lower=$(echo "$bssid" | tr '[:upper:]' '[:lower:]')
        if [[ -n "${WL_BSSID[$bssid_lower]+x}" ]]; then
            if ! grep -qi "$bssid_lower" "$scan_file" 2>/dev/null; then
                alert "AP autorizado DESAPARECIDO: SSID='$ssid' BSSID=$bssid (posible jamming)"
            fi
        fi
    done < "$BASELINE_FILE"

    # Detectar cambios significativos de senal
    if [[ -f "$PREVIOUS_SCAN" ]]; then
        while IFS='|' read -r bssid ssid freq signal security; do
            [[ -z "$bssid" || -z "$signal" ]] && continue
            bssid_lower=$(echo "$bssid" | tr '[:upper:]' '[:lower:]')
            prev_signal=$(grep -i "$bssid_lower" "$PREVIOUS_SCAN" 2>/dev/null | cut -d'|' -f4 || echo "")
            if [[ -n "$prev_signal" ]]; then
                # Comparar potencia de senal (formato: -XX.XX dBm)
                curr_dbm=$(echo "$signal" | grep -oP '\-[0-9]+' | head -1 || echo "0")
                prev_dbm=$(echo "$prev_signal" | grep -oP '\-[0-9]+' | head -1 || echo "0")
                if [[ -n "$curr_dbm" ]] && [[ -n "$prev_dbm" ]]; then
                    diff=$(( curr_dbm - prev_dbm ))
                    abs_diff=${diff#-}
                    if [[ "$abs_diff" -gt 20 ]]; then
                        alert "Cambio significativo de senal: SSID='$ssid' BSSID=$bssid ($prev_signal -> $signal)"
                    fi
                fi
            fi
        done < "$scan_file"
    fi
}

# ── Verificar deauth floods ──────────────────────────────
check_deauth_floods() {
    local iface="$1"
    # Verificar contadores de frames deauth en el kernel
    local deauth_count=0
    if [[ -f "/sys/kernel/debug/ieee80211/$(cat /sys/class/net/${iface}/phy80211/name 2>/dev/null || echo "phy0")/statistics/dot11FCSErrorCount" ]]; then
        deauth_count=$(cat "/sys/kernel/debug/ieee80211/$(cat /sys/class/net/${iface}/phy80211/name 2>/dev/null || echo "phy0")/statistics/dot11FCSErrorCount" 2>/dev/null || echo "0")
    fi
    # Tambien verificar en journalctl
    local recent_deauth
    recent_deauth=$(journalctl -u wpa_supplicant --since "1 hour ago" 2>/dev/null | grep -ci "deauth\|disassoc" || echo "0")
    if [[ "$recent_deauth" -gt 10 ]]; then
        alert "Posible ataque de deautenticacion: $recent_deauth eventos en la ultima hora (interfaz: $iface)"
    fi
}

# ── Monitoreo de canales ─────────────────────────────────
monitor_channels() {
    local iface="$1"
    local scan_file="$2"

    if [[ ! -f "$scan_file" ]]; then
        return
    fi

    # Contar APs por canal
    declare -A channel_count
    while IFS='|' read -r bssid ssid freq signal security; do
        [[ -z "$freq" ]] && continue
        # Convertir frecuencia a canal
        local channel
        case "$freq" in
            2412) channel=1 ;; 2417) channel=2 ;; 2422) channel=3 ;;
            2427) channel=4 ;; 2432) channel=5 ;; 2437) channel=6 ;;
            2442) channel=7 ;; 2447) channel=8 ;; 2452) channel=9 ;;
            2457) channel=10 ;; 2462) channel=11 ;; 2467) channel=12 ;;
            2472) channel=13 ;; 5180) channel=36 ;; 5200) channel=40 ;;
            5220) channel=44 ;; 5240) channel=48 ;; 5260) channel=52 ;;
            5280) channel=56 ;; 5300) channel=60 ;; 5320) channel=64 ;;
            5500) channel=100 ;; 5520) channel=104 ;; 5540) channel=108 ;;
            5560) channel=112 ;; 5580) channel=116 ;; 5600) channel=120 ;;
            5620) channel=124 ;; 5640) channel=128 ;; 5660) channel=132 ;;
            5680) channel=136 ;; 5700) channel=140 ;; 5720) channel=144 ;;
            5745) channel=149 ;; 5765) channel=153 ;; 5785) channel=157 ;;
            5805) channel=161 ;; 5825) channel=165 ;;
            *) channel="$freq" ;;
        esac
        channel_count[$channel]=$(( ${channel_count[$channel]:-0} + 1 ))
    done < "$scan_file"

    # Log de utilizacion de canales
    log_monitor "Utilizacion de canales:"
    for ch in $(echo "${!channel_count[@]}" | tr ' ' '\n' | sort -n); do
        log_monitor "  Canal $ch: ${channel_count[$ch]} APs"
        # Alertar si un canal tiene demasiados APs (congestion)
        if [[ "${channel_count[$ch]}" -gt 15 ]]; then
            alert "Congestion en canal $ch: ${channel_count[$ch]} APs detectados"
        fi
    done
}

# ── Bucle principal de monitoreo ──────────────────────────
main() {
    log_monitor "═══ Inicio de monitoreo wireless ═══"

    WIFI_IFACE=$(detect_iface)
    if [[ -z "$WIFI_IFACE" ]]; then
        log_monitor "No hay interfaz wireless disponible. Monitoreo detenido."
        exit 0
    fi
    log_monitor "Interfaz wireless: $WIFI_IFACE"
    log_monitor "Intervalo de escaneo: ${SCAN_INTERVAL}s"

    load_whitelist
    log_monitor "Whitelist cargada: ${#WL_BSSID[@]} APs autorizados"

    # Modo oneshot o continuo
    if [[ "${1:-}" == "--oneshot" ]]; then
        log_monitor "Modo oneshot: un solo escaneo"
        SCAN_TEMP="${LOG_DIR}/scan-temp-$$.dat"
        if scan_aps "$WIFI_IFACE" > "$SCAN_TEMP" 2>/dev/null; then
            local ap_count
            ap_count=$(wc -l < "$SCAN_TEMP")
            log_monitor "Escaneo completado: $ap_count APs detectados"
            compare_with_baseline "$SCAN_TEMP"
            monitor_channels "$WIFI_IFACE" "$SCAN_TEMP"
            check_deauth_floods "$WIFI_IFACE"
            cp "$SCAN_TEMP" "$PREVIOUS_SCAN"
            rm -f "$SCAN_TEMP"
        else
            log_monitor "Error en el escaneo"
        fi
        log_monitor "═══ Fin de monitoreo oneshot ═══"
        return
    fi

    # Modo continuo (para systemd service)
    while true; do
        SCAN_TEMP="${LOG_DIR}/scan-temp-$$.dat"
        log_monitor "--- Escaneo periodico ---"

        if scan_aps "$WIFI_IFACE" > "$SCAN_TEMP" 2>/dev/null; then
            local ap_count
            ap_count=$(wc -l < "$SCAN_TEMP")
            log_monitor "Escaneo completado: $ap_count APs detectados"

            compare_with_baseline "$SCAN_TEMP"
            monitor_channels "$WIFI_IFACE" "$SCAN_TEMP"
            check_deauth_floods "$WIFI_IFACE"

            # Actualizar escaneo anterior
            cp "$SCAN_TEMP" "$PREVIOUS_SCAN"
        else
            log_monitor "Error en el escaneo - reintentando en ${SCAN_INTERVAL}s"
        fi

        rm -f "$SCAN_TEMP"

        # Rotar logs si superan 50MB
        if [[ -f "$SCAN_LOG" ]]; then
            local log_size
            log_size=$(stat -c %s "$SCAN_LOG" 2>/dev/null || echo "0")
            if [[ "$log_size" -gt 52428800 ]]; then
                mv "$SCAN_LOG" "${SCAN_LOG}.old"
                log_monitor "Log rotado (>50MB)"
            fi
        fi

        sleep "$SCAN_INTERVAL"
    done
}

main "$@"
EOFMONWIFI
    chmod +x /usr/local/bin/monitorizar-wireless.sh
    log_change "Creado" "/usr/local/bin/monitorizar-wireless.sh"

    # Systemd service para monitoreo continuo
    cat > /etc/systemd/system/securizar-wireless-monitor.service << 'EOFWIFIMONSVC'
[Unit]
Description=Securizar - Monitoreo Wireless Continuo
After=network-online.target
Wants=network-online.target
Documentation=man:iw(8)

[Service]
Type=simple
ExecStart=/usr/local/bin/monitorizar-wireless.sh
Restart=on-failure
RestartSec=60

# Hardening
NoNewPrivileges=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/var/log/securizar
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes

# Capacidades minimas (necesita CAP_NET_ADMIN para escaneo)
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

# Logs
StandardOutput=journal
StandardError=journal
SyslogIdentifier=securizar-wireless-monitor

[Install]
WantedBy=multi-user.target
EOFWIFIMONSVC
    chmod 644 /etc/systemd/system/securizar-wireless-monitor.service
    log_change "Creado" "/etc/systemd/system/securizar-wireless-monitor.service"

    if ask "¿Activar servicio de monitoreo wireless continuo?"; then
        systemctl daemon-reload 2>/dev/null || true
        systemctl enable securizar-wireless-monitor.service 2>/dev/null || true
        systemctl start securizar-wireless-monitor.service 2>/dev/null || true
        log_change "Activado" "securizar-wireless-monitor.service"
    else
        log_skip "activar servicio de monitoreo wireless"
    fi

else
    log_skip "monitoreo wireless continuo"
fi

# ============================================================
# S9: POLITICAS DE SEGURIDAD WIRELESS
# ============================================================
log_section "S9: POLITICAS DE SEGURIDAD WIRELESS"

log_info "Politicas de seguridad wireless empresarial:"
log_info "  - ALLOWED_PROTOCOLS, MIN_KEY_LENGTH"
log_info "  - REQUIRE_PMF, REQUIRE_802_1X"
log_info "  - MAX_OPEN_NETWORK_CONNECTIONS"
log_info "  - BLUETOOTH_POLICY, SCAN_INTERVAL"
log_info "  - Script de validacion: /usr/local/bin/validar-politica-wireless.sh"

if ask "¿Crear politicas de seguridad wireless?"; then

    POLICY_FILE="/etc/securizar/wireless-policy.conf"

    if [[ -f "$POLICY_FILE" ]]; then
        cp -a "$POLICY_FILE" "$BACKUP_DIR/"
        log_change "Backup" "$POLICY_FILE"
    fi

    cat > "$POLICY_FILE" << 'EOFPOLICY'
# ============================================================
# wireless-policy.conf - Politicas de seguridad wireless
# Generado por securizar - Modulo 56
# ============================================================
# Este archivo define la politica de seguridad wireless de la
# organizacion. Es consultado por los scripts de validacion
# y monitoreo.
# ============================================================

# ── Protocolos WiFi permitidos ────────────────────────────
# Protocolos aceptados para conexiones WiFi
# Opciones: WPA3-SAE WPA3-Enterprise WPA2-Enterprise WPA2-PSK
ALLOWED_PROTOCOLS="WPA3-SAE WPA3-Enterprise"

# ── Longitud minima de clave ──────────────────────────────
# Longitud minima de la clave de cifrado en bits
MIN_KEY_LENGTH=128

# ── Requerir PMF (802.11w) ───────────────────────────────
# Si se requiere Protected Management Frames
# yes = obligatorio, optional = preferido, no = no requerido
REQUIRE_PMF=yes

# ── Requerir 802.1X ──────────────────────────────────────
# Si se requiere autenticacion 802.1X (enterprise)
# yes = solo enterprise, no = PSK aceptable
REQUIRE_802_1X=yes

# ── Redes abiertas ───────────────────────────────────────
# Numero maximo de conexiones a redes abiertas permitidas
# 0 = no se permiten redes abiertas
MAX_OPEN_NETWORK_CONNECTIONS=0

# ── Politica Bluetooth ────────────────────────────────────
# disabled = Bluetooth deshabilitado completamente
# restricted = Bluetooth habilitado con restricciones
# unrestricted = Sin restricciones (no recomendado)
BLUETOOTH_POLICY="disabled"

# ── Intervalo de escaneo (segundos) ──────────────────────
# Frecuencia de escaneo de rogue APs y monitoreo wireless
SCAN_INTERVAL=3600

# ── MAC randomization ────────────────────────────────────
# Requerir randomizacion de MAC en escaneo y conexion
REQUIRE_MAC_RANDOMIZATION=yes

# ── Metodos EAP permitidos ───────────────────────────────
# Metodos de autenticacion EAP aceptados
ALLOWED_EAP_METHODS="TLS PEAP TTLS"

# ── Verificacion de servidor RADIUS ──────────────────────
# Requerir verificacion del certificado del servidor RADIUS
REQUIRE_SERVER_CERT_VALIDATION=yes

# ── Tiempo maximo de sesion WiFi (segundos) ──────────────
# 0 = sin limite
MAX_SESSION_TIME=0

# ── Logging ───────────────────────────────────────────────
# Nivel de logging para eventos wireless
# debug, info, warning, error
LOG_LEVEL=info

# ── Alertas ───────────────────────────────────────────────
# Habilitar alertas por email (requiere configurar SMTP)
ALERT_EMAIL_ENABLED=no
ALERT_EMAIL_TO=""
ALERT_EMAIL_FROM="securizar@$(hostname -f 2>/dev/null || echo localhost)"

# ── Whitelist ─────────────────────────────────────────────
# Ruta al archivo de whitelist de APs
AP_WHITELIST_FILE="/etc/securizar/ap-whitelist.conf"
EOFPOLICY
    chmod 640 "$POLICY_FILE"
    log_change "Creado" "$POLICY_FILE"

    # Script de validacion de politica wireless
    cat > /usr/local/bin/validar-politica-wireless.sh << 'EOFVALIDPOL'
#!/bin/bash
# ============================================================
# validar-politica-wireless.sh - Validar cumplimiento de politica
# Generado por securizar - Modulo 56
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

POLICY_FILE="/etc/securizar/wireless-policy.conf"

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  VALIDACION DE POLITICA WIRELESS${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""
echo -e "${DIM}Fecha: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo ""

# Cargar politica
if [[ ! -f "$POLICY_FILE" ]]; then
    echo -e "${RED}[X] Politica no encontrada: $POLICY_FILE${NC}"
    echo -e "${RED}[X] Ejecute seguridad-wireless.sh primero${NC}"
    exit 1
fi

source "$POLICY_FILE"
echo -e "${GREEN}[+]${NC} Politica cargada: $POLICY_FILE"
echo ""

score=0
total=0
violations=()

check() {
    local desc="$1" result="$2"
    ((total++))
    if [[ "$result" == "OK" ]]; then
        echo -e "  ${GREEN}[OK]${NC} $desc"
        ((score++))
    elif [[ "$result" == "WARN" ]]; then
        echo -e "  ${YELLOW}[!!]${NC} $desc"
    else
        echo -e "  ${RED}[XX]${NC} $desc"
        violations+=("$desc")
    fi
}

# ── 1. Verificar redes WiFi guardadas ─────────────────────
echo -e "${CYAN}[1] Perfiles de red WiFi:${NC}"
NM_CONN_DIR="/etc/NetworkManager/system-connections"
if [[ -d "$NM_CONN_DIR" ]]; then
    open_count=0
    wpa2_psk_count=0
    enterprise_count=0
    wpa3_count=0

    for conn in "$NM_CONN_DIR"/*; do
        [[ -f "$conn" ]] || continue
        if grep -q "type=wifi" "$conn" 2>/dev/null || \
           grep -q "type=802-11-wireless" "$conn" 2>/dev/null; then
            key_mgmt=$(grep "^key-mgmt=" "$conn" 2>/dev/null | cut -d= -f2- || echo "none")
            case "$key_mgmt" in
                none|"") ((open_count++)) || true ;;
                wpa-psk) ((wpa2_psk_count++)) || true ;;
                wpa-eap*) ((enterprise_count++)) || true ;;
                sae) ((wpa3_count++)) || true ;;
            esac
        fi
    done

    # Verificar contra politica
    if [[ "$MAX_OPEN_NETWORK_CONNECTIONS" -eq 0 ]] && [[ $open_count -gt 0 ]]; then
        check "Redes abiertas: $open_count (politica: 0)" "FAIL"
    elif [[ $open_count -le "$MAX_OPEN_NETWORK_CONNECTIONS" ]]; then
        check "Redes abiertas: $open_count (limite: $MAX_OPEN_NETWORK_CONNECTIONS)" "OK"
    else
        check "Redes abiertas: $open_count (excede limite: $MAX_OPEN_NETWORK_CONNECTIONS)" "FAIL"
    fi

    if [[ "$REQUIRE_802_1X" == "yes" ]] && [[ $wpa2_psk_count -gt 0 ]]; then
        check "Redes WPA2-PSK: $wpa2_psk_count (politica requiere 802.1X)" "FAIL"
    else
        check "Redes WPA2-PSK: $wpa2_psk_count" "OK"
    fi

    if [[ "$ALLOWED_PROTOCOLS" != *"WPA2-PSK"* ]] && [[ $wpa2_psk_count -gt 0 ]]; then
        check "WPA2-PSK no esta en protocolos permitidos" "WARN"
    fi

    check "Redes Enterprise: $enterprise_count" "OK"
    check "Redes WPA3: $wpa3_count" "OK"
else
    echo -e "  ${DIM}NetworkManager no encontrado${NC}"
fi
echo ""

# ── 2. Verificar PMF ──────────────────────────────────────
echo -e "${CYAN}[2] PMF (802.11w):${NC}"
if [[ "$REQUIRE_PMF" == "yes" ]]; then
    # Verificar en configuracion global
    pmf_configured=0
    if [[ -f "/etc/NetworkManager/conf.d/99-securizar-wifi.conf" ]]; then
        pmf_configured=1
        check "Configuracion securizar NM presente" "OK"
    fi
    # Verificar wpa_supplicant
    for f in /etc/wpa_supplicant/wpa_supplicant.conf /etc/wpa_supplicant.conf; do
        if [[ -f "$f" ]] && grep -q "pmf=2" "$f" 2>/dev/null; then
            pmf_configured=1
            check "PMF requerido en $f" "OK"
        fi
    done
    if [[ $pmf_configured -eq 0 ]]; then
        check "PMF no configurado (politica: requerido)" "FAIL"
    fi
else
    check "PMF: no requerido por politica" "OK"
fi
echo ""

# ── 3. Verificar MAC randomization ───────────────────────
echo -e "${CYAN}[3] MAC address randomization:${NC}"
if [[ "${REQUIRE_MAC_RANDOMIZATION:-no}" == "yes" ]]; then
    if [[ -f "/etc/NetworkManager/conf.d/99-securizar-wifi.conf" ]]; then
        if grep -q "scan-rand-mac-address=yes" "/etc/NetworkManager/conf.d/99-securizar-wifi.conf" 2>/dev/null; then
            check "MAC randomization en escaneo: habilitada" "OK"
        else
            check "MAC randomization en escaneo: no configurada" "FAIL"
        fi
        if grep -q "cloned-mac-address=random" "/etc/NetworkManager/conf.d/99-securizar-wifi.conf" 2>/dev/null; then
            check "MAC aleatoria por conexion: habilitada" "OK"
        else
            check "MAC aleatoria por conexion: no configurada" "FAIL"
        fi
    else
        check "Configuracion de MAC randomization no encontrada" "FAIL"
    fi
else
    check "MAC randomization: no requerido por politica" "OK"
fi
echo ""

# ── 4. Verificar Bluetooth ───────────────────────────────
echo -e "${CYAN}[4] Politica Bluetooth:${NC}"
case "${BLUETOOTH_POLICY:-unrestricted}" in
    disabled)
        bt_active=0
        if command -v rfkill &>/dev/null; then
            if rfkill list bluetooth 2>/dev/null | grep -q "Soft blocked: no"; then
                bt_active=1
            fi
        fi
        if systemctl is-active bluetooth &>/dev/null; then
            bt_active=1
        fi
        if [[ $bt_active -eq 0 ]]; then
            check "Bluetooth: deshabilitado (cumple politica)" "OK"
        else
            check "Bluetooth: ACTIVO (politica: disabled)" "FAIL"
        fi
        ;;
    restricted)
        bt_conf="/etc/bluetooth/main.conf"
        if [[ -f "$bt_conf" ]]; then
            if grep -q "^Discoverable = false" "$bt_conf" 2>/dev/null; then
                check "Bluetooth: discoverable=false" "OK"
            else
                check "Bluetooth: discoverable no deshabilitado" "FAIL"
            fi
            if grep -q "^Pairable = false" "$bt_conf" 2>/dev/null; then
                check "Bluetooth: pairable=false" "OK"
            else
                check "Bluetooth: pairable no deshabilitado" "FAIL"
            fi
        else
            check "Bluetooth: main.conf no encontrado" "WARN"
        fi
        ;;
    *)
        check "Bluetooth: sin restricciones (no recomendado)" "WARN"
        ;;
esac
echo ""

# ── 5. Verificar monitoreo ───────────────────────────────
echo -e "${CYAN}[5] Monitoreo wireless:${NC}"
if systemctl is-active securizar-wireless-monitor &>/dev/null; then
    check "Servicio de monitoreo wireless: activo" "OK"
elif systemctl is-enabled securizar-wireless-monitor &>/dev/null; then
    check "Servicio de monitoreo wireless: habilitado pero inactivo" "WARN"
else
    check "Servicio de monitoreo wireless: no configurado" "FAIL"
fi

if systemctl is-active securizar-rogue-ap.timer &>/dev/null; then
    check "Timer de deteccion de rogue APs: activo" "OK"
elif systemctl is-enabled securizar-rogue-ap.timer &>/dev/null; then
    check "Timer de deteccion de rogue APs: habilitado pero inactivo" "WARN"
else
    check "Timer de deteccion de rogue APs: no configurado" "WARN"
fi

# Verificar whitelist
if [[ -f "${AP_WHITELIST_FILE:-/etc/securizar/ap-whitelist.conf}" ]]; then
    wl_count=$(grep -cvE '^\s*#|^\s*$' "${AP_WHITELIST_FILE:-/etc/securizar/ap-whitelist.conf}" 2>/dev/null || echo "0")
    if [[ "$wl_count" -gt 0 ]]; then
        check "Whitelist de APs: $wl_count entradas" "OK"
    else
        check "Whitelist de APs: vacia (agregar APs autorizados)" "WARN"
    fi
else
    check "Whitelist de APs: no encontrada" "FAIL"
fi
echo ""

# ── 6. Verificar wireless en servidores ───────────────────
echo -e "${CYAN}[6] Wireless en servidores:${NC}"
if ! command -v Xorg &>/dev/null && [[ -z "${DISPLAY:-}" ]] && [[ -z "${WAYLAND_DISPLAY:-}" ]]; then
    # Es un servidor
    wifi_active=0
    for wdir in /sys/class/net/*/wireless; do
        [[ -d "$wdir" ]] && wifi_active=1 && break
    done
    if [[ $wifi_active -eq 0 ]]; then
        check "Servidor sin interfaces wireless activas" "OK"
    else
        check "Servidor CON interfaces wireless activas (deshabilitar)" "FAIL"
    fi
    # Verificar blacklist
    if [[ -f "/etc/modprobe.d/securizar-no-wireless.conf" ]]; then
        check "Blacklist de modulos wireless presente" "OK"
    else
        check "Sin blacklist de modulos wireless en servidor" "WARN"
    fi
else
    check "Estacion de trabajo: wireless permitido" "OK"
fi
echo ""

# ── Resumen ───────────────────────────────────────────────
echo -e "${BOLD}══════════════════════════════════════════${NC}"
pct=0
if [[ $total -gt 0 ]]; then
    pct=$(( (score * 100) / total ))
fi

if [[ $pct -ge 80 ]]; then
    echo -e "  Puntuacion: ${GREEN}${BOLD}${score}/${total} (${pct}%)${NC}"
    echo -e "  Cumplimiento: ${GREEN}${BOLD}BUENO${NC}"
elif [[ $pct -ge 50 ]]; then
    echo -e "  Puntuacion: ${YELLOW}${BOLD}${score}/${total} (${pct}%)${NC}"
    echo -e "  Cumplimiento: ${YELLOW}${BOLD}PARCIAL${NC}"
else
    echo -e "  Puntuacion: ${RED}${BOLD}${score}/${total} (${pct}%)${NC}"
    echo -e "  Cumplimiento: ${RED}${BOLD}NO CUMPLE${NC}"
fi

if [[ ${#violations[@]} -gt 0 ]]; then
    echo ""
    echo -e "  ${RED}Violaciones de politica:${NC}"
    for v in "${violations[@]}"; do
        echo -e "    ${RED}-${NC} $v"
    done
fi
echo -e "${BOLD}══════════════════════════════════════════${NC}"
EOFVALIDPOL
    chmod +x /usr/local/bin/validar-politica-wireless.sh
    log_change "Creado" "/usr/local/bin/validar-politica-wireless.sh"

else
    log_skip "politicas de seguridad wireless"
fi

# ============================================================
# S10: AUDITORIA INTEGRAL DE SEGURIDAD WIRELESS
# ============================================================
log_section "S10: AUDITORIA INTEGRAL DE SEGURIDAD WIRELESS"

log_info "Auditoria integral de seguridad wireless:"
log_info "  - Inventario de interfaces y estado"
log_info "  - Evaluacion de seguridad WiFi"
log_info "  - Estado de seguridad Bluetooth"
log_info "  - Resultados de escaneo de rogue APs"
log_info "  - Verificacion de protecciones contra ataques"
log_info "  - Cumplimiento de politica"
log_info "  - Rating: BUENO/MEJORABLE/DEFICIENTE"
log_info "  - Cron semanal: /etc/cron.weekly/auditoria-wireless"

if ask "¿Crear sistema de auditoria integral wireless?"; then

    AUDIT_LOG_DIR="/var/log/securizar"
    mkdir -p "$AUDIT_LOG_DIR"

    # Script de auditoria integral
    cat > /usr/local/bin/auditoria-wireless-completa.sh << 'EOFAUDITINT'
#!/bin/bash
# ============================================================
# auditoria-wireless-completa.sh - Auditoria integral wireless
# Generado por securizar - Modulo 56
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

FECHA=$(date '+%Y%m%d-%H%M%S')
REPORT_FILE="/var/log/securizar/auditoria-wireless-${FECHA}.log"
POLICY_FILE="/etc/securizar/wireless-policy.conf"

# Variables para puntuacion global
GLOBAL_SCORE=0
GLOBAL_TOTAL=0

mkdir -p /var/log/securizar

# ── Funciones ─────────────────────────────────────────────
_out() {
    echo -e "$1"
    echo -e "$1" | sed 's/\x1b\[[0-9;]*m//g' >> "$REPORT_FILE"
}

_check() {
    local desc="$1" result="$2"
    ((GLOBAL_TOTAL++))
    if [[ "$result" == "OK" ]]; then
        _out "  ${GREEN}[OK]${NC} $desc"
        ((GLOBAL_SCORE++))
    elif [[ "$result" == "WARN" ]]; then
        _out "  ${YELLOW}[!!]${NC} $desc"
    else
        _out "  ${RED}[XX]${NC} $desc"
    fi
}

# ── Inicio ────────────────────────────────────────────────
_out "${BOLD}══════════════════════════════════════════════════════════${NC}"
_out "${BOLD}  AUDITORIA INTEGRAL DE SEGURIDAD WIRELESS${NC}"
_out "${BOLD}══════════════════════════════════════════════════════════${NC}"
_out ""
_out "${DIM}Fecha: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
_out "${DIM}Host: $(hostname -f 2>/dev/null || hostname)${NC}"
_out "${DIM}Kernel: $(uname -r)${NC}"
_out "${DIM}Reporte: $REPORT_FILE${NC}"
_out ""

# ══════════════════════════════════════════════════════════
# SECCION 1: INVENTARIO DE INTERFACES WIRELESS
# ══════════════════════════════════════════════════════════
_out "${CYAN}══ [1/6] INVENTARIO DE INTERFACES WIRELESS ══${NC}"
_out ""

# Interfaces wireless
iface_count=0
for wdir in /sys/class/net/*/wireless; do
    if [[ -d "$wdir" ]]; then
        iface=$(basename "$(dirname "$wdir")")
        ((iface_count++))
        driver="desconocido"
        if [[ -L "/sys/class/net/${iface}/device/driver" ]]; then
            driver=$(basename "$(readlink -f "/sys/class/net/${iface}/device/driver")" 2>/dev/null || echo "?")
        fi
        state=$(cat "/sys/class/net/${iface}/operstate" 2>/dev/null || echo "?")
        mac=$(cat "/sys/class/net/${iface}/address" 2>/dev/null || echo "?")
        _out "  Interfaz: ${BOLD}${iface}${NC}"
        _out "    Driver: $driver | Estado: $state | MAC: $mac"
    fi
done

if [[ $iface_count -eq 0 ]]; then
    _check "Sin interfaces wireless activas" "OK"
else
    # En servidores, wireless activo es un problema
    if ! command -v Xorg &>/dev/null && [[ -z "${DISPLAY:-}" ]] && [[ -z "${WAYLAND_DISPLAY:-}" ]]; then
        _check "$iface_count interfaz(ces) wireless en servidor" "FAIL"
    else
        _check "$iface_count interfaz(ces) wireless en estacion de trabajo" "OK"
    fi
fi

# rfkill
if command -v rfkill &>/dev/null; then
    wifi_blocked=$(rfkill list wifi 2>/dev/null | grep -c "Soft blocked: yes" || echo "0")
    bt_blocked=$(rfkill list bluetooth 2>/dev/null | grep -c "Soft blocked: yes" || echo "0")
    _out ""
    _out "  rfkill WiFi bloqueado: $wifi_blocked"
    _out "  rfkill BT bloqueado: $bt_blocked"
fi

# Modulos wireless cargados
mods=$(lsmod 2>/dev/null | grep -iE 'iwl|ath|rt2|rtl|b43|brcm|mt76|cfg80211|mac80211' | awk '{print $1}' || true)
if [[ -n "$mods" ]]; then
    mod_count=$(echo "$mods" | wc -l)
    _check "Modulos wireless cargados: $mod_count" "WARN"
else
    _check "Sin modulos wireless cargados" "OK"
fi

# Blacklists
if [[ -f "/etc/modprobe.d/securizar-no-wireless.conf" ]]; then
    _check "Blacklist de modulos wireless presente" "OK"
fi
_out ""

# ══════════════════════════════════════════════════════════
# SECCION 2: CONFIGURACION DE SEGURIDAD WIFI
# ══════════════════════════════════════════════════════════
_out "${CYAN}══ [2/6] CONFIGURACION DE SEGURIDAD WIFI ══${NC}"
_out ""

# NetworkManager hardening
nm_conf="/etc/NetworkManager/conf.d/99-securizar-wifi.conf"
if [[ -f "$nm_conf" ]]; then
    _check "Configuracion securizar WiFi NM presente" "OK"
    if grep -q "scan-rand-mac-address=yes" "$nm_conf" 2>/dev/null; then
        _check "MAC randomization en escaneo" "OK"
    else
        _check "MAC randomization en escaneo no configurada" "FAIL"
    fi
    if grep -q "cloned-mac-address=random" "$nm_conf" 2>/dev/null; then
        _check "MAC aleatoria por conexion" "OK"
    else
        _check "MAC aleatoria por conexion no configurada" "WARN"
    fi
else
    _check "Configuracion securizar WiFi NM no encontrada" "FAIL"
fi

# wpa_supplicant
wpa_found=0
for f in /etc/wpa_supplicant/wpa_supplicant.conf /etc/wpa_supplicant.conf; do
    if [[ -f "$f" ]]; then
        wpa_found=1
        if grep -q "pmf=2" "$f" 2>/dev/null; then
            _check "PMF requerido en $f" "OK"
        elif grep -q "pmf=1" "$f" 2>/dev/null; then
            _check "PMF opcional en $f (deberia ser 2)" "WARN"
        else
            _check "PMF no configurado en $f" "FAIL"
        fi
        if grep -q "disable_pmksa_caching=1" "$f" 2>/dev/null; then
            _check "PMKID caching deshabilitado" "OK"
        else
            _check "PMKID caching no deshabilitado" "WARN"
        fi
    fi
done

# Perfiles de red
NM_CONN_DIR="/etc/NetworkManager/system-connections"
if [[ -d "$NM_CONN_DIR" ]]; then
    open_nets=0
    total_wifi_nets=0
    no_pmf_nets=0
    for conn in "$NM_CONN_DIR"/*; do
        [[ -f "$conn" ]] || continue
        if grep -q "type=wifi" "$conn" 2>/dev/null; then
            ((total_wifi_nets++)) || true
            if ! grep -q "key-mgmt=" "$conn" 2>/dev/null || \
               grep -q "key-mgmt=none" "$conn" 2>/dev/null; then
                ((open_nets++)) || true
            fi
            if ! grep -q "pmf=" "$conn" 2>/dev/null; then
                ((no_pmf_nets++)) || true
            fi
        fi
    done
    _out ""
    _out "  Total perfiles WiFi: $total_wifi_nets"
    if [[ $open_nets -eq 0 ]]; then
        _check "Sin redes abiertas guardadas" "OK"
    else
        _check "$open_nets red(es) abierta(s) guardada(s)" "FAIL"
    fi
    if [[ $no_pmf_nets -eq 0 ]] || [[ $total_wifi_nets -eq 0 ]]; then
        _check "Todas las redes con PMF configurado" "OK"
    else
        _check "$no_pmf_nets red(es) sin PMF configurado" "WARN"
    fi
fi
_out ""

# ══════════════════════════════════════════════════════════
# SECCION 3: SEGURIDAD BLUETOOTH
# ══════════════════════════════════════════════════════════
_out "${CYAN}══ [3/6] SEGURIDAD BLUETOOTH ══${NC}"
_out ""

bt_present=0
if [[ -d /sys/class/bluetooth ]] || lsmod 2>/dev/null | grep -q "bluetooth\|btusb"; then
    bt_present=1
fi

if [[ $bt_present -eq 0 ]]; then
    _check "Sin hardware Bluetooth detectado" "OK"
else
    _out "  Hardware Bluetooth detectado"

    # Servicio bluetooth
    if systemctl is-active bluetooth &>/dev/null; then
        if ! command -v Xorg &>/dev/null && [[ -z "${DISPLAY:-}" ]]; then
            _check "Bluetooth activo en servidor" "FAIL"
        else
            _check "Bluetooth activo en estacion de trabajo" "OK"
        fi
    else
        _check "Servicio Bluetooth inactivo" "OK"
    fi

    # Configuracion
    bt_conf="/etc/bluetooth/main.conf"
    if [[ -f "$bt_conf" ]]; then
        if grep -q "^Discoverable = false" "$bt_conf" 2>/dev/null; then
            _check "Bluetooth: Discoverable = false" "OK"
        else
            _check "Bluetooth: Discoverable no deshabilitado" "FAIL"
        fi
        if grep -q "^Pairable = false" "$bt_conf" 2>/dev/null; then
            _check "Bluetooth: Pairable = false" "OK"
        else
            _check "Bluetooth: Pairable no deshabilitado" "FAIL"
        fi
        if grep -q "^Privacy = device" "$bt_conf" 2>/dev/null; then
            _check "Bluetooth: Privacy = device" "OK"
        else
            _check "Bluetooth: Privacy no configurado" "WARN"
        fi
    else
        _check "Bluetooth: main.conf no encontrado" "WARN"
    fi

    # Blacklist
    if [[ -f "/etc/modprobe.d/securizar-no-bluetooth.conf" ]]; then
        _check "Blacklist de modulos Bluetooth presente" "OK"
    fi
fi
_out ""

# ══════════════════════════════════════════════════════════
# SECCION 4: ESCANEO DE ROGUE APs
# ══════════════════════════════════════════════════════════
_out "${CYAN}══ [4/6] DETECCION DE ROGUE APs ══${NC}"
_out ""

# Verificar si el timer esta activo
if systemctl is-active securizar-rogue-ap.timer &>/dev/null; then
    _check "Timer de escaneo de rogue APs: activo" "OK"
else
    _check "Timer de escaneo de rogue APs: no activo" "WARN"
fi

# Verificar whitelist
wl_file="/etc/securizar/ap-whitelist.conf"
if [[ -f "$wl_file" ]]; then
    wl_count=$(grep -cvE '^\s*#|^\s*$' "$wl_file" 2>/dev/null || echo "0")
    if [[ "$wl_count" -gt 0 ]]; then
        _check "Whitelist de APs: $wl_count entradas" "OK"
    else
        _check "Whitelist de APs: vacia" "WARN"
    fi
else
    _check "Whitelist de APs no encontrada" "FAIL"
fi

# Verificar ultimo escaneo
rogue_log="/var/log/securizar/rogue-ap"
if [[ -d "$rogue_log" ]]; then
    last_scan=$(ls -t "$rogue_log"/scan-*.log 2>/dev/null | head -1)
    if [[ -n "$last_scan" ]]; then
        scan_age=$(( ($(date +%s) - $(stat -c %Y "$last_scan")) / 3600 ))
        if [[ $scan_age -lt 24 ]]; then
            _check "Ultimo escaneo: hace ${scan_age}h" "OK"
        elif [[ $scan_age -lt 168 ]]; then
            _check "Ultimo escaneo: hace ${scan_age}h (>24h)" "WARN"
        else
            _check "Ultimo escaneo: hace ${scan_age}h (>1 semana)" "FAIL"
        fi

        # Verificar alertas recientes
        if [[ -f "${rogue_log}/alertas.log" ]]; then
            recent_alerts=$(tail -100 "${rogue_log}/alertas.log" 2>/dev/null | \
                grep -c "$(date +%Y-%m-%d)" || echo "0")
            if [[ "$recent_alerts" -gt 0 ]]; then
                _check "Alertas de hoy: $recent_alerts" "WARN"
            else
                _check "Sin alertas de rogue APs hoy" "OK"
            fi
        fi
    else
        _check "Sin escaneos de rogue APs realizados" "WARN"
    fi
else
    _check "Directorio de logs de rogue APs no encontrado" "WARN"
fi

# Realizar escaneo rapido si hay interfaz y somos root
if [[ $EUID -eq 0 ]] && command -v iw &>/dev/null; then
    wifi_iface=""
    for wdir in /sys/class/net/*/wireless; do
        if [[ -d "$wdir" ]]; then
            wifi_iface=$(basename "$(dirname "$wdir")")
            break
        fi
    done
    if [[ -n "$wifi_iface" ]]; then
        _out ""
        _out "  Ejecutando escaneo rapido en $wifi_iface..."
        scan_count=$(iw dev "$wifi_iface" scan 2>/dev/null | grep -c "^BSS" || echo "0")
        _out "  APs detectados en escaneo rapido: $scan_count"
    fi
fi
_out ""

# ══════════════════════════════════════════════════════════
# SECCION 5: PROTECCIONES CONTRA ATAQUES
# ══════════════════════════════════════════════════════════
_out "${CYAN}══ [5/6] PROTECCIONES CONTRA ATAQUES WIFI ══${NC}"
_out ""

# Version wpa_supplicant
if command -v wpa_supplicant &>/dev/null; then
    ver=$(wpa_supplicant -v 2>&1 | head -1)
    ver_num=$(echo "$ver" | grep -oP 'v\K[0-9.]+' || echo "0.0")
    major=$(echo "$ver_num" | cut -d. -f1)
    minor=$(echo "$ver_num" | cut -d. -f2)

    _out "  wpa_supplicant: $ver"

    if [[ "$major" -ge 2 ]] && [[ "$minor" -ge 10 ]]; then
        _check "KRACK (CVE-2017-13077): parcheado" "OK"
        _check "DragonBlood (CVE-2019-9494): parcheado" "OK"
        _check "FragAttacks (CVE-2020-24586): parcheado" "OK"
    elif [[ "$major" -ge 2 ]] && [[ "$minor" -ge 9 ]]; then
        _check "KRACK: parcheado" "OK"
        _check "DragonBlood: parcheado" "OK"
        _check "FragAttacks: verificar" "WARN"
    elif [[ "$major" -ge 2 ]] && [[ "$minor" -ge 7 ]]; then
        _check "KRACK: parcheado" "OK"
        _check "DragonBlood: VULNERABLE" "FAIL"
    else
        _check "KRACK: posiblemente VULNERABLE" "FAIL"
    fi
else
    _out "  wpa_supplicant no encontrado"
fi

# Kernel Bluetooth vulnerabilities
kernel_major=$(uname -r | cut -d. -f1)
kernel_minor=$(uname -r | cut -d. -f2)

if [[ "$kernel_major" -gt 4 ]] || { [[ "$kernel_major" -eq 4 ]] && [[ "$kernel_minor" -ge 14 ]]; }; then
    _check "BlueBorne (CVE-2017-1000251): parcheado" "OK"
else
    _check "BlueBorne: posiblemente vulnerable" "FAIL"
fi

if [[ "$kernel_major" -gt 5 ]] || { [[ "$kernel_major" -eq 5 ]] && [[ "$kernel_minor" -ge 2 ]]; }; then
    _check "KNOB (CVE-2019-9506): parcheado" "OK"
else
    _check "KNOB: posiblemente vulnerable" "FAIL"
fi
_out ""

# ══════════════════════════════════════════════════════════
# SECCION 6: CUMPLIMIENTO DE POLITICA
# ══════════════════════════════════════════════════════════
_out "${CYAN}══ [6/6] CUMPLIMIENTO DE POLITICA ══${NC}"
_out ""

if [[ -f "$POLICY_FILE" ]]; then
    _check "Archivo de politica wireless presente" "OK"
    source "$POLICY_FILE" 2>/dev/null || true
    _out "  Protocolos permitidos: ${ALLOWED_PROTOCOLS:-no definido}"
    _out "  Requerir PMF: ${REQUIRE_PMF:-no definido}"
    _out "  Requerir 802.1X: ${REQUIRE_802_1X:-no definido}"
    _out "  Max redes abiertas: ${MAX_OPEN_NETWORK_CONNECTIONS:-no definido}"
    _out "  Politica BT: ${BLUETOOTH_POLICY:-no definido}"
    _out "  Intervalo escaneo: ${SCAN_INTERVAL:-no definido}s"

    # Verificar que hay scripts de monitoreo
    for script in /usr/local/bin/auditar-wireless.sh \
                  /usr/local/bin/detectar-rogue-ap.sh \
                  /usr/local/bin/verificar-protecciones-wifi.sh \
                  /usr/local/bin/securizar-bluetooth.sh \
                  /usr/local/bin/monitorizar-wireless.sh \
                  /usr/local/bin/validar-politica-wireless.sh; do
        if [[ -x "$script" ]]; then
            _check "Script presente: $(basename "$script")" "OK"
        else
            _check "Script falta: $(basename "$script")" "WARN"
        fi
    done
else
    _check "Politica wireless no definida" "FAIL"
    _out "  Ejecute seguridad-wireless.sh seccion S9 para crear la politica"
fi

# Servicio de monitoreo
if systemctl is-active securizar-wireless-monitor &>/dev/null; then
    _check "Monitoreo wireless continuo: activo" "OK"
elif systemctl is-enabled securizar-wireless-monitor &>/dev/null; then
    _check "Monitoreo wireless continuo: habilitado" "WARN"
else
    _check "Monitoreo wireless continuo: no configurado" "WARN"
fi
_out ""

# ══════════════════════════════════════════════════════════
# RESUMEN GLOBAL
# ══════════════════════════════════════════════════════════
_out "${BOLD}══════════════════════════════════════════════════════════${NC}"
_out "${BOLD}  RESUMEN DE AUDITORIA WIRELESS${NC}"
_out "${BOLD}══════════════════════════════════════════════════════════${NC}"
_out ""

pct=0
if [[ $GLOBAL_TOTAL -gt 0 ]]; then
    pct=$(( (GLOBAL_SCORE * 100) / GLOBAL_TOTAL ))
fi

_out "  Checks ejecutados: $GLOBAL_TOTAL"
_out "  Checks pasados:    $GLOBAL_SCORE"
_out "  Porcentaje:        ${pct}%"
_out ""

if [[ $pct -ge 80 ]]; then
    _out "  ${GREEN}${BOLD}╔═════════════════════════════════════╗${NC}"
    _out "  ${GREEN}${BOLD}║  ESTADO: BUENO (${pct}%)               ║${NC}"
    _out "  ${GREEN}${BOLD}║  La seguridad wireless es adecuada  ║${NC}"
    _out "  ${GREEN}${BOLD}╚═════════════════════════════════════╝${NC}"
elif [[ $pct -ge 50 ]]; then
    _out "  ${YELLOW}${BOLD}╔═════════════════════════════════════╗${NC}"
    _out "  ${YELLOW}${BOLD}║  ESTADO: MEJORABLE (${pct}%)           ║${NC}"
    _out "  ${YELLOW}${BOLD}║  Hay aspectos que mejorar           ║${NC}"
    _out "  ${YELLOW}${BOLD}╚═════════════════════════════════════╝${NC}"
else
    _out "  ${RED}${BOLD}╔═════════════════════════════════════╗${NC}"
    _out "  ${RED}${BOLD}║  ESTADO: DEFICIENTE (${pct}%)           ║${NC}"
    _out "  ${RED}${BOLD}║  Se requiere accion inmediata        ║${NC}"
    _out "  ${RED}${BOLD}╚═════════════════════════════════════╝${NC}"
fi

_out ""
_out "${DIM}Reporte guardado en: $REPORT_FILE${NC}"
_out "${BOLD}══════════════════════════════════════════════════════════${NC}"
EOFAUDITINT
    chmod +x /usr/local/bin/auditoria-wireless-completa.sh
    log_change "Creado" "/usr/local/bin/auditoria-wireless-completa.sh"

    # Cron weekly para auditoria
    cat > /etc/cron.weekly/auditoria-wireless << 'EOFCRONWIFI'
#!/bin/bash
# ============================================================
# Auditoria wireless semanal - securizar Modulo 56
# ============================================================

LOG_DIR="/var/log/securizar"
mkdir -p "$LOG_DIR"

# Ejecutar auditoria
/usr/local/bin/auditoria-wireless-completa.sh > /dev/null 2>&1

# Rotar logs antiguos (mantener 90 dias)
find "$LOG_DIR" -name "auditoria-wireless-*.log" -mtime +90 -delete 2>/dev/null || true

# Rotar logs de rogue AP (mantener 30 dias)
find "$LOG_DIR/rogue-ap" -name "scan-*.log" -mtime +30 -delete 2>/dev/null || true

# Rotar logs de monitoreo wireless (mantener 30 dias)
find "$LOG_DIR/wireless-monitor" -name "scan-*.log" -mtime +30 -delete 2>/dev/null || true
EOFCRONWIFI
    chmod +x /etc/cron.weekly/auditoria-wireless
    log_change "Creado" "/etc/cron.weekly/auditoria-wireless"

    log_info "Auditoria integral wireless configurada"
    log_info "  - Script: /usr/local/bin/auditoria-wireless-completa.sh"
    log_info "  - Cron semanal: /etc/cron.weekly/auditoria-wireless"
    log_info "  - Reportes en: /var/log/securizar/auditoria-wireless-*.log"

else
    log_skip "auditoria integral wireless"
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
log_section "MODULO 56 COMPLETADO"

log_info "Seguridad Wireless Empresarial configurada."
log_info ""
log_info "Scripts creados:"
log_info "  /usr/local/bin/auditar-wireless.sh            - Auditoria de interfaces"
log_info "  /usr/local/bin/detectar-rogue-ap.sh           - Deteccion de rogue APs"
log_info "  /usr/local/bin/verificar-protecciones-wifi.sh  - Verificar protecciones"
log_info "  /usr/local/bin/securizar-bluetooth.sh          - Hardening Bluetooth"
log_info "  /usr/local/bin/monitorizar-wireless.sh         - Monitoreo continuo"
log_info "  /usr/local/bin/validar-politica-wireless.sh    - Validar politica"
log_info "  /usr/local/bin/auditoria-wireless-completa.sh  - Auditoria integral"
log_info "  /usr/local/bin/securizar-radius-setup.sh       - Setup FreeRADIUS"
log_info ""
log_info "Configuracion:"
log_info "  /etc/securizar/wireless-policy.conf            - Politica wireless"
log_info "  /etc/securizar/ap-whitelist.conf               - Whitelist de APs"
log_info "  /etc/securizar/wifi-enterprise/                - Templates WPA3 Enterprise"
log_info "  /etc/securizar/freeradius/                     - Templates FreeRADIUS"
log_info ""
log_info "Servicios systemd:"
log_info "  securizar-wireless-monitor.service             - Monitoreo continuo"
log_info "  securizar-rogue-ap.timer                       - Escaneo periodico"
log_info ""
log_info "Cron:"
log_info "  /etc/cron.weekly/auditoria-wireless            - Auditoria semanal"

show_changes_summary
