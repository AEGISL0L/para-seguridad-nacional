#!/bin/bash
# ============================================================
# seguridad-fisica.sh - Modulo 58: Seguridad Fisica Avanzada
# ============================================================
# Secciones:
#   S1  - USBGuard: control de dispositivos USB
#   S2  - Proteccion de BIOS/UEFI
#   S3  - Proteccion de GRUB bootloader
#   S4  - Bloqueo de pantalla automatico
#   S5  - Proteccion TPM (Trusted Platform Module)
#   S6  - Proteccion contra Thunderbolt/DMA attacks
#   S7  - Cifrado de disco completo
#   S8  - Control de perifericos
#   S9  - Proteccion contra evil maid attacks
#   S10 - Auditoria integral de seguridad fisica
# ============================================================
# Multi-distro: openSUSE, Debian/Ubuntu, RHEL/Fedora, Arch
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps
init_backup "physical-security"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MODULO 58 - SEGURIDAD FISICA AVANZADA                  ║"
echo "║   USBGuard, BIOS/UEFI, GRUB, TPM, Thunderbolt, Cifrado   ║"
echo "║   Control de perifericos, evil maid, auditoria integral   ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

log_section "MODULO 58: SEGURIDAD FISICA AVANZADA"
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

# ── Variables globales del modulo ─────────────────────────────
SECURIZAR_LOG_DIR="/var/log/securizar"
SECURIZAR_BIN_DIR="/usr/local/bin"
SECURIZAR_UDEV_DIR="/etc/udev/rules.d"
SECURIZAR_MODPROBE_DIR="/etc/modprobe.d"
SECURIZAR_CRON_WEEKLY="/etc/cron.weekly"

mkdir -p "$SECURIZAR_LOG_DIR" 2>/dev/null || true

# ── Helpers del modulo ────────────────────────────────────────

# Detectar entorno de escritorio activo
detect_desktop_environment() {
    local de="unknown"
    if [[ -n "${XDG_CURRENT_DESKTOP:-}" ]]; then
        case "${XDG_CURRENT_DESKTOP,,}" in
            *gnome*)    de="gnome" ;;
            *kde*)      de="kde" ;;
            *xfce*)     de="xfce" ;;
            *cinnamon*) de="cinnamon" ;;
            *mate*)     de="mate" ;;
            *lxqt*)     de="lxqt" ;;
            *lxde*)     de="lxde" ;;
            *)          de="${XDG_CURRENT_DESKTOP,,}" ;;
        esac
    elif [[ -n "${DESKTOP_SESSION:-}" ]]; then
        case "${DESKTOP_SESSION,,}" in
            *gnome*)    de="gnome" ;;
            *kde*|*plasma*) de="kde" ;;
            *xfce*)     de="xfce" ;;
            *)          de="${DESKTOP_SESSION,,}" ;;
        esac
    elif pgrep -x gnome-shell &>/dev/null; then
        de="gnome"
    elif pgrep -x plasmashell &>/dev/null; then
        de="kde"
    elif pgrep -x xfce4-session &>/dev/null; then
        de="xfce"
    fi
    echo "$de"
}

# Verificar si un modulo del kernel esta cargado
is_module_loaded() {
    lsmod | grep -qw "$1" 2>/dev/null
}

# Verificar si un modulo del kernel esta blacklisted
is_module_blacklisted() {
    local mod="$1"
    grep -rqsw "blacklist ${mod}" /etc/modprobe.d/ 2>/dev/null
}

# Obtener el directorio de configuracion de GRUB
get_grub_cfg_path() {
    local grub_cfg=""
    for path in /boot/grub2/grub.cfg /boot/grub/grub.cfg /boot/efi/EFI/*/grub.cfg; do
        if [[ -f "$path" ]]; then
            grub_cfg="$path"
            break
        fi
    done
    echo "$grub_cfg"
}

# Obtener el comando update-grub apropiado
get_update_grub_cmd() {
    if command -v grub2-mkconfig &>/dev/null; then
        echo "grub2-mkconfig"
    elif command -v grub-mkconfig &>/dev/null; then
        echo "grub-mkconfig"
    elif command -v update-grub &>/dev/null; then
        echo "update-grub"
    else
        echo ""
    fi
}

# Detectar si el sistema usa UEFI
is_uefi_system() {
    [[ -d /sys/firmware/efi ]]
}

# Detectar si TPM esta presente
has_tpm() {
    [[ -d /sys/class/tpm/tpm0 ]] || [[ -c /dev/tpm0 ]] || [[ -c /dev/tpmrm0 ]]
}

# Obtener version del TPM
get_tpm_version() {
    local version="unknown"
    if [[ -f /sys/class/tpm/tpm0/tpm_version_major ]]; then
        local major minor
        major=$(cat /sys/class/tpm/tpm0/tpm_version_major 2>/dev/null || echo "")
        minor=$(cat /sys/class/tpm/tpm0/tpm_version_minor 2>/dev/null || echo "0")
        if [[ -n "$major" ]]; then
            version="${major}.${minor}"
        fi
    elif [[ -f /sys/class/tpm/tpm0/device/description ]]; then
        local desc
        desc=$(cat /sys/class/tpm/tpm0/device/description 2>/dev/null || echo "")
        if [[ "$desc" == *"2.0"* ]]; then
            version="2.0"
        elif [[ "$desc" == *"1.2"* ]]; then
            version="1.2"
        fi
    elif command -v tpm2_getcap &>/dev/null; then
        if tpm2_getcap properties-fixed 2>/dev/null | grep -q "TPM2"; then
            version="2.0"
        fi
    elif [[ -f /sys/class/tpm/tpm0/caps ]]; then
        local caps
        caps=$(cat /sys/class/tpm/tpm0/caps 2>/dev/null || echo "")
        if [[ "$caps" == *"1.2"* ]]; then
            version="1.2"
        elif [[ "$caps" == *"2.0"* ]]; then
            version="2.0"
        fi
    fi
    echo "$version"
}

# Verificar si LUKS esta en uso para una particion
is_luks_device() {
    local dev="$1"
    cryptsetup isLuks "$dev" 2>/dev/null
}

# Crear backup seguro de un archivo
safe_backup() {
    local file="$1"
    if [[ -f "$file" ]]; then
        local bak_name
        bak_name=$(basename "$file")
        cp -a "$file" "${BACKUP_DIR}/${bak_name}.bak" 2>/dev/null || true
        log_info "Backup: $file -> ${BACKUP_DIR}/${bak_name}.bak"
    fi
}

# Escribir archivo solo si el contenido cambia
write_if_changed() {
    local target="$1"
    local content="$2"
    local perms="${3:-0644}"
    if [[ -f "$target" ]]; then
        local existing
        existing=$(cat "$target" 2>/dev/null || echo "")
        if [[ "$existing" == "$content" ]]; then
            return 1  # sin cambios
        fi
        safe_backup "$target"
    fi
    echo "$content" > "$target"
    chmod "$perms" "$target"
    return 0
}

# ══════════════════════════════════════════════════════════════
# S1: USBGuard — control de dispositivos USB
# ══════════════════════════════════════════════════════════════
log_section "S1: USBGuard — control de dispositivos USB"

configure_usbguard() {
    log_info "Configurando USBGuard para control de dispositivos USB..."

    # --- 1.1: Instalar usbguard ---
    if ! command -v usbguard &>/dev/null; then
        if ask "Instalar usbguard para control de dispositivos USB?"; then
            log_info "Instalando usbguard..."
            pkg_install usbguard || {
                log_error "No se pudo instalar usbguard"
                log_skip "Instalacion de usbguard fallida"
                return 1
            }
            log_change "Instalado" "usbguard"
        else
            log_skip "Instalacion de usbguard (usuario declino)"
            return 0
        fi
    else
        log_info "usbguard ya esta instalado"
    fi

    # --- 1.2: Generar politica inicial desde dispositivos conectados ---
    local usbguard_rules="/etc/usbguard/rules.conf"
    local usbguard_conf="/etc/usbguard/usbguard-daemon.conf"

    mkdir -p /etc/usbguard 2>/dev/null || true

    if ask "Generar politica USBGuard desde dispositivos actualmente conectados?"; then
        log_info "Generando politica desde dispositivos USB actuales..."

        if [[ -f "$usbguard_rules" ]]; then
            safe_backup "$usbguard_rules"
        fi

        # Generar politica base de dispositivos actualmente conectados
        local generated_rules=""
        if command -v usbguard &>/dev/null; then
            generated_rules=$(usbguard generate-policy 2>/dev/null || echo "")
        fi

        # Crear reglas con enfoque whitelist
        cat > "$usbguard_rules" << 'USBGUARD_RULES_EOF'
# ============================================================
# USBGuard Rules - Generado por securizar (Modulo 58)
# ============================================================
# Politica: whitelist (solo dispositivos autorizados)
# Fecha: GENERATED_DATE
# ============================================================

# --- Regla por defecto: bloquear todos los dispositivos ---
# Esta politica se aplica a cualquier dispositivo no cubierto
# por las reglas de abajo.

# --- Dispositivos HID (teclados y ratones) permitidos ---
# Permitir dispositivos HID genericos (clase 03)
# Teclados USB (subclase 01, protocolo 01)
allow with-interface equals { 03:01:01 }
# Ratones USB (subclase 01, protocolo 02)
allow with-interface equals { 03:01:02 }
# HID generico (subclase 00)
allow with-interface equals { 03:00:00 }

# --- Hubs USB internos permitidos ---
# Permitir hubs USB (clase 09)
allow with-interface equals { 09:00:00 }
allow with-interface equals { 09:00:01 }
allow with-interface equals { 09:00:02 }

# --- Dispositivos de almacenamiento USB ---
# NOTA: Descomente las siguientes lineas si necesita permitir
# almacenamiento USB. Por defecto esta bloqueado por seguridad.
# allow with-interface equals { 08:06:50 }
# allow with-interface equals { 08:06:80 }

# --- Dispositivos de audio USB permitidos ---
# Clase 01: Audio
# allow with-interface equals { 01:01:00 }
# allow with-interface equals { 01:02:00 }

# --- Dispositivos de video USB permitidos ---
# Clase 0E: Video (webcams)
# allow with-interface equals { 0e:01:00 }
# allow with-interface equals { 0e:02:00 }

# --- Dispositivos de red USB permitidos ---
# Clase 02: CDC (adaptadores ethernet/wifi USB)
# allow with-interface one-of { 02:*:* }

# --- Impresoras USB ---
# Clase 07: Printer
# allow with-interface equals { 07:01:01 }
# allow with-interface equals { 07:01:02 }

# --- Dispositivos de smartcard ---
# Clase 0B: Smart Card
# allow with-interface equals { 0b:00:00 }

USBGUARD_RULES_EOF

        # Reemplazar fecha de generacion
        sed -i "s/GENERATED_DATE/$(date '+%Y-%m-%d %H:%M:%S')/" "$usbguard_rules"

        # Agregar reglas generadas automaticamente si existen
        if [[ -n "$generated_rules" ]]; then
            {
                echo ""
                echo "# --- Dispositivos actualmente conectados (auto-generados) ---"
                echo "# Revise estas reglas y elimine las que no sean necesarias"
                echo "$generated_rules"
            } >> "$usbguard_rules"
        fi

        chmod 600 "$usbguard_rules"
        log_change "Creado" "$usbguard_rules con politica whitelist"
    else
        log_skip "Generacion de politica USBGuard"
    fi

    # --- 1.3: Configurar daemon de USBGuard ---
    if [[ -f "$usbguard_conf" ]]; then
        if ask "Configurar daemon de USBGuard con politica restrictiva?"; then
            safe_backup "$usbguard_conf"

            # Asegurar configuracion restrictiva
            # ImplicitPolicyTarget=block -> bloquear dispositivos no cubiertos
            if grep -q "^ImplicitPolicyTarget=" "$usbguard_conf" 2>/dev/null; then
                sed -i 's/^ImplicitPolicyTarget=.*/ImplicitPolicyTarget=block/' "$usbguard_conf"
            else
                echo "ImplicitPolicyTarget=block" >> "$usbguard_conf"
            fi

            # PresentDevicePolicy=apply-policy -> aplicar politica a dispositivos ya conectados
            if grep -q "^PresentDevicePolicy=" "$usbguard_conf" 2>/dev/null; then
                sed -i 's/^PresentDevicePolicy=.*/PresentDevicePolicy=apply-policy/' "$usbguard_conf"
            else
                echo "PresentDevicePolicy=apply-policy" >> "$usbguard_conf"
            fi

            # PresentControllerPolicy=keep -> mantener controladores USB existentes
            if grep -q "^PresentControllerPolicy=" "$usbguard_conf" 2>/dev/null; then
                sed -i 's/^PresentControllerPolicy=.*/PresentControllerPolicy=keep/' "$usbguard_conf"
            else
                echo "PresentControllerPolicy=keep" >> "$usbguard_conf"
            fi

            # InsertedDevicePolicy=apply-policy
            if grep -q "^InsertedDevicePolicy=" "$usbguard_conf" 2>/dev/null; then
                sed -i 's/^InsertedDevicePolicy=.*/InsertedDevicePolicy=apply-policy/' "$usbguard_conf"
            else
                echo "InsertedDevicePolicy=apply-policy" >> "$usbguard_conf"
            fi

            # AuditBackend=LinuxAudit -> registrar eventos en audit
            if grep -q "^AuditBackend=" "$usbguard_conf" 2>/dev/null; then
                sed -i 's/^AuditBackend=.*/AuditBackend=LinuxAudit/' "$usbguard_conf"
            else
                echo "AuditBackend=LinuxAudit" >> "$usbguard_conf"
            fi

            chmod 600 "$usbguard_conf"
            log_change "Configurado" "$usbguard_conf con politica restrictiva"
        else
            log_skip "Configuracion del daemon USBGuard"
        fi
    else
        log_warn "Archivo de configuracion USBGuard no encontrado: $usbguard_conf"
    fi

    # --- 1.4: Habilitar y arrancar servicio ---
    if ask "Habilitar y arrancar servicio usbguard?"; then
        if systemctl is-active usbguard &>/dev/null; then
            log_info "usbguard ya esta activo, reiniciando..."
            systemctl restart usbguard || {
                log_warn "No se pudo reiniciar usbguard"
            }
            log_change "Reiniciado" "servicio usbguard"
        else
            systemctl enable usbguard 2>/dev/null || true
            systemctl start usbguard 2>/dev/null || {
                log_warn "No se pudo arrancar usbguard (revisar configuracion)"
            }
            log_change "Habilitado" "servicio usbguard"
        fi
    else
        log_skip "Habilitacion del servicio usbguard"
    fi

    # --- 1.5: Crear script de gestion de USBGuard ---
    if ask "Crear script de gestion de USBGuard en ${SECURIZAR_BIN_DIR}/?"; then
        local gestionar_usbguard="${SECURIZAR_BIN_DIR}/gestionar-usbguard.sh"

        cat > "$gestionar_usbguard" << 'GESTIONAR_USB_EOF'
#!/bin/bash
# ============================================================
# gestionar-usbguard.sh - Gestion de reglas USBGuard
# ============================================================
# Generado por securizar (Modulo 58 - Seguridad Fisica)
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

RULES_FILE="/etc/usbguard/rules.conf"
LOG_FILE="/var/log/securizar/usbguard-gestion.log"

log_action() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
    echo -e "${GREEN}[+]${NC} $1"
}

log_err() {
    echo -e "${RED}[X]${NC} $1" >&2
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_err "Este script debe ejecutarse como root"
        exit 1
    fi
}

show_menu() {
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Gestion de USBGuard${NC}"
    echo -e "${CYAN}══════════════════════════════════════════${NC}"
    echo ""
    echo "  1) Listar dispositivos USB conectados"
    echo "  2) Listar dispositivos bloqueados"
    echo "  3) Permitir dispositivo temporal"
    echo "  4) Bloquear dispositivo"
    echo "  5) Agregar regla permanente"
    echo "  6) Eliminar regla"
    echo "  7) Ver reglas actuales"
    echo "  8) Recargar reglas"
    echo "  9) Ver estado del servicio"
    echo " 10) Ver log de eventos"
    echo "  0) Salir"
    echo ""
}

list_connected_devices() {
    echo -e "\n${BOLD}Dispositivos USB conectados:${NC}"
    if command -v usbguard &>/dev/null; then
        usbguard list-devices 2>/dev/null || {
            log_err "No se pudo obtener lista de dispositivos"
            echo "Usando lsusb como alternativa:"
            lsusb 2>/dev/null || echo "lsusb no disponible"
        }
    else
        lsusb 2>/dev/null || echo "lsusb no disponible"
    fi
}

list_blocked_devices() {
    echo -e "\n${BOLD}Dispositivos USB bloqueados:${NC}"
    if command -v usbguard &>/dev/null; then
        usbguard list-devices -b 2>/dev/null || {
            log_err "No se pudo obtener lista de dispositivos bloqueados"
        }
    else
        log_err "usbguard no instalado"
    fi
}

allow_device_temp() {
    local device_id
    echo -e "\n${BOLD}Dispositivos disponibles:${NC}"
    usbguard list-devices 2>/dev/null || true
    echo ""
    read -p "ID del dispositivo a permitir temporalmente: " device_id
    if [[ -n "$device_id" ]]; then
        usbguard allow-device "$device_id" 2>/dev/null && {
            log_action "Dispositivo $device_id permitido temporalmente"
        } || {
            log_err "No se pudo permitir dispositivo $device_id"
        }
    fi
}

block_device() {
    local device_id
    echo -e "\n${BOLD}Dispositivos permitidos:${NC}"
    usbguard list-devices -a 2>/dev/null || true
    echo ""
    read -p "ID del dispositivo a bloquear: " device_id
    if [[ -n "$device_id" ]]; then
        usbguard block-device "$device_id" 2>/dev/null && {
            log_action "Dispositivo $device_id bloqueado"
        } || {
            log_err "No se pudo bloquear dispositivo $device_id"
        }
    fi
}

add_permanent_rule() {
    echo -e "\n${BOLD}Agregar regla permanente:${NC}"
    echo ""
    echo "Opciones de regla:"
    echo "  1) Permitir por vendor:product ID"
    echo "  2) Permitir por interfaz de clase"
    echo "  3) Agregar regla personalizada"
    echo ""
    read -p "Opcion: " opt
    case "$opt" in
        1)
            local vid pid
            read -p "Vendor ID (ej: 046d): " vid
            read -p "Product ID (ej: c52b): " pid
            if [[ -n "$vid" && -n "$pid" ]]; then
                local rule="allow id ${vid}:${pid}"
                echo "$rule" >> "$RULES_FILE"
                log_action "Regla permanente agregada: $rule"
                echo -e "${GREEN}Regla agregada.${NC} Recargue las reglas para aplicar."
            fi
            ;;
        2)
            echo "Clases comunes:"
            echo "  03:01:01 - Teclado"
            echo "  03:01:02 - Raton"
            echo "  08:06:50 - Almacenamiento USB (SCSI)"
            echo "  09:00:00 - Hub USB"
            echo "  0e:01:00 - Video (webcam)"
            echo ""
            local iface
            read -p "Interfaz (ej: 03:01:01): " iface
            if [[ -n "$iface" ]]; then
                local rule="allow with-interface equals { ${iface} }"
                echo "$rule" >> "$RULES_FILE"
                log_action "Regla de interfaz agregada: $rule"
                echo -e "${GREEN}Regla agregada.${NC} Recargue las reglas para aplicar."
            fi
            ;;
        3)
            echo "Escriba la regla completa (formato USBGuard):"
            local custom_rule
            read -p "Regla: " custom_rule
            if [[ -n "$custom_rule" ]]; then
                echo "$custom_rule" >> "$RULES_FILE"
                log_action "Regla personalizada agregada: $custom_rule"
                echo -e "${GREEN}Regla agregada.${NC} Recargue las reglas para aplicar."
            fi
            ;;
        *)
            echo "Opcion invalida"
            ;;
    esac
}

remove_rule() {
    echo -e "\n${BOLD}Reglas actuales:${NC}"
    local i=1
    while IFS= read -r line; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        echo "  $i) $line"
        ((i++))
    done < "$RULES_FILE"
    echo ""
    read -p "Numero de regla a eliminar (0=cancelar): " num
    if [[ "$num" -gt 0 ]] 2>/dev/null; then
        local j=0
        local tmp_file
        tmp_file=$(mktemp)
        while IFS= read -r line; do
            if [[ -z "$line" || "$line" == \#* ]]; then
                echo "$line" >> "$tmp_file"
            else
                ((j++))
                if [[ "$j" -ne "$num" ]]; then
                    echo "$line" >> "$tmp_file"
                else
                    log_action "Regla eliminada: $line"
                fi
            fi
        done < "$RULES_FILE"
        mv "$tmp_file" "$RULES_FILE"
        chmod 600 "$RULES_FILE"
        echo -e "${GREEN}Regla eliminada.${NC} Recargue las reglas para aplicar."
    fi
}

show_rules() {
    echo -e "\n${BOLD}Reglas actuales ($RULES_FILE):${NC}"
    if [[ -f "$RULES_FILE" ]]; then
        cat -n "$RULES_FILE"
    else
        echo "Archivo de reglas no encontrado"
    fi
}

reload_rules() {
    echo "Recargando reglas de USBGuard..."
    systemctl restart usbguard 2>/dev/null && {
        log_action "Reglas USBGuard recargadas"
        echo -e "${GREEN}Reglas recargadas correctamente${NC}"
    } || {
        log_err "No se pudieron recargar las reglas"
    }
}

show_service_status() {
    echo -e "\n${BOLD}Estado del servicio USBGuard:${NC}"
    systemctl status usbguard --no-pager 2>/dev/null || {
        echo "Servicio no encontrado o no disponible"
    }
}

show_event_log() {
    echo -e "\n${BOLD}Ultimos 50 eventos USBGuard:${NC}"
    journalctl -u usbguard --no-pager -n 50 2>/dev/null || {
        echo "No se pudo acceder al journal de usbguard"
    }
}

# --- Principal ---
check_root
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true

if [[ "${1:-}" == "--status" ]]; then
    show_service_status
    exit 0
elif [[ "${1:-}" == "--list" ]]; then
    list_connected_devices
    exit 0
elif [[ "${1:-}" == "--blocked" ]]; then
    list_blocked_devices
    exit 0
fi

while true; do
    show_menu
    read -p "Seleccione opcion: " choice
    case "$choice" in
        1) list_connected_devices ;;
        2) list_blocked_devices ;;
        3) allow_device_temp ;;
        4) block_device ;;
        5) add_permanent_rule ;;
        6) remove_rule ;;
        7) show_rules ;;
        8) reload_rules ;;
        9) show_service_status ;;
       10) show_event_log ;;
        0) echo "Saliendo..."; exit 0 ;;
        *) echo "Opcion invalida" ;;
    esac
done
GESTIONAR_USB_EOF

        chmod 755 "$gestionar_usbguard"
        log_change "Creado" "$gestionar_usbguard (gestion de USBGuard)"
    else
        log_skip "Creacion de script de gestion de USBGuard"
    fi

    log_info "Configuracion de USBGuard completada"
}

configure_usbguard

# ══════════════════════════════════════════════════════════════
# S2: Proteccion de BIOS/UEFI
# ══════════════════════════════════════════════════════════════
log_section "S2: Proteccion de BIOS/UEFI"

check_bios_uefi_protection() {
    log_info "Verificando proteccion de BIOS/UEFI..."

    local bios_issues=0
    local bios_checks=0

    # --- 2.1: Verificar modo de arranque (UEFI vs Legacy) ---
    if is_uefi_system; then
        log_info "Sistema arrancado en modo UEFI"
        ((bios_checks++))

        # --- 2.2: Verificar Secure Boot ---
        if command -v mokutil &>/dev/null; then
            local sb_state
            sb_state=$(mokutil --sb-state 2>/dev/null || echo "unknown")
            if echo "$sb_state" | grep -qi "enabled"; then
                log_info "Secure Boot: HABILITADO"
                ((bios_checks++))
            elif echo "$sb_state" | grep -qi "disabled"; then
                log_warn "Secure Boot: DESHABILITADO"
                log_warn "  Se recomienda habilitar Secure Boot en la configuracion UEFI"
                ((bios_issues++))
            else
                log_warn "Secure Boot: estado desconocido ($sb_state)"
            fi
        else
            log_warn "mokutil no disponible - no se puede verificar Secure Boot"
            if ask "Instalar mokutil para verificar Secure Boot?"; then
                # mokutil suele estar en paquete mokutil o shim-utils
                case "$DISTRO_FAMILY" in
                    suse)   zypper --non-interactive install mokutil 2>/dev/null || true ;;
                    debian) apt-get install -y mokutil 2>/dev/null || true ;;
                    rhel)   dnf install -y mokutil 2>/dev/null || true ;;
                    arch)   log_info "mokutil no disponible en repos de Arch por defecto" ;;
                esac
                if command -v mokutil &>/dev/null; then
                    local sb_state
                    sb_state=$(mokutil --sb-state 2>/dev/null || echo "unknown")
                    log_info "Secure Boot: $sb_state"
                    log_change "Instalado" "mokutil"
                fi
            else
                log_skip "Instalacion de mokutil"
            fi
        fi

        # --- 2.3: Verificar claves Secure Boot enrolladas ---
        if command -v mokutil &>/dev/null; then
            local key_count
            key_count=$(mokutil --list-enrolled 2>/dev/null | grep -c "Subject:" || echo "0")
            log_info "Claves MOK enrolladas: $key_count"
        fi
    else
        log_info "Sistema arrancado en modo Legacy BIOS"
        log_warn "  Considere migrar a UEFI con Secure Boot para mayor seguridad"
        ((bios_issues++))
    fi

    # --- 2.4: Verificar password de BIOS (via dmidecode) ---
    if command -v dmidecode &>/dev/null; then
        log_info "Verificando configuracion de BIOS via dmidecode..."

        local bios_vendor bios_version bios_date
        bios_vendor=$(dmidecode -s bios-vendor 2>/dev/null || echo "desconocido")
        bios_version=$(dmidecode -s bios-version 2>/dev/null || echo "desconocida")
        bios_date=$(dmidecode -s bios-release-date 2>/dev/null || echo "desconocida")

        log_info "BIOS Vendor: $bios_vendor"
        log_info "BIOS Version: $bios_version"
        log_info "BIOS Fecha: $bios_date"

        # Verificar password status
        local passwd_status
        passwd_status=$(dmidecode -t 1 2>/dev/null | grep -i "password" || echo "")
        if [[ -n "$passwd_status" ]]; then
            log_info "Estado password BIOS: $passwd_status"
        fi

        # Verificar Security Status en BIOS
        local security_status
        security_status=$(dmidecode -t 24 2>/dev/null || echo "")
        if [[ -n "$security_status" ]]; then
            if echo "$security_status" | grep -qi "none\|unknown"; then
                log_warn "BIOS Security Status: Sin proteccion de hardware"
                log_warn "  Configure password de BIOS/UEFI manualmente"
                ((bios_issues++))
            else
                log_info "BIOS Security Status detectado"
                ((bios_checks++))
            fi
        fi

        # Verificar chassis intrusion (si disponible)
        local chassis_info
        chassis_info=$(dmidecode -t 3 2>/dev/null || echo "")
        if echo "$chassis_info" | grep -qi "intrusion\|security"; then
            log_info "Deteccion de intrusion de chasis disponible"
            ((bios_checks++))
        fi
    else
        log_warn "dmidecode no disponible"
        if ask "Instalar dmidecode para verificar BIOS?"; then
            pkg_install dmidecode || true
            log_change "Instalado" "dmidecode"
        else
            log_skip "Instalacion de dmidecode"
        fi
    fi

    # --- 2.5: Verificar proteccion de orden de arranque ---
    log_info "Verificando proteccion de orden de arranque..."
    if is_uefi_system && command -v efibootmgr &>/dev/null; then
        local boot_entries
        boot_entries=$(efibootmgr -v 2>/dev/null || echo "")
        if [[ -n "$boot_entries" ]]; then
            local entry_count
            entry_count=$(echo "$boot_entries" | grep -c "^Boot[0-9]" || echo "0")
            log_info "Entradas de arranque UEFI: $entry_count"
            echo "$boot_entries" | grep "^Boot[0-9]" | head -10 | while IFS= read -r line; do
                log_info "  $line"
            done
            ((bios_checks++))
        fi
    elif ! is_uefi_system; then
        log_warn "En modo Legacy BIOS, la proteccion de orden de arranque depende del password de BIOS"
    fi

    # --- 2.6: Verificar estado del TPM ---
    if has_tpm; then
        local tpm_ver
        tpm_ver=$(get_tpm_version)
        log_info "TPM detectado: version $tpm_ver"
        ((bios_checks++))

        # Verificar si TPM esta habilitado
        if [[ -c /dev/tpm0 ]] || [[ -c /dev/tpmrm0 ]]; then
            log_info "TPM accesible via /dev/tpm*"
        fi
    else
        log_warn "TPM no detectado"
        log_warn "  Se recomienda habilitar TPM en la configuracion BIOS/UEFI"
        ((bios_issues++))
    fi

    # --- 2.7: Verificar herramientas de actualizacion de BIOS ---
    log_info "Verificando herramientas de actualizacion de firmware..."
    if command -v fwupdmgr &>/dev/null; then
        log_info "fwupd disponible para actualizacion de firmware"
        local fw_updates
        fw_updates=$(fwupdmgr get-updates 2>/dev/null || echo "No hay actualizaciones disponibles")
        if echo "$fw_updates" | grep -qi "update\|disponible"; then
            log_warn "Hay actualizaciones de firmware disponibles:"
            echo "$fw_updates" | head -20
        else
            log_info "Firmware actualizado (sin actualizaciones pendientes)"
            ((bios_checks++))
        fi

        # Verificar dispositivos con firmware gestionable
        local fw_devices
        fw_devices=$(fwupdmgr get-devices 2>/dev/null | grep -c "Device ID" || echo "0")
        log_info "Dispositivos con firmware gestionable: $fw_devices"
    else
        log_info "fwupd no disponible"
        if ask "Instalar fwupd para gestion de firmware?"; then
            pkg_install fwupd || true
            if command -v fwupdmgr &>/dev/null; then
                log_change "Instalado" "fwupd"
            fi
        else
            log_skip "Instalacion de fwupd"
        fi
    fi

    # --- 2.8: Crear script de verificacion BIOS/UEFI ---
    if ask "Crear script de verificacion BIOS/UEFI en ${SECURIZAR_BIN_DIR}/?"; then
        local verificar_bios="${SECURIZAR_BIN_DIR}/verificar-bios-uefi.sh"

        cat > "$verificar_bios" << 'VERIFICAR_BIOS_EOF'
#!/bin/bash
# ============================================================
# verificar-bios-uefi.sh - Verificacion de seguridad BIOS/UEFI
# ============================================================
# Generado por securizar (Modulo 58 - Seguridad Fisica)
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

LOG_DIR="/var/log/securizar"
REPORT_FILE="${LOG_DIR}/bios-uefi-check-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$LOG_DIR" 2>/dev/null || true

passed=0
warned=0
failed=0

check_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    echo "[PASS] $1" >> "$REPORT_FILE"
    ((passed++))
}

check_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    echo "[WARN] $1" >> "$REPORT_FILE"
    ((warned++))
}

check_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    echo "[FAIL] $1" >> "$REPORT_FILE"
    ((failed++))
}

echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "${CYAN}  Verificacion de Seguridad BIOS/UEFI${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo ""
echo "Fecha: $(date '+%Y-%m-%d %H:%M:%S')" | tee "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

# 1. Modo de arranque
if [[ -d /sys/firmware/efi ]]; then
    check_pass "Sistema en modo UEFI"
else
    check_warn "Sistema en modo Legacy BIOS (se recomienda UEFI)"
fi

# 2. Secure Boot
if command -v mokutil &>/dev/null; then
    sb_state=$(mokutil --sb-state 2>/dev/null || echo "unknown")
    if echo "$sb_state" | grep -qi "enabled"; then
        check_pass "Secure Boot habilitado"
    else
        check_fail "Secure Boot no habilitado: $sb_state"
    fi
else
    check_warn "mokutil no disponible para verificar Secure Boot"
fi

# 3. TPM
if [[ -d /sys/class/tpm/tpm0 ]]; then
    tpm_ver="unknown"
    if [[ -f /sys/class/tpm/tpm0/tpm_version_major ]]; then
        tpm_ver=$(cat /sys/class/tpm/tpm0/tpm_version_major 2>/dev/null || echo "?")
    fi
    check_pass "TPM detectado (version: $tpm_ver)"
else
    check_fail "TPM no detectado"
fi

# 4. BIOS password (via dmidecode)
if command -v dmidecode &>/dev/null; then
    bios_vendor=$(dmidecode -s bios-vendor 2>/dev/null || echo "desconocido")
    bios_version=$(dmidecode -s bios-version 2>/dev/null || echo "desconocida")
    echo "BIOS: $bios_vendor v$bios_version" | tee -a "$REPORT_FILE"

    hw_sec=$(dmidecode -t 24 2>/dev/null | grep -i "status" || echo "")
    if [[ -n "$hw_sec" ]]; then
        if echo "$hw_sec" | grep -qi "enabled\|activated"; then
            check_pass "Hardware Security Status: activo"
        else
            check_warn "Hardware Security Status: $hw_sec"
        fi
    else
        check_warn "No se pudo determinar Hardware Security Status"
    fi
else
    check_warn "dmidecode no disponible"
fi

# 5. Boot order
if command -v efibootmgr &>/dev/null; then
    boot_order=$(efibootmgr 2>/dev/null | grep "BootOrder" || echo "")
    if [[ -n "$boot_order" ]]; then
        check_pass "Orden de arranque UEFI accesible: $boot_order"
    fi

    # Verificar si hay entradas de arranque externo (USB, PXE)
    usb_boot=$(efibootmgr -v 2>/dev/null | grep -i "usb\|removable" || echo "")
    pxe_boot=$(efibootmgr -v 2>/dev/null | grep -i "pxe\|network\|ipv4\|ipv6" || echo "")
    if [[ -n "$usb_boot" ]]; then
        check_warn "Arranque USB detectado en entradas UEFI (riesgo de arranque no autorizado)"
    fi
    if [[ -n "$pxe_boot" ]]; then
        check_warn "Arranque PXE/Red detectado en entradas UEFI"
    fi
fi

# 6. Firmware updates
if command -v fwupdmgr &>/dev/null; then
    fw_updates=$(fwupdmgr get-updates 2>/dev/null || echo "")
    if echo "$fw_updates" | grep -qi "no updates"; then
        check_pass "Firmware actualizado"
    elif [[ -n "$fw_updates" ]]; then
        check_warn "Actualizaciones de firmware disponibles"
    fi
else
    check_warn "fwupd no disponible para verificar actualizaciones de firmware"
fi

# 7. IOMMU
iommu_enabled=0
if grep -qi "intel_iommu=on" /proc/cmdline 2>/dev/null; then
    check_pass "Intel IOMMU habilitado"
    iommu_enabled=1
fi
if grep -qi "amd_iommu=on" /proc/cmdline 2>/dev/null; then
    check_pass "AMD IOMMU habilitado"
    iommu_enabled=1
fi
if [[ $iommu_enabled -eq 0 ]]; then
    dmesg_iommu=$(dmesg 2>/dev/null | grep -i "iommu" | head -3 || echo "")
    if [[ -n "$dmesg_iommu" ]]; then
        check_warn "IOMMU detectado en dmesg pero no habilitado explicitamente en cmdline"
    else
        check_fail "IOMMU no detectado"
    fi
fi

# Resumen
echo ""
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "  ${GREEN}Pasados: $passed${NC} | ${YELLOW}Advertencias: $warned${NC} | ${RED}Fallidos: $failed${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo ""
echo "Reporte guardado en: $REPORT_FILE"

total=$((passed + warned + failed))
if [[ $total -gt 0 ]]; then
    score=$(( (passed * 100) / total ))
    echo "Puntuacion: ${score}%"
    echo "" >> "$REPORT_FILE"
    echo "Puntuacion: ${score}% (${passed}/${total})" >> "$REPORT_FILE"
fi
VERIFICAR_BIOS_EOF

        chmod 755 "$verificar_bios"
        log_change "Creado" "$verificar_bios"
    else
        log_skip "Creacion de script de verificacion BIOS/UEFI"
    fi

    # Resumen de la seccion
    log_info "Verificacion BIOS/UEFI: $bios_checks checks OK, $bios_issues problemas detectados"
}

check_bios_uefi_protection

# ══════════════════════════════════════════════════════════════
# S3: Proteccion de GRUB bootloader
# ══════════════════════════════════════════════════════════════
log_section "S3: Proteccion de GRUB bootloader"

harden_grub_bootloader() {
    log_info "Configurando proteccion del bootloader GRUB..."

    local grub_cfg
    grub_cfg=$(get_grub_cfg_path)
    local grub_default="/etc/default/grub"
    local grub_password_set=0

    # --- 3.1: Verificar si GRUB tiene password ---
    log_info "Verificando password de GRUB..."

    local grub_cfg_dir=""
    for d in /etc/grub.d /etc/grub2.d; do
        if [[ -d "$d" ]]; then
            grub_cfg_dir="$d"
            break
        fi
    done

    # Buscar password existente
    local has_grub_password=0
    if [[ -n "$grub_cfg_dir" ]]; then
        if grep -rqs "password_pbkdf2\|set superusers" "$grub_cfg_dir"/ 2>/dev/null; then
            has_grub_password=1
        fi
    fi
    if [[ -f "/boot/grub2/user.cfg" ]] && grep -qs "GRUB2_PASSWORD=" /boot/grub2/user.cfg 2>/dev/null; then
        has_grub_password=1
    fi
    if [[ -f "/boot/grub/user.cfg" ]] && grep -qs "GRUB2_PASSWORD=" /boot/grub/user.cfg 2>/dev/null; then
        has_grub_password=1
    fi

    if [[ $has_grub_password -eq 1 ]]; then
        log_info "GRUB password ya esta configurado"
        grub_password_set=1
    else
        log_warn "GRUB no tiene password configurado"

        if ask "Configurar password de GRUB para proteger la edicion de parametros de arranque?"; then
            # Intentar usar grub2-setpassword (RHEL/SUSE)
            if command -v grub2-setpassword &>/dev/null; then
                log_info "Usando grub2-setpassword..."
                echo "Establezca el password de GRUB:"
                grub2-setpassword || {
                    log_warn "grub2-setpassword fallo"
                }
                if [[ -f "/boot/grub2/user.cfg" ]]; then
                    grub_password_set=1
                    log_change "Configurado" "password de GRUB via grub2-setpassword"
                fi
            elif command -v grub-mkpasswd-pbkdf2 &>/dev/null; then
                log_info "Usando grub-mkpasswd-pbkdf2..."
                echo "Introduzca un password para GRUB (se le pedira 2 veces):"
                local grub_hash
                grub_hash=$(grub-mkpasswd-pbkdf2 2>/dev/null | grep "grub.pbkdf2" | awk '{print $NF}')

                if [[ -n "$grub_hash" && -n "$grub_cfg_dir" ]]; then
                    local grub_password_file="${grub_cfg_dir}/40_custom_password"
                    cat > "$grub_password_file" << GRUB_PASS_EOF
#!/bin/sh
# Proteccion de password GRUB - Generado por securizar (Modulo 58)
exec tail -n +4 \$0
set superusers="admin"
password_pbkdf2 admin ${grub_hash}
GRUB_PASS_EOF
                    chmod 755 "$grub_password_file"
                    grub_password_set=1
                    log_change "Creado" "$grub_password_file con password PBKDF2"
                else
                    log_warn "No se pudo generar hash de password GRUB"
                fi
            else
                log_warn "No se encontro herramienta de password GRUB"
                log_warn "  Instale grub2-tools o grub-common segun su distribucion"
            fi
        else
            log_skip "Configuracion de password GRUB"
        fi
    fi

    # --- 3.2: Restringir edicion de parametros de arranque ---
    if [[ -f "$grub_default" ]]; then
        if ask "Restringir edicion de parametros de arranque en GRUB?"; then
            safe_backup "$grub_default"

            # Agregar GRUB_DISABLE_RECOVERY si no existe
            if ! grep -qs "^GRUB_DISABLE_RECOVERY=" "$grub_default" 2>/dev/null; then
                echo 'GRUB_DISABLE_RECOVERY="true"' >> "$grub_default"
                log_change "Agregado" "GRUB_DISABLE_RECOVERY=true en $grub_default"
            else
                sed -i 's/^GRUB_DISABLE_RECOVERY=.*/GRUB_DISABLE_RECOVERY="true"/' "$grub_default"
                log_change "Actualizado" "GRUB_DISABLE_RECOVERY=true"
            fi

            # Reducir timeout para minimizar ventana de ataque
            if grep -qs "^GRUB_TIMEOUT=" "$grub_default" 2>/dev/null; then
                local current_timeout
                current_timeout=$(grep "^GRUB_TIMEOUT=" "$grub_default" | head -1 | cut -d= -f2 | tr -d '"')
                if [[ "${current_timeout:-10}" -gt 5 ]]; then
                    sed -i 's/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT=5/' "$grub_default"
                    log_change "Reducido" "GRUB_TIMEOUT a 5 segundos (era $current_timeout)"
                fi
            fi

            # Deshabilitar submenu para evitar entradas ocultas
            if ! grep -qs "^GRUB_DISABLE_SUBMENU=" "$grub_default" 2>/dev/null; then
                echo 'GRUB_DISABLE_SUBMENU="y"' >> "$grub_default"
                log_change "Agregado" "GRUB_DISABLE_SUBMENU=y"
            fi
        else
            log_skip "Restriccion de edicion de parametros GRUB"
        fi
    else
        log_warn "Archivo $grub_default no encontrado"
    fi

    # --- 3.3: Verificar permisos de configuracion GRUB ---
    log_info "Verificando permisos de archivos GRUB..."

    if [[ -n "$grub_cfg" && -f "$grub_cfg" ]]; then
        local grub_perms
        grub_perms=$(stat -c '%a' "$grub_cfg" 2>/dev/null || echo "")
        if [[ "$grub_perms" != "600" ]]; then
            if ask "Permisos de $grub_cfg son $grub_perms (deberian ser 600). Corregir?"; then
                chmod 600 "$grub_cfg"
                log_change "Permisos" "$grub_cfg cambiado a 600 (era $grub_perms)"
            else
                log_skip "Correccion de permisos de $grub_cfg"
            fi
        else
            log_info "Permisos de $grub_cfg correctos (600)"
        fi
    fi

    # Verificar permisos de grub.d
    if [[ -n "$grub_cfg_dir" && -d "$grub_cfg_dir" ]]; then
        local cfg_dir_perms
        cfg_dir_perms=$(stat -c '%a' "$grub_cfg_dir" 2>/dev/null || echo "")
        if [[ "$cfg_dir_perms" != "700" ]]; then
            if ask "Permisos de $grub_cfg_dir son $cfg_dir_perms (recomendado 700). Corregir?"; then
                chmod 700 "$grub_cfg_dir"
                log_change "Permisos" "$grub_cfg_dir cambiado a 700 (era $cfg_dir_perms)"
            else
                log_skip "Correccion de permisos de $grub_cfg_dir"
            fi
        fi
    fi

    # --- 3.4: Verificar entradas de verificacion de OS ---
    log_info "Verificando integridad de la configuracion GRUB..."

    if [[ -n "$grub_cfg" && -f "$grub_cfg" ]]; then
        # Contar entradas de menu
        local menu_entries
        menu_entries=$(grep -c "^menuentry\|^submenu" "$grub_cfg" 2>/dev/null || echo "0")
        log_info "Entradas de menu en GRUB: $menu_entries"

        # Verificar que no haya entradas sospechosas
        local suspicious_entries
        suspicious_entries=$(grep -i "single\|init=/bin/bash\|init=/bin/sh\|emergency" "$grub_cfg" 2>/dev/null | grep -v "^#" | head -5 || echo "")
        if [[ -n "$suspicious_entries" ]]; then
            log_warn "Entradas que podrian permitir acceso de emergencia sin password:"
            echo "$suspicious_entries" | while IFS= read -r line; do
                log_warn "  $line"
            done
        fi
    fi

    # --- 3.5: Backup de la configuracion GRUB ---
    if ask "Crear backup de la configuracion GRUB actual?"; then
        mkdir -p "${BACKUP_DIR}/grub" 2>/dev/null || true

        if [[ -n "$grub_cfg" && -f "$grub_cfg" ]]; then
            cp -a "$grub_cfg" "${BACKUP_DIR}/grub/" 2>/dev/null || true
            log_change "Backup" "grub.cfg -> ${BACKUP_DIR}/grub/"
        fi
        if [[ -f "$grub_default" ]]; then
            cp -a "$grub_default" "${BACKUP_DIR}/grub/" 2>/dev/null || true
            log_change "Backup" "default/grub -> ${BACKUP_DIR}/grub/"
        fi
        if [[ -n "$grub_cfg_dir" && -d "$grub_cfg_dir" ]]; then
            cp -a "$grub_cfg_dir" "${BACKUP_DIR}/grub/grub.d" 2>/dev/null || true
            log_change "Backup" "grub.d/ -> ${BACKUP_DIR}/grub/grub.d/"
        fi
    else
        log_skip "Backup de configuracion GRUB"
    fi

    # --- 3.6: Hardening de /etc/default/grub y update-grub ---
    if [[ -f "$grub_default" ]]; then
        if ask "Aplicar hardening adicional a /etc/default/grub (parametros de seguridad del kernel)?"; then
            safe_backup "$grub_default"

            # Leer GRUB_CMDLINE_LINUX_DEFAULT actual
            local current_cmdline
            current_cmdline=$(grep "^GRUB_CMDLINE_LINUX_DEFAULT=" "$grub_default" 2>/dev/null | head -1 | sed 's/^GRUB_CMDLINE_LINUX_DEFAULT=//' | tr -d '"' || echo "")

            # Parametros de seguridad a agregar si no estan presentes
            local security_params=(
                "slab_nomerge"
                "init_on_alloc=1"
                "init_on_free=1"
                "page_alloc.shuffle=1"
                "pti=on"
                "vsyscall=none"
                "debugfs=off"
                "oops=panic"
                "module.sig_enforce=1"
                "lockdown=confidentiality"
                "random.trust_cpu=off"
                "random.trust_bootloader=off"
            )

            local new_cmdline="$current_cmdline"
            local params_added=0

            for param in "${security_params[@]}"; do
                local param_name
                param_name=$(echo "$param" | cut -d= -f1)
                if ! echo "$new_cmdline" | grep -qw "$param_name"; then
                    new_cmdline="$new_cmdline $param"
                    ((params_added++))
                fi
            done

            # Limpiar espacios multiples
            new_cmdline=$(echo "$new_cmdline" | sed 's/  */ /g' | sed 's/^ //')

            if [[ $params_added -gt 0 ]]; then
                if grep -qs "^GRUB_CMDLINE_LINUX_DEFAULT=" "$grub_default"; then
                    sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"${new_cmdline}\"|" "$grub_default"
                else
                    echo "GRUB_CMDLINE_LINUX_DEFAULT=\"${new_cmdline}\"" >> "$grub_default"
                fi
                log_change "Agregados" "$params_added parametros de seguridad kernel en GRUB"
            else
                log_info "Todos los parametros de seguridad ya estan presentes en GRUB"
            fi

            # Ejecutar update-grub
            local update_cmd
            update_cmd=$(get_update_grub_cmd)
            if [[ -n "$update_cmd" ]]; then
                if ask "Ejecutar $update_cmd para aplicar cambios?"; then
                    local grub_output_path=""
                    if [[ "$update_cmd" == "update-grub" ]]; then
                        $update_cmd 2>&1 || {
                            log_warn "update-grub retorno error (puede ser normal)"
                        }
                    else
                        # grub2-mkconfig o grub-mkconfig
                        if [[ -n "$grub_cfg" ]]; then
                            grub_output_path="$grub_cfg"
                        elif [[ -d /boot/grub2 ]]; then
                            grub_output_path="/boot/grub2/grub.cfg"
                        else
                            grub_output_path="/boot/grub/grub.cfg"
                        fi
                        $update_cmd -o "$grub_output_path" 2>&1 || {
                            log_warn "$update_cmd retorno error"
                        }
                    fi
                    log_change "Ejecutado" "$update_cmd"
                else
                    log_skip "Ejecucion de $update_cmd"
                    log_warn "Ejecute '$update_cmd' manualmente para aplicar los cambios"
                fi
            else
                log_warn "No se encontro herramienta update-grub"
            fi
        else
            log_skip "Hardening adicional de /etc/default/grub"
        fi
    fi

    log_info "Proteccion de GRUB completada"
}

harden_grub_bootloader

# ══════════════════════════════════════════════════════════════
# S4: Bloqueo de pantalla automatico
# ══════════════════════════════════════════════════════════════
log_section "S4: Bloqueo de pantalla automatico"

configure_screen_lock() {
    log_info "Configurando bloqueo de pantalla automatico..."

    local desktop_env
    desktop_env=$(detect_desktop_environment)
    log_info "Entorno de escritorio detectado: $desktop_env"

    local lock_timeout=300  # 5 minutos en segundos

    # --- 4.1: Configurar bloqueo segun entorno de escritorio ---

    # --- GNOME ---
    configure_gnome_lock() {
        log_info "Configurando bloqueo de pantalla para GNOME..."

        if ! command -v gsettings &>/dev/null; then
            log_warn "gsettings no disponible (GNOME no completamente instalado)"
            return 1
        fi

        if ask "Configurar bloqueo automatico de pantalla GNOME (${lock_timeout}s)?"; then
            # Crear script que configure gsettings para cada usuario
            local gnome_lock_script="${SECURIZAR_BIN_DIR}/configurar-gnome-lock.sh"

            cat > "$gnome_lock_script" << GNOME_LOCK_EOF
#!/bin/bash
# Configurar bloqueo de pantalla GNOME
# Generado por securizar (Modulo 58)
set -euo pipefail

LOCK_TIMEOUT=${lock_timeout}
LOCK_DELAY=0

# Configurar para el usuario actual
configure_for_user() {
    local user="\$1"
    local uid
    uid=\$(id -u "\$user" 2>/dev/null || echo "")
    [[ -z "\$uid" || "\$uid" -lt 1000 ]] && return 0

    local dbus_addr=""
    # Intentar encontrar el bus de sesion del usuario
    if [[ -f "/run/user/\${uid}/bus" ]]; then
        dbus_addr="unix:path=/run/user/\${uid}/bus"
    fi

    if [[ -n "\$dbus_addr" ]]; then
        sudo -u "\$user" DBUS_SESSION_BUS_ADDRESS="\$dbus_addr" \
            gsettings set org.gnome.desktop.session idle-delay "\$LOCK_TIMEOUT" 2>/dev/null || true
        sudo -u "\$user" DBUS_SESSION_BUS_ADDRESS="\$dbus_addr" \
            gsettings set org.gnome.desktop.screensaver lock-enabled true 2>/dev/null || true
        sudo -u "\$user" DBUS_SESSION_BUS_ADDRESS="\$dbus_addr" \
            gsettings set org.gnome.desktop.screensaver lock-delay "\$LOCK_DELAY" 2>/dev/null || true
        sudo -u "\$user" DBUS_SESSION_BUS_ADDRESS="\$dbus_addr" \
            gsettings set org.gnome.desktop.screensaver idle-activation-enabled true 2>/dev/null || true
        echo "[+] Configurado bloqueo GNOME para usuario: \$user"
    else
        echo "[!] No se encontro bus de sesion para \$user"
    fi
}

# Aplicar a todos los usuarios con sesion grafica
if [[ "\${1:-}" == "--all" ]]; then
    while IFS=: read -r username _ uid _ _ home _; do
        [[ "\$uid" -lt 1000 ]] && continue
        [[ ! -d "\$home" ]] && continue
        configure_for_user "\$username"
    done < /etc/passwd
else
    # Aplicar solo al usuario actual
    if [[ -n "\${SUDO_USER:-}" ]]; then
        configure_for_user "\$SUDO_USER"
    elif [[ -n "\${USER:-}" ]]; then
        configure_for_user "\$USER"
    fi
fi

# Configuracion global via dconf (afecta a todos los usuarios nuevos)
DCONF_PROFILE_DIR="/etc/dconf/profile"
DCONF_DB_DIR="/etc/dconf/db/local.d"
DCONF_LOCKS_DIR="/etc/dconf/db/local.d/locks"

mkdir -p "\$DCONF_PROFILE_DIR" "\$DCONF_DB_DIR" "\$DCONF_LOCKS_DIR" 2>/dev/null || true

# Crear perfil dconf
cat > "\$DCONF_PROFILE_DIR/user" << 'DCONF_PROFILE'
user-db:user
system-db:local
DCONF_PROFILE

# Crear configuracion de bloqueo
cat > "\$DCONF_DB_DIR/00-screensaver" << DCONF_SCREEN
[org/gnome/desktop/session]
idle-delay=uint32 \$LOCK_TIMEOUT

[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 \$LOCK_DELAY
idle-activation-enabled=true
DCONF_SCREEN

# Bloquear configuracion (evita que usuarios cambien estos valores)
cat > "\$DCONF_LOCKS_DIR/screensaver" << 'DCONF_LOCKS'
/org/gnome/desktop/session/idle-delay
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/desktop/screensaver/lock-delay
/org/gnome/desktop/screensaver/idle-activation-enabled
DCONF_LOCKS

# Actualizar base de datos dconf
if command -v dconf &>/dev/null; then
    dconf update 2>/dev/null || true
    echo "[+] Base de datos dconf actualizada"
fi

echo "[+] Configuracion de bloqueo GNOME completada"
GNOME_LOCK_EOF

            chmod 755 "$gnome_lock_script"
            log_change "Creado" "$gnome_lock_script"

            # Ejecutar configuracion
            if ask "Aplicar configuracion de bloqueo GNOME ahora?"; then
                bash "$gnome_lock_script" --all 2>/dev/null || {
                    log_warn "Algunos ajustes de GNOME no se pudieron aplicar (normal si no hay sesion activa)"
                }
                log_change "Aplicado" "bloqueo de pantalla GNOME ($lock_timeout segundos)"
            else
                log_skip "Aplicacion inmediata de bloqueo GNOME"
            fi
        else
            log_skip "Configuracion de bloqueo GNOME"
        fi
    }

    # --- KDE Plasma ---
    configure_kde_lock() {
        log_info "Configurando bloqueo de pantalla para KDE Plasma..."

        if ask "Configurar bloqueo automatico de pantalla KDE (${lock_timeout}s)?"; then
            local kde_lock_script="${SECURIZAR_BIN_DIR}/configurar-kde-lock.sh"

            cat > "$kde_lock_script" << KDE_LOCK_EOF
#!/bin/bash
# Configurar bloqueo de pantalla KDE Plasma
# Generado por securizar (Modulo 58)
set -euo pipefail

LOCK_TIMEOUT_MINUTES=$(( lock_timeout / 60 ))

configure_kde_for_user() {
    local user="\$1"
    local home
    home=\$(getent passwd "\$user" | cut -d: -f6)
    [[ -z "\$home" || ! -d "\$home" ]] && return 0

    local kde_config="\${home}/.config/kscreenlockerrc"
    mkdir -p "\$(dirname "\$kde_config")" 2>/dev/null || true

    cat > "\$kde_config" << KSCREEN_EOF
[Daemon]
Autolock=true
LockGrace=0
LockOnResume=true
Timeout=\$LOCK_TIMEOUT_MINUTES
KSCREEN_EOF

    chown "\$user:\$user" "\$kde_config" 2>/dev/null || true
    echo "[+] Configurado kscreenlocker para usuario: \$user"
}

# Configurar para todos los usuarios con home
while IFS=: read -r username _ uid _ _ home _; do
    [[ "\$uid" -lt 1000 ]] && continue
    [[ ! -d "\$home" ]] && continue
    configure_kde_for_user "\$username"
done < /etc/passwd

echo "[+] Configuracion de bloqueo KDE completada"
KDE_LOCK_EOF

            chmod 755 "$kde_lock_script"
            log_change "Creado" "$kde_lock_script"

            if ask "Aplicar configuracion de bloqueo KDE ahora?"; then
                bash "$kde_lock_script" 2>/dev/null || true
                log_change "Aplicado" "bloqueo de pantalla KDE ($lock_timeout segundos)"
            else
                log_skip "Aplicacion inmediata de bloqueo KDE"
            fi
        else
            log_skip "Configuracion de bloqueo KDE"
        fi
    }

    # --- XFCE ---
    configure_xfce_lock() {
        log_info "Configurando bloqueo de pantalla para XFCE..."

        if ask "Configurar bloqueo automatico de pantalla XFCE (${lock_timeout}s)?"; then
            local xfce_lock_script="${SECURIZAR_BIN_DIR}/configurar-xfce-lock.sh"

            cat > "$xfce_lock_script" << XFCE_LOCK_EOF
#!/bin/bash
# Configurar bloqueo de pantalla XFCE
# Generado por securizar (Modulo 58)
set -euo pipefail

LOCK_TIMEOUT_MINUTES=$(( lock_timeout / 60 ))

configure_xfce_for_user() {
    local user="\$1"
    local home
    home=\$(getent passwd "\$user" | cut -d: -f6)
    [[ -z "\$home" || ! -d "\$home" ]] && return 0

    # xfce4-screensaver settings
    local xfce_config_dir="\${home}/.config/xfce4/xfconf/xfce-perchannel-xml"
    mkdir -p "\$xfce_config_dir" 2>/dev/null || true

    local screensaver_config="\${xfce_config_dir}/xfce4-screensaver.xml"
    cat > "\$screensaver_config" << 'XFCE_SCREEN'
<?xml version="1.0" encoding="UTF-8"?>
<channel name="xfce4-screensaver" version="1.0">
  <property name="saver" type="empty">
    <property name="enabled" type="bool" value="true"/>
    <property name="mode" type="int" value="0"/>
  </property>
  <property name="lock" type="empty">
    <property name="enabled" type="bool" value="true"/>
    <property name="saver-activation" type="bool" value="true"/>
  </property>
XFCE_SCREEN

    # Agregar idle timeout
    echo "  <property name=\"idle-activation\" type=\"empty\">" >> "\$screensaver_config"
    echo "    <property name=\"delay\" type=\"int\" value=\"\${LOCK_TIMEOUT_MINUTES}\"/>" >> "\$screensaver_config"
    echo "    <property name=\"enabled\" type=\"bool\" value=\"true\"/>" >> "\$screensaver_config"
    echo "  </property>" >> "\$screensaver_config"
    echo "</channel>" >> "\$screensaver_config"

    chown "\$user:\$user" "\$screensaver_config" 2>/dev/null || true
    echo "[+] Configurado xfce4-screensaver para usuario: \$user"

    # Tambien configurar xfce4-power-manager para bloqueo en suspend
    local power_config="\${xfce_config_dir}/xfce4-power-manager.xml"
    if [[ ! -f "\$power_config" ]]; then
        cat > "\$power_config" << 'XFCE_POWER'
<?xml version="1.0" encoding="UTF-8"?>
<channel name="xfce4-power-manager" version="1.0">
  <property name="xfce4-power-manager" type="empty">
    <property name="lock-screen-suspend-hibernate" type="bool" value="true"/>
    <property name="dpms-enabled" type="bool" value="true"/>
  </property>
</channel>
XFCE_POWER
        chown "\$user:\$user" "\$power_config" 2>/dev/null || true
    fi
}

while IFS=: read -r username _ uid _ _ home _; do
    [[ "\$uid" -lt 1000 ]] && continue
    [[ ! -d "\$home" ]] && continue
    configure_xfce_for_user "\$username"
done < /etc/passwd

echo "[+] Configuracion de bloqueo XFCE completada"
XFCE_LOCK_EOF

            chmod 755 "$xfce_lock_script"
            log_change "Creado" "$xfce_lock_script"

            if ask "Aplicar configuracion de bloqueo XFCE ahora?"; then
                bash "$xfce_lock_script" 2>/dev/null || true
                log_change "Aplicado" "bloqueo de pantalla XFCE ($lock_timeout segundos)"
            else
                log_skip "Aplicacion inmediata de bloqueo XFCE"
            fi
        else
            log_skip "Configuracion de bloqueo XFCE"
        fi
    }

    # --- Consola (vlock) ---
    configure_console_lock() {
        log_info "Configurando bloqueo de consola..."

        if ask "Instalar y configurar vlock para bloqueo de consola?"; then
            # Instalar vlock/vlock-all (o kbd que lo incluye)
            if ! command -v vlock &>/dev/null; then
                case "$DISTRO_FAMILY" in
                    suse)
                        zypper --non-interactive install kbd 2>/dev/null || true
                        ;;
                    debian)
                        apt-get install -y vlock 2>/dev/null || \
                        apt-get install -y kbd 2>/dev/null || true
                        ;;
                    rhel)
                        dnf install -y kbd 2>/dev/null || true
                        ;;
                    arch)
                        pacman -S --noconfirm kbd 2>/dev/null || true
                        ;;
                esac
                if command -v vlock &>/dev/null; then
                    log_change "Instalado" "vlock (bloqueo de consola)"
                else
                    log_warn "No se pudo instalar vlock"
                fi
            else
                log_info "vlock ya esta instalado"
            fi

            # Configurar TMOUT para sesiones de shell
            local tmout_file="/etc/profile.d/securizar-tmout.sh"
            local tmout_value=$lock_timeout

            if [[ ! -f "$tmout_file" ]] || ! grep -qs "TMOUT=" "$tmout_file" 2>/dev/null; then
                cat > "$tmout_file" << TMOUT_EOF
# Timeout de sesion de consola - securizar (Modulo 58)
# Cierra sesiones inactivas despues de ${tmout_value} segundos
readonly TMOUT=${tmout_value}
export TMOUT
TMOUT_EOF
                chmod 644 "$tmout_file"
                log_change "Creado" "$tmout_file (TMOUT=${tmout_value}s)"
            else
                log_info "TMOUT ya esta configurado en $tmout_file"
            fi

            # Configurar login.defs TMOUT
            if [[ -f /etc/login.defs ]]; then
                if ! grep -qs "^TMOUT" /etc/login.defs 2>/dev/null; then
                    safe_backup /etc/login.defs
                    echo "" >> /etc/login.defs
                    echo "# Timeout de sesion (securizar Modulo 58)" >> /etc/login.defs
                    echo "TMOUT ${tmout_value}" >> /etc/login.defs
                    log_change "Agregado" "TMOUT=${tmout_value} en /etc/login.defs"
                fi
            fi
        else
            log_skip "Configuracion de bloqueo de consola"
        fi
    }

    # --- 4.2: Aplicar segun entorno detectado ---
    case "$desktop_env" in
        gnome)
            configure_gnome_lock
            configure_console_lock
            ;;
        kde)
            configure_kde_lock
            configure_console_lock
            ;;
        xfce)
            configure_xfce_lock
            configure_console_lock
            ;;
        *)
            log_info "No se detecto entorno grafico especifico"
            log_info "Configurando todos los entornos disponibles..."

            # Verificar si hay paquetes GNOME instalados
            if command -v gsettings &>/dev/null || command -v dconf &>/dev/null; then
                configure_gnome_lock
            fi

            # Verificar si hay paquetes KDE instalados
            if command -v kscreenlocker_greet &>/dev/null || \
               command -v kwriteconfig5 &>/dev/null || \
               command -v kwriteconfig6 &>/dev/null; then
                configure_kde_lock
            fi

            # Verificar si hay paquetes XFCE instalados
            if command -v xfce4-screensaver &>/dev/null || \
               command -v xfce4-session &>/dev/null; then
                configure_xfce_lock
            fi

            configure_console_lock
            ;;
    esac

    # --- 4.3: Crear script unificado de configuracion ---
    if ask "Crear script unificado de configuracion de screen lock?"; then
        local configurar_lock="${SECURIZAR_BIN_DIR}/configurar-screen-lock.sh"

        cat > "$configurar_lock" << 'SCREEN_LOCK_MAIN_EOF'
#!/bin/bash
# ============================================================
# configurar-screen-lock.sh - Configuracion de bloqueo de pantalla
# ============================================================
# Generado por securizar (Modulo 58 - Seguridad Fisica)
# Detecta el entorno de escritorio y aplica la configuracion
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

DEFAULT_TIMEOUT=300  # 5 minutos
TIMEOUT="${1:-$DEFAULT_TIMEOUT}"

echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "${CYAN}  Configuracion de Bloqueo de Pantalla${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo ""
echo "Timeout configurado: ${TIMEOUT} segundos ($(( TIMEOUT / 60 )) minutos)"
echo ""

BIN_DIR="/usr/local/bin"

# Detectar y ejecutar scripts de entorno especifico
configured=0

if [[ -x "${BIN_DIR}/configurar-gnome-lock.sh" ]]; then
    echo -e "${GREEN}[+]${NC} Aplicando configuracion GNOME..."
    bash "${BIN_DIR}/configurar-gnome-lock.sh" --all 2>/dev/null && ((configured++)) || true
fi

if [[ -x "${BIN_DIR}/configurar-kde-lock.sh" ]]; then
    echo -e "${GREEN}[+]${NC} Aplicando configuracion KDE..."
    bash "${BIN_DIR}/configurar-kde-lock.sh" 2>/dev/null && ((configured++)) || true
fi

if [[ -x "${BIN_DIR}/configurar-xfce-lock.sh" ]]; then
    echo -e "${GREEN}[+]${NC} Aplicando configuracion XFCE..."
    bash "${BIN_DIR}/configurar-xfce-lock.sh" 2>/dev/null && ((configured++)) || true
fi

# Verificar TMOUT
if [[ -f /etc/profile.d/securizar-tmout.sh ]]; then
    echo -e "${GREEN}[+]${NC} TMOUT configurado para sesiones de consola"
    ((configured++))
fi

# Verificar vlock
if command -v vlock &>/dev/null; then
    echo -e "${GREEN}[+]${NC} vlock disponible para bloqueo de consola"
    ((configured++))
fi

echo ""
echo -e "${BOLD}Entornos configurados: $configured${NC}"

# Verificar estado actual
echo ""
echo -e "${CYAN}Estado actual:${NC}"
echo "  TMOUT=${TMOUT:-no definido}"

if command -v loginctl &>/dev/null; then
    echo ""
    echo "Sesiones activas:"
    loginctl list-sessions --no-pager 2>/dev/null || true
fi
SCREEN_LOCK_MAIN_EOF

        chmod 755 "$configurar_lock"
        log_change "Creado" "$configurar_lock"
    else
        log_skip "Creacion de script unificado de screen lock"
    fi

    log_info "Configuracion de bloqueo de pantalla completada"
}

configure_screen_lock

# ══════════════════════════════════════════════════════════════
# S5: Proteccion TPM (Trusted Platform Module)
# ══════════════════════════════════════════════════════════════
log_section "S5: Proteccion TPM (Trusted Platform Module)"

configure_tpm_protection() {
    log_info "Verificando y configurando proteccion TPM..."

    # --- 5.1: Detectar presencia y version de TPM ---
    if ! has_tpm; then
        log_warn "TPM no detectado en este sistema"
        log_warn "  Verifique que el TPM esta habilitado en BIOS/UEFI"

        # Verificar si hay soporte TPM en el kernel
        if lsmod | grep -qw "tpm" 2>/dev/null; then
            log_info "Modulos TPM cargados en el kernel pero dispositivo no accesible"
        else
            log_info "Modulos TPM no cargados. Intentando cargar..."
            modprobe tpm_tis 2>/dev/null || true
            modprobe tpm_crb 2>/dev/null || true
            if has_tpm; then
                log_info "TPM accesible despues de cargar modulos"
            else
                log_skip "Configuracion TPM (hardware no detectado)"
                return 0
            fi
        fi
    fi

    local tpm_version
    tpm_version=$(get_tpm_version)
    log_info "TPM detectado: version $tpm_version"

    # --- 5.2: Instalar herramientas TPM ---
    if [[ "$tpm_version" == "2"* ]]; then
        log_info "TPM 2.0 detectado"

        if ! command -v tpm2_getcap &>/dev/null; then
            if ask "Instalar tpm2-tools para gestionar TPM 2.0?"; then
                pkg_install tpm2-tools || {
                    log_warn "No se pudo instalar tpm2-tools"
                }
                # Instalar tambien tpm2-abrmd (broker de acceso)
                pkg_install tpm2-abrmd 2>/dev/null || true

                if command -v tpm2_getcap &>/dev/null; then
                    log_change "Instalado" "tpm2-tools"
                fi
            else
                log_skip "Instalacion de tpm2-tools"
            fi
        else
            log_info "tpm2-tools ya esta instalado"
        fi

        # Habilitar servicio tpm2-abrmd si existe
        if systemctl list-unit-files 2>/dev/null | grep -q "tpm2-abrmd"; then
            if ! systemctl is-active tpm2-abrmd &>/dev/null; then
                if ask "Habilitar servicio tpm2-abrmd (broker de acceso TPM)?"; then
                    systemctl enable --now tpm2-abrmd 2>/dev/null || {
                        log_warn "No se pudo habilitar tpm2-abrmd"
                    }
                    log_change "Habilitado" "servicio tpm2-abrmd"
                else
                    log_skip "Habilitacion de tpm2-abrmd"
                fi
            else
                log_info "tpm2-abrmd ya esta activo"
            fi
        fi
    elif [[ "$tpm_version" == "1"* ]]; then
        log_info "TPM 1.2 detectado"
        log_warn "TPM 1.2 tiene limitaciones de seguridad conocidas"
        log_warn "  Se recomienda actualizar a hardware con TPM 2.0"

        if ! command -v tpm_version &>/dev/null; then
            if ask "Instalar trousers (herramientas TPM 1.2)?"; then
                case "$DISTRO_FAMILY" in
                    suse)   zypper --non-interactive install trousers tpm-tools 2>/dev/null || true ;;
                    debian) apt-get install -y trousers tpm-tools 2>/dev/null || true ;;
                    rhel)   dnf install -y trousers tpm-tools 2>/dev/null || true ;;
                    arch)   pacman -S --noconfirm trousers 2>/dev/null || true ;;
                esac
                log_change "Instalado" "trousers (herramientas TPM 1.2)"
            else
                log_skip "Instalacion de trousers"
            fi
        fi
    fi

    # --- 5.3: Verificar uso del TPM ---
    log_info "Verificando uso del TPM en el sistema..."

    # Verificar LUKS con TPM
    local luks_tpm_found=0
    if command -v cryptsetup &>/dev/null; then
        # Verificar si hay tokens TPM2 en slots LUKS
        local luks_devices
        luks_devices=$(blkid -t TYPE="crypto_LUKS" -o device 2>/dev/null || echo "")
        if [[ -n "$luks_devices" ]]; then
            while IFS= read -r dev; do
                [[ -z "$dev" ]] && continue
                local tokens
                tokens=$(cryptsetup luksDump "$dev" 2>/dev/null | grep -i "tpm2\|systemd-tpm2" || echo "")
                if [[ -n "$tokens" ]]; then
                    log_info "  LUKS en $dev tiene token TPM2"
                    luks_tpm_found=1
                else
                    log_info "  LUKS en $dev NO tiene token TPM2"
                fi
            done <<< "$luks_devices"
        fi
    fi

    if [[ $luks_tpm_found -eq 0 ]]; then
        log_warn "No se encontro cifrado LUKS vinculado a TPM"
        log_info "  Para vincular LUKS a TPM2: systemd-cryptenroll --tpm2-device=auto /dev/sdXn"
    fi

    # Verificar measured boot
    local measured_boot=0
    if [[ -d /sys/kernel/security/tpm0 ]]; then
        if [[ -f /sys/kernel/security/tpm0/binary_bios_measurements ]]; then
            log_info "Measured boot: mediciones de BIOS disponibles"
            measured_boot=1
        fi
    fi

    # Verificar IMA (Integrity Measurement Architecture)
    if [[ -d /sys/kernel/security/ima ]]; then
        log_info "IMA (Integrity Measurement Architecture) activo"
        local ima_count
        ima_count=$(cat /sys/kernel/security/ima/runtime_measurements_count 2>/dev/null || echo "0")
        log_info "  Mediciones IMA: $ima_count"
        measured_boot=1
    else
        log_info "IMA no activo (agregar ima_policy=tcb al cmdline del kernel para habilitarlo)"
    fi

    if [[ $measured_boot -eq 0 ]]; then
        log_warn "Measured boot no detectado"
    fi

    # Verificar SSH keys backed by TPM
    local tpm_ssh_found=0
    if command -v ssh-keygen &>/dev/null && [[ "$tpm_version" == "2"* ]]; then
        # Buscar claves SSH PKCS#11 con TPM
        if command -v tpm2_ptool &>/dev/null; then
            log_info "tpm2-pkcs11 disponible para SSH keys con TPM"
            tpm_ssh_found=1
        else
            log_info "tpm2-pkcs11 no disponible (necesario para SSH keys con TPM)"
        fi
    fi

    # --- 5.4: Verificar PCR values ---
    if command -v tpm2_pcrread &>/dev/null; then
        if ask "Verificar valores PCR del TPM?"; then
            log_info "Leyendo valores PCR del TPM 2.0..."

            # PCR 0: BIOS/UEFI code
            # PCR 1: BIOS/UEFI configuration
            # PCR 2: Option ROMs
            # PCR 3: Option ROM config
            # PCR 4: MBR/bootloader code
            # PCR 5: MBR/bootloader config
            # PCR 6: Host platform events
            # PCR 7: Secure Boot state

            local pcr_output
            pcr_output=$(tpm2_pcrread sha256:0,1,2,3,4,5,6,7 2>/dev/null || echo "Error al leer PCRs")

            if [[ "$pcr_output" != "Error"* ]]; then
                log_info "Valores PCR (SHA-256):"
                echo "$pcr_output" | head -20

                # Guardar PCR values para comparacion futura
                local pcr_log="${SECURIZAR_LOG_DIR}/tpm-pcr-values-$(date +%Y%m%d-%H%M%S).log"
                echo "# TPM PCR Values - $(date '+%Y-%m-%d %H:%M:%S')" > "$pcr_log"
                echo "$pcr_output" >> "$pcr_log"
                chmod 600 "$pcr_log"
                log_change "Guardado" "valores PCR en $pcr_log"
            else
                log_warn "No se pudieron leer valores PCR"
            fi
        else
            log_skip "Verificacion de valores PCR"
        fi
    fi

    # --- 5.5: Verificar event log ---
    if [[ "$tpm_version" == "2"* ]] && command -v tpm2_eventlog &>/dev/null; then
        if ask "Verificar log de eventos del TPM?"; then
            local eventlog_path=""
            for epath in /sys/kernel/security/tpm0/binary_bios_measurements \
                         /sys/kernel/security/tpm0/ascii_bios_measurements; do
                if [[ -f "$epath" ]]; then
                    eventlog_path="$epath"
                    break
                fi
            done

            if [[ -n "$eventlog_path" ]]; then
                log_info "Analizando log de eventos TPM desde $eventlog_path..."
                local event_count
                event_count=$(tpm2_eventlog "$eventlog_path" 2>/dev/null | grep -c "PCRIndex" || echo "0")
                log_info "Eventos en el log: $event_count"

                # Guardar event log
                local eventlog_file="${SECURIZAR_LOG_DIR}/tpm-eventlog-$(date +%Y%m%d-%H%M%S).log"
                tpm2_eventlog "$eventlog_path" > "$eventlog_file" 2>/dev/null || true
                chmod 600 "$eventlog_file"
                log_change "Guardado" "event log TPM en $eventlog_file"
            else
                log_warn "Event log del TPM no accesible"
            fi
        else
            log_skip "Verificacion de event log TPM"
        fi
    fi

    # --- 5.6: Crear script de verificacion TPM ---
    if ask "Crear script de verificacion TPM en ${SECURIZAR_BIN_DIR}/?"; then
        local verificar_tpm="${SECURIZAR_BIN_DIR}/verificar-tpm.sh"

        cat > "$verificar_tpm" << 'VERIFICAR_TPM_EOF'
#!/bin/bash
# ============================================================
# verificar-tpm.sh - Verificacion de estado del TPM
# ============================================================
# Generado por securizar (Modulo 58 - Seguridad Fisica)
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

LOG_DIR="/var/log/securizar"
REPORT_FILE="${LOG_DIR}/tpm-check-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$LOG_DIR" 2>/dev/null || true

passed=0
warned=0
failed=0

check_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    echo "[PASS] $1" >> "$REPORT_FILE"
    ((passed++))
}

check_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    echo "[WARN] $1" >> "$REPORT_FILE"
    ((warned++))
}

check_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    echo "[FAIL] $1" >> "$REPORT_FILE"
    ((failed++))
}

echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "${CYAN}  Verificacion de TPM${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo ""
echo "Fecha: $(date '+%Y-%m-%d %H:%M:%S')" | tee "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

# 1. Presencia de TPM
if [[ -d /sys/class/tpm/tpm0 ]]; then
    check_pass "TPM detectado en /sys/class/tpm/tpm0"
else
    check_fail "TPM no detectado"
    echo ""
    echo "Reporte guardado en: $REPORT_FILE"
    exit 1
fi

# 2. Version del TPM
tpm_version="unknown"
if [[ -f /sys/class/tpm/tpm0/tpm_version_major ]]; then
    major=$(cat /sys/class/tpm/tpm0/tpm_version_major 2>/dev/null || echo "?")
    tpm_version="$major.x"
fi

if [[ "$tpm_version" == "2"* ]]; then
    check_pass "TPM version 2.0"
elif [[ "$tpm_version" == "1"* ]]; then
    check_warn "TPM version 1.2 (se recomienda 2.0)"
else
    check_warn "Version TPM desconocida: $tpm_version"
fi

# 3. Accesibilidad del dispositivo
if [[ -c /dev/tpm0 ]]; then
    check_pass "Dispositivo /dev/tpm0 accesible"
else
    check_warn "Dispositivo /dev/tpm0 no accesible (puede requerir modulos)"
fi

if [[ -c /dev/tpmrm0 ]]; then
    check_pass "Dispositivo /dev/tpmrm0 (resource manager) accesible"
fi

# 4. Herramientas TPM
if command -v tpm2_getcap &>/dev/null; then
    check_pass "tpm2-tools instalado"

    # Verificar capacidades
    caps=$(tpm2_getcap properties-fixed 2>/dev/null | head -5 || echo "")
    if [[ -n "$caps" ]]; then
        check_pass "TPM responde a consultas de capacidades"
    else
        check_warn "TPM no responde a consultas (puede estar bloqueado)"
    fi
else
    check_warn "tpm2-tools no instalado"
fi

# 5. Servicio tpm2-abrmd
if systemctl is-active tpm2-abrmd &>/dev/null; then
    check_pass "Servicio tpm2-abrmd activo"
elif systemctl list-unit-files 2>/dev/null | grep -q "tpm2-abrmd"; then
    check_warn "Servicio tpm2-abrmd disponible pero no activo"
fi

# 6. LUKS con TPM
luks_tpm=0
if command -v cryptsetup &>/dev/null; then
    luks_devs=$(blkid -t TYPE="crypto_LUKS" -o device 2>/dev/null || echo "")
    while IFS= read -r dev; do
        [[ -z "$dev" ]] && continue
        tokens=$(cryptsetup luksDump "$dev" 2>/dev/null | grep -i "tpm" || echo "")
        if [[ -n "$tokens" ]]; then
            check_pass "LUKS en $dev vinculado a TPM"
            luks_tpm=1
        else
            check_warn "LUKS en $dev NO vinculado a TPM"
        fi
    done <<< "$luks_devs"
fi
if [[ $luks_tpm -eq 0 ]]; then
    check_warn "No se encontro cifrado LUKS con TPM"
fi

# 7. Measured boot
if [[ -f /sys/kernel/security/tpm0/binary_bios_measurements ]]; then
    check_pass "Measured boot: mediciones disponibles"
else
    check_warn "Measured boot: mediciones no disponibles"
fi

# 8. IMA
if [[ -d /sys/kernel/security/ima ]]; then
    ima_count=$(cat /sys/kernel/security/ima/runtime_measurements_count 2>/dev/null || echo "0")
    check_pass "IMA activo ($ima_count mediciones)"
else
    check_warn "IMA no activo"
fi

# 9. PCR values
if command -v tpm2_pcrread &>/dev/null; then
    pcr_output=$(tpm2_pcrread sha256:0,7 2>/dev/null || echo "")
    if [[ -n "$pcr_output" ]]; then
        check_pass "Valores PCR accesibles"
        echo "" | tee -a "$REPORT_FILE"
        echo "PCR 0 (BIOS) y PCR 7 (Secure Boot):" | tee -a "$REPORT_FILE"
        echo "$pcr_output" | tee -a "$REPORT_FILE"
    else
        check_warn "No se pudieron leer valores PCR"
    fi
fi

# 10. tpm2-pkcs11 para SSH
if command -v tpm2_ptool &>/dev/null; then
    check_pass "tpm2-pkcs11 disponible para SSH/TLS con TPM"
else
    check_warn "tpm2-pkcs11 no disponible (SSH keys con TPM no posible)"
fi

# Resumen
echo ""
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "  ${GREEN}Pasados: $passed${NC} | ${YELLOW}Advertencias: $warned${NC} | ${RED}Fallidos: $failed${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"

total=$((passed + warned + failed))
if [[ $total -gt 0 ]]; then
    score=$(( (passed * 100) / total ))
    echo "Puntuacion: ${score}%"
    echo "" >> "$REPORT_FILE"
    echo "Puntuacion: ${score}% (${passed}/${total})" >> "$REPORT_FILE"
fi
echo ""
echo "Reporte guardado en: $REPORT_FILE"
VERIFICAR_TPM_EOF

        chmod 755 "$verificar_tpm"
        log_change "Creado" "$verificar_tpm"
    else
        log_skip "Creacion de script de verificacion TPM"
    fi

    log_info "Verificacion TPM completada"
}

configure_tpm_protection

# ══════════════════════════════════════════════════════════════
# S6: Proteccion contra Thunderbolt/DMA attacks
# ══════════════════════════════════════════════════════════════
log_section "S6: Proteccion contra Thunderbolt/DMA attacks"

configure_thunderbolt_dma_protection() {
    log_info "Configurando proteccion contra ataques Thunderbolt/DMA..."

    local thunderbolt_found=0
    local iommu_enabled=0

    # --- 6.1: Detectar controladores Thunderbolt ---
    log_info "Buscando controladores Thunderbolt..."

    if [[ -d /sys/bus/thunderbolt ]]; then
        local tb_devices
        tb_devices=$(ls /sys/bus/thunderbolt/devices/ 2>/dev/null | wc -l || echo "0")
        if [[ "$tb_devices" -gt 0 ]]; then
            thunderbolt_found=1
            log_info "Controlador(es) Thunderbolt detectado(s): $tb_devices dispositivo(s)"

            # Listar dispositivos Thunderbolt
            for dev_path in /sys/bus/thunderbolt/devices/*/; do
                [[ ! -d "$dev_path" ]] && continue
                local dev_name
                dev_name=$(cat "${dev_path}/device_name" 2>/dev/null || echo "desconocido")
                local dev_vendor
                dev_vendor=$(cat "${dev_path}/vendor_name" 2>/dev/null || echo "desconocido")
                local dev_auth
                dev_auth=$(cat "${dev_path}/authorized" 2>/dev/null || echo "?")
                log_info "  Thunderbolt: $dev_vendor - $dev_name (autorizado: $dev_auth)"
            done
        else
            log_info "Bus Thunderbolt presente pero sin dispositivos"
        fi
    else
        log_info "No se detecto bus Thunderbolt"
    fi

    # Verificar via lspci
    local pci_thunderbolt
    pci_thunderbolt=$(lspci 2>/dev/null | grep -i "thunderbolt\|alpine ridge\|titan ridge\|ice lake" || echo "")
    if [[ -n "$pci_thunderbolt" ]]; then
        thunderbolt_found=1
        log_info "Controladores Thunderbolt en PCI:"
        echo "$pci_thunderbolt" | while IFS= read -r line; do
            log_info "  $line"
        done
    fi

    # --- 6.2: Verificar y configurar nivel de seguridad Thunderbolt ---
    if [[ $thunderbolt_found -eq 1 ]]; then
        local security_level=""
        for sec_file in /sys/bus/thunderbolt/devices/*/security; do
            [[ ! -f "$sec_file" ]] && continue
            security_level=$(cat "$sec_file" 2>/dev/null || echo "")
            log_info "Nivel de seguridad Thunderbolt actual: $security_level"
            break
        done

        if [[ -n "$security_level" ]]; then
            case "$security_level" in
                none)
                    log_warn "Thunderbolt: seguridad DESHABILITADA (todos los dispositivos permitidos)"
                    log_warn "  Esto permite ataques DMA via Thunderbolt"
                    ;;
                user)
                    log_info "Thunderbolt: nivel 'user' (requiere autorizacion del usuario)"
                    ;;
                secure)
                    log_info "Thunderbolt: nivel 'secure' (autorizacion + verificacion de clave)"
                    ;;
                dponly)
                    log_info "Thunderbolt: nivel 'dponly' (solo DisplayPort, sin datos)"
                    ;;
                usbonly)
                    log_info "Thunderbolt: nivel 'usbonly' (solo USB, sin Thunderbolt)"
                    ;;
                *)
                    log_info "Thunderbolt: nivel desconocido: $security_level"
                    ;;
            esac
        fi

        # Instalar bolt para gestion de Thunderbolt
        if ! command -v boltctl &>/dev/null; then
            if ask "Instalar bolt para gestion de seguridad Thunderbolt?"; then
                case "$DISTRO_FAMILY" in
                    suse)   zypper --non-interactive install bolt 2>/dev/null || true ;;
                    debian) apt-get install -y bolt 2>/dev/null || true ;;
                    rhel)   dnf install -y bolt 2>/dev/null || true ;;
                    arch)   pacman -S --noconfirm bolt 2>/dev/null || true ;;
                esac
                if command -v boltctl &>/dev/null; then
                    log_change "Instalado" "bolt (gestion Thunderbolt)"
                fi
            else
                log_skip "Instalacion de bolt"
            fi
        else
            log_info "bolt ya instalado para gestion Thunderbolt"
            # Mostrar dispositivos gestionados
            boltctl list 2>/dev/null | head -20 || true
        fi
    fi

    # --- 6.3: Verificar y configurar IOMMU ---
    log_info "Verificando proteccion IOMMU..."

    local kernel_cmdline
    kernel_cmdline=$(cat /proc/cmdline 2>/dev/null || echo "")

    # Intel IOMMU
    if echo "$kernel_cmdline" | grep -qi "intel_iommu=on"; then
        log_info "Intel IOMMU (VT-d): HABILITADO en cmdline"
        iommu_enabled=1
    fi

    # AMD IOMMU
    if echo "$kernel_cmdline" | grep -qi "amd_iommu=on\|amd_iommu=force_isolation"; then
        log_info "AMD IOMMU (AMD-Vi): HABILITADO en cmdline"
        iommu_enabled=1
    fi

    # iommu=pt (passthrough mode for performance)
    if echo "$kernel_cmdline" | grep -qi "iommu=pt"; then
        log_info "IOMMU: modo passthrough (pt) habilitado"
    fi

    # Verificar via dmesg
    if [[ $iommu_enabled -eq 0 ]]; then
        local dmesg_iommu
        dmesg_iommu=$(dmesg 2>/dev/null | grep -i "iommu\|DMAR\|AMD-Vi" | head -5 || echo "")
        if [[ -n "$dmesg_iommu" ]]; then
            log_info "IOMMU detectado en dmesg (puede estar habilitado automaticamente):"
            echo "$dmesg_iommu" | while IFS= read -r line; do
                log_info "  $line"
            done
            iommu_enabled=1
        fi
    fi

    if [[ $iommu_enabled -eq 0 ]]; then
        log_warn "IOMMU no detectado - sistema vulnerable a ataques DMA"

        if ask "Agregar parametros IOMMU a la configuracion de GRUB?"; then
            local grub_default="/etc/default/grub"
            if [[ -f "$grub_default" ]]; then
                safe_backup "$grub_default"

                local current_cmdline
                current_cmdline=$(grep "^GRUB_CMDLINE_LINUX_DEFAULT=" "$grub_default" 2>/dev/null | head -1 | sed 's/^GRUB_CMDLINE_LINUX_DEFAULT=//' | tr -d '"' || echo "")

                local iommu_params=""
                # Detectar CPU vendor
                local cpu_vendor
                cpu_vendor=$(grep -m1 "vendor_id" /proc/cpuinfo 2>/dev/null | awk '{print $3}' || echo "")

                if [[ "$cpu_vendor" == "GenuineIntel" ]]; then
                    iommu_params="intel_iommu=on iommu=pt"
                elif [[ "$cpu_vendor" == "AuthenticAMD" ]]; then
                    iommu_params="amd_iommu=force_isolation iommu=pt"
                else
                    iommu_params="iommu=pt"
                fi

                # Agregar parametros si no existen
                local new_cmdline="$current_cmdline"
                for param in $iommu_params; do
                    local param_name
                    param_name=$(echo "$param" | cut -d= -f1)
                    if ! echo "$new_cmdline" | grep -qw "$param_name"; then
                        new_cmdline="$new_cmdline $param"
                    fi
                done
                new_cmdline=$(echo "$new_cmdline" | sed 's/  */ /g' | sed 's/^ //')

                if grep -qs "^GRUB_CMDLINE_LINUX_DEFAULT=" "$grub_default"; then
                    sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"${new_cmdline}\"|" "$grub_default"
                else
                    echo "GRUB_CMDLINE_LINUX_DEFAULT=\"${new_cmdline}\"" >> "$grub_default"
                fi
                log_change "Agregado" "parametros IOMMU ($iommu_params) en GRUB"
                log_warn "Requiere reinicio y ejecutar update-grub para aplicar"
            else
                log_warn "No se encontro $grub_default"
            fi
        else
            log_skip "Configuracion de IOMMU"
        fi
    fi

    # --- 6.4: Deshabilitar DMA en puertos no utilizados ---
    if ask "Configurar proteccion adicional contra DMA en puertos no utilizados?"; then
        # Verificar efi_lockdown
        if echo "$kernel_cmdline" | grep -qi "lockdown=confidentiality\|lockdown=integrity"; then
            log_info "Kernel lockdown activo (proteccion DMA incluida)"
        fi

        # Thunderspy mitigations
        if [[ -f /sys/bus/thunderbolt/devices/0-0/nvm_authenticate_on_disconnect ]]; then
            local nvm_auth
            nvm_auth=$(cat /sys/bus/thunderbolt/devices/0-0/nvm_authenticate_on_disconnect 2>/dev/null || echo "0")
            if [[ "$nvm_auth" == "1" ]]; then
                log_info "Thunderspy: autenticacion en desconexion habilitada"
            fi
        fi

        # Verificar si IOMMU groups estan correctamente configurados
        if [[ -d /sys/kernel/iommu_groups ]]; then
            local iommu_groups
            iommu_groups=$(ls /sys/kernel/iommu_groups/ 2>/dev/null | wc -l || echo "0")
            log_info "Grupos IOMMU configurados: $iommu_groups"
        fi

        # Deshabilitar hotplug de buses PCIe si no es necesario
        local pcie_hotplug_modconf="${SECURIZAR_MODPROBE_DIR}/securizar-dma-protection.conf"
        if [[ ! -f "$pcie_hotplug_modconf" ]]; then
            cat > "$pcie_hotplug_modconf" << 'DMA_MODPROBE_EOF'
# Proteccion contra ataques DMA - securizar (Modulo 58)
# Deshabilitar buses externos potencialmente peligrosos

# Deshabilitar FireWire (IEEE 1394) - vector de ataque DMA comun
blacklist firewire-core
blacklist firewire-ohci
blacklist firewire-sbp2
blacklist firewire-net

# Nota: Los modulos Thunderbolt NO se deshabilitan aqui porque
# se gestionan via bolt/boltctl con autenticacion
DMA_MODPROBE_EOF
            chmod 644 "$pcie_hotplug_modconf"
            log_change "Creado" "$pcie_hotplug_modconf"
        else
            log_info "Configuracion de proteccion DMA ya existe"
        fi

        log_change "Configurado" "proteccion contra DMA"
    else
        log_skip "Proteccion adicional contra DMA"
    fi

    # --- 6.5: Crear script de securizacion Thunderbolt ---
    if ask "Crear script de securizacion Thunderbolt en ${SECURIZAR_BIN_DIR}/?"; then
        local securizar_tb="${SECURIZAR_BIN_DIR}/securizar-thunderbolt.sh"

        cat > "$securizar_tb" << 'SECURIZAR_TB_EOF'
#!/bin/bash
# ============================================================
# securizar-thunderbolt.sh - Securizacion de Thunderbolt/DMA
# ============================================================
# Generado por securizar (Modulo 58 - Seguridad Fisica)
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

LOG_DIR="/var/log/securizar"
REPORT_FILE="${LOG_DIR}/thunderbolt-check-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$LOG_DIR" 2>/dev/null || true

passed=0
warned=0
failed=0

check_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    echo "[PASS] $1" >> "$REPORT_FILE"
    ((passed++))
}

check_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    echo "[WARN] $1" >> "$REPORT_FILE"
    ((warned++))
}

check_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    echo "[FAIL] $1" >> "$REPORT_FILE"
    ((failed++))
}

echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "${CYAN}  Securizacion Thunderbolt/DMA${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo ""
echo "Fecha: $(date '+%Y-%m-%d %H:%M:%S')" | tee "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

# 1. Thunderbolt controllers
if [[ -d /sys/bus/thunderbolt ]]; then
    tb_count=$(ls /sys/bus/thunderbolt/devices/ 2>/dev/null | wc -l || echo "0")
    if [[ "$tb_count" -gt 0 ]]; then
        echo "Controladores Thunderbolt: $tb_count" | tee -a "$REPORT_FILE"

        # Security level
        for sec_file in /sys/bus/thunderbolt/devices/*/security; do
            [[ ! -f "$sec_file" ]] && continue
            level=$(cat "$sec_file" 2>/dev/null || echo "")
            case "$level" in
                none)    check_fail "Seguridad Thunderbolt: NONE (DMA abierto)" ;;
                user)    check_pass "Seguridad Thunderbolt: USER" ;;
                secure)  check_pass "Seguridad Thunderbolt: SECURE" ;;
                dponly)  check_pass "Seguridad Thunderbolt: DPONLY (mas seguro)" ;;
                usbonly) check_pass "Seguridad Thunderbolt: USBONLY (mas seguro)" ;;
                *)       check_warn "Seguridad Thunderbolt: $level" ;;
            esac
        done
    else
        echo "No hay dispositivos Thunderbolt conectados" | tee -a "$REPORT_FILE"
    fi
else
    echo "Bus Thunderbolt no presente" | tee -a "$REPORT_FILE"
fi

# 2. IOMMU
cmdline=$(cat /proc/cmdline 2>/dev/null || echo "")
iommu_ok=0

if echo "$cmdline" | grep -qi "intel_iommu=on"; then
    check_pass "Intel IOMMU habilitado"
    iommu_ok=1
fi
if echo "$cmdline" | grep -qi "amd_iommu=on\|amd_iommu=force_isolation"; then
    check_pass "AMD IOMMU habilitado"
    iommu_ok=1
fi

if [[ $iommu_ok -eq 0 ]]; then
    # Check dmesg
    dmesg_iommu=$(dmesg 2>/dev/null | grep -ci "iommu\|DMAR\|AMD-Vi" || echo "0")
    if [[ "$dmesg_iommu" -gt 0 ]]; then
        check_warn "IOMMU detectado en dmesg pero no en cmdline"
    else
        check_fail "IOMMU no detectado"
    fi
fi

# 3. IOMMU groups
if [[ -d /sys/kernel/iommu_groups ]]; then
    groups=$(ls /sys/kernel/iommu_groups/ 2>/dev/null | wc -l || echo "0")
    check_pass "Grupos IOMMU: $groups"
else
    check_warn "No se encontraron grupos IOMMU"
fi

# 4. Kernel lockdown
if echo "$cmdline" | grep -qi "lockdown="; then
    lockdown=$(echo "$cmdline" | grep -oP 'lockdown=\S+' || echo "")
    check_pass "Kernel lockdown: $lockdown"
else
    check_warn "Kernel lockdown no activo"
fi

# 5. FireWire modules
fw_loaded=0
for mod in firewire_core firewire_ohci firewire_sbp2; do
    if lsmod | grep -qw "$mod" 2>/dev/null; then
        check_fail "Modulo $mod cargado (vector DMA)"
        fw_loaded=1
    fi
done
if [[ $fw_loaded -eq 0 ]]; then
    check_pass "Modulos FireWire no cargados"
fi

# 6. FireWire blacklist
if grep -rqs "blacklist firewire" /etc/modprobe.d/ 2>/dev/null; then
    check_pass "Modulos FireWire en blacklist"
else
    check_warn "Modulos FireWire no estan en blacklist"
fi

# 7. Bolt service
if command -v boltctl &>/dev/null; then
    if systemctl is-active bolt &>/dev/null; then
        check_pass "Servicio bolt activo para gestion Thunderbolt"
    else
        check_warn "bolt instalado pero servicio no activo"
    fi
else
    if [[ -d /sys/bus/thunderbolt ]]; then
        check_warn "bolt no instalado (recomendado para gestion Thunderbolt)"
    fi
fi

# Resumen
echo ""
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "  ${GREEN}Pasados: $passed${NC} | ${YELLOW}Advertencias: $warned${NC} | ${RED}Fallidos: $failed${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"

total=$((passed + warned + failed))
if [[ $total -gt 0 ]]; then
    score=$(( (passed * 100) / total ))
    echo "Puntuacion: ${score}%"
    echo "" >> "$REPORT_FILE"
    echo "Puntuacion: ${score}% (${passed}/${total})" >> "$REPORT_FILE"
fi
echo ""
echo "Reporte guardado en: $REPORT_FILE"
SECURIZAR_TB_EOF

        chmod 755 "$securizar_tb"
        log_change "Creado" "$securizar_tb"
    else
        log_skip "Creacion de script de securizacion Thunderbolt"
    fi

    log_info "Proteccion contra Thunderbolt/DMA completada"
}

configure_thunderbolt_dma_protection

# ══════════════════════════════════════════════════════════════
# S7: Cifrado de disco completo
# ══════════════════════════════════════════════════════════════
log_section "S7: Cifrado de disco completo"

audit_disk_encryption() {
    log_info "Auditando cifrado de disco..."

    local encryption_issues=0
    local encryption_checks=0

    # --- 7.1: Verificar si root esta cifrado con LUKS ---
    log_info "Verificando cifrado de particiones..."

    # Obtener dispositivo raiz
    local root_dev
    root_dev=$(findmnt -n -o SOURCE / 2>/dev/null || echo "")
    local root_is_encrypted=0

    if [[ -n "$root_dev" ]]; then
        log_info "Particion raiz: $root_dev"

        # Si es un device-mapper, verificar si es LUKS
        if [[ "$root_dev" == /dev/mapper/* ]]; then
            local dm_name
            dm_name=$(basename "$root_dev")
            local dm_slave=""

            # Buscar dispositivo fisico subyacente
            if [[ -d "/sys/block/dm-"* ]]; then
                for dm_path in /sys/block/dm-*/dm/name; do
                    [[ ! -f "$dm_path" ]] && continue
                    if [[ "$(cat "$dm_path" 2>/dev/null)" == "$dm_name" ]]; then
                        local dm_dir
                        dm_dir=$(dirname "$(dirname "$dm_path")")
                        if [[ -d "${dm_dir}/slaves" ]]; then
                            dm_slave=$(ls "${dm_dir}/slaves/" 2>/dev/null | head -1)
                            if [[ -n "$dm_slave" ]]; then
                                dm_slave="/dev/${dm_slave}"
                            fi
                        fi
                        break
                    fi
                done
            fi

            if [[ -n "$dm_slave" ]] && cryptsetup isLuks "$dm_slave" 2>/dev/null; then
                root_is_encrypted=1
                log_info "Particion raiz cifrada con LUKS (dispositivo: $dm_slave)"
                ((encryption_checks++))
            elif cryptsetup status "$dm_name" &>/dev/null; then
                root_is_encrypted=1
                log_info "Particion raiz cifrada (dm-crypt activo: $dm_name)"
                ((encryption_checks++))
            fi
        else
            # Dispositivo directo, verificar si es LUKS
            if cryptsetup isLuks "$root_dev" 2>/dev/null; then
                root_is_encrypted=1
                log_info "Particion raiz cifrada con LUKS"
                ((encryption_checks++))
            fi
        fi

        if [[ $root_is_encrypted -eq 0 ]]; then
            log_warn "Particion raiz NO esta cifrada"
            log_warn "  Se recomienda cifrado LUKS para la particion raiz"
            ((encryption_issues++))
        fi
    fi

    # Verificar /home
    local home_dev
    home_dev=$(findmnt -n -o SOURCE /home 2>/dev/null || echo "")
    if [[ -n "$home_dev" && "$home_dev" != "$root_dev" ]]; then
        local home_is_encrypted=0
        if [[ "$home_dev" == /dev/mapper/* ]]; then
            local hm_name
            hm_name=$(basename "$home_dev")
            if cryptsetup status "$hm_name" &>/dev/null; then
                home_is_encrypted=1
                log_info "Particion /home cifrada (dm-crypt: $hm_name)"
                ((encryption_checks++))
            fi
        fi
        if [[ $home_is_encrypted -eq 0 ]]; then
            log_warn "Particion /home NO esta cifrada"
            ((encryption_issues++))
        fi
    elif [[ -z "$home_dev" || "$home_dev" == "$root_dev" ]]; then
        log_info "/home esta en la particion raiz"
    fi

    # --- 7.2: Verificar fuerza del cifrado LUKS ---
    log_info "Verificando parametros de cifrado LUKS..."

    local luks_devices
    luks_devices=$(blkid -t TYPE="crypto_LUKS" -o device 2>/dev/null || echo "")
    if [[ -n "$luks_devices" ]]; then
        while IFS= read -r dev; do
            [[ -z "$dev" ]] && continue
            log_info "Analizando LUKS en $dev..."

            local luks_dump
            luks_dump=$(cryptsetup luksDump "$dev" 2>/dev/null || echo "")
            if [[ -n "$luks_dump" ]]; then
                # Version LUKS
                local luks_version
                luks_version=$(echo "$luks_dump" | grep "^Version:" | awk '{print $2}' || echo "")
                if [[ "$luks_version" == "2" ]]; then
                    log_info "  LUKS version: 2 (recomendada)"
                    ((encryption_checks++))
                elif [[ "$luks_version" == "1" ]]; then
                    log_warn "  LUKS version: 1 (considere migrar a LUKS2)"
                fi

                # Cipher
                local cipher
                cipher=$(echo "$luks_dump" | grep -i "cipher:" | head -1 | awk '{print $NF}' || echo "")
                log_info "  Cifrado: $cipher"
                if echo "$cipher" | grep -qi "aes-xts"; then
                    log_info "  Modo cifrado: AES-XTS (recomendado)"
                    ((encryption_checks++))
                fi

                # Key derivation function
                local kdf
                kdf=$(echo "$luks_dump" | grep -i "PBKDF\|Argon2" | head -1 || echo "")
                if [[ -n "$kdf" ]]; then
                    log_info "  KDF: $kdf"
                    if echo "$kdf" | grep -qi "argon2"; then
                        log_info "  KDF Argon2 (fuerte, recomendado)"
                        ((encryption_checks++))
                    elif echo "$kdf" | grep -qi "pbkdf2"; then
                        log_warn "  KDF PBKDF2 (considere migrar a Argon2id con LUKS2)"
                    fi
                fi

                # Key size
                local key_size
                key_size=$(echo "$luks_dump" | grep -i "key.*size\|MK bits" | head -1 || echo "")
                if [[ -n "$key_size" ]]; then
                    log_info "  $key_size"
                    if echo "$key_size" | grep -q "512\|256"; then
                        ((encryption_checks++))
                    fi
                fi

                # Active keyslots
                local active_slots
                active_slots=$(echo "$luks_dump" | grep -c "ENABLED\|Keyslot:" || echo "0")
                log_info "  Slots activos: $active_slots"
                if [[ "$active_slots" -gt 3 ]]; then
                    log_warn "  Demasiados slots activos ($active_slots) - considere reducir"
                fi
            fi
        done <<< "$luks_devices"
    else
        log_warn "No se encontraron dispositivos LUKS"
        ((encryption_issues++))
    fi

    # --- 7.3: Verificar cifrado de swap ---
    log_info "Verificando cifrado de swap..."

    local swap_devices
    swap_devices=$(swapon --show=NAME --noheadings 2>/dev/null || cat /proc/swaps 2>/dev/null | tail -n +2 | awk '{print $1}')
    if [[ -n "$swap_devices" ]]; then
        while IFS= read -r swap_dev; do
            [[ -z "$swap_dev" ]] && continue
            if [[ "$swap_dev" == /dev/mapper/* ]]; then
                log_info "Swap cifrada: $swap_dev (device-mapper)"
                ((encryption_checks++))
            elif [[ "$swap_dev" == /dev/dm-* ]]; then
                log_info "Swap cifrada: $swap_dev (dm-crypt)"
                ((encryption_checks++))
            elif [[ "$swap_dev" == /dev/zram* ]]; then
                log_info "Swap en zram: $swap_dev (sin persistencia en disco)"
                ((encryption_checks++))
            else
                log_warn "Swap NO cifrada: $swap_dev"
                log_warn "  Una swap sin cifrar puede contener datos sensibles de la memoria"
                ((encryption_issues++))
            fi
        done <<< "$swap_devices"
    else
        log_info "No hay dispositivos swap activos"
    fi

    # --- 7.4: Verificar /tmp y /var/tmp ---
    log_info "Verificando cifrado/tmpfs para /tmp y /var/tmp..."

    local tmp_fstype
    tmp_fstype=$(findmnt -n -o FSTYPE /tmp 2>/dev/null || echo "")
    if [[ "$tmp_fstype" == "tmpfs" ]]; then
        log_info "/tmp esta en tmpfs (en memoria, no persiste)"
        ((encryption_checks++))
    else
        local tmp_dev
        tmp_dev=$(findmnt -n -o SOURCE /tmp 2>/dev/null || echo "")
        if [[ "$tmp_dev" == /dev/mapper/* ]]; then
            log_info "/tmp esta cifrado via device-mapper"
            ((encryption_checks++))
        elif [[ -n "$tmp_dev" && "$tmp_dev" == "$root_dev" && $root_is_encrypted -eq 1 ]]; then
            log_info "/tmp esta en la particion raiz cifrada"
            ((encryption_checks++))
        else
            log_warn "/tmp no esta en tmpfs ni cifrado separadamente"
            ((encryption_issues++))

            if ask "Configurar /tmp como tmpfs?"; then
                # Verificar si ya hay entrada en fstab
                if ! grep -qs "^tmpfs.*/tmp" /etc/fstab 2>/dev/null; then
                    safe_backup /etc/fstab
                    echo "" >> /etc/fstab
                    echo "# /tmp como tmpfs - securizar (Modulo 58)" >> /etc/fstab
                    echo "tmpfs  /tmp  tmpfs  defaults,noatime,nosuid,nodev,noexec,mode=1777,size=2G  0  0" >> /etc/fstab
                    log_change "Agregado" "tmpfs para /tmp en /etc/fstab"
                    log_warn "Requiere reinicio o 'mount -o remount /tmp' para aplicar"
                else
                    log_info "tmpfs para /tmp ya esta en fstab"
                fi
            else
                log_skip "Configuracion de tmpfs para /tmp"
            fi
        fi
    fi

    local vartmp_fstype
    vartmp_fstype=$(findmnt -n -o FSTYPE /var/tmp 2>/dev/null || echo "")
    if [[ "$vartmp_fstype" == "tmpfs" ]]; then
        log_info "/var/tmp esta en tmpfs"
        ((encryption_checks++))
    else
        local vartmp_dev
        vartmp_dev=$(findmnt -n -o SOURCE /var/tmp 2>/dev/null || echo "")
        if [[ -z "$vartmp_dev" || "$vartmp_dev" == "$root_dev" ]] && [[ $root_is_encrypted -eq 1 ]]; then
            log_info "/var/tmp esta en la particion raiz cifrada"
            ((encryption_checks++))
        else
            log_warn "/var/tmp no esta en tmpfs ni cifrado separadamente"
            ((encryption_issues++))
        fi
    fi

    # --- 7.5: Verificar key escrow / backup seguro ---
    log_info "Verificando backup seguro de claves de cifrado..."

    local key_backup_found=0
    # Buscar headers LUKS en backups
    for bak_dir in /root/luks-backup* /root/backup*/luks* /root/*.luks-header*; do
        if [[ -e "$bak_dir" ]]; then
            key_backup_found=1
            log_info "  Backup de claves LUKS encontrado: $bak_dir"
        fi
    done

    if [[ $key_backup_found -eq 0 && -n "$luks_devices" ]]; then
        log_warn "No se encontraron backups de headers LUKS"
        log_warn "  Cree un backup con: cryptsetup luksHeaderBackup /dev/sdXn --header-backup-file backup.luks"

        if ask "Crear backup de headers LUKS ahora?"; then
            mkdir -p "${BACKUP_DIR}/luks-headers" 2>/dev/null || true
            while IFS= read -r dev; do
                [[ -z "$dev" ]] && continue
                local dev_name
                dev_name=$(basename "$dev")
                cryptsetup luksHeaderBackup "$dev" \
                    --header-backup-file "${BACKUP_DIR}/luks-headers/${dev_name}.luks-header" 2>/dev/null && {
                    log_change "Backup" "header LUKS de $dev"
                } || {
                    log_warn "No se pudo hacer backup del header de $dev"
                }
            done <<< "$luks_devices"
        else
            log_skip "Backup de headers LUKS"
        fi
    fi

    # --- 7.6: Crear script de auditoria de cifrado ---
    if ask "Crear script de auditoria de cifrado de disco en ${SECURIZAR_BIN_DIR}/?"; then
        local auditar_cifrado="${SECURIZAR_BIN_DIR}/auditar-cifrado-disco.sh"

        cat > "$auditar_cifrado" << 'AUDITAR_CIFRADO_EOF'
#!/bin/bash
# ============================================================
# auditar-cifrado-disco.sh - Auditoria de cifrado de disco
# ============================================================
# Generado por securizar (Modulo 58 - Seguridad Fisica)
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

LOG_DIR="/var/log/securizar"
REPORT_FILE="${LOG_DIR}/cifrado-disco-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$LOG_DIR" 2>/dev/null || true

passed=0
warned=0
failed=0

check_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    echo "[PASS] $1" >> "$REPORT_FILE"
    ((passed++))
}

check_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    echo "[WARN] $1" >> "$REPORT_FILE"
    ((warned++))
}

check_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    echo "[FAIL] $1" >> "$REPORT_FILE"
    ((failed++))
}

echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "${CYAN}  Auditoria de Cifrado de Disco${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo ""
echo "Fecha: $(date '+%Y-%m-%d %H:%M:%S')" | tee "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

# 1. Particion raiz
root_dev=$(findmnt -n -o SOURCE / 2>/dev/null || echo "")
if [[ "$root_dev" == /dev/mapper/* ]]; then
    dm_name=$(basename "$root_dev")
    if cryptsetup status "$dm_name" &>/dev/null; then
        check_pass "Particion raiz cifrada ($root_dev)"
    else
        check_warn "Particion raiz en device-mapper pero estado desconocido"
    fi
else
    check_fail "Particion raiz NO cifrada ($root_dev)"
fi

# 2. Particion /home
home_dev=$(findmnt -n -o SOURCE /home 2>/dev/null || echo "")
if [[ -n "$home_dev" && "$home_dev" != "$root_dev" ]]; then
    if [[ "$home_dev" == /dev/mapper/* ]]; then
        check_pass "Particion /home cifrada ($home_dev)"
    else
        check_fail "Particion /home NO cifrada ($home_dev)"
    fi
else
    check_pass "/home en particion raiz (hereda cifrado)"
fi

# 3. LUKS details
echo "" | tee -a "$REPORT_FILE"
echo "=== Dispositivos LUKS ===" | tee -a "$REPORT_FILE"
luks_devs=$(blkid -t TYPE="crypto_LUKS" -o device 2>/dev/null || echo "")
if [[ -n "$luks_devs" ]]; then
    while IFS= read -r dev; do
        [[ -z "$dev" ]] && continue
        echo "--- $dev ---" | tee -a "$REPORT_FILE"

        luks_dump=$(cryptsetup luksDump "$dev" 2>/dev/null || echo "")

        # Version
        ver=$(echo "$luks_dump" | grep "^Version:" | awk '{print $2}' || echo "?")
        if [[ "$ver" == "2" ]]; then
            check_pass "LUKS version 2 en $dev"
        else
            check_warn "LUKS version $ver en $dev (se recomienda LUKS2)"
        fi

        # Cipher
        cipher=$(echo "$luks_dump" | grep -i "cipher:" | head -1 | awk '{print $NF}' || echo "?")
        echo "  Cifrado: $cipher" | tee -a "$REPORT_FILE"
        if echo "$cipher" | grep -qi "aes-xts-plain64"; then
            check_pass "Cifrado AES-XTS-plain64 en $dev"
        fi

        # KDF
        kdf=$(echo "$luks_dump" | grep -i "PBKDF\|Argon2" | head -1 || echo "")
        echo "  KDF: $kdf" | tee -a "$REPORT_FILE"
        if echo "$kdf" | grep -qi "argon2"; then
            check_pass "KDF Argon2 en $dev"
        elif echo "$kdf" | grep -qi "pbkdf2"; then
            check_warn "KDF PBKDF2 en $dev (Argon2 recomendado)"
        fi

        # Key size
        key_bits=$(echo "$luks_dump" | grep -i "MK bits\|Key.*size" | head -1 || echo "")
        echo "  $key_bits" | tee -a "$REPORT_FILE"

    done <<< "$luks_devs"
else
    check_fail "No se encontraron dispositivos LUKS"
fi

# 4. Swap
echo "" | tee -a "$REPORT_FILE"
echo "=== Swap ===" | tee -a "$REPORT_FILE"
swap_devs=$(swapon --show=NAME --noheadings 2>/dev/null || echo "")
if [[ -n "$swap_devs" ]]; then
    while IFS= read -r sdev; do
        [[ -z "$sdev" ]] && continue
        if [[ "$sdev" == /dev/mapper/* ]] || [[ "$sdev" == /dev/zram* ]]; then
            check_pass "Swap protegida: $sdev"
        else
            check_fail "Swap NO cifrada: $sdev"
        fi
    done <<< "$swap_devs"
else
    check_pass "No hay swap activa"
fi

# 5. /tmp
tmp_fs=$(findmnt -n -o FSTYPE /tmp 2>/dev/null || echo "")
if [[ "$tmp_fs" == "tmpfs" ]]; then
    check_pass "/tmp en tmpfs"
else
    tmp_src=$(findmnt -n -o SOURCE /tmp 2>/dev/null || echo "")
    if [[ "$tmp_src" == /dev/mapper/* ]]; then
        check_pass "/tmp cifrado"
    elif [[ "$tmp_src" == "$root_dev" ]]; then
        check_pass "/tmp en particion raiz (hereda cifrado)"
    else
        check_warn "/tmp no esta en tmpfs ni cifrado separadamente"
    fi
fi

# 6. Header backups
header_backup_found=0
for bak in /root/luks-backup* /root/backup*/luks* /root/*.luks-header*; do
    if [[ -e "$bak" ]]; then
        header_backup_found=1
        break
    fi
done
if [[ $header_backup_found -eq 1 ]]; then
    check_pass "Backup de headers LUKS encontrado"
else
    check_warn "No se encontraron backups de headers LUKS"
fi

# Resumen
echo "" | tee -a "$REPORT_FILE"
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "  ${GREEN}Pasados: $passed${NC} | ${YELLOW}Advertencias: $warned${NC} | ${RED}Fallidos: $failed${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"

total=$((passed + warned + failed))
if [[ $total -gt 0 ]]; then
    score=$(( (passed * 100) / total ))
    echo "Puntuacion: ${score}%"
    echo "" >> "$REPORT_FILE"
    echo "Puntuacion: ${score}% (${passed}/${total})" >> "$REPORT_FILE"

    if [[ $score -ge 80 ]]; then
        echo -e "  ${GREEN}${BOLD}BUENO${NC} - Cifrado de disco bien configurado"
    elif [[ $score -ge 50 ]]; then
        echo -e "  ${YELLOW}${BOLD}MEJORABLE${NC} - Algunos aspectos del cifrado necesitan atencion"
    else
        echo -e "  ${RED}${BOLD}DEFICIENTE${NC} - Cifrado de disco necesita mejoras urgentes"
    fi
fi
echo ""
echo "Reporte guardado en: $REPORT_FILE"
AUDITAR_CIFRADO_EOF

        chmod 755 "$auditar_cifrado"
        log_change "Creado" "$auditar_cifrado"
    else
        log_skip "Creacion de script de auditoria de cifrado"
    fi

    # Resumen
    log_info "Auditoria de cifrado: $encryption_checks checks OK, $encryption_issues problemas detectados"
}

audit_disk_encryption

# ══════════════════════════════════════════════════════════════
# S8: Control de perifericos
# ══════════════════════════════════════════════════════════════
log_section "S8: Control de perifericos"

configure_peripheral_control() {
    log_info "Configurando control de perifericos..."

    # --- 8.1: Deshabilitar modulos de puertos no utilizados ---

    # --- Firewire ---
    if ask "Deshabilitar modulos FireWire (firewire-core, firewire-ohci)?"; then
        local fw_modconf="${SECURIZAR_MODPROBE_DIR}/securizar-firewire-disable.conf"

        if [[ ! -f "$fw_modconf" ]] || ! grep -qs "blacklist firewire-core" "$fw_modconf" 2>/dev/null; then
            cat > "$fw_modconf" << 'FW_DISABLE_EOF'
# Deshabilitar FireWire (IEEE 1394) - securizar (Modulo 58)
# FireWire permite acceso directo a memoria (DMA) y es un vector de ataque
blacklist firewire-core
blacklist firewire-ohci
blacklist firewire-sbp2
blacklist firewire-net
blacklist ohci1394
blacklist sbp2
blacklist dv1394
blacklist raw1394
blacklist video1394

# install directives para prevenir carga manual
install firewire-core /bin/false
install firewire-ohci /bin/false
install firewire-sbp2 /bin/false
install firewire-net /bin/false
FW_DISABLE_EOF
            chmod 644 "$fw_modconf"
            log_change "Creado" "$fw_modconf (FireWire deshabilitado)"

            # Descargar modulos si estan cargados
            for mod in firewire_net firewire_sbp2 firewire_ohci firewire_core; do
                if is_module_loaded "$mod"; then
                    modprobe -r "$mod" 2>/dev/null || {
                        log_warn "No se pudo descargar modulo $mod (en uso)"
                    }
                fi
            done
        else
            log_info "FireWire ya esta deshabilitado en $fw_modconf"
        fi
    else
        log_skip "Deshabilitacion de FireWire"
    fi

    # --- PCMCIA ---
    if ask "Deshabilitar modulos PCMCIA?"; then
        local pcmcia_modconf="${SECURIZAR_MODPROBE_DIR}/securizar-pcmcia-disable.conf"

        if [[ ! -f "$pcmcia_modconf" ]] || ! grep -qs "blacklist pcmcia" "$pcmcia_modconf" 2>/dev/null; then
            cat > "$pcmcia_modconf" << 'PCMCIA_DISABLE_EOF'
# Deshabilitar PCMCIA - securizar (Modulo 58)
# PCMCIA/CardBus permite acceso DMA y rara vez se usa en equipos modernos
blacklist pcmcia
blacklist pcmcia_core
blacklist pcmcia_rsrc
blacklist yenta_socket
blacklist i82365
blacklist pd6729
blacklist tcic

install pcmcia /bin/false
install pcmcia_core /bin/false
install yenta_socket /bin/false
PCMCIA_DISABLE_EOF
            chmod 644 "$pcmcia_modconf"
            log_change "Creado" "$pcmcia_modconf (PCMCIA deshabilitado)"

            for mod in pcmcia pcmcia_rsrc pcmcia_core yenta_socket; do
                if is_module_loaded "$mod"; then
                    modprobe -r "$mod" 2>/dev/null || true
                fi
            done
        else
            log_info "PCMCIA ya esta deshabilitado"
        fi
    else
        log_skip "Deshabilitacion de PCMCIA"
    fi

    # --- Floppy ---
    if ask "Deshabilitar modulo de disquetera (floppy)?"; then
        local floppy_modconf="${SECURIZAR_MODPROBE_DIR}/securizar-floppy-disable.conf"

        if [[ ! -f "$floppy_modconf" ]] || ! grep -qs "blacklist floppy" "$floppy_modconf" 2>/dev/null; then
            cat > "$floppy_modconf" << 'FLOPPY_DISABLE_EOF'
# Deshabilitar modulo floppy - securizar (Modulo 58)
blacklist floppy
install floppy /bin/false
FLOPPY_DISABLE_EOF
            chmod 644 "$floppy_modconf"
            log_change "Creado" "$floppy_modconf (floppy deshabilitado)"

            if is_module_loaded "floppy"; then
                modprobe -r floppy 2>/dev/null || true
            fi
        else
            log_info "Floppy ya esta deshabilitado"
        fi
    else
        log_skip "Deshabilitacion de floppy"
    fi

    # --- Modulos adicionales potencialmente peligrosos ---
    if ask "Deshabilitar modulos adicionales de buses obsoletos (Bluetooth HID, etc)?"; then
        local extra_modconf="${SECURIZAR_MODPROBE_DIR}/securizar-extra-peripherals.conf"

        if [[ ! -f "$extra_modconf" ]]; then
            cat > "$extra_modconf" << 'EXTRA_DISABLE_EOF'
# Modulos adicionales potencialmente peligrosos - securizar (Modulo 58)

# Deshabilitar modulo de CPU MSR (puede exponer informacion sensible)
# Descomente si no necesita acceso a MSR
# blacklist msr

# Deshabilitar acceso directo a puertos I/O
# blacklist pcspkr  # Descomente para silenciar el beep del sistema

# Cramfs y otros sistemas de archivos poco usados (vectores de ataque potenciales)
blacklist cramfs
blacklist freevxfs
blacklist jffs2
blacklist hfs
blacklist hfsplus
blacklist squashfs
blacklist udf

install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install udf /bin/false
EXTRA_DISABLE_EOF
            chmod 644 "$extra_modconf"
            log_change "Creado" "$extra_modconf"
        else
            log_info "Configuracion de perifericos extra ya existe"
        fi
    else
        log_skip "Deshabilitacion de modulos adicionales"
    fi

    # --- 8.2: Verificar whitelist PCI/PCIe ---
    log_info "Verificando dispositivos PCI/PCIe..."

    if command -v lspci &>/dev/null; then
        local pci_devices
        pci_devices=$(lspci 2>/dev/null | wc -l || echo "0")
        log_info "Dispositivos PCI/PCIe detectados: $pci_devices"

        # Buscar dispositivos desconocidos o sospechosos
        local unknown_pci
        unknown_pci=$(lspci 2>/dev/null | grep -i "unknown\|unassigned" || echo "")
        if [[ -n "$unknown_pci" ]]; then
            log_warn "Dispositivos PCI desconocidos detectados:"
            echo "$unknown_pci" | while IFS= read -r line; do
                log_warn "  $line"
            done
        fi

        # Guardar inventario PCI
        local pci_inventory="${SECURIZAR_LOG_DIR}/pci-inventory-$(date +%Y%m%d).log"
        if [[ ! -f "$pci_inventory" ]]; then
            {
                echo "# Inventario PCI - $(date '+%Y-%m-%d %H:%M:%S')"
                echo "# Generado por securizar (Modulo 58)"
                echo ""
                lspci -nn 2>/dev/null
            } > "$pci_inventory"
            chmod 600 "$pci_inventory"
            log_change "Guardado" "inventario PCI en $pci_inventory"
        fi
    fi

    # --- 8.3: Monitorear nuevas conexiones de dispositivos (udev rules) ---
    if ask "Crear reglas udev para monitorear conexiones de dispositivos?"; then
        local udev_rules="${SECURIZAR_UDEV_DIR}/99-securizar-devices.rules"

        cat > "$udev_rules" << 'UDEV_RULES_EOF'
# ============================================================
# 99-securizar-devices.rules - Monitoreo de dispositivos
# ============================================================
# Generado por securizar (Modulo 58 - Seguridad Fisica)
# ============================================================

# --- Registrar conexion de dispositivos USB ---
ACTION=="add", SUBSYSTEM=="usb", ATTR{bDeviceClass}!="09", \
    RUN+="/usr/local/bin/securizar-udev-logger.sh usb add '%k' '%E{ID_VENDOR}' '%E{ID_MODEL}'"

# --- Registrar desconexion de dispositivos USB ---
ACTION=="remove", SUBSYSTEM=="usb", \
    RUN+="/usr/local/bin/securizar-udev-logger.sh usb remove '%k'"

# --- Registrar conexion de dispositivos de almacenamiento ---
ACTION=="add", SUBSYSTEM=="block", KERNEL=="sd[a-z]*", \
    RUN+="/usr/local/bin/securizar-udev-logger.sh block add '%k' '%E{ID_VENDOR}' '%E{ID_MODEL}'"

# --- Registrar conexion de dispositivos de red ---
ACTION=="add", SUBSYSTEM=="net", \
    RUN+="/usr/local/bin/securizar-udev-logger.sh net add '%k' '%E{ID_VENDOR}' '%E{ID_MODEL}'"

# --- Registrar dispositivos Thunderbolt ---
ACTION=="add", SUBSYSTEM=="thunderbolt", \
    RUN+="/usr/local/bin/securizar-udev-logger.sh thunderbolt add '%k' '%E{ID_VENDOR}' '%E{ID_MODEL}'"

# --- Alertar sobre dispositivos HID nuevos (posibles keyloggers) ---
ACTION=="add", SUBSYSTEM=="hidraw", \
    RUN+="/usr/local/bin/securizar-udev-logger.sh hid add '%k' '%E{ID_VENDOR}' '%E{ID_MODEL}'"

# --- Alertar sobre dispositivos PCI hotplug ---
ACTION=="add", SUBSYSTEM=="pci", \
    RUN+="/usr/local/bin/securizar-udev-logger.sh pci add '%k' '%E{PCI_ID}'"
UDEV_RULES_EOF

        chmod 644 "$udev_rules"
        log_change "Creado" "$udev_rules"

        # Crear script de logging para udev
        local udev_logger="${SECURIZAR_BIN_DIR}/securizar-udev-logger.sh"
        cat > "$udev_logger" << 'UDEV_LOGGER_EOF'
#!/bin/bash
# ============================================================
# securizar-udev-logger.sh - Logger de eventos de dispositivos
# ============================================================
# Llamado por reglas udev (99-securizar-devices.rules)
# Generado por securizar (Modulo 58 - Seguridad Fisica)
# ============================================================

LOG_FILE="/var/log/securizar/device-events.log"
ALERT_FILE="/var/log/securizar/device-alerts.log"

mkdir -p /var/log/securizar 2>/dev/null || true

timestamp=$(date '+%Y-%m-%d %H:%M:%S')
subsystem="${1:-unknown}"
action="${2:-unknown}"
device="${3:-unknown}"
vendor="${4:-}"
model="${5:-}"

# Registrar evento
echo "[$timestamp] $action $subsystem: device=$device vendor=$vendor model=$model" >> "$LOG_FILE"

# Alertas para eventos criticos
case "$subsystem" in
    usb)
        if [[ "$action" == "add" ]]; then
            echo "[$timestamp] ALERTA: Nuevo dispositivo USB conectado: $device ($vendor $model)" >> "$ALERT_FILE"
            # Enviar a syslog
            logger -t securizar-udev -p auth.notice "USB device connected: $device vendor=$vendor model=$model"
        fi
        ;;
    thunderbolt)
        if [[ "$action" == "add" ]]; then
            echo "[$timestamp] ALERTA CRITICA: Dispositivo Thunderbolt conectado: $device ($vendor $model)" >> "$ALERT_FILE"
            logger -t securizar-udev -p auth.warning "Thunderbolt device connected: $device vendor=$vendor model=$model"
        fi
        ;;
    hid)
        if [[ "$action" == "add" ]]; then
            echo "[$timestamp] ALERTA: Nuevo dispositivo HID conectado: $device ($vendor $model) - posible keylogger" >> "$ALERT_FILE"
            logger -t securizar-udev -p auth.warning "New HID device connected: $device vendor=$vendor model=$model"
        fi
        ;;
    pci)
        if [[ "$action" == "add" ]]; then
            echo "[$timestamp] ALERTA CRITICA: Dispositivo PCI hotplug: $device ($vendor)" >> "$ALERT_FILE"
            logger -t securizar-udev -p auth.crit "PCI device hotplug: $device vendor=$vendor"
        fi
        ;;
esac
UDEV_LOGGER_EOF

        chmod 755 "$udev_logger"
        log_change "Creado" "$udev_logger"

        # Recargar reglas udev
        udevadm control --reload-rules 2>/dev/null || true
        udevadm trigger 2>/dev/null || true
        log_change "Recargado" "reglas udev"
    else
        log_skip "Creacion de reglas udev"
    fi

    # --- 8.4: Crear script de gestion de perifericos ---
    if ask "Crear script de gestion de perifericos en ${SECURIZAR_BIN_DIR}/?"; then
        local gestionar_perifericos="${SECURIZAR_BIN_DIR}/gestionar-perifericos.sh"

        cat > "$gestionar_perifericos" << 'GESTIONAR_PERIF_EOF'
#!/bin/bash
# ============================================================
# gestionar-perifericos.sh - Gestion de control de perifericos
# ============================================================
# Generado por securizar (Modulo 58 - Seguridad Fisica)
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

MODPROBE_DIR="/etc/modprobe.d"
UDEV_DIR="/etc/udev/rules.d"
LOG_DIR="/var/log/securizar"

show_menu() {
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Gestion de Control de Perifericos${NC}"
    echo -e "${CYAN}══════════════════════════════════════════${NC}"
    echo ""
    echo "  1) Listar modulos blacklisted"
    echo "  2) Listar dispositivos USB conectados"
    echo "  3) Listar dispositivos PCI"
    echo "  4) Ver log de eventos de dispositivos"
    echo "  5) Ver alertas de dispositivos"
    echo "  6) Agregar modulo a blacklist"
    echo "  7) Quitar modulo de blacklist"
    echo "  8) Estado de modulos de buses externos"
    echo "  9) Verificar integridad de blacklists"
    echo " 10) Recargar reglas udev"
    echo "  0) Salir"
    echo ""
}

list_blacklisted() {
    echo -e "\n${BOLD}Modulos en blacklist (securizar):${NC}"
    for f in "$MODPROBE_DIR"/securizar-*.conf; do
        [[ ! -f "$f" ]] && continue
        echo -e "\n${CYAN}--- $(basename "$f") ---${NC}"
        grep "^blacklist" "$f" 2>/dev/null || echo "  (sin blacklist)"
    done
    echo ""
    echo -e "${BOLD}Todos los modulos blacklisted:${NC}"
    grep -rh "^blacklist" "$MODPROBE_DIR"/ 2>/dev/null | sort -u || echo "  (ninguno)"
}

list_usb() {
    echo -e "\n${BOLD}Dispositivos USB conectados:${NC}"
    if command -v lsusb &>/dev/null; then
        lsusb 2>/dev/null || echo "Error al listar USB"
    else
        echo "lsusb no disponible"
        ls /sys/bus/usb/devices/ 2>/dev/null || echo "No se puede listar bus USB"
    fi
}

list_pci() {
    echo -e "\n${BOLD}Dispositivos PCI:${NC}"
    if command -v lspci &>/dev/null; then
        lspci -nn 2>/dev/null || echo "Error al listar PCI"
    else
        echo "lspci no disponible"
    fi
}

show_device_log() {
    local log_file="${LOG_DIR}/device-events.log"
    echo -e "\n${BOLD}Ultimos 50 eventos de dispositivos:${NC}"
    if [[ -f "$log_file" ]]; then
        tail -50 "$log_file"
    else
        echo "No hay log de eventos"
    fi
}

show_device_alerts() {
    local alert_file="${LOG_DIR}/device-alerts.log"
    echo -e "\n${BOLD}Ultimas 30 alertas:${NC}"
    if [[ -f "$alert_file" ]]; then
        tail -30 "$alert_file"
    else
        echo "No hay alertas registradas"
    fi
}

add_blacklist() {
    read -p "Nombre del modulo a blacklistar: " mod_name
    if [[ -z "$mod_name" ]]; then
        echo "Nombre vacio"
        return
    fi
    local conf="${MODPROBE_DIR}/securizar-custom-blacklist.conf"
    echo "blacklist $mod_name" >> "$conf"
    echo "install $mod_name /bin/false" >> "$conf"
    echo -e "${GREEN}[+]${NC} Modulo $mod_name agregado a blacklist"
    echo "  Ejecute 'depmod -a' y reinicie para aplicar"
}

remove_blacklist() {
    read -p "Nombre del modulo a quitar de blacklist: " mod_name
    if [[ -z "$mod_name" ]]; then
        echo "Nombre vacio"
        return
    fi
    for f in "$MODPROBE_DIR"/securizar-*.conf; do
        [[ ! -f "$f" ]] && continue
        if grep -q "blacklist $mod_name" "$f" 2>/dev/null; then
            sed -i "/blacklist $mod_name/d" "$f"
            sed -i "/install $mod_name/d" "$f"
            echo -e "${GREEN}[+]${NC} Modulo $mod_name removido de $(basename "$f")"
        fi
    done
}

status_external_buses() {
    echo -e "\n${BOLD}Estado de modulos de buses externos:${NC}"
    local modules=(
        "firewire_core:FireWire"
        "firewire_ohci:FireWire OHCI"
        "pcmcia:PCMCIA"
        "pcmcia_core:PCMCIA Core"
        "yenta_socket:CardBus/Yenta"
        "floppy:Floppy"
        "thunderbolt:Thunderbolt"
    )
    for entry in "${modules[@]}"; do
        local mod="${entry%%:*}"
        local desc="${entry##*:}"
        local status="no cargado"
        local blacklisted="no"

        if lsmod | grep -qw "$mod" 2>/dev/null; then
            status="${RED}CARGADO${NC}"
        else
            status="${GREEN}no cargado${NC}"
        fi

        if grep -rqs "blacklist $mod" "$MODPROBE_DIR"/ 2>/dev/null; then
            blacklisted="${GREEN}si${NC}"
        else
            blacklisted="${YELLOW}no${NC}"
        fi

        echo -e "  $desc ($mod): estado=$status blacklist=$blacklisted"
    done
}

verify_blacklists() {
    echo -e "\n${BOLD}Verificando integridad de blacklists:${NC}"
    local issues=0
    for f in "$MODPROBE_DIR"/securizar-*.conf; do
        [[ ! -f "$f" ]] && continue
        local perms
        perms=$(stat -c '%a' "$f" 2>/dev/null || echo "")
        local owner
        owner=$(stat -c '%U' "$f" 2>/dev/null || echo "")
        if [[ "$owner" != "root" ]]; then
            echo -e "  ${RED}[!]${NC} $f - propietario incorrecto: $owner (debe ser root)"
            ((issues++))
        fi
        if [[ "$perms" != "644" ]]; then
            echo -e "  ${YELLOW}[!]${NC} $f - permisos: $perms (recomendado: 644)"
        fi

        # Verificar que blacklist tienen install correspondiente
        while IFS= read -r mod; do
            mod=$(echo "$mod" | awk '{print $2}')
            if ! grep -q "install $mod" "$f" 2>/dev/null; then
                echo -e "  ${YELLOW}[!]${NC} $mod blacklisted pero sin 'install' correspondiente en $f"
            fi
        done < <(grep "^blacklist" "$f" 2>/dev/null)
    done
    if [[ $issues -eq 0 ]]; then
        echo -e "  ${GREEN}Todo correcto${NC}"
    fi
}

reload_udev() {
    echo "Recargando reglas udev..."
    udevadm control --reload-rules 2>/dev/null && {
        echo -e "${GREEN}[+]${NC} Reglas udev recargadas"
    } || {
        echo -e "${RED}[X]${NC} Error al recargar reglas udev"
    }
}

# --- Principal ---
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[X]${NC} Este script debe ejecutarse como root"
    exit 1
fi

if [[ "${1:-}" == "--status" ]]; then
    status_external_buses
    exit 0
elif [[ "${1:-}" == "--alerts" ]]; then
    show_device_alerts
    exit 0
fi

while true; do
    show_menu
    read -p "Seleccione opcion: " choice
    case "$choice" in
        1) list_blacklisted ;;
        2) list_usb ;;
        3) list_pci ;;
        4) show_device_log ;;
        5) show_device_alerts ;;
        6) add_blacklist ;;
        7) remove_blacklist ;;
        8) status_external_buses ;;
        9) verify_blacklists ;;
       10) reload_udev ;;
        0) echo "Saliendo..."; exit 0 ;;
        *) echo "Opcion invalida" ;;
    esac
done
GESTIONAR_PERIF_EOF

        chmod 755 "$gestionar_perifericos"
        log_change "Creado" "$gestionar_perifericos"
    else
        log_skip "Creacion de script de gestion de perifericos"
    fi

    # Actualizar initramfs para aplicar blacklists
    if ask "Actualizar initramfs para aplicar cambios de blacklist?"; then
        case "$DISTRO_FAMILY" in
            suse)
                dracut --force 2>/dev/null && log_change "Actualizado" "initramfs (dracut)" || \
                    log_warn "Error al actualizar initramfs"
                ;;
            debian)
                update-initramfs -u 2>/dev/null && log_change "Actualizado" "initramfs" || \
                    log_warn "Error al actualizar initramfs"
                ;;
            rhel)
                dracut --force 2>/dev/null && log_change "Actualizado" "initramfs (dracut)" || \
                    log_warn "Error al actualizar initramfs"
                ;;
            arch)
                mkinitcpio -P 2>/dev/null && log_change "Actualizado" "initramfs (mkinitcpio)" || \
                    log_warn "Error al actualizar initramfs"
                ;;
        esac
    else
        log_skip "Actualizacion de initramfs"
        log_warn "Ejecute la regeneracion de initramfs manualmente para aplicar blacklists"
    fi

    log_info "Control de perifericos completado"
}

configure_peripheral_control

# ══════════════════════════════════════════════════════════════
# S9: Proteccion contra evil maid attacks
# ══════════════════════════════════════════════════════════════
log_section "S9: Proteccion contra evil maid attacks"

configure_evil_maid_protection() {
    log_info "Configurando proteccion contra evil maid attacks..."

    # --- 9.1: Verificar cadena de arranque medida (TPM PCRs) ---
    log_info "Verificando integridad de la cadena de arranque..."

    local boot_integrity_ok=0

    # Verificar que Secure Boot esta activo
    if command -v mokutil &>/dev/null; then
        local sb_state
        sb_state=$(mokutil --sb-state 2>/dev/null || echo "")
        if echo "$sb_state" | grep -qi "enabled"; then
            log_info "Secure Boot habilitado (primera linea de defensa contra evil maid)"
            ((boot_integrity_ok++))
        else
            log_warn "Secure Boot no habilitado - vulnerable a modificacion del bootloader"
        fi
    fi

    # Verificar PCRs si TPM disponible
    if has_tpm && command -v tpm2_pcrread &>/dev/null; then
        local pcr_baseline="${SECURIZAR_LOG_DIR}/tpm-pcr-baseline.log"

        if [[ -f "$pcr_baseline" ]]; then
            log_info "Comparando valores PCR con baseline..."
            local current_pcrs
            current_pcrs=$(tpm2_pcrread sha256:0,1,2,3,4,5,6,7 2>/dev/null || echo "")

            if [[ -n "$current_pcrs" ]]; then
                local baseline_pcrs
                baseline_pcrs=$(grep -v "^#" "$pcr_baseline" 2>/dev/null || echo "")

                if [[ "$current_pcrs" == "$baseline_pcrs" ]]; then
                    log_info "Valores PCR coinciden con baseline (arranque no modificado)"
                    ((boot_integrity_ok++))
                else
                    log_warn "ALERTA: Valores PCR NO coinciden con baseline"
                    log_warn "  Posible modificacion de la cadena de arranque"
                    log_warn "  Revise los cambios cuidadosamente"
                fi
            fi
        else
            log_info "No hay baseline de PCR guardada"
            if ask "Guardar baseline de PCR actual?"; then
                local pcr_data
                pcr_data=$(tpm2_pcrread sha256:0,1,2,3,4,5,6,7 2>/dev/null || echo "")
                if [[ -n "$pcr_data" ]]; then
                    echo "# TPM PCR Baseline - $(date '+%Y-%m-%d %H:%M:%S')" > "$pcr_baseline"
                    echo "$pcr_data" >> "$pcr_baseline"
                    chmod 600 "$pcr_baseline"
                    log_change "Guardado" "baseline PCR en $pcr_baseline"
                fi
            else
                log_skip "Guardado de baseline PCR"
            fi
        fi
    fi

    # --- 9.2: Verificar integridad del initramfs ---
    log_info "Verificando integridad del initramfs..."

    local boot_dir="/boot"
    local hash_store="${SECURIZAR_LOG_DIR}/boot-hashes.sha256"

    # Buscar archivos criticos del arranque
    local boot_files=()
    for pattern in vmlinuz-* initramfs-* initrd.img-* initrd-*; do
        for f in "${boot_dir}"/${pattern}; do
            [[ -f "$f" ]] && boot_files+=("$f")
        done
    done

    # Agregar grub.cfg
    local grub_cfg
    grub_cfg=$(get_grub_cfg_path)
    if [[ -n "$grub_cfg" && -f "$grub_cfg" ]]; then
        boot_files+=("$grub_cfg")
    fi

    if [[ ${#boot_files[@]} -gt 0 ]]; then
        log_info "Archivos criticos de arranque encontrados: ${#boot_files[@]}"

        if [[ -f "$hash_store" ]]; then
            # Comparar hashes
            log_info "Comparando hashes con almacenamiento previo..."
            local hash_changes=0
            for bf in "${boot_files[@]}"; do
                local current_hash
                current_hash=$(sha256sum "$bf" 2>/dev/null | awk '{print $1}' || echo "")
                local stored_hash
                stored_hash=$(grep "$bf" "$hash_store" 2>/dev/null | awk '{print $1}' || echo "")

                if [[ -z "$stored_hash" ]]; then
                    log_warn "  NUEVO: $bf (no estaba en baseline)"
                    ((hash_changes++))
                elif [[ "$current_hash" != "$stored_hash" ]]; then
                    log_warn "  MODIFICADO: $bf"
                    log_warn "    Hash anterior: $stored_hash"
                    log_warn "    Hash actual:   $current_hash"
                    ((hash_changes++))
                else
                    log_info "  OK: $(basename "$bf")"
                fi
            done

            if [[ $hash_changes -gt 0 ]]; then
                log_warn "Se detectaron $hash_changes cambios en archivos de arranque"
                log_warn "  Esto puede ser una actualizacion legitima o un ataque evil maid"

                if ask "Actualizar hashes de referencia (aceptar cambios como validos)?"; then
                    sha256sum "${boot_files[@]}" > "$hash_store" 2>/dev/null || true
                    chmod 600 "$hash_store"
                    log_change "Actualizado" "hashes de referencia de arranque"
                else
                    log_skip "Actualizacion de hashes de referencia"
                fi
            else
                log_info "Todos los archivos de arranque intactos"
                ((boot_integrity_ok++))
            fi
        else
            log_info "No hay hashes de referencia previos"
            if ask "Crear hashes de referencia para archivos de arranque?"; then
                sha256sum "${boot_files[@]}" > "$hash_store" 2>/dev/null || true
                chmod 600 "$hash_store"
                log_change "Creado" "hashes de referencia en $hash_store"
            else
                log_skip "Creacion de hashes de referencia"
            fi
        fi
    else
        log_warn "No se encontraron archivos de arranque en $boot_dir"
    fi

    # --- 9.3: Verificar integridad de la particion de boot ---
    log_info "Verificando integridad de la particion de boot..."

    local boot_dev
    boot_dev=$(findmnt -n -o SOURCE /boot 2>/dev/null || echo "")
    if [[ -n "$boot_dev" ]]; then
        log_info "Particion de boot: $boot_dev"

        # Verificar permisos del directorio /boot
        local boot_perms
        boot_perms=$(stat -c '%a' /boot 2>/dev/null || echo "")
        if [[ -n "$boot_perms" ]]; then
            if [[ "$boot_perms" == "700" || "$boot_perms" == "755" ]]; then
                log_info "Permisos de /boot: $boot_perms"
            else
                log_warn "Permisos de /boot: $boot_perms (recomendado: 700 o 755)"
                if ask "Restringir permisos de /boot a 700?"; then
                    chmod 700 /boot
                    log_change "Permisos" "/boot cambiado a 700 (era $boot_perms)"
                else
                    log_skip "Restriccion de permisos de /boot"
                fi
            fi
        fi

        # Verificar propietario
        local boot_owner
        boot_owner=$(stat -c '%U:%G' /boot 2>/dev/null || echo "")
        if [[ "$boot_owner" != "root:root" ]]; then
            log_warn "Propietario de /boot: $boot_owner (deberia ser root:root)"
            if ask "Corregir propietario de /boot a root:root?"; then
                chown root:root /boot
                log_change "Propietario" "/boot cambiado a root:root"
            else
                log_skip "Correccion de propietario de /boot"
            fi
        fi

        # Verificar si /boot esta montado como read-only
        local boot_opts
        boot_opts=$(findmnt -n -o OPTIONS /boot 2>/dev/null || echo "")
        if echo "$boot_opts" | grep -q "ro"; then
            log_info "/boot montado como read-only (buena practica)"
            ((boot_integrity_ok++))
        else
            log_info "/boot montado como read-write"
            log_info "  Considere montar /boot como read-only y remontar solo para actualizaciones"
        fi
    else
        log_info "/boot no es una particion separada (incluido en particion raiz)"
    fi

    # --- 9.4: Crear script de verificacion de integridad de boot ---
    if ask "Crear script de verificacion de integridad de boot?"; then
        local verificar_boot="${SECURIZAR_BIN_DIR}/verificar-integridad-boot.sh"

        cat > "$verificar_boot" << 'VERIFICAR_BOOT_EOF'
#!/bin/bash
# ============================================================
# verificar-integridad-boot.sh - Verificacion de integridad del boot
# ============================================================
# Generado por securizar (Modulo 58 - Seguridad Fisica)
# Verifica que los componentes de arranque no han sido modificados
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

LOG_DIR="/var/log/securizar"
HASH_STORE="${LOG_DIR}/boot-hashes.sha256"
REPORT_FILE="${LOG_DIR}/boot-integrity-$(date +%Y%m%d-%H%M%S).log"
ALERT_FILE="${LOG_DIR}/boot-integrity-alerts.log"
BOOT_DIR="/boot"

mkdir -p "$LOG_DIR" 2>/dev/null || true

passed=0
warned=0
failed=0

check_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    echo "[PASS] $1" >> "$REPORT_FILE"
    ((passed++))
}

check_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    echo "[WARN] $1" >> "$REPORT_FILE"
    ((warned++))
}

check_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    echo "[FAIL] $1" >> "$REPORT_FILE"
    ((failed++))
    # Registrar alerta
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] FAIL: $1" >> "$ALERT_FILE"
}

echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "${CYAN}  Verificacion de Integridad del Boot${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo ""
echo "Fecha: $(date '+%Y-%m-%d %H:%M:%S')" | tee "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

# 1. Recopilar archivos de arranque
boot_files=()
for pattern in vmlinuz-* initramfs-* initrd.img-* initrd-*; do
    for f in "${BOOT_DIR}"/${pattern}; do
        [[ -f "$f" ]] && boot_files+=("$f")
    done
done

# Agregar grub.cfg
for g in /boot/grub2/grub.cfg /boot/grub/grub.cfg; do
    [[ -f "$g" ]] && boot_files+=("$g")
done

# Agregar EFI files
for e in /boot/efi/EFI/*/grubx64.efi /boot/efi/EFI/*/shimx64.efi; do
    [[ -f "$e" ]] && boot_files+=("$e")
done

echo "Archivos de arranque encontrados: ${#boot_files[@]}" | tee -a "$REPORT_FILE"

# 2. Verificar contra hashes almacenados
if [[ -f "$HASH_STORE" ]]; then
    echo "" | tee -a "$REPORT_FILE"
    echo "=== Comparacion con Baseline ===" | tee -a "$REPORT_FILE"

    changes_detected=0

    for bf in "${boot_files[@]}"; do
        current_hash=$(sha256sum "$bf" 2>/dev/null | awk '{print $1}' || echo "")
        stored_hash=$(grep "  $bf$\| $bf$" "$HASH_STORE" 2>/dev/null | awk '{print $1}' || echo "")

        if [[ -z "$stored_hash" ]]; then
            check_warn "NUEVO: $bf (no estaba en baseline)"
            ((changes_detected++))
        elif [[ "$current_hash" != "$stored_hash" ]]; then
            check_fail "MODIFICADO: $bf"
            echo "  Hash baseline: $stored_hash" | tee -a "$REPORT_FILE"
            echo "  Hash actual:   $current_hash" | tee -a "$REPORT_FILE"
            ((changes_detected++))
        else
            check_pass "Integro: $(basename "$bf")"
        fi
    done

    # Verificar archivos eliminados
    while IFS= read -r line; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        stored_file=$(echo "$line" | awk '{print $2}')
        if [[ ! -f "$stored_file" ]]; then
            check_fail "ELIMINADO: $stored_file"
            ((changes_detected++))
        fi
    done < "$HASH_STORE"

    if [[ $changes_detected -gt 0 ]]; then
        echo "" | tee -a "$REPORT_FILE"
        echo -e "${RED}${BOLD}ALERTA: Se detectaron $changes_detected cambios en componentes de arranque${NC}" | tee -a "$REPORT_FILE"
        logger -t securizar-boot-integrity -p auth.crit "Boot integrity check: $changes_detected changes detected"
    fi
else
    echo "" | tee -a "$REPORT_FILE"
    echo "No hay baseline de hashes. Creando baseline inicial..." | tee -a "$REPORT_FILE"

    if [[ ${#boot_files[@]} -gt 0 ]]; then
        sha256sum "${boot_files[@]}" > "$HASH_STORE" 2>/dev/null || true
        chmod 600 "$HASH_STORE"
        check_pass "Baseline de hashes creada en $HASH_STORE"
    fi
fi

# 3. Verificar Secure Boot
if command -v mokutil &>/dev/null; then
    sb=$(mokutil --sb-state 2>/dev/null || echo "")
    if echo "$sb" | grep -qi "enabled"; then
        check_pass "Secure Boot habilitado"
    else
        check_fail "Secure Boot no habilitado"
    fi
fi

# 4. Verificar permisos de /boot
boot_perms=$(stat -c '%a' "$BOOT_DIR" 2>/dev/null || echo "")
boot_owner=$(stat -c '%U:%G' "$BOOT_DIR" 2>/dev/null || echo "")
if [[ "$boot_owner" == "root:root" ]]; then
    check_pass "Propietario de /boot: root:root"
else
    check_fail "Propietario de /boot incorrecto: $boot_owner"
fi

if [[ "$boot_perms" == "700" ]]; then
    check_pass "Permisos de /boot: 700 (restrictivos)"
elif [[ "$boot_perms" == "755" ]]; then
    check_warn "Permisos de /boot: 755 (se recomienda 700)"
else
    check_warn "Permisos de /boot: $boot_perms"
fi

# 5. Verificar TPM PCR baseline
if command -v tpm2_pcrread &>/dev/null; then
    pcr_baseline="${LOG_DIR}/tpm-pcr-baseline.log"
    if [[ -f "$pcr_baseline" ]]; then
        current_pcrs=$(tpm2_pcrread sha256:0,4,7 2>/dev/null || echo "")
        stored_pcrs=$(grep -v "^#" "$pcr_baseline" 2>/dev/null || echo "")
        if [[ "$current_pcrs" == "$stored_pcrs" ]]; then
            check_pass "Valores PCR coinciden con baseline"
        else
            check_fail "Valores PCR NO coinciden con baseline (posible manipulacion)"
        fi
    else
        check_warn "No hay baseline de PCR para comparar"
    fi
fi

# 6. Verificar GRUB password
grub_has_password=0
for d in /etc/grub.d /etc/grub2.d; do
    if grep -rqs "password_pbkdf2\|set superusers" "$d"/ 2>/dev/null; then
        grub_has_password=1
        break
    fi
done
for cfg in /boot/grub2/user.cfg /boot/grub/user.cfg; do
    if [[ -f "$cfg" ]] && grep -qs "GRUB2_PASSWORD=" "$cfg" 2>/dev/null; then
        grub_has_password=1
        break
    fi
done

if [[ $grub_has_password -eq 1 ]]; then
    check_pass "GRUB protegido con password"
else
    check_fail "GRUB no tiene password"
fi

# Resumen
echo ""
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "  ${GREEN}Pasados: $passed${NC} | ${YELLOW}Advertencias: $warned${NC} | ${RED}Fallidos: $failed${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"

total=$((passed + warned + failed))
if [[ $total -gt 0 ]]; then
    score=$(( (passed * 100) / total ))
    echo "Puntuacion: ${score}%"
    echo "" >> "$REPORT_FILE"
    echo "Puntuacion: ${score}% (${passed}/${total})" >> "$REPORT_FILE"

    if [[ $score -ge 80 ]]; then
        echo -e "  ${GREEN}${BOLD}BUENO${NC} - Integridad del arranque verificada"
    elif [[ $score -ge 50 ]]; then
        echo -e "  ${YELLOW}${BOLD}MEJORABLE${NC} - Algunos aspectos de la integridad necesitan atencion"
    else
        echo -e "  ${RED}${BOLD}DEFICIENTE${NC} - Integridad del arranque comprometida o no verificable"
    fi
fi
echo ""
echo "Reporte guardado en: $REPORT_FILE"
VERIFICAR_BOOT_EOF

        chmod 755 "$verificar_boot"
        log_change "Creado" "$verificar_boot"
    else
        log_skip "Creacion de script de verificacion de integridad de boot"
    fi

    # --- 9.5: Crear servicio systemd para verificacion en cada arranque ---
    if ask "Crear servicio systemd para verificar integridad en cada arranque?"; then
        local service_file="/etc/systemd/system/securizar-boot-integrity.service"

        cat > "$service_file" << 'BOOT_SERVICE_EOF'
[Unit]
Description=Securizar - Verificacion de integridad del arranque
After=local-fs.target
Before=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/verificar-integridad-boot.sh
StandardOutput=journal
StandardError=journal
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
BOOT_SERVICE_EOF

        chmod 644 "$service_file"
        systemctl daemon-reload 2>/dev/null || true

        if ask "Habilitar servicio de verificacion de integridad de boot?"; then
            systemctl enable securizar-boot-integrity 2>/dev/null || {
                log_warn "No se pudo habilitar el servicio"
            }
            log_change "Habilitado" "servicio securizar-boot-integrity"
        else
            log_skip "Habilitacion del servicio de integridad"
        fi

        log_change "Creado" "$service_file"
    else
        log_skip "Creacion de servicio systemd de integridad de boot"
    fi

    # --- 9.6: Alertas sobre modificacion de componentes de boot ---
    if ask "Configurar alertas por syslog para cambios en /boot?"; then
        # Crear regla de auditd si esta disponible
        if command -v auditctl &>/dev/null; then
            local audit_rules="/etc/audit/rules.d/securizar-boot-watch.rules"
            if [[ ! -f "$audit_rules" ]]; then
                cat > "$audit_rules" << 'AUDIT_BOOT_RULES_EOF'
# Monitorear cambios en /boot - securizar (Modulo 58)
-w /boot/ -p wa -k boot-modification
-w /boot/grub2/ -p wa -k grub-modification
-w /boot/grub/ -p wa -k grub-modification
-w /boot/efi/ -p wa -k efi-modification
-w /etc/default/grub -p wa -k grub-config
-w /etc/grub.d/ -p wa -k grub-scripts
AUDIT_BOOT_RULES_EOF
                chmod 640 "$audit_rules"
                # Recargar reglas de auditd
                augenrules --load 2>/dev/null || auditctl -R "$audit_rules" 2>/dev/null || true
                log_change "Creado" "$audit_rules (monitoreo de /boot)"
            else
                log_info "Reglas de auditoria de boot ya existen"
            fi
        else
            log_info "auditd no disponible - usando inotifywait como alternativa"
        fi
    else
        log_skip "Configuracion de alertas de cambios en /boot"
    fi

    log_info "Proteccion contra evil maid attacks completada"
    log_info "Nivel de proteccion de boot: $boot_integrity_ok checks pasados"
}

configure_evil_maid_protection

# ══════════════════════════════════════════════════════════════
# S10: Auditoria integral de seguridad fisica
# ══════════════════════════════════════════════════════════════
log_section "S10: Auditoria integral de seguridad fisica"

configure_physical_security_audit() {
    log_info "Configurando auditoria integral de seguridad fisica..."

    # --- 10.1: Crear script de auditoria completa ---
    if ask "Crear script de auditoria integral de seguridad fisica?"; then
        local auditar_fisica="${SECURIZAR_BIN_DIR}/auditar-seguridad-fisica.sh"

        cat > "$auditar_fisica" << 'AUDITAR_FISICA_EOF'
#!/bin/bash
# ============================================================
# auditar-seguridad-fisica.sh - Auditoria integral de seguridad fisica
# ============================================================
# Generado por securizar (Modulo 58 - Seguridad Fisica)
# Ejecuta verificaciones completas de todos los aspectos de
# seguridad fisica del sistema.
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

LOG_DIR="/var/log/securizar"
FECHA=$(date +%Y%m%d-%H%M%S)
REPORT_FILE="${LOG_DIR}/auditoria-fisica-${FECHA}.log"
BIN_DIR="/usr/local/bin"

mkdir -p "$LOG_DIR" 2>/dev/null || true

total_passed=0
total_warned=0
total_failed=0
section_results=()

check_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    echo "[PASS] $1" >> "$REPORT_FILE"
    ((total_passed++))
}

check_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    echo "[WARN] $1" >> "$REPORT_FILE"
    ((total_warned++))
}

check_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    echo "[FAIL] $1" >> "$REPORT_FILE"
    ((total_failed++))
}

section_header() {
    local title="$1"
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $title${NC}"
    echo -e "${CYAN}══════════════════════════════════════════${NC}"
    echo "" >> "$REPORT_FILE"
    echo "=== $title ===" >> "$REPORT_FILE"
}

echo -e "${BOLD}${CYAN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   AUDITORIA INTEGRAL DE SEGURIDAD FISICA                  ║"
echo "║   Modulo 58 - securizar                                    ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo "Fecha: $(date '+%Y-%m-%d %H:%M:%S')" | tee "$REPORT_FILE"
echo "Hostname: $(hostname)" | tee -a "$REPORT_FILE"
echo "Kernel: $(uname -r)" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

# ══════════════════════════════════════════
# 1. USBGuard
# ══════════════════════════════════════════
section_header "1. USBGuard - Control de dispositivos USB"
sp=0; sw=0; sf=0

if command -v usbguard &>/dev/null; then
    check_pass "USBGuard instalado"
    ((sp++))

    if systemctl is-active usbguard &>/dev/null; then
        check_pass "Servicio usbguard activo"
        ((sp++))
    else
        check_fail "Servicio usbguard no activo"
        ((sf++))
    fi

    if [[ -f /etc/usbguard/rules.conf ]]; then
        rule_count=$(grep -cv "^#\|^$" /etc/usbguard/rules.conf 2>/dev/null || echo "0")
        check_pass "Politica USBGuard con $rule_count reglas"
        ((sp++))
    else
        check_fail "No hay archivo de reglas USBGuard"
        ((sf++))
    fi

    # Verificar politica implicita
    if [[ -f /etc/usbguard/usbguard-daemon.conf ]]; then
        implicit=$(grep "^ImplicitPolicyTarget=" /etc/usbguard/usbguard-daemon.conf 2>/dev/null | cut -d= -f2)
        if [[ "$implicit" == "block" ]]; then
            check_pass "Politica implicita: block (restrictiva)"
            ((sp++))
        else
            check_warn "Politica implicita: ${implicit:-no definida} (deberia ser block)"
            ((sw++))
        fi
    fi
else
    check_fail "USBGuard no instalado"
    ((sf++))
fi
section_results+=("USBGuard: ${sp}P/${sw}W/${sf}F")

# ══════════════════════════════════════════
# 2. BIOS/UEFI
# ══════════════════════════════════════════
section_header "2. BIOS/UEFI - Seguridad de firmware"
sp=0; sw=0; sf=0

if [[ -d /sys/firmware/efi ]]; then
    check_pass "Sistema UEFI"
    ((sp++))

    if command -v mokutil &>/dev/null; then
        sb=$(mokutil --sb-state 2>/dev/null || echo "")
        if echo "$sb" | grep -qi "enabled"; then
            check_pass "Secure Boot habilitado"
            ((sp++))
        else
            check_fail "Secure Boot no habilitado"
            ((sf++))
        fi
    else
        check_warn "mokutil no disponible"
        ((sw++))
    fi
else
    check_warn "Sistema Legacy BIOS (se recomienda UEFI)"
    ((sw++))
fi

# Verificar firmware update tool
if command -v fwupdmgr &>/dev/null; then
    check_pass "fwupd disponible"
    ((sp++))
else
    check_warn "fwupd no disponible"
    ((sw++))
fi
section_results+=("BIOS/UEFI: ${sp}P/${sw}W/${sf}F")

# ══════════════════════════════════════════
# 3. GRUB
# ══════════════════════════════════════════
section_header "3. GRUB - Proteccion del bootloader"
sp=0; sw=0; sf=0

# Password
grub_pass=0
for d in /etc/grub.d /etc/grub2.d; do
    if grep -rqs "password_pbkdf2\|set superusers" "$d"/ 2>/dev/null; then
        grub_pass=1
        break
    fi
done
for cfg in /boot/grub2/user.cfg /boot/grub/user.cfg; do
    if [[ -f "$cfg" ]] && grep -qs "GRUB2_PASSWORD=" "$cfg" 2>/dev/null; then
        grub_pass=1
        break
    fi
done

if [[ $grub_pass -eq 1 ]]; then
    check_pass "GRUB protegido con password"
    ((sp++))
else
    check_fail "GRUB sin proteccion de password"
    ((sf++))
fi

# Permisos de grub.cfg
for gcfg in /boot/grub2/grub.cfg /boot/grub/grub.cfg; do
    if [[ -f "$gcfg" ]]; then
        gperms=$(stat -c '%a' "$gcfg" 2>/dev/null || echo "")
        if [[ "$gperms" == "600" ]]; then
            check_pass "Permisos de $gcfg: 600"
            ((sp++))
        else
            check_warn "Permisos de $gcfg: $gperms (deberia ser 600)"
            ((sw++))
        fi
        break
    fi
done

# Recovery mode
if [[ -f /etc/default/grub ]]; then
    if grep -qs 'GRUB_DISABLE_RECOVERY.*true' /etc/default/grub 2>/dev/null; then
        check_pass "Modo recovery deshabilitado en GRUB"
        ((sp++))
    else
        check_warn "Modo recovery habilitado en GRUB"
        ((sw++))
    fi
fi
section_results+=("GRUB: ${sp}P/${sw}W/${sf}F")

# ══════════════════════════════════════════
# 4. Screen Lock
# ══════════════════════════════════════════
section_header "4. Screen Lock - Bloqueo de pantalla"
sp=0; sw=0; sf=0

# TMOUT
if [[ -f /etc/profile.d/securizar-tmout.sh ]]; then
    check_pass "TMOUT configurado para sesiones de consola"
    ((sp++))
else
    tmout_set=0
    if grep -rqs "^TMOUT=" /etc/profile /etc/profile.d/ /etc/login.defs 2>/dev/null; then
        tmout_set=1
    fi
    if [[ $tmout_set -eq 1 ]]; then
        check_pass "TMOUT configurado en el sistema"
        ((sp++))
    else
        check_fail "TMOUT no configurado (sesiones de consola sin timeout)"
        ((sf++))
    fi
fi

# vlock
if command -v vlock &>/dev/null; then
    check_pass "vlock disponible para bloqueo de consola"
    ((sp++))
else
    check_warn "vlock no instalado"
    ((sw++))
fi

# dconf screen lock (GNOME)
if [[ -d /etc/dconf/db/local.d ]]; then
    if grep -rqs "lock-enabled=true" /etc/dconf/db/local.d/ 2>/dev/null; then
        check_pass "Bloqueo de pantalla GNOME configurado via dconf"
        ((sp++))
    fi
fi
section_results+=("Screen Lock: ${sp}P/${sw}W/${sf}F")

# ══════════════════════════════════════════
# 5. TPM
# ══════════════════════════════════════════
section_header "5. TPM - Trusted Platform Module"
sp=0; sw=0; sf=0

if [[ -d /sys/class/tpm/tpm0 ]]; then
    check_pass "TPM detectado"
    ((sp++))

    # Version
    tpm_ver="unknown"
    if [[ -f /sys/class/tpm/tpm0/tpm_version_major ]]; then
        tpm_ver=$(cat /sys/class/tpm/tpm0/tpm_version_major 2>/dev/null || echo "?")
    fi
    if [[ "$tpm_ver" == "2" ]]; then
        check_pass "TPM version 2.0"
        ((sp++))
    elif [[ "$tpm_ver" == "1" ]]; then
        check_warn "TPM version 1.2"
        ((sw++))
    fi

    if command -v tpm2_getcap &>/dev/null; then
        check_pass "tpm2-tools instalado"
        ((sp++))
    else
        check_warn "tpm2-tools no instalado"
        ((sw++))
    fi
else
    check_fail "TPM no detectado"
    ((sf++))
fi
section_results+=("TPM: ${sp}P/${sw}W/${sf}F")

# ══════════════════════════════════════════
# 6. Disk Encryption
# ══════════════════════════════════════════
section_header "6. Cifrado de disco"
sp=0; sw=0; sf=0

root_dev=$(findmnt -n -o SOURCE / 2>/dev/null || echo "")
if [[ "$root_dev" == /dev/mapper/* ]]; then
    dm_name=$(basename "$root_dev")
    if cryptsetup status "$dm_name" &>/dev/null; then
        check_pass "Particion raiz cifrada"
        ((sp++))
    else
        check_warn "Particion raiz en device-mapper (cifrado no confirmado)"
        ((sw++))
    fi
else
    check_fail "Particion raiz NO cifrada"
    ((sf++))
fi

# Swap
swap_ok=1
swap_devs=$(swapon --show=NAME --noheadings 2>/dev/null || echo "")
while IFS= read -r sdev; do
    [[ -z "$sdev" ]] && continue
    if [[ "$sdev" != /dev/mapper/* ]] && [[ "$sdev" != /dev/zram* ]]; then
        swap_ok=0
        check_fail "Swap NO cifrada: $sdev"
        ((sf++))
    fi
done <<< "$swap_devs"
if [[ $swap_ok -eq 1 ]]; then
    check_pass "Swap cifrada o en zram"
    ((sp++))
fi

# /tmp
tmp_fs=$(findmnt -n -o FSTYPE /tmp 2>/dev/null || echo "")
if [[ "$tmp_fs" == "tmpfs" ]]; then
    check_pass "/tmp en tmpfs"
    ((sp++))
else
    check_warn "/tmp no en tmpfs"
    ((sw++))
fi
section_results+=("Cifrado: ${sp}P/${sw}W/${sf}F")

# ══════════════════════════════════════════
# 7. Peripheral Control
# ══════════════════════════════════════════
section_header "7. Control de perifericos"
sp=0; sw=0; sf=0

# FireWire
fw_blacklisted=0
if grep -rqs "blacklist firewire" /etc/modprobe.d/ 2>/dev/null; then
    check_pass "FireWire en blacklist"
    ((sp++))
    fw_blacklisted=1
fi
if lsmod | grep -qw "firewire" 2>/dev/null; then
    check_fail "Modulos FireWire cargados"
    ((sf++))
elif [[ $fw_blacklisted -eq 0 ]]; then
    check_warn "FireWire no en blacklist (pero no cargado)"
    ((sw++))
fi

# PCMCIA
if grep -rqs "blacklist pcmcia" /etc/modprobe.d/ 2>/dev/null; then
    check_pass "PCMCIA en blacklist"
    ((sp++))
else
    if ! lsmod | grep -qw "pcmcia" 2>/dev/null; then
        check_warn "PCMCIA no en blacklist (pero no cargado)"
        ((sw++))
    else
        check_fail "PCMCIA cargado y no en blacklist"
        ((sf++))
    fi
fi

# Floppy
if grep -rqs "blacklist floppy" /etc/modprobe.d/ 2>/dev/null; then
    check_pass "Floppy en blacklist"
    ((sp++))
else
    check_warn "Floppy no en blacklist"
    ((sw++))
fi

# udev monitoring
if [[ -f /etc/udev/rules.d/99-securizar-devices.rules ]]; then
    check_pass "Reglas udev de monitoreo configuradas"
    ((sp++))
else
    check_warn "No hay reglas udev de monitoreo"
    ((sw++))
fi
section_results+=("Perifericos: ${sp}P/${sw}W/${sf}F")

# ══════════════════════════════════════════
# 8. Boot Integrity
# ══════════════════════════════════════════
section_header "8. Integridad del arranque"
sp=0; sw=0; sf=0

# Hash baseline
if [[ -f "${LOG_DIR}/boot-hashes.sha256" ]]; then
    check_pass "Baseline de hashes de boot disponible"
    ((sp++))

    # Ejecutar verificacion rapida
    hash_changes=0
    for bf in /boot/vmlinuz-* /boot/initramfs-* /boot/initrd.img-*; do
        [[ ! -f "$bf" ]] && continue
        current=$(sha256sum "$bf" 2>/dev/null | awk '{print $1}' || echo "")
        stored=$(grep "  $bf$\| $bf$" "${LOG_DIR}/boot-hashes.sha256" 2>/dev/null | awk '{print $1}' || echo "")
        if [[ -n "$stored" && "$current" != "$stored" ]]; then
            check_fail "Archivo de boot modificado: $bf"
            ((sf++))
            ((hash_changes++))
        fi
    done
    if [[ $hash_changes -eq 0 ]]; then
        check_pass "Archivos de boot intactos"
        ((sp++))
    fi
else
    check_warn "No hay baseline de hashes de boot"
    ((sw++))
fi

# Permisos de /boot
boot_perms=$(stat -c '%a' /boot 2>/dev/null || echo "")
if [[ "$boot_perms" == "700" ]]; then
    check_pass "Permisos de /boot: 700"
    ((sp++))
elif [[ "$boot_perms" == "755" ]]; then
    check_warn "Permisos de /boot: 755 (se recomienda 700)"
    ((sw++))
else
    check_warn "Permisos de /boot: $boot_perms"
    ((sw++))
fi

# Servicio de verificacion
if systemctl is-enabled securizar-boot-integrity &>/dev/null; then
    check_pass "Servicio de verificacion de integridad habilitado"
    ((sp++))
else
    check_warn "Servicio de verificacion de integridad no habilitado"
    ((sw++))
fi

# Audit rules for /boot
if [[ -f /etc/audit/rules.d/securizar-boot-watch.rules ]]; then
    check_pass "Reglas de auditoria para /boot configuradas"
    ((sp++))
else
    check_warn "No hay reglas de auditoria para /boot"
    ((sw++))
fi
section_results+=("Boot Integrity: ${sp}P/${sw}W/${sf}F")

# ══════════════════════════════════════════
# 9. Thunderbolt/DMA
# ══════════════════════════════════════════
section_header "9. Thunderbolt/DMA"
sp=0; sw=0; sf=0

cmdline=$(cat /proc/cmdline 2>/dev/null || echo "")
iommu_ok=0

if echo "$cmdline" | grep -qi "intel_iommu=on\|amd_iommu=on\|amd_iommu=force"; then
    check_pass "IOMMU habilitado en cmdline"
    ((sp++))
    iommu_ok=1
else
    dmesg_iommu=$(dmesg 2>/dev/null | grep -ci "iommu\|DMAR\|AMD-Vi" || echo "0")
    if [[ "$dmesg_iommu" -gt 0 ]]; then
        check_warn "IOMMU detectado pero no explicitamente en cmdline"
        ((sw++))
    else
        check_fail "IOMMU no detectado"
        ((sf++))
    fi
fi

if echo "$cmdline" | grep -qi "lockdown="; then
    check_pass "Kernel lockdown activo"
    ((sp++))
else
    check_warn "Kernel lockdown no activo"
    ((sw++))
fi

if [[ -d /sys/bus/thunderbolt ]]; then
    for sec_file in /sys/bus/thunderbolt/devices/*/security; do
        [[ ! -f "$sec_file" ]] && continue
        level=$(cat "$sec_file" 2>/dev/null || echo "none")
        if [[ "$level" == "none" ]]; then
            check_fail "Thunderbolt seguridad: none"
            ((sf++))
        else
            check_pass "Thunderbolt seguridad: $level"
            ((sp++))
        fi
    done
fi
section_results+=("Thunderbolt/DMA: ${sp}P/${sw}W/${sf}F")

# ══════════════════════════════════════════
# RESUMEN FINAL
# ══════════════════════════════════════════
echo ""
echo -e "${CYAN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║             RESUMEN DE AUDITORIA FISICA                   ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

echo "=== RESUMEN FINAL ===" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

for result in "${section_results[@]}"; do
    echo -e "  ${BOLD}$result${NC}"
    echo "  $result" >> "$REPORT_FILE"
done

echo ""
total=$((total_passed + total_warned + total_failed))
echo -e "  ${BOLD}TOTAL:${NC}"
echo -e "    ${GREEN}Pasados:      $total_passed${NC}"
echo -e "    ${YELLOW}Advertencias: $total_warned${NC}"
echo -e "    ${RED}Fallidos:     $total_failed${NC}"

echo "" >> "$REPORT_FILE"
echo "TOTAL: Pasados=$total_passed Advertencias=$total_warned Fallidos=$total_failed" >> "$REPORT_FILE"

if [[ $total -gt 0 ]]; then
    score=$(( (total_passed * 100) / total ))
    echo ""
    echo "  Puntuacion global: ${score}%"
    echo "" >> "$REPORT_FILE"
    echo "Puntuacion global: ${score}%" >> "$REPORT_FILE"

    echo ""
    if [[ $score -ge 80 ]]; then
        echo -e "  ${GREEN}${BOLD}██████████████████████████████████████████████${NC}"
        echo -e "  ${GREEN}${BOLD}  CALIFICACION: BUENO (${score}%)${NC}"
        echo -e "  ${GREEN}${BOLD}  La seguridad fisica del sistema es adecuada${NC}"
        echo -e "  ${GREEN}${BOLD}██████████████████████████████████████████████${NC}"
        echo "CALIFICACION: BUENO (${score}%)" >> "$REPORT_FILE"
    elif [[ $score -ge 50 ]]; then
        echo -e "  ${YELLOW}${BOLD}██████████████████████████████████████████████${NC}"
        echo -e "  ${YELLOW}${BOLD}  CALIFICACION: MEJORABLE (${score}%)${NC}"
        echo -e "  ${YELLOW}${BOLD}  Varios aspectos de seguridad necesitan atencion${NC}"
        echo -e "  ${YELLOW}${BOLD}██████████████████████████████████████████████${NC}"
        echo "CALIFICACION: MEJORABLE (${score}%)" >> "$REPORT_FILE"
    else
        echo -e "  ${RED}${BOLD}██████████████████████████████████████████████${NC}"
        echo -e "  ${RED}${BOLD}  CALIFICACION: DEFICIENTE (${score}%)${NC}"
        echo -e "  ${RED}${BOLD}  La seguridad fisica necesita mejoras URGENTES${NC}"
        echo -e "  ${RED}${BOLD}██████████████████████████████████████████████${NC}"
        echo "CALIFICACION: DEFICIENTE (${score}%)" >> "$REPORT_FILE"
    fi
fi

echo ""
echo "Reporte completo guardado en: $REPORT_FILE"
echo ""

# Si se ejecuta en modo no interactivo (cron), enviar resumen a syslog
if [[ ! -t 0 ]]; then
    if [[ $total -gt 0 ]]; then
        score=$(( (total_passed * 100) / total ))
        logger -t securizar-audit-fisica -p auth.info \
            "Auditoria fisica: score=${score}% passed=${total_passed} warned=${total_warned} failed=${total_failed}"
    fi
fi
AUDITAR_FISICA_EOF

        chmod 755 "$auditar_fisica"
        log_change "Creado" "$auditar_fisica"
    else
        log_skip "Creacion de script de auditoria integral"
    fi

    # --- 10.2: Crear cron semanal ---
    if ask "Crear tarea cron semanal para auditoria de seguridad fisica?"; then
        mkdir -p "$SECURIZAR_CRON_WEEKLY" 2>/dev/null || true
        local cron_script="${SECURIZAR_CRON_WEEKLY}/auditoria-seguridad-fisica"

        cat > "$cron_script" << 'CRON_AUDIT_EOF'
#!/bin/bash
# ============================================================
# Auditoria semanal de seguridad fisica
# Generado por securizar (Modulo 58)
# ============================================================
# Se ejecuta semanalmente via /etc/cron.weekly/
# ============================================================

SCRIPT="/usr/local/bin/auditar-seguridad-fisica.sh"
LOG_DIR="/var/log/securizar"

if [[ ! -x "$SCRIPT" ]]; then
    logger -t securizar-cron -p auth.warning "Script de auditoria no encontrado: $SCRIPT"
    exit 1
fi

mkdir -p "$LOG_DIR" 2>/dev/null || true

# Ejecutar auditoria
"$SCRIPT" > "${LOG_DIR}/cron-auditoria-fisica-$(date +%Y%m%d).log" 2>&1

# Rotar logs antiguos (mantener 12 semanas)
find "$LOG_DIR" -name "auditoria-fisica-*.log" -type f -mtime +84 -delete 2>/dev/null || true
find "$LOG_DIR" -name "cron-auditoria-fisica-*.log" -type f -mtime +84 -delete 2>/dev/null || true

exit 0
CRON_AUDIT_EOF

        chmod 755 "$cron_script"
        log_change "Creado" "$cron_script (auditoria semanal)"
    else
        log_skip "Creacion de tarea cron semanal"
    fi

    # --- 10.3: Ejecutar scripts auxiliares si existen ---
    log_info "Scripts de seguridad fisica disponibles:"
    local scripts_found=0
    for script in \
        "${SECURIZAR_BIN_DIR}/gestionar-usbguard.sh" \
        "${SECURIZAR_BIN_DIR}/verificar-bios-uefi.sh" \
        "${SECURIZAR_BIN_DIR}/configurar-screen-lock.sh" \
        "${SECURIZAR_BIN_DIR}/verificar-tpm.sh" \
        "${SECURIZAR_BIN_DIR}/securizar-thunderbolt.sh" \
        "${SECURIZAR_BIN_DIR}/auditar-cifrado-disco.sh" \
        "${SECURIZAR_BIN_DIR}/gestionar-perifericos.sh" \
        "${SECURIZAR_BIN_DIR}/verificar-integridad-boot.sh" \
        "${SECURIZAR_BIN_DIR}/auditar-seguridad-fisica.sh"; do
        if [[ -x "$script" ]]; then
            log_info "  [OK] $script"
            ((scripts_found++))
        else
            log_info "  [--] $script (no instalado)"
        fi
    done
    log_info "Scripts instalados: $scripts_found de 9"

    log_info "Configuracion de auditoria integral completada"
}

configure_physical_security_audit

# ══════════════════════════════════════════════════════════════
# RESUMEN FINAL DEL MODULO 58
# ══════════════════════════════════════════════════════════════
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MODULO 58 - SEGURIDAD FISICA AVANZADA - COMPLETADO     ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Todos los controles de seguridad fisica han sido procesados"
log_info "Backup disponible en: $BACKUP_DIR"
echo ""

show_changes_summary
