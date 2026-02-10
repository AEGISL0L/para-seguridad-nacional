#!/bin/bash
# ============================================================
# HARDENING DE KERNEL BOOT Y SECURE BOOT - Linux Multi-Distro
# ============================================================
# Secciones:
#   S1 - Parámetros de seguridad en cmdline del kernel (GRUB)
#   S2 - Verificar Secure Boot (informativo)
#   S3 - Script para verificar módulos sin firma
#   S4 - Verificar protección GRUB (contraseña, permisos)
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "hardening-kernel-boot"
securizar_setup_traps
log_section "S1: PARÁMETROS DE SEGURIDAD EN GRUB CMDLINE"

echo "Parámetros de seguridad a añadir al kernel:"
echo "  init_on_alloc=1            - Inicializar memoria al asignar"
echo "  init_on_free=1             - Limpiar memoria al liberar"
echo "  slab_nomerge               - No fusionar slabs (previene heap exploits)"
echo "  page_alloc.shuffle=1       - Aleatorizar asignación de páginas"
echo "  pti=on                     - Page Table Isolation (Meltdown)"
echo "  vsyscall=none              - Deshabilitar vsyscall (legacy)"
echo "  debugfs=off                - Deshabilitar debugfs"
echo "  oops=panic                 - Panic en oops del kernel"
echo "  randomize_kstack_offset=on - Aleatorizar offset del stack"
echo "  lockdown=confidentiality   - Lockdown del kernel"
echo ""

if ask "¿Añadir parámetros de seguridad al cmdline del kernel?"; then
    if [[ -f /etc/default/grub ]]; then
        cp /etc/default/grub "$BACKUP_DIR/"
        log_change "Backup" "/etc/default/grub"

        # Parámetros a añadir
        SECURITY_PARAMS="init_on_alloc=1 init_on_free=1 slab_nomerge page_alloc.shuffle=1 pti=on vsyscall=none debugfs=off oops=panic randomize_kstack_offset=on lockdown=confidentiality"

        # Leer línea actual de GRUB_CMDLINE_LINUX_DEFAULT
        current_cmdline=$(grep "^GRUB_CMDLINE_LINUX_DEFAULT=" /etc/default/grub | sed 's/GRUB_CMDLINE_LINUX_DEFAULT="//' | sed 's/"$//')

        # Añadir solo parámetros que no estén ya presentes
        new_params=""
        for param in $SECURITY_PARAMS; do
            param_name="${param%%=*}"
            if ! echo "$current_cmdline" | grep -q "$param_name"; then
                new_params="$new_params $param"
            else
                log_info "  Ya presente: $param_name"
            fi
        done

        if [[ -n "$new_params" ]]; then
            new_cmdline="${current_cmdline}${new_params}"
            sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"${new_cmdline}\"|" /etc/default/grub
            log_change "Modificado" "/etc/default/grub"
            log_info "Parámetros añadidos:$new_params"

            # Regenerar grub.cfg
            log_info "Regenerando grub.cfg..."
            grub_regenerate
            log_change "Aplicado" "grub_regenerate"
            log_info "grub.cfg regenerado"
            log_warn "Los cambios se aplicarán en el próximo reinicio"
        else
            log_info "Todos los parámetros ya estaban configurados"
        fi
    else
        log_error "/etc/default/grub no encontrado"
    fi
else
    log_skip "Añadir parámetros de seguridad al cmdline del kernel"
fi

# ============================================================
# S2: Verificar Secure Boot (informativo)
# ============================================================
log_section "S2: VERIFICAR SECURE BOOT"

log_info "Comprobando estado de Secure Boot..."

if command -v mokutil &>/dev/null; then
    sb_state=$(mokutil --sb-state 2>&1 || true)
    echo "  Estado: $sb_state"

    if echo "$sb_state" | grep -qi "enabled"; then
        log_info "Secure Boot está HABILITADO"
    else
        log_warn "Secure Boot NO está habilitado"
        log_warn "Recomendación: habilitar Secure Boot en la BIOS/UEFI"
    fi
else
    log_warn "mokutil no instalado. Instalando..."
    if ask "¿Instalar mokutil para verificar Secure Boot?"; then
        pkg_install mokutil
        if command -v mokutil &>/dev/null; then
            sb_state=$(mokutil --sb-state 2>&1 || true)
            echo "  Estado: $sb_state"
        else
            log_error "No se pudo instalar mokutil"
        fi
    else
        log_skip "Instalar mokutil para verificar Secure Boot"
    fi
fi

# Verificar modo UEFI
if [[ -d /sys/firmware/efi ]]; then
    log_info "Sistema arrancado en modo UEFI"
else
    log_warn "Sistema arrancado en modo BIOS legacy (Secure Boot no disponible)"
fi

# ============================================================
# S3: Script para verificar módulos sin firma
# ============================================================
log_section "S3: SCRIPT DE VERIFICACIÓN DE MÓDULOS"

if ask "¿Crear /usr/local/bin/verificar-modulos-firmados.sh?"; then
    cat > /usr/local/bin/verificar-modulos-firmados.sh << 'EOFMOD'
#!/bin/bash
# ============================================================
# Verificar módulos del kernel cargados sin firma
# Uso: sudo verificar-modulos-firmados.sh
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  VERIFICACIÓN DE MÓDULOS DEL KERNEL${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

total=0
sin_firma=0
con_firma=0

echo -e "${BOLD}Módulos sin firma (tainted):${NC}"
for mod in $(lsmod | awk 'NR>1 {print $1}'); do
    ((total++))
    modinfo_out=$(modinfo "$mod" 2>/dev/null)

    # Verificar si tiene firma
    if echo "$modinfo_out" | grep -q "sig_id\|signature"; then
        ((con_firma++))
    else
        echo -e "  ${YELLOW}!!${NC}  $mod - SIN FIRMA"
        ((sin_firma++))
    fi
done

echo ""
echo -e "${BOLD}Resumen:${NC}"
echo -e "  Total módulos cargados: $total"
echo -e "  Con firma: ${GREEN}$con_firma${NC}"
echo -e "  Sin firma: ${YELLOW}$sin_firma${NC}"

# Verificar kernel tainted
tainted=$(cat /proc/sys/kernel/tainted 2>/dev/null || echo "N/A")
echo ""
echo -e "  Kernel tainted flags: $tainted"
if [[ "$tainted" == "0" ]]; then
    echo -e "  ${GREEN}OK${NC}  Kernel no está contaminado"
else
    echo -e "  ${YELLOW}!!${NC}  Kernel contaminado (tainted=$tainted)"
    echo "  Consulta: https://www.kernel.org/doc/html/latest/admin-guide/tainted-kernels.html"
fi

echo ""
echo -e "${BOLD}Verificación completada: $(date)${NC}"
EOFMOD

    log_change "Creado" "/usr/local/bin/verificar-modulos-firmados.sh"
    chmod +x /usr/local/bin/verificar-modulos-firmados.sh
    log_change "Permisos" "/usr/local/bin/verificar-modulos-firmados.sh -> +x"
    log_info "Script creado: /usr/local/bin/verificar-modulos-firmados.sh"
else
    log_skip "Crear /usr/local/bin/verificar-modulos-firmados.sh"
fi

# ============================================================
# S4: Verificar protección GRUB
# ============================================================
log_section "S4: VERIFICAR PROTECCIÓN DE GRUB"

log_info "Verificando protección de GRUB..."

# Verificar contraseña de GRUB
if [[ -f $GRUB_USER_CFG ]]; then
    if grep -q "GRUB2_PASSWORD" $GRUB_USER_CFG 2>/dev/null; then
        log_info "GRUB tiene contraseña configurada"
    else
        log_warn "GRUB user.cfg existe pero sin contraseña"
    fi
else
    log_warn "GRUB NO tiene contraseña ($GRUB_USER_CFG no existe)"
    if ask "¿Proteger GRUB con contraseña ahora?"; then
        echo ""
        echo "Introduce una contraseña para GRUB:"
        grub_set_password 2>/dev/null || true
        if [[ -f $GRUB_USER_CFG ]]; then
            log_change "Aplicado" "grub_set_password"
            log_info "Contraseña de GRUB establecida"
        else
            log_error "No se pudo establecer la contraseña de GRUB"
        fi
    else
        log_skip "Proteger GRUB con contraseña"
    fi
fi

# Verificar permisos de /boot
log_info "Verificando permisos de /boot..."
boot_perm=$(stat -c "%a" /boot 2>/dev/null || echo "???")
if [[ "$boot_perm" == "700" ]]; then
    log_info "/boot tiene permisos restrictivos ($boot_perm)"
else
    log_warn "/boot tiene permisos: $boot_perm (recomendado: 700)"
    if ask "¿Aplicar permisos 700 a /boot?"; then
        chmod 700 /boot
        log_change "Permisos" "/boot -> 700"
        log_info "/boot -> 700"
    else
        log_skip "Aplicar permisos 700 a /boot"
    fi
fi

# Verificar permisos de grub.cfg
if [[ -f $GRUB_CFG ]]; then
    grub_perm=$(stat -c "%a" $GRUB_CFG 2>/dev/null || echo "???")
    if [[ "$grub_perm" == "600" ]]; then
        log_info "$GRUB_CFG tiene permisos restrictivos ($grub_perm)"
    else
        log_warn "$GRUB_CFG tiene permisos: $grub_perm (recomendado: 600)"
        if ask "¿Aplicar permisos 600 a $GRUB_CFG?"; then
            chmod 600 $GRUB_CFG
            log_change "Permisos" "$GRUB_CFG -> 600"
            log_info "$GRUB_CFG -> 600"
        else
            log_skip "Aplicar permisos 600 a $GRUB_CFG"
        fi
    fi
fi

# Verificar cmdline actual del kernel
echo ""
log_info "Cmdline actual del kernel en ejecución:"
echo "  $(cat /proc/cmdline 2>/dev/null || echo 'No disponible')"

echo ""
log_info "Hardening de kernel boot completado"
log_info "Backup en: $BACKUP_DIR"
show_changes_summary
