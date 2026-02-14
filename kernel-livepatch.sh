#!/bin/bash
# ============================================================
# kernel-livepatch.sh - Modulo 47: Kernel live patching
# ============================================================
# Secciones:
#   S1  - Auditoria de seguridad del kernel
#   S2  - Configuracion de live patching
#   S3  - Mitigacion de exploits via sysctl
#   S4  - Hardening de modulos del kernel
#   S5  - Validacion de parametros del kernel
#   S6  - Monitorizacion de CVEs del kernel
#   S7  - Politica de actualizacion del kernel
#   S8  - Secure Boot y firma de modulos
#   S9  - Rollback seguro del kernel
#   S10 - Auditoria y scoring integral
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps

# ── Pre-check rapido ────────────────────────────────────
_precheck 10
_pc check_executable /usr/local/bin/auditar-kernel.sh
_pc check_file_exists /etc/securizar/livepatch.conf
_pc check_file_exists /etc/sysctl.d/99-securizar-kernel-exploit.conf
_pc check_file_exists /etc/modprobe.d/securizar-blacklist.conf
_pc check_executable /usr/local/bin/validar-kernel-params.sh
_pc check_executable /usr/local/bin/monitorizar-cves-kernel.sh
_pc check_executable /usr/local/bin/gestionar-kernel-updates.sh
_pc check_executable /usr/local/bin/verificar-secure-boot.sh
_pc check_executable /usr/local/bin/kernel-rollback.sh
_pc check_executable /usr/local/bin/auditoria-livepatch.sh
_precheck_result

init_backup "kernel-livepatch"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MODULO 47 - KERNEL LIVE PATCHING Y MITIGACION          ║"
echo "║   DE EXPLOITS                                             ║"
echo "║   Live patching, sysctl, modulos, CVEs, Secure Boot,     ║"
echo "║   rollback, auditoria integral                            ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

KERNEL_VERSION=$(uname -r)
KERNEL_MAJOR=$(uname -r | cut -d. -f1)
KERNEL_MINOR=$(uname -r | cut -d. -f2)
log_info "Kernel actual: $KERNEL_VERSION"

# Directorio de configuracion securizar
mkdir -p /etc/securizar
mkdir -p /var/log/securizar

# ============================================================
# S1: AUDITORIA DE SEGURIDAD DEL KERNEL
# ============================================================
log_section "S1: AUDITORIA DE SEGURIDAD DEL KERNEL"

echo "Crea /usr/local/bin/auditar-kernel.sh:"
echo "  - Version y arquitectura del kernel"
echo "  - Estado KASLR, SMEP, SMAP, KPTI"
echo "  - Retpoline, modo lockdown, Secure Boot"
echo "  - Kernel taint, modulos cargados"
echo "  - Parametros de seguridad del kernel"
echo "  - Puntuacion de seguridad"
echo ""

if check_executable /usr/local/bin/auditar-kernel.sh; then
    log_already "Auditoria de seguridad del kernel (auditar-kernel.sh existe)"
elif ask "¿Crear herramienta de auditoria de seguridad del kernel?"; then

    cat > /usr/local/bin/auditar-kernel.sh << 'EOFAUDITKERNEL'
#!/bin/bash
# ============================================================
# auditar-kernel.sh - Auditoria de seguridad del kernel
# Generado por securizar - Modulo 47
# ============================================================
set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SCORE=0
MAX_SCORE=0
ISSUES=()

check_pass() {
    echo -e "  ${GREEN}[PASS]${NC} $1"
    ((SCORE++)) || true
    ((MAX_SCORE++)) || true
}

check_fail() {
    echo -e "  ${RED}[FAIL]${NC} $1"
    ISSUES+=("$1")
    ((MAX_SCORE++)) || true
}

check_warn() {
    echo -e "  ${YELLOW}[WARN]${NC} $1"
    ((MAX_SCORE++)) || true
}

check_info() {
    echo -e "  ${CYAN}[INFO]${NC} $1"
}

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║       AUDITORIA DE SEGURIDAD DEL KERNEL                  ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo -e "${BOLD}Fecha:${NC}         $(date '+%Y-%m-%d %H:%M:%S')"
echo -e "${BOLD}Kernel:${NC}        $(uname -r)"
echo -e "${BOLD}Arquitectura:${NC}  $(uname -m)"
echo -e "${BOLD}Hostname:${NC}      $(hostname)"
echo ""

# --- Version del kernel ---
echo -e "${CYAN}── Version del Kernel ──────────────────────────────────${NC}"
KVER=$(uname -r)
KMAJ=$(echo "$KVER" | cut -d. -f1)
KMIN=$(echo "$KVER" | cut -d. -f2)
check_info "Kernel: $KVER"

if [[ "$KMAJ" -ge 6 ]]; then
    check_pass "Kernel principal >= 6.x (moderno)"
elif [[ "$KMAJ" -ge 5 && "$KMIN" -ge 10 ]]; then
    check_pass "Kernel 5.10+ (LTS con buen soporte)"
elif [[ "$KMAJ" -ge 5 ]]; then
    check_warn "Kernel 5.x pero menor a 5.10 - considerar actualizar"
else
    check_fail "Kernel $KMAJ.x es antiguo - alto riesgo de CVEs sin parchear"
fi

# --- KASLR ---
echo ""
echo -e "${CYAN}── KASLR (Kernel Address Space Layout Randomization) ──${NC}"
if [[ -f /proc/cmdline ]]; then
    CMDLINE=$(cat /proc/cmdline)
    if echo "$CMDLINE" | grep -q "nokaslr"; then
        check_fail "KASLR esta DESHABILITADO (nokaslr en cmdline)"
    else
        # Verificar via /sys si disponible
        if [[ -f /sys/kernel/boot_params/data ]] || ! echo "$CMDLINE" | grep -q "nokaslr"; then
            check_pass "KASLR esta habilitado (no hay 'nokaslr' en cmdline)"
        fi
    fi
else
    check_warn "No se pudo verificar /proc/cmdline para KASLR"
fi

# --- SMEP/SMAP ---
echo ""
echo -e "${CYAN}── SMEP/SMAP (CPU Security Features) ─────────────────${NC}"
if [[ -f /proc/cpuinfo ]]; then
    if grep -q "smep" /proc/cpuinfo; then
        check_pass "SMEP (Supervisor Mode Execution Prevention) presente"
    else
        check_fail "SMEP no disponible en CPU"
    fi
    if grep -q "smap" /proc/cpuinfo; then
        check_pass "SMAP (Supervisor Mode Access Prevention) presente"
    else
        check_fail "SMAP no disponible en CPU"
    fi
else
    check_warn "No se pudo leer /proc/cpuinfo"
fi

# --- KPTI ---
echo ""
echo -e "${CYAN}── KPTI (Kernel Page Table Isolation - Meltdown) ─────${NC}"
if [[ -d /sys/kernel/debug/x86 ]] && [[ -f /sys/kernel/debug/x86/pti_enabled ]] 2>/dev/null; then
    PTI_VAL=$(cat /sys/kernel/debug/x86/pti_enabled 2>/dev/null || echo "unknown")
    if [[ "$PTI_VAL" == "1" ]]; then
        check_pass "KPTI esta habilitado"
    elif [[ "$PTI_VAL" == "0" ]]; then
        check_fail "KPTI esta deshabilitado"
    else
        check_warn "No se pudo determinar estado de KPTI"
    fi
elif grep -q "Mitigation: PTI" /sys/devices/system/cpu/vulnerabilities/meltdown 2>/dev/null; then
    check_pass "KPTI/PTI mitigacion activa (Meltdown)"
elif grep -q "Not affected" /sys/devices/system/cpu/vulnerabilities/meltdown 2>/dev/null; then
    check_pass "CPU no afectada por Meltdown"
else
    check_warn "No se pudo verificar KPTI/PTI"
fi

# --- Retpoline ---
echo ""
echo -e "${CYAN}── Retpoline (Spectre v2 Mitigation) ─────────────────${NC}"
if [[ -f /sys/devices/system/cpu/vulnerabilities/spectre_v2 ]]; then
    SPECTRE_V2=$(cat /sys/devices/system/cpu/vulnerabilities/spectre_v2 2>/dev/null)
    if echo "$SPECTRE_V2" | grep -qi "retpoline\|IBRS\|IBPB\|Mitigation"; then
        check_pass "Mitigacion Spectre v2 activa: $SPECTRE_V2"
    elif echo "$SPECTRE_V2" | grep -qi "Not affected"; then
        check_pass "CPU no afectada por Spectre v2"
    else
        check_fail "Spectre v2 vulnerable: $SPECTRE_V2"
    fi
else
    check_warn "No se pudo verificar mitigacion Spectre v2"
fi

# --- Lockdown mode ---
echo ""
echo -e "${CYAN}── Kernel Lockdown Mode ───────────────────────────────${NC}"
if [[ -f /sys/kernel/security/lockdown ]]; then
    LOCKDOWN=$(cat /sys/kernel/security/lockdown 2>/dev/null)
    if echo "$LOCKDOWN" | grep -q "\[integrity\]"; then
        check_pass "Lockdown modo: integrity"
    elif echo "$LOCKDOWN" | grep -q "\[confidentiality\]"; then
        check_pass "Lockdown modo: confidentiality (maximo)"
    elif echo "$LOCKDOWN" | grep -q "\[none\]"; then
        check_fail "Lockdown deshabilitado"
    else
        check_info "Lockdown estado: $LOCKDOWN"
    fi
else
    check_warn "Kernel lockdown no disponible (kernel >= 5.4 requerido)"
fi

# --- Secure Boot ---
echo ""
echo -e "${CYAN}── Secure Boot ────────────────────────────────────────${NC}"
if command -v mokutil &>/dev/null; then
    SB_STATE=$(mokutil --sb-state 2>/dev/null || echo "unknown")
    if echo "$SB_STATE" | grep -qi "SecureBoot enabled"; then
        check_pass "Secure Boot habilitado"
    elif echo "$SB_STATE" | grep -qi "SecureBoot disabled"; then
        check_fail "Secure Boot deshabilitado"
    else
        check_info "Secure Boot estado: $SB_STATE"
    fi
elif [[ -d /sys/firmware/efi ]]; then
    if [[ -f /sys/firmware/efi/efivars/SecureBoot-* ]] 2>/dev/null; then
        check_info "Sistema UEFI detectado - instalar mokutil para verificar Secure Boot"
    else
        check_warn "UEFI presente pero no se puede verificar Secure Boot"
    fi
else
    check_info "Sistema BIOS (legacy) - Secure Boot no aplicable"
fi

# --- Kernel taint ---
echo ""
echo -e "${CYAN}── Kernel Taint ───────────────────────────────────────${NC}"
if [[ -f /proc/sys/kernel/tainted ]]; then
    TAINT=$(cat /proc/sys/kernel/tainted)
    if [[ "$TAINT" == "0" ]]; then
        check_pass "Kernel no esta contaminado (taint=0)"
    else
        check_warn "Kernel contaminado (taint=$TAINT)"
        # Decodificar flags
        [[ $((TAINT & 1)) -ne 0 ]] && check_info "  Bit 0: modulo propietario cargado"
        [[ $((TAINT & 2)) -ne 0 ]] && check_info "  Bit 1: modulo forzado a cargar"
        [[ $((TAINT & 4)) -ne 0 ]] && check_info "  Bit 2: CPU SMP con hardware no seguro"
        [[ $((TAINT & 8)) -ne 0 ]] && check_info "  Bit 3: modulo fuera del arbol"
        [[ $((TAINT & 16)) -ne 0 ]] && check_info "  Bit 4: staging driver cargado"
        [[ $((TAINT & 32)) -ne 0 ]] && check_info "  Bit 5: ACPI override"
        [[ $((TAINT & 64)) -ne 0 ]] && check_info "  Bit 6: modulo sin firma valida"
        [[ $((TAINT & 128)) -ne 0 ]] && check_warn "  Bit 7: firmware workaround aplicado"
        [[ $((TAINT & 256)) -ne 0 ]] && check_info "  Bit 8: debugging framework activo"
        [[ $((TAINT & 512)) -ne 0 ]] && check_warn "  Bit 9: WARN detectado"
        [[ $((TAINT & 1024)) -ne 0 ]] && check_fail "  Bit 10: BUG detectado"
        [[ $((TAINT & 4096)) -ne 0 ]] && check_fail "  Bit 12: OOPS detectado"
        [[ $((TAINT & 8192)) -ne 0 ]] && check_warn "  Bit 13: firmware sin firma"
        [[ $((TAINT & 16384)) -ne 0 ]] && check_warn "  Bit 14: modulo soft-lockup"
        [[ $((TAINT & 32768)) -ne 0 ]] && check_warn "  Bit 15: live patch activo"
    fi
fi

# --- Modulos cargados ---
echo ""
echo -e "${CYAN}── Modulos del Kernel ─────────────────────────────────${NC}"
MOD_COUNT=$(lsmod | wc -l)
((MOD_COUNT--)) || true  # Restar cabecera
check_info "Modulos cargados: $MOD_COUNT"
if [[ "$MOD_COUNT" -lt 50 ]]; then
    check_pass "Cantidad de modulos razonable (<50)"
elif [[ "$MOD_COUNT" -lt 100 ]]; then
    check_warn "Cantidad moderada de modulos ($MOD_COUNT)"
else
    check_warn "Alta cantidad de modulos cargados ($MOD_COUNT) - revisar necesidad"
fi

# --- Parametros de seguridad ---
echo ""
echo -e "${CYAN}── Parametros de Seguridad del Kernel ─────────────────${NC}"

check_sysctl() {
    local param="$1"
    local expected="$2"
    local desc="$3"
    local actual
    actual=$(sysctl -n "$param" 2>/dev/null || echo "N/A")
    if [[ "$actual" == "$expected" ]]; then
        check_pass "$desc ($param = $actual)"
    elif [[ "$actual" == "N/A" ]]; then
        check_warn "$desc ($param no disponible)"
    else
        check_fail "$desc ($param = $actual, esperado: $expected)"
    fi
}

check_sysctl "kernel.kptr_restrict" "2" "Ocultar punteros del kernel"
check_sysctl "kernel.dmesg_restrict" "1" "Restringir dmesg a root"
check_sysctl "kernel.perf_event_paranoid" "3" "Restringir perf_event"
check_sysctl "kernel.yama.ptrace_scope" "2" "Restringir ptrace"
check_sysctl "kernel.unprivileged_bpf_disabled" "1" "Deshabilitar BPF sin privilegios"
check_sysctl "kernel.kexec_load_disabled" "1" "Deshabilitar kexec"
check_sysctl "vm.mmap_min_addr" "65536" "Direccion minima mmap"
check_sysctl "kernel.sysrq" "0" "Deshabilitar SysRq"
check_sysctl "fs.protected_hardlinks" "1" "Proteger hardlinks"
check_sysctl "fs.protected_symlinks" "1" "Proteger symlinks"
check_sysctl "fs.protected_fifos" "2" "Proteger FIFOs"
check_sysctl "fs.protected_regular" "2" "Proteger archivos regulares"

# --- Vulnerabilidades CPU ---
echo ""
echo -e "${CYAN}── Vulnerabilidades CPU ───────────────────────────────${NC}"
if [[ -d /sys/devices/system/cpu/vulnerabilities ]]; then
    for vuln_file in /sys/devices/system/cpu/vulnerabilities/*; do
        vuln_name=$(basename "$vuln_file")
        vuln_status=$(cat "$vuln_file" 2>/dev/null || echo "unknown")
        if echo "$vuln_status" | grep -qi "not affected"; then
            check_pass "$vuln_name: No afectado"
        elif echo "$vuln_status" | grep -qi "mitigation"; then
            check_pass "$vuln_name: Mitigado ($vuln_status)"
        elif echo "$vuln_status" | grep -qi "vulnerable"; then
            check_fail "$vuln_name: VULNERABLE ($vuln_status)"
        else
            check_info "$vuln_name: $vuln_status"
        fi
    done
else
    check_warn "Directorio de vulnerabilidades CPU no disponible"
fi

# --- Resultado final ---
echo ""
echo "════════════════════════════════════════════════════════════"
if [[ $MAX_SCORE -gt 0 ]]; then
    PERCENTAGE=$(( (SCORE * 100) / MAX_SCORE ))
else
    PERCENTAGE=0
fi

echo -e "${BOLD}Puntuacion de Seguridad del Kernel:${NC} $SCORE / $MAX_SCORE ($PERCENTAGE%)"
echo ""

if [[ $PERCENTAGE -ge 80 ]]; then
    echo -e "${GREEN}${BOLD}RESULTADO: BUENO${NC} - El kernel tiene una postura de seguridad solida"
elif [[ $PERCENTAGE -ge 50 ]]; then
    echo -e "${YELLOW}${BOLD}RESULTADO: MEJORABLE${NC} - Hay areas de mejora en la seguridad del kernel"
else
    echo -e "${RED}${BOLD}RESULTADO: DEFICIENTE${NC} - Se requiere atencion urgente"
fi

if [[ ${#ISSUES[@]} -gt 0 ]]; then
    echo ""
    echo -e "${RED}Problemas detectados:${NC}"
    for issue in "${ISSUES[@]}"; do
        echo "  - $issue"
    done
fi

echo ""
echo "Fecha del informe: $(date '+%Y-%m-%d %H:%M:%S')"

# Guardar JSON
LOG_DIR="/var/log/securizar"
mkdir -p "$LOG_DIR"
cat > "$LOG_DIR/kernel-audit.json" << EOFJSON
{
  "timestamp": "$(date -Iseconds)",
  "kernel_version": "$(uname -r)",
  "architecture": "$(uname -m)",
  "hostname": "$(hostname)",
  "score": $SCORE,
  "max_score": $MAX_SCORE,
  "percentage": $PERCENTAGE,
  "issues_count": ${#ISSUES[@]}
}
EOFJSON

echo "Informe guardado en: $LOG_DIR/kernel-audit.json"
EOFAUDITKERNEL

    chmod +x /usr/local/bin/auditar-kernel.sh
    log_change "Creado" "/usr/local/bin/auditar-kernel.sh"

    # Ejecutar auditoria inicial
    log_info "Ejecutando auditoria rapida del kernel actual..."
    echo ""
    echo "  Kernel:     $KERNEL_VERSION"
    echo "  Arch:       $(uname -m)"
    echo "  Taint:      $(cat /proc/sys/kernel/tainted 2>/dev/null || echo 'N/A')"
    echo "  Modulos:    $(lsmod | wc -l) cargados"
    echo ""
    log_info "Ejecuta 'auditar-kernel.sh' para auditoria completa"
else
    log_skip "Auditoria de seguridad del kernel"
fi

# ============================================================
# S2: CONFIGURACION DE LIVE PATCHING
# ============================================================
log_section "S2: CONFIGURACION DE LIVE PATCHING"

echo "Instala y configura el framework de live patching apropiado:"
echo "  - RHEL/SUSE: kpatch / kGraft"
echo "  - Debian/Ubuntu: canonical-livepatch / kpatch"
echo "  - Habilita servicio de live patching"
echo "  - Crea configuracion en /etc/securizar/livepatch.conf"
echo ""

if check_file_exists /etc/securizar/livepatch.conf; then
    log_already "Live patching del kernel (livepatch.conf existe)"
elif ask "¿Configurar live patching del kernel?"; then

    LIVEPATCH_METHOD="none"
    LIVEPATCH_SERVICE="none"

    case "$DISTRO_FAMILY" in
        rhel)
            log_info "Familia RHEL detectada - configurando kpatch..."
            if pkg_install kpatch; then
                LIVEPATCH_METHOD="kpatch"
                LIVEPATCH_SERVICE="kpatch"
                log_change "Instalado" "kpatch para live patching"
            else
                log_warn "No se pudo instalar kpatch"
            fi

            # Verificar si kpatch-dnf esta disponible
            if command -v dnf &>/dev/null; then
                if dnf list kpatch-dnf 2>/dev/null | grep -q kpatch-dnf; then
                    dnf install -y kpatch-dnf 2>/dev/null || true
                    log_info "kpatch-dnf instalado para parches automaticos"
                fi
            fi
            ;;
        suse)
            log_info "Familia SUSE detectada - configurando kGraft/kpatch..."
            # SUSE usa kGraft o kpatch segun version
            if zypper --non-interactive install kgraft-patch 2>/dev/null; then
                LIVEPATCH_METHOD="kgraft"
                LIVEPATCH_SERVICE="kgraftd"
                log_change "Instalado" "kGraft para live patching"
            elif pkg_install kpatch; then
                LIVEPATCH_METHOD="kpatch"
                LIVEPATCH_SERVICE="kpatch"
                log_change "Instalado" "kpatch para live patching (fallback)"
            else
                log_warn "No se pudo instalar kGraft ni kpatch"
                # Intentar SLE Live Patching
                if zypper --non-interactive install kernel-livepatch-tools 2>/dev/null; then
                    LIVEPATCH_METHOD="sle-livepatch"
                    LIVEPATCH_SERVICE="klp"
                    log_change "Instalado" "SLE Live Patching tools"
                fi
            fi
            ;;
        debian)
            log_info "Familia Debian detectada..."
            # Ubuntu tiene canonical-livepatch
            if [[ -f /etc/os-release ]] && grep -qi "ubuntu" /etc/os-release; then
                log_info "Ubuntu detectado - verificando canonical-livepatch..."
                if command -v canonical-livepatch &>/dev/null; then
                    LIVEPATCH_METHOD="canonical-livepatch"
                    LIVEPATCH_SERVICE="canonical-livepatch"
                    log_info "canonical-livepatch ya instalado"
                elif snap list 2>/dev/null | grep -q canonical-livepatch; then
                    LIVEPATCH_METHOD="canonical-livepatch"
                    LIVEPATCH_SERVICE="snap.canonical-livepatch.canonical-livepatchd"
                    log_info "canonical-livepatch instalado via snap"
                else
                    if command -v snap &>/dev/null; then
                        snap install canonical-livepatch 2>/dev/null || true
                        if command -v canonical-livepatch &>/dev/null; then
                            LIVEPATCH_METHOD="canonical-livepatch"
                            LIVEPATCH_SERVICE="snap.canonical-livepatch.canonical-livepatchd"
                            log_change "Instalado" "canonical-livepatch via snap"
                        fi
                    fi
                fi
                if [[ "$LIVEPATCH_METHOD" == "canonical-livepatch" ]]; then
                    log_info "Para activar: canonical-livepatch enable <TOKEN>"
                    log_info "Obtener token en: https://ubuntu.com/security/livepatch"
                fi
            fi

            # Fallback a kpatch para Debian
            if [[ "$LIVEPATCH_METHOD" == "none" ]]; then
                log_info "Intentando instalar kpatch..."
                if pkg_install kpatch; then
                    LIVEPATCH_METHOD="kpatch"
                    LIVEPATCH_SERVICE="kpatch"
                    log_change "Instalado" "kpatch para live patching"
                else
                    log_warn "No se pudo instalar kpatch"
                fi
            fi
            ;;
        arch)
            log_info "Familia Arch detectada..."
            log_warn "Live patching en Arch Linux requiere kernel personalizado"
            log_info "Opciones: kpatch desde AUR o kernel con CONFIG_LIVEPATCH=y"
            if command -v yay &>/dev/null; then
                log_info "Puedes instalar: yay -S kpatch-git"
            elif command -v paru &>/dev/null; then
                log_info "Puedes instalar: paru -S kpatch-git"
            fi
            LIVEPATCH_METHOD="manual"
            ;;
    esac

    # Verificar soporte de livepatch en kernel
    if [[ -f /sys/kernel/livepatch ]]; then
        log_info "Kernel soporta CONFIG_LIVEPATCH"
    elif [[ -d /sys/kernel/livepatch ]]; then
        log_info "Directorio livepatch del kernel presente"
    else
        KCONFIG="/boot/config-$(uname -r)"
        if [[ -f "$KCONFIG" ]]; then
            if grep -q "CONFIG_LIVEPATCH=y" "$KCONFIG"; then
                log_info "CONFIG_LIVEPATCH=y en configuracion del kernel"
            else
                log_warn "CONFIG_LIVEPATCH no habilitado en el kernel actual"
                log_warn "Live patching requiere recompilar kernel con CONFIG_LIVEPATCH=y"
            fi
        elif [[ -f /proc/config.gz ]]; then
            if zcat /proc/config.gz 2>/dev/null | grep -q "CONFIG_LIVEPATCH=y"; then
                log_info "CONFIG_LIVEPATCH=y verificado via /proc/config.gz"
            else
                log_warn "CONFIG_LIVEPATCH no habilitado en el kernel actual"
            fi
        fi
    fi

    # Habilitar servicio si corresponde
    if [[ "$LIVEPATCH_SERVICE" != "none" ]]; then
        if systemctl is-active "$LIVEPATCH_SERVICE" &>/dev/null; then
            log_info "Servicio $LIVEPATCH_SERVICE ya esta activo"
        else
            systemctl enable "$LIVEPATCH_SERVICE" 2>/dev/null || true
            systemctl start "$LIVEPATCH_SERVICE" 2>/dev/null || true
            if systemctl is-active "$LIVEPATCH_SERVICE" &>/dev/null; then
                log_change "Habilitado" "servicio $LIVEPATCH_SERVICE"
            else
                log_warn "No se pudo iniciar servicio $LIVEPATCH_SERVICE"
            fi
        fi
    fi

    # Verificar estado operativo
    case "$LIVEPATCH_METHOD" in
        kpatch)
            if command -v kpatch &>/dev/null; then
                KPATCH_LOADED=$(kpatch list 2>/dev/null || echo "sin parches")
                log_info "kpatch parches: $KPATCH_LOADED"
            fi
            ;;
        canonical-livepatch)
            if command -v canonical-livepatch &>/dev/null; then
                CLP_STATUS=$(canonical-livepatch status 2>/dev/null || echo "no configurado")
                log_info "canonical-livepatch estado: $CLP_STATUS"
            fi
            ;;
        kgraft)
            if [[ -d /sys/kernel/livepatch ]]; then
                log_info "kGraft modulos activos: $(ls /sys/kernel/livepatch/ 2>/dev/null || echo 'ninguno')"
            fi
            ;;
    esac

    # Crear configuracion
    cat > /etc/securizar/livepatch.conf << EOFLIVEPATCH
# ============================================================
# livepatch.conf - Configuracion de live patching del kernel
# Generado por securizar - Modulo 47
# Fecha: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================

# Metodo de live patching detectado
LIVEPATCH_METHOD="$LIVEPATCH_METHOD"

# Servicio asociado
LIVEPATCH_SERVICE="$LIVEPATCH_SERVICE"

# Kernel al momento de configuracion
LIVEPATCH_KERNEL="$KERNEL_VERSION"

# Verificar parches automaticamente (cron)
LIVEPATCH_AUTO_CHECK="yes"

# Intervalo de verificacion (horas)
LIVEPATCH_CHECK_INTERVAL="6"

# Notificar nuevos parches por correo
LIVEPATCH_NOTIFY_EMAIL=""

# Aplicar parches automaticamente
LIVEPATCH_AUTO_APPLY="no"

# Log de actividad
LIVEPATCH_LOG="/var/log/securizar/livepatch.log"
EOFLIVEPATCH

    chmod 600 /etc/securizar/livepatch.conf
    log_change "Creado" "/etc/securizar/livepatch.conf"
    log_info "Metodo de live patching: $LIVEPATCH_METHOD"

else
    log_skip "Configuracion de live patching"
fi

# ============================================================
# S3: MITIGACION DE EXPLOITS VIA SYSCTL
# ============================================================
log_section "S3: MITIGACION DE EXPLOITS VIA SYSCTL"

echo "Crea /etc/sysctl.d/99-securizar-kernel-exploit.conf con:"
echo "  - KASLR enforcement, kptr_restrict=2"
echo "  - dmesg_restrict=1, perf_event_paranoid=3"
echo "  - yama.ptrace_scope=2, unprivileged_bpf_disabled=1"
echo "  - kexec_load_disabled=1, mmap_min_addr=65536"
echo "  - unprivileged_userfaultfd=0, sysrq=0"
echo "  - protected_hardlinks/symlinks/fifos/regular"
echo ""

if check_file_exists /etc/sysctl.d/99-securizar-kernel-exploit.conf; then
    log_already "Mitigaciones sysctl (99-securizar-kernel-exploit.conf existe)"
elif ask "¿Aplicar mitigaciones de exploits del kernel via sysctl?"; then

    # Backup de configuracion existente
    if [[ -f /etc/sysctl.d/99-securizar-kernel-exploit.conf ]]; then
        cp /etc/sysctl.d/99-securizar-kernel-exploit.conf "$BACKUP_DIR/"
        log_change "Backup" "/etc/sysctl.d/99-securizar-kernel-exploit.conf"
    fi

    # Backup de valores actuales
    log_info "Valores actuales de seguridad del kernel:"
    for param in kernel.kptr_restrict kernel.dmesg_restrict kernel.perf_event_paranoid \
                 kernel.yama.ptrace_scope kernel.unprivileged_bpf_disabled kernel.kexec_load_disabled \
                 vm.mmap_min_addr vm.unprivileged_userfaultfd kernel.sysrq \
                 fs.protected_hardlinks fs.protected_symlinks fs.protected_fifos fs.protected_regular; do
        current=$(sysctl -n "$param" 2>/dev/null || echo "N/A")
        echo "  $param = $current"
    done
    echo ""

    cat > /etc/sysctl.d/99-securizar-kernel-exploit.conf << 'EOFSYSCTL'
# ============================================================
# 99-securizar-kernel-exploit.conf
# Hardening del kernel contra exploits - Generado por securizar
# Modulo 47 - Kernel Live Patching y Mitigacion de Exploits
# ============================================================

# ── KASLR y ocultacion de punteros ────────────────────────
# Ocultar punteros del kernel a procesos sin privilegios
# 0=sin restriccion, 1=ocultar a no-root, 2=ocultar a todos
kernel.kptr_restrict = 2

# ── Restriccion de acceso a dmesg ─────────────────────────
# Solo root puede leer el log del kernel
kernel.dmesg_restrict = 1

# ── Restriccion de perf_event ─────────────────────────────
# 3=denegar a todos los usuarios no-root (mas restrictivo)
kernel.perf_event_paranoid = 3

# ── YAMA ptrace scope ────────────────────────────────────
# 0=sin restriccion, 1=solo padre, 2=solo admin, 3=nadie
# 2=solo procesos con CAP_SYS_PTRACE pueden usar ptrace
kernel.yama.ptrace_scope = 2

# ── BPF sin privilegios ──────────────────────────────────
# Deshabilitar bpf() para usuarios sin privilegios
kernel.unprivileged_bpf_disabled = 1

# ── JIT hardening para BPF ────────────────────────────────
# Endurecer JIT compiler de BPF
net.core.bpf_jit_harden = 2

# ── Deshabilitar kexec ────────────────────────────────────
# Prevenir carga de kernel alternativo (bypass de Secure Boot)
kernel.kexec_load_disabled = 1

# ── Direccion minima de mmap ──────────────────────────────
# Prevenir exploits de null pointer dereference
vm.mmap_min_addr = 65536

# ── Userfaultfd sin privilegios ───────────────────────────
# Deshabilitar userfaultfd para no-root (usado en exploits UAF)
vm.unprivileged_userfaultfd = 0

# ── SysRq ─────────────────────────────────────────────────
# 0=deshabilitar completamente, 1=todo habilitado
# Alternativa segura: 176 = sync + reboot + remount-ro
kernel.sysrq = 0

# ── Proteccion de enlaces ────────────────────────────────
# Proteger contra ataques via hardlinks
fs.protected_hardlinks = 1

# Proteger contra ataques via symlinks
fs.protected_symlinks = 1

# Proteger contra ataques via FIFOs en directorios sticky
# 2=solo propietario o root pueden acceder
fs.protected_fifos = 2

# Proteger archivos regulares en directorios sticky
fs.protected_regular = 2

# ── Core dumps ────────────────────────────────────────────
# No crear core dumps con SUID
fs.suid_dumpable = 0

# ── Restriccion de user namespaces ────────────────────────
# Limitar user namespaces (muchos exploits los usan)
# Comentado por defecto - descomentar si no se usan contenedores
# user.max_user_namespaces = 0

# ── Randomizacion de espacio de direcciones ───────────────
# 2=randomizar stack, mmap, VDSO, heap
kernel.randomize_va_space = 2

# ── Panic en oops ─────────────────────────────────────────
# Reiniciar en caso de kernel oops (puede indicar ataque)
kernel.panic_on_oops = 1
kernel.panic = 60

# ── Restringir acceso a logs de auditoria ─────────────────
# Solo procesos con CAP_AUDIT_READ pueden leer logs
kernel.modules_disabled = 0
EOFSYSCTL

    log_change "Creado" "/etc/sysctl.d/99-securizar-kernel-exploit.conf"

    # Aplicar parametros
    log_info "Aplicando parametros de seguridad..."
    SYSCTL_ERRORS=0
    while IFS= read -r line; do
        # Saltar comentarios y lineas vacias
        [[ -z "$line" || "$line" == \#* ]] && continue
        param_name=$(echo "$line" | cut -d= -f1 | tr -d ' ')
        if sysctl -w "$line" &>/dev/null; then
            log_info "  Aplicado: $param_name"
        else
            log_warn "  No se pudo aplicar: $param_name (puede no existir en este kernel)"
            ((SYSCTL_ERRORS++)) || true
        fi
    done < <(grep -v '^\s*#' /etc/sysctl.d/99-securizar-kernel-exploit.conf | grep -v '^\s*$')

    if [[ $SYSCTL_ERRORS -gt 0 ]]; then
        log_warn "$SYSCTL_ERRORS parametros no se pudieron aplicar (normal si el kernel no los soporta)"
    fi

    log_change "Aplicado" "mitigaciones de exploits via sysctl ($(($(grep -c '=' /etc/sysctl.d/99-securizar-kernel-exploit.conf) - SYSCTL_ERRORS)) parametros)"
    log_info "Los parametros persisten tras reinicio via /etc/sysctl.d/"

else
    log_skip "Mitigaciones de exploits via sysctl"
fi

# ============================================================
# S4: HARDENING DE MODULOS DEL KERNEL
# ============================================================
log_section "S4: HARDENING DE MODULOS DEL KERNEL"

echo "Crea /etc/modprobe.d/securizar-blacklist.conf:"
echo "  - Blacklist modulos peligrosos: firewire, thunderbolt"
echo "  - Filesystems raramente usados: cramfs, freevxfs, jffs2, hfs, etc."
echo "  - Protocolos de red innecesarios: dccp, sctp, rds, tipc"
echo "  - USB storage (opcional)"
echo "  - Opcion de bloquear carga de modulos"
echo ""

if check_file_exists /etc/modprobe.d/securizar-blacklist.conf; then
    log_already "Hardening de modulos (securizar-blacklist.conf existe)"
elif ask "¿Aplicar hardening de modulos del kernel?"; then

    # Backup
    if [[ -f /etc/modprobe.d/securizar-blacklist.conf ]]; then
        cp /etc/modprobe.d/securizar-blacklist.conf "$BACKUP_DIR/"
        log_change "Backup" "/etc/modprobe.d/securizar-blacklist.conf"
    fi

    # Listar modulos peligrosos actualmente cargados
    log_info "Verificando modulos peligrosos actualmente cargados..."
    DANGEROUS_LOADED=()
    for mod in firewire-core firewire-ohci firewire-sbp2 thunderbolt \
               cramfs freevxfs jffs2 hfs hfsplus squashfs udf \
               dccp sctp rds tipc usb-storage; do
        if lsmod | grep -q "^${mod//-/_}"; then
            DANGEROUS_LOADED+=("$mod")
            log_warn "  Modulo peligroso cargado: $mod"
        fi
    done
    if [[ ${#DANGEROUS_LOADED[@]} -eq 0 ]]; then
        log_info "  Ningun modulo peligroso detectado cargado"
    fi

    # Preguntar sobre USB storage
    BLACKLIST_USB="no"
    if ask "¿Bloquear modulo usb-storage? (impide uso de USBs de almacenamiento)"; then
        BLACKLIST_USB="yes"
    fi

    cat > /etc/modprobe.d/securizar-blacklist.conf << 'EOFBLACKLIST'
# ============================================================
# securizar-blacklist.conf - Blacklist de modulos peligrosos
# Generado por securizar - Modulo 47
# ============================================================

# ── Firewire (DMA attacks) ────────────────────────────────
# FireWire permite acceso directo a memoria (DMA) desde
# dispositivos externos - vector de ataque conocido
install firewire-core /bin/true
install firewire-ohci /bin/true
install firewire-sbp2 /bin/true
install firewire-net /bin/true
blacklist firewire-core
blacklist firewire-ohci
blacklist firewire-sbp2
blacklist firewire-net

# ── Thunderbolt (DMA attacks) ────────────────────────────
# Thunderbolt tambien permite DMA - vector de ataque
install thunderbolt /bin/true
blacklist thunderbolt

# ── Filesystems raramente usados ─────────────────────────
# Reducir superficie de ataque deshabilitando FS innecesarios
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
blacklist cramfs
blacklist freevxfs
blacklist jffs2
blacklist hfs
blacklist hfsplus
blacklist squashfs
blacklist udf

# ── Protocolos de red innecesarios ───────────────────────
# DCCP - Datagram Congestion Control Protocol (rara vez usado)
install dccp /bin/true
blacklist dccp

# SCTP - Stream Control Transmission Protocol
install sctp /bin/true
blacklist sctp

# RDS - Reliable Datagram Sockets (Oracle)
install rds /bin/true
blacklist rds

# TIPC - Transparent Inter Process Communication
install tipc /bin/true
blacklist tipc

# ── Otros modulos potencialmente peligrosos ──────────────
# Bluetooth (si no se usa)
# install bluetooth /bin/true
# blacklist bluetooth

# Network filesystems (si no se usan)
# install cifs /bin/true
# install nfs /bin/true
# install gfs2 /bin/true
EOFBLACKLIST

    # Agregar USB storage si se solicito
    if [[ "$BLACKLIST_USB" == "yes" ]]; then
        cat >> /etc/modprobe.d/securizar-blacklist.conf << 'EOFUSB'

# ── USB Storage ──────────────────────────────────────────
# Bloquear dispositivos de almacenamiento USB
# ADVERTENCIA: Esto impide el uso de pendrives y discos USB
install usb-storage /bin/true
blacklist usb-storage
EOFUSB
        log_change "Blacklisted" "usb-storage (almacenamiento USB bloqueado)"
    fi

    log_change "Creado" "/etc/modprobe.d/securizar-blacklist.conf"

    # Descargar modulos peligrosos actualmente cargados
    for mod in "${DANGEROUS_LOADED[@]}"; do
        if [[ "$mod" == "usb-storage" && "$BLACKLIST_USB" != "yes" ]]; then
            continue
        fi
        log_info "Intentando descargar modulo: $mod"
        modprobe -r "$mod" 2>/dev/null || log_warn "No se pudo descargar $mod (puede estar en uso)"
    done

    # Opcion de bloquear carga de modulos
    echo ""
    echo "ADVERTENCIA: Bloquear la carga de nuevos modulos impide cargar"
    echo "cualquier modulo nuevo. Solo recomendado para servidores con"
    echo "hardware bien definido. Es IRREVERSIBLE hasta reinicio."
    echo ""
    if ask "¿Bloquear carga de nuevos modulos del kernel? (AVANZADO)"; then
        echo "1" > /proc/sys/kernel/modules_disabled
        log_change "Bloqueado" "carga de nuevos modulos (kernel.modules_disabled=1)"
        log_warn "Carga de modulos bloqueada hasta el proximo reinicio"
    else
        log_skip "Bloqueo de carga de modulos"
    fi

    # Verificar firma de modulos
    if [[ -f /proc/sys/kernel/modules_disabled ]]; then
        log_info "kernel.modules_disabled = $(cat /proc/sys/kernel/modules_disabled)"
    fi

    KCONFIG="/boot/config-$(uname -r)"
    if [[ -f "$KCONFIG" ]]; then
        if grep -q "CONFIG_MODULE_SIG=y" "$KCONFIG"; then
            log_info "Firma de modulos habilitada en kernel (CONFIG_MODULE_SIG=y)"
            if grep -q "CONFIG_MODULE_SIG_FORCE=y" "$KCONFIG"; then
                log_info "Firma de modulos es OBLIGATORIA (CONFIG_MODULE_SIG_FORCE=y)"
            else
                log_warn "Firma de modulos no es obligatoria (CONFIG_MODULE_SIG_FORCE no habilitado)"
            fi
        else
            log_warn "Firma de modulos NO habilitada en kernel"
        fi
    fi

    # Actualizar initramfs para que blacklist surta efecto
    log_info "Actualizando initramfs..."
    case "$DISTRO_FAMILY" in
        suse)
            dracut -f 2>/dev/null && log_change "Actualizado" "initramfs (dracut)" || log_warn "No se pudo actualizar initramfs"
            ;;
        debian)
            update-initramfs -u 2>/dev/null && log_change "Actualizado" "initramfs (update-initramfs)" || log_warn "No se pudo actualizar initramfs"
            ;;
        rhel)
            dracut -f 2>/dev/null && log_change "Actualizado" "initramfs (dracut)" || log_warn "No se pudo actualizar initramfs"
            ;;
        arch)
            mkinitcpio -P 2>/dev/null && log_change "Actualizado" "initramfs (mkinitcpio)" || log_warn "No se pudo actualizar initramfs"
            ;;
    esac

    log_info "Blacklist de modulos aplicada. Efectiva tras reinicio."

else
    log_skip "Hardening de modulos del kernel"
fi

# ============================================================
# S5: VALIDACION DE PARAMETROS DEL KERNEL
# ============================================================
log_section "S5: VALIDACION DE PARAMETROS DEL KERNEL"

echo "Crea herramientas de validacion de parametros:"
echo "  - /etc/securizar/kernel-baseline.conf - linea base de seguridad"
echo "  - /usr/local/bin/validar-kernel-params.sh - validador con deteccion de drift"
echo "  - Soporte de auto-remediacion"
echo ""

if check_executable /usr/local/bin/validar-kernel-params.sh; then
    log_already "Validacion de parametros del kernel (validar-kernel-params.sh existe)"
elif ask "¿Crear sistema de validacion de parametros del kernel?"; then

    # Crear baseline de parametros
    cat > /etc/securizar/kernel-baseline.conf << 'EOFBASELINE'
# ============================================================
# kernel-baseline.conf - Linea base de seguridad del kernel
# Generado por securizar - Modulo 47
# ============================================================
# Formato: parametro=valor_esperado
# Lineas que empiezan con # son comentarios
# Prefijo ! indica parametro critico (fallo = error)
# ============================================================

# ── Parametros criticos (!) ───────────────────────────────
!kernel.kptr_restrict=2
!kernel.dmesg_restrict=1
!kernel.yama.ptrace_scope=2
!kernel.unprivileged_bpf_disabled=1
!kernel.kexec_load_disabled=1
!fs.protected_hardlinks=1
!fs.protected_symlinks=1
!kernel.randomize_va_space=2
!fs.suid_dumpable=0

# ── Parametros importantes ────────────────────────────────
kernel.perf_event_paranoid=3
vm.mmap_min_addr=65536
vm.unprivileged_userfaultfd=0
kernel.sysrq=0
fs.protected_fifos=2
fs.protected_regular=2
net.core.bpf_jit_harden=2
kernel.panic_on_oops=1
kernel.panic=60

# ── Parametros de red (hardening) ─────────────────────────
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.tcp_syncookies=1
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.default.accept_source_route=0
EOFBASELINE

    chmod 600 /etc/securizar/kernel-baseline.conf
    log_change "Creado" "/etc/securizar/kernel-baseline.conf"

    # Crear script validador
    cat > /usr/local/bin/validar-kernel-params.sh << 'EOFVALIDAR'
#!/bin/bash
# ============================================================
# validar-kernel-params.sh - Validador de parametros del kernel
# Generado por securizar - Modulo 47
# ============================================================
set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

BASELINE="/etc/securizar/kernel-baseline.conf"
REMEDIATE=0
VERBOSE=0
TOTAL=0
PASS=0
FAIL=0
CRITICAL_FAIL=0
DRIFT_PARAMS=()

usage() {
    echo "Uso: $0 [opciones]"
    echo ""
    echo "Opciones:"
    echo "  -r, --remediate    Auto-remediar parametros no conformes"
    echo "  -b, --baseline F   Usar archivo baseline alternativo"
    echo "  -v, --verbose      Mostrar todos los parametros (incluido PASS)"
    echo "  -q, --quiet        Solo mostrar fallos"
    echo "  -j, --json         Salida en formato JSON"
    echo "  -h, --help         Mostrar esta ayuda"
    exit 0
}

JSON_OUTPUT=0
QUIET=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        -r|--remediate) REMEDIATE=1 ;;
        -b|--baseline) BASELINE="$2"; shift ;;
        -v|--verbose) VERBOSE=1 ;;
        -q|--quiet) QUIET=1 ;;
        -j|--json) JSON_OUTPUT=1 ;;
        -h|--help) usage ;;
        *) echo "Opcion desconocida: $1"; usage ;;
    esac
    shift
done

if [[ ! -f "$BASELINE" ]]; then
    echo -e "${RED}Error: archivo baseline no encontrado: $BASELINE${NC}" >&2
    exit 1
fi

if [[ $JSON_OUTPUT -eq 0 && $QUIET -eq 0 ]]; then
    echo ""
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║   VALIDACION DE PARAMETROS DEL KERNEL                    ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo ""
    echo -e "${BOLD}Baseline:${NC}  $BASELINE"
    echo -e "${BOLD}Kernel:${NC}    $(uname -r)"
    echo -e "${BOLD}Fecha:${NC}     $(date '+%Y-%m-%d %H:%M:%S')"
    if [[ $REMEDIATE -eq 1 ]]; then
        echo -e "${YELLOW}Modo:      AUTO-REMEDIACION ACTIVA${NC}"
    fi
    echo ""
fi

JSON_ENTRIES=()

while IFS= read -r line; do
    # Saltar comentarios y vacias
    [[ -z "$line" || "$line" == \#* ]] && continue

    # Detectar parametro critico
    CRITICAL=0
    if [[ "$line" == !* ]]; then
        CRITICAL=1
        line="${line#!}"
    fi

    PARAM=$(echo "$line" | cut -d= -f1)
    EXPECTED=$(echo "$line" | cut -d= -f2-)
    ACTUAL=$(sysctl -n "$PARAM" 2>/dev/null || echo "N/A")

    ((TOTAL++)) || true

    if [[ "$ACTUAL" == "$EXPECTED" ]]; then
        ((PASS++)) || true
        if [[ $VERBOSE -eq 1 && $JSON_OUTPUT -eq 0 ]]; then
            echo -e "  ${GREEN}[OK]${NC}   $PARAM = $ACTUAL"
        fi
        if [[ $JSON_OUTPUT -eq 1 ]]; then
            JSON_ENTRIES+=("{\"param\":\"$PARAM\",\"expected\":\"$EXPECTED\",\"actual\":\"$ACTUAL\",\"status\":\"pass\",\"critical\":$CRITICAL}")
        fi
    elif [[ "$ACTUAL" == "N/A" ]]; then
        ((FAIL++)) || true
        if [[ $JSON_OUTPUT -eq 0 && $QUIET -eq 0 ]]; then
            echo -e "  ${YELLOW}[N/A]${NC}  $PARAM (no disponible en este kernel)"
        fi
        if [[ $JSON_OUTPUT -eq 1 ]]; then
            JSON_ENTRIES+=("{\"param\":\"$PARAM\",\"expected\":\"$EXPECTED\",\"actual\":\"N/A\",\"status\":\"unavailable\",\"critical\":$CRITICAL}")
        fi
    else
        ((FAIL++)) || true
        if [[ $CRITICAL -eq 1 ]]; then
            ((CRITICAL_FAIL++)) || true
            DRIFT_PARAMS+=("$PARAM")
            if [[ $JSON_OUTPUT -eq 0 ]]; then
                echo -e "  ${RED}[CRITICO]${NC} $PARAM = $ACTUAL (esperado: $EXPECTED)"
            fi
        else
            DRIFT_PARAMS+=("$PARAM")
            if [[ $JSON_OUTPUT -eq 0 ]]; then
                echo -e "  ${YELLOW}[DRIFT]${NC}  $PARAM = $ACTUAL (esperado: $EXPECTED)"
            fi
        fi
        if [[ $JSON_OUTPUT -eq 1 ]]; then
            status_str="drift"
            [[ $CRITICAL -eq 1 ]] && status_str="critical_drift"
            JSON_ENTRIES+=("{\"param\":\"$PARAM\",\"expected\":\"$EXPECTED\",\"actual\":\"$ACTUAL\",\"status\":\"$status_str\",\"critical\":$CRITICAL}")
        fi

        # Auto-remediar si se solicito
        if [[ $REMEDIATE -eq 1 ]]; then
            if sysctl -w "${PARAM}=${EXPECTED}" &>/dev/null; then
                if [[ $JSON_OUTPUT -eq 0 ]]; then
                    echo -e "    ${GREEN}-> Remediado:${NC} $PARAM = $EXPECTED"
                fi
            else
                if [[ $JSON_OUTPUT -eq 0 ]]; then
                    echo -e "    ${RED}-> No se pudo remediar:${NC} $PARAM"
                fi
            fi
        fi
    fi
done < "$BASELINE"

if [[ $JSON_OUTPUT -eq 1 ]]; then
    echo "{"
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"kernel\": \"$(uname -r)\","
    echo "  \"baseline\": \"$BASELINE\","
    echo "  \"total\": $TOTAL,"
    echo "  \"pass\": $PASS,"
    echo "  \"fail\": $FAIL,"
    echo "  \"critical_fail\": $CRITICAL_FAIL,"
    echo "  \"remediated\": $REMEDIATE,"
    echo "  \"results\": ["
    first=1
    for entry in "${JSON_ENTRIES[@]}"; do
        [[ $first -eq 0 ]] && echo ","
        echo -n "    $entry"
        first=0
    done
    echo ""
    echo "  ]"
    echo "}"
else
    echo ""
    echo "════════════════════════════════════════════════════════════"
    echo -e "${BOLD}Resultado:${NC} $PASS/$TOTAL conformes"
    if [[ $FAIL -gt 0 ]]; then
        echo -e "${YELLOW}  Drift detectado: $FAIL parametros${NC}"
    fi
    if [[ $CRITICAL_FAIL -gt 0 ]]; then
        echo -e "${RED}  Fallos criticos: $CRITICAL_FAIL parametros${NC}"
    fi
    if [[ ${#DRIFT_PARAMS[@]} -gt 0 ]]; then
        echo ""
        echo -e "${BOLD}Parametros con drift:${NC}"
        for dp in "${DRIFT_PARAMS[@]}"; do
            echo "  - $dp"
        done
    fi
    if [[ $FAIL -eq 0 ]]; then
        echo -e "${GREEN}${BOLD}ESTADO: CONFORME${NC} - Todos los parametros cumplen la linea base"
    elif [[ $CRITICAL_FAIL -gt 0 ]]; then
        echo -e "${RED}${BOLD}ESTADO: NO CONFORME${NC} - Hay fallos criticos que requieren atencion"
    else
        echo -e "${YELLOW}${BOLD}ESTADO: DRIFT DETECTADO${NC} - Hay parametros fuera de linea base"
    fi
    echo ""
fi

# Guardar resultado en log
mkdir -p /var/log/securizar
echo "$(date -Iseconds) validacion: $PASS/$TOTAL conformes, $FAIL drift, $CRITICAL_FAIL criticos" >> /var/log/securizar/kernel-validation.log

exit $CRITICAL_FAIL
EOFVALIDAR

    chmod +x /usr/local/bin/validar-kernel-params.sh
    log_change "Creado" "/usr/local/bin/validar-kernel-params.sh"

    # Crear cron de validacion diaria
    cat > /etc/cron.daily/securizar-kernel-validate << 'EOFCRON'
#!/bin/bash
# Validacion diaria de parametros del kernel - securizar Modulo 47
/usr/local/bin/validar-kernel-params.sh -q >> /var/log/securizar/kernel-validation.log 2>&1
EOFCRON
    chmod +x /etc/cron.daily/securizar-kernel-validate
    log_change "Creado" "/etc/cron.daily/securizar-kernel-validate"

    # Ejecutar validacion inicial
    log_info "Ejecutando validacion inicial contra baseline..."
    /usr/local/bin/validar-kernel-params.sh -v 2>/dev/null || true

else
    log_skip "Validacion de parametros del kernel"
fi

# ============================================================
# S6: MONITORIZACION DE CVES DEL KERNEL
# ============================================================
log_section "S6: MONITORIZACION DE CVES DEL KERNEL"

echo "Crea /usr/local/bin/monitorizar-cves-kernel.sh:"
echo "  - Verifica kernel actual contra CVEs conocidos"
echo "  - Descarga base de datos de CVEs del kernel"
echo "  - Reporta: CVE ID, severidad, versiones afectadas"
echo "  - Salida en /var/log/securizar/kernel-cves.json"
echo ""

if check_executable /usr/local/bin/monitorizar-cves-kernel.sh; then
    log_already "Monitorizacion de CVEs del kernel (monitorizar-cves-kernel.sh existe)"
elif ask "¿Crear sistema de monitorizacion de CVEs del kernel?"; then

    cat > /usr/local/bin/monitorizar-cves-kernel.sh << 'EOFCVE'
#!/bin/bash
# ============================================================
# monitorizar-cves-kernel.sh - Monitor de CVEs del kernel
# Generado por securizar - Modulo 47
# ============================================================
set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

CVE_DB_DIR="/var/lib/securizar/cve-db"
CVE_OUTPUT="/var/log/securizar/kernel-cves.json"
KERNEL_VERSION=$(uname -r)
KERNEL_BASE=$(echo "$KERNEL_VERSION" | sed 's/-.*//')
LOG_DIR="/var/log/securizar"

mkdir -p "$CVE_DB_DIR" "$LOG_DIR"

usage() {
    echo "Uso: $0 [opciones]"
    echo ""
    echo "Opciones:"
    echo "  -u, --update     Actualizar base de datos de CVEs"
    echo "  -s, --scan       Escanear kernel actual (por defecto)"
    echo "  -k, --kernel V   Escanear version de kernel especifica"
    echo "  -v, --verbose    Salida detallada"
    echo "  -j, --json       Solo salida JSON"
    echo "  -h, --help       Mostrar esta ayuda"
    exit 0
}

UPDATE_DB=0
SCAN=1
VERBOSE=0
JSON_ONLY=0
TARGET_KERNEL="$KERNEL_VERSION"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -u|--update) UPDATE_DB=1 ;;
        -s|--scan) SCAN=1 ;;
        -k|--kernel) TARGET_KERNEL="$2"; shift ;;
        -v|--verbose) VERBOSE=1 ;;
        -j|--json) JSON_ONLY=1 ;;
        -h|--help) usage ;;
        *) echo "Opcion desconocida: $1"; usage ;;
    esac
    shift
done

# ── Funcion para comparar versiones ──────────────────────
version_compare() {
    # Retorna: 0 si v1==v2, 1 si v1>v2, 2 si v1<v2
    if [[ "$1" == "$2" ]]; then
        return 0
    fi
    local IFS=.
    local i v1=($1) v2=($2)
    for ((i=0; i<${#v1[@]} || i<${#v2[@]}; i++)); do
        local n1=${v1[i]:-0}
        local n2=${v2[i]:-0}
        if ((n1 > n2)); then
            return 1
        elif ((n1 < n2)); then
            return 2
        fi
    done
    return 0
}

# ── Actualizar base de datos de CVEs ─────────────────────
update_cve_database() {
    echo -e "${CYAN}Actualizando base de datos de CVEs del kernel...${NC}"

    # Intentar descargar desde kernel.org CVE list
    local CVE_URL="https://cdn.kernel.org/pub/linux/kernel/v$(echo "$KERNEL_BASE" | cut -d. -f1).x/ChangeLog-${KERNEL_BASE}"
    local VULN_URL="https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/index.html"

    # Crear lista local de CVEs conocidos si no se puede descargar
    # Usamos los datos de /sys/devices/system/cpu/vulnerabilities como fuente local
    echo -e "${CYAN}Recopilando informacion de vulnerabilidades locales...${NC}"

    # Vulnerabilidades de CPU desde sysfs
    local vuln_json="["
    local first=1
    if [[ -d /sys/devices/system/cpu/vulnerabilities ]]; then
        for vuln_file in /sys/devices/system/cpu/vulnerabilities/*; do
            local name=$(basename "$vuln_file")
            local status=$(cat "$vuln_file" 2>/dev/null || echo "unknown")
            local severity="info"
            if echo "$status" | grep -qi "vulnerable"; then
                severity="critical"
            elif echo "$status" | grep -qi "mitigation"; then
                severity="mitigated"
            elif echo "$status" | grep -qi "not affected"; then
                severity="not_affected"
            fi
            [[ $first -eq 0 ]] && vuln_json+=","
            vuln_json+="{\"name\":\"$name\",\"status\":\"$status\",\"severity\":\"$severity\"}"
            first=0
        done
    fi
    vuln_json+="]"

    echo "$vuln_json" > "$CVE_DB_DIR/cpu-vulnerabilities.json"
    echo -e "${GREEN}Base de datos de vulnerabilidades CPU actualizada${NC}"

    # Verificar si hay herramientas de escaneo disponibles
    if command -v spectre-meltdown-checker &>/dev/null; then
        echo -e "${GREEN}spectre-meltdown-checker disponible para escaneo detallado${NC}"
    fi

    # Intentar obtener CVEs via changelog del kernel
    if command -v curl &>/dev/null; then
        echo -e "${CYAN}Descargando informacion de CVEs...${NC}"

        # Intentar varias fuentes
        local downloaded=0

        # Fuente 1: kernel.org changelog
        if curl -sf --max-time 30 "$CVE_URL" -o "$CVE_DB_DIR/changelog-${KERNEL_BASE}.txt" 2>/dev/null; then
            # Extraer CVEs del changelog
            grep -oP 'CVE-\d{4}-\d{4,}' "$CVE_DB_DIR/changelog-${KERNEL_BASE}.txt" 2>/dev/null | \
                sort -u > "$CVE_DB_DIR/changelog-cves.txt" || true
            local cve_count=$(wc -l < "$CVE_DB_DIR/changelog-cves.txt" 2>/dev/null || echo "0")
            echo -e "${GREEN}  Changelog: $cve_count CVEs encontrados${NC}"
            downloaded=1
        fi

        # Fuente 2: NVD/NIST para kernel linux (ultimos 30 dias)
        local nvd_url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=linux+kernel&resultsPerPage=20"
        if curl -sf --max-time 30 "$nvd_url" -o "$CVE_DB_DIR/nvd-kernel-recent.json" 2>/dev/null; then
            echo -e "${GREEN}  NVD: datos recientes descargados${NC}"
            downloaded=1
        fi

        if [[ $downloaded -eq 0 ]]; then
            echo -e "${YELLOW}No se pudo descargar datos de CVEs (sin conexion?)${NC}"
            echo -e "${YELLOW}Usando solo datos locales de /sys${NC}"
        fi
    else
        echo -e "${YELLOW}curl no disponible - usando solo datos locales${NC}"
    fi

    echo "$(date -Iseconds)" > "$CVE_DB_DIR/last-update"
    echo -e "${GREEN}Actualizacion completada${NC}"
}

# ── Escanear kernel contra CVEs ──────────────────────────
scan_kernel() {
    local TARGET_BASE=$(echo "$TARGET_KERNEL" | sed 's/-.*//')

    if [[ $JSON_ONLY -eq 0 ]]; then
        echo ""
        echo "╔═══════════════════════════════════════════════════════════╗"
        echo "║   ESCANEO DE CVES DEL KERNEL                             ║"
        echo "╚═══════════════════════════════════════════════════════════╝"
        echo ""
        echo -e "${BOLD}Kernel escaneado:${NC}  $TARGET_KERNEL"
        echo -e "${BOLD}Version base:${NC}      $TARGET_BASE"
        echo -e "${BOLD}Fecha:${NC}             $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""
    fi

    local total_vulns=0
    local critical_vulns=0
    local mitigated_vulns=0
    local not_affected=0
    local cve_entries=""

    # 1. Verificar vulnerabilidades de CPU
    if [[ $JSON_ONLY -eq 0 ]]; then
        echo -e "${CYAN}── Vulnerabilidades CPU ───────────────────────────────${NC}"
    fi

    if [[ -d /sys/devices/system/cpu/vulnerabilities ]]; then
        for vuln_file in /sys/devices/system/cpu/vulnerabilities/*; do
            local name=$(basename "$vuln_file")
            local status=$(cat "$vuln_file" 2>/dev/null || echo "unknown")
            ((total_vulns++)) || true

            if echo "$status" | grep -qi "vulnerable"; then
                ((critical_vulns++)) || true
                [[ $JSON_ONLY -eq 0 ]] && echo -e "  ${RED}[VULNERABLE]${NC} $name: $status"
            elif echo "$status" | grep -qi "mitigation"; then
                ((mitigated_vulns++)) || true
                [[ $JSON_ONLY -eq 0 && $VERBOSE -eq 1 ]] && echo -e "  ${GREEN}[MITIGADO]${NC}   $name: $status"
            elif echo "$status" | grep -qi "not affected"; then
                ((not_affected++)) || true
                [[ $JSON_ONLY -eq 0 && $VERBOSE -eq 1 ]] && echo -e "  ${GREEN}[NO AFECT.]${NC} $name"
            fi

            [[ -n "$cve_entries" ]] && cve_entries+=","
            cve_entries+="{\"type\":\"cpu\",\"name\":\"$name\",\"status\":\"$(echo "$status" | tr '"' "'"  )\"}"
        done
    fi

    # 2. Verificar CVEs conocidos del changelog
    if [[ -f "$CVE_DB_DIR/changelog-cves.txt" ]]; then
        local cve_count=$(wc -l < "$CVE_DB_DIR/changelog-cves.txt")
        if [[ $JSON_ONLY -eq 0 ]]; then
            echo ""
            echo -e "${CYAN}── CVEs parcheados en esta version ────────────────────${NC}"
            echo -e "  CVEs corregidos en kernel $TARGET_BASE: ${GREEN}$cve_count${NC}"
        fi
        if [[ $VERBOSE -eq 1 && $JSON_ONLY -eq 0 ]]; then
            while IFS= read -r cve; do
                echo "    $cve"
            done < "$CVE_DB_DIR/changelog-cves.txt"
        fi
    fi

    # 3. Verificar edad del kernel
    if [[ $JSON_ONLY -eq 0 ]]; then
        echo ""
        echo -e "${CYAN}── Edad del Kernel ────────────────────────────────────${NC}"
    fi

    local install_date=""
    if [[ -f "/boot/vmlinuz-$TARGET_KERNEL" ]]; then
        install_date=$(stat -c '%Y' "/boot/vmlinuz-$TARGET_KERNEL" 2>/dev/null || echo "")
    elif [[ -f "/boot/vmlinuz" ]]; then
        install_date=$(stat -c '%Y' "/boot/vmlinuz" 2>/dev/null || echo "")
    fi

    local days_old="unknown"
    if [[ -n "$install_date" ]]; then
        local now=$(date +%s)
        days_old=$(( (now - install_date) / 86400 ))
        if [[ $JSON_ONLY -eq 0 ]]; then
            if [[ $days_old -gt 90 ]]; then
                echo -e "  ${RED}[ANTIGUO]${NC} Kernel instalado hace $days_old dias (>90 dias)"
            elif [[ $days_old -gt 30 ]]; then
                echo -e "  ${YELLOW}[MODERADO]${NC} Kernel instalado hace $days_old dias"
            else
                echo -e "  ${GREEN}[RECIENTE]${NC} Kernel instalado hace $days_old dias"
            fi
        fi
    fi

    # 4. Verificar si hay actualizacion disponible
    if [[ $JSON_ONLY -eq 0 ]]; then
        echo ""
        echo -e "${CYAN}── Actualizaciones Disponibles ────────────────────────${NC}"
    fi
    local update_available="unknown"
    case "$(. /etc/os-release 2>/dev/null && echo "${ID_LIKE:-$ID}")" in
        *debian*|*ubuntu*|debian|ubuntu)
            local avail=$(apt list --upgradable 2>/dev/null | grep -i "linux-image" || true)
            if [[ -n "$avail" ]]; then
                update_available="yes"
                [[ $JSON_ONLY -eq 0 ]] && echo -e "  ${YELLOW}Actualización de kernel disponible:${NC} $avail"
            else
                update_available="no"
                [[ $JSON_ONLY -eq 0 ]] && echo -e "  ${GREEN}Kernel al dia${NC}"
            fi
            ;;
        *rhel*|*fedora*|*centos*)
            local avail=$(dnf check-update kernel 2>/dev/null | grep -i kernel || true)
            if [[ -n "$avail" ]]; then
                update_available="yes"
                [[ $JSON_ONLY -eq 0 ]] && echo -e "  ${YELLOW}Actualización disponible:${NC} $avail"
            else
                update_available="no"
                [[ $JSON_ONLY -eq 0 ]] && echo -e "  ${GREEN}Kernel al dia${NC}"
            fi
            ;;
        *suse*)
            local avail=$(zypper list-updates 2>/dev/null | grep -i kernel || true)
            if [[ -n "$avail" ]]; then
                update_available="yes"
                [[ $JSON_ONLY -eq 0 ]] && echo -e "  ${YELLOW}Actualización disponible:${NC} $avail"
            else
                update_available="no"
                [[ $JSON_ONLY -eq 0 ]] && echo -e "  ${GREEN}Kernel al dia${NC}"
            fi
            ;;
        *)
            [[ $JSON_ONLY -eq 0 ]] && echo -e "  ${YELLOW}Verificacion automatica no disponible para esta distro${NC}"
            ;;
    esac

    # Generar JSON de salida
    cat > "$CVE_OUTPUT" << EOFJSONOUT
{
  "timestamp": "$(date -Iseconds)",
  "kernel_version": "$TARGET_KERNEL",
  "kernel_base": "$TARGET_BASE",
  "hostname": "$(hostname)",
  "scan_results": {
    "total_checks": $total_vulns,
    "critical": $critical_vulns,
    "mitigated": $mitigated_vulns,
    "not_affected": $not_affected,
    "kernel_age_days": "$days_old",
    "update_available": "$update_available"
  },
  "vulnerabilities": [$cve_entries]
}
EOFJSONOUT

    if [[ $JSON_ONLY -eq 1 ]]; then
        cat "$CVE_OUTPUT"
    else
        # Resumen
        echo ""
        echo "════════════════════════════════════════════════════════════"
        echo -e "${BOLD}Resumen de CVEs:${NC}"
        echo "  Total verificados:    $total_vulns"
        echo "  Criticos/Vulnerables: $critical_vulns"
        echo "  Mitigados:            $mitigated_vulns"
        echo "  No afectados:         $not_affected"
        echo ""

        if [[ $critical_vulns -gt 0 ]]; then
            echo -e "${RED}${BOLD}ESTADO: VULNERABLE${NC} - Hay $critical_vulns vulnerabilidades criticas"
        elif [[ $mitigated_vulns -gt 0 ]]; then
            echo -e "${GREEN}${BOLD}ESTADO: MITIGADO${NC} - Vulnerabilidades conocidas tienen mitigacion"
        else
            echo -e "${GREEN}${BOLD}ESTADO: SEGURO${NC} - Sin vulnerabilidades criticas detectadas"
        fi
        echo ""
        echo "Informe JSON guardado en: $CVE_OUTPUT"
    fi
}

# ── Ejecucion principal ──────────────────────────────────
if [[ $UPDATE_DB -eq 1 ]]; then
    update_cve_database
fi

if [[ $SCAN -eq 1 ]]; then
    scan_kernel
fi
EOFCVE

    chmod +x /usr/local/bin/monitorizar-cves-kernel.sh
    log_change "Creado" "/usr/local/bin/monitorizar-cves-kernel.sh"

    # Crear cron semanal para CVEs
    cat > /etc/cron.weekly/securizar-kernel-cves << 'EOFCRONCVE'
#!/bin/bash
# Escaneo semanal de CVEs del kernel - securizar Modulo 47
/usr/local/bin/monitorizar-cves-kernel.sh --update --scan -q >> /var/log/securizar/kernel-cves-scan.log 2>&1
EOFCRONCVE
    chmod +x /etc/cron.weekly/securizar-kernel-cves
    log_change "Creado" "/etc/cron.weekly/securizar-kernel-cves"

    log_info "Ejecuta 'monitorizar-cves-kernel.sh --update --scan' para escaneo completo"
    log_info "Salida JSON en: /var/log/securizar/kernel-cves.json"

else
    log_skip "Monitorizacion de CVEs del kernel"
fi

# ============================================================
# S7: POLITICA DE ACTUALIZACION DEL KERNEL
# ============================================================
log_section "S7: POLITICA DE ACTUALIZACION DEL KERNEL"

echo "Crea politica de actualizacion del kernel:"
echo "  - /etc/securizar/kernel-update-policy.conf"
echo "  - /usr/local/bin/gestionar-kernel-updates.sh"
echo "  - Auto-update, notificaciones, exclusiones"
echo "  - Integracion con gestor de paquetes de la distro"
echo ""

if check_executable /usr/local/bin/gestionar-kernel-updates.sh; then
    log_already "Politica de actualizacion del kernel (gestionar-kernel-updates.sh existe)"
elif ask "¿Crear politica de actualizacion del kernel?"; then

    # Crear archivo de politica
    cat > /etc/securizar/kernel-update-policy.conf << 'EOFPOLICY'
# ============================================================
# kernel-update-policy.conf - Politica de actualizacion del kernel
# Generado por securizar - Modulo 47
# ============================================================

# ── Auto-actualizacion ────────────────────────────────────
# yes = aplicar actualizaciones de kernel automaticamente
# no  = solo notificar, requiere intervencion manual
AUTO_UPDATE="no"

# ── Notificacion de reinicio requerido ────────────────────
# Notificar cuando se requiere reinicio tras actualizar kernel
NOTIFY_REBOOT_REQUIRED="yes"

# ── Dias maximos sin actualizar ──────────────────────────
# Numero maximo de dias que el kernel puede estar sin actualizar
# Genera alerta si se supera este umbral
MAX_DAYS_WITHOUT_UPDATE=90

# ── Correo de notificacion ───────────────────────────────
# Direccion de correo para notificaciones (vacio = deshabilitado)
NOTIFY_EMAIL=""

# ── Excluir versiones de kernel ──────────────────────────
# Versiones a excluir de actualizacion (regex, una por linea)
# Ejemplo: EXCLUDE_PATTERNS=(".*debug.*" ".*test.*")
EXCLUDE_PATTERNS=()

# ── Mantener kernels anteriores ──────────────────────────
# Numero minimo de kernels a mantener instalados
MIN_KERNELS_KEEP=2

# ── Solo actualizaciones de seguridad ────────────────────
# yes = solo instalar parches de seguridad del kernel
SECURITY_ONLY="yes"

# ── Ventana de mantenimiento ─────────────────────────────
# Horario permitido para aplicar actualizaciones (formato HH:MM)
# Vacio = sin restriccion horaria
MAINTENANCE_WINDOW_START=""
MAINTENANCE_WINDOW_END=""

# ── Log de actualizaciones ───────────────────────────────
UPDATE_LOG="/var/log/securizar/kernel-updates.log"

# ── Validacion post-actualizacion ────────────────────────
# Ejecutar validacion de parametros tras actualizar
POST_UPDATE_VALIDATE="yes"
EOFPOLICY

    chmod 600 /etc/securizar/kernel-update-policy.conf
    log_change "Creado" "/etc/securizar/kernel-update-policy.conf"

    # Crear script gestor de actualizaciones
    cat > /usr/local/bin/gestionar-kernel-updates.sh << 'EOFGESTOR'
#!/bin/bash
# ============================================================
# gestionar-kernel-updates.sh - Gestor de actualizaciones del kernel
# Generado por securizar - Modulo 47
# ============================================================
set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

POLICY_FILE="/etc/securizar/kernel-update-policy.conf"
UPDATE_LOG="/var/log/securizar/kernel-updates.log"

mkdir -p /var/log/securizar

# Cargar politica
if [[ -f "$POLICY_FILE" ]]; then
    # Parsear solo variables seguras
    while IFS='=' read -r key value; do
        key=$(echo "$key" | tr -d ' ')
        value=$(echo "$value" | tr -d '"' | tr -d "'")
        [[ -z "$key" || "$key" == \#* ]] && continue
        case "$key" in
            AUTO_UPDATE|NOTIFY_REBOOT_REQUIRED|MAX_DAYS_WITHOUT_UPDATE|\
            NOTIFY_EMAIL|MIN_KERNELS_KEEP|SECURITY_ONLY|\
            POST_UPDATE_VALIDATE|UPDATE_LOG)
                declare "$key=$value"
                ;;
        esac
    done < "$POLICY_FILE"
fi

AUTO_UPDATE="${AUTO_UPDATE:-no}"
MAX_DAYS_WITHOUT_UPDATE="${MAX_DAYS_WITHOUT_UPDATE:-90}"
MIN_KERNELS_KEEP="${MIN_KERNELS_KEEP:-2}"
SECURITY_ONLY="${SECURITY_ONLY:-yes}"
POST_UPDATE_VALIDATE="${POST_UPDATE_VALIDATE:-yes}"

usage() {
    echo "Uso: $0 [comando]"
    echo ""
    echo "Comandos:"
    echo "  check      Verificar actualizaciones disponibles"
    echo "  apply      Aplicar actualizaciones de kernel"
    echo "  status     Mostrar estado actual del kernel"
    echo "  history    Mostrar historial de actualizaciones"
    echo "  policy     Mostrar politica actual"
    echo "  help       Mostrar esta ayuda"
    exit 0
}

log_update() {
    echo "$(date -Iseconds) $*" >> "$UPDATE_LOG"
}

# Detectar distro
DISTRO_FAMILY="unknown"
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    case "${ID:-}" in
        opensuse*|sles|sled) DISTRO_FAMILY="suse" ;;
        debian|ubuntu|linuxmint|pop|kali) DISTRO_FAMILY="debian" ;;
        fedora|rhel|centos|rocky|alma) DISTRO_FAMILY="rhel" ;;
        arch|manjaro|endeavouros) DISTRO_FAMILY="arch" ;;
    esac
fi

cmd_check() {
    echo ""
    echo -e "${BOLD}Verificando actualizaciones de kernel...${NC}"
    echo -e "Kernel actual: $(uname -r)"
    echo ""

    local updates=""
    case "$DISTRO_FAMILY" in
        debian)
            apt-get update -qq 2>/dev/null
            updates=$(apt list --upgradable 2>/dev/null | grep -i "linux-image\|linux-headers" || true)
            ;;
        rhel)
            updates=$(dnf check-update kernel 2>/dev/null | grep -i kernel || true)
            ;;
        suse)
            zypper --non-interactive refresh 2>/dev/null
            updates=$(zypper list-updates 2>/dev/null | grep -i kernel || true)
            ;;
        arch)
            updates=$(checkupdates 2>/dev/null | grep -i "linux " || true)
            ;;
    esac

    if [[ -n "$updates" ]]; then
        echo -e "${YELLOW}Actualizaciones de kernel disponibles:${NC}"
        echo "$updates"
        log_update "CHECK: actualizaciones disponibles"
    else
        echo -e "${GREEN}No hay actualizaciones de kernel pendientes${NC}"
        log_update "CHECK: sin actualizaciones"
    fi

    # Verificar edad del kernel
    echo ""
    local kernel_file="/boot/vmlinuz-$(uname -r)"
    if [[ -f "$kernel_file" ]]; then
        local install_epoch=$(stat -c '%Y' "$kernel_file")
        local now=$(date +%s)
        local days_old=$(( (now - install_epoch) / 86400 ))
        echo -e "Edad del kernel: ${BOLD}$days_old dias${NC}"
        if [[ $days_old -gt $MAX_DAYS_WITHOUT_UPDATE ]]; then
            echo -e "${RED}ALERTA: Kernel supera $MAX_DAYS_WITHOUT_UPDATE dias sin actualizar${NC}"
            log_update "ALERT: kernel tiene $days_old dias (maximo: $MAX_DAYS_WITHOUT_UPDATE)"
        fi
    fi

    # Verificar si hay reinicio pendiente
    if [[ -f /var/run/reboot-required ]]; then
        echo -e "\n${YELLOW}REINICIO REQUERIDO${NC} - Hay un kernel nuevo instalado pendiente de reinicio"
    fi
}

cmd_apply() {
    echo ""
    echo -e "${BOLD}Aplicando actualizaciones de kernel...${NC}"

    if [[ "$AUTO_UPDATE" != "yes" ]]; then
        echo -e "${YELLOW}NOTA: AUTO_UPDATE esta en 'no' en la politica${NC}"
        read -p "¿Continuar de todas formas? [s/N]: " resp
        if [[ ! "$resp" =~ ^[sS]$ ]]; then
            echo "Cancelado."
            return 0
        fi
    fi

    local rc=0
    case "$DISTRO_FAMILY" in
        debian)
            if [[ "$SECURITY_ONLY" == "yes" ]]; then
                apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade linux-image-$(dpkg --print-architecture) 2>/dev/null || rc=$?
            else
                apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y linux-image-$(dpkg --print-architecture) 2>/dev/null || rc=$?
            fi
            ;;
        rhel)
            if [[ "$SECURITY_ONLY" == "yes" ]]; then
                dnf upgrade --security -y kernel 2>/dev/null || rc=$?
            else
                dnf upgrade -y kernel 2>/dev/null || rc=$?
            fi
            ;;
        suse)
            if [[ "$SECURITY_ONLY" == "yes" ]]; then
                zypper --non-interactive patch --category security 2>/dev/null || rc=$?
            else
                zypper --non-interactive update kernel-default 2>/dev/null || rc=$?
            fi
            ;;
        arch)
            pacman -Syu --noconfirm linux 2>/dev/null || rc=$?
            ;;
        *)
            echo -e "${RED}Distro no soportada para actualizacion automatica${NC}"
            return 1
            ;;
    esac

    if [[ $rc -eq 0 ]]; then
        echo -e "${GREEN}Actualizacion completada exitosamente${NC}"
        log_update "APPLY: actualizacion exitosa"

        if [[ "$POST_UPDATE_VALIDATE" == "yes" ]] && [[ -x /usr/local/bin/validar-kernel-params.sh ]]; then
            echo ""
            echo -e "${CYAN}Ejecutando validacion post-actualizacion...${NC}"
            /usr/local/bin/validar-kernel-params.sh 2>/dev/null || true
        fi

        echo -e "\n${YELLOW}NOTA: Reiniciar el sistema para usar el nuevo kernel${NC}"
    else
        echo -e "${RED}Error en la actualizacion (codigo: $rc)${NC}"
        log_update "APPLY: error codigo $rc"
    fi
}

cmd_status() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║   ESTADO DEL KERNEL                                      ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo ""
    echo -e "${BOLD}Kernel en ejecucion:${NC}  $(uname -r)"
    echo -e "${BOLD}Arquitectura:${NC}         $(uname -m)"
    echo -e "${BOLD}Compilado:${NC}            $(uname -v)"
    echo -e "${BOLD}Hostname:${NC}             $(hostname)"
    echo ""

    # Kernels instalados
    echo -e "${CYAN}Kernels instalados:${NC}"
    case "$DISTRO_FAMILY" in
        debian)
            dpkg -l 'linux-image-*' 2>/dev/null | grep '^ii' | awk '{print "  " $2 " (" $3 ")"}' || true
            ;;
        rhel)
            rpm -qa kernel 2>/dev/null | sort | while read -r k; do echo "  $k"; done || true
            ;;
        suse)
            rpm -qa kernel-default 2>/dev/null | sort | while read -r k; do echo "  $k"; done || true
            ;;
        arch)
            pacman -Q linux 2>/dev/null | while read -r k v; do echo "  $k ($v)"; done || true
            ;;
    esac

    echo ""
    echo -e "${CYAN}Politica:${NC}"
    echo "  Auto-update:    $AUTO_UPDATE"
    echo "  Solo seguridad: $SECURITY_ONLY"
    echo "  Max dias:       $MAX_DAYS_WITHOUT_UPDATE"
    echo "  Min kernels:    $MIN_KERNELS_KEEP"
}

cmd_history() {
    echo ""
    echo -e "${BOLD}Historial de actualizaciones del kernel:${NC}"
    echo ""
    if [[ -f "$UPDATE_LOG" ]]; then
        tail -50 "$UPDATE_LOG"
    else
        echo "Sin historial registrado"
    fi
}

cmd_policy() {
    echo ""
    echo -e "${BOLD}Politica de actualizacion del kernel:${NC}"
    echo ""
    if [[ -f "$POLICY_FILE" ]]; then
        grep -v '^\s*#' "$POLICY_FILE" | grep -v '^\s*$'
    else
        echo "Archivo de politica no encontrado: $POLICY_FILE"
    fi
}

# ── Main ──────────────────────────────────────────────────
CMD="${1:-status}"
case "$CMD" in
    check)   cmd_check ;;
    apply)   cmd_apply ;;
    status)  cmd_status ;;
    history) cmd_history ;;
    policy)  cmd_policy ;;
    help|-h|--help) usage ;;
    *) echo "Comando desconocido: $CMD"; usage ;;
esac
EOFGESTOR

    chmod +x /usr/local/bin/gestionar-kernel-updates.sh
    log_change "Creado" "/usr/local/bin/gestionar-kernel-updates.sh"

    # Crear cron para verificacion
    cat > /etc/cron.daily/securizar-kernel-update-check << 'EOFCRONUPD'
#!/bin/bash
# Verificacion diaria de actualizaciones del kernel - securizar Modulo 47
/usr/local/bin/gestionar-kernel-updates.sh check >> /var/log/securizar/kernel-updates.log 2>&1
EOFCRONUPD
    chmod +x /etc/cron.daily/securizar-kernel-update-check
    log_change "Creado" "/etc/cron.daily/securizar-kernel-update-check"

    log_info "Politica de actualizacion configurada"
    log_info "Ejecuta 'gestionar-kernel-updates.sh check' para verificar actualizaciones"
    log_info "Ejecuta 'gestionar-kernel-updates.sh apply' para aplicar actualizaciones"

else
    log_skip "Politica de actualizacion del kernel"
fi

# ============================================================
# S8: SECURE BOOT Y FIRMA DE MODULOS
# ============================================================
log_section "S8: SECURE BOOT Y FIRMA DE MODULOS"

echo "Verifica y configura Secure Boot:"
echo "  - Estado de UEFI Secure Boot via mokutil"
echo "  - Firma de imagen del kernel"
echo "  - Enforcement de firma de modulos"
echo "  - /usr/local/bin/verificar-secure-boot.sh"
echo "  - Guia para enrollar claves personalizadas"
echo ""

if check_executable /usr/local/bin/verificar-secure-boot.sh; then
    log_already "Verificacion de Secure Boot (verificar-secure-boot.sh existe)"
elif ask "¿Crear herramienta de verificacion de Secure Boot?"; then

    # Instalar mokutil si no esta
    if ! command -v mokutil &>/dev/null; then
        log_info "Instalando mokutil..."
        case "$DISTRO_FAMILY" in
            suse)   zypper --non-interactive install mokutil 2>/dev/null || log_warn "No se pudo instalar mokutil" ;;
            debian) DEBIAN_FRONTEND=noninteractive apt-get install -y mokutil 2>/dev/null || log_warn "No se pudo instalar mokutil" ;;
            rhel)   dnf install -y mokutil 2>/dev/null || log_warn "No se pudo instalar mokutil" ;;
            arch)   pacman -S --noconfirm mokutil 2>/dev/null || log_warn "No se pudo instalar mokutil" ;;
        esac
    fi

    cat > /usr/local/bin/verificar-secure-boot.sh << 'EOFSECBOOT'
#!/bin/bash
# ============================================================
# verificar-secure-boot.sh - Verificacion de Secure Boot
# Generado por securizar - Modulo 47
# ============================================================
set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

SCORE=0
MAX_SCORE=0
ISSUES=()

pass() { echo -e "  ${GREEN}[OK]${NC}    $1"; ((SCORE++)) || true; ((MAX_SCORE++)) || true; }
fail() { echo -e "  ${RED}[FAIL]${NC}  $1"; ISSUES+=("$1"); ((MAX_SCORE++)) || true; }
warn() { echo -e "  ${YELLOW}[WARN]${NC}  $1"; ((MAX_SCORE++)) || true; }
info() { echo -e "  ${DIM}[INFO]${NC}  $1"; }

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   VERIFICACION DE SECURE BOOT Y FIRMA DE MODULOS         ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo -e "${BOLD}Fecha:${NC}     $(date '+%Y-%m-%d %H:%M:%S')"
echo -e "${BOLD}Kernel:${NC}    $(uname -r)"
echo ""

# ── 1. Tipo de firmware ──────────────────────────────────
echo -e "${CYAN}── Firmware ───────────────────────────────────────────${NC}"
if [[ -d /sys/firmware/efi ]]; then
    pass "Sistema UEFI detectado"
    UEFI=1
else
    info "Sistema BIOS legacy (Secure Boot no aplicable)"
    UEFI=0
fi

# ── 2. Estado de Secure Boot ─────────────────────────────
echo ""
echo -e "${CYAN}── Secure Boot ────────────────────────────────────────${NC}"
if [[ $UEFI -eq 1 ]]; then
    if command -v mokutil &>/dev/null; then
        SB_STATE=$(mokutil --sb-state 2>/dev/null || echo "error")
        if echo "$SB_STATE" | grep -qi "SecureBoot enabled"; then
            pass "Secure Boot HABILITADO"
        elif echo "$SB_STATE" | grep -qi "SecureBoot disabled"; then
            fail "Secure Boot DESHABILITADO"
        else
            warn "Estado de Secure Boot indeterminado: $SB_STATE"
        fi

        # Verificar claves MOK enrolladas
        echo ""
        echo -e "${CYAN}── Claves MOK (Machine Owner Keys) ───────────────────${NC}"
        MOK_LIST=$(mokutil --list-enrolled 2>/dev/null || echo "")
        if [[ -n "$MOK_LIST" ]]; then
            MOK_COUNT=$(echo "$MOK_LIST" | grep -c "Subject:" || echo "0")
            info "Claves MOK enrolladas: $MOK_COUNT"
            echo "$MOK_LIST" | grep "Subject:" | head -5 | while read -r line; do
                info "  $line"
            done
        else
            info "Sin claves MOK adicionales enrolladas"
        fi

        # Verificar si validacion de Secure Boot esta habilitada
        SB_VALIDATION=$(mokutil --validation-state 2>/dev/null || echo "")
        if [[ -n "$SB_VALIDATION" ]]; then
            info "Validacion: $SB_VALIDATION"
        fi
    else
        warn "mokutil no instalado - no se puede verificar Secure Boot"
        # Intentar via efivars
        if ls /sys/firmware/efi/efivars/SecureBoot-* &>/dev/null; then
            SB_VAR=$(ls /sys/firmware/efi/efivars/SecureBoot-* 2>/dev/null | head -1)
            if [[ -n "$SB_VAR" ]]; then
                # El ultimo byte indica estado
                SB_BYTE=$(od -An -tx1 -j4 -N1 "$SB_VAR" 2>/dev/null | tr -d ' ')
                if [[ "$SB_BYTE" == "01" ]]; then
                    pass "Secure Boot habilitado (via efivars)"
                else
                    fail "Secure Boot deshabilitado (via efivars)"
                fi
            fi
        fi
    fi
else
    info "BIOS legacy - Secure Boot no disponible"
fi

# ── 3. Firma del kernel ──────────────────────────────────
echo ""
echo -e "${CYAN}── Firma de Imagen del Kernel ─────────────────────────${NC}"
KERNEL_IMAGE="/boot/vmlinuz-$(uname -r)"
if [[ -f "$KERNEL_IMAGE" ]]; then
    # Verificar si tiene firma PE/COFF (Secure Boot)
    if command -v sbverify &>/dev/null; then
        if sbverify --list "$KERNEL_IMAGE" 2>/dev/null | grep -q "signature"; then
            pass "Imagen del kernel tiene firma digital"
        else
            warn "Imagen del kernel sin firma verificable con sbverify"
        fi
    elif command -v pesign &>/dev/null; then
        if pesign -S -i "$KERNEL_IMAGE" 2>/dev/null | grep -q "signer"; then
            pass "Imagen del kernel firmada (pesign)"
        else
            warn "Imagen del kernel sin firma verificable con pesign"
        fi
    else
        info "Instalar sbsigntool o pesign para verificar firmas de kernel"
    fi
else
    warn "Imagen del kernel no encontrada en $KERNEL_IMAGE"
fi

# ── 4. Firma de modulos del kernel ───────────────────────
echo ""
echo -e "${CYAN}── Firma de Modulos del Kernel ────────────────────────${NC}"
KCONFIG="/boot/config-$(uname -r)"

if [[ -f "$KCONFIG" ]]; then
    if grep -q "CONFIG_MODULE_SIG=y" "$KCONFIG"; then
        pass "Firma de modulos habilitada (CONFIG_MODULE_SIG=y)"
    else
        fail "Firma de modulos NO habilitada"
    fi

    if grep -q "CONFIG_MODULE_SIG_FORCE=y" "$KCONFIG"; then
        pass "Firma obligatoria (CONFIG_MODULE_SIG_FORCE=y)"
    else
        warn "Firma de modulos no es obligatoria"
    fi

    if grep -q "CONFIG_MODULE_SIG_ALL=y" "$KCONFIG"; then
        pass "Todos los modulos firmados en compilacion"
    fi

    # Algoritmo de firma
    SIG_HASH=$(grep "CONFIG_MODULE_SIG_HASH=" "$KCONFIG" 2>/dev/null | cut -d'"' -f2 || echo "")
    if [[ -n "$SIG_HASH" ]]; then
        info "Algoritmo de firma: $SIG_HASH"
        if [[ "$SIG_HASH" == "sha512" || "$SIG_HASH" == "sha384" || "$SIG_HASH" == "sha256" ]]; then
            pass "Algoritmo de firma robusto: $SIG_HASH"
        else
            warn "Algoritmo de firma debil: $SIG_HASH"
        fi
    fi
elif [[ -f /proc/config.gz ]]; then
    if zcat /proc/config.gz 2>/dev/null | grep -q "CONFIG_MODULE_SIG=y"; then
        pass "Firma de modulos habilitada"
    else
        fail "Firma de modulos NO habilitada"
    fi
    if zcat /proc/config.gz 2>/dev/null | grep -q "CONFIG_MODULE_SIG_FORCE=y"; then
        pass "Firma obligatoria"
    else
        warn "Firma de modulos no es obligatoria"
    fi
else
    warn "No se pudo verificar configuracion del kernel"
fi

# ── 5. Verificar modulos sin firma ───────────────────────
echo ""
echo -e "${CYAN}── Modulos Sin Firma ──────────────────────────────────${NC}"
UNSIGNED_COUNT=0
TOTAL_MODS=0
while IFS= read -r modname; do
    ((TOTAL_MODS++)) || true
    modpath=$(modinfo -n "$modname" 2>/dev/null || echo "")
    if [[ -n "$modpath" && -f "$modpath" ]]; then
        if ! modinfo -F signer "$modname" &>/dev/null || [[ -z "$(modinfo -F signer "$modname" 2>/dev/null)" ]]; then
            ((UNSIGNED_COUNT++)) || true
            if [[ $UNSIGNED_COUNT -le 5 ]]; then
                info "  Sin firma: $modname"
            fi
        fi
    fi
done < <(lsmod | awk 'NR>1 {print $1}')

if [[ $UNSIGNED_COUNT -eq 0 ]]; then
    pass "Todos los modulos cargados estan firmados ($TOTAL_MODS modulos)"
elif [[ $UNSIGNED_COUNT -le 5 ]]; then
    warn "$UNSIGNED_COUNT de $TOTAL_MODS modulos sin firma"
else
    fail "$UNSIGNED_COUNT de $TOTAL_MODS modulos sin firma"
    if [[ $UNSIGNED_COUNT -gt 5 ]]; then
        info "  ... y $((UNSIGNED_COUNT - 5)) modulos mas sin firma"
    fi
fi

# ── 6. Lockdown mode ─────────────────────────────────────
echo ""
echo -e "${CYAN}── Kernel Lockdown ────────────────────────────────────${NC}"
if [[ -f /sys/kernel/security/lockdown ]]; then
    LOCKDOWN=$(cat /sys/kernel/security/lockdown)
    if echo "$LOCKDOWN" | grep -q "\[confidentiality\]"; then
        pass "Lockdown: confidentiality (maximo)"
    elif echo "$LOCKDOWN" | grep -q "\[integrity\]"; then
        pass "Lockdown: integrity"
    elif echo "$LOCKDOWN" | grep -q "\[none\]"; then
        fail "Lockdown: deshabilitado"
    fi
else
    warn "Lockdown no disponible en este kernel"
fi

# ── Guia de enrollamiento de claves ──────────────────────
echo ""
echo -e "${CYAN}── Guia: Enrollar Claves Personalizadas ───────────────${NC}"
echo "  Para firmar modulos personalizados con Secure Boot:"
echo ""
echo "  1. Generar par de claves:"
echo "     openssl req -new -x509 -newkey rsa:2048 -keyout MOK.priv \\"
echo "       -outform DER -out MOK.der -nodes -days 36500 \\"
echo "       -subj '/CN=Mi Clave MOK/'"
echo ""
echo "  2. Enrollar la clave:"
echo "     mokutil --import MOK.der"
echo "     # Requiere reinicio y confirmacion en UEFI"
echo ""
echo "  3. Firmar modulo:"
echo "     /usr/src/linux-headers-\$(uname -r)/scripts/sign-file \\"
echo "       sha256 MOK.priv MOK.der modulo.ko"
echo ""

# ── Resultado ─────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════"
if [[ $MAX_SCORE -gt 0 ]]; then
    PERCENTAGE=$(( (SCORE * 100) / MAX_SCORE ))
else
    PERCENTAGE=0
fi

echo -e "${BOLD}Puntuacion Secure Boot:${NC} $SCORE / $MAX_SCORE ($PERCENTAGE%)"
echo ""

if [[ $PERCENTAGE -ge 80 ]]; then
    echo -e "${GREEN}${BOLD}RESULTADO: BUENO${NC}"
elif [[ $PERCENTAGE -ge 50 ]]; then
    echo -e "${YELLOW}${BOLD}RESULTADO: MEJORABLE${NC}"
else
    echo -e "${RED}${BOLD}RESULTADO: DEFICIENTE${NC}"
fi

if [[ ${#ISSUES[@]} -gt 0 ]]; then
    echo ""
    echo -e "${RED}Problemas detectados:${NC}"
    for issue in "${ISSUES[@]}"; do
        echo "  - $issue"
    done
fi
echo ""

# Guardar resultado
mkdir -p /var/log/securizar
cat > /var/log/securizar/secure-boot-audit.json << EOFJSONSB
{
  "timestamp": "$(date -Iseconds)",
  "kernel": "$(uname -r)",
  "uefi": $UEFI,
  "score": $SCORE,
  "max_score": $MAX_SCORE,
  "percentage": $PERCENTAGE,
  "issues": ${#ISSUES[@]}
}
EOFJSONSB
echo "Informe guardado en: /var/log/securizar/secure-boot-audit.json"
EOFSECBOOT

    chmod +x /usr/local/bin/verificar-secure-boot.sh
    log_change "Creado" "/usr/local/bin/verificar-secure-boot.sh"

    # Verificacion rapida del estado actual
    log_info "Estado actual de Secure Boot:"
    if command -v mokutil &>/dev/null; then
        SB_STATUS=$(mokutil --sb-state 2>/dev/null || echo "No se pudo determinar")
        log_info "  $SB_STATUS"
    elif [[ -d /sys/firmware/efi ]]; then
        log_info "  Sistema UEFI - instalar mokutil para verificar"
    else
        log_info "  Sistema BIOS legacy - Secure Boot no aplicable"
    fi
    log_info "Ejecuta 'verificar-secure-boot.sh' para informe completo"

else
    log_skip "Verificacion de Secure Boot"
fi

# ============================================================
# S9: ROLLBACK SEGURO DEL KERNEL
# ============================================================
log_section "S9: ROLLBACK SEGURO DEL KERNEL"

echo "Crea /usr/local/bin/kernel-rollback.sh:"
echo "  - Lista kernels instalados"
echo "  - Permite rollback a version anterior"
echo "  - Verifica entradas GRUB"
echo "  - Asegura al menos 2 kernels disponibles"
echo "  - Test opcional con kexec"
echo "  - Historial de rollbacks"
echo ""

if check_executable /usr/local/bin/kernel-rollback.sh; then
    log_already "Rollback de kernel (kernel-rollback.sh existe)"
elif ask "¿Crear herramienta de rollback de kernel?"; then

    cat > /usr/local/bin/kernel-rollback.sh << 'EOFROLLBACK'
#!/bin/bash
# ============================================================
# kernel-rollback.sh - Rollback seguro del kernel
# Generado por securizar - Modulo 47
# ============================================================
set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

ROLLBACK_LOG="/var/log/securizar/kernel-rollback.log"
MIN_KERNELS=2

mkdir -p /var/log/securizar

log_rollback() {
    echo "$(date -Iseconds) $*" >> "$ROLLBACK_LOG"
}

usage() {
    echo "Uso: $0 [comando] [opciones]"
    echo ""
    echo "Comandos:"
    echo "  list              Listar kernels instalados"
    echo "  rollback [VER]    Rollback a version anterior"
    echo "  grub              Verificar entradas GRUB"
    echo "  test [VER]        Test con kexec (sin reinicio)"
    echo "  history           Ver historial de rollbacks"
    echo "  cleanup           Limpiar kernels antiguos"
    echo "  help              Mostrar esta ayuda"
    exit 0
}

# Detectar distro
DISTRO_FAMILY="unknown"
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    case "${ID:-}" in
        opensuse*|sles|sled) DISTRO_FAMILY="suse" ;;
        debian|ubuntu|linuxmint|pop|kali) DISTRO_FAMILY="debian" ;;
        fedora|rhel|centos|rocky|alma) DISTRO_FAMILY="rhel" ;;
        arch|manjaro|endeavouros) DISTRO_FAMILY="arch" ;;
    esac
fi

# ── Listar kernels instalados ────────────────────────────
cmd_list() {
    echo ""
    echo -e "${BOLD}Kernels instalados:${NC}"
    echo ""
    local current=$(uname -r)
    echo -e "  Kernel en ejecucion: ${GREEN}$current${NC}"
    echo ""

    local kernels=()
    case "$DISTRO_FAMILY" in
        debian)
            while IFS= read -r line; do
                local pkg=$(echo "$line" | awk '{print $2}')
                local ver=$(echo "$line" | awk '{print $3}')
                local kver=$(echo "$pkg" | sed 's/linux-image-//')
                if [[ "$kver" == "$current" ]]; then
                    echo -e "  ${GREEN}* $pkg ($ver)${NC}  <- EN USO"
                else
                    echo "    $pkg ($ver)"
                fi
                kernels+=("$kver")
            done < <(dpkg -l 'linux-image-[0-9]*' 2>/dev/null | grep '^ii' || true)
            ;;
        rhel)
            while IFS= read -r pkg; do
                local kver=$(echo "$pkg" | sed 's/kernel-//')
                if echo "$current" | grep -q "$kver"; then
                    echo -e "  ${GREEN}* $pkg${NC}  <- EN USO"
                else
                    echo "    $pkg"
                fi
                kernels+=("$kver")
            done < <(rpm -qa kernel --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null | sort -V || true)
            ;;
        suse)
            while IFS= read -r pkg; do
                local kver=$(echo "$pkg" | sed 's/kernel-default-//')
                if echo "$current" | grep -q "$kver"; then
                    echo -e "  ${GREEN}* $pkg${NC}  <- EN USO"
                else
                    echo "    $pkg"
                fi
                kernels+=("$kver")
            done < <(rpm -qa kernel-default --qf '%{NAME}-%{VERSION}-%{RELEASE}\n' 2>/dev/null | sort -V || true)
            ;;
        arch)
            local installed_ver=$(pacman -Q linux 2>/dev/null | awk '{print $2}')
            echo "  linux ($installed_ver)"
            if pacman -Q linux-lts 2>/dev/null; then
                local lts_ver=$(pacman -Q linux-lts 2>/dev/null | awk '{print $2}')
                echo "  linux-lts ($lts_ver)"
            fi
            ;;
    esac

    # Verificar imagenes en /boot
    echo ""
    echo -e "${BOLD}Imagenes en /boot:${NC}"
    for img in /boot/vmlinuz-*; do
        if [[ -f "$img" ]]; then
            local size=$(du -sh "$img" 2>/dev/null | awk '{print $1}')
            local date_mod=$(stat -c '%Y' "$img" 2>/dev/null)
            local date_fmt=$(date -d "@$date_mod" '+%Y-%m-%d' 2>/dev/null || echo "?")
            local kname=$(basename "$img" | sed 's/vmlinuz-//')
            if [[ "$kname" == "$current" ]]; then
                echo -e "  ${GREEN}* $img ($size, $date_fmt)${NC}  <- EN USO"
            else
                echo "    $img ($size, $date_fmt)"
            fi
        fi
    done

    echo ""
    echo -e "${BOLD}Total kernels:${NC} $(ls /boot/vmlinuz-* 2>/dev/null | wc -l)"
}

# ── Verificar GRUB ────────────────────────────────────────
cmd_grub() {
    echo ""
    echo -e "${BOLD}Verificacion de entradas GRUB:${NC}"
    echo ""

    # Buscar configuracion GRUB
    local GRUB_CFG=""
    for candidate in /boot/grub2/grub.cfg /boot/grub/grub.cfg /boot/efi/EFI/*/grub.cfg; do
        if [[ -f "$candidate" ]]; then
            GRUB_CFG="$candidate"
            break
        fi
    done

    if [[ -z "$GRUB_CFG" ]]; then
        echo -e "${YELLOW}No se encontro grub.cfg${NC}"
        return 1
    fi

    echo -e "  Archivo GRUB: $GRUB_CFG"
    echo ""

    # Extraer entradas de menu
    echo -e "${CYAN}Entradas de arranque:${NC}"
    local idx=0
    while IFS= read -r entry; do
        local title=$(echo "$entry" | sed "s/menuentry '//;s/' .*//" | head -c 70)
        if echo "$entry" | grep -q "$(uname -r)"; then
            echo -e "  ${GREEN}[$idx] $title${NC}  <- ACTUAL"
        else
            echo "  [$idx] $title"
        fi
        ((idx++)) || true
    done < <(grep "^menuentry " "$GRUB_CFG" 2>/dev/null || true)

    # Verificar default
    echo ""
    local default_entry=$(grep "^GRUB_DEFAULT" /etc/default/grub 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "0")
    echo -e "  GRUB_DEFAULT: $default_entry"

    if grep -q "GRUB_SAVEDEFAULT" /etc/default/grub 2>/dev/null; then
        echo -e "  GRUB_SAVEDEFAULT habilitado"
    fi
}

# ── Rollback ──────────────────────────────────────────────
cmd_rollback() {
    local target_ver="${1:-}"
    local current=$(uname -r)

    echo ""
    echo -e "${BOLD}Rollback del kernel${NC}"
    echo ""

    # Listar kernels disponibles (excepto el actual)
    local available=()
    for img in /boot/vmlinuz-*; do
        if [[ -f "$img" ]]; then
            local kver=$(basename "$img" | sed 's/vmlinuz-//')
            if [[ "$kver" != "$current" ]]; then
                available+=("$kver")
            fi
        fi
    done

    if [[ ${#available[@]} -eq 0 ]]; then
        echo -e "${RED}No hay kernels alternativos disponibles para rollback${NC}"
        return 1
    fi

    # Verificar que hay suficientes kernels
    local total_kernels=$(( ${#available[@]} + 1 ))
    if [[ $total_kernels -lt $MIN_KERNELS ]]; then
        echo -e "${RED}Operacion cancelada: solo hay $total_kernels kernels (minimo: $MIN_KERNELS)${NC}"
        return 1
    fi

    if [[ -z "$target_ver" ]]; then
        echo "Kernels disponibles para rollback:"
        local idx=1
        for kver in "${available[@]}"; do
            local date_mod=$(stat -c '%Y' "/boot/vmlinuz-$kver" 2>/dev/null)
            local date_fmt=$(date -d "@$date_mod" '+%Y-%m-%d' 2>/dev/null || echo "?")
            echo "  [$idx] $kver ($date_fmt)"
            ((idx++)) || true
        done
        echo ""
        read -p "Seleccionar kernel (numero): " selection
        if [[ "$selection" =~ ^[0-9]+$ ]] && [[ $selection -ge 1 ]] && [[ $selection -le ${#available[@]} ]]; then
            target_ver="${available[$((selection-1))]}"
        else
            echo "Seleccion invalida"
            return 1
        fi
    fi

    # Verificar que existe
    if [[ ! -f "/boot/vmlinuz-$target_ver" ]]; then
        echo -e "${RED}Kernel no encontrado: /boot/vmlinuz-$target_ver${NC}"
        return 1
    fi

    echo ""
    echo -e "Kernel actual:   ${RED}$current${NC}"
    echo -e "Rollback hacia:  ${GREEN}$target_ver${NC}"
    echo ""

    read -p "¿Confirmar rollback? [s/N]: " confirm
    if [[ ! "$confirm" =~ ^[sS]$ ]]; then
        echo "Rollback cancelado"
        return 0
    fi

    # Configurar GRUB para arrancar con el kernel seleccionado
    if [[ -f /etc/default/grub ]]; then
        # Buscar indice del kernel en GRUB
        local GRUB_CFG=""
        for candidate in /boot/grub2/grub.cfg /boot/grub/grub.cfg; do
            [[ -f "$candidate" ]] && GRUB_CFG="$candidate" && break
        done

        if [[ -n "$GRUB_CFG" ]]; then
            local grub_idx=0
            local found_idx=""
            while IFS= read -r entry; do
                if echo "$entry" | grep -q "$target_ver"; then
                    found_idx=$grub_idx
                    break
                fi
                ((grub_idx++)) || true
            done < <(grep "^menuentry " "$GRUB_CFG" 2>/dev/null || true)

            if [[ -n "$found_idx" ]]; then
                # Hacer backup de grub default
                cp /etc/default/grub /etc/default/grub.bak.securizar
                # Configurar para arrancar una vez con ese kernel
                if command -v grub2-reboot &>/dev/null; then
                    grub2-reboot "$found_idx"
                    echo -e "${GREEN}Configurado GRUB para arrancar con kernel $target_ver en proximo reinicio${NC}"
                elif command -v grub-reboot &>/dev/null; then
                    grub-reboot "$found_idx"
                    echo -e "${GREEN}Configurado GRUB para arrancar con kernel $target_ver en proximo reinicio${NC}"
                else
                    echo -e "${YELLOW}Configurar manualmente GRUB_DEFAULT=$found_idx en /etc/default/grub${NC}"
                fi
            else
                echo -e "${YELLOW}No se encontro entrada GRUB para $target_ver${NC}"
                echo "Puede ser necesario actualizar GRUB manualmente"
            fi
        fi
    fi

    log_rollback "ROLLBACK: $current -> $target_ver"
    echo ""
    echo -e "${YELLOW}IMPORTANTE: Reiniciar el sistema para completar el rollback${NC}"
    echo -e "  systemctl reboot"
}

# ── Test con kexec ────────────────────────────────────────
cmd_test() {
    local target_ver="${1:-}"

    if [[ -z "$target_ver" ]]; then
        echo "Uso: $0 test <version-kernel>"
        return 1
    fi

    echo ""
    echo -e "${BOLD}Test de kernel con kexec${NC}"
    echo ""

    if ! command -v kexec &>/dev/null; then
        echo -e "${RED}kexec no instalado. Instalar kexec-tools${NC}"
        return 1
    fi

    local vmlinuz="/boot/vmlinuz-$target_ver"
    local initrd="/boot/initrd-$target_ver"
    [[ ! -f "$initrd" ]] && initrd="/boot/initramfs-$target_ver.img"
    [[ ! -f "$initrd" ]] && initrd="/boot/initrd.img-$target_ver"

    if [[ ! -f "$vmlinuz" ]]; then
        echo -e "${RED}Kernel no encontrado: $vmlinuz${NC}"
        return 1
    fi

    echo -e "  Kernel: $vmlinuz"
    echo -e "  Initrd: ${initrd:-N/A}"
    echo ""

    echo -e "${YELLOW}ADVERTENCIA: kexec reiniciara el sistema inmediatamente con el nuevo kernel${NC}"
    echo -e "${YELLOW}No hay rollback automatico - el sistema reiniciara sin apagar servicios limpiamente${NC}"
    echo ""
    read -p "¿Continuar con kexec test? [s/N]: " confirm
    if [[ ! "$confirm" =~ ^[sS]$ ]]; then
        echo "Test cancelado"
        return 0
    fi

    # Cargar kernel
    local kexec_args="-l $vmlinuz"
    [[ -f "$initrd" ]] && kexec_args+=" --initrd=$initrd"
    local cmdline=$(cat /proc/cmdline)
    kexec_args+=" --command-line='$cmdline'"

    echo "Cargando kernel..."
    eval kexec $kexec_args || { echo -e "${RED}Error cargando kernel${NC}"; return 1; }

    log_rollback "KEXEC_TEST: $(uname -r) -> $target_ver"
    echo "Kernel cargado. Ejecutando..."
    kexec -e
}

# ── Historial ─────────────────────────────────────────────
cmd_history() {
    echo ""
    echo -e "${BOLD}Historial de rollbacks:${NC}"
    echo ""
    if [[ -f "$ROLLBACK_LOG" ]]; then
        cat "$ROLLBACK_LOG"
    else
        echo "Sin historial registrado"
    fi
}

# ── Cleanup ───────────────────────────────────────────────
cmd_cleanup() {
    echo ""
    echo -e "${BOLD}Limpieza de kernels antiguos${NC}"
    echo ""

    local current=$(uname -r)
    local count=0
    local removable=()

    for img in /boot/vmlinuz-*; do
        [[ -f "$img" ]] && ((count++)) || true
    done

    echo "Kernels instalados: $count"
    echo "Minimo a mantener: $MIN_KERNELS"
    echo "Kernel actual: $current"
    echo ""

    if [[ $count -le $MIN_KERNELS ]]; then
        echo -e "${GREEN}No hay kernels para limpiar (ya en el minimo)${NC}"
        return 0
    fi

    # Listar candidatos para limpieza (los mas antiguos)
    for img in /boot/vmlinuz-*; do
        if [[ -f "$img" ]]; then
            local kver=$(basename "$img" | sed 's/vmlinuz-//')
            if [[ "$kver" != "$current" ]]; then
                removable+=("$kver")
            fi
        fi
    done

    echo "Kernels candidatos para limpieza:"
    for kver in "${removable[@]}"; do
        local date_mod=$(stat -c '%Y' "/boot/vmlinuz-$kver" 2>/dev/null)
        local date_fmt=$(date -d "@$date_mod" '+%Y-%m-%d' 2>/dev/null || echo "?")
        echo "  - $kver ($date_fmt)"
    done

    echo ""
    echo -e "${YELLOW}Usar el gestor de paquetes para eliminar kernels de forma segura${NC}"
    case "$DISTRO_FAMILY" in
        debian) echo "  apt-get autoremove --purge" ;;
        rhel)   echo "  dnf remove --oldinstallonly --setopt=installonly_limit=$MIN_KERNELS kernel" ;;
        suse)   echo "  zypper purge-kernels --keep $MIN_KERNELS" ;;
    esac
}

# ── Main ──────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Este script requiere permisos de root${NC}" >&2
    exit 1
fi

CMD="${1:-list}"
shift 2>/dev/null || true
case "$CMD" in
    list)     cmd_list ;;
    rollback) cmd_rollback "${1:-}" ;;
    grub)     cmd_grub ;;
    test)     cmd_test "${1:-}" ;;
    history)  cmd_history ;;
    cleanup)  cmd_cleanup ;;
    help|-h|--help) usage ;;
    *) echo "Comando desconocido: $CMD"; usage ;;
esac
EOFROLLBACK

    chmod +x /usr/local/bin/kernel-rollback.sh
    log_change "Creado" "/usr/local/bin/kernel-rollback.sh"

    # Mostrar kernels instalados actualmente
    log_info "Kernels instalados actualmente:"
    for img in /boot/vmlinuz-*; do
        if [[ -f "$img" ]]; then
            kver=$(basename "$img" | sed 's/vmlinuz-//')
            if [[ "$kver" == "$KERNEL_VERSION" ]]; then
                log_info "  * $kver (en uso)"
            else
                log_info "    $kver"
            fi
        fi
    done

    KERNEL_COUNT=$(ls /boot/vmlinuz-* 2>/dev/null | wc -l || echo "0")
    if [[ "$KERNEL_COUNT" -lt 2 ]]; then
        log_warn "Solo hay $KERNEL_COUNT kernel(s) instalado(s) - se recomienda mantener al menos 2"
    else
        log_info "Total kernels: $KERNEL_COUNT (minimo recomendado: 2)"
    fi

    log_info "Ejecuta 'kernel-rollback.sh list' para ver kernels disponibles"
    log_info "Ejecuta 'kernel-rollback.sh rollback' para hacer rollback"

else
    log_skip "Rollback seguro del kernel"
fi

# ============================================================
# S10: AUDITORIA Y SCORING INTEGRAL
# ============================================================
log_section "S10: AUDITORIA Y SCORING INTEGRAL"

echo "Crea /usr/local/bin/auditoria-livepatch.sh:"
echo "  - Auditoria integral: livepatch, mitigaciones, modulos"
echo "  - CVE exposure, Secure Boot, frescura del kernel"
echo "  - Puntuacion: BUENO / MEJORABLE / DEFICIENTE"
echo ""

if check_executable /usr/local/bin/auditoria-livepatch.sh; then
    log_already "Auditoria integral de live patching (auditoria-livepatch.sh existe)"
elif ask "¿Crear herramienta de auditoria integral de live patching?"; then

    cat > /usr/local/bin/auditoria-livepatch.sh << 'EOFAUDIT'
#!/bin/bash
# ============================================================
# auditoria-livepatch.sh - Auditoria integral de live patching
# Generado por securizar - Modulo 47
# ============================================================
set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

SCORE=0
MAX_SCORE=0
ISSUES=()
RECOMMENDATIONS=()

pass() { echo -e "  ${GREEN}[OK]${NC}    $1"; ((SCORE++)) || true; ((MAX_SCORE++)) || true; }
fail() { echo -e "  ${RED}[FAIL]${NC}  $1"; ISSUES+=("$1"); ((MAX_SCORE++)) || true; }
warn() { echo -e "  ${YELLOW}[WARN]${NC}  $1"; ((MAX_SCORE++)) || true; }
info() { echo -e "  ${DIM}[INFO]${NC}  $1"; }
recommend() { RECOMMENDATIONS+=("$1"); }

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   AUDITORIA INTEGRAL - KERNEL LIVE PATCHING              ║"
echo "║   Modulo 47 - securizar                                   ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo -e "${BOLD}Fecha:${NC}     $(date '+%Y-%m-%d %H:%M:%S')"
echo -e "${BOLD}Kernel:${NC}    $(uname -r)"
echo -e "${BOLD}Hostname:${NC}  $(hostname)"
echo ""

# ═══════════════════════════════════════════════════════════
# AREA 1: LIVE PATCHING
# ═══════════════════════════════════════════════════════════
echo -e "${CYAN}═══ AREA 1: LIVE PATCHING ═════════════════════════════${NC}"
echo ""

# Verificar soporte de livepatch en kernel
KCONFIG="/boot/config-$(uname -r)"
LIVEPATCH_SUPPORT=0
if [[ -d /sys/kernel/livepatch ]]; then
    LIVEPATCH_SUPPORT=1
elif [[ -f "$KCONFIG" ]] && grep -q "CONFIG_LIVEPATCH=y" "$KCONFIG"; then
    LIVEPATCH_SUPPORT=1
elif [[ -f /proc/config.gz ]] && zcat /proc/config.gz 2>/dev/null | grep -q "CONFIG_LIVEPATCH=y"; then
    LIVEPATCH_SUPPORT=1
fi

if [[ $LIVEPATCH_SUPPORT -eq 1 ]]; then
    pass "Kernel soporta live patching (CONFIG_LIVEPATCH)"
else
    fail "Kernel no soporta live patching"
    recommend "Recompilar kernel con CONFIG_LIVEPATCH=y o usar kernel de distro"
fi

# Verificar herramientas de livepatch
if command -v kpatch &>/dev/null; then
    pass "kpatch instalado"
    KPATCH_LIST=$(kpatch list 2>/dev/null || echo "")
    if [[ -n "$KPATCH_LIST" ]] && ! echo "$KPATCH_LIST" | grep -q "No loaded"; then
        pass "Parches kpatch activos"
    else
        warn "kpatch instalado pero sin parches activos"
    fi
elif command -v canonical-livepatch &>/dev/null; then
    pass "canonical-livepatch instalado"
    CLP_STATUS=$(canonical-livepatch status 2>/dev/null || echo "")
    if echo "$CLP_STATUS" | grep -qi "running\|enabled"; then
        pass "canonical-livepatch activo"
    else
        warn "canonical-livepatch instalado pero no activo"
        recommend "Activar: canonical-livepatch enable <TOKEN>"
    fi
else
    fail "Ningun framework de live patching instalado"
    recommend "Instalar kpatch o canonical-livepatch"
fi

# Verificar configuracion
if [[ -f /etc/securizar/livepatch.conf ]]; then
    pass "Configuracion de livepatch presente (/etc/securizar/livepatch.conf)"
else
    warn "Sin configuracion de livepatch"
fi

# ═══════════════════════════════════════════════════════════
# AREA 2: MITIGACIONES DE EXPLOITS
# ═══════════════════════════════════════════════════════════
echo ""
echo -e "${CYAN}═══ AREA 2: MITIGACIONES DE EXPLOITS ═════════════════${NC}"
echo ""

check_sysctl_audit() {
    local param="$1" expected="$2" desc="$3"
    local actual=$(sysctl -n "$param" 2>/dev/null || echo "N/A")
    if [[ "$actual" == "$expected" ]]; then
        pass "$desc ($param=$actual)"
    elif [[ "$actual" == "N/A" ]]; then
        warn "$desc ($param no disponible)"
    else
        fail "$desc ($param=$actual, esperado=$expected)"
        recommend "sysctl -w $param=$expected"
    fi
}

check_sysctl_audit "kernel.kptr_restrict" "2" "Punteros kernel ocultos"
check_sysctl_audit "kernel.dmesg_restrict" "1" "dmesg restringido"
check_sysctl_audit "kernel.perf_event_paranoid" "3" "perf_event restrictivo"
check_sysctl_audit "kernel.yama.ptrace_scope" "2" "ptrace restringido"
check_sysctl_audit "kernel.unprivileged_bpf_disabled" "1" "BPF sin privilegios deshabilitado"
check_sysctl_audit "kernel.kexec_load_disabled" "1" "kexec deshabilitado"
check_sysctl_audit "vm.mmap_min_addr" "65536" "mmap_min_addr"
check_sysctl_audit "kernel.sysrq" "0" "SysRq deshabilitado"
check_sysctl_audit "fs.protected_hardlinks" "1" "Hardlinks protegidos"
check_sysctl_audit "fs.protected_symlinks" "1" "Symlinks protegidos"
check_sysctl_audit "fs.protected_fifos" "2" "FIFOs protegidos"
check_sysctl_audit "fs.protected_regular" "2" "Regular files protegidos"
check_sysctl_audit "kernel.randomize_va_space" "2" "ASLR completo"
check_sysctl_audit "fs.suid_dumpable" "0" "Core dumps SUID deshabilitados"

# Verificar archivo de sysctl persistente
if [[ -f /etc/sysctl.d/99-securizar-kernel-exploit.conf ]]; then
    pass "Configuracion sysctl persistente presente"
else
    fail "Sin configuracion sysctl de hardening persistente"
    recommend "Ejecutar modulo 47 seccion S3 de securizar"
fi

# ═══════════════════════════════════════════════════════════
# AREA 3: MODULOS HARDENED
# ═══════════════════════════════════════════════════════════
echo ""
echo -e "${CYAN}═══ AREA 3: HARDENING DE MODULOS ═════════════════════${NC}"
echo ""

# Verificar blacklist
if [[ -f /etc/modprobe.d/securizar-blacklist.conf ]]; then
    pass "Blacklist de modulos presente"

    # Verificar modulos peligrosos
    DANGEROUS_LOADED=0
    for mod in firewire-core thunderbolt cramfs freevxfs jffs2 hfs hfsplus dccp sctp rds tipc; do
        mod_underscore="${mod//-/_}"
        if lsmod | grep -q "^${mod_underscore}"; then
            fail "Modulo peligroso cargado: $mod"
            ((DANGEROUS_LOADED++)) || true
        fi
    done
    if [[ $DANGEROUS_LOADED -eq 0 ]]; then
        pass "Ningun modulo peligroso cargado"
    fi
else
    fail "Sin blacklist de modulos"
    recommend "Ejecutar modulo 47 seccion S4 de securizar"
fi

# Firma de modulos
if [[ -f "$KCONFIG" ]]; then
    if grep -q "CONFIG_MODULE_SIG=y" "$KCONFIG"; then
        pass "Firma de modulos habilitada"
    else
        fail "Firma de modulos no habilitada"
    fi
    if grep -q "CONFIG_MODULE_SIG_FORCE=y" "$KCONFIG"; then
        pass "Firma de modulos obligatoria"
    else
        warn "Firma de modulos no es obligatoria"
    fi
fi

# ═══════════════════════════════════════════════════════════
# AREA 4: EXPOSICION A CVES
# ═══════════════════════════════════════════════════════════
echo ""
echo -e "${CYAN}═══ AREA 4: EXPOSICION A CVES ════════════════════════${NC}"
echo ""

# Vulnerabilidades CPU
VULN_COUNT=0
VULN_MITIGATED=0
VULN_EXPOSED=0
if [[ -d /sys/devices/system/cpu/vulnerabilities ]]; then
    for vuln_file in /sys/devices/system/cpu/vulnerabilities/*; do
        ((VULN_COUNT++)) || true
        status=$(cat "$vuln_file" 2>/dev/null || echo "unknown")
        name=$(basename "$vuln_file")
        if echo "$status" | grep -qi "vulnerable"; then
            ((VULN_EXPOSED++)) || true
            fail "CPU vulnerable: $name"
        elif echo "$status" | grep -qi "mitigation\|not affected"; then
            ((VULN_MITIGATED++)) || true
        fi
    done

    if [[ $VULN_EXPOSED -eq 0 ]]; then
        pass "Todas las vulnerabilidades CPU mitigadas/no afectadas ($VULN_MITIGATED/$VULN_COUNT)"
    else
        recommend "Actualizar kernel y microcodigo CPU para mitigar vulnerabilidades"
    fi
else
    warn "No se pudo verificar vulnerabilidades CPU"
fi

# Verificar ultimo escaneo de CVEs
if [[ -f /var/log/securizar/kernel-cves.json ]]; then
    pass "Escaneo de CVEs disponible"
    scan_date=$(grep -o '"timestamp":"[^"]*"' /var/log/securizar/kernel-cves.json 2>/dev/null | head -1 | cut -d'"' -f4)
    info "Ultimo escaneo: ${scan_date:-desconocido}"
else
    warn "Sin escaneo de CVEs realizado"
    recommend "Ejecutar: monitorizar-cves-kernel.sh --update --scan"
fi

# ═══════════════════════════════════════════════════════════
# AREA 5: SECURE BOOT
# ═══════════════════════════════════════════════════════════
echo ""
echo -e "${CYAN}═══ AREA 5: SECURE BOOT ══════════════════════════════${NC}"
echo ""

if [[ -d /sys/firmware/efi ]]; then
    pass "Sistema UEFI"
    if command -v mokutil &>/dev/null; then
        SB=$(mokutil --sb-state 2>/dev/null || echo "")
        if echo "$SB" | grep -qi "SecureBoot enabled"; then
            pass "Secure Boot habilitado"
        elif echo "$SB" | grep -qi "SecureBoot disabled"; then
            fail "Secure Boot deshabilitado"
            recommend "Habilitar Secure Boot en BIOS/UEFI"
        else
            warn "Estado de Secure Boot indeterminado"
        fi
    else
        warn "mokutil no instalado"
        recommend "Instalar mokutil para verificar Secure Boot"
    fi
else
    info "Sistema BIOS legacy (Secure Boot no aplicable)"
fi

# Lockdown
if [[ -f /sys/kernel/security/lockdown ]]; then
    LOCKDOWN=$(cat /sys/kernel/security/lockdown)
    if echo "$LOCKDOWN" | grep -q "\[integrity\]\|\[confidentiality\]"; then
        pass "Kernel lockdown activo: $LOCKDOWN"
    else
        fail "Kernel lockdown deshabilitado"
        recommend "Habilitar lockdown: echo integrity > /sys/kernel/security/lockdown"
    fi
else
    warn "Kernel lockdown no disponible"
fi

# ═══════════════════════════════════════════════════════════
# AREA 6: FRESCURA DEL KERNEL
# ═══════════════════════════════════════════════════════════
echo ""
echo -e "${CYAN}═══ AREA 6: FRESCURA DEL KERNEL ═══════════════════════${NC}"
echo ""

KERNEL_FILE="/boot/vmlinuz-$(uname -r)"
if [[ -f "$KERNEL_FILE" ]]; then
    INSTALL_EPOCH=$(stat -c '%Y' "$KERNEL_FILE" 2>/dev/null || echo "0")
    NOW=$(date +%s)
    DAYS_OLD=$(( (NOW - INSTALL_EPOCH) / 86400 ))
    info "Kernel instalado hace $DAYS_OLD dias"

    if [[ $DAYS_OLD -le 30 ]]; then
        pass "Kernel reciente ($DAYS_OLD dias)"
    elif [[ $DAYS_OLD -le 90 ]]; then
        warn "Kernel moderadamente antiguo ($DAYS_OLD dias)"
        recommend "Considerar actualizar el kernel"
    else
        fail "Kernel antiguo ($DAYS_OLD dias, >90 dias)"
        recommend "Actualizar kernel urgentemente"
    fi
else
    warn "No se pudo determinar edad del kernel"
fi

# Verificar si hay actualizacion pendiente
if [[ -f /var/run/reboot-required ]]; then
    warn "Reinicio pendiente - hay un kernel nuevo instalado"
    recommend "Reiniciar para aplicar nuevo kernel"
fi

# Verificar politica de actualizacion
if [[ -f /etc/securizar/kernel-update-policy.conf ]]; then
    pass "Politica de actualizacion configurada"
else
    warn "Sin politica de actualizacion"
    recommend "Ejecutar modulo 47 seccion S7 de securizar"
fi

# Verificar validador
if [[ -x /usr/local/bin/validar-kernel-params.sh ]]; then
    pass "Validador de parametros instalado"
else
    warn "Validador de parametros no instalado"
    recommend "Ejecutar modulo 47 seccion S5 de securizar"
fi

# Verificar rollback
if [[ -x /usr/local/bin/kernel-rollback.sh ]]; then
    pass "Herramienta de rollback instalada"
else
    warn "Herramienta de rollback no instalada"
fi

# Kernels disponibles
KERNEL_COUNT=$(ls /boot/vmlinuz-* 2>/dev/null | wc -l || echo "0")
if [[ "$KERNEL_COUNT" -ge 2 ]]; then
    pass "Multiples kernels disponibles ($KERNEL_COUNT)"
else
    fail "Solo $KERNEL_COUNT kernel(s) - riesgo de no poder hacer rollback"
    recommend "Mantener al menos 2 kernels instalados"
fi

# ═══════════════════════════════════════════════════════════
# RESULTADO FINAL
# ═══════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo ""

if [[ $MAX_SCORE -gt 0 ]]; then
    PERCENTAGE=$(( (SCORE * 100) / MAX_SCORE ))
else
    PERCENTAGE=0
fi

echo -e "${BOLD}PUNTUACION INTEGRAL DE SEGURIDAD DEL KERNEL${NC}"
echo ""
echo -e "  Verificaciones pasadas: ${GREEN}$SCORE${NC} / $MAX_SCORE"
echo -e "  Problemas detectados:   ${RED}${#ISSUES[@]}${NC}"
echo -e "  Porcentaje:             ${BOLD}$PERCENTAGE%${NC}"
echo ""

# Barra visual
BAR_LEN=40
FILLED=$(( (PERCENTAGE * BAR_LEN) / 100 ))
EMPTY=$(( BAR_LEN - FILLED ))
BAR=""
for ((i=0; i<FILLED; i++)); do BAR+="█"; done
for ((i=0; i<EMPTY; i++)); do BAR+="░"; done

if [[ $PERCENTAGE -ge 80 ]]; then
    echo -e "  ${GREEN}[$BAR]${NC} $PERCENTAGE%"
    echo ""
    echo -e "  ${GREEN}${BOLD}╔═══════════════════════════════════════╗${NC}"
    echo -e "  ${GREEN}${BOLD}║         RESULTADO: BUENO              ║${NC}"
    echo -e "  ${GREEN}${BOLD}╚═══════════════════════════════════════╝${NC}"
elif [[ $PERCENTAGE -ge 50 ]]; then
    echo -e "  ${YELLOW}[$BAR]${NC} $PERCENTAGE%"
    echo ""
    echo -e "  ${YELLOW}${BOLD}╔═══════════════════════════════════════╗${NC}"
    echo -e "  ${YELLOW}${BOLD}║       RESULTADO: MEJORABLE            ║${NC}"
    echo -e "  ${YELLOW}${BOLD}╚═══════════════════════════════════════╝${NC}"
else
    echo -e "  ${RED}[$BAR]${NC} $PERCENTAGE%"
    echo ""
    echo -e "  ${RED}${BOLD}╔═══════════════════════════════════════╗${NC}"
    echo -e "  ${RED}${BOLD}║      RESULTADO: DEFICIENTE            ║${NC}"
    echo -e "  ${RED}${BOLD}╚═══════════════════════════════════════╝${NC}"
fi

if [[ ${#ISSUES[@]} -gt 0 ]]; then
    echo ""
    echo -e "${RED}${BOLD}Problemas detectados:${NC}"
    for issue in "${ISSUES[@]}"; do
        echo -e "  ${RED}✗${NC} $issue"
    done
fi

if [[ ${#RECOMMENDATIONS[@]} -gt 0 ]]; then
    echo ""
    echo -e "${CYAN}${BOLD}Recomendaciones:${NC}"
    idx=1
    for rec in "${RECOMMENDATIONS[@]}"; do
        echo -e "  ${CYAN}$idx.${NC} $rec"
        ((idx++)) || true
    done
fi

echo ""

# Guardar resultado JSON
mkdir -p /var/log/securizar
cat > /var/log/securizar/kernel-audit-integral.json << EOFJSONAUDIT
{
  "timestamp": "$(date -Iseconds)",
  "kernel_version": "$(uname -r)",
  "hostname": "$(hostname)",
  "score": $SCORE,
  "max_score": $MAX_SCORE,
  "percentage": $PERCENTAGE,
  "issues_count": ${#ISSUES[@]},
  "recommendations_count": ${#RECOMMENDATIONS[@]},
  "areas": {
    "livepatch": "checked",
    "exploit_mitigations": "checked",
    "module_hardening": "checked",
    "cve_exposure": "checked",
    "secure_boot": "checked",
    "kernel_freshness": "checked"
  }
}
EOFJSONAUDIT

echo "Informe guardado en: /var/log/securizar/kernel-audit-integral.json"
echo ""
EOFAUDIT

    chmod +x /usr/local/bin/auditoria-livepatch.sh
    log_change "Creado" "/usr/local/bin/auditoria-livepatch.sh"

    # Crear cron mensual
    cat > /etc/cron.monthly/securizar-kernel-audit << 'EOFCRONAUDIT'
#!/bin/bash
# Auditoria mensual de seguridad del kernel - securizar Modulo 47
/usr/local/bin/auditoria-livepatch.sh >> /var/log/securizar/kernel-audit-monthly.log 2>&1
EOFCRONAUDIT
    chmod +x /etc/cron.monthly/securizar-kernel-audit
    log_change "Creado" "/etc/cron.monthly/securizar-kernel-audit"

    log_info "Ejecuta 'auditoria-livepatch.sh' para auditoria integral"

else
    log_skip "Auditoria integral de live patching"
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
show_changes_summary
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     KERNEL LIVE PATCHING COMPLETADO                      ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups guardados en: $BACKUP_DIR"
echo ""
echo "Comandos utiles post-configuracion:"
echo "  - Auditar kernel:          auditar-kernel.sh"
echo "  - Validar parametros:      validar-kernel-params.sh"
echo "  - Monitorizar CVEs:        monitorizar-cves-kernel.sh --update --scan"
echo "  - Gestionar updates:       gestionar-kernel-updates.sh check"
echo "  - Verificar Secure Boot:   verificar-secure-boot.sh"
echo "  - Rollback de kernel:      kernel-rollback.sh list"
echo "  - Auditoria integral:      auditoria-livepatch.sh"
echo ""
log_warn "RECOMENDACION: Ejecuta 'auditoria-livepatch.sh' para ver la postura actual"
log_info "Modulo 47 completado"
echo ""
