#!/bin/bash
# ============================================================
# integridad-arranque.sh - Modulo 73: Integridad de Arranque
# ============================================================
# Secciones:
#   S1  - Estado Secure Boot
#   S2  - UEFI hardening
#   S3  - GRUB2 hardening
#   S4  - Verificacion de kernel
#   S5  - dm-verity para particiones
#   S6  - IMA/EVM
#   S7  - TPM2 integration
#   S8  - Deteccion de bootkits
#   S9  - Measured Boot logging
#   S10 - Auditoria integral arranque
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "boot-integrity"
securizar_setup_traps

# ── Pre-check: detectar secciones ya aplicadas ──────────────
_precheck 10
_pc 'check_executable /usr/local/bin/securizar-secureboot-check.sh'
_pc 'check_file_exists /etc/securizar/boot/uefi-hardening.conf'
_pc 'check_file_exists /etc/securizar/boot/grub2-hardening.conf'
_pc 'check_executable /usr/local/bin/securizar-kernel-verify.sh'
_pc 'check_file_exists /etc/securizar/boot/dm-verity.conf'
_pc 'check_file_exists /etc/securizar/boot/ima-evm.conf'
_pc 'check_executable /usr/local/bin/securizar-tpm2-check.sh'
_pc 'check_executable /usr/local/bin/securizar-bootkit-detect.sh'
_pc 'check_file_exists /etc/securizar/boot/measured-boot.conf'
_pc 'check_executable /usr/local/bin/auditoria-boot-completa.sh'
_precheck_result

log_section "MODULO 73: INTEGRIDAD DE ARRANQUE"
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

BOOT_DIR="/etc/securizar/boot"
BOOT_BIN="/usr/local/bin"
BOOT_LOG="/var/log/securizar/boot"
mkdir -p "$BOOT_DIR" "$BOOT_LOG" || true

# ============================================================
# S1: ESTADO SECURE BOOT
# ============================================================
log_section "S1: Estado Secure Boot"

log_info "Verifica el estado de Secure Boot y sus bases de datos."
log_info "  - mokutil --sb-state, variables EFI"
log_info "  - Claves db/dbx/KEK/PK"
log_info ""

if check_executable /usr/local/bin/securizar-secureboot-check.sh; then
    log_already "Estado Secure Boot (securizar-secureboot-check.sh existe)"
elif ask "Crear herramienta de verificacion de Secure Boot?"; then

    cat > "$BOOT_BIN/securizar-secureboot-check.sh" << 'EOFSB'
#!/bin/bash
# ============================================================
# securizar-secureboot-check.sh - Estado de Secure Boot
# ============================================================
set -euo pipefail

RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"
CYAN="\033[0;36m"; BOLD="\033[1m"; DIM="\033[2m"; NC="\033[0m"

LOG_DIR="/var/log/securizar/boot"; mkdir -p "$LOG_DIR"
REPORT="$LOG_DIR/secureboot-$(date +%Y%m%d-%H%M%S).log"
log_r() { echo -e "$1" | tee -a "$REPORT"; }

log_r "${BOLD}=== ESTADO DE SECURE BOOT ===${NC}"
log_r "Fecha: $(date '+%Y-%m-%d %H:%M:%S') | Host: $(hostname)"
log_r ""

SCORE=0; MAX=0

# 1. Modo UEFI vs BIOS
MAX=$((MAX + 1))
if [[ -d /sys/firmware/efi ]]; then
    log_r "  ${GREEN}[OK]${NC} Sistema arrancado en modo UEFI"
    SCORE=$((SCORE + 1))
else
    log_r "  ${YELLOW}[!!]${NC} Sistema en modo BIOS/Legacy (Secure Boot no disponible)"
    log_r ""; log_r "Reporte: $REPORT"; exit 0
fi

# 2. Secure Boot habilitado
MAX=$((MAX + 1))
if command -v mokutil &>/dev/null; then
    sb_state=$(mokutil --sb-state 2>/dev/null || echo "unknown")
    log_r "  mokutil: $sb_state"
    if echo "$sb_state" | grep -qi "enabled"; then
        log_r "  ${GREEN}[OK]${NC} Secure Boot habilitado"
        SCORE=$((SCORE + 1))
    else
        log_r "  ${YELLOW}[!!]${NC} Secure Boot NO habilitado"
    fi
elif [[ -f /sys/firmware/efi/efivars/SecureBoot-* ]] 2>/dev/null; then
    sb_var=$(find /sys/firmware/efi/efivars/ -name 'SecureBoot-*' 2>/dev/null | head -1)
    if [[ -n "$sb_var" ]]; then
        val=$(od -An -t u1 "$sb_var" 2>/dev/null | awk '{print $NF}')
        if [[ "$val" == "1" ]]; then
            log_r "  ${GREEN}[OK]${NC} Secure Boot habilitado (EFI var)"
            SCORE=$((SCORE + 1))
        else
            log_r "  ${YELLOW}[!!]${NC} Secure Boot deshabilitado (EFI var=$val)"
        fi
    fi
else
    log_r "  ${DIM}mokutil no disponible, no se puede verificar${NC}"
fi

# 3. Bases de datos de claves
MAX=$((MAX + 1))
log_r ""; log_r "${CYAN}=== Bases de datos de claves ===${NC}"
keys_ok=0
for var in PK KEK db dbx; do
    found=$(find /sys/firmware/efi/efivars/ -name "${var}-*" 2>/dev/null | head -1)
    if [[ -n "$found" ]]; then
        size=$(stat -c%s "$found" 2>/dev/null || echo "?")
        log_r "  ${GREEN}[OK]${NC} $var presente (${size} bytes)"
        keys_ok=$((keys_ok + 1))
    else
        log_r "  ${YELLOW}[--]${NC} $var no encontrado"
    fi
done
[[ $keys_ok -ge 3 ]] && SCORE=$((SCORE + 1))

# 4. MOK (Machine Owner Key)
MAX=$((MAX + 1))
if command -v mokutil &>/dev/null; then
    mok_count=$(mokutil --list-enrolled 2>/dev/null | grep -c "Subject:" || echo "0")
    log_r ""; log_r "  MOK enrolladas: $mok_count"
    [[ "$mok_count" -gt 0 ]] && SCORE=$((SCORE + 1))
fi

# Resumen
log_r ""; log_r "${BOLD}===============================${NC}"
PCT=0; [[ $MAX -gt 0 ]] && PCT=$((SCORE * 100 / MAX))
if [[ $PCT -ge 70 ]]; then
    log_r "  ${GREEN}Puntuacion: ${SCORE}/${MAX} (${PCT}%) - BUENO${NC}"
elif [[ $PCT -ge 40 ]]; then
    log_r "  ${YELLOW}Puntuacion: ${SCORE}/${MAX} (${PCT}%) - MEJORABLE${NC}"
else
    log_r "  ${RED}Puntuacion: ${SCORE}/${MAX} (${PCT}%) - DEFICIENTE${NC}"
fi
log_r "Reporte: $REPORT"
EOFSB
    chmod +x "$BOOT_BIN/securizar-secureboot-check.sh"
    log_change "Creado" "$BOOT_BIN/securizar-secureboot-check.sh"

else
    log_skip "Estado Secure Boot"
fi

# ============================================================
# S2: UEFI HARDENING
# ============================================================
log_section "S2: UEFI hardening"

log_info "Documenta recomendaciones de hardening UEFI."
log_info "  - Desactivar EFI Shell, proteger variables"
log_info "  - Password de Setup, boot order fijo"
log_info ""

if check_file_exists /etc/securizar/boot/uefi-hardening.conf; then
    log_already "UEFI hardening (uefi-hardening.conf existe)"
elif ask "Crear guia de hardening UEFI?"; then

    cat > "$BOOT_DIR/uefi-hardening.conf" << 'EOFUEFI'
# ============================================================
# uefi-hardening.conf - Recomendaciones de hardening UEFI
# ============================================================
# Generado por securizar - Modulo 73
# NOTA: Estos cambios se aplican desde BIOS/UEFI Setup,
# no pueden modificarse de forma segura desde el SO.

# === 1. Secure Boot ===
# - Habilitar Secure Boot en modo User/Deployed
# - No usar modo Setup/Audit salvo para enrollar claves
# - Mantener dbx (lista de revocacion) actualizada
#   Fuente: https://uefi.org/revocationlistfile

# === 2. Password de Setup ===
# - Establecer password de administrador en UEFI Setup
# - Usar password fuerte (>12 caracteres)
# - Diferente al password de disco/SO

# === 3. Boot Order ===
# - Establecer disco interno como unica opcion de arranque
# - Deshabilitar arranque por USB/CD/Red (PXE)
# - Si se necesita PXE, habilitar solo temporalmente

# === 4. EFI Shell ===
# - Deshabilitar EFI Shell integrado
# - Eliminar Shell.efi del ESP si existe
# - Verificar: ls /boot/efi/EFI/*/Shell*.efi

# === 5. Variables UEFI ===
# - Proteger variables con efi_attr=EFI_VARIABLE_NON_VOLATILE
# - Monitorizar cambios en /sys/firmware/efi/efivars/
# - No exponer efivars a usuarios no-root

# === 6. TPM ===
# - Habilitar TPM 2.0 en UEFI
# - Activar SHA-256 (no solo SHA-1)
# - Vincular Secure Boot a PCR[7]

# === 7. Intel Boot Guard / AMD PSB ===
# - Verificar si el hardware soporta Boot Guard
# - Solo aplicable si el OEM lo configuro en fabrica
# - dmesg | grep -i "boot guard"
EOFUEFI
    chmod 0640 "$BOOT_DIR/uefi-hardening.conf"
    log_change "Creado" "$BOOT_DIR/uefi-hardening.conf"

    # Verificar Shell.efi en ESP
    if [[ -d /boot/efi/EFI ]]; then
        shell_efi=$(find /boot/efi/EFI -iname 'Shell*.efi' 2>/dev/null || true)
        if [[ -n "$shell_efi" ]]; then
            log_info "ALERTA: EFI Shell encontrado en ESP:"
            log_info "  $shell_efi"
            log_info "  Considere eliminarlo para mayor seguridad"
        fi
    fi

else
    log_skip "UEFI hardening"
fi

# ============================================================
# S3: GRUB2 HARDENING
# ============================================================
log_section "S3: GRUB2 hardening"

log_info "Asegura GRUB2 contra modificacion no autorizada."
log_info "  - Password de GRUB, restringir edicion"
log_info "  - grub2-setpassword si disponible"
log_info ""

if check_file_exists /etc/securizar/boot/grub2-hardening.conf; then
    log_already "GRUB2 hardening (grub2-hardening.conf existe)"
elif ask "Configurar hardening de GRUB2?"; then

    cat > "$BOOT_DIR/grub2-hardening.conf" << 'EOFGRUB'
# ============================================================
# grub2-hardening.conf - Directivas de seguridad GRUB2
# ============================================================
# Generado por securizar - Modulo 73

# === 1. Password de GRUB ===
# Impide editar entradas de arranque sin password.
#
# Metodo 1 (recomendado en RHEL/SUSE):
#   grub2-setpassword
#   -> Crea /boot/grub2/user.cfg con GRUB2_PASSWORD=grub.pbkdf2...
#
# Metodo 2 (manual, Debian/Ubuntu):
#   grub-mkpasswd-pbkdf2
#   -> Genera hash, agregar a /etc/grub.d/40_custom:
#      set superusers="admin"
#      password_pbkdf2 admin grub.pbkdf2.sha512.10000.HASH
#   -> update-grub

# === 2. Restringir edicion ===
# En /etc/grub.d/10_linux, las entradas deben tener:
#   --unrestricted  = arranque sin password, edicion con password
#   (sin flag)      = todo requiere password
# Recomendacion: usar --unrestricted para arranque normal

# === 3. Permisos de ficheros ===
# chmod 600 /boot/grub2/grub.cfg
# chmod 600 /boot/grub2/user.cfg (si existe)
# chown root:root /boot/grub2/grub.cfg

# === 4. Modulos de GRUB ===
# Minimizar modulos cargados. No incluir:
#   - shell, chain (salvo dual-boot necesario)
#   - net (salvo PXE)
#   - http, tftp

# === 5. Kernel command line ===
# En GRUB_CMDLINE_LINUX (via /etc/default/grub):
#   module.sig_enforce=1    - Solo modulos firmados
#   lockdown=confidentiality - Kernel lockdown
#   slab_nomerge            - Mitigar heap exploits
#   init_on_alloc=1         - Limpiar memoria
#   iommu=force             - Proteccion DMA
EOFGRUB
    chmod 0640 "$BOOT_DIR/grub2-hardening.conf"
    log_change "Creado" "$BOOT_DIR/grub2-hardening.conf"

    # Asegurar permisos del grub.cfg existente
    for grub_cfg in /boot/grub2/grub.cfg /boot/grub/grub.cfg; do
        if [[ -f "$grub_cfg" ]]; then
            current_perms=$(stat -c '%a' "$grub_cfg" 2>/dev/null || echo "???")
            if [[ "$current_perms" != "600" ]]; then
                backup_file "$grub_cfg"
                chmod 600 "$grub_cfg"
                log_change "Permisos" "$grub_cfg -> 600 (era $current_perms)"
            fi
            break
        fi
    done

else
    log_skip "GRUB2 hardening"
fi

# ============================================================
# S4: VERIFICACION DE KERNEL
# ============================================================
log_section "S4: Verificacion de kernel"

log_info "Verifica firma del kernel y modulos cargados."
log_info "  - module.sig_enforce, modulos firmados"
log_info "  - Kernel lockdown mode"
log_info ""

if check_executable /usr/local/bin/securizar-kernel-verify.sh; then
    log_already "Verificacion de kernel (securizar-kernel-verify.sh existe)"
elif ask "Crear herramienta de verificacion de kernel?"; then

    cat > "$BOOT_BIN/securizar-kernel-verify.sh" << 'EOFKVER'
#!/bin/bash
# ============================================================
# securizar-kernel-verify.sh - Verificacion de integridad del kernel
# ============================================================
set -euo pipefail

RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"
CYAN="\033[0;36m"; BOLD="\033[1m"; DIM="\033[2m"; NC="\033[0m"

LOG_DIR="/var/log/securizar/boot"; mkdir -p "$LOG_DIR"
REPORT="$LOG_DIR/kernel-verify-$(date +%Y%m%d-%H%M%S).log"
log_r() { echo -e "$1" | tee -a "$REPORT"; }

log_r "${BOLD}=== VERIFICACION DE KERNEL ===${NC}"
log_r "Fecha: $(date) | Kernel: $(uname -r)"
log_r ""

SCORE=0; MAX=0

# 1. module.sig_enforce
MAX=$((MAX + 1))
sig_enforce=$(cat /proc/cmdline 2>/dev/null | tr ' ' '\n' | grep "module.sig_enforce" || true)
if [[ -n "$sig_enforce" ]]; then
    log_r "  ${GREEN}[OK]${NC} module.sig_enforce presente en cmdline"
    SCORE=$((SCORE + 1))
else
    sig_file="/proc/sys/kernel/module_sig_enforce"
    if [[ -f "$sig_file" ]] && [[ "$(cat "$sig_file" 2>/dev/null)" == "1" ]]; then
        log_r "  ${GREEN}[OK]${NC} module_sig_enforce=1 (sysctl)"
        SCORE=$((SCORE + 1))
    else
        log_r "  ${YELLOW}[!!]${NC} module.sig_enforce no activo"
    fi
fi

# 2. Kernel lockdown
MAX=$((MAX + 1))
lockdown_file="/sys/kernel/security/lockdown"
if [[ -f "$lockdown_file" ]]; then
    lockdown=$(cat "$lockdown_file" 2>/dev/null)
    if echo "$lockdown" | grep -qE '\[(integrity|confidentiality)\]'; then
        log_r "  ${GREEN}[OK]${NC} Kernel lockdown: $lockdown"
        SCORE=$((SCORE + 1))
    else
        log_r "  ${YELLOW}[!!]${NC} Kernel lockdown: $lockdown"
    fi
else
    log_r "  ${DIM}Lockdown no disponible en este kernel${NC}"
fi

# 3. Modulos firmados
MAX=$((MAX + 1))
log_r ""; log_r "${CYAN}=== Modulos cargados ===${NC}"
total_mods=$(lsmod | tail -n +2 | wc -l)
unsigned=0
while IFS= read -r mod; do
    mod_name=$(echo "$mod" | awk '{print $1}')
    info=$(modinfo "$mod_name" 2>/dev/null || true)
    if ! echo "$info" | grep -q "sig_id:"; then
        unsigned=$((unsigned + 1))
    fi
done < <(lsmod | tail -n +2 | head -50)
signed=$((total_mods - unsigned))
log_r "  Total modulos: $total_mods | Firmados: $signed | Sin firma: $unsigned"
if [[ "$unsigned" -eq 0 ]]; then
    log_r "  ${GREEN}[OK]${NC} Todos los modulos verificados tienen firma"
    SCORE=$((SCORE + 1))
else
    log_r "  ${YELLOW}[!!]${NC} $unsigned modulos sin firma detectados"
fi

# 4. Tainted kernel
MAX=$((MAX + 1))
tainted=$(cat /proc/sys/kernel/tainted 2>/dev/null || echo "?")
if [[ "$tainted" == "0" ]]; then
    log_r "  ${GREEN}[OK]${NC} Kernel no tainted (valor: 0)"
    SCORE=$((SCORE + 1))
else
    log_r "  ${YELLOW}[!!]${NC} Kernel tainted (valor: $tainted)"
fi

# Resumen
log_r ""; log_r "${BOLD}===============================${NC}"
PCT=0; [[ $MAX -gt 0 ]] && PCT=$((SCORE * 100 / MAX))
if [[ $PCT -ge 70 ]]; then
    log_r "  ${GREEN}Puntuacion: ${SCORE}/${MAX} (${PCT}%) - BUENO${NC}"
elif [[ $PCT -ge 40 ]]; then
    log_r "  ${YELLOW}Puntuacion: ${SCORE}/${MAX} (${PCT}%) - MEJORABLE${NC}"
else
    log_r "  ${RED}Puntuacion: ${SCORE}/${MAX} (${PCT}%) - DEFICIENTE${NC}"
fi
log_r "Reporte: $REPORT"
EOFKVER
    chmod +x "$BOOT_BIN/securizar-kernel-verify.sh"
    log_change "Creado" "$BOOT_BIN/securizar-kernel-verify.sh"

else
    log_skip "Verificacion de kernel"
fi

# ============================================================
# S5: DM-VERITY PARA PARTICIONES
# ============================================================
log_section "S5: dm-verity para particiones"

log_info "Documenta configuracion de dm-verity para integridad de particiones."
log_info "  - Verificacion de bloques en particiones read-only"
log_info "  - Setup con veritysetup"
log_info ""

if check_file_exists /etc/securizar/boot/dm-verity.conf; then
    log_already "dm-verity (dm-verity.conf existe)"
elif ask "Crear documentacion de dm-verity?"; then

    cat > "$BOOT_DIR/dm-verity.conf" << 'EOFVERITY'
# ============================================================
# dm-verity.conf - Configuracion de dm-verity
# ============================================================
# Generado por securizar - Modulo 73
#
# dm-verity proporciona verificacion de integridad por bloques
# para particiones de solo lectura. Cada lectura se verifica
# contra un arbol de hashes Merkle.

# === Requisitos ===
# - Paquete: cryptsetup (contiene veritysetup)
# - Kernel con CONFIG_DM_VERITY=y|m
# - Particion objetivo en modo read-only

# === Crear tabla verity ===
# 1. Formatear:
#    veritysetup format /dev/sdX1 /dev/sdX2
#    (sdX1=datos, sdX2=hashes)
#    -> Anota el root-hash generado
#
# 2. Verificar y abrir:
#    veritysetup open /dev/sdX1 verity-data /dev/sdX2 <root-hash>
#
# 3. Montar:
#    mount -o ro /dev/mapper/verity-data /mnt/datos
#
# 4. Cerrar:
#    umount /mnt/datos
#    veritysetup close verity-data

# === Verificar soporte en kernel ===
# modinfo dm_verity 2>/dev/null && echo "dm-verity disponible"
# grep -i dm_verity /boot/config-$(uname -r)

# === Integracion con systemd ===
# systemd soporta verity nativo para imagenes:
#   systemd-dissect --with=verity imagen.raw
# Tambien usable con systemd-veritysetup@.service

# === Casos de uso ===
# - Particion /usr en modo read-only con verity
# - Imagenes de contenedores verificadas
# - Sistemas inmutables (MicroOS, Fedora Silverblue)

# === Limitaciones ===
# - Solo particiones read-only
# - El root-hash debe almacenarse de forma segura (TPM, kernel cmdline)
# - Cualquier escritura invalida la verificacion
EOFVERITY
    chmod 0640 "$BOOT_DIR/dm-verity.conf"
    log_change "Creado" "$BOOT_DIR/dm-verity.conf"

else
    log_skip "dm-verity"
fi

# ============================================================
# S6: IMA/EVM
# ============================================================
log_section "S6: IMA/EVM"

log_info "Configura Integrity Measurement Architecture y Extended Verification Module."
log_info "  - Politicas IMA, listas de medicion"
log_info "  - Estado actual de IMA en el sistema"
log_info ""

if check_file_exists /etc/securizar/boot/ima-evm.conf; then
    log_already "IMA/EVM (ima-evm.conf existe)"
elif ask "Crear configuracion IMA/EVM?"; then

    cat > "$BOOT_DIR/ima-evm.conf" << 'EOFIMA'
# ============================================================
# ima-evm.conf - Configuracion IMA/EVM
# ============================================================
# Generado por securizar - Modulo 73
#
# IMA (Integrity Measurement Architecture): mide/verifica ficheros
# EVM (Extended Verification Module): protege metadatos (xattrs)

# === Verificar soporte IMA ===
# grep -i ima /boot/config-$(uname -r)
# cat /sys/kernel/security/ima/ascii_runtime_measurements | wc -l
# dmesg | grep -i ima

# === Habilitar IMA en arranque ===
# Agregar a GRUB_CMDLINE_LINUX en /etc/default/grub:
#   ima_policy=tcb          # Politica basica (medir ejecutables)
#   ima_appraise=fix        # Modo fix (medir sin bloquear)
#   ima_appraise=enforce    # Modo enforce (bloquear si falla)
#   ima_hash=sha256         # Algoritmo de hash
#   evm=fix                 # EVM en modo fix

# === Politicas IMA personalizadas ===
# Fichero: /etc/ima/ima-policy (o via securityfs)
# Formato de regla:
#   measure func=FILE_CHECK mask=MAY_EXEC
#   appraise func=MODULE_CHECK
#   measure func=BPRM_CHECK mask=MAY_EXEC
#   dont_measure fsmagic=0x9fa0  # /proc
#   dont_measure fsmagic=0x62656572  # /sys

# === Comandos utiles ===
# Mediciones actuales:
#   cat /sys/kernel/security/ima/ascii_runtime_measurements
# Numero de mediciones:
#   cat /sys/kernel/security/ima/runtime_measurements_count
# Violaciones:
#   cat /sys/kernel/security/ima/violations

# === EVM ===
# EVM protege xattrs de seguridad (security.ima, security.selinux)
# Requiere clave HMAC o firma digital
#   evmctl import /etc/keys/pubkey.pem /etc/keys/ima-keyring
#   evmctl sign -k /etc/keys/privkey.pem /usr/bin/programa
EOFIMA
    chmod 0640 "$BOOT_DIR/ima-evm.conf"
    log_change "Creado" "$BOOT_DIR/ima-evm.conf"

    # Verificar estado actual de IMA
    if [[ -d /sys/kernel/security/ima ]]; then
        count=$(cat /sys/kernel/security/ima/runtime_measurements_count 2>/dev/null || echo "0")
        violations=$(cat /sys/kernel/security/ima/violations 2>/dev/null || echo "?")
        log_info "IMA activo: $count mediciones, $violations violaciones"
    else
        log_info "IMA no activo en el kernel actual"
    fi

else
    log_skip "IMA/EVM"
fi

# ============================================================
# S7: TPM2 INTEGRATION
# ============================================================
log_section "S7: TPM2 integration"

log_info "Verifica disponibilidad de TPM2 y su estado."
log_info "  - Dispositivo TPM, PCR values"
log_info "  - tpm2-tools"
log_info ""

if check_executable /usr/local/bin/securizar-tpm2-check.sh; then
    log_already "TPM2 check (securizar-tpm2-check.sh existe)"
elif ask "Crear herramienta de verificacion TPM2?"; then

    cat > "$BOOT_BIN/securizar-tpm2-check.sh" << 'EOFTPM'
#!/bin/bash
# ============================================================
# securizar-tpm2-check.sh - Verificacion de TPM2
# ============================================================
set -euo pipefail

RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"
CYAN="\033[0;36m"; BOLD="\033[1m"; DIM="\033[2m"; NC="\033[0m"

LOG_DIR="/var/log/securizar/boot"; mkdir -p "$LOG_DIR"
REPORT="$LOG_DIR/tpm2-$(date +%Y%m%d-%H%M%S).log"
log_r() { echo -e "$1" | tee -a "$REPORT"; }

log_r "${BOLD}=== VERIFICACION TPM2 ===${NC}"
log_r "Fecha: $(date)"
log_r ""

SCORE=0; MAX=0

# 1. Dispositivo TPM presente
MAX=$((MAX + 1))
if [[ -c /dev/tpm0 ]] || [[ -c /dev/tpmrm0 ]]; then
    log_r "  ${GREEN}[OK]${NC} Dispositivo TPM detectado"
    [[ -c /dev/tpm0 ]] && log_r "       /dev/tpm0 presente"
    [[ -c /dev/tpmrm0 ]] && log_r "       /dev/tpmrm0 presente (resource manager)"
    SCORE=$((SCORE + 1))
else
    log_r "  ${RED}[--]${NC} No se detecto dispositivo TPM"
    log_r "       Verificar en UEFI que TPM este habilitado"
    log_r "Reporte: $REPORT"; exit 0
fi

# 2. Version TPM
MAX=$((MAX + 1))
if [[ -f /sys/class/tpm/tpm0/tpm_version_major ]]; then
    ver=$(cat /sys/class/tpm/tpm0/tpm_version_major 2>/dev/null || echo "?")
    log_r "  TPM version: $ver"
    if [[ "$ver" == "2" ]]; then
        log_r "  ${GREEN}[OK]${NC} TPM 2.0 detectado"
        SCORE=$((SCORE + 1))
    else
        log_r "  ${YELLOW}[!!]${NC} TPM version $ver (se recomienda 2.0)"
    fi
fi

# 3. tpm2-tools disponible
MAX=$((MAX + 1))
if command -v tpm2_getcap &>/dev/null; then
    log_r "  ${GREEN}[OK]${NC} tpm2-tools instalado"
    SCORE=$((SCORE + 1))

    # PCR values
    log_r ""; log_r "${CYAN}=== PCR Values (SHA-256) ===${NC}"
    if tpm2_pcrread sha256:0,1,2,3,4,5,6,7 2>/dev/null | \
       while IFS= read -r line; do log_r "    $line"; done; then
        true
    else
        log_r "    ${DIM}No se pudieron leer PCRs${NC}"
    fi

    # Capabilities
    log_r ""; log_r "${CYAN}=== Capacidades ===${NC}"
    tpm2_getcap properties-fixed 2>/dev/null | grep -E "TPM2_PT_(FAMILY|REVISION|FIRMWARE)" | \
        while IFS= read -r line; do log_r "    $line"; done || true
else
    log_r "  ${YELLOW}[!!]${NC} tpm2-tools no instalado"
    log_r "       Instalar: zypper install tpm2.0-tools (o equivalente)"
fi

# 4. Sealed secrets
MAX=$((MAX + 1))
if command -v systemd-cryptenroll &>/dev/null; then
    log_r ""; log_r "  ${GREEN}[OK]${NC} systemd-cryptenroll disponible (LUKS + TPM2)"
    SCORE=$((SCORE + 1))
elif command -v clevis &>/dev/null; then
    log_r ""; log_r "  ${GREEN}[OK]${NC} Clevis disponible (LUKS + TPM2)"
    SCORE=$((SCORE + 1))
else
    log_r ""; log_r "  ${DIM}Ni systemd-cryptenroll ni clevis disponibles${NC}"
fi

# Resumen
log_r ""; log_r "${BOLD}===============================${NC}"
PCT=0; [[ $MAX -gt 0 ]] && PCT=$((SCORE * 100 / MAX))
if [[ $PCT -ge 70 ]]; then
    log_r "  ${GREEN}Puntuacion: ${SCORE}/${MAX} (${PCT}%) - BUENO${NC}"
elif [[ $PCT -ge 40 ]]; then
    log_r "  ${YELLOW}Puntuacion: ${SCORE}/${MAX} (${PCT}%) - MEJORABLE${NC}"
else
    log_r "  ${RED}Puntuacion: ${SCORE}/${MAX} (${PCT}%) - DEFICIENTE${NC}"
fi
log_r "Reporte: $REPORT"
EOFTPM
    chmod +x "$BOOT_BIN/securizar-tpm2-check.sh"
    log_change "Creado" "$BOOT_BIN/securizar-tpm2-check.sh"

else
    log_skip "TPM2 integration"
fi

# ============================================================
# S8: DETECCION DE BOOTKITS
# ============================================================
log_section "S8: Deteccion de bootkits"

log_info "Detecta modificaciones en ficheros de arranque."
log_info "  - Hashes de EFI binaries, MBR/ESP integrity"
log_info "  - Comparacion con baseline"
log_info ""

if check_executable /usr/local/bin/securizar-bootkit-detect.sh; then
    log_already "Deteccion de bootkits (securizar-bootkit-detect.sh existe)"
elif ask "Crear herramienta de deteccion de bootkits?"; then

    cat > "$BOOT_BIN/securizar-bootkit-detect.sh" << 'EOFBOOTKIT'
#!/bin/bash
# ============================================================
# securizar-bootkit-detect.sh - Deteccion de bootkits
# ============================================================
set -euo pipefail

RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"
CYAN="\033[0;36m"; BOLD="\033[1m"; NC="\033[0m"

BOOT_DIR="/etc/securizar/boot"
LOG_DIR="/var/log/securizar/boot"; mkdir -p "$LOG_DIR" "$BOOT_DIR"
REPORT="$LOG_DIR/bootkit-$(date +%Y%m%d-%H%M%S).log"
BASELINE="$BOOT_DIR/boot-hashes.baseline"

log_r() { echo -e "$1" | tee -a "$REPORT"; }

log_r "${BOLD}=== DETECCION DE BOOTKITS ===${NC}"
log_r "Fecha: $(date)"
log_r ""

ALERTS=0

# 1. Generar hashes actuales de ficheros de arranque
CURRENT=$(mktemp)
trap 'rm -f "$CURRENT"' EXIT

log_r "${CYAN}=== Hashes de ficheros de arranque ===${NC}"
for dir in /boot /boot/efi/EFI; do
    [[ -d "$dir" ]] || continue
    find "$dir" -type f \( -name '*.efi' -o -name 'vmlinuz*' -o -name 'initrd*' \
        -o -name 'initramfs*' -o -name 'grub.cfg' -o -name 'grub2.cfg' \
        -o -name '*.img' -o -name 'shim*' \) 2>/dev/null | sort | \
    while IFS= read -r f; do
        sha256sum "$f" 2>/dev/null
    done
done > "$CURRENT"

count=$(wc -l < "$CURRENT")
log_r "  Ficheros escaneados: $count"

# 2. Comparar con baseline
if [[ -f "$BASELINE" ]]; then
    log_r ""; log_r "${CYAN}=== Comparacion con baseline ===${NC}"
    # Ficheros modificados
    while IFS= read -r line; do
        hash=$(echo "$line" | awk '{print $1}')
        file=$(echo "$line" | awk '{print $2}')
        old_hash=$(grep " ${file}$" "$BASELINE" 2>/dev/null | awk '{print $1}')
        if [[ -z "$old_hash" ]]; then
            log_r "  ${YELLOW}[NUEVO]${NC} $file"
            ALERTS=$((ALERTS + 1))
        elif [[ "$hash" != "$old_hash" ]]; then
            log_r "  ${RED}[MODIFICADO]${NC} $file"
            ALERTS=$((ALERTS + 1))
        fi
    done < "$CURRENT"
    # Ficheros eliminados
    while IFS= read -r line; do
        file=$(echo "$line" | awk '{print $2}')
        if ! grep -q " ${file}$" "$CURRENT" 2>/dev/null; then
            log_r "  ${RED}[ELIMINADO]${NC} $file"
            ALERTS=$((ALERTS + 1))
        fi
    done < "$BASELINE"
    if [[ $ALERTS -eq 0 ]]; then
        log_r "  ${GREEN}[OK]${NC} Sin cambios respecto al baseline"
    fi
else
    log_r ""; log_r "  ${YELLOW}No existe baseline previo - creando...${NC}"
    cp "$CURRENT" "$BASELINE"
    chmod 0600 "$BASELINE"
    log_r "  Baseline guardado en: $BASELINE"
fi

# 3. Verificar MBR (primeros 440 bytes del disco)
log_r ""; log_r "${CYAN}=== Verificacion MBR/ESP ===${NC}"
boot_disk=$(mount | grep ' /boot' | head -1 | awk '{print $1}' | sed 's/[0-9]*$//')
if [[ -z "$boot_disk" ]]; then
    boot_disk=$(mount | grep ' / ' | head -1 | awk '{print $1}' | sed 's/[0-9]*$//' | sed 's/p$//')
fi
if [[ -b "$boot_disk" ]]; then
    mbr_hash=$(dd if="$boot_disk" bs=440 count=1 2>/dev/null | sha256sum | awk '{print $1}')
    log_r "  MBR hash ($boot_disk): $mbr_hash"
else
    log_r "  ${YELLOW}No se pudo determinar disco de arranque${NC}"
fi

# Resumen
log_r ""
if [[ $ALERTS -eq 0 ]]; then
    log_r "${GREEN}${BOLD}Sin alertas de bootkit${NC}"
else
    log_r "${RED}${BOLD}ALERTAS: $ALERTS cambios detectados en ficheros de arranque${NC}"
    log_r "Revisar cambios y actualizar baseline si son legitimos:"
    log_r "  securizar-bootkit-detect.sh --update-baseline"
fi
log_r "Reporte: $REPORT"

# Flag para actualizar baseline
if [[ "${1:-}" == "--update-baseline" ]]; then
    cp "$CURRENT" "$BASELINE"
    chmod 0600 "$BASELINE"
    echo -e "${GREEN}Baseline actualizado${NC}"
fi
EOFBOOTKIT
    chmod +x "$BOOT_BIN/securizar-bootkit-detect.sh"
    log_change "Creado" "$BOOT_BIN/securizar-bootkit-detect.sh"

    # Generar baseline inicial
    log_info "Generando baseline inicial de ficheros de arranque..."
    "$BOOT_BIN/securizar-bootkit-detect.sh" > /dev/null 2>&1 || true

else
    log_skip "Deteccion de bootkits"
fi

# ============================================================
# S9: MEASURED BOOT LOGGING
# ============================================================
log_section "S9: Measured Boot logging"

log_info "Documenta configuracion de measured boot y attestation."
log_info "  - Event log de arranque medido"
log_info "  - Remote attestation con TPM2"
log_info ""

if check_file_exists /etc/securizar/boot/measured-boot.conf; then
    log_already "Measured Boot (measured-boot.conf existe)"
elif ask "Crear documentacion de Measured Boot?"; then

    cat > "$BOOT_DIR/measured-boot.conf" << 'EOFMBOOT'
# ============================================================
# measured-boot.conf - Measured Boot y Remote Attestation
# ============================================================
# Generado por securizar - Modulo 73
#
# Measured Boot extiende las mediciones de cada etapa del arranque
# a los PCRs del TPM, creando una cadena de confianza verificable.

# === PCR Assignments (TCG PC Client) ===
# PCR 0: BIOS/UEFI firmware
# PCR 1: BIOS/UEFI configuration
# PCR 2: Option ROMs
# PCR 3: Option ROM configuration
# PCR 4: MBR / IPL code (bootloader)
# PCR 5: MBR / IPL configuration (particiones)
# PCR 6: State transitions / wake events
# PCR 7: Secure Boot state (db, dbx, KEK, PK)
# PCR 8-15: Uso libre (IMA usa PCR 10 por defecto)

# === Event Log ===
# El event log registra que se midio en cada PCR.
# Ubicacion: /sys/kernel/security/tpm0/binary_bios_measurements
# Formato: TCG Event Log v2 (EFI_TCG2_EVENT)
#
# Leer con tpm2-tools:
#   tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements
#
# Verificar consistencia:
#   tpm2_pcrread sha256:0,1,2,3,4,5,6,7
#   (Comparar con replay del event log)

# === Remote Attestation ===
# Permite a un servidor remoto verificar el estado del arranque.
#
# Flujo:
# 1. Verifier envia nonce al Attester
# 2. Attester firma PCR quote con AK (Attestation Key):
#    tpm2_quote -c ak_ctx -l sha256:0,1,2,3,4,7 -q <nonce> -m quote.msg -s quote.sig
# 3. Attester envia: quote, firma, event log
# 4. Verifier: verifica firma, replay event log, compara PCRs
#
# Herramientas:
# - keylime: https://keylime.dev/ (attestation framework)
# - tpm2-tools: tpm2_createak, tpm2_quote, tpm2_checkquote

# === Habilitar measured boot ===
# 1. Habilitar TPM 2.0 en UEFI
# 2. El firmware UEFI mide automaticamente (PCR 0-7)
# 3. GRUB2: grub2-install con modulo tpm
# 4. IMA extiende PCR 10 con mediciones de ficheros
#    (agregar ima_policy=tcb al cmdline)

# === Verificacion local ===
# Leer PCRs actuales:
#   tpm2_pcrread sha256:all
# Leer event log:
#   tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements 2>/dev/null | head -50
EOFMBOOT
    chmod 0640 "$BOOT_DIR/measured-boot.conf"
    log_change "Creado" "$BOOT_DIR/measured-boot.conf"

else
    log_skip "Measured Boot logging"
fi

# ============================================================
# S10: AUDITORIA INTEGRAL ARRANQUE
# ============================================================
log_section "S10: Auditoria integral arranque"

log_info "Crea herramienta de auditoria integral de arranque."
log_info ""

if check_executable /usr/local/bin/auditoria-boot-completa.sh; then
    log_already "Auditoria integral (auditoria-boot-completa.sh existe)"
elif ask "Crear herramienta de auditoria integral de arranque?"; then

    cat > "$BOOT_BIN/auditoria-boot-completa.sh" << 'EOFAUDIT'
#!/bin/bash
# ============================================================
# auditoria-boot-completa.sh - Auditoria integral de arranque
# ============================================================
set -euo pipefail

RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"
CYAN="\033[0;36m"; BOLD="\033[1m"; DIM="\033[2m"; NC="\033[0m"

LOG_DIR="/var/log/securizar/boot"; mkdir -p "$LOG_DIR"
REPORT="$LOG_DIR/audit-integral-$(date +%Y%m%d-%H%M%S).log"

SCORE=0; MAX=0

check() {
    local desc="$1" result="$2"
    MAX=$((MAX + 1))
    if [[ "$result" -eq 0 ]]; then
        echo -e "  ${GREEN}[OK]${NC} $desc" | tee -a "$REPORT"
        SCORE=$((SCORE + 1))
    else
        echo -e "  ${YELLOW}[!!]${NC} $desc" | tee -a "$REPORT"
    fi
}

echo -e "${BOLD}=============================================" | tee "$REPORT"
echo -e "  AUDITORIA INTEGRAL DE ARRANQUE" | tee -a "$REPORT"
echo -e "  $(date '+%Y-%m-%d %H:%M:%S') - $(hostname)" | tee -a "$REPORT"
echo -e "=============================================${NC}" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# 1. UEFI y Secure Boot
echo -e "${CYAN}=== 1. UEFI / Secure Boot ===${NC}" | tee -a "$REPORT"
check "Sistema UEFI" "$([[ -d /sys/firmware/efi ]]; echo $?)"
if command -v mokutil &>/dev/null; then
    sb=$(mokutil --sb-state 2>/dev/null || echo "")
    check "Secure Boot habilitado" "$(echo "$sb" | grep -qi "enabled"; echo $?)"
fi

# 2. GRUB2 seguridad
echo "" | tee -a "$REPORT"
echo -e "${CYAN}=== 2. GRUB2 ===${NC}" | tee -a "$REPORT"
grub_cfg=""
for f in /boot/grub2/grub.cfg /boot/grub/grub.cfg; do
    [[ -f "$f" ]] && grub_cfg="$f" && break
done
if [[ -n "$grub_cfg" ]]; then
    perms=$(stat -c '%a' "$grub_cfg" 2>/dev/null || echo "???")
    check "grub.cfg permisos restrictivos (600)" "$([[ "$perms" == "600" ]]; echo $?)"
fi
user_cfg=""
for f in /boot/grub2/user.cfg /boot/grub/user.cfg; do
    [[ -f "$f" ]] && user_cfg="$f" && break
done
check "GRUB password configurado" "$([[ -n "$user_cfg" ]]; echo $?)"

# 3. Kernel
echo "" | tee -a "$REPORT"
echo -e "${CYAN}=== 3. Kernel ===${NC}" | tee -a "$REPORT"
cmdline=$(cat /proc/cmdline 2>/dev/null || echo "")
check "module.sig_enforce" "$(echo "$cmdline" | grep -q "module.sig_enforce"; echo $?)"
if [[ -f /sys/kernel/security/lockdown ]]; then
    ld=$(cat /sys/kernel/security/lockdown 2>/dev/null)
    check "Kernel lockdown activo" "$(echo "$ld" | grep -qE '\[(integrity|confidentiality)\]'; echo $?)"
fi
tainted=$(cat /proc/sys/kernel/tainted 2>/dev/null || echo "1")
check "Kernel no tainted" "$([[ "$tainted" == "0" ]]; echo $?)"

# 4. TPM
echo "" | tee -a "$REPORT"
echo -e "${CYAN}=== 4. TPM ===${NC}" | tee -a "$REPORT"
check "TPM presente" "$([[ -c /dev/tpm0 ]] || [[ -c /dev/tpmrm0 ]]; echo $?)"
check "tpm2-tools instalado" "$(command -v tpm2_getcap &>/dev/null; echo $?)"

# 5. IMA
echo "" | tee -a "$REPORT"
echo -e "${CYAN}=== 5. IMA ===${NC}" | tee -a "$REPORT"
check "IMA activo" "$([[ -d /sys/kernel/security/ima ]]; echo $?)"

# 6. Herramientas securizar
echo "" | tee -a "$REPORT"
echo -e "${CYAN}=== 6. Herramientas securizar ===${NC}" | tee -a "$REPORT"
check "securizar-secureboot-check.sh" "$([[ -x /usr/local/bin/securizar-secureboot-check.sh ]]; echo $?)"
check "securizar-kernel-verify.sh" "$([[ -x /usr/local/bin/securizar-kernel-verify.sh ]]; echo $?)"
check "securizar-tpm2-check.sh" "$([[ -x /usr/local/bin/securizar-tpm2-check.sh ]]; echo $?)"
check "securizar-bootkit-detect.sh" "$([[ -x /usr/local/bin/securizar-bootkit-detect.sh ]]; echo $?)"

# 7. Configuracion
echo "" | tee -a "$REPORT"
echo -e "${CYAN}=== 7. Configuracion ===${NC}" | tee -a "$REPORT"
check "uefi-hardening.conf" "$([[ -f /etc/securizar/boot/uefi-hardening.conf ]]; echo $?)"
check "grub2-hardening.conf" "$([[ -f /etc/securizar/boot/grub2-hardening.conf ]]; echo $?)"
check "dm-verity.conf" "$([[ -f /etc/securizar/boot/dm-verity.conf ]]; echo $?)"
check "ima-evm.conf" "$([[ -f /etc/securizar/boot/ima-evm.conf ]]; echo $?)"
check "measured-boot.conf" "$([[ -f /etc/securizar/boot/measured-boot.conf ]]; echo $?)"
check "boot-hashes.baseline" "$([[ -f /etc/securizar/boot/boot-hashes.baseline ]]; echo $?)"

# Resumen
echo "" | tee -a "$REPORT"
echo -e "${BOLD}=============================================${NC}" | tee -a "$REPORT"
PCT=0; [[ $MAX -gt 0 ]] && PCT=$((SCORE * 100 / MAX))
if [[ $PCT -ge 80 ]]; then
    echo -e "  ${GREEN}${BOLD}PUNTUACION: ${SCORE}/${MAX} (${PCT}%) - BUENO${NC}" | tee -a "$REPORT"
elif [[ $PCT -ge 50 ]]; then
    echo -e "  ${YELLOW}${BOLD}PUNTUACION: ${SCORE}/${MAX} (${PCT}%) - MEJORABLE${NC}" | tee -a "$REPORT"
else
    echo -e "  ${RED}${BOLD}PUNTUACION: ${SCORE}/${MAX} (${PCT}%) - DEFICIENTE${NC}" | tee -a "$REPORT"
fi
echo -e "${BOLD}=============================================${NC}" | tee -a "$REPORT"
echo -e "${DIM}Reporte: $REPORT${NC}" | tee -a "$REPORT"
logger -t securizar-boot "Boot integrity audit: $SCORE/$MAX ($PCT%)"
EOFAUDIT
    chmod +x "$BOOT_BIN/auditoria-boot-completa.sh"
    log_change "Creado" "$BOOT_BIN/auditoria-boot-completa.sh"

    # Cron semanal
    cat > /etc/cron.weekly/auditoria-boot << 'EOFCRON'
#!/bin/bash
/usr/local/bin/auditoria-boot-completa.sh > /dev/null 2>&1
EOFCRON
    chmod 700 /etc/cron.weekly/auditoria-boot
    log_change "Creado" "/etc/cron.weekly/auditoria-boot"

else
    log_skip "Auditoria integral arranque"
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
show_changes_summary
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   INTEGRIDAD DE ARRANQUE (MODULO 73) COMPLETADO           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups guardados en: $BACKUP_DIR"
echo ""
echo "Comandos disponibles:"
echo "  - Secure Boot:      securizar-secureboot-check.sh"
echo "  - Kernel verify:    securizar-kernel-verify.sh"
echo "  - TPM2 check:       securizar-tpm2-check.sh"
echo "  - Bootkit detect:   securizar-bootkit-detect.sh"
echo "  - Auditoria:        auditoria-boot-completa.sh"
