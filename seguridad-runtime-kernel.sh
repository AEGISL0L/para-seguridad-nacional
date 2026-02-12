#!/bin/bash
# ============================================================
# seguridad-runtime-kernel.sh — Módulo 66: Protección Runtime del Kernel
# ============================================================
# LKRG, eBPF, Falco, kernel lockdown, módulos firmados, CPU mitigations
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/securizar-common.sh"

require_root
securizar_setup_traps
init_backup "seguridad-runtime-kernel"

# ── Sección 1: LKRG (Linux Kernel Runtime Guard) ──
section_1() {
    log_section "1. LKRG (Linux Kernel Runtime Guard)"

    if [[ -f /etc/securizar/kernel-runtime/lkrg.conf ]]; then
        log_already "LKRG configurado (/etc/securizar/kernel-runtime/lkrg.conf existe)"; return 0
    fi
    ask "¿Configurar detección y monitorización LKRG para integridad del kernel?" || { log_skip "LKRG omitido"; return 0; }

    mkdir -p /etc/securizar/kernel-runtime /var/log/securizar/kernel-runtime

    cat > /usr/local/bin/securizar-kernel-lkrg.sh << 'EOFLKRG'
#!/bin/bash
# ============================================================
# securizar-kernel-lkrg.sh — Verificar y configurar LKRG
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar/kernel-runtime"
mkdir -p "$LOG_DIR"
REPORT="$LOG_DIR/lkrg-$(date +%Y%m%d).txt"

{
echo "=========================================="
echo " LKRG — Linux Kernel Runtime Guard"
echo " $(date) - $(hostname)"
echo "=========================================="
echo ""

# Verificar si LKRG está instalado
LKRG_LOADED=false
if lsmod 2>/dev/null | grep -q '^lkrg'; then
    echo "[OK] Módulo LKRG cargado en el kernel"
    LKRG_LOADED=true
elif modinfo lkrg &>/dev/null; then
    echo "[INFO] LKRG disponible pero NO cargado"
    echo "  Cargar: modprobe lkrg"
else
    echo "[WARN] LKRG NO instalado"
    echo "  Instalar desde: https://lkrg.org/"
    echo "  openSUSE: zypper install lkrg lkrg-kmp-default"
fi

echo ""
echo "=== Estado DKMS ==="
if command -v dkms &>/dev/null; then
    LKRG_DKMS=$(dkms status 2>/dev/null | grep -i lkrg || true)
    if [[ -n "$LKRG_DKMS" ]]; then
        echo "[OK] LKRG en DKMS: $LKRG_DKMS"
    else
        echo "[INFO] DKMS disponible pero LKRG no registrado"
    fi
else
    echo "[INFO] DKMS no instalado"
fi

echo ""
echo "=== Parámetros LKRG recomendados ==="
LKRG_PARAMS=(
    "lkrg.block_modules=1:Bloquear carga de módulos no firmados"
    "lkrg.umh_validate=2:Validar usermode helpers estrictamente"
    "lkrg.msr_validate=1:Validar registros MSR del CPU"
    "lkrg.hide=0:No ocultar LKRG (mejor auditoría)"
)

for param_desc in "${LKRG_PARAMS[@]}"; do
    param="${param_desc%%:*}"
    desc="${param_desc#*:}"
    key="${param%%=*}"
    val="${param#*=}"

    if $LKRG_LOADED; then
        SYSFS="/sys/module/lkrg/parameters/${key#lkrg.}"
        if [[ -f "$SYSFS" ]]; then
            CUR=$(cat "$SYSFS" 2>/dev/null || echo "?")
            if [[ "$CUR" == "$val" ]]; then
                echo "  [OK] $key = $val ($desc)"
            else
                echo "  [!!] $key = $CUR (recomendado: $val) — $desc"
            fi
        else
            echo "  [--] $key — parámetro no disponible en esta versión"
        fi
    else
        echo "  [--] $key=$val — $desc (LKRG no cargado)"
    fi
done

echo ""
echo "=== Alertas LKRG recientes ==="
LKRG_ALERTS=$(journalctl -k --no-pager -n 500 2>/dev/null | grep -i "lkrg" | tail -20 || true)
if [[ -n "$LKRG_ALERTS" ]]; then
    echo "$LKRG_ALERTS"
else
    LKRG_DMESG=$(dmesg 2>/dev/null | grep -i "lkrg" | tail -10 || true)
    if [[ -n "$LKRG_DMESG" ]]; then
        echo "$LKRG_DMESG"
    else
        echo "  Sin alertas LKRG en logs recientes"
    fi
fi

echo ""
echo "Completado: $(date)"
} 2>&1 | tee "$REPORT"
EOFLKRG
    chmod +x /usr/local/bin/securizar-kernel-lkrg.sh

    # Configuración recomendada
    cat > /etc/securizar/kernel-runtime/lkrg.conf << 'EOF'
# Securizar — Configuración LKRG recomendada
# Cargar con: modprobe lkrg $(cat /etc/securizar/kernel-runtime/lkrg.conf | grep -v '^#' | tr '\n' ' ')
lkrg.block_modules=1
lkrg.umh_validate=2
lkrg.msr_validate=1
lkrg.hide=0
EOF

    log_change "Verificador LKRG instalado"
    log_change "Aplicado" "Sección 1: LKRG — detección integridad kernel runtime"
}

# ── Sección 2: Kernel lockdown mode ──
section_2() {
    log_section "2. Kernel lockdown mode"

    if check_executable /usr/local/bin/securizar-kernel-lockdown.sh; then
        log_already "Kernel lockdown (securizar-kernel-lockdown.sh existe)"; return 0
    fi
    ask "¿Configurar verificación y activación del modo lockdown del kernel?" || { log_skip "Kernel lockdown omitido"; return 0; }

    mkdir -p /var/log/securizar/kernel-runtime

    cat > /usr/local/bin/securizar-kernel-lockdown.sh << 'EOFLOCKDOWN'
#!/bin/bash
# ============================================================
# securizar-kernel-lockdown.sh — Verificar kernel lockdown
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar/kernel-runtime"
mkdir -p "$LOG_DIR"
REPORT="$LOG_DIR/lockdown-$(date +%Y%m%d).txt"

{
echo "=========================================="
echo " Kernel Lockdown Mode"
echo " $(date) - $(hostname)"
echo "=========================================="
echo ""

# Verificar estado actual
LOCKDOWN_FILE="/sys/kernel/security/lockdown"
if [[ -f "$LOCKDOWN_FILE" ]]; then
    LOCKDOWN_STATE=$(cat "$LOCKDOWN_FILE" 2>/dev/null)
    echo "Estado actual: $LOCKDOWN_STATE"

    if echo "$LOCKDOWN_STATE" | grep -q '\[confidentiality\]'; then
        echo "[OK] Kernel lockdown: confidentiality (máximo)"
    elif echo "$LOCKDOWN_STATE" | grep -q '\[integrity\]'; then
        echo "[OK] Kernel lockdown: integrity (recomendado)"
    elif echo "$LOCKDOWN_STATE" | grep -q '\[none\]'; then
        echo "[WARN] Kernel lockdown: DESACTIVADO"
    fi
else
    echo "[WARN] /sys/kernel/security/lockdown no disponible"
    echo "  El kernel puede no soportar lockdown (CONFIG_SECURITY_LOCKDOWN_LSM)"
fi

echo ""
echo "=== Parámetros de arranque relacionados ==="
CMDLINE=$(cat /proc/cmdline 2>/dev/null || echo "")
if echo "$CMDLINE" | grep -q "lockdown="; then
    LOCK_PARAM=$(echo "$CMDLINE" | grep -oP 'lockdown=\S+')
    echo "[OK] Parámetro encontrado: $LOCK_PARAM"
else
    echo "[INFO] lockdown= NO presente en cmdline"
    echo "  Añadir a GRUB: lockdown=integrity"
fi

echo ""
echo "=== Secure Boot ==="
if command -v mokutil &>/dev/null; then
    SB_STATE=$(mokutil --sb-state 2>/dev/null || echo "desconocido")
    echo "Secure Boot: $SB_STATE"
    if echo "$SB_STATE" | grep -qi "enabled"; then
        echo "[OK] Secure Boot habilitado (lockdown=confidentiality seguro)"
    else
        echo "[INFO] Sin Secure Boot, usar lockdown=integrity"
    fi
else
    echo "[INFO] mokutil no disponible"
fi

echo ""
echo "=== Capacidades restringidas por lockdown ==="
echo "  integrity: bloquea escritura /dev/mem, kexec sin firma, hibernación"
echo "  confidentiality: +bloquea lectura /proc/kcore, /dev/kmem, debugfs"

echo ""
echo "=== Recomendación ==="
if [[ -f "$LOCKDOWN_FILE" ]]; then
    STATE=$(cat "$LOCKDOWN_FILE")
    if echo "$STATE" | grep -q '\[none\]'; then
        echo "  1. Editar /etc/default/grub"
        echo "  2. Añadir lockdown=integrity a GRUB_CMDLINE_LINUX"
        echo "  3. Regenerar grub: grub2-mkconfig -o /boot/grub2/grub.cfg"
        echo "  4. Reiniciar"
    fi
fi

echo ""
echo "Completado: $(date)"
} 2>&1 | tee "$REPORT"
EOFLOCKDOWN
    chmod +x /usr/local/bin/securizar-kernel-lockdown.sh

    log_change "Verificador kernel lockdown instalado"
    log_change "Aplicado" "Sección 2: Auditoría y guía de activación kernel lockdown"
}

# ── Sección 3: eBPF hardening ──
section_3() {
    log_section "3. eBPF hardening"

    if check_executable /usr/local/bin/securizar-kernel-ebpf.sh; then
        log_already "eBPF hardening (securizar-kernel-ebpf.sh existe)"; return 0
    fi
    ask "¿Aplicar hardening de eBPF (restringir acceso no privilegiado)?" || { log_skip "eBPF hardening omitido"; return 0; }

    mkdir -p /var/log/securizar/kernel-runtime

    # Aplicar sysctl de eBPF
    local SYSCTL_FILE="/etc/sysctl.d/90-securizar-ebpf.conf"
    backup_if_exists "$SYSCTL_FILE"

    cat > "$SYSCTL_FILE" << 'EOF'
# Securizar — eBPF hardening
# Deshabilitar BPF no privilegiado
kernel.unprivileged_bpf_disabled = 1
# Endurecimiento JIT de BPF (ofuscación de constantes)
net.core.bpf_jit_harden = 2
EOF
    sysctl -p "$SYSCTL_FILE" 2>/dev/null || true

    # Script de verificación
    cat > /usr/local/bin/securizar-kernel-ebpf.sh << 'EOFEBPF'
#!/bin/bash
# ============================================================
# securizar-kernel-ebpf.sh — Verificar hardening eBPF
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar/kernel-runtime"
mkdir -p "$LOG_DIR"
REPORT="$LOG_DIR/ebpf-$(date +%Y%m%d).txt"

{
echo "=========================================="
echo " eBPF Hardening"
echo " $(date) - $(hostname)"
echo "=========================================="
echo ""

echo "=== Parámetros sysctl ==="
PARAMS=(
    "kernel.unprivileged_bpf_disabled:1:Deshabilitar BPF no privilegiado"
    "net.core.bpf_jit_harden:2:JIT hardening máximo"
)

for entry in "${PARAMS[@]}"; do
    key="${entry%%:*}"
    rest="${entry#*:}"
    expected="${rest%%:*}"
    desc="${rest#*:}"

    val=$(sysctl -n "$key" 2>/dev/null || echo "N/A")
    if [[ "$val" == "$expected" ]]; then
        echo "  [OK] $key = $val ($desc)"
    else
        echo "  [!!] $key = $val (esperado: $expected) — $desc"
    fi
done

echo ""
echo "=== Programas BPF cargados ==="
if command -v bpftool &>/dev/null; then
    BPF_PROGS=$(bpftool prog list 2>/dev/null | head -30 || echo "  No se pudo listar")
    echo "$BPF_PROGS"
else
    echo "  bpftool no disponible"
    # Alternativa: /proc
    if [[ -d /proc/sys/net/core ]]; then
        echo "  BPF JIT: $(cat /proc/sys/net/core/bpf_jit_enable 2>/dev/null || echo 'N/A')"
    fi
fi

echo ""
echo "=== Maps BPF activos ==="
if command -v bpftool &>/dev/null; then
    bpftool map list 2>/dev/null | head -20 || echo "  Sin maps BPF"
fi

echo ""
echo "Completado: $(date)"
} 2>&1 | tee "$REPORT"
EOFEBPF
    chmod +x /usr/local/bin/securizar-kernel-ebpf.sh

    log_change "Hardening eBPF aplicado (sysctl + verificador)"
    log_change "Aplicado" "Sección 3: BPF no privilegiado deshabilitado, JIT hardening=2"
}

# ── Sección 4: Falco runtime monitoring ──
section_4() {
    log_section "4. Falco runtime monitoring"

    if check_executable /usr/local/bin/securizar-kernel-falco.sh; then
        log_already "Falco runtime monitoring (securizar-kernel-falco.sh existe)"; return 0
    fi
    ask "¿Configurar Falco para monitorización runtime de syscalls sospechosos?" || { log_skip "Falco omitido"; return 0; }

    mkdir -p /etc/securizar/kernel-runtime/falco-rules /var/log/securizar/kernel-runtime

    # Reglas Falco personalizadas
    cat > /etc/securizar/kernel-runtime/falco-rules/securizar-rules.yaml << 'EOFFALCO'
# Securizar — Reglas Falco personalizadas
# Copiar a /etc/falco/rules.d/ tras instalar Falco

- rule: Securizar - Acceso a /etc/shadow
  desc: Detectar lectura de /etc/shadow por procesos no autorizados
  condition: >
    open_read and fd.name = "/etc/shadow"
    and not proc.name in (login, su, sudo, sshd, passwd, chage, useradd, usermod,
                          groupadd, groupmod, vipw, grpck, pwck, pam_unix)
  output: >
    Acceso sospechoso a /etc/shadow
    (user=%user.name command=%proc.cmdline file=%fd.name container=%container.id)
  priority: WARNING
  tags: [securizar, credential_access]

- rule: Securizar - Reverse shell detectado
  desc: Detectar intentos de reverse shell
  condition: >
    spawned_process and
    ((proc.name = "bash" or proc.name = "sh" or proc.name = "dash") and
     proc.cmdline contains "/dev/tcp") or
    (proc.name in (nc, ncat, netcat, socat) and
     (proc.cmdline contains "-e" or proc.cmdline contains "-c"))
  output: >
    Posible reverse shell detectado
    (user=%user.name command=%proc.cmdline parent=%proc.pname container=%container.id)
  priority: CRITICAL
  tags: [securizar, execution, reverse_shell]

- rule: Securizar - Carga de módulo kernel
  desc: Detectar carga dinámica de módulos del kernel
  condition: >
    spawned_process and proc.name in (insmod, modprobe) and not proc.pname in (systemd, dracut)
  output: >
    Carga de módulo kernel detectada
    (user=%user.name command=%proc.cmdline parent=%proc.pname)
  priority: WARNING
  tags: [securizar, persistence, kernel_module]

- rule: Securizar - Container escape intento
  desc: Detectar intentos de escape de contenedor
  condition: >
    spawned_process and container and
    (proc.cmdline contains "nsenter" or
     proc.cmdline contains "mount " or
     proc.name = "chroot")
  output: >
    Posible intento de escape de contenedor
    (user=%user.name command=%proc.cmdline container=%container.id image=%container.image.repository)
  priority: CRITICAL
  tags: [securizar, container_escape]

- rule: Securizar - Modificación de binarios del sistema
  desc: Detectar escritura en directorios de binarios del sistema
  condition: >
    open_write and (fd.directory = "/usr/bin" or fd.directory = "/usr/sbin"
    or fd.directory = "/bin" or fd.directory = "/sbin")
    and not proc.name in (rpm, dpkg, zypper, dnf, yum, apt, apt-get, packagekitd)
  output: >
    Modificación de binario del sistema
    (user=%user.name command=%proc.cmdline file=%fd.name)
  priority: CRITICAL
  tags: [securizar, persistence, trojan]
EOFFALCO

    # Script de gestión Falco
    cat > /usr/local/bin/securizar-kernel-falco.sh << 'EOFFALCOSH'
#!/bin/bash
# ============================================================
# securizar-kernel-falco.sh — Gestionar Falco runtime monitoring
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar/kernel-runtime"
mkdir -p "$LOG_DIR"
REPORT="$LOG_DIR/falco-$(date +%Y%m%d).txt"
ACTION="${1:-status}"

case "$ACTION" in
    status)
        {
        echo "=========================================="
        echo " Falco Runtime Monitoring"
        echo " $(date) - $(hostname)"
        echo "=========================================="
        echo ""

        echo "=== Estado de Falco ==="
        if command -v falco &>/dev/null; then
            echo "[OK] Falco instalado: $(falco --version 2>/dev/null | head -1)"
            if systemctl is-active falco &>/dev/null; then
                echo "[OK] Servicio Falco activo"
            else
                echo "[!!] Servicio Falco NO activo"
                echo "  Iniciar: systemctl start falco"
            fi
        else
            echo "[WARN] Falco NO instalado"
            echo "  openSUSE: zypper ar https://download.falco.org/packages/rpm/ falco"
            echo "  zypper install falco"
        fi

        echo ""
        echo "=== Reglas Securizar ==="
        RULES_SRC="/etc/securizar/kernel-runtime/falco-rules/securizar-rules.yaml"
        RULES_DST="/etc/falco/rules.d/securizar-rules.yaml"

        if [[ -f "$RULES_SRC" ]]; then
            echo "[OK] Reglas Securizar disponibles: $RULES_SRC"
            RULE_COUNT=$(grep -c '^\- rule:' "$RULES_SRC" 2>/dev/null || echo "0")
            echo "  Reglas definidas: $RULE_COUNT"
        fi

        if [[ -f "$RULES_DST" ]]; then
            echo "[OK] Reglas desplegadas en Falco: $RULES_DST"
        else
            echo "[INFO] Reglas NO desplegadas en Falco"
            echo "  Copiar: cp $RULES_SRC $RULES_DST"
        fi

        echo ""
        echo "=== Alertas recientes ==="
        if [[ -f /var/log/falco/falco.log ]]; then
            tail -20 /var/log/falco/falco.log 2>/dev/null || true
        else
            journalctl -u falco --no-pager -n 20 2>/dev/null || echo "  Sin logs de Falco"
        fi

        echo ""
        echo "Completado: $(date)"
        } 2>&1 | tee "$REPORT"
        ;;

    deploy)
        echo "=== Desplegando reglas Securizar en Falco ==="
        RULES_SRC="/etc/securizar/kernel-runtime/falco-rules/securizar-rules.yaml"
        RULES_DST="/etc/falco/rules.d/securizar-rules.yaml"

        if [[ ! -f "$RULES_SRC" ]]; then
            echo "[ERROR] Reglas no encontradas: $RULES_SRC"
            exit 1
        fi

        if [[ ! -d /etc/falco/rules.d ]]; then
            echo "[WARN] Directorio Falco no existe. ¿Está instalado?"
            mkdir -p /etc/falco/rules.d
        fi

        cp "$RULES_SRC" "$RULES_DST"
        echo "[OK] Reglas copiadas a $RULES_DST"

        if systemctl is-active falco &>/dev/null; then
            systemctl restart falco
            echo "[OK] Falco reiniciado"
        fi
        ;;

    *)
        echo "Uso: $0 {status|deploy}"
        echo ""
        echo "  status  — Ver estado de Falco y reglas"
        echo "  deploy  — Desplegar reglas Securizar en Falco"
        ;;
esac
EOFFALCOSH
    chmod +x /usr/local/bin/securizar-kernel-falco.sh

    log_change "Reglas Falco de Securizar creadas"
    log_change "Aplicado" "Sección 4: Falco con reglas para shadow, reverse shells, container escape"
}

# ── Sección 5: Kernel module signing enforcement ──
section_5() {
    log_section "5. Kernel module signing enforcement"

    if check_executable /usr/local/bin/securizar-kernel-modsign.sh; then
        log_already "Module signing (securizar-kernel-modsign.sh existe)"; return 0
    fi
    ask "¿Configurar verificación de firmas de módulos del kernel?" || { log_skip "Module signing omitido"; return 0; }

    mkdir -p /var/log/securizar/kernel-runtime

    cat > /usr/local/bin/securizar-kernel-modsign.sh << 'EOFMODSIGN'
#!/bin/bash
# ============================================================
# securizar-kernel-modsign.sh — Verificar firmas de módulos kernel
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar/kernel-runtime"
mkdir -p "$LOG_DIR"
REPORT="$LOG_DIR/modsign-$(date +%Y%m%d).txt"

{
echo "=========================================="
echo " Kernel Module Signing"
echo " $(date) - $(hostname)"
echo "=========================================="
echo ""

echo "=== Configuración de firma de módulos ==="
# Verificar config del kernel compilado
CONFIG="/boot/config-$(uname -r)"
if [[ -f "$CONFIG" ]]; then
    for opt in CONFIG_MODULE_SIG CONFIG_MODULE_SIG_FORCE CONFIG_MODULE_SIG_ALL \
               CONFIG_MODULE_SIG_SHA256 CONFIG_MODULE_SIG_SHA512; do
        VAL=$(grep "^${opt}=" "$CONFIG" 2>/dev/null || echo "${opt}=n")
        if echo "$VAL" | grep -q "=y"; then
            echo "  [OK] $VAL"
        else
            echo "  [--] $VAL"
        fi
    done
elif [[ -f /proc/config.gz ]]; then
    for opt in CONFIG_MODULE_SIG CONFIG_MODULE_SIG_FORCE; do
        VAL=$(zcat /proc/config.gz 2>/dev/null | grep "^${opt}=" || echo "${opt}=n")
        if echo "$VAL" | grep -q "=y"; then
            echo "  [OK] $VAL"
        else
            echo "  [--] $VAL"
        fi
    done
else
    echo "  [INFO] Config del kernel no accesible"
fi

echo ""
echo "=== Parámetros de cmdline ==="
CMDLINE=$(cat /proc/cmdline)
for param in "module.sig_enforce" "module.sig_unenforce"; do
    if echo "$CMDLINE" | grep -q "$param"; then
        echo "  [OK] $param encontrado en cmdline"
    else
        echo "  [--] $param NO en cmdline"
    fi
done

echo ""
echo "=== Módulos cargados sin firma ==="
UNSIGNED=0
TOTAL=0
while read -r mod_name _; do
    [[ -z "$mod_name" || "$mod_name" == "Module" ]] && continue
    ((TOTAL++))
    INFO=$(modinfo "$mod_name" 2>/dev/null || true)
    if echo "$INFO" | grep -q "^sig_id:"; then
        : # Firmado
    else
        echo "  [WARN] Sin firma: $mod_name"
        ((UNSIGNED++))
    fi
done < /proc/modules

echo ""
echo "Total módulos: $TOTAL"
echo "Sin firma: $UNSIGNED"

if [[ $UNSIGNED -eq 0 ]]; then
    echo "[OK] Todos los módulos están firmados"
else
    echo "[!!] $UNSIGNED módulos sin firma detectados"
fi

echo ""
echo "=== Restricción de carga dinámica ==="
MODULES_DISABLED=$(sysctl -n kernel.modules_disabled 2>/dev/null || echo "N/A")
echo "  kernel.modules_disabled = $MODULES_DISABLED"
if [[ "$MODULES_DISABLED" == "1" ]]; then
    echo "  [OK] Carga de nuevos módulos bloqueada"
else
    echo "  [INFO] Carga de módulos permitida (normal en operación)"
fi

echo ""
echo "Completado: $(date)"
} 2>&1 | tee "$REPORT"
EOFMODSIGN
    chmod +x /usr/local/bin/securizar-kernel-modsign.sh

    log_change "Verificador de firmas de módulos kernel instalado"
    log_change "Aplicado" "Sección 5: Detección de módulos sin firma, estado sig_enforce"
}

# ── Sección 6: Mitigaciones CPU avanzadas ──
section_6() {
    log_section "6. Mitigaciones CPU avanzadas"

    if check_executable /usr/local/bin/securizar-kernel-cpumit.sh; then
        log_already "CPU mitigations (securizar-kernel-cpumit.sh existe)"; return 0
    fi
    ask "¿Verificar y auditar mitigaciones de vulnerabilidades CPU?" || { log_skip "CPU mitigations omitidas"; return 0; }

    mkdir -p /var/log/securizar/kernel-runtime

    cat > /usr/local/bin/securizar-kernel-cpumit.sh << 'EOFCPUMIT'
#!/bin/bash
# ============================================================
# securizar-kernel-cpumit.sh — Auditoría de mitigaciones CPU
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar/kernel-runtime"
mkdir -p "$LOG_DIR"
REPORT="$LOG_DIR/cpu-mitigations-$(date +%Y%m%d).txt"

{
echo "=========================================="
echo " Mitigaciones de Vulnerabilidades CPU"
echo " $(date) - $(hostname)"
echo "=========================================="
echo ""

echo "=== CPU ==="
CPU_MODEL=$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || echo "Desconocido")
echo "  Modelo: $CPU_MODEL"
echo ""

echo "=== Vulnerabilidades conocidas (/sys/devices/system/cpu/vulnerabilities/) ==="
VULN_DIR="/sys/devices/system/cpu/vulnerabilities"
if [[ -d "$VULN_DIR" ]]; then
    MITIGATED=0
    VULNERABLE=0
    for vuln in "$VULN_DIR"/*; do
        VNAME=$(basename "$vuln")
        STATUS=$(cat "$vuln" 2>/dev/null || echo "desconocido")
        if echo "$STATUS" | grep -qi "not affected\|mitigat"; then
            echo "  [OK] $VNAME: $STATUS"
            ((MITIGATED++))
        elif echo "$STATUS" | grep -qi "vulnerable"; then
            echo "  [!!] $VNAME: $STATUS"
            ((VULNERABLE++))
        else
            echo "  [--] $VNAME: $STATUS"
        fi
    done
    echo ""
    echo "  Mitigadas: $MITIGATED | Vulnerables: $VULNERABLE"
else
    echo "  [WARN] Directorio de vulnerabilidades no disponible"
fi

echo ""
echo "=== Parámetros de cmdline de mitigación ==="
CMDLINE=$(cat /proc/cmdline)
MIT_PARAMS=(
    "mitigations:Estado global de mitigaciones"
    "spectre_v1:Spectre v1 (bounds check bypass)"
    "spectre_v2:Spectre v2 (branch target injection)"
    "spec_store_bypass_disable:Spectre v4 (speculative store bypass)"
    "mds:Microarchitectural Data Sampling"
    "tsx_async_abort:TSX Asynchronous Abort"
    "l1tf:L1 Terminal Fault"
    "srbds:Special Register Buffer Data Sampling"
    "mmio_stale_data:MMIO Stale Data"
    "retbleed:Retbleed"
    "tsx:TSX control"
    "pti:Page Table Isolation (Meltdown)"
)

for entry in "${MIT_PARAMS[@]}"; do
    param="${entry%%:*}"
    desc="${entry#*:}"
    if echo "$CMDLINE" | grep -qoP "${param}=\S+"; then
        VAL=$(echo "$CMDLINE" | grep -oP "${param}=\S+")
        echo "  [OK] $VAL ($desc)"
    else
        echo "  [--] $param no explícito ($desc)"
    fi
done

echo ""
echo "=== Recomendaciones ==="
if echo "$CMDLINE" | grep -q "mitigations=off"; then
    echo "  [CRIT] mitigations=off detectado — TODAS las mitigaciones desactivadas"
    echo "  Remover mitigations=off de GRUB_CMDLINE_LINUX"
fi
echo "  Recomendado: mitigations=auto,nosmt (si no necesita HyperThreading)"
echo "  Alternativa: espectre_v2=on spec_store_bypass_disable=on tsx=off pti=on"

echo ""
echo "Completado: $(date)"
} 2>&1 | tee "$REPORT"
EOFCPUMIT
    chmod +x /usr/local/bin/securizar-kernel-cpumit.sh

    log_change "Auditor de mitigaciones CPU instalado"
    log_change "Aplicado" "Sección 6: Spectre, MDS, TAA, L1TF, Retbleed, MMIO, TSX"
}

# ── Sección 7: Protección memoria kernel ──
section_7() {
    log_section "7. Protección memoria kernel"

    if check_executable /usr/local/bin/securizar-kernel-memory.sh; then
        log_already "Kernel memory protection (securizar-kernel-memory.sh existe)"; return 0
    fi
    ask "¿Aplicar hardening de memoria del kernel (KFENCE, usercopy, init_on_alloc)?" || { log_skip "Kernel memory omitido"; return 0; }

    mkdir -p /var/log/securizar/kernel-runtime

    # Sysctl de memoria
    local SYSCTL_FILE="/etc/sysctl.d/90-securizar-kernel-memory.conf"
    backup_if_exists "$SYSCTL_FILE"

    cat > "$SYSCTL_FILE" << 'EOF'
# Securizar — Protección memoria kernel
# Randomizar stack del kernel en cada syscall
kernel.randomize_va_space = 2
EOF
    sysctl -p "$SYSCTL_FILE" 2>/dev/null || true

    # Script de verificación
    cat > /usr/local/bin/securizar-kernel-memory.sh << 'EOFKMEM'
#!/bin/bash
# ============================================================
# securizar-kernel-memory.sh — Verificar protección memoria kernel
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar/kernel-runtime"
mkdir -p "$LOG_DIR"
REPORT="$LOG_DIR/kernel-memory-$(date +%Y%m%d).txt"

{
echo "=========================================="
echo " Protección de Memoria del Kernel"
echo " $(date) - $(hostname)"
echo "=========================================="
echo ""

echo "=== Parámetros de cmdline ==="
CMDLINE=$(cat /proc/cmdline)
MEM_PARAMS=(
    "init_on_alloc:Inicializar memoria al alocar (prevent info leak)"
    "init_on_free:Inicializar memoria al liberar"
    "slab_nomerge:Evitar merge de slabs (dificulta heap exploits)"
    "page_alloc.shuffle:Randomizar alocación de páginas"
    "hardened_usercopy:Validar copias user/kernel"
    "random.trust_cpu:Confiar en RDRAND del CPU"
)

for entry in "${MEM_PARAMS[@]}"; do
    param="${entry%%:*}"
    desc="${entry#*:}"
    if echo "$CMDLINE" | grep -qoP "${param}(=\S+)?"; then
        VAL=$(echo "$CMDLINE" | grep -oP "${param}(=\S+)?" || echo "$param")
        echo "  [OK] $VAL ($desc)"
    else
        echo "  [--] $param no configurado ($desc)"
    fi
done

echo ""
echo "=== Configuración del kernel compilado ==="
CONFIG="/boot/config-$(uname -r)"
if [[ -f "$CONFIG" ]]; then
    MEM_OPTS=(
        CONFIG_HARDENED_USERCOPY
        CONFIG_KFENCE
        CONFIG_INIT_ON_ALLOC_DEFAULT_ON
        CONFIG_INIT_ON_FREE_DEFAULT_ON
        CONFIG_SLAB_FREELIST_HARDENED
        CONFIG_SLAB_FREELIST_RANDOM
        CONFIG_SHUFFLE_PAGE_ALLOCATOR
        CONFIG_GCC_PLUGIN_STRUCTLEAK
        CONFIG_GCC_PLUGIN_STACKLEAK
    )
    for opt in "${MEM_OPTS[@]}"; do
        VAL=$(grep "^${opt}=" "$CONFIG" 2>/dev/null || echo "${opt} no definido")
        if echo "$VAL" | grep -q "=y"; then
            echo "  [OK] $VAL"
        else
            echo "  [--] $VAL"
        fi
    done
else
    echo "  [INFO] Config del kernel no accesible"
fi

echo ""
echo "=== KFENCE ==="
if [[ -d /sys/kernel/debug/kfence ]]; then
    echo "  [OK] KFENCE activo"
    for f in /sys/kernel/debug/kfence/*; do
        [[ -f "$f" ]] && echo "    $(basename "$f"): $(head -1 "$f" 2>/dev/null || echo 'N/A')"
    done
elif grep -q "CONFIG_KFENCE=y" "$CONFIG" 2>/dev/null; then
    echo "  [OK] KFENCE compilado en el kernel"
else
    echo "  [--] KFENCE no disponible"
fi

echo ""
echo "=== Recomendaciones cmdline ==="
echo "  init_on_alloc=1 init_on_free=1 slab_nomerge page_alloc.shuffle=1"
echo "  hardened_usercopy=1 random.trust_cpu=off"

echo ""
echo "Completado: $(date)"
} 2>&1 | tee "$REPORT"
EOFKMEM
    chmod +x /usr/local/bin/securizar-kernel-memory.sh

    log_change "Verificador de protección de memoria kernel instalado"
    log_change "Aplicado" "Sección 7: KFENCE, hardened_usercopy, init_on_alloc, slab_nomerge"
}

# ── Sección 8: Restricción interfaces debug ──
section_8() {
    log_section "8. Restricción interfaces debug"

    if check_executable /usr/local/bin/securizar-kernel-debug.sh; then
        log_already "Debug restriction (securizar-kernel-debug.sh existe)"; return 0
    fi
    ask "¿Restringir interfaces de debug del kernel (kprobes, ftrace, perf, dmesg)?" || { log_skip "Debug restriction omitida"; return 0; }

    mkdir -p /var/log/securizar/kernel-runtime

    # Sysctl de restricción debug
    local SYSCTL_FILE="/etc/sysctl.d/90-securizar-kernel-debug.conf"
    backup_if_exists "$SYSCTL_FILE"

    cat > "$SYSCTL_FILE" << 'EOF'
# Securizar — Restricción de interfaces debug del kernel
# Restringir acceso a perf_event (3 = solo root)
kernel.perf_event_paranoid = 3
# Ocultar punteros del kernel en logs
kernel.kptr_restrict = 2
# Restringir dmesg a root
kernel.dmesg_restrict = 1
EOF
    sysctl -p "$SYSCTL_FILE" 2>/dev/null || true

    # Script de verificación
    cat > /usr/local/bin/securizar-kernel-debug.sh << 'EOFDEBUG'
#!/bin/bash
# ============================================================
# securizar-kernel-debug.sh — Verificar restricciones debug kernel
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar/kernel-runtime"
mkdir -p "$LOG_DIR"
REPORT="$LOG_DIR/kernel-debug-$(date +%Y%m%d).txt"

{
echo "=========================================="
echo " Restricción de Interfaces Debug"
echo " $(date) - $(hostname)"
echo "=========================================="
echo ""

echo "=== Sysctl de seguridad ==="
CHECKS=(
    "kernel.perf_event_paranoid:3:Restringir perf a root"
    "kernel.kptr_restrict:2:Ocultar punteros kernel"
    "kernel.dmesg_restrict:1:Restringir dmesg a root"
)

for entry in "${CHECKS[@]}"; do
    key="${entry%%:*}"
    rest="${entry#*:}"
    expected="${rest%%:*}"
    desc="${rest#*:}"
    val=$(sysctl -n "$key" 2>/dev/null || echo "N/A")
    if [[ "$val" == "$expected" ]]; then
        echo "  [OK] $key = $val ($desc)"
    elif [[ "$val" -ge "$expected" ]] 2>/dev/null; then
        echo "  [OK] $key = $val (>= $expected) ($desc)"
    else
        echo "  [!!] $key = $val (esperado: $expected) — $desc"
    fi
done

echo ""
echo "=== kprobes ==="
KPROBES=$(sysctl -n debug.kprobes-optimization 2>/dev/null || echo "N/A")
if [[ -f /proc/sys/debug/kprobes-optimization ]]; then
    echo "  kprobes-optimization: $KPROBES"
fi
if [[ -f /sys/kernel/debug/kprobes/enabled ]]; then
    KP_ENABLED=$(cat /sys/kernel/debug/kprobes/enabled 2>/dev/null || echo "?")
    if [[ "$KP_ENABLED" == "0" ]]; then
        echo "  [OK] kprobes deshabilitados"
    else
        echo "  [INFO] kprobes habilitados (considerar deshabilitar en producción)"
    fi
else
    echo "  [INFO] kprobes: no accesible (debugfs puede estar desmontado)"
fi

echo ""
echo "=== ftrace ==="
if [[ -f /sys/kernel/debug/tracing/tracing_on ]]; then
    FTRACE=$(cat /sys/kernel/debug/tracing/tracing_on 2>/dev/null || echo "?")
    if [[ "$FTRACE" == "0" ]]; then
        echo "  [OK] ftrace desactivado"
    else
        echo "  [INFO] ftrace activo (normal si se usa para monitoreo)"
    fi
else
    echo "  [INFO] ftrace: no accesible"
fi

echo ""
echo "=== debugfs ==="
CMDLINE=$(cat /proc/cmdline)
if echo "$CMDLINE" | grep -q "debugfs=off"; then
    echo "  [OK] debugfs=off en cmdline"
elif mountpoint -q /sys/kernel/debug 2>/dev/null; then
    echo "  [INFO] debugfs montado (considerar debugfs=off en GRUB)"
else
    echo "  [OK] debugfs no montado"
fi

echo ""
echo "Completado: $(date)"
} 2>&1 | tee "$REPORT"
EOFDEBUG
    chmod +x /usr/local/bin/securizar-kernel-debug.sh

    log_change "Restricción de interfaces debug aplicada"
    log_change "Aplicado" "Sección 8: perf_event_paranoid=3, kptr_restrict=2, dmesg_restrict=1"
}

# ── Sección 9: Verificación integridad runtime ──
section_9() {
    log_section "9. Verificación integridad runtime"

    if check_executable /usr/local/bin/securizar-kernel-integrity.sh; then
        log_already "Runtime integrity (securizar-kernel-integrity.sh existe)"; return 0
    fi
    ask "¿Instalar verificador de integridad de módulos cargados vs baseline?" || { log_skip "Integridad runtime omitida"; return 0; }

    mkdir -p /var/log/securizar/kernel-runtime /etc/securizar/kernel-runtime

    cat > /usr/local/bin/securizar-kernel-integrity.sh << 'EOFINTEGRITY'
#!/bin/bash
# ============================================================
# securizar-kernel-integrity.sh — Verificar integridad runtime
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar/kernel-runtime"
mkdir -p "$LOG_DIR"
BASELINE="/etc/securizar/kernel-runtime/modules-baseline.txt"
REPORT="$LOG_DIR/integrity-$(date +%Y%m%d).txt"
ACTION="${1:-check}"

case "$ACTION" in
    baseline)
        echo "=== Generando baseline de módulos ==="
        {
            echo "# Securizar — Baseline de módulos kernel"
            echo "# Generado: $(date -Iseconds)"
            echo "# Kernel: $(uname -r)"
            echo "#"
            while read -r mod_name size used_by deps state addr; do
                [[ -z "$mod_name" || "$mod_name" == "Module" ]] && continue
                # Obtener hash del módulo
                MOD_PATH=$(modinfo -n "$mod_name" 2>/dev/null || echo "builtin")
                if [[ -f "$MOD_PATH" ]]; then
                    HASH=$(sha256sum "$MOD_PATH" | cut -d' ' -f1)
                else
                    HASH="builtin"
                fi
                echo "$mod_name|$HASH|$MOD_PATH"
            done < /proc/modules
        } > "$BASELINE"
        echo "[OK] Baseline guardada: $BASELINE"
        echo "  Módulos registrados: $(grep -cv '^#' "$BASELINE")"
        ;;

    check)
        {
        echo "=========================================="
        echo " Verificación de Integridad Runtime"
        echo " $(date) - $(hostname)"
        echo "=========================================="
        echo ""

        if [[ ! -f "$BASELINE" ]]; then
            echo "[WARN] No hay baseline. Generar con: $0 baseline"
            echo ""
            echo "=== Módulos actualmente cargados ==="
            lsmod | head -30
            exit 0
        fi

        echo "=== Comparando módulos contra baseline ==="
        echo "  Baseline: $BASELINE"
        echo "  Generada: $(head -2 "$BASELINE" | tail -1 | sed 's/# Generado: //')"
        echo ""

        # Cargar baseline en array asociativo
        declare -A BASELINE_HASH
        while IFS='|' read -r bmod bhash bpath; do
            [[ -z "$bmod" || "$bmod" =~ ^# ]] && continue
            BASELINE_HASH["$bmod"]="$bhash"
        done < "$BASELINE"

        UNEXPECTED=0
        MODIFIED=0
        MISSING=0

        # Verificar módulos actuales vs baseline
        while read -r mod_name _; do
            [[ -z "$mod_name" || "$mod_name" == "Module" ]] && continue

            if [[ -z "${BASELINE_HASH[$mod_name]:-}" ]]; then
                echo "  [!!] INESPERADO: $mod_name (no en baseline)"
                ((UNEXPECTED++))
            else
                MOD_PATH=$(modinfo -n "$mod_name" 2>/dev/null || echo "builtin")
                if [[ -f "$MOD_PATH" ]]; then
                    CUR_HASH=$(sha256sum "$MOD_PATH" | cut -d' ' -f1)
                    if [[ "$CUR_HASH" != "${BASELINE_HASH[$mod_name]}" ]]; then
                        echo "  [!!] MODIFICADO: $mod_name (hash difiere)"
                        ((MODIFIED++))
                    fi
                fi
                unset "BASELINE_HASH[$mod_name]"
            fi
        done < /proc/modules

        # Módulos en baseline pero no cargados
        for missing_mod in "${!BASELINE_HASH[@]}"; do
            echo "  [--] NO CARGADO: $missing_mod (estaba en baseline)"
            ((MISSING++))
        done

        echo ""
        echo "=== Resumen ==="
        echo "  Inesperados: $UNEXPECTED"
        echo "  Modificados: $MODIFIED"
        echo "  No cargados: $MISSING"

        if [[ $UNEXPECTED -eq 0 && $MODIFIED -eq 0 ]]; then
            echo ""
            echo "[OK] Integridad de módulos verificada"
        else
            echo ""
            echo "[!!] Se detectaron anomalías en módulos del kernel"
        fi

        echo ""
        echo "Completado: $(date)"
        } 2>&1 | tee "$REPORT"
        ;;

    *)
        echo "Uso: $0 {baseline|check}"
        echo ""
        echo "  baseline — Generar baseline de módulos actuales"
        echo "  check    — Comparar módulos actuales contra baseline"
        ;;
esac
EOFINTEGRITY
    chmod +x /usr/local/bin/securizar-kernel-integrity.sh

    log_change "Verificador de integridad runtime de módulos instalado"
    log_change "Aplicado" "Sección 9: Baseline y comparación de hashes de módulos kernel"
}

# ── Sección 10: Auditoría completa del kernel ──
section_10() {
    log_section "10. Auditoría completa del kernel"

    if check_executable /usr/local/bin/auditoria-kernel-runtime.sh; then
        log_already "Auditoría kernel (auditoria-kernel-runtime.sh existe)"; return 0
    fi
    ask "¿Instalar auditoría completa del kernel con scoring?" || { log_skip "Auditoría kernel omitida"; return 0; }

    mkdir -p /var/log/securizar/kernel-runtime

    cat > /usr/local/bin/auditoria-kernel-runtime.sh << 'EOFAUDIT'
#!/bin/bash
# ============================================================
# auditoria-kernel-runtime.sh — Auditoría integral kernel runtime
# ============================================================
set -euo pipefail

LOG_DIR="/var/log/securizar/kernel-runtime"
mkdir -p "$LOG_DIR"
REPORT="$LOG_DIR/auditoria-kernel-$(date +%Y%m%d).txt"

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
echo " Auditoría de Seguridad Runtime del Kernel"
echo " $(date) - $(hostname)"
echo " Kernel: $(uname -r)"
echo "=========================================="
echo ""

echo "=== 1. LKRG ==="
check_item "LKRG módulo cargado" 3 "lsmod | grep -q '^lkrg'"
check_item "LKRG disponible (modinfo)" 1 "modinfo lkrg"
check_item "Configuración LKRG Securizar" 1 "test -f /etc/securizar/kernel-runtime/lkrg.conf"

echo ""
echo "=== 2. Kernel Lockdown ==="
check_item "Lockdown activo (integrity o confidentiality)" 3 \
    "cat /sys/kernel/security/lockdown 2>/dev/null | grep -qv '\[none\]'"
check_item "lockdown= en cmdline" 2 "grep -q 'lockdown=' /proc/cmdline"

echo ""
echo "=== 3. eBPF Hardening ==="
check_item "BPF no privilegiado deshabilitado" 2 "test $(sysctl -n kernel.unprivileged_bpf_disabled 2>/dev/null) -eq 1"
check_item "BPF JIT harden=2" 2 "test $(sysctl -n net.core.bpf_jit_harden 2>/dev/null) -eq 2"

echo ""
echo "=== 4. Falco ==="
check_item "Falco instalado" 2 "command -v falco"
check_item "Falco servicio activo" 2 "systemctl is-active falco"
check_item "Reglas Securizar desplegadas" 1 "test -f /etc/falco/rules.d/securizar-rules.yaml"

echo ""
echo "=== 5. Firmas de módulos ==="
check_item "Script modsign instalado" 1 "test -x /usr/local/bin/securizar-kernel-modsign.sh"
check_item "CONFIG_MODULE_SIG habilitado" 2 \
    "grep -q 'CONFIG_MODULE_SIG=y' /boot/config-$(uname -r) 2>/dev/null || zcat /proc/config.gz 2>/dev/null | grep -q 'CONFIG_MODULE_SIG=y'"

echo ""
echo "=== 6. Mitigaciones CPU ==="
check_item "mitigations != off" 3 "! grep -q 'mitigations=off' /proc/cmdline"
check_item "PTI habilitado" 2 \
    "grep -q 'Mitigation' /sys/devices/system/cpu/vulnerabilities/meltdown 2>/dev/null"
check_item "Spectre v2 mitigado" 2 \
    "grep -q 'Mitigation' /sys/devices/system/cpu/vulnerabilities/spectre_v2 2>/dev/null"

echo ""
echo "=== 7. Memoria Kernel ==="
check_item "init_on_alloc=1 en cmdline" 2 "grep -q 'init_on_alloc=1' /proc/cmdline"
check_item "slab_nomerge en cmdline" 1 "grep -q 'slab_nomerge' /proc/cmdline"
check_item "ASLR = 2" 2 "test $(sysctl -n kernel.randomize_va_space 2>/dev/null) -eq 2"

echo ""
echo "=== 8. Restricciones Debug ==="
check_item "perf_event_paranoid >= 3" 2 "test $(sysctl -n kernel.perf_event_paranoid 2>/dev/null) -ge 3"
check_item "kptr_restrict = 2" 2 "test $(sysctl -n kernel.kptr_restrict 2>/dev/null) -eq 2"
check_item "dmesg_restrict = 1" 2 "test $(sysctl -n kernel.dmesg_restrict 2>/dev/null) -eq 1"
check_item "debugfs=off en cmdline" 1 "grep -q 'debugfs=off' /proc/cmdline"

echo ""
echo "=== 9. Integridad Runtime ==="
check_item "Script integridad instalado" 1 "test -x /usr/local/bin/securizar-kernel-integrity.sh"
check_item "Baseline de módulos existe" 2 "test -f /etc/securizar/kernel-runtime/modules-baseline.txt"

echo ""
echo "=== 10. Scripts Securizar ==="
check_item "securizar-kernel-lkrg.sh" 1 "test -x /usr/local/bin/securizar-kernel-lkrg.sh"
check_item "securizar-kernel-lockdown.sh" 1 "test -x /usr/local/bin/securizar-kernel-lockdown.sh"
check_item "securizar-kernel-ebpf.sh" 1 "test -x /usr/local/bin/securizar-kernel-ebpf.sh"
check_item "securizar-kernel-falco.sh" 1 "test -x /usr/local/bin/securizar-kernel-falco.sh"
check_item "securizar-kernel-cpumit.sh" 1 "test -x /usr/local/bin/securizar-kernel-cpumit.sh"
check_item "securizar-kernel-memory.sh" 1 "test -x /usr/local/bin/securizar-kernel-memory.sh"
check_item "securizar-kernel-debug.sh" 1 "test -x /usr/local/bin/securizar-kernel-debug.sh"

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
    echo " Calificación: ██████████ EXCELENTE"
    echo " La seguridad runtime del kernel está bien configurada."
elif [[ $PCT -ge 60 ]]; then
    echo " Calificación: ███████░░░ BUENO"
    echo " La mayoría de protecciones runtime están activas."
elif [[ $PCT -ge 40 ]]; then
    echo " Calificación: █████░░░░░ MEJORABLE"
    echo " Hay aspectos de seguridad runtime que mejorar."
else
    echo " Calificación: ███░░░░░░░ DEFICIENTE"
    echo " La seguridad runtime del kernel necesita atención urgente."
fi

echo ""
echo " Auditado: $(date)"
echo "=========================================="
} 2>&1 | tee "$REPORT"

echo "Reporte: $REPORT"
EOFAUDIT
    chmod +x /usr/local/bin/auditoria-kernel-runtime.sh

    # Cron semanal
    cat > /etc/cron.weekly/securizar-kernel-audit << 'EOF'
#!/bin/bash
/usr/local/bin/auditoria-kernel-runtime.sh >> /var/log/securizar/kernel-runtime/audit-cron.log 2>&1
EOF
    chmod +x /etc/cron.weekly/securizar-kernel-audit

    log_change "Auditoría integral de seguridad runtime del kernel configurada"
    log_change "Aplicado" "Sección 10: Scoring de LKRG, lockdown, eBPF, Falco, CPU, memoria"
}

# ── Main ──
main() {
    log_section "MÓDULO 66: PROTECCIÓN RUNTIME DEL KERNEL"

    # ── Pre-check: detectar secciones ya aplicadas ──────────────
    _precheck 10
    _pc 'test -f /etc/securizar/kernel-runtime/lkrg.conf'
    _pc 'check_executable /usr/local/bin/securizar-kernel-lockdown.sh'
    _pc 'check_executable /usr/local/bin/securizar-kernel-ebpf.sh'
    _pc 'check_executable /usr/local/bin/securizar-kernel-falco.sh'
    _pc 'check_executable /usr/local/bin/securizar-kernel-modsign.sh'
    _pc 'check_executable /usr/local/bin/securizar-kernel-cpumit.sh'
    _pc 'check_executable /usr/local/bin/securizar-kernel-memory.sh'
    _pc 'check_executable /usr/local/bin/securizar-kernel-debug.sh'
    _pc 'check_executable /usr/local/bin/securizar-kernel-integrity.sh'
    _pc 'check_executable /usr/local/bin/auditoria-kernel-runtime.sh'
    _precheck_result

    for i in $(seq 1 10); do
        "section_$i"
    done
    echo ""
    show_changes_summary
}
main "$@"
