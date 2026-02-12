#!/bin/bash
# ============================================================
# CUMPLIMIENTO Y BENCHMARKS CIS - Modulo 41
# Linux Multi-Distro (openSUSE, Debian/Ubuntu, RHEL/Fedora, Arch)
# ============================================================
# Evaluacion de cumplimiento CIS Benchmark Level 1 y 2, con
# motor de puntuacion, remediacion segura, mapeo NIST 800-53
# y generacion de informes de cumplimiento automatizados.
#
# Secciones:
#   S1  - CIS Nivel 1: Sistema de archivos
#   S2  - CIS Nivel 1: Servicios
#   S3  - CIS Nivel 1: Red
#   S4  - CIS Nivel 1: Logging y auditoria
#   S5  - CIS Nivel 1: Acceso y autenticacion
#   S6  - CIS Nivel 2: Controles adicionales
#   S7  - Mapeo a NIST 800-53
#   S8  - Motor de puntuacion CIS
#   S9  - Remediacion automatica segura
#   S10 - Generacion de informe de cumplimiento
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps

# ── Pre-check rapido ────────────────────────────────────
_precheck 10
_pc true  # S1: auditoria filesystem (siempre re-evaluar)
_pc true  # S2: auditoria servicios (siempre re-evaluar)
_pc true  # S3: auditoria red (siempre re-evaluar)
_pc true  # S4: auditoria logging (siempre re-evaluar)
_pc true  # S5: auditoria acceso (siempre re-evaluar)
_pc true  # S6: controles nivel 2 (siempre re-evaluar)
_pc check_file_exists /var/lib/securizar/nist-mapping.json
_pc check_executable /usr/local/bin/cis-scoring.sh
_pc true  # S9: remediacion automatica (siempre re-evaluar)
_pc check_executable /usr/local/bin/reporte-cumplimiento-cis.sh
_precheck_result

# ── Variables globales ───────────────────────────────────────
CIS_BASE="/var/lib/securizar"
CIS_SCORES_DIR="${CIS_BASE}/cis-scores"
CIS_CONF_DIR="/etc/securizar"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"

mkdir -p "$CIS_BASE" "$CIS_SCORES_DIR" "$CIS_CONF_DIR"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   CUMPLIMIENTO Y BENCHMARKS CIS - Modulo 41              ║"
echo "║   CIS Level 1/2, NIST 800-53, scoring y reportes         ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# ────────────────────────────────────────────────────────────────
# S1: CIS NIVEL 1 - SISTEMA DE ARCHIVOS
# ────────────────────────────────────────────────────────────────
log_section "S1: CIS NIVEL 1 - SISTEMA DE ARCHIVOS"

echo "Verifica y corrige montajes, permisos y modulos de"
echo "almacenamiento segun CIS Benchmark para Linux."
echo ""
echo "Comprobaciones:"
echo "  - /tmp, /var, /var/tmp, /var/log, /home: opciones de montaje"
echo "  - Sticky bit en directorios world-writable"
echo "  - Deshabilitar automounting (autofs) y USB storage"
echo "  - Archivos world-writable y sin propietario"
echo "  - hidepid=2 en /proc"
echo ""

if ask "¿Evaluar y corregir sistema de archivos CIS?"; then

    # --- /tmp con nodev,nosuid,noexec ---
    log_info "Verificando opciones de montaje de /tmp..."
    if findmnt -n /tmp &>/dev/null; then
        tmp_opts=$(findmnt -n -o OPTIONS /tmp 2>/dev/null || echo "")
        missing_opts=""
        for opt in nodev nosuid noexec; do
            if ! echo "$tmp_opts" | grep -q "$opt"; then
                missing_opts="$missing_opts $opt"
            fi
        done
        if [[ -z "$missing_opts" ]]; then
            log_info "  /tmp: nodev,nosuid,noexec presentes"
        else
            log_warn "  /tmp: faltan opciones:$missing_opts"
            if grep -q " /tmp " /etc/fstab 2>/dev/null; then
                log_warn "  Agrega nodev,nosuid,noexec a /tmp en /etc/fstab manualmente"
            fi
        fi
    else
        log_warn "  /tmp no esta en una particion separada (CIS recomienda particion dedicada)"
    fi

    # --- /var, /var/tmp, /var/log, /home ---
    for mnt in /var /var/tmp /var/log /home; do
        if findmnt -n "$mnt" &>/dev/null; then
            mnt_opts=$(findmnt -n -o OPTIONS "$mnt" 2>/dev/null || echo "")
            if echo "$mnt_opts" | grep -q "nodev"; then
                log_info "  $mnt: nodev presente"
            else
                log_warn "  $mnt: falta nodev"
            fi
            if [[ "$mnt" == "/var/tmp" ]]; then
                for opt in nosuid noexec; do
                    if ! echo "$mnt_opts" | grep -q "$opt"; then
                        log_warn "  $mnt: falta $opt"
                    fi
                done
            fi
            if [[ "$mnt" == "/home" ]]; then
                if ! echo "$mnt_opts" | grep -q "nosuid"; then
                    log_warn "  $mnt: falta nosuid"
                fi
            fi
        else
            log_warn "  $mnt: no montado en particion separada"
        fi
    done

    # --- Sticky bit en directorios world-writable ---
    log_info "Verificando sticky bit en directorios world-writable..."
    ww_no_sticky=$(find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | head -20 || true)
    if [[ -n "$ww_no_sticky" ]]; then
        ww_count=$(echo "$ww_no_sticky" | wc -l)
        log_warn "  $ww_count directorios world-writable sin sticky bit"
        echo "$ww_no_sticky" | while IFS= read -r dir; do
            echo "    $dir"
        done
        if ask "¿Aplicar sticky bit a estos directorios?"; then
            echo "$ww_no_sticky" | while IFS= read -r dir; do
                chmod +t "$dir" 2>/dev/null || true
            done
            log_change "Permisos" "sticky bit aplicado a $ww_count directorios"
        fi
    else
        log_info "  Todos los directorios world-writable tienen sticky bit"
    fi

    # --- Deshabilitar automounting (autofs) ---
    if systemctl is-enabled autofs &>/dev/null 2>&1; then
        log_warn "  autofs esta habilitado"
        if ask "¿Deshabilitar autofs?"; then
            systemctl stop autofs 2>/dev/null || true
            systemctl disable autofs 2>/dev/null || true
            log_change "Deshabilitado" "autofs (automounting)"
        fi
    else
        log_info "  autofs no esta habilitado"
    fi

    # --- Deshabilitar USB storage ---
    usb_loaded=$(lsmod 2>/dev/null | grep -c "^usb_storage" || true)
    if [[ "$usb_loaded" -gt 0 ]]; then
        log_warn "  Modulo usb_storage cargado"
        if ask "¿Deshabilitar modulo usb_storage?"; then
            echo "install usb-storage /bin/true" > /etc/modprobe.d/cis-usb-storage.conf
            echo "blacklist usb-storage" >> /etc/modprobe.d/cis-usb-storage.conf
            log_change "Creado" "/etc/modprobe.d/cis-usb-storage.conf"
            log_warn "  usb_storage se deshabilitara en el proximo reinicio"
        fi
    else
        if [[ -f /etc/modprobe.d/cis-usb-storage.conf ]]; then
            log_info "  usb_storage ya esta deshabilitado via modprobe.d"
        else
            log_info "  usb_storage no esta cargado"
        fi
    fi

    # --- Archivos world-writable ---
    log_info "Buscando archivos world-writable (puede tardar)..."
    ww_files=$(find / -xdev -type f -perm -0002 2>/dev/null | head -30 || true)
    if [[ -n "$ww_files" ]]; then
        ww_fcount=$(echo "$ww_files" | wc -l)
        log_warn "  $ww_fcount archivos world-writable encontrados (primeros 30):"
        echo "$ww_files" | while IFS= read -r f; do
            echo "    $f"
        done
    else
        log_info "  No se encontraron archivos world-writable"
    fi

    # --- Archivos sin propietario ---
    log_info "Buscando archivos sin propietario..."
    no_user=$(find / -xdev \( -nouser -o -nogroup \) 2>/dev/null | head -20 || true)
    if [[ -n "$no_user" ]]; then
        no_count=$(echo "$no_user" | wc -l)
        log_warn "  $no_count archivos sin usuario o grupo valido:"
        echo "$no_user" | while IFS= read -r f; do
            echo "    $f"
        done
    else
        log_info "  Todos los archivos tienen propietario valido"
    fi

    # --- hidepid=2 en /proc ---
    proc_opts=$(findmnt -n -o OPTIONS /proc 2>/dev/null || echo "")
    if echo "$proc_opts" | grep -q "hidepid=2"; then
        log_info "  /proc montado con hidepid=2"
    else
        log_warn "  /proc sin hidepid=2 (los procesos de otros usuarios son visibles)"
        if ! grep -q "hidepid=2" /etc/fstab 2>/dev/null; then
            log_warn "  Agrega 'proc /proc proc defaults,hidepid=2 0 0' a /etc/fstab"
        fi
    fi

    log_info "Evaluacion CIS sistema de archivos completada"

else
    log_skip "CIS Nivel 1: Sistema de archivos"
fi

# ────────────────────────────────────────────────────────────────
# S2: CIS NIVEL 1 - SERVICIOS
# ────────────────────────────────────────────────────────────────
log_section "S2: CIS NIVEL 1 - SERVICIOS"

echo "Verifica y deshabilita servicios innecesarios segun CIS."
echo ""
echo "Servicios a verificar:"
echo "  - xinetd, telnet, rsh, talk, tftp, chargen, daytime, echo"
echo "  - NFS (nfs-server, rpcbind), DNS, HTTP, SNMP, Samba"
echo "  - squid, ypserv, ypbind"
echo ""

if ask "¿Evaluar y deshabilitar servicios innecesarios CIS?"; then

    # Lista de servicios a verificar y deshabilitar
    declare -A CIS_SERVICES=(
        ["xinetd"]="xinetd"
        ["telnet-server"]="telnet.socket"
        ["rsh-server"]="rsh.socket"
        ["talk-server"]="ntalk"
        ["tftp-server"]="tftp.socket"
        ["chargen"]="chargen-dgram chargen-stream"
        ["daytime"]="daytime-dgram daytime-stream"
        ["echo-svc"]="echo-dgram echo-stream"
        ["discard"]="discard-dgram discard-stream"
        ["nfs-server"]="nfs-server"
        ["rpcbind"]="rpcbind rpcbind.socket"
        ["named"]="named"
        ["httpd"]="httpd apache2 nginx"
        ["snmpd"]="snmpd"
        ["smb"]="smb nmb"
        ["squid"]="squid"
        ["ypserv"]="ypserv"
        ["ypbind"]="ypbind"
    )

    for svc_name in "${!CIS_SERVICES[@]}"; do
        svc_units="${CIS_SERVICES[$svc_name]}"
        svc_found=false
        svc_active=false

        for unit in $svc_units; do
            if systemctl list-unit-files "${unit}.service" &>/dev/null 2>&1 || \
               systemctl list-unit-files "${unit}" &>/dev/null 2>&1; then
                if systemctl is-enabled "$unit" &>/dev/null 2>&1; then
                    svc_found=true
                    svc_active=true
                    break
                elif systemctl is-active "$unit" &>/dev/null 2>&1; then
                    svc_found=true
                    svc_active=true
                    break
                else
                    svc_found=true
                fi
            fi
        done

        if $svc_active; then
            log_warn "  [FAIL] $svc_name: servicio activo/habilitado"
            if ask "¿Deshabilitar $svc_name?"; then
                for unit in $svc_units; do
                    systemctl stop "$unit" 2>/dev/null || true
                    systemctl disable "$unit" 2>/dev/null || true
                done
                log_change "Deshabilitado" "$svc_name ($svc_units)"
            fi
        elif $svc_found; then
            log_info "  [PASS] $svc_name: instalado pero no activo"
        else
            echo -e "  ${DIM}[N/A]  $svc_name: no instalado${NC}"
        fi
    done

    log_info "Evaluacion CIS servicios completada"

else
    log_skip "CIS Nivel 1: Servicios"
fi

# ────────────────────────────────────────────────────────────────
# S3: CIS NIVEL 1 - RED
# ────────────────────────────────────────────────────────────────
log_section "S3: CIS NIVEL 1 - RED"

echo "Verifica y aplica parametros de red segun CIS Benchmark."
echo ""
echo "Parametros sysctl:"
echo "  - IP forwarding, packet redirects, source routing"
echo "  - ICMP redirects, log_martians, SYN cookies"
echo "  - IPv6: router advertisements, redirects"
echo ""

if ask "¿Evaluar y aplicar hardening de red CIS?"; then

    # Parametros CIS de red
    declare -A CIS_NET_PARAMS=(
        ["net.ipv4.ip_forward"]="0"
        ["net.ipv4.conf.all.send_redirects"]="0"
        ["net.ipv4.conf.default.send_redirects"]="0"
        ["net.ipv4.conf.all.accept_source_route"]="0"
        ["net.ipv4.conf.default.accept_source_route"]="0"
        ["net.ipv4.conf.all.accept_redirects"]="0"
        ["net.ipv4.conf.default.accept_redirects"]="0"
        ["net.ipv4.conf.all.secure_redirects"]="1"
        ["net.ipv4.conf.default.secure_redirects"]="1"
        ["net.ipv4.conf.all.log_martians"]="1"
        ["net.ipv4.conf.default.log_martians"]="1"
        ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
        ["net.ipv4.tcp_syncookies"]="1"
        ["net.ipv6.conf.all.accept_ra"]="0"
        ["net.ipv6.conf.default.accept_ra"]="0"
        ["net.ipv6.conf.all.accept_redirects"]="0"
        ["net.ipv6.conf.default.accept_redirects"]="0"
    )

    conf_file="/etc/sysctl.d/99-securizar-cis-network.conf"
    needs_write=false

    {
        echo "# ============================================================"
        echo "# CIS Benchmark - Hardening de red"
        echo "# Generado por securizar - cumplimiento-cis.sh"
        echo "# Fecha: $(date -Iseconds)"
        echo "# ============================================================"
        echo ""
    } > "$conf_file"

    for param in "${!CIS_NET_PARAMS[@]}"; do
        expected="${CIS_NET_PARAMS[$param]}"
        current=$(sysctl -n "$param" 2>/dev/null || echo "N/A")

        if [[ "$current" == "$expected" ]]; then
            log_info "  [PASS] $param = $current"
        else
            log_warn "  [FAIL] $param = $current (esperado: $expected)"
            needs_write=true
        fi
        echo "$param = $expected" >> "$conf_file"
    done

    if $needs_write; then
        sysctl -p "$conf_file" &>/dev/null || true
        log_change "Creado" "$conf_file"
        log_change "Aplicado" "sysctl -p $conf_file"
        log_info "Parametros de red CIS aplicados"
    else
        log_info "Todos los parametros de red ya cumplen CIS"
    fi

else
    log_skip "CIS Nivel 1: Red"
fi

# ────────────────────────────────────────────────────────────────
# S4: CIS NIVEL 1 - LOGGING Y AUDITORIA
# ────────────────────────────────────────────────────────────────
log_section "S4: CIS NIVEL 1 - LOGGING Y AUDITORIA"

echo "Verifica configuracion de logging y auditoria CIS."
echo ""
echo "Comprobaciones:"
echo "  - rsyslog/journald configurados"
echo "  - Permisos de archivos de log"
echo "  - auditd instalado y habilitado"
echo "  - Reglas de auditoria CIS"
echo "  - Backlog y space_left_action"
echo ""

if ask "¿Evaluar y configurar logging y auditoria CIS?"; then

    # --- rsyslog o journald ---
    if systemctl is-active --quiet rsyslog 2>/dev/null; then
        log_info "  [PASS] rsyslog activo"
    elif systemctl is-active --quiet systemd-journald 2>/dev/null; then
        log_info "  [PASS] systemd-journald activo"
        if [[ -f /etc/systemd/journald.conf ]]; then
            storage=$(grep -E "^Storage=" /etc/systemd/journald.conf 2>/dev/null | cut -d= -f2 || echo "auto")
            if [[ "$storage" == "persistent" ]]; then
                log_info "  [PASS] journald: Storage=persistent"
            else
                log_warn "  [FAIL] journald: Storage=$storage (recomendado: persistent)"
            fi
        fi
    else
        log_warn "  [FAIL] Ni rsyslog ni journald estan activos"
    fi

    # --- Permisos de archivos de log ---
    log_info "Verificando permisos de logs..."
    log_files_bad=0
    for logfile in /var/log/syslog /var/log/messages /var/log/auth.log /var/log/secure /var/log/kern.log; do
        if [[ -f "$logfile" ]]; then
            perms=$(stat -c %a "$logfile" 2>/dev/null || echo "777")
            # CIS requiere 640 o mas restrictivo
            if [[ "$perms" -le 640 ]]; then
                log_info "  [PASS] $logfile: permisos $perms"
            else
                log_warn "  [FAIL] $logfile: permisos $perms (max 640)"
                chmod 640 "$logfile" 2>/dev/null || true
                log_change "Permisos" "$logfile -> 640"
                ((log_files_bad++)) || true
            fi
        fi
    done

    # --- auditd ---
    if command -v auditd &>/dev/null || command -v auditctl &>/dev/null; then
        if systemctl is-active --quiet auditd 2>/dev/null; then
            log_info "  [PASS] auditd activo"
        else
            log_warn "  [FAIL] auditd instalado pero no activo"
            if ask "¿Habilitar auditd?"; then
                systemctl enable --now auditd 2>/dev/null || true
                log_change "Habilitado" "auditd"
            fi
        fi
    else
        log_warn "  [FAIL] auditd no instalado"
        if ask "¿Instalar auditd?"; then
            pkg_install audit || pkg_install auditd || true
            systemctl enable --now auditd 2>/dev/null || true
            log_change "Instalado" "auditd"
        fi
    fi

    # --- Reglas de auditoria CIS ---
    if [[ -d /etc/audit/rules.d ]]; then
        cis_rules_file="/etc/audit/rules.d/99-cis-benchmark.rules"
        if [[ ! -f "$cis_rules_file" ]]; then
            log_info "Creando reglas de auditoria CIS..."
            cat > "$cis_rules_file" << 'EOFCISRULES'
# ============================================================
# Reglas de auditoria CIS Benchmark
# Generado por securizar - cumplimiento-cis.sh
# ============================================================

# Cambios de hora del sistema
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# Cambios de usuarios y grupos
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Cambios de red
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/hostname -p wa -k system-locale

# Cambios de politica MAC (SELinux/AppArmor)
-w /etc/selinux/ -p wa -k MAC-policy
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy

# Login y logout
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

# Inicio y fin de sesion
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

# Cambios de permisos DAC
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -k perm_mod

# Intentos de acceso no autorizados
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -k access

# Montajes del sistema
-a always,exit -F arch=b64 -S mount -k mounts

# Eliminacion de archivos
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k delete

# Cambios en sudoers
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Carga de modulos del kernel
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
EOFCISRULES
            log_change "Creado" "$cis_rules_file"

            # Recargar reglas
            augenrules --load 2>/dev/null || auditctl -R "$cis_rules_file" 2>/dev/null || true
            log_change "Aplicado" "reglas de auditoria CIS"
        else
            log_info "  Reglas CIS ya existen: $cis_rules_file"
        fi
    fi

    # --- audit_backlog_limit ---
    if [[ -f /etc/audit/auditd.conf ]]; then
        current_backlog=$(grep -E "^backlog_limit" /etc/default/grub 2>/dev/null || echo "")
        grub_backlog=$(grep "audit_backlog_limit" /proc/cmdline 2>/dev/null || echo "")
        if echo "$grub_backlog" | grep -q "audit_backlog_limit=8192"; then
            log_info "  [PASS] audit_backlog_limit=8192 en cmdline"
        else
            log_warn "  [FAIL] audit_backlog_limit no configurado a 8192 en cmdline"
            log_warn "  Agrega audit_backlog_limit=8192 a GRUB_CMDLINE_LINUX en /etc/default/grub"
        fi

        # space_left_action
        space_action=$(grep -E "^space_left_action" /etc/audit/auditd.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' || echo "")
        if [[ "$space_action" == "email" || "$space_action" == "halt" || "$space_action" == "SYSLOG" ]]; then
            log_info "  [PASS] space_left_action = $space_action"
        else
            log_warn "  [FAIL] space_left_action = ${space_action:-no_configurado} (recomendado: email o halt)"
        fi
    fi

    log_info "Evaluacion CIS logging y auditoria completada"

else
    log_skip "CIS Nivel 1: Logging y auditoria"
fi

# ────────────────────────────────────────────────────────────────
# S5: CIS NIVEL 1 - ACCESO Y AUTENTICACION
# ────────────────────────────────────────────────────────────────
log_section "S5: CIS NIVEL 1 - ACCESO Y AUTENTICACION"

echo "Verifica controles de acceso y autenticacion CIS."
echo ""
echo "Comprobaciones:"
echo "  - Cron restringido (/etc/cron.allow)"
echo "  - SSH hardening (ciphers, MACs, kex, parametros)"
echo "  - Politica de contrasenas (minlen, complejidad)"
echo "  - Expiracion de contrasenas (login.defs)"
echo "  - Cuentas con UID 0, contrasenas vacias"
echo ""

if ask "¿Evaluar y aplicar controles de acceso CIS?"; then

    # --- Cron restringido ---
    if [[ -f /etc/cron.allow ]]; then
        log_info "  [PASS] /etc/cron.allow existe"
    else
        log_warn "  [FAIL] /etc/cron.allow no existe"
        if ask "¿Crear /etc/cron.allow (solo root)?"; then
            echo "root" > /etc/cron.allow
            chmod 600 /etc/cron.allow
            chown root:root /etc/cron.allow
            log_change "Creado" "/etc/cron.allow (solo root)"
        fi
    fi

    if [[ -f /etc/cron.deny ]]; then
        log_warn "  [FAIL] /etc/cron.deny existe (CIS recomienda eliminarlo si cron.allow esta presente)"
    else
        log_info "  [PASS] /etc/cron.deny no existe"
    fi

    # --- SSH hardening CIS ---
    if [[ -f /etc/ssh/sshd_config ]]; then
        log_info "Verificando parametros SSH CIS..."

        # Parametros SSH a verificar
        declare -A SSH_CIS_PARAMS=(
            ["LogLevel"]="INFO VERBOSE"
            ["MaxAuthTries"]="4"
            ["IgnoreRhosts"]="yes"
            ["HostbasedAuthentication"]="no"
            ["PermitEmptyPasswords"]="no"
            ["PermitUserEnvironment"]="no"
            ["LoginGraceTime"]="60"
            ["ClientAliveInterval"]="300"
            ["ClientAliveCountMax"]="3"
        )

        for param in "${!SSH_CIS_PARAMS[@]}"; do
            expected="${SSH_CIS_PARAMS[$param]}"
            current=$(grep -iE "^\s*${param}\s+" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1 || echo "")

            if [[ -z "$current" ]]; then
                log_warn "  [FAIL] SSH $param: no configurado (esperado: $expected)"
            elif [[ "$param" == "LogLevel" ]]; then
                if echo "$expected" | grep -qw "$current"; then
                    log_info "  [PASS] SSH $param = $current"
                else
                    log_warn "  [FAIL] SSH $param = $current (esperado: $expected)"
                fi
            elif [[ "$param" == "MaxAuthTries" || "$param" == "LoginGraceTime" ]]; then
                if [[ "$current" -le "${expected}" ]] 2>/dev/null; then
                    log_info "  [PASS] SSH $param = $current (<= $expected)"
                else
                    log_warn "  [FAIL] SSH $param = $current (max: $expected)"
                fi
            else
                if [[ "${current,,}" == "${expected,,}" ]]; then
                    log_info "  [PASS] SSH $param = $current"
                else
                    log_warn "  [FAIL] SSH $param = $current (esperado: $expected)"
                fi
            fi
        done

        # Verificar ciphers fuertes
        ciphers=$(grep -iE "^\s*Ciphers\s+" /etc/ssh/sshd_config 2>/dev/null | head -1 || echo "")
        if [[ -n "$ciphers" ]]; then
            if echo "$ciphers" | grep -qE "3des|arcfour|blowfish|cast128"; then
                log_warn "  [FAIL] SSH Ciphers: contiene algoritmos debiles"
            else
                log_info "  [PASS] SSH Ciphers: sin algoritmos debiles"
            fi
        else
            log_warn "  [FAIL] SSH Ciphers: no configurados (se usan defaults)"
        fi

        # Verificar MACs fuertes
        macs=$(grep -iE "^\s*MACs\s+" /etc/ssh/sshd_config 2>/dev/null | head -1 || echo "")
        if [[ -n "$macs" ]]; then
            if echo "$macs" | grep -qE "md5|96"; then
                log_warn "  [FAIL] SSH MACs: contiene algoritmos debiles"
            else
                log_info "  [PASS] SSH MACs: sin algoritmos debiles"
            fi
        else
            log_warn "  [FAIL] SSH MACs: no configurados (se usan defaults)"
        fi
    else
        log_warn "  sshd_config no encontrado"
    fi

    # --- Politica de contrasenas ---
    log_info "Verificando politica de contrasenas..."
    if [[ -f /etc/security/pwquality.conf ]]; then
        minlen=$(grep -E "^\s*minlen\s*=" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' || echo "0")
        minclass=$(grep -E "^\s*minclass\s*=" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' || echo "0")

        if [[ "${minlen:-0}" -ge 14 ]]; then
            log_info "  [PASS] pwquality minlen = $minlen (>= 14)"
        else
            log_warn "  [FAIL] pwquality minlen = ${minlen:-0} (minimo: 14)"
        fi

        if [[ "${minclass:-0}" -ge 4 ]]; then
            log_info "  [PASS] pwquality minclass = $minclass (>= 4)"
        else
            # Verificar creditos individuales
            dcredit=$(grep -E "^\s*dcredit\s*=" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' || echo "0")
            ucredit=$(grep -E "^\s*ucredit\s*=" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' || echo "0")
            lcredit=$(grep -E "^\s*lcredit\s*=" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' || echo "0")
            ocredit=$(grep -E "^\s*ocredit\s*=" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' || echo "0")
            if [[ "$dcredit" -le -1 && "$ucredit" -le -1 && "$lcredit" -le -1 && "$ocredit" -le -1 ]] 2>/dev/null; then
                log_info "  [PASS] pwquality: dcredit=$dcredit ucredit=$ucredit lcredit=$lcredit ocredit=$ocredit"
            else
                log_warn "  [FAIL] pwquality minclass = ${minclass:-0} y creditos insuficientes"
            fi
        fi
    else
        log_warn "  [FAIL] /etc/security/pwquality.conf no existe"
    fi

    # --- Expiracion de contrasenas (login.defs) ---
    if [[ -f /etc/login.defs ]]; then
        max_days=$(grep -E "^\s*PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}' || echo "99999")
        min_days=$(grep -E "^\s*PASS_MIN_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}' || echo "0")
        warn_age=$(grep -E "^\s*PASS_WARN_AGE" /etc/login.defs 2>/dev/null | awk '{print $2}' || echo "0")

        if [[ "${max_days:-99999}" -le 365 ]]; then
            log_info "  [PASS] PASS_MAX_DAYS = $max_days (<= 365)"
        else
            log_warn "  [FAIL] PASS_MAX_DAYS = ${max_days:-99999} (max: 365)"
        fi
        if [[ "${min_days:-0}" -ge 1 ]]; then
            log_info "  [PASS] PASS_MIN_DAYS = $min_days (>= 1)"
        else
            log_warn "  [FAIL] PASS_MIN_DAYS = ${min_days:-0} (minimo: 1)"
        fi
        if [[ "${warn_age:-0}" -ge 7 ]]; then
            log_info "  [PASS] PASS_WARN_AGE = $warn_age (>= 7)"
        else
            log_warn "  [FAIL] PASS_WARN_AGE = ${warn_age:-0} (minimo: 7)"
        fi
    fi

    # --- Cuentas con UID 0 ---
    uid0_accounts=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd 2>/dev/null || true)
    if [[ -z "$uid0_accounts" ]]; then
        log_info "  [PASS] Solo root tiene UID=0"
    else
        log_warn "  [FAIL] Cuentas con UID=0 ademas de root: $uid0_accounts"
    fi

    # --- Contrasenas vacias en /etc/shadow ---
    empty_pass=$(awk -F: '($2 == "" ) {print $1}' /etc/shadow 2>/dev/null || true)
    if [[ -z "$empty_pass" ]]; then
        log_info "  [PASS] No hay contrasenas vacias en /etc/shadow"
    else
        log_warn "  [FAIL] Cuentas con contrasena vacia: $empty_pass"
    fi

    # --- PATH de root seguro ---
    root_path=$(su -c 'echo $PATH' root 2>/dev/null || echo "$PATH")
    if echo "$root_path" | grep -qE "(^:|::|:$|\.)" ; then
        log_warn "  [FAIL] PATH de root contiene entradas inseguras (., ::, :trailing)"
    else
        log_info "  [PASS] PATH de root no contiene entradas inseguras"
    fi

    log_info "Evaluacion CIS acceso y autenticacion completada"

else
    log_skip "CIS Nivel 1: Acceso y autenticacion"
fi

# ────────────────────────────────────────────────────────────────
# S6: CIS NIVEL 2 - CONTROLES ADICIONALES
# ────────────────────────────────────────────────────────────────
log_section "S6: CIS NIVEL 2 - CONTROLES ADICIONALES"

echo "Verifica controles CIS Nivel 2 adicionales."
echo ""
echo "Comprobaciones:"
echo "  - Process accounting (psacct/acct)"
echo "  - Core dumps restringidos"
echo "  - ASLR (randomize_va_space=2)"
echo "  - prelink deshabilitado"
echo "  - SELinux o AppArmor enforcing"
echo "  - Contrasena de bootloader (GRUB)"
echo "  - Single user mode autenticado"
echo "  - Banners de advertencia"
echo ""

if ask "¿Evaluar controles CIS Nivel 2?"; then

    # --- Process accounting ---
    if systemctl is-active --quiet psacct 2>/dev/null || systemctl is-active --quiet acct 2>/dev/null; then
        log_info "  [PASS] Process accounting activo"
    else
        log_warn "  [FAIL] Process accounting no activo"
        if ask "¿Instalar y habilitar process accounting?"; then
            pkg_install psacct || pkg_install acct || true
            systemctl enable --now psacct 2>/dev/null || systemctl enable --now acct 2>/dev/null || true
            log_change "Habilitado" "process accounting (psacct/acct)"
        fi
    fi

    # --- Core dumps restringidos ---
    core_limits=$(grep -rE "^\s*\*\s+hard\s+core\s+0" /etc/security/limits.conf /etc/security/limits.d/ 2>/dev/null || true)
    core_sysctl=$(sysctl -n fs.suid_dumpable 2>/dev/null || echo "2")
    if [[ -n "$core_limits" && "$core_sysctl" == "0" ]]; then
        log_info "  [PASS] Core dumps restringidos (limits.conf + sysctl)"
    else
        log_warn "  [FAIL] Core dumps no completamente restringidos"
        if ask "¿Restringir core dumps?"; then
            if ! grep -q "hard core 0" /etc/security/limits.conf 2>/dev/null; then
                echo "* hard core 0" >> /etc/security/limits.conf
                log_change "Modificado" "/etc/security/limits.conf: * hard core 0"
            fi
            if [[ "$core_sysctl" != "0" ]]; then
                echo "fs.suid_dumpable = 0" > /etc/sysctl.d/99-securizar-cis-coredump.conf
                sysctl -p /etc/sysctl.d/99-securizar-cis-coredump.conf &>/dev/null || true
                log_change "Creado" "/etc/sysctl.d/99-securizar-cis-coredump.conf"
            fi
        fi
    fi

    # --- ASLR ---
    aslr=$(sysctl -n kernel.randomize_va_space 2>/dev/null || echo "0")
    if [[ "$aslr" == "2" ]]; then
        log_info "  [PASS] ASLR = 2 (full randomization)"
    else
        log_warn "  [FAIL] ASLR = $aslr (esperado: 2)"
        if ask "¿Habilitar ASLR completo?"; then
            sysctl -w kernel.randomize_va_space=2 &>/dev/null || true
            echo "kernel.randomize_va_space = 2" > /etc/sysctl.d/99-securizar-cis-aslr.conf
            sysctl -p /etc/sysctl.d/99-securizar-cis-aslr.conf &>/dev/null || true
            log_change "Aplicado" "ASLR = 2"
        fi
    fi

    # --- prelink deshabilitado ---
    if command -v prelink &>/dev/null; then
        log_warn "  [FAIL] prelink esta instalado (debilita ASLR)"
        if ask "¿Desinstalar prelink?"; then
            prelink -ua 2>/dev/null || true
            pkg_remove prelink || true
            log_change "Eliminado" "prelink"
        fi
    else
        log_info "  [PASS] prelink no instalado"
    fi

    # --- SELinux o AppArmor ---
    mac_enforcing=false
    if command -v getenforce &>/dev/null; then
        selinux_mode=$(getenforce 2>/dev/null || echo "Disabled")
        if [[ "$selinux_mode" == "Enforcing" ]]; then
            log_info "  [PASS] SELinux: Enforcing"
            mac_enforcing=true
        else
            log_warn "  [FAIL] SELinux: $selinux_mode (esperado: Enforcing)"
        fi
    fi
    if ! $mac_enforcing; then
        if command -v aa-status &>/dev/null || command -v apparmor_status &>/dev/null; then
            aa_profiles=$(aa-status 2>/dev/null | grep "profiles are in enforce mode" | awk '{print $1}' || echo "0")
            if [[ "${aa_profiles:-0}" -gt 0 ]]; then
                log_info "  [PASS] AppArmor: $aa_profiles perfiles enforcing"
                mac_enforcing=true
            else
                log_warn "  [FAIL] AppArmor: sin perfiles enforcing"
            fi
        fi
    fi
    if ! $mac_enforcing; then
        log_warn "  [FAIL] Ni SELinux ni AppArmor estan en modo enforcing"
    fi

    # --- SETroubleshoot y mcstrans (RHEL) ---
    if [[ "$DISTRO_FAMILY" == "rhel" ]]; then
        if pkg_is_installed setroubleshoot 2>/dev/null; then
            log_warn "  [FAIL] SETroubleshoot instalado (no recomendado en produccion)"
        else
            log_info "  [PASS] SETroubleshoot no instalado"
        fi
        if pkg_is_installed mcstrans 2>/dev/null; then
            log_warn "  [FAIL] mcstrans instalado (no recomendado en produccion)"
        else
            log_info "  [PASS] mcstrans no instalado"
        fi
    fi

    # --- Contrasena GRUB ---
    if [[ -f "$GRUB_USER_CFG" ]] && grep -q "GRUB2_PASSWORD" "$GRUB_USER_CFG" 2>/dev/null; then
        log_info "  [PASS] GRUB tiene contrasena configurada"
    elif [[ -f "$GRUB_CFG" ]] && grep -q "password_pbkdf2" "$GRUB_CFG" 2>/dev/null; then
        log_info "  [PASS] GRUB tiene contrasena configurada (en grub.cfg)"
    else
        log_warn "  [FAIL] GRUB no tiene contrasena configurada"
    fi

    # --- Single user mode autenticado ---
    if [[ -f /usr/lib/systemd/system/rescue.service ]]; then
        rescue_exec=$(grep "^ExecStart=" /usr/lib/systemd/system/rescue.service 2>/dev/null || echo "")
        if echo "$rescue_exec" | grep -q "sulogin"; then
            log_info "  [PASS] Single user mode requiere autenticacion (sulogin)"
        else
            log_warn "  [FAIL] Single user mode no requiere autenticacion"
        fi
    fi

    # --- Banners de advertencia ---
    for banner_file in /etc/motd /etc/issue /etc/issue.net; do
        if [[ -f "$banner_file" ]]; then
            content=$(cat "$banner_file" 2>/dev/null || echo "")
            if [[ -z "$content" ]]; then
                log_warn "  [FAIL] $banner_file esta vacio"
            elif echo "$content" | grep -qiE "ubuntu|debian|opensuse|centos|fedora|red hat|kernel|\\\\r|\\\\v|\\\\m|\\\\s"; then
                log_warn "  [FAIL] $banner_file contiene informacion del sistema operativo"
            else
                log_info "  [PASS] $banner_file configurado sin info del SO"
            fi
        else
            log_warn "  [FAIL] $banner_file no existe"
        fi
    done

    # ── S6b: CIS Level 2 - Módulos kernel peligrosos ──
    log_info "Verificando módulos kernel CIS Level 2..."

    MODPROBE_CIS="/etc/modprobe.d/cis-level2-modules.conf"
    if [[ ! -f "$MODPROBE_CIS" ]]; then
        cat > "$MODPROBE_CIS" << 'EOFMOD'
# CIS Level 2 - Módulos kernel innecesarios deshabilitados
# Generado por cumplimiento-cis.sh

# Filesystems innecesarios (CIS 1.1.1.x)
install cramfs /bin/true
install freevxfs /bin/true
install hfs /bin/true
install hfsplus /bin/true
install jffs2 /bin/true
install udf /bin/true
install vfat /bin/true

# Protocolos de red obsoletos (CIS 3.4.x)
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true

# Otros módulos innecesarios
install squashfs /bin/true
install fat /bin/true
EOFMOD
        log_change "Creado" "$MODPROBE_CIS"
        log_info "Módulos kernel CIS Level 2 deshabilitados"
    else
        log_info "  [PASS] $MODPROBE_CIS ya existe"
    fi

    log_info "Evaluacion CIS Nivel 2 completada"

else
    log_skip "CIS Nivel 2: Controles adicionales"
fi

# ────────────────────────────────────────────────────────────────
# S7: MAPEO A NIST 800-53
# ────────────────────────────────────────────────────────────────
log_section "S7: MAPEO A NIST 800-53"

echo "Genera un mapeo de los 41 modulos de securizar a las"
echo "familias de controles NIST 800-53."
echo ""
echo "Familias NIST:"
echo "  AC (Access Control), AU (Audit), CM (Config Management)"
echo "  IA (Identification), SC (System/Comms), SI (System Integrity)"
echo "  MP (Media Protection), PE (Physical), SA (System Acquisition)"
echo ""

if check_file_exists /var/lib/securizar/nist-mapping.json; then
    log_already "Mapeo NIST 800-53 (nist-mapping.json existe)"
elif ask "¿Generar mapeo NIST 800-53?"; then

    nist_file="${CIS_BASE}/nist-mapping.json"

    cat > "$nist_file" << 'EOFNIST'
{
  "_metadata": {
    "generated_by": "securizar - cumplimiento-cis.sh",
    "standard": "NIST SP 800-53 Rev. 5",
    "description": "Mapeo de modulos securizar a familias de controles NIST 800-53"
  },
  "modules": {
    "01-hardening-opensuse":       {"families": ["CM-6","CM-7","SC-7"],  "name": "Hardening Base openSUSE"},
    "02-hardening-seguro":         {"families": ["CM-6","AC-3","AC-6"],  "name": "Hardening Seguro"},
    "03-hardening-cuentas":        {"families": ["AC-2","AC-3","IA-2","IA-5"], "name": "Hardening Cuentas"},
    "04-hardening-kernel-boot":    {"families": ["CM-6","SI-16","SC-39"], "name": "Hardening Kernel Boot"},
    "05-hardening-servicios-systemd": {"families": ["CM-7","SC-7","AC-4"], "name": "Hardening Servicios Systemd"},
    "06-hardening-paranoico":      {"families": ["CM-6","CM-7","SC-7","AC-3"], "name": "Hardening Paranoico"},
    "07-hardening-extremo":        {"families": ["CM-6","CM-7","SC-7","SI-7"], "name": "Hardening Extremo"},
    "08-hardening-final":          {"families": ["CM-6","SI-7","AU-2"],  "name": "Hardening Final"},
    "09-hardening-externo":        {"families": ["SC-7","SC-8","SI-4"],  "name": "Hardening Externo"},
    "10-automatizar-seguridad":    {"families": ["AU-6","SI-4","CM-3"],  "name": "Automatizar Seguridad"},
    "11-proteger-red-avanzado":    {"families": ["SC-7","SC-8","AC-4","SI-4"], "name": "Proteger Red Avanzado"},
    "12-aplicar-banner-total":     {"families": ["AC-8","AT-1"],         "name": "Aplicar Banner Total"},
    "13-reportar-seguridad":       {"families": ["AU-6","AU-7","CA-7"],  "name": "Reportar Seguridad"},
    "14-proteger-privacidad":      {"families": ["SC-8","SC-12","SC-28"], "name": "Proteger Privacidad"},
    "15-proteger-contra-isp":      {"families": ["SC-8","SC-12","SC-23"], "name": "Proteger Contra ISP"},
    "16-sandbox-aplicaciones":     {"families": ["CM-7","SC-39","AC-4"], "name": "Sandbox Aplicaciones"},
    "17-monitorizar-continuo":     {"families": ["SI-4","AU-6","CA-7","IR-5"], "name": "Monitorizar Continuo"},
    "18-respuesta-incidentes":     {"families": ["IR-1","IR-4","IR-5","IR-6"], "name": "Respuesta Incidentes"},
    "19-cazar-amenazas":           {"families": ["SI-4","RA-5","CA-7"],  "name": "Cazar Amenazas"},
    "20-contramedidas-avanzadas":  {"families": ["SC-7","SI-4","SC-35"], "name": "Contramedidas Avanzadas"},
    "21-contramedidas-mesh":       {"families": ["SC-7","SI-4","SC-35","SC-26"], "name": "Contramedidas Mesh"},
    "22-inteligencia-amenazas":    {"families": ["SI-5","RA-3","PM-16"], "name": "Inteligencia Amenazas"},
    "23-auditoria-externa":        {"families": ["CA-2","CA-7","RA-5"],  "name": "Auditoria Externa"},
    "24-mitigar-acceso-inicial":   {"families": ["AC-4","SC-7","SI-3"],  "name": "Mitigar Acceso Inicial"},
    "25-mitigar-ejecucion":        {"families": ["CM-7","SI-3","SI-7"],  "name": "Mitigar Ejecucion"},
    "26-mitigar-persistencia":     {"families": ["CM-3","SI-7","AU-2"],  "name": "Mitigar Persistencia"},
    "27-mitigar-escalada":         {"families": ["AC-6","CM-6","SI-7"],  "name": "Mitigar Escalada"},
    "28-mitigar-evasion":          {"families": ["SI-4","SI-7","AU-2"],  "name": "Mitigar Evasion"},
    "29-mitigar-credenciales":     {"families": ["IA-2","IA-5","AC-7"],  "name": "Mitigar Credenciales"},
    "30-mitigar-descubrimiento":   {"families": ["AC-3","SC-7","SI-4"],  "name": "Mitigar Descubrimiento"},
    "31-mitigar-movimiento-lateral": {"families": ["AC-4","SC-7","AC-3"], "name": "Mitigar Movimiento Lateral"},
    "32-mitigar-recoleccion":      {"families": ["AC-3","SC-28","MP-2"], "name": "Mitigar Recoleccion"},
    "33-mitigar-comando-control":  {"families": ["SC-7","SC-8","SI-4"],  "name": "Mitigar Comando Control"},
    "34-mitigar-exfiltracion":     {"families": ["AC-4","SC-7","SC-8","SI-4"], "name": "Mitigar Exfiltracion"},
    "35-mitigar-impacto":          {"families": ["CP-9","CP-10","IR-4","SC-28"], "name": "Mitigar Impacto"},
    "36-validar-controles":        {"families": ["CA-2","CA-8","RA-5"],  "name": "Validar Controles"},
    "37-ciberinteligencia":        {"families": ["SI-5","RA-3","PM-16","RA-5"], "name": "Ciberinteligencia"},
    "38-automatizar-respuesta":    {"families": ["IR-4","IR-5","SI-4"],  "name": "Automatizar Respuesta"},
    "39-hardening-extra":          {"families": ["CM-6","CM-7","SC-7"],  "name": "Hardening Extra"},
    "40-seguridad-avanzada":       {"families": ["SC-7","SI-4","AU-6"],  "name": "Seguridad Avanzada"},
    "41-cumplimiento-cis":         {"families": ["CA-2","CA-7","CM-6","RA-5","SA-11"], "name": "Cumplimiento CIS"}
  },
  "nist_families": {
    "AC":  "Access Control",
    "AT":  "Awareness and Training",
    "AU":  "Audit and Accountability",
    "CA":  "Assessment, Authorization, and Monitoring",
    "CM":  "Configuration Management",
    "CP":  "Contingency Planning",
    "IA":  "Identification and Authentication",
    "IR":  "Incident Response",
    "MP":  "Media Protection",
    "PE":  "Physical and Environmental Protection",
    "PM":  "Program Management",
    "RA":  "Risk Assessment",
    "SA":  "System and Services Acquisition",
    "SC":  "System and Communications Protection",
    "SI":  "System and Information Integrity"
  }
}
EOFNIST

    chmod 644 "$nist_file"
    log_change "Creado" "$nist_file"

    # Calcular resumen
    total_modules=41
    # Contar familias unicas usadas en el mapeo
    families_used=$(grep '"families"' "$nist_file" | grep -oE '"[A-Z]{2}-[0-9]+"' | sed 's/"//g' | cut -d- -f1 | sort -u | wc -l)
    controls_mapped=$(grep '"families"' "$nist_file" | grep -oE '"[A-Z]{2}-[0-9]+"' | sed 's/"//g' | sort -u | wc -l)

    log_info "Mapeo NIST 800-53 generado:"
    echo ""
    echo -e "  ${BOLD}$total_modules modulos${NC} mapeados a ${BOLD}$controls_mapped controles${NC} en ${BOLD}$families_used familias NIST${NC}"
    echo ""

    # Mostrar cobertura por familia
    echo -e "  ${CYAN}Cobertura por familia NIST:${NC}"
    for fam in AC AU CA CM CP IA IR MP PM RA SA SC SI AT PE; do
        fam_count=$(grep '"families"' "$nist_file" | grep -c "\"${fam}-" || true)
        if [[ "$fam_count" -gt 0 ]]; then
            bar=""
            for ((i=0; i<fam_count && i<20; i++)); do bar="${bar}#"; done
            printf "    %-4s %-20s %s\n" "$fam" "$bar" "($fam_count modulos)"
        fi
    done

    # Identificar gaps
    echo ""
    echo -e "  ${YELLOW}Familias con baja cobertura (< 3 modulos):${NC}"
    for fam in AT PE MP CP PM; do
        fam_count=$(grep '"families"' "$nist_file" | grep -c "\"${fam}-" || true)
        if [[ "$fam_count" -lt 3 ]]; then
            echo "    $fam: $fam_count modulos - considerar ampliacion"
        fi
    done

    # ── S7b: DISA STIG cross-reference ──
    log_info "Generando mapeo DISA STIG..."

    cat > /var/lib/securizar/stig-mapping.json << 'EOFSTIG'
{
  "_metadata": {
    "generated_by": "securizar - cumplimiento-cis.sh",
    "standard": "DISA STIG",
    "description": "Mapeo de controles CIS a DISA STIG IDs"
  },
  "mappings": {
    "CIS-1.1": {"stig": "V-230223", "title": "Filesystem separate partitions", "severity": "medium"},
    "CIS-1.1.1": {"stig": "V-230300", "title": "Disable cramfs/freevxfs/hfs/udf", "severity": "low"},
    "CIS-1.3.1": {"stig": "V-230234", "title": "AIDE installed", "severity": "medium"},
    "CIS-1.4.1": {"stig": "V-230236", "title": "Bootloader password", "severity": "high"},
    "CIS-1.5.1": {"stig": "V-230269", "title": "Core dumps restricted", "severity": "medium"},
    "CIS-1.5.3": {"stig": "V-230268", "title": "ASLR enabled", "severity": "medium"},
    "CIS-2.1": {"stig": "V-230310", "title": "Unnecessary services", "severity": "medium"},
    "CIS-3.1": {"stig": "V-230505", "title": "IP forwarding disabled", "severity": "medium"},
    "CIS-3.2": {"stig": "V-230533", "title": "ICMP redirects", "severity": "medium"},
    "CIS-4.1": {"stig": "V-230386", "title": "auditd enabled", "severity": "medium"},
    "CIS-4.2": {"stig": "V-230475", "title": "rsyslog configured", "severity": "medium"},
    "CIS-5.1": {"stig": "V-230332", "title": "SSH Protocol 2", "severity": "high"},
    "CIS-5.2": {"stig": "V-230380", "title": "Password complexity", "severity": "medium"},
    "CIS-5.3": {"stig": "V-230340", "title": "Account lockout", "severity": "medium"},
    "CIS-6.1": {"stig": "V-230258", "title": "File permissions", "severity": "medium"}
  }
}
EOFSTIG
    log_change "Creado" "/var/lib/securizar/stig-mapping.json"

    cat > /usr/local/bin/reporte-dual-cis-stig.sh << 'EOFDUAL'
#!/bin/bash
# Reporte dual CIS/STIG - muestra mapeo cruzado
set -euo pipefail
BOLD='\033[1m'; DIM='\033[2m'; CYAN='\033[0;36m'; NC='\033[0m'

echo -e "${BOLD}=== REPORTE DUAL CIS / DISA STIG ===${NC}"
echo ""

NIST_FILE="/var/lib/securizar/nist-mapping.json"
STIG_FILE="/var/lib/securizar/stig-mapping.json"

if [[ -f "$STIG_FILE" ]] && command -v jq &>/dev/null; then
    echo -e "${CYAN}Mapeo CIS → STIG:${NC}"
    jq -r '.mappings | to_entries[] | "\(.key)\t\(.value.stig)\t\(.value.severity)\t\(.value.title)"' "$STIG_FILE" 2>/dev/null | \
        while IFS=$'\t' read -r cis stig sev title; do
            printf "  %-12s → %-10s [%-6s] %s\n" "$cis" "$stig" "$sev" "$title"
        done
else
    echo "  Requiere jq y stig-mapping.json"
fi

if [[ -f "$NIST_FILE" ]] && command -v jq &>/dev/null; then
    echo ""
    echo -e "${CYAN}Familias NIST cubiertas:${NC}"
    jq -r '.modules | to_entries[] | .value.families[]' "$NIST_FILE" 2>/dev/null | sort | uniq -c | sort -rn | while read -r count family; do
        printf "  %-6s %s\n" "$family" "($count módulos)"
    done
fi
EOFDUAL
    chmod 755 /usr/local/bin/reporte-dual-cis-stig.sh
    log_change "Creado" "/usr/local/bin/reporte-dual-cis-stig.sh"
    log_info "Mapeo DISA STIG y reporte dual generados"

else
    log_skip "Mapeo NIST 800-53"
fi

# ────────────────────────────────────────────────────────────────
# S8: MOTOR DE PUNTUACION CIS
# ────────────────────────────────────────────────────────────────
log_section "S8: MOTOR DE PUNTUACION CIS"

echo "Crea /usr/local/bin/cis-scoring.sh que ejecuta todas"
echo "las comprobaciones CIS en modo solo auditoria (sin cambios),"
echo "calcula puntuacion, compara con ejecuciones anteriores"
echo "y muestra tendencia."
echo ""

if check_executable /usr/local/bin/cis-scoring.sh; then
    log_already "Motor de puntuacion CIS (cis-scoring.sh existe)"
elif ask "¿Instalar motor de puntuacion CIS?"; then

    cat > /usr/local/bin/cis-scoring.sh << 'EOFSCORING'
#!/bin/bash
# ============================================================
# MOTOR DE PUNTUACION CIS BENCHMARK
# Ejecuta todas las comprobaciones CIS en modo auditoria
# Sin modificar nada en el sistema
# ============================================================
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root: sudo cis-scoring.sh"
    exit 1
fi

SCORES_DIR="/var/lib/securizar/cis-scores"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
RESULT_FILE="$SCORES_DIR/cis-score-${TIMESTAMP}.txt"
mkdir -p "$SCORES_DIR"

# Contadores globales
declare -A CAT_PASS CAT_FAIL CAT_NA
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_NA=0

check() {
    local category="$1"
    local id="$2"
    local desc="$3"
    local status="$4"  # PASS, FAIL, N/A

    # Inicializar categoria si no existe
    [[ -z "${CAT_PASS[$category]+x}" ]] && CAT_PASS[$category]=0
    [[ -z "${CAT_FAIL[$category]+x}" ]] && CAT_FAIL[$category]=0
    [[ -z "${CAT_NA[$category]+x}" ]]   && CAT_NA[$category]=0

    case "$status" in
        PASS)
            CAT_PASS[$category]=$(( ${CAT_PASS[$category]} + 1 ))
            TOTAL_PASS=$((TOTAL_PASS+1))
            echo "[PASS] $id: $desc" >> "$RESULT_FILE"
            ;;
        FAIL)
            CAT_FAIL[$category]=$(( ${CAT_FAIL[$category]} + 1 ))
            TOTAL_FAIL=$((TOTAL_FAIL+1))
            echo "[FAIL] $id: $desc" >> "$RESULT_FILE"
            ;;
        *)
            CAT_NA[$category]=$(( ${CAT_NA[$category]} + 1 ))
            TOTAL_NA=$((TOTAL_NA+1))
            echo "[N/A]  $id: $desc" >> "$RESULT_FILE"
            ;;
    esac
}

echo "============================================================" | tee "$RESULT_FILE"
echo " CIS BENCHMARK SCORING - $(hostname)"                        | tee -a "$RESULT_FILE"
echo " Fecha: $(date -Iseconds)"                                   | tee -a "$RESULT_FILE"
echo "============================================================" | tee -a "$RESULT_FILE"
echo "" | tee -a "$RESULT_FILE"

# ── CATEGORIA: FILESYSTEM ──────────────────────────────────────
echo ">>> Evaluando: Sistema de archivos..." | tee -a "$RESULT_FILE"

# FS-01: /tmp particion separada
if findmnt -n /tmp &>/dev/null; then check "Filesystem" "FS-01" "/tmp particion separada" "PASS"
else check "Filesystem" "FS-01" "/tmp particion separada" "FAIL"; fi

# FS-02: /tmp con nodev,nosuid,noexec
if findmnt -n /tmp &>/dev/null; then
    opts=$(findmnt -n -o OPTIONS /tmp)
    if echo "$opts" | grep -q "nodev" && echo "$opts" | grep -q "nosuid" && echo "$opts" | grep -q "noexec"; then
        check "Filesystem" "FS-02" "/tmp nodev,nosuid,noexec" "PASS"
    else check "Filesystem" "FS-02" "/tmp nodev,nosuid,noexec" "FAIL"; fi
else check "Filesystem" "FS-02" "/tmp nodev,nosuid,noexec" "N/A"; fi

# FS-03: /var particion separada
if findmnt -n /var &>/dev/null; then check "Filesystem" "FS-03" "/var particion separada" "PASS"
else check "Filesystem" "FS-03" "/var particion separada" "FAIL"; fi

# FS-04: /var/tmp con nodev,nosuid,noexec
if findmnt -n /var/tmp &>/dev/null; then
    opts=$(findmnt -n -o OPTIONS /var/tmp)
    if echo "$opts" | grep -q "nodev" && echo "$opts" | grep -q "nosuid" && echo "$opts" | grep -q "noexec"; then
        check "Filesystem" "FS-04" "/var/tmp nodev,nosuid,noexec" "PASS"
    else check "Filesystem" "FS-04" "/var/tmp nodev,nosuid,noexec" "FAIL"; fi
else check "Filesystem" "FS-04" "/var/tmp nodev,nosuid,noexec" "N/A"; fi

# FS-05: /var/log particion separada
if findmnt -n /var/log &>/dev/null; then check "Filesystem" "FS-05" "/var/log particion separada" "PASS"
else check "Filesystem" "FS-05" "/var/log particion separada" "FAIL"; fi

# FS-06: /home con nodev
if findmnt -n /home &>/dev/null; then
    if findmnt -n -o OPTIONS /home | grep -q "nodev"; then check "Filesystem" "FS-06" "/home nodev" "PASS"
    else check "Filesystem" "FS-06" "/home nodev" "FAIL"; fi
else check "Filesystem" "FS-06" "/home nodev" "N/A"; fi

# FS-07: Sticky bit en world-writable dirs
ww_no_sticky=$(find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | wc -l || echo "0")
if [[ "$ww_no_sticky" -eq 0 ]]; then check "Filesystem" "FS-07" "Sticky bit en world-writable dirs" "PASS"
else check "Filesystem" "FS-07" "Sticky bit en world-writable dirs ($ww_no_sticky sin sticky)" "FAIL"; fi

# FS-08: autofs deshabilitado
if ! systemctl is-enabled autofs &>/dev/null 2>&1; then check "Filesystem" "FS-08" "autofs deshabilitado" "PASS"
else check "Filesystem" "FS-08" "autofs deshabilitado" "FAIL"; fi

# FS-09: USB storage deshabilitado
if [[ -f /etc/modprobe.d/cis-usb-storage.conf ]] || ! lsmod 2>/dev/null | grep -q "^usb_storage"; then
    check "Filesystem" "FS-09" "usb_storage controlado" "PASS"
else check "Filesystem" "FS-09" "usb_storage controlado" "FAIL"; fi

# FS-10: hidepid en /proc
if findmnt -n -o OPTIONS /proc 2>/dev/null | grep -q "hidepid=2"; then
    check "Filesystem" "FS-10" "hidepid=2 en /proc" "PASS"
else check "Filesystem" "FS-10" "hidepid=2 en /proc" "FAIL"; fi

# ── CATEGORIA: SERVICIOS ───────────────────────────────────────
echo ">>> Evaluando: Servicios..." | tee -a "$RESULT_FILE"

svc_idx=1
for svc in xinetd telnet.socket rsh.socket ntalk tftp.socket nfs-server rpcbind snmpd smb squid ypserv ypbind; do
    sid=$(printf "SVC-%02d" $svc_idx)
    if systemctl is-enabled "$svc" &>/dev/null 2>&1; then
        check "Servicios" "$sid" "$svc deshabilitado" "FAIL"
    else
        check "Servicios" "$sid" "$svc deshabilitado" "PASS"
    fi
    svc_idx=$((svc_idx+1))
done

# ── CATEGORIA: RED ─────────────────────────────────────────────
echo ">>> Evaluando: Red..." | tee -a "$RESULT_FILE"

declare -A NET_CHECKS=(
    ["NET-01:net.ipv4.ip_forward"]="0"
    ["NET-02:net.ipv4.conf.all.send_redirects"]="0"
    ["NET-03:net.ipv4.conf.all.accept_source_route"]="0"
    ["NET-04:net.ipv4.conf.all.accept_redirects"]="0"
    ["NET-05:net.ipv4.conf.all.secure_redirects"]="1"
    ["NET-06:net.ipv4.conf.all.log_martians"]="1"
    ["NET-07:net.ipv4.icmp_echo_ignore_broadcasts"]="1"
    ["NET-08:net.ipv4.tcp_syncookies"]="1"
    ["NET-09:net.ipv6.conf.all.accept_ra"]="0"
    ["NET-10:net.ipv6.conf.all.accept_redirects"]="0"
)

for entry in "${!NET_CHECKS[@]}"; do
    nid="${entry%%:*}"
    param="${entry#*:}"
    expected="${NET_CHECKS[$entry]}"
    current=$(sysctl -n "$param" 2>/dev/null || echo "N/A")
    if [[ "$current" == "$expected" ]]; then check "Red" "$nid" "$param=$current" "PASS"
    elif [[ "$current" == "N/A" ]]; then check "Red" "$nid" "$param" "N/A"
    else check "Red" "$nid" "$param=$current (esperado $expected)" "FAIL"; fi
done

# ── CATEGORIA: LOGGING ─────────────────────────────────────────
echo ">>> Evaluando: Logging..." | tee -a "$RESULT_FILE"

# LOG-01: rsyslog o journald activo
if systemctl is-active --quiet rsyslog 2>/dev/null || systemctl is-active --quiet systemd-journald 2>/dev/null; then
    check "Logging" "LOG-01" "Logging activo (rsyslog/journald)" "PASS"
else check "Logging" "LOG-01" "Logging activo" "FAIL"; fi

# LOG-02: auditd activo
if systemctl is-active --quiet auditd 2>/dev/null; then check "Logging" "LOG-02" "auditd activo" "PASS"
else check "Logging" "LOG-02" "auditd activo" "FAIL"; fi

# LOG-03: Reglas de auditoria CIS
if [[ -f /etc/audit/rules.d/99-cis-benchmark.rules ]]; then check "Logging" "LOG-03" "Reglas CIS auditd presentes" "PASS"
else check "Logging" "LOG-03" "Reglas CIS auditd presentes" "FAIL"; fi

# LOG-04: Log permissions
log_bad=0
for lf in /var/log/syslog /var/log/messages /var/log/auth.log /var/log/secure; do
    if [[ -f "$lf" ]]; then
        p=$(stat -c %a "$lf" 2>/dev/null || echo "777")
        [[ "$p" -gt 640 ]] && log_bad=$((log_bad+1))
    fi
done
if [[ $log_bad -eq 0 ]]; then check "Logging" "LOG-04" "Permisos de logs <= 640" "PASS"
else check "Logging" "LOG-04" "Permisos de logs <= 640 ($log_bad archivos inseguros)" "FAIL"; fi

# ── CATEGORIA: ACCESO ──────────────────────────────────────────
echo ">>> Evaluando: Acceso y autenticacion..." | tee -a "$RESULT_FILE"

# ACC-01: cron.allow existe
if [[ -f /etc/cron.allow ]]; then check "Acceso" "ACC-01" "/etc/cron.allow existe" "PASS"
else check "Acceso" "ACC-01" "/etc/cron.allow existe" "FAIL"; fi

# ACC-02: SSH MaxAuthTries <= 4
max_auth=$(grep -iE "^\s*MaxAuthTries" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1 || echo "6")
if [[ "${max_auth:-6}" -le 4 ]]; then check "Acceso" "ACC-02" "SSH MaxAuthTries <= 4" "PASS"
else check "Acceso" "ACC-02" "SSH MaxAuthTries <= 4 (actual: ${max_auth:-6})" "FAIL"; fi

# ACC-03: SSH PermitEmptyPasswords no
pep=$(grep -iE "^\s*PermitEmptyPasswords" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1 || echo "no")
if [[ "${pep,,}" == "no" ]]; then check "Acceso" "ACC-03" "SSH PermitEmptyPasswords no" "PASS"
else check "Acceso" "ACC-03" "SSH PermitEmptyPasswords no" "FAIL"; fi

# ACC-04: PASS_MAX_DAYS <= 365
pmd=$(grep -E "^\s*PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}' || echo "99999")
if [[ "${pmd:-99999}" -le 365 ]]; then check "Acceso" "ACC-04" "PASS_MAX_DAYS <= 365" "PASS"
else check "Acceso" "ACC-04" "PASS_MAX_DAYS <= 365 (actual: ${pmd:-99999})" "FAIL"; fi

# ACC-05: PASS_MIN_DAYS >= 1
pmind=$(grep -E "^\s*PASS_MIN_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}' || echo "0")
if [[ "${pmind:-0}" -ge 1 ]]; then check "Acceso" "ACC-05" "PASS_MIN_DAYS >= 1" "PASS"
else check "Acceso" "ACC-05" "PASS_MIN_DAYS >= 1 (actual: ${pmind:-0})" "FAIL"; fi

# ACC-06: Solo root con UID=0
uid0=$(awk -F: '$3 == 0 && $1 != "root"' /etc/passwd 2>/dev/null | wc -l || echo "0")
if [[ "$uid0" -eq 0 ]]; then check "Acceso" "ACC-06" "Solo root con UID=0" "PASS"
else check "Acceso" "ACC-06" "Solo root con UID=0" "FAIL"; fi

# ACC-07: Sin contrasenas vacias
empty=$(awk -F: '($2 == "")' /etc/shadow 2>/dev/null | wc -l || echo "0")
if [[ "$empty" -eq 0 ]]; then check "Acceso" "ACC-07" "Sin contrasenas vacias" "PASS"
else check "Acceso" "ACC-07" "Sin contrasenas vacias ($empty encontradas)" "FAIL"; fi

# ── CATEGORIA: CONTROLES ADICIONALES ──────────────────────────
echo ">>> Evaluando: Controles adicionales..." | tee -a "$RESULT_FILE"

# EXT-01: ASLR=2
aslr=$(sysctl -n kernel.randomize_va_space 2>/dev/null || echo "0")
if [[ "$aslr" == "2" ]]; then check "Adicional" "EXT-01" "ASLR=2" "PASS"
else check "Adicional" "EXT-01" "ASLR=2 (actual: $aslr)" "FAIL"; fi

# EXT-02: Core dumps restringidos
core=$(sysctl -n fs.suid_dumpable 2>/dev/null || echo "2")
if [[ "$core" == "0" ]]; then check "Adicional" "EXT-02" "Core dumps restringidos" "PASS"
else check "Adicional" "EXT-02" "Core dumps restringidos" "FAIL"; fi

# EXT-03: prelink no instalado
if ! command -v prelink &>/dev/null; then check "Adicional" "EXT-03" "prelink no instalado" "PASS"
else check "Adicional" "EXT-03" "prelink no instalado" "FAIL"; fi

# EXT-04: SELinux/AppArmor enforcing
mac_ok=false
if command -v getenforce &>/dev/null && [[ "$(getenforce 2>/dev/null)" == "Enforcing" ]]; then mac_ok=true; fi
if command -v aa-status &>/dev/null; then
    aa_enf=$(aa-status 2>/dev/null | grep "profiles are in enforce" | awk '{print $1}' || echo "0")
    [[ "${aa_enf:-0}" -gt 0 ]] && mac_ok=true
fi
if $mac_ok; then check "Adicional" "EXT-04" "MAC enforcing (SELinux/AppArmor)" "PASS"
else check "Adicional" "EXT-04" "MAC enforcing (SELinux/AppArmor)" "FAIL"; fi

# EXT-05: GRUB password
grub_pass=false
for gcf in /boot/grub2/user.cfg /boot/grub/user.cfg; do
    [[ -f "$gcf" ]] && grep -q "GRUB2_PASSWORD" "$gcf" 2>/dev/null && grub_pass=true
done
if $grub_pass; then check "Adicional" "EXT-05" "GRUB password configurado" "PASS"
else check "Adicional" "EXT-05" "GRUB password configurado" "FAIL"; fi

# ── RESUMEN ────────────────────────────────────────────────────
echo "" | tee -a "$RESULT_FILE"
echo "============================================================" | tee -a "$RESULT_FILE"
echo " RESUMEN DE PUNTUACION CIS" | tee -a "$RESULT_FILE"
echo "============================================================" | tee -a "$RESULT_FILE"
echo "" | tee -a "$RESULT_FILE"

# Tabla por categoria
printf "  %-18s %6s %6s %6s %8s\n" "CATEGORIA" "PASS" "FAIL" "N/A" "SCORE" | tee -a "$RESULT_FILE"
printf "  %-18s %6s %6s %6s %8s\n" "──────────────────" "──────" "──────" "──────" "────────" | tee -a "$RESULT_FILE"

for cat in Filesystem Servicios Red Logging Acceso Adicional; do
    p=${CAT_PASS[$cat]:-0}
    f=${CAT_FAIL[$cat]:-0}
    n=${CAT_NA[$cat]:-0}
    applicable=$((p + f))
    if [[ $applicable -gt 0 ]]; then
        pct=$((p * 100 / applicable))
    else
        pct=0
    fi
    printf "  %-18s %6d %6d %6d %7d%%\n" "$cat" "$p" "$f" "$n" "$pct" | tee -a "$RESULT_FILE"
done

echo "" | tee -a "$RESULT_FILE"
total_applicable=$((TOTAL_PASS + TOTAL_FAIL))
if [[ $total_applicable -gt 0 ]]; then
    total_pct=$((TOTAL_PASS * 100 / total_applicable))
else
    total_pct=0
fi

printf "  %-18s %6d %6d %6d %7d%%\n" "TOTAL" "$TOTAL_PASS" "$TOTAL_FAIL" "$TOTAL_NA" "$total_pct" | tee -a "$RESULT_FILE"
echo "" | tee -a "$RESULT_FILE"

# Guardar score numerico para tracking
echo "$total_pct" > "$SCORES_DIR/cis-score-latest.txt"
echo "${TIMESTAMP}:${total_pct}:${TOTAL_PASS}:${TOTAL_FAIL}:${TOTAL_NA}" >> "$SCORES_DIR/cis-score-history.csv"

# Comparar con ejecucion anterior
if [[ -f "$SCORES_DIR/cis-score-history.csv" ]]; then
    lines=$(wc -l < "$SCORES_DIR/cis-score-history.csv")
    if [[ $lines -ge 2 ]]; then
        prev_score=$(tail -2 "$SCORES_DIR/cis-score-history.csv" | head -1 | cut -d: -f2)
        delta=$((total_pct - prev_score))
        if [[ $delta -gt 0 ]]; then
            echo "  Delta vs anterior: +${delta}% (mejora)" | tee -a "$RESULT_FILE"
        elif [[ $delta -lt 0 ]]; then
            echo "  Delta vs anterior: ${delta}% (regresion)" | tee -a "$RESULT_FILE"
        else
            echo "  Delta vs anterior: sin cambios" | tee -a "$RESULT_FILE"
        fi
    fi

    # Tendencia: ultimas 5 ejecuciones
    echo "" | tee -a "$RESULT_FILE"
    echo "  Tendencia (ultimas 5 ejecuciones):" | tee -a "$RESULT_FILE"
    tail -5 "$SCORES_DIR/cis-score-history.csv" | while IFS=: read -r ts sc ps fl na; do
        bar=""
        for ((i=0; i<sc/5 && i<20; i++)); do bar="${bar}#"; done
        printf "    %-17s %-20s %3d%%\n" "$ts" "$bar" "$sc"
    done | tee -a "$RESULT_FILE"
fi

echo "" | tee -a "$RESULT_FILE"
echo "Resultados: $RESULT_FILE" | tee -a "$RESULT_FILE"
echo "Historial:  $SCORES_DIR/cis-score-history.csv" | tee -a "$RESULT_FILE"
EOFSCORING

    chmod 700 /usr/local/bin/cis-scoring.sh
    log_change "Creado" "/usr/local/bin/cis-scoring.sh"
    log_info "Motor de puntuacion CIS instalado"

else
    log_skip "Motor de puntuacion CIS"
fi

# ────────────────────────────────────────────────────────────────
# S9: REMEDIACION AUTOMATICA SEGURA
# ────────────────────────────────────────────────────────────────
log_section "S9: REMEDIACION AUTOMATICA SEGURA"

echo "Ofrece remediacion automatica para checks CIS que se"
echo "pueden corregir de forma segura, con rollback."
echo ""
echo "Auto-remediable:"
echo "  - Parametros sysctl -> archivo conf"
echo "  - Servicios innecesarios -> systemctl disable"
echo "  - Permisos de archivos -> chmod"
echo "  - Opciones de montaje -> fstab (con backup)"
echo "  - login.defs -> actualizacion directa"
echo ""
echo "NUNCA auto-remedia:"
echo "  - Layout de particiones, PAM, bootloader, SELinux mode"
echo ""

if ask "¿Ejecutar remediacion automatica segura?"; then

    # Crear script de rollback
    rollback_file="${CIS_CONF_DIR}/cis-rollback-${TIMESTAMP}.sh"
    cat > "$rollback_file" << EOFROLLBACK_HEADER
#!/bin/bash
# ============================================================
# ROLLBACK de remediacion CIS
# Generado: $(date -Iseconds)
# Ejecutar con: sudo bash $rollback_file
# ============================================================
set -euo pipefail
echo "Ejecutando rollback de remediacion CIS..."
EOFROLLBACK_HEADER
    chmod 700 "$rollback_file"
    log_change "Creado" "$rollback_file"

    remediation_count=0

    # --- R1: Parametros sysctl ---
    log_info "R1: Verificando parametros sysctl..."
    declare -A SYSCTL_FIX=(
        ["net.ipv4.ip_forward"]="0"
        ["net.ipv4.conf.all.send_redirects"]="0"
        ["net.ipv4.conf.default.send_redirects"]="0"
        ["net.ipv4.conf.all.accept_source_route"]="0"
        ["net.ipv4.conf.all.accept_redirects"]="0"
        ["net.ipv4.conf.all.secure_redirects"]="1"
        ["net.ipv4.conf.all.log_martians"]="1"
        ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
        ["net.ipv4.tcp_syncookies"]="1"
        ["net.ipv6.conf.all.accept_ra"]="0"
        ["net.ipv6.conf.all.accept_redirects"]="0"
        ["kernel.randomize_va_space"]="2"
        ["fs.suid_dumpable"]="0"
    )

    sysctl_needs_fix=false
    for param in "${!SYSCTL_FIX[@]}"; do
        expected="${SYSCTL_FIX[$param]}"
        current=$(sysctl -n "$param" 2>/dev/null || echo "N/A")
        if [[ "$current" != "$expected" && "$current" != "N/A" ]]; then
            sysctl_needs_fix=true
            break
        fi
    done

    if $sysctl_needs_fix; then
        if ask "¿Corregir parametros sysctl que no cumplen CIS?"; then
            conf="/etc/sysctl.d/99-securizar-cis-remediation.conf"
            echo "# CIS Remediation - $(date -Iseconds)" > "$conf"
            for param in "${!SYSCTL_FIX[@]}"; do
                expected="${SYSCTL_FIX[$param]}"
                current=$(sysctl -n "$param" 2>/dev/null || echo "N/A")
                if [[ "$current" != "$expected" && "$current" != "N/A" ]]; then
                    echo "$param = $expected" >> "$conf"
                    # Rollback
                    echo "sysctl -w $param=$current 2>/dev/null || true" >> "$rollback_file"
                    log_change "Sysctl" "$param: $current -> $expected"
                    ((remediation_count++)) || true
                fi
            done
            sysctl -p "$conf" &>/dev/null || true
            echo "rm -f $conf" >> "$rollback_file"
            log_change "Creado" "$conf"
        fi
    else
        log_info "  Todos los parametros sysctl cumplen CIS"
    fi

    # --- R2: Servicios innecesarios ---
    log_info "R2: Verificando servicios innecesarios..."
    for svc in xinetd telnet.socket rsh.socket ntalk tftp.socket snmpd squid ypserv ypbind; do
        if systemctl is-enabled "$svc" &>/dev/null 2>&1; then
            if ask "¿Deshabilitar servicio $svc?"; then
                systemctl stop "$svc" 2>/dev/null || true
                systemctl disable "$svc" 2>/dev/null || true
                echo "systemctl enable $svc 2>/dev/null || true" >> "$rollback_file"
                log_change "Deshabilitado" "$svc"
                ((remediation_count++)) || true
            fi
        fi
    done

    # --- R3: Permisos de logs ---
    log_info "R3: Verificando permisos de archivos de log..."
    for logfile in /var/log/syslog /var/log/messages /var/log/auth.log /var/log/secure /var/log/kern.log; do
        if [[ -f "$logfile" ]]; then
            perms=$(stat -c %a "$logfile" 2>/dev/null || echo "777")
            if [[ "$perms" -gt 640 ]]; then
                if ask "¿Corregir permisos de $logfile ($perms -> 640)?"; then
                    echo "chmod $perms $logfile" >> "$rollback_file"
                    chmod 640 "$logfile"
                    log_change "Permisos" "$logfile: $perms -> 640"
                    ((remediation_count++)) || true
                fi
            fi
        fi
    done

    # --- R4: Opciones de montaje en fstab ---
    log_info "R4: Verificando opciones de montaje..."
    if [[ -f /etc/fstab ]]; then
        # Backup de fstab siempre
        cp /etc/fstab "${CIS_CONF_DIR}/fstab-backup-${TIMESTAMP}"
        echo "cp ${CIS_CONF_DIR}/fstab-backup-${TIMESTAMP} /etc/fstab" >> "$rollback_file"
        log_change "Backup" "/etc/fstab -> ${CIS_CONF_DIR}/fstab-backup-${TIMESTAMP}"

        # /tmp: agregar nodev,nosuid,noexec si existe en fstab
        if grep -qE "\s/tmp\s" /etc/fstab 2>/dev/null; then
            tmp_line=$(grep -E "\s/tmp\s" /etc/fstab)
            for opt in nodev nosuid noexec; do
                if ! echo "$tmp_line" | grep -q "$opt"; then
                    if ask "¿Agregar $opt a /tmp en fstab?"; then
                        sed -i "/[[:space:]]\/tmp[[:space:]]/ s/defaults/defaults,$opt/" /etc/fstab 2>/dev/null || true
                        log_change "Fstab" "/tmp: agregado $opt"
                        ((remediation_count++)) || true
                    fi
                fi
            done
        fi
    fi

    # --- R5: login.defs ---
    log_info "R5: Verificando login.defs..."
    if [[ -f /etc/login.defs ]]; then
        cp /etc/login.defs "${CIS_CONF_DIR}/login.defs-backup-${TIMESTAMP}"
        echo "cp ${CIS_CONF_DIR}/login.defs-backup-${TIMESTAMP} /etc/login.defs" >> "$rollback_file"

        declare -A LOGIN_DEFS_FIX=(
            ["PASS_MAX_DAYS"]="365"
            ["PASS_MIN_DAYS"]="1"
            ["PASS_WARN_AGE"]="7"
        )

        for param in "${!LOGIN_DEFS_FIX[@]}"; do
            expected="${LOGIN_DEFS_FIX[$param]}"
            current=$(grep -E "^\s*${param}" /etc/login.defs 2>/dev/null | awk '{print $2}' || echo "")

            needs_fix=false
            if [[ -z "$current" ]]; then
                needs_fix=true
            elif [[ "$param" == "PASS_MAX_DAYS" && "$current" -gt "$expected" ]] 2>/dev/null; then
                needs_fix=true
            elif [[ "$param" == "PASS_MIN_DAYS" && "$current" -lt "$expected" ]] 2>/dev/null; then
                needs_fix=true
            elif [[ "$param" == "PASS_WARN_AGE" && "$current" -lt "$expected" ]] 2>/dev/null; then
                needs_fix=true
            fi

            if $needs_fix; then
                if ask "¿Corregir $param en login.defs (${current:-vacio} -> $expected)?"; then
                    if grep -qE "^\s*${param}" /etc/login.defs 2>/dev/null; then
                        sed -i "s/^\s*${param}\s\+.*/${param}\t${expected}/" /etc/login.defs
                    else
                        echo "${param}	${expected}" >> /etc/login.defs
                    fi
                    log_change "Login.defs" "$param: ${current:-vacio} -> $expected"
                    ((remediation_count++)) || true
                fi
            fi
        done
    fi

    echo "" >> "$rollback_file"
    echo "echo 'Rollback completado.'" >> "$rollback_file"

    # ── S9b: Remediaciones CIS adicionales (R6-R8) ──
    log_info "Aplicando remediaciones CIS adicionales..."

    # R6: SSH CIS hardening
    SSH_CONF="/etc/ssh/sshd_config.d/99-cis-hardening.conf"
    if [[ ! -f "$SSH_CONF" ]]; then
        mkdir -p /etc/ssh/sshd_config.d
        cat > "$SSH_CONF" << 'EOFSSH'
# CIS SSH Hardening - generado por cumplimiento-cis.sh
# CIS 5.2.x recommendations
Protocol 2
LogLevel VERBOSE
MaxAuthTries 4
IgnoreRhosts yes
HostbasedAuthentication no
PermitEmptyPasswords no
MaxStartups 10:30:60
MaxSessions 10
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 3
EOFSSH
        chmod 644 "$SSH_CONF"
        log_change "Creado" "$SSH_CONF"
        echo "cp /dev/null $SSH_CONF  # Rollback R6" >> "$rollback_file"
        remediation_count=$((remediation_count + 1))
    fi

    # R7: cron.allow
    if [[ ! -f /etc/cron.allow ]]; then
        echo "root" > /etc/cron.allow
        chmod 600 /etc/cron.allow
        log_change "Creado" "/etc/cron.allow (solo root)"
        echo "rm -f /etc/cron.allow  # Rollback R7" >> "$rollback_file"
        remediation_count=$((remediation_count + 1))
    fi

    # R8: Core dump restriction
    LIMITS_CORE="/etc/security/limits.d/99-cis-coredump.conf"
    if [[ ! -f "$LIMITS_CORE" ]]; then
        echo "* hard core 0" > "$LIMITS_CORE"
        chmod 644 "$LIMITS_CORE"
        log_change "Creado" "$LIMITS_CORE"
        echo "rm -f $LIMITS_CORE  # Rollback R8" >> "$rollback_file"
        remediation_count=$((remediation_count + 1))
    fi

    log_info "Remediacion completada: $remediation_count correcciones aplicadas"
    log_info "Script de rollback: $rollback_file"

else
    log_skip "Remediacion automatica segura"
fi

# ────────────────────────────────────────────────────────────────
# S10: GENERACION DE INFORME DE CUMPLIMIENTO
# ────────────────────────────────────────────────────────────────
log_section "S10: GENERACION DE INFORME DE CUMPLIMIENTO"

echo "Crea /usr/local/bin/reporte-cumplimiento-cis.sh que genera"
echo "un informe completo de cumplimiento CIS con:"
echo "  - Tabla resumen por categoria"
echo "  - Referencia cruzada NIST 800-53"
echo "  - Recomendaciones de remediacion"
echo "  - Veredicto: CUMPLE / CUMPLE PARCIALMENTE / NO CUMPLE"
echo "  - Cron mensual automatico"
echo ""

if check_executable /usr/local/bin/reporte-cumplimiento-cis.sh; then
    log_already "Generador de informe CIS (reporte-cumplimiento-cis.sh existe)"
elif ask "¿Instalar generador de informe de cumplimiento CIS?"; then

    cat > /usr/local/bin/reporte-cumplimiento-cis.sh << 'EOFREPORTE'
#!/bin/bash
# ============================================================
# REPORTE DE CUMPLIMIENTO CIS BENCHMARK
# Genera informe completo con evidencia, scoring y mapeo NIST
# ============================================================
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root: sudo reporte-cumplimiento-cis.sh"
    exit 1
fi

REPORT_DIR="/var/lib/securizar/cis-reports"
SCORES_DIR="/var/lib/securizar/cis-scores"
NIST_FILE="/var/lib/securizar/nist-mapping.json"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
REPORT_FILE="$REPORT_DIR/reporte-cis-${TIMESTAMP}.txt"
mkdir -p "$REPORT_DIR" "$SCORES_DIR"

# Ejecutar scoring si existe
if [[ -x /usr/local/bin/cis-scoring.sh ]]; then
    echo "[*] Ejecutando motor de puntuacion CIS..."
    /usr/local/bin/cis-scoring.sh > /dev/null 2>&1 || true
fi

# Obtener ultimo resultado
LATEST_SCORE=""
LATEST_RESULT=""
if [[ -f "$SCORES_DIR/cis-score-latest.txt" ]]; then
    LATEST_SCORE=$(cat "$SCORES_DIR/cis-score-latest.txt" 2>/dev/null || echo "0")
fi
# Buscar ultimo archivo de resultados
LATEST_RESULT=$(ls -t "$SCORES_DIR"/cis-score-*.txt 2>/dev/null | head -1 || echo "")

{
echo "================================================================"
echo " INFORME DE CUMPLIMIENTO CIS BENCHMARK"
echo " Host: $(hostname)"
echo " Fecha: $(date -Iseconds)"
echo " Sistema: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"' || echo 'N/A')"
echo " Kernel: $(uname -r)"
echo "================================================================"
echo ""

# Incluir resultados detallados
if [[ -n "$LATEST_RESULT" && -f "$LATEST_RESULT" ]]; then
    echo "── RESULTADOS DETALLADOS ──────────────────────────────────"
    echo ""
    cat "$LATEST_RESULT"
    echo ""
fi

# Tabla resumen
echo "── TABLA RESUMEN ──────────────────────────────────────────"
echo ""
if [[ -n "$LATEST_RESULT" && -f "$LATEST_RESULT" ]]; then
    total_pass=$(grep -c "^\[PASS\]" "$LATEST_RESULT" || true)
    total_fail=$(grep -c "^\[FAIL\]" "$LATEST_RESULT" || true)
    total_na=$(grep -c "^\[N/A\]" "$LATEST_RESULT" || true)
    total_checks=$((total_pass + total_fail))

    printf "  %-24s %s\n" "Checks evaluados:" "$((total_pass + total_fail + total_na))"
    printf "  %-24s %s\n" "Aprobados (PASS):" "$total_pass"
    printf "  %-24s %s\n" "Fallidos (FAIL):" "$total_fail"
    printf "  %-24s %s\n" "No aplicable (N/A):" "$total_na"
    if [[ $total_checks -gt 0 ]]; then
        printf "  %-24s %s%%\n" "Puntuacion:" "$((total_pass * 100 / total_checks))"
    fi
    echo ""
fi

# Mapeo NIST
echo "── REFERENCIA CRUZADA NIST 800-53 ──────────────────────────"
echo ""
if [[ -f "$NIST_FILE" ]]; then
    echo "  El mapeo NIST 800-53 esta disponible en:"
    echo "  $NIST_FILE"
    echo ""
    echo "  Familias de controles cubiertas por el modulo CIS:"
    echo "    CA - Assessment, Authorization, and Monitoring"
    echo "    CM - Configuration Management"
    echo "    AC - Access Control"
    echo "    AU - Audit and Accountability"
    echo "    IA - Identification and Authentication"
    echo "    SC - System and Communications Protection"
    echo "    SI - System and Information Integrity"
    echo "    RA - Risk Assessment"
    echo "    SA - System and Services Acquisition"
else
    echo "  Mapeo NIST no generado. Ejecute cumplimiento-cis.sh seccion S7."
fi
echo ""

# Recomendaciones de remediacion
echo "── RECOMENDACIONES DE REMEDIACION ─────────────────────────"
echo ""
if [[ -n "$LATEST_RESULT" && -f "$LATEST_RESULT" ]]; then
    rec_num=1
    while IFS= read -r line; do
        check_id=$(echo "$line" | sed 's/\[FAIL\] //' | cut -d: -f1)
        check_desc=$(echo "$line" | cut -d: -f2-)
        printf "  %2d. %-20s %s\n" "$rec_num" "$check_id" "$check_desc"
        rec_num=$((rec_num+1))
    done < <(grep "^\[FAIL\]" "$LATEST_RESULT" 2>/dev/null)

    if [[ $rec_num -eq 1 ]]; then
        echo "  Sin recomendaciones - todos los checks aprobados."
    fi
else
    echo "  No hay resultados de scoring disponibles."
fi
echo ""

# Veredicto final
echo "── VEREDICTO ────────────────────────────────────────────────"
echo ""
score="${LATEST_SCORE:-0}"
if [[ "$score" -ge 90 ]]; then
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║           C U M P L E                    ║"
    echo "  ║     Score: ${score}% - CIS Benchmark           ║"
    echo "  ╚══════════════════════════════════════════╝"
elif [[ "$score" -ge 60 ]]; then
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║   C U M P L E   P A R C I A L M E N T E ║"
    echo "  ║     Score: ${score}% - CIS Benchmark           ║"
    echo "  ╚══════════════════════════════════════════╝"
else
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║       N O   C U M P L E                  ║"
    echo "  ║     Score: ${score}% - CIS Benchmark           ║"
    echo "  ╚══════════════════════════════════════════╝"
fi
echo ""

# Historial
if [[ -f "$SCORES_DIR/cis-score-history.csv" ]]; then
    echo "── HISTORIAL DE PUNTUACIONES ──────────────────────────────"
    echo ""
    tail -10 "$SCORES_DIR/cis-score-history.csv" | while IFS=: read -r ts sc ps fl na; do
        printf "  %s  Score: %3d%%  (PASS: %d, FAIL: %d, N/A: %d)\n" "$ts" "$sc" "$ps" "$fl" "$na"
    done
    echo ""
fi

echo "================================================================"
echo " Fin del informe"
echo " Archivo: $REPORT_FILE"
echo "================================================================"
} | tee "$REPORT_FILE"

echo ""
echo "Informe guardado en: $REPORT_FILE"
EOFREPORTE

    chmod 700 /usr/local/bin/reporte-cumplimiento-cis.sh
    log_change "Creado" "/usr/local/bin/reporte-cumplimiento-cis.sh"
    log_info "Generador de informes CIS instalado"

    # Cron mensual
    cat > /etc/cron.monthly/reporte-cumplimiento-cis << 'EOFCRON'
#!/bin/bash
# Informe mensual de cumplimiento CIS
# Generado por securizar - cumplimiento-cis.sh
/usr/local/bin/reporte-cumplimiento-cis.sh > /var/lib/securizar/cis-reports/reporte-mensual-$(date +%Y%m).txt 2>&1
logger -t securizar-cis "Informe mensual CIS generado. Ver /var/lib/securizar/cis-reports/"
# Limpiar informes antiguos (>12 meses)
find /var/lib/securizar/cis-reports/ -name "*.txt" -mtime +365 -delete 2>/dev/null || true
EOFCRON

    chmod 700 /etc/cron.monthly/reporte-cumplimiento-cis
    log_change "Creado" "/etc/cron.monthly/reporte-cumplimiento-cis"
    log_info "Cron mensual: /etc/cron.monthly/reporte-cumplimiento-cis"

else
    log_skip "Generacion de informe de cumplimiento"
fi

# ════════════════════════════════════════════════════════════════
# RESUMEN FINAL
# ════════════════════════════════════════════════════════════════
log_section "RESUMEN - CUMPLIMIENTO Y BENCHMARKS CIS"

echo ""
echo "Estado de herramientas de cumplimiento CIS:"
echo ""

declare -A CIS_TOOLS=(
    ["/usr/local/bin/cis-scoring.sh"]="Motor de puntuacion CIS"
    ["/usr/local/bin/reporte-cumplimiento-cis.sh"]="Generador de informes"
    ["/etc/cron.monthly/reporte-cumplimiento-cis"]="Cron mensual de informes"
    ["/etc/sysctl.d/99-securizar-cis-network.conf"]="Hardening de red CIS"
    ["/etc/audit/rules.d/99-cis-benchmark.rules"]="Reglas de auditoria CIS"
    ["/var/lib/securizar/nist-mapping.json"]="Mapeo NIST 800-53"
)

ok_count=0
total_tools=${#CIS_TOOLS[@]}

for tool_path in "${!CIS_TOOLS[@]}"; do
    tool_name="${CIS_TOOLS[$tool_path]}"
    if [[ -f "$tool_path" ]]; then
        echo -e "  ${GREEN}[OK]${NC} $tool_name"
        ((ok_count++)) || true
    else
        echo -e "  ${DIM}[--]${NC} $tool_name"
    fi
done

echo ""
echo "Herramientas instaladas: $ok_count/$total_tools"
echo ""
echo "Uso:"
echo "  cis-scoring.sh                 - Evaluar cumplimiento CIS (sin cambios)"
echo "  reporte-cumplimiento-cis.sh    - Generar informe completo"
echo ""
echo "Datos en:"
echo "  /var/lib/securizar/cis-scores/      - Historico de puntuaciones"
echo "  /var/lib/securizar/cis-reports/      - Informes generados"
echo "  /var/lib/securizar/nist-mapping.json - Mapeo NIST 800-53"
echo "  /etc/securizar/cis-rollback-*.sh     - Scripts de rollback"
echo ""

# ── S10b: Compliance drift monitor ──
log_info "Configurando monitor de drift de cumplimiento..."

if [[ ! -x /usr/local/bin/cis-drift-monitor.sh ]]; then
    cat > /usr/local/bin/cis-drift-monitor.sh << 'EOFDRIFT'
#!/bin/bash
# Monitor de drift de cumplimiento CIS
# Compara score actual contra última evaluación
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

SCORES_DIR="/var/lib/securizar/cis-scores"
mkdir -p "$SCORES_DIR"

echo -e "${BOLD}=== MONITOR DE DRIFT CIS ===${NC}"
echo "Fecha: $(date -Iseconds)"
echo ""

# Obtener score actual ejecutando cis-scoring.sh
CURRENT_SCORE=0
if [[ -x /usr/local/bin/cis-scoring.sh ]]; then
    RESULT=$(/usr/local/bin/cis-scoring.sh 2>/dev/null | grep -oP 'Score.*?(\d+)%' | grep -oP '\d+' | tail -1 || echo 0)
    CURRENT_SCORE="${RESULT:-0}"
fi

# Guardar score actual
echo "$(date +%Y-%m-%d),$CURRENT_SCORE" >> "$SCORES_DIR/drift-history.csv"

# Comparar con último score
if [[ -f "$SCORES_DIR/drift-history.csv" ]]; then
    PREV_LINE=$(tail -2 "$SCORES_DIR/drift-history.csv" | head -1)
    PREV_SCORE=$(echo "$PREV_LINE" | cut -d, -f2)
    PREV_DATE=$(echo "$PREV_LINE" | cut -d, -f1)

    if [[ -n "$PREV_SCORE" ]] && [[ "$PREV_SCORE" != "$CURRENT_SCORE" ]]; then
        DIFF=$((CURRENT_SCORE - PREV_SCORE))
        if [[ $DIFF -lt 0 ]]; then
            echo -e "${RED}DRIFT DETECTADO: Score bajó de $PREV_SCORE% a $CURRENT_SCORE% (${DIFF}%)${NC}"
            echo -e "${DIM}Último score: $PREV_DATE${NC}"
            logger -t securizar-cis "CIS DRIFT: score dropped from $PREV_SCORE% to $CURRENT_SCORE%"
        else
            echo -e "${GREEN}Score mejoró: $PREV_SCORE% → $CURRENT_SCORE% (+${DIFF}%)${NC}"
        fi
    else
        echo -e "${GREEN}Sin drift: score estable en $CURRENT_SCORE%${NC}"
    fi
fi

# Histórico reciente
echo ""
echo -e "${BOLD}Histórico (últimas 10 evaluaciones):${NC}"
tail -10 "$SCORES_DIR/drift-history.csv" 2>/dev/null | while IFS=, read -r date score; do
    printf "  %s  %s%%\n" "$date" "$score"
done
EOFDRIFT

    chmod 755 /usr/local/bin/cis-drift-monitor.sh
    log_change "Creado" "/usr/local/bin/cis-drift-monitor.sh"

    # Cron diario de drift
    cat > /etc/cron.daily/cis-drift-check << 'EOFCRON'
#!/bin/bash
/usr/local/bin/cis-drift-monitor.sh > /dev/null 2>&1
EOFCRON
    chmod 700 /etc/cron.daily/cis-drift-check
    log_change "Creado" "/etc/cron.daily/cis-drift-check"
    log_info "Monitor de drift CIS instalado (cron diario)"
fi

show_changes_summary
