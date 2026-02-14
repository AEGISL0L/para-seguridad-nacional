#!/bin/bash
# ============================================================
# MITIGACIÓN DE PERSISTENCIA - TA0003 (Persistence)
# Linux Multi-Distro (openSUSE, Debian/Ubuntu, RHEL/Fedora, Arch)
# ============================================================
# Técnicas MITRE ATT&CK cubiertas:
#   T1053 - Scheduled Task/Job
#   T1543 - Create or Modify System Process
#   T1547 - Boot or Logon Autostart Execution
#   T1136 - Create Account
#   T1556 - Modify Authentication Process
#   T1546 - Event Triggered Execution
#   T1574 - Hijack Execution Flow
#   T1037 - Boot or Logon Initialization Scripts
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "mitigar-persistencia"
securizar_setup_traps

_precheck 7
_pc 'check_file_exists /etc/audit/rules.d/persistence-cron.rules'
_pc 'check_file_exists /etc/audit/rules.d/persistence-systemd.rules'
_pc 'check_file_exists /etc/audit/rules.d/persistence-autostart.rules'
_pc 'check_file_exists /etc/audit/rules.d/persistence-accounts.rules'
_pc 'check_file_exists /etc/audit/rules.d/persistence-auth.rules'
_pc true  # S6: hijack execution flow (detección)
_pc 'check_executable /usr/local/bin/detectar-persistencia.sh'
_precheck_result

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MITIGACIÓN DE PERSISTENCIA - TA0003                     ║"
echo "║   Detectar y prevenir mecanismos de persistencia           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# ============================================================
log_section "1. AUDITORÍA DE TAREAS PROGRAMADAS (T1053)"
# ============================================================

echo "Escaneando todas las tareas programadas del sistema..."
echo ""

echo -e "${BOLD}Crontabs de usuarios:${NC}"
CRON_ISSUES=0
for user_cron in /var/spool/cron/tabs/*; do
    [[ -f "$user_cron" ]] || continue
    user=$(basename "$user_cron")
    echo -e "  ${CYAN}Usuario: $user${NC}"
    grep -v "^#" "$user_cron" 2>/dev/null | grep -v "^$" | while IFS= read -r line; do
        echo -e "    $line"
    done
done

echo ""
echo -e "${BOLD}Cron del sistema (/etc/crontab):${NC}"
if [[ -f /etc/crontab ]]; then
    grep -v "^#" /etc/crontab 2>/dev/null | grep -v "^$" | sed 's/^/  /'
fi

echo ""
echo -e "${BOLD}Entradas en /etc/cron.d/:${NC}"
for f in /etc/cron.d/*; do
    [[ -f "$f" ]] || continue
    echo -e "  ${CYAN}$f:${NC}"
    grep -v "^#" "$f" 2>/dev/null | grep -v "^$" | head -5 | sed 's/^/    /'
done

echo ""
echo -e "${BOLD}Timers systemd personalizados:${NC}"
systemctl list-unit-files --type=timer 2>/dev/null | grep -v "^$" | grep -vE "^UNIT|^$|listed" | while IFS= read -r line; do
    TIMER_NAME=$(echo "$line" | awk '{print $1}')
    TIMER_STATE=$(echo "$line" | awk '{print $2}')
    # Detectar timers que no son del sistema
    if ! pkg_query_file "/usr/lib/systemd/system/$TIMER_NAME" &>/dev/null 2>&1; then
        echo -e "  ${YELLOW}●${NC} $TIMER_NAME ($TIMER_STATE) - NO pertenece a ningún paquete"
    fi
done || true

if check_file_exists /etc/audit/rules.d/persistence-cron.rules; then
    log_already "Monitoreo de tareas programadas (persistence-cron.rules)"
elif ask "¿Configurar monitoreo de cambios en tareas programadas?"; then
    if command -v auditctl &>/dev/null; then
        mkdir -p /etc/audit/rules.d
        cat > /etc/audit/rules.d/persistence-cron.rules << 'EOF'
# Monitoreo de persistencia via cron - T1053
-w /etc/crontab -p wa -k persist_cron
-w /etc/cron.d/ -p wa -k persist_cron
-w /etc/cron.daily/ -p wa -k persist_cron
-w /etc/cron.hourly/ -p wa -k persist_cron
-w /etc/cron.weekly/ -p wa -k persist_cron
-w /etc/cron.monthly/ -p wa -k persist_cron
-w /var/spool/cron/tabs/ -p wa -k persist_cron
-w /etc/anacrontab -p wa -k persist_cron
EOF
        log_change "Creado" "/etc/audit/rules.d/persistence-cron.rules"
        augenrules --load 2>/dev/null || true
        log_change "Aplicado" "augenrules --load"
        log_info "Monitoreo de cron configurado en auditd"
    fi
else
    log_skip "Monitoreo de tareas programadas no configurado"
fi

# ============================================================
log_section "2. AUDITORÍA DE SERVICIOS SYSTEMD (T1543)"
# ============================================================

echo "Buscando servicios systemd no estándar..."
echo ""

echo -e "${BOLD}Servicios de usuario (no de paquete):${NC}"
CUSTOM_SERVICES=0
for svc_file in /etc/systemd/system/*.service; do
    [[ -f "$svc_file" ]] || continue
    svc_name=$(basename "$svc_file")
    # Excluir enlaces simbólicos y drop-ins
    if [[ ! -L "$svc_file" ]]; then
        echo -e "  ${YELLOW}●${NC} $svc_name (personalizado en /etc/systemd/system/)"
        # Mostrar ExecStart
        EXEC=$(grep "^ExecStart=" "$svc_file" 2>/dev/null | head -1)
        [[ -n "$EXEC" ]] && echo -e "    ${DIM}$EXEC${NC}"
        CUSTOM_SERVICES=$((CUSTOM_SERVICES + 1))
    fi
done

# Buscar en directorios de usuario
for user_dir in /home/*; do
    [[ -d "$user_dir" ]] || continue
    user=$(basename "$user_dir")
    USER_SVC_DIR="$user_dir/.config/systemd/user"
    if [[ -d "$USER_SVC_DIR" ]]; then
        for svc_file in "$USER_SVC_DIR"/*.service; do
            [[ -f "$svc_file" ]] || continue
            svc_name=$(basename "$svc_file")
            echo -e "  ${RED}●${NC} $svc_name (servicio de usuario: $user)"
            EXEC=$(grep "^ExecStart=" "$svc_file" 2>/dev/null | head -1)
            [[ -n "$EXEC" ]] && echo -e "    ${DIM}$EXEC${NC}"
            CUSTOM_SERVICES=$((CUSTOM_SERVICES + 1))
        done
    fi
done

if [[ $CUSTOM_SERVICES -eq 0 ]]; then
    echo -e "  ${GREEN}OK${NC} No se detectan servicios personalizados sospechosos"
fi

echo ""
if check_file_exists /etc/audit/rules.d/persistence-systemd.rules; then
    log_already "Monitoreo de servicios systemd (persistence-systemd.rules)"
elif ask "¿Configurar monitoreo de cambios en servicios systemd?"; then
    if command -v auditctl &>/dev/null; then
        mkdir -p /etc/audit/rules.d
        cat > /etc/audit/rules.d/persistence-systemd.rules << 'EOF'
# Monitoreo de persistencia via systemd - T1543
-w /etc/systemd/system/ -p wa -k persist_systemd
-w /usr/lib/systemd/system/ -p wa -k persist_systemd
-w /run/systemd/system/ -p wa -k persist_systemd
-w /etc/systemd/system.conf -p wa -k persist_systemd
EOF
        log_change "Creado" "/etc/audit/rules.d/persistence-systemd.rules"
        augenrules --load 2>/dev/null || true
        log_change "Aplicado" "augenrules --load"
        log_info "Monitoreo de servicios systemd configurado"
    fi
else
    log_skip "Monitoreo de servicios systemd no configurado"
fi

# ============================================================
log_section "3. AUTOSTART Y SCRIPTS DE INICIO (T1547/T1037)"
# ============================================================

echo "Auditando mecanismos de autostart..."
echo ""

# Scripts de login
echo -e "${BOLD}Scripts de inicio de sesión:${NC}"
LOGIN_SCRIPTS=("/etc/profile" "/etc/profile.d/" "/etc/bash.bashrc" "/etc/environment")
for ls_path in "${LOGIN_SCRIPTS[@]}"; do
    if [[ -d "$ls_path" ]]; then
        for f in "$ls_path"*; do
            [[ -f "$f" ]] || continue
            if ! pkg_query_file "$f" &>/dev/null 2>&1; then
                echo -e "  ${YELLOW}●${NC} $f (no pertenece a paquete)"
            fi
        done
    elif [[ -f "$ls_path" ]]; then
        MOD_DATE=$(stat -c "%y" "$ls_path" 2>/dev/null | cut -d' ' -f1)
        echo -e "  ${DIM}$ls_path (modificado: $MOD_DATE)${NC}"
    fi
done

# Bashrc de usuarios
echo ""
echo -e "${BOLD}Bashrc/profile de usuarios (comandos sospechosos):${NC}"
for home_dir in /root /home/*; do
    [[ -d "$home_dir" ]] || continue
    user=$(basename "$home_dir")
    for rc_file in "$home_dir/.bashrc" "$home_dir/.bash_profile" "$home_dir/.profile" "$home_dir/.bash_login"; do
        [[ -f "$rc_file" ]] || continue
        # Buscar comandos sospechosos
        SUSPICIOUS=$(grep -nE "(curl|wget|nc |ncat|socat|python.*-c|perl.*-e|bash.*-i|/dev/tcp|eval|base64.*-d)" "$rc_file" 2>/dev/null || true)
        if [[ -n "$SUSPICIOUS" ]]; then
            log_warn "Comandos sospechosos en $rc_file:"
            echo "$SUSPICIOUS" | sed 's/^/    /'
        fi
    done
done

# XDG autostart
echo ""
echo -e "${BOLD}XDG autostart:${NC}"
for autostart_dir in /etc/xdg/autostart /home/*/.config/autostart; do
    if [[ -d "$autostart_dir" ]]; then
        for desktop_file in "$autostart_dir"/*.desktop; do
            [[ -f "$desktop_file" ]] || continue
            APP_NAME=$(grep "^Name=" "$desktop_file" | cut -d= -f2)
            APP_EXEC=$(grep "^Exec=" "$desktop_file" | cut -d= -f2)
            echo -e "  ${DIM}$desktop_file${NC}"
            echo -e "    Nombre: $APP_NAME"
            echo -e "    Exec: $APP_EXEC"
        done
    fi
done

# rc.local
if [[ -f /etc/rc.local ]] && [[ -s /etc/rc.local ]]; then
    CONTENT=$(grep -v "^#" /etc/rc.local | grep -v "^$" | head -10)
    if [[ -n "$CONTENT" ]]; then
        log_warn "/etc/rc.local tiene comandos:"
        echo "$CONTENT" | sed 's/^/    /'
    fi
fi

echo ""
if check_file_exists /etc/audit/rules.d/persistence-autostart.rules; then
    log_already "Monitoreo de scripts de autostart (persistence-autostart.rules)"
elif ask "¿Configurar monitoreo de scripts de autostart?"; then
    if command -v auditctl &>/dev/null; then
        mkdir -p /etc/audit/rules.d
        cat > /etc/audit/rules.d/persistence-autostart.rules << 'EOF'
# Monitoreo de persistencia via autostart - T1547/T1037
-w /etc/profile -p wa -k persist_login
-w /etc/profile.d/ -p wa -k persist_login
-w /etc/bash.bashrc -p wa -k persist_login
-w /etc/environment -p wa -k persist_login
-w /etc/rc.local -p wa -k persist_boot
-w /etc/init.d/ -p wa -k persist_boot
-w /etc/xdg/autostart/ -p wa -k persist_autostart
EOF
        log_change "Creado" "/etc/audit/rules.d/persistence-autostart.rules"
        augenrules --load 2>/dev/null || true
        log_change "Aplicado" "augenrules --load"
        log_info "Monitoreo de autostart configurado"
    fi
else
    log_skip "Monitoreo de scripts de autostart no configurado"
fi

# ============================================================
log_section "4. DETECCIÓN DE CUENTAS SOSPECHOSAS (T1136)"
# ============================================================

echo "Auditando cuentas del sistema..."
echo ""

# Cuentas creadas recientemente
echo -e "${BOLD}Cuentas con login reciente o creación reciente:${NC}"
while IFS=: read -r user _ uid gid _ home shell; do
    [[ "$uid" -ge 1000 && "$uid" -lt 65534 ]] || continue
    LAST_LOGIN=$(lastlog -u "$user" 2>/dev/null | tail -1 | awk '{print $4, $5, $6, $7}' || echo "Nunca")
    echo -e "  $user (UID=$uid) - Shell: $shell - Último login: $LAST_LOGIN"
done < /etc/passwd

# UID=0 (además de root)
echo ""
echo -e "${BOLD}Cuentas con UID=0:${NC}"
UID0_COUNT=0
while IFS=: read -r user _ uid _; do
    if [[ "$uid" -eq 0 ]]; then
        if [[ "$user" == "root" ]]; then
            echo -e "  ${GREEN}●${NC} root (esperado)"
        else
            echo -e "  ${RED}●${NC} $user - UID=0 INESPERADO"
            UID0_COUNT=$((UID0_COUNT + 1))
        fi
    fi
done < /etc/passwd

if [[ $UID0_COUNT -gt 0 ]]; then
    log_error "$UID0_COUNT cuenta(s) con UID=0 además de root"
fi

# Cuentas sin contraseña
echo ""
echo -e "${BOLD}Cuentas sin contraseña:${NC}"
EMPTY_PASS=0
while IFS=: read -r user pass _; do
    if [[ "$pass" == "" || "$pass" == "!" || "$pass" == "!!" ]]; then
        continue  # Bloqueada/sin password (normal para sistema)
    fi
    if [[ ${#pass} -lt 4 ]]; then
        echo -e "  ${RED}●${NC} $user - contraseña potencialmente débil/vacía"
        EMPTY_PASS=$((EMPTY_PASS + 1))
    fi
done < /etc/shadow 2>/dev/null

[[ $EMPTY_PASS -eq 0 ]] && echo -e "  ${GREEN}OK${NC} No se detectan cuentas con contraseñas débiles"

echo ""
if check_file_exists /etc/audit/rules.d/persistence-accounts.rules; then
    log_already "Monitoreo de cuentas (persistence-accounts.rules)"
elif ask "¿Configurar monitoreo de creación/modificación de cuentas?"; then
    if command -v auditctl &>/dev/null; then
        mkdir -p /etc/audit/rules.d
        cat > /etc/audit/rules.d/persistence-accounts.rules << 'EOF'
# Monitoreo de persistencia via cuentas - T1136
-w /etc/passwd -p wa -k persist_account
-w /etc/shadow -p wa -k persist_account
-w /etc/group -p wa -k persist_account
-w /etc/gshadow -p wa -k persist_account
-w /etc/sudoers -p wa -k persist_priv
-w /etc/sudoers.d/ -p wa -k persist_priv

# Monitorear comandos de gestión de usuarios
-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/useradd -k account_create
-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/usermod -k account_modify
-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/userdel -k account_delete
-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/groupadd -k group_create
EOF
        log_change "Creado" "/etc/audit/rules.d/persistence-accounts.rules"
        augenrules --load 2>/dev/null || true
        log_change "Aplicado" "augenrules --load"
        log_info "Monitoreo de cuentas configurado"
    fi
else
    log_skip "Monitoreo de cuentas no configurado"
fi

# ============================================================
log_section "5. INTEGRIDAD DE AUTENTICACIÓN (T1556)"
# ============================================================

echo "Verificando integridad del sistema de autenticación..."
echo ""
echo -e "${DIM}(Solo verificación - NO se modifica PAM por restricción del proyecto)${NC}"
echo ""

# Verificar que PAM no fue modificado
echo -e "${BOLD}Archivos PAM:${NC}"
for pam_file in /etc/pam.d/su /etc/pam.d/sudo /etc/pam.d/sshd /etc/pam.d/login; do
    if [[ -f "$pam_file" ]]; then
        HASH=$(sha256sum "$pam_file" 2>/dev/null | awk '{print $1}')
        PKG=$(pkg_query_file "$pam_file"2>/dev/null || echo "sin paquete")
        echo -e "  $pam_file ($PKG)"
        echo -e "    ${DIM}SHA256: ${HASH:0:32}...${NC}"
    fi
done

# Verificar nsswitch
echo ""
echo -e "${BOLD}NSS configuración (/etc/nsswitch.conf):${NC}"
if [[ -f /etc/nsswitch.conf ]]; then
    grep -E "^(passwd|shadow|group):" /etc/nsswitch.conf | while IFS= read -r line; do
        if echo "$line" | grep -qE "ldap|nis|sss|winbind"; then
            echo -e "  ${YELLOW}●${NC} $line (fuente externa detectada)"
        else
            echo -e "  ${GREEN}●${NC} $line"
        fi
    done
fi

# SSH authorized_keys - integridad
echo ""
echo -e "${BOLD}Claves SSH autorizadas:${NC}"
for home_dir in /root /home/*; do
    AUTH_KEYS="$home_dir/.ssh/authorized_keys"
    [[ -f "$AUTH_KEYS" ]] || continue
    user=$(basename "$home_dir")
    KEYS=$(grep -c "^ssh-" "$AUTH_KEYS" 2>/dev/null || echo 0)
    PERMS=$(stat -c "%a" "$AUTH_KEYS" 2>/dev/null)
    echo -e "  $user: $KEYS clave(s) (permisos: $PERMS)"
    if [[ "$PERMS" != "600" && "$PERMS" != "644" ]]; then
        log_warn "Permisos incorrectos en $AUTH_KEYS"
    fi
done

echo ""
if check_file_exists /etc/audit/rules.d/persistence-auth.rules; then
    log_already "Monitoreo de autenticación (persistence-auth.rules)"
elif ask "¿Configurar monitoreo de autenticación?"; then
    if command -v auditctl &>/dev/null; then
        mkdir -p /etc/audit/rules.d
        cat > /etc/audit/rules.d/persistence-auth.rules << 'EOF'
# Monitoreo de persistencia via autenticación - T1556
-w /etc/pam.d/ -p wa -k persist_auth
-w /etc/nsswitch.conf -p wa -k persist_auth
-w /etc/ssh/sshd_config -p wa -k persist_ssh
-w /etc/ssh/sshd_config.d/ -p wa -k persist_ssh
EOF

        log_change "Creado" "/etc/audit/rules.d/persistence-auth.rules"
        # Monitorear authorized_keys de todos los usuarios
        for home_dir in /root /home/*; do
            AUTH_DIR="$home_dir/.ssh"
            if [[ -d "$AUTH_DIR" ]]; then
                echo "-w $AUTH_DIR/authorized_keys -p wa -k persist_ssh_keys" >> /etc/audit/rules.d/persistence-auth.rules
                log_change "Modificado" "/etc/audit/rules.d/persistence-auth.rules"
            fi
        done

        augenrules --load 2>/dev/null || true
        log_change "Aplicado" "augenrules --load"
        log_info "Monitoreo de autenticación configurado"
    fi
else
    log_skip "Monitoreo de autenticación no configurado"
fi

# ============================================================
log_section "6. HIJACK DE FLUJO DE EJECUCIÓN (T1574)"
# ============================================================

echo "Verificando vectores de hijacking..."
echo ""

# PATH hijacking - verificar directorios escribibles en PATH
echo -e "${BOLD}Directorios en PATH:${NC}"
PATH_ISSUES=0
IFS=':' read -ra PATH_DIRS <<< "$PATH"
for dir in "${PATH_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        PERMS=$(stat -c "%a" "$dir" 2>/dev/null)
        OWNER=$(stat -c "%U" "$dir" 2>/dev/null)
        if [[ "$PERMS" == *"7"* && "$OWNER" != "root" ]] || [[ "${PERMS:2:1}" == "7" ]]; then
            echo -e "  ${RED}●${NC} $dir (permisos: $PERMS, owner: $OWNER) - ESCRIBIBLE POR OTROS"
            PATH_ISSUES=$((PATH_ISSUES + 1))
        else
            echo -e "  ${GREEN}●${NC} $dir ($PERMS)"
        fi
    fi
done

if [[ $PATH_ISSUES -gt 0 ]]; then
    log_warn "$PATH_ISSUES directorio(s) del PATH escribibles por otros"
fi

# LD_LIBRARY_PATH y LD_PRELOAD
echo ""
echo -e "${BOLD}Variables de entorno de carga:${NC}"
if [[ -n "${LD_PRELOAD:-}" ]]; then
    log_warn "LD_PRELOAD establecido: $LD_PRELOAD"
else
    echo -e "  ${GREEN}OK${NC} LD_PRELOAD no establecido"
fi

if [[ -n "${LD_LIBRARY_PATH:-}" ]]; then
    log_warn "LD_LIBRARY_PATH establecido: $LD_LIBRARY_PATH"
else
    echo -e "  ${GREEN}OK${NC} LD_LIBRARY_PATH no establecido"
fi

# Verificar RPATH/RUNPATH en binarios SUID
echo ""
echo -e "${BOLD}Binarios SUID con RPATH:${NC}"
find /usr/bin /usr/sbin /usr/local/bin -perm -4000 -type f 2>/dev/null | head -20 | while read -r suid_bin; do
    if command -v readelf &>/dev/null; then
        RPATH=$(readelf -d "$suid_bin" 2>/dev/null | grep -E "RPATH|RUNPATH" || true)
        if [[ -n "$RPATH" ]]; then
            echo -e "  ${RED}●${NC} $suid_bin tiene RPATH: $RPATH"
        fi
    fi
done || echo -e "  ${DIM}readelf no disponible${NC}"

# ============================================================
log_section "7. SCRIPT DE DETECCIÓN DE PERSISTENCIA"
# ============================================================

if check_executable /usr/local/bin/detectar-persistencia.sh; then
    log_already "Script de detección de persistencia (/usr/local/bin/detectar-persistencia.sh)"
elif ask "¿Crear script de detección periódica de persistencia?"; then
    cat > /usr/local/bin/detectar-persistencia.sh << 'PERSIST_EOF'
#!/bin/bash
# ============================================================
# DETECTOR DE PERSISTENCIA - TA0003
# Verificación periódica de mecanismos de persistencia
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

LOGFILE="/var/log/detectar-persistencia-$(date +%Y%m%d).log"

echo "============================================================" | tee "$LOGFILE"
echo " DETECCIÓN DE PERSISTENCIA - $(date)" | tee -a "$LOGFILE"
echo "============================================================" | tee -a "$LOGFILE"
echo "" | tee -a "$LOGFILE"

ALERTS=0

# 1. Crontabs nuevos o modificados (últimas 24h)
echo -e "${CYAN}[1/7] Crontabs modificados recientemente:${NC}" | tee -a "$LOGFILE"
find /var/spool/cron/tabs/ /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ -mtime -1 -type f 2>/dev/null | while read -r f; do
    echo -e "  ${YELLOW}[!]${NC} Modificado: $f" | tee -a "$LOGFILE"
    ALERTS=$((ALERTS + 1))
done

# 2. Servicios systemd nuevos
echo -e "${CYAN}[2/7] Servicios systemd en /etc:${NC}" | tee -a "$LOGFILE"
find /etc/systemd/system/ -name "*.service" -not -type l -mtime -7 2>/dev/null | while read -r f; do
    echo -e "  ${YELLOW}[!]${NC} Servicio reciente: $f" | tee -a "$LOGFILE"
    ALERTS=$((ALERTS + 1))
done

# 3. Cuentas nuevas
echo -e "${CYAN}[3/7] Cuentas con UID >= 1000:${NC}" | tee -a "$LOGFILE"
awk -F: '$3 >= 1000 && $3 < 65534 {print "  "$1" (UID="$3", shell="$7")"}' /etc/passwd | tee -a "$LOGFILE"

# 4. UID=0 extra
echo -e "${CYAN}[4/7] Cuentas con UID=0:${NC}" | tee -a "$LOGFILE"
awk -F: '$3 == 0 && $1 != "root" {print "  '$RED'[!] "$1" tiene UID=0'$NC'"}' /etc/passwd | tee -a "$LOGFILE"

# 5. authorized_keys cambios
echo -e "${CYAN}[5/7] Claves SSH:${NC}" | tee -a "$LOGFILE"
find /root/.ssh /home/*/.ssh -name "authorized_keys" -mtime -7 2>/dev/null | while read -r f; do
    KEYS=$(grep -c "^ssh-" "$f" 2>/dev/null || echo 0)
    echo -e "  $f: $KEYS clave(s) (modificado recientemente)" | tee -a "$LOGFILE"
done

# 6. Binarios SUID nuevos
echo -e "${CYAN}[6/7] Binarios SUID:${NC}" | tee -a "$LOGFILE"
find / -perm -4000 -type f -mtime -7 2>/dev/null | while read -r f; do
    echo -e "  ${YELLOW}[!]${NC} SUID reciente: $f" | tee -a "$LOGFILE"
    ALERTS=$((ALERTS + 1))
done

# 7. Módulos del kernel cargados no estándar
echo -e "${CYAN}[7/7] Módulos del kernel:${NC}" | tee -a "$LOGFILE"
lsmod 2>/dev/null | tail -n +2 | while read -r mod _; do
    if ! modinfo "$mod" 2>/dev/null | grep -q "filename.*kernel/"; then
        echo -e "  ${RED}[!]${NC} Módulo no estándar: $mod" | tee -a "$LOGFILE"
        ALERTS=$((ALERTS + 1))
    fi
done 2>/dev/null || true

echo "" | tee -a "$LOGFILE"
echo "Alertas: $ALERTS" | tee -a "$LOGFILE"
echo "Log: $LOGFILE" | tee -a "$LOGFILE"
PERSIST_EOF

    log_change "Creado" "/usr/local/bin/detectar-persistencia.sh"
    chmod +x /usr/local/bin/detectar-persistencia.sh
    log_change "Permisos" "/usr/local/bin/detectar-persistencia.sh -> +x"
    log_info "Script creado: /usr/local/bin/detectar-persistencia.sh"

    # Programar ejecución diaria
    if check_executable /etc/cron.daily/detectar-persistencia; then
        log_already "Detección diaria de persistencia (cron)"
    elif ask "¿Programar detección de persistencia diaria (cron)?"; then
        cat > /etc/cron.daily/detectar-persistencia << 'DCRON_EOF'
#!/bin/bash
/usr/local/bin/detectar-persistencia.sh > /dev/null 2>&1
DCRON_EOF
        log_change "Creado" "/etc/cron.daily/detectar-persistencia"
        chmod +x /etc/cron.daily/detectar-persistencia
        log_change "Permisos" "/etc/cron.daily/detectar-persistencia -> +x"
        log_info "Detección diaria programada"
    else
        log_skip "Detección diaria de persistencia no programada"
    fi
else
    log_skip "Script de detección de persistencia no creado"
fi

show_changes_summary

# ============================================================
# RESUMEN
# ============================================================
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║    MITIGACIÓN PERSISTENCIA COMPLETADA (TA0003)             ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "Técnicas mitigadas:"
echo "  T1053 - Scheduled Task       → Auditoría cron + monitoreo"
echo "  T1543 - System Process       → Auditoría servicios systemd"
echo "  T1547 - Boot Autostart       → Auditoría scripts de inicio"
echo "  T1136 - Create Account       → Monitoreo de cuentas"
echo "  T1556 - Auth Process         → Verificación PAM/NSS/SSH"
echo "  T1574 - Hijack Execution     → PATH, LD_PRELOAD, RPATH"
echo "  T1037 - Login Scripts        → Auditoría bashrc/profile"
echo ""
echo "Monitoreo: auditd + detección diaria de persistencia"
echo ""
log_info "Backups en: $BACKUP_DIR"
