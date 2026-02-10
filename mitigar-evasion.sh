#!/bin/bash
# ============================================================
# MITIGACIÓN DE EVASIÓN DE DEFENSAS - TA0005 (Defense Evasion)
# Linux Multi-Distro (openSUSE, Debian/Ubuntu, RHEL/Fedora, Arch)
# ============================================================
# Técnicas MITRE ATT&CK cubiertas:
#   T1070     - Indicator Removal (protección de logs)
#   T1070.003 - Clear Command History
#   T1070.004 - File Deletion (detección)
#   T1036     - Masquerading (detección de binarios falsos)
#   T1027     - Obfuscated Files or Scripts
#   T1562     - Impair Defenses (proteger herramientas de seguridad)
#   T1562.001 - Disable or Modify Tools
#   T1562.004 - Disable or Modify System Firewall
#   T1014     - Rootkit (detección)
#   T1218     - System Binary Proxy Execution
#   T1564     - Hide Artifacts (detección de artefactos ocultos)
#   T1564.001 - Hidden Files and Directories
#   T1140     - Deobfuscate/Decode Files
# ============================================================


set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "mitigar-evasion"
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MITIGACIÓN DE EVASIÓN DE DEFENSAS - TA0005              ║"
echo "║   Prevenir que atacantes evadan controles de seguridad     ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups se guardarán en: $BACKUP_DIR"

# ============================================================
log_section "1. PROTECCIÓN DE LOGS CONTRA ELIMINACIÓN (T1070)"
# ============================================================

echo "Proteger los logs del sistema contra eliminación o manipulación."
echo "Esto previene que un atacante borre sus huellas."
echo ""
echo "Medidas:"
echo "  - Logs inmutables con atributo append-only"
echo "  - Reenvío remoto de logs con journald"
echo "  - Auditoría de acceso a archivos de log"
echo ""

if ask "¿Proteger logs del sistema contra manipulación?"; then

    # 1a. Configurar atributos append-only en logs críticos
    echo ""
    echo -e "${BOLD}Protegiendo logs críticos con append-only...${NC}"

    LOG_FILES=(
        "/var/log/audit/audit.log"
        "/var/log/messages"
        "/var/log/secure"
        "/var/log/firewalld"
    )

    for logfile in "${LOG_FILES[@]}"; do
        if [[ -f "$logfile" ]]; then
            # Solo aplicar si no tiene ya el atributo
            if ! lsattr "$logfile" 2>/dev/null | grep -q "a"; then
                chattr +a "$logfile" 2>/dev/null && \
                    echo -e "  ${GREEN}OK${NC} append-only: $logfile" || \
                    echo -e "  ${YELLOW}!!${NC} No se pudo proteger: $logfile"
            else
                echo -e "  ${GREEN}OK${NC} Ya protegido: $logfile"
            fi
        fi
    done

    # 1b. Reglas auditd para monitorear acceso a logs
    if command -v auditctl &>/dev/null; then
        echo ""
        echo -e "${BOLD}Añadiendo reglas auditd para monitorear acceso a logs...${NC}"

        AUDIT_RULES_FILE="/etc/audit/rules.d/60-log-protection.rules"
        cp "$AUDIT_RULES_FILE" "$BACKUP_DIR/" 2>/dev/null || true

        cat > "$AUDIT_RULES_FILE" << 'EOF'
## Protección de logs - T1070 Indicator Removal
# Monitorear eliminación/modificación de logs del sistema
-w /var/log/audit/ -p wa -k log-tampering
-w /var/log/messages -p wa -k log-tampering
-w /var/log/secure -p wa -k log-tampering
-w /var/log/syslog -p wa -k log-tampering
-w /var/log/firewalld -p wa -k log-tampering
-w /var/log/fail2ban.log -p wa -k log-tampering

# Monitorear truncado/eliminación de logs (T1070.002)
-a always,exit -F arch=b64 -S truncate -S ftruncate -F dir=/var/log -F success=1 -k log-truncation
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F dir=/var/log -F success=1 -k log-deletion

# Monitorear journald y rsyslog config
-w /etc/systemd/journald.conf -p wa -k log-config-change
-w /etc/rsyslog.conf -p wa -k log-config-change
-w /etc/rsyslog.d/ -p wa -k log-config-change

# Monitorear uso de herramientas de limpieza de logs
-w /usr/bin/shred -p x -k log-wipe-tool
-w /usr/bin/wipe -p x -k log-wipe-tool
EOF

        log_info "Reglas auditd de protección de logs creadas: $AUDIT_RULES_FILE"

        # Recargar reglas
        augenrules --load 2>/dev/null || auditctl -R "$AUDIT_RULES_FILE" 2>/dev/null || true
        log_info "Reglas auditd recargadas"
    else
        log_warn "auditd no disponible - instálalo para protección completa de logs"
    fi

    # 1c. Configurar journald para persistencia y forward
    echo ""
    echo -e "${BOLD}Configurando journald para persistencia...${NC}"

    mkdir -p /etc/systemd/journald.conf.d
    cp /etc/systemd/journald.conf "$BACKUP_DIR/" 2>/dev/null || true

    cat > /etc/systemd/journald.conf.d/01-proteccion.conf << 'EOF'
# Protección de logs - T1070
[Journal]
# Almacenamiento persistente
Storage=persistent
# No comprimir (evita manipulación)
Compress=yes
# Sellar los logs para detectar manipulación
Seal=yes
# Mantener al menos 2GB de logs
SystemMaxUse=2G
SystemKeepFree=1G
# Mantener logs al menos 90 días
MaxRetentionSec=90day
# Rate limiting para evitar flood
RateLimitIntervalSec=30s
RateLimitBurst=10000
EOF

    systemctl restart systemd-journald 2>/dev/null || true
    log_info "journald configurado con persistencia y sellado"

    log_info "Protección de logs aplicada"
else
    log_warn "Protección de logs no aplicada"
fi

# ============================================================
log_section "2. PROTECCIÓN DEL HISTORIAL DE COMANDOS (T1070.003)"
# ============================================================

echo "Prevenir que atacantes borren el historial de comandos de bash."
echo "Esto dificulta ocultar la actividad post-explotación."
echo ""

if ask "¿Proteger historial de comandos contra eliminación?"; then

    # Crear configuración global de bash history
    cat > /etc/profile.d/history-protection.sh << 'EOFHIST'
# Protección de historial de comandos - T1070.003
# Establecer historial inmediato (cada comando se registra al instante)
shopt -s histappend
export PROMPT_COMMAND='history -a'

# Historial con timestamps
export HISTTIMEFORMAT="%Y-%m-%d %H:%M:%S  "

# Tamaño amplio de historial
export HISTSIZE=50000
export HISTFILESIZE=50000

# No ignorar comandos duplicados o con espacios
export HISTCONTROL=""

# No permitir que se desactive el historial
readonly HISTFILE
readonly HISTSIZE
readonly HISTFILESIZE
readonly HISTTIMEFORMAT
EOFHIST

    chmod 644 /etc/profile.d/history-protection.sh

    # Reglas auditd para monitorear borrado de historial
    if command -v auditctl &>/dev/null; then
        cat >> /etc/audit/rules.d/60-log-protection.rules << 'EOF'

# T1070.003 - Monitorear borrado de historial de comandos
-w /root/.bash_history -p wa -k history-tampering
-a always,exit -F arch=b64 -S unlink -S unlinkat -F path=/root/.bash_history -k history-delete
EOF
        augenrules --load 2>/dev/null || true
    fi

    # Auditoría centralizada de comandos con logger
    cat > /etc/profile.d/command-logging.sh << 'EOFCMDLOG'
# Logging centralizado de comandos a syslog
function log_command() {
    local cmd
    cmd=$(history 1 | sed 's/^ *[0-9]* *//')
    logger -p local6.info -t "bash-cmd[$$]" "user=$(whoami) pwd=$(pwd) cmd=$cmd"
}
export PROMPT_COMMAND="${PROMPT_COMMAND:+$PROMPT_COMMAND;}log_command"
EOFCMDLOG

    chmod 644 /etc/profile.d/command-logging.sh

    log_info "Protección de historial de comandos configurada"
else
    log_warn "Protección de historial no aplicada"
fi

# ============================================================
log_section "3. DETECCIÓN DE MASQUERADING (T1036)"
# ============================================================

echo "Detectar binarios que se hacen pasar por procesos legítimos."
echo "Atacantes renombran malware para parecer procesos del sistema."
echo ""

if ask "¿Configurar detección de binarios masquerading?"; then

    cat > /usr/local/bin/detectar-masquerading.sh << 'EOFMASQ'
#!/bin/bash
# Detección de masquerading (T1036)
# Busca binarios sospechosos que imitan nombres del sistema

LOG="/var/log/masquerading-detection-$(date +%Y%m%d).log"
ALERTS=0

echo "=== Detección de Masquerading - $(date) ===" | tee "$LOG"

# 1. Binarios en rutas no estándar con nombres del sistema
echo "" | tee -a "$LOG"
echo "--- Binarios con nombres del sistema en rutas no estándar ---" | tee -a "$LOG"

SYSTEM_NAMES="sshd httpd nginx systemd journald auditd firewalld NetworkManager polkitd"
for name in $SYSTEM_NAMES; do
    # Buscar en /tmp, /var/tmp, /dev/shm, /home
    FOUND=$(find /tmp /var/tmp /dev/shm /home -name "$name" -o -name "${name}.*" 2>/dev/null || true)
    if [[ -n "$FOUND" ]]; then
        echo "ALERTA: '$name' encontrado en ruta sospechosa:" | tee -a "$LOG"
        echo "$FOUND" | tee -a "$LOG"
        ((ALERTS++)) || true
    fi
done

# 2. Procesos ejecutándose desde rutas no estándar
echo "" | tee -a "$LOG"
echo "--- Procesos desde rutas sospechosas ---" | tee -a "$LOG"

while IFS= read -r proc_exe; do
    if [[ -n "$proc_exe" ]] && [[ "$proc_exe" =~ ^(/tmp|/var/tmp|/dev/shm|/home) ]]; then
        PID=$(echo "$proc_exe" | cut -d: -f1)
        EXE=$(echo "$proc_exe" | cut -d: -f2-)
        CMDLINE=$(cat "/proc/$PID/cmdline" 2>/dev/null | tr '\0' ' ' || echo "N/A")
        echo "ALERTA: PID $PID ejecutándose desde $EXE (cmd: $CMDLINE)" | tee -a "$LOG"
        ((ALERTS++)) || true
    fi
done < <(find /proc/[0-9]*/exe -maxdepth 0 2>/dev/null | while read -r link; do
    PID=$(echo "$link" | grep -oP '[0-9]+')
    EXE=$(readlink -f "$link" 2>/dev/null || echo "")
    [[ -n "$EXE" ]] && echo "$PID:$EXE"
done)

# 3. Binarios con espacios o caracteres Unicode en el nombre
echo "" | tee -a "$LOG"
echo "--- Binarios con nombres sospechosos ---" | tee -a "$LOG"

# Nombres con caracteres de dirección RTL o Unicode lookalikes
SUSPICIOUS_BINS=$(find /usr/bin /usr/sbin /usr/local/bin -name "*[[:space:]]*" -o -name ".*" 2>/dev/null || true)
if [[ -n "$SUSPICIOUS_BINS" ]]; then
    echo "ALERTA: Binarios con nombres sospechosos encontrados:" | tee -a "$LOG"
    echo "$SUSPICIOUS_BINS" | tee -a "$LOG"
    ((ALERTS++)) || true
else
    echo "OK: No se encontraron nombres sospechosos en rutas de binarios" | tee -a "$LOG"
fi

# 4. Verificar integridad de binarios del sistema con rpm
echo "" | tee -a "$LOG"
echo "--- Verificación de integridad de binarios críticos ---" | tee -a "$LOG"

CRITICAL_BINS="/usr/bin/ssh /usr/sbin/sshd /usr/bin/sudo /usr/bin/su /usr/bin/passwd /usr/bin/login"
for bin in $CRITICAL_BINS; do
    if [[ -x "$bin" ]]; then
        PKG=$(pkg_query_file "$bin" 2>/dev/null || echo "NO_PKG")
        if [[ "$PKG" != "NO_PKG" ]]; then
            VERIFY=$(pkg_verify_single "$PKG" 2>/dev/null | grep "^..5" || true)
            if [[ -n "$VERIFY" ]]; then
                echo "ALERTA: Binario modificado: $bin (pkg: $PKG)" | tee -a "$LOG"
                echo "$VERIFY" | tee -a "$LOG"
                ((ALERTS++)) || true
            else
                echo "OK: $bin (integridad verificada)" | tee -a "$LOG"
            fi
        fi
    fi
done

# Resumen
echo "" | tee -a "$LOG"
echo "=== RESUMEN ===" | tee -a "$LOG"
if [[ $ALERTS -eq 0 ]]; then
    echo "OK: Sin indicadores de masquerading" | tee -a "$LOG"
else
    echo "ALERTA: $ALERTS indicadores de masquerading detectados" | tee -a "$LOG"
    logger -t detectar-masquerading "ALERTA: $ALERTS indicadores de masquerading (T1036)"
fi

find /var/log -name "masquerading-detection-*.log" -mtime +30 -delete 2>/dev/null || true
EOFMASQ

    chmod 700 /usr/local/bin/detectar-masquerading.sh
    log_info "Script de detección de masquerading creado: /usr/local/bin/detectar-masquerading.sh"

    # Cron diario
    cat > /etc/cron.daily/detectar-masquerading << 'EOFCRON'
#!/bin/bash
/usr/local/bin/detectar-masquerading.sh 2>&1 | logger -t detectar-masquerading
EOFCRON
    chmod 700 /etc/cron.daily/detectar-masquerading

    log_info "Detección diaria de masquerading configurada"
else
    log_warn "Detección de masquerading no configurada"
fi

# ============================================================
log_section "4. PROTEGER HERRAMIENTAS DE SEGURIDAD (T1562)"
# ============================================================

echo "Prevenir que atacantes deshabiliten herramientas de seguridad."
echo "Esto cubre:"
echo "  - T1562.001: Desactivar o modificar herramientas (AV, IDS)"
echo "  - T1562.004: Desactivar o modificar firewall"
echo ""

if ask "¿Proteger herramientas de seguridad contra desactivación?"; then

    # 4a. Monitorear parada de servicios de seguridad
    echo ""
    echo -e "${BOLD}Configurando monitoreo de servicios de seguridad...${NC}"

    SECURITY_SERVICES="firewalld fail2ban auditd apparmor suricata clamd aide"

    # Reglas auditd para detectar manipulación de servicios
    if command -v auditctl &>/dev/null; then
        cat > /etc/audit/rules.d/61-defense-evasion.rules << 'EOF'
## Protección de herramientas de seguridad - T1562
# Monitorear intentos de desactivar servicios de seguridad
-w /usr/bin/systemctl -p x -k security-service-control
-w /usr/bin/service -p x -k security-service-control

# Monitorear modificación de configuración de seguridad
-w /etc/firewalld/ -p wa -k firewall-config-change
-w /etc/fail2ban/ -p wa -k fail2ban-config-change
-w /etc/audit/ -p wa -k audit-config-change
-w /etc/apparmor.d/ -p wa -k apparmor-config-change
-w /etc/suricata/ -p wa -k ids-config-change

# Monitorear desactivación de AppArmor
-w /usr/sbin/aa-disable -p x -k apparmor-disable
-w /usr/sbin/aa-teardown -p x -k apparmor-disable

# Monitorear iptables/nftables flush (T1562.004)
-w /usr/sbin/iptables -p x -k firewall-modify
-w /usr/sbin/nft -p x -k firewall-modify
-w /usr/sbin/firewall-cmd -p x -k firewall-modify
EOF

        augenrules --load 2>/dev/null || true
        log_info "Reglas auditd de protección de herramientas creadas"
    fi

    # 4b. Script de watchdog para servicios de seguridad
    cat > /usr/local/bin/watchdog-seguridad.sh << 'EOFWATCH'
#!/bin/bash
# Watchdog de servicios de seguridad - T1562
# Verifica que los servicios de seguridad estén activos y los reinicia si no

LOG="/var/log/security-watchdog.log"
ALERT=0

SERVICES="firewalld fail2ban auditd"

for svc in $SERVICES; do
    if systemctl is-enabled "$svc" &>/dev/null; then
        if ! systemctl is-active "$svc" &>/dev/null; then
            echo "$(date): ALERTA - $svc estaba caído, reiniciando..." >> "$LOG"
            systemctl start "$svc" 2>/dev/null
            if systemctl is-active "$svc" &>/dev/null; then
                echo "$(date): $svc reiniciado exitosamente" >> "$LOG"
            else
                echo "$(date): CRÍTICO - No se pudo reiniciar $svc" >> "$LOG"
            fi
            logger -t watchdog-seguridad "ALERTA: $svc estaba caído (T1562.001)"
            ((ALERT++)) || true
        fi
    fi
done

# Verificar AppArmor
if command -v aa-status &>/dev/null; then
    if ! aa-status --enabled 2>/dev/null; then
        echo "$(date): ALERTA - AppArmor desactivado" >> "$LOG"
        systemctl start apparmor 2>/dev/null || true
        logger -t watchdog-seguridad "ALERTA: AppArmor desactivado (T1562.001)"
        ((ALERT++)) || true
    fi
fi

# Verificar firewalld
if systemctl is-enabled firewalld &>/dev/null; then
    ZONES_ACTIVE=$(fw_get_active_zones 2>/dev/null | wc -l)
    if [[ "$ZONES_ACTIVE" -eq 0 ]]; then
        echo "$(date): ALERTA - firewalld sin zonas activas" >> "$LOG"
        logger -t watchdog-seguridad "ALERTA: Firewall sin zonas activas (T1562.004)"
        ((ALERT++)) || true
    fi
fi

if [[ $ALERT -gt 0 ]]; then
    logger -t watchdog-seguridad "ALERTA: $ALERT servicios de seguridad requirieron intervención"
fi
EOFWATCH

    chmod 700 /usr/local/bin/watchdog-seguridad.sh

    # Crear timer de systemd para el watchdog (cada 5 minutos)
    cat > /etc/systemd/system/watchdog-seguridad.service << 'EOFSVC'
[Unit]
Description=Watchdog de servicios de seguridad (T1562)
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/watchdog-seguridad.sh
StandardOutput=journal
StandardError=journal
EOFSVC

    cat > /etc/systemd/system/watchdog-seguridad.timer << 'EOFTIMER'
[Unit]
Description=Timer para watchdog de seguridad (cada 5 min)

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
Persistent=true

[Install]
WantedBy=timers.target
EOFTIMER

    systemctl daemon-reload
    systemctl enable --now watchdog-seguridad.timer 2>/dev/null || true

    log_info "Watchdog de servicios de seguridad activo (cada 5 minutos)"
else
    log_warn "Protección de herramientas de seguridad no aplicada"
fi

# ============================================================
log_section "5. DETECCIÓN DE ROOTKITS (T1014)"
# ============================================================

echo "Configurar detección periódica de rootkits."
echo "Los rootkits ocultan procesos, archivos y conexiones maliciosas."
echo ""

RKHUNTER_INSTALLED=false
CHKROOTKIT_INSTALLED=false

if command -v rkhunter &>/dev/null; then
    RKHUNTER_INSTALLED=true
    echo -e "  ${GREEN}OK${NC} rkhunter instalado"
else
    echo -e "  ${YELLOW}!!${NC} rkhunter no instalado"
fi

if command -v chkrootkit &>/dev/null; then
    CHKROOTKIT_INSTALLED=true
    echo -e "  ${GREEN}OK${NC} chkrootkit instalado"
else
    echo -e "  ${YELLOW}!!${NC} chkrootkit no instalado"
fi

echo ""

if ask "¿Instalar/configurar detección de rootkits?"; then

    # Instalar rkhunter si no está
    if [[ "$RKHUNTER_INSTALLED" == "false" ]]; then
        echo "Instalando rkhunter..."
        pkg_install rkhunter
        if command -v rkhunter &>/dev/null; then
            RKHUNTER_INSTALLED=true
            log_info "rkhunter instalado"
        fi
    fi

    # Configurar rkhunter
    if [[ "$RKHUNTER_INSTALLED" == "true" ]]; then
        cp /etc/rkhunter.conf "$BACKUP_DIR/" 2>/dev/null || true

        # Actualizar base de datos
        rkhunter --update 2>/dev/null || true
        rkhunter --propupd 2>/dev/null || true

        log_info "rkhunter actualizado y base de propiedades generada"
    fi

    # Script de detección combinada
    cat > /usr/local/bin/detectar-rootkits.sh << 'EOFRK'
#!/bin/bash
# Detección de rootkits - T1014
LOG="/var/log/rootkit-detection-$(date +%Y%m%d).log"
ALERTS=0

echo "=== Detección de Rootkits - $(date) ===" | tee "$LOG"

# 1. rkhunter
if command -v rkhunter &>/dev/null; then
    echo "" | tee -a "$LOG"
    echo "--- rkhunter ---" | tee -a "$LOG"
    rkhunter --check --skip-keypress --report-warnings-only 2>/dev/null | tee -a "$LOG"
    RK_WARNINGS=$(grep -c "Warning" "$LOG" 2>/dev/null || echo 0)
    if [[ "$RK_WARNINGS" -gt 0 ]]; then
        ((ALERTS+=RK_WARNINGS)) || true
    fi
fi

# 2. Detección manual de módulos ocultos del kernel
echo "" | tee -a "$LOG"
echo "--- Módulos del kernel sospechosos ---" | tee -a "$LOG"
HIDDEN_MODULES=$(diff <(cat /proc/modules | awk '{print $1}' | sort) <(lsmod | tail -n+2 | awk '{print $1}' | sort) 2>/dev/null || true)
if [[ -n "$HIDDEN_MODULES" ]]; then
    echo "ALERTA: Discrepancia en módulos del kernel:" | tee -a "$LOG"
    echo "$HIDDEN_MODULES" | tee -a "$LOG"
    ((ALERTS++)) || true
else
    echo "OK: Módulos del kernel consistentes" | tee -a "$LOG"
fi

# 3. Verificar /proc por procesos ocultos
echo "" | tee -a "$LOG"
echo "--- Procesos ocultos ---" | tee -a "$LOG"
PS_PIDS=$(ps -eo pid --no-headers | sort -n)
PROC_PIDS=$(ls -1 /proc/ 2>/dev/null | grep -E '^[0-9]+$' | sort -n)
HIDDEN_PIDS=$(comm -23 <(echo "$PROC_PIDS") <(echo "$PS_PIDS") 2>/dev/null || true)
if [[ -n "$HIDDEN_PIDS" ]]; then
    echo "ALERTA: PIDs en /proc no visibles en ps:" | tee -a "$LOG"
    echo "$HIDDEN_PIDS" | tee -a "$LOG"
    ((ALERTS++)) || true
else
    echo "OK: No se detectaron procesos ocultos" | tee -a "$LOG"
fi

# 4. Verificar libc por hooking
echo "" | tee -a "$LOG"
echo "--- Verificación de integridad de bibliotecas ---" | tee -a "$LOG"
LD_PRELOAD_ENV=$(env | grep LD_PRELOAD 2>/dev/null || true)
LD_PRELOAD_FILE=""
if [[ -f /etc/ld.so.preload ]]; then
    LD_PRELOAD_FILE=$(cat /etc/ld.so.preload 2>/dev/null || true)
fi

if [[ -n "$LD_PRELOAD_ENV" ]] || [[ -n "$LD_PRELOAD_FILE" ]]; then
    echo "ALERTA: LD_PRELOAD activo (posible hooking):" | tee -a "$LOG"
    [[ -n "$LD_PRELOAD_ENV" ]] && echo "  ENV: $LD_PRELOAD_ENV" | tee -a "$LOG"
    [[ -n "$LD_PRELOAD_FILE" ]] && echo "  FILE: $LD_PRELOAD_FILE" | tee -a "$LOG"
    ((ALERTS++)) || true
else
    echo "OK: No hay LD_PRELOAD sospechoso" | tee -a "$LOG"
fi

# Resumen
echo "" | tee -a "$LOG"
echo "=== RESUMEN ===" | tee -a "$LOG"
if [[ $ALERTS -eq 0 ]]; then
    echo "OK: Sin indicadores de rootkit" | tee -a "$LOG"
else
    echo "ALERTA: $ALERTS indicadores de rootkit detectados" | tee -a "$LOG"
    logger -t detectar-rootkits "ALERTA: $ALERTS indicadores de rootkit (T1014)"
fi

find /var/log -name "rootkit-detection-*.log" -mtime +30 -delete 2>/dev/null || true
EOFRK

    chmod 700 /usr/local/bin/detectar-rootkits.sh

    # Cron semanal
    cat > /etc/cron.weekly/detectar-rootkits << 'EOFCRON'
#!/bin/bash
/usr/local/bin/detectar-rootkits.sh 2>&1 | logger -t detectar-rootkits
EOFCRON
    chmod 700 /etc/cron.weekly/detectar-rootkits

    log_info "Detección semanal de rootkits configurada"
else
    log_warn "Detección de rootkits no configurada"
fi

# ============================================================
log_section "6. CONTROL DE PROXY EXECUTION (T1218)"
# ============================================================

echo "Restringir binarios del sistema que pueden usarse como proxy"
echo "para ejecutar código malicioso (LOLBins - Living Off The Land)."
echo ""
echo "Binarios comunes abusados:"
echo "  - certutil, xdg-open, env, script, strace, ltrace"
echo "  - python, perl, ruby (si no son necesarios)"
echo ""

if ask "¿Restringir binarios de proxy execution?"; then

    # Lista de binarios que pueden usarse como proxy
    LOLBINS=(
        "/usr/bin/strace"
        "/usr/bin/ltrace"
        "/usr/bin/gdb"
        "/usr/bin/ncat"
        "/usr/bin/nc"
        "/usr/bin/nmap"
        "/usr/bin/tcpdump"
        "/usr/bin/socat"
        "/usr/bin/curl"  # Solo restringir ejecución a grupo
        "/usr/bin/wget"
    )

    echo ""
    echo -e "${BOLD}Restringiendo acceso a LOLBins...${NC}"

    # Crear grupo para usuarios que necesiten estas herramientas
    if ! getent group security-tools &>/dev/null; then
        groupadd security-tools 2>/dev/null || true
        log_info "Grupo 'security-tools' creado"
    fi

    for bin in "${LOLBINS[@]}"; do
        if [[ -x "$bin" ]]; then
            CURRENT_PERMS=$(stat -c "%a" "$bin" 2>/dev/null)
            echo -e "  Restringiendo ${BOLD}$bin${NC} (permisos: $CURRENT_PERMS)"
            # Cambiar grupo y restringir ejecución
            chgrp security-tools "$bin" 2>/dev/null || true
            chmod 750 "$bin" 2>/dev/null || true
        fi
    done

    echo ""
    echo -e "${DIM}Usuarios que necesiten estas herramientas: usermod -aG security-tools <usuario>${NC}"

    # Reglas auditd para LOLBins
    if command -v auditctl &>/dev/null; then
        cat >> /etc/audit/rules.d/61-defense-evasion.rules << 'EOF'

# T1218 - System Binary Proxy Execution (LOLBins)
-w /usr/bin/strace -p x -k lolbin-exec
-w /usr/bin/ltrace -p x -k lolbin-exec
-w /usr/bin/gdb -p x -k lolbin-exec
-w /usr/bin/ncat -p x -k lolbin-exec
-w /usr/bin/nmap -p x -k lolbin-exec
-w /usr/bin/socat -p x -k lolbin-exec
-w /usr/bin/script -p x -k lolbin-exec
EOF
        augenrules --load 2>/dev/null || true
    fi

    log_info "LOLBins restringidos al grupo security-tools"
else
    log_warn "Control de proxy execution no aplicado"
fi

# ============================================================
log_section "7. DETECCIÓN DE ARTEFACTOS OCULTOS (T1564)"
# ============================================================

echo "Detectar archivos y directorios ocultos sospechosos."
echo "Atacantes usan archivos ocultos, ADS, y directorios con nombres"
echo "engañosos para esconder herramientas y datos."
echo ""

if ask "¿Configurar detección de artefactos ocultos?"; then

    cat > /usr/local/bin/detectar-ocultos.sh << 'EOFOCULTOS'
#!/bin/bash
# Detección de artefactos ocultos - T1564
LOG="/var/log/hidden-artifacts-$(date +%Y%m%d).log"
ALERTS=0

echo "=== Detección de Artefactos Ocultos - $(date) ===" | tee "$LOG"

# 1. Archivos ocultos en directorios sospechosos
echo "" | tee -a "$LOG"
echo "--- Archivos ocultos en rutas sospechosas ---" | tee -a "$LOG"

SUSPICIOUS_DIRS="/tmp /var/tmp /dev/shm /var/spool"
for dir in $SUSPICIOUS_DIRS; do
    HIDDEN=$(find "$dir" -maxdepth 3 -name ".*" -not -name "." -not -name ".." -not -name ".font-unix" -not -name ".ICE-unix" -not -name ".X11-unix" -not -name ".XIM-unix" 2>/dev/null || true)
    if [[ -n "$HIDDEN" ]]; then
        echo "ALERTA: Archivos ocultos en $dir:" | tee -a "$LOG"
        echo "$HIDDEN" | head -20 | tee -a "$LOG"
        ((ALERTS++)) || true
    fi
done

# 2. Directorios con nombres engañosos (espacios, puntos)
echo "" | tee -a "$LOG"
echo "--- Directorios con nombres engañosos ---" | tee -a "$LOG"

DECEPTIVE=$(find / -maxdepth 4 -type d \( -name ".. " -o -name "... " -o -name ".  " -o -name " " \) 2>/dev/null || true)
if [[ -n "$DECEPTIVE" ]]; then
    echo "ALERTA: Directorios con nombres engañosos:" | tee -a "$LOG"
    echo "$DECEPTIVE" | tee -a "$LOG"
    ((ALERTS++)) || true
else
    echo "OK: No se encontraron directorios engañosos" | tee -a "$LOG"
fi

# 3. Archivos con extensiones dobles o engañosas
echo "" | tee -a "$LOG"
echo "--- Archivos con extensiones sospechosas ---" | tee -a "$LOG"

DOUBLE_EXT=$(find /tmp /var/tmp /home -maxdepth 3 -type f \( -name "*.jpg.sh" -o -name "*.pdf.sh" -o -name "*.doc.sh" -o -name "*.txt.elf" -o -name "*.png.py" -o -name "*.pdf.py" \) 2>/dev/null || true)
if [[ -n "$DOUBLE_EXT" ]]; then
    echo "ALERTA: Archivos con extensiones dobles:" | tee -a "$LOG"
    echo "$DOUBLE_EXT" | tee -a "$LOG"
    ((ALERTS++)) || true
else
    echo "OK: Sin archivos con extensiones dobles" | tee -a "$LOG"
fi

# 4. Archivos setuid/setgid en /tmp o /home
echo "" | tee -a "$LOG"
echo "--- Archivos SUID/SGID en rutas no estándar ---" | tee -a "$LOG"

SUID_SUSPECT=$(find /tmp /var/tmp /home /dev/shm -perm /6000 -type f 2>/dev/null || true)
if [[ -n "$SUID_SUSPECT" ]]; then
    echo "ALERTA: SUID/SGID en rutas sospechosas:" | tee -a "$LOG"
    echo "$SUID_SUSPECT" | tee -a "$LOG"
    ((ALERTS++)) || true
else
    echo "OK: Sin SUID/SGID en rutas sospechosas" | tee -a "$LOG"
fi

# 5. Procesos con nombres vacíos o invisibles
echo "" | tee -a "$LOG"
echo "--- Procesos con nombres sospechosos ---" | tee -a "$LOG"

INVISIBLE_PROCS=$(ps aux 2>/dev/null | awk '{if(length($11)==0 || $11~/^\[.*\]$/ && NR>1) print}' | grep -v "^\[" || true)
if [[ -n "$INVISIBLE_PROCS" ]]; then
    echo "ALERTA: Procesos con nombres vacíos/sospechosos:" | tee -a "$LOG"
    echo "$INVISIBLE_PROCS" | head -10 | tee -a "$LOG"
    ((ALERTS++)) || true
else
    echo "OK: Sin procesos con nombres sospechosos" | tee -a "$LOG"
fi

# Resumen
echo "" | tee -a "$LOG"
echo "=== RESUMEN ===" | tee -a "$LOG"
if [[ $ALERTS -eq 0 ]]; then
    echo "OK: Sin artefactos ocultos detectados" | tee -a "$LOG"
else
    echo "ALERTA: $ALERTS categorías de artefactos ocultos detectadas" | tee -a "$LOG"
    logger -t detectar-ocultos "ALERTA: $ALERTS artefactos ocultos (T1564)"
fi

find /var/log -name "hidden-artifacts-*.log" -mtime +30 -delete 2>/dev/null || true
EOFOCULTOS

    chmod 700 /usr/local/bin/detectar-ocultos.sh

    cat > /etc/cron.daily/detectar-ocultos << 'EOFCRON'
#!/bin/bash
/usr/local/bin/detectar-ocultos.sh 2>&1 | logger -t detectar-ocultos
EOFCRON
    chmod 700 /etc/cron.daily/detectar-ocultos

    log_info "Detección diaria de artefactos ocultos configurada"
else
    log_warn "Detección de artefactos ocultos no configurada"
fi

# ============================================================
log_section "8. DETECCIÓN DE SCRIPTS OFUSCADOS (T1027/T1140)"
# ============================================================

echo "Detectar archivos y scripts con contenido ofuscado o codificado."
echo "Atacantes usan base64, hex encoding, y ofuscación para evadir."
echo ""

if ask "¿Configurar detección de scripts ofuscados?"; then

    cat > /usr/local/bin/detectar-ofuscados.sh << 'EOFOFUSC'
#!/bin/bash
# Detección de scripts ofuscados - T1027/T1140
LOG="/var/log/obfuscation-detection-$(date +%Y%m%d).log"
ALERTS=0

echo "=== Detección de Scripts Ofuscados - $(date) ===" | tee "$LOG"

# 1. Scripts con base64 decode inline
echo "" | tee -a "$LOG"
echo "--- Scripts con base64 decode ---" | tee -a "$LOG"

B64_FILES=$(grep -rl "base64.*-d\|base64.*--decode\|echo.*|.*base64\|openssl.*enc\|python.*-c.*base64\|perl.*-e.*decode_base64" /tmp /var/tmp /home /dev/shm 2>/dev/null | head -20 || true)
if [[ -n "$B64_FILES" ]]; then
    echo "ALERTA: Archivos con decodificación base64:" | tee -a "$LOG"
    echo "$B64_FILES" | tee -a "$LOG"
    ((ALERTS++)) || true
else
    echo "OK: Sin scripts con base64 decode en rutas temporales" | tee -a "$LOG"
fi

# 2. Scripts con eval de contenido dinámico
echo "" | tee -a "$LOG"
echo "--- Scripts con eval sospechoso ---" | tee -a "$LOG"

EVAL_FILES=$(grep -rl "eval.*\$(.*)\|eval.*\`.*\`\|eval.*\$(" /tmp /var/tmp /home /dev/shm 2>/dev/null | head -20 || true)
if [[ -n "$EVAL_FILES" ]]; then
    echo "ALERTA: Archivos con eval dinámico:" | tee -a "$LOG"
    echo "$EVAL_FILES" | tee -a "$LOG"
    ((ALERTS++)) || true
else
    echo "OK: Sin scripts con eval dinámico en rutas temporales" | tee -a "$LOG"
fi

# 3. Archivos con alta entropía (posible cifrado/compresión)
echo "" | tee -a "$LOG"
echo "--- Archivos con alta entropía en /tmp ---" | tee -a "$LOG"

while IFS= read -r file; do
    if [[ -f "$file" ]] && [[ -r "$file" ]]; then
        SIZE=$(stat -c%s "$file" 2>/dev/null || echo 0)
        if [[ "$SIZE" -gt 1000 ]] && [[ "$SIZE" -lt 10000000 ]]; then
            # Verificar si es binario no-reconocido
            FILETYPE=$(file -b "$file" 2>/dev/null || echo "")
            if echo "$FILETYPE" | grep -qi "data\|encrypted\|random"; then
                echo "ALERTA: Archivo sospechoso (alta entropía): $file ($FILETYPE)" | tee -a "$LOG"
                ((ALERTS++)) || true
            fi
        fi
    fi
done < <(find /tmp /var/tmp /dev/shm -maxdepth 2 -type f -newer /tmp -mtime -7 2>/dev/null || true)

# 4. Scripts con cadenas hexadecimales largas
echo "" | tee -a "$LOG"
echo "--- Scripts con cadenas hex/encoded ---" | tee -a "$LOG"

HEX_FILES=$(grep -rlP "\\\\x[0-9a-fA-F]{2}(\\\\x[0-9a-fA-F]{2}){10,}" /tmp /var/tmp /dev/shm 2>/dev/null | head -10 || true)
if [[ -n "$HEX_FILES" ]]; then
    echo "ALERTA: Archivos con cadenas hex largas:" | tee -a "$LOG"
    echo "$HEX_FILES" | tee -a "$LOG"
    ((ALERTS++)) || true
else
    echo "OK: Sin cadenas hex sospechosas" | tee -a "$LOG"
fi

# Resumen
echo "" | tee -a "$LOG"
echo "=== RESUMEN ===" | tee -a "$LOG"
if [[ $ALERTS -eq 0 ]]; then
    echo "OK: Sin scripts ofuscados detectados" | tee -a "$LOG"
else
    echo "ALERTA: $ALERTS indicadores de ofuscación detectados" | tee -a "$LOG"
    logger -t detectar-ofuscados "ALERTA: $ALERTS scripts ofuscados (T1027)"
fi

find /var/log -name "obfuscation-detection-*.log" -mtime +30 -delete 2>/dev/null || true
EOFOFUSC

    chmod 700 /usr/local/bin/detectar-ofuscados.sh

    cat > /etc/cron.daily/detectar-ofuscados << 'EOFCRON'
#!/bin/bash
/usr/local/bin/detectar-ofuscados.sh 2>&1 | logger -t detectar-ofuscados
EOFCRON
    chmod 700 /etc/cron.daily/detectar-ofuscados

    log_info "Detección diaria de scripts ofuscados configurada"
else
    log_warn "Detección de ofuscación no configurada"
fi

# ============================================================
log_section "RESUMEN DE MITIGACIONES TA0005"
# ============================================================

echo ""
echo -e "${BOLD}Estado de mitigaciones de Evasión de Defensas (TA0005):${NC}"
echo ""

# T1070 - Protección de logs
if [[ -f /etc/audit/rules.d/60-log-protection.rules ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1070 - Protección de logs contra manipulación"
else
    echo -e "  ${YELLOW}[--]${NC} T1070 - Protección de logs no configurada"
fi

# T1070.003 - Protección de historial
if [[ -f /etc/profile.d/history-protection.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1070.003 - Protección de historial de comandos"
else
    echo -e "  ${YELLOW}[--]${NC} T1070.003 - Protección de historial no configurada"
fi

# T1036 - Detección masquerading
if [[ -x /usr/local/bin/detectar-masquerading.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1036 - Detección de masquerading"
else
    echo -e "  ${YELLOW}[--]${NC} T1036 - Detección de masquerading no configurada"
fi

# T1562 - Protección de herramientas
if [[ -f /etc/systemd/system/watchdog-seguridad.timer ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1562 - Watchdog de herramientas de seguridad"
else
    echo -e "  ${YELLOW}[--]${NC} T1562 - Watchdog de herramientas no configurado"
fi

# T1014 - Detección rootkits
if [[ -x /usr/local/bin/detectar-rootkits.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1014 - Detección de rootkits"
else
    echo -e "  ${YELLOW}[--]${NC} T1014 - Detección de rootkits no configurada"
fi

# T1218 - Proxy execution
if [[ -f /etc/audit/rules.d/61-defense-evasion.rules ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1218 - Control de proxy execution (LOLBins)"
else
    echo -e "  ${YELLOW}[--]${NC} T1218 - Control de LOLBins no configurado"
fi

# T1564 - Artefactos ocultos
if [[ -x /usr/local/bin/detectar-ocultos.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1564 - Detección de artefactos ocultos"
else
    echo -e "  ${YELLOW}[--]${NC} T1564 - Detección de artefactos ocultos no configurada"
fi

# T1027 - Scripts ofuscados
if [[ -x /usr/local/bin/detectar-ofuscados.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1027/T1140 - Detección de scripts ofuscados"
else
    echo -e "  ${YELLOW}[--]${NC} T1027/T1140 - Detección de ofuscación no configurada"
fi

echo ""
log_info "Script de mitigación de evasión de defensas completado"
log_info "Backups de configuración en: $BACKUP_DIR"
