#!/bin/bash
# ============================================================
# AUTOMATIZACIÓN DE SEGURIDAD - Linux Multi-Distro
# ============================================================
# Secciones:
#   S1 - Cron diario AIDE
#   S2 - Cron diario parches de seguridad zypper
#   S3 - Cron semanal auditoría lynis
#   S4 - Cron diario rkhunter
#   S5 - Sistema de notificaciones + timer systemd
#   S6 - Cron semanal verificar logrotate
#   S7 - Cron diario digest de seguridad
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps

# ── Pre-check: detectar secciones ya aplicadas ──
_precheck 7
_pc check_file_exists /etc/cron.daily/aide-check
_pc check_file_exists /etc/cron.daily/zypper-security-update
_pc check_file_exists /etc/cron.weekly/lynis-audit
_pc check_file_exists /etc/cron.daily/rkhunter-check
_pc check_executable /usr/local/bin/seguridad-notificar.sh
_pc check_file_exists /etc/cron.weekly/verificar-logrotate
_pc check_file_exists /etc/cron.daily/seguridad-resumen
_precheck_result

log_info "Configurando automatización de seguridad..."

# ============================================================
# S1: Cron diario AIDE (verificación de integridad)
# ============================================================
log_section "S1: VERIFICACIÓN DIARIA AIDE"

if command -v aide &>/dev/null; then
    echo "AIDE detectado. Se creará un cron job diario para verificar integridad."
    echo ""

    if check_file_exists /etc/cron.daily/aide-check; then
        log_already "Cron diario AIDE (aide-check)"
    elif ask "¿Crear /etc/cron.daily/aide-check?"; then
        cat > /etc/cron.daily/aide-check << 'EOFAIDE'
#!/bin/bash
# Verificación diaria de integridad con AIDE
LOG="/var/log/aide-check-$(date +%Y%m%d).log"

echo "=== AIDE Check - $(date) ===" > "$LOG"

if [[ -f /var/lib/aide/aide.db ]]; then
    aide --check >> "$LOG" 2>&1
    RESULT=$?
    if [[ $RESULT -ne 0 ]]; then
        echo "ALERTA: AIDE detectó cambios (código: $RESULT)" >> "$LOG"
        logger -t aide-check "ALERTA: cambios detectados en archivos del sistema"
    else
        echo "OK: Sin cambios detectados" >> "$LOG"
    fi
else
    echo "ERROR: Base de datos AIDE no encontrada" >> "$LOG"
    echo "Ejecutar: aide --init && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db" >> "$LOG"
fi

# Limpiar logs antiguos (>30 días)
find /var/log -name "aide-check-*.log" -mtime +30 -delete 2>/dev/null
EOFAIDE

        chmod 700 /etc/cron.daily/aide-check
        log_change "Creado" "/etc/cron.daily/aide-check"
        log_change "Permisos" "/etc/cron.daily/aide-check -> 700"
        log_info "Cron diario AIDE creado: /etc/cron.daily/aide-check"
    else
        log_skip "Crear /etc/cron.daily/aide-check"
    fi
else
    log_warn "AIDE no instalado. Instálalo primero con el módulo 6 (paranoico)"
fi

# ============================================================
# S2: Cron diario parches de seguridad
# ============================================================
log_section "S2: PARCHES DE SEGURIDAD AUTOMÁTICOS"

echo "Se creará un cron job diario para instalar parches de seguridad."
echo "Solo instala parches marcados como 'security'."
echo ""

if check_file_exists /etc/cron.daily/zypper-security-update; then
    log_already "Parches de seguridad automáticos (zypper-security-update)"
elif ask "¿Crear /etc/cron.daily/zypper-security-update?"; then
    cat > /etc/cron.daily/zypper-security-update << 'EOFZYPPER'
#!/bin/bash
# Instalación automática de parches de seguridad (multi-distro)
LOG="/var/log/security-update-$(date +%Y%m%d).log"

echo "=== Security Update - $(date) ===" > "$LOG"

# Detectar gestor de paquetes y aplicar parches de seguridad
if command -v zypper &>/dev/null; then
    zypper --non-interactive refresh >> "$LOG" 2>&1
    zypper --non-interactive patch --category security >> "$LOG" 2>&1
    RESULT=$?
elif command -v apt-get &>/dev/null; then
    apt-get update >> "$LOG" 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get -y --only-upgrade install $(apt list --upgradable 2>/dev/null | grep -i security | cut -d/ -f1) >> "$LOG" 2>&1
    RESULT=$?
elif command -v dnf &>/dev/null; then
    dnf -y --security upgrade >> "$LOG" 2>&1
    RESULT=$?
elif command -v pacman &>/dev/null; then
    pacman -Syu --noconfirm >> "$LOG" 2>&1
    RESULT=$?
else
    echo "WARN: No se encontró gestor de paquetes" >> "$LOG"
    RESULT=1
fi

if [[ $RESULT -eq 0 ]]; then
    echo "OK: Parches de seguridad aplicados" >> "$LOG"
elif [[ $RESULT -eq 103 ]]; then
    echo "INFO: Se requiere reinicio para completar la actualización" >> "$LOG"
    logger -t security-update "Se requiere reinicio tras parches de seguridad"
else
    echo "WARN: Gestor de paquetes terminó con código $RESULT" >> "$LOG"
fi

# Limpiar logs antiguos (>30 días)
find /var/log -name "security-update-*.log" -mtime +30 -delete 2>/dev/null
EOFZYPPER

    chmod 700 /etc/cron.daily/zypper-security-update
    log_change "Creado" "/etc/cron.daily/zypper-security-update"
    log_change "Permisos" "/etc/cron.daily/zypper-security-update -> 700"
    log_info "Cron diario creado: /etc/cron.daily/zypper-security-update"
else
    log_skip "Crear /etc/cron.daily/zypper-security-update"
fi

# ============================================================
# S3: Cron semanal auditoría lynis
# ============================================================
log_section "S3: AUDITORÍA SEMANAL LYNIS"

if command -v lynis &>/dev/null; then
    echo "Lynis detectado. Se creará una auditoría semanal automatizada."
    echo ""

    if check_file_exists /etc/cron.weekly/lynis-audit; then
        log_already "Auditoría semanal Lynis (lynis-audit)"
    elif ask "¿Crear /etc/cron.weekly/lynis-audit?"; then
        cat > /etc/cron.weekly/lynis-audit << 'EOFLYNIS'
#!/bin/bash
# Auditoría semanal de seguridad con lynis
LOG="/var/log/lynis-audit-$(date +%Y%m%d).log"

echo "=== Lynis Audit - $(date) ===" > "$LOG"

lynis audit system --no-colors --quiet >> "$LOG" 2>&1

# Extraer puntuación
score=$(grep "Hardening index" /var/log/lynis.log 2>/dev/null | tail -1 | grep -oP '\d+')
if [[ -n "$score" ]]; then
    echo "Puntuación de hardening: $score" >> "$LOG"
    logger -t lynis-audit "Auditoría semanal completada - Score: $score"
fi

# Copiar reporte
cp /var/log/lynis.log /var/log/lynis-report-$(date +%Y%m%d).log 2>/dev/null

# Limpiar logs antiguos (>60 días)
find /var/log -name "lynis-audit-*.log" -mtime +60 -delete 2>/dev/null
find /var/log -name "lynis-report-*.log" -mtime +60 -delete 2>/dev/null
EOFLYNIS

        chmod 700 /etc/cron.weekly/lynis-audit
        log_change "Creado" "/etc/cron.weekly/lynis-audit"
        log_change "Permisos" "/etc/cron.weekly/lynis-audit -> 700"
        log_info "Cron semanal lynis creado: /etc/cron.weekly/lynis-audit"
    else
        log_skip "Crear /etc/cron.weekly/lynis-audit"
    fi
else
    log_warn "lynis no instalado. Instálalo primero con el módulo 6 (paranoico)"
fi

# ============================================================
# S4: Cron diario rkhunter
# ============================================================
log_section "S4: ESCANEO DIARIO RKHUNTER"

if command -v rkhunter &>/dev/null; then
    echo "rkhunter detectado. Se creará un escaneo diario de rootkits."
    echo ""

    if check_file_exists /etc/cron.daily/rkhunter-check; then
        log_already "Escaneo diario rkhunter (rkhunter-check)"
    elif ask "¿Crear /etc/cron.daily/rkhunter-check?"; then
        cat > /etc/cron.daily/rkhunter-check << 'EOFRKHUNTER'
#!/bin/bash
# Escaneo diario de rootkits con rkhunter
LOG="/var/log/rkhunter-check-$(date +%Y%m%d).log"

echo "=== rkhunter Check - $(date) ===" > "$LOG"

# Actualizar bases de datos
rkhunter --update >> "$LOG" 2>&1 || true

# Escaneo
rkhunter --check --skip-keypress --report-warnings-only >> "$LOG" 2>&1
RESULT=$?

if [[ $RESULT -ne 0 ]]; then
    echo "ALERTA: rkhunter detectó advertencias (código: $RESULT)" >> "$LOG"
    logger -t rkhunter-check "ALERTA: advertencias detectadas en escaneo de rootkits"
else
    echo "OK: Sin advertencias" >> "$LOG"
fi

# Limpiar logs antiguos (>30 días)
find /var/log -name "rkhunter-check-*.log" -mtime +30 -delete 2>/dev/null
EOFRKHUNTER

        chmod 700 /etc/cron.daily/rkhunter-check
        log_change "Creado" "/etc/cron.daily/rkhunter-check"
        log_change "Permisos" "/etc/cron.daily/rkhunter-check -> 700"
        log_info "Cron diario rkhunter creado: /etc/cron.daily/rkhunter-check"
    else
        log_skip "Crear /etc/cron.daily/rkhunter-check"
    fi
else
    log_warn "rkhunter no instalado. Instálalo primero con el módulo 6 (paranoico)"
fi

# ============================================================
# S5: Sistema de notificaciones + timer systemd
# ============================================================
log_section "S5: SISTEMA DE NOTIFICACIONES"

echo "Se creará un script de notificaciones y un timer horario."
echo "Las notificaciones se envían via notify-send (escritorio) y logger (syslog)."
echo ""

if check_executable /usr/local/bin/seguridad-notificar.sh; then
    log_already "Sistema de notificaciones (seguridad-notificar.sh)"
elif ask "¿Crear sistema de notificaciones de seguridad?"; then
    # Script de notificaciones
    cat > /usr/local/bin/seguridad-notificar.sh << 'EOFNOTIFY'
#!/bin/bash
# ============================================================
# Notificaciones de seguridad
# Verifica estado del sistema y notifica si hay problemas
# ============================================================

LOG="/var/log/seguridad-notificaciones.log"
ALERTAS=0

notificar() {
    local nivel="$1"
    local mensaje="$2"

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$nivel] $mensaje" >> "$LOG"
    logger -t seguridad-notificar "[$nivel] $mensaje"

    # Notificación de escritorio si hay sesión gráfica
    if [[ -n "${DISPLAY:-}" ]] || [[ -n "${WAYLAND_DISPLAY:-}" ]]; then
        XUSER=$(who | grep -m1 '(:' | awk '{print $1}')
        if [[ -n "$XUSER" ]]; then
            su - "$XUSER" -c "notify-send 'Seguridad [$nivel]' '$mensaje'" 2>/dev/null || true
        fi
    fi
}

# 1. Verificar servicios de seguridad
for svc in firewalld fail2ban auditd; do
    if systemctl is-enabled "$svc" &>/dev/null && ! systemctl is-active "$svc" &>/dev/null; then
        notificar "ALERTA" "$svc está habilitado pero NO activo"
        ((ALERTAS++))
    fi
done

# 2. Verificar logins fallidos recientes (última hora)
failed_logins=$(journalctl -u sshd --since "1 hour ago" 2>/dev/null | grep -c "Failed password" || echo 0)
if [[ "$failed_logins" -gt 5 ]]; then
    notificar "ALERTA" "$failed_logins intentos de login SSH fallidos en la última hora"
    ((ALERTAS++))
fi

# 3. Verificar IPs baneadas por fail2ban
if command -v fail2ban-client &>/dev/null; then
    banned=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $NF}' || echo 0)
    if [[ "$banned" -gt 0 ]]; then
        notificar "INFO" "fail2ban: $banned IPs baneadas en jail sshd"
    fi
fi

# 4. Verificar espacio en disco
disk_usage=$(df / | tail -1 | awk '{print $5}' | tr -d '%')
if [[ "$disk_usage" -gt 90 ]]; then
    notificar "ALERTA" "Disco raíz al ${disk_usage}% de uso"
    ((ALERTAS++))
fi

# 5. Verificar si hay actualizaciones de seguridad pendientes
if command -v zypper &>/dev/null; then
    sec_updates=$(zypper --non-interactive list-patches --category security 2>/dev/null | grep -c "needed" || echo 0)
elif command -v apt-get &>/dev/null; then
    sec_updates=$(apt list --upgradable 2>/dev/null | grep -ci "security" || echo 0)
elif command -v dnf &>/dev/null; then
    sec_updates=$(dnf updateinfo list --security 2>/dev/null | grep -cE "^[A-Z]" || echo 0)
else
    sec_updates=0
fi
if [[ "$sec_updates" -gt 0 ]]; then
    notificar "INFO" "$sec_updates parches de seguridad pendientes"
fi

if [[ $ALERTAS -eq 0 ]]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [OK] Sin alertas" >> "$LOG"
fi

# Limpiar log si supera 10MB
if [[ -f "$LOG" ]] && [[ $(stat -c%s "$LOG" 2>/dev/null || echo 0) -gt 10485760 ]]; then
    tail -1000 "$LOG" > "${LOG}.tmp" && mv "${LOG}.tmp" "$LOG"
fi
EOFNOTIFY

    chmod +x /usr/local/bin/seguridad-notificar.sh
    log_change "Creado" "/usr/local/bin/seguridad-notificar.sh"
    log_change "Permisos" "/usr/local/bin/seguridad-notificar.sh -> +x"
    log_info "Script creado: /usr/local/bin/seguridad-notificar.sh"

    # Timer systemd
    cat > /etc/systemd/system/seguridad-notificar.service << 'EOF'
[Unit]
Description=Verificación horaria de seguridad
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/seguridad-notificar.sh
EOF
    log_change "Creado" "/etc/systemd/system/seguridad-notificar.service"

    cat > /etc/systemd/system/seguridad-notificar.timer << 'EOF'
[Unit]
Description=Timer horario de verificación de seguridad

[Timer]
OnCalendar=hourly
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
EOF
    log_change "Creado" "/etc/systemd/system/seguridad-notificar.timer"

    systemctl daemon-reload
    log_change "Aplicado" "systemctl daemon-reload"
    systemctl enable --now seguridad-notificar.timer 2>/dev/null || true
    log_change "Servicio" "seguridad-notificar.timer enable --now"
    log_info "Timer horario habilitado: seguridad-notificar.timer"
else
    log_skip "Sistema de notificaciones de seguridad"
fi

# ============================================================
# S6: Cron semanal verificar logrotate
# ============================================================
log_section "S6: VERIFICACIÓN SEMANAL DE LOGROTATE"

echo "Se verificará que logrotate está funcionando correctamente."
echo ""

if check_file_exists /etc/cron.weekly/verificar-logrotate; then
    log_already "Verificación de logrotate (verificar-logrotate)"
elif ask "¿Crear /etc/cron.weekly/verificar-logrotate?"; then
    cat > /etc/cron.weekly/verificar-logrotate << 'EOFLOGROTATE'
#!/bin/bash
# Verificación semanal de logrotate
LOG="/var/log/verificar-logrotate-$(date +%Y%m%d).log"

echo "=== Verificación de logrotate - $(date) ===" > "$LOG"

# Verificar configuración
logrotate -d /etc/logrotate.conf >> "$LOG" 2>&1
RESULT=$?

if [[ $RESULT -eq 0 ]]; then
    echo "OK: Configuración de logrotate válida" >> "$LOG"
else
    echo "ALERTA: Errores en configuración de logrotate" >> "$LOG"
    logger -t verificar-logrotate "ALERTA: errores en configuración de logrotate"
fi

# Verificar logs que no rotan (>100MB)
echo "" >> "$LOG"
echo "Logs grandes (>100MB):" >> "$LOG"
find /var/log -type f -size +100M -exec ls -lh {} \; >> "$LOG" 2>/dev/null

# Verificar estado de logrotate
if [[ -f /var/lib/logrotate/logrotate.status ]]; then
    echo "" >> "$LOG"
    echo "Última ejecución de logrotate:" >> "$LOG"
    head -5 /var/lib/logrotate/logrotate.status >> "$LOG"
fi

# Limpiar logs antiguos
find /var/log -name "verificar-logrotate-*.log" -mtime +60 -delete 2>/dev/null
EOFLOGROTATE

    chmod 700 /etc/cron.weekly/verificar-logrotate
    log_change "Creado" "/etc/cron.weekly/verificar-logrotate"
    log_change "Permisos" "/etc/cron.weekly/verificar-logrotate -> 700"
    log_info "Cron semanal creado: /etc/cron.weekly/verificar-logrotate"
else
    log_skip "Crear /etc/cron.weekly/verificar-logrotate"
fi

# ============================================================
# S7: Cron diario digest de seguridad
# ============================================================
log_section "S7: DIGEST DIARIO DE SEGURIDAD"

echo "Se generará un resumen diario con:"
echo "  - Estado de servicios de seguridad"
echo "  - Estado de fail2ban"
echo "  - Logins recientes"
echo "  - Alertas del día"
echo ""

if check_file_exists /etc/cron.daily/seguridad-resumen; then
    log_already "Digest diario de seguridad (seguridad-resumen)"
elif ask "¿Crear /etc/cron.daily/seguridad-resumen?"; then
    cat > /etc/cron.daily/seguridad-resumen << 'EOFRESUMEN'
#!/bin/bash
# Digest diario de seguridad
RESUMEN="/var/log/seguridad-resumen-$(date +%Y%m%d).log"

echo "════════════════════════════════════════════════════════════" > "$RESUMEN"
echo "  RESUMEN DE SEGURIDAD - $(date '+%Y-%m-%d %H:%M:%S')" >> "$RESUMEN"
echo "════════════════════════════════════════════════════════════" >> "$RESUMEN"

# 1. Estado de servicios
echo "" >> "$RESUMEN"
echo "── SERVICIOS DE SEGURIDAD ──" >> "$RESUMEN"
for svc in firewalld fail2ban auditd sshd usbguard security-monitor; do
    if systemctl is-active "$svc" &>/dev/null; then
        echo "  [OK]  $svc activo" >> "$RESUMEN"
    elif systemctl is-enabled "$svc" &>/dev/null; then
        echo "  [!!]  $svc habilitado pero INACTIVO" >> "$RESUMEN"
    fi
done

# 2. fail2ban
echo "" >> "$RESUMEN"
echo "── FAIL2BAN ──" >> "$RESUMEN"
if command -v fail2ban-client &>/dev/null; then
    fail2ban-client status >> "$RESUMEN" 2>&1
    for jail in $(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*://;s/,/ /g'); do
        fail2ban-client status "$jail" >> "$RESUMEN" 2>&1 || true
    done
else
    echo "  fail2ban no instalado" >> "$RESUMEN"
fi

# 3. Logins (últimas 24h)
echo "" >> "$RESUMEN"
echo "── LOGINS RECIENTES (24h) ──" >> "$RESUMEN"
journalctl -u sshd --since "24 hours ago" 2>/dev/null | grep -E "Accepted|Failed" | tail -20 >> "$RESUMEN" 2>/dev/null || echo "  Sin datos de journal" >> "$RESUMEN"

echo "" >> "$RESUMEN"
echo "── INTENTOS FALLIDOS ──" >> "$RESUMEN"
failed=$(journalctl -u sshd --since "24 hours ago" 2>/dev/null | grep -c "Failed password" || echo 0)
echo "  Total intentos fallidos SSH (24h): $failed" >> "$RESUMEN"

# 4. Actualizaciones pendientes
echo "" >> "$RESUMEN"
echo "── ACTUALIZACIONES DE SEGURIDAD ──" >> "$RESUMEN"
if command -v zypper &>/dev/null; then
    zypper --non-interactive list-patches --category security 2>/dev/null | grep "needed" >> "$RESUMEN" 2>/dev/null || echo "  Sin parches pendientes" >> "$RESUMEN"
elif command -v apt-get &>/dev/null; then
    apt list --upgradable 2>/dev/null | grep -i security >> "$RESUMEN" 2>/dev/null || echo "  Sin parches pendientes" >> "$RESUMEN"
elif command -v dnf &>/dev/null; then
    dnf updateinfo list --security 2>/dev/null | head -20 >> "$RESUMEN" 2>/dev/null || echo "  Sin parches pendientes" >> "$RESUMEN"
else
    echo "  Gestor de paquetes no reconocido" >> "$RESUMEN"
fi

# 5. Espacio en disco
echo "" >> "$RESUMEN"
echo "── ESPACIO EN DISCO ──" >> "$RESUMEN"
df -h / /boot /home 2>/dev/null >> "$RESUMEN"

# 6. Alertas del día
echo "" >> "$RESUMEN"
echo "── ALERTAS DEL DÍA ──" >> "$RESUMEN"
if [[ -f /var/log/seguridad-notificaciones.log ]]; then
    grep "$(date +%Y-%m-%d)" /var/log/seguridad-notificaciones.log >> "$RESUMEN" 2>/dev/null || echo "  Sin alertas" >> "$RESUMEN"
else
    echo "  Sin log de notificaciones" >> "$RESUMEN"
fi

echo "" >> "$RESUMEN"
echo "════════════════════════════════════════════════════════════" >> "$RESUMEN"
echo "  Fin del resumen" >> "$RESUMEN"
echo "════════════════════════════════════════════════════════════" >> "$RESUMEN"

logger -t seguridad-resumen "Resumen diario generado: $RESUMEN"

# Limpiar resúmenes antiguos (>30 días)
find /var/log -name "seguridad-resumen-*.log" -mtime +30 -delete 2>/dev/null
EOFRESUMEN

    chmod 700 /etc/cron.daily/seguridad-resumen
    log_change "Creado" "/etc/cron.daily/seguridad-resumen"
    log_change "Permisos" "/etc/cron.daily/seguridad-resumen -> 700"
    log_info "Cron diario creado: /etc/cron.daily/seguridad-resumen"
else
    log_skip "Crear /etc/cron.daily/seguridad-resumen"
fi

show_changes_summary

echo ""
log_info "Automatización de seguridad completada"
echo ""
echo "Resumen de cron jobs creados:"
echo "  /etc/cron.daily/aide-check          - Verificación AIDE"
echo "  /etc/cron.daily/zypper-security-update - Parches automáticos"
echo "  /etc/cron.weekly/lynis-audit         - Auditoría lynis"
echo "  /etc/cron.daily/rkhunter-check       - Escaneo rootkits"
echo "  /etc/cron.weekly/verificar-logrotate  - Verificar rotación logs"
echo "  /etc/cron.daily/seguridad-resumen    - Digest diario"
echo ""
echo "Timer systemd:"
echo "  seguridad-notificar.timer            - Notificaciones horarias"
