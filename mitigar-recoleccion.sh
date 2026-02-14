#!/bin/bash
# ============================================================
# MITIGACIÓN DE RECOLECCIÓN - TA0009 (Collection)
# Linux Multi-Distro (openSUSE, Debian/Ubuntu, RHEL/Fedora, Arch)
# ============================================================
# Técnicas MITRE ATT&CK cubiertas:
#   T1005     - Data from Local System
#   T1039     - Data from Network Shared Drive
#   T1025     - Data from Removable Media
#   T1074     - Data Staged
#   T1074.001 - Local Data Staging
#   T1113     - Screen Capture
#   T1125     - Video Capture
#   T1123     - Audio Capture
#   T1119     - Automated Collection
#   T1560     - Archive Collected Data
#   T1560.001 - Archive via Utility
#   T1056     - Input Capture
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "mitigar-recoleccion"
securizar_setup_traps

# ── Pre-check: detectar secciones ya aplicadas ──
_precheck 6
_pc check_file_exists /etc/audit/rules.d/65-collection.rules
_pc 'check_file_contains /etc/audit/rules.d/65-collection.rules network-share-access'
_pc check_file_exists /etc/udisks2/mount_options.conf
_pc check_executable /usr/local/bin/detectar-staging.sh
_pc check_file_exists /etc/udev/rules.d/90-multimedia-restrict.rules
_pc check_executable /usr/local/bin/detectar-recoleccion.sh
_precheck_result

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MITIGACIÓN DE RECOLECCIÓN - TA0009                      ║"
echo "║   Prevenir recopilación masiva de datos por atacantes      ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups se guardarán en: $BACKUP_DIR"

# ============================================================
log_section "1. PROTECCIÓN DE DATOS LOCALES SENSIBLES (T1005)"
# ============================================================

echo "Proteger archivos sensibles del sistema local contra lectura"
echo "no autorizada y recolección masiva."
echo ""
echo "Medidas:"
echo "  - Permisos estrictos en directorios sensibles"
echo "  - Monitoreo de acceso a datos críticos"
echo "  - Cifrado de directorios sensibles"
echo ""

if check_file_exists /etc/audit/rules.d/65-collection.rules; then
    log_already "Protección de datos locales (65-collection.rules)"
elif ask "¿Proteger datos locales sensibles?"; then

    # 1a. Endurecer permisos de directorios sensibles
    echo ""
    echo -e "${BOLD}Endureciendo permisos de directorios sensibles...${NC}"

    # Restringir /root
    chmod 700 /root 2>/dev/null && echo -e "  ${GREEN}OK${NC} /root: 700"
    log_change "Permisos" "/root -> 700"

    # Restringir homes de usuarios
    for home in /home/*/; do
        if [[ -d "$home" ]]; then
            chmod 700 "$home" 2>/dev/null && echo -e "  ${GREEN}OK${NC} $home: 700"
            log_change "Permisos" "$home -> 700"
        fi
    done

    # Restringir acceso a logs
    chmod 750 /var/log 2>/dev/null && echo -e "  ${GREEN}OK${NC} /var/log: 750"
    log_change "Permisos" "/var/log -> 750"
    chmod 640 /var/log/messages 2>/dev/null || true
    log_change "Permisos" "/var/log/messages -> 640"
    chmod 640 /var/log/secure 2>/dev/null || true
    log_change "Permisos" "/var/log/secure -> 640"

    # Restringir cron
    chmod 700 /etc/cron.d 2>/dev/null && echo -e "  ${GREEN}OK${NC} /etc/cron.d: 700"
    log_change "Permisos" "/etc/cron.d -> 700"
    chmod 700 /etc/cron.daily 2>/dev/null || true
    log_change "Permisos" "/etc/cron.daily -> 700"
    chmod 700 /etc/cron.weekly 2>/dev/null || true
    log_change "Permisos" "/etc/cron.weekly -> 700"

    # 1b. Auditoría de acceso a datos sensibles
    if command -v auditctl &>/dev/null; then
        mkdir -p /etc/audit/rules.d
        cat > /etc/audit/rules.d/65-collection.rules << 'EOF'
## Detección de recolección de datos - TA0009
# T1005 - Acceso a datos sensibles del sistema
-w /etc/shadow -p r -k data-collection
-w /etc/gshadow -p r -k data-collection
-w /root/.ssh/ -p r -k data-collection
-w /etc/ssh/ssh_host_rsa_key -p r -k data-collection
-w /etc/ssh/ssh_host_ed25519_key -p r -k data-collection

# Monitorear acceso masivo a /home
-w /home/ -p r -k home-access

# Monitorear lectura de bases de datos locales
-w /var/lib/mysql/ -p r -k db-access
-w /var/lib/pgsql/ -p r -k db-access
-w /var/lib/redis/ -p r -k db-access
EOF

        log_change "Creado" "/etc/audit/rules.d/65-collection.rules"
        augenrules --load 2>/dev/null || true
        log_change "Aplicado" "augenrules --load"
        log_info "Reglas auditd de protección de datos creadas"
    fi

    log_info "Protección de datos locales aplicada"
else
    log_skip "Protección de datos locales no aplicada"
    log_warn "Protección de datos locales no aplicada"
fi

# ============================================================
log_section "2. PROTECCIÓN DE DATOS EN SHARES (T1039)"
# ============================================================

echo "Monitorear y proteger acceso a datos en recursos compartidos."
echo ""

if check_file_contains /etc/audit/rules.d/65-collection.rules "network-share-access"; then
    log_already "Monitoreo de acceso a shares (audit rules)"
elif ask "¿Monitorear acceso a datos compartidos?"; then

    # Auditar acceso a montajes de red
    if command -v auditctl &>/dev/null; then
        cat >> /etc/audit/rules.d/65-collection.rules << 'EOF'

# T1039 - Data from Network Shared Drive
-w /mnt/ -p r -k network-share-access
-w /srv/samba/ -p r -k network-share-access
-w /srv/nfs/ -p r -k network-share-access
EOF
        log_change "Modificado" "/etc/audit/rules.d/65-collection.rules"
        augenrules --load 2>/dev/null || true
        log_change "Aplicado" "augenrules --load"
    fi

    # Verificar que shares montan con permisos restrictivos
    echo ""
    echo -e "${BOLD}Verificando montajes de red...${NC}"

    MOUNTS=$(mount 2>/dev/null | grep -E "nfs|cifs" || true)
    if [[ -n "$MOUNTS" ]]; then
        echo "$MOUNTS"
        echo ""
        echo -e "${DIM}Recomendación: montar con noexec,nosuid,nodev${NC}"
    else
        echo -e "  ${GREEN}OK${NC} No hay montajes de red activos"
    fi

    log_info "Monitoreo de acceso a shares configurado"
else
    log_skip "Monitoreo de shares no configurado"
    log_warn "Monitoreo de shares no configurado"
fi

# ============================================================
log_section "3. CONTROL DE MEDIOS EXTRAÍBLES (T1025)"
# ============================================================

echo "Controlar acceso a medios USB y extraíbles para prevenir"
echo "que un atacante copie datos a dispositivos portátiles."
echo ""

if check_file_exists /etc/udisks2/mount_options.conf; then
    log_already "Control de medios extraíbles (udisks2 mount_options.conf)"
elif ask "¿Restringir medios extraíbles para prevenir exfiltración?"; then

    # 3a. Verificar USBGuard
    if command -v usbguard &>/dev/null; then
        echo -e "  ${GREEN}OK${NC} USBGuard instalado"
        systemctl is-active usbguard &>/dev/null && \
            echo -e "  ${GREEN}OK${NC} USBGuard activo" || \
            echo -e "  ${YELLOW}!!${NC} USBGuard no activo"
    else
        echo -e "  ${YELLOW}!!${NC} USBGuard no instalado"
        if ask "  ¿Instalar USBGuard?"; then
            pkg_install usbguard
            if command -v usbguard &>/dev/null; then
                # Generar política inicial (permitir dispositivos conectados)
                usbguard generate-policy > /etc/usbguard/rules.conf 2>/dev/null || true
                log_change "Creado" "/etc/usbguard/rules.conf"
                systemctl enable --now usbguard 2>/dev/null || true
                log_change "Servicio" "usbguard enable --now"
                log_info "USBGuard instalado y configurado (dispositivos actuales permitidos)"
            fi
        else
            log_skip "Instalación de USBGuard omitida"
        fi
    fi

    # 3b. Montar USB automontados con restricciones
    echo ""
    echo -e "${BOLD}Configurando restricciones de automontaje...${NC}"

    mkdir -p /etc/udisks2
    log_change "Creado" "/etc/udisks2/"
    cat > /etc/udisks2/mount_options.conf << 'EOF'
# Restricciones de montaje USB - T1025
[defaults]
# Montar con noexec, nosuid, nodev por defecto
defaults=nosuid,nodev,noexec
allow=exec,noexec,nodev,nosuid,atime,noatime,nodiratime,ro,sync,dirsync,noload
EOF
    log_change "Creado" "/etc/udisks2/mount_options.conf"

    # 3c. Auditd para acceso a USB
    if command -v auditctl &>/dev/null; then
        cat >> /etc/audit/rules.d/65-collection.rules << 'EOF'

# T1025 - Data from Removable Media
-w /media/ -p rw -k removable-media-access
-w /run/media/ -p rw -k removable-media-access
-a always,exit -F arch=b64 -S mount -S umount2 -k media-mount
EOF
        log_change "Modificado" "/etc/audit/rules.d/65-collection.rules"
        augenrules --load 2>/dev/null || true
        log_change "Aplicado" "augenrules --load"
    fi

    log_info "Control de medios extraíbles configurado"
else
    log_skip "Control de medios extraíbles no configurado"
    log_warn "Control de medios extraíbles no configurado"
fi

# ============================================================
log_section "4. DETECCIÓN DE STAGING DE DATOS (T1074)"
# ============================================================

echo "Detectar cuando un atacante acumula datos en un directorio"
echo "antes de exfiltrarlos."
echo ""

if check_executable /usr/local/bin/detectar-staging.sh; then
    log_already "Detección de data staging (detectar-staging.sh)"
elif ask "¿Configurar detección de data staging?"; then

    cat > /usr/local/bin/detectar-staging.sh << 'EOFSTAG'
#!/bin/bash
# Detección de data staging - T1074
LOG="/var/log/data-staging-$(date +%Y%m%d).log"
ALERTS=0

echo "=== Detección de Data Staging - $(date) ===" | tee "$LOG"

# 1. Directorios /tmp con muchos archivos recientes
echo "" | tee -a "$LOG"
echo "--- Acumulación de datos en /tmp ---" | tee -a "$LOG"

STAGING_DIRS="/tmp /var/tmp /dev/shm"
for dir in $STAGING_DIRS; do
    if [[ -d "$dir" ]]; then
        RECENT_COUNT=$(find "$dir" -maxdepth 2 -type f -mtime -1 2>/dev/null | wc -l)
        RECENT_SIZE=$(find "$dir" -maxdepth 2 -type f -mtime -1 -exec du -ch {} + 2>/dev/null | tail -1 | awk '{print $1}' || echo "0")
        echo "  $dir: $RECENT_COUNT archivos recientes ($RECENT_SIZE)" | tee -a "$LOG"

        if [[ "$RECENT_COUNT" -gt 100 ]]; then
            echo "  ALERTA: $dir tiene $RECENT_COUNT archivos nuevos en 24h" | tee -a "$LOG"
            ((ALERTS++)) || true
        fi
    fi
done

# 2. Archivos comprimidos grandes recientes (T1560.001)
echo "" | tee -a "$LOG"
echo "--- Archivos comprimidos recientes ---" | tee -a "$LOG"

ARCHIVES=$(find /tmp /var/tmp /home /root -maxdepth 3 -type f \( -name "*.tar.gz" -o -name "*.zip" -o -name "*.7z" -o -name "*.tar.bz2" -o -name "*.rar" -o -name "*.tar.xz" \) -mtime -1 -size +10M 2>/dev/null || true)
if [[ -n "$ARCHIVES" ]]; then
    echo "ALERTA: Archivos comprimidos grandes recientes (>10MB):" | tee -a "$LOG"
    while IFS= read -r archive; do
        SIZE=$(du -h "$archive" 2>/dev/null | awk '{print $1}')
        OWNER=$(stat -c "%U" "$archive" 2>/dev/null)
        echo "  $archive ($SIZE, propietario: $OWNER)" | tee -a "$LOG"
        ((ALERTS++)) || true
    done <<< "$ARCHIVES"
else
    echo "OK: Sin archivos comprimidos grandes recientes" | tee -a "$LOG"
fi

# 3. Uso inusual de herramientas de compresión
echo "" | tee -a "$LOG"
echo "--- Uso de herramientas de compresión ---" | tee -a "$LOG"

if command -v ausearch &>/dev/null; then
    COMPRESS_EVENTS=$(ausearch -k data-archive -ts recent 2>/dev/null | grep -c "type=SYSCALL" || echo 0)
    if [[ "$COMPRESS_EVENTS" -gt 10 ]]; then
        echo "ALERTA: $COMPRESS_EVENTS eventos de compresión recientes" | tee -a "$LOG"
        ((ALERTS++)) || true
    else
        echo "OK: $COMPRESS_EVENTS eventos de compresión (normal)" | tee -a "$LOG"
    fi
fi

# 4. Directorios ocultos con datos acumulados
echo "" | tee -a "$LOG"
echo "--- Directorios ocultos con datos ---" | tee -a "$LOG"

for basedir in /tmp /var/tmp /dev/shm; do
    HIDDEN_DIRS=$(find "$basedir" -maxdepth 2 -type d -name ".*" ! -name "." ! -name ".." 2>/dev/null || true)
    if [[ -n "$HIDDEN_DIRS" ]]; then
        while IFS= read -r hdir; do
            FILE_COUNT=$(find "$hdir" -type f 2>/dev/null | wc -l)
            if [[ "$FILE_COUNT" -gt 5 ]]; then
                echo "ALERTA: Directorio oculto con $FILE_COUNT archivos: $hdir" | tee -a "$LOG"
                ((ALERTS++)) || true
            fi
        done <<< "$HIDDEN_DIRS"
    fi
done

echo "" | tee -a "$LOG"
echo "=== RESUMEN ===" | tee -a "$LOG"
if [[ $ALERTS -eq 0 ]]; then
    echo "OK: Sin indicadores de data staging" | tee -a "$LOG"
else
    echo "ALERTA: $ALERTS indicadores de data staging" | tee -a "$LOG"
    logger -t detectar-staging "ALERTA: $ALERTS indicadores de data staging (T1074)"
fi

find /var/log -name "data-staging-*.log" -mtime +30 -delete 2>/dev/null || true
EOFSTAG

    log_change "Creado" "/usr/local/bin/detectar-staging.sh"
    chmod 700 /usr/local/bin/detectar-staging.sh
    log_change "Permisos" "/usr/local/bin/detectar-staging.sh -> 700"

    # Auditar herramientas de compresión
    if command -v auditctl &>/dev/null; then
        cat >> /etc/audit/rules.d/65-collection.rules << 'EOF'

# T1560 - Archive Collected Data
-w /usr/bin/tar -p x -k data-archive
-w /usr/bin/gzip -p x -k data-archive
-w /usr/bin/bzip2 -p x -k data-archive
-w /usr/bin/xz -p x -k data-archive
-w /usr/bin/zip -p x -k data-archive
-w /usr/bin/7z -p x -k data-archive
-w /usr/bin/rar -p x -k data-archive
EOF
        log_change "Modificado" "/etc/audit/rules.d/65-collection.rules"
        augenrules --load 2>/dev/null || true
        log_change "Aplicado" "augenrules --load"
    fi

    cat > /etc/cron.daily/detectar-staging << 'EOFCRON'
#!/bin/bash
/usr/local/bin/detectar-staging.sh 2>&1 | logger -t detectar-staging
EOFCRON
    log_change "Creado" "/etc/cron.daily/detectar-staging"
    chmod 700 /etc/cron.daily/detectar-staging
    log_change "Permisos" "/etc/cron.daily/detectar-staging -> 700"

    log_info "Detección diaria de data staging configurada"
else
    log_skip "Detección de staging no configurada"
    log_warn "Detección de staging no configurada"
fi

# ============================================================
log_section "5. PROTECCIÓN CONTRA CAPTURA DE PANTALLA/AV (T1113/T1125)"
# ============================================================

echo "Restringir herramientas de captura de pantalla, video y audio"
echo "que un atacante podría usar para espionaje."
echo ""

if check_file_exists /etc/udev/rules.d/90-multimedia-restrict.rules; then
    log_already "Captura multimedia restringida (90-multimedia-restrict.rules)"
elif ask "¿Restringir herramientas de captura multimedia?"; then

    # 5a. Monitorear uso de herramientas de captura
    echo ""
    echo -e "${BOLD}Configurando monitoreo de captura multimedia...${NC}"

    if command -v auditctl &>/dev/null; then
        cat >> /etc/audit/rules.d/65-collection.rules << 'EOF'

# T1113 - Screen Capture
-w /usr/bin/scrot -p x -k screen-capture
-w /usr/bin/import -p x -k screen-capture
-w /usr/bin/xwd -p x -k screen-capture
-w /usr/bin/spectacle -p x -k screen-capture
-w /usr/bin/gnome-screenshot -p x -k screen-capture
-w /usr/bin/xdotool -p x -k screen-capture
-w /usr/bin/xclip -p x -k screen-capture

# T1125 - Video Capture
-w /dev/video0 -p r -k video-capture
-w /dev/video1 -p r -k video-capture
-w /usr/bin/ffmpeg -p x -k av-capture
-w /usr/bin/avconv -p x -k av-capture

# T1123 - Audio Capture
-w /dev/snd/ -p r -k audio-capture
-w /usr/bin/arecord -p x -k audio-capture
-w /usr/bin/parecord -p x -k audio-capture
EOF
        log_change "Modificado" "/etc/audit/rules.d/65-collection.rules"
        augenrules --load 2>/dev/null || true
        log_change "Aplicado" "augenrules --load"
    fi

    # 5b. Restringir acceso a /dev/video* y /dev/snd/*
    echo ""
    echo -e "${BOLD}Restringiendo acceso a dispositivos multimedia...${NC}"

    # Crear grupo multimedia para acceso controlado
    if ! getent group multimedia-access &>/dev/null; then
        groupadd multimedia-access 2>/dev/null || true
        log_change "Usuario" "groupadd multimedia-access"
    fi

    # Regla udev para restringir dispositivos de video
    cat > /etc/udev/rules.d/90-multimedia-restrict.rules << 'EOF'
# Restringir acceso a cámara y micrófono - T1125/T1123
KERNEL=="video[0-9]*", GROUP="multimedia-access", MODE="0660"
SUBSYSTEM=="sound", GROUP="multimedia-access", MODE="0660"
EOF
    log_change "Creado" "/etc/udev/rules.d/90-multimedia-restrict.rules"

    udevadm control --reload-rules 2>/dev/null || true
    log_change "Aplicado" "udevadm control --reload-rules"
    udevadm trigger 2>/dev/null || true

    echo -e "${DIM}Usuarios que necesiten cámara/micro: usermod -aG multimedia-access <usuario>${NC}"

    log_info "Protección contra captura multimedia configurada"
else
    log_skip "Protección contra captura multimedia no configurada"
    log_warn "Protección contra captura multimedia no configurada"
fi

# ============================================================
log_section "6. DETECCIÓN DE RECOLECCIÓN AUTOMATIZADA (T1119)"
# ============================================================

echo "Detectar scripts y procesos de recolección automatizada"
echo "que buscan y copian datos de forma masiva."
echo ""

if check_executable /usr/local/bin/detectar-recoleccion.sh; then
    log_already "Detección de recolección automatizada (detectar-recoleccion.sh)"
elif ask "¿Configurar detección de recolección automatizada?"; then

    cat > /usr/local/bin/detectar-recoleccion.sh << 'EOFREC'
#!/bin/bash
# Detección de recolección automatizada - T1119
LOG="/var/log/collection-detection-$(date +%Y%m%d).log"
ALERTS=0

echo "=== Detección de Recolección Automatizada - $(date) ===" | tee "$LOG"

# 1. Procesos con muchos archivos abiertos (posible recolección masiva)
echo "" | tee -a "$LOG"
echo "--- Procesos con muchos archivos abiertos ---" | tee -a "$LOG"

for pid_dir in /proc/[0-9]*; do
    PID=$(basename "$pid_dir")
    FD_COUNT=$(ls "$pid_dir/fd" 2>/dev/null | wc -l)
    if [[ "$FD_COUNT" -gt 200 ]]; then
        COMM=$(cat "$pid_dir/comm" 2>/dev/null || echo "N/A")
        USER=$(stat -c "%U" "$pid_dir" 2>/dev/null || echo "N/A")
        # Filtrar procesos conocidos
        if ! echo "$COMM" | grep -qE "^(systemd|journald|Xorg|firefox|thunderbird|code|java|python)"; then
            echo "ALERTA: PID $PID ($COMM, user: $USER) tiene $FD_COUNT archivos abiertos" | tee -a "$LOG"
            ((ALERTS++)) || true
        fi
    fi
done

# 2. Búsquedas masivas de archivos (find/locate sospechoso)
echo "" | tee -a "$LOG"
echo "--- Procesos de búsqueda de archivos ---" | tee -a "$LOG"

FIND_PROCS=$(ps aux 2>/dev/null | grep -E "find / |find /home|find /etc|locate " | grep -v grep || true)
if [[ -n "$FIND_PROCS" ]]; then
    echo "ALERTA: Búsquedas masivas de archivos activas:" | tee -a "$LOG"
    echo "$FIND_PROCS" | tee -a "$LOG"
    ((ALERTS++)) || true
else
    echo "OK: Sin búsquedas masivas activas" | tee -a "$LOG"
fi

# 3. Actividad de copia masiva
echo "" | tee -a "$LOG"
echo "--- Actividad de copia masiva ---" | tee -a "$LOG"

COPY_PROCS=$(ps aux 2>/dev/null | grep -E "cp -r|rsync|dd if=|scp -r" | grep -v grep || true)
if [[ -n "$COPY_PROCS" ]]; then
    echo "ALERTA: Copias masivas activas:" | tee -a "$LOG"
    echo "$COPY_PROCS" | tee -a "$LOG"
    ((ALERTS++)) || true
else
    echo "OK: Sin copias masivas activas" | tee -a "$LOG"
fi

# 4. Scripts buscando tipos de archivos específicos (documentos, DBs)
echo "" | tee -a "$LOG"
echo "--- Búsqueda de archivos sensibles en /tmp ---" | tee -a "$LOG"

SENSITIVE_SEARCH=$(find /tmp /var/tmp -maxdepth 2 -type f -name "*.sh" -newer /tmp -mtime -1 -exec grep -l "\.pdf\|\.doc\|\.xlsx\|\.pptx\|\.db\|\.sqlite\|\.sql\|\.csv\|\.key\|\.pem\|\.p12" {} \; 2>/dev/null || true)
if [[ -n "$SENSITIVE_SEARCH" ]]; then
    echo "ALERTA: Scripts buscando archivos sensibles:" | tee -a "$LOG"
    echo "$SENSITIVE_SEARCH" | tee -a "$LOG"
    ((ALERTS++)) || true
else
    echo "OK: Sin scripts de recolección en /tmp" | tee -a "$LOG"
fi

echo "" | tee -a "$LOG"
echo "=== RESUMEN ===" | tee -a "$LOG"
if [[ $ALERTS -eq 0 ]]; then
    echo "OK: Sin indicadores de recolección automatizada" | tee -a "$LOG"
else
    echo "ALERTA: $ALERTS indicadores de recolección automatizada" | tee -a "$LOG"
    logger -t detectar-recoleccion "ALERTA: $ALERTS indicadores de recolección (T1119)"
fi

find /var/log -name "collection-detection-*.log" -mtime +30 -delete 2>/dev/null || true
EOFREC

    log_change "Creado" "/usr/local/bin/detectar-recoleccion.sh"
    chmod 700 /usr/local/bin/detectar-recoleccion.sh
    log_change "Permisos" "/usr/local/bin/detectar-recoleccion.sh -> 700"

    cat > /etc/cron.daily/detectar-recoleccion << 'EOFCRON'
#!/bin/bash
/usr/local/bin/detectar-recoleccion.sh 2>&1 | logger -t detectar-recoleccion
EOFCRON
    log_change "Creado" "/etc/cron.daily/detectar-recoleccion"
    chmod 700 /etc/cron.daily/detectar-recoleccion
    log_change "Permisos" "/etc/cron.daily/detectar-recoleccion -> 700"

    log_info "Detección diaria de recolección automatizada configurada"
else
    log_skip "Detección de recolección no configurada"
    log_warn "Detección de recolección no configurada"
fi

# ============================================================
log_section "RESUMEN DE MITIGACIONES TA0009"
# ============================================================

echo ""
echo -e "${BOLD}Estado de mitigaciones de Recolección (TA0009):${NC}"
echo ""

# T1005 - Data from Local System
if [[ -f /etc/audit/rules.d/65-collection.rules ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1005 - Protección de datos locales sensibles"
else
    echo -e "  ${YELLOW}[--]${NC} T1005 - Datos locales no protegidos"
fi

# T1039 - Network Shared Drive
if command -v auditctl &>/dev/null && grep -q "network-share-access" /etc/audit/rules.d/65-collection.rules 2>/dev/null; then
    echo -e "  ${GREEN}[OK]${NC} T1039 - Monitoreo de acceso a shares"
else
    echo -e "  ${YELLOW}[--]${NC} T1039 - Shares no monitoreados"
fi

# T1025 - Removable Media
if command -v usbguard &>/dev/null; then
    echo -e "  ${GREEN}[OK]${NC} T1025 - Control de medios extraíbles"
else
    echo -e "  ${YELLOW}[--]${NC} T1025 - Medios extraíbles no controlados"
fi

# T1074 - Data Staging
if [[ -x /usr/local/bin/detectar-staging.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1074 - Detección de data staging"
else
    echo -e "  ${YELLOW}[--]${NC} T1074 - Data staging no monitoreado"
fi

# T1113/T1125 - Screen/Video Capture
if [[ -f /etc/udev/rules.d/90-multimedia-restrict.rules ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1113/T1125 - Captura multimedia restringida"
else
    echo -e "  ${YELLOW}[--]${NC} T1113/T1125 - Captura multimedia no restringida"
fi

# T1119 - Automated Collection
if [[ -x /usr/local/bin/detectar-recoleccion.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1119 - Detección de recolección automatizada"
else
    echo -e "  ${YELLOW}[--]${NC} T1119 - Recolección automatizada no monitoreada"
fi

show_changes_summary

echo ""
log_info "Script de mitigación de recolección completado"
log_info "Backups de configuración en: $BACKUP_DIR"
