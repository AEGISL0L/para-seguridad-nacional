#!/bin/bash
# ============================================================
# MITIGACIÓN DE IMPACTO - TA0040
# Linux Multi-Distro (openSUSE, Debian/Ubuntu, RHEL/Fedora, Arch)
# ============================================================
# Técnicas MITRE ATT&CK cubiertas:
#   T1486 - Data Encrypted for Impact (Ransomware)
#   T1490 - Inhibit System Recovery
#   T1561 - Disk Wipe
#   T1485 - Data Destruction (refuerzo)
#
# Mitigaciones implementadas:
#   M1053 - Data Backup (offsite automático, protección snapshots)
#   M1049 - Antivirus/Antimalware (ClamAV anti-ransomware)
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "mitigar-impacto"
securizar_setup_traps
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MITIGACIÓN DE IMPACTO - TA0040                          ║"
echo "║   Proteger contra ransomware, destrucción y disk wipe      ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups se guardarán en: $BACKUP_DIR"

# ============================================================
log_section "1. BACKUPS OFFSITE AUTOMÁTICOS (T1486/T1561 - M1053)"
# ============================================================

echo "Configura backups automáticos a destinos offsite (disco secundario,"
echo "USB montado, o servidor remoto vía rsync/SSH)."
echo ""
echo "Esto protege contra:"
echo "  - T1486: Ransomware que cifra datos locales"
echo "  - T1561: Disk Wipe que destruye el disco principal"
echo "  - T1485: Destrucción de datos"
echo ""

if ask "¿Configurar sistema de backups offsite automáticos?"; then

    # Crear directorio de configuración
    mkdir -p /etc/backup-offsite
    log_change "Creado" "/etc/backup-offsite/"

    # Preguntar tipo de destino
    echo ""
    echo -e "${BOLD}Tipo de destino para backups:${NC}"
    echo "  1) Directorio local/disco secundario (ej: /mnt/backup)"
    echo "  2) Servidor remoto vía SSH/rsync (ej: user@server:/backup)"
    echo ""
    read -p "Selecciona [1/2]: " backup_tipo

    BACKUP_DEST=""
    BACKUP_TYPE="local"

    case "$backup_tipo" in
        1)
            read -p "Ruta del directorio destino (ej: /mnt/backup-offsite): " BACKUP_DEST
            BACKUP_TYPE="local"
            if [[ -z "$BACKUP_DEST" ]]; then
                BACKUP_DEST="/mnt/backup-offsite"
            fi
            mkdir -p "$BACKUP_DEST" 2>/dev/null || true
            ;;
        2)
            read -p "Destino SSH (ej: backupuser@192.168.1.100:/backups): " BACKUP_DEST
            BACKUP_TYPE="remote"
            if [[ -z "$BACKUP_DEST" ]]; then
                log_warn "No se proporcionó destino remoto, usando /mnt/backup-offsite local"
                BACKUP_DEST="/mnt/backup-offsite"
                BACKUP_TYPE="local"
                mkdir -p "$BACKUP_DEST" 2>/dev/null || true
            fi
            ;;
        *)
            BACKUP_DEST="/mnt/backup-offsite"
            BACKUP_TYPE="local"
            mkdir -p "$BACKUP_DEST" 2>/dev/null || true
            ;;
    esac

    # Guardar configuración
    cat > /etc/backup-offsite/config << EOFCFG
# Configuración de backups offsite
# Generado por mitigar-impacto.sh - $(date)
BACKUP_DEST="$BACKUP_DEST"
BACKUP_TYPE="$BACKUP_TYPE"

# Directorios a respaldar
BACKUP_SOURCES="/etc /home /root /var/log /var/spool/cron $GRUB_CFG_DIR"

# Retención: número de backups a mantener
BACKUP_RETENTION=7

# Excluir patrones
BACKUP_EXCLUDE="*.tmp *.cache .cache/ .local/share/Trash/ lost+found/"
EOFCFG

    log_change "Creado" "/etc/backup-offsite/config"
    chmod 600 /etc/backup-offsite/config
    log_change "Permisos" "/etc/backup-offsite/config -> 600"
    log_info "Configuración guardada en /etc/backup-offsite/config"

    # Crear script de backup offsite
    cat > /usr/local/bin/backup-offsite.sh << 'EOFBACKUP'
#!/bin/bash
# ============================================================
# Backup offsite automático - Anti-Ransomware/Disk Wipe
# MITRE: T1486/T1561 - M1053
# ============================================================

set -euo pipefail

CONFIG="/etc/backup-offsite/config"
if [[ ! -f "$CONFIG" ]]; then
    echo "ERROR: No existe $CONFIG" >&2
    exit 1
fi

source "$CONFIG"

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
LOG="/var/log/backup-offsite-${TIMESTAMP}.log"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG"; }

log "=== Inicio backup offsite ==="
log "Destino: $BACKUP_DEST (tipo: $BACKUP_TYPE)"

# Verificar destino accesible
if [[ "$BACKUP_TYPE" == "local" ]]; then
    if [[ ! -d "$BACKUP_DEST" ]]; then
        log "ERROR: Directorio destino no accesible: $BACKUP_DEST"
        logger -t backup-offsite "ERROR: destino no accesible $BACKUP_DEST"
        exit 1
    fi
elif [[ "$BACKUP_TYPE" == "remote" ]]; then
    REMOTE_HOST="${BACKUP_DEST%%:*}"
    if ! ssh -o ConnectTimeout=10 -o BatchMode=yes "$REMOTE_HOST" true 2>/dev/null; then
        log "ERROR: No se puede conectar al servidor remoto: $REMOTE_HOST"
        logger -t backup-offsite "ERROR: servidor remoto no accesible $REMOTE_HOST"
        exit 1
    fi
fi

# Construir opciones de exclusión
EXCLUDE_OPTS=""
for pattern in $BACKUP_EXCLUDE; do
    EXCLUDE_OPTS="$EXCLUDE_OPTS --exclude=$pattern"
done

# Directorio de este backup
if [[ "$BACKUP_TYPE" == "local" ]]; then
    DEST_DIR="${BACKUP_DEST}/backup-${TIMESTAMP}"
    LATEST_LINK="${BACKUP_DEST}/latest"
else
    DEST_DIR="${BACKUP_DEST}/backup-${TIMESTAMP}"
    LATEST_LINK="${BACKUP_DEST}/latest"
fi

# Ejecutar rsync con link-dest para backups incrementales
ERRORS=0
for src_dir in $BACKUP_SOURCES; do
    if [[ ! -d "$src_dir" ]]; then
        log "WARN: Directorio no existe, omitiendo: $src_dir"
        continue
    fi

    log "Respaldando: $src_dir"

    LINK_DEST_OPT=""
    if [[ "$BACKUP_TYPE" == "local" ]] && [[ -L "$LATEST_LINK" ]]; then
        LINK_DEST_OPT="--link-dest=${LATEST_LINK}${src_dir}"
    fi

    if rsync -aAX --delete \
        $EXCLUDE_OPTS \
        $LINK_DEST_OPT \
        "$src_dir/" \
        "${DEST_DIR}${src_dir}/" \
        >> "$LOG" 2>&1; then
        log "OK: $src_dir respaldado"
    else
        log "ERROR: Falló backup de $src_dir"
        ((ERRORS++)) || true
    fi
done

# Actualizar enlace latest (solo local)
if [[ "$BACKUP_TYPE" == "local" ]]; then
    ln -sfn "$DEST_DIR" "$LATEST_LINK"
fi

# Rotación: eliminar backups antiguos
if [[ "$BACKUP_TYPE" == "local" ]] && [[ -d "$BACKUP_DEST" ]]; then
    BACKUP_COUNT=$(find "$BACKUP_DEST" -maxdepth 1 -name "backup-*" -type d | wc -l)
    if [[ "$BACKUP_COUNT" -gt "$BACKUP_RETENTION" ]]; then
        DELETE_COUNT=$((BACKUP_COUNT - BACKUP_RETENTION))
        log "Rotación: eliminando $DELETE_COUNT backups antiguos (retención: $BACKUP_RETENTION)"
        find "$BACKUP_DEST" -maxdepth 1 -name "backup-*" -type d | sort | head -n "$DELETE_COUNT" | while read -r old_backup; do
            log "Eliminando: $old_backup"
            rm -rf "$old_backup"
        done
    fi
fi

# Verificar integridad básica
BACKUP_SIZE=$(du -sh "$DEST_DIR" 2>/dev/null | awk '{print $1}' || echo "?")
log "Tamaño del backup: $BACKUP_SIZE"

if [[ $ERRORS -eq 0 ]]; then
    log "=== Backup completado exitosamente ==="
    logger -t backup-offsite "Backup exitoso en $DEST_DIR ($BACKUP_SIZE)"
else
    log "=== Backup completado con $ERRORS errores ==="
    logger -t backup-offsite "Backup con errores ($ERRORS) en $DEST_DIR"
    echo "ALERTA: Backup offsite con errores" >> /var/log/security-alerts.log
fi

# Limpiar logs antiguos (>60 días)
find /var/log -name "backup-offsite-*.log" -mtime +60 -delete 2>/dev/null || true
EOFBACKUP

    log_change "Creado" "/usr/local/bin/backup-offsite.sh"
    chmod 700 /usr/local/bin/backup-offsite.sh
    log_change "Permisos" "/usr/local/bin/backup-offsite.sh -> 700"
    log_info "Script de backup creado: /usr/local/bin/backup-offsite.sh"

    # Crear cron job diario
    cat > /etc/cron.daily/backup-offsite << 'EOFCRON'
#!/bin/bash
# Backup offsite diario - Anti-Ransomware (T1486/T1561 - M1053)
/usr/local/bin/backup-offsite.sh 2>&1 | logger -t backup-offsite
EOFCRON

    log_change "Creado" "/etc/cron.daily/backup-offsite"
    chmod 700 /etc/cron.daily/backup-offsite
    log_change "Permisos" "/etc/cron.daily/backup-offsite -> 700"
    log_info "Cron diario creado: /etc/cron.daily/backup-offsite"
    log_info "Destino configurado: $BACKUP_DEST ($BACKUP_TYPE)"

    echo ""
    echo -e "${DIM}Uso manual: /usr/local/bin/backup-offsite.sh${NC}"
    echo -e "${DIM}Logs en: /var/log/backup-offsite-*.log${NC}"
    echo -e "${DIM}Configuración: /etc/backup-offsite/config${NC}"
else
    log_skip "Backups offsite no configurados"
    log_warn "Backups offsite no configurados"
fi

# ============================================================
log_section "2. CLAMAV ANTI-RANSOMWARE (T1486 - M1049)"
# ============================================================

echo "Configura ClamAV con detección especializada de ransomware:"
echo "  - Firmas adicionales para ransomware conocido"
echo "  - Detección de extensiones típicas de ransomware"
echo "  - Monitoreo de cifrado masivo de archivos"
echo ""

if ask "¿Configurar ClamAV con protección anti-ransomware?"; then

    # Verificar/instalar ClamAV
    if ! command -v clamscan &>/dev/null; then
        log_info "Instalando ClamAV..."
        pkg_install clamav || {
            log_error "No se pudo instalar ClamAV"
            log_warn "Omitiendo configuración anti-ransomware"
        }
    fi

    if command -v clamscan &>/dev/null; then

        # Asegurar que freshclam y clamd estén activos
        systemctl enable --now freshclam.service 2>/dev/null || systemctl enable --now clamav-freshclam.service 2>/dev/null || true
        log_change "Servicio" "freshclam enable --now"

        # Crear directorio para firmas personalizadas
        mkdir -p /var/lib/clamav/custom
        log_change "Creado" "/var/lib/clamav/custom/"
        mkdir -p /var/lib/clamav/quarantine
        log_change "Creado" "/var/lib/clamav/quarantine/"
        chmod 700 /var/lib/clamav/quarantine
        log_change "Permisos" "/var/lib/clamav/quarantine -> 700"

        # Crear base de datos de firmas anti-ransomware personalizada
        cat > /var/lib/clamav/custom/ransomware-signatures.yar << 'EOFYAR'
// ============================================================
// Firmas YARA anti-ransomware para ClamAV
// MITRE: T1486 - Data Encrypted for Impact
// ============================================================

rule RansomNote_Generic
{
    meta:
        description = "Detecta notas de rescate genéricas"
        mitre = "T1486"
    strings:
        $s1 = "your files have been encrypted" nocase
        $s2 = "your files are encrypted" nocase
        $s3 = "decrypt your files" nocase
        $s4 = "bitcoin" nocase
        $s5 = "pay the ransom" nocase
        $s6 = "all your files" nocase
        $s7 = "send bitcoin" nocase
        $s8 = "recover your files" nocase
        $s9 = "tus archivos han sido cifrados" nocase
        $s10 = "recuperar tus archivos" nocase
    condition:
        3 of them
}

rule Ransomware_Dropper_Script
{
    meta:
        description = "Detecta scripts sospechosos de ransomware"
        mitre = "T1486"
    strings:
        $encrypt1 = "openssl enc -aes" nocase
        $encrypt2 = "gpg --symmetric" nocase
        $encrypt3 = "gpg -c" nocase
        $loop1 = "for f in" nocase
        $loop2 = "find / " nocase
        $loop3 = "find /home" nocase
        $ext1 = ".encrypted"
        $ext2 = ".locked"
        $ext3 = ".crypto"
        $del1 = "shred "
        $del2 = "rm -rf /"
    condition:
        (any of ($encrypt*)) and (any of ($loop*)) and (any of ($ext*) or any of ($del*))
}
EOFYAR

        log_change "Creado" "/var/lib/clamav/custom/ransomware-signatures.yar"
        log_info "Firmas YARA anti-ransomware creadas"

        # Script de escaneo anti-ransomware
        cat > /usr/local/bin/clamav-antiransomware.sh << 'EOFRANSOM'
#!/bin/bash
# ============================================================
# ClamAV Anti-Ransomware Scanner
# MITRE: T1486 - M1049 Antivirus/Antimalware
# ============================================================

set -euo pipefail

QUARANTINE="/var/lib/clamav/quarantine"
LOG="/var/log/clamav-ransomware-$(date +%Y%m%d-%H%M%S).log"
ALERT_LOG="/var/log/security-alerts.log"

echo "=== ClamAV Anti-Ransomware Scan - $(date) ===" | tee "$LOG"

# Actualizar firmas
echo "Actualizando firmas ClamAV..." | tee -a "$LOG"
freshclam --quiet 2>/dev/null || true

# Extensiones típicas de ransomware
RANSOM_EXTENSIONS=(
    ".encrypted" ".locked" ".crypto" ".crypt" ".enc"
    ".locky" ".zepto" ".cerber" ".cerber3" ".crypted"
    ".crinf" ".r5a" ".XRNT" ".XTBL" ".aaa"
    ".abc" ".xyz" ".zzz" ".micro" ".vvv"
    ".ecc" ".ezz" ".exx" ".fff" ".ttt"
    ".xxx" ".bleep" ".wncry" ".wcry" ".wncryt"
    ".WNCRY" ".onion" ".dharma" ".wallet" ".arena"
    ".bip" ".gamma" ".java" ".adobe" ".combo"
)

# 1. Escaneo ClamAV con firmas personalizadas
echo "" | tee -a "$LOG"
echo "--- Escaneo ClamAV en /home /tmp /var/tmp /root ---" | tee -a "$LOG"
SCAN_DIRS="/home /tmp /var/tmp /root"

INFECTED=0
for dir in $SCAN_DIRS; do
    if [[ -d "$dir" ]]; then
        echo "Escaneando: $dir" | tee -a "$LOG"
        RESULT=$(clamscan -r --quiet --infected \
            --move="$QUARANTINE" \
            --log="$LOG" \
            "$dir" 2>&1) || true
        COUNT=$(echo "$RESULT" | grep -c "FOUND" 2>/dev/null || echo 0)
        INFECTED=$((INFECTED + COUNT))
    fi
done

# 2. Buscar extensiones de ransomware
echo "" | tee -a "$LOG"
echo "--- Buscando extensiones de ransomware ---" | tee -a "$LOG"
RANSOM_FOUND=0

for ext in "${RANSOM_EXTENSIONS[@]}"; do
    FILES=$(find /home /root /tmp /var/tmp -name "*${ext}" -type f 2>/dev/null | head -20)
    if [[ -n "$FILES" ]]; then
        echo "ALERTA: Extensión ransomware detectada: ${ext}" | tee -a "$LOG"
        echo "$FILES" | tee -a "$LOG"
        RANSOM_FOUND=$((RANSOM_FOUND + 1))
    fi
done

# 3. Buscar notas de rescate
echo "" | tee -a "$LOG"
echo "--- Buscando notas de rescate ---" | tee -a "$LOG"
RANSOM_NOTES=(
    "DECRYPT_INSTRUCTION*" "HOW_TO_DECRYPT*" "HELP_DECRYPT*"
    "README_FOR_DECRYPT*" "RECOVERY_FILE*" "DECRYPT_FILES*"
    "YOUR_FILES*" "_RECOVERY_*" "HELP_YOUR_FILES*"
    "HOW_TO_RECOVER*" "_readme.txt" "COMO_RECUPERAR*"
)

NOTES_FOUND=0
for pattern in "${RANSOM_NOTES[@]}"; do
    FILES=$(find /home /root /tmp -name "$pattern" -type f 2>/dev/null | head -10)
    if [[ -n "$FILES" ]]; then
        echo "ALERTA: Posible nota de rescate: $pattern" | tee -a "$LOG"
        echo "$FILES" | tee -a "$LOG"
        NOTES_FOUND=$((NOTES_FOUND + 1))
    fi
done

# Resumen
echo "" | tee -a "$LOG"
echo "=== RESUMEN ===" | tee -a "$LOG"
echo "Archivos infectados ClamAV: $INFECTED" | tee -a "$LOG"
echo "Extensiones ransomware encontradas: $RANSOM_FOUND" | tee -a "$LOG"
echo "Notas de rescate encontradas: $NOTES_FOUND" | tee -a "$LOG"

TOTAL_ALERTS=$((INFECTED + RANSOM_FOUND + NOTES_FOUND))
if [[ $TOTAL_ALERTS -gt 0 ]]; then
    echo "ALERTA CRÍTICA: Posible actividad de ransomware detectada ($TOTAL_ALERTS indicadores)" | tee -a "$LOG"
    echo "$(date): RANSOMWARE - $TOTAL_ALERTS indicadores detectados" >> "$ALERT_LOG"
    logger -t clamav-antiransomware "ALERTA: $TOTAL_ALERTS indicadores de ransomware detectados"
else
    echo "OK: No se detectaron indicadores de ransomware" | tee -a "$LOG"
fi

echo "" | tee -a "$LOG"
echo "Log: $LOG" | tee -a "$LOG"

# Limpiar logs antiguos (>30 días)
find /var/log -name "clamav-ransomware-*.log" -mtime +30 -delete 2>/dev/null || true
EOFRANSOM

        log_change "Creado" "/usr/local/bin/clamav-antiransomware.sh"
        chmod 700 /usr/local/bin/clamav-antiransomware.sh
        log_change "Permisos" "/usr/local/bin/clamav-antiransomware.sh -> 700"
        log_info "Script anti-ransomware creado: /usr/local/bin/clamav-antiransomware.sh"

        # Cron job semanal anti-ransomware
        cat > /etc/cron.weekly/clamav-antiransomware << 'EOFCRONAV'
#!/bin/bash
# Escaneo semanal anti-ransomware (T1486 - M1049)
/usr/local/bin/clamav-antiransomware.sh 2>&1 | logger -t clamav-antiransomware
EOFCRONAV

        log_change "Creado" "/etc/cron.weekly/clamav-antiransomware"
        chmod 700 /etc/cron.weekly/clamav-antiransomware
        log_change "Permisos" "/etc/cron.weekly/clamav-antiransomware -> 700"
        log_info "Cron semanal anti-ransomware creado: /etc/cron.weekly/clamav-antiransomware"

        echo ""
        echo -e "${DIM}Uso manual: /usr/local/bin/clamav-antiransomware.sh${NC}"
    fi
else
    log_skip "ClamAV anti-ransomware no configurado"
    log_warn "ClamAV anti-ransomware no configurado"
fi

# ============================================================
log_section "3. PROTECCIÓN DE SNAPSHOTS Y BACKUPS (T1490 - M1053)"
# ============================================================

echo "Protege los backups y snapshots contra modificación o eliminación"
echo "por un atacante que intenta inhibir la recuperación del sistema."
echo ""
echo "Medidas:"
echo "  - Directorio de backups con permisos restrictivos"
echo "  - Verificación de integridad de backups con checksums"
echo "  - Alertas si se detecta manipulación de backups"
echo "  - Protección de snapshots de Snapper (si existe)"
echo ""

if ask "¿Configurar protección de snapshots y backups?"; then

    # Proteger directorio de backups del hardening
    BACKUP_DIRS_TO_PROTECT=(
        "/root/hardening-backup-*"
        "/root/mitigar-*"
        "/mnt/backup-offsite"
    )

    echo ""
    echo -e "${BOLD}Protegiendo directorios de backups existentes:${NC}"

    for pattern in "${BACKUP_DIRS_TO_PROTECT[@]}"; do
        for dir in $pattern; do
            if [[ -d "$dir" ]]; then
                chmod 700 "$dir"
                log_change "Permisos" "$dir -> 700"
                chown root:root "$dir"
                log_change "Permisos" "$dir -> root:root"
                echo -e "  ${GREEN}●${NC} Protegido: $dir (700, root:root)"
            fi
        done
    done

    # Proteger snapshots de Snapper si existe
    if command -v snapper &>/dev/null; then
        echo ""
        echo -e "${BOLD}Snapper detectado - Protegiendo snapshots:${NC}"

        # Verificar configuración de Snapper
        SNAPPER_CONFIGS=$(snapper list-configs 2>/dev/null | tail -n +3 | awk '{print $1}') || true

        if [[ -n "$SNAPPER_CONFIGS" ]]; then
            for config in $SNAPPER_CONFIGS; do
                echo -e "  ${GREEN}●${NC} Configuración Snapper: $config"

                # Asegurar que el directorio de snapshots tenga permisos correctos
                SNAPSHOT_DIR="/.snapshots"
                if [[ "$config" != "root" ]]; then
                    SNAPSHOT_DIR=$(snapper -c "$config" get-config 2>/dev/null | grep "SUBVOLUME" | awk '{print $NF}')/.snapshots
                fi

                if [[ -d "$SNAPSHOT_DIR" ]]; then
                    chmod 700 "$SNAPSHOT_DIR"
                    log_change "Permisos" "$SNAPSHOT_DIR -> 700"
                    chown root:root "$SNAPSHOT_DIR"
                    log_change "Permisos" "$SNAPSHOT_DIR -> root:root"
                    echo -e "  ${GREEN}●${NC} Snapshots protegidos: $SNAPSHOT_DIR (700)"
                fi
            done

            # Configurar retención mínima de snapshots
            if ask "¿Asegurar retención mínima de snapshots en Snapper?"; then
                for config in $SNAPPER_CONFIGS; do
                    # Mínimo 5 snapshots de timeline
                    snapper -c "$config" set-config "TIMELINE_MIN_AGE=1800" 2>/dev/null || true
                    snapper -c "$config" set-config "TIMELINE_LIMIT_DAILY=7" 2>/dev/null || true
                    snapper -c "$config" set-config "TIMELINE_LIMIT_WEEKLY=4" 2>/dev/null || true
                    snapper -c "$config" set-config "TIMELINE_LIMIT_MONTHLY=6" 2>/dev/null || true
                    echo -e "  ${GREEN}●${NC} Retención configurada para: $config"
                done
                log_info "Retención mínima de snapshots configurada"
            else
                log_skip "Retención mínima de snapshots no configurada"
            fi
        else
            log_warn "Snapper instalado pero sin configuraciones activas"
        fi
    else
        log_info "Snapper no detectado (snapshots BTRFS no disponibles)"
    fi

    # Script de verificación de integridad de backups
    cat > /usr/local/bin/verificar-backups.sh << 'EOFVERIFY'
#!/bin/bash
# ============================================================
# Verificación de integridad de backups
# MITRE: T1490 - M1053
# ============================================================

set -euo pipefail

LOG="/var/log/backup-verify-$(date +%Y%m%d).log"
CHECKSUMS_DIR="/etc/backup-offsite/checksums"
ALERT_LOG="/var/log/security-alerts.log"

mkdir -p "$CHECKSUMS_DIR"

echo "=== Verificación de Backups - $(date) ===" | tee "$LOG"

WARNINGS=0

# 1. Verificar existencia de backups recientes
echo "" | tee -a "$LOG"
echo "--- Backups del sistema ---" | tee -a "$LOG"

# Buscar backups del hardening
HARDENING_BACKUPS=$(find /root -maxdepth 1 -name "hardening-backup-*" -type d 2>/dev/null | sort -r)
if [[ -n "$HARDENING_BACKUPS" ]]; then
    LATEST=$(echo "$HARDENING_BACKUPS" | head -1)
    AGE_DAYS=$(( ($(date +%s) - $(stat -c %Y "$LATEST")) / 86400 ))
    echo "OK: Backup hardening más reciente: $LATEST (hace ${AGE_DAYS} días)" | tee -a "$LOG"
else
    echo "WARN: No se encontraron backups del hardening" | tee -a "$LOG"
    ((WARNINGS++)) || true
fi

# Verificar backup offsite
if [[ -f /etc/backup-offsite/config ]]; then
    source /etc/backup-offsite/config
    if [[ "$BACKUP_TYPE" == "local" ]] && [[ -d "$BACKUP_DEST" ]]; then
        OFFSITE_LATEST=$(find "$BACKUP_DEST" -maxdepth 1 -name "backup-*" -type d 2>/dev/null | sort -r | head -1)
        if [[ -n "$OFFSITE_LATEST" ]]; then
            AGE_DAYS=$(( ($(date +%s) - $(stat -c %Y "$OFFSITE_LATEST")) / 86400 ))
            echo "OK: Backup offsite más reciente: $OFFSITE_LATEST (hace ${AGE_DAYS} días)" | tee -a "$LOG"
            if [[ $AGE_DAYS -gt 7 ]]; then
                echo "WARN: Backup offsite tiene más de 7 días" | tee -a "$LOG"
                ((WARNINGS++)) || true
            fi
        else
            echo "WARN: No hay backups en destino offsite" | tee -a "$LOG"
            ((WARNINGS++)) || true
        fi
    fi
fi

# 2. Verificar integridad con checksums
echo "" | tee -a "$LOG"
echo "--- Integridad de archivos críticos ---" | tee -a "$LOG"

CRITICAL_FILES=(
    "/etc/passwd"
    "/etc/shadow"
    "/etc/group"
    "/etc/sudoers"
    "/etc/ssh/sshd_config"
    "/etc/fstab"
    "$GRUB_CFG"
)

CHECKSUM_FILE="$CHECKSUMS_DIR/critical-files.sha256"

if [[ -f "$CHECKSUM_FILE" ]]; then
    # Verificar checksums existentes
    while IFS='  ' read -r stored_hash filepath; do
        if [[ -f "$filepath" ]]; then
            current_hash=$(sha256sum "$filepath" 2>/dev/null | awk '{print $1}')
            if [[ "$current_hash" == "$stored_hash" ]]; then
                echo "OK: $filepath intacto" | tee -a "$LOG"
            else
                echo "ALERTA: $filepath MODIFICADO (hash cambió)" | tee -a "$LOG"
                echo "$(date): INTEGRIDAD - $filepath modificado" >> "$ALERT_LOG"
                ((WARNINGS++)) || true
            fi
        else
            echo "WARN: $filepath no existe" | tee -a "$LOG"
            ((WARNINGS++)) || true
        fi
    done < "$CHECKSUM_FILE"
else
    # Crear checksums iniciales
    echo "Creando checksums iniciales..." | tee -a "$LOG"
    > "$CHECKSUM_FILE"
    for filepath in "${CRITICAL_FILES[@]}"; do
        if [[ -f "$filepath" ]]; then
            sha256sum "$filepath" >> "$CHECKSUM_FILE"
            echo "  Registrado: $filepath" | tee -a "$LOG"
        fi
    done
    chmod 600 "$CHECKSUM_FILE"
    echo "Checksums iniciales creados en $CHECKSUM_FILE" | tee -a "$LOG"
fi

# 3. Verificar Snapper si existe
if command -v snapper &>/dev/null; then
    echo "" | tee -a "$LOG"
    echo "--- Snapshots Snapper ---" | tee -a "$LOG"
    SNAP_COUNT=$(snapper list 2>/dev/null | tail -n +4 | wc -l)
    if [[ "$SNAP_COUNT" -gt 0 ]]; then
        echo "OK: $SNAP_COUNT snapshots disponibles" | tee -a "$LOG"
    else
        echo "WARN: No hay snapshots de Snapper" | tee -a "$LOG"
        ((WARNINGS++)) || true
    fi
fi

# Resumen
echo "" | tee -a "$LOG"
if [[ $WARNINGS -eq 0 ]]; then
    echo "=== Verificación OK: Backups y snapshots intactos ===" | tee -a "$LOG"
else
    echo "=== ALERTA: $WARNINGS problemas detectados ===" | tee -a "$LOG"
    logger -t verificar-backups "ALERTA: $WARNINGS problemas en backups/snapshots"
fi

# Limpiar logs antiguos (>30 días)
find /var/log -name "backup-verify-*.log" -mtime +30 -delete 2>/dev/null || true
EOFVERIFY

    log_change "Creado" "/usr/local/bin/verificar-backups.sh"
    chmod 700 /usr/local/bin/verificar-backups.sh
    log_change "Permisos" "/usr/local/bin/verificar-backups.sh -> 700"
    log_info "Script de verificación creado: /usr/local/bin/verificar-backups.sh"

    # Cron semanal de verificación
    cat > /etc/cron.weekly/verificar-backups << 'EOFCRONVERIFY'
#!/bin/bash
# Verificación semanal de backups e integridad (T1490 - M1053)
/usr/local/bin/verificar-backups.sh 2>&1 | logger -t verificar-backups
EOFCRONVERIFY

    log_change "Creado" "/etc/cron.weekly/verificar-backups"
    chmod 700 /etc/cron.weekly/verificar-backups
    log_change "Permisos" "/etc/cron.weekly/verificar-backups -> 700"
    log_info "Cron semanal de verificación creado: /etc/cron.weekly/verificar-backups"

    # Ejecutar primera verificación para crear checksums base
    echo ""
    if ask "¿Ejecutar verificación inicial ahora (crea checksums base)?"; then
        /usr/local/bin/verificar-backups.sh
    else
        log_skip "Verificación inicial de backups no ejecutada"
    fi

    echo ""
    echo -e "${DIM}Uso manual: /usr/local/bin/verificar-backups.sh${NC}"
else
    log_skip "Protección de snapshots/backups no configurada"
    log_warn "Protección de snapshots/backups no configurada"
fi

# ============================================================
log_section "4. MONITOREO DE ACTIVIDAD DE IMPACTO (T1485/T1486/T1489)"
# ============================================================

echo "Configura monitoreo para detectar actividad de impacto:"
echo "  - Borrado masivo de archivos (T1485 Data Destruction)"
echo "  - Cifrado masivo sospechoso (T1486 Ransomware)"
echo "  - Parada de servicios críticos (T1489 Service Stop)"
echo ""

if ask "¿Configurar monitoreo de actividad de impacto?"; then

    # Reglas auditd para detección de impacto
    if command -v auditctl &>/dev/null; then
        mkdir -p /etc/audit/rules.d

        cat > /etc/audit/rules.d/impact-detection.rules << 'EOFAUDIT'
## ============================================================
## Reglas auditd - Detección de Impacto (TA0040)
## ============================================================

## T1485: Detectar eliminación masiva con shred/wipe
-w /usr/bin/shred -p x -k impact-data-destroy
-w /usr/bin/wipe -p x -k impact-data-destroy

## T1486: Detectar uso de herramientas de cifrado en contextos sospechosos
-w /usr/bin/openssl -p x -k impact-encrypt-tool
-w /usr/bin/gpg -p x -k impact-encrypt-tool
-w /usr/bin/gpg2 -p x -k impact-encrypt-tool
-w /usr/bin/age -p x -k impact-encrypt-tool

## T1489: Detectar parada de servicios
-w /usr/bin/systemctl -p x -k impact-service-control
-w /usr/sbin/service -p x -k impact-service-control

## T1490: Detectar modificación de backups/snapshots
-w /root/ -p w -k impact-backup-modify
-w /.snapshots/ -p wa -k impact-snapshot-modify

## T1529: Detectar intentos de apagado/reinicio
-w /usr/sbin/shutdown -p x -k impact-shutdown
-w /usr/sbin/reboot -p x -k impact-shutdown
-w /usr/sbin/poweroff -p x -k impact-shutdown
-w /usr/sbin/halt -p x -k impact-shutdown

## T1561: Detectar acceso directo a dispositivos de disco
-a always,exit -F arch=b64 -S open -S openat -F dir=/dev -F perm=w -F key=impact-disk-write
EOFAUDIT

        log_change "Creado" "/etc/audit/rules.d/impact-detection.rules"
        # Cargar reglas
        augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/impact-detection.rules 2>/dev/null || true
        log_change "Aplicado" "augenrules --load"
        log_info "Reglas auditd de detección de impacto cargadas"
    else
        log_warn "auditd no disponible, omitiendo reglas de auditoría"
    fi

    # Script de monitoreo de impacto
    cat > /usr/local/bin/detectar-impacto.sh << 'EOFDETECT'
#!/bin/bash
# ============================================================
# Detector de actividad de impacto (TA0040)
# MITRE: T1485, T1486, T1489, T1490, T1529, T1561
# ============================================================

set -euo pipefail

LOG="/var/log/impact-detection-$(date +%Y%m%d).log"
ALERT_LOG="/var/log/security-alerts.log"

echo "=== Detección de Impacto - $(date) ===" | tee -a "$LOG"

ALERTS=0

# 1. Verificar servicios críticos activos (T1489)
echo "" | tee -a "$LOG"
echo "--- T1489: Estado de servicios críticos ---" | tee -a "$LOG"
CRITICAL_SERVICES=("sshd" "firewalld" "auditd" "fail2ban" "cron" "crond")
for svc in "${CRITICAL_SERVICES[@]}"; do
    if systemctl list-unit-files "${svc}.service" &>/dev/null 2>&1; then
        if systemctl is-active "$svc" &>/dev/null; then
            echo "OK: $svc activo" | tee -a "$LOG"
        else
            echo "ALERTA: $svc NO ACTIVO" | tee -a "$LOG"
            echo "$(date): IMPACT/T1489 - Servicio $svc detenido" >> "$ALERT_LOG"
            ((ALERTS++)) || true
        fi
    fi
done

# 2. Verificar actividad reciente de cifrado (T1486)
echo "" | tee -a "$LOG"
echo "--- T1486: Actividad de cifrado reciente ---" | tee -a "$LOG"
if command -v ausearch &>/dev/null; then
    ENCRYPT_EVENTS=$(ausearch -k impact-encrypt-tool -ts recent 2>/dev/null | grep -c "type=SYSCALL" || echo 0)
    if [[ "$ENCRYPT_EVENTS" -gt 20 ]]; then
        echo "ALERTA: $ENCRYPT_EVENTS eventos de cifrado recientes (umbral: 20)" | tee -a "$LOG"
        echo "$(date): IMPACT/T1486 - $ENCRYPT_EVENTS eventos de cifrado detectados" >> "$ALERT_LOG"
        ((ALERTS++)) || true
    else
        echo "OK: $ENCRYPT_EVENTS eventos de cifrado (normal)" | tee -a "$LOG"
    fi
fi

# 3. Verificar eliminación masiva reciente (T1485)
echo "" | tee -a "$LOG"
echo "--- T1485: Actividad de destrucción reciente ---" | tee -a "$LOG"
if command -v ausearch &>/dev/null; then
    DESTROY_EVENTS=$(ausearch -k impact-data-destroy -ts recent 2>/dev/null | grep -c "type=SYSCALL" || echo 0)
    if [[ "$DESTROY_EVENTS" -gt 0 ]]; then
        echo "ALERTA: $DESTROY_EVENTS eventos de destrucción detectados" | tee -a "$LOG"
        echo "$(date): IMPACT/T1485 - $DESTROY_EVENTS eventos de destrucción" >> "$ALERT_LOG"
        ((ALERTS++)) || true
    else
        echo "OK: Sin actividad de destrucción" | tee -a "$LOG"
    fi
fi

# 4. Verificar cambios en snapshots/backups (T1490)
echo "" | tee -a "$LOG"
echo "--- T1490: Integridad de backups ---" | tee -a "$LOG"
if command -v ausearch &>/dev/null; then
    BACKUP_EVENTS=$(ausearch -k impact-backup-modify -ts recent 2>/dev/null | grep -c "type=SYSCALL" || echo 0)
    SNAP_EVENTS=$(ausearch -k impact-snapshot-modify -ts recent 2>/dev/null | grep -c "type=SYSCALL" || echo 0)
    TOTAL_MODIFY=$((BACKUP_EVENTS + SNAP_EVENTS))
    if [[ "$TOTAL_MODIFY" -gt 50 ]]; then
        echo "ALERTA: $TOTAL_MODIFY modificaciones en backups/snapshots" | tee -a "$LOG"
        echo "$(date): IMPACT/T1490 - $TOTAL_MODIFY modificaciones en backups" >> "$ALERT_LOG"
        ((ALERTS++)) || true
    else
        echo "OK: $TOTAL_MODIFY modificaciones (normal)" | tee -a "$LOG"
    fi
fi

# 5. Verificar uso de disco anómalo (posible wipe T1561)
echo "" | tee -a "$LOG"
echo "--- T1561: Uso de disco ---" | tee -a "$LOG"
ROOT_USE=$(df / 2>/dev/null | tail -1 | awk '{print $5}' | tr -d '%')
if [[ -n "$ROOT_USE" ]]; then
    if [[ "$ROOT_USE" -lt 5 ]]; then
        echo "ALERTA: Disco raíz casi vacío (${ROOT_USE}%) - posible disk wipe" | tee -a "$LOG"
        echo "$(date): IMPACT/T1561 - Disco raíz al ${ROOT_USE}%" >> "$ALERT_LOG"
        ((ALERTS++)) || true
    else
        echo "OK: Disco raíz al ${ROOT_USE}%" | tee -a "$LOG"
    fi
fi

# 6. Buscar procesos sospechosos de cifrado/destrucción
echo "" | tee -a "$LOG"
echo "--- Procesos sospechosos activos ---" | tee -a "$LOG"
SUSPICIOUS_PROCS=$(ps aux 2>/dev/null | grep -iE "(encrypt|ransom|wiper|shred.*-[fnuz])" | grep -v grep || true)
if [[ -n "$SUSPICIOUS_PROCS" ]]; then
    echo "ALERTA: Procesos sospechosos detectados:" | tee -a "$LOG"
    echo "$SUSPICIOUS_PROCS" | tee -a "$LOG"
    ((ALERTS++)) || true
else
    echo "OK: No hay procesos sospechosos" | tee -a "$LOG"
fi

# Resumen
echo "" | tee -a "$LOG"
echo "=== RESUMEN ===" | tee -a "$LOG"
if [[ $ALERTS -eq 0 ]]; then
    echo "OK: Sin indicadores de actividad de impacto" | tee -a "$LOG"
else
    echo "ALERTA CRÍTICA: $ALERTS indicadores de impacto detectados" | tee -a "$LOG"
    logger -t detectar-impacto "ALERTA: $ALERTS indicadores de impacto (TA0040)"
fi

# Limpiar logs antiguos (>30 días)
find /var/log -name "impact-detection-*.log" -mtime +30 -delete 2>/dev/null || true
EOFDETECT

    log_change "Creado" "/usr/local/bin/detectar-impacto.sh"
    chmod 700 /usr/local/bin/detectar-impacto.sh
    log_change "Permisos" "/usr/local/bin/detectar-impacto.sh -> 700"
    log_info "Script de detección de impacto creado: /usr/local/bin/detectar-impacto.sh"

    # Cron diario de monitoreo
    cat > /etc/cron.daily/detectar-impacto << 'EOFCRONDET'
#!/bin/bash
# Detección diaria de actividad de impacto (TA0040)
/usr/local/bin/detectar-impacto.sh 2>&1 | logger -t detectar-impacto
EOFCRONDET

    log_change "Creado" "/etc/cron.daily/detectar-impacto"
    chmod 700 /etc/cron.daily/detectar-impacto
    log_change "Permisos" "/etc/cron.daily/detectar-impacto -> 700"
    log_info "Cron diario de detección creado: /etc/cron.daily/detectar-impacto"

    echo ""
    echo -e "${DIM}Uso manual: /usr/local/bin/detectar-impacto.sh${NC}"
else
    log_skip "Monitoreo de impacto no configurado"
    log_warn "Monitoreo de impacto no configurado"
fi

# ============================================================
log_section "RESUMEN DE MITIGACIONES TA0040"
# ============================================================

echo ""
echo -e "${BOLD}Estado de mitigaciones de Impacto (TA0040):${NC}"
echo ""

# T1486/T1561 - Backups offsite
if [[ -f /etc/backup-offsite/config ]] && [[ -x /usr/local/bin/backup-offsite.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1486/T1561 M1053 - Backups offsite automáticos"
else
    echo -e "  ${YELLOW}[--]${NC} T1486/T1561 M1053 - Backups offsite no configurados"
fi

# T1486 - ClamAV anti-ransomware
if [[ -x /usr/local/bin/clamav-antiransomware.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1486 M1049 - ClamAV anti-ransomware"
else
    echo -e "  ${YELLOW}[--]${NC} T1486 M1049 - ClamAV anti-ransomware no configurado"
fi

# T1490 - Protección snapshots/backups
if [[ -x /usr/local/bin/verificar-backups.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1490 M1053 - Protección snapshots/backups"
else
    echo -e "  ${YELLOW}[--]${NC} T1490 M1053 - Protección snapshots no configurada"
fi

# T1485/T1486/T1489 - Monitoreo impacto
if [[ -x /usr/local/bin/detectar-impacto.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1485/T1486/T1489 M1047 - Monitoreo de impacto"
else
    echo -e "  ${YELLOW}[--]${NC} T1485/T1486/T1489 M1047 - Monitoreo no configurado"
fi

show_changes_summary

echo ""
log_info "Script de mitigación de impacto completado"
log_info "Backups de configuración en: $BACKUP_DIR"
