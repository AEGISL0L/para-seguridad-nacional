#!/bin/bash
# ============================================================
# HARDENING SEGURO - Sin quedarte fuera del sistema
# Securiza sin bloquear tu acceso ni la red
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps

USER_ACTUAL="${SUDO_USER:-$USER}"
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   HARDENING SEGURO - Sin quedarte fuera                   ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Usuario protegido: $USER_ACTUAL"

# ============================================================
# 1. PROTEGER ARCHIVOS DE CONFIGURACIÓN CRÍTICOS
# ============================================================
log_info "1. Protegiendo archivos críticos del sistema..."

# Hacer copias de seguridad
mkdir -p /root/backup-criticos-$(date +%Y%m%d)
cp /etc/passwd /etc/shadow /etc/group /etc/sudoers /root/backup-criticos-$(date +%Y%m%d)/ 2>/dev/null || true

# Permisos correctos (no inmutables para no quedarte fuera)
chmod 644 /etc/passwd
chmod 640 /etc/shadow
chmod 644 /etc/group
chmod 440 /etc/sudoers

log_info "   Permisos de archivos críticos asegurados"

# ============================================================
# 2. PROTECCIÓN DE PROCESOS Y MEMORIA
# ============================================================
log_info "2. Protección de procesos..."

cat > /etc/sysctl.d/99-process-hardening.conf << 'EOF'
# Protección de procesos
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3
kernel.yama.ptrace_scope = 1

# Core dumps limitados (no deshabilitados totalmente)
fs.suid_dumpable = 0

# Protección de archivos
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# Memoria
vm.mmap_min_addr = 65536
EOF

/usr/sbin/sysctl --system > /dev/null 2>&1
log_info "   Protección de memoria y procesos activa"

# ============================================================
# 3. MONITOREAR CAMBIOS EN ARCHIVOS CRÍTICOS
# ============================================================
log_info "3. Configurando monitoreo de integridad..."

# Guardar hashes de archivos críticos
HASH_FILE="/root/.critical-hashes"
cat > "$HASH_FILE" << EOF
# Hashes de archivos críticos - $(date)
$(sha256sum /etc/passwd 2>/dev/null)
$(sha256sum /etc/shadow 2>/dev/null)
$(sha256sum /etc/group 2>/dev/null)
$(sha256sum /etc/sudoers 2>/dev/null)
$(sha256sum /usr/bin/sudo 2>/dev/null)
$(sha256sum /usr/bin/su 2>/dev/null)
$(sha256sum /usr/bin/passwd 2>/dev/null)
$(sha256sum /usr/bin/login 2>/dev/null)
EOF
chmod 600 "$HASH_FILE"

# Script para verificar integridad
cat > /usr/local/bin/verificar-integridad.sh << 'EOFVERIFY'
#!/bin/bash
# Verificar integridad de archivos críticos

HASH_FILE="/root/.critical-hashes"
ALERT=0

echo "Verificando integridad de archivos críticos..."

while read -r line; do
    [[ "$line" =~ ^# ]] && continue
    [[ -z "$line" ]] && continue

    HASH=$(echo "$line" | awk '{print $1}')
    FILE=$(echo "$line" | awk '{print $2}')

    if [[ -f "$FILE" ]]; then
        CURRENT=$(sha256sum "$FILE" | awk '{print $1}')
        if [[ "$HASH" != "$CURRENT" ]]; then
            echo "[ALERTA] $FILE ha sido MODIFICADO!"
            ALERT=1
        fi
    fi
done < "$HASH_FILE"

if [[ $ALERT -eq 0 ]]; then
    echo "✓ Todos los archivos íntegros"
else
    echo ""
    echo "⚠️  SE DETECTARON MODIFICACIONES"
fi
EOFVERIFY
chmod +x /usr/local/bin/verificar-integridad.sh

log_info "   Ejecutar: verificar-integridad.sh"

# ============================================================
# 4. PROTEGER CONTRA ESCALADA DE PRIVILEGIOS
# ============================================================
log_info "4. Protección contra escalada de privilegios..."

# Limitar SUID/SGID (solo los esenciales)
cat > /usr/local/bin/auditar-suid.sh << 'EOFSUID'
#!/bin/bash
echo "Archivos SUID/SGID en el sistema:"
echo ""
find / -perm /6000 -type f 2>/dev/null | while read -r file; do
    ls -la "$file"
done
echo ""
echo "Verificar que todos son necesarios."
EOFSUID
chmod +x /usr/local/bin/auditar-suid.sh

# Asegurar que sudo requiere contraseña
if [[ -f /etc/sudoers ]]; then
    # Verificar NOPASSWD peligrosos
    if grep -q "NOPASSWD.*ALL" /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
        log_warn "   Hay reglas NOPASSWD:ALL - revisar manualmente"
    fi
fi

# ============================================================
# 5. PROTEGER SESIÓN DE USUARIO
# ============================================================
log_info "5. Protegiendo sesión de usuario..."

# Historial seguro
if [[ -f "/home/$USER_ACTUAL/.bashrc" ]]; then
    if ! grep -q "HISTCONTROL" "/home/$USER_ACTUAL/.bashrc"; then
        cat >> "/home/$USER_ACTUAL/.bashrc" << 'EOF'

# Historial seguro
HISTCONTROL=ignoreboth:erasedups
HISTSIZE=10000
HISTFILESIZE=20000
HISTTIMEFORMAT="%Y-%m-%d %H:%M:%S "
shopt -s histappend
EOF
    fi
fi

# ============================================================
# 6. DETECTAR PROCESOS OCULTOS/SOSPECHOSOS
# ============================================================
log_info "6. Configurando detección de procesos sospechosos..."

cat > /usr/local/bin/procesos-sospechosos.sh << 'EOFPROC'
#!/bin/bash
echo "=== PROCESOS SOSPECHOSOS ==="
echo ""

# Procesos con nombres sospechosos
echo "Buscando nombres sospechosos..."
ps aux | grep -iE "shell|backdoor|reverse|bind|keylog|miner|crypto|xmr|monero" | grep -v grep

echo ""
echo "Procesos sin TTY (posibles daemons maliciosos):"
ps aux | awk '$7 == "?" {print}' | grep -vE "^\[|systemd|dbus|polkit|gdm|sddm|Xorg|pipewire|pulseaudio|gnome|kde|plasma|firefox|chrome"

echo ""
echo "Procesos escuchando en puertos:"
ss -tlnp 2>/dev/null

echo ""
echo "Procesos con conexiones de red:"
ss -tnp 2>/dev/null | grep -v "127.0.0.1"
EOFPROC
chmod +x /usr/local/bin/procesos-sospechosos.sh

# ============================================================
# 7. PROTEGER CRON Y TAREAS PROGRAMADAS
# ============================================================
log_info "7. Asegurando cron..."

# Ver crontabs sospechosos
cat > /usr/local/bin/auditar-cron.sh << 'EOFCRON'
#!/bin/bash
echo "=== AUDITORÍA DE CRON ==="
echo ""
echo "Crontab de root:"
crontab -l 2>/dev/null || echo "(vacío)"

echo ""
echo "Archivos en /etc/cron.d/:"
ls -la /etc/cron.d/

echo ""
echo "Contenido de /etc/cron.d/:"
for f in /etc/cron.d/*; do
    echo "--- $f ---"
    cat "$f" 2>/dev/null
done

echo ""
echo "Timers de systemd activos:"
systemctl list-timers --all
EOFCRON
chmod +x /usr/local/bin/auditar-cron.sh

# Restringir cron a usuarios autorizados
echo "root" > /etc/cron.allow
echo "$USER_ACTUAL" >> /etc/cron.allow
chmod 600 /etc/cron.allow

# ============================================================
# 8. AUDITORÍA DE PAQUETES
# ============================================================
log_info "8. Verificando integridad de paquetes instalados..."

cat > /usr/local/bin/verificar-paquetes.sh << 'EOFPKG'
#!/bin/bash
echo "Verificando integridad de paquetes instalados..."
echo "Esto puede tomar tiempo..."
echo ""

# Verificar archivos modificados (multi-distro)
if command -v rpm &>/dev/null; then
    rpm -Va 2>/dev/null | grep -vE "^\.\.\.\.\.\.\.\.T" | head -50
    echo ""
    echo "Si hay líneas con '5' (MD5), los archivos fueron modificados."
elif command -v debsums &>/dev/null; then
    debsums -c 2>/dev/null | head -50
    echo ""
    echo "Los archivos listados han sido modificados respecto al paquete original."
elif command -v pacman &>/dev/null; then
    pacman -Qkk 2>/dev/null | grep -v " 0 altered" | head -50
    echo ""
    echo "Los paquetes listados tienen archivos modificados."
else
    echo "No se encontró herramienta de verificación de paquetes."
    echo "Instalar: debsums (Debian/Ubuntu) o usar rpm -Va (RHEL/SUSE)."
fi
echo "Verificar manualmente si es legítimo."
EOFPKG
chmod +x /usr/local/bin/verificar-paquetes.sh

# ============================================================
# 9. PROTEGER BOOT
# ============================================================
log_info "9. Protegiendo arranque..."

# Permisos de GRUB
chmod 600 $GRUB_CFG 2>/dev/null || true
chmod 700 /boot 2>/dev/null || true

# ============================================================
# 10. MONITOREO DE CAMBIOS EN TIEMPO REAL
# ============================================================
log_info "10. Configurando monitor de cambios..."

cat > /usr/local/bin/monitor-cambios.sh << 'EOFMON'
#!/bin/bash
# Monitor de cambios en directorios críticos

inotifywait -m -r -e modify,create,delete,move \
    /etc/passwd /etc/shadow /etc/sudoers /etc/cron.d /etc/systemd/system \
    2>/dev/null | while read -r directory event filename; do
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $event en $directory$filename" | tee -a /var/log/file-changes.log
done
EOFMON
chmod +x /usr/local/bin/monitor-cambios.sh

# Instalar inotify-tools si no existe
if ! command -v inotifywait &>/dev/null; then
    pkg_install inotify-tools
fi

# ============================================================
# 11. SCRIPT DE AUDITORÍA RÁPIDA
# ============================================================
log_info "11. Creando script de auditoría rápida..."

cat > /usr/local/bin/auditoria-rapida.sh << 'EOFAUDIT'
#!/bin/bash
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║            AUDITORÍA RÁPIDA DE SEGURIDAD                  ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

echo "=== USUARIOS CONECTADOS ==="
who
echo ""

echo "=== ÚLTIMOS LOGINS ==="
last -10
echo ""

echo "=== PROCESOS CON MÁS CPU ==="
ps aux --sort=-%cpu | head -10
echo ""

echo "=== CONEXIONES DE RED ==="
ss -tunap | grep -v "127.0.0.1" | head -20
echo ""

echo "=== PUERTOS ESCUCHANDO ==="
ss -tlnp
echo ""

echo "=== ARCHIVOS MODIFICADOS HOY EN /etc ==="
find /etc -mtime 0 -type f 2>/dev/null | head -20
echo ""

echo "=== VERIFICAR INTEGRIDAD ==="
/usr/local/bin/verificar-integridad.sh
echo ""

echo "=== ESTADO DE SERVICIOS DE SEGURIDAD ==="
for svc in firewalld fail2ban auditd; do
    printf "%-15s: %s\n" "$svc" "$(systemctl is-active $svc 2>/dev/null || echo 'no instalado')"
done
EOFAUDIT
chmod +x /usr/local/bin/auditoria-rapida.sh

# ============================================================
# RESUMEN
# ============================================================
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║         HARDENING SEGURO COMPLETADO                       ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "Scripts de seguridad instalados:"
echo "  • auditoria-rapida.sh     - Revisión rápida del sistema"
echo "  • verificar-integridad.sh - Verificar hashes de archivos"
echo "  • procesos-sospechosos.sh - Buscar procesos maliciosos"
echo "  • auditar-cron.sh         - Revisar tareas programadas"
echo "  • auditar-suid.sh         - Listar archivos SUID/SGID"
echo "  • verificar-paquetes.sh   - Integridad de RPM"
echo "  • monitor-cambios.sh      - Monitor en tiempo real"
echo ""
echo "Ejecuta ahora:"
echo "  sudo auditoria-rapida.sh"
echo ""
log_info "Tu acceso al sistema NO ha sido afectado"
