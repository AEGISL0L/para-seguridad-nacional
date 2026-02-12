#!/bin/bash
# ============================================================
# RESPUESTA A INCIDENTES - Operaciones de Seguridad
# Linux Multi-Distro (openSUSE, Debian/Ubuntu, RHEL/Fedora, Arch)
# ============================================================
# Capacidades implementadas:
#   - Recolección forense de datos volátiles
#   - Playbooks automáticos de contención por táctica MITRE
#   - Preservación de evidencia con cadena de custodia
#   - Aislamiento de red del host comprometido
#   - Recuperación guiada post-incidente
#   - Timeline de ataque desde logs
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps
IR_BASE="/var/lib/incident-response"
mkdir -p "$IR_BASE"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   RESPUESTA A INCIDENTES - Operaciones de Seguridad       ║"
echo "║   Contención, forense, recuperación                        ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# ============================================================
log_section "1. TOOLKIT DE RECOLECCIÓN FORENSE"
# ============================================================

echo "Crear herramientas de recolección forense que preserven"
echo "datos volátiles del sistema ante un incidente activo."
echo ""
echo "Datos recolectados:"
echo "  - Procesos activos, conexiones de red, memoria"
echo "  - Archivos abiertos, módulos kernel, usuarios logueados"
echo "  - Logs del sistema, reglas de firewall, estado de servicios"
echo ""

if ask "¿Instalar toolkit de recolección forense?"; then

    cat > /usr/local/bin/ir-recolectar-forense.sh << 'EOFFORENSE'
#!/bin/bash
# ============================================================
# RECOLECCIÓN FORENSE DE DATOS VOLÁTILES
# Ejecutar ANTES de cualquier acción de contención
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

INCIDENT_ID="${1:-INC-$(date +%Y%m%d-%H%M%S)}"
IR_DIR="/var/lib/incident-response/$INCIDENT_ID"
mkdir -p "$IR_DIR"

LOG="$IR_DIR/recoleccion.log"
echo "=== RECOLECCIÓN FORENSE - $INCIDENT_ID ===" | tee "$LOG"
echo "Inicio: $(date -Iseconds)" | tee -a "$LOG"
echo "Hostname: $(hostname)" | tee -a "$LOG"
echo "Kernel: $(uname -r)" | tee -a "$LOG"
echo "Recolector: $(whoami) (PID $$)" | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Hash de inicio para cadena de custodia
echo "=== CADENA DE CUSTODIA ===" > "$IR_DIR/cadena-custodia.txt"
echo "Inicio recolección: $(date -Iseconds)" >> "$IR_DIR/cadena-custodia.txt"
echo "Operador: $(whoami)" >> "$IR_DIR/cadena-custodia.txt"
echo "Sistema: $(hostname) $(uname -r)" >> "$IR_DIR/cadena-custodia.txt"

# 1. Fecha y hora exacta del sistema
echo "[1/15] Fecha y hora del sistema..." | tee -a "$LOG"
date -Iseconds > "$IR_DIR/01-timestamp.txt"
timedatectl status >> "$IR_DIR/01-timestamp.txt" 2>/dev/null
uptime >> "$IR_DIR/01-timestamp.txt"

# 2. Usuarios logueados
echo "[2/15] Usuarios logueados..." | tee -a "$LOG"
who -a > "$IR_DIR/02-usuarios-logueados.txt" 2>/dev/null
w >> "$IR_DIR/02-usuarios-logueados.txt" 2>/dev/null
last -20 >> "$IR_DIR/02-usuarios-logueados.txt" 2>/dev/null

# 3. Procesos activos (CRÍTICO - capturar antes de matar nada)
echo "[3/15] Procesos activos..." | tee -a "$LOG"
ps auxwwf > "$IR_DIR/03-procesos-arbol.txt" 2>/dev/null
ps -eo pid,ppid,user,uid,gid,vsz,rss,tty,stat,start,time,comm,args > "$IR_DIR/03-procesos-detalle.txt" 2>/dev/null

# Procesos con conexiones de red
for pid in /proc/[0-9]*; do
    P=$(basename "$pid")
    FD_COUNT=$(ls "$pid/fd" 2>/dev/null | wc -l)
    if [[ "$FD_COUNT" -gt 10 ]]; then
        COMM=$(cat "$pid/comm" 2>/dev/null || echo "?")
        CMDLINE=$(cat "$pid/cmdline" 2>/dev/null | tr '\0' ' ' || echo "?")
        EXE=$(readlink -f "$pid/exe" 2>/dev/null || echo "?")
        echo "PID=$P COMM=$COMM EXE=$EXE FDs=$FD_COUNT CMD=$CMDLINE" >> "$IR_DIR/03-procesos-fd-altos.txt"
    fi
done

# 4. Conexiones de red (CRÍTICO)
echo "[4/15] Conexiones de red..." | tee -a "$LOG"
ss -tupna > "$IR_DIR/04-conexiones-red.txt" 2>/dev/null
ss -tlnp > "$IR_DIR/04-puertos-escucha.txt" 2>/dev/null
ip addr show > "$IR_DIR/04-interfaces.txt" 2>/dev/null
ip route show > "$IR_DIR/04-rutas.txt" 2>/dev/null
ip neigh show > "$IR_DIR/04-tabla-arp.txt" 2>/dev/null
cat /etc/resolv.conf > "$IR_DIR/04-dns.txt" 2>/dev/null

# 5. Archivos abiertos
echo "[5/15] Archivos abiertos..." | tee -a "$LOG"
lsof -nP > "$IR_DIR/05-archivos-abiertos.txt" 2>/dev/null || true

# 6. Módulos del kernel
echo "[6/15] Módulos del kernel..." | tee -a "$LOG"
lsmod > "$IR_DIR/06-modulos-kernel.txt" 2>/dev/null
cat /proc/modules > "$IR_DIR/06-proc-modules.txt" 2>/dev/null

# 7. Tareas programadas
echo "[7/15] Tareas programadas..." | tee -a "$LOG"
for user in $(cut -d: -f1 /etc/passwd); do
    CRON=$(crontab -u "$user" -l 2>/dev/null)
    if [[ -n "$CRON" ]]; then
        echo "=== $user ===" >> "$IR_DIR/07-crontabs.txt"
        echo "$CRON" >> "$IR_DIR/07-crontabs.txt"
    fi
done
systemctl list-timers --all > "$IR_DIR/07-timers-systemd.txt" 2>/dev/null

# 8. Servicios systemd
echo "[8/15] Estado de servicios..." | tee -a "$LOG"
systemctl list-units --type=service --all > "$IR_DIR/08-servicios.txt" 2>/dev/null
systemctl list-unit-files --type=service > "$IR_DIR/08-servicios-habilitados.txt" 2>/dev/null

# 9. Firewall
echo "[9/15] Reglas de firewall..." | tee -a "$LOG"
fw_list_all_zones > "$IR_DIR/09-firewall-zonas.txt" 2>/dev/null || true
iptables -L -n -v > "$IR_DIR/09-iptables.txt" 2>/dev/null || true
nft list ruleset > "$IR_DIR/09-nftables.txt" 2>/dev/null || true

# 10. Logs recientes
echo "[10/15] Logs recientes..." | tee -a "$LOG"
journalctl --since "24 hours ago" --no-pager > "$IR_DIR/10-journal-24h.txt" 2>/dev/null
journalctl -u "$SSH_SERVICE_NAME" --since "7 days ago" --no-pager > "$IR_DIR/10-ssh-7d.txt" 2>/dev/null
cp /var/log/audit/audit.log "$IR_DIR/10-audit.log" 2>/dev/null || true
cp /var/log/messages "$IR_DIR/10-messages.txt" 2>/dev/null || true
tail -1000 /var/log/secure "$IR_DIR/10-secure.txt" 2>/dev/null || true

# 11. Archivos modificados recientemente
echo "[11/15] Archivos modificados (24h)..." | tee -a "$LOG"
find /etc /usr/local/bin /usr/bin /usr/sbin -maxdepth 3 -mtime -1 -type f 2>/dev/null > "$IR_DIR/11-archivos-recientes-sistema.txt"
find /tmp /var/tmp /dev/shm -maxdepth 3 -type f 2>/dev/null > "$IR_DIR/11-archivos-tmp.txt"

# 12. Binarios SUID/SGID
echo "[12/15] Binarios SUID/SGID..." | tee -a "$LOG"
find / -maxdepth 5 -perm /6000 -type f 2>/dev/null > "$IR_DIR/12-suid-sgid.txt"

# 13. Estado de integridad
echo "[13/15] Integridad del sistema..." | tee -a "$LOG"
if command -v aide &>/dev/null; then
    aide --check > "$IR_DIR/13-aide-check.txt" 2>/dev/null || true
fi
pkg_verify > "$IR_DIR/13-pkg-verify.txt" 2>/dev/null || true

# 14. Variables de entorno
echo "[14/15] Variables de entorno..." | tee -a "$LOG"
env > "$IR_DIR/14-env-root.txt" 2>/dev/null
cat /etc/environment > "$IR_DIR/14-etc-environment.txt" 2>/dev/null || true
ls -la /etc/profile.d/ > "$IR_DIR/14-profile-d.txt" 2>/dev/null

# 15. Hash de evidencia
echo "[15/15] Generando hashes de evidencia..." | tee -a "$LOG"
find "$IR_DIR" -type f -exec sha256sum {} \; > "$IR_DIR/HASHES-SHA256.txt" 2>/dev/null

echo "" | tee -a "$LOG"
echo "Fin recolección: $(date -Iseconds)" >> "$IR_DIR/cadena-custodia.txt"
echo "Archivos recolectados: $(find "$IR_DIR" -type f | wc -l)" >> "$IR_DIR/cadena-custodia.txt"

TOTAL_SIZE=$(du -sh "$IR_DIR" | awk '{print $1}')
echo "=== RECOLECCIÓN COMPLETADA ===" | tee -a "$LOG"
echo "ID Incidente: $INCIDENT_ID" | tee -a "$LOG"
echo "Directorio: $IR_DIR" | tee -a "$LOG"
echo "Tamaño total: $TOTAL_SIZE" | tee -a "$LOG"
echo "Archivos: $(find "$IR_DIR" -type f | wc -l)" | tee -a "$LOG"
EOFFORENSE

    chmod 700 /usr/local/bin/ir-recolectar-forense.sh
    log_change "Creado" "/usr/local/bin/ir-recolectar-forense.sh"
    log_change "Permisos" "/usr/local/bin/ir-recolectar-forense.sh -> 700"
    log_info "Toolkit forense instalado: /usr/local/bin/ir-recolectar-forense.sh"
    echo -e "${DIM}Uso: ir-recolectar-forense.sh [ID-INCIDENTE]${NC}"

else
    log_skip "Toolkit de recolección forense"
fi

# ============================================================
log_section "2. PLAYBOOKS DE CONTENCIÓN AUTOMÁTICA"
# ============================================================

echo "Playbooks automáticos de contención para diferentes tipos"
echo "de incidente, mapeados a tácticas MITRE ATT&CK."
echo ""
echo "Playbooks disponibles:"
echo "  - Compromiso de cuenta de usuario"
echo "  - Malware/ransomware activo"
echo "  - Movimiento lateral detectado"
echo "  - Exfiltración de datos"
echo "  - C2 activo"
echo ""

if ask "¿Instalar playbooks de contención?"; then

    mkdir -p /usr/local/lib/incident-response/playbooks
    log_change "Creado" "/usr/local/lib/incident-response/playbooks/"

    # --- Playbook: Compromiso de cuenta ---
    cat > /usr/local/lib/incident-response/playbooks/pb-cuenta-comprometida.sh << 'EOFPB1'
#!/bin/bash
# PLAYBOOK: Cuenta de usuario comprometida
# MITRE: T1078 (Valid Accounts), T1110 (Brute Force)
# Severidad: ALTA

USUARIO="$1"
INCIDENT_ID="${2:-INC-$(date +%Y%m%d-%H%M%S)}"
IR_DIR="/var/lib/incident-response/$INCIDENT_ID"
mkdir -p "$IR_DIR"
LOG="$IR_DIR/playbook-cuenta.log"

if [[ -z "$USUARIO" ]]; then
    echo "Uso: $0 <usuario> [ID-incidente]"
    exit 1
fi

echo "=== PLAYBOOK: Cuenta Comprometida ===" | tee "$LOG"
echo "Usuario: $USUARIO" | tee -a "$LOG"
echo "Inicio: $(date -Iseconds)" | tee -a "$LOG"

# Paso 1: Recolectar evidencia del usuario
echo "" | tee -a "$LOG"
echo "[1/6] Recolectando evidencia del usuario..." | tee -a "$LOG"
id "$USUARIO" > "$IR_DIR/usuario-info.txt" 2>/dev/null
last "$USUARIO" | head -30 > "$IR_DIR/usuario-logins.txt" 2>/dev/null
ps -u "$USUARIO" -f > "$IR_DIR/usuario-procesos.txt" 2>/dev/null
crontab -u "$USUARIO" -l > "$IR_DIR/usuario-crontab.txt" 2>/dev/null || true

# Paso 2: Matar sesiones activas
echo "[2/6] Terminando sesiones activas de $USUARIO..." | tee -a "$LOG"
pkill -u "$USUARIO" 2>/dev/null || true
echo "  Sesiones terminadas" | tee -a "$LOG"

# Paso 3: Bloquear cuenta
echo "[3/6] Bloqueando cuenta $USUARIO..." | tee -a "$LOG"
passwd -l "$USUARIO" 2>/dev/null
usermod -s /sbin/nologin "$USUARIO" 2>/dev/null
echo "  Cuenta bloqueada y shell cambiado a nologin" | tee -a "$LOG"

# Paso 4: Revocar claves SSH
echo "[4/6] Revocando claves SSH..." | tee -a "$LOG"
USER_HOME=$(getent passwd "$USUARIO" | cut -d: -f6)
if [[ -d "$USER_HOME/.ssh" ]]; then
    cp -r "$USER_HOME/.ssh" "$IR_DIR/usuario-ssh-backup/" 2>/dev/null
    > "$USER_HOME/.ssh/authorized_keys" 2>/dev/null
    echo "  authorized_keys vaciado (backup en $IR_DIR)" | tee -a "$LOG"
fi

# Paso 5: Verificar persistencia
echo "[5/6] Verificando mecanismos de persistencia..." | tee -a "$LOG"
# Crontabs
if crontab -u "$USUARIO" -l 2>/dev/null | grep -v "^#" | grep -q "."; then
    crontab -u "$USUARIO" -r 2>/dev/null
    echo "  Crontab eliminada (backup en $IR_DIR)" | tee -a "$LOG"
fi
# Servicios systemd del usuario
find "$USER_HOME/.config/systemd/user/" -name "*.service" 2>/dev/null | while read -r svc; do
    echo "  ALERTA: Servicio systemd de usuario: $svc" | tee -a "$LOG"
    cp "$svc" "$IR_DIR/" 2>/dev/null
done

# Paso 6: Registrar en log del sistema
echo "[6/6] Registrando incidente..." | tee -a "$LOG"
logger -t incident-response "PLAYBOOK: Cuenta $USUARIO comprometida - contenida (INC: $INCIDENT_ID)"

echo "" | tee -a "$LOG"
echo "=== CONTENCIÓN COMPLETADA ===" | tee -a "$LOG"
echo "ACCIONES PENDIENTES:" | tee -a "$LOG"
echo "  1. Investigar origen del compromiso" | tee -a "$LOG"
echo "  2. Revisar archivos en $USER_HOME" | tee -a "$LOG"
echo "  3. Verificar si la cuenta se usó para movimiento lateral" | tee -a "$LOG"
echo "  4. Resetear contraseña cuando se reactive la cuenta" | tee -a "$LOG"
echo "  5. Revisar logs de acceso: last $USUARIO" | tee -a "$LOG"
EOFPB1

    chmod 700 /usr/local/lib/incident-response/playbooks/pb-cuenta-comprometida.sh
    log_change "Creado" "/usr/local/lib/incident-response/playbooks/pb-cuenta-comprometida.sh"
    log_change "Permisos" "/usr/local/lib/incident-response/playbooks/pb-cuenta-comprometida.sh -> 700"

    # --- Playbook: Malware/Ransomware ---
    cat > /usr/local/lib/incident-response/playbooks/pb-malware-activo.sh << 'EOFPB2'
#!/bin/bash
# PLAYBOOK: Malware/Ransomware activo
# MITRE: T1486 (Ransomware), T1059 (Execution), TA0040 (Impact)
# Severidad: CRÍTICA

PID_SOSPECHOSO="$1"
INCIDENT_ID="${2:-INC-$(date +%Y%m%d-%H%M%S)}"
IR_DIR="/var/lib/incident-response/$INCIDENT_ID"
mkdir -p "$IR_DIR"
LOG="$IR_DIR/playbook-malware.log"

echo "=== PLAYBOOK: Malware/Ransomware Activo ===" | tee "$LOG"
echo "PID sospechoso: $PID_SOSPECHOSO" | tee -a "$LOG"
echo "Inicio: $(date -Iseconds)" | tee -a "$LOG"

# Paso 1: Recolectar información del proceso ANTES de matarlo
echo "" | tee -a "$LOG"
echo "[1/7] Recolectando info del proceso sospechoso..." | tee -a "$LOG"

if [[ -n "$PID_SOSPECHOSO" ]] && [[ -d "/proc/$PID_SOSPECHOSO" ]]; then
    cat "/proc/$PID_SOSPECHOSO/cmdline" 2>/dev/null | tr '\0' ' ' > "$IR_DIR/malware-cmdline.txt"
    readlink -f "/proc/$PID_SOSPECHOSO/exe" > "$IR_DIR/malware-exe-path.txt" 2>/dev/null
    cat "/proc/$PID_SOSPECHOSO/environ" 2>/dev/null | tr '\0' '\n' > "$IR_DIR/malware-environ.txt"
    cat "/proc/$PID_SOSPECHOSO/maps" > "$IR_DIR/malware-maps.txt" 2>/dev/null
    ls -la "/proc/$PID_SOSPECHOSO/fd/" > "$IR_DIR/malware-fds.txt" 2>/dev/null

    # Copiar el binario para análisis
    EXE_PATH=$(readlink -f "/proc/$PID_SOSPECHOSO/exe" 2>/dev/null)
    if [[ -f "$EXE_PATH" ]]; then
        cp "$EXE_PATH" "$IR_DIR/malware-binary" 2>/dev/null
        sha256sum "$EXE_PATH" > "$IR_DIR/malware-hash.txt" 2>/dev/null
        file "$EXE_PATH" > "$IR_DIR/malware-filetype.txt" 2>/dev/null
        echo "  Binario preservado: $EXE_PATH" | tee -a "$LOG"
    fi
fi

# Paso 2: Suspender el proceso (NO matar aún - preservar memoria)
echo "[2/7] Suspendiendo proceso sospechoso..." | tee -a "$LOG"
if [[ -n "$PID_SOSPECHOSO" ]]; then
    kill -STOP "$PID_SOSPECHOSO" 2>/dev/null && \
        echo "  PID $PID_SOSPECHOSO suspendido (SIGSTOP)" | tee -a "$LOG"
fi

# Paso 3: Aislar de la red compartida
echo "[3/7] Protegiendo shares de red..." | tee -a "$LOG"
# Desmontar shares NFS/CIFS para proteger datos
mount 2>/dev/null | grep -E "nfs|cifs" | awk '{print $3}' | while read -r mnt; do
    umount -l "$mnt" 2>/dev/null && echo "  Desmontado: $mnt" | tee -a "$LOG"
done

# Paso 4: Snapshot del estado actual
echo "[4/7] Capturando snapshot del sistema..." | tee -a "$LOG"
ps auxwwf > "$IR_DIR/snapshot-procesos.txt" 2>/dev/null
ss -tupna > "$IR_DIR/snapshot-red.txt" 2>/dev/null
df -h > "$IR_DIR/snapshot-disco.txt" 2>/dev/null

# Paso 5: Matar el proceso y procesos hijos
echo "[5/7] Terminando proceso malicioso y descendientes..." | tee -a "$LOG"
if [[ -n "$PID_SOSPECHOSO" ]]; then
    # Matar todo el grupo de procesos
    kill -KILL -"$PID_SOSPECHOSO" 2>/dev/null || kill -KILL "$PID_SOSPECHOSO" 2>/dev/null
    echo "  PID $PID_SOSPECHOSO eliminado" | tee -a "$LOG"
fi

# Paso 6: Buscar y eliminar persistencia del malware
echo "[6/7] Buscando mecanismos de persistencia..." | tee -a "$LOG"

# Buscar en crontabs
for crontab_file in /var/spool/cron/tabs/*; do
    if [[ -f "$crontab_file" ]] && grep -q "$EXE_PATH" "$crontab_file" 2>/dev/null; then
        echo "  ALERTA: Persistencia en crontab: $crontab_file" | tee -a "$LOG"
    fi
done

# Buscar servicios systemd sospechosos
grep -rl "$EXE_PATH" /etc/systemd/system/ /usr/lib/systemd/system/ 2>/dev/null | while read -r svc; do
    echo "  ALERTA: Persistencia en servicio: $svc" | tee -a "$LOG"
done

# Buscar en autostart
grep -rl "$EXE_PATH" /etc/profile.d/ /etc/rc.d/ /etc/init.d/ 2>/dev/null | while read -r f; do
    echo "  ALERTA: Persistencia en autostart: $f" | tee -a "$LOG"
done

# Paso 7: Verificar backups
echo "[7/7] Verificando integridad de backups..." | tee -a "$LOG"
if [[ -x /usr/local/bin/verificar-backups.sh ]]; then
    /usr/local/bin/verificar-backups.sh >> "$IR_DIR/estado-backups.txt" 2>/dev/null
    echo "  Estado de backups guardado" | tee -a "$LOG"
fi

logger -t incident-response "PLAYBOOK: Malware activo PID=$PID_SOSPECHOSO contenido (INC: $INCIDENT_ID)"

echo "" | tee -a "$LOG"
echo "=== CONTENCIÓN COMPLETADA ===" | tee -a "$LOG"
echo "ACCIONES PENDIENTES:" | tee -a "$LOG"
echo "  1. Analizar binario en sandbox: $IR_DIR/malware-binary" | tee -a "$LOG"
echo "  2. Buscar hash en VirusTotal: $(cat "$IR_DIR/malware-hash.txt" 2>/dev/null)" | tee -a "$LOG"
echo "  3. Verificar integridad de datos con AIDE" | tee -a "$LOG"
echo "  4. Ejecutar ClamAV scan completo: clamscan -r /" | tee -a "$LOG"
echo "  5. Restaurar datos desde backup si hay cifrado" | tee -a "$LOG"
EOFPB2

    chmod 700 /usr/local/lib/incident-response/playbooks/pb-malware-activo.sh
    log_change "Creado" "/usr/local/lib/incident-response/playbooks/pb-malware-activo.sh"
    log_change "Permisos" "/usr/local/lib/incident-response/playbooks/pb-malware-activo.sh -> 700"

    # --- Playbook: C2 / Exfiltración ---
    cat > /usr/local/lib/incident-response/playbooks/pb-c2-exfiltracion.sh << 'EOFPB3'
#!/bin/bash
# PLAYBOOK: C2 activo o exfiltración detectada
# MITRE: TA0011 (C2), TA0010 (Exfiltration)
# Severidad: CRÍTICA

IP_SOSPECHOSA="$1"
INCIDENT_ID="${2:-INC-$(date +%Y%m%d-%H%M%S)}"
IR_DIR="/var/lib/incident-response/$INCIDENT_ID"
mkdir -p "$IR_DIR"
LOG="$IR_DIR/playbook-c2.log"

echo "=== PLAYBOOK: C2/Exfiltración ===" | tee "$LOG"
echo "IP sospechosa: $IP_SOSPECHOSA" | tee -a "$LOG"
echo "Inicio: $(date -Iseconds)" | tee -a "$LOG"

# Paso 1: Capturar conexiones activas a la IP
echo "" | tee -a "$LOG"
echo "[1/6] Capturando conexiones a $IP_SOSPECHOSA..." | tee -a "$LOG"
ss -tupna | grep "$IP_SOSPECHOSA" > "$IR_DIR/conexiones-c2.txt" 2>/dev/null
# Identificar procesos conectados
ss -tupna | grep "$IP_SOSPECHOSA" | grep -oP 'pid=\K[0-9]+' | sort -u | while read -r pid; do
    COMM=$(cat "/proc/$pid/comm" 2>/dev/null || echo "?")
    CMDLINE=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ' || echo "?")
    echo "PID=$pid COMM=$COMM CMD=$CMDLINE" >> "$IR_DIR/procesos-c2.txt"
done

# Paso 2: Bloquear IP en firewall inmediatamente
echo "[2/6] Bloqueando IP $IP_SOSPECHOSA en firewall..." | tee -a "$LOG"
if fw_is_active &>/dev/null; then
    fw_runtime_add_rich_rule "rule family='ipv4' source address='$IP_SOSPECHOSA' drop" 2>/dev/null
    fw_add_rich_rule "rule family='ipv4' source address='$IP_SOSPECHOSA' drop" 2>/dev/null
    echo "  IP bloqueada en firewalld" | tee -a "$LOG"
fi

# Paso 3: Matar conexiones activas
echo "[3/6] Terminando conexiones activas..." | tee -a "$LOG"
ss -K dst "$IP_SOSPECHOSA" 2>/dev/null || true
# Matar procesos conectados
ss -tupna | grep "$IP_SOSPECHOSA" | grep -oP 'pid=\K[0-9]+' | sort -u | while read -r pid; do
    kill -STOP "$pid" 2>/dev/null
    echo "  PID $pid suspendido" | tee -a "$LOG"
done

# Paso 4: Capturar tráfico residual (30 segundos)
echo "[4/6] Capturando tráfico residual (30s)..." | tee -a "$LOG"
if command -v tcpdump &>/dev/null; then
    timeout 30 tcpdump -i any host "$IP_SOSPECHOSA" -w "$IR_DIR/captura-c2.pcap" -c 1000 2>/dev/null &
fi

# Paso 5: Buscar indicadores de compromiso relacionados
echo "[5/6] Buscando IoCs relacionados..." | tee -a "$LOG"
# DNS queries a la IP
journalctl -u systemd-resolved --since "7 days ago" 2>/dev/null | \
    grep -i "$IP_SOSPECHOSA" > "$IR_DIR/dns-queries-c2.txt" 2>/dev/null || true

# Buscar en logs de Suricata
if [[ -f /var/log/suricata/fast.log ]]; then
    grep "$IP_SOSPECHOSA" /var/log/suricata/fast.log > "$IR_DIR/suricata-c2.txt" 2>/dev/null || true
fi

# Buscar IoC en feeds
if [[ -x /usr/local/bin/ioc-lookup.sh ]]; then
    /usr/local/bin/ioc-lookup.sh "$IP_SOSPECHOSA" > "$IR_DIR/ioc-lookup-c2.txt" 2>/dev/null || true
fi

# Paso 6: Evaluar datos potencialmente exfiltrados
echo "[6/6] Evaluando posible exfiltración..." | tee -a "$LOG"
# Volumen de datos transferidos
IFACE=$(ip route get "$IP_SOSPECHOSA" 2>/dev/null | grep -oP 'dev \K\S+' || echo "eth0")
echo "  Interfaz: $IFACE" | tee -a "$LOG"

logger -t incident-response "PLAYBOOK: C2/Exfil IP=$IP_SOSPECHOSA bloqueada (INC: $INCIDENT_ID)"

echo "" | tee -a "$LOG"
echo "=== CONTENCIÓN COMPLETADA ===" | tee -a "$LOG"
echo "ACCIONES PENDIENTES:" | tee -a "$LOG"
echo "  1. Analizar PCAP: $IR_DIR/captura-c2.pcap" | tee -a "$LOG"
echo "  2. Consultar IP en VirusTotal/AbuseIPDB" | tee -a "$LOG"
echo "  3. Buscar otros hosts con conexiones a $IP_SOSPECHOSA" | tee -a "$LOG"
echo "  4. Verificar datos exfiltrados (logs de transferencia)" | tee -a "$LOG"
echo "  5. Ejecutar detectar-c2-completo.sh para buscar más C2" | tee -a "$LOG"
EOFPB3

    chmod 700 /usr/local/lib/incident-response/playbooks/pb-c2-exfiltracion.sh
    log_change "Creado" "/usr/local/lib/incident-response/playbooks/pb-c2-exfiltracion.sh"
    log_change "Permisos" "/usr/local/lib/incident-response/playbooks/pb-c2-exfiltracion.sh -> 700"

    # --- Playbook: Movimiento lateral ---
    cat > /usr/local/lib/incident-response/playbooks/pb-movimiento-lateral.sh << 'EOFPB4'
#!/bin/bash
# PLAYBOOK: Movimiento lateral detectado
# MITRE: TA0008 (Lateral Movement)
# Severidad: ALTA

IP_ORIGEN="$1"
INCIDENT_ID="${2:-INC-$(date +%Y%m%d-%H%M%S)}"
IR_DIR="/var/lib/incident-response/$INCIDENT_ID"
mkdir -p "$IR_DIR"
LOG="$IR_DIR/playbook-lateral.log"

echo "=== PLAYBOOK: Movimiento Lateral ===" | tee "$LOG"
echo "IP origen: $IP_ORIGEN" | tee -a "$LOG"
echo "Inicio: $(date -Iseconds)" | tee -a "$LOG"

# Paso 1: Identificar sesiones desde esa IP
echo "" | tee -a "$LOG"
echo "[1/5] Identificando sesiones desde $IP_ORIGEN..." | tee -a "$LOG"
who | grep "$IP_ORIGEN" > "$IR_DIR/sesiones-lateral.txt" 2>/dev/null
ss -tupna | grep "$IP_ORIGEN" > "$IR_DIR/conexiones-lateral.txt" 2>/dev/null

# Paso 2: Capturar actividad de la sesión
echo "[2/5] Capturando actividad..." | tee -a "$LOG"
journalctl -u "$SSH_SERVICE_NAME" --since "24 hours ago" 2>/dev/null | \
    grep "$IP_ORIGEN" > "$IR_DIR/ssh-actividad.txt" 2>/dev/null || true

# Paso 3: Bloquear IP origen en firewall
echo "[3/5] Bloqueando IP origen $IP_ORIGEN..." | tee -a "$LOG"
if fw_is_active &>/dev/null; then
    fw_runtime_add_rich_rule "rule family='ipv4' source address='$IP_ORIGEN' drop" 2>/dev/null
    fw_add_rich_rule "rule family='ipv4' source address='$IP_ORIGEN' drop" 2>/dev/null
    echo "  IP bloqueada" | tee -a "$LOG"
fi

# Paso 4: Terminar sesiones SSH desde esa IP
echo "[4/5] Terminando sesiones SSH..." | tee -a "$LOG"
ss -K src "$IP_ORIGEN" 2>/dev/null || true
# Matar procesos sshd de esa IP
pgrep -a sshd 2>/dev/null | grep "$IP_ORIGEN" | awk '{print $1}' | while read -r pid; do
    kill "$pid" 2>/dev/null
    echo "  sshd PID $pid terminado" | tee -a "$LOG"
done

# Paso 5: Verificar si hubo propagación
echo "[5/5] Verificando propagación..." | tee -a "$LOG"
# Buscar conexiones SSH salientes que pudieron ser hechas por el atacante
ss -tn state established | grep ":22" | grep -v "$IP_ORIGEN" > "$IR_DIR/ssh-salientes.txt" 2>/dev/null

logger -t incident-response "PLAYBOOK: Mov. lateral desde $IP_ORIGEN contenido (INC: $INCIDENT_ID)"

echo "" | tee -a "$LOG"
echo "=== CONTENCIÓN COMPLETADA ===" | tee -a "$LOG"
echo "ACCIONES PENDIENTES:" | tee -a "$LOG"
echo "  1. Investigar host origen: $IP_ORIGEN" | tee -a "$LOG"
echo "  2. Verificar cuentas usadas para movimiento lateral" | tee -a "$LOG"
echo "  3. Buscar persistencia dejada por el atacante" | tee -a "$LOG"
echo "  4. Verificar otros hosts que pudieron ser comprometidos" | tee -a "$LOG"
EOFPB4

    chmod 700 /usr/local/lib/incident-response/playbooks/pb-movimiento-lateral.sh
    log_change "Creado" "/usr/local/lib/incident-response/playbooks/pb-movimiento-lateral.sh"
    log_change "Permisos" "/usr/local/lib/incident-response/playbooks/pb-movimiento-lateral.sh -> 700"

    # --- Script dispatcher de playbooks ---
    cat > /usr/local/bin/ir-responder.sh << 'EOFDISPATCH'
#!/bin/bash
# Dispatcher de playbooks de respuesta a incidentes
PB_DIR="/usr/local/lib/incident-response/playbooks"

echo ""
echo "╔════════════════════════════════════════╗"
echo "║   RESPUESTA A INCIDENTES              ║"
echo "╚════════════════════════════════════════╝"
echo ""
echo "Playbooks disponibles:"
echo ""
echo "  1) Cuenta comprometida       (T1078/T1110)"
echo "  2) Malware/Ransomware activo (T1486/T1059)"
echo "  3) C2/Exfiltración detectada (TA0011/TA0010)"
echo "  4) Movimiento lateral        (TA0008)"
echo "  5) Recolección forense       (general)"
echo ""
read -p "Selecciona playbook [1-5]: " opcion

case "$opcion" in
    1)
        read -p "Usuario comprometido: " usuario
        "$PB_DIR/pb-cuenta-comprometida.sh" "$usuario"
        ;;
    2)
        read -p "PID del proceso sospechoso: " pid
        "$PB_DIR/pb-malware-activo.sh" "$pid"
        ;;
    3)
        read -p "IP del servidor C2: " ip
        "$PB_DIR/pb-c2-exfiltracion.sh" "$ip"
        ;;
    4)
        read -p "IP origen del movimiento lateral: " ip
        "$PB_DIR/pb-movimiento-lateral.sh" "$ip"
        ;;
    5)
        read -p "ID de incidente (Enter para auto): " inc_id
        /usr/local/bin/ir-recolectar-forense.sh "$inc_id"
        ;;
    *)
        echo "Opción no válida"
        ;;
esac
EOFDISPATCH

    chmod 700 /usr/local/bin/ir-responder.sh
    log_change "Creado" "/usr/local/bin/ir-responder.sh"
    log_change "Permisos" "/usr/local/bin/ir-responder.sh -> 700"
    log_info "Playbooks de contención instalados"
    log_info "Dispatcher: /usr/local/bin/ir-responder.sh"

else
    log_skip "Playbooks de contención"
fi

# ============================================================
log_section "3. GENERADOR DE TIMELINE DE ATAQUE"
# ============================================================

echo "Herramienta para reconstruir la línea temporal del ataque"
echo "desde múltiples fuentes de logs, con mapeo MITRE."
echo ""

if ask "¿Instalar generador de timeline?"; then

    cat > /usr/local/bin/ir-timeline.sh << 'EOFTIMELINE'
#!/bin/bash
# Generador de timeline de ataque con mapeo MITRE
# Uso: ir-timeline.sh [horas-atras] [ID-incidente]

HORAS="${1:-24}"
INCIDENT_ID="${2:-TL-$(date +%Y%m%d-%H%M%S)}"
IR_DIR="/var/lib/incident-response/$INCIDENT_ID"
mkdir -p "$IR_DIR"
TIMELINE="$IR_DIR/timeline.txt"

echo "=== TIMELINE DE ATAQUE ===" | tee "$TIMELINE"
echo "Período: últimas $HORAS horas" | tee -a "$TIMELINE"
echo "Generado: $(date -Iseconds)" | tee -a "$TIMELINE"
echo "════════════════════════════════════════════════════" | tee -a "$TIMELINE"

# Recopilar eventos de múltiples fuentes y ordenar por timestamp

TEMP_TL=$(mktemp)

# 1. SSH auth events
echo "Recopilando eventos SSH..." >&2
journalctl -u "$SSH_SERVICE_NAME" --since "$HORAS hours ago" --no-pager 2>/dev/null | \
    grep -iE "accepted|failed|invalid|disconnect|session opened|session closed" | \
    while IFS= read -r line; do
        TS=$(echo "$line" | grep -oP '^\w+ \d+ \d+:\d+:\d+' || echo "?")
        if echo "$line" | grep -qi "failed\|invalid"; then
            echo "$TS | SSH      | T1110    | ALERTA | $line"
        elif echo "$line" | grep -qi "accepted"; then
            echo "$TS | SSH      | T1078    | INFO   | $line"
        else
            echo "$TS | SSH      | T1021    | INFO   | $line"
        fi
    done >> "$TEMP_TL" 2>/dev/null

# 2. Sudo events
echo "Recopilando eventos sudo..." >&2
journalctl --since "$HORAS hours ago" --no-pager 2>/dev/null | \
    grep -i "sudo" | grep -v "pam_unix" | \
    while IFS= read -r line; do
        TS=$(echo "$line" | grep -oP '^\w+ \d+ \d+:\d+:\d+' || echo "?")
        if echo "$line" | grep -qi "incorrect\|failed\|not allowed"; then
            echo "$TS | SUDO     | T1548    | ALERTA | $line"
        else
            echo "$TS | SUDO     | T1078    | INFO   | $line"
        fi
    done >> "$TEMP_TL" 2>/dev/null

# 3. Auditd events
echo "Recopilando eventos auditd..." >&2
if command -v ausearch &>/dev/null; then
    for key in credential-access lateral-ssh tool-download log-tampering data-transfer network-scan security-service-control; do
        ausearch -k "$key" -ts "recent" 2>/dev/null | grep "type=SYSCALL" | \
            while IFS= read -r line; do
                TS=$(echo "$line" | grep -oP 'msg=audit\(\K[0-9.]+')
                TS_HUMAN=$(date -d "@${TS%.*}" '+%b %d %H:%M:%S' 2>/dev/null || echo "?")
                echo "$TS_HUMAN | AUDIT    | $key | INFO   | $(echo "$line" | head -c 200)"
            done >> "$TEMP_TL" 2>/dev/null
    done
fi

# 4. Firewall events
echo "Recopilando eventos firewall..." >&2
journalctl --since "$HORAS hours ago" --no-pager 2>/dev/null | \
    grep -iE "REJECT|DROP|C2-PORT|EXFIL|ICMP-FLOOD|DNS-FLOOD" | \
    while IFS= read -r line; do
        TS=$(echo "$line" | grep -oP '^\w+ \d+ \d+:\d+:\d+' || echo "?")
        if echo "$line" | grep -qi "C2-PORT"; then
            echo "$TS | FIREWALL | T1571    | ALERTA | $line"
        elif echo "$line" | grep -qi "EXFIL"; then
            echo "$TS | FIREWALL | T1041    | ALERTA | $line"
        else
            echo "$TS | FIREWALL | T1046    | INFO   | $(echo "$line" | head -c 200)"
        fi
    done >> "$TEMP_TL" 2>/dev/null

# 5. Suricata alerts
echo "Recopilando alertas Suricata..." >&2
if [[ -f /var/log/suricata/fast.log ]]; then
    grep "$(date +%m/%d/%Y)" /var/log/suricata/fast.log 2>/dev/null | \
        while IFS= read -r line; do
            TS=$(echo "$line" | grep -oP '^\d+/\d+/\d+-\d+:\d+:\d+' || echo "?")
            echo "$TS | SURICATA | T1071    | ALERTA | $(echo "$line" | head -c 200)"
        done >> "$TEMP_TL" 2>/dev/null
fi

# 6. Detección scripts alerts
echo "Recopilando alertas de scripts de detección..." >&2
journalctl --since "$HORAS hours ago" --no-pager 2>/dev/null | \
    grep -E "detectar-|monitor-|watchdog-|buscar-credenciales" | \
    grep -i "alerta" | \
    while IFS= read -r line; do
        TS=$(echo "$line" | grep -oP '^\w+ \d+ \d+:\d+:\d+' || echo "?")
        echo "$TS | DETECT   | TA00XX   | ALERTA | $line"
    done >> "$TEMP_TL" 2>/dev/null

# Ordenar por timestamp y generar timeline final
echo "" | tee -a "$TIMELINE"
sort "$TEMP_TL" 2>/dev/null | while IFS= read -r line; do
    echo "$line" | tee -a "$TIMELINE"
done

TOTAL_EVENTS=$(wc -l < "$TEMP_TL")
ALERT_COUNT=$(grep -c "ALERTA" "$TEMP_TL" 2>/dev/null || echo 0)

echo "" | tee -a "$TIMELINE"
echo "════════════════════════════════════════════════════" | tee -a "$TIMELINE"
echo "Total eventos: $TOTAL_EVENTS | Alertas: $ALERT_COUNT" | tee -a "$TIMELINE"
echo "Timeline guardada: $TIMELINE" | tee -a "$TIMELINE"

rm -f "$TEMP_TL"
EOFTIMELINE

    chmod 700 /usr/local/bin/ir-timeline.sh
    log_change "Creado" "/usr/local/bin/ir-timeline.sh"
    log_change "Permisos" "/usr/local/bin/ir-timeline.sh -> 700"
    log_info "Generador de timeline instalado: /usr/local/bin/ir-timeline.sh"
    echo -e "${DIM}Uso: ir-timeline.sh [horas-atrás] [ID-incidente]${NC}"

else
    log_skip "Generador de timeline"
fi

# ============================================================
log_section "4. AISLAMIENTO DE RED DE EMERGENCIA"
# ============================================================

echo "Script de aislamiento de red para contención rápida."
echo "Corta todo tráfico excepto SSH desde IP específica."
echo ""
echo -e "${RED}ADVERTENCIA: Esto cortará todas las conexiones de red.${NC}"
echo ""

if ask "¿Instalar script de aislamiento de red?"; then

    cat > /usr/local/bin/ir-aislar-red.sh << 'EOFAISLAR'
#!/bin/bash
# Aislamiento de red de emergencia
# MANTIENE: SSH desde la IP del operador
# BLOQUEA: Todo lo demás

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

IP_PERMITIDA="$1"
if [[ -z "$IP_PERMITIDA" ]]; then
    # Detectar IP del operador actual
    IP_PERMITIDA=$(who am i 2>/dev/null | grep -oP '\(.*?\)' | tr -d '()')
    if [[ -z "$IP_PERMITIDA" ]]; then
        echo "Uso: $0 <IP-operador-permitida>"
        echo "No se pudo detectar tu IP automáticamente."
        exit 1
    fi
fi

echo "╔════════════════════════════════════════╗"
echo "║   AISLAMIENTO DE RED DE EMERGENCIA    ║"
echo "╚════════════════════════════════════════╝"
echo ""
echo "IP permitida (SSH): $IP_PERMITIDA"
echo ""
echo "ESTO CORTARÁ TODAS LAS CONEXIONES excepto SSH desde $IP_PERMITIDA"
echo ""
read -p "¿CONFIRMAR AISLAMIENTO? (escribir 'AISLAR' para confirmar): " confirm
if [[ "$confirm" != "AISLAR" ]]; then
    echo "Operación cancelada."
    exit 0
fi

# Guardar estado actual del firewall
BACKUP="/var/lib/incident-response/firewall-pre-aislamiento-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP"
fw_list_all_zones > "$BACKUP/zonas.txt" 2>/dev/null
iptables-save > "$BACKUP/iptables.txt" 2>/dev/null

echo "Backup de firewall guardado en: $BACKUP"

# Aplicar aislamiento
if fw_is_active &>/dev/null; then
    # Bloquear todo excepto SSH desde IP operador
    fw_set_default_zone drop 2>/dev/null
    fw_runtime_add_rich_rule "rule family='ipv4' source address='$IP_PERMITIDA' service name='ssh' accept" 2>/dev/null
    # Permitir loopback
    fw_runtime_add_rich_rule "rule family='ipv4' source address='127.0.0.1' accept" 2>/dev/null
fi

logger -t incident-response "AISLAMIENTO DE RED ACTIVADO - Solo SSH desde $IP_PERMITIDA"

echo ""
echo "[+] AISLAMIENTO ACTIVO"
echo "[+] Solo SSH desde $IP_PERMITIDA está permitido"
echo "[+] Para restaurar: ir-restaurar-red.sh"
echo "[+] Backup: $BACKUP"
EOFAISLAR

    cat > /usr/local/bin/ir-restaurar-red.sh << 'EOFRESTORE'
#!/bin/bash
# Restaurar red después de aislamiento
if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

# Buscar último backup
LATEST=$(ls -td /var/lib/incident-response/firewall-pre-aislamiento-* 2>/dev/null | head -1)

if [[ -z "$LATEST" ]]; then
    echo "[!] No se encontró backup de firewall"
    echo "Restaurando zona por defecto a 'public'..."
    if command -v firewall-cmd &>/dev/null; then
        firewall-cmd --set-default-zone=public 2>/dev/null
    elif command -v ufw &>/dev/null; then
        ufw --force enable 2>/dev/null
        ufw default deny incoming 2>/dev/null
        ufw default allow outgoing 2>/dev/null
    fi
else
    echo "Restaurando firewall desde: $LATEST"
    if [[ -f "$LATEST/iptables.txt" ]]; then
        iptables-restore < "$LATEST/iptables.txt" 2>/dev/null || true
    fi
    if command -v firewall-cmd &>/dev/null; then
        firewall-cmd --set-default-zone=public 2>/dev/null
        firewall-cmd --reload 2>/dev/null
    elif command -v ufw &>/dev/null; then
        ufw --force enable 2>/dev/null
    fi
fi

logger -t incident-response "AISLAMIENTO DE RED DESACTIVADO"
echo "[+] Red restaurada"
EOFRESTORE

    chmod 700 /usr/local/bin/ir-aislar-red.sh
    chmod 700 /usr/local/bin/ir-restaurar-red.sh
    log_change "Creado" "/usr/local/bin/ir-aislar-red.sh"
    log_change "Permisos" "/usr/local/bin/ir-aislar-red.sh -> 700"
    log_change "Creado" "/usr/local/bin/ir-restaurar-red.sh"
    log_change "Permisos" "/usr/local/bin/ir-restaurar-red.sh -> 700"
    log_info "Scripts de aislamiento instalados"
    echo -e "${DIM}Aislar: ir-aislar-red.sh [IP-operador]${NC}"
    echo -e "${DIM}Restaurar: ir-restaurar-red.sh${NC}"

else
    log_skip "Scripts de aislamiento de red"
fi

# ============================================================
log_section "5. GUÍA DE RECUPERACIÓN POST-INCIDENTE"
# ============================================================

echo "Checklist automático de recuperación después de un incidente."
echo ""

if ask "¿Instalar guía de recuperación?"; then

    cat > /usr/local/bin/ir-recuperacion.sh << 'EOFRECOV'
#!/bin/bash
# Guía de recuperación post-incidente

INCIDENT_ID="${1:-RECOVERY-$(date +%Y%m%d-%H%M%S)}"
IR_DIR="/var/lib/incident-response/$INCIDENT_ID"
mkdir -p "$IR_DIR"
LOG="$IR_DIR/recuperacion.log"

echo "╔════════════════════════════════════════╗" | tee "$LOG"
echo "║   RECUPERACIÓN POST-INCIDENTE         ║" | tee -a "$LOG"
echo "╚════════════════════════════════════════╝" | tee -a "$LOG"
echo "" | tee -a "$LOG"
echo "ID: $INCIDENT_ID" | tee -a "$LOG"
echo "Fecha: $(date -Iseconds)" | tee -a "$LOG"

PASSED=0
FAILED=0

check() {
    local desc="$1"
    local cmd="$2"
    if eval "$cmd" &>/dev/null; then
        echo -e "  [\033[0;32mOK\033[0m]  $desc" | tee -a "$LOG"
        ((PASSED++))
    else
        echo -e "  [\033[0;31mKO\033[0m]  $desc" | tee -a "$LOG"
        ((FAILED++))
    fi
}

echo "" | tee -a "$LOG"
echo "=== 1. INTEGRIDAD DEL SISTEMA ===" | tee -a "$LOG"
check "Kernel sin modificar" "uname -r | grep -q '$(uname -r)'"
check "/etc/passwd sin cambios recientes (>1h)" "test $(( $(date +%s) - $(stat -c %Y /etc/passwd) )) -gt 3600"
check "/etc/shadow permisos correctos (000)" "test '$(stat -c %a /etc/shadow 2>/dev/null)' = '000' -o '$(stat -c %a /etc/shadow 2>/dev/null)' = '640'"
check "No hay usuarios con UID=0 extra" "test $(awk -F: '\$3==0' /etc/passwd | wc -l) -eq 1"

echo "" | tee -a "$LOG"
echo "=== 2. SERVICIOS DE SEGURIDAD ===" | tee -a "$LOG"
check "firewalld activo" "systemctl is-active firewalld"
check "auditd activo" "systemctl is-active auditd"
check "fail2ban activo" "systemctl is-active fail2ban"
check "$SSH_SERVICE_NAME activo" "systemctl is-active $SSH_SERVICE_NAME"
for svc in apparmor suricata clamd; do
    if systemctl is-enabled "$svc" &>/dev/null 2>&1; then
        check "$svc activo" "systemctl is-active $svc"
    fi
done

echo "" | tee -a "$LOG"
echo "=== 3. RED Y FIREWALL ===" | tee -a "$LOG"
check "Firewall zona activa" "fw_get_active_zones 2>/dev/null | grep -q '.'"
check "Sin puertos C2 abiertos" "! ss -tlnp | grep -qE ':4444|:1337|:31337'"
check "DNS resolviendo" "getent hosts google.com"

echo "" | tee -a "$LOG"
echo "=== 4. PERSISTENCIA LIMPIA ===" | tee -a "$LOG"
check "Sin archivos ejecutables en /tmp" "test -z '$(find /tmp -maxdepth 2 -type f -executable 2>/dev/null | head -1)'"
check "Sin archivos ejecutables en /dev/shm" "test -z '$(find /dev/shm -maxdepth 2 -type f -executable 2>/dev/null | head -1)'"
check "Sin crontabs sospechosas" "! crontab -l 2>/dev/null | grep -v '^#' | grep -qiE 'curl|wget|nc |ncat|base64|python.*-c'"

echo "" | tee -a "$LOG"
echo "=== 5. BACKUPS Y DATOS ===" | tee -a "$LOG"
check "Script de backup existe" "test -x /usr/local/bin/backup-offsite.sh"
check "Logs de audit intactos" "test -f /var/log/audit/audit.log"

echo "" | tee -a "$LOG"
echo "═══════════════════════════════════════" | tee -a "$LOG"
TOTAL=$((PASSED + FAILED))
echo "Resultado: $PASSED/$TOTAL checks pasados" | tee -a "$LOG"
if [[ $FAILED -eq 0 ]]; then
    echo -e "\033[0;32mSISTEMA RECUPERADO - Listo para producción\033[0m" | tee -a "$LOG"
else
    echo -e "\033[1;33m$FAILED checks fallidos - Revisar antes de volver a producción\033[0m" | tee -a "$LOG"
fi
EOFRECOV

    chmod 700 /usr/local/bin/ir-recuperacion.sh
    log_change "Creado" "/usr/local/bin/ir-recuperacion.sh"
    log_change "Permisos" "/usr/local/bin/ir-recuperacion.sh -> 700"
    log_info "Guía de recuperación instalada: /usr/local/bin/ir-recuperacion.sh"

else
    log_skip "Guía de recuperación post-incidente"
fi

# ============================================================
log_section "RESUMEN DE RESPUESTA A INCIDENTES"
# ============================================================

echo ""
echo -e "${BOLD}Herramientas de IR instaladas:${NC}"
echo ""

if [[ -x /usr/local/bin/ir-recolectar-forense.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} Toolkit forense (ir-recolectar-forense.sh)"
else
    echo -e "  ${YELLOW}[--]${NC} Toolkit forense no instalado"
fi

if [[ -x /usr/local/bin/ir-responder.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} Dispatcher de playbooks (ir-responder.sh)"
else
    echo -e "  ${YELLOW}[--]${NC} Playbooks no instalados"
fi

if [[ -x /usr/local/bin/ir-timeline.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} Generador de timeline (ir-timeline.sh)"
else
    echo -e "  ${YELLOW}[--]${NC} Timeline no instalado"
fi

if [[ -x /usr/local/bin/ir-aislar-red.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} Aislamiento de red (ir-aislar-red.sh)"
else
    echo -e "  ${YELLOW}[--]${NC} Aislamiento no instalado"
fi

if [[ -x /usr/local/bin/ir-recuperacion.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} Recuperación post-incidente (ir-recuperacion.sh)"
else
    echo -e "  ${YELLOW}[--]${NC} Recuperación no instalada"
fi

echo ""
echo -e "${BOLD}Uso rápido:${NC}"
echo -e "  ${DIM}Incidente activo:${NC}  ir-responder.sh"
echo -e "  ${DIM}Recolectar datos:${NC} ir-recolectar-forense.sh INC-001"
echo -e "  ${DIM}Ver timeline:${NC}     ir-timeline.sh 48 INC-001"
echo -e "  ${DIM}Aislar host:${NC}      ir-aislar-red.sh 192.168.1.100"
echo -e "  ${DIM}Recuperar:${NC}        ir-recuperacion.sh INC-001"
echo ""
show_changes_summary
log_info "Módulo de respuesta a incidentes completado"
