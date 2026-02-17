#!/bin/bash
# ============================================================
# RESPUESTA A INCIDENTES - Operaciones de Seguridad
# Módulo 68 - Linux Multi-Distro (openSUSE, Debian/Ubuntu, RHEL/Fedora, Arch)
# ============================================================
# Secciones:
#   S1  - Toolkit de recolección forense
#   S2  - Playbooks de contención automática
#   S3  - Generador de timeline de ataque
#   S4  - Aislamiento de red de emergencia
#   S5  - Guía de recuperación post-incidente
#   S6  - Cadena de custodia digital
#   S7  - Extracción de IOCs
#   S8  - Comunicación y escalación
#   S9  - Hunting de IOCs en flota
#   S10 - Revisión post-incidente y métricas
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "respuesta-incidentes"
securizar_setup_traps

# ── Pre-check: detectar secciones ya aplicadas ──────────────
_precheck 10
_pc 'check_executable /usr/local/bin/ir-recolectar-forense.sh'
_pc 'check_executable /usr/local/bin/ir-responder.sh'
_pc 'check_executable /usr/local/bin/ir-timeline.sh'
_pc 'check_executable /usr/local/bin/ir-aislar-red.sh'
_pc 'check_executable /usr/local/bin/ir-recuperacion.sh'
_pc 'check_executable /usr/local/bin/ir-cadena-custodia.sh'
_pc 'check_executable /usr/local/bin/ir-extraer-iocs.sh'
_pc 'check_file_exists /usr/local/lib/incident-response/templates/notificacion-csirt.txt'
_pc 'check_executable /usr/local/bin/ir-hunt-fleet.sh'
_pc 'check_executable /usr/local/bin/ir-post-review.sh'
_precheck_result

IR_BASE="/var/lib/incident-response"
mkdir -p "$IR_BASE"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   RESPUESTA A INCIDENTES - Operaciones de Seguridad       ║"
echo "║   Contención, forense, timeline, IOCs, métricas IR        ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# ============================================================
# S1: TOOLKIT DE RECOLECCIÓN FORENSE
# ============================================================
log_section "S1: TOOLKIT DE RECOLECCIÓN FORENSE"

echo "Crear herramientas de recolección forense que preserven"
echo "datos volátiles del sistema ante un incidente activo."
echo ""
echo "Datos recolectados:"
echo "  - Procesos activos, conexiones de red, memoria"
echo "  - Archivos abiertos, módulos kernel, usuarios logueados"
echo "  - Logs del sistema, reglas de firewall, estado de servicios"
echo ""

if check_executable /usr/local/bin/ir-recolectar-forense.sh; then
    log_already "Toolkit de recolección forense"
elif ask "¿Instalar toolkit de recolección forense?"; then

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
# S2: PLAYBOOKS DE CONTENCIÓN AUTOMÁTICA
# ============================================================
log_section "S2: PLAYBOOKS DE CONTENCIÓN AUTOMÁTICA"

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

if check_executable /usr/local/bin/ir-responder.sh; then
    log_already "Playbooks de contención"
elif ask "¿Instalar playbooks de contención?"; then

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
if crontab -u "$USUARIO" -l 2>/dev/null | grep -v "^#" | grep -q "."; then
    crontab -u "$USUARIO" -r 2>/dev/null
    echo "  Crontab eliminada (backup en $IR_DIR)" | tee -a "$LOG"
fi
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

echo "" | tee -a "$LOG"
echo "[1/7] Recolectando info del proceso sospechoso..." | tee -a "$LOG"

if [[ -n "$PID_SOSPECHOSO" ]] && [[ -d "/proc/$PID_SOSPECHOSO" ]]; then
    cat "/proc/$PID_SOSPECHOSO/cmdline" 2>/dev/null | tr '\0' ' ' > "$IR_DIR/malware-cmdline.txt"
    readlink -f "/proc/$PID_SOSPECHOSO/exe" > "$IR_DIR/malware-exe-path.txt" 2>/dev/null
    cat "/proc/$PID_SOSPECHOSO/environ" 2>/dev/null | tr '\0' '\n' > "$IR_DIR/malware-environ.txt"
    cat "/proc/$PID_SOSPECHOSO/maps" > "$IR_DIR/malware-maps.txt" 2>/dev/null
    ls -la "/proc/$PID_SOSPECHOSO/fd/" > "$IR_DIR/malware-fds.txt" 2>/dev/null
    EXE_PATH=$(readlink -f "/proc/$PID_SOSPECHOSO/exe" 2>/dev/null)
    if [[ -f "$EXE_PATH" ]]; then
        cp "$EXE_PATH" "$IR_DIR/malware-binary" 2>/dev/null
        sha256sum "$EXE_PATH" > "$IR_DIR/malware-hash.txt" 2>/dev/null
        file "$EXE_PATH" > "$IR_DIR/malware-filetype.txt" 2>/dev/null
        echo "  Binario preservado: $EXE_PATH" | tee -a "$LOG"
    fi
fi

echo "[2/7] Suspendiendo proceso sospechoso..." | tee -a "$LOG"
if [[ -n "$PID_SOSPECHOSO" ]]; then
    kill -STOP "$PID_SOSPECHOSO" 2>/dev/null && \
        echo "  PID $PID_SOSPECHOSO suspendido (SIGSTOP)" | tee -a "$LOG"
fi

echo "[3/7] Protegiendo shares de red..." | tee -a "$LOG"
mount 2>/dev/null | grep -E "nfs|cifs" | awk '{print $3}' | while read -r mnt; do
    umount -l "$mnt" 2>/dev/null && echo "  Desmontado: $mnt" | tee -a "$LOG"
done

echo "[4/7] Capturando snapshot del sistema..." | tee -a "$LOG"
ps auxwwf > "$IR_DIR/snapshot-procesos.txt" 2>/dev/null
ss -tupna > "$IR_DIR/snapshot-red.txt" 2>/dev/null
df -h > "$IR_DIR/snapshot-disco.txt" 2>/dev/null

echo "[5/7] Terminando proceso malicioso y descendientes..." | tee -a "$LOG"
if [[ -n "$PID_SOSPECHOSO" ]]; then
    kill -KILL -"$PID_SOSPECHOSO" 2>/dev/null || kill -KILL "$PID_SOSPECHOSO" 2>/dev/null
    echo "  PID $PID_SOSPECHOSO eliminado" | tee -a "$LOG"
fi

echo "[6/7] Buscando mecanismos de persistencia..." | tee -a "$LOG"
for crontab_file in /var/spool/cron/tabs/*; do
    if [[ -f "$crontab_file" ]] && grep -q "$EXE_PATH" "$crontab_file" 2>/dev/null; then
        echo "  ALERTA: Persistencia en crontab: $crontab_file" | tee -a "$LOG"
    fi
done
grep -rl "$EXE_PATH" /etc/systemd/system/ /usr/lib/systemd/system/ 2>/dev/null | while read -r svc; do
    echo "  ALERTA: Persistencia en servicio: $svc" | tee -a "$LOG"
done
grep -rl "$EXE_PATH" /etc/profile.d/ /etc/rc.d/ /etc/init.d/ 2>/dev/null | while read -r f; do
    echo "  ALERTA: Persistencia en autostart: $f" | tee -a "$LOG"
done

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

echo "" | tee -a "$LOG"
echo "[1/6] Capturando conexiones a $IP_SOSPECHOSA..." | tee -a "$LOG"
ss -tupna | grep "$IP_SOSPECHOSA" > "$IR_DIR/conexiones-c2.txt" 2>/dev/null
ss -tupna | grep "$IP_SOSPECHOSA" | grep -oP 'pid=\K[0-9]+' | sort -u | while read -r pid; do
    COMM=$(cat "/proc/$pid/comm" 2>/dev/null || echo "?")
    CMDLINE=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ' || echo "?")
    echo "PID=$pid COMM=$COMM CMD=$CMDLINE" >> "$IR_DIR/procesos-c2.txt"
done

echo "[2/6] Bloqueando IP $IP_SOSPECHOSA en firewall..." | tee -a "$LOG"
if fw_is_active &>/dev/null; then
    fw_runtime_add_rich_rule "rule family='ipv4' source address='$IP_SOSPECHOSA' drop" 2>/dev/null
    fw_add_rich_rule "rule family='ipv4' source address='$IP_SOSPECHOSA' drop" 2>/dev/null
    echo "  IP bloqueada en firewalld" | tee -a "$LOG"
fi

echo "[3/6] Terminando conexiones activas..." | tee -a "$LOG"
ss -K dst "$IP_SOSPECHOSA" 2>/dev/null || true
ss -tupna | grep "$IP_SOSPECHOSA" | grep -oP 'pid=\K[0-9]+' | sort -u | while read -r pid; do
    kill -STOP "$pid" 2>/dev/null
    echo "  PID $pid suspendido" | tee -a "$LOG"
done

echo "[4/6] Capturando tráfico residual (30s)..." | tee -a "$LOG"
if command -v tcpdump &>/dev/null; then
    timeout 30 tcpdump -i any host "$IP_SOSPECHOSA" -w "$IR_DIR/captura-c2.pcap" -c 1000 2>/dev/null &
fi

echo "[5/6] Buscando IoCs relacionados..." | tee -a "$LOG"
journalctl -u systemd-resolved --since "7 days ago" 2>/dev/null | \
    grep -i "$IP_SOSPECHOSA" > "$IR_DIR/dns-queries-c2.txt" 2>/dev/null || true
if [[ -f /var/log/suricata/fast.log ]]; then
    grep "$IP_SOSPECHOSA" /var/log/suricata/fast.log > "$IR_DIR/suricata-c2.txt" 2>/dev/null || true
fi
if [[ -x /usr/local/bin/ioc-lookup.sh ]]; then
    /usr/local/bin/ioc-lookup.sh "$IP_SOSPECHOSA" > "$IR_DIR/ioc-lookup-c2.txt" 2>/dev/null || true
fi

echo "[6/6] Evaluando posible exfiltración..." | tee -a "$LOG"
IFACE=$(ip route get "$IP_SOSPECHOSA" 2>/dev/null | grep -oP 'dev \K\S+' || ip -o link show up 2>/dev/null | awk -F': ' '{print $2}' | grep -v lo | head -1)
IFACE="${IFACE:-$(ls /sys/class/net/ 2>/dev/null | grep -v lo | head -1)}"
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

echo "" | tee -a "$LOG"
echo "[1/5] Identificando sesiones desde $IP_ORIGEN..." | tee -a "$LOG"
who | grep "$IP_ORIGEN" > "$IR_DIR/sesiones-lateral.txt" 2>/dev/null
ss -tupna | grep "$IP_ORIGEN" > "$IR_DIR/conexiones-lateral.txt" 2>/dev/null

echo "[2/5] Capturando actividad..." | tee -a "$LOG"
journalctl -u "$SSH_SERVICE_NAME" --since "24 hours ago" 2>/dev/null | \
    grep "$IP_ORIGEN" > "$IR_DIR/ssh-actividad.txt" 2>/dev/null || true

echo "[3/5] Bloqueando IP origen $IP_ORIGEN..." | tee -a "$LOG"
if fw_is_active &>/dev/null; then
    fw_runtime_add_rich_rule "rule family='ipv4' source address='$IP_ORIGEN' drop" 2>/dev/null
    fw_add_rich_rule "rule family='ipv4' source address='$IP_ORIGEN' drop" 2>/dev/null
    echo "  IP bloqueada" | tee -a "$LOG"
fi

echo "[4/5] Terminando sesiones SSH..." | tee -a "$LOG"
ss -K src "$IP_ORIGEN" 2>/dev/null || true
pgrep -a sshd 2>/dev/null | grep "$IP_ORIGEN" | awk '{print $1}' | while read -r pid; do
    kill "$pid" 2>/dev/null
    echo "  sshd PID $pid terminado" | tee -a "$LOG"
done

echo "[5/5] Verificando propagación..." | tee -a "$LOG"
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
    log_info "Playbooks de contención instalados"

else
    log_skip "Playbooks de contención"
fi

# ============================================================
# S3: GENERADOR DE TIMELINE DE ATAQUE
# ============================================================
log_section "S3: GENERADOR DE TIMELINE DE ATAQUE"

echo "Herramienta para reconstruir la línea temporal del ataque"
echo "desde múltiples fuentes de logs, con mapeo MITRE."
echo ""

if check_executable /usr/local/bin/ir-timeline.sh; then
    log_already "Generador de timeline"
elif ask "¿Instalar generador de timeline?"; then

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
    log_info "Generador de timeline instalado: /usr/local/bin/ir-timeline.sh"

else
    log_skip "Generador de timeline"
fi

# ============================================================
# S4: AISLAMIENTO DE RED DE EMERGENCIA
# ============================================================
log_section "S4: AISLAMIENTO DE RED DE EMERGENCIA"

echo "Script de aislamiento de red para contención rápida."
echo "Corta todo tráfico excepto SSH desde IP específica."
echo ""
echo -e "${RED}ADVERTENCIA: Esto cortará todas las conexiones de red.${NC}"
echo ""

if check_executable /usr/local/bin/ir-aislar-red.sh; then
    log_already "Scripts de aislamiento de red"
elif ask "¿Instalar script de aislamiento de red?"; then

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

BACKUP="/var/lib/incident-response/firewall-pre-aislamiento-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP"
fw_list_all_zones > "$BACKUP/zonas.txt" 2>/dev/null
iptables-save > "$BACKUP/iptables.txt" 2>/dev/null

echo "Backup de firewall guardado en: $BACKUP"

if fw_is_active &>/dev/null; then
    fw_set_default_zone drop 2>/dev/null
    fw_runtime_add_rich_rule "rule family='ipv4' source address='$IP_PERMITIDA' service name='ssh' accept" 2>/dev/null
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
    log_change "Creado" "/usr/local/bin/ir-restaurar-red.sh"
    log_info "Scripts de aislamiento instalados"

else
    log_skip "Scripts de aislamiento de red"
fi

# ============================================================
# S5: GUÍA DE RECUPERACIÓN POST-INCIDENTE
# ============================================================
log_section "S5: GUÍA DE RECUPERACIÓN POST-INCIDENTE"

echo "Checklist automático de recuperación después de un incidente."
echo ""

if check_executable /usr/local/bin/ir-recuperacion.sh; then
    log_already "Guía de recuperación post-incidente"
elif ask "¿Instalar guía de recuperación?"; then

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
    log_info "Guía de recuperación instalada: /usr/local/bin/ir-recuperacion.sh"

else
    log_skip "Guía de recuperación post-incidente"
fi

# ============================================================
# S6: CADENA DE CUSTODIA DIGITAL
# ============================================================
log_section "S6: CADENA DE CUSTODIA DIGITAL"

echo "Gestión formal de cadena de custodia para evidencia digital."
echo "Sellado con SHA-256/SHA-512 y opcionalmente GPG."
echo "Complementa módulo 44 (forense avanzado)."
echo ""

if check_executable /usr/local/bin/ir-cadena-custodia.sh; then
    log_already "Cadena de custodia digital"
elif ask "¿Instalar herramienta de cadena de custodia?"; then

    cat > /usr/local/bin/ir-cadena-custodia.sh << 'EOFCUSTODIA'
#!/bin/bash
# ============================================================
# CADENA DE CUSTODIA DIGITAL
# Sellado, verificación e integridad de evidencia
# Uso: ir-cadena-custodia.sh [seal DIR|verify DIR|transfer DIR DESTINO]
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

case "${1:-help}" in
    seal)
        DIR="${2:?Uso: $0 seal DIRECTORIO}"
        if [[ ! -d "$DIR" ]]; then echo "Directorio no existe: $DIR"; exit 1; fi

        MANIFEST="$DIR/CADENA-CUSTODIA.txt"
        echo "═══════════════════════════════════════" > "$MANIFEST"
        echo "CADENA DE CUSTODIA DIGITAL" >> "$MANIFEST"
        echo "═══════════════════════════════════════" >> "$MANIFEST"
        echo "Fecha sellado: $(date -Iseconds)" >> "$MANIFEST"
        echo "Operador: $(whoami)" >> "$MANIFEST"
        echo "Hostname: $(hostname)" >> "$MANIFEST"
        echo "Kernel: $(uname -r)" >> "$MANIFEST"
        echo "" >> "$MANIFEST"

        # Generar hashes SHA-256 y SHA-512
        echo "=== HASHES SHA-256 ===" >> "$MANIFEST"
        find "$DIR" -type f ! -name "CADENA-CUSTODIA.txt" ! -name "*.sig" -exec sha256sum {} \; >> "$MANIFEST" 2>/dev/null
        echo "" >> "$MANIFEST"
        echo "=== HASHES SHA-512 ===" >> "$MANIFEST"
        find "$DIR" -type f ! -name "CADENA-CUSTODIA.txt" ! -name "*.sig" -exec sha512sum {} \; >> "$MANIFEST" 2>/dev/null

        TOTAL_FILES=$(find "$DIR" -type f ! -name "CADENA-CUSTODIA.txt" ! -name "*.sig" | wc -l)
        TOTAL_SIZE=$(du -sh "$DIR" | awk '{print $1}')
        echo "" >> "$MANIFEST"
        echo "Total archivos: $TOTAL_FILES" >> "$MANIFEST"
        echo "Tamaño total: $TOTAL_SIZE" >> "$MANIFEST"
        echo "Fin sellado: $(date -Iseconds)" >> "$MANIFEST"

        # Firma GPG si disponible
        if command -v gpg &>/dev/null; then
            DEFAULT_KEY=$(gpg --list-secret-keys --keyid-format long 2>/dev/null | grep "^sec" | head -1 | awk '{print $2}' | cut -d/ -f2)
            if [[ -n "$DEFAULT_KEY" ]]; then
                gpg --detach-sign --armor "$MANIFEST" 2>/dev/null && \
                    echo -e "${GREEN}Firmado con GPG (key: $DEFAULT_KEY)${NC}"
            else
                echo -e "${DIM}Sin clave GPG para firma (opcional)${NC}"
            fi
        fi

        echo -e "${GREEN}Evidencia sellada: $TOTAL_FILES archivos ($TOTAL_SIZE)${NC}"
        echo -e "${DIM}Manifiesto: $MANIFEST${NC}"
        logger -t ir-custodia "Evidence sealed: $DIR ($TOTAL_FILES files)"
        ;;

    verify)
        DIR="${2:?Uso: $0 verify DIRECTORIO}"
        MANIFEST="$DIR/CADENA-CUSTODIA.txt"
        if [[ ! -f "$MANIFEST" ]]; then
            echo -e "${RED}No hay manifiesto de custodia en $DIR${NC}"
            exit 1
        fi

        echo -e "${BOLD}=== VERIFICACIÓN DE CADENA DE CUSTODIA ===${NC}"
        echo ""

        # Verificar firma GPG
        if [[ -f "${MANIFEST}.asc" ]] && command -v gpg &>/dev/null; then
            if gpg --verify "${MANIFEST}.asc" "$MANIFEST" 2>/dev/null; then
                echo -e "${GREEN}OK${NC} Firma GPG válida"
            else
                echo -e "${RED}ALERTA: Firma GPG inválida${NC}"
            fi
        fi

        # Verificar hashes SHA-256
        FAILURES=0
        echo -e "\n${CYAN}Verificando SHA-256...${NC}"
        while IFS= read -r line; do
            HASH=$(echo "$line" | awk '{print $1}')
            FILE=$(echo "$line" | awk '{$1=""; print $0}' | sed 's/^ *//')
            if [[ -f "$FILE" ]]; then
                ACTUAL=$(sha256sum "$FILE" | awk '{print $1}')
                if [[ "$HASH" == "$ACTUAL" ]]; then
                    echo -e "  ${GREEN}OK${NC}  $(basename "$FILE")"
                else
                    echo -e "  ${RED}ALTERADO${NC}  $(basename "$FILE")"
                    FAILURES=$((FAILURES + 1))
                fi
            else
                echo -e "  ${RED}FALTA${NC}  $(basename "$FILE")"
                FAILURES=$((FAILURES + 1))
            fi
        done < <(sed -n '/=== HASHES SHA-256 ===/,/^$/p' "$MANIFEST" | grep -v "^===" | grep -v "^$")

        echo ""
        if [[ $FAILURES -eq 0 ]]; then
            echo -e "${GREEN}INTEGRIDAD VERIFICADA - Sin alteraciones${NC}"
        else
            echo -e "${RED}$FAILURES archivos alterados o faltantes${NC}"
        fi
        ;;

    transfer)
        DIR="${2:?Uso: $0 transfer DIRECTORIO DESTINO}"
        DEST="${3:?Falta destino}"
        MANIFEST="$DIR/CADENA-CUSTODIA.txt"

        echo "=== TRANSFERENCIA ===" >> "$MANIFEST"
        echo "Fecha: $(date -Iseconds)" >> "$MANIFEST"
        echo "Origen: $(whoami)@$(hostname)" >> "$MANIFEST"
        echo "Destino: $DEST" >> "$MANIFEST"
        echo "Método: $(basename "$0")" >> "$MANIFEST"

        echo -e "${CYAN}Transferencia registrada en manifiesto${NC}"
        logger -t ir-custodia "Evidence transfer registered: $DIR -> $DEST"
        ;;

    *)
        echo "Uso: $0 {seal DIR|verify DIR|transfer DIR DESTINO}"
        echo ""
        echo "  seal DIR       - Sellar directorio con hashes + GPG"
        echo "  verify DIR     - Verificar integridad de evidencia"
        echo "  transfer DIR D - Registrar transferencia de custodia"
        ;;
esac
EOFCUSTODIA

    chmod 755 /usr/local/bin/ir-cadena-custodia.sh
    log_change "Creado" "/usr/local/bin/ir-cadena-custodia.sh"
    log_info "Cadena de custodia instalada: ir-cadena-custodia.sh"

else
    log_skip "Cadena de custodia digital"
fi

# ============================================================
# S7: EXTRACCIÓN DE IOCs
# ============================================================
log_section "S7: EXTRACCIÓN DE IOCs"

echo "Extrae Indicadores de Compromiso de evidencia recolectada."
echo "Formatos: texto, CSV, STIX 2.1 simplificado."
echo "Integra con módulos 35 (ioc-lookup), 23 (YARA), 33 (retrospectivo)."
echo ""

if check_executable /usr/local/bin/ir-extraer-iocs.sh; then
    log_already "Extracción de IOCs"
elif ask "¿Instalar extractor de IOCs?"; then

    cat > /usr/local/bin/ir-extraer-iocs.sh << 'EOFIOCS'
#!/bin/bash
# ============================================================
# EXTRACCIÓN DE IOCs DE EVIDENCIA
# Uso: ir-extraer-iocs.sh DIRECTORIO [--format csv|stix|text]
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

DIR="${1:?Uso: $0 DIRECTORIO [--format csv|stix|text]}"
FORMAT="text"
[[ "${2:-}" == "--format" ]] && FORMAT="${3:-text}"

if [[ ! -d "$DIR" ]]; then echo "Directorio no existe: $DIR"; exit 1; fi

IOC_DIR="$DIR/iocs"
mkdir -p "$IOC_DIR"

echo -e "${BOLD}=== EXTRACCIÓN DE IOCs ===${NC}"
echo -e "${DIM}Directorio: $DIR${NC}"
echo ""

# Extraer IPs (IPv4)
echo -e "${CYAN}Extrayendo IPs...${NC}"
grep -rhoP '\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b' "$DIR" 2>/dev/null | \
    grep -v -E '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|0\.|255\.)' | \
    sort -u > "$IOC_DIR/iocs-ips.txt"
IP_COUNT=$(wc -l < "$IOC_DIR/iocs-ips.txt")
echo "  IPs externas únicas: $IP_COUNT"

# Extraer dominios
echo -e "${CYAN}Extrayendo dominios...${NC}"
grep -rhoP '[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}' "$DIR" 2>/dev/null | \
    grep -v -E '\.(sh|txt|log|conf|json|xml|html|css|js|py|c|h|md|cfg|bak|old)$' | \
    sort -u > "$IOC_DIR/iocs-domains.txt"
DOM_COUNT=$(wc -l < "$IOC_DIR/iocs-domains.txt")
echo "  Dominios únicos: $DOM_COUNT"

# Extraer hashes (MD5, SHA1, SHA256)
echo -e "${CYAN}Extrayendo hashes...${NC}"
grep -rhoP '\b[a-fA-F0-9]{64}\b' "$DIR" 2>/dev/null | sort -u > "$IOC_DIR/iocs-sha256.txt"
grep -rhoP '\b[a-fA-F0-9]{40}\b' "$DIR" 2>/dev/null | sort -u > "$IOC_DIR/iocs-sha1.txt"
grep -rhoP '\b[a-fA-F0-9]{32}\b' "$DIR" 2>/dev/null | sort -u > "$IOC_DIR/iocs-md5.txt"
SHA256_COUNT=$(wc -l < "$IOC_DIR/iocs-sha256.txt")
echo "  SHA-256: $SHA256_COUNT"

# Extraer URLs
echo -e "${CYAN}Extrayendo URLs...${NC}"
grep -rhoP 'https?://[^\s"<>]+' "$DIR" 2>/dev/null | sort -u > "$IOC_DIR/iocs-urls.txt"
URL_COUNT=$(wc -l < "$IOC_DIR/iocs-urls.txt")
echo "  URLs: $URL_COUNT"

# Formato de salida
case "$FORMAT" in
    csv)
        CSV="$IOC_DIR/iocs-all.csv"
        echo "type,value,source" > "$CSV"
        while read -r ip; do echo "ipv4,$ip,evidence" >> "$CSV"; done < "$IOC_DIR/iocs-ips.txt"
        while read -r dom; do echo "domain,$dom,evidence" >> "$CSV"; done < "$IOC_DIR/iocs-domains.txt"
        while read -r hash; do echo "sha256,$hash,evidence" >> "$CSV"; done < "$IOC_DIR/iocs-sha256.txt"
        while read -r url; do echo "url,$url,evidence" >> "$CSV"; done < "$IOC_DIR/iocs-urls.txt"
        echo -e "${GREEN}CSV generado: $CSV${NC}"
        ;;
    stix)
        STIX="$IOC_DIR/iocs-stix.json"
        cat > "$STIX" << EOFSTIX
{
  "type": "bundle",
  "id": "bundle--$(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "unknown")",
  "objects": [
    {
      "type": "indicator",
      "id": "indicator--$(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "unknown")",
      "created": "$(date -Iseconds)",
      "name": "IOCs extraídos de evidencia",
      "description": "IOCs extraídos automáticamente de $DIR",
      "pattern": "[ipv4-addr:value IN ($(head -10 "$IOC_DIR/iocs-ips.txt" | tr '\n' ',' | sed 's/,$//'))]",
      "pattern_type": "stix",
      "valid_from": "$(date -Iseconds)"
    }
  ]
}
EOFSTIX
        echo -e "${GREEN}STIX 2.1 generado: $STIX${NC}"
        ;;
    *)
        echo ""
        echo -e "${BOLD}Resumen de IOCs:${NC}"
        echo "  IPs: $IP_COUNT | Dominios: $DOM_COUNT | SHA-256: $SHA256_COUNT | URLs: $URL_COUNT"
        ;;
esac

# Consultar feeds si disponible
if [[ -x /usr/local/bin/ioc-lookup.sh ]] && [[ "$IP_COUNT" -gt 0 ]]; then
    echo ""
    echo -e "${CYAN}Consultando IOC feeds (primeras 5 IPs)...${NC}"
    head -5 "$IOC_DIR/iocs-ips.txt" | while read -r ip; do
        /usr/local/bin/ioc-lookup.sh "$ip" 2>/dev/null | head -1 || true
    done
fi

echo ""
echo -e "${DIM}IOCs guardados en: $IOC_DIR/${NC}"
logger -t ir-iocs "IOCs extracted: $IP_COUNT IPs, $DOM_COUNT domains, $SHA256_COUNT hashes"
EOFIOCS

    chmod 755 /usr/local/bin/ir-extraer-iocs.sh
    log_change "Creado" "/usr/local/bin/ir-extraer-iocs.sh"
    log_info "Extractor de IOCs instalado: ir-extraer-iocs.sh DIR [--format csv|stix]"

else
    log_skip "Extracción de IOCs"
fi

# ============================================================
# S8: COMUNICACIÓN Y ESCALACIÓN
# ============================================================
log_section "S8: COMUNICACIÓN Y ESCALACIÓN"

echo "Plantillas de notificación y matriz de escalación."
echo "4 plantillas: CSIRT/FIRST, gerencia, legal, usuarios."
echo ""

if check_file_exists /usr/local/lib/incident-response/templates/notificacion-csirt.txt; then
    log_already "Templates de comunicación"
elif ask "¿Instalar templates de comunicación y escalación?"; then

    mkdir -p /usr/local/lib/incident-response/templates
    log_change "Creado" "/usr/local/lib/incident-response/templates/"

    # Template CSIRT
    cat > /usr/local/lib/incident-response/templates/notificacion-csirt.txt << 'EOFCSIRT'
NOTIFICACIÓN DE INCIDENTE DE SEGURIDAD - CSIRT/FIRST
=====================================================

Fecha/Hora detección: [FECHA]
ID Incidente: [INC-ID]
Severidad: [BAJA|MEDIA|ALTA|CRÍTICA]
Estado: [DETECTADO|CONTENIDO|ERRADICADO|RECUPERADO]

DESCRIPCIÓN:
[Breve descripción del incidente]

SISTEMAS AFECTADOS:
- Hostname: [HOSTNAME]
- IP: [IP]
- SO: [SISTEMA OPERATIVO]
- Servicio: [SERVICIO AFECTADO]

TÁCTICAS MITRE ATT&CK:
- [TA00XX - Nombre]

IOCs IDENTIFICADOS:
- IPs: [IP_LIST]
- Hashes: [HASH_LIST]
- Dominios: [DOMAIN_LIST]

ACCIONES TOMADAS:
1. [ACCIÓN]

CONTACTO:
- Nombre: [RESPONSABLE]
- Email: [EMAIL]
- Teléfono: [TELÉFONO]
EOFCSIRT

    cat > /usr/local/lib/incident-response/templates/notificacion-gerencia.txt << 'EOFGER'
REPORTE DE INCIDENTE DE SEGURIDAD - GERENCIA
=============================================

Fecha: [FECHA]
Severidad: [BAJA|MEDIA|ALTA|CRÍTICA]
Impacto negocio: [BAJO|MEDIO|ALTO|CRÍTICO]

RESUMEN EJECUTIVO:
[1-2 párrafos describiendo qué pasó, impacto y acciones tomadas]

ESTADO ACTUAL: [CONTENIDO|EN INVESTIGACIÓN|RESUELTO]

PRÓXIMOS PASOS:
1. [PASO]

TIMELINE ESTIMADA DE RESOLUCIÓN: [TIEMPO]

NECESIDADES:
- [RECURSO/DECISIÓN NECESARIA]
EOFGER

    cat > /usr/local/lib/incident-response/templates/notificacion-legal.txt << 'EOFLEGAL'
NOTIFICACIÓN DE INCIDENTE - ASESORÍA LEGAL
===========================================

Fecha detección: [FECHA]
ID Incidente: [INC-ID]

DATOS POTENCIALMENTE COMPROMETIDOS:
- Tipo: [PERSONAL|FINANCIERO|PROPIEDAD INTELECTUAL|OTRO]
- Volumen: [CANTIDAD DE REGISTROS/ARCHIVOS]
- Regulaciones aplicables: [GDPR|LOPD|PCI-DSS|HIPAA|OTRO]

EVIDENCIA PRESERVADA:
- Ubicación: [RUTA]
- Cadena de custodia: [SÍ/NO]
- Hash integridad: [HASH]

OBLIGACIONES DE NOTIFICACIÓN:
- AEPD (72h): [SÍ/NO]
- Afectados: [SÍ/NO]
- Regulador sectorial: [SÍ/NO]
EOFLEGAL

    cat > /usr/local/lib/incident-response/templates/notificacion-usuarios.txt << 'EOFUSR'
AVISO DE SEGURIDAD
==================

Estimado usuario,

Le informamos de un incidente de seguridad detectado el [FECHA].

QUÉ HA OCURRIDO:
[Descripción simple y clara]

QUÉ DATOS SE HAN VISTO AFECTADOS:
[Información afectada]

QUÉ HEMOS HECHO:
[Acciones tomadas]

QUÉ DEBE HACER USTED:
1. Cambie su contraseña inmediatamente
2. Active autenticación de dos factores
3. Revise actividad reciente en su cuenta

CONTACTO:
Si tiene preguntas, contacte a [EMAIL/TELÉFONO].
EOFUSR

    log_change "Creado" "4 templates de notificación"

    # Matriz de escalación
    cat > /etc/securizar/escalation-matrix.conf << 'EOFMATRIX'
# Matriz de escalación por severidad
# Formato: SEVERIDAD|TIEMPO_RESPUESTA|NOTIFICAR_A|CANAL

BAJA|24h|equipo-seguridad|email
MEDIA|4h|equipo-seguridad,responsable-IT|email,slack
ALTA|1h|equipo-seguridad,responsable-IT,CISO|email,slack,telefono
CRITICA|15min|equipo-seguridad,responsable-IT,CISO,CEO,legal|email,slack,telefono,csirt
EOFMATRIX

    log_change "Creado" "/etc/securizar/escalation-matrix.conf"

    # Script de escalación
    cat > /usr/local/bin/ir-escalar.sh << 'EOFESCALAR'
#!/bin/bash
# Escalación de incidentes según matriz
set -euo pipefail

SEVERITY="${1:-MEDIA}"
INCIDENT_ID="${2:-INC-$(date +%Y%m%d-%H%M%S)}"
MATRIX="/etc/securizar/escalation-matrix.conf"
TEMPLATES="/usr/local/lib/incident-response/templates"

echo "╔════════════════════════════════════════╗"
echo "║   ESCALACIÓN DE INCIDENTE              ║"
echo "╚════════════════════════════════════════╝"
echo ""
echo "Severidad: $SEVERITY"
echo "Incidente: $INCIDENT_ID"
echo ""

if [[ -f "$MATRIX" ]]; then
    LINE=$(grep -i "^$SEVERITY" "$MATRIX" | head -1)
    if [[ -n "$LINE" ]]; then
        TIEMPO=$(echo "$LINE" | cut -d'|' -f2)
        NOTIFICAR=$(echo "$LINE" | cut -d'|' -f3)
        CANAL=$(echo "$LINE" | cut -d'|' -f4)
        echo "Tiempo respuesta: $TIEMPO"
        echo "Notificar a: $NOTIFICAR"
        echo "Canal: $CANAL"
    fi
fi

echo ""
echo "Templates disponibles:"
ls -1 "$TEMPLATES"/ 2>/dev/null | while read -r t; do
    echo "  $TEMPLATES/$t"
done

logger -t ir-escalacion "Incident $INCIDENT_ID escalated: severity=$SEVERITY"
EOFESCALAR

    chmod 755 /usr/local/bin/ir-escalar.sh
    log_change "Creado" "/usr/local/bin/ir-escalar.sh"
    log_info "Templates y escalación instalados"

else
    log_skip "Templates de comunicación y escalación"
fi

# ============================================================
# S9: HUNTING DE IOCs EN FLOTA
# ============================================================
log_section "S9: HUNTING DE IOCs EN FLOTA"

echo "Escaneo SSH paralelo multi-host buscando IOCs."
echo "Busca: conexiones a IPs maliciosas, DNS, hashes en /tmp."
echo ""

if check_executable /usr/local/bin/ir-hunt-fleet.sh; then
    log_already "Hunting en flota"
elif ask "¿Instalar herramienta de hunting en flota?"; then

    # Config de hosts
    cat > /etc/securizar/ir-fleet-hosts.conf << 'EOFHOSTS'
# Hosts para hunting de IOCs
# Formato: usuario@host (uno por línea)
# Ejemplo:
# root@192.168.1.10
# admin@server2.local
EOFHOSTS

    log_change "Creado" "/etc/securizar/ir-fleet-hosts.conf"

    cat > /usr/local/bin/ir-hunt-fleet.sh << 'EOFHUNT'
#!/bin/bash
# ============================================================
# HUNTING DE IOCs EN FLOTA
# Escaneo SSH paralelo buscando indicadores de compromiso
# Uso: ir-hunt-fleet.sh IOC_FILE [--parallel N]
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

IOC_FILE="${1:?Uso: $0 ARCHIVO_IOCs [--parallel N]}"
HOSTS_FILE="/etc/securizar/ir-fleet-hosts.conf"
PARALLEL=5
RESULTS_DIR="/var/lib/incident-response/fleet-hunt-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RESULTS_DIR"

[[ "${2:-}" == "--parallel" ]] && PARALLEL="${3:-5}"

if [[ ! -f "$IOC_FILE" ]]; then
    echo -e "${RED}Archivo IOC no encontrado: $IOC_FILE${NC}"
    exit 1
fi

if [[ ! -f "$HOSTS_FILE" ]]; then
    echo -e "${RED}Configurar hosts: $HOSTS_FILE${NC}"
    exit 1
fi

echo -e "${BOLD}╔════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║   HUNTING DE IOCs EN FLOTA             ║${NC}"
echo -e "${BOLD}╚════════════════════════════════════════╝${NC}"
echo ""
echo -e "${DIM}IOCs: $IOC_FILE${NC}"
echo -e "${DIM}Parallelismo: $PARALLEL${NC}"
echo ""

# Extraer IOCs por tipo
IOC_IPS=$(grep -oP '\b(?:\d{1,3}\.){3}\d{1,3}\b' "$IOC_FILE" 2>/dev/null | sort -u)
IOC_DOMAINS=$(grep -oP '[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}' "$IOC_FILE" 2>/dev/null | sort -u)
IOC_HASHES=$(grep -oP '\b[a-fA-F0-9]{64}\b' "$IOC_FILE" 2>/dev/null | sort -u)

hunt_host() {
    local HOST="$1"
    local RESULT="$RESULTS_DIR/$(echo "$HOST" | tr '@:' '_').txt"
    echo -e "  ${CYAN}Escaneando:${NC} $HOST"

    {
        echo "=== HUNT: $HOST ==="
        echo "Fecha: $(date -Iseconds)"

        # Buscar conexiones a IPs IOC
        if [[ -n "$IOC_IPS" ]]; then
            echo ""
            echo "--- Conexiones a IPs IOC ---"
            for ip in $IOC_IPS; do
                MATCHES=$(ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$HOST" \
                    "ss -tn 2>/dev/null | grep '$ip'" 2>/dev/null || true)
                if [[ -n "$MATCHES" ]]; then
                    echo "ALERTA: Conexión a IOC IP $ip"
                    echo "$MATCHES"
                fi
            done
        fi

        # Buscar DNS a dominios IOC
        if [[ -n "$IOC_DOMAINS" ]]; then
            echo ""
            echo "--- DNS a dominios IOC ---"
            for dom in $IOC_DOMAINS; do
                MATCHES=$(ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$HOST" \
                    "journalctl -u systemd-resolved --since '24h ago' 2>/dev/null | grep -i '$dom' | head -5" 2>/dev/null || true)
                if [[ -n "$MATCHES" ]]; then
                    echo "ALERTA: DNS query a IOC domain $dom"
                    echo "$MATCHES"
                fi
            done
        fi

        # Buscar hashes en /tmp
        if [[ -n "$IOC_HASHES" ]]; then
            echo ""
            echo "--- Hashes IOC en /tmp ---"
            REMOTE_HASHES=$(ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$HOST" \
                "find /tmp /var/tmp /dev/shm -maxdepth 2 -type f -exec sha256sum {} \; 2>/dev/null" 2>/dev/null || true)
            for hash in $IOC_HASHES; do
                if echo "$REMOTE_HASHES" | grep -qi "$hash"; then
                    echo "ALERTA: Hash IOC encontrado: $hash"
                fi
            done
        fi

        # Verificar Falco alertas
        FALCO=$(ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$HOST" \
            "journalctl -u falco --since '24h ago' 2>/dev/null | grep -i 'warning\|error\|critical' | tail -5" 2>/dev/null || true)
        if [[ -n "$FALCO" ]]; then
            echo ""
            echo "--- Alertas Falco ---"
            echo "$FALCO"
        fi

    } > "$RESULT" 2>/dev/null

    # Reportar hallazgos
    ALERTS=$(grep -c "ALERTA:" "$RESULT" 2>/dev/null || echo 0)
    if [[ "$ALERTS" -gt 0 ]]; then
        echo -e "    ${RED}$ALERTS alertas en $HOST${NC}"
    else
        echo -e "    ${GREEN}Limpio${NC}"
    fi
}

# Ejecutar en paralelo
ACTIVE=0
while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    [[ "$host" == "#"* ]] && continue
    hunt_host "$host" &
    ACTIVE=$((ACTIVE + 1))
    if [[ $ACTIVE -ge $PARALLEL ]]; then
        wait -n 2>/dev/null || true
        ACTIVE=$((ACTIVE - 1))
    fi
done < "$HOSTS_FILE"
wait

echo ""
echo -e "${BOLD}Resultados en: $RESULTS_DIR${NC}"
TOTAL_ALERTS=$(grep -rc "ALERTA:" "$RESULTS_DIR"/*.txt 2>/dev/null | awk -F: '{s+=$2}END{print s+0}')
echo -e "${BOLD}Total alertas: $TOTAL_ALERTS${NC}"
logger -t ir-hunt "Fleet hunt completed: $TOTAL_ALERTS alerts"
EOFHUNT

    chmod 755 /usr/local/bin/ir-hunt-fleet.sh
    log_change "Creado" "/usr/local/bin/ir-hunt-fleet.sh"
    log_info "Hunting en flota instalado: ir-hunt-fleet.sh IOC_FILE"

else
    log_skip "Hunting en flota"
fi

# ============================================================
# S10: REVISIÓN POST-INCIDENTE Y MÉTRICAS
# ============================================================
log_section "S10: REVISIÓN POST-INCIDENTE Y MÉTRICAS"

echo "Cálculo automático de métricas IR: MTTD, MTTR, MTTC, MTTE."
echo "Scoring de madurez IR (5 niveles: Inicial→Optimizado)."
echo ""

if check_executable /usr/local/bin/ir-post-review.sh; then
    log_already "Revisión post-incidente"
elif ask "¿Instalar herramienta de revisión post-incidente?"; then

    cat > /usr/local/bin/ir-post-review.sh << 'EOFREVIEW'
#!/bin/bash
# ============================================================
# REVISIÓN POST-INCIDENTE Y MÉTRICAS IR
# Uso: ir-post-review.sh [INC-ID] [--detect EPOCH] [--contain EPOCH] [--eradicate EPOCH] [--recover EPOCH]
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

INCIDENT_ID="${1:-REVIEW-$(date +%Y%m%d-%H%M%S)}"
METRICS_DIR="/var/lib/incident-response/metrics"
HISTORY_CSV="$METRICS_DIR/ir-history.csv"
mkdir -p "$METRICS_DIR"

# Parsear timestamps
T_DETECT="" T_CONTAIN="" T_ERADICATE="" T_RECOVER=""
shift || true
while [[ $# -gt 0 ]]; do
    case "$1" in
        --detect) T_DETECT="$2"; shift 2 ;;
        --contain) T_CONTAIN="$2"; shift 2 ;;
        --eradicate) T_ERADICATE="$2"; shift 2 ;;
        --recover) T_RECOVER="$2"; shift 2 ;;
        *) shift ;;
    esac
done

echo -e "${BOLD}╔════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║   REVISIÓN POST-INCIDENTE              ║${NC}"
echo -e "${BOLD}╚════════════════════════════════════════╝${NC}"
echo ""
echo -e "Incidente: ${BOLD}$INCIDENT_ID${NC}"
echo ""

# Calcular métricas si hay timestamps
if [[ -n "$T_DETECT" ]] && [[ -n "$T_CONTAIN" ]]; then
    MTTC=$((T_CONTAIN - T_DETECT))
    echo -e "${CYAN}MTTC (Mean Time to Contain):${NC} $((MTTC / 60)) minutos"
fi
if [[ -n "$T_DETECT" ]] && [[ -n "$T_ERADICATE" ]]; then
    MTTE=$((T_ERADICATE - T_DETECT))
    echo -e "${CYAN}MTTE (Mean Time to Eradicate):${NC} $((MTTE / 3600)) horas"
fi
if [[ -n "$T_DETECT" ]] && [[ -n "$T_RECOVER" ]]; then
    MTTR=$((T_RECOVER - T_DETECT))
    echo -e "${CYAN}MTTR (Mean Time to Recover):${NC} $((MTTR / 3600)) horas"
fi

# Guardar en histórico
if [[ ! -f "$HISTORY_CSV" ]]; then
    echo "date,incident_id,mttc_min,mtte_h,mttr_h" > "$HISTORY_CSV"
fi
echo "$(date +%Y-%m-%d),$INCIDENT_ID,$((${MTTC:-0} / 60)),$((${MTTE:-0} / 3600)),$((${MTTR:-0} / 3600))" >> "$HISTORY_CSV"

# Scoring de madurez IR
echo ""
echo -e "${BOLD}=== SCORING DE MADUREZ IR ===${NC}"
echo ""

IR_SCORE=0
IR_MAX=100

score_check() {
    local desc="$1" cmd="$2" pts="$3"
    IR_MAX=$((IR_MAX))
    if eval "$cmd" &>/dev/null; then
        echo -e "  ${GREEN}[+$pts]${NC}  $desc"
        IR_SCORE=$((IR_SCORE + pts))
    else
        echo -e "  ${RED}[  0]${NC}  $desc"
    fi
}

score_check "Toolkit forense instalado" "test -x /usr/local/bin/ir-recolectar-forense.sh" 10
score_check "Playbooks de contención" "test -x /usr/local/bin/ir-responder.sh" 15
score_check "Timeline de ataque" "test -x /usr/local/bin/ir-timeline.sh" 10
score_check "Aislamiento de red" "test -x /usr/local/bin/ir-aislar-red.sh" 10
score_check "Recuperación post-incidente" "test -x /usr/local/bin/ir-recuperacion.sh" 10
score_check "Cadena de custodia" "test -x /usr/local/bin/ir-cadena-custodia.sh" 10
score_check "Extracción de IOCs" "test -x /usr/local/bin/ir-extraer-iocs.sh" 10
score_check "Templates de comunicación" "test -f /usr/local/lib/incident-response/templates/notificacion-csirt.txt" 5
score_check "Hunting en flota" "test -x /usr/local/bin/ir-hunt-fleet.sh" 10
score_check "Métricas IR (este script)" "test -x /usr/local/bin/ir-post-review.sh" 10

echo ""

# Nivel de madurez
LEVEL="Inicial"
if [[ $IR_SCORE -ge 90 ]]; then LEVEL="Optimizado"
elif [[ $IR_SCORE -ge 70 ]]; then LEVEL="Gestionado"
elif [[ $IR_SCORE -ge 50 ]]; then LEVEL="Definido"
elif [[ $IR_SCORE -ge 30 ]]; then LEVEL="Repetible"
fi

echo -e "${BOLD}Score IR: $IR_SCORE/100 - Nivel: $LEVEL${NC}"
echo ""

# Histórico de incidentes
if [[ -f "$HISTORY_CSV" ]] && [[ $(wc -l < "$HISTORY_CSV") -gt 1 ]]; then
    echo -e "${CYAN}Histórico de incidentes:${NC}"
    tail -10 "$HISTORY_CSV" | while IFS=, read -r date inc mttc mtte mttr; do
        [[ "$date" == "date" ]] && continue
        printf "  %s  %-20s  MTTC:%smin  MTTE:%sh  MTTR:%sh\n" "$date" "$inc" "$mttc" "$mtte" "$mttr"
    done
fi

logger -t ir-review "Post-incident review: $INCIDENT_ID score=$IR_SCORE level=$LEVEL"
EOFREVIEW

    chmod 755 /usr/local/bin/ir-post-review.sh
    log_change "Creado" "/usr/local/bin/ir-post-review.sh"
    log_info "Revisión post-incidente instalada: ir-post-review.sh"

else
    log_skip "Revisión post-incidente"
fi

# ============================================================
# RESUMEN
# ============================================================
echo ""
echo -e "${BOLD}Herramientas de IR instaladas:${NC}"
echo ""

for script in ir-recolectar-forense.sh ir-responder.sh ir-timeline.sh \
              ir-aislar-red.sh ir-recuperacion.sh ir-cadena-custodia.sh \
              ir-extraer-iocs.sh ir-escalar.sh ir-hunt-fleet.sh ir-post-review.sh; do
    if [[ -x "/usr/local/bin/$script" ]]; then
        echo -e "  ${GREEN}[OK]${NC} $script"
    else
        echo -e "  ${YELLOW}[--]${NC} $script"
    fi
done

echo ""
show_changes_summary
log_info "Módulo de respuesta a incidentes completado"
