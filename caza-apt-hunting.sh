#!/bin/bash
# ============================================================
# caza-apt-hunting.sh - Modulo 75: Caza de APTs
# ============================================================
# Secciones:
#   S1  - Motor de reglas YARA
#   S2  - Escaneo de filesystem
#   S3  - Hunting en memoria
#   S4  - Hunting en red
#   S5  - Behavioral baseline
#   S6  - Deteccion de persistencia
#   S7  - IOC sweeper
#   S8  - Threat intelligence correlation
#   S9  - Hunting playbooks automatizados
#   S10 - Auditoria integral APT hunting
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "apt-hunting"
securizar_setup_traps

# ── Pre-check: detectar secciones ya aplicadas ──────────────
_precheck 10
_pc 'check_executable /usr/local/bin/securizar-yara-engine.sh'
_pc 'check_executable /usr/local/bin/securizar-fs-hunt.sh'
_pc 'check_executable /usr/local/bin/securizar-mem-hunt.sh'
_pc 'check_executable /usr/local/bin/securizar-net-hunt.sh'
_pc 'check_file_exists /etc/securizar/hunting/behavioral-baseline.conf'
_pc 'check_executable /usr/local/bin/securizar-persistence-detect.sh'
_pc 'check_executable /usr/local/bin/securizar-ioc-sweep.sh'
_pc 'check_file_exists /etc/securizar/hunting/threat-intel.conf'
_pc 'check_executable /usr/local/bin/securizar-hunt-playbook.sh'
_pc 'check_executable /usr/local/bin/auditoria-hunting-completa.sh'
_precheck_result

log_section "MODULO 75: CAZA DE APTs"
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

HUNT_DIR="/etc/securizar/hunting"
HUNT_BIN="/usr/local/bin"
HUNT_LOG="/var/log/securizar/hunting"
mkdir -p "$HUNT_DIR" "$HUNT_LOG" || true

# ============================================================
# S1: MOTOR DE REGLAS YARA
# ============================================================
log_section "S1: Motor de reglas YARA"

log_info "Instala YARA, descarga reglas comunitarias y configura auto-update."
log_info "  - Instalacion de yara via gestor de paquetes"
log_info "  - Descarga de reglas desde github.com/Yara-Rules/rules"
log_info "  - Cron de actualizacion semanal"
log_info ""

if check_executable /usr/local/bin/securizar-yara-engine.sh; then
    log_already "Motor YARA (securizar-yara-engine.sh existe)"
elif ask "Crear motor de reglas YARA?"; then

    cat > "$HUNT_BIN/securizar-yara-engine.sh" << 'EOFYARA'
#!/bin/bash
# ============================================================
# securizar-yara-engine.sh - Motor de reglas YARA
# ============================================================
set -euo pipefail

RULES_DIR="/etc/securizar/hunting/yara-rules"
LOG="/var/log/securizar/hunting/yara-engine.log"
mkdir -p "$RULES_DIR" "$(dirname "$LOG")"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG"; }

# Instalar yara si no esta presente
if ! command -v yara &>/dev/null; then
    log "YARA no encontrado, instalando..."
    if command -v zypper &>/dev/null; then
        zypper -n install yara 2>/dev/null || log "WARN: No se pudo instalar yara con zypper"
    elif command -v apt-get &>/dev/null; then
        apt-get -y install yara 2>/dev/null || log "WARN: No se pudo instalar yara con apt"
    elif command -v dnf &>/dev/null; then
        dnf -y install yara 2>/dev/null || log "WARN: No se pudo instalar yara con dnf"
    else
        log "ERROR: Gestor de paquetes no soportado, instalar yara manualmente"
        exit 1
    fi
fi

# Descargar/actualizar reglas comunitarias
if command -v git &>/dev/null; then
    if [[ -d "$RULES_DIR/.git" ]]; then
        log "Actualizando reglas YARA..."
        cd "$RULES_DIR" && git pull --quiet 2>/dev/null || log "WARN: No se pudo actualizar"
    else
        log "Descargando reglas YARA comunitarias..."
        rm -rf "$RULES_DIR"
        git clone --depth 1 https://github.com/Yara-Rules/rules.git "$RULES_DIR" 2>/dev/null || \
            log "WARN: No se pudo clonar repositorio de reglas"
    fi
else
    log "WARN: git no instalado, descarga manual necesaria"
fi

# Escanear directorio dado como argumento
TARGET="${1:-}"
if [[ -n "$TARGET" ]] && [[ -e "$TARGET" ]] && command -v yara &>/dev/null; then
    log "Escaneando: $TARGET"
    find "$RULES_DIR" -name "*.yar" -o -name "*.yara" 2>/dev/null | head -50 | while read -r rule; do
        yara -r -w "$rule" "$TARGET" 2>/dev/null | tee -a "$LOG" || true
    done
    log "Escaneo completado"
elif [[ -n "$TARGET" ]]; then
    log "ERROR: Objetivo no encontrado o yara no disponible: $TARGET"
else
    log "Motor YARA listo. Uso: $0 /ruta/a/escanear"
    log "Reglas en: $RULES_DIR"
fi
EOFYARA
    chmod +x "$HUNT_BIN/securizar-yara-engine.sh"
    log_change "Creado" "$HUNT_BIN/securizar-yara-engine.sh"

    # Cron semanal para actualizar reglas
    cat > /etc/cron.weekly/securizar-yara-update << 'EOFCRON'
#!/bin/bash
/usr/local/bin/securizar-yara-engine.sh > /dev/null 2>&1
EOFCRON
    chmod 700 /etc/cron.weekly/securizar-yara-update
    log_change "Creado" "/etc/cron.weekly/securizar-yara-update"

else
    log_skip "Motor de reglas YARA"
fi

# ============================================================
# S2: ESCANEO DE FILESYSTEM
# ============================================================
log_section "S2: Escaneo de filesystem"

log_info "Escanea el filesystem buscando indicadores de compromiso:"
log_info "  - Binarios recientes en /usr/bin, /usr/sbin"
log_info "  - Ficheros ocultos en /tmp y /dev/shm"
log_info "  - Ficheros con timestamps anomalos"
log_info "  - Ejecutables world-writable"
log_info ""

if check_executable /usr/local/bin/securizar-fs-hunt.sh; then
    log_already "Escaneo filesystem (securizar-fs-hunt.sh existe)"
elif ask "Crear herramienta de escaneo de filesystem?"; then

    cat > "$HUNT_BIN/securizar-fs-hunt.sh" << 'EOFFSHUNT'
#!/bin/bash
# ============================================================
# securizar-fs-hunt.sh - Hunting en filesystem
# ============================================================
set -euo pipefail

LOG="/var/log/securizar/hunting/fs-hunt-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$(dirname "$LOG")"
FINDINGS=0

log() { echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOG"; }
finding() { echo "  [!] $1" | tee -a "$LOG"; FINDINGS=$((FINDINGS + 1)); }

log "=== Hunting en filesystem ==="
log "Fecha: $(date)"

# 1. Binarios modificados recientemente en rutas del sistema
log "--- Binarios recientes en /usr/bin, /usr/sbin (ultimas 48h) ---"
for dir in /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin; do
    [[ -d "$dir" ]] || continue
    while IFS= read -r f; do
        finding "Binario reciente: $f ($(stat -c '%y' "$f" 2>/dev/null | cut -d. -f1))"
    done < <(find "$dir" -maxdepth 1 -type f -mtime -2 2>/dev/null | head -20)
done

# 2. Ficheros ocultos en /tmp y /dev/shm
log "--- Ficheros ocultos en /tmp y /dev/shm ---"
for dir in /tmp /dev/shm /var/tmp; do
    [[ -d "$dir" ]] || continue
    while IFS= read -r f; do
        finding "Oculto en $dir: $f"
    done < <(find "$dir" -name ".*" -not -name "." -not -name ".." -type f 2>/dev/null | head -20)
done

# 3. Timestamps anomalos (futuro o muy antiguo en /usr)
log "--- Ficheros con timestamp futuro ---"
while IFS= read -r f; do
    finding "Timestamp futuro: $f"
done < <(find /usr/bin /usr/sbin -maxdepth 1 -type f -newer /proc/1/status 2>/dev/null | head -10)

# 4. Ejecutables world-writable
log "--- Ejecutables world-writable ---"
for dir in /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt; do
    [[ -d "$dir" ]] || continue
    while IFS= read -r f; do
        finding "World-writable ejecutable: $f ($(stat -c '%a' "$f" 2>/dev/null))"
    done < <(find "$dir" -maxdepth 2 -type f -perm -o+w -executable 2>/dev/null | head -10)
done

log ""
log "=== Resultado: $FINDINGS hallazgos ==="
log "Reporte: $LOG"
EOFFSHUNT
    chmod +x "$HUNT_BIN/securizar-fs-hunt.sh"
    log_change "Creado" "$HUNT_BIN/securizar-fs-hunt.sh"

else
    log_skip "Escaneo de filesystem"
fi

# ============================================================
# S3: HUNTING EN MEMORIA
# ============================================================
log_section "S3: Hunting en memoria"

log_info "Analiza /proc buscando indicadores en memoria:"
log_info "  - Binarios eliminados que siguen ejecutandose"
log_info "  - Cmdlines sospechosas (codificadas, ofuscadas)"
log_info "  - Mapas de memoria con rwx (inyeccion de codigo)"
log_info "  - Procesos ejecutandose desde /tmp o /dev/shm"
log_info ""

if check_executable /usr/local/bin/securizar-mem-hunt.sh; then
    log_already "Hunting en memoria (securizar-mem-hunt.sh existe)"
elif ask "Crear herramienta de hunting en memoria?"; then

    cat > "$HUNT_BIN/securizar-mem-hunt.sh" << 'EOFMEMHUNT'
#!/bin/bash
# ============================================================
# securizar-mem-hunt.sh - Hunting en memoria via /proc
# ============================================================
set -euo pipefail

LOG="/var/log/securizar/hunting/mem-hunt-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$(dirname "$LOG")"
FINDINGS=0

log() { echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOG"; }
finding() { echo "  [!] $1" | tee -a "$LOG"; FINDINGS=$((FINDINGS + 1)); }

log "=== Hunting en memoria ==="
log "Fecha: $(date)"

# 1. Binarios eliminados aun en ejecucion
log "--- Binarios eliminados en ejecucion ---"
for pid_dir in /proc/[0-9]*; do
    pid=$(basename "$pid_dir")
    exe=$(readlink "$pid_dir/exe" 2>/dev/null || true)
    if [[ "$exe" == *"(deleted)"* ]]; then
        cmd=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null || echo "?")
        finding "PID $pid: binario eliminado: $exe (cmd: ${cmd:0:80})"
    fi
done

# 2. Procesos ejecutandose desde /tmp o /dev/shm
log "--- Procesos desde /tmp o /dev/shm ---"
for pid_dir in /proc/[0-9]*; do
    pid=$(basename "$pid_dir")
    exe=$(readlink "$pid_dir/exe" 2>/dev/null || true)
    if [[ "$exe" == /tmp/* ]] || [[ "$exe" == /dev/shm/* ]] || [[ "$exe" == /var/tmp/* ]]; then
        cmd=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null || echo "?")
        finding "PID $pid: ejecutandose desde $exe (cmd: ${cmd:0:80})"
    fi
done

# 3. Regiones de memoria rwx (posible inyeccion de codigo)
log "--- Regiones de memoria rwx ---"
for pid_dir in /proc/[0-9]*; do
    pid=$(basename "$pid_dir")
    maps_file="$pid_dir/maps"
    [[ -r "$maps_file" ]] || continue
    rwx_count=$(grep -c 'rwxp' "$maps_file" 2>/dev/null || echo "0")
    if [[ "$rwx_count" -gt 2 ]]; then
        comm=$(cat "$pid_dir/comm" 2>/dev/null || echo "?")
        finding "PID $pid ($comm): $rwx_count regiones rwx"
    fi
done

# 4. Cmdlines sospechosas (base64, eval, /dev/tcp, ncat, perl -e)
log "--- Cmdlines sospechosas ---"
SUSPICIOUS_PATTERNS="base64|eval |/dev/tcp|ncat |nc -e|perl -e|python.*-c.*import|bash -i|curl.*|.*sh$"
for pid_dir in /proc/[0-9]*; do
    pid=$(basename "$pid_dir")
    cmd=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null || true)
    [[ -z "$cmd" ]] && continue
    if echo "$cmd" | grep -qEi "$SUSPICIOUS_PATTERNS" 2>/dev/null; then
        comm=$(cat "$pid_dir/comm" 2>/dev/null || echo "?")
        # Excluir este propio script y grep
        [[ "$comm" == "grep" ]] && continue
        [[ "$comm" == "securizar-mem"* ]] && continue
        finding "PID $pid ($comm): cmdline sospechosa: ${cmd:0:100}"
    fi
done

log ""
log "=== Resultado: $FINDINGS hallazgos ==="
log "Reporte: $LOG"
EOFMEMHUNT
    chmod +x "$HUNT_BIN/securizar-mem-hunt.sh"
    log_change "Creado" "$HUNT_BIN/securizar-mem-hunt.sh"

else
    log_skip "Hunting en memoria"
fi

# ============================================================
# S4: HUNTING EN RED
# ============================================================
log_section "S4: Hunting en red"

log_info "Detecta anomalias de red indicativas de APT:"
log_info "  - Patrones de beaconing (conexiones a intervalos regulares)"
log_info "  - Anomalias DNS (dominios largos, consultas TXT)"
log_info "  - Conexiones a IPs externas raras"
log_info "  - Procesos con conexiones inesperadas"
log_info ""

if check_executable /usr/local/bin/securizar-net-hunt.sh; then
    log_already "Hunting en red (securizar-net-hunt.sh existe)"
elif ask "Crear herramienta de hunting en red?"; then

    cat > "$HUNT_BIN/securizar-net-hunt.sh" << 'EOFNETHUNT'
#!/bin/bash
# ============================================================
# securizar-net-hunt.sh - Hunting en red
# ============================================================
set -euo pipefail

LOG="/var/log/securizar/hunting/net-hunt-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$(dirname "$LOG")"
FINDINGS=0

log() { echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOG"; }
finding() { echo "  [!] $1" | tee -a "$LOG"; FINDINGS=$((FINDINGS + 1)); }

log "=== Hunting en red ==="
log "Fecha: $(date)"

# 1. Conexiones ESTABLISHED a IPs externas
log "--- Conexiones externas activas ---"
ss -tnp state established 2>/dev/null | while IFS= read -r line; do
    # Extraer IP destino
    dst=$(echo "$line" | awk '{print $4}' | rev | cut -d: -f2- | rev)
    [[ -z "$dst" ]] && continue
    # Saltar IPs privadas y localhost
    [[ "$dst" =~ ^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|::1|fe80) ]] && continue
    [[ "$dst" == "0.0.0.0" ]] || [[ "$dst" == "*" ]] && continue
    proc=$(echo "$line" | grep -oP 'users:\(\("[^"]+' | cut -d'"' -f2 || echo "?")
    finding "Conexion externa: $dst (proceso: $proc)"
done

# 2. Puertos en escucha inusuales (no estandar)
log "--- Puertos en escucha no estandar ---"
STANDARD_PORTS="22 25 53 80 443 993 995 3306 5432 8080 8443"
ss -tlnp 2>/dev/null | tail -n +2 | while IFS= read -r line; do
    port=$(echo "$line" | awk '{print $4}' | rev | cut -d: -f1 | rev)
    [[ -z "$port" ]] && continue
    is_standard=0
    for sp in $STANDARD_PORTS; do
        [[ "$port" == "$sp" ]] && is_standard=1 && break
    done
    if [[ $is_standard -eq 0 ]] && [[ "$port" -gt 1024 ]]; then
        proc=$(echo "$line" | grep -oP 'users:\(\("[^"]+' | cut -d'"' -f2 || echo "?")
        finding "Puerto no estandar en escucha: $port (proceso: $proc)"
    fi
done

# 3. DNS: dominios largos en cache/logs (posible tunneling)
log "--- Dominios DNS sospechosos (largos/inusuales) ---"
if [[ -f /var/log/named/queries.log ]]; then
    grep -oP 'query: \K[^ ]+' /var/log/named/queries.log 2>/dev/null | \
        awk 'length > 50' | sort -u | head -10 | while IFS= read -r domain; do
        finding "Dominio largo en DNS: $domain (${#domain} chars)"
    done
fi
# Revisar tambien en journalctl si hay systemd-resolved
if command -v journalctl &>/dev/null; then
    journalctl -u systemd-resolved --since "24 hours ago" --no-pager 2>/dev/null | \
        grep -oP 'query\[.*?\] \K[^ ]+' 2>/dev/null | awk 'length > 50' | sort -u | head -10 | \
        while IFS= read -r domain; do
            finding "Dominio largo DNS (resolved): $domain"
        done
fi

# 4. Procesos con muchas conexiones (posible C2)
log "--- Procesos con muchas conexiones ---"
ss -tnp 2>/dev/null | grep -oP 'users:\(\("[^"]+' | cut -d'"' -f2 | sort | uniq -c | sort -rn | \
    head -10 | while read -r count proc; do
    if [[ "$count" -gt 20 ]]; then
        finding "Proceso con $count conexiones: $proc"
    fi
done

log ""
log "=== Resultado: $FINDINGS hallazgos ==="
log "Reporte: $LOG"
EOFNETHUNT
    chmod +x "$HUNT_BIN/securizar-net-hunt.sh"
    log_change "Creado" "$HUNT_BIN/securizar-net-hunt.sh"

else
    log_skip "Hunting en red"
fi

# ============================================================
# S5: BEHAVIORAL BASELINE
# ============================================================
log_section "S5: Behavioral baseline"

log_info "Documenta la linea base de comportamiento normal del sistema:"
log_info "  - Procesos esperados, conexiones de red, cron jobs"
log_info "  - Puertos en escucha, usuarios activos"
log_info ""

if check_file_exists /etc/securizar/hunting/behavioral-baseline.conf; then
    log_already "Behavioral baseline (behavioral-baseline.conf existe)"
elif ask "Crear configuracion de behavioral baseline?"; then

    # Capturar estado actual del sistema como baseline
    cat > "$HUNT_DIR/behavioral-baseline.conf" << 'EOFBASELINE'
# ============================================================
# behavioral-baseline.conf - Linea base de comportamiento
# ============================================================
# Generado por securizar - Modulo 75
# Revisar y ajustar manualmente tras la instalacion
#
# Este fichero documenta el estado "normal" del sistema.
# Las herramientas de hunting comparan contra esta baseline
# para detectar desviaciones indicativas de APT.

# === Procesos esperados ===
# Listar procesos que deben estar corriendo siempre
# Formato: PROC_nombre_del_proceso=usuario
PROC_systemd=root
PROC_sshd=root
PROC_rsyslogd=root
PROC_cron=root
PROC_agetty=root
PROC_dbus-daemon=messagebus

# === Puertos en escucha esperados ===
# Formato: PORT_numero=protocolo:proceso
PORT_22=tcp:sshd
#PORT_80=tcp:nginx
#PORT_443=tcp:nginx
#PORT_3306=tcp:mysqld
#PORT_5432=tcp:postgres

# === Conexiones de red esperadas ===
# Formato: NET_descripcion=destino_ip:puerto
#NET_ntp=pool.ntp.org:123
#NET_dns=8.8.8.8:53
#NET_updates=download.opensuse.org:443

# === Cron jobs esperados ===
# Formato: CRON_nombre=frecuencia:usuario:comando_corto
CRON_logrotate=daily:root:logrotate
CRON_man-db=daily:root:mandb
#CRON_certbot=daily:root:certbot

# === Usuarios con login habilitado ===
# Formato: USER_nombre=shell
USER_root=/bin/bash
#USER_admin=/bin/bash

# === Modulos del kernel esperados ===
# Formato: KMOD_nombre=1
#KMOD_ip_tables=1
#KMOD_nf_conntrack=1
#KMOD_br_netfilter=1
EOFBASELINE
    chmod 0640 "$HUNT_DIR/behavioral-baseline.conf"
    log_change "Creado" "$HUNT_DIR/behavioral-baseline.conf"

    # Capturar snapshot actual
    {
        echo "# === Snapshot automatico: $(date) ==="
        echo "# Puertos en escucha actuales:"
        ss -tlnp 2>/dev/null | tail -n +2 | awk '{print "# " $4 " " $6}' | head -20
        echo ""
        echo "# Procesos actuales:"
        ps -eo user,comm --no-headers 2>/dev/null | sort -u | head -30 | awk '{print "# " $1 " " $2}'
    } >> "$HUNT_DIR/behavioral-baseline.conf"
    log_change "Capturado" "snapshot actual en behavioral-baseline.conf"

else
    log_skip "Behavioral baseline"
fi

# ============================================================
# S6: DETECCION DE PERSISTENCIA
# ============================================================
log_section "S6: Deteccion de persistencia"

log_info "Verifica todos los mecanismos de persistencia conocidos:"
log_info "  - cron/crontab, systemd services/timers, init.d"
log_info "  - udev rules, at jobs, kernel modules, LD_PRELOAD"
log_info "  - shell rc files, authorized_keys"
log_info ""

if check_executable /usr/local/bin/securizar-persistence-detect.sh; then
    log_already "Deteccion persistencia (securizar-persistence-detect.sh existe)"
elif ask "Crear herramienta de deteccion de persistencia?"; then

    cat > "$HUNT_BIN/securizar-persistence-detect.sh" << 'EOFPERSIST'
#!/bin/bash
# ============================================================
# securizar-persistence-detect.sh - Deteccion de persistencia APT
# ============================================================
set -euo pipefail

LOG="/var/log/securizar/hunting/persistence-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$(dirname "$LOG")"
FINDINGS=0

log() { echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOG"; }
finding() { echo "  [!] $1" | tee -a "$LOG"; FINDINGS=$((FINDINGS + 1)); }

log "=== Deteccion de persistencia ==="
log "Fecha: $(date)"

# 1. Crontabs de todos los usuarios
log "--- Crontabs de usuarios ---"
for user_home in /home/* /root; do
    user=$(basename "$user_home")
    crontab -u "$user" -l 2>/dev/null | grep -v '^#' | grep -v '^$' | while IFS= read -r line; do
        finding "Crontab ($user): $line"
    done
done
# Ficheros en /etc/cron.*
for cdir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    [[ -d "$cdir" ]] || continue
    for f in "$cdir"/*; do
        [[ -f "$f" ]] || continue
        bn=$(basename "$f")
        [[ "$bn" == "." ]] || [[ "$bn" == ".." ]] && continue
        log "  Cron: $f ($(stat -c '%U:%a' "$f" 2>/dev/null))"
    done
done

# 2. Systemd services/timers no nativos
log "--- Servicios systemd no nativos ---"
for sdir in /etc/systemd/system /usr/local/lib/systemd/system; do
    [[ -d "$sdir" ]] || continue
    find "$sdir" -maxdepth 1 \( -name "*.service" -o -name "*.timer" \) -type f 2>/dev/null | \
        while IFS= read -r f; do
            finding "Systemd custom: $f"
        done
done

# 3. Init.d scripts
log "--- Scripts init.d ---"
if [[ -d /etc/init.d ]]; then
    find /etc/init.d -maxdepth 1 -type f -newer /etc/os-release 2>/dev/null | while IFS= read -r f; do
        finding "Init.d reciente: $f"
    done
fi

# 4. Udev rules custom
log "--- Udev rules custom ---"
find /etc/udev/rules.d -maxdepth 1 -type f 2>/dev/null | while IFS= read -r f; do
    finding "Udev rule: $f"
done

# 5. At jobs
log "--- At jobs ---"
if command -v atq &>/dev/null; then
    atq 2>/dev/null | while IFS= read -r line; do
        finding "At job: $line"
    done
fi

# 6. Kernel modules recientes
log "--- Modulos kernel cargados fuera de /lib/modules ---"
lsmod 2>/dev/null | tail -n +2 | awk '{print $1}' | while read -r mod; do
    modpath=$(modinfo -n "$mod" 2>/dev/null || true)
    if [[ -n "$modpath" ]] && [[ "$modpath" != /lib/modules/* ]] && [[ "$modpath" != "(builtin)" ]]; then
        finding "Kernel module ruta inusual: $mod -> $modpath"
    fi
done

# 7. LD_PRELOAD
log "--- LD_PRELOAD ---"
if [[ -f /etc/ld.so.preload ]] && [[ -s /etc/ld.so.preload ]]; then
    finding "LD_PRELOAD activo: $(cat /etc/ld.so.preload)"
fi
grep -r "LD_PRELOAD" /etc/environment /etc/profile.d/ 2>/dev/null | while IFS= read -r line; do
    finding "LD_PRELOAD en entorno: $line"
done

# 8. Shell rc files modificados recientemente
log "--- Shell RC files recientes (7 dias) ---"
for rc in /etc/profile /etc/bash.bashrc /etc/bashrc /etc/zshrc; do
    [[ -f "$rc" ]] || continue
    if find "$rc" -mtime -7 2>/dev/null | grep -q .; then
        finding "RC reciente: $rc ($(stat -c '%y' "$rc" 2>/dev/null | cut -d. -f1))"
    fi
done
for home in /home/* /root; do
    for rc in .bashrc .bash_profile .profile .zshrc; do
        f="$home/$rc"
        [[ -f "$f" ]] || continue
        if find "$f" -mtime -7 2>/dev/null | grep -q .; then
            finding "RC usuario reciente: $f"
        fi
    done
done

# 9. authorized_keys
log "--- authorized_keys ---"
for home in /home/* /root; do
    ak="$home/.ssh/authorized_keys"
    [[ -f "$ak" ]] || continue
    count=$(wc -l < "$ak" 2>/dev/null || echo 0)
    finding "authorized_keys: $ak ($count claves)"
done

log ""
log "=== Resultado: $FINDINGS hallazgos ==="
log "NOTA: No todos los hallazgos son maliciosos. Comparar con la baseline."
log "Reporte: $LOG"
EOFPERSIST
    chmod +x "$HUNT_BIN/securizar-persistence-detect.sh"
    log_change "Creado" "$HUNT_BIN/securizar-persistence-detect.sh"

else
    log_skip "Deteccion de persistencia"
fi

# ============================================================
# S7: IOC SWEEPER
# ============================================================
log_section "S7: IOC sweeper"

log_info "Barre el sistema buscando Indicadores de Compromiso (IOCs):"
log_info "  - Hashes maliciosos conocidos (SHA256)"
log_info "  - IPs sospechosas en logs"
log_info "  - Dominios maliciosos en cache/logs DNS"
log_info ""

if check_executable /usr/local/bin/securizar-ioc-sweep.sh; then
    log_already "IOC sweeper (securizar-ioc-sweep.sh existe)"
elif ask "Crear herramienta IOC sweeper?"; then

    # Crear directorio de IOCs y ficheros de ejemplo
    mkdir -p "$HUNT_DIR/iocs"
    cat > "$HUNT_DIR/iocs/hashes.txt" << 'EOFHASH'
# IOC hashes SHA256 - uno por linea
# Actualizar con feeds de threat intel
# Formato: hash descripcion
# Ejemplo:
# e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 empty_file_test
EOFHASH

    cat > "$HUNT_DIR/iocs/bad-ips.txt" << 'EOFIPS'
# IOC IPs maliciosas - una por linea
# Actualizar con feeds de threat intel
# Ejemplo:
# 198.51.100.1
# 203.0.113.50
EOFIPS

    cat > "$HUNT_DIR/iocs/bad-domains.txt" << 'EOFDOMS'
# IOC dominios maliciosos - uno por linea
# Actualizar con feeds de threat intel
# Ejemplo:
# malware-c2.example.com
# evil-domain.example.net
EOFDOMS

    cat > "$HUNT_BIN/securizar-ioc-sweep.sh" << 'EOFSWEEP'
#!/bin/bash
# ============================================================
# securizar-ioc-sweep.sh - IOC Sweeper
# ============================================================
set -euo pipefail

IOC_DIR="/etc/securizar/hunting/iocs"
LOG="/var/log/securizar/hunting/ioc-sweep-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$(dirname "$LOG")"
FINDINGS=0

log() { echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOG"; }
finding() { echo "  [!!!] $1" | tee -a "$LOG"; FINDINGS=$((FINDINGS + 1)); }

log "=== IOC Sweep ==="
log "Fecha: $(date)"

# 1. Hash sweep: buscar hashes maliciosos en binarios recientes
log "--- Sweep de hashes ---"
HASH_FILE="$IOC_DIR/hashes.txt"
if [[ -f "$HASH_FILE" ]]; then
    mapfile -t BAD_HASHES < <(grep -v '^#' "$HASH_FILE" | grep -v '^$' | awk '{print $1}')
    if [[ ${#BAD_HASHES[@]} -gt 0 ]]; then
        log "  Comprobando ${#BAD_HASHES[@]} hashes contra binarios recientes..."
        find /usr/local/bin /tmp /var/tmp /dev/shm -maxdepth 2 -type f -mtime -30 2>/dev/null | \
            head -200 | while IFS= read -r f; do
            h=$(sha256sum "$f" 2>/dev/null | awk '{print $1}' || true)
            for bad in "${BAD_HASHES[@]}"; do
                if [[ "$h" == "$bad" ]]; then
                    finding "HASH MATCH: $f -> $h"
                fi
            done
        done
    else
        log "  Sin hashes IOC configurados en $HASH_FILE"
    fi
else
    log "  WARN: $HASH_FILE no encontrado"
fi

# 2. IP sweep: buscar IPs maliciosas en logs
log "--- Sweep de IPs ---"
IP_FILE="$IOC_DIR/bad-ips.txt"
if [[ -f "$IP_FILE" ]]; then
    mapfile -t BAD_IPS < <(grep -v '^#' "$IP_FILE" | grep -v '^$')
    if [[ ${#BAD_IPS[@]} -gt 0 ]]; then
        log "  Buscando ${#BAD_IPS[@]} IPs en logs..."
        for ip in "${BAD_IPS[@]}"; do
            for logfile in /var/log/syslog /var/log/messages /var/log/auth.log /var/log/secure; do
                [[ -f "$logfile" ]] || continue
                count=$(grep -c "$ip" "$logfile" 2>/dev/null || echo "0")
                [[ "$count" -gt 0 ]] && finding "IP IOC $ip encontrada $count veces en $logfile"
            done
        done
    fi
fi

# 3. Domain sweep: buscar dominios maliciosos
log "--- Sweep de dominios ---"
DOM_FILE="$IOC_DIR/bad-domains.txt"
if [[ -f "$DOM_FILE" ]]; then
    mapfile -t BAD_DOMS < <(grep -v '^#' "$DOM_FILE" | grep -v '^$')
    if [[ ${#BAD_DOMS[@]} -gt 0 ]]; then
        log "  Buscando ${#BAD_DOMS[@]} dominios..."
        for dom in "${BAD_DOMS[@]}"; do
            for logfile in /var/log/syslog /var/log/messages /var/log/named/queries.log; do
                [[ -f "$logfile" ]] || continue
                count=$(grep -c "$dom" "$logfile" 2>/dev/null || echo "0")
                [[ "$count" -gt 0 ]] && finding "Dominio IOC $dom encontrado $count veces en $logfile"
            done
        done
    fi
fi

log ""
log "=== Resultado: $FINDINGS IOCs detectados ==="
[[ $FINDINGS -gt 0 ]] && log "ALERTA: Se encontraron IOCs activos - iniciar investigacion"
log "Reporte: $LOG"
EOFSWEEP
    chmod +x "$HUNT_BIN/securizar-ioc-sweep.sh"
    log_change "Creado" "$HUNT_BIN/securizar-ioc-sweep.sh"
    log_change "Creado" "$HUNT_DIR/iocs/ (hashes, bad-ips, bad-domains)"

else
    log_skip "IOC sweeper"
fi

# ============================================================
# S8: THREAT INTELLIGENCE CORRELATION
# ============================================================
log_section "S8: Threat intelligence correlation"

log_info "Configura integracion con fuentes de threat intelligence:"
log_info "  - STIX/TAXII feeds"
log_info "  - Conexion MISP"
log_info "  - Fuentes de enriquecimiento de IOCs"
log_info ""

if check_file_exists /etc/securizar/hunting/threat-intel.conf; then
    log_already "Threat intelligence (threat-intel.conf existe)"
elif ask "Crear configuracion de threat intelligence?"; then

    cat > "$HUNT_DIR/threat-intel.conf" << 'EOFTHREAT'
# ============================================================
# threat-intel.conf - Integracion de Threat Intelligence
# ============================================================
# Generado por securizar - Modulo 75

# === STIX/TAXII Feeds ===
# Configurar URLs de feeds TAXII para descarga automatica de IOCs
# Formato: TAXII_nombre=url|collection|usuario|password

# AlienVault OTX (gratuito, requiere registro)
#TAXII_otx=https://otx.alienvault.com/taxii/discovery|default|API_KEY|

# CIRCL MISP TAXII (gratuito)
#TAXII_circl=https://www.circl.lu/taxii/discovery|default||

# === MISP Integration ===
# Configurar conexion a instancia MISP para correlacion de IOCs
#MISP_URL=https://misp.example.com
#MISP_API_KEY=your_api_key_here
#MISP_VERIFY_SSL=true
#MISP_PUBLISH_SIGHTINGS=true

# === Fuentes de enriquecimiento ===
# APIs para enriquecer IOCs con contexto adicional

# VirusTotal (requiere API key)
#VT_API_KEY=your_virustotal_api_key

# AbuseIPDB (requiere API key)
#ABUSEIPDB_API_KEY=your_abuseipdb_api_key

# Shodan (requiere API key)
#SHODAN_API_KEY=your_shodan_api_key

# === Fuentes OSINT gratuitas (sin API key) ===
# URLhaus: https://urlhaus-api.abuse.ch/v1/
# MalwareBazaar: https://bazaar.abuse.ch/api/
# ThreatFox: https://threatfox-api.abuse.ch/api/v1/
# Feodo Tracker: https://feodotracker.abuse.ch/

# === Actualizacion automatica de IOCs ===
# Frecuencia de descarga de IOCs desde feeds
IOC_UPDATE_FREQUENCY=daily
IOC_DIR=/etc/securizar/hunting/iocs

# === Retention ===
# Dias que se mantienen IOCs antes de expirar
IOC_RETENTION_DAYS=90

# === Alertas ===
# Donde enviar alertas cuando se detecta un IOC
#ALERT_EMAIL=security@example.com
#ALERT_SYSLOG=true
ALERT_LOG=/var/log/securizar/hunting/ioc-alerts.log
EOFTHREAT
    chmod 0640 "$HUNT_DIR/threat-intel.conf"
    log_change "Creado" "$HUNT_DIR/threat-intel.conf"

else
    log_skip "Threat intelligence correlation"
fi

# ============================================================
# S9: HUNTING PLAYBOOKS AUTOMATIZADOS
# ============================================================
log_section "S9: Hunting playbooks automatizados"

log_info "Crea un playbook que ejecuta todas las herramientas de hunting"
log_info "en secuencia y genera un informe consolidado."
log_info ""

if check_executable /usr/local/bin/securizar-hunt-playbook.sh; then
    log_already "Hunt playbook (securizar-hunt-playbook.sh existe)"
elif ask "Crear playbook de hunting automatizado?"; then

    cat > "$HUNT_BIN/securizar-hunt-playbook.sh" << 'EOFPLAYBOOK'
#!/bin/bash
# ============================================================
# securizar-hunt-playbook.sh - Playbook de hunting automatizado
# ============================================================
set -euo pipefail

HUNT_LOG="/var/log/securizar/hunting"
mkdir -p "$HUNT_LOG"
REPORT="$HUNT_LOG/playbook-$(date +%Y%m%d-%H%M%S).log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

log() { echo "[$(date '+%H:%M:%S')] $1" | tee -a "$REPORT"; }

log "============================================================"
log "  HUNTING PLAYBOOK - Ejecucion automatizada"
log "  $TIMESTAMP - $(hostname)"
log "============================================================"
log ""

TOTAL_FINDINGS=0
MODULES_OK=0
MODULES_FAIL=0

run_module() {
    local name="$1" script="$2"
    log ">>> Ejecutando: $name"
    if [[ -x "$script" ]]; then
        output=$("$script" 2>&1) || true
        echo "$output" >> "$REPORT"
        # Contar findings del modulo
        count=$(echo "$output" | grep -c '\[!\]' || echo "0")
        TOTAL_FINDINGS=$((TOTAL_FINDINGS + count))
        MODULES_OK=$((MODULES_OK + 1))
        log "    Completado: $count hallazgos"
    else
        log "    WARN: $script no encontrado, saltando"
        MODULES_FAIL=$((MODULES_FAIL + 1))
    fi
    log ""
}

# Ejecutar modulos de hunting en orden
run_module "Filesystem Hunt"      /usr/local/bin/securizar-fs-hunt.sh
run_module "Memory Hunt"          /usr/local/bin/securizar-mem-hunt.sh
run_module "Network Hunt"         /usr/local/bin/securizar-net-hunt.sh
run_module "Persistence Detect"   /usr/local/bin/securizar-persistence-detect.sh
run_module "IOC Sweep"            /usr/local/bin/securizar-ioc-sweep.sh

# YARA scan de directorios sospechosos
if [[ -x /usr/local/bin/securizar-yara-engine.sh ]]; then
    log ">>> Ejecutando: YARA scan (/tmp, /dev/shm)"
    for target in /tmp /dev/shm /var/tmp; do
        [[ -d "$target" ]] && /usr/local/bin/securizar-yara-engine.sh "$target" >> "$REPORT" 2>&1 || true
    done
    MODULES_OK=$((MODULES_OK + 1))
    log "    YARA scan completado"
else
    MODULES_FAIL=$((MODULES_FAIL + 1))
fi

log ""
log "============================================================"
log "  RESUMEN DEL PLAYBOOK"
log "============================================================"
log "  Modulos ejecutados: $MODULES_OK"
log "  Modulos no disponibles: $MODULES_FAIL"
log "  Total hallazgos: $TOTAL_FINDINGS"
log ""
if [[ $TOTAL_FINDINGS -eq 0 ]]; then
    log "  ESTADO: Sin hallazgos sospechosos"
elif [[ $TOTAL_FINDINGS -lt 10 ]]; then
    log "  ESTADO: Pocos hallazgos - revisar manualmente"
else
    log "  ESTADO: ATENCION - Multiples hallazgos detectados"
fi
log "  Reporte completo: $REPORT"
log "============================================================"

# Enviar alerta si hay hallazgos criticos
if [[ $TOTAL_FINDINGS -gt 0 ]]; then
    logger -t securizar-hunting "Playbook: $TOTAL_FINDINGS hallazgos detectados. Ver $REPORT"
fi
EOFPLAYBOOK
    chmod +x "$HUNT_BIN/securizar-hunt-playbook.sh"
    log_change "Creado" "$HUNT_BIN/securizar-hunt-playbook.sh"

    # Cron diario
    cat > /etc/cron.daily/securizar-hunt-playbook << 'EOFCRON'
#!/bin/bash
/usr/local/bin/securizar-hunt-playbook.sh > /dev/null 2>&1
EOFCRON
    chmod 700 /etc/cron.daily/securizar-hunt-playbook
    log_change "Creado" "/etc/cron.daily/securizar-hunt-playbook"

else
    log_skip "Hunt playbook automatizado"
fi

# ============================================================
# S10: AUDITORIA INTEGRAL APT HUNTING
# ============================================================
log_section "S10: Auditoria integral APT hunting"

log_info "Crea herramienta de auditoria integral del sistema de hunting."
log_info ""

if check_executable /usr/local/bin/auditoria-hunting-completa.sh; then
    log_already "Auditoria integral (auditoria-hunting-completa.sh existe)"
elif ask "Crear herramienta de auditoria integral APT hunting?"; then

    cat > "$HUNT_BIN/auditoria-hunting-completa.sh" << 'EOFAUDIT'
#!/bin/bash
# ============================================================
# auditoria-hunting-completa.sh - Auditoria integral APT hunting
# ============================================================
set -euo pipefail

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
BOLD="\033[1m"
DIM="\033[2m"
NC="\033[0m"

LOG_DIR="/var/log/securizar/hunting"
mkdir -p "$LOG_DIR"
REPORT="$LOG_DIR/audit-integral-$(date +%Y%m%d-%H%M%S).log"

SCORE=0
MAX=0

check() {
    local desc="$1" result="$2"
    MAX=$((MAX + 1))
    if [[ "$result" -eq 0 ]]; then
        echo -e "  ${GREEN}[OK]${NC} $desc" | tee -a "$REPORT"
        SCORE=$((SCORE + 1))
    else
        echo -e "  ${YELLOW}[!!]${NC} $desc" | tee -a "$REPORT"
    fi
}

echo -e "${BOLD}=============================================" | tee "$REPORT"
echo -e "  AUDITORIA INTEGRAL APT HUNTING" | tee -a "$REPORT"
echo -e "  $(date '+%Y-%m-%d %H:%M:%S') - $(hostname)" | tee -a "$REPORT"
echo -e "=============================================${NC}" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# 1. Herramientas de hunting
echo -e "${CYAN}=== 1. Herramientas de hunting ===${NC}" | tee -a "$REPORT"
check "securizar-yara-engine.sh" "$([[ -x /usr/local/bin/securizar-yara-engine.sh ]]; echo $?)"
check "securizar-fs-hunt.sh" "$([[ -x /usr/local/bin/securizar-fs-hunt.sh ]]; echo $?)"
check "securizar-mem-hunt.sh" "$([[ -x /usr/local/bin/securizar-mem-hunt.sh ]]; echo $?)"
check "securizar-net-hunt.sh" "$([[ -x /usr/local/bin/securizar-net-hunt.sh ]]; echo $?)"
check "securizar-persistence-detect.sh" "$([[ -x /usr/local/bin/securizar-persistence-detect.sh ]]; echo $?)"
check "securizar-ioc-sweep.sh" "$([[ -x /usr/local/bin/securizar-ioc-sweep.sh ]]; echo $?)"
check "securizar-hunt-playbook.sh" "$([[ -x /usr/local/bin/securizar-hunt-playbook.sh ]]; echo $?)"

# 2. Configuracion
echo "" | tee -a "$REPORT"
echo -e "${CYAN}=== 2. Configuracion ===${NC}" | tee -a "$REPORT"
check "behavioral-baseline.conf" "$([[ -f /etc/securizar/hunting/behavioral-baseline.conf ]]; echo $?)"
check "threat-intel.conf" "$([[ -f /etc/securizar/hunting/threat-intel.conf ]]; echo $?)"
check "IOCs directorio" "$([[ -d /etc/securizar/hunting/iocs ]]; echo $?)"

# 3. YARA
echo "" | tee -a "$REPORT"
echo -e "${CYAN}=== 3. Motor YARA ===${NC}" | tee -a "$REPORT"
check "yara instalado" "$(command -v yara &>/dev/null; echo $?)"
check "Reglas YARA descargadas" "$([[ -d /etc/securizar/hunting/yara-rules ]]; echo $?)"
check "Cron actualizacion YARA" "$([[ -f /etc/cron.weekly/securizar-yara-update ]]; echo $?)"

# 4. Automatizacion
echo "" | tee -a "$REPORT"
echo -e "${CYAN}=== 4. Automatizacion ===${NC}" | tee -a "$REPORT"
check "Cron playbook diario" "$([[ -f /etc/cron.daily/securizar-hunt-playbook ]]; echo $?)"
check "Directorio de logs" "$([[ -d /var/log/securizar/hunting ]]; echo $?)"

# 5. Reportes recientes
echo "" | tee -a "$REPORT"
echo -e "${CYAN}=== 5. Actividad reciente ===${NC}" | tee -a "$REPORT"
recent=$(find /var/log/securizar/hunting -name "playbook-*.log" -mtime -7 2>/dev/null | wc -l)
check "Playbook ejecutado esta semana (>0)" "$([[ "$recent" -gt 0 ]]; echo $?)"
echo -e "  ${DIM}Reportes de playbook recientes: $recent${NC}" | tee -a "$REPORT"

# Resumen
echo "" | tee -a "$REPORT"
echo -e "${BOLD}=============================================${NC}" | tee -a "$REPORT"
PCT=0
[[ $MAX -gt 0 ]] && PCT=$((SCORE * 100 / MAX))

if [[ $PCT -ge 80 ]]; then
    echo -e "  ${GREEN}${BOLD}PUNTUACION: ${SCORE}/${MAX} (${PCT}%) - BUENO${NC}" | tee -a "$REPORT"
elif [[ $PCT -ge 50 ]]; then
    echo -e "  ${YELLOW}${BOLD}PUNTUACION: ${SCORE}/${MAX} (${PCT}%) - MEJORABLE${NC}" | tee -a "$REPORT"
else
    echo -e "  ${RED}${BOLD}PUNTUACION: ${SCORE}/${MAX} (${PCT}%) - DEFICIENTE${NC}" | tee -a "$REPORT"
fi
echo -e "${BOLD}=============================================${NC}" | tee -a "$REPORT"
echo -e "${DIM}Reporte: $REPORT${NC}" | tee -a "$REPORT"
logger -t securizar-hunting "APT hunting audit: $SCORE/$MAX ($PCT%)"
EOFAUDIT
    chmod +x "$HUNT_BIN/auditoria-hunting-completa.sh"
    log_change "Creado" "$HUNT_BIN/auditoria-hunting-completa.sh"

    # Cron semanal
    cat > /etc/cron.weekly/auditoria-hunting << 'EOFCRON'
#!/bin/bash
/usr/local/bin/auditoria-hunting-completa.sh > /dev/null 2>&1
EOFCRON
    chmod 700 /etc/cron.weekly/auditoria-hunting
    log_change "Creado" "/etc/cron.weekly/auditoria-hunting"

else
    log_skip "Auditoria integral APT hunting"
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
show_changes_summary
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   CAZA DE APTs (MODULO 75) COMPLETADO                    ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups guardados en: $BACKUP_DIR"
echo ""
echo "Comandos disponibles:"
echo "  - Motor YARA:         securizar-yara-engine.sh [directorio]"
echo "  - Hunt filesystem:    securizar-fs-hunt.sh"
echo "  - Hunt memoria:       securizar-mem-hunt.sh"
echo "  - Hunt red:           securizar-net-hunt.sh"
echo "  - Persistencia:       securizar-persistence-detect.sh"
echo "  - IOC sweep:          securizar-ioc-sweep.sh"
echo "  - Playbook completo:  securizar-hunt-playbook.sh"
echo "  - Auditoria:          auditoria-hunting-completa.sh"
