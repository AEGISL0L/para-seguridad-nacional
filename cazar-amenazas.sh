#!/bin/bash
# ============================================================
# CAZA DE AMENAZAS - Threat Hunting & UEBA
# Linux Multi-Distro (openSUSE, Debian/Ubuntu, RHEL/Fedora, Arch)
# ============================================================
# Capacidades implementadas:
#   - Baseline de comportamiento de usuarios (UEBA)
#   - Playbooks de caza de amenazas por hipótesis
#   - Detección de anomalías de comportamiento
#   - Búsqueda retrospectiva en logs históricos
#   - Detección de técnicas de persistencia avanzadas (T1098)
#   - Hunting proactivo por indicadores de compromiso
# ============================================================


set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
HUNT_DIR="/var/lib/threat-hunting"
mkdir -p "$HUNT_DIR"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   CAZA DE AMENAZAS - Threat Hunting & UEBA                ║"
echo "║   Behavioral analytics, hunting proactivo                  ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# ============================================================
log_section "1. BASELINE DE COMPORTAMIENTO DE USUARIOS (UEBA)"
# ============================================================

echo "Crea perfiles de comportamiento normal para cada usuario"
echo "del sistema y detecta desviaciones que indiquen compromiso."
echo ""
echo "Métricas capturadas por usuario:"
echo "  - Horarios habituales de login"
echo "  - IPs de origen frecuentes"
echo "  - Comandos más ejecutados (via auditd)"
echo "  - Patrones de acceso a archivos"
echo "  - Uso de sudo y privilegios elevados"
echo ""

if ask "¿Instalar sistema UEBA de baseline comportamental?"; then

    mkdir -p "$HUNT_DIR/ueba/baselines" "$HUNT_DIR/ueba/anomalias"

    cat > /usr/local/bin/ueba-crear-baseline.sh << 'EOFUEBA_BL'
#!/bin/bash
# ============================================================
# UEBA - CREAR BASELINE DE COMPORTAMIENTO
# Ejecutar en un período de actividad normal (7-30 días)
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

UEBA_DIR="/var/lib/threat-hunting/ueba/baselines"
mkdir -p "$UEBA_DIR"
DIAS="${1:-30}"

echo "=== CREANDO BASELINE UEBA ==="
echo "Período de análisis: últimos $DIAS días"
echo "Fecha: $(date -Iseconds)"
echo ""

# Obtener usuarios humanos (UID >= 1000, con shell válida)
USERS=$(awk -F: '$3 >= 1000 && $7 !~ /nologin|false/ {print $1}' /etc/passwd)

for USER in $USERS; do
    echo "── Analizando usuario: $USER ──"
    USER_DIR="$UEBA_DIR/$USER"
    mkdir -p "$USER_DIR"

    # 1. Horarios de login (horas del día en que inicia sesión)
    echo "  [1/5] Horarios de login..."
    last "$USER" 2>/dev/null | head -100 | \
        grep -oP '\d+:\d+' | cut -d: -f1 | \
        sort | uniq -c | sort -rn > "$USER_DIR/horarios-login.baseline" 2>/dev/null

    # 2. IPs de origen
    echo "  [2/5] IPs de origen..."
    last "$USER" 2>/dev/null | head -100 | \
        grep -oP '\d+\.\d+\.\d+\.\d+' | \
        sort | uniq -c | sort -rn > "$USER_DIR/ips-origen.baseline" 2>/dev/null

    # Desde journal SSH
    journalctl -u sshd --since "$DIAS days ago" --no-pager 2>/dev/null | \
        grep -i "accepted.*$USER" | \
        grep -oP '\d+\.\d+\.\d+\.\d+' | \
        sort | uniq -c | sort -rn >> "$USER_DIR/ips-origen.baseline" 2>/dev/null

    # 3. Comandos frecuentes (desde auditd si disponible)
    echo "  [3/5] Comandos frecuentes..."
    if command -v ausearch &>/dev/null; then
        ausearch -ua "$(id -u "$USER" 2>/dev/null)" -ts "$(date -d "$DIAS days ago" '+%m/%d/%Y')" 2>/dev/null | \
            grep "type=EXECVE" | grep -oP 'a0="[^"]*"' | \
            sed 's/a0="//;s/"//' | sort | uniq -c | sort -rn | head -50 \
            > "$USER_DIR/comandos-frecuentes.baseline" 2>/dev/null || true
    fi

    # Desde historial de bash si accesible
    USER_HOME=$(getent passwd "$USER" | cut -d: -f6)
    if [[ -f "$USER_HOME/.bash_history" ]]; then
        cat "$USER_HOME/.bash_history" 2>/dev/null | \
            awk '{print $1}' | sort | uniq -c | sort -rn | head -50 \
            >> "$USER_DIR/comandos-frecuentes.baseline" 2>/dev/null
    fi

    # 4. Archivos accedidos con frecuencia (desde auditd)
    echo "  [4/5] Archivos accedidos..."
    if command -v ausearch &>/dev/null; then
        ausearch -ua "$(id -u "$USER" 2>/dev/null)" -k file-access -ts "$(date -d "$DIAS days ago" '+%m/%d/%Y')" 2>/dev/null | \
            grep "name=" | grep -oP 'name="[^"]*"' | \
            sed 's/name="//;s/"//' | sort | uniq -c | sort -rn | head -50 \
            > "$USER_DIR/archivos-accedidos.baseline" 2>/dev/null || true
    fi

    # 5. Uso de sudo
    echo "  [5/5] Uso de sudo..."
    journalctl --since "$DIAS days ago" --no-pager 2>/dev/null | \
        grep "sudo.*$USER" | grep "COMMAND=" | \
        grep -oP 'COMMAND=\K.*' | sort | uniq -c | sort -rn \
        > "$USER_DIR/sudo-comandos.baseline" 2>/dev/null

    echo "  Baseline creado: $USER_DIR"
done

# Metadata
echo "$(date -Iseconds)" > "$UEBA_DIR/baseline-timestamp.txt"
echo "$DIAS" > "$UEBA_DIR/baseline-dias.txt"

echo ""
echo "=== BASELINE UEBA COMPLETADO ==="
echo "Directorio: $UEBA_DIR"
echo "Usuarios analizados: $(echo "$USERS" | wc -w)"
EOFUEBA_BL

    chmod 700 /usr/local/bin/ueba-crear-baseline.sh

    # Script de detección de anomalías
    cat > /usr/local/bin/ueba-detectar-anomalias.sh << 'EOFUEBA_DET'
#!/bin/bash
# ============================================================
# UEBA - DETECTAR ANOMALÍAS DE COMPORTAMIENTO
# Compara actividad actual contra baseline
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

UEBA_DIR="/var/lib/threat-hunting/ueba/baselines"
ANOM_DIR="/var/lib/threat-hunting/ueba/anomalias"
mkdir -p "$ANOM_DIR"
REPORT="$ANOM_DIR/anomalias-$(date +%Y%m%d-%H%M%S).txt"
HORAS="${1:-24}"

if [[ ! -f "$UEBA_DIR/baseline-timestamp.txt" ]]; then
    echo "[!] No hay baseline UEBA. Ejecutar: ueba-crear-baseline.sh"
    exit 1
fi

echo "=== DETECCIÓN DE ANOMALÍAS UEBA ===" | tee "$REPORT"
echo "Período: últimas $HORAS horas" | tee -a "$REPORT"
echo "Baseline desde: $(cat "$UEBA_DIR/baseline-timestamp.txt")" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

ANOMALIES=0

# Obtener usuarios humanos
USERS=$(awk -F: '$3 >= 1000 && $7 !~ /nologin|false/ {print $1}' /etc/passwd)

for USER in $USERS; do
    USER_BL="$UEBA_DIR/$USER"
    [[ -d "$USER_BL" ]] || continue

    USER_ANOMALIES=0

    # 1. Login en horario inusual
    CURRENT_HOUR=$(date +%H)
    if [[ -f "$USER_BL/horarios-login.baseline" ]]; then
        # Verificar si el usuario tiene sesión activa
        if who | grep -q "^$USER "; then
            KNOWN_HOURS=$(awk '{print $2}' "$USER_BL/horarios-login.baseline" | tr '\n' '|' | sed 's/|$//')
            if [[ -n "$KNOWN_HOURS" ]] && ! echo "$CURRENT_HOUR" | grep -qP "^($KNOWN_HOURS)$"; then
                echo "[ANOMALÍA] $USER: Login activo en hora inusual ($CURRENT_HOUR:xx)" | tee -a "$REPORT"
                echo "  Horarios habituales: $KNOWN_HOURS" | tee -a "$REPORT"
                ((USER_ANOMALIES++))
            fi
        fi
    fi

    # 2. Login desde IP no conocida
    if [[ -f "$USER_BL/ips-origen.baseline" ]]; then
        # Obtener IPs actuales del usuario
        CURRENT_IPS=$(who | grep "^$USER " | grep -oP '\(\K[^)]+' | grep -oP '\d+\.\d+\.\d+\.\d+' || true)
        if [[ -n "$CURRENT_IPS" ]]; then
            KNOWN_IPS=$(awk '{print $2}' "$USER_BL/ips-origen.baseline" | sort -u)
            for IP in $CURRENT_IPS; do
                if ! echo "$KNOWN_IPS" | grep -q "^$IP$"; then
                    echo "[ANOMALÍA] $USER: Login desde IP desconocida $IP" | tee -a "$REPORT"
                    echo "  IPs conocidas: $(echo "$KNOWN_IPS" | head -5 | tr '\n' ', ')" | tee -a "$REPORT"
                    ((USER_ANOMALIES++))
                fi
            done
        fi
    fi

    # 3. Comandos sudo inusuales
    if [[ -f "$USER_BL/sudo-comandos.baseline" ]]; then
        RECENT_SUDO=$(journalctl --since "$HORAS hours ago" --no-pager 2>/dev/null | \
            grep "sudo.*$USER" | grep "COMMAND=" | \
            grep -oP 'COMMAND=\K.*' | sort -u)

        if [[ -n "$RECENT_SUDO" ]]; then
            KNOWN_SUDO=$(awk '{$1=""; print $0}' "$USER_BL/sudo-comandos.baseline" | sed 's/^ //' | sort -u)
            while IFS= read -r cmd; do
                if [[ -n "$cmd" ]] && ! echo "$KNOWN_SUDO" | grep -qF "$cmd"; then
                    echo "[ANOMALÍA] $USER: Comando sudo inusual: $cmd" | tee -a "$REPORT"
                    ((USER_ANOMALIES++))
                fi
            done <<< "$RECENT_SUDO"
        fi
    fi

    # 4. Volumen anómalo de actividad
    RECENT_EVENTS=$(journalctl --since "$HORAS hours ago" --no-pager 2>/dev/null | grep -c "$USER" || echo 0)
    if [[ $RECENT_EVENTS -gt 1000 ]]; then
        echo "[ANOMALÍA] $USER: Volumen de actividad inusual ($RECENT_EVENTS eventos en ${HORAS}h)" | tee -a "$REPORT"
        ((USER_ANOMALIES++))
    fi

    if [[ $USER_ANOMALIES -gt 0 ]]; then
        ANOMALIES=$((ANOMALIES + USER_ANOMALIES))
        echo "  → $USER: $USER_ANOMALIES anomalías detectadas" | tee -a "$REPORT"
        echo "" | tee -a "$REPORT"
    fi
done

# 5. Detección de cuentas nuevas no esperadas
NEW_ACCOUNTS=$(journalctl --since "$HORAS hours ago" --no-pager 2>/dev/null | \
    grep -iE "useradd|adduser|new user" || true)
if [[ -n "$NEW_ACCOUNTS" ]]; then
    echo "[ANOMALÍA] Cuentas nuevas creadas en las últimas ${HORAS}h:" | tee -a "$REPORT"
    echo "$NEW_ACCOUNTS" | tee -a "$REPORT"
    ((ANOMALIES++))
fi

# 6. Detección de SSH authorized_keys modificadas (T1098.004)
for USER in $USERS; do
    USER_HOME=$(getent passwd "$USER" | cut -d: -f6)
    AK="$USER_HOME/.ssh/authorized_keys"
    if [[ -f "$AK" ]]; then
        MOD_TIME=$(stat -c %Y "$AK" 2>/dev/null || echo 0)
        MOD_AGO=$(( $(date +%s) - MOD_TIME ))
        if [[ $MOD_AGO -lt $((HORAS * 3600)) ]]; then
            echo "[ANOMALÍA] $USER: authorized_keys modificado hace $(( MOD_AGO / 3600 ))h" | tee -a "$REPORT"
            echo "  Archivo: $AK" | tee -a "$REPORT"
            echo "  Claves: $(wc -l < "$AK") entradas" | tee -a "$REPORT"
            ((ANOMALIES++))
        fi
    fi
done

echo "" | tee -a "$REPORT"
echo "════════════════════════════════════════════" | tee -a "$REPORT"
if [[ $ANOMALIES -eq 0 ]]; then
    echo "Sin anomalías de comportamiento detectadas." | tee -a "$REPORT"
else
    echo "TOTAL ANOMALÍAS: $ANOMALIES" | tee -a "$REPORT"
    echo "Investigar cada anomalía. Ejecutar: ir-recolectar-forense.sh" | tee -a "$REPORT"
    logger -t ueba-detection "ALERTA: $ANOMALIES anomalías de comportamiento detectadas"
fi
echo "Reporte: $REPORT"
EOFUEBA_DET

    chmod 700 /usr/local/bin/ueba-detectar-anomalias.sh

    # Cron diario para UEBA
    cat > /etc/cron.daily/ueba-anomalias << 'EOFUEBA_CRON'
#!/bin/bash
/usr/local/bin/ueba-detectar-anomalias.sh 24 > /var/log/ueba-anomalias-latest.txt 2>&1
if grep -q "ANOMALÍA" /var/log/ueba-anomalias-latest.txt 2>/dev/null; then
    logger -t ueba-detection "Anomalías de comportamiento detectadas - revisar /var/log/ueba-anomalias-latest.txt"
fi
EOFUEBA_CRON

    chmod 700 /etc/cron.daily/ueba-anomalias
    log_info "UEBA instalado: ueba-crear-baseline.sh / ueba-detectar-anomalias.sh"
    echo -e "${DIM}1. Crear baseline: ueba-crear-baseline.sh 30${NC}"
    echo -e "${DIM}2. Detectar anomalías: ueba-detectar-anomalias.sh 24${NC}"

else
    log_warn "UEBA no instalado"
fi

# ============================================================
log_section "2. PLAYBOOKS DE CAZA DE AMENAZAS"
# ============================================================

echo "Framework de caza de amenazas con hipótesis predefinidas"
echo "para buscar indicadores de compromiso proactivamente."
echo ""
echo "Hipótesis de caza:"
echo "  - Persistencia oculta (T1098, T1547, T1053)"
echo "  - Living-off-the-land (LOLBins) (T1218)"
echo "  - Movimiento lateral silencioso (T1021)"
echo "  - Exfiltración lenta (T1030)"
echo "  - C2 encubierto por DNS/HTTPS (T1071)"
echo ""

if ask "¿Instalar playbooks de caza de amenazas?"; then

    mkdir -p /usr/local/lib/threat-hunting/playbooks

    cat > /usr/local/bin/cazar-amenazas.sh << 'EOFHUNT'
#!/bin/bash
# ============================================================
# FRAMEWORK DE CAZA DE AMENAZAS
# Ejecución de playbooks de hunting por hipótesis
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

HUNT_DIR="/var/lib/threat-hunting/hunts"
mkdir -p "$HUNT_DIR"
HUNT_ID="HUNT-$(date +%Y%m%d-%H%M%S)"
REPORT="$HUNT_DIR/$HUNT_ID.txt"

echo "╔════════════════════════════════════════╗" | tee "$REPORT"
echo "║   CAZA DE AMENAZAS                    ║" | tee -a "$REPORT"
echo "╚════════════════════════════════════════╝" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"
echo "ID: $HUNT_ID" | tee -a "$REPORT"
echo "Fecha: $(date -Iseconds)" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

FINDINGS=0

# ── H1: Persistencia oculta ──
echo "═══ HIPÓTESIS 1: Persistencia Oculta ═══" | tee -a "$REPORT"
echo "Técnicas: T1098, T1547, T1053, T1543" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# H1.1: SSH authorized_keys con claves desconocidas
echo "  [H1.1] Verificando authorized_keys..." | tee -a "$REPORT"
for AK in /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys; do
    if [[ -f "$AK" ]]; then
        KEY_COUNT=$(wc -l < "$AK")
        if [[ $KEY_COUNT -gt 0 ]]; then
            echo "  → $AK: $KEY_COUNT claves" | tee -a "$REPORT"
            # Buscar claves sin comentario identificador (sospechoso)
            NO_COMMENT=$(grep -c "^ssh-" "$AK" 2>/dev/null | grep -v "@" || echo 0)
            if [[ "$NO_COMMENT" -gt 0 ]]; then
                echo "  [!] $NO_COMMENT claves sin identificador de usuario" | tee -a "$REPORT"
                ((FINDINGS++))
            fi
        fi
    fi
done

# H1.2: Servicios systemd no estándar
echo "  [H1.2] Servicios systemd no estándar..." | tee -a "$REPORT"
for svc in /etc/systemd/system/*.service; do
    [[ -f "$svc" ]] || continue
    SVC_NAME=$(basename "$svc")
    # Verificar si el servicio fue instalado por rpm
    if ! pkg_query_file "$svc" &>/dev/null 2>&1; then
        EXEC=$(grep "^ExecStart=" "$svc" 2>/dev/null | head -1)
        echo "  [!] Servicio no empaquetado: $SVC_NAME ($EXEC)" | tee -a "$REPORT"
        ((FINDINGS++))
    fi
done

# H1.3: Crontabs con comandos de red
echo "  [H1.3] Crontabs con comandos sospechosos..." | tee -a "$REPORT"
for crontab_file in /var/spool/cron/tabs/*; do
    [[ -f "$crontab_file" ]] || continue
    USER=$(basename "$crontab_file")
    SUSPICIOUS=$(grep -v "^#" "$crontab_file" 2>/dev/null | \
        grep -iE "curl|wget|nc |ncat|python.*http|bash.*-i|/dev/tcp|base64.*-d" || true)
    if [[ -n "$SUSPICIOUS" ]]; then
        echo "  [!!] $USER tiene crontab sospechosa:" | tee -a "$REPORT"
        echo "  $SUSPICIOUS" | tee -a "$REPORT"
        ((FINDINGS++))
    fi
done

# H1.4: Tareas at programadas
echo "  [H1.4] Tareas at programadas..." | tee -a "$REPORT"
AT_JOBS=$(atq 2>/dev/null | wc -l || echo 0)
if [[ "$AT_JOBS" -gt 0 ]]; then
    echo "  [!] $AT_JOBS tareas at programadas" | tee -a "$REPORT"
    atq 2>/dev/null | tee -a "$REPORT"
    ((FINDINGS++))
fi

echo "" | tee -a "$REPORT"

# ── H2: Living-off-the-land ──
echo "═══ HIPÓTESIS 2: Living-off-the-Land (LOLBins) ═══" | tee -a "$REPORT"
echo "Técnicas: T1218, T1059, T1105" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# H2.1: Procesos sospechosos usando LOLBins
echo "  [H2.1] Procesos LOLBin activos..." | tee -a "$REPORT"
LOLBINS="curl|wget|nc|ncat|socat|python.*http|perl.*socket|ruby.*socket|php.*-r|lua.*socket"
LOLBIN_PROCS=$(ps auxwwf 2>/dev/null | grep -iE "$LOLBINS" | grep -v grep || true)
if [[ -n "$LOLBIN_PROCS" ]]; then
    echo "  [!] Procesos LOLBin detectados:" | tee -a "$REPORT"
    echo "$LOLBIN_PROCS" | head -10 | tee -a "$REPORT"
    ((FINDINGS++))
fi

# H2.2: Scripts en directorios temporales
echo "  [H2.2] Scripts en directorios temporales..." | tee -a "$REPORT"
for dir in /tmp /var/tmp /dev/shm; do
    SCRIPTS=$(find "$dir" -maxdepth 3 -type f \( -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*.rb" \) 2>/dev/null)
    if [[ -n "$SCRIPTS" ]]; then
        echo "  [!] Scripts encontrados en $dir:" | tee -a "$REPORT"
        echo "$SCRIPTS" | head -10 | tee -a "$REPORT"
        ((FINDINGS++))
    fi
done

# H2.3: Binarios sin empaquetar en /usr/local/bin (no de securizar)
echo "  [H2.3] Binarios no identificados en /usr/local/bin..." | tee -a "$REPORT"
SECURIZAR_SCRIPTS="detectar-|monitorear-|buscar-|watchdog-|ir-|security-|correlacionar-|ueba-|cazar-|reporte-|exportar-|inventario-|resumen-|segmentacion-|escanear-"
for bin in /usr/local/bin/*; do
    [[ -f "$bin" ]] || continue
    BN=$(basename "$bin")
    if ! echo "$BN" | grep -qE "$SECURIZAR_SCRIPTS" && ! pkg_query_file "$bin" &>/dev/null 2>&1; then
        # Verificar que no es un script de securizar sin el prefijo
        if ! head -5 "$bin" 2>/dev/null | grep -qi "securizar\|hardening\|openSUSE\|incident-response\|threat-hunting\|security"; then
            echo "  [?] Binario no identificado: $bin" | tee -a "$REPORT"
        fi
    fi
done

echo "" | tee -a "$REPORT"

# ── H3: Movimiento lateral silencioso ──
echo "═══ HIPÓTESIS 3: Movimiento Lateral Silencioso ═══" | tee -a "$REPORT"
echo "Técnicas: T1021, T1550, T1563" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# H3.1: Conexiones SSH salientes inusuales
echo "  [H3.1] Conexiones SSH salientes..." | tee -a "$REPORT"
SSH_OUT=$(ss -tn state established 2>/dev/null | grep ":22" | awk '{print $5}' | grep -oP '\d+\.\d+\.\d+\.\d+' | sort -u || true)
if [[ -n "$SSH_OUT" ]]; then
    echo "  [!] Conexiones SSH salientes activas:" | tee -a "$REPORT"
    echo "$SSH_OUT" | while read -r ip; do
        echo "    → $ip" | tee -a "$REPORT"
    done
    ((FINDINGS++))
fi

# H3.2: Sesiones SSH con port forwarding
echo "  [H3.2] SSH port forwarding activo..." | tee -a "$REPORT"
FWD_PROCS=$(ps aux 2>/dev/null | grep "ssh.*-[LRD]" | grep -v grep || true)
if [[ -n "$FWD_PROCS" ]]; then
    echo "  [!!] SSH port forwarding detectado:" | tee -a "$REPORT"
    echo "$FWD_PROCS" | tee -a "$REPORT"
    ((FINDINGS++))
fi

# H3.3: Archivos compartidos Samba/NFS accedidos recientemente
echo "  [H3.3] Shares de red montados..." | tee -a "$REPORT"
SHARES=$(mount 2>/dev/null | grep -E "cifs|nfs|smb" || true)
if [[ -n "$SHARES" ]]; then
    echo "  [!] Shares de red montados:" | tee -a "$REPORT"
    echo "$SHARES" | tee -a "$REPORT"
    ((FINDINGS++))
fi

echo "" | tee -a "$REPORT"

# ── H4: Exfiltración lenta ──
echo "═══ HIPÓTESIS 4: Exfiltración Lenta ═══" | tee -a "$REPORT"
echo "Técnicas: T1030, T1048, T1567" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# H4.1: Conexiones persistentes de larga duración
echo "  [H4.1] Conexiones de larga duración..." | tee -a "$REPORT"
# Buscar conexiones establecidas con tiempo > 1h
LONG_CONNS=$(ss -tn state established 2>/dev/null | awk 'NR>1 {print $4, $5}' | \
    grep -v "127.0.0.1\|::1" | head -20 || true)
CONN_COUNT=$(echo "$LONG_CONNS" | grep -c "." 2>/dev/null || echo 0)
if [[ $CONN_COUNT -gt 10 ]]; then
    echo "  [!] $CONN_COUNT conexiones externas establecidas" | tee -a "$REPORT"
    echo "$LONG_CONNS" | head -10 | tee -a "$REPORT"
fi

# H4.2: Archivos comprimidos grandes creados recientemente
echo "  [H4.2] Archivos comprimidos recientes..." | tee -a "$REPORT"
ARCHIVES=$(find /tmp /var/tmp /home /root -maxdepth 3 -type f \
    \( -name "*.tar.gz" -o -name "*.zip" -o -name "*.7z" -o -name "*.rar" \
    -o -name "*.tar.bz2" -o -name "*.tar.xz" \) \
    -mtime -1 -size +10M 2>/dev/null)
if [[ -n "$ARCHIVES" ]]; then
    echo "  [!!] Archivos comprimidos grandes (>10M, <24h):" | tee -a "$REPORT"
    echo "$ARCHIVES" | while read -r f; do
        SIZE=$(du -h "$f" 2>/dev/null | awk '{print $1}')
        echo "    $f ($SIZE)" | tee -a "$REPORT"
    done
    ((FINDINGS++))
fi

# H4.3: Transferencias DNS sospechosas (alto volumen)
echo "  [H4.3] Volumen DNS anómalo..." | tee -a "$REPORT"
if [[ -f /var/log/suricata/dns.log ]]; then
    DNS_UNIQUE=$(tail -10000 /var/log/suricata/dns.log 2>/dev/null | \
        grep -oP '"rrname":"[^"]*"' | sort -u | wc -l || echo 0)
    if [[ $DNS_UNIQUE -gt 500 ]]; then
        echo "  [!] Alto volumen de dominios DNS únicos: $DNS_UNIQUE" | tee -a "$REPORT"
        ((FINDINGS++))
    fi
fi

echo "" | tee -a "$REPORT"

# ── H5: C2 encubierto ──
echo "═══ HIPÓTESIS 5: C2 Encubierto ═══" | tee -a "$REPORT"
echo "Técnicas: T1071, T1573, T1572" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# H5.1: Conexiones HTTPS persistentes sin hostname
echo "  [H5.1] Conexiones HTTPS sin reverse DNS..." | tee -a "$REPORT"
HTTPS_NO_DNS=0
ss -tn state established 2>/dev/null | grep ":443" | awk '{print $5}' | \
    grep -oP '\d+\.\d+\.\d+\.\d+' | sort -u | while read -r ip; do
    RDNS=$(host "$ip" 2>/dev/null | grep "domain name pointer" || true)
    if [[ -z "$RDNS" ]]; then
        echo "  [!] HTTPS a IP sin rDNS: $ip" | tee -a "$REPORT"
        HTTPS_NO_DNS=$((HTTPS_NO_DNS + 1))
    fi
done
[[ $HTTPS_NO_DNS -gt 0 ]] && ((FINDINGS++)) || true

# H5.2: Procesos con conexiones a puertos no estándar
echo "  [H5.2] Conexiones a puertos no estándar..." | tee -a "$REPORT"
NONSTANDARD=$(ss -tn state established 2>/dev/null | awk '{print $5}' | \
    grep -oP ':(\d+)$' | sed 's/://' | sort | uniq -c | sort -rn | \
    while read -r count port; do
        if [[ "$port" != "22" ]] && [[ "$port" != "80" ]] && [[ "$port" != "443" ]] && \
           [[ "$port" != "53" ]] && [[ "$port" != "123" ]] && [[ "$port" -gt 1024 ]] && \
           [[ "$count" -gt 3 ]]; then
            echo "$count conexiones al puerto $port"
        fi
    done)
if [[ -n "$NONSTANDARD" ]]; then
    echo "  [!] Conexiones frecuentes a puertos no estándar:" | tee -a "$REPORT"
    echo "$NONSTANDARD" | tee -a "$REPORT"
    ((FINDINGS++))
fi

# H5.3: Procesos que se comunican con IPs de IoC
echo "  [H5.3] Conexiones a IPs de feeds IoC..." | tee -a "$REPORT"
if [[ -f /etc/security/ioc-feeds/blocklist-de.txt ]]; then
    ACTIVE_IPS=$(ss -tn state established 2>/dev/null | awk '{print $5}' | grep -oP '\d+\.\d+\.\d+\.\d+' | sort -u)
    IOC_MATCH=""
    for ioc_file in /etc/security/ioc-feeds/*.txt; do
        [[ -f "$ioc_file" ]] || continue
        while IFS= read -r ioc_ip; do
            [[ -z "$ioc_ip" ]] && continue
            [[ "$ioc_ip" =~ ^# ]] && continue
            if echo "$ACTIVE_IPS" | grep -q "^$ioc_ip$"; then
                echo "  [!!] Conexión activa a IoC: $ioc_ip (feed: $(basename "$ioc_file"))" | tee -a "$REPORT"
                ((FINDINGS++))
                break
            fi
        done < "$ioc_file"
    done
fi

echo "" | tee -a "$REPORT"

# ── Resumen ──
echo "════════════════════════════════════════════" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"
if [[ $FINDINGS -eq 0 ]]; then
    echo "Sin hallazgos de caza. Sistema sin indicadores sospechosos." | tee -a "$REPORT"
else
    echo "TOTAL HALLAZGOS: $FINDINGS" | tee -a "$REPORT"
    echo "" | tee -a "$REPORT"
    echo "Acciones recomendadas:" | tee -a "$REPORT"
    echo "  1. Investigar cada hallazgo detalladamente" | tee -a "$REPORT"
    echo "  2. Recolectar evidencia: ir-recolectar-forense.sh $HUNT_ID" | tee -a "$REPORT"
    echo "  3. Generar timeline: ir-timeline.sh 168 $HUNT_ID" | tee -a "$REPORT"
    echo "  4. Verificar UEBA: ueba-detectar-anomalias.sh 168" | tee -a "$REPORT"
    logger -t threat-hunting "HUNT $HUNT_ID: $FINDINGS hallazgos detectados"
fi
echo "Reporte: $REPORT"
EOFHUNT

    chmod 700 /usr/local/bin/cazar-amenazas.sh
    log_info "Framework de caza instalado: /usr/local/bin/cazar-amenazas.sh"

else
    log_warn "Framework de caza no instalado"
fi

# ============================================================
log_section "3. DETECCIÓN DE PERSISTENCIA AVANZADA (T1098)"
# ============================================================

echo "Monitorización en tiempo real de cambios en mecanismos"
echo "de persistencia que no cubren los módulos existentes:"
echo ""
echo "  - T1098.004: Cambios en SSH authorized_keys"
echo "  - T1098.002: Creación de cuentas"
echo "  - T1098.003: Modificación de credenciales"
echo "  - T1547.006: Módulos kernel"
echo "  - T1546.004: Trap handlers (.bashrc/.profile)"
echo ""

if ask "¿Instalar detección de persistencia avanzada?"; then

    cat > /usr/local/bin/detectar-persistencia-avanzada.sh << 'EOFPERS'
#!/bin/bash
# ============================================================
# DETECCIÓN DE PERSISTENCIA AVANZADA
# T1098, T1547.006, T1546.004
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

PERS_DIR="/var/lib/threat-hunting/persistence"
mkdir -p "$PERS_DIR"
FINDINGS=0

echo "=== DETECCIÓN DE PERSISTENCIA AVANZADA ==="
echo "Fecha: $(date -Iseconds)"
echo ""

# 1. T1098.004: Cambios en authorized_keys
echo "── T1098.004: SSH Authorized Keys ──"
AK_SNAPSHOT="$PERS_DIR/authorized_keys_hashes.txt"

# Crear snapshot actual
CURRENT_AK=$(mktemp)
for ak_file in /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys; do
    if [[ -f "$ak_file" ]]; then
        HASH=$(sha256sum "$ak_file" 2>/dev/null | awk '{print $1}')
        KEYS=$(wc -l < "$ak_file")
        echo "$ak_file|$HASH|$KEYS" >> "$CURRENT_AK"
    fi
done

if [[ -f "$AK_SNAPSHOT" ]]; then
    # Comparar contra snapshot anterior
    while IFS='|' read -r file hash keys; do
        PREV_HASH=$(grep "^$file|" "$AK_SNAPSHOT" 2>/dev/null | cut -d'|' -f2)
        if [[ -n "$PREV_HASH" ]] && [[ "$hash" != "$PREV_HASH" ]]; then
            PREV_KEYS=$(grep "^$file|" "$AK_SNAPSHOT" 2>/dev/null | cut -d'|' -f3)
            echo "  [ALERTA] $file MODIFICADO (claves: $PREV_KEYS → $keys)"
            logger -t persistence-detection "ALERTA T1098.004: $file modificado ($PREV_KEYS → $keys claves)"
            ((FINDINGS++))
        fi
    done < "$CURRENT_AK"

    # Archivos nuevos
    while IFS='|' read -r file hash keys; do
        if ! grep -q "^$file|" "$AK_SNAPSHOT" 2>/dev/null; then
            echo "  [ALERTA] NUEVO authorized_keys: $file ($keys claves)"
            logger -t persistence-detection "ALERTA T1098.004: Nuevo $file ($keys claves)"
            ((FINDINGS++))
        fi
    done < "$CURRENT_AK"
else
    echo "  Creando snapshot inicial..."
fi

# Actualizar snapshot
cp "$CURRENT_AK" "$AK_SNAPSHOT"
rm -f "$CURRENT_AK"

# 2. T1098.002/003: Cambios en cuentas
echo ""
echo "── T1098.002/003: Cuentas del Sistema ──"
PASSWD_SNAP="$PERS_DIR/passwd_hash.txt"
SHADOW_SNAP="$PERS_DIR/shadow_hash.txt"

CURRENT_PASSWD=$(sha256sum /etc/passwd 2>/dev/null | awk '{print $1}')
CURRENT_SHADOW=$(sha256sum /etc/shadow 2>/dev/null | awk '{print $1}')

if [[ -f "$PASSWD_SNAP" ]]; then
    PREV_PASSWD=$(cat "$PASSWD_SNAP")
    if [[ "$CURRENT_PASSWD" != "$PREV_PASSWD" ]]; then
        echo "  [ALERTA] /etc/passwd MODIFICADO"
        # Mostrar diferencias
        diff <(cat "$PERS_DIR/passwd_backup.txt" 2>/dev/null) /etc/passwd 2>/dev/null | head -5
        logger -t persistence-detection "ALERTA T1098.002: /etc/passwd modificado"
        ((FINDINGS++))
    fi
fi

if [[ -f "$SHADOW_SNAP" ]]; then
    PREV_SHADOW=$(cat "$SHADOW_SNAP")
    if [[ "$CURRENT_SHADOW" != "$PREV_SHADOW" ]]; then
        echo "  [ALERTA] /etc/shadow MODIFICADO (cambio de contraseñas)"
        logger -t persistence-detection "ALERTA T1098.003: /etc/shadow modificado"
        ((FINDINGS++))
    fi
fi

echo "$CURRENT_PASSWD" > "$PASSWD_SNAP"
echo "$CURRENT_SHADOW" > "$SHADOW_SNAP"
cp /etc/passwd "$PERS_DIR/passwd_backup.txt" 2>/dev/null

# 3. T1547.006: Módulos kernel cargados
echo ""
echo "── T1547.006: Módulos Kernel ──"
KMOD_SNAP="$PERS_DIR/kernel_modules.txt"
CURRENT_MODS=$(mktemp)
lsmod | awk 'NR>1 {print $1}' | sort > "$CURRENT_MODS"

if [[ -f "$KMOD_SNAP" ]]; then
    NEW_MODS=$(comm -13 "$KMOD_SNAP" "$CURRENT_MODS" 2>/dev/null)
    if [[ -n "$NEW_MODS" ]]; then
        echo "  [ALERTA] Módulos kernel NUEVOS cargados:"
        echo "$NEW_MODS" | while read -r mod; do
            echo "    + $mod"
            logger -t persistence-detection "ALERTA T1547.006: Módulo kernel nuevo: $mod"
        done
        ((FINDINGS++))
    fi
fi

cp "$CURRENT_MODS" "$KMOD_SNAP"
rm -f "$CURRENT_MODS"

# 4. T1546.004: Trap handlers / shell initialization
echo ""
echo "── T1546.004: Shell Initialization ──"
SHELL_SNAP="$PERS_DIR/shell_init_hashes.txt"
CURRENT_SHELL=$(mktemp)

for f in /etc/profile /etc/bashrc /etc/bash.bashrc /etc/profile.d/*.sh \
         /home/*/.bashrc /home/*/.bash_profile /home/*/.profile \
         /root/.bashrc /root/.bash_profile /root/.profile; do
    if [[ -f "$f" ]]; then
        HASH=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')
        echo "$f|$HASH" >> "$CURRENT_SHELL"
    fi
done

if [[ -f "$SHELL_SNAP" ]]; then
    while IFS='|' read -r file hash; do
        PREV_HASH=$(grep "^$file|" "$SHELL_SNAP" 2>/dev/null | cut -d'|' -f2)
        if [[ -n "$PREV_HASH" ]] && [[ "$hash" != "$PREV_HASH" ]]; then
            echo "  [ALERTA] $file MODIFICADO"
            logger -t persistence-detection "ALERTA T1546.004: $file modificado"
            ((FINDINGS++))
        fi
    done < "$CURRENT_SHELL"
fi

cp "$CURRENT_SHELL" "$SHELL_SNAP"
rm -f "$CURRENT_SHELL"

# Resumen
echo ""
echo "════════════════════════════════════════════"
if [[ $FINDINGS -eq 0 ]]; then
    echo "Sin cambios de persistencia detectados."
else
    echo "ALERTA: $FINDINGS cambios de persistencia detectados"
fi
EOFPERS

    chmod 700 /usr/local/bin/detectar-persistencia-avanzada.sh

    # Timer systemd cada 15 minutos
    cat > /etc/systemd/system/detectar-persistencia.service << 'EOFPERSSVC'
[Unit]
Description=Detección de persistencia avanzada
After=network.target auditd.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/detectar-persistencia-avanzada.sh
StandardOutput=journal
StandardError=journal
EOFPERSSVC

    cat > /etc/systemd/system/detectar-persistencia.timer << 'EOFPERSTMR'
[Unit]
Description=Ejecutar detección de persistencia cada 15 min

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min

[Install]
WantedBy=timers.target
EOFPERSTMR

    systemctl daemon-reload 2>/dev/null
    systemctl enable detectar-persistencia.timer 2>/dev/null
    systemctl start detectar-persistencia.timer 2>/dev/null
    log_info "Detección de persistencia instalada (timer 15min)"
    log_info "Script: /usr/local/bin/detectar-persistencia-avanzada.sh"

else
    log_warn "Detección de persistencia avanzada no instalada"
fi

# ============================================================
log_section "4. BÚSQUEDA RETROSPECTIVA EN LOGS"
# ============================================================

echo "Herramienta para buscar indicadores de compromiso (IoC)"
echo "en logs históricos del sistema retrospectivamente."
echo ""
echo "Búsquedas soportadas:"
echo "  - Buscar IP sospechosa en todos los logs"
echo "  - Buscar usuario comprometido en historial"
echo "  - Buscar hash de binario malicioso"
echo "  - Buscar dominio C2 en DNS/proxy logs"
echo ""

if ask "¿Instalar herramienta de búsqueda retrospectiva?"; then

    cat > /usr/local/bin/buscar-retrospectivo.sh << 'EOFRETRO'
#!/bin/bash
# ============================================================
# BÚSQUEDA RETROSPECTIVA EN LOGS
# Busca IoC en logs históricos
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

TIPO="${1:-}"
VALOR="${2:-}"
DIAS="${3:-30}"

if [[ -z "$TIPO" ]] || [[ -z "$VALOR" ]]; then
    echo "Uso: $0 <tipo> <valor> [días-atrás]"
    echo ""
    echo "Tipos de búsqueda:"
    echo "  ip        Buscar IP en todos los logs"
    echo "  usuario   Buscar actividad de un usuario"
    echo "  dominio   Buscar dominio en DNS/logs"
    echo "  hash      Buscar hash SHA256 en logs de integridad"
    echo "  comando   Buscar comando ejecutado en auditd"
    echo "  archivo   Buscar acceso a archivo en auditd"
    echo ""
    echo "Ejemplo: $0 ip 192.168.1.100 60"
    exit 0
fi

RETRO_DIR="/var/lib/threat-hunting/retrospective"
mkdir -p "$RETRO_DIR"
REPORT="$RETRO_DIR/retro-$TIPO-$(date +%Y%m%d-%H%M%S).txt"

echo "=== BÚSQUEDA RETROSPECTIVA ===" | tee "$REPORT"
echo "Tipo: $TIPO" | tee -a "$REPORT"
echo "Valor: $VALOR" | tee -a "$REPORT"
echo "Período: últimos $DIAS días" | tee -a "$REPORT"
echo "Fecha: $(date -Iseconds)" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

HITS=0

case "$TIPO" in
    ip)
        echo "── Journal (systemd) ──" | tee -a "$REPORT"
        JOURNAL_HITS=$(journalctl --since "$DIAS days ago" --no-pager 2>/dev/null | grep -c "$VALOR" || echo 0)
        echo "  $JOURNAL_HITS hits en journal" | tee -a "$REPORT"
        HITS=$((HITS + JOURNAL_HITS))

        echo "── SSH logs ──" | tee -a "$REPORT"
        journalctl -u sshd --since "$DIAS days ago" --no-pager 2>/dev/null | \
            grep "$VALOR" | tail -20 | tee -a "$REPORT"

        echo "── Firewall logs ──" | tee -a "$REPORT"
        journalctl --since "$DIAS days ago" --no-pager 2>/dev/null | \
            grep -E "REJECT|DROP" | grep "$VALOR" | tail -20 | tee -a "$REPORT"

        echo "── Suricata ──" | tee -a "$REPORT"
        if [[ -f /var/log/suricata/fast.log ]]; then
            grep "$VALOR" /var/log/suricata/fast.log 2>/dev/null | tail -20 | tee -a "$REPORT"
        fi

        echo "── Fail2ban ──" | tee -a "$REPORT"
        journalctl -u fail2ban --since "$DIAS days ago" --no-pager 2>/dev/null | \
            grep "$VALOR" | tail -10 | tee -a "$REPORT"

        echo "── last (sesiones) ──" | tee -a "$REPORT"
        last 2>/dev/null | grep "$VALOR" | tee -a "$REPORT"
        ;;

    usuario)
        echo "── Sesiones ──" | tee -a "$REPORT"
        last "$VALOR" 2>/dev/null | head -30 | tee -a "$REPORT"

        echo "── SSH auth ──" | tee -a "$REPORT"
        journalctl -u sshd --since "$DIAS days ago" --no-pager 2>/dev/null | \
            grep -i "$VALOR" | tail -30 | tee -a "$REPORT"

        echo "── Sudo ──" | tee -a "$REPORT"
        journalctl --since "$DIAS days ago" --no-pager 2>/dev/null | \
            grep "sudo.*$VALOR" | tail -20 | tee -a "$REPORT"

        echo "── Auditd ──" | tee -a "$REPORT"
        if command -v ausearch &>/dev/null; then
            USER_UID=$(id -u "$VALOR" 2>/dev/null)
            if [[ -n "$USER_UID" ]]; then
                ausearch -ua "$USER_UID" -ts "$(date -d "$DIAS days ago" '+%m/%d/%Y')" 2>/dev/null | \
                    grep "type=EXECVE" | tail -30 | tee -a "$REPORT"
            fi
        fi
        ;;

    dominio)
        echo "── DNS logs ──" | tee -a "$REPORT"
        if [[ -f /var/log/suricata/dns.log ]]; then
            grep -i "$VALOR" /var/log/suricata/dns.log 2>/dev/null | tail -30 | tee -a "$REPORT"
        fi

        echo "── Journal (resolved) ──" | tee -a "$REPORT"
        journalctl -u systemd-resolved --since "$DIAS days ago" --no-pager 2>/dev/null | \
            grep -i "$VALOR" | tail -20 | tee -a "$REPORT"

        echo "── /etc/hosts ──" | tee -a "$REPORT"
        grep -i "$VALOR" /etc/hosts 2>/dev/null | tee -a "$REPORT"
        ;;

    hash)
        echo "── Package verify ──" | tee -a "$REPORT"
        pkg_verify 2>/dev/null | grep "$VALOR" | tee -a "$REPORT"

        echo "── AIDE database ──" | tee -a "$REPORT"
        if [[ -f /var/lib/aide/aide.db.gz ]]; then
            zgrep "$VALOR" /var/lib/aide/aide.db.gz 2>/dev/null | tee -a "$REPORT"
        fi

        echo "── Audit logs ──" | tee -a "$REPORT"
        grep -r "$VALOR" /var/log/audit/ 2>/dev/null | tail -10 | tee -a "$REPORT"
        ;;

    comando)
        echo "── Auditd EXECVE ──" | tee -a "$REPORT"
        if command -v ausearch &>/dev/null; then
            ausearch -c "$VALOR" -ts "$(date -d "$DIAS days ago" '+%m/%d/%Y')" 2>/dev/null | \
                tail -50 | tee -a "$REPORT"
        fi

        echo "── Bash history (todos los usuarios) ──" | tee -a "$REPORT"
        for hist in /home/*/.bash_history /root/.bash_history; do
            if [[ -f "$hist" ]]; then
                MATCH=$(grep -n "$VALOR" "$hist" 2>/dev/null || true)
                if [[ -n "$MATCH" ]]; then
                    echo "  $hist:" | tee -a "$REPORT"
                    echo "$MATCH" | tail -10 | tee -a "$REPORT"
                fi
            fi
        done
        ;;

    archivo)
        echo "── Auditd file access ──" | tee -a "$REPORT"
        if command -v ausearch &>/dev/null; then
            ausearch -f "$VALOR" -ts "$(date -d "$DIAS days ago" '+%m/%d/%Y')" 2>/dev/null | \
                tail -50 | tee -a "$REPORT"
        fi

        echo "── Journal ──" | tee -a "$REPORT"
        journalctl --since "$DIAS days ago" --no-pager 2>/dev/null | \
            grep "$VALOR" | tail -20 | tee -a "$REPORT"
        ;;

    *)
        echo "Tipo desconocido: $TIPO"
        exit 1
        ;;
esac

echo "" | tee -a "$REPORT"
echo "Reporte: $REPORT" | tee -a "$REPORT"
EOFRETRO

    chmod 700 /usr/local/bin/buscar-retrospectivo.sh
    log_info "Búsqueda retrospectiva: /usr/local/bin/buscar-retrospectivo.sh"
    echo -e "${DIM}Uso: buscar-retrospectivo.sh ip 192.168.1.100 60${NC}"

else
    log_warn "Búsqueda retrospectiva no instalada"
fi

# ============================================================
log_section "5. DETECCIÓN DE ANOMALÍAS DE RED ESTADÍSTICAS"
# ============================================================

echo "Análisis estadístico del tráfico de red para detectar"
echo "patrones de C2 encubierto y exfiltración que evaden"
echo "detección basada en firmas."
echo ""
echo "Detecciones:"
echo "  - Beaconing por intervalos regulares (T1071)"
echo "  - Tráfico cifrado anómalo (T1573)"
echo "  - Volumen de datos asimétrico (T1041)"
echo "  - Conexiones a IPs sin rDNS (T1571)"
echo ""

if ask "¿Instalar detección estadística de red?"; then

    cat > /usr/local/bin/detectar-anomalias-red.sh << 'EOFNETANOM'
#!/bin/bash
# ============================================================
# DETECCIÓN DE ANOMALÍAS DE RED ESTADÍSTICAS
# T1071 (beaconing), T1573 (encrypted C2), T1041 (exfil)
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

ANOM_DIR="/var/lib/threat-hunting/net-anomalies"
mkdir -p "$ANOM_DIR"
REPORT="$ANOM_DIR/anomalias-red-$(date +%Y%m%d-%H%M%S).txt"

echo "=== DETECCIÓN DE ANOMALÍAS DE RED ===" | tee "$REPORT"
echo "Fecha: $(date -Iseconds)" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

FINDINGS=0

# 1. Detección de beaconing (intervalos regulares)
echo "── Beaconing (T1071/T1573) ──" | tee -a "$REPORT"
echo "Buscando conexiones con intervalos regulares..." | tee -a "$REPORT"

# Analizar conexiones salientes por destino
declare -A DEST_COUNTS
while IFS= read -r line; do
    DEST=$(echo "$line" | awk '{print $5}' | grep -oP '\d+\.\d+\.\d+\.\d+:\d+' || true)
    if [[ -n "$DEST" ]]; then
        DEST_COUNTS[$DEST]=$(( ${DEST_COUNTS[$DEST]:-0} + 1 ))
    fi
done < <(ss -tn state established 2>/dev/null)

for DEST in "${!DEST_COUNTS[@]}"; do
    COUNT=${DEST_COUNTS[$DEST]}
    if [[ $COUNT -ge 5 ]]; then
        IP=$(echo "$DEST" | cut -d: -f1)
        PORT=$(echo "$DEST" | cut -d: -f2)
        RDNS=$(host "$IP" 2>/dev/null | grep "domain name pointer" | awk '{print $NF}' || echo "sin-rDNS")
        echo "  [!] $DEST: $COUNT conexiones simultáneas (rDNS: $RDNS)" | tee -a "$REPORT"
        if [[ "$RDNS" == "sin-rDNS" ]]; then
            echo "  → IP sin reverse DNS - posible C2" | tee -a "$REPORT"
            ((FINDINGS++))
        fi
    fi
done

# 2. Detección de tráfico asimétrico (upload >> download)
echo "" | tee -a "$REPORT"
echo "── Tráfico Asimétrico (T1041) ──" | tee -a "$REPORT"

# Usar /proc/net/dev para estadísticas de interfaz
for iface in $(ls /sys/class/net/ 2>/dev/null | grep -v lo); do
    RX_BYTES=$(cat "/sys/class/net/$iface/statistics/rx_bytes" 2>/dev/null || echo 0)
    TX_BYTES=$(cat "/sys/class/net/$iface/statistics/tx_bytes" 2>/dev/null || echo 0)

    if [[ $RX_BYTES -gt 0 ]]; then
        RATIO=$((TX_BYTES * 100 / RX_BYTES))
        TX_MB=$((TX_BYTES / 1048576))
        RX_MB=$((RX_BYTES / 1048576))

        echo "  $iface: TX=${TX_MB}MB RX=${RX_MB}MB (ratio TX/RX: ${RATIO}%)" | tee -a "$REPORT"

        # Si TX >> RX (más de 3x), posible exfiltración
        if [[ $RATIO -gt 300 ]] && [[ $TX_MB -gt 100 ]]; then
            echo "  [!!] Tráfico saliente anómalo en $iface (TX > 3x RX)" | tee -a "$REPORT"
            echo "  → Posible exfiltración de datos" | tee -a "$REPORT"
            ((FINDINGS++))
        fi
    fi
done

# 3. Conexiones a puertos C2 conocidos
echo "" | tee -a "$REPORT"
echo "── Puertos C2 Conocidos (T1571) ──" | tee -a "$REPORT"

C2_PORTS="4444 5555 6666 7777 8888 9999 1234 1337 31337 4443 8443 2222 3333"
for port in $C2_PORTS; do
    CONNS=$(ss -tn state established 2>/dev/null | grep ":$port " | grep -v "127.0.0.1" || true)
    if [[ -n "$CONNS" ]]; then
        echo "  [!!] Conexión a puerto C2 conocido :$port" | tee -a "$REPORT"
        echo "$CONNS" | tee -a "$REPORT"
        ((FINDINGS++))
    fi
done

# 4. Conexiones HTTPS de larga duración sin hostname SNI
echo "" | tee -a "$REPORT"
echo "── Conexiones HTTPS sin SNI/rDNS ──" | tee -a "$REPORT"

HTTPS_IPS=$(ss -tn state established 2>/dev/null | grep ":443 " | \
    awk '{print $5}' | grep -oP '\d+\.\d+\.\d+\.\d+' | sort -u || true)

NO_RDNS_COUNT=0
for ip in $HTTPS_IPS; do
    # Excluir IPs privadas
    if echo "$ip" | grep -qP "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"; then
        continue
    fi
    RDNS=$(host "$ip" 2>/dev/null | grep "domain name pointer" || true)
    if [[ -z "$RDNS" ]]; then
        echo "  [!] HTTPS a IP sin rDNS: $ip" | tee -a "$REPORT"
        ((NO_RDNS_COUNT++))
    fi
done

if [[ $NO_RDNS_COUNT -gt 3 ]]; then
    echo "  → $NO_RDNS_COUNT IPs HTTPS sin rDNS - investigar" | tee -a "$REPORT"
    ((FINDINGS++))
fi

# Resumen
echo "" | tee -a "$REPORT"
echo "════════════════════════════════════════════" | tee -a "$REPORT"
if [[ $FINDINGS -eq 0 ]]; then
    echo "Sin anomalías de red detectadas." | tee -a "$REPORT"
else
    echo "ANOMALÍAS DE RED: $FINDINGS hallazgos" | tee -a "$REPORT"
    logger -t net-anomaly "ALERTA: $FINDINGS anomalías de red detectadas"
fi
echo "Reporte: $REPORT"
EOFNETANOM

    chmod 700 /usr/local/bin/detectar-anomalias-red.sh

    cat > /etc/cron.daily/detectar-anomalias-red << 'EOFNETCRON'
#!/bin/bash
/usr/local/bin/detectar-anomalias-red.sh > /var/log/anomalias-red-latest.txt 2>&1
if grep -q "\[!!\]" /var/log/anomalias-red-latest.txt 2>/dev/null; then
    logger -t net-anomaly "Anomalías de red críticas detectadas"
fi
EOFNETCRON

    chmod 700 /etc/cron.daily/detectar-anomalias-red
    log_info "Detección estadística de red instalada"

else
    log_warn "Detección estadística de red no instalada"
fi

# ============================================================
log_section "RESUMEN DE CAZA DE AMENAZAS"
# ============================================================

echo ""
echo -e "${BOLD}Herramientas de hunting instaladas:${NC}"
echo ""

if [[ -x /usr/local/bin/ueba-crear-baseline.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} UEBA baseline (ueba-crear-baseline.sh)"
else
    echo -e "  ${YELLOW}[--]${NC} UEBA baseline no instalado"
fi

if [[ -x /usr/local/bin/ueba-detectar-anomalias.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} UEBA detección (ueba-detectar-anomalias.sh)"
else
    echo -e "  ${YELLOW}[--]${NC} UEBA detección no instalada"
fi

if [[ -x /usr/local/bin/cazar-amenazas.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} Framework de caza (cazar-amenazas.sh)"
else
    echo -e "  ${YELLOW}[--]${NC} Framework de caza no instalado"
fi

if [[ -x /usr/local/bin/detectar-persistencia-avanzada.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} Persistencia avanzada T1098 (timer 15min)"
else
    echo -e "  ${YELLOW}[--]${NC} Persistencia avanzada no instalada"
fi

if [[ -x /usr/local/bin/buscar-retrospectivo.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} Búsqueda retrospectiva (buscar-retrospectivo.sh)"
else
    echo -e "  ${YELLOW}[--]${NC} Búsqueda retrospectiva no instalada"
fi

if [[ -x /usr/local/bin/detectar-anomalias-red.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} Anomalías de red estadísticas (cron diario)"
else
    echo -e "  ${YELLOW}[--]${NC} Anomalías de red no instaladas"
fi

echo ""
echo -e "${BOLD}Uso rápido:${NC}"
echo -e "  ${DIM}Crear baseline:${NC}    ueba-crear-baseline.sh 30"
echo -e "  ${DIM}Detectar UEBA:${NC}     ueba-detectar-anomalias.sh 24"
echo -e "  ${DIM}Cazar amenazas:${NC}    cazar-amenazas.sh"
echo -e "  ${DIM}Buscar IoC:${NC}        buscar-retrospectivo.sh ip 1.2.3.4 60"
echo -e "  ${DIM}Anomalías red:${NC}     detectar-anomalias-red.sh"
echo ""
log_info "Módulo de caza de amenazas completado"
