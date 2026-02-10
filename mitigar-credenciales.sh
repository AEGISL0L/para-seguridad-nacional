#!/bin/bash
# ============================================================
# MITIGACIÓN DE ACCESO A CREDENCIALES - TA0006 (Credential Access)
# Linux Multi-Distro (openSUSE, Debian/Ubuntu, RHEL/Fedora, Arch)
# ============================================================
# Técnicas MITRE ATT&CK cubiertas:
#   T1003     - OS Credential Dumping
#   T1003.007 - /proc Filesystem (mimipenguin)
#   T1003.008 - /etc/passwd and /etc/shadow
#   T1110     - Brute Force
#   T1110.001 - Password Guessing
#   T1110.003 - Password Spraying
#   T1557     - Adversary-in-the-Middle
#   T1552     - Unsecured Credentials
#   T1552.001 - Credentials In Files
#   T1552.003 - Bash History
#   T1552.004 - Private Keys
#   T1040     - Network Sniffing
#   T1056.001 - Keylogging (detección)
#   T1539     - Steal Web Session Cookie
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "mitigar-credenciales"
securizar_setup_traps
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MITIGACIÓN DE ACCESO A CREDENCIALES - TA0006            ║"
echo "║   Proteger credenciales contra robo y abuso                ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups se guardarán en: $BACKUP_DIR"

# ============================================================
log_section "1. PROTECCIÓN CONTRA CREDENTIAL DUMPING (T1003)"
# ============================================================

echo "Prevenir el volcado de credenciales desde memoria y archivos."
echo "Herramientas como mimipenguin extraen contraseñas de /proc."
echo ""
echo "Medidas:"
echo "  - Restringir ptrace (bloquear depuración de procesos)"
echo "  - Proteger /proc/*/maps y /proc/*/mem"
echo "  - Endurecer permisos de /etc/shadow"
echo ""

if ask "¿Aplicar protección contra credential dumping?"; then

    # 1a. Restringir ptrace
    echo ""
    echo -e "${BOLD}Restringiendo ptrace...${NC}"

    SYSCTL_FILE="/etc/sysctl.d/91-credential-protection.conf"
    cp "$SYSCTL_FILE" "$BACKUP_DIR/" 2>/dev/null || true

    cat > "$SYSCTL_FILE" << 'EOF'
# Protección contra credential dumping - T1003
# Restringir ptrace: 0=todos, 1=solo hijos, 2=solo admin, 3=nadie
kernel.yama.ptrace_scope = 2

# Ocultar direcciones de kernel en /proc/kallsyms
kernel.kptr_restrict = 2

# Restringir dmesg a root
kernel.dmesg_restrict = 1

# Restringir acceso a perf
kernel.perf_event_paranoid = 3

# Ocultar PIDs de otros usuarios
# (requiere hidepid mount en /proc)
EOF

    sysctl -p "$SYSCTL_FILE" 2>/dev/null || true
    log_info "ptrace restringido a solo admin (scope=2)"

    # 1b. Montar /proc con hidepid
    echo ""
    echo -e "${BOLD}Configurando hidepid en /proc...${NC}"

    if ! grep -q "hidepid" /etc/fstab 2>/dev/null; then
        cp /etc/fstab "$BACKUP_DIR/"
        _priv_group=$(get_privileged_group)
        # Añadir mount de /proc con hidepid=2
        echo "" >> /etc/fstab
        echo "# T1003 - Ocultar procesos de otros usuarios" >> /etc/fstab
        echo "proc    /proc    proc    defaults,hidepid=2,gid=${_priv_group}    0    0" >> /etc/fstab

        # Aplicar ahora
        mount -o "remount,hidepid=2,gid=${_priv_group}" /proc 2>/dev/null || \
            log_warn "No se pudo remontar /proc con hidepid (se aplicará en reinicio)"

        log_info "hidepid=2 configurado en /proc (grupo ${_priv_group}, usuarios solo ven sus procesos)"
        unset _priv_group
    else
        echo -e "  ${GREEN}OK${NC} hidepid ya configurado en /proc"
    fi

    # 1c. Permisos estrictos en archivos de credenciales
    echo ""
    echo -e "${BOLD}Endureciendo permisos de archivos de credenciales...${NC}"

    chmod 000 /etc/shadow 2>/dev/null && echo -e "  ${GREEN}OK${NC} /etc/shadow: 000"
    chmod 000 /etc/gshadow 2>/dev/null && echo -e "  ${GREEN}OK${NC} /etc/gshadow: 000"
    chmod 644 /etc/passwd 2>/dev/null && echo -e "  ${GREEN}OK${NC} /etc/passwd: 644"
    chmod 644 /etc/group 2>/dev/null && echo -e "  ${GREEN}OK${NC} /etc/group: 644"

    # Reglas auditd para acceso a credenciales
    if command -v auditctl &>/dev/null; then
        cat > /etc/audit/rules.d/62-credential-access.rules << 'EOF'
## Protección de credenciales - T1003
# Monitorear acceso a archivos de credenciales
-w /etc/shadow -p rwa -k credential-access
-w /etc/gshadow -p rwa -k credential-access
-w /etc/passwd -p wa -k credential-access
-w /etc/security/opasswd -p rwa -k credential-access

# Monitorear uso de herramientas de dumping
-w /usr/bin/gcore -p x -k credential-dump
-w /usr/bin/gdb -p x -k credential-dump

# Monitorear acceso a /proc/*/mem (T1003.007)
-a always,exit -F arch=b64 -S ptrace -k credential-ptrace

# Monitorear uso de nsswitch y PAM
-w /etc/nsswitch.conf -p wa -k credential-config
-w /etc/pam.d/ -p wa -k pam-config-change
EOF

        augenrules --load 2>/dev/null || true
        log_info "Reglas auditd de protección de credenciales creadas"
    fi

    log_info "Protección contra credential dumping aplicada"
else
    log_warn "Protección contra credential dumping no aplicada"
fi

# ============================================================
log_section "2. PROTECCIÓN CONTRA FUERZA BRUTA (T1110)"
# ============================================================

echo "Mitigar ataques de fuerza bruta, password guessing y spraying."
echo ""
echo "Medidas:"
echo "  - faillock: bloqueo de cuentas tras intentos fallidos"
echo "  - Políticas de contraseña fuertes"
echo "  - Monitoreo de intentos fallidos"
echo ""

if ask "¿Configurar protección contra fuerza bruta?"; then

    # 2a. Verificar/configurar faillock
    echo ""
    echo -e "${BOLD}Configurando faillock...${NC}"

    FAILLOCK_CONF="/etc/security/faillock.conf"
    if [[ -f "$FAILLOCK_CONF" ]]; then
        cp "$FAILLOCK_CONF" "$BACKUP_DIR/"
    fi

    cat > "$FAILLOCK_CONF" << 'EOF'
# Protección contra fuerza bruta - T1110
# Bloquear cuenta después de 5 intentos fallidos
deny = 5
# Tiempo de bloqueo: 15 minutos
unlock_time = 900
# Ventana de tiempo para contar fallos: 15 minutos
fail_interval = 900
# No bloquear root (para evitar lockout total)
even_deny_root = false
# Directorio de datos de faillock
dir = /var/run/faillock
# Auditar intentos
audit
# Silenciar mensajes al usuario
silent
EOF

    log_info "faillock configurado: 5 intentos, bloqueo 15min"

    # 2b. Política de contraseñas fuertes con pwquality
    echo ""
    echo -e "${BOLD}Configurando políticas de contraseña...${NC}"

    PWQUALITY_CONF="/etc/security/pwquality.conf"
    if [[ -f "$PWQUALITY_CONF" ]]; then
        cp "$PWQUALITY_CONF" "$BACKUP_DIR/"
    fi

    cat > "$PWQUALITY_CONF" << 'EOF'
# Política de contraseñas - T1110
# Longitud mínima: 12 caracteres
minlen = 12
# Mínimo de clases diferentes (mayúsculas, minúsculas, números, símbolos)
minclass = 3
# Máximo de caracteres consecutivos iguales
maxrepeat = 3
# Máximo de caracteres secuenciales (abc, 123)
maxsequence = 3
# No permitir que contenga el nombre de usuario
usercheck = 1
# Verificar contra diccionario
dictcheck = 1
# Complejidad mínima por tipo
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
# Mínimo de caracteres diferentes respecto a la anterior
difok = 5
# Rechazar palíndromos
palindrome = 1
EOF

    log_info "Política de contraseñas configurada (min 12 chars, 3 clases)"

    # 2c. Script de monitoreo de intentos de fuerza bruta
    cat > /usr/local/bin/monitorear-bruteforce.sh << 'EOFBRUTE'
#!/bin/bash
# Monitoreo de fuerza bruta - T1110
LOG="/var/log/bruteforce-monitor-$(date +%Y%m%d).log"

echo "=== Monitoreo de Fuerza Bruta - $(date) ===" | tee "$LOG"

# 1. Intentos SSH fallidos (últimas 24h)
echo "" | tee -a "$LOG"
echo "--- Intentos SSH fallidos (24h) ---" | tee -a "$LOG"

SSH_FAILS=$(journalctl -u sshd --since "24 hours ago" 2>/dev/null | grep -c "Failed password\|authentication failure\|Invalid user" || echo 0)
echo "Total intentos fallidos SSH: $SSH_FAILS" | tee -a "$LOG"

if [[ "$SSH_FAILS" -gt 50 ]]; then
    echo "ALERTA: Posible ataque de fuerza bruta SSH ($SSH_FAILS intentos)" | tee -a "$LOG"
    logger -t monitor-bruteforce "ALERTA: $SSH_FAILS intentos SSH fallidos (T1110)"
fi

# Top IPs atacantes
echo "" | tee -a "$LOG"
echo "Top 10 IPs con intentos fallidos:" | tee -a "$LOG"
journalctl -u sshd --since "24 hours ago" 2>/dev/null | \
    grep -oP "from \K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | \
    sort | uniq -c | sort -rn | head -10 | tee -a "$LOG"

# 2. Cuentas bloqueadas por faillock
echo "" | tee -a "$LOG"
echo "--- Cuentas bloqueadas (faillock) ---" | tee -a "$LOG"

if command -v faillock &>/dev/null; then
    LOCKED=$(faillock --dir /var/run/faillock 2>/dev/null | grep -v "^$\|^When" || true)
    if [[ -n "$LOCKED" ]]; then
        echo "$LOCKED" | tee -a "$LOG"
    else
        echo "OK: No hay cuentas bloqueadas" | tee -a "$LOG"
    fi
fi

# 3. Intentos su/sudo fallidos
echo "" | tee -a "$LOG"
echo "--- Intentos su/sudo fallidos (24h) ---" | tee -a "$LOG"

SU_FAILS=$(journalctl --since "24 hours ago" 2>/dev/null | grep -c "FAILED su\|authentication failure.*sudo\|incorrect password.*sudo" || echo 0)
echo "Intentos su/sudo fallidos: $SU_FAILS" | tee -a "$LOG"

find /var/log -name "bruteforce-monitor-*.log" -mtime +30 -delete 2>/dev/null || true
EOFBRUTE

    chmod 700 /usr/local/bin/monitorear-bruteforce.sh

    cat > /etc/cron.daily/monitorear-bruteforce << 'EOFCRON'
#!/bin/bash
/usr/local/bin/monitorear-bruteforce.sh 2>&1 | logger -t monitor-bruteforce
EOFCRON
    chmod 700 /etc/cron.daily/monitorear-bruteforce

    log_info "Monitoreo diario de fuerza bruta configurado"
else
    log_warn "Protección contra fuerza bruta no configurada"
fi

# ============================================================
log_section "3. PROTECCIÓN CONTRA MITM (T1557)"
# ============================================================

echo "Mitigar ataques Man-in-the-Middle en la red local."
echo ""
echo "Medidas:"
echo "  - Protección ARP (arp spoofing)"
echo "  - Verificación de certificados SSL/TLS"
echo "  - Detección de rogue DHCP"
echo ""

if ask "¿Configurar protección contra MITM?"; then

    # 3a. Instalar y configurar arpwatch
    if ! command -v arpwatch &>/dev/null; then
        echo "Instalando arpwatch..."
        pkg_install arpwatch
    fi

    if command -v arpwatch &>/dev/null; then
        systemctl enable --now arpwatch 2>/dev/null || true
        log_info "arpwatch activado (monitoreo de cambios ARP)"
    fi

    # 3b. Configurar ARP estático para gateway
    echo ""
    echo -e "${BOLD}Configurando protección ARP...${NC}"

    GATEWAY=$(ip route | grep default | awk '{print $3}' | head -1)
    if [[ -n "$GATEWAY" ]]; then
        GATEWAY_MAC=$(ip neigh show "$GATEWAY" 2>/dev/null | awk '{print $5}' | head -1)
        if [[ -n "$GATEWAY_MAC" ]] && [[ "$GATEWAY_MAC" != "FAILED" ]]; then
            echo -e "  Gateway: $GATEWAY (MAC: $GATEWAY_MAC)"
            if ask "  ¿Fijar ARP estático para el gateway?"; then
                ip neigh replace "$GATEWAY" lladdr "$GATEWAY_MAC" nud permanent dev "$(ip route | grep default | awk '{print $5}' | head -1)" 2>/dev/null || true
                log_info "ARP estático configurado para gateway $GATEWAY"

                # Persistir en NetworkManager dispatcher
                mkdir -p /etc/NetworkManager/dispatcher.d
                cat > /etc/NetworkManager/dispatcher.d/90-static-arp.sh << EOFDISPATCH
#!/bin/bash
# ARP estático para gateway - T1557
if [[ "\$2" == "up" ]]; then
    ip neigh replace $GATEWAY lladdr $GATEWAY_MAC nud permanent dev "\$1" 2>/dev/null || true
fi
EOFDISPATCH
                chmod 755 /etc/NetworkManager/dispatcher.d/90-static-arp.sh
            fi
        fi
    fi

    # 3c. Sysctl para mitigaciones ARP
    cat >> /etc/sysctl.d/91-credential-protection.conf << 'EOF'

# Protección MITM - T1557
# Ignorar ARP gratuitous
net.ipv4.conf.all.arp_accept = 0
# Responder solo por la interfaz correcta
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.all.arp_ignore = 1
# No aceptar redirects ICMP
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
EOF

    sysctl -p /etc/sysctl.d/91-credential-protection.conf 2>/dev/null || true
    log_info "Mitigaciones ARP/ICMP aplicadas"

else
    log_warn "Protección MITM no configurada"
fi

# ============================================================
log_section "4. DETECCIÓN DE CREDENCIALES EXPUESTAS (T1552)"
# ============================================================

echo "Buscar credenciales almacenadas inseguramente en el sistema."
echo ""
echo "Escanea:"
echo "  - T1552.001: Credenciales en archivos de configuración"
echo "  - T1552.003: Credenciales en historial de bash"
echo "  - T1552.004: Claves privadas SSH expuestas"
echo ""

if ask "¿Escanear el sistema en busca de credenciales expuestas?"; then

    cat > /usr/local/bin/buscar-credenciales.sh << 'EOFCRED'
#!/bin/bash
# Búsqueda de credenciales expuestas - T1552
LOG="/var/log/credential-scan-$(date +%Y%m%d).log"
FINDINGS=0

echo "=== Búsqueda de Credenciales Expuestas - $(date) ===" | tee "$LOG"

# 1. Buscar contraseñas en archivos de configuración (T1552.001)
echo "" | tee -a "$LOG"
echo "--- Credenciales en archivos de configuración ---" | tee -a "$LOG"

PATTERNS="password\s*=\s*['\"][^'\"]+['\"]|passwd\s*=\s*\S+|secret\s*=\s*['\"][^'\"]+['\"]|api_key\s*=\s*\S+|token\s*=\s*['\"][^'\"]{10,}['\"]"

CRED_FILES=$(grep -rlP "$PATTERNS" /etc /opt /var/www /home 2>/dev/null | \
    grep -v ".log\|.journal\|/proc\|credential-scan" | head -30 || true)

if [[ -n "$CRED_FILES" ]]; then
    echo "ALERTA: Posibles credenciales en texto plano:" | tee -a "$LOG"
    while IFS= read -r file; do
        echo "  $file" | tee -a "$LOG"
        ((FINDINGS++)) || true
    done <<< "$CRED_FILES"
else
    echo "OK: No se encontraron credenciales en texto plano evidentes" | tee -a "$LOG"
fi

# 2. Buscar en historial de bash (T1552.003)
echo "" | tee -a "$LOG"
echo "--- Credenciales en historial de bash ---" | tee -a "$LOG"

for histfile in /root/.bash_history /home/*/.bash_history; do
    if [[ -f "$histfile" ]]; then
        HIST_CREDS=$(grep -iP "password|passwd|secret|token|api.key|mysql.*-p|curl.*-u|wget.*--password" "$histfile" 2>/dev/null | head -5 || true)
        if [[ -n "$HIST_CREDS" ]]; then
            echo "ALERTA: Posibles credenciales en $histfile:" | tee -a "$LOG"
            echo "$HIST_CREDS" | sed 's/./*/g' | tee -a "$LOG"  # Censurar output
            ((FINDINGS++)) || true
        fi
    fi
done

# 3. Buscar claves privadas SSH expuestas (T1552.004)
echo "" | tee -a "$LOG"
echo "--- Claves privadas SSH ---" | tee -a "$LOG"

while IFS= read -r keyfile; do
    if [[ -f "$keyfile" ]]; then
        PERMS=$(stat -c "%a" "$keyfile" 2>/dev/null)
        OWNER=$(stat -c "%U" "$keyfile" 2>/dev/null)
        if [[ "$PERMS" != "600" ]] && [[ "$PERMS" != "400" ]]; then
            echo "ALERTA: Clave privada con permisos inseguros: $keyfile ($PERMS)" | tee -a "$LOG"
            ((FINDINGS++)) || true
        fi
        # Verificar si la clave no está protegida con passphrase
        if grep -q "ENCRYPTED" "$keyfile" 2>/dev/null; then
            echo "  OK: $keyfile (cifrada con passphrase)" | tee -a "$LOG"
        else
            echo "  AVISO: $keyfile NO tiene passphrase" | tee -a "$LOG"
            ((FINDINGS++)) || true
        fi
    fi
done < <(find /root/.ssh /home/*/.ssh -name "id_*" -not -name "*.pub" 2>/dev/null || true)

# 4. Buscar archivos .netrc, .pgpass, .my.cnf
echo "" | tee -a "$LOG"
echo "--- Archivos de credenciales conocidos ---" | tee -a "$LOG"

CRED_NAMES=".netrc .pgpass .my.cnf .boto .s3cfg .git-credentials .docker/config.json"
for name in $CRED_NAMES; do
    FOUND=$(find /root /home -name "$(basename "$name")" -path "*${name}*" 2>/dev/null || true)
    if [[ -n "$FOUND" ]]; then
        while IFS= read -r f; do
            PERMS=$(stat -c "%a" "$f" 2>/dev/null)
            echo "ALERTA: Archivo de credenciales encontrado: $f (permisos: $PERMS)" | tee -a "$LOG"
            if [[ "$PERMS" != "600" ]] && [[ "$PERMS" != "400" ]]; then
                echo "  -> Permisos demasiado abiertos" | tee -a "$LOG"
            fi
            ((FINDINGS++)) || true
        done <<< "$FOUND"
    fi
done

# 5. Buscar tokens/keys en variables de entorno
echo "" | tee -a "$LOG"
echo "--- Variables de entorno sospechosas ---" | tee -a "$LOG"

ENV_CREDS=$(env 2>/dev/null | grep -iP "PASSWORD|SECRET|TOKEN|API_KEY|AWS_ACCESS|PRIVATE_KEY" | sed 's/=.*/=***CENSURADO***/' || true)
if [[ -n "$ENV_CREDS" ]]; then
    echo "ALERTA: Variables de entorno con posibles credenciales:" | tee -a "$LOG"
    echo "$ENV_CREDS" | tee -a "$LOG"
    ((FINDINGS++)) || true
else
    echo "OK: Sin variables de entorno sospechosas" | tee -a "$LOG"
fi

# Resumen
echo "" | tee -a "$LOG"
echo "=== RESUMEN ===" | tee -a "$LOG"
if [[ $FINDINGS -eq 0 ]]; then
    echo "OK: No se encontraron credenciales expuestas" | tee -a "$LOG"
else
    echo "ALERTA: $FINDINGS hallazgos de credenciales expuestas" | tee -a "$LOG"
    logger -t buscar-credenciales "ALERTA: $FINDINGS credenciales expuestas (T1552)"
fi

find /var/log -name "credential-scan-*.log" -mtime +30 -delete 2>/dev/null || true
EOFCRED

    chmod 700 /usr/local/bin/buscar-credenciales.sh

    # Ejecutar escaneo inmediato
    echo ""
    echo -e "${BOLD}Ejecutando escaneo de credenciales...${NC}"
    /usr/local/bin/buscar-credenciales.sh

    cat > /etc/cron.weekly/buscar-credenciales << 'EOFCRON'
#!/bin/bash
/usr/local/bin/buscar-credenciales.sh 2>&1 | logger -t buscar-credenciales
EOFCRON
    chmod 700 /etc/cron.weekly/buscar-credenciales

    log_info "Escaneo semanal de credenciales configurado"
else
    log_warn "Escaneo de credenciales no configurado"
fi

# ============================================================
log_section "5. PROTECCIÓN CONTRA SNIFFING (T1040)"
# ============================================================

echo "Detectar y prevenir sniffing de red en interfaces locales."
echo ""

if ask "¿Configurar protección contra network sniffing?"; then

    # 5a. Detectar interfaces en modo promiscuo
    cat > /usr/local/bin/detectar-promiscuo.sh << 'EOFPROM'
#!/bin/bash
# Detección de interfaces en modo promiscuo - T1040
LOG="/var/log/promiscuous-detection.log"

echo "$(date): Verificando interfaces de red..." >> "$LOG"

for iface in /sys/class/net/*; do
    IFACE_NAME=$(basename "$iface")
    [[ "$IFACE_NAME" == "lo" ]] && continue

    FLAGS=$(cat "$iface/flags" 2>/dev/null || echo "0x0")
    # Bit 8 (0x100) = PROMISC
    if (( FLAGS & 0x100 )); then
        echo "$(date): ALERTA - Interface $IFACE_NAME en modo PROMISCUO" >> "$LOG"
        logger -t detectar-promiscuo "ALERTA: $IFACE_NAME en modo promiscuo (T1040)"
    fi
done

# Verificar si hay herramientas de sniffing activas
SNIFF_PROCS=$(ps aux 2>/dev/null | grep -iE "tcpdump|wireshark|tshark|ettercap|bettercap|responder|arpspoof" | grep -v grep || true)
if [[ -n "$SNIFF_PROCS" ]]; then
    echo "$(date): ALERTA - Herramientas de sniffing detectadas:" >> "$LOG"
    echo "$SNIFF_PROCS" >> "$LOG"
    logger -t detectar-promiscuo "ALERTA: Herramientas de sniffing activas (T1040)"
fi
EOFPROM

    chmod 700 /usr/local/bin/detectar-promiscuo.sh

    # Timer de systemd (cada 10 minutos)
    cat > /etc/systemd/system/detectar-promiscuo.service << 'EOFSVC'
[Unit]
Description=Detección de modo promiscuo (T1040)
[Service]
Type=oneshot
ExecStart=/usr/local/bin/detectar-promiscuo.sh
EOFSVC

    cat > /etc/systemd/system/detectar-promiscuo.timer << 'EOFTIMER'
[Unit]
Description=Timer detección promiscuo (cada 10min)
[Timer]
OnBootSec=3min
OnUnitActiveSec=10min
Persistent=true
[Install]
WantedBy=timers.target
EOFTIMER

    systemctl daemon-reload
    systemctl enable --now detectar-promiscuo.timer 2>/dev/null || true

    # 5b. Regla auditd para herramientas de captura
    if command -v auditctl &>/dev/null; then
        cat >> /etc/audit/rules.d/62-credential-access.rules << 'EOF'

# T1040 - Network Sniffing
-w /usr/bin/tcpdump -p x -k network-sniff
-w /usr/bin/tshark -p x -k network-sniff
-w /usr/bin/wireshark -p x -k network-sniff
-w /usr/sbin/tcpdump -p x -k network-sniff
EOF
        augenrules --load 2>/dev/null || true
    fi

    log_info "Detección de sniffing configurada (cada 10 minutos)"
else
    log_warn "Protección contra sniffing no configurada"
fi

# ============================================================
log_section "6. DETECCIÓN DE KEYLOGGERS (T1056.001)"
# ============================================================

echo "Detectar posibles keyloggers en el sistema."
echo "Los keyloggers capturan pulsaciones de teclado para robar credenciales."
echo ""

if ask "¿Configurar detección de keyloggers?"; then

    cat > /usr/local/bin/detectar-keylogger.sh << 'EOFKL'
#!/bin/bash
# Detección de keyloggers - T1056.001
LOG="/var/log/keylogger-detection-$(date +%Y%m%d).log"
ALERTS=0

echo "=== Detección de Keyloggers - $(date) ===" | tee "$LOG"

# 1. Procesos leyendo /dev/input/
echo "" | tee -a "$LOG"
echo "--- Procesos accediendo a /dev/input ---" | tee -a "$LOG"

INPUT_PROCS=$(fuser /dev/input/event* 2>/dev/null || true)
if [[ -n "$INPUT_PROCS" ]]; then
    echo "Procesos con acceso a dispositivos de entrada:" | tee -a "$LOG"
    for pid in $INPUT_PROCS; do
        pid=$(echo "$pid" | tr -d 'em')
        [[ -z "$pid" ]] && continue
        CMDLINE=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ' || echo "N/A")
        COMM=$(cat "/proc/$pid/comm" 2>/dev/null || echo "N/A")
        # Filtrar procesos legítimos (Xorg, systemd-logind, etc.)
        if ! echo "$COMM" | grep -qE "^(Xorg|X|systemd-logind|gdm|sddm|kwin|mutter|libinput)"; then
            echo "ALERTA: PID $pid ($COMM) accediendo a input: $CMDLINE" | tee -a "$LOG"
            ((ALERTS++)) || true
        fi
    done
fi

# 2. Módulos del kernel sospechosos para input
echo "" | tee -a "$LOG"
echo "--- Módulos del kernel sospechosos ---" | tee -a "$LOG"

SUSPECT_MODS=$(lsmod 2>/dev/null | grep -iE "keylog|keyboard|input.*hook" | grep -v "^hid\|^usbhid\|^evdev\|^input_leds" || true)
if [[ -n "$SUSPECT_MODS" ]]; then
    echo "ALERTA: Módulos del kernel sospechosos:" | tee -a "$LOG"
    echo "$SUSPECT_MODS" | tee -a "$LOG"
    ((ALERTS++)) || true
else
    echo "OK: Sin módulos de input sospechosos" | tee -a "$LOG"
fi

# 3. Verificar xinput (X11 keylogging)
echo "" | tee -a "$LOG"
echo "--- Xinput listeners ---" | tee -a "$LOG"

if command -v xinput &>/dev/null; then
    XI_TEST=$(ps aux 2>/dev/null | grep "xinput.*test\|xinput.*record" | grep -v grep || true)
    if [[ -n "$XI_TEST" ]]; then
        echo "ALERTA: xinput test/record activo (posible keylogger X11):" | tee -a "$LOG"
        echo "$XI_TEST" | tee -a "$LOG"
        ((ALERTS++)) || true
    else
        echo "OK: No hay xinput listeners activos" | tee -a "$LOG"
    fi
fi

# 4. Verificar strace/ltrace en procesos de login
echo "" | tee -a "$LOG"
echo "--- Strace/ltrace en procesos sensibles ---" | tee -a "$LOG"

TRACE_PROCS=$(ps aux 2>/dev/null | grep -E "strace.*-p|ltrace.*-p|strace.*sshd|strace.*login|strace.*su " | grep -v grep || true)
if [[ -n "$TRACE_PROCS" ]]; then
    echo "ALERTA: Tracing de procesos sensibles detectado:" | tee -a "$LOG"
    echo "$TRACE_PROCS" | tee -a "$LOG"
    ((ALERTS++)) || true
else
    echo "OK: No se detectó tracing de procesos sensibles" | tee -a "$LOG"
fi

# Resumen
echo "" | tee -a "$LOG"
echo "=== RESUMEN ===" | tee -a "$LOG"
if [[ $ALERTS -eq 0 ]]; then
    echo "OK: Sin indicadores de keylogger" | tee -a "$LOG"
else
    echo "ALERTA: $ALERTS indicadores de keylogger detectados" | tee -a "$LOG"
    logger -t detectar-keylogger "ALERTA: $ALERTS indicadores de keylogger (T1056.001)"
fi

find /var/log -name "keylogger-detection-*.log" -mtime +30 -delete 2>/dev/null || true
EOFKL

    chmod 700 /usr/local/bin/detectar-keylogger.sh

    cat > /etc/cron.daily/detectar-keylogger << 'EOFCRON'
#!/bin/bash
/usr/local/bin/detectar-keylogger.sh 2>&1 | logger -t detectar-keylogger
EOFCRON
    chmod 700 /etc/cron.daily/detectar-keylogger

    log_info "Detección diaria de keyloggers configurada"
else
    log_warn "Detección de keyloggers no configurada"
fi

# ============================================================
log_section "RESUMEN DE MITIGACIONES TA0006"
# ============================================================

echo ""
echo -e "${BOLD}Estado de mitigaciones de Acceso a Credenciales (TA0006):${NC}"
echo ""

# T1003 - Credential Dumping
if [[ -f /etc/sysctl.d/91-credential-protection.conf ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1003 - Protección contra credential dumping"
else
    echo -e "  ${YELLOW}[--]${NC} T1003 - Protección contra credential dumping no configurada"
fi

# T1110 - Brute Force
if [[ -f /etc/security/faillock.conf ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1110 - Protección contra fuerza bruta (faillock)"
else
    echo -e "  ${YELLOW}[--]${NC} T1110 - Protección contra fuerza bruta no configurada"
fi

# T1557 - MITM
if command -v arpwatch &>/dev/null && systemctl is-active arpwatch &>/dev/null 2>&1; then
    echo -e "  ${GREEN}[OK]${NC} T1557 - Protección MITM (arpwatch activo)"
else
    echo -e "  ${YELLOW}[--]${NC} T1557 - Protección MITM no configurada"
fi

# T1552 - Credenciales expuestas
if [[ -x /usr/local/bin/buscar-credenciales.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1552 - Escaneo de credenciales expuestas"
else
    echo -e "  ${YELLOW}[--]${NC} T1552 - Escaneo de credenciales no configurado"
fi

# T1040 - Network Sniffing
if [[ -x /usr/local/bin/detectar-promiscuo.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1040 - Detección de sniffing"
else
    echo -e "  ${YELLOW}[--]${NC} T1040 - Detección de sniffing no configurada"
fi

# T1056.001 - Keylogging
if [[ -x /usr/local/bin/detectar-keylogger.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1056.001 - Detección de keyloggers"
else
    echo -e "  ${YELLOW}[--]${NC} T1056.001 - Detección de keyloggers no configurada"
fi

echo ""
log_info "Script de mitigación de acceso a credenciales completado"
log_info "Backups de configuración en: $BACKUP_DIR"
