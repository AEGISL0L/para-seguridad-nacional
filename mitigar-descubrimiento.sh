#!/bin/bash
# ============================================================
# MITIGACIÓN DE DESCUBRIMIENTO - TA0007 (Discovery)
# Linux Multi-Distro (openSUSE, Debian/Ubuntu, RHEL/Fedora, Arch)
# ============================================================
# Técnicas MITRE ATT&CK cubiertas:
#   T1046 - Network Service Discovery (port scanning)
#   T1057 - Process Discovery
#   T1082 - System Information Discovery
#   T1083 - File and Directory Discovery
#   T1018 - Remote System Discovery
#   T1016 - System Network Configuration Discovery
#   T1049 - System Network Connections Discovery
#   T1087 - Account Discovery
#   T1069 - Permission Groups Discovery
#   T1007 - System Service Discovery
#   T1518 - Software Discovery
# ============================================================


set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "mitigar-descubrimiento"
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MITIGACIÓN DE DESCUBRIMIENTO - TA0007                   ║"
echo "║   Limitar reconocimiento interno del atacante              ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups se guardarán en: $BACKUP_DIR"

# ============================================================
log_section "1. DETECCIÓN DE PORT SCANNING (T1046)"
# ============================================================

echo "Detectar escaneo de puertos desde la red interna."
echo "Un atacante con acceso inicial escaneará servicios para moverse."
echo ""
echo "Medidas:"
echo "  - Reglas de firewall anti-scan"
echo "  - Detección con auditd de herramientas de scan"
echo "  - Limitación de rate en conexiones"
echo ""

if ask "¿Configurar detección de port scanning interno?"; then

    # 1a. Reglas de firewall para detectar/limitar escaneos
    echo ""
    echo -e "${BOLD}Configurando reglas anti-scan en firewalld...${NC}"

    if fw_is_active &>/dev/null; then
        # Crear regla rich rule para limitar nuevas conexiones por segundo
        ZONE=$(fw_get_default_zone 2>/dev/null || echo "public")

        # Rate limiting: máximo 25 nuevas conexiones por segundo
        fw_add_rich_rule 'rule family="ipv4" limit value="25/s" accept' "$ZONE"

        # Logear conexiones rechazadas (indicador de scan)
        fw_set_log_denied unicast 2>/dev/null || true

        fw_reload 2>/dev/null || true
        log_info "Rate limiting y logging de conexiones rechazadas configurado"
    fi

    # 1b. Reglas auditd para herramientas de scan
    if command -v auditctl &>/dev/null; then
        cat > /etc/audit/rules.d/63-discovery.rules << 'EOF'
## Detección de Discovery - TA0007
# T1046 - Herramientas de escaneo de red
-w /usr/bin/nmap -p x -k network-scan
-w /usr/bin/masscan -p x -k network-scan
-w /usr/bin/ncat -p x -k network-scan
-w /usr/bin/netcat -p x -k network-scan
-w /usr/bin/nc -p x -k network-scan

# T1046 - Monitorear conexiones a muchos puertos (socket syscalls masivos)
-a always,exit -F arch=b64 -S connect -F a2=16 -F key=network-connect-ipv4

# T1018 - Herramientas de descubrimiento de red
-w /usr/bin/arp -p x -k network-discovery
-w /usr/sbin/arp -p x -k network-discovery
-w /usr/bin/ping -p x -k network-discovery
-w /usr/bin/arping -p x -k network-discovery
EOF

        augenrules --load 2>/dev/null || true
        log_info "Reglas auditd de descubrimiento creadas"
    fi

    # 1c. Script de detección de escaneos en logs de firewall
    cat > /usr/local/bin/detectar-portscan.sh << 'EOFPS'
#!/bin/bash
# Detección de port scanning interno - T1046
LOG="/var/log/portscan-detection-$(date +%Y%m%d).log"
ALERTS=0

echo "=== Detección de Port Scanning - $(date) ===" | tee "$LOG"

# Analizar logs de firewall por IPs con muchos rechazos
echo "" | tee -a "$LOG"
echo "--- IPs con conexiones rechazadas (24h) ---" | tee -a "$LOG"

if command -v journalctl &>/dev/null; then
    REJECTED=$(journalctl --since "24 hours ago" 2>/dev/null | \
        grep -iP "reject|drop|denied" | \
        grep -oP "SRC=\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | \
        sort | uniq -c | sort -rn | head -20)

    if [[ -n "$REJECTED" ]]; then
        echo "$REJECTED" | tee -a "$LOG"
        # IPs con más de 100 rechazos = probable scan
        while IFS= read -r line; do
            COUNT=$(echo "$line" | awk '{print $1}')
            IP=$(echo "$line" | awk '{print $2}')
            if [[ "$COUNT" -gt 100 ]]; then
                echo "ALERTA: $IP con $COUNT conexiones rechazadas (posible scan)" | tee -a "$LOG"
                logger -t detectar-portscan "ALERTA: $IP $COUNT rechazos (T1046)"
                ((ALERTS++)) || true
            fi
        done <<< "$REJECTED"
    else
        echo "OK: Sin rechazos significativos" | tee -a "$LOG"
    fi
fi

# Analizar conexiones activas por patrón de scan
echo "" | tee -a "$LOG"
echo "--- Patrones de conexiones sospechosas ---" | tee -a "$LOG"

# IPs con conexiones a muchos puertos diferentes
SS_OUTPUT=$(ss -tn 2>/dev/null | tail -n+2)
if [[ -n "$SS_OUTPUT" ]]; then
    MULTI_PORT=$(echo "$SS_OUTPUT" | awk '{print $5}' | grep -oP '.*(?=:)' | sort | uniq -c | sort -rn | head -5)
    while IFS= read -r line; do
        COUNT=$(echo "$line" | awk '{print $1}')
        IP=$(echo "$line" | awk '{print $2}')
        if [[ -n "$COUNT" ]] && [[ "$COUNT" -gt 50 ]]; then
            echo "ALERTA: $IP con $COUNT conexiones activas" | tee -a "$LOG"
            ((ALERTS++)) || true
        fi
    done <<< "$MULTI_PORT"
fi

echo "" | tee -a "$LOG"
echo "=== RESUMEN ===" | tee -a "$LOG"
if [[ $ALERTS -eq 0 ]]; then
    echo "OK: Sin indicadores de port scanning" | tee -a "$LOG"
else
    echo "ALERTA: $ALERTS indicadores de port scanning" | tee -a "$LOG"
fi

find /var/log -name "portscan-detection-*.log" -mtime +30 -delete 2>/dev/null || true
EOFPS

    chmod 700 /usr/local/bin/detectar-portscan.sh

    cat > /etc/cron.daily/detectar-portscan << 'EOFCRON'
#!/bin/bash
/usr/local/bin/detectar-portscan.sh 2>&1 | logger -t detectar-portscan
EOFCRON
    chmod 700 /etc/cron.daily/detectar-portscan

    log_info "Detección diaria de port scanning configurada"
else
    log_warn "Detección de port scanning no configurada"
fi

# ============================================================
log_section "2. RESTRINGIR ENUMERACIÓN DE PROCESOS (T1057)"
# ============================================================

echo "Limitar la capacidad de listar procesos de otros usuarios."
echo "Esto dificulta que un atacante descubra servicios y usuarios."
echo ""

if ask "¿Restringir enumeración de procesos?"; then

    # hidepid en /proc (ya puede estar de credenciales)
    if ! grep -q "hidepid" /etc/fstab 2>/dev/null; then
        cp /etc/fstab "$BACKUP_DIR/"
        echo "" >> /etc/fstab
        echo "# T1057 - Restringir visibilidad de procesos" >> /etc/fstab
        echo "proc    /proc    proc    defaults,hidepid=2,gid=wheel    0    0" >> /etc/fstab
        mount -o remount,hidepid=2,gid=wheel /proc 2>/dev/null || true
        log_info "hidepid=2 aplicado: usuarios solo ven sus propios procesos"
    else
        echo -e "  ${GREEN}OK${NC} hidepid ya configurado"
    fi

    # Reglas auditd para herramientas de enumeración
    if command -v auditctl &>/dev/null; then
        cat >> /etc/audit/rules.d/63-discovery.rules << 'EOF'

# T1057 - Process Discovery
-w /usr/bin/ps -p x -k process-discovery
-w /usr/bin/top -p x -k process-discovery
-w /usr/bin/htop -p x -k process-discovery
-a always,exit -F arch=b64 -S sched_getaffinity -k process-enum
EOF
        augenrules --load 2>/dev/null || true
    fi

    log_info "Restricción de enumeración de procesos aplicada"
else
    log_warn "Enumeración de procesos no restringida"
fi

# ============================================================
log_section "3. LIMITAR INFORMACIÓN DEL SISTEMA (T1082)"
# ============================================================

echo "Reducir la información del sistema accesible a usuarios no privilegiados."
echo "Atacantes recopilan versión de kernel, SO y hardware para exploits."
echo ""

if ask "¿Limitar información del sistema expuesta?"; then

    # 3a. Restringir acceso a información del kernel
    echo ""
    echo -e "${BOLD}Restringiendo información del kernel...${NC}"

    SYSCTL_DISC="/etc/sysctl.d/92-discovery-protection.conf"

    cat > "$SYSCTL_DISC" << 'EOF'
# Protección contra Discovery - T1082
# Restringir acceso a direcciones del kernel
kernel.kptr_restrict = 2

# Restringir dmesg
kernel.dmesg_restrict = 1

# No mostrar versión del kernel en /proc/version a no-root
# (requiere grsecurity/PaX - documentamos la intención)

# Restringir información de perf
kernel.perf_event_paranoid = 3
EOF

    sysctl -p "$SYSCTL_DISC" 2>/dev/null || true
    log_info "Información del kernel restringida"

    # 3b. Eliminar banners de versión de servicios
    echo ""
    echo -e "${BOLD}Eliminando banners de versión de servicios...${NC}"

    # SSH - eliminar banner de versión
    if [[ -f /etc/ssh/sshd_config ]]; then
        if ! grep -q "^DebianBanner\|^Banner none" /etc/ssh/sshd_config 2>/dev/null; then
            mkdir -p /etc/ssh/sshd_config.d
            cat > /etc/ssh/sshd_config.d/05-no-banner.conf << 'EOF'
# T1082 - Ocultar información de versión
Banner none
DebianBanner no
EOF
            log_info "Banner SSH desactivado"
        fi
    fi

    # 3c. Restringir /etc/issue y /etc/issue.net
    for issue_file in /etc/issue /etc/issue.net; do
        if [[ -f "$issue_file" ]]; then
            cp "$issue_file" "$BACKUP_DIR/"
            echo "Authorized access only. All activity is monitored." > "$issue_file"
        fi
    done
    log_info "Banners de login simplificados"

    # 3d. Restringir acceso a herramientas de información
    if command -v auditctl &>/dev/null; then
        cat >> /etc/audit/rules.d/63-discovery.rules << 'EOF'

# T1082 - System Information Discovery
-w /usr/bin/uname -p x -k system-info-discovery
-w /usr/bin/hostnamectl -p x -k system-info-discovery
-w /usr/bin/lscpu -p x -k system-info-discovery
-w /usr/bin/lsblk -p x -k system-info-discovery
-w /usr/bin/dmidecode -p x -k system-info-discovery
-w /etc/os-release -p r -k system-info-discovery
EOF
        augenrules --load 2>/dev/null || true
    fi

    log_info "Información del sistema restringida"
else
    log_warn "Información del sistema no restringida"
fi

# ============================================================
log_section "4. MONITOREAR DESCUBRIMIENTO DE RED (T1016/T1049)"
# ============================================================

echo "Detectar reconocimiento de red interno por atacantes."
echo "  - T1016: Descubrimiento de configuración de red"
echo "  - T1049: Descubrimiento de conexiones de red"
echo ""

if ask "¿Monitorear comandos de reconocimiento de red?"; then

    if command -v auditctl &>/dev/null; then
        cat >> /etc/audit/rules.d/63-discovery.rules << 'EOF'

# T1016 - System Network Configuration Discovery
-w /usr/bin/ip -p x -k network-config-discovery
-w /usr/sbin/ifconfig -p x -k network-config-discovery
-w /usr/bin/nmcli -p x -k network-config-discovery
-w /usr/sbin/route -p x -k network-config-discovery
-w /usr/bin/traceroute -p x -k network-config-discovery

# T1049 - System Network Connections Discovery
-w /usr/bin/ss -p x -k network-conn-discovery
-w /usr/bin/netstat -p x -k network-conn-discovery
-w /usr/bin/lsof -p x -k network-conn-discovery

# T1018 - Remote System Discovery
-w /usr/bin/nslookup -p x -k remote-discovery
-w /usr/bin/dig -p x -k remote-discovery
-w /usr/bin/host -p x -k remote-discovery
-w /usr/bin/arp -p x -k remote-discovery
-w /usr/sbin/arp -p x -k remote-discovery
EOF

        augenrules --load 2>/dev/null || true
        log_info "Auditoría de herramientas de reconocimiento de red configurada"
    else
        log_warn "auditd no disponible para monitoreo de red"
    fi

    # Script de detección de actividad de reconocimiento
    cat > /usr/local/bin/detectar-reconocimiento.sh << 'EOFRECON'
#!/bin/bash
# Detección de reconocimiento interno - T1016/T1049/T1018
LOG="/var/log/recon-detection-$(date +%Y%m%d).log"
ALERTS=0

echo "=== Detección de Reconocimiento Interno - $(date) ===" | tee "$LOG"

# Analizar eventos auditd de discovery
if command -v ausearch &>/dev/null; then
    echo "" | tee -a "$LOG"
    echo "--- Actividad de reconocimiento (24h) ---" | tee -a "$LOG"

    for key in network-scan network-discovery network-config-discovery network-conn-discovery remote-discovery system-info-discovery process-discovery; do
        COUNT=$(ausearch -k "$key" -ts recent 2>/dev/null | grep -c "type=SYSCALL" || echo 0)
        if [[ "$COUNT" -gt 0 ]]; then
            echo "  $key: $COUNT eventos" | tee -a "$LOG"
            if [[ "$COUNT" -gt 20 ]]; then
                echo "  ALERTA: Actividad excesiva de $key" | tee -a "$LOG"
                ((ALERTS++)) || true
            fi
        fi
    done

    # Identificar usuarios con más actividad de reconocimiento
    echo "" | tee -a "$LOG"
    echo "--- Usuarios con actividad de reconocimiento ---" | tee -a "$LOG"

    RECON_USERS=$(ausearch -k network-scan -k network-discovery -k network-config-discovery -k system-info-discovery -ts today 2>/dev/null | \
        grep "auid=" | grep -oP "auid=\K[0-9]+" | sort | uniq -c | sort -rn | head -5)

    if [[ -n "$RECON_USERS" ]]; then
        while IFS= read -r line; do
            COUNT=$(echo "$line" | awk '{print $1}')
            UID_NUM=$(echo "$line" | awk '{print $2}')
            USERNAME=$(getent passwd "$UID_NUM" 2>/dev/null | cut -d: -f1 || echo "UID:$UID_NUM")
            echo "  $USERNAME: $COUNT eventos de reconocimiento" | tee -a "$LOG"
            if [[ "$COUNT" -gt 50 ]]; then
                echo "  ALERTA: Actividad de reconocimiento excesiva para $USERNAME" | tee -a "$LOG"
                logger -t detectar-reconocimiento "ALERTA: $USERNAME con $COUNT eventos de reconocimiento"
                ((ALERTS++)) || true
            fi
        done <<< "$RECON_USERS"
    fi
fi

echo "" | tee -a "$LOG"
echo "=== RESUMEN ===" | tee -a "$LOG"
if [[ $ALERTS -eq 0 ]]; then
    echo "OK: Actividad de reconocimiento dentro de lo normal" | tee -a "$LOG"
else
    echo "ALERTA: $ALERTS indicadores de reconocimiento anómalo" | tee -a "$LOG"
fi

find /var/log -name "recon-detection-*.log" -mtime +30 -delete 2>/dev/null || true
EOFRECON

    chmod 700 /usr/local/bin/detectar-reconocimiento.sh

    cat > /etc/cron.daily/detectar-reconocimiento << 'EOFCRON'
#!/bin/bash
/usr/local/bin/detectar-reconocimiento.sh 2>&1 | logger -t detectar-reconocimiento
EOFCRON
    chmod 700 /etc/cron.daily/detectar-reconocimiento

    log_info "Detección diaria de reconocimiento configurada"
else
    log_warn "Monitoreo de reconocimiento no configurado"
fi

# ============================================================
log_section "5. RESTRINGIR ENUMERACIÓN DE CUENTAS (T1087/T1069)"
# ============================================================

echo "Limitar la capacidad de enumerar cuentas y grupos del sistema."
echo "  - T1087: Descubrimiento de cuentas locales"
echo "  - T1069: Descubrimiento de grupos de permisos"
echo ""

if ask "¿Restringir enumeración de cuentas y grupos?"; then

    # Restringir acceso a /etc/passwd (lectura para otros)
    # Nota: /etc/passwd necesita ser legible por muchos servicios
    # Solo podemos monitorear el acceso, no bloquearlo

    echo -e "${BOLD}Configurando monitoreo de enumeración de cuentas...${NC}"

    if command -v auditctl &>/dev/null; then
        cat >> /etc/audit/rules.d/63-discovery.rules << 'EOF'

# T1087 - Account Discovery
-w /etc/passwd -p r -k account-discovery
-w /etc/group -p r -k account-discovery
-w /usr/bin/who -p x -k account-discovery
-w /usr/bin/w -p x -k account-discovery
-w /usr/bin/last -p x -k account-discovery
-w /usr/bin/lastlog -p x -k account-discovery
-w /usr/bin/id -p x -k account-discovery

# T1069 - Permission Groups Discovery
-w /usr/bin/groups -p x -k group-discovery
-w /etc/sudoers -p r -k privilege-discovery
-w /etc/sudoers.d/ -p r -k privilege-discovery
EOF

        augenrules --load 2>/dev/null || true
        log_info "Auditoría de enumeración de cuentas configurada"
    fi

    # Restringir comandos who/w/last para no-root
    echo ""
    echo -e "${BOLD}Restringiendo herramientas de enumeración...${NC}"

    for cmd in /usr/bin/who /usr/bin/w /usr/bin/last /usr/bin/lastlog; do
        if [[ -x "$cmd" ]]; then
            chmod 750 "$cmd" 2>/dev/null || true
            echo -e "  ${GREEN}OK${NC} Restringido: $cmd"
        fi
    done

    log_info "Enumeración de cuentas restringida y monitoreada"
else
    log_warn "Enumeración de cuentas no restringida"
fi

# ============================================================
log_section "6. RESTRINGIR DESCUBRIMIENTO DE SOFTWARE (T1518)"
# ============================================================

echo "Limitar la capacidad de listar software instalado."
echo "Atacantes buscan software vulnerable para escalar o moverse."
echo ""

if ask "¿Restringir descubrimiento de software?"; then

    # Monitorear uso de gestores de paquetes
    if command -v auditctl &>/dev/null; then
        cat >> /etc/audit/rules.d/63-discovery.rules << 'EOF'

# T1518 - Software Discovery
-w /usr/bin/zypper -p x -k software-discovery
# Reglas adicionales por distro (solo aplica la del gestor presente)
-w /usr/bin/apt -p x -k software-discovery
-w /usr/bin/apt-get -p x -k software-discovery
-w /usr/bin/dnf -p x -k software-discovery
-w /usr/bin/pacman -p x -k software-discovery
-w /usr/bin/rpm -p x -k software-discovery
-w /usr/bin/dpkg -p x -k software-discovery
EOF
        augenrules --load 2>/dev/null || true
    fi

    # Nota sobre restricción del gestor de paquetes
    echo ""
    echo -e "${DIM}Nota: El gestor de paquetes ($PKG_MANAGER_NAME) no puede restringirse sin romper funcionalidad.${NC}"
    echo -e "${DIM}Se configura solo monitoreo via auditd.${NC}"

    log_info "Monitoreo de descubrimiento de software configurado"
else
    log_warn "Descubrimiento de software no restringido"
fi

# ============================================================
log_section "RESUMEN DE MITIGACIONES TA0007"
# ============================================================

echo ""
echo -e "${BOLD}Estado de mitigaciones de Descubrimiento (TA0007):${NC}"
echo ""

# T1046 - Port Scanning
if [[ -x /usr/local/bin/detectar-portscan.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1046 - Detección de port scanning"
else
    echo -e "  ${YELLOW}[--]${NC} T1046 - Detección de port scanning no configurada"
fi

# T1057 - Process Discovery
if grep -q "hidepid" /etc/fstab 2>/dev/null; then
    echo -e "  ${GREEN}[OK]${NC} T1057 - Restricción de enumeración de procesos"
else
    echo -e "  ${YELLOW}[--]${NC} T1057 - Enumeración de procesos no restringida"
fi

# T1082 - System Information
if [[ -f /etc/sysctl.d/92-discovery-protection.conf ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1082 - Información del sistema restringida"
else
    echo -e "  ${YELLOW}[--]${NC} T1082 - Información del sistema no restringida"
fi

# T1016/T1049 - Network Discovery
if [[ -x /usr/local/bin/detectar-reconocimiento.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1016/T1049 - Detección de reconocimiento de red"
else
    echo -e "  ${YELLOW}[--]${NC} T1016/T1049 - Reconocimiento de red no monitoreado"
fi

# T1087/T1069 - Account/Group Discovery
if [[ -f /etc/audit/rules.d/63-discovery.rules ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1087/T1069 - Auditoría de enumeración de cuentas"
else
    echo -e "  ${YELLOW}[--]${NC} T1087/T1069 - Enumeración de cuentas no monitoreada"
fi

# T1518 - Software Discovery
if command -v auditctl &>/dev/null; then
    echo -e "  ${GREEN}[OK]${NC} T1518 - Monitoreo de descubrimiento de software"
else
    echo -e "  ${YELLOW}[--]${NC} T1518 - Descubrimiento de software no monitoreado"
fi

echo ""
log_info "Script de mitigación de descubrimiento completado"
log_info "Backups de configuración en: $BACKUP_DIR"
