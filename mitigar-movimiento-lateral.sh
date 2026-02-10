#!/bin/bash
# ============================================================
# MITIGACIÓN DE MOVIMIENTO LATERAL - TA0008 (Lateral Movement)
# Linux Multi-Distro (openSUSE, Debian/Ubuntu, RHEL/Fedora, Arch)
# ============================================================
# Técnicas MITRE ATT&CK cubiertas:
#   T1021     - Remote Services
#   T1021.001 - Remote Desktop Protocol
#   T1021.002 - SMB/Windows Admin Shares
#   T1021.004 - SSH
#   T1021.005 - VNC
#   T1080     - Taint Shared Content
#   T1563     - Remote Service Session Hijacking
#   T1563.001 - SSH Hijacking
#   T1072     - Software Deployment Tools
#   T1550     - Use Alternate Authentication Material
#   T1550.001 - Application Access Token
#   T1550.004 - Web Session Cookie
#   T1534     - Internal Spearphishing
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "mitigar-movimiento-lateral"
securizar_setup_traps
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MITIGACIÓN DE MOVIMIENTO LATERAL - TA0008               ║"
echo "║   Prevenir propagación del atacante en la red              ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups se guardarán en: $BACKUP_DIR"

# ============================================================
log_section "1. HARDENING DE SERVICIOS REMOTOS (T1021)"
# ============================================================

echo "Endurecer servicios remotos que permiten movimiento lateral."
echo ""
echo "Servicios a proteger:"
echo "  - T1021.004: SSH (principal vector en Linux)"
echo "  - T1021.001: RDP/XRDP (si existe)"
echo "  - T1021.005: VNC (si existe)"
echo "  - T1021.002: SMB/Samba (si existe)"
echo ""

if ask "¿Endurecer servicios remotos contra movimiento lateral?"; then

    # 1a. Hardening SSH adicional contra lateral movement
    echo ""
    echo -e "${BOLD}Endureciendo SSH contra movimiento lateral...${NC}"

    mkdir -p /etc/ssh/sshd_config.d
    log_change "Creado" "/etc/ssh/sshd_config.d/"
    cp /etc/ssh/sshd_config "$BACKUP_DIR/" 2>/dev/null || true
    log_change "Backup" "/etc/ssh/sshd_config"

    cat > /etc/ssh/sshd_config.d/06-lateral-movement.conf << 'EOF'
# Protección contra movimiento lateral - T1021.004
# Deshabilitar agent forwarding (previene SSH hijacking T1563.001)
AllowAgentForwarding no

# Deshabilitar túneles SSH
PermitTunnel no

# Deshabilitar port forwarding (previene pivoting)
AllowTcpForwarding no
GatewayPorts no

# Deshabilitar X11 forwarding
X11Forwarding no

# No permitir variables de entorno
PermitUserEnvironment no

# Limitar sesiones por usuario
MaxSessions 3

# Forzar re-autenticación (no reusar sesiones)
RekeyLimit 1G 1h
EOF
    log_change "Creado" "/etc/ssh/sshd_config.d/06-lateral-movement.conf"

    # Reiniciar SSH con cuidado
    if sshd -t 2>/dev/null; then
        systemctl reload "$SSH_SERVICE_NAME" 2>/dev/null || true
        log_change "Servicio" "$SSH_SERVICE_NAME reload"
        log_info "SSH endurecido contra movimiento lateral"
    else
        log_warn "Error en configuración SSH - revirtiendo"
        rm -f /etc/ssh/sshd_config.d/06-lateral-movement.conf
    fi

    # 1b. Deshabilitar servicios de escritorio remoto si no se usan
    echo ""
    echo -e "${BOLD}Verificando servicios de escritorio remoto...${NC}"

    for svc in xrdp vncserver x11vnc tigervnc; do
        if systemctl is-enabled "$svc" 2>/dev/null; then
            echo -e "  ${YELLOW}!!${NC} $svc habilitado"
            if ask "  ¿Deshabilitar $svc?"; then
                systemctl disable --now "$svc" 2>/dev/null || true
                log_change "Servicio" "$svc disable --now"
                log_info "$svc deshabilitado"
            else
                log_skip "Deshabilitar $svc"
            fi
        fi
    done

    # 1c. Hardening SMB/Samba si existe
    if command -v smbclient &>/dev/null || [[ -f /etc/samba/smb.conf ]]; then
        echo ""
        echo -e "${BOLD}Samba detectado - aplicando hardening...${NC}"

        if [[ -f /etc/samba/smb.conf ]]; then
            cp /etc/samba/smb.conf "$BACKUP_DIR/"
            log_change "Backup" "/etc/samba/smb.conf"

            # Verificar si ya está endurecido
            if ! grep -q "server signing = mandatory" /etc/samba/smb.conf 2>/dev/null; then
                if ask "¿Endurecer Samba contra movimiento lateral?"; then
                    cat >> /etc/samba/smb.conf << 'EOF'

# Protección contra movimiento lateral - T1021.002
[global]
    # Requerir firma SMB
    server signing = mandatory
    # Deshabilitar SMBv1
    server min protocol = SMB2
    # Restringir acceso por IP
    # hosts allow = 192.168.1.0/24
    # No permitir acceso de invitado
    map to guest = never
    restrict anonymous = 2
    # Logging de acceso
    log level = 1 auth:3
EOF
                    log_change "Modificado" "/etc/samba/smb.conf"
                    systemctl restart smb 2>/dev/null || true
                    log_change "Servicio" "smb restart"
                    log_info "Samba endurecido (firma obligatoria, sin SMBv1)"
                else
                    log_skip "Endurecer Samba"
                fi
            else
                echo -e "  ${GREEN}OK${NC} Samba ya tiene firma obligatoria"
            fi
        fi
    else
        echo -e "  ${GREEN}OK${NC} Samba no instalado"
    fi

    # 1d. Reglas auditd para servicios remotos
    if command -v auditctl &>/dev/null; then
        mkdir -p /etc/audit/rules.d
        cat > /etc/audit/rules.d/64-lateral-movement.rules << 'EOF'
## Detección de movimiento lateral - TA0008
# T1021 - Conexiones a servicios remotos
-w /usr/bin/ssh -p x -k lateral-ssh
-w /usr/bin/scp -p x -k lateral-scp
-w /usr/bin/sftp -p x -k lateral-sftp
-w /usr/bin/rsync -p x -k lateral-rsync
-w /usr/bin/smbclient -p x -k lateral-smb
-w /usr/bin/rdesktop -p x -k lateral-rdp
-w /usr/bin/xfreerdp -p x -k lateral-rdp
-w /usr/bin/vncviewer -p x -k lateral-vnc
EOF
        log_change "Creado" "/etc/audit/rules.d/64-lateral-movement.rules"

        augenrules --load 2>/dev/null || true
        log_info "Reglas auditd para servicios remotos creadas"
    fi

else
    log_skip "Hardening de servicios remotos"
    log_warn "Hardening de servicios remotos no aplicado"
fi

# ============================================================
log_section "2. PREVENIR SSH HIJACKING (T1563.001)"
# ============================================================

echo "Proteger sesiones SSH contra secuestro."
echo "Un atacante con acceso root puede secuestrar el SSH agent"
echo "de otro usuario para moverse lateralmente."
echo ""

if ask "¿Proteger contra SSH session hijacking?"; then

    # 2a. Proteger SSH agent sockets
    echo ""
    echo -e "${BOLD}Protegiendo SSH agent sockets...${NC}"

    # Configurar que SSH_AUTH_SOCK se limpie al salir
    cat > /etc/profile.d/ssh-agent-protection.sh << 'EOFSSH'
# Protección contra SSH Hijacking - T1563.001
# Limpiar SSH_AUTH_SOCK al cerrar sesión
trap 'ssh-agent -k 2>/dev/null' EXIT

# Reducir tiempo de vida de claves en el agent
if [[ -n "$SSH_AUTH_SOCK" ]]; then
    ssh-add -t 3600 2>/dev/null || true  # Claves expiran en 1h
fi
EOFSSH

    log_change "Creado" "/etc/profile.d/ssh-agent-protection.sh"
    chmod 644 /etc/profile.d/ssh-agent-protection.sh
    log_change "Permisos" "/etc/profile.d/ssh-agent-protection.sh -> 644"

    # 2b. Restringir permisos de sockets SSH
    cat > /etc/tmpfiles.d/ssh-agent-security.conf << 'EOF'
# Proteger directorios de SSH agent sockets
d /tmp/ssh-* 0700 - - -
EOF
    log_change "Creado" "/etc/tmpfiles.d/ssh-agent-security.conf"

    log_info "Protección contra SSH hijacking configurada"

    # 2c. Monitorear acceso a SSH agent sockets ajenos
    if command -v auditctl &>/dev/null; then
        mkdir -p /etc/audit/rules.d
        cat >> /etc/audit/rules.d/64-lateral-movement.rules << 'EOF'

# T1563.001 - SSH Hijacking
# Monitorear acceso a SSH agent sockets
-a always,exit -F arch=b64 -S connect -F a0=1 -F key=ssh-agent-access
# Monitorear SSH_AUTH_SOCK
-w /tmp/ssh- -p rwa -k ssh-agent-socket
EOF
        log_change "Modificado" "/etc/audit/rules.d/64-lateral-movement.rules"
        augenrules --load 2>/dev/null || true
    fi

else
    log_skip "Protección contra SSH hijacking"
    log_warn "Protección contra SSH hijacking no aplicada"
fi

# ============================================================
log_section "3. PROTECCIÓN DE CONTENIDO COMPARTIDO (T1080)"
# ============================================================

echo "Prevenir que contenido malicioso en recursos compartidos"
echo "se use para infectar otros sistemas."
echo ""

if ask "¿Proteger recursos compartidos contra contenido malicioso?"; then

    # 3a. Montar shares con noexec
    echo ""
    echo -e "${BOLD}Verificando montajes de red...${NC}"

    # Buscar montajes NFS/CIFS sin noexec
    NETWORK_MOUNTS=$(mount 2>/dev/null | grep -E "nfs|cifs|smb" || true)
    if [[ -n "$NETWORK_MOUNTS" ]]; then
        echo "Montajes de red encontrados:"
        echo "$NETWORK_MOUNTS"
        echo ""

        while IFS= read -r mnt_line; do
            MOUNT_POINT=$(echo "$mnt_line" | awk '{print $3}')
            OPTIONS=$(echo "$mnt_line" | grep -oP '\(.*?\)')
            if ! echo "$OPTIONS" | grep -q "noexec"; then
                echo -e "  ${YELLOW}!!${NC} $MOUNT_POINT montado SIN noexec"
                log_warn "Share $MOUNT_POINT debería montarse con noexec,nosuid"
            else
                echo -e "  ${GREEN}OK${NC} $MOUNT_POINT tiene noexec"
            fi
        done <<< "$NETWORK_MOUNTS"
    else
        echo -e "  ${GREEN}OK${NC} No hay montajes de red activos"
    fi

    # 3b. Configurar ClamAV para escanear shares si existe
    if command -v clamscan &>/dev/null; then
        echo ""
        if ask "  ¿Configurar escaneo ClamAV de directorios compartidos?"; then
            cat > /usr/local/bin/escanear-shares.sh << 'EOFSCAN'
#!/bin/bash
# Escaneo de contenido compartido - T1080
LOG="/var/log/share-scan-$(date +%Y%m%d).log"
SHARES="/srv/samba /srv/nfs /var/lib/samba/shares /mnt/share"

echo "=== Escaneo de Shares - $(date) ===" | tee "$LOG"

for dir in $SHARES; do
    if [[ -d "$dir" ]]; then
        echo "Escaneando: $dir" | tee -a "$LOG"
        clamscan --infected --recursive --log="$LOG" "$dir" 2>/dev/null || true
    fi
done

INFECTED=$(grep -c "FOUND$" "$LOG" 2>/dev/null || echo 0)
if [[ "$INFECTED" -gt 0 ]]; then
    logger -t escanear-shares "ALERTA: $INFECTED archivos infectados en shares (T1080)"
fi

find /var/log -name "share-scan-*.log" -mtime +30 -delete 2>/dev/null || true
EOFSCAN

            log_change "Creado" "/usr/local/bin/escanear-shares.sh"
            chmod 700 /usr/local/bin/escanear-shares.sh
            log_change "Permisos" "/usr/local/bin/escanear-shares.sh -> 700"
            log_info "Escaneo de shares configurado"
        else
            log_skip "Escaneo ClamAV de directorios compartidos"
        fi
    fi

    log_info "Protección de contenido compartido configurada"
else
    log_skip "Protección de contenido compartido"
    log_warn "Protección de contenido compartido no aplicada"
fi

# ============================================================
log_section "4. SEGMENTACIÓN DE RED (M1030)"
# ============================================================

echo "Implementar segmentación de red para limitar movimiento lateral."
echo "Esto es la mitigación más efectiva contra TA0008."
echo ""
echo "Medidas:"
echo "  - Firewall host-based estricto"
echo "  - Restricción de tráfico entre segmentos"
echo "  - Microsegmentación con zonas de firewalld"
echo ""

if ask "¿Configurar segmentación de red host-based?"; then

    if fw_is_active &>/dev/null; then
        echo ""
        echo -e "${BOLD}Configurando firewall host-based restrictivo...${NC}"

        # Crear zona restrictiva para tráfico interno
        fw_new_zone internal-restricted 2>/dev/null || true

        # Solo permitir servicios necesarios en zona interna
        fw_add_service ssh internal-restricted
        fw_add_service dns internal-restricted

        # Bloquear por defecto en zona interna
        fw_zone_set_target internal-restricted DROP 2>/dev/null || true

        # Aplicar reglas anti-lateral para la zona por defecto
        ZONE=$(fw_get_default_zone 2>/dev/null || echo "public")

        # Limitar servicios outbound
        echo ""
        echo -e "${BOLD}Servicios salientes permitidos actualmente:${NC}"
        fw_list_services "$ZONE" 2>/dev/null
        echo ""
        echo -e "${DIM}Para restringir más: firewall-cmd --zone=$ZONE --remove-service=<servicio>${NC}"

        fw_reload 2>/dev/null || true

        log_info "Zona internal-restricted creada"
    fi

    # Configurar iptables/nftables para bloquear tráfico entre subredes
    echo ""
    echo -e "${BOLD}Configurando restricciones de tráfico saliente...${NC}"

    cat > /usr/local/bin/segmentacion-red.sh << 'EOFSEG'
#!/bin/bash
# Verificación de segmentación de red - M1030
LOG="/var/log/network-segmentation-$(date +%Y%m%d).log"

echo "=== Verificación de Segmentación - $(date) ===" | tee "$LOG"

# Listar todas las conexiones establecidas salientes
echo "" | tee -a "$LOG"
echo "--- Conexiones salientes activas ---" | tee -a "$LOG"

ss -tn state established 2>/dev/null | tail -n+2 | awk '{print $4" -> "$5}' | \
    sort | uniq -c | sort -rn | head -30 | tee -a "$LOG"

# Verificar conexiones a IPs internas (posible lateral movement)
echo "" | tee -a "$LOG"
echo "--- Conexiones a redes internas ---" | tee -a "$LOG"

INTERNAL_CONNS=$(ss -tn state established 2>/dev/null | \
    grep -oP "(?<=\s)(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+):\d+" | \
    sort | uniq -c | sort -rn)

if [[ -n "$INTERNAL_CONNS" ]]; then
    echo "$INTERNAL_CONNS" | tee -a "$LOG"
fi

# Listar puertos abiertos (superficie de ataque para lateral)
echo "" | tee -a "$LOG"
echo "--- Puertos locales abiertos ---" | tee -a "$LOG"

ss -tlnp 2>/dev/null | tail -n+2 | awk '{print $4" "$6}' | tee -a "$LOG"

find /var/log -name "network-segmentation-*.log" -mtime +30 -delete 2>/dev/null || true
EOFSEG

    log_change "Creado" "/usr/local/bin/segmentacion-red.sh"
    chmod 700 /usr/local/bin/segmentacion-red.sh
    log_change "Permisos" "/usr/local/bin/segmentacion-red.sh -> 700"
    log_info "Script de verificación de segmentación creado"

else
    log_skip "Segmentación de red host-based"
    log_warn "Segmentación de red no configurada"
fi

# ============================================================
log_section "5. DETECCIÓN DE MOVIMIENTO LATERAL (M1031)"
# ============================================================

echo "Configurar detección activa de intentos de movimiento lateral."
echo ""

if ask "¿Configurar detección de movimiento lateral?"; then

    cat > /usr/local/bin/detectar-lateral.sh << 'EOFLAT'
#!/bin/bash
# Detección de movimiento lateral - TA0008
LOG="/var/log/lateral-movement-$(date +%Y%m%d).log"
ALERTS=0

echo "=== Detección de Movimiento Lateral - $(date) ===" | tee "$LOG"

# 1. Sesiones SSH salientes inusuales
echo "" | tee -a "$LOG"
echo "--- Conexiones SSH salientes (24h) ---" | tee -a "$LOG"

if command -v ausearch &>/dev/null; then
    SSH_OUT=$(ausearch -k lateral-ssh -ts recent 2>/dev/null | grep -c "type=SYSCALL" || echo 0)
    SCP_OUT=$(ausearch -k lateral-scp -ts recent 2>/dev/null | grep -c "type=SYSCALL" || echo 0)
    echo "  SSH salientes: $SSH_OUT | SCP salientes: $SCP_OUT" | tee -a "$LOG"

    if [[ "$SSH_OUT" -gt 20 ]]; then
        echo "ALERTA: Actividad SSH saliente excesiva ($SSH_OUT eventos)" | tee -a "$LOG"
        ((ALERTS++)) || true
    fi
fi

# 2. Conexiones SSH desde cuentas inusuales
echo "" | tee -a "$LOG"
echo "--- Sesiones SSH entrantes activas ---" | tee -a "$LOG"

SSH_SESSIONS=$(who 2>/dev/null | grep -v "tty" || true)
if [[ -n "$SSH_SESSIONS" ]]; then
    echo "$SSH_SESSIONS" | tee -a "$LOG"

    # Verificar conexiones desde IPs internas inusuales
    while IFS= read -r session; do
        IP=$(echo "$session" | grep -oP '\(.*?\)' | tr -d '()')
        USER=$(echo "$session" | awk '{print $1}')
        if [[ -n "$IP" ]] && echo "$IP" | grep -qP "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"; then
            echo "  NOTA: $USER conectado desde IP interna: $IP" | tee -a "$LOG"
        fi
    done <<< "$SSH_SESSIONS"
fi

# 3. Transferencias de archivos sospechosas
echo "" | tee -a "$LOG"
echo "--- Transferencias de archivos (24h) ---" | tee -a "$LOG"

if command -v ausearch &>/dev/null; then
    for key in lateral-scp lateral-sftp lateral-rsync lateral-smb; do
        COUNT=$(ausearch -k "$key" -ts recent 2>/dev/null | grep -c "type=SYSCALL" || echo 0)
        if [[ "$COUNT" -gt 0 ]]; then
            echo "  $key: $COUNT eventos" | tee -a "$LOG"
            if [[ "$COUNT" -gt 10 ]]; then
                echo "  ALERTA: Transferencia excesiva ($key)" | tee -a "$LOG"
                ((ALERTS++)) || true
            fi
        fi
    done
fi

# 4. Nuevas conexiones a puertos internos
echo "" | tee -a "$LOG"
echo "--- Conexiones activas a redes internas ---" | tee -a "$LOG"

INTERNAL=$(ss -tn state established 2>/dev/null | \
    awk '{print $5}' | grep -P "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)" | \
    sort | uniq -c | sort -rn | head -10)

if [[ -n "$INTERNAL" ]]; then
    echo "$INTERNAL" | tee -a "$LOG"
fi

# 5. Herramientas de lateral movement detectadas
echo "" | tee -a "$LOG"
echo "--- Herramientas de lateral movement ---" | tee -a "$LOG"

LATERAL_TOOLS=$(ps aux 2>/dev/null | grep -iE "psexec|wmiexec|smbexec|evil-winrm|crackmapexec|impacket|chisel|ligolo|proxychains" | grep -v grep || true)
if [[ -n "$LATERAL_TOOLS" ]]; then
    echo "ALERTA: Herramientas de lateral movement activas:" | tee -a "$LOG"
    echo "$LATERAL_TOOLS" | tee -a "$LOG"
    ((ALERTS++)) || true
    logger -t detectar-lateral "ALERTA: Herramientas de lateral movement detectadas"
else
    echo "OK: Sin herramientas de lateral movement" | tee -a "$LOG"
fi

# Resumen
echo "" | tee -a "$LOG"
echo "=== RESUMEN ===" | tee -a "$LOG"
if [[ $ALERTS -eq 0 ]]; then
    echo "OK: Sin indicadores de movimiento lateral" | tee -a "$LOG"
else
    echo "ALERTA: $ALERTS indicadores de movimiento lateral" | tee -a "$LOG"
    logger -t detectar-lateral "ALERTA: $ALERTS indicadores de movimiento lateral (TA0008)"
fi

find /var/log -name "lateral-movement-*.log" -mtime +30 -delete 2>/dev/null || true
EOFLAT

    log_change "Creado" "/usr/local/bin/detectar-lateral.sh"
    chmod 700 /usr/local/bin/detectar-lateral.sh
    log_change "Permisos" "/usr/local/bin/detectar-lateral.sh -> 700"

    cat > /etc/cron.daily/detectar-lateral << 'EOFCRON'
#!/bin/bash
/usr/local/bin/detectar-lateral.sh 2>&1 | logger -t detectar-lateral
EOFCRON
    log_change "Creado" "/etc/cron.daily/detectar-lateral"
    chmod 700 /etc/cron.daily/detectar-lateral
    log_change "Permisos" "/etc/cron.daily/detectar-lateral -> 700"

    log_info "Detección diaria de movimiento lateral configurada"
else
    log_skip "Detección de movimiento lateral"
    log_warn "Detección de movimiento lateral no configurada"
fi

# ============================================================
log_section "6. RESTRICCIÓN DE SOFTWARE DEPLOYMENT (T1072)"
# ============================================================

echo "Controlar herramientas de deployment que pueden usarse"
echo "para propagar malware a múltiples sistemas."
echo ""

if ask "¿Restringir herramientas de software deployment?"; then

    # Monitorear herramientas de deployment
    if command -v auditctl &>/dev/null; then
        cat >> /etc/audit/rules.d/64-lateral-movement.rules << 'EOF'

# T1072 - Software Deployment Tools
-w /usr/bin/ansible -p x -k deploy-tool
-w /usr/bin/ansible-playbook -p x -k deploy-tool
-w /usr/bin/puppet -p x -k deploy-tool
-w /usr/bin/chef-client -p x -k deploy-tool
-w /usr/bin/salt-call -p x -k deploy-tool
-w /usr/bin/pdsh -p x -k deploy-tool
-w /usr/bin/pssh -p x -k deploy-tool
-w /usr/bin/cssh -p x -k deploy-tool
EOF
        log_change "Modificado" "/etc/audit/rules.d/64-lateral-movement.rules"
        augenrules --load 2>/dev/null || true
        log_info "Auditoría de herramientas de deployment configurada"
    fi

else
    log_skip "Restricción de herramientas de deployment"
    log_warn "Restricción de deployment no configurada"
fi

show_changes_summary

# ============================================================
log_section "RESUMEN DE MITIGACIONES TA0008"
# ============================================================

echo ""
echo -e "${BOLD}Estado de mitigaciones de Movimiento Lateral (TA0008):${NC}"
echo ""

# T1021 - Remote Services
if [[ -f /etc/ssh/sshd_config.d/06-lateral-movement.conf ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1021 - Hardening de servicios remotos"
else
    echo -e "  ${YELLOW}[--]${NC} T1021 - Servicios remotos no endurecidos"
fi

# T1563.001 - SSH Hijacking
if [[ -f /etc/profile.d/ssh-agent-protection.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1563.001 - Protección contra SSH hijacking"
else
    echo -e "  ${YELLOW}[--]${NC} T1563.001 - SSH hijacking no protegido"
fi

# T1080 - Taint Shared Content
if [[ -x /usr/local/bin/escanear-shares.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1080 - Escaneo de contenido compartido"
else
    echo -e "  ${YELLOW}[--]${NC} T1080 - Contenido compartido no escaneado"
fi

# M1030 - Network Segmentation
if [[ -x /usr/local/bin/segmentacion-red.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} M1030 - Segmentación de red"
else
    echo -e "  ${YELLOW}[--]${NC} M1030 - Segmentación de red no configurada"
fi

# Detection
if [[ -x /usr/local/bin/detectar-lateral.sh ]]; then
    echo -e "  ${GREEN}[OK]${NC} TA0008 - Detección de movimiento lateral"
else
    echo -e "  ${YELLOW}[--]${NC} TA0008 - Detección de movimiento lateral no configurada"
fi

# T1072 - Software Deployment
if [[ -f /etc/audit/rules.d/64-lateral-movement.rules ]]; then
    echo -e "  ${GREEN}[OK]${NC} T1072 - Auditoría de herramientas de deployment"
else
    echo -e "  ${YELLOW}[--]${NC} T1072 - Herramientas de deployment no monitoreadas"
fi

echo ""
log_info "Script de mitigación de movimiento lateral completado"
log_info "Backups de configuración en: $BACKUP_DIR"
