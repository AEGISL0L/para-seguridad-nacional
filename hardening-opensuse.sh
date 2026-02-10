#!/bin/bash
# Script de Hardening base - Linux Multi-Distro
# Ejecutar como root: sudo bash hardening-opensuse.sh
# Cada sección es independiente y pregunta antes de aplicar


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "hardening-opensuse"
securizar_setup_traps
echo ""
echo "=========================================="
echo " Hardening base del sistema"
echo "=========================================="
echo ""

# ============================================
# 1. KERNEL HARDENING (sysctl)
# ============================================
echo ""
log_info "=== 1. HARDENING DEL KERNEL (sysctl) ==="
echo "Mejora protecciones de red y kernel sin afectar rendimiento."
echo ""

if ask "¿Aplicar hardening del kernel?"; then
    # Backup
    cp /etc/sysctl.conf "$BACKUP_DIR/" 2>/dev/null || true

    cat > /etc/sysctl.d/90-hardening.conf << 'EOF'
# Hardening de red
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1

# IPv6 (si no lo usas, considera deshabilitarlo)
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Protecciones del kernel
kernel.sysrq = 0
kernel.core_uses_pid = 1
fs.suid_dumpable = 0

# Protección de enlaces simbólicos y hardlinks
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
EOF

    sysctl --system > /dev/null 2>&1
    log_info "Kernel hardening aplicado"
else
    log_warn "Kernel hardening omitido"
fi

# ============================================
# 2. DESHABILITAR FTP
# ============================================
echo ""
log_info "=== 2. DESHABILITAR FTP ==="
echo "FTP transmite credenciales en texto plano - usar SFTP/SCP en su lugar."
echo ""

# Deshabilitar todos los servicios FTP conocidos
FTP_SERVICES="vsftpd proftpd pure-ftpd ftpd wu-ftpd"
for svc in $FTP_SERVICES; do
    if systemctl list-unit-files | grep -q "^${svc}.service"; then
        log_warn "Servicio FTP encontrado: $svc"
        systemctl stop "$svc" 2>/dev/null || true
        systemctl disable "$svc" 2>/dev/null || true
        systemctl mask "$svc" 2>/dev/null || true
        log_info "$svc deshabilitado y enmascarado"
    fi
done

# Bloquear FTP en firewall
if fw_is_active &>/dev/null; then
    fw_remove_service ftp 2>/dev/null || true
    fw_remove_port 21/tcp 2>/dev/null || true
    fw_remove_port 20/tcp 2>/dev/null || true
    fw_reload 2>/dev/null || true
    log_info "FTP bloqueado en firewall (puertos 20, 21)"
fi

# Verificar si hay paquetes FTP instalados
FTP_PKGS=$(pkg_query_all | grep -iE "vsftpd|proftpd|pure-ftpd" 2>/dev/null || true)
if [[ -n "$FTP_PKGS" ]]; then
    log_warn "Paquetes FTP instalados: $FTP_PKGS"
    if ask "¿Desinstalar paquetes FTP?"; then
        pkg_remove $FTP_PKGS
        log_info "Paquetes FTP eliminados"
    fi
else
    log_info "No hay paquetes FTP instalados"
fi

# ============================================
# 3. SERVICIOS POTENCIALMENTE INNECESARIOS
# ============================================
echo ""
log_info "=== 3. SERVICIOS POTENCIALMENTE INNECESARIOS ==="
echo "Deshabilitar servicios que no uses reduce superficie de ataque."
echo ""

# Avahi (mDNS/Bonjour)
if systemctl is-enabled avahi-daemon &>/dev/null; then
    echo "avahi-daemon: Descubrimiento automático de red (mDNS)"
    echo "  - Útil para: Impresoras de red, Chromecast, AirPlay"
    echo "  - Riesgo: Expone información del sistema en la red local"
    if ask "¿Deshabilitar avahi-daemon?"; then
        systemctl stop avahi-daemon 2>/dev/null || true
        systemctl disable avahi-daemon
        log_info "avahi-daemon deshabilitado"
    fi
fi

# ModemManager
if systemctl is-enabled ModemManager &>/dev/null; then
    echo ""
    echo "ModemManager: Gestión de módems móviles (3G/4G/LTE)"
    echo "  - Útil para: Conexiones móviles USB"
    echo "  - Si no usas módems móviles, puedes deshabilitarlo"
    if ask "¿Deshabilitar ModemManager?"; then
        systemctl stop ModemManager 2>/dev/null || true
        systemctl disable ModemManager
        log_info "ModemManager deshabilitado"
    fi
fi

# Bluetooth
if systemctl is-enabled bluetooth &>/dev/null; then
    echo ""
    echo "bluetooth: Servicio Bluetooth"
    echo "  - Si no usas dispositivos Bluetooth, puedes deshabilitarlo"
    if ask "¿Deshabilitar bluetooth?"; then
        systemctl stop bluetooth 2>/dev/null || true
        systemctl disable bluetooth
        log_info "bluetooth deshabilitado"
    fi
fi

# ============================================
# 4. FIREWALL
# ============================================
echo ""
log_info "=== 4. CONFIGURACIÓN DEL FIREWALL ==="
echo ""

if fw_is_active &>/dev/null; then
    log_info "firewalld está activo"
    fw_list_all 2>/dev/null || true
else
    log_warn "firewalld no está activo"
    if ask "¿Activar firewalld?"; then
        systemctl enable --now firewalld
        log_info "firewalld activado"
    fi
fi

# ============================================
# 5. SSH HARDENING (compatible con GitHub y VPS)
# ============================================
echo ""
log_info "=== 5. HARDENING SSH ==="
echo ""
echo "NOTA: Tus conexiones SALIENTES a GitHub y tu VPS NO se ven afectadas"
echo "      por esta configuración (sshd_config solo afecta conexiones ENTRANTES)"
echo ""

if [[ -f /etc/ssh/sshd_config ]]; then
    if ask "¿Aplicar configuración segura de SSH?"; then
        cp /etc/ssh/sshd_config "$BACKUP_DIR/"

        # Crear configuración de hardening compatible con GitHub/VPS
        cat > /etc/ssh/sshd_config.d/90-hardening.conf << 'EOF'
# SSH Hardening - Compatible con GitHub y conexiones a VPS
# Esta configuración afecta SOLO conexiones ENTRANTES a esta máquina

Protocol 2
PermitRootLogin no
MaxAuthTries 4
MaxSessions 5
LoginGraceTime 60

# Autenticación
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Agent Forwarding habilitado (necesario para GitHub con ssh-agent)
AllowAgentForwarding yes

# TCP Forwarding deshabilitado (seguridad)
AllowTcpForwarding no

# X11 Forwarding deshabilitado (seguridad)
X11Forwarding no

# Keepalive para evitar desconexiones
TCPKeepAlive yes
ClientAliveInterval 300
ClientAliveCountMax 3

# Logs
PrintMotd no
PrintLastLog yes

# Algoritmos seguros (compatibles con GitHub)
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
EOF

        # Verificar sintaxis antes de reiniciar
        if sshd -t 2>/dev/null; then
            if systemctl is-active sshd &>/dev/null; then
                systemctl reload sshd
            fi
            log_info "SSH hardening aplicado"
            log_info "  - Agent forwarding habilitado (GitHub compatible)"
            log_info "  - Password authentication habilitado"
            log_info "  - Algoritmos de cifrado modernos"
        else
            log_error "Error en configuración SSH, revirtiendo..."
            rm -f /etc/ssh/sshd_config.d/90-hardening.conf
        fi
    fi
else
    log_info "SSH no instalado (normal si no lo necesitas)"
fi

# Configurar cliente SSH para GitHub
echo ""
log_info "Configurando cliente SSH para GitHub..."
SSH_CONFIG_DIR="/home/${SUDO_USER:-}/.ssh"
if [[ -n "${SUDO_USER:-}" && -d "$SSH_CONFIG_DIR" ]]; then
    if [[ ! -f "$SSH_CONFIG_DIR/config" ]] || ! grep -q "Host github.com" "$SSH_CONFIG_DIR/config" 2>/dev/null; then
        if ask "¿Agregar configuración óptima de cliente SSH para GitHub?"; then
            cat >> "$SSH_CONFIG_DIR/config" << 'EOF'

# GitHub
Host github.com
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_ed25519
    AddKeysToAgent yes
    PreferredAuthentications publickey

EOF
            chown "${SUDO_USER:-}:$(id -gn "${SUDO_USER:-}")" "$SSH_CONFIG_DIR/config"
            chmod 600 "$SSH_CONFIG_DIR/config"
            log_info "Configuración de cliente SSH para GitHub agregada"
            log_info "  Si no tienes llave SSH para GitHub, créala con:"
            log_info "  ssh-keygen -t ed25519 -C 'tu@email.com'"
        fi
    else
        log_info "Ya existe configuración para GitHub en ~/.ssh/config"
    fi
fi

# ============================================
# 6. POLÍTICA DE CONTRASEÑAS
# ============================================
echo ""
log_info "=== 6. POLÍTICA DE CONTRASEÑAS ==="
echo "Configura requisitos mínimos para contraseñas."
echo ""

if [[ -f /etc/security/pwquality.conf ]]; then
    if ask "¿Fortalecer política de contraseñas?"; then
        cp /etc/security/pwquality.conf "$BACKUP_DIR/"

        cat > /etc/security/pwquality.conf << 'EOF'
# Política de contraseñas
minlen = 12
minclass = 3
maxrepeat = 3
maxsequence = 3
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
dictcheck = 1
usercheck = 1
enforcing = 1
retry = 3
EOF
        log_info "Política de contraseñas aplicada"
        log_info "  - Mínimo 12 caracteres"
        log_info "  - Al menos 3 tipos de caracteres (mayús, minús, números, símbolos)"
    fi
fi

# ============================================
# 7. PERMISOS DE ARCHIVOS SENSIBLES
# ============================================
echo ""
log_info "=== 7. PERMISOS DE ARCHIVOS SENSIBLES ==="
echo ""

if ask "¿Verificar y corregir permisos de archivos críticos?"; then
    # /etc/passwd y /etc/group deben ser legibles
    chmod 644 /etc/passwd 2>/dev/null || true
    chmod 644 /etc/group 2>/dev/null || true

    # /etc/shadow y /etc/gshadow solo root
    chmod 640 /etc/shadow 2>/dev/null || true
    chmod 640 /etc/gshadow 2>/dev/null || true

    # Crontabs
    chmod 700 /var/spool/cron 2>/dev/null || true

    # SSH host keys
    chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null || true
    chmod 644 /etc/ssh/ssh_host_*_key.pub 2>/dev/null || true

    log_info "Permisos verificados y corregidos"
fi

# ============================================
# 8. FAIL2BAN (Protección contra fuerza bruta)
# ============================================
echo ""
log_info "=== 8. FAIL2BAN (Protección contra fuerza bruta) ==="
echo "Bloquea IPs que intentan ataques de fuerza bruta."
echo ""

if ! command -v fail2ban-client &>/dev/null; then
    if ask "¿Instalar fail2ban?"; then
        pkg_install fail2ban

        cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/messages
maxretry = 3
bantime = 2h
EOF

        systemctl enable --now fail2ban
        log_info "fail2ban instalado y configurado"
    fi
else
    log_info "fail2ban ya instalado"
fi

# ============================================
# 9. ACTUALIZACIONES DE SEGURIDAD
# ============================================
echo ""
log_info "=== 9. ACTUALIZACIONES DE SEGURIDAD ==="
echo ""

echo "Estado actual de actualizaciones:"
pkg_list_security_patches 2>/dev/null | head -10 || true

if ask "¿Instalar actualizaciones de seguridad pendientes ahora?"; then
    pkg_patch_security
    log_info "Actualizaciones de seguridad aplicadas"
fi

# ============================================
# 10. AUDITD (Auditoría del sistema)
# ============================================
echo ""
log_info "=== 10. AUDITORÍA DEL SISTEMA ==="
echo ""

if systemctl is-active auditd &>/dev/null; then
    log_info "auditd está activo (bien)"

    if ask "¿Agregar reglas de auditoría básicas?"; then
        cat > /etc/audit/rules.d/90-hardening.rules << 'EOF'
# Monitorear cambios en usuarios/grupos
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Monitorear logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# Monitorear cambios en hora del sistema
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
EOF

        augenrules --load 2>/dev/null || service auditd reload
        log_info "Reglas de auditoría agregadas"
    fi
else
    log_warn "auditd no está activo"
fi

# ============================================
# 11. MFA PARA SSH (MITRE T1133 - M1032)
# Autenticación multifactor sin modificar PAM
# ============================================
echo ""
log_info "=== 11. MFA PARA SSH (Autenticación Multifactor) ==="
echo "Configura autenticación en dos pasos para SSH:"
echo "  - Requiere llave SSH (algo que tienes) + contraseña (algo que sabes)"
echo "  - Soporte para llaves FIDO2/U2F (YubiKey, etc.)"
echo "  - NO modifica PAM: usa AuthenticationMethods nativo de OpenSSH"
echo ""

if [[ -f /etc/ssh/sshd_config ]]; then
    if ask "¿Activar MFA para SSH (llave + contraseña)?"; then
        cp /etc/ssh/sshd_config.d/90-hardening.conf "$BACKUP_DIR/" 2>/dev/null || true

        # Crear configuración MFA como drop-in adicional
        cat > /etc/ssh/sshd_config.d/91-mfa.conf << 'EOF'
# ============================================
# MFA para SSH - MITRE T1133 / M1032
# ============================================
# Requiere DOS factores para autenticarse:
#   1. Llave SSH (publickey) - algo que TIENES
#   2. Contraseña (password) - algo que SABES
#
# IMPORTANTE: Los usuarios deben tener AMBOS:
#   - Una llave SSH configurada en ~/.ssh/authorized_keys
#   - Una contraseña válida en el sistema
#
# Esto NO modifica PAM - usa AuthenticationMethods nativo de OpenSSH

# Exigir llave pública Y contraseña (2FA nativo)
AuthenticationMethods publickey,password

# Asegurar que ambos métodos estén habilitados
PubkeyAuthentication yes
PasswordAuthentication yes

# Soporte para llaves FIDO2/U2F (ed25519-sk, ecdsa-sk)
# Las llaves -sk requieren presencia física del token
PubkeyAcceptedAlgorithms +ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,rsa-sha2-512,rsa-sha2-256
EOF

        # Verificar sintaxis antes de aplicar
        if sshd -t 2>/dev/null; then
            if systemctl is-active sshd &>/dev/null; then
                systemctl reload sshd
            fi
            log_info "MFA para SSH activado"
            log_info "  - Se requiere: llave SSH + contraseña"
            log_info "  - Soporte FIDO2/U2F habilitado"
        else
            log_error "Error en configuración SSH MFA, revirtiendo..."
            rm -f /etc/ssh/sshd_config.d/91-mfa.conf
            # Restaurar backup si existe
            if [[ -f "$BACKUP_DIR/90-hardening.conf" ]]; then
                cp "$BACKUP_DIR/90-hardening.conf" /etc/ssh/sshd_config.d/ 2>/dev/null || true
            fi
        fi

        # Crear script helper para generar llaves FIDO2
        cat > /usr/local/bin/generar-llave-fido2.sh << 'EOFFIDO'
#!/bin/bash
# Genera una llave SSH FIDO2/U2F (requiere token físico como YubiKey)
# Uso: sudo -u usuario generar-llave-fido2.sh

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo ""
echo "=========================================="
echo " Generador de llaves SSH FIDO2/U2F"
echo "=========================================="
echo ""
echo "Tipos de llave disponibles:"
echo "  1. ed25519-sk  (recomendado, requiere token FIDO2)"
echo "  2. ecdsa-sk    (compatible con más tokens U2F)"
echo ""

read -p "Selecciona tipo [1/2]: " tipo

case "$tipo" in
    1) KEYTYPE="ed25519-sk" ;;
    2) KEYTYPE="ecdsa-sk" ;;
    *) echo -e "${RED}Opción no válida${NC}"; exit 1 ;;
esac

KEYFILE="$HOME/.ssh/id_${KEYTYPE}"

if [[ -f "$KEYFILE" ]]; then
    echo -e "${YELLOW}Ya existe una llave en $KEYFILE${NC}"
    read -p "¿Sobrescribir? [s/N]: " resp
    [[ "$resp" =~ ^[sS]$ ]] || exit 0
fi

echo ""
echo "Conecta tu token FIDO2/U2F y toca cuando se indique..."
echo ""

ssh-keygen -t "$KEYTYPE" -f "$KEYFILE" -C "$(whoami)@$(hostname)-fido2"

echo ""
echo -e "${GREEN}Llave generada:${NC} $KEYFILE"
echo -e "${GREEN}Llave pública:${NC}  ${KEYFILE}.pub"
echo ""
echo "Para usar en este servidor, añade la llave pública a:"
echo "  ~/.ssh/authorized_keys"
echo ""
echo "Contenido de la llave pública:"
cat "${KEYFILE}.pub"
echo ""
EOFFIDO
        chmod +x /usr/local/bin/generar-llave-fido2.sh

        log_info "Script auxiliar: /usr/local/bin/generar-llave-fido2.sh"

        echo ""
        log_warn "IMPORTANTE: Antes de cerrar esta sesión, asegúrate de que"
        log_warn "tu usuario tiene una llave SSH en ~/.ssh/authorized_keys"
        log_warn "Si no tienes llave SSH configurada, puedes perder acceso."
        echo ""

        # Verificar si el usuario actual tiene llaves SSH
        if [[ -n "${SUDO_USER:-}" ]]; then
            local USER_HOME
            USER_HOME=$(eval echo "~${SUDO_USER:-}")
            if [[ -f "$USER_HOME/.ssh/authorized_keys" ]] && [[ -s "$USER_HOME/.ssh/authorized_keys" ]]; then
                log_info "El usuario ${SUDO_USER:-} tiene llaves SSH configuradas"
            else
                log_warn "El usuario ${SUDO_USER:-} NO tiene llaves SSH en authorized_keys"
                log_warn "Genera una llave con: ssh-keygen -t ed25519"
                log_warn "O para FIDO2: /usr/local/bin/generar-llave-fido2.sh"

                echo ""
                if ask "¿Desactivar MFA temporalmente hasta configurar llaves?"; then
                    rm -f /etc/ssh/sshd_config.d/91-mfa.conf
                    if sshd -t 2>/dev/null; then
                        systemctl reload sshd 2>/dev/null || true
                    fi
                    log_warn "MFA desactivado. Actívalo después con:"
                    log_warn "  sudo cp $BACKUP_DIR/91-mfa.conf /etc/ssh/sshd_config.d/"
                    # Guardar copia para activación futura
                    cat > "$BACKUP_DIR/91-mfa.conf" << 'EOF2'
AuthenticationMethods publickey,password
PubkeyAuthentication yes
PasswordAuthentication yes
PubkeyAcceptedAlgorithms +ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,rsa-sha2-512,rsa-sha2-256
EOF2
                fi
            fi
        fi
    fi
else
    log_info "SSH no instalado, MFA no aplicable"
fi

# ============================================
# 12. CLAMAV ANTIMALWARE (MITRE T1566 - M1049)
# Escaneo antivirus/antimalware de archivos
# ============================================
echo ""
log_info "=== 12. CLAMAV ANTIMALWARE ==="
echo "Instala ClamAV para escaneo antivirus/antimalware."
echo "  - Escaneo bajo demanda y periódico"
echo "  - Actualización automática de firmas"
echo "  - Protección contra phishing y malware en archivos"
echo ""

if ask "¿Instalar y configurar ClamAV?"; then
    # Instalar ClamAV si no está presente
    if ! command -v clamscan &>/dev/null; then
        log_info "Instalando ClamAV..."
        pkg_install clamav || {
            log_error "No se pudo instalar ClamAV. Verifica los repositorios."
            log_warn "Sección 12 omitida"
        }
    fi

    if command -v clamscan &>/dev/null; then
        log_info "ClamAV instalado"

        # Configurar freshclam (actualizador de firmas)
        if [[ -f /etc/freshclam.conf ]]; then
            cp /etc/freshclam.conf "$BACKUP_DIR/" 2>/dev/null || true
        fi

        # Asegurar que freshclam no tiene la línea Example activa
        if [[ -f /etc/freshclam.conf ]]; then
            sed -i 's/^Example/#Example/' /etc/freshclam.conf 2>/dev/null || true
        fi

        # Configurar directorio de cuarentena
        mkdir -p /var/lib/clamav/quarantine
        chmod 700 /var/lib/clamav/quarantine

        # Actualizar firmas por primera vez
        log_info "Actualizando base de datos de firmas de virus..."
        freshclam 2>/dev/null || log_warn "No se pudieron actualizar firmas (sin conexión?)"

        # Habilitar servicio de actualización automática
        if systemctl list-unit-files | grep -q "clamav-freshclam"; then
            systemctl enable --now clamav-freshclam 2>/dev/null || true
            log_info "Actualización automática de firmas activada"
        fi

        # Crear script de escaneo bajo demanda
        cat > /usr/local/bin/clamav-escanear.sh << 'EOFCLAM'
#!/bin/bash
# ============================================
# Escaneo antimalware con ClamAV
# MITRE T1566 - M1049 (Antivirus/Antimalware)
# ============================================
# Uso:
#   clamav-escanear.sh              → Escaneo rápido (/home, /tmp, /var/tmp)
#   clamav-escanear.sh /ruta        → Escaneo de ruta específica
#   clamav-escanear.sh --completo   → Escaneo completo del sistema

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

LOGFILE="/var/log/clamav-scan-$(date +%Y%m%d-%H%M%S).log"
QUARANTINE="/var/lib/clamav/quarantine"

echo ""
echo -e "${CYAN}══════════════════════════════════════${NC}"
echo -e "${CYAN}  Escaneo Antimalware ClamAV${NC}"
echo -e "${CYAN}══════════════════════════════════════${NC}"
echo ""

# Verificar firmas actualizadas
if [[ ! -f /var/lib/clamav/main.cvd ]] && [[ ! -f /var/lib/clamav/main.cld ]]; then
    echo -e "${YELLOW}[!] Base de datos de firmas no encontrada. Actualizando...${NC}"
    freshclam 2>/dev/null || echo -e "${RED}[X] No se pudieron actualizar firmas${NC}"
fi

# Determinar rutas a escanear
if [[ "$1" == "--completo" ]]; then
    SCAN_PATHS="/"
    SCAN_DESC="Sistema completo"
    EXTRA_ARGS="--exclude-dir='^/proc' --exclude-dir='^/sys' --exclude-dir='^/dev' --exclude-dir='^/run'"
elif [[ -n "$1" ]]; then
    SCAN_PATHS="$1"
    SCAN_DESC="$1"
    EXTRA_ARGS=""
else
    SCAN_PATHS="/home /tmp /var/tmp /root"
    SCAN_DESC="Directorios de usuario (/home, /tmp, /var/tmp, /root)"
    EXTRA_ARGS=""
fi

echo -e "Escaneando: ${BOLD}${SCAN_DESC}${NC}"
echo -e "Log: $LOGFILE"
echo -e "Cuarentena: $QUARANTINE"
echo ""

# Ejecutar escaneo
if [[ "$1" == "--completo" ]]; then
    clamscan -r -i \
        --move="$QUARANTINE" \
        --log="$LOGFILE" \
        --exclude-dir='^/proc' \
        --exclude-dir='^/sys' \
        --exclude-dir='^/dev' \
        --exclude-dir='^/run' \
        --exclude-dir='^/var/lib/clamav' \
        / 2>/dev/null || true
else
    clamscan -r -i \
        --move="$QUARANTINE" \
        --log="$LOGFILE" \
        $SCAN_PATHS 2>/dev/null || true
fi

# Mostrar resultados
echo ""
echo -e "${CYAN}══════════════════════════════════════${NC}"
echo -e "${CYAN}  Resultados del escaneo${NC}"
echo -e "${CYAN}══════════════════════════════════════${NC}"

INFECTED=$(grep "Infected files:" "$LOGFILE" 2>/dev/null | tail -1 | awk '{print $NF}')
SCANNED=$(grep "Scanned files:" "$LOGFILE" 2>/dev/null | tail -1 | awk '{print $NF}')

echo ""
echo -e "  Archivos escaneados: ${BOLD}${SCANNED:-0}${NC}"

if [[ "${INFECTED:-0}" -gt 0 ]]; then
    echo -e "  Archivos infectados: ${RED}${BOLD}${INFECTED}${NC}"
    echo -e "  ${YELLOW}Archivos movidos a cuarentena: $QUARANTINE${NC}"
    echo ""
    echo -e "  ${RED}AMENAZAS DETECTADAS:${NC}"
    grep "FOUND" "$LOGFILE" 2>/dev/null | sed 's/^/    /'
else
    echo -e "  Archivos infectados: ${GREEN}${BOLD}0${NC}"
    echo -e "  ${GREEN}Sin amenazas detectadas${NC}"
fi

echo ""
echo -e "Log completo: $LOGFILE"
echo ""
EOFCLAM
        chmod +x /usr/local/bin/clamav-escanear.sh

        # Crear cron diario para escaneo automático
        cat > /etc/cron.daily/clamav-scan << 'EOFCRON'
#!/bin/bash
# Escaneo diario antimalware ClamAV (MITRE T1566 - M1049)
# Escanea directorios de usuario y temporales

LOGDIR="/var/log/clamav"
mkdir -p "$LOGDIR"
LOGFILE="$LOGDIR/scan-$(date +%Y%m%d).log"
QUARANTINE="/var/lib/clamav/quarantine"
mkdir -p "$QUARANTINE"

# Actualizar firmas antes de escanear
freshclam --quiet 2>/dev/null || true

# Escaneo de directorios sensibles
clamscan -r -i \
    --move="$QUARANTINE" \
    --log="$LOGFILE" \
    /home /tmp /var/tmp /root /var/spool/mail 2>/dev/null || true

# Alertar si se encontraron amenazas
INFECTED=$(grep "Infected files:" "$LOGFILE" 2>/dev/null | tail -1 | awk '{print $NF}')
if [[ "${INFECTED:-0}" -gt 0 ]]; then
    echo "[$(date)] ALERTA: ClamAV detectó $INFECTED archivo(s) infectado(s)" >> /var/log/security-alerts.log
    logger -p auth.alert "ClamAV: $INFECTED archivo(s) infectado(s) detectado(s)"
fi

# Mantener solo 30 días de logs
find "$LOGDIR" -name "scan-*.log" -mtime +30 -delete 2>/dev/null || true
EOFCRON
        chmod +x /etc/cron.daily/clamav-scan

        log_info "ClamAV configurado correctamente"
        log_info "  - Escaneo bajo demanda: /usr/local/bin/clamav-escanear.sh"
        log_info "  - Escaneo diario automático: /etc/cron.daily/clamav-scan"
        log_info "  - Cuarentena: /var/lib/clamav/quarantine"
        log_info "  - Actualización de firmas: automática (freshclam)"
    fi
else
    log_warn "ClamAV omitido"
fi

# ============================================
# 13. OPENSCAP AUDITORÍA (MITRE T1195 - M1016)
# Escaneo periódico de vulnerabilidades y compliance
# ============================================
echo ""
log_info "=== 13. OPENSCAP - AUDITORÍA DE VULNERABILIDADES ==="
echo "Instala OpenSCAP para escaneo de compliance y vulnerabilidades."
echo "  - Evaluación de seguridad basada en estándares SCAP"
echo "  - Informes HTML detallados"
echo "  - Escaneo periódico automatizado"
echo ""

if ask "¿Instalar y configurar OpenSCAP?"; then
    # Instalar OpenSCAP y guías de seguridad
    if ! command -v oscap &>/dev/null; then
        log_info "Instalando OpenSCAP..."
        pkg_install openscap-utils || {
            log_error "No se pudo instalar openscap-utils"
        }
    fi

    # Instalar SCAP Security Guide (perfiles de seguridad)
    if ! pkg_is_installed scap-security-guide; then
        log_info "Instalando SCAP Security Guide..."
        pkg_install scap-security-guide || {
            log_warn "scap-security-guide no disponible. Se usarán perfiles locales."
        }
    fi

    if command -v oscap &>/dev/null; then
        log_info "OpenSCAP instalado"

        # Crear directorio para reportes
        mkdir -p /var/log/openscap/reports
        chmod 700 /var/log/openscap

        # Crear script de auditoría SCAP
        cat > /usr/local/bin/openscap-auditar.sh << 'EOFSCAP'
#!/bin/bash
# ============================================
# Auditoría de seguridad con OpenSCAP
# MITRE T1195 - M1016 (Vulnerability Scanning)
# ============================================
# Uso:
#   openscap-auditar.sh              → Auditoría estándar
#   openscap-auditar.sh --perfil ID  → Auditoría con perfil específico
#   openscap-auditar.sh --listar     → Listar perfiles disponibles
#   openscap-auditar.sh --vuln       → Solo escaneo de vulnerabilidades

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

REPORT_DIR="/var/log/openscap/reports"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
mkdir -p "$REPORT_DIR"

echo ""
echo -e "${CYAN}══════════════════════════════════════${NC}"
echo -e "${CYAN}  Auditoría de Seguridad OpenSCAP${NC}"
echo -e "${CYAN}══════════════════════════════════════${NC}"
echo ""

# Buscar contenido SCAP disponible
SSG_DS=""
for ds_path in \
    $SCAP_DS_PATH \
    $SCAP_DS_PATH \
    $SCAP_DS_PATH; do
    if [[ -f "$ds_path" ]]; then
        SSG_DS="$ds_path"
        break
    fi
done

# Listar perfiles disponibles
if [[ "$1" == "--listar" ]]; then
    if [[ -n "$SSG_DS" ]]; then
        echo -e "${BOLD}Perfiles disponibles en:${NC} $SSG_DS"
        echo ""
        oscap info --profiles "$SSG_DS" 2>/dev/null || oscap info "$SSG_DS" 2>/dev/null
    else
        echo -e "${YELLOW}No se encontró SCAP Security Guide${NC}"
        if command -v zypper &>/dev/null; then
            echo "Instalar: zypper install scap-security-guide"
        elif command -v apt-get &>/dev/null; then
            echo "Instalar: apt-get install ssg-base ssg-debderived"
        elif command -v dnf &>/dev/null; then
            echo "Instalar: dnf install scap-security-guide"
        else
            echo "Instalar el paquete scap-security-guide de tu distribución"
        fi
    fi
    exit 0
fi

# Escaneo de vulnerabilidades del sistema (CVE)
if [[ "$1" == "--vuln" ]]; then
    echo -e "${BOLD}Escaneo de vulnerabilidades (CVE)...${NC}"
    VULN_REPORT="$REPORT_DIR/vuln-${TIMESTAMP}.html"
    VULN_RESULTS="$REPORT_DIR/vuln-${TIMESTAMP}-results.xml"

    # Usar oval definitions si están disponibles
    OVAL_DEF=""
    for oval_path in \
        $SCAP_OVAL_PATH \
        $SCAP_OVAL_PATH; do
        if [[ -f "$oval_path" ]]; then
            OVAL_DEF="$oval_path"
            break
        fi
    done

    if [[ -n "$OVAL_DEF" ]]; then
        oscap oval eval \
            --results "$VULN_RESULTS" \
            --report "$VULN_REPORT" \
            "$OVAL_DEF" 2>/dev/null || true

        echo ""
        echo -e "${GREEN}Reporte generado:${NC} $VULN_REPORT"
    else
        echo -e "${YELLOW}No se encontraron definiciones OVAL${NC}"
        echo "Se realizará evaluación XCCDF en su lugar."
    fi
    exit 0
fi

# Auditoría XCCDF con perfil de seguridad
if [[ -n "$SSG_DS" ]]; then
    # Determinar perfil
    PROFILE=""
    if [[ "$1" == "--perfil" ]] && [[ -n "$2" ]]; then
        PROFILE="$2"
    else
        # Intentar perfil estándar de hardening
        for p in "xccdf_org.ssgproject.content_profile_standard" \
                 "xccdf_org.ssgproject.content_profile_cis" \
                 "xccdf_org.ssgproject.content_profile_stig"; do
            if oscap info --profiles "$SSG_DS" 2>/dev/null | grep -q "$p"; then
                PROFILE="$p"
                break
            fi
        done
    fi

    if [[ -z "$PROFILE" ]]; then
        echo -e "${YELLOW}No se encontró perfil compatible.${NC}"
        echo "Perfiles disponibles:"
        oscap info --profiles "$SSG_DS" 2>/dev/null || oscap info "$SSG_DS" 2>/dev/null
        echo ""
        echo "Usa: $0 --perfil <ID_PERFIL>"
        exit 1
    fi

    XCCDF_REPORT="$REPORT_DIR/audit-${TIMESTAMP}.html"
    XCCDF_RESULTS="$REPORT_DIR/audit-${TIMESTAMP}-results.xml"
    XCCDF_ARF="$REPORT_DIR/audit-${TIMESTAMP}-arf.xml"

    echo -e "Perfil: ${BOLD}$PROFILE${NC}"
    echo -e "Contenido: $SSG_DS"
    echo ""

    oscap xccdf eval \
        --profile "$PROFILE" \
        --results "$XCCDF_RESULTS" \
        --results-arf "$XCCDF_ARF" \
        --report "$XCCDF_REPORT" \
        "$SSG_DS" 2>/dev/null || true

    echo ""
    echo -e "${CYAN}══════════════════════════════════════${NC}"
    echo -e "${CYAN}  Resultados de la auditoría${NC}"
    echo -e "${CYAN}══════════════════════════════════════${NC}"
    echo ""

    # Extraer resumen de resultados
    if [[ -f "$XCCDF_RESULTS" ]]; then
        PASS=$(grep -c 'result>pass<' "$XCCDF_RESULTS" 2>/dev/null || echo 0)
        FAIL=$(grep -c 'result>fail<' "$XCCDF_RESULTS" 2>/dev/null || echo 0)
        NOTAPPL=$(grep -c 'result>notapplicable<' "$XCCDF_RESULTS" 2>/dev/null || echo 0)
        TOTAL=$((PASS + FAIL))

        if [[ $TOTAL -gt 0 ]]; then
            SCORE=$((PASS * 100 / TOTAL))
        else
            SCORE=0
        fi

        echo -e "  Reglas aprobadas:       ${GREEN}${BOLD}$PASS${NC}"
        echo -e "  Reglas fallidas:        ${RED}${BOLD}$FAIL${NC}"
        echo -e "  No aplicables:          ${BOLD}$NOTAPPL${NC}"
        echo -e "  Puntuación:             ${BOLD}${SCORE}%${NC}"
    fi

    echo ""
    echo -e "${GREEN}Reporte HTML:${NC}  $XCCDF_REPORT"
    echo -e "${GREEN}Resultados XML:${NC} $XCCDF_RESULTS"
    echo -e "${GREEN}ARF (SCAP):${NC}    $XCCDF_ARF"
else
    echo -e "${YELLOW}SCAP Security Guide no encontrado.${NC}"
    echo ""
    echo "Realizando auditoría básica del sistema..."
    echo ""

    # Auditoría básica sin SSG: verificar configuraciones clave
    BASIC_REPORT="$REPORT_DIR/basic-audit-${TIMESTAMP}.txt"

    {
        echo "=== AUDITORÍA BÁSICA DE SEGURIDAD ==="
        echo "Fecha: $(date)"
        echo "Host: $(hostname)"
        echo "Kernel: $(uname -r)"
        echo ""

        echo "--- Paquetes con actualizaciones de seguridad pendientes ---"
        if command -v zypper &>/dev/null; then
            zypper --non-interactive list-patches --category security 2>/dev/null | head -30 || echo "No se pudo verificar"
        elif command -v apt-get &>/dev/null; then
            apt list --upgradable 2>/dev/null | grep -i security | head -30 || echo "No se pudo verificar"
        elif command -v dnf &>/dev/null; then
            dnf updateinfo list --security 2>/dev/null | head -30 || echo "No se pudo verificar"
        else
            echo "Gestor de paquetes no reconocido"
        fi
        echo ""

        echo "--- Verificación de integridad de paquetes (archivos modificados) ---"
        if command -v rpm &>/dev/null; then
            rpm -Va --nomtime 2>/dev/null | head -50 || echo "No se pudo verificar"
        elif command -v debsums &>/dev/null; then
            debsums -c 2>/dev/null | head -50 || echo "No se pudo verificar"
        elif command -v pacman &>/dev/null; then
            pacman -Qkk 2>/dev/null | grep -v " 0 altered" | head -50 || echo "No se pudo verificar"
        else
            echo "Herramienta de verificación no disponible"
        fi
        echo ""

        echo "--- Servicios escuchando en red ---"
        ss -tlnp 2>/dev/null || echo "No se pudo verificar"
        echo ""

        echo "--- SUID/SGID files ---"
        find / -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null | head -30 || echo "No se pudo verificar"
    } > "$BASIC_REPORT"

    echo -e "${GREEN}Reporte básico:${NC} $BASIC_REPORT"
fi

echo ""
EOFSCAP
        chmod +x /usr/local/bin/openscap-auditar.sh

        # Crear cron semanal para auditoría periódica
        cat > /etc/cron.weekly/openscap-audit << 'EOFCRON2'
#!/bin/bash
# Auditoría semanal de compliance OpenSCAP (MITRE T1195 - M1016)

REPORT_DIR="/var/log/openscap/reports"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
mkdir -p "$REPORT_DIR"

# Buscar contenido SCAP
SSG_DS=""
for ds_path in \
    $SCAP_DS_PATH \
    $SCAP_DS_PATH; do
    if [[ -f "$ds_path" ]]; then
        SSG_DS="$ds_path"
        break
    fi
done

if [[ -n "$SSG_DS" ]] && command -v oscap &>/dev/null; then
    # Determinar perfil
    PROFILE=""
    for p in "xccdf_org.ssgproject.content_profile_standard" \
             "xccdf_org.ssgproject.content_profile_cis"; do
        if oscap info --profiles "$SSG_DS" 2>/dev/null | grep -q "$p"; then
            PROFILE="$p"
            break
        fi
    done

    if [[ -n "$PROFILE" ]]; then
        oscap xccdf eval \
            --profile "$PROFILE" \
            --results "$REPORT_DIR/weekly-${TIMESTAMP}-results.xml" \
            --report "$REPORT_DIR/weekly-${TIMESTAMP}.html" \
            "$SSG_DS" 2>/dev/null || true

        # Registrar en log de seguridad
        FAIL=$(grep -c 'result>fail<' "$REPORT_DIR/weekly-${TIMESTAMP}-results.xml" 2>/dev/null || echo 0)
        if [[ "$FAIL" -gt 0 ]]; then
            echo "[$(date)] OpenSCAP: $FAIL regla(s) de compliance fallida(s)" >> /var/log/security-alerts.log
            logger -p auth.warning "OpenSCAP: $FAIL regla(s) de compliance fallida(s)"
        fi
    fi
fi

# Mantener solo 12 semanas de reportes
find "$REPORT_DIR" -name "weekly-*" -mtime +84 -delete 2>/dev/null || true
EOFCRON2
        chmod +x /etc/cron.weekly/openscap-audit

        # Ejecutar auditoría inicial si el usuario quiere
        echo ""
        if ask "¿Ejecutar auditoría OpenSCAP inicial ahora?"; then
            /usr/local/bin/openscap-auditar.sh || log_warn "La auditoría inicial generó advertencias (normal)"
        fi

        log_info "OpenSCAP configurado correctamente"
        log_info "  - Auditoría manual: /usr/local/bin/openscap-auditar.sh"
        log_info "  - Auditoría semanal: /etc/cron.weekly/openscap-audit"
        log_info "  - Reportes HTML: /var/log/openscap/reports/"
    else
        log_warn "OpenSCAP no se pudo instalar"
    fi
else
    log_warn "OpenSCAP omitido"
fi

# ============================================
# RESUMEN
# ============================================
echo ""
echo "=========================================="
log_info "HARDENING COMPLETADO"
echo "=========================================="
echo ""
echo "Backups guardados en: $BACKUP_DIR"
echo ""
echo "Recomendaciones adicionales:"
echo "  - Usa contraseñas fuertes para todos los usuarios"
echo "  - Considera usar llaves SSH en lugar de contraseñas"
echo "  - Revisa logs regularmente: journalctl -p err"
echo "  - Mantén el sistema actualizado: $PKG_UPDATE_CMD"
echo ""
echo "Nuevas herramientas disponibles:"
echo "  - MFA SSH: requiere llave + contraseña (si activado)"
echo "  - ClamAV: /usr/local/bin/clamav-escanear.sh"
echo "  - OpenSCAP: /usr/local/bin/openscap-auditar.sh"
echo "  - FIDO2: /usr/local/bin/generar-llave-fido2.sh"
echo ""
log_info "Si algo falla, restaura desde: $BACKUP_DIR"
