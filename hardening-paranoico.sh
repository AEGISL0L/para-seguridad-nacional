#!/bin/bash
# ============================================================
# HARDENING PARANOICO - Linux Multi-Distro
# ============================================================
# ADVERTENCIA: Medidas agresivas de seguridad
# Ejecutar como root: sudo bash hardening-paranoico.sh
# ============================================================


set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "hardening-paranoico"
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     HARDENING PARANOICO - Linux Multi-Distro              ║"
echo "║     ADVERTENCIA: Medidas de seguridad agresivas           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups en: $BACKUP_DIR"

# ============================================================
log_section "1. KERNEL HARDENING EXTREMO"
# ============================================================

if ask "¿Aplicar hardening extremo del kernel?"; then
    cat > /etc/sysctl.d/99-paranoid.conf << 'EOF'
# ===========================================
# KERNEL HARDENING PARANOICO
# ===========================================

# --- Protección de memoria ---
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3
kernel.yama.ptrace_scope = 2
kernel.unprivileged_bpf_disabled = 1
kernel.kexec_load_disabled = 1

# --- Deshabilitar SysRq (magic keys) ---
kernel.sysrq = 0

# --- Core dumps deshabilitados ---
kernel.core_pattern = |/bin/false
fs.suid_dumpable = 0

# --- Protección de archivos ---
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# --- Red IPv4 ---
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
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# --- Red IPv6 (restringir) ---
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# --- User namespaces (comentado - puede romper algunas apps) ---
# kernel.unprivileged_userns_clone = 0
EOF

    /usr/sbin/sysctl --system > /dev/null 2>&1
    log_info "Kernel hardening extremo aplicado"
    log_warn "ptrace_scope=2 puede afectar debuggers (gdb, strace)"
fi

# ============================================================
log_section "2. BLACKLIST DE MÓDULOS PELIGROSOS"
# ============================================================

echo "Módulos que se pueden bloquear:"
echo "  - firewire (DMA attacks)"
echo "  - thunderbolt (DMA attacks)"
echo "  - bluetooth (si no lo usas)"
echo "  - cramfs, freevxfs, jffs2, hfs, hfsplus, udf (filesystems raros)"
echo ""

if ask "¿Bloquear módulos peligrosos (NO incluye USB)?"; then
    cat > /etc/modprobe.d/paranoid-blacklist.conf << 'EOF'
# Bloquear protocolos de red obsoletos/peligrosos
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false

# Bloquear DMA attack vectors
install firewire-core /bin/false
install firewire-ohci /bin/false
install firewire-sbp2 /bin/false
install thunderbolt /bin/false

# Bloquear filesystems raros
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install udf /bin/false
install squashfs /bin/false
EOF

    log_info "Módulos peligrosos bloqueados"
fi

if ask "¿Bloquear Bluetooth también?"; then
    cat >> /etc/modprobe.d/paranoid-blacklist.conf << 'EOF'

# Bloquear Bluetooth
install bluetooth /bin/false
install btusb /bin/false
EOF
    systemctl stop bluetooth 2>/dev/null || true
    systemctl disable bluetooth 2>/dev/null || true
    log_info "Bluetooth bloqueado"
fi

# ============================================================
log_section "3. DESHABILITAR CORE DUMPS"
# ============================================================

if ask "¿Deshabilitar core dumps completamente?"; then
    # limits.conf
    cp /etc/security/limits.conf "$BACKUP_DIR/" 2>/dev/null || true
    if ! grep -q "hard core 0" /etc/security/limits.conf; then
        echo "* hard core 0" >> /etc/security/limits.conf
        echo "* soft core 0" >> /etc/security/limits.conf
    fi

    # systemd
    mkdir -p /etc/systemd/coredump.conf.d/
    cat > /etc/systemd/coredump.conf.d/disable.conf << 'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF

    # Profile
    echo "ulimit -c 0" > /etc/profile.d/disable-coredump.sh

    log_info "Core dumps deshabilitados"
fi

# ============================================================
log_section "4. TIMEOUTS DE SESIÓN"
# ============================================================

if ask "¿Configurar timeout automático de sesiones (15 min)?"; then
    cat > /etc/profile.d/timeout.sh << 'EOF'
# Auto-logout después de 15 minutos de inactividad
TMOUT=900
readonly TMOUT
export TMOUT
EOF

    log_info "Timeout de sesión: 15 minutos"
fi

# ============================================================
log_section "5. RESTRINGIR ACCESO A SU"
# ============================================================

echo "Limitar 'su' solo a usuarios del grupo wheel"
if ask "¿Restringir 'su' al grupo wheel?"; then
    # En algunas distribuciones, /etc/pam.d/su puede no existir
    # Crear archivo PAM para su si no existe
    if [[ -f /etc/pam.d/su ]]; then
        cp /etc/pam.d/su "$BACKUP_DIR/"
        # Habilitar pam_wheel en su existente
        if grep -q "^#.*pam_wheel.so" /etc/pam.d/su; then
            sed -i 's/^#\(.*pam_wheel.so.*\)/\1/' /etc/pam.d/su
        elif ! grep -q "pam_wheel.so" /etc/pam.d/su; then
            sed -i '1a auth\t\trequired\tpam_wheel.so use_uid' /etc/pam.d/su
        fi
    else
        # Crear /etc/pam.d/su para openSUSE
        cat > /etc/pam.d/su << 'EOF'
#%PAM-1.0
# Restringir su al grupo wheel
auth     sufficient     pam_rootok.so
auth     required       pam_wheel.so use_uid
auth     include        common-auth
account  include        common-account
password include        common-password
session  include        common-session
session  optional       pam_xauth.so
EOF
        log_info "Archivo /etc/pam.d/su creado"
    fi

    log_info "'su' restringido al grupo wheel"
    log_info "Solo usuarios en grupo wheel pueden usar 'su'"
fi

# ============================================================
log_section "6. RESTRINGIR CRON"
# ============================================================

if ask "¿Restringir cron solo a root y tu usuario?"; then
    echo "root" > /etc/cron.allow
    echo "$SUDO_USER" >> /etc/cron.allow
    chmod 600 /etc/cron.allow
    rm -f /etc/cron.deny 2>/dev/null || true

    # at también
    echo "root" > /etc/at.allow
    echo "$SUDO_USER" >> /etc/at.allow
    chmod 600 /etc/at.allow
    rm -f /etc/at.deny 2>/dev/null || true

    log_info "cron/at restringido a root y $SUDO_USER"
fi

# ============================================================
log_section "7. BANNER DE ADVERTENCIA LEGAL"
# ============================================================

if ask "¿Agregar banner de advertencia legal?"; then
    BANNER="
╔═══════════════════════════════════════════════════════════════════╗
║  SISTEMA PRIVADO - ACCESO NO AUTORIZADO PROHIBIDO                 ║
║                                                                   ║
║  Este sistema es de uso exclusivo para usuarios autorizados.      ║
║  Toda actividad es monitoreada y registrada.                      ║
║  El acceso no autorizado está prohibido y será perseguido         ║
║  conforme a la legislación aplicable.                             ║
╚═══════════════════════════════════════════════════════════════════╝
"
    echo "$BANNER" > /etc/issue
    echo "$BANNER" > /etc/issue.net

    # SSH banner
    echo "$BANNER" > /etc/ssh/banner
    if [[ -f /etc/ssh/sshd_config ]]; then
        if ! grep -q "^Banner" /etc/ssh/sshd_config; then
            echo "Banner /etc/ssh/banner" >> /etc/ssh/sshd_config
        fi
    fi

    log_info "Banner legal configurado"
fi

# ============================================================
log_section "8. PERMISOS RESTRICTIVOS"
# ============================================================

if ask "¿Aplicar permisos restrictivos a archivos del sistema?"; then
    # Archivos de configuración críticos
    chmod 600 /etc/shadow 2>/dev/null || true
    chmod 600 /etc/gshadow 2>/dev/null || true
    chmod 644 /etc/passwd 2>/dev/null || true
    chmod 644 /etc/group 2>/dev/null || true

    # Crontabs
    chmod 700 /etc/crontab 2>/dev/null || true
    chmod 700 /etc/cron.d 2>/dev/null || true
    chmod 700 /etc/cron.daily 2>/dev/null || true
    chmod 700 /etc/cron.hourly 2>/dev/null || true
    chmod 700 /etc/cron.weekly 2>/dev/null || true
    chmod 700 /etc/cron.monthly 2>/dev/null || true

    # SSH
    chmod 700 /etc/ssh 2>/dev/null || true
    chmod 600 /etc/ssh/sshd_config 2>/dev/null || true
    chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null || true

    # GRUB (si existe)
    chmod 600 $GRUB_CFG 2>/dev/null || true

    log_info "Permisos restrictivos aplicados"
fi

# ============================================================
log_section "9. PROTEGER GRUB CON CONTRASEÑA"
# ============================================================

echo "Esto previene que alguien edite parámetros del kernel en boot"
if ask "¿Proteger GRUB con contraseña?"; then
    echo ""
    echo "Introduce una contraseña para GRUB:"
    grub_set_password

    log_info "GRUB protegido con contraseña"
    log_warn "Necesitarás esta contraseña para editar entradas de GRUB"
fi

# ============================================================
log_section "10. INSTALAR HERRAMIENTAS DE SEGURIDAD"
# ============================================================

echo "Herramientas disponibles:"
echo "  - aide: Verificador de integridad de archivos"
echo "  - rkhunter: Detector de rootkits"
echo "  - lynis: Auditor de seguridad"
echo ""

if ask "¿Instalar AIDE (verificador de integridad)?"; then
    if pkg_install aide; then
        log_info "Inicializando base de datos AIDE..."
        aide --init
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null || true
        log_info "AIDE instalado. Ejecutar: aide --check"
    fi
fi

if ask "¿Instalar rkhunter (detector de rootkits)?"; then
    if pkg_install rkhunter; then
        rkhunter --update 2>/dev/null || true
        rkhunter --propupd 2>/dev/null || true
        log_info "rkhunter instalado. Ejecutar: rkhunter --check"
    fi
fi

if ask "¿Instalar lynis (auditor de seguridad)?"; then
    if pkg_install lynis; then
        log_info "lynis instalado. Ejecutar: lynis audit system"
    fi
fi

# ============================================================
log_section "11. FIREWALL PARANOICO"
# ============================================================

if ask "¿Configurar firewall en modo paranoico (DROP por defecto)?"; then
    systemctl enable --now firewalld 2>/dev/null || true

    # Zona drop como default para interfaces no confiables
    fw_set_default_zone drop 2>/dev/null || true

    # Solo permitir lo esencial en la zona de trabajo
    fw_add_service dhcpv6-client work
    fw_add_service dns work

    # Bloquear ICMP excepto los necesarios
    fw_add_icmp_block echo-request 2>/dev/null || true
    fw_add_icmp_block timestamp-request 2>/dev/null || true
    fw_add_icmp_block timestamp-reply 2>/dev/null || true

    # Logging de paquetes rechazados
    fw_set_log_denied all 2>/dev/null || true

    fw_reload 2>/dev/null || true

    log_info "Firewall configurado en modo paranoico"
    log_warn "Zona por defecto: DROP (bloquea todo lo no explícito)"
fi

# ============================================================
log_section "12. CUPS - RESTRINGIR"
# ============================================================

if systemctl is-active cups &>/dev/null; then
    echo "CUPS está activo (impresión)"
    if ask "¿Restringir CUPS solo a localhost?"; then
        cp /etc/cups/cupsd.conf "$BACKUP_DIR/" 2>/dev/null || true

        # Asegurar que solo escuche en localhost
        sed -i 's/^Listen.*/Listen localhost:631/' /etc/cups/cupsd.conf 2>/dev/null || true
        sed -i 's/^Port.*/# Port 631/' /etc/cups/cupsd.conf 2>/dev/null || true

        # Deshabilitar browsing
        sed -i 's/^Browsing.*/Browsing Off/' /etc/cups/cupsd.conf 2>/dev/null || true

        systemctl restart cups
        log_info "CUPS restringido a localhost"
    fi

    if ask "¿Deshabilitar CUPS completamente (no podrás imprimir)?"; then
        systemctl stop cups
        systemctl disable cups
        log_info "CUPS deshabilitado"
    fi
fi

# ============================================================
log_section "13. UMASK RESTRICTIVO"
# ============================================================

if ask "¿Configurar umask restrictivo (027)?"; then
    # /etc/profile
    if ! grep -q "umask 027" /etc/profile; then
        echo "umask 027" >> /etc/profile
    fi

    # /etc/bashrc
    if [[ -f /etc/bashrc ]] && ! grep -q "umask 027" /etc/bashrc; then
        echo "umask 027" >> /etc/bashrc
    fi

    # login.defs
    sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs 2>/dev/null || true

    log_info "umask configurado a 027 (archivos: 640, directorios: 750)"
fi

# ============================================================
log_section "14. DESHABILITAR USB STORAGE (OPCIONAL)"
# ============================================================

log_warn "CUIDADO: Esto impedirá usar memorias USB"
if ask "¿Bloquear almacenamiento USB (memorias, discos externos)?"; then
    echo "install usb-storage /bin/false" >> /etc/modprobe.d/paranoid-blacklist.conf
    rmmod usb_storage 2>/dev/null || true
    log_info "USB storage bloqueado"
fi

# ============================================================
log_section "15. AUDITORÍA AVANZADA"
# ============================================================

if systemctl is-active auditd &>/dev/null; then
    if ask "¿Configurar reglas de auditoría paranoicas?"; then
        cat > /etc/audit/rules.d/99-paranoid.rules << 'EOF'
# Eliminar reglas anteriores
-D

# Buffer grande
-b 8192

# Fallar si no puede auditar
-f 1

# Monitorear cambios en usuarios y grupos
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Monitorear sudoers
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Monitorear cambios en PAM
-w /etc/pam.d/ -p wa -k pam

# Monitorear SSH
-w /etc/ssh/sshd_config -p wa -k sshd

# Monitorear cron
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# Monitorear logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
-w /var/run/utmp -p wa -k logins

# Monitorear hora del sistema
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change

# Monitorear cambios en red
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-w /etc/hostname -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale

# Monitorear módulos del kernel
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# Monitorear montajes
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

# Monitorear borrado de archivos
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

# Monitorear uso de sudo
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k privilege_escalation

# Monitorear acceso a archivos sensibles
-w /etc/passwd -p r -k passwd_read
-w /etc/shadow -p r -k shadow_read

# Hacer reglas inmutables (requiere reboot para cambiar)
-e 2
EOF

        augenrules --load 2>/dev/null || service auditd restart
        log_info "Auditoría paranoica configurada"
        log_warn "Reglas inmutables: requiere reboot para modificar"
    fi
fi

# ============================================================
log_section "16. FAIL2BAN AGRESIVO"
# ============================================================

if command -v fail2ban-client &>/dev/null; then
    if ask "¿Configurar fail2ban en modo agresivo?"; then
        cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 24h
findtime = 10m
maxretry = 3
ignoreip = 127.0.0.1/8 ::1
banaction = firewallcmd-rich-rules[actiontype=<multiport>]
banaction_allports = firewallcmd-rich-rules[actiontype=<allports>]

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/secure
maxretry = 3
bantime = 48h

[sshd-ddos]
enabled = true
port = ssh
filter = sshd-ddos
logpath = /var/log/secure
maxretry = 2
bantime = 72h
EOF

        systemctl restart fail2ban
        log_info "fail2ban configurado en modo agresivo"
        log_info "  - Ban general: 24h, SSH: 48h, DDoS: 72h"
    fi
else
    log_warn "fail2ban no instalado. Instálalo primero."
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║          HARDENING PARANOICO COMPLETADO                   ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups guardados en: $BACKUP_DIR"
echo ""
echo "Comandos útiles post-hardening:"
echo "  - Verificar integridad:  aide --check"
echo "  - Buscar rootkits:       rkhunter --check"
echo "  - Auditoría completa:    lynis audit system"
echo "  - Ver logs de audit:     ausearch -k identity"
echo "  - Ver bans de fail2ban:  fail2ban-client status sshd"
echo ""
log_warn "RECOMENDACIÓN: Reinicia el sistema para aplicar todos los cambios"
echo ""
