#!/bin/bash
# ============================================================
# HARDENING FINAL - Correcciones y mejoras adicionales
# ============================================================


set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "hardening-final"
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║         HARDENING FINAL - Correcciones                    ║"
echo "╚═══════════════════════════════════════════════════════════╝"

# ============================================================
log_section "1. ACTIVAR AUDITD"
# ============================================================

if ! systemctl is-active auditd &>/dev/null; then
    log_warn "Auditd está INACTIVO"
    if ask "¿Activar auditd (auditoría del sistema)?"; then

        # Primero limpiar reglas problemáticas anteriores
        log_info "Limpiando reglas de auditoría anteriores..."
        rm -f /etc/audit/rules.d/99-*.rules 2>/dev/null || true
        rm -f /etc/audit/rules.d/90-*.rules 2>/dev/null || true

        # Crear reglas simples y compatibles
        cat > /etc/audit/rules.d/50-security.rules << 'EOF'
## Reglas de auditoría de seguridad

# Monitorear archivos de identidad
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity

# Monitorear sudoers
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d -p wa -k sudoers

# Monitorear SSH
-w /etc/ssh/sshd_config -p wa -k sshd

# Monitorear logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# Monitorear red
-w /etc/hosts -p wa -k hosts
-w /etc/resolv.conf -p wa -k dns
EOF

        # Reiniciar audit-rules primero
        systemctl reset-failed audit-rules.service 2>/dev/null || true
        systemctl restart audit-rules.service 2>/dev/null || true

        # Luego iniciar auditd
        systemctl enable auditd 2>/dev/null || true
        systemctl start auditd 2>/dev/null

        # Verificar
        if systemctl is-active auditd &>/dev/null; then
            log_info "Auditd activado correctamente"
        else
            log_warn "Auditd no pudo iniciarse, intentando método alternativo..."
            # Cargar reglas manualmente
            auditctl -D 2>/dev/null || true
            auditctl -R /etc/audit/rules.d/50-security.rules 2>/dev/null || true
            systemctl start auditd 2>/dev/null || true

            if systemctl is-active auditd &>/dev/null; then
                log_info "Auditd activado (método alternativo)"
            else
                log_error "No se pudo activar auditd. Verificar: journalctl -xe -u auditd"
            fi
        fi
    fi
else
    log_info "Auditd ya está activo"
fi

# ============================================================
log_section "2. DESHABILITAR BLUETOOTH"
# ============================================================

if systemctl is-active bluetooth &>/dev/null; then
    log_warn "Bluetooth está ACTIVO (vector de ataque)"
    if ask "¿Deshabilitar Bluetooth?"; then
        systemctl stop bluetooth
        systemctl disable bluetooth
        systemctl mask bluetooth

        # Bloquear módulo
        echo "install bluetooth /bin/false" >> /etc/modprobe.d/disable-bluetooth.conf
        echo "install btusb /bin/false" >> /etc/modprobe.d/disable-bluetooth.conf

        # Descargar módulo si está cargado
        rmmod btusb 2>/dev/null || true
        rmmod bluetooth 2>/dev/null || true

        log_info "Bluetooth deshabilitado y bloqueado"
    fi
fi

# ============================================================
log_section "3. SECURIZAR GRUB"
# ============================================================

if [[ -f $GRUB_CFG ]]; then
    GRUB_PERMS=$(stat -c %a $GRUB_CFG 2>/dev/null)
    if [[ "$GRUB_PERMS" != "600" ]]; then
        log_warn "GRUB tiene permisos inseguros: $GRUB_PERMS"
        if ask "¿Securizar permisos de GRUB?"; then
            chmod 600 $GRUB_CFG
            chown root:root $GRUB_CFG
            log_info "GRUB securizado (600)"
        fi
    else
        log_info "GRUB ya tiene permisos seguros"
    fi
fi

# ============================================================
log_section "4. DESHABILITAR CTRL+ALT+DEL"
# ============================================================

if [[ -L /etc/systemd/system/ctrl-alt-del.target ]] || \
   systemctl is-enabled ctrl-alt-del.target &>/dev/null; then
    log_info "Ctrl+Alt+Del ya está configurado"
else
    if ask "¿Deshabilitar Ctrl+Alt+Del (previene reboot accidental)?"; then
        systemctl mask ctrl-alt-del.target
        log_info "Ctrl+Alt+Del deshabilitado"
    fi
fi

# ============================================================
log_section "5. LIMITAR ACCESO A DMESG"
# ============================================================

DMESG_RESTRICT=$(/usr/sbin/sysctl -n kernel.dmesg_restrict 2>/dev/null)
if [[ "$DMESG_RESTRICT" != "1" ]]; then
    if ask "¿Restringir acceso a dmesg?"; then
        echo "kernel.dmesg_restrict = 1" >> /etc/sysctl.d/99-dmesg.conf
        /usr/sbin/sysctl -w kernel.dmesg_restrict=1
        log_info "dmesg restringido a root"
    fi
else
    log_info "dmesg ya está restringido"
fi

# ============================================================
log_section "6. SECURIZAR /tmp y /var/tmp"
# ============================================================

echo "Opciones de montaje seguras para /tmp:"
FSTAB_TMP=$(grep -E "^\s*/tmp\s" /etc/fstab 2>/dev/null || echo "")
if [[ -z "$FSTAB_TMP" ]]; then
    log_warn "/tmp no está en fstab como partición separada"
    echo "Recomendación: montar /tmp con noexec,nosuid,nodev"
else
    log_info "/tmp configurado en fstab"
fi

# Limpiar /tmp en cada boot
if ask "¿Configurar limpieza automática de /tmp en cada boot?"; then
    cat > /etc/tmpfiles.d/tmp-clean.conf << 'EOF'
# Limpiar /tmp en cada boot
D /tmp 1777 root root 0
D /var/tmp 1777 root root 30d
EOF
    log_info "Limpieza automática de /tmp configurada"
fi

# ============================================================
log_section "7. FORTALECER SUDO"
# ============================================================

if [[ -f /etc/sudoers ]]; then
    if ! grep -q "Defaults.*timestamp_timeout" /etc/sudoers; then
        if ask "¿Fortalecer configuración de sudo?"; then
            cp /etc/sudoers "$BACKUP_DIR/"

            cat > /etc/sudoers.d/99-hardening << 'EOF'
# Timeout de sudo: 5 minutos
Defaults timestamp_timeout=5

# Requerir contraseña para sudo -l
Defaults listpw=always

# Log de comandos sudo
Defaults logfile=/var/log/sudo.log

# Mostrar advertencia si falla
Defaults insults

# No permitir sudo desde shells no interactivas
Defaults requiretty

# Limitar PATH en sudo
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
EOF
            chmod 440 /etc/sudoers.d/99-hardening

            # Verificar sintaxis
            if visudo -c &>/dev/null; then
                log_info "Sudo fortalecido"
            else
                rm /etc/sudoers.d/99-hardening
                log_error "Error en configuración, revertido"
            fi
        fi
    else
        log_info "Sudo ya tiene configuración de hardening"
    fi
fi

# ============================================================
log_section "8. DESHABILITAR SERVICIOS INNECESARIOS"
# ============================================================

SERVICES_TO_CHECK="avahi-daemon cups ModemManager"
for svc in $SERVICES_TO_CHECK; do
    if systemctl is-active "$svc" &>/dev/null; then
        echo ""
        log_warn "$svc está activo"
        if ask "¿Deshabilitar $svc?"; then
            systemctl stop "$svc"
            systemctl disable "$svc"
            log_info "$svc deshabilitado"
        fi
    fi
done

# ============================================================
log_section "9. PROTECCIÓN CONTRA USB MALICIOSO (USBGuard)"
# ============================================================

if ! command -v usbguard &>/dev/null; then
    echo "USBGuard protege contra ataques BadUSB/Rubber Ducky"
    if ask "¿Instalar USBGuard?"; then
        pkg_install usbguard

        # Generar política inicial (permitir dispositivos actuales)
        usbguard generate-policy > /etc/usbguard/rules.conf

        systemctl enable --now usbguard
        log_info "USBGuard instalado (dispositivos actuales permitidos)"
        log_warn "Nuevos USB serán bloqueados por defecto"
        log_info "Ver dispositivos: usbguard list-devices"
        log_info "Permitir nuevo: usbguard allow-device <id>"
    fi
else
    log_info "USBGuard ya instalado"
fi

# ============================================================
log_section "10. LIMITAR INFORMACIÓN DEL SISTEMA"
# ============================================================

if ask "¿Ocultar información del sistema (kernel, OS)?"; then
    # /etc/issue ya tiene banner personalizado

    # Ocultar versión del kernel en /proc
    echo "kernel.version = 0" > /etc/sysctl.d/99-hide-kernel.conf 2>/dev/null || true

    # Deshabilitar motd dinámico si existe
    chmod -x /etc/update-motd.d/* 2>/dev/null || true

    log_info "Información del sistema limitada"
fi

# ============================================================
log_section "11. PROTECCIÓN DE MEMORIA ADICIONAL"
# ============================================================

if ask "¿Aplicar protecciones de memoria adicionales?"; then
    cat > /etc/sysctl.d/99-memory-hardening.conf << 'EOF'
# Protección contra buffer overflows
kernel.exec-shield = 1

# Randomización de direcciones
kernel.randomize_va_space = 2

# Proteger contra ataques de kernel
kernel.kptr_restrict = 2
kernel.perf_event_paranoid = 3

# Deshabilitar kexec (carga de kernel en caliente)
kernel.kexec_load_disabled = 1

# Restringir BPF
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# Proteger memoria del kernel
vm.mmap_min_addr = 65536
EOF

    /usr/sbin/sysctl --system > /dev/null 2>&1
    log_info "Protecciones de memoria aplicadas"
fi

# ============================================================
log_section "12. CONFIGURAR LOGROTATE SEGURO"
# ============================================================

if ask "¿Configurar retención de logs extendida (1 año)?"; then
    cat > /etc/logrotate.d/security-logs << 'EOF'
/var/log/secure
/var/log/auth.log
/var/log/sudo.log
/var/log/fail2ban.log
{
    rotate 52
    weekly
    compress
    delaycompress
    notifempty
    create 0600 root root
    missingok
}

/var/log/audit/audit.log
{
    rotate 52
    weekly
    compress
    delaycompress
    notifempty
    create 0600 root root
    missingok
    postrotate
        /usr/bin/systemctl reload auditd 2>/dev/null || true
    endscript
}
EOF
    log_info "Logs de seguridad retenidos por 1 año"
fi

# ============================================================
log_section "13. VERIFICACIÓN FINAL"
# ============================================================

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║              VERIFICACIÓN DE SEGURIDAD                    ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

echo "Kernel:"
/usr/sbin/sysctl kernel.randomize_va_space kernel.kptr_restrict kernel.dmesg_restrict 2>/dev/null | sed 's/^/  /'

echo ""
echo "Red:"
/usr/sbin/sysctl net.ipv4.conf.all.rp_filter net.ipv4.tcp_syncookies 2>/dev/null | sed 's/^/  /'

echo ""
echo "Servicios de seguridad:"
for svc in firewalld fail2ban auditd usbguard; do
    STATUS=$(systemctl is-active $svc 2>/dev/null || echo "no instalado")
    printf "  %-15s %s\n" "$svc:" "$STATUS"
done

echo ""
echo "Puertos TCP abiertos:"
TCP_PORTS=$(ss -tlnp 2>/dev/null | grep -v "^State" | wc -l)
echo "  $TCP_PORTS puertos"

echo ""
log_info "Backups en: $BACKUP_DIR"
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║              HARDENING COMPLETADO                         ║"
echo "╚═══════════════════════════════════════════════════════════╝"
