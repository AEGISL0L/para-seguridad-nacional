#!/bin/bash
# ============================================================
# HARDENING FINAL - Correcciones y mejoras adicionales
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "hardening-final"
securizar_setup_traps

# ── Pre-check: salida temprana si todo aplicado ──
_precheck 13
_pc check_service_active auditd
_pc true  # S2: deshabilitar bluetooth (condicional)
_pc true  # S3: securizar GRUB (condicional)
_pc true  # S4: deshabilitar Ctrl+Alt+Del (condicional)
_pc check_sysctl kernel.dmesg_restrict 1
_pc check_file_exists /etc/tmpfiles.d/tmp-clean.conf
_pc check_file_exists /etc/sudoers.d/99-hardening
_pc true  # S8: deshabilitar servicios innecesarios (condicional)
_pc true  # S9: USBGuard (condicional)
_pc check_file_exists /etc/sysctl.d/99-hide-kernel.conf
_pc check_file_exists /etc/sysctl.d/99-memory-hardening.conf
_pc check_file_exists /etc/logrotate.d/security-logs
_pc true  # S13: verificacion final (siempre informacional)
_precheck_result

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
        log_change "Creado" "/etc/audit/rules.d/50-security.rules"

        # Reiniciar audit-rules primero
        systemctl reset-failed audit-rules.service 2>/dev/null || true
        systemctl restart audit-rules.service 2>/dev/null || true
        log_change "Servicio" "audit-rules restart"

        # Luego iniciar auditd
        systemctl enable auditd 2>/dev/null || true
        log_change "Servicio" "auditd enable"
        systemctl start auditd 2>/dev/null
        log_change "Servicio" "auditd start"

        # Verificar
        if systemctl is-active auditd &>/dev/null; then
            log_info "Auditd activado correctamente"
        else
            log_warn "Auditd no pudo iniciarse, intentando método alternativo..."
            # Cargar reglas manualmente
            auditctl -D 2>/dev/null || true
            auditctl -R /etc/audit/rules.d/50-security.rules 2>/dev/null || true
            systemctl start auditd 2>/dev/null || true
            log_change "Servicio" "auditd start (alternativo)"

            if systemctl is-active auditd &>/dev/null; then
                log_info "Auditd activado (método alternativo)"
            else
                log_error "No se pudo activar auditd. Verificar: journalctl -xe -u auditd"
            fi
        fi
    else
        log_skip "Activar auditd"
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
        systemctl stop bluetooth 2>/dev/null || true
        log_change "Servicio" "bluetooth stop"
        systemctl disable bluetooth 2>/dev/null || true
        log_change "Servicio" "bluetooth disable"
        systemctl mask bluetooth 2>/dev/null || true
        log_change "Servicio" "bluetooth mask"

        # Bloquear módulo (idempotente: no duplicar si contramedidas-mesh.sh ya aplicó)
        if ! grep -q "install bluetooth /bin/false" /etc/modprobe.d/disable-bluetooth.conf 2>/dev/null; then
            echo "install bluetooth /bin/false" >> /etc/modprobe.d/disable-bluetooth.conf
            log_change "Añadido" "install bluetooth en disable-bluetooth.conf"
        fi
        if ! grep -q "install btusb /bin/false" /etc/modprobe.d/disable-bluetooth.conf 2>/dev/null; then
            echo "install btusb /bin/false" >> /etc/modprobe.d/disable-bluetooth.conf
            log_change "Añadido" "install btusb en disable-bluetooth.conf"
        fi

        # Descargar módulo si está cargado
        rmmod btusb 2>/dev/null || true
        rmmod bluetooth 2>/dev/null || true

        log_info "Bluetooth deshabilitado y bloqueado"
    else
        log_skip "Deshabilitar Bluetooth"
    fi
fi

# ============================================================
log_section "3. SECURIZAR GRUB"
# ============================================================

if [[ -f "$GRUB_CFG" ]]; then
    GRUB_PERMS=$(stat -c %a "$GRUB_CFG" 2>/dev/null)
    if [[ "$GRUB_PERMS" != "600" ]]; then
        log_warn "GRUB tiene permisos inseguros: $GRUB_PERMS"
        if ask "¿Securizar permisos de GRUB?"; then
            chmod 600 "$GRUB_CFG"
            log_change "Permisos" "$GRUB_CFG -> 600"
            chown root:root "$GRUB_CFG"
            log_change "Permisos" "$GRUB_CFG -> root:root"
            log_info "GRUB securizado (600)"
        else
            log_skip "Securizar permisos de GRUB"
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
        log_change "Servicio" "ctrl-alt-del.target mask"
        log_info "Ctrl+Alt+Del deshabilitado"
    else
        log_skip "Deshabilitar Ctrl+Alt+Del"
    fi
fi

# ============================================================
log_section "5. LIMITAR ACCESO A DMESG"
# ============================================================

DMESG_RESTRICT=$(/usr/sbin/sysctl -n kernel.dmesg_restrict 2>/dev/null)
if [[ "$DMESG_RESTRICT" != "1" ]]; then
    if ask "¿Restringir acceso a dmesg?"; then
        echo "kernel.dmesg_restrict = 1" >> /etc/sysctl.d/99-dmesg.conf
        log_change "Modificado" "/etc/sysctl.d/99-dmesg.conf"
        /usr/sbin/sysctl -w kernel.dmesg_restrict=1
        log_change "Aplicado" "sysctl kernel.dmesg_restrict=1"
        log_info "dmesg restringido a root"
    else
        log_skip "Restringir acceso a dmesg"
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
if check_file_exists /etc/tmpfiles.d/tmp-clean.conf; then
    log_already "Limpieza automática de /tmp"
elif ask "¿Configurar limpieza automática de /tmp en cada boot?"; then
    cat > /etc/tmpfiles.d/tmp-clean.conf << 'EOF'
# Limpiar /tmp en cada boot
D /tmp 1777 root root 0
D /var/tmp 1777 root root 30d
EOF
    log_change "Creado" "/etc/tmpfiles.d/tmp-clean.conf"
    log_info "Limpieza automática de /tmp configurada"
else
    log_skip "Configurar limpieza automática de /tmp"
fi

# ============================================================
log_section "7. FORTALECER SUDO"
# ============================================================

if [[ -f /etc/sudoers ]]; then
    if check_file_exists /etc/sudoers.d/99-hardening; then
        log_already "Fortalecimiento de sudo"
    elif ! grep -q "Defaults.*timestamp_timeout" /etc/sudoers; then
        if ask "¿Fortalecer configuración de sudo?"; then
            cp /etc/sudoers "$BACKUP_DIR/"
            log_change "Backup" "/etc/sudoers"

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
            log_change "Creado" "/etc/sudoers.d/99-hardening"
            chmod 440 /etc/sudoers.d/99-hardening
            log_change "Permisos" "/etc/sudoers.d/99-hardening -> 440"

            # Verificar sintaxis
            if visudo -c &>/dev/null; then
                log_info "Sudo fortalecido"
            else
                rm /etc/sudoers.d/99-hardening
                log_error "Error en configuración, revertido"
            fi
        else
            log_skip "Fortalecer configuración de sudo"
        fi
    else
        log_info "Sudo ya tiene configuración de hardening"
    fi
fi

# ============================================================
log_section "8. DESHABILITAR SERVICIOS INNECESARIOS"
# ============================================================

SERVICES_TO_CHECK="avahi-daemon cups cups.socket cups-browsed lldpd ModemManager"
for svc in $SERVICES_TO_CHECK; do
    if systemctl is-active "$svc" &>/dev/null; then
        echo ""
        log_warn "$svc está activo"
        if ask "¿Deshabilitar $svc?"; then
            systemctl stop "$svc" 2>/dev/null || true
            log_change "Servicio" "$svc stop"
            systemctl disable "$svc" 2>/dev/null || true
            log_change "Servicio" "$svc disable"
            log_info "$svc deshabilitado"
        else
            log_skip "Deshabilitar $svc"
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
        log_change "Creado" "/etc/usbguard/rules.conf"

        systemctl enable --now usbguard
        log_change "Servicio" "usbguard enable --now"
        log_info "USBGuard instalado (dispositivos actuales permitidos)"
        log_warn "Nuevos USB serán bloqueados por defecto"
        log_info "Ver dispositivos: usbguard list-devices"
        log_info "Permitir nuevo: usbguard allow-device <id>"
    else
        log_skip "Instalar USBGuard"
    fi
else
    log_info "USBGuard ya instalado"
fi

# ============================================================
log_section "10. LIMITAR INFORMACIÓN DEL SISTEMA"
# ============================================================

if check_file_exists /etc/sysctl.d/99-hide-kernel.conf; then
    log_already "Ocultar información del sistema"
elif ask "¿Ocultar información del sistema (kernel, OS)?"; then
    # /etc/issue ya tiene banner personalizado

    # Ocultar versión del kernel en /proc
    echo "kernel.version = 0" > /etc/sysctl.d/99-hide-kernel.conf 2>/dev/null || true
    log_change "Creado" "/etc/sysctl.d/99-hide-kernel.conf"

    # Deshabilitar motd dinámico si existe
    chmod -x /etc/update-motd.d/* 2>/dev/null || true
    log_change "Permisos" "/etc/update-motd.d/* -> -x"

    log_info "Información del sistema limitada"
else
    log_skip "Ocultar información del sistema"
fi

# ============================================================
log_section "11. PROTECCIÓN DE MEMORIA ADICIONAL"
# ============================================================

if check_file_exists /etc/sysctl.d/99-memory-hardening.conf; then
    log_already "Protecciones de memoria adicionales"
elif ask "¿Aplicar protecciones de memoria adicionales?"; then
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
    log_change "Creado" "/etc/sysctl.d/99-memory-hardening.conf"

    /usr/sbin/sysctl --system > /dev/null 2>&1 || true
    log_change "Aplicado" "sysctl --system (memory hardening)"
    log_info "Protecciones de memoria aplicadas"
else
    log_skip "Aplicar protecciones de memoria adicionales"
fi

# ============================================================
log_section "12. CONFIGURAR LOGROTATE SEGURO"
# ============================================================

if check_file_exists /etc/logrotate.d/security-logs; then
    log_already "Retención de logs extendida (1 año)"
elif ask "¿Configurar retención de logs extendida (1 año)?"; then
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
    log_change "Creado" "/etc/logrotate.d/security-logs"
    log_info "Logs de seguridad retenidos por 1 año"
else
    log_skip "Configurar retención de logs extendida"
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
show_changes_summary

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║              HARDENING COMPLETADO                         ║"
echo "╚═══════════════════════════════════════════════════════════╝"
