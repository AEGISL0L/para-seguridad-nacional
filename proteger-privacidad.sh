#!/bin/bash
# ============================================================
# PROTECCIÓN DE PRIVACIDAD - Contra observadores externos
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps

# ── Pre-check: detectar secciones ya aplicadas ──────────────
_precheck 14
_pc true  # S1 - detección/acción directa (siempre re-evaluar)
_pc true  # S2 - limpieza cookies (siempre re-evaluar)
_pc 'check_file_exists ~/.config/xdg-desktop-portal/portals.conf'
_pc true  # S4 - permisos (siempre re-evaluar)
_pc true  # S5 - carpeta cifrada (depende de gocryptfs)
_pc 'check_file_exists /etc/modprobe.d/disable-webcam.conf'
_pc true  # S7 - limpieza historial (siempre re-evaluar)
_pc 'check_file_exists ~/.config/kscreenlockerrc'
_pc 'check_file_exists ~/.config/autostart/security-notify.desktop'
_pc true  # S10 - detección spyware (siempre re-evaluar)
_pc 'check_file_exists /etc/NetworkManager/conf.d/99-no-connectivity-check.conf'
_pc true  # S12 - Firefox HTTPS-Only (siempre re-evaluar)
_pc true  # S13 - firewall (siempre re-evaluar)
_pc true  # S14 - informativo
_precheck_result

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   PROTECCIÓN DE PRIVACIDAD - Anti-Observadores            ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# ============================================================
# 1. DESINSTALAR/DESHABILITAR VNC Y REMOTE DESKTOP
# ============================================================
log_info "1. Eliminando software de acceso remoto..."

# Deshabilitar VNC
sudo systemctl stop vncserver@* 2>/dev/null || true
log_change "Servicio" "vncserver@* stop"
sudo systemctl disable vncserver@* 2>/dev/null || true
log_change "Servicio" "vncserver@* disable"
sudo systemctl mask vncserver@* 2>/dev/null || true
log_change "Servicio" "vncserver@* mask"
sudo systemctl stop xvnc* 2>/dev/null || true
log_change "Servicio" "xvnc* stop"
sudo systemctl disable xvnc* 2>/dev/null || true
log_change "Servicio" "xvnc* disable"

# Deshabilitar KDE Remote Desktop (krfb)
sudo systemctl stop krfb 2>/dev/null || true
log_change "Servicio" "krfb stop"
killall krfb 2>/dev/null || true

# Bloquear X11 forwarding
if [[ -f /etc/ssh/sshd_config ]]; then
    sudo sed -i 's/^X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config 2>/dev/null || true
    sudo sed -i 's/^#X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config 2>/dev/null || true
    log_change "Modificado" "/etc/ssh/sshd_config (X11Forwarding no)"
fi

log_info "   VNC y acceso remoto deshabilitados"

# ============================================================
# 2. CERRAR SESIONES WEB EN NAVEGADORES
# ============================================================
log_info "2. Limpiando sesiones del navegador..."

echo ""
log_warn "IMPORTANTE: Cierra sesiones web manualmente en:"
echo "   • https://myaccount.google.com/device-activity"
echo "   • https://account.live.com/Activity"
echo "   • https://www.facebook.com/settings?tab=security"
echo "   • https://github.com/settings/sessions"
echo "   • Cualquier servicio en la nube que uses"
echo ""

if ask "¿Borrar cookies y datos de navegación de Firefox?"; then
    # Cerrar Firefox primero
    killall firefox 2>/dev/null || true
    sleep 2

    # Borrar datos de sesión
    rm -rf ~/.mozilla/firefox/*/cookies.sqlite* 2>/dev/null || true
    rm -rf ~/.mozilla/firefox/*/sessionstore* 2>/dev/null || true
    rm -rf ~/.mozilla/firefox/*/webappsstore.sqlite* 2>/dev/null || true

    log_info "   Datos de Firefox eliminados"
    log_warn "   Deberás iniciar sesión nuevamente en los sitios web"
else
    log_skip "Borrar cookies y datos de navegación de Firefox"
fi

# ============================================================
# 3. BLOQUEAR COMPARTICIÓN DE PANTALLA EN WAYLAND/X11
# ============================================================
log_info "3. Bloqueando compartición de pantalla..."

# Deshabilitar PipeWire screen sharing portal
mkdir -p ~/.config/xdg-desktop-portal
log_change "Creado" "~/.config/xdg-desktop-portal/"
cat > ~/.config/xdg-desktop-portal/portals.conf << 'EOF'
[preferred]
default=kde
org.freedesktop.impl.portal.ScreenCast=none
org.freedesktop.impl.portal.RemoteDesktop=none
EOF
log_change "Creado" "~/.config/xdg-desktop-portal/portals.conf"

# Bloquear en KDE
mkdir -p ~/.config
cat >> ~/.config/kwinrc << 'EOF'

[Plugins]
screencastEnabled=false
remoteaccessEnabled=false
EOF
log_change "Modificado" "~/.config/kwinrc"

log_info "   Screen sharing bloqueado"

# ============================================================
# 4. PROTEGER PERMISOS DE ARCHIVOS SENSIBLES
# ============================================================
log_info "4. Protegiendo archivos sensibles..."

# Home directory solo accesible por ti
chmod 700 ~
log_change "Permisos" "~ -> 700"

# Archivos de configuración
chmod 700 ~/.config 2>/dev/null || true
log_change "Permisos" "~/.config -> 700"
chmod 700 ~/.local 2>/dev/null || true
log_change "Permisos" "~/.local -> 700"
chmod 700 ~/.cache 2>/dev/null || true
log_change "Permisos" "~/.cache -> 700"
chmod 700 ~/.mozilla 2>/dev/null || true
log_change "Permisos" "~/.mozilla -> 700"
chmod 700 ~/.ssh 2>/dev/null || true
log_change "Permisos" "~/.ssh -> 700"
chmod 600 ~/.ssh/* 2>/dev/null || true
log_change "Permisos" "~/.ssh/* -> 600"
chmod 700 ~/.gnupg 2>/dev/null || true
log_change "Permisos" "~/.gnupg -> 700"

# Documentos
chmod 700 ~/Documentos 2>/dev/null || true
log_change "Permisos" "~/Documentos -> 700"
chmod 700 ~/Descargas 2>/dev/null || true
log_change "Permisos" "~/Descargas -> 700"
chmod 700 ~/Escritorio 2>/dev/null || true
log_change "Permisos" "~/Escritorio -> 700"

log_info "   Permisos restrictivos aplicados"

# ============================================================
# 5. CREAR CARPETA CIFRADA PARA ARCHIVOS SENSIBLES
# ============================================================
log_info "5. Creando carpeta cifrada para archivos sensibles..."

if ! command -v gocryptfs &>/dev/null; then
    if ask "¿Instalar gocryptfs para carpeta cifrada?"; then
        pkg_install gocryptfs
    fi
fi

if command -v gocryptfs &>/dev/null; then
    VAULT_DIR=~/.vault-cifrado
    MOUNT_DIR=~/Privado

    if [[ ! -d "$VAULT_DIR" ]]; then
        mkdir -p "$VAULT_DIR" "$MOUNT_DIR"
        chmod 700 "$VAULT_DIR" "$MOUNT_DIR"
        log_change "Creado" "$VAULT_DIR/"
        log_change "Creado" "$MOUNT_DIR/"
        log_change "Permisos" "$VAULT_DIR -> 700"
        log_change "Permisos" "$MOUNT_DIR -> 700"

        echo ""
        log_warn "Configurando carpeta cifrada..."
        log_warn "Recuerda la contraseña - no se puede recuperar"
        echo ""
        gocryptfs -init "$VAULT_DIR"

        echo ""
        log_info "Carpeta cifrada creada"
        log_info "Para montar: gocryptfs $VAULT_DIR $MOUNT_DIR"
        log_info "Para desmontar: fusermount -u $MOUNT_DIR"
        log_info "Guarda archivos sensibles en: $MOUNT_DIR"
    else
        log_info "   Carpeta cifrada ya existe"
    fi
fi

# ============================================================
# 6. BLOQUEAR WEBCAM Y MICRÓFONO
# ============================================================
log_info "6. Bloqueando webcam y micrófono..."

if check_file_exists /etc/modprobe.d/disable-webcam.conf; then
    log_already "Webcam/micrófono bloqueados (modprobe conf existe)"
elif ask "¿Bloquear webcam y micrófono por software?"; then
    # Blacklist módulos de webcam
    echo "install uvcvideo /bin/false" | sudo tee /etc/modprobe.d/disable-webcam.conf > /dev/null
    echo "install snd_usb_audio /bin/false" | sudo tee -a /etc/modprobe.d/disable-webcam.conf > /dev/null
    log_change "Creado" "/etc/modprobe.d/disable-webcam.conf"

    # Descargar módulos
    sudo rmmod uvcvideo 2>/dev/null || true

    log_info "   Webcam bloqueada (necesita reboot para efecto completo)"
    log_warn "   Para reactivar: sudo rm /etc/modprobe.d/disable-webcam.conf"
else
    log_skip "Bloquear webcam y micrófono"
fi

# ============================================================
# 7. LIMPIAR HISTORIAL Y METADATOS
# ============================================================
log_info "7. Limpiando historiales y metadatos..."

if ask "¿Limpiar historial de bash y archivos recientes?"; then
    # Historial de bash
    cat /dev/null > ~/.bash_history
    history -c

    # Archivos recientes de KDE
    rm -f ~/.local/share/recently-used.xbel 2>/dev/null || true
    rm -rf ~/.local/share/RecentDocuments/* 2>/dev/null || true

    # Thumbnails
    rm -rf ~/.cache/thumbnails/* 2>/dev/null || true

    # Trash
    rm -rf ~/.local/share/Trash/* 2>/dev/null || true

    log_info "   Historiales limpiados"
else
    log_skip "Limpiar historial de bash y archivos recientes"
fi

# ============================================================
# 8. CONFIGURAR BLOQUEO AUTOMÁTICO DE PANTALLA
# ============================================================
log_info "8. Configurando bloqueo automático de pantalla..."

# KDE - bloqueo rápido
mkdir -p ~/.config
cat > ~/.config/kscreenlockerrc << 'EOF'
[Daemon]
Autolock=true
LockGrace=0
LockOnResume=true
Timeout=1

[Greeter][Wallpaper][org.kde.color][General]
Color=0,0,0
EOF
log_change "Creado" "~/.config/kscreenlockerrc"

log_info "   Bloqueo automático: 1 minuto de inactividad"
log_info "   Atajo de teclado: Super+L (bloqueo inmediato)"

# ============================================================
# 9. HABILITAR NOTIFICACIONES DE ACCESO
# ============================================================
log_info "9. Configurando notificaciones de seguridad..."

# Script de notificación en login
mkdir -p ~/.config/autostart
log_change "Creado" "~/.config/autostart/"
cat > ~/.config/autostart/security-notify.desktop << 'EOF'
[Desktop Entry]
Type=Application
Name=Security Notification
Exec=notify-send -u critical "SESIÓN INICIADA" "Alguien ha iniciado sesión en este equipo a las $(date '+%H:%M:%S')"
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
EOF
log_change "Creado" "~/.config/autostart/security-notify.desktop"

log_info "   Notificación de login habilitada"

# ============================================================
# 10. VERIFICAR Y ELIMINAR SOFTWARE ESPÍA CONOCIDO
# ============================================================
log_info "10. Buscando software espía conocido..."

SPYWARE_FOUND=0

# Buscar procesos sospechosos
SUSPICIOUS="keylogger|screenlog|spyware|ratware|backdoor|logger|capture|record|monitor"
if ps aux | grep -iE "$SUSPICIOUS" | grep -v grep > /dev/null 2>&1; then
    log_alert "¡PROCESO SOSPECHOSO DETECTADO!"
    ps aux | grep -iE "$SUSPICIOUS" | grep -v grep
    SPYWARE_FOUND=1
fi

# Buscar extensiones de navegador sospechosas
if find ~/.mozilla -name "*.xpi" -exec unzip -l {} \; 2>/dev/null | grep -iE "screenshot|capture|keylog" > /dev/null 2>&1; then
    log_alert "¡EXTENSIÓN SOSPECHOSA EN FIREFOX!"
    SPYWARE_FOUND=1
fi

if [[ $SPYWARE_FOUND -eq 0 ]]; then
    log_info "   No se detectó software espía conocido"
fi

# ============================================================
# 11. DESHABILITAR NM CONNECTIVITY CHECK
# ============================================================
log_info "11. Deshabilitando NetworkManager connectivity check..."

# NM hace peticiones periódicas a servidores de detección de portal cautivo
# Esto filtra información de red y actividad a terceros
if check_file_exists /etc/NetworkManager/conf.d/99-no-connectivity-check.conf; then
    log_already "NM connectivity check deshabilitado"
else
    mkdir -p /etc/NetworkManager/conf.d
    cat > /etc/NetworkManager/conf.d/99-no-connectivity-check.conf << 'CONN_EOF'
# Deshabilitar connectivity check de NetworkManager
# Evita peticiones periódicas a servidores externos
# Generado por proteger-privacidad.sh
[connectivity]
enabled=false
CONN_EOF
    chmod 644 /etc/NetworkManager/conf.d/99-no-connectivity-check.conf
    log_change "Creado" "/etc/NetworkManager/conf.d/99-no-connectivity-check.conf"

    # Recargar configuración de NM
    if systemctl is-active NetworkManager &>/dev/null; then
        if command -v nmcli &>/dev/null; then
            nmcli general reload conf 2>/dev/null || true
        else
            systemctl reload NetworkManager 2>/dev/null || true
        fi
        log_change "Recargado" "NetworkManager conf (connectivity check deshabilitado)"
    fi
fi

log_info "   NM connectivity check deshabilitado"

# ============================================================
# 12. FIREFOX HTTPS-ONLY MODE
# ============================================================
log_info "12. Verificando Firefox HTTPS-Only mode..."

# Forzar HTTPS en toda la navegación para evitar interceptación de tráfico HTTP
FIREFOX_PROFILES_DIR=""
for d in /home/*/.mozilla/firefox; do
    [[ -d "$d" ]] && FIREFOX_PROFILES_DIR="$d" && break
done

if [[ -n "$FIREFOX_PROFILES_DIR" ]]; then
    _https_applied=0
    _https_missing=0
    while IFS= read -r -d '' profile_dir; do
        if grep -q 'user_pref("dom.security.https_only_mode", true)' "$profile_dir/user.js" 2>/dev/null; then
            ((_https_applied++)) || true
        else
            ((_https_missing++)) || true
        fi
    done < <(find "$FIREFOX_PROFILES_DIR" -maxdepth 1 -name "*.default*" -type d -print0 2>/dev/null)

    if [[ $_https_missing -eq 0 ]] && [[ $_https_applied -gt 0 ]]; then
        log_info "   Firefox HTTPS-Only ya configurado en todos los perfiles"
    elif [[ $_https_missing -gt 0 ]]; then
        log_warn "   $_https_missing perfil(es) Firefox sin HTTPS-Only"
        echo "   HTTPS-Only fuerza HTTPS en toda navegación, previniendo MITM."
        echo ""
        while IFS= read -r -d '' profile_dir; do
            if ! grep -q 'user_pref("dom.security.https_only_mode", true)' "$profile_dir/user.js" 2>/dev/null; then
                {
                    echo ""
                    echo '// Hardening: forzar HTTPS-Only mode'
                    echo 'user_pref("dom.security.https_only_mode", true);'
                    echo 'user_pref("dom.security.https_only_mode_ever_enabled", true);'
                    echo 'user_pref("dom.security.https_only_mode.upgrade_local", true);'
                    echo 'user_pref("dom.security.https_only_mode_ever_enabled_pbm", true);'
                } >> "$profile_dir/user.js"
                local_user=$(stat -c '%U' "$profile_dir")
                chown "$local_user:$(id -gn "$local_user")" "$profile_dir/user.js"
                log_change "Aplicado" "HTTPS-Only en $(basename "$profile_dir")"
            fi
        done < <(find "$FIREFOX_PROFILES_DIR" -maxdepth 1 -name "*.default*" -type d -print0 2>/dev/null)
        log_warn "   Requiere reiniciar Firefox para aplicarse"
    fi
else
    log_info "   No se encontraron perfiles de Firefox"
fi

# ============================================================
# 13. CONFIGURAR FIREWALL PARA BLOQUEAR EXFILTRACIÓN
# ============================================================
log_info "13. Bloqueando puertos de exfiltración comunes..."

# Puertos usados por spyware común
fw_add_rich_rule 'rule family="ipv4" port port="4444" protocol="tcp" drop'
fw_add_rich_rule 'rule family="ipv4" port port="5555" protocol="tcp" drop'
fw_add_rich_rule 'rule family="ipv4" port port="6666" protocol="tcp" drop'
fw_add_rich_rule 'rule family="ipv4" port port="1337" protocol="tcp" drop'
fw_reload 2>/dev/null || true

log_info "   Puertos de exfiltración bloqueados"

# ============================================================
# 14. INSTRUCCIONES FINALES
# ============================================================
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║         PROTECCIÓN DE PRIVACIDAD COMPLETADA               ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "ACCIONES MANUALES RECOMENDADAS:"
echo ""
echo "1. CERRAR SESIONES WEB:"
echo "   • Google: https://myaccount.google.com/device-activity"
echo "   • Microsoft: https://account.live.com/Activity"
echo "   • GitHub: https://github.com/settings/sessions"
echo ""
echo "2. CAMBIAR CONTRASEÑAS de:"
echo "   • Cuentas de email"
echo "   • Servicios en la nube"
echo "   • Redes sociales"
echo ""
echo "3. HABILITAR 2FA en todas las cuentas importantes"
echo ""
echo "4. REVISAR EXTENSIONES DEL NAVEGADOR:"
echo "   Firefox: about:addons"
echo ""
echo "5. REVISAR DISPOSITIVOS AUTORIZADOS en cuentas de Google/Microsoft"
echo ""
echo "6. USAR LA CARPETA CIFRADA para documentos sensibles:"
echo "   Montar: gocryptfs ~/.vault-cifrado ~/Privado"
echo "   Guardar archivos en: ~/Privado/"
echo "   Desmontar: fusermount -u ~/Privado"
echo ""
echo "7. CUBRIR LA WEBCAM físicamente si no la usas"
echo ""
show_changes_summary
log_warn "Si sospechas de SEQUOIA o acceso no autorizado específico,"
log_warn "considera contactar con las autoridades."
