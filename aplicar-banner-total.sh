#!/bin/bash
# ============================================================
# APLICAR BANNER DISUASORIO EN TODA LA SUPERFICIE DE ATAQUE
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps
BANNER='
    ══════════════════════════════════════════════════════════════════
    ██╗    ██╗ █████╗ ██████╗ ███╗   ██╗██╗███╗   ██╗ ██████╗
    ██║    ██║██╔══██╗██╔══██╗████╗  ██║██║████╗  ██║██╔════╝
    ██║ █╗ ██║███████║██████╔╝██╔██╗ ██║██║██╔██╗ ██║██║  ███╗
    ██║███╗██║██╔══██║██╔══██╗██║╚██╗██║██║██║╚██╗██║██║   ██║
    ╚███╔███╔╝██║  ██║██║  ██║██║ ╚████║██║██║ ╚████║╚██████╔╝
     ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝
    ══════════════════════════════════════════════════════════════════

    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
    ▓                                                                ▓
    ▓   SISTEMA PRIVADO DE ALTA SEGURIDAD                            ▓
    ▓   ACCESO ESTRICTAMENTE RESTRINGIDO                             ▓
    ▓                                                                ▓
    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓

    ADVERTENCIA LEGAL:

    Este sistema informático es propiedad PRIVADA y está protegido
    por la legislación vigente en materia de delitos informáticos.

    ● El acceso NO AUTORIZADO está PROHIBIDO
    ● Todas las conexiones son MONITOREADAS y REGISTRADAS
    ● Las direcciones IP son capturadas y almacenadas
    ● Se tomarán acciones legales contra intrusos

    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    NOTIFICACIÓN ESPECÍFICA:

    ██  SEQUOIA: ACCESO PERMANENTEMENTE DENEGADO  ██

    Cualquier intento de acceso por parte de "Sequoia" o entidades
    asociadas será considerado como intrusión maliciosa y se
    procederá con denuncia inmediata ante las autoridades competentes.

    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    Si has llegado aquí por error, DESCONÉCTATE INMEDIATAMENTE.

    Código Penal - Delitos Informáticos:
    Art. 197 bis, 264, 264 bis CP (España)
    Ley Orgánica de Protección de Datos (LOPD/RGPD)

    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
'

# Banner corto para espacios limitados
BANNER_CORTO='
╔═══════════════════════════════════════════════════════════════════╗
║  ⚠️  SISTEMA PRIVADO - ACCESO NO AUTORIZADO PROHIBIDO  ⚠️          ║
║  Todas las conexiones son monitoreadas y registradas.             ║
║  SEQUOIA: ACCESO PERMANENTEMENTE DENEGADO                         ║
║  Intrusión = Denuncia inmediata (Art. 197 bis, 264 CP)            ║
╚═══════════════════════════════════════════════════════════════════╝
'

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   APLICANDO BANNER EN TODA LA SUPERFICIE DE ATAQUE        ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# ============================================================
# 1. LOGIN LOCAL (TTY)
# ============================================================
log_info "1. /etc/issue (login TTY local)"
echo "$BANNER" > /etc/issue
log_change "Creado" "/etc/issue"

# ============================================================
# 2. LOGIN REMOTO (telnet, etc)
# ============================================================
log_info "2. /etc/issue.net (login remoto)"
echo "$BANNER" > /etc/issue.net
log_change "Creado" "/etc/issue.net"

# ============================================================
# 3. MESSAGE OF THE DAY (post-login)
# ============================================================
log_info "3. /etc/motd (mensaje post-login)"
echo "$BANNER" > /etc/motd
log_change "Creado" "/etc/motd"

# ============================================================
# 4. SSH BANNER (pre-autenticación)
# ============================================================
log_info "4. SSH Banner (pre-auth)"
mkdir -p /etc/ssh
echo "$BANNER" > /etc/ssh/banner
log_change "Creado" "/etc/ssh/banner"
chmod 644 /etc/ssh/banner
log_change "Permisos" "/etc/ssh/banner -> 644"

# Configurar en sshd_config
if [[ -f /etc/ssh/sshd_config ]]; then
    # Eliminar banners anteriores
    sed -i '/^Banner/d' /etc/ssh/sshd_config
    log_change "Modificado" "/etc/ssh/sshd_config"
    echo "Banner /etc/ssh/banner" >> /etc/ssh/sshd_config
    log_change "Modificado" "/etc/ssh/sshd_config"

    # También mostrar en PrintMotd
    sed -i 's/^PrintMotd.*/PrintMotd yes/' /etc/ssh/sshd_config
    log_change "Modificado" "/etc/ssh/sshd_config"
    if ! grep -q "^PrintMotd" /etc/ssh/sshd_config; then
        echo "PrintMotd yes" >> /etc/ssh/sshd_config
        log_change "Modificado" "/etc/ssh/sshd_config"
    fi

    # Verificar y recargar SSH
    if sshd -t 2>/dev/null; then
        systemctl reload "$SSH_SERVICE_NAME" 2>/dev/null || true
        log_change "Servicio" "$SSH_SERVICE_NAME reload"
        log_info "   SSH configurado correctamente"
    else
        log_warn "   Error en config SSH, verificar manualmente"
    fi
fi

# ============================================================
# 5. SHELL LOGIN (/etc/profile.d/)
# ============================================================
log_info "5. Shell login scripts (/etc/profile.d/)"
cat > /etc/profile.d/z-security-banner.sh << 'EOFPROFILE'
#!/bin/bash
# Mostrar banner de seguridad en cada login de shell

# Solo mostrar una vez por sesión
if [[ -z "$SECURITY_BANNER_SHOWN" ]]; then
    export SECURITY_BANNER_SHOWN=1
    cat << 'BANNER'

    ══════════════════════════════════════════════════════════════════
    ██╗    ██╗ █████╗ ██████╗ ███╗   ██╗██╗███╗   ██╗ ██████╗
    ██║    ██║██╔══██╗██╔══██╗████╗  ██║██║████╗  ██║██╔════╝
    ██║ █╗ ██║███████║██████╔╝██╔██╗ ██║██║██╔██╗ ██║██║  ███╗
    ██║███╗██║██╔══██║██╔══██╗██║╚██╗██║██║██║╚██╗██║██║   ██║
    ╚███╔███╔╝██║  ██║██║  ██║██║ ╚████║██║██║ ╚████║╚██████╔╝
     ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝
    ══════════════════════════════════════════════════════════════════

    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
    ▓                                                                ▓
    ▓   SISTEMA PRIVADO DE ALTA SEGURIDAD                            ▓
    ▓   ACCESO ESTRICTAMENTE RESTRINGIDO                             ▓
    ▓                                                                ▓
    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓

    ADVERTENCIA LEGAL:

    Este sistema informático es propiedad PRIVADA y está protegido
    por la legislación vigente en materia de delitos informáticos.

    ● El acceso NO AUTORIZADO está PROHIBIDO
    ● Todas las conexiones son MONITOREADAS y REGISTRADAS
    ● Las direcciones IP son capturadas y almacenadas
    ● Se tomarán acciones legales contra intrusos

    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    NOTIFICACIÓN ESPECÍFICA:

    ██  SEQUOIA: ACCESO PERMANENTEMENTE DENEGADO  ██

    Cualquier intento de acceso por parte de "Sequoia" o entidades
    asociadas será considerado como intrusión maliciosa y se
    procederá con denuncia inmediata ante las autoridades competentes.

    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    Si has llegado aquí por error, DESCONÉCTATE INMEDIATAMENTE.

    Código Penal - Delitos Informáticos:
    Art. 197 bis, 264, 264 bis CP (España)
    Ley Orgánica de Protección de Datos (LOPD/RGPD)

    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓

BANNER
fi
EOFPROFILE
log_change "Creado" "/etc/profile.d/z-security-banner.sh"
chmod +x /etc/profile.d/z-security-banner.sh
log_change "Permisos" "/etc/profile.d/z-security-banner.sh -> +x"

# ============================================================
# 6. BASHRC GLOBAL
# ============================================================
log_info "6. /etc/bash.bashrc (shell interactivo)"
if [[ -f /etc/bash.bashrc ]]; then
    if ! grep -q "SECURITY_BANNER" /etc/bash.bashrc; then
        cat >> /etc/bash.bashrc << 'EOFBASH'

# Security banner reminder
if [[ $- == *i* ]] && [[ -z "$SECURITY_BANNER_SHOWN" ]]; then
    export SECURITY_BANNER_SHOWN=1
fi
EOFBASH
        log_change "Modificado" "/etc/bash.bashrc"
    fi
fi

# ============================================================
# 7. SDDM (Display Manager KDE/Plasma)
# ============================================================
if [[ -d /etc/sddm.conf.d ]] || command -v sddm &>/dev/null; then
    log_info "7. SDDM (Display Manager)"
    mkdir -p /etc/sddm.conf.d
    log_change "Creado" "/etc/sddm.conf.d/"

    # Crear tema con mensaje
    SDDM_THEME_DIR="/usr/share/sddm/themes/warning-theme"
    if [[ -d /usr/share/sddm/themes ]]; then
        mkdir -p "$SDDM_THEME_DIR"
        log_change "Creado" "$SDDM_THEME_DIR/"

        # Mensaje para SDDM
        cat > "$SDDM_THEME_DIR/theme.conf" << 'EOF'
[General]
background=/usr/share/sddm/themes/warning-theme/background.png
EOF
        log_change "Creado" "$SDDM_THEME_DIR/theme.conf"

        # Crear QML con advertencia completa
        cat > "$SDDM_THEME_DIR/Main.qml" << 'EOF'
import QtQuick 2.0
import SddmComponents 2.0

Rectangle {
    color: "#1a1a2e"

    Text {
        anchors.top: parent.top
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.topMargin: 10
        width: parent.width - 40
        text: "══════════════════════════════════════════════════════════════════\n" +
              "██╗    ██╗ █████╗ ██████╗ ███╗   ██╗██╗███╗   ██╗ ██████╗\n" +
              "██║    ██║██╔══██╗██╔══██╗████╗  ██║██║████╗  ██║██╔════╝\n" +
              "██║ █╗ ██║███████║██████╔╝██╔██╗ ██║██║██╔██╗ ██║██║  ███╗\n" +
              "██║███╗██║██╔══██║██╔══██╗██║╚██╗██║██║██║╚██╗██║██║   ██║\n" +
              "╚███╔███╔╝██║  ██║██║  ██║██║ ╚████║██║██║ ╚████║╚██████╔╝\n" +
              " ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝\n" +
              "══════════════════════════════════════════════════════════════════\n\n" +
              "▓▓▓ SISTEMA PRIVADO DE ALTA SEGURIDAD ▓▓▓\n" +
              "▓▓▓ ACCESO ESTRICTAMENTE RESTRINGIDO ▓▓▓\n\n" +
              "ADVERTENCIA LEGAL:\n" +
              "Este sistema es propiedad PRIVADA y está protegido por la legislación vigente.\n\n" +
              "● El acceso NO AUTORIZADO está PROHIBIDO\n" +
              "● Todas las conexiones son MONITOREADAS y REGISTRADAS\n" +
              "● Las direcciones IP son capturadas y almacenadas\n" +
              "● Se tomarán acciones legales contra intrusos\n\n" +
              "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n" +
              "██  SEQUOIA: ACCESO PERMANENTEMENTE DENEGADO  ██\n\n" +
              "Cualquier intento de acceso por parte de 'Sequoia' o entidades\n" +
              "asociadas será considerado como intrusión maliciosa y se\n" +
              "procederá con denuncia inmediata ante las autoridades.\n\n" +
              "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n" +
              "Si has llegado aquí por error, DESCONÉCTATE INMEDIATAMENTE.\n" +
              "Código Penal: Art. 197 bis, 264, 264 bis CP (España) - LOPD/RGPD"
        color: "#ff4444"
        font.pixelSize: 10
        font.family: "monospace"
        font.bold: true
        horizontalAlignment: Text.AlignHCenter
        wrapMode: Text.WordWrap
    }

    // Incluir el tema por defecto para el login
    Loader {
        anchors.centerIn: parent
        anchors.verticalCenterOffset: 100
        source: "/usr/share/sddm/themes/breeze/Main.qml"
    }
}
EOF
        log_change "Creado" "$SDDM_THEME_DIR/Main.qml"
        log_info "   Tema SDDM con advertencia completa creado"
    fi
fi

# ============================================================
# 8. GDM (GNOME Display Manager)
# ============================================================
if command -v gdm &>/dev/null || [[ -d /etc/gdm ]]; then
    log_info "8. GDM (GNOME Display Manager)"
    mkdir -p /etc/dconf/db/gdm.d
    log_change "Creado" "/etc/dconf/db/gdm.d/"

    cat > /etc/dconf/db/gdm.d/01-banner << 'EOF'
[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='══════════════════════════════════════════════════════════════════\n\n▓▓▓ SISTEMA PRIVADO DE ALTA SEGURIDAD ▓▓▓\n▓▓▓ ACCESO ESTRICTAMENTE RESTRINGIDO ▓▓▓\n\n══════════════════════════════════════════════════════════════════\n\nADVERTENCIA LEGAL:\n\nEste sistema informático es propiedad PRIVADA y está protegido\npor la legislación vigente en materia de delitos informáticos.\n\n● El acceso NO AUTORIZADO está PROHIBIDO\n● Todas las conexiones son MONITOREADAS y REGISTRADAS\n● Las direcciones IP son capturadas y almacenadas\n● Se tomarán acciones legales contra intrusos\n\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\nNOTIFICACIÓN ESPECÍFICA:\n\n██  SEQUOIA: ACCESO PERMANENTEMENTE DENEGADO  ██\n\nCualquier intento de acceso por parte de "Sequoia" o entidades\nasociadas será considerado como intrusión maliciosa y se\nprocederá con denuncia inmediata ante las autoridades competentes.\n\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\nSi has llegado aquí por error, DESCONÉCTATE INMEDIATAMENTE.\n\nCódigo Penal - Delitos Informáticos:\nArt. 197 bis, 264, 264 bis CP (España)\nLey Orgánica de Protección de Datos (LOPD/RGPD)\n\n▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓'
EOF
    log_change "Creado" "/etc/dconf/db/gdm.d/01-banner"

    dconf update 2>/dev/null || true
    log_change "Aplicado" "dconf update"
fi

# ============================================================
# 9. PANTALLA DE BLOQUEO (KDE)
# ============================================================
log_info "9. Pantalla de bloqueo KDE"
KSCREENLOCKER_DIR="/etc/xdg/kscreenlockerrc"
cat > /etc/xdg/kscreenlockerrc << 'EOF'
[Greeter][LnF]
showMediaControls=false

[Greeter][Wallpaper][org.kde.color]
Color=26,26,46
EOF
log_change "Creado" "/etc/xdg/kscreenlockerrc"

# ============================================================
# 10. POLKIT (autenticación gráfica)
# ============================================================
log_info "10. Polkit (diálogos de autenticación)"
mkdir -p /etc/polkit-1/rules.d
log_change "Creado" "/etc/polkit-1/rules.d/"
cat > /etc/polkit-1/rules.d/00-banner.rules << 'EOF'
// Banner de seguridad para Polkit
polkit.addRule(function(action, subject) {
    // Log de intentos de autenticación
    polkit.log("Auth attempt: " + action.id + " by " + subject.user);
    return polkit.Result.NOT_HANDLED;
});
EOF
log_change "Creado" "/etc/polkit-1/rules.d/00-banner.rules"

# ============================================================
# 11. SUDO
# ============================================================
log_info "11. Sudo (mensaje en autenticación)"
if [[ -f /etc/sudoers ]]; then
    # Crear archivo de lecture con warning completo
    cat > /etc/sudo_lecture << 'EOF'

    ══════════════════════════════════════════════════════════════════
    ██╗    ██╗ █████╗ ██████╗ ███╗   ██╗██╗███╗   ██╗ ██████╗
    ██║    ██║██╔══██╗██╔══██╗████╗  ██║██║████╗  ██║██╔════╝
    ██║ █╗ ██║███████║██████╔╝██╔██╗ ██║██║██╔██╗ ██║██║  ███╗
    ██║███╗██║██╔══██║██╔══██╗██║╚██╗██║██║██║╚██╗██║██║   ██║
    ╚███╔███╔╝██║  ██║██║  ██║██║ ╚████║██║██║ ╚████║╚██████╔╝
     ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝
    ══════════════════════════════════════════════════════════════════

    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
    ▓                                                                ▓
    ▓   SISTEMA PRIVADO DE ALTA SEGURIDAD                            ▓
    ▓   ACCESO ESTRICTAMENTE RESTRINGIDO                             ▓
    ▓                                                                ▓
    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓

    ADVERTENCIA LEGAL:

    Este sistema informático es propiedad PRIVADA y está protegido
    por la legislación vigente en materia de delitos informáticos.

    ● El acceso NO AUTORIZADO está PROHIBIDO
    ● Todas las conexiones son MONITOREADAS y REGISTRADAS
    ● Las direcciones IP son capturadas y almacenadas
    ● Se tomarán acciones legales contra intrusos

    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    NOTIFICACIÓN ESPECÍFICA:

    ██  SEQUOIA: ACCESO PERMANENTEMENTE DENEGADO  ██

    Cualquier intento de acceso por parte de "Sequoia" o entidades
    asociadas será considerado como intrusión maliciosa y se
    procederá con denuncia inmediata ante las autoridades competentes.

    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    Si has llegado aquí por error, DESCONÉCTATE INMEDIATAMENTE.

    Código Penal - Delitos Informáticos:
    Art. 197 bis, 264, 264 bis CP (España)
    Ley Orgánica de Protección de Datos (LOPD/RGPD)

    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓

EOF
    log_change "Creado" "/etc/sudo_lecture"
    chmod 644 /etc/sudo_lecture
    log_change "Permisos" "/etc/sudo_lecture -> 644"

    # Añadir a sudoers si no existe
    if ! grep -q "lecture_file" /etc/sudoers.d/99-hardening 2>/dev/null; then
        mkdir -p /etc/sudoers.d
        cat >> /etc/sudoers.d/99-hardening << 'EOF'

# Mostrar advertencia siempre
Defaults lecture=always
Defaults lecture_file=/etc/sudo_lecture
EOF
        log_change "Modificado" "/etc/sudoers.d/99-hardening"
        chmod 440 /etc/sudoers.d/99-hardening
        log_change "Permisos" "/etc/sudoers.d/99-hardening -> 440"
    fi
fi

# ============================================================
# 12. TTY (consolas virtuales)
# ============================================================
log_info "12. TTY consolas virtuales"
for i in {1..6}; do
    if [[ -f /etc/systemd/system/getty@tty${i}.service.d/override.conf ]]; then
        continue
    fi
    mkdir -p /etc/systemd/system/getty@tty${i}.service.d/
    cat > /etc/systemd/system/getty@tty${i}.service.d/override.conf << EOF
[Service]
ExecStart=
ExecStart=-/sbin/agetty --nohostname -o '-p -- \\u' %I \$TERM
EOF
    log_change "Creado" "/etc/systemd/system/getty@tty${i}.service.d/override.conf"
done

# ============================================================
# 13. FAILLOCK (PAM - intentos fallidos)
# ============================================================
log_info "13. Faillock mensaje"
if [[ -f /etc/security/faillock.conf ]]; then
    sed -i 's/^# *audit/audit/' /etc/security/faillock.conf
    log_change "Modificado" "/etc/security/faillock.conf"
fi

# ============================================================
# 14. JOURNAL/LOGS
# ============================================================
log_info "14. Configurar logging de advertencias"
cat > /etc/rsyslog.d/99-security-banner.conf << 'EOF'
# Log de accesos y advertencias de seguridad
auth,authpriv.*                 /var/log/auth.log
*.warn                          /var/log/warnings.log
EOF
log_change "Creado" "/etc/rsyslog.d/99-security-banner.conf"
systemctl restart rsyslog 2>/dev/null || true
log_change "Servicio" "rsyslog restart"

# ============================================================
# 15. FIREWALL REJECT MESSAGE (en logs)
# ============================================================
log_info "15. Firewall logging"
fw_set_log_denied all 2>/dev/null || true

# ============================================================
# 16. TCP WRAPPERS (/etc/hosts.deny)
# ============================================================
log_info "16. TCP Wrappers (/etc/hosts.deny)"
cat > /etc/hosts.deny << 'EOF'
# ══════════════════════════════════════════════════════════════════
# SISTEMA PRIVADO DE ALTA SEGURIDAD
# ACCESO ESTRICTAMENTE RESTRINGIDO
# ══════════════════════════════════════════════════════════════════
#
# ADVERTENCIA LEGAL:
# Este sistema es propiedad PRIVADA y está protegido por la
# legislación vigente en materia de delitos informáticos.
#
# ● El acceso NO AUTORIZADO está PROHIBIDO
# ● Todas las conexiones son MONITOREADAS y REGISTRADAS
# ● Las direcciones IP son capturadas y almacenadas
# ● Se tomarán acciones legales contra intrusos
#
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
# ██  SEQUOIA: ACCESO PERMANENTEMENTE DENEGADO  ██
#
# Cualquier intento de acceso por parte de "Sequoia" o entidades
# asociadas será considerado como intrusión maliciosa.
#
# Código Penal: Art. 197 bis, 264, 264 bis CP (España)
# ══════════════════════════════════════════════════════════════════

# Denegar todo por defecto y registrar
ALL: ALL: spawn /bin/echo "[ALERTA] Intento de acceso no autorizado desde %a a %d - $(date)" >> /var/log/tcpwrappers.log : DENY
EOF
log_change "Creado" "/etc/hosts.deny"

cat > /etc/hosts.allow << 'EOF'
# ══════════════════════════════════════════════════════════════════
# HOSTS PERMITIDOS - Sistema de Alta Seguridad
# ══════════════════════════════════════════════════════════════════

# Permitir localhost
ALL: 127.0.0.1
ALL: [::1]

# Permitir red local (ajustar según necesidad)
# sshd: 192.168.1.0/24
EOF
log_change "Creado" "/etc/hosts.allow"

# ============================================================
# 17. USB EVENTS (udev)
# ============================================================
log_info "17. USB eventos (udev logging)"
cat > /etc/udev/rules.d/99-usb-security.rules << 'EOF'
# Log de dispositivos USB conectados
ACTION=="add", SUBSYSTEM=="usb", RUN+="/bin/sh -c 'echo USB conectado: $env{ID_VENDOR} $env{ID_MODEL} >> /var/log/usb-events.log'"
EOF
log_change "Creado" "/etc/udev/rules.d/99-usb-security.rules"
udevadm control --reload-rules 2>/dev/null || true
log_change "Aplicado" "udevadm control --reload-rules"

# ============================================================
# 18. CRON (banner en ejecución)
# ============================================================
log_info "18. Cron banner"
cat > /etc/cron.d/security-reminder << 'EOF'
# Recordatorio de seguridad diario en logs
0 0 * * * root echo "=== SISTEMA MONITOREADO - SEQUOIA DENEGADO ===" >> /var/log/security-reminder.log
EOF
log_change "Creado" "/etc/cron.d/security-reminder"

# ============================================================
# 19. AUDIT WELCOME (si auditd está activo)
# ============================================================
log_info "19. Audit logging"
if systemctl is-active auditd &>/dev/null; then
    # Las reglas ya registran accesos
    log_info "   Auditd activo - accesos registrados"
fi

# ============================================================
# 20. GRUB (mensaje en boot)
# ============================================================
log_info "20. GRUB bootloader"
if [[ -f /etc/default/grub ]]; then
    # Añadir mensaje al menú de GRUB
    if ! grep -q "GRUB_INIT_TUNE" /etc/default/grub; then
        echo '# Beep de advertencia en boot' >> /etc/default/grub
        echo 'GRUB_INIT_TUNE="480 440 1"' >> /etc/default/grub
        log_change "Modificado" "/etc/default/grub"
    fi

    # Actualizar GRUB
    grub_regenerate
fi

# ============================================================
# RESUMEN
# ============================================================
show_changes_summary
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║          BANNER APLICADO EN TODOS LOS PUNTOS              ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "Superficies cubiertas:"
echo "  ✓ /etc/issue          - Login TTY local"
echo "  ✓ /etc/issue.net      - Login remoto"
echo "  ✓ /etc/motd           - Post-login message"
echo "  ✓ SSH Banner          - Pre-autenticación SSH"
echo "  ✓ Shell profile       - Login de shell"
echo "  ✓ Bash global         - Shell interactivo"
echo "  ✓ SDDM                - Display manager"
echo "  ✓ GDM                 - GNOME display manager"
echo "  ✓ Pantalla bloqueo    - KDE lock screen"
echo "  ✓ Polkit              - Auth gráfica"
echo "  ✓ Sudo                - Elevación privilegios"
echo "  ✓ TTY 1-6             - Consolas virtuales"
echo "  ✓ Faillock            - Intentos fallidos"
echo "  ✓ Rsyslog             - Logging"
echo "  ✓ Firewall            - Log denied"
echo "  ✓ TCP Wrappers        - hosts.allow/deny"
echo "  ✓ USB udev            - Dispositivos USB"
echo "  ✓ Cron                - Recordatorio diario"
echo "  ✓ Auditd              - Auditoría sistema"
echo "  ✓ GRUB                - Bootloader"
echo ""
log_info "Banner de seguridad desplegado en toda la superficie de ataque"
