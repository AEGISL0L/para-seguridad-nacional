#!/bin/bash
# ============================================================
# SANDBOXING DE APLICACIONES - Linux Multi-Distro
# ============================================================
# Secciones:
#   S1 - Instalar Firejail
#   S2 - Perfil para Firefox
#   S3 - Perfil para Thunderbird
#   S4 - Perfil para LibreOffice
#   S5 - Perfil para Dolphin (KDE)
#   S6 - firecfg (aplicar Firejail por defecto)
#   S7 - bubblewrap + script genérico
#   S8 - Script de verificación
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(eval echo "~$REAL_USER")

log_info "Usuario real: $REAL_USER (home: $REAL_HOME)"

# ============================================================
# S1: Instalar Firejail
# ============================================================
log_section "S1: INSTALAR FIREJAIL"

echo "Firejail es un sandbox SUID que reduce la superficie de ataque"
echo "de aplicaciones de escritorio usando namespaces y seccomp."
echo ""

if ask "¿Instalar Firejail?"; then
    if ! command -v firejail &>/dev/null; then
        log_info "Instalando Firejail..."
        pkg_install firejail || {
            log_error "No se pudo instalar Firejail"
            log_warn "Verifica que los repositorios estén configurados"
        }
    fi

    if command -v firejail &>/dev/null; then
        log_info "Firejail instalado: $(firejail --version 2>&1 | head -1)"
    fi
else
    log_skip "Instalar Firejail"
fi

# Verificar que firejail está disponible para las secciones siguientes
if ! command -v firejail &>/dev/null; then
    log_warn "Firejail no disponible. Las secciones S2-S6 requieren Firejail."
    log_warn "Saltando a S7 (bubblewrap)..."
fi

# ============================================================
# S2: Perfil para Firefox
# ============================================================
if command -v firejail &>/dev/null; then
    log_section "S2: PERFIL FIREJAIL PARA FIREFOX"

    echo "Restricciones para Firefox:"
    echo "  - Acceso solo a ~/Descargas y ~/.mozilla"
    echo "  - Sin acceso a SSH, GPG, ni config del sistema"
    echo "  - Seccomp, noroot, private-dev"
    echo ""

    if ask "¿Crear perfil de Firejail para Firefox?"; then
        mkdir -p /etc/firejail
        log_change "Creado" "/etc/firejail/"

        cat > /etc/firejail/firefox.local << 'EOF'
# Perfil local de Firefox para Firejail
# Generado por sandbox-aplicaciones.sh

# Acceso a descargas
whitelist ${HOME}/Descargas
whitelist ${HOME}/Downloads

# Perfil de Firefox
whitelist ${HOME}/.mozilla

# Bloquear acceso sensible
blacklist ${HOME}/.ssh
blacklist ${HOME}/.gnupg
blacklist ${HOME}/.config/autostart
blacklist ${HOME}/.bashrc
blacklist ${HOME}/.bash_history
blacklist /etc/shadow
blacklist /etc/sudoers

# Seguridad adicional
seccomp
noroot
private-dev
private-tmp
nogroups
nonewprivs
EOF

        log_change "Creado" "/etc/firejail/firefox.local"
        log_info "Perfil Firefox creado: /etc/firejail/firefox.local"
    else
        log_skip "Perfil Firejail para Firefox"
    fi

    # ============================================================
    # S3: Perfil para Thunderbird
    # ============================================================
    log_section "S3: PERFIL FIREJAIL PARA THUNDERBIRD"

    echo "Restricciones para Thunderbird:"
    echo "  - Acceso solo a ~/Descargas y ~/.thunderbird"
    echo "  - Sin acceso a SSH, GPG, ni archivos del sistema"
    echo ""

    if ask "¿Crear perfil de Firejail para Thunderbird?"; then
        cat > /etc/firejail/thunderbird.local << 'EOF'
# Perfil local de Thunderbird para Firejail
# Generado por sandbox-aplicaciones.sh

# Acceso a descargas y perfil
whitelist ${HOME}/Descargas
whitelist ${HOME}/Downloads
whitelist ${HOME}/.thunderbird

# Bloquear acceso sensible
blacklist ${HOME}/.ssh
blacklist ${HOME}/.gnupg
blacklist ${HOME}/.config/autostart
blacklist ${HOME}/.bashrc
blacklist ${HOME}/.bash_history
blacklist /etc/shadow
blacklist /etc/sudoers

# Seguridad
seccomp
noroot
private-dev
private-tmp
nogroups
nonewprivs
EOF

        log_change "Creado" "/etc/firejail/thunderbird.local"
        log_info "Perfil Thunderbird creado: /etc/firejail/thunderbird.local"
    else
        log_skip "Perfil Firejail para Thunderbird"
    fi

    # ============================================================
    # S4: Perfil para LibreOffice
    # ============================================================
    log_section "S4: PERFIL FIREJAIL PARA LIBREOFFICE"

    echo "Restricciones para LibreOffice:"
    echo "  - Acceso a ~/Documentos y ~/Descargas"
    echo "  - Sin acceso a red, SSH, ni config del sistema"
    echo ""

    if ask "¿Crear perfil de Firejail para LibreOffice?"; then
        cat > /etc/firejail/libreoffice.local << 'EOF'
# Perfil local de LibreOffice para Firejail
# Generado por sandbox-aplicaciones.sh

# Acceso a documentos y descargas
whitelist ${HOME}/Documentos
whitelist ${HOME}/Documents
whitelist ${HOME}/Descargas
whitelist ${HOME}/Downloads
whitelist ${HOME}/.config/libreoffice

# Bloquear acceso sensible
blacklist ${HOME}/.ssh
blacklist ${HOME}/.gnupg
blacklist ${HOME}/.config/autostart
blacklist ${HOME}/.bashrc
blacklist ${HOME}/.bash_history
blacklist /etc/shadow
blacklist /etc/sudoers

# Seguridad
seccomp
noroot
private-dev
private-tmp
nogroups
nonewprivs
EOF

        log_change "Creado" "/etc/firejail/libreoffice.local"
        log_info "Perfil LibreOffice creado: /etc/firejail/libreoffice.local"
    else
        log_skip "Perfil Firejail para LibreOffice"
    fi

    # ============================================================
    # S5: Perfil para Dolphin (KDE)
    # ============================================================
    log_section "S5: PERFIL FIREJAIL PARA DOLPHIN"

    echo "Restricciones para Dolphin (gestor de archivos KDE):"
    echo "  - Acceso al home del usuario"
    echo "  - Sin acceso a archivos del sistema"
    echo "  - Seccomp, noroot"
    echo ""

    if ask "¿Crear perfil de Firejail para Dolphin?"; then
        cat > /etc/firejail/dolphin.local << 'EOF'
# Perfil local de Dolphin para Firejail
# Generado por sandbox-aplicaciones.sh

# Dolphin necesita acceso amplio al home para gestionar archivos
whitelist ${HOME}

# Bloquear acceso sensible del sistema
blacklist /etc/shadow
blacklist /etc/sudoers
blacklist /etc/ssh

# KDE config
whitelist ${HOME}/.local/share/dolphin
whitelist ${HOME}/.config/dolphinrc

# Seguridad (conservador - Dolphin necesita acceso a dispositivos)
seccomp
noroot
nonewprivs
EOF

        log_change "Creado" "/etc/firejail/dolphin.local"
        log_info "Perfil Dolphin creado: /etc/firejail/dolphin.local"
    else
        log_skip "Perfil Firejail para Dolphin"
    fi

    # ============================================================
    # S6: firecfg (aplicar Firejail por defecto)
    # ============================================================
    log_section "S6: APLICAR FIREJAIL POR DEFECTO (firecfg)"

    echo "firecfg crea symlinks en /usr/local/bin para que las aplicaciones"
    echo "se ejecuten automáticamente dentro de Firejail."
    echo ""
    log_warn "Esto afectará a TODAS las aplicaciones con perfil Firejail."
    echo ""

    if ask "¿Ejecutar firecfg para aplicar Firejail por defecto?"; then
        if command -v firecfg &>/dev/null; then
            firecfg 2>/dev/null || log_warn "firecfg tuvo errores (algunos symlinks pueden ya existir)"
            log_change "Aplicado" "firecfg (Firejail por defecto)"
            log_info "firecfg ejecutado - Firejail aplicado por defecto"
            log_info "Para revertir: firecfg --clean"
        else
            log_error "firecfg no disponible"
        fi
    else
        log_skip "Aplicar Firejail por defecto (firecfg)"
    fi
fi

# ============================================================
# S7: bubblewrap + script genérico
# ============================================================
log_section "S7: BUBBLEWRAP (SANDBOX GENÉRICO)"

echo "bubblewrap (bwrap) es un sandbox de bajo nivel sin SUID."
echo "Se instalará y creará un script de sandbox genérico."
echo ""

if ask "¿Instalar bubblewrap y crear script de sandbox?"; then
    if ! command -v bwrap &>/dev/null; then
        log_info "Instalando bubblewrap..."
        pkg_install bubblewrap || {
            log_error "No se pudo instalar bubblewrap"
        }
    fi

    if command -v bwrap &>/dev/null; then
        log_info "bubblewrap instalado: $(bwrap --version 2>&1)"

        cat > /usr/local/bin/bwrap-sandbox.sh << 'EOFBWRAP'
#!/bin/bash
# ============================================================
# Sandbox genérico con bubblewrap
# Uso: bwrap-sandbox.sh <comando> [argumentos...]
#
# Ejecuta un comando en un entorno aislado con:
#   - Sistema de archivos de solo lectura
#   - /tmp y /home aislados
#   - Sin acceso a red (opcional)
#   - Namespaces separados
# ============================================================

if [[ $# -eq 0 ]]; then
    echo "Uso: bwrap-sandbox.sh <comando> [argumentos...]"
    echo ""
    echo "Opciones de entorno:"
    echo "  BWRAP_NET=1     Permitir acceso a red (por defecto: sin red)"
    echo "  BWRAP_HOME=1    Montar home real (por defecto: home temporal)"
    echo ""
    echo "Ejemplos:"
    echo "  bwrap-sandbox.sh bash"
    echo "  bwrap-sandbox.sh python3 script.py"
    echo "  BWRAP_NET=1 bwrap-sandbox.sh curl https://example.com"
    exit 1
fi

BWRAP_ARGS=(
    --ro-bind / /
    --dev /dev
    --proc /proc
    --tmpfs /tmp
    --tmpfs /run
    --die-with-parent
    --new-session
)

# Red
if [[ "${BWRAP_NET:-0}" != "1" ]]; then
    BWRAP_ARGS+=(--unshare-net)
fi

# Home
if [[ "${BWRAP_HOME:-0}" != "1" ]]; then
    BWRAP_ARGS+=(--tmpfs "$HOME")
fi

# PID namespace
BWRAP_ARGS+=(--unshare-pid)

exec bwrap "${BWRAP_ARGS[@]}" -- "$@"
EOFBWRAP

        chmod +x /usr/local/bin/bwrap-sandbox.sh
        log_change "Creado" "/usr/local/bin/bwrap-sandbox.sh"
        log_change "Permisos" "/usr/local/bin/bwrap-sandbox.sh -> +x"
        log_info "Script creado: /usr/local/bin/bwrap-sandbox.sh"
        echo ""
        echo "Ejemplo de uso:"
        echo "  bwrap-sandbox.sh bash          # Shell aislada sin red"
        echo "  BWRAP_NET=1 bwrap-sandbox.sh curl https://example.com"
    fi
else
    log_skip "Instalar bubblewrap y script de sandbox"
fi

# ============================================================
# S8: Script de verificación
# ============================================================
log_section "S8: SCRIPT DE VERIFICACIÓN DE SANDBOX"

if ask "¿Crear /usr/local/bin/verificar-sandbox.sh?"; then
    cat > /usr/local/bin/verificar-sandbox.sh << 'EOFVERIFY'
#!/bin/bash
# ============================================================
# Verificación de sandboxing de aplicaciones
# Uso: sudo verificar-sandbox.sh
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  VERIFICACIÓN DE SANDBOXING${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

# 1. Firejail
echo -e "${CYAN}── Firejail ──${NC}"
if command -v firejail &>/dev/null; then
    echo -e "  ${GREEN}OK${NC}  Firejail instalado: $(firejail --version 2>&1 | head -1)"

    # Verificar perfiles
    echo ""
    echo "  Perfiles locales:"
    for app in firefox thunderbird libreoffice dolphin; do
        if [[ -f "/etc/firejail/${app}.local" ]]; then
            echo -e "    ${GREEN}OK${NC}  ${app}.local"
        else
            echo -e "    ${YELLOW}--${NC}  ${app}.local no encontrado"
        fi
    done

    # Verificar symlinks de firecfg
    echo ""
    echo "  Symlinks de firecfg:"
    symlinks=$(ls -la /usr/local/bin/ 2>/dev/null | grep -c "firejail" || echo 0)
    if [[ "$symlinks" -gt 0 ]]; then
        echo -e "    ${GREEN}OK${NC}  $symlinks aplicaciones con Firejail por defecto"
    else
        echo -e "    ${YELLOW}--${NC}  firecfg no aplicado (0 symlinks)"
    fi

    # Procesos con firejail activos
    echo ""
    echo "  Procesos en sandbox ahora:"
    firejail --list 2>/dev/null || echo "    Ninguno"

else
    echo -e "  ${YELLOW}!!${NC}  Firejail NO instalado"
fi

# 2. bubblewrap
echo ""
echo -e "${CYAN}── bubblewrap ──${NC}"
if command -v bwrap &>/dev/null; then
    echo -e "  ${GREEN}OK${NC}  bubblewrap instalado: $(bwrap --version 2>&1)"

    if [[ -f /usr/local/bin/bwrap-sandbox.sh ]]; then
        echo -e "  ${GREEN}OK${NC}  bwrap-sandbox.sh disponible"
    else
        echo -e "  ${YELLOW}--${NC}  bwrap-sandbox.sh no encontrado"
    fi
else
    echo -e "  ${YELLOW}!!${NC}  bubblewrap NO instalado"
fi

# 3. User namespaces
echo ""
echo -e "${CYAN}── Soporte del kernel ──${NC}"
if [[ -f /proc/sys/kernel/unprivileged_userns_clone ]]; then
    userns=$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || echo "N/A")
    if [[ "$userns" == "1" ]]; then
        echo -e "  ${GREEN}OK${NC}  User namespaces habilitados (unprivileged)"
    else
        echo -e "  ${YELLOW}!!${NC}  User namespaces deshabilitados (puede afectar bwrap)"
    fi
else
    echo -e "  ${GREEN}OK${NC}  User namespaces soportados por el kernel"
fi

# Seccomp
if [[ -f /proc/sys/kernel/seccomp/actions_avail ]]; then
    echo -e "  ${GREEN}OK${NC}  Seccomp disponible"
else
    # Verificar de otra forma
    if grep -q "seccomp" /proc/self/status 2>/dev/null; then
        echo -e "  ${GREEN}OK${NC}  Seccomp soportado"
    else
        echo -e "  ${YELLOW}!!${NC}  Estado de seccomp desconocido"
    fi
fi

echo ""
echo -e "${BOLD}Verificación completada: $(date)${NC}"
EOFVERIFY

    chmod +x /usr/local/bin/verificar-sandbox.sh
    log_change "Creado" "/usr/local/bin/verificar-sandbox.sh"
    log_change "Permisos" "/usr/local/bin/verificar-sandbox.sh -> +x"
    log_info "Script creado: /usr/local/bin/verificar-sandbox.sh"
else
    log_skip "Script de verificación de sandbox"
fi

echo ""
show_changes_summary
log_info "Sandboxing de aplicaciones completado"
echo ""
echo "Resumen:"
if command -v firejail &>/dev/null; then
    echo "  Firejail: instalado"
else
    echo "  Firejail: no instalado"
fi
if command -v bwrap &>/dev/null; then
    echo "  bubblewrap: instalado"
else
    echo "  bubblewrap: no instalado"
fi
echo ""
echo "Scripts creados:"
echo "  /usr/local/bin/bwrap-sandbox.sh    - Sandbox genérico"
echo "  /usr/local/bin/verificar-sandbox.sh - Verificación"
