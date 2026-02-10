#!/bin/bash
# ============================================================
# MITIGACIÓN DE EJECUCIÓN - TA0002 (Execution)
# Linux Multi-Distro (openSUSE, Debian/Ubuntu, RHEL/Fedora, Arch)
# ============================================================
# Técnicas MITRE ATT&CK cubiertas:
#   T1059     - Command and Scripting Interpreter (M1038)
#   T1059.004 - Unix Shell (M1038)
#   T1204     - User Execution (M1038)
#   T1129     - Shared Modules (M1044)
#   T1203     - Exploitation for Client Execution (M1050) [verificar]
#   T1053     - Scheduled Task/Job (M1018/M1047) [verificar]
#   T1569     - System Services (M1026) [verificar]
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "mitigar-ejecucion"
securizar_setup_traps
CURRENT_USER="${SUDO_USER:-$USER}"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MITIGACIÓN DE EJECUCIÓN - TA0002                       ║"
echo "║   Prevenir ejecución no autorizada de código              ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# ============================================================
log_section "1. APPARMOR - PERFILES RESTRICTIVOS (T1059 - M1038)"
# ============================================================

echo "AppArmor confina procesos a un conjunto mínimo de recursos."
echo "openSUSE lo incluye por defecto pero puede no estar activo."
echo ""

# Verificar estado actual de AppArmor
AA_STATUS="no_instalado"
if command -v aa-status &>/dev/null; then
    if aa-status --enabled 2>/dev/null; then
        AA_STATUS="activo"
        echo -e "  ${GREEN}OK${NC} AppArmor está activo"
        ENFORCED=$(aa-status 2>/dev/null | grep "profiles are in enforce mode" | awk '{print $1}' || echo "0")
        COMPLAIN=$(aa-status 2>/dev/null | grep "profiles are in complain mode" | awk '{print $1}' || echo "0")
        UNCONFINED=$(aa-status 2>/dev/null | grep "processes are unconfined" | awk '{print $1}' || echo "?")
        echo -e "  ${DIM}Perfiles enforce: $ENFORCED | complain: $COMPLAIN | procesos no confinados: $UNCONFINED${NC}"
    else
        AA_STATUS="instalado_inactivo"
        echo -e "  ${YELLOW}!!${NC} AppArmor instalado pero NO activo"
    fi
else
    echo -e "  ${YELLOW}!!${NC} AppArmor no está instalado"
fi

echo ""

if [[ "$AA_STATUS" == "no_instalado" ]]; then
    if ask "¿Instalar AppArmor con perfiles y utilidades?"; then
        pkg_install apparmor-profiles apparmor-utils apparmor-parser
        if command -v aa-status &>/dev/null; then
            systemctl enable --now apparmor 2>/dev/null || true
            log_info "AppArmor instalado y habilitado"
            AA_STATUS="activo"
        else
            log_error "No se pudo instalar AppArmor"
        fi
    fi
elif [[ "$AA_STATUS" == "instalado_inactivo" ]]; then
    if ask "¿Activar AppArmor?"; then
        systemctl enable --now apparmor 2>/dev/null || true
        if aa-status --enabled 2>/dev/null; then
            log_info "AppArmor activado"
            AA_STATUS="activo"
        else
            log_warn "No se pudo activar AppArmor. Verificar parámetros de kernel."
            log_warn "Puede necesitar: apparmor=1 security=apparmor en GRUB_CMDLINE_LINUX"
        fi
    fi
fi

# Instalar paquete de perfiles adicionales si no existe
if [[ "$AA_STATUS" == "activo" ]]; then
    if ! pkg_is_installed apparmor-profiles; then
        if ask "¿Instalar paquete de perfiles adicionales de AppArmor?"; then
            pkg_install apparmor-profiles
            log_info "Paquete apparmor-profiles instalado"
        fi
    fi

    echo ""
    echo -e "${BOLD}Perfiles actuales:${NC}"
    aa-status 2>/dev/null | head -20 | sed 's/^/  /' || true
    echo ""

    if ask "¿Poner todos los perfiles existentes en modo enforce?"; then
        COMPLAIN_PROFILES=$(aa-status 2>/dev/null | sed -n '/profiles are in complain mode/,/^[0-9]/p' | grep '/' || true)
        if [[ -n "$COMPLAIN_PROFILES" ]]; then
            while IFS= read -r profile; do
                profile=$(echo "$profile" | xargs)
                [[ -z "$profile" ]] && continue
                aa-enforce "$profile" 2>/dev/null || true
            done <<< "$COMPLAIN_PROFILES"
            log_info "Perfiles en complain movidos a enforce"
        else
            log_info "Todos los perfiles ya están en enforce"
        fi
    fi

    # Crear perfiles personalizados para herramientas de red
    if ask "¿Crear perfiles AppArmor para herramientas de red (curl, wget)?"; then
        # Perfil para curl
        if [[ -x /usr/bin/curl ]] && [[ ! -f /etc/apparmor.d/usr.bin.curl ]]; then
            cat > /etc/apparmor.d/usr.bin.curl << 'EOF'
#include <tunables/global>

/usr/bin/curl {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/openssl>
  #include <abstractions/ssl_certs>

  # Acceso de red
  network inet stream,
  network inet dgram,
  network inet6 stream,
  network inet6 dgram,

  # Lectura de configuración
  /etc/curlrc r,
  @{HOME}/.curlrc r,

  # Certificados
  /etc/ssl/** r,
  /etc/pki/** r,

  # Escritura solo en directorios de descarga
  @{HOME}/Descargas/** rw,
  @{HOME}/Downloads/** rw,
  /tmp/** rw,

  # Denegar acceso a archivos sensibles
  deny /etc/shadow r,
  deny /etc/gshadow r,
  deny @{HOME}/.ssh/** r,
  deny @{HOME}/.gnupg/** r,
}
EOF
            apparmor_parser -r /etc/apparmor.d/usr.bin.curl 2>/dev/null || true
            log_info "Perfil AppArmor para curl creado (enforce)"
        fi

        # Perfil para wget
        if [[ -x /usr/bin/wget ]] && [[ ! -f /etc/apparmor.d/usr.bin.wget ]]; then
            cat > /etc/apparmor.d/usr.bin.wget << 'EOF'
#include <tunables/global>

/usr/bin/wget {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/openssl>
  #include <abstractions/ssl_certs>

  # Acceso de red
  network inet stream,
  network inet dgram,
  network inet6 stream,
  network inet6 dgram,

  # Lectura de configuración
  /etc/wgetrc r,
  @{HOME}/.wgetrc r,

  # Certificados
  /etc/ssl/** r,
  /etc/pki/** r,

  # Escritura solo en directorios de descarga
  @{HOME}/Descargas/** rw,
  @{HOME}/Downloads/** rw,
  /tmp/** rw,

  # Denegar acceso sensible
  deny /etc/shadow r,
  deny /etc/gshadow r,
  deny @{HOME}/.ssh/** r,
  deny @{HOME}/.gnupg/** r,
}
EOF
            apparmor_parser -r /etc/apparmor.d/usr.bin.wget 2>/dev/null || true
            log_info "Perfil AppArmor para wget creado (enforce)"
        fi
    fi

    # Verificar parámetros de kernel para AppArmor
    if [[ -f /etc/default/grub ]]; then
        GRUB_LINE=$(grep "^GRUB_CMDLINE_LINUX_DEFAULT" /etc/default/grub 2>/dev/null || true)
        if ! echo "$GRUB_LINE" | grep -q "apparmor=1"; then
            log_warn "Parámetro 'apparmor=1' NO encontrado en GRUB"
            if ask "¿Agregar 'apparmor=1 security=apparmor' a GRUB?"; then
                cp /etc/default/grub "$BACKUP_DIR/"
                if grep -q "^GRUB_CMDLINE_LINUX_DEFAULT=" /etc/default/grub; then
                    sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 apparmor=1 security=apparmor"/' /etc/default/grub
                else
                    echo 'GRUB_CMDLINE_LINUX_DEFAULT="apparmor=1 security=apparmor"' >> /etc/default/grub
                fi
                grub_regenerate
                log_info "Parámetros de AppArmor agregados a GRUB"
                log_warn "Se requiere reiniciar para activar AppArmor en el kernel"
            fi
        else
            echo -e "  ${GREEN}OK${NC} AppArmor ya configurado en parámetros de GRUB"
        fi
    fi
fi

# ============================================================
log_section "2. RESTRINGIR BASH A USUARIOS AUTORIZADOS (T1059.004 - M1038)"
# ============================================================

echo "Solo los usuarios autorizados deberían tener acceso a bash."
echo "Las cuentas de sistema deben usar /sbin/nologin."
echo ""

# Auditar cuentas actuales con bash
echo -e "${BOLD}Cuentas con shell interactivo:${NC}"
BASH_COUNT=0
while IFS=: read -r user _ uid _ _ _ shell; do
    if [[ "$shell" == */bash || "$shell" == */sh || "$shell" == */zsh || "$shell" == */fish ]]; then
        if [[ "$uid" -ge 1000 || "$uid" -eq 0 ]]; then
            echo -e "  ${GREEN}●${NC} $user (UID=$uid) → $shell ${DIM}[usuario regular]${NC}"
        else
            echo -e "  ${RED}●${NC} $user (UID=$uid) → $shell ${DIM}[cuenta de sistema!]${NC}"
        fi
        BASH_COUNT=$((BASH_COUNT + 1))
    fi
done < /etc/passwd
echo -e "  ${DIM}Total con shell: $BASH_COUNT${NC}"
echo ""

# Asegurar que cuentas de sistema no tengan bash
SYSTEM_WITH_BASH=0
while IFS=: read -r user _ uid _ _ _ shell; do
    if [[ "$uid" -ge 1 && "$uid" -lt 1000 ]] && [[ "$shell" == */bash || "$shell" == */sh || "$shell" == */zsh ]]; then
        SYSTEM_WITH_BASH=$((SYSTEM_WITH_BASH + 1))
    fi
done < /etc/passwd

if [[ $SYSTEM_WITH_BASH -gt 0 ]]; then
    log_warn "$SYSTEM_WITH_BASH cuenta(s) de sistema con shell interactivo"
    if ask "¿Cambiar shell de cuentas de sistema a /sbin/nologin?"; then
        while IFS=: read -r user _ uid _ _ _ shell; do
            if [[ "$uid" -ge 1 && "$uid" -lt 1000 ]] && [[ "$shell" == */bash || "$shell" == */sh || "$shell" == */zsh ]]; then
                usermod -s /sbin/nologin "$user" 2>/dev/null || true
                log_info "Shell cambiado a nologin: $user (UID=$uid)"
            fi
        done < /etc/passwd
    fi
else
    echo -e "  ${GREEN}OK${NC} Ninguna cuenta de sistema tiene shell interactivo"
fi

echo ""

# Restringir acceso al binario bash por grupo
echo -e "${BOLD}Restricción del binario bash por grupo:${NC}"
echo -e "  ${DIM}Cambia permisos de /bin/bash a 750 con grupo 'shell-users'.${NC}"
echo -e "  ${DIM}Solo root y miembros de 'shell-users' podrán ejecutar bash.${NC}"
echo -e "  ${DIM}Se añadirán automáticamente: root, $CURRENT_USER y usuarios con UID>=1000${NC}"
echo ""

if ask "¿Restringir acceso a /bin/bash mediante grupo 'shell-users'?"; then
    # Crear grupo si no existe
    if ! getent group shell-users &>/dev/null; then
        groupadd shell-users
        log_info "Grupo 'shell-users' creado"
    fi

    # Añadir root y usuario actual al grupo
    usermod -aG shell-users root 2>/dev/null || true
    if [[ -n "$CURRENT_USER" && "$CURRENT_USER" != "root" ]]; then
        usermod -aG shell-users "$CURRENT_USER" 2>/dev/null || true
        log_info "$CURRENT_USER añadido al grupo shell-users"
    fi

    # Añadir todos los usuarios humanos (UID >= 1000) que tengan bash
    while IFS=: read -r user _ uid _ _ _ shell; do
        if [[ "$uid" -ge 1000 ]] && [[ "$shell" == */bash || "$shell" == */zsh ]]; then
            usermod -aG shell-users "$user" 2>/dev/null || true
        fi
    done < /etc/passwd

    # Backup y restringir
    BASH_PATH=$(command -v bash)
    stat -c "%a %U %G %n" "$BASH_PATH" > "$BACKUP_DIR/bash-permisos-originales.txt"

    chgrp shell-users "$BASH_PATH"
    chmod 750 "$BASH_PATH"
    log_info "/bin/bash restringido al grupo shell-users (750)"

    # Si /bin/sh es symlink a bash, advertir
    if [[ -L /bin/sh ]]; then
        SH_TARGET=$(readlink -f /bin/sh)
        if [[ "$SH_TARGET" == "$(readlink -f "$BASH_PATH")" ]]; then
            log_warn "/bin/sh apunta a bash - también estará restringido"
        fi
    fi

    log_warn "Para añadir usuarios: usermod -aG shell-users USUARIO"
fi

# ============================================================
log_section "3. NOEXEC EN MONTAJES TEMPORALES (T1204 - M1038)"
# ============================================================

echo "Impedir ejecución de binarios en /tmp, /var/tmp y /dev/shm"
echo "previene que atacantes ejecuten payloads descargados."
echo ""

# Verificar estado actual de montajes
echo -e "${BOLD}Estado actual de montajes temporales:${NC}"
for mp in /tmp /var/tmp /dev/shm; do
    if mountpoint -q "$mp" 2>/dev/null; then
        MOUNT_OPTS=$(mount | grep " on $mp " | sed 's/.*(\(.*\))/\1/')
        HAS_NOEXEC="no"
        HAS_NOSUID="no"
        HAS_NODEV="no"
        echo "$MOUNT_OPTS" | grep -q "noexec" && HAS_NOEXEC="si"
        echo "$MOUNT_OPTS" | grep -q "nosuid" && HAS_NOSUID="si"
        echo "$MOUNT_OPTS" | grep -q "nodev" && HAS_NODEV="si"

        if [[ "$HAS_NOEXEC" == "si" && "$HAS_NOSUID" == "si" && "$HAS_NODEV" == "si" ]]; then
            echo -e "  ${GREEN}OK${NC} $mp → noexec,nosuid,nodev"
        else
            MISSING=""
            [[ "$HAS_NOEXEC" == "no" ]] && MISSING+="noexec "
            [[ "$HAS_NOSUID" == "no" ]] && MISSING+="nosuid "
            [[ "$HAS_NODEV" == "no" ]] && MISSING+="nodev "
            echo -e "  ${YELLOW}!!${NC} $mp → falta: $MISSING"
        fi
    else
        echo -e "  ${YELLOW}!!${NC} $mp → no es un punto de montaje separado"
    fi
done
echo ""

if ask "¿Configurar noexec,nosuid,nodev en montajes temporales?"; then
    cp /etc/fstab "$BACKUP_DIR/fstab.backup"

    # --- /tmp ---
    if grep -qE "^\s*[^#].*\s+/tmp\s+" /etc/fstab; then
        # Existe entrada para /tmp - verificar y modificar opciones
        if ! grep -E "^\s*[^#].*\s+/tmp\s+" /etc/fstab | grep -q "noexec"; then
            sed -i '/^\s*[^#].*\s\+\/tmp\s/ s/defaults/defaults,noexec,nosuid,nodev/' /etc/fstab
            log_info "/tmp: opciones noexec,nosuid,nodev añadidas a fstab"
        else
            echo -e "  ${GREEN}OK${NC} /tmp ya tiene noexec en fstab"
        fi
    else
        # No hay entrada - crear tmpfs para /tmp
        echo "" >> /etc/fstab
        echo "# TA0002/T1204 - Prevenir ejecución en /tmp" >> /etc/fstab
        echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,size=2G 0 0" >> /etc/fstab
        log_info "/tmp: montaje tmpfs con noexec,nosuid,nodev añadido"
    fi

    # --- /var/tmp ---
    if grep -qE "^\s*[^#].*\s+/var/tmp\s+" /etc/fstab; then
        if ! grep -E "^\s*[^#].*\s+/var/tmp\s+" /etc/fstab | grep -q "noexec"; then
            sed -i '/^\s*[^#].*\s\+\/var\/tmp\s/ s/defaults/defaults,noexec,nosuid,nodev/' /etc/fstab
            log_info "/var/tmp: opciones noexec,nosuid,nodev añadidas"
        else
            echo -e "  ${GREEN}OK${NC} /var/tmp ya tiene noexec en fstab"
        fi
    else
        echo "# TA0002/T1204 - Prevenir ejecución en /var/tmp" >> /etc/fstab
        echo "tmpfs /var/tmp tmpfs defaults,noexec,nosuid,nodev,size=1G 0 0" >> /etc/fstab
        log_info "/var/tmp: montaje tmpfs con noexec,nosuid,nodev añadido"
    fi

    # --- /dev/shm ---
    if grep -qE "^\s*[^#].*\s+/dev/shm\s+" /etc/fstab; then
        if ! grep -E "^\s*[^#].*\s+/dev/shm\s+" /etc/fstab | grep -q "noexec"; then
            sed -i '/^\s*[^#].*\s\+\/dev\/shm\s/ s/defaults/defaults,noexec,nosuid,nodev/' /etc/fstab
            log_info "/dev/shm: opciones noexec,nosuid,nodev añadidas"
        else
            echo -e "  ${GREEN}OK${NC} /dev/shm ya tiene noexec en fstab"
        fi
    else
        echo "# TA0002/T1204 - Prevenir ejecución en /dev/shm" >> /etc/fstab
        echo "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
        log_info "/dev/shm: montaje tmpfs con noexec,nosuid,nodev añadido"
    fi

    # Remontar sin reiniciar
    echo ""
    if ask "¿Remontar ahora los puntos de montaje? (sin reiniciar)"; then
        for mp in /tmp /var/tmp /dev/shm; do
            if mountpoint -q "$mp" 2>/dev/null; then
                mount -o remount "$mp" 2>/dev/null && \
                    log_info "$mp remontado con nuevas opciones" || \
                    log_warn "$mp: no se pudo remontar (se aplicará al reiniciar)"
            else
                mount "$mp" 2>/dev/null && \
                    log_info "$mp montado con nuevas opciones" || \
                    log_warn "$mp: se aplicará al reiniciar"
            fi
        done
    else
        log_warn "Los cambios se aplicarán al próximo reinicio"
    fi

    # Verificar resultado
    echo ""
    echo -e "${BOLD}Estado tras configuración:${NC}"
    for mp in /tmp /var/tmp /dev/shm; do
        if mountpoint -q "$mp" 2>/dev/null; then
            MOUNT_OPTS=$(mount | grep " on $mp " | sed 's/.*(\(.*\))/\1/')
            if echo "$MOUNT_OPTS" | grep -q "noexec"; then
                echo -e "  ${GREEN}OK${NC} $mp → noexec activo"
            else
                echo -e "  ${YELLOW}!!${NC} $mp → noexec pendiente (reiniciar)"
            fi
        fi
    done
fi

# ============================================================
log_section "4. RESTRINGIR LD_PRELOAD Y LD_LIBRARY_PATH (T1129 - M1044)"
# ============================================================

echo "LD_PRELOAD y LD_LIBRARY_PATH permiten inyectar bibliotecas"
echo "compartidas en procesos. Restringirlos previene hijacking."
echo ""

# Verificar estado actual
echo -e "${BOLD}Estado actual:${NC}"
if [[ -f /etc/ld.so.preload ]]; then
    PRELOAD_CONTENT=$(grep -v "^#" /etc/ld.so.preload 2>/dev/null | grep -v "^$" || true)
    if [[ -n "$PRELOAD_CONTENT" ]]; then
        echo -e "  ${YELLOW}!!${NC} /etc/ld.so.preload contiene entradas:"
        echo "$PRELOAD_CONTENT" | sed 's/^/      /'
    else
        echo -e "  ${GREEN}OK${NC} /etc/ld.so.preload vacío o solo comentarios"
    fi
else
    echo -e "  ${GREEN}OK${NC} /etc/ld.so.preload no existe"
fi

if [[ -f /etc/profile.d/restrict-ld-env.sh ]]; then
    echo -e "  ${GREEN}OK${NC} Restricción LD_PRELOAD ya configurada en profile.d"
else
    echo -e "  ${YELLOW}!!${NC} Sin restricción de LD_PRELOAD en profile.d"
fi
echo ""

if ask "¿Aplicar restricciones sobre LD_PRELOAD y LD_LIBRARY_PATH?"; then
    # 1. Proteger /etc/ld.so.preload
    if [[ ! -f /etc/ld.so.preload ]]; then
        touch /etc/ld.so.preload
    fi
    chmod 644 /etc/ld.so.preload
    chown root:root /etc/ld.so.preload
    log_info "/etc/ld.so.preload permisos asegurados (644, root:root)"

    # 2. Script en profile.d para limpiar variables de carga
    cat > /etc/profile.d/restrict-ld-env.sh << 'EOF'
# ============================================================
# RESTRICCIÓN LD_PRELOAD / LD_LIBRARY_PATH - T1129 (TA0002)
# Prevenir library injection para usuarios no privilegiados
# ============================================================
if [ "$(id -u)" -ne 0 ]; then
    unset LD_PRELOAD 2>/dev/null
    unset LD_LIBRARY_PATH 2>/dev/null
    unset LD_AUDIT 2>/dev/null
    unset LD_PROFILE 2>/dev/null
    unset LD_SHOW_AUXV 2>/dev/null
    unset LD_DEBUG 2>/dev/null
    unset LD_DYNAMIC_WEAK 2>/dev/null
    readonly LD_PRELOAD 2>/dev/null || true
    readonly LD_LIBRARY_PATH 2>/dev/null || true
    readonly LD_AUDIT 2>/dev/null || true
fi
EOF
    chmod 644 /etc/profile.d/restrict-ld-env.sh
    log_info "Script /etc/profile.d/restrict-ld-env.sh creado"

    # 3. Reglas de auditoría para detectar uso de LD_PRELOAD
    if [[ -d /etc/audit/rules.d ]]; then
        if ! grep -rq "ld_preload" /etc/audit/rules.d/ 2>/dev/null; then
            cat > /etc/audit/rules.d/98-ld-preload.rules << 'EOF'
# Auditar inyección de bibliotecas - T1129 (TA0002)
-w /etc/ld.so.preload -p wa -k ld_preload_modify
-w /etc/ld.so.conf -p wa -k ld_config_modify
-w /etc/ld.so.conf.d/ -p wa -k ld_config_modify
-w /sbin/ldconfig -p x -k ldconfig_exec
EOF
            augenrules --load 2>/dev/null || service auditd restart 2>/dev/null || true
            log_info "Reglas de auditoría para LD_PRELOAD configuradas"
        else
            echo -e "  ${GREEN}OK${NC} Reglas de auditoría para LD_PRELOAD ya existen"
        fi
    fi

    # 4. Verificar permisos de directorios de bibliotecas
    echo ""
    echo -e "${BOLD}Verificando permisos de directorios de bibliotecas:${NC}"
    for libdir in /lib64 /usr/lib64 /lib /usr/lib /usr/local/lib64 /usr/local/lib; do
        if [[ -d "$libdir" ]]; then
            OWNER=$(stat -c "%U" "$libdir" 2>/dev/null)
            PERMS=$(stat -c "%a" "$libdir" 2>/dev/null)
            if [[ "$OWNER" == "root" ]]; then
                echo -e "  ${GREEN}OK${NC} $libdir (owner: $OWNER, perms: $PERMS)"
            else
                echo -e "  ${RED}!!${NC} $libdir (owner: $OWNER - debería ser root!)"
                chown root:root "$libdir" 2>/dev/null || true
            fi
        fi
    done

    # 5. Asegurar permisos de ld.so.conf.d
    chmod 755 /etc/ld.so.conf.d/ 2>/dev/null || true
    chown root:root /etc/ld.so.conf.d/ 2>/dev/null || true
    for conf_file in /etc/ld.so.conf.d/*.conf; do
        [[ -f "$conf_file" ]] || continue
        chmod 644 "$conf_file" 2>/dev/null || true
        chown root:root "$conf_file" 2>/dev/null || true
    done
    log_info "Permisos de /etc/ld.so.conf.d/ asegurados"
fi

# ============================================================
log_section "5. RESTRINGIR INTÉRPRETES A USUARIOS ESPECÍFICOS (T1059 - M1038)"
# ============================================================

echo "Restringir acceso a intérpretes (Python, Perl, Ruby) previene"
echo "la ejecución de scripts maliciosos por usuarios no autorizados."
echo ""

# Detectar intérpretes instalados
echo -e "${BOLD}Intérpretes detectados en el sistema:${NC}"
INTERP_LIST=()
for interp in python3 python perl ruby lua; do
    INTERP_PATH=$(command -v "$interp" 2>/dev/null || true)
    if [[ -n "$INTERP_PATH" ]]; then
        INTERP_PERMS=$(stat -c "%a %U:%G" "$INTERP_PATH" 2>/dev/null)
        echo -e "  ${YELLOW}●${NC} $interp → $INTERP_PATH ($INTERP_PERMS)"
        INTERP_LIST+=("$INTERP_PATH")
    fi
done

if [[ ${#INTERP_LIST[@]} -eq 0 ]]; then
    echo -e "  ${GREEN}OK${NC} No se detectaron intérpretes adicionales"
else
    echo ""
    echo -e "  ${DIM}Se creará un grupo 'interp-users' con acceso a los intérpretes.${NC}"
    echo -e "  ${DIM}Se añadirá automáticamente a: root, $CURRENT_USER${NC}"
    echo ""

    if ask "¿Restringir intérpretes al grupo 'interp-users'?"; then
        # Crear grupo si no existe
        if ! getent group interp-users &>/dev/null; then
            groupadd interp-users
            log_info "Grupo 'interp-users' creado"
        fi

        # Añadir root y usuario actual
        usermod -aG interp-users root 2>/dev/null || true
        if [[ -n "$CURRENT_USER" && "$CURRENT_USER" != "root" ]]; then
            usermod -aG interp-users "$CURRENT_USER" 2>/dev/null || true
            log_info "$CURRENT_USER añadido al grupo interp-users"
        fi

        for interp_path in "${INTERP_LIST[@]}"; do
            # Backup permisos originales
            stat -c "%a %U %G %n" "$interp_path" >> "$BACKUP_DIR/interpreters-permisos-originales.txt"

            chgrp interp-users "$interp_path" 2>/dev/null || true
            chmod 750 "$interp_path" 2>/dev/null || true
            log_info "Restringido: $interp_path (750, grupo: interp-users)"
        done

        log_warn "Para dar acceso a otro usuario: usermod -aG interp-users USUARIO"
    fi
fi

# ============================================================
log_section "6. SCRIPT DE MONITOREO DE EJECUCIÓN SOSPECHOSA"
# ============================================================

echo "Script auxiliar para detectar ejecución anómala de procesos."
echo ""

if ask "¿Crear script de monitoreo de ejecución sospechosa?"; then
    cat > /usr/local/bin/monitor-ejecucion.sh << 'EXECEOF'
#!/bin/bash
# ============================================================
# MONITOR DE EJECUCIÓN SOSPECHOSA - T1059 (TA0002)
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MONITOR DE EJECUCIÓN - TA0002                          ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# 1. Procesos ejecutando intérpretes
echo -e "${BOLD}[1] Procesos con intérpretes activos:${NC}"
for interp in bash sh python python3 perl ruby lua; do
    PIDS=$(pgrep -x "$interp" 2>/dev/null || true)
    if [[ -n "$PIDS" ]]; then
        COUNT=$(echo "$PIDS" | wc -l)
        echo -e "  ${YELLOW}●${NC} $interp: $COUNT proceso(s)"
        for pid in $PIDS; do
            USER=$(ps -o user= -p "$pid" 2>/dev/null || echo "?")
            CMD=$(ps -o args= -p "$pid" 2>/dev/null | head -c 80 || echo "?")
            echo -e "    PID=$pid  USER=$USER  CMD=$CMD"
        done
    fi
done

# 2. Procesos ejecutando desde /tmp, /var/tmp, /dev/shm
echo ""
echo -e "${BOLD}[2] Procesos ejecutando desde directorios temporales:${NC}"
SUSPICIOUS=0
for proc_dir in /proc/[0-9]*/exe; do
    [[ -L "$proc_dir" ]] || continue
    TARGET=$(readlink -f "$proc_dir" 2>/dev/null || true)
    if echo "$TARGET" | grep -qE "^/(tmp|var/tmp|dev/shm)/"; then
        PID=$(echo "$proc_dir" | cut -d/ -f3)
        USER=$(ps -o user= -p "$PID" 2>/dev/null || echo "?")
        echo -e "  ${RED}●${NC} PID=$PID USER=$USER EXE=$TARGET"
        SUSPICIOUS=$((SUSPICIOUS + 1))
    fi
done
[[ $SUSPICIOUS -eq 0 ]] && echo -e "  ${GREEN}OK${NC} Ninguno detectado"

# 3. Archivos ejecutables en /tmp, /var/tmp, /dev/shm
echo ""
echo -e "${BOLD}[3] Ejecutables en directorios temporales:${NC}"
for dir in /tmp /var/tmp /dev/shm; do
    [[ -d "$dir" ]] || continue
    EXECS=$(find "$dir" -maxdepth 3 -type f -executable 2>/dev/null | head -20)
    if [[ -n "$EXECS" ]]; then
        echo -e "  ${RED}Ejecutables en $dir:${NC}"
        echo "$EXECS" | while read -r f; do
            FILE_TYPE=$(file -b "$f" 2>/dev/null | head -c 50)
            echo -e "    ${RED}●${NC} $f ($FILE_TYPE)"
        done
    else
        echo -e "  ${GREEN}OK${NC} $dir: sin ejecutables"
    fi
done

# 4. Verificar LD_PRELOAD en procesos
echo ""
echo -e "${BOLD}[4] Procesos con LD_PRELOAD activo:${NC}"
LD_FOUND=0
for proc_env in /proc/[0-9]*/environ; do
    [[ -r "$proc_env" ]] || continue
    if tr '\0' '\n' < "$proc_env" 2>/dev/null | grep -q "^LD_PRELOAD="; then
        PID=$(echo "$proc_env" | cut -d/ -f3)
        USER=$(ps -o user= -p "$PID" 2>/dev/null || echo "?")
        CMD=$(ps -o comm= -p "$PID" 2>/dev/null || echo "?")
        LD_VAL=$(tr '\0' '\n' < "$proc_env" 2>/dev/null | grep "^LD_PRELOAD=" | head -1)
        echo -e "  ${RED}●${NC} PID=$PID USER=$USER CMD=$CMD $LD_VAL"
        LD_FOUND=$((LD_FOUND + 1))
    fi
done
[[ $LD_FOUND -eq 0 ]] && echo -e "  ${GREEN}OK${NC} Ningún proceso con LD_PRELOAD"

# 5. Estado de AppArmor
echo ""
echo -e "${BOLD}[5] Estado de AppArmor:${NC}"
if command -v aa-status &>/dev/null; then
    if aa-status --enabled 2>/dev/null; then
        ENFORCED=$(aa-status 2>/dev/null | grep "profiles are in enforce mode" | awk '{print $1}')
        UNCONFINED=$(aa-status 2>/dev/null | grep "processes are unconfined" | awk '{print $1}')
        echo -e "  ${GREEN}OK${NC} AppArmor activo (enforce: $ENFORCED, no confinados: $UNCONFINED)"
    else
        echo -e "  ${RED}!!${NC} AppArmor NO activo"
    fi
else
    echo -e "  ${YELLOW}!!${NC} AppArmor no instalado"
fi

# 6. Estado de noexec en montajes
echo ""
echo -e "${BOLD}[6] Protección noexec en montajes temporales:${NC}"
for mp in /tmp /var/tmp /dev/shm; do
    if mountpoint -q "$mp" 2>/dev/null; then
        MOUNT_OPTS=$(mount | grep " on $mp " | sed 's/.*(\(.*\))/\1/')
        if echo "$MOUNT_OPTS" | grep -q "noexec"; then
            echo -e "  ${GREEN}OK${NC} $mp → noexec"
        else
            echo -e "  ${RED}!!${NC} $mp → SIN noexec"
        fi
    else
        echo -e "  ${YELLOW}!!${NC} $mp → no es punto de montaje separado"
    fi
done

# 7. Verificar cron jobs sospechosos
echo ""
echo -e "${BOLD}[7] Cron jobs de usuarios no-root:${NC}"
CRON_FOUND=0
if [[ -d /var/spool/cron/tabs ]]; then
    for crontab_file in /var/spool/cron/tabs/*; do
        [[ -f "$crontab_file" ]] || continue
        CRON_USER=$(basename "$crontab_file")
        [[ "$CRON_USER" == "root" ]] && continue
        LINES=$(grep -c "^[^#]" "$crontab_file" 2>/dev/null || echo 0)
        if [[ "$LINES" -gt 0 ]]; then
            echo -e "  ${YELLOW}●${NC} $CRON_USER tiene $LINES cron job(s)"
            CRON_FOUND=$((CRON_FOUND + 1))
        fi
    done
fi
[[ $CRON_FOUND -eq 0 ]] && echo -e "  ${GREEN}OK${NC} Sin cron jobs de usuarios no-root"

echo ""
echo -e "${DIM}Fecha del análisis: $(date)${NC}"
EXECEOF

    chmod +x /usr/local/bin/monitor-ejecucion.sh
    log_info "Script creado: /usr/local/bin/monitor-ejecucion.sh"
    log_info "Ejecutar con: sudo /usr/local/bin/monitor-ejecucion.sh"
fi

# ============================================================
log_section "7. VERIFICACIÓN DE CONTROLES EXISTENTES"
# ============================================================

echo "Verificando controles de ejecución ya implementados..."
echo ""

# T1059 M1026 - sudo fortalecido, requiretty
echo -e "${BOLD}[T1059 M1026] Sudo fortalecido:${NC}"
if [[ -f /etc/sudoers ]]; then
    if grep -qE "^\s*Defaults\s+.*requiretty" /etc/sudoers 2>/dev/null || \
       grep -rqE "^\s*Defaults\s+.*requiretty" /etc/sudoers.d/ 2>/dev/null; then
        echo -e "  ${GREEN}OK${NC} requiretty configurado en sudoers"
    else
        echo -e "  ${YELLOW}!!${NC} requiretty NO configurado en sudoers"
    fi
fi

# T1053 M1018 - cron.allow
echo ""
echo -e "${BOLD}[T1053 M1018] Restricción de cron:${NC}"
if [[ -f /etc/cron.allow ]]; then
    CRON_USERS=$(wc -l < /etc/cron.allow 2>/dev/null)
    echo -e "  ${GREEN}OK${NC} cron.allow presente ($CRON_USERS usuario(s) autorizados)"
else
    echo -e "  ${YELLOW}!!${NC} cron.allow NO existe (cualquier usuario puede usar cron)"
fi

# T1053 M1047 - Auditoría de cron
echo ""
echo -e "${BOLD}[T1053 M1047] Auditoría de cron:${NC}"
if grep -rq "cron" /etc/audit/rules.d/ 2>/dev/null; then
    echo -e "  ${GREEN}OK${NC} Reglas de auditoría para cron configuradas"
else
    echo -e "  ${YELLOW}!!${NC} Sin reglas de auditoría para cron"
fi

# T1203 M1050 - ASLR y kptr_restrict
echo ""
echo -e "${BOLD}[T1203 M1050] Protección contra exploits:${NC}"
ASLR=$(sysctl -n kernel.randomize_va_space 2>/dev/null || echo "?")
KPTR=$(sysctl -n kernel.kptr_restrict 2>/dev/null || echo "?")
if [[ "$ASLR" == "2" ]]; then
    echo -e "  ${GREEN}OK${NC} ASLR activo (kernel.randomize_va_space = $ASLR)"
else
    echo -e "  ${YELLOW}!!${NC} ASLR: kernel.randomize_va_space = $ASLR (esperado: 2)"
fi
if [[ "$KPTR" -ge 1 ]] 2>/dev/null; then
    echo -e "  ${GREEN}OK${NC} kptr_restrict = $KPTR"
else
    echo -e "  ${YELLOW}!!${NC} kptr_restrict = $KPTR (esperado: >= 1)"
fi

# T1569 M1026 - Servicios innecesarios
echo ""
echo -e "${BOLD}[T1569 M1026] Servicios innecesarios deshabilitados:${NC}"
for svc in cups avahi-daemon bluetooth ModemManager; do
    if systemctl is-active "$svc" &>/dev/null; then
        echo -e "  ${YELLOW}!!${NC} $svc aún activo"
    else
        echo -e "  ${GREEN}OK${NC} $svc inactivo"
    fi
done

# ============================================================
# RESUMEN
# ============================================================
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║    MITIGACIÓN DE EJECUCIÓN COMPLETADA (TA0002)            ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "Controles aplicados:"
echo "  T1059     AppArmor perfiles restrictivos  → M1038 Execution Prevention"
echo "  T1059.004 Bash restringido a grupo        → M1038 Execution Prevention"
echo "  T1204     noexec en /tmp,/var/tmp,/dev/shm → M1038 Execution Prevention"
echo "  T1129     LD_PRELOAD restringido           → M1044 Restrict Library Loading"
echo "  T1059     Intérpretes restringidos          → M1038 Execution Prevention"
echo ""
echo "Controles verificados (implementados en otros módulos):"
echo "  T1059     sudo fortalecido, requiretty     → M1026 Privileged Account Mgmt"
echo "  T1053     cron.allow, auditoría de cron    → M1018/M1047"
echo "  T1203     ASLR, kptr_restrict              → M1050 Exploit Protection"
echo "  T1569     Servicios innecesarios           → M1026 Privileged Account Mgmt"
echo ""
echo "Scripts auxiliares:"
echo "  /usr/local/bin/monitor-ejecucion.sh"
echo ""
echo "Grupos de control creados:"
echo "  shell-users   → Acceso a /bin/bash"
echo "  interp-users  → Acceso a intérpretes (python, perl, ruby...)"
echo ""
log_info "Backups en: $BACKUP_DIR"
