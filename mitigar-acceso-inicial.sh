#!/bin/bash
# ============================================================
# MITIGACIÓN DE ACCESO INICIAL - TA0001 (Initial Access)
# Linux Multi-Distro (openSUSE, Debian/Ubuntu, RHEL/Fedora, Arch)
# ============================================================
# Técnicas MITRE ATT&CK cubiertas:
#   T1190 - Exploit Public-Facing Application
#   T1133 - External Remote Services
#   T1078 - Valid Accounts
#   T1566 - Phishing
#   T1189 - Drive-by Compromise
#   T1195 - Supply Chain Compromise
#   T1200 - Hardware Additions
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "mitigar-acceso-inicial"
securizar_setup_traps
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MITIGACIÓN DE ACCESO INICIAL - TA0001                   ║"
echo "║   Prevenir vectores de entrada del atacante                ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# ============================================================
log_section "1. HARDENING SSH AVANZADO (T1133 External Remote Services)"
# ============================================================

echo "Verificando configuración SSH actual..."
echo ""

if [[ -f /etc/ssh/sshd_config ]]; then
    cp /etc/ssh/sshd_config "$BACKUP_DIR/"
    echo "Configuración actual relevante:"
    grep -E "^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|MaxAuthTries|X11Forwarding|AllowTcpForwarding|ClientAliveInterval|LoginGraceTime|Protocol|PermitEmptyPasswords|AllowAgentForwarding)" /etc/ssh/sshd_config 2>/dev/null | sed 's/^/  /' || echo "  (valores por defecto)"
    echo ""

    if ask "¿Aplicar hardening SSH avanzado contra acceso inicial?"; then
        # Crear directorio de configuración modular
        mkdir -p /etc/ssh/sshd_config.d

        # Detectar conflictos con otros drop-ins de securizar
        for _sshd_dropin in /etc/ssh/sshd_config.d/*-hardening*.conf; do
            [[ -f "$_sshd_dropin" ]] || continue
            if grep -q "PasswordAuthentication yes" "$_sshd_dropin" 2>/dev/null; then
                log_warn "Conflicto: $_sshd_dropin tiene PasswordAuthentication yes"
                log_warn "  Este script configura PasswordAuthentication no (solo llaves)"
                log_warn "  El archivo con numero mayor prevalece en sshd"
            fi
        done
        unset _sshd_dropin

        cat > /etc/ssh/sshd_config.d/80-acceso-inicial.conf << 'EOF'
# ============================================================
# HARDENING SSH - Mitigación TA0001 (Initial Access)
# ============================================================

# T1133 - Restringir servicios remotos
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no

# Limitar intentos de autenticación
MaxAuthTries 3
LoginGraceTime 30

# Deshabilitar funciones innecesarias
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitUserEnvironment no
PermitTunnel no
GatewayPorts no

# Timeouts de sesión
ClientAliveInterval 300
ClientAliveCountMax 2

# Solo protocolo 2
Protocol 2

# Algoritmos seguros (eliminar débiles)
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# Logging completo
LogLevel VERBOSE

# Deshabilitar autenticación basada en host
HostbasedAuthentication no
IgnoreRhosts yes

# Limitar usuarios (descomentar y ajustar)
# AllowUsers usuario1 usuario2
# AllowGroups wheel
EOF

        # Verificar que la config incluye el directorio
        if ! grep -q "^Include /etc/ssh/sshd_config.d/" /etc/ssh/sshd_config 2>/dev/null; then
            # Insertar al inicio del archivo
            sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
        fi

        # Verificar sintaxis antes de recargar
        if sshd -t 2>/dev/null; then
            systemctl reload "$SSH_SERVICE_NAME" 2>/dev/null || true
            log_info "SSH hardening aplicado (config modular en sshd_config.d/)"
        else
            log_error "Error de sintaxis en configuración SSH - revirtiendo"
            rm -f /etc/ssh/sshd_config.d/80-acceso-inicial.conf
        fi
    fi
else
    log_warn "No se encontró /etc/ssh/sshd_config"
fi

# ============================================================
log_section "2. PROTECCIÓN CONTRA EXPLOITS WEB (T1190)"
# ============================================================

echo "Verificando aplicaciones web expuestas..."
echo ""

WEB_PORTS=$(ss -tlnp 2>/dev/null | grep -E ':(80|443|8080|8443|3000|5000|8000|9000)\b' | grep -v "127.0.0.1" || true)

if [[ -n "$WEB_PORTS" ]]; then
    echo -e "${YELLOW}Servicios web detectados:${NC}"
    echo "$WEB_PORTS" | while IFS= read -r line; do
        echo "  $line"
    done
    echo ""

    if ask "¿Aplicar protecciones contra exploits de aplicaciones web?"; then
        # Módulos de seguridad del kernel para proteger contra exploits
        cat > /etc/sysctl.d/99-anti-exploit-web.conf << 'EOF'
# ============================================================
# ANTI-EXPLOIT WEB - T1190
# ============================================================

# Proteger contra buffer overflow
kernel.randomize_va_space = 2

# Proteger enlaces simbólicos/duros
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# Limitar mapeo de memoria
vm.mmap_min_addr = 65536

# Deshabilitar SysRq (prevenir manipulación de kernel)
kernel.sysrq = 0

# Prevenir core dumps (evitar fuga de datos sensibles)
fs.suid_dumpable = 0
EOF

        /usr/sbin/sysctl --system > /dev/null 2>&1
        log_info "Protecciones anti-exploit aplicadas (sysctl)"

        # Limitar core dumps
        if [[ -f /etc/security/limits.conf ]]; then
            cp /etc/security/limits.conf "$BACKUP_DIR/"
            if ! grep -q "^\* hard core 0" /etc/security/limits.conf 2>/dev/null; then
                echo "* hard core 0" >> /etc/security/limits.conf
                log_info "Core dumps deshabilitados en limits.conf"
            fi
        fi

        # Deshabilitar core dumps via systemd
        mkdir -p /etc/systemd/coredump.conf.d/
        cat > /etc/systemd/coredump.conf.d/disable.conf << 'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
        log_info "Core dumps deshabilitados via systemd"
    fi
else
    echo -e "  ${GREEN}OK${NC} No se detectan servicios web expuestos externamente"
fi

# ============================================================
log_section "3. CONTROL DE CUENTAS VÁLIDAS (T1078)"
# ============================================================

echo "Auditando cuentas del sistema..."
echo ""

# Cuentas con shell de login
echo -e "${BOLD}Cuentas con shell de login:${NC}"
SHELL_ACCOUNTS=0
while IFS=: read -r user _ uid _ _ _ shell; do
    if [[ "$shell" == */bash || "$shell" == */sh || "$shell" == */zsh || "$shell" == */fish ]]; then
        echo -e "  UID=$uid  $user  ($shell)"
        SHELL_ACCOUNTS=$((SHELL_ACCOUNTS + 1))
    fi
done < /etc/passwd
echo -e "  ${DIM}Total: $SHELL_ACCOUNTS cuentas con shell${NC}"
echo ""

# Cuentas de sistema con shell (sospechoso)
SYSTEM_SHELLS=0
while IFS=: read -r user _ uid _ _ _ shell; do
    if [[ "$uid" -ge 1 && "$uid" -lt 1000 ]] && [[ "$shell" == */bash || "$shell" == */sh || "$shell" == */zsh ]]; then
        log_warn "Cuenta de sistema con shell: $user (UID=$uid, shell=$shell)"
        SYSTEM_SHELLS=$((SYSTEM_SHELLS + 1))
    fi
done < /etc/passwd

if [[ $SYSTEM_SHELLS -gt 0 ]]; then
    if ask "¿Asignar /sbin/nologin a cuentas de sistema con shell?"; then
        while IFS=: read -r user _ uid _ _ _ shell; do
            if [[ "$uid" -ge 1 && "$uid" -lt 1000 ]] && [[ "$shell" == */bash || "$shell" == */sh || "$shell" == */zsh ]]; then
                usermod -s /sbin/nologin "$user" 2>/dev/null || true
                log_info "Shell cambiado a nologin: $user"
            fi
        done < /etc/passwd
    fi
else
    echo -e "  ${GREEN}OK${NC} No hay cuentas de sistema con shell inapropiado"
fi

echo ""

# Verificar intentos recientes de login fallidos
echo -e "${BOLD}Intentos de login fallidos recientes:${NC}"
if command -v lastb &>/dev/null; then
    FAILED_LOGINS=$(lastb -n 20 2>/dev/null | head -20 || true)
    if [[ -n "$FAILED_LOGINS" && "$FAILED_LOGINS" != *"btmp begins"* ]]; then
        echo "$FAILED_LOGINS" | sed 's/^/  /'
    else
        echo "  (ninguno registrado)"
    fi
fi

# Auditar login exitosos sospechosos
echo ""
echo -e "${BOLD}Últimos logins:${NC}"
last -n 10 2>/dev/null | head -10 | sed 's/^/  /' || echo "  (no disponible)"

# ============================================================
log_section "4. ANTI-PHISHING Y PROTECCIÓN DE EMAIL (T1566)"
# ============================================================

echo "Configurando protecciones contra phishing..."
echo ""

if ask "¿Agregar dominios de phishing conocidos al bloqueo de hosts?"; then
    cp /etc/hosts "$BACKUP_DIR/"

    # Verificar si ya existe el bloque
    if ! grep -q "ANTI-PHISHING" /etc/hosts 2>/dev/null; then
        cat >> /etc/hosts << 'EOF'

# ============================================================
# ANTI-PHISHING - T1566 (TA0001)
# ============================================================
# Dominios de phishing y distribución de malware
0.0.0.0 login-verify.com
0.0.0.0 secure-update.com
0.0.0.0 account-verify.net
0.0.0.0 security-alert.com
0.0.0.0 update-flash.com
0.0.0.0 free-download.xyz
0.0.0.0 crack-software.com
0.0.0.0 keygen-free.net

# Dominios de typosquatting comunes
0.0.0.0 g00gle.com
0.0.0.0 gooogle.com
0.0.0.0 microsofft.com
0.0.0.0 paypa1.com
0.0.0.0 arnazon.com
0.0.0.0 faceb00k.com

# Acortadores sospechosos (descomentar si se desea bloquear)
# 0.0.0.0 bit.ly
# 0.0.0.0 tinyurl.com
# 0.0.0.0 t.co
EOF
        log_info "Dominios de phishing bloqueados en /etc/hosts"
    else
        log_info "Bloqueo anti-phishing ya presente en /etc/hosts"
    fi
fi

# ============================================================
log_section "5. PROTECCIÓN CONTRA DRIVE-BY (T1189)"
# ============================================================

echo "Configurando protecciones contra descargas maliciosas..."
echo ""

if ask "¿Aplicar protecciones contra drive-by compromise?"; then
    # Restringir ejecución en directorios de descarga comunes
    # Crear script de monitoreo de descargas sospechosas
    cat > /usr/local/bin/monitor-descargas.sh << 'DLEOF'
#!/bin/bash
# Monitor de archivos sospechosos en directorios de descarga
# T1189 - Drive-by Compromise

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=== MONITOR DE DESCARGAS SOSPECHOSAS ==="
echo "Fecha: $(date)"
echo ""

# Buscar ejecutables en directorios de descarga
DOWNLOAD_DIRS=("/tmp" "/var/tmp" "/home/*/Descargas" "/home/*/Downloads" "/home/*/Desktop" "/home/*/Escritorio")

for dir_pattern in "${DOWNLOAD_DIRS[@]}"; do
    for dir in $dir_pattern; do
        [[ -d "$dir" ]] || continue
        echo -e "${YELLOW}Directorio: $dir${NC}"

        # Archivos ejecutables
        EXECS=$(find "$dir" -maxdepth 2 -type f -executable 2>/dev/null | head -20)
        if [[ -n "$EXECS" ]]; then
            echo -e "  ${RED}Ejecutables encontrados:${NC}"
            echo "$EXECS" | while read -r f; do
                FILE_TYPE=$(file -b "$f" 2>/dev/null | head -c 60)
                echo -e "    ${RED}●${NC} $f ($FILE_TYPE)"
            done
        fi

        # Scripts sospechosos
        SCRIPTS=$(find "$dir" -maxdepth 2 -type f \( -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*.rb" \) 2>/dev/null | head -20)
        if [[ -n "$SCRIPTS" ]]; then
            echo -e "  ${YELLOW}Scripts encontrados:${NC}"
            echo "$SCRIPTS" | while read -r f; do
                echo -e "    ${YELLOW}●${NC} $f"
            done
        fi

        # Archivos con extensión engañosa (doble extensión)
        DOUBLE_EXT=$(find "$dir" -maxdepth 2 -type f -regex '.*\.\(pdf\|doc\|jpg\|png\)\.\(sh\|exe\|bat\|py\|pl\)' 2>/dev/null | head -10)
        if [[ -n "$DOUBLE_EXT" ]]; then
            echo -e "  ${RED}DOBLE EXTENSIÓN (sospechoso):${NC}"
            echo "$DOUBLE_EXT" | while read -r f; do
                echo -e "    ${RED}●${NC} $f"
            done
        fi

        echo ""
    done
done
DLEOF

    chmod +x /usr/local/bin/monitor-descargas.sh
    log_info "Script creado: /usr/local/bin/monitor-descargas.sh"

    # Montar /tmp con noexec si no lo está
    if mount | grep -q "on /tmp " && ! mount | grep "on /tmp " | grep -q "noexec"; then
        log_warn "/tmp no tiene noexec - se recomienda añadir noexec,nosuid,nodev en /etc/fstab"
        echo -e "  ${DIM}Para aplicar: agregar 'noexec,nosuid,nodev' a las opciones de /tmp en /etc/fstab${NC}"
    elif mount | grep "on /tmp " | grep -q "noexec"; then
        echo -e "  ${GREEN}OK${NC} /tmp ya tiene noexec"
    fi
fi

# ============================================================
log_section "6. INTEGRIDAD DE CADENA DE SUMINISTRO (T1195)"
# ============================================================

echo "Verificando integridad de repositorios y paquetes..."
echo ""

if ask "¿Verificar y securizar la cadena de suministro de software?"; then
    # Verificar GPG de repositorios
    echo -e "${BOLD}Repositorios configurados:${NC}"
    pkg_list_repos 2>/dev/null | sed 's/^/  /' || echo "  (gestor de paquetes no disponible)"
    echo ""

    # Verificar que la verificacion de firmas esta habilitada (multi-distro)
    REPOS_WITHOUT_GPG=0
    case "$DISTRO_FAMILY" in
        suse)
            for repo_file in /etc/zypp/repos.d/*.repo; do
                [[ -f "$repo_file" ]] || continue
                repo_name=$(grep "^\[" "$repo_file" | tr -d '[]')
                gpg_check=$(grep "^gpgcheck=" "$repo_file" | cut -d= -f2)
                if [[ "$gpg_check" == "0" ]]; then
                    log_warn "Repo sin verificación GPG: $repo_name ($repo_file)"
                    REPOS_WITHOUT_GPG=$((REPOS_WITHOUT_GPG + 1))
                fi
            done
            ;;
        rhel)
            for repo_file in /etc/yum.repos.d/*.repo; do
                [[ -f "$repo_file" ]] || continue
                repo_name=$(grep "^\[" "$repo_file" | tr -d '[]')
                gpg_check=$(grep "^gpgcheck=" "$repo_file" | cut -d= -f2)
                if [[ "$gpg_check" == "0" ]]; then
                    log_warn "Repo sin verificación GPG: $repo_name ($repo_file)"
                    REPOS_WITHOUT_GPG=$((REPOS_WITHOUT_GPG + 1))
                fi
            done
            ;;
        debian)
            # Detectar repos con trusted=yes (omite verificacion de firma)
            for src_file in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
                [[ -f "$src_file" ]] || continue
                if grep -qi "trusted=yes" "$src_file" 2>/dev/null; then
                    log_warn "Repo con trusted=yes (sin GPG): $src_file"
                    REPOS_WITHOUT_GPG=$((REPOS_WITHOUT_GPG + 1))
                fi
            done
            ;;
        arch)
            # Verificar SigLevel en pacman.conf
            if grep -q "^SigLevel.*Never" /etc/pacman.conf 2>/dev/null; then
                log_warn "pacman.conf tiene SigLevel = Never (sin verificación GPG)"
                REPOS_WITHOUT_GPG=$((REPOS_WITHOUT_GPG + 1))
            fi
            ;;
    esac

    if [[ $REPOS_WITHOUT_GPG -eq 0 ]]; then
        echo -e "  ${GREEN}OK${NC} Todos los repositorios tienen GPG habilitado"
    else
        if ask "¿Habilitar verificación GPG en todos los repositorios?"; then
            case "$DISTRO_FAMILY" in
                suse)
                    for repo_file in /etc/zypp/repos.d/*.repo; do
                        [[ -f "$repo_file" ]] || continue
                        if grep -q "^gpgcheck=0" "$repo_file"; then
                            cp "$repo_file" "$BACKUP_DIR/"
                            sed -i 's/^gpgcheck=0/gpgcheck=1/' "$repo_file"
                        fi
                    done
                    ;;
                rhel)
                    for repo_file in /etc/yum.repos.d/*.repo; do
                        [[ -f "$repo_file" ]] || continue
                        if grep -q "^gpgcheck=0" "$repo_file"; then
                            cp "$repo_file" "$BACKUP_DIR/"
                            sed -i 's/^gpgcheck=0/gpgcheck=1/' "$repo_file"
                        fi
                    done
                    ;;
                debian)
                    for src_file in /etc/apt/sources.list /etc/apt/sources.list.d/*.list; do
                        [[ -f "$src_file" ]] || continue
                        if grep -qi "trusted=yes" "$src_file" 2>/dev/null; then
                            cp "$src_file" "$BACKUP_DIR/"
                            sed -i 's/\[trusted=yes\]//gi' "$src_file"
                        fi
                    done
                    ;;
                arch)
                    if grep -q "^SigLevel.*Never" /etc/pacman.conf 2>/dev/null; then
                        cp /etc/pacman.conf "$BACKUP_DIR/"
                        sed -i 's/^SigLevel.*Never/SigLevel = Required DatabaseOptional/' /etc/pacman.conf
                    fi
                    ;;
            esac
            log_info "Verificación GPG habilitada en todos los repositorios"
        fi
    fi

    # Verificar paquetes no firmados instalados
    echo ""
    echo -e "${BOLD}Verificando paquetes instalados sin firma:${NC}"
    UNSIGNED=""
    case "$DISTRO_FAMILY" in
        suse|rhel)
            UNSIGNED=$(rpm -qa --qf '%{NAME}-%{VERSION} %{SIGPGP:pgpsig}\n' 2>/dev/null | grep -i "not signed\|none" || true) ;;
        debian)
            UNSIGNED=$(apt list --installed 2>/dev/null | grep -i "local\]" || true) ;;
        arch)
            UNSIGNED=$(pacman -Qk 2>/dev/null | grep -i "warning" || true) ;;
    esac
    if [[ -n "$UNSIGNED" ]]; then
        UNSIGNED_COUNT=$(echo "$UNSIGNED" | wc -l)
        log_warn "$UNSIGNED_COUNT paquete(s) sin firma GPG detectados"
        echo "$UNSIGNED" | head -10 | sed 's/^/    /'
        [[ $UNSIGNED_COUNT -gt 10 ]] && echo "    ... y $((UNSIGNED_COUNT - 10)) más"
    else
        echo -e "  ${GREEN}OK${NC} Todos los paquetes verificados tienen firma"
    fi
fi

# ============================================================
log_section "7. CONTROL DE HARDWARE (T1200)"
# ============================================================

echo "Verificando protecciones contra hardware malicioso..."
echo ""

# USBGuard
if command -v usbguard &>/dev/null; then
    if systemctl is-active usbguard &>/dev/null; then
        echo -e "  ${GREEN}OK${NC} USBGuard activo - dispositivos USB controlados"
    else
        log_warn "USBGuard instalado pero NO activo"
        if ask "¿Activar USBGuard?"; then
            # Generar política base con dispositivos actuales
            usbguard generate-policy > /etc/usbguard/rules.conf 2>/dev/null || true
            systemctl enable --now usbguard 2>/dev/null || true
            log_info "USBGuard activado con política base"
        fi
    fi
else
    log_warn "USBGuard no instalado"
    if ask "¿Instalar USBGuard para control de dispositivos USB?"; then
        pkg_install usbguard
        if command -v usbguard &>/dev/null; then
            usbguard generate-policy > /etc/usbguard/rules.conf 2>/dev/null || true
            systemctl enable --now usbguard 2>/dev/null || true
            log_info "USBGuard instalado y configurado"
        fi
    fi
fi

echo ""

# Thunderbolt/DMA protección
echo -e "${BOLD}Protección DMA (Thunderbolt/FireWire):${NC}"
if [[ -f /etc/modprobe.d/network-hardening.conf ]] || [[ -f /etc/modprobe.d/dma-hardening.conf ]]; then
    if grep -rq "firewire" /etc/modprobe.d/ 2>/dev/null; then
        echo -e "  ${GREEN}OK${NC} Módulos FireWire bloqueados"
    else
        log_warn "Módulos FireWire no bloqueados"
    fi
    if grep -rq "thunderbolt" /etc/modprobe.d/ 2>/dev/null; then
        echo -e "  ${GREEN}OK${NC} Módulos Thunderbolt bloqueados"
    else
        log_warn "Módulos Thunderbolt no bloqueados"
    fi
else
    if ask "¿Bloquear módulos DMA peligrosos (FireWire, Thunderbolt)?"; then
        cat > /etc/modprobe.d/dma-hardening.conf << 'EOF'
# Bloquear acceso DMA - T1200
install firewire-core /bin/false
install firewire-ohci /bin/false
install firewire-sbp2 /bin/false
install thunderbolt /bin/false
EOF
        log_info "Módulos DMA bloqueados"
    fi
fi

# ============================================================
log_section "8. AUDITORÍA DE SERVICIOS EXPUESTOS"
# ============================================================

echo "Auditando todos los servicios accesibles desde la red..."
echo ""

echo -e "${BOLD}Servicios TCP escuchando (acceso remoto posible):${NC}"
ss -tlnp 2>/dev/null | tail -n +2 | while IFS= read -r line; do
    local_addr=$(echo "$line" | awk '{print $4}')
    process=$(echo "$line" | awk '{print $6}')
    if echo "$local_addr" | grep -qE "^(0\.0\.0\.0|::|\*):" ; then
        port=$(echo "$local_addr" | rev | cut -d: -f1 | rev)
        echo -e "  ${RED}●${NC} Puerto $port ABIERTO a todo → $process"
    elif ! echo "$local_addr" | grep -qE "^(127\.|::1)"; then
        port=$(echo "$local_addr" | rev | cut -d: -f1 | rev)
        echo -e "  ${YELLOW}●${NC} Puerto $port en interfaz específica → $process"
    fi
done

echo ""
echo -e "${BOLD}Servicios UDP escuchando:${NC}"
ss -ulnp 2>/dev/null | tail -n +2 | grep -vE "127\.|::1" | while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    local_addr=$(echo "$line" | awk '{print $4}')
    process=$(echo "$line" | awk '{print $6}')
    port=$(echo "$local_addr" | rev | cut -d: -f1 | rev)
    echo -e "  ${YELLOW}●${NC} UDP $port → $process"
done || echo "  (ninguno)"

echo ""
if ask "¿Crear reglas de firewall para limitar acceso a servicios detectados?"; then
    if fw_is_active &>/dev/null; then
        # Limitar SSH a rate limiting
        fw_add_rich_rule 'rule family="ipv4" service name="ssh" limit value="5/m" accept'

        # Log de nuevas conexiones
        fw_set_log_denied all 2>/dev/null || true

        fw_reload 2>/dev/null || true
        log_info "Reglas de firewall aplicadas (rate limiting + logging)"
    else
        log_warn "firewalld no activo - no se pueden aplicar reglas"
    fi
fi

# ============================================================
# RESUMEN
# ============================================================
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║    MITIGACIÓN ACCESO INICIAL COMPLETADA (TA0001)          ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "Técnicas mitigadas:"
echo "  T1190 - Exploit Public-Facing App    → Protecciones anti-exploit"
echo "  T1133 - External Remote Services     → SSH hardening avanzado"
echo "  T1078 - Valid Accounts               → Auditoría de cuentas"
echo "  T1566 - Phishing                     → Bloqueo de dominios"
echo "  T1189 - Drive-by Compromise          → Monitor de descargas"
echo "  T1195 - Supply Chain Compromise      → Verificación GPG repos"
echo "  T1200 - Hardware Additions           → USBGuard, DMA bloqueado"
echo ""
log_info "Backups en: $BACKUP_DIR"
