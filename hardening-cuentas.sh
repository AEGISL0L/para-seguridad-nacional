#!/bin/bash
# ============================================================
# HARDENING DE CUENTAS Y CONTRASEÑAS - Linux Multi-Distro
# ============================================================
# Secciones:
#   S1 - Políticas de contraseñas (/etc/login.defs + chage)
#   S2 - Faillock (NO es PAM)
#   S3 - Detectar cuentas sin contraseña
#   S4 - Detectar cuentas con UID=0 extra
#   S5 - Auditar shells de cuentas del sistema
#   S6 - Deshabilitar cuentas no usadas
#   S7 - Script de auditoría permanente
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "hardening-cuentas"
securizar_setup_traps

# ── Pre-check: salida temprana si todo aplicado ──
_precheck 7
_pc check_file_contains /etc/login.defs "PASS_MAX_DAYS.*90"
_pc check_file_contains /etc/security/faillock.conf "deny = 5"
_pc true  # S3: deteccion cuentas sin password (siempre re-evaluar)
_pc true  # S4: deteccion UID=0 extra (siempre re-evaluar)
_pc true  # S5: auditoria shells sistema (siempre re-evaluar)
_pc true  # S6: cuentas no usadas (siempre re-evaluar)
_pc check_executable /usr/local/bin/auditar-cuentas.sh
_precheck_result

log_section "S1: POLÍTICAS DE CONTRASEÑAS (login.defs)"

echo "Configuración propuesta:"
echo "  PASS_MAX_DAYS = 90  (expiración cada 90 días)"
echo "  PASS_MIN_DAYS = 7   (mínimo 7 días entre cambios)"
echo "  PASS_WARN_AGE = 14  (avisar 14 días antes)"
echo "  LOGIN_RETRIES = 3   (máx 3 intentos)"
echo "  LOGIN_TIMEOUT = 60  (timeout de login 60s)"
echo "  ENCRYPT_METHOD = YESCRYPT (o SHA512 si no hay soporte)"
echo ""

if check_file_contains /etc/login.defs "PASS_MAX_DAYS.*90"; then
    log_already "Políticas de contraseñas en /etc/login.defs"
elif ask "¿Aplicar políticas de contraseñas en /etc/login.defs?"; then
    cp /etc/login.defs "$BACKUP_DIR/" 2>/dev/null || true
    log_change "Backup" "/etc/login.defs"

    # PASS_MAX_DAYS
    if grep -q "^PASS_MAX_DAYS" /etc/login.defs; then
        sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/' /etc/login.defs
    else
        echo -e "PASS_MAX_DAYS\t90" >> /etc/login.defs
    fi
    log_change "Modificado" "/etc/login.defs -> PASS_MAX_DAYS=90"

    # PASS_MIN_DAYS
    if grep -q "^PASS_MIN_DAYS" /etc/login.defs; then
        sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t7/' /etc/login.defs
    else
        echo -e "PASS_MIN_DAYS\t7" >> /etc/login.defs
    fi
    log_change "Modificado" "/etc/login.defs -> PASS_MIN_DAYS=7"

    # PASS_WARN_AGE
    if grep -q "^PASS_WARN_AGE" /etc/login.defs; then
        sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE\t14/' /etc/login.defs
    else
        echo -e "PASS_WARN_AGE\t14" >> /etc/login.defs
    fi
    log_change "Modificado" "/etc/login.defs -> PASS_WARN_AGE=14"

    # LOGIN_RETRIES
    if grep -q "^LOGIN_RETRIES" /etc/login.defs; then
        sed -i 's/^LOGIN_RETRIES.*/LOGIN_RETRIES\t3/' /etc/login.defs
    else
        echo -e "LOGIN_RETRIES\t3" >> /etc/login.defs
    fi
    log_change "Modificado" "/etc/login.defs -> LOGIN_RETRIES=3"

    # LOGIN_TIMEOUT
    if grep -q "^LOGIN_TIMEOUT" /etc/login.defs; then
        sed -i 's/^LOGIN_TIMEOUT.*/LOGIN_TIMEOUT\t60/' /etc/login.defs
    else
        echo -e "LOGIN_TIMEOUT\t60" >> /etc/login.defs
    fi
    log_change "Modificado" "/etc/login.defs -> LOGIN_TIMEOUT=60"

    # ENCRYPT_METHOD - preferir yescrypt (memory-hard) sobre SHA512 (CPU-bound)
    _encrypt_method="SHA512"
    if [[ -f /etc/login.defs ]]; then
        # Detectar soporte de yescrypt en libcrypt/pam
        if python3 -c "import crypt; crypt.mksalt(crypt.METHOD_BLOWFISH)" &>/dev/null 2>&1 || \
           grep -rq "yescrypt" /etc/pam.d/ 2>/dev/null || \
           [[ -f /usr/lib64/libcrypt.so.2 ]] || [[ -f /usr/lib/x86_64-linux-gnu/libcrypt.so.2 ]]; then
            _encrypt_method="YESCRYPT"
            log_info "yescrypt detectado (memory-hard, más resistente que SHA512)"
        fi
    fi
    if grep -q "^ENCRYPT_METHOD" /etc/login.defs; then
        sed -i "s/^ENCRYPT_METHOD.*/ENCRYPT_METHOD\t${_encrypt_method}/" /etc/login.defs
    else
        echo -e "ENCRYPT_METHOD\t${_encrypt_method}" >> /etc/login.defs
    fi
    log_change "Modificado" "/etc/login.defs -> ENCRYPT_METHOD=${_encrypt_method}"
    unset _encrypt_method

    log_info "login.defs actualizado"

    # Aplicar a usuarios existentes con chage
    if ask "¿Aplicar políticas a usuarios existentes (UID >= 1000)?"; then
        while IFS=: read -r username _ uid _ _ _ _; do
            if [[ "$uid" -ge 1000 ]] && [[ "$username" != "nobody" ]] && [[ "$username" != "nfsnobody" ]]; then
                chage --maxdays 90 --mindays 7 --warndays 14 "$username" 2>/dev/null || true
                log_change "Usuario" "$username chage maxdays=90 mindays=7 warndays=14"
                log_info "  chage aplicado a: $username"
            fi
        done < /etc/passwd
    else
        log_skip "Aplicar políticas a usuarios existentes (chage)"
    fi
else
    log_skip "Aplicar políticas de contraseñas en /etc/login.defs"
fi

# ============================================================
# S2: Configurar faillock (NO es PAM)
# ============================================================
log_section "S2: FAILLOCK (bloqueo por intentos fallidos)"

echo "faillock.conf configura el bloqueo de cuentas tras intentos fallidos."
echo "  deny = 5         (bloquear tras 5 intentos)"
echo "  unlock_time = 600 (desbloquear tras 10 min)"
echo "  fail_interval = 900 (ventana de 15 min)"
echo "  audit            (registrar en log)"
echo ""

if check_file_contains /etc/security/faillock.conf "deny = 5"; then
    log_already "Configurar /etc/security/faillock.conf"
elif ask "¿Configurar /etc/security/faillock.conf?"; then
    cp /etc/security/faillock.conf "$BACKUP_DIR/" 2>/dev/null || true
    log_change "Backup" "/etc/security/faillock.conf"

    cat > /etc/security/faillock.conf << 'EOF'
# ============================================================
# Configuración de faillock - Bloqueo por intentos fallidos
# Generado por hardening-cuentas.sh
# ============================================================

# Número de intentos fallidos antes de bloquear
deny = 5

# Tiempo de bloqueo en segundos (600 = 10 minutos)
unlock_time = 600

# Ventana de tiempo para contar intentos (900 = 15 minutos)
fail_interval = 900

# Registrar intentos en el log de auditoría
audit

# Directorio para almacenar datos de faillock
dir = /var/run/faillock

# No bloquear a root (evitar lockout total)
even_deny_root = false

# Silenciar mensajes (seguridad por oscuridad)
silent
EOF

    log_change "Creado" "/etc/security/faillock.conf"
    log_info "faillock.conf configurado"
    log_warn "NOTA: faillock.conf es independiente de PAM - no modifica /etc/pam.d/"
else
    log_skip "Configurar /etc/security/faillock.conf"
fi

# ============================================================
# S3: Detectar cuentas sin contraseña
# ============================================================
log_section "S3: CUENTAS SIN CONTRASEÑA"

log_info "Buscando cuentas sin contraseña..."
sin_pass=()
while IFS=: read -r username pass _; do
    if [[ "$pass" == "" ]] || [[ "$pass" == "!" ]] || [[ "$pass" == "!!" ]]; then
        # Cuentas bloqueadas (! o !!) son normales para cuentas de sistema
        continue
    fi
    if [[ "$pass" == "*" ]]; then
        continue
    fi
done < /etc/shadow

# Buscar cuentas con campo de contraseña vacío (realmente sin contraseña)
while IFS=: read -r username pass _; do
    if [[ "$pass" == "" ]]; then
        sin_pass+=("$username")
    fi
done < /etc/shadow

if [[ ${#sin_pass[@]} -gt 0 ]]; then
    log_warn "Cuentas SIN contraseña detectadas:"
    for user in "${sin_pass[@]}"; do
        echo -e "  ${RED}!!${NC}  $user"
    done

    if ask "¿Bloquear cuentas sin contraseña?"; then
        for user in "${sin_pass[@]}"; do
            if [[ "$user" != "root" ]]; then
                passwd -l "$user" 2>/dev/null || true
                log_change "Usuario" "$user bloqueada (passwd -l, sin contraseña)"
                log_info "  Bloqueada: $user"
            else
                log_warn "  root sin contraseña detectado - NO se bloquea automáticamente"
                log_warn "  Establece contraseña manualmente: passwd root"
            fi
        done
    else
        log_skip "Bloquear cuentas sin contraseña"
    fi
else
    log_info "No hay cuentas sin contraseña"
fi

# ============================================================
# S4: Detectar cuentas con UID=0 (además de root)
# ============================================================
log_section "S4: CUENTAS CON UID=0"

log_info "Buscando cuentas con UID=0 (además de root)..."
uid0_extra=()
while IFS=: read -r username _ uid _ _ _ _; do
    if [[ "$uid" -eq 0 ]] && [[ "$username" != "root" ]]; then
        uid0_extra+=("$username")
    fi
done < /etc/passwd

if [[ ${#uid0_extra[@]} -gt 0 ]]; then
    log_warn "¡ALERTA! Cuentas con UID=0 además de root:"
    for user in "${uid0_extra[@]}"; do
        echo -e "  ${RED}!!${NC}  $user (UID=0 = privilegios de root)"
    done
    log_warn "Esto es un indicador potencial de compromiso del sistema."
    log_warn "Revisa manualmente estas cuentas."

    if ask "¿Bloquear cuentas UID=0 extra?"; then
        for user in "${uid0_extra[@]}"; do
            passwd -l "$user" 2>/dev/null || true
            log_change "Usuario" "$user bloqueada (passwd -l, UID=0)"
            log_info "  Bloqueada: $user"
        done
    else
        log_skip "Bloquear cuentas UID=0 extra"
    fi
else
    log_info "Solo root tiene UID=0 (correcto)"
fi

# ============================================================
# S5: Auditar shells de cuentas del sistema
# ============================================================
log_section "S5: SHELLS DE CUENTAS DEL SISTEMA"

log_info "Auditando cuentas de sistema (UID < 1000) con shell real..."
shells_sospechosas=()
while IFS=: read -r username _ uid _ _ _ shell; do
    if [[ "$uid" -lt 1000 ]] && [[ "$username" != "root" ]]; then
        if [[ "$shell" == "/bin/bash" ]] || [[ "$shell" == "/bin/sh" ]] || [[ "$shell" == "/bin/zsh" ]]; then
            shells_sospechosas+=("$username:$uid:$shell")
        fi
    fi
done < /etc/passwd

if [[ ${#shells_sospechosas[@]} -gt 0 ]]; then
    log_warn "Cuentas de sistema con shell interactiva:"
    for entry in "${shells_sospechosas[@]}"; do
        IFS=: read -r user uid shell <<< "$entry"
        echo -e "  ${YELLOW}!!${NC}  $user (UID=$uid) -> $shell"
    done

    if ask "¿Cambiar shells de cuentas del sistema a /usr/sbin/nologin?"; then
        for entry in "${shells_sospechosas[@]}"; do
            IFS=: read -r user uid shell <<< "$entry"
            usermod -s /usr/sbin/nologin "$user" 2>/dev/null || true
            log_change "Usuario" "$user shell -> /usr/sbin/nologin"
            log_info "  $user -> /usr/sbin/nologin"
        done
    else
        log_skip "Cambiar shells de cuentas del sistema a /usr/sbin/nologin"
    fi
else
    log_info "Ninguna cuenta de sistema tiene shell interactiva"
fi

# ============================================================
# S6: Deshabilitar cuentas no usadas
# ============================================================
log_section "S6: CUENTAS NO USADAS"

log_info "Buscando cuentas de usuario (UID >= 1000) sin login reciente..."
current_user="${SUDO_USER:-$USER}"
cuentas_inactivas=()

while IFS=: read -r username _ uid _ _ _ _; do
    if [[ "$uid" -ge 1000 ]] && [[ "$username" != "nobody" ]] && [[ "$username" != "nfsnobody" ]] && [[ "$username" != "$current_user" ]]; then
        # Verificar último login
        last_login=$(lastlog -u "$username" 2>/dev/null | tail -1 | awk '{print $4, $5, $6, $7, $8, $9}')
        if echo "$last_login" | grep -q "Nunca\|Never\|\*\*Never" 2>/dev/null; then
            cuentas_inactivas+=("$username")
        fi
    fi
done < /etc/passwd

if [[ ${#cuentas_inactivas[@]} -gt 0 ]]; then
    log_warn "Cuentas que nunca han iniciado sesión:"
    for user in "${cuentas_inactivas[@]}"; do
        echo -e "  ${YELLOW}!!${NC}  $user"
    done

    if ask "¿Deshabilitar cuentas inactivas (se pueden reactivar después)?"; then
        for user in "${cuentas_inactivas[@]}"; do
            usermod -L -e 1 "$user" 2>/dev/null || true
            log_change "Usuario" "$user deshabilitada (usermod -L -e 1)"
            log_info "  Deshabilitada: $user"
        done
        log_info "Para reactivar: usermod -U -e '' <usuario>"
    else
        log_skip "Deshabilitar cuentas inactivas"
    fi
else
    log_info "No se encontraron cuentas inactivas"
fi

# ============================================================
# S7: Script de auditoría permanente
# ============================================================
log_section "S7: SCRIPT DE AUDITORÍA DE CUENTAS"

if check_executable /usr/local/bin/auditar-cuentas.sh; then
    log_already "Crear /usr/local/bin/auditar-cuentas.sh"
elif ask "¿Crear /usr/local/bin/auditar-cuentas.sh?"; then
    cat > /usr/local/bin/auditar-cuentas.sh << 'EOFAUDIT'
#!/bin/bash
# ============================================================
# Auditoría de cuentas del sistema
# Uso: sudo auditar-cuentas.sh
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  AUDITORÍA DE CUENTAS DEL SISTEMA${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

# 1. Políticas de contraseñas
echo -e "${CYAN}── Políticas de contraseñas (login.defs) ──${NC}"
for param in PASS_MAX_DAYS PASS_MIN_DAYS PASS_WARN_AGE LOGIN_RETRIES LOGIN_TIMEOUT ENCRYPT_METHOD; do
    valor=$(grep "^$param" /etc/login.defs 2>/dev/null | awk '{print $2}')
    if [[ -n "$valor" ]]; then
        echo -e "  ${GREEN}OK${NC}  $param = $valor"
    else
        echo -e "  ${YELLOW}!!${NC}  $param no configurado"
    fi
done

# 2. Faillock
echo ""
echo -e "${CYAN}── Configuración de faillock ──${NC}"
if [[ -f /etc/security/faillock.conf ]]; then
    deny=$(grep "^deny" /etc/security/faillock.conf 2>/dev/null | awk '{print $3}')
    unlock=$(grep "^unlock_time" /etc/security/faillock.conf 2>/dev/null | awk '{print $3}')
    echo -e "  ${GREEN}OK${NC}  deny = ${deny:-no configurado}"
    echo -e "  ${GREEN}OK${NC}  unlock_time = ${unlock:-no configurado}"
else
    echo -e "  ${YELLOW}!!${NC}  /etc/security/faillock.conf no existe"
fi

# 3. Cuentas sin contraseña
echo ""
echo -e "${CYAN}── Cuentas sin contraseña ──${NC}"
sin_pass=0
while IFS=: read -r username pass _; do
    if [[ "$pass" == "" ]]; then
        echo -e "  ${RED}!!${NC}  $username SIN CONTRASEÑA"
        ((sin_pass++))
    fi
done < /etc/shadow
if [[ $sin_pass -eq 0 ]]; then
    echo -e "  ${GREEN}OK${NC}  Ninguna cuenta sin contraseña"
fi

# 4. Cuentas UID=0
echo ""
echo -e "${CYAN}── Cuentas con UID=0 ──${NC}"
while IFS=: read -r username _ uid _ _ _ _; do
    if [[ "$uid" -eq 0 ]]; then
        if [[ "$username" == "root" ]]; then
            echo -e "  ${GREEN}OK${NC}  root (UID=0)"
        else
            echo -e "  ${RED}!!${NC}  $username (UID=0) - SOSPECHOSO"
        fi
    fi
done < /etc/passwd

# 5. Shells de cuentas de sistema
echo ""
echo -e "${CYAN}── Cuentas de sistema con shell interactiva ──${NC}"
shells_found=0
while IFS=: read -r username _ uid _ _ _ shell; do
    if [[ "$uid" -lt 1000 ]] && [[ "$username" != "root" ]]; then
        if [[ "$shell" == "/bin/bash" ]] || [[ "$shell" == "/bin/sh" ]] || [[ "$shell" == "/bin/zsh" ]]; then
            echo -e "  ${YELLOW}!!${NC}  $username (UID=$uid) -> $shell"
            ((shells_found++))
        fi
    fi
done < /etc/passwd
if [[ $shells_found -eq 0 ]]; then
    echo -e "  ${GREEN}OK${NC}  Ninguna cuenta de sistema con shell interactiva"
fi

# 6. Cuentas bloqueadas
echo ""
echo -e "${CYAN}── Cuentas bloqueadas ──${NC}"
bloqueadas=0
while IFS=: read -r username pass _; do
    if [[ "$pass" == "!"* ]] && [[ "$pass" != "!!" ]]; then
        echo -e "  ${YELLOW}--${NC}  $username (bloqueada)"
        ((bloqueadas++))
    fi
done < /etc/shadow
echo -e "  Total bloqueadas: $bloqueadas"

# 7. Último login de usuarios
echo ""
echo -e "${CYAN}── Últimos logins de usuarios (UID >= 1000) ──${NC}"
while IFS=: read -r username _ uid _ _ _ _; do
    if [[ "$uid" -ge 1000 ]] && [[ "$username" != "nobody" ]] && [[ "$username" != "nfsnobody" ]]; then
        last_info=$(lastlog -u "$username" 2>/dev/null | tail -1)
        echo "  $last_info"
    fi
done < /etc/passwd

echo ""
echo -e "${BOLD}Auditoría completada: $(date)${NC}"
EOFAUDIT

    chmod +x /usr/local/bin/auditar-cuentas.sh
    log_change "Creado" "/usr/local/bin/auditar-cuentas.sh"
    log_change "Permisos" "/usr/local/bin/auditar-cuentas.sh -> +x"
    log_info "Script creado: /usr/local/bin/auditar-cuentas.sh"
else
    log_skip "Crear /usr/local/bin/auditar-cuentas.sh"
fi

echo ""
log_info "Hardening de cuentas completado"
log_info "Backup en: $BACKUP_DIR"
show_changes_summary
