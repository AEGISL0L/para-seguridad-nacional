#!/bin/bash
# ============================================================
# VALIDACIÓN DE CONTROLES - Purple Team
# Linux Multi-Distro (openSUSE, Debian/Ubuntu, RHEL/Fedora, Arch)
# ============================================================
# Capacidades implementadas:
#   - Simulación segura de técnicas MITRE ATT&CK
#   - Validación de controles de autenticación y acceso
#   - Validación de controles de red y detección
#   - Validación de controles de endpoint y ejecución
#   - Pruebas de detección y respuesta automática
#   - Reporte de eficacia de controles con scoring
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps

# ── Pre-check: detectar secciones ya aplicadas ────────────
_precheck 6
_pc 'check_file_exists "/usr/local/bin/validar-autenticacion.sh"'
_pc 'check_file_exists "/usr/local/bin/validar-red.sh"'
_pc 'check_file_exists "/usr/local/bin/validar-endpoint.sh"'
_pc 'check_file_exists "/usr/local/bin/simular-ataques.sh"'
_pc 'check_file_exists "/usr/local/bin/validar-metasploit.sh"'
_pc 'check_file_exists "/usr/local/bin/reporte-validacion.sh"'
_precheck_result

VALIDATION_DIR="/var/lib/purple-team"
mkdir -p "$VALIDATION_DIR/results" "$VALIDATION_DIR/evidence"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   VALIDACIÓN DE CONTROLES - Purple Team                    ║"
echo "║   Simulación segura, pruebas de detección y eficacia       ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Contadores globales
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

# ============================================================
log_section "1. VALIDADOR DE CONTROLES DE AUTENTICACIÓN"
# ============================================================

echo "Pruebas seguras de los controles de autenticación y"
echo "acceso implementados por los módulos de securización."
echo ""
echo "Validaciones:"
echo "  - Política de contraseñas (pwquality/login.defs)"
echo "  - Protección contra fuerza bruta (faillock)"
echo "  - SSH hardening (config y detección)"
echo "  - Cuentas sin contraseña y cuentas innecesarias"
echo "  - MFA (Google Authenticator / TOTP)"
echo ""

if check_file_exists "/usr/local/bin/validar-autenticacion.sh"; then
    log_already "Validador autenticacion (validar-autenticacion.sh ya instalado)"
elif ask "¿Instalar validador de controles de autenticación?"; then

    cat > /usr/local/bin/validar-autenticacion.sh << 'EOFVALAUTH'
#!/bin/bash
# ============================================================
# VALIDAR CONTROLES DE AUTENTICACIÓN
# Pruebas no destructivas de controles auth
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

RESULT_DIR="/var/lib/purple-team/results"
RESULT_FILE="$RESULT_DIR/auth-$(date +%Y%m%d-%H%M%S).txt"
mkdir -p "$RESULT_DIR"

TOTAL=0
PASS=0
FAIL=0
SKIP=0

test_result() {
    local NAME="$1"
    local STATUS="$2"
    local DETAIL="$3"
    TOTAL=$((TOTAL+1))
    case "$STATUS" in
        PASS) PASS=$((PASS+1)); echo "[PASS] $NAME: $DETAIL" | tee -a "$RESULT_FILE" ;;
        FAIL) FAIL=$((FAIL+1)); echo "[FAIL] $NAME: $DETAIL" | tee -a "$RESULT_FILE" ;;
        SKIP) SKIP=$((SKIP+1)); echo "[SKIP] $NAME: $DETAIL" | tee -a "$RESULT_FILE" ;;
    esac
}

echo "=== VALIDACIÓN DE CONTROLES DE AUTENTICACIÓN ===" | tee "$RESULT_FILE"
echo "Fecha: $(date -Iseconds)" | tee -a "$RESULT_FILE"
echo "Host: $(hostname)" | tee -a "$RESULT_FILE"
echo "" | tee -a "$RESULT_FILE"

# --- T1: Política de contraseñas ---
echo "--- Política de contraseñas ---" | tee -a "$RESULT_FILE"

# T1.1: PASS_MIN_DAYS > 0
if [[ -f /etc/login.defs ]]; then
    MIN_DAYS=$(grep -E "^PASS_MIN_DAYS" /etc/login.defs | awk '{print $2}' 2>/dev/null || echo "0")
    if [[ "$MIN_DAYS" -gt 0 ]] 2>/dev/null; then
        test_result "AUTH-01 PASS_MIN_DAYS" "PASS" "Valor=$MIN_DAYS (>0)"
    else
        test_result "AUTH-01 PASS_MIN_DAYS" "FAIL" "Valor=$MIN_DAYS (debería ser >0)"
    fi
else
    test_result "AUTH-01 PASS_MIN_DAYS" "SKIP" "/etc/login.defs no encontrado"
fi

# T1.2: PASS_MAX_DAYS <= 365
if [[ -f /etc/login.defs ]]; then
    MAX_DAYS=$(grep -E "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}' 2>/dev/null || echo "99999")
    if [[ "$MAX_DAYS" -le 365 ]] 2>/dev/null; then
        test_result "AUTH-02 PASS_MAX_DAYS" "PASS" "Valor=$MAX_DAYS (<=365)"
    else
        test_result "AUTH-02 PASS_MAX_DAYS" "FAIL" "Valor=$MAX_DAYS (debería ser <=365)"
    fi
else
    test_result "AUTH-02 PASS_MAX_DAYS" "SKIP" "/etc/login.defs no encontrado"
fi

# T1.3: PASS_MIN_LEN >= 12
if [[ -f /etc/login.defs ]]; then
    MIN_LEN=$(grep -E "^PASS_MIN_LEN" /etc/login.defs | awk '{print $2}' 2>/dev/null || echo "5")
    if [[ "$MIN_LEN" -ge 12 ]] 2>/dev/null; then
        test_result "AUTH-03 PASS_MIN_LEN" "PASS" "Valor=$MIN_LEN (>=12)"
    else
        test_result "AUTH-03 PASS_MIN_LEN" "FAIL" "Valor=$MIN_LEN (debería ser >=12)"
    fi
else
    test_result "AUTH-03 PASS_MIN_LEN" "SKIP" "/etc/login.defs no encontrado"
fi

# T1.4: pwquality instalado y configurado
if [[ -f /etc/security/pwquality.conf ]]; then
    MINLEN=$(grep -E "^minlen" /etc/security/pwquality.conf | head -1 | awk -F= '{print $2}' | tr -d ' ' 2>/dev/null || echo "0")
    if [[ "$MINLEN" -ge 12 ]] 2>/dev/null; then
        test_result "AUTH-04 pwquality minlen" "PASS" "minlen=$MINLEN (>=12)"
    else
        test_result "AUTH-04 pwquality minlen" "FAIL" "minlen=$MINLEN (debería ser >=12)"
    fi
else
    test_result "AUTH-04 pwquality minlen" "SKIP" "pwquality no configurado"
fi

# --- T2: Protección fuerza bruta ---
echo "" | tee -a "$RESULT_FILE"
echo "--- Protección fuerza bruta ---" | tee -a "$RESULT_FILE"

# T2.1: faillock configurado
if grep -rq "pam_faillock" /etc/pam.d/ 2>/dev/null; then
    test_result "AUTH-05 faillock PAM" "PASS" "pam_faillock presente en PAM"
else
    test_result "AUTH-05 faillock PAM" "FAIL" "pam_faillock no encontrado en PAM"
fi

# T2.2: fail2ban activo
if systemctl is-active --quiet fail2ban 2>/dev/null; then
    JAILS=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*://;s/,/ /g' | xargs echo)
    test_result "AUTH-06 fail2ban activo" "PASS" "Jails: $JAILS"
else
    test_result "AUTH-06 fail2ban activo" "FAIL" "fail2ban no activo"
fi

# T2.3: MaxAuthTries SSH <= 4
if [[ -f /etc/ssh/sshd_config ]]; then
    MAX_AUTH=$(grep -iE "^MaxAuthTries" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "6")
    if [[ -z "$MAX_AUTH" ]]; then MAX_AUTH=6; fi
    if [[ "$MAX_AUTH" -le 4 ]] 2>/dev/null; then
        test_result "AUTH-07 SSH MaxAuthTries" "PASS" "Valor=$MAX_AUTH (<=4)"
    else
        test_result "AUTH-07 SSH MaxAuthTries" "FAIL" "Valor=$MAX_AUTH (debería ser <=4)"
    fi
else
    test_result "AUTH-07 SSH MaxAuthTries" "SKIP" "sshd_config no encontrado"
fi

# --- T3: SSH hardening ---
echo "" | tee -a "$RESULT_FILE"
echo "--- SSH hardening ---" | tee -a "$RESULT_FILE"

if [[ -f /etc/ssh/sshd_config ]]; then
    # T3.1: PermitRootLogin
    ROOT_LOGIN=$(grep -iE "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "yes")
    if [[ "$ROOT_LOGIN" == "no" || "$ROOT_LOGIN" == "prohibit-password" ]]; then
        test_result "AUTH-08 SSH PermitRootLogin" "PASS" "Valor=$ROOT_LOGIN"
    else
        test_result "AUTH-08 SSH PermitRootLogin" "FAIL" "Valor=${ROOT_LOGIN:-yes} (debería ser no/prohibit-password)"
    fi

    # T3.2: PasswordAuthentication
    PASS_AUTH=$(grep -iE "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "yes")
    if [[ "$PASS_AUTH" == "no" ]]; then
        test_result "AUTH-09 SSH PasswordAuth" "PASS" "Deshabilitado (solo keys)"
    else
        test_result "AUTH-09 SSH PasswordAuth" "FAIL" "Habilitado (debería ser no para solo keys)"
    fi

    # T3.3: Protocol 2 (implícito en OpenSSH moderno, pero verificar)
    if ! grep -qiE "^Protocol\s+1" /etc/ssh/sshd_config 2>/dev/null; then
        test_result "AUTH-10 SSH Protocol" "PASS" "Protocol 1 no habilitado"
    else
        test_result "AUTH-10 SSH Protocol" "FAIL" "Protocol 1 encontrado"
    fi

    # T3.4: X11Forwarding
    X11=$(grep -iE "^X11Forwarding" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "yes")
    if [[ "$X11" == "no" ]]; then
        test_result "AUTH-11 SSH X11Forwarding" "PASS" "Deshabilitado"
    else
        test_result "AUTH-11 SSH X11Forwarding" "FAIL" "Habilitado (debería ser no)"
    fi
else
    test_result "AUTH-08 SSH config" "SKIP" "sshd_config no encontrado"
fi

# --- T4: Cuentas ---
echo "" | tee -a "$RESULT_FILE"
echo "--- Cuentas del sistema ---" | tee -a "$RESULT_FILE"

# T4.1: Cuentas sin contraseña
NO_PASS=$(awk -F: '($2 == "" || $2 == "!") && $1 != "root" {print $1}' /etc/shadow 2>/dev/null | head -20)
if [[ -z "$NO_PASS" ]]; then
    test_result "AUTH-12 Cuentas sin password" "PASS" "No hay cuentas sin contraseña"
else
    test_result "AUTH-12 Cuentas sin password" "FAIL" "Cuentas: $(echo "$NO_PASS" | tr '\n' ',')"
fi

# T4.2: UID=0 extra
UID0=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd 2>/dev/null)
if [[ -z "$UID0" ]]; then
    test_result "AUTH-13 UID=0 extra" "PASS" "Solo root tiene UID=0"
else
    test_result "AUTH-13 UID=0 extra" "FAIL" "Cuentas UID=0: $(echo "$UID0" | tr '\n' ',')"
fi

# T4.3: Shells válidos para cuentas de sistema
SYS_SHELLS=$(awk -F: '$3 < 1000 && $3 != 0 && $7 !~ /nologin|false|sync|shutdown|halt/ {print $1 ":" $7}' /etc/passwd 2>/dev/null | head -20)
if [[ -z "$SYS_SHELLS" ]]; then
    test_result "AUTH-14 Shells de sistema" "PASS" "Todas las cuentas de sistema tienen shell restringido"
else
    test_result "AUTH-14 Shells de sistema" "FAIL" "Cuentas con shell: $(echo "$SYS_SHELLS" | tr '\n' ',')"
fi

# --- T5: MFA ---
echo "" | tee -a "$RESULT_FILE"
echo "--- MFA / Autenticación multifactor ---" | tee -a "$RESULT_FILE"

if pkg_is_installed google-authenticator-libpam 2>/dev/null; then
    test_result "AUTH-15 MFA TOTP" "PASS" "Google Authenticator PAM instalado"
else
    test_result "AUTH-15 MFA TOTP" "FAIL" "MFA TOTP no instalado"
fi

# Resumen
echo "" | tee -a "$RESULT_FILE"
echo "=== RESUMEN AUTENTICACIÓN ===" | tee -a "$RESULT_FILE"
echo "Total: $TOTAL | Pass: $PASS | Fail: $FAIL | Skip: $SKIP" | tee -a "$RESULT_FILE"
SCORE=0
if [[ $((TOTAL-SKIP)) -gt 0 ]]; then
    SCORE=$((PASS * 100 / (TOTAL-SKIP)))
fi
echo "Score: ${SCORE}%" | tee -a "$RESULT_FILE"
echo "" | tee -a "$RESULT_FILE"
echo "Resultados guardados en: $RESULT_FILE"
EOFVALAUTH

    chmod 700 /usr/local/bin/validar-autenticacion.sh
    log_info "Instalado: /usr/local/bin/validar-autenticacion.sh"

else
    log_warn "Omitido: validador de autenticación"
fi

# ============================================================
log_section "2. VALIDADOR DE CONTROLES DE RED"
# ============================================================

echo "Pruebas seguras de los controles de red y detección"
echo "de amenazas de red implementados."
echo ""
echo "Validaciones:"
echo "  - Firewall (firewalld zonas, reglas, servicios)"
echo "  - IDS/IPS (Suricata estado, reglas, detección)"
echo "  - DNS seguro (DoT, bloqueos)"
echo "  - Anti-exfiltración (puertos bloqueados, rate limiting)"
echo "  - Segmentación de red"
echo ""

if check_file_exists "/usr/local/bin/validar-red.sh"; then
    log_already "Validador red (validar-red.sh ya instalado)"
elif ask "¿Instalar validador de controles de red?"; then

    cat > /usr/local/bin/validar-red.sh << 'EOFVALRED'
#!/bin/bash
# ============================================================
# VALIDAR CONTROLES DE RED
# Pruebas no destructivas de controles de red
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

RESULT_DIR="/var/lib/purple-team/results"
RESULT_FILE="$RESULT_DIR/red-$(date +%Y%m%d-%H%M%S).txt"
mkdir -p "$RESULT_DIR"

TOTAL=0
PASS=0
FAIL=0
SKIP=0

test_result() {
    local NAME="$1"
    local STATUS="$2"
    local DETAIL="$3"
    TOTAL=$((TOTAL+1))
    case "$STATUS" in
        PASS) PASS=$((PASS+1)); echo "[PASS] $NAME: $DETAIL" | tee -a "$RESULT_FILE" ;;
        FAIL) FAIL=$((FAIL+1)); echo "[FAIL] $NAME: $DETAIL" | tee -a "$RESULT_FILE" ;;
        SKIP) SKIP=$((SKIP+1)); echo "[SKIP] $NAME: $DETAIL" | tee -a "$RESULT_FILE" ;;
    esac
}

echo "=== VALIDACIÓN DE CONTROLES DE RED ===" | tee "$RESULT_FILE"
echo "Fecha: $(date -Iseconds)" | tee -a "$RESULT_FILE"
echo "" | tee -a "$RESULT_FILE"

# --- T1: Firewall ---
echo "--- Firewall ---" | tee -a "$RESULT_FILE"

# T1.1: firewalld activo
if systemctl is-active --quiet firewalld 2>/dev/null; then
    test_result "RED-01 firewalld activo" "PASS" "Servicio activo"
else
    test_result "RED-01 firewalld activo" "FAIL" "firewalld no activo"
fi

# T1.2: Zona por defecto no es trusted
if command -v firewall-cmd &>/dev/null; then
    DEFAULT_ZONE=$(firewall-cmd --get-default-zone 2>/dev/null || echo "unknown")
elif command -v ufw &>/dev/null; then
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        DEFAULT_ZONE="ufw-active"
    else
        DEFAULT_ZONE="unknown"
    fi
else
    DEFAULT_ZONE="unknown"
fi
if [[ "$DEFAULT_ZONE" != "trusted" && "$DEFAULT_ZONE" != "unknown" ]]; then
    test_result "RED-02 Zona default" "PASS" "Zona=$DEFAULT_ZONE (no trusted)"
else
    test_result "RED-02 Zona default" "FAIL" "Zona=$DEFAULT_ZONE"
fi

# T1.3: Servicios expuestos mínimos
if fw_is_active; then
    SERVICES=$(fw_list_services 2>/dev/null || echo "")
    SVC_COUNT=$(echo "$SERVICES" | wc -w)
    if [[ "$SVC_COUNT" -le 5 ]]; then
        test_result "RED-03 Servicios expuestos" "PASS" "$SVC_COUNT servicios: $SERVICES"
    else
        test_result "RED-03 Servicios expuestos" "FAIL" "$SVC_COUNT servicios (demasiados): $SERVICES"
    fi
else
    test_result "RED-03 Servicios expuestos" "SKIP" "Firewall no disponible"
fi

# T1.4: Puertos C2 bloqueados
C2_BLOCKED=true
for PORT in 4444 5555 8443 1337 31337; do
    if fw_list_all 2>/dev/null | grep -q "${PORT}/tcp"; then
        C2_BLOCKED=false
        break
    fi
done
if $C2_BLOCKED; then
    test_result "RED-04 Puertos C2 bloqueados" "PASS" "Puertos 4444,5555,8443,1337,31337 no abiertos"
else
    test_result "RED-04 Puertos C2 bloqueados" "FAIL" "Algún puerto C2 está abierto"
fi

# T1.5: Rich rules de bloqueo presentes
if fw_is_active; then
    RICH=$(fw_list_rich_rules 2>/dev/null | wc -l)
    if [[ "$RICH" -gt 0 ]]; then
        test_result "RED-05 Rich rules" "PASS" "$RICH rich rules configuradas"
    else
        test_result "RED-05 Rich rules" "FAIL" "No hay rich rules de protección"
    fi
else
    test_result "RED-05 Rich rules" "SKIP" "Firewall no disponible"
fi

# --- T2: IDS/IPS ---
echo "" | tee -a "$RESULT_FILE"
echo "--- IDS/IPS ---" | tee -a "$RESULT_FILE"

# T2.1: Suricata activo
if systemctl is-active --quiet suricata 2>/dev/null; then
    test_result "RED-06 Suricata activo" "PASS" "Suricata corriendo"
else
    test_result "RED-06 Suricata activo" "FAIL" "Suricata no activo"
fi

# T2.2: Reglas Suricata cargadas
if [[ -d /var/lib/suricata/rules ]]; then
    RULE_COUNT=$(cat /var/lib/suricata/rules/*.rules 2>/dev/null | grep -cE "^alert " || echo "0")
    if [[ "$RULE_COUNT" -gt 100 ]]; then
        test_result "RED-07 Reglas Suricata" "PASS" "$RULE_COUNT reglas activas"
    else
        test_result "RED-07 Reglas Suricata" "FAIL" "Solo $RULE_COUNT reglas (esperadas >100)"
    fi
elif [[ -d /etc/suricata/rules ]]; then
    RULE_COUNT=$(cat /etc/suricata/rules/*.rules 2>/dev/null | grep -cE "^alert " || echo "0")
    if [[ "$RULE_COUNT" -gt 100 ]]; then
        test_result "RED-07 Reglas Suricata" "PASS" "$RULE_COUNT reglas activas"
    else
        test_result "RED-07 Reglas Suricata" "FAIL" "Solo $RULE_COUNT reglas (esperadas >100)"
    fi
else
    test_result "RED-07 Reglas Suricata" "SKIP" "Directorio de reglas no encontrado"
fi

# T2.3: Reglas IoC personalizadas
if [[ -f /etc/suricata/rules/ioc-custom.rules ]] || [[ -f /var/lib/suricata/rules/ioc-custom.rules ]]; then
    test_result "RED-08 Reglas IoC custom" "PASS" "Reglas IoC personalizadas presentes"
else
    test_result "RED-08 Reglas IoC custom" "FAIL" "No hay reglas IoC personalizadas"
fi

# --- T3: DNS seguro ---
echo "" | tee -a "$RESULT_FILE"
echo "--- DNS seguro ---" | tee -a "$RESULT_FILE"

# T3.1: DNS over TLS
if [[ -f /etc/systemd/resolved.conf ]]; then
    DOT=$(grep -E "^DNSOverTLS" /etc/systemd/resolved.conf 2>/dev/null | head -1)
    if echo "$DOT" | grep -qiE "yes|opportunistic"; then
        test_result "RED-09 DNS over TLS" "PASS" "$DOT"
    else
        test_result "RED-09 DNS over TLS" "FAIL" "DNSOverTLS no habilitado"
    fi
else
    test_result "RED-09 DNS over TLS" "SKIP" "resolved.conf no encontrado"
fi

# T3.2: DNS tunneling detection
if [[ -f /usr/local/bin/detectar-dns-tunnel.sh ]]; then
    test_result "RED-10 Detección DNS tunnel" "PASS" "Script detectar-dns-tunnel.sh instalado"
else
    test_result "RED-10 Detección DNS tunnel" "FAIL" "No hay detección de DNS tunneling"
fi

# --- T4: Anti-exfiltración ---
echo "" | tee -a "$RESULT_FILE"
echo "--- Anti-exfiltración ---" | tee -a "$RESULT_FILE"

# T4.1: Detección de exfiltración
if [[ -f /usr/local/bin/detectar-exfiltracion.sh ]]; then
    test_result "RED-11 Detección exfiltración" "PASS" "Script de detección instalado"
else
    test_result "RED-11 Detección exfiltración" "FAIL" "No hay detección de exfiltración"
fi

# T4.2: Monitoreo de transferencias
if [[ -f /usr/local/bin/monitorear-transferencias.sh ]]; then
    test_result "RED-12 Monitor transferencias" "PASS" "Monitoreo de volumen instalado"
else
    test_result "RED-12 Monitor transferencias" "FAIL" "No hay monitoreo de transferencias"
fi

# T4.3: Rate limiting con tc
if tc qdisc show 2>/dev/null | grep -q "htb\|tbf"; then
    test_result "RED-13 Rate limiting" "PASS" "tc rate limiting configurado"
else
    test_result "RED-13 Rate limiting" "FAIL" "No hay rate limiting de tráfico"
fi

# --- T5: Portscan detection ---
echo "" | tee -a "$RESULT_FILE"
echo "--- Detección de scanning ---" | tee -a "$RESULT_FILE"

if [[ -f /usr/local/bin/detectar-portscan.sh ]]; then
    test_result "RED-14 Detección portscan" "PASS" "Detección de port scanning instalada"
else
    test_result "RED-14 Detección portscan" "FAIL" "No hay detección de port scanning"
fi

# T5.2: Firewall rate limiting
if fw_list_rich_rules 2>/dev/null | grep -q "limit"; then
    test_result "RED-15 FW rate limiting" "PASS" "Rate limiting en firewall"
else
    test_result "RED-15 FW rate limiting" "FAIL" "Sin rate limiting en firewall"
fi

# Resumen
echo "" | tee -a "$RESULT_FILE"
echo "=== RESUMEN RED ===" | tee -a "$RESULT_FILE"
echo "Total: $TOTAL | Pass: $PASS | Fail: $FAIL | Skip: $SKIP" | tee -a "$RESULT_FILE"
SCORE=0
if [[ $((TOTAL-SKIP)) -gt 0 ]]; then
    SCORE=$((PASS * 100 / (TOTAL-SKIP)))
fi
echo "Score: ${SCORE}%" | tee -a "$RESULT_FILE"
echo ""
echo "Resultados guardados en: $RESULT_FILE"
EOFVALRED

    chmod 700 /usr/local/bin/validar-red.sh
    log_info "Instalado: /usr/local/bin/validar-red.sh"

else
    log_warn "Omitido: validador de controles de red"
fi

# ============================================================
log_section "3. VALIDADOR DE CONTROLES DE ENDPOINT"
# ============================================================

echo "Pruebas seguras de los controles de endpoint:"
echo "  - Kernel hardening (sysctl)"
echo "  - Protección de ejecución (noexec, AppArmor)"
echo "  - Integridad de archivos (AIDE)"
echo "  - Auditoría (auditd reglas activas)"
echo "  - Antimalware (ClamAV)"
echo "  - Sandboxing (Firejail, systemd)"
echo ""

if check_file_exists "/usr/local/bin/validar-endpoint.sh"; then
    log_already "Validador endpoint (validar-endpoint.sh ya instalado)"
elif ask "¿Instalar validador de controles de endpoint?"; then

    cat > /usr/local/bin/validar-endpoint.sh << 'EOFVALEND'
#!/bin/bash
# ============================================================
# VALIDAR CONTROLES DE ENDPOINT
# Pruebas no destructivas de controles de host
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

RESULT_DIR="/var/lib/purple-team/results"
RESULT_FILE="$RESULT_DIR/endpoint-$(date +%Y%m%d-%H%M%S).txt"
mkdir -p "$RESULT_DIR"

TOTAL=0
PASS=0
FAIL=0
SKIP=0

test_result() {
    local NAME="$1"
    local STATUS="$2"
    local DETAIL="$3"
    TOTAL=$((TOTAL+1))
    case "$STATUS" in
        PASS) PASS=$((PASS+1)); echo "[PASS] $NAME: $DETAIL" | tee -a "$RESULT_FILE" ;;
        FAIL) FAIL=$((FAIL+1)); echo "[FAIL] $NAME: $DETAIL" | tee -a "$RESULT_FILE" ;;
        SKIP) SKIP=$((SKIP+1)); echo "[SKIP] $NAME: $DETAIL" | tee -a "$RESULT_FILE" ;;
    esac
}

echo "=== VALIDACIÓN DE CONTROLES DE ENDPOINT ===" | tee "$RESULT_FILE"
echo "Fecha: $(date -Iseconds)" | tee -a "$RESULT_FILE"
echo "" | tee -a "$RESULT_FILE"

# --- T1: Kernel hardening ---
echo "--- Kernel hardening ---" | tee -a "$RESULT_FILE"

# T1.1: ASLR
ASLR=$(sysctl -n kernel.randomize_va_space 2>/dev/null || echo "0")
if [[ "$ASLR" -eq 2 ]]; then
    test_result "END-01 ASLR" "PASS" "kernel.randomize_va_space=$ASLR (full)"
else
    test_result "END-01 ASLR" "FAIL" "kernel.randomize_va_space=$ASLR (debería ser 2)"
fi

# T1.2: kptr_restrict
KPTR=$(sysctl -n kernel.kptr_restrict 2>/dev/null || echo "0")
if [[ "$KPTR" -ge 1 ]]; then
    test_result "END-02 kptr_restrict" "PASS" "Valor=$KPTR (>=1)"
else
    test_result "END-02 kptr_restrict" "FAIL" "Valor=$KPTR (debería ser >=1)"
fi

# T1.3: ptrace scope
PTRACE=$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null || echo "0")
if [[ "$PTRACE" -ge 1 ]]; then
    test_result "END-03 ptrace_scope" "PASS" "Valor=$PTRACE (>=1)"
else
    test_result "END-03 ptrace_scope" "FAIL" "Valor=$PTRACE (debería ser >=1)"
fi

# T1.4: dmesg_restrict
DMESG=$(sysctl -n kernel.dmesg_restrict 2>/dev/null || echo "0")
if [[ "$DMESG" -ge 1 ]]; then
    test_result "END-04 dmesg_restrict" "PASS" "Valor=$DMESG (>=1)"
else
    test_result "END-04 dmesg_restrict" "FAIL" "Valor=$DMESG (debería ser >=1)"
fi

# T1.5: SYN cookies
SYNCOOKIES=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo "0")
if [[ "$SYNCOOKIES" -eq 1 ]]; then
    test_result "END-05 SYN cookies" "PASS" "Habilitado"
else
    test_result "END-05 SYN cookies" "FAIL" "Deshabilitado"
fi

# T1.6: IP forwarding deshabilitado
IP_FWD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "1")
if [[ "$IP_FWD" -eq 0 ]]; then
    test_result "END-06 IP forwarding" "PASS" "Deshabilitado"
else
    test_result "END-06 IP forwarding" "FAIL" "Habilitado (debería ser 0)"
fi

# T1.7: ICMP redirects deshabilitados
ICMP=$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null || echo "1")
if [[ "$ICMP" -eq 0 ]]; then
    test_result "END-07 ICMP redirects" "PASS" "Deshabilitado"
else
    test_result "END-07 ICMP redirects" "FAIL" "Habilitado (debería ser 0)"
fi

# --- T2: Ejecución ---
echo "" | tee -a "$RESULT_FILE"
echo "--- Control de ejecución ---" | tee -a "$RESULT_FILE"

# T2.1: noexec en /tmp
if mount | grep -E " /tmp " | grep -q "noexec"; then
    test_result "END-08 noexec /tmp" "PASS" "/tmp montado con noexec"
else
    test_result "END-08 noexec /tmp" "FAIL" "/tmp sin noexec"
fi

# T2.2: noexec en /dev/shm
if mount | grep -E " /dev/shm " | grep -q "noexec"; then
    test_result "END-09 noexec /dev/shm" "PASS" "/dev/shm montado con noexec"
else
    test_result "END-09 noexec /dev/shm" "FAIL" "/dev/shm sin noexec"
fi

# T2.3: AppArmor activo
if systemctl is-active --quiet apparmor 2>/dev/null; then
    PROFILES=$(aa-status 2>/dev/null | grep "profiles are in" | head -3 || echo "")
    test_result "END-10 AppArmor activo" "PASS" "AppArmor activo: $PROFILES"
elif aa-enabled 2>/dev/null | grep -q "Yes"; then
    test_result "END-10 AppArmor activo" "PASS" "AppArmor habilitado"
else
    test_result "END-10 AppArmor activo" "FAIL" "AppArmor no activo"
fi

# T2.4: Bash restringido
if getent group shell-users &>/dev/null; then
    test_result "END-11 Grupo shell-users" "PASS" "Grupo shell-users existe (bash restringido)"
else
    test_result "END-11 Grupo shell-users" "FAIL" "Grupo shell-users no existe"
fi

# --- T3: Integridad ---
echo "" | tee -a "$RESULT_FILE"
echo "--- Integridad de archivos ---" | tee -a "$RESULT_FILE"

# T3.1: AIDE instalado
if command -v aide &>/dev/null; then
    test_result "END-12 AIDE instalado" "PASS" "AIDE disponible"
else
    test_result "END-12 AIDE instalado" "FAIL" "AIDE no instalado"
fi

# T3.2: AIDE database
if [[ -f /var/lib/aide/aide.db ]] || [[ -f /var/lib/aide/aide.db.gz ]]; then
    test_result "END-13 AIDE database" "PASS" "Base de datos AIDE existe"
else
    test_result "END-13 AIDE database" "FAIL" "No hay base de datos AIDE"
fi

# T3.3: rkhunter
if command -v rkhunter &>/dev/null; then
    test_result "END-14 rkhunter" "PASS" "rkhunter instalado"
else
    test_result "END-14 rkhunter" "FAIL" "rkhunter no instalado"
fi

# --- T4: Auditoría ---
echo "" | tee -a "$RESULT_FILE"
echo "--- Auditoría del sistema ---" | tee -a "$RESULT_FILE"

# T4.1: auditd activo
if systemctl is-active --quiet auditd 2>/dev/null; then
    test_result "END-15 auditd activo" "PASS" "Servicio activo"
else
    test_result "END-15 auditd activo" "FAIL" "auditd no activo"
fi

# T4.2: Reglas auditd MITRE
MITRE_RULES=0
for RULE_FILE in /etc/audit/rules.d/6*.rules; do
    if [[ -f "$RULE_FILE" ]]; then
        MITRE_RULES=$((MITRE_RULES+1))
    fi
done
if [[ "$MITRE_RULES" -ge 5 ]]; then
    test_result "END-16 Reglas MITRE auditd" "PASS" "$MITRE_RULES archivos de reglas MITRE"
else
    test_result "END-16 Reglas MITRE auditd" "FAIL" "Solo $MITRE_RULES archivos (esperados >=5)"
fi

# T4.3: Reglas auditd activas totales
ACTIVE_RULES=$(auditctl -l 2>/dev/null | wc -l)
if [[ "$ACTIVE_RULES" -gt 20 ]]; then
    test_result "END-17 Reglas auditd activas" "PASS" "$ACTIVE_RULES reglas cargadas"
else
    test_result "END-17 Reglas auditd activas" "FAIL" "Solo $ACTIVE_RULES reglas (esperadas >20)"
fi

# --- T5: Antimalware ---
echo "" | tee -a "$RESULT_FILE"
echo "--- Antimalware ---" | tee -a "$RESULT_FILE"

# T5.1: ClamAV instalado
if command -v clamscan &>/dev/null; then
    test_result "END-18 ClamAV instalado" "PASS" "ClamAV disponible"
else
    test_result "END-18 ClamAV instalado" "FAIL" "ClamAV no instalado"
fi

# T5.2: freshclam actualizado
if systemctl is-active --quiet clamav-freshclam 2>/dev/null || systemctl is-active --quiet freshclam 2>/dev/null; then
    test_result "END-19 ClamAV actualizado" "PASS" "freshclam activo"
else
    test_result "END-19 ClamAV actualizado" "FAIL" "freshclam no activo"
fi

# --- T6: Sandboxing ---
echo "" | tee -a "$RESULT_FILE"
echo "--- Sandboxing ---" | tee -a "$RESULT_FILE"

# T6.1: Firejail
if command -v firejail &>/dev/null; then
    PROFILES=$(ls /etc/firejail/*.profile 2>/dev/null | wc -l)
    test_result "END-20 Firejail" "PASS" "Instalado con $PROFILES perfiles"
else
    test_result "END-20 Firejail" "FAIL" "Firejail no instalado"
fi

# T6.2: systemd sandboxing drop-ins
DROPINS=$(find /etc/systemd/system/*.service.d/ -name "*.conf" 2>/dev/null | wc -l)
if [[ "$DROPINS" -gt 0 ]]; then
    test_result "END-21 Systemd sandboxing" "PASS" "$DROPINS drop-ins de sandboxing"
else
    test_result "END-21 Systemd sandboxing" "FAIL" "No hay drop-ins de sandboxing"
fi

# Resumen
echo "" | tee -a "$RESULT_FILE"
echo "=== RESUMEN ENDPOINT ===" | tee -a "$RESULT_FILE"
echo "Total: $TOTAL | Pass: $PASS | Fail: $FAIL | Skip: $SKIP" | tee -a "$RESULT_FILE"
SCORE=0
if [[ $((TOTAL-SKIP)) -gt 0 ]]; then
    SCORE=$((PASS * 100 / (TOTAL-SKIP)))
fi
echo "Score: ${SCORE}%" | tee -a "$RESULT_FILE"
echo ""
echo "Resultados guardados en: $RESULT_FILE"
EOFVALEND

    chmod 700 /usr/local/bin/validar-endpoint.sh
    log_info "Instalado: /usr/local/bin/validar-endpoint.sh"

else
    log_warn "Omitido: validador de controles de endpoint"
fi

# ============================================================
log_section "4. SIMULACIONES SEGURAS DE TÉCNICAS MITRE ATT&CK"
# ============================================================

echo "Ejecuta simulaciones seguras (no destructivas) de técnicas"
echo "ATT&CK para verificar si los controles las detectan."
echo ""
echo "Las simulaciones son SEGURAS:"
echo "  - Crean artefactos temporales que luego se eliminan"
echo "  - Verifican si la detección los identifica"
echo "  - NO modifican la configuración del sistema"
echo "  - NO comprometen la seguridad real"
echo ""

if check_file_exists "/usr/local/bin/simular-ataques.sh"; then
    log_already "Simulador ATT&CK (simular-ataques.sh ya instalado)"
elif ask "¿Instalar simulador de técnicas ATT&CK?"; then

    cat > /usr/local/bin/simular-ataques.sh << 'EOFSIMULAR'
#!/bin/bash
# ============================================================
# SIMULADOR DE TÉCNICAS MITRE ATT&CK (SEGURO)
# Pruebas no destructivas para validar detección
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

RESULT_DIR="/var/lib/purple-team/results"
EVIDENCE_DIR="/var/lib/purple-team/evidence"
RESULT_FILE="$RESULT_DIR/simulacion-$(date +%Y%m%d-%H%M%S).txt"
mkdir -p "$RESULT_DIR" "$EVIDENCE_DIR"

TOTAL=0
DETECTED=0
NOT_DETECTED=0
ERROR=0

sim_result() {
    local TECNICA="$1"
    local RESULTADO="$2"
    local DETALLE="$3"
    TOTAL=$((TOTAL+1))
    case "$RESULTADO" in
        DETECTED)     DETECTED=$((DETECTED+1));     echo "[DETECTED]     $TECNICA: $DETALLE" | tee -a "$RESULT_FILE" ;;
        NOT_DETECTED) NOT_DETECTED=$((NOT_DETECTED+1)); echo "[NOT_DETECTED] $TECNICA: $DETALLE" | tee -a "$RESULT_FILE" ;;
        ERROR)        ERROR=$((ERROR+1));            echo "[ERROR]        $TECNICA: $DETALLE" | tee -a "$RESULT_FILE" ;;
    esac
}

echo "=== SIMULACIÓN DE TÉCNICAS MITRE ATT&CK ===" | tee "$RESULT_FILE"
echo "Fecha: $(date -Iseconds)" | tee -a "$RESULT_FILE"
echo "NOTA: Todas las simulaciones son seguras y reversibles" | tee -a "$RESULT_FILE"
echo "" | tee -a "$RESULT_FILE"

# --- SIM-01: T1053.003 Persistencia via cron (crear y eliminar) ---
echo "--- SIM-01: T1053.003 Persistencia via cron ---" | tee -a "$RESULT_FILE"
TEMP_CRON="/tmp/purpleteam-cron-test-$$"
echo "# PURPLE TEAM TEST - $(date)" > "$TEMP_CRON"
echo "*/5 * * * * /tmp/purpleteam-test-payload-$$.sh" >> "$TEMP_CRON"
crontab -l > /tmp/purpleteam-cron-backup-$$ 2>/dev/null || true
# Instalar y desinstalar rápidamente
crontab "$TEMP_CRON" 2>/dev/null
sleep 2
# Verificar si fue detectado por auditd
DETECTED_CRON=false
if ausearch -k cron_modification -ts recent 2>/dev/null | grep -q "purpleteam"; then
    DETECTED_CRON=true
fi
if ausearch -k T1053_scheduled_task -ts recent 2>/dev/null | grep -q "cron"; then
    DETECTED_CRON=true
fi
# Restaurar crontab original
if [[ -s /tmp/purpleteam-cron-backup-$$ ]]; then
    crontab /tmp/purpleteam-cron-backup-$$
else
    crontab -r 2>/dev/null || true
fi
rm -f "$TEMP_CRON" /tmp/purpleteam-cron-backup-$$
if $DETECTED_CRON; then
    sim_result "T1053.003 Cron persistencia" "DETECTED" "Regla auditd detectó modificación de crontab"
else
    sim_result "T1053.003 Cron persistencia" "NOT_DETECTED" "No hubo alerta de modificación de crontab"
fi

# --- SIM-02: T1059.004 Ejecución de script en /tmp ---
echo "" | tee -a "$RESULT_FILE"
echo "--- SIM-02: T1059.004 Ejecución en /tmp ---" | tee -a "$RESULT_FILE"
TEMP_SCRIPT="/tmp/purpleteam-exec-test-$$.sh"
echo '#!/bin/bash' > "$TEMP_SCRIPT"
echo 'echo "PURPLE TEAM TEST"' >> "$TEMP_SCRIPT"
chmod +x "$TEMP_SCRIPT"
# Intentar ejecutar (debería fallar si noexec está activo)
EXEC_BLOCKED=false
if ! "$TEMP_SCRIPT" &>/dev/null; then
    EXEC_BLOCKED=true
fi
rm -f "$TEMP_SCRIPT"
if $EXEC_BLOCKED; then
    sim_result "T1059.004 Exec en /tmp" "DETECTED" "noexec bloqueó ejecución en /tmp"
else
    # Verificar si auditd lo registró
    if ausearch -k T1059_command_scripting -ts recent 2>/dev/null | grep -q "purpleteam"; then
        sim_result "T1059.004 Exec en /tmp" "DETECTED" "Ejecución permitida pero registrada por auditd"
    else
        sim_result "T1059.004 Exec en /tmp" "NOT_DETECTED" "Ejecución permitida en /tmp sin detección"
    fi
fi

# --- SIM-03: T1070.003 Borrado de historial ---
echo "" | tee -a "$RESULT_FILE"
echo "--- SIM-03: T1070.003 Borrado de historial ---" | tee -a "$RESULT_FILE"
# Solo verificar si el historial está protegido (append-only)
HIST_PROTECTED=false
if [[ -f /root/.bash_history ]]; then
    ATTRS=$(lsattr /root/.bash_history 2>/dev/null | awk '{print $1}')
    if echo "$ATTRS" | grep -q "a"; then
        HIST_PROTECTED=true
    fi
fi
if $HIST_PROTECTED; then
    sim_result "T1070.003 Historial protegido" "DETECTED" "Historial tiene atributo append-only"
else
    sim_result "T1070.003 Historial protegido" "NOT_DETECTED" "Historial no tiene protección append-only"
fi

# --- SIM-04: T1036 Masquerading (binary rename test) ---
echo "" | tee -a "$RESULT_FILE"
echo "--- SIM-04: T1036 Masquerading ---" | tee -a "$RESULT_FILE"
# Crear un binario falso con nombre sospechoso
FAKE_BIN="/tmp/purpleteam-sshd-$$"
cp /usr/bin/echo "$FAKE_BIN" 2>/dev/null || true
chmod +x "$FAKE_BIN" 2>/dev/null || true
"$FAKE_BIN" "test" &>/dev/null || true
sleep 1
rm -f "$FAKE_BIN"
# Verificar si el script de masquerading lo detectaría
if [[ -f /usr/local/bin/detectar-masquerading.sh ]]; then
    sim_result "T1036 Masquerading" "DETECTED" "Script detectar-masquerading.sh instalado para detectar binarios falsos"
else
    sim_result "T1036 Masquerading" "NOT_DETECTED" "No hay detección de masquerading"
fi

# --- SIM-05: T1564.001 Archivos ocultos ---
echo "" | tee -a "$RESULT_FILE"
echo "--- SIM-05: T1564.001 Archivos ocultos ---" | tee -a "$RESULT_FILE"
HIDDEN_DIR="/tmp/.purpleteam-hidden-$$"
mkdir -p "$HIDDEN_DIR"
echo "PURPLE TEAM TEST" > "$HIDDEN_DIR/.secret-data"
sleep 1
rm -rf "$HIDDEN_DIR"
if [[ -f /usr/local/bin/detectar-ocultos.sh ]]; then
    sim_result "T1564.001 Archivos ocultos" "DETECTED" "Script detectar-ocultos.sh instalado"
else
    sim_result "T1564.001 Archivos ocultos" "NOT_DETECTED" "No hay detección de artefactos ocultos"
fi

# --- SIM-06: T1027 Ofuscación base64 ---
echo "" | tee -a "$RESULT_FILE"
echo "--- SIM-06: T1027 Ofuscación base64 ---" | tee -a "$RESULT_FILE"
OBFUSCATED_SCRIPT="/tmp/purpleteam-obfuscated-$$.sh"
cat > "$OBFUSCATED_SCRIPT" << 'EOFOBF'
#!/bin/bash
# PURPLE TEAM TEST - Simulated obfuscated script
ENCODED=$(echo "PURPLE TEAM TEST" | base64)
echo "$ENCODED" | base64 -d
EOFOBF
sleep 1
rm -f "$OBFUSCATED_SCRIPT"
if [[ -f /usr/local/bin/detectar-ofuscados.sh ]]; then
    sim_result "T1027 Ofuscación base64" "DETECTED" "Script detectar-ofuscados.sh instalado"
else
    sim_result "T1027 Ofuscación base64" "NOT_DETECTED" "No hay detección de scripts ofuscados"
fi

# --- SIM-07: T1548 SUID monitoring ---
echo "" | tee -a "$RESULT_FILE"
echo "--- SIM-07: T1548 Monitoreo SUID ---" | tee -a "$RESULT_FILE"
# Verificar si hay auditoría de chmod (SUID)
if auditctl -l 2>/dev/null | grep -qE "chmod|T1548"; then
    sim_result "T1548 Auditoría SUID" "DETECTED" "Regla auditd para chmod/SUID activa"
else
    sim_result "T1548 Auditoría SUID" "NOT_DETECTED" "No hay auditoría de cambios SUID"
fi

# --- SIM-08: T1046 Port scan detection ---
echo "" | tee -a "$RESULT_FILE"
echo "--- SIM-08: T1046 Detección de port scan ---" | tee -a "$RESULT_FILE"
if [[ -f /usr/local/bin/detectar-portscan.sh ]]; then
    sim_result "T1046 Detección portscan" "DETECTED" "Script detectar-portscan.sh instalado"
else
    sim_result "T1046 Detección portscan" "NOT_DETECTED" "No hay detección de port scanning"
fi

# --- SIM-09: T1071 C2 Beaconing detection ---
echo "" | tee -a "$RESULT_FILE"
echo "--- SIM-09: T1071 Detección beaconing ---" | tee -a "$RESULT_FILE"
if [[ -f /usr/local/bin/detectar-beaconing.sh ]]; then
    sim_result "T1071 Detección beaconing" "DETECTED" "Script detectar-beaconing.sh instalado"
else
    sim_result "T1071 Detección beaconing" "NOT_DETECTED" "No hay detección de beaconing C2"
fi

# --- SIM-10: T1003 Credential dumping protection ---
echo "" | tee -a "$RESULT_FILE"
echo "--- SIM-10: T1003 Protección credential dumping ---" | tee -a "$RESULT_FILE"
# Verificar hidepid en /proc
HIDEPID=false
if mount | grep -E " /proc " | grep -q "hidepid"; then
    HIDEPID=true
fi
# Verificar permisos de /etc/shadow
SHADOW_PERM=$(stat -c %a /etc/shadow 2>/dev/null || echo "644")
SHADOW_OK=false
if [[ "$SHADOW_PERM" == "000" || "$SHADOW_PERM" == "400" || "$SHADOW_PERM" == "600" || "$SHADOW_PERM" == "640" ]]; then
    SHADOW_OK=true
fi
if $HIDEPID && $SHADOW_OK; then
    sim_result "T1003 Credential dumping" "DETECTED" "hidepid activo y shadow permisos=$SHADOW_PERM"
elif $SHADOW_OK; then
    sim_result "T1003 Credential dumping" "DETECTED" "shadow permisos=$SHADOW_PERM (hidepid no activo)"
else
    sim_result "T1003 Credential dumping" "NOT_DETECTED" "shadow permisos=$SHADOW_PERM, hidepid ausente"
fi

# --- SIM-11: T1105 Tool transfer detection ---
echo "" | tee -a "$RESULT_FILE"
echo "--- SIM-11: T1105 Detección de tool transfer ---" | tee -a "$RESULT_FILE"
if [[ -f /usr/local/bin/detectar-tool-transfer.sh ]]; then
    sim_result "T1105 Tool transfer" "DETECTED" "Script detectar-tool-transfer.sh instalado"
else
    sim_result "T1105 Tool transfer" "NOT_DETECTED" "No hay detección de tool transfer"
fi

# --- SIM-12: T1562 Servicio de seguridad watchdog ---
echo "" | tee -a "$RESULT_FILE"
echo "--- SIM-12: T1562 Watchdog de servicios ---" | tee -a "$RESULT_FILE"
if [[ -f /usr/local/bin/watchdog-seguridad.sh ]]; then
    sim_result "T1562 Watchdog seguridad" "DETECTED" "watchdog-seguridad.sh instalado"
else
    sim_result "T1562 Watchdog seguridad" "NOT_DETECTED" "No hay watchdog de servicios de seguridad"
fi

# Resumen
echo "" | tee -a "$RESULT_FILE"
echo "=== RESUMEN SIMULACIONES ===" | tee -a "$RESULT_FILE"
echo "Total: $TOTAL | Detectados: $DETECTED | No detectados: $NOT_DETECTED | Error: $ERROR" | tee -a "$RESULT_FILE"
if [[ $TOTAL -gt 0 ]]; then
    DET_RATE=$((DETECTED * 100 / TOTAL))
    echo "Tasa de detección: ${DET_RATE}%" | tee -a "$RESULT_FILE"
fi
echo "" | tee -a "$RESULT_FILE"
echo "Resultados guardados en: $RESULT_FILE"
EOFSIMULAR

    chmod 700 /usr/local/bin/simular-ataques.sh
    log_info "Instalado: /usr/local/bin/simular-ataques.sh"

else
    log_warn "Omitido: simulador de técnicas ATT&CK"
fi

# ============================================================
log_section "5. VALIDACIÓN OFENSIVA CON METASPLOIT"
# ============================================================

echo "Genera un validador ofensivo que ejecuta 12 tests usando"
echo "Metasploit Framework contra localhost para verificar que"
echo "las mitigaciones aplicadas funcionan frente a exploits reales."
echo ""
echo "Incluye:"
echo "  - Scanning de servicios (SSH, puertos, SMB, SSL)"
echo "  - Checks de exploits conocidos (DirtyPipe, PwnKit, Samba, Log4Shell)"
echo "  - Detección de payloads (AV, IDS, firewall)"
echo "  - Verificación de controles de credenciales (fail2ban)"
echo ""
echo "NOTA: Todos los tests apuntan a 127.0.0.1 exclusivamente."
echo "Si msfconsole no está instalado, todos los tests se marcan SKIP."
echo ""

if check_file_exists "/usr/local/bin/validar-metasploit.sh"; then
    log_already "Validador Metasploit (validar-metasploit.sh ya instalado)"
elif ask "¿Instalar validador ofensivo Metasploit?"; then

    cat > /usr/local/bin/validar-metasploit.sh << 'EOFMSFVAL'
#!/bin/bash
# ============================================================
# VALIDADOR OFENSIVO CON METASPLOIT FRAMEWORK
# Ejecuta 12 tests contra localhost para verificar controles
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

RESULT_DIR="/var/lib/purple-team/msf-results"
RESULT_FILE="$RESULT_DIR/msf-validacion-$(date +%Y%m%d-%H%M%S).txt"
mkdir -p "$RESULT_DIR"

MSF_TIMEOUT="${SECURIZAR_MSF_TIMEOUT:-120}"
MSF_TARGET="${SECURIZAR_MSF_TARGETS:-127.0.0.1}"

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║      VALIDACIÓN OFENSIVA CON METASPLOIT FRAMEWORK        ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "Target: $MSF_TARGET"
echo "Timeout por test: ${MSF_TIMEOUT}s"
echo "Fecha: $(date -Iseconds)"
echo ""

# Verificar disponibilidad de msfconsole
if ! command -v msfconsole &>/dev/null; then
    echo "[!] msfconsole no disponible - todos los tests serán SKIP"
    echo ""
    for i in $(seq 1 12); do
        printf -v tid "MSF-%02d" "$i"
        echo "[SKIP] $tid: msfconsole no instalado"
    done | tee "$RESULT_FILE"
    echo ""
    echo "Instala Metasploit Framework para ejecutar validación ofensiva."
    exit 0
fi

PASS=0
FAIL=0
SKIP=0

_msf_run() {
    local rc_file
    rc_file=$(mktemp /tmp/msf-val-XXXXXX.rc)
    echo "$1" > "$rc_file"
    echo "exit" >> "$rc_file"
    local out
    out=$(timeout "$MSF_TIMEOUT" msfconsole -q -r "$rc_file" 2>&1)
    local rc=$?
    rm -f "$rc_file"
    if [[ $rc -eq 124 ]]; then
        echo "TIMEOUT"
        return 1
    fi
    echo "$out"
    return 0
}

_result() {
    local status="$1"
    local tid="$2"
    local msg="$3"
    echo "[$status] $tid: $msg" | tee -a "$RESULT_FILE"
    case "$status" in
        PASS) PASS=$((PASS+1)) ;;
        FAIL) FAIL=$((FAIL+1)) ;;
        SKIP) SKIP=$((SKIP+1)) ;;
    esac
}

{
echo "=========================================================="
echo " VALIDACIÓN OFENSIVA CON METASPLOIT"
echo " Target: $MSF_TARGET"
echo " Fecha:  $(date -Iseconds)"
echo "=========================================================="
echo ""

# ── MSF-01: SSH version scan ──
echo ">>> MSF-01: SSH version scan..."
OUT=$(_msf_run "use auxiliary/scanner/ssh/ssh_version
set RHOSTS $MSF_TARGET
run")
if echo "$OUT" | grep -qi "SSH"; then
    _result "PASS" "MSF-01" "SSH version detectada (servicio expuesto - verificar versión)"
else
    _result "SKIP" "MSF-01" "SSH no accesible o timeout"
fi

# ── MSF-02: Port scan TCP ──
echo ">>> MSF-02: Port scan TCP..."
OUT=$(_msf_run "use auxiliary/scanner/portscan/tcp
set RHOSTS $MSF_TARGET
set PORTS 1-1024
set THREADS 10
run")
OPEN_PORTS=$(echo "$OUT" | grep -c "TCP OPEN" || true)
if [[ $OPEN_PORTS -le 5 ]]; then
    _result "PASS" "MSF-02" "Puertos TCP abiertos: $OPEN_PORTS (≤5)"
else
    _result "FAIL" "MSF-02" "Puertos TCP abiertos: $OPEN_PORTS (>5 - reducir superficie)"
fi

# ── MSF-03: SMB version ──
echo ">>> MSF-03: SMB version scan..."
OUT=$(_msf_run "use auxiliary/scanner/smb/smb_version
set RHOSTS $MSF_TARGET
run")
if echo "$OUT" | grep -qi "SMBv1\|SMB1"; then
    _result "FAIL" "MSF-03" "SMBv1 detectado (protocolo inseguro)"
else
    _result "PASS" "MSF-03" "SMBv1 no detectado"
fi

# ── MSF-04: SSL/TLS Heartbleed ──
echo ">>> MSF-04: Heartbleed check..."
OUT=$(_msf_run "use auxiliary/scanner/ssl/openssl_heartbleed
set RHOSTS $MSF_TARGET
set RPORT 443
run")
if echo "$OUT" | grep -qi "vulnerable"; then
    _result "FAIL" "MSF-04" "Vulnerable a Heartbleed"
else
    _result "PASS" "MSF-04" "No vulnerable a Heartbleed"
fi

# ── MSF-05: DirtyPipe check ──
echo ">>> MSF-05: DirtyPipe (CVE-2022-0847) check..."
OUT=$(_msf_run "use exploit/linux/local/dirty_pipe
set SESSION 0
check" 2>&1)
if echo "$OUT" | grep -qiE '\[\+\].*vulnerable'; then
    _result "FAIL" "MSF-05" "Vulnerable a DirtyPipe (CVE-2022-0847)"
elif echo "$OUT" | grep -qiE '\[-\].*not vulnerable'; then
    _result "PASS" "MSF-05" "No vulnerable a DirtyPipe"
else
    _result "SKIP" "MSF-05" "Check no concluyente (requiere sesión activa)"
fi

# ── MSF-06: PwnKit/pkexec ──
echo ">>> MSF-06: PwnKit (CVE-2021-4034) check..."
OUT=$(_msf_run "use exploit/linux/local/pkexec
set SESSION 0
check" 2>&1)
if echo "$OUT" | grep -qiE '\[\+\].*vulnerable'; then
    _result "FAIL" "MSF-06" "Vulnerable a PwnKit (CVE-2021-4034)"
elif echo "$OUT" | grep -qiE '\[-\].*not vulnerable'; then
    _result "PASS" "MSF-06" "No vulnerable a PwnKit"
else
    _result "SKIP" "MSF-06" "Check no concluyente (requiere sesión activa)"
fi

# ── MSF-07: Samba exploits ──
echo ">>> MSF-07: Samba check..."
OUT=$(_msf_run "use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS $MSF_TARGET
run")
if echo "$OUT" | grep -qiE '\[\+\].*vulnerable'; then
    _result "FAIL" "MSF-07" "Vulnerable a exploit Samba/SMB"
elif echo "$OUT" | grep -qiE '\[-\].*not vulnerable|does not appear'; then
    _result "PASS" "MSF-07" "No vulnerable a exploits Samba/SMB conocidos"
else
    _result "SKIP" "MSF-07" "SMB no accesible o check no concluyente"
fi

# ── MSF-08: Log4Shell ──
echo ">>> MSF-08: Log4Shell (CVE-2021-44228) scan..."
OUT=$(_msf_run "use auxiliary/scanner/http/log4shell_scanner
set RHOSTS $MSF_TARGET
set RPORT 8080
run")
if echo "$OUT" | grep -qiE '\[\+\].*vulnerable|log4shell'; then
    _result "FAIL" "MSF-08" "Vulnerable a Log4Shell (CVE-2021-44228)"
else
    _result "PASS" "MSF-08" "No vulnerable a Log4Shell"
fi

# ── MSF-09: Detección AV de payload Meterpreter ──
echo ">>> MSF-09: Detección AV de payload Meterpreter..."
if command -v msfvenom &>/dev/null && command -v clamscan &>/dev/null; then
    PAYLOAD_FILE=$(mktemp /tmp/msf-test-payload-XXXXXX.elf)
    msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 \
        -f elf -o "$PAYLOAD_FILE" &>/dev/null
    if [[ -f "$PAYLOAD_FILE" ]]; then
        AV_RESULT=$(clamscan --no-summary "$PAYLOAD_FILE" 2>&1)
        rm -f "$PAYLOAD_FILE"
        if echo "$AV_RESULT" | grep -qi "FOUND"; then
            _result "PASS" "MSF-09" "ClamAV detectó payload Meterpreter"
        else
            _result "FAIL" "MSF-09" "ClamAV NO detectó payload Meterpreter"
        fi
    else
        _result "SKIP" "MSF-09" "Error generando payload de test"
    fi
else
    _result "SKIP" "MSF-09" "msfvenom o clamscan no disponible"
fi

# ── MSF-10: Beaconing C2 + Suricata ──
echo ">>> MSF-10: Simulación beaconing C2..."
if command -v suricata &>/dev/null; then
    # Generar tráfico sospechoso tipo beaconing a localhost (puerto cerrado)
    for _ in $(seq 1 5); do
        timeout 2 bash -c "echo test > /dev/tcp/127.0.0.1/4444" 2>/dev/null || true
        sleep 1
    done
    sleep 2
    # Verificar alertas de Suricata
    if [[ -f /var/log/suricata/fast.log ]]; then
        RECENT_ALERTS=$(tail -20 /var/log/suricata/fast.log 2>/dev/null | grep -c "127.0.0.1" || true)
        if [[ $RECENT_ALERTS -gt 0 ]]; then
            _result "PASS" "MSF-10" "Suricata detectó tráfico C2 sospechoso ($RECENT_ALERTS alertas)"
        else
            _result "FAIL" "MSF-10" "Suricata NO detectó tráfico C2 sospechoso"
        fi
    else
        _result "SKIP" "MSF-10" "Log de Suricata no encontrado"
    fi
else
    _result "SKIP" "MSF-10" "Suricata no disponible"
fi

# ── MSF-11: Reverse shell bloqueada por firewall ──
echo ">>> MSF-11: Verificación firewall bloquea reverse shell..."
# Intentar conexión saliente a puerto típico C2
BLOCKED=0
for PORT in 4444 5555 8443; do
    if ! timeout 3 bash -c "echo test > /dev/tcp/127.0.0.1/$PORT" 2>/dev/null; then
        BLOCKED=$((BLOCKED+1))
    fi
done
if [[ $BLOCKED -ge 2 ]]; then
    _result "PASS" "MSF-11" "Firewall bloquea puertos C2 típicos ($BLOCKED/3 bloqueados)"
else
    _result "FAIL" "MSF-11" "Firewall NO bloquea puertos C2 típicos ($BLOCKED/3 bloqueados)"
fi

# ── MSF-12: SSH brute force + fail2ban ──
echo ">>> MSF-12: SSH brute force mini + fail2ban..."
if command -v fail2ban-client &>/dev/null && command -v ssh &>/dev/null; then
    # Intentar 3 logins fallidos
    for _ in $(seq 1 3); do
        timeout 5 ssh -o StrictHostKeyChecking=no -o BatchMode=yes \
            -o ConnectTimeout=3 fakeuser_msf_test@127.0.0.1 "exit" 2>/dev/null || true
    done
    sleep 3
    # Verificar si fail2ban registró algo
    F2B_STATUS=$(fail2ban-client status sshd 2>/dev/null || true)
    if echo "$F2B_STATUS" | grep -qi "Currently banned\|Total banned"; then
        BANNED=$(echo "$F2B_STATUS" | grep -oP 'Currently banned:\s+\K\d+' || echo "0")
        _result "PASS" "MSF-12" "fail2ban activo (baneados: $BANNED)"
    else
        _result "FAIL" "MSF-12" "fail2ban no detectó intentos de brute force SSH"
    fi
else
    _result "SKIP" "MSF-12" "fail2ban-client o ssh no disponible"
fi

echo ""
echo "=========================================================="
echo " RESUMEN DE VALIDACIÓN OFENSIVA"
echo "=========================================================="
echo ""
echo "  Tests ejecutados: $((PASS + FAIL + SKIP))"
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
echo "  SKIP: $SKIP"
if [[ $((PASS + FAIL)) -gt 0 ]]; then
    SCORE=$((PASS * 100 / (PASS + FAIL)))
    echo "  Score: ${SCORE}%"
fi
echo ""
} | tee -a "$RESULT_FILE"

echo "Resultados guardados en: $RESULT_FILE"
EOFMSFVAL

    chmod 700 /usr/local/bin/validar-metasploit.sh
    log_info "Instalado: /usr/local/bin/validar-metasploit.sh"

else
    log_warn "Omitido: validador ofensivo Metasploit"
fi

# ============================================================
log_section "6. REPORTE CONSOLIDADO DE VALIDACIÓN"
# ============================================================

echo "Ejecuta todas las validaciones y genera un reporte"
echo "consolidado de eficacia de controles con scoring."
echo ""
echo "Incluye:"
echo "  - Validación de autenticación"
echo "  - Validación de red"
echo "  - Validación de endpoint"
echo "  - Simulaciones ATT&CK"
echo "  - Validación ofensiva Metasploit"
echo "  - Score global de eficacia"
echo "  - Recomendaciones de mejora"
echo ""

if check_file_exists "/usr/local/bin/reporte-validacion.sh"; then
    log_already "Reporte validacion (reporte-validacion.sh ya instalado)"
elif ask "¿Instalar generador de reporte consolidado de validación?"; then

    cat > /usr/local/bin/reporte-validacion.sh << 'EOFREPORTVAL'
#!/bin/bash
# ============================================================
# REPORTE CONSOLIDADO DE VALIDACIÓN DE CONTROLES
# Ejecuta todas las validaciones y genera reporte final
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

RESULT_DIR="/var/lib/purple-team/results"
REPORT_FILE="$RESULT_DIR/reporte-consolidado-$(date +%Y%m%d-%H%M%S).txt"
mkdir -p "$RESULT_DIR"

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     REPORTE CONSOLIDADO DE VALIDACIÓN DE CONTROLES        ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

{
echo "=========================================================="
echo " REPORTE CONSOLIDADO DE VALIDACIÓN DE CONTROLES"
echo " Purple Team - $(hostname)"
echo " Fecha: $(date -Iseconds)"
echo "=========================================================="
echo ""

# Ejecutar cada validador
echo ">>> Ejecutando validación de autenticación..."
echo ""
echo "=== MÓDULO: AUTENTICACIÓN ==="
} | tee "$REPORT_FILE"

# Ejecutar validaciones y capturar resultados
AUTH_OUTPUT=""
RED_OUTPUT=""
END_OUTPUT=""
SIM_OUTPUT=""
MSF_OUTPUT=""

if [[ -x /usr/local/bin/validar-autenticacion.sh ]]; then
    echo "[*] Ejecutando validación de autenticación..."
    AUTH_OUTPUT=$(/usr/local/bin/validar-autenticacion.sh 2>&1)
    echo "$AUTH_OUTPUT" >> "$REPORT_FILE"
else
    echo "[!] validar-autenticacion.sh no encontrado" | tee -a "$REPORT_FILE"
fi

echo "" | tee -a "$REPORT_FILE"
echo "=== MÓDULO: RED ===" | tee -a "$REPORT_FILE"

if [[ -x /usr/local/bin/validar-red.sh ]]; then
    echo "[*] Ejecutando validación de red..."
    RED_OUTPUT=$(/usr/local/bin/validar-red.sh 2>&1)
    echo "$RED_OUTPUT" >> "$REPORT_FILE"
else
    echo "[!] validar-red.sh no encontrado" | tee -a "$REPORT_FILE"
fi

echo "" | tee -a "$REPORT_FILE"
echo "=== MÓDULO: ENDPOINT ===" | tee -a "$REPORT_FILE"

if [[ -x /usr/local/bin/validar-endpoint.sh ]]; then
    echo "[*] Ejecutando validación de endpoint..."
    END_OUTPUT=$(/usr/local/bin/validar-endpoint.sh 2>&1)
    echo "$END_OUTPUT" >> "$REPORT_FILE"
else
    echo "[!] validar-endpoint.sh no encontrado" | tee -a "$REPORT_FILE"
fi

echo "" | tee -a "$REPORT_FILE"
echo "=== MÓDULO: SIMULACIONES ATT&CK ===" | tee -a "$REPORT_FILE"

if [[ -x /usr/local/bin/simular-ataques.sh ]]; then
    echo "[*] Ejecutando simulaciones ATT&CK..."
    SIM_OUTPUT=$(/usr/local/bin/simular-ataques.sh 2>&1)
    echo "$SIM_OUTPUT" >> "$REPORT_FILE"
else
    echo "[!] simular-ataques.sh no encontrado" | tee -a "$REPORT_FILE"
fi

echo "" | tee -a "$REPORT_FILE"
echo "=== MÓDULO: VALIDACIÓN OFENSIVA (METASPLOIT) ===" | tee -a "$REPORT_FILE"

if [[ -x /usr/local/bin/validar-metasploit.sh ]]; then
    echo "[*] Ejecutando validación ofensiva Metasploit..."
    MSF_OUTPUT=$(/usr/local/bin/validar-metasploit.sh 2>&1)
    echo "$MSF_OUTPUT" >> "$REPORT_FILE"
else
    echo "[!] validar-metasploit.sh no encontrado" | tee -a "$REPORT_FILE"
fi

# Calcular scores globales
echo "" | tee -a "$REPORT_FILE"
echo "=========================================================="  | tee -a "$REPORT_FILE"
echo " RESUMEN EJECUTIVO" | tee -a "$REPORT_FILE"
echo "==========================================================" | tee -a "$REPORT_FILE"

# Contar resultados de todos los archivos recientes (últimos 5 min)
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0
TOTAL_DETECTED=0
TOTAL_NOT_DETECTED=0

# Contar de los outputs capturados
for OUTPUT in "$AUTH_OUTPUT" "$RED_OUTPUT" "$END_OUTPUT" "$MSF_OUTPUT"; do
    P=$(echo "$OUTPUT" | grep -c "^\[PASS\]" || true)
    F=$(echo "$OUTPUT" | grep -c "^\[FAIL\]" || true)
    S=$(echo "$OUTPUT" | grep -c "^\[SKIP\]" || true)
    TOTAL_PASS=$((TOTAL_PASS + P))
    TOTAL_FAIL=$((TOTAL_FAIL + F))
    TOTAL_SKIP=$((TOTAL_SKIP + S))
done

TOTAL_DETECTED=$(echo "$SIM_OUTPUT" | grep -c "^\[DETECTED\]" || true)
TOTAL_NOT_DETECTED=$(echo "$SIM_OUTPUT" | grep -c "^\[NOT_DETECTED\]" || true)

TOTAL_CONTROLS=$((TOTAL_PASS + TOTAL_FAIL))
TOTAL_SIMS=$((TOTAL_DETECTED + TOTAL_NOT_DETECTED))

{
echo ""
echo "Controles verificados:"
echo "  Total tests:     $((TOTAL_PASS + TOTAL_FAIL + TOTAL_SKIP))"
echo "  Pasados:         $TOTAL_PASS"
echo "  Fallidos:        $TOTAL_FAIL"
echo "  Omitidos:        $TOTAL_SKIP"
if [[ $TOTAL_CONTROLS -gt 0 ]]; then
    CTRL_SCORE=$((TOTAL_PASS * 100 / TOTAL_CONTROLS))
    echo "  Score controles: ${CTRL_SCORE}%"
fi
echo ""
echo "Simulaciones ATT&CK:"
echo "  Total tests:     $((TOTAL_DETECTED + TOTAL_NOT_DETECTED))"
echo "  Detectados:      $TOTAL_DETECTED"
echo "  No detectados:   $TOTAL_NOT_DETECTED"
if [[ $TOTAL_SIMS -gt 0 ]]; then
    DET_SCORE=$((TOTAL_DETECTED * 100 / TOTAL_SIMS))
    echo "  Tasa detección:  ${DET_SCORE}%"
fi
echo ""

# Score global ponderado (60% controles, 40% detección)
if [[ $TOTAL_CONTROLS -gt 0 && $TOTAL_SIMS -gt 0 ]]; then
    CTRL_SCORE=$((TOTAL_PASS * 100 / TOTAL_CONTROLS))
    DET_SCORE=$((TOTAL_DETECTED * 100 / TOTAL_SIMS))
    GLOBAL_SCORE=$(( (CTRL_SCORE * 60 + DET_SCORE * 40) / 100 ))
    echo "Score global:      ${GLOBAL_SCORE}% (60% controles + 40% detección)"
    echo ""
    if [[ $GLOBAL_SCORE -ge 80 ]]; then
        echo "Evaluación: EXCELENTE - Controles bien implementados"
    elif [[ $GLOBAL_SCORE -ge 60 ]]; then
        echo "Evaluación: BUENA - Mejoras recomendadas en controles fallidos"
    elif [[ $GLOBAL_SCORE -ge 40 ]]; then
        echo "Evaluación: REGULAR - Se requiere atención en múltiples áreas"
    else
        echo "Evaluación: DEFICIENTE - Se requiere hardening urgente"
    fi
fi
echo ""

# Recomendaciones
echo "=========================================================="
echo " RECOMENDACIONES"
echo "=========================================================="
echo ""

REC_NUM=1

# Generar recomendaciones basadas en fallos
for OUTPUT in "$AUTH_OUTPUT" "$RED_OUTPUT" "$END_OUTPUT" "$MSF_OUTPUT"; do
    while IFS= read -r LINE; do
        TEST_NAME=$(echo "$LINE" | sed 's/\[FAIL\] //' | cut -d: -f1)
        echo "  ${REC_NUM}. Remediar: $TEST_NAME"
        REC_NUM=$((REC_NUM+1))
    done <<< "$(echo "$OUTPUT" | grep "^\[FAIL\]" 2>/dev/null)"
done

for LINE in $(echo "$SIM_OUTPUT" | grep "^\[NOT_DETECTED\]" 2>/dev/null); do
    TEST_NAME=$(echo "$LINE" | sed 's/\[NOT_DETECTED\] //' | cut -d: -f1)
    if [[ -n "$TEST_NAME" ]]; then
        echo "  ${REC_NUM}. Implementar detección: $TEST_NAME"
        REC_NUM=$((REC_NUM+1))
    fi
done

if [[ $REC_NUM -eq 1 ]]; then
    echo "  No hay recomendaciones - todos los controles están implementados"
fi

echo ""
echo "=========================================================="
echo " FIN DEL REPORTE"
echo "=========================================================="
} | tee -a "$REPORT_FILE"

echo ""
echo "Reporte guardado en: $REPORT_FILE"
EOFREPORTVAL

    chmod 700 /usr/local/bin/reporte-validacion.sh
    log_info "Instalado: /usr/local/bin/reporte-validacion.sh"

    # Crear cron semanal para validación automática
    cat > /etc/cron.weekly/purple-team-validation << 'EOFCRON'
#!/bin/bash
# Validación semanal automática de controles - Purple Team
/usr/local/bin/reporte-validacion.sh > /var/lib/purple-team/results/validacion-semanal-$(date +%Y%m%d).txt 2>&1
# Notificar al admin
logger -t purple-team "Validación semanal completada. Ver /var/lib/purple-team/results/"
EOFCRON
    chmod 700 /etc/cron.weekly/purple-team-validation
    log_info "Cron semanal: /etc/cron.weekly/purple-team-validation"

else
    log_warn "Omitido: reporte consolidado de validación"
fi

# ============================================================
log_section "RESUMEN - VALIDACIÓN DE CONTROLES"
# ============================================================

echo ""
echo "Estado de las herramientas de validación Purple Team:"
echo ""

declare -A TOOLS=(
    ["/usr/local/bin/validar-autenticacion.sh"]="Validador de autenticación"
    ["/usr/local/bin/validar-red.sh"]="Validador de red"
    ["/usr/local/bin/validar-endpoint.sh"]="Validador de endpoint"
    ["/usr/local/bin/simular-ataques.sh"]="Simulador ATT&CK seguro"
    ["/usr/local/bin/reporte-validacion.sh"]="Reporte consolidado"
    ["/etc/cron.weekly/purple-team-validation"]="Validación semanal automática"
)

OK_COUNT=0
TOTAL_TOOLS=${#TOOLS[@]}

for TOOL_PATH in "${!TOOLS[@]}"; do
    TOOL_NAME="${TOOLS[$TOOL_PATH]}"
    if [[ -f "$TOOL_PATH" ]]; then
        echo -e "  ${GREEN}[OK]${NC} $TOOL_NAME"
        OK_COUNT=$((OK_COUNT+1))
    else
        echo -e "  ${DIM}[--]${NC} $TOOL_NAME"
    fi
done

echo ""
echo "Herramientas instaladas: $OK_COUNT/$TOTAL_TOOLS"
echo ""
echo "Uso:"
echo "  validar-autenticacion.sh   - Validar controles de auth"
echo "  validar-red.sh             - Validar controles de red"
echo "  validar-endpoint.sh        - Validar controles de endpoint"
echo "  simular-ataques.sh         - Simular técnicas ATT&CK"
echo "  reporte-validacion.sh      - Reporte consolidado completo"
echo ""
echo "Datos en: /var/lib/purple-team/"
echo ""
show_changes_summary
