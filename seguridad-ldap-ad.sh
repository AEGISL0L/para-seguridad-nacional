#!/bin/bash
# ============================================================
# seguridad-ldap-ad.sh - Modulo 53: Seguridad LDAP y Active Directory
# ============================================================
# Secciones:
#   S1  - Deteccion de infraestructura LDAP/AD
#   S2  - Hardening de servidor OpenLDAP
#   S3  - Hardening de cliente LDAP/SSSD
#   S4  - Seguridad de Kerberos
#   S5  - FreeIPA Server hardening
#   S6  - Samba/Winbind e integracion AD
#   S7  - Control de acceso basado en LDAP
#   S8  - Monitorizacion de directorio
#   S9  - Hardening de replicacion y backup LDAP
#   S10 - Auditoria integral LDAP/AD
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"
require_root
securizar_setup_traps
init_backup "ldap-ad-security"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MODULO 53 - SEGURIDAD LDAP Y ACTIVE DIRECTORY          ║"
echo "║   OpenLDAP, SSSD, Kerberos, FreeIPA, Samba/Winbind,      ║"
echo "║   PAM, auditd, replicacion, auditoria integral            ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

log_section "MODULO 53: SEGURIDAD LDAP Y ACTIVE DIRECTORY"
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

# ── Directorio de configuracion de securizar ─────────────────
mkdir -p /etc/securizar
mkdir -p /var/log/securizar
mkdir -p /var/backups/securizar/ldap

# ── Variables de deteccion globales ──────────────────────────
HAS_SLAPD=false
HAS_SSSD=false
HAS_WINBIND=false
HAS_NSLCD=false
HAS_REALMD=false
HAS_FREEIPA_SERVER=false
HAS_FREEIPA_CLIENT=false
HAS_SAMBA=false
HAS_KRB5=false
LDAP_SERVER_DETECTED=false
LDAP_CLIENT_DETECTED=false
AD_JOINED=false
SLAPD_CONF=""
SLAPD_CONF_TYPE=""  # "file" o "cn=config"

# ── Helpers ──────────────────────────────────────────────────

# Establecer o reemplazar parametro en un archivo de configuracion
# set_config_param file key value [separator]
set_config_param() {
    local file="$1" key="$2" value="$3" sep="${4:- = }"
    if grep -qE "^[[:space:]]*#?[[:space:]]*${key}[[:space:]]*[=:]" "$file" 2>/dev/null; then
        sed -i "s|^[[:space:]]*#\?[[:space:]]*${key}[[:space:]]*[=:].*|${key}${sep}${value}|" "$file"
    else
        echo "${key}${sep}${value}" >> "$file"
    fi
}

# Verificar si un servicio esta activo
service_is_active() {
    systemctl is-active "$1" &>/dev/null 2>&1
}

# Verificar si un servicio existe
service_exists() {
    systemctl list-unit-files "$1.service" 2>/dev/null | grep -q "$1"
}

# Generar contrasena segura
generate_strong_password() {
    local length="${1:-32}"
    openssl rand -base64 "$length" 2>/dev/null | tr -dc 'A-Za-z0-9!@#$%^&*' | head -c "$length"
}

# ============================================================
# S1: DETECCION DE INFRAESTRUCTURA LDAP/AD
# ============================================================
log_section "S1: DETECCION DE INFRAESTRUCTURA LDAP/AD"

echo "Detecta la infraestructura LDAP/AD presente en el sistema:"
echo "  - Servidor OpenLDAP (slapd)"
echo "  - Cliente LDAP (sssd, nslcd, realmd, winbind)"
echo "  - Dominio Active Directory (realm list)"
echo "  - Entradas LDAP/SSS en nsswitch.conf"
echo "  - FreeIPA server/client"
echo "  - Kerberos configurado"
echo ""

if ask "¿Detectar infraestructura LDAP/AD en este sistema?"; then

    log_info "Analizando infraestructura LDAP/AD..."

    # ── Detectar servidor OpenLDAP (slapd) ───────────────────
    if command -v slapd &>/dev/null || service_is_active slapd || \
       [[ -d /etc/openldap/slapd.d ]] || [[ -d /etc/ldap/slapd.d ]] || \
       [[ -f /etc/openldap/slapd.conf ]] || [[ -f /etc/ldap/slapd.conf ]]; then
        HAS_SLAPD=true
        LDAP_SERVER_DETECTED=true
        log_info "Servidor OpenLDAP (slapd) detectado"

        # Determinar tipo de configuracion
        if [[ -d /etc/openldap/slapd.d ]] || [[ -d /etc/ldap/slapd.d ]]; then
            SLAPD_CONF_TYPE="cn=config"
            if [[ -d /etc/openldap/slapd.d ]]; then
                SLAPD_CONF="/etc/openldap/slapd.d"
            else
                SLAPD_CONF="/etc/ldap/slapd.d"
            fi
            log_info "Tipo de configuracion: cn=config (directorio: $SLAPD_CONF)"
        elif [[ -f /etc/openldap/slapd.conf ]]; then
            SLAPD_CONF_TYPE="file"
            SLAPD_CONF="/etc/openldap/slapd.conf"
            log_info "Tipo de configuracion: slapd.conf ($SLAPD_CONF)"
        elif [[ -f /etc/ldap/slapd.conf ]]; then
            SLAPD_CONF_TYPE="file"
            SLAPD_CONF="/etc/ldap/slapd.conf"
            log_info "Tipo de configuracion: slapd.conf ($SLAPD_CONF)"
        fi

        if service_is_active slapd; then
            log_info "Servicio slapd esta activo y en ejecucion"
        else
            log_warn "slapd instalado pero no activo"
        fi
    else
        log_info "Servidor OpenLDAP no detectado"
    fi

    # ── Detectar SSSD ────────────────────────────────────────
    if command -v sssd &>/dev/null || service_is_active sssd || \
       [[ -f /etc/sssd/sssd.conf ]]; then
        HAS_SSSD=true
        LDAP_CLIENT_DETECTED=true
        log_info "SSSD detectado"
        if service_is_active sssd; then
            log_info "Servicio sssd esta activo"
        else
            log_warn "sssd instalado pero no activo"
        fi
    fi

    # ── Detectar realmd ──────────────────────────────────────
    if command -v realm &>/dev/null; then
        HAS_REALMD=true
        log_info "realmd detectado"

        # Verificar si esta unido a un dominio AD
        local realm_output=""
        realm_output=$(realm list 2>/dev/null) || true
        if [[ -n "$realm_output" ]]; then
            AD_JOINED=true
            LDAP_CLIENT_DETECTED=true
            log_info "Sistema unido a dominio Active Directory:"
            while IFS= read -r line; do
                log_info "  $line"
            done <<< "$realm_output"
        else
            log_info "realmd presente pero no unido a ningun dominio"
        fi
    fi

    # ── Detectar Winbind ─────────────────────────────────────
    if command -v wbinfo &>/dev/null || service_is_active winbind || \
       [[ -f /etc/samba/smb.conf ]] && grep -qi "winbind" /etc/samba/smb.conf 2>/dev/null; then
        HAS_WINBIND=true
        LDAP_CLIENT_DETECTED=true
        log_info "Winbind detectado"
        if service_is_active winbind; then
            log_info "Servicio winbind esta activo"
        fi
    fi

    # ── Detectar nslcd ───────────────────────────────────────
    if command -v nslcd &>/dev/null || service_is_active nslcd || \
       [[ -f /etc/nslcd.conf ]]; then
        HAS_NSLCD=true
        LDAP_CLIENT_DETECTED=true
        log_info "nslcd detectado"
        if service_is_active nslcd; then
            log_info "Servicio nslcd esta activo"
        fi
    fi

    # ── Detectar Samba ───────────────────────────────────────
    if command -v smbd &>/dev/null || service_is_active smb || \
       service_is_active smbd || [[ -f /etc/samba/smb.conf ]]; then
        HAS_SAMBA=true
        log_info "Samba detectado"
    fi

    # ── Detectar FreeIPA ─────────────────────────────────────
    if [[ -d /etc/ipa ]] || command -v ipa &>/dev/null; then
        if command -v ipa-server-install &>/dev/null || \
           [[ -f /etc/ipa/default.conf ]] && grep -qi "enable_ra" /etc/ipa/default.conf 2>/dev/null; then
            HAS_FREEIPA_SERVER=true
            LDAP_SERVER_DETECTED=true
            log_info "FreeIPA Server detectado"
        fi
        if command -v ipa-client-install &>/dev/null || \
           [[ -f /etc/ipa/default.conf ]]; then
            HAS_FREEIPA_CLIENT=true
            LDAP_CLIENT_DETECTED=true
            log_info "FreeIPA Client detectado"
        fi
    fi

    # ── Detectar Kerberos ────────────────────────────────────
    if [[ -f /etc/krb5.conf ]] || command -v kinit &>/dev/null; then
        HAS_KRB5=true
        log_info "Kerberos detectado (krb5.conf o kinit disponible)"
    fi

    # ── Analizar nsswitch.conf ───────────────────────────────
    if [[ -f /etc/nsswitch.conf ]]; then
        log_info "Analizando /etc/nsswitch.conf..."
        local nsswitch_ldap=false
        local nsswitch_sss=false

        if grep -qE "^(passwd|group|shadow).*ldap" /etc/nsswitch.conf 2>/dev/null; then
            nsswitch_ldap=true
            LDAP_CLIENT_DETECTED=true
            log_info "nsswitch.conf contiene entradas LDAP"
        fi

        if grep -qE "^(passwd|group|shadow).*sss" /etc/nsswitch.conf 2>/dev/null; then
            nsswitch_sss=true
            LDAP_CLIENT_DETECTED=true
            log_info "nsswitch.conf contiene entradas SSS"
        fi

        if [[ "$nsswitch_ldap" == false && "$nsswitch_sss" == false ]]; then
            log_info "nsswitch.conf no contiene entradas LDAP/SSS"
        fi
    fi

    # ── Detectar ldap-utils ──────────────────────────────────
    if command -v ldapsearch &>/dev/null; then
        log_info "ldap-utils detectados (ldapsearch disponible)"
    fi

    # ── Guardar resultados de deteccion ──────────────────────
    local env_conf="/etc/securizar/ldap-environment.conf"
    cat > "$env_conf" << EOFENV
# ============================================================
# ldap-environment.conf - Entorno LDAP/AD detectado
# Generado por securizar - Modulo 53
# Fecha: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================
LDAP_SERVER_DETECTED=$LDAP_SERVER_DETECTED
LDAP_CLIENT_DETECTED=$LDAP_CLIENT_DETECTED
AD_JOINED=$AD_JOINED
HAS_SLAPD=$HAS_SLAPD
HAS_SSSD=$HAS_SSSD
HAS_WINBIND=$HAS_WINBIND
HAS_NSLCD=$HAS_NSLCD
HAS_REALMD=$HAS_REALMD
HAS_FREEIPA_SERVER=$HAS_FREEIPA_SERVER
HAS_FREEIPA_CLIENT=$HAS_FREEIPA_CLIENT
HAS_SAMBA=$HAS_SAMBA
HAS_KRB5=$HAS_KRB5
SLAPD_CONF_TYPE=$SLAPD_CONF_TYPE
SLAPD_CONF=$SLAPD_CONF
EOFENV
    chmod 600 "$env_conf"
    log_change "Creado" "$env_conf (entorno LDAP/AD detectado)"

    # ── Resumen de deteccion ─────────────────────────────────
    log_info "=== Resumen de deteccion ==="
    if [[ "$LDAP_SERVER_DETECTED" == true ]]; then
        log_info "Rol: SERVIDOR LDAP"
    fi
    if [[ "$LDAP_CLIENT_DETECTED" == true ]]; then
        log_info "Rol: CLIENTE LDAP"
    fi
    if [[ "$AD_JOINED" == true ]]; then
        log_info "Rol: UNIDO A DOMINIO AD"
    fi
    if [[ "$LDAP_SERVER_DETECTED" == false && "$LDAP_CLIENT_DETECTED" == false ]]; then
        log_warn "No se detecto infraestructura LDAP/AD activa"
        log_info "Las secciones siguientes prepararan scripts para uso futuro"
    fi

    log_change "Detectado" "Infraestructura LDAP/AD analizada"
else
    log_skip "Deteccion de infraestructura LDAP/AD"
fi

# ============================================================
# S2: HARDENING DE SERVIDOR OpenLDAP
# ============================================================
log_section "S2: HARDENING DE SERVIDOR OpenLDAP"

echo "Aplica hardening al servidor OpenLDAP (slapd):"
echo "  - Enforce TLS (ldaps:// o StartTLS)"
echo "  - Verificar certificados TLS"
echo "  - Deshabilitar binds anonimos"
echo "  - Configurar password policy overlay (ppolicy)"
echo "  - Configurar ACLs (control de acceso)"
echo "  - Limites olcSizeLimit/olcTimeLimit (anti-DoS)"
echo "  - Deshabilitar LDAPv2 (solo LDAPv3)"
echo "  - Verificar olcLogLevel"
echo ""

if ask "¿Aplicar hardening de servidor OpenLDAP?"; then

    if [[ "$HAS_SLAPD" == true ]]; then
        log_info "Procediendo con hardening de slapd..."

        # Backup de configuracion slapd
        if [[ -n "$SLAPD_CONF" ]]; then
            if [[ "$SLAPD_CONF_TYPE" == "cn=config" ]]; then
                cp -a "$SLAPD_CONF" "$BACKUP_DIR/slapd.d-backup" 2>/dev/null || true
                log_change "Backup" "cn=config ($SLAPD_CONF)"
                # Tambien hacer backup LDIF via slapcat
                if command -v slapcat &>/dev/null; then
                    slapcat -n 0 > "$BACKUP_DIR/cn-config-backup.ldif" 2>/dev/null || true
                    slapcat -n 1 > "$BACKUP_DIR/data-backup.ldif" 2>/dev/null || true
                    log_change "Backup" "LDIF export (cn=config + datos)"
                fi
            elif [[ "$SLAPD_CONF_TYPE" == "file" ]]; then
                cp -a "$SLAPD_CONF" "$BACKUP_DIR/"
                log_change "Backup" "$SLAPD_CONF"
            fi
        fi

        # Backup de ldap.conf si existe
        for ldap_conf_path in /etc/openldap/ldap.conf /etc/ldap/ldap.conf; do
            if [[ -f "$ldap_conf_path" ]]; then
                cp -a "$ldap_conf_path" "$BACKUP_DIR/"
                log_change "Backup" "$ldap_conf_path"
            fi
        done

        # ── Crear script de hardening de slapd ──────────────
        cat > /usr/local/bin/securizar-slapd.sh << 'EOFSLAPD'
#!/bin/bash
# ============================================================
# securizar-slapd.sh - Hardening de servidor OpenLDAP
# Generado por securizar - Modulo 53
# ============================================================
set -euo pipefail

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[X]${NC} $1"; }
section() { echo -e "\n${CYAN}── $1 ──${NC}"; }

if [[ $EUID -ne 0 ]]; then
    error "Ejecutar como root: sudo $0"
    exit 1
fi

echo ""
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  SECURIZAR - HARDENING DE SERVIDOR OpenLDAP${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo ""

SCORE=0
TOTAL=0
ISSUES=()

# ── Verificar que slapd esta instalado ───────────────────────
if ! command -v slapd &>/dev/null && ! systemctl list-unit-files slapd.service &>/dev/null 2>&1; then
    error "slapd no esta instalado en este sistema"
    exit 1
fi

# ── Detectar tipo de configuracion ───────────────────────────
CONF_TYPE=""
CONF_PATH=""
if [[ -d /etc/openldap/slapd.d ]]; then
    CONF_TYPE="cn=config"
    CONF_PATH="/etc/openldap/slapd.d"
elif [[ -d /etc/ldap/slapd.d ]]; then
    CONF_TYPE="cn=config"
    CONF_PATH="/etc/ldap/slapd.d"
elif [[ -f /etc/openldap/slapd.conf ]]; then
    CONF_TYPE="file"
    CONF_PATH="/etc/openldap/slapd.conf"
elif [[ -f /etc/ldap/slapd.conf ]]; then
    CONF_TYPE="file"
    CONF_PATH="/etc/ldap/slapd.conf"
else
    error "No se encontro configuracion de slapd"
    exit 1
fi

info "Configuracion detectada: $CONF_TYPE ($CONF_PATH)"

# ── 1. Verificar TLS ────────────────────────────────────────
section "1. Verificar TLS/SSL"
((TOTAL++)) || true

TLS_OK=false
if [[ "$CONF_TYPE" == "cn=config" ]]; then
    # Buscar olcTLSCertificateFile en cn=config
    if grep -r "olcTLSCertificateFile" "$CONF_PATH" &>/dev/null; then
        TLS_CERT=$(grep -r "olcTLSCertificateFile" "$CONF_PATH" 2>/dev/null | head -1 | awk '{print $2}')
        TLS_KEY=$(grep -r "olcTLSCertificateKeyFile" "$CONF_PATH" 2>/dev/null | head -1 | awk '{print $2}')
        TLS_CA=$(grep -r "olcTLSCACertificateFile" "$CONF_PATH" 2>/dev/null | head -1 | awk '{print $2}')

        if [[ -n "$TLS_CERT" && -f "$TLS_CERT" ]]; then
            info "Certificado TLS: $TLS_CERT"
            TLS_OK=true

            # Verificar validez del certificado
            EXPIRY=$(openssl x509 -enddate -noout -in "$TLS_CERT" 2>/dev/null | cut -d= -f2)
            if [[ -n "$EXPIRY" ]]; then
                EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null) || EXPIRY_EPOCH=0
                NOW_EPOCH=$(date +%s)
                DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
                if [[ $DAYS_LEFT -lt 0 ]]; then
                    error "Certificado TLS EXPIRADO hace $((DAYS_LEFT * -1)) dias"
                    ISSUES+=("Certificado TLS expirado")
                elif [[ $DAYS_LEFT -lt 30 ]]; then
                    warn "Certificado TLS expira en $DAYS_LEFT dias"
                    ISSUES+=("Certificado TLS expira pronto ($DAYS_LEFT dias)")
                else
                    info "Certificado TLS valido ($DAYS_LEFT dias restantes)"
                fi
            fi

            # Verificar fortaleza de la clave
            KEY_SIZE=$(openssl x509 -text -noout -in "$TLS_CERT" 2>/dev/null | grep "Public-Key:" | grep -oP '\d+')
            if [[ -n "$KEY_SIZE" ]]; then
                if [[ $KEY_SIZE -lt 2048 ]]; then
                    error "Clave TLS debil: ${KEY_SIZE} bits (minimo 2048)"
                    ISSUES+=("Clave TLS debil: ${KEY_SIZE} bits")
                else
                    info "Fortaleza de clave TLS: ${KEY_SIZE} bits"
                fi
            fi
        else
            warn "Certificado TLS configurado pero archivo no encontrado: $TLS_CERT"
            ISSUES+=("Archivo de certificado TLS no encontrado")
        fi
    else
        error "TLS no configurado en slapd"
        ISSUES+=("TLS no configurado")
    fi
else
    # slapd.conf
    if grep -q "^TLSCertificateFile" "$CONF_PATH" 2>/dev/null; then
        TLS_OK=true
        info "TLS configurado en slapd.conf"
    else
        error "TLS no configurado en slapd.conf"
        ISSUES+=("TLS no configurado")
    fi
fi

if [[ "$TLS_OK" == true ]]; then
    ((SCORE++)) || true
    info "PASS: TLS configurado"
else
    error "FAIL: TLS no configurado"
fi

# Verificar que slapd escucha en ldaps://
if ss -tlnp 2>/dev/null | grep -q ":636" || \
   netstat -tlnp 2>/dev/null | grep -q ":636"; then
    info "slapd escuchando en puerto 636 (ldaps://)"
else
    warn "slapd no escucha en puerto 636 (ldaps://). Considere habilitar ldaps://"
    ISSUES+=("ldaps:// no habilitado en puerto 636")
fi

# ── 2. Verificar binds anonimos ─────────────────────────────
section "2. Verificar binds anonimos"
((TOTAL++)) || true

ANON_DISABLED=false
if [[ "$CONF_TYPE" == "cn=config" ]]; then
    if grep -r "olcDisallows:.*bind_anon" "$CONF_PATH" &>/dev/null; then
        ANON_DISABLED=true
    fi
    if grep -r "olcRequires:.*authc" "$CONF_PATH" &>/dev/null; then
        ANON_DISABLED=true
    fi
else
    if grep -q "^disallow.*bind_anon" "$CONF_PATH" 2>/dev/null; then
        ANON_DISABLED=true
    fi
    if grep -q "^require.*authc" "$CONF_PATH" 2>/dev/null; then
        ANON_DISABLED=true
    fi
fi

if [[ "$ANON_DISABLED" == true ]]; then
    ((SCORE++)) || true
    info "PASS: Binds anonimos deshabilitados"
else
    error "FAIL: Binds anonimos pueden estar habilitados"
    ISSUES+=("Binds anonimos no deshabilitados explicitamente")
fi

# ── 3. Verificar password policy overlay ─────────────────────
section "3. Verificar ppolicy overlay"
((TOTAL++)) || true

PPOLICY_OK=false
if [[ "$CONF_TYPE" == "cn=config" ]]; then
    if grep -r "olcOverlay.*ppolicy\|moduleload.*ppolicy" "$CONF_PATH" &>/dev/null; then
        PPOLICY_OK=true
    fi
else
    if grep -qE "^overlay\s+ppolicy|^moduleload.*ppolicy" "$CONF_PATH" 2>/dev/null; then
        PPOLICY_OK=true
    fi
fi

if [[ "$PPOLICY_OK" == true ]]; then
    ((SCORE++)) || true
    info "PASS: Password policy overlay (ppolicy) habilitado"
else
    warn "FAIL: ppolicy overlay no detectado"
    ISSUES+=("ppolicy overlay no configurado")
fi

# ── 4. Verificar limites (SizeLimit/TimeLimit) ──────────────
section "4. Verificar limites anti-DoS"
((TOTAL++)) || true

LIMITS_OK=false
if [[ "$CONF_TYPE" == "cn=config" ]]; then
    if grep -r "olcSizeLimit" "$CONF_PATH" &>/dev/null && \
       grep -r "olcTimeLimit" "$CONF_PATH" &>/dev/null; then
        LIMITS_OK=true
        SIZE_LIMIT=$(grep -r "olcSizeLimit" "$CONF_PATH" 2>/dev/null | head -1 | awk '{print $2}')
        TIME_LIMIT=$(grep -r "olcTimeLimit" "$CONF_PATH" 2>/dev/null | head -1 | awk '{print $2}')
        info "olcSizeLimit: $SIZE_LIMIT"
        info "olcTimeLimit: $TIME_LIMIT"
    fi
else
    if grep -q "^sizelimit" "$CONF_PATH" 2>/dev/null && \
       grep -q "^timelimit" "$CONF_PATH" 2>/dev/null; then
        LIMITS_OK=true
    fi
fi

if [[ "$LIMITS_OK" == true ]]; then
    ((SCORE++)) || true
    info "PASS: Limites SizeLimit/TimeLimit configurados"
else
    warn "FAIL: Limites no configurados (riesgo de DoS)"
    ISSUES+=("olcSizeLimit/olcTimeLimit no configurados")
fi

# ── 5. Verificar LDAPv2 deshabilitado ───────────────────────
section "5. Verificar que LDAPv2 esta deshabilitado"
((TOTAL++)) || true

LDAPv2_DISABLED=true
if [[ "$CONF_TYPE" == "cn=config" ]]; then
    if grep -r "olcAllows:.*LDAPv2" "$CONF_PATH" &>/dev/null; then
        LDAPv2_DISABLED=false
    fi
else
    if grep -q "^allow.*LDAPv2\|^allow.*bind_v2" "$CONF_PATH" 2>/dev/null; then
        LDAPv2_DISABLED=false
    fi
fi

if [[ "$LDAPv2_DISABLED" == true ]]; then
    ((SCORE++)) || true
    info "PASS: LDAPv2 no permitido (solo LDAPv3)"
else
    error "FAIL: LDAPv2 esta habilitado"
    ISSUES+=("LDAPv2 habilitado - usar solo LDAPv3")
fi

# ── 6. Verificar log level ──────────────────────────────────
section "6. Verificar logging adecuado"
((TOTAL++)) || true

LOG_OK=false
if [[ "$CONF_TYPE" == "cn=config" ]]; then
    if grep -r "olcLogLevel" "$CONF_PATH" &>/dev/null; then
        LOG_LEVEL=$(grep -r "olcLogLevel" "$CONF_PATH" 2>/dev/null | head -1 | awk '{print $2}')
        if [[ "$LOG_LEVEL" != "none" && "$LOG_LEVEL" != "0" ]]; then
            LOG_OK=true
            info "olcLogLevel: $LOG_LEVEL"
        fi
    fi
else
    if grep -q "^loglevel" "$CONF_PATH" 2>/dev/null; then
        LOG_LEVEL=$(grep "^loglevel" "$CONF_PATH" 2>/dev/null | awk '{print $2}')
        if [[ "$LOG_LEVEL" != "none" && "$LOG_LEVEL" != "0" ]]; then
            LOG_OK=true
        fi
    fi
fi

if [[ "$LOG_OK" == true ]]; then
    ((SCORE++)) || true
    info "PASS: Logging adecuado configurado"
else
    warn "FAIL: Logging insuficiente o no configurado"
    ISSUES+=("olcLogLevel no configurado adecuadamente")
fi

# ── 7. Verificar ACLs ───────────────────────────────────────
section "7. Verificar ACLs de acceso"
((TOTAL++)) || true

ACL_OK=false
if [[ "$CONF_TYPE" == "cn=config" ]]; then
    ACL_COUNT=$(grep -r "olcAccess:" "$CONF_PATH" 2>/dev/null | wc -l)
    if [[ $ACL_COUNT -gt 0 ]]; then
        ACL_OK=true
        info "Se encontraron $ACL_COUNT reglas de acceso (ACLs)"
        # Verificar si userPassword esta protegido
        if grep -r "olcAccess:.*userPassword" "$CONF_PATH" &>/dev/null; then
            info "userPassword tiene ACL especifica"
        else
            warn "userPassword no tiene ACL explicita"
            ISSUES+=("userPassword sin ACL explicita")
        fi
    fi
else
    ACL_COUNT=$(grep -c "^access to" "$CONF_PATH" 2>/dev/null) || ACL_COUNT=0
    if [[ $ACL_COUNT -gt 0 ]]; then
        ACL_OK=true
        info "Se encontraron $ACL_COUNT reglas de acceso"
    fi
fi

if [[ "$ACL_OK" == true ]]; then
    ((SCORE++)) || true
    info "PASS: ACLs de acceso configuradas"
else
    error "FAIL: No se encontraron ACLs de acceso"
    ISSUES+=("Sin ACLs de acceso configuradas")
fi

# ── Resumen ──────────────────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  RESUMEN DE HARDENING OpenLDAP${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo ""

PCT=$((SCORE * 100 / TOTAL))
if [[ $PCT -ge 80 ]]; then
    echo -e "  ${BOLD}PUNTUACION: ${GREEN}${SCORE}/${TOTAL} (${PCT}%) - BUENO${NC}"
elif [[ $PCT -ge 50 ]]; then
    echo -e "  ${BOLD}PUNTUACION: ${YELLOW}${SCORE}/${TOTAL} (${PCT}%) - MEJORABLE${NC}"
else
    echo -e "  ${BOLD}PUNTUACION: ${RED}${SCORE}/${TOTAL} (${PCT}%) - DEFICIENTE${NC}"
fi

if [[ ${#ISSUES[@]} -gt 0 ]]; then
    echo ""
    echo -e "${BOLD}  Problemas detectados:${NC}"
    for issue in "${ISSUES[@]}"; do
        echo -e "    ${RED}- $issue${NC}"
    done
fi

echo ""
echo "Para aplicar correcciones automaticas use:"
echo "  securizar-slapd.sh --fix"
echo ""

# ── Modo --fix ───────────────────────────────────────────────
if [[ "${1:-}" == "--fix" ]]; then
    echo ""
    echo -e "${BOLD}Aplicando correcciones...${NC}"
    echo ""

    if [[ "$CONF_TYPE" == "cn=config" ]]; then
        # Deshabilitar binds anonimos
        if [[ "$ANON_DISABLED" == false ]]; then
            ldapmodify -Y EXTERNAL -H ldapi:/// << 'LDIFMOD' 2>/dev/null || warn "Error deshabilitando binds anonimos"
dn: cn=config
changetype: modify
add: olcDisallows
olcDisallows: bind_anon
-
add: olcRequires
olcRequires: authc
LDIFMOD
            info "Binds anonimos deshabilitados"
        fi

        # Configurar limites si no existen
        if [[ "$LIMITS_OK" == false ]]; then
            ldapmodify -Y EXTERNAL -H ldapi:/// << 'LDIFMOD' 2>/dev/null || warn "Error configurando limites"
dn: cn=config
changetype: modify
replace: olcSizeLimit
olcSizeLimit: 500
-
replace: olcTimeLimit
olcTimeLimit: 3600
LDIFMOD
            info "Limites configurados: SizeLimit=500, TimeLimit=3600"
        fi

        # Configurar log level
        if [[ "$LOG_OK" == false ]]; then
            ldapmodify -Y EXTERNAL -H ldapi:/// << 'LDIFMOD' 2>/dev/null || warn "Error configurando loglevel"
dn: cn=config
changetype: modify
replace: olcLogLevel
olcLogLevel: stats
LDIFMOD
            info "LogLevel configurado: stats"
        fi

        info "Correcciones aplicadas. Reiniciar slapd: systemctl restart slapd"
    else
        # slapd.conf
        CONF="$CONF_PATH"

        if [[ "$ANON_DISABLED" == false ]]; then
            echo "disallow bind_anon" >> "$CONF"
            echo "require authc" >> "$CONF"
            info "Binds anonimos deshabilitados en slapd.conf"
        fi

        if [[ "$LIMITS_OK" == false ]]; then
            echo "sizelimit 500" >> "$CONF"
            echo "timelimit 3600" >> "$CONF"
            info "Limites configurados en slapd.conf"
        fi

        if [[ "$LOG_OK" == false ]]; then
            echo "loglevel stats" >> "$CONF"
            info "LogLevel configurado en slapd.conf"
        fi

        info "Correcciones aplicadas. Reiniciar slapd: systemctl restart slapd"
    fi
fi
EOFSLAPD
        chmod +x /usr/local/bin/securizar-slapd.sh
        log_change "Creado" "/usr/local/bin/securizar-slapd.sh"

        # Ejecutar verificacion inicial
        log_info "Ejecutando verificacion de slapd..."
        /usr/local/bin/securizar-slapd.sh 2>/dev/null || true

        # Preguntar si aplicar correcciones
        if ask "¿Aplicar correcciones automaticas a slapd?"; then
            /usr/local/bin/securizar-slapd.sh --fix 2>/dev/null || true
            log_change "Aplicado" "Correcciones automaticas de slapd"
        else
            log_skip "Correcciones automaticas de slapd"
        fi

    else
        log_warn "slapd no detectado en este sistema"
        log_info "El script /usr/local/bin/securizar-slapd.sh queda disponible para uso futuro"

        # Crear script igualmente
        cat > /usr/local/bin/securizar-slapd.sh << 'EOFSLAPDSTUB'
#!/bin/bash
echo "[!] slapd no detectado durante la instalacion de securizar"
echo "    Reinstale el modulo 53 despues de instalar OpenLDAP"
exit 1
EOFSLAPDSTUB
        chmod +x /usr/local/bin/securizar-slapd.sh
        log_change "Creado" "/usr/local/bin/securizar-slapd.sh (stub)"
    fi

    log_info "Hardening de servidor OpenLDAP completado"
else
    log_skip "Hardening de servidor OpenLDAP"
fi

# ============================================================
# S3: HARDENING DE CLIENTE LDAP/SSSD
# ============================================================
log_section "S3: HARDENING DE CLIENTE LDAP/SSSD"

echo "Aplica hardening al cliente LDAP (SSSD/nslcd):"
echo "  - Forzar TLS (ldap_id_use_start_tls = true)"
echo "  - Verificar certificado servidor (ldap_tls_reqcert = demand)"
echo "  - Configurar ruta CA (ldap_tls_cacert)"
echo "  - Cache de credenciales cifrada"
echo "  - Deshabilitar enumeracion"
echo "  - Autenticacion offline"
echo "  - Rangos min/max UID/GID"
echo "  - Hardening Kerberos en SSSD"
echo ""

if ask "¿Aplicar hardening de cliente LDAP/SSSD?"; then

    # ── Hardening de SSSD ────────────────────────────────────
    if [[ "$HAS_SSSD" == true ]] || [[ -f /etc/sssd/sssd.conf ]]; then
        log_info "Procediendo con hardening de SSSD..."
        SSSD_CONF="/etc/sssd/sssd.conf"

        if [[ -f "$SSSD_CONF" ]]; then
            cp -a "$SSSD_CONF" "$BACKUP_DIR/"
            log_change "Backup" "$SSSD_CONF"

            # ── Forzar TLS ───────────────────────────────────
            if grep -q "^\[domain/" "$SSSD_CONF" 2>/dev/null; then
                log_info "Aplicando hardening TLS a SSSD..."

                # ldap_id_use_start_tls = true
                if grep -q "ldap_id_use_start_tls" "$SSSD_CONF"; then
                    sed -i 's/^[[:space:]]*ldap_id_use_start_tls.*/ldap_id_use_start_tls = true/' "$SSSD_CONF"
                else
                    # Insertar despues de la primera linea [domain/
                    sed -i '/^\[domain\//a ldap_id_use_start_tls = true' "$SSSD_CONF"
                fi
                log_change "Configurado" "SSSD: ldap_id_use_start_tls = true"

                # ldap_tls_reqcert = demand
                if grep -q "ldap_tls_reqcert" "$SSSD_CONF"; then
                    sed -i 's/^[[:space:]]*ldap_tls_reqcert.*/ldap_tls_reqcert = demand/' "$SSSD_CONF"
                else
                    sed -i '/^\[domain\//a ldap_tls_reqcert = demand' "$SSSD_CONF"
                fi
                log_change "Configurado" "SSSD: ldap_tls_reqcert = demand"

                # ldap_tls_cacert - detectar ruta CA
                local ca_cert_path=""
                for ca_path in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt \
                               /etc/ssl/ca-bundle.pem /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem \
                               /etc/ssl/certs/ca-bundle.crt; do
                    if [[ -f "$ca_path" ]]; then
                        ca_cert_path="$ca_path"
                        break
                    fi
                done

                if [[ -n "$ca_cert_path" ]]; then
                    if grep -q "ldap_tls_cacert" "$SSSD_CONF"; then
                        sed -i "s|^[[:space:]]*ldap_tls_cacert.*|ldap_tls_cacert = $ca_cert_path|" "$SSSD_CONF"
                    else
                        sed -i "/^\[domain\//a ldap_tls_cacert = $ca_cert_path" "$SSSD_CONF"
                    fi
                    log_change "Configurado" "SSSD: ldap_tls_cacert = $ca_cert_path"
                else
                    log_warn "No se encontro bundle de CA. Configure ldap_tls_cacert manualmente."
                fi

                # cache_credentials = true (autenticacion offline)
                if grep -q "cache_credentials" "$SSSD_CONF"; then
                    sed -i 's/^[[:space:]]*cache_credentials.*/cache_credentials = true/' "$SSSD_CONF"
                else
                    sed -i '/^\[domain\//a cache_credentials = true' "$SSSD_CONF"
                fi
                log_change "Configurado" "SSSD: cache_credentials = true"

                # Deshabilitar enumeracion (mejora rendimiento y seguridad)
                if grep -q "enumerate" "$SSSD_CONF"; then
                    sed -i 's/^[[:space:]]*enumerate.*/enumerate = false/' "$SSSD_CONF"
                else
                    sed -i '/^\[domain\//a enumerate = false' "$SSSD_CONF"
                fi
                log_change "Configurado" "SSSD: enumerate = false"

                # Rangos UID/GID para evitar conflictos
                if ! grep -q "min_id" "$SSSD_CONF" 2>/dev/null; then
                    sed -i '/^\[domain\//a min_id = 1000' "$SSSD_CONF"
                    log_change "Configurado" "SSSD: min_id = 1000"
                fi
                if ! grep -q "max_id" "$SSSD_CONF" 2>/dev/null; then
                    sed -i '/^\[domain\//a max_id = 60000' "$SSSD_CONF"
                    log_change "Configurado" "SSSD: max_id = 60000"
                fi

                # Timeout de enumeracion
                if ! grep -q "ldap_enumeration_refresh_timeout" "$SSSD_CONF" 2>/dev/null; then
                    sed -i '/^\[domain\//a ldap_enumeration_refresh_timeout = 300' "$SSSD_CONF"
                    log_change "Configurado" "SSSD: ldap_enumeration_refresh_timeout = 300"
                fi

                # Hardening Kerberos si hay seccion krb5
                if grep -q "krb5_" "$SSSD_CONF" 2>/dev/null || grep -q "id_provider.*ad\|id_provider.*ipa" "$SSSD_CONF" 2>/dev/null; then
                    log_info "Configuracion Kerberos detectada en SSSD"
                    if ! grep -q "krb5_renewable_lifetime" "$SSSD_CONF" 2>/dev/null; then
                        sed -i '/^\[domain\//a krb5_renewable_lifetime = 7d' "$SSSD_CONF"
                        log_change "Configurado" "SSSD: krb5_renewable_lifetime = 7d"
                    fi
                    if ! grep -q "krb5_lifetime" "$SSSD_CONF" 2>/dev/null; then
                        sed -i '/^\[domain\//a krb5_lifetime = 10h' "$SSSD_CONF"
                        log_change "Configurado" "SSSD: krb5_lifetime = 10h"
                    fi
                fi

            else
                log_warn "No se encontro seccion [domain/] en sssd.conf"
                log_warn "SSSD puede no estar configurado correctamente"
            fi

            # Asegurar permisos de sssd.conf (debe ser 600 root:root)
            chmod 600 "$SSSD_CONF"
            chown root:root "$SSSD_CONF"
            log_change "Permisos" "$SSSD_CONF: 600 root:root"

            # Reiniciar SSSD si esta activo
            if service_is_active sssd; then
                if ask "¿Reiniciar SSSD para aplicar cambios?"; then
                    systemctl restart sssd 2>/dev/null || true
                    log_change "Reiniciado" "servicio sssd"
                else
                    log_skip "Reinicio de sssd (aplicar manualmente: systemctl restart sssd)"
                fi
            fi
        else
            log_warn "sssd.conf no encontrado. Creando plantilla de configuracion..."
            mkdir -p /etc/sssd
            cat > "$SSSD_CONF" << 'EOFSSSDTPL'
# ============================================================
# sssd.conf - Plantilla de configuracion SSSD hardened
# Generado por securizar - Modulo 53
# ============================================================
# IMPORTANTE: Adapte los valores de ldap_uri, ldap_search_base,
# y otros parametros a su entorno antes de activar SSSD.
# ============================================================

[sssd]
services = nss, pam, sudo
config_file_version = 2
domains = EXAMPLE.COM

[nss]
filter_groups = root
filter_users = root
reconnection_retries = 3

[pam]
reconnection_retries = 3
offline_credentials_expiration = 7

[domain/EXAMPLE.COM]
# Tipo de proveedor - cambiar segun su entorno:
# ldap, ad, ipa
id_provider = ldap
auth_provider = ldap
chpass_provider = ldap

# URI del servidor LDAP
ldap_uri = ldaps://ldap.example.com

# Base de busqueda
ldap_search_base = dc=example,dc=com

# TLS hardened
ldap_id_use_start_tls = true
ldap_tls_reqcert = demand
# ldap_tls_cacert = /etc/ssl/certs/ca-certificates.crt

# Cache de credenciales
cache_credentials = true
# Expirar credenciales offline tras 7 dias
account_cache_expiration = 7

# Deshabilitar enumeracion
enumerate = false
ldap_enumeration_refresh_timeout = 300

# Rangos UID/GID
min_id = 1000
max_id = 60000

# Kerberos (si aplica)
# krb5_realm = EXAMPLE.COM
# krb5_server = kdc.example.com
# krb5_lifetime = 10h
# krb5_renewable_lifetime = 7d
EOFSSSDTPL
            chmod 600 "$SSSD_CONF"
            chown root:root "$SSSD_CONF"
            log_change "Creado" "$SSSD_CONF (plantilla hardened)"
        fi
    else
        log_info "SSSD no detectado en el sistema"
    fi

    # ── Hardening de nslcd ───────────────────────────────────
    if [[ "$HAS_NSLCD" == true ]] || [[ -f /etc/nslcd.conf ]]; then
        log_info "Procediendo con hardening de nslcd..."
        NSLCD_CONF="/etc/nslcd.conf"

        if [[ -f "$NSLCD_CONF" ]]; then
            cp -a "$NSLCD_CONF" "$BACKUP_DIR/"
            log_change "Backup" "$NSLCD_CONF"

            # Forzar TLS
            set_config_param "$NSLCD_CONF" "ssl" "start_tls" " "
            log_change "Configurado" "nslcd: ssl start_tls"

            # Verificar certificado
            set_config_param "$NSLCD_CONF" "tls_reqcert" "demand" " "
            log_change "Configurado" "nslcd: tls_reqcert demand"

            # CA cert
            local ca_cert_path_nslcd=""
            for ca_path in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt \
                           /etc/ssl/ca-bundle.pem /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem; do
                if [[ -f "$ca_path" ]]; then
                    ca_cert_path_nslcd="$ca_path"
                    break
                fi
            done
            if [[ -n "$ca_cert_path_nslcd" ]]; then
                set_config_param "$NSLCD_CONF" "tls_cacertfile" "$ca_cert_path_nslcd" " "
                log_change "Configurado" "nslcd: tls_cacertfile = $ca_cert_path_nslcd"
            fi

            # Permisos de nslcd.conf
            chmod 640 "$NSLCD_CONF"
            chown root:nslcd "$NSLCD_CONF" 2>/dev/null || chown root:root "$NSLCD_CONF"
            log_change "Permisos" "$NSLCD_CONF: 640"

            # Reiniciar nslcd si activo
            if service_is_active nslcd; then
                if ask "¿Reiniciar nslcd para aplicar cambios?"; then
                    systemctl restart nslcd 2>/dev/null || true
                    log_change "Reiniciado" "servicio nslcd"
                else
                    log_skip "Reinicio de nslcd"
                fi
            fi
        else
            log_warn "nslcd.conf no encontrado"
        fi
    fi

    # ── Crear script de verificacion SSSD ────────────────────
    cat > /usr/local/bin/securizar-sssd.sh << 'EOFSSSD'
#!/bin/bash
# ============================================================
# securizar-sssd.sh - Verificacion de hardening SSSD
# Generado por securizar - Modulo 53
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[X]${NC} $1"; }
section() { echo -e "\n${CYAN}── $1 ──${NC}"; }

echo ""
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  SECURIZAR - VERIFICACION DE SSSD${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo ""

SSSD_CONF="/etc/sssd/sssd.conf"
SCORE=0
TOTAL=0

if [[ ! -f "$SSSD_CONF" ]]; then
    error "sssd.conf no encontrado"
    exit 1
fi

# 1. Permisos de sssd.conf
section "1. Permisos de sssd.conf"
((TOTAL++)) || true
PERMS=$(stat -c '%a' "$SSSD_CONF" 2>/dev/null)
OWNER=$(stat -c '%U:%G' "$SSSD_CONF" 2>/dev/null)
if [[ "$PERMS" == "600" && "$OWNER" == "root:root" ]]; then
    ((SCORE++)) || true
    info "PASS: Permisos correctos ($PERMS $OWNER)"
else
    error "FAIL: Permisos: $PERMS $OWNER (esperado: 600 root:root)"
fi

# 2. TLS habilitado
section "2. TLS habilitado"
((TOTAL++)) || true
if grep -q "ldap_id_use_start_tls.*=.*[Tt]rue\|ldap_uri.*ldaps://" "$SSSD_CONF" 2>/dev/null; then
    ((SCORE++)) || true
    info "PASS: TLS habilitado"
else
    error "FAIL: TLS no habilitado"
fi

# 3. Verificacion de certificado
section "3. Verificacion de certificado"
((TOTAL++)) || true
if grep -q "ldap_tls_reqcert.*=.*demand\|ldap_tls_reqcert.*=.*hard" "$SSSD_CONF" 2>/dev/null; then
    ((SCORE++)) || true
    info "PASS: Verificacion de certificado habilitada (demand)"
else
    error "FAIL: ldap_tls_reqcert no es 'demand'"
fi

# 4. Cache de credenciales
section "4. Cache de credenciales"
((TOTAL++)) || true
if grep -q "cache_credentials.*=.*[Tt]rue" "$SSSD_CONF" 2>/dev/null; then
    ((SCORE++)) || true
    info "PASS: Cache de credenciales habilitada"
else
    warn "FAIL: Cache de credenciales no habilitada"
fi

# 5. Enumeracion deshabilitada
section "5. Enumeracion deshabilitada"
((TOTAL++)) || true
if grep -q "enumerate.*=.*[Ff]alse" "$SSSD_CONF" 2>/dev/null; then
    ((SCORE++)) || true
    info "PASS: Enumeracion deshabilitada"
elif ! grep -q "enumerate" "$SSSD_CONF" 2>/dev/null; then
    ((SCORE++)) || true
    info "PASS: Enumeracion no configurada (default=false)"
else
    error "FAIL: Enumeracion habilitada"
fi

# 6. Rangos UID
section "6. Rangos UID/GID"
((TOTAL++)) || true
if grep -q "min_id" "$SSSD_CONF" 2>/dev/null; then
    ((SCORE++)) || true
    info "PASS: min_id configurado"
else
    warn "FAIL: min_id no configurado"
fi

# 7. Servicio SSSD activo
section "7. Estado del servicio"
((TOTAL++)) || true
if systemctl is-active sssd &>/dev/null; then
    ((SCORE++)) || true
    info "PASS: sssd activo"
else
    warn "FAIL: sssd no esta activo"
fi

# Resumen
echo ""
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
PCT=$((SCORE * 100 / TOTAL))
if [[ $PCT -ge 80 ]]; then
    echo -e "  ${BOLD}SSSD: ${GREEN}${SCORE}/${TOTAL} (${PCT}%) - BUENO${NC}"
elif [[ $PCT -ge 50 ]]; then
    echo -e "  ${BOLD}SSSD: ${YELLOW}${SCORE}/${TOTAL} (${PCT}%) - MEJORABLE${NC}"
else
    echo -e "  ${BOLD}SSSD: ${RED}${SCORE}/${TOTAL} (${PCT}%) - DEFICIENTE${NC}"
fi
echo ""
EOFSSSD
    chmod +x /usr/local/bin/securizar-sssd.sh
    log_change "Creado" "/usr/local/bin/securizar-sssd.sh"

    log_info "Hardening de cliente LDAP/SSSD completado"
else
    log_skip "Hardening de cliente LDAP/SSSD"
fi

# ============================================================
# S4: SEGURIDAD DE KERBEROS
# ============================================================
log_section "S4: SEGURIDAD DE KERBEROS"

echo "Aplica hardening a la configuracion Kerberos:"
echo "  - Forzar tipos de cifrado fuertes (AES256, AES128)"
echo "  - Eliminar enctypes debiles (DES, RC4, DES3)"
echo "  - Lifetime razonable (10h) y renew (7d)"
echo "  - forwardable = false por defecto"
echo "  - dns_lookup_kdc y dns_lookup_realm"
echo "  - Logging a /var/log/krb5kdc.log"
echo "  - Permisos de keytab (0600 root:root)"
echo "  - Verificar ticket encryption"
echo ""

if ask "¿Aplicar hardening de Kerberos?"; then

    KRB5_CONF="/etc/krb5.conf"

    if [[ -f "$KRB5_CONF" ]]; then
        cp -a "$KRB5_CONF" "$BACKUP_DIR/"
        log_change "Backup" "$KRB5_CONF"

        log_info "Analizando configuracion Kerberos..."

        # ── Verificar enctypes debiles ───────────────────────
        KRB5_HAS_WEAK=false
        if grep -qiE "des-cbc|des3-cbc|rc4-hmac|arcfour" "$KRB5_CONF" 2>/dev/null; then
            KRB5_HAS_WEAK=true
            log_warn "Tipos de cifrado debiles detectados en krb5.conf"
        fi

        # ── Verificar enctypes fuertes ───────────────────────
        KRB5_HAS_STRONG=false
        if grep -qiE "aes256-cts|aes128-cts" "$KRB5_CONF" 2>/dev/null; then
            KRB5_HAS_STRONG=true
            log_info "Tipos de cifrado fuertes detectados"
        fi

        # ── Aplicar hardening ────────────────────────────────
        if ask "¿Aplicar configuracion Kerberos hardened?"; then

            # Verificar si existe seccion [libdefaults]
            if ! grep -q "^\[libdefaults\]" "$KRB5_CONF" 2>/dev/null; then
                log_warn "Seccion [libdefaults] no encontrada, anadiendo..."
                {
                    echo ""
                    echo "[libdefaults]"
                } >> "$KRB5_CONF"
            fi

            # Forzar enctypes fuertes
            if grep -q "default_tgs_enctypes\|permitted_enctypes\|default_tkt_enctypes" "$KRB5_CONF" 2>/dev/null; then
                sed -i 's/^[[:space:]]*default_tgs_enctypes.*/    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96/' "$KRB5_CONF"
                sed -i 's/^[[:space:]]*default_tkt_enctypes.*/    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96/' "$KRB5_CONF"
                sed -i 's/^[[:space:]]*permitted_enctypes.*/    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96/' "$KRB5_CONF"
            else
                sed -i '/^\[libdefaults\]/a\    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96\n    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96\n    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96' "$KRB5_CONF"
            fi
            log_change "Configurado" "Kerberos: enctypes fuertes (AES256, AES128)"

            # Eliminar enctypes debiles (comentar lineas)
            if [[ "$KRB5_HAS_WEAK" == true ]]; then
                sed -i 's/\bdes-cbc-[a-z0-9]*//g; s/\bdes3-cbc-[a-z0-9]*//g; s/\brc4-hmac//g; s/\barcfour-hmac-[a-z0-9]*//g' "$KRB5_CONF"
                log_change "Eliminado" "Kerberos: enctypes debiles (DES, DES3, RC4)"
            fi

            # Ticket lifetime
            if grep -q "ticket_lifetime" "$KRB5_CONF" 2>/dev/null; then
                sed -i 's/^[[:space:]]*ticket_lifetime.*/    ticket_lifetime = 10h/' "$KRB5_CONF"
            else
                sed -i '/^\[libdefaults\]/a\    ticket_lifetime = 10h' "$KRB5_CONF"
            fi
            log_change "Configurado" "Kerberos: ticket_lifetime = 10h"

            # Renew lifetime
            if grep -q "renew_lifetime" "$KRB5_CONF" 2>/dev/null; then
                sed -i 's/^[[:space:]]*renew_lifetime.*/    renew_lifetime = 7d/' "$KRB5_CONF"
            else
                sed -i '/^\[libdefaults\]/a\    renew_lifetime = 7d' "$KRB5_CONF"
            fi
            log_change "Configurado" "Kerberos: renew_lifetime = 7d"

            # forwardable = false
            if grep -q "forwardable" "$KRB5_CONF" 2>/dev/null; then
                sed -i 's/^[[:space:]]*forwardable.*/    forwardable = false/' "$KRB5_CONF"
            else
                sed -i '/^\[libdefaults\]/a\    forwardable = false' "$KRB5_CONF"
            fi
            log_change "Configurado" "Kerberos: forwardable = false"

            # dns_lookup_kdc = true
            if grep -q "dns_lookup_kdc" "$KRB5_CONF" 2>/dev/null; then
                sed -i 's/^[[:space:]]*dns_lookup_kdc.*/    dns_lookup_kdc = true/' "$KRB5_CONF"
            else
                sed -i '/^\[libdefaults\]/a\    dns_lookup_kdc = true' "$KRB5_CONF"
            fi
            log_change "Configurado" "Kerberos: dns_lookup_kdc = true"

            # dns_lookup_realm = false (mas seguro, requiere config explicita)
            if grep -q "dns_lookup_realm" "$KRB5_CONF" 2>/dev/null; then
                sed -i 's/^[[:space:]]*dns_lookup_realm.*/    dns_lookup_realm = false/' "$KRB5_CONF"
            else
                sed -i '/^\[libdefaults\]/a\    dns_lookup_realm = false' "$KRB5_CONF"
            fi
            log_change "Configurado" "Kerberos: dns_lookup_realm = false"

            log_info "Configuracion Kerberos hardened aplicada"
        else
            log_skip "Configuracion Kerberos hardened"
        fi

        # ── Configurar logging ───────────────────────────────
        if ! grep -q "^\[logging\]" "$KRB5_CONF" 2>/dev/null; then
            if ask "¿Configurar logging de Kerberos?"; then
                cat >> "$KRB5_CONF" << 'EOFKRBLOG'

[logging]
    default = FILE:/var/log/krb5libs.log
    kdc = FILE:/var/log/krb5kdc.log
    admin_server = FILE:/var/log/kadmind.log
EOFKRBLOG
                log_change "Configurado" "Kerberos: logging a /var/log/krb5kdc.log"
                # Crear archivos de log
                touch /var/log/krb5libs.log /var/log/krb5kdc.log /var/log/kadmind.log
                chmod 600 /var/log/krb5libs.log /var/log/krb5kdc.log /var/log/kadmind.log
            else
                log_skip "Logging de Kerberos"
            fi
        else
            log_info "Seccion [logging] ya existe en krb5.conf"
        fi

    else
        log_warn "krb5.conf no encontrado"
        if ask "¿Crear krb5.conf con plantilla hardened?"; then
            cat > "$KRB5_CONF" << 'EOFKRB5TPL'
# ============================================================
# krb5.conf - Configuracion Kerberos hardened
# Generado por securizar - Modulo 53
# ============================================================
# IMPORTANTE: Adapte default_realm, [realms] y [domain_realm]
# a su entorno antes de usar esta configuracion.
# ============================================================

[libdefaults]
    # default_realm = EXAMPLE.COM
    dns_lookup_realm = false
    dns_lookup_kdc = true
    ticket_lifetime = 10h
    renew_lifetime = 7d
    forwardable = false
    rdns = false
    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96

[logging]
    default = FILE:/var/log/krb5libs.log
    kdc = FILE:/var/log/krb5kdc.log
    admin_server = FILE:/var/log/kadmind.log

# [realms]
#     EXAMPLE.COM = {
#         kdc = kdc.example.com
#         admin_server = kdc.example.com
#     }

# [domain_realm]
#     .example.com = EXAMPLE.COM
#     example.com = EXAMPLE.COM
EOFKRB5TPL
            chmod 644 "$KRB5_CONF"
            log_change "Creado" "$KRB5_CONF (plantilla hardened)"
        else
            log_skip "Creacion de krb5.conf"
        fi
    fi

    # ── Verificar permisos de keytab ─────────────────────────
    if [[ -f /etc/krb5.keytab ]]; then
        log_info "Verificando permisos de /etc/krb5.keytab..."
        local keytab_perms keytab_owner
        keytab_perms=$(stat -c '%a' /etc/krb5.keytab 2>/dev/null)
        keytab_owner=$(stat -c '%U:%G' /etc/krb5.keytab 2>/dev/null)

        if [[ "$keytab_perms" != "600" || "$keytab_owner" != "root:root" ]]; then
            log_warn "Permisos de keytab inseguros: $keytab_perms $keytab_owner"
            if ask "¿Corregir permisos de /etc/krb5.keytab a 0600 root:root?"; then
                chmod 600 /etc/krb5.keytab
                chown root:root /etc/krb5.keytab
                log_change "Corregido" "/etc/krb5.keytab: 600 root:root"
            else
                log_skip "Correccion de permisos de keytab"
            fi
        else
            log_info "Permisos de keytab correctos: 600 root:root"
        fi
    else
        log_info "Archivo /etc/krb5.keytab no encontrado (normal si no es servidor KDC)"
    fi

    # ── Verificar ticket encryption ──────────────────────────
    if command -v klist &>/dev/null; then
        log_info "Verificando tickets Kerberos activos..."
        local klist_output=""
        klist_output=$(klist 2>/dev/null) || true
        if [[ -n "$klist_output" ]]; then
            if echo "$klist_output" | grep -qi "des-cbc\|rc4-hmac\|arcfour"; then
                log_warn "Se detectaron tickets con cifrado debil"
            else
                log_info "Tickets existentes usan cifrado aceptable"
            fi
        else
            log_info "No hay tickets Kerberos activos"
        fi
    fi

    # ── Crear script de verificacion Kerberos ────────────────
    cat > /usr/local/bin/verificar-kerberos.sh << 'EOFKRBVERIFY'
#!/bin/bash
# ============================================================
# verificar-kerberos.sh - Verificacion de seguridad Kerberos
# Generado por securizar - Modulo 53
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[X]${NC} $1"; }
section() { echo -e "\n${CYAN}── $1 ──${NC}"; }

echo ""
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  SECURIZAR - VERIFICACION DE KERBEROS${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo ""

KRB5_CONF="/etc/krb5.conf"
SCORE=0
TOTAL=0
ISSUES=()

# 1. Existencia de krb5.conf
section "1. Configuracion krb5.conf"
((TOTAL++)) || true
if [[ -f "$KRB5_CONF" ]]; then
    ((SCORE++)) || true
    info "PASS: krb5.conf existe"
else
    error "FAIL: krb5.conf no encontrado"
    ISSUES+=("krb5.conf no encontrado")
    echo -e "\n${RED}No se puede continuar sin krb5.conf${NC}"
    exit 1
fi

# 2. Enctypes fuertes
section "2. Tipos de cifrado"
((TOTAL++)) || true
if grep -qiE "aes256-cts|aes128-cts" "$KRB5_CONF" 2>/dev/null; then
    ((SCORE++)) || true
    info "PASS: Enctypes fuertes configurados"
else
    error "FAIL: No se detectaron enctypes AES"
    ISSUES+=("Enctypes AES no configurados")
fi

# 3. Enctypes debiles
((TOTAL++)) || true
if grep -qiE "des-cbc|des3-cbc|rc4-hmac|arcfour" "$KRB5_CONF" 2>/dev/null; then
    error "FAIL: Enctypes debiles presentes"
    ISSUES+=("Enctypes debiles: DES/DES3/RC4")
else
    ((SCORE++)) || true
    info "PASS: Sin enctypes debiles"
fi

# 4. Ticket lifetime razonable
section "3. Lifetimes"
((TOTAL++)) || true
if grep -q "ticket_lifetime" "$KRB5_CONF" 2>/dev/null; then
    TKT_LIFE=$(grep "ticket_lifetime" "$KRB5_CONF" | head -1 | awk '{print $NF}')
    ((SCORE++)) || true
    info "PASS: ticket_lifetime = $TKT_LIFE"
else
    warn "FAIL: ticket_lifetime no configurado"
    ISSUES+=("ticket_lifetime no configurado")
fi

# 5. Forwardable
section "4. Forwardable"
((TOTAL++)) || true
if grep -qi "forwardable.*=.*false" "$KRB5_CONF" 2>/dev/null; then
    ((SCORE++)) || true
    info "PASS: forwardable = false"
elif grep -qi "forwardable.*=.*true" "$KRB5_CONF" 2>/dev/null; then
    warn "FAIL: forwardable = true (riesgo de relay)"
    ISSUES+=("forwardable = true")
else
    warn "FAIL: forwardable no configurado (default puede ser true)"
    ISSUES+=("forwardable no configurado")
fi

# 6. Permisos keytab
section "5. Permisos keytab"
((TOTAL++)) || true
if [[ -f /etc/krb5.keytab ]]; then
    PERMS=$(stat -c '%a' /etc/krb5.keytab 2>/dev/null)
    OWNER=$(stat -c '%U:%G' /etc/krb5.keytab 2>/dev/null)
    if [[ "$PERMS" == "600" && "$OWNER" == "root:root" ]]; then
        ((SCORE++)) || true
        info "PASS: keytab permisos correctos ($PERMS $OWNER)"
    else
        error "FAIL: keytab permisos: $PERMS $OWNER (esperado: 600 root:root)"
        ISSUES+=("keytab permisos inseguros")
    fi
else
    info "keytab no encontrado (puede no ser necesario)"
    ((SCORE++)) || true
fi

# 7. Logging configurado
section "6. Logging"
((TOTAL++)) || true
if grep -q "^\[logging\]" "$KRB5_CONF" 2>/dev/null; then
    ((SCORE++)) || true
    info "PASS: Logging configurado"
else
    warn "FAIL: Logging no configurado"
    ISSUES+=("Logging Kerberos no configurado")
fi

# 8. Tickets activos
section "7. Tickets activos"
((TOTAL++)) || true
if command -v klist &>/dev/null; then
    KLIST_OUT=$(klist 2>/dev/null) || KLIST_OUT=""
    if [[ -n "$KLIST_OUT" ]]; then
        info "Tickets activos encontrados:"
        echo "$KLIST_OUT" | head -10
        if echo "$KLIST_OUT" | grep -qi "des-cbc\|rc4-hmac\|arcfour"; then
            error "Tickets con cifrado debil detectados"
            ISSUES+=("Tickets con cifrado debil")
        else
            ((SCORE++)) || true
            info "PASS: Cifrado de tickets aceptable"
        fi
    else
        ((SCORE++)) || true
        info "Sin tickets activos (verificacion N/A)"
    fi
else
    ((SCORE++)) || true
    info "klist no disponible"
fi

# Resumen
echo ""
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
PCT=$((SCORE * 100 / TOTAL))
if [[ $PCT -ge 80 ]]; then
    echo -e "  ${BOLD}KERBEROS: ${GREEN}${SCORE}/${TOTAL} (${PCT}%) - BUENO${NC}"
elif [[ $PCT -ge 50 ]]; then
    echo -e "  ${BOLD}KERBEROS: ${YELLOW}${SCORE}/${TOTAL} (${PCT}%) - MEJORABLE${NC}"
else
    echo -e "  ${BOLD}KERBEROS: ${RED}${SCORE}/${TOTAL} (${PCT}%) - DEFICIENTE${NC}"
fi

if [[ ${#ISSUES[@]} -gt 0 ]]; then
    echo ""
    echo -e "${BOLD}  Problemas detectados:${NC}"
    for issue in "${ISSUES[@]}"; do
        echo -e "    ${RED}- $issue${NC}"
    done
fi
echo ""
EOFKRBVERIFY
    chmod +x /usr/local/bin/verificar-kerberos.sh
    log_change "Creado" "/usr/local/bin/verificar-kerberos.sh"

    log_info "Seguridad de Kerberos completada"
else
    log_skip "Seguridad de Kerberos"
fi

# ============================================================
# S5: FreeIPA SERVER HARDENING
# ============================================================
log_section "S5: FreeIPA SERVER HARDENING"

echo "Verifica y fortalece la seguridad de FreeIPA Server:"
echo "  - Salud del sistema de certificados"
echo "  - Estado de replicacion (multi-master)"
echo "  - Politica de contrasenas (minlength, complejidad, historial)"
echo "  - Reglas HBAC (control de acceso basado en host)"
echo "  - Reglas sudo en FreeIPA"
echo "  - Seguridad de zonas DNS (si FreeIPA gestiona DNS)"
echo "  - Perfiles de certificados"
echo ""

if ask "¿Verificar y fortalecer FreeIPA Server?"; then

    # ── Crear script de auditoria FreeIPA ────────────────────
    cat > /usr/local/bin/auditar-freeipa.sh << 'EOFFREEIPA'
#!/bin/bash
# ============================================================
# auditar-freeipa.sh - Auditoria de seguridad FreeIPA
# Generado por securizar - Modulo 53
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[X]${NC} $1"; }
section() { echo -e "\n${CYAN}── $1 ──${NC}"; }

if [[ $EUID -ne 0 ]]; then
    error "Ejecutar como root: sudo $0"
    exit 1
fi

echo ""
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  SECURIZAR - AUDITORIA DE FREEIPA SERVER${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo ""

SCORE=0
TOTAL=0
ISSUES=()
REPORT_FILE="/var/log/securizar/auditoria-freeipa-$(date +%Y%m%d-%H%M%S).log"
mkdir -p /var/log/securizar

# Verificar que FreeIPA esta instalado
if ! command -v ipa &>/dev/null; then
    error "FreeIPA no esta instalado en este sistema"
    exit 1
fi

# Verificar que tenemos ticket Kerberos
if ! klist &>/dev/null 2>&1; then
    warn "No hay ticket Kerberos activo. Intentando kinit admin..."
    echo "Ejecute 'kinit admin' antes de este script para mejores resultados"
fi

HAS_TICKET=false
if klist &>/dev/null 2>&1; then
    HAS_TICKET=true
fi

# ── 1. Salud del sistema de certificados ────────────────────
section "1. Sistema de certificados"
((TOTAL++)) || true

if command -v ipa-healthcheck &>/dev/null; then
    CERT_HEALTH=$(ipa-healthcheck --source=ipahealthcheck.ipa.certs 2>/dev/null) || CERT_HEALTH=""
    if [[ -n "$CERT_HEALTH" ]]; then
        CERT_ERRORS=$(echo "$CERT_HEALTH" | python3 -c "import sys,json; data=json.load(sys.stdin); print(sum(1 for d in data if d.get('result','') == 'ERROR'))" 2>/dev/null) || CERT_ERRORS="?"
        CERT_WARNINGS=$(echo "$CERT_HEALTH" | python3 -c "import sys,json; data=json.load(sys.stdin); print(sum(1 for d in data if d.get('result','') == 'WARNING'))" 2>/dev/null) || CERT_WARNINGS="?"
        if [[ "$CERT_ERRORS" == "0" || "$CERT_ERRORS" == "?" ]]; then
            ((SCORE++)) || true
            info "PASS: Certificados sin errores criticos (advertencias: $CERT_WARNINGS)"
        else
            error "FAIL: $CERT_ERRORS errores de certificado detectados"
            ISSUES+=("Errores en sistema de certificados: $CERT_ERRORS")
        fi
    else
        warn "No se pudo ejecutar healthcheck de certificados"
        ISSUES+=("healthcheck de certificados no disponible")
    fi
else
    warn "ipa-healthcheck no disponible. Verificacion manual..."
    # Verificar certificados basicos
    if [[ -d /etc/ipa ]]; then
        IPA_CERT_EXPIRY=""
        for cert_file in /etc/ipa/ca.crt /var/lib/ipa/certs/httpd.crt; do
            if [[ -f "$cert_file" ]]; then
                EXPIRY=$(openssl x509 -enddate -noout -in "$cert_file" 2>/dev/null | cut -d= -f2) || EXPIRY=""
                if [[ -n "$EXPIRY" ]]; then
                    EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null) || EXPIRY_EPOCH=0
                    NOW_EPOCH=$(date +%s)
                    DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
                    if [[ $DAYS_LEFT -lt 30 ]]; then
                        warn "Certificado $cert_file expira en $DAYS_LEFT dias"
                        ISSUES+=("Certificado $cert_file expira pronto")
                    else
                        info "Certificado $cert_file: $DAYS_LEFT dias restantes"
                    fi
                fi
            fi
        done
        ((SCORE++)) || true
    fi
fi

# ── 2. Estado de replicacion ────────────────────────────────
section "2. Replicacion"
((TOTAL++)) || true

if [[ "$HAS_TICKET" == true ]]; then
    REPL_STATUS=$(ipa topologysegment-find 2>/dev/null) || REPL_STATUS=""
    if [[ -n "$REPL_STATUS" ]]; then
        SEGMENT_COUNT=$(echo "$REPL_STATUS" | grep -c "Segment name:" 2>/dev/null) || SEGMENT_COUNT=0
        if [[ $SEGMENT_COUNT -gt 0 ]]; then
            ((SCORE++)) || true
            info "PASS: $SEGMENT_COUNT segmentos de replicacion encontrados"
        else
            info "Servidor unico (sin replicacion)"
            ((SCORE++)) || true
        fi
    else
        # Intentar con csreplica
        if command -v ipa-csreplica-manage &>/dev/null; then
            REPL_LIST=$(ipa-csreplica-manage list 2>/dev/null) || REPL_LIST=""
            if [[ -n "$REPL_LIST" ]]; then
                info "Replicas detectadas:"
                echo "$REPL_LIST" | head -5
                ((SCORE++)) || true
            else
                info "Sin replicas configuradas"
                ((SCORE++)) || true
            fi
        else
            ((SCORE++)) || true
            info "Verificacion de replicacion no disponible"
        fi
    fi
else
    warn "Se necesita ticket Kerberos para verificar replicacion"
    ISSUES+=("Sin ticket Kerberos para verificar replicacion")
fi

# ── 3. Politica de contrasenas ──────────────────────────────
section "3. Politica de contrasenas"
((TOTAL++)) || true

if [[ "$HAS_TICKET" == true ]]; then
    PW_POLICY=$(ipa pwpolicy-show 2>/dev/null) || PW_POLICY=""
    if [[ -n "$PW_POLICY" ]]; then
        MIN_LENGTH=$(echo "$PW_POLICY" | grep -i "min length" | awk '{print $NF}') || MIN_LENGTH="?"
        MIN_CLASSES=$(echo "$PW_POLICY" | grep -i "min.*class" | awk '{print $NF}') || MIN_CLASSES="?"
        HISTORY=$(echo "$PW_POLICY" | grep -i "history" | awk '{print $NF}') || HISTORY="?"
        MAX_LIFE=$(echo "$PW_POLICY" | grep -i "max.*life" | awk '{print $NF}') || MAX_LIFE="?"
        LOCKOUT=$(echo "$PW_POLICY" | grep -i "max.*fail" | awk '{print $NF}') || LOCKOUT="?"

        info "Min length: $MIN_LENGTH"
        info "Min classes: $MIN_CLASSES"
        info "History: $HISTORY"
        info "Max lifetime: $MAX_LIFE days"
        info "Max failures: $LOCKOUT"

        PW_SCORE=0
        [[ -n "$MIN_LENGTH" && "$MIN_LENGTH" != "?" && "$MIN_LENGTH" -ge 12 ]] && ((PW_SCORE++)) || true
        [[ -n "$MIN_CLASSES" && "$MIN_CLASSES" != "?" && "$MIN_CLASSES" -ge 3 ]] && ((PW_SCORE++)) || true
        [[ -n "$HISTORY" && "$HISTORY" != "?" && "$HISTORY" -ge 6 ]] && ((PW_SCORE++)) || true

        if [[ $PW_SCORE -ge 2 ]]; then
            ((SCORE++)) || true
            info "PASS: Politica de contrasenas adecuada"
        else
            warn "FAIL: Politica de contrasenas debil"
            ISSUES+=("Politica de contrasenas insuficiente")
        fi
    else
        warn "No se pudo obtener politica de contrasenas"
        ISSUES+=("Politica de contrasenas no accesible")
    fi
else
    warn "Se necesita ticket Kerberos para verificar politica"
    ISSUES+=("Sin ticket Kerberos")
fi

# ── 4. Reglas HBAC ──────────────────────────────────────────
section "4. Reglas HBAC"
((TOTAL++)) || true

if [[ "$HAS_TICKET" == true ]]; then
    HBAC_RULES=$(ipa hbacrule-find 2>/dev/null) || HBAC_RULES=""
    if [[ -n "$HBAC_RULES" ]]; then
        HBAC_COUNT=$(echo "$HBAC_RULES" | grep -c "Rule name:" 2>/dev/null) || HBAC_COUNT=0
        info "Reglas HBAC encontradas: $HBAC_COUNT"

        # Verificar si existe regla allow_all (peligrosa)
        if echo "$HBAC_RULES" | grep -qi "allow_all"; then
            ALLOW_ALL_STATUS=$(ipa hbacrule-show allow_all 2>/dev/null | grep -i "enabled" | awk '{print $NF}') || ALLOW_ALL_STATUS=""
            if [[ "$ALLOW_ALL_STATUS" == "TRUE" || "$ALLOW_ALL_STATUS" == "True" ]]; then
                error "REGLA allow_all HABILITADA - permite acceso irrestricto"
                ISSUES+=("HBAC allow_all habilitada")
            else
                ((SCORE++)) || true
                info "PASS: Regla allow_all deshabilitada"
            fi
        else
            ((SCORE++)) || true
            info "PASS: No existe regla allow_all"
        fi
    else
        warn "No se pudieron obtener reglas HBAC"
        ISSUES+=("HBAC no accesible")
    fi
else
    warn "Se necesita ticket Kerberos para verificar HBAC"
    ISSUES+=("Sin ticket Kerberos")
fi

# ── 5. Reglas sudo ──────────────────────────────────────────
section "5. Reglas sudo"
((TOTAL++)) || true

if [[ "$HAS_TICKET" == true ]]; then
    SUDO_RULES=$(ipa sudorule-find 2>/dev/null) || SUDO_RULES=""
    if [[ -n "$SUDO_RULES" ]]; then
        SUDO_COUNT=$(echo "$SUDO_RULES" | grep -c "Rule name:" 2>/dev/null) || SUDO_COUNT=0
        info "Reglas sudo en FreeIPA: $SUDO_COUNT"

        # Verificar si hay reglas ALL
        if echo "$SUDO_RULES" | grep -qi "ALL"; then
            warn "Se detectaron reglas sudo con 'ALL' - revisar manualmente"
            ISSUES+=("Reglas sudo con ALL detectadas")
        else
            ((SCORE++)) || true
            info "PASS: No se detectaron reglas sudo con ALL irrestricto"
        fi
    else
        ((SCORE++)) || true
        info "No se encontraron reglas sudo en FreeIPA"
    fi
else
    warn "Se necesita ticket Kerberos"
    ISSUES+=("Sin ticket Kerberos")
fi

# ── 6. DNS ──────────────────────────────────────────────────
section "6. Zonas DNS"
((TOTAL++)) || true

if [[ "$HAS_TICKET" == true ]]; then
    DNS_ZONES=$(ipa dnszone-find 2>/dev/null) || DNS_ZONES=""
    if [[ -n "$DNS_ZONES" ]]; then
        ZONE_COUNT=$(echo "$DNS_ZONES" | grep -c "Zone name:" 2>/dev/null) || ZONE_COUNT=0
        info "Zonas DNS gestionadas: $ZONE_COUNT"

        # Verificar DNSSEC
        if echo "$DNS_ZONES" | grep -qi "dnssec"; then
            ((SCORE++)) || true
            info "PASS: DNSSEC configurado"
        else
            warn "DNSSEC no configurado en zonas DNS"
            ISSUES+=("DNSSEC no habilitado")
        fi
    else
        ((SCORE++)) || true
        info "FreeIPA no gestiona DNS"
    fi
else
    warn "Se necesita ticket Kerberos"
    ISSUES+=("Sin ticket Kerberos")
fi

# ── 7. Perfiles de certificado ──────────────────────────────
section "7. Perfiles de certificado"
((TOTAL++)) || true

if [[ "$HAS_TICKET" == true ]]; then
    CERT_PROFILES=$(ipa certprofile-find 2>/dev/null) || CERT_PROFILES=""
    if [[ -n "$CERT_PROFILES" ]]; then
        PROFILE_COUNT=$(echo "$CERT_PROFILES" | grep -c "Profile ID:" 2>/dev/null) || PROFILE_COUNT=0
        ((SCORE++)) || true
        info "PASS: Perfiles de certificado encontrados: $PROFILE_COUNT"
    else
        ((SCORE++)) || true
        info "Perfiles de certificado por defecto"
    fi
else
    ((SCORE++)) || true
    info "Verificacion de perfiles requiere ticket Kerberos"
fi

# ── Resumen ──────────────────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  RESUMEN AUDITORIA FreeIPA${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo ""

if [[ $TOTAL -gt 0 ]]; then
    PCT=$((SCORE * 100 / TOTAL))
    if [[ $PCT -ge 80 ]]; then
        echo -e "  ${BOLD}FreeIPA: ${GREEN}${SCORE}/${TOTAL} (${PCT}%) - BUENO${NC}"
    elif [[ $PCT -ge 50 ]]; then
        echo -e "  ${BOLD}FreeIPA: ${YELLOW}${SCORE}/${TOTAL} (${PCT}%) - MEJORABLE${NC}"
    else
        echo -e "  ${BOLD}FreeIPA: ${RED}${SCORE}/${TOTAL} (${PCT}%) - DEFICIENTE${NC}"
    fi
fi

if [[ ${#ISSUES[@]} -gt 0 ]]; then
    echo ""
    echo -e "${BOLD}  Problemas detectados:${NC}"
    for issue in "${ISSUES[@]}"; do
        echo -e "    ${RED}- $issue${NC}"
    done
fi

# Guardar reporte
{
    echo "AUDITORIA DE SEGURIDAD FREEIPA"
    echo "Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Hostname: $(hostname)"
    echo ""
    echo "Puntuacion: ${SCORE}/${TOTAL}"
    echo ""
    if [[ ${#ISSUES[@]} -gt 0 ]]; then
        echo "Problemas:"
        for issue in "${ISSUES[@]}"; do
            echo "  - $issue"
        done
    fi
} > "$REPORT_FILE"
chmod 600 "$REPORT_FILE"
echo ""
echo "Reporte guardado en: $REPORT_FILE"
echo ""
EOFFREEIPA
    chmod +x /usr/local/bin/auditar-freeipa.sh
    log_change "Creado" "/usr/local/bin/auditar-freeipa.sh"

    if [[ "$HAS_FREEIPA_SERVER" == true ]]; then
        log_info "FreeIPA Server detectado. Ejecutando auditoria..."
        /usr/local/bin/auditar-freeipa.sh 2>/dev/null || true
    else
        log_info "FreeIPA Server no detectado en este sistema"
        log_info "El script auditar-freeipa.sh queda disponible para uso futuro"
    fi

    log_info "FreeIPA Server hardening completado"
else
    log_skip "FreeIPA Server hardening"
fi

# ============================================================
# S6: SAMBA/WINBIND E INTEGRACION AD
# ============================================================
log_section "S6: SAMBA/WINBIND E INTEGRACION AD"

echo "Aplica hardening a Samba/Winbind para integracion AD:"
echo "  - Protocolo minimo SMB3 (deshabilitar SMB1, SMB2)"
echo "  - Firma obligatoria (server signing = mandatory)"
echo "  - Cifrado obligatorio (smb encrypt = required)"
echo "  - winbind use default domain"
echo "  - Verificar configuracion idmap"
echo "  - Permisos de shares y seguridad"
echo "  - Deshabilitar sesiones nulas"
echo "  - Configuracion registry vs smb.conf"
echo ""

if ask "¿Aplicar hardening de Samba/Winbind?"; then

    SMB_CONF="/etc/samba/smb.conf"

    if [[ "$HAS_SAMBA" == true ]] || [[ -f "$SMB_CONF" ]]; then
        log_info "Procediendo con hardening de Samba..."

        if [[ -f "$SMB_CONF" ]]; then
            cp -a "$SMB_CONF" "$BACKUP_DIR/"
            log_change "Backup" "$SMB_CONF"

            # Helper para configurar parametro en smb.conf
            smb_set_param() {
                local param="$1"
                local value="$2"
                local file="$SMB_CONF"
                if grep -qi "^[[:space:]]*${param}" "$file" 2>/dev/null; then
                    sed -i "s|^[[:space:]]*${param}[[:space:]]*=.*|    ${param} = ${value}|i" "$file"
                else
                    # Insertar en seccion [global]
                    if grep -q "^\[global\]" "$file" 2>/dev/null; then
                        sed -i "/^\[global\]/a\\    ${param} = ${value}" "$file"
                    else
                        {
                            echo "[global]"
                            echo "    ${param} = ${value}"
                        } >> "$file"
                    fi
                fi
            }

            # ── Protocolo minimo SMB3 ────────────────────────
            if ask "¿Forzar protocolo minimo SMB3 (deshabilitara SMB1/SMB2)?"; then
                smb_set_param "server min protocol" "SMB3"
                smb_set_param "client min protocol" "SMB3"
                log_change "Configurado" "Samba: server/client min protocol = SMB3"

                # Deshabilitar SMB1 explicitamente
                smb_set_param "server smb1 unix extensions" "no"
                log_change "Configurado" "Samba: SMB1 unix extensions = no"
            else
                log_skip "Protocolo minimo SMB3"
            fi

            # ── Firma obligatoria ────────────────────────────
            smb_set_param "server signing" "mandatory"
            smb_set_param "client signing" "mandatory"
            log_change "Configurado" "Samba: signing = mandatory (server + client)"

            # ── Cifrado obligatorio ──────────────────────────
            smb_set_param "smb encrypt" "required"
            log_change "Configurado" "Samba: smb encrypt = required"

            # ── Deshabilitar sesiones nulas ───────────────────
            smb_set_param "restrict anonymous" "2"
            smb_set_param "map to guest" "never"
            smb_set_param "null passwords" "no"
            log_change "Configurado" "Samba: sesiones nulas deshabilitadas"

            # ── Deshabilitar cuentas de invitado ─────────────
            smb_set_param "guest account" "nobody"
            smb_set_param "usershare allow guests" "no"
            log_change "Configurado" "Samba: acceso invitado deshabilitado"

            # ── Logging adecuado ─────────────────────────────
            smb_set_param "log level" "1 auth:3 passdb:3"
            smb_set_param "log file" "/var/log/samba/log.%m"
            smb_set_param "max log size" "10000"
            log_change "Configurado" "Samba: logging con nivel auth:3 passdb:3"

            # ── Winbind ──────────────────────────────────────
            if [[ "$HAS_WINBIND" == true ]]; then
                log_info "Aplicando configuracion Winbind..."
                smb_set_param "winbind use default domain" "yes"
                smb_set_param "winbind offline logon" "yes"
                smb_set_param "winbind refresh tickets" "yes"
                log_change "Configurado" "Samba: winbind use default domain + offline logon"
            fi

            # ── Verificar idmap ──────────────────────────────
            if grep -qi "idmap" "$SMB_CONF" 2>/dev/null; then
                log_info "Configuracion idmap detectada:"
                grep -i "idmap" "$SMB_CONF" 2>/dev/null | head -10 | while IFS= read -r line; do
                    log_info "  $line"
                done
            else
                log_warn "idmap no configurado en smb.conf"
                if [[ "$HAS_WINBIND" == true ]]; then
                    log_warn "Se recomienda configurar idmap para integracion AD"
                fi
            fi

            # ── Verificar shares ─────────────────────────────
            log_info "Verificando shares configurados..."
            SHARE_COUNT=$(grep -c "^\[" "$SMB_CONF" 2>/dev/null) || SHARE_COUNT=0
            # Excluir [global], [homes], [printers]
            CUSTOM_SHARES=$(grep "^\[" "$SMB_CONF" 2>/dev/null | grep -cvE "\[global\]|\[homes\]|\[printers\]") || CUSTOM_SHARES=0
            log_info "Shares personalizados: $CUSTOM_SHARES"

            # Verificar si hay shares con guest ok = yes
            if grep -A5 "^\[" "$SMB_CONF" 2>/dev/null | grep -qi "guest ok.*=.*yes"; then
                log_warn "Se detectaron shares con acceso de invitado habilitado"
                log_warn "Revise manualmente y deshabilite 'guest ok = yes' donde sea posible"
            fi

            # ── Verificar config registry ────────────────────
            if grep -qi "config backend.*=.*registry\|include.*=.*registry" "$SMB_CONF" 2>/dev/null; then
                log_warn "Configuracion basada en registry detectada"
                log_warn "Verifique tambien la configuracion via 'net conf list'"
            fi

            # ── Verificar configuracion con testparm ─────────
            if command -v testparm &>/dev/null; then
                log_info "Verificando configuracion con testparm..."
                if testparm -s 2>/dev/null | grep -qi "error\|warning"; then
                    log_warn "testparm reporta errores/advertencias. Revise manualmente."
                else
                    log_info "Configuracion Samba valida segun testparm"
                fi
            fi

            # ── Reiniciar Samba si activo ────────────────────
            local smb_service="smb"
            if service_is_active smbd; then
                smb_service="smbd"
            fi
            if service_is_active "$smb_service" || service_is_active smbd; then
                if ask "¿Reiniciar Samba para aplicar cambios?"; then
                    systemctl restart "$smb_service" 2>/dev/null || systemctl restart smbd 2>/dev/null || true
                    if [[ "$HAS_WINBIND" == true ]]; then
                        systemctl restart winbind 2>/dev/null || true
                    fi
                    log_change "Reiniciado" "servicios Samba"
                else
                    log_skip "Reinicio de Samba"
                fi
            fi

        else
            log_warn "smb.conf no encontrado"
            log_info "Creando configuracion Samba hardened base..."

            mkdir -p /etc/samba
            cat > "$SMB_CONF" << 'EOFSMBTPL'
# ============================================================
# smb.conf - Plantilla Samba hardened
# Generado por securizar - Modulo 53
# ============================================================
# Adapte a su entorno antes de activar Samba.
# ============================================================

[global]
    workgroup = WORKGROUP
    # realm = EXAMPLE.COM
    # security = ads

    # Protocolo minimo
    server min protocol = SMB3
    client min protocol = SMB3

    # Firma y cifrado obligatorios
    server signing = mandatory
    client signing = mandatory
    smb encrypt = required

    # Deshabilitar sesiones nulas
    restrict anonymous = 2
    map to guest = never
    null passwords = no

    # Deshabilitar invitados
    usershare allow guests = no

    # Logging
    log level = 1 auth:3 passdb:3
    log file = /var/log/samba/log.%m
    max log size = 10000

    # Winbind (descomentar si AD)
    # winbind use default domain = yes
    # winbind offline logon = yes
    # winbind refresh tickets = yes

    # idmap (descomentar y adaptar si AD)
    # idmap config * : backend = tdb
    # idmap config * : range = 3000-7999
    # idmap config EXAMPLE : backend = rid
    # idmap config EXAMPLE : range = 10000-999999
EOFSMBTPL
            chmod 644 "$SMB_CONF"
            log_change "Creado" "$SMB_CONF (plantilla hardened)"
        fi
    else
        log_info "Samba no detectado. Creando scripts para uso futuro."
    fi

    # ── Crear script de hardening de Samba ───────────────────
    cat > /usr/local/bin/securizar-samba.sh << 'EOFSAMBA'
#!/bin/bash
# ============================================================
# securizar-samba.sh - Verificacion de hardening Samba/Winbind
# Generado por securizar - Modulo 53
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[X]${NC} $1"; }
section() { echo -e "\n${CYAN}── $1 ──${NC}"; }

echo ""
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  SECURIZAR - VERIFICACION DE SAMBA/WINBIND${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo ""

SMB_CONF="/etc/samba/smb.conf"
SCORE=0
TOTAL=0
ISSUES=()

if [[ ! -f "$SMB_CONF" ]]; then
    error "smb.conf no encontrado"
    exit 1
fi

# 1. Protocolo minimo
section "1. Protocolo minimo"
((TOTAL++)) || true
MIN_PROTO=$(grep -i "server min protocol" "$SMB_CONF" 2>/dev/null | awk -F= '{print $2}' | xargs) || MIN_PROTO=""
if [[ "$MIN_PROTO" == "SMB3" || "$MIN_PROTO" == "SMB3_00" || "$MIN_PROTO" == "SMB3_11" ]]; then
    ((SCORE++)) || true
    info "PASS: Protocolo minimo: $MIN_PROTO"
else
    error "FAIL: Protocolo minimo: ${MIN_PROTO:-no configurado}"
    ISSUES+=("Protocolo minimo no es SMB3")
fi

# 2. Firma obligatoria
section "2. Firma obligatoria"
((TOTAL++)) || true
SERVER_SIGNING=$(grep -i "server signing" "$SMB_CONF" 2>/dev/null | awk -F= '{print $2}' | xargs) || SERVER_SIGNING=""
if [[ "$SERVER_SIGNING" == "mandatory" || "$SERVER_SIGNING" == "required" ]]; then
    ((SCORE++)) || true
    info "PASS: Server signing = $SERVER_SIGNING"
else
    error "FAIL: Server signing: ${SERVER_SIGNING:-no configurado}"
    ISSUES+=("Server signing no es mandatory")
fi

# 3. Cifrado SMB
section "3. Cifrado SMB"
((TOTAL++)) || true
SMB_ENCRYPT=$(grep -i "smb encrypt" "$SMB_CONF" 2>/dev/null | awk -F= '{print $2}' | xargs) || SMB_ENCRYPT=""
if [[ "$SMB_ENCRYPT" == "required" || "$SMB_ENCRYPT" == "mandatory" ]]; then
    ((SCORE++)) || true
    info "PASS: SMB encrypt = $SMB_ENCRYPT"
else
    error "FAIL: SMB encrypt: ${SMB_ENCRYPT:-no configurado}"
    ISSUES+=("SMB encrypt no es required")
fi

# 4. Sesiones nulas
section "4. Sesiones nulas"
((TOTAL++)) || true
RESTRICT_ANON=$(grep -i "restrict anonymous" "$SMB_CONF" 2>/dev/null | awk -F= '{print $2}' | xargs) || RESTRICT_ANON=""
if [[ "$RESTRICT_ANON" == "2" ]]; then
    ((SCORE++)) || true
    info "PASS: restrict anonymous = 2"
else
    error "FAIL: restrict anonymous: ${RESTRICT_ANON:-no configurado}"
    ISSUES+=("restrict anonymous no es 2")
fi

# 5. Map to guest
section "5. Map to guest"
((TOTAL++)) || true
MAP_GUEST=$(grep -i "map to guest" "$SMB_CONF" 2>/dev/null | awk -F= '{print $2}' | xargs) || MAP_GUEST=""
if [[ "$MAP_GUEST" == "never" || "$MAP_GUEST" == "Never" ]]; then
    ((SCORE++)) || true
    info "PASS: map to guest = never"
else
    error "FAIL: map to guest: ${MAP_GUEST:-no configurado}"
    ISSUES+=("map to guest no es 'never'")
fi

# 6. Null passwords
section "6. Null passwords"
((TOTAL++)) || true
NULL_PW=$(grep -i "null passwords" "$SMB_CONF" 2>/dev/null | awk -F= '{print $2}' | xargs) || NULL_PW=""
if [[ "$NULL_PW" == "no" || "$NULL_PW" == "No" ]]; then
    ((SCORE++)) || true
    info "PASS: null passwords = no"
else
    warn "FAIL: null passwords: ${NULL_PW:-no configurado (default: no)}"
    if [[ -z "$NULL_PW" ]]; then
        ((SCORE++)) || true  # default es no
    else
        ISSUES+=("null passwords no deshabilitado")
    fi
fi

# 7. Shares con acceso invitado
section "7. Shares con acceso invitado"
((TOTAL++)) || true
if grep -A10 "^\[" "$SMB_CONF" 2>/dev/null | grep -qi "guest ok.*=.*yes"; then
    error "FAIL: Shares con acceso invitado detectados"
    ISSUES+=("Shares con guest ok = yes")
else
    ((SCORE++)) || true
    info "PASS: Sin shares con acceso invitado"
fi

# 8. testparm
section "8. Validacion testparm"
((TOTAL++)) || true
if command -v testparm &>/dev/null; then
    TESTPARM_OUT=$(testparm -s 2>&1) || true
    if echo "$TESTPARM_OUT" | grep -qi "error"; then
        error "FAIL: testparm reporta errores"
        ISSUES+=("testparm reporta errores")
    else
        ((SCORE++)) || true
        info "PASS: testparm sin errores"
    fi
else
    ((SCORE++)) || true
    info "testparm no disponible (samba-common no instalado)"
fi

# Resumen
echo ""
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
PCT=$((SCORE * 100 / TOTAL))
if [[ $PCT -ge 80 ]]; then
    echo -e "  ${BOLD}SAMBA: ${GREEN}${SCORE}/${TOTAL} (${PCT}%) - BUENO${NC}"
elif [[ $PCT -ge 50 ]]; then
    echo -e "  ${BOLD}SAMBA: ${YELLOW}${SCORE}/${TOTAL} (${PCT}%) - MEJORABLE${NC}"
else
    echo -e "  ${BOLD}SAMBA: ${RED}${SCORE}/${TOTAL} (${PCT}%) - DEFICIENTE${NC}"
fi

if [[ ${#ISSUES[@]} -gt 0 ]]; then
    echo ""
    echo -e "${BOLD}  Problemas detectados:${NC}"
    for issue in "${ISSUES[@]}"; do
        echo -e "    ${RED}- $issue${NC}"
    done
fi
echo ""
EOFSAMBA
    chmod +x /usr/local/bin/securizar-samba.sh
    log_change "Creado" "/usr/local/bin/securizar-samba.sh"

    log_info "Samba/Winbind hardening completado"
else
    log_skip "Samba/Winbind hardening"
fi

# ============================================================
# S7: CONTROL DE ACCESO BASADO EN LDAP
# ============================================================
log_section "S7: CONTROL DE ACCESO BASADO EN LDAP"

echo "Configura control de acceso para usuarios LDAP:"
echo "  - Integracion PAM (pam_ldap / pam_sss)"
echo "  - pam_faillock para usuarios LDAP"
echo "  - Complejidad de contrasena para usuarios LDAP"
echo "  - Creacion automatica de home (pam_mkhomedir/oddjob)"
echo "  - Integracion sudo con LDAP/SSSD"
echo "  - Ordenamiento nsswitch.conf (sss antes de files)"
echo ""

if ask "¿Configurar control de acceso basado en LDAP?"; then

    # ── Verificar integracion PAM ────────────────────────────
    log_info "Analizando integracion PAM para LDAP..."

    PAM_SSS_INSTALLED=false
    PAM_LDAP_INSTALLED=false

    # Detectar pam_sss
    if find /lib/security/ /lib64/security/ /usr/lib/security/ /usr/lib64/security/ \
            -name "pam_sss.so" -print -quit 2>/dev/null | grep -q "pam_sss"; then
        PAM_SSS_INSTALLED=true
        log_info "pam_sss.so detectado"
    fi

    # Detectar pam_ldap
    if find /lib/security/ /lib64/security/ /usr/lib/security/ /usr/lib64/security/ \
            -name "pam_ldap.so" -print -quit 2>/dev/null | grep -q "pam_ldap"; then
        PAM_LDAP_INSTALLED=true
        log_info "pam_ldap.so detectado"
    fi

    if [[ "$PAM_SSS_INSTALLED" == false && "$PAM_LDAP_INSTALLED" == false ]]; then
        log_warn "Ni pam_sss ni pam_ldap detectados"
        log_info "La autenticacion LDAP via PAM no esta configurada"
    fi

    # ── Verificar pam_faillock para usuarios LDAP ────────────
    log_info "Verificando pam_faillock..."
    FAILLOCK_CONFIGURED=false

    for pam_file in /etc/pam.d/system-auth /etc/pam.d/common-auth /etc/pam.d/password-auth; do
        if [[ -f "$pam_file" ]]; then
            if grep -q "pam_faillock" "$pam_file" 2>/dev/null; then
                FAILLOCK_CONFIGURED=true
                log_info "pam_faillock configurado en $pam_file"
            fi
        fi
    done

    if [[ "$FAILLOCK_CONFIGURED" == false ]]; then
        log_warn "pam_faillock no configurado"
        log_warn "Los usuarios LDAP podrian ser vulnerables a ataques de fuerza bruta"
        log_info "Considere ejecutar el modulo de hardening de cuentas para configurar faillock"
    fi

    # ── Verificar complejidad de contrasena ──────────────────
    log_info "Verificando complejidad de contrasena..."
    PWQUALITY_OK=false

    for pam_file in /etc/pam.d/system-auth /etc/pam.d/common-password /etc/pam.d/password-auth; do
        if [[ -f "$pam_file" ]]; then
            if grep -q "pam_pwquality\|pam_cracklib" "$pam_file" 2>/dev/null; then
                PWQUALITY_OK=true
                log_info "Complejidad de contrasena configurada en $pam_file"
            fi
        fi
    done

    if [[ "$PWQUALITY_OK" == false ]]; then
        log_warn "Complejidad de contrasena no configurada via PAM"
    fi

    # ── Configurar creacion automatica de home ───────────────
    log_info "Verificando creacion automatica de home directory..."

    MKHOMEDIR_OK=false
    for pam_file in /etc/pam.d/system-auth /etc/pam.d/common-session /etc/pam.d/password-auth; do
        if [[ -f "$pam_file" ]]; then
            if grep -q "pam_mkhomedir\|pam_oddjob_mkhomedir" "$pam_file" 2>/dev/null; then
                MKHOMEDIR_OK=true
                log_info "Creacion automatica de home configurada en $pam_file"
            fi
        fi
    done

    if [[ "$MKHOMEDIR_OK" == false ]]; then
        if ask "¿Habilitar creacion automatica de home para usuarios LDAP?"; then
            # Detectar archivo PAM correcto
            local pam_session_file=""
            if [[ -f /etc/pam.d/common-session ]]; then
                pam_session_file="/etc/pam.d/common-session"
            elif [[ -f /etc/pam.d/system-auth ]]; then
                pam_session_file="/etc/pam.d/system-auth"
            fi

            if [[ -n "$pam_session_file" ]]; then
                cp -a "$pam_session_file" "$BACKUP_DIR/"
                log_change "Backup" "$pam_session_file"

                # Verificar si oddjob esta disponible (preferido en RHEL/Fedora)
                if command -v oddjobd &>/dev/null || service_exists oddjobd; then
                    if ! grep -q "pam_oddjob_mkhomedir" "$pam_session_file" 2>/dev/null; then
                        echo "session     optional      pam_oddjob_mkhomedir.so umask=0077" >> "$pam_session_file"
                        log_change "Configurado" "pam_oddjob_mkhomedir en $pam_session_file"
                        systemctl enable --now oddjobd 2>/dev/null || true
                    fi
                else
                    if ! grep -q "pam_mkhomedir" "$pam_session_file" 2>/dev/null; then
                        echo "session     optional      pam_mkhomedir.so umask=0077 skel=/etc/skel" >> "$pam_session_file"
                        log_change "Configurado" "pam_mkhomedir en $pam_session_file"
                    fi
                fi
            else
                log_warn "No se encontro archivo PAM de sesion"
            fi
        else
            log_skip "Creacion automatica de home"
        fi
    fi

    # ── Integracion sudo con LDAP/SSSD ──────────────────────
    log_info "Verificando integracion sudo con LDAP/SSSD..."

    SUDO_SSS_OK=false
    if [[ -f /etc/nsswitch.conf ]]; then
        if grep -qE "^sudoers:.*sss" /etc/nsswitch.conf 2>/dev/null; then
            SUDO_SSS_OK=true
            log_info "sudo integrado con SSSD via nsswitch.conf"
        fi
    fi

    if [[ "$SUDO_SSS_OK" == false && "$HAS_SSSD" == true ]]; then
        if ask "¿Integrar sudo con SSSD (anadir sss a sudoers en nsswitch.conf)?"; then
            cp -a /etc/nsswitch.conf "$BACKUP_DIR/"
            log_change "Backup" "/etc/nsswitch.conf"

            if grep -q "^sudoers:" /etc/nsswitch.conf 2>/dev/null; then
                # Anadir sss si no esta
                if ! grep -q "^sudoers:.*sss" /etc/nsswitch.conf 2>/dev/null; then
                    sed -i 's/^sudoers:.*/& sss/' /etc/nsswitch.conf
                    log_change "Configurado" "nsswitch.conf: sudoers += sss"
                fi
            else
                echo "sudoers: files sss" >> /etc/nsswitch.conf
                log_change "Configurado" "nsswitch.conf: sudoers: files sss"
            fi

            # Verificar que sssd tiene servicio sudo
            if [[ -f /etc/sssd/sssd.conf ]]; then
                if ! grep -q "sudo" /etc/sssd/sssd.conf 2>/dev/null; then
                    sed -i 's/^services.*/&, sudo/' /etc/sssd/sssd.conf
                    log_change "Configurado" "SSSD: servicio sudo habilitado"
                fi
            fi
        else
            log_skip "Integracion sudo con SSSD"
        fi
    fi

    # ── Verificar ordenamiento nsswitch.conf ─────────────────
    if [[ -f /etc/nsswitch.conf ]]; then
        log_info "Verificando ordenamiento en nsswitch.conf..."
        # Verificar que sss esta antes de files para passwd/group/shadow
        for ns_entry in passwd group shadow; do
            local ns_line=""
            ns_line=$(grep "^${ns_entry}:" /etc/nsswitch.conf 2>/dev/null) || true
            if [[ -n "$ns_line" ]]; then
                if echo "$ns_line" | grep -q "sss"; then
                    # Verificar orden: sss debe estar presente
                    log_info "nsswitch $ns_entry: $ns_line"
                fi
            fi
        done
    fi

    # ── Crear script de auditoria de acceso LDAP ────────────
    cat > /usr/local/bin/auditar-acceso-ldap.sh << 'EOFACCESOLDAP'
#!/bin/bash
# ============================================================
# auditar-acceso-ldap.sh - Auditoria de acceso LDAP/PAM
# Generado por securizar - Modulo 53
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[X]${NC} $1"; }
section() { echo -e "\n${CYAN}── $1 ──${NC}"; }

echo ""
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  SECURIZAR - AUDITORIA DE ACCESO LDAP${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo ""

SCORE=0
TOTAL=0
ISSUES=()

# 1. PAM LDAP/SSS
section "1. Modulos PAM LDAP"
((TOTAL++)) || true
PAM_OK=false
for mod_path in /lib/security /lib64/security /usr/lib/security /usr/lib64/security; do
    if [[ -f "$mod_path/pam_sss.so" ]] || [[ -f "$mod_path/pam_ldap.so" ]]; then
        PAM_OK=true
        break
    fi
done
if [[ "$PAM_OK" == true ]]; then
    ((SCORE++)) || true
    info "PASS: Modulo PAM LDAP disponible"
else
    error "FAIL: Sin modulo PAM LDAP"
    ISSUES+=("Sin modulo PAM LDAP")
fi

# 2. pam_faillock
section "2. pam_faillock"
((TOTAL++)) || true
FAILLOCK_OK=false
for pf in /etc/pam.d/system-auth /etc/pam.d/common-auth /etc/pam.d/password-auth; do
    if grep -q "pam_faillock" "$pf" 2>/dev/null; then
        FAILLOCK_OK=true
        break
    fi
done
if [[ "$FAILLOCK_OK" == true ]]; then
    ((SCORE++)) || true
    info "PASS: pam_faillock configurado"
else
    error "FAIL: pam_faillock no configurado"
    ISSUES+=("pam_faillock no configurado")
fi

# 3. pam_pwquality/pam_cracklib
section "3. Complejidad de contrasena"
((TOTAL++)) || true
PWQUAL_OK=false
for pf in /etc/pam.d/system-auth /etc/pam.d/common-password /etc/pam.d/password-auth; do
    if grep -q "pam_pwquality\|pam_cracklib" "$pf" 2>/dev/null; then
        PWQUAL_OK=true
        break
    fi
done
if [[ "$PWQUAL_OK" == true ]]; then
    ((SCORE++)) || true
    info "PASS: Complejidad de contrasena configurada"
else
    error "FAIL: Sin complejidad de contrasena"
    ISSUES+=("Complejidad de contrasena no configurada")
fi

# 4. pam_mkhomedir
section "4. Creacion automatica de home"
((TOTAL++)) || true
MKHR_OK=false
for pf in /etc/pam.d/system-auth /etc/pam.d/common-session /etc/pam.d/password-auth; do
    if grep -q "pam_mkhomedir\|pam_oddjob_mkhomedir" "$pf" 2>/dev/null; then
        MKHR_OK=true
        break
    fi
done
if [[ "$MKHR_OK" == true ]]; then
    ((SCORE++)) || true
    info "PASS: Creacion automatica de home habilitada"
else
    warn "FAIL: Creacion automatica de home no habilitada"
    ISSUES+=("pam_mkhomedir no configurado")
fi

# 5. nsswitch.conf
section "5. nsswitch.conf"
((TOTAL++)) || true
if [[ -f /etc/nsswitch.conf ]]; then
    if grep -qE "^(passwd|group).*sss\|^(passwd|group).*ldap" /etc/nsswitch.conf 2>/dev/null; then
        ((SCORE++)) || true
        info "PASS: nsswitch.conf integrado con LDAP/SSS"
    else
        warn "FAIL: nsswitch.conf sin integracion LDAP/SSS"
        ISSUES+=("nsswitch.conf sin LDAP/SSS")
    fi
fi

# 6. sudo integrado
section "6. Integracion sudo"
((TOTAL++)) || true
if grep -qE "^sudoers:.*sss" /etc/nsswitch.conf 2>/dev/null; then
    ((SCORE++)) || true
    info "PASS: sudo integrado con SSSD"
elif [[ -f /etc/sudo-ldap.conf ]] || [[ -f /etc/ldap/ldap.conf ]]; then
    ((SCORE++)) || true
    info "PASS: sudo integrado con LDAP directamente"
else
    warn "FAIL: sudo no integrado con LDAP/SSSD"
    ISSUES+=("sudo sin integracion LDAP/SSSD")
fi

# 7. Usuarios LDAP activos
section "7. Usuarios LDAP en el sistema"
if command -v getent &>/dev/null; then
    LDAP_USERS=$(getent passwd 2>/dev/null | awk -F: '$3 >= 1000 && $3 < 60000' | wc -l) || LDAP_USERS=0
    info "Usuarios con UID 1000-60000: $LDAP_USERS"
fi

# Resumen
echo ""
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
if [[ $TOTAL -gt 0 ]]; then
    PCT=$((SCORE * 100 / TOTAL))
    if [[ $PCT -ge 80 ]]; then
        echo -e "  ${BOLD}ACCESO LDAP: ${GREEN}${SCORE}/${TOTAL} (${PCT}%) - BUENO${NC}"
    elif [[ $PCT -ge 50 ]]; then
        echo -e "  ${BOLD}ACCESO LDAP: ${YELLOW}${SCORE}/${TOTAL} (${PCT}%) - MEJORABLE${NC}"
    else
        echo -e "  ${BOLD}ACCESO LDAP: ${RED}${SCORE}/${TOTAL} (${PCT}%) - DEFICIENTE${NC}"
    fi
fi

if [[ ${#ISSUES[@]} -gt 0 ]]; then
    echo ""
    echo -e "${BOLD}  Problemas detectados:${NC}"
    for issue in "${ISSUES[@]}"; do
        echo -e "    ${RED}- $issue${NC}"
    done
fi
echo ""
EOFACCESOLDAP
    chmod +x /usr/local/bin/auditar-acceso-ldap.sh
    log_change "Creado" "/usr/local/bin/auditar-acceso-ldap.sh"

    log_info "Control de acceso basado en LDAP completado"
else
    log_skip "Control de acceso basado en LDAP"
fi

# ============================================================
# S8: MONITORIZACION DE DIRECTORIO
# ============================================================
log_section "S8: MONITORIZACION DE DIRECTORIO"

echo "Configura monitorizacion de eventos LDAP/AD:"
echo "  - Reglas auditd para archivos LDAP"
echo "  - Watch keytab, sssd.conf, krb5.conf, smb.conf"
echo "  - Script de monitorizacion de directorio"
echo "  - Deteccion de bind failures (fuerza bruta)"
echo "  - Deteccion de lockouts y escalada"
echo "  - Cambios de grupo y schema"
echo ""

if ask "¿Configurar monitorizacion de directorio LDAP/AD?"; then

    # ── Reglas auditd ────────────────────────────────────────
    log_info "Configurando reglas auditd para LDAP/AD..."

    AUDIT_RULES_DIR=""
    if [[ -d /etc/audit/rules.d ]]; then
        AUDIT_RULES_DIR="/etc/audit/rules.d"
    elif [[ -d /etc/audit ]]; then
        AUDIT_RULES_DIR="/etc/audit"
    fi

    if [[ -n "$AUDIT_RULES_DIR" ]]; then
        AUDIT_LDAP_RULES="$AUDIT_RULES_DIR/60-ldap-securizar.rules"

        if [[ -f "$AUDIT_LDAP_RULES" ]]; then
            cp -a "$AUDIT_LDAP_RULES" "$BACKUP_DIR/"
            log_change "Backup" "$AUDIT_LDAP_RULES"
        fi

        cat > "$AUDIT_LDAP_RULES" << 'EOFAUDITRULES'
## ============================================================
## Reglas auditd para LDAP/AD - securizar Modulo 53
## ============================================================

## ── Archivos de configuracion LDAP ─────────────────────────
-w /etc/openldap/ -p wa -k ldap-config
-w /etc/ldap/ -p wa -k ldap-config
-w /etc/sssd/ -p wa -k sssd-config
-w /etc/sssd/sssd.conf -p wa -k sssd-config-change

## ── Kerberos ───────────────────────────────────────────────
-w /etc/krb5.conf -p wa -k krb5-config
-w /etc/krb5.keytab -p ra -k keytab-access
-w /etc/krb5kdc/ -p wa -k kdc-config

## ── Samba/Winbind ──────────────────────────────────────────
-w /etc/samba/smb.conf -p wa -k samba-config
-w /etc/samba/ -p wa -k samba-config

## ── FreeIPA ────────────────────────────────────────────────
-w /etc/ipa/ -p wa -k freeipa-config

## ── nsswitch y PAM ─────────────────────────────────────────
-w /etc/nsswitch.conf -p wa -k nsswitch-change
-w /etc/pam.d/ -p wa -k pam-config

## ── LDAP client config ─────────────────────────────────────
-w /etc/ldap.conf -p wa -k ldap-client-config
-w /etc/nslcd.conf -p wa -k nslcd-config

## ── Herramientas LDAP ──────────────────────────────────────
-w /usr/bin/ldapsearch -p x -k ldap-tools
-w /usr/bin/ldapmodify -p x -k ldap-tools
-w /usr/bin/ldapadd -p x -k ldap-tools
-w /usr/bin/ldapdelete -p x -k ldap-tools

## ── Kerberos tools ─────────────────────────────────────────
-w /usr/bin/kinit -p x -k krb5-tools
-w /usr/bin/kdestroy -p x -k krb5-tools
-w /usr/bin/kpasswd -p x -k krb5-tools

## ── realm/join tools ───────────────────────────────────────
-w /usr/sbin/realm -p x -k realm-tools
-w /usr/bin/realm -p x -k realm-tools
-w /usr/sbin/adcli -p x -k ad-tools
EOFAUDITRULES
        chmod 640 "$AUDIT_LDAP_RULES"
        log_change "Creado" "$AUDIT_LDAP_RULES"

        # Recargar reglas auditd
        if service_is_active auditd; then
            augenrules --load 2>/dev/null || auditctl -R "$AUDIT_LDAP_RULES" 2>/dev/null || true
            log_change "Recargado" "reglas auditd para LDAP/AD"
        else
            log_warn "auditd no esta activo. Las reglas se aplicaran al iniciar."
        fi
    else
        log_warn "Directorio de reglas auditd no encontrado"
        log_warn "Instale auditd: pkg_install audit"
    fi

    # ── Crear script de monitorizacion de directorio ─────────
    cat > /usr/local/bin/monitorizar-directorio.sh << 'EOFMONDIR'
#!/bin/bash
# ============================================================
# monitorizar-directorio.sh - Monitorizacion de directorio LDAP/AD
# Generado por securizar - Modulo 53
# ============================================================
# Uso: monitorizar-directorio.sh [--watch] [--report]
# --watch: modo continuo (requiere Ctrl+C para detener)
# --report: genera reporte puntual
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[X]${NC} $1"; }
section() { echo -e "\n${CYAN}── $1 ──${NC}"; }

LOG_DIR="/var/log/securizar"
mkdir -p "$LOG_DIR"
REPORT_FILE="$LOG_DIR/monitorizacion-directorio-$(date +%Y%m%d-%H%M%S).log"

MODE="${1:---report}"

echo ""
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  SECURIZAR - MONITORIZACION DE DIRECTORIO LDAP/AD${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo ""

# ── 1. LDAP Bind Failures (deteccion de fuerza bruta) ───────
section "1. LDAP Bind Failures"

# Buscar en logs de slapd
BIND_FAILURES=0
for logfile in /var/log/syslog /var/log/messages /var/log/slapd.log; do
    if [[ -f "$logfile" ]]; then
        RECENT_FAILURES=$(grep -c "RESULT.*err=49\|bind.*invalid credentials\|BIND.*err=49" "$logfile" 2>/dev/null) || RECENT_FAILURES=0
        BIND_FAILURES=$((BIND_FAILURES + RECENT_FAILURES))
    fi
done

# Buscar en journal
if command -v journalctl &>/dev/null; then
    JOURNAL_FAILURES=$(journalctl -u slapd --since "24 hours ago" 2>/dev/null | grep -c "err=49\|invalid credentials" 2>/dev/null) || JOURNAL_FAILURES=0
    BIND_FAILURES=$((BIND_FAILURES + JOURNAL_FAILURES))
fi

if [[ $BIND_FAILURES -gt 50 ]]; then
    error "ALERTA: $BIND_FAILURES bind failures en las ultimas 24h (posible fuerza bruta)"
elif [[ $BIND_FAILURES -gt 10 ]]; then
    warn "ATENCION: $BIND_FAILURES bind failures en las ultimas 24h"
else
    info "Bind failures (24h): $BIND_FAILURES (normal)"
fi

# ── 2. Account Lockouts ─────────────────────────────────────
section "2. Account Lockouts"

LOCKOUT_COUNT=0
# SSSD lockouts
for logfile in /var/log/sssd/*.log /var/log/secure /var/log/auth.log; do
    if [[ -f "$logfile" ]]; then
        LOCKOUTS=$(grep -c "Account.*locked\|account.*disabled\|pam_faillock.*locked" "$logfile" 2>/dev/null) || LOCKOUTS=0
        LOCKOUT_COUNT=$((LOCKOUT_COUNT + LOCKOUTS))
    fi
done

if [[ $LOCKOUT_COUNT -gt 0 ]]; then
    warn "Lockouts detectados (24h): $LOCKOUT_COUNT"
else
    info "Sin lockouts recientes"
fi

# ── 3. Privilege Escalation ─────────────────────────────────
section "3. Escalada de privilegios en directorio"

PRIV_ESC=0
# Buscar cambios de grupo admin/wheel/domain admins
for logfile in /var/log/syslog /var/log/messages /var/log/secure /var/log/auth.log; do
    if [[ -f "$logfile" ]]; then
        ESC=$(grep -c "group.*admin\|usermod.*-G\|gpasswd.*admin\|Domain Admins" "$logfile" 2>/dev/null) || ESC=0
        PRIV_ESC=$((PRIV_ESC + ESC))
    fi
done

if command -v ausearch &>/dev/null; then
    AUDIT_ESC=$(ausearch -k ldap-tools -ts today 2>/dev/null | grep -c "type=EXECVE" 2>/dev/null) || AUDIT_ESC=0
    PRIV_ESC=$((PRIV_ESC + AUDIT_ESC))
fi

if [[ $PRIV_ESC -gt 0 ]]; then
    warn "Eventos de escalada/cambio de privilegios: $PRIV_ESC"
else
    info "Sin eventos de escalada recientes"
fi

# ── 4. Group Membership Changes ─────────────────────────────
section "4. Cambios de membresía de grupo"

GROUP_CHANGES=0
if command -v ausearch &>/dev/null; then
    GROUP_CHANGES=$(ausearch -k ldap-tools -ts today 2>/dev/null | grep -c "ldapmodify\|ldapadd" 2>/dev/null) || GROUP_CHANGES=0
fi

for logfile in /var/log/syslog /var/log/messages; do
    if [[ -f "$logfile" ]]; then
        GC=$(grep -c "MOD.*member\|ADD.*member\|groupmod\|usermod.*-G" "$logfile" 2>/dev/null) || GC=0
        GROUP_CHANGES=$((GROUP_CHANGES + GC))
    fi
done

if [[ $GROUP_CHANGES -gt 0 ]]; then
    warn "Cambios de membresía de grupo detectados: $GROUP_CHANGES"
else
    info "Sin cambios de membresía de grupo recientes"
fi

# ── 5. Schema Modifications ─────────────────────────────────
section "5. Modificaciones de schema"

SCHEMA_MODS=0
for logfile in /var/log/syslog /var/log/messages /var/log/slapd.log; do
    if [[ -f "$logfile" ]]; then
        SM=$(grep -c "cn=schema\|MODIFY.*cn=config\|schema.*modify" "$logfile" 2>/dev/null) || SM=0
        SCHEMA_MODS=$((SCHEMA_MODS + SM))
    fi
done

if [[ $SCHEMA_MODS -gt 0 ]]; then
    warn "Modificaciones de schema detectadas: $SCHEMA_MODS"
else
    info "Sin modificaciones de schema recientes"
fi

# ── 6. Config file changes (auditd) ─────────────────────────
section "6. Cambios en archivos de configuracion"

if command -v ausearch &>/dev/null; then
    CONFIG_CHANGES=0
    for audit_key in ldap-config sssd-config krb5-config samba-config nsswitch-change; do
        KC=$(ausearch -k "$audit_key" -ts today 2>/dev/null | grep -c "type=SYSCALL" 2>/dev/null) || KC=0
        CONFIG_CHANGES=$((CONFIG_CHANGES + KC))
        if [[ $KC -gt 0 ]]; then
            warn "Cambios detectados ($audit_key): $KC"
        fi
    done
    if [[ $CONFIG_CHANGES -eq 0 ]]; then
        info "Sin cambios de configuracion recientes (auditd)"
    fi
else
    warn "ausearch no disponible. Instale auditd para mejor monitorizacion."
fi

# ── 7. Keytab access ────────────────────────────────────────
section "7. Acceso a keytab"

if command -v ausearch &>/dev/null; then
    KEYTAB_ACCESS=$(ausearch -k keytab-access -ts today 2>/dev/null | grep -c "type=SYSCALL" 2>/dev/null) || KEYTAB_ACCESS=0
    if [[ $KEYTAB_ACCESS -gt 0 ]]; then
        warn "Accesos a keytab detectados: $KEYTAB_ACCESS"
    else
        info "Sin accesos a keytab recientes"
    fi
fi

# ── Guardar reporte ──────────────────────────────────────────
{
    echo "MONITORIZACION DE DIRECTORIO LDAP/AD"
    echo "Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Hostname: $(hostname)"
    echo ""
    echo "Bind failures (24h): $BIND_FAILURES"
    echo "Lockouts: $LOCKOUT_COUNT"
    echo "Escalada de privilegios: $PRIV_ESC"
    echo "Cambios de grupo: $GROUP_CHANGES"
    echo "Modificaciones de schema: $SCHEMA_MODS"
} > "$REPORT_FILE"
chmod 600 "$REPORT_FILE"
info "Reporte guardado en: $REPORT_FILE"

# ── Modo watch ───────────────────────────────────────────────
if [[ "$MODE" == "--watch" ]]; then
    echo ""
    info "Modo watch activado. Monitorizando en tiempo real..."
    info "Presione Ctrl+C para detener"
    echo ""

    # Monitorizar logs en tiempo real
    WATCH_FILES=()
    for lf in /var/log/syslog /var/log/messages /var/log/secure /var/log/auth.log /var/log/slapd.log; do
        if [[ -f "$lf" ]]; then
            WATCH_FILES+=("$lf")
        fi
    done

    if [[ ${#WATCH_FILES[@]} -gt 0 ]]; then
        tail -f "${WATCH_FILES[@]}" 2>/dev/null | grep --line-buffered -iE \
            "slapd|sssd|krb5|kerberos|ldap|winbind|smbd|realm|kinit|bind.*err|locked|failed.*password" || true
    else
        warn "No se encontraron archivos de log para monitorizar"
        # Fallback a journalctl
        if command -v journalctl &>/dev/null; then
            journalctl -f -u slapd -u sssd -u winbind -u smbd -u krb5kdc 2>/dev/null || true
        fi
    fi
fi

echo ""
EOFMONDIR
    chmod +x /usr/local/bin/monitorizar-directorio.sh
    log_change "Creado" "/usr/local/bin/monitorizar-directorio.sh"

    log_info "Monitorizacion de directorio LDAP/AD configurada"
else
    log_skip "Monitorizacion de directorio LDAP/AD"
fi

# ============================================================
# S9: HARDENING DE REPLICACION Y BACKUP LDAP
# ============================================================
log_section "S9: HARDENING DE REPLICACION Y BACKUP LDAP"

echo "Configura replicacion segura y backups para LDAP:"
echo "  - Verificar que replicacion usa TLS"
echo "  - Verificar seguridad de syncrepl"
echo "  - Backup automatizado con slapcat"
echo "  - Almacenamiento en /var/backups/securizar/ldap/"
echo "  - Retencion de 30 dias"
echo "  - Script de restauracion"
echo "  - Cron diario de backup"
echo ""

if ask "¿Configurar replicacion segura y backups LDAP?"; then

    LDAP_BACKUP_DIR="/var/backups/securizar/ldap"
    mkdir -p "$LDAP_BACKUP_DIR"
    chmod 700 "$LDAP_BACKUP_DIR"

    # ── Verificar replicacion con TLS ────────────────────────
    if [[ "$HAS_SLAPD" == true && -n "$SLAPD_CONF" ]]; then
        log_info "Verificando seguridad de replicacion..."

        REPL_TLS_OK=true
        if [[ "$SLAPD_CONF_TYPE" == "cn=config" ]]; then
            # Buscar syncrepl en cn=config
            if grep -r "olcSyncRepl\|syncrepl" "$SLAPD_CONF" &>/dev/null 2>&1; then
                log_info "Configuracion syncrepl detectada"
                if grep -r "olcSyncRepl" "$SLAPD_CONF" 2>/dev/null | grep -qi "starttls=critical\|tls_reqcert=demand\|ldaps://"; then
                    log_info "Replicacion usando TLS"
                else
                    REPL_TLS_OK=false
                    log_warn "Replicacion puede no estar usando TLS"
                    log_warn "Agregue starttls=critical a la configuracion syncrepl"
                fi
            else
                log_info "No se detecto configuracion de replicacion (servidor unico)"
            fi
        elif [[ "$SLAPD_CONF_TYPE" == "file" ]]; then
            if grep -q "^syncrepl" "$SLAPD_CONF" 2>/dev/null; then
                log_info "Configuracion syncrepl detectada"
                if grep "^syncrepl" "$SLAPD_CONF" 2>/dev/null | grep -qi "starttls=critical\|tls_reqcert=demand"; then
                    log_info "Replicacion usando TLS"
                else
                    REPL_TLS_OK=false
                    log_warn "Replicacion puede no estar usando TLS"
                fi
            else
                log_info "No se detecto configuracion de replicacion"
            fi
        fi

        if [[ "$REPL_TLS_OK" == false ]]; then
            log_warn "RECOMENDACION: Configure replicacion con starttls=critical"
        fi
    fi

    # ── Crear script de backup LDAP ──────────────────────────
    cat > /usr/local/bin/backup-ldap.sh << 'EOFBACKUPLDAP'
#!/bin/bash
# ============================================================
# backup-ldap.sh - Backup automatizado de LDAP
# Generado por securizar - Modulo 53
# ============================================================
# Uso: backup-ldap.sh [--verify] [--list]
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[X]${NC} $1"; }

BACKUP_DIR="/var/backups/securizar/ldap"
RETENTION_DAYS=30
DATE_STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_PREFIX="ldap-backup"

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

MODE="${1:---backup}"

case "$MODE" in
    --list)
        echo ""
        echo -e "${BOLD}Backups LDAP disponibles:${NC}"
        echo ""
        ls -lh "$BACKUP_DIR"/${BACKUP_PREFIX}-*.ldif.gz 2>/dev/null || echo "  (ninguno)"
        echo ""
        TOTAL_SIZE=$(du -sh "$BACKUP_DIR" 2>/dev/null | awk '{print $1}') || TOTAL_SIZE="?"
        echo "Tamano total: $TOTAL_SIZE"
        echo ""
        exit 0
        ;;
    --verify)
        echo ""
        echo -e "${BOLD}Verificando integridad de backups LDAP...${NC}"
        echo ""
        LAST_BACKUP=$(ls -t "$BACKUP_DIR"/${BACKUP_PREFIX}-*.ldif.gz 2>/dev/null | head -1)
        if [[ -n "$LAST_BACKUP" ]]; then
            info "Ultimo backup: $LAST_BACKUP"
            # Verificar que se puede descomprimir
            if gzip -t "$LAST_BACKUP" 2>/dev/null; then
                info "PASS: Integridad del archivo comprimido OK"
                # Contar entradas
                ENTRY_COUNT=$(zcat "$LAST_BACKUP" 2>/dev/null | grep -c "^dn:" 2>/dev/null) || ENTRY_COUNT=0
                info "Entradas LDAP en backup: $ENTRY_COUNT"
                BACKUP_SIZE=$(ls -lh "$LAST_BACKUP" | awk '{print $5}')
                info "Tamano: $BACKUP_SIZE"
                BACKUP_DATE=$(stat -c '%y' "$LAST_BACKUP" 2>/dev/null | cut -d. -f1) || BACKUP_DATE="?"
                info "Fecha: $BACKUP_DATE"
            else
                error "FAIL: Archivo corrupto: $LAST_BACKUP"
            fi
        else
            error "No se encontraron backups"
        fi
        echo ""
        exit 0
        ;;
esac

# ── Modo backup ──────────────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  BACKUP LDAP - $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo ""

# Verificar que slapcat esta disponible
if ! command -v slapcat &>/dev/null; then
    error "slapcat no encontrado. Instale openldap-servers/slapd"
    exit 1
fi

# Backup de configuracion (database 0 = cn=config)
CONFIG_BACKUP="$BACKUP_DIR/${BACKUP_PREFIX}-config-${DATE_STAMP}.ldif"
info "Exportando configuracion cn=config..."
if slapcat -n 0 -l "$CONFIG_BACKUP" 2>/dev/null; then
    gzip "$CONFIG_BACKUP"
    info "Config backup: ${CONFIG_BACKUP}.gz"
else
    warn "No se pudo exportar cn=config (puede no estar configurado)"
fi

# Backup de datos (database 1 = datos principales)
DATA_BACKUP="$BACKUP_DIR/${BACKUP_PREFIX}-data-${DATE_STAMP}.ldif"
info "Exportando datos LDAP..."
if slapcat -n 1 -l "$DATA_BACKUP" 2>/dev/null; then
    gzip "$DATA_BACKUP"
    ENTRY_COUNT=$(zcat "${DATA_BACKUP}.gz" 2>/dev/null | grep -c "^dn:" 2>/dev/null) || ENTRY_COUNT=0
    BACKUP_SIZE=$(ls -lh "${DATA_BACKUP}.gz" | awk '{print $5}')
    info "Data backup: ${DATA_BACKUP}.gz ($ENTRY_COUNT entradas, $BACKUP_SIZE)"
elif slapcat -l "$DATA_BACKUP" 2>/dev/null; then
    gzip "$DATA_BACKUP"
    info "Data backup: ${DATA_BACKUP}.gz (database default)"
else
    warn "No se pudo exportar datos LDAP"
    # Intentar backup online con ldapsearch si slapd esta corriendo
    if command -v ldapsearch &>/dev/null; then
        warn "Intentando backup online via ldapsearch..."
        ldapsearch -x -H ldapi:/// -b "" "(objectClass=*)" > "$DATA_BACKUP" 2>/dev/null || true
        if [[ -s "$DATA_BACKUP" ]]; then
            gzip "$DATA_BACKUP"
            info "Backup online: ${DATA_BACKUP}.gz"
        else
            rm -f "$DATA_BACKUP"
            error "Backup fallido completamente"
        fi
    fi
fi

# Backup de archivos de configuracion
CONFIG_TAR="$BACKUP_DIR/${BACKUP_PREFIX}-configs-${DATE_STAMP}.tar.gz"
info "Respaldando archivos de configuracion..."
CONFIG_FILES=()
for cf in /etc/openldap /etc/ldap /etc/sssd/sssd.conf /etc/krb5.conf /etc/samba/smb.conf \
          /etc/nsswitch.conf /etc/nslcd.conf /etc/ipa; do
    if [[ -e "$cf" ]]; then
        CONFIG_FILES+=("$cf")
    fi
done

if [[ ${#CONFIG_FILES[@]} -gt 0 ]]; then
    tar czf "$CONFIG_TAR" "${CONFIG_FILES[@]}" 2>/dev/null || true
    info "Config files backup: $CONFIG_TAR"
fi

# ── Limpiar backups antiguos (retencion) ─────────────────────
info "Limpiando backups con mas de $RETENTION_DAYS dias..."
DELETED=$(find "$BACKUP_DIR" -name "${BACKUP_PREFIX}-*" -mtime +${RETENTION_DAYS} -delete -print 2>/dev/null | wc -l) || DELETED=0
if [[ $DELETED -gt 0 ]]; then
    info "Eliminados $DELETED backups antiguos"
else
    info "Sin backups antiguos que eliminar"
fi

# ── Verificar integridad del ultimo backup ───────────────────
info "Verificando integridad..."
LAST_DATA=$(ls -t "$BACKUP_DIR"/${BACKUP_PREFIX}-data-*.ldif.gz 2>/dev/null | head -1)
if [[ -n "$LAST_DATA" ]]; then
    if gzip -t "$LAST_DATA" 2>/dev/null; then
        info "Integridad verificada OK"
    else
        error "ERROR de integridad en $LAST_DATA"
    fi
fi

# Resumen
TOTAL_SIZE=$(du -sh "$BACKUP_DIR" 2>/dev/null | awk '{print $1}') || TOTAL_SIZE="?"
BACKUP_COUNT=$(ls "$BACKUP_DIR"/${BACKUP_PREFIX}-*.gz 2>/dev/null | wc -l) || BACKUP_COUNT=0
echo ""
info "Resumen: $BACKUP_COUNT archivos, $TOTAL_SIZE total"
info "Directorio: $BACKUP_DIR"
echo ""
EOFBACKUPLDAP
    chmod +x /usr/local/bin/backup-ldap.sh
    log_change "Creado" "/usr/local/bin/backup-ldap.sh"

    # ── Crear script de restauracion ─────────────────────────
    cat > /usr/local/bin/restaurar-ldap.sh << 'EOFRESTAURALDAP'
#!/bin/bash
# ============================================================
# restaurar-ldap.sh - Restauracion de backup LDAP
# Generado por securizar - Modulo 53
# ============================================================
# Uso: restaurar-ldap.sh [archivo.ldif.gz]
# Sin argumento: restaura el ultimo backup
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[X]${NC} $1"; }

if [[ $EUID -ne 0 ]]; then
    error "Ejecutar como root: sudo $0"
    exit 1
fi

BACKUP_DIR="/var/backups/securizar/ldap"

echo ""
echo -e "${RED}${BOLD}══════════════════════════════════════════════════${NC}"
echo -e "${RED}${BOLD}  RESTAURACION DE LDAP - OPERACION DESTRUCTIVA${NC}"
echo -e "${RED}${BOLD}══════════════════════════════════════════════════${NC}"
echo ""

# Determinar archivo de backup
BACKUP_FILE="${1:-}"
if [[ -z "$BACKUP_FILE" ]]; then
    BACKUP_FILE=$(ls -t "$BACKUP_DIR"/ldap-backup-data-*.ldif.gz 2>/dev/null | head -1) || true
    if [[ -z "$BACKUP_FILE" ]]; then
        error "No se encontraron backups en $BACKUP_DIR"
        echo "Uso: $0 [archivo.ldif.gz]"
        exit 1
    fi
fi

if [[ ! -f "$BACKUP_FILE" ]]; then
    error "Archivo no encontrado: $BACKUP_FILE"
    exit 1
fi

info "Archivo de backup: $BACKUP_FILE"
BACKUP_SIZE=$(ls -lh "$BACKUP_FILE" | awk '{print $5}')
BACKUP_DATE=$(stat -c '%y' "$BACKUP_FILE" 2>/dev/null | cut -d. -f1)
info "Tamano: $BACKUP_SIZE"
info "Fecha: $BACKUP_DATE"

# Verificar integridad
info "Verificando integridad..."
if ! gzip -t "$BACKUP_FILE" 2>/dev/null; then
    error "Archivo corrupto. Abortando."
    exit 1
fi
info "Integridad OK"

ENTRY_COUNT=$(zcat "$BACKUP_FILE" 2>/dev/null | grep -c "^dn:" 2>/dev/null) || ENTRY_COUNT=0
info "Entradas a restaurar: $ENTRY_COUNT"

echo ""
echo -e "${RED}${BOLD}ADVERTENCIA: Esta operacion eliminara los datos LDAP actuales${NC}"
echo -e "${RED}${BOLD}y los reemplazara con el backup seleccionado.${NC}"
echo ""
read -p "¿Continuar con la restauracion? [escriba SI para confirmar]: " CONFIRM
if [[ "$CONFIRM" != "SI" ]]; then
    info "Restauracion cancelada"
    exit 0
fi

# Pre-backup de seguridad
PRE_BACKUP="$BACKUP_DIR/pre-restore-$(date +%Y%m%d-%H%M%S).ldif"
info "Creando pre-backup de seguridad..."
if command -v slapcat &>/dev/null; then
    slapcat -l "$PRE_BACKUP" 2>/dev/null || true
    if [[ -s "$PRE_BACKUP" ]]; then
        gzip "$PRE_BACKUP"
        info "Pre-backup: ${PRE_BACKUP}.gz"
    fi
fi

# Detener slapd
info "Deteniendo slapd..."
systemctl stop slapd 2>/dev/null || true
sleep 2

# Descomprimir backup
TEMP_LDIF="/tmp/ldap-restore-$$.ldif"
zcat "$BACKUP_FILE" > "$TEMP_LDIF"

# Restaurar
info "Restaurando datos LDAP..."
if command -v slapadd &>/dev/null; then
    # Determinar directorio de datos
    DB_DIR=""
    for dd in /var/lib/ldap /var/lib/openldap-data /var/lib/openldap/openldap-data; do
        if [[ -d "$dd" ]]; then
            DB_DIR="$dd"
            break
        fi
    done

    if [[ -n "$DB_DIR" ]]; then
        # Limpiar datos actuales
        warn "Limpiando datos actuales en $DB_DIR..."
        rm -f "$DB_DIR"/__db.* "$DB_DIR"/log.* "$DB_DIR"/*.bdb "$DB_DIR"/alock 2>/dev/null || true

        # Restaurar
        slapadd -l "$TEMP_LDIF" 2>/dev/null
        RC=$?

        if [[ $RC -eq 0 ]]; then
            info "Restauracion completada exitosamente"
            # Corregir propietario
            SLAPD_USER=$(grep "^ldap:" /etc/passwd 2>/dev/null | head -1 | cut -d: -f1) || SLAPD_USER="ldap"
            chown -R "$SLAPD_USER":"$SLAPD_USER" "$DB_DIR" 2>/dev/null || true
        else
            error "Error durante la restauracion (codigo: $RC)"
        fi
    else
        error "No se encontro directorio de datos LDAP"
    fi
else
    error "slapadd no disponible"
fi

# Limpiar
rm -f "$TEMP_LDIF"

# Iniciar slapd
info "Iniciando slapd..."
systemctl start slapd 2>/dev/null || true
sleep 2

if systemctl is-active slapd &>/dev/null; then
    info "slapd iniciado correctamente"
else
    error "slapd no se pudo iniciar. Revise logs: journalctl -u slapd"
fi

echo ""
EOFRESTAURALDAP
    chmod +x /usr/local/bin/restaurar-ldap.sh
    log_change "Creado" "/usr/local/bin/restaurar-ldap.sh"

    # ── Crear cron diario de backup ──────────────────────────
    if ask "¿Programar backup diario de LDAP?"; then
        cat > /etc/cron.daily/backup-ldap << 'EOFCRONBACKUP'
#!/bin/bash
# Backup diario de LDAP - securizar Modulo 53
/usr/local/bin/backup-ldap.sh >> /var/log/securizar/backup-ldap.log 2>&1
EOFCRONBACKUP
        chmod +x /etc/cron.daily/backup-ldap
        log_change "Creado" "/etc/cron.daily/backup-ldap"
    else
        log_skip "Cron diario de backup LDAP"
    fi

    # ── Ejecutar primer backup ───────────────────────────────
    if [[ "$HAS_SLAPD" == true ]]; then
        if ask "¿Ejecutar primer backup ahora?"; then
            /usr/local/bin/backup-ldap.sh 2>/dev/null || true
            log_change "Ejecutado" "Primer backup LDAP"
        else
            log_skip "Primer backup LDAP"
        fi
    fi

    log_info "Hardening de replicacion y backup LDAP completado"
else
    log_skip "Hardening de replicacion y backup LDAP"
fi

# ============================================================
# S10: AUDITORIA INTEGRAL LDAP/AD
# ============================================================
log_section "S10: AUDITORIA INTEGRAL LDAP/AD"

echo "Crea sistema de auditoria integral LDAP/AD:"
echo "  - Verificacion de todas las secciones anteriores"
echo "  - TLS para todas las conexiones LDAP"
echo "  - Cumplimiento de politica de contrasenas"
echo "  - Revision de cuentas (stale, servicio)"
echo "  - Analisis de anidamiento de grupos"
echo "  - Auditoria de permisos"
echo "  - Puntuacion: BUENO/MEJORABLE/DEFICIENTE"
echo "  - Reporte en /var/log/securizar/"
echo "  - Cron semanal de auditoria"
echo ""

if ask "¿Crear sistema de auditoria integral LDAP/AD?"; then

    cat > /usr/local/bin/auditar-ldap-seguridad.sh << 'EOFAUDITLDAP'
#!/bin/bash
# ============================================================
# auditar-ldap-seguridad.sh - Auditoria integral LDAP/AD
# Generado por securizar - Modulo 53
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[X]${NC} $1"; }
section() { echo -e "\n${CYAN}══ $1 ══${NC}"; }

LOG_DIR="/var/log/securizar"
mkdir -p "$LOG_DIR"
REPORT_FILE="$LOG_DIR/auditoria-ldap-$(date +%Y%m%d-%H%M%S).log"

TOTAL_SCORE=0
TOTAL_CHECKS=0
ALL_ISSUES=()
SECTION_RESULTS=()

# Funcion para registrar resultado de seccion
record_section() {
    local name="$1" score="$2" total="$3"
    local pct=0
    if [[ $total -gt 0 ]]; then
        pct=$((score * 100 / total))
    fi
    local status="DEFICIENTE"
    if [[ $pct -ge 80 ]]; then
        status="BUENO"
    elif [[ $pct -ge 50 ]]; then
        status="MEJORABLE"
    fi
    SECTION_RESULTS+=("$name: $score/$total ($pct%) - $status")
    TOTAL_SCORE=$((TOTAL_SCORE + score))
    TOTAL_CHECKS=$((TOTAL_CHECKS + total))
}

echo ""
echo -e "${BOLD}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║   AUDITORIA INTEGRAL DE SEGURIDAD LDAP/AD                ║${NC}"
echo -e "${BOLD}║   Fecha: $(date '+%Y-%m-%d %H:%M:%S')                           ║${NC}"
echo -e "${BOLD}║   Host: $(hostname)                                      ${NC}"
echo -e "${BOLD}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Cargar entorno detectado ─────────────────────────────────
ENV_CONF="/etc/securizar/ldap-environment.conf"
if [[ -f "$ENV_CONF" ]]; then
    source "$ENV_CONF"
    info "Entorno LDAP/AD cargado desde $ENV_CONF"
else
    warn "Archivo de entorno no encontrado. Ejecute primero S1 del modulo 53."
    # Deteccion basica
    LDAP_SERVER_DETECTED=false
    LDAP_CLIENT_DETECTED=false
    HAS_SLAPD=false
    HAS_SSSD=false
    HAS_SAMBA=false
    HAS_KRB5=false
    HAS_FREEIPA_SERVER=false

    command -v slapd &>/dev/null && HAS_SLAPD=true && LDAP_SERVER_DETECTED=true
    [[ -f /etc/sssd/sssd.conf ]] && HAS_SSSD=true && LDAP_CLIENT_DETECTED=true
    [[ -f /etc/samba/smb.conf ]] && HAS_SAMBA=true
    [[ -f /etc/krb5.conf ]] && HAS_KRB5=true
    command -v ipa &>/dev/null && HAS_FREEIPA_SERVER=true
fi

# ══════════════════════════════════════════════════════════════
# A1: TLS para todas las conexiones LDAP
# ══════════════════════════════════════════════════════════════
section "A1: Verificacion TLS"
A1_SCORE=0
A1_TOTAL=0

# Verificar TLS en servidor slapd
if [[ "$HAS_SLAPD" == "true" ]]; then
    ((A1_TOTAL++)) || true
    # Verificar puerto 636
    if ss -tlnp 2>/dev/null | grep -q ":636" || \
       netstat -tlnp 2>/dev/null | grep -q ":636"; then
        ((A1_SCORE++)) || true
        info "PASS: slapd escuchando en ldaps:// (636)"
    else
        error "FAIL: ldaps:// no habilitado"
        ALL_ISSUES+=("slapd sin ldaps://")
    fi

    # Verificar certificado
    ((A1_TOTAL++)) || true
    for conf_dir in /etc/openldap/slapd.d /etc/ldap/slapd.d; do
        if [[ -d "$conf_dir" ]]; then
            CERT_FILE=$(grep -r "olcTLSCertificateFile" "$conf_dir" 2>/dev/null | head -1 | awk '{print $2}') || CERT_FILE=""
            if [[ -n "$CERT_FILE" && -f "$CERT_FILE" ]]; then
                DAYS_LEFT=$(( ($(date -d "$(openssl x509 -enddate -noout -in "$CERT_FILE" 2>/dev/null | cut -d= -f2)" +%s 2>/dev/null || echo 0) - $(date +%s)) / 86400 )) || DAYS_LEFT=0
                if [[ $DAYS_LEFT -gt 30 ]]; then
                    ((A1_SCORE++)) || true
                    info "PASS: Certificado slapd valido ($DAYS_LEFT dias)"
                else
                    error "FAIL: Certificado slapd expira en $DAYS_LEFT dias"
                    ALL_ISSUES+=("Certificado slapd expira pronto")
                fi
                break
            fi
        fi
    done
fi

# Verificar TLS en SSSD
if [[ "$HAS_SSSD" == "true" && -f /etc/sssd/sssd.conf ]]; then
    ((A1_TOTAL++)) || true
    if grep -q "ldap_id_use_start_tls.*=.*[Tt]rue\|ldap_uri.*ldaps://" /etc/sssd/sssd.conf 2>/dev/null; then
        ((A1_SCORE++)) || true
        info "PASS: SSSD usando TLS"
    else
        error "FAIL: SSSD sin TLS"
        ALL_ISSUES+=("SSSD sin TLS habilitado")
    fi

    ((A1_TOTAL++)) || true
    if grep -q "ldap_tls_reqcert.*=.*demand" /etc/sssd/sssd.conf 2>/dev/null; then
        ((A1_SCORE++)) || true
        info "PASS: SSSD verifica certificado (demand)"
    else
        error "FAIL: SSSD no verifica certificado"
        ALL_ISSUES+=("SSSD ldap_tls_reqcert no es demand")
    fi
fi

record_section "A1-TLS" $A1_SCORE $A1_TOTAL

# ══════════════════════════════════════════════════════════════
# A2: Politica de contrasenas
# ══════════════════════════════════════════════════════════════
section "A2: Politica de contrasenas"
A2_SCORE=0
A2_TOTAL=0

# Verificar pwquality
((A2_TOTAL++)) || true
PWQUAL_FOUND=false
for pf in /etc/pam.d/system-auth /etc/pam.d/common-password /etc/pam.d/password-auth; do
    if grep -q "pam_pwquality\|pam_cracklib" "$pf" 2>/dev/null; then
        PWQUAL_FOUND=true
        break
    fi
done
if [[ "$PWQUAL_FOUND" == true ]]; then
    ((A2_SCORE++)) || true
    info "PASS: Complejidad de contrasena configurada en PAM"
else
    error "FAIL: Sin complejidad de contrasena en PAM"
    ALL_ISSUES+=("Sin pam_pwquality/pam_cracklib")
fi

# Verificar faillock
((A2_TOTAL++)) || true
FAILLOCK_FOUND=false
for pf in /etc/pam.d/system-auth /etc/pam.d/common-auth /etc/pam.d/password-auth; do
    if grep -q "pam_faillock" "$pf" 2>/dev/null; then
        FAILLOCK_FOUND=true
        break
    fi
done
if [[ "$FAILLOCK_FOUND" == true ]]; then
    ((A2_SCORE++)) || true
    info "PASS: pam_faillock configurado"
else
    error "FAIL: pam_faillock no configurado"
    ALL_ISSUES+=("pam_faillock no configurado")
fi

# ppolicy en slapd
if [[ "$HAS_SLAPD" == "true" ]]; then
    ((A2_TOTAL++)) || true
    PPOLICY_FOUND=false
    for conf_dir in /etc/openldap/slapd.d /etc/ldap/slapd.d; do
        if [[ -d "$conf_dir" ]]; then
            if grep -r "ppolicy" "$conf_dir" &>/dev/null 2>&1; then
                PPOLICY_FOUND=true
            fi
        fi
    done
    if [[ "$PPOLICY_FOUND" == true ]]; then
        ((A2_SCORE++)) || true
        info "PASS: ppolicy overlay activo en slapd"
    else
        error "FAIL: ppolicy overlay no activo"
        ALL_ISSUES+=("ppolicy overlay no configurado en slapd")
    fi
fi

record_section "A2-Contrasenas" $A2_SCORE $A2_TOTAL

# ══════════════════════════════════════════════════════════════
# A3: Kerberos
# ══════════════════════════════════════════════════════════════
section "A3: Kerberos"
A3_SCORE=0
A3_TOTAL=0

if [[ "$HAS_KRB5" == "true" && -f /etc/krb5.conf ]]; then
    # Enctypes fuertes
    ((A3_TOTAL++)) || true
    if grep -qiE "aes256-cts|aes128-cts" /etc/krb5.conf 2>/dev/null; then
        ((A3_SCORE++)) || true
        info "PASS: Enctypes fuertes configurados"
    else
        error "FAIL: Sin enctypes AES"
        ALL_ISSUES+=("Kerberos sin enctypes AES")
    fi

    # Sin enctypes debiles
    ((A3_TOTAL++)) || true
    if grep -qiE "des-cbc|des3-cbc|rc4-hmac|arcfour" /etc/krb5.conf 2>/dev/null; then
        error "FAIL: Enctypes debiles presentes"
        ALL_ISSUES+=("Kerberos con enctypes debiles")
    else
        ((A3_SCORE++)) || true
        info "PASS: Sin enctypes debiles"
    fi

    # Forwardable false
    ((A3_TOTAL++)) || true
    if grep -qi "forwardable.*=.*false" /etc/krb5.conf 2>/dev/null; then
        ((A3_SCORE++)) || true
        info "PASS: forwardable = false"
    else
        warn "FAIL: forwardable no es false"
        ALL_ISSUES+=("Kerberos forwardable no deshabilitado")
    fi

    # Keytab permisos
    ((A3_TOTAL++)) || true
    if [[ -f /etc/krb5.keytab ]]; then
        KT_PERMS=$(stat -c '%a' /etc/krb5.keytab 2>/dev/null)
        if [[ "$KT_PERMS" == "600" ]]; then
            ((A3_SCORE++)) || true
            info "PASS: Keytab permisos 600"
        else
            error "FAIL: Keytab permisos $KT_PERMS"
            ALL_ISSUES+=("keytab permisos inseguros: $KT_PERMS")
        fi
    else
        ((A3_SCORE++)) || true
        info "keytab no aplica"
    fi
fi

record_section "A3-Kerberos" $A3_SCORE $A3_TOTAL

# ══════════════════════════════════════════════════════════════
# A4: Samba/AD
# ══════════════════════════════════════════════════════════════
section "A4: Samba/AD"
A4_SCORE=0
A4_TOTAL=0

if [[ "$HAS_SAMBA" == "true" && -f /etc/samba/smb.conf ]]; then
    SMB="/etc/samba/smb.conf"

    # Protocolo minimo
    ((A4_TOTAL++)) || true
    MIN_P=$(grep -i "server min protocol" "$SMB" 2>/dev/null | awk -F= '{print $2}' | xargs) || MIN_P=""
    if [[ "$MIN_P" == "SMB3" || "$MIN_P" == "SMB3_00" || "$MIN_P" == "SMB3_11" ]]; then
        ((A4_SCORE++)) || true
        info "PASS: Protocolo minimo SMB3"
    else
        error "FAIL: Protocolo minimo: ${MIN_P:-no configurado}"
        ALL_ISSUES+=("Samba protocolo minimo no es SMB3")
    fi

    # Firma
    ((A4_TOTAL++)) || true
    S_SIGN=$(grep -i "server signing" "$SMB" 2>/dev/null | awk -F= '{print $2}' | xargs) || S_SIGN=""
    if [[ "$S_SIGN" == "mandatory" || "$S_SIGN" == "required" ]]; then
        ((A4_SCORE++)) || true
        info "PASS: Server signing mandatory"
    else
        error "FAIL: Server signing: ${S_SIGN:-no configurado}"
        ALL_ISSUES+=("Samba server signing no mandatory")
    fi

    # Cifrado
    ((A4_TOTAL++)) || true
    S_ENC=$(grep -i "smb encrypt" "$SMB" 2>/dev/null | awk -F= '{print $2}' | xargs) || S_ENC=""
    if [[ "$S_ENC" == "required" || "$S_ENC" == "mandatory" ]]; then
        ((A4_SCORE++)) || true
        info "PASS: SMB encrypt required"
    else
        error "FAIL: SMB encrypt: ${S_ENC:-no configurado}"
        ALL_ISSUES+=("Samba smb encrypt no required")
    fi

    # Sesiones nulas
    ((A4_TOTAL++)) || true
    R_ANON=$(grep -i "restrict anonymous" "$SMB" 2>/dev/null | awk -F= '{print $2}' | xargs) || R_ANON=""
    if [[ "$R_ANON" == "2" ]]; then
        ((A4_SCORE++)) || true
        info "PASS: restrict anonymous = 2"
    else
        error "FAIL: restrict anonymous: ${R_ANON:-no configurado}"
        ALL_ISSUES+=("Samba restrict anonymous no es 2")
    fi
fi

record_section "A4-Samba" $A4_SCORE $A4_TOTAL

# ══════════════════════════════════════════════════════════════
# A5: Cuentas y permisos
# ══════════════════════════════════════════════════════════════
section "A5: Revision de cuentas"
A5_SCORE=0
A5_TOTAL=0

# Verificar cuentas stale (sin login en >90 dias)
((A5_TOTAL++)) || true
if command -v lastlog &>/dev/null; then
    STALE_ACCOUNTS=$(lastlog -b 90 2>/dev/null | awk 'NR>1 && $0 !~ /Never logged in/' | wc -l) || STALE_ACCOUNTS=0
    NEVER_LOGGED=$(lastlog 2>/dev/null | grep -c "Never logged in" 2>/dev/null) || NEVER_LOGGED=0
    info "Cuentas sin login en >90 dias: $STALE_ACCOUNTS"
    info "Cuentas que nunca han iniciado sesion: $NEVER_LOGGED"
    if [[ $STALE_ACCOUNTS -lt 10 ]]; then
        ((A5_SCORE++)) || true
        info "PASS: Pocas cuentas stale"
    else
        warn "FAIL: Muchas cuentas stale ($STALE_ACCOUNTS)"
        ALL_ISSUES+=("$STALE_ACCOUNTS cuentas stale")
    fi
else
    ((A5_SCORE++)) || true
    info "lastlog no disponible"
fi

# Verificar cuentas de servicio con shell
((A5_TOTAL++)) || true
SVC_WITH_SHELL=$(awk -F: '$3 < 1000 && $3 > 0 && $7 !~ /(nologin|false|sync|halt|shutdown)/' /etc/passwd 2>/dev/null | wc -l) || SVC_WITH_SHELL=0
if [[ $SVC_WITH_SHELL -le 1 ]]; then
    ((A5_SCORE++)) || true
    info "PASS: Cuentas de servicio con shell: $SVC_WITH_SHELL"
else
    warn "FAIL: $SVC_WITH_SHELL cuentas de servicio con shell interactiva"
    ALL_ISSUES+=("$SVC_WITH_SHELL cuentas de servicio con shell")
fi

# nsswitch.conf
((A5_TOTAL++)) || true
if [[ -f /etc/nsswitch.conf ]]; then
    if grep -qE "^(passwd|group).*(sss|ldap)" /etc/nsswitch.conf 2>/dev/null; then
        ((A5_SCORE++)) || true
        info "PASS: nsswitch.conf integrado con directorio"
    else
        info "nsswitch.conf sin integracion de directorio (puede ser correcto)"
        ((A5_SCORE++)) || true
    fi
fi

# mkhomedir
((A5_TOTAL++)) || true
MKHR=false
for pf in /etc/pam.d/system-auth /etc/pam.d/common-session /etc/pam.d/password-auth; do
    if grep -q "pam_mkhomedir\|pam_oddjob_mkhomedir" "$pf" 2>/dev/null; then
        MKHR=true
        break
    fi
done
if [[ "$MKHR" == true ]]; then
    ((A5_SCORE++)) || true
    info "PASS: Creacion automatica de home habilitada"
else
    warn "FAIL: pam_mkhomedir no configurado"
    ALL_ISSUES+=("pam_mkhomedir no configurado")
fi

record_section "A5-Cuentas" $A5_SCORE $A5_TOTAL

# ══════════════════════════════════════════════════════════════
# A6: Auditd y monitorizacion
# ══════════════════════════════════════════════════════════════
section "A6: Auditd y monitorizacion"
A6_SCORE=0
A6_TOTAL=0

# auditd activo
((A6_TOTAL++)) || true
if systemctl is-active auditd &>/dev/null; then
    ((A6_SCORE++)) || true
    info "PASS: auditd activo"
else
    error "FAIL: auditd no activo"
    ALL_ISSUES+=("auditd no activo")
fi

# Reglas LDAP en auditd
((A6_TOTAL++)) || true
LDAP_RULES_FOUND=false
if [[ -f /etc/audit/rules.d/60-ldap-securizar.rules ]]; then
    LDAP_RULES_FOUND=true
elif command -v auditctl &>/dev/null; then
    if auditctl -l 2>/dev/null | grep -q "ldap-config\|sssd-config\|krb5-config"; then
        LDAP_RULES_FOUND=true
    fi
fi
if [[ "$LDAP_RULES_FOUND" == true ]]; then
    ((A6_SCORE++)) || true
    info "PASS: Reglas auditd para LDAP configuradas"
else
    error "FAIL: Sin reglas auditd para LDAP"
    ALL_ISSUES+=("Sin reglas auditd para LDAP")
fi

# Backup configurado
((A6_TOTAL++)) || true
if [[ -x /usr/local/bin/backup-ldap.sh ]]; then
    ((A6_SCORE++)) || true
    info "PASS: Script de backup LDAP instalado"
else
    warn "FAIL: Script de backup LDAP no encontrado"
    ALL_ISSUES+=("Sin script de backup LDAP")
fi

# Cron de backup
((A6_TOTAL++)) || true
if [[ -x /etc/cron.daily/backup-ldap ]]; then
    ((A6_SCORE++)) || true
    info "PASS: Cron diario de backup configurado"
else
    warn "FAIL: Sin cron de backup diario"
    ALL_ISSUES+=("Sin cron de backup diario")
fi

record_section "A6-Monitorizacion" $A6_SCORE $A6_TOTAL

# ══════════════════════════════════════════════════════════════
# A7: Grupo nesting y permisos (analisis basico)
# ══════════════════════════════════════════════════════════════
section "A7: Grupos y permisos"
A7_SCORE=0
A7_TOTAL=0

# Verificar grupos con muchos miembros
((A7_TOTAL++)) || true
LARGE_GROUPS=0
while IFS=: read -r gname _ _ gmembers; do
    if [[ -n "$gmembers" ]]; then
        MEMBER_COUNT=$(echo "$gmembers" | tr ',' '\n' | wc -l)
        if [[ $MEMBER_COUNT -gt 50 ]]; then
            warn "Grupo '$gname' tiene $MEMBER_COUNT miembros"
            ((LARGE_GROUPS++)) || true
        fi
    fi
done < /etc/group 2>/dev/null || true

if [[ $LARGE_GROUPS -eq 0 ]]; then
    ((A7_SCORE++)) || true
    info "PASS: Sin grupos excesivamente grandes"
else
    warn "FAIL: $LARGE_GROUPS grupos con >50 miembros"
    ALL_ISSUES+=("$LARGE_GROUPS grupos muy grandes")
fi

# Verificar permisos de archivos criticos
((A7_TOTAL++)) || true
PERM_ISSUES=0
for crit_file in /etc/sssd/sssd.conf /etc/krb5.keytab; do
    if [[ -f "$crit_file" ]]; then
        PERMS=$(stat -c '%a' "$crit_file" 2>/dev/null) || PERMS="?"
        if [[ "$PERMS" != "600" && "$PERMS" != "640" ]]; then
            warn "Permisos inseguros: $crit_file ($PERMS)"
            ((PERM_ISSUES++)) || true
        fi
    fi
done
if [[ $PERM_ISSUES -eq 0 ]]; then
    ((A7_SCORE++)) || true
    info "PASS: Permisos de archivos criticos correctos"
else
    error "FAIL: $PERM_ISSUES archivos con permisos inseguros"
    ALL_ISSUES+=("$PERM_ISSUES archivos criticos con permisos inseguros")
fi

record_section "A7-Grupos" $A7_SCORE $A7_TOTAL

# ══════════════════════════════════════════════════════════════
# RESUMEN FINAL
# ══════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║   RESUMEN DE AUDITORIA INTEGRAL LDAP/AD                  ║${NC}"
echo -e "${BOLD}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Resultados por seccion
echo -e "  ${BOLD}Resultados por seccion:${NC}"
for result in "${SECTION_RESULTS[@]}"; do
    echo "    - $result"
done
echo ""

# Puntuacion global
if [[ $TOTAL_CHECKS -gt 0 ]]; then
    GLOBAL_PCT=$((TOTAL_SCORE * 100 / TOTAL_CHECKS))
    if [[ $GLOBAL_PCT -ge 80 ]]; then
        echo -e "  ${BOLD}PUNTUACION GLOBAL: ${GREEN}${TOTAL_SCORE}/${TOTAL_CHECKS} (${GLOBAL_PCT}%) - BUENO${NC}"
    elif [[ $GLOBAL_PCT -ge 50 ]]; then
        echo -e "  ${BOLD}PUNTUACION GLOBAL: ${YELLOW}${TOTAL_SCORE}/${TOTAL_CHECKS} (${GLOBAL_PCT}%) - MEJORABLE${NC}"
    else
        echo -e "  ${BOLD}PUNTUACION GLOBAL: ${RED}${TOTAL_SCORE}/${TOTAL_CHECKS} (${GLOBAL_PCT}%) - DEFICIENTE${NC}"
    fi
else
    echo -e "  ${YELLOW}No se pudieron ejecutar verificaciones${NC}"
fi

# Problemas detectados
if [[ ${#ALL_ISSUES[@]} -gt 0 ]]; then
    echo ""
    echo -e "  ${BOLD}Problemas detectados (${#ALL_ISSUES[@]}):${NC}"
    for issue in "${ALL_ISSUES[@]}"; do
        echo -e "    ${RED}- $issue${NC}"
    done
fi

echo ""
echo "Reporte guardado en: $REPORT_FILE"

# ── Guardar reporte ──────────────────────────────────────────
{
    echo "============================================================"
    echo "AUDITORIA INTEGRAL DE SEGURIDAD LDAP/AD"
    echo "============================================================"
    echo "Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Hostname: $(hostname)"
    echo "Distro: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"
    echo ""
    echo "RESULTADOS POR SECCION:"
    for result in "${SECTION_RESULTS[@]}"; do
        echo "  $result"
    done
    echo ""
    if [[ $TOTAL_CHECKS -gt 0 ]]; then
        GLOBAL_PCT=$((TOTAL_SCORE * 100 / TOTAL_CHECKS))
        echo "PUNTUACION GLOBAL: ${TOTAL_SCORE}/${TOTAL_CHECKS} (${GLOBAL_PCT}%)"
        if [[ $GLOBAL_PCT -ge 80 ]]; then
            echo "ESTADO: BUENO"
        elif [[ $GLOBAL_PCT -ge 50 ]]; then
            echo "ESTADO: MEJORABLE"
        else
            echo "ESTADO: DEFICIENTE"
        fi
    fi
    echo ""
    if [[ ${#ALL_ISSUES[@]} -gt 0 ]]; then
        echo "PROBLEMAS DETECTADOS:"
        for issue in "${ALL_ISSUES[@]}"; do
            echo "  - $issue"
        done
    fi
    echo ""
    echo "============================================================"
} > "$REPORT_FILE"
chmod 600 "$REPORT_FILE"
echo ""
EOFAUDITLDAP
    chmod +x /usr/local/bin/auditar-ldap-seguridad.sh
    log_change "Creado" "/usr/local/bin/auditar-ldap-seguridad.sh"

    # ── Cron semanal de auditoria ────────────────────────────
    if ask "¿Programar auditoria semanal LDAP/AD?"; then
        cat > /etc/cron.weekly/auditoria-ldap << 'EOFCRONAUDIT'
#!/bin/bash
# Auditoria semanal de seguridad LDAP/AD - securizar Modulo 53
/usr/local/bin/auditar-ldap-seguridad.sh >> /var/log/securizar/auditoria-ldap-semanal.log 2>&1
EOFCRONAUDIT
        chmod +x /etc/cron.weekly/auditoria-ldap
        log_change "Creado" "/etc/cron.weekly/auditoria-ldap"
    else
        log_skip "Cron semanal de auditoria LDAP/AD"
    fi

    # ── Ejecutar auditoria inicial ───────────────────────────
    if ask "¿Ejecutar auditoria integral ahora?"; then
        /usr/local/bin/auditar-ldap-seguridad.sh 2>/dev/null || true
        log_change "Ejecutado" "Auditoria integral LDAP/AD"
    else
        log_skip "Auditoria integral inicial"
    fi

    log_info "Sistema de auditoria integral LDAP/AD instalado"
    log_info "Ejecuta: auditar-ldap-seguridad.sh"
else
    log_skip "Auditoria integral LDAP/AD"
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
show_changes_summary
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     SEGURIDAD LDAP Y ACTIVE DIRECTORY COMPLETADO          ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups guardados en: $BACKUP_DIR"
echo ""
echo "Comandos utiles post-hardening:"
echo "  - Verificar slapd:         securizar-slapd.sh"
echo "  - Verificar SSSD:          securizar-sssd.sh"
echo "  - Verificar Kerberos:      verificar-kerberos.sh"
echo "  - Auditar FreeIPA:         auditar-freeipa.sh"
echo "  - Verificar Samba:         securizar-samba.sh"
echo "  - Auditar acceso LDAP:     auditar-acceso-ldap.sh"
echo "  - Monitorizar directorio:  monitorizar-directorio.sh [--watch|--report]"
echo "  - Backup LDAP:             backup-ldap.sh [--verify|--list]"
echo "  - Restaurar LDAP:          restaurar-ldap.sh [archivo.ldif.gz]"
echo "  - Auditoria completa:      auditar-ldap-seguridad.sh"
echo ""
log_info "Modulo 53 completado"
log_warn "RECOMENDACION: Ejecuta 'auditar-ldap-seguridad.sh' para ver la postura actual"
