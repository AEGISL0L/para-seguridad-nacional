#!/bin/bash
# ============================================================
# SEGURIDAD DE EMAIL - Linux Multi-Distro
# Modulo 42 - Securizar Suite
# ============================================================
# Secciones:
#   S1  - Hardening de Postfix/SMTP
#   S2  - SPF (Sender Policy Framework)
#   S3  - DKIM (DomainKeys Identified Mail)
#   S4  - DMARC (Domain-based Message Authentication)
#   S5  - TLS obligatorio para SMTP
#   S6  - Anti-relay y restricciones SMTP
#   S7  - Proteccion contra email spoofing
#   S8  - Filtrado de contenido y spam
#   S9  - Monitorizacion de email
#   S10 - Auditoria completa de seguridad email
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "seguridad-email"
securizar_setup_traps

# ── Pre-check: detectar secciones ya aplicadas ────────────
_precheck 10
_pc 'check_file_contains "/etc/postfix/main.cf" "disable_vrfy_command = yes"'
_pc 'check_executable "/usr/local/bin/verificar-spf.sh"'
_pc 'check_file_exists "/etc/opendkim/opendkim.conf"'
_pc 'check_executable "/usr/local/bin/verificar-dmarc.sh"'
_pc 'check_file_contains "/etc/postfix/main.cf" "smtpd_tls_security_level"'
_pc 'check_file_contains "/etc/postfix/main.cf" "smtpd_recipient_restrictions"'
_pc 'check_executable "/usr/local/bin/detectar-email-spoofing.sh"'
_pc 'check_file_exists "/etc/mail/spamassassin/local.cf"'
_pc 'check_executable "/usr/local/bin/monitorizar-email.sh"'
_pc 'check_executable "/usr/local/bin/auditoria-email.sh"'
_precheck_result

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MODULO 42 - SEGURIDAD DE EMAIL                         ║"
echo "║   SPF, DKIM, DMARC, TLS, anti-relay, spoofing,          ║"
echo "║   spam, monitorizacion                                    ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

# Directorio de configuracion securizar para email
mkdir -p /etc/securizar/email

# Detectar Postfix
HAS_POSTFIX=0
if command -v postconf &>/dev/null; then
    HAS_POSTFIX=1
    log_info "Postfix detectado: $(postconf -d mail_version 2>/dev/null | awk '{print $NF}' || echo 'version desconocida')"
else
    log_warn "Postfix no detectado. Algunas secciones prepararan configuracion para uso futuro."
fi

# Obtener hostname y dominio del sistema
SYSTEM_HOSTNAME=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo "localhost")
SYSTEM_DOMAIN=$(hostname -d 2>/dev/null || echo "localdomain")
[[ -z "$SYSTEM_DOMAIN" || "$SYSTEM_DOMAIN" == "(none)" ]] && SYSTEM_DOMAIN="localdomain"

# ============================================================
# S1: HARDENING DE POSTFIX/SMTP
# ============================================================
log_section "S1: HARDENING DE POSTFIX/SMTP"

echo "Aplica configuracion de seguridad a Postfix:"
echo "  - Banner sin fuga de version"
echo "  - Desactivar VRFY y exigir HELO"
echo "  - Envolventes estrictas RFC 821"
echo "  - Retraso de rechazo (delay_reject)"
echo "  - Restricciones de cabeceras (header_checks)"
echo ""

if check_file_contains "/etc/postfix/main.cf" "disable_vrfy_command = yes"; then
    log_already "Hardening de Postfix (disable_vrfy_command ya configurado)"
elif ask "¿Aplicar hardening de Postfix?"; then

    if [[ $HAS_POSTFIX -eq 0 ]]; then
        log_warn "Postfix no esta instalado."
        if ask "¿Instalar Postfix ahora?"; then
            pkg_install "postfix"
            HAS_POSTFIX=1
            log_info "Postfix instalado correctamente"
        else
            log_skip "Instalacion de Postfix"
        fi
    fi

    if [[ $HAS_POSTFIX -eq 1 ]]; then
        POSTFIX_MAIN="/etc/postfix/main.cf"

        if [[ -f "$POSTFIX_MAIN" ]]; then
            cp "$POSTFIX_MAIN" "$BACKUP_DIR/"
            log_change "Backup" "$POSTFIX_MAIN"
        else
            mkdir -p /etc/postfix
            touch "$POSTFIX_MAIN"
            log_warn "main.cf no existia, creado vacio"
        fi

        # Funcion auxiliar para establecer parametro en main.cf
        # Si ya existe, lo reemplaza; si no, lo anade al final
        postfix_set_param() {
            local param="$1"
            local value="$2"
            local file="${3:-$POSTFIX_MAIN}"
            if grep -q "^${param}\s*=" "$file" 2>/dev/null; then
                sed -i "s|^${param}\s*=.*|${param} = ${value}|" "$file"
            else
                echo "${param} = ${value}" >> "$file"
            fi
        }

        # Banner sin fuga de version
        postfix_set_param "smtpd_banner" "\$myhostname ESMTP"
        log_change "Configurado" "smtpd_banner sin version (anti-fingerprinting)"

        # Desactivar VRFY (enumeracion de usuarios)
        postfix_set_param "disable_vrfy_command" "yes"
        log_change "Configurado" "disable_vrfy_command = yes"

        # Exigir HELO/EHLO
        postfix_set_param "smtpd_helo_required" "yes"
        log_change "Configurado" "smtpd_helo_required = yes"

        # Envolventes estrictas RFC 821
        postfix_set_param "strict_rfc821_envelopes" "yes"
        log_change "Configurado" "strict_rfc821_envelopes = yes"

        # Retraso de rechazo (mejora deteccion de spam)
        postfix_set_param "smtpd_delay_reject" "yes"
        log_change "Configurado" "smtpd_delay_reject = yes"

        # Limitar tamano de mensaje (25MB)
        postfix_set_param "message_size_limit" "26214400"
        log_change "Configurado" "message_size_limit = 25MB"

        # Limitar tamano de buzon (512MB)
        postfix_set_param "mailbox_size_limit" "536870912"
        log_change "Configurado" "mailbox_size_limit = 512MB"

        # No mostrar informacion de software en respuestas
        postfix_set_param "smtpd_forbid_bare_newline" "yes"
        log_change "Configurado" "smtpd_forbid_bare_newline = yes"

        # Configurar header_checks para filtrar cabeceras sensibles
        HEADER_CHECKS="/etc/postfix/header_checks"
        if [[ -f "$HEADER_CHECKS" ]]; then
            cp "$HEADER_CHECKS" "$BACKUP_DIR/"
            log_change "Backup" "$HEADER_CHECKS"
        fi

        cat > "$HEADER_CHECKS" << 'EOF'
# ============================================================
# header_checks - Filtro de cabeceras de correo
# Generado por securizar - Modulo 42
# ============================================================
# Eliminar cabeceras que revelan informacion interna
/^X-Mailer:/                    IGNORE
/^X-Originating-IP:/            IGNORE
/^X-MimeOLE:/                   IGNORE
/^User-Agent:/                  IGNORE
# Rechazar asuntos vacios (comun en spam)
/^Subject:\s*$/                 REJECT El asunto del mensaje no puede estar vacio
# Advertir sobre contenido ejecutable en asunto
/^Subject:.*\.(exe|bat|scr|vbs|js|cmd|ps1)/  WARN Posible contenido malicioso en asunto
EOF
        chmod 644 "$HEADER_CHECKS"
        postfix_set_param "header_checks" "regexp:$HEADER_CHECKS"
        log_change "Creado" "$HEADER_CHECKS (filtro de cabeceras)"

        # Recargar Postfix si esta activo
        if systemctl is-active postfix &>/dev/null; then
            postfix check 2>/dev/null && {
                systemctl reload postfix 2>/dev/null || true
                log_change "Aplicado" "reload postfix"
            } || {
                log_error "Error en configuracion de Postfix - revisar manualmente"
            }
        else
            log_info "Postfix no esta activo. Los cambios se aplicaran al iniciar."
        fi

        log_info "Hardening basico de Postfix aplicado"
    fi
else
    log_skip "Hardening de Postfix"
fi

# ============================================================
# S2: SPF (SENDER POLICY FRAMEWORK)
# ============================================================
log_section "S2: SPF (SENDER POLICY FRAMEWORK)"

echo "Crea herramientas de verificacion y auditoria SPF:"
echo "  - Script de validacion de registros SPF via DNS"
echo "  - Deteccion de SPF permisivos (~all vs -all)"
echo "  - Plantilla de registro SPF recomendado"
echo "  - Verificador instalado en /usr/local/bin/"
echo ""

if check_executable "/usr/local/bin/verificar-spf.sh"; then
    log_already "Herramientas SPF (verificar-spf.sh ya instalado)"
elif ask "¿Crear herramientas de verificacion SPF?"; then

    # Verificar que dig o host estan disponibles
    DIG_CMD=""
    if command -v dig &>/dev/null; then
        DIG_CMD="dig"
    elif command -v host &>/dev/null; then
        DIG_CMD="host"
    else
        log_warn "Ni dig ni host encontrados. Intentando instalar bind-utils..."
        pkg_install "bind-utils" || pkg_install "dnsutils" || true
        if command -v dig &>/dev/null; then
            DIG_CMD="dig"
        elif command -v host &>/dev/null; then
            DIG_CMD="host"
        fi
    fi

    if [[ -z "$DIG_CMD" ]]; then
        log_warn "No se pudo obtener herramientas DNS. Los scripts se crearan pero necesitaran dig/host."
    fi

    # Script de verificacion SPF
    cat > /usr/local/bin/verificar-spf.sh << 'EOFSPF'
#!/bin/bash
# ============================================================
# Verificador de registros SPF - securizar Modulo 42
# Uso: verificar-spf.sh [dominio]
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

DOMINIO="${1:-}"
if [[ -z "$DOMINIO" ]]; then
    DOMINIO=$(hostname -d 2>/dev/null || echo "")
    if [[ -z "$DOMINIO" || "$DOMINIO" == "(none)" ]]; then
        echo "Uso: verificar-spf.sh <dominio>"
        echo "Ejemplo: verificar-spf.sh midominio.com"
        exit 1
    fi
    echo -e "${DIM}Usando dominio del sistema: ${DOMINIO}${NC}"
fi

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  VERIFICACION SPF: ${DOMINIO}${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

# Obtener registro SPF
SPF_RECORD=""
if command -v dig &>/dev/null; then
    SPF_RECORD=$(dig +short TXT "$DOMINIO" 2>/dev/null | grep -i "v=spf1" | tr -d '"' || echo "")
elif command -v host &>/dev/null; then
    SPF_RECORD=$(host -t TXT "$DOMINIO" 2>/dev/null | grep -i "v=spf1" | sed 's/.*descriptive text "//;s/"$//' || echo "")
else
    echo -e "${RED}[X] Se necesita dig o host para consultas DNS${NC}"
    exit 1
fi

if [[ -z "$SPF_RECORD" ]]; then
    echo -e "${RED}[X] NO se encontro registro SPF para ${DOMINIO}${NC}"
    echo ""
    echo -e "${YELLOW}Recomendacion: Crear un registro DNS TXT con:${NC}"
    echo -e "  ${BOLD}v=spf1 mx a -all${NC}"
    echo ""
    echo "Registro recomendado (minimo):"
    echo "  ${DOMINIO}.  IN  TXT  \"v=spf1 mx -all\""
    exit 1
fi

echo -e "${CYAN}Registro SPF encontrado:${NC}"
echo -e "  ${BOLD}${SPF_RECORD}${NC}"
echo ""

# Analizar el registro
PUNTUACION=0
TOTAL_CHECKS=0
PROBLEMAS=()

# Verificar version
((TOTAL_CHECKS++))
if echo "$SPF_RECORD" | grep -qi "^v=spf1"; then
    echo -e "  ${GREEN}[OK]${NC} Version SPF1 correcta"
    ((PUNTUACION++))
else
    echo -e "  ${RED}[!!]${NC} Version SPF invalida"
    PROBLEMAS+=("Version SPF no es v=spf1")
fi

# Verificar mecanismo all
((TOTAL_CHECKS++))
if echo "$SPF_RECORD" | grep -q "\-all$"; then
    echo -e "  ${GREEN}[OK]${NC} Politica estricta: -all (hard fail)"
    ((PUNTUACION++))
elif echo "$SPF_RECORD" | grep -q "~all$"; then
    echo -e "  ${YELLOW}[!]${NC}  Politica permisiva: ~all (soft fail) - se recomienda -all"
    PROBLEMAS+=("Usar -all en lugar de ~all para mayor seguridad")
elif echo "$SPF_RECORD" | grep -q "\?all$"; then
    echo -e "  ${RED}[!!]${NC} Politica neutral: ?all - equivale a no tener SPF"
    PROBLEMAS+=("?all es inseguro, usar -all")
elif echo "$SPF_RECORD" | grep -q "+all$"; then
    echo -e "  ${RED}[!!]${NC} Politica abierta: +all - CUALQUIERA puede enviar como ${DOMINIO}"
    PROBLEMAS+=("CRITICO: +all permite a cualquiera suplantar el dominio")
else
    echo -e "  ${YELLOW}[!]${NC}  No se encontro mecanismo 'all' al final"
    PROBLEMAS+=("Falta mecanismo all al final del registro")
fi

# Contar lookups DNS (limite de 10)
((TOTAL_CHECKS++))
LOOKUP_COUNT=0
for mechanism in include redirect a mx ptr exists; do
    count=$(echo "$SPF_RECORD" | grep -oi "${mechanism}[: ]" | wc -l)
    ((LOOKUP_COUNT += count)) || true
done
if [[ $LOOKUP_COUNT -le 10 ]]; then
    echo -e "  ${GREEN}[OK]${NC} Lookups DNS: ${LOOKUP_COUNT}/10"
    ((PUNTUACION++))
else
    echo -e "  ${RED}[!!]${NC} Demasiados lookups DNS: ${LOOKUP_COUNT}/10 (limite excedido)"
    PROBLEMAS+=("Excede el limite de 10 lookups DNS")
fi

# Verificar mecanismos peligrosos
((TOTAL_CHECKS++))
PELIGROSO=0
if echo "$SPF_RECORD" | grep -qi "ptr"; then
    echo -e "  ${YELLOW}[!]${NC}  Mecanismo 'ptr' encontrado (lento, no recomendado)"
    PROBLEMAS+=("Mecanismo ptr es lento y no recomendado (RFC 7208)")
    PELIGROSO=1
fi
if echo "$SPF_RECORD" | grep -qi "ip4:0.0.0.0/0\|ip6:::/0"; then
    echo -e "  ${RED}[!!]${NC} Rango IP abierto detectado (0.0.0.0/0 o ::/0)"
    PROBLEMAS+=("Rango IP abierto permite envio desde cualquier IP")
    PELIGROSO=1
fi
if [[ $PELIGROSO -eq 0 ]]; then
    echo -e "  ${GREEN}[OK]${NC} Sin mecanismos peligrosos detectados"
    ((PUNTUACION++))
fi

# Resumen
echo ""
echo -e "${BOLD}── Resultado ──${NC}"
PORCENTAJE=$(( (PUNTUACION * 100) / TOTAL_CHECKS ))
if [[ $PORCENTAJE -ge 80 ]]; then
    echo -e "  ${GREEN}SEGURO${NC} - Puntuacion: ${PUNTUACION}/${TOTAL_CHECKS} (${PORCENTAJE}%)"
elif [[ $PORCENTAJE -ge 50 ]]; then
    echo -e "  ${YELLOW}MEJORABLE${NC} - Puntuacion: ${PUNTUACION}/${TOTAL_CHECKS} (${PORCENTAJE}%)"
else
    echo -e "  ${RED}INSEGURO${NC} - Puntuacion: ${PUNTUACION}/${TOTAL_CHECKS} (${PORCENTAJE}%)"
fi

if [[ ${#PROBLEMAS[@]} -gt 0 ]]; then
    echo ""
    echo -e "${YELLOW}Problemas encontrados:${NC}"
    for prob in "${PROBLEMAS[@]}"; do
        echo -e "  - ${prob}"
    done
fi

echo ""
echo -e "${DIM}Verificacion completada: $(date)${NC}"
EOFSPF
    chmod +x /usr/local/bin/verificar-spf.sh
    log_change "Creado" "/usr/local/bin/verificar-spf.sh"

    # Plantilla SPF recomendada
    cat > /etc/securizar/email/spf-recomendado.txt << EOF
# ============================================================
# Registro SPF recomendado para: ${SYSTEM_DOMAIN}
# Generado por securizar - Modulo 42
# ============================================================
# Registro DNS TXT a crear:
#
# Basico (solo el servidor MX puede enviar):
#   ${SYSTEM_DOMAIN}.  IN  TXT  "v=spf1 mx -all"
#
# Con IP especifica:
#   ${SYSTEM_DOMAIN}.  IN  TXT  "v=spf1 mx ip4:<IP_SERVIDOR> -all"
#
# Con servicio externo (ej: Google Workspace):
#   ${SYSTEM_DOMAIN}.  IN  TXT  "v=spf1 mx include:_spf.google.com -all"
#
# IMPORTANTE: Siempre usar -all (hard fail) en lugar de ~all
# IMPORTANTE: No exceder 10 lookups DNS en total
# ============================================================
EOF
    log_change "Creado" "/etc/securizar/email/spf-recomendado.txt"

    log_info "Herramientas SPF instaladas. Ejecuta: verificar-spf.sh <dominio>"
else
    log_skip "Herramientas de verificacion SPF"
fi

# ============================================================
# S3: DKIM (DOMAINKEYS IDENTIFIED MAIL)
# ============================================================
log_section "S3: DKIM (DOMAINKEYS IDENTIFIED MAIL)"

echo "Instala y configura OpenDKIM para firma de correos:"
echo "  - Generacion de par de claves DKIM"
echo "  - Configuracion de KeyTable, SigningTable, TrustedHosts"
echo "  - Integracion con Postfix via milter"
echo "  - Script de rotacion de claves"
echo ""

if check_file_exists "/etc/opendkim/opendkim.conf"; then
    log_already "DKIM (opendkim.conf ya configurado)"
elif ask "¿Configurar DKIM (OpenDKIM)?"; then

    # Instalar opendkim
    if ! command -v opendkim &>/dev/null; then
        log_info "Instalando OpenDKIM..."
        pkg_install "opendkim" || {
            log_error "No se pudo instalar opendkim"
            log_skip "Configuracion DKIM"
        }
    fi

    if command -v opendkim &>/dev/null || [[ -f /usr/sbin/opendkim ]]; then
        DKIM_DIR="/etc/opendkim"
        DKIM_KEYS_DIR="${DKIM_DIR}/keys/${SYSTEM_DOMAIN}"

        mkdir -p "$DKIM_KEYS_DIR"
        mkdir -p "${DKIM_DIR}/keys"

        # Backup si existe configuracion previa
        if [[ -f "${DKIM_DIR}/opendkim.conf" ]]; then
            cp "${DKIM_DIR}/opendkim.conf" "$BACKUP_DIR/"
            log_change "Backup" "${DKIM_DIR}/opendkim.conf"
        fi

        # Generar clave DKIM si no existe
        SELECTOR="securizar$(date +%Y%m)"
        KEY_FILE="${DKIM_KEYS_DIR}/${SELECTOR}.private"

        if [[ ! -f "$KEY_FILE" ]]; then
            if command -v opendkim-genkey &>/dev/null; then
                opendkim-genkey -b 2048 -d "$SYSTEM_DOMAIN" -D "$DKIM_KEYS_DIR" -s "$SELECTOR" -v 2>/dev/null || true
                log_change "Generado" "Clave DKIM: ${DKIM_KEYS_DIR}/${SELECTOR}"
            else
                log_warn "opendkim-genkey no disponible. Genera la clave manualmente."
            fi
        else
            log_info "Clave DKIM ya existe: $KEY_FILE"
        fi

        # Establecer permisos seguros
        chown -R opendkim:opendkim "$DKIM_DIR" 2>/dev/null || chown -R root:root "$DKIM_DIR"
        chmod 700 "$DKIM_KEYS_DIR"
        [[ -f "$KEY_FILE" ]] && chmod 600 "$KEY_FILE"

        # Configuracion principal de OpenDKIM
        cat > "${DKIM_DIR}/opendkim.conf" << EOF
# ============================================================
# OpenDKIM - Configuracion generada por securizar Modulo 42
# ============================================================

# Parametros basicos
Syslog                  yes
SyslogSuccess           yes
LogWhy                  yes

# Modo: firmar (s) y verificar (v)
Mode                    sv

# Canonicalizacion: relaxed para cabeceras, simple para cuerpo
Canonicalization        relaxed/simple

# Directorio de claves
KeyTable                refile:${DKIM_DIR}/KeyTable
SigningTable             refile:${DKIM_DIR}/SigningTable
ExternalIgnoreList      refile:${DKIM_DIR}/TrustedHosts
InternalHosts           refile:${DKIM_DIR}/TrustedHosts

# Algoritmo de firma
SignatureAlgorithm      rsa-sha256

# Socket para comunicacion con Postfix
Socket                  inet:8891@localhost

# PID
PidFile                 /run/opendkim/opendkim.pid

# Usuario
UserID                  opendkim:opendkim

# Directorio temporal
TemporaryDirectory      /var/tmp

# Longitud minima de clave para verificacion
MinimumKeyBits          1024

# No firmar subdominios automaticamente
SubDomains              no

# Auto reiniciar en caso de error
AutoRestart             yes
AutoRestartRate         10/1h
EOF
        chmod 644 "${DKIM_DIR}/opendkim.conf"
        log_change "Creado" "${DKIM_DIR}/opendkim.conf"

        # KeyTable
        cat > "${DKIM_DIR}/KeyTable" << EOF
# ============================================================
# KeyTable - Mapeo de selectores a claves DKIM
# Formato: nombre_clave dominio:selector:/ruta/clave.private
# ============================================================
${SELECTOR}._domainkey.${SYSTEM_DOMAIN} ${SYSTEM_DOMAIN}:${SELECTOR}:${DKIM_KEYS_DIR}/${SELECTOR}.private
EOF
        log_change "Creado" "${DKIM_DIR}/KeyTable"

        # SigningTable
        cat > "${DKIM_DIR}/SigningTable" << EOF
# ============================================================
# SigningTable - Que dominios firmar con que clave
# Formato: patron nombre_clave
# ============================================================
*@${SYSTEM_DOMAIN} ${SELECTOR}._domainkey.${SYSTEM_DOMAIN}
EOF
        log_change "Creado" "${DKIM_DIR}/SigningTable"

        # TrustedHosts
        cat > "${DKIM_DIR}/TrustedHosts" << EOF
# ============================================================
# TrustedHosts - Hosts de confianza (no verificar firmas)
# ============================================================
127.0.0.1
::1
localhost
${SYSTEM_HOSTNAME}
*.${SYSTEM_DOMAIN}
EOF
        log_change "Creado" "${DKIM_DIR}/TrustedHosts"

        # Integracion con Postfix
        if [[ $HAS_POSTFIX -eq 1 ]]; then
            # Verificar si ya tiene milter configurado
            CURRENT_MILTERS=$(postconf -h smtpd_milters 2>/dev/null || echo "")
            DKIM_MILTER="inet:localhost:8891"

            if echo "$CURRENT_MILTERS" | grep -q "8891"; then
                log_info "Milter DKIM ya configurado en Postfix"
            else
                if [[ -n "$CURRENT_MILTERS" ]]; then
                    NEW_MILTERS="${CURRENT_MILTERS}, ${DKIM_MILTER}"
                else
                    NEW_MILTERS="$DKIM_MILTER"
                fi
                postfix_set_param "smtpd_milters" "$NEW_MILTERS"
                postfix_set_param "non_smtpd_milters" "$NEW_MILTERS"
                postfix_set_param "milter_default_action" "accept"
                postfix_set_param "milter_protocol" "6"
                log_change "Configurado" "Postfix milter DKIM: $DKIM_MILTER"
            fi
        fi

        # Script de rotacion de claves DKIM
        cat > /usr/local/bin/rotar-dkim.sh << 'EOFDKIMROT'
#!/bin/bash
# ============================================================
# Rotacion de claves DKIM - securizar Modulo 42
# Genera nueva clave y actualiza configuracion
# Uso: rotar-dkim.sh [dominio]
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Este script debe ejecutarse como root${NC}"
    exit 1
fi

DOMINIO="${1:-}"
if [[ -z "$DOMINIO" ]]; then
    DOMINIO=$(hostname -d 2>/dev/null || echo "")
    if [[ -z "$DOMINIO" || "$DOMINIO" == "(none)" ]]; then
        echo "Uso: rotar-dkim.sh <dominio>"
        exit 1
    fi
fi

DKIM_DIR="/etc/opendkim"
KEYS_DIR="${DKIM_DIR}/keys/${DOMINIO}"
NEW_SELECTOR="securizar$(date +%Y%m)"

echo -e "${BOLD}Rotacion de clave DKIM para: ${DOMINIO}${NC}"
echo -e "Nuevo selector: ${NEW_SELECTOR}"
echo ""

# Backup de clave anterior
if [[ -d "$KEYS_DIR" ]]; then
    BACKUP_KEYS="${KEYS_DIR}/backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_KEYS"
    cp "${KEYS_DIR}"/*.private "$BACKUP_KEYS/" 2>/dev/null || true
    cp "${KEYS_DIR}"/*.txt "$BACKUP_KEYS/" 2>/dev/null || true
    echo -e "${GREEN}[+]${NC} Claves anteriores respaldadas en: $BACKUP_KEYS"
fi

# Generar nueva clave
mkdir -p "$KEYS_DIR"
if command -v opendkim-genkey &>/dev/null; then
    opendkim-genkey -b 2048 -d "$DOMINIO" -D "$KEYS_DIR" -s "$NEW_SELECTOR" -v
    echo -e "${GREEN}[+]${NC} Nueva clave generada: ${KEYS_DIR}/${NEW_SELECTOR}"
else
    echo -e "${RED}[X] opendkim-genkey no disponible${NC}"
    exit 1
fi

# Actualizar permisos
chown -R opendkim:opendkim "$DKIM_DIR" 2>/dev/null || true
chmod 600 "${KEYS_DIR}/${NEW_SELECTOR}.private"

# Actualizar KeyTable
cat > "${DKIM_DIR}/KeyTable" << EOFKT
${NEW_SELECTOR}._domainkey.${DOMINIO} ${DOMINIO}:${NEW_SELECTOR}:${KEYS_DIR}/${NEW_SELECTOR}.private
EOFKT

# Actualizar SigningTable
cat > "${DKIM_DIR}/SigningTable" << EOFST
*@${DOMINIO} ${NEW_SELECTOR}._domainkey.${DOMINIO}
EOFST

echo ""
echo -e "${GREEN}[+]${NC} KeyTable y SigningTable actualizados"

# Mostrar registro DNS necesario
echo ""
echo -e "${YELLOW}IMPORTANTE: Actualiza el registro DNS TXT:${NC}"
if [[ -f "${KEYS_DIR}/${NEW_SELECTOR}.txt" ]]; then
    echo ""
    cat "${KEYS_DIR}/${NEW_SELECTOR}.txt"
fi

echo ""
echo -e "${YELLOW}No elimines el registro DNS del selector anterior hasta que${NC}"
echo -e "${YELLOW}todos los correos firmados con el hayan sido entregados (48-72h).${NC}"

# Reiniciar opendkim
if systemctl is-active opendkim &>/dev/null; then
    systemctl restart opendkim
    echo -e "${GREEN}[+]${NC} OpenDKIM reiniciado"
fi

echo ""
echo -e "${BOLD}Rotacion completada: $(date)${NC}"
EOFDKIMROT
        chmod +x /usr/local/bin/rotar-dkim.sh
        log_change "Creado" "/usr/local/bin/rotar-dkim.sh"

        # Habilitar servicio opendkim
        systemctl enable opendkim 2>/dev/null || true
        log_change "Habilitado" "servicio opendkim"

        # Mostrar registro DNS necesario
        DNS_RECORD_FILE="${DKIM_KEYS_DIR}/${SELECTOR}.txt"
        if [[ -f "$DNS_RECORD_FILE" ]]; then
            echo ""
            log_warn "IMPORTANTE: Crea el siguiente registro DNS TXT:"
            cat "$DNS_RECORD_FILE"
            echo ""
        fi

        log_info "OpenDKIM configurado. Selector: $SELECTOR"
    fi
else
    log_skip "Configuracion DKIM"
fi

# ============================================================
# S4: DMARC (DOMAIN-BASED MESSAGE AUTHENTICATION)
# ============================================================
log_section "S4: DMARC (DOMAIN-BASED MESSAGE AUTHENTICATION)"

echo "Instala y configura OpenDMARC:"
echo "  - Configuracion de /etc/opendmarc.conf"
echo "  - Integracion con Postfix milter (despues de DKIM)"
echo "  - Script de verificacion DMARC por dominio"
echo "  - Plantilla de registro DMARC recomendado (p=reject)"
echo ""

if check_executable "/usr/local/bin/verificar-dmarc.sh"; then
    log_already "DMARC (verificar-dmarc.sh ya instalado)"
elif ask "¿Configurar DMARC (OpenDMARC)?"; then

    # Instalar opendmarc
    if ! command -v opendmarc &>/dev/null; then
        log_info "Instalando OpenDMARC..."
        pkg_install "opendmarc" || {
            log_error "No se pudo instalar opendmarc"
            log_skip "Configuracion DMARC"
        }
    fi

    if command -v opendmarc &>/dev/null || [[ -f /usr/sbin/opendmarc ]]; then
        DMARC_CONF="/etc/opendmarc.conf"

        if [[ -f "$DMARC_CONF" ]]; then
            cp "$DMARC_CONF" "$BACKUP_DIR/"
            log_change "Backup" "$DMARC_CONF"
        fi

        # Crear directorio para base de datos de historial
        mkdir -p /var/lib/opendmarc
        chown opendmarc:opendmarc /var/lib/opendmarc 2>/dev/null || true

        cat > "$DMARC_CONF" << EOF
# ============================================================
# OpenDMARC - Configuracion generada por securizar Modulo 42
# ============================================================

# Dominio de autenticacion
AuthservID              ${SYSTEM_HOSTNAME}

# Rechazar mensajes que fallen DMARC
# none = solo reportar, quarantine = cuarentena, reject = rechazar
FailureReports          true

# Socket para comunicacion con Postfix
Socket                  inet:8893@localhost

# PID
PidFile                 /run/opendmarc/opendmarc.pid

# Logging
Syslog                  true
SyslogFacility          mail

# Base de datos de historial
HistoryFile             /var/lib/opendmarc/opendmarc.dat

# Ignorar hosts internos (mismo que TrustedHosts de DKIM)
IgnoreAuthenticatedClients  true

# No ignorar listas de correo
IgnoreMailFrom          no

# SPF: verificar SPF ademas de DKIM
SPFSelfValidate         true
SPFIgnoreResults        false

# Cabeceras a insertar
AuthservIDWithJobID     no

# Registro detallado
RequiredHeaders         true

# Usuario
UserID                  opendmarc:opendmarc
EOF
        chmod 644 "$DMARC_CONF"
        log_change "Creado" "$DMARC_CONF"

        # Integracion con Postfix (despues del milter DKIM)
        if [[ $HAS_POSTFIX -eq 1 ]]; then
            CURRENT_MILTERS=$(postconf -h smtpd_milters 2>/dev/null || echo "")
            DMARC_MILTER="inet:localhost:8893"

            if echo "$CURRENT_MILTERS" | grep -q "8893"; then
                log_info "Milter DMARC ya configurado en Postfix"
            else
                if [[ -n "$CURRENT_MILTERS" ]]; then
                    NEW_MILTERS="${CURRENT_MILTERS}, ${DMARC_MILTER}"
                else
                    NEW_MILTERS="$DMARC_MILTER"
                fi
                postfix_set_param "smtpd_milters" "$NEW_MILTERS"
                postfix_set_param "non_smtpd_milters" "$NEW_MILTERS"
                log_change "Configurado" "Postfix milter DMARC: $DMARC_MILTER"
            fi
        fi

        # Script de verificacion DMARC
        cat > /usr/local/bin/verificar-dmarc.sh << 'EOFDMARC'
#!/bin/bash
# ============================================================
# Verificador de registros DMARC - securizar Modulo 42
# Uso: verificar-dmarc.sh [dominio]
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

DOMINIO="${1:-}"
if [[ -z "$DOMINIO" ]]; then
    DOMINIO=$(hostname -d 2>/dev/null || echo "")
    if [[ -z "$DOMINIO" || "$DOMINIO" == "(none)" ]]; then
        echo "Uso: verificar-dmarc.sh <dominio>"
        exit 1
    fi
fi

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  VERIFICACION DMARC: ${DOMINIO}${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

# Obtener registro DMARC
DMARC_RECORD=""
if command -v dig &>/dev/null; then
    DMARC_RECORD=$(dig +short TXT "_dmarc.${DOMINIO}" 2>/dev/null | tr -d '"' || echo "")
elif command -v host &>/dev/null; then
    DMARC_RECORD=$(host -t TXT "_dmarc.${DOMINIO}" 2>/dev/null | grep "descriptive text" | sed 's/.*descriptive text "//;s/"$//' || echo "")
else
    echo -e "${RED}[X] Se necesita dig o host${NC}"
    exit 1
fi

if [[ -z "$DMARC_RECORD" ]]; then
    echo -e "${RED}[X] NO se encontro registro DMARC para ${DOMINIO}${NC}"
    echo ""
    echo -e "${YELLOW}Recomendacion: Crear registro DNS TXT en _dmarc.${DOMINIO}:${NC}"
    echo -e "  ${BOLD}v=DMARC1; p=reject; rua=mailto:dmarc@${DOMINIO}; pct=100${NC}"
    exit 1
fi

echo -e "${CYAN}Registro DMARC encontrado:${NC}"
echo -e "  ${BOLD}${DMARC_RECORD}${NC}"
echo ""

PUNTUACION=0
TOTAL_CHECKS=0
PROBLEMAS=()

# Verificar version
((TOTAL_CHECKS++))
if echo "$DMARC_RECORD" | grep -qi "v=DMARC1"; then
    echo -e "  ${GREEN}[OK]${NC} Version DMARC1 correcta"
    ((PUNTUACION++))
else
    echo -e "  ${RED}[!!]${NC} Version DMARC invalida"
    PROBLEMAS+=("Version debe ser v=DMARC1")
fi

# Verificar politica
((TOTAL_CHECKS++))
POLICY=$(echo "$DMARC_RECORD" | grep -oi "p=[a-z]*" | head -1 | cut -d= -f2)
case "$POLICY" in
    reject)
        echo -e "  ${GREEN}[OK]${NC} Politica: reject (maxima proteccion)"
        ((PUNTUACION++))
        ;;
    quarantine)
        echo -e "  ${YELLOW}[!]${NC}  Politica: quarantine (buena, pero reject es mejor)"
        PROBLEMAS+=("Considerar cambiar p=quarantine a p=reject")
        ;;
    none)
        echo -e "  ${RED}[!!]${NC} Politica: none (solo monitoreo, sin proteccion)"
        PROBLEMAS+=("p=none no protege contra spoofing, usar p=reject")
        ;;
    *)
        echo -e "  ${RED}[!!]${NC} Politica no reconocida: $POLICY"
        PROBLEMAS+=("Politica DMARC no valida")
        ;;
esac

# Verificar rua (reportes agregados)
((TOTAL_CHECKS++))
if echo "$DMARC_RECORD" | grep -qi "rua="; then
    RUA=$(echo "$DMARC_RECORD" | grep -oi "rua=mailto:[^ ;]*" || echo "")
    echo -e "  ${GREEN}[OK]${NC} Reportes agregados (rua): ${RUA}"
    ((PUNTUACION++))
else
    echo -e "  ${YELLOW}[!]${NC}  Sin reportes agregados (rua) - no recibiras informes"
    PROBLEMAS+=("Agregar rua=mailto:dmarc@${DOMINIO} para recibir reportes")
fi

# Verificar porcentaje
((TOTAL_CHECKS++))
PCT=$(echo "$DMARC_RECORD" | grep -oi "pct=[0-9]*" | cut -d= -f2 || echo "")
if [[ -z "$PCT" || "$PCT" == "100" ]]; then
    echo -e "  ${GREEN}[OK]${NC} Porcentaje: 100% (todos los mensajes evaluados)"
    ((PUNTUACION++))
elif [[ "$PCT" -lt 100 ]]; then
    echo -e "  ${YELLOW}[!]${NC}  Porcentaje: ${PCT}% (no todos los mensajes evaluados)"
    PROBLEMAS+=("pct=${PCT} significa que solo ${PCT}% de mensajes se evaluan")
fi

# Verificar politica de subdominios
((TOTAL_CHECKS++))
SP=$(echo "$DMARC_RECORD" | grep -oi "sp=[a-z]*" | cut -d= -f2 || echo "")
if [[ -n "$SP" ]]; then
    if [[ "$SP" == "reject" ]]; then
        echo -e "  ${GREEN}[OK]${NC} Politica subdominios (sp): reject"
        ((PUNTUACION++))
    else
        echo -e "  ${YELLOW}[!]${NC}  Politica subdominios (sp): $SP"
        PROBLEMAS+=("Considerar sp=reject para subdominios")
    fi
else
    echo -e "  ${DIM}[--]${NC} Sin politica explicita de subdominios (hereda de p=)"
    ((PUNTUACION++))
fi

# Resumen
echo ""
echo -e "${BOLD}── Resultado ──${NC}"
PORCENTAJE=$(( (PUNTUACION * 100) / TOTAL_CHECKS ))
if [[ $PORCENTAJE -ge 80 ]]; then
    echo -e "  ${GREEN}SEGURO${NC} - Puntuacion: ${PUNTUACION}/${TOTAL_CHECKS} (${PORCENTAJE}%)"
elif [[ $PORCENTAJE -ge 50 ]]; then
    echo -e "  ${YELLOW}MEJORABLE${NC} - Puntuacion: ${PUNTUACION}/${TOTAL_CHECKS} (${PORCENTAJE}%)"
else
    echo -e "  ${RED}INSEGURO${NC} - Puntuacion: ${PUNTUACION}/${TOTAL_CHECKS} (${PORCENTAJE}%)"
fi

if [[ ${#PROBLEMAS[@]} -gt 0 ]]; then
    echo ""
    echo -e "${YELLOW}Problemas encontrados:${NC}"
    for prob in "${PROBLEMAS[@]}"; do
        echo -e "  - ${prob}"
    done
fi

echo ""
echo -e "${DIM}Verificacion completada: $(date)${NC}"
EOFDMARC
        chmod +x /usr/local/bin/verificar-dmarc.sh
        log_change "Creado" "/usr/local/bin/verificar-dmarc.sh"

        # Plantilla DMARC recomendada
        cat > /etc/securizar/email/dmarc-recomendado.txt << EOF
# ============================================================
# Registro DMARC recomendado para: ${SYSTEM_DOMAIN}
# Generado por securizar - Modulo 42
# ============================================================
# Registro DNS TXT en _dmarc.${SYSTEM_DOMAIN}:
#
# Implementacion gradual (fase 1 - monitoreo):
#   _dmarc.${SYSTEM_DOMAIN}.  IN  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@${SYSTEM_DOMAIN}; pct=100"
#
# Fase 2 - cuarentena:
#   _dmarc.${SYSTEM_DOMAIN}.  IN  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@${SYSTEM_DOMAIN}; pct=100"
#
# Fase 3 - rechazo total (recomendado):
#   _dmarc.${SYSTEM_DOMAIN}.  IN  TXT  "v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@${SYSTEM_DOMAIN}; ruf=mailto:dmarc-forensic@${SYSTEM_DOMAIN}; pct=100"
#
# IMPORTANTE: Implementar SPF y DKIM antes de activar DMARC con p=reject
# ============================================================
EOF
        log_change "Creado" "/etc/securizar/email/dmarc-recomendado.txt"

        # Habilitar servicio
        systemctl enable opendmarc 2>/dev/null || true
        log_change "Habilitado" "servicio opendmarc"

        log_info "OpenDMARC configurado. Ejecuta: verificar-dmarc.sh <dominio>"
    fi
else
    log_skip "Configuracion DMARC"
fi

# ============================================================
# S5: TLS OBLIGATORIO PARA SMTP
# ============================================================
log_section "S5: TLS OBLIGATORIO PARA SMTP"

echo "Configura cifrado TLS para correo entrante y saliente:"
echo "  - smtpd_tls_security_level = may (entrante)"
echo "  - smtp_tls_security_level = dane (saliente con DANE)"
echo "  - Protocolos: solo TLSv1.2 y TLSv1.3"
echo "  - Cifrados robustos sin SSLv2/SSLv3/TLSv1.0/TLSv1.1"
echo "  - Generacion de certificado autofirmado si no existe"
echo ""

if check_file_contains "/etc/postfix/main.cf" "smtpd_tls_security_level"; then
    log_already "TLS SMTP (smtpd_tls_security_level ya configurado)"
elif ask "¿Configurar TLS obligatorio para SMTP?"; then

    if [[ $HAS_POSTFIX -eq 0 ]]; then
        log_warn "Postfix no detectado. Configuracion TLS omitida."
        log_skip "TLS para SMTP (Postfix no disponible)"
    else
        POSTFIX_MAIN="/etc/postfix/main.cf"

        # Verificar si existen certificados
        CERT_FILE="/etc/ssl/certs/postfix-securizar.pem"
        KEY_FILE="/etc/ssl/private/postfix-securizar.key"

        # Comprobar certificados existentes de Postfix
        EXISTING_CERT=$(postconf -h smtpd_tls_cert_file 2>/dev/null || echo "")
        EXISTING_KEY=$(postconf -h smtpd_tls_key_file 2>/dev/null || echo "")

        USE_EXISTING=0
        if [[ -n "$EXISTING_CERT" && -f "$EXISTING_CERT" && -n "$EXISTING_KEY" && -f "$EXISTING_KEY" ]]; then
            log_info "Certificados TLS existentes detectados:"
            echo "  Certificado: $EXISTING_CERT"
            echo "  Clave:       $EXISTING_KEY"
            if ask "¿Usar los certificados existentes?"; then
                CERT_FILE="$EXISTING_CERT"
                KEY_FILE="$EXISTING_KEY"
                USE_EXISTING=1
            fi
        fi

        if [[ $USE_EXISTING -eq 0 ]]; then
            # Verificar Let's Encrypt
            LE_CERT="/etc/letsencrypt/live/${SYSTEM_HOSTNAME}/fullchain.pem"
            LE_KEY="/etc/letsencrypt/live/${SYSTEM_HOSTNAME}/privkey.pem"

            if [[ -f "$LE_CERT" && -f "$LE_KEY" ]]; then
                log_info "Certificado Let's Encrypt detectado para ${SYSTEM_HOSTNAME}"
                if ask "¿Usar certificado Let's Encrypt?"; then
                    CERT_FILE="$LE_CERT"
                    KEY_FILE="$LE_KEY"
                    USE_EXISTING=1
                fi
            fi
        fi

        if [[ $USE_EXISTING -eq 0 ]]; then
            # Generar certificado autofirmado
            if ask "¿Generar certificado TLS autofirmado para Postfix?"; then
                mkdir -p /etc/ssl/private
                chmod 700 /etc/ssl/private

                openssl req -new -x509 -days 3650 -nodes \
                    -out "$CERT_FILE" \
                    -keyout "$KEY_FILE" \
                    -subj "/C=ES/ST=Securizar/L=Securizar/O=Securizar/CN=${SYSTEM_HOSTNAME}" \
                    2>/dev/null

                chmod 644 "$CERT_FILE"
                chmod 600 "$KEY_FILE"
                log_change "Generado" "Certificado TLS autofirmado: $CERT_FILE"
                log_change "Generado" "Clave TLS: $KEY_FILE"
                log_warn "El certificado autofirmado no sera confiable para otros servidores."
                log_warn "Para produccion, usa Let's Encrypt: certbot certonly --standalone -d ${SYSTEM_HOSTNAME}"
            else
                log_warn "Sin certificado TLS. Usando los valores por defecto de Postfix."
                CERT_FILE=""
                KEY_FILE=""
            fi
        fi

        # Configurar TLS en Postfix
        if [[ -n "$CERT_FILE" && -n "$KEY_FILE" ]]; then
            postfix_set_param "smtpd_tls_cert_file" "$CERT_FILE"
            postfix_set_param "smtpd_tls_key_file" "$KEY_FILE"
            log_change "Configurado" "smtpd_tls_cert_file = $CERT_FILE"
            log_change "Configurado" "smtpd_tls_key_file = $KEY_FILE"
        fi

        # TLS entrante (may = ofrecer TLS, no obligar)
        postfix_set_param "smtpd_tls_security_level" "may"
        log_change "Configurado" "smtpd_tls_security_level = may (entrante)"

        # TLS saliente con DANE
        postfix_set_param "smtp_tls_security_level" "dane"
        log_change "Configurado" "smtp_tls_security_level = dane (saliente)"

        # Nivel de log TLS
        postfix_set_param "smtp_tls_loglevel" "1"
        postfix_set_param "smtpd_tls_loglevel" "1"
        log_change "Configurado" "TLS loglevel = 1"

        # DANE para saliente
        postfix_set_param "smtp_dns_support_level" "dnssec"
        log_change "Configurado" "smtp_dns_support_level = dnssec (para DANE)"

        # Protocolos: solo TLSv1.2+
        postfix_set_param "smtpd_tls_protocols" "!SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
        postfix_set_param "smtp_tls_protocols" "!SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
        postfix_set_param "smtpd_tls_mandatory_protocols" "!SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
        postfix_set_param "smtp_tls_mandatory_protocols" "!SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
        log_change "Configurado" "Protocolos TLS: solo TLSv1.2 y TLSv1.3"

        # Cifrados robustos
        CIPHERS="ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
        postfix_set_param "smtpd_tls_mandatory_ciphers" "high"
        postfix_set_param "tls_high_cipherlist" "$CIPHERS"
        log_change "Configurado" "Cifrados TLS robustos (ECDHE+AES-GCM/ChaCha20)"

        # Cache de sesiones TLS
        postfix_set_param "smtpd_tls_session_cache_database" "btree:\${data_directory}/smtpd_scache"
        postfix_set_param "smtp_tls_session_cache_database" "btree:\${data_directory}/smtp_scache"
        postfix_set_param "smtpd_tls_session_cache_timeout" "3600s"
        log_change "Configurado" "Cache de sesiones TLS"

        # Preferir cifrados del servidor
        postfix_set_param "tls_preempt_cipherlist" "yes"
        log_change "Configurado" "tls_preempt_cipherlist = yes"

        # Recargar si esta activo
        if systemctl is-active postfix &>/dev/null; then
            postfix check 2>/dev/null && {
                systemctl reload postfix 2>/dev/null || true
                log_change "Aplicado" "reload postfix (TLS)"
            } || {
                log_error "Error en configuracion de Postfix - revisar manualmente"
            }
        fi

        log_info "TLS para SMTP configurado correctamente"
    fi
else
    log_skip "TLS obligatorio para SMTP"
fi

# ============================================================
# S6: ANTI-RELAY Y RESTRICCIONES SMTP
# ============================================================
log_section "S6: ANTI-RELAY Y RESTRICCIONES SMTP"

echo "Configura restricciones para prevenir relay abierto y abuso:"
echo "  - smtpd_recipient_restrictions con reject_unauth_destination"
echo "  - smtpd_sender_restrictions con reject_unknown_sender_domain"
echo "  - smtpd_client_restrictions con permit_mynetworks"
echo "  - Rate limiting: mensajes, conexiones y tasas"
echo "  - Puerto de submission (587) para usuarios autenticados"
echo ""

if check_file_contains "/etc/postfix/main.cf" "smtpd_recipient_restrictions"; then
    log_already "Anti-relay SMTP (smtpd_recipient_restrictions ya configurado)"
elif ask "¿Aplicar restricciones anti-relay SMTP?"; then

    if [[ $HAS_POSTFIX -eq 0 ]]; then
        log_warn "Postfix no detectado. Restricciones SMTP omitidas."
        log_skip "Anti-relay SMTP (Postfix no disponible)"
    else
        POSTFIX_MAIN="/etc/postfix/main.cf"

        # Restricciones de destinatario (anti-relay principal)
        postfix_set_param "smtpd_recipient_restrictions" "permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination, reject_non_fqdn_recipient, reject_unknown_recipient_domain"
        log_change "Configurado" "smtpd_recipient_restrictions (anti-relay)"

        # Restricciones de remitente
        postfix_set_param "smtpd_sender_restrictions" "permit_mynetworks, permit_sasl_authenticated, reject_non_fqdn_sender, reject_unknown_sender_domain"
        log_change "Configurado" "smtpd_sender_restrictions"

        # Restricciones de cliente
        postfix_set_param "smtpd_client_restrictions" "permit_mynetworks, permit_sasl_authenticated, reject_unauth_pipelining"
        log_change "Configurado" "smtpd_client_restrictions"

        # Restricciones de HELO
        postfix_set_param "smtpd_helo_restrictions" "permit_mynetworks, reject_invalid_helo_hostname, reject_non_fqdn_helo_hostname"
        log_change "Configurado" "smtpd_helo_restrictions"

        # Restricciones de datos
        postfix_set_param "smtpd_data_restrictions" "reject_unauth_pipelining"
        log_change "Configurado" "smtpd_data_restrictions"

        # Rate limiting
        postfix_set_param "smtpd_client_message_rate_limit" "50"
        log_change "Configurado" "smtpd_client_message_rate_limit = 50"

        postfix_set_param "smtpd_client_connection_rate_limit" "20"
        log_change "Configurado" "smtpd_client_connection_rate_limit = 20"

        postfix_set_param "smtpd_client_recipient_rate_limit" "100"
        log_change "Configurado" "smtpd_client_recipient_rate_limit = 100"

        postfix_set_param "anvil_rate_time_unit" "60s"
        log_change "Configurado" "anvil_rate_time_unit = 60s"

        # Limitar conexiones simultaneas por cliente
        postfix_set_param "smtpd_client_connection_count_limit" "10"
        log_change "Configurado" "smtpd_client_connection_count_limit = 10"

        # Configurar puerto de submission (587) para autenticacion
        MASTER_CF="/etc/postfix/master.cf"
        if [[ -f "$MASTER_CF" ]]; then
            cp "$MASTER_CF" "$BACKUP_DIR/"
            log_change "Backup" "$MASTER_CF"

            # Verificar si submission ya esta habilitado
            if grep -q "^submission" "$MASTER_CF"; then
                log_info "Puerto submission (587) ya esta habilitado en master.cf"
            else
                if ask "¿Habilitar puerto submission (587) para usuarios autenticados?"; then
                    cat >> "$MASTER_CF" << 'EOF'

# ============================================================
# Puerto Submission (587) - solo usuarios autenticados
# Generado por securizar Modulo 42
# ============================================================
submission inet n       -       n       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_tls_auth_only=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
EOF
                    log_change "Configurado" "Puerto submission (587) en master.cf"
                else
                    log_skip "Puerto submission (587)"
                fi
            fi
        fi

        # Recargar Postfix
        if systemctl is-active postfix &>/dev/null; then
            postfix check 2>/dev/null && {
                systemctl reload postfix 2>/dev/null || true
                log_change "Aplicado" "reload postfix (anti-relay)"
            } || {
                log_error "Error en configuracion Postfix - revisar manualmente"
            }
        fi

        log_info "Restricciones anti-relay SMTP aplicadas"
    fi
else
    log_skip "Anti-relay y restricciones SMTP"
fi

# ============================================================
# S7: PROTECCION CONTRA EMAIL SPOOFING
# ============================================================
log_section "S7: PROTECCION CONTRA EMAIL SPOOFING"

echo "Protecciones adicionales contra suplantacion de identidad:"
echo "  - Mapeo sender_login para evitar spoofing autenticado"
echo "  - Rechazo de discrepancia envelope/header From"
echo "  - Script de deteccion de spoofing en cabeceras"
echo "  - Filtros header_checks contra patrones sospechosos"
echo ""

if check_executable "/usr/local/bin/detectar-email-spoofing.sh"; then
    log_already "Anti-spoofing (detectar-email-spoofing.sh ya instalado)"
elif ask "¿Aplicar protecciones contra email spoofing?"; then

    if [[ $HAS_POSTFIX -eq 1 ]]; then
        POSTFIX_MAIN="/etc/postfix/main.cf"

        # Crear mapeo sender_login (usuarios autenticados solo pueden enviar desde su direccion)
        SENDER_LOGIN_MAP="/etc/postfix/sender_login_maps"
        cat > "$SENDER_LOGIN_MAP" << EOF
# ============================================================
# Mapeo sender_login - Evita spoofing por usuarios autenticados
# Formato: direccion_de_correo  usuario_autenticado
# Generado por securizar Modulo 42
# ============================================================
# Ejemplo:
# usuario@${SYSTEM_DOMAIN}    usuario
# admin@${SYSTEM_DOMAIN}      admin
# Descomentar y adaptar segun los usuarios del sistema
EOF
        chmod 644 "$SENDER_LOGIN_MAP"
        log_change "Creado" "$SENDER_LOGIN_MAP (plantilla)"

        # Configurar reject_authenticated_sender_login_mismatch
        postfix_set_param "smtpd_sender_login_maps" "hash:$SENDER_LOGIN_MAP"
        log_change "Configurado" "smtpd_sender_login_maps"

        # Postmap
        postmap "$SENDER_LOGIN_MAP" 2>/dev/null || true
        log_change "Compilado" "postmap $SENDER_LOGIN_MAP"

        # header_checks adicionales contra spoofing
        SPOOF_CHECKS="/etc/postfix/spoof_header_checks"
        cat > "$SPOOF_CHECKS" << 'EOF'
# ============================================================
# Verificaciones de cabeceras anti-spoofing
# Generado por securizar Modulo 42
# ============================================================
# Detectar intentos de spoofing comunes
# Multiples From: (no deberia haber mas de uno)
/^From:.*\n\s+.*@/     WARN Cabecera From con multiples lineas (posible spoofing)
# Detectar codificacion sospechosa en From
/^From:.*=\?.*\?[Bb]\?/    WARN Codificacion Base64 sospechosa en From
# Rechazar mensajes sin Message-ID
/^Message-ID:\s*$/      REJECT Mensaje sin Message-ID valido
# Detectar From con unicode sospechoso (homoglifos)
/^From:.*[\x{0400}-\x{04FF}]/  WARN Caracteres cirilicos en From (posible homoglifo)
EOF
        chmod 644 "$SPOOF_CHECKS"
        log_change "Creado" "$SPOOF_CHECKS"
    fi

    # Script de deteccion de spoofing
    cat > /usr/local/bin/detectar-email-spoofing.sh << 'EOFSPOOFDETECT'
#!/bin/bash
# ============================================================
# Detector de email spoofing en cabeceras
# securizar Modulo 42
# Uso: detectar-email-spoofing.sh <archivo_email.eml>
#      cat email.eml | detectar-email-spoofing.sh
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  DETECTOR DE EMAIL SPOOFING${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

# Leer cabeceras del email
if [[ -n "${1:-}" && -f "$1" ]]; then
    HEADERS=$(sed '/^$/q' "$1")
    echo -e "${DIM}Analizando archivo: $1${NC}"
else
    echo -e "${DIM}Leyendo de stdin (pega las cabeceras, Ctrl+D para finalizar)${NC}"
    HEADERS=$(sed '/^$/q')
fi

if [[ -z "$HEADERS" ]]; then
    echo -e "${RED}[X] No se encontraron cabeceras${NC}"
    exit 1
fi

echo ""
ALERTAS=0

# Extraer campos relevantes
FROM_HEADER=$(echo "$HEADERS" | grep -i "^From:" | head -1 || echo "")
RETURN_PATH=$(echo "$HEADERS" | grep -i "^Return-Path:" | head -1 || echo "")
REPLY_TO=$(echo "$HEADERS" | grep -i "^Reply-To:" | head -1 || echo "")
ENVELOPE_FROM=$(echo "$HEADERS" | grep -i "^X-Envelope-From:\|^Envelope-From:" | head -1 || echo "")
RECEIVED=$(echo "$HEADERS" | grep -i "^Received:" || echo "")
AUTH_RESULTS=$(echo "$HEADERS" | grep -i "^Authentication-Results:" || echo "")
DKIM_SIG=$(echo "$HEADERS" | grep -i "^DKIM-Signature:" | head -1 || echo "")

echo -e "${CYAN}── Cabeceras clave ──${NC}"
[[ -n "$FROM_HEADER" ]] && echo -e "  From:        ${BOLD}${FROM_HEADER#*:}${NC}"
[[ -n "$RETURN_PATH" ]] && echo -e "  Return-Path: ${RETURN_PATH#*:}"
[[ -n "$REPLY_TO" ]] && echo -e "  Reply-To:    ${REPLY_TO#*:}"
echo ""

echo -e "${CYAN}── Analisis de spoofing ──${NC}"

# 1. Discrepancia From vs Return-Path
if [[ -n "$FROM_HEADER" && -n "$RETURN_PATH" ]]; then
    FROM_DOMAIN=$(echo "$FROM_HEADER" | grep -oi '@[a-z0-9._-]*' | head -1 | tr '[:upper:]' '[:lower:]')
    RP_DOMAIN=$(echo "$RETURN_PATH" | grep -oi '@[a-z0-9._-]*' | head -1 | tr '[:upper:]' '[:lower:]')
    if [[ -n "$FROM_DOMAIN" && -n "$RP_DOMAIN" && "$FROM_DOMAIN" != "$RP_DOMAIN" ]]; then
        echo -e "  ${RED}[!!]${NC} Discrepancia From/Return-Path: ${FROM_DOMAIN} vs ${RP_DOMAIN}"
        ((ALERTAS++))
    else
        echo -e "  ${GREEN}[OK]${NC} From y Return-Path coinciden en dominio"
    fi
fi

# 2. Reply-To diferente de From
if [[ -n "$FROM_HEADER" && -n "$REPLY_TO" ]]; then
    FROM_ADDR=$(echo "$FROM_HEADER" | grep -oi '[a-z0-9._+-]*@[a-z0-9._-]*' | head -1 | tr '[:upper:]' '[:lower:]')
    RT_ADDR=$(echo "$REPLY_TO" | grep -oi '[a-z0-9._+-]*@[a-z0-9._-]*' | head -1 | tr '[:upper:]' '[:lower:]')
    if [[ -n "$FROM_ADDR" && -n "$RT_ADDR" && "$FROM_ADDR" != "$RT_ADDR" ]]; then
        echo -e "  ${YELLOW}[!]${NC}  Reply-To diferente de From: ${RT_ADDR}"
        ((ALERTAS++))
    else
        echo -e "  ${GREEN}[OK]${NC} Reply-To coincide con From"
    fi
fi

# 3. Verificar resultados de autenticacion
if [[ -n "$AUTH_RESULTS" ]]; then
    echo ""
    echo -e "${CYAN}── Resultados de autenticacion ──${NC}"
    # SPF
    SPF_RESULT=$(echo "$AUTH_RESULTS" | grep -oi "spf=[a-z]*" | head -1 || echo "")
    if [[ -n "$SPF_RESULT" ]]; then
        case "$SPF_RESULT" in
            *pass*) echo -e "  ${GREEN}[OK]${NC} SPF: pass" ;;
            *fail*) echo -e "  ${RED}[!!]${NC} SPF: fail"; ((ALERTAS++)) ;;
            *softfail*) echo -e "  ${YELLOW}[!]${NC}  SPF: softfail"; ((ALERTAS++)) ;;
            *) echo -e "  ${YELLOW}[?]${NC}  SPF: $SPF_RESULT" ;;
        esac
    fi
    # DKIM
    DKIM_RESULT=$(echo "$AUTH_RESULTS" | grep -oi "dkim=[a-z]*" | head -1 || echo "")
    if [[ -n "$DKIM_RESULT" ]]; then
        case "$DKIM_RESULT" in
            *pass*) echo -e "  ${GREEN}[OK]${NC} DKIM: pass" ;;
            *fail*) echo -e "  ${RED}[!!]${NC} DKIM: fail"; ((ALERTAS++)) ;;
            *) echo -e "  ${YELLOW}[?]${NC}  DKIM: $DKIM_RESULT" ;;
        esac
    fi
    # DMARC
    DMARC_RESULT=$(echo "$AUTH_RESULTS" | grep -oi "dmarc=[a-z]*" | head -1 || echo "")
    if [[ -n "$DMARC_RESULT" ]]; then
        case "$DMARC_RESULT" in
            *pass*) echo -e "  ${GREEN}[OK]${NC} DMARC: pass" ;;
            *fail*) echo -e "  ${RED}[!!]${NC} DMARC: fail"; ((ALERTAS++)) ;;
            *) echo -e "  ${YELLOW}[?]${NC}  DMARC: $DMARC_RESULT" ;;
        esac
    fi
else
    echo -e "  ${YELLOW}[!]${NC}  Sin cabecera Authentication-Results"
fi

# 4. Verificar cadena Received
RECEIVED_COUNT=$(echo "$HEADERS" | grep -ci "^Received:" || echo "0")
echo ""
echo -e "${CYAN}── Cadena de recepcion ──${NC}"
echo -e "  Saltos (Received): ${RECEIVED_COUNT}"
if [[ "$RECEIVED_COUNT" -gt 10 ]]; then
    echo -e "  ${YELLOW}[!]${NC}  Demasiados saltos (posible manipulacion)"
    ((ALERTAS++))
fi

# 5. Resumen
echo ""
echo -e "${BOLD}── Resultado ──${NC}"
if [[ $ALERTAS -eq 0 ]]; then
    echo -e "  ${GREEN}SIN ALERTAS${NC} - Las cabeceras parecen legitimas"
elif [[ $ALERTAS -le 2 ]]; then
    echo -e "  ${YELLOW}${ALERTAS} ALERTAS${NC} - Verificar manualmente"
else
    echo -e "  ${RED}${ALERTAS} ALERTAS${NC} - Alta probabilidad de spoofing"
fi

echo ""
echo -e "${DIM}Analisis completado: $(date)${NC}"
EOFSPOOFDETECT
    chmod +x /usr/local/bin/detectar-email-spoofing.sh
    log_change "Creado" "/usr/local/bin/detectar-email-spoofing.sh"

    log_info "Protecciones anti-spoofing configuradas"
else
    log_skip "Proteccion contra email spoofing"
fi

# ============================================================
# S8: FILTRADO DE CONTENIDO Y SPAM
# ============================================================
log_section "S8: FILTRADO DE CONTENIDO Y SPAM"

echo "Instala y configura SpamAssassin para filtrado de spam:"
echo "  - Configuracion de /etc/mail/spamassassin/local.cf"
echo "  - Puntuacion, Bayes, auto-aprendizaje"
echo "  - Integracion con Postfix"
echo "  - Bloqueo de adjuntos peligrosos (.exe, .bat, .scr, etc.)"
echo "  - Restricciones MIME en header_checks"
echo ""

if check_file_exists "/etc/mail/spamassassin/local.cf"; then
    log_already "Filtrado de spam (SpamAssassin local.cf ya configurado)"
elif ask "¿Configurar filtrado de contenido y spam?"; then

    # Instalar SpamAssassin si el usuario acepta
    SPAM_INSTALLED=0
    if command -v spamassassin &>/dev/null || command -v spamd &>/dev/null; then
        log_info "SpamAssassin ya esta instalado"
        SPAM_INSTALLED=1
    else
        if ask "¿Instalar SpamAssassin?"; then
            pkg_install "spamassassin" && SPAM_INSTALLED=1 || log_warn "No se pudo instalar spamassassin"
        fi
    fi

    if [[ $SPAM_INSTALLED -eq 1 ]]; then
        SA_CONF_DIR="/etc/mail/spamassassin"
        SA_LOCAL_CF="${SA_CONF_DIR}/local.cf"

        mkdir -p "$SA_CONF_DIR"

        if [[ -f "$SA_LOCAL_CF" ]]; then
            cp "$SA_LOCAL_CF" "$BACKUP_DIR/"
            log_change "Backup" "$SA_LOCAL_CF"
        fi

        cat > "$SA_LOCAL_CF" << 'EOF'
# ============================================================
# SpamAssassin - Configuracion generada por securizar Modulo 42
# ============================================================

# Puntuacion necesaria para marcar como spam (5.0 es el defecto)
required_score          5.0

# Reescribir asunto de mensajes spam
rewrite_header Subject  [***SPAM***]

# Reportar como texto adjunto en lugar de modificar el mensaje
report_safe             1

# Activar Bayes (aprendizaje automatico)
use_bayes               1
bayes_auto_learn        1
bayes_auto_learn_threshold_nonspam  0.1
bayes_auto_learn_threshold_spam     12.0

# Directorio de base de datos Bayes
bayes_path              /var/lib/spamassassin/bayes

# Verificaciones de red
skip_rbl_checks         0
use_razor2              0
use_pyzor               0

# Verificaciones DNS
dns_available           yes

# Listas blancas/negras locales (descomentar y adaptar)
# whitelist_from          *@midominio.com
# blacklist_from          *@spammer.com

# Puntuaciones personalizadas para mayor deteccion
score URIBL_BLACK           3.0
score URIBL_GREY            1.5
score URIBL_RED             3.0
score RCVD_IN_SORBS_DUL     2.0
score RCVD_IN_XBL           3.0
score BAYES_99              4.0
score BAYES_95              3.0
score BAYES_80              2.0

# Deshabilitar plugins problematicos
loadplugin Mail::SpamAssassin::Plugin::Check
loadplugin Mail::SpamAssassin::Plugin::HTTPSMismatch
loadplugin Mail::SpamAssassin::Plugin::URIDetail

# Idioma de preferencia (para deteccion de idioma sospechoso)
ok_locales              es en
EOF
        chmod 644 "$SA_LOCAL_CF"
        log_change "Creado" "$SA_LOCAL_CF"

        # Crear directorio para base de datos Bayes
        mkdir -p /var/lib/spamassassin
        chown -R nobody:nobody /var/lib/spamassassin 2>/dev/null || true

        # Habilitar servicio spamd
        systemctl enable spamassassin 2>/dev/null || systemctl enable spamd 2>/dev/null || true
        log_change "Habilitado" "servicio SpamAssassin"

        # Integracion con Postfix
        if [[ $HAS_POSTFIX -eq 1 ]]; then
            if ask "¿Integrar SpamAssassin con Postfix via content_filter?"; then
                postfix_set_param "content_filter" "spamassassin"
                log_change "Configurado" "Postfix content_filter = spamassassin"

                # Agregar transporte en master.cf si no existe
                MASTER_CF="/etc/postfix/master.cf"
                if ! grep -q "^spamassassin" "$MASTER_CF" 2>/dev/null; then
                    cat >> "$MASTER_CF" << 'EOF'

# ============================================================
# SpamAssassin via pipe - securizar Modulo 42
# ============================================================
spamassassin unix -     n       n       -       -       pipe
  user=nobody argv=/usr/bin/spamc -f -e /usr/sbin/sendmail -oi -f ${sender} ${recipient}
EOF
                    log_change "Configurado" "Transporte spamassassin en master.cf"
                else
                    log_info "Transporte spamassassin ya existe en master.cf"
                fi
            fi
        fi

        # Actualizar reglas de SpamAssassin
        if command -v sa-update &>/dev/null; then
            log_info "Actualizando reglas de SpamAssassin..."
            sa-update 2>/dev/null || log_warn "No se pudieron actualizar las reglas (puede requerir canal GPG)"
        fi
    fi

    # Bloqueo de adjuntos peligrosos (independiente de SpamAssassin)
    if [[ $HAS_POSTFIX -eq 1 ]]; then
        log_info "Configurando bloqueo de adjuntos peligrosos..."

        MIME_CHECKS="/etc/postfix/mime_header_checks"
        if [[ -f "$MIME_CHECKS" ]]; then
            cp "$MIME_CHECKS" "$BACKUP_DIR/"
            log_change "Backup" "$MIME_CHECKS"
        fi

        cat > "$MIME_CHECKS" << 'EOF'
# ============================================================
# Bloqueo de adjuntos peligrosos - securizar Modulo 42
# ============================================================
# Ejecutables Windows
/name=[^>]*\.(exe|com|scr|pif|cpl)(\.\w+)?/    REJECT Adjunto ejecutable bloqueado por politica de seguridad
# Scripts
/name=[^>]*\.(bat|cmd|vbs|vbe|js|jse|wsf|wsh|ps1|psm1)/   REJECT Adjunto de script bloqueado por politica de seguridad
# Archivos de Office con macros
/name=[^>]*\.(docm|xlsm|pptm|dotm|xltm|potm)/  REJECT Adjunto con macros bloqueado por politica de seguridad
# Otros formatos peligrosos
/name=[^>]*\.(hta|inf|ins|isp|reg|rgs|sct|shb|shs|lnk)/   REJECT Adjunto potencialmente peligroso bloqueado
# Archivos con doble extension (ej: foto.jpg.exe)
/name=[^>]*\.\w+\.(exe|scr|bat|com|pif|cmd|vbs|js)/        REJECT Adjunto con doble extension bloqueado
EOF
        chmod 644 "$MIME_CHECKS"
        postfix_set_param "mime_header_checks" "regexp:$MIME_CHECKS"
        log_change "Creado" "$MIME_CHECKS (bloqueo de adjuntos peligrosos)"
    fi

    log_info "Filtrado de contenido y spam configurado"
else
    log_skip "Filtrado de contenido y spam"
fi

# ============================================================
# S9: MONITORIZACION DE EMAIL
# ============================================================
log_section "S9: MONITORIZACION DE EMAIL"

echo "Crea sistema de monitorizacion de correo electronico:"
echo "  - Script de monitorizacion: cola, logs, fallos de auth"
echo "  - Tarea cron diaria con umbrales de alerta"
echo "  - Deteccion de patrones sospechosos en logs"
echo "  - Estadisticas de uso TLS"
echo "  - Alertas de conexiones sin TLS"
echo ""

if check_executable "/usr/local/bin/monitorizar-email.sh"; then
    log_already "Monitorizacion email (monitorizar-email.sh ya instalado)"
elif ask "¿Crear sistema de monitorizacion de email?"; then

    # Script principal de monitorizacion
    cat > /usr/local/bin/monitorizar-email.sh << 'EOFMON'
#!/bin/bash
# ============================================================
# Monitor de seguridad de email - securizar Modulo 42
# Verifica estado del servicio, cola, logs y seguridad
# Uso: monitorizar-email.sh [--json] [--quiet]
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

JSON_MODE=0
QUIET_MODE=0
for arg in "$@"; do
    case "$arg" in
        --json) JSON_MODE=1 ;;
        --quiet) QUIET_MODE=1 ;;
    esac
done

# Umbrales de alerta
QUEUE_WARN=50
QUEUE_CRIT=200
AUTH_FAIL_WARN=10
AUTH_FAIL_CRIT=50
RELAY_ATTEMPT_WARN=5

ALERTAS=0
ESTADO="OK"

# Archivo de log de correo (varia segun distro)
MAIL_LOG=""
for logfile in /var/log/mail.log /var/log/maillog /var/log/mail/info; do
    if [[ -f "$logfile" ]]; then
        MAIL_LOG="$logfile"
        break
    fi
done

if [[ $QUIET_MODE -eq 0 && $JSON_MODE -eq 0 ]]; then
    echo -e "${BOLD}══════════════════════════════════════════${NC}"
    echo -e "${BOLD}  MONITOR DE SEGURIDAD EMAIL${NC}"
    echo -e "${BOLD}══════════════════════════════════════════${NC}"
    echo -e "${DIM}  $(date)${NC}"
    echo ""
fi

# 1. Estado del servicio Postfix
POSTFIX_STATUS="inactivo"
if systemctl is-active postfix &>/dev/null; then
    POSTFIX_STATUS="activo"
    [[ $JSON_MODE -eq 0 && $QUIET_MODE -eq 0 ]] && echo -e "  ${GREEN}[OK]${NC} Postfix: activo"
else
    [[ $JSON_MODE -eq 0 && $QUIET_MODE -eq 0 ]] && echo -e "  ${RED}[!!]${NC} Postfix: inactivo"
    ((ALERTAS++))
fi

# 2. Estado OpenDKIM
DKIM_STATUS="no instalado"
if command -v opendkim &>/dev/null; then
    if systemctl is-active opendkim &>/dev/null; then
        DKIM_STATUS="activo"
        [[ $JSON_MODE -eq 0 && $QUIET_MODE -eq 0 ]] && echo -e "  ${GREEN}[OK]${NC} OpenDKIM: activo"
    else
        DKIM_STATUS="inactivo"
        [[ $JSON_MODE -eq 0 && $QUIET_MODE -eq 0 ]] && echo -e "  ${YELLOW}[!]${NC}  OpenDKIM: inactivo"
        ((ALERTAS++))
    fi
fi

# 3. Estado OpenDMARC
DMARC_STATUS="no instalado"
if command -v opendmarc &>/dev/null; then
    if systemctl is-active opendmarc &>/dev/null; then
        DMARC_STATUS="activo"
        [[ $JSON_MODE -eq 0 && $QUIET_MODE -eq 0 ]] && echo -e "  ${GREEN}[OK]${NC} OpenDMARC: activo"
    else
        DMARC_STATUS="inactivo"
        [[ $JSON_MODE -eq 0 && $QUIET_MODE -eq 0 ]] && echo -e "  ${YELLOW}[!]${NC}  OpenDMARC: inactivo"
        ((ALERTAS++))
    fi
fi

# 4. Cola de correo
QUEUE_SIZE=0
if command -v mailq &>/dev/null; then
    QUEUE_OUTPUT=$(mailq 2>/dev/null || echo "")
    if echo "$QUEUE_OUTPUT" | grep -q "Mail queue is empty"; then
        QUEUE_SIZE=0
    else
        QUEUE_SIZE=$(echo "$QUEUE_OUTPUT" | grep -c "^[A-F0-9]" || echo "0")
    fi
fi
if [[ $JSON_MODE -eq 0 && $QUIET_MODE -eq 0 ]]; then
    echo ""
    echo -e "${CYAN}── Cola de correo ──${NC}"
    if [[ $QUEUE_SIZE -ge $QUEUE_CRIT ]]; then
        echo -e "  ${RED}[!!]${NC} Mensajes en cola: ${QUEUE_SIZE} (CRITICO > ${QUEUE_CRIT})"
        ((ALERTAS++))
    elif [[ $QUEUE_SIZE -ge $QUEUE_WARN ]]; then
        echo -e "  ${YELLOW}[!]${NC}  Mensajes en cola: ${QUEUE_SIZE} (AVISO > ${QUEUE_WARN})"
        ((ALERTAS++))
    else
        echo -e "  ${GREEN}[OK]${NC} Mensajes en cola: ${QUEUE_SIZE}"
    fi
fi

# 5. Analisis de logs (ultimas 24 horas)
AUTH_FAILURES=0
RELAY_ATTEMPTS=0
TLS_CONNECTIONS=0
NOTLS_CONNECTIONS=0
REJECTED_MESSAGES=0

if [[ -n "$MAIL_LOG" && -f "$MAIL_LOG" ]]; then
    YESTERDAY=$(date -d "yesterday" "+%b %e" 2>/dev/null || date -v-1d "+%b %e" 2>/dev/null || echo "")
    TODAY=$(date "+%b %e")

    # Fallos de autenticacion
    AUTH_FAILURES=$(grep -c "authentication fail\|SASL.*authentication failed\|auth failed" "$MAIL_LOG" 2>/dev/null || echo "0")

    # Intentos de relay
    RELAY_ATTEMPTS=$(grep -c "Relay access denied\|reject.*relay" "$MAIL_LOG" 2>/dev/null || echo "0")

    # Conexiones TLS vs no-TLS
    TLS_CONNECTIONS=$(grep -c "TLS connection established\|Anonymous TLS\|Trusted TLS\|Verified TLS" "$MAIL_LOG" 2>/dev/null || echo "0")
    NOTLS_CONNECTIONS=$(grep -c "connect from.*\[" "$MAIL_LOG" 2>/dev/null || echo "0")
    # Ajustar: las no-TLS son las totales menos las TLS
    if [[ $NOTLS_CONNECTIONS -gt $TLS_CONNECTIONS ]]; then
        NOTLS_CONNECTIONS=$((NOTLS_CONNECTIONS - TLS_CONNECTIONS))
    else
        NOTLS_CONNECTIONS=0
    fi

    # Mensajes rechazados
    REJECTED_MESSAGES=$(grep -c "NOQUEUE: reject\|rejected:" "$MAIL_LOG" 2>/dev/null || echo "0")

    if [[ $JSON_MODE -eq 0 && $QUIET_MODE -eq 0 ]]; then
        echo ""
        echo -e "${CYAN}── Analisis de logs ──${NC}"

        # Fallos de autenticacion
        if [[ $AUTH_FAILURES -ge $AUTH_FAIL_CRIT ]]; then
            echo -e "  ${RED}[!!]${NC} Fallos de autenticacion: ${AUTH_FAILURES} (CRITICO)"
            ((ALERTAS++))
        elif [[ $AUTH_FAILURES -ge $AUTH_FAIL_WARN ]]; then
            echo -e "  ${YELLOW}[!]${NC}  Fallos de autenticacion: ${AUTH_FAILURES} (AVISO)"
            ((ALERTAS++))
        else
            echo -e "  ${GREEN}[OK]${NC} Fallos de autenticacion: ${AUTH_FAILURES}"
        fi

        # Intentos de relay
        if [[ $RELAY_ATTEMPTS -ge $RELAY_ATTEMPT_WARN ]]; then
            echo -e "  ${YELLOW}[!]${NC}  Intentos de relay rechazados: ${RELAY_ATTEMPTS}"
            ((ALERTAS++))
        else
            echo -e "  ${GREEN}[OK]${NC} Intentos de relay rechazados: ${RELAY_ATTEMPTS}"
        fi

        # Estadisticas TLS
        echo ""
        echo -e "${CYAN}── Estadisticas TLS ──${NC}"
        TOTAL_CONN=$((TLS_CONNECTIONS + NOTLS_CONNECTIONS))
        if [[ $TOTAL_CONN -gt 0 ]]; then
            TLS_PCT=$(( (TLS_CONNECTIONS * 100) / TOTAL_CONN ))
            echo -e "  Conexiones TLS:    ${TLS_CONNECTIONS} (${TLS_PCT}%)"
            echo -e "  Conexiones sin TLS: ${NOTLS_CONNECTIONS}"
            if [[ $NOTLS_CONNECTIONS -gt 0 ]]; then
                echo -e "  ${YELLOW}[!]${NC}  Se detectaron ${NOTLS_CONNECTIONS} conexiones sin cifrar"
            fi
        else
            echo -e "  ${DIM}Sin datos de conexiones en el log${NC}"
        fi

        # Mensajes rechazados
        echo ""
        echo -e "  Mensajes rechazados: ${REJECTED_MESSAGES}"
    fi
fi

# Resultado final
if [[ $ALERTAS -gt 3 ]]; then
    ESTADO="CRITICO"
elif [[ $ALERTAS -gt 0 ]]; then
    ESTADO="ALERTA"
fi

if [[ $JSON_MODE -eq 1 ]]; then
    cat << EOFJSON
{
  "timestamp": "$(date -Iseconds)",
  "estado": "${ESTADO}",
  "alertas": ${ALERTAS},
  "servicios": {
    "postfix": "${POSTFIX_STATUS}",
    "opendkim": "${DKIM_STATUS}",
    "opendmarc": "${DMARC_STATUS}"
  },
  "cola": ${QUEUE_SIZE},
  "logs": {
    "auth_failures": ${AUTH_FAILURES},
    "relay_attempts": ${RELAY_ATTEMPTS},
    "tls_connections": ${TLS_CONNECTIONS},
    "notls_connections": ${NOTLS_CONNECTIONS},
    "rejected_messages": ${REJECTED_MESSAGES}
  }
}
EOFJSON
elif [[ $QUIET_MODE -eq 0 ]]; then
    echo ""
    echo -e "${BOLD}── Estado general ──${NC}"
    case "$ESTADO" in
        OK)       echo -e "  ${GREEN}${BOLD}${ESTADO}${NC} - Sistema de email funcionando correctamente" ;;
        ALERTA)   echo -e "  ${YELLOW}${BOLD}${ESTADO}${NC} - ${ALERTAS} alertas detectadas" ;;
        CRITICO)  echo -e "  ${RED}${BOLD}${ESTADO}${NC} - ${ALERTAS} alertas criticas" ;;
    esac
    echo ""
    echo -e "${DIM}Monitorizacion completada: $(date)${NC}"
else
    # Modo quiet: solo imprimir si hay alertas
    if [[ $ALERTAS -gt 0 ]]; then
        echo "EMAIL_MONITOR: ${ESTADO} - ${ALERTAS} alertas (cola=${QUEUE_SIZE}, auth_fail=${AUTH_FAILURES}, relay=${RELAY_ATTEMPTS})"
    fi
fi

exit $ALERTAS
EOFMON
    chmod +x /usr/local/bin/monitorizar-email.sh
    log_change "Creado" "/usr/local/bin/monitorizar-email.sh"

    # Tarea cron diaria
    mkdir -p /etc/cron.daily
    cat > /etc/cron.daily/securizar-email-monitor << 'EOFCRON'
#!/bin/bash
# ============================================================
# Monitor diario de seguridad email - securizar Modulo 42
# ============================================================

LOG_FILE="/var/log/securizar-email-monitor.log"
ALERT_EMAIL="${SECURIZAR_ALERT_EMAIL:-root}"

# Ejecutar monitor en modo quiet
RESULTADO=$(/usr/local/bin/monitorizar-email.sh --quiet 2>/dev/null)
ALERTAS=$?

# Registrar en log
echo "$(date -Iseconds) - Alertas: ${ALERTAS} - ${RESULTADO}" >> "$LOG_FILE"

# Enviar alerta si hay problemas
if [[ $ALERTAS -gt 0 ]]; then
    if command -v mail &>/dev/null; then
        echo "$RESULTADO" | mail -s "[SECURIZAR] Alerta email: ${ALERTAS} problemas detectados" "$ALERT_EMAIL" 2>/dev/null || true
    fi
    # Tambien registrar via syslog
    logger -t securizar-email-monitor -p mail.warning "$RESULTADO" 2>/dev/null || true
fi

# Rotar log si supera 10MB
LOG_SIZE=$(stat -c%s "$LOG_FILE" 2>/dev/null || echo "0")
if [[ "$LOG_SIZE" -gt 10485760 ]]; then
    mv "$LOG_FILE" "${LOG_FILE}.old"
    gzip "${LOG_FILE}.old" 2>/dev/null || true
fi
EOFCRON
    chmod +x /etc/cron.daily/securizar-email-monitor
    log_change "Creado" "/etc/cron.daily/securizar-email-monitor"

    log_info "Sistema de monitorizacion de email instalado"
    log_info "Ejecuta: monitorizar-email.sh [--json]"
else
    log_skip "Monitorizacion de email"
fi

# ============================================================
# S10: AUDITORIA COMPLETA DE SEGURIDAD EMAIL
# ============================================================
log_section "S10: AUDITORIA COMPLETA DE SEGURIDAD EMAIL"

echo "Crea script de auditoria integral de seguridad email:"
echo "  - Verifica: Postfix hardened, SPF, DKIM, DMARC, TLS"
echo "  - Verifica: anti-relay, anti-spoofing, spam, monitorizacion"
echo "  - Puntuacion: SEGURO / MEJORABLE / INSEGURO"
echo "  - Salida JSON opcional"
echo "  - Tarea cron semanal"
echo ""

if check_executable "/usr/local/bin/auditoria-email.sh"; then
    log_already "Auditoria email (auditoria-email.sh ya instalado)"
elif ask "¿Crear sistema de auditoria de seguridad email?"; then

    cat > /usr/local/bin/auditoria-email.sh << 'EOFAUDIT'
#!/bin/bash
# ============================================================
# Auditoria completa de seguridad email - securizar Modulo 42
# Uso: auditoria-email.sh [--json] [dominio]
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

JSON_MODE=0
DOMINIO=""
for arg in "$@"; do
    case "$arg" in
        --json) JSON_MODE=1 ;;
        *) DOMINIO="$arg" ;;
    esac
done

if [[ -z "$DOMINIO" ]]; then
    DOMINIO=$(hostname -d 2>/dev/null || echo "")
    [[ -z "$DOMINIO" || "$DOMINIO" == "(none)" ]] && DOMINIO="localdomain"
fi

# Contadores
TOTAL_CHECKS=0
PASSED=0
WARNINGS=0
FAILED=0
RESULTADOS=()

# Funcion de verificacion
check_pass() {
    ((TOTAL_CHECKS++)); ((PASSED++))
    RESULTADOS+=("{\"check\":\"$1\",\"result\":\"pass\",\"detail\":\"$2\"}")
    [[ $JSON_MODE -eq 0 ]] && echo -e "  ${GREEN}[OK]${NC} $1: $2"
}
check_warn() {
    ((TOTAL_CHECKS++)); ((WARNINGS++))
    RESULTADOS+=("{\"check\":\"$1\",\"result\":\"warn\",\"detail\":\"$2\"}")
    [[ $JSON_MODE -eq 0 ]] && echo -e "  ${YELLOW}[!]${NC}  $1: $2"
}
check_fail() {
    ((TOTAL_CHECKS++)); ((FAILED++))
    RESULTADOS+=("{\"check\":\"$1\",\"result\":\"fail\",\"detail\":\"$2\"}")
    [[ $JSON_MODE -eq 0 ]] && echo -e "  ${RED}[!!]${NC} $1: $2"
}

if [[ $JSON_MODE -eq 0 ]]; then
    echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  AUDITORIA DE SEGURIDAD EMAIL${NC}"
    echo -e "${BOLD}  Dominio: ${DOMINIO}${NC}"
    echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
    echo -e "${DIM}  $(date)${NC}"
    echo ""
fi

# ── 1. Postfix hardened ──
if [[ $JSON_MODE -eq 0 ]]; then
    echo -e "${CYAN}── Postfix ──${NC}"
fi

if command -v postconf &>/dev/null; then
    check_pass "Postfix" "instalado y disponible"

    # Banner
    BANNER=$(postconf -h smtpd_banner 2>/dev/null || echo "")
    if echo "$BANNER" | grep -qi "postfix\|version\|ubuntu\|debian\|centos"; then
        check_warn "Banner SMTP" "Revela informacion del software: $BANNER"
    else
        check_pass "Banner SMTP" "No revela version del software"
    fi

    # VRFY
    VRFY=$(postconf -h disable_vrfy_command 2>/dev/null || echo "no")
    if [[ "$VRFY" == "yes" ]]; then
        check_pass "VRFY desactivado" "Enumeracion de usuarios bloqueada"
    else
        check_fail "VRFY activo" "Permite enumeracion de usuarios (disable_vrfy_command=no)"
    fi

    # HELO requerido
    HELO=$(postconf -h smtpd_helo_required 2>/dev/null || echo "no")
    if [[ "$HELO" == "yes" ]]; then
        check_pass "HELO requerido" "Clientes deben identificarse"
    else
        check_warn "HELO no requerido" "smtpd_helo_required=no"
    fi

    # Restricciones de destinatario (anti-relay)
    RCPT_REST=$(postconf -h smtpd_recipient_restrictions 2>/dev/null || echo "")
    if echo "$RCPT_REST" | grep -q "reject_unauth_destination"; then
        check_pass "Anti-relay" "reject_unauth_destination configurado"
    else
        check_fail "Anti-relay" "Falta reject_unauth_destination en smtpd_recipient_restrictions"
    fi
else
    check_fail "Postfix" "No instalado"
fi

# ── 2. TLS ──
if [[ $JSON_MODE -eq 0 ]]; then
    echo ""
    echo -e "${CYAN}── TLS ──${NC}"
fi

if command -v postconf &>/dev/null; then
    # TLS entrante
    SMTPD_TLS=$(postconf -h smtpd_tls_security_level 2>/dev/null || echo "")
    case "$SMTPD_TLS" in
        encrypt) check_pass "TLS entrante" "Obligatorio (encrypt)" ;;
        may)     check_pass "TLS entrante" "Oportunista (may)" ;;
        ""|none) check_fail "TLS entrante" "No configurado" ;;
        *)       check_warn "TLS entrante" "Nivel: $SMTPD_TLS" ;;
    esac

    # TLS saliente
    SMTP_TLS=$(postconf -h smtp_tls_security_level 2>/dev/null || echo "")
    case "$SMTP_TLS" in
        dane|verify|secure) check_pass "TLS saliente" "Nivel alto: $SMTP_TLS" ;;
        encrypt)            check_pass "TLS saliente" "Obligatorio (encrypt)" ;;
        may)                check_warn "TLS saliente" "Oportunista (may) - considerar dane" ;;
        ""|none)            check_fail "TLS saliente" "No configurado" ;;
        *)                  check_warn "TLS saliente" "Nivel: $SMTP_TLS" ;;
    esac

    # Protocolos
    SMTPD_PROTO=$(postconf -h smtpd_tls_protocols 2>/dev/null || echo "")
    if echo "$SMTPD_PROTO" | grep -q "!SSLv3" && echo "$SMTPD_PROTO" | grep -q "!TLSv1"; then
        check_pass "Protocolos TLS" "SSLv3 y TLSv1 deshabilitados"
    elif [[ -z "$SMTPD_PROTO" ]]; then
        check_warn "Protocolos TLS" "Usando valores por defecto (pueden incluir TLSv1)"
    else
        check_warn "Protocolos TLS" "Verificar que SSLv3 y TLSv1 estan deshabilitados"
    fi

    # Certificado
    CERT=$(postconf -h smtpd_tls_cert_file 2>/dev/null || echo "")
    if [[ -n "$CERT" && -f "$CERT" ]]; then
        CERT_EXPIRY=$(openssl x509 -enddate -noout -in "$CERT" 2>/dev/null | cut -d= -f2 || echo "")
        if [[ -n "$CERT_EXPIRY" ]]; then
            EXPIRY_EPOCH=$(date -d "$CERT_EXPIRY" +%s 2>/dev/null || echo "0")
            NOW_EPOCH=$(date +%s)
            DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
            if [[ $DAYS_LEFT -lt 0 ]]; then
                check_fail "Certificado TLS" "EXPIRADO hace $((DAYS_LEFT * -1)) dias"
            elif [[ $DAYS_LEFT -lt 30 ]]; then
                check_warn "Certificado TLS" "Expira en $DAYS_LEFT dias"
            else
                check_pass "Certificado TLS" "Valido, expira en $DAYS_LEFT dias"
            fi
        fi
    else
        check_fail "Certificado TLS" "No configurado o archivo no encontrado"
    fi
fi

# ── 3. SPF ──
if [[ $JSON_MODE -eq 0 ]]; then
    echo ""
    echo -e "${CYAN}── SPF ──${NC}"
fi

SPF_RECORD=""
if command -v dig &>/dev/null; then
    SPF_RECORD=$(dig +short TXT "$DOMINIO" 2>/dev/null | grep -i "v=spf1" | tr -d '"' || echo "")
elif command -v host &>/dev/null; then
    SPF_RECORD=$(host -t TXT "$DOMINIO" 2>/dev/null | grep -i "v=spf1" | sed 's/.*descriptive text "//;s/"$//' || echo "")
fi

if [[ -n "$SPF_RECORD" ]]; then
    check_pass "SPF" "Registro encontrado"
    if echo "$SPF_RECORD" | grep -q "\-all$"; then
        check_pass "SPF politica" "Hard fail (-all)"
    elif echo "$SPF_RECORD" | grep -q "~all$"; then
        check_warn "SPF politica" "Soft fail (~all) - se recomienda -all"
    else
        check_warn "SPF politica" "No termina en -all"
    fi
else
    check_fail "SPF" "No se encontro registro SPF para $DOMINIO"
fi

# ── 4. DKIM ──
if [[ $JSON_MODE -eq 0 ]]; then
    echo ""
    echo -e "${CYAN}── DKIM ──${NC}"
fi

if command -v opendkim &>/dev/null; then
    if systemctl is-active opendkim &>/dev/null; then
        check_pass "OpenDKIM" "Activo y funcionando"
    else
        check_warn "OpenDKIM" "Instalado pero inactivo"
    fi
    # Verificar configuracion
    if [[ -f /etc/opendkim/opendkim.conf ]]; then
        check_pass "DKIM config" "/etc/opendkim/opendkim.conf presente"
    else
        check_warn "DKIM config" "Archivo de configuracion no encontrado"
    fi
    # Verificar claves
    DKIM_KEY_DIR="/etc/opendkim/keys/${DOMINIO}"
    if [[ -d "$DKIM_KEY_DIR" ]] && ls "$DKIM_KEY_DIR"/*.private &>/dev/null 2>&1; then
        check_pass "DKIM claves" "Clave privada encontrada en $DKIM_KEY_DIR"
    else
        check_warn "DKIM claves" "No se encontraron claves para $DOMINIO"
    fi
else
    check_fail "OpenDKIM" "No instalado"
fi

# ── 5. DMARC ──
if [[ $JSON_MODE -eq 0 ]]; then
    echo ""
    echo -e "${CYAN}── DMARC ──${NC}"
fi

DMARC_RECORD=""
if command -v dig &>/dev/null; then
    DMARC_RECORD=$(dig +short TXT "_dmarc.${DOMINIO}" 2>/dev/null | tr -d '"' || echo "")
elif command -v host &>/dev/null; then
    DMARC_RECORD=$(host -t TXT "_dmarc.${DOMINIO}" 2>/dev/null | grep "descriptive text" | sed 's/.*descriptive text "//;s/"$//' || echo "")
fi

if [[ -n "$DMARC_RECORD" ]]; then
    check_pass "DMARC" "Registro encontrado"
    DMARC_POLICY=$(echo "$DMARC_RECORD" | grep -oi "p=[a-z]*" | head -1 | cut -d= -f2)
    case "$DMARC_POLICY" in
        reject)     check_pass "DMARC politica" "reject (maxima proteccion)" ;;
        quarantine) check_warn "DMARC politica" "quarantine (buena, reject es mejor)" ;;
        none)       check_warn "DMARC politica" "none (solo monitoreo)" ;;
        *)          check_fail "DMARC politica" "No reconocida: $DMARC_POLICY" ;;
    esac
else
    check_fail "DMARC" "No se encontro registro DMARC para $DOMINIO"
fi

if command -v opendmarc &>/dev/null; then
    if systemctl is-active opendmarc &>/dev/null; then
        check_pass "OpenDMARC" "Activo y funcionando"
    else
        check_warn "OpenDMARC" "Instalado pero inactivo"
    fi
else
    check_warn "OpenDMARC" "No instalado localmente"
fi

# ── 6. Anti-spoofing ──
if [[ $JSON_MODE -eq 0 ]]; then
    echo ""
    echo -e "${CYAN}── Anti-spoofing ──${NC}"
fi

if [[ -f /etc/postfix/sender_login_maps ]]; then
    check_pass "Sender login maps" "Mapeo de remitentes configurado"
else
    check_warn "Sender login maps" "No configurado (posible spoofing autenticado)"
fi

if [[ -f /etc/postfix/spoof_header_checks ]]; then
    check_pass "Header checks spoofing" "Filtro anti-spoofing activo"
else
    check_warn "Header checks spoofing" "No configurado"
fi

if [[ -x /usr/local/bin/detectar-email-spoofing.sh ]]; then
    check_pass "Detector spoofing" "Script disponible"
fi

# ── 7. Spam ──
if [[ $JSON_MODE -eq 0 ]]; then
    echo ""
    echo -e "${CYAN}── Filtrado de spam ──${NC}"
fi

if command -v spamassassin &>/dev/null || command -v spamd &>/dev/null; then
    if systemctl is-active spamassassin &>/dev/null || systemctl is-active spamd &>/dev/null; then
        check_pass "SpamAssassin" "Activo y funcionando"
    else
        check_warn "SpamAssassin" "Instalado pero inactivo"
    fi
else
    check_warn "SpamAssassin" "No instalado"
fi

if [[ -f /etc/postfix/mime_header_checks ]]; then
    check_pass "Bloqueo adjuntos" "Filtro de adjuntos peligrosos activo"
else
    check_warn "Bloqueo adjuntos" "No configurado"
fi

# ── 8. Monitorizacion ──
if [[ $JSON_MODE -eq 0 ]]; then
    echo ""
    echo -e "${CYAN}── Monitorizacion ──${NC}"
fi

if [[ -x /usr/local/bin/monitorizar-email.sh ]]; then
    check_pass "Monitor email" "Script de monitorizacion instalado"
else
    check_warn "Monitor email" "No instalado"
fi

if [[ -x /etc/cron.daily/securizar-email-monitor ]]; then
    check_pass "Cron monitor" "Tarea diaria de monitorizacion activa"
else
    check_warn "Cron monitor" "Sin tarea cron de monitorizacion"
fi

# ── RESULTADO FINAL ──
PUNTUACION=0
if [[ $TOTAL_CHECKS -gt 0 ]]; then
    PUNTUACION=$(( (PASSED * 100) / TOTAL_CHECKS ))
fi

CALIFICACION="INSEGURO"
if [[ $PUNTUACION -ge 80 ]]; then
    CALIFICACION="SEGURO"
elif [[ $PUNTUACION -ge 50 ]]; then
    CALIFICACION="MEJORABLE"
fi

if [[ $JSON_MODE -eq 1 ]]; then
    # Construir JSON
    CHECKS_JSON=""
    for r in "${RESULTADOS[@]}"; do
        [[ -n "$CHECKS_JSON" ]] && CHECKS_JSON="${CHECKS_JSON},"
        CHECKS_JSON="${CHECKS_JSON}${r}"
    done
    cat << EOFJSON
{
  "timestamp": "$(date -Iseconds)",
  "dominio": "${DOMINIO}",
  "calificacion": "${CALIFICACION}",
  "puntuacion": ${PUNTUACION},
  "total_checks": ${TOTAL_CHECKS},
  "passed": ${PASSED},
  "warnings": ${WARNINGS},
  "failed": ${FAILED},
  "checks": [${CHECKS_JSON}]
}
EOFJSON
else
    echo ""
    echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  RESULTADO DE LA AUDITORIA${NC}"
    echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
    echo ""
    case "$CALIFICACION" in
        SEGURO)    echo -e "  Calificacion: ${GREEN}${BOLD}${CALIFICACION}${NC}" ;;
        MEJORABLE) echo -e "  Calificacion: ${YELLOW}${BOLD}${CALIFICACION}${NC}" ;;
        INSEGURO)  echo -e "  Calificacion: ${RED}${BOLD}${CALIFICACION}${NC}" ;;
    esac
    echo -e "  Puntuacion:   ${PUNTUACION}%"
    echo -e "  Verificaciones: ${TOTAL_CHECKS} total"
    echo -e "    ${GREEN}Correctas:${NC}  ${PASSED}"
    echo -e "    ${YELLOW}Avisos:${NC}     ${WARNINGS}"
    echo -e "    ${RED}Fallos:${NC}     ${FAILED}"
    echo ""
    echo -e "${DIM}Auditoria completada: $(date)${NC}"
fi
EOFAUDIT
    chmod +x /usr/local/bin/auditoria-email.sh
    log_change "Creado" "/usr/local/bin/auditoria-email.sh"

    # Tarea cron semanal
    mkdir -p /etc/cron.weekly
    cat > /etc/cron.weekly/auditoria-email << 'EOFCRONW'
#!/bin/bash
# ============================================================
# Auditoria semanal de seguridad email - securizar Modulo 42
# ============================================================

LOG_DIR="/var/log/securizar"
mkdir -p "$LOG_DIR"

# Ejecutar auditoria en modo JSON
/usr/local/bin/auditoria-email.sh --json > "${LOG_DIR}/auditoria-email-$(date +%Y%m%d).json" 2>/dev/null

# Registrar via syslog
CALIFICACION=$(/usr/local/bin/auditoria-email.sh --json 2>/dev/null | grep -o '"calificacion":"[^"]*"' | cut -d'"' -f4)
logger -t securizar-auditoria-email -p mail.info "Auditoria semanal: ${CALIFICACION:-desconocida}" 2>/dev/null || true

# Limpiar auditorias antiguas (mas de 90 dias)
find "$LOG_DIR" -name "auditoria-email-*.json" -mtime +90 -delete 2>/dev/null || true
EOFCRONW
    chmod +x /etc/cron.weekly/auditoria-email
    log_change "Creado" "/etc/cron.weekly/auditoria-email"

    log_info "Sistema de auditoria de seguridad email instalado"
    log_info "Ejecuta: auditoria-email.sh [--json] [dominio]"
else
    log_skip "Auditoria completa de seguridad email"
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
show_changes_summary
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║       SEGURIDAD DE EMAIL COMPLETADA                       ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups guardados en: $BACKUP_DIR"
echo ""
echo "Comandos utiles post-configuracion:"
echo "  - Verificar SPF:          verificar-spf.sh <dominio>"
echo "  - Verificar DMARC:        verificar-dmarc.sh <dominio>"
echo "  - Rotar clave DKIM:       rotar-dkim.sh <dominio>"
echo "  - Detectar spoofing:      detectar-email-spoofing.sh <email.eml>"
echo "  - Monitorizar email:      monitorizar-email.sh [--json]"
echo "  - Auditoria completa:     auditoria-email.sh [--json] [dominio]"
echo ""
log_warn "RECOMENDACION: Ejecuta 'auditoria-email.sh' para verificar la postura actual"
echo ""
log_info "Modulo 42 completado"
