#!/bin/bash
# ============================================================
# seguridad-web.sh - Modulo 50: Seguridad de aplicaciones web
# ============================================================
# Secciones:
#   S1  - Hardening de nginx
#   S2  - Hardening de Apache/httpd
#   S3  - Cabeceras de seguridad HTTP
#   S4  - ModSecurity WAF
#   S5  - Optimizacion TLS/SSL
#   S6  - Rate Limiting y proteccion DDoS
#   S7  - Reglas WAF personalizadas
#   S8  - Control de acceso y autenticacion
#   S9  - Monitorizacion y analisis de logs web
#   S10 - Auditoria de seguridad web
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps

# ── Pre-check: detectar secciones ya aplicadas ──────────────
_precheck 10
_pc 'check_file_exists /etc/nginx/conf.d/securizar-hardening.conf'
_pc true  # S2 - Apache hardening (depende de distro_family)
_pc 'check_executable /usr/local/bin/verificar-headers-seguridad.sh'
_pc 'check_executable /usr/local/bin/gestionar-modsecurity.sh'
_pc 'check_executable /usr/local/bin/verificar-tls-web.sh'
_pc 'check_executable /usr/local/bin/detectar-ddos-web.sh'
_pc 'check_dir_exists /etc/securizar/waf-custom-rules'
_pc 'check_executable /usr/local/bin/configurar-acceso-web.sh'
_pc 'check_executable /usr/local/bin/monitorizar-web.sh'
_pc 'check_executable /usr/local/bin/auditoria-seguridad-web.sh'
_precheck_result

init_backup "seguridad-web"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MODULO 50 - SEGURIDAD DE APLICACIONES WEB             ║"
echo "║   nginx, Apache, headers, WAF, TLS, rate-limiting,      ║"
echo "║   acceso, monitorizacion, auditoria                     ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_section "MODULO 50: SEGURIDAD DE APLICACIONES WEB"
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

# ── Deteccion de servidores web ────────────────────────────────
NGINX_INSTALLED=false
APACHE_INSTALLED=false
NGINX_CONF_DIR=""
APACHE_CONF_DIR=""
APACHE_SERVICE=""

if command -v nginx &>/dev/null; then
    NGINX_INSTALLED=true
    NGINX_CONF_DIR="/etc/nginx"
    log_info "nginx detectado: $(nginx -v 2>&1 | head -1)"
fi

if command -v httpd &>/dev/null || command -v apache2ctl &>/dev/null; then
    APACHE_INSTALLED=true
    if [[ "$DISTRO_FAMILY" == "debian" ]]; then
        APACHE_CONF_DIR="/etc/apache2"
        APACHE_SERVICE="apache2"
    else
        APACHE_CONF_DIR="/etc/httpd"
        APACHE_SERVICE="httpd"
    fi
    log_info "Apache detectado en: $APACHE_CONF_DIR"
fi

if [[ "$NGINX_INSTALLED" == false && "$APACHE_INSTALLED" == false ]]; then
    log_warn "No se detecto nginx ni Apache instalados"
    log_warn "Las secciones de hardening de servidor se omitiran"
fi

mkdir -p /etc/securizar

# ============================================================
# S1: HARDENING DE NGINX
# ============================================================
log_section "S1: HARDENING DE NGINX"

echo "Aplica hardening de seguridad a nginx:"
echo "  - server_tokens off (ocultar version)"
echo "  - Deshabilitar autoindex"
echo "  - Restringir metodos HTTP (GET/POST/HEAD)"
echo "  - Limitar buffers y tamano de body"
echo "  - Limitar conexiones por IP"
echo "  - Deshabilitar SSLv3/TLSv1/TLSv1.1"
echo "  - Suite de cifrado robusta"
echo "  - OCSP stapling"
echo "  - DH params 4096-bit"
echo ""

if [[ "$NGINX_INSTALLED" == true ]]; then
    if check_file_exists /etc/nginx/conf.d/securizar-hardening.conf; then
        log_already "Hardening de nginx (configuracion ya existe)"
    elif ask "¿Aplicar hardening de nginx?"; then

        # Backup de configuracion actual
        if [[ -d "$NGINX_CONF_DIR" ]]; then
            cp -a "$NGINX_CONF_DIR" "$BACKUP_DIR/nginx-conf-backup" 2>/dev/null || true
            log_change "Backup" "configuracion nginx en $BACKUP_DIR/nginx-conf-backup"
        fi

        mkdir -p "$NGINX_CONF_DIR/conf.d"
        mkdir -p "$NGINX_CONF_DIR/snippets"

        # Generar DH params si no existen
        DH_PARAMS_FILE="$NGINX_CONF_DIR/dhparam.pem"
        if [[ ! -f "$DH_PARAMS_FILE" ]]; then
            log_info "Generando DH params 4096-bit (puede tardar varios minutos)..."
            openssl dhparam -out "$DH_PARAMS_FILE" 4096 2>/dev/null
            chmod 600 "$DH_PARAMS_FILE"
            log_change "Generado" "DH params 4096-bit: $DH_PARAMS_FILE"
        else
            log_info "DH params ya existen: $DH_PARAMS_FILE"
        fi

        # Crear configuracion de hardening
        cat > "$NGINX_CONF_DIR/conf.d/securizar-hardening.conf" << 'EOF'
# ============================================================
# securizar-hardening.conf - Hardening nginx
# Generado por securizar - Modulo 50
# ============================================================

# ── Ocultar version del servidor ────────────────────────────
server_tokens off;

# ── Deshabilitar autoindex ──────────────────────────────────
autoindex off;

# ── Limitar tamano de buffers ───────────────────────────────
client_body_buffer_size 16k;
client_header_buffer_size 1k;
client_max_body_size 10m;
large_client_header_buffers 4 8k;

# ── Timeouts de seguridad ──────────────────────────────────
client_body_timeout 12;
client_header_timeout 12;
keepalive_timeout 15;
send_timeout 10;

# ── Rate limiting zones ────────────────────────────────────
limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=login:10m rate=3r/s;
limit_req_zone $binary_remote_addr zone=api:10m rate=30r/s;
limit_conn_zone $binary_remote_addr zone=addr:10m;

# ── Limitar conexiones por IP ──────────────────────────────
limit_conn addr 20;

# ── Cabeceras de seguridad base ────────────────────────────
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "0" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# ── Desactivar metodos HTTP peligrosos ─────────────────────
# Usar dentro de bloques server/location:
# if ($request_method !~ ^(GET|POST|HEAD)$ ) {
#     return 405;
# }
EOF
        log_change "Creado" "$NGINX_CONF_DIR/conf.d/securizar-hardening.conf"

        # Configuracion SSL/TLS
        cat > "$NGINX_CONF_DIR/snippets/securizar-ssl.conf" << EOF
# ============================================================
# securizar-ssl.conf - TLS hardening para nginx
# Generado por securizar - Modulo 50
# ============================================================

# ── Protocolos: solo TLS 1.2 y 1.3 ─────────────────────────
ssl_protocols TLSv1.2 TLSv1.3;

# ── Cifrados robustos ──────────────────────────────────────
ssl_ciphers 'ECDHE+AESGCM:ECDHE+CHACHA20POLY1305:!aNULL:!MD5:!DSS:!3DES:!RC4';
ssl_prefer_server_ciphers on;

# ── DH params ─────────────────────────────────────────────
ssl_dhparam ${DH_PARAMS_FILE};

# ── OCSP stapling ─────────────────────────────────────────
ssl_stapling on;
ssl_stapling_verify on;
resolver 1.1.1.1 8.8.8.8 valid=300s;
resolver_timeout 5s;

# ── Session cache ─────────────────────────────────────────
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;

# ── HSTS ──────────────────────────────────────────────────
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
EOF
        log_change "Creado" "$NGINX_CONF_DIR/snippets/securizar-ssl.conf"

        # Snippet para restringir metodos HTTP
        cat > "$NGINX_CONF_DIR/snippets/securizar-metodos.conf" << 'EOF'
# ============================================================
# securizar-metodos.conf - Restriccion de metodos HTTP
# Incluir dentro de bloques server { }
# Generado por securizar - Modulo 50
# ============================================================

# Denegar metodos HTTP peligrosos
if ($request_method !~ ^(GET|POST|HEAD)$ ) {
    return 405;
}
EOF
        log_change "Creado" "$NGINX_CONF_DIR/snippets/securizar-metodos.conf"

        # Verificar configuracion de nginx
        if nginx -t 2>/dev/null; then
            log_info "Configuracion de nginx validada correctamente"
        else
            log_warn "Error en configuracion de nginx - revisar manualmente"
            log_warn "Ejecuta: nginx -t"
        fi

        log_info "Hardening de nginx aplicado"
        log_info "Incluir en bloques server: include snippets/securizar-ssl.conf;"
        log_info "Incluir en bloques server: include snippets/securizar-metodos.conf;"
    else
        log_skip "Hardening de nginx"
    fi
else
    log_skip "nginx no instalado"
fi

# ============================================================
# S2: HARDENING DE APACHE/HTTPD
# ============================================================
log_section "S2: HARDENING DE APACHE/HTTPD"

echo "Aplica hardening de seguridad a Apache/httpd:"
echo "  - ServerTokens Prod, ServerSignature Off"
echo "  - TraceEnable Off"
echo "  - Deshabilitar listado de directorios (Options -Indexes)"
echo "  - Deshabilitar CGI si no se usa"
echo "  - Restringir metodos HTTP"
echo "  - Ajustar timeouts"
echo "  - Deshabilitar mod_info/mod_status en produccion"
echo ""

if [[ "$APACHE_INSTALLED" == true ]]; then
    if check_file_exists /etc/apache2/conf-available/securizar-hardening.conf || check_file_exists /etc/httpd/conf.d/securizar-hardening.conf; then
        log_already "Hardening de Apache (configuracion ya existe)"
    elif ask "¿Aplicar hardening de Apache?"; then

        # Backup de configuracion
        if [[ -d "$APACHE_CONF_DIR" ]]; then
            cp -a "$APACHE_CONF_DIR" "$BACKUP_DIR/apache-conf-backup" 2>/dev/null || true
            log_change "Backup" "configuracion Apache en $BACKUP_DIR/apache-conf-backup"
        fi

        # Determinar ruta de configuracion
        if [[ "$DISTRO_FAMILY" == "debian" ]]; then
            APACHE_HARDENING_CONF="$APACHE_CONF_DIR/conf-available/securizar-hardening.conf"
        else
            mkdir -p "$APACHE_CONF_DIR/conf.d"
            APACHE_HARDENING_CONF="$APACHE_CONF_DIR/conf.d/securizar-hardening.conf"
        fi

        cat > "$APACHE_HARDENING_CONF" << 'EOF'
# ============================================================
# securizar-hardening.conf - Hardening Apache
# Generado por securizar - Modulo 50
# ============================================================

# ── Ocultar informacion del servidor ───────────────────────
ServerTokens Prod
ServerSignature Off

# ── Deshabilitar TRACE ─────────────────────────────────────
TraceEnable Off

# ── Deshabilitar listado de directorios ────────────────────
<Directory />
    Options -Indexes -FollowSymLinks
    AllowOverride None
    Require all denied
</Directory>

# ── Timeouts de seguridad ──────────────────────────────────
Timeout 60
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 5

# ── Limitar tamano de peticiones ───────────────────────────
LimitRequestBody 10485760
LimitRequestFields 50
LimitRequestFieldSize 8190
LimitRequestLine 8190

# ── Restringir metodos HTTP ────────────────────────────────
<Directory />
    <LimitExcept GET POST HEAD>
        Require all denied
    </LimitExcept>
</Directory>

# ── Deshabilitar ETags ─────────────────────────────────────
FileETag None

# ── Cabeceras de seguridad ─────────────────────────────────
<IfModule mod_headers.c>
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "0"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always unset X-Powered-By
    Header always unset Server
</IfModule>
EOF
        log_change "Creado" "$APACHE_HARDENING_CONF"

        # Configuracion SSL/TLS para Apache
        if [[ "$DISTRO_FAMILY" == "debian" ]]; then
            APACHE_SSL_CONF="$APACHE_CONF_DIR/conf-available/securizar-ssl.conf"
        else
            APACHE_SSL_CONF="$APACHE_CONF_DIR/conf.d/securizar-ssl.conf"
        fi

        cat > "$APACHE_SSL_CONF" << 'EOF'
# ============================================================
# securizar-ssl.conf - TLS hardening para Apache
# Generado por securizar - Modulo 50
# ============================================================

<IfModule mod_ssl.c>
    # ── Protocolos: solo TLS 1.2 y 1.3 ─────────────────────
    SSLProtocol -all +TLSv1.2 +TLSv1.3

    # ── Cifrados robustos ──────────────────────────────────
    SSLCipherSuite ECDHE+AESGCM:ECDHE+CHACHA20POLY1305:!aNULL:!MD5:!DSS:!3DES:!RC4
    SSLHonorCipherOrder on

    # ── Compresion SSL deshabilitada (CRIME) ───────────────
    SSLCompression off

    # ── OCSP stapling ─────────────────────────────────────
    SSLUseStapling on
    SSLStaplingResponderTimeout 5
    SSLStaplingReturnResponderErrors off
    SSLStaplingCache shmcb:/var/run/ocsp(128000)

    # ── Session tickets ───────────────────────────────────
    SSLSessionTickets off

    # ── HSTS ──────────────────────────────────────────────
    <IfModule mod_headers.c>
        Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    </IfModule>
</IfModule>
EOF
        log_change "Creado" "$APACHE_SSL_CONF"

        # Habilitar configuracion en Debian
        if [[ "$DISTRO_FAMILY" == "debian" ]]; then
            if command -v a2enconf &>/dev/null; then
                a2enconf securizar-hardening 2>/dev/null || true
                a2enconf securizar-ssl 2>/dev/null || true
                log_change "Habilitado" "a2enconf securizar-hardening + securizar-ssl"
            fi
            # Habilitar modulos necesarios
            if command -v a2enmod &>/dev/null; then
                a2enmod headers 2>/dev/null || true
                a2enmod ssl 2>/dev/null || true
                log_change "Habilitado" "a2enmod headers + ssl"
            fi
        fi

        # Deshabilitar mod_info y mod_status en produccion
        if [[ "$DISTRO_FAMILY" == "debian" ]]; then
            if command -v a2dismod &>/dev/null; then
                a2dismod info 2>/dev/null || true
                a2dismod status 2>/dev/null || true
                log_change "Deshabilitado" "mod_info y mod_status (produccion)"
            fi
        else
            # RHEL/SUSE: comentar LoadModule en conf
            for conf_file in "$APACHE_CONF_DIR/conf.modules.d/"*.conf "$APACHE_CONF_DIR/conf/"*.conf; do
                [[ -f "$conf_file" ]] || continue
                if grep -q "^LoadModule info_module" "$conf_file" 2>/dev/null; then
                    sed -i 's/^LoadModule info_module/#LoadModule info_module/' "$conf_file"
                    log_change "Deshabilitado" "mod_info en $conf_file"
                fi
                if grep -q "^LoadModule status_module" "$conf_file" 2>/dev/null; then
                    sed -i 's/^LoadModule status_module/#LoadModule status_module/' "$conf_file"
                    log_change "Deshabilitado" "mod_status en $conf_file"
                fi
            done
        fi

        # Verificar configuracion de Apache
        if [[ "$DISTRO_FAMILY" == "debian" ]]; then
            if apache2ctl configtest 2>/dev/null; then
                log_info "Configuracion de Apache validada correctamente"
            else
                log_warn "Error en configuracion de Apache - revisar manualmente"
            fi
        else
            if httpd -t 2>/dev/null; then
                log_info "Configuracion de Apache validada correctamente"
            else
                log_warn "Error en configuracion de Apache - revisar manualmente"
            fi
        fi

        log_info "Hardening de Apache aplicado"
    else
        log_skip "Hardening de Apache"
    fi
else
    log_skip "Apache no instalado"
fi

# ============================================================
# S3: CABECERAS DE SEGURIDAD HTTP
# ============================================================
log_section "S3: CABECERAS DE SEGURIDAD HTTP"

echo "Configura cabeceras de seguridad HTTP estandar:"
echo "  - Content-Security-Policy (default-src 'self')"
echo "  - Strict-Transport-Security (HSTS con preload)"
echo "  - X-Frame-Options DENY"
echo "  - X-Content-Type-Options nosniff"
echo "  - X-XSS-Protection '0' (deprecated, usar CSP)"
echo "  - Referrer-Policy strict-origin-when-cross-origin"
echo "  - Permissions-Policy (camera, microphone, geolocation)"
echo "  - Script verificador de cabeceras"
echo ""

if check_executable /usr/local/bin/verificar-headers-seguridad.sh; then
    log_already "Cabeceras de seguridad HTTP (verificador ya instalado)"
elif ask "¿Configurar cabeceras de seguridad HTTP?"; then

    # Snippet para nginx
    if [[ "$NGINX_INSTALLED" == true ]]; then
        cat > "$NGINX_CONF_DIR/snippets/securizar-headers.conf" << 'EOF'
# ============================================================
# securizar-headers.conf - Cabeceras de seguridad HTTP
# Incluir dentro de bloques server { }
# Generado por securizar - Modulo 50
# ============================================================

# Content-Security-Policy
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;

# HSTS
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# X-Frame-Options
add_header X-Frame-Options "DENY" always;

# X-Content-Type-Options
add_header X-Content-Type-Options "nosniff" always;

# X-XSS-Protection (deprecated, usar CSP en su lugar)
add_header X-XSS-Protection "0" always;

# Referrer-Policy
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Permissions-Policy
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()" always;

# Cross-Origin policies
add_header Cross-Origin-Embedder-Policy "require-corp" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
EOF
        log_change "Creado" "$NGINX_CONF_DIR/snippets/securizar-headers.conf"
        log_info "Incluir en bloques server: include snippets/securizar-headers.conf;"
    fi

    # Snippet para Apache
    if [[ "$APACHE_INSTALLED" == true ]]; then
        if [[ "$DISTRO_FAMILY" == "debian" ]]; then
            APACHE_HEADERS_CONF="$APACHE_CONF_DIR/conf-available/securizar-headers.conf"
        else
            APACHE_HEADERS_CONF="$APACHE_CONF_DIR/conf.d/securizar-headers.conf"
        fi

        cat > "$APACHE_HEADERS_CONF" << 'EOF'
# ============================================================
# securizar-headers.conf - Cabeceras de seguridad HTTP
# Generado por securizar - Modulo 50
# ============================================================

<IfModule mod_headers.c>
    # Content-Security-Policy
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';"

    # HSTS
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"

    # X-Frame-Options
    Header always set X-Frame-Options "DENY"

    # X-Content-Type-Options
    Header always set X-Content-Type-Options "nosniff"

    # X-XSS-Protection (deprecated, usar CSP en su lugar)
    Header always set X-XSS-Protection "0"

    # Referrer-Policy
    Header always set Referrer-Policy "strict-origin-when-cross-origin"

    # Permissions-Policy
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()"

    # Cross-Origin policies
    Header always set Cross-Origin-Embedder-Policy "require-corp"
    Header always set Cross-Origin-Opener-Policy "same-origin"
    Header always set Cross-Origin-Resource-Policy "same-origin"

    # Eliminar headers informativos
    Header always unset X-Powered-By
    Header always unset Server
</IfModule>
EOF
        log_change "Creado" "$APACHE_HEADERS_CONF"

        if [[ "$DISTRO_FAMILY" == "debian" ]] && command -v a2enconf &>/dev/null; then
            a2enconf securizar-headers 2>/dev/null || true
            log_change "Habilitado" "a2enconf securizar-headers"
        fi
    fi

    # Script verificador de cabeceras
    cat > /usr/local/bin/verificar-headers-seguridad.sh << 'EOFSCRIPT'
#!/bin/bash
# ============================================================
# verificar-headers-seguridad.sh
# Verifica cabeceras de seguridad en servicios locales
# Generado por securizar - Modulo 50
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

URLS=("${@:-http://localhost}")
ERRORES=0
CORRECTOS=0
TOTAL_CHECKS=0

CABECERAS_REQUERIDAS=(
    "Content-Security-Policy"
    "Strict-Transport-Security"
    "X-Frame-Options"
    "X-Content-Type-Options"
    "Referrer-Policy"
    "Permissions-Policy"
)

CABECERAS_AUSENTES=(
    "X-Powered-By"
    "Server"
)

echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "${CYAN}  VERIFICACION DE CABECERAS DE SEGURIDAD${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo ""

for url in "${URLS[@]}"; do
    echo -e "${CYAN}--- Verificando: $url ---${NC}"
    echo ""

    headers=$(curl -s -I -o /dev/null -w "%{http_code}" --connect-timeout 5 "$url" 2>/dev/null)
    if [[ "$headers" == "000" ]]; then
        echo -e "${RED}[X] No se pudo conectar a $url${NC}"
        continue
    fi

    full_headers=$(curl -s -I --connect-timeout 5 "$url" 2>/dev/null)

    # Verificar cabeceras requeridas
    for header in "${CABECERAS_REQUERIDAS[@]}"; do
        ((TOTAL_CHECKS++)) || true
        value=$(echo "$full_headers" | grep -i "^${header}:" | head -1 | cut -d: -f2- | xargs 2>/dev/null)
        if [[ -n "$value" ]]; then
            echo -e "${GREEN}[OK] ${header}: ${value}${NC}"
            ((CORRECTOS++)) || true
        else
            echo -e "${RED}[FALTA] ${header}${NC}"
            ((ERRORES++)) || true
        fi
    done

    # Verificar cabeceras que NO deben estar
    for header in "${CABECERAS_AUSENTES[@]}"; do
        ((TOTAL_CHECKS++)) || true
        value=$(echo "$full_headers" | grep -i "^${header}:" | head -1 | cut -d: -f2- | xargs 2>/dev/null)
        if [[ -z "$value" ]]; then
            echo -e "${GREEN}[OK] ${header} no expuesto${NC}"
            ((CORRECTOS++)) || true
        else
            echo -e "${YELLOW}[!] ${header} expuesto: ${value}${NC}"
            ((ERRORES++)) || true
        fi
    done

    echo ""
done

# Resumen
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "${CYAN}  RESUMEN${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "  Total verificaciones: ${TOTAL_CHECKS}"
echo -e "  ${GREEN}Correctas: ${CORRECTOS}${NC}"
echo -e "  ${RED}Con problemas: ${ERRORES}${NC}"

if [[ $ERRORES -eq 0 ]]; then
    echo -e "\n${GREEN}[+] Todas las cabeceras de seguridad estan correctas${NC}"
else
    echo -e "\n${YELLOW}[!] Se detectaron $ERRORES problemas en las cabeceras${NC}"
fi

exit $ERRORES
EOFSCRIPT
    chmod +x /usr/local/bin/verificar-headers-seguridad.sh
    log_change "Creado" "/usr/local/bin/verificar-headers-seguridad.sh"

    log_info "Cabeceras de seguridad configuradas"
    log_info "Verificar con: verificar-headers-seguridad.sh http://localhost"
else
    log_skip "Cabeceras de seguridad HTTP"
fi

# ============================================================
# S4: MODSECURITY WAF
# ============================================================
log_section "S4: MODSECURITY WAF"

echo "Instala y configura ModSecurity Web Application Firewall:"
echo "  - libmodsecurity (nginx) / mod_security2 (Apache)"
echo "  - OWASP Core Rule Set (CRS)"
echo "  - SecRuleEngine On, anomaly scoring mode"
echo "  - Limites de body de peticion"
echo "  - Configuracion de exclusiones de falsos positivos"
echo "  - Script de gestion de ModSecurity"
echo ""

if check_executable /usr/local/bin/gestionar-modsecurity.sh; then
    log_already "ModSecurity WAF (script gestion ya instalado)"
elif ask "¿Instalar y configurar ModSecurity WAF?"; then

    MODSEC_CONF_DIR="/etc/modsecurity"
    MODSEC_CRS_DIR="/etc/modsecurity/crs"
    mkdir -p "$MODSEC_CONF_DIR"
    mkdir -p "$MODSEC_CRS_DIR"

    # Instalar ModSecurity segun servidor web y distro
    if [[ "$NGINX_INSTALLED" == true ]]; then
        case "$DISTRO_FAMILY" in
            debian)
                pkg_install libnginx-mod-http-modsecurity || log_warn "No se pudo instalar libnginx-mod-http-modsecurity"
                ;;
            rhel)
                pkg_install libmodsecurity || log_warn "No se pudo instalar libmodsecurity"
                ;;
            suse)
                pkg_install libmodsecurity3 || log_warn "No se pudo instalar libmodsecurity3"
                ;;
            arch)
                pkg_install libmodsecurity || log_warn "No se pudo instalar libmodsecurity"
                ;;
        esac
    fi

    if [[ "$APACHE_INSTALLED" == true ]]; then
        case "$DISTRO_FAMILY" in
            debian)
                pkg_install libapache2-mod-security2 || log_warn "No se pudo instalar libapache2-mod-security2"
                if command -v a2enmod &>/dev/null; then
                    a2enmod security2 2>/dev/null || true
                    log_change "Habilitado" "a2enmod security2"
                fi
                ;;
            rhel)
                pkg_install mod_security || log_warn "No se pudo instalar mod_security"
                ;;
            suse)
                pkg_install apache2-mod_security2 || log_warn "No se pudo instalar apache2-mod_security2"
                ;;
            arch)
                log_warn "ModSecurity para Apache en Arch: instalar desde AUR"
                ;;
        esac
    fi

    # Configuracion principal de ModSecurity
    cat > "$MODSEC_CONF_DIR/modsecurity.conf" << 'EOF'
# ============================================================
# modsecurity.conf - Configuracion principal ModSecurity
# Generado por securizar - Modulo 50
# ============================================================

# ── Motor de reglas activado ───────────────────────────────
SecRuleEngine On

# ── Modo de deteccion ─────────────────────────────────────
# DetectionOnly = solo detectar, no bloquear (para testing)
# On = detectar y bloquear
# Off = deshabilitado

# ── Cuerpo de peticion ────────────────────────────────────
SecRequestBodyAccess On
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
SecRequestBodyLimitAction Reject

# ── Cuerpo de respuesta ──────────────────────────────────
SecResponseBodyAccess Off

# ── Directorio temporal ───────────────────────────────────
SecTmpDir /tmp/modsecurity_tmp
SecDataDir /tmp/modsecurity_data

# ── Auditoria ─────────────────────────────────────────────
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts ABIJDEFHZ
SecAuditLogType Serial
SecAuditLog /var/log/modsecurity/modsec_audit.log

# ── Debug ─────────────────────────────────────────────────
SecDebugLog /var/log/modsecurity/modsec_debug.log
SecDebugLogLevel 0

# ── Reglas generales ──────────────────────────────────────
SecRule REQUEST_HEADERS:Content-Type "(?:application(?:/soap\+|/)|text/)xml" \
    "id:'200000',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"

SecRule REQUEST_HEADERS:Content-Type "application/json" \
    "id:'200001',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"

# ── Anomaly scoring mode ──────────────────────────────────
SecAction "id:900110,phase:1,nolog,pass,t:none,\
    setvar:tx.inbound_anomaly_score_threshold=5,\
    setvar:tx.outbound_anomaly_score_threshold=4"

# ── Paranoia level (1-4, 1=basico, 4=maximo) ─────────────
SecAction "id:900000,phase:1,nolog,pass,t:none,\
    setvar:tx.paranoia_level=1"

# ── Modo de respuesta ────────────────────────────────────
SecDefaultAction "phase:1,log,auditlog,pass"
SecDefaultAction "phase:2,log,auditlog,pass"
EOF
    log_change "Creado" "$MODSEC_CONF_DIR/modsecurity.conf"

    # Crear directorios de log
    mkdir -p /var/log/modsecurity
    mkdir -p /tmp/modsecurity_tmp
    mkdir -p /tmp/modsecurity_data
    chmod 750 /var/log/modsecurity

    # Configuracion de exclusiones de falsos positivos
    cat > "$MODSEC_CONF_DIR/exclusiones-securizar.conf" << 'EOF'
# ============================================================
# exclusiones-securizar.conf - Falsos positivos conocidos
# Generado por securizar - Modulo 50
# ============================================================
# Agregar exclusiones de reglas aqui.
# Formato:
#   SecRuleRemoveById <ID>
#   SecRuleRemoveByTag <TAG>
#   SecRuleUpdateTargetById <ID> "!REQUEST_COOKIES:/<cookie>/"

# Ejemplo: excluir regla para formularios de login
# SecRuleRemoveById 942100

# Ejemplo: excluir para ruta especifica
# SecRule REQUEST_URI "@beginsWith /api/upload" \
#     "id:1000001,phase:1,nolog,pass,ctl:ruleRemoveById=200003"
EOF
    log_change "Creado" "$MODSEC_CONF_DIR/exclusiones-securizar.conf"

    # Descargar OWASP CRS si no existe
    if [[ ! -d "$MODSEC_CRS_DIR/rules" ]]; then
        CRS_VERSION="4.0.0"
        CRS_URL="https://github.com/coreruleset/coreruleset/archive/refs/tags/v${CRS_VERSION}.tar.gz"
        CRS_TMP="/tmp/crs-${CRS_VERSION}.tar.gz"

        log_info "Descargando OWASP CRS v${CRS_VERSION}..."
        if curl -sL -o "$CRS_TMP" "$CRS_URL" 2>/dev/null; then
            tar xzf "$CRS_TMP" -C /tmp/ 2>/dev/null || true
            if [[ -d "/tmp/coreruleset-${CRS_VERSION}" ]]; then
                cp -a "/tmp/coreruleset-${CRS_VERSION}/rules" "$MODSEC_CRS_DIR/"
                cp -a "/tmp/coreruleset-${CRS_VERSION}/crs-setup.conf.example" "$MODSEC_CRS_DIR/crs-setup.conf" 2>/dev/null || true
                rm -rf "/tmp/coreruleset-${CRS_VERSION}" "$CRS_TMP"
                log_change "Instalado" "OWASP CRS v${CRS_VERSION} en $MODSEC_CRS_DIR"
            else
                log_warn "No se pudo extraer OWASP CRS"
            fi
        else
            log_warn "No se pudo descargar OWASP CRS (sin conexion a Internet?)"
            log_info "Descargar manualmente: $CRS_URL"
        fi
    else
        log_info "OWASP CRS ya instalado en $MODSEC_CRS_DIR/rules"
    fi

    # Configuracion para nginx
    if [[ "$NGINX_INSTALLED" == true ]]; then
        cat > "$NGINX_CONF_DIR/snippets/securizar-modsecurity.conf" << EOF
# ============================================================
# securizar-modsecurity.conf - ModSecurity para nginx
# Incluir dentro de bloques server { } o http { }
# Generado por securizar - Modulo 50
# ============================================================

modsecurity on;
modsecurity_rules_file ${MODSEC_CONF_DIR}/modsecurity.conf;
EOF
        log_change "Creado" "$NGINX_CONF_DIR/snippets/securizar-modsecurity.conf"
    fi

    # Configuracion para Apache
    if [[ "$APACHE_INSTALLED" == true ]]; then
        if [[ "$DISTRO_FAMILY" == "debian" ]]; then
            MODSEC_APACHE_CONF="$APACHE_CONF_DIR/conf-available/securizar-modsecurity.conf"
        else
            MODSEC_APACHE_CONF="$APACHE_CONF_DIR/conf.d/securizar-modsecurity.conf"
        fi

        cat > "$MODSEC_APACHE_CONF" << EOF
# ============================================================
# securizar-modsecurity.conf - ModSecurity para Apache
# Generado por securizar - Modulo 50
# ============================================================

<IfModule security2_module>
    IncludeOptional ${MODSEC_CONF_DIR}/modsecurity.conf
    IncludeOptional ${MODSEC_CRS_DIR}/crs-setup.conf
    IncludeOptional ${MODSEC_CRS_DIR}/rules/*.conf
    IncludeOptional ${MODSEC_CONF_DIR}/exclusiones-securizar.conf
</IfModule>
EOF
        log_change "Creado" "$MODSEC_APACHE_CONF"

        if [[ "$DISTRO_FAMILY" == "debian" ]] && command -v a2enconf &>/dev/null; then
            a2enconf securizar-modsecurity 2>/dev/null || true
            log_change "Habilitado" "a2enconf securizar-modsecurity"
        fi
    fi

    # Script de gestion de ModSecurity
    cat > /usr/local/bin/gestionar-modsecurity.sh << 'EOFSCRIPT'
#!/bin/bash
# ============================================================
# gestionar-modsecurity.sh
# Gestion de ModSecurity: enable/disable/status/test/update-rules
# Generado por securizar - Modulo 50
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

MODSEC_CONF="/etc/modsecurity/modsecurity.conf"
MODSEC_CRS_DIR="/etc/modsecurity/crs"

usage() {
    echo -e "${CYAN}Uso: $0 {enable|disable|status|test|update-rules|audit-log}${NC}"
    echo ""
    echo "  enable       - Activar ModSecurity (SecRuleEngine On)"
    echo "  disable      - Desactivar ModSecurity (SecRuleEngine Off)"
    echo "  detect-only  - Modo deteccion (SecRuleEngine DetectionOnly)"
    echo "  status       - Estado actual de ModSecurity"
    echo "  test         - Probar reglas con peticion de prueba"
    echo "  update-rules - Actualizar OWASP CRS"
    echo "  audit-log    - Mostrar ultimas entradas del audit log"
    exit 1
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[X] Ejecutar como root${NC}"
        exit 1
    fi
}

cmd_enable() {
    check_root
    if [[ -f "$MODSEC_CONF" ]]; then
        sed -i 's/^SecRuleEngine .*/SecRuleEngine On/' "$MODSEC_CONF"
        echo -e "${GREEN}[+] ModSecurity activado (SecRuleEngine On)${NC}"
        echo -e "${YELLOW}[!] Reiniciar servidor web para aplicar cambios${NC}"
    else
        echo -e "${RED}[X] No se encontro $MODSEC_CONF${NC}"
    fi
}

cmd_disable() {
    check_root
    if [[ -f "$MODSEC_CONF" ]]; then
        sed -i 's/^SecRuleEngine .*/SecRuleEngine Off/' "$MODSEC_CONF"
        echo -e "${YELLOW}[!] ModSecurity desactivado (SecRuleEngine Off)${NC}"
        echo -e "${YELLOW}[!] Reiniciar servidor web para aplicar cambios${NC}"
    else
        echo -e "${RED}[X] No se encontro $MODSEC_CONF${NC}"
    fi
}

cmd_detect_only() {
    check_root
    if [[ -f "$MODSEC_CONF" ]]; then
        sed -i 's/^SecRuleEngine .*/SecRuleEngine DetectionOnly/' "$MODSEC_CONF"
        echo -e "${YELLOW}[!] ModSecurity en modo deteccion (DetectionOnly)${NC}"
        echo -e "${YELLOW}[!] Reiniciar servidor web para aplicar cambios${NC}"
    else
        echo -e "${RED}[X] No se encontro $MODSEC_CONF${NC}"
    fi
}

cmd_status() {
    echo -e "${CYAN}══════════════════════════════════════════${NC}"
    echo -e "${CYAN}  ESTADO DE MODSECURITY${NC}"
    echo -e "${CYAN}══════════════════════════════════════════${NC}"

    if [[ -f "$MODSEC_CONF" ]]; then
        local engine
        engine=$(grep "^SecRuleEngine" "$MODSEC_CONF" | awk '{print $2}')
        echo -e "  Motor de reglas: ${BOLD}${engine:-desconocido}${NC}"
    else
        echo -e "  ${RED}Configuracion no encontrada: $MODSEC_CONF${NC}"
    fi

    if [[ -d "$MODSEC_CRS_DIR/rules" ]]; then
        local num_rules
        num_rules=$(ls "$MODSEC_CRS_DIR/rules/"*.conf 2>/dev/null | wc -l)
        echo -e "  Reglas CRS cargadas: ${BOLD}${num_rules}${NC}"
    else
        echo -e "  ${YELLOW}Reglas CRS no instaladas${NC}"
    fi

    local audit_log="/var/log/modsecurity/modsec_audit.log"
    if [[ -f "$audit_log" ]]; then
        local log_size
        log_size=$(du -h "$audit_log" | cut -f1)
        local last_entry
        last_entry=$(tail -1 "$audit_log" 2>/dev/null | head -c 80)
        echo -e "  Audit log: ${log_size} - ultima: ${last_entry:-vacio}"
    fi

    # Verificar si nginx/Apache tienen ModSecurity cargado
    if command -v nginx &>/dev/null; then
        if nginx -V 2>&1 | grep -qi modsecurity; then
            echo -e "  nginx: ${GREEN}ModSecurity compilado${NC}"
        else
            echo -e "  nginx: ${YELLOW}ModSecurity no detectado en binario${NC}"
        fi
    fi

    if command -v httpd &>/dev/null || command -v apache2ctl &>/dev/null; then
        local apache_cmd="httpd"
        command -v apache2ctl &>/dev/null && apache_cmd="apache2ctl"
        if $apache_cmd -M 2>/dev/null | grep -qi security2; then
            echo -e "  Apache: ${GREEN}security2_module cargado${NC}"
        else
            echo -e "  Apache: ${YELLOW}security2_module no cargado${NC}"
        fi
    fi
}

cmd_test() {
    echo -e "${CYAN}Probando reglas ModSecurity con peticiones de prueba...${NC}"
    echo ""

    local test_url="${1:-http://localhost}"

    # Test 1: SQL injection
    echo -e "${YELLOW}Test 1: SQL Injection${NC}"
    local resp
    resp=$(curl -s -o /dev/null -w "%{http_code}" "${test_url}/?id=1' OR '1'='1" 2>/dev/null)
    if [[ "$resp" == "403" ]]; then
        echo -e "  ${GREEN}[BLOQUEADO] HTTP $resp - SQLi detectado y bloqueado${NC}"
    else
        echo -e "  ${RED}[NO BLOQUEADO] HTTP $resp - SQLi no fue bloqueado${NC}"
    fi

    # Test 2: XSS
    echo -e "${YELLOW}Test 2: XSS${NC}"
    resp=$(curl -s -o /dev/null -w "%{http_code}" "${test_url}/?q=<script>alert(1)</script>" 2>/dev/null)
    if [[ "$resp" == "403" ]]; then
        echo -e "  ${GREEN}[BLOQUEADO] HTTP $resp - XSS detectado y bloqueado${NC}"
    else
        echo -e "  ${RED}[NO BLOQUEADO] HTTP $resp - XSS no fue bloqueado${NC}"
    fi

    # Test 3: Path traversal
    echo -e "${YELLOW}Test 3: Path Traversal${NC}"
    resp=$(curl -s -o /dev/null -w "%{http_code}" "${test_url}/../../etc/passwd" 2>/dev/null)
    if [[ "$resp" == "403" ]]; then
        echo -e "  ${GREEN}[BLOQUEADO] HTTP $resp - Path traversal bloqueado${NC}"
    else
        echo -e "  ${RED}[NO BLOQUEADO] HTTP $resp - Path traversal no fue bloqueado${NC}"
    fi

    # Test 4: Agente malicioso
    echo -e "${YELLOW}Test 4: User-Agent malicioso (sqlmap)${NC}"
    resp=$(curl -s -o /dev/null -w "%{http_code}" -A "sqlmap/1.0" "${test_url}/" 2>/dev/null)
    if [[ "$resp" == "403" ]]; then
        echo -e "  ${GREEN}[BLOQUEADO] HTTP $resp - User-Agent bloqueado${NC}"
    else
        echo -e "  ${RED}[NO BLOQUEADO] HTTP $resp - User-Agent no fue bloqueado${NC}"
    fi
}

cmd_update_rules() {
    check_root
    local CRS_VERSION="4.0.0"
    local CRS_URL="https://github.com/coreruleset/coreruleset/archive/refs/tags/v${CRS_VERSION}.tar.gz"
    local CRS_TMP="/tmp/crs-update-${CRS_VERSION}.tar.gz"

    echo -e "${CYAN}Actualizando OWASP CRS v${CRS_VERSION}...${NC}"

    if curl -sL -o "$CRS_TMP" "$CRS_URL" 2>/dev/null; then
        # Backup de reglas actuales
        if [[ -d "$MODSEC_CRS_DIR/rules" ]]; then
            cp -a "$MODSEC_CRS_DIR/rules" "$MODSEC_CRS_DIR/rules.backup.$(date +%Y%m%d)" 2>/dev/null || true
        fi
        tar xzf "$CRS_TMP" -C /tmp/ 2>/dev/null || true
        if [[ -d "/tmp/coreruleset-${CRS_VERSION}" ]]; then
            cp -a "/tmp/coreruleset-${CRS_VERSION}/rules" "$MODSEC_CRS_DIR/"
            rm -rf "/tmp/coreruleset-${CRS_VERSION}" "$CRS_TMP"
            echo -e "${GREEN}[+] OWASP CRS actualizado a v${CRS_VERSION}${NC}"
            echo -e "${YELLOW}[!] Reiniciar servidor web para aplicar${NC}"
        else
            echo -e "${RED}[X] Error extrayendo CRS${NC}"
        fi
    else
        echo -e "${RED}[X] Error descargando CRS${NC}"
    fi
}

cmd_audit_log() {
    local audit_log="/var/log/modsecurity/modsec_audit.log"
    local lines="${1:-50}"

    if [[ -f "$audit_log" ]]; then
        echo -e "${CYAN}Ultimas $lines entradas del audit log:${NC}"
        echo ""
        tail -n "$lines" "$audit_log"
    else
        echo -e "${YELLOW}[!] Audit log no encontrado: $audit_log${NC}"
    fi
}

case "${1:-}" in
    enable)       cmd_enable ;;
    disable)      cmd_disable ;;
    detect-only)  cmd_detect_only ;;
    status)       cmd_status ;;
    test)         cmd_test "${2:-http://localhost}" ;;
    update-rules) cmd_update_rules ;;
    audit-log)    cmd_audit_log "${2:-50}" ;;
    *)            usage ;;
esac
EOFSCRIPT
    chmod +x /usr/local/bin/gestionar-modsecurity.sh
    log_change "Creado" "/usr/local/bin/gestionar-modsecurity.sh"

    log_info "ModSecurity WAF configurado"
    log_info "Gestion: gestionar-modsecurity.sh {enable|disable|status|test|update-rules}"
else
    log_skip "ModSecurity WAF"
fi

# ============================================================
# S5: OPTIMIZACION TLS/SSL
# ============================================================
log_section "S5: OPTIMIZACION TLS/SSL"

echo "Optimiza y verifica la configuracion TLS/SSL:"
echo "  - Generacion de DH params 4096-bit"
echo "  - TLS 1.2 + 1.3 exclusivamente"
echo "  - Suite de cifrado robusta (ECDHE+AESGCM, CHACHA20)"
echo "  - OCSP stapling"
echo "  - Rotacion de session tickets"
echo "  - Script verificador de TLS"
echo ""

if check_executable /usr/local/bin/verificar-tls-web.sh; then
    log_already "Optimizacion TLS/SSL (verificador ya instalado)"
elif ask "¿Optimizar y verificar TLS/SSL?"; then

    mkdir -p /etc/securizar/tls

    # DH params global (si no se genero en S1)
    DH_GLOBAL="/etc/securizar/tls/dhparam-4096.pem"
    if [[ ! -f "$DH_GLOBAL" ]]; then
        if [[ -f "${NGINX_CONF_DIR:-/nonexistent}/dhparam.pem" ]]; then
            cp "${NGINX_CONF_DIR}/dhparam.pem" "$DH_GLOBAL"
            log_info "DH params copiados desde nginx"
        else
            log_info "Generando DH params 4096-bit globales (puede tardar)..."
            openssl dhparam -out "$DH_GLOBAL" 4096 2>/dev/null
            log_change "Generado" "DH params 4096-bit: $DH_GLOBAL"
        fi
        chmod 600 "$DH_GLOBAL"
    else
        log_info "DH params globales ya existen: $DH_GLOBAL"
    fi

    # Documentar configuracion TLS recomendada
    cat > /etc/securizar/tls/tls-web-policy.conf << 'EOF'
# ============================================================
# tls-web-policy.conf - Politica TLS para servidores web
# Generado por securizar - Modulo 50
# ============================================================

# Protocolos permitidos
TLS_MIN_VERSION=1.2
TLS_MAX_VERSION=1.3

# Cifrados (orden de preferencia)
CIPHERS_TLS12="ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
CIPHERSUITES_TLS13="TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"

# Curvas ECDH
ECDH_CURVES="X25519:secp384r1:secp256r1"

# OCSP Stapling
OCSP_STAPLING=on

# Session tickets
SESSION_TICKETS=off
SESSION_TIMEOUT=1d

# HSTS
HSTS_MAX_AGE=31536000
HSTS_INCLUDE_SUBDOMAINS=true
HSTS_PRELOAD=true
EOF
    log_change "Creado" "/etc/securizar/tls/tls-web-policy.conf"

    # Script verificador de TLS
    cat > /usr/local/bin/verificar-tls-web.sh << 'EOFSCRIPT'
#!/bin/bash
# ============================================================
# verificar-tls-web.sh
# Verifica configuracion TLS de servidores web
# Generado por securizar - Modulo 50
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

HOST="${1:-localhost}"
PORT="${2:-443}"
ERRORES=0
CORRECTOS=0

echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "${CYAN}  VERIFICACION TLS - ${HOST}:${PORT}${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo ""

# Verificar conectividad
if ! timeout 5 bash -c "echo >/dev/tcp/${HOST}/${PORT}" 2>/dev/null; then
    echo -e "${RED}[X] No se puede conectar a ${HOST}:${PORT}${NC}"
    exit 1
fi

# ── Test 1: Protocolos ───────────────────────────────────
echo -e "${BOLD}Protocolos TLS:${NC}"

for proto in ssl3 tls1 tls1_1 tls1_2 tls1_3; do
    result=$(echo | timeout 5 openssl s_client -connect "${HOST}:${PORT}" -"${proto}" 2>/dev/null)
    if echo "$result" | grep -q "CONNECTED"; then
        case "$proto" in
            ssl3|tls1|tls1_1)
                echo -e "  ${RED}[INSEGURO] ${proto} habilitado${NC}"
                ((ERRORES++)) || true
                ;;
            tls1_2|tls1_3)
                echo -e "  ${GREEN}[OK] ${proto} habilitado${NC}"
                ((CORRECTOS++)) || true
                ;;
        esac
    else
        case "$proto" in
            ssl3|tls1|tls1_1)
                echo -e "  ${GREEN}[OK] ${proto} deshabilitado${NC}"
                ((CORRECTOS++)) || true
                ;;
            tls1_2|tls1_3)
                echo -e "  ${YELLOW}[!] ${proto} no disponible${NC}"
                ;;
        esac
    fi
done
echo ""

# ── Test 2: Certificado ──────────────────────────────────
echo -e "${BOLD}Certificado:${NC}"

cert_info=$(echo | timeout 5 openssl s_client -connect "${HOST}:${PORT}" -servername "${HOST}" 2>/dev/null)
if [[ -n "$cert_info" ]]; then
    # Fecha de expiracion
    not_after=$(echo "$cert_info" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
    if [[ -n "$not_after" ]]; then
        exp_epoch=$(date -d "$not_after" +%s 2>/dev/null || echo 0)
        now_epoch=$(date +%s)
        days_left=$(( (exp_epoch - now_epoch) / 86400 ))

        if [[ $days_left -lt 0 ]]; then
            echo -e "  ${RED}[EXPIRADO] Certificado expirado hace $((-days_left)) dias${NC}"
            ((ERRORES++)) || true
        elif [[ $days_left -lt 30 ]]; then
            echo -e "  ${YELLOW}[!] Certificado expira en $days_left dias ($not_after)${NC}"
            ((ERRORES++)) || true
        else
            echo -e "  ${GREEN}[OK] Certificado valido por $days_left dias ($not_after)${NC}"
            ((CORRECTOS++)) || true
        fi
    fi

    # Subject y SANs
    subject=$(echo "$cert_info" | openssl x509 -noout -subject 2>/dev/null | sed 's/subject=//')
    echo -e "  Subject: ${subject:-desconocido}"

    sans=$(echo "$cert_info" | openssl x509 -noout -ext subjectAltName 2>/dev/null | grep -v "X509v3" | xargs 2>/dev/null)
    if [[ -n "$sans" ]]; then
        echo -e "  SANs: $sans"
    fi

    # Tamano de clave
    key_size=$(echo "$cert_info" | openssl x509 -noout -text 2>/dev/null | grep "Public-Key:" | grep -oP '\d+')
    if [[ -n "$key_size" ]]; then
        if [[ "$key_size" -ge 2048 ]]; then
            echo -e "  ${GREEN}[OK] Clave: ${key_size} bits${NC}"
            ((CORRECTOS++)) || true
        else
            echo -e "  ${RED}[DEBIL] Clave: ${key_size} bits (minimo 2048)${NC}"
            ((ERRORES++)) || true
        fi
    fi

    # Cadena de certificados
    chain_depth=$(echo "$cert_info" | grep -c "^ [0-9]" 2>/dev/null || echo 0)
    verify_result=$(echo "$cert_info" | grep "Verify return code:" | head -1)
    if echo "$verify_result" | grep -q "0 (ok)"; then
        echo -e "  ${GREEN}[OK] Cadena de certificados verificada${NC}"
        ((CORRECTOS++)) || true
    else
        echo -e "  ${YELLOW}[!] Verificacion de cadena: $verify_result${NC}"
        ((ERRORES++)) || true
    fi
fi
echo ""

# ── Test 3: Cifrados ─────────────────────────────────────
echo -e "${BOLD}Cifrados negociados:${NC}"

cipher=$(echo | timeout 5 openssl s_client -connect "${HOST}:${PORT}" -servername "${HOST}" 2>/dev/null | grep "Cipher    :" | awk '{print $NF}')
if [[ -n "$cipher" && "$cipher" != "0000" ]]; then
    echo -e "  Cifrado actual: ${BOLD}$cipher${NC}"
    case "$cipher" in
        *GCM*|*CHACHA20*)
            echo -e "  ${GREEN}[OK] Cifrado AEAD${NC}"
            ((CORRECTOS++)) || true
            ;;
        *CBC*)
            echo -e "  ${YELLOW}[!] Cifrado CBC (prefiere AEAD)${NC}"
            ((ERRORES++)) || true
            ;;
        *)
            echo -e "  ${YELLOW}[?] Tipo de cifrado desconocido${NC}"
            ;;
    esac
fi

# Verificar cifrados debiles
WEAK_CIPHERS=("RC4" "DES" "3DES" "NULL" "EXPORT" "MD5")
for weak in "${WEAK_CIPHERS[@]}"; do
    if echo | timeout 5 openssl s_client -connect "${HOST}:${PORT}" -cipher "$weak" 2>/dev/null | grep -q "CONNECTED"; then
        echo -e "  ${RED}[INSEGURO] Cifrado debil aceptado: $weak${NC}"
        ((ERRORES++)) || true
    fi
done
echo ""

# ── Test 4: OCSP Stapling ────────────────────────────────
echo -e "${BOLD}OCSP Stapling:${NC}"
ocsp=$(echo | timeout 5 openssl s_client -connect "${HOST}:${PORT}" -servername "${HOST}" -status 2>/dev/null | grep -A2 "OCSP response:")
if echo "$ocsp" | grep -qi "no response"; then
    echo -e "  ${YELLOW}[!] OCSP stapling no activo${NC}"
    ((ERRORES++)) || true
elif [[ -n "$ocsp" ]]; then
    echo -e "  ${GREEN}[OK] OCSP stapling activo${NC}"
    ((CORRECTOS++)) || true
else
    echo -e "  ${YELLOW}[?] No se pudo verificar OCSP stapling${NC}"
fi
echo ""

# ── Test 5: DH Params ────────────────────────────────────
echo -e "${BOLD}Diffie-Hellman:${NC}"
dh_info=$(echo | timeout 5 openssl s_client -connect "${HOST}:${PORT}" -servername "${HOST}" 2>/dev/null | grep "Server Temp Key:")
if [[ -n "$dh_info" ]]; then
    echo -e "  $dh_info"
    dh_bits=$(echo "$dh_info" | grep -oP '\d+' | tail -1)
    if [[ -n "$dh_bits" && "$dh_bits" -ge 2048 ]]; then
        echo -e "  ${GREEN}[OK] DH params ${dh_bits} bits${NC}"
        ((CORRECTOS++)) || true
    elif [[ -n "$dh_bits" ]]; then
        echo -e "  ${RED}[DEBIL] DH params ${dh_bits} bits (minimo 2048)${NC}"
        ((ERRORES++)) || true
    fi
fi
echo ""

# ── Resumen ──────────────────────────────────────────────
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "${CYAN}  RESUMEN TLS${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "  ${GREEN}Correctos: $CORRECTOS${NC}"
echo -e "  ${RED}Problemas: $ERRORES${NC}"

if [[ $ERRORES -eq 0 ]]; then
    echo -e "\n${GREEN}[+] Configuracion TLS BUENA${NC}"
elif [[ $ERRORES -le 2 ]]; then
    echo -e "\n${YELLOW}[!] Configuracion TLS MEJORABLE${NC}"
else
    echo -e "\n${RED}[X] Configuracion TLS DEFICIENTE${NC}"
fi

exit $ERRORES
EOFSCRIPT
    chmod +x /usr/local/bin/verificar-tls-web.sh
    log_change "Creado" "/usr/local/bin/verificar-tls-web.sh"

    log_info "Optimizacion TLS/SSL completada"
    log_info "Verificar con: verificar-tls-web.sh <host> [port]"
else
    log_skip "Optimizacion TLS/SSL"
fi

# ============================================================
# S6: RATE LIMITING Y PROTECCION DDoS
# ============================================================
log_section "S6: RATE LIMITING Y PROTECCION DDoS"

echo "Configura proteccion contra rate limiting y DDoS:"
echo "  - nginx: limit_req_zone, limit_conn_zone con burst"
echo "  - Apache: mod_ratelimit, mod_evasive"
echo "  - Limites de conexion por IP"
echo "  - Proteccion contra Slowloris (timeouts)"
echo "  - Proteccion SYN flood (sysctl)"
echo "  - Script detector de DDoS"
echo ""

if check_executable /usr/local/bin/detectar-ddos-web.sh; then
    log_already "Rate limiting y proteccion DDoS (script ya instalado)"
elif ask "¿Configurar rate limiting y proteccion DDoS?"; then

    mkdir -p /etc/securizar

    # Configuracion centralizada de rate limits
    cat > /etc/securizar/rate-limits.conf << 'EOF'
# ============================================================
# rate-limits.conf - Limites de rate para servidores web
# Generado por securizar - Modulo 50
# ============================================================

# Conexiones maximas por IP
MAX_CONN_PER_IP=20

# Peticiones por segundo (general)
RATE_GENERAL=10
RATE_GENERAL_BURST=20

# Peticiones por segundo (login/auth)
RATE_LOGIN=3
RATE_LOGIN_BURST=5

# Peticiones por segundo (API)
RATE_API=30
RATE_API_BURST=50

# Peticiones por segundo (assets estaticos)
RATE_STATIC=50
RATE_STATIC_BURST=100

# Tamano maximo de body (bytes)
MAX_BODY_SIZE=10485760

# Timeout de conexion (segundos)
CONN_TIMEOUT=60
KEEPALIVE_TIMEOUT=15

# Umbral de deteccion DDoS (peticiones/minuto por IP)
DDOS_THRESHOLD=300

# Umbral de deteccion Slowloris (conexiones simultaneas por IP)
SLOWLORIS_THRESHOLD=50
EOF
    log_change "Creado" "/etc/securizar/rate-limits.conf"

    # Rate limiting para nginx (snippet adicional)
    if [[ "$NGINX_INSTALLED" == true ]]; then
        cat > "$NGINX_CONF_DIR/snippets/securizar-rate-limit.conf" << 'EOF'
# ============================================================
# securizar-rate-limit.conf - Rate limiting para nginx
# Incluir dentro de bloques location { }
# Generado por securizar - Modulo 50
# ============================================================

# Rate limiting general (aplicar en location /)
# limit_req zone=general burst=20 nodelay;

# Rate limiting para login (aplicar en location /login)
# limit_req zone=login burst=5 nodelay;

# Rate limiting para API (aplicar en location /api)
# limit_req zone=api burst=50 nodelay;

# Respuesta cuando se excede el limite
# limit_req_status 429;
# limit_conn_status 429;

# Pagina personalizada para 429
# error_page 429 /429.html;
EOF
        log_change "Creado" "$NGINX_CONF_DIR/snippets/securizar-rate-limit.conf"
    fi

    # mod_evasive para Apache
    if [[ "$APACHE_INSTALLED" == true ]]; then
        case "$DISTRO_FAMILY" in
            debian)
                pkg_install libapache2-mod-evasive || log_warn "No se pudo instalar mod_evasive"
                if command -v a2enmod &>/dev/null; then
                    a2enmod evasive 2>/dev/null || true
                fi
                EVASIVE_CONF="$APACHE_CONF_DIR/conf-available/securizar-evasive.conf"
                ;;
            rhel)
                pkg_install mod_evasive || log_warn "No se pudo instalar mod_evasive"
                EVASIVE_CONF="$APACHE_CONF_DIR/conf.d/securizar-evasive.conf"
                ;;
            suse)
                pkg_install apache2-mod_evasive || log_warn "No se pudo instalar mod_evasive"
                EVASIVE_CONF="$APACHE_CONF_DIR/conf.d/securizar-evasive.conf"
                ;;
            *)
                EVASIVE_CONF="$APACHE_CONF_DIR/conf.d/securizar-evasive.conf"
                ;;
        esac

        mkdir -p "$(dirname "$EVASIVE_CONF")"
        cat > "$EVASIVE_CONF" << 'EOF'
# ============================================================
# securizar-evasive.conf - mod_evasive para Apache
# Generado por securizar - Modulo 50
# ============================================================

<IfModule mod_evasive24.c>
    DOSHashTableSize    3097
    DOSPageCount        5
    DOSSiteCount        50
    DOSPageInterval     1
    DOSSiteInterval     1
    DOSBlockingPeriod   60
    DOSLogDir           /var/log/mod_evasive
    # DOSEmailNotify    admin@ejemplo.com
    # DOSSystemCommand  "/usr/local/bin/bloquear-ip.sh %s"
</IfModule>

<IfModule mod_evasive20.c>
    DOSHashTableSize    3097
    DOSPageCount        5
    DOSSiteCount        50
    DOSPageInterval     1
    DOSSiteInterval     1
    DOSBlockingPeriod   60
    DOSLogDir           /var/log/mod_evasive
</IfModule>
EOF
        mkdir -p /var/log/mod_evasive
        chmod 750 /var/log/mod_evasive
        log_change "Creado" "$EVASIVE_CONF"

        if [[ "$DISTRO_FAMILY" == "debian" ]] && command -v a2enconf &>/dev/null; then
            a2enconf securizar-evasive 2>/dev/null || true
        fi
    fi

    # Proteccion SYN flood via sysctl
    SYSCTL_WEB="/etc/sysctl.d/90-securizar-web-ddos.conf"
    cat > "$SYSCTL_WEB" << 'EOF'
# ============================================================
# 90-securizar-web-ddos.conf - Proteccion DDoS via sysctl
# Generado por securizar - Modulo 50
# ============================================================

# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 3

# Limitar conexiones TIME_WAIT
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1

# Detectar conexiones muertas mas rapido
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5

# Limitar backlog de conexiones
net.core.somaxconn = 4096
net.core.netdev_max_backlog = 4096

# Proteccion contra spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# No responder a broadcasts ICMP (Smurf)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignorar ICMP redirect
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
EOF
    sysctl -p "$SYSCTL_WEB" 2>/dev/null || true
    log_change "Creado" "$SYSCTL_WEB"
    log_change "Aplicado" "sysctl anti-DDoS"

    # Script detector de DDoS
    cat > /usr/local/bin/detectar-ddos-web.sh << 'EOFSCRIPT'
#!/bin/bash
# ============================================================
# detectar-ddos-web.sh
# Detecta posibles ataques DDoS en servidores web
# Generado por securizar - Modulo 50
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Cargar configuracion
CONF="/etc/securizar/rate-limits.conf"
if [[ -f "$CONF" ]]; then
    # shellcheck source=/dev/null
    source "$CONF"
fi
DDOS_THRESHOLD="${DDOS_THRESHOLD:-300}"
SLOWLORIS_THRESHOLD="${SLOWLORIS_THRESHOLD:-50}"

echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "${CYAN}  DETECCION DE DDoS EN SERVIDORES WEB${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo ""

# ── 1. Conexiones activas por IP ────────────────────────
echo -e "${BOLD}Conexiones activas por IP (top 20):${NC}"
echo ""
ss -tn state established 2>/dev/null | awk '{print $5}' | \
    grep -oP '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -rn | head -20 | \
    while read -r count ip; do
        if [[ "$count" -ge "$SLOWLORIS_THRESHOLD" ]]; then
            echo -e "  ${RED}[ALERTA] $ip - $count conexiones (umbral: $SLOWLORIS_THRESHOLD)${NC}"
        elif [[ "$count" -ge $((SLOWLORIS_THRESHOLD / 2)) ]]; then
            echo -e "  ${YELLOW}[AVISO] $ip - $count conexiones${NC}"
        else
            echo -e "  ${GREEN}$ip - $count conexiones${NC}"
        fi
    done
echo ""

# ── 2. Conexiones SYN_RECV (posible SYN flood) ─────────
echo -e "${BOLD}Conexiones SYN_RECV (posible SYN flood):${NC}"
syn_count=$(ss -tn state syn-recv 2>/dev/null | wc -l)
if [[ "$syn_count" -gt 100 ]]; then
    echo -e "  ${RED}[ALERTA] $syn_count conexiones SYN_RECV${NC}"
elif [[ "$syn_count" -gt 20 ]]; then
    echo -e "  ${YELLOW}[AVISO] $syn_count conexiones SYN_RECV${NC}"
else
    echo -e "  ${GREEN}$syn_count conexiones SYN_RECV (normal)${NC}"
fi

ss -tn state syn-recv 2>/dev/null | awk '{print $5}' | \
    grep -oP '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -rn | head -10 | \
    while read -r count ip; do
        echo -e "  $ip - $count SYN_RECV"
    done
echo ""

# ── 3. Conexiones TIME_WAIT ─────────────────────────────
echo -e "${BOLD}Conexiones TIME_WAIT:${NC}"
tw_count=$(ss -tn state time-wait 2>/dev/null | wc -l)
if [[ "$tw_count" -gt 1000 ]]; then
    echo -e "  ${YELLOW}[AVISO] $tw_count conexiones TIME_WAIT (alto)${NC}"
else
    echo -e "  ${GREEN}$tw_count conexiones TIME_WAIT${NC}"
fi
echo ""

# ── 4. Peticiones recientes en logs ─────────────────────
echo -e "${BOLD}IPs con mas peticiones (ultimo minuto):${NC}"

for log_file in /var/log/nginx/access.log /var/log/apache2/access.log /var/log/httpd/access_log; do
    if [[ -f "$log_file" ]]; then
        echo -e "  ${CYAN}Analizando: $log_file${NC}"
        current_min=$(date '+%d/%b/%Y:%H:%M')
        grep "$current_min" "$log_file" 2>/dev/null | \
            awk '{print $1}' | sort | uniq -c | sort -rn | head -10 | \
            while read -r count ip; do
                if [[ "$count" -ge "$DDOS_THRESHOLD" ]]; then
                    echo -e "  ${RED}[ALERTA] $ip - $count peticiones/min (umbral: $DDOS_THRESHOLD)${NC}"
                elif [[ "$count" -ge $((DDOS_THRESHOLD / 2)) ]]; then
                    echo -e "  ${YELLOW}[AVISO] $ip - $count peticiones/min${NC}"
                else
                    echo -e "  $ip - $count peticiones/min"
                fi
            done
    fi
done
echo ""

# ── 5. Puertos web en escucha ───────────────────────────
echo -e "${BOLD}Puertos web activos:${NC}"
ss -tlnp 2>/dev/null | grep -E ':80|:443|:8080|:8443' | while read -r line; do
    echo -e "  $line"
done
echo ""

# ── 6. Carga del sistema ────────────────────────────────
echo -e "${BOLD}Carga del sistema:${NC}"
load=$(uptime | awk -F'load average:' '{print $2}' | xargs)
echo -e "  Load average: $load"
echo -e "  Memoria:"
free -h | head -2 | tail -1 | awk '{printf "    Total: %s  Usado: %s  Libre: %s\n", $2, $3, $4}'
echo ""

# ── 7. Resumen ──────────────────────────────────────────
total_conns=$(ss -tn state established 2>/dev/null | wc -l)
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "${CYAN}  RESUMEN${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "  Conexiones establecidas: $total_conns"
echo -e "  SYN_RECV: $syn_count"
echo -e "  TIME_WAIT: $tw_count"
echo -e "  Load: $load"

if [[ "$syn_count" -gt 100 || "$total_conns" -gt 5000 ]]; then
    echo -e "\n${RED}[!!!] POSIBLE ATAQUE DDoS EN CURSO${NC}"
    echo -e "${YELLOW}Acciones sugeridas:${NC}"
    echo -e "  1. Identificar IPs atacantes con: ss -tn | awk '{print \$5}' | sort | uniq -c | sort -rn | head"
    echo -e "  2. Bloquear IP: iptables -A INPUT -s <IP> -j DROP"
    echo -e "  3. Activar rate limiting adicional"
    echo -e "  4. Contactar proveedor de hosting/CDN"
fi
EOFSCRIPT
    chmod +x /usr/local/bin/detectar-ddos-web.sh
    log_change "Creado" "/usr/local/bin/detectar-ddos-web.sh"

    log_info "Rate limiting y proteccion DDoS configurados"
    log_info "Detector: detectar-ddos-web.sh"
else
    log_skip "Rate limiting y proteccion DDoS"
fi

# ============================================================
# S7: REGLAS WAF PERSONALIZADAS
# ============================================================
log_section "S7: REGLAS WAF PERSONALIZADAS"

echo "Configura reglas WAF personalizadas adicionales a OWASP CRS:"
echo "  - Bloquear user-agents maliciosos (sqlmap, nikto, dirbuster)"
echo "  - Bloquear acceso directo por IP (requerir Host header)"
echo "  - Bloquear rutas de exploits comunes (.env, .git, wp-admin...)"
echo "  - Plantilla de restricciones geograficas"
echo ""

if check_dir_exists /etc/securizar/waf-custom-rules; then
    log_already "Reglas WAF personalizadas (directorio ya existe)"
elif ask "¿Configurar reglas WAF personalizadas?"; then

    WAF_RULES_DIR="/etc/securizar/waf-custom-rules"
    mkdir -p "$WAF_RULES_DIR"

    # Regla: Bloquear user-agents maliciosos
    cat > "$WAF_RULES_DIR/01-bad-user-agents.conf" << 'EOF'
# ============================================================
# 01-bad-user-agents.conf - Bloquear user-agents maliciosos
# Generado por securizar - Modulo 50
# ============================================================

# Herramientas de escaneo y ataque
SecRule REQUEST_HEADERS:User-Agent "@rx (?i)(sqlmap|nikto|dirbuster|nessus|nmap|masscan|wpscan|acunetix|burpsuite|havij|w3af|skipfish|arachni|openvas|gobuster|ffuf|feroxbuster|nuclei)" \
    "id:100001,phase:1,deny,status:403,log,msg:'User-Agent malicioso bloqueado: %{MATCHED_VAR}',tag:'securizar/bad-ua'"

# Bots genericos maliciosos
SecRule REQUEST_HEADERS:User-Agent "@rx (?i)(bot.*crawl|crawl.*bot|spider.*bot|scan.*http|http.*scan)" \
    "id:100002,phase:1,deny,status:403,log,msg:'Bot sospechoso bloqueado: %{MATCHED_VAR}',tag:'securizar/bad-ua'"

# User-Agent vacio o sospechoso
SecRule REQUEST_HEADERS:User-Agent "@rx ^$" \
    "id:100003,phase:1,deny,status:403,log,msg:'User-Agent vacio',tag:'securizar/bad-ua'"

# Herramientas de fuerza bruta
SecRule REQUEST_HEADERS:User-Agent "@rx (?i)(hydra|medusa|patator|hashcat)" \
    "id:100004,phase:1,deny,status:403,log,msg:'Herramienta de fuerza bruta: %{MATCHED_VAR}',tag:'securizar/bad-ua'"
EOF
    log_change "Creado" "$WAF_RULES_DIR/01-bad-user-agents.conf"

    # Regla: Bloquear acceso directo por IP
    cat > "$WAF_RULES_DIR/02-require-host-header.conf" << 'EOF'
# ============================================================
# 02-require-host-header.conf - Requerir header Host valido
# Generado por securizar - Modulo 50
# ============================================================

# Bloquear peticiones sin header Host
SecRule &REQUEST_HEADERS:Host "@eq 0" \
    "id:100010,phase:1,deny,status:403,log,msg:'Peticion sin header Host',tag:'securizar/no-host'"

# Bloquear acceso directo por IP (sin dominio)
# NOTA: Ajustar el patron segun los dominios permitidos
# SecRule REQUEST_HEADERS:Host "@rx ^\d+\.\d+\.\d+\.\d+" \
#     "id:100011,phase:1,deny,status:403,log,msg:'Acceso directo por IP bloqueado',tag:'securizar/direct-ip'"
EOF
    log_change "Creado" "$WAF_RULES_DIR/02-require-host-header.conf"

    # Regla: Bloquear rutas de exploits comunes
    cat > "$WAF_RULES_DIR/03-block-exploit-paths.conf" << 'EOF'
# ============================================================
# 03-block-exploit-paths.conf - Bloquear rutas peligrosas
# Generado por securizar - Modulo 50
# ============================================================

# WordPress admin y rutas de login
SecRule REQUEST_URI "@rx (?i)/(wp-admin|wp-login\.php|wp-config\.php|xmlrpc\.php)" \
    "id:100020,phase:1,deny,status:403,log,msg:'Acceso a ruta WordPress bloqueado: %{REQUEST_URI}',tag:'securizar/exploit-path'"

# phpMyAdmin y herramientas de administracion
SecRule REQUEST_URI "@rx (?i)/(phpmyadmin|pma|myadmin|phpminiadmin|adminer|dbadmin)" \
    "id:100021,phase:1,deny,status:403,log,msg:'Acceso a herramienta de DB bloqueado: %{REQUEST_URI}',tag:'securizar/exploit-path'"

# Archivos de configuracion expuestos
SecRule REQUEST_URI "@rx (?i)/(\.(env|git|svn|hg|htaccess|htpasswd|DS_Store|config)|web\.config|config\.php|settings\.php)" \
    "id:100022,phase:1,deny,status:403,log,msg:'Acceso a archivo de config bloqueado: %{REQUEST_URI}',tag:'securizar/exploit-path'"

# Archivos de backup
SecRule REQUEST_URI "@rx (?i)\.(bak|backup|old|orig|save|swp|tmp|temp|sql|dump|tar\.gz|zip)$" \
    "id:100023,phase:1,deny,status:403,log,msg:'Acceso a archivo de backup bloqueado: %{REQUEST_URI}',tag:'securizar/exploit-path'"

# Directorios de control de versiones
SecRule REQUEST_URI "@rx (?i)/\.(git|svn|hg|bzr)/" \
    "id:100024,phase:1,deny,status:403,log,msg:'Acceso a directorio VCS bloqueado: %{REQUEST_URI}',tag:'securizar/exploit-path'"

# Shell uploads y webshells
SecRule REQUEST_URI "@rx (?i)/(shell|cmd|c99|r57|b374k|wso|alfa|mini-shell|webshell)" \
    "id:100025,phase:1,deny,status:403,log,msg:'Posible acceso a webshell: %{REQUEST_URI}',tag:'securizar/exploit-path'"

# Rutas de informacion del servidor
SecRule REQUEST_URI "@rx (?i)/(server-status|server-info|phpinfo\.php|info\.php|test\.php)" \
    "id:100026,phase:1,deny,status:403,log,msg:'Acceso a info del servidor bloqueado: %{REQUEST_URI}',tag:'securizar/exploit-path'"
EOF
    log_change "Creado" "$WAF_RULES_DIR/03-block-exploit-paths.conf"

    # Plantilla de restricciones geograficas
    cat > "$WAF_RULES_DIR/04-geo-restrictions.conf.template" << 'EOF'
# ============================================================
# 04-geo-restrictions.conf.template - Restricciones geograficas
# PLANTILLA - Renombrar a .conf y ajustar para activar
# Generado por securizar - Modulo 50
# ============================================================
# Requiere: mod_geoip o mod_maxminddb para Apache
#           ngx_http_geoip2_module para nginx
#
# Ejemplo para ModSecurity con GeoIP:
#
# # Bloquear paises especificos (codigos ISO)
# SecGeoLookupDb /usr/share/GeoIP/GeoLite2-Country.mmdb
#
# SecRule REMOTE_ADDR "@geoLookup" \
#     "id:100030,phase:1,pass,nolog"
#
# SecRule GEO:COUNTRY_CODE "@pm CN RU KP" \
#     "id:100031,phase:1,deny,status:403,log,\
#      msg:'Acceso desde pais bloqueado: %{GEO.COUNTRY_CODE}',\
#      tag:'securizar/geo-block'"
#
# # Permitir solo paises especificos
# SecRule GEO:COUNTRY_CODE "!@pm ES US GB DE FR PT" \
#     "id:100032,phase:1,deny,status:403,log,\
#      msg:'Acceso desde pais no permitido: %{GEO.COUNTRY_CODE}',\
#      tag:'securizar/geo-allow'"
EOF
    log_change "Creado" "$WAF_RULES_DIR/04-geo-restrictions.conf.template"

    # Configuracion nginx para rutas bloqueadas
    if [[ "$NGINX_INSTALLED" == true ]]; then
        cat > "$NGINX_CONF_DIR/snippets/securizar-block-paths.conf" << 'EOF'
# ============================================================
# securizar-block-paths.conf - Bloquear rutas peligrosas
# Incluir dentro de bloques server { }
# Generado por securizar - Modulo 50
# ============================================================

# Bloquear archivos ocultos
location ~ /\. {
    deny all;
    access_log off;
    log_not_found off;
    return 404;
}

# Bloquear rutas WordPress (si no se usa)
location ~* ^/(wp-admin|wp-login\.php|wp-config\.php|xmlrpc\.php) {
    deny all;
    return 403;
}

# Bloquear phpMyAdmin
location ~* ^/(phpmyadmin|pma|myadmin|adminer) {
    deny all;
    return 403;
}

# Bloquear archivos de backup
location ~* \.(bak|backup|old|orig|save|swp|sql|dump)$ {
    deny all;
    return 403;
}

# Bloquear archivos de configuracion
location ~* ^/(\.env|web\.config|config\.php|settings\.php) {
    deny all;
    return 403;
}

# Bloquear info del servidor
location ~* ^/(server-status|server-info|phpinfo\.php|info\.php|test\.php) {
    deny all;
    return 403;
}
EOF
        log_change "Creado" "$NGINX_CONF_DIR/snippets/securizar-block-paths.conf"
    fi

    # Configuracion Apache para rutas bloqueadas
    if [[ "$APACHE_INSTALLED" == true ]]; then
        if [[ "$DISTRO_FAMILY" == "debian" ]]; then
            BLOCK_PATHS_CONF="$APACHE_CONF_DIR/conf-available/securizar-block-paths.conf"
        else
            BLOCK_PATHS_CONF="$APACHE_CONF_DIR/conf.d/securizar-block-paths.conf"
        fi

        cat > "$BLOCK_PATHS_CONF" << 'EOF'
# ============================================================
# securizar-block-paths.conf - Bloquear rutas peligrosas
# Generado por securizar - Modulo 50
# ============================================================

# Bloquear archivos ocultos (.env, .git, etc.)
<DirectoryMatch "^\.|\/\.">
    Require all denied
</DirectoryMatch>

# Bloquear rutas WordPress (si no se usa)
<LocationMatch "^/(wp-admin|wp-login\.php|wp-config\.php|xmlrpc\.php)">
    Require all denied
</LocationMatch>

# Bloquear phpMyAdmin
<LocationMatch "^/(phpmyadmin|pma|myadmin|adminer)">
    Require all denied
</LocationMatch>

# Bloquear archivos de backup
<FilesMatch "\.(bak|backup|old|orig|save|swp|sql|dump)$">
    Require all denied
</FilesMatch>

# Bloquear info del servidor
<LocationMatch "^/(server-status|server-info|phpinfo\.php|info\.php|test\.php)">
    Require all denied
</LocationMatch>
EOF
        log_change "Creado" "$BLOCK_PATHS_CONF"

        if [[ "$DISTRO_FAMILY" == "debian" ]] && command -v a2enconf &>/dev/null; then
            a2enconf securizar-block-paths 2>/dev/null || true
        fi
    fi

    log_info "Reglas WAF personalizadas configuradas en $WAF_RULES_DIR"
else
    log_skip "Reglas WAF personalizadas"
fi

# ============================================================
# S8: CONTROL DE ACCESO Y AUTENTICACION
# ============================================================
log_section "S8: CONTROL DE ACCESO Y AUTENTICACION"

echo "Configura control de acceso y autenticacion web:"
echo "  - HTTP Basic/Digest auth para rutas de admin"
echo "  - Restriccion por IP para endpoints sensibles"
echo "  - Plantilla de autenticacion con certificado cliente"
echo "  - Script de configuracion de acceso"
echo ""

if check_executable /usr/local/bin/configurar-acceso-web.sh; then
    log_already "Control de acceso y autenticacion web (script ya instalado)"
elif ask "¿Configurar control de acceso y autenticacion web?"; then

    mkdir -p /etc/securizar/web-auth

    # Generar archivo htpasswd de ejemplo
    if command -v htpasswd &>/dev/null || command -v openssl &>/dev/null; then
        if [[ ! -f /etc/securizar/web-auth/.htpasswd ]]; then
            # Crear con password aleatorio para admin
            ADMIN_PASS=$(openssl rand -base64 16 2>/dev/null || head -c 16 /dev/urandom | base64)
            if command -v htpasswd &>/dev/null; then
                htpasswd -cb /etc/securizar/web-auth/.htpasswd admin "$ADMIN_PASS" 2>/dev/null
            else
                # Fallback con openssl
                HASH=$(openssl passwd -apr1 "$ADMIN_PASS" 2>/dev/null)
                echo "admin:${HASH}" > /etc/securizar/web-auth/.htpasswd
            fi
            chmod 640 /etc/securizar/web-auth/.htpasswd
            log_change "Creado" "/etc/securizar/web-auth/.htpasswd"
            log_warn "Password de admin generado: $ADMIN_PASS"
            log_warn "CAMBIAR INMEDIATAMENTE con: htpasswd /etc/securizar/web-auth/.htpasswd admin"
        else
            log_info ".htpasswd ya existe"
        fi
    fi

    # Snippet nginx para autenticacion basica
    if [[ "$NGINX_INSTALLED" == true ]]; then
        cat > "$NGINX_CONF_DIR/snippets/securizar-auth-basic.conf" << 'EOF'
# ============================================================
# securizar-auth-basic.conf - Autenticacion basica
# Incluir dentro de location { } que requieran auth
# Generado por securizar - Modulo 50
# ============================================================

auth_basic "Area restringida - Acceso autorizado requerido";
auth_basic_user_file /etc/securizar/web-auth/.htpasswd;
EOF
        log_change "Creado" "$NGINX_CONF_DIR/snippets/securizar-auth-basic.conf"

        # Snippet para restriccion por IP
        cat > "$NGINX_CONF_DIR/snippets/securizar-ip-restrict.conf" << 'EOF'
# ============================================================
# securizar-ip-restrict.conf - Restriccion por IP
# Incluir dentro de location { } que requieran restriccion
# Generado por securizar - Modulo 50
# ============================================================

# Permitir redes locales
allow 127.0.0.1;
allow 10.0.0.0/8;
allow 172.16.0.0/12;
allow 192.168.0.0/16;
# Agregar IPs adicionales permitidas:
# allow X.X.X.X;
deny all;
EOF
        log_change "Creado" "$NGINX_CONF_DIR/snippets/securizar-ip-restrict.conf"

        # Plantilla para autenticacion con certificado cliente
        cat > "$NGINX_CONF_DIR/snippets/securizar-client-cert.conf.template" << 'EOF'
# ============================================================
# securizar-client-cert.conf.template - Autenticacion por certificado
# PLANTILLA - Renombrar a .conf y ajustar para activar
# Generado por securizar - Modulo 50
# ============================================================

# Requiere: CA que firme los certificados de cliente
#
# ssl_client_certificate /etc/securizar/tls/client-ca.pem;
# ssl_verify_client on;
# ssl_verify_depth 2;
#
# # Pasar info del certificado a la aplicacion
# proxy_set_header X-Client-Cert $ssl_client_s_dn;
# proxy_set_header X-Client-Verify $ssl_client_verify;
#
# # Denegar si el certificado no es valido
# if ($ssl_client_verify != SUCCESS) {
#     return 403;
# }
EOF
        log_change "Creado" "$NGINX_CONF_DIR/snippets/securizar-client-cert.conf.template"
    fi

    # Configuracion Apache para autenticacion
    if [[ "$APACHE_INSTALLED" == true ]]; then
        if [[ "$DISTRO_FAMILY" == "debian" ]]; then
            AUTH_CONF="$APACHE_CONF_DIR/conf-available/securizar-auth.conf"
        else
            AUTH_CONF="$APACHE_CONF_DIR/conf.d/securizar-auth.conf"
        fi

        cat > "$AUTH_CONF" << 'EOF'
# ============================================================
# securizar-auth.conf - Autenticacion y control de acceso
# Generado por securizar - Modulo 50
# ============================================================

# Proteger rutas de administracion con Basic Auth
# <Location /admin>
#     AuthType Basic
#     AuthName "Area restringida"
#     AuthUserFile /etc/securizar/web-auth/.htpasswd
#     Require valid-user
# </Location>

# Restringir por IP para endpoints sensibles
# <Location /api/admin>
#     Require ip 127.0.0.1
#     Require ip 10.0.0.0/8
#     Require ip 172.16.0.0/12
#     Require ip 192.168.0.0/16
# </Location>

# Autenticacion por certificado cliente
# <Location /secure>
#     SSLVerifyClient require
#     SSLVerifyDepth 2
#     SSLCACertificateFile /etc/securizar/tls/client-ca.pem
# </Location>
EOF
        log_change "Creado" "$AUTH_CONF"

        if [[ "$DISTRO_FAMILY" == "debian" ]] && command -v a2enconf &>/dev/null; then
            a2enconf securizar-auth 2>/dev/null || true
        fi
    fi

    # Script de configuracion de acceso
    cat > /usr/local/bin/configurar-acceso-web.sh << 'EOFSCRIPT'
#!/bin/bash
# ============================================================
# configurar-acceso-web.sh
# Gestion de acceso y autenticacion web
# Generado por securizar - Modulo 50
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

HTPASSWD_FILE="/etc/securizar/web-auth/.htpasswd"

usage() {
    echo -e "${CYAN}Uso: $0 {add-user|del-user|list-users|check-auth|gen-client-cert}${NC}"
    echo ""
    echo "  add-user <usuario>     - Agregar/actualizar usuario en htpasswd"
    echo "  del-user <usuario>     - Eliminar usuario de htpasswd"
    echo "  list-users             - Listar usuarios en htpasswd"
    echo "  check-auth <url>       - Verificar autenticacion en URL"
    echo "  gen-client-cert <cn>   - Generar certificado de cliente"
    exit 1
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[X] Ejecutar como root${NC}"
        exit 1
    fi
}

cmd_add_user() {
    check_root
    local user="$1"
    if [[ -z "$user" ]]; then
        echo -e "${RED}[X] Especificar nombre de usuario${NC}"
        exit 1
    fi

    mkdir -p "$(dirname "$HTPASSWD_FILE")"

    if command -v htpasswd &>/dev/null; then
        if [[ -f "$HTPASSWD_FILE" ]]; then
            htpasswd "$HTPASSWD_FILE" "$user"
        else
            htpasswd -c "$HTPASSWD_FILE" "$user"
        fi
    else
        echo -n "Password: "
        read -rs password
        echo ""
        local hash
        hash=$(openssl passwd -apr1 "$password" 2>/dev/null)
        if [[ -f "$HTPASSWD_FILE" ]]; then
            # Eliminar entrada existente si la hay
            sed -i "/^${user}:/d" "$HTPASSWD_FILE"
        fi
        echo "${user}:${hash}" >> "$HTPASSWD_FILE"
    fi

    chmod 640 "$HTPASSWD_FILE"
    echo -e "${GREEN}[+] Usuario '$user' configurado${NC}"
}

cmd_del_user() {
    check_root
    local user="$1"
    if [[ -z "$user" ]]; then
        echo -e "${RED}[X] Especificar nombre de usuario${NC}"
        exit 1
    fi

    if [[ ! -f "$HTPASSWD_FILE" ]]; then
        echo -e "${RED}[X] Archivo htpasswd no encontrado${NC}"
        exit 1
    fi

    if command -v htpasswd &>/dev/null; then
        htpasswd -D "$HTPASSWD_FILE" "$user"
    else
        sed -i "/^${user}:/d" "$HTPASSWD_FILE"
    fi
    echo -e "${GREEN}[+] Usuario '$user' eliminado${NC}"
}

cmd_list_users() {
    if [[ ! -f "$HTPASSWD_FILE" ]]; then
        echo -e "${YELLOW}[!] Archivo htpasswd no encontrado${NC}"
        exit 1
    fi

    echo -e "${CYAN}Usuarios configurados:${NC}"
    while IFS=: read -r user _; do
        echo -e "  - $user"
    done < "$HTPASSWD_FILE"
}

cmd_check_auth() {
    local url="$1"
    if [[ -z "$url" ]]; then
        echo -e "${RED}[X] Especificar URL${NC}"
        exit 1
    fi

    echo -e "${CYAN}Verificando autenticacion en: $url${NC}"
    echo ""

    # Sin credenciales
    code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "$url" 2>/dev/null)
    if [[ "$code" == "401" ]]; then
        echo -e "  ${GREEN}[OK] Requiere autenticacion (HTTP 401)${NC}"
    elif [[ "$code" == "403" ]]; then
        echo -e "  ${GREEN}[OK] Acceso denegado (HTTP 403)${NC}"
    else
        echo -e "  ${YELLOW}[!] Respuesta sin autenticacion: HTTP $code${NC}"
    fi
}

cmd_gen_client_cert() {
    check_root
    local cn="$1"
    if [[ -z "$cn" ]]; then
        echo -e "${RED}[X] Especificar CN (nombre comun) del certificado${NC}"
        exit 1
    fi

    local cert_dir="/etc/securizar/tls/client-certs"
    mkdir -p "$cert_dir"

    # Generar CA si no existe
    if [[ ! -f "$cert_dir/ca.pem" ]]; then
        echo -e "${CYAN}Generando CA para certificados de cliente...${NC}"
        openssl genrsa -out "$cert_dir/ca.key" 4096 2>/dev/null
        openssl req -new -x509 -days 3650 -key "$cert_dir/ca.key" \
            -out "$cert_dir/ca.pem" \
            -subj "/C=ES/ST=Madrid/O=Securizar/OU=WebAuth/CN=Securizar Client CA" 2>/dev/null
        chmod 600 "$cert_dir/ca.key"
        echo -e "${GREEN}[+] CA generada: $cert_dir/ca.pem${NC}"
    fi

    # Generar certificado de cliente
    openssl genrsa -out "$cert_dir/${cn}.key" 2048 2>/dev/null
    openssl req -new -key "$cert_dir/${cn}.key" \
        -out "$cert_dir/${cn}.csr" \
        -subj "/C=ES/ST=Madrid/O=Securizar/OU=WebAuth/CN=${cn}" 2>/dev/null
    openssl x509 -req -days 365 \
        -in "$cert_dir/${cn}.csr" \
        -CA "$cert_dir/ca.pem" \
        -CAkey "$cert_dir/ca.key" \
        -CAcreateserial \
        -out "$cert_dir/${cn}.pem" 2>/dev/null

    # Generar PKCS12 para importar en navegador
    openssl pkcs12 -export \
        -out "$cert_dir/${cn}.p12" \
        -inkey "$cert_dir/${cn}.key" \
        -in "$cert_dir/${cn}.pem" \
        -certfile "$cert_dir/ca.pem" \
        -passout pass: 2>/dev/null

    chmod 600 "$cert_dir/${cn}.key" "$cert_dir/${cn}.p12"
    rm -f "$cert_dir/${cn}.csr"

    echo -e "${GREEN}[+] Certificado de cliente generado:${NC}"
    echo -e "  Certificado: $cert_dir/${cn}.pem"
    echo -e "  Clave:       $cert_dir/${cn}.key"
    echo -e "  PKCS12:      $cert_dir/${cn}.p12 (importar en navegador)"
    echo -e "  CA:          $cert_dir/ca.pem (configurar en servidor)"
}

case "${1:-}" in
    add-user)         cmd_add_user "${2:-}" ;;
    del-user)         cmd_del_user "${2:-}" ;;
    list-users)       cmd_list_users ;;
    check-auth)       cmd_check_auth "${2:-}" ;;
    gen-client-cert)  cmd_gen_client_cert "${2:-}" ;;
    *)                usage ;;
esac
EOFSCRIPT
    chmod +x /usr/local/bin/configurar-acceso-web.sh
    log_change "Creado" "/usr/local/bin/configurar-acceso-web.sh"

    log_info "Control de acceso y autenticacion configurados"
    log_info "Gestionar: configurar-acceso-web.sh {add-user|del-user|list-users|check-auth|gen-client-cert}"
else
    log_skip "Control de acceso y autenticacion web"
fi

# ============================================================
# S9: MONITORIZACION Y ANALISIS DE LOGS WEB
# ============================================================
log_section "S9: MONITORIZACION Y ANALISIS DE LOGS WEB"

echo "Crea herramientas de monitorizacion y analisis de logs web:"
echo "  - Monitor de errores 4xx/5xx, tiempos de respuesta"
echo "  - Top IPs, user-agents sospechosos, bloques WAF"
echo "  - Analizador de logs: fuerza bruta, SQLi, XSS, LFI/RFI"
echo "  - Deteccion de patrones de ataque"
echo ""

if check_executable /usr/local/bin/monitorizar-web.sh; then
    log_already "Monitorizacion y analisis de logs web (script ya instalado)"
elif ask "¿Configurar monitorizacion y analisis de logs web?"; then

    # Script de monitorizacion web
    cat > /usr/local/bin/monitorizar-web.sh << 'EOFSCRIPT'
#!/bin/bash
# ============================================================
# monitorizar-web.sh
# Monitoriza servidores web en tiempo real
# Generado por securizar - Modulo 50
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

INTERVALO="${1:-60}"

# Detectar logs
NGINX_LOG="/var/log/nginx/access.log"
APACHE_LOG=""
if [[ -f /var/log/apache2/access.log ]]; then
    APACHE_LOG="/var/log/apache2/access.log"
elif [[ -f /var/log/httpd/access_log ]]; then
    APACHE_LOG="/var/log/httpd/access_log"
fi

MODSEC_LOG="/var/log/modsecurity/modsec_audit.log"

analizar_log() {
    local log_file="$1"
    local nombre="$2"

    if [[ ! -f "$log_file" ]]; then
        return
    fi

    echo -e "${CYAN}--- $nombre: $log_file ---${NC}"
    echo ""

    # Ventana de tiempo: ultimo minuto
    local ahora
    ahora=$(date +%s)
    local inicio=$((ahora - INTERVALO))

    # Total de peticiones recientes (ultimas lineas)
    local total_lineas
    total_lineas=$(wc -l < "$log_file" 2>/dev/null || echo 0)
    # Analizar ultimas 10000 lineas como muestra
    local muestra=10000
    [[ "$total_lineas" -lt "$muestra" ]] && muestra="$total_lineas"

    # Errores 4xx
    local errores_4xx
    errores_4xx=$(tail -n "$muestra" "$log_file" | awk '$9 ~ /^4[0-9][0-9]$/ {count++} END {print count+0}')

    # Errores 5xx
    local errores_5xx
    errores_5xx=$(tail -n "$muestra" "$log_file" | awk '$9 ~ /^5[0-9][0-9]$/ {count++} END {print count+0}')

    # Peticiones exitosas
    local exitosas
    exitosas=$(tail -n "$muestra" "$log_file" | awk '$9 ~ /^2[0-9][0-9]$/ {count++} END {print count+0}')

    echo -e "  ${BOLD}Peticiones (ultimas $muestra lineas):${NC}"
    echo -e "    ${GREEN}Exitosas (2xx): $exitosas${NC}"
    if [[ "$errores_4xx" -gt 100 ]]; then
        echo -e "    ${RED}Errores 4xx: $errores_4xx (ALTO)${NC}"
    else
        echo -e "    ${YELLOW}Errores 4xx: $errores_4xx${NC}"
    fi
    if [[ "$errores_5xx" -gt 10 ]]; then
        echo -e "    ${RED}Errores 5xx: $errores_5xx (CRITICO)${NC}"
    else
        echo -e "    ${YELLOW}Errores 5xx: $errores_5xx${NC}"
    fi
    echo ""

    # Top 10 IPs
    echo -e "  ${BOLD}Top 10 IPs por peticiones:${NC}"
    tail -n "$muestra" "$log_file" | awk '{print $1}' | sort | uniq -c | sort -rn | head -10 | \
        while read -r count ip; do
            if [[ "$count" -gt 500 ]]; then
                echo -e "    ${RED}$ip - $count peticiones${NC}"
            elif [[ "$count" -gt 100 ]]; then
                echo -e "    ${YELLOW}$ip - $count peticiones${NC}"
            else
                echo -e "    $ip - $count peticiones"
            fi
        done
    echo ""

    # Top errores 4xx por ruta
    echo -e "  ${BOLD}Top rutas con errores 4xx:${NC}"
    tail -n "$muestra" "$log_file" | awk '$9 ~ /^4[0-9][0-9]$/ {print $7}' | sort | uniq -c | sort -rn | head -5 | \
        while read -r count path; do
            echo -e "    ${YELLOW}$path - $count errores${NC}"
        done
    echo ""

    # User-agents sospechosos
    echo -e "  ${BOLD}User-Agents sospechosos:${NC}"
    local sospechosos
    sospechosos=$(tail -n "$muestra" "$log_file" | \
        grep -iE '(sqlmap|nikto|dirbuster|nmap|masscan|wpscan|acunetix|burp|gobuster|ffuf|nuclei)' | wc -l)
    if [[ "$sospechosos" -gt 0 ]]; then
        echo -e "    ${RED}Detectados $sospechosos peticiones con UAs maliciosos${NC}"
        tail -n "$muestra" "$log_file" | \
            grep -ioE '(sqlmap|nikto|dirbuster|nmap|masscan|wpscan|acunetix|burp|gobuster|ffuf|nuclei)[^ "]*' | \
            sort | uniq -c | sort -rn | head -5 | \
            while read -r count ua; do
                echo -e "    ${RED}  $ua - $count${NC}"
            done
    else
        echo -e "    ${GREEN}Ninguno detectado${NC}"
    fi
    echo ""

    # Ancho de banda (bytes transferidos)
    echo -e "  ${BOLD}Ancho de banda (ultimas $muestra peticiones):${NC}"
    local bytes_total
    bytes_total=$(tail -n "$muestra" "$log_file" | awk '{sum+=$10} END {print sum+0}')
    if [[ "$bytes_total" -gt 1073741824 ]]; then
        echo -e "    $(echo "scale=2; $bytes_total/1073741824" | bc 2>/dev/null || echo "$bytes_total") GB"
    elif [[ "$bytes_total" -gt 1048576 ]]; then
        echo -e "    $(echo "scale=2; $bytes_total/1048576" | bc 2>/dev/null || echo "$bytes_total") MB"
    else
        echo -e "    $(echo "scale=2; $bytes_total/1024" | bc 2>/dev/null || echo "$bytes_total") KB"
    fi
    echo ""
}

echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "${CYAN}  MONITORIZACION DE SERVIDORES WEB${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "${DIM}  Fecha: $(date)${NC}"
echo ""

# Analizar logs de nginx
if [[ -f "$NGINX_LOG" ]]; then
    analizar_log "$NGINX_LOG" "nginx"
fi

# Analizar logs de Apache
if [[ -n "$APACHE_LOG" && -f "$APACHE_LOG" ]]; then
    analizar_log "$APACHE_LOG" "Apache"
fi

# Bloques WAF (ModSecurity)
if [[ -f "$MODSEC_LOG" ]]; then
    echo -e "${CYAN}--- ModSecurity WAF ---${NC}"
    echo ""
    local waf_blocks
    waf_blocks=$(grep -c "Action: Intercepted" "$MODSEC_LOG" 2>/dev/null || echo 0)
    echo -e "  Peticiones bloqueadas por WAF: ${BOLD}$waf_blocks${NC}"

    echo -e "  ${BOLD}Ultimas reglas activadas:${NC}"
    grep "id \"" "$MODSEC_LOG" 2>/dev/null | grep -oP 'id "\K[^"]+' | \
        sort | uniq -c | sort -rn | head -5 | \
        while read -r count rule_id; do
            echo -e "    Regla $rule_id - $count activaciones"
        done
    echo ""
fi

# Estado de servicios
echo -e "${CYAN}--- Estado de Servicios ---${NC}"
echo ""
for svc in nginx apache2 httpd; do
    if systemctl is-active "$svc" &>/dev/null; then
        echo -e "  ${GREEN}$svc: activo${NC}"
    elif systemctl is-enabled "$svc" &>/dev/null 2>&1; then
        echo -e "  ${YELLOW}$svc: inactivo (habilitado)${NC}"
    fi
done
EOFSCRIPT
    chmod +x /usr/local/bin/monitorizar-web.sh
    log_change "Creado" "/usr/local/bin/monitorizar-web.sh"

    # Script de analisis de logs
    cat > /usr/local/bin/analizar-logs-web.sh << 'EOFSCRIPT'
#!/bin/bash
# ============================================================
# analizar-logs-web.sh
# Analisis de logs web para deteccion de ataques
# Generado por securizar - Modulo 50
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

LOGS=()
TOTAL_ATAQUES=0

# Detectar logs disponibles
for log_path in /var/log/nginx/access.log /var/log/apache2/access.log /var/log/httpd/access_log; do
    [[ -f "$log_path" ]] && LOGS+=("$log_path")
done

if [[ ${#LOGS[@]} -eq 0 ]]; then
    echo -e "${RED}[X] No se encontraron logs de acceso web${NC}"
    exit 1
fi

# Lineas a analizar
LINEAS="${1:-50000}"

echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "${CYAN}  ANALISIS DE LOGS WEB - DETECCION DE ATAQUES${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "  Fecha: $(date)"
echo -e "  Lineas por log: $LINEAS"
echo ""

for log_file in "${LOGS[@]}"; do
    echo -e "${CYAN}═══ Analizando: $log_file ═══${NC}"
    echo ""

    # ── 1. Fuerza bruta (multiples intentos a login) ─────
    echo -e "${BOLD}1. Intentos de fuerza bruta:${NC}"
    brute_force=$(tail -n "$LINEAS" "$log_file" | \
        grep -iE '(login|signin|authenticate|auth|session|wp-login)' | \
        awk '$9 ~ /^(401|403)$/ {print $1}' | sort | uniq -c | sort -rn | head -10)

    if [[ -n "$brute_force" ]]; then
        echo "$brute_force" | while read -r count ip; do
            if [[ "$count" -gt 20 ]]; then
                echo -e "  ${RED}[ALERTA] $ip - $count intentos fallidos${NC}"
                ((TOTAL_ATAQUES++)) || true
            elif [[ "$count" -gt 5 ]]; then
                echo -e "  ${YELLOW}[AVISO] $ip - $count intentos fallidos${NC}"
            fi
        done
    else
        echo -e "  ${GREEN}No se detectaron intentos de fuerza bruta${NC}"
    fi
    echo ""

    # ── 2. Directory traversal ───────────────────────────
    echo -e "${BOLD}2. Directory traversal:${NC}"
    traversal=$(tail -n "$LINEAS" "$log_file" | \
        grep -cE '(\.\./|\.\.\\|%2e%2e|%252e%252e)' 2>/dev/null || echo 0)

    if [[ "$traversal" -gt 0 ]]; then
        echo -e "  ${RED}[ALERTA] $traversal intentos de directory traversal${NC}"
        tail -n "$LINEAS" "$log_file" | \
            grep -E '(\.\./|\.\.\\|%2e%2e)' | \
            awk '{print $1}' | sort | uniq -c | sort -rn | head -5 | \
            while read -r count ip; do
                echo -e "  ${RED}  $ip - $count intentos${NC}"
            done
        ((TOTAL_ATAQUES += traversal)) || true
    else
        echo -e "  ${GREEN}No se detectaron intentos de traversal${NC}"
    fi
    echo ""

    # ── 3. SQL Injection ─────────────────────────────────
    echo -e "${BOLD}3. SQL Injection:${NC}"
    sqli=$(tail -n "$LINEAS" "$log_file" | \
        grep -ciE "(union\+select|union%20select|%27|'--|\bor\b.*=.*\b|select.*from|insert.*into|drop\+table|%23|information_schema|1%3D1|1=1)" 2>/dev/null || echo 0)

    if [[ "$sqli" -gt 0 ]]; then
        echo -e "  ${RED}[ALERTA] $sqli posibles intentos de SQL injection${NC}"
        tail -n "$LINEAS" "$log_file" | \
            grep -iE "(union.select|%27|select.*from|drop.table)" | \
            awk '{print $1}' | sort | uniq -c | sort -rn | head -5 | \
            while read -r count ip; do
                echo -e "  ${RED}  $ip - $count intentos${NC}"
            done
        ((TOTAL_ATAQUES += sqli)) || true
    else
        echo -e "  ${GREEN}No se detectaron intentos de SQLi${NC}"
    fi
    echo ""

    # ── 4. XSS (Cross-Site Scripting) ────────────────────
    echo -e "${BOLD}4. Cross-Site Scripting (XSS):${NC}"
    xss=$(tail -n "$LINEAS" "$log_file" | \
        grep -ciE '(<script|%3Cscript|javascript:|onerror=|onload=|onclick=|alert\(|prompt\(|confirm\()' 2>/dev/null || echo 0)

    if [[ "$xss" -gt 0 ]]; then
        echo -e "  ${RED}[ALERTA] $xss posibles intentos de XSS${NC}"
        tail -n "$LINEAS" "$log_file" | \
            grep -iE '(<script|%3Cscript|javascript:)' | \
            awk '{print $1}' | sort | uniq -c | sort -rn | head -5 | \
            while read -r count ip; do
                echo -e "  ${RED}  $ip - $count intentos${NC}"
            done
        ((TOTAL_ATAQUES += xss)) || true
    else
        echo -e "  ${GREEN}No se detectaron intentos de XSS${NC}"
    fi
    echo ""

    # ── 5. File Inclusion (LFI/RFI) ─────────────────────
    echo -e "${BOLD}5. File Inclusion (LFI/RFI):${NC}"
    lfi=$(tail -n "$LINEAS" "$log_file" | \
        grep -ciE '(/etc/passwd|/etc/shadow|/proc/self|php://|data://|expect://|file://|include=|require=|path=.*\.\./)' 2>/dev/null || echo 0)

    if [[ "$lfi" -gt 0 ]]; then
        echo -e "  ${RED}[ALERTA] $lfi posibles intentos de File Inclusion${NC}"
        tail -n "$LINEAS" "$log_file" | \
            grep -iE '(/etc/passwd|/etc/shadow|php://|data://|file://)' | \
            awk '{print $1}' | sort | uniq -c | sort -rn | head -5 | \
            while read -r count ip; do
                echo -e "  ${RED}  $ip - $count intentos${NC}"
            done
        ((TOTAL_ATAQUES += lfi)) || true
    else
        echo -e "  ${GREEN}No se detectaron intentos de LFI/RFI${NC}"
    fi
    echo ""

    # ── 6. Command Injection ─────────────────────────────
    echo -e "${BOLD}6. Command Injection:${NC}"
    cmdi=$(tail -n "$LINEAS" "$log_file" | \
        grep -ciE '(;ls|;cat|;id|;whoami|;uname|;wget|;curl|;bash|;sh|%7C|%60|\|.*cat|\`.*\`)' 2>/dev/null || echo 0)

    if [[ "$cmdi" -gt 0 ]]; then
        echo -e "  ${RED}[ALERTA] $cmdi posibles intentos de Command Injection${NC}"
        tail -n "$LINEAS" "$log_file" | \
            grep -iE '(;ls|;cat|;id|;whoami|;wget|;curl|;bash)' | \
            awk '{print $1}' | sort | uniq -c | sort -rn | head -5 | \
            while read -r count ip; do
                echo -e "  ${RED}  $ip - $count intentos${NC}"
            done
        ((TOTAL_ATAQUES += cmdi)) || true
    else
        echo -e "  ${GREEN}No se detectaron intentos de Command Injection${NC}"
    fi
    echo ""

    # ── 7. Escaneo de puertos/rutas ──────────────────────
    echo -e "${BOLD}7. Escaneo automatizado (por tasa de 404):${NC}"
    scanners=$(tail -n "$LINEAS" "$log_file" | \
        awk '$9 == "404" {print $1}' | sort | uniq -c | sort -rn | head -10)

    if [[ -n "$scanners" ]]; then
        echo "$scanners" | while read -r count ip; do
            if [[ "$count" -gt 100 ]]; then
                echo -e "  ${RED}[ESCANEO] $ip - $count errores 404${NC}"
            elif [[ "$count" -gt 30 ]]; then
                echo -e "  ${YELLOW}[POSIBLE] $ip - $count errores 404${NC}"
            fi
        done
    else
        echo -e "  ${GREEN}No se detectaron patrones de escaneo${NC}"
    fi
    echo ""
done

# ── Resumen ──────────────────────────────────────────────
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "${CYAN}  RESUMEN DE ANALISIS${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "  Total de indicadores de ataque: ${BOLD}${TOTAL_ATAQUES}${NC}"
echo -e "  Logs analizados: ${#LOGS[@]}"

if [[ $TOTAL_ATAQUES -eq 0 ]]; then
    echo -e "\n${GREEN}[+] No se detectaron patrones de ataque significativos${NC}"
elif [[ $TOTAL_ATAQUES -lt 10 ]]; then
    echo -e "\n${YELLOW}[!] Se detectaron algunos indicadores - revisar${NC}"
else
    echo -e "\n${RED}[!!!] MULTIPLES INDICADORES DE ATAQUE DETECTADOS${NC}"
    echo -e "${YELLOW}Recomendaciones:${NC}"
    echo -e "  1. Revisar IPs reportadas y considerar bloqueo"
    echo -e "  2. Verificar que ModSecurity WAF este activo"
    echo -e "  3. Activar rate limiting si no esta configurado"
    echo -e "  4. Revisar logs completos para mas detalle"
fi
EOFSCRIPT
    chmod +x /usr/local/bin/analizar-logs-web.sh
    log_change "Creado" "/usr/local/bin/analizar-logs-web.sh"

    # Cron de monitorizacion (opcional)
    cat > /etc/cron.d/securizar-web-monitor << 'EOF'
# Monitorizacion web cada hora - securizar
0 * * * * root /usr/local/bin/monitorizar-web.sh > /var/log/securizar-web-monitor.log 2>&1
# Analisis de logs diario
0 6 * * * root /usr/local/bin/analizar-logs-web.sh > /var/log/securizar-web-analisis.log 2>&1
EOF
    chmod 644 /etc/cron.d/securizar-web-monitor
    log_change "Creado" "/etc/cron.d/securizar-web-monitor (cron de monitorizacion)"

    log_info "Monitorizacion y analisis de logs configurados"
    log_info "Monitor: monitorizar-web.sh"
    log_info "Analisis: analizar-logs-web.sh [lineas]"
else
    log_skip "Monitorizacion y analisis de logs web"
fi

# ============================================================
# S10: AUDITORIA DE SEGURIDAD WEB
# ============================================================
log_section "S10: AUDITORIA DE SEGURIDAD WEB"

echo "Crea herramienta de auditoria completa de seguridad web:"
echo "  - Hardening del servidor"
echo "  - Cabeceras de seguridad"
echo "  - Configuracion TLS"
echo "  - WAF activo"
echo "  - Rate limiting"
echo "  - Control de acceso"
echo "  - Monitorizacion"
echo "  - Cumplimiento OWASP"
echo "  - Puntuacion: BUENO/MEJORABLE/DEFICIENTE"
echo ""

if check_executable /usr/local/bin/auditoria-seguridad-web.sh; then
    log_already "Auditoria de seguridad web (script ya instalado)"
elif ask "¿Crear herramienta de auditoria de seguridad web?"; then

    cat > /usr/local/bin/auditoria-seguridad-web.sh << 'EOFSCRIPT'
#!/bin/bash
# ============================================================
# auditoria-seguridad-web.sh
# Auditoria completa de seguridad de servidores web
# Generado por securizar - Modulo 50
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

PUNTOS_TOTAL=0
PUNTOS_OK=0
PUNTOS_WARN=0
PUNTOS_FAIL=0

check_ok() {
    echo -e "  ${GREEN}[OK]${NC} $1"
    ((PUNTOS_OK++)) || true
    ((PUNTOS_TOTAL++)) || true
}

check_warn() {
    echo -e "  ${YELLOW}[!]${NC} $1"
    ((PUNTOS_WARN++)) || true
    ((PUNTOS_TOTAL++)) || true
}

check_fail() {
    echo -e "  ${RED}[X]${NC} $1"
    ((PUNTOS_FAIL++)) || true
    ((PUNTOS_TOTAL++)) || true
}

echo -e "${CYAN}══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}       AUDITORIA DE SEGURIDAD WEB COMPLETA${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════${NC}"
echo -e "${DIM}  Fecha: $(date)${NC}"
echo -e "${DIM}  Host:  $(hostname)${NC}"
echo ""

# ════════════════════════════════════════════════════════════
# 1. HARDENING DEL SERVIDOR
# ════════════════════════════════════════════════════════════
echo -e "${BOLD}${CYAN}1. HARDENING DEL SERVIDOR${NC}"
echo ""

# nginx
if command -v nginx &>/dev/null; then
    echo -e "  ${BOLD}nginx:${NC}"
    nginx_conf="/etc/nginx"

    if [[ -f "$nginx_conf/conf.d/securizar-hardening.conf" ]]; then
        check_ok "Configuracion de hardening presente"
    else
        check_fail "Falta configuracion de hardening nginx"
    fi

    # server_tokens off
    if grep -rq "server_tokens off" "$nginx_conf/" 2>/dev/null; then
        check_ok "server_tokens off"
    else
        check_warn "server_tokens no configurado como off"
    fi

    # autoindex off
    if ! grep -rq "autoindex on" "$nginx_conf/" 2>/dev/null; then
        check_ok "autoindex off"
    else
        check_fail "autoindex on encontrado"
    fi
    echo ""
fi

# Apache
if command -v httpd &>/dev/null || command -v apache2ctl &>/dev/null; then
    echo -e "  ${BOLD}Apache:${NC}"
    apache_conf=""
    if [[ -d /etc/apache2 ]]; then
        apache_conf="/etc/apache2"
    elif [[ -d /etc/httpd ]]; then
        apache_conf="/etc/httpd"
    fi

    if [[ -n "$apache_conf" ]]; then
        # ServerTokens Prod
        if grep -rq "ServerTokens Prod" "$apache_conf/" 2>/dev/null; then
            check_ok "ServerTokens Prod"
        else
            check_fail "ServerTokens no configurado como Prod"
        fi

        # ServerSignature Off
        if grep -rq "ServerSignature Off" "$apache_conf/" 2>/dev/null; then
            check_ok "ServerSignature Off"
        else
            check_warn "ServerSignature no configurado como Off"
        fi

        # TraceEnable Off
        if grep -rq "TraceEnable Off" "$apache_conf/" 2>/dev/null; then
            check_ok "TraceEnable Off"
        else
            check_fail "TraceEnable no deshabilitado"
        fi

        # mod_info/mod_status
        local apache_cmd="httpd"
        command -v apache2ctl &>/dev/null && apache_cmd="apache2ctl"
        if ! $apache_cmd -M 2>/dev/null | grep -q "info_module"; then
            check_ok "mod_info deshabilitado"
        else
            check_warn "mod_info habilitado (deshabilitar en produccion)"
        fi
    fi
    echo ""
fi

# ════════════════════════════════════════════════════════════
# 2. CABECERAS DE SEGURIDAD
# ════════════════════════════════════════════════════════════
echo -e "${BOLD}${CYAN}2. CABECERAS DE SEGURIDAD${NC}"
echo ""

test_url="${1:-http://localhost}"
headers=$(curl -sI --connect-timeout 5 "$test_url" 2>/dev/null)

if [[ -n "$headers" ]]; then
    # Content-Security-Policy
    if echo "$headers" | grep -qi "Content-Security-Policy"; then
        check_ok "Content-Security-Policy presente"
    else
        check_fail "Content-Security-Policy ausente"
    fi

    # HSTS
    if echo "$headers" | grep -qi "Strict-Transport-Security"; then
        check_ok "Strict-Transport-Security presente"
    else
        check_warn "Strict-Transport-Security ausente"
    fi

    # X-Frame-Options
    if echo "$headers" | grep -qi "X-Frame-Options"; then
        check_ok "X-Frame-Options presente"
    else
        check_warn "X-Frame-Options ausente"
    fi

    # X-Content-Type-Options
    if echo "$headers" | grep -qi "X-Content-Type-Options"; then
        check_ok "X-Content-Type-Options presente"
    else
        check_fail "X-Content-Type-Options ausente"
    fi

    # Referrer-Policy
    if echo "$headers" | grep -qi "Referrer-Policy"; then
        check_ok "Referrer-Policy presente"
    else
        check_warn "Referrer-Policy ausente"
    fi

    # Permissions-Policy
    if echo "$headers" | grep -qi "Permissions-Policy"; then
        check_ok "Permissions-Policy presente"
    else
        check_warn "Permissions-Policy ausente"
    fi

    # Server header filtrado
    server_header=$(echo "$headers" | grep -i "^Server:" | head -1)
    if [[ -z "$server_header" ]]; then
        check_ok "Header Server no expuesto"
    elif echo "$server_header" | grep -qiE "(apache|nginx|iis)/[0-9]"; then
        check_fail "Header Server expone version: $server_header"
    else
        check_warn "Header Server presente: $server_header"
    fi

    # X-Powered-By
    if echo "$headers" | grep -qi "X-Powered-By"; then
        check_fail "X-Powered-By expuesto (eliminar)"
    else
        check_ok "X-Powered-By no expuesto"
    fi
else
    check_warn "No se pudo conectar a $test_url para verificar cabeceras"
fi
echo ""

# ════════════════════════════════════════════════════════════
# 3. CONFIGURACION TLS
# ════════════════════════════════════════════════════════════
echo -e "${BOLD}${CYAN}3. CONFIGURACION TLS${NC}"
echo ""

tls_host="${1:-localhost}"
tls_port="443"

if timeout 3 bash -c "echo >/dev/tcp/${tls_host}/${tls_port}" 2>/dev/null; then
    # TLS 1.2
    if echo | timeout 5 openssl s_client -connect "${tls_host}:${tls_port}" -tls1_2 2>/dev/null | grep -q "CONNECTED"; then
        check_ok "TLS 1.2 habilitado"
    else
        check_warn "TLS 1.2 no disponible"
    fi

    # TLS 1.3
    if echo | timeout 5 openssl s_client -connect "${tls_host}:${tls_port}" -tls1_3 2>/dev/null | grep -q "CONNECTED"; then
        check_ok "TLS 1.3 habilitado"
    else
        check_warn "TLS 1.3 no disponible"
    fi

    # SSLv3 (no debe estar)
    if echo | timeout 5 openssl s_client -connect "${tls_host}:${tls_port}" -ssl3 2>/dev/null | grep -q "CONNECTED"; then
        check_fail "SSLv3 habilitado (INSEGURO)"
    else
        check_ok "SSLv3 deshabilitado"
    fi

    # TLS 1.0 (no debe estar)
    if echo | timeout 5 openssl s_client -connect "${tls_host}:${tls_port}" -tls1 2>/dev/null | grep -q "CONNECTED"; then
        check_fail "TLS 1.0 habilitado (INSEGURO)"
    else
        check_ok "TLS 1.0 deshabilitado"
    fi

    # DH params
    dh_info=$(echo | timeout 5 openssl s_client -connect "${tls_host}:${tls_port}" 2>/dev/null | grep "Server Temp Key:")
    if [[ -n "$dh_info" ]]; then
        dh_bits=$(echo "$dh_info" | grep -oP '\d+' | tail -1)
        if [[ -n "$dh_bits" && "$dh_bits" -ge 2048 ]]; then
            check_ok "DH params $dh_bits bits"
        else
            check_warn "DH params debiles: $dh_bits bits"
        fi
    fi

    # Certificado
    cert_days=$(echo | timeout 5 openssl s_client -connect "${tls_host}:${tls_port}" -servername "${tls_host}" 2>/dev/null | \
        openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
    if [[ -n "$cert_days" ]]; then
        exp_epoch=$(date -d "$cert_days" +%s 2>/dev/null || echo 0)
        now_epoch=$(date +%s)
        days_remaining=$(( (exp_epoch - now_epoch) / 86400 ))
        if [[ $days_remaining -lt 0 ]]; then
            check_fail "Certificado expirado"
        elif [[ $days_remaining -lt 30 ]]; then
            check_warn "Certificado expira en $days_remaining dias"
        else
            check_ok "Certificado valido ($days_remaining dias)"
        fi
    fi
else
    check_warn "Puerto TLS (443) no accesible en $tls_host"
fi
echo ""

# ════════════════════════════════════════════════════════════
# 4. WAF (ModSecurity)
# ════════════════════════════════════════════════════════════
echo -e "${BOLD}${CYAN}4. WAF (ModSecurity)${NC}"
echo ""

modsec_conf="/etc/modsecurity/modsecurity.conf"
if [[ -f "$modsec_conf" ]]; then
    engine=$(grep "^SecRuleEngine" "$modsec_conf" | awk '{print $2}')
    case "$engine" in
        On)
            check_ok "ModSecurity activo (SecRuleEngine On)"
            ;;
        DetectionOnly)
            check_warn "ModSecurity en modo deteccion (DetectionOnly)"
            ;;
        *)
            check_fail "ModSecurity desactivado o no configurado"
            ;;
    esac

    if [[ -d "/etc/modsecurity/crs/rules" ]]; then
        num_rules=$(ls /etc/modsecurity/crs/rules/*.conf 2>/dev/null | wc -l)
        if [[ "$num_rules" -gt 0 ]]; then
            check_ok "OWASP CRS instalado ($num_rules archivos de reglas)"
        else
            check_warn "Directorio CRS existe pero sin reglas"
        fi
    else
        check_warn "OWASP CRS no instalado"
    fi

    if [[ -f "/etc/modsecurity/exclusiones-securizar.conf" ]]; then
        check_ok "Configuracion de exclusiones presente"
    fi
else
    check_fail "ModSecurity no configurado"
fi
echo ""

# ════════════════════════════════════════════════════════════
# 5. RATE LIMITING
# ════════════════════════════════════════════════════════════
echo -e "${BOLD}${CYAN}5. RATE LIMITING Y PROTECCION DDoS${NC}"
echo ""

if [[ -f "/etc/securizar/rate-limits.conf" ]]; then
    check_ok "Configuracion de rate limits presente"
else
    check_warn "Sin configuracion de rate limits"
fi

# nginx rate limiting
if command -v nginx &>/dev/null; then
    if grep -rq "limit_req_zone" /etc/nginx/ 2>/dev/null; then
        check_ok "nginx: limit_req_zone configurado"
    else
        check_warn "nginx: sin rate limiting configurado"
    fi
fi

# Sysctl anti-DDoS
if [[ -f "/etc/sysctl.d/90-securizar-web-ddos.conf" ]]; then
    check_ok "Proteccion anti-DDoS sysctl configurada"
else
    check_warn "Sin proteccion anti-DDoS sysctl"
fi

# SYN cookies
syn_cookies=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo "?")
if [[ "$syn_cookies" == "1" ]]; then
    check_ok "SYN cookies activados"
else
    check_fail "SYN cookies desactivados"
fi
echo ""

# ════════════════════════════════════════════════════════════
# 6. CONTROL DE ACCESO
# ════════════════════════════════════════════════════════════
echo -e "${BOLD}${CYAN}6. CONTROL DE ACCESO${NC}"
echo ""

if [[ -f "/etc/securizar/web-auth/.htpasswd" ]]; then
    num_users=$(wc -l < /etc/securizar/web-auth/.htpasswd 2>/dev/null || echo 0)
    check_ok "htpasswd configurado ($num_users usuarios)"

    perms=$(stat -c '%a' /etc/securizar/web-auth/.htpasswd 2>/dev/null || echo "?")
    if [[ "$perms" == "640" || "$perms" == "600" ]]; then
        check_ok "Permisos htpasswd correctos ($perms)"
    else
        check_warn "Permisos htpasswd: $perms (recomendado: 640)"
    fi
else
    check_warn "Sin htpasswd configurado"
fi

# Reglas WAF personalizadas
if [[ -d "/etc/securizar/waf-custom-rules" ]]; then
    num_custom=$(ls /etc/securizar/waf-custom-rules/*.conf 2>/dev/null | wc -l)
    if [[ "$num_custom" -gt 0 ]]; then
        check_ok "Reglas WAF personalizadas: $num_custom archivos"
    else
        check_warn "Directorio WAF personalizado vacio"
    fi
else
    check_warn "Sin reglas WAF personalizadas"
fi
echo ""

# ════════════════════════════════════════════════════════════
# 7. MONITORIZACION
# ════════════════════════════════════════════════════════════
echo -e "${BOLD}${CYAN}7. MONITORIZACION${NC}"
echo ""

if [[ -x "/usr/local/bin/monitorizar-web.sh" ]]; then
    check_ok "Script de monitorizacion web instalado"
else
    check_warn "Script de monitorizacion web no encontrado"
fi

if [[ -x "/usr/local/bin/analizar-logs-web.sh" ]]; then
    check_ok "Script de analisis de logs instalado"
else
    check_warn "Script de analisis de logs no encontrado"
fi

if [[ -x "/usr/local/bin/detectar-ddos-web.sh" ]]; then
    check_ok "Script de deteccion DDoS instalado"
else
    check_warn "Script de deteccion DDoS no encontrado"
fi

if [[ -f "/etc/cron.d/securizar-web-monitor" ]]; then
    check_ok "Cron de monitorizacion configurado"
else
    check_warn "Sin cron de monitorizacion"
fi

# Logs existentes
for log_path in /var/log/nginx/access.log /var/log/apache2/access.log /var/log/httpd/access_log; do
    if [[ -f "$log_path" ]]; then
        check_ok "Log de acceso: $log_path"
    fi
done
echo ""

# ════════════════════════════════════════════════════════════
# 8. CUMPLIMIENTO OWASP
# ════════════════════════════════════════════════════════════
echo -e "${BOLD}${CYAN}8. CUMPLIMIENTO OWASP TOP 10${NC}"
echo ""

# A01:2021 - Broken Access Control
echo -e "  ${BOLD}A01 - Broken Access Control:${NC}"
if [[ -f "/etc/securizar/web-auth/.htpasswd" ]] || \
   grep -rq "auth_basic\|Require valid-user\|Require ip" /etc/nginx/ /etc/apache2/ /etc/httpd/ 2>/dev/null; then
    check_ok "Controles de acceso configurados"
else
    check_warn "Revisar controles de acceso"
fi

# A02:2021 - Cryptographic Failures
echo -e "  ${BOLD}A02 - Cryptographic Failures:${NC}"
if [[ -f "/etc/securizar/tls/tls-web-policy.conf" ]]; then
    check_ok "Politica TLS definida"
else
    check_warn "Sin politica TLS formal"
fi

# A03:2021 - Injection
echo -e "  ${BOLD}A03 - Injection:${NC}"
if [[ -f "$modsec_conf" ]] && grep -q "SecRuleEngine On" "$modsec_conf" 2>/dev/null; then
    check_ok "WAF activo contra inyeccion"
else
    check_warn "WAF no activo contra inyeccion"
fi

# A05:2021 - Security Misconfiguration
echo -e "  ${BOLD}A05 - Security Misconfiguration:${NC}"
if grep -rq "server_tokens off\|ServerTokens Prod" /etc/nginx/ /etc/apache2/ /etc/httpd/ 2>/dev/null; then
    check_ok "Informacion de servidor oculta"
else
    check_warn "Informacion de servidor expuesta"
fi

# A06:2021 - Vulnerable and Outdated Components
echo -e "  ${BOLD}A06 - Vulnerable Components:${NC}"
if command -v nginx &>/dev/null; then
    nginx_ver=$(nginx -v 2>&1 | grep -oP '\d+\.\d+\.\d+')
    echo -e "    nginx version: $nginx_ver"
fi
if command -v httpd &>/dev/null; then
    httpd_ver=$(httpd -v 2>/dev/null | grep -oP '\d+\.\d+\.\d+' | head -1)
    echo -e "    Apache version: $httpd_ver"
elif command -v apache2ctl &>/dev/null; then
    apache2_ver=$(apache2ctl -v 2>/dev/null | grep -oP '\d+\.\d+\.\d+' | head -1)
    echo -e "    Apache version: $apache2_ver"
fi
check_warn "Verificar versiones contra CVE actuales"

# A09:2021 - Security Logging and Monitoring Failures
echo -e "  ${BOLD}A09 - Logging and Monitoring:${NC}"
if [[ -x "/usr/local/bin/monitorizar-web.sh" && -x "/usr/local/bin/analizar-logs-web.sh" ]]; then
    check_ok "Herramientas de logging y monitorizacion instaladas"
else
    check_warn "Faltan herramientas de monitorizacion"
fi
echo ""

# ════════════════════════════════════════════════════════════
# PUNTUACION FINAL
# ════════════════════════════════════════════════════════════
echo -e "${CYAN}══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}       PUNTUACION FINAL${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Total de verificaciones: ${BOLD}$PUNTOS_TOTAL${NC}"
echo -e "  ${GREEN}Correctas:  $PUNTOS_OK${NC}"
echo -e "  ${YELLOW}Avisos:     $PUNTOS_WARN${NC}"
echo -e "  ${RED}Fallos:     $PUNTOS_FAIL${NC}"
echo ""

if [[ $PUNTOS_TOTAL -gt 0 ]]; then
    pct_ok=$(( (PUNTOS_OK * 100) / PUNTOS_TOTAL ))
else
    pct_ok=0
fi

echo -e "  Puntuacion: ${BOLD}${pct_ok}%${NC}"
echo ""

if [[ $pct_ok -ge 80 ]]; then
    echo -e "  ${GREEN}${BOLD}╔═══════════════════════════════════════╗${NC}"
    echo -e "  ${GREEN}${BOLD}║         CALIFICACION: BUENO           ║${NC}"
    echo -e "  ${GREEN}${BOLD}╚═══════════════════════════════════════╝${NC}"
elif [[ $pct_ok -ge 50 ]]; then
    echo -e "  ${YELLOW}${BOLD}╔═══════════════════════════════════════╗${NC}"
    echo -e "  ${YELLOW}${BOLD}║       CALIFICACION: MEJORABLE         ║${NC}"
    echo -e "  ${YELLOW}${BOLD}╚═══════════════════════════════════════╝${NC}"
else
    echo -e "  ${RED}${BOLD}╔═══════════════════════════════════════╗${NC}"
    echo -e "  ${RED}${BOLD}║      CALIFICACION: DEFICIENTE         ║${NC}"
    echo -e "  ${RED}${BOLD}╚═══════════════════════════════════════╝${NC}"
fi
echo ""

if [[ $PUNTOS_FAIL -gt 0 ]]; then
    echo -e "${YELLOW}Recomendaciones prioritarias:${NC}"
    echo -e "  1. Ejecutar seguridad-web.sh para aplicar hardening"
    echo -e "  2. Activar ModSecurity WAF con OWASP CRS"
    echo -e "  3. Configurar cabeceras de seguridad HTTP"
    echo -e "  4. Verificar configuracion TLS: verificar-tls-web.sh"
    echo -e "  5. Activar monitorizacion: monitorizar-web.sh"
fi
EOFSCRIPT
    chmod +x /usr/local/bin/auditoria-seguridad-web.sh
    log_change "Creado" "/usr/local/bin/auditoria-seguridad-web.sh"

    # Cron semanal de auditoria
    cat > /etc/cron.weekly/auditoria-seguridad-web << 'EOFCRON'
#!/bin/bash
# Auditoria semanal de seguridad web - securizar
/usr/local/bin/auditoria-seguridad-web.sh > /var/log/securizar-auditoria-web.log 2>&1
EOFCRON
    chmod +x /etc/cron.weekly/auditoria-seguridad-web
    log_change "Creado" "/etc/cron.weekly/auditoria-seguridad-web"

    log_info "Auditoria de seguridad web configurada"
    log_info "Ejecutar: auditoria-seguridad-web.sh [url]"
else
    log_skip "Auditoria de seguridad web"
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
show_changes_summary
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     SEGURIDAD DE APLICACIONES WEB COMPLETADO             ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups guardados en: $BACKUP_DIR"
echo ""
echo "Comandos utiles post-configuracion:"
echo "  - Verificar cabeceras:       verificar-headers-seguridad.sh http://localhost"
echo "  - Gestionar WAF:             gestionar-modsecurity.sh {enable|status|test}"
echo "  - Verificar TLS:             verificar-tls-web.sh <host> [port]"
echo "  - Detectar DDoS:             detectar-ddos-web.sh"
echo "  - Configurar acceso:         configurar-acceso-web.sh {add-user|list-users}"
echo "  - Monitorizar web:           monitorizar-web.sh"
echo "  - Analizar logs:             analizar-logs-web.sh [lineas]"
echo "  - Auditoria completa:        auditoria-seguridad-web.sh [url]"
echo ""
log_info "Modulo 50 completado"
echo ""
