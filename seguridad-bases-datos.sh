#!/bin/bash
# ============================================================
# seguridad-bases-datos.sh - Modulo 48: Seguridad de bases de datos
# ============================================================
# Secciones:
#   S1  - PostgreSQL Hardening
#   S2  - MySQL/MariaDB Hardening
#   S3  - Redis Hardening
#   S4  - MongoDB Hardening
#   S5  - Database Authentication & Access Control
#   S6  - Database Encryption (at rest & in transit)
#   S7  - Database Backup Security
#   S8  - Database Audit Logging
#   S9  - SQL Injection Prevention & Query Monitoring
#   S10 - Database Security Audit
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps
init_backup "seguridad-bases-datos"

# ── Pre-check: detectar secciones ya aplicadas ────────────
_precheck 10
_pc 'check_executable "/usr/local/bin/auditar-postgresql.sh"'
_pc 'check_executable "/usr/local/bin/auditar-mysql.sh"'
_pc 'check_executable "/usr/local/bin/auditar-redis.sh"'
_pc 'check_executable "/usr/local/bin/auditar-mongodb.sh"'
_pc 'check_executable "/usr/local/bin/auditar-acceso-db.sh"'
_pc 'check_executable "/usr/local/bin/verificar-cifrado-db.sh"'
_pc 'check_executable "/usr/local/bin/backup-seguro-db.sh"'
_pc 'check_executable "/usr/local/bin/configurar-audit-db.sh"'
_pc 'check_executable "/usr/local/bin/detectar-sqli.sh"'
_pc 'check_executable "/usr/local/bin/auditoria-bases-datos.sh"'
_precheck_result

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MODULO 48 - SEGURIDAD DE BASES DE DATOS                ║"
echo "║   PostgreSQL, MySQL/MariaDB, Redis, MongoDB               ║"
echo "║   Autenticacion, cifrado, backups, auditoria, SQLi        ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

log_section "MODULO 48: SEGURIDAD DE BASES DE DATOS"
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

# ── Helpers de deteccion de bases de datos ──────────────────
detect_postgresql() {
    command -v psql &>/dev/null || command -v pg_isready &>/dev/null || \
        systemctl list-unit-files 2>/dev/null | grep -q 'postgresql' || \
        [[ -d /var/lib/pgsql ]] || [[ -d /var/lib/postgresql ]]
}

detect_mysql() {
    command -v mysql &>/dev/null || command -v mariadb &>/dev/null || \
        systemctl list-unit-files 2>/dev/null | grep -qE 'mysql|mariadb' || \
        [[ -d /var/lib/mysql ]]
}

detect_redis() {
    command -v redis-server &>/dev/null || command -v redis-cli &>/dev/null || \
        systemctl list-unit-files 2>/dev/null | grep -q 'redis'
}

detect_mongodb() {
    command -v mongod &>/dev/null || command -v mongosh &>/dev/null || \
        systemctl list-unit-files 2>/dev/null | grep -q 'mongod'
}

find_pg_conf() {
    local conf=""
    for d in /etc/postgresql/*/main /var/lib/pgsql/data /var/lib/postgresql/*/data /etc/postgresql; do
        if [[ -f "$d/postgresql.conf" ]]; then
            conf="$d/postgresql.conf"
            break
        fi
    done
    echo "$conf"
}

find_pg_hba() {
    local hba=""
    for d in /etc/postgresql/*/main /var/lib/pgsql/data /var/lib/postgresql/*/data /etc/postgresql; do
        if [[ -f "$d/pg_hba.conf" ]]; then
            hba="$d/pg_hba.conf"
            break
        fi
    done
    echo "$hba"
}

find_mysql_conf() {
    local conf=""
    for f in /etc/my.cnf /etc/mysql/my.cnf /etc/mysql/mariadb.conf.d/50-server.cnf /etc/my.cnf.d/server.cnf; do
        if [[ -f "$f" ]]; then
            conf="$f"
            break
        fi
    done
    echo "$conf"
}

find_redis_conf() {
    local conf=""
    for f in /etc/redis/redis.conf /etc/redis.conf /etc/redis/6379.conf; do
        if [[ -f "$f" ]]; then
            conf="$f"
            break
        fi
    done
    echo "$conf"
}

find_mongod_conf() {
    local conf=""
    for f in /etc/mongod.conf /etc/mongodb.conf /etc/mongos.conf; do
        if [[ -f "$f" ]]; then
            conf="$f"
            break
        fi
    done
    echo "$conf"
}

# Genera contrasena segura
generate_strong_password() {
    local length="${1:-32}"
    openssl rand -base64 "$length" 2>/dev/null | tr -dc 'A-Za-z0-9!@#$%^&*' | head -c "$length"
}

# Directorio de configuracion de securizar
mkdir -p /etc/securizar

# ============================================================
# S1: POSTGRESQL HARDENING
# ============================================================
log_section "S1: POSTGRESQL HARDENING"

echo "Hardening de PostgreSQL:"
echo "  - ssl=on, password_encryption=scram-sha-256"
echo "  - log_connections/disconnections=on, log_statement=ddl"
echo "  - Restriccion de listen_addresses"
echo "  - pg_hba.conf: forzar scram-sha-256 (sin trust/md5)"
echo "  - Deshabilitar autenticacion trust remota"
echo ""

if detect_postgresql; then
    log_info "PostgreSQL detectado en el sistema"

    if check_executable "/usr/local/bin/auditar-postgresql.sh"; then
        log_already "Hardening PostgreSQL (auditar-postgresql.sh ya instalado)"
    elif ask "¿Aplicar hardening de PostgreSQL?"; then

        PG_CONF=$(find_pg_conf)
        PG_HBA=$(find_pg_hba)

        if [[ -n "$PG_CONF" ]]; then
            cp "$PG_CONF" "$BACKUP_DIR/"
            log_change "Backup" "$PG_CONF"

            # Hardening de postgresql.conf
            log_info "Aplicando hardening a postgresql.conf..."

            # ssl = on
            if grep -q "^#\?ssl\s*=" "$PG_CONF"; then
                sed -i "s/^#\?ssl\s*=.*/ssl = on/" "$PG_CONF"
            else
                echo "ssl = on" >> "$PG_CONF"
            fi
            log_change "Configurado" "PostgreSQL: ssl = on"

            # password_encryption = scram-sha-256
            if grep -q "^#\?password_encryption\s*=" "$PG_CONF"; then
                sed -i "s/^#\?password_encryption\s*=.*/password_encryption = scram-sha-256/" "$PG_CONF"
            else
                echo "password_encryption = scram-sha-256" >> "$PG_CONF"
            fi
            log_change "Configurado" "PostgreSQL: password_encryption = scram-sha-256"

            # log_connections = on
            if grep -q "^#\?log_connections\s*=" "$PG_CONF"; then
                sed -i "s/^#\?log_connections\s*=.*/log_connections = on/" "$PG_CONF"
            else
                echo "log_connections = on" >> "$PG_CONF"
            fi
            log_change "Configurado" "PostgreSQL: log_connections = on"

            # log_disconnections = on
            if grep -q "^#\?log_disconnections\s*=" "$PG_CONF"; then
                sed -i "s/^#\?log_disconnections\s*=.*/log_disconnections = on/" "$PG_CONF"
            else
                echo "log_disconnections = on" >> "$PG_CONF"
            fi
            log_change "Configurado" "PostgreSQL: log_disconnections = on"

            # log_statement = ddl
            if grep -q "^#\?log_statement\s*=" "$PG_CONF"; then
                sed -i "s/^#\?log_statement\s*=.*/log_statement = ddl/" "$PG_CONF"
            else
                echo "log_statement = ddl" >> "$PG_CONF"
            fi
            log_change "Configurado" "PostgreSQL: log_statement = ddl"

            # listen_addresses = localhost
            if grep -q "^#\?listen_addresses\s*=" "$PG_CONF"; then
                sed -i "s/^#\?listen_addresses\s*=.*/listen_addresses = 'localhost'/" "$PG_CONF"
            else
                echo "listen_addresses = 'localhost'" >> "$PG_CONF"
            fi
            log_change "Configurado" "PostgreSQL: listen_addresses = 'localhost'"

            # log_line_prefix con timestamp y usuario
            if grep -q "^#\?log_line_prefix\s*=" "$PG_CONF"; then
                sed -i "s/^#\?log_line_prefix\s*=.*/log_line_prefix = '%m [%p] %u@%d '/" "$PG_CONF"
            else
                echo "log_line_prefix = '%m [%p] %u@%d '" >> "$PG_CONF"
            fi
            log_change "Configurado" "PostgreSQL: log_line_prefix con timestamp y usuario"

            # log_duration = on
            if grep -q "^#\?log_duration\s*=" "$PG_CONF"; then
                sed -i "s/^#\?log_duration\s*=.*/log_duration = on/" "$PG_CONF"
            else
                echo "log_duration = on" >> "$PG_CONF"
            fi
            log_change "Configurado" "PostgreSQL: log_duration = on"

        else
            log_warn "No se encontro postgresql.conf - verifica la instalacion"
        fi

        if [[ -n "$PG_HBA" ]]; then
            cp "$PG_HBA" "$BACKUP_DIR/"
            log_change "Backup" "$PG_HBA"

            # Reemplazar metodos trust y md5 con scram-sha-256
            log_info "Securizando pg_hba.conf..."
            local hba_changed=0

            if grep -qE '^\s*(local|host)\s+.*\s+trust\s*$' "$PG_HBA"; then
                sed -i 's/\btrust\s*$/scram-sha-256/' "$PG_HBA"
                log_change "Reemplazado" "pg_hba.conf: trust -> scram-sha-256"
                hba_changed=1
            fi

            if grep -qE '^\s*(local|host)\s+.*\s+md5\s*$' "$PG_HBA"; then
                sed -i 's/\bmd5\s*$/scram-sha-256/' "$PG_HBA"
                log_change "Reemplazado" "pg_hba.conf: md5 -> scram-sha-256"
                hba_changed=1
            fi

            if [[ $hba_changed -eq 0 ]]; then
                log_info "pg_hba.conf: no se encontraron metodos trust/md5 que reemplazar"
            fi

            # Deshabilitar autenticacion trust remota
            if grep -qE '^\s*host\s+.*\s+0\.0\.0\.0/0\s+trust' "$PG_HBA"; then
                sed -i '/^\s*host\s\+.*\s\+0\.0\.0\.0\/0\s\+trust/d' "$PG_HBA"
                log_change "Eliminado" "pg_hba.conf: entradas trust remotas (0.0.0.0/0)"
            fi
        else
            log_warn "No se encontro pg_hba.conf - verifica la instalacion"
        fi

        # Crear script de auditoria PostgreSQL
        cat > /usr/local/bin/auditar-postgresql.sh << 'EOFPGAUDIT'
#!/bin/bash
# ============================================================
# Auditoria de seguridad PostgreSQL
# Generado por securizar - Modulo 48
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  AUDITORIA DE SEGURIDAD POSTGRESQL${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

score=0
total=0

check() {
    local desc="$1" result="$2"
    ((total++))
    if [[ "$result" == "OK" ]]; then
        echo -e "  ${GREEN}[OK]${NC} $desc"
        ((score++))
    elif [[ "$result" == "WARN" ]]; then
        echo -e "  ${YELLOW}[!!]${NC} $desc"
    else
        echo -e "  ${RED}[XX]${NC} $desc"
    fi
}

# Detectar configuracion
PG_CONF=""
for d in /etc/postgresql/*/main /var/lib/pgsql/data /var/lib/postgresql/*/data /etc/postgresql; do
    [[ -f "$d/postgresql.conf" ]] && PG_CONF="$d/postgresql.conf" && break
done
PG_HBA=""
for d in /etc/postgresql/*/main /var/lib/pgsql/data /var/lib/postgresql/*/data /etc/postgresql; do
    [[ -f "$d/pg_hba.conf" ]] && PG_HBA="$d/pg_hba.conf" && break
done

if [[ -z "$PG_CONF" ]]; then
    echo -e "${RED}No se encontro postgresql.conf${NC}"
    exit 1
fi

echo -e "${CYAN}── Configuracion: $PG_CONF ──${NC}"

# SSL
ssl_val=$(grep -E "^ssl\s*=" "$PG_CONF" 2>/dev/null | awk '{print $3}' || echo "off")
[[ "$ssl_val" == "on" ]] && check "SSL habilitado" "OK" || check "SSL deshabilitado" "FAIL"

# password_encryption
pw_enc=$(grep -E "^password_encryption\s*=" "$PG_CONF" 2>/dev/null | awk '{print $3}' || echo "md5")
[[ "$pw_enc" == "scram-sha-256" ]] && check "Cifrado de password: scram-sha-256" "OK" || check "Cifrado de password: $pw_enc (deberia ser scram-sha-256)" "FAIL"

# log_connections
log_conn=$(grep -E "^log_connections\s*=" "$PG_CONF" 2>/dev/null | awk '{print $3}' || echo "off")
[[ "$log_conn" == "on" ]] && check "Log de conexiones habilitado" "OK" || check "Log de conexiones deshabilitado" "FAIL"

# log_disconnections
log_disc=$(grep -E "^log_disconnections\s*=" "$PG_CONF" 2>/dev/null | awk '{print $3}' || echo "off")
[[ "$log_disc" == "on" ]] && check "Log de desconexiones habilitado" "OK" || check "Log de desconexiones deshabilitado" "FAIL"

# log_statement
log_stmt=$(grep -E "^log_statement\s*=" "$PG_CONF" 2>/dev/null | awk '{print $3}' || echo "none")
[[ "$log_stmt" == "ddl" || "$log_stmt" == "all" ]] && check "Log de statements: $log_stmt" "OK" || check "Log de statements: $log_stmt (deberia ser ddl o all)" "WARN"

# listen_addresses
listen=$(grep -E "^listen_addresses\s*=" "$PG_CONF" 2>/dev/null | sed "s/.*=\s*//" | tr -d "'" || echo "*")
[[ "$listen" == "localhost" || "$listen" == "127.0.0.1" ]] && check "listen_addresses restringido: $listen" "OK" || check "listen_addresses: $listen (restringir a localhost)" "WARN"

# pg_hba.conf checks
if [[ -n "$PG_HBA" ]]; then
    echo ""
    echo -e "${CYAN}── pg_hba.conf: $PG_HBA ──${NC}"

    trust_count=$(grep -cE '^\s*(local|host)\s+.*\s+trust\s*$' "$PG_HBA" 2>/dev/null || echo "0")
    [[ "$trust_count" -eq 0 ]] && check "Sin entradas trust en pg_hba.conf" "OK" || check "$trust_count entradas con autenticacion trust" "FAIL"

    md5_count=$(grep -cE '^\s*(local|host)\s+.*\s+md5\s*$' "$PG_HBA" 2>/dev/null || echo "0")
    [[ "$md5_count" -eq 0 ]] && check "Sin entradas md5 en pg_hba.conf" "OK" || check "$md5_count entradas con md5 (migrar a scram-sha-256)" "WARN"

    remote_trust=$(grep -cE '^\s*host\s+.*\s+0\.0\.0\.0/0\s+trust' "$PG_HBA" 2>/dev/null || echo "0")
    [[ "$remote_trust" -eq 0 ]] && check "Sin trust remoto (0.0.0.0/0)" "OK" || check "Trust remoto detectado - CRITICO" "FAIL"
fi

# Resumen
echo ""
echo -e "${BOLD}── Resultado ──${NC}"
pct=$((score * 100 / total))
if [[ $pct -ge 80 ]]; then
    echo -e "  Puntuacion: ${GREEN}${score}/${total} (${pct}%) - BUENO${NC}"
elif [[ $pct -ge 50 ]]; then
    echo -e "  Puntuacion: ${YELLOW}${score}/${total} (${pct}%) - MEJORABLE${NC}"
else
    echo -e "  Puntuacion: ${RED}${score}/${total} (${pct}%) - DEFICIENTE${NC}"
fi
EOFPGAUDIT
        chmod +x /usr/local/bin/auditar-postgresql.sh
        log_change "Creado" "/usr/local/bin/auditar-postgresql.sh"

        # Recargar PostgreSQL si esta activo
        if systemctl is-active postgresql &>/dev/null; then
            systemctl reload postgresql 2>/dev/null || log_warn "No se pudo recargar PostgreSQL"
            log_info "PostgreSQL recargado con nueva configuracion"
        fi

        log_info "Hardening de PostgreSQL completado"
    else
        log_skip "Hardening de PostgreSQL"
    fi
else
    log_info "PostgreSQL no detectado - omitiendo seccion"
    log_skip "PostgreSQL no instalado"
fi

# ============================================================
# S2: MYSQL/MARIADB HARDENING
# ============================================================
log_section "S2: MYSQL/MARIADB HARDENING"

echo "Hardening de MySQL/MariaDB:"
echo "  - bind-address=127.0.0.1, skip-symbolic-links"
echo "  - local-infile=0, require_secure_transport=ON"
echo "  - general_log, log_error, slow_query_log"
echo "  - Plugin de validacion de contrasenas"
echo "  - Deshabilitar LOAD DATA LOCAL"
echo ""

if detect_mysql; then
    log_info "MySQL/MariaDB detectado en el sistema"

    # Identificar si es MySQL o MariaDB
    MYSQL_TYPE="MySQL"
    if command -v mariadb &>/dev/null || mysql --version 2>/dev/null | grep -qi mariadb; then
        MYSQL_TYPE="MariaDB"
    fi
    log_info "Motor detectado: $MYSQL_TYPE"

    if check_executable "/usr/local/bin/auditar-mysql.sh"; then
        log_already "Hardening $MYSQL_TYPE (auditar-mysql.sh ya instalado)"
    elif ask "¿Aplicar hardening de $MYSQL_TYPE?"; then

        MYSQL_CONF=$(find_mysql_conf)

        if [[ -n "$MYSQL_CONF" ]]; then
            cp "$MYSQL_CONF" "$BACKUP_DIR/"
            log_change "Backup" "$MYSQL_CONF"
        fi

        # Crear directorio conf.d si es necesario
        MYSQL_CONFD=""
        for d in /etc/mysql/conf.d /etc/my.cnf.d; do
            if [[ -d "$d" ]]; then
                MYSQL_CONFD="$d"
                break
            fi
        done
        [[ -z "$MYSQL_CONFD" ]] && MYSQL_CONFD="/etc/my.cnf.d" && mkdir -p "$MYSQL_CONFD"

        # Escribir configuracion hardened
        cat > "${MYSQL_CONFD}/99-securizar-hardening.cnf" << 'EOFMYSQL'
# ============================================================
# Hardening MySQL/MariaDB - Generado por securizar - Modulo 48
# ============================================================

[mysqld]
# ── Red ──
bind-address = 127.0.0.1
skip-symbolic-links = 1
skip-name-resolve = 1

# ── Seguridad ──
local-infile = 0
secure-file-priv = /var/lib/mysql-files
symbolic-links = 0

# ── Transporte seguro ──
require_secure_transport = ON

# ── Logging ──
general_log = 1
general_log_file = /var/log/mysql/general.log
log_error = /var/log/mysql/error.log
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2
log_queries_not_using_indexes = 1

# ── Validacion de contrasenas ──
# MySQL: validate_password plugin
# MariaDB: simple_password_check / cracklib_password_check

[mysql]
# Deshabilitar LOAD DATA LOCAL en cliente
local-infile = 0
EOFMYSQL
        log_change "Creado" "${MYSQL_CONFD}/99-securizar-hardening.cnf"

        # Crear directorio de logs si no existe
        mkdir -p /var/log/mysql
        if id mysql &>/dev/null; then
            chown mysql:mysql /var/log/mysql
        fi
        chmod 750 /var/log/mysql
        log_change "Configurado" "/var/log/mysql con permisos 750"

        # Crear directorio secure-file-priv si no existe
        if [[ ! -d /var/lib/mysql-files ]]; then
            mkdir -p /var/lib/mysql-files
            if id mysql &>/dev/null; then
                chown mysql:mysql /var/lib/mysql-files
            fi
            chmod 750 /var/lib/mysql-files
            log_change "Creado" "/var/lib/mysql-files (secure-file-priv)"
        fi

        # Intentar activar plugin de validacion de contrasenas
        log_info "Para activar plugin de validacion de contrasenas, ejecuta:"
        if [[ "$MYSQL_TYPE" == "MariaDB" ]]; then
            echo "  INSTALL SONAME 'simple_password_check';"
            echo "  SET GLOBAL simple_password_check_digits=1;"
            echo "  SET GLOBAL simple_password_check_letters_same_case=1;"
            echo "  SET GLOBAL simple_password_check_other_characters=1;"
        else
            echo "  INSTALL PLUGIN validate_password SONAME 'validate_password.so';"
            echo "  SET GLOBAL validate_password_policy=STRONG;"
            echo "  SET GLOBAL validate_password_length=14;"
        fi

        # Crear script de auditoria MySQL
        cat > /usr/local/bin/auditar-mysql.sh << 'EOFMYSQLAUDIT'
#!/bin/bash
# ============================================================
# Auditoria de seguridad MySQL/MariaDB
# Generado por securizar - Modulo 48
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  AUDITORIA DE SEGURIDAD MYSQL/MARIADB${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

score=0
total=0

check() {
    local desc="$1" result="$2"
    ((total++))
    if [[ "$result" == "OK" ]]; then
        echo -e "  ${GREEN}[OK]${NC} $desc"
        ((score++))
    elif [[ "$result" == "WARN" ]]; then
        echo -e "  ${YELLOW}[!!]${NC} $desc"
    else
        echo -e "  ${RED}[XX]${NC} $desc"
    fi
}

# Verificar si MySQL/MariaDB esta accesible
if ! command -v mysql &>/dev/null && ! command -v mariadb &>/dev/null; then
    echo -e "${RED}Cliente MySQL/MariaDB no encontrado${NC}"
    exit 1
fi

MYSQL_CMD="mysql"
command -v mariadb &>/dev/null && MYSQL_CMD="mariadb"

echo -e "${CYAN}── Configuracion de red ──${NC}"

# bind-address
bind_addr=$($MYSQL_CMD -N -e "SHOW VARIABLES LIKE 'bind_address'" 2>/dev/null | awk '{print $2}' || echo "desconocido")
[[ "$bind_addr" == "127.0.0.1" || "$bind_addr" == "localhost" ]] && check "bind-address restringido: $bind_addr" "OK" || check "bind-address: $bind_addr (deberia ser 127.0.0.1)" "FAIL"

echo -e "\n${CYAN}── Seguridad ──${NC}"

# local_infile
local_infile=$($MYSQL_CMD -N -e "SHOW VARIABLES LIKE 'local_infile'" 2>/dev/null | awk '{print $2}' || echo "desconocido")
[[ "$local_infile" == "OFF" ]] && check "local_infile deshabilitado" "OK" || check "local_infile: $local_infile (deberia ser OFF)" "FAIL"

# secure_file_priv
secure_fp=$($MYSQL_CMD -N -e "SHOW VARIABLES LIKE 'secure_file_priv'" 2>/dev/null | awk '{print $2}' || echo "")
[[ -n "$secure_fp" && "$secure_fp" != "NULL" ]] && check "secure_file_priv configurado: $secure_fp" "OK" || check "secure_file_priv no configurado" "WARN"

# skip_name_resolve
skip_name=$($MYSQL_CMD -N -e "SHOW VARIABLES LIKE 'skip_name_resolve'" 2>/dev/null | awk '{print $2}' || echo "desconocido")
[[ "$skip_name" == "ON" ]] && check "skip_name_resolve habilitado" "OK" || check "skip_name_resolve deshabilitado" "WARN"

echo -e "\n${CYAN}── Logging ──${NC}"

# general_log
gen_log=$($MYSQL_CMD -N -e "SHOW VARIABLES LIKE 'general_log'" 2>/dev/null | awk '{print $2}' || echo "desconocido")
[[ "$gen_log" == "ON" ]] && check "general_log habilitado" "OK" || check "general_log deshabilitado" "WARN"

# slow_query_log
slow_log=$($MYSQL_CMD -N -e "SHOW VARIABLES LIKE 'slow_query_log'" 2>/dev/null | awk '{print $2}' || echo "desconocido")
[[ "$slow_log" == "ON" ]] && check "slow_query_log habilitado" "OK" || check "slow_query_log deshabilitado" "WARN"

echo -e "\n${CYAN}── Usuarios ──${NC}"

# Usuarios sin contrasena
no_pass=$($MYSQL_CMD -N -e "SELECT user,host FROM mysql.user WHERE authentication_string='' OR authentication_string IS NULL" 2>/dev/null | wc -l || echo "0")
[[ "$no_pass" -eq 0 ]] && check "Sin usuarios sin contrasena" "OK" || check "$no_pass usuarios sin contrasena" "FAIL"

# Usuarios root remotos
root_remote=$($MYSQL_CMD -N -e "SELECT host FROM mysql.user WHERE user='root' AND host NOT IN ('localhost','127.0.0.1','::1')" 2>/dev/null | wc -l || echo "0")
[[ "$root_remote" -eq 0 ]] && check "Sin acceso root remoto" "OK" || check "$root_remote accesos root remotos" "FAIL"

# Base de datos test
test_db=$($MYSQL_CMD -N -e "SHOW DATABASES LIKE 'test'" 2>/dev/null | wc -l || echo "0")
[[ "$test_db" -eq 0 ]] && check "Base de datos test eliminada" "OK" || check "Base de datos test presente (eliminar)" "WARN"

# Resumen
echo ""
echo -e "${BOLD}── Resultado ──${NC}"
pct=$((score * 100 / total))
if [[ $pct -ge 80 ]]; then
    echo -e "  Puntuacion: ${GREEN}${score}/${total} (${pct}%) - BUENO${NC}"
elif [[ $pct -ge 50 ]]; then
    echo -e "  Puntuacion: ${YELLOW}${score}/${total} (${pct}%) - MEJORABLE${NC}"
else
    echo -e "  Puntuacion: ${RED}${score}/${total} (${pct}%) - DEFICIENTE${NC}"
fi
EOFMYSQLAUDIT
        chmod +x /usr/local/bin/auditar-mysql.sh
        log_change "Creado" "/usr/local/bin/auditar-mysql.sh"

        # Recargar MySQL/MariaDB si esta activo
        for svc in mysql mariadb mysqld; do
            if systemctl is-active "$svc" &>/dev/null; then
                systemctl restart "$svc" 2>/dev/null || log_warn "No se pudo reiniciar $svc"
                log_info "$svc reiniciado con nueva configuracion"
                break
            fi
        done

        log_info "Hardening de $MYSQL_TYPE completado"
    else
        log_skip "Hardening de $MYSQL_TYPE"
    fi
else
    log_info "MySQL/MariaDB no detectado - omitiendo seccion"
    log_skip "MySQL/MariaDB no instalado"
fi

# ============================================================
# S3: REDIS HARDENING
# ============================================================
log_section "S3: REDIS HARDENING"

echo "Hardening de Redis:"
echo "  - requirepass con contrasena fuerte generada"
echo "  - bind 127.0.0.1 ::1, protected-mode yes"
echo "  - rename-command para comandos peligrosos"
echo "  - maxmemory-policy, TLS si Redis 6+"
echo "  - Configuracion ACL"
echo ""

if detect_redis; then
    log_info "Redis detectado en el sistema"

    if check_executable "/usr/local/bin/auditar-redis.sh"; then
        log_already "Hardening Redis (auditar-redis.sh ya instalado)"
    elif ask "¿Aplicar hardening de Redis?"; then

        REDIS_CONF=$(find_redis_conf)

        if [[ -n "$REDIS_CONF" ]]; then
            cp "$REDIS_CONF" "$BACKUP_DIR/"
            log_change "Backup" "$REDIS_CONF"

            # Generar contrasena fuerte para Redis
            REDIS_PASS=$(generate_strong_password 32)
            log_info "Contrasena generada para Redis (guardada en /etc/securizar/redis-credentials)"

            # Guardar credenciales de forma segura
            cat > /etc/securizar/redis-credentials << EOFREDISCRED
# Credenciales Redis - Generado por securizar
# Fecha: $(date '+%Y-%m-%d %H:%M:%S')
# PROTEGER este archivo
REDIS_PASSWORD=${REDIS_PASS}
EOFREDISCRED
            chmod 600 /etc/securizar/redis-credentials
            log_change "Creado" "/etc/securizar/redis-credentials (modo 600)"

            # requirepass
            if grep -q "^#\?\s*requirepass\s" "$REDIS_CONF"; then
                sed -i "s/^#\?\s*requirepass\s.*/requirepass ${REDIS_PASS}/" "$REDIS_CONF"
            else
                echo "requirepass ${REDIS_PASS}" >> "$REDIS_CONF"
            fi
            log_change "Configurado" "Redis: requirepass con contrasena fuerte"

            # bind 127.0.0.1 ::1
            if grep -q "^#\?\s*bind\s" "$REDIS_CONF"; then
                sed -i "s/^#\?\s*bind\s.*/bind 127.0.0.1 ::1/" "$REDIS_CONF"
            else
                echo "bind 127.0.0.1 ::1" >> "$REDIS_CONF"
            fi
            log_change "Configurado" "Redis: bind 127.0.0.1 ::1"

            # protected-mode yes
            if grep -q "^#\?\s*protected-mode\s" "$REDIS_CONF"; then
                sed -i "s/^#\?\s*protected-mode\s.*/protected-mode yes/" "$REDIS_CONF"
            else
                echo "protected-mode yes" >> "$REDIS_CONF"
            fi
            log_change "Configurado" "Redis: protected-mode yes"

            # rename-command para comandos peligrosos
            for cmd in FLUSHALL FLUSHDB CONFIG DEBUG SHUTDOWN; do
                renamed="SECURIZAR_${cmd}_$(openssl rand -hex 4 2>/dev/null || echo 'disabled')"
                if ! grep -q "^rename-command ${cmd}" "$REDIS_CONF"; then
                    echo "rename-command ${cmd} ${renamed}" >> "$REDIS_CONF"
                    log_change "Configurado" "Redis: rename-command ${cmd} -> ${renamed}"
                fi
            done

            # Guardar nombres renombrados
            grep "^rename-command" "$REDIS_CONF" > /etc/securizar/redis-renamed-commands 2>/dev/null || true
            chmod 600 /etc/securizar/redis-renamed-commands 2>/dev/null || true

            # maxmemory-policy
            if grep -q "^#\?\s*maxmemory-policy\s" "$REDIS_CONF"; then
                sed -i "s/^#\?\s*maxmemory-policy\s.*/maxmemory-policy allkeys-lru/" "$REDIS_CONF"
            else
                echo "maxmemory-policy allkeys-lru" >> "$REDIS_CONF"
            fi
            log_change "Configurado" "Redis: maxmemory-policy allkeys-lru"

            # Detectar version de Redis para TLS
            REDIS_VERSION=$(redis-server --version 2>/dev/null | grep -oP 'v=\K[0-9]+' || echo "0")
            if [[ "$REDIS_VERSION" -ge 6 ]]; then
                log_info "Redis 6+ detectado - TLS disponible"
                echo "# TLS - Descomentar y configurar certificados:" >> "$REDIS_CONF"
                echo "# tls-port 6380" >> "$REDIS_CONF"
                echo "# tls-cert-file /etc/redis/tls/redis.crt" >> "$REDIS_CONF"
                echo "# tls-key-file /etc/redis/tls/redis.key" >> "$REDIS_CONF"
                echo "# tls-ca-cert-file /etc/redis/tls/ca.crt" >> "$REDIS_CONF"
                echo "# tls-auth-clients optional" >> "$REDIS_CONF"
                log_change "Anadido" "Redis: plantilla TLS (requiere configurar certificados)"

                # ACL configuration
                echo "" >> "$REDIS_CONF"
                echo "# ACL - Ejemplo de configuracion:" >> "$REDIS_CONF"
                echo "# user default on ~* &* +@all" >> "$REDIS_CONF"
                echo "# user admin on >admin_password ~* &* +@all" >> "$REDIS_CONF"
                echo "# user readonly on >readonly_password ~* &* +@read" >> "$REDIS_CONF"
                log_change "Anadido" "Redis: plantilla ACL"
            fi

            # Deshabilitar comandos peligrosos adicionales
            if ! grep -q "^rename-command KEYS" "$REDIS_CONF"; then
                echo "rename-command KEYS SECURIZAR_KEYS_$(openssl rand -hex 4 2>/dev/null || echo 'disabled')" >> "$REDIS_CONF"
                log_change "Configurado" "Redis: rename-command KEYS (operacion costosa)"
            fi

        else
            log_warn "No se encontro redis.conf - verifica la instalacion"
        fi

        # Crear script de auditoria Redis
        cat > /usr/local/bin/auditar-redis.sh << 'EOFREDISAUDIT'
#!/bin/bash
# ============================================================
# Auditoria de seguridad Redis
# Generado por securizar - Modulo 48
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  AUDITORIA DE SEGURIDAD REDIS${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

score=0
total=0

check() {
    local desc="$1" result="$2"
    ((total++))
    if [[ "$result" == "OK" ]]; then
        echo -e "  ${GREEN}[OK]${NC} $desc"
        ((score++))
    elif [[ "$result" == "WARN" ]]; then
        echo -e "  ${YELLOW}[!!]${NC} $desc"
    else
        echo -e "  ${RED}[XX]${NC} $desc"
    fi
}

REDIS_CONF=""
for f in /etc/redis/redis.conf /etc/redis.conf /etc/redis/6379.conf; do
    [[ -f "$f" ]] && REDIS_CONF="$f" && break
done

if [[ -z "$REDIS_CONF" ]]; then
    echo -e "${RED}No se encontro redis.conf${NC}"
    exit 1
fi

echo -e "${CYAN}── Configuracion: $REDIS_CONF ──${NC}"

# requirepass
has_pass=$(grep -cE "^requirepass\s+\S+" "$REDIS_CONF" 2>/dev/null || echo "0")
[[ "$has_pass" -gt 0 ]] && check "Contrasena configurada (requirepass)" "OK" || check "Sin contrasena (requirepass)" "FAIL"

# bind
bind_val=$(grep -E "^bind\s" "$REDIS_CONF" 2>/dev/null | head -1 || echo "")
if [[ -n "$bind_val" ]]; then
    if echo "$bind_val" | grep -qv "0.0.0.0"; then
        check "bind restringido: $bind_val" "OK"
    else
        check "bind incluye 0.0.0.0 - abierto a red" "FAIL"
    fi
else
    check "bind no configurado (escucha en todas las interfaces)" "FAIL"
fi

# protected-mode
prot_mode=$(grep -E "^protected-mode\s" "$REDIS_CONF" 2>/dev/null | awk '{print $2}' || echo "no")
[[ "$prot_mode" == "yes" ]] && check "protected-mode habilitado" "OK" || check "protected-mode deshabilitado" "FAIL"

# rename-command
renamed=$(grep -cE "^rename-command\s" "$REDIS_CONF" 2>/dev/null || echo "0")
[[ "$renamed" -gt 0 ]] && check "$renamed comandos renombrados" "OK" || check "Sin rename-command (comandos peligrosos accesibles)" "WARN"

# maxmemory-policy
maxmem=$(grep -E "^maxmemory-policy\s" "$REDIS_CONF" 2>/dev/null | awk '{print $2}' || echo "noeviction")
[[ "$maxmem" != "noeviction" ]] && check "maxmemory-policy: $maxmem" "OK" || check "maxmemory-policy: noeviction (configurar politica)" "WARN"

# Redis corriendo como root
redis_user=$(ps -o user= -p "$(pgrep redis-server 2>/dev/null | head -1)" 2>/dev/null || echo "desconocido")
if [[ "$redis_user" == "redis" || "$redis_user" == "nobody" ]]; then
    check "Redis corriendo como usuario: $redis_user" "OK"
elif [[ "$redis_user" == "root" ]]; then
    check "Redis corriendo como root - PELIGROSO" "FAIL"
else
    check "Usuario de Redis: $redis_user" "WARN"
fi

# Resumen
echo ""
echo -e "${BOLD}── Resultado ──${NC}"
if [[ $total -gt 0 ]]; then
    pct=$((score * 100 / total))
    if [[ $pct -ge 80 ]]; then
        echo -e "  Puntuacion: ${GREEN}${score}/${total} (${pct}%) - BUENO${NC}"
    elif [[ $pct -ge 50 ]]; then
        echo -e "  Puntuacion: ${YELLOW}${score}/${total} (${pct}%) - MEJORABLE${NC}"
    else
        echo -e "  Puntuacion: ${RED}${score}/${total} (${pct}%) - DEFICIENTE${NC}"
    fi
fi
EOFREDISAUDIT
        chmod +x /usr/local/bin/auditar-redis.sh
        log_change "Creado" "/usr/local/bin/auditar-redis.sh"

        # Recargar Redis si esta activo
        for svc in redis redis-server redis-sentinel; do
            if systemctl is-active "$svc" &>/dev/null; then
                systemctl restart "$svc" 2>/dev/null || log_warn "No se pudo reiniciar $svc"
                log_info "$svc reiniciado con nueva configuracion"
                break
            fi
        done

        log_info "Hardening de Redis completado"
    else
        log_skip "Hardening de Redis"
    fi
else
    log_info "Redis no detectado - omitiendo seccion"
    log_skip "Redis no instalado"
fi

# ============================================================
# S4: MONGODB HARDENING
# ============================================================
log_section "S4: MONGODB HARDENING"

echo "Hardening de MongoDB:"
echo "  - security.authorization=enabled"
echo "  - net.bindIp=127.0.0.1"
echo "  - net.ssl.mode=requireSSL"
echo "  - authenticationMechanisms=SCRAM-SHA-256"
echo "  - Audit log, deshabilitar JavaScript"
echo ""

if detect_mongodb; then
    log_info "MongoDB detectado en el sistema"

    if check_executable "/usr/local/bin/auditar-mongodb.sh"; then
        log_already "Hardening MongoDB (auditar-mongodb.sh ya instalado)"
    elif ask "¿Aplicar hardening de MongoDB?"; then

        MONGOD_CONF=$(find_mongod_conf)

        if [[ -n "$MONGOD_CONF" ]]; then
            cp "$MONGOD_CONF" "$BACKUP_DIR/"
            log_change "Backup" "$MONGOD_CONF"

            log_info "Aplicando hardening a $MONGOD_CONF..."

            # Verificar formato YAML
            if grep -q "^security:" "$MONGOD_CONF" 2>/dev/null; then
                # Ya tiene seccion security - modificar existente
                if ! grep -q "authorization:" "$MONGOD_CONF"; then
                    sed -i '/^security:/a\  authorization: enabled' "$MONGOD_CONF"
                else
                    sed -i 's/authorization:.*/authorization: enabled/' "$MONGOD_CONF"
                fi
                if ! grep -q "javascriptEnabled:" "$MONGOD_CONF"; then
                    sed -i '/^security:/a\  javascriptEnabled: false' "$MONGOD_CONF"
                else
                    sed -i 's/javascriptEnabled:.*/javascriptEnabled: false/' "$MONGOD_CONF"
                fi
            else
                cat >> "$MONGOD_CONF" << 'EOFMONGOSEC'

security:
  authorization: enabled
  javascriptEnabled: false
EOFMONGOSEC
            fi
            log_change "Configurado" "MongoDB: security.authorization = enabled"
            log_change "Configurado" "MongoDB: security.javascriptEnabled = false"

            # net.bindIp
            if grep -q "^net:" "$MONGOD_CONF" 2>/dev/null; then
                if grep -q "bindIp:" "$MONGOD_CONF"; then
                    sed -i 's/bindIp:.*/bindIp: 127.0.0.1/' "$MONGOD_CONF"
                else
                    sed -i '/^net:/a\  bindIp: 127.0.0.1' "$MONGOD_CONF"
                fi
            else
                cat >> "$MONGOD_CONF" << 'EOFMONGONET'

net:
  bindIp: 127.0.0.1
  port: 27017
EOFMONGONET
            fi
            log_change "Configurado" "MongoDB: net.bindIp = 127.0.0.1"

            # TLS/SSL
            if grep -q "^net:" "$MONGOD_CONF" 2>/dev/null; then
                if ! grep -q "ssl:" "$MONGOD_CONF" && ! grep -q "tls:" "$MONGOD_CONF"; then
                    # Anadir plantilla TLS
                    cat >> "$MONGOD_CONF" << 'EOFMONGOTLS'

# TLS - Descomentar y configurar certificados:
#  tls:
#    mode: requireTLS
#    certificateKeyFile: /etc/ssl/mongodb/server.pem
#    CAFile: /etc/ssl/mongodb/ca.pem
EOFMONGOTLS
                    log_change "Anadido" "MongoDB: plantilla TLS (requiere configurar certificados)"
                fi
            fi

            # Authentication mechanism
            if grep -q "^setParameter:" "$MONGOD_CONF" 2>/dev/null; then
                if ! grep -q "authenticationMechanisms:" "$MONGOD_CONF"; then
                    sed -i '/^setParameter:/a\  authenticationMechanisms: SCRAM-SHA-256' "$MONGOD_CONF"
                fi
            else
                cat >> "$MONGOD_CONF" << 'EOFMONGOPARAM'

setParameter:
  authenticationMechanisms: SCRAM-SHA-256
EOFMONGOPARAM
            fi
            log_change "Configurado" "MongoDB: authenticationMechanisms = SCRAM-SHA-256"

            # Audit log
            if ! grep -q "auditLog:" "$MONGOD_CONF"; then
                cat >> "$MONGOD_CONF" << 'EOFMONGOAUDIT'

# Audit log (requiere MongoDB Enterprise o Percona Server for MongoDB):
#auditLog:
#  destination: file
#  format: JSON
#  path: /var/log/mongodb/audit.json
EOFMONGOAUDIT
                log_change "Anadido" "MongoDB: plantilla auditLog"
            fi

            # Logging
            if ! grep -q "^systemLog:" "$MONGOD_CONF"; then
                cat >> "$MONGOD_CONF" << 'EOFMONGOLOG'

systemLog:
  destination: file
  logAppend: true
  path: /var/log/mongodb/mongod.log
  verbosity: 1
EOFMONGOLOG
                log_change "Configurado" "MongoDB: systemLog"
            fi

        else
            log_warn "No se encontro mongod.conf - verifica la instalacion"
        fi

        # Crear script de auditoria MongoDB
        cat > /usr/local/bin/auditar-mongodb.sh << 'EOFMONGODBAUDIT'
#!/bin/bash
# ============================================================
# Auditoria de seguridad MongoDB
# Generado por securizar - Modulo 48
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  AUDITORIA DE SEGURIDAD MONGODB${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

score=0
total=0

check() {
    local desc="$1" result="$2"
    ((total++))
    if [[ "$result" == "OK" ]]; then
        echo -e "  ${GREEN}[OK]${NC} $desc"
        ((score++))
    elif [[ "$result" == "WARN" ]]; then
        echo -e "  ${YELLOW}[!!]${NC} $desc"
    else
        echo -e "  ${RED}[XX]${NC} $desc"
    fi
}

MONGOD_CONF=""
for f in /etc/mongod.conf /etc/mongodb.conf /etc/mongos.conf; do
    [[ -f "$f" ]] && MONGOD_CONF="$f" && break
done

if [[ -z "$MONGOD_CONF" ]]; then
    echo -e "${RED}No se encontro mongod.conf${NC}"
    exit 1
fi

echo -e "${CYAN}── Configuracion: $MONGOD_CONF ──${NC}"

# Authorization
auth=$(grep -E "^\s*authorization:" "$MONGOD_CONF" 2>/dev/null | awk '{print $2}' || echo "disabled")
[[ "$auth" == "enabled" ]] && check "Autorizacion habilitada" "OK" || check "Autorizacion: $auth (habilitar)" "FAIL"

# bindIp
bind_ip=$(grep -E "^\s*bindIp:" "$MONGOD_CONF" 2>/dev/null | awk '{print $2}' || echo "0.0.0.0")
[[ "$bind_ip" == "127.0.0.1" || "$bind_ip" == "localhost" ]] && check "bindIp restringido: $bind_ip" "OK" || check "bindIp: $bind_ip (deberia ser 127.0.0.1)" "FAIL"

# JavaScript
js_enabled=$(grep -E "^\s*javascriptEnabled:" "$MONGOD_CONF" 2>/dev/null | awk '{print $2}' || echo "true")
[[ "$js_enabled" == "false" ]] && check "JavaScript deshabilitado" "OK" || check "JavaScript habilitado (deshabilitar)" "WARN"

# Authentication mechanism
auth_mech=$(grep -E "^\s*authenticationMechanisms:" "$MONGOD_CONF" 2>/dev/null | awk '{print $2}' || echo "no configurado")
[[ "$auth_mech" == *"SCRAM-SHA-256"* ]] && check "Auth mechanism: SCRAM-SHA-256" "OK" || check "Auth mechanism: $auth_mech" "WARN"

# Log file
has_log=$(grep -cE "^\s*path:" "$MONGOD_CONF" 2>/dev/null || echo "0")
[[ "$has_log" -gt 0 ]] && check "Logging a archivo configurado" "OK" || check "Logging a archivo no configurado" "WARN"

# Verificar si mongod corre como root
mongo_user=$(ps -o user= -p "$(pgrep mongod 2>/dev/null | head -1)" 2>/dev/null || echo "desconocido")
if [[ "$mongo_user" == "mongod" || "$mongo_user" == "mongodb" ]]; then
    check "MongoDB corriendo como usuario: $mongo_user" "OK"
elif [[ "$mongo_user" == "root" ]]; then
    check "MongoDB corriendo como root - PELIGROSO" "FAIL"
elif [[ "$mongo_user" != "desconocido" ]]; then
    check "Usuario de MongoDB: $mongo_user" "WARN"
fi

# Resumen
echo ""
echo -e "${BOLD}── Resultado ──${NC}"
if [[ $total -gt 0 ]]; then
    pct=$((score * 100 / total))
    if [[ $pct -ge 80 ]]; then
        echo -e "  Puntuacion: ${GREEN}${score}/${total} (${pct}%) - BUENO${NC}"
    elif [[ $pct -ge 50 ]]; then
        echo -e "  Puntuacion: ${YELLOW}${score}/${total} (${pct}%) - MEJORABLE${NC}"
    else
        echo -e "  Puntuacion: ${RED}${score}/${total} (${pct}%) - DEFICIENTE${NC}"
    fi
fi
EOFMONGODBAUDIT
        chmod +x /usr/local/bin/auditar-mongodb.sh
        log_change "Creado" "/usr/local/bin/auditar-mongodb.sh"

        # Recargar MongoDB si esta activo
        if systemctl is-active mongod &>/dev/null; then
            systemctl restart mongod 2>/dev/null || log_warn "No se pudo reiniciar mongod"
            log_info "MongoDB reiniciado con nueva configuracion"
        fi

        log_info "Hardening de MongoDB completado"
    else
        log_skip "Hardening de MongoDB"
    fi
else
    log_info "MongoDB no detectado - omitiendo seccion"
    log_skip "MongoDB no instalado"
fi

# ============================================================
# S5: DATABASE AUTHENTICATION & ACCESS CONTROL
# ============================================================
log_section "S5: AUTENTICACION Y CONTROL DE ACCESO DE BASES DE DATOS"

echo "Control de acceso cross-database:"
echo "  - Verificar credenciales por defecto"
echo "  - Detectar cuentas sin contrasena"
echo "  - Auditar privilegios de usuario (GRANT ALL)"
echo "  - Verificacion de acceso basado en roles"
echo ""

if check_executable "/usr/local/bin/auditar-acceso-db.sh"; then
    log_already "Autenticacion DB (auditar-acceso-db.sh ya instalado)"
elif ask "¿Auditar autenticacion y control de acceso de bases de datos?"; then

    # Crear script de auditoria de acceso
    cat > /usr/local/bin/auditar-acceso-db.sh << 'EOFACCESSAUDIT'
#!/bin/bash
# ============================================================
# Auditoria de autenticacion y control de acceso de bases de datos
# Generado por securizar - Modulo 48
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  AUDITORIA DE ACCESO A BASES DE DATOS${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

issues=0

# ── PostgreSQL ──
if command -v psql &>/dev/null; then
    echo -e "${CYAN}── PostgreSQL ──${NC}"

    # Verificar cuentas sin contrasena
    echo -e "  ${BOLD}Cuentas sin contrasena:${NC}"
    no_pass=$(sudo -u postgres psql -t -c "SELECT usename FROM pg_shadow WHERE passwd IS NULL OR passwd = ''" 2>/dev/null || echo "")
    if [[ -n "$no_pass" && "$no_pass" != *"0 rows"* ]]; then
        echo -e "  ${RED}[XX]${NC} Cuentas sin contrasena encontradas:"
        echo "$no_pass" | while read -r user; do
            [[ -n "$user" ]] && echo -e "    - $user"
        done
        ((issues++)) || true
    else
        echo -e "  ${GREEN}[OK]${NC} Todas las cuentas tienen contrasena"
    fi

    # Verificar superusers
    echo -e "  ${BOLD}Superusuarios:${NC}"
    superusers=$(sudo -u postgres psql -t -c "SELECT usename FROM pg_user WHERE usesuper = true" 2>/dev/null || echo "")
    if [[ -n "$superusers" ]]; then
        echo "$superusers" | while read -r user; do
            [[ -n "$user" ]] && echo -e "    - ${YELLOW}$user${NC} (superusuario)"
        done
    fi

    # Verificar usuarios con CREATEDB
    echo -e "  ${BOLD}Usuarios con CREATEDB:${NC}"
    createdb_users=$(sudo -u postgres psql -t -c "SELECT usename FROM pg_user WHERE usecreatedb = true AND usesuper = false" 2>/dev/null || echo "")
    if [[ -n "$createdb_users" ]]; then
        echo "$createdb_users" | while read -r user; do
            [[ -n "$user" ]] && echo -e "    - ${YELLOW}$user${NC} (CREATEDB)"
        done
    fi

    # Verificar pg_hba.conf trust entries
    echo -e "  ${BOLD}Metodos de autenticacion (pg_hba.conf):${NC}"
    PG_HBA=""
    for d in /etc/postgresql/*/main /var/lib/pgsql/data /var/lib/postgresql/*/data; do
        [[ -f "$d/pg_hba.conf" ]] && PG_HBA="$d/pg_hba.conf" && break
    done
    if [[ -n "$PG_HBA" ]]; then
        trust_count=$(grep -cE '^\s*(local|host)\s+.*\s+trust\s*$' "$PG_HBA" 2>/dev/null || echo "0")
        if [[ "$trust_count" -gt 0 ]]; then
            echo -e "  ${RED}[XX]${NC} $trust_count entradas con metodo 'trust' en pg_hba.conf"
            ((issues++)) || true
        else
            echo -e "  ${GREEN}[OK]${NC} Sin entradas 'trust' en pg_hba.conf"
        fi
    fi
    echo ""
fi

# ── MySQL/MariaDB ──
MYSQL_CMD=""
command -v mariadb &>/dev/null && MYSQL_CMD="mariadb"
command -v mysql &>/dev/null && MYSQL_CMD="mysql"

if [[ -n "$MYSQL_CMD" ]]; then
    echo -e "${CYAN}── MySQL/MariaDB ──${NC}"

    # Cuentas sin contrasena
    echo -e "  ${BOLD}Cuentas sin contrasena:${NC}"
    no_pass=$($MYSQL_CMD -N -e "SELECT user,host FROM mysql.user WHERE authentication_string='' OR authentication_string IS NULL" 2>/dev/null || echo "")
    if [[ -n "$no_pass" ]]; then
        echo -e "  ${RED}[XX]${NC} Cuentas sin contrasena:"
        echo "$no_pass" | while IFS=$'\t' read -r user host; do
            [[ -n "$user" ]] && echo -e "    - ${user}@${host}"
        done
        ((issues++)) || true
    else
        echo -e "  ${GREEN}[OK]${NC} Todas las cuentas tienen contrasena"
    fi

    # Cuentas anonimas
    echo -e "  ${BOLD}Cuentas anonimas:${NC}"
    anon=$($MYSQL_CMD -N -e "SELECT user,host FROM mysql.user WHERE user=''" 2>/dev/null || echo "")
    if [[ -n "$anon" ]]; then
        echo -e "  ${RED}[XX]${NC} Cuentas anonimas encontradas (eliminar)"
        ((issues++)) || true
    else
        echo -e "  ${GREEN}[OK]${NC} Sin cuentas anonimas"
    fi

    # GRANT ALL
    echo -e "  ${BOLD}Usuarios con GRANT ALL:${NC}"
    grant_all=$($MYSQL_CMD -N -e "SELECT grantee FROM information_schema.user_privileges WHERE privilege_type='SUPER' OR privilege_type='ALL PRIVILEGES'" 2>/dev/null || echo "")
    if [[ -n "$grant_all" ]]; then
        echo "$grant_all" | sort -u | while read -r grantee; do
            [[ -n "$grantee" ]] && echo -e "    - ${YELLOW}$grantee${NC}"
        done
    fi

    # Root accesible remotamente
    echo -e "  ${BOLD}Acceso root remoto:${NC}"
    root_remote=$($MYSQL_CMD -N -e "SELECT host FROM mysql.user WHERE user='root' AND host NOT IN ('localhost','127.0.0.1','::1')" 2>/dev/null || echo "")
    if [[ -n "$root_remote" ]]; then
        echo -e "  ${RED}[XX]${NC} Root accesible remotamente desde: $root_remote"
        ((issues++)) || true
    else
        echo -e "  ${GREEN}[OK]${NC} Root solo accesible localmente"
    fi
    echo ""
fi

# ── Redis ──
if command -v redis-cli &>/dev/null; then
    echo -e "${CYAN}── Redis ──${NC}"

    # Verificar si requirepass esta configurado
    REDIS_CONF=""
    for f in /etc/redis/redis.conf /etc/redis.conf /etc/redis/6379.conf; do
        [[ -f "$f" ]] && REDIS_CONF="$f" && break
    done
    if [[ -n "$REDIS_CONF" ]]; then
        has_pass=$(grep -cE "^requirepass\s+\S+" "$REDIS_CONF" 2>/dev/null || echo "0")
        if [[ "$has_pass" -gt 0 ]]; then
            echo -e "  ${GREEN}[OK]${NC} Contrasena configurada"
        else
            echo -e "  ${RED}[XX]${NC} Sin contrasena configurada"
            ((issues++)) || true
        fi
    fi

    # Verificar si se puede acceder sin contrasena
    if redis-cli ping 2>/dev/null | grep -q "PONG"; then
        echo -e "  ${RED}[XX]${NC} Redis accesible sin autenticacion"
        ((issues++)) || true
    else
        echo -e "  ${GREEN}[OK]${NC} Redis requiere autenticacion"
    fi
    echo ""
fi

# ── MongoDB ──
if command -v mongosh &>/dev/null || command -v mongo &>/dev/null; then
    echo -e "${CYAN}── MongoDB ──${NC}"

    MONGO_CMD="mongosh"
    command -v mongosh &>/dev/null || MONGO_CMD="mongo"

    MONGOD_CONF=""
    for f in /etc/mongod.conf /etc/mongodb.conf; do
        [[ -f "$f" ]] && MONGOD_CONF="$f" && break
    done

    if [[ -n "$MONGOD_CONF" ]]; then
        auth=$(grep -E "^\s*authorization:" "$MONGOD_CONF" 2>/dev/null | awk '{print $2}' || echo "disabled")
        if [[ "$auth" == "enabled" ]]; then
            echo -e "  ${GREEN}[OK]${NC} Autorizacion habilitada"
        else
            echo -e "  ${RED}[XX]${NC} Autorizacion deshabilitada"
            ((issues++)) || true
        fi
    fi
    echo ""
fi

# Resumen
echo -e "${BOLD}══════════════════════════════════════════${NC}"
if [[ "$issues" -eq 0 ]]; then
    echo -e "  ${GREEN}Sin problemas criticos de acceso detectados${NC}"
else
    echo -e "  ${RED}$issues problemas de acceso detectados - revisar${NC}"
fi
EOFACCESSAUDIT
    chmod +x /usr/local/bin/auditar-acceso-db.sh
    log_change "Creado" "/usr/local/bin/auditar-acceso-db.sh"

    # Ejecutar verificacion basica
    log_info "Verificando credenciales por defecto..."

    # PostgreSQL: verificar si 'postgres' tiene contrasena por defecto
    if command -v psql &>/dev/null; then
        if PGPASSWORD=postgres psql -U postgres -h 127.0.0.1 -c "SELECT 1" &>/dev/null; then
            log_warn "PostgreSQL: usuario 'postgres' accesible con contrasena 'postgres' - CAMBIAR INMEDIATAMENTE"
        else
            log_info "PostgreSQL: credencial por defecto 'postgres' no funciona (bien)"
        fi
    fi

    # MySQL: verificar root sin contrasena
    if command -v mysql &>/dev/null || command -v mariadb &>/dev/null; then
        MYSQL_CMD="mysql"
        command -v mariadb &>/dev/null && MYSQL_CMD="mariadb"
        if $MYSQL_CMD -u root -e "SELECT 1" &>/dev/null; then
            log_warn "MySQL/MariaDB: root accesible sin contrasena desde localhost - revisar"
        fi
    fi

    # MongoDB: verificar acceso anonimo
    if command -v mongosh &>/dev/null; then
        if mongosh --quiet --eval "db.adminCommand('listDatabases')" &>/dev/null; then
            log_warn "MongoDB: accesible sin autenticacion - HABILITAR authorization"
        fi
    fi

    log_info "Auditoria de acceso completada"
    log_info "Ejecuta: auditar-acceso-db.sh para auditoria completa"
else
    log_skip "Auditoria de autenticacion y control de acceso"
fi

# ============================================================
# S6: DATABASE ENCRYPTION (AT REST & IN TRANSIT)
# ============================================================
log_section "S6: CIFRADO DE BASES DE DATOS (REPOSO Y TRANSITO)"

echo "Cifrado de bases de datos:"
echo "  - TLS para cada motor de base de datos"
echo "  - Cifrado en reposo: pgcrypto, InnoDB, WiredTiger"
echo "  - Gestion de claves"
echo ""

if check_executable "/usr/local/bin/verificar-cifrado-db.sh"; then
    log_already "Cifrado DB (verificar-cifrado-db.sh ya instalado)"
elif ask "¿Configurar cifrado de bases de datos?"; then

    # Crear script de verificacion de cifrado
    cat > /usr/local/bin/verificar-cifrado-db.sh << 'EOFCIFRADODB'
#!/bin/bash
# ============================================================
# Verificacion de cifrado de bases de datos
# Generado por securizar - Modulo 48
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  VERIFICACION DE CIFRADO DE BASES DE DATOS${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

score=0
total=0

check() {
    local desc="$1" result="$2"
    ((total++))
    if [[ "$result" == "OK" ]]; then
        echo -e "  ${GREEN}[OK]${NC} $desc"
        ((score++))
    elif [[ "$result" == "WARN" ]]; then
        echo -e "  ${YELLOW}[!!]${NC} $desc"
    else
        echo -e "  ${RED}[XX]${NC} $desc"
    fi
}

# ── PostgreSQL TLS ──
if command -v psql &>/dev/null; then
    echo -e "${CYAN}── PostgreSQL: Cifrado ──${NC}"

    PG_CONF=""
    for d in /etc/postgresql/*/main /var/lib/pgsql/data /var/lib/postgresql/*/data; do
        [[ -f "$d/postgresql.conf" ]] && PG_CONF="$d/postgresql.conf" && break
    done

    if [[ -n "$PG_CONF" ]]; then
        # SSL
        ssl_val=$(grep -E "^ssl\s*=" "$PG_CONF" 2>/dev/null | awk '{print $3}' || echo "off")
        [[ "$ssl_val" == "on" ]] && check "PostgreSQL SSL habilitado" "OK" || check "PostgreSQL SSL deshabilitado" "FAIL"

        # SSL cert
        ssl_cert=$(grep -E "^ssl_cert_file\s*=" "$PG_CONF" 2>/dev/null | sed "s/.*=\s*//" | tr -d "'" || echo "")
        if [[ -n "$ssl_cert" ]]; then
            check "PostgreSQL SSL cert: $ssl_cert" "OK"
        else
            check "PostgreSQL SSL cert no configurado" "WARN"
        fi

        # pgcrypto extension
        pgcrypto_installed=$(sudo -u postgres psql -t -c "SELECT count(*) FROM pg_available_extensions WHERE name='pgcrypto' AND installed_version IS NOT NULL" 2>/dev/null | tr -d ' ' || echo "0")
        [[ "$pgcrypto_installed" -gt 0 ]] && check "PostgreSQL pgcrypto extension instalada" "OK" || check "PostgreSQL pgcrypto no instalada (CREATE EXTENSION pgcrypto)" "WARN"
    fi
    echo ""
fi

# ── MySQL/MariaDB TLS ──
MYSQL_CMD=""
command -v mariadb &>/dev/null && MYSQL_CMD="mariadb"
command -v mysql &>/dev/null && MYSQL_CMD="mysql"

if [[ -n "$MYSQL_CMD" ]]; then
    echo -e "${CYAN}── MySQL/MariaDB: Cifrado ──${NC}"

    # TLS habilitado
    have_ssl=$($MYSQL_CMD -N -e "SHOW VARIABLES LIKE 'have_ssl'" 2>/dev/null | awk '{print $2}' || echo "DISABLED")
    [[ "$have_ssl" == "YES" ]] && check "MySQL/MariaDB SSL habilitado" "OK" || check "MySQL/MariaDB SSL: $have_ssl" "FAIL"

    # require_secure_transport
    secure_transport=$($MYSQL_CMD -N -e "SHOW VARIABLES LIKE 'require_secure_transport'" 2>/dev/null | awk '{print $2}' || echo "OFF")
    [[ "$secure_transport" == "ON" ]] && check "require_secure_transport ON" "OK" || check "require_secure_transport: $secure_transport" "WARN"

    # InnoDB encryption
    innodb_encrypt=$($MYSQL_CMD -N -e "SHOW VARIABLES LIKE 'innodb_encrypt_tables'" 2>/dev/null | awk '{print $2}' || echo "OFF")
    if [[ "$innodb_encrypt" == "ON" || "$innodb_encrypt" == "FORCE" ]]; then
        check "InnoDB tablespace encryption habilitado" "OK"
    else
        check "InnoDB tablespace encryption: $innodb_encrypt (habilitar para cifrado en reposo)" "WARN"
    fi

    # Binlog encryption
    binlog_encrypt=$($MYSQL_CMD -N -e "SHOW VARIABLES LIKE 'encrypt_binlog'" 2>/dev/null | awk '{print $2}' || echo "OFF")
    [[ "$binlog_encrypt" == "ON" ]] && check "Binlog encryption habilitado" "OK" || check "Binlog encryption: $binlog_encrypt" "WARN"
    echo ""
fi

# ── Redis TLS ──
if command -v redis-cli &>/dev/null; then
    echo -e "${CYAN}── Redis: Cifrado ──${NC}"

    REDIS_CONF=""
    for f in /etc/redis/redis.conf /etc/redis.conf /etc/redis/6379.conf; do
        [[ -f "$f" ]] && REDIS_CONF="$f" && break
    done

    if [[ -n "$REDIS_CONF" ]]; then
        tls_port=$(grep -E "^tls-port\s" "$REDIS_CONF" 2>/dev/null | awk '{print $2}' || echo "0")
        if [[ "$tls_port" -gt 0 ]]; then
            check "Redis TLS habilitado en puerto $tls_port" "OK"
        else
            check "Redis TLS no habilitado" "WARN"
        fi
    fi
    echo ""
fi

# ── MongoDB TLS ──
if command -v mongod &>/dev/null; then
    echo -e "${CYAN}── MongoDB: Cifrado ──${NC}"

    MONGOD_CONF=""
    for f in /etc/mongod.conf /etc/mongodb.conf; do
        [[ -f "$f" ]] && MONGOD_CONF="$f" && break
    done

    if [[ -n "$MONGOD_CONF" ]]; then
        # TLS mode
        tls_mode=$(grep -E "^\s*mode:" "$MONGOD_CONF" 2>/dev/null | awk '{print $2}' || echo "disabled")
        if [[ "$tls_mode" == *"TLS"* || "$tls_mode" == *"SSL"* ]]; then
            check "MongoDB TLS mode: $tls_mode" "OK"
        else
            check "MongoDB TLS no configurado" "WARN"
        fi

        # WiredTiger encryption
        wt_encrypt=$(grep -cE "encryptionKeyFile:" "$MONGOD_CONF" 2>/dev/null || echo "0")
        if [[ "$wt_encrypt" -gt 0 ]]; then
            check "WiredTiger encryption configurado" "OK"
        else
            check "WiredTiger encryption no configurado (requiere Enterprise)" "WARN"
        fi
    fi
    echo ""
fi

# Resumen
echo -e "${BOLD}── Resultado ──${NC}"
if [[ $total -gt 0 ]]; then
    pct=$((score * 100 / total))
    if [[ $pct -ge 80 ]]; then
        echo -e "  Puntuacion: ${GREEN}${score}/${total} (${pct}%) - BUENO${NC}"
    elif [[ $pct -ge 50 ]]; then
        echo -e "  Puntuacion: ${YELLOW}${score}/${total} (${pct}%) - MEJORABLE${NC}"
    else
        echo -e "  Puntuacion: ${RED}${score}/${total} (${pct}%) - DEFICIENTE${NC}"
    fi
else
    echo -e "  ${YELLOW}No se detectaron bases de datos instaladas${NC}"
fi
EOFCIFRADODB
    chmod +x /usr/local/bin/verificar-cifrado-db.sh
    log_change "Creado" "/usr/local/bin/verificar-cifrado-db.sh"

    # Configurar TLS para PostgreSQL si esta presente
    if detect_postgresql; then
        PG_CONF=$(find_pg_conf)
        if [[ -n "$PG_CONF" ]]; then
            PG_DATA_DIR=$(dirname "$PG_CONF")

            # Generar certificados autofirmados si no existen
            if [[ ! -f "${PG_DATA_DIR}/server.crt" ]]; then
                log_info "Generando certificados SSL autofirmados para PostgreSQL..."
                openssl req -new -x509 -days 365 -nodes \
                    -out "${PG_DATA_DIR}/server.crt" \
                    -keyout "${PG_DATA_DIR}/server.key" \
                    -subj "/CN=postgresql-server/O=securizar" 2>/dev/null || true

                if [[ -f "${PG_DATA_DIR}/server.key" ]]; then
                    # Permisos apropiados para PostgreSQL
                    local pg_user="postgres"
                    chown "${pg_user}:${pg_user}" "${PG_DATA_DIR}/server.crt" "${PG_DATA_DIR}/server.key" 2>/dev/null || true
                    chmod 600 "${PG_DATA_DIR}/server.key"
                    chmod 644 "${PG_DATA_DIR}/server.crt"

                    # Configurar rutas en postgresql.conf
                    if grep -q "^#\?ssl_cert_file\s*=" "$PG_CONF"; then
                        sed -i "s|^#\?ssl_cert_file\s*=.*|ssl_cert_file = 'server.crt'|" "$PG_CONF"
                    else
                        echo "ssl_cert_file = 'server.crt'" >> "$PG_CONF"
                    fi
                    if grep -q "^#\?ssl_key_file\s*=" "$PG_CONF"; then
                        sed -i "s|^#\?ssl_key_file\s*=.*|ssl_key_file = 'server.key'|" "$PG_CONF"
                    else
                        echo "ssl_key_file = 'server.key'" >> "$PG_CONF"
                    fi
                    log_change "Generado" "Certificados SSL autofirmados para PostgreSQL"
                    log_warn "RECOMENDACION: Reemplazar certificados autofirmados por certificados de CA"
                fi
            else
                log_info "PostgreSQL: certificados SSL ya existen"
            fi

            # Instalar pgcrypto si es posible
            log_info "Para cifrado en reposo con PostgreSQL, ejecuta:"
            echo "  sudo -u postgres psql -c 'CREATE EXTENSION IF NOT EXISTS pgcrypto;'"
        fi
    fi

    # Guia de cifrado para MySQL/MariaDB
    if detect_mysql; then
        log_info "Para cifrado en reposo con MySQL/MariaDB (InnoDB):"
        echo "  -- En my.cnf [mysqld]:"
        echo "  innodb_encrypt_tables = ON"
        echo "  innodb_encrypt_log = ON"
        echo "  -- Para MariaDB File Key Management:"
        echo "  plugin_load_add = file_key_management"
        echo "  file_key_management_filename = /etc/mysql/keys/keyfile"
    fi

    log_info "Verificacion de cifrado configurada"
    log_info "Ejecuta: verificar-cifrado-db.sh"
else
    log_skip "Configuracion de cifrado de bases de datos"
fi

# ============================================================
# S7: DATABASE BACKUP SECURITY
# ============================================================
log_section "S7: SEGURIDAD DE BACKUPS DE BASES DE DATOS"

echo "Backups seguros de bases de datos:"
echo "  - Scripts de backup con cifrado AES-256 (GPG)"
echo "  - Verificacion de integridad (checksums)"
echo "  - Programacion automatica de backups"
echo "  - Politicas de retencion"
echo "  - Pruebas de restauracion"
echo ""

if check_executable "/usr/local/bin/backup-seguro-db.sh"; then
    log_already "Backups DB (backup-seguro-db.sh ya instalado)"
elif ask "¿Configurar backups seguros de bases de datos?"; then

    # Directorio de backups
    BACKUP_DB_DIR="/var/backups/databases"
    mkdir -p "$BACKUP_DB_DIR"
    chmod 700 "$BACKUP_DB_DIR"
    log_change "Creado" "$BACKUP_DB_DIR con permisos 700"

    # Crear script de backup seguro
    cat > /usr/local/bin/backup-seguro-db.sh << 'EOFBACKUPDB'
#!/bin/bash
# ============================================================
# Backup seguro de bases de datos con cifrado GPG
# Generado por securizar - Modulo 48
# ============================================================
# Uso: backup-seguro-db.sh [postgresql|mysql|mongodb|redis|all]
# ============================================================

set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

BACKUP_BASE="/var/backups/databases"
DATE=$(date +%Y%m%d-%H%M%S)
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"
LOG_FILE="/var/log/backup-db.log"

# Passphrase para cifrado (desde variable de entorno o archivo)
GPG_PASSPHRASE=""
if [[ -n "${DB_BACKUP_PASSPHRASE:-}" ]]; then
    GPG_PASSPHRASE="$DB_BACKUP_PASSPHRASE"
elif [[ -f /etc/securizar/backup-passphrase ]]; then
    GPG_PASSPHRASE=$(cat /etc/securizar/backup-passphrase)
else
    echo -e "${RED}Error: No se encontro passphrase de cifrado${NC}"
    echo "Configura DB_BACKUP_PASSPHRASE o crea /etc/securizar/backup-passphrase"
    exit 1
fi

log_backup() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$msg" >> "$LOG_FILE"
    echo -e "$1"
}

encrypt_backup() {
    local input_file="$1"
    local output_file="${input_file}.gpg"

    gpg --batch --yes --symmetric --cipher-algo AES256 \
        --passphrase "$GPG_PASSPHRASE" \
        --output "$output_file" "$input_file" 2>/dev/null

    if [[ $? -eq 0 ]]; then
        # Generar checksum
        sha256sum "$output_file" > "${output_file}.sha256"
        # Eliminar archivo sin cifrar
        rm -f "$input_file"
        log_backup "${GREEN}[OK]${NC} Cifrado: $(basename "$output_file")"
        echo "$output_file"
    else
        log_backup "${RED}[XX]${NC} Error cifrando: $(basename "$input_file")"
        return 1
    fi
}

verify_backup() {
    local gpg_file="$1"
    if [[ -f "${gpg_file}.sha256" ]]; then
        if sha256sum -c "${gpg_file}.sha256" &>/dev/null; then
            log_backup "${GREEN}[OK]${NC} Integridad verificada: $(basename "$gpg_file")"
            return 0
        else
            log_backup "${RED}[XX]${NC} Integridad fallida: $(basename "$gpg_file")"
            return 1
        fi
    else
        log_backup "${YELLOW}[!!]${NC} Sin checksum: $(basename "$gpg_file")"
        return 1
    fi
}

cleanup_old_backups() {
    local db_type="$1"
    local dir="${BACKUP_BASE}/${db_type}"
    if [[ -d "$dir" ]]; then
        local deleted
        deleted=$(find "$dir" -name "*.gpg" -mtime +"$RETENTION_DAYS" -delete -print 2>/dev/null | wc -l)
        find "$dir" -name "*.sha256" -mtime +"$RETENTION_DAYS" -delete 2>/dev/null || true
        [[ "$deleted" -gt 0 ]] && log_backup "${CYAN}Limpieza:${NC} $deleted backups antiguos eliminados de $db_type"
    fi
}

backup_postgresql() {
    log_backup "${BOLD}── Backup PostgreSQL ──${NC}"
    local dir="${BACKUP_BASE}/postgresql"
    mkdir -p "$dir"

    if ! command -v pg_dumpall &>/dev/null; then
        log_backup "${RED}[XX]${NC} pg_dumpall no encontrado"
        return 1
    fi

    local dump_file="${dir}/postgresql-all-${DATE}.sql"
    if sudo -u postgres pg_dumpall > "$dump_file" 2>/dev/null; then
        local size
        size=$(du -h "$dump_file" | awk '{print $1}')
        log_backup "${GREEN}[OK]${NC} Dump PostgreSQL: $size"
        encrypt_backup "$dump_file"
    else
        log_backup "${RED}[XX]${NC} Error en pg_dumpall"
        rm -f "$dump_file"
        return 1
    fi

    cleanup_old_backups "postgresql"
}

backup_mysql() {
    log_backup "${BOLD}── Backup MySQL/MariaDB ──${NC}"
    local dir="${BACKUP_BASE}/mysql"
    mkdir -p "$dir"

    local mysql_cmd="mysqldump"
    command -v mariadb-dump &>/dev/null && mysql_cmd="mariadb-dump"

    if ! command -v "$mysql_cmd" &>/dev/null; then
        log_backup "${RED}[XX]${NC} $mysql_cmd no encontrado"
        return 1
    fi

    local dump_file="${dir}/mysql-all-${DATE}.sql"
    if $mysql_cmd --all-databases --single-transaction --routines --triggers --events > "$dump_file" 2>/dev/null; then
        local size
        size=$(du -h "$dump_file" | awk '{print $1}')
        log_backup "${GREEN}[OK]${NC} Dump MySQL/MariaDB: $size"
        encrypt_backup "$dump_file"
    else
        log_backup "${RED}[XX]${NC} Error en $mysql_cmd"
        rm -f "$dump_file"
        return 1
    fi

    cleanup_old_backups "mysql"
}

backup_mongodb() {
    log_backup "${BOLD}── Backup MongoDB ──${NC}"
    local dir="${BACKUP_BASE}/mongodb"
    mkdir -p "$dir"

    if ! command -v mongodump &>/dev/null; then
        log_backup "${RED}[XX]${NC} mongodump no encontrado"
        return 1
    fi

    local dump_dir="${dir}/mongodump-${DATE}"
    if mongodump --out "$dump_dir" 2>/dev/null; then
        # Comprimir y cifrar
        local tar_file="${dir}/mongodb-${DATE}.tar.gz"
        tar czf "$tar_file" -C "$dir" "mongodump-${DATE}" 2>/dev/null
        rm -rf "$dump_dir"
        local size
        size=$(du -h "$tar_file" | awk '{print $1}')
        log_backup "${GREEN}[OK]${NC} Dump MongoDB: $size"
        encrypt_backup "$tar_file"
    else
        log_backup "${RED}[XX]${NC} Error en mongodump"
        rm -rf "$dump_dir"
        return 1
    fi

    cleanup_old_backups "mongodb"
}

backup_redis() {
    log_backup "${BOLD}── Backup Redis ──${NC}"
    local dir="${BACKUP_BASE}/redis"
    mkdir -p "$dir"

    if ! command -v redis-cli &>/dev/null; then
        log_backup "${RED}[XX]${NC} redis-cli no encontrado"
        return 1
    fi

    # Trigger BGSAVE
    local redis_auth=""
    if [[ -f /etc/securizar/redis-credentials ]]; then
        redis_auth=$(grep "^REDIS_PASSWORD=" /etc/securizar/redis-credentials 2>/dev/null | cut -d= -f2)
    fi

    if [[ -n "$redis_auth" ]]; then
        redis-cli -a "$redis_auth" --no-auth-warning BGSAVE &>/dev/null || true
    else
        redis-cli BGSAVE &>/dev/null || true
    fi
    sleep 2

    # Copiar RDB file
    local rdb_file=""
    for f in /var/lib/redis/dump.rdb /var/lib/redis/6379/dump.rdb /var/lib/redis-server/dump.rdb; do
        [[ -f "$f" ]] && rdb_file="$f" && break
    done

    if [[ -n "$rdb_file" ]]; then
        local backup_file="${dir}/redis-${DATE}.rdb"
        cp "$rdb_file" "$backup_file"
        local size
        size=$(du -h "$backup_file" | awk '{print $1}')
        log_backup "${GREEN}[OK]${NC} Backup Redis: $size"
        encrypt_backup "$backup_file"
    else
        log_backup "${RED}[XX]${NC} No se encontro dump.rdb"
        return 1
    fi

    cleanup_old_backups "redis"
}

# Main
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  BACKUP SEGURO DE BASES DE DATOS${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

TARGET="${1:-all}"
errors=0

case "$TARGET" in
    postgresql|pg) backup_postgresql || ((errors++)) ;;
    mysql|mariadb) backup_mysql || ((errors++)) ;;
    mongodb|mongo) backup_mongodb || ((errors++)) ;;
    redis)         backup_redis || ((errors++)) ;;
    all)
        command -v pg_dumpall &>/dev/null && backup_postgresql || true
        command -v mysqldump &>/dev/null && backup_mysql || true
        command -v mariadb-dump &>/dev/null && { command -v mysqldump &>/dev/null || backup_mysql || true; }
        command -v mongodump &>/dev/null && backup_mongodb || true
        command -v redis-cli &>/dev/null && backup_redis || true
        ;;
    *)
        echo "Uso: $0 [postgresql|mysql|mongodb|redis|all]"
        exit 1
        ;;
esac

echo ""
log_backup "${BOLD}Backups almacenados en: ${BACKUP_BASE}${NC}"
log_backup "${BOLD}Retencion: ${RETENTION_DAYS} dias${NC}"

if [[ $errors -gt 0 ]]; then
    log_backup "${RED}$errors errores durante el backup${NC}"
    exit 1
fi
EOFBACKUPDB
    chmod +x /usr/local/bin/backup-seguro-db.sh
    log_change "Creado" "/usr/local/bin/backup-seguro-db.sh"

    # Crear passphrase de backup si no existe
    if [[ ! -f /etc/securizar/backup-passphrase ]]; then
        generate_strong_password 48 > /etc/securizar/backup-passphrase
        chmod 600 /etc/securizar/backup-passphrase
        log_change "Generado" "/etc/securizar/backup-passphrase (modo 600)"
        log_warn "IMPORTANTE: Guarda /etc/securizar/backup-passphrase en un lugar seguro externo"
    fi

    # Programar backup automatico con cron
    if ask "¿Programar backup diario automatico?"; then
        cat > /etc/cron.daily/backup-bases-datos << 'EOFCRONBACKUP'
#!/bin/bash
# Backup diario de bases de datos - securizar Modulo 48
/usr/local/bin/backup-seguro-db.sh all >> /var/log/backup-db.log 2>&1
EOFCRONBACKUP
        chmod +x /etc/cron.daily/backup-bases-datos
        log_change "Creado" "/etc/cron.daily/backup-bases-datos"
    else
        log_skip "Cron de backup automatico"
    fi

    log_info "Sistema de backup seguro configurado"
    log_info "Ejecuta: backup-seguro-db.sh [postgresql|mysql|mongodb|redis|all]"
else
    log_skip "Backups seguros de bases de datos"
fi

# ============================================================
# S8: DATABASE AUDIT LOGGING
# ============================================================
log_section "S8: AUDITORIA DE LOGGING DE BASES DE DATOS"

echo "Configuracion de audit logging:"
echo "  - Logging de autenticacion, DDL, DML"
echo "  - Reenvio a syslog/journald"
echo "  - Integracion con modulo 43 (logging centralizado)"
echo ""

if check_executable "/usr/local/bin/configurar-audit-db.sh"; then
    log_already "Audit logging DB (configurar-audit-db.sh ya instalado)"
elif ask "¿Configurar audit logging de bases de datos?"; then

    # Crear script de configuracion de audit
    cat > /usr/local/bin/configurar-audit-db.sh << 'EOFAUDITCONF'
#!/bin/bash
# ============================================================
# Configuracion de audit logging para bases de datos
# Generado por securizar - Modulo 48
# ============================================================

set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  CONFIGURACION DE AUDIT LOGGING DB${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

# ── PostgreSQL Audit ──
if command -v psql &>/dev/null; then
    echo -e "${CYAN}── PostgreSQL Audit Logging ──${NC}"

    PG_CONF=""
    for d in /etc/postgresql/*/main /var/lib/pgsql/data /var/lib/postgresql/*/data; do
        [[ -f "$d/postgresql.conf" ]] && PG_CONF="$d/postgresql.conf" && break
    done

    if [[ -n "$PG_CONF" ]]; then
        echo -e "  Configuracion: $PG_CONF"

        # Verificar log_statement
        log_stmt=$(grep -E "^log_statement\s*=" "$PG_CONF" 2>/dev/null | awk '{print $3}' || echo "none")
        echo -e "  log_statement = $log_stmt"

        # Verificar log_connections
        log_conn=$(grep -E "^log_connections\s*=" "$PG_CONF" 2>/dev/null | awk '{print $3}' || echo "off")
        echo -e "  log_connections = $log_conn"

        # Verificar log_disconnections
        log_disc=$(grep -E "^log_disconnections\s*=" "$PG_CONF" 2>/dev/null | awk '{print $3}' || echo "off")
        echo -e "  log_disconnections = $log_disc"

        # Verificar log_duration
        log_dur=$(grep -E "^log_duration\s*=" "$PG_CONF" 2>/dev/null | awk '{print $3}' || echo "off")
        echo -e "  log_duration = $log_dur"

        # Sugerir pgaudit
        echo ""
        echo -e "  ${YELLOW}Recomendacion:${NC} Instalar pgAudit para auditoria granular:"
        echo "    shared_preload_libraries = 'pgaudit'"
        echo "    pgaudit.log = 'read, write, ddl, role'"
    fi
    echo ""
fi

# ── MySQL/MariaDB Audit ──
MYSQL_CMD=""
command -v mariadb &>/dev/null && MYSQL_CMD="mariadb"
command -v mysql &>/dev/null && MYSQL_CMD="mysql"

if [[ -n "$MYSQL_CMD" ]]; then
    echo -e "${CYAN}── MySQL/MariaDB Audit Logging ──${NC}"

    # general_log
    gen_log=$($MYSQL_CMD -N -e "SHOW VARIABLES LIKE 'general_log'" 2>/dev/null | awk '{print $2}' || echo "desconocido")
    echo -e "  general_log = $gen_log"

    # slow_query_log
    slow_log=$($MYSQL_CMD -N -e "SHOW VARIABLES LIKE 'slow_query_log'" 2>/dev/null | awk '{print $2}' || echo "desconocido")
    echo -e "  slow_query_log = $slow_log"

    # log_error
    log_err=$($MYSQL_CMD -N -e "SHOW VARIABLES LIKE 'log_error'" 2>/dev/null | awk '{print $2}' || echo "desconocido")
    echo -e "  log_error = $log_err"

    echo ""
    echo -e "  ${YELLOW}Recomendacion:${NC} Habilitar plugin de auditoria:"
    echo "    MariaDB: INSTALL SONAME 'server_audit';"
    echo "             SET GLOBAL server_audit_logging=ON;"
    echo "             SET GLOBAL server_audit_events='CONNECT,QUERY_DDL,QUERY_DML';"
    echo "    MySQL:   INSTALL PLUGIN audit_log SONAME 'audit_log.so';"
    echo ""
fi

# ── Redis Audit ──
if command -v redis-cli &>/dev/null; then
    echo -e "${CYAN}── Redis Audit Logging ──${NC}"

    REDIS_CONF=""
    for f in /etc/redis/redis.conf /etc/redis.conf /etc/redis/6379.conf; do
        [[ -f "$f" ]] && REDIS_CONF="$f" && break
    done

    if [[ -n "$REDIS_CONF" ]]; then
        # loglevel
        loglevel=$(grep -E "^loglevel\s" "$REDIS_CONF" 2>/dev/null | awk '{print $2}' || echo "notice")
        echo -e "  loglevel = $loglevel"

        # logfile
        logfile=$(grep -E "^logfile\s" "$REDIS_CONF" 2>/dev/null | awk '{print $2}' | tr -d '"' || echo "stdout")
        echo -e "  logfile = $logfile"
    fi
    echo ""
fi

# ── MongoDB Audit ──
if command -v mongod &>/dev/null; then
    echo -e "${CYAN}── MongoDB Audit Logging ──${NC}"

    MONGOD_CONF=""
    for f in /etc/mongod.conf /etc/mongodb.conf; do
        [[ -f "$f" ]] && MONGOD_CONF="$f" && break
    done

    if [[ -n "$MONGOD_CONF" ]]; then
        has_audit=$(grep -c "auditLog:" "$MONGOD_CONF" 2>/dev/null || echo "0")
        if [[ "$has_audit" -gt 0 ]]; then
            echo -e "  ${GREEN}[OK]${NC} auditLog configurado"
        else
            echo -e "  ${YELLOW}[!!]${NC} auditLog no configurado"
            echo -e "  Requiere MongoDB Enterprise o Percona Server for MongoDB"
        fi

        # systemLog
        has_syslog=$(grep -c "systemLog:" "$MONGOD_CONF" 2>/dev/null || echo "0")
        if [[ "$has_syslog" -gt 0 ]]; then
            log_path=$(grep -E "^\s*path:" "$MONGOD_CONF" 2>/dev/null | awk '{print $2}' | head -1 || echo "no definido")
            echo -e "  systemLog.path = $log_path"
        fi
    fi
    echo ""
fi

echo -e "${BOLD}Configuracion de audit logging verificada${NC}"
EOFAUDITCONF
    chmod +x /usr/local/bin/configurar-audit-db.sh
    log_change "Creado" "/usr/local/bin/configurar-audit-db.sh"

    # Configurar rsyslog para bases de datos si esta disponible
    if [[ -d /etc/rsyslog.d ]]; then
        cat > /etc/rsyslog.d/60-databases.conf << 'EOFRSYSLOGDB'
# Logging de bases de datos - securizar Modulo 48

# PostgreSQL logs
:programname, isequal, "postgres" /var/log/db-audit/postgresql.log
& stop

# MySQL/MariaDB logs
:programname, isequal, "mysqld" /var/log/db-audit/mysql.log
& stop

# MongoDB logs
:programname, isequal, "mongod" /var/log/db-audit/mongodb.log
& stop

# Redis logs
:programname, isequal, "redis-server" /var/log/db-audit/redis.log
& stop
EOFRSYSLOGDB
        mkdir -p /var/log/db-audit
        chmod 750 /var/log/db-audit
        log_change "Creado" "/etc/rsyslog.d/60-databases.conf"
        log_change "Creado" "/var/log/db-audit/ con permisos 750"

        # Recargar rsyslog
        systemctl restart rsyslog 2>/dev/null || log_warn "No se pudo reiniciar rsyslog"
    fi

    # Configurar logrotate para logs de DB
    if [[ -d /etc/logrotate.d ]]; then
        cat > /etc/logrotate.d/db-audit << 'EOFLOGROTATEDB'
/var/log/db-audit/*.log {
    weekly
    rotate 52
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
    sharedscripts
    postrotate
        /usr/bin/systemctl reload rsyslog 2>/dev/null || true
    endscript
}
EOFLOGROTATEDB
        log_change "Creado" "/etc/logrotate.d/db-audit"
    fi

    log_info "Audit logging de bases de datos configurado"
    log_info "Ejecuta: configurar-audit-db.sh para ver estado actual"
else
    log_skip "Audit logging de bases de datos"
fi

# ============================================================
# S9: SQL INJECTION PREVENTION & QUERY MONITORING
# ============================================================
log_section "S9: PREVENCION DE SQL INJECTION Y MONITOREO DE QUERIES"

echo "Prevencion de SQL Injection:"
echo "  - Monitoreo de logs para patrones de SQLi"
echo "  - UNION SELECT, OR 1=1, SLEEP, BENCHMARK, xp_cmdshell"
echo "  - Alertas en queries sospechosas"
echo "  - Cron job para monitoreo continuo"
echo ""

if check_executable "/usr/local/bin/detectar-sqli.sh"; then
    log_already "SQLi prevention (detectar-sqli.sh ya instalado)"
elif ask "¿Configurar prevencion de SQL injection?"; then

    # Crear archivo de patrones SQLi
    cat > /etc/securizar/sqli-patterns.conf << 'EOFSQLIPATTERNS'
# ============================================================
# Patrones de SQL Injection - securizar Modulo 48
# ============================================================
# Formato: Un patron regex por linea
# Lineas que empiezan con # son comentarios
# ============================================================

# Union-based injection
UNION\s+(ALL\s+)?SELECT
UNION\s+(ALL\s+)?SELECT\s+NULL

# Boolean-based blind injection
OR\s+1\s*=\s*1
OR\s+'1'\s*=\s*'1'
AND\s+1\s*=\s*1
AND\s+'1'\s*=\s*'1'
OR\s+''=''
OR\s+true
AND\s+true

# Time-based blind injection
SLEEP\s*\(
BENCHMARK\s*\(
WAITFOR\s+DELAY
pg_sleep\s*\(

# Error-based injection
EXTRACTVALUE\s*\(
UPDATEXML\s*\(
EXP\s*\(\s*~
CONVERT\s*\(

# Stacked queries
;\s*DROP\s+
;\s*DELETE\s+
;\s*UPDATE\s+
;\s*INSERT\s+
;\s*ALTER\s+
;\s*CREATE\s+
;\s*EXEC\s+

# MSSQL specific
xp_cmdshell
sp_executesql
xp_regread

# Comment injection
--\s*$
/\*.*\*/
#\s+

# File operations
LOAD_FILE\s*\(
INTO\s+(OUT|DUMP)FILE
LOAD\s+DATA\s+

# Information gathering
information_schema
sysobjects
syscolumns
pg_catalog
pg_shadow

# Encoding evasion
CHAR\s*\(\s*\d+
0x[0-9a-fA-F]+
UNHEX\s*\(
HEX\s*\(
CONCAT\s*\(
CONCAT_WS\s*\(
GROUP_CONCAT\s*\(
EOFSQLIPATTERNS
    chmod 644 /etc/securizar/sqli-patterns.conf
    log_change "Creado" "/etc/securizar/sqli-patterns.conf"

    # Crear script de deteccion SQLi
    cat > /usr/local/bin/detectar-sqli.sh << 'EOFSQLIDETECT'
#!/bin/bash
# ============================================================
# Deteccion de SQL Injection en logs de bases de datos
# Generado por securizar - Modulo 48
# ============================================================
# Uso: detectar-sqli.sh [--watch] [--log-file FILE] [--since MINUTES]
# ============================================================

set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PATTERNS_FILE="/etc/securizar/sqli-patterns.conf"
ALERT_LOG="/var/log/sqli-alerts.log"
WATCH_MODE=0
SINCE_MINUTES=60
CUSTOM_LOG=""

# Parsear argumentos
while [[ $# -gt 0 ]]; do
    case "$1" in
        --watch)     WATCH_MODE=1; shift ;;
        --log-file)  CUSTOM_LOG="$2"; shift 2 ;;
        --since)     SINCE_MINUTES="$2"; shift 2 ;;
        -h|--help)
            echo "Uso: $0 [--watch] [--log-file FILE] [--since MINUTES]"
            echo "  --watch        Monitoreo continuo (tail -f)"
            echo "  --log-file     Archivo de log a analizar"
            echo "  --since N      Analizar ultimos N minutos (default: 60)"
            exit 0
            ;;
        *) shift ;;
    esac
done

if [[ ! -f "$PATTERNS_FILE" ]]; then
    echo -e "${RED}Error: $PATTERNS_FILE no encontrado${NC}"
    exit 1
fi

# Construir regex combinado de patrones
COMBINED_PATTERN=""
while IFS= read -r line; do
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$line" || "$line" == \#* ]] && continue
    if [[ -z "$COMBINED_PATTERN" ]]; then
        COMBINED_PATTERN="$line"
    else
        COMBINED_PATTERN="${COMBINED_PATTERN}|${line}"
    fi
done < "$PATTERNS_FILE"

if [[ -z "$COMBINED_PATTERN" ]]; then
    echo -e "${RED}Error: No se cargaron patrones${NC}"
    exit 1
fi

# Detectar archivos de log disponibles
LOG_FILES=()
if [[ -n "$CUSTOM_LOG" ]]; then
    LOG_FILES+=("$CUSTOM_LOG")
else
    # PostgreSQL
    for f in /var/log/postgresql/*.log /var/lib/pgsql/data/log/*.log /var/log/db-audit/postgresql.log; do
        [[ -f "$f" ]] && LOG_FILES+=("$f")
    done
    # MySQL/MariaDB
    for f in /var/log/mysql/general.log /var/log/mysql/*.log /var/log/db-audit/mysql.log; do
        [[ -f "$f" ]] && LOG_FILES+=("$f")
    done
    # MongoDB
    for f in /var/log/mongodb/mongod.log /var/log/db-audit/mongodb.log; do
        [[ -f "$f" ]] && LOG_FILES+=("$f")
    done
fi

if [[ ${#LOG_FILES[@]} -eq 0 ]]; then
    echo -e "${YELLOW}No se encontraron archivos de log de bases de datos${NC}"
    exit 0
fi

alert_sqli() {
    local file="$1" line="$2"
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    local msg="[$ts] ALERTA SQLi en $file: $line"
    echo "$msg" >> "$ALERT_LOG"
    echo -e "${RED}${BOLD}[ALERTA SQLi]${NC} ${file}: ${line}"

    # Enviar alerta por syslog/journal
    logger -t "securizar-sqli" -p auth.alert "SQL Injection detectada en $file: $line" 2>/dev/null || true
}

scan_log() {
    local file="$1"
    local alerts=0

    echo -e "${CYAN}Analizando: $file${NC}"

    while IFS= read -r line; do
        if echo "$line" | grep -iEq "$COMBINED_PATTERN"; then
            alert_sqli "$file" "$line"
            ((alerts++)) || true
        fi
    done < <(
        if [[ "$SINCE_MINUTES" -gt 0 && "$WATCH_MODE" -eq 0 ]]; then
            # Solo las ultimas N lineas (aproximacion)
            tail -n "$((SINCE_MINUTES * 10))" "$file" 2>/dev/null || cat "$file"
        else
            cat "$file"
        fi
    )

    if [[ $alerts -eq 0 ]]; then
        echo -e "  ${GREEN}[OK]${NC} Sin patrones SQLi detectados"
    else
        echo -e "  ${RED}[XX]${NC} $alerts alertas SQLi"
    fi
    return $alerts
}

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  DETECCION DE SQL INJECTION${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

total_alerts=0

if [[ "$WATCH_MODE" -eq 1 ]]; then
    echo -e "${YELLOW}Modo monitoreo continuo - Ctrl+C para salir${NC}"
    echo ""
    tail -f "${LOG_FILES[@]}" 2>/dev/null | while IFS= read -r line; do
        if echo "$line" | grep -iEq "$COMBINED_PATTERN"; then
            alert_sqli "monitor" "$line"
        fi
    done
else
    for log_file in "${LOG_FILES[@]}"; do
        scan_log "$log_file" || true
        file_alerts=$?
        total_alerts=$((total_alerts + file_alerts))
    done

    echo ""
    echo -e "${BOLD}── Resultado ──${NC}"
    if [[ $total_alerts -eq 0 ]]; then
        echo -e "  ${GREEN}Sin intentos de SQL Injection detectados${NC}"
    else
        echo -e "  ${RED}$total_alerts alertas SQLi - revisar $ALERT_LOG${NC}"
    fi
fi
EOFSQLIDETECT
    chmod +x /usr/local/bin/detectar-sqli.sh
    log_change "Creado" "/usr/local/bin/detectar-sqli.sh"

    # Configurar cron job para monitoreo
    cat > /etc/cron.hourly/detectar-sqli << 'EOFCRONSQLI'
#!/bin/bash
# Monitoreo horario de SQL Injection - securizar Modulo 48
/usr/local/bin/detectar-sqli.sh --since 60 >> /var/log/sqli-alerts.log 2>&1
EOFCRONSQLI
    chmod +x /etc/cron.hourly/detectar-sqli
    log_change "Creado" "/etc/cron.hourly/detectar-sqli"

    # Crear logrotate para alertas SQLi
    if [[ -d /etc/logrotate.d ]]; then
        cat > /etc/logrotate.d/sqli-alerts << 'EOFLOGROTSQLI'
/var/log/sqli-alerts.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
}
EOFLOGROTSQLI
        log_change "Creado" "/etc/logrotate.d/sqli-alerts"
    fi

    log_info "Sistema de deteccion de SQL Injection configurado"
    log_info "Ejecuta: detectar-sqli.sh [--watch] para monitoreo"
    log_info "Alertas en: /var/log/sqli-alerts.log"
else
    log_skip "Prevencion de SQL injection"
fi

# ============================================================
# S10: DATABASE SECURITY AUDIT
# ============================================================
log_section "S10: AUDITORIA INTEGRAL DE SEGURIDAD DE BASES DE DATOS"

echo "Auditoria integral de seguridad:"
echo "  - Verifica todos los motores instalados"
echo "  - Autenticacion, cifrado, acceso, backups"
echo "  - Audit logging, exposicion de red"
echo "  - Puntuacion BUENO/MEJORABLE/DEFICIENTE"
echo ""

if check_executable "/usr/local/bin/auditoria-bases-datos.sh"; then
    log_already "Auditoria DB (auditoria-bases-datos.sh ya instalado)"
elif ask "¿Instalar herramienta de auditoria integral de bases de datos?"; then

    cat > /usr/local/bin/auditoria-bases-datos.sh << 'EOFDBAUDIT'
#!/bin/bash
# ============================================================
# Auditoria integral de seguridad de bases de datos
# Generado por securizar - Modulo 48
# ============================================================

set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

REPORT_FILE="/var/log/auditoria-db-$(date +%Y%m%d-%H%M%S).txt"

echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  AUDITORIA INTEGRAL DE SEGURIDAD - BASES DE DATOS${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo ""
echo "Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
echo "Hostname: $(hostname)"
echo ""

# Variables globales
total_score=0
total_checks=0
db_results=()

check_item() {
    local desc="$1" result="$2"
    ((total_checks++))
    if [[ "$result" == "OK" ]]; then
        echo -e "  ${GREEN}[OK]${NC} $desc"
        ((total_score++))
    elif [[ "$result" == "WARN" ]]; then
        echo -e "  ${YELLOW}[!!]${NC} $desc"
    else
        echo -e "  ${RED}[XX]${NC} $desc"
    fi
}

rate_db() {
    local db_name="$1" db_score="$2" db_total="$3"
    local pct=0
    [[ $db_total -gt 0 ]] && pct=$((db_score * 100 / db_total))
    local rating="DEFICIENTE"
    local color="$RED"
    if [[ $pct -ge 80 ]]; then
        rating="BUENO"
        color="$GREEN"
    elif [[ $pct -ge 50 ]]; then
        rating="MEJORABLE"
        color="$YELLOW"
    fi
    echo -e "  ${BOLD}${db_name}:${NC} ${color}${db_score}/${db_total} (${pct}%) - ${rating}${NC}"
    db_results+=("${db_name}: ${db_score}/${db_total} (${pct}%) - ${rating}")
}

# ══════════════════════════════════════════
# PostgreSQL
# ══════════════════════════════════════════
if command -v psql &>/dev/null || [[ -d /var/lib/pgsql ]] || [[ -d /var/lib/postgresql ]]; then
    echo -e "${CYAN}══ PostgreSQL ══${NC}"
    pg_score=0
    pg_total=0

    PG_CONF=""
    for d in /etc/postgresql/*/main /var/lib/pgsql/data /var/lib/postgresql/*/data; do
        [[ -f "$d/postgresql.conf" ]] && PG_CONF="$d/postgresql.conf" && break
    done
    PG_HBA=""
    for d in /etc/postgresql/*/main /var/lib/pgsql/data /var/lib/postgresql/*/data; do
        [[ -f "$d/pg_hba.conf" ]] && PG_HBA="$d/pg_hba.conf" && break
    done

    if [[ -n "$PG_CONF" ]]; then
        echo -e "  ${DIM}Config: $PG_CONF${NC}"

        # Autenticacion
        echo -e "  ${BOLD}Autenticacion:${NC}"
        pw_enc=$(grep -E "^password_encryption\s*=" "$PG_CONF" 2>/dev/null | awk '{print $3}' || echo "md5")
        ((pg_total++)); [[ "$pw_enc" == "scram-sha-256" ]] && { check_item "password_encryption: scram-sha-256" "OK"; ((pg_score++)); } || check_item "password_encryption: $pw_enc" "FAIL"

        if [[ -n "$PG_HBA" ]]; then
            trust_n=$(grep -cE '^\s*(local|host)\s+.*\s+trust\s*$' "$PG_HBA" 2>/dev/null || echo "0")
            ((pg_total++)); [[ "$trust_n" -eq 0 ]] && { check_item "Sin metodo trust en pg_hba.conf" "OK"; ((pg_score++)); } || check_item "$trust_n entradas trust" "FAIL"
        fi

        # Cifrado
        echo -e "  ${BOLD}Cifrado:${NC}"
        ssl_v=$(grep -E "^ssl\s*=" "$PG_CONF" 2>/dev/null | awk '{print $3}' || echo "off")
        ((pg_total++)); [[ "$ssl_v" == "on" ]] && { check_item "SSL habilitado" "OK"; ((pg_score++)); } || check_item "SSL deshabilitado" "FAIL"

        # Red
        echo -e "  ${BOLD}Red:${NC}"
        listen_v=$(grep -E "^listen_addresses\s*=" "$PG_CONF" 2>/dev/null | sed "s/.*=\s*//" | tr -d "'" || echo "*")
        ((pg_total++)); [[ "$listen_v" == "localhost" || "$listen_v" == "127.0.0.1" ]] && { check_item "listen_addresses restringido" "OK"; ((pg_score++)); } || check_item "listen_addresses: $listen_v" "WARN"

        # Logging
        echo -e "  ${BOLD}Logging:${NC}"
        log_c=$(grep -E "^log_connections\s*=" "$PG_CONF" 2>/dev/null | awk '{print $3}' || echo "off")
        ((pg_total++)); [[ "$log_c" == "on" ]] && { check_item "log_connections habilitado" "OK"; ((pg_score++)); } || check_item "log_connections deshabilitado" "FAIL"

        log_s=$(grep -E "^log_statement\s*=" "$PG_CONF" 2>/dev/null | awk '{print $3}' || echo "none")
        ((pg_total++)); [[ "$log_s" == "ddl" || "$log_s" == "all" ]] && { check_item "log_statement: $log_s" "OK"; ((pg_score++)); } || check_item "log_statement: $log_s" "WARN"

        # Puerto expuesto
        if ss -tlnp 2>/dev/null | grep -q ':5432.*0.0.0.0'; then
            ((pg_total++)); check_item "Puerto 5432 expuesto en 0.0.0.0" "FAIL"
        else
            ((pg_total++)); check_item "Puerto 5432 no expuesto externamente" "OK"; ((pg_score++))
        fi
    fi

    rate_db "PostgreSQL" "$pg_score" "$pg_total"
    total_score=$((total_score + pg_score))
    total_checks=$((total_checks + pg_total))
    echo ""
fi

# ══════════════════════════════════════════
# MySQL/MariaDB
# ══════════════════════════════════════════
if command -v mysql &>/dev/null || command -v mariadb &>/dev/null || [[ -d /var/lib/mysql ]]; then
    echo -e "${CYAN}══ MySQL/MariaDB ══${NC}"
    my_score=0
    my_total=0

    MYSQL_CMD=""
    command -v mariadb &>/dev/null && MYSQL_CMD="mariadb"
    command -v mysql &>/dev/null && MYSQL_CMD="mysql"

    if [[ -n "$MYSQL_CMD" ]]; then
        # Red
        echo -e "  ${BOLD}Red:${NC}"
        bind_a=$($MYSQL_CMD -N -e "SHOW VARIABLES LIKE 'bind_address'" 2>/dev/null | awk '{print $2}' || echo "desconocido")
        ((my_total++)); [[ "$bind_a" == "127.0.0.1" || "$bind_a" == "localhost" ]] && { check_item "bind-address: $bind_a" "OK"; ((my_score++)); } || check_item "bind-address: $bind_a" "WARN"

        # Seguridad
        echo -e "  ${BOLD}Seguridad:${NC}"
        local_inf=$($MYSQL_CMD -N -e "SHOW VARIABLES LIKE 'local_infile'" 2>/dev/null | awk '{print $2}' || echo "desconocido")
        ((my_total++)); [[ "$local_inf" == "OFF" ]] && { check_item "local_infile deshabilitado" "OK"; ((my_score++)); } || check_item "local_infile: $local_inf" "FAIL"

        sec_fp=$($MYSQL_CMD -N -e "SHOW VARIABLES LIKE 'secure_file_priv'" 2>/dev/null | awk '{print $2}' || echo "")
        ((my_total++)); [[ -n "$sec_fp" ]] && { check_item "secure_file_priv: $sec_fp" "OK"; ((my_score++)); } || check_item "secure_file_priv no configurado" "WARN"

        # Autenticacion
        echo -e "  ${BOLD}Autenticacion:${NC}"
        no_pass=$($MYSQL_CMD -N -e "SELECT count(*) FROM mysql.user WHERE authentication_string='' OR authentication_string IS NULL" 2>/dev/null || echo "-1")
        if [[ "$no_pass" != "-1" ]]; then
            ((my_total++)); [[ "$no_pass" -eq 0 ]] && { check_item "Sin cuentas sin contrasena" "OK"; ((my_score++)); } || check_item "$no_pass cuentas sin contrasena" "FAIL"
        fi

        root_rem=$($MYSQL_CMD -N -e "SELECT count(*) FROM mysql.user WHERE user='root' AND host NOT IN ('localhost','127.0.0.1','::1')" 2>/dev/null || echo "-1")
        if [[ "$root_rem" != "-1" ]]; then
            ((my_total++)); [[ "$root_rem" -eq 0 ]] && { check_item "Sin root remoto" "OK"; ((my_score++)); } || check_item "$root_rem accesos root remotos" "FAIL"
        fi

        # Logging
        echo -e "  ${BOLD}Logging:${NC}"
        gen_l=$($MYSQL_CMD -N -e "SHOW VARIABLES LIKE 'general_log'" 2>/dev/null | awk '{print $2}' || echo "desconocido")
        ((my_total++)); [[ "$gen_l" == "ON" ]] && { check_item "general_log habilitado" "OK"; ((my_score++)); } || check_item "general_log: $gen_l" "WARN"

        slow_l=$($MYSQL_CMD -N -e "SHOW VARIABLES LIKE 'slow_query_log'" 2>/dev/null | awk '{print $2}' || echo "desconocido")
        ((my_total++)); [[ "$slow_l" == "ON" ]] && { check_item "slow_query_log habilitado" "OK"; ((my_score++)); } || check_item "slow_query_log: $slow_l" "WARN"

        # Cifrado
        echo -e "  ${BOLD}Cifrado:${NC}"
        have_s=$($MYSQL_CMD -N -e "SHOW VARIABLES LIKE 'have_ssl'" 2>/dev/null | awk '{print $2}' || echo "DISABLED")
        ((my_total++)); [[ "$have_s" == "YES" ]] && { check_item "SSL habilitado" "OK"; ((my_score++)); } || check_item "SSL: $have_s" "FAIL"

        # Puerto expuesto
        if ss -tlnp 2>/dev/null | grep -q ':3306.*0.0.0.0'; then
            ((my_total++)); check_item "Puerto 3306 expuesto en 0.0.0.0" "FAIL"
        else
            ((my_total++)); check_item "Puerto 3306 no expuesto externamente" "OK"; ((my_score++))
        fi
    fi

    rate_db "MySQL/MariaDB" "$my_score" "$my_total"
    total_score=$((total_score + my_score))
    total_checks=$((total_checks + my_total))
    echo ""
fi

# ══════════════════════════════════════════
# Redis
# ══════════════════════════════════════════
if command -v redis-server &>/dev/null || command -v redis-cli &>/dev/null; then
    echo -e "${CYAN}══ Redis ══${NC}"
    rd_score=0
    rd_total=0

    REDIS_CONF=""
    for f in /etc/redis/redis.conf /etc/redis.conf /etc/redis/6379.conf; do
        [[ -f "$f" ]] && REDIS_CONF="$f" && break
    done

    if [[ -n "$REDIS_CONF" ]]; then
        echo -e "  ${DIM}Config: $REDIS_CONF${NC}"

        # Autenticacion
        echo -e "  ${BOLD}Autenticacion:${NC}"
        has_p=$(grep -cE "^requirepass\s+\S+" "$REDIS_CONF" 2>/dev/null || echo "0")
        ((rd_total++)); [[ "$has_p" -gt 0 ]] && { check_item "Contrasena configurada" "OK"; ((rd_score++)); } || check_item "Sin contrasena" "FAIL"

        # Red
        echo -e "  ${BOLD}Red:${NC}"
        bind_v=$(grep -E "^bind\s" "$REDIS_CONF" 2>/dev/null | head -1 || echo "")
        ((rd_total++))
        if [[ -n "$bind_v" ]] && ! echo "$bind_v" | grep -q "0.0.0.0"; then
            check_item "bind restringido" "OK"; ((rd_score++))
        else
            check_item "bind no restringido" "FAIL"
        fi

        prot_m=$(grep -E "^protected-mode\s" "$REDIS_CONF" 2>/dev/null | awk '{print $2}' || echo "no")
        ((rd_total++)); [[ "$prot_m" == "yes" ]] && { check_item "protected-mode habilitado" "OK"; ((rd_score++)); } || check_item "protected-mode: $prot_m" "FAIL"

        # Seguridad
        echo -e "  ${BOLD}Seguridad:${NC}"
        renamed=$(grep -cE "^rename-command\s" "$REDIS_CONF" 2>/dev/null || echo "0")
        ((rd_total++)); [[ "$renamed" -gt 0 ]] && { check_item "$renamed comandos renombrados" "OK"; ((rd_score++)); } || check_item "Sin rename-command" "WARN"

        # Puerto expuesto
        if ss -tlnp 2>/dev/null | grep -q ':6379.*0.0.0.0'; then
            ((rd_total++)); check_item "Puerto 6379 expuesto en 0.0.0.0" "FAIL"
        else
            ((rd_total++)); check_item "Puerto 6379 no expuesto externamente" "OK"; ((rd_score++))
        fi
    fi

    rate_db "Redis" "$rd_score" "$rd_total"
    total_score=$((total_score + rd_score))
    total_checks=$((total_checks + rd_total))
    echo ""
fi

# ══════════════════════════════════════════
# MongoDB
# ══════════════════════════════════════════
if command -v mongod &>/dev/null || command -v mongosh &>/dev/null; then
    echo -e "${CYAN}══ MongoDB ══${NC}"
    mg_score=0
    mg_total=0

    MONGOD_CONF=""
    for f in /etc/mongod.conf /etc/mongodb.conf; do
        [[ -f "$f" ]] && MONGOD_CONF="$f" && break
    done

    if [[ -n "$MONGOD_CONF" ]]; then
        echo -e "  ${DIM}Config: $MONGOD_CONF${NC}"

        # Autenticacion
        echo -e "  ${BOLD}Autenticacion:${NC}"
        auth_v=$(grep -E "^\s*authorization:" "$MONGOD_CONF" 2>/dev/null | awk '{print $2}' || echo "disabled")
        ((mg_total++)); [[ "$auth_v" == "enabled" ]] && { check_item "Autorizacion habilitada" "OK"; ((mg_score++)); } || check_item "Autorizacion: $auth_v" "FAIL"

        # Red
        echo -e "  ${BOLD}Red:${NC}"
        bind_ip=$(grep -E "^\s*bindIp:" "$MONGOD_CONF" 2>/dev/null | awk '{print $2}' || echo "0.0.0.0")
        ((mg_total++)); [[ "$bind_ip" == "127.0.0.1" || "$bind_ip" == "localhost" ]] && { check_item "bindIp: $bind_ip" "OK"; ((mg_score++)); } || check_item "bindIp: $bind_ip" "WARN"

        # Seguridad
        echo -e "  ${BOLD}Seguridad:${NC}"
        js_en=$(grep -E "^\s*javascriptEnabled:" "$MONGOD_CONF" 2>/dev/null | awk '{print $2}' || echo "true")
        ((mg_total++)); [[ "$js_en" == "false" ]] && { check_item "JavaScript deshabilitado" "OK"; ((mg_score++)); } || check_item "JavaScript habilitado" "WARN"

        # Puerto expuesto
        if ss -tlnp 2>/dev/null | grep -q ':27017.*0.0.0.0'; then
            ((mg_total++)); check_item "Puerto 27017 expuesto en 0.0.0.0" "FAIL"
        else
            ((mg_total++)); check_item "Puerto 27017 no expuesto externamente" "OK"; ((mg_score++))
        fi
    fi

    rate_db "MongoDB" "$mg_score" "$mg_total"
    total_score=$((total_score + mg_score))
    total_checks=$((total_checks + mg_total))
    echo ""
fi

# ══════════════════════════════════════════
# Verificaciones transversales
# ══════════════════════════════════════════
echo -e "${CYAN}══ Verificaciones transversales ══${NC}"

# Backups
echo -e "  ${BOLD}Backups:${NC}"
if [[ -d /var/backups/databases ]]; then
    backup_count=$(find /var/backups/databases -name "*.gpg" -mtime -7 2>/dev/null | wc -l)
    ((total_checks++))
    if [[ "$backup_count" -gt 0 ]]; then
        check_item "$backup_count backups cifrados en ultimos 7 dias" "OK"
        ((total_score++))
    else
        check_item "Sin backups recientes (ultimos 7 dias)" "WARN"
    fi
else
    ((total_checks++)); check_item "Directorio de backups no existe" "WARN"
fi

# SQLi monitoring
echo -e "  ${BOLD}Monitoreo SQLi:${NC}"
((total_checks++))
if [[ -x /usr/local/bin/detectar-sqli.sh ]]; then
    check_item "Sistema de deteccion SQLi instalado" "OK"
    ((total_score++))
else
    check_item "Sistema de deteccion SQLi no instalado" "WARN"
fi

# Audit logging
echo -e "  ${BOLD}Audit logging:${NC}"
((total_checks++))
if [[ -d /var/log/db-audit ]]; then
    check_item "Directorio de audit logging existe" "OK"
    ((total_score++))
else
    check_item "Directorio de audit logging no existe" "WARN"
fi

# ══════════════════════════════════════════
# RESUMEN FINAL
# ══════════════════════════════════════════
echo ""
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  RESUMEN DE AUDITORIA${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo ""

# Resultados por base de datos
if [[ ${#db_results[@]} -gt 0 ]]; then
    echo -e "  ${BOLD}Por base de datos:${NC}"
    for result in "${db_results[@]}"; do
        echo "    - $result"
    done
    echo ""
fi

# Puntuacion global
if [[ $total_checks -gt 0 ]]; then
    global_pct=$((total_score * 100 / total_checks))
    if [[ $global_pct -ge 80 ]]; then
        echo -e "  ${BOLD}PUNTUACION GLOBAL: ${GREEN}${total_score}/${total_checks} (${global_pct}%) - BUENO${NC}"
    elif [[ $global_pct -ge 50 ]]; then
        echo -e "  ${BOLD}PUNTUACION GLOBAL: ${YELLOW}${total_score}/${total_checks} (${global_pct}%) - MEJORABLE${NC}"
    else
        echo -e "  ${BOLD}PUNTUACION GLOBAL: ${RED}${total_score}/${total_checks} (${global_pct}%) - DEFICIENTE${NC}"
    fi
else
    echo -e "  ${YELLOW}No se detectaron bases de datos para auditar${NC}"
fi

echo ""
echo "Reporte guardado en: $REPORT_FILE"

# Guardar reporte en texto plano
{
    echo "AUDITORIA DE SEGURIDAD DE BASES DE DATOS"
    echo "Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Hostname: $(hostname)"
    echo ""
    for result in "${db_results[@]}"; do
        echo "  $result"
    done
    echo ""
    if [[ $total_checks -gt 0 ]]; then
        echo "GLOBAL: ${total_score}/${total_checks} ($((total_score * 100 / total_checks))%)"
    fi
} > "$REPORT_FILE"
chmod 600 "$REPORT_FILE"
EOFDBAUDIT
    chmod +x /usr/local/bin/auditoria-bases-datos.sh
    log_change "Creado" "/usr/local/bin/auditoria-bases-datos.sh"

    # Programar auditoria semanal
    if ask "¿Programar auditoria semanal de bases de datos?"; then
        cat > /etc/cron.weekly/auditoria-bases-datos << 'EOFCRONAUDIT'
#!/bin/bash
# Auditoria semanal de seguridad de bases de datos - securizar Modulo 48
/usr/local/bin/auditoria-bases-datos.sh >> /var/log/auditoria-db.log 2>&1
EOFCRONAUDIT
        chmod +x /etc/cron.weekly/auditoria-bases-datos
        log_change "Creado" "/etc/cron.weekly/auditoria-bases-datos"
    else
        log_skip "Cron de auditoria semanal"
    fi

    log_info "Sistema de auditoria integral de bases de datos instalado"
    log_info "Ejecuta: auditoria-bases-datos.sh"
else
    log_skip "Auditoria integral de seguridad de bases de datos"
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
show_changes_summary
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     SEGURIDAD DE BASES DE DATOS COMPLETADO               ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups guardados en: $BACKUP_DIR"
echo ""
echo "Comandos utiles post-hardening:"
echo "  - Auditar PostgreSQL:     auditar-postgresql.sh"
echo "  - Auditar MySQL/MariaDB:  auditar-mysql.sh"
echo "  - Auditar Redis:          auditar-redis.sh"
echo "  - Auditar MongoDB:        auditar-mongodb.sh"
echo "  - Auditar acceso DB:      auditar-acceso-db.sh"
echo "  - Verificar cifrado:      verificar-cifrado-db.sh"
echo "  - Backup seguro:          backup-seguro-db.sh [db|all]"
echo "  - Configurar audit log:   configurar-audit-db.sh"
echo "  - Detectar SQLi:          detectar-sqli.sh [--watch]"
echo "  - Auditoria completa:     auditoria-bases-datos.sh"
echo ""
log_info "Modulo 48 completado"
log_warn "RECOMENDACION: Ejecuta 'auditoria-bases-datos.sh' para ver la postura actual"
