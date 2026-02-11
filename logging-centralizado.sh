#!/bin/bash
# ============================================================
# LOGGING CENTRALIZADO Y SIEM - Linux Multi-Distro
# Modulo 43 - Securizar Suite
# ============================================================
# Secciones:
#   S1  - Hardening de rsyslog/journald
#   S2  - Reenvio seguro de logs (TLS)
#   S3  - Agregacion y normalizacion
#   S4  - Almacenamiento seguro de logs
#   S5  - Correlacion basica de eventos
#   S6  - Alertas en tiempo real
#   S7  - Retencion y rotacion avanzada
#   S8  - Integracion SIEM (ELK/Splunk/Graylog)
#   S9  - Forense de logs
#   S10 - Auditoria de logging
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "logging-centralizado"
securizar_setup_traps

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MODULO 43 - LOGGING CENTRALIZADO Y SIEM                ║"
echo "║   rsyslog TLS, agregacion, correlacion, alertas,         ║"
echo "║   SIEM, forense                                          ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

# Directorios base del modulo
mkdir -p /etc/securizar/log-certs
mkdir -p /etc/securizar/siem
mkdir -p /var/lib/securizar/log-hashes
mkdir -p /var/lib/securizar/forense
mkdir -p /var/log/securizar

# ============================================================
# S1: HARDENING DE RSYSLOG/JOURNALD
# ============================================================
log_section "S1: HARDENING DE RSYSLOG/JOURNALD"

echo "Configura rsyslog y journald con parametros de seguridad:"
echo "  - Permisos restrictivos de archivos de log"
echo "  - Cola asincrona con persistencia ante apagados"
echo "  - journald persistente con sellado criptografico"
echo "  - Compresion y limites de almacenamiento"
echo ""

if ask "¿Aplicar hardening de rsyslog y journald?"; then

    # --- Instalar y activar rsyslog ---
    if ! command -v rsyslogd &>/dev/null; then
        log_info "Instalando rsyslog..."
        pkg_install "rsyslog"
    else
        log_skip "rsyslog ya instalado"
    fi

    systemctl enable rsyslog &>/dev/null || true
    systemctl start rsyslog &>/dev/null || true
    log_info "rsyslog activo y habilitado"

    # --- Configuracion de hardening rsyslog ---
    RSYSLOG_HARD="/etc/rsyslog.d/01-securizar-hardening.conf"
    if [[ -f "$RSYSLOG_HARD" ]]; then
        cp "$RSYSLOG_HARD" "$BACKUP_DIR/"
        log_change "Backup" "$RSYSLOG_HARD"
    fi

    cat > "$RSYSLOG_HARD" << 'EOFRSYSHARD'
# ============================================================
# Hardening rsyslog - Generado por logging-centralizado.sh
# Modulo 43 - Securizar Suite
# ============================================================

# --- Permisos restrictivos para archivos de log ---
$FileOwner root
$FileGroup adm
$FileCreateMode 0640
$DirCreateMode 0750
$Umask 0027

# --- Cola asincrona para mejor rendimiento ---
$ActionQueueType LinkedList
$ActionQueueFileName securizar-fwd
$ActionQueueSaveOnShutdown on
$ActionResumeRetryCount -1
$ActionQueueMaxDiskSpace 500M
$ActionQueueSize 100000

# --- Limitar tamano de mensajes ---
$MaxMessageSize 32k

# --- Descartar mensajes malformados ---
$AbortOnUncleanConfig on

# --- Rate limiting para evitar DoS de logs ---
$SystemLogRateLimitInterval 5
$SystemLogRateLimitBurst 500

# --- DNS cache para rendimiento ---
$DNSCacheEnable on

# --- Escapar caracteres de control en logs ---
$EscapeControlCharactersOnReceive on
$DropTrailingLFOnReception on
EOFRSYSHARD

    chmod 644 "$RSYSLOG_HARD"
    log_change "Creado" "$RSYSLOG_HARD (hardening rsyslog)"

    # --- Hardening de journald ---
    mkdir -p /etc/systemd/journald.conf.d
    JOURNALD_CONF="/etc/systemd/journald.conf.d/01-securizar.conf"
    if [[ -f "$JOURNALD_CONF" ]]; then
        cp "$JOURNALD_CONF" "$BACKUP_DIR/"
        log_change "Backup" "$JOURNALD_CONF"
    fi

    cat > "$JOURNALD_CONF" << 'EOFJOURNALD'
# ============================================================
# Hardening journald - Generado por logging-centralizado.sh
# Modulo 43 - Securizar Suite
# ============================================================

[Journal]
# Almacenamiento persistente en /var/log/journal
Storage=persistent

# Compresion de logs almacenados
Compress=yes

# Limites de almacenamiento
SystemMaxUse=2G
SystemKeepFree=1G
SystemMaxFileSize=100M
RuntimeMaxUse=500M
RuntimeKeepFree=100M
RuntimeMaxFileSize=50M

# Reenviar a syslog para rsyslog
ForwardToSyslog=yes

# Sellado criptografico (Forward Secure Sealing)
Seal=yes

# Niveles maximos de log
MaxLevelStore=debug
MaxLevelSyslog=debug
MaxLevelKMsg=notice
MaxLevelConsole=info
MaxLevelWall=emerg

# Rate limiting
RateLimitIntervalSec=30s
RateLimitBurst=10000

# Campos de confianza
SplitMode=uid
EOFJOURNALD

    chmod 644 "$JOURNALD_CONF"
    log_change "Creado" "$JOURNALD_CONF (hardening journald)"

    # --- Permisos de /var/log ---
    VARLOG_PERMS=$(stat -c '%a' /var/log 2>/dev/null || echo "755")
    if [[ "$VARLOG_PERMS" != "750" ]]; then
        chmod 750 /var/log
        chown root:adm /var/log 2>/dev/null || chown root:root /var/log
        log_change "Permisos" "/var/log -> 750 root:adm"
    else
        log_skip "/var/log ya tiene permisos 750"
    fi

    # --- Crear directorio persistente de journal ---
    mkdir -p /var/log/journal
    systemd-tmpfiles --create --prefix /var/log/journal 2>/dev/null || true
    log_change "Creado" "/var/log/journal (almacenamiento persistente)"

    # --- Reiniciar journald ---
    systemctl restart systemd-journald 2>/dev/null || true
    log_info "journald reiniciado con configuracion segura"

    # --- Validar y recargar rsyslog ---
    if rsyslogd -N1 &>/dev/null; then
        systemctl restart rsyslog 2>/dev/null || true
        log_info "rsyslog reiniciado - configuracion validada"
    else
        log_warn "Error de sintaxis en rsyslog. Revisa: rsyslogd -N1"
    fi

else
    log_skip "Hardening de rsyslog/journald"
fi

# ============================================================
# S2: REENVIO SEGURO DE LOGS (TLS)
# ============================================================
log_section "S2: REENVIO SEGURO DE LOGS (TLS)"

echo "Configura reenvio de logs via TLS a servidor central:"
echo "  - Modulo rsyslog-gnutls para cifrado"
echo "  - Generacion de certificados auto-firmados"
echo "  - Template JSON estructurado para SIEM"
echo "  - Cola con respaldo en disco (10000 mensajes)"
echo ""

if ask "¿Configurar reenvio seguro de logs via TLS?"; then

    # --- Instalar modulo TLS ---
    if ! pkg_is_installed "rsyslog-gnutls"; then
        log_info "Instalando modulo rsyslog-gnutls..."
        pkg_install "rsyslog-gnutls"
    else
        log_skip "rsyslog-gnutls ya instalado"
    fi

    # --- Generar certificados auto-firmados ---
    CERT_DIR="/etc/securizar/log-certs"
    mkdir -p "$CERT_DIR"

    if [[ ! -f "$CERT_DIR/ca.pem" ]]; then
        log_info "Generando CA y certificados para rsyslog TLS..."

        # Generar CA
        openssl genrsa -out "$CERT_DIR/ca-key.pem" 4096 2>/dev/null
        openssl req -new -x509 -days 3650 -key "$CERT_DIR/ca-key.pem" \
            -out "$CERT_DIR/ca.pem" \
            -subj "/CN=Securizar Log CA/O=Securizar/OU=Logging" 2>/dev/null

        # Generar certificado de servidor/cliente
        openssl genrsa -out "$CERT_DIR/log-key.pem" 2048 2>/dev/null
        openssl req -new -key "$CERT_DIR/log-key.pem" \
            -out "$CERT_DIR/log.csr" \
            -subj "/CN=$(hostname)/O=Securizar/OU=Logging" 2>/dev/null
        openssl x509 -req -days 1825 -in "$CERT_DIR/log.csr" \
            -CA "$CERT_DIR/ca.pem" -CAkey "$CERT_DIR/ca-key.pem" \
            -CAcreateserial -out "$CERT_DIR/log-cert.pem" 2>/dev/null

        # Permisos restrictivos
        chmod 600 "$CERT_DIR"/*.pem "$CERT_DIR"/*.csr 2>/dev/null || true
        chmod 644 "$CERT_DIR/ca.pem"
        chmod 700 "$CERT_DIR"
        chown -R root:root "$CERT_DIR"

        rm -f "$CERT_DIR/log.csr" "$CERT_DIR/ca.srl"
        log_change "Generados" "certificados TLS en $CERT_DIR"
    else
        log_skip "Certificados TLS ya existen en $CERT_DIR"
    fi

    # --- Configuracion de reenvio TLS ---
    TLS_CONF="/etc/rsyslog.d/10-securizar-tls-forwarding.conf"
    if [[ -f "$TLS_CONF" ]]; then
        cp "$TLS_CONF" "$BACKUP_DIR/"
        log_change "Backup" "$TLS_CONF"
    fi

    cat > "$TLS_CONF" << 'EOFTLS'
# ============================================================
# Reenvio seguro de logs via TLS
# Generado por logging-centralizado.sh - Modulo 43
# ============================================================
# INSTRUCCIONES:
#   1. Edita LOG_SERVER_IP y LOG_SERVER_PORT abajo
#   2. Copia ca.pem al servidor central
#   3. Ejecuta: /usr/local/bin/configurar-log-remoto.sh <IP>
# ============================================================

# --- Cargar modulo GnuTLS ---
module(load="imtcp")
$DefaultNetstreamDriver gtls

# --- Certificados TLS ---
$DefaultNetstreamDriverCAFile /etc/securizar/log-certs/ca.pem
$DefaultNetstreamDriverCertFile /etc/securizar/log-certs/log-cert.pem
$DefaultNetstreamDriverKeyFile /etc/securizar/log-certs/log-key.pem

# --- Template JSON estructurado para SIEM ---
template(name="SecurizarJSON" type="list") {
    constant(value="{")
    constant(value="\"@timestamp\":\"")     property(name="timereported" dateFormat="rfc3339")
    constant(value="\",\"host\":\"")        property(name="hostname")
    constant(value="\",\"severity\":\"")    property(name="syslogseverity-text")
    constant(value="\",\"facility\":\"")    property(name="syslogfacility-text")
    constant(value="\",\"tag\":\"")         property(name="syslogtag" format="json")
    constant(value="\",\"message\":\"")     property(name="msg" format="json")
    constant(value="\",\"program\":\"")     property(name="programname")
    constant(value="\",\"pid\":\"")         property(name="procid")
    constant(value="\",\"source_ip\":\"")   property(name="fromhost-ip")
    constant(value="\"}\n")
}

# --- Accion de reenvio (DESACTIVADA por defecto) ---
# Descomenta y configura la IP del servidor central:
#
# action(type="omfwd"
#     Target="SERVIDOR_LOG_IP"
#     Port="6514"
#     Protocol="tcp"
#     StreamDriver="gtls"
#     StreamDriverMode="1"
#     StreamDriverAuthMode="x509/name"
#     StreamDriverPermittedPeers="*.securizar.local"
#     template="SecurizarJSON"
#     queue.type="LinkedList"
#     queue.filename="securizar-fwd-tls"
#     queue.maxDiskSpace="500m"
#     queue.saveOnShutdown="on"
#     queue.size="10000"
#     queue.dequeueBatchSize="128"
#     action.resumeRetryCount="-1"
#     action.resumeInterval="30"
# )
EOFTLS

    chmod 644 "$TLS_CONF"
    log_change "Creado" "$TLS_CONF (reenvio TLS)"

    # --- Helper para configurar servidor remoto ---
    cat > /usr/local/bin/configurar-log-remoto.sh << 'EOFHELPER'
#!/bin/bash
# ============================================================
# Configura el servidor remoto de logs (rsyslog TLS)
# Uso: configurar-log-remoto.sh <IP_SERVIDOR> [PUERTO]
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

SERVER_IP="${1:-}"
SERVER_PORT="${2:-6514}"

if [[ -z "$SERVER_IP" ]]; then
    echo "Uso: $0 <IP_SERVIDOR> [PUERTO]"
    echo "  Ejemplo: $0 192.168.1.100 6514"
    exit 1
fi

TLS_CONF="/etc/rsyslog.d/10-securizar-tls-forwarding.conf"
if [[ ! -f "$TLS_CONF" ]]; then
    echo "[X] No existe $TLS_CONF. Ejecuta primero logging-centralizado.sh"
    exit 1
fi

# Verificar que los certificados existen
for cert in ca.pem log-cert.pem log-key.pem; do
    if [[ ! -f "/etc/securizar/log-certs/$cert" ]]; then
        echo "[X] Certificado faltante: /etc/securizar/log-certs/$cert"
        exit 1
    fi
done

# Activar el reenvio en la configuracion
cat >> "$TLS_CONF" << EOFACTIVE

# --- Reenvio activo configurado: $(date -Iseconds) ---
action(type="omfwd"
    Target="$SERVER_IP"
    Port="$SERVER_PORT"
    Protocol="tcp"
    StreamDriver="gtls"
    StreamDriverMode="1"
    StreamDriverAuthMode="x509/name"
    StreamDriverPermittedPeers="*"
    template="SecurizarJSON"
    queue.type="LinkedList"
    queue.filename="securizar-fwd-tls-active"
    queue.maxDiskSpace="500m"
    queue.saveOnShutdown="on"
    queue.size="10000"
    queue.dequeueBatchSize="128"
    action.resumeRetryCount="-1"
    action.resumeInterval="30"
)
EOFACTIVE

# Validar configuracion
if rsyslogd -N1 &>/dev/null; then
    systemctl restart rsyslog
    echo "[+] Reenvio TLS activado hacia $SERVER_IP:$SERVER_PORT"
    echo "[+] rsyslog reiniciado correctamente"
else
    echo "[X] Error de sintaxis en rsyslog. Revisa: rsyslogd -N1"
    echo "[!] Revierte manualmente: $TLS_CONF"
fi
EOFHELPER

    chmod 755 /usr/local/bin/configurar-log-remoto.sh
    log_change "Creado" "/usr/local/bin/configurar-log-remoto.sh"

    log_info "Reenvio TLS configurado (desactivado por defecto)"
    log_info "Activa con: configurar-log-remoto.sh <IP_SERVIDOR>"

else
    log_skip "Reenvio seguro de logs (TLS)"
fi

# ============================================================
# S3: AGREGACION Y NORMALIZACION
# ============================================================
log_section "S3: AGREGACION Y NORMALIZACION"

echo "Configura normalizacion y clasificacion de logs:"
echo "  - Templates CEF y JSON para salida estructurada"
echo "  - Filtros por servicio: SSH, sudo, firewall, cron, auth"
echo "  - Organizacion por facility+severity"
echo "  - Enriquecimiento con hostname, IP, prioridad"
echo "  - Normalizacion de timestamps (RFC 5424)"
echo ""

if ask "¿Configurar agregacion y normalizacion de logs?"; then

    # --- Template de normalizacion ---
    NORM_CONF="/etc/rsyslog.d/20-securizar-normalize.conf"
    if [[ -f "$NORM_CONF" ]]; then
        cp "$NORM_CONF" "$BACKUP_DIR/"
        log_change "Backup" "$NORM_CONF"
    fi

    cat > "$NORM_CONF" << 'EOFNORM'
# ============================================================
# Normalizacion y clasificacion de logs
# Generado por logging-centralizado.sh - Modulo 43
# ============================================================

# --- Template CEF (Common Event Format) ---
template(name="SecurizarCEF" type="string"
    string="CEF:0|Securizar|LinuxHost|1.0|%syslogseverity%|%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%|%syslogseverity%|src=%fromhost-ip% dhost=%hostname% msg=%msg:::json%\n"
)

# --- Template JSON estructurado ---
template(name="SecurizarJSONFull" type="list") {
    constant(value="{")
    constant(value="\"@timestamp\":\"")     property(name="timereported" dateFormat="rfc3339")
    constant(value="\",\"host\":\"")        property(name="hostname")
    constant(value="\",\"severity\":\"")    property(name="syslogseverity-text")
    constant(value="\",\"severity_num\":")  property(name="syslogseverity")
    constant(value=",\"facility\":\"")      property(name="syslogfacility-text")
    constant(value="\",\"program\":\"")     property(name="programname")
    constant(value="\",\"pid\":\"")         property(name="procid")
    constant(value="\",\"tag\":\"")         property(name="syslogtag" format="json")
    constant(value="\",\"source_ip\":\"")   property(name="fromhost-ip")
    constant(value="\",\"message\":\"")     property(name="msg" format="json")
    constant(value="\"}\n")
}

# --- Template para nombres de archivo por fecha ---
template(name="SecurizarDynFile" type="string"
    string="/var/log/securizar/%syslogfacility-text%/%syslogseverity-text%/%$year%-%$month%-%$day%.log"
)

# --- Directorios de clasificacion ---
template(name="SecurizarSSH" type="string"
    string="/var/log/securizar/ssh/%$year%-%$month%-%$day%.log"
)
template(name="SecurizarSudo" type="string"
    string="/var/log/securizar/sudo/%$year%-%$month%-%$day%.log"
)
template(name="SecurizarFirewall" type="string"
    string="/var/log/securizar/firewall/%$year%-%$month%-%$day%.log"
)
template(name="SecurizarCron" type="string"
    string="/var/log/securizar/cron/%$year%-%$month%-%$day%.log"
)
template(name="SecurizarAuth" type="string"
    string="/var/log/securizar/auth/%$year%-%$month%-%$day%.log"
)

# --- Filtros por servicio ---
# SSH
if $programname == 'sshd' then {
    action(type="omfile" dynaFile="SecurizarSSH" template="SecurizarJSONFull"
           FileOwner="root" FileGroup="adm" FileCreateMode="0640"
           DirCreateMode="0750" CreateDirs="on")
}

# Sudo
if $programname == 'sudo' then {
    action(type="omfile" dynaFile="SecurizarSudo" template="SecurizarJSONFull"
           FileOwner="root" FileGroup="adm" FileCreateMode="0640"
           DirCreateMode="0750" CreateDirs="on")
}

# Firewall (iptables, nftables, firewalld)
if $msg contains 'iptables' or $msg contains 'nftables' or $msg contains 'firewalld' or $msg contains 'UFW' then {
    action(type="omfile" dynaFile="SecurizarFirewall" template="SecurizarJSONFull"
           FileOwner="root" FileGroup="adm" FileCreateMode="0640"
           DirCreateMode="0750" CreateDirs="on")
}

# Cron
if $programname == 'cron' or $programname == 'CRON' or $programname == 'crond' then {
    action(type="omfile" dynaFile="SecurizarCron" template="SecurizarJSONFull"
           FileOwner="root" FileGroup="adm" FileCreateMode="0640"
           DirCreateMode="0750" CreateDirs="on")
}

# Auth (PAM, login, su)
if $syslogfacility-text == 'auth' or $syslogfacility-text == 'authpriv' then {
    action(type="omfile" dynaFile="SecurizarAuth" template="SecurizarJSONFull"
           FileOwner="root" FileGroup="adm" FileCreateMode="0640"
           DirCreateMode="0750" CreateDirs="on")
}

# --- Catch-all clasificado por facility+severity ---
action(type="omfile" dynaFile="SecurizarDynFile" template="SecurizarJSONFull"
       FileOwner="root" FileGroup="adm" FileCreateMode="0640"
       DirCreateMode="0750" CreateDirs="on")
EOFNORM

    chmod 644 "$NORM_CONF"
    log_change "Creado" "$NORM_CONF (normalizacion)"

    # --- Enriquecimiento y deduplicacion ---
    ENRICH_CONF="/etc/rsyslog.d/21-securizar-enrich.conf"
    if [[ -f "$ENRICH_CONF" ]]; then
        cp "$ENRICH_CONF" "$BACKUP_DIR/"
        log_change "Backup" "$ENRICH_CONF"
    fi

    cat > "$ENRICH_CONF" << 'EOFENRICH'
# ============================================================
# Enriquecimiento y deduplicacion de logs
# Generado por logging-centralizado.sh - Modulo 43
# ============================================================

# --- Forzar timestamps RFC 5424 ---
$ActionFileDefaultTemplate RSYSLOG_SyslogProtocol23Format

# --- Agregar hostname y prioridad a todos los mensajes ---
template(name="SecurizarEnriched" type="list") {
    constant(value="<")
    property(name="pri")
    constant(value=">1 ")
    property(name="timereported" dateFormat="rfc3339")
    constant(value=" ")
    property(name="hostname")
    constant(value=" ")
    property(name="programname")
    constant(value=" ")
    property(name="procid")
    constant(value=" - - ")
    property(name="msg" droplastlf="on")
    constant(value="\n")
}

# --- Deduplicacion de mensajes repetidos ---
# rsyslog reduce mensajes identicos consecutivos automaticamente
$RepeatedMsgReduction on
$RepeatedMsgContainsOriginalMsg on
EOFENRICH

    chmod 644 "$ENRICH_CONF"
    log_change "Creado" "$ENRICH_CONF (enriquecimiento)"

    # Crear directorios de clasificacion
    for subdir in ssh sudo firewall cron auth; do
        mkdir -p "/var/log/securizar/$subdir"
        chown root:adm "/var/log/securizar/$subdir" 2>/dev/null || true
        chmod 750 "/var/log/securizar/$subdir"
    done
    log_change "Creados" "directorios de clasificacion en /var/log/securizar/"

    # Validar y recargar rsyslog
    if rsyslogd -N1 &>/dev/null; then
        systemctl restart rsyslog 2>/dev/null || true
        log_info "rsyslog reiniciado con normalizacion activa"
    else
        log_warn "Error de sintaxis en rsyslog. Revisa: rsyslogd -N1"
    fi

else
    log_skip "Agregacion y normalizacion de logs"
fi

# ============================================================
# S4: ALMACENAMIENTO SEGURO DE LOGS
# ============================================================
log_section "S4: ALMACENAMIENTO SEGURO DE LOGS"

echo "Configura almacenamiento seguro e integridad de logs:"
echo "  - Atributos inmutables (chattr +a) en logs criticos"
echo "  - Cadena de hashes SHA-256 para integridad"
echo "  - Integracion con logrotate"
echo "  - Almacenamiento cifrado opcional (gocryptfs)"
echo ""

if ask "¿Configurar almacenamiento seguro de logs?"; then

    # --- Atributos inmutables en logs criticos ---
    CRITICAL_LOGS=(
        /var/log/auth.log
        /var/log/secure
        /var/log/syslog
        /var/log/messages
        /var/log/kern.log
    )
    for logfile in "${CRITICAL_LOGS[@]}"; do
        if [[ -f "$logfile" ]]; then
            # append-only: solo se puede agregar, no borrar ni truncar
            chattr +a "$logfile" 2>/dev/null || true
            log_change "Inmutable" "$logfile (chattr +a)"
        fi
    done

    # --- Script de integridad de logs ---
    cat > /usr/local/bin/securizar-log-integrity.sh << 'EOFINTEGRITY'
#!/bin/bash
# ============================================================
# Verificacion de integridad de logs (cadena SHA-256)
# Uso: securizar-log-integrity.sh [generar|verificar]
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

HASH_DIR="/var/lib/securizar/log-hashes"
mkdir -p "$HASH_DIR"

MODO="${1:-verificar}"
FECHA=$(date +%Y%m%d)
HASH_FILE="$HASH_DIR/hashes-${FECHA}.sha256"
CHAIN_FILE="$HASH_DIR/chain.sha256"

# Logs criticos a verificar
LOGS_CRITICOS=(
    /var/log/auth.log
    /var/log/secure
    /var/log/syslog
    /var/log/messages
    /var/log/kern.log
    /var/log/audit/audit.log
)

case "$MODO" in
    generar)
        echo "=== Generando hashes SHA-256: $(date -Iseconds) ===" > "$HASH_FILE"

        for logfile in "${LOGS_CRITICOS[@]}"; do
            if [[ -f "$logfile" ]]; then
                hash=$(sha256sum "$logfile" | awk '{print $1}')
                size=$(stat -c '%s' "$logfile" 2>/dev/null || echo "0")
                echo "${hash}  ${logfile}  size=${size}  date=$(date -Iseconds)" >> "$HASH_FILE"
            fi
        done

        # Agregar a la cadena de hashes
        if [[ -f "$CHAIN_FILE" ]]; then
            PREV_HASH=$(tail -1 "$CHAIN_FILE" | awk '{print $1}')
        else
            PREV_HASH="GENESIS"
        fi

        CURRENT_HASH=$(sha256sum "$HASH_FILE" | awk '{print $1}')
        echo "${CURRENT_HASH}  ${HASH_FILE}  prev=${PREV_HASH}  date=$(date -Iseconds)" >> "$CHAIN_FILE"

        echo "[+] Hashes generados en $HASH_FILE"
        echo "[+] Cadena actualizada en $CHAIN_FILE"
        ;;

    verificar)
        if [[ ! -f "$HASH_FILE" ]]; then
            # Buscar el hash mas reciente
            HASH_FILE=$(ls -t "$HASH_DIR"/hashes-*.sha256 2>/dev/null | head -1)
            if [[ -z "$HASH_FILE" ]]; then
                echo "[!] No hay hashes generados. Ejecuta: $0 generar"
                exit 1
            fi
        fi

        echo "=== Verificacion de integridad: $(date -Iseconds) ==="
        echo "Archivo de referencia: $HASH_FILE"
        echo ""

        FALLOS=0
        while IFS= read -r line; do
            [[ "$line" == "==="* ]] && continue
            [[ -z "$line" ]] && continue

            EXPECTED_HASH=$(echo "$line" | awk '{print $1}')
            LOGFILE=$(echo "$line" | awk '{print $2}')

            if [[ ! -f "$LOGFILE" ]]; then
                echo "[!] FALTANTE: $LOGFILE"
                ((FALLOS++)) || true
                continue
            fi

            ACTUAL_HASH=$(sha256sum "$LOGFILE" | awk '{print $1}')
            if [[ "$EXPECTED_HASH" == "$ACTUAL_HASH" ]]; then
                echo "[OK] $LOGFILE"
            else
                echo "[X] MODIFICADO: $LOGFILE"
                echo "    Esperado: $EXPECTED_HASH"
                echo "    Actual:   $ACTUAL_HASH"
                ((FALLOS++)) || true
            fi
        done < "$HASH_FILE"

        echo ""
        if [[ $FALLOS -eq 0 ]]; then
            echo "[+] Integridad OK - todos los logs verificados"
        else
            echo "[X] ALERTA: $FALLOS archivos con integridad comprometida"
            exit 1
        fi
        ;;

    cadena)
        # Verificar integridad de la cadena completa
        if [[ ! -f "$CHAIN_FILE" ]]; then
            echo "[!] No existe cadena de hashes"
            exit 1
        fi

        echo "=== Verificacion de cadena de custodia ==="
        PREV="GENESIS"
        FALLOS=0
        while IFS= read -r line; do
            HASH=$(echo "$line" | awk '{print $1}')
            FILE=$(echo "$line" | awk '{print $2}')
            EXPECTED_PREV=$(echo "$line" | grep -oP 'prev=\K[^ ]+')

            if [[ "$EXPECTED_PREV" != "$PREV" ]]; then
                echo "[X] ROTURA EN CADENA: $FILE"
                echo "    Esperado prev=$PREV, encontrado prev=$EXPECTED_PREV"
                ((FALLOS++)) || true
            else
                echo "[OK] $FILE (prev=$PREV)"
            fi
            PREV="$HASH"
        done < "$CHAIN_FILE"

        if [[ $FALLOS -eq 0 ]]; then
            echo "[+] Cadena integra"
        else
            echo "[X] ALERTA: cadena comprometida ($FALLOS roturas)"
        fi
        ;;

    *)
        echo "Uso: $0 [generar|verificar|cadena]"
        exit 1
        ;;
esac
EOFINTEGRITY

    chmod 755 /usr/local/bin/securizar-log-integrity.sh
    log_change "Creado" "/usr/local/bin/securizar-log-integrity.sh"

    # --- Cron diario para generar hashes ---
    cat > /etc/cron.daily/securizar-log-hashes << 'EOFCRONHASH'
#!/bin/bash
# Generacion diaria de hashes de integridad de logs
/usr/local/bin/securizar-log-integrity.sh generar >/dev/null 2>&1
EOFCRONHASH

    chmod 755 /etc/cron.daily/securizar-log-hashes
    log_change "Creado" "/etc/cron.daily/securizar-log-hashes"

    # --- Logrotate para logs de securizar ---
    cat > /etc/logrotate.d/securizar-logs << 'EOFROTATE'
/var/log/securizar/*/*.log {
    daily
    missingok
    rotate 90
    compress
    delaycompress
    notifempty
    create 0640 root adm
    dateext
    dateformat -%Y%m%d
    sharedscripts
    postrotate
        # Quitar chattr +a antes de rotar, restaurar despues
        for f in /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages /var/log/kern.log; do
            [ -f "$f" ] && chattr -a "$f" 2>/dev/null || true
        done
        /usr/lib/rsyslog/rsyslog-rotate 2>/dev/null || systemctl kill -s HUP rsyslog 2>/dev/null || true
        for f in /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages /var/log/kern.log; do
            [ -f "$f" ] && chattr +a "$f" 2>/dev/null || true
        done
    endscript
}
EOFROTATE

    chmod 644 /etc/logrotate.d/securizar-logs
    log_change "Creado" "/etc/logrotate.d/securizar-logs"

    # --- Almacenamiento cifrado opcional ---
    if command -v gocryptfs &>/dev/null; then
        log_info "gocryptfs detectado - almacenamiento cifrado disponible"
        VAULT_DIR="/var/log/securizar-vault"
        VAULT_CIPHER="/var/log/.securizar-vault-cipher"

        if [[ ! -d "$VAULT_CIPHER" ]]; then
            mkdir -p "$VAULT_DIR" "$VAULT_CIPHER"
            chmod 700 "$VAULT_DIR" "$VAULT_CIPHER"
            log_info "Directorios de vault creados"
            log_warn "Para inicializar el vault cifrado ejecuta:"
            log_warn "  gocryptfs -init $VAULT_CIPHER"
            log_warn "  gocryptfs $VAULT_CIPHER $VAULT_DIR"
        else
            log_skip "Vault cifrado ya inicializado"
        fi
    else
        log_info "gocryptfs no disponible. Para cifrado de logs: pkg_install gocryptfs"
    fi

    # Generar hashes iniciales
    /usr/local/bin/securizar-log-integrity.sh generar 2>/dev/null || true
    log_info "Hashes iniciales de integridad generados"

else
    log_skip "Almacenamiento seguro de logs"
fi

# ============================================================
# S5: CORRELACION BASICA DE EVENTOS
# ============================================================
log_section "S5: CORRELACION BASICA DE EVENTOS"

echo "Crea herramienta de correlacion de eventos de seguridad:"
echo "  - Fuerza bruta SSH (>5 fallos en 5 min)"
echo "  - Escalada de privilegios (su/sudo tras SSH)"
echo "  - Interrupcion de servicios multiples"
echo "  - Movimiento lateral (SSH desde host interno)"
echo "  - Preparacion de exfiltracion (archivos grandes + red)"
echo "  - Anomalia de autenticacion (login fuera de horario)"
echo "  - Manipulacion de logs (borrado/truncado)"
echo "  - Instalacion de persistencia (crontab/systemd tras SSH)"
echo ""

if ask "¿Instalar herramienta de correlacion de eventos?"; then

    cat > /usr/local/bin/correlacionar-eventos.sh << 'EOFCORR'
#!/bin/bash
# ============================================================
# CORRELACION BASICA DE EVENTOS DE SEGURIDAD
# Detecta patrones de ataque combinando multiples fuentes de log
# Uso: correlacionar-eventos.sh [--rango HORAS]
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

RANGO_HORAS="${1:-1}"
if [[ "$1" == "--rango" ]]; then
    RANGO_HORAS="${2:-1}"
fi

SINCE="$(date -d "${RANGO_HORAS} hours ago" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')"
OUTPUT="/var/log/securizar/correlacion.log"
mkdir -p "$(dirname "$OUTPUT")"

ALERTAS=0

echo "=== CORRELACION DE EVENTOS: $(date -Iseconds) ===" | tee "$OUTPUT"
echo "Rango analizado: ultimas $RANGO_HORAS hora(s) desde $SINCE" | tee -a "$OUTPUT"
echo "" | tee -a "$OUTPUT"

# ── Patron 1: Fuerza bruta SSH ──
echo -e "${BOLD}[P1] Fuerza bruta SSH (>5 fallos desde misma IP en 5min)${NC}" | tee -a "$OUTPUT"

AUTH_LOG=""
for f in /var/log/auth.log /var/log/secure; do
    [[ -f "$f" ]] && AUTH_LOG="$f" && break
done

if [[ -n "$AUTH_LOG" ]]; then
    declare -A SSH_FAILS
    while IFS= read -r line; do
        ip=$(echo "$line" | grep -oP 'from \K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
        if [[ -n "$ip" ]]; then
            SSH_FAILS[$ip]=$(( ${SSH_FAILS[$ip]:-0} + 1 ))
        fi
    done < <(grep -i "failed password\|authentication failure" "$AUTH_LOG" 2>/dev/null | tail -500)

    for ip in "${!SSH_FAILS[@]}"; do
        count="${SSH_FAILS[$ip]}"
        if [[ "$count" -ge 5 ]]; then
            echo -e "  ${RED}[ALERTA]${NC} IP $ip: $count intentos fallidos" | tee -a "$OUTPUT"
            ((ALERTAS++)) || true
        fi
    done
    unset SSH_FAILS
else
    echo "  (sin log de autenticacion disponible)" | tee -a "$OUTPUT"
fi
echo "" | tee -a "$OUTPUT"

# ── Patron 2: Escalada de privilegios ──
echo -e "${BOLD}[P2] Escalada de privilegios (su/sudo tras login SSH)${NC}" | tee -a "$OUTPUT"

if [[ -n "$AUTH_LOG" ]]; then
    # Buscar usuarios que hicieron SSH login y luego su/sudo
    SSH_USERS=$(grep "Accepted\|session opened" "$AUTH_LOG" 2>/dev/null | grep -i ssh | grep -oP 'for \K\w+' | sort -u || true)
    for user in $SSH_USERS; do
        SUDO_COUNT=$(grep -c "sudo.*${user}\|su.*${user}" "$AUTH_LOG" 2>/dev/null || echo "0")
        if [[ "$SUDO_COUNT" -gt 0 ]]; then
            echo -e "  ${YELLOW}[INFO]${NC} $user: SSH login + $SUDO_COUNT acciones sudo/su" | tee -a "$OUTPUT"
        fi
    done
fi
echo "" | tee -a "$OUTPUT"

# ── Patron 3: Interrupcion de servicios ──
echo -e "${BOLD}[P3] Interrupcion de servicios (multiples fallos en periodo)${NC}" | tee -a "$OUTPUT"

SYSLOG=""
for f in /var/log/syslog /var/log/messages; do
    [[ -f "$f" ]] && SYSLOG="$f" && break
done

if [[ -n "$SYSLOG" ]]; then
    FAILED_SVCS=$(grep -i "failed\|error\|stopped" "$SYSLOG" 2>/dev/null | grep -i "systemd" | grep -oP "Started\s+\K.+|Stopped\s+\K.+|Failed\s+\K.+" | sort | uniq -c | sort -rn | head -10 || true)
    if [[ -n "$FAILED_SVCS" ]]; then
        echo "$FAILED_SVCS" | while IFS= read -r line; do
            count=$(echo "$line" | awk '{print $1}')
            svc=$(echo "$line" | sed 's/^[[:space:]]*[0-9]*[[:space:]]*//')
            if [[ "$count" -ge 3 ]]; then
                echo -e "  ${YELLOW}[INFO]${NC} Servicio '$svc': $count eventos" | tee -a "$OUTPUT"
            fi
        done
    fi
fi
echo "" | tee -a "$OUTPUT"

# ── Patron 4: Movimiento lateral ──
echo -e "${BOLD}[P4] Movimiento lateral (SSH desde hosts internos)${NC}" | tee -a "$OUTPUT"

if [[ -n "$AUTH_LOG" ]]; then
    INTERNAL_SSH=$(grep "Accepted" "$AUTH_LOG" 2>/dev/null | grep -oP 'from \K(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)[0-9.]+' | sort | uniq -c | sort -rn | head -10 || true)
    if [[ -n "$INTERNAL_SSH" ]]; then
        while IFS= read -r line; do
            count=$(echo "$line" | awk '{print $1}')
            ip=$(echo "$line" | awk '{print $2}')
            echo -e "  ${CYAN}[INFO]${NC} SSH desde host interno $ip: $count conexiones" | tee -a "$OUTPUT"
        done <<< "$INTERNAL_SSH"
    else
        echo "  (sin conexiones SSH desde hosts internos)" | tee -a "$OUTPUT"
    fi
fi
echo "" | tee -a "$OUTPUT"

# ── Patron 5: Preparacion de exfiltracion ──
echo -e "${BOLD}[P5] Preparacion de datos (archivos grandes + conexion red)${NC}" | tee -a "$OUTPUT"

# Archivos grandes creados recientemente en /tmp, /dev/shm, /var/tmp
LARGE_FILES=$(find /tmp /dev/shm /var/tmp -type f -size +50M -mmin -60 2>/dev/null || true)
if [[ -n "$LARGE_FILES" ]]; then
    while IFS= read -r file; do
        size=$(stat -c '%s' "$file" 2>/dev/null || echo "?")
        owner=$(stat -c '%U' "$file" 2>/dev/null || echo "?")
        echo -e "  ${RED}[ALERTA]${NC} Archivo grande: $file (${size}B, owner=$owner)" | tee -a "$OUTPUT"
        ((ALERTAS++)) || true
    done <<< "$LARGE_FILES"
else
    echo "  (sin archivos grandes sospechosos)" | tee -a "$OUTPUT"
fi
echo "" | tee -a "$OUTPUT"

# ── Patron 6: Anomalia de autenticacion ──
echo -e "${BOLD}[P6] Anomalia de autenticacion (login fuera de horario)${NC}" | tee -a "$OUTPUT"

HORA_ACTUAL=$(date +%H)
if [[ "$HORA_ACTUAL" -lt 7 ]] || [[ "$HORA_ACTUAL" -ge 22 ]]; then
    HORARIO="fuera_de_horario"
else
    HORARIO="horario_laboral"
fi

if [[ -n "$AUTH_LOG" ]] && [[ "$HORARIO" == "fuera_de_horario" ]]; then
    LOGINS_RECIENTES=$(grep "Accepted\|session opened" "$AUTH_LOG" 2>/dev/null | tail -20 || true)
    if [[ -n "$LOGINS_RECIENTES" ]]; then
        N_LOGINS=$(echo "$LOGINS_RECIENTES" | wc -l)
        echo -e "  ${YELLOW}[INFO]${NC} $N_LOGINS logins durante horario no laboral (${HORA_ACTUAL}:00)" | tee -a "$OUTPUT"
    fi
else
    echo "  (horario laboral actual: ${HORA_ACTUAL}:00 - sin anomalia)" | tee -a "$OUTPUT"
fi
echo "" | tee -a "$OUTPUT"

# ── Patron 7: Manipulacion de logs ──
echo -e "${BOLD}[P7] Manipulacion de logs (borrado/truncado)${NC}" | tee -a "$OUTPUT"

LOGS_MONITORED=(/var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages /var/log/audit/audit.log)
for logfile in "${LOGS_MONITORED[@]}"; do
    if [[ -f "$logfile" ]]; then
        size=$(stat -c '%s' "$logfile" 2>/dev/null || echo "0")
        if [[ "$size" -eq 0 ]]; then
            echo -e "  ${RED}[ALERTA]${NC} $logfile esta vacio (posible truncado)" | tee -a "$OUTPUT"
            ((ALERTAS++)) || true
        fi
    else
        # Verificar si deberia existir
        case "$logfile" in
            /var/log/auth.log) [[ -f /var/log/secure ]] || { echo -e "  ${YELLOW}[INFO]${NC} $logfile no existe"; } ;;
            /var/log/secure) [[ -f /var/log/auth.log ]] || { echo -e "  ${YELLOW}[INFO]${NC} $logfile no existe"; } ;;
        esac
    fi
done

# Detectar borrados en auditd
if [[ -f /var/log/audit/audit.log ]]; then
    LOG_DELETES=$(grep -c "type=DELETE\|unlink.*\/var\/log" /var/log/audit/audit.log 2>/dev/null || echo "0")
    if [[ "$LOG_DELETES" -gt 0 ]]; then
        echo -e "  ${RED}[ALERTA]${NC} $LOG_DELETES eventos de borrado de logs en audit" | tee -a "$OUTPUT"
        ((ALERTAS++)) || true
    fi
fi
echo "" | tee -a "$OUTPUT"

# ── Patron 8: Instalacion de persistencia ──
echo -e "${BOLD}[P8] Instalacion de persistencia (crontab/systemd tras SSH)${NC}" | tee -a "$OUTPUT"

if [[ -n "$SYSLOG" ]]; then
    # Cambios en crontab
    CRON_CHANGES=$(grep -i "crontab\|CRON.*EDIT\|cron.*REPLACE" "$SYSLOG" 2>/dev/null | tail -20 || true)
    if [[ -n "$CRON_CHANGES" ]]; then
        N_CRON=$(echo "$CRON_CHANGES" | wc -l)
        echo -e "  ${YELLOW}[INFO]${NC} $N_CRON cambios de crontab detectados" | tee -a "$OUTPUT"
    fi

    # Nuevos servicios systemd
    SYSTEMD_NEW=$(grep -i "Created symlink\|Reloaded\|new unit" "$SYSLOG" 2>/dev/null | tail -20 || true)
    if [[ -n "$SYSTEMD_NEW" ]]; then
        N_SYSTEMD=$(echo "$SYSTEMD_NEW" | wc -l)
        echo -e "  ${YELLOW}[INFO]${NC} $N_SYSTEMD eventos de cambio en systemd" | tee -a "$OUTPUT"
    fi
fi
echo "" | tee -a "$OUTPUT"

# --- Resumen ---
echo "============================================" | tee -a "$OUTPUT"
if [[ $ALERTAS -gt 0 ]]; then
    echo -e "${RED}[!] TOTAL: $ALERTAS alertas de correlacion${NC}" | tee -a "$OUTPUT"
else
    echo -e "${GREEN}[+] Sin alertas de correlacion detectadas${NC}" | tee -a "$OUTPUT"
fi
echo "Resultados guardados en: $OUTPUT" | tee -a "$OUTPUT"
EOFCORR

    chmod 755 /usr/local/bin/correlacionar-eventos.sh
    log_change "Creado" "/usr/local/bin/correlacionar-eventos.sh"

    # --- Timer systemd para correlacion cada 15 min ---
    cat > /etc/systemd/system/securizar-correlacion.service << 'EOFSVC'
[Unit]
Description=Securizar - Correlacion de eventos de seguridad
After=rsyslog.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/correlacionar-eventos.sh --rango 1
StandardOutput=journal
StandardError=journal
Nice=10
IOSchedulingClass=idle
EOFSVC

    cat > /etc/systemd/system/securizar-correlacion.timer << 'EOFTIMER'
[Unit]
Description=Securizar - Correlacion periodica de eventos (cada 15min)

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
RandomizedDelaySec=60
Persistent=true

[Install]
WantedBy=timers.target
EOFTIMER

    systemctl daemon-reload
    systemctl enable securizar-correlacion.timer 2>/dev/null || true
    systemctl start securizar-correlacion.timer 2>/dev/null || true
    log_change "Creado" "/etc/systemd/system/securizar-correlacion.timer (cada 15min)"

    log_info "Herramienta de correlacion instalada"
    log_info "Ejecuta manualmente: correlacionar-eventos.sh"

else
    log_skip "Correlacion basica de eventos"
fi

# ============================================================
# S6: ALERTAS EN TIEMPO REAL
# ============================================================
log_section "S6: ALERTAS EN TIEMPO REAL"

echo "Configura sistema de alertas en tiempo real via rsyslog:"
echo "  - Accion omprog para eventos criticos"
echo "  - Clasificacion: CRITICAL, HIGH, MEDIUM, LOW"
echo "  - Rate limiting: max 10 alertas/minuto por categoria"
echo "  - Soporte email y webhook opcionales"
echo ""

if ask "¿Configurar alertas en tiempo real?"; then

    # --- Script de alertas ---
    cat > /usr/local/bin/securizar-log-alertas.sh << 'EOFALERTAS'
#!/bin/bash
# ============================================================
# SISTEMA DE ALERTAS EN TIEMPO REAL
# Recibe lineas de rsyslog via omprog y clasifica eventos
# ============================================================

ALERT_LOG="/var/log/securizar/alertas.log"
mkdir -p "$(dirname "$ALERT_LOG")"

# Rate limiting: archivos de control
RATE_DIR="/var/run/securizar-alertas"
mkdir -p "$RATE_DIR"
MAX_PER_MIN=10

# Funcion: verificar rate limit por categoria
check_rate() {
    local categoria="$1"
    local rate_file="$RATE_DIR/${categoria}.count"
    local rate_ts="$RATE_DIR/${categoria}.ts"
    local now
    now=$(date +%s)

    if [[ -f "$rate_ts" ]]; then
        local last_reset
        last_reset=$(cat "$rate_ts" 2>/dev/null || echo "0")
        local elapsed=$(( now - last_reset ))
        if [[ $elapsed -ge 60 ]]; then
            echo "0" > "$rate_file"
            echo "$now" > "$rate_ts"
        fi
    else
        echo "0" > "$rate_file"
        echo "$now" > "$rate_ts"
    fi

    local count
    count=$(cat "$rate_file" 2>/dev/null || echo "0")
    if [[ "$count" -ge "$MAX_PER_MIN" ]]; then
        return 1
    fi
    echo "$(( count + 1 ))" > "$rate_file"
    return 0
}

# Funcion: clasificar y registrar alerta
registrar_alerta() {
    local nivel="$1"
    local mensaje="$2"
    local timestamp
    timestamp=$(date -Iseconds)

    if ! check_rate "$nivel"; then
        return 0
    fi

    echo "[$timestamp] [$nivel] $mensaje" >> "$ALERT_LOG"

    # Email opcional
    if [[ -n "${SECURIZAR_ALERT_EMAIL:-}" ]] && command -v mail &>/dev/null; then
        if [[ "$nivel" == "CRITICAL" ]] || [[ "$nivel" == "HIGH" ]]; then
            echo "$mensaje" | mail -s "Securizar ALERTA [$nivel] $(hostname)" "$SECURIZAR_ALERT_EMAIL" 2>/dev/null || true
        fi
    fi

    # Webhook opcional
    if [[ -n "${SECURIZAR_WEBHOOK_URL:-}" ]] && command -v curl &>/dev/null; then
        if [[ "$nivel" == "CRITICAL" ]] || [[ "$nivel" == "HIGH" ]]; then
            curl -s -X POST "$SECURIZAR_WEBHOOK_URL" \
                -H "Content-Type: application/json" \
                -d "{\"level\":\"$nivel\",\"host\":\"$(hostname)\",\"message\":\"$mensaje\",\"timestamp\":\"$timestamp\"}" \
                --max-time 5 2>/dev/null || true
        fi
    fi
}

# Bucle principal: lee lineas de stdin (rsyslog omprog)
while IFS= read -r line; do
    # --- CRITICAL ---
    if echo "$line" | grep -qiE "kernel panic|out of memory|oom.*kill|segfault.*kernel"; then
        registrar_alerta "CRITICAL" "$line"
        continue
    fi

    # --- HIGH ---
    if echo "$line" | grep -qiE "failed.*root.*password|BREAK-IN ATTEMPT|authentication failure.*root|sudo.*COMMAND.*rm -rf|sudo.*COMMAND.*chmod 777|possible SYN flooding"; then
        registrar_alerta "HIGH" "$line"
        continue
    fi

    # --- MEDIUM ---
    if echo "$line" | grep -qiE "failed password|invalid user|connection closed.*preauth|refused connect|error.*permission denied|firewall.*DROP|firewall.*REJECT"; then
        registrar_alerta "MEDIUM" "$line"
        continue
    fi

    # --- LOW ---
    if echo "$line" | grep -qiE "session opened|session closed|accepted.*key|new seat|user not known"; then
        registrar_alerta "LOW" "$line"
        continue
    fi
done
EOFALERTAS

    chmod 755 /usr/local/bin/securizar-log-alertas.sh
    log_change "Creado" "/usr/local/bin/securizar-log-alertas.sh"

    # --- Configuracion rsyslog omprog ---
    ALERTAS_CONF="/etc/rsyslog.d/30-securizar-alertas.conf"
    if [[ -f "$ALERTAS_CONF" ]]; then
        cp "$ALERTAS_CONF" "$BACKUP_DIR/"
        log_change "Backup" "$ALERTAS_CONF"
    fi

    cat > "$ALERTAS_CONF" << 'EOFALERTCONF'
# ============================================================
# Alertas en tiempo real via omprog
# Generado por logging-centralizado.sh - Modulo 43
# ============================================================

# --- Modulo de programa externo ---
module(load="omprog")

# --- Filtro: eventos criticos al script de alertas ---
# Auth failures
if $syslogfacility-text == 'auth' or $syslogfacility-text == 'authpriv' then {
    if $msg contains 'failed' or $msg contains 'FAILED' or $msg contains 'error' or $msg contains 'BREAK-IN' then {
        action(type="omprog"
            binary="/usr/local/bin/securizar-log-alertas.sh"
            template="RSYSLOG_TraditionalFileFormat"
            name="securizar-alertas-auth"
            confirmMessages="off"
            reportFailures="on"
            closeTimeout="5000"
        )
    }
}

# Kernel criticos
if $syslogfacility-text == 'kern' then {
    if $syslogseverity <= 3 then {
        action(type="omprog"
            binary="/usr/local/bin/securizar-log-alertas.sh"
            template="RSYSLOG_TraditionalFileFormat"
            name="securizar-alertas-kern"
            confirmMessages="off"
            reportFailures="on"
            closeTimeout="5000"
        )
    }
}

# Sudo abuso
if $programname == 'sudo' then {
    action(type="omprog"
        binary="/usr/local/bin/securizar-log-alertas.sh"
        template="RSYSLOG_TraditionalFileFormat"
        name="securizar-alertas-sudo"
        confirmMessages="off"
        reportFailures="on"
        closeTimeout="5000"
    )
}

# Firewall drops/rejects
if $msg contains 'DROP' or $msg contains 'REJECT' or $msg contains 'BLOCK' then {
    if $msg contains 'iptables' or $msg contains 'nftables' or $msg contains 'UFW' or $msg contains 'firewalld' then {
        action(type="omprog"
            binary="/usr/local/bin/securizar-log-alertas.sh"
            template="RSYSLOG_TraditionalFileFormat"
            name="securizar-alertas-firewall"
            confirmMessages="off"
            reportFailures="on"
            closeTimeout="5000"
        )
    }
}
EOFALERTCONF

    chmod 644 "$ALERTAS_CONF"
    log_change "Creado" "$ALERTAS_CONF (alertas omprog)"

    # Validar y recargar rsyslog
    if rsyslogd -N1 &>/dev/null; then
        systemctl restart rsyslog 2>/dev/null || true
        log_info "rsyslog reiniciado con alertas activas"
    else
        log_warn "Error de sintaxis en rsyslog. Revisa: rsyslogd -N1"
    fi

    log_info "Sistema de alertas en tiempo real configurado"
    log_info "Alertas en: /var/log/securizar/alertas.log"
    log_info "Configura SECURIZAR_ALERT_EMAIL o SECURIZAR_WEBHOOK_URL para notificaciones"

else
    log_skip "Alertas en tiempo real"
fi

# ============================================================
# S7: RETENCION Y ROTACION AVANZADA
# ============================================================
log_section "S7: RETENCION Y ROTACION AVANZADA"

echo "Configura politicas de retencion diferenciadas por tipo de log:"
echo "  - Criticos (auth, sudo, audit): 365 dias"
echo "  - Seguridad (firewall, IDS): 180 dias"
echo "  - Sistema: 90 dias"
echo "  - Aplicacion: 30 dias"
echo "  - Compresion zstd/gzip, postrotate rsyslog"
echo ""

if ask "¿Configurar retencion y rotacion avanzada?"; then

    # Detectar compresor disponible
    if command -v zstd &>/dev/null; then
        COMPRESSCMD="zstd"
        UNCOMPRESSCMD="unzstd"
        COMPRESSEXT=".zst"
    else
        COMPRESSCMD="gzip"
        UNCOMPRESSCMD="gunzip"
        COMPRESSEXT=".gz"
    fi
    log_info "Compresor seleccionado: $COMPRESSCMD"

    # --- Retencion critica: 365 dias ---
    cat > /etc/logrotate.d/securizar-retencion << EOFRETENCION
# ============================================================
# Retencion avanzada - Generado por logging-centralizado.sh
# Modulo 43 - Securizar Suite
# ============================================================

# --- CRITICOS: 365 dias (auth, sudo, audit) ---
/var/log/auth.log /var/log/secure /var/log/sudo.log /var/log/securizar/auth/*.log /var/log/securizar/sudo/*.log {
    daily
    missingok
    rotate 365
    compress
    compresscmd $COMPRESSCMD
    uncompresscmd $UNCOMPRESSCMD
    compressext $COMPRESSEXT
    delaycompress
    notifempty
    create 0640 root adm
    dateext
    dateformat -%Y%m%d
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate 2>/dev/null || systemctl kill -s HUP rsyslog 2>/dev/null || true
    endscript
}

# --- SEGURIDAD: 180 dias (firewall, IDS) ---
/var/log/securizar/firewall/*.log /var/log/suricata/*.log /var/log/fail2ban.log {
    daily
    missingok
    rotate 180
    compress
    compresscmd $COMPRESSCMD
    uncompresscmd $UNCOMPRESSCMD
    compressext $COMPRESSEXT
    delaycompress
    notifempty
    create 0640 root adm
    dateext
    dateformat -%Y%m%d
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate 2>/dev/null || systemctl kill -s HUP rsyslog 2>/dev/null || true
    endscript
}

# --- SISTEMA: 90 dias ---
/var/log/securizar/cron/*.log /var/log/syslog /var/log/messages /var/log/kern.log /var/log/daemon.log {
    daily
    missingok
    rotate 90
    compress
    compresscmd $COMPRESSCMD
    uncompresscmd $UNCOMPRESSCMD
    compressext $COMPRESSEXT
    delaycompress
    notifempty
    create 0640 root adm
    dateext
    dateformat -%Y%m%d
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate 2>/dev/null || systemctl kill -s HUP rsyslog 2>/dev/null || true
    endscript
}

# --- APLICACION: 30 dias ---
/var/log/securizar/ssh/*.log /var/log/securizar/correlacion.log /var/log/securizar/alertas.log {
    daily
    missingok
    rotate 30
    compress
    compresscmd $COMPRESSCMD
    uncompresscmd $UNCOMPRESSCMD
    compressext $COMPRESSEXT
    delaycompress
    notifempty
    create 0640 root adm
    dateext
    dateformat -%Y%m%d
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate 2>/dev/null || systemctl kill -s HUP rsyslog 2>/dev/null || true
    endscript
}
EOFRETENCION

    chmod 644 /etc/logrotate.d/securizar-retencion
    log_change "Creado" "/etc/logrotate.d/securizar-retencion"

    # --- Script de gestion de retencion ---
    cat > /usr/local/bin/gestionar-retencion-logs.sh << 'EOFGESTION'
#!/bin/bash
# ============================================================
# GESTION DE RETENCION DE LOGS
# Muestra uso, alerta sobre limites, limpia logs antiguos
# Uso: gestionar-retencion-logs.sh [resumen|limpiar|espacio]
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

MODO="${1:-resumen}"

# Umbrales de alerta (en MB)
UMBRAL_WARN=500
UMBRAL_CRIT=1000

uso_directorio() {
    local dir="$1"
    local nombre="$2"
    if [[ -d "$dir" ]]; then
        local size_kb
        size_kb=$(du -sk "$dir" 2>/dev/null | awk '{print $1}')
        local size_mb=$(( size_kb / 1024 ))
        local files
        files=$(find "$dir" -type f 2>/dev/null | wc -l)

        local color="$GREEN"
        local estado="OK"
        if [[ $size_mb -ge $UMBRAL_CRIT ]]; then
            color="$RED"
            estado="CRITICO"
        elif [[ $size_mb -ge $UMBRAL_WARN ]]; then
            color="$YELLOW"
            estado="ALERTA"
        fi

        printf "  %-30s %6s MB  %5s archivos  ${color}[%s]${NC}\n" "$nombre" "$size_mb" "$files" "$estado"
    fi
}

case "$MODO" in
    resumen)
        echo ""
        echo -e "${BOLD}=== RESUMEN DE USO DE LOGS ===${NC}"
        echo -e "${DIM}Fecha: $(date -Iseconds)${NC}"
        echo ""

        echo -e "${BOLD}Logs del sistema:${NC}"
        uso_directorio "/var/log" "Total /var/log"
        echo ""

        echo -e "${BOLD}Logs de Securizar:${NC}"
        uso_directorio "/var/log/securizar" "Total securizar"
        uso_directorio "/var/log/securizar/auth" "  Auth"
        uso_directorio "/var/log/securizar/ssh" "  SSH"
        uso_directorio "/var/log/securizar/sudo" "  Sudo"
        uso_directorio "/var/log/securizar/firewall" "  Firewall"
        uso_directorio "/var/log/securizar/cron" "  Cron"
        echo ""

        echo -e "${BOLD}Almacenamiento:${NC}"
        df -h /var/log 2>/dev/null | tail -1 | awk '{printf "  Disco: %s usado de %s (%s libre)\n", $3, $2, $4}'
        echo ""
        ;;

    limpiar)
        echo -e "${BOLD}=== LIMPIEZA DE LOGS ANTIGUOS ===${NC}"
        echo ""

        # Limpiar segun politica de retencion
        echo "Eliminando logs de aplicacion > 30 dias..."
        find /var/log/securizar/ssh -name "*.log*" -mtime +30 -delete 2>/dev/null || true

        echo "Eliminando logs de sistema > 90 dias..."
        find /var/log/securizar/cron -name "*.log*" -mtime +90 -delete 2>/dev/null || true

        echo "Eliminando logs de seguridad > 180 dias..."
        find /var/log/securizar/firewall -name "*.log*" -mtime +180 -delete 2>/dev/null || true

        echo "Eliminando logs criticos > 365 dias..."
        find /var/log/securizar/auth /var/log/securizar/sudo -name "*.log*" -mtime +365 -delete 2>/dev/null || true

        # Limpiar directorios vacios
        find /var/log/securizar -type d -empty -delete 2>/dev/null || true

        echo "[+] Limpieza completada"
        ;;

    espacio)
        echo -e "${BOLD}=== ESPACIO EN DISCO PARA LOGS ===${NC}"
        echo ""
        df -h /var/log 2>/dev/null
        echo ""
        echo -e "${BOLD}Top 10 archivos de log mas grandes:${NC}"
        find /var/log -type f -printf '%s %p\n' 2>/dev/null | sort -rn | head -10 | while IFS= read -r line; do
            size=$(echo "$line" | awk '{print $1}')
            file=$(echo "$line" | awk '{$1=""; print $0}' | sed 's/^ //')
            size_mb=$(( size / 1048576 ))
            printf "  %6s MB  %s\n" "$size_mb" "$file"
        done
        echo ""
        ;;

    *)
        echo "Uso: $0 [resumen|limpiar|espacio]"
        exit 1
        ;;
esac
EOFGESTION

    chmod 755 /usr/local/bin/gestionar-retencion-logs.sh
    log_change "Creado" "/usr/local/bin/gestionar-retencion-logs.sh"

    log_info "Retencion avanzada configurada"
    log_info "Gestionar con: gestionar-retencion-logs.sh [resumen|limpiar|espacio]"

else
    log_skip "Retencion y rotacion avanzada"
fi

# ============================================================
# S8: INTEGRACION SIEM (ELK/Splunk/Graylog)
# ============================================================
log_section "S8: INTEGRACION SIEM (ELK/SPLUNK/GRAYLOG)"

echo "Crea templates de integracion para plataformas SIEM:"
echo "  - Elasticsearch (omelasticsearch)"
echo "  - Splunk (omhttp HEC)"
echo "  - Graylog (omgelf)"
echo "  - Script de activacion con test de conectividad"
echo ""

if ask "¿Instalar templates de integracion SIEM?"; then

    mkdir -p /etc/securizar/siem

    # --- Template Elasticsearch ---
    cat > /etc/securizar/siem/elasticsearch-template.conf << 'EOFES'
# ============================================================
# Integracion rsyslog -> Elasticsearch
# Generado por logging-centralizado.sh - Modulo 43
# ============================================================
# Requisito: rsyslog-module-omelasticsearch (segun distro)
# Instalar: pkg_install rsyslog-elasticsearch
# ============================================================

# Cargar modulo
module(load="omelasticsearch")

# Template de indice
template(name="securizar-es-index" type="string"
    string="securizar-logs-%$year%.%$month%.%$day%"
)

# Template de documento JSON
template(name="securizar-es-doc" type="list") {
    constant(value="{")
    constant(value="\"@timestamp\":\"")     property(name="timereported" dateFormat="rfc3339")
    constant(value="\",\"host\":\"")        property(name="hostname")
    constant(value="\",\"severity\":\"")    property(name="syslogseverity-text")
    constant(value="\",\"facility\":\"")    property(name="syslogfacility-text")
    constant(value="\",\"program\":\"")     property(name="programname")
    constant(value="\",\"pid\":\"")         property(name="procid")
    constant(value="\",\"source_ip\":\"")   property(name="fromhost-ip")
    constant(value="\",\"message\":\"")     property(name="msg" format="json")
    constant(value="\"}")
}

# Accion: enviar a Elasticsearch
# CONFIGURA: server, serverport, uid, pwd
action(type="omelasticsearch"
    server="ELASTICSEARCH_HOST"
    serverport="9200"
    searchIndex="securizar-es-index"
    dynSearchIndex="on"
    template="securizar-es-doc"
    searchType="_doc"
    bulkmode="on"
    maxbytes="100m"
    queue.type="LinkedList"
    queue.filename="securizar-es-queue"
    queue.maxDiskSpace="1g"
    queue.saveOnShutdown="on"
    queue.size="5000"
    action.resumeRetryCount="-1"
    action.resumeInterval="30"
    # TLS (descomentar si es necesario):
    # usehttps="on"
    # tls.cacert="/etc/securizar/log-certs/ca.pem"
    # uid="elastic"
    # pwd="changeme"
)
EOFES

    chmod 644 /etc/securizar/siem/elasticsearch-template.conf
    log_change "Creado" "/etc/securizar/siem/elasticsearch-template.conf"

    # --- Template Splunk HEC ---
    cat > /etc/securizar/siem/splunk-template.conf << 'EOFSPLUNK'
# ============================================================
# Integracion rsyslog -> Splunk (HTTP Event Collector)
# Generado por logging-centralizado.sh - Modulo 43
# ============================================================
# Requisito: rsyslog con soporte omhttp
# ============================================================

# Cargar modulo HTTP
module(load="omhttp")

# Template HEC de Splunk
template(name="securizar-splunk-hec" type="list") {
    constant(value="{\"event\":{")
    constant(value="\"timestamp\":\"")      property(name="timereported" dateFormat="rfc3339")
    constant(value="\",\"host\":\"")        property(name="hostname")
    constant(value="\",\"severity\":\"")    property(name="syslogseverity-text")
    constant(value="\",\"facility\":\"")    property(name="syslogfacility-text")
    constant(value="\",\"program\":\"")     property(name="programname")
    constant(value="\",\"pid\":\"")         property(name="procid")
    constant(value="\",\"source_ip\":\"")   property(name="fromhost-ip")
    constant(value="\",\"message\":\"")     property(name="msg" format="json")
    constant(value="\"},\"sourcetype\":\"securizar:syslog\",\"index\":\"securizar\"}")
}

# Accion: enviar a Splunk HEC
# CONFIGURA: server, httpheaderkey (token HEC)
action(type="omhttp"
    server="SPLUNK_HOST"
    serverport="8088"
    restpath="services/collector/event"
    template="securizar-splunk-hec"
    httpheaderkey="Authorization"
    httpheadervalue="Splunk SPLUNK_HEC_TOKEN"
    batch="on"
    batch.maxsize="100"
    batch.format="newline"
    useHttps="on"
    # tls.cacert="/etc/securizar/log-certs/ca.pem"
    queue.type="LinkedList"
    queue.filename="securizar-splunk-queue"
    queue.maxDiskSpace="1g"
    queue.saveOnShutdown="on"
    queue.size="5000"
    action.resumeRetryCount="-1"
    action.resumeInterval="30"
)
EOFSPLUNK

    chmod 644 /etc/securizar/siem/splunk-template.conf
    log_change "Creado" "/etc/securizar/siem/splunk-template.conf"

    # --- Template Graylog GELF ---
    cat > /etc/securizar/siem/graylog-template.conf << 'EOFGRAYLOG'
# ============================================================
# Integracion rsyslog -> Graylog (GELF)
# Generado por logging-centralizado.sh - Modulo 43
# ============================================================
# Requisito: rsyslog con soporte omgelf o GELF via TCP/UDP
# ============================================================

# Template GELF (Graylog Extended Log Format)
template(name="securizar-gelf" type="list") {
    constant(value="{\"version\":\"1.1\"")
    constant(value=",\"host\":\"")          property(name="hostname")
    constant(value="\",\"short_message\":\"") property(name="msg" format="json")
    constant(value="\",\"timestamp\":")     property(name="timegenerated" dateFormat="unixtimestamp")
    constant(value=",\"level\":")           property(name="syslogseverity")
    constant(value=",\"_facility\":\"")     property(name="syslogfacility-text")
    constant(value="\",\"_program\":\"")    property(name="programname")
    constant(value="\",\"_pid\":\"")        property(name="procid")
    constant(value="\",\"_source_ip\":\"")  property(name="fromhost-ip")
    constant(value="\"}")
}

# Accion: enviar a Graylog via TCP GELF
# CONFIGURA: Target (IP de Graylog), Port
action(type="omfwd"
    Target="GRAYLOG_HOST"
    Port="12201"
    Protocol="tcp"
    template="securizar-gelf"
    TCP_Framing="octet-counted"
    queue.type="LinkedList"
    queue.filename="securizar-graylog-queue"
    queue.maxDiskSpace="1g"
    queue.saveOnShutdown="on"
    queue.size="5000"
    action.resumeRetryCount="-1"
    action.resumeInterval="30"
    # StreamDriver="gtls"
    # StreamDriverMode="1"
    # StreamDriverAuthMode="x509/name"
)
EOFGRAYLOG

    chmod 644 /etc/securizar/siem/graylog-template.conf
    log_change "Creado" "/etc/securizar/siem/graylog-template.conf"

    # --- Script de activacion SIEM ---
    cat > /usr/local/bin/activar-siem.sh << 'EOFSIEM'
#!/bin/bash
# ============================================================
# ACTIVAR INTEGRACION SIEM
# Configura rsyslog para enviar logs a la plataforma elegida
# Uso: activar-siem.sh
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SIEM_DIR="/etc/securizar/siem"
RSYSLOG_SIEM="/etc/rsyslog.d/50-securizar-siem.conf"

echo ""
echo -e "${BOLD}=== ACTIVAR INTEGRACION SIEM ===${NC}"
echo ""
echo "Selecciona la plataforma SIEM:"
echo "  1) Elasticsearch / ELK Stack"
echo "  2) Splunk (HTTP Event Collector)"
echo "  3) Graylog (GELF)"
echo "  4) Desactivar integracion SIEM"
echo ""
read -p "Opcion [1-4]: " opcion

case "$opcion" in
    1)
        TEMPLATE="$SIEM_DIR/elasticsearch-template.conf"
        SIEM_NAME="Elasticsearch"
        read -p "IP/hostname de Elasticsearch: " SIEM_HOST
        read -p "Puerto [9200]: " SIEM_PORT
        SIEM_PORT="${SIEM_PORT:-9200}"

        if [[ -z "$SIEM_HOST" ]]; then
            echo "[X] Debes especificar un host"
            exit 1
        fi

        cp "$TEMPLATE" "$RSYSLOG_SIEM"
        sed -i "s/ELASTICSEARCH_HOST/$SIEM_HOST/g" "$RSYSLOG_SIEM"
        sed -i "s/9200/$SIEM_PORT/g" "$RSYSLOG_SIEM"
        ;;
    2)
        TEMPLATE="$SIEM_DIR/splunk-template.conf"
        SIEM_NAME="Splunk"
        read -p "IP/hostname de Splunk: " SIEM_HOST
        read -p "Puerto HEC [8088]: " SIEM_PORT
        SIEM_PORT="${SIEM_PORT:-8088}"
        read -p "Token HEC: " SIEM_TOKEN

        if [[ -z "$SIEM_HOST" ]] || [[ -z "$SIEM_TOKEN" ]]; then
            echo "[X] Debes especificar host y token HEC"
            exit 1
        fi

        cp "$TEMPLATE" "$RSYSLOG_SIEM"
        sed -i "s/SPLUNK_HOST/$SIEM_HOST/g" "$RSYSLOG_SIEM"
        sed -i "s/8088/$SIEM_PORT/g" "$RSYSLOG_SIEM"
        sed -i "s/SPLUNK_HEC_TOKEN/$SIEM_TOKEN/g" "$RSYSLOG_SIEM"
        ;;
    3)
        TEMPLATE="$SIEM_DIR/graylog-template.conf"
        SIEM_NAME="Graylog"
        read -p "IP/hostname de Graylog: " SIEM_HOST
        read -p "Puerto GELF [12201]: " SIEM_PORT
        SIEM_PORT="${SIEM_PORT:-12201}"

        if [[ -z "$SIEM_HOST" ]]; then
            echo "[X] Debes especificar un host"
            exit 1
        fi

        cp "$TEMPLATE" "$RSYSLOG_SIEM"
        sed -i "s/GRAYLOG_HOST/$SIEM_HOST/g" "$RSYSLOG_SIEM"
        sed -i "s/12201/$SIEM_PORT/g" "$RSYSLOG_SIEM"
        ;;
    4)
        if [[ -f "$RSYSLOG_SIEM" ]]; then
            rm -f "$RSYSLOG_SIEM"
            systemctl restart rsyslog 2>/dev/null || true
            echo "[+] Integracion SIEM desactivada"
        else
            echo "[+] No hay integracion SIEM activa"
        fi
        exit 0
        ;;
    *)
        echo "[X] Opcion no valida"
        exit 1
        ;;
esac

# Validar configuracion rsyslog
echo ""
echo "Validando configuracion rsyslog..."
if rsyslogd -N1 &>/dev/null; then
    echo -e "${GREEN}[+]${NC} Sintaxis de rsyslog correcta"
else
    echo -e "${RED}[X]${NC} Error de sintaxis en rsyslog"
    echo "Revisa: rsyslogd -N1"
    echo "Eliminando configuracion problematica..."
    rm -f "$RSYSLOG_SIEM"
    exit 1
fi

# Test de conectividad
echo "Probando conectividad con $SIEM_NAME ($SIEM_HOST:$SIEM_PORT)..."
if timeout 5 bash -c "echo >/dev/tcp/$SIEM_HOST/$SIEM_PORT" 2>/dev/null; then
    echo -e "${GREEN}[+]${NC} Conexion exitosa a $SIEM_HOST:$SIEM_PORT"
else
    echo -e "${YELLOW}[!]${NC} No se pudo conectar a $SIEM_HOST:$SIEM_PORT"
    echo "    Verifica que $SIEM_NAME esta corriendo y el puerto esta abierto"
    echo "    La configuracion se activara igualmente (rsyslog reintentara)"
fi

# Reiniciar rsyslog
systemctl restart rsyslog 2>/dev/null || true
echo ""
echo -e "${GREEN}[+]${NC} Integracion $SIEM_NAME activada"
echo "    Configuracion: $RSYSLOG_SIEM"
echo "    Monitorear: tail -f /var/log/securizar/alertas.log"
EOFSIEM

    chmod 755 /usr/local/bin/activar-siem.sh
    log_change "Creado" "/usr/local/bin/activar-siem.sh"

    log_info "Templates SIEM instalados en /etc/securizar/siem/"
    log_info "Activa con: activar-siem.sh"

else
    log_skip "Integracion SIEM"
fi

# ============================================================
# S9: FORENSE DE LOGS
# ============================================================
log_section "S9: FORENSE DE LOGS"

echo "Herramienta forense completa para analisis de logs:"
echo "  - Reconstruccion de timeline multi-fuente"
echo "  - Rastreo de actividad de usuarios"
echo "  - Forense de autenticacion y procesos"
echo "  - Forense de conexiones de red"
echo "  - Salida JSON + formato legible"
echo "  - Filtrado por rango de fechas"
echo "  - Metadatos de cadena de custodia"
echo ""

if ask "¿Instalar herramienta de forense de logs?"; then

    cat > /usr/local/bin/forense-logs.sh << 'EOFFORENSE'
#!/bin/bash
# ============================================================
# FORENSE DE LOGS - Analisis integral
# Uso: forense-logs.sh [--desde FECHA] [--hasta FECHA] [--usuario USER]
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# --- Parseo de argumentos ---
DESDE=""
HASTA=""
USUARIO=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --desde) DESDE="$2"; shift 2 ;;
        --hasta) HASTA="$2"; shift 2 ;;
        --usuario) USUARIO="$2"; shift 2 ;;
        *) echo "Uso: $0 [--desde YYYY-MM-DD] [--hasta YYYY-MM-DD] [--usuario USER]"; exit 1 ;;
    esac
done

DESDE="${DESDE:-$(date -d '24 hours ago' '+%Y-%m-%d' 2>/dev/null || date '+%Y-%m-%d')}"
HASTA="${HASTA:-$(date '+%Y-%m-%d')}"

FORENSE_DIR="/var/lib/securizar/forense"
CASE_ID="FORENSE-$(date +%Y%m%d-%H%M%S)"
CASE_DIR="$FORENSE_DIR/$CASE_ID"
mkdir -p "$CASE_DIR"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║   FORENSE DE LOGS - $CASE_ID   ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════╝${NC}"
echo ""
echo "Rango: $DESDE - $HASTA"
[[ -n "$USUARIO" ]] && echo "Usuario filtro: $USUARIO"
echo ""

# --- Cadena de custodia ---
CUSTODIA="$CASE_DIR/cadena-custodia.json"
cat > "$CUSTODIA" << EOFCUST
{
    "case_id": "$CASE_ID",
    "collector": "$(whoami)",
    "hostname": "$(hostname)",
    "kernel": "$(uname -r)",
    "start_time": "$(date -Iseconds)",
    "date_range": {"from": "$DESDE", "to": "$HASTA"},
    "user_filter": "${USUARIO:-null}",
    "tools": ["journalctl", "grep", "awk", "last", "lastlog"]
}
EOFCUST

# Determinar log de auth
AUTH_LOG=""
for f in /var/log/auth.log /var/log/secure; do
    [[ -f "$f" ]] && AUTH_LOG="$f" && break
done

SYSLOG=""
for f in /var/log/syslog /var/log/messages; do
    [[ -f "$f" ]] && SYSLOG="$f" && break
done

# ── 1. Timeline de autenticacion ──
echo -e "${BOLD}[1/6] Timeline de autenticacion...${NC}"
TIMELINE_AUTH="$CASE_DIR/01-timeline-auth.txt"

{
    echo "=== TIMELINE DE AUTENTICACION ==="
    echo "Rango: $DESDE - $HASTA"
    echo ""

    if [[ -n "$AUTH_LOG" ]]; then
        echo "--- Fuente: $AUTH_LOG ---"
        if [[ -n "$USUARIO" ]]; then
            grep -i "$USUARIO" "$AUTH_LOG" 2>/dev/null | tail -500
        else
            tail -1000 "$AUTH_LOG"
        fi
    fi

    echo ""
    echo "--- Fuente: journalctl ---"
    if [[ -n "$USUARIO" ]]; then
        journalctl --since="$DESDE" --until="$HASTA" -u ssh* -u sshd* 2>/dev/null | grep -i "$USUARIO" | tail -500 || true
    else
        journalctl --since="$DESDE" --until="$HASTA" -u ssh* -u sshd* 2>/dev/null | tail -500 || true
    fi

    echo ""
    echo "--- Logins recientes (last) ---"
    if [[ -n "$USUARIO" ]]; then
        last "$USUARIO" 2>/dev/null | head -50
    else
        last -50 2>/dev/null
    fi
} > "$TIMELINE_AUTH" 2>&1

echo "  Guardado en: $TIMELINE_AUTH"

# ── 2. Actividad de usuarios ──
echo -e "${BOLD}[2/6] Actividad de usuarios...${NC}"
USER_ACTIVITY="$CASE_DIR/02-actividad-usuarios.txt"

{
    echo "=== ACTIVIDAD DE USUARIOS ==="
    echo ""

    echo "--- Usuarios con login reciente ---"
    lastlog 2>/dev/null | grep -v "Never" | head -50

    echo ""
    echo "--- Comandos sudo ejecutados ---"
    if [[ -n "$AUTH_LOG" ]]; then
        if [[ -n "$USUARIO" ]]; then
            grep "sudo.*${USUARIO}" "$AUTH_LOG" 2>/dev/null | tail -200
        else
            grep "sudo.*COMMAND" "$AUTH_LOG" 2>/dev/null | tail -200
        fi
    fi

    echo ""
    echo "--- Cambios de usuario (su) ---"
    if [[ -n "$AUTH_LOG" ]]; then
        grep -i "su\[" "$AUTH_LOG" 2>/dev/null | tail -100
    fi
} > "$USER_ACTIVITY" 2>&1

echo "  Guardado en: $USER_ACTIVITY"

# ── 3. Procesos ejecutados (auditd) ──
echo -e "${BOLD}[3/6] Historial de procesos (auditd)...${NC}"
PROC_HISTORY="$CASE_DIR/03-procesos-ejecutados.txt"

{
    echo "=== HISTORIAL DE EJECUCION DE PROCESOS ==="
    echo ""

    if [[ -f /var/log/audit/audit.log ]]; then
        echo "--- Fuente: auditd ---"
        if command -v ausearch &>/dev/null; then
            if [[ -n "$USUARIO" ]]; then
                ausearch -ua "$USUARIO" --start "$DESDE" --end "$HASTA" 2>/dev/null | tail -500 || true
            else
                ausearch -m EXECVE --start "$DESDE" --end "$HASTA" 2>/dev/null | tail -500 || true
            fi
        else
            grep "EXECVE\|PROCTITLE" /var/log/audit/audit.log 2>/dev/null | tail -500
        fi
    else
        echo "(auditd no disponible)"
    fi

    echo ""
    echo "--- Procesos actuales sospechosos ---"
    ps auxwwf 2>/dev/null | head -100
} > "$PROC_HISTORY" 2>&1

echo "  Guardado en: $PROC_HISTORY"

# ── 4. Conexiones de red ──
echo -e "${BOLD}[4/6] Forense de conexiones de red...${NC}"
NET_FORENSE="$CASE_DIR/04-conexiones-red.txt"

{
    echo "=== FORENSE DE CONEXIONES DE RED ==="
    echo ""

    echo "--- Conexiones activas ---"
    ss -tunapeo 2>/dev/null || netstat -tunapeo 2>/dev/null || true

    echo ""
    echo "--- Logs de firewall ---"
    if [[ -d /var/log/securizar/firewall ]]; then
        echo "Fuente: /var/log/securizar/firewall/"
        cat /var/log/securizar/firewall/*.log 2>/dev/null | tail -200
    fi

    if [[ -n "$SYSLOG" ]]; then
        echo ""
        echo "--- Eventos de firewall en syslog ---"
        grep -i "iptables\|nftables\|UFW\|firewalld\|DROP\|REJECT" "$SYSLOG" 2>/dev/null | tail -200
    fi
} > "$NET_FORENSE" 2>&1

echo "  Guardado en: $NET_FORENSE"

# ── 5. Modificaciones de archivos ──
echo -e "${BOLD}[5/6] Rastreo de modificaciones de archivos...${NC}"
FILE_CHANGES="$CASE_DIR/05-modificaciones-archivos.txt"

{
    echo "=== MODIFICACIONES DE ARCHIVOS ==="
    echo ""

    echo "--- Archivos modificados en /etc (ultimas 24h) ---"
    find /etc -type f -mtime -1 -printf '%T+ %p\n' 2>/dev/null | sort -r | head -50

    echo ""
    echo "--- Archivos modificados en /usr/local/bin (ultimas 24h) ---"
    find /usr/local/bin -type f -mtime -1 -printf '%T+ %p\n' 2>/dev/null | sort -r | head -50

    echo ""
    echo "--- Binarios SUID modificados recientemente ---"
    find / -perm -4000 -type f -mtime -7 -printf '%T+ %p\n' 2>/dev/null | sort -r | head -20

    echo ""
    if [[ -f /var/log/audit/audit.log ]]; then
        echo "--- Modificaciones de archivos en audit ---"
        grep "type=PATH.*nametype=CREATE\|type=PATH.*nametype=DELETE" /var/log/audit/audit.log 2>/dev/null | tail -200
    fi
} > "$FILE_CHANGES" 2>&1

echo "  Guardado en: $FILE_CHANGES"

# ── 6. Timeline consolidado ──
echo -e "${BOLD}[6/6] Generando timeline consolidado...${NC}"
TIMELINE="$CASE_DIR/06-timeline-consolidado.json"

{
    echo "["
    FIRST=1

    # Auth events
    if [[ -n "$AUTH_LOG" ]]; then
        while IFS= read -r line; do
            ts=$(echo "$line" | awk '{print $1, $2, $3}')
            msg=$(echo "$line" | cut -d' ' -f6- | sed 's/"/\\"/g')
            if [[ $FIRST -eq 1 ]]; then
                FIRST=0
            else
                echo ","
            fi
            printf '  {"timestamp":"%s","source":"auth","message":"%s"}' "$ts" "$msg"
        done < <(tail -200 "$AUTH_LOG" 2>/dev/null)
    fi

    # Syslog events
    if [[ -n "$SYSLOG" ]]; then
        while IFS= read -r line; do
            ts=$(echo "$line" | awk '{print $1, $2, $3}')
            msg=$(echo "$line" | cut -d' ' -f6- | sed 's/"/\\"/g')
            if [[ $FIRST -eq 1 ]]; then
                FIRST=0
            else
                echo ","
            fi
            printf '  {"timestamp":"%s","source":"syslog","message":"%s"}' "$ts" "$msg"
        done < <(grep -i "error\|fail\|denied\|warning\|critical" "$SYSLOG" 2>/dev/null | tail -200)
    fi

    echo ""
    echo "]"
} > "$TIMELINE" 2>&1

echo "  Guardado en: $TIMELINE"

# --- Hash de evidencia ---
echo ""
echo -e "${BOLD}Generando hashes de evidencia...${NC}"
HASHES="$CASE_DIR/hashes-evidencia.sha256"
sha256sum "$CASE_DIR"/*.txt "$CASE_DIR"/*.json > "$HASHES" 2>/dev/null || true

# Actualizar cadena de custodia
END_TS=$(date -Iseconds)
EVIDENCE_HASH=$(sha256sum "$HASHES" 2>/dev/null | awk '{print $1}')

# Usar un enfoque seguro para actualizar JSON
{
    head -n -1 "$CUSTODIA"
    echo "    ,\"end_time\": \"$END_TS\","
    echo "    \"evidence_hash\": \"$EVIDENCE_HASH\","
    echo "    \"files_collected\": $(ls "$CASE_DIR" | wc -l)"
    echo "}"
} > "${CUSTODIA}.tmp" && mv "${CUSTODIA}.tmp" "$CUSTODIA"

echo ""
echo -e "${GREEN}[+]${NC} Forense completado: $CASE_DIR"
echo ""
echo "Archivos generados:"
ls -la "$CASE_DIR/"
echo ""
echo "Hash de evidencia: $EVIDENCE_HASH"
EOFFORENSE

    chmod 755 /usr/local/bin/forense-logs.sh
    log_change "Creado" "/usr/local/bin/forense-logs.sh"

    log_info "Herramienta forense instalada"
    log_info "Ejecuta: forense-logs.sh [--desde FECHA] [--hasta FECHA] [--usuario USER]"

else
    log_skip "Forense de logs"
fi

# ============================================================
# S10: AUDITORIA DE LOGGING
# ============================================================
log_section "S10: AUDITORIA DE LOGGING"

echo "Auditoria integral de la infraestructura de logging:"
echo "  - Estado de rsyslog, journald, TLS, permisos"
echo "  - Integridad, correlacion, alertas, retencion"
echo "  - Integracion SIEM y herramientas forenses"
echo "  - Puntuacion: COMPLETO / PARCIAL / INSUFICIENTE"
echo ""

if ask "¿Instalar auditoria de infraestructura de logging?"; then

    cat > /usr/local/bin/auditoria-logging.sh << 'EOFAUDIT'
#!/bin/bash
# ============================================================
# AUDITORIA DE INFRAESTRUCTURA DE LOGGING
# Verifica todos los controles de logging del Modulo 43
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[X] Ejecutar como root"
    exit 1
fi

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

TOTAL=0
PASADOS=0
FECHA=$(date -Iseconds)

RESULT_DIR="/var/lib/securizar"
mkdir -p "$RESULT_DIR"
JSON_OUT="$RESULT_DIR/auditoria-logging-latest.json"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║   AUDITORIA DE INFRAESTRUCTURA DE LOGGING        ║${NC}"
echo -e "${BOLD}║   $(date '+%Y-%m-%d %H:%M:%S')                             ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}"
echo ""

check() {
    local nombre="$1"
    local resultado="$2"
    ((TOTAL++)) || true
    if [[ "$resultado" == "OK" ]]; then
        ((PASADOS++)) || true
        echo -e "  ${GREEN}[OK]${NC} $nombre"
    else
        echo -e "  ${RED}[--]${NC} $nombre"
    fi
}

# --- 1. rsyslog activo ---
echo -e "${BOLD}[1/10] rsyslog${NC}"
if systemctl is-active rsyslog &>/dev/null; then
    check "rsyslog activo" "OK"
else
    check "rsyslog activo" "FAIL"
fi
if [[ -f /etc/rsyslog.d/01-securizar-hardening.conf ]]; then
    check "Hardening rsyslog configurado" "OK"
else
    check "Hardening rsyslog configurado" "FAIL"
fi

# --- 2. journald persistente ---
echo -e "${BOLD}[2/10] journald${NC}"
if [[ -f /etc/systemd/journald.conf.d/01-securizar.conf ]]; then
    check "journald hardening configurado" "OK"
else
    check "journald hardening configurado" "FAIL"
fi
if [[ -d /var/log/journal ]]; then
    check "journald almacenamiento persistente" "OK"
else
    check "journald almacenamiento persistente" "FAIL"
fi

# --- 3. TLS forwarding ---
echo -e "${BOLD}[3/10] Reenvio TLS${NC}"
if [[ -f /etc/rsyslog.d/10-securizar-tls-forwarding.conf ]]; then
    check "Configuracion TLS presente" "OK"
else
    check "Configuracion TLS presente" "FAIL"
fi
if [[ -f /etc/securizar/log-certs/ca.pem ]]; then
    check "Certificados TLS generados" "OK"
else
    check "Certificados TLS generados" "FAIL"
fi

# --- 4. Permisos de logs ---
echo -e "${BOLD}[4/10] Permisos de logs${NC}"
VARLOG_PERMS=$(stat -c '%a' /var/log 2>/dev/null || echo "?")
if [[ "$VARLOG_PERMS" == "750" ]]; then
    check "/var/log permisos 750" "OK"
else
    check "/var/log permisos 750 (actual: $VARLOG_PERMS)" "FAIL"
fi

# --- 5. Integridad de logs ---
echo -e "${BOLD}[5/10] Integridad${NC}"
if [[ -x /usr/local/bin/securizar-log-integrity.sh ]]; then
    check "Script de integridad instalado" "OK"
else
    check "Script de integridad instalado" "FAIL"
fi
if [[ -f /etc/cron.daily/securizar-log-hashes ]]; then
    check "Cron diario de hashes activo" "OK"
else
    check "Cron diario de hashes activo" "FAIL"
fi

# --- 6. Normalizacion ---
echo -e "${BOLD}[6/10] Normalizacion${NC}"
if [[ -f /etc/rsyslog.d/20-securizar-normalize.conf ]]; then
    check "Normalizacion de logs configurada" "OK"
else
    check "Normalizacion de logs configurada" "FAIL"
fi

# --- 7. Correlacion ---
echo -e "${BOLD}[7/10] Correlacion${NC}"
if [[ -x /usr/local/bin/correlacionar-eventos.sh ]]; then
    check "Herramienta de correlacion instalada" "OK"
else
    check "Herramienta de correlacion instalada" "FAIL"
fi
if systemctl is-active securizar-correlacion.timer &>/dev/null; then
    check "Timer de correlacion activo" "OK"
else
    check "Timer de correlacion activo" "FAIL"
fi

# --- 8. Alertas ---
echo -e "${BOLD}[8/10] Alertas${NC}"
if [[ -f /etc/rsyslog.d/30-securizar-alertas.conf ]]; then
    check "Alertas rsyslog configuradas" "OK"
else
    check "Alertas rsyslog configuradas" "FAIL"
fi
if [[ -x /usr/local/bin/securizar-log-alertas.sh ]]; then
    check "Script de alertas instalado" "OK"
else
    check "Script de alertas instalado" "FAIL"
fi

# --- 9. Retencion ---
echo -e "${BOLD}[9/10] Retencion${NC}"
if [[ -f /etc/logrotate.d/securizar-retencion ]]; then
    check "Politica de retencion configurada" "OK"
else
    check "Politica de retencion configurada" "FAIL"
fi
if [[ -x /usr/local/bin/gestionar-retencion-logs.sh ]]; then
    check "Herramienta de gestion de retencion" "OK"
else
    check "Herramienta de gestion de retencion" "FAIL"
fi

# --- 10. SIEM y forense ---
echo -e "${BOLD}[10/10] SIEM y forense${NC}"
if [[ -d /etc/securizar/siem ]] && ls /etc/securizar/siem/*.conf &>/dev/null; then
    check "Templates SIEM disponibles" "OK"
else
    check "Templates SIEM disponibles" "FAIL"
fi
if [[ -x /usr/local/bin/forense-logs.sh ]]; then
    check "Herramienta forense instalada" "OK"
else
    check "Herramienta forense instalada" "FAIL"
fi

# --- Puntuacion ---
echo ""
PORCENT=$(( PASADOS * 100 / TOTAL ))
if [[ $PORCENT -ge 80 ]]; then
    NIVEL="COMPLETO"
    COLOR="$GREEN"
elif [[ $PORCENT -ge 50 ]]; then
    NIVEL="PARCIAL"
    COLOR="$YELLOW"
else
    NIVEL="INSUFICIENTE"
    COLOR="$RED"
fi

echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo -e "  Controles verificados: $PASADOS / $TOTAL ($PORCENT%)"
echo -e "  Nivel de cobertura:    ${COLOR}${BOLD}$NIVEL${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo ""

# --- Exportar JSON ---
cat > "$JSON_OUT" << EOFJSON
{
    "fecha": "$FECHA",
    "hostname": "$(hostname)",
    "total_controles": $TOTAL,
    "controles_pasados": $PASADOS,
    "porcentaje": $PORCENT,
    "nivel": "$NIVEL",
    "detalles": {
        "rsyslog_activo": $(systemctl is-active rsyslog &>/dev/null && echo "true" || echo "false"),
        "rsyslog_hardening": $([ -f /etc/rsyslog.d/01-securizar-hardening.conf ] && echo "true" || echo "false"),
        "journald_hardening": $([ -f /etc/systemd/journald.conf.d/01-securizar.conf ] && echo "true" || echo "false"),
        "journald_persistente": $([ -d /var/log/journal ] && echo "true" || echo "false"),
        "tls_configurado": $([ -f /etc/rsyslog.d/10-securizar-tls-forwarding.conf ] && echo "true" || echo "false"),
        "tls_certificados": $([ -f /etc/securizar/log-certs/ca.pem ] && echo "true" || echo "false"),
        "permisos_varlog": "$VARLOG_PERMS",
        "integridad_script": $([ -x /usr/local/bin/securizar-log-integrity.sh ] && echo "true" || echo "false"),
        "integridad_cron": $([ -f /etc/cron.daily/securizar-log-hashes ] && echo "true" || echo "false"),
        "normalizacion": $([ -f /etc/rsyslog.d/20-securizar-normalize.conf ] && echo "true" || echo "false"),
        "correlacion_script": $([ -x /usr/local/bin/correlacionar-eventos.sh ] && echo "true" || echo "false"),
        "correlacion_timer": $(systemctl is-active securizar-correlacion.timer &>/dev/null && echo "true" || echo "false"),
        "alertas_rsyslog": $([ -f /etc/rsyslog.d/30-securizar-alertas.conf ] && echo "true" || echo "false"),
        "alertas_script": $([ -x /usr/local/bin/securizar-log-alertas.sh ] && echo "true" || echo "false"),
        "retencion_logrotate": $([ -f /etc/logrotate.d/securizar-retencion ] && echo "true" || echo "false"),
        "retencion_gestion": $([ -x /usr/local/bin/gestionar-retencion-logs.sh ] && echo "true" || echo "false"),
        "siem_templates": $([ -d /etc/securizar/siem ] && ls /etc/securizar/siem/*.conf &>/dev/null && echo "true" || echo "false"),
        "forense_script": $([ -x /usr/local/bin/forense-logs.sh ] && echo "true" || echo "false")
    }
}
EOFJSON

echo "Resultado JSON: $JSON_OUT"
echo ""
EOFAUDIT

    chmod 755 /usr/local/bin/auditoria-logging.sh
    log_change "Creado" "/usr/local/bin/auditoria-logging.sh"

    # --- Cron semanal ---
    cat > /etc/cron.weekly/auditoria-logging << 'EOFCRONAUDIT'
#!/bin/bash
# Auditoria semanal de infraestructura de logging
/usr/local/bin/auditoria-logging.sh >/dev/null 2>&1
EOFCRONAUDIT

    chmod 755 /etc/cron.weekly/auditoria-logging
    log_change "Creado" "/etc/cron.weekly/auditoria-logging"

    log_info "Auditoria de logging instalada"
    log_info "Ejecuta: auditoria-logging.sh"

else
    log_skip "Auditoria de logging"
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
show_changes_summary
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║       LOGGING CENTRALIZADO Y SIEM COMPLETADO              ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups guardados en: $BACKUP_DIR"
echo ""
echo "Comandos utiles post-instalacion:"
echo "  - Configurar log remoto: configurar-log-remoto.sh <IP>"
echo "  - Verificar integridad:  securizar-log-integrity.sh [generar|verificar]"
echo "  - Correlacionar eventos: correlacionar-eventos.sh [--rango HORAS]"
echo "  - Gestionar retencion:   gestionar-retencion-logs.sh [resumen|limpiar]"
echo "  - Activar SIEM:          activar-siem.sh"
echo "  - Forense de logs:       forense-logs.sh [--desde FECHA] [--hasta FECHA]"
echo "  - Auditoria de logging:  auditoria-logging.sh"
echo ""
log_warn "RECOMENDACION: Ejecuta 'auditoria-logging.sh' para verificar la configuracion"
echo ""
log_info "Modulo 43 completado"
