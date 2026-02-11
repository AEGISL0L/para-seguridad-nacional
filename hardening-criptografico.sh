#!/bin/bash
# ============================================================
# HARDENING CRIPTOGRAFICO - Linux Multi-Distro
# Modulo 39 - Securizar Suite
# ============================================================
# Secciones:
#   S1  - Auditoria y hardening de algoritmos SSH
#   S2  - TLS system-wide hardening
#   S3  - Monitorizacion de certificados
#   S4  - Calidad de entropia y numeros aleatorios
#   S5  - Hardening GPG
#   S6  - Verificacion de cifrado de disco
#   S7  - Escaneo TLS de servicios locales
#   S8  - Auditoria de hashing de contrasenas
#   S9  - Hardening criptografico del kernel
#   S10 - Auditoria criptografica completa
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "hardening-criptografico"
securizar_setup_traps

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MODULO 39 - HARDENING CRIPTOGRAFICO                    ║"
echo "║   Algoritmos SSH, TLS, certificados, entropia, GPG,      ║"
echo "║   LUKS, hashing, kernel crypto                           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

# ============================================================
# S1: AUDITORIA Y HARDENING DE ALGORITMOS SSH
# ============================================================
log_section "S1: AUDITORIA Y HARDENING DE ALGORITMOS SSH"

echo "Configura algoritmos criptograficos robustos para SSH:"
echo "  - KexAlgorithms: sntrup761x25519, curve25519, DH grupo 16/18"
echo "  - Ciphers: chacha20-poly1305, aes256-gcm, aes128-gcm, aes256-ctr"
echo "  - MACs: hmac-sha2-512-etm, hmac-sha2-256-etm, umac-128-etm"
echo "  - HostKey: ed25519, rsa-sha2-512/256"
echo "  - Elimina claves DSA/ECDSA, genera Ed25519 si falta"
echo ""

if ask "¿Aplicar hardening criptografico de SSH?"; then

    # Analizar configuracion actual
    log_info "Analizando configuracion SSH actual..."
    if [[ -f /etc/ssh/sshd_config ]]; then
        cp /etc/ssh/sshd_config "$BACKUP_DIR/"
        log_change "Backup" "/etc/ssh/sshd_config"

        # Mostrar estado actual
        for param in Ciphers MACs KexAlgorithms HostKeyAlgorithms PubkeyAcceptedAlgorithms; do
            current=$(grep -i "^${param}" /etc/ssh/sshd_config 2>/dev/null | head -1 || echo "  (no definido - usa defaults)")
            echo "  Actual $param: $current"
        done
    fi

    # Crear directorio sshd_config.d si no existe
    mkdir -p /etc/ssh/sshd_config.d

    # Escribir configuracion hardened
    cat > /etc/ssh/sshd_config.d/99-securizar-crypto.conf << 'EOF'
# ============================================================
# Hardening criptografico SSH - Generado por securizar
# ============================================================
# Solo algoritmos modernos y robustos

KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512

Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr

MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com

HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
PubkeyAcceptedAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
EOF
    log_change "Creado" "/etc/ssh/sshd_config.d/99-securizar-crypto.conf"

    # Generar clave Ed25519 si no existe
    if [[ ! -f /etc/ssh/ssh_host_ed25519_key ]]; then
        ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" -q
        log_change "Generado" "clave host Ed25519: /etc/ssh/ssh_host_ed25519_key"
        log_info "Clave Ed25519 generada"
    else
        log_info "Clave Ed25519 ya existe"
    fi

    # Eliminar claves DSA y ECDSA si existen
    for keytype in dsa ecdsa; do
        keyfile="/etc/ssh/ssh_host_${keytype}_key"
        if [[ -f "$keyfile" ]]; then
            cp "$keyfile" "$BACKUP_DIR/" 2>/dev/null || true
            cp "${keyfile}.pub" "$BACKUP_DIR/" 2>/dev/null || true
            rm -f "$keyfile" "${keyfile}.pub"
            log_change "Eliminado" "clave host ${keytype}: $keyfile (insegura)"
        fi
    done

    # Crear script de auditoria SSH
    cat > /usr/local/bin/auditar-ssh-crypto.sh << 'EOFSSH'
#!/bin/bash
# ============================================================
# Auditoria de configuracion criptografica SSH
# Generado por securizar - Modulo 39
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  AUDITORIA CRIPTOGRAFICA SSH${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

# Algoritmos configurados
echo -e "${CYAN}── Algoritmos configurados ──${NC}"
for param in KexAlgorithms Ciphers MACs HostKeyAlgorithms PubkeyAcceptedAlgorithms; do
    value=$(sshd -T 2>/dev/null | grep -i "^${param,,}" | head -1 || echo "no disponible")
    echo -e "  ${BOLD}${param}:${NC} ${value#* }"
done

# Claves host
echo ""
echo -e "${CYAN}── Claves host ──${NC}"
for keyfile in /etc/ssh/ssh_host_*_key; do
    [[ -f "$keyfile" ]] || continue
    keytype=$(ssh-keygen -l -f "$keyfile" 2>/dev/null | awk '{print $4}' || echo "?")
    keybits=$(ssh-keygen -l -f "$keyfile" 2>/dev/null | awk '{print $1}' || echo "?")
    basename_key=$(basename "$keyfile")
    case "$keytype" in
        *ED25519*|*RSA*)
            echo -e "  ${GREEN}OK${NC}  $basename_key ($keybits bits, $keytype)" ;;
        *DSA*|*ECDSA*)
            echo -e "  ${RED}!!${NC}  $basename_key ($keybits bits, $keytype) - INSEGURO" ;;
        *)
            echo -e "  ${YELLOW}??${NC}  $basename_key ($keybits bits, $keytype)" ;;
    esac
done

# Verificar algoritmos debiles activos
echo ""
echo -e "${CYAN}── Verificacion de algoritmos debiles ──${NC}"
weak_found=0
active_ciphers=$(sshd -T 2>/dev/null | grep "^ciphers " | head -1 || echo "")
for weak in 3des-cbc aes128-cbc aes256-cbc arcfour blowfish-cbc cast128-cbc; do
    if echo "$active_ciphers" | grep -qi "$weak"; then
        echo -e "  ${RED}!!${NC}  Cifrado debil activo: $weak"
        ((weak_found++))
    fi
done
active_macs=$(sshd -T 2>/dev/null | grep "^macs " | head -1 || echo "")
for weak in hmac-md5 hmac-sha1 umac-64; do
    if echo "$active_macs" | grep -qi "$weak"; then
        echo -e "  ${RED}!!${NC}  MAC debil activo: $weak"
        ((weak_found++))
    fi
done
if [[ $weak_found -eq 0 ]]; then
    echo -e "  ${GREEN}OK${NC}  No se detectaron algoritmos debiles"
fi

echo ""
echo -e "${BOLD}Auditoria completada: $(date)${NC}"
EOFSSH
    chmod +x /usr/local/bin/auditar-ssh-crypto.sh
    log_change "Creado" "/usr/local/bin/auditar-ssh-crypto.sh"
    log_change "Permisos" "/usr/local/bin/auditar-ssh-crypto.sh -> +x"

    # Validar configuracion SSH antes de recargar
    if sshd -t 2>/dev/null; then
        log_info "Configuracion SSH validada correctamente"
        systemctl reload "$SSH_SERVICE_NAME" 2>/dev/null || true
        log_change "Aplicado" "reload $SSH_SERVICE_NAME"
    else
        log_error "Error en configuracion SSH - revisa manualmente"
        log_warn "Archivo: /etc/ssh/sshd_config.d/99-securizar-crypto.conf"
    fi

    log_info "Hardening SSH criptografico aplicado"
else
    log_skip "Hardening criptografico SSH"
fi

# ============================================================
# S2: TLS SYSTEM-WIDE HARDENING
# ============================================================
log_section "S2: TLS SYSTEM-WIDE HARDENING"

echo "Endurece la configuracion TLS a nivel de sistema:"
echo "  - Crypto-policies FUTURE (RHEL/Fedora)"
echo "  - OpenSSL: MinProtocol TLSv1.2, sin MD5/3DES/RC4/DES"
echo "  - Deshabilita TLS 1.0/1.1 en Apache/nginx si existen"
echo ""

if ask "¿Aplicar hardening TLS del sistema?"; then

    # RHEL family: usar crypto-policies
    if [[ "$DISTRO_FAMILY" == "rhel" ]]; then
        if command -v update-crypto-policies &>/dev/null; then
            current_policy=$(update-crypto-policies --show 2>/dev/null || echo "desconocida")
            log_info "Crypto-policy actual: $current_policy"
            if [[ "$current_policy" != "FUTURE" ]]; then
                update-crypto-policies --set FUTURE 2>/dev/null || true
                log_change "Aplicado" "update-crypto-policies --set FUTURE"
                log_info "Crypto-policy establecida a FUTURE"
            else
                log_info "Crypto-policy ya es FUTURE"
            fi
        fi
    fi

    # Directorio de configuracion securizar
    mkdir -p /etc/securizar

    # Documentar estandares minimos
    cat > /etc/securizar/tls-hardening.conf << 'EOF'
# ============================================================
# Estandares minimos TLS - securizar
# ============================================================
# Protocolo minimo: TLSv1.2
# Protocolo recomendado: TLSv1.3
# Cifrados prohibidos: RC4, DES, 3DES, MD5, aNULL, eNULL
# Tamano minimo de clave RSA: 2048 bits
# Curvas permitidas: X25519, P-256, P-384
# Firma minima: SHA-256
# ============================================================
MIN_PROTOCOL=TLSv1.2
CIPHER_STRING="HIGH:!aNULL:!MD5:!3DES:!RC4:!DES:!eNULL:!EXPORT"
MIN_RSA_KEY_SIZE=2048
MIN_DH_PARAM_SIZE=2048
EOF
    log_change "Creado" "/etc/securizar/tls-hardening.conf"

    # Configuracion OpenSSL hardened
    cat > /etc/ssl/openssl-securizar.cnf << 'EOF'
# ============================================================
# OpenSSL hardened - securizar
# ============================================================
[openssl_init]
ssl_conf = ssl_configuration

[ssl_configuration]
system_default = tls_defaults

[tls_defaults]
MinProtocol = TLSv1.2
CipherString = HIGH:!aNULL:!MD5:!3DES:!RC4:!DES:!eNULL:!EXPORT
Options = PrioritizeChaCha
EOF
    log_change "Creado" "/etc/ssl/openssl-securizar.cnf"

    # Reportar protocolo minimo actual de OpenSSL
    if command -v openssl &>/dev/null; then
        openssl_version=$(openssl version 2>/dev/null || echo "desconocida")
        log_info "Version OpenSSL: $openssl_version"
        # Verificar protocolos soportados
        for proto in tls1 tls1_1 tls1_2 tls1_3; do
            if openssl s_client -help 2>&1 | grep -q "\-${proto} "; then
                echo "  Protocolo $proto: soportado"
            fi
        done
    fi

    # Deshabilitar TLS 1.0/1.1 en Apache si existe
    if [[ -d /etc/apache2 ]] || [[ -d /etc/httpd ]]; then
        apache_conf=""
        if [[ -d /etc/apache2/conf-available ]]; then
            apache_conf="/etc/apache2/conf-available/securizar-tls.conf"
        elif [[ -d /etc/httpd/conf.d ]]; then
            apache_conf="/etc/httpd/conf.d/securizar-tls.conf"
        fi
        if [[ -n "$apache_conf" ]]; then
            cat > "$apache_conf" << 'EOF'
# Hardening TLS - securizar
SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLCipherSuite HIGH:!aNULL:!MD5:!3DES:!RC4:!DES
SSLHonorCipherOrder on
SSLCompression off
SSLSessionTickets off
EOF
            log_change "Creado" "$apache_conf"
            # Activar en Debian
            if [[ -d /etc/apache2/conf-available ]] && command -v a2enconf &>/dev/null; then
                a2enconf securizar-tls 2>/dev/null || true
            fi
        fi
    fi

    # Deshabilitar TLS 1.0/1.1 en nginx si existe
    if [[ -d /etc/nginx ]]; then
        nginx_conf=""
        if [[ -d /etc/nginx/conf.d ]]; then
            nginx_conf="/etc/nginx/conf.d/securizar-tls.conf"
        fi
        if [[ -n "$nginx_conf" ]]; then
            cat > "$nginx_conf" << 'EOF'
# Hardening TLS - securizar
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'HIGH:!aNULL:!MD5:!3DES:!RC4:!DES';
ssl_prefer_server_ciphers on;
ssl_session_tickets off;
EOF
            log_change "Creado" "$nginx_conf"
        fi
    fi

    log_info "Hardening TLS del sistema aplicado"
else
    log_skip "Hardening TLS del sistema"
fi

# ============================================================
# S3: MONITORIZACION DE CERTIFICADOS
# ============================================================
log_section "S3: MONITORIZACION DE CERTIFICADOS"

echo "Crea un sistema de monitorizacion de certificados:"
echo "  - Escanea /etc/ssl y /etc/pki buscando .pem/.crt/.cert"
echo "  - Detecta: expirados, proximos a expirar, claves debiles, SHA-1"
echo "  - Instala tarea cron semanal"
echo ""

if ask "¿Crear sistema de monitorizacion de certificados?"; then

    cat > /usr/local/bin/monitorizar-certificados.sh << 'EOFCERT'
#!/bin/bash
# ============================================================
# Monitor de certificados X.509 - securizar
# Escanea el sistema en busca de certificados problematicos
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  MONITOR DE CERTIFICADOS X.509${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

total=0
expirados=0
proximos=0
debiles=0
sha1_count=0

# Directorios a escanear
CERT_DIRS="/etc/ssl /etc/pki /usr/local/share/ca-certificates /etc/ca-certificates"

for dir in $CERT_DIRS; do
    [[ -d "$dir" ]] || continue
    while IFS= read -r -d '' certfile; do
        # Verificar que es un certificado valido
        if ! openssl x509 -in "$certfile" -noout 2>/dev/null; then
            continue
        fi
        ((total++))

        # Informacion del certificado
        subject=$(openssl x509 -in "$certfile" -noout -subject 2>/dev/null | sed 's/subject=//')
        enddate=$(openssl x509 -in "$certfile" -noout -enddate 2>/dev/null | sed 's/notAfter=//')
        keysize=$(openssl x509 -in "$certfile" -noout -text 2>/dev/null | grep "Public-Key:" | grep -oP '\d+' || echo "?")
        sigalgo=$(openssl x509 -in "$certfile" -noout -text 2>/dev/null | grep "Signature Algorithm:" | head -1 | awk '{print $3}')

        # Comprobar expiracion
        endepoch=$(date -d "$enddate" +%s 2>/dev/null || echo 0)
        now=$(date +%s)
        days_left=$(( (endepoch - now) / 86400 ))

        status=""
        color="$GREEN"

        if [[ $days_left -lt 0 ]]; then
            status="EXPIRADO (hace $((days_left * -1)) dias)"
            color="$RED"
            ((expirados++))
        elif [[ $days_left -lt 30 ]]; then
            status="EXPIRA en $days_left dias"
            color="$YELLOW"
            ((proximos++))
        else
            status="OK ($days_left dias restantes)"
        fi

        # Comprobar clave debil
        weak_key=0
        if [[ "$keysize" =~ ^[0-9]+$ ]] && [[ "$keysize" -lt 2048 ]]; then
            weak_key=1
            ((debiles++))
        fi

        # Comprobar SHA-1
        sha1_sig=0
        if echo "$sigalgo" | grep -qi "sha1"; then
            sha1_sig=1
            ((sha1_count++))
        fi

        # Solo mostrar si hay problemas o modo verbose
        if [[ $days_left -lt 30 ]] || [[ $weak_key -eq 1 ]] || [[ $sha1_sig -eq 1 ]]; then
            echo -e "${color}  $certfile${NC}"
            echo -e "    Subject: ${DIM}$subject${NC}"
            echo -e "    Estado:  ${color}${status}${NC}"
            [[ $weak_key -eq 1 ]] && echo -e "    ${RED}!! Clave debil: ${keysize} bits (minimo recomendado: 2048)${NC}"
            [[ $sha1_sig -eq 1 ]] && echo -e "    ${RED}!! Firma SHA-1 detectada (insegura)${NC}"
            echo ""
        fi
    done < <(find "$dir" -type f \( -name "*.pem" -o -name "*.crt" -o -name "*.cert" \) -print0 2>/dev/null)
done

echo -e "${CYAN}── Resumen ──${NC}"
echo -e "  Total certificados escaneados: $total"
echo -e "  ${RED}Expirados:${NC}          $expirados"
echo -e "  ${YELLOW}Proximos a expirar:${NC} $proximos (<30 dias)"
echo -e "  ${RED}Claves debiles:${NC}     $debiles (<2048 bits RSA)"
echo -e "  ${RED}Firmas SHA-1:${NC}       $sha1_count"
echo ""
echo -e "${BOLD}Escaneo completado: $(date)${NC}"
EOFCERT
    chmod +x /usr/local/bin/monitorizar-certificados.sh
    log_change "Creado" "/usr/local/bin/monitorizar-certificados.sh"
    log_change "Permisos" "/usr/local/bin/monitorizar-certificados.sh -> +x"

    # Instalar cron semanal
    cat > /etc/cron.weekly/monitorizar-certificados << 'EOFCRON'
#!/bin/bash
# Monitorizacion semanal de certificados - securizar
/usr/local/bin/monitorizar-certificados.sh > /var/log/securizar-certificados.log 2>&1
EOFCRON
    chmod +x /etc/cron.weekly/monitorizar-certificados
    log_change "Creado" "/etc/cron.weekly/monitorizar-certificados"

    log_info "Sistema de monitorizacion de certificados instalado"
else
    log_skip "Monitorizacion de certificados"
fi

# ============================================================
# S4: CALIDAD DE ENTROPIA Y NUMEROS ALEATORIOS
# ============================================================
log_section "S4: CALIDAD DE ENTROPIA Y NUMEROS ALEATORIOS"

echo "Verifica y mejora la calidad de entropia del sistema:"
echo "  - Comprueba /proc/sys/kernel/random/entropy_avail"
echo "  - Instala rng-tools o haveged si la entropia es baja"
echo "  - Crea script de verificacion permanente"
echo ""

if ask "¿Verificar y mejorar la entropia del sistema?"; then

    # Comprobar entropia actual
    if [[ -f /proc/sys/kernel/random/entropy_avail ]]; then
        entropy_avail=$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null || echo 0)
        log_info "Entropia disponible: $entropy_avail bits"

        if [[ "$entropy_avail" -lt 256 ]]; then
            log_warn "Entropia BAJA ($entropy_avail < 256). Se recomienda instalar generador de entropia"

            # Intentar instalar rng-tools primero, luego haveged como fallback
            installed_rng=0
            if command -v rngd &>/dev/null; then
                log_info "rng-tools ya instalado"
                installed_rng=1
            else
                log_info "Intentando instalar rng-tools..."
                if pkg_install rng-tools 2>/dev/null; then
                    installed_rng=1
                    log_change "Instalado" "rng-tools"
                fi
            fi

            if [[ $installed_rng -eq 1 ]]; then
                systemctl enable rng-tools 2>/dev/null || systemctl enable rngd 2>/dev/null || true
                systemctl start rng-tools 2>/dev/null || systemctl start rngd 2>/dev/null || true
                log_change "Activado" "servicio rng-tools/rngd"
            else
                # Fallback a haveged
                log_info "rng-tools no disponible, intentando haveged..."
                if pkg_install haveged 2>/dev/null; then
                    systemctl enable haveged 2>/dev/null || true
                    systemctl start haveged 2>/dev/null || true
                    log_change "Instalado" "haveged (generador de entropia)"
                    log_change "Activado" "servicio haveged"
                else
                    log_warn "No se pudo instalar rng-tools ni haveged"
                fi
            fi

            # Verificar mejora
            sleep 1
            entropy_new=$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null || echo 0)
            log_info "Entropia despues de mejora: $entropy_new bits"
        else
            log_info "Entropia adecuada ($entropy_avail >= 256)"
        fi
    else
        log_warn "/proc/sys/kernel/random/entropy_avail no disponible"
    fi

    # Verificar pool size
    if [[ -f /proc/sys/kernel/random/poolsize ]]; then
        poolsize=$(cat /proc/sys/kernel/random/poolsize 2>/dev/null || echo "?")
        log_info "Tamano del pool de entropia: $poolsize bits"
    fi

    # Configurar urandom_min_reseed_secs si existe
    if [[ -f /proc/sys/kernel/random/urandom_min_reseed_secs ]]; then
        current_reseed=$(cat /proc/sys/kernel/random/urandom_min_reseed_secs 2>/dev/null || echo "?")
        log_info "urandom_min_reseed_secs actual: $current_reseed"
        if [[ "$current_reseed" != "60" ]]; then
            echo "kernel.random.urandom_min_reseed_secs = 60" >> /etc/sysctl.d/99-securizar-entropy.conf
            sysctl -w kernel.random.urandom_min_reseed_secs=60 2>/dev/null || true
            log_change "Configurado" "kernel.random.urandom_min_reseed_secs = 60"
        fi
    fi

    # Crear script de verificacion
    cat > /usr/local/bin/verificar-entropia.sh << 'EOFENT'
#!/bin/bash
# ============================================================
# Verificacion de entropia del sistema - securizar
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  VERIFICACION DE ENTROPIA${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

# Entropia disponible
entropy=$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null || echo "N/A")
poolsize=$(cat /proc/sys/kernel/random/poolsize 2>/dev/null || echo "N/A")

echo -e "${CYAN}── Pool de entropia ──${NC}"
echo -e "  Disponible: ${BOLD}$entropy${NC} bits"
echo -e "  Pool size:  $poolsize bits"

if [[ "$entropy" =~ ^[0-9]+$ ]]; then
    if [[ "$entropy" -ge 1000 ]]; then
        echo -e "  Estado: ${GREEN}EXCELENTE${NC}"
    elif [[ "$entropy" -ge 256 ]]; then
        echo -e "  Estado: ${GREEN}ADECUADO${NC}"
    elif [[ "$entropy" -ge 100 ]]; then
        echo -e "  Estado: ${YELLOW}BAJO${NC} - considere instalar rng-tools o haveged"
    else
        echo -e "  Estado: ${RED}CRITICO${NC} - operaciones criptograficas pueden bloquearse"
    fi
fi

# Servicios de entropia
echo ""
echo -e "${CYAN}── Servicios de entropia ──${NC}"
for svc in rngd rng-tools haveged jitterentropy; do
    if systemctl is-active "$svc" &>/dev/null 2>&1; then
        echo -e "  ${GREEN}ACTIVO${NC}  $svc"
    elif systemctl is-enabled "$svc" &>/dev/null 2>&1; then
        echo -e "  ${YELLOW}INACT.${NC}  $svc (habilitado pero no corriendo)"
    fi
done

# Fuentes de entropia hardware
echo ""
echo -e "${CYAN}── Fuentes de entropia hardware ──${NC}"
if [[ -c /dev/hwrng ]]; then
    echo -e "  ${GREEN}OK${NC}  /dev/hwrng presente (HWRNG)"
else
    echo -e "  ${YELLOW}--${NC}  No se detecta HWRNG (/dev/hwrng)"
fi
if grep -q "rdrand" /proc/cpuinfo 2>/dev/null; then
    echo -e "  ${GREEN}OK${NC}  CPU soporta RDRAND"
else
    echo -e "  ${YELLOW}--${NC}  CPU no soporta RDRAND"
fi
if grep -q "rdseed" /proc/cpuinfo 2>/dev/null; then
    echo -e "  ${GREEN}OK${NC}  CPU soporta RDSEED"
else
    echo -e "  ${YELLOW}--${NC}  CPU no soporta RDSEED"
fi

# Monitoreo de bloqueo en /dev/random
echo ""
echo -e "${CYAN}── Test rapido de /dev/random ──${NC}"
start_time=$(date +%s%N)
dd if=/dev/random bs=16 count=1 iflag=nonblock 2>/dev/null | wc -c > /dev/null
end_time=$(date +%s%N)
elapsed=$(( (end_time - start_time) / 1000000 ))
if [[ $elapsed -gt 1000 ]]; then
    echo -e "  ${RED}!!${NC}  Lectura de /dev/random lenta (${elapsed}ms) - posible bloqueo"
else
    echo -e "  ${GREEN}OK${NC}  /dev/random responde rapidamente (${elapsed}ms)"
fi

echo ""
echo -e "${BOLD}Verificacion completada: $(date)${NC}"
EOFENT
    chmod +x /usr/local/bin/verificar-entropia.sh
    log_change "Creado" "/usr/local/bin/verificar-entropia.sh"
    log_change "Permisos" "/usr/local/bin/verificar-entropia.sh -> +x"

    log_info "Verificacion de entropia configurada"
else
    log_skip "Calidad de entropia"
fi

# ============================================================
# S5: HARDENING GPG
# ============================================================
log_section "S5: HARDENING GPG"

echo "Configura algoritmos seguros por defecto para GnuPG:"
echo "  - personal-cipher-preferences: AES256 AES192 AES"
echo "  - personal-digest-preferences: SHA512 SHA384 SHA256"
echo "  - s2k-cipher-algo AES256, s2k-digest-algo SHA512"
echo "  - Aplica a /etc/skel y usuarios existentes"
echo ""

if ask "¿Aplicar hardening de GPG?"; then

    if command -v gpg &>/dev/null; then
        log_info "GPG detectado: $(gpg --version 2>/dev/null | head -1)"

        # Contenido de gpg.conf hardened
        GPG_HARDENED_CONF='# ============================================================
# GPG hardened - securizar
# ============================================================
# Algoritmos y preferencias seguras

personal-cipher-preferences AES256 AES192 AES
personal-digest-preferences SHA512 SHA384 SHA256
cert-digest-algo SHA512
default-preference-list SHA512 SHA384 SHA256 AES256 AES192 AES ZLIB BZIP2 ZIP Uncompressed

# Opciones de keyserver
keyserver-options no-honor-keyserver-url

# Privacidad
no-emit-version
no-comments

# S2K (String-to-Key) hardening
s2k-cipher-algo AES256
s2k-digest-algo SHA512
s2k-mode 3
s2k-count 65011712
'

        # Configurar /etc/skel para nuevos usuarios
        mkdir -p /etc/skel/.gnupg
        chmod 700 /etc/skel/.gnupg
        echo "$GPG_HARDENED_CONF" > /etc/skel/.gnupg/gpg.conf
        chmod 600 /etc/skel/.gnupg/gpg.conf
        log_change "Creado" "/etc/skel/.gnupg/gpg.conf (hardened)"

        # Auditar configuracion de usuarios existentes
        log_info "Auditando configuracion GPG de usuarios existentes..."
        while IFS=: read -r username _ uid _ _ homedir _; do
            # Solo usuarios normales (UID >= 1000) y root
            if [[ "$uid" -ge 1000 ]] || [[ "$uid" -eq 0 ]]; then
                [[ -d "$homedir" ]] || continue
                gpg_dir="${homedir}/.gnupg"
                gpg_conf="${gpg_dir}/gpg.conf"

                if [[ -d "$gpg_dir" ]]; then
                    if [[ -f "$gpg_conf" ]]; then
                        # Verificar si ya tiene preferencias seguras
                        if grep -q "s2k-cipher-algo AES256" "$gpg_conf" 2>/dev/null; then
                            log_info "  $username: gpg.conf ya hardened"
                        else
                            cp "$gpg_conf" "$BACKUP_DIR/gpg.conf.${username}" 2>/dev/null || true
                            echo "" >> "$gpg_conf"
                            echo "$GPG_HARDENED_CONF" >> "$gpg_conf"
                            log_change "Modificado" "${gpg_conf} (anadidas preferencias seguras)"
                        fi
                    else
                        echo "$GPG_HARDENED_CONF" > "$gpg_conf"
                        chown "${username}:" "$gpg_conf" 2>/dev/null || true
                        chmod 600 "$gpg_conf"
                        log_change "Creado" "${gpg_conf} (hardened)"
                    fi

                    # Asegurar permisos del directorio
                    chmod 700 "$gpg_dir"
                fi
            fi
        done < /etc/passwd

        log_info "Hardening GPG aplicado"
    else
        log_warn "GPG no esta instalado en el sistema"
    fi
else
    log_skip "Hardening GPG"
fi

# ============================================================
# S6: VERIFICACION DE CIFRADO DE DISCO
# ============================================================
log_section "S6: VERIFICACION DE CIFRADO DE DISCO"

echo "Analiza volumenes LUKS y reporta su configuracion:"
echo "  - Cifrado, tamano de clave, hash, key slots activos"
echo "  - Alerta si usa aes-cbc, clave <256 bits, muchos key slots"
echo ""

if ask "¿Auditar cifrado de disco LUKS?"; then

    if command -v cryptsetup &>/dev/null; then
        log_info "Buscando volumenes LUKS..."

        luks_found=0
        while IFS= read -r device; do
            [[ -z "$device" ]] && continue
            # Verificar si es LUKS
            if cryptsetup isLuks "$device" 2>/dev/null; then
                ((luks_found++))
                echo ""
                echo -e "${CYAN}── Dispositivo LUKS: $device ──${NC}"

                # Dump de informacion
                dump_output=$(cryptsetup luksDump "$device" 2>/dev/null || echo "")

                cipher=$(echo "$dump_output" | grep "Cipher:" | head -1 | awk '{print $2}' || echo "?")
                cipher_mode=$(echo "$dump_output" | grep "Cipher mode:" | head -1 | awk -F: '{print $2}' | xargs || echo "?")
                keysize=$(echo "$dump_output" | grep "MK bits:" | head -1 | awk '{print $3}' || echo "?")
                hash=$(echo "$dump_output" | grep "Hash spec:" | head -1 | awk '{print $3}' || echo "?")

                echo "  Cifrado:      $cipher ($cipher_mode)"
                echo "  Tamano clave: $keysize bits"
                echo "  Hash:         $hash"

                # Contar key slots activos
                active_slots=$(echo "$dump_output" | grep -c "ENABLED" || echo "0")
                echo "  Key slots activos: $active_slots"

                # Alertas
                if echo "$cipher_mode" | grep -qi "cbc"; then
                    log_warn "  $device usa modo CBC - se recomienda XTS"
                fi
                if [[ "$keysize" =~ ^[0-9]+$ ]] && [[ "$keysize" -lt 256 ]]; then
                    log_warn "  $device tiene clave de $keysize bits - se recomienda >= 256"
                fi
                if [[ "$active_slots" =~ ^[0-9]+$ ]] && [[ "$active_slots" -gt 3 ]]; then
                    log_warn "  $device tiene $active_slots key slots activos (riesgo: mas vectores de ataque)"
                fi
                if echo "$hash" | grep -qi "sha1"; then
                    log_warn "  $device usa SHA-1 como hash - se recomienda SHA-256 o superior"
                fi
            fi
        done < <(lsblk -dpno NAME 2>/dev/null)

        if [[ $luks_found -eq 0 ]]; then
            log_warn "No se encontraron volumenes LUKS"
            log_warn "Recomendacion: cifrar discos con LUKS (aes-xts-plain64, 512 bits)"
        else
            log_info "Encontrados $luks_found volumenes LUKS"
        fi
    else
        log_warn "cryptsetup no instalado - no se puede auditar LUKS"
    fi

    # Crear script de auditoria LUKS
    cat > /usr/local/bin/auditar-luks.sh << 'EOFLUKS'
#!/bin/bash
# ============================================================
# Auditoria de volumenes LUKS - securizar
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  AUDITORIA DE CIFRADO DE DISCO (LUKS)${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

if ! command -v cryptsetup &>/dev/null; then
    echo -e "${RED}cryptsetup no instalado${NC}"
    exit 1
fi

luks_found=0
problemas=0

while IFS= read -r device; do
    [[ -z "$device" ]] && continue
    if cryptsetup isLuks "$device" 2>/dev/null; then
        ((luks_found++))
        echo -e "${CYAN}── $device ──${NC}"

        dump=$(cryptsetup luksDump "$device" 2>/dev/null)
        cipher=$(echo "$dump" | grep "Cipher:" | head -1 | awk '{print $2}')
        mode=$(echo "$dump" | grep "Cipher mode:" | head -1 | awk -F: '{print $2}' | xargs)
        keysize=$(echo "$dump" | grep "MK bits:" | head -1 | awk '{print $3}')
        hash=$(echo "$dump" | grep "Hash spec:" | head -1 | awk '{print $3}')
        slots=$(echo "$dump" | grep -c "ENABLED")

        echo "  Cifrado: $cipher-$mode | Clave: ${keysize}b | Hash: $hash | Slots: $slots"

        # Evaluacion
        ok=1
        if echo "$mode" | grep -qi "cbc"; then
            echo -e "  ${RED}!! Modo CBC detectado (vulnerable a watermarking, usar XTS)${NC}"
            ok=0; ((problemas++))
        fi
        if [[ "$keysize" =~ ^[0-9]+$ ]] && [[ "$keysize" -lt 256 ]]; then
            echo -e "  ${RED}!! Clave corta: ${keysize} bits (minimo 256)${NC}"
            ok=0; ((problemas++))
        fi
        if [[ "$slots" =~ ^[0-9]+$ ]] && [[ "$slots" -gt 3 ]]; then
            echo -e "  ${YELLOW}!! Muchos key slots activos: $slots${NC}"
            ok=0; ((problemas++))
        fi
        [[ $ok -eq 1 ]] && echo -e "  ${GREEN}OK${NC}  Configuracion adecuada"
        echo ""
    fi
done < <(lsblk -dpno NAME 2>/dev/null)

if [[ $luks_found -eq 0 ]]; then
    echo -e "${YELLOW}No se encontraron volumenes LUKS${NC}"
    echo "Recomendacion: cifrar discos con 'cryptsetup luksFormat --type luks2'"
fi

echo -e "${BOLD}Dispositivos LUKS: $luks_found | Problemas: $problemas${NC}"
echo -e "${BOLD}Auditoria completada: $(date)${NC}"
EOFLUKS
    chmod +x /usr/local/bin/auditar-luks.sh
    log_change "Creado" "/usr/local/bin/auditar-luks.sh"
    log_change "Permisos" "/usr/local/bin/auditar-luks.sh -> +x"

    log_info "Auditoria LUKS configurada"
else
    log_skip "Verificacion de cifrado de disco"
fi

# ============================================================
# S7: ESCANEO TLS DE SERVICIOS LOCALES
# ============================================================
log_section "S7: ESCANEO TLS DE SERVICIOS LOCALES"

echo "Crea script que analiza servicios TLS locales:"
echo "  - Busca puertos TCP en escucha (443, 636, 993, 995, 8443...)"
echo "  - Conecta con openssl s_client para inspeccionar TLS"
echo "  - Reporta: protocolo, cifrado, certificado, intercambio de claves"
echo ""

if ask "¿Crear script de escaneo TLS de servicios locales?"; then

    cat > /usr/local/bin/escanear-tls-local.sh << 'EOFTLS'
#!/bin/bash
# ============================================================
# Escaneo TLS de servicios locales - securizar
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  ESCANEO TLS DE SERVICIOS LOCALES${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

if ! command -v openssl &>/dev/null; then
    echo -e "${RED}openssl no instalado${NC}"
    exit 1
fi

# Puertos comunes TLS
TLS_PORTS="443 636 993 995 8443 8080 3389 5986 9443 4443"

total_scanned=0
total_issues=0

# Encontrar puertos en escucha
echo -e "${CYAN}── Buscando servicios TLS en escucha ──${NC}"
while IFS= read -r line; do
    # Extraer puerto
    port=$(echo "$line" | awk '{print $4}' | rev | cut -d: -f1 | rev)
    addr=$(echo "$line" | awk '{print $4}' | rev | cut -d: -f2- | rev)
    proc=$(echo "$line" | awk '{print $7}')

    # Verificar si es un puerto TLS comun o intentar en todos
    is_tls_port=0
    for tp in $TLS_PORTS; do
        if [[ "$port" == "$tp" ]]; then
            is_tls_port=1
            break
        fi
    done

    # Solo escanear puertos TLS conocidos
    [[ $is_tls_port -eq 0 ]] && continue

    ((total_scanned++))
    echo ""
    echo -e "${CYAN}── Puerto $port ($proc) ──${NC}"

    # Conectar con openssl s_client
    connect_addr="localhost"
    result=$(echo "Q" | timeout 5 openssl s_client -connect "${connect_addr}:${port}" -brief 2>&1 || echo "CONEXION_FALLIDA")

    if echo "$result" | grep -q "CONEXION_FALLIDA\|Connection refused\|connect:errno"; then
        echo -e "  ${DIM}No se pudo establecer conexion TLS${NC}"
        continue
    fi

    # Extraer informacion
    protocol=$(echo "$result" | grep -i "Protocol version:" | awk -F: '{print $2}' | xargs || echo "?")
    cipher=$(echo "$result" | grep -i "Ciphersuite:" | awk -F: '{print $2}' | xargs || echo "?")

    # Informacion del certificado
    cert_info=$(echo "Q" | timeout 5 openssl s_client -connect "${connect_addr}:${port}" 2>/dev/null || echo "")
    cert_subject=$(echo "$cert_info" | openssl x509 -noout -subject 2>/dev/null | sed 's/subject=//' || echo "?")
    cert_issuer=$(echo "$cert_info" | openssl x509 -noout -issuer 2>/dev/null | sed 's/issuer=//' || echo "?")
    cert_dates=$(echo "$cert_info" | openssl x509 -noout -dates 2>/dev/null || echo "?")
    cert_enddate=$(echo "$cert_dates" | grep "notAfter" | sed 's/notAfter=//' || echo "?")

    echo "  Protocolo:    $protocol"
    echo "  Cifrado:      $cipher"
    echo -e "  Subject:      ${DIM}$cert_subject${NC}"
    echo -e "  Issuer:       ${DIM}$cert_issuer${NC}"
    echo "  Expira:       $cert_enddate"

    # Alertas
    issues=0
    if echo "$protocol" | grep -qiE "TLSv1$|TLSv1\.0|TLSv1\.1|SSLv"; then
        echo -e "  ${RED}!! Protocolo obsoleto: $protocol${NC}"
        ((issues++))
    fi
    for weak_cipher in RC4 DES 3DES MD5 NULL EXPORT; do
        if echo "$cipher" | grep -qi "$weak_cipher"; then
            echo -e "  ${RED}!! Cifrado debil: $cipher${NC}"
            ((issues++))
            break
        fi
    done
    # Certificado auto-firmado
    if [[ "$cert_subject" == "$cert_issuer" ]]; then
        echo -e "  ${YELLOW}!! Certificado auto-firmado${NC}"
        ((issues++))
    fi
    # Certificado expirado
    if [[ "$cert_enddate" != "?" ]]; then
        endepoch=$(date -d "$cert_enddate" +%s 2>/dev/null || echo 0)
        now=$(date +%s)
        if [[ "$endepoch" -lt "$now" ]]; then
            echo -e "  ${RED}!! Certificado EXPIRADO${NC}"
            ((issues++))
        fi
    fi

    if [[ $issues -eq 0 ]]; then
        echo -e "  ${GREEN}OK${NC}  Sin problemas detectados"
    fi
    total_issues=$((total_issues + issues))

done < <(ss -tlnp 2>/dev/null | grep -v "^State")

echo ""
echo -e "${CYAN}── Resumen ──${NC}"
echo -e "  Servicios TLS escaneados: $total_scanned"
echo -e "  Problemas detectados:     $total_issues"
echo ""
echo -e "${BOLD}Escaneo completado: $(date)${NC}"
EOFTLS
    chmod +x /usr/local/bin/escanear-tls-local.sh
    log_change "Creado" "/usr/local/bin/escanear-tls-local.sh"
    log_change "Permisos" "/usr/local/bin/escanear-tls-local.sh -> +x"

    log_info "Script de escaneo TLS local creado"
else
    log_skip "Escaneo TLS de servicios locales"
fi

# ============================================================
# S8: AUDITORIA DE HASHING DE CONTRASENAS
# ============================================================
log_section "S8: AUDITORIA DE HASHING DE CONTRASENAS"

echo "Verifica que las contrasenas usan algoritmos seguros:"
echo "  - ENCRYPT_METHOD en /etc/login.defs (SHA512 o YESCRYPT)"
echo "  - PAM password hash algo (common-password / system-auth)"
echo "  - Escanea /etc/shadow buscando hashes debiles"
echo ""

if ask "¿Auditar hashing de contrasenas?"; then

    # Verificar ENCRYPT_METHOD en login.defs
    if [[ -f /etc/login.defs ]]; then
        encrypt_method=$(grep "^ENCRYPT_METHOD" /etc/login.defs 2>/dev/null | awk '{print $2}' || echo "no definido")
        log_info "ENCRYPT_METHOD en login.defs: $encrypt_method"

        case "$encrypt_method" in
            SHA512|YESCRYPT)
                log_info "Algoritmo de hashing seguro: $encrypt_method" ;;
            SHA256)
                log_warn "SHA256 es aceptable pero se recomienda SHA512 o YESCRYPT" ;;
            MD5|DES|"")
                log_warn "Algoritmo de hashing DEBIL o no definido: $encrypt_method" ;;
            *)
                log_info "Algoritmo: $encrypt_method (verificar manualmente)" ;;
        esac
    fi

    # Verificar PAM
    pam_file=""
    if [[ -f /etc/pam.d/common-password ]]; then
        pam_file="/etc/pam.d/common-password"
    elif [[ -f /etc/pam.d/system-auth ]]; then
        pam_file="/etc/pam.d/system-auth"
    elif [[ -f /etc/pam.d/system-auth-ac ]]; then
        pam_file="/etc/pam.d/system-auth-ac"
    fi

    if [[ -n "$pam_file" ]]; then
        log_info "Archivo PAM de password: $pam_file"
        pam_hash=$(grep "pam_unix.so" "$pam_file" 2>/dev/null | grep -oP '(sha512|sha256|yescrypt|md5|blowfish)' | head -1 || echo "no especificado")
        log_info "Hash en PAM: $pam_hash"
    fi

    # Escanear /etc/shadow
    echo ""
    log_info "Escaneando /etc/shadow en busca de hashes debiles..."
    weak_hash_count=0
    strong_hash_count=0
    no_pass_count=0

    while IFS=: read -r username hash_field _; do
        [[ -z "$hash_field" ]] && continue
        # Ignorar cuentas bloqueadas o sin password
        case "$hash_field" in
            "!"|"!!"|"*"|"!*")
                continue ;;
        esac

        case "$hash_field" in
            '$6$'*)
                # SHA-512 - seguro
                ((strong_hash_count++)) ;;
            '$y$'*)
                # yescrypt - seguro
                ((strong_hash_count++)) ;;
            '$5$'*)
                # SHA-256 - aceptable
                ((strong_hash_count++)) ;;
            '$1$'*)
                # MD5 - DEBIL
                echo -e "  ${RED}!!${NC}  $username: MD5 (\$1\$) - DEBIL"
                ((weak_hash_count++)) ;;
            '$2a$'*|'$2b$'*|'$2y$'*)
                # Blowfish/bcrypt - aceptable pero inusual en Linux
                echo -e "  ${YELLOW}!!${NC}  $username: Blowfish (\$2a\$/\$2b\$) - inusual en Linux"
                ((weak_hash_count++)) ;;
            *)
                # DES o desconocido
                if [[ ${#hash_field} -eq 13 ]]; then
                    echo -e "  ${RED}!!${NC}  $username: DES (sin prefijo) - MUY DEBIL"
                    ((weak_hash_count++))
                else
                    echo -e "  ${YELLOW}??${NC}  $username: formato desconocido"
                fi ;;
        esac
    done < /etc/shadow

    echo ""
    log_info "Hashes fuertes (SHA-512/yescrypt/SHA-256): $strong_hash_count"
    if [[ $weak_hash_count -gt 0 ]]; then
        log_warn "Hashes debiles encontrados: $weak_hash_count"
        log_warn "Las cuentas afectadas deben cambiar su contrasena"
    else
        log_info "No se encontraron hashes debiles"
    fi

    # Opcion de corregir login.defs
    if [[ "$encrypt_method" != "SHA512" ]] && [[ "$encrypt_method" != "YESCRYPT" ]]; then
        echo ""
        if ask "¿Establecer ENCRYPT_METHOD=SHA512 en /etc/login.defs?"; then
            cp /etc/login.defs "$BACKUP_DIR/login.defs.bak" 2>/dev/null || true
            if grep -q "^ENCRYPT_METHOD" /etc/login.defs; then
                sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD\tSHA512/' /etc/login.defs
            else
                echo -e "ENCRYPT_METHOD\tSHA512" >> /etc/login.defs
            fi
            log_change "Modificado" "/etc/login.defs -> ENCRYPT_METHOD=SHA512"
            log_info "ENCRYPT_METHOD establecido a SHA512"
        fi
    fi

    log_info "Auditoria de hashing completada"
else
    log_skip "Auditoria de hashing de contrasenas"
fi

# ============================================================
# S9: HARDENING CRIPTOGRAFICO DEL KERNEL
# ============================================================
log_section "S9: HARDENING CRIPTOGRAFICO DEL KERNEL"

echo "Endurece la configuracion criptografica del kernel:"
echo "  - Blacklist de modulos crypto debiles (des_generic, md4, md5)"
echo "  - Verifica modo FIPS"
echo "  - Lista modulos crypto cargados y detecta obsoletos"
echo ""

if ask "¿Aplicar hardening criptografico del kernel?"; then

    # Verificar modo FIPS
    if [[ -f /proc/sys/crypto/fips_enabled ]]; then
        fips=$(cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo "?")
        if [[ "$fips" == "1" ]]; then
            log_info "Modo FIPS: HABILITADO"
        else
            log_info "Modo FIPS: deshabilitado (fips_enabled=$fips)"
        fi
    else
        log_info "FIPS no disponible en este kernel"
    fi

    # Listar algoritmos crypto del kernel
    if [[ -f /proc/crypto ]]; then
        log_info "Algoritmos criptograficos del kernel:"
        algo_count=$(grep -c "^name" /proc/crypto 2>/dev/null || echo "0")
        log_info "  Total algoritmos registrados: $algo_count"

        # Buscar algoritmos obsoletos/debiles
        echo ""
        echo -e "${CYAN}── Algoritmos debiles en /proc/crypto ──${NC}"
        weak_algos=0
        for weak_name in "des" "md4" "md5" "rc4" "ecb(des)" "cbc(des)"; do
            if grep -q "name.*: ${weak_name}$" /proc/crypto 2>/dev/null; then
                echo -e "  ${YELLOW}!!${NC}  Algoritmo debil registrado: $weak_name"
                ((weak_algos++))
            fi
        done
        if [[ $weak_algos -eq 0 ]]; then
            echo -e "  ${GREEN}OK${NC}  No se detectaron algoritmos debiles activos"
        fi

        # Algoritmos modernos
        echo ""
        echo -e "${CYAN}── Algoritmos modernos disponibles ──${NC}"
        for modern_name in "aes" "chacha20" "sha256" "sha512" "poly1305" "gcm(aes)" "xts(aes)"; do
            if grep -q "name.*: ${modern_name}" /proc/crypto 2>/dev/null; then
                echo -e "  ${GREEN}OK${NC}  $modern_name"
            else
                echo -e "  ${YELLOW}--${NC}  $modern_name (no encontrado)"
            fi
        done
    fi

    # Listar modulos crypto cargados
    echo ""
    log_info "Modulos crypto del kernel cargados:"
    crypto_mods=0
    deprecated_mods=0
    while IFS= read -r mod; do
        [[ -z "$mod" ]] && continue
        # Verificar si es un modulo crypto
        mod_desc=$(modinfo "$mod" 2>/dev/null | grep "description:" | head -1 || echo "")
        if echo "$mod_desc" | grep -qi "crypt\|cipher\|hash\|aes\|sha\|des\|md5\|hmac"; then
            ((crypto_mods++))
            # Detectar modulos deprecados
            case "$mod" in
                des_generic|des3_ede|md4|md5|arc4|ecb|blowfish*|cast5*|cast6*|serpent*|twofish*)
                    echo -e "  ${YELLOW}!!${NC}  $mod - ${DIM}$mod_desc${NC}"
                    ((deprecated_mods++)) ;;
                *)
                    echo -e "  ${GREEN}OK${NC}  $mod" ;;
            esac
        fi
    done < <(lsmod | awk 'NR>1 {print $1}')
    log_info "Modulos crypto cargados: $crypto_mods (deprecados: $deprecated_mods)"

    # Crear blacklist de modulos crypto debiles
    cat > /etc/modprobe.d/securizar-crypto-blacklist.conf << 'EOF'
# ============================================================
# Blacklist de modulos crypto debiles - securizar
# ============================================================
# Estos modulos implementan algoritmos criptograficos obsoletos
# que no deben usarse en un sistema hardened.

# DES - clave de 56 bits, trivialmente rompible
install des_generic /bin/false

# MD4 - colisiones triviales, completamente roto
install md4 /bin/false

# MD5 - colisiones demostradas, no usar para seguridad
install md5 /bin/false

# RC4/ARC4 - multiples vulnerabilidades conocidas
install arc4 /bin/false

# Blowfish - reemplazado por AES
install blowfish_generic /bin/false
install blowfish_common /bin/false
EOF
    log_change "Creado" "/etc/modprobe.d/securizar-crypto-blacklist.conf"

    log_info "Hardening criptografico del kernel aplicado"
    log_warn "Los modulos blacklisted no se cargaran en el proximo arranque"
else
    log_skip "Hardening criptografico del kernel"
fi

# ============================================================
# S10: AUDITORIA CRIPTOGRAFICA COMPLETA
# ============================================================
log_section "S10: AUDITORIA CRIPTOGRAFICA COMPLETA"

echo "Crea script de auditoria criptografica integral:"
echo "  - SSH, TLS, certificados, entropia, LUKS, password hashing, kernel"
echo "  - Puntuacion: FUERTE / ACEPTABLE / DEBIL"
echo "  - Salida con colores e instalacion cron semanal"
echo ""

if ask "¿Crear sistema de auditoria criptografica completa?"; then

    cat > /usr/local/bin/auditoria-criptografica.sh << 'EOFAUDIT'
#!/bin/bash
# ============================================================
# Auditoria criptografica completa - securizar
# Ejecuta una revision integral de la postura criptografica
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

echo -e "${BOLD}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║       AUDITORIA CRIPTOGRAFICA COMPLETA                   ║${NC}"
echo -e "${BOLD}║       $(date)                  ║${NC}"
echo -e "${BOLD}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

score=0
max_score=0
issues=()

# ── 1. SSH ──────────────────────────────────────────────────
echo -e "${CYAN}══ 1. ALGORITMOS SSH ══${NC}"
((max_score += 20))

# Verificar claves host
ssh_score=0
if [[ -f /etc/ssh/ssh_host_ed25519_key ]]; then
    echo -e "  ${GREEN}OK${NC}  Clave Ed25519 presente"
    ((ssh_score += 5))
else
    echo -e "  ${RED}!!${NC}  Falta clave Ed25519"
    issues+=("SSH: falta clave Ed25519")
fi

if [[ -f /etc/ssh/ssh_host_dsa_key ]]; then
    echo -e "  ${RED}!!${NC}  Clave DSA presente (insegura)"
    issues+=("SSH: clave DSA presente")
else
    echo -e "  ${GREEN}OK${NC}  No hay clave DSA"
    ((ssh_score += 5))
fi

if [[ -f /etc/ssh/ssh_host_ecdsa_key ]]; then
    echo -e "  ${YELLOW}!!${NC}  Clave ECDSA presente (debatible)"
else
    echo -e "  ${GREEN}OK${NC}  No hay clave ECDSA"
    ((ssh_score += 5))
fi

# Verificar config hardened
if [[ -f /etc/ssh/sshd_config.d/99-securizar-crypto.conf ]]; then
    echo -e "  ${GREEN}OK${NC}  Configuracion crypto hardened presente"
    ((ssh_score += 5))
else
    echo -e "  ${YELLOW}!!${NC}  Sin configuracion crypto hardened"
    issues+=("SSH: sin config hardened en sshd_config.d")
fi

score=$((score + ssh_score))
echo -e "  ${DIM}Puntuacion SSH: $ssh_score/20${NC}"

# ── 2. TLS ──────────────────────────────────────────────────
echo ""
echo -e "${CYAN}══ 2. CONFIGURACION TLS ══${NC}"
((max_score += 15))
tls_score=0

if [[ -f /etc/ssl/openssl-securizar.cnf ]]; then
    echo -e "  ${GREEN}OK${NC}  OpenSSL hardened config presente"
    ((tls_score += 5))
else
    echo -e "  ${YELLOW}!!${NC}  Sin config OpenSSL hardened"
    issues+=("TLS: sin openssl-securizar.cnf")
fi

if command -v update-crypto-policies &>/dev/null; then
    policy=$(update-crypto-policies --show 2>/dev/null || echo "?")
    if [[ "$policy" == "FUTURE" ]]; then
        echo -e "  ${GREEN}OK${NC}  Crypto-policy: FUTURE"
        ((tls_score += 5))
    elif [[ "$policy" == "FIPS" ]]; then
        echo -e "  ${GREEN}OK${NC}  Crypto-policy: FIPS"
        ((tls_score += 5))
    else
        echo -e "  ${YELLOW}!!${NC}  Crypto-policy: $policy (recomendado: FUTURE)"
        issues+=("TLS: crypto-policy no es FUTURE")
    fi
else
    ((tls_score += 5))  # No aplica
fi

openssl_ver=$(openssl version 2>/dev/null || echo "no instalado")
echo -e "  ${DIM}OpenSSL: $openssl_ver${NC}"
if echo "$openssl_ver" | grep -qP "1\.[01]\."; then
    echo -e "  ${RED}!!${NC}  Version de OpenSSL obsoleta"
    issues+=("TLS: OpenSSL version obsoleta")
else
    ((tls_score += 5))
fi

score=$((score + tls_score))
echo -e "  ${DIM}Puntuacion TLS: $tls_score/15${NC}"

# ── 3. Certificados ─────────────────────────────────────────
echo ""
echo -e "${CYAN}══ 3. CERTIFICADOS ══${NC}"
((max_score += 10))
cert_score=10
cert_issues=0

for dir in /etc/ssl /etc/pki; do
    [[ -d "$dir" ]] || continue
    while IFS= read -r -d '' cf; do
        if openssl x509 -in "$cf" -noout -checkend 0 2>/dev/null; then
            : # No expirado
        else
            if openssl x509 -in "$cf" -noout 2>/dev/null; then
                echo -e "  ${RED}!!${NC}  Expirado: $cf"
                ((cert_issues++))
            fi
        fi
    done < <(find "$dir" -type f \( -name "*.pem" -o -name "*.crt" \) -print0 2>/dev/null)
done

if [[ $cert_issues -gt 0 ]]; then
    cert_score=$((cert_score - cert_issues * 2))
    [[ $cert_score -lt 0 ]] && cert_score=0
    issues+=("Certificados: $cert_issues expirados")
else
    echo -e "  ${GREEN}OK${NC}  Sin certificados expirados detectados"
fi

score=$((score + cert_score))
echo -e "  ${DIM}Puntuacion certificados: $cert_score/10${NC}"

# ── 4. Entropia ─────────────────────────────────────────────
echo ""
echo -e "${CYAN}══ 4. ENTROPIA ══${NC}"
((max_score += 10))
ent_score=0

entropy=$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null || echo 0)
echo -e "  Entropia disponible: ${BOLD}$entropy${NC} bits"
if [[ "$entropy" -ge 256 ]]; then
    echo -e "  ${GREEN}OK${NC}  Entropia adecuada"
    ((ent_score += 10))
elif [[ "$entropy" -ge 100 ]]; then
    echo -e "  ${YELLOW}!!${NC}  Entropia baja"
    ((ent_score += 5))
    issues+=("Entropia: baja ($entropy bits)")
else
    echo -e "  ${RED}!!${NC}  Entropia critica"
    issues+=("Entropia: critica ($entropy bits)")
fi

score=$((score + ent_score))
echo -e "  ${DIM}Puntuacion entropia: $ent_score/10${NC}"

# ── 5. LUKS ─────────────────────────────────────────────────
echo ""
echo -e "${CYAN}══ 5. CIFRADO DE DISCO ══${NC}"
((max_score += 15))
luks_score=0

if command -v cryptsetup &>/dev/null; then
    luks_found=0
    while IFS= read -r dev; do
        [[ -z "$dev" ]] && continue
        if cryptsetup isLuks "$dev" 2>/dev/null; then
            ((luks_found++))
            dump=$(cryptsetup luksDump "$dev" 2>/dev/null)
            mode=$(echo "$dump" | grep "Cipher mode:" | head -1 | awk -F: '{print $2}' | xargs)
            keysize=$(echo "$dump" | grep "MK bits:" | head -1 | awk '{print $3}')
            echo -e "  ${GREEN}OK${NC}  $dev (LUKS, ${keysize}b, $mode)"
            ((luks_score += 5))
            if echo "$mode" | grep -qi "cbc"; then
                issues+=("LUKS: $dev usa CBC")
                ((luks_score -= 2))
            fi
        fi
    done < <(lsblk -dpno NAME 2>/dev/null)
    if [[ $luks_found -eq 0 ]]; then
        echo -e "  ${YELLOW}!!${NC}  No hay volumenes LUKS"
        issues+=("LUKS: no hay cifrado de disco")
    fi
    [[ $luks_score -gt 15 ]] && luks_score=15
else
    echo -e "  ${YELLOW}!!${NC}  cryptsetup no instalado"
    issues+=("LUKS: cryptsetup no instalado")
fi

score=$((score + luks_score))
echo -e "  ${DIM}Puntuacion LUKS: $luks_score/15${NC}"

# ── 6. Password Hashing ────────────────────────────────────
echo ""
echo -e "${CYAN}══ 6. HASHING DE CONTRASENAS ══${NC}"
((max_score += 15))
hash_score=0

if [[ -f /etc/login.defs ]]; then
    enc=$(grep "^ENCRYPT_METHOD" /etc/login.defs 2>/dev/null | awk '{print $2}')
    case "$enc" in
        SHA512|YESCRYPT) echo -e "  ${GREEN}OK${NC}  ENCRYPT_METHOD=$enc"; ((hash_score += 10)) ;;
        SHA256) echo -e "  ${YELLOW}!!${NC}  ENCRYPT_METHOD=$enc (aceptable)"; ((hash_score += 5)) ;;
        *) echo -e "  ${RED}!!${NC}  ENCRYPT_METHOD=$enc (debil)"; issues+=("Hash: ENCRYPT_METHOD=$enc") ;;
    esac
fi

# Verificar shadow
weak_in_shadow=0
while IFS=: read -r user hf _; do
    case "$hf" in
        '!'*|'!!'|'*'|'') continue ;;
        '$1$'*) ((weak_in_shadow++)) ;;
        '$2'*) ((weak_in_shadow++)) ;;
    esac
    # DES (13 chars, no prefix)
    if [[ ${#hf} -eq 13 ]] && [[ "$hf" != '!'* ]]; then
        ((weak_in_shadow++))
    fi
done < /etc/shadow 2>/dev/null

if [[ $weak_in_shadow -eq 0 ]]; then
    echo -e "  ${GREEN}OK${NC}  Sin hashes debiles en /etc/shadow"
    ((hash_score += 5))
else
    echo -e "  ${RED}!!${NC}  $weak_in_shadow cuentas con hash debil"
    issues+=("Hash: $weak_in_shadow cuentas con hash debil")
fi

score=$((score + hash_score))
echo -e "  ${DIM}Puntuacion hashing: $hash_score/15${NC}"

# ── 7. Kernel Crypto ────────────────────────────────────────
echo ""
echo -e "${CYAN}══ 7. KERNEL CRYPTO ══${NC}"
((max_score += 15))
kern_score=0

# FIPS
if [[ -f /proc/sys/crypto/fips_enabled ]]; then
    fips=$(cat /proc/sys/crypto/fips_enabled)
    if [[ "$fips" == "1" ]]; then
        echo -e "  ${GREEN}OK${NC}  Modo FIPS habilitado"
        ((kern_score += 5))
    else
        echo -e "  ${DIM}--${NC}  Modo FIPS no habilitado"
    fi
fi

# Blacklist de modulos debiles
if [[ -f /etc/modprobe.d/securizar-crypto-blacklist.conf ]]; then
    echo -e "  ${GREEN}OK${NC}  Blacklist crypto activa"
    ((kern_score += 5))
else
    echo -e "  ${YELLOW}!!${NC}  Sin blacklist de modulos crypto debiles"
    issues+=("Kernel: sin blacklist crypto")
fi

# Algoritmos modernos en /proc/crypto
if [[ -f /proc/crypto ]]; then
    modern_count=0
    for alg in aes chacha20 sha256 sha512; do
        grep -q "name.*: ${alg}" /proc/crypto 2>/dev/null && ((modern_count++))
    done
    if [[ $modern_count -ge 3 ]]; then
        echo -e "  ${GREEN}OK${NC}  Algoritmos modernos disponibles ($modern_count/4)"
        ((kern_score += 5))
    else
        echo -e "  ${YELLOW}!!${NC}  Pocos algoritmos modernos ($modern_count/4)"
    fi
fi

score=$((score + kern_score))
echo -e "  ${DIM}Puntuacion kernel: $kern_score/15${NC}"

# ── RESULTADO FINAL ─────────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════════════════════════════${NC}"
pct=0
if [[ $max_score -gt 0 ]]; then
    pct=$(( (score * 100) / max_score ))
fi

if [[ $pct -ge 80 ]]; then
    nivel="FUERTE"
    nivel_color="$GREEN"
elif [[ $pct -ge 50 ]]; then
    nivel="ACEPTABLE"
    nivel_color="$YELLOW"
else
    nivel="DEBIL"
    nivel_color="$RED"
fi

echo -e "  Puntuacion: ${BOLD}$score / $max_score${NC} ($pct%)"
echo -e "  Nivel:      ${nivel_color}${BOLD}$nivel${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"

# Lista de problemas
if [[ ${#issues[@]} -gt 0 ]]; then
    echo ""
    echo -e "${CYAN}── Problemas detectados (${#issues[@]}) ──${NC}"
    for issue in "${issues[@]}"; do
        echo -e "  ${RED}*${NC}  $issue"
    done
fi

echo ""
echo -e "${BOLD}Auditoria completada: $(date)${NC}"
echo ""
EOFAUDIT
    chmod +x /usr/local/bin/auditoria-criptografica.sh
    log_change "Creado" "/usr/local/bin/auditoria-criptografica.sh"
    log_change "Permisos" "/usr/local/bin/auditoria-criptografica.sh -> +x"

    # Instalar cron semanal
    cat > /etc/cron.weekly/auditoria-criptografica << 'EOFCRON'
#!/bin/bash
# Auditoria criptografica semanal - securizar
/usr/local/bin/auditoria-criptografica.sh > /var/log/securizar-auditoria-crypto.log 2>&1
EOFCRON
    chmod +x /etc/cron.weekly/auditoria-criptografica
    log_change "Creado" "/etc/cron.weekly/auditoria-criptografica"

    log_info "Sistema de auditoria criptografica completa instalado"
    log_info "Ejecuta: auditoria-criptografica.sh"
else
    log_skip "Auditoria criptografica completa"
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
show_changes_summary
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║       HARDENING CRIPTOGRAFICO COMPLETADO                  ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups guardados en: $BACKUP_DIR"
echo ""
echo "Comandos utiles post-hardening:"
echo "  - Auditar SSH:           auditar-ssh-crypto.sh"
echo "  - Monitor certificados:  monitorizar-certificados.sh"
echo "  - Verificar entropia:    verificar-entropia.sh"
echo "  - Auditar LUKS:          auditar-luks.sh"
echo "  - Escanear TLS local:    escanear-tls-local.sh"
echo "  - Auditoria completa:    auditoria-criptografica.sh"
echo ""
log_warn "RECOMENDACION: Ejecuta 'auditoria-criptografica.sh' para ver la postura actual"
echo ""
