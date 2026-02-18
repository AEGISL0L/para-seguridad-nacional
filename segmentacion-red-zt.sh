#!/bin/bash
# ============================================================
# segmentacion-red-zt.sh - Módulo 45: Segmentación de red y Zero Trust
# ============================================================
# Implementa segmentación de red basada en zonas, políticas inter-zona,
# microsegmentación por servicio, aislamiento de contenedores,
# evaluación de postura de dispositivos (Zero Trust), control de
# acceso basado en identidad, monitorización de tráfico y auditoría.
#
# Secciones:
#   S1  - Zonas de red con nftables
#   S2  - Políticas inter-zona
#   S3  - Microsegmentación por servicio
#   S4  - Aislamiento de red para contenedores
#   S5  - Device posture assessment (Zero Trust)
#   S6  - Identity-based access control
#   S7  - Traffic monitoring & anomaly detection
#   S8  - Network validation
#   S9  - Zero Trust continuous verification
#   S10 - Auditoría y scoring
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps
init_backup "segmentacion-red-zt"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MÓDULO 45 - SEGMENTACIÓN DE RED Y ZERO TRUST           ║"
echo "║   Zonas, políticas inter-zona, microsegmentación,        ║"
echo "║   aislamiento contenedores, postura ZT, identidad        ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

log_section "MÓDULO 45: SEGMENTACIÓN DE RED Y ZERO TRUST"
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

# ── Pre-check rapido ────────────────────────────────────
_precheck 10
_pc check_file_exists /etc/securizar/zonas-red.conf
_pc check_executable /usr/local/bin/aplicar-politicas-zona.sh
_pc check_executable /usr/local/bin/microsegmentar-servicio.sh
_pc check_executable /usr/local/bin/aislar-contenedores-red.sh
_pc check_executable /usr/local/bin/evaluar-postura-dispositivo.sh
_pc check_executable /usr/local/bin/aplicar-acceso-identidad.sh
_pc check_executable /usr/local/bin/monitorizar-trafico-zonas.sh
_pc check_executable /usr/local/bin/validar-segmentacion.sh
_pc check_executable /usr/local/bin/verificar-zt-continuo.sh
_pc check_executable /usr/local/bin/auditoria-segmentacion-zt.sh
_precheck_result

# Directorios base
mkdir -p /etc/securizar /var/log/securizar /etc/nftables.d /usr/local/bin

# ============================================================
# S1: ZONAS DE RED CON NFTABLES
# ============================================================
log_section "S1: ZONAS DE RED CON NFTABLES"

echo "Configura zonas de red con nftables:"
echo "  - Define 4 zonas: TRUSTED, INTERNAL, DMZ, RESTRICTED"
echo "  - Asigna CIDRs a cada zona"
echo "  - Crea estructura de cadenas nftables por zona"
echo "  - Instala nftables si no está disponible"
echo ""

if check_file_exists /etc/securizar/zonas-red.conf; then
    log_already "Zonas de red (zonas-red.conf existe)"
elif ask "¿Configurar zonas de red con nftables?"; then

    # Instalar nftables si no está disponible
    if ! command -v nft &>/dev/null; then
        log_info "Instalando nftables..."
        pkg_install nftables || log_warn "No se pudo instalar nftables"
    fi

    if command -v nft &>/dev/null; then
        # Crear configuración de zonas
        log_info "Creando configuración de zonas de red..."

        if [[ -f /etc/securizar/zonas-red.conf ]]; then
            cp /etc/securizar/zonas-red.conf "$BACKUP_DIR/" 2>/dev/null || true
            log_change "Backup" "/etc/securizar/zonas-red.conf"
        fi

        cat > /etc/securizar/zonas-red.conf << 'ZONASEOF'
# ============================================================
# zonas-red.conf - Definición de zonas de red
# Generado por securizar - Módulo 45
# ============================================================
# Formato: ZONA|CIDR|INTERFAZ|DESCRIPCION
# Modificar CIDRs según la topología de red real
# ============================================================

# TRUSTED: Redes de administración y gestión
TRUSTED|10.0.1.0/24|eth0|Red de administración
TRUSTED|10.0.2.0/24|eth0|Red de gestión

# INTERNAL: Redes de usuarios y estaciones de trabajo
INTERNAL|10.0.10.0/24|eth1|Red de usuarios
INTERNAL|10.0.11.0/24|eth1|Red de estaciones de trabajo
INTERNAL|192.168.1.0/24|eth1|Red interna legacy

# DMZ: Servicios expuestos (web, correo, DNS público)
DMZ|10.0.100.0/24|eth2|DMZ servicios web
DMZ|10.0.101.0/24|eth2|DMZ correo y DNS

# RESTRICTED: Bases de datos, secretos, backups
RESTRICTED|10.0.200.0/24|eth3|Bases de datos
RESTRICTED|10.0.201.0/24|eth3|Almacenamiento de secretos
RESTRICTED|10.0.202.0/24|eth3|Red de backups
ZONASEOF
        chmod 0640 /etc/securizar/zonas-red.conf
        log_change "Creado" "/etc/securizar/zonas-red.conf (4 zonas de red)"

        # Crear estructura nftables para zonas
        log_info "Creando reglas nftables por zona..."

        if [[ -f /etc/nftables.d/securizar-zonas.nft ]]; then
            cp /etc/nftables.d/securizar-zonas.nft "$BACKUP_DIR/" 2>/dev/null || true
            log_change "Backup" "/etc/nftables.d/securizar-zonas.nft"
        fi

        cat > /etc/nftables.d/securizar-zonas.nft << 'NFTEOF'
#!/usr/sbin/nft -f
# ============================================================
# securizar-zonas.nft - Reglas nftables por zona de red
# Generado por securizar - Módulo 45
# ============================================================
# Cargar con: nft -f /etc/nftables.d/securizar-zonas.nft
# Poblar blocklist: nft add element inet securizar_zonas blocklist_ips { 1.2.3.4 }
# Poblar blocklist: nft add element inet securizar_zonas blocklist_nets { 198.18.0.0/15 }
# ============================================================

# Idempotente: crear si no existe, borrar, recrear limpio
table inet securizar_zonas
delete table inet securizar_zonas

table inet securizar_zonas {

    # --- Sets de zonas ---
    set trusted_nets {
        type ipv4_addr
        flags interval
        elements = { 10.0.1.0/24, 10.0.2.0/24 }
    }

    set internal_nets {
        type ipv4_addr
        flags interval
        elements = { 10.0.10.0/24, 10.0.11.0/24, 192.168.1.0/24 }
    }

    set dmz_nets {
        type ipv4_addr
        flags interval
        elements = { 10.0.100.0/24, 10.0.101.0/24 }
    }

    set restricted_nets {
        type ipv4_addr
        flags interval
        elements = { 10.0.200.0/24, 10.0.201.0/24, 10.0.202.0/24 }
    }

    # --- Sets defensivos ---
    set bogon_nets {
        type ipv4_addr
        flags interval
        elements = {
            0.0.0.0/8,
            169.254.0.0/16,
            192.0.0.0/24,
            192.0.2.0/24,
            198.51.100.0/24,
            203.0.113.0/24,
            224.0.0.0/4,
            240.0.0.0/4
        }
    }

    set blocklist_ips {
        type ipv4_addr
        flags timeout
        timeout 24h
    }

    set blocklist_nets {
        type ipv4_addr
        flags interval,timeout
        timeout 24h
    }

    set port_scanners {
        type ipv4_addr
        flags dynamic,timeout
        timeout 5m
        size 65535
    }

    set ssh_bruteforce {
        type ipv4_addr
        flags dynamic,timeout
        timeout 10m
        size 65535
    }

    # --- Anti-spoofing (prerouting, raw priority) ---
    chain antispoof {
        type filter hook prerouting priority -300; policy accept;

        # Descartar direcciones origen que nunca son legítimas
        ip saddr @bogon_nets counter drop

        # Descartar loopback fuera de interfaz lo
        iif != lo ip saddr 127.0.0.0/8 counter drop

        # Descartar broadcast como origen
        ip saddr 255.255.255.255 counter drop
    }

    # --- Filtro IPv6 (defensa en profundidad - IPv6 deshabilitado vía sysctl) ---
    chain ipv6_filter {
        # Permitir IPv6 en loopback
        iif lo accept

        # Permitir NDP link-local (necesario en algunos kernels)
        ip6 saddr fe80::/10 icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, nd-redirect } accept

        # Descartar el resto de IPv6
        counter drop
    }

    # --- Filtro ICMP ---
    chain icmp_filter {
        # Tipos esenciales: PMTUD, traceroute, respuestas
        icmp type { destination-unreachable, time-exceeded, echo-reply, parameter-problem } accept

        # Ping con rate limit
        icmp type echo-request limit rate 5/second burst 10 packets accept

        # Descartar el resto (redirect, source-quench, timestamp, etc.)
        counter drop
    }

    # --- Protección SYN flood ---
    chain syn_flood_protect {
        limit rate 25/second burst 50 packets return
        counter drop
    }

    # --- Cadena de clasificación por zona (input) ---
    chain zona_input {
        type filter hook input priority -10; policy accept;

        # Tráfico loopback siempre permitido
        iif lo accept

        # Filtro IPv6 (defensa en profundidad)
        meta nfproto ipv6 jump ipv6_filter

        # Blocklist - bloquear IPs maliciosas incluso en conexiones activas
        ip saddr @blocklist_ips counter drop
        ip saddr @blocklist_nets counter drop

        # Conexiones establecidas
        ct state established,related accept

        # Descartar estado inválido
        ct state invalid counter drop

        # Bloquear escáneres de puertos detectados
        ip saddr @port_scanners counter drop

        # Filtro ICMP
        ip protocol icmp jump icmp_filter

        # Protección SYN flood (solo SYN nuevos)
        tcp flags & (fin | syn | rst | ack) == syn ct state new jump syn_flood_protect

        # Clasificar por zona de origen
        ip saddr @trusted_nets jump trusted_input
        ip saddr @internal_nets jump internal_input
        ip saddr @dmz_nets jump dmz_input
        ip saddr @restricted_nets jump restricted_input

        # Tráfico no clasificado: log con rate limit
        limit rate 10/minute log prefix "securizar-zonas-noclasif: " level warn
        counter drop
    }

    chain zona_forward {
        type filter hook forward priority -10; policy drop;

        # Blocklist (origen y destino)
        ip saddr @blocklist_ips counter drop
        ip daddr @blocklist_ips counter drop
        ip saddr @blocklist_nets counter drop
        ip daddr @blocklist_nets counter drop

        # Bloquear acceso saliente al admin del router
        ip daddr 192.168.1.1 tcp dport { 80, 443, 8080 } counter log prefix "ROUTER-ADMIN-BLOCK: " reject with icmp port-unreachable
        ip daddr 192.168.1.1 tcp dport 53 counter log prefix "ROUTER-DNS-BLOCK: " drop
        ip daddr 192.168.1.1 udp dport 53 counter log prefix "ROUTER-DNS-BLOCK: " drop

        # Conexiones establecidas
        ct state established,related accept

        # Descartar estado inválido
        ct state invalid counter drop

        # Políticas inter-zona dinámicas (gestionadas por aplicar-politicas-zona.sh)
        jump politicas_forward

        # Clasificar tráfico inter-zona
        ip saddr @trusted_nets jump trusted_forward
        ip saddr @internal_nets jump internal_forward
        ip saddr @dmz_nets jump dmz_forward
        ip saddr @restricted_nets jump restricted_forward

        # Denegar no clasificado con log rate-limited
        limit rate 10/minute log prefix "securizar-zonas-fwd-deny: " level warn
        counter drop
    }

    # --- Cadenas por zona (input) ---
    chain trusted_input {
        # TRUSTED puede acceder a todo
        counter accept
    }

    chain internal_input {
        # SSH con rate limit per-IP (5/min burst 3, bloqueo 10min)
        tcp dport 22 ct state new add @ssh_bruteforce { ip saddr limit rate over 5/minute burst 3 packets } counter drop
        tcp dport 22 counter accept

        # INTERNAL: servicios permitidos
        tcp dport { 80, 443, 53 } counter accept
        udp dport { 53, 123 } counter accept

        # Detección de escáneres + log rate-limited + drop
        limit rate 10/minute log prefix "securizar-internal-deny: " level info
        update @port_scanners { ip saddr } counter drop
    }

    chain dmz_input {
        # DMZ: acceso limitado al host
        tcp dport { 80, 443 } counter accept

        # Detección de escáneres + log rate-limited + drop
        limit rate 10/minute log prefix "securizar-dmz-deny: " level info
        update @port_scanners { ip saddr } counter drop
    }

    chain restricted_input {
        # RESTRICTED: sin acceso directo
        limit rate 10/minute log prefix "securizar-restricted-deny: " level warn
        counter drop
    }

    # --- Cadenas por zona (forward) ---
    chain trusted_forward {
        # TRUSTED puede reenviar a cualquier zona
        counter accept
    }

    chain internal_forward {
        # INTERNAL solo puede llegar a DMZ (http/https)
        ip daddr @dmz_nets tcp dport { 80, 443 } counter accept
        limit rate 10/minute log prefix "securizar-int-fwd-deny: " level info
        counter drop
    }

    chain dmz_forward {
        # DMZ NO puede llegar a RESTRICTED
        ip daddr @restricted_nets limit rate 10/minute log prefix "securizar-dmz-restricted-block: " level warn
        ip daddr @restricted_nets counter drop
        # DMZ no puede llegar a TRUSTED ni INTERNAL
        ip daddr @trusted_nets counter drop
        ip daddr @internal_nets counter drop
    }

    chain restricted_forward {
        # RESTRICTED no reenvía a ningún lado
        limit rate 10/minute log prefix "securizar-restricted-fwd-deny: " level warn
        counter drop
    }

    # --- Cadena de políticas dinámicas (flush-safe) ---
    chain politicas_forward {
        # Poblada por aplicar-politicas-zona.sh
        # Se puede hacer flush sin afectar reglas base de zona_forward
    }

    # --- Cadena de salida (egress visibility) ---
    chain zona_output {
        type filter hook output priority -10; policy accept;

        # Loopback
        oif lo accept

        # Conexiones establecidas
        ct state established,related accept

        # Blocklist egress - no conectar a IPs maliciosas conocidas
        ip daddr @blocklist_ips counter drop
        ip daddr @blocklist_nets counter drop

        # Bloquear acceso saliente al admin del router
        ip daddr 192.168.1.1 tcp dport { 80, 443, 8080 } counter log prefix "ROUTER-ADMIN-BLOCK: " reject with icmp port-unreachable
        ip daddr 192.168.1.1 tcp dport 53 counter log prefix "ROUTER-DNS-BLOCK: " drop
        ip daddr 192.168.1.1 udp dport 53 counter log prefix "ROUTER-DNS-BLOCK: " drop

        # Tráfico saliente común (silencioso)
        tcp dport { 22, 53, 80, 443 } accept
        udp dport { 53, 123 } accept
        ip protocol icmp accept

        # Tráfico saliente no común: log para visibilidad
        limit rate 10/minute log prefix "securizar-zonas-egress: " level info
    }
}
NFTEOF
        chmod 0640 /etc/nftables.d/securizar-zonas.nft
        log_change "Creado" "/etc/nftables.d/securizar-zonas.nft (estructura de zonas nftables)"

        # Intentar cargar las reglas
        if nft -c -f /etc/nftables.d/securizar-zonas.nft 2>/dev/null; then
            log_info "Reglas nftables validadas correctamente"
            if ask "¿Cargar reglas de zonas en nftables ahora?"; then
                nft -f /etc/nftables.d/securizar-zonas.nft || log_warn "Error al cargar reglas nftables"
                log_change "Aplicado" "reglas nftables de zonas cargadas"
            else
                log_skip "Carga inmediata de reglas nftables"
            fi
        else
            log_warn "Las reglas nftables no pasaron validación - revisar manualmente"
        fi

        # Habilitar nftables en el arranque
        if systemctl is-enabled nftables &>/dev/null 2>&1; then
            log_info "nftables ya está habilitado en el arranque"
        else
            if ask "¿Habilitar nftables en el arranque?"; then
                systemctl enable nftables 2>/dev/null || log_warn "No se pudo habilitar nftables"
                log_change "Habilitado" "nftables en el arranque"
            else
                log_skip "Habilitar nftables en arranque"
            fi
        fi

        # Ajustar sysctl ICMP: delegar control a nftables icmp_filter
        # (icmp_echo_ignore_all=1 bloquea echo-request antes de nftables)
        if [[ "$(sysctl -n net.ipv4.icmp_echo_ignore_all 2>/dev/null)" == "1" ]]; then
            sysctl -w net.ipv4.icmp_echo_ignore_all=0 &>/dev/null || true
            # Persistir override (mayor prioridad que 99-paranoid-max.conf)
            cat > /etc/sysctl.d/99-securizar-zonas.conf << 'SYSCTLEOF'
# Override ICMP: nftables icmp_filter gestiona echo-request con rate-limit
# Desactiva bloqueo total del kernel para que nftables tenga control granular
net.ipv4.icmp_echo_ignore_all = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
SYSCTLEOF
            log_change "Ajustado" "sysctl icmp_echo_ignore_all=0 (delegado a nftables icmp_filter)"
        fi

        log_info "Zonas de red configuradas: TRUSTED, INTERNAL, DMZ, RESTRICTED"
    else
        log_warn "nftables no disponible - no se pueden crear zonas"
    fi
else
    log_skip "Zonas de red con nftables"
fi

# ============================================================
# S2: POLÍTICAS INTER-ZONA
# ============================================================
log_section "S2: POLÍTICAS INTER-ZONA"

echo "Define políticas de comunicación entre zonas:"
echo "  - Default-deny entre todas las zonas"
echo "  - Matriz de políticas: TRUSTED->all, INTERNAL->DMZ(http/https)"
echo "  - DMZ->RESTRICTED(deny), RESTRICTED->ninguno"
echo "  - Script de aplicación de políticas"
echo ""

if check_executable /usr/local/bin/aplicar-politicas-zona.sh; then
    log_already "Politicas inter-zona (aplicar-politicas-zona.sh existe)"
elif ask "¿Configurar políticas inter-zona?"; then

    # Crear fichero de políticas inter-zona
    log_info "Creando matriz de políticas inter-zona..."

    if [[ -f /etc/securizar/politicas-interzona.conf ]]; then
        cp /etc/securizar/politicas-interzona.conf "$BACKUP_DIR/" 2>/dev/null || true
        log_change "Backup" "/etc/securizar/politicas-interzona.conf"
    fi

    cat > /etc/securizar/politicas-interzona.conf << 'POLEOF'
# ============================================================
# politicas-interzona.conf - Matriz de políticas entre zonas
# Generado por securizar - Módulo 45
# ============================================================
# Formato: ORIGEN|DESTINO|ACCION|PUERTOS|PROTOCOLO|DESCRIPCION
# ACCION: allow, deny, log-deny, rate-limit
# PUERTOS: all, o lista separada por comas (80,443)
# PROTOCOLO: tcp, udp, any
# ============================================================

# --- Política por defecto: DENY ---
DEFAULT|DEFAULT|deny|all|any|Denegación por defecto entre zonas

# --- TRUSTED -> todo permitido ---
TRUSTED|INTERNAL|allow|all|any|Admin puede acceder a red interna
TRUSTED|DMZ|allow|all|any|Admin puede acceder a DMZ
TRUSTED|RESTRICTED|allow|all|any|Admin puede acceder a zona restringida

# --- INTERNAL -> DMZ (solo web) ---
INTERNAL|DMZ|allow|80,443|tcp|Usuarios pueden acceder a servicios web DMZ
INTERNAL|DMZ|allow|53|udp|Usuarios pueden consultar DNS en DMZ
INTERNAL|TRUSTED|deny|all|any|Usuarios no pueden acceder a red de admin
INTERNAL|RESTRICTED|deny|all|any|Usuarios no pueden acceder a zona restringida

# --- DMZ -> limitado ---
DMZ|TRUSTED|deny|all|any|DMZ no puede acceder a admin
DMZ|INTERNAL|deny|all|any|DMZ no puede acceder a red interna
DMZ|RESTRICTED|deny|all|any|DMZ no puede acceder a zona restringida
DMZ|INTERNET|allow|80,443|tcp|DMZ puede salir a internet para actualizaciones

# --- RESTRICTED -> aislado ---
RESTRICTED|TRUSTED|log-deny|all|any|Restringida no puede contactar admin (log)
RESTRICTED|INTERNAL|deny|all|any|Restringida no puede contactar usuarios
RESTRICTED|DMZ|deny|all|any|Restringida no puede contactar DMZ
RESTRICTED|INTERNET|deny|all|any|Restringida sin acceso a internet
POLEOF
    chmod 0640 /etc/securizar/politicas-interzona.conf
    log_change "Creado" "/etc/securizar/politicas-interzona.conf (matriz de políticas)"

    # Script de aplicación de políticas
    log_info "Creando script de aplicación de políticas..."

    cat > /usr/local/bin/aplicar-politicas-zona.sh << 'APLICAREOF'
#!/bin/bash
# ============================================================
# aplicar-politicas-zona.sh - Aplica políticas inter-zona
# Generado por securizar - Módulo 45
# ============================================================
set -uo pipefail

CONF="/etc/securizar/politicas-interzona.conf"
ZONAS_CONF="/etc/securizar/zonas-red.conf"
LOG="/var/log/securizar/politicas-zona.log"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG"; }

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Ejecutar como root" >&2
    exit 1
fi

if [[ ! -f "$CONF" ]]; then
    echo "ERROR: No existe $CONF" >&2
    exit 1
fi

if ! command -v nft &>/dev/null; then
    echo "ERROR: nftables no disponible" >&2
    exit 1
fi

mkdir -p /var/log/securizar

log "=== Aplicando políticas inter-zona ==="

# Función: resolver CIDR de zona
resolver_zona_cidrs() {
    local zona="$1"
    local cidrs=()
    while IFS='|' read -r z cidr iface desc; do
        [[ "$z" == "$zona" ]] && cidrs+=("$cidr")
    done < <(grep -v '^#' "$ZONAS_CONF" | grep -v '^$')
    echo "${cidrs[*]}"
}

# Leer políticas y generar reglas
politicas_aplicadas=0
politicas_error=0

while IFS='|' read -r origen destino accion puertos protocolo descripcion; do
    # Saltar comentarios, vacías y default
    [[ "$origen" =~ ^# ]] && continue
    [[ -z "$origen" ]] && continue
    [[ "$origen" == "DEFAULT" ]] && continue

    log "Política: $origen -> $destino [$accion] puertos=$puertos proto=$protocolo"

    # Resolver CIDRs
    cidrs_origen=$(resolver_zona_cidrs "$origen")
    cidrs_destino=$(resolver_zona_cidrs "$destino")

    # Si destino es INTERNET, no aplicar regla nft específica
    if [[ "$destino" == "INTERNET" ]]; then
        log "  -> Destino INTERNET: política informativa (gestionada por gateway)"
        continue
    fi

    if [[ -z "$cidrs_origen" || -z "$cidrs_destino" ]]; then
        log "  -> AVISO: No se resolvieron CIDRs para $origen/$destino"
        ((politicas_error++)) || true
        continue
    fi

    # Aplicar regla
    for src_cidr in $cidrs_origen; do
        for dst_cidr in $cidrs_destino; do
            case "$accion" in
                allow)
                    if [[ "$puertos" == "all" ]]; then
                        nft add rule inet securizar_zonas zona_forward \
                            ip saddr "$src_cidr" ip daddr "$dst_cidr" accept 2>/dev/null || true
                    else
                        for port in ${puertos//,/ }; do
                            nft add rule inet securizar_zonas zona_forward \
                                ip saddr "$src_cidr" ip daddr "$dst_cidr" \
                                "$protocolo" dport "$port" accept 2>/dev/null || true
                        done
                    fi
                    ;;
                deny)
                    nft add rule inet securizar_zonas zona_forward \
                        ip saddr "$src_cidr" ip daddr "$dst_cidr" drop 2>/dev/null || true
                    ;;
                log-deny)
                    nft add rule inet securizar_zonas zona_forward \
                        ip saddr "$src_cidr" ip daddr "$dst_cidr" \
                        log prefix "\"zt-policy-deny: \"" level warn 2>/dev/null || true
                    nft add rule inet securizar_zonas zona_forward \
                        ip saddr "$src_cidr" ip daddr "$dst_cidr" drop 2>/dev/null || true
                    ;;
                rate-limit)
                    nft add rule inet securizar_zonas zona_forward \
                        ip saddr "$src_cidr" ip daddr "$dst_cidr" \
                        limit rate 10/second accept 2>/dev/null || true
                    ;;
            esac
            ((politicas_aplicadas++)) || true
        done
    done
done < "$CONF"

log "=== Resultado: $politicas_aplicadas políticas aplicadas, $politicas_error errores ==="
echo ""
echo "Políticas aplicadas: $politicas_aplicadas"
echo "Errores: $politicas_error"
APLICAREOF
    chmod 0755 /usr/local/bin/aplicar-politicas-zona.sh
    log_change "Creado" "/usr/local/bin/aplicar-politicas-zona.sh"

    log_info "Políticas inter-zona configuradas"
    log_info "Ejecuta: aplicar-politicas-zona.sh"
else
    log_skip "Políticas inter-zona"
fi

# ============================================================
# S3: MICROSEGMENTACIÓN POR SERVICIO
# ============================================================
log_section "S3: MICROSEGMENTACIÓN POR SERVICIO"

echo "Configura microsegmentación a nivel de servicio:"
echo "  - Mapeo de servicios a puertos/IPs permitidos"
echo "  - Reglas nftables por servicio individual"
echo "  - Script para aplicar microsegmentación"
echo ""

if check_executable /usr/local/bin/microsegmentar-servicio.sh; then
    log_already "Microsegmentacion por servicio (microsegmentar-servicio.sh existe)"
elif ask "¿Configurar microsegmentación por servicio?"; then

    log_info "Creando configuración de microsegmentación..."

    if [[ -f /etc/securizar/microseg-servicios.conf ]]; then
        cp /etc/securizar/microseg-servicios.conf "$BACKUP_DIR/" 2>/dev/null || true
        log_change "Backup" "/etc/securizar/microseg-servicios.conf"
    fi

    cat > /etc/securizar/microseg-servicios.conf << 'MICROSEGEOF'
# ============================================================
# microseg-servicios.conf - Microsegmentación por servicio
# Generado por securizar - Módulo 45
# ============================================================
# Formato: SERVICIO|PUERTOS_TCP|PUERTOS_UDP|IPS_PERMITIDAS|DESCRIPCION
# IPS_PERMITIDAS: CIDR separados por comas, o "any" para todos
# Dejar vacío con "-" si no aplica
# ============================================================

# Servicios de infraestructura
sshd|22|-|10.0.1.0/24,10.0.2.0/24|SSH solo desde TRUSTED
ntpd|-|123|any|NTP desde cualquier zona
systemd-resolved|-|53|10.0.10.0/24,10.0.11.0/24,192.168.1.0/24|DNS para INTERNAL

# Servicios web
nginx|80,443|-|any|Servidor web público
apache2|80,443|-|any|Servidor web Apache

# Bases de datos (solo acceso desde DMZ y TRUSTED)
postgresql|5432|-|10.0.100.0/24,10.0.1.0/24|PostgreSQL desde DMZ y admin
mysql|3306|-|10.0.100.0/24,10.0.1.0/24|MySQL desde DMZ y admin
redis|6379|-|10.0.100.0/24|Redis solo desde DMZ

# Servicios de mensajería
rabbitmq|5672,15672|-|10.0.100.0/24,10.0.10.0/24|RabbitMQ desde DMZ e INTERNAL

# Monitorización
prometheus|9090|-|10.0.1.0/24|Prometheus solo desde admin
node_exporter|9100|-|10.0.1.0/24|Node exporter solo desde admin
grafana|3000|-|10.0.1.0/24,10.0.10.0/24|Grafana desde admin e INTERNAL

# Backup
borgbackup|22|-|10.0.202.0/24|Backup SSH solo desde red de backups
MICROSEGEOF
    chmod 0640 /etc/securizar/microseg-servicios.conf
    log_change "Creado" "/etc/securizar/microseg-servicios.conf"

    # Script de microsegmentación
    log_info "Creando script de microsegmentación..."

    cat > /usr/local/bin/microsegmentar-servicio.sh << 'MICROSEGSCRIPT'
#!/bin/bash
# ============================================================
# microsegmentar-servicio.sh - Aplica microsegmentación por servicio
# Generado por securizar - Módulo 45
# ============================================================
# Uso: microsegmentar-servicio.sh <servicio|all> [--dry-run]
# ============================================================
set -uo pipefail

CONF="/etc/securizar/microseg-servicios.conf"
LOG="/var/log/securizar/microseg.log"
DRY_RUN=0

usage() {
    echo "Uso: $0 <servicio|all> [--dry-run]"
    echo ""
    echo "Servicios disponibles:"
    grep -v '^#' "$CONF" 2>/dev/null | grep -v '^$' | cut -d'|' -f1 | sort
    exit 1
}

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG"; }

nft_exec() {
    if [[ $DRY_RUN -eq 1 ]]; then
        echo "  [DRY-RUN] nft $*"
    else
        nft "$@" 2>/dev/null || true
    fi
}

[[ $EUID -ne 0 ]] && { echo "ERROR: Ejecutar como root" >&2; exit 1; }
[[ ! -f "$CONF" ]] && { echo "ERROR: No existe $CONF" >&2; exit 1; }

SERVICIO="${1:-}"
[[ -z "$SERVICIO" ]] && usage
[[ "${2:-}" == "--dry-run" ]] && DRY_RUN=1

mkdir -p /var/log/securizar

# Asegurar tabla nftables de microsegmentación
nft_exec add table inet securizar_microseg
nft_exec add chain inet securizar_microseg input \
    '{ type filter hook input priority 5 ; policy accept ; }'

aplicar_servicio() {
    local svc="$1" tcp_ports="$2" udp_ports="$3" ips_permitidas="$4" desc="$5"

    log "Microsegmentando servicio: $svc ($desc)"

    # Verificar si el servicio está activo
    if ! systemctl is-active "$svc" &>/dev/null 2>&1; then
        # Intentar variantes del nombre
        local svc_alt="${svc}.service"
        if ! systemctl is-active "$svc_alt" &>/dev/null 2>&1; then
            log "  AVISO: Servicio $svc no parece activo (se aplican reglas igualmente)"
        fi
    fi

    # Aplicar reglas TCP
    if [[ "$tcp_ports" != "-" && -n "$tcp_ports" ]]; then
        for port in ${tcp_ports//,/ }; do
            if [[ "$ips_permitidas" == "any" ]]; then
                nft_exec add rule inet securizar_microseg input \
                    tcp dport "$port" accept \
                    comment "\"microseg-$svc-tcp-$port\""
            else
                for cidr in ${ips_permitidas//,/ }; do
                    nft_exec add rule inet securizar_microseg input \
                        ip saddr "$cidr" tcp dport "$port" accept \
                        comment "\"microseg-$svc-tcp-$port-$cidr\""
                done
                # Denegar el resto para este puerto
                nft_exec add rule inet securizar_microseg input \
                    tcp dport "$port" \
                    log prefix "\"microseg-deny-$svc: \"" level info
                nft_exec add rule inet securizar_microseg input \
                    tcp dport "$port" drop \
                    comment "\"microseg-$svc-deny-tcp-$port\""
            fi
        done
    fi

    # Aplicar reglas UDP
    if [[ "$udp_ports" != "-" && -n "$udp_ports" ]]; then
        for port in ${udp_ports//,/ }; do
            if [[ "$ips_permitidas" == "any" ]]; then
                nft_exec add rule inet securizar_microseg input \
                    udp dport "$port" accept \
                    comment "\"microseg-$svc-udp-$port\""
            else
                for cidr in ${ips_permitidas//,/ }; do
                    nft_exec add rule inet securizar_microseg input \
                        ip saddr "$cidr" udp dport "$port" accept \
                        comment "\"microseg-$svc-udp-$port-$cidr\""
                done
                nft_exec add rule inet securizar_microseg input \
                    udp dport "$port" drop \
                    comment "\"microseg-$svc-deny-udp-$port\""
            fi
        done
    fi

    log "  -> Servicio $svc microsegmentado correctamente"
}

# Procesar servicio(s)
servicios_aplicados=0

while IFS='|' read -r svc tcp_ports udp_ports ips desc; do
    [[ "$svc" =~ ^# ]] && continue
    [[ -z "$svc" ]] && continue

    if [[ "$SERVICIO" == "all" || "$SERVICIO" == "$svc" ]]; then
        aplicar_servicio "$svc" "$tcp_ports" "$udp_ports" "$ips" "$desc"
        ((servicios_aplicados++)) || true
    fi
done < "$CONF"

if [[ $servicios_aplicados -eq 0 ]]; then
    echo "ERROR: Servicio '$SERVICIO' no encontrado en $CONF" >&2
    usage
fi

log "=== $servicios_aplicados servicio(s) microsegmentado(s) ==="
echo ""
echo "Servicios procesados: $servicios_aplicados"
[[ $DRY_RUN -eq 1 ]] && echo "(modo dry-run: no se aplicaron cambios reales)"
MICROSEGSCRIPT
    chmod 0755 /usr/local/bin/microsegmentar-servicio.sh
    log_change "Creado" "/usr/local/bin/microsegmentar-servicio.sh"

    log_info "Microsegmentación configurada"
    log_info "Ejecuta: microsegmentar-servicio.sh <servicio|all> [--dry-run]"
else
    log_skip "Microsegmentación por servicio"
fi

# ============================================================
# S4: AISLAMIENTO DE RED PARA CONTENEDORES
# ============================================================
log_section "S4: AISLAMIENTO DE RED PARA CONTENEDORES"

echo "Aislamiento de red para contenedores Docker/Podman:"
echo "  - Redes bridge personalizadas con flag --internal"
echo "  - Bloqueo de comunicación inter-contenedor"
echo "  - Script de aislamiento automático"
echo ""

if check_executable /usr/local/bin/aislar-contenedores-red.sh; then
    log_already "Aislamiento de red para contenedores (aislar-contenedores-red.sh existe)"
elif ask "¿Configurar aislamiento de red para contenedores?"; then

    CONTAINER_ENGINE=""
    if command -v docker &>/dev/null; then
        CONTAINER_ENGINE="docker"
    elif command -v podman &>/dev/null; then
        CONTAINER_ENGINE="podman"
    fi

    if [[ -n "$CONTAINER_ENGINE" ]]; then
        log_info "Motor de contenedores detectado: $CONTAINER_ENGINE"

        # Script de aislamiento de contenedores
        log_info "Creando script de aislamiento de contenedores..."

        cat > /usr/local/bin/aislar-contenedores-red.sh << 'CONTEOF'
#!/bin/bash
# ============================================================
# aislar-contenedores-red.sh - Aislamiento de red para contenedores
# Generado por securizar - Módulo 45
# ============================================================
# Uso: aislar-contenedores-red.sh [--audit|--apply|--create-networks]
# ============================================================
set -uo pipefail

LOG="/var/log/securizar/contenedores-red.log"
mkdir -p /var/log/securizar

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG"; }

# Detectar motor
ENGINE=""
if command -v docker &>/dev/null; then
    ENGINE="docker"
elif command -v podman &>/dev/null; then
    ENGINE="podman"
else
    echo "ERROR: No se detectó Docker ni Podman" >&2
    exit 1
fi

ACTION="${1:---audit}"

# --- Función: auditar redes ---
auditar_redes() {
    log "=== Auditoría de redes de contenedores ($ENGINE) ==="
    echo ""

    echo "Redes existentes:"
    $ENGINE network ls --format "table {{.Name}}\t{{.Driver}}\t{{.Scope}}"
    echo ""

    # Verificar si ICC está deshabilitado (Docker)
    if [[ "$ENGINE" == "docker" ]]; then
        echo "Configuración de Docker daemon:"
        if [[ -f /etc/docker/daemon.json ]]; then
            if grep -q '"icc"' /etc/docker/daemon.json 2>/dev/null; then
                icc_value=$(python3 -c "import json; d=json.load(open('/etc/docker/daemon.json')); print(d.get('icc', True))" 2>/dev/null || echo "unknown")
                echo "  ICC (Inter-Container Communication): $icc_value"
                if [[ "$icc_value" == "True" || "$icc_value" == "true" ]]; then
                    echo "  [!] AVISO: ICC está habilitado - contenedores pueden comunicarse entre sí"
                else
                    echo "  [+] ICC deshabilitado correctamente"
                fi
            else
                echo "  [!] ICC no configurado (habilitado por defecto)"
            fi

            if grep -q '"userland-proxy"' /etc/docker/daemon.json 2>/dev/null; then
                echo "  userland-proxy: configurado"
            else
                echo "  [!] userland-proxy no configurado"
            fi
        else
            echo "  [!] /etc/docker/daemon.json no existe"
        fi
    fi

    echo ""
    echo "Contenedores en ejecución y sus redes:"
    $ENGINE ps --format "table {{.Names}}\t{{.Networks}}\t{{.Ports}}" 2>/dev/null || \
    $ENGINE ps --format "table {{.Names}}\t{{.Ports}}" 2>/dev/null || true
    echo ""

    # Verificar redes internas
    echo "Redes internas (aisladas):"
    local found_internal=0
    for net in $($ENGINE network ls -q 2>/dev/null); do
        internal=$($ENGINE network inspect "$net" --format '{{.Internal}}' 2>/dev/null || echo "false")
        if [[ "$internal" == "true" ]]; then
            echo "  [+] $net (internal=true)"
            ((found_internal++)) || true
        fi
    done
    [[ $found_internal -eq 0 ]] && echo "  [!] No se encontraron redes internas"

    log "Auditoría completada"
}

# --- Función: crear redes aisladas ---
crear_redes() {
    log "=== Creando redes aisladas ==="

    # Red interna para servicios backend
    if ! $ENGINE network inspect securizar-backend &>/dev/null 2>&1; then
        $ENGINE network create \
            --driver bridge \
            --internal \
            --subnet 172.30.0.0/24 \
            --label "securizar.zona=restricted" \
            --label "securizar.proposito=backend" \
            securizar-backend || log "Error creando red securizar-backend"
        log "Creada red securizar-backend (internal, 172.30.0.0/24)"
    else
        log "Red securizar-backend ya existe"
    fi

    # Red interna para bases de datos
    if ! $ENGINE network inspect securizar-datos &>/dev/null 2>&1; then
        $ENGINE network create \
            --driver bridge \
            --internal \
            --subnet 172.30.1.0/24 \
            --label "securizar.zona=restricted" \
            --label "securizar.proposito=datos" \
            securizar-datos || log "Error creando red securizar-datos"
        log "Creada red securizar-datos (internal, 172.30.1.0/24)"
    else
        log "Red securizar-datos ya existe"
    fi

    # Red para servicios con acceso externo controlado (no internal)
    if ! $ENGINE network inspect securizar-frontend &>/dev/null 2>&1; then
        $ENGINE network create \
            --driver bridge \
            --subnet 172.30.2.0/24 \
            --label "securizar.zona=dmz" \
            --label "securizar.proposito=frontend" \
            securizar-frontend || log "Error creando red securizar-frontend"
        log "Creada red securizar-frontend (bridge, 172.30.2.0/24)"
    else
        log "Red securizar-frontend ya existe"
    fi

    echo ""
    echo "Redes securizar creadas:"
    $ENGINE network ls --filter "label=securizar.zona" \
        --format "table {{.Name}}\t{{.Driver}}\t{{.Internal}}" 2>/dev/null || \
    $ENGINE network ls 2>/dev/null
}

# --- Función: aplicar hardening ---
aplicar_hardening() {
    log "=== Aplicando hardening de red de contenedores ==="

    # Docker: configurar daemon.json
    if [[ "$ENGINE" == "docker" ]]; then
        local daemon_conf="/etc/docker/daemon.json"

        if [[ -f "$daemon_conf" ]]; then
            cp "$daemon_conf" "${daemon_conf}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
        fi

        # Crear o actualizar daemon.json con opciones de seguridad de red
        if command -v python3 &>/dev/null; then
            python3 << 'PYEOF'
import json, os

conf_path = "/etc/docker/daemon.json"
conf = {}
if os.path.exists(conf_path):
    try:
        with open(conf_path) as f:
            conf = json.load(f)
    except json.JSONDecodeError:
        conf = {}

# Deshabilitar ICC (Inter-Container Communication)
conf["icc"] = False

# Deshabilitar userland-proxy (usar iptables hairpin NAT)
conf["userland-proxy"] = False

# Habilitar iptables
conf["iptables"] = True

# No permitir que contenedores obtengan privilegios extra
conf["no-new-privileges"] = True

with open(conf_path, "w") as f:
    json.dump(conf, f, indent=2)

print(f"Actualizado {conf_path}")
PYEOF
            log "Configurado Docker daemon: icc=false, userland-proxy=false"
            echo ""
            echo "IMPORTANTE: Reiniciar Docker para aplicar cambios:"
            echo "  systemctl restart docker"
        else
            log "AVISO: python3 no disponible para actualizar daemon.json"
            echo "Agregar manualmente a /etc/docker/daemon.json:"
            echo '  {"icc": false, "userland-proxy": false, "iptables": true}'
        fi
    fi

    # Podman: configurar containers.conf
    if [[ "$ENGINE" == "podman" ]]; then
        local podman_conf="/etc/containers/containers.conf"
        mkdir -p /etc/containers

        if [[ -f "$podman_conf" ]]; then
            cp "$podman_conf" "${podman_conf}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
        fi

        # Añadir configuración de red segura si no existe
        if ! grep -q '\[network\]' "$podman_conf" 2>/dev/null; then
            cat >> "$podman_conf" << 'PODMANCEOF'

[network]
# Usar netavark como backend de red
network_backend = "netavark"

# Firewall con nftables
firewall_driver = "nftables"
PODMANCEOF
            log "Configurado Podman: netavark + nftables"
        else
            log "Sección [network] ya existe en containers.conf"
        fi
    fi

    # Reglas nftables para aislar redes de contenedores
    if command -v nft &>/dev/null; then
        log "Creando reglas nftables para contenedores..."

        cat > /etc/nftables.d/securizar-contenedores.nft << 'CNFTEOF'
#!/usr/sbin/nft -f
# Reglas de aislamiento de red para contenedores
# Generado por securizar - Módulo 45

table inet securizar_contenedores {
    chain forward {
        type filter hook forward priority 10; policy accept;

        # Bloquear tráfico entre redes de contenedores aisladas
        # securizar-backend (172.30.0.0/24) no puede hablar con frontend (172.30.2.0/24)
        ip saddr 172.30.0.0/24 ip daddr 172.30.2.0/24 drop
        ip saddr 172.30.2.0/24 ip daddr 172.30.0.0/24 drop

        # securizar-datos (172.30.1.0/24) solo accesible desde backend
        ip saddr 172.30.1.0/24 ip daddr != 172.30.0.0/24 drop

        # Log tráfico sospechoso
        ip saddr 172.30.0.0/16 ip daddr 172.30.0.0/16 \
            log prefix "securizar-container-fwd: " level info
    }
}
CNFTEOF
        chmod 0640 /etc/nftables.d/securizar-contenedores.nft
        log "Creado /etc/nftables.d/securizar-contenedores.nft"
    fi

    log "Hardening de red de contenedores aplicado"
}

# --- Ejecución ---
case "$ACTION" in
    --audit)           auditar_redes ;;
    --apply)           aplicar_hardening ;;
    --create-networks) crear_redes ;;
    *)
        echo "Uso: $0 [--audit|--apply|--create-networks]"
        echo ""
        echo "  --audit            Auditar configuración actual de redes"
        echo "  --apply            Aplicar hardening (daemon.json, nftables)"
        echo "  --create-networks  Crear redes aisladas securizar-*"
        exit 1
        ;;
esac
CONTEOF
        chmod 0755 /usr/local/bin/aislar-contenedores-red.sh
        log_change "Creado" "/usr/local/bin/aislar-contenedores-red.sh"

        log_info "Script de aislamiento de contenedores instalado"
        log_info "Ejecuta: aislar-contenedores-red.sh --audit"
    else
        log_warn "No se detectó Docker ni Podman"
        log_info "Se creará el script igualmente para uso futuro"

        # Crear el script de todas formas para cuando se instale un motor
        cat > /usr/local/bin/aislar-contenedores-red.sh << 'CONTFALLBACK'
#!/bin/bash
echo "ERROR: No se detectó Docker ni Podman" >&2
echo "Instala Docker o Podman y vuelve a ejecutar este script" >&2
exit 1
CONTFALLBACK
        chmod 0755 /usr/local/bin/aislar-contenedores-red.sh
        log_change "Creado" "/usr/local/bin/aislar-contenedores-red.sh (placeholder)"
    fi
else
    log_skip "Aislamiento de red para contenedores"
fi

# ============================================================
# S5: DEVICE POSTURE ASSESSMENT (ZERO TRUST)
# ============================================================
log_section "S5: DEVICE POSTURE ASSESSMENT (ZERO TRUST)"

echo "Evaluación de postura del dispositivo (Zero Trust):"
echo "  - Verifica: actualizaciones OS, firewall, AV, cifrado disco"
echo "  - Comprueba bloqueo de pantalla y cumplimiento endpoint"
echo "  - Puntuación 0-100 del dispositivo"
echo "  - Reporte JSON en /var/log/securizar/"
echo ""

if check_executable /usr/local/bin/evaluar-postura-dispositivo.sh; then
    log_already "Evaluacion de postura de dispositivo (evaluar-postura-dispositivo.sh existe)"
elif ask "¿Crear herramienta de evaluación de postura de dispositivo?"; then

    log_info "Creando script de evaluación de postura..."

    cat > /usr/local/bin/evaluar-postura-dispositivo.sh << 'POSTURAEOF'
#!/bin/bash
# ============================================================
# evaluar-postura-dispositivo.sh - Evaluación de postura Zero Trust
# Generado por securizar - Módulo 45
# ============================================================
# Uso: evaluar-postura-dispositivo.sh [--json|--verbose|--quiet]
# Salida: Puntuación 0-100 y reporte
# ============================================================
set -uo pipefail

REPORT_DIR="/var/log/securizar"
REPORT_FILE="$REPORT_DIR/postura-dispositivo.json"
LOG="$REPORT_DIR/postura-eval.log"
VERBOSE=0
QUIET=0
JSON_ONLY=0

mkdir -p "$REPORT_DIR"

case "${1:-}" in
    --json)    JSON_ONLY=1 ;;
    --verbose) VERBOSE=1 ;;
    --quiet)   QUIET=1 ;;
esac

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG"; }

# Variables de puntuación
SCORE_TOTAL=0
SCORE_MAX=0
declare -a CHECKS=()
declare -a CHECK_RESULTS=()
declare -a CHECK_SCORES=()
declare -a CHECK_DETAILS=()

# Función: registrar check
check_register() {
    local name="$1" weight="$2" passed="$3" detail="$4"
    CHECKS+=("$name")
    CHECK_RESULTS+=("$passed")
    CHECK_SCORES+=("$weight")
    CHECK_DETAILS+=("$detail")
    SCORE_MAX=$((SCORE_MAX + weight))
    if [[ "$passed" == "pass" ]]; then
        SCORE_TOTAL=$((SCORE_TOTAL + weight))
    fi
    log "Check: $name = $passed ($detail) [peso=$weight]"
}

# === CHECK 1: Actualizaciones del sistema (peso 20) ===
check_os_updates() {
    local pending=0
    local detail=""

    case "$(. /etc/os-release 2>/dev/null && echo "$ID")" in
        opensuse*|sles)
            pending=$(zypper --non-interactive list-patches 2>/dev/null | grep -c "needed" || true)
            ;;
        debian|ubuntu|linuxmint|pop)
            apt-get update -qq 2>/dev/null
            pending=$(apt list --upgradable 2>/dev/null | grep -c "upgradable" || true)
            ;;
        fedora|rhel|centos|rocky|alma)
            pending=$(dnf check-update --quiet 2>/dev/null | grep -cE "^[a-zA-Z]" || true)
            ;;
        arch|manjaro)
            pending=$(checkupdates 2>/dev/null | wc -l || echo "0")
            ;;
    esac

    if [[ "$pending" -le 5 ]]; then
        detail="$pending actualizaciones pendientes (aceptable)"
        check_register "os_updates" 20 "pass" "$detail"
    elif [[ "$pending" -le 20 ]]; then
        detail="$pending actualizaciones pendientes (moderado)"
        check_register "os_updates" 20 "warn" "$detail"
        SCORE_TOTAL=$((SCORE_TOTAL + 10))  # Puntuación parcial
    else
        detail="$pending actualizaciones pendientes (crítico)"
        check_register "os_updates" 20 "fail" "$detail"
    fi
}

# === CHECK 2: Firewall activo (peso 20) ===
check_firewall() {
    local fw_status="inactive"
    local detail=""

    if systemctl is-active firewalld &>/dev/null 2>&1; then
        fw_status="firewalld"
    elif [[ "$(systemctl is-enabled firewalld 2>/dev/null)" == "masked" ]]; then
        # firewalld masked: comprobar si queda tabla huérfana
        if nft list table inet firewalld &>/dev/null 2>&1; then
            fw_status="nftables"
            detail="AVISO: firewalld masked pero tabla inet firewalld huérfana en kernel"
            check_register "firewall" 20 "warn" "$detail"
            SCORE_TOTAL=$((SCORE_TOTAL + 10))
            return
        fi
        fw_status="inactive"
        detail="firewalld masked"
    fi

    if [[ "$fw_status" == "inactive" ]]; then
        if ufw status 2>/dev/null | grep -q "active"; then
            fw_status="ufw"
        elif nft list ruleset &>/dev/null 2>&1 && [[ $(nft list ruleset 2>/dev/null | wc -l) -gt 2 ]]; then
            fw_status="nftables"
        elif iptables -L -n 2>/dev/null | grep -qv "^$\|^Chain\|^target"; then
            fw_status="iptables"
        fi
    fi

    if [[ "$fw_status" != "inactive" ]]; then
        if [[ -n "$detail" ]]; then
            detail="$detail; fallback $fw_status activo"
        else
            detail="Firewall activo: $fw_status"
        fi
        check_register "firewall" 20 "pass" "$detail"
    else
        if [[ -n "$detail" ]]; then
            detail="$detail; sin firewall alternativo"
        else
            detail="No se detectó firewall activo"
        fi
        check_register "firewall" 20 "fail" "$detail"
    fi
}

# === CHECK 3: Antivirus/antimalware (peso 10) ===
check_antivirus() {
    local av_found=""

    if command -v clamscan &>/dev/null; then
        av_found="ClamAV"
    fi
    if command -v rkhunter &>/dev/null; then
        [[ -n "$av_found" ]] && av_found="$av_found, rkhunter" || av_found="rkhunter"
    fi
    if command -v chkrootkit &>/dev/null; then
        [[ -n "$av_found" ]] && av_found="$av_found, chkrootkit" || av_found="chkrootkit"
    fi

    if [[ -n "$av_found" ]]; then
        check_register "antivirus" 10 "pass" "AV detectado: $av_found"
    else
        check_register "antivirus" 10 "fail" "No se detectó antivirus/antimalware"
    fi
}

# === CHECK 4: Cifrado de disco (peso 15) ===
check_disk_encryption() {
    local encrypted=0
    local detail=""

    # Verificar LUKS
    if command -v lsblk &>/dev/null; then
        if lsblk -o TYPE 2>/dev/null | grep -q "crypt"; then
            encrypted=1
            detail="LUKS detectado en dispositivos de bloque"
        fi
    fi

    # Verificar dm-crypt
    if [[ -d /sys/block ]] && ls /dev/mapper/luks-* &>/dev/null 2>&1; then
        encrypted=1
        detail="dm-crypt/LUKS detectado"
    fi

    # Verificar eCryptfs
    if mount | grep -q "ecryptfs"; then
        encrypted=1
        detail="eCryptfs detectado"
    fi

    if [[ $encrypted -eq 1 ]]; then
        check_register "disk_encryption" 15 "pass" "$detail"
    else
        check_register "disk_encryption" 15 "fail" "No se detectó cifrado de disco"
    fi
}

# === CHECK 5: Bloqueo de pantalla / timeout de sesión (peso 10) ===
check_screen_lock() {
    local locked=0
    local detail=""

    # Verificar TMOUT en bash
    if grep -rq "^TMOUT=" /etc/profile /etc/profile.d/ /etc/bash.bashrc 2>/dev/null; then
        locked=1
        local tmout_val
        tmout_val=$(grep -rh "^TMOUT=" /etc/profile /etc/profile.d/ /etc/bash.bashrc 2>/dev/null | head -1 | cut -d= -f2)
        detail="TMOUT configurado: ${tmout_val}s"
    fi

    # Verificar SSH ClientAliveInterval
    if grep -q "^ClientAliveInterval" /etc/ssh/sshd_config 2>/dev/null; then
        local cai
        cai=$(grep "^ClientAliveInterval" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
        [[ -n "$detail" ]] && detail="$detail, SSH ClientAlive=${cai}s" || detail="SSH ClientAliveInterval=${cai}s"
        locked=1
    fi

    # Verificar systemd-logind IdleAction
    if grep -q "^IdleAction=" /etc/systemd/logind.conf 2>/dev/null; then
        local idle_action
        idle_action=$(grep "^IdleAction=" /etc/systemd/logind.conf | cut -d= -f2)
        [[ -n "$detail" ]] && detail="$detail, logind IdleAction=$idle_action" || detail="logind IdleAction=$idle_action"
        locked=1
    fi

    if [[ $locked -eq 1 ]]; then
        check_register "screen_lock" 10 "pass" "$detail"
    else
        check_register "screen_lock" 10 "fail" "No se detectó timeout de sesión ni bloqueo de pantalla"
    fi
}

# === CHECK 6: Endpoint compliance (peso 15) ===
check_endpoint_compliance() {
    local compliance_score=0
    local max_sub=5
    local details=()

    # Sub-check: SELinux/AppArmor
    if command -v getenforce &>/dev/null && [[ "$(getenforce 2>/dev/null)" == "Enforcing" ]]; then
        ((compliance_score++)) || true
        details+=("SELinux=Enforcing")
    elif command -v aa-status &>/dev/null && aa-status &>/dev/null 2>&1; then
        ((compliance_score++)) || true
        details+=("AppArmor=activo")
    fi

    # Sub-check: auditd activo
    if systemctl is-active auditd &>/dev/null 2>&1; then
        ((compliance_score++)) || true
        details+=("auditd=activo")
    fi

    # Sub-check: SSH con clave (no password)
    if grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config 2>/dev/null; then
        ((compliance_score++)) || true
        details+=("SSH=solo-clave")
    fi

    # Sub-check: sysctl hardening
    local ip_fwd
    ip_fwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "1")
    if [[ "$ip_fwd" == "0" ]]; then
        ((compliance_score++)) || true
        details+=("ip_forward=deshabilitado")
    fi

    # Sub-check: servicios innecesarios
    local unnecessary=0
    for svc in telnet.socket rsh.socket rlogin.socket rexec.socket; do
        if systemctl is-active "$svc" &>/dev/null 2>&1; then
            ((unnecessary++)) || true
        fi
    done
    if [[ $unnecessary -eq 0 ]]; then
        ((compliance_score++)) || true
        details+=("servicios-inseguros=0")
    fi

    local detail_str="${details[*]}"
    if [[ $compliance_score -ge 4 ]]; then
        check_register "endpoint_compliance" 15 "pass" "$compliance_score/$max_sub ($detail_str)"
    elif [[ $compliance_score -ge 2 ]]; then
        check_register "endpoint_compliance" 15 "warn" "$compliance_score/$max_sub ($detail_str)"
        SCORE_TOTAL=$((SCORE_TOTAL + 8))
    else
        check_register "endpoint_compliance" 15 "fail" "$compliance_score/$max_sub ($detail_str)"
    fi
}

# === CHECK 7: Integridad del sistema (peso 10) ===
check_system_integrity() {
    local integrity_ok=0
    local detail=""

    # Verificar AIDE
    if command -v aide &>/dev/null && [[ -f /var/lib/aide/aide.db ]]; then
        integrity_ok=1
        detail="AIDE instalado con base de datos"
    fi

    # Verificar dm-verity o IMA
    if [[ -f /sys/kernel/security/ima/ascii_runtime_measurements ]]; then
        [[ $integrity_ok -eq 1 ]] && detail="$detail + IMA activo" || detail="IMA activo"
        integrity_ok=1
    fi

    # Verificar Secure Boot
    if command -v mokutil &>/dev/null && mokutil --sb-state 2>/dev/null | grep -q "enabled"; then
        [[ $integrity_ok -eq 1 ]] && detail="$detail + SecureBoot" || detail="SecureBoot habilitado"
        integrity_ok=1
    fi

    if [[ $integrity_ok -eq 1 ]]; then
        check_register "system_integrity" 10 "pass" "$detail"
    else
        check_register "system_integrity" 10 "fail" "Sin verificación de integridad (AIDE/IMA/SecureBoot)"
    fi
}

# === Ejecutar todos los checks ===
log "=== Evaluación de postura iniciada ==="

check_os_updates
check_firewall
check_antivirus
check_disk_encryption
check_screen_lock
check_endpoint_compliance
check_system_integrity

# Calcular puntuación final (normalizada 0-100)
if [[ $SCORE_MAX -gt 0 ]]; then
    SCORE_FINAL=$(( (SCORE_TOTAL * 100) / SCORE_MAX ))
else
    SCORE_FINAL=0
fi

# Determinar nivel
NIVEL="DEFICIENTE"
if [[ $SCORE_FINAL -ge 80 ]]; then
    NIVEL="BUENO"
elif [[ $SCORE_FINAL -ge 50 ]]; then
    NIVEL="MEJORABLE"
fi

# Generar reporte JSON
{
    echo "{"
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"hostname\": \"$(hostname)\","
    echo "  \"score\": $SCORE_FINAL,"
    echo "  \"score_raw\": $SCORE_TOTAL,"
    echo "  \"score_max\": $SCORE_MAX,"
    echo "  \"nivel\": \"$NIVEL\","
    echo "  \"checks\": ["
    i=0
    for i in "${!CHECKS[@]}"; do
        comma=","
        [[ $i -eq $((${#CHECKS[@]} - 1)) ]] && comma=""
        echo "    {"
        echo "      \"name\": \"${CHECKS[$i]}\","
        echo "      \"result\": \"${CHECK_RESULTS[$i]}\","
        echo "      \"weight\": ${CHECK_SCORES[$i]},"
        echo "      \"detail\": \"${CHECK_DETAILS[$i]}\""
        echo "    }$comma"
    done
    echo "  ]"
    echo "}"
} > "$REPORT_FILE"

chmod 0640 "$REPORT_FILE"
log "Reporte guardado en $REPORT_FILE"

# Salida
if [[ $JSON_ONLY -eq 1 ]]; then
    cat "$REPORT_FILE"
elif [[ $QUIET -eq 1 ]]; then
    echo "$SCORE_FINAL"
else
    echo ""
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║     EVALUACIÓN DE POSTURA - ZERO TRUST                   ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo ""
    echo "  Host: $(hostname)"
    echo "  Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""

    for i in "${!CHECKS[@]}"; do
        icon="[X]"
        [[ "${CHECK_RESULTS[$i]}" == "pass" ]] && icon="[+]"
        [[ "${CHECK_RESULTS[$i]}" == "warn" ]] && icon="[!]"
        printf "  %-4s %-25s %s\n" "$icon" "${CHECKS[$i]}" "${CHECK_DETAILS[$i]}"
    done

    echo ""
    echo "  ════════════════════════════════════════════════"
    echo "  PUNTUACIÓN: $SCORE_FINAL/100 ($SCORE_TOTAL/$SCORE_MAX) - $NIVEL"
    echo "  ════════════════════════════════════════════════"
    echo ""
    echo "  Reporte JSON: $REPORT_FILE"
fi
POSTURAEOF
    chmod 0755 /usr/local/bin/evaluar-postura-dispositivo.sh
    log_change "Creado" "/usr/local/bin/evaluar-postura-dispositivo.sh"

    log_info "Herramienta de evaluación de postura instalada"
    log_info "Ejecuta: evaluar-postura-dispositivo.sh [--json|--verbose|--quiet]"
else
    log_skip "Device posture assessment"
fi

# ============================================================
# S6: IDENTITY-BASED ACCESS CONTROL
# ============================================================
log_section "S6: IDENTITY-BASED ACCESS CONTROL"

echo "Control de acceso basado en identidad y zona de red:"
echo "  - Integración PAM para autenticación por zona de red"
echo "  - Mapeo usuarios/grupos a zonas de red permitidas"
echo "  - Reglas sudo condicionadas por zona de red"
echo ""

if check_executable /usr/local/bin/aplicar-acceso-identidad.sh; then
    log_already "Control de acceso basado en identidad (aplicar-acceso-identidad.sh existe)"
elif ask "¿Configurar control de acceso basado en identidad?"; then

    # Crear configuración de acceso por identidad
    log_info "Creando configuración de acceso por identidad..."

    if [[ -f /etc/securizar/acceso-identidad.conf ]]; then
        cp /etc/securizar/acceso-identidad.conf "$BACKUP_DIR/" 2>/dev/null || true
        log_change "Backup" "/etc/securizar/acceso-identidad.conf"
    fi

    cat > /etc/securizar/acceso-identidad.conf << 'IDENTEOF'
# ============================================================
# acceso-identidad.conf - Control de acceso basado en identidad
# Generado por securizar - Módulo 45
# ============================================================
# Formato: TIPO|NOMBRE|ZONAS_PERMITIDAS|SERVICIOS|HORARIO|DESCRIPCION
# TIPO: user, group
# ZONAS_PERMITIDAS: lista de zonas separadas por comas
# SERVICIOS: ssh,sudo,login,all
# HORARIO: always, business (08-18 L-V), restricted (10-16 L-V)
# ============================================================

# Administradores: acceso total desde TRUSTED
group|wheel|TRUSTED|all|always|Admins desde red de gestión
group|sudo|TRUSTED|all|always|Admins desde red de gestión

# Administradores: acceso limitado desde INTERNAL
group|wheel|INTERNAL|ssh|business|Admins SSH desde red interna (horario laboral)
group|sudo|INTERNAL|ssh|business|Admins SSH desde red interna (horario laboral)

# Usuarios regulares: solo desde INTERNAL
group|users|INTERNAL|ssh,login|business|Usuarios desde red interna
group|users|TRUSTED|ssh|always|Usuarios desde red de admin (emergencia)

# Servicio de monitorización
user|prometheus|TRUSTED,DMZ|login|always|Monitorización desde admin/DMZ
user|grafana|TRUSTED|login|always|Grafana solo desde admin

# Denegar explícitamente
group|users|DMZ|deny|always|Usuarios no pueden acceder desde DMZ
group|users|RESTRICTED|deny|always|Usuarios no pueden acceder desde RESTRICTED
IDENTEOF
    chmod 0640 /etc/securizar/acceso-identidad.conf
    log_change "Creado" "/etc/securizar/acceso-identidad.conf"

    # Script de aplicación de acceso por identidad
    log_info "Creando script de aplicación de acceso por identidad..."

    cat > /usr/local/bin/aplicar-acceso-identidad.sh << 'IDSCRIPTEOF'
#!/bin/bash
# ============================================================
# aplicar-acceso-identidad.sh - Aplica control de acceso por identidad
# Generado por securizar - Módulo 45
# ============================================================
# Uso: aplicar-acceso-identidad.sh [--apply|--audit|--test-user <user>]
# ============================================================
set -uo pipefail

CONF="/etc/securizar/acceso-identidad.conf"
ZONAS_CONF="/etc/securizar/zonas-red.conf"
LOG="/var/log/securizar/acceso-identidad.log"
PAM_CONF="/etc/security/access.conf"

mkdir -p /var/log/securizar

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG"; }

[[ $EUID -ne 0 ]] && { echo "ERROR: Ejecutar como root" >&2; exit 1; }
[[ ! -f "$CONF" ]] && { echo "ERROR: No existe $CONF" >&2; exit 1; }

ACTION="${1:---audit}"

# Resolver CIDRs de zona
resolver_zona_cidrs() {
    local zona="$1"
    local cidrs=""
    if [[ -f "$ZONAS_CONF" ]]; then
        while IFS='|' read -r z cidr iface desc; do
            [[ "$z" == "$zona" ]] && {
                [[ -n "$cidrs" ]] && cidrs="$cidrs $cidr" || cidrs="$cidr"
            }
        done < <(grep -v '^#' "$ZONAS_CONF" | grep -v '^$')
    fi
    echo "$cidrs"
}

# --- Auditar configuración actual ---
auditar() {
    log "=== Auditoría de acceso por identidad ==="

    echo ""
    echo "Configuración actual de /etc/security/access.conf:"
    if [[ -f "$PAM_CONF" ]]; then
        grep -v '^#' "$PAM_CONF" | grep -v '^$' | head -20
    else
        echo "  (no existe)"
    fi

    echo ""
    echo "Políticas definidas en $CONF:"
    echo ""
    printf "  %-6s %-15s %-20s %-12s %-12s %s\n" "TIPO" "NOMBRE" "ZONAS" "SERVICIOS" "HORARIO" "DESC"
    echo "  $(printf '%.0s-' {1..80})"

    while IFS='|' read -r tipo nombre zonas servicios horario desc; do
        [[ "$tipo" =~ ^# ]] && continue
        [[ -z "$tipo" ]] && continue
        printf "  %-6s %-15s %-20s %-12s %-12s %s\n" "$tipo" "$nombre" "$zonas" "$servicios" "$horario" "$desc"
    done < "$CONF"

    echo ""
    echo "PAM access module configurado:"
    if grep -q "pam_access" /etc/pam.d/sshd 2>/dev/null; then
        echo "  [+] pam_access habilitado en sshd"
    else
        echo "  [-] pam_access NO habilitado en sshd"
    fi
    if grep -q "pam_access" /etc/pam.d/login 2>/dev/null; then
        echo "  [+] pam_access habilitado en login"
    else
        echo "  [-] pam_access NO habilitado en login"
    fi
}

# --- Aplicar configuración ---
aplicar() {
    log "=== Aplicando control de acceso por identidad ==="

    # Backup de access.conf
    if [[ -f "$PAM_CONF" ]]; then
        cp "$PAM_CONF" "${PAM_CONF}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
    fi

    # Generar access.conf desde la configuración
    {
        echo "# ============================================================"
        echo "# access.conf - Generado por securizar - Módulo 45"
        echo "# Control de acceso basado en identidad y zona de red"
        echo "# $(date '+%Y-%m-%d %H:%M:%S')"
        echo "# ============================================================"
        echo ""
        echo "# Reglas generadas desde /etc/securizar/acceso-identidad.conf"
    } > "$PAM_CONF"

    while IFS='|' read -r tipo nombre zonas servicios horario desc; do
        [[ "$tipo" =~ ^# ]] && continue
        [[ -z "$tipo" ]] && continue

        # Resolver CIDRs de las zonas
        for zona in ${zonas//,/ }; do
            local cidrs
            cidrs=$(resolver_zona_cidrs "$zona")
            if [[ -z "$cidrs" ]]; then
                log "AVISO: No se resolvieron CIDRs para zona $zona"
                continue
            fi

            for cidr in $cidrs; do
                if [[ "$servicios" == "deny" ]]; then
                    if [[ "$tipo" == "group" ]]; then
                        echo "- : @${nombre} : $cidr" >> "$PAM_CONF"
                    else
                        echo "- : ${nombre} : $cidr" >> "$PAM_CONF"
                    fi
                else
                    if [[ "$tipo" == "group" ]]; then
                        echo "+ : @${nombre} : $cidr" >> "$PAM_CONF"
                    else
                        echo "+ : ${nombre} : $cidr" >> "$PAM_CONF"
                    fi
                fi
            done
        done
    done < "$CONF"

    # Regla final: denegar todo lo demás
    echo "" >> "$PAM_CONF"
    echo "# Denegación por defecto (Zero Trust)" >> "$PAM_CONF"
    echo "# NOTA: Descomentar solo si se han validado las reglas anteriores" >> "$PAM_CONF"
    echo "# - : ALL : ALL" >> "$PAM_CONF"

    chmod 0644 "$PAM_CONF"
    log "Generado $PAM_CONF"

    # Configurar PAM para usar access.conf
    for pam_service in sshd login; do
        local pam_file="/etc/pam.d/$pam_service"
        if [[ -f "$pam_file" ]]; then
            if ! grep -q "pam_access.so" "$pam_file" 2>/dev/null; then
                cp "$pam_file" "${pam_file}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
                # Añadir al inicio de account
                if grep -q "^account" "$pam_file"; then
                    sed -i '0,/^account/s/^account/account    required     pam_access.so\naccount/' "$pam_file"
                else
                    echo "account    required     pam_access.so" >> "$pam_file"
                fi
                log "Habilitado pam_access en $pam_file"
            else
                log "pam_access ya habilitado en $pam_file"
            fi
        fi
    done

    # Configurar reglas sudo por zona
    log "Configurando sudo por zona de red..."
    local sudoers_zt="/etc/sudoers.d/securizar-zt-identity"

    {
        echo "# ============================================================"
        echo "# Reglas sudo por zona de red - Generado por securizar"
        echo "# ============================================================"
        echo ""
        echo "# Admins desde red TRUSTED: acceso sudo completo"
        echo "# (el control de red se hace via PAM, sudo confía en PAM)"
        echo ""
        echo "# Restringir comandos peligrosos para usuarios normales"
        echo "Cmnd_Alias NETWORK_ADMIN = /usr/sbin/nft, /usr/sbin/iptables, /usr/sbin/ip, /usr/bin/firewall-cmd"
        echo "Cmnd_Alias SYSTEM_ADMIN = /usr/bin/systemctl, /usr/sbin/reboot, /usr/sbin/shutdown"
        echo ""
        echo "# Solo admins pueden ejecutar comandos de red y sistema"
        echo "%wheel ALL=(ALL) NETWORK_ADMIN, SYSTEM_ADMIN"
        echo "%sudo  ALL=(ALL) NETWORK_ADMIN, SYSTEM_ADMIN"
    } > "$sudoers_zt"

    chmod 0440 "$sudoers_zt"
    # Validar sudoers
    if visudo -cf "$sudoers_zt" &>/dev/null; then
        log "Creado $sudoers_zt (validado)"
    else
        log "ERROR: $sudoers_zt no pasó validación - eliminando"
        rm -f "$sudoers_zt"
    fi

    log "=== Control de acceso por identidad aplicado ==="
    echo ""
    echo "Archivos modificados:"
    echo "  - $PAM_CONF"
    echo "  - /etc/pam.d/sshd (pam_access)"
    echo "  - /etc/pam.d/login (pam_access)"
    echo "  - $sudoers_zt"
}

# --- Test usuario ---
test_usuario() {
    local test_user="${2:-}"
    [[ -z "$test_user" ]] && { echo "Uso: $0 --test-user <usuario>" >&2; exit 1; }

    echo "Test de acceso para usuario: $test_user"
    echo ""

    # Obtener grupos del usuario
    local user_groups
    user_groups=$(id -nG "$test_user" 2>/dev/null || echo "")
    echo "Grupos: $user_groups"
    echo ""

    echo "Políticas aplicables:"
    while IFS='|' read -r tipo nombre zonas servicios horario desc; do
        [[ "$tipo" =~ ^# ]] && continue
        [[ -z "$tipo" ]] && continue

        local aplica=0
        if [[ "$tipo" == "user" && "$nombre" == "$test_user" ]]; then
            aplica=1
        elif [[ "$tipo" == "group" ]]; then
            for g in $user_groups; do
                [[ "$g" == "$nombre" ]] && aplica=1
            done
        fi

        if [[ $aplica -eq 1 ]]; then
            printf "  %-6s %-15s zonas=%-20s servicios=%-10s horario=%-10s %s\n" \
                "$tipo" "$nombre" "$zonas" "$servicios" "$horario" "$desc"
        fi
    done < "$CONF"
}

# --- Ejecución ---
case "$ACTION" in
    --apply)     aplicar ;;
    --audit)     auditar ;;
    --test-user) test_usuario "$@" ;;
    *)
        echo "Uso: $0 [--apply|--audit|--test-user <user>]"
        echo ""
        echo "  --apply              Aplicar políticas de acceso por identidad"
        echo "  --audit              Auditar configuración actual"
        echo "  --test-user <user>   Probar acceso de un usuario"
        exit 1
        ;;
esac
IDSCRIPTEOF
    chmod 0755 /usr/local/bin/aplicar-acceso-identidad.sh
    log_change "Creado" "/usr/local/bin/aplicar-acceso-identidad.sh"

    log_info "Control de acceso por identidad configurado"
    log_info "Ejecuta: aplicar-acceso-identidad.sh --audit"
else
    log_skip "Control de acceso basado en identidad"
fi

# ============================================================
# S7: TRAFFIC MONITORING & ANOMALY DETECTION
# ============================================================
log_section "S7: TRAFFIC MONITORING & ANOMALY DETECTION"

echo "Monitorización de tráfico entre zonas y detección de anomalías:"
echo "  - Monitorización de tráfico inter-zona con tcpdump/conntrack"
echo "  - Alertas por cruce de zona no autorizado"
echo "  - Detección de port scans y movimiento lateral"
echo "  - Log en /var/log/securizar/trafico-zonas.log"
echo ""

if check_executable /usr/local/bin/monitorizar-trafico-zonas.sh; then
    log_already "Monitorizacion de trafico entre zonas (monitorizar-trafico-zonas.sh existe)"
elif ask "¿Configurar monitorización de tráfico entre zonas?"; then

    # Instalar herramientas necesarias
    for tool in tcpdump conntrack; do
        if ! command -v "$tool" &>/dev/null; then
            log_info "Instalando $tool..."
            case "$tool" in
                tcpdump)   pkg_install tcpdump || log_warn "No se pudo instalar tcpdump" ;;
                conntrack) pkg_install conntrack-tools || log_warn "No se pudo instalar conntrack-tools" ;;
            esac
        fi
    done

    log_info "Creando script de monitorización de tráfico..."

    cat > /usr/local/bin/monitorizar-trafico-zonas.sh << 'TRAFEOF'
#!/bin/bash
# ============================================================
# monitorizar-trafico-zonas.sh - Monitor de tráfico inter-zona
# Generado por securizar - Módulo 45
# ============================================================
# Uso: monitorizar-trafico-zonas.sh [--live|--report|--detect-scan|--daemon]
# ============================================================
set -uo pipefail

ZONAS_CONF="/etc/securizar/zonas-red.conf"
LOG="/var/log/securizar/trafico-zonas.log"
ALERT_LOG="/var/log/securizar/alertas-trafico.log"
PID_FILE="/run/securizar-trafico-monitor.pid"

mkdir -p /var/log/securizar

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG"; }
alert() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] ALERTA: $1" | tee -a "$ALERT_LOG" "$LOG"; }

[[ $EUID -ne 0 ]] && { echo "ERROR: Ejecutar como root" >&2; exit 1; }

ACTION="${1:---report}"

# Cargar zonas
declare -A ZONA_CIDRS
if [[ -f "$ZONAS_CONF" ]]; then
    while IFS='|' read -r zona cidr iface desc; do
        [[ "$zona" =~ ^# ]] && continue
        [[ -z "$zona" ]] && continue
        if [[ -n "${ZONA_CIDRS[$zona]:-}" ]]; then
            ZONA_CIDRS[$zona]="${ZONA_CIDRS[$zona]} $cidr"
        else
            ZONA_CIDRS[$zona]="$cidr"
        fi
    done < "$ZONAS_CONF"
fi

# Función: clasificar IP en zona
clasificar_ip() {
    local ip="$1"
    for zona in "${!ZONA_CIDRS[@]}"; do
        for cidr in ${ZONA_CIDRS[$zona]}; do
            # Verificación simplificada por prefijo de red
            local net="${cidr%/*}"
            local prefix="${net%.*}."
            if [[ "$ip" == "$prefix"* ]]; then
                echo "$zona"
                return 0
            fi
        done
    done
    echo "UNKNOWN"
}

# --- Reporte de conexiones actuales ---
reporte() {
    log "=== Reporte de tráfico inter-zona ==="

    echo ""
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║     REPORTE DE TRÁFICO INTER-ZONA                        ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo ""

    # Conexiones activas con conntrack
    if command -v conntrack &>/dev/null; then
        echo "Conexiones inter-zona activas (conntrack):"
        echo ""
        printf "  %-12s %-20s %-12s %-20s %-8s %s\n" "ZONA_ORIG" "IP_ORIGEN" "ZONA_DEST" "IP_DESTINO" "PROTO" "PUERTO"
        echo "  $(printf '%.0s-' {1..90})"

        local violations=0
        conntrack -L 2>/dev/null | while read -r line; do
            local proto src dst dport
            proto=$(echo "$line" | grep -oP '^\w+' || echo "?")
            src=$(echo "$line" | grep -oP 'src=[\d.]+' | head -1 | cut -d= -f2 || echo "?")
            dst=$(echo "$line" | grep -oP 'dst=[\d.]+' | head -1 | cut -d= -f2 || echo "?")
            dport=$(echo "$line" | grep -oP 'dport=\d+' | head -1 | cut -d= -f2 || echo "?")

            [[ "$src" == "?" || "$dst" == "?" ]] && continue
            [[ "$src" == "127."* || "$dst" == "127."* ]] && continue

            local zona_src zona_dst
            zona_src=$(clasificar_ip "$src")
            zona_dst=$(clasificar_ip "$dst")

            # Solo mostrar tráfico inter-zona
            if [[ "$zona_src" != "$zona_dst" ]]; then
                printf "  %-12s %-20s %-12s %-20s %-8s %s\n" \
                    "$zona_src" "$src" "$zona_dst" "$dst" "$proto" "$dport"

                # Alertar en violaciones de política
                case "${zona_src}->${zona_dst}" in
                    DMZ-\>RESTRICTED|RESTRICTED-\>*|INTERNAL-\>RESTRICTED)
                        alert "Tráfico prohibido: $zona_src($src) -> $zona_dst($dst):$dport/$proto"
                        ((violations++)) || true
                        ;;
                esac
            fi
        done

        echo ""
        [[ ${violations:-0} -gt 0 ]] && echo "  [!] VIOLACIONES DETECTADAS: $violations (ver $ALERT_LOG)"
    else
        echo "  conntrack no disponible - instalando conntrack-tools"
        echo "  Usando ss como alternativa:"
        echo ""
        ss -tuanp 2>/dev/null | head -30
    fi

    echo ""
    echo "Estadísticas de nftables por zona:"
    if command -v nft &>/dev/null; then
        nft list table inet securizar_zonas 2>/dev/null | grep -E "packets|bytes|counter" || \
            echo "  (tabla securizar_zonas no encontrada)"
    fi

    echo ""
    log "Reporte completado"
}

# --- Detección de port scans ---
detectar_scans() {
    log "=== Detección de port scans y movimiento lateral ==="

    echo ""
    echo "Analizando patrones de conexión sospechosos..."
    echo ""

    if command -v conntrack &>/dev/null; then
        # Buscar IPs con muchas conexiones a puertos diferentes (indicador de scan)
        echo "IPs con conexiones a múltiples puertos (posible port scan):"
        echo ""

        conntrack -L 2>/dev/null | \
            grep -oP 'src=[\d.]+.*dport=\d+' | \
            sed 's/.*src=//;s/ .*dport=/|/' | \
            sort | uniq | \
            awk -F'|' '{count[$1]++} END {for (ip in count) if (count[ip] > 10) printf "  [!] %s: %d puertos diferentes\n", ip, count[ip]}' || true

        echo ""

        # Detectar movimiento lateral: conexiones desde DMZ/INTERNAL a puertos sensibles
        echo "Conexiones a puertos sensibles desde zonas no autorizadas:"
        local sensitive_ports="22 3389 5900 5985 5986 445 139 3306 5432 6379 27017"

        for port in $sensitive_ports; do
            conntrack -L 2>/dev/null | grep "dport=$port " | while read -r line; do
                local src dst
                src=$(echo "$line" | grep -oP 'src=[\d.]+' | head -1 | cut -d= -f2)
                dst=$(echo "$line" | grep -oP 'dst=[\d.]+' | head -1 | cut -d= -f2)
                [[ -z "$src" || -z "$dst" ]] && continue

                local zona_src
                zona_src=$(clasificar_ip "$src")
                if [[ "$zona_src" == "DMZ" || "$zona_src" == "UNKNOWN" ]]; then
                    alert "Conexión sospechosa: $zona_src($src) -> $dst:$port"
                    echo "  [!] $zona_src($src) -> $dst:$port (puerto sensible)"
                fi
            done
        done
    fi

    # Verificar logs de nftables por denegaciones recientes
    echo ""
    echo "Últimas denegaciones de firewall (últimas 50):"
    if command -v journalctl &>/dev/null; then
        journalctl -k --no-pager -n 50 2>/dev/null | grep -i "securizar.*deny\|securizar.*block\|securizar.*drop" || \
            echo "  (sin denegaciones recientes en journal)"
    fi

    log "Detección de scans completada"
}

# --- Modo live (captura en tiempo real) ---
modo_live() {
    log "=== Monitorización en tiempo real ==="
    echo "Capturando tráfico inter-zona en tiempo real (Ctrl+C para parar)..."
    echo ""

    if ! command -v tcpdump &>/dev/null; then
        echo "ERROR: tcpdump no disponible" >&2
        exit 1
    fi

    # Construir filtro BPF para las zonas
    local bpf_filter="not host 127.0.0.1"
    for zona in "${!ZONA_CIDRS[@]}"; do
        for cidr in ${ZONA_CIDRS[$zona]}; do
            bpf_filter="$bpf_filter and not (src net $cidr and dst net $cidr)"
        done
    done

    # Capturar solo tráfico que cruza zonas
    tcpdump -n -l -c 1000 "$bpf_filter" 2>/dev/null | while read -r line; do
        echo "[$(date '+%H:%M:%S')] $line"
        echo "$line" >> "$LOG"
    done
}

# --- Modo daemon ---
modo_daemon() {
    if [[ -f "$PID_FILE" ]]; then
        local old_pid
        old_pid=$(cat "$PID_FILE" 2>/dev/null)
        if kill -0 "$old_pid" 2>/dev/null; then
            echo "Monitor ya ejecutándose (PID $old_pid)"
            exit 0
        fi
    fi

    log "Iniciando monitor daemon..."
    echo $$ > "$PID_FILE"

    while true; do
        detectar_scans >> "$LOG" 2>&1
        sleep 300  # Cada 5 minutos
    done
}

# --- Ejecución ---
case "$ACTION" in
    --report)      reporte ;;
    --detect-scan) detectar_scans ;;
    --live)        modo_live ;;
    --daemon)      modo_daemon ;;
    --stop)
        if [[ -f "$PID_FILE" ]]; then
            kill "$(cat "$PID_FILE")" 2>/dev/null && rm -f "$PID_FILE"
            echo "Monitor detenido"
        else
            echo "Monitor no está ejecutándose"
        fi
        ;;
    *)
        echo "Uso: $0 [--report|--detect-scan|--live|--daemon|--stop]"
        echo ""
        echo "  --report       Reporte de conexiones inter-zona actuales"
        echo "  --detect-scan  Detectar port scans y movimiento lateral"
        echo "  --live         Captura de tráfico en tiempo real"
        echo "  --daemon       Ejecutar como daemon (detección periódica)"
        echo "  --stop         Detener daemon"
        exit 1
        ;;
esac
TRAFEOF
    chmod 0755 /usr/local/bin/monitorizar-trafico-zonas.sh
    log_change "Creado" "/usr/local/bin/monitorizar-trafico-zonas.sh"

    log_info "Monitorización de tráfico inter-zona configurada"
    log_info "Ejecuta: monitorizar-trafico-zonas.sh --report"
else
    log_skip "Monitorización de tráfico entre zonas"
fi

# ============================================================
# S8: NETWORK VALIDATION
# ============================================================
log_section "S8: NETWORK VALIDATION"

echo "Validación de segmentación de red:"
echo "  - Test de aislamiento entre zonas"
echo "  - Verificación de reglas de firewall activas"
echo "  - Comprobación de carga de nftables"
echo "  - Verificación de políticas inter-zona"
echo ""

if check_executable /usr/local/bin/validar-segmentacion.sh; then
    log_already "Validacion de segmentacion (validar-segmentacion.sh existe)"
elif ask "¿Crear herramienta de validación de segmentación?"; then

    log_info "Creando script de validación de segmentación..."

    cat > /usr/local/bin/validar-segmentacion.sh << 'VALIDEOF'
#!/bin/bash
# ============================================================
# validar-segmentacion.sh - Validación de segmentación de red
# Generado por securizar - Módulo 45
# ============================================================
# Uso: validar-segmentacion.sh [--full|--quick|--json]
# ============================================================
set -uo pipefail

ZONAS_CONF="/etc/securizar/zonas-red.conf"
POLITICAS_CONF="/etc/securizar/politicas-interzona.conf"
LOG="/var/log/securizar/validacion-segmentacion.log"
REPORT_FILE="/var/log/securizar/validacion-segmentacion.json"

mkdir -p /var/log/securizar

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG"; }

MODE="${1:---full}"
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
TOTAL_COUNT=0

declare -a TEST_NAMES=()
declare -a TEST_RESULTS=()
declare -a TEST_DETAILS=()

# Función: registrar resultado de test
test_result() {
    local name="$1" result="$2" detail="$3"
    TEST_NAMES+=("$name")
    TEST_RESULTS+=("$result")
    TEST_DETAILS+=("$detail")
    ((TOTAL_COUNT++)) || true

    case "$result" in
        PASS) ((PASS_COUNT++)) || true; local icon="[+]" ;;
        FAIL) ((FAIL_COUNT++)) || true; local icon="[X]" ;;
        WARN) ((WARN_COUNT++)) || true; local icon="[!]" ;;
        *)    local icon="[?]" ;;
    esac

    if [[ "$MODE" != "--json" ]]; then
        printf "  %-4s %-40s %s\n" "$icon" "$name" "$detail"
    fi
    log "TEST $result: $name - $detail"
}

# === TEST 1: Configuración de zonas existe ===
test_zonas_config() {
    if [[ -f "$ZONAS_CONF" ]]; then
        local num_zonas
        num_zonas=$(grep -v '^#' "$ZONAS_CONF" | grep -v '^$' | cut -d'|' -f1 | sort -u | wc -l)
        test_result "zonas_config_existe" "PASS" "Archivo de zonas existe ($num_zonas zonas definidas)"
    else
        test_result "zonas_config_existe" "FAIL" "No existe $ZONAS_CONF"
    fi
}

# === TEST 2: Políticas inter-zona definidas ===
test_politicas_config() {
    if [[ -f "$POLITICAS_CONF" ]]; then
        local num_politicas
        num_politicas=$(grep -v '^#' "$POLITICAS_CONF" | grep -v '^$' | grep -v "^DEFAULT" | wc -l)
        test_result "politicas_interzona" "PASS" "$num_politicas políticas inter-zona definidas"
    else
        test_result "politicas_interzona" "FAIL" "No existe $POLITICAS_CONF"
    fi
}

# === TEST 3: nftables cargado ===
test_nftables_cargado() {
    if command -v nft &>/dev/null; then
        local num_reglas
        num_reglas=$(nft list ruleset 2>/dev/null | wc -l || echo "0")
        if [[ "$num_reglas" -gt 5 ]]; then
            test_result "nftables_cargado" "PASS" "nftables activo con $num_reglas líneas de reglas"
        else
            test_result "nftables_cargado" "WARN" "nftables disponible pero pocas reglas ($num_reglas)"
        fi
    else
        test_result "nftables_cargado" "FAIL" "nftables no disponible"
    fi
}

# === TEST 4: Tabla securizar_zonas existe ===
test_tabla_zonas() {
    if command -v nft &>/dev/null; then
        if nft list table inet securizar_zonas &>/dev/null 2>&1; then
            local chains
            chains=$(nft list table inet securizar_zonas 2>/dev/null | grep -c "chain " || true)
            test_result "tabla_securizar_zonas" "PASS" "Tabla securizar_zonas existe ($chains cadenas)"
        else
            test_result "tabla_securizar_zonas" "FAIL" "Tabla inet securizar_zonas no cargada"
        fi
    else
        test_result "tabla_securizar_zonas" "FAIL" "nftables no disponible"
    fi
}

# === TEST 5: Firewall activo ===
test_firewall_activo() {
    local fw_detected=""
    local fw_warn=""
    if systemctl is-active firewalld &>/dev/null 2>&1; then
        fw_detected="firewalld"
    elif [[ "$(systemctl is-enabled firewalld 2>/dev/null)" == "masked" ]]; then
        fw_warn="firewalld masked"
        if nft list table inet firewalld &>/dev/null 2>&1; then
            fw_warn="$fw_warn + tabla huérfana en kernel"
        fi
    fi

    if [[ -z "$fw_detected" ]]; then
        if ufw status 2>/dev/null | grep -q "active"; then
            fw_detected="ufw"
        elif command -v nft &>/dev/null && [[ $(nft list ruleset 2>/dev/null | wc -l) -gt 2 ]]; then
            fw_detected="nftables"
        elif iptables -L -n 2>/dev/null | grep -qv "^$\|^Chain\|^target"; then
            fw_detected="iptables"
        fi
    fi

    if [[ -n "$fw_detected" && -n "$fw_warn" ]]; then
        test_result "firewall_activo" "WARN" "Firewall: $fw_detected ($fw_warn)"
    elif [[ -n "$fw_detected" ]]; then
        test_result "firewall_activo" "PASS" "Firewall activo: $fw_detected"
    else
        test_result "firewall_activo" "FAIL" "No se detectó firewall activo"
    fi
}

# === TEST 6: Default policy es DROP ===
test_default_policy() {
    local policy_ok=0
    if command -v nft &>/dev/null; then
        if nft list chain inet securizar_zonas zona_forward 2>/dev/null | grep -q "policy drop"; then
            policy_ok=1
            test_result "default_policy_drop" "PASS" "Forward policy es DROP (securizar_zonas)"
        fi
    fi

    if [[ $policy_ok -eq 0 ]]; then
        # Verificar iptables
        local fwd_policy
        fwd_policy=$(iptables -L FORWARD -n 2>/dev/null | head -1 | grep -oP 'policy \K\w+' || echo "unknown")
        if [[ "$fwd_policy" == "DROP" ]]; then
            test_result "default_policy_drop" "PASS" "Forward policy es DROP (iptables)"
        else
            test_result "default_policy_drop" "WARN" "Forward policy no es DROP ($fwd_policy)"
        fi
    fi
}

# === TEST 7: Aislamiento de zona RESTRICTED ===
test_aislamiento_restricted() {
    if [[ ! -f "$ZONAS_CONF" ]]; then
        test_result "aislamiento_restricted" "FAIL" "Sin configuración de zonas"
        return
    fi

    # Obtener un CIDR de RESTRICTED
    local restricted_cidr
    restricted_cidr=$(grep "^RESTRICTED" "$ZONAS_CONF" | head -1 | cut -d'|' -f2)

    if [[ -z "$restricted_cidr" ]]; then
        test_result "aislamiento_restricted" "WARN" "No se encontró CIDR para RESTRICTED"
        return
    fi

    # Verificar que hay reglas de drop para RESTRICTED
    if command -v nft &>/dev/null; then
        if nft list ruleset 2>/dev/null | grep -q "restricted.*drop\|RESTRICTED.*drop"; then
            test_result "aislamiento_restricted" "PASS" "Reglas de aislamiento para RESTRICTED detectadas"
        else
            test_result "aislamiento_restricted" "WARN" "No se detectaron reglas explícitas de drop para RESTRICTED"
        fi
    else
        test_result "aislamiento_restricted" "WARN" "No se puede verificar sin nftables"
    fi
}

# === TEST 8: Scripts de gestión instalados ===
test_scripts_instalados() {
    local scripts=(
        "/usr/local/bin/aplicar-politicas-zona.sh"
        "/usr/local/bin/microsegmentar-servicio.sh"
        "/usr/local/bin/aislar-contenedores-red.sh"
        "/usr/local/bin/evaluar-postura-dispositivo.sh"
        "/usr/local/bin/aplicar-acceso-identidad.sh"
        "/usr/local/bin/monitorizar-trafico-zonas.sh"
    )

    local installed=0
    local missing=0
    for script in "${scripts[@]}"; do
        if [[ -x "$script" ]]; then
            ((installed++)) || true
        else
            ((missing++)) || true
        fi
    done

    if [[ $missing -eq 0 ]]; then
        test_result "scripts_instalados" "PASS" "Todos los scripts instalados ($installed/$installed)"
    elif [[ $installed -gt 0 ]]; then
        test_result "scripts_instalados" "WARN" "$installed instalados, $missing faltantes"
    else
        test_result "scripts_instalados" "FAIL" "Ningún script instalado"
    fi
}

# === TEST 9: Configuración de microsegmentación ===
test_microseg() {
    if [[ -f /etc/securizar/microseg-servicios.conf ]]; then
        local num_svcs
        num_svcs=$(grep -v '^#' /etc/securizar/microseg-servicios.conf | grep -v '^$' | wc -l)
        test_result "microsegmentacion" "PASS" "$num_svcs servicios definidos en microsegmentación"
    else
        test_result "microsegmentacion" "FAIL" "Sin configuración de microsegmentación"
    fi
}

# === TEST 10: IP forwarding controlado ===
test_ip_forwarding() {
    local ipv4_fwd
    ipv4_fwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "unknown")
    local ipv6_fwd
    ipv6_fwd=$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo "unknown")

    if [[ "$ipv4_fwd" == "0" && "$ipv6_fwd" == "0" ]]; then
        test_result "ip_forwarding" "PASS" "IP forwarding deshabilitado (IPv4=$ipv4_fwd, IPv6=$ipv6_fwd)"
    elif [[ "$ipv4_fwd" == "1" ]]; then
        test_result "ip_forwarding" "WARN" "IPv4 forwarding habilitado (necesario si es router/gateway)"
    else
        test_result "ip_forwarding" "WARN" "IPv4=$ipv4_fwd, IPv6=$ipv6_fwd"
    fi
}

# === Ejecutar tests ===
if [[ "$MODE" != "--json" ]]; then
    echo ""
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║     VALIDACIÓN DE SEGMENTACIÓN DE RED                     ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo ""
fi

test_zonas_config
test_politicas_config
test_nftables_cargado
test_tabla_zonas
test_firewall_activo
test_default_policy
test_aislamiento_restricted
test_scripts_instalados
test_microseg
test_ip_forwarding

# Resultado global
if [[ "$MODE" == "--json" ]]; then
    {
        echo "{"
        echo "  \"timestamp\": \"$(date -Iseconds)\","
        echo "  \"hostname\": \"$(hostname)\","
        echo "  \"pass\": $PASS_COUNT,"
        echo "  \"fail\": $FAIL_COUNT,"
        echo "  \"warn\": $WARN_COUNT,"
        echo "  \"total\": $TOTAL_COUNT,"
        echo "  \"tests\": ["
        for i in "${!TEST_NAMES[@]}"; do
            comma=","
            [[ $i -eq $((${#TEST_NAMES[@]} - 1)) ]] && comma=""
            echo "    {\"name\": \"${TEST_NAMES[$i]}\", \"result\": \"${TEST_RESULTS[$i]}\", \"detail\": \"${TEST_DETAILS[$i]}\"}$comma"
        done
        echo "  ]"
        echo "}"
    } | tee "$REPORT_FILE"
else
    echo ""
    echo "  ════════════════════════════════════════════════"
    echo "  RESULTADO: $PASS_COUNT PASS / $WARN_COUNT WARN / $FAIL_COUNT FAIL (total: $TOTAL_COUNT)"
    echo "  ════════════════════════════════════════════════"
    echo ""
    if [[ $FAIL_COUNT -eq 0 ]]; then
        echo "  Estado: BUENO - Segmentación de red validada"
    elif [[ $FAIL_COUNT -le 3 ]]; then
        echo "  Estado: MEJORABLE - Hay $FAIL_COUNT controles sin implementar"
    else
        echo "  Estado: DEFICIENTE - $FAIL_COUNT controles fallidos"
    fi
fi
VALIDEOF
    chmod 0755 /usr/local/bin/validar-segmentacion.sh
    log_change "Creado" "/usr/local/bin/validar-segmentacion.sh"

    log_info "Herramienta de validación de segmentación instalada"
    log_info "Ejecuta: validar-segmentacion.sh [--full|--quick|--json]"
else
    log_skip "Validación de segmentación de red"
fi

# ============================================================
# S9: ZERO TRUST CONTINUOUS VERIFICATION
# ============================================================
log_section "S9: ZERO TRUST CONTINUOUS VERIFICATION"

echo "Verificación continua Zero Trust:"
echo "  - Cron job cada 15 minutos"
echo "  - Re-evaluación de postura del dispositivo"
echo "  - Detección de drift de políticas"
echo "  - Verificación de integridad de segmentación"
echo "  - Alertas por degradación"
echo ""

if check_executable /usr/local/bin/verificar-zt-continuo.sh; then
    log_already "Verificacion continua Zero Trust (verificar-zt-continuo.sh existe)"
elif ask "¿Configurar verificación continua Zero Trust?"; then

    log_info "Creando script de verificación continua..."

    # Script de verificación continua
    cat > /usr/local/bin/verificar-zt-continuo.sh << 'ZTVEREOF'
#!/bin/bash
# ============================================================
# verificar-zt-continuo.sh - Verificación continua Zero Trust
# Generado por securizar - Módulo 45
# ============================================================
# Ejecutado por cron cada 15 minutos
# ============================================================
set -uo pipefail

LOG="/var/log/securizar/zt-verificacion.log"
ALERT_LOG="/var/log/securizar/zt-alertas.log"
STATE_FILE="/var/lib/securizar/zt-state.json"

mkdir -p /var/log/securizar /var/lib/securizar

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG"; }
alert() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] ALERTA ZT: $1"
    echo "$msg" >> "$ALERT_LOG"
    echo "$msg" >> "$LOG"
    # Enviar al syslog
    logger -t securizar-zt -p auth.warning "$1" 2>/dev/null || true
}

log "=== Verificación ZT iniciada ==="

DEGRADATION=0
CHECKS_TOTAL=0
CHECKS_OK=0

check() {
    local name="$1" result="$2" detail="$3"
    ((CHECKS_TOTAL++)) || true
    if [[ "$result" == "ok" ]]; then
        ((CHECKS_OK++)) || true
        log "CHECK OK: $name - $detail"
    else
        log "CHECK FAIL: $name - $detail"
        alert "$name: $detail"
        ((DEGRADATION++)) || true
    fi
}

# --- Check 1: Firewall activo ---
fw_active=0
fw_detail=""
if systemctl is-active firewalld &>/dev/null 2>&1; then
    fw_active=1
    fw_detail="firewalld activo"
elif [[ "$(systemctl is-enabled firewalld 2>/dev/null)" == "masked" ]]; then
    fw_detail="firewalld masked"
    if nft list table inet firewalld &>/dev/null 2>&1; then
        fw_detail="$fw_detail + tabla huérfana en kernel"
    fi
fi

if [[ $fw_active -eq 0 ]]; then
    if ufw status 2>/dev/null | grep -q "active"; then
        fw_active=1
        fw_detail="${fw_detail:+$fw_detail; }ufw activo"
    elif command -v nft &>/dev/null && [[ $(nft list ruleset 2>/dev/null | wc -l) -gt 2 ]]; then
        fw_active=1
        fw_detail="${fw_detail:+$fw_detail; }nftables activo"
    fi
fi

if [[ $fw_active -eq 1 ]]; then
    check "firewall" "ok" "Firewall activo (${fw_detail})"
else
    check "firewall" "fail" "Firewall no detectado o inactivo${fw_detail:+ ($fw_detail)}"
fi

# --- Check 2: nftables zonas cargadas ---
if command -v nft &>/dev/null; then
    if nft list table inet securizar_zonas &>/dev/null 2>&1; then
        check "nftables_zonas" "ok" "Tabla securizar_zonas cargada"
    else
        check "nftables_zonas" "fail" "Tabla securizar_zonas no cargada"
    fi
else
    check "nftables_zonas" "fail" "nftables no disponible"
fi

# --- Check 3: Configuraciones no modificadas (drift) ---
for conf_file in /etc/securizar/zonas-red.conf /etc/securizar/politicas-interzona.conf /etc/securizar/microseg-servicios.conf; do
    if [[ -f "$conf_file" ]]; then
        hash_file="/var/lib/securizar/$(basename "$conf_file").sha256"
        current_hash=""
        current_hash=$(sha256sum "$conf_file" | awk '{print $1}')

        if [[ -f "$hash_file" ]]; then
            stored_hash=""
            stored_hash=$(cat "$hash_file" 2>/dev/null)
            if [[ "$current_hash" == "$stored_hash" ]]; then
                check "drift_$(basename "$conf_file")" "ok" "Sin cambios desde última verificación"
            else
                check "drift_$(basename "$conf_file")" "fail" "Archivo modificado desde última verificación"
                echo "$current_hash" > "$hash_file"
            fi
        else
            # Primera ejecución: guardar hash
            echo "$current_hash" > "$hash_file"
            check "drift_$(basename "$conf_file")" "ok" "Hash inicial registrado"
        fi
    fi
done

# --- Check 4: Postura del dispositivo ---
if [[ -x /usr/local/bin/evaluar-postura-dispositivo.sh ]]; then
    postura_score=""
    postura_score=$(/usr/local/bin/evaluar-postura-dispositivo.sh --quiet 2>/dev/null || echo "0")
    if [[ "$postura_score" -ge 70 ]]; then
        check "postura_dispositivo" "ok" "Puntuación: $postura_score/100"
    elif [[ "$postura_score" -ge 40 ]]; then
        check "postura_dispositivo" "fail" "Puntuación baja: $postura_score/100"
    else
        check "postura_dispositivo" "fail" "Puntuación crítica: $postura_score/100"
    fi
else
    check "postura_dispositivo" "fail" "Script de postura no instalado"
fi

# --- Check 5: Servicios SSH seguros ---
if systemctl is-active "$( [[ -f /etc/debian_version ]] && echo ssh || echo sshd )" &>/dev/null 2>&1; then
    if grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null; then
        check "ssh_seguro" "ok" "SSH con autenticación por clave"
    else
        check "ssh_seguro" "fail" "SSH permite autenticación por contraseña"
    fi
else
    check "ssh_seguro" "ok" "SSH no activo (no aplica)"
fi

# --- Check 6: Puertos inesperados abiertos ---
unexpected_ports=0
for port in $(ss -tlnp 2>/dev/null | awk 'NR>1 {print $4}' | grep -oP ':\K\d+$' | sort -un); do
    # Puertos esperados en un servidor seguro
    case "$port" in
        22|80|443|53|123|9090|9100|3000) ;; # Puertos conocidos
        *)
            if [[ "$port" -lt 1024 ]]; then
                ((unexpected_ports++)) || true
            fi
            ;;
    esac
done

if [[ $unexpected_ports -le 2 ]]; then
    check "puertos_inesperados" "ok" "$unexpected_ports puertos privilegiados inesperados"
else
    check "puertos_inesperados" "fail" "$unexpected_ports puertos privilegiados inesperados abiertos"
fi

# --- Check 7: Integridad PAM ---
if [[ -f /etc/security/access.conf ]]; then
    if grep -q "securizar" /etc/security/access.conf 2>/dev/null; then
        check "pam_access" "ok" "access.conf con reglas securizar"
    else
        check "pam_access" "fail" "access.conf sin reglas securizar"
    fi
else
    check "pam_access" "fail" "access.conf no existe"
fi

# --- Guardar estado ---
{
    echo "{"
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"checks_total\": $CHECKS_TOTAL,"
    echo "  \"checks_ok\": $CHECKS_OK,"
    echo "  \"degradation\": $DEGRADATION"
    echo "}"
} > "$STATE_FILE"

# --- Resumen ---
if [[ $DEGRADATION -gt 0 ]]; then
    alert "DEGRADACIÓN DETECTADA: $DEGRADATION de $CHECKS_TOTAL checks fallidos"
    log "Estado: DEGRADADO ($CHECKS_OK/$CHECKS_TOTAL OK)"
else
    log "Estado: CORRECTO ($CHECKS_OK/$CHECKS_TOTAL OK)"
fi

log "=== Verificación ZT completada ==="
ZTVEREOF
    chmod 0755 /usr/local/bin/verificar-zt-continuo.sh
    log_change "Creado" "/usr/local/bin/verificar-zt-continuo.sh"

    # Crear cron job
    log_info "Creando cron job de verificación continua..."

    cat > /etc/cron.d/securizar-zt-verify << 'CRONEOF'
# ============================================================
# securizar-zt-verify - Verificación continua Zero Trust
# Generado por securizar - Módulo 45
# ============================================================
# Ejecuta verificación ZT cada 15 minutos
SHELL=/bin/bash
PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin

*/15 * * * * root /usr/local/bin/verificar-zt-continuo.sh >/dev/null 2>&1
CRONEOF
    chmod 0644 /etc/cron.d/securizar-zt-verify
    log_change "Creado" "/etc/cron.d/securizar-zt-verify (cada 15 min)"

    log_info "Verificación continua Zero Trust configurada"
    log_info "Cron job: /etc/cron.d/securizar-zt-verify (cada 15 min)"
    log_info "Logs: /var/log/securizar/zt-verificacion.log"
    log_info "Alertas: /var/log/securizar/zt-alertas.log"
else
    log_skip "Verificación continua Zero Trust"
fi

# ============================================================
# S10: AUDITORÍA Y SCORING
# ============================================================
log_section "S10: AUDITORÍA Y SCORING"

echo "Auditoría integral de segmentación y Zero Trust:"
echo "  - Evaluación de: zonas, políticas, microseg, contenedores"
echo "  - Postura de dispositivo, identidad, monitorización"
echo "  - Puntuación global: BUENO / MEJORABLE / DEFICIENTE"
echo ""

if check_executable /usr/local/bin/auditoria-segmentacion-zt.sh; then
    log_already "Auditoria de segmentacion y ZT (auditoria-segmentacion-zt.sh existe)"
elif ask "¿Crear herramienta de auditoría de segmentación y ZT?"; then

    log_info "Creando script de auditoría integral..."

    cat > /usr/local/bin/auditoria-segmentacion-zt.sh << 'AUDITEOF'
#!/bin/bash
# ============================================================
# auditoria-segmentacion-zt.sh - Auditoría de segmentación y ZT
# Generado por securizar - Módulo 45
# ============================================================
# Uso: auditoria-segmentacion-zt.sh [--json|--verbose]
# ============================================================
set -uo pipefail

LOG="/var/log/securizar/auditoria-segmentacion-zt.log"
REPORT="/var/log/securizar/auditoria-segmentacion-zt.json"
mkdir -p /var/log/securizar

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG"; }

MODE="${1:---verbose}"

# Categorías y puntuaciones
declare -A CAT_SCORE
declare -A CAT_MAX
declare -A CAT_DETAIL

CATEGORIES=(
    "zonas_red"
    "politicas_interzona"
    "microsegmentacion"
    "aislamiento_contenedores"
    "postura_dispositivo"
    "acceso_identidad"
    "monitorizacion"
    "verificacion_continua"
)

for cat in "${CATEGORIES[@]}"; do
    CAT_SCORE[$cat]=0
    CAT_MAX[$cat]=0
    CAT_DETAIL[$cat]=""
done

# Función: puntuar check
score_check() {
    local category="$1" points="$2" max="$3" detail="$4"
    CAT_SCORE[$category]=$(( ${CAT_SCORE[$category]} + points ))
    CAT_MAX[$category]=$(( ${CAT_MAX[$category]} + max ))
    if [[ -n "${CAT_DETAIL[$category]}" ]]; then
        CAT_DETAIL[$category]="${CAT_DETAIL[$category]}; $detail"
    else
        CAT_DETAIL[$category]="$detail"
    fi
}

# === 1. Zonas de red ===
log "Auditando zonas de red..."

if [[ -f /etc/securizar/zonas-red.conf ]]; then
    num_zonas=$(grep -v '^#' /etc/securizar/zonas-red.conf | grep -v '^$' | cut -d'|' -f1 | sort -u | wc -l)
    if [[ $num_zonas -ge 4 ]]; then
        score_check "zonas_red" 10 10 "$num_zonas zonas definidas"
    elif [[ $num_zonas -ge 2 ]]; then
        score_check "zonas_red" 5 10 "Solo $num_zonas zonas (recomendado: 4+)"
    else
        score_check "zonas_red" 0 10 "Pocas zonas: $num_zonas"
    fi
else
    score_check "zonas_red" 0 10 "Sin configuración de zonas"
fi

if [[ -f /etc/nftables.d/securizar-zonas.nft ]]; then
    score_check "zonas_red" 5 5 "Reglas nftables de zonas creadas"
else
    score_check "zonas_red" 0 5 "Sin reglas nftables de zonas"
fi

if command -v nft &>/dev/null && nft list table inet securizar_zonas &>/dev/null 2>&1; then
    score_check "zonas_red" 5 5 "Tabla securizar_zonas cargada"
else
    score_check "zonas_red" 0 5 "Tabla securizar_zonas no cargada"
fi

# === 2. Políticas inter-zona ===
log "Auditando políticas inter-zona..."

if [[ -f /etc/securizar/politicas-interzona.conf ]]; then
    num_pol=$(grep -v '^#' /etc/securizar/politicas-interzona.conf | grep -v '^$' | grep -v "^DEFAULT" | wc -l)
    score_check "politicas_interzona" 10 10 "$num_pol políticas definidas"
else
    score_check "politicas_interzona" 0 10 "Sin políticas inter-zona"
fi

if [[ -x /usr/local/bin/aplicar-politicas-zona.sh ]]; then
    score_check "politicas_interzona" 5 5 "Script de aplicación instalado"
else
    score_check "politicas_interzona" 0 5 "Script de aplicación no instalado"
fi

# Forward policy
if command -v nft &>/dev/null; then
    if nft list ruleset 2>/dev/null | grep "policy drop" >/dev/null 2>&1; then
        score_check "politicas_interzona" 5 5 "Default policy DROP"
    else
        score_check "politicas_interzona" 0 5 "Default policy no es DROP"
    fi
else
    score_check "politicas_interzona" 0 5 "No se puede verificar policy"
fi

# === 3. Microsegmentación ===
log "Auditando microsegmentación..."

if [[ -f /etc/securizar/microseg-servicios.conf ]]; then
    num_svcs=$(grep -v '^#' /etc/securizar/microseg-servicios.conf | grep -v '^$' | wc -l)
    score_check "microsegmentacion" 10 10 "$num_svcs servicios microsegmentados"
else
    score_check "microsegmentacion" 0 10 "Sin microsegmentación"
fi

if [[ -x /usr/local/bin/microsegmentar-servicio.sh ]]; then
    score_check "microsegmentacion" 5 5 "Script de microsegmentación instalado"
else
    score_check "microsegmentacion" 0 5 "Script no instalado"
fi

# === 4. Aislamiento de contenedores ===
log "Auditando aislamiento de contenedores..."

container_engine=""
if command -v docker &>/dev/null; then
    container_engine="docker"
elif command -v podman &>/dev/null; then
    container_engine="podman"
fi

if [[ -n "$container_engine" ]]; then
    # Verificar redes internas
    internal_nets=$($container_engine network ls -q 2>/dev/null | while read -r net; do
        internal=$($container_engine network inspect "$net" --format '{{.Internal}}' 2>/dev/null)
        [[ "$internal" == "true" ]] && echo "$net"
    done | wc -l)

    if [[ $internal_nets -gt 0 ]]; then
        score_check "aislamiento_contenedores" 10 10 "$internal_nets redes internas encontradas"
    else
        score_check "aislamiento_contenedores" 0 10 "Sin redes internas de contenedores"
    fi

    # Verificar ICC deshabilitado (Docker)
    if [[ "$container_engine" == "docker" ]] && [[ -f /etc/docker/daemon.json ]]; then
        if grep -q '"icc".*false' /etc/docker/daemon.json 2>/dev/null; then
            score_check "aislamiento_contenedores" 5 5 "ICC deshabilitado"
        else
            score_check "aislamiento_contenedores" 0 5 "ICC habilitado o no configurado"
        fi
    else
        score_check "aislamiento_contenedores" 3 5 "Podman (aislamiento nativo)"
    fi
else
    score_check "aislamiento_contenedores" 5 5 "Sin motor de contenedores (N/A)"
    CAT_MAX["aislamiento_contenedores"]=5
fi

if [[ -x /usr/local/bin/aislar-contenedores-red.sh ]]; then
    score_check "aislamiento_contenedores" 5 5 "Script de aislamiento instalado"
else
    score_check "aislamiento_contenedores" 0 5 "Script no instalado"
fi

# === 5. Postura del dispositivo ===
log "Auditando evaluación de postura..."

if [[ -x /usr/local/bin/evaluar-postura-dispositivo.sh ]]; then
    score_check "postura_dispositivo" 5 5 "Script de postura instalado"

    if [[ -f /var/log/securizar/postura-dispositivo.json ]]; then
        postura_score=$(grep '"score"' /var/log/securizar/postura-dispositivo.json 2>/dev/null | grep -oP '\d+' | head -1 || echo "0")
        if [[ "${postura_score:-0}" -ge 70 ]]; then
            score_check "postura_dispositivo" 10 10 "Postura: $postura_score/100"
        elif [[ "${postura_score:-0}" -ge 40 ]]; then
            score_check "postura_dispositivo" 5 10 "Postura mejorable: $postura_score/100"
        else
            score_check "postura_dispositivo" 0 10 "Postura baja: $postura_score/100"
        fi
    else
        score_check "postura_dispositivo" 0 10 "Sin reporte de postura (ejecutar evaluar-postura-dispositivo.sh)"
    fi
else
    score_check "postura_dispositivo" 0 15 "Script de postura no instalado"
fi

# === 6. Acceso por identidad ===
log "Auditando control de acceso por identidad..."

if [[ -f /etc/securizar/acceso-identidad.conf ]]; then
    score_check "acceso_identidad" 5 5 "Configuración de identidad existe"
else
    score_check "acceso_identidad" 0 5 "Sin configuración de identidad"
fi

if [[ -f /etc/security/access.conf ]] && grep -q "securizar" /etc/security/access.conf 2>/dev/null; then
    score_check "acceso_identidad" 5 5 "PAM access.conf configurado"
else
    score_check "acceso_identidad" 0 5 "PAM access.conf sin reglas securizar"
fi

if [[ -x /usr/local/bin/aplicar-acceso-identidad.sh ]]; then
    score_check "acceso_identidad" 5 5 "Script de identidad instalado"
else
    score_check "acceso_identidad" 0 5 "Script de identidad no instalado"
fi

# === 7. Monitorización ===
log "Auditando monitorización..."

if [[ -x /usr/local/bin/monitorizar-trafico-zonas.sh ]]; then
    score_check "monitorizacion" 5 5 "Script de monitorización instalado"
else
    score_check "monitorizacion" 0 5 "Script de monitorización no instalado"
fi

if command -v conntrack &>/dev/null; then
    score_check "monitorizacion" 5 5 "conntrack disponible"
else
    score_check "monitorizacion" 0 5 "conntrack no disponible"
fi

if command -v tcpdump &>/dev/null; then
    score_check "monitorizacion" 5 5 "tcpdump disponible"
else
    score_check "monitorizacion" 0 5 "tcpdump no disponible"
fi

# === 8. Verificación continua ===
log "Auditando verificación continua..."

if [[ -f /etc/cron.d/securizar-zt-verify ]]; then
    score_check "verificacion_continua" 5 5 "Cron job ZT instalado"
else
    score_check "verificacion_continua" 0 5 "Cron job ZT no instalado"
fi

if [[ -x /usr/local/bin/verificar-zt-continuo.sh ]]; then
    score_check "verificacion_continua" 5 5 "Script de verificación instalado"
else
    score_check "verificacion_continua" 0 5 "Script de verificación no instalado"
fi

if [[ -f /var/lib/securizar/zt-state.json ]]; then
    score_check "verificacion_continua" 5 5 "Estado ZT registrado"
else
    score_check "verificacion_continua" 0 5 "Sin estado ZT registrado (ejecutar verificar-zt-continuo.sh)"
fi

# === Calcular puntuación global ===
SCORE_TOTAL=0
SCORE_MAX=0
for cat in "${CATEGORIES[@]}"; do
    SCORE_TOTAL=$(( SCORE_TOTAL + ${CAT_SCORE[$cat]} ))
    SCORE_MAX=$(( SCORE_MAX + ${CAT_MAX[$cat]} ))
done

if [[ $SCORE_MAX -gt 0 ]]; then
    SCORE_PERCENT=$(( (SCORE_TOTAL * 100) / SCORE_MAX ))
else
    SCORE_PERCENT=0
fi

# Determinar nivel
NIVEL="DEFICIENTE"
if [[ $SCORE_PERCENT -ge 75 ]]; then
    NIVEL="BUENO"
elif [[ $SCORE_PERCENT -ge 45 ]]; then
    NIVEL="MEJORABLE"
fi

# === Salida ===
if [[ "$MODE" == "--json" ]]; then
    {
        echo "{"
        echo "  \"timestamp\": \"$(date -Iseconds)\","
        echo "  \"hostname\": \"$(hostname)\","
        echo "  \"score_total\": $SCORE_TOTAL,"
        echo "  \"score_max\": $SCORE_MAX,"
        echo "  \"score_percent\": $SCORE_PERCENT,"
        echo "  \"nivel\": \"$NIVEL\","
        echo "  \"categories\": {"
        idx=0
        for cat in "${CATEGORIES[@]}"; do
            idx=$((idx + 1))
            comma=","
            [[ $idx -eq ${#CATEGORIES[@]} ]] && comma=""
            echo "    \"$cat\": {"
            echo "      \"score\": ${CAT_SCORE[$cat]},"
            echo "      \"max\": ${CAT_MAX[$cat]},"
            echo "      \"detail\": \"${CAT_DETAIL[$cat]}\""
            echo "    }$comma"
        done
        echo "  }"
        echo "}"
    } | tee "$REPORT"
else
    echo ""
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║   AUDITORÍA DE SEGMENTACIÓN DE RED Y ZERO TRUST          ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo ""
    echo "  Host: $(hostname)"
    echo "  Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""

    printf "  %-30s %6s / %-6s  %s\n" "CATEGORÍA" "SCORE" "MAX" "DETALLE"
    echo "  $(printf '%.0s─' {1..80})"

    for cat in "${CATEGORIES[@]}"; do
        s=${CAT_SCORE[$cat]}
        m=${CAT_MAX[$cat]}
        d="${CAT_DETAIL[$cat]}"
        icon="[X]"
        if [[ $m -gt 0 ]]; then
            pct=$(( (s * 100) / m ))
            [[ $pct -ge 75 ]] && icon="[+]"
            [[ $pct -ge 45 && $pct -lt 75 ]] && icon="[!]"
        fi
        # Truncar detalle
        [[ ${#d} -gt 40 ]] && d="${d:0:37}..."
        printf "  %-4s %-26s %3d / %-3d     %s\n" "$icon" "$cat" "$s" "$m" "$d"
    done

    echo ""
    echo "  ════════════════════════════════════════════════════════"
    echo "  PUNTUACIÓN GLOBAL: $SCORE_TOTAL/$SCORE_MAX ($SCORE_PERCENT%) - $NIVEL"
    echo "  ════════════════════════════════════════════════════════"
    echo ""

    case "$NIVEL" in
        BUENO)
            echo "  Estado: BUENO"
            echo "  La segmentación de red y los controles Zero Trust están"
            echo "  correctamente implementados."
            ;;
        MEJORABLE)
            echo "  Estado: MEJORABLE"
            echo "  Hay controles parcialmente implementados. Revise las"
            echo "  categorías con puntuación baja y aplique las mejoras."
            ;;
        DEFICIENTE)
            echo "  Estado: DEFICIENTE"
            echo "  La segmentación de red y Zero Trust requieren atención"
            echo "  inmediata. Ejecute los scripts de configuración."
            ;;
    esac

    echo ""
    echo "  Reporte JSON: auditoria-segmentacion-zt.sh --json"
fi

log "=== Auditoría completada: $SCORE_PERCENT% ($NIVEL) ==="
AUDITEOF
    chmod 0755 /usr/local/bin/auditoria-segmentacion-zt.sh
    log_change "Creado" "/usr/local/bin/auditoria-segmentacion-zt.sh"

    log_info "Herramienta de auditoría integral instalada"
    log_info "Ejecuta: auditoria-segmentacion-zt.sh [--verbose|--json]"
else
    log_skip "Auditoría de segmentación y ZT"
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
show_changes_summary
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     SEGMENTACIÓN DE RED Y ZERO TRUST COMPLETADO          ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups guardados en: $BACKUP_DIR"
echo ""
echo "Comandos útiles post-configuración:"
echo "  - Aplicar políticas:     aplicar-politicas-zona.sh"
echo "  - Microsegmentar:        microsegmentar-servicio.sh <svc|all>"
echo "  - Aislar contenedores:   aislar-contenedores-red.sh --audit"
echo "  - Evaluar postura:       evaluar-postura-dispositivo.sh"
echo "  - Control identidad:     aplicar-acceso-identidad.sh --audit"
echo "  - Monitor tráfico:       monitorizar-trafico-zonas.sh --report"
echo "  - Validar segmentación:  validar-segmentacion.sh"
echo "  - Verificación ZT:       verificar-zt-continuo.sh"
echo "  - Auditoría completa:    auditoria-segmentacion-zt.sh"
echo ""
log_warn "RECOMENDACIÓN: Ejecuta 'auditoria-segmentacion-zt.sh' para ver la postura actual"
log_info "Módulo 45 completado"
echo ""
