#!/bin/bash
# ============================================================
# securizar-firewall.sh - Abstraccion de firewall multi-backend
# ============================================================
# Detecta: firewalld > ufw > nftables > iptables
# Exporta: FW_BACKEND
# ============================================================

[[ -n "${_SECURIZAR_FIREWALL_LOADED:-}" ]] && return 0
_SECURIZAR_FIREWALL_LOADED=1

# ── Deteccion de backend ───────────────────────────────────
# Permite override via securizar.conf
if [[ -z "${SECURIZAR_FW_BACKEND:-}" ]]; then
    if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null 2>&1; then
        FW_BACKEND="firewalld"
    elif command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "active"; then
        FW_BACKEND="ufw"
    elif command -v nft &>/dev/null; then
        FW_BACKEND="nftables"
    elif command -v iptables &>/dev/null; then
        FW_BACKEND="iptables"
    else
        FW_BACKEND="none"
    fi
else
    FW_BACKEND="$SECURIZAR_FW_BACKEND"
fi

export FW_BACKEND

# ── fw_is_active ────────────────────────────────────────────
fw_is_active() {
    case "$FW_BACKEND" in
        firewalld) systemctl is-active firewalld &>/dev/null ;;
        ufw)       ufw status 2>/dev/null | grep -q "active" ;;
        nftables)  nft list ruleset &>/dev/null ;;
        iptables)  iptables -L &>/dev/null ;;
        *)         return 1 ;;
    esac
}

# ── fw_add_service service [zone] ──────────────────────────
fw_add_service() {
    local service="$1"
    local zone="${2:-}"

    case "$FW_BACKEND" in
        firewalld)
            if [[ -n "$zone" ]]; then
                firewall-cmd --permanent --zone="$zone" --add-service="$service" 2>/dev/null || true
            else
                firewall-cmd --permanent --add-service="$service" 2>/dev/null || true
            fi
            ;;
        ufw)
            ufw allow "$service" 2>/dev/null || true
            ;;
        nftables)
            echo "AVISO: Agrega manualmente regla nftables para servicio $service" >&2
            ;;
        iptables)
            echo "AVISO: Agrega manualmente regla iptables para servicio $service" >&2
            ;;
    esac
}

# ── fw_remove_service service [zone] ───────────────────────
fw_remove_service() {
    local service="$1"
    local zone="${2:-}"

    case "$FW_BACKEND" in
        firewalld)
            if [[ -n "$zone" ]]; then
                firewall-cmd --permanent --zone="$zone" --remove-service="$service" 2>/dev/null || true
            else
                firewall-cmd --permanent --remove-service="$service" 2>/dev/null || true
            fi
            ;;
        ufw)
            ufw delete allow "$service" 2>/dev/null || true
            ;;
        nftables|iptables)
            echo "AVISO: Elimina manualmente regla para servicio $service" >&2
            ;;
    esac
}

# ── fw_add_port port [zone] ────────────────────────────────
# port en formato "80/tcp" o "443/tcp"
fw_add_port() {
    local port="$1"
    local zone="${2:-}"

    case "$FW_BACKEND" in
        firewalld)
            if [[ -n "$zone" ]]; then
                firewall-cmd --permanent --zone="$zone" --add-port="$port" 2>/dev/null || true
            else
                firewall-cmd --permanent --add-port="$port" 2>/dev/null || true
            fi
            ;;
        ufw)
            local p proto
            p="${port%%/*}"
            proto="${port##*/}"
            ufw allow "$p/$proto" 2>/dev/null || true
            ;;
        nftables|iptables)
            echo "AVISO: Agrega manualmente regla para puerto $port" >&2
            ;;
    esac
}

# ── fw_remove_port port [zone] ─────────────────────────────
fw_remove_port() {
    local port="$1"
    local zone="${2:-}"

    case "$FW_BACKEND" in
        firewalld)
            if [[ -n "$zone" ]]; then
                firewall-cmd --permanent --zone="$zone" --remove-port="$port" 2>/dev/null || true
            else
                firewall-cmd --permanent --remove-port="$port" 2>/dev/null || true
            fi
            ;;
        ufw)
            local p proto
            p="${port%%/*}"
            proto="${port##*/}"
            ufw delete allow "$p/$proto" 2>/dev/null || true
            ;;
        nftables|iptables)
            echo "AVISO: Elimina manualmente regla para puerto $port" >&2
            ;;
    esac
}

# ── fw_add_rich_rule rule [zone] ────────────────────────────
# Acepta reglas en formato firewalld rich rule
# En ufw traduce los patrones mas comunes automaticamente
fw_add_rich_rule() {
    local rule="$1"
    local zone="${2:-}"

    case "$FW_BACKEND" in
        firewalld)
            if [[ -n "$zone" ]]; then
                firewall-cmd --permanent --zone="$zone" --add-rich-rule="$rule" 2>/dev/null || true
            else
                firewall-cmd --permanent --add-rich-rule="$rule" 2>/dev/null || true
            fi
            ;;
        ufw)
            _fw_rich_rule_to_ufw "$rule"
            ;;
        nftables)
            _fw_rich_rule_to_nft "$rule"
            ;;
        iptables)
            echo "AVISO: Traduce manualmente rich rule a iptables: $rule" >&2
            ;;
    esac
}

# ── fw_remove_rich_rule rule [zone] ─────────────────────────
fw_remove_rich_rule() {
    local rule="$1"
    local zone="${2:-}"

    case "$FW_BACKEND" in
        firewalld)
            if [[ -n "$zone" ]]; then
                firewall-cmd --permanent --zone="$zone" --remove-rich-rule="$rule" 2>/dev/null || true
            else
                firewall-cmd --permanent --remove-rich-rule="$rule" 2>/dev/null || true
            fi
            ;;
        ufw)
            # Attempt to remove the equivalent ufw rule
            _fw_rich_rule_to_ufw_delete "$rule"
            ;;
        nftables|iptables)
            echo "AVISO: Elimina manualmente rich rule: $rule" >&2
            ;;
    esac
}

# ── fw_query_rich_rule rule [zone] ──────────────────────────
fw_query_rich_rule() {
    local rule="$1"
    local zone="${2:-}"

    case "$FW_BACKEND" in
        firewalld)
            if [[ -n "$zone" ]]; then
                firewall-cmd --zone="$zone" --query-rich-rule="$rule" 2>/dev/null
            else
                firewall-cmd --query-rich-rule="$rule" 2>/dev/null
            fi
            ;;
        ufw)
            ufw status numbered 2>/dev/null | grep -q "$(echo "$rule" | grep -oP 'address="[^"]*"' | grep -oP '"[^"]*"' | tr -d '"')" 2>/dev/null
            ;;
        *)
            return 1
            ;;
    esac
}

# ── fw_set_default_zone zone ───────────────────────────────
fw_set_default_zone() {
    local zone="$1"

    case "$FW_BACKEND" in
        firewalld)
            firewall-cmd --set-default-zone="$zone" 2>/dev/null || true
            ;;
        ufw)
            case "$zone" in
                drop)   ufw default deny incoming 2>/dev/null; ufw default deny outgoing 2>/dev/null ;;
                public) ufw default deny incoming 2>/dev/null; ufw default allow outgoing 2>/dev/null ;;
                *)      ufw default deny incoming 2>/dev/null ;;
            esac
            ;;
        nftables|iptables)
            echo "AVISO: Configura manualmente la politica por defecto" >&2
            ;;
    esac
}

# ── fw_get_default_zone ────────────────────────────────────
fw_get_default_zone() {
    case "$FW_BACKEND" in
        firewalld) firewall-cmd --get-default-zone 2>/dev/null ;;
        ufw)       ufw status verbose 2>/dev/null | grep "Default:" | head -1 ;;
        *)         echo "unknown" ;;
    esac
}

# ── fw_new_zone zone ───────────────────────────────────────
fw_new_zone() {
    local zone="$1"

    case "$FW_BACKEND" in
        firewalld)
            firewall-cmd --permanent --new-zone="$zone" 2>/dev/null || true
            ;;
        ufw)
            # UFW no tiene zonas; las reglas se aplican globalmente
            echo "INFO: UFW no soporta zonas. Reglas se aplican globalmente." >&2
            ;;
        nftables|iptables)
            echo "AVISO: Crea manualmente cadena/tabla para zona $zone" >&2
            ;;
    esac
}

# ── fw_zone_set_target zone target ─────────────────────────
fw_zone_set_target() {
    local zone="$1"
    local target="$2"

    case "$FW_BACKEND" in
        firewalld)
            firewall-cmd --permanent --zone="$zone" --set-target="$target" 2>/dev/null || true
            ;;
        ufw)
            echo "INFO: UFW no soporta targets por zona" >&2
            ;;
        *)
            echo "AVISO: Configura manualmente target para $zone" >&2
            ;;
    esac
}

# ── fw_set_log_denied value ─────────────────────────────────
fw_set_log_denied() {
    local value="${1:-all}"

    case "$FW_BACKEND" in
        firewalld)
            firewall-cmd --set-log-denied="$value" 2>/dev/null || true
            ;;
        ufw)
            case "$value" in
                all|unicast) ufw logging high 2>/dev/null || true ;;
                off)         ufw logging off 2>/dev/null || true ;;
                *)           ufw logging medium 2>/dev/null || true ;;
            esac
            ;;
        nftables|iptables)
            echo "AVISO: Configura manualmente logging de paquetes denegados" >&2
            ;;
    esac
}

# ── fw_get_log_denied ───────────────────────────────────────
fw_get_log_denied() {
    case "$FW_BACKEND" in
        firewalld) firewall-cmd --get-log-denied 2>/dev/null ;;
        ufw)       ufw status verbose 2>/dev/null | grep "Logging:" ;;
        *)         echo "unknown" ;;
    esac
}

# ── fw_reload ───────────────────────────────────────────────
fw_reload() {
    case "$FW_BACKEND" in
        firewalld) firewall-cmd --reload 2>/dev/null || true ;;
        ufw)       ufw reload 2>/dev/null || true ;;
        nftables)  systemctl reload nftables 2>/dev/null || nft -f /etc/nftables.conf 2>/dev/null || true ;;
        iptables)  true ;;  # iptables no tiene reload
    esac
}

# ── fw_list_all ─────────────────────────────────────────────
fw_list_all() {
    case "$FW_BACKEND" in
        firewalld) firewall-cmd --list-all 2>/dev/null ;;
        ufw)       ufw status verbose 2>/dev/null ;;
        nftables)  nft list ruleset 2>/dev/null ;;
        iptables)  iptables -L -n -v 2>/dev/null ;;
        *)         echo "Sin firewall activo" ;;
    esac
}

# ── fw_list_all_zones ──────────────────────────────────────
fw_list_all_zones() {
    case "$FW_BACKEND" in
        firewalld) firewall-cmd --list-all-zones 2>/dev/null ;;
        ufw)       ufw status verbose 2>/dev/null ;;
        nftables)  nft list ruleset 2>/dev/null ;;
        iptables)  iptables -L -n -v 2>/dev/null ;;
        *)         echo "Sin firewall activo" ;;
    esac
}

# ── fw_list_rich_rules [zone] ──────────────────────────────
fw_list_rich_rules() {
    local zone="${1:-}"

    case "$FW_BACKEND" in
        firewalld)
            if [[ -n "$zone" ]]; then
                firewall-cmd --zone="$zone" --list-rich-rules 2>/dev/null
            else
                firewall-cmd --list-rich-rules 2>/dev/null
            fi
            ;;
        ufw)
            ufw status numbered 2>/dev/null
            ;;
        *)
            echo "No disponible para $FW_BACKEND"
            ;;
    esac
}

# ── fw_list_services [zone] ────────────────────────────────
fw_list_services() {
    local zone="${1:-}"

    case "$FW_BACKEND" in
        firewalld)
            if [[ -n "$zone" ]]; then
                firewall-cmd --zone="$zone" --list-services 2>/dev/null
            else
                firewall-cmd --list-services 2>/dev/null
            fi
            ;;
        ufw)
            ufw status 2>/dev/null | grep -E "ALLOW|DENY"
            ;;
        *)
            echo "No disponible para $FW_BACKEND"
            ;;
    esac
}

# ── fw_get_active_zones ────────────────────────────────────
fw_get_active_zones() {
    case "$FW_BACKEND" in
        firewalld) firewall-cmd --get-active-zones 2>/dev/null ;;
        ufw)       ufw status verbose 2>/dev/null ;;
        *)         echo "No disponible para $FW_BACKEND" ;;
    esac
}

# ── fw_add_icmp_block type ──────────────────────────────────
fw_add_icmp_block() {
    local icmp_type="$1"

    case "$FW_BACKEND" in
        firewalld)
            firewall-cmd --permanent --add-icmp-block="$icmp_type" 2>/dev/null || true
            ;;
        ufw)
            # UFW no tiene bloqueo ICMP nativo, usar iptables
            ufw deny proto icmp 2>/dev/null || true
            ;;
        nftables|iptables)
            echo "AVISO: Bloquea manualmente ICMP type $icmp_type" >&2
            ;;
    esac
}

# ── fw_direct_add_rule family table chain priority args... ──
# Passthrough para reglas directas (iptables)
# Solo funciona con firewalld; en otros backends usa iptables nativo
fw_direct_add_rule() {
    local family="$1"
    local table="$2"
    local chain="$3"
    local priority="$4"
    shift 4

    case "$FW_BACKEND" in
        firewalld)
            firewall-cmd --permanent --direct --add-rule "$family" "$table" "$chain" "$priority" "$@" 2>/dev/null || true
            ;;
        ufw|nftables)
            # Fallback: usar iptables directamente
            if [[ "$family" == "ipv4" ]] && command -v iptables &>/dev/null; then
                iptables -A "$chain" "$@" 2>/dev/null || true
            elif [[ "$family" == "ipv6" ]] && command -v ip6tables &>/dev/null; then
                ip6tables -A "$chain" "$@" 2>/dev/null || true
            fi
            ;;
        iptables)
            if [[ "$family" == "ipv4" ]]; then
                iptables -A "$chain" "$@" 2>/dev/null || true
            elif [[ "$family" == "ipv6" ]]; then
                ip6tables -A "$chain" "$@" 2>/dev/null || true
            fi
            ;;
    esac
}

# ── fw_direct_query_rule family table chain priority args... ──
# Verifica si una regla directa existe. Return 0 si existe, 1 si no.
fw_direct_query_rule() {
    local family="$1"
    local table="$2"
    local chain="$3"
    local priority="$4"
    shift 4

    case "$FW_BACKEND" in
        firewalld)
            firewall-cmd --permanent --direct --query-rule "$family" "$table" "$chain" "$priority" "$@" 2>/dev/null
            ;;
        ufw|nftables|iptables)
            # Usar iptables -C (check) para verificar si la regla existe
            if [[ "$family" == "ipv4" ]] && command -v iptables &>/dev/null; then
                iptables -C "$chain" "$@" 2>/dev/null
            elif [[ "$family" == "ipv6" ]] && command -v ip6tables &>/dev/null; then
                ip6tables -C "$chain" "$@" 2>/dev/null
            else
                return 1
            fi
            ;;
        *) return 1 ;;
    esac
}

# ── fw_direct_get_all_rules ─────────────────────────────────
fw_direct_get_all_rules() {
    case "$FW_BACKEND" in
        firewalld) firewall-cmd --direct --get-all-rules 2>/dev/null ;;
        ufw)       iptables -L -n -v 2>/dev/null ;;
        nftables)  nft list ruleset 2>/dev/null ;;
        iptables)  iptables -L -n -v 2>/dev/null ;;
        *)         echo "Sin firewall activo" ;;
    esac
}

# ── fw_runtime_add_rich_rule rule ───────────────────────────
# Agrega rich rule solo en runtime (no permanente)
fw_runtime_add_rich_rule() {
    local rule="$1"

    case "$FW_BACKEND" in
        firewalld)
            firewall-cmd --add-rich-rule="$rule" 2>/dev/null || true
            ;;
        ufw)
            _fw_rich_rule_to_ufw "$rule"
            ;;
        *)
            echo "AVISO: Backend $FW_BACKEND no soporta reglas runtime" >&2
            ;;
    esac
}

# ── fw_runtime_remove_rich_rule rule ────────────────────────
fw_runtime_remove_rich_rule() {
    local rule="$1"

    case "$FW_BACKEND" in
        firewalld)
            firewall-cmd --remove-rich-rule="$rule" 2>/dev/null || true
            ;;
        ufw)
            _fw_rich_rule_to_ufw_delete "$rule"
            ;;
        *)
            echo "AVISO: Backend $FW_BACKEND no soporta reglas runtime" >&2
            ;;
    esac
}

# ── Funciones internas de traduccion ────────────────────────

# Traduce rich rule comun a comando ufw
_fw_rich_rule_to_ufw() {
    local rule="$1"

    # Patron: source address drop
    if echo "$rule" | grep -qP "source address=\"([^\"]+)\".*drop"; then
        local addr
        addr=$(echo "$rule" | grep -oP 'address="[^"]*"' | grep -oP '"[^"]*"' | tr -d '"')
        ufw deny from "$addr" 2>/dev/null || true
        return
    fi

    # Patron: source address + port accept/drop
    if echo "$rule" | grep -qP "source address=\"([^\"]+)\".*port.*port=\"([^\"]+)\""; then
        local addr port action proto
        addr=$(echo "$rule" | grep -oP 'source address="[^"]*"' | grep -oP '"[^"]*"' | tr -d '"')
        port=$(echo "$rule" | grep -oP 'port="[^"]*"' | head -1 | grep -oP '"[^"]*"' | tr -d '"')
        proto=$(echo "$rule" | grep -oP 'protocol="[^"]*"' | grep -oP '"[^"]*"' | tr -d '"')
        [[ -z "$proto" ]] && proto="tcp"
        if echo "$rule" | grep -q "drop"; then
            ufw deny from "$addr" to any port "$port" proto "$proto" 2>/dev/null || true
        elif echo "$rule" | grep -q "accept"; then
            ufw allow from "$addr" to any port "$port" proto "$proto" 2>/dev/null || true
        fi
        return
    fi

    # Patron: service con limit
    if echo "$rule" | grep -qP "service name=\"([^\"]+)\".*limit"; then
        local svc
        svc=$(echo "$rule" | grep -oP 'service name="[^"]*"' | grep -oP '"[^"]*"' | tr -d '"')
        ufw limit "$svc" 2>/dev/null || true
        return
    fi

    # Patron: service accept
    if echo "$rule" | grep -qP "service name=\"([^\"]+)\".*accept"; then
        local svc
        svc=$(echo "$rule" | grep -oP 'service name="[^"]*"' | grep -oP '"[^"]*"' | tr -d '"')
        ufw allow "$svc" 2>/dev/null || true
        return
    fi

    # Patron: source address drop (simple)
    if echo "$rule" | grep -qP "source address=\"([^\"]+)\""; then
        local addr
        addr=$(echo "$rule" | grep -oP 'address="[^"]*"' | grep -oP '"[^"]*"' | tr -d '"')
        if echo "$rule" | grep -q "drop"; then
            ufw deny from "$addr" 2>/dev/null || true
        elif echo "$rule" | grep -q "accept"; then
            ufw allow from "$addr" 2>/dev/null || true
        fi
        return
    fi

    # Patron: protocol limit accept (ICMP etc)
    if echo "$rule" | grep -qP "protocol value=\"([^\"]+)\".*limit"; then
        # UFW no soporta rate limiting nativo para protocolos arbitrarios
        echo "AVISO: Regla de rate-limit no soportada directamente en UFW: $rule" >&2
        return
    fi

    # Patron: limit general
    if echo "$rule" | grep -qP "limit value=\"([^\"]+)\".*accept"; then
        echo "AVISO: Regla de rate-limit general no soportada directamente en UFW: $rule" >&2
        return
    fi

    echo "AVISO: Rich rule no traducida a UFW: $rule" >&2
}

_fw_rich_rule_to_ufw_delete() {
    local rule="$1"

    # Patron: source address drop
    if echo "$rule" | grep -qP "source address=\"([^\"]+)\".*drop"; then
        local addr
        addr=$(echo "$rule" | grep -oP 'address="[^"]*"' | grep -oP '"[^"]*"' | tr -d '"')
        ufw delete deny from "$addr" 2>/dev/null || true
        return
    fi

    # Patron: source address accept
    if echo "$rule" | grep -qP "source address=\"([^\"]+)\".*accept"; then
        local addr
        addr=$(echo "$rule" | grep -oP 'address="[^"]*"' | grep -oP '"[^"]*"' | tr -d '"')
        ufw delete allow from "$addr" 2>/dev/null || true
        return
    fi

    echo "AVISO: No se pudo eliminar rich rule en UFW: $rule" >&2
}

_fw_rich_rule_to_nft() {
    local rule="$1"
    echo "AVISO: Traduce manualmente rich rule a nftables: $rule" >&2
}
