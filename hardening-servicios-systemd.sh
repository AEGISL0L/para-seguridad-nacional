#!/bin/bash
# ============================================================
# SANDBOXING DE SERVICIOS SYSTEMD - Linux Multi-Distro
# ============================================================
# Secciones:
#   S1 - Analizar seguridad con systemd-analyze security
#   S2 - Drop-in para sshd
#   S3 - Drop-in para fail2ban
#   S4 - Drop-in para firewalld
#   S5 - Drop-in para NetworkManager
#   S6 - Drop-in para security-monitor (si existe)
#   S7 - Script de análisis permanente
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "hardening-servicios-systemd"
securizar_setup_traps
log_section "S1: ANÁLISIS DE SEGURIDAD DE SERVICIOS"

log_info "Ejecutando systemd-analyze security..."
echo ""

if command -v systemd-analyze &>/dev/null; then
    # Mostrar servicios con peor puntuación
    echo -e "${BOLD}Servicios con peor puntuación de seguridad:${NC}"
    systemd-analyze security 2>/dev/null | head -30 | while IFS= read -r line; do
        if echo "$line" | grep -q "UNSAFE\|EXPOSED"; then
            echo -e "  ${RED}$line${NC}"
        elif echo "$line" | grep -q "MEDIUM"; then
            echo -e "  ${YELLOW}$line${NC}"
        elif echo "$line" | grep -q "OK\|SAFE"; then
            echo -e "  ${GREEN}$line${NC}"
        else
            echo "  $line"
        fi
    done
    echo ""
    log_info "Análisis completo. Los drop-ins mejorarán las puntuaciones."
else
    log_error "systemd-analyze no disponible"
fi

# ============================================================
# S2: Drop-in para sshd
# ============================================================
log_section "S2: SANDBOXING DE SSHD"

echo "Configuración de sandboxing para sshd:"
echo "  PrivateTmp=yes           - Directorio /tmp aislado"
echo "  NoNewPrivileges=yes      - Sin escalación de privilegios"
echo "  ProtectSystem=strict     - Sistema de archivos de solo lectura"
echo "  ProtectHome=read-only    - Home de solo lectura"
echo "  ProtectKernelTunables=yes"
echo "  ProtectKernelModules=yes"
echo "  ProtectControlGroups=yes"
echo "  RestrictNamespaces=yes"
echo "  RestrictRealtime=yes"
echo "  RestrictSUIDSGID=yes"
echo ""

if systemctl list-unit-files "${SSH_SERVICE_NAME}.service" &>/dev/null 2>&1; then
    if ask "¿Aplicar sandboxing a sshd?"; then
        mkdir -p "/etc/systemd/system/${SSH_SERVICE_NAME}.service.d/"

        cat > "/etc/systemd/system/${SSH_SERVICE_NAME}.service.d/hardening.conf" << 'EOF'
[Service]
# Sandboxing de sshd - generado por hardening-servicios-systemd.sh
PrivateTmp=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
ReadWritePaths=/var/log /run/sshd /var/run/sshd /etc/ssh
EOF

        systemctl daemon-reload
        log_info "Drop-in de sshd creado"
        log_warn "Reinicia sshd para aplicar: systemctl restart $SSH_SERVICE_NAME"
    fi
else
    log_warn "${SSH_SERVICE_NAME}.service no encontrado"
fi

# ============================================================
# S3: Drop-in para fail2ban
# ============================================================
log_section "S3: SANDBOXING DE FAIL2BAN"

if systemctl list-unit-files fail2ban.service &>/dev/null 2>&1; then
    echo "Configuración de sandboxing para fail2ban:"
    echo "  Incluye CapabilityBoundingSet para operaciones de red"
    echo ""

    if ask "¿Aplicar sandboxing a fail2ban?"; then
        mkdir -p /etc/systemd/system/fail2ban.service.d/

        cat > /etc/systemd/system/fail2ban.service.d/hardening.conf << 'EOF'
[Service]
# Sandboxing de fail2ban - generado por hardening-servicios-systemd.sh
PrivateTmp=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH CAP_AUDIT_WRITE
ReadWritePaths=/var/log /var/lib/fail2ban /run/fail2ban /var/run/fail2ban
EOF

        systemctl daemon-reload
        log_info "Drop-in de fail2ban creado"
        log_warn "Reinicia fail2ban para aplicar: systemctl restart fail2ban"
    fi
else
    log_warn "fail2ban.service no encontrado"
fi

# ============================================================
# S4: Drop-in para firewalld (conservador)
# ============================================================
log_section "S4: SANDBOXING DE FIREWALLD"

if systemctl list-unit-files firewalld.service &>/dev/null 2>&1; then
    echo "Configuración conservadora para firewalld:"
    echo "  (firewalld necesita acceso a kernel para reglas de red)"
    echo ""

    if ask "¿Aplicar sandboxing conservador a firewalld?"; then
        mkdir -p /etc/systemd/system/firewalld.service.d/

        cat > /etc/systemd/system/firewalld.service.d/hardening.conf << 'EOF'
[Service]
# Sandboxing conservador de firewalld - generado por hardening-servicios-systemd.sh
PrivateTmp=yes
NoNewPrivileges=yes
ProtectHome=yes
ProtectKernelModules=yes
EOF

        systemctl daemon-reload
        log_info "Drop-in de firewalld creado (conservador)"
        log_warn "Reinicia firewalld para aplicar: systemctl restart firewalld"
    fi
else
    log_warn "firewalld.service no encontrado"
fi

# ============================================================
# S5: Drop-in para NetworkManager (conservador)
# ============================================================
log_section "S5: SANDBOXING DE NETWORKMANAGER"

if systemctl list-unit-files NetworkManager.service &>/dev/null 2>&1; then
    echo "Configuración conservadora para NetworkManager:"
    echo "  (NM necesita acceso amplio al sistema para gestionar red)"
    echo ""

    if ask "¿Aplicar sandboxing conservador a NetworkManager?"; then
        mkdir -p /etc/systemd/system/NetworkManager.service.d/

        cat > /etc/systemd/system/NetworkManager.service.d/hardening.conf << 'EOF'
[Service]
# Sandboxing conservador de NetworkManager - generado por hardening-servicios-systemd.sh
PrivateTmp=yes
ProtectHome=yes
ProtectKernelModules=yes
EOF

        systemctl daemon-reload
        log_info "Drop-in de NetworkManager creado (conservador)"
        log_warn "Reinicia NM para aplicar: systemctl restart NetworkManager"
    fi
else
    log_warn "NetworkManager.service no encontrado"
fi

# ============================================================
# S6: Drop-in para security-monitor (si existe)
# ============================================================
log_section "S6: SANDBOXING DE SECURITY-MONITOR"

if systemctl list-unit-files security-monitor.service &>/dev/null 2>&1; then
    echo "security-monitor.service detectado."
    echo ""

    if ask "¿Aplicar sandboxing a security-monitor?"; then
        mkdir -p /etc/systemd/system/security-monitor.service.d/

        cat > /etc/systemd/system/security-monitor.service.d/hardening.conf << 'EOF'
[Service]
# Sandboxing de security-monitor - generado por hardening-servicios-systemd.sh
PrivateTmp=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
ReadWritePaths=/var/log
EOF

        systemctl daemon-reload
        log_info "Drop-in de security-monitor creado"
        log_warn "Reinicia para aplicar: systemctl restart security-monitor"
    fi
else
    log_info "security-monitor.service no encontrado (se creará con módulo 5 extremo)"
fi

# ============================================================
# S7: Script de análisis permanente
# ============================================================
log_section "S7: SCRIPT DE ANÁLISIS DE SERVICIOS"

if ask "¿Crear /usr/local/bin/analizar-servicios-seguridad.sh?"; then
    cat > /usr/local/bin/analizar-servicios-seguridad.sh << 'EOFANALYZE'
#!/bin/bash
# ============================================================
# Análisis de seguridad de servicios systemd
# Uso: sudo analizar-servicios-seguridad.sh
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  ANÁLISIS DE SEGURIDAD DE SERVICIOS${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo ""

# 1. systemd-analyze security
echo -e "${CYAN}── Puntuaciones de seguridad ──${NC}"
if command -v systemd-analyze &>/dev/null; then
    systemd-analyze security 2>/dev/null | while IFS= read -r line; do
        if echo "$line" | grep -q "UNSAFE\|EXPOSED"; then
            echo -e "  ${RED}$line${NC}"
        elif echo "$line" | grep -q "MEDIUM"; then
            echo -e "  ${YELLOW}$line${NC}"
        elif echo "$line" | grep -q "OK\|SAFE"; then
            echo -e "  ${GREEN}$line${NC}"
        else
            echo "  $line"
        fi
    done
fi

# 2. Drop-ins instalados
echo ""
echo -e "${CYAN}── Drop-ins de hardening instalados ──${NC}"
for svc in "$SSH_SERVICE_NAME" fail2ban firewalld NetworkManager security-monitor; do
    dropin="/etc/systemd/system/${svc}.service.d/hardening.conf"
    if [[ -f "$dropin" ]]; then
        echo -e "  ${GREEN}OK${NC}  $svc - drop-in presente"
    else
        echo -e "  ${YELLOW}--${NC}  $svc - sin drop-in"
    fi
done

# 3. Detalle de servicios críticos
echo ""
echo -e "${CYAN}── Detalle de servicios críticos ──${NC}"
for svc in "$SSH_SERVICE_NAME" fail2ban firewalld auditd; do
    if systemctl is-active "$svc" &>/dev/null; then
        score=$(systemd-analyze security "$svc" 2>/dev/null | tail -1 | awk '{print $2}' || echo "N/A")
        echo -e "  ${GREEN}ACTIVO${NC}  $svc (score: $score)"
    else
        echo -e "  ${YELLOW}INACT.${NC}  $svc"
    fi
done

echo ""
echo -e "${BOLD}Análisis completado: $(date)${NC}"
EOFANALYZE

    chmod +x /usr/local/bin/analizar-servicios-seguridad.sh
    log_info "Script creado: /usr/local/bin/analizar-servicios-seguridad.sh"
fi

# Recargar daemon final
systemctl daemon-reload

echo ""
log_info "Sandboxing de servicios completado"
log_info "Ejecuta 'systemd-analyze security' para ver mejoras"
log_info "Backup en: $BACKUP_DIR"
