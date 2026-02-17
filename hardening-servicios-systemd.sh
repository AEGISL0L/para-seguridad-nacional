#!/bin/bash
# ============================================================
# SANDBOXING DE SERVICIOS SYSTEMD - Linux Multi-Distro
# ============================================================
# Secciones:
#   S1  - Analizar seguridad con systemd-analyze security
#   S2  - Drop-in para sshd
#   S3  - Drop-in para fail2ban
#   S4  - Drop-in para firewalld
#   S5  - Drop-in para NetworkManager
#   S6  - Drop-in para security-monitor (si existe)
#   S7  - Drop-in para rsyslog
#   S8  - Drop-in para auditd
#   S9  - Drop-in para wpa_supplicant
#   S10 - Drop-in para smartd
#   S11 - Drop-in para pcscd
#   S12 - Drop-in para mcelog
#   S13 - Drop-in para switcheroo-control
#   S14 - Drop-in para rng-tools
#   S15 - Drop-in para accounts-daemon
#   S16 - Drop-in para rtkit-daemon
#   S17 - Script de análisis permanente
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "hardening-servicios-systemd"
securizar_setup_traps

_precheck 17
_pc true  # S1: análisis/detección, siempre re-evaluar
_pc 'check_file_exists "/etc/systemd/system/${SSH_SERVICE_NAME}.service.d/hardening.conf"'
_pc 'check_file_exists /etc/systemd/system/fail2ban.service.d/hardening.conf'
_pc 'check_file_exists /etc/systemd/system/firewalld.service.d/hardening.conf'
_pc 'check_file_exists /etc/systemd/system/NetworkManager.service.d/hardening.conf'
_pc 'check_file_exists /etc/systemd/system/security-monitor.service.d/hardening.conf'
_pc 'check_file_exists /etc/systemd/system/rsyslog.service.d/hardening.conf'
_pc 'check_file_exists /etc/systemd/system/auditd.service.d/hardening.conf'
_pc 'check_file_exists /etc/systemd/system/wpa_supplicant.service.d/hardening.conf'
_pc 'check_file_exists /etc/systemd/system/smartd.service.d/hardening.conf'
_pc 'check_file_exists /etc/systemd/system/pcscd.service.d/hardening.conf'
_pc 'check_file_exists /etc/systemd/system/mcelog.service.d/hardening.conf'
_pc 'check_file_exists /etc/systemd/system/switcheroo-control.service.d/hardening.conf'
_pc 'check_file_exists /etc/systemd/system/rng-tools.service.d/hardening.conf'
_pc 'check_file_exists /etc/systemd/system/accounts-daemon.service.d/hardening.conf'
_pc 'check_file_exists /etc/systemd/system/rtkit-daemon.service.d/hardening.conf'
_pc 'check_executable /usr/local/bin/analizar-servicios-seguridad.sh'
_precheck_result

# ── Helper: instalar drop-in si servicio existe ──
_install_dropin() {
    local svc="$1" desc="$2" dropin_content="$3"
    if ! systemctl list-unit-files "${svc}.service" &>/dev/null 2>&1; then
        log_info "${svc}.service no encontrado — omitido"
        return
    fi
    if check_file_exists "/etc/systemd/system/${svc}.service.d/hardening.conf"; then
        log_already "Sandboxing de ${svc} (drop-in hardening.conf presente)"
        return
    fi
    echo "$desc"
    echo ""
    if ask "¿Aplicar sandboxing a ${svc}?"; then
        mkdir -p "/etc/systemd/system/${svc}.service.d/"
        echo "$dropin_content" > "/etc/systemd/system/${svc}.service.d/hardening.conf"
        log_change "Creado" "/etc/systemd/system/${svc}.service.d/hardening.conf"
    else
        log_skip "Sandboxing de ${svc}"
    fi
}

# ============================================================
# S1: ANÁLISIS DE SEGURIDAD
# ============================================================
log_section "S1: ANÁLISIS DE SEGURIDAD DE SERVICIOS"

log_info "Ejecutando systemd-analyze security..."
echo ""

if command -v systemd-analyze &>/dev/null; then
    echo -e "${BOLD}Servicios con peor puntuación de seguridad:${NC}"
    systemd-analyze security 2>/dev/null | head -40 | while IFS= read -r line; do
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

_install_dropin "$SSH_SERVICE_NAME" \
    "sshd: ProtectSystem=strict, ReadWritePaths limitados, syscall filter" \
    '[Service]
# Sandboxing de sshd - generado por hardening-servicios-systemd.sh
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
UMask=0077
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
NoNewPrivileges=yes
RemoveIPC=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_SYS_CHROOT CAP_CHOWN CAP_DAC_OVERRIDE CAP_AUDIT_WRITE CAP_KILL
ReadWritePaths=/var/log /run/sshd /var/run/sshd /etc/ssh
SystemCallArchitectures=native
SystemCallFilter=~@clock @cpu-emulation @debug @module @mount @obsolete @reboot @swap @raw-io'

# ============================================================
# S3: Drop-in para fail2ban
# ============================================================
log_section "S3: SANDBOXING DE FAIL2BAN"

_install_dropin fail2ban \
    "fail2ban: ProtectSystem=full, CapabilityBoundingSet para firewall" \
    '[Service]
# Sandboxing de fail2ban - generado por hardening-servicios-systemd.sh
# Nota: ProtectSystem=full (no strict) — fail2ban necesita escribir a /var/log, /var/run
ProtectSystem=full
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
UMask=0077
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RemoveIPC=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH CAP_AUDIT_READ
SystemCallArchitectures=native
SystemCallFilter=~@clock @cpu-emulation @module @mount @obsolete @reboot @swap @raw-io'

# ============================================================
# S4: Drop-in para firewalld
# ============================================================
log_section "S4: SANDBOXING DE FIREWALLD"

_install_dropin firewalld \
    "firewalld: sandboxing moderado (necesita acceso a kernel para reglas de red)" \
    '[Service]
# Sandboxing de firewalld - generado por hardening-servicios-systemd.sh
PrivateTmp=yes
NoNewPrivileges=yes
ProtectHome=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RemoveIPC=yes
UMask=0077
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
SystemCallArchitectures=native
SystemCallFilter=~@clock @cpu-emulation @debug @module @obsolete @reboot @swap @raw-io'

# ============================================================
# S5: Drop-in para NetworkManager
# ============================================================
log_section "S5: SANDBOXING DE NETWORKMANAGER"

_install_dropin NetworkManager \
    "NetworkManager: sandboxing conservador (necesita acceso amplio al sistema)" \
    '[Service]
# Sandboxing de NetworkManager - generado por hardening-servicios-systemd.sh
# Conservador: NM necesita privilegios de red, hardware, DBus
PrivateTmp=yes
ProtectHome=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RemoveIPC=yes
UMask=0077
SystemCallArchitectures=native'

# ============================================================
# S6: Drop-in para security-monitor
# ============================================================
log_section "S6: SANDBOXING DE SECURITY-MONITOR"

_install_dropin security-monitor \
    "security-monitor: necesita root (pkill), /proc (pgrep), AF_NETLINK (ss)" \
    '[Service]
# Sandboxing de security-monitor - generado por hardening-servicios-systemd.sh
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=/var/log
UMask=0077
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProcSubset=all
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
RestrictNamespaces=yes
NoNewPrivileges=yes
RemoveIPC=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
CapabilityBoundingSet=CAP_KILL CAP_DAC_READ_SEARCH
SystemCallArchitectures=native
SystemCallFilter=~@clock @cpu-emulation @module @mount @obsolete @reboot @swap @raw-io'

# ============================================================
# S7: Drop-in para rsyslog
# ============================================================
log_section "S7: SANDBOXING DE RSYSLOG"

_install_dropin rsyslog \
    "rsyslog: ProtectSystem=strict, escribe solo a /var/log y /var/spool/rsyslog" \
    '[Service]
# Sandboxing de rsyslog - generado por hardening-servicios-systemd.sh
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=/var/log /var/spool/rsyslog /run/rsyslog
UMask=0077
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=no
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
RestrictNamespaces=yes
NoNewPrivileges=yes
RemoveIPC=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=CAP_SYSLOG CAP_DAC_READ_SEARCH CAP_SETUID CAP_SETGID
SystemCallArchitectures=native
SystemCallFilter=~@clock @cpu-emulation @module @mount @obsolete @reboot @swap @raw-io'

# ============================================================
# S8: Drop-in para auditd
# ============================================================
log_section "S8: SANDBOXING DE AUDITD"

_install_dropin auditd \
    "auditd: ProtectSystem=full, interfaz kernel audit, PrivateNetwork" \
    '[Service]
# Sandboxing de auditd - generado por hardening-servicios-systemd.sh
# Nota: ProtectSystem=full (no strict) — auditd necesita escribir PID y audit rules
ProtectSystem=full
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateNetwork=yes
UMask=0077
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
RestrictNamespaces=yes
RemoveIPC=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK
CapabilityBoundingSet=CAP_AUDIT_CONTROL CAP_AUDIT_READ CAP_AUDIT_WRITE CAP_SYS_NICE CAP_CHOWN CAP_FOWNER
SystemCallArchitectures=native
SystemCallFilter=~@clock @cpu-emulation @module @mount @obsolete @reboot @swap @raw-io'

# ============================================================
# S9: Drop-in para wpa_supplicant
# ============================================================
log_section "S9: SANDBOXING DE WPA_SUPPLICANT"

_install_dropin wpa_supplicant \
    "wpa_supplicant: WiFi auth, necesita CAP_NET_ADMIN/RAW y AF_PACKET" \
    '[Service]
# Sandboxing de wpa_supplicant - generado por hardening-servicios-systemd.sh
PrivateTmp=yes
ProtectClock=yes
ProtectProc=invisible
ProcSubset=pid
LockPersonality=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
RestrictNamespaces=yes
NoNewPrivileges=yes
RemoveIPC=yes
UMask=0077
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_PACKET AF_INET AF_INET6
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
SystemCallArchitectures=native
SystemCallFilter=~@clock @cpu-emulation @debug @module @mount @obsolete @reboot @swap @resources'

# ============================================================
# S10: Drop-in para smartd
# ============================================================
log_section "S10: SANDBOXING DE SMARTD"

_install_dropin smartd \
    "smartd: monitorización de discos, PrivateNetwork, sin red necesaria" \
    '[Service]
# Sandboxing de smartd - generado por hardening-servicios-systemd.sh
PrivateTmp=yes
PrivateNetwork=yes
ProtectClock=yes
ProtectProc=invisible
ProcSubset=pid
LockPersonality=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
RestrictNamespaces=yes
NoNewPrivileges=yes
RemoveIPC=yes
UMask=0077
RestrictAddressFamilies=AF_UNIX
CapabilityBoundingSet=CAP_SYS_RAWIO CAP_SYS_ADMIN
SystemCallArchitectures=native
SystemCallFilter=~@clock @cpu-emulation @debug @module @mount @obsolete @reboot @swap'

# ============================================================
# S11: Drop-in para pcscd
# ============================================================
log_section "S11: SANDBOXING DE PCSCD"

_install_dropin pcscd \
    "pcscd: smart card daemon, PrivateNetwork, acceso USB" \
    '[Service]
# Sandboxing de pcscd - generado por hardening-servicios-systemd.sh
PrivateTmp=yes
PrivateNetwork=yes
ProtectClock=yes
ProtectProc=invisible
ProcSubset=pid
LockPersonality=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
RestrictNamespaces=yes
NoNewPrivileges=yes
RemoveIPC=yes
UMask=0077
RestrictAddressFamilies=AF_UNIX AF_NETLINK
CapabilityBoundingSet=
SystemCallArchitectures=native
SystemCallFilter=~@clock @cpu-emulation @debug @module @mount @obsolete @reboot @swap @raw-io'

# ============================================================
# S12: Drop-in para mcelog
# ============================================================
log_section "S12: SANDBOXING DE MCELOG"

_install_dropin mcelog \
    "mcelog: MCE logging, PrivateNetwork, necesita cargar módulo msr" \
    '[Service]
# Sandboxing de mcelog - generado por hardening-servicios-systemd.sh
# Nota: NO incluye ProtectKernelModules — mcelog necesita cargar módulo msr
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateNetwork=yes
ReadWritePaths=/var/log
UMask=0077
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
RestrictNamespaces=yes
RemoveIPC=yes
RestrictAddressFamilies=AF_UNIX
CapabilityBoundingSet=CAP_SYS_ADMIN
SystemCallArchitectures=native
SystemCallFilter=~@clock @cpu-emulation @debug @mount @obsolete @reboot @swap'

# ============================================================
# S13: Drop-in para switcheroo-control
# ============================================================
log_section "S13: SANDBOXING DE SWITCHEROO-CONTROL"

_install_dropin switcheroo-control \
    "switcheroo-control: GPU switching, sin red, sin capabilities" \
    '[Service]
# Sandboxing de switcheroo-control - generado por hardening-servicios-systemd.sh
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateNetwork=yes
UMask=0077
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
RestrictNamespaces=yes
NoNewPrivileges=yes
RemoveIPC=yes
RestrictAddressFamilies=AF_UNIX
CapabilityBoundingSet=
SystemCallArchitectures=native
SystemCallFilter=~@clock @cpu-emulation @debug @module @mount @obsolete @reboot @swap @raw-io @privileged @resources'

# ============================================================
# S14: Drop-in para rng-tools
# ============================================================
log_section "S14: SANDBOXING DE RNG-TOOLS"

_install_dropin rng-tools \
    "rng-tools: alimenta entropy pool, PrivateNetwork, acceso a /dev/hwrng" \
    '[Service]
# Sandboxing de rng-tools - generado por hardening-servicios-systemd.sh
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateNetwork=yes
UMask=0077
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
RestrictNamespaces=yes
NoNewPrivileges=yes
RemoveIPC=yes
RestrictAddressFamilies=AF_UNIX
CapabilityBoundingSet=CAP_SYS_ADMIN
SystemCallArchitectures=native
SystemCallFilter=~@clock @cpu-emulation @debug @module @mount @obsolete @reboot @swap'

# ============================================================
# S15: Drop-in para accounts-daemon
# ============================================================
log_section "S15: SANDBOXING DE ACCOUNTS-DAEMON"

_install_dropin accounts-daemon \
    "accounts-daemon: gestión de cuentas via DBus" \
    '[Service]
# Sandboxing de accounts-daemon - generado por hardening-servicios-systemd.sh
ProtectClock=yes
ProtectKernelLogs=yes
ProtectProc=invisible
ProcSubset=pid
LockPersonality=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
RestrictNamespaces=yes
RemoveIPC=yes
UMask=0077
RestrictAddressFamilies=AF_UNIX AF_NETLINK
SystemCallArchitectures=native
SystemCallFilter=~@clock @cpu-emulation @debug @module @mount @obsolete @reboot @swap @raw-io'

# ============================================================
# S16: Drop-in para rtkit-daemon
# ============================================================
log_section "S16: SANDBOXING DE RTKIT-DAEMON"

_install_dropin rtkit-daemon \
    "rtkit-daemon: scheduling realtime para audio, sin syscall filter (necesita @privileged)" \
    '[Service]
# Sandboxing de rtkit-daemon - generado por hardening-servicios-systemd.sh
# Nota: sin SystemCallFilter — rtkit necesita sched_setparam, sched_setscheduler
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateNetwork=yes
UMask=0077
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
LockPersonality=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
RestrictNamespaces=yes
RemoveIPC=yes
RestrictAddressFamilies=AF_UNIX
SystemCallArchitectures=native'

# ============================================================
# S17: Script de análisis permanente
# ============================================================
log_section "S17: SCRIPT DE ANÁLISIS DE SERVICIOS"

# Lista de todos los servicios que hardenamos
_ALL_HARDENED_SVCS=(
    "$SSH_SERVICE_NAME" fail2ban firewalld NetworkManager security-monitor
    rsyslog auditd wpa_supplicant smartd pcscd mcelog
    switcheroo-control rng-tools accounts-daemon rtkit-daemon
)

if check_executable /usr/local/bin/analizar-servicios-seguridad.sh; then
    log_already "Script de análisis de servicios (/usr/local/bin/analizar-servicios-seguridad.sh)"
elif ask "¿Crear /usr/local/bin/analizar-servicios-seguridad.sh?"; then
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

echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  ANÁLISIS DE SEGURIDAD DE SERVICIOS SYSTEMD${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
echo ""

# 1. systemd-analyze security completo
echo -e "${CYAN}── Puntuaciones de seguridad (todos los servicios) ──${NC}"
_ok=0 _total=0
if command -v systemd-analyze &>/dev/null; then
    while IFS= read -r line; do
        ((_total++)) || true
        if echo "$line" | grep -q "UNSAFE\|EXPOSED"; then
            echo -e "  ${RED}$line${NC}"
        elif echo "$line" | grep -q "MEDIUM"; then
            echo -e "  ${YELLOW}$line${NC}"
        elif echo "$line" | grep -qE "OK|SAFE"; then
            echo -e "  ${GREEN}$line${NC}"
            ((_ok++)) || true
        else
            echo "  $line"
        fi
    done < <(systemd-analyze security 2>/dev/null | grep -v '^$' | grep -v '^UNIT')
fi
echo ""
echo -e "  ${BOLD}${_ok}/${_total} servicios en zona OK/SAFE${NC}"

# 2. Drop-ins instalados
echo ""
echo -e "${CYAN}── Drop-ins de hardening instalados ──${NC}"
for svc in sshd ssh fail2ban firewalld NetworkManager security-monitor \
           rsyslog auditd wpa_supplicant smartd pcscd mcelog \
           switcheroo-control rng-tools accounts-daemon rtkit-daemon \
           unbound securizar-traffic-pad; do
    dropin="/etc/systemd/system/${svc}.service.d/hardening.conf"
    if [[ -f "$dropin" ]]; then
        if systemctl is-active "${svc}.service" &>/dev/null; then
            _score=$(systemd-analyze security "${svc}.service" 2>/dev/null | tail -1 | awk '{print $2}' || echo "?")
            echo -e "  ${GREEN}✓${NC}  ${svc} (score: ${_score})"
        else
            echo -e "  ${YELLOW}✓${NC}  ${svc} (drop-in presente, servicio inactivo)"
        fi
    elif systemctl list-unit-files "${svc}.service" &>/dev/null 2>&1; then
        echo -e "  ${RED}✗${NC}  ${svc} — sin drop-in"
    fi
done

echo ""
echo -e "${BOLD}Análisis completado: $(date)${NC}"
EOFANALYZE
    log_change "Creado" "/usr/local/bin/analizar-servicios-seguridad.sh"

    chmod +x /usr/local/bin/analizar-servicios-seguridad.sh
    log_change "Permisos" "/usr/local/bin/analizar-servicios-seguridad.sh -> +x"
    log_info "Script creado: /usr/local/bin/analizar-servicios-seguridad.sh"
else
    log_skip "Crear script de analisis de servicios"
fi

# Recargar daemon final
systemctl daemon-reload
log_change "Aplicado" "systemctl daemon-reload"

show_changes_summary
echo ""
log_info "Sandboxing de servicios completado"
log_info "Ejecuta 'sudo analizar-servicios-seguridad.sh' para ver puntuaciones"
log_info "Backup en: $BACKUP_DIR"
