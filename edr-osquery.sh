#!/bin/bash
# ============================================================
# EDR CON OSQUERY - Detección y Respuesta en Endpoint
# Módulo 69 - Linux Multi-Distro (openSUSE, Debian/Ubuntu, RHEL/Fedora, Arch)
# ============================================================
# Secciones:
#   S1  - Instalación y configuración de osquery
#   S2  - Packs de seguridad personalizados
#   S3  - Detección de amenazas avanzada
#   S4  - Agente Wazuh/OSSEC (guía)
#   S5  - Decorators y tablas custom
#   S6  - Alertas syslog/JSON
#   S7  - Baseline y drift detection
#   S8  - FleetDM prep (enrollment)
#   S9  - Queries diferenciales programadas
#   S10 - Auditoría EDR
# ============================================================


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "edr-osquery"
securizar_setup_traps

# ── Pre-check: detectar secciones ya aplicadas ──────────────
_precheck 10
_pc 'check_file_exists /etc/osquery/osquery.conf'
_pc 'check_file_exists /etc/osquery/packs/securizar-security.conf'
_pc 'check_file_exists /etc/osquery/packs/securizar-threat-detection.conf'
_pc 'check_executable /usr/local/bin/securizar-edr-wazuh.sh'
_pc 'check_file_exists /etc/securizar/edr/decorators.conf'
_pc 'check_executable /usr/local/bin/securizar-edr-alerts.sh'
_pc 'check_executable /usr/local/bin/securizar-edr-baseline.sh'
_pc 'check_executable /usr/local/bin/securizar-edr-fleet.sh'
_pc 'check_executable /usr/local/bin/securizar-edr-scheduled.sh'
_pc 'check_executable /usr/local/bin/auditoria-edr.sh'
_precheck_result

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   EDR CON OSQUERY - Detección y Respuesta en Endpoint     ║"
echo "║   Osquery, Wazuh, threat queries, fleet, baseline         ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

mkdir -p /etc/osquery/packs
mkdir -p /etc/securizar/edr
mkdir -p /var/lib/securizar/edr
mkdir -p /var/log/securizar/edr

# ============================================================
# S1: INSTALACIÓN Y CONFIGURACIÓN DE OSQUERY
# ============================================================
log_section "S1: INSTALACIÓN Y CONFIGURACIÓN DE OSQUERY"

echo "Osquery expone el SO como base de datos relacional con SQL."
echo "Permite consultar procesos, puertos, usuarios, archivos y más."
echo ""

if check_file_exists /etc/osquery/osquery.conf; then
    log_already "Osquery configurado"
elif ask "¿Instalar y configurar osquery?"; then

    # Instalar osquery si no está presente
    if ! command -v osqueryi &>/dev/null; then
        log_info "Instalando osquery..."
        case "$DISTRO_FAMILY" in
            suse)
                rpm --import https://pkg.osquery.io/rpm/GPG 2>/dev/null || true
                zypper addrepo -f https://pkg.osquery.io/rpm/osquery-s3-rpm.repo 2>/dev/null || true
                zypper --non-interactive install osquery 2>/dev/null || log_warn "No se pudo instalar osquery desde repo oficial"
                ;;
            debian)
                export OSQUERY_KEY=1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B
                apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys "$OSQUERY_KEY" 2>/dev/null || true
                echo "deb [arch=amd64] https://pkg.osquery.io/deb deb main" > /etc/apt/sources.list.d/osquery.list 2>/dev/null || true
                apt-get update -qq 2>/dev/null
                apt-get install -y osquery 2>/dev/null || log_warn "No se pudo instalar osquery"
                ;;
            rhel)
                rpm --import https://pkg.osquery.io/rpm/GPG 2>/dev/null || true
                cat > /etc/yum.repos.d/osquery.repo << 'EOFREPO'
[osquery-s3-rpm-repo]
name=osquery RPM repo
baseurl=https://pkg.osquery.io/rpm
enabled=1
gpgcheck=1
gpgkey=https://pkg.osquery.io/rpm/GPG
EOFREPO
                dnf install -y osquery 2>/dev/null || yum install -y osquery 2>/dev/null || log_warn "No se pudo instalar osquery"
                ;;
            arch)
                pacman -S --noconfirm osquery 2>/dev/null || log_warn "No se pudo instalar osquery (disponible en AUR)"
                ;;
        esac
    fi

    if command -v osqueryi &>/dev/null || command -v osqueryd &>/dev/null; then
        # Configuración principal
        cat > /etc/osquery/osquery.conf << 'EOFCONF'
{
  "options": {
    "config_plugin": "filesystem",
    "logger_plugin": "filesystem,syslog",
    "logger_path": "/var/log/osquery",
    "disable_logging": "false",
    "log_result_events": "true",
    "schedule_splay_percent": "10",
    "pidfile": "/var/osquery/osquery.pidfile",
    "events_expiry": "3600",
    "database_path": "/var/osquery/osquery.db",
    "verbose": "false",
    "worker_threads": "2",
    "enable_monitor": "true",
    "disable_events": "false",
    "disable_audit": "false",
    "audit_allow_config": "true",
    "audit_allow_sockets": "true",
    "host_identifier": "hostname",
    "enable_syslog": "true",
    "schedule_default_interval": "3600"
  },

  "schedule": {
    "system_info": {
      "query": "SELECT hostname, cpu_brand, physical_memory, hardware_vendor, hardware_model FROM system_info;",
      "interval": 3600,
      "description": "Información del sistema"
    },
    "os_version": {
      "query": "SELECT name, version, major, minor, patch, build, platform FROM os_version;",
      "interval": 3600,
      "description": "Versión del SO"
    },
    "uptime": {
      "query": "SELECT days, hours, minutes, total_seconds FROM uptime;",
      "interval": 1800,
      "description": "Tiempo activo"
    },
    "logged_in_users": {
      "query": "SELECT user, host, time, tty, pid, type FROM logged_in_users WHERE type = 'user';",
      "interval": 600,
      "description": "Usuarios logueados"
    }
  },

  "packs": {
    "securizar-security": "/etc/osquery/packs/securizar-security.conf",
    "securizar-threat-detection": "/etc/osquery/packs/securizar-threat-detection.conf"
  },

  "file_paths": {
    "etc": ["/etc/%%"],
    "binaries": ["/usr/bin/%%", "/usr/sbin/%%", "/usr/local/bin/%%"],
    "tmp": ["/tmp/%%"]
  },

  "exclude_paths": {
    "etc": ["/etc/machine-id", "/etc/resolv.conf"]
  }
}
EOFCONF

        chmod 644 /etc/osquery/osquery.conf
        log_change "Creado" "/etc/osquery/osquery.conf"

        # Daemon flags
        cat > /etc/osquery/osquery.flags << 'EOFFLAGS'
--disable_watchdog=false
--watchdog_memory_limit=300
--watchdog_utilization_limit=20
--watchdog_delay=60
--enable_file_events=true
--disable_audit=false
EOFFLAGS

        chmod 644 /etc/osquery/osquery.flags
        log_change "Creado" "/etc/osquery/osquery.flags"

        # Habilitar servicio
        systemctl enable osqueryd 2>/dev/null || true
        systemctl start osqueryd 2>/dev/null || log_warn "osqueryd no pudo arrancar"
        log_change "Servicio" "osqueryd enable+start"
        log_info "Osquery instalado y configurado"
    else
        log_warn "osquery no se pudo instalar. Instálalo manualmente desde https://osquery.io"
    fi

else
    log_skip "Instalación de osquery"
fi

# ============================================================
# S2: PACKS DE SEGURIDAD PERSONALIZADOS
# ============================================================
log_section "S2: PACKS DE SEGURIDAD PERSONALIZADOS"

echo "Packs de queries orientados a seguridad: procesos, puertos,"
echo "crontab, FIM en /etc, usuarios y grupos."
echo ""

if check_file_exists /etc/osquery/packs/securizar-security.conf; then
    log_already "Pack de seguridad securizar"
elif ask "¿Crear packs de seguridad para osquery?"; then

    cat > /etc/osquery/packs/securizar-security.conf << 'EOFPACK'
{
  "queries": {
    "listening_ports": {
      "query": "SELECT p.pid, p.name, p.path, lp.port, lp.protocol, lp.address FROM listening_ports lp JOIN processes p ON lp.pid = p.pid WHERE lp.port != 0;",
      "interval": 300,
      "description": "Puertos en escucha con proceso asociado",
      "snapshot": true
    },
    "process_open_sockets": {
      "query": "SELECT DISTINCT p.name, p.path, pos.remote_address, pos.remote_port, pos.local_port, pos.protocol FROM process_open_sockets pos JOIN processes p ON pos.pid = p.pid WHERE pos.remote_port != 0 AND pos.remote_address != '127.0.0.1' AND pos.remote_address != '::1';",
      "interval": 600,
      "description": "Procesos con conexiones remotas activas"
    },
    "crontab_all": {
      "query": "SELECT event, minute, hour, day_of_month, month, day_of_week, command, path FROM crontab;",
      "interval": 900,
      "description": "Todas las entradas de crontab"
    },
    "etc_changes": {
      "query": "SELECT target_path, action, md5, sha256, time FROM file_events WHERE target_path LIKE '/etc/%';",
      "interval": 60,
      "description": "Cambios en archivos de /etc (FIM)"
    },
    "users_groups": {
      "query": "SELECT u.username, u.uid, u.gid, u.shell, u.directory, g.groupname FROM users u LEFT JOIN groups g ON u.gid = g.gid WHERE u.uid >= 0 AND u.uid < 65534;",
      "interval": 3600,
      "description": "Usuarios y grupos del sistema"
    },
    "suid_binaries": {
      "query": "SELECT path, username, groupname, permissions, mtime FROM suid_bin;",
      "interval": 3600,
      "description": "Binarios con SUID/SGID",
      "snapshot": true
    },
    "kernel_modules": {
      "query": "SELECT name, size, used_by, status FROM kernel_modules WHERE status = 'Live';",
      "interval": 1800,
      "description": "Módulos del kernel cargados"
    },
    "authorized_keys": {
      "query": "SELECT uid, username, key_file, key, algorithm FROM authorized_keys;",
      "interval": 3600,
      "description": "Claves SSH autorizadas por usuario"
    },
    "systemd_units": {
      "query": "SELECT id, description, load_state, active_state, sub_state, fragment_path FROM systemd_units WHERE active_state = 'active';",
      "interval": 1800,
      "description": "Servicios systemd activos"
    },
    "mounts_noexec": {
      "query": "SELECT device, path, type, flags FROM mounts WHERE path IN ('/tmp', '/var/tmp', '/dev/shm');",
      "interval": 3600,
      "description": "Opciones de montaje de directorios temporales"
    }
  }
}
EOFPACK

    chmod 644 /etc/osquery/packs/securizar-security.conf
    log_change "Creado" "/etc/osquery/packs/securizar-security.conf"
    log_info "Pack de seguridad instalado con 10 queries"

else
    log_skip "Packs de seguridad osquery"
fi

# ============================================================
# S3: DETECCIÓN DE AMENAZAS AVANZADA
# ============================================================
log_section "S3: DETECCIÓN DE AMENAZAS AVANZADA"

echo "Pack de queries orientado a detección de amenazas:"
echo "  - Procesos en /tmp o /dev/shm"
echo "  - Nuevos binarios SUID"
echo "  - Reverse shells y conexiones sospechosas"
echo "  - SSH lateral entre hosts internos"
echo ""

if check_file_exists /etc/osquery/packs/securizar-threat-detection.conf; then
    log_already "Pack de detección de amenazas"
elif ask "¿Crear pack de detección de amenazas?"; then

    cat > /etc/osquery/packs/securizar-threat-detection.conf << 'EOFTHRT'
{
  "queries": {
    "processes_in_tmp": {
      "query": "SELECT p.pid, p.name, p.path, p.cmdline, p.uid, p.gid, p.cwd, p.start_time FROM processes p WHERE p.path LIKE '/tmp/%' OR p.path LIKE '/var/tmp/%' OR p.path LIKE '/dev/shm/%' OR p.cwd LIKE '/tmp/%';",
      "interval": 60,
      "description": "THREAT: Procesos ejecutándose desde directorios temporales",
      "snapshot": true
    },
    "reverse_shells": {
      "query": "SELECT p.pid, p.name, p.cmdline, p.path, pos.remote_address, pos.remote_port FROM processes p JOIN process_open_sockets pos ON p.pid = pos.pid WHERE (p.name IN ('bash', 'sh', 'dash', 'zsh', 'python', 'python3', 'perl', 'ruby', 'nc', 'ncat', 'socat') AND pos.remote_port != 0 AND pos.remote_address NOT LIKE '127.%' AND pos.remote_address != '::1');",
      "interval": 60,
      "description": "THREAT: Posibles reverse shells activas"
    },
    "ssh_lateral_movement": {
      "query": "SELECT p.pid, p.name, p.cmdline, p.uid, pos.remote_address, pos.remote_port FROM processes p JOIN process_open_sockets pos ON p.pid = pos.pid WHERE p.name = 'ssh' AND pos.remote_port = 22 AND pos.remote_address LIKE '10.%' OR pos.remote_address LIKE '192.168.%' OR pos.remote_address LIKE '172.1%';",
      "interval": 120,
      "description": "THREAT: Conexiones SSH laterales a red interna"
    },
    "new_suid_binaries": {
      "query": "SELECT path, username, groupname, permissions, mtime FROM suid_bin WHERE mtime > (strftime('%s', 'now') - 86400);",
      "interval": 300,
      "description": "THREAT: Binarios SUID creados en últimas 24h"
    },
    "suspicious_cron_entries": {
      "query": "SELECT event, command, path FROM crontab WHERE command LIKE '%curl%' OR command LIKE '%wget%' OR command LIKE '%nc %' OR command LIKE '%ncat%' OR command LIKE '%base64%' OR command LIKE '%python -c%' OR command LIKE '%bash -i%';",
      "interval": 300,
      "description": "THREAT: Entradas crontab sospechosas"
    },
    "hidden_processes": {
      "query": "SELECT pid, name, path, cmdline, uid FROM processes WHERE name LIKE '.%' OR path LIKE '/tmp/.%' OR path LIKE '/var/tmp/.%';",
      "interval": 120,
      "description": "THREAT: Procesos con nombres ocultos (dot-prefix)"
    },
    "deleted_executables": {
      "query": "SELECT pid, name, path, cmdline FROM processes WHERE path LIKE '%(deleted)%' OR on_disk = 0;",
      "interval": 120,
      "description": "THREAT: Procesos cuyo binario fue borrado del disco"
    },
    "crypto_miners": {
      "query": "SELECT pid, name, cmdline, path, uid FROM processes WHERE cmdline LIKE '%stratum+%' OR cmdline LIKE '%xmrig%' OR cmdline LIKE '%minerd%' OR cmdline LIKE '%cpuminer%' OR name LIKE '%miner%';",
      "interval": 300,
      "description": "THREAT: Posibles crypto-miners"
    },
    "promiscuous_interfaces": {
      "query": "SELECT name, flags, mtu FROM interface_details WHERE flags LIKE '%PROMISC%';",
      "interval": 600,
      "description": "THREAT: Interfaces en modo promiscuo (sniffing)"
    },
    "unauthorized_listeners": {
      "query": "SELECT lp.port, lp.protocol, lp.address, p.name, p.path, p.uid FROM listening_ports lp JOIN processes p ON lp.pid = p.pid WHERE lp.port IN (4444, 5555, 6666, 1337, 31337, 8888, 9999, 1234, 4321, 6667, 6697);",
      "interval": 120,
      "description": "THREAT: Puertos de escucha comunes de C2/backdoors"
    }
  }
}
EOFTHRT

    chmod 644 /etc/osquery/packs/securizar-threat-detection.conf
    log_change "Creado" "/etc/osquery/packs/securizar-threat-detection.conf"
    log_info "Pack de detección de amenazas instalado con 10 queries"

    # Recargar osquery si está activo
    if systemctl is-active osqueryd &>/dev/null; then
        systemctl restart osqueryd 2>/dev/null || true
        log_info "osqueryd reiniciado para cargar nuevos packs"
    fi

else
    log_skip "Pack de detección de amenazas"
fi

# ============================================================
# S4: AGENTE WAZUH/OSSEC (GUÍA)
# ============================================================
log_section "S4: AGENTE WAZUH/OSSEC (GUÍA)"

echo "Wazuh es un SIEM/XDR open-source basado en OSSEC."
echo "Este script genera una guía de instalación y configuración."
echo -e "${YELLOW}NO se instala automáticamente - requiere servidor Wazuh.${NC}"
echo ""

if check_executable /usr/local/bin/securizar-edr-wazuh.sh; then
    log_already "Guía Wazuh/OSSEC"
elif ask "¿Crear guía de integración Wazuh?"; then

    cat > /usr/local/bin/securizar-edr-wazuh.sh << 'EOFWAZUH'
#!/bin/bash
# ============================================================
# GUÍA DE INTEGRACIÓN WAZUH/OSSEC
# Genera instrucciones específicas para la distro detectada
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

echo -e "${BOLD}╔════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║   GUÍA DE INTEGRACIÓN WAZUH               ║${NC}"
echo -e "${BOLD}╚════════════════════════════════════════════╝${NC}"
echo ""

# Detectar distro
if command -v zypper &>/dev/null; then
    DISTRO="suse"
elif command -v apt-get &>/dev/null; then
    DISTRO="debian"
elif command -v dnf &>/dev/null; then
    DISTRO="rhel"
elif command -v pacman &>/dev/null; then
    DISTRO="arch"
else
    DISTRO="unknown"
fi

echo -e "${CYAN}Distro detectada:${NC} $DISTRO"
echo ""

WAZUH_MANAGER="${1:-WAZUH_MANAGER_IP}"

echo -e "${BOLD}=== PASO 1: Importar clave GPG ===${NC}"
case "$DISTRO" in
    suse)
        echo "  rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH"
        ;;
    debian)
        echo "  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import"
        echo "  chmod 644 /usr/share/keyrings/wazuh.gpg"
        ;;
    rhel)
        echo "  rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH"
        ;;
esac

echo ""
echo -e "${BOLD}=== PASO 2: Añadir repositorio ===${NC}"
case "$DISTRO" in
    suse)
        echo "  zypper addrepo https://packages.wazuh.com/4.x/yum/ wazuh"
        ;;
    debian)
        echo '  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list'
        echo "  apt-get update"
        ;;
    rhel)
        cat << 'EOFREPO2'
  cat > /etc/yum.repos.d/wazuh.repo << 'EOF'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
EOFREPO2
        ;;
esac

echo ""
echo -e "${BOLD}=== PASO 3: Instalar agente ===${NC}"
echo "  WAZUH_MANAGER='$WAZUH_MANAGER'"
case "$DISTRO" in
    suse)   echo "  zypper install -y wazuh-agent" ;;
    debian) echo "  WAZUH_MANAGER='$WAZUH_MANAGER' apt-get install -y wazuh-agent" ;;
    rhel)   echo "  WAZUH_MANAGER='$WAZUH_MANAGER' dnf install -y wazuh-agent" ;;
esac

echo ""
echo -e "${BOLD}=== PASO 4: Configurar manager ===${NC}"
echo "  Editar /var/ossec/etc/ossec.conf:"
echo "    <client>"
echo "      <server>"
echo "        <address>$WAZUH_MANAGER</address>"
echo "      </server>"
echo "    </client>"

echo ""
echo -e "${BOLD}=== PASO 5: Iniciar servicio ===${NC}"
echo "  systemctl daemon-reload"
echo "  systemctl enable wazuh-agent"
echo "  systemctl start wazuh-agent"

echo ""
echo -e "${BOLD}=== PASO 6: Verificar ===${NC}"
echo "  systemctl status wazuh-agent"
echo "  /var/ossec/bin/agent-auth -m $WAZUH_MANAGER"

echo ""
echo -e "${YELLOW}NOTA: Requiere un servidor Wazuh accesible en $WAZUH_MANAGER${NC}"
echo -e "${DIM}Documentación: https://documentation.wazuh.com${NC}"
EOFWAZUH

    chmod 755 /usr/local/bin/securizar-edr-wazuh.sh
    log_change "Creado" "/usr/local/bin/securizar-edr-wazuh.sh"
    log_info "Guía Wazuh creada: securizar-edr-wazuh.sh [IP-MANAGER]"

else
    log_skip "Guía Wazuh/OSSEC"
fi

# ============================================================
# S5: DECORATORS Y TABLAS CUSTOM
# ============================================================
log_section "S5: DECORATORS Y TABLAS CUSTOM"

echo "Decorators añaden contexto a cada query (hostname, IP, tags)."
echo "Configuración de tablas ATC para datos personalizados."
echo ""

if check_file_exists /etc/securizar/edr/decorators.conf; then
    log_already "Decorators EDR"
elif ask "¿Configurar decorators y tablas custom?"; then

    cat > /etc/securizar/edr/decorators.conf << 'EOFDEC'
{
  "decorators": {
    "load": [
      "SELECT uuid AS host_uuid FROM system_info;",
      "SELECT hostname AS hostname FROM system_info;",
      "SELECT address AS primary_ip FROM interface_addresses WHERE interface NOT LIKE 'lo%' AND address NOT LIKE '127%' AND address NOT LIKE 'fe80%' LIMIT 1;"
    ],
    "always": [
      "SELECT user AS current_user FROM logged_in_users ORDER BY time DESC LIMIT 1;"
    ]
  }
}
EOFDEC

    chmod 644 /etc/securizar/edr/decorators.conf
    log_change "Creado" "/etc/securizar/edr/decorators.conf"

    # Integrar decorators en osquery.conf si existe
    if [[ -f /etc/osquery/osquery.conf ]] && command -v jq &>/dev/null; then
        DECORATORS=$(cat /etc/securizar/edr/decorators.conf)
        jq --argjson dec "$DECORATORS" '. + $dec' /etc/osquery/osquery.conf > /tmp/osquery-merged.json 2>/dev/null && \
            mv /tmp/osquery-merged.json /etc/osquery/osquery.conf && \
            log_info "Decorators integrados en osquery.conf" || \
            log_warn "No se pudieron integrar decorators automáticamente"
    fi

    log_info "Decorators configurados"

else
    log_skip "Decorators EDR"
fi

# ============================================================
# S6: ALERTAS SYSLOG/JSON
# ============================================================
log_section "S6: ALERTAS SYSLOG/JSON"

echo "Dispatcher de alertas osquery a syslog y JSON."
echo "Configuración de rsyslog para separar logs osquery."
echo ""

if check_executable /usr/local/bin/securizar-edr-alerts.sh; then
    log_already "Alertas EDR"
elif ask "¿Configurar alertas syslog/JSON para osquery?"; then

    # Configuración rsyslog para osquery
    if [[ -d /etc/rsyslog.d ]]; then
        cat > /etc/rsyslog.d/60-osquery.conf << 'EOFRSYS'
# Osquery alerts - separar en archivo dedicado
if $programname == 'osqueryd' then /var/log/osquery/osquery-alerts.log
& stop
EOFRSYS
        chmod 644 /etc/rsyslog.d/60-osquery.conf
        log_change "Creado" "/etc/rsyslog.d/60-osquery.conf"
        systemctl restart rsyslog 2>/dev/null || true
    fi

    # Logrotate para osquery
    cat > /etc/logrotate.d/osquery << 'EOFLR'
/var/log/osquery/*.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}
EOFLR
    log_change "Creado" "/etc/logrotate.d/osquery"

    # Alert dispatcher
    cat > /usr/local/bin/securizar-edr-alerts.sh << 'EOFALERT'
#!/bin/bash
# ============================================================
# EDR ALERT DISPATCHER
# Procesa resultados de osquery y genera alertas
# Uso: securizar-edr-alerts.sh [--tail] [--summary]
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

RESULT_LOG="/var/log/osquery/osqueryd.results.log"
ALERT_LOG="/var/log/securizar/edr/alerts.log"
mkdir -p "$(dirname "$ALERT_LOG")"

case "${1:---summary}" in
    --tail)
        echo -e "${BOLD}Monitorizando alertas EDR en tiempo real...${NC}"
        echo -e "${DIM}Ctrl+C para salir${NC}"
        tail -f "$RESULT_LOG" 2>/dev/null | while IFS= read -r line; do
            NAME=$(echo "$line" | jq -r '.name // empty' 2>/dev/null)
            ACTION=$(echo "$line" | jq -r '.action // empty' 2>/dev/null)
            if [[ -n "$NAME" ]]; then
                if echo "$NAME" | grep -qi "threat\|suspicious\|reverse_shell\|crypto\|hidden"; then
                    echo -e "${RED}[THREAT]${NC} $NAME ($ACTION)" | tee -a "$ALERT_LOG"
                else
                    echo -e "${CYAN}[INFO]${NC} $NAME ($ACTION)"
                fi
            fi
        done
        ;;
    --summary)
        echo -e "${BOLD}=== RESUMEN DE ALERTAS EDR ===${NC}"
        echo ""
        if [[ -f "$RESULT_LOG" ]]; then
            echo -e "${CYAN}Últimos eventos (24h):${NC}"
            TOTAL=$(wc -l < "$RESULT_LOG" 2>/dev/null || echo 0)
            echo "  Total eventos en log: $TOTAL"
            echo ""
            echo -e "${CYAN}Top queries por frecuencia:${NC}"
            if command -v jq &>/dev/null; then
                jq -r '.name // "unknown"' "$RESULT_LOG" 2>/dev/null | sort | uniq -c | sort -rn | head -10 | while read -r count name; do
                    printf "  %5d  %s\n" "$count" "$name"
                done
            fi
            echo ""
            echo -e "${CYAN}Eventos THREAT:${NC}"
            if command -v jq &>/dev/null; then
                jq -r 'select(.name | test("threat|suspicious|reverse|crypto|hidden"; "i")) | "\(.name): \(.columns // {} | keys | join(", "))"' "$RESULT_LOG" 2>/dev/null | head -10 || echo "  Sin alertas threat"
            fi
        else
            echo "  No hay logs de osquery disponibles"
        fi
        ;;
esac
EOFALERT

    chmod 755 /usr/local/bin/securizar-edr-alerts.sh
    log_change "Creado" "/usr/local/bin/securizar-edr-alerts.sh"
    log_info "Alertas EDR configuradas"

else
    log_skip "Alertas EDR"
fi

# ============================================================
# S7: BASELINE Y DRIFT DETECTION
# ============================================================
log_section "S7: BASELINE Y DRIFT DETECTION"

echo "Snapshot del estado del endpoint como baseline."
echo "Comparación semanal: nuevos procesos, puertos, crontab, módulos."
echo ""

if check_executable /usr/local/bin/securizar-edr-baseline.sh; then
    log_already "Baseline EDR"
elif ask "¿Configurar baseline y drift detection?"; then

    cat > /usr/local/bin/securizar-edr-baseline.sh << 'EOFBASE'
#!/bin/bash
# ============================================================
# EDR BASELINE Y DRIFT DETECTION
# Uso: securizar-edr-baseline.sh [learn|check|status]
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

BASE_DIR="/var/lib/securizar/edr/baseline"
mkdir -p "$BASE_DIR"

case "${1:-status}" in
    learn)
        echo -e "${BOLD}=== Aprendiendo baseline EDR ===${NC}"
        TS=$(date +%Y%m%d-%H%M%S)

        # Snapshot via osquery si disponible
        if command -v osqueryi &>/dev/null; then
            osqueryi --json "SELECT pid, name, path, uid FROM processes WHERE path NOT LIKE '/usr/%' AND path != ''" > "$BASE_DIR/processes.json" 2>/dev/null || true
            osqueryi --json "SELECT port, protocol, pid, path FROM listening_ports WHERE port != 0" > "$BASE_DIR/listeners.json" 2>/dev/null || true
            osqueryi --json "SELECT event, command, path FROM crontab" > "$BASE_DIR/crontab.json" 2>/dev/null || true
            osqueryi --json "SELECT name, status FROM kernel_modules WHERE status='Live'" > "$BASE_DIR/modules.json" 2>/dev/null || true
            osqueryi --json "SELECT path, permissions, mtime FROM suid_bin" > "$BASE_DIR/suid.json" 2>/dev/null || true
            echo -e "${GREEN}Baseline capturada via osquery${NC}"
        else
            # Fallback sin osquery
            ps -eo pid,user,comm,args --no-headers | sort > "$BASE_DIR/processes.txt" 2>/dev/null
            ss -tlnp 2>/dev/null | sort > "$BASE_DIR/listeners.txt"
            lsmod | sort > "$BASE_DIR/modules.txt" 2>/dev/null
            echo -e "${GREEN}Baseline capturada (fallback sin osquery)${NC}"
        fi

        echo "$TS" > "$BASE_DIR/last-learn"
        logger -t securizar-edr "EDR baseline learned"
        ;;

    check)
        if [[ ! -f "$BASE_DIR/last-learn" ]]; then
            echo -e "${YELLOW}No hay baseline. Ejecuta: $0 learn${NC}"
            exit 1
        fi

        echo -e "${BOLD}=== DRIFT DETECTION EDR ===${NC}"
        echo -e "${DIM}Baseline: $(cat "$BASE_DIR/last-learn")${NC}"
        echo ""
        ALERTS=0

        if command -v osqueryi &>/dev/null && [[ -f "$BASE_DIR/processes.json" ]]; then
            # Comparar procesos
            echo -e "${CYAN}Procesos:${NC}"
            CURRENT=$(mktemp)
            osqueryi --json "SELECT name, path FROM processes WHERE path NOT LIKE '/usr/%' AND path != ''" > "$CURRENT" 2>/dev/null || true
            if command -v jq &>/dev/null; then
                NEW_PROCS=$(jq -r '.[].path' "$CURRENT" 2>/dev/null | sort -u | comm -13 <(jq -r '.[].path' "$BASE_DIR/processes.json" 2>/dev/null | sort -u) -)
                if [[ -n "$NEW_PROCS" ]]; then
                    echo -e "  ${YELLOW}Nuevos procesos:${NC}"
                    echo "$NEW_PROCS" | head -10 | while read -r p; do echo "    $p"; done
                    ALERTS=$((ALERTS + 1))
                else
                    echo -e "  ${GREEN}OK${NC} Sin nuevos procesos"
                fi
            fi
            rm -f "$CURRENT"

            # Comparar listeners
            echo -e "${CYAN}Puertos:${NC}"
            CURRENT=$(mktemp)
            osqueryi --json "SELECT port, protocol FROM listening_ports WHERE port != 0" > "$CURRENT" 2>/dev/null || true
            if command -v jq &>/dev/null; then
                NEW_PORTS=$(jq -r '.[] | "\(.port)/\(.protocol)"' "$CURRENT" 2>/dev/null | sort -u | comm -13 <(jq -r '.[] | "\(.port)/\(.protocol)"' "$BASE_DIR/listeners.json" 2>/dev/null | sort -u) -)
                if [[ -n "$NEW_PORTS" ]]; then
                    echo -e "  ${YELLOW}Nuevos puertos:${NC}"
                    echo "$NEW_PORTS" | while read -r p; do echo "    $p"; done
                    ALERTS=$((ALERTS + 1))
                else
                    echo -e "  ${GREEN}OK${NC} Sin nuevos puertos"
                fi
            fi
            rm -f "$CURRENT"
        fi

        echo ""
        if [[ $ALERTS -gt 0 ]]; then
            echo -e "${YELLOW}$ALERTS categorías con drift detectado${NC}"
            logger -t securizar-edr "EDR drift detected: $ALERTS categories"
        else
            echo -e "${GREEN}Sin drift detectado${NC}"
        fi
        ;;

    status)
        echo -e "${BOLD}=== Estado Baseline EDR ===${NC}"
        if [[ -f "$BASE_DIR/last-learn" ]]; then
            echo "  Último aprendizaje: $(cat "$BASE_DIR/last-learn")"
            echo "  Archivos baseline: $(ls "$BASE_DIR" | wc -l)"
        else
            echo "  No hay baseline. Ejecuta: $0 learn"
        fi
        ;;
esac
EOFBASE

    chmod 755 /usr/local/bin/securizar-edr-baseline.sh
    log_change "Creado" "/usr/local/bin/securizar-edr-baseline.sh"

    # Timer semanal
    cat > /etc/systemd/system/securizar-edr-drift.timer << 'EOFTIMER'
[Unit]
Description=EDR Drift Detection semanal

[Timer]
OnCalendar=weekly
Persistent=true

[Install]
WantedBy=timers.target
EOFTIMER

    cat > /etc/systemd/system/securizar-edr-drift.service << 'EOFSVC'
[Unit]
Description=EDR Drift Detection

[Service]
Type=oneshot
ExecStart=/usr/local/bin/securizar-edr-baseline.sh check
EOFSVC

    systemctl daemon-reload
    systemctl enable securizar-edr-drift.timer 2>/dev/null || true
    log_change "Creado" "securizar-edr-drift.timer (semanal)"
    log_info "Baseline EDR y drift detection configurados"

else
    log_skip "Baseline EDR"
fi

# ============================================================
# S8: FLEETDM PREP (ENROLLMENT)
# ============================================================
log_section "S8: FLEETDM PREP (ENROLLMENT)"

echo "Preparación para integración con FleetDM."
echo "Genera template de enrollment TLS y flags."
echo -e "${YELLOW}NO auto-enrolla - requiere servidor FleetDM.${NC}"
echo ""

if check_executable /usr/local/bin/securizar-edr-fleet.sh; then
    log_already "FleetDM prep"
elif ask "¿Crear template de integración FleetDM?"; then

    cat > /usr/local/bin/securizar-edr-fleet.sh << 'EOFFLEET'
#!/bin/bash
# ============================================================
# FLEETDM PREP - Template de enrollment
# Uso: securizar-edr-fleet.sh [FLEET_URL]
# ============================================================
set -euo pipefail

BOLD='\033[1m'; DIM='\033[2m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'

FLEET_URL="${1:-https://fleet.example.com}"
ENROLL_SECRET="${2:-FLEET_ENROLL_SECRET_HERE}"

echo -e "${BOLD}╔════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║   FLEETDM ENROLLMENT PREP              ║${NC}"
echo -e "${BOLD}╚════════════════════════════════════════╝${NC}"
echo ""

# Template de flags para fleet mode
FLEET_FLAGS="/etc/osquery/osquery.flags.fleet"
cat > "$FLEET_FLAGS" << EOFFLAGS
# FleetDM enrollment flags
--tls_hostname=$(echo "$FLEET_URL" | sed 's|https://||' | sed 's|/.*||')
--tls_server_certs=/etc/osquery/fleet-ca.pem
--enroll_tls_endpoint=/api/osquery/enroll
--config_plugin=tls
--config_tls_endpoint=/api/osquery/config
--config_tls_refresh=10
--logger_plugin=tls
--logger_tls_endpoint=/api/osquery/log
--logger_tls_period=10
--distributed_plugin=tls
--distributed_tls_max_attempts=3
--distributed_tls_read_endpoint=/api/osquery/distributed/read
--distributed_tls_write_endpoint=/api/osquery/distributed/write
--enroll_secret_path=/etc/osquery/enroll.secret
--disable_distributed=false
EOFFLAGS

echo -e "${CYAN}Flags generados:${NC} $FLEET_FLAGS"
echo ""
echo -e "${BOLD}Pasos para enrollment:${NC}"
echo "  1. Obtener el certificado CA del servidor FleetDM:"
echo "     curl -o /etc/osquery/fleet-ca.pem $FLEET_URL/api/fleet/certificate"
echo ""
echo "  2. Configurar enroll secret:"
echo "     echo '$ENROLL_SECRET' > /etc/osquery/enroll.secret"
echo "     chmod 600 /etc/osquery/enroll.secret"
echo ""
echo "  3. Aplicar flags fleet:"
echo "     cp $FLEET_FLAGS /etc/osquery/osquery.flags"
echo "     systemctl restart osqueryd"
echo ""
echo -e "${YELLOW}NOTA: NO auto-enrolla. Requiere servidor FleetDM activo.${NC}"
echo -e "${DIM}Documentación: https://fleetdm.com/docs${NC}"
EOFFLEET

    chmod 755 /usr/local/bin/securizar-edr-fleet.sh
    log_change "Creado" "/usr/local/bin/securizar-edr-fleet.sh"
    log_info "FleetDM prep instalado: securizar-edr-fleet.sh [URL]"

else
    log_skip "FleetDM prep"
fi

# ============================================================
# S9: QUERIES DIFERENCIALES PROGRAMADAS
# ============================================================
log_section "S9: QUERIES DIFERENCIALES PROGRAMADAS"

echo "Procesamiento diario de resultados diferenciales de osquery."
echo "Categorización por severidad y generación de reportes."
echo ""

if check_executable /usr/local/bin/securizar-edr-scheduled.sh; then
    log_already "Queries diferenciales"
elif ask "¿Configurar procesamiento de queries diferenciales?"; then

    cat > /usr/local/bin/securizar-edr-scheduled.sh << 'EOFSCHD'
#!/bin/bash
# ============================================================
# PROCESAMIENTO DE QUERIES DIFERENCIALES
# Analiza resultados de osquery y genera reporte diario
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

RESULT_LOG="/var/log/osquery/osqueryd.results.log"
REPORT_DIR="/var/log/securizar/edr"
mkdir -p "$REPORT_DIR"

REPORT="$REPORT_DIR/differential-$(date +%Y%m%d).txt"

echo -e "${BOLD}=== PROCESAMIENTO DE QUERIES DIFERENCIALES ===${NC}" | tee "$REPORT"
echo "Fecha: $(date -Iseconds)" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

if [[ ! -f "$RESULT_LOG" ]]; then
    echo "No hay log de resultados de osquery" | tee -a "$REPORT"
    exit 0
fi

CRITICAL=0 HIGH=0 MEDIUM=0 LOW=0

if command -v jq &>/dev/null; then
    # Procesar resultados de las últimas 24h
    SINCE=$(date -d '24 hours ago' +%s 2>/dev/null || echo 0)

    while IFS= read -r line; do
        NAME=$(echo "$line" | jq -r '.name // empty' 2>/dev/null)
        ACTION=$(echo "$line" | jq -r '.action // empty' 2>/dev/null)
        [[ -z "$NAME" ]] && continue
        [[ "$ACTION" != "added" ]] && continue

        # Categorizar por severidad
        SEV="LOW"
        case "$NAME" in
            *threat*|*reverse_shell*|*deleted_executable*|*crypto_miner*)
                SEV="CRITICAL"; CRITICAL=$((CRITICAL + 1)) ;;
            *processes_in_tmp*|*hidden_process*|*unauthorized_listener*|*promiscuous*)
                SEV="HIGH"; HIGH=$((HIGH + 1)) ;;
            *suspicious_cron*|*new_suid*|*ssh_lateral*)
                SEV="MEDIUM"; MEDIUM=$((MEDIUM + 1)) ;;
            *)
                LOW=$((LOW + 1)) ;;
        esac

        if [[ "$SEV" != "LOW" ]]; then
            echo "[$SEV] $NAME ($ACTION)" | tee -a "$REPORT"
        fi
    done < "$RESULT_LOG"
fi

echo "" | tee -a "$REPORT"
echo "Resumen:" | tee -a "$REPORT"
echo "  CRITICAL: $CRITICAL" | tee -a "$REPORT"
echo "  HIGH: $HIGH" | tee -a "$REPORT"
echo "  MEDIUM: $MEDIUM" | tee -a "$REPORT"
echo "  LOW: $LOW" | tee -a "$REPORT"

if [[ $CRITICAL -gt 0 ]]; then
    logger -t securizar-edr "CRITICAL: $CRITICAL differential alerts detected"
fi

echo "" | tee -a "$REPORT"
echo -e "${DIM}Reporte: $REPORT${NC}"
EOFSCHD

    chmod 755 /usr/local/bin/securizar-edr-scheduled.sh
    log_change "Creado" "/usr/local/bin/securizar-edr-scheduled.sh"

    # Cron diario
    cat > /etc/cron.daily/securizar-edr-differential << 'EOFCRON'
#!/bin/bash
/usr/local/bin/securizar-edr-scheduled.sh > /dev/null 2>&1
EOFCRON
    chmod 700 /etc/cron.daily/securizar-edr-differential
    log_change "Creado" "/etc/cron.daily/securizar-edr-differential"
    log_info "Queries diferenciales configuradas (cron diario)"

else
    log_skip "Queries diferenciales"
fi

# ============================================================
# S10: AUDITORÍA EDR
# ============================================================
log_section "S10: AUDITORÍA EDR"

echo "Auditoría automatizada de todos los controles EDR."
echo "Scoring de 30 puntos con verificación de cada componente."
echo ""

if check_executable /usr/local/bin/auditoria-edr.sh; then
    log_already "Auditoría EDR"
elif ask "¿Crear auditoría EDR?"; then

    cat > /usr/local/bin/auditoria-edr.sh << 'EOFAUDIT'
#!/bin/bash
# ============================================================
# AUDITORÍA EDR - Scoring de controles
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

SCORE=0; MAX=0
REPORT="/var/log/securizar/edr/auditoria-edr-$(date +%Y%m%d).txt"
mkdir -p "$(dirname "$REPORT")"

ci() {
    local d="$1" c="$2" p="${3:-1}"
    MAX=$((MAX + p))
    if eval "$c" &>/dev/null; then
        echo -e "  ${GREEN}[+$p]${NC}  $d" | tee -a "$REPORT"
        SCORE=$((SCORE + p))
    else
        echo -e "  ${RED}[  0]${NC}  $d" | tee -a "$REPORT"
    fi
}

echo -e "${BOLD}╔════════════════════════════════════════╗${NC}" | tee "$REPORT"
echo -e "${BOLD}║   AUDITORÍA EDR                        ║${NC}" | tee -a "$REPORT"
echo -e "${BOLD}╚════════════════════════════════════════╝${NC}" | tee -a "$REPORT"
echo "Fecha: $(date -Iseconds)" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

echo -e "${CYAN}── Osquery ──${NC}" | tee -a "$REPORT"
ci "osquery instalado" "command -v osqueryi" 3
ci "osqueryd activo" "systemctl is-active osqueryd" 3
ci "Config principal" "test -f /etc/osquery/osquery.conf" 2
ci "Pack seguridad" "test -f /etc/osquery/packs/securizar-security.conf" 2
ci "Pack threat detection" "test -f /etc/osquery/packs/securizar-threat-detection.conf" 3

echo "" | tee -a "$REPORT"
echo -e "${CYAN}── Integración ──${NC}" | tee -a "$REPORT"
ci "Guía Wazuh" "test -x /usr/local/bin/securizar-edr-wazuh.sh" 1
ci "Decorators" "test -f /etc/securizar/edr/decorators.conf" 2
ci "Alertas syslog" "test -x /usr/local/bin/securizar-edr-alerts.sh" 2

echo "" | tee -a "$REPORT"
echo -e "${CYAN}── Detección ──${NC}" | tee -a "$REPORT"
ci "Baseline EDR" "test -f /var/lib/securizar/edr/baseline/last-learn" 3
ci "Drift timer" "systemctl is-enabled securizar-edr-drift.timer" 2
ci "Queries diferenciales" "test -x /usr/local/bin/securizar-edr-scheduled.sh" 2
ci "FleetDM prep" "test -x /usr/local/bin/securizar-edr-fleet.sh" 1

echo "" | tee -a "$REPORT"
PCT=0; [[ $MAX -gt 0 ]] && PCT=$((SCORE * 100 / MAX))
echo -e "${BOLD}Score: $SCORE/$MAX ($PCT%)${NC}" | tee -a "$REPORT"

LEVEL="BAJO"
[[ $PCT -ge 80 ]] && LEVEL="EXCELENTE"
[[ $PCT -ge 60 ]] && [[ $PCT -lt 80 ]] && LEVEL="BUENO"
[[ $PCT -ge 40 ]] && [[ $PCT -lt 60 ]] && LEVEL="PARCIAL"
echo -e "${BOLD}Nivel: $LEVEL${NC}" | tee -a "$REPORT"
echo -e "${DIM}Reporte: $REPORT${NC}"
logger -t securizar-edr "EDR audit: $SCORE/$MAX ($PCT%) $LEVEL"
EOFAUDIT

    chmod 755 /usr/local/bin/auditoria-edr.sh
    log_change "Creado" "/usr/local/bin/auditoria-edr.sh"

    # Cron semanal
    cat > /etc/cron.weekly/auditoria-edr << 'EOFCRON'
#!/bin/bash
/usr/local/bin/auditoria-edr.sh > /dev/null 2>&1
EOFCRON
    chmod 700 /etc/cron.weekly/auditoria-edr
    log_change "Creado" "/etc/cron.weekly/auditoria-edr"
    log_info "Auditoría EDR instalada"

else
    log_skip "Auditoría EDR"
fi

echo ""
show_changes_summary
log_info "Módulo EDR con Osquery completado"
log_info "Backup en: $BACKUP_DIR"
