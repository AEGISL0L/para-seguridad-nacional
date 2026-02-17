# Securizar

Suite completa de hardening y securizacion para Linux, con 78 modulos interactivos, cobertura total del framework MITRE ATT&CK, operaciones de seguridad (SOC), ciberinteligencia avanzada (MISP, STIX/TAXII, plataforma TIP, OSINT), cumplimiento CIS/GDPR/PCI-DSS/HIPAA/SOC2/ISO27001, forensia digital, Zero Trust, DevSecOps, anti-ransomware, seguridad de APIs/IoT/DNS, auditoria de red con Wireshark, auditoria de infraestructura de red, proteccion runtime del kernel (LKRG, eBPF, Falco), hardening avanzado de memoria/procesos (ASLR, W^X, seccomp, cgroups v2), respuesta a incidentes (forense, custodia digital, IOCs, escalacion, hunting, metricas IR), EDR con osquery (threat detection, Wazuh, fleet, baseline/drift), gestion de vulnerabilidades (Trivy, grype, OpenSCAP, CVSS/EPSS, drift), control de acceso obligatorio (SELinux/AppArmor), aislamiento de namespaces, integridad de arranque (Secure Boot, TPM2, IMA/EVM), gestion de acceso privilegiado, caza de APTs (YARA, IOC sweep, hunting playbooks), inteligencia de trafico de red (JA3, beaconing, exfiltracion) y monitorizacion de superficie de ataque (CT logs, subdominios, fugas). Soporta multiples distribuciones mediante una biblioteca de abstraccion compartida.

```
███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗███████╗ █████╗ ██████╗
██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══███╔╝██╔══██╗██╔══██╗
███████╗█████╗  ██║     ██║   ██║██████╔╝██║  ███╔╝ ███████║██████╔╝
╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║ ███╔╝  ██╔══██║██╔══██╗
███████║███████╗╚██████╗╚██████╔╝██║  ██║██║███████╗██║  ██║██║  ██║
╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
```

## Caracteristicas principales

- **78 modulos** organizados en 10 categorias con menu interactivo
- **Multi-distro**: openSUSE, Debian/Ubuntu, RHEL/Fedora/CentOS, Arch Linux
- **Cobertura MITRE ATT&CK** de las 14 tacticas enterprise (TA0001-TA0043)
- **100% interactivo**: cada seccion pregunta antes de aplicar cambios
- **Backups automaticos** antes de cada modificacion
- **Protecciones de seguridad**: no bloquea al usuario, no modifica PAM, no deshabilita SSH
- **Verificacion proactiva** de 87 categorias de controles
- **Operaciones SOC**: IR, monitoreo continuo, SOAR, threat hunting, purple team
- **Ciberinteligencia**: enriquecimiento de IoC, inteligencia DNS, alerta temprana, MISP/STIX/TAXII, plataforma TIP
- **Inteligencia de red**: JA3/JA4 fingerprinting, beaconing C2, passive DNS, exfiltracion, forense de red
- **OSINT**: Certificate Transparency, subdominios, WHOIS, cloud discovery, fugas de codigo, vendor risk
- **Cumplimiento**: CIS Benchmarks Level 1/2, NIST 800-53, PCI-DSS v4.0, GDPR, HIPAA, SOC2, ISO 27001
- **Anti-ransomware**: canary files, LVM snapshots, whitelisting, YARA, containment
- **DevSecOps**: CI/CD pipeline security, SAST, secrets detection, code signing
- **Seguridad de APIs**: rate limiting, JWT/OAuth2, mTLS, GraphQL, WAF
- **IoT**: MQTT hardening, device inventory, firmware integrity, segmentacion
- **DNS avanzado**: DNSSEC, DoT/DoH, RPZ sinkhole, tunneling detection
- **Auditoria de red**: Wireshark, tshark, capturas automatizadas, deteccion de anomalias (18 checks: ARP, DHCP, DNS tunneling, Spotify Connect, Google Cast, SSDP/UPnP, SNMP, MAC randomization), correlacion IDS
- **Auditoria de infraestructura de red**: nmap, TLS/SSL (testssl.sh), SNMP, inventario de servicios, baseline y drift, deteccion de APIs IoT expuestas (Cast/Roku/UPnP/IPP), deteccion EOL 12+ categorias, generacion automatica de script de aislamiento LAN, protocolos modernos (MQTT, Modbus/ICS, CoAP, AMQP, Kubernetes API), CVE cross-reference de versiones de servicios
- **Runtime kernel**: LKRG, kernel lockdown, eBPF hardening, Falco, module signing, CPU mitigations
- **Memoria y procesos**: ASLR, PIE enforcement, W^X, seccomp-BPF, cgroups v2, ptrace, coredumps
- **YARA + Sigma**: reglas de deteccion de malware y correlacion de eventos de evasion
- **Post-quantum crypto**: evaluacion de preparacion ML-KEM/ML-DSA, Certificate Transparency
- **EDR con osquery**: packs de seguridad, deteccion de amenazas, Wazuh, FleetDM, baseline/drift, alertas syslog
- **Gestion de vulnerabilidades**: Trivy, grype, OpenSCAP, priorizacion CVSS+EPSS+KEV+Reachability, reporting HTML, drift, madurez, deteccion directa de CVEs kernel (2024-2026), verificacion de integridad supply chain

---

## Requisitos

- **Sistema operativo**: Linux (cualquier familia soportada)
- **Permisos**: root (`sudo bash securizar-menu.sh`)
- **Shell**: Bash 4.0+
- **Dependencias**: las herramientas se instalan automaticamente al ejecutar cada modulo (fail2ban, ClamAV, Suricata, AIDE, etc.)

### Distribuciones soportadas

| Familia | Distribuciones | Gestor de paquetes | Firewall por defecto |
|---------|---------------|-------------------|---------------------|
| `suse` | openSUSE Leap/Tumbleweed, SLES | zypper | firewalld |
| `debian` | Debian, Ubuntu, Linux Mint, Kali, Pop!_OS | apt | ufw |
| `rhel` | RHEL, Fedora, CentOS, Rocky, Alma | dnf | firewalld |
| `arch` | Arch Linux, Manjaro, EndeavourOS | pacman | nftables/iptables |

---

## Inicio rapido

```bash
# Clonar el repositorio
git clone https://github.com/tu-usuario/securizar.git
cd securizar

# Ejecutar el menu interactivo (requiere root)
sudo bash securizar-menu.sh
```

El menu principal muestra 10 categorias con indicadores de progreso. Se navega con las teclas indicadas o accediendo directamente por numero de modulo (1-78):

```
  b  Hardening Base            (modulos 1-9)    ●●●○○○○○○○
  p  Securizacion Proactiva    (modulos 10-17)   ○○○○○○○○
  m  Mitigaciones MITRE        (modulos 18-29)   ○○○○○○○○○○○○
  o  Operaciones de Seguridad  (modulos 30-34)   ○○○○○
  i  Inteligencia              (3 modulos)       ○○○
  ─────────────────────────────────────────────
  n  Infraestructura y Red     (9 modulos)       ○○○○○○○○○
  s  Aplicaciones y Servicios  (8 modulos)       ○○○○○○○○
  r  Proteccion y Resiliencia  (11 modulos)      ○○○○○○○○○○○
  d  Deteccion y Respuesta     (11 modulos)      ○○○○○○○○○○○
  c  Cumplimiento              (2 modulos)       ○○

  a  Aplicar todos    v  Verificacion    1-78 Acceso directo    q  Salir
```

Tambien es posible ejecutar cualquier modulo individualmente:

```bash
sudo bash hardening-opensuse.sh      # Modulo 1
sudo bash mitigar-acceso-inicial.sh  # Modulo 18
```

---

## Estructura del proyecto

```
securizar/
├── securizar-menu.sh              # Menu orquestador principal (78 modulos)
├── securizar.conf                 # Configuracion global (opcional)
├── lib/                           # Biblioteca compartida
│   ├── securizar-common.sh        # Punto de entrada: colores, logging, ask(), backup
│   ├── securizar-distro.sh        # Deteccion automatica de distribucion
│   ├── securizar-pkg-map.sh       # Mapeo de nombres de paquetes por distro
│   ├── securizar-pkg.sh           # Abstraccion del gestor de paquetes
│   ├── securizar-firewall.sh      # Abstraccion de firewall multi-backend
│   ├── securizar-paths.sh         # Rutas GRUB y SCAP por distribucion
│   ├── securizar-msf.sh           # Integracion con Metasploit Framework
│   └── ciberint-lib.sh            # Biblioteca de ciberinteligencia
│
├── hardening-opensuse.sh          # Modulo   1: Hardening base del sistema
├── hardening-seguro.sh            # Modulo   2: Nivel seguro de hardening
├── hardening-final.sh             # Modulo   3: Hardening final consolidado
├── hardening-externo.sh           # Modulo   4: Hardening de servicios externos
├── hardening-extremo.sh           # Modulo   5: Nivel extremo (via menu = seguro)
├── hardening-paranoico.sh         # Modulo   6: Nivel paranoico (via menu = seguro)
├── contramedidas-mesh.sh          # Modulo   7: Contramedidas de red mesh
├── proteger-privacidad.sh         # Modulo   8: Proteccion de privacidad
├── aplicar-banner-total.sh        # Modulo  9: Banners de seguridad
├── hardening-kernel-boot.sh       # Modulo 10: Kernel boot y Secure Boot
├── hardening-servicios-systemd.sh # Modulo 11: Sandboxing de servicios systemd
├── hardening-cuentas.sh           # Modulo 12: Seguridad de cuentas
├── proteger-red-avanzado.sh       # Modulo 13: Red avanzada (IDS, VPN, DoT)
├── automatizar-seguridad.sh       # Modulo 14: Automatizacion de seguridad
├── sandbox-aplicaciones.sh        # Modulo 15: Sandboxing de aplicaciones
├── auditoria-externa.sh           # Modulo 16: Auditoria de reconocimiento
├── inteligencia-amenazas.sh       # Modulo 17: Inteligencia de amenazas IoC
├── mitigar-acceso-inicial.sh      # Modulo 18: MITRE TA0001
├── mitigar-ejecucion.sh           # Modulo 19: MITRE TA0002
├── mitigar-persistencia.sh        # Modulo 20: MITRE TA0003
├── mitigar-escalada.sh            # Modulo 21: MITRE TA0004
├── mitigar-impacto.sh             # Modulo 22: MITRE TA0040
├── mitigar-evasion.sh             # Modulo 23: MITRE TA0005
├── mitigar-credenciales.sh        # Modulo 24: MITRE TA0006
├── mitigar-descubrimiento.sh      # Modulo 25: MITRE TA0007
├── mitigar-movimiento-lateral.sh  # Modulo 26: MITRE TA0008
├── mitigar-recoleccion.sh         # Modulo 27: MITRE TA0009
├── mitigar-exfiltracion.sh        # Modulo 28: MITRE TA0010
├── mitigar-comando-control.sh     # Modulo 29: MITRE TA0011
├── monitorizar-continuo.sh        # Modulo 30: Monitorizacion continua
├── reportar-seguridad.sh          # Modulo 31: Reportes de seguridad
├── cazar-amenazas.sh              # Modulo 32: Caza de amenazas (UEBA)
├── automatizar-respuesta.sh       # Modulo 33: Automatizacion SOAR
├── validar-controles.sh           # Modulo 34: Validacion Purple Team
├── ciberinteligencia.sh           # Modulo 35: Ciberinteligencia proactiva
├── proteger-contra-isp.sh         # Modulo 36: Proteccion contra espionaje ISP
├── hardening-criptografico.sh     # Modulo 37: Hardening criptografico
├── seguridad-contenedores.sh      # Modulo 38: Seguridad de contenedores
├── cumplimiento-cis.sh            # Modulo 39: Cumplimiento CIS Benchmarks
├── seguridad-email.sh             # Modulo 40: Seguridad de email
├── logging-centralizado.sh        # Modulo 41: Logging centralizado y SIEM
├── seguridad-cadena-suministro.sh # Modulo 42: Cadena de suministro
├── segmentacion-red-zt.sh         # Modulo 43: Segmentacion de red y Zero Trust
├── forense-avanzado.sh            # Modulo 44: Forense avanzado
├── kernel-livepatch.sh            # Modulo 45: Kernel live patching
├── seguridad-bases-datos.sh       # Modulo 46: Seguridad de bases de datos
├── backup-recuperacion.sh         # Modulo 47: Backup y recuperacion
├── seguridad-web.sh               # Modulo 48: Seguridad web
├── seguridad-secrets.sh           # Modulo 49: Gestion de secretos
├── seguridad-cloud.sh             # Modulo 50: Seguridad cloud
├── seguridad-ldap-ad.sh           # Modulo 51: LDAP y Active Directory
├── cumplimiento-normativo.sh      # Modulo 52: Cumplimiento normativo
├── tecnologia-engano.sh           # Modulo 53: Tecnologia de engano
├── seguridad-wireless.sh          # Modulo 54: Seguridad wireless
├── seguridad-virtualizacion.sh    # Modulo 55: Seguridad de virtualizacion
├── seguridad-fisica.sh            # Modulo 56: Seguridad fisica avanzada
├── zero-trust-identity.sh         # Modulo 57: Zero Trust Identity
├── proteger-ransomware.sh         # Modulo 58: Proteccion anti-ransomware
├── gestion-parches.sh             # Modulo 59: Gestion de parches
├── devsecops-hardening.sh         # Modulo 60: DevSecOps hardening
├── seguridad-api.sh               # Modulo 61: Seguridad de APIs
├── seguridad-iot.sh               # Modulo 62: Seguridad IoT
├── seguridad-dns-avanzada.sh      # Modulo 63: DNS avanzado
├── auditoria-red-wireshark.sh     # Modulo 64: Auditoria de red con Wireshark
├── auditoria-red-infraestructura.sh # Modulo 65: Auditoria de infraestructura de red
├── seguridad-runtime-kernel.sh    # Modulo 66: Proteccion runtime del kernel
├── hardening-memoria-procesos.sh  # Modulo 67: Hardening de memoria y procesos
├── respuesta-incidentes.sh        # Modulo 68: Respuesta a incidentes (IR, forense, custodia, IOCs, hunting)
├── edr-osquery.sh                 # Modulo 69: EDR con osquery (threat detection, Wazuh, fleet, baseline)
├── gestion-vulnerabilidades.sh    # Modulo 70: Gestion de vulnerabilidades (Trivy, grype, SCAP, CVSS/EPSS)
├── mac-selinux-apparmor.sh        # Modulo 71: Control de acceso obligatorio (SELinux/AppArmor)
├── aislamiento-namespaces.sh      # Modulo 72: Aislamiento de namespaces
├── integridad-arranque.sh         # Modulo 73: Integridad de arranque (Secure Boot, UEFI, TPM2)
├── acceso-privilegiado.sh         # Modulo 74: Gestion de acceso privilegiado
├── caza-apt-hunting.sh            # Modulo 75: Caza de APTs (YARA, IOC sweep, hunting playbooks)
├── inteligencia-red-avanzada.sh   # Modulo 76: Inteligencia de red (JA3, beaconing, pDNS, exfiltracion)
├── plataforma-tip.sh              # Modulo 77: Plataforma TIP (MISP, STIX, TAXII, IOC lifecycle)
├── osint-superficie.sh            # Modulo 78: OSINT y superficie de ataque (CT, subdominios, fugas)
│
└── panel/                         # Panel web Django (monitor de deception)
    ├── manage.py
    ├── panel/                     # Config Django (settings, urls, wsgi)
    ├── dashboard/                 # App principal (views, parsers, monitor, europol)
    └── templates/                 # Templates HTML con tema oscuro inline
```

---

## Panel Web - Monitor de Tecnologia de Engano (`panel/`)

Panel web local para visualizar en tiempo real las alertas del sistema de deception, explorar evidencia forense y generar reportes para Europol.

### Stack

- **Django 5+** con SQLite, bind `127.0.0.1:3000` (solo acceso local)
- **Python 3.13**, sin dependencias JS externas, CSS inline (tema oscuro)
- Interfaz en espanol

### Inicio rapido

```bash
cd panel
pip install django
python3 manage.py migrate
python3 manage.py runserver 127.0.0.1:3000
```

### Funcionalidades

| Seccion | Ruta | Descripcion |
|---------|------|-------------|
| **Dashboard** | `/` | Cards de estado (tokens, alertas, incidentes, nivel de amenaza), feed de alertas en vivo (SSE/AJAX), incidentes recientes, tokens comprometidos |
| **Tokens** | `/tokens/` | Tabla de honey tokens con estado (OK/LEIDO/MODIFICADO/BORRADO), alta y baja de tokens |
| **Detalle Token** | `/tokens/<id>/` | Metadata, historial de alertas, incidentes forenses relacionados |
| **Incidentes** | `/incidents/` | Lista de incidentes forenses con filtros (evento, token), paginacion |
| **Detalle Incidente** | `/incidents/<id>/` | Metadata, verificacion de integridad SHA256, todos los archivos de evidencia |
| **Visor Evidencia** | `/incidents/<id>/evidence/<file>` | Contenido de archivo de evidencia individual (con proteccion path traversal) |
| **Monitor** | `/monitor/` | Estado del daemon inotifywait, controles start/stop, estado de auditd |
| **Europol** | `/europol/` | Formulario para seleccionar incidentes y generar reporte self-contained (HTML printable con timeline, IOCs, cadena de custodia) |
| **Config** | `/settings/` | Umbrales de alerta, intervalo de polling, datos de organizacion |

### APIs

| Endpoint | Formato | Descripcion |
|----------|---------|-------------|
| `/api/alerts/` | JSON | Ultimas N alertas, filtro por timestamp (`?since=`) |
| `/api/status/` | JSON | Estado del monitor, contadores globales |
| `/api/alerts/stream/` | SSE | Stream en tiempo real (tail del alert log) |

### Reporte Europol

El reporte generado es un HTML self-contained (sin assets externos) que incluye:

1. Datos del denunciante y referencia del caso
2. Resumen ejecutivo (tokens afectados, total alertas)
3. Timeline cronologica de eventos
4. Indicadores de compromiso (IPs, procesos, hashes SHA256)
5. Detalle por incidente (metadata, red, procesos, auditd)
6. Cadena de custodia (verificacion de integridad de evidencia)
7. Tokens afectados con metadata

Incluye botones de impresion y descarga, con `@media print` para formato correcto en papel.

### Data sources

El panel lee directamente los archivos generados por `tecnologia-engano.sh` (modulo 53):

| Archivo | Formato | Contenido |
|---------|---------|-----------|
| `~/.config/securizar/honey-registry.conf` | Pipe-delimited | Registro de tokens: `ID\|PATH\|TYPE\|DATE\|DESC` |
| `~/.config/securizar/honey-alerts.log` | Texto | Alertas: `[TIMESTAMP] EVENT CANARY_ID PATH` |
| `~/.config/securizar/honey-forensic.log` | Key-value | Incidentes: INCIDENT, TIME, EVENT, TOKEN, EVIDENCE, SSH_ORIGINS |
| `~/.config/securizar/evidence/*/` | Directorios | 10+ archivos por incidente (incident.json, network, processes, auditd, hashes, manifest) |

### Seguridad

- Bind exclusivo a `127.0.0.1` (sin acceso remoto)
- CSRF habilitado por defecto (Django)
- Proteccion contra path traversal en visor de evidencia
- SECRET_KEY generada aleatoriamente en primer arranque
- DEBUG=False

---

## Biblioteca compartida (`lib/`)

Todos los scripts cargan la biblioteca con una unica linea:

```bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"
```

Esto provee deteccion de distro, gestion de paquetes, firewall, rutas del sistema y funciones de utilidad, todo abstraido por distribucion.

### `securizar-common.sh` - Punto de entrada

Carga todos los demas modulos de `lib/` y provee las funciones comunes:

| Funcion | Descripcion |
|---------|-------------|
| `log_info "msg"` | Mensaje con icono `[+]` verde |
| `log_warn "msg"` | Advertencia con icono `[!]` amarillo |
| `log_error "msg"` | Error con icono `[X]` rojo |
| `log_section "titulo"` | Separador visual con `══════` |
| `log_alert "msg"` | Alerta critica con `[!!!]` rojo bold |
| `log_change "verbo" "detalle"` | Registra un cambio aplicado (`->`) |
| `log_skip "desc"` | Registra una accion omitida (`--`) |
| `show_changes_summary` | Resumen con contadores de cambios/omitidos |
| `ask "pregunta"` | Prompt interactivo `[s/N]`, devuelve `true` si responde `s` |
| `require_root` | Aborta si no es root |
| `init_backup "nombre"` | Crea `$BACKUP_DIR` con timestamp |
| `securizar_setup_traps [func]` | Instala traps ERR/EXIT con diagnostico |
| `get_privileged_group` | Devuelve `wheel`, `sudo` o `root` segun la distro |

Ademas:
- Umask restrictiva `0077` por defecto para que los backups no sean world-readable
- Validacion de seguridad de `securizar.conf` antes de cargarlo (permisos, owner, sintaxis)
- Variable `SSH_SERVICE_NAME` ajustada automaticamente (`ssh` en Debian, `sshd` en el resto)

### `securizar-distro.sh` - Deteccion de distribucion

Lee `/etc/os-release` y clasifica el sistema en una familia:

```bash
# Variables exportadas
DISTRO_ID       # ej: "opensuse-tumbleweed", "ubuntu", "fedora"
DISTRO_FAMILY   # ej: "suse", "debian", "rhel", "arch"
DISTRO_VERSION  # ej: "15.5", "22.04", "39"
DISTRO_NAME     # ej: "openSUSE Tumbleweed"
```

Soporta fallback via `ID_LIKE` para derivadas no reconocidas directamente.

### `securizar-pkg-map.sh` - Mapeo de paquetes

Tabla de 50+ paquetes con sus nombres equivalentes por distribucion:

```bash
# Formato: PKG_MAP[nombre_generico]="suse|debian|rhel|arch"
PKG_MAP[audit]="audit|auditd|audit|audit"
PKG_MAP[openscap-utils]="openscap-utils|libopenscap8|openscap-utils|openscap"
PKG_MAP[google-authenticator-libpam]="google-authenticator-libpam|libpam-google-authenticator|google-authenticator|libpam-google-authenticator"
```

`pkg_resolve_name "audit"` devuelve `auditd` en Debian o `audit` en el resto. Si un paquete no existe en una distro, el valor es `"-"` y se omite automaticamente.

### `securizar-pkg.sh` - Abstraccion del gestor de paquetes

| Funcion | Descripcion |
|---------|-------------|
| `pkg_install pkg1 [pkg2...]` | Instala paquetes resolviendo nombres por distro |
| `pkg_remove pkg1 [pkg2...]` | Elimina paquetes |
| `pkg_refresh` | Actualiza cache de repositorios |
| `pkg_patch_security` | Instala solo parches de seguridad |
| `pkg_list_security_patches` | Lista parches de seguridad pendientes |
| `pkg_is_installed pkg` | Verifica si un paquete esta instalado |
| `pkg_query_all` | Lista todos los paquetes instalados |
| `pkg_query_file file` | Consulta a que paquete pertenece un archivo |
| `pkg_verify` | Verifica integridad de paquetes instalados |
| `pkg_verify_single pkg` | Verifica un paquete especifico |
| `pkg_query_signatures` | Lista paquetes con informacion de firma |
| `pkg_audit_tool_paths` | Rutas del gestor de paquetes para reglas auditd |

Maneja internamente `zypper`, `apt`, `dnf` y `pacman` segun `$DISTRO_FAMILY`.

### `securizar-firewall.sh` - Abstraccion de firewall

Detecta automaticamente el backend de firewall activo (override posible via `securizar.conf`):

**Orden de deteccion**: firewalld > ufw > nftables > iptables

| Funcion | Descripcion |
|---------|-------------|
| `fw_is_active` | Verifica si hay un firewall activo |
| `fw_add_service service [zone]` | Permite un servicio |
| `fw_remove_service service [zone]` | Bloquea un servicio |
| `fw_add_port port/proto [zone]` | Abre un puerto |
| `fw_remove_port port/proto [zone]` | Cierra un puerto |
| `fw_add_rich_rule rule [zone]` | Agrega regla avanzada |
| `fw_set_default_zone zone` | Cambia la zona por defecto |
| `fw_reload` | Recarga la configuracion (soporta openSUSE y Debian paths) |
| `fw_list_all` | Lista todas las reglas activas |
| `fw_direct_add_rule ...` | Regla directa (iptables-like) |
| `fw_check_firewalld_conflict` | Detecta si firewalld impide que nftables arranque al boot |
| `fw_fix_firewalld_conflict` | Resuelve el conflicto: stop + mask firewalld, enable nftables |

Para nftables, mantiene una tabla `inet securizar` y resuelve automaticamente puertos de servicios conocidos.

**Conflicto firewalld/nftables**: firewalld usa nftables como backend pero tiene `Conflicts=nftables.service`, lo que impide que ambos esten activos. Si se usa nftables directo, firewalld debe estar masked (`systemctl mask firewalld`). Las funciones `fw_check_firewalld_conflict` y `fw_fix_firewalld_conflict` detectan y resuelven esto automaticamente.

### `securizar-paths.sh` - Rutas GRUB y SCAP

Ajusta rutas del sistema automaticamente por distribucion:

```bash
# GRUB
GRUB_CFG          # /boot/grub2/grub.cfg (suse/rhel) o /boot/grub/grub.cfg (debian/arch)
GRUB_CFG_DIR      # Directorio de configuracion GRUB
GRUB_EFI_CFG      # Ruta del grub.cfg en particion EFI
GRUB_MKCONFIG_CMD # grub2-mkconfig, grub-mkconfig o update-grub
GRUB_SETPASSWORD_CMD
SCAP_DS_PATH      # Datastream OpenSCAP por distro
SCAP_OVAL_PATH    # OVAL definitions por distro
```

Funciones helper:
- `grub_regenerate` - Regenera grub.cfg con el comando correcto
- `grub_set_password` - Establece contrasena de GRUB

### `securizar-msf.sh` - Integracion Metasploit

Abstraccion de Metasploit Framework para validacion purple team:

| Funcion | Descripcion |
|---------|-------------|
| `msf_is_available` | Retorna 0 si msfconsole esta disponible |
| `msf_db_init` | Arranca PostgreSQL e inicializa DB |
| `msf_run_check module rhosts [opts]` | Ejecuta modulo en modo check (no destructivo) |
| `msf_run_scan module rhosts [opts]` | Ejecuta scanner auxiliar |
| `msf_run_rc rc_file` | Ejecuta resource script |
| `msf_generate_payload format lhost lport output` | Wrapper de msfvenom para test AV |
| `msf_parse_output text pattern` | Parsea salida MSF |
| `msf_cleanup` | Limpia temporales y para PostgreSQL si lo arranco |

Por seguridad, los objetivos estan restringidos a `127.0.0.1` por defecto (`SECURIZAR_MSF_TARGETS`).

### `ciberint-lib.sh` - Biblioteca de ciberinteligencia

Funciones compartidas para los modulos de ciberinteligencia (35, 76-78):
- Enriquecimiento de IoC con scoring 0-100 (IPs y dominios)
- Consulta de APIs de inteligencia de amenazas con rate limiting
- Umbrales configurables: enrich (30), alert (50), block (75)
- Gestion de cache con TTL de 24h
- Generador de indicadores STIX 2.1
- Normalizacion de IOC (defang/refang)
- Rate limiter por servicio API
- Merge de objetos JSON

---

## Configuracion (`securizar.conf`)

Archivo opcional en la raiz del proyecto. Se carga automaticamente si pasa las validaciones de seguridad (propiedad root, no world-writable, solo asignaciones de variables).

```bash
# Directorio base para backups (default: /root)
SECURIZAR_BACKUP_BASE="/root"

# Backend de firewall forzado (default: autodeteccion)
# Valores: firewalld, ufw, nftables, iptables
SECURIZAR_FW_BACKEND=""

# Archivo de log global (default: sin log a archivo)
SECURIZAR_LOG_TO_FILE="/var/log/securizar.log"

# Timeout de Metasploit en segundos (default: 120)
SECURIZAR_MSF_TIMEOUT=120

# Objetivos para pruebas Metasploit (default: 127.0.0.1)
SECURIZAR_MSF_TARGETS="127.0.0.1"
```

---

## Catalogo de modulos

### Categoria 1: Hardening Base (modulos 1-9)

Modulos fundamentales de securizacion del sistema.

| # | Modulo | Script | Descripcion |
|---|--------|--------|-------------|
| 1 | **Hardening base** | `hardening-opensuse.sh` | 16 secciones: hardening de kernel (sysctl con protecciones memoria 2025: dmesg_restrict, ptrace_scope=2, kptr_restrict=2, perf_event_paranoid=3, unprivileged_userns_clone=0), blacklist de modulos kernel peligrosos (DCCP, SCTP, RDS, TIPC, Firewire), hardening de filesystem (noexec /tmp /dev/shm /var/tmp), eliminacion de FTP, servicios innecesarios, firewall, SSH hardening 2025 (MaxStartups, LogLevel VERBOSE, curve25519-only, Compression no), politicas de contrasenas, permisos de archivos criticos, fail2ban, actualizaciones automaticas, auditd con 50+ reglas MITRE (execve, ptrace, modulos, namespaces, red, persistencia), MFA para SSH, ClamAV antimalware, OpenSCAP, verificacion de CVEs kernel criticos (CVE-2025-21756, CVE-2025-38236, CVE-2025-39866, CVE-2024-1086, CVE-2022-0847), banner legal |
| 2 | **Hardening seguro** | `hardening-seguro.sh` | Seguridad de archivos, procesos, AIDE (integridad), claves SSH |
| 3 | **Hardening final** | `hardening-final.sh` | Consolidacion de auditd, sysctl avanzado, reglas de firewall, actualizaciones |
| 4 | **Hardening externo** | `hardening-externo.sh` | Banners de seguridad, honeypot, DNS seguro, plantilla VPN |
| 5 | **Hardening extremo** | *(inline en menu)* | USB, kernel, red. **SEGURO**: el menu reimplementa este modulo eliminando las secciones que causan lockout (deshabilitacion de sshd, firewall DROP, chattr +i) |
| 6 | **Hardening paranoico** | *(inline en menu)* | Core dumps, GRUB, auditoria avanzada, deteccion conflicto firewalld/nftables, aislamiento LAN triple (MAC+IP+subnet). **SEGURO**: el menu reimplementa eliminando TMOUT readonly y modificacion de PAM |
| 7 | **Contramedidas mesh** | `contramedidas-mesh.sh` | Proteccion de redes WiFi, Bluetooth e IoT mesh |
| 8 | **Proteger privacidad** | `proteger-privacidad.sh` | VNC seguro, camara, prevencion DNS leaks, integracion Tor |
| 9 | **Aplicar banners** | `aplicar-banner-total.sh` | MOTD, /etc/issue, banner SSH, GDM, Firefox |

### Categoria 2: Securizacion Proactiva (modulos 10-17)

Modulos avanzados de proteccion preventiva.

| # | Modulo | Script | Descripcion |
|---|--------|--------|-------------|
| 10 | **Kernel boot y Secure Boot** | `hardening-kernel-boot.sh` | Parametros GRUB cmdline, verificacion Secure Boot, modulos firmados, proteccion GRUB con contrasena, lockdown del kernel |
| 11 | **Sandboxing de servicios** | `hardening-servicios-systemd.sh` | Drop-ins systemd para sshd, fail2ban, firewalld, NetworkManager, security-monitor con ProtectSystem, ProtectHome, NoNewPrivileges |
| 12 | **Seguridad de cuentas** | `hardening-cuentas.sh` | Politicas de contrasenas en login.defs, faillock, deteccion de cuentas sin contrasena, verificacion UID=0 extra, shells de sistema, cuentas inactivas |
| 13 | **Red avanzada** | `proteger-red-avanzado.sh` | Suricata IDS, DNS over TLS, WireGuard VPN, arpwatch, captura forense ring buffer, custom IDS rules, DNS sinkhole, baseline de trafico, auditoria de red, proteccion ARP avanzada (arp_accept/arp_filter/IPv6 ND hardening), validacion MAC del gateway |
| 14 | **Automatizacion** | `automatizar-seguridad.sh` | Cron jobs para AIDE, parches de seguridad, lynis, rkhunter, logrotate, digest diario; timer systemd de notificaciones |
| 15 | **Sandboxing de aplicaciones** | `sandbox-aplicaciones.sh` | Firejail (perfiles para Firefox, Thunderbird, LibreOffice, Dolphin, firecfg), bubblewrap |
| 16 | **Auditoria externa** | `auditoria-externa.sh` | Reconocimiento MITRE TA0043: puertos expuestos, banners, fingerprinting OS, DNS, cabeceras HTTP, SNMP, consulta Shodan/Censys, metadatos web, certificados SSL/TLS, defensas anti-escaneo |
| 17 | **Inteligencia de amenazas** | `inteligencia-amenazas.sh` | MITRE M1019/TA0042: feeds de IoC (Blocklist.de, Feodo Tracker, ET, Spamhaus DROP/EDROP, Tor Exit Nodes, CI Army, SSLBL, URLhaus), integracion firewall/ipset, reglas Suricata, herramienta `ioc-lookup.sh`, actualizacion diaria |

### Categoria 3: Mitigaciones MITRE ATT&CK (modulos 18-29)

Defensas especificas contra cada tactica del framework MITRE ATT&CK.

| # | Modulo | Script | Tactica | Tecnicas principales |
|---|--------|--------|---------|---------------------|
| 18 | **Acceso inicial** | `mitigar-acceso-inicial.sh` | TA0001 | T1133 (SSH), T1190 (exploits web), T1078 (cuentas validas), T1566 (phishing), T1189 (drive-by), T1195 (supply chain GPG), T1200 (USBGuard/DMA) |
| 19 | **Ejecucion** | `mitigar-ejecucion.sh` | TA0002 | T1059 (AppArmor, bash restringido, interpretes), T1204 (noexec /tmp), T1129 (restriccion LD_PRELOAD), monitor de ejecucion |
| 20 | **Persistencia** | `mitigar-persistencia.sh` | TA0003 | T1053 (cron/timers), T1543 (servicios systemd), T1547/T1037 (autostart), T1136 (cuentas), T1556 (autenticacion), T1574 (PATH hijack) |
| 21 | **Escalada de privilegios** | `mitigar-escalada.sh` | TA0004 | T1548 (SUID/SGID), T1134 (capabilities), T1078 (sudo), T1068 (kernel sysctl), T1055 (anti-ptrace), T1053 (cron privesc) |
| 22 | **Impacto** | `mitigar-impacto.sh` | TA0040 | T1486/T1561 (backups offsite rsync), T1486 (ClamAV anti-ransomware con YARA), T1490 (proteccion snapshots/checksums), T1485 (monitoreo auditd) |
| 23 | **Evasion de defensas** | `mitigar-evasion.sh` | TA0005 | T1070 (logs append-only), T1036 (masquerading), T1562 (watchdog servicios), T1014 (rootkits rkhunter + YARA scanning), T1218 (LOLBins), T1564 (artefactos ocultos + reglas Sigma), T1027 (ofuscacion) |
| 24 | **Acceso a credenciales** | `mitigar-credenciales.sh` | TA0006 | T1003 (credential dumping), T1110 (fuerza bruta faillock), T1557 (MITM arpwatch), T1552 (credenciales expuestas), T1040 (modo promiscuo), T1056 (keyloggers) |
| 25 | **Descubrimiento** | `mitigar-descubrimiento.sh` | TA0007 | T1046 (portscan rate-limit), T1057 (hidepid procesos), T1082 (info sistema), T1016/T1049 (red), T1087/T1069 (cuentas), T1518 (software) |
| 26 | **Movimiento lateral** | `mitigar-movimiento-lateral.sh` | TA0008 | T1021 (SSH anti-forwarding), T1021.001/005 (RDP/VNC desactivado), T1021.002 (Samba firma obligatoria), T1563 (SSH agent), T1080 (contenido compartido noexec), M1030 (segmentacion) |
| 27 | **Recoleccion** | `mitigar-recoleccion.sh` | TA0009 | T1005 (datos locales), T1039 (shares), T1025 (medios extraibles USBGuard), T1074 (data staging), T1113/T1125/T1123 (captura), T1119 (automatizada), T1560 (compresion) |
| 28 | **Exfiltracion** | `mitigar-exfiltracion.sh` | TA0010 | T1041 (trafico saliente), T1048 (DNS tunneling), T1567 (cloud), T1052 (USB), T1030 (ancho de banda tc), monitoreo de transferencias |
| 29 | **Comando y control** | `mitigar-comando-control.sh` | TA0011 | T1571 (puertos C2), T1071 (Cobalt Strike/Meterpreter/Sliver Suricata), T1105 (tool transfer), T1090/T1572 (proxies/tuneles), T1568 (DGA heuristicas) |

Cada modulo MITRE instala scripts de deteccion en `/usr/local/bin/`, reglas auditd en `/etc/audit/rules.d/` y cron jobs/timers systemd para monitoreo continuo.

### Categoria 4: Operaciones de Seguridad (modulos 30-34)

Herramientas para un SOC (Security Operations Center) funcional.

| # | Modulo | Script | Descripcion |
|---|--------|--------|-------------|
| 30 | **Monitorizacion continua** | `monitorizar-continuo.sh` | Dashboard de estado (`security-dashboard.sh`), correlacion de alertas multi-fuente (5 patrones de ataque), baseline de comportamiento del sistema, health check de controles (cron diario), digest periodico (timer 06:00) |
| 31 | **Reportes de seguridad** | `reportar-seguridad.sh` | Reporte de cobertura MITRE ATT&CK, exportacion ATT&CK Navigator JSON layer, reporte de cumplimiento por categoria, inventario de activos de seguridad, resumen ejecutivo con score de postura |
| 32 | **Caza de amenazas** | `cazar-amenazas.sh` | UEBA (baseline de usuarios + deteccion de anomalias), 5 playbooks de hunting (persistencia oculta, LOLBins, lateral silencioso, exfil lenta, C2 encubierto), deteccion persistencia avanzada T1098 (timer 15min), busqueda retrospectiva en logs, anomalias de red (beaconing, asimetrico, C2), hunting /proc + eBPF (deleted binaries, mount namespaces, capabilities) |
| 33 | **Automatizacion de respuesta** | `automatizar-respuesta.sh` | SOAR ligero: motor de respuesta automatica (6 tipos de eventos), bloqueo IP/cuenta, preservacion de evidencia, gestion de bloqueos (listar/whitelist/limpiar), notificaciones por severidad, reglas configurables en `/etc/security/soar-rules.conf` |
| 34 | **Validacion de controles** | `validar-controles.sh` | Purple team: validador de autenticacion (15 tests), red (15 tests), endpoint (34 tests incluyendo: BPF/kexec/perf, blacklist 10 modulos kernel, vsock CVE-2025-21756, 5 CVE kernel version checks, audit execve/ptrace/modules/mount, capabilities peligrosas, SUID no estandar), simulador seguro de 12 tecnicas ATT&CK, 20 tests Metasploit (8 nuevos: CVE-2025-21756 vsock, CVE-2024-1086 nf_tables, user namespace escape, kernel modules, ptrace T1055, SSH hardening, TLS deprecado, payload encoded evasion), reporte consolidado con scoring global, validacion semanal automatica |

### Categoria 5: Inteligencia (3 modulos)

| # | Modulo | Script | Descripcion |
|---|--------|--------|-------------|
| 35 | **Ciberinteligencia proactiva** | `ciberinteligencia.sh` | Motor de enriquecimiento de IoC multi-fuente con scoring 0-100, inteligencia de red proactiva (GeoIP, correlacion), inteligencia DNS (DGA, tunneling, NRD), monitorizacion de superficie de ataque, sistema de alerta temprana y CVE monitoring, informes de inteligencia automatizados, monitorizacion de credenciales expuestas, integracion SOAR. Instala 16 scripts y 6 timers systemd |
| 36 | **Proteccion contra ISP** | `proteger-contra-isp.sh` | Kill switch VPN (iptables DROP si cae la VPN), prevencion de fugas DNS (DoT estricto + DNSSEC), ECH (Encrypted Client Hello), prevencion WebRTC leaks, evasion de DPI (obfs4/stunnel), hardening de privacidad del navegador, HTTPS-Only enforcement, NTP con NTS, ofuscacion de patrones de trafico, auditoria de metadatos ISP |
| 77 | **Plataforma TIP** | `plataforma-tip.sh` | Cliente MISP (PyMISP/curl REST), parser STIX 2.1, consumer TAXII 2.1 (CIRCL + configurables), ciclo de vida IOC (aging, dedup, expiracion), tracker de campañas con mapeo MITRE ATT&CK, framework de atribucion Diamond Model, comparticion de inteligencia (STIX/CSV/MISP con TLP), correlacion cross-source, threat briefings diarios/semanales, auditoria integral |

### Categoria 6: Infraestructura y Red (9 modulos)

| # | Modulo | Script | Descripcion |
|---|--------|--------|-------------|
| 37 | **Hardening criptografico** | `hardening-criptografico.sh` | Algoritmos SSH, TLS system-wide, certificados, entropia, GPG, LUKS, kernel crypto |
| 43 | **Segmentacion de red** | `segmentacion-red-zt.sh` | Zonas nftables, microsegmentacion, contenedores, postura ZT, identidad |
| 50 | **Seguridad cloud** | `seguridad-cloud.sh` | AWS/Azure/GCP, IMDS hardening, IAM audit, postura cloud, exfiltracion |
| 51 | **LDAP y Active Directory** | `seguridad-ldap-ad.sh` | OpenLDAP TLS, SSSD, Kerberos, FreeIPA, Samba/Winbind, replicacion |
| 54 | **Seguridad wireless** | `seguridad-wireless.sh` | WPA3 Enterprise, FreeRADIUS 802.1X, rogue AP, Bluetooth, monitoring |
| 55 | **Seguridad virtualizacion** | `seguridad-virtualizacion.sh` | KVM/QEMU, libvirt hardening, VM aislamiento, escape protection |
| 57 | **Zero Trust Identity** | `zero-trust-identity.sh` | CISA ZT maturity, continuous auth, device trust, IAP, microseg |
| 63 | **DNS avanzado** | `seguridad-dns-avanzada.sh` | DNSSEC, DoT/DoH, Unbound, RPZ sinkhole, tunneling, cache poisoning, DNS multi-resolver consistency, TTL anomaly detection, DNS rebinding protection |
| 73 | **Integridad de arranque** | `integridad-arranque.sh` | Secure Boot, UEFI hardening, GRUB2, kernel signature, dm-verity, IMA/EVM, TPM2, bootkit detection, measured boot |

### Categoria 7: Aplicaciones y Servicios (8 modulos)

| # | Modulo | Script | Descripcion |
|---|--------|--------|-------------|
| 38 | **Seguridad de contenedores** | `seguridad-contenedores.sh` | Docker/Podman daemon, seccomp, AppArmor, imagenes, registry, rootless, K8s, CIS |
| 40 | **Seguridad de email** | `seguridad-email.sh` | Postfix, SPF, DKIM 2048-bit, DMARC, TLS/DANE, anti-relay, SpamAssassin |
| 46 | **Seguridad de BBDD** | `seguridad-bases-datos.sh` | PostgreSQL, MySQL, Redis, MongoDB, cifrado, pgaudit, SQLi detection |
| 48 | **Seguridad web** | `seguridad-web.sh` | nginx/Apache, CSP/HSTS, ModSecurity WAF OWASP CRS, TLS, DDoS, logs |
| 49 | **Gestion de secretos** | `seguridad-secrets.sh` | Vault, rotacion credenciales, escaneo secretos, SSH keys, pass/gopass/SOPS |
| 60 | **DevSecOps** | `devsecops-hardening.sh` | Git security, CI/CD, Trivy, SAST, secrets detection, code signing |
| 61 | **Seguridad de APIs** | `seguridad-api.sh` | Rate limiting, JWT/OAuth2, CORS, mTLS, GraphQL, webhooks, audit |
| 62 | **Seguridad IoT** | `seguridad-iot.sh` | Inventario IoT, MQTT TLS, CoAP, firmware, credenciales, Zigbee/BLE |

### Categoria 8: Proteccion y Resiliencia (11 modulos)

| # | Modulo | Script | Descripcion |
|---|--------|--------|-------------|
| 42 | **Cadena de suministro** | `seguridad-cadena-suministro.sh` | GPG, SBOM CycloneDX, CVEs, repositorios, integridad binarios, troyanizados |
| 45 | **Kernel live patching** | `kernel-livepatch.sh` | KASLR/SMEP/KPTI, kpatch/kGraft, sysctl 25+ params, modulos, CVEs, rollback |
| 47 | **Backup y DR** | `backup-recuperacion.sh` | 3-2-1, Borg, Restic, WORM inmutable, bare metal, RTO/RPO, offsite |
| 53 | **Tecnologia de engano** | `tecnologia-engano.sh` | Honeypots de red, honeytokens, honey files/users/dirs, DNS, alertas. **Submenu interactivo** con 10 secciones individuales y dashboard en vivo |
| 56 | **Seguridad fisica** | `seguridad-fisica.sh` | USBGuard, BIOS/UEFI, GRUB, TPM, Thunderbolt DMA, screen lock |
| 58 | **Anti-ransomware** | `proteger-ransomware.sh` | Canary files, LVM snapshots, exec whitelisting, YARA, SMB, containment |
| 59 | **Gestion de parches** | `gestion-parches.sh` | Auto-patch, CVE scan, SBOM, staging/rollback, advisories, compliance |
| 66 | **Runtime kernel** | `seguridad-runtime-kernel.sh` | LKRG, kernel lockdown, eBPF hardening, Falco runtime monitoring, module signing, CPU mitigations (Spectre/MDS/TAA/Retbleed), kernel memory protection, debug restriction, runtime integrity, audit con scoring |
| 67 | **Memoria y procesos** | `hardening-memoria-procesos.sh` | Hardened allocator, stack protection (SSP/CET), user namespace restriction, cgroups v2, seccomp-BPF generator, ASLR/PIE enforcement, W^X strict (noexec), ptrace control (yama), coredump sanitization, process integrity audit |
| 71 | **Control acceso obligatorio** | `mac-selinux-apparmor.sh` | SELinux/AppArmor enforcing, politicas de red, confinamiento servicios, proteccion ficheros, contenedores, denegaciones, politicas custom, MLS/MCS |
| 72 | **Aislamiento namespaces** | `aislamiento-namespaces.sh` | User/PID/net/mount namespaces, rootless containers, systemd sandboxing, seccomp-BPF, cgroups v2, escape detection |

### Categoria 9: Deteccion y Respuesta (11 modulos)

| # | Modulo | Script | Descripcion |
|---|--------|--------|-------------|
| 41 | **Logging centralizado** | `logging-centralizado.sh` | rsyslog TLS, CEF/JSON, hash chain SHA-256, correlacion 8 patrones, SIEM, forense |
| 44 | **Forense avanzado** | `forense-avanzado.sh` | RAM (LiME), disco forense, volatiles RFC 3227, YARA, custodia digital, timeline |
| 64 | **Auditoria de red** | `auditoria-red-wireshark.sh` | Wireshark/tshark, capturas automatizadas, 20 checks de anomalias (ARP spoofing/flooding, port scan, DNS tunneling, DHCP starvation, rogue DHCP, LLMNR/mDNS poisoning, Spotify Connect, Google Cast, SSDP/UPnP, DHCP device ID con EOL multi-OS/IoT, MAC randomization, SNMP exposure, captive portal detection, SNI plaintext analysis), filtros BPF/display, correlacion IDS |
| 65 | **Auditoria infra red** | `auditoria-red-infraestructura.sh` | nmap (12 fases), TLS/SSL, SNMP, inventario servicios, baseline, drift, reportes, deteccion de APIs IoT expuestas (Cast, Roku ECP, UPnP, IPP, router panel), deteccion EOL 12+ categorias, generacion automatica de script de aislamiento LAN triple (MAC+IP+subnet), auditoria sysctl ARP/IPv6, verificacion cifrado disco LUKS, auditoria mount options, crypto policy check, systemd sandboxing audit |
| 68 | **Respuesta a incidentes** | `respuesta-incidentes.sh` | Recoleccion forense, playbooks contencion MITRE, timeline, aislamiento de red, recuperacion, cadena de custodia digital, extraccion de IOCs, comunicacion/escalacion, hunting de IOCs en flota, metricas IR (MTTD/MTTR/MTTC) |
| 69 | **EDR con Osquery** | `edr-osquery.sh` | Osquery multi-distro, packs de seguridad (10 queries), deteccion de amenazas (10 queries), guia Wazuh, decorators custom, alertas syslog/JSON, baseline y drift, FleetDM prep, queries diferenciales, auditoria EDR |
| 70 | **Gestion de vulnerabilidades** | `gestion-vulnerabilidades.sh` | Trivy, grype, OpenSCAP, escaneo sistema/contenedores, priorizacion CVSS+EPSS+KEV+Reachability (formula mejorada 4 factores), analisis dependencias, reporting HTML/JSON, verificacion parches, escaneo programado semanal, auditoria madurez (L1-L5), deteccion directa de 9 CVEs kernel criticos (2024-2026) con opcion --fix, verificacion supply chain (integridad paquetes, firmas GPG, SUID no estandar), output JSON |
| 74 | **Acceso privilegiado** | `acceso-privilegiado.sh` | Inventario privilegiado, grabacion sesiones, sudo granular, restriccion su, JIT access, alertas, capabilities, credenciales, breakglass |
| 75 | **Caza de APTs** | `caza-apt-hunting.sh` | YARA rules engine, filesystem scan, memory hunting, network hunting, behavioral baseline, persistence detection, IOC sweep, threat intel, hunting playbooks |
| 76 | **Inteligencia de red** | `inteligencia-red-avanzada.sh` | JA3/JA4 TLS fingerprinting (abuse.ch), deteccion de beaconing C2 (jitter ratio), passive DNS collector (DGA, NXD), anomalias de protocolo, analisis de trafico cifrado (ETA), monitor de rutas BGP (RIPE RIS), colector NetFlow/ss sampling (baseline 3-sigma), deteccion de exfiltracion (large transfers, DNS exfil, slow exfil), forense de red (pcap + cadena custodia SHA-256), auditoria integral |
| 78 | **OSINT superficie** | `osint-superficie.sh` | Monitor de Certificate Transparency (crt.sh, delta certs), enumeracion pDNS (HackerTarget, dig), monitor WHOIS (delta registrar/NS), descubrimiento de subdominios (CT+pDNS+brute+AXFR), cloud discovery (S3/GCS buckets, dangling CNAMEs), fingerprinting tecnologico (headers, TLS, security headers), deteccion de fugas de codigo (GitHub dorks, HIBP), superficie de ingenieria social (SPF/DMARC/DKIM), riesgo de terceros (vendor risk scoring), auditoria integral |

### Categoria 10: Cumplimiento (2 modulos)

| # | Modulo | Script | Descripcion |
|---|--------|--------|-------------|
| 39 | **Cumplimiento CIS** | `cumplimiento-cis.sh` | CIS Benchmark L1/L2, NIST 800-53, scoring, remediacion, informes |
| 52 | **Cumplimiento normativo** | `cumplimiento-normativo.sh` | PCI-DSS v4.0, GDPR, HIPAA, SOC2, ISO 27001, evidencias, remediacion |

---

## Menu orquestador (`securizar-menu.sh`)

El menu orquestador es el punto de entrada principal de la suite. Proporciona:

### Navegacion jerarquica

```
Menu principal
├── b  Hardening Base (1-9)
├── p  Securizacion Proactiva (10-17)
├── m  Mitigaciones MITRE ATT&CK (18-29)
├── o  Operaciones de Seguridad (30-34)
├── i  Inteligencia (3 modulos)
├── n  Infraestructura y Red (9 modulos)
├── s  Aplicaciones y Servicios (8 modulos)
├── r  Proteccion y Resiliencia (11 modulos)
├── d  Deteccion y Respuesta (11 modulos)
├── c  Cumplimiento (2 modulos)
├── a  Aplicar todos los 78 modulos
├── v  Verificacion proactiva (87 checks)
├── 1-78  Acceso directo por numero
├── ?  Ayuda
└── q  Salir con resumen de sesion
```

Cada sub-menu muestra sus modulos con estado (`✓` completado, `○` pendiente, `!` archivo faltante) y permite ejecutar modulos individuales o todos los de la categoria con `t`.

El modulo 55 (Tecnologia de engano) dispone de un **submenu propio** con 10 secciones ejecutables individualmente y un dashboard en vivo:

```
Securizar ❯ Protección y Resiliencia ❯ Tecnología de engaño

  ✓   1  Honeypots de Red
  ✓   2  Honey Tokens
  ✓   3  Honey Files
  ✓   4  Honey Users
  ✓   5  Honey Directories
  ✓   6  Honey DNS
  ○   7  Deception Services
  ✓   8  Alertas de Deception
  ✓   9  Dashboard                  ← Muestra dashboard en vivo si esta instalado
  ✓  10  Auditoría Integral

  t Todos    b Volver    q Salir
```

Cada seccion se puede ejecutar individualmente con `sudo bash tecnologia-engano.sh S1` ... `S10`, o todas con `sudo bash tecnologia-engano.sh` (sin argumento).

### Protecciones de seguridad

El menu reimplementa inline los modulos 5 (extremo) y 6 (paranoico) eliminando secciones peligrosas:

- **Modulo 5 (extremo)**: elimina deshabilitacion de sshd, firewall DROP ultra-restrictivo y chattr +i en archivos criticos
- **Modulo 6 (paranoico)**: elimina TMOUT=900 readonly y modificacion de `/etc/pam.d/su`

Esto garantiza que nunca se bloquee el acceso al sistema.

### Verificacion proactiva

La opcion `v` ejecuta 87 verificaciones agrupadas por categoria:

- Kernel y sysctl
- Servicios y firewall
- Red y DNS
- Permisos y archivos
- PAM intacto y acceso SSH
- sudo y sin inmutabilidad
- Herramientas de seguridad instaladas
- Scripts de monitoreo desplegados
- Parametros de arranque y Secure Boot
- Sandboxing de servicios y aplicaciones
- Cuentas y automatizacion
- Cada tactica MITRE ATT&CK (TA0001-TA0011)
- Respuesta a incidentes, monitorizacion, reportes
- Caza de amenazas, SOAR, Purple Team
- Ciberinteligencia, proteccion ISP
- Criptografia, contenedores, CIS
- Seguridad de email, logging SIEM, cadena de suministro
- Segmentacion de red y Zero Trust
- Forense avanzado
- Kernel live patching
- Seguridad de bases de datos
- Backup y recuperacion
- Seguridad web
- Gestion de secretos, seguridad cloud, LDAP/AD
- Cumplimiento normativo, tecnologia de engano, wireless
- Virtualizacion, seguridad fisica, Zero Trust Identity
- Anti-ransomware, gestion de parches, DevSecOps
- Seguridad de APIs, IoT, DNS avanzado
- Auditoria de red (Wireshark/tshark)
- Auditoria de infraestructura de red (nmap, TLS, SNMP, baseline)
- Runtime kernel, memoria y procesos
- Respuesta a incidentes
- EDR con Osquery (packs, threat detection, baseline, auditoria)
- Gestion de vulnerabilidades (escaneo, priorizacion, reporting, auditoria)
- Control de acceso obligatorio (SELinux/AppArmor, enforce, denegaciones)
- Aislamiento de namespaces (user ns, PID, escape detection)
- Integridad de arranque (Secure Boot, GRUB2, bootkit detection)
- Acceso privilegiado (inventario, sesiones, auditoria)
- Caza de APTs (YARA, persistencia, IOC sweep, playbooks)
- Inteligencia de red (JA3 fingerprinting, beaconing, exfiltracion, auditoria)
- Plataforma TIP (MISP, STIX parser, IOC lifecycle, auditoria)
- OSINT superficie (CT logs, subdominios, fugas de codigo, auditoria)

### Session tracking

- Rastrea que modulos se han ejecutado en la sesion actual
- Al salir (`q`), muestra resumen con modulos ejecutados, tiempo total y ruta del log
- Logs en `/var/log/securizar-menu-TIMESTAMP.log`

---

## Cobertura MITRE ATT&CK

El proyecto cubre las 14 tacticas del framework MITRE ATT&CK enterprise:

| Tactica | ID | Modulo(s) | Tecnicas principales |
|---------|-----|--------|---------------------|
| Reconnaissance | TA0043 | 17 | T1595, T1593, T1596, T1592, T1590 |
| Resource Development | TA0042 | 18 | M1019, IoC feeds |
| Initial Access | TA0001 | 19 | T1133, T1190, T1078, T1566, T1189, T1195, T1200 |
| Execution | TA0002 | 20 | T1059, T1204, T1129, T1203 |
| Persistence | TA0003 | 21 | T1053, T1543, T1547, T1136, T1556, T1574 |
| Privilege Escalation | TA0004 | 22 | T1548, T1068, T1134, T1055, T1078 |
| Defense Evasion | TA0005 | 24 | T1070, T1036, T1562, T1014, T1218, T1564, T1027 |
| Credential Access | TA0006 | 25 | T1003, T1110, T1557, T1552, T1040, T1056 |
| Discovery | TA0007 | 26 | T1046, T1057, T1082, T1016, T1049, T1087 |
| Lateral Movement | TA0008 | 27 | T1021, T1563, T1080, T1072 |
| Collection | TA0009 | 28 | T1005, T1039, T1025, T1074, T1113, T1119 |
| Exfiltration | TA0010 | 29 | T1041, T1048, T1567, T1052, T1030 |
| Command and Control | TA0011 | 30 | T1071, T1105, T1090, T1572, T1571, T1568 |
| Impact | TA0040 | 23 | T1486, T1490, T1561, T1485 |

### Scripts de deteccion instalados

Los modulos MITRE instalan mas de 20 scripts de deteccion en `/usr/local/bin/`:

| Script | Tecnica | Frecuencia |
|--------|---------|------------|
| `detectar-masquerading.sh` | T1036 | cron diario |
| `detectar-rootkits.sh` | T1014 | cron semanal |
| `detectar-ocultos.sh` | T1564 | cron diario |
| `detectar-ofuscados.sh` | T1027 | cron diario |
| `watchdog-seguridad.sh` | T1562 | timer 5min |
| `monitorear-bruteforce.sh` | T1110 | cron diario |
| `buscar-credenciales.sh` | T1552 | cron semanal |
| `detectar-promiscuo.sh` | T1040 | timer 10min |
| `detectar-keylogger.sh` | T1056.001 | cron diario |
| `detectar-portscan.sh` | T1046 | cron diario |
| `detectar-reconocimiento.sh` | T1016/T1049 | cron diario |
| `detectar-lateral.sh` | TA0008 | cron diario |
| `detectar-staging.sh` | T1074 | cron diario |
| `detectar-recoleccion.sh` | T1119 | cron diario |
| `detectar-exfiltracion.sh` | TA0010 | cron diario |
| `detectar-dns-tunnel.sh` | T1048.003 | cron diario |
| `monitorear-transferencias.sh` | T1030 | timer 1h |
| `detectar-beaconing.sh` | T1071 | cron diario |
| `detectar-tunneling.sh` | T1090/T1572 | cron diario |
| `detectar-dga.sh` | T1568 | cron diario |
| `detectar-tool-transfer.sh` | T1105 | cron diario |
| `detectar-c2-completo.sh` | TA0011 | consolidado |

### Reglas auditd

Se crean reglas en `/etc/audit/rules.d/` con numeracion `6X`:

| Archivo | Cobertura |
|---------|-----------|
| `60-log-protection.rules` | T1070 - proteccion de logs |
| `61-defense-evasion.rules` | T1562/T1218 - herramientas de seguridad y LOLBins |
| `62-credential-access.rules` | T1003/T1040 - credenciales y sniffing |
| `63-discovery.rules` | T1046/T1057/T1082/T1016/T1087/T1518 |
| `64-lateral-movement.rules` | T1021/T1563/T1072 |
| `65-collection.rules` | T1005/T1039/T1025/T1074/T1113/T1560 |
| `66-exfiltration.rules` | T1041/T1048/T1567/T1052 |
| `67-command-control.rules` | T1105/T1090/T1572 |

---

## Herramientas desplegadas

### Respuesta a incidentes

| Herramienta | Ubicacion | Funcion |
|-------------|-----------|---------|
| `ir-recolectar-forense.sh` | `/usr/local/bin/` | Recoleccion de 15 categorias de datos volatiles con cadena de custodia |
| `ir-responder.sh` | `/usr/local/bin/` | Dispatcher de playbooks de contencion |
| `pb-cuenta-comprometida.sh` | `/usr/local/lib/incident-response/playbooks/` | Playbook T1078/T1110 |
| `pb-malware-activo.sh` | `/usr/local/lib/incident-response/playbooks/` | Playbook T1486/T1059 |
| `pb-c2-exfiltracion.sh` | `/usr/local/lib/incident-response/playbooks/` | Playbook TA0011/TA0010 |
| `pb-movimiento-lateral.sh` | `/usr/local/lib/incident-response/playbooks/` | Playbook TA0008 |
| `ir-timeline.sh` | `/usr/local/bin/` | Timeline de ataque multi-fuente con mapeo MITRE |
| `ir-aislar-red.sh` | `/usr/local/bin/` | Aislamiento de red de emergencia (mantiene SSH) |
| `ir-restaurar-red.sh` | `/usr/local/bin/` | Restauracion de red post-aislamiento |
| `ir-recuperacion.sh` | `/usr/local/bin/` | Guia de recuperacion post-incidente |
| `ir-cadena-custodia.sh` | `/usr/local/bin/` | Cadena de custodia digital con SHA-256/512 y GPG |
| `ir-extraer-iocs.sh` | `/usr/local/bin/` | Extraccion de IOCs (IPs, dominios, hashes) con exportacion STIX 2.1 |
| `ir-escalar.sh` | `/usr/local/bin/` | Comunicacion y escalacion con 4 plantillas y matriz de severidad |
| `ir-hunt-fleet.sh` | `/usr/local/bin/` | Hunting de IOCs en flota via SSH paralelo |
| `ir-post-review.sh` | `/usr/local/bin/` | Metricas IR (MTTD/MTTR/MTTC/MTTE), scoring madurez IR (5 niveles) |

### Monitorizacion continua

| Herramienta | Funcion |
|-------------|---------|
| `security-dashboard.sh` | Dashboard consolidado (servicios, deteccion, timers, alertas, integridad) |
| `correlacionar-alertas.sh` | Correlacion multi-fuente (5 patrones: brute force->acceso, portscan->conexion, IDS->C2, multi-fuente, cadena de ataque) |
| `security-baseline.sh` | Crear/verificar baseline (puertos, servicios, usuarios, SUID, destinos, crontabs) |
| `security-healthcheck.sh` | Health check de controles (cron diario) |
| `security-digest.sh` | Digest periodico de seguridad (timer systemd 06:00) |

### Reportes

| Herramienta | Funcion |
|-------------|---------|
| `reporte-mitre.sh` | Cobertura MITRE ATT&CK con evaluacion real por tecnica |
| `exportar-navigator.sh` | JSON layer para ATT&CK Navigator (visualizacion web) |
| `reporte-cumplimiento.sh` | Cumplimiento por categoria (AUTH/NET/KERN/AUDIT/AV/MON/IR) |
| `inventario-seguridad.sh` | Inventario de activos de seguridad (scripts/reglas/timers/cron) |
| `resumen-ejecutivo.sh` | Resumen ejecutivo con score de postura |

### Caza de amenazas

| Herramienta | Funcion |
|-------------|---------|
| `ueba-crear-baseline.sh` | Baseline de comportamiento por usuario (login, IPs, comandos, archivos, sudo) |
| `ueba-detectar-anomalias.sh` | Detectar anomalias contra baseline UEBA (cron diario) |
| `cazar-amenazas.sh` | 5 playbooks de hunting (persistencia, LOLBins, lateral, exfil, C2) |
| `detectar-persistencia-avanzada.sh` | T1098: authorized_keys, passwd, kernel modules, shell init (timer 15min) |
| `buscar-retrospectivo.sh` | Busqueda en logs por IP/usuario/dominio/hash/comando/archivo |
| `detectar-anomalias-red.sh` | Anomalias estadisticas de red (beaconing, asimetrico, C2, HTTPS sin rDNS) |

### SOAR (automatizacion de respuesta)

| Herramienta | Funcion |
|-------------|---------|
| `soar-responder.sh` | Motor SOAR: 6 tipos de eventos, bloqueo IP/cuenta, evidencia (timer 10min) |
| `soar-gestionar-bloqueos.sh` | Gestion de IPs bloqueadas (listar/whitelist/estadisticas/limpiar) |
| `soar-notificar.sh` | Notificaciones consolidadas por severidad (CRITICAL/HIGH/MEDIUM/LOW) |
| `soar-rules.conf` | Configuracion de reglas trigger->accion (`/etc/security/`) |

### Validacion Purple Team

| Herramienta | Funcion |
|-------------|---------|
| `validar-autenticacion.sh` | 15 tests de controles de autenticacion |
| `validar-red.sh` | 15 tests de controles de red |
| `validar-endpoint.sh` | 21 tests de controles de endpoint |
| `simular-ataques.sh` | 12 simulaciones seguras de tecnicas ATT&CK |
| `reporte-validacion.sh` | Scoring global (60% controles + 40% deteccion) |

### Seguridad de email

| Herramienta | Funcion |
|-------------|---------|
| `verificar-spf.sh` | Auditoria de registros SPF: sintaxis DNS, -all vs ~all, conteo de lookups |
| `verificar-dmarc.sh` | Auditoria de registros DMARC: politica p=reject, rua/ruf, pct |
| `rotar-dkim.sh` | Rotacion de claves DKIM con generacion de nuevo par 2048-bit |
| `detectar-email-spoofing.sh` | Analisis de cabeceras de correo (From/Return-Path/Received) |
| `monitorizar-email.sh` | Estado de cola, fallos de autenticacion, intentos de relay, stats TLS |
| `auditoria-email.sh` | Auditoria completa de seguridad email (SEGURO/MEJORABLE/INSEGURO) |

### Logging centralizado y SIEM

| Herramienta | Funcion |
|-------------|---------|
| `configurar-log-remoto.sh` | Configura servidor/cliente de reenvio TLS de logs |
| `securizar-log-integrity.sh` | Cadena de hashes SHA-256 para integridad de logs criticos |
| `correlacionar-eventos.sh` | Correlacion de 8 patrones de ataque (brute force, escalada, lateral, staging) |
| `securizar-log-alertas.sh` | Alertas en tiempo real via omprog (email/webhook, rate limiting) |
| `gestionar-retencion-logs.sh` | Gestion de retencion por categoria (365/180/90/30 dias) |
| `activar-siem.sh` | Activar integracion SIEM (Elasticsearch, Splunk HEC, Graylog GELF) |
| `forense-logs.sh` | Timeline forense multi-fuente con chain of custody |
| `auditoria-logging.sh` | Auditoria de infraestructura de logging (COMPLETO/PARCIAL/INSUFICIENTE) |

### Cadena de suministro

| Herramienta | Funcion |
|-------------|---------|
| `verificar-firmas-paquetes.sh` | Verificacion de firmas GPG de todos los paquetes instalados |
| `generar-sbom.sh` | Generacion de SBOM en formato CycloneDX JSON con diff |
| `auditar-cves.sh` | Auditoria de CVEs contra paquetes instalados (CRITICAL/HIGH/MEDIUM/LOW) |
| `verificar-dependencias.sh` | Deteccion de paquetes huerfanos, obsoletos y de terceros |
| `auditar-repositorios.sh` | Auditoria de repositorios (HTTPS, GPG, whitelist) |
| `verificar-integridad-binarios.sh` | Verificacion SHA-256 de binarios criticos contra baseline |
| `securizar-install-hook.sh` | Hook de logging de instalaciones con enforcement de politica |
| `detectar-troyanizados.sh` | Deteccion de SUID/SGID, orphans, LD_PRELOAD, capabilities, PATH |
| `monitorizar-software.sh` | Monitorizacion de cambios: installs/removals, SUID, kernel modules |
| `auditoria-cadena-suministro.sh` | Auditoria completa de supply chain (SEGURO/MEJORABLE/INSEGURO) |

### Segmentacion de red y Zero Trust

| Herramienta | Funcion |
|-------------|---------|
| `aplicar-politicas-zona.sh` | Aplicacion y gestion de politicas inter-zona (nftables) |
| `microsegmentar-servicio.sh` | Microsegmentacion por servicio individual o masiva |
| `aislar-contenedores-red.sh` | Aislamiento de redes Docker/Podman (internal, ICC) |
| `evaluar-postura-dispositivo.sh` | Evaluacion Zero Trust del dispositivo (scoring 0-100, JSON) |
| `aplicar-acceso-identidad.sh` | Control de acceso basado en identidad y zona de red |
| `monitorizar-trafico-zonas.sh` | Monitorizacion de trafico inter-zona con deteccion de anomalias |
| `validar-segmentacion.sh` | Tests de aislamiento y validacion de reglas de segmentacion |
| `verificar-zt-continuo.sh` | Verificacion continua de postura Zero Trust (drift detection) |
| `auditoria-segmentacion-zt.sh` | Auditoria integral de segmentacion y ZT (BUENO/MEJORABLE/DEFICIENTE) |

### Forense avanzado

| Herramienta | Funcion |
|-------------|---------|
| `forense-capturar-ram.sh` | Adquisicion de memoria RAM (LiME/proc/kcore, multi-formato) |
| `forense-imagen-disco.sh` | Imagen forense de disco (dc3dd/dd, dual hash, write-blocking) |
| `forense-volatil.sh` | Preservacion de datos volatiles (RFC 3227, 10 categorias) |
| `forense-artefactos.sh` | Recopilacion de artefactos del sistema (logs, histories, SUID) |
| `forense-timeline.sh` | Timeline unificada (MAC times, logs, journal, wtmp/btmp, CSV) |
| `forense-yara-scan.sh` | Escaneo de directorios con 6 sets de reglas YARA |
| `forense-analizar-binario.sh` | Analisis estatico de binarios (strings, entropia, ELF, YARA) |
| `forense-custodia.sh` | Cadena de custodia digital (crear/agregar/verificar/transferir) |
| `forense-analizar-logs.sh` | Analisis automatizado de logs (brute force, escalada, anomalias) |
| `forense-recopilar-todo.sh` | Script maestro: recopilacion forense completa en orden optimo |
| `auditoria-forense.sh` | Auditoria de preparacion forense (BUENO/MEJORABLE/DEFICIENTE) |

### Kernel live patching

| Herramienta | Funcion |
|-------------|---------|
| `auditar-kernel.sh` | Auditoria de seguridad del kernel (KASLR, SMEP, KPTI, Retpoline) |
| `validar-kernel-params.sh` | Validacion de parametros del kernel contra baseline |
| `monitorizar-cves-kernel.sh` | Monitorizacion de CVEs contra kernel en ejecucion |
| `gestionar-kernel-updates.sh` | Gestion de actualizaciones del kernel segun politica |
| `verificar-secure-boot.sh` | Verificacion de Secure Boot, firmas y MOK |
| `kernel-rollback.sh` | Rollback seguro de kernel (GRUB, kexec, minimo 2 kernels) |
| `auditoria-livepatch.sh` | Auditoria integral de kernel y livepatch (BUENO/MEJORABLE/DEFICIENTE) |

### Seguridad de bases de datos

| Herramienta | Funcion |
|-------------|---------|
| `auditar-postgresql.sh` | Auditoria de PostgreSQL (pg_hba.conf, SSL, logging, connection limits) |
| `auditar-mysql.sh` | Auditoria de MySQL/MariaDB (bind-address, local-infile, secure transport, password validation) |
| `auditar-redis.sh` | Auditoria de Redis (requirepass, bind, protected-mode, rename-command, ACL) |
| `auditar-mongodb.sh` | Auditoria de MongoDB (authorization, bindIp, JavaScript disable, audit) |
| `auditar-acceso-db.sh` | Auditoria de autenticacion y control de acceso (role-based, minimum privilege) |
| `verificar-cifrado-db.sh` | Verificacion de cifrado de bases de datos (at rest e in transit, TLS) |
| `backup-seguro-db.sh` | Backup seguro de bases de datos (encrypted dumps, GPG signing, retention) |
| `configurar-audit-db.sh` | Configuracion de audit logging (pgaudit, MariaDB audit, query monitoring) |
| `detectar-sqli.sh` | Deteccion de SQL injection (log-based detection, pattern matching) |
| `auditoria-bases-datos.sh` | Auditoria completa de seguridad de bases de datos (multi-engine, scoring) |

### Backup y recuperacion

| Herramienta | Funcion |
|-------------|---------|
| `verificar-estrategia-321.sh` | Verificacion de estrategia de backup 3-2-1 (config generator, validation) |
| `securizar-backup-borg.sh` | Backup cifrado con Borg (repokey-blake2, zstd, retention, systemd timer) |
| `securizar-backup-restic.sh` | Backup cifrado con Restic (AES-256, S3/SFTP support, health check) |
| `securizar-backup-inmutable.sh` | Backups inmutables WORM (chattr +i, btrfs snapshots, lockdown) |
| `verificar-backups.sh` | Verificacion de integridad de backups (integrity check, test restore) |
| `restaurar-backup.sh` | Restauracion automatica de backups |
| `backup-sistema-completo.sh` | Backup de sistema completo bare metal (full disk/partition image) |
| `validar-rto-rpo.sh` | Validacion RTO/RPO y planificacion DR (DR plan generator, compliance, SLA) |
| `securizar-backup-offsite.sh` | Backup offsite automatizado (SFTP, S3, rsync, cron automation) |
| `proteger-backups-ransomware.sh` | Proteccion anti-ransomware (honeypots, process monitoring, lockdown) |
| `auditoria-backup-dr.sh` | Auditoria de backup y DR (scoring, compliance check) |

### Seguridad web

| Herramienta | Funcion |
|-------------|---------|
| `verificar-headers-seguridad.sh` | Verificacion de cabeceras de seguridad HTTP (CSP, HSTS, X-Frame-Options) |
| `gestionar-modsecurity.sh` | Gestion de ModSecurity WAF (OWASP CRS, SecRuleEngine, anomaly detection) |
| `verificar-tls-web.sh` | Verificacion y optimizacion TLS/SSL (TLS 1.2/1.3, OCSP stapling) |
| `detectar-ddos-web.sh` | Deteccion y proteccion DDoS (nftables rules, connection limits, geoblocking) |
| `configurar-acceso-web.sh` | Control de acceso y autenticacion web (htpasswd, IP restrict, admin protection) |
| `monitorizar-web.sh` | Monitorizacion de servicios web en tiempo real |
| `analizar-logs-web.sh` | Analisis de logs web (real-time analysis, pattern detection) |
| `auditoria-seguridad-web.sh` | Auditoria de seguridad web (OWASP Top 10 compliance, scoring) |

### Gestion de secretos

| Herramienta | Funcion |
|-------------|---------|
| `auditar-secretos.sh` | Auditoria integral de gestion de secretos |
| `escanear-secretos.sh` | Escaneo de secretos en filesystem (API keys, passwords, tokens) |
| `rotar-credenciales.sh` | Rotacion automatica de credenciales |
| `auditar-ssh-keys.sh` | Auditoria de claves SSH (edad, fortaleza, authorized_keys) |

### Seguridad cloud

| Herramienta | Funcion |
|-------------|---------|
| `auditar-seguridad-cloud.sh` | Auditoria integral de seguridad cloud |
| `auditar-iam-cloud.sh` | Auditoria de IAM (AWS/Azure/GCP) |
| `verificar-imds.sh` | Verificacion de seguridad IMDS (Instance Metadata Service) |
| `auditar-cloud-init.sh` | Auditoria de cloud-init (credenciales, permisos, modulos peligrosos) |
| `enforcar-imds-hoplimit.sh` | Enforcement de hop-limit IMDSv2 con nftables |
| `auditar-credenciales-cloud.sh` | Auditoria de rotacion de credenciales cloud (AWS/Azure/GCP) |
| `filtrado-egress-cloud.sh` | Filtrado de trafico saliente cloud con whitelist |

### LDAP y Active Directory

| Herramienta | Funcion |
|-------------|---------|
| `auditar-ldap-ad.sh` | Auditoria integral de LDAP/AD |
| `hardening-openldap.sh` | Hardening de OpenLDAP (TLS, ACLs, logging) |
| `auditar-kerberos.sh` | Auditoria de Kerberos (tickets, keytabs, cifrado) |

### Cumplimiento normativo

| Herramienta | Funcion |
|-------------|---------|
| `auditar-cumplimiento.sh` | Auditoria de cumplimiento multi-framework |
| `evaluar-pci-dss.sh` | Evaluacion PCI-DSS v4.0 |
| `evaluar-gdpr.sh` | Evaluacion GDPR |
| `generar-evidencias.sh` | Generacion de evidencias de cumplimiento |

### Tecnologia de engano

| Herramienta | Funcion |
|-------------|---------|
| `dashboard-deception.sh` | Dashboard en vivo de deception (honeypots, tokens, files, users, dirs, alertas, IPs) |
| `informe-deception.sh` | Informes automatizados de deception (`24h`, `7d`, `30d`) |
| `auditoria-deception.sh` | Auditoria integral de deception |
| `gestionar-honeypots.sh` | Gestion de honeypots de red (`start`, `stop`, `status`, `logs`) |
| `generar-honeytokens.sh` | Gestion de honeytokens (`deploy`, `list`, `verify`, `rotate`) |
| `desplegar-honeyfiles.sh` | Gestion de honey files (`deploy`, `list`, `verify`, `remove`) |
| `gestionar-honey-users.sh` | Gestion de honey users (`create`, `remove`, `status`, `check-auth`) |
| `gestionar-honeydirs.sh` | Gestion de honey dirs (`deploy`, `list`, `verify`, `monitor`) |
| `configurar-honey-dns.sh` | Configuracion de honey DNS (`deploy`, `remove`, `status`) |
| `gestionar-servicios-decoy.sh` | Gestion de servicios decoy (`start`, `stop`, `status`) |
| `alertar-deception.sh` | Sistema de alertas de deception (`NIVEL TIPO 'Mensaje'`) |
| `analizar-deception-logs.sh` | Analisis de logs de deception |

### Seguridad wireless

| Herramienta | Funcion |
|-------------|---------|
| `auditar-wireless.sh` | Auditoria integral de seguridad wireless |
| `detectar-rogue-ap.sh` | Deteccion de puntos de acceso no autorizados |
| `hardening-bluetooth.sh` | Hardening de Bluetooth |

### Seguridad de virtualizacion

| Herramienta | Funcion |
|-------------|---------|
| `auditar-virtualizacion.sh` | Auditoria de seguridad de virtualizacion |
| `securizar-libvirt.sh` | Hardening de libvirt/KVM/QEMU |

### Seguridad fisica

| Herramienta | Funcion |
|-------------|---------|
| `auditar-seguridad-fisica.sh` | Auditoria de seguridad fisica |
| `gestionar-usbguard.sh` | Gestion de politicas USBGuard |

### Zero Trust Identity

| Herramienta | Funcion |
|-------------|---------|
| `evaluar-zero-trust.sh` | Evaluacion de madurez Zero Trust (CISA model) |
| `verificar-device-trust.sh` | Verificacion de confianza de dispositivo |

### Anti-ransomware

| Herramienta | Funcion |
|-------------|---------|
| `detectar-ransomware.sh` | Deteccion de actividad ransomware (canary files, YARA, patrones) |
| `respuesta-ransomware.sh` | Respuesta automatizada: contencion, aislamiento, evidencia |
| `auditar-anti-ransomware.sh` | Auditoria de preparacion anti-ransomware |

### Gestion de parches

| Herramienta | Funcion |
|-------------|---------|
| `escanear-cves.sh` | Escaneo de CVEs contra paquetes instalados |
| `generar-sbom.sh` | Generacion de SBOM (Software Bill of Materials) |
| `auditar-parches.sh` | Auditoria de gestion de parches y compliance |
| `parche-emergencia.sh` | Procedimiento de parche de emergencia por CVE |

### DevSecOps

| Herramienta | Funcion |
|-------------|---------|
| `auditar-devsecops.sh` | Auditoria integral DevSecOps |
| `sast-scanner.sh` | SAST multi-lenguaje (Python, JS, Go, C/C++) |
| `detectar-secretos-codigo.sh` | Deteccion de secretos en repositorios de codigo |
| `instalar-precommit-hooks.sh` | Instalacion de hooks pre-commit de seguridad |

### Seguridad de APIs

| Herramienta | Funcion |
|-------------|---------|
| `auditar-seguridad-api.sh` | Auditoria integral de seguridad de APIs |
| `gestionar-mtls.sh` | Gestion de mTLS (CA, certificados, revocacion) |
| `auditar-graphql.sh` | Auditoria de seguridad GraphQL |
| `auditar-headers-api.sh` | Auditoria de CORS y headers de seguridad API |

### Seguridad IoT

| Herramienta | Funcion |
|-------------|---------|
| `descubrir-dispositivos-iot.sh` | Descubrimiento e inventario de dispositivos IoT |
| `hardening-mqtt.sh` | Hardening de broker MQTT (Mosquitto TLS, ACL) |
| `auditar-seguridad-iot.sh` | Auditoria integral de seguridad IoT |
| `monitorear-trafico-iot.sh` | Monitorizacion de trafico IoT anomalo |

### DNS avanzado

| Herramienta | Funcion |
|-------------|---------|
| `auditar-dns-avanzado.sh` | Auditoria integral de seguridad DNS |
| `verificar-dnssec.sh` | Verificacion de DNSSEC y cadena de confianza |
| `actualizar-dns-blocklist.sh` | Actualizacion de blocklists DNS (RPZ/sinkhole) |
| `detectar-dns-tunneling.sh` | Deteccion de DNS tunneling (entropia, patrones) |
| `monitorear-dns.sh` | Monitorizacion continua de DNS (hijacking, disponibilidad) |

### Auditoria de red (Wireshark)

| Herramienta | Funcion |
|-------------|---------|
| `auditoria-red-captura.sh` | Captura automatizada con 6 perfiles (general, inseguros, dns, escaneos, lateral, exfiltracion) |
| `auditoria-red-analisis.sh` | Analisis de seguridad de capturas (protocolos, DNS, credenciales, TLS, ARP) |
| `auditoria-red-listar.sh` | Listado de capturas de red disponibles |
| `auditoria-red-anomalias.sh` | Deteccion de anomalias de red (20 checks: ARP spoofing/flooding, port scan, DNS tunneling, DHCP starvation, rogue DHCP, LLMNR/mDNS poisoning, Spotify Connect, Google Cast, SSDP/UPnP, DHCP device ID con EOL multi-OS/IoT, MAC randomization, SNMP, protocolos inseguros, captive portal detection, SNI plaintext analysis) |
| `auditoria-red-reporte.sh` | Generacion de reportes consolidados de auditoria de red |
| `auditoria-red-csv.sh` | Exportacion de capturas a CSV para analisis externo |
| `auditoria-red-correlacion.sh` | Correlacion de capturas con alertas Suricata IDS |
| `auditoria-red-rotacion.sh` | Rotacion y retencion de capturas (politica configurable) |

### Auditoria de infraestructura de red

| Herramienta | Funcion |
|-------------|---------|
| `auditoria-red-descubrimiento.sh` | Descubrimiento y mapeado de red (12 fases: ARP, nmap, OS fingerprint, NetBIOS, APIs IoT expuestas (Cast/Roku/UPnP/IPP), deteccion EOL 12+ categorias, generacion automatica de script de aislamiento LAN, verificacion cifrado disco LUKS, auditoria mount options, crypto policy + systemd sandboxing, inventario consolidado) |
| `auditoria-red-puertos.sh` | Auditoria de puertos TCP/UDP con politica de puertos autorizados/prohibidos |
| `auditoria-red-tls.sh` | Auditoria TLS/SSL (certificados, protocolos, cipher suites, testssl.sh, scoring A-F, batch) |
| `auditoria-red-snmp.sh` | Auditoria SNMP (community strings por defecto, SNMPv1/v2c vs v3, OIDs expuestos) |
| `auditoria-red-config.sh` | Auditoria de configuracion de red (interfaces, rutas, ARP, sysctl, DNS, firewall, conexiones) |
| `auditoria-red-inventario.sh` | Inventario de servicios con deteccion de version, comparacion con aprobados, shadow IT |
| `auditoria-red-baseline.sh` | Gestion de baseline de red y deteccion de drift (capture/compare/history) |
| `auditoria-red-programada.sh` | Orquestador de auditorias periodicas (diaria/semanal/mensual/trimestral/completa) |
| `auditoria-red-reporte-global.sh` | Reporte consolidado con puntuacion 0-100, grado A-D, exportacion JSON para SIEM |
| `auditoria-red-limpieza.sh` | Limpieza de reportes y scans antiguos segun politica de retencion |
| `auditoria-red-protocolos-modernos.sh` | Auditoria de protocolos IoT/ICS (MQTT auth+TLS, Modbus TCP, CoAP DTLS, AMQP management UI, Kubernetes API/etcd/kubelet), CVE cross-reference de versiones (OpenSSH regreSSHion, nginx, Apache, MariaDB, PostgreSQL, Redis, curl, Exim) |

### EDR con Osquery

| Herramienta | Funcion |
|-------------|---------|
| `securizar-edr-wazuh.sh` | Guia de integracion Wazuh/OSSEC (multi-distro) |
| `securizar-edr-alerts.sh` | Alertas syslog/JSON para osquery (dispatcher con tail/summary) |
| `securizar-edr-baseline.sh` | Baseline y drift detection (learn/check/status, timer semanal) |
| `securizar-edr-fleet.sh` | Template de integracion FleetDM (enrollment, TLS) |
| `securizar-edr-scheduled.sh` | Procesamiento de queries diferenciales (severidad, cron diario) |
| `auditoria-edr.sh` | Auditoria EDR con scoring (12 checks, 5 niveles, cron semanal) |

### Gestion de vulnerabilidades

| Herramienta | Funcion |
|-------------|---------|
| `securizar-vuln-system.sh` | Escaneo de vulnerabilidades del sistema (Trivy/grype/fallback) |
| `securizar-vuln-containers.sh` | Escaneo de contenedores Docker/Podman con threshold policy |
| `securizar-vuln-openscap.sh` | Evaluacion OpenSCAP con auto-deteccion de perfil SSG |
| `securizar-vuln-prioritize.sh` | Priorizacion CVSS+EPSS+KEV+Reachability (risk score 4 factores) |
| `securizar-vuln-deps.sh` | Analisis de dependencias (SUID binaries, librerias criticas) |
| `securizar-vuln-report.sh` | Reporting ejecutivo HTML/JSON/texto con dashboard |
| `securizar-vuln-patch-verify.sh` | Verificacion pre/post-patch con diff y rollback |
| `securizar-vuln-scheduled.sh` | Escaneo programado semanal con drift detection (timer systemd) |
| `auditoria-vuln-management.sh` | Auditoria de madurez L1-L5 con scoring (cron semanal) |
| `securizar-vuln-kernel.sh` | Deteccion directa de 9 CVEs kernel criticos (2024-2026: CVE-2025-21756 vsock UAF, CVE-2025-38236 MSG_OOB, CVE-2025-39866 writeback UAF, CVE-2024-1086 nf_tables, CVE-2022-0847 DirtyPipe, container escapes), modulos peligrosos cargados con --fix, verificacion supply chain (integridad paquetes, GPG, SUID), output JSON |

---

## Directorios de datos

| Directorio | Funcion |
|------------|---------|
| `/var/lib/incident-response/` | Datos de incidentes (forense, playbooks, timelines) |
| `/var/lib/security-monitoring/` | Monitorizacion (correlaciones, baselines, healthchecks, digests) |
| `/var/lib/security-reports/` | Reportes generados (MITRE, cumplimiento, inventario, Navigator JSON) |
| `/var/lib/threat-hunting/` | Caza de amenazas (baselines UEBA, anomalias, resultados de hunting) |
| `/var/lib/soar/` | SOAR (queue de eventos, acciones ejecutadas, IPs bloqueadas) |
| `/var/lib/purple-team/` | Purple Team (validacion, evidencia de simulaciones, reportes) |
| `/var/lib/ciberinteligencia/` | Ciberinteligencia (cache, config, datos, alertas) |
| `/var/lib/securizar/` | CIS scores, SBOM, binary hashes, CVE audits, software changes |
| `/var/lib/securizar/sbom/` | Inventarios SBOM en formato CycloneDX JSON |
| `/var/lib/securizar/binary-hashes/` | Baseline SHA-256 de binarios criticos del sistema |
| `/var/lib/securizar/cve-audit/` | Resultados de auditorias CVE |
| `/var/lib/securizar/log-hashes/` | Cadena de hashes para integridad de logs |
| `/var/lib/securizar/forense/` | Timelines y datos de forense de logs |
| `/var/log/securizar/` | Logs de correlacion, alertas, cambios de software |
| `/etc/securizar/email/` | Plantillas SPF, configuracion de seguridad email |
| `/etc/securizar/siem/` | Templates de integracion SIEM (ELK, Splunk, Graylog) |
| `/etc/securizar/log-certs/` | Certificados TLS para reenvio seguro de logs |
| `/etc/securizar/zonas-red.conf` | Definicion de zonas de red (TRUSTED/INTERNAL/DMZ/RESTRICTED) |
| `/etc/securizar/politicas-interzona.conf` | Matriz de politicas inter-zona |
| `/etc/securizar/microseg-servicios.conf` | Configuracion de microsegmentacion por servicio |
| `/etc/securizar/acceso-identidad.conf` | Mapeo usuarios/grupos a zonas de red |
| `/etc/securizar/yara-rules/` | Reglas YARA (crypto miners, shells, webshells, rootkits) |
| `/etc/securizar/custodia-plantilla.json` | Plantilla de cadena de custodia digital |
| `/etc/securizar/livepatch.conf` | Configuracion de live patching del kernel |
| `/etc/securizar/kernel-baseline.conf` | Baseline de parametros de seguridad del kernel |
| `/etc/securizar/kernel-update-policy.conf` | Politica de actualizacion del kernel |
| `/var/forensics/` | Almacenamiento de evidencia forense (RAM, disco, artefactos) |
| `/var/log/securizar/postura-dispositivo.json` | Reporte de postura Zero Trust |
| `/var/log/securizar/trafico-zonas.log` | Log de trafico inter-zona |
| `/var/log/securizar/kernel-cves.json` | Resultados de escaneo de CVEs del kernel |
| `/var/lib/securizar/zt-state.json` | Estado de verificacion continua Zero Trust |
| `/var/lib/securizar/db-security/` | Datos de auditoria de seguridad de bases de datos |
| `/var/lib/securizar/backup-dr/` | Datos de auditoria de backup y DR, estrategia 3-2-1 |
| `/var/lib/securizar/web-security/` | Datos de auditoria de seguridad web |
| `/etc/securizar/db-audit.conf` | Configuracion de audit logging de bases de datos |
| `/etc/securizar/backup-strategy.conf` | Configuracion de estrategia de backup 3-2-1 |
| `/etc/securizar/backup-offsite.conf` | Configuracion de backup offsite automatizado |
| `/etc/securizar/waf-rules/` | Reglas WAF personalizadas (SQL injection, XSS, path traversal) |
| `/etc/securizar/web-access.conf` | Configuracion de control de acceso web |
| `/var/log/securizar/db-audit.log` | Log de auditoria de bases de datos |
| `/var/log/securizar/backup-dr.log` | Log de operaciones de backup y DR |
| `/var/log/securizar/web-security.log` | Log de seguridad web y deteccion de ataques |
| `/etc/securizar/ransomware-canary.conf` | Configuracion de canary files anti-ransomware |
| `/etc/securizar/patch-policy.conf` | Politica de parcheo automatico |
| `/etc/securizar/devsecops-policy.conf` | Politica de seguridad DevSecOps |
| `/etc/securizar/api-security-policy.conf` | Politica de seguridad de APIs |
| `/etc/securizar/iot-security-policy.conf` | Politica de seguridad IoT |
| `/etc/securizar/dns-security-policy.conf` | Politica de seguridad DNS |
| `/etc/securizar/auditoria-red-policy.conf` | Politica de auditoria de red (retencion, perfiles) |
| `/etc/securizar/wireshark-filters/` | Filtros BPF y display para auditoria de seguridad |
| `/etc/securizar/wireshark-profiles/` | Perfiles de captura (6 perfiles predefinidos) |
| `/var/lib/securizar/capturas-red/` | Capturas de red (.pcapng) |
| `/var/lib/securizar/reportes-red/` | Reportes de auditoria de red |
| `/var/lib/securizar/sbom/` | Inventarios SBOM generados |
| `/var/lib/securizar/iot-inventory.json` | Inventario de dispositivos IoT |
| `/var/lib/securizar/patch-staging/` | Area de staging de parches |
| `/var/lib/securizar/auditoria-red/` | Datos de auditoria de infraestructura de red |
| `/var/lib/securizar/auditoria-red/scans/` | Resultados de escaneos nmap (XML, gnmap, txt) |
| `/var/lib/securizar/auditoria-red/reportes/` | Reportes de auditoria (texto, JSON) |
| `/var/lib/securizar/auditoria-red/baseline/` | Snapshots de baseline de red |
| `/var/lib/securizar/auditoria-red/baseline/history/` | Historial de drifts detectados |
| `/etc/securizar/auditoria-red/` | Configuracion de auditorias de infraestructura |
| `/etc/securizar/auditoria-red/puertos-autorizados.conf` | Politica de puertos autorizados/prohibidos |
| `/etc/securizar/auditoria-red/politica-tls.conf` | Politica de seguridad TLS/SSL |
| `/etc/securizar/auditoria-red/servicios-aprobados.conf` | Inventario de servicios aprobados |
| `/etc/securizar/auditoria-red/auditoria-programada.conf` | Configuracion de auditorias periodicas |
| `/etc/osquery/` | Configuracion de osquery (osquery.conf, packs, flags) |
| `/etc/osquery/packs/securizar-security.conf` | Pack de queries de seguridad (10 queries) |
| `/etc/osquery/packs/securizar-threat-detection.conf` | Pack de deteccion de amenazas (10 queries) |
| `/etc/securizar/edr/` | Configuracion EDR (decorators, baselines) |
| `/var/lib/securizar/edr-baseline/` | Snapshots de baseline EDR |
| `/etc/securizar/vuln-management/` | Configuracion de gestion de vulnerabilidades |
| `/var/lib/securizar/vuln-management/` | Datos de escaneos, reportes, parches |
| `/etc/securizar/cloud-egress-whitelist.conf` | Whitelist de trafico saliente cloud |
| `/usr/local/lib/incident-response/templates/` | Plantillas de comunicacion IR (CSIRT, gerencia, legal, usuarios) |
| `/etc/securizar/escalation-matrix.conf` | Matriz de escalacion por severidad |

---

## Convenciones del proyecto

### Interactividad

Cada seccion de cada modulo pregunta al usuario antes de aplicar cambios:

```
  ❯ ¿Aplicar hardening del kernel? [s/N]:
```

Nada se ejecuta sin confirmacion explicita.

### Backups

Antes de modificar cualquier archivo, se crea un backup automatico:

```
[+] Backup en: /root/hardening-opensuse-20250211-143022/
```

El directorio base se configura con `SECURIZAR_BACKUP_BASE` (default: `/root/`).

### Logging

Todas las acciones se registran con funciones estandarizadas:

```
  ✓ Servicio fail2ban habilitado        (log_info)
  ⚠ Paquete no encontrado               (log_warn)
  ✗ Error al aplicar configuracion       (log_error)
  -> Instalado: fail2ban (via zypper)    (log_change)
  -- Omitido: ya configurado             (log_skip)
```

Al final de cada modulo, `show_changes_summary` muestra un resumen:

```
  ┌── RESUMEN DE CAMBIOS ──────────────────────────────────
  │  12 cambios aplicados · 3 omitidos
  │
  │   -> Backup: directorio: /root/hardening-opensuse-...
  │   -> Instalado: fail2ban (via zypper)
  │   ...
  └────────────────────────────────────────────────────────
```

### Multi-distro

Los scripts nunca llaman directamente a gestores de paquetes o firewalls:

```bash
# Correcto
pkg_install fail2ban clamav aide
fw_add_service ssh
grub_regenerate

# Incorrecto (nunca hacer esto)
zypper install fail2ban    # Solo funciona en SUSE
firewall-cmd --add-service=ssh  # Solo funciona con firewalld
grub2-mkconfig -o /boot/grub2/grub.cfg  # Ruta incorrecta en Debian
```

---

## Restricciones de seguridad

La suite opera bajo restricciones estrictas para evitar lockouts:

| Restriccion | Motivo |
|-------------|--------|
| **NO modificar PAM** | Evitar bloqueo de autenticacion. `/etc/pam.d/su` y demas archivos PAM se dejan intactos |
| **NO limitar recursos** | No establecer `TMOUT=900; readonly TMOUT` ni otros timeouts |
| **NO bloquear al usuario** | No deshabilitar sshd, no aplicar firewall DROP sin servicios, no usar `chattr +i` en passwd/shadow/sudoers |
| **NO ejecutar directamente extremo/paranoico** | Usar siempre `securizar-menu.sh` que aplica versiones seguras |

---

## Uso avanzado

### Ejecutar un modulo individualmente

```bash
sudo bash hardening-opensuse.sh
```

### Ejecutar el menu y aplicar todo

```bash
sudo bash securizar-menu.sh
# Dentro del menu: pulsar 'a' para aplicar los 70 modulos secuencialmente
```

### Verificar controles sin aplicar cambios

```bash
sudo bash securizar-menu.sh
# Dentro del menu: pulsar 'v' para verificacion proactiva
```

### Ejecutar solo mitigaciones MITRE

```bash
sudo bash securizar-menu.sh
# Dentro del menu: pulsar 'm', luego 't' para ejecutar todos los MITRE
```

### Generar reportes

```bash
# Despues de instalar modulo 33
sudo /usr/local/bin/reporte-mitre.sh         # Cobertura MITRE ATT&CK
sudo /usr/local/bin/exportar-navigator.sh     # JSON para ATT&CK Navigator
sudo /usr/local/bin/resumen-ejecutivo.sh      # Score de postura
sudo /usr/local/bin/reporte-cumplimiento.sh   # Cumplimiento por categoria
```

### Dashboard de seguridad

```bash
# Despues de instalar modulo 32
sudo /usr/local/bin/security-dashboard.sh     # Estado en tiempo real
sudo /usr/local/bin/correlacionar-alertas.sh  # Correlacion de alertas
```

### Auditar infraestructura de red

```bash
# Despues de instalar modulo 65
sudo /usr/local/bin/auditoria-red-descubrimiento.sh 192.168.1.0/24     # Mapeado de red
sudo /usr/local/bin/auditoria-red-puertos.sh localhost --full           # Auditoria de puertos
sudo /usr/local/bin/auditoria-red-tls.sh example.com                    # Auditoria TLS/SSL
sudo /usr/local/bin/auditoria-red-snmp.sh 192.168.1.0/24               # Auditoria SNMP
sudo /usr/local/bin/auditoria-red-config.sh                             # Configuracion de red
sudo /usr/local/bin/auditoria-red-baseline.sh --capture                 # Capturar baseline
sudo /usr/local/bin/auditoria-red-baseline.sh --compare                 # Detectar drift
sudo /usr/local/bin/auditoria-red-reporte-global.sh --json              # Reporte consolidado
```

### Responder a un incidente

```bash
# Despues de instalar modulo 68
sudo /usr/local/bin/ir-recolectar-forense.sh          # Recoleccion forense
sudo /usr/local/bin/ir-responder.sh malware            # Ejecutar playbook
sudo /usr/local/bin/ir-aislar-red.sh                   # Aislar red (emergencia)
sudo /usr/local/bin/ir-timeline.sh                     # Generar timeline
sudo /usr/local/bin/ir-cadena-custodia.sh seal /tmp/evidencia  # Cadena de custodia
sudo /usr/local/bin/ir-extraer-iocs.sh /tmp/evidencia  # Extraer IOCs
sudo /usr/local/bin/ir-hunt-fleet.sh iocs.txt          # Hunting en flota
sudo /usr/local/bin/ir-post-review.sh                  # Metricas IR
```

### EDR y deteccion de amenazas

```bash
# Despues de instalar modulo 69
sudo /usr/local/bin/securizar-edr-baseline.sh learn    # Crear baseline
sudo /usr/local/bin/securizar-edr-baseline.sh check    # Detectar drift
sudo /usr/local/bin/securizar-edr-alerts.sh --tail     # Alertas en tiempo real
sudo /usr/local/bin/auditoria-edr.sh                   # Auditoria EDR
```

### Gestion de vulnerabilidades

```bash
# Despues de instalar modulo 70
sudo /usr/local/bin/securizar-vuln-system.sh           # Escaneo del sistema
sudo /usr/local/bin/securizar-vuln-containers.sh       # Escaneo de contenedores
sudo /usr/local/bin/securizar-vuln-prioritize.sh CVE-2024-1234  # Priorizacion
sudo /usr/local/bin/securizar-vuln-report.sh --format html     # Reporte HTML
sudo /usr/local/bin/securizar-vuln-patch-verify.sh --before    # Pre-patch snapshot
sudo /usr/local/bin/auditoria-vuln-management.sh       # Auditoria madurez
```

---

## Estructura de un modulo

Cada script sigue esta estructura obligatoria:

```bash
#!/bin/bash
# Descripcion del script

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "nombre-modulo"
securizar_setup_traps

# S1: NOMBRE DE LA SECCION
log_section "S1: NOMBRE DE LA SECCION"

echo "Descripcion de lo que se va a hacer..."

if ask "¿Aplicar este cambio?"; then
    # Backup del archivo antes de modificar
    cp /etc/config "$BACKUP_DIR/" 2>/dev/null || true
    log_change "Backup" "/etc/config"

    # Aplicar cambios
    pkg_install paquete-necesario
    fw_add_service servicio
    # ...

    log_info "Configuracion aplicada"
else
    log_skip "Seccion omitida por el usuario"
fi

# Al final del script
show_changes_summary
```

---

## Licencia

Este proyecto es software libre para uso defensivo en securizacion de sistemas Linux.

---

## Advertencias

- Ejecutar siempre en un entorno de test antes de aplicar en produccion
- Revisar cada seccion antes de confirmar (`s`) ya que los cambios modifican configuraciones del sistema
- Los backups se crean automaticamente pero verificar que el espacio en disco es suficiente
- Los modulos 5 y 6 solo deben ejecutarse a traves del menu (`securizar-menu.sh`) que aplica versiones seguras
- Las pruebas de Metasploit (modulo 36) estan restringidas a localhost por defecto
