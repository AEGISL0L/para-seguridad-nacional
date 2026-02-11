# Securizar

Suite completa de hardening y securizacion para Linux, con 50 modulos interactivos, cobertura total del framework MITRE ATT&CK, operaciones de seguridad (SOC), ciberinteligencia, cumplimiento CIS, forensia digital y Zero Trust. Soporta multiples distribuciones mediante una biblioteca de abstraccion compartida.

```
███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗███████╗ █████╗ ██████╗
██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══███╔╝██╔══██╗██╔══██╗
███████╗█████╗  ██║     ██║   ██║██████╔╝██║  ███╔╝ ███████║██████╔╝
╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║ ███╔╝  ██╔══██║██╔══██╗
███████║███████╗╚██████╗╚██████╔╝██║  ██║██║███████╗██║  ██║██║  ██║
╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
```

## Caracteristicas principales

- **50 modulos** organizados en 6 categorias con menu interactivo
- **Multi-distro**: openSUSE, Debian/Ubuntu, RHEL/Fedora/CentOS, Arch Linux
- **Cobertura MITRE ATT&CK** de las 14 tacticas enterprise (TA0001-TA0043)
- **100% interactivo**: cada seccion pregunta antes de aplicar cambios
- **Backups automaticos** antes de cada modificacion
- **Protecciones de seguridad**: no bloquea al usuario, no modifica PAM, no deshabilita SSH
- **Verificacion proactiva** de 58 categorias de controles
- **Operaciones SOC**: IR, monitoreo continuo, SOAR, threat hunting, purple team
- **Ciberinteligencia**: enriquecimiento de IoC, inteligencia DNS, alerta temprana
- **Cumplimiento**: CIS Benchmarks Level 1/2, mapeo NIST 800-53

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

El menu principal muestra 6 categorias con indicadores de progreso. Se navega con las teclas indicadas o accediendo directamente por numero de modulo (1-50):

```
  b  Hardening Base          (modulos 1-10)   ●●●○○○○○○○
  p  Securizacion Proactiva  (modulos 11-18)  ○○○○○○○○
  m  Mitigaciones MITRE      (modulos 19-30)  ○○○○○○○○○○○○
  o  Operaciones de Seguridad(modulos 31-36)  ○○○○○○
  i  Inteligencia            (modulos 37-38)  ○○
  x  Avanzado                (modulos 39-50)  ○○○○○○○○○○○○

  a  Aplicar todos    v  Verificacion    1-50 Acceso directo    q  Salir
```

Tambien es posible ejecutar cualquier modulo individualmente:

```bash
sudo bash hardening-opensuse.sh      # Modulo 1
sudo bash mitigar-acceso-inicial.sh  # Modulo 19
sudo bash respuesta-incidentes.sh    # Modulo 31
```

---

## Estructura del proyecto

```
securizar/
├── securizar-menu.sh              # Menu orquestador principal (50 modulos)
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
├── hardening-opensuse.sh          # Modulo  1: Hardening base del sistema
├── hardening-seguro.sh            # Modulo  2: Nivel seguro de hardening
├── hardening-final.sh             # Modulo  3: Hardening final consolidado
├── hardening-externo.sh           # Modulo  4: Hardening de servicios externos
├── hardening-extremo.sh           # Modulo  5: Nivel extremo (via menu = seguro)
├── hardening-paranoico.sh         # Modulo  6: Nivel paranoico (via menu = seguro)
├── contramedidas-mesh.sh          # Modulo  7: Contramedidas de red mesh
├── contramedidas-avanzadas.sh     # Modulo  8: Contramedidas vigilancia avanzada
├── proteger-privacidad.sh         # Modulo  9: Proteccion de privacidad
├── aplicar-banner-total.sh        # Modulo 10: Banners de seguridad
├── hardening-kernel-boot.sh       # Modulo 11: Kernel boot y Secure Boot
├── hardening-servicios-systemd.sh # Modulo 12: Sandboxing de servicios systemd
├── hardening-cuentas.sh           # Modulo 13: Seguridad de cuentas
├── proteger-red-avanzado.sh       # Modulo 14: Red avanzada (IDS, VPN, DoT)
├── automatizar-seguridad.sh       # Modulo 15: Automatizacion de seguridad
├── sandbox-aplicaciones.sh        # Modulo 16: Sandboxing de aplicaciones
├── auditoria-externa.sh           # Modulo 17: Auditoria de reconocimiento
├── inteligencia-amenazas.sh       # Modulo 18: Inteligencia de amenazas IoC
├── mitigar-acceso-inicial.sh      # Modulo 19: MITRE TA0001
├── mitigar-ejecucion.sh           # Modulo 20: MITRE TA0002
├── mitigar-persistencia.sh        # Modulo 21: MITRE TA0003
├── mitigar-escalada.sh            # Modulo 22: MITRE TA0004
├── mitigar-impacto.sh             # Modulo 23: MITRE TA0040
├── mitigar-evasion.sh             # Modulo 24: MITRE TA0005
├── mitigar-credenciales.sh        # Modulo 25: MITRE TA0006
├── mitigar-descubrimiento.sh      # Modulo 26: MITRE TA0007
├── mitigar-movimiento-lateral.sh  # Modulo 27: MITRE TA0008
├── mitigar-recoleccion.sh         # Modulo 28: MITRE TA0009
├── mitigar-exfiltracion.sh        # Modulo 29: MITRE TA0010
├── mitigar-comando-control.sh     # Modulo 30: MITRE TA0011
├── respuesta-incidentes.sh        # Modulo 31: Respuesta a incidentes
├── monitorizar-continuo.sh        # Modulo 32: Monitorizacion continua
├── reportar-seguridad.sh          # Modulo 33: Reportes de seguridad
├── cazar-amenazas.sh              # Modulo 34: Caza de amenazas (UEBA)
├── automatizar-respuesta.sh       # Modulo 35: Automatizacion SOAR
├── validar-controles.sh           # Modulo 36: Validacion Purple Team
├── ciberinteligencia.sh           # Modulo 37: Ciberinteligencia proactiva
├── proteger-contra-isp.sh         # Modulo 38: Proteccion contra espionaje ISP
├── hardening-criptografico.sh     # Modulo 39: Hardening criptografico
├── seguridad-contenedores.sh      # Modulo 40: Seguridad de contenedores
├── cumplimiento-cis.sh            # Modulo 41: Cumplimiento CIS Benchmarks
├── seguridad-email.sh             # Modulo 42: Seguridad de email
├── logging-centralizado.sh        # Modulo 43: Logging centralizado y SIEM
├── seguridad-cadena-suministro.sh # Modulo 44: Cadena de suministro
├── segmentacion-red-zt.sh         # Modulo 45: Segmentacion de red y Zero Trust
├── forense-avanzado.sh            # Modulo 46: Forense avanzado
├── kernel-livepatch.sh            # Modulo 47: Kernel live patching
├── seguridad-bases-datos.sh       # Modulo 48: Seguridad de bases de datos
├── backup-recuperacion.sh         # Modulo 49: Backup y recuperacion
└── seguridad-web.sh               # Modulo 50: Seguridad web
```

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
| `fw_reload` | Recarga la configuracion |
| `fw_list_all` | Lista todas las reglas activas |
| `fw_direct_add_rule ...` | Regla directa (iptables-like) |

Para nftables, mantiene una tabla `inet securizar` y resuelve automaticamente puertos de servicios conocidos.

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

Funciones compartidas para el modulo 37 (ciberinteligencia proactiva):
- Enriquecimiento de IoC con scoring (0-100)
- Consulta de APIs de inteligencia de amenazas
- Rate limiting configurable entre consultas
- Umbrales configurables: enrich (30), alert (50), block (75)
- Gestion de cache con TTL de 24h

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

### Categoria 1: Hardening Base (modulos 1-10)

Modulos fundamentales de securizacion del sistema.

| # | Modulo | Script | Descripcion |
|---|--------|--------|-------------|
| 1 | **Hardening base** | `hardening-opensuse.sh` | 13 secciones: hardening de kernel (sysctl), eliminacion de FTP, servicios innecesarios, firewall, SSH hardening, politicas de contrasenas, permisos de archivos criticos, fail2ban, actualizaciones automaticas, auditd, MFA para SSH, ClamAV antimalware, OpenSCAP |
| 2 | **Hardening seguro** | `hardening-seguro.sh` | Seguridad de archivos, procesos, AIDE (integridad), claves SSH |
| 3 | **Hardening final** | `hardening-final.sh` | Consolidacion de auditd, sysctl avanzado, reglas de firewall, actualizaciones |
| 4 | **Hardening externo** | `hardening-externo.sh` | Banners de seguridad, honeypot, DNS seguro, plantilla VPN |
| 5 | **Hardening extremo** | *(inline en menu)* | USB, kernel, red. **SEGURO**: el menu reimplementa este modulo eliminando las secciones que causan lockout (deshabilitacion de sshd, firewall DROP, chattr +i) |
| 6 | **Hardening paranoico** | *(inline en menu)* | Core dumps, GRUB, auditoria avanzada. **SEGURO**: el menu reimplementa eliminando TMOUT readonly y modificacion de PAM |
| 7 | **Contramedidas mesh** | `contramedidas-mesh.sh` | Proteccion de redes WiFi, Bluetooth e IoT mesh |
| 8 | **Contramedidas avanzadas** | `contramedidas-avanzadas.sh` | TEMPEST, canales acusticos, side-channel attacks |
| 9 | **Proteger privacidad** | `proteger-privacidad.sh` | VNC seguro, camara, prevencion DNS leaks, integracion Tor |
| 10 | **Aplicar banners** | `aplicar-banner-total.sh` | MOTD, /etc/issue, banner SSH, GDM, Firefox |

### Categoria 2: Securizacion Proactiva (modulos 11-18)

Modulos avanzados de proteccion preventiva.

| # | Modulo | Script | Descripcion |
|---|--------|--------|-------------|
| 11 | **Kernel boot y Secure Boot** | `hardening-kernel-boot.sh` | Parametros GRUB cmdline, verificacion Secure Boot, modulos firmados, proteccion GRUB con contrasena, lockdown del kernel |
| 12 | **Sandboxing de servicios** | `hardening-servicios-systemd.sh` | Drop-ins systemd para sshd, fail2ban, firewalld, NetworkManager, security-monitor con ProtectSystem, ProtectHome, NoNewPrivileges |
| 13 | **Seguridad de cuentas** | `hardening-cuentas.sh` | Politicas de contrasenas en login.defs, faillock, deteccion de cuentas sin contrasena, verificacion UID=0 extra, shells de sistema, cuentas inactivas |
| 14 | **Red avanzada** | `proteger-red-avanzado.sh` | Suricata IDS con reglas ET Open, DNS over TLS (systemd-resolved), plantilla WireGuard VPN, arpwatch y proteccion ARP |
| 15 | **Automatizacion** | `automatizar-seguridad.sh` | Cron jobs para AIDE, parches de seguridad, lynis, rkhunter, logrotate, digest diario; timer systemd de notificaciones |
| 16 | **Sandboxing de aplicaciones** | `sandbox-aplicaciones.sh` | Firejail (perfiles para Firefox, Thunderbird, LibreOffice, Dolphin, firecfg), bubblewrap |
| 17 | **Auditoria externa** | `auditoria-externa.sh` | Reconocimiento MITRE TA0043: puertos expuestos, banners, fingerprinting OS, DNS, cabeceras HTTP, SNMP, consulta Shodan/Censys, metadatos web, certificados SSL/TLS, defensas anti-escaneo |
| 18 | **Inteligencia de amenazas** | `inteligencia-amenazas.sh` | MITRE M1019/TA0042: feeds de IoC (Blocklist.de, Feodo Tracker, ET, Spamhaus DROP/EDROP, Tor Exit Nodes, CI Army, SSLBL, URLhaus), integracion firewall/ipset, reglas Suricata, herramienta `ioc-lookup.sh`, actualizacion diaria |

### Categoria 3: Mitigaciones MITRE ATT&CK (modulos 19-30)

Defensas especificas contra cada tactica del framework MITRE ATT&CK.

| # | Modulo | Script | Tactica | Tecnicas principales |
|---|--------|--------|---------|---------------------|
| 19 | **Acceso inicial** | `mitigar-acceso-inicial.sh` | TA0001 | T1133 (SSH), T1190 (exploits web), T1078 (cuentas validas), T1566 (phishing), T1189 (drive-by), T1195 (supply chain GPG), T1200 (USBGuard/DMA) |
| 20 | **Ejecucion** | `mitigar-ejecucion.sh` | TA0002 | T1059 (AppArmor, bash restringido, interpretes), T1204 (noexec /tmp), T1129 (restriccion LD_PRELOAD), monitor de ejecucion |
| 21 | **Persistencia** | `mitigar-persistencia.sh` | TA0003 | T1053 (cron/timers), T1543 (servicios systemd), T1547/T1037 (autostart), T1136 (cuentas), T1556 (autenticacion), T1574 (PATH hijack) |
| 22 | **Escalada de privilegios** | `mitigar-escalada.sh` | TA0004 | T1548 (SUID/SGID), T1134 (capabilities), T1078 (sudo), T1068 (kernel sysctl), T1055 (anti-ptrace), T1053 (cron privesc) |
| 23 | **Impacto** | `mitigar-impacto.sh` | TA0040 | T1486/T1561 (backups offsite rsync), T1486 (ClamAV anti-ransomware con YARA), T1490 (proteccion snapshots/checksums), T1485 (monitoreo auditd) |
| 24 | **Evasion de defensas** | `mitigar-evasion.sh` | TA0005 | T1070 (logs append-only), T1036 (masquerading), T1562 (watchdog servicios), T1014 (rootkits rkhunter), T1218 (LOLBins), T1564 (artefactos ocultos), T1027 (ofuscacion) |
| 25 | **Acceso a credenciales** | `mitigar-credenciales.sh` | TA0006 | T1003 (credential dumping), T1110 (fuerza bruta faillock), T1557 (MITM arpwatch), T1552 (credenciales expuestas), T1040 (modo promiscuo), T1056 (keyloggers) |
| 26 | **Descubrimiento** | `mitigar-descubrimiento.sh` | TA0007 | T1046 (portscan rate-limit), T1057 (hidepid procesos), T1082 (info sistema), T1016/T1049 (red), T1087/T1069 (cuentas), T1518 (software) |
| 27 | **Movimiento lateral** | `mitigar-movimiento-lateral.sh` | TA0008 | T1021 (SSH anti-forwarding), T1021.001/005 (RDP/VNC desactivado), T1021.002 (Samba firma obligatoria), T1563 (SSH agent), T1080 (contenido compartido noexec), M1030 (segmentacion) |
| 28 | **Recoleccion** | `mitigar-recoleccion.sh` | TA0009 | T1005 (datos locales), T1039 (shares), T1025 (medios extraibles USBGuard), T1074 (data staging), T1113/T1125/T1123 (captura), T1119 (automatizada), T1560 (compresion) |
| 29 | **Exfiltracion** | `mitigar-exfiltracion.sh` | TA0010 | T1041 (trafico saliente), T1048 (DNS tunneling), T1567 (cloud), T1052 (USB), T1030 (ancho de banda tc), monitoreo de transferencias |
| 30 | **Comando y control** | `mitigar-comando-control.sh` | TA0011 | T1571 (puertos C2), T1071 (Cobalt Strike/Meterpreter/Sliver Suricata), T1105 (tool transfer), T1090/T1572 (proxies/tuneles), T1568 (DGA heuristicas) |

Cada modulo MITRE instala scripts de deteccion en `/usr/local/bin/`, reglas auditd en `/etc/audit/rules.d/` y cron jobs/timers systemd para monitoreo continuo.

### Categoria 4: Operaciones de Seguridad (modulos 31-36)

Herramientas para un SOC (Security Operations Center) funcional.

| # | Modulo | Script | Descripcion |
|---|--------|--------|-------------|
| 31 | **Respuesta a incidentes** | `respuesta-incidentes.sh` | Toolkit forense (`ir-recolectar-forense.sh` con 15 categorias y cadena de custodia), playbooks de contencion (cuenta comprometida, malware, C2, movimiento lateral), timeline de ataque con mapeo MITRE, aislamiento/restauracion de red, guia de recuperacion |
| 32 | **Monitorizacion continua** | `monitorizar-continuo.sh` | Dashboard de estado (`security-dashboard.sh`), correlacion de alertas multi-fuente (5 patrones de ataque), baseline de comportamiento del sistema, health check de controles (cron diario), digest periodico (timer 06:00) |
| 33 | **Reportes de seguridad** | `reportar-seguridad.sh` | Reporte de cobertura MITRE ATT&CK, exportacion ATT&CK Navigator JSON layer, reporte de cumplimiento por categoria, inventario de activos de seguridad, resumen ejecutivo con score de postura |
| 34 | **Caza de amenazas** | `cazar-amenazas.sh` | UEBA (baseline de usuarios + deteccion de anomalias), 5 playbooks de hunting (persistencia oculta, LOLBins, lateral silencioso, exfil lenta, C2 encubierto), deteccion persistencia avanzada T1098 (timer 15min), busqueda retrospectiva en logs, anomalias de red (beaconing, asimetrico, C2) |
| 35 | **Automatizacion de respuesta** | `automatizar-respuesta.sh` | SOAR ligero: motor de respuesta automatica (6 tipos de eventos), bloqueo IP/cuenta, preservacion de evidencia, gestion de bloqueos (listar/whitelist/limpiar), notificaciones por severidad, reglas configurables en `/etc/security/soar-rules.conf` |
| 36 | **Validacion de controles** | `validar-controles.sh` | Purple team: validador de autenticacion (15 tests), red (15 tests), endpoint (21 tests), simulador seguro de 12 tecnicas ATT&CK, reporte consolidado con scoring global (60% controles + 40% deteccion), validacion semanal automatica |

### Categoria 5: Inteligencia (modulos 37-38)

| # | Modulo | Script | Descripcion |
|---|--------|--------|-------------|
| 37 | **Ciberinteligencia proactiva** | `ciberinteligencia.sh` | Motor de enriquecimiento de IoC multi-fuente con scoring 0-100, inteligencia de red proactiva (GeoIP, correlacion), inteligencia DNS (DGA, tunneling, NRD), monitorizacion de superficie de ataque, sistema de alerta temprana y CVE monitoring, informes de inteligencia automatizados, monitorizacion de credenciales expuestas, integracion SOAR. Instala 16 scripts y 6 timers systemd |
| 38 | **Proteccion contra ISP** | `proteger-contra-isp.sh` | Kill switch VPN (iptables DROP si cae la VPN), prevencion de fugas DNS (DoT estricto + DNSSEC), ECH (Encrypted Client Hello), prevencion WebRTC leaks, evasion de DPI (obfs4/stunnel), hardening de privacidad del navegador, HTTPS-Only enforcement, NTP con NTS, ofuscacion de patrones de trafico, auditoria de metadatos ISP |

### Categoria 6: Avanzado (modulos 39-50)

| # | Modulo | Script | Descripcion |
|---|--------|--------|-------------|
| 39 | **Hardening criptografico** | `hardening-criptografico.sh` | Auditoria y hardening de algoritmos SSH (KexAlgorithms, Ciphers, MACs, HostKey), TLS system-wide, monitorizacion de certificados, calidad de entropia, hardening GPG, verificacion de cifrado de disco (LUKS), escaneo TLS de servicios locales, auditoria de hashing de contrasenas, hardening criptografico del kernel |
| 40 | **Seguridad de contenedores** | `seguridad-contenedores.sh` | Hardening de Docker/Podman daemon, restricciones de runtime (seccomp, AppArmor, capabilities), seguridad de imagenes, aislamiento de red de contenedores, seguridad de almacenamiento, seguridad de registro (registry), contenedores rootless, monitorizacion, seguridad Kubernetes basica, auditoria CIS de contenedores |
| 41 | **Cumplimiento CIS** | `cumplimiento-cis.sh` | Evaluacion CIS Benchmark Level 1 y 2 (sistema de archivos, servicios, red, logging, acceso), mapeo a NIST 800-53, motor de puntuacion CIS con scoring, remediacion automatica segura, generacion de informe de cumplimiento |
| 42 | **Seguridad de email** | `seguridad-email.sh` | Hardening de Postfix (banner, VRFY, HELO), SPF (verificacion DNS, sintaxis, ~all vs -all), DKIM (opendkim 2048-bit, rotacion de claves), DMARC (opendmarc, p=reject), TLS obligatorio (DANE, cipher hardening), anti-relay (restricciones, rate limiting, submission 587), proteccion anti-spoofing (header_checks, sender_login_maps), filtrado de spam (SpamAssassin, Bayes, MIME blocking), monitorizacion de email, auditoria completa (SEGURO/MEJORABLE/INSEGURO) |
| 43 | **Logging centralizado** | `logging-centralizado.sh` | Hardening rsyslog/journald (permisos, async, Forward Secure Sealing), reenvio TLS (rsyslog-gnutls, certificados auto-generados, cola persistente), agregacion CEF/JSON con normalizacion RFC 5424, almacenamiento seguro (chattr +a, hash chain SHA-256, gocryptfs vault), correlacion de eventos (8 patrones: brute force, escalada, lateral, staging, tampering), alertas en tiempo real (omprog, email/webhook, rate limiting), retencion avanzada (365/180/90/30 dias, zstd), integracion SIEM (templates ELK/Splunk/Graylog), forense de logs (timeline, chain of custody), auditoria (COMPLETO/PARCIAL/INSUFICIENTE) |
| 44 | **Cadena de suministro** | `seguridad-cadena-suministro.sh` | Verificacion de firmas GPG por distro (zypper/apt/dnf/pacman), inventario SBOM en CycloneDX JSON con diff, auditoria de CVEs (zypper list-patches/dnf updateinfo/arch-audit), repositorios seguros (HTTPS, whitelist, prioridades), integridad de binarios (rpm -Va/debsums/pacman -Qk, baseline SHA-256), politica de instalacion (hook de logging, enforcement por distro), deteccion de troyanizados (SUID/SGID, orphan binaries, LD_PRELOAD, capabilities, PATH hijack), hardening del gestor de paquetes, monitorizacion de cambios de software (timer 6h), auditoria completa (SEGURO/MEJORABLE/INSEGURO, NIST 800-53 SA) |
| 45 | **Segmentacion de red y Zero Trust** | `segmentacion-red-zt.sh` | Zonas de red con nftables (TRUSTED/INTERNAL/DMZ/RESTRICTED), politicas inter-zona (default-deny, matriz de flujos), microsegmentacion por servicio (nftables per-service), aislamiento de contenedores Docker/Podman (redes internas, ICC disabled), evaluacion de postura de dispositivo Zero Trust (scoring 0-100, JSON), control de acceso basado en identidad (PAM + zonas de red), monitorizacion de trafico inter-zona (tcpdump/conntrack, deteccion de anomalias), validacion de segmentacion (tests de aislamiento), verificacion continua ZT (cron 15min, drift detection), auditoria completa (BUENO/MEJORABLE/DEFICIENTE) |
| 46 | **Forense avanzado** | `forense-avanzado.sh` | Kit de adquisicion de memoria (LiME/proc/kcore, multi-formato), imagen de disco forense (dc3dd/dd, dual hash SHA-256+MD5, write-blocking), preservacion de datos volatiles (RFC 3227, 10 categorias por orden de volatilidad), recopilacion de artefactos (logs, histories, SUID, hidden files, tarball firmado), timeline unificada (MAC times, logs, journal, wtmp/btmp, CSV con filtrado), analisis de malware (YARA con 6 sets de reglas, analisis estatico de binarios), cadena de custodia digital (JSON manifest, hash verification), analisis de logs (brute force, escalada, anomalias), script maestro de recopilacion total, auditoria de preparacion forense (BUENO/MEJORABLE/DEFICIENTE) |
| 47 | **Kernel live patching** | `kernel-livepatch.sh` | Auditoria de seguridad del kernel (KASLR, SMEP/SMAP, KPTI, Retpoline, lockdown), setup de live patching (kpatch/livepatch/kGraft por distro), mitigacion de exploits via sysctl (25+ parametros: kptr_restrict, dmesg_restrict, perf_event_paranoid, yama ptrace, unprivileged_bpf, kexec_load_disabled), hardening de modulos kernel (blacklist 15+ modulos peligrosos, modprobe.d), validacion de parametros contra baseline (drift detection, auto-remediacion), monitorizacion de CVEs del kernel (base de datos local, matching por version), politica de actualizacion del kernel, verificacion de Secure Boot y firma de modulos, rollback seguro de kernel (GRUB, kexec), auditoria completa (BUENO/MEJORABLE/DEFICIENTE) |
| 48 | **Seguridad de bases de datos** | `seguridad-bases-datos.sh` | PostgreSQL hardening (pg_hba.conf, SSL, logging, connection limits), MySQL/MariaDB hardening (bind-address, local-infile, secure transport, password validation), Redis hardening (requirepass, bind, protected-mode, rename-command, ACL), MongoDB hardening (authorization, bindIp, JavaScript disable, audit), autenticacion y control de acceso (role-based, minimum privilege, audit scripts), cifrado de bases de datos (at rest e in transit, TLS para todos los motores), backup seguro de bases de datos (encrypted dumps, GPG signing, retention), audit logging (pgaudit, MariaDB audit, query monitoring), prevencion de SQL injection y monitorizacion de queries (log-based detection, pattern matching), auditoria de seguridad de bases de datos (multi-engine audit con scoring) |
| 49 | **Backup y recuperacion** | `backup-recuperacion.sh` | Estrategia 3-2-1 (config generator, validation), backup cifrado con Borg (repokey-blake2, zstd, retention, systemd timer), backup cifrado con Restic (AES-256, S3/SFTP support, health check), backups inmutables WORM (chattr +i, btrfs snapshots, lockdown), verificacion y restauracion automatica (integrity check, test restore), backup de sistema completo bare metal (full disk/partition image), RTO/RPO y planificacion (DR plan generator, compliance, SLA), backup offsite automatizado (SFTP, S3, rsync, cron automation), proteccion anti-ransomware (honeypots, process monitoring, lockdown), auditoria de backup y DR (scoring, compliance check) |
| 50 | **Seguridad web** | `seguridad-web.sh` | Hardening de nginx (server_tokens, buffers, timeouts, rate limiting, DH params), hardening de Apache/httpd (ServerTokens, TraceEnable, mod_info/status disable), cabeceras de seguridad HTTP (CSP, HSTS, X-Frame-Options, Permissions-Policy), ModSecurity WAF (OWASP CRS, SecRuleEngine, anomaly detection), optimizacion TLS/SSL (TLS 1.2/1.3, OCSP stapling, session tickets off), rate limiting y proteccion DDoS (nftables rules, connection limits, geoblocking), reglas WAF personalizadas (SQL injection, XSS, path traversal, scanners), control de acceso y autenticacion (htpasswd, IP restrict, admin protection), monitorizacion y analisis de logs web (real-time analysis, pattern detection), auditoria de seguridad web (OWASP Top 10 compliance, scoring) |

---

## Menu orquestador (`securizar-menu.sh`)

El menu orquestador es el punto de entrada principal de la suite. Proporciona:

### Navegacion jerarquica

```
Menu principal
├── b  Hardening Base (1-10)
├── p  Securizacion Proactiva (11-18)
├── m  Mitigaciones MITRE ATT&CK (19-30)
├── o  Operaciones de Seguridad (31-36)
├── i  Inteligencia (37-38)
├── x  Avanzado (39-50)
├── a  Aplicar todos los 50 modulos
├── v  Verificacion proactiva (58 checks)
├── 1-50  Acceso directo por numero
├── ?  Ayuda
└── q  Salir con resumen de sesion
```

Cada sub-menu muestra sus modulos con estado (`✓` completado, `○` pendiente, `!` archivo faltante) y permite ejecutar modulos individuales o todos los de la categoria con `t`.

### Protecciones de seguridad

El menu reimplementa inline los modulos 5 (extremo) y 6 (paranoico) eliminando secciones peligrosas:

- **Modulo 5 (extremo)**: elimina deshabilitacion de sshd, firewall DROP ultra-restrictivo y chattr +i en archivos criticos
- **Modulo 6 (paranoico)**: elimina TMOUT=900 readonly y modificacion de `/etc/pam.d/su`

Esto garantiza que nunca se bloquee el acceso al sistema.

### Verificacion proactiva

La opcion `v` ejecuta 58 verificaciones agrupadas por categoria:

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
# Dentro del menu: pulsar 'a' para aplicar los 50 modulos secuencialmente
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

### Responder a un incidente

```bash
# Despues de instalar modulo 31
sudo /usr/local/bin/ir-recolectar-forense.sh          # Recoleccion forense
sudo /usr/local/bin/ir-responder.sh malware            # Ejecutar playbook
sudo /usr/local/bin/ir-aislar-red.sh                   # Aislar red (emergencia)
sudo /usr/local/bin/ir-timeline.sh                     # Generar timeline
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
