# Securizar - Scripts de Hardening Multi-Distro

Colección de scripts Bash interactivos para hardening y securización de sistemas Linux. Soporta openSUSE, Debian/Ubuntu, RHEL/Fedora/CentOS y Arch Linux mediante una biblioteca compartida de abstracción.

## Estructura del proyecto

### Biblioteca compartida (`lib/`)

Todos los scripts cargan una única línea `source "${SCRIPT_DIR}/lib/securizar-common.sh"` que provee:

| Fichero | Función |
|---------|---------|
| `lib/securizar-common.sh` | Punto de entrada: colores, `log_info/warn/error/section/alert()`, `ask()`, `require_root`, `init_backup`, carga los demás módulos |
| `lib/securizar-distro.sh` | Detección de distro vía `/etc/os-release` → `DISTRO_ID`, `DISTRO_FAMILY` (suse/debian/rhel/arch), `DISTRO_VERSION`, `DISTRO_NAME` |
| `lib/securizar-pkg-map.sh` | Tabla de mapeo de 26 paquetes por distro (`declare -gA PKG_MAP`), `pkg_resolve_name()` |
| `lib/securizar-pkg.sh` | Abstracción de paquetes: `pkg_install`, `pkg_remove`, `pkg_refresh`, `pkg_patch_security`, `pkg_is_installed`, `pkg_query_all`, `pkg_query_file`, `pkg_verify`, `pkg_query_signatures`, `pkg_audit_tool_paths` |
| `lib/securizar-firewall.sh` | Abstracción de firewall (firewalld/ufw/nftables/iptables): `fw_add_service`, `fw_add_port`, `fw_add_rich_rule`, `fw_set_default_zone`, `fw_reload`, `fw_list_all`, `fw_direct_add_rule`, etc. |
| `lib/securizar-paths.sh` | Rutas GRUB y SCAP por distro: `$GRUB_CFG`, `$GRUB_CFG_DIR`, `$GRUB_EFI_CFG`, `grub_regenerate()`, `grub_set_password()`, `$SCAP_DS_PATH`, `$SCAP_OVAL_PATH` |

Configuración opcional en `securizar.conf` (variables: `SECURIZAR_BACKUP_BASE`, `SECURIZAR_FW_BACKEND`, `SECURIZAR_LOG_TO_FILE`).

#### Distribuciones soportadas

| Familia | Distribuciones | Gestor de paquetes | Firewall por defecto |
|---------|---------------|-------------------|---------------------|
| `suse` | openSUSE Leap/Tumbleweed, SLES | zypper | firewalld |
| `debian` | Debian, Ubuntu, Linux Mint | apt | ufw |
| `rhel` | RHEL, Fedora, CentOS, Rocky, Alma | dnf | firewalld |
| `arch` | Arch Linux, Manjaro, EndeavourOS | pacman | nftables/iptables |

### Menú orquestador
- `securizar-menu.sh` - Menú interactivo con navegación por sub-menús que orquesta los 36 scripts con protecciones de seguridad. Reimplementa inline los scripts peligrosos (extremo y paranoico) eliminando secciones que causan lockout o violan restricciones. Incluye verificación proactiva de 43 categorías. Navegación jerárquica: menú principal con 4 categorías (b=Base, p=Proactiva, m=MITRE, o=Operaciones) + acciones (a=aplicar todo, v=verificación) + acceso directo por número (1-36).

### Scripts de hardening base (10)
- `hardening-opensuse.sh` - Hardening base del sistema (13 secciones: kernel, FTP, servicios, firewall, SSH, contraseñas, permisos, fail2ban, actualizaciones, auditd, MFA SSH, ClamAV, OpenSCAP)
- `hardening-seguro.sh` - Nivel seguro de hardening
- `hardening-extremo.sh` - Nivel extremo (PELIGROSO: deshabilita sshd, firewall DROP, chattr +i)
- `hardening-paranoico.sh` - Nivel paranoico (PELIGROSO: TMOUT readonly, modifica PAM)
- `hardening-final.sh` - Hardening final consolidado
- `hardening-externo.sh` - Hardening de servicios externos
- `contramedidas-mesh.sh` - Contramedidas de red mesh
- `contramedidas-avanzadas.sh` - Contramedidas contra vigilancia avanzada (TEMPEST, side-channel)
- `proteger-privacidad.sh` - Protección de privacidad
- `aplicar-banner-total.sh` - Aplicación de banners de seguridad

### Scripts de securización proactiva (8)
- `hardening-kernel-boot.sh` - Parámetros de arranque del kernel (cmdline GRUB), verificación Secure Boot, módulos firmados, protección GRUB
- `hardening-servicios-systemd.sh` - Sandboxing de servicios systemd con drop-ins (sshd, fail2ban, firewalld, NetworkManager, security-monitor)
- `hardening-cuentas.sh` - Seguridad de cuentas: políticas de contraseñas (login.defs), faillock, cuentas sin contraseña, UID=0 extra, shells de sistema, cuentas inactivas
- `proteger-red-avanzado.sh` - Red avanzada: Suricata IDS, DNS over TLS (systemd-resolved), WireGuard VPN (plantilla), arpwatch + protección ARP
- `automatizar-seguridad.sh` - Automatización: cron jobs (AIDE, parches de seguridad, lynis, rkhunter, logrotate, digest diario), timer systemd de notificaciones
- `sandbox-aplicaciones.sh` - Sandboxing de aplicaciones: Firejail (perfiles Firefox, Thunderbird, LibreOffice, Dolphin, firecfg), bubblewrap
- `auditoria-externa.sh` - Auditoría de reconocimiento (MITRE TA0043): puertos expuestos, banners, fingerprinting OS, DNS, cabeceras HTTP, SNMP, consulta Shodan/Censys, metadatos web, defensas anti-escaneo, certificados SSL/TLS, script periódico
- `inteligencia-amenazas.sh` - Inteligencia de amenazas (MITRE M1019/TA0042): feeds de IoC (Blocklist.de, Feodo Tracker, ET, Spamhaus DROP/EDROP, Tor Exit Nodes, CI Army, SSLBL, URLhaus), integración firewall/ipset (vía lib/securizar-firewall.sh), reglas Suricata IoC, herramienta ioc-lookup.sh, actualización diaria automática

### Scripts de mitigaciones MITRE ATT&CK (12)
- `mitigar-acceso-inicial.sh` - Mitigación acceso inicial (MITRE TA0001): SSH hardening avanzado (T1133), anti-exploit web (T1190), control cuentas válidas (T1078), anti-phishing (T1566), anti drive-by (T1189), cadena de suministro GPG (T1195), USBGuard/DMA (T1200)
- `mitigar-ejecucion.sh` - Mitigación ejecución (MITRE TA0002): AppArmor perfiles restrictivos (T1059/M1038), bash restringido a grupo shell-users (T1059.004/M1038), noexec en /tmp /var/tmp /dev/shm (T1204/M1038), restricción LD_PRELOAD/LD_LIBRARY_PATH con profile.d y auditoría (T1129/M1044), intérpretes (python,perl,ruby) restringidos a grupo interp-users (T1059/M1038), script monitor-ejecucion.sh, verificación de controles existentes (sudo/requiretty, cron.allow, ASLR/kptr_restrict, servicios)
- `mitigar-persistencia.sh` - Mitigación persistencia (MITRE TA0003): auditoría cron/timers (T1053), servicios systemd (T1543), autostart/login scripts (T1547/T1037), detección cuentas (T1136), integridad autenticación (T1556), hijack PATH/LD_PRELOAD (T1574), detección periódica
- `mitigar-escalada.sh` - Mitigación escalada (MITRE TA0004): auditoría SUID/SGID (T1548), capabilities (T1134), hardening sudo (T1078), kernel anti-privesc sysctl (T1068), anti-inyección ptrace (T1055), cron como privesc (T1053), world-writable (T1548), detección periódica
- `mitigar-impacto.sh` - Mitigación impacto (MITRE TA0040): backups offsite automáticos rsync (T1486/T1561/M1053), ClamAV anti-ransomware con firmas YARA y detección extensiones (T1486/M1049), protección snapshots/backups con checksums e integridad (T1490/M1053), monitoreo de actividad de impacto con reglas auditd (T1485/T1486/T1489)
- `mitigar-evasion.sh` - Mitigación evasión de defensas (MITRE TA0005): protección de logs append-only y auditd (T1070), protección historial de comandos (T1070.003), detección masquerading con verificación de paquetes e integridad de binarios (T1036), watchdog de servicios de seguridad con timer systemd (T1562/T1562.001/T1562.004), detección de rootkits rkhunter y verificación manual (T1014), restricción LOLBins a grupo security-tools (T1218), detección de artefactos ocultos y directorios engañosos (T1564/T1564.001), detección de scripts ofuscados base64/eval/hex (T1027/T1140)
- `mitigar-credenciales.sh` - Mitigación acceso a credenciales (MITRE TA0006): protección contra credential dumping ptrace/hidepid/permisos (T1003/T1003.007/T1003.008), protección fuerza bruta faillock y pwquality (T1110/T1110.001/T1110.003), protección MITM arpwatch y ARP estático (T1557), escaneo de credenciales expuestas en archivos/historial/claves SSH (T1552/T1552.001/T1552.003/T1552.004), detección de modo promiscuo y sniffing (T1040), detección de keyloggers input/xinput/strace (T1056.001)
- `mitigar-descubrimiento.sh` - Mitigación descubrimiento (MITRE TA0007): detección port scanning con firewall rate-limiting y auditd (T1046), restricción enumeración procesos hidepid (T1057), reducción información del sistema kptr_restrict/banners (T1082), monitoreo reconocimiento de red y conexiones (T1016/T1049), restricción enumeración cuentas who/w/last (T1087/T1069), monitoreo descubrimiento de software (T1518)
- `mitigar-movimiento-lateral.sh` - Mitigación movimiento lateral (MITRE TA0008): hardening SSH anti-forwarding/tunneling (T1021/T1021.004), desactivación RDP/VNC (T1021.001/T1021.005), hardening Samba firma obligatoria sin SMBv1 (T1021.002), protección SSH agent hijacking (T1563.001), protección contenido compartido noexec/ClamAV (T1080), segmentación de red host-based con firewall (M1030), detección de movimiento lateral y herramientas (TA0008), auditoría herramientas deployment (T1072)
- `mitigar-recoleccion.sh` - Mitigación recolección (MITRE TA0009): protección datos locales permisos estrictos y auditd (T1005), monitoreo acceso shares de red (T1039), control medios extraíbles USBGuard y udisks2 (T1025), detección data staging archivos comprimidos y directorios ocultos (T1074/T1074.001), restricción captura pantalla/video/audio con udev y auditd (T1113/T1125/T1123), detección recolección automatizada procesos y búsquedas masivas (T1119), auditoría herramientas de compresión (T1560/T1560.001)
- `mitigar-exfiltracion.sh` - Mitigación exfiltración (MITRE TA0010): monitoreo tráfico saliente con firewall y detección DNS tunneling/cloud/ICMP (T1041/T1048), bloqueo dominios de exfiltración en /etc/hosts (T1567/T1567.002), detección DNS tunneling subdominios largos y queries TXT (T1048.003), control escritura USB con udev y auditd (T1052), limitación ancho de banda saliente con tc (T1030), monitoreo volumen transferencias con timer systemd (T1030), auditoría herramientas de transferencia curl/wget/scp/rclone/aws (T1041/T1567)
- `mitigar-comando-control.sh` - Mitigación comando y control (MITRE TA0011): bloqueo puertos C2 conocidos en firewall (T1571), reglas Suricata para Cobalt Strike/Meterpreter/Sliver (T1071.001), detección beaconing HTTPS y conexiones sin rDNS (T1071), auditoría descarga herramientas y noexec en /tmp (T1105), detección proxies/túneles SSH/SOCKS/proxychains (T1090/T1090.001/T1090.002/T1572), detección DGA por heurísticas de entropía en dominios (T1568), script consolidado detectar-c2-completo.sh (TA0011), auditoría herramientas C2 y proxies (T1090/T1572)

### Scripts de operaciones de seguridad (6)
- `respuesta-incidentes.sh` - Respuesta a incidentes: toolkit forense de datos volátiles (ir-recolectar-forense.sh con 15 categorías de datos y cadena de custodia), playbooks automáticos de contención (pb-cuenta-comprometida.sh T1078/T1110, pb-malware-activo.sh T1486/T1059, pb-c2-exfiltracion.sh TA0011/TA0010, pb-movimiento-lateral.sh TA0008) con dispatcher (ir-responder.sh), generador de timeline de ataque multi-fuente con mapeo MITRE (ir-timeline.sh), aislamiento de red de emergencia (ir-aislar-red.sh/ir-restaurar-red.sh), guía de recuperación post-incidente (ir-recuperacion.sh)
- `monitorizar-continuo.sh` - Monitorización continua: dashboard consolidado de estado de seguridad (security-dashboard.sh con servicios, scripts, timers, alertas, integridad), correlación de alertas multi-fuente con 5 patrones de ataque (correlacionar-alertas.sh: brute force→acceso, port scan→conexión, IDS→C2, multi-fuente, cadena de ataque), baseline de comportamiento del sistema (security-baseline.sh crear/verificar: puertos, servicios, usuarios, SUID, destinos, crontabs), health check de controles de seguridad (security-healthcheck.sh con cron diario), digest periódico de seguridad (security-digest.sh con timer systemd 06:00)
- `reportar-seguridad.sh` - Reportes de seguridad: reporte de cobertura MITRE ATT&CK con evaluación real por técnica (reporte-mitre.sh), exportación ATT&CK Navigator JSON layer para visualización (exportar-navigator.sh), reporte de cumplimiento de controles por categoría AUTH/NET/KERN/AUDIT/AV/MON/IR (reporte-cumplimiento.sh), inventario de activos de seguridad scripts/reglas/timers/cron (inventario-seguridad.sh), resumen ejecutivo de auditoría con score de postura (resumen-ejecutivo.sh)
- `cazar-amenazas.sh` - Caza de amenazas y UEBA: baseline de comportamiento de usuarios por métricas (ueba-crear-baseline.sh: horarios login, IPs origen, comandos, archivos, sudo) con detección de anomalías (ueba-detectar-anomalias.sh cron diario), playbooks de hunting por hipótesis (cazar-amenazas.sh: 5 hipótesis - persistencia oculta, LOLBins, movimiento lateral silencioso, exfiltración lenta, C2 encubierto), detección persistencia avanzada T1098 (detectar-persistencia-avanzada.sh: authorized_keys, passwd/shadow, kernel modules, shell init files con timer 15min), búsqueda retrospectiva en logs (buscar-retrospectivo.sh: por IP/usuario/dominio/hash/comando/archivo), detección estadística de anomalías de red (detectar-anomalias-red.sh: beaconing, tráfico asimétrico, puertos C2, HTTPS sin rDNS con cron diario)
- `automatizar-respuesta.sh` - Automatización de respuesta SOAR ligero: motor de respuesta automática (soar-responder.sh: procesa brute force SSH, port scan, alertas Suricata, anomalías UEBA, cambios de persistencia, coincidencias IoC con acciones bloquear IP/cuenta/preservar evidencia), procesamiento automático con timer systemd cada 10min, gestión de bloqueos (soar-gestionar-bloqueos.sh: listar, whitelist, estadísticas, limpiar), notificaciones consolidadas por severidad (soar-notificar.sh: CRITICAL/HIGH/MEDIUM/LOW), configuración de reglas de respuesta (/etc/security/soar-rules.conf)
- `validar-controles.sh` - Validación de controles Purple Team: validador de autenticación (validar-autenticacion.sh: 15 tests de políticas contraseñas, faillock, SSH, cuentas, MFA), validador de red (validar-red.sh: 15 tests firewall, IDS/Suricata, DNS seguro, anti-exfiltración, portscan), validador de endpoint (validar-endpoint.sh: 21 tests kernel sysctl, ejecución noexec/AppArmor, integridad AIDE, auditd, ClamAV, sandboxing), simulador seguro de técnicas ATT&CK (simular-ataques.sh: 12 simulaciones no destructivas T1053/T1059/T1070/T1036/T1564/T1027/T1548/T1046/T1071/T1003/T1105/T1562), reporte consolidado de validación con scoring global (reporte-validacion.sh: 60% controles + 40% detección, validación semanal automática)

## Arquitectura de securizar-menu.sh

### Delegación de módulos
- 33 scripts seguros se delegan directamente con `bash script.sh`
- 2 scripts peligrosos (extremo, paranoico) se reimplementan inline con secciones eliminadas:
  - **hardening-extremo.sh**: eliminadas secciones 1 (deshabilita sshd), 2 (firewall DROP ultra-restrictivo), 10 (chattr +i)
  - **hardening-paranoico.sh**: eliminadas secciones 4 (TMOUT=900 readonly), 5 (modifica /etc/pam.d/su)

### Navegación jerárquica (sub-menús)
- **Menú principal**: muestra 4 categorías con indicadores de progreso (dots ●○), acciones globales, y acceso directo por número
  - `b` → sub-menú Hardening Base (módulos 1-10)
  - `p` → sub-menú Securización Proactiva (módulos 11-18)
  - `m` → sub-menú Mitigaciones MITRE ATT&CK (módulos 19-30)
  - `o` → sub-menú Operaciones de Seguridad (módulos 31-36)
  - `a` → aplicar todos los 36 módulos secuencialmente
  - `v` → verificación proactiva (43 checks)
  - `1-36` → acceso directo a cualquier módulo por número
  - `?` → ayuda con atajos de teclado
  - `q` → salir con resumen de sesión
- **Sub-menús**: cada categoría muestra sus módulos con estado (✓ completado, ○ pendiente, ! archivo faltante), tags SEGURO donde aplica, y descripción breve. Opciones: número de módulo, `t` ejecutar todos en categoría, `b` volver, `q` salir.
- **Breadcrumbs**: navegación visual (`Securizar ❯ Hardening Base`)

### Registro de módulos (metadata)
- Arrays `MOD_NAMES`, `MOD_DESCS`, `MOD_FUNCS`, `MOD_FILES`, `MOD_TAGS` con 36 entradas
- Usados por sub-menús, `_show_module_entry()`, `_exec_module()`, `_run_category()` y `aplicar_todo_seguro()`
- Módulos 19-30 = Mitigaciones MITRE ATT&CK (TA0001, TA0002, TA0003, TA0004, TA0040, TA0005, TA0006, TA0007, TA0008, TA0009, TA0010, TA0011)
- Módulos 31-36 = Operaciones de Seguridad (IR, Monitorización, Reportes, Threat Hunting, SOAR, Purple Team)

### Session tracking
- `MOD_RUN` (associative array): rastrea qué módulos se han ejecutado en la sesión actual
- `SESSION_START`: timestamp de inicio para calcular duración al salir
- `_exit_securizar()`: muestra resumen de sesión (módulos ejecutados, tiempo, ruta del log)

### Funciones UI
- `_draw_header()` - ASCII art SECURIZAR con separador `━`
- `_draw_header_compact()` - Header compacto para sub-menús
- `_draw_sysinfo()` - Box con hostname, kernel, user, uptime, módulos ejecutados (esquinas redondeadas ╭╮╰╯)
- `_draw_footer()` - Protecciones con checkmarks `✓ sin PAM  ✓ sin TMOUT  ✓ sin lockout  ✓ sshd activo`
- `_breadcrumb()` - Ruta de navegación
- `_pause()` - "Presiona Enter para continuar"
- `_mod_icon()` - Icono de estado del módulo (✓/○/!)
- `_show_module_entry()` - Línea formateada de módulo para sub-menú
- `_cat_dots()` - Indicador de progreso por categoría (●●●○○○)
- `_exec_module()` - Wrapper de ejecución con header, tracking y pausa
- `_run_category()` - Ejecuta todos los módulos de un rango con progreso
- `_show_help()` - Pantalla de ayuda con atajos de teclado
- `_progress_bar()` - Barra de progreso con porcentaje

### Verificación proactiva (43 checks)
Audita: kernel, servicios, firewall, red, permisos, PAM intacto, sin TMOUT, acceso SSH, sudo, sin inmutabilidad, módulos bloqueados, herramientas, scripts de monitoreo, parámetros de arranque, sandboxing systemd, cuentas, red avanzada, automatización, sandboxing de apps, exposición externa (reconocimiento), MFA SSH (T1133), ClamAV antimalware (T1566), OpenSCAP auditoría (T1195), inteligencia de amenazas IoC (M1019), acceso inicial (TA0001), ejecución (TA0002), persistencia (TA0003), escalada de privilegios (TA0004), impacto (TA0040: backups offsite, ClamAV anti-ransomware, protección snapshots, monitoreo impacto), evasión de defensas (TA0005: protección logs, masquerading, watchdog servicios), acceso a credenciales (TA0006: credential dumping, faillock, credenciales expuestas), descubrimiento (TA0007: portscan, auditoría reconocimiento), movimiento lateral (TA0008: SSH anti-lateral, detección lateral), recolección (TA0009: auditoría recolección, data staging), exfiltración (TA0010: detección exfiltración, DNS tunneling), comando y control (TA0011: beaconing, proxy/tunneling, auditoría C2), respuesta a incidentes (toolkit forense, playbooks, timeline), monitorización continua (dashboard, correlación, health check), reportes de seguridad (MITRE ATT&CK, Navigator, cumplimiento), caza de amenazas (UEBA baseline, hunting playbooks, T1098 persistencia avanzada), automatización de respuesta (SOAR motor, gestión bloqueos, notificaciones), validación de controles (simulador ATT&CK, validadores auth/red/endpoint, reporte Purple Team)

## Cobertura MITRE ATT&CK

El proyecto cubre las 14 tácticas del framework MITRE ATT&CK enterprise:

| Táctica | ID | Módulo | Técnicas principales |
|---------|-----|--------|---------------------|
| Reconnaissance | TA0043 | auditoria-externa.sh | T1595, T1593, T1596, T1592, T1590 |
| Resource Development | TA0042 | inteligencia-amenazas.sh | M1019, IoC feeds |
| Initial Access | TA0001 | mitigar-acceso-inicial.sh | T1133, T1190, T1078, T1566, T1189, T1195, T1200 |
| Execution | TA0002 | mitigar-ejecucion.sh | T1059, T1204, T1129, T1203 |
| Persistence | TA0003 | mitigar-persistencia.sh | T1053, T1543, T1547, T1136, T1556, T1574 |
| Privilege Escalation | TA0004 | mitigar-escalada.sh | T1548, T1068, T1134, T1055, T1078 |
| Defense Evasion | TA0005 | mitigar-evasion.sh | T1070, T1036, T1562, T1014, T1218, T1564, T1027 |
| Credential Access | TA0006 | mitigar-credenciales.sh | T1003, T1110, T1557, T1552, T1040, T1056 |
| Discovery | TA0007 | mitigar-descubrimiento.sh | T1046, T1057, T1082, T1016, T1049, T1087 |
| Lateral Movement | TA0008 | mitigar-movimiento-lateral.sh | T1021, T1563, T1080, T1072 |
| Collection | TA0009 | mitigar-recoleccion.sh | T1005, T1039, T1025, T1074, T1113, T1119 |
| Exfiltration | TA0010 | mitigar-exfiltracion.sh | T1041, T1048, T1567, T1052, T1030 |
| Command and Control | TA0011 | mitigar-comando-control.sh | T1071, T1105, T1090, T1572, T1571, T1568 |
| Impact | TA0040 | mitigar-impacto.sh | T1486, T1490, T1561, T1485 |

### Scripts de detección creados por módulos MITRE
- `/usr/local/bin/detectar-masquerading.sh` - T1036 binarios falsos (cron diario)
- `/usr/local/bin/detectar-rootkits.sh` - T1014 rootkits rkhunter + manual (cron semanal)
- `/usr/local/bin/detectar-ocultos.sh` - T1564 artefactos ocultos (cron diario)
- `/usr/local/bin/detectar-ofuscados.sh` - T1027 scripts ofuscados (cron diario)
- `/usr/local/bin/watchdog-seguridad.sh` - T1562 watchdog servicios (timer 5min)
- `/usr/local/bin/monitorear-bruteforce.sh` - T1110 fuerza bruta SSH (cron diario)
- `/usr/local/bin/buscar-credenciales.sh` - T1552 credenciales expuestas (cron semanal)
- `/usr/local/bin/detectar-promiscuo.sh` - T1040 modo promiscuo (timer 10min)
- `/usr/local/bin/detectar-keylogger.sh` - T1056.001 keyloggers (cron diario)
- `/usr/local/bin/detectar-portscan.sh` - T1046 port scanning (cron diario)
- `/usr/local/bin/detectar-reconocimiento.sh` - T1016/T1049 reconocimiento red (cron diario)
- `/usr/local/bin/detectar-lateral.sh` - TA0008 movimiento lateral (cron diario)
- `/usr/local/bin/segmentacion-red.sh` - M1030 verificación segmentación
- `/usr/local/bin/detectar-staging.sh` - T1074 data staging (cron diario)
- `/usr/local/bin/detectar-recoleccion.sh` - T1119 recolección automatizada (cron diario)
- `/usr/local/bin/detectar-exfiltracion.sh` - TA0010 exfiltración (cron diario)
- `/usr/local/bin/detectar-dns-tunnel.sh` - T1048.003 DNS tunneling (cron diario)
- `/usr/local/bin/monitorear-transferencias.sh` - T1030 volumen transferencias (timer 1h)
- `/usr/local/bin/detectar-beaconing.sh` - T1071 C2 beaconing (cron diario)
- `/usr/local/bin/detectar-tunneling.sh` - T1090/T1572 proxy/tunneling (cron diario)
- `/usr/local/bin/detectar-dga.sh` - T1568 DGA (cron diario)
- `/usr/local/bin/detectar-tool-transfer.sh` - T1105 tool transfer (cron diario)
- `/usr/local/bin/detectar-c2-completo.sh` - TA0011 detección C2 consolidada

### Herramientas de respuesta a incidentes
- `/usr/local/bin/ir-recolectar-forense.sh` - Recolección forense de 15 categorías de datos volátiles con cadena de custodia
- `/usr/local/bin/ir-responder.sh` - Dispatcher de playbooks de contención
- `/usr/local/lib/incident-response/playbooks/pb-cuenta-comprometida.sh` - Playbook compromiso de cuenta (T1078/T1110)
- `/usr/local/lib/incident-response/playbooks/pb-malware-activo.sh` - Playbook malware/ransomware (T1486/T1059)
- `/usr/local/lib/incident-response/playbooks/pb-c2-exfiltracion.sh` - Playbook C2/exfiltración (TA0011/TA0010)
- `/usr/local/lib/incident-response/playbooks/pb-movimiento-lateral.sh` - Playbook movimiento lateral (TA0008)
- `/usr/local/bin/ir-timeline.sh` - Generador de timeline de ataque multi-fuente con mapeo MITRE
- `/usr/local/bin/ir-aislar-red.sh` - Aislamiento de red de emergencia (mantiene SSH operador)
- `/usr/local/bin/ir-restaurar-red.sh` - Restauración de red post-aislamiento
- `/usr/local/bin/ir-recuperacion.sh` - Guía de recuperación post-incidente con checks

### Herramientas de monitorización continua
- `/usr/local/bin/security-dashboard.sh` - Dashboard consolidado de estado (servicios, detección, timers, alertas, integridad)
- `/usr/local/bin/correlacionar-alertas.sh` - Correlación multi-fuente (5 patrones: brute force→acceso, portscan→conexión, IDS→C2, multi-fuente, cadena de ataque)
- `/usr/local/bin/security-baseline.sh` - Baseline de comportamiento (crear/verificar: puertos, servicios, usuarios, SUID, destinos, crontabs)
- `/usr/local/bin/security-healthcheck.sh` - Health check de controles (cron diario con alerta)
- `/usr/local/bin/security-digest.sh` - Digest periódico de seguridad (timer systemd 06:00)

### Herramientas de reporte
- `/usr/local/bin/reporte-mitre.sh` - Reporte de cobertura MITRE ATT&CK con evaluación real por técnica
- `/usr/local/bin/exportar-navigator.sh` - Exportación ATT&CK Navigator JSON layer para visualización web
- `/usr/local/bin/reporte-cumplimiento.sh` - Reporte de cumplimiento por categoría (AUTH/NET/KERN/AUDIT/AV/MON/IR)
- `/usr/local/bin/inventario-seguridad.sh` - Inventario completo de activos de seguridad
- `/usr/local/bin/resumen-ejecutivo.sh` - Resumen ejecutivo de postura de seguridad con score

### Herramientas de caza de amenazas (threat hunting)
- `/usr/local/bin/ueba-crear-baseline.sh` - Crear baseline de comportamiento por usuario (login hours, IPs, commands, files, sudo)
- `/usr/local/bin/ueba-detectar-anomalias.sh` - Detectar anomalías contra baseline UEBA (cron diario)
- `/usr/local/bin/cazar-amenazas.sh` - Playbooks de hunting por hipótesis (5: persistencia oculta, LOLBins, lateral silencioso, exfil lenta, C2 encubierto)
- `/usr/local/bin/detectar-persistencia-avanzada.sh` - Detección T1098 authorized_keys, passwd, kernel modules, shell init (timer 15min)
- `/usr/local/bin/buscar-retrospectivo.sh` - Búsqueda retrospectiva en logs por IP/usuario/dominio/hash/comando/archivo
- `/usr/local/bin/detectar-anomalias-red.sh` - Detección estadística anomalías de red: beaconing, asimétrico, C2, HTTPS sin rDNS (cron diario)

### Herramientas de respuesta automática (SOAR)
- `/usr/local/bin/soar-responder.sh` - Motor SOAR: procesa 6 tipos de eventos, bloqueo IP/cuenta, preservar evidencia (timer 10min)
- `/usr/local/bin/soar-gestionar-bloqueos.sh` - Gestión de IPs bloqueadas: listar, whitelist, estadísticas, limpiar
- `/usr/local/bin/soar-notificar.sh` - Notificaciones consolidadas por severidad (CRITICAL/HIGH/MEDIUM/LOW)
- `/etc/security/soar-rules.conf` - Configuración de reglas trigger→acción del SOAR

### Herramientas de validación Purple Team
- `/usr/local/bin/validar-autenticacion.sh` - Validar 15 controles de autenticación (passwords, faillock, SSH, cuentas, MFA)
- `/usr/local/bin/validar-red.sh` - Validar 15 controles de red (firewall, IDS, DNS, exfiltración, portscan)
- `/usr/local/bin/validar-endpoint.sh` - Validar 21 controles de endpoint (kernel, ejecución, integridad, auditd, AV, sandbox)
- `/usr/local/bin/simular-ataques.sh` - Simulador seguro de 12 técnicas ATT&CK (T1053, T1059, T1070, T1036, T1564, T1027, T1548, T1046, T1071, T1003, T1105, T1562)
- `/usr/local/bin/reporte-validacion.sh` - Reporte consolidado con scoring global (60% controles + 40% detección)
- `/etc/cron.weekly/purple-team-validation` - Validación semanal automática

### Reglas auditd creadas por módulos MITRE
- `/etc/audit/rules.d/60-log-protection.rules` - T1070 protección de logs
- `/etc/audit/rules.d/61-defense-evasion.rules` - T1562/T1218 herramientas de seguridad y LOLBins
- `/etc/audit/rules.d/62-credential-access.rules` - T1003/T1040 credenciales y sniffing
- `/etc/audit/rules.d/63-discovery.rules` - T1046/T1057/T1082/T1016/T1087/T1518 descubrimiento
- `/etc/audit/rules.d/64-lateral-movement.rules` - T1021/T1563/T1072 movimiento lateral
- `/etc/audit/rules.d/65-collection.rules` - T1005/T1039/T1025/T1074/T1113/T1560 recolección
- `/etc/audit/rules.d/66-exfiltration.rules` - T1041/T1048/T1567/T1052 exfiltración
- `/etc/audit/rules.d/67-command-control.rules` - T1105/T1090/T1572 comando y control

### Datos de operaciones
- `/var/lib/incident-response/` - Directorio de datos de incidentes (forense, playbooks, timelines)
- `/var/lib/security-monitoring/` - Directorio de monitorización (correlaciones, baselines, healthchecks, digests)
- `/var/lib/security-reports/` - Directorio de reportes generados (MITRE, cumplimiento, inventario, ejecutivo, Navigator JSON)
- `/var/lib/threat-hunting/` - Directorio de caza de amenazas (baselines UEBA, anomalías, resultados de hunting, persistencia T1098)
- `/var/lib/soar/` - Directorio SOAR (queue de eventos, acciones ejecutadas, IPs bloqueadas, logs de respuesta)
- `/var/lib/purple-team/` - Directorio Purple Team (resultados de validación, evidencia de simulaciones, reportes consolidados)

## Convenciones

- **Idioma**: Español para mensajes de usuario, comentarios y documentación
- **Shell**: Bash con `set -e` (scripts individuales) o `set -euo pipefail` (menú)
- **Ejecución**: Todos los scripts requieren root (`sudo bash script.sh`)
- **Interactividad**: Cada sección pregunta al usuario antes de aplicar cambios con `ask()` (prompt `❯`, respuesta s/N)
- **Backups**: `init_backup "nombre"` crea `$SECURIZAR_BACKUP_BASE/nombre-TIMESTAMP/` (por defecto `/root/`)
- **Logging**: Funciones `log_info` (✓), `log_warn` (⚠), `log_error` (✗) con iconos Unicode. `log_section()` usa separadores `══`. Todo se escribe a `$LOGFILE` vía `tee -a`.
- **Target OS**: openSUSE, Debian/Ubuntu, RHEL/Fedora/CentOS, Arch Linux (detección automática via `lib/securizar-distro.sh`)
- **Colores y utilidades**: Provistos por `lib/securizar-common.sh`, no se definen en cada script
- **Paquetes**: Usar `pkg_install`, `pkg_is_installed`, etc. de `lib/securizar-pkg.sh`. Nunca llamar a zypper/apt/dnf/pacman directamente
- **Firewall**: Usar `fw_add_service`, `fw_add_rich_rule`, etc. de `lib/securizar-firewall.sh`. Nunca llamar a firewall-cmd/ufw/nft directamente
- **Rutas GRUB/SCAP**: Usar variables `$GRUB_CFG`, `$SCAP_DS_PATH`, etc. de `lib/securizar-paths.sh`. Nunca hardcodear rutas específicas de una distro

## Restricciones

- **NO modificar PAM**: No securizar, endurecer ni alterar la configuración de PAM (Pluggable Authentication Modules). Dejar `/etc/pam.d/su` y demás archivos PAM tal como están en el sistema.
- **NO limitar recursos**: No establecer `TMOUT=900; readonly TMOUT` ni otros timeouts que limiten la sesión del usuario.
- **NO bloquear al usuario**: No deshabilitar/enmascarar sshd, no aplicar firewall DROP ultra-restrictivo sin servicios, no usar `chattr +i` en archivos críticos (passwd, shadow, sudoers).
- **NO ejecutar directamente** `hardening-extremo.sh` ni `hardening-paranoico.sh`: usar siempre `securizar-menu.sh` que aplica las versiones seguras.

## Reglas al editar/crear scripts

### Estructura obligatoria de cada script
```bash
#!/bin/bash
# Descripción del script

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "nombre-modulo"

# ... resto del script usando funciones de la biblioteca ...
```

### Reglas generales
- Mantener la estructura interactiva: nunca aplicar cambios sin confirmación del usuario
- Siempre usar `init_backup` antes de modificar archivos del sistema
- Usar las funciones de logging de la biblioteca (`log_info`, `log_warn`, `log_error`, `log_section`)
- Usar `require_root` en lugar de verificar `$EUID` manualmente
- Cada sección debe ser independiente y autocontenida
- Documentar con comentarios qué hace cada bloque de hardening

### Multi-distro
- **Nunca** llamar directamente a gestores de paquetes (`zypper`, `apt`, `dnf`, `pacman`). Usar `pkg_install`, `pkg_remove`, `pkg_is_installed`, etc.
- **Nunca** llamar directamente a `firewall-cmd`, `ufw` o `nft`. Usar `fw_add_service`, `fw_add_rich_rule`, `fw_reload`, etc.
- **Nunca** hardcodear rutas GRUB (`/boot/grub2/`) ni SCAP. Usar `$GRUB_CFG`, `$GRUB_CFG_DIR`, `$SCAP_DS_PATH`, etc.
- Para lógica condicional por distro, usar `$DISTRO_FAMILY` (valores: `suse`, `debian`, `rhel`, `arch`)
- Para nombres de paquetes con diferencias entre distros, añadir entrada en `lib/securizar-pkg-map.sh` y usar `pkg_resolve_name`
- Los heredocs que generan scripts standalone (cron jobs, scripts de respuesta) usan detección con `command -v` para llamar al gestor de paquetes/firewall correcto en runtime

### Registro de módulos
- Nuevos módulos deben registrarse en los arrays `MOD_NAMES`, `MOD_DESCS`, `MOD_FUNCS`, `MOD_FILES`, `MOD_TAGS` y añadirse al sub-menú correspondiente. Actualizar todos los contadores (total módulos, rango de acceso directo, categorías de verificación)

### Convenciones visuales y de instalación
- Mantener la coherencia visual: usar iconos ✓/⚠/✗, prompt ❯, separadores ══, esquinas redondeadas ╭╮╰╯
- Los scripts de detección se instalan en `/usr/local/bin/` con permisos 700
- Los cron jobs se crean en `/etc/cron.daily/` o `/etc/cron.weekly/` con permisos 700
- Los timers systemd se usan para frecuencias menores a 1 día (5min, 10min, 1h)
- Las reglas auditd se crean en `/etc/audit/rules.d/` con numeración 6X para evitar conflictos
- Cada módulo MITRE incluye sección de RESUMEN al final con estado OK/-- por técnica
- Las herramientas operativas (IR, monitorización, reportes) guardan datos en `/var/lib/`
