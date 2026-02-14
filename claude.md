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
| `lib/securizar-msf.sh` | Integración con Metasploit Framework para validación ofensiva |
| `lib/ciberint-lib.sh` | Biblioteca de ciberinteligencia: enriquecimiento IoC, consultas OSINT, surface analysis |

Configuración opcional en `securizar.conf` (variables: `SECURIZAR_BACKUP_BASE`, `SECURIZAR_FW_BACKEND`, `SECURIZAR_LOG_TO_FILE`).

#### Distribuciones soportadas

| Familia | Distribuciones | Gestor de paquetes | Firewall por defecto |
|---------|---------------|-------------------|---------------------|
| `suse` | openSUSE Leap/Tumbleweed, SLES | zypper | firewalld |
| `debian` | Debian, Ubuntu, Linux Mint | apt | ufw |
| `rhel` | RHEL, Fedora, CentOS, Rocky, Alma | dnf | firewalld |
| `arch` | Arch Linux, Manjaro, EndeavourOS | pacman | nftables/iptables |

### Menú orquestador
- `securizar-menu.sh` (~5500 líneas) - Menú interactivo con navegación por sub-menús que orquesta los 75 módulos con protecciones de seguridad. Reimplementa inline los scripts peligrosos (extremo y paranoico) eliminando secciones que causan lockout o violan restricciones. Incluye verificación proactiva de 84 checks ponderados. Navegación jerárquica: menú principal con 10 categorías + acciones globales + acceso directo por número (1-75).

### Scripts de hardening base (9) — categoría `b`
1. `hardening-opensuse.sh` - Hardening base del sistema (kernel, FTP, servicios, firewall, SSH, contraseñas, permisos, fail2ban, actualizaciones, auditd, MFA SSH, ClamAV, OpenSCAP)
2. `hardening-seguro.sh` - Nivel seguro de hardening (archivos, procesos, AIDE, SSH keys)
3. `hardening-final.sh` - Hardening final consolidado (auditd, sysctl, firewall, updates)
4. `hardening-externo.sh` - Hardening de servicios externos (banners, honeypot, DNS, VPN)
5. `hardening-extremo.sh` - Nivel extremo SEGURO (USB, kernel, red — sin lockout, inline en menú)
6. `hardening-paranoico.sh` - Nivel paranoico SEGURO (core dumps, GRUB, audit — sin PAM, inline en menú)
7. `contramedidas-mesh.sh` - Contramedidas de red mesh (WiFi, Bluetooth, IoT)
8. `proteger-privacidad.sh` - Protección de privacidad (VNC, cámara, DNS leaks, Tor)
9. `aplicar-banner-total.sh` - Aplicación de banners (MOTD, issue, SSH, GDM, Firefox)

### Scripts de securización proactiva (8) — categoría `p`
10. `hardening-kernel-boot.sh` - Parámetros de arranque del kernel (cmdline GRUB), verificación Secure Boot, módulos firmados, protección GRUB
11. `hardening-servicios-systemd.sh` - Sandboxing de servicios systemd con drop-ins (sshd, fail2ban, firewalld, NetworkManager, security-monitor)
12. `hardening-cuentas.sh` - Seguridad de cuentas: políticas de contraseñas (login.defs), faillock, cuentas sin contraseña, UID=0 extra, shells de sistema, cuentas inactivas
13. `proteger-red-avanzado.sh` - Red avanzada: Suricata IDS, DNS over TLS (systemd-resolved), WireGuard VPN (plantilla), arpwatch + protección ARP, sinkhole, baseline
14. `automatizar-seguridad.sh` - Automatización: cron jobs (AIDE, parches de seguridad, lynis, rkhunter, logrotate, digest diario), timer systemd de notificaciones
15. `sandbox-aplicaciones.sh` - Sandboxing de aplicaciones: Firejail (perfiles Firefox, Thunderbird, LibreOffice, Dolphin, firecfg), bubblewrap
16. `auditoria-externa.sh` - Auditoría de reconocimiento (MITRE TA0043): puertos expuestos, banners, fingerprinting OS, DNS, cabeceras HTTP, SNMP, consulta Shodan/Censys, metadatos web, defensas anti-escaneo, certificados SSL/TLS, script periódico
17. `inteligencia-amenazas.sh` - Inteligencia de amenazas (MITRE M1019/TA0042): feeds de IoC (Blocklist.de, Feodo Tracker, ET, Spamhaus DROP/EDROP, Tor Exit Nodes, CI Army, SSLBL, URLhaus), integración firewall/ipset, reglas Suricata IoC, herramienta ioc-lookup.sh, actualización diaria automática

### Scripts de mitigaciones MITRE ATT&CK (12) — categoría `m`
18. `mitigar-acceso-inicial.sh` - TA0001: SSH hardening avanzado (T1133), anti-exploit web (T1190), control cuentas válidas (T1078), anti-phishing (T1566), anti drive-by (T1189), cadena de suministro GPG (T1195), USBGuard/DMA (T1200)
19. `mitigar-ejecucion.sh` - TA0002: AppArmor perfiles restrictivos (T1059/M1038), bash restringido (T1059.004), noexec en /tmp /var/tmp /dev/shm (T1204), restricción LD_PRELOAD (T1129/M1044), intérpretes restringidos (T1059)
20. `mitigar-persistencia.sh` - TA0003: auditoría cron/timers (T1053), servicios systemd (T1543), autostart/login scripts (T1547/T1037), detección cuentas (T1136), integridad autenticación (T1556), hijack PATH/LD_PRELOAD (T1574)
21. `mitigar-escalada.sh` - TA0004: auditoría SUID/SGID (T1548), capabilities (T1134), hardening sudo (T1078), kernel anti-privesc sysctl (T1068), anti-inyección ptrace (T1055), cron como privesc (T1053)
22. `mitigar-impacto.sh` - TA0040: backups offsite automáticos rsync (T1486/T1561/M1053), ClamAV anti-ransomware con firmas YARA (T1486/M1049), protección snapshots/backups (T1490/M1053), monitoreo de actividad de impacto auditd (T1485/T1486/T1489)
23. `mitigar-evasion.sh` - TA0005: protección de logs append-only (T1070), historial de comandos (T1070.003), detección masquerading (T1036), watchdog servicios de seguridad (T1562), detección rootkits rkhunter (T1014), restricción LOLBins (T1218), artefactos ocultos (T1564), scripts ofuscados (T1027/T1140)
24. `mitigar-credenciales.sh` - TA0006: protección contra credential dumping ptrace/hidepid (T1003), fuerza bruta faillock/pwquality (T1110), protección MITM arpwatch (T1557), credenciales expuestas (T1552), detección sniffing (T1040), detección keyloggers (T1056.001)
25. `mitigar-descubrimiento.sh` - TA0007: detección port scanning firewall rate-limiting (T1046), restricción enumeración procesos hidepid (T1057), reducción información del sistema (T1082), monitoreo red/conexiones (T1016/T1049), restricción enumeración cuentas (T1087/T1069)
26. `mitigar-movimiento-lateral.sh` - TA0008: hardening SSH anti-forwarding/tunneling (T1021), desactivación RDP/VNC (T1021.001/T1021.005), hardening Samba (T1021.002), protección SSH agent hijacking (T1563.001), contenido compartido noexec/ClamAV (T1080), segmentación de red (M1030)
27. `mitigar-recoleccion.sh` - TA0009: protección datos locales (T1005), monitoreo shares de red (T1039), control medios extraíbles USBGuard (T1025), detección data staging (T1074), restricción captura pantalla/video/audio (T1113/T1125/T1123), detección recolección automatizada (T1119)
28. `mitigar-exfiltracion.sh` - TA0010: monitoreo tráfico saliente/DNS tunneling/cloud/ICMP (T1041/T1048), bloqueo dominios exfiltración (T1567), detección DNS tunneling (T1048.003), control USB (T1052), limitación ancho de banda tc (T1030)
29. `mitigar-comando-control.sh` - TA0011: bloqueo puertos C2 en firewall (T1571), reglas Suricata Cobalt Strike/Meterpreter/Sliver (T1071.001), detección beaconing HTTPS (T1071), auditoría descarga herramientas (T1105), detección proxies/túneles (T1090/T1572), detección DGA (T1568)

### Scripts de operaciones de seguridad (5) — categoría `o`
30. `monitorizar-continuo.sh` - Dashboard, correlación alertas, baseline, health check, digest
31. `reportar-seguridad.sh` - Reporte MITRE ATT&CK, Navigator JSON, cumplimiento, inventario, resumen ejecutivo
32. `cazar-amenazas.sh` - UEBA baseline/anomalías, hunting playbooks, detección T1098, anomalías de red
33. `automatizar-respuesta.sh` - SOAR ligero: motor respuesta automática, gestión bloqueos, notificaciones
34. `validar-controles.sh` - Purple Team: validadores auth/red/endpoint, simulador ATT&CK (12 técnicas), scoring

### Scripts de inteligencia (2) — categoría `i`
35. `ciberinteligencia.sh` - Ciberinteligencia proactiva: IoC enriquecimiento, red, DNS, superficie, integración SOAR
36. `proteger-contra-isp.sh` - Protección ISP: kill switch, DNS leak, ECH, DPI evasion, NTS

### Scripts de infraestructura y red (9) — categoría `n`
37. `hardening-criptografico.sh` - SSH, TLS, certificados, LUKS, NTS
43. `segmentacion-red-zt.sh` - Zonas, microsegmentación, Zero Trust
50. `seguridad-cloud.sh` - AWS, Azure, GCP, IAM, postura
51. `seguridad-ldap-ad.sh` - LDAP TLS, FreeIPA, sssd, Kerberos
54. `seguridad-wireless.sh` - WPA3, RADIUS, rogue AP, 802.1X
55. `seguridad-virtualizacion.sh` - KVM, QEMU, libvirt, VM aislamiento
57. `zero-trust-identity.sh` - IAP, device trust, autenticación continua
63. `seguridad-dns-avanzada.sh` - DNSSEC, DoH/DoT, sinkhole, RPZ
73. `integridad-arranque.sh` - Secure Boot, UEFI, GRUB2, dm-verity, IMA/EVM, TPM2

### Scripts de aplicaciones y servicios (8) — categoría `s`
38. `seguridad-contenedores.sh` - Docker, Podman, seccomp, K8s, CIS benchmarks
40. `seguridad-email.sh` - SPF, DKIM, DMARC, TLS, anti-relay
46. `seguridad-bases-datos.sh` - PostgreSQL, MySQL, Redis, MongoDB
48. `seguridad-web.sh` - WAF, ModSecurity, headers, TLS, DDoS
49. `seguridad-secrets.sh` - Vault, rotación, escaneo, SSH keys
60. `devsecops-hardening.sh` - CI/CD, SAST, DAST, containers, Git
61. `seguridad-api.sh` - Rate limit, JWT, mTLS, WAF API
62. `seguridad-iot.sh` - MQTT, CoAP, firmware, segmentación

### Scripts de protección y resiliencia (11) — categoría `r`
42. `seguridad-cadena-suministro.sh` - SBOM, CVEs, firmas, integridad
45. `kernel-livepatch.sh` - Livepatch, CVEs, exploits, módulos
47. `backup-recuperacion.sh` - 3-2-1, borg, restic, inmutable, DR
53. `tecnologia-engano.sh` - Honeypots, honeytokens, decoys, canary
56. `seguridad-fisica.sh` - USBGuard, BIOS, screen lock, TPM
58. `proteger-ransomware.sh` - Canary files, snapshots, whitelisting
59. `gestion-parches.sh` - CVE scan, auto-patch, SBOM, staging
66. `seguridad-runtime-kernel.sh` - LKRG, eBPF, Falco, lockdown, módulos
67. `hardening-memoria-procesos.sh` - ASLR, W^X, seccomp, cgroups, namespaces
71. `mac-selinux-apparmor.sh` - SELinux/AppArmor enforcing, políticas, confinamiento, MLS
72. `aislamiento-namespaces.sh` - User/PID/net/mount ns, rootless, cgroups v2, seccomp

### Scripts de detección y respuesta (9) — categoría `d`
41. `logging-centralizado.sh` - rsyslog TLS, SIEM, correlación, forense
44. `forense-avanzado.sh` - Memoria, disco, timeline, custodia
64. `auditoria-red-wireshark.sh` - Wireshark, tshark, capturas, anomalías
65. `auditoria-red-infraestructura.sh` - nmap, TLS/SSL, SNMP, baseline, drift
68. `respuesta-incidentes.sh` - Forense, custodia, IOCs, escalación, hunting, métricas
69. `edr-osquery.sh` - Osquery, Wazuh, threat queries, fleet, baseline
70. `gestion-vulnerabilidades.sh` - Trivy, grype, SCAP, CVSS/EPSS, drift, madurez
74. `acceso-privilegiado.sh` - Session recording, sudo granular, JIT, capabilities, breakglass
75. `caza-apt-hunting.sh` - YARA, memory hunting, beaconing, IOC sweep, playbooks

### Scripts de cumplimiento (2) — categoría `c`
39. `cumplimiento-cis.sh` - CIS Benchmark, NIST 800-53, scoring
52. `cumplimiento-normativo.sh` - PCI-DSS, HIPAA, GDPR, SOC2, ISO27001

### Otros scripts
- `deploy-dns-fix.sh` - Script de despliegue DNS: override global con NetworkManager, fuerza DNS a unbound (DoT + DNSSEC), override DNS de VPNs comerciales (ProtonVPN, Mullvad, etc.)

### Panel web (`panel/`)
- Panel Django para monitorización de tecnología de engaño (honeypots/decoys)
- `panel/dashboard/` - App Django con modelos, vistas, parsers, monitor, integración Europol
- `panel/templates/` - Templates HTML del dashboard
- `panel/manage.py` - Entry point Django
- `panel/db.sqlite3` - Base de datos SQLite

### Ficheros de configuración
- `securizar.conf` - Configuración principal (root-owned, 600)
- `99-securizar-hardening.conf` - Parámetros sysctl de hardening (IPv4/IPv6, TCP, ICMP)

## Arquitectura de securizar-menu.sh

### Delegación de módulos
- 73 scripts seguros se delegan directamente con `bash script.sh`
- 2 scripts peligrosos (extremo, paranoico) se reimplementan inline con secciones eliminadas:
  - **hardening-extremo.sh** (mod 5): eliminadas secciones 1 (deshabilita sshd), 2 (firewall DROP ultra-restrictivo), 10 (chattr +i)
  - **hardening-paranoico.sh** (mod 6): eliminadas secciones 4 (TMOUT=900 readonly), 5 (modifica /etc/pam.d/su)

### Navegación jerárquica (10 categorías)
- **Menú principal**: muestra 10 categorías con indicadores de progreso (dots ●○), acciones globales, y acceso directo por número
  - `b` → Hardening Base (módulos 1-9, consecutivos)
  - `p` → Securización Proactiva (módulos 10-17, consecutivos)
  - `m` → Mitigaciones MITRE ATT&CK (módulos 18-29, consecutivos)
  - `o` → Operaciones de Seguridad (módulos 30-34, consecutivos)
  - `i` → Inteligencia (módulos 35-36, consecutivos)
  - `n` → Infraestructura y Red (módulos 37,43,50,51,54,55,57,63,73 — no consecutivos)
  - `s` → Aplicaciones y Servicios (módulos 38,40,46,48,49,60,61,62 — no consecutivos)
  - `r` → Protección y Resiliencia (módulos 42,45,47,53,56,58,59,66,67,71,72 — no consecutivos)
  - `d` → Detección y Respuesta (módulos 41,44,64,65,68,69,70,74,75 — no consecutivos)
  - `c` → Cumplimiento (módulos 39,52 — no consecutivos)
  - `a` → aplicar todos los 75 módulos secuencialmente
  - `v` → verificación proactiva (84 checks)
  - `1-75` → acceso directo a cualquier módulo por número
  - `?` → ayuda con atajos de teclado
  - `q` → salir con resumen de sesión
- **Sub-menús**: cada categoría muestra sus módulos con estado (✓ completado, ○ pendiente, ! archivo faltante), tags SEGURO donde aplica, y descripción breve. Opciones: número de módulo, `t` ejecutar todos en categoría, `b` volver, `q` salir.
- **Breadcrumbs**: navegación visual (`Securizar ❯ Hardening Base`)
- **Sub-menús especiales**: módulos 53 (Deception), 64 (Wireshark), 65 (Auditoría infra) tienen sub-menús propios con dispatch por sección

### Registro de módulos (metadata)
- Arrays `MOD_NAMES`, `MOD_DESCS`, `MOD_FUNCS`, `MOD_FILES`, `MOD_TAGS` con 75 entradas
- Usados por sub-menús, `_show_module_entry()`, `_exec_module()`, `_run_category()` y `aplicar_todo_seguro()`
- `MOD_TAGS[5]="SEGURO"` y `MOD_TAGS[6]="SEGURO"` marcan los módulos extremo/paranoico como versiones seguras

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

### Verificación proactiva (84 checks)
Función `verificacion_proactiva()` — 84 checks ponderados con scoring:
- **Pesos**: CRITICAL=3, HIGH=2, MEDIUM=1
- **Categorías de checks** (por número): Kernel(1), Servicios seguridad(2), Serv. innecesarios(3), Firewall(4), Puertos/red(5), Permisos(6), PAM(7), TMOUT(8), SSH(9), Sudo(10), Inmutabilidad(11), Módulos kernel(12), Herramientas(13), Scripts monitoreo(14), Boot/Secure Boot(15), Sandbox systemd(16), Cuentas(17), Red avanzada(18), Automatización(19), Sandbox apps(20), Exposición externa(21), MFA SSH(22), ClamAV(23), OpenSCAP(24), IoC feeds(25), TA0001-TA0011(26-37), Monitorización(38), Reportes(39), Threat hunting(40), SOAR(41), Purple team(42), Ciberinteligencia(43), Validación MSF(44), Protección ISP(45), Criptografía(46), Contenedores(47), Cumplim. CIS(48), Email(49), Logging SIEM(50), Cadena suministro(51), Segmentación ZT(52), Forense(53), Livepatch(54), BBDD(55), Backup/DR(56), Web(57), Secretos(58), Cloud(59), LDAP/AD(60), Cumplim. normativo(61), Engaño(62), Wireless(63), Virtualización(64), Física(65), Zero Trust ID(66), Anti-ransomware(67), Parches(68), DevSecOps(69), APIs(70), IoT(71), DNS(72), Auditoría red(73), Auditoría infra(74), Runtime kernel(75), Memoria(76), Resp. incidentes(77), EDR Osquery(78), Vuln management(79), MAC SELinux(80), Namespaces(81), Boot integrity(82), Acceso privilegiado(83), APT hunting(84)

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
- `/usr/local/bin/security-dashboard.sh` - Dashboard consolidado de estado
- `/usr/local/bin/correlacionar-alertas.sh` - Correlación multi-fuente (5 patrones de ataque)
- `/usr/local/bin/security-baseline.sh` - Baseline de comportamiento (crear/verificar)
- `/usr/local/bin/security-healthcheck.sh` - Health check de controles (cron diario)
- `/usr/local/bin/security-digest.sh` - Digest periódico de seguridad (timer systemd 06:00)

### Herramientas de reporte
- `/usr/local/bin/reporte-mitre.sh` - Reporte de cobertura MITRE ATT&CK
- `/usr/local/bin/exportar-navigator.sh` - Exportación ATT&CK Navigator JSON layer
- `/usr/local/bin/reporte-cumplimiento.sh` - Reporte de cumplimiento por categoría
- `/usr/local/bin/inventario-seguridad.sh` - Inventario completo de activos de seguridad
- `/usr/local/bin/resumen-ejecutivo.sh` - Resumen ejecutivo con score de postura

### Herramientas de caza de amenazas (threat hunting)
- `/usr/local/bin/ueba-crear-baseline.sh` - Crear baseline de comportamiento por usuario
- `/usr/local/bin/ueba-detectar-anomalias.sh` - Detectar anomalías contra baseline UEBA (cron diario)
- `/usr/local/bin/cazar-amenazas.sh` - Playbooks de hunting por hipótesis (5 hipótesis)
- `/usr/local/bin/detectar-persistencia-avanzada.sh` - Detección T1098 (timer 15min)
- `/usr/local/bin/buscar-retrospectivo.sh` - Búsqueda retrospectiva en logs
- `/usr/local/bin/detectar-anomalias-red.sh` - Detección estadística anomalías de red (cron diario)

### Herramientas de respuesta automática (SOAR)
- `/usr/local/bin/soar-responder.sh` - Motor SOAR (timer 10min)
- `/usr/local/bin/soar-gestionar-bloqueos.sh` - Gestión de IPs bloqueadas
- `/usr/local/bin/soar-notificar.sh` - Notificaciones consolidadas por severidad
- `/etc/security/soar-rules.conf` - Configuración de reglas trigger→acción

### Herramientas de validación Purple Team
- `/usr/local/bin/validar-autenticacion.sh` - Validar 15 controles de autenticación
- `/usr/local/bin/validar-red.sh` - Validar 15 controles de red
- `/usr/local/bin/validar-endpoint.sh` - Validar 21 controles de endpoint
- `/usr/local/bin/simular-ataques.sh` - Simulador seguro de 12 técnicas ATT&CK
- `/usr/local/bin/reporte-validacion.sh` - Reporte consolidado con scoring global
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
- `/var/lib/incident-response/` - Datos de incidentes (forense, playbooks, timelines)
- `/var/lib/security-monitoring/` - Monitorización (correlaciones, baselines, healthchecks, digests)
- `/var/lib/security-reports/` - Reportes generados (MITRE, cumplimiento, inventario, ejecutivo, Navigator JSON)
- `/var/lib/threat-hunting/` - Caza de amenazas (baselines UEBA, anomalías, resultados de hunting, persistencia T1098)
- `/var/lib/soar/` - SOAR (queue de eventos, acciones ejecutadas, IPs bloqueadas, logs de respuesta)
- `/var/lib/purple-team/` - Purple Team (resultados de validación, evidencia de simulaciones, reportes consolidados)

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
