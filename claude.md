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
1. `hardening-opensuse.sh` - Hardening base del sistema (kernel, FTP, servicios, firewall, SSH, contraseñas, permisos, fail2ban, actualizaciones, auditd, MFA SSH, ClamAV, OpenSCAP, TCP SACK/DSACK=0, keepalive=600/30/5, IPv6 use_tempaddr=2)
2. `hardening-seguro.sh` - Nivel seguro de hardening (archivos, procesos, AIDE, SSH keys)
3. `hardening-final.sh` - Hardening final consolidado (auditd, sysctl, firewall, updates, bluetooth config idempotente, sudoers atómicos)
4. `hardening-externo.sh` - Hardening de servicios externos (banners, honeypot, DNS, VPN, guard nmcli)
5. `hardening-extremo.sh` - Nivel extremo SEGURO (USB, kernel, red — sin lockout, inline en menú)
6. `hardening-paranoico.sh` - Nivel paranoico SEGURO, 23 secciones (core dumps, GRUB, audit, sysctl, per-interface hardening rp_filter=2 strict, faillock, user namespaces, crypto FUTURE, OBEX/Geoclue/captive portal, mount options — sin PAM, inline en menú)
7. `contramedidas-mesh.sh` - Contramedidas de red mesh (WiFi, Bluetooth, IoT, bt_coex_active=N, WoWLAN disable + NM dispatcher, 12 pre-checks)
8. `proteger-privacidad.sh` - Protección de privacidad (VNC, cámara, DNS leaks, Tor, NM connectivity check, Firefox HTTPS-Only, Polkit WiFi, 14 pre-checks)
9. `aplicar-banner-total.sh` - Aplicación de banners (MOTD, issue, SSH, GDM, Firefox)

### Scripts de securización proactiva (8) — categoría `p`
10. `hardening-kernel-boot.sh` - Parámetros de arranque del kernel (cmdline GRUB), verificación Secure Boot, módulos firmados, protección GRUB
11. `hardening-servicios-systemd.sh` - Sandboxing de servicios systemd con drop-ins (sshd, fail2ban, firewalld, NetworkManager, security-monitor)
12. `hardening-cuentas.sh` - Seguridad de cuentas: políticas de contraseñas (login.defs), faillock, cuentas sin contraseña, UID=0 extra, shells de sistema, cuentas inactivas
13. `proteger-red-avanzado.sh` - Red avanzada: Suricata IDS, DNS over TLS (systemd-resolved), WireGuard VPN (plantilla), arpwatch + protección ARP, sinkhole, baseline, S5b per-interface sysctl enforcement (11 pre-checks)
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
34. `validar-controles.sh` - Purple Team: validadores auth/red/endpoint (21 tests), simulador ATT&CK (20 técnicas), SELinux/AppArmor detection, scoring, +5 validaciones (TCP SACK, keepalive, per-interface sysctl, NM connectivity)

### Scripts de inteligencia (2) — categoría `i`
35. `ciberinteligencia.sh` - Ciberinteligencia proactiva: IoC enriquecimiento, red, DNS, superficie, integración SOAR
36. `proteger-contra-isp.sh` - Protección ISP: kill switch, DNS leak, ECH, DPI evasion, NTS

### Scripts de infraestructura y red (9) — categoría `n`
37. `hardening-criptografico.sh` - SSH, TLS, certificados, LUKS, NTS
43. `segmentacion-red-zt.sh` - Zonas, microsegmentación, Zero Trust
50. `seguridad-cloud.sh` - AWS, Azure, GCP, IAM, postura
51. `seguridad-ldap-ad.sh` - LDAP TLS, FreeIPA, sssd, Kerberos
54. `seguridad-wireless.sh` - WPA3, RADIUS, rogue AP, 802.1X, PSK-flags credential protection, Polkit WiFi toggle restriction
55. `seguridad-virtualizacion.sh` - KVM, QEMU, libvirt, VM aislamiento
57. `zero-trust-identity.sh` - IAP, device trust, autenticación continua
63. `seguridad-dns-avanzada.sh` - DNSSEC, DoH/DoT, sinkhole, RPZ (tcp_timestamps=0 corregido)
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
64. `auditoria-red-wireshark.sh` - Wireshark, tshark, capturas, 20 checks de anomalías (ARP/DNS/DHCP/LLMNR/mDNS/SSDP poisoning, protocolos inseguros, C2/backdoor, tunneling, captive portal, SNI plaintext, detección dinámica de interfaz)
65. `auditoria-red-infraestructura.sh` - Provisionador: instala 22 scripts de auditoría de red en `/usr/local/bin/auditoria-red-*.sh` (discovery, puertos, TLS/SSL, SNMP, config, inventario, baseline/drift, reporte global con scoring 0-100, verificación LUKS, mount options, crypto policy, systemd sandboxing — 12 fases, +checks TCP SACK/DSACK/keepalive/tempaddr, auditoría sysctl per-interface, auditoría ARP per-interface L2)
68. `respuesta-incidentes.sh` - Forense, custodia, IOCs, escalación, hunting, métricas
69. `edr-osquery.sh` - Osquery, Wazuh, threat queries, fleet, baseline
70. `gestion-vulnerabilidades.sh` - Trivy, grype, SCAP, CVSS/EPSS, drift, madurez
74. `acceso-privilegiado.sh` - Session recording, sudo granular, JIT, capabilities, breakglass
75. `caza-apt-hunting.sh` - YARA, memory hunting, beaconing, IOC sweep, playbooks

### Scripts de cumplimiento (2) — categoría `c`
39. `cumplimiento-cis.sh` - CIS Benchmark, NIST 800-53, scoring
52. `cumplimiento-normativo.sh` - PCI-DSS, HIPAA, GDPR, SOC2, ISO27001

### Otros scripts
- `deploy-dns-fix.sh` - Script de despliegue DNS: override global con NetworkManager, fuerza DNS a unbound (DoT + DNSSEC), override DNS de VPNs comerciales (ProtonVPN, Mullvad, etc.), guard nmcli
- `verificar-segmentacion-final.sh` - Verificación exhaustiva de segmentación de red nftables (7 secciones, 50+ checks)
- `corregir-adaptador-red.sh` - **(REDUNDANTE)** Parche puntual de 10 hallazgos de auditoría de red, ahora integrados en scripts canónicos

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

### Herramientas de auditoría de infraestructura de red (módulo 65)
- `/usr/local/bin/auditoria-red-programada.sh` - Orquestador principal (entry point): ejecuta auditoría completa/trimestral/mensual/semanal/diaria en cascada
- `/usr/local/bin/auditoria-red-descubrimiento.sh` - Discovery de hosts en la red local (arp-scan, nbtscan, nmap)
- `/usr/local/bin/auditoria-red-puertos.sh` - Escaneo de puertos y servicios
- `/usr/local/bin/auditoria-red-tls.sh` - Auditoría TLS/SSL con testssl.sh (batch desde tls-endpoints.txt)
- `/usr/local/bin/auditoria-red-snmp.sh` - Auditoría SNMP (community strings, configuración)
- `/usr/local/bin/auditoria-red-config.sh` - Auditoría configuración de red (interfaces, rutas, ARP, sysctl, DNS, firewall, conexiones) con scoring 0-100
- `/usr/local/bin/auditoria-red-inventario.sh` - Inventario de servicios de red con detección de versiones (nmap)
- `/usr/local/bin/auditoria-red-baseline.sh` - Baseline y detección de drift (--capture / --compare)
- `/usr/local/bin/auditoria-red-reporte-global.sh` - Reporte consolidado con scoring (herramientas, firewall, sysctl, puertos, baseline)
- `/usr/local/bin/auditoria-red-analisis.sh` - Análisis de tráfico de red
- `/usr/local/bin/auditoria-red-anomalias.sh` - Detección de anomalías de red
- `/usr/local/bin/auditoria-red-captura.sh` - Captura de tráfico (tshark)
- `/usr/local/bin/auditoria-red-topologia.sh` - Topología de red (lldpctl, ethtool)
- `/usr/local/bin/auditoria-red-csv.sh` - Exportación CSV de resultados
- `/usr/local/bin/auditoria-red-limpieza.sh` - Limpieza de datos antiguos
- `/usr/local/bin/auditoria-red-rotacion.sh` - Rotación de reportes y logs
- `/usr/local/bin/auditoria-red-listar.sh` - Listar auditorías realizadas
- `/etc/securizar/auditoria-red/` - Políticas y configuración (puertos-autorizados.conf, tls-endpoints.txt, servicios-aprobados.conf)
- `/var/lib/securizar/auditoria-red/{baseline,scans,reportes}/` - Datos de auditoría

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

### Reglas auditd consolidadas
- `/etc/audit/rules.d/90-hardening.rules` - Archivo único con `-D` y `-b 8192` headers (evita conflictos "Rule exists"). 40+ reglas mapeadas a MITRE ATT&CK: identity (T1078), logins, time-change (T1070.006), execve (T1059), network (T1071), kernel modules (T1547.006), priv-escalation (T1548), ptrace (T1055), boot/sysctl/SSH/PAM/ld.so, persistence cron/systemd (T1053), defense evasion audit+SELinux (T1562), credential access (T1003), mount/namespace (container escape)
- Reglas MITRE legacy (6X) respaldadas como `.bak` al aplicar 90-hardening.rules

### Hardening sysctl de red aplicado (`/etc/sysctl.d/99-securizar.conf`)
Parámetros persistidos (auditoría de red 2026-02-16, score 100/100):
- `net.ipv4.conf.all.log_martians = 1` - Log paquetes con IPs imposibles (anti-spoofing)
- `net.ipv6.conf.all.accept_ra = 0` - Rechazar IPv6 Router Advertisements (anti-MITM)
- `net.ipv6.conf.default.accept_ra = 0` - Rechazar IPv6 RA en interfaces nuevas (anti-RA spoofing)
- `net.ipv4.conf.all.arp_ignore = 1` - Solo responder ARP en interfaz correcta (anti-ARP spoofing)
- `net.ipv4.conf.all.arp_announce = 2` - Usar mejor dirección local para ARP (anti-cache poisoning)

Parámetros ya correctos en el sistema (no requirieron cambio):
- `net.ipv4.conf.all.accept_redirects = 0`, `net.ipv4.ip_forward = 0`, `net.ipv4.conf.all.rp_filter = 1`
- `net.ipv4.conf.all.accept_source_route = 0`, `net.ipv4.tcp_syncookies = 1`
- `net.ipv4.icmp_ignore_bogus_error_responses = 1`, `net.ipv4.icmp_echo_ignore_broadcasts = 1`
- `net.ipv4.conf.all.send_redirects = 0`, `net.ipv4.conf.all.arp_accept = 0`
- `net.ipv6.conf.all.accept_source_route = 0`, `net.ipv6.conf.all.accept_redirects = 0`
- `net.ipv4.tcp_sack = 0` (anti CVE-2019-11477 SACK Panic), `net.ipv4.tcp_rfc1337 = 1` (anti TIME-WAIT assassination)
- `net.ipv4.tcp_timestamps = 0` (anti TCP fingerprinting)

### Hardening manual aplicado (2026-02-16)

#### Servicios desactivados y enmascarados
- **Avahi** (mDNS, puerto 5353) — `systemctl mask avahi-daemon.service avahi-daemon.socket` — anti-mDNS poisoning
- **Samba/NetBIOS** — `systemctl mask smb.service nmb.service winbind.service` — anti-SMB relay, NBNS poisoning
- **UPnP** — `systemctl mask miniupnpd.service` — anti-port mapping remoto, CallStranger

#### Puertos bloqueados por firewall (firewalld direct rules)
| Protocolo | Puertos | Dirección | Propósito |
|-----------|---------|-----------|-----------|
| mDNS | 5353/udp | INPUT | Anti-mDNS poisoning (avahi) |
| NetBIOS | 135,137,138,139,445 tcp+udp | INPUT+OUTPUT | Anti-SMB relay, EternalBlue |
| UPnP/SSDP | 1900/udp, 5000/tcp, 5351/udp | INPUT+OUTPUT | Anti-UPnP exploits |
| Multicast SSDP | 239.255.255.250 | INPUT+OUTPUT | Anti-SSDP amplificación |
| HTTP plano | 80/tcp, 8080/tcp | OUTPUT | Forzar HTTPS |
| LLMNR | 5355/udp | INPUT+OUTPUT (ipv4+ipv6) | Anti-LLMNR poisoning |
| IGMP/Multicast | igmp + 224.0.0.0/4 | INPUT+OUTPUT | Anti-multicast attacks |
| ICMPv6 RA | router-advertisement, router-solicitation | INPUT (ipv6) | Anti-rogue router IPv6 |
| DHCP rogue | 67→68/udp de IPs != gateway | INPUT | Solo aceptar DHCP del router real |

#### HTTPS forzado a nivel de sistema
- `wget`: `https_only = on` en `/etc/wgetrc`
- `curl`: alias `curl --proto =https` en `/etc/profile.d/force-https.sh`
- `git`: `url."https://".insteadOf "http://"` (global)
- `zypper`: repos convertidos de http a https en `/etc/zypp/repos.d/`

#### DNS cifrado (DNS-over-TLS)
- Servidor: Quad9 (`9.9.9.9#dns.quad9.net`, `149.112.112.112#dns.quad9.net`)
- `DNSOverTLS=yes`, `DNSSEC=yes` en `/etc/systemd/resolved.conf.d/force-dot.conf`
- LLMNR y MulticastDNS desactivados en `/etc/systemd/resolved.conf.d/no-llmnr.conf`

#### ARP estático contra spoofing
- MAC del gateway fijada permanentemente: `ip neigh replace <gateway> lladdr <mac> nud permanent`
- Servicio persistente: `/etc/systemd/system/static-arp.service` (oneshot, After=network-online.target)

#### Sysctl adicionales (`/etc/sysctl.d/99-anti-router.conf` y `99-anti-router-extra.conf`)
**99-anti-router.conf:**
- `net.ipv4.conf.all.accept_redirects=0` — Anti-ICMP redirect hijacking
- `net.ipv4.conf.default.accept_redirects=0`
- `net.ipv6.conf.all.accept_redirects=0`
- `net.ipv4.conf.all.send_redirects=0`
- `net.ipv4.conf.all.secure_redirects=0`
- `net.ipv4.conf.all.accept_source_route=0` — Anti-source routing spoofing
- `net.ipv6.conf.all.accept_source_route=0`
- `net.ipv4.conf.all.rp_filter=1` — Validación ruta inversa (anti-spoofing)
- `net.ipv4.icmp_echo_ignore_broadcasts=1` — Anti-smurf
- `net.ipv4.tcp_syncookies=1` — Anti-SYN flood

**99-anti-router-extra.conf:**
- `net.ipv6.conf.all.accept_ra=0` — Rechazar Router Advertisements IPv6
- `net.ipv6.conf.default.accept_ra=0`
- `net.ipv6.conf.all.router_solicitations=0`
- `net.ipv6.conf.all.accept_ra_defrtr=0`
- `net.ipv6.conf.all.accept_ra_pinfo=0`
- `net.ipv4.tcp_timestamps=0` — Anti-fingerprinting TCP
- `net.ipv4.tcp_syn_retries=3` — Limitar reintentos SYN
- `net.ipv4.tcp_synack_retries=2`
- `net.ipv4.tcp_fin_timeout=15` — Cerrar conexiones huérfanas rápido
- `net.ipv4.tcp_keepalive_time=600`
- `net.ipv4.tcp_keepalive_intvl=30`
- `net.ipv4.tcp_keepalive_probes=3`
- `net.ipv4.conf.all.log_martians=1` — Log paquetes spoofing

#### Hardening TLS — Protección contra cifrado débil del router (2026-02-16)

**OpenSSL global** (`/etc/ssl/openssl.cnf`):
- `MinProtocol = TLSv1.2` — TLS 1.0 y 1.1 rechazados (verificado)
- `CipherString = ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:!aNULL:!MD5:!DSS:!RC4:!3DES:!DES:!SEED:!CAMELLIA:!IDEA:!eNULL:!EXPORT:!SHA1`
- `Options = NoSSLv2,NoSSLv3,NoTLSv1,NoTLSv1.1`

**NSS (Firefox/Thunderbird)** (`/etc/crypto-policies/local.d/nss-strong.config`):
- Solo TLS 1.2+, sin SHA1, MD5, RC4, 3DES, DES, SEED, CAMELLIA, IDEA

**Panel web del router bloqueado por firewall:**
- OUTPUT → router:80 (HTTP) — DROP
- OUTPUT → router:443 (TLS vulnerable) — DROP
- OUTPUT → router:139,445 (SMB) — DROP

**curl** (`/etc/curlrc`): `--tlsv1.2`, cifrados AEAD, `--proto =https`

**wget** (`/etc/wgetrc`): `secure_protocol = TLSv1_2`, `check_certificate = on`

**SSH cliente** (`/etc/ssh/ssh_config.d/strong-crypto.conf`):
- KexAlgorithms: curve25519-sha256, diffie-hellman-group16/18-sha512
- Ciphers: chacha20-poly1305, aes256-gcm, aes128-gcm
- MACs: hmac-sha2-512/256-etm
- HostKeyAlgorithms: ssh-ed25519, rsa-sha2-512/256

**Auditoría TLS** (`/etc/audit/rules.d/68-tls-protection.rules`):
- Monitoriza cambios en `/etc/ssl/certs/`, `/etc/pki/tls/`, `/usr/share/ca-certificates/`
- Monitoriza cambios en `/etc/ssl/openssl.cnf`, `/etc/ssh/ssh_config`

#### Entropía maximizada (2026-02-16)
- **Kernel CRNG**: pool 256/256 (100%) — Linux 5.18+ fija el pool en 256 bits
- **haveged**: activo (`systemctl enable --now`), pool 4096, `/etc/default/haveged`
- **jitterentropy**: built-in en kernel (no módulo)
- **rng-tools**: enabled, alimenta pool al arranque y sale (no hardware RNG persistente)
- **sysctl** (`/etc/sysctl.d/99-max-entropy.conf`): `read_wakeup_threshold=2048`, `write_wakeup_threshold=4096`, `urandom_min_reseed_secs=10`

### Estado de auditoría de red (2026-02-16, auditoría exhaustiva)
- **Puntuación configuración de red**: 100/100 (0 problemas)
- **Reporte global**: todos los checks OK excepto suricata (no instalado, opcional)
- **Superficie de ataque**: 0 puertos TCP en escucha, 1 UDP (chrony 323/udp localhost)
- **Firewall**: nftables activo, firewalld masked. Política DROP input, DROP forward, ACCEPT output
- **Baseline**: configurada, sin drift
- **Red**: 192.168.1.149/24 vía wlp0s20f3 (MAC randomizada 92:e7:21:4a:9b:91), gateway 192.168.1.1
- **Router (192.168.1.1)**: Sagemcom (d0:6e:de:13:21:04). SMB/NetBIOS abierto pero BLOQUEADO. Panel HTTP/HTTPS bloqueado por nftables
- **DNS**: Quad9 (9.9.9.9) + Google (8.8.8.8) via NetworkManager. 0 DNS leaks a ISP
- **ISP bloquea Cloudflare**: 1.1.1.1 bloqueado completamente (ICMP, UDP 53, TCP 443)
- **NTP**: chrony con pool 2.opensuse.pool.ntp.org → tick.espanix.net (stratum 1), time.cloudflare.com, ntp1.adora.codes, IONOS

#### Dispositivos en la red (descubrimiento nmap 2026-02-16)
| IP | MAC | Dispositivo | Estado |
|---|---|---|---|
| 192.168.1.1 | d0:6e:de:13:21:04 | Router Sagemcom | Permitido (solo DNS/DHCP) |
| 192.168.1.130 | 98:0d:51:df:28:c0 | Huawei Y6s (JAT-L41HW, Android 9, EMUI 9.1.0) | **AISLADO** triple bloqueo. EOL sin parches, NetBIOS/SNMP/mDNS expuestos |
| 192.168.1.137 | b8:c6:aa:ff:5c:62 | Xiaomi Mi TV Stick (Earda WiFi module, Google Cast) | **AISLADO** triple bloqueo. API eureka_info sin auth |
| 192.168.1.142 | 06:f4:a8:07:02:34 | Samsung Galaxy Tab A (T509K, Android 14) | **AISLADO** triple bloqueo. 0 puertos TCP abiertos |
| 192.168.1.143 | 28:40:dd:fd:28:3d | Sony PlayStation 5 (FreeBSD 11/Orbis OS) | **AISLADO** triple bloqueo. 0 puertos TCP abiertos |
| 192.168.1.149 | 92:e7:21:4a:9b:91 | Este equipo (MAC randomizada) | 0 puertos expuestos |

#### Servicios deshabilitados en auditoría (2026-02-16)
- **CUPS** (cups.service + cups.socket + cups-browsed) — sin impresora, cerraba puerto 631
- **LLDP** (lldpd.service) — filtraba OS, kernel, hostname y MAC cada 30s
- **firewalld** — masked (conflicto con nftables impedía arranque al boot)

#### Firewall nftables — Triple aislamiento (tabla inet filter)
Migrado de firewalld con TODAS las reglas originales + aislamiento LAN completo.
Ruta config openSUSE: `/etc/nftables/rules/main.nft` (copia en `/etc/nftables.conf`)

**INPUT (policy DROP):**
- Loopback, established/related, ICMP básico → accept
- DHCP solo desde router (192.168.1.1) → accept. Rogue DHCP → drop
- **Capa 1 MAC**: drop 4 MACs conocidas (Huawei, Mi TV, Samsung, PS5)
- **Capa 2 IP**: drop 4 IPs conocidas (.130, .137, .142, .143)
- **Capa 3 Subnet**: router accept, resto 192.168.1.0/24 → drop
- SMB/NetBIOS/RPC (135,137,138,139,445) tcp+udp → drop
- UPnP/SSDP (1900/udp, 5000/tcp, 239.255.255.250) → drop
- mDNS (5353), LLMNR (5355) → drop
- IoT: MQTT (1883,8883), CoAP (5683,5684) → drop
- TCP reject RST, UDP reject icmp-port-unreachable

**OUTPUT (policy ACCEPT):**
- **Capa 1 MAC**: drop 4 MACs destino
- **Capa 2 IP**: drop 4 IPs destino
- **Capa 3 Subnet**: router DNS(53)/DHCP(67) accept, resto LAN → drop
- Multicast (224.0.0.0/4), broadcast (255.255.255.255) → drop
- SMB/NetBIOS/RPC, UPnP/SSDP/NAT-PMP, mDNS/LLMNR → drop
- HTTP plano (80, 8080) → drop (fuerza HTTPS)

**FORWARD (policy DROP)**

#### Auditoría exhaustiva de sistema (2026-02-16)
**RPM integrity**: sudo, openssh, coreutils, nftables, pam, shadow, glibc — **todos limpios**
**SUID binarios**: 16 estándar (chfn, chsh, mount, sudo, pkexec, etc.) — 0 anómalos
**Capabilities**: 6 normales (dumpcap, clockdiff, kwin, newuidmap, newgidmap, mtr)
**Kernel modules**: todos estándar Tiger Lake (i915, xe, iwlwifi, snd, nf_tables, etc.)
**SELinux**: enforcing, política targeted
**Kernel security**: ASLR=2, ptrace_scope=3, kptr_restrict=2, dmesg_restrict=1, perf_paranoid=3, unprivileged_bpf=1, kexec_disabled=1, tcp_sack=0, rp_filter=1, core_pattern=|/bin/false, protected_hardlinks=1, protected_symlinks=1
**LD_PRELOAD/ld.so.preload**: limpio. /dev/shm vacío. /tmp sin ejecutables
**Crontabs**: 0 user, 0 system. 20 timers systemd legítimos
**Login failures**: 0. SSH hardened (curve25519, ed25519, MaxAuthTries=3). Sin authorized_keys
**IP forwarding**: deshabilitado. Modo promiscuo: ninguno
**Secure Boot**: deshabilitado (WARN). GRUB sin contraseña (WARN)
**Filesystem**: /tmp como tmpfs con noexec,nosuid,nodev (systemd override). /dev/shm noexec. btrfs con subvolumes
**auditd**: activo, enabled, audit=1 en GRUB. 40+ reglas MITRE ATT&CK en 90-hardening.rules
**Passwords**: pwquality minlen=12, minclass=3, enforcing=1
**Containers**: 0 (docker/podman/lxc no instalados)
**Env variables**: limpio (0 proxy/LD_/DYLD_ sospechosas)

#### Hallazgos de auditoría tshark (2026-02-16, capturas múltiples >15000 paquetes)
Auditoría de 40+ vectores con capturas de 15s, 30s, 60s, 90s y 120s:
- **0 intrusos** — todos los dispositivos identificados
- **0 ARP/DNS/DHCP/LLMNR/mDNS/SSDP poisoning**
- **0 protocolos inseguros** (HTTP, FTP, Telnet, POP3, IMAP, SMTP)
- **0 credenciales en claro**, 0 paquetes malformados, 0 TCP anomalías
- **0 puertos C2/TOR/backdoor**, 0 ICMP/DNS tunneling, 0 IPv6 RA spoofing
- **0 procesos ocultos**, 0 SUID no-stock, 0 LD_PRELOAD, 0 kernel modules no-stock
- **0 HTTP saliente** (nftables fuerza HTTPS)
- **100% tráfico cifrado** TLS 1.2/1.3
- **Destinos legítimos**: Anthropic, Google, ProtonMail, GitHub, openSUSE, Datadog
- **Huawei Y6s**: NetBIOS 137/138, SNMP 161, mDNS 5353, Spotify 57621/udp expuestos — AISLADO
- **Mi TV Stick**: API Google Cast (8008,8009,8443) sin autenticación — AISLADO

### Auditoría exhaustiva de sistema (2026-02-17, 42 vectores)

#### Hallazgos críticos y fixes aplicados
- **IPv6 per-interface**: `disable_ipv6=1` global no propagaba a wlp0s20f3 → link-local fe80:: activo. Fix: `sysctl -w net.ipv6.conf.wlp0s20f3.disable_ipv6=1`, persistido en `/etc/sysctl.d/99-securizar-ipv6.conf` (600)
- **rp_filter per-interface**: `all=1` pero wlp0s20f3=2 (loose). Fix: `sysctl -w net.ipv4.conf.wlp0s20f3.rp_filter=1`, persistido en `/etc/sysctl.d/99-securizar-rpfilter.conf` (600)
- **OBEX bluetooth**: obexd se re-activaba vía D-Bus aunque bluetooth estaba masked. Fix: `systemctl --user mask obex.service`
- **Geoclue location agent**: triangulaba posición vía WiFi BSSIDs. Fix: `Hidden=true` en autostart desktop file
- **Crypto policy FUTURE**: `update-crypto-policies --set FUTURE` → TLS mínimo 1.3, RSA mínimo 3072, SHA-1 deshabilitado

#### Estado por vector (42 checks)
**OK (24)**: Puertos escucha (0 TCP, 1 UDP chrony localhost), conexiones (100% HTTPS), servicios (29 legítimos), kernel params (todos correctos), WiFi (WPA2-PSK 5GHz, MAC randomizada), SELinux (enforcing targeted), SSH (disabled, ed25519 only para GitHub), SUID (17 estándar), RPM integrity, /tmp /dev/shm limpios, crontabs (0), env variables limpias, containers (0), hostname=localhost, firmware actualizado, DNS (Quad9 sin leaks), NTP (chrony stratum 1), 0 world-writable en /etc /usr, credentials (600), git (SSH remote, 0 secrets)

**CRITICAL (1)**: Disco NO cifrado (sin LUKS, swap sin cifrar)

**WARN (13)**: Secure Boot OFF, GRUB sin contraseña, mount options (/home sin nosuid,nodev; /tmp sin noexec; /boot/efi sin nosuid,nodev,noexec), PASS_MAX_DAYS=99999, faillock no configurado, user_namespaces=30026 (alto, CVE-2022-0185), WiFi PSK visible vía nmcli -s, SNI plaintext (ISP ve dominios), captive portal checks (NM + Firefox), systemd sandboxing (security-monitor 9.6 UNSAFE), Firefox (0 extensiones, no DoH, WebRTC/WebGL no deshabilitados), gcc/gdb/strace disponibles, telemetría Datadog (Claude Code)

**INFO (2)**: Kernel taint 2147484160 (out-of-tree iwlmvm + SUSE tech preview, sin impacto seguridad), dumpcap cap_net_admin,cap_net_raw=eip (flag inheritable notable)

#### Capturas de red (2626 + 7351 paquetes)
- 100% TCP/TLS, DNS solo a 9.9.9.9, NTP 8 paquetes
- 0 ARP/broadcast/LAN traffic
- Dominios DNS: api.anthropic.com, cdn.opensuse.org, conncheck.opensuse.org, detectportal.firefox.com, http-intake.logs.us5.datadoghq.com, storage.googleapis.com
- Exposición externa: IP 213.94.43.40, ISP XTRA TELECOM (Oviedo), sin VPN/Tor/WARP

#### Nuevos módulos en hardening-paranoico.sh (S17-S22)
- **S17**: Per-interface hardening — IPv6 disable + rp_filter=1 en todas las interfaces
- **S18**: Faillock brute-force — pam_faillock (5 intentos → 15min bloqueo, incluso root)
- **S19**: User namespaces limit — `user.max_user_namespaces = 0`
- **S20**: Crypto policy FUTURE — `update-crypto-policies --set FUTURE`
- **S21**: Disable tracking — OBEX masked, Geoclue Hidden, NM captive portal deshabilitado
- **S22**: Mount options — /home nosuid,nodev; /boot/efi nosuid,nodev,noexec

#### Nuevos checks en auditoria-red-wireshark.sh (19-20)
- **Check 19**: Detección tráfico captive portal (conncheck, detectportal, nmcheck)
- **Check 20**: Análisis SNI plaintext (dominios visibles al ISP en ClientHello TLS)

#### Nuevas fases en auditoria-red-infraestructura.sh (9-12)
- **Fase 9**: Verificación cifrado disco (LUKS en particiones + swap)
- **Fase 10**: Auditoría mount options (/home, /tmp, /var, /boot/efi, /dev/shm)
- **Fase 11**: Crypto policy + systemd sandboxing (UNSAFE/EXPOSED/OK scoring)

### Auditoría de seguridad consolidada (2026-02-17)

#### Progresión de score
| Fase | PASS | FAIL | Score | Grado |
|------|------|------|-------|-------|
| Inicial (pre-sysctl) | 12 | 20 | 35% | D |
| Post-sysctl --system | 34 | 7 | 83% | B |
| Post-auditd + SELinux detection | 35 | 6 | 85% | B |
| Post-3fixes (SSH, /tmp, pwquality) | 37 | 4 | 92% | A |

#### Fixes aplicados (2026-02-17)
- **Kernel sysctl**: `sysctl --system` cargó parámetros de 50-hardening-base.conf y 99-paranoid.conf
- **auditd**: `audit-rules.service` fallaba por reglas duplicadas → consolidado en 90-hardening.rules con `-D`/`-b 8192`. `audit=1` añadido a GRUB cmdline
- **SELinux**: Sistema usa SELinux enforcing (targeted), no AppArmor. Scripts actualizados para detectar SELinux
- **SSH hardening**: `/etc/ssh/sshd_config.d/50-hardening-base.conf` con curve25519, chacha20-poly1305, ed25519. Host keys generadas (RSA, ECDSA, ED25519)
- **/tmp noexec**: Override systemd `/etc/systemd/system/tmp.mount.d/noexec.conf`
- **pwquality**: minlen=12, minclass=3, maxrepeat=3, enforcing=1

#### FAILs no corregibles
- `net.core.bpf_jit_harden`: No soportado por kernel 6.12.0-160000.9
- CVE-2025-39866: Requiere kernel >= 6.12.16 (esperar parche openSUSE)
- CVE-2025-21756: Mitigado (vsock blacklisted), requiere kernel >= 6.13.4
- SSH MFA: Requiere configuración FIDO2/TOTP adicional

#### Compatibilidad OpenSSH 10.0p2
Directivas eliminadas (causan `sshd -t` failure):
- `ChallengeResponseAuthentication` → usar `KbdInteractiveAuthentication`
- `PrintMotd`, `PrintLastLog` → eliminados completamente
- `Protocol 2` → redundante desde OpenSSH 7.4

### Integración de hallazgos de auditoría de red (2026-02-17, 4 rondas)

Todos los hallazgos de `corregir-adaptador-red.sh` (10 fixes puntuales) integrados en scripts canónicos:

#### Nuevas secciones en scripts canónicos
- **hardening-opensuse.sh**: TCP SACK/DSACK=0 (CVE-2019-11477), keepalive=600/30/5, IPv6 use_tempaddr=2 en heredoc sysctl base
- **proteger-red-avanzado.sh S5b**: Per-interface sysctl enforcement — enumera `/sys/class/net/*` (excluyendo lo), escribe 9 params por interfaz en `/etc/sysctl.d/99-per-interface-hardening.conf`
- **contramedidas-mesh.sh §2b**: `bt_coex_active=N` en `/etc/modprobe.d/disable-bluetooth.conf` (solo si iwlwifi cargado)
- **contramedidas-mesh.sh §11**: WoWLAN disable via `iw phy` + persistencia NM dispatcher `/etc/NetworkManager/dispatcher.d/99-disable-wowlan`
- **seguridad-wireless.sh**: PSK-flags=1 credential protection, Polkit WiFi toggle restriction
- **proteger-privacidad.sh §11**: NM connectivity check disable (`/etc/NetworkManager/conf.d/99-no-connectivity-check.conf`)
- **proteger-privacidad.sh §12**: Firefox HTTPS-Only mode via user.js
- **auditoria-red-infraestructura.sh**: +4 SYSCTL_CHECKS (tcp_sack, tcp_dsack, tcp_keepalive_time, use_tempaddr), per-interface sysctl + ARP audit
- **validar-controles.sh**: +5 validaciones (TCP SACK, keepalive, per-interface sysctl, NM connectivity)

#### Fixes cross-script (robustez)
- **Detección dinámica de interfaz**: Reemplazados fallbacks `eth0` hardcoded con 3-tier: `ip route get` → `ip link show up` → `/sys/class/net/` → `eth0` (securizar-menu.sh, auditoria-red-infraestructura.sh, auditoria-red-wireshark.sh, respuesta-incidentes.sh)
- **Guards `command -v`**: Antes de usar `nmcli`/`iw` en contramedidas-mesh.sh, proteger-privacidad.sh, hardening-externo.sh, deploy-dns-fix.sh
- **Bluetooth config idempotente**: hardening-final.sh usa grep antes de append (evita duplicados con contramedidas-mesh.sh)
- **Sudoers atómicos**: hardening-final.sh y mitigar-escalada.sh usan `install -m 440` antes de escribir contenido
- **Sysctl consistencia**: tcp_timestamps=1→0 en seguridad-dns-avanzada.sh, rp_filter 1→2 en hardening-paranoico.sh, duplicado rp_filter eliminado en hardening-opensuse.sh
- **hardening-kernel-boot.sh**: Variable `$GRUB_USER_CFG` entrecomillada en 4 ubicaciones
- **verificar-segmentacion-final.sh**: Flag `-e` faltante añadido a `set -euo pipefail`

#### UPnP eliminado del sistema
- **libupnp17** desinstalada (arrastra VLC como dependencia). Servicios UPnP ya masked y puertos bloqueados por nftables

### Datos de operaciones
- `/var/lib/incident-response/` - Datos de incidentes (forense, playbooks, timelines)
- `/var/lib/security-monitoring/` - Monitorización (correlaciones, baselines, healthchecks, digests)
- `/var/lib/security-reports/` - Reportes generados (MITRE, cumplimiento, inventario, ejecutivo, Navigator JSON)
- `/var/lib/threat-hunting/` - Caza de amenazas (baselines UEBA, anomalías, resultados de hunting, persistencia T1098)
- `/var/lib/soar/` - SOAR (queue de eventos, acciones ejecutadas, IPs bloqueadas, logs de respuesta)
- `/var/lib/purple-team/` - Purple Team (resultados de validación, evidencia de simulaciones, reportes consolidados)
- `/var/lib/securizar/auditoria-red/` - Auditoría de red (baselines, scans nmap, reportes config/inventario/global)
- `/var/log/securizar/auditoria-red.log` - Log del orquestador de auditoría de red

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
- **Detección de interfaz**: Nunca hardcodear `eth0`. Usar detección dinámica: `ip route get 1.1.1.1` → `ip -o link show up` → `ls /sys/class/net/` → `eth0` como último fallback
- **Guards de comandos externos**: Usar `command -v nmcli/iw/etc.` antes de invocarlos. Si no están disponibles, usar fallback (`systemctl` para NM) o skip con advertencia
- **Permisos atómicos**: Al crear ficheros sudoers o sensibles, usar `install -m 440 /dev/null <path>` antes de escribir contenido (evita ventana de permisos inseguros)
- **Idempotencia en configs compartidos**: Al append a ficheros que múltiples scripts pueden modificar (ej. disable-bluetooth.conf), verificar con grep antes de añadir (evitar duplicados)
- **Sysctl per-interface**: Los valores `conf.all` NO se propagan automáticamente a interfaces existentes. Siempre aplicar también a `conf.$iface` para cada interfaz activa
- **Pre-checks**: Scripts con `_precheck()` deben actualizar el conteo al añadir nuevos checks (`_precheck N` donde N = total)

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
- Las reglas auditd de hardening base van en `/etc/audit/rules.d/90-hardening.rules` (archivo único con `-D` header). Las reglas MITRE-específicas usan numeración 6X
- Cada módulo MITRE incluye sección de RESUMEN al final con estado OK/-- por técnica
- Las herramientas operativas (IR, monitorización, reportes) guardan datos en `/var/lib/`
