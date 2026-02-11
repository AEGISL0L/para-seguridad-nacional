#!/bin/bash
# ============================================================
# forense-avanzado.sh - Modulo 46: Forense avanzado
# ============================================================
# Toolkit completo de forensia digital y respuesta a incidentes:
#   S1  - Kit de adquisicion de memoria (LiME / /proc/kcore)
#   S2  - Imagen de disco forense (dc3dd/dd + hashes)
#   S3  - Preservacion de datos volatiles (orden de volatilidad)
#   S4  - Recopilacion de artefactos del sistema
#   S5  - Construccion de linea temporal unificada
#   S6  - Toolkit de analisis de malware (YARA + analisis estatico)
#   S7  - Cadena de custodia digital
#   S8  - Toolkit de analisis de logs
#   S9  - Script maestro de recopilacion forense
#   S10 - Auditoria y puntuacion de preparacion forense
# ============================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps
init_backup "forense-avanzado"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MODULO 46 - FORENSE AVANZADO & RESPUESTA A INCIDENTES  ║"
echo "║   Memoria, disco, volatiles, artefactos, timeline,       ║"
echo "║   YARA, custodia, logs, recopilacion, auditoria          ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_section "MODULO 46: FORENSE AVANZADO"
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

# Directorio base para evidencia forense
FORENSICS_BASE="/var/forensics"
FORENSICS_TOOLS="/usr/local/bin"
FORENSICS_ETC="/etc/securizar"

# ============================================================
# S1: KIT DE ADQUISICION DE MEMORIA
# ============================================================
log_section "S1: KIT DE ADQUISICION DE MEMORIA"

echo "Instala herramientas para volcado de RAM:"
echo "  - LiME kernel module para adquisicion de memoria"
echo "  - Script de captura: forense-capturar-ram.sh"
echo "  - Soporte para formatos: raw, lime, padded"
echo "  - Hash SHA-256 automatico del volcado"
echo "  - Metadatos: timestamp, hostname, kernel version"
echo ""

if ask "¿Instalar kit de adquisicion de memoria?"; then

    # Crear directorios de evidencia forense
    mkdir -p "${FORENSICS_BASE}/memory"
    mkdir -p "${FORENSICS_BASE}/disk"
    mkdir -p "${FORENSICS_BASE}/volatile"
    mkdir -p "${FORENSICS_BASE}/artifacts"
    mkdir -p "${FORENSICS_BASE}/timeline"
    mkdir -p "${FORENSICS_BASE}/yara"
    mkdir -p "${FORENSICS_BASE}/logs"
    mkdir -p "${FORENSICS_BASE}/custody"
    chmod 700 "${FORENSICS_BASE}"
    log_change "Creado" "estructura de directorios: ${FORENSICS_BASE}/"

    # Instalar dependencias para compilacion de LiME
    log_info "Instalando dependencias de compilacion para LiME..."
    case "$DISTRO_FAMILY" in
        suse)
            pkg_install make gcc kernel-devel || log_warn "Algunas dependencias de LiME no se pudieron instalar"
            ;;
        debian)
            pkg_install make gcc linux-headers-$(uname -r) || log_warn "Algunas dependencias de LiME no se pudieron instalar"
            ;;
        rhel)
            pkg_install make gcc kernel-devel || log_warn "Algunas dependencias de LiME no se pudieron instalar"
            ;;
        arch)
            pkg_install make gcc linux-headers || log_warn "Algunas dependencias de LiME no se pudieron instalar"
            ;;
    esac

    # Script de captura de memoria RAM
    cat > "${FORENSICS_TOOLS}/forense-capturar-ram.sh" << 'EOFRAM'
#!/bin/bash
# ============================================================
# forense-capturar-ram.sh - Adquisicion de memoria RAM
# ============================================================
# Captura volcado completo de RAM con hash y metadatos.
# Uso: forense-capturar-ram.sh [formato] [directorio_salida]
#   formato: raw (default), lime, padded
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[X]${NC} $1"; }

if [[ $EUID -ne 0 ]]; then
    log_error "Debe ejecutarse como root"
    exit 1
fi

FORMATO="${1:-raw}"
OUTPUT_DIR="${2:-/var/forensics/memory}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
HOSTNAME_SHORT=$(hostname -s)
KERNEL_VER=$(uname -r)
OUTPUT_FILE="${OUTPUT_DIR}/memdump-${HOSTNAME_SHORT}-${TIMESTAMP}.${FORMATO}"
METADATA_FILE="${OUTPUT_DIR}/memdump-${HOSTNAME_SHORT}-${TIMESTAMP}.metadata"
HASH_FILE="${OUTPUT_DIR}/memdump-${HOSTNAME_SHORT}-${TIMESTAMP}.sha256"

mkdir -p "${OUTPUT_DIR}"
chmod 700 "${OUTPUT_DIR}"

log_info "=== Adquisicion de Memoria RAM ==="
log_info "Fecha/hora:    $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
log_info "Hostname:      ${HOSTNAME_SHORT}"
log_info "Kernel:        ${KERNEL_VER}"
log_info "Formato:       ${FORMATO}"
log_info "Salida:        ${OUTPUT_FILE}"

# Obtener tamano de RAM
RAM_TOTAL=$(grep MemTotal /proc/meminfo | awk '{print $2}')
RAM_TOTAL_MB=$((RAM_TOTAL / 1024))
log_info "RAM total:     ${RAM_TOTAL_MB} MB"

# Verificar espacio disponible
AVAIL_KB=$(df -k "${OUTPUT_DIR}" | awk 'NR==2 {print $4}')
if [[ ${AVAIL_KB} -lt ${RAM_TOTAL} ]]; then
    log_error "Espacio insuficiente en ${OUTPUT_DIR}: ${AVAIL_KB}KB disponible, ${RAM_TOTAL}KB necesario"
    exit 1
fi

# Registrar metadatos antes de la captura
cat > "${METADATA_FILE}" << EOFMETA
# Metadatos de adquisicion de memoria
fecha_inicio=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
hostname=${HOSTNAME_SHORT}
fqdn=$(hostname -f 2>/dev/null || hostname)
kernel=${KERNEL_VER}
arch=$(uname -m)
ram_total_kb=${RAM_TOTAL}
ram_total_mb=${RAM_TOTAL_MB}
formato=${FORMATO}
archivo_salida=${OUTPUT_FILE}
usuario_captura=$(whoami)
pid_captura=$$
metodo=
EOFMETA

CAPTURA_OK=0

# Intentar LiME primero
if lsmod | grep -q "^lime " 2>/dev/null; then
    log_info "Modulo LiME detectado, usando LiME para captura..."
    echo "metodo=lime" >> "${METADATA_FILE}"

    # Descargar via insmod con parametros
    rmmod lime 2>/dev/null || true
    if insmod /lib/modules/${KERNEL_VER}/extra/lime.ko "path=${OUTPUT_FILE} format=${FORMATO}" 2>/dev/null; then
        CAPTURA_OK=1
        log_info "Captura LiME completada"
    else
        log_warn "LiME fallo, intentando metodo alternativo..."
    fi
elif [[ -f "/lib/modules/${KERNEL_VER}/extra/lime.ko" ]]; then
    log_info "Modulo LiME encontrado, cargando..."
    echo "metodo=lime" >> "${METADATA_FILE}"

    if insmod "/lib/modules/${KERNEL_VER}/extra/lime.ko" "path=${OUTPUT_FILE} format=${FORMATO}" 2>/dev/null; then
        CAPTURA_OK=1
        # Esperar a que termine la captura
        sleep 2
        while lsmod | grep -q "^lime " 2>/dev/null; do
            sleep 1
        done
        log_info "Captura LiME completada"
    else
        log_warn "No se pudo cargar LiME, intentando alternativa..."
    fi
fi

# Fallback: /proc/kcore
if [[ ${CAPTURA_OK} -eq 0 ]] && [[ -f /proc/kcore ]]; then
    log_info "Usando /proc/kcore para captura (menos fiable que LiME)..."
    echo "metodo=proc_kcore" >> "${METADATA_FILE}"

    if command -v pv &>/dev/null; then
        pv /proc/kcore > "${OUTPUT_FILE}" 2>/dev/null || true
    else
        dd if=/proc/kcore of="${OUTPUT_FILE}" bs=4M status=progress 2>/dev/null || true
    fi

    if [[ -s "${OUTPUT_FILE}" ]]; then
        CAPTURA_OK=1
        log_info "Captura via /proc/kcore completada"
    fi
fi

# Fallback: /dev/mem (puede estar restringido)
if [[ ${CAPTURA_OK} -eq 0 ]] && [[ -c /dev/mem ]]; then
    log_warn "Intentando /dev/mem (puede estar restringido por CONFIG_STRICT_DEVMEM)..."
    echo "metodo=dev_mem" >> "${METADATA_FILE}"

    dd if=/dev/mem of="${OUTPUT_FILE}" bs=4M count=$((RAM_TOTAL_MB / 4 + 1)) status=progress 2>/dev/null || true

    if [[ -s "${OUTPUT_FILE}" ]]; then
        CAPTURA_OK=1
        log_info "Captura via /dev/mem completada"
    fi
fi

# Fallback: /dev/fmem o /proc/mem
if [[ ${CAPTURA_OK} -eq 0 ]]; then
    log_error "No se pudo capturar la memoria con ningún metodo disponible"
    log_warn "Sugerencias:"
    log_warn "  1. Compilar e instalar LiME: https://github.com/504ensicsLabs/LiME"
    log_warn "  2. Usar herramienta externa como AVML (Azure VMLinux Memory)"
    echo "estado=fallido" >> "${METADATA_FILE}"
    exit 1
fi

# Calcular hash SHA-256
log_info "Calculando hash SHA-256..."
sha256sum "${OUTPUT_FILE}" > "${HASH_FILE}"
HASH_VALUE=$(awk '{print $1}' "${HASH_FILE}")
log_info "SHA-256: ${HASH_VALUE}"

# Completar metadatos
cat >> "${METADATA_FILE}" << EOFMETA2
fecha_fin=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
tamano_bytes=$(stat -c %s "${OUTPUT_FILE}" 2>/dev/null || echo "desconocido")
sha256=${HASH_VALUE}
estado=completado
EOFMETA2

chmod 600 "${OUTPUT_FILE}" "${METADATA_FILE}" "${HASH_FILE}"

log_info "=== Adquisicion completada ==="
log_info "Volcado:   ${OUTPUT_FILE}"
log_info "Metadatos: ${METADATA_FILE}"
log_info "Hash:      ${HASH_FILE}"
echo ""
echo "Para verificar integridad:"
echo "  sha256sum -c ${HASH_FILE}"
EOFRAM
    chmod +x "${FORENSICS_TOOLS}/forense-capturar-ram.sh"
    log_change "Creado" "${FORENSICS_TOOLS}/forense-capturar-ram.sh"

    log_info "Kit de adquisicion de memoria instalado"
    log_info "Uso: forense-capturar-ram.sh [raw|lime|padded] [directorio]"
else
    log_skip "Kit de adquisicion de memoria"
fi

# ============================================================
# S2: IMAGEN DE DISCO FORENSE
# ============================================================
log_section "S2: IMAGEN DE DISCO FORENSE"

echo "Crea imagenes forenses de disco con verificacion de hash:"
echo "  - Soporte dc3dd (preferido) o dd como fallback"
echo "  - Hash dual SHA-256 + MD5 para cadena de custodia"
echo "  - Soporte: disco completo, particion, volumen logico"
echo "  - Guia de bloqueo de escritura"
echo "  - Indicador de progreso con pv si esta disponible"
echo ""

if ask "¿Instalar herramienta de imagen de disco forense?"; then

    # Instalar dc3dd si esta disponible
    log_info "Instalando herramientas de imagen forense..."
    pkg_install pv || log_warn "pv no disponible (sin indicador de progreso)"

    # dc3dd no esta en todos los repos, intentar
    case "$DISTRO_FAMILY" in
        debian)
            pkg_install dc3dd 2>/dev/null || log_warn "dc3dd no disponible, se usara dd como fallback"
            ;;
        rhel)
            pkg_install dc3dd 2>/dev/null || log_warn "dc3dd no disponible en repos standard"
            ;;
        *)
            log_info "dc3dd: verificar disponibilidad manual para $DISTRO_FAMILY"
            ;;
    esac

    cat > "${FORENSICS_TOOLS}/forense-imagen-disco.sh" << 'EOFDISK'
#!/bin/bash
# ============================================================
# forense-imagen-disco.sh - Imagen forense de disco
# ============================================================
# Crea imagen forense con hash dual (SHA-256 + MD5) y metadatos.
# Uso: forense-imagen-disco.sh <dispositivo> [directorio_salida]
# Ejemplos:
#   forense-imagen-disco.sh /dev/sda
#   forense-imagen-disco.sh /dev/sda1 /mnt/evidencia
#   forense-imagen-disco.sh /dev/vg0/lv_root
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[X]${NC} $1"; }

if [[ $EUID -ne 0 ]]; then
    log_error "Debe ejecutarse como root"
    exit 1
fi

if [[ $# -lt 1 ]]; then
    echo "Uso: $0 <dispositivo> [directorio_salida]"
    echo "  Dispositivo: /dev/sdX, /dev/sdXN, /dev/vgname/lvname"
    exit 1
fi

DEVICE="$1"
OUTPUT_DIR="${2:-/var/forensics/disk}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
HOSTNAME_SHORT=$(hostname -s)
DEVICE_SAFE=$(echo "${DEVICE}" | sed 's|/|_|g; s|^_||')
IMAGE_FILE="${OUTPUT_DIR}/imagen-${HOSTNAME_SHORT}-${DEVICE_SAFE}-${TIMESTAMP}.dd"
HASH_FILE="${OUTPUT_DIR}/imagen-${HOSTNAME_SHORT}-${DEVICE_SAFE}-${TIMESTAMP}.hashes"
META_FILE="${OUTPUT_DIR}/imagen-${HOSTNAME_SHORT}-${DEVICE_SAFE}-${TIMESTAMP}.metadata"
LOG_FILE="${OUTPUT_DIR}/imagen-${HOSTNAME_SHORT}-${DEVICE_SAFE}-${TIMESTAMP}.log"

# Validar dispositivo
if [[ ! -b "${DEVICE}" ]] && [[ ! -f "${DEVICE}" ]]; then
    log_error "Dispositivo no encontrado o no es un bloque: ${DEVICE}"
    exit 1
fi

# Verificar que no este montado (para escritura)
if mount | grep -q "^${DEVICE} "; then
    log_warn "AVISO: ${DEVICE} esta montado. Para integridad forense, desmonte primero."
    echo -n "¿Continuar de todas formas? [s/N]: "
    read -r resp
    if [[ ! "$resp" =~ ^[sS]$ ]]; then
        echo "Abortado."
        exit 0
    fi
fi

mkdir -p "${OUTPUT_DIR}"
chmod 700 "${OUTPUT_DIR}"

# Obtener tamano del dispositivo
DEVICE_SIZE=$(blockdev --getsize64 "${DEVICE}" 2>/dev/null || echo "desconocido")
DEVICE_SIZE_GB="desconocido"
if [[ "${DEVICE_SIZE}" != "desconocido" ]]; then
    DEVICE_SIZE_GB=$(echo "scale=2; ${DEVICE_SIZE} / 1073741824" | bc 2>/dev/null || echo "N/A")
fi

log_info "=== Imagen Forense de Disco ==="
log_info "Fecha/hora:    $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
log_info "Hostname:      ${HOSTNAME_SHORT}"
log_info "Dispositivo:   ${DEVICE}"
log_info "Tamano:        ${DEVICE_SIZE_GB} GB (${DEVICE_SIZE} bytes)"
log_info "Imagen:        ${IMAGE_FILE}"

# Guia de bloqueo de escritura
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  GUIA DE BLOQUEO DE ESCRITURA                            ║"
echo "╠═══════════════════════════════════════════════════════════╣"
echo "║  Para garantizar integridad forense:                     ║"
echo "║  1. Usar bloqueador hardware (Tableau, WiebeTech)        ║"
echo "║  2. O montar como solo lectura:                          ║"
echo "║     blockdev --setro ${DEVICE}                           ║"
echo "║  3. Verificar: blockdev --getro ${DEVICE} (debe ser 1)   ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Verificar espacio disponible
AVAIL_BYTES=$(df -B1 "${OUTPUT_DIR}" | awk 'NR==2 {print $4}')
if [[ "${DEVICE_SIZE}" != "desconocido" ]] && [[ ${AVAIL_BYTES} -lt ${DEVICE_SIZE} ]]; then
    log_error "Espacio insuficiente: ${AVAIL_BYTES} bytes disponibles, ${DEVICE_SIZE} necesarios"
    exit 1
fi

# Registrar metadatos
cat > "${META_FILE}" << EOFMETA
# Metadatos de imagen forense
fecha_inicio=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
hostname=${HOSTNAME_SHORT}
fqdn=$(hostname -f 2>/dev/null || hostname)
dispositivo=${DEVICE}
tamano_bytes=${DEVICE_SIZE}
tamano_gb=${DEVICE_SIZE_GB}
archivo_imagen=${IMAGE_FILE}
operador=$(whoami)
metodo=
EOFMETA

# Info del dispositivo
log_info "Recopilando informacion del dispositivo..."
{
    echo "=== fdisk -l ${DEVICE} ==="
    fdisk -l "${DEVICE}" 2>/dev/null || true
    echo ""
    echo "=== hdparm -I ${DEVICE} ==="
    hdparm -I "${DEVICE}" 2>/dev/null || true
    echo ""
    echo "=== smartctl -a ${DEVICE} ==="
    smartctl -a "${DEVICE}" 2>/dev/null || true
} >> "${META_FILE}" 2>/dev/null

IMAGING_OK=0

# Intentar dc3dd primero (preferido para forense)
if command -v dc3dd &>/dev/null; then
    log_info "Usando dc3dd para imagen forense..."
    echo "metodo=dc3dd" >> "${META_FILE}"

    dc3dd if="${DEVICE}" of="${IMAGE_FILE}" hash=sha256 hash=md5 log="${LOG_FILE}" 2>&1 | tee -a "${LOG_FILE}" || true

    if [[ -s "${IMAGE_FILE}" ]]; then
        IMAGING_OK=1
        log_info "Imagen dc3dd completada"
    fi
fi

# Fallback: dd con pv para progreso
if [[ ${IMAGING_OK} -eq 0 ]]; then
    log_info "Usando dd para imagen forense..."
    echo "metodo=dd" >> "${META_FILE}"

    if command -v pv &>/dev/null && [[ "${DEVICE_SIZE}" != "desconocido" ]]; then
        log_info "Progreso habilitado via pv"
        dd if="${DEVICE}" bs=4M conv=noerror,sync status=none 2>"${LOG_FILE}" | \
            pv -s "${DEVICE_SIZE}" | \
            dd of="${IMAGE_FILE}" bs=4M status=none 2>>"${LOG_FILE}"
    else
        dd if="${DEVICE}" of="${IMAGE_FILE}" bs=4M conv=noerror,sync status=progress 2>"${LOG_FILE}"
    fi

    if [[ -s "${IMAGE_FILE}" ]]; then
        IMAGING_OK=1
        log_info "Imagen dd completada"
    fi
fi

if [[ ${IMAGING_OK} -eq 0 ]]; then
    log_error "No se pudo crear la imagen forense"
    echo "estado=fallido" >> "${META_FILE}"
    exit 1
fi

# Calcular hashes duales
log_info "Calculando hashes de verificacion (esto puede tardar)..."
echo "# Hashes de imagen forense - $(date -u '+%Y-%m-%d %H:%M:%S UTC')" > "${HASH_FILE}"
echo "# Archivo: ${IMAGE_FILE}" >> "${HASH_FILE}"

SHA256_IMG=$(sha256sum "${IMAGE_FILE}" | awk '{print $1}')
echo "SHA256_IMAGEN=${SHA256_IMG}" >> "${HASH_FILE}"
log_info "SHA-256 imagen: ${SHA256_IMG}"

MD5_IMG=$(md5sum "${IMAGE_FILE}" | awk '{print $1}')
echo "MD5_IMAGEN=${MD5_IMG}" >> "${HASH_FILE}"
log_info "MD5 imagen:    ${MD5_IMG}"

# Hash del dispositivo original para verificacion
log_info "Calculando hash del dispositivo original..."
SHA256_DEV=$(sha256sum "${DEVICE}" 2>/dev/null | awk '{print $1}' || echo "no_disponible")
echo "SHA256_DISPOSITIVO=${SHA256_DEV}" >> "${HASH_FILE}"

MD5_DEV=$(md5sum "${DEVICE}" 2>/dev/null | awk '{print $1}' || echo "no_disponible")
echo "MD5_DISPOSITIVO=${MD5_DEV}" >> "${HASH_FILE}"

# Verificar match
if [[ "${SHA256_IMG}" == "${SHA256_DEV}" ]] && [[ "${SHA256_DEV}" != "no_disponible" ]]; then
    echo "VERIFICACION=OK" >> "${HASH_FILE}"
    log_info "VERIFICACION: Hashes coinciden - imagen integra"
else
    echo "VERIFICACION=NO_VERIFICADO" >> "${HASH_FILE}"
    log_warn "No se pudo verificar hash contra dispositivo original"
fi

# Completar metadatos
cat >> "${META_FILE}" << EOFMETA2
fecha_fin=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
tamano_imagen=$(stat -c %s "${IMAGE_FILE}" 2>/dev/null || echo "desconocido")
sha256_imagen=${SHA256_IMG}
md5_imagen=${MD5_IMG}
estado=completado
EOFMETA2

chmod 600 "${IMAGE_FILE}" "${HASH_FILE}" "${META_FILE}" "${LOG_FILE}" 2>/dev/null

log_info "=== Imagen forense completada ==="
log_info "Imagen:    ${IMAGE_FILE}"
log_info "Hashes:    ${HASH_FILE}"
log_info "Metadatos: ${META_FILE}"
log_info "Log:       ${LOG_FILE}"
echo ""
echo "Para verificar integridad:"
echo "  sha256sum ${IMAGE_FILE}"
echo "  Comparar con: ${SHA256_IMG}"
EOFDISK
    chmod +x "${FORENSICS_TOOLS}/forense-imagen-disco.sh"
    log_change "Creado" "${FORENSICS_TOOLS}/forense-imagen-disco.sh"

    log_info "Herramienta de imagen forense instalada"
    log_info "Uso: forense-imagen-disco.sh /dev/sdX [directorio_salida]"
else
    log_skip "Imagen de disco forense"
fi

# ============================================================
# S3: PRESERVACION DE DATOS VOLATILES
# ============================================================
log_section "S3: PRESERVACION DE DATOS VOLATILES"

echo "Captura datos volatiles en orden de volatilidad:"
echo "  - Conexiones de red (ss/netstat)"
echo "  - Procesos en ejecucion (ps aux)"
echo "  - Archivos abiertos (lsof)"
echo "  - Tablas de enrutamiento, cache ARP, cache DNS"
echo "  - Usuarios conectados, variables de entorno"
echo "  - Modulos de kernel cargados, servicios activos"
echo ""

if ask "¿Instalar herramienta de preservacion de datos volatiles?"; then

    cat > "${FORENSICS_TOOLS}/forense-volatil.sh" << 'EOFVOL'
#!/bin/bash
# ============================================================
# forense-volatil.sh - Preservacion de datos volatiles
# ============================================================
# Captura datos volatiles en orden de volatilidad (RFC 3227).
# Uso: forense-volatil.sh [directorio_salida]
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[X]${NC} $1"; }

if [[ $EUID -ne 0 ]]; then
    log_error "Debe ejecutarse como root"
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
HOSTNAME_SHORT=$(hostname -s)
OUTPUT_DIR="${1:-/var/forensics/volatile}/volatil-${HOSTNAME_SHORT}-${TIMESTAMP}"
mkdir -p "${OUTPUT_DIR}"
chmod 700 "${OUTPUT_DIR}"

log_info "=== Preservacion de Datos Volatiles ==="
log_info "Fecha/hora:  $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
log_info "Hostname:    ${HOSTNAME_SHORT}"
log_info "Directorio:  ${OUTPUT_DIR}"
echo ""
log_info "Siguiendo orden de volatilidad (RFC 3227)..."

# Funcion auxiliar para capturar con timestamp
capturar() {
    local nombre="$1"
    local archivo="${OUTPUT_DIR}/${nombre}.txt"
    local desc="$2"
    shift 2
    log_info "Capturando: ${desc}..."
    {
        echo "# ${desc}"
        echo "# Capturado: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo "# Comando: $*"
        echo "# ============================================"
        echo ""
    } > "${archivo}"
    eval "$@" >> "${archivo}" 2>&1 || true
    log_info "  -> ${archivo} ($(wc -l < "${archivo}") lineas)"
}

# 1. Conexiones de red (mas volatil)
capturar "01-conexiones-red-ss" "Conexiones de red (ss)" \
    "ss -tulnpa"

capturar "01-conexiones-red-netstat" "Conexiones de red (netstat)" \
    "netstat -tulnpa 2>/dev/null || echo 'netstat no disponible'"

capturar "01-sockets-raw" "Sockets raw" \
    "ss -w -a"

# 2. Procesos en ejecucion
capturar "02-procesos-full" "Procesos en ejecucion (completo)" \
    "ps auxwwf"

capturar "02-procesos-tree" "Arbol de procesos" \
    "pstree -alpn 2>/dev/null || ps axjf"

capturar "02-procesos-detalle" "Detalle de procesos (/proc)" \
    'for pid in /proc/[0-9]*; do p=$(basename $pid); echo "=== PID $p ==="; cat $pid/cmdline 2>/dev/null | tr "\0" " "; echo ""; cat $pid/status 2>/dev/null | head -5; echo ""; done'

# 3. Archivos abiertos
capturar "03-archivos-abiertos" "Archivos abiertos (lsof)" \
    "lsof -n -P 2>/dev/null || echo 'lsof no disponible'"

capturar "03-archivos-eliminados-abiertos" "Archivos eliminados pero abiertos" \
    "lsof +L1 2>/dev/null || echo 'lsof no disponible'"

# 4. Tablas de enrutamiento
capturar "04-rutas" "Tablas de enrutamiento" \
    "ip route show table all"

capturar "04-reglas-routing" "Reglas de routing" \
    "ip rule show"

# 5. Cache ARP
capturar "05-cache-arp" "Cache ARP" \
    "ip neigh show"

capturar "05-arp-tabla" "Tabla ARP clasica" \
    "arp -a 2>/dev/null || echo 'arp no disponible'"

# 6. Cache DNS
capturar "06-cache-dns" "Cache DNS (systemd-resolved)" \
    "resolvectl statistics 2>/dev/null; echo '---'; resolvectl status 2>/dev/null || echo 'systemd-resolved no activo'"

capturar "06-dns-config" "Configuracion DNS" \
    "cat /etc/resolv.conf 2>/dev/null; echo '---'; cat /etc/nsswitch.conf 2>/dev/null"

# 7. Usuarios conectados
capturar "07-usuarios-conectados" "Usuarios conectados" \
    "who -a"

capturar "07-sesiones-login" "Sesiones de login" \
    "w"

capturar "07-utmp-wtmp" "Ultimo acceso (last)" \
    "last -50"

capturar "07-last-failed" "Accesos fallidos (lastb)" \
    "lastb -50 2>/dev/null || echo 'lastb no disponible'"

# 8. Variables de entorno
capturar "08-entorno-root" "Variables de entorno (root)" \
    "env | sort"

capturar "08-entorno-procesos" "Variables de entorno de procesos" \
    'for pid in $(ps -eo pid --no-headers | head -50); do echo "=== PID $pid ($(cat /proc/$pid/comm 2>/dev/null)) ==="; cat /proc/$pid/environ 2>/dev/null | tr "\0" "\n" | sort; echo ""; done'

# 9. Modulos de kernel cargados
capturar "09-modulos-kernel" "Modulos de kernel cargados" \
    "lsmod"

capturar "09-modulos-detalle" "Detalle de modulos" \
    'lsmod | tail -n +2 | while read mod rest; do echo "=== $mod ==="; modinfo "$mod" 2>/dev/null | head -10; echo ""; done'

# 10. Servicios activos
capturar "10-servicios-activos" "Servicios activos (systemd)" \
    "systemctl list-units --type=service --state=running --no-pager"

capturar "10-servicios-todos" "Todos los servicios" \
    "systemctl list-units --type=service --all --no-pager"

capturar "10-timers-activos" "Timers programados" \
    "systemctl list-timers --all --no-pager"

# 11. Informacion adicional del sistema
capturar "11-uptime" "Uptime del sistema" \
    "uptime; echo '---'; cat /proc/uptime"

capturar "11-fecha-sistema" "Fecha y hora del sistema" \
    "date -u; echo '---'; timedatectl status 2>/dev/null || true"

capturar "11-interfaces-red" "Interfaces de red" \
    "ip addr show; echo '---'; ip link show"

capturar "11-iptables" "Reglas de firewall (iptables)" \
    "iptables -L -n -v 2>/dev/null; echo '=== nat ==='; iptables -t nat -L -n -v 2>/dev/null"

capturar "11-nftables" "Reglas de firewall (nftables)" \
    "nft list ruleset 2>/dev/null || echo 'nftables no disponible'"

capturar "11-montajes" "Puntos de montaje" \
    "mount; echo '---'; df -h; echo '---'; cat /proc/mounts"

# Generar indice
{
    echo "# Indice de datos volatiles capturados"
    echo "# Fecha: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo "# Hostname: ${HOSTNAME_SHORT}"
    echo "# ============================================"
    echo ""
    for f in "${OUTPUT_DIR}"/*.txt; do
        if [[ -f "$f" ]]; then
            fname=$(basename "$f")
            lines=$(wc -l < "$f")
            size=$(du -h "$f" | awk '{print $1}')
            echo "${fname}  (${lines} lineas, ${size})"
        fi
    done
} > "${OUTPUT_DIR}/00-INDICE.txt"

# Calcular hashes de todos los archivos
log_info "Calculando hashes de archivos capturados..."
(cd "${OUTPUT_DIR}" && sha256sum *.txt > SHA256SUMS)

log_info "=== Captura de datos volatiles completada ==="
log_info "Directorio: ${OUTPUT_DIR}"
log_info "Archivos:   $(find "${OUTPUT_DIR}" -type f | wc -l)"
log_info "Indice:     ${OUTPUT_DIR}/00-INDICE.txt"
EOFVOL
    chmod +x "${FORENSICS_TOOLS}/forense-volatil.sh"
    log_change "Creado" "${FORENSICS_TOOLS}/forense-volatil.sh"

    log_info "Herramienta de datos volatiles instalada"
    log_info "Uso: forense-volatil.sh [directorio_salida]"
else
    log_skip "Preservacion de datos volatiles"
fi

# ============================================================
# S4: RECOPILACION DE ARTEFACTOS
# ============================================================
log_section "S4: RECOPILACION DE ARTEFACTOS"

echo "Recopila artefactos del sistema para analisis forense:"
echo "  - Logs de autenticacion, syslog, journal"
echo "  - Crontabs, SSH authorized_keys, historiales de shell"
echo "  - Archivos modificados recientemente, SUID/SGID"
echo "  - Archivos world-writable, ocultos en /tmp"
echo "  - Archivos sospechosos en /dev"
echo "  - Empaqueta todo en tarball firmado"
echo ""

if ask "¿Instalar herramienta de recopilacion de artefactos?"; then

    cat > "${FORENSICS_TOOLS}/forense-artefactos.sh" << 'EOFART'
#!/bin/bash
# ============================================================
# forense-artefactos.sh - Recopilacion de artefactos forenses
# ============================================================
# Recopila artefactos del sistema para investigacion.
# Uso: forense-artefactos.sh [directorio_salida] [dias_atras]
#   dias_atras: buscar archivos modificados en los ultimos N dias (default: 7)
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[X]${NC} $1"; }

if [[ $EUID -ne 0 ]]; then
    log_error "Debe ejecutarse como root"
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
HOSTNAME_SHORT=$(hostname -s)
OUTPUT_BASE="${1:-/var/forensics/artifacts}"
DAYS_BACK="${2:-7}"
OUTPUT_DIR="${OUTPUT_BASE}/artefactos-${HOSTNAME_SHORT}-${TIMESTAMP}"

mkdir -p "${OUTPUT_DIR}"/{logs,cron,ssh,shell-history,filesystem,permissions}
chmod 700 "${OUTPUT_DIR}"

log_info "=== Recopilacion de Artefactos Forenses ==="
log_info "Fecha/hora:    $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
log_info "Hostname:      ${HOSTNAME_SHORT}"
log_info "Directorio:    ${OUTPUT_DIR}"
log_info "Dias atras:    ${DAYS_BACK}"
echo ""

# --- Logs de autenticacion ---
log_info "Recopilando logs de autenticacion..."
for logfile in /var/log/auth.log /var/log/secure /var/log/auth /var/log/messages; do
    if [[ -f "${logfile}" ]]; then
        cp -a "${logfile}"* "${OUTPUT_DIR}/logs/" 2>/dev/null || true
        log_info "  -> Copiado: ${logfile}"
    fi
done

# Logs rotados
for logfile in /var/log/auth.log.* /var/log/secure-* /var/log/secure.* /var/log/messages-* /var/log/messages.*; do
    if [[ -f "${logfile}" ]]; then
        cp -a "${logfile}" "${OUTPUT_DIR}/logs/" 2>/dev/null || true
    fi
done

# --- Syslog ---
log_info "Recopilando syslog..."
for logfile in /var/log/syslog /var/log/syslog.* /var/log/kern.log /var/log/kern.log.*; do
    if [[ -f "${logfile}" ]]; then
        cp -a "${logfile}" "${OUTPUT_DIR}/logs/" 2>/dev/null || true
    fi
done

# --- Journal (systemd) ---
log_info "Recopilando journal de systemd..."
if command -v journalctl &>/dev/null; then
    journalctl --since "${DAYS_BACK} days ago" --no-pager > "${OUTPUT_DIR}/logs/journal-${DAYS_BACK}d.txt" 2>/dev/null || true
    journalctl --since "${DAYS_BACK} days ago" --priority=0..4 --no-pager > "${OUTPUT_DIR}/logs/journal-errores-${DAYS_BACK}d.txt" 2>/dev/null || true
    journalctl --since "${DAYS_BACK} days ago" -u sshd --no-pager > "${OUTPUT_DIR}/logs/journal-sshd-${DAYS_BACK}d.txt" 2>/dev/null || true
    log_info "  -> Journal exportado (${DAYS_BACK} dias)"
fi

# --- Crontabs ---
log_info "Recopilando crontabs..."
# Crontab del sistema
for crondir in /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    if [[ -e "${crondir}" ]]; then
        cp -a "${crondir}" "${OUTPUT_DIR}/cron/" 2>/dev/null || true
    fi
done
# Crontabs de usuarios
if [[ -d /var/spool/cron ]]; then
    cp -a /var/spool/cron "${OUTPUT_DIR}/cron/spool-cron" 2>/dev/null || true
fi
if [[ -d /var/spool/cron/crontabs ]]; then
    cp -a /var/spool/cron/crontabs "${OUTPUT_DIR}/cron/crontabs-users" 2>/dev/null || true
fi
# Systemd timers
if command -v systemctl &>/dev/null; then
    systemctl list-timers --all --no-pager > "${OUTPUT_DIR}/cron/systemd-timers.txt" 2>/dev/null || true
fi
# at jobs
if [[ -d /var/spool/at ]]; then
    cp -a /var/spool/at "${OUTPUT_DIR}/cron/at-jobs" 2>/dev/null || true
fi
log_info "  -> Crontabs recopilados"

# --- SSH authorized_keys ---
log_info "Recopilando SSH authorized_keys..."
{
    echo "# SSH authorized_keys encontradas"
    echo "# Fecha: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo ""
    while IFS=: read -r user _ uid _ _ home _; do
        if [[ ${uid} -ge 0 ]] && [[ -d "${home}" ]]; then
            for keyfile in "${home}/.ssh/authorized_keys" "${home}/.ssh/authorized_keys2"; do
                if [[ -f "${keyfile}" ]]; then
                    echo "=== ${user} (${keyfile}) ==="
                    cat "${keyfile}"
                    echo ""
                fi
            done
        fi
    done < /etc/passwd
} > "${OUTPUT_DIR}/ssh/authorized_keys_all.txt" 2>/dev/null

# SSH known_hosts
{
    echo "# SSH known_hosts"
    while IFS=: read -r user _ uid _ _ home _; do
        if [[ ${uid} -ge 0 ]] && [[ -f "${home}/.ssh/known_hosts" ]]; then
            echo "=== ${user} ==="
            cat "${home}/.ssh/known_hosts"
            echo ""
        fi
    done < /etc/passwd
} > "${OUTPUT_DIR}/ssh/known_hosts_all.txt" 2>/dev/null

# Configuracion SSH
cp -a /etc/ssh/sshd_config "${OUTPUT_DIR}/ssh/" 2>/dev/null || true
cp -a /etc/ssh/sshd_config.d "${OUTPUT_DIR}/ssh/" 2>/dev/null || true
cp -a /etc/ssh/ssh_config "${OUTPUT_DIR}/ssh/" 2>/dev/null || true
log_info "  -> SSH keys y config recopilados"

# --- Shell histories ---
log_info "Recopilando historiales de shell..."
while IFS=: read -r user _ uid _ _ home _; do
    if [[ ${uid} -ge 0 ]] && [[ -d "${home}" ]]; then
        for histfile in .bash_history .zsh_history .sh_history .history .python_history .mysql_history .psql_history; do
            if [[ -f "${home}/${histfile}" ]]; then
                mkdir -p "${OUTPUT_DIR}/shell-history/${user}"
                cp -a "${home}/${histfile}" "${OUTPUT_DIR}/shell-history/${user}/" 2>/dev/null || true
            fi
        done
    fi
done < /etc/passwd
log_info "  -> Historiales de shell recopilados"

# --- Archivos modificados recientemente ---
log_info "Buscando archivos modificados en los ultimos ${DAYS_BACK} dias..."
find / -xdev -type f -mtime "-${DAYS_BACK}" -not -path '/proc/*' -not -path '/sys/*' -not -path '/run/*' \
    -printf '%T@ %Tc %p\n' 2>/dev/null | sort -rn | head -500 \
    > "${OUTPUT_DIR}/filesystem/archivos-recientes-${DAYS_BACK}d.txt" 2>/dev/null || true
log_info "  -> Archivos recientes listados"

# --- Binarios SUID/SGID ---
log_info "Buscando binarios SUID/SGID..."
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f \
    -printf '%M %u:%g %p\n' 2>/dev/null \
    > "${OUTPUT_DIR}/permissions/suid-sgid.txt" 2>/dev/null || true
log_info "  -> SUID/SGID binarios listados"

# --- Archivos world-writable ---
log_info "Buscando archivos world-writable..."
find / -xdev -type f -perm -0002 -not -path '/proc/*' -not -path '/sys/*' \
    -printf '%M %u:%g %p\n' 2>/dev/null \
    > "${OUTPUT_DIR}/permissions/world-writable.txt" 2>/dev/null || true
log_info "  -> World-writable listados"

# --- Permisos inusuales ---
log_info "Buscando permisos inusuales..."
find / -xdev -type f \( -perm -0777 -o \( -not -user root -a -perm -4000 \) \) \
    -printf '%M %u:%g %p\n' 2>/dev/null \
    > "${OUTPUT_DIR}/permissions/permisos-inusuales.txt" 2>/dev/null || true

# --- Archivos ocultos en /tmp ---
log_info "Buscando archivos ocultos en /tmp..."
find /tmp /var/tmp -name ".*" -type f \
    -printf '%T@ %Tc %M %u:%g %s %p\n' 2>/dev/null | sort -rn \
    > "${OUTPUT_DIR}/filesystem/ocultos-tmp.txt" 2>/dev/null || true
log_info "  -> Archivos ocultos en /tmp listados"

# --- Archivos sospechosos en /dev ---
log_info "Buscando archivos sospechosos en /dev..."
find /dev -type f \
    -printf '%M %u:%g %s %p\n' 2>/dev/null \
    > "${OUTPUT_DIR}/filesystem/dev-files.txt" 2>/dev/null || true

find /dev -not -type c -not -type b -not -type d -not -type l \
    -printf '%y %M %u:%g %p\n' 2>/dev/null \
    > "${OUTPUT_DIR}/filesystem/dev-sospechosos.txt" 2>/dev/null || true
log_info "  -> Archivos en /dev analizados"

# --- Archivos sin propietario ---
log_info "Buscando archivos sin propietario valido..."
find / -xdev \( -nouser -o -nogroup \) -type f \
    -printf '%M %u:%g %p\n' 2>/dev/null | head -200 \
    > "${OUTPUT_DIR}/permissions/sin-propietario.txt" 2>/dev/null || true

# --- Generar indice ---
{
    echo "# Indice de artefactos recopilados"
    echo "# Fecha: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo "# Hostname: ${HOSTNAME_SHORT}"
    echo "# ============================================"
    echo ""
    find "${OUTPUT_DIR}" -type f | sort | while read -r f; do
        size=$(du -h "$f" | awk '{print $1}')
        echo "$(echo "$f" | sed "s|${OUTPUT_DIR}/||")  ($size)"
    done
} > "${OUTPUT_DIR}/00-INDICE.txt"

# --- Empaquetar tarball ---
TARBALL="${OUTPUT_BASE}/artefactos-${HOSTNAME_SHORT}-${TIMESTAMP}.tar.gz"
log_info "Empaquetando artefactos..."
tar czf "${TARBALL}" -C "${OUTPUT_BASE}" "artefactos-${HOSTNAME_SHORT}-${TIMESTAMP}" 2>/dev/null
chmod 600 "${TARBALL}"

# Hash del tarball
SHA256_TAR=$(sha256sum "${TARBALL}" | awk '{print $1}')
echo "${SHA256_TAR}  ${TARBALL}" > "${TARBALL}.sha256"
log_info "SHA-256 tarball: ${SHA256_TAR}"

log_info "=== Recopilacion de artefactos completada ==="
log_info "Directorio: ${OUTPUT_DIR}"
log_info "Tarball:    ${TARBALL}"
log_info "Hash:       ${TARBALL}.sha256"
EOFART
    chmod +x "${FORENSICS_TOOLS}/forense-artefactos.sh"
    log_change "Creado" "${FORENSICS_TOOLS}/forense-artefactos.sh"

    log_info "Herramienta de artefactos forenses instalada"
    log_info "Uso: forense-artefactos.sh [directorio] [dias_atras]"
else
    log_skip "Recopilacion de artefactos"
fi

# ============================================================
# S5: CONSTRUCCION DE LINEA TEMPORAL
# ============================================================
log_section "S5: CONSTRUCCION DE LINEA TEMPORAL"

echo "Construye linea temporal unificada de eventos:"
echo "  - Timestamps del sistema de archivos (MAC times)"
echo "  - Entradas de log del sistema"
echo "  - Journal de systemd"
echo "  - wtmp/btmp (logins exitosos y fallidos)"
echo "  - lastlog"
echo "  - Salida en formato CSV para analisis"
echo "  - Soporte de filtrado por rango temporal"
echo ""

if ask "¿Instalar herramienta de linea temporal forense?"; then

    cat > "${FORENSICS_TOOLS}/forense-timeline.sh" << 'EOFTL'
#!/bin/bash
# ============================================================
# forense-timeline.sh - Construccion de linea temporal forense
# ============================================================
# Genera timeline unificado en formato CSV.
# Uso: forense-timeline.sh [directorio_salida] [fecha_inicio] [fecha_fin]
#   fecha_inicio/fin: formato YYYY-MM-DD (default: ultimos 7 dias)
# Salida CSV: timestamp,fuente,accion,detalle
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[X]${NC} $1"; }

if [[ $EUID -ne 0 ]]; then
    log_error "Debe ejecutarse como root"
    exit 1
fi

TIMESTAMP_NOW=$(date +%Y%m%d-%H%M%S)
HOSTNAME_SHORT=$(hostname -s)
OUTPUT_DIR="${1:-/var/forensics/timeline}"
DATE_START="${2:-$(date -d '7 days ago' '+%Y-%m-%d' 2>/dev/null || date -v-7d '+%Y-%m-%d' 2>/dev/null || echo '')}"
DATE_END="${3:-$(date '+%Y-%m-%d')}"

mkdir -p "${OUTPUT_DIR}"
chmod 700 "${OUTPUT_DIR}"

TIMELINE_FILE="${OUTPUT_DIR}/timeline-${HOSTNAME_SHORT}-${TIMESTAMP_NOW}.csv"
TIMELINE_TMP="${OUTPUT_DIR}/.timeline-tmp-$$"

log_info "=== Construccion de Linea Temporal Forense ==="
log_info "Fecha/hora:    $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
log_info "Hostname:      ${HOSTNAME_SHORT}"
log_info "Rango:         ${DATE_START:-sin_limite} a ${DATE_END}"
log_info "Salida:        ${TIMELINE_FILE}"
echo ""

# Cabecera CSV
echo "timestamp,fuente,accion,detalle" > "${TIMELINE_FILE}"

# Archivo temporal para recopilar y luego ordenar
> "${TIMELINE_TMP}"

# --- 1. Filesystem timestamps (MAC times) ---
log_info "Recopilando timestamps del sistema de archivos..."
FIND_ARGS=""
if [[ -n "${DATE_START}" ]]; then
    FIND_ARGS="-newermt ${DATE_START}"
fi

# Modified time
find / -xdev -type f ${FIND_ARGS} -not -path '/proc/*' -not -path '/sys/*' -not -path '/run/*' \
    -printf '%T+ filesystem file_modified %p\n' 2>/dev/null | head -10000 >> "${TIMELINE_TMP}" || true

# Access time (si noatime no esta activo)
find / -xdev -type f ${FIND_ARGS} -not -path '/proc/*' -not -path '/sys/*' -not -path '/run/*' \
    -printf '%A+ filesystem file_accessed %p\n' 2>/dev/null | head -5000 >> "${TIMELINE_TMP}" || true

# Change time (inode change)
find / -xdev -type f ${FIND_ARGS} -not -path '/proc/*' -not -path '/sys/*' -not -path '/run/*' \
    -printf '%C+ filesystem inode_changed %p\n' 2>/dev/null | head -5000 >> "${TIMELINE_TMP}" || true

log_info "  -> Timestamps de filesystem recopilados"

# --- 2. Log entries ---
log_info "Procesando entradas de log..."
for logfile in /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages; do
    if [[ -f "${logfile}" ]]; then
        logname=$(basename "${logfile}")
        while IFS= read -r line; do
            # Extraer timestamp del formato syslog: "Mon DD HH:MM:SS"
            ts_raw=$(echo "$line" | awk '{print $1, $2, $3}')
            # Convertir a ISO format
            ts_iso=$(date -d "${ts_raw}" '+%Y-%m-%dT%H:%M:%S' 2>/dev/null || echo "${ts_raw}")
            # Limpiar comillas del detalle para CSV
            detail=$(echo "$line" | sed 's/,/;/g')
            echo "${ts_iso} ${logname} log_entry ${detail}" >> "${TIMELINE_TMP}"
        done < "${logfile}" 2>/dev/null || true
    fi
done
log_info "  -> Entradas de log procesadas"

# --- 3. Journal entries ---
log_info "Procesando journal de systemd..."
if command -v journalctl &>/dev/null; then
    JOURNAL_ARGS=""
    if [[ -n "${DATE_START}" ]]; then
        JOURNAL_ARGS="--since=${DATE_START}"
    fi
    if [[ -n "${DATE_END}" ]]; then
        JOURNAL_ARGS="${JOURNAL_ARGS} --until=${DATE_END} 23:59:59"
    fi
    journalctl ${JOURNAL_ARGS} -o short-iso --no-pager 2>/dev/null | while IFS= read -r line; do
        ts=$(echo "$line" | awk '{print $1}')
        detail=$(echo "$line" | cut -d' ' -f2- | sed 's/,/;/g')
        echo "${ts} journal journal_entry ${detail}" >> "${TIMELINE_TMP}"
    done || true
    log_info "  -> Journal procesado"
fi

# --- 4. wtmp (logins exitosos) ---
log_info "Procesando wtmp (logins exitosos)..."
if command -v last &>/dev/null; then
    last -F -w 2>/dev/null | while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        [[ "$line" == *"begins"* ]] && continue
        ts_raw=$(echo "$line" | awk '{for(i=4;i<=8;i++) printf "%s ", $i; print ""}' | sed 's/ *$//')
        ts_iso=$(date -d "${ts_raw}" '+%Y-%m-%dT%H:%M:%S' 2>/dev/null || echo "${ts_raw}")
        user=$(echo "$line" | awk '{print $1}')
        terminal=$(echo "$line" | awk '{print $2}')
        host=$(echo "$line" | awk '{print $3}')
        echo "${ts_iso} wtmp user_login user=${user};tty=${terminal};from=${host}" >> "${TIMELINE_TMP}"
    done || true
fi
log_info "  -> wtmp procesado"

# --- 5. btmp (logins fallidos) ---
log_info "Procesando btmp (logins fallidos)..."
if command -v lastb &>/dev/null; then
    lastb -F -w 2>/dev/null | while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        [[ "$line" == *"begins"* ]] && continue
        ts_raw=$(echo "$line" | awk '{for(i=4;i<=8;i++) printf "%s ", $i; print ""}' | sed 's/ *$//')
        ts_iso=$(date -d "${ts_raw}" '+%Y-%m-%dT%H:%M:%S' 2>/dev/null || echo "${ts_raw}")
        user=$(echo "$line" | awk '{print $1}')
        terminal=$(echo "$line" | awk '{print $2}')
        host=$(echo "$line" | awk '{print $3}')
        echo "${ts_iso} btmp failed_login user=${user};tty=${terminal};from=${host}" >> "${TIMELINE_TMP}"
    done || true
fi
log_info "  -> btmp procesado"

# --- 6. lastlog ---
log_info "Procesando lastlog..."
if command -v lastlog &>/dev/null; then
    lastlog 2>/dev/null | tail -n +2 | while IFS= read -r line; do
        user=$(echo "$line" | awk '{print $1}')
        port=$(echo "$line" | awk '{print $2}')
        rest=$(echo "$line" | awk '{for(i=3;i<=NF;i++) printf "%s ", $i; print ""}')
        if [[ "${rest}" != *"Never"* ]] && [[ -n "${rest// /}" ]]; then
            ts_iso=$(date -d "${rest}" '+%Y-%m-%dT%H:%M:%S' 2>/dev/null || echo "${rest}")
            echo "${ts_iso} lastlog last_login user=${user};port=${port}" >> "${TIMELINE_TMP}"
        fi
    done || true
fi
log_info "  -> lastlog procesado"

# --- Ordenar y formatear timeline final ---
log_info "Ordenando y generando timeline final..."
sort "${TIMELINE_TMP}" 2>/dev/null | while IFS= read -r line; do
    ts=$(echo "$line" | awk '{print $1}')
    src=$(echo "$line" | awk '{print $2}')
    action=$(echo "$line" | awk '{print $3}')
    detail=$(echo "$line" | cut -d' ' -f4- | sed 's/"/\\"/g')
    echo "\"${ts}\",\"${src}\",\"${action}\",\"${detail}\"" >> "${TIMELINE_FILE}"
done

# Limpiar temporal
rm -f "${TIMELINE_TMP}"

# Estadisticas
TOTAL_ENTRIES=$(wc -l < "${TIMELINE_FILE}")
TOTAL_ENTRIES=$((TOTAL_ENTRIES - 1))  # descontar cabecera

log_info "=== Timeline forense completado ==="
log_info "Archivo:   ${TIMELINE_FILE}"
log_info "Entradas:  ${TOTAL_ENTRIES}"
log_info "Formato:   CSV (timestamp,fuente,accion,detalle)"
echo ""
echo "Para analizar:"
echo "  head -20 ${TIMELINE_FILE}"
echo "  grep 'failed_login' ${TIMELINE_FILE}"
echo "  grep 'file_modified' ${TIMELINE_FILE} | grep '/etc/'"
EOFTL
    chmod +x "${FORENSICS_TOOLS}/forense-timeline.sh"
    log_change "Creado" "${FORENSICS_TOOLS}/forense-timeline.sh"

    log_info "Herramienta de linea temporal instalada"
    log_info "Uso: forense-timeline.sh [directorio] [fecha_inicio] [fecha_fin]"
else
    log_skip "Construccion de linea temporal"
fi

# ============================================================
# S6: TOOLKIT DE ANALISIS DE MALWARE (YARA)
# ============================================================
log_section "S6: TOOLKIT DE ANALISIS DE MALWARE"

echo "Instala toolkit de analisis de malware:"
echo "  - YARA para deteccion basada en reglas"
echo "  - Reglas base: crypto miners, reverse shells, webshells"
echo "  - Reglas: rootkit indicators, scripts sospechosos"
echo "  - Reglas: payloads codificados"
echo "  - Script de escaneo: forense-yara-scan.sh"
echo "  - Analisis estatico: forense-analizar-binario.sh"
echo ""

if ask "¿Instalar toolkit de analisis de malware?"; then

    # Instalar YARA
    log_info "Instalando YARA..."
    case "$DISTRO_FAMILY" in
        debian)
            pkg_install yara || log_warn "YARA no disponible via apt, considerar compilar desde fuente"
            ;;
        rhel)
            # YARA puede estar en EPEL
            pkg_install yara 2>/dev/null || {
                log_warn "YARA no disponible en repos standard, intentando EPEL..."
                pkg_install epel-release 2>/dev/null || true
                pkg_install yara 2>/dev/null || log_warn "Instalar YARA manualmente: https://github.com/VirusTotal/yara"
            }
            ;;
        suse)
            pkg_install yara 2>/dev/null || log_warn "YARA no disponible, compilar desde fuente"
            ;;
        arch)
            pkg_install yara || log_warn "YARA no disponible"
            ;;
    esac

    # Instalar herramientas para analisis estatico
    pkg_install file binutils || true

    # Crear directorio de reglas YARA
    mkdir -p "${FORENSICS_ETC}/yara-rules"
    chmod 750 "${FORENSICS_ETC}/yara-rules"

    # --- Regla: Crypto miners ---
    cat > "${FORENSICS_ETC}/yara-rules/crypto_miners.yar" << 'EOFYARA1'
rule CryptoMiner_Strings {
    meta:
        description = "Detecta indicadores de mineros de criptomonedas"
        author = "securizar"
        severity = "alta"
    strings:
        $pool1 = "stratum+tcp://" nocase
        $pool2 = "stratum+ssl://" nocase
        $pool3 = "pool.minexmr.com" nocase
        $pool4 = "xmrpool.eu" nocase
        $pool5 = "nanopool.org" nocase
        $pool6 = "hashvault.pro" nocase
        $pool7 = "supportxmr.com" nocase
        $miner1 = "xmrig" nocase
        $miner2 = "cpuminer" nocase
        $miner3 = "cgminer" nocase
        $miner4 = "bfgminer" nocase
        $miner5 = "minerd" nocase
        $miner6 = "cryptonight" nocase
        $miner7 = "RandomX" nocase
        $wallet1 = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/
        $config1 = "\"algo\"" nocase
        $config2 = "\"coin\"" nocase
        $config3 = "\"pool\"" nocase
    condition:
        any of ($pool*) or
        (any of ($miner*) and any of ($config*)) or
        (any of ($miner*) and $wallet1)
}
EOFYARA1
    log_change "Creado" "${FORENSICS_ETC}/yara-rules/crypto_miners.yar"

    # --- Regla: Reverse shells ---
    cat > "${FORENSICS_ETC}/yara-rules/reverse_shells.yar" << 'EOFYARA2'
rule ReverseShell_Bash {
    meta:
        description = "Detecta reverse shells en bash"
        author = "securizar"
        severity = "critica"
    strings:
        $bash1 = "bash -i >& /dev/tcp/" nocase
        $bash2 = "bash -c 'bash -i >& /dev/tcp/" nocase
        $bash3 = "/dev/tcp/" nocase
        $bash4 = "0>&1" nocase
        $nc1 = "nc -e /bin/" nocase
        $nc2 = "ncat -e /bin/" nocase
        $nc3 = "netcat -e /bin/" nocase
        $nc4 = "nc.traditional -e" nocase
        $py1 = "socket.socket" nocase
        $py2 = "subprocess.call" nocase
        $py3 = "pty.spawn" nocase
        $perl1 = "IO::Socket::INET" nocase
        $perl2 = "exec(\"/bin/" nocase
        $php1 = "fsockopen" nocase
        $php2 = "proc_open" nocase
        $php3 = "shell_exec" nocase
        $ruby1 = "TCPSocket" nocase
        $mkfifo = "mkfifo" nocase
        $devnull = "/dev/null" nocase
    condition:
        ($bash1 or $bash2) or
        ($bash3 and $bash4) or
        any of ($nc*) or
        ($py1 and $py2 and $py3) or
        ($perl1 and $perl2) or
        ($php1 and ($php2 or $php3)) or
        ($mkfifo and any of ($nc*))
}
EOFYARA2
    log_change "Creado" "${FORENSICS_ETC}/yara-rules/reverse_shells.yar"

    # --- Regla: Webshells ---
    cat > "${FORENSICS_ETC}/yara-rules/webshells.yar" << 'EOFYARA3'
rule WebShell_PHP {
    meta:
        description = "Detecta webshells PHP comunes"
        author = "securizar"
        severity = "critica"
    strings:
        $eval1 = "eval($_" nocase
        $eval2 = "eval(base64_decode" nocase
        $eval3 = "eval(gzinflate" nocase
        $eval4 = "eval(gzuncompress" nocase
        $eval5 = "eval(str_rot13" nocase
        $assert1 = "assert($_" nocase
        $exec1 = "system($_" nocase
        $exec2 = "passthru($_" nocase
        $exec3 = "shell_exec($_" nocase
        $exec4 = "exec($_" nocase
        $exec5 = "popen($_" nocase
        $exec6 = "proc_open($_" nocase
        $upload1 = "move_uploaded_file" nocase
        $c99 = "c99shell" nocase
        $r57 = "r57shell" nocase
        $wso = "WSO " nocase
        $b374k = "b374k" nocase
        $weevely = "weevely" nocase
        $preg = /preg_replace\s*\(\s*['"]\/.+\/e['"]/ nocase
    condition:
        any of ($eval*) or
        any of ($assert*) or
        any of ($exec*) or
        any of ($c99, $r57, $wso, $b374k, $weevely) or
        $preg
}

rule WebShell_JSP {
    meta:
        description = "Detecta webshells JSP"
        author = "securizar"
        severity = "critica"
    strings:
        $rt1 = "Runtime.getRuntime().exec" nocase
        $rt2 = "ProcessBuilder" nocase
        $cmd1 = "request.getParameter" nocase
    condition:
        ($rt1 or $rt2) and $cmd1
}
EOFYARA3
    log_change "Creado" "${FORENSICS_ETC}/yara-rules/webshells.yar"

    # --- Regla: Rootkit indicators ---
    cat > "${FORENSICS_ETC}/yara-rules/rootkit_indicators.yar" << 'EOFYARA4'
rule Rootkit_Indicators {
    meta:
        description = "Detecta indicadores de rootkits en Linux"
        author = "securizar"
        severity = "critica"
    strings:
        $ld1 = "/etc/ld.so.preload" nocase
        $ld2 = "LD_PRELOAD" nocase
        $proc1 = "/proc/self/maps" nocase
        $proc2 = "hide_pid" nocase
        $mod1 = "init_module" nocase
        $mod2 = "delete_module" nocase
        $sys1 = "sys_call_table" nocase
        $sys2 = "__NR_" nocase
        $hook1 = "kprobe" nocase
        $hook2 = "ftrace" nocase
        $hide1 = "hide_process" nocase
        $hide2 = "hidden_port" nocase
        $hide3 = "invisible" nocase
        $rk1 = "diamorphine" nocase
        $rk2 = "reptile" nocase
        $rk3 = "suterusu" nocase
        $rk4 = "adore-ng" nocase
        $rk5 = "knark" nocase
    condition:
        any of ($rk*) or
        ($sys1 and any of ($mod*)) or
        ($ld1 and any of ($hide*)) or
        (2 of ($hide*) and any of ($mod*))
}
EOFYARA4
    log_change "Creado" "${FORENSICS_ETC}/yara-rules/rootkit_indicators.yar"

    # --- Regla: Scripts sospechosos ---
    cat > "${FORENSICS_ETC}/yara-rules/suspicious_scripts.yar" << 'EOFYARA5'
rule Suspicious_Script_Patterns {
    meta:
        description = "Detecta patrones sospechosos en scripts"
        author = "securizar"
        severity = "media"
    strings:
        $wget_exec = /wget\s+.+\|\s*(ba)?sh/ nocase
        $curl_exec = /curl\s+.+\|\s*(ba)?sh/ nocase
        $chmod_suid = "chmod +s " nocase
        $chmod_777 = "chmod 777 " nocase
        $iptables_flush = "iptables -F" nocase
        $cron_inject = /echo\s+.+>\s*\/var\/spool\/cron/ nocase
        $ssh_key_inject = /echo\s+.+>\s*.*authorized_keys/ nocase
        $history_clear = "history -c" nocase
        $log_clear1 = "> /var/log/" nocase
        $log_clear2 = "truncate -s 0 /var/log/" nocase
        $dd_dev = /dd\s+if=\/dev\/(zero|urandom)\s+of=\/dev\/sd/ nocase
        $base64_pipe = /base64\s+-d\s*\|\s*(ba)?sh/ nocase
        $python_exec = /python[23]?\s+-c\s+['"]import\s/ nocase
        $disable_selinux = "setenforce 0" nocase
        $disable_fw = "systemctl stop firewalld" nocase
    condition:
        any of them
}
EOFYARA5
    log_change "Creado" "${FORENSICS_ETC}/yara-rules/suspicious_scripts.yar"

    # --- Regla: Payloads codificados ---
    cat > "${FORENSICS_ETC}/yara-rules/encoded_payloads.yar" << 'EOFYARA6'
rule Encoded_Payload {
    meta:
        description = "Detecta payloads codificados (base64, hex, etc.)"
        author = "securizar"
        severity = "media"
    strings:
        $b64_shebang = "IyEvYmluL2Jhc2g" // #!/bin/bash en base64
        $b64_binsh = "L2Jpbi9zaA" // /bin/sh en base64
        $b64_eval = "ZXZhbC" // eval en base64
        $b64_system = "c3lzdGVt" // system en base64
        $b64_wget = "d2dldCA" // wget en base64
        $b64_curl = "Y3VybCA" // curl en base64
        $hex_shebang = "2321" // #! en hex
        $long_b64 = /[A-Za-z0-9+\/]{200,}={0,2}/ // Cadena base64 larga
        $php_b64 = "base64_decode(" nocase
        $py_b64 = "b64decode(" nocase
        $perl_b64 = "decode_base64(" nocase
        $gzip_b64 = "H4sIA" // gzip magic en base64
        $xor_loop = /for\s*\(\s*\$?\w+\s*=\s*0.+\^\s*\$?\w+/ nocase
    condition:
        (any of ($b64_shebang, $b64_binsh, $b64_eval, $b64_system, $b64_wget, $b64_curl)) or
        ($long_b64 and any of ($php_b64, $py_b64, $perl_b64)) or
        ($gzip_b64 and any of ($php_b64, $py_b64)) or
        $xor_loop
}
EOFYARA6
    log_change "Creado" "${FORENSICS_ETC}/yara-rules/encoded_payloads.yar"

    # --- Script de escaneo YARA ---
    cat > "${FORENSICS_TOOLS}/forense-yara-scan.sh" << 'EOFYARASCAN'
#!/bin/bash
# ============================================================
# forense-yara-scan.sh - Escaneo YARA de directorios
# ============================================================
# Escanea directorios con todas las reglas YARA configuradas.
# Uso: forense-yara-scan.sh [directorio_a_escanear] [directorio_salida]
#   Default: escanea /tmp, /var/tmp, /dev/shm, /home, /var/www
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[X]${NC} $1"; }

if [[ $EUID -ne 0 ]]; then
    log_error "Debe ejecutarse como root"
    exit 1
fi

if ! command -v yara &>/dev/null; then
    log_error "YARA no esta instalado. Instalar primero."
    exit 1
fi

RULES_DIR="/etc/securizar/yara-rules"
SCAN_DIR="${1:-}"
OUTPUT_DIR="${2:-/var/forensics/yara}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
HOSTNAME_SHORT=$(hostname -s)
REPORT_FILE="${OUTPUT_DIR}/yara-scan-${HOSTNAME_SHORT}-${TIMESTAMP}.txt"
FINDINGS_FILE="${OUTPUT_DIR}/yara-hallazgos-${HOSTNAME_SHORT}-${TIMESTAMP}.txt"

mkdir -p "${OUTPUT_DIR}"
chmod 700 "${OUTPUT_DIR}"

if [[ ! -d "${RULES_DIR}" ]] || [[ -z "$(ls -A "${RULES_DIR}" 2>/dev/null)" ]]; then
    log_error "No hay reglas YARA en ${RULES_DIR}"
    exit 1
fi

# Directorios a escanear
if [[ -n "${SCAN_DIR}" ]]; then
    SCAN_DIRS=("${SCAN_DIR}")
else
    SCAN_DIRS=()
    for d in /tmp /var/tmp /dev/shm /home /var/www /opt /usr/local/bin /root; do
        [[ -d "$d" ]] && SCAN_DIRS+=("$d")
    done
fi

RULES_COUNT=$(find "${RULES_DIR}" -name "*.yar" -o -name "*.yara" | wc -l)

log_info "=== Escaneo YARA Forense ==="
log_info "Fecha/hora:    $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
log_info "Reglas:        ${RULES_COUNT} archivos en ${RULES_DIR}"
log_info "Directorios:   ${SCAN_DIRS[*]}"
log_info "Reporte:       ${REPORT_FILE}"
echo ""

{
    echo "# Reporte de escaneo YARA"
    echo "# Fecha: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo "# Hostname: ${HOSTNAME_SHORT}"
    echo "# Reglas: ${RULES_DIR} (${RULES_COUNT} archivos)"
    echo "# ============================================"
    echo ""
} > "${REPORT_FILE}"

> "${FINDINGS_FILE}"
TOTAL_FINDINGS=0
TOTAL_FILES=0

for scan_dir in "${SCAN_DIRS[@]}"; do
    if [[ ! -d "${scan_dir}" ]]; then
        continue
    fi

    log_info "Escaneando: ${scan_dir}..."
    echo "=== Directorio: ${scan_dir} ===" >> "${REPORT_FILE}"

    for rulefile in "${RULES_DIR}"/*.yar "${RULES_DIR}"/*.yara; do
        [[ -f "${rulefile}" ]] || continue
        rulename=$(basename "${rulefile}")

        # Escanear con YARA
        results=$(yara -r -w -s "${rulefile}" "${scan_dir}" 2>/dev/null || true)

        if [[ -n "${results}" ]]; then
            echo "${results}" >> "${REPORT_FILE}"
            echo "${results}" >> "${FINDINGS_FILE}"
            match_count=$(echo "${results}" | wc -l)
            TOTAL_FINDINGS=$((TOTAL_FINDINGS + match_count))
            log_warn "  [!] ${rulename}: ${match_count} coincidencias en ${scan_dir}"
        fi
    done

    files_scanned=$(find "${scan_dir}" -type f 2>/dev/null | wc -l)
    TOTAL_FILES=$((TOTAL_FILES + files_scanned))
    echo "" >> "${REPORT_FILE}"
done

echo "" >> "${REPORT_FILE}"
echo "# Resumen: ${TOTAL_FINDINGS} hallazgos en ${TOTAL_FILES} archivos escaneados" >> "${REPORT_FILE}"

log_info "=== Escaneo YARA completado ==="
log_info "Archivos escaneados: ${TOTAL_FILES}"
if [[ ${TOTAL_FINDINGS} -gt 0 ]]; then
    log_warn "HALLAZGOS: ${TOTAL_FINDINGS} coincidencias detectadas"
    log_warn "Ver detalles en: ${FINDINGS_FILE}"
else
    log_info "No se encontraron coincidencias"
fi
log_info "Reporte completo: ${REPORT_FILE}"
EOFYARASCAN
    chmod +x "${FORENSICS_TOOLS}/forense-yara-scan.sh"
    log_change "Creado" "${FORENSICS_TOOLS}/forense-yara-scan.sh"

    # --- Script de analisis estatico de binarios ---
    cat > "${FORENSICS_TOOLS}/forense-analizar-binario.sh" << 'EOFBIN'
#!/bin/bash
# ============================================================
# forense-analizar-binario.sh - Analisis estatico de binarios
# ============================================================
# Analisis estatico basico: tipo de archivo, strings, entropia,
# imports, secciones, checksums.
# Uso: forense-analizar-binario.sh <archivo> [directorio_salida]
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[X]${NC} $1"; }

if [[ $# -lt 1 ]]; then
    echo "Uso: $0 <archivo> [directorio_salida]"
    exit 1
fi

TARGET="$1"
OUTPUT_DIR="${2:-/var/forensics/yara}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BASENAME=$(basename "${TARGET}")
REPORT="${OUTPUT_DIR}/analisis-${BASENAME}-${TIMESTAMP}.txt"

if [[ ! -f "${TARGET}" ]]; then
    log_error "Archivo no encontrado: ${TARGET}"
    exit 1
fi

mkdir -p "${OUTPUT_DIR}"

log_info "=== Analisis Estatico de Binario ==="
log_info "Archivo:   ${TARGET}"
log_info "Reporte:   ${REPORT}"
echo ""

{
    echo "# Analisis Estatico Forense"
    echo "# Fecha: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo "# Archivo: ${TARGET}"
    echo "# ============================================"
    echo ""

    # 1. Informacion basica
    echo "=== INFORMACION BASICA ==="
    echo "Ruta completa: $(readlink -f "${TARGET}")"
    echo "Tamano: $(stat -c %s "${TARGET}" 2>/dev/null || echo 'N/A') bytes"
    echo "Permisos: $(stat -c '%A (%a)' "${TARGET}" 2>/dev/null || echo 'N/A')"
    echo "Propietario: $(stat -c '%U:%G' "${TARGET}" 2>/dev/null || echo 'N/A')"
    echo "Modificado: $(stat -c '%y' "${TARGET}" 2>/dev/null || echo 'N/A')"
    echo "Accedido: $(stat -c '%x' "${TARGET}" 2>/dev/null || echo 'N/A')"
    echo "Cambiado: $(stat -c '%z' "${TARGET}" 2>/dev/null || echo 'N/A')"
    echo ""

    # 2. Tipo de archivo
    echo "=== TIPO DE ARCHIVO ==="
    file "${TARGET}"
    file -i "${TARGET}"
    echo ""

    # 3. Checksums
    echo "=== CHECKSUMS ==="
    echo "MD5:    $(md5sum "${TARGET}" | awk '{print $1}')"
    echo "SHA1:   $(sha1sum "${TARGET}" | awk '{print $1}')"
    echo "SHA256: $(sha256sum "${TARGET}" | awk '{print $1}')"
    echo ""

    # 4. Strings relevantes
    echo "=== STRINGS RELEVANTES (URLs, IPs, paths) ==="
    if command -v strings &>/dev/null; then
        echo "--- URLs ---"
        strings "${TARGET}" | grep -iE 'https?://|ftp://' | sort -u | head -50
        echo ""
        echo "--- Direcciones IP ---"
        strings "${TARGET}" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort -u | head -50
        echo ""
        echo "--- Rutas de archivo ---"
        strings "${TARGET}" | grep -E '^/(bin|sbin|usr|etc|var|tmp|home|root)/' | sort -u | head -50
        echo ""
        echo "--- Emails ---"
        strings "${TARGET}" | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | sort -u | head -20
        echo ""
        echo "--- Comandos del sistema ---"
        strings "${TARGET}" | grep -iE '(wget|curl|nc |ncat|chmod|chown|iptables|crontab|passwd|shadow|sudoers)' | sort -u | head -30
        echo ""
        echo "--- Total strings ---"
        echo "Total: $(strings "${TARGET}" | wc -l) strings extraidas"
    else
        echo "strings no disponible (instalar binutils)"
    fi
    echo ""

    # 5. Entropia (indicador de empaquetado/cifrado)
    echo "=== ENTROPIA ==="
    if command -v ent &>/dev/null; then
        ent "${TARGET}" 2>/dev/null
    else
        # Calcular entropia basica con dd y od
        total_bytes=$(stat -c %s "${TARGET}" 2>/dev/null || echo 0)
        if [[ ${total_bytes} -gt 0 ]]; then
            unique_bytes=$(od -A n -t x1 "${TARGET}" | tr ' ' '\n' | sort -u | wc -l)
            echo "Bytes unicos: ${unique_bytes}/256"
            if [[ ${unique_bytes} -gt 240 ]]; then
                echo "AVISO: Alta entropia - posiblemente cifrado o empaquetado"
            elif [[ ${unique_bytes} -gt 200 ]]; then
                echo "Entropia moderada-alta"
            else
                echo "Entropia normal"
            fi
        fi
    fi
    echo ""

    # 6. ELF headers (si es binario ELF)
    if file "${TARGET}" | grep -q "ELF"; then
        echo "=== ELF HEADERS ==="
        if command -v readelf &>/dev/null; then
            echo "--- Header ---"
            readelf -h "${TARGET}" 2>/dev/null
            echo ""
            echo "--- Secciones ---"
            readelf -S "${TARGET}" 2>/dev/null
            echo ""
            echo "--- Simbolos dinamicos ---"
            readelf --dyn-syms "${TARGET}" 2>/dev/null | head -50
            echo ""
            echo "--- Bibliotecas compartidas ---"
            readelf -d "${TARGET}" 2>/dev/null | grep NEEDED
        elif command -v objdump &>/dev/null; then
            echo "--- Headers ---"
            objdump -f "${TARGET}" 2>/dev/null
            echo ""
            echo "--- Secciones ---"
            objdump -h "${TARGET}" 2>/dev/null
        fi
        echo ""

        # Verificar si esta stripped
        if file "${TARGET}" | grep -q "stripped"; then
            echo "NOTA: Binario esta stripped (sin simbolos de debug)"
        elif file "${TARGET}" | grep -q "not stripped"; then
            echo "NOTA: Binario no esta stripped (contiene simbolos de debug)"
        fi
        echo ""
    fi

    # 7. Paquete al que pertenece
    echo "=== PAQUETE DEL SISTEMA ==="
    case "$(cat /etc/os-release 2>/dev/null | grep "^ID_LIKE\|^ID=" | head -1)" in
        *suse*|*rhel*|*fedora*|*centos*)
            rpm -qf "${TARGET}" 2>/dev/null || echo "No pertenece a ningún paquete RPM"
            ;;
        *debian*|*ubuntu*)
            dpkg -S "${TARGET}" 2>/dev/null || echo "No pertenece a ningún paquete DEB"
            ;;
        *)
            echo "Verificacion de paquete no implementada para esta distro"
            ;;
    esac
    echo ""

    # 8. YARA scan
    echo "=== YARA SCAN ==="
    if command -v yara &>/dev/null && [[ -d "/etc/securizar/yara-rules" ]]; then
        for rulefile in /etc/securizar/yara-rules/*.yar /etc/securizar/yara-rules/*.yara; do
            [[ -f "${rulefile}" ]] || continue
            result=$(yara -s "${rulefile}" "${TARGET}" 2>/dev/null || true)
            if [[ -n "${result}" ]]; then
                echo "ALERTA: ${result}"
            fi
        done
        echo "(Escaneo YARA completado)"
    else
        echo "YARA no disponible o sin reglas"
    fi

} > "${REPORT}" 2>&1

# Mostrar resumen en pantalla
log_info "Analisis completado"
echo ""
echo "--- Resumen ---"
grep -A1 "^=== TIPO\|^=== CHECKSUMS\|^=== ENTROPIA\|AVISO:\|ALERTA:" "${REPORT}" 2>/dev/null | head -30
echo ""
log_info "Reporte completo: ${REPORT}"
EOFBIN
    chmod +x "${FORENSICS_TOOLS}/forense-analizar-binario.sh"
    log_change "Creado" "${FORENSICS_TOOLS}/forense-analizar-binario.sh"

    log_info "Toolkit de analisis de malware instalado"
    log_info "Reglas YARA en: ${FORENSICS_ETC}/yara-rules/"
    log_info "Escaneo: forense-yara-scan.sh [directorio]"
    log_info "Analisis: forense-analizar-binario.sh <archivo>"
else
    log_skip "Toolkit de analisis de malware"
fi

# ============================================================
# S7: CADENA DE CUSTODIA DIGITAL
# ============================================================
log_section "S7: CADENA DE CUSTODIA DIGITAL"

echo "Implementa sistema de cadena de custodia digital:"
echo "  - Generacion de documentos de custodia en JSON"
echo "  - Registro: quien, cuando, que, hash, ubicacion"
echo "  - Historial de transferencias"
echo "  - Manifiesto JSON firmado con sha256"
echo "  - Plantilla reutilizable"
echo ""

if ask "¿Instalar sistema de cadena de custodia digital?"; then

    mkdir -p "${FORENSICS_ETC}"
    mkdir -p "${FORENSICS_BASE}/custody"
    chmod 700 "${FORENSICS_BASE}/custody"

    # Plantilla JSON de custodia
    cat > "${FORENSICS_ETC}/custodia-plantilla.json" << 'EOFJSON'
{
    "cadena_custodia": {
        "version": "1.0",
        "generado_por": "securizar-forense-avanzado",
        "caso": {
            "id_caso": "",
            "descripcion": "",
            "fecha_apertura": "",
            "investigador_principal": "",
            "organizacion": ""
        },
        "evidencia": {
            "id_evidencia": "",
            "tipo": "",
            "descripcion": "",
            "fuente": {
                "hostname": "",
                "ip": "",
                "sistema_operativo": "",
                "ubicacion_fisica": ""
            },
            "adquisicion": {
                "fecha": "",
                "hora_utc": "",
                "metodo": "",
                "herramienta": "",
                "version_herramienta": "",
                "operador": "",
                "testigos": []
            },
            "archivos": [
                {
                    "nombre": "",
                    "ruta": "",
                    "tamano_bytes": 0,
                    "sha256": "",
                    "md5": "",
                    "fecha_creacion": "",
                    "descripcion": ""
                }
            ]
        },
        "almacenamiento": {
            "ubicacion": "",
            "medio": "",
            "cifrado": false,
            "metodo_cifrado": "",
            "acceso_restringido": true
        },
        "transferencias": [
            {
                "fecha": "",
                "de": "",
                "a": "",
                "motivo": "",
                "metodo": "",
                "verificacion_hash": ""
            }
        ],
        "notas": []
    }
}
EOFJSON
    chmod 640 "${FORENSICS_ETC}/custodia-plantilla.json"
    log_change "Creado" "${FORENSICS_ETC}/custodia-plantilla.json"

    # Script de cadena de custodia
    cat > "${FORENSICS_TOOLS}/forense-custodia.sh" << 'EOFCUST'
#!/bin/bash
# ============================================================
# forense-custodia.sh - Cadena de custodia digital
# ============================================================
# Genera y mantiene documentos de cadena de custodia.
# Uso:
#   forense-custodia.sh crear <id_caso> <descripcion> <investigador>
#   forense-custodia.sh agregar <id_caso> <archivo_evidencia> <descripcion>
#   forense-custodia.sh transferir <id_caso> <de> <a> <motivo>
#   forense-custodia.sh verificar <id_caso>
#   forense-custodia.sh listar
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[X]${NC} $1"; }

CUSTODY_DIR="/var/forensics/custody"
TEMPLATE="/etc/securizar/custodia-plantilla.json"

mkdir -p "${CUSTODY_DIR}"
chmod 700 "${CUSTODY_DIR}"

# Funcion para generar JSON seguro (sin jq como dependencia)
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\t'/\\t}"
    echo "$s"
}

caso_dir() {
    echo "${CUSTODY_DIR}/caso-${1}"
}

cmd_crear() {
    local id_caso="${1:-}"
    local descripcion="${2:-}"
    local investigador="${3:-}"

    if [[ -z "${id_caso}" ]] || [[ -z "${descripcion}" ]] || [[ -z "${investigador}" ]]; then
        echo "Uso: $0 crear <id_caso> <descripcion> <investigador>"
        exit 1
    fi

    local caso_path
    caso_path=$(caso_dir "${id_caso}")
    if [[ -d "${caso_path}" ]]; then
        log_error "El caso ${id_caso} ya existe en ${caso_path}"
        exit 1
    fi

    mkdir -p "${caso_path}"
    chmod 700 "${caso_path}"

    local hostname_full
    hostname_full=$(hostname -f 2>/dev/null || hostname)
    local ip_addr
    ip_addr=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "N/A")
    local os_info
    os_info=$(cat /etc/os-release 2>/dev/null | grep "^PRETTY_NAME=" | cut -d= -f2 | tr -d '"' || uname -s)

    cat > "${caso_path}/custodia.json" << EOFCJ
{
    "cadena_custodia": {
        "version": "1.0",
        "generado_por": "securizar-forense-avanzado",
        "fecha_generacion": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
        "caso": {
            "id_caso": "$(json_escape "${id_caso}")",
            "descripcion": "$(json_escape "${descripcion}")",
            "fecha_apertura": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
            "investigador_principal": "$(json_escape "${investigador}")",
            "organizacion": ""
        },
        "evidencia": {
            "fuente": {
                "hostname": "${hostname_full}",
                "ip": "${ip_addr}",
                "sistema_operativo": "$(json_escape "${os_info}")",
                "kernel": "$(uname -r)"
            },
            "archivos": []
        },
        "transferencias": [],
        "notas": [
            {
                "fecha": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
                "autor": "$(json_escape "${investigador}")",
                "texto": "Caso creado"
            }
        ]
    }
}
EOFCJ

    # Hash del manifiesto
    sha256sum "${caso_path}/custodia.json" > "${caso_path}/custodia.json.sha256"

    log_info "Caso ${id_caso} creado en ${caso_path}"
    log_info "Manifiesto: ${caso_path}/custodia.json"
}

cmd_agregar() {
    local id_caso="${1:-}"
    local archivo="${2:-}"
    local descripcion="${3:-}"

    if [[ -z "${id_caso}" ]] || [[ -z "${archivo}" ]]; then
        echo "Uso: $0 agregar <id_caso> <archivo_evidencia> [descripcion]"
        exit 1
    fi

    local caso_path
    caso_path=$(caso_dir "${id_caso}")
    if [[ ! -d "${caso_path}" ]]; then
        log_error "Caso ${id_caso} no encontrado"
        exit 1
    fi

    if [[ ! -f "${archivo}" ]]; then
        log_error "Archivo no encontrado: ${archivo}"
        exit 1
    fi

    # Calcular hashes
    local sha256_val md5_val file_size file_name
    sha256_val=$(sha256sum "${archivo}" | awk '{print $1}')
    md5_val=$(md5sum "${archivo}" | awk '{print $1}')
    file_size=$(stat -c %s "${archivo}" 2>/dev/null || echo "0")
    file_name=$(basename "${archivo}")

    # Copiar evidencia al directorio del caso
    local evidence_dir="${caso_path}/evidencia"
    mkdir -p "${evidence_dir}"
    cp -a "${archivo}" "${evidence_dir}/"
    chmod 600 "${evidence_dir}/${file_name}"

    # Registrar en log de evidencias
    cat >> "${caso_path}/evidencia.log" << EOFEVLOG
# Evidencia agregada: $(date -u '+%Y-%m-%dT%H:%M:%SZ')
archivo=${file_name}
ruta_original=$(readlink -f "${archivo}")
tamano_bytes=${file_size}
sha256=${sha256_val}
md5=${md5_val}
descripcion=$(json_escape "${descripcion:-Sin descripcion}")
agregado_por=$(whoami)
EOFEVLOG

    # Actualizar hash del manifiesto
    sha256sum "${caso_path}/custodia.json" > "${caso_path}/custodia.json.sha256"

    log_info "Evidencia agregada al caso ${id_caso}"
    log_info "  Archivo: ${file_name}"
    log_info "  SHA-256: ${sha256_val}"
    log_info "  MD5:     ${md5_val}"
    log_info "  Tamano:  ${file_size} bytes"
}

cmd_transferir() {
    local id_caso="${1:-}"
    local de="${2:-}"
    local a="${3:-}"
    local motivo="${4:-}"

    if [[ -z "${id_caso}" ]] || [[ -z "${de}" ]] || [[ -z "${a}" ]]; then
        echo "Uso: $0 transferir <id_caso> <de> <a> [motivo]"
        exit 1
    fi

    local caso_path
    caso_path=$(caso_dir "${id_caso}")
    if [[ ! -d "${caso_path}" ]]; then
        log_error "Caso ${id_caso} no encontrado"
        exit 1
    fi

    cat >> "${caso_path}/transferencias.log" << EOFTR
# Transferencia: $(date -u '+%Y-%m-%dT%H:%M:%SZ')
fecha=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
de=$(json_escape "${de}")
a=$(json_escape "${a}")
motivo=$(json_escape "${motivo:-Sin motivo especificado}")
hash_manifiesto=$(sha256sum "${caso_path}/custodia.json" | awk '{print $1}')
EOFTR

    log_info "Transferencia registrada para caso ${id_caso}"
    log_info "  De: ${de} -> A: ${a}"
    log_info "  Fecha: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
}

cmd_verificar() {
    local id_caso="${1:-}"

    if [[ -z "${id_caso}" ]]; then
        echo "Uso: $0 verificar <id_caso>"
        exit 1
    fi

    local caso_path
    caso_path=$(caso_dir "${id_caso}")
    if [[ ! -d "${caso_path}" ]]; then
        log_error "Caso ${id_caso} no encontrado"
        exit 1
    fi

    log_info "=== Verificacion de Cadena de Custodia: ${id_caso} ==="

    # Verificar integridad del manifiesto
    if [[ -f "${caso_path}/custodia.json.sha256" ]]; then
        if (cd "${caso_path}" && sha256sum -c custodia.json.sha256 &>/dev/null); then
            log_info "Manifiesto: INTEGRO (SHA-256 valido)"
        else
            log_error "Manifiesto: ALTERADO (SHA-256 no coincide)"
        fi
    fi

    # Verificar evidencias
    if [[ -d "${caso_path}/evidencia" ]]; then
        log_info "Evidencias registradas:"
        if [[ -f "${caso_path}/evidencia.log" ]]; then
            grep "^sha256=" "${caso_path}/evidencia.log" | while IFS= read -r line; do
                hash_reg="${line#sha256=}"
                file_line=$(grep -B2 "${line}" "${caso_path}/evidencia.log" | grep "^archivo=" | tail -1)
                fname="${file_line#archivo=}"
                if [[ -f "${caso_path}/evidencia/${fname}" ]]; then
                    hash_actual=$(sha256sum "${caso_path}/evidencia/${fname}" | awk '{print $1}')
                    if [[ "${hash_reg}" == "${hash_actual}" ]]; then
                        log_info "  [OK] ${fname} - hash verificado"
                    else
                        log_error "  [!!] ${fname} - HASH NO COINCIDE"
                    fi
                else
                    log_warn "  [??] ${fname} - archivo no encontrado"
                fi
            done
        fi
    fi

    # Mostrar transferencias
    if [[ -f "${caso_path}/transferencias.log" ]]; then
        log_info "Transferencias:"
        grep "^fecha=" "${caso_path}/transferencias.log" | while IFS= read -r line; do
            echo "  ${line}"
        done
    fi
}

cmd_listar() {
    log_info "=== Casos de custodia registrados ==="
    if [[ ! -d "${CUSTODY_DIR}" ]] || [[ -z "$(ls -A "${CUSTODY_DIR}" 2>/dev/null)" ]]; then
        log_info "No hay casos registrados"
        return
    fi

    for caso_dir in "${CUSTODY_DIR}"/caso-*; do
        [[ -d "${caso_dir}" ]] || continue
        caso_id=$(basename "${caso_dir}" | sed 's/^caso-//')
        evidencias=0
        if [[ -d "${caso_dir}/evidencia" ]]; then
            evidencias=$(find "${caso_dir}/evidencia" -type f 2>/dev/null | wc -l)
        fi
        fecha="desconocida"
        if [[ -f "${caso_dir}/custodia.json" ]]; then
            fecha=$(grep "fecha_apertura" "${caso_dir}/custodia.json" | head -1 | sed 's/.*: "//; s/".*//')
        fi
        echo "  Caso: ${caso_id} | Fecha: ${fecha} | Evidencias: ${evidencias}"
    done
}

# --- Main ---
ACTION="${1:-}"
shift 2>/dev/null || true

case "${ACTION}" in
    crear)      cmd_crear "$@" ;;
    agregar)    cmd_agregar "$@" ;;
    transferir) cmd_transferir "$@" ;;
    verificar)  cmd_verificar "$@" ;;
    listar)     cmd_listar ;;
    *)
        echo "Uso: $0 {crear|agregar|transferir|verificar|listar} [argumentos]"
        echo ""
        echo "Comandos:"
        echo "  crear       <id_caso> <descripcion> <investigador>"
        echo "  agregar     <id_caso> <archivo> [descripcion]"
        echo "  transferir  <id_caso> <de> <a> [motivo]"
        echo "  verificar   <id_caso>"
        echo "  listar"
        exit 1
        ;;
esac
EOFCUST
    chmod +x "${FORENSICS_TOOLS}/forense-custodia.sh"
    log_change "Creado" "${FORENSICS_TOOLS}/forense-custodia.sh"

    log_info "Sistema de cadena de custodia instalado"
    log_info "Plantilla: ${FORENSICS_ETC}/custodia-plantilla.json"
    log_info "Uso: forense-custodia.sh crear <caso> <desc> <investigador>"
else
    log_skip "Cadena de custodia digital"
fi

# ============================================================
# S8: TOOLKIT DE ANALISIS DE LOGS
# ============================================================
log_section "S8: TOOLKIT DE ANALISIS DE LOGS"

echo "Analisis automatizado de logs del sistema:"
echo "  - Deteccion de fuerza bruta (SSH, auth)"
echo "  - Patrones de escalacion de privilegios"
echo "  - Logins en horarios/ubicaciones inusuales"
echo "  - Anomalias de inicio/parada de servicios"
echo "  - Patrones de acceso a archivos"
echo "  - Intentos fallidos de sudo"
echo "  - Genera reporte consolidado"
echo ""

if ask "¿Instalar toolkit de analisis de logs?"; then

    cat > "${FORENSICS_TOOLS}/forense-analizar-logs.sh" << 'EOFLOGS'
#!/bin/bash
# ============================================================
# forense-analizar-logs.sh - Analisis forense de logs
# ============================================================
# Analisis automatizado de logs del sistema.
# Uso: forense-analizar-logs.sh [directorio_salida] [dias_atras]
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[X]${NC} $1"; }

if [[ $EUID -ne 0 ]]; then
    log_error "Debe ejecutarse como root"
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
HOSTNAME_SHORT=$(hostname -s)
OUTPUT_DIR="${1:-/var/forensics/logs}"
DAYS_BACK="${2:-7}"
REPORT="${OUTPUT_DIR}/analisis-logs-${HOSTNAME_SHORT}-${TIMESTAMP}.txt"
ALERTS="${OUTPUT_DIR}/alertas-${HOSTNAME_SHORT}-${TIMESTAMP}.txt"

mkdir -p "${OUTPUT_DIR}"
chmod 700 "${OUTPUT_DIR}"

TOTAL_ALERTS=0
alert() {
    local severity="$1"
    local message="$2"
    echo "[${severity}] ${message}" >> "${ALERTS}"
    TOTAL_ALERTS=$((TOTAL_ALERTS + 1))
    case "${severity}" in
        CRITICO) log_error "${message}" ;;
        ALTO)    log_warn "${message}" ;;
        *)       log_info "${message}" ;;
    esac
}

log_info "=== Analisis Forense de Logs ==="
log_info "Fecha/hora:    $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
log_info "Hostname:      ${HOSTNAME_SHORT}"
log_info "Dias atras:    ${DAYS_BACK}"
log_info "Reporte:       ${REPORT}"
echo ""

{
    echo "# Analisis Forense de Logs"
    echo "# Fecha: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo "# Hostname: ${HOSTNAME_SHORT}"
    echo "# Periodo: ultimos ${DAYS_BACK} dias"
    echo "# ============================================"
    echo ""

    # --- 1. Deteccion de fuerza bruta ---
    echo "=== 1. DETECCION DE FUERZA BRUTA ==="
    log_info "Analizando intentos de fuerza bruta..."

    # SSH failed logins
    echo "--- SSH: Intentos fallidos por IP ---"
    for logfile in /var/log/auth.log /var/log/secure; do
        if [[ -f "${logfile}" ]]; then
            grep -i "failed password\|authentication failure\|invalid user" "${logfile}" 2>/dev/null | \
                grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | \
                sort | uniq -c | sort -rn | head -20
            break
        fi
    done
    echo ""

    echo "--- SSH: Usuarios no validos mas intentados ---"
    for logfile in /var/log/auth.log /var/log/secure; do
        if [[ -f "${logfile}" ]]; then
            grep -i "invalid user" "${logfile}" 2>/dev/null | \
                grep -oP 'invalid user \K\S+' | \
                sort | uniq -c | sort -rn | head -20
            break
        fi
    done
    echo ""

    # Verificar umbrales de fuerza bruta
    for logfile in /var/log/auth.log /var/log/secure; do
        if [[ -f "${logfile}" ]]; then
            while IFS= read -r line; do
                count=$(echo "$line" | awk '{print $1}')
                ip=$(echo "$line" | awk '{print $2}')
                if [[ ${count} -gt 100 ]]; then
                    alert "CRITICO" "Fuerza bruta: ${count} intentos desde ${ip}"
                elif [[ ${count} -gt 20 ]]; then
                    alert "ALTO" "Posible fuerza bruta: ${count} intentos desde ${ip}"
                fi
            done < <(grep -i "failed password" "${logfile}" 2>/dev/null | \
                grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | \
                sort | uniq -c | sort -rn | head -20)
            break
        fi
    done

    # Journal
    if command -v journalctl &>/dev/null; then
        echo "--- Journal: Fallos de autenticacion (${DAYS_BACK} dias) ---"
        journalctl --since "${DAYS_BACK} days ago" -u sshd --no-pager 2>/dev/null | \
            grep -i "failed\|invalid\|error" | wc -l | xargs echo "Total entradas fallidas:"
        echo ""
    fi

    # --- 2. Escalacion de privilegios ---
    echo ""
    echo "=== 2. PATRONES DE ESCALACION DE PRIVILEGIOS ==="
    log_info "Analizando escalacion de privilegios..."

    echo "--- sudo: Comandos ejecutados ---"
    for logfile in /var/log/auth.log /var/log/secure; do
        if [[ -f "${logfile}" ]]; then
            grep -i "sudo:" "${logfile}" 2>/dev/null | grep "COMMAND=" | tail -30
            break
        fi
    done
    echo ""

    echo "--- su: Cambios de usuario ---"
    for logfile in /var/log/auth.log /var/log/secure; do
        if [[ -f "${logfile}" ]]; then
            grep -iE "su\[|su:" "${logfile}" 2>/dev/null | \
                grep -iv "sudo\|suspend\|success" | tail -20
            break
        fi
    done
    echo ""

    echo "--- Intentos fallidos de sudo ---"
    for logfile in /var/log/auth.log /var/log/secure; do
        if [[ -f "${logfile}" ]]; then
            fail_count=$(grep -ci "sudo.*authentication failure\|sudo.*incorrect password\|sudo.*NOT in sudoers" "${logfile}" 2>/dev/null || echo "0")
            echo "Total intentos fallidos de sudo: ${fail_count}"
            if [[ ${fail_count} -gt 0 ]]; then
                grep -i "sudo.*authentication failure\|sudo.*incorrect password\|sudo.*NOT in sudoers" "${logfile}" 2>/dev/null | tail -10
                if [[ ${fail_count} -gt 10 ]]; then
                    alert "ALTO" "Multiples fallos de sudo: ${fail_count} intentos"
                fi
            fi
            break
        fi
    done
    echo ""

    echo "--- Usuarios que se convirtieron en root ---"
    for logfile in /var/log/auth.log /var/log/secure; do
        if [[ -f "${logfile}" ]]; then
            grep -i "session opened for user root" "${logfile}" 2>/dev/null | \
                grep -oP 'by\s+\K\S+' | sort | uniq -c | sort -rn | head -10
            break
        fi
    done
    echo ""

    # --- 3. Logins en horarios inusuales ---
    echo ""
    echo "=== 3. LOGINS EN HORARIOS INUSUALES ==="
    log_info "Analizando horarios de login..."

    echo "--- Logins fuera de horario laboral (22:00-06:00) ---"
    if command -v last &>/dev/null; then
        last -w 2>/dev/null | grep -vE "reboot|still|begins|^$" | \
            while IFS= read -r line; do
                hour=$(echo "$line" | awk '{print $NF}' | grep -oP '^\d{2}' 2>/dev/null || echo "")
                if [[ -n "${hour}" ]] && { [[ ${hour#0} -ge 22 ]] || [[ ${hour#0} -lt 6 ]]; }; then
                    echo "  FUERA DE HORARIO: ${line}"
                fi
            done | head -20
    fi
    echo ""

    echo "--- Logins por IP externa (no RFC1918) ---"
    for logfile in /var/log/auth.log /var/log/secure; do
        if [[ -f "${logfile}" ]]; then
            grep -i "accepted" "${logfile}" 2>/dev/null | \
                grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | \
                grep -vE '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)' | \
                sort -u | head -20
            if [[ $(grep -i "accepted" "${logfile}" 2>/dev/null | \
                grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | \
                grep -cvE '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)' 2>/dev/null || echo 0) -gt 0 ]]; then
                alert "MEDIO" "Logins desde IPs externas detectados"
            fi
            break
        fi
    done
    echo ""

    # --- 4. Anomalias de servicios ---
    echo ""
    echo "=== 4. ANOMALIAS DE INICIO/PARADA DE SERVICIOS ==="
    log_info "Analizando anomalias de servicios..."

    if command -v journalctl &>/dev/null; then
        echo "--- Servicios detenidos inesperadamente ---"
        journalctl --since "${DAYS_BACK} days ago" --no-pager 2>/dev/null | \
            grep -iE "stopped|failed|crashed|killed" | \
            grep -v "session\|scope" | tail -20
        echo ""

        echo "--- Servicios iniciados ---"
        journalctl --since "${DAYS_BACK} days ago" --no-pager 2>/dev/null | \
            grep -i "started" | \
            grep -v "session\|scope\|user slice\|slice of" | tail -20
    fi
    echo ""

    # --- 5. Patrones de acceso a archivos ---
    echo ""
    echo "=== 5. PATRONES DE ACCESO A ARCHIVOS ==="
    log_info "Analizando accesos a archivos sensibles..."

    echo "--- Accesos al archivo shadow ---"
    for logfile in /var/log/auth.log /var/log/secure /var/log/audit/audit.log; do
        if [[ -f "${logfile}" ]]; then
            grep -i "shadow" "${logfile}" 2>/dev/null | tail -10
        fi
    done
    echo ""

    echo "--- Accesos a archivos de configuracion sensibles ---"
    if [[ -f /var/log/audit/audit.log ]]; then
        for pattern in "/etc/passwd" "/etc/shadow" "/etc/sudoers" "/etc/ssh"; do
            count=$(grep -c "${pattern}" /var/log/audit/audit.log 2>/dev/null || echo "0")
            if [[ ${count} -gt 0 ]]; then
                echo "  ${pattern}: ${count} accesos registrados"
            fi
        done
    else
        echo "  audit.log no disponible (auditd no activo?)"
    fi
    echo ""

    # --- 6. Resumen ---
    echo ""
    echo "=== RESUMEN ==="
    echo "Total alertas generadas: ${TOTAL_ALERTS}"
    if [[ -f "${ALERTS}" ]]; then
        criticos=$(grep -c "^\[CRITICO\]" "${ALERTS}" 2>/dev/null || echo "0")
        altos=$(grep -c "^\[ALTO\]" "${ALERTS}" 2>/dev/null || echo "0")
        medios=$(grep -c "^\[MEDIO\]" "${ALERTS}" 2>/dev/null || echo "0")
        echo "  CRITICOS: ${criticos}"
        echo "  ALTOS:    ${altos}"
        echo "  MEDIOS:   ${medios}"
    fi

} > "${REPORT}" 2>&1

chmod 600 "${REPORT}" "${ALERTS}" 2>/dev/null

log_info "=== Analisis de logs completado ==="
log_info "Reporte: ${REPORT}"
if [[ ${TOTAL_ALERTS} -gt 0 ]]; then
    log_warn "Alertas: ${TOTAL_ALERTS} (ver ${ALERTS})"
else
    log_info "No se detectaron alertas"
fi
EOFLOGS
    chmod +x "${FORENSICS_TOOLS}/forense-analizar-logs.sh"
    log_change "Creado" "${FORENSICS_TOOLS}/forense-analizar-logs.sh"

    log_info "Toolkit de analisis de logs instalado"
    log_info "Uso: forense-analizar-logs.sh [directorio] [dias_atras]"
else
    log_skip "Toolkit de analisis de logs"
fi

# ============================================================
# S9: SCRIPT MAESTRO DE RECOPILACION FORENSE
# ============================================================
log_section "S9: SCRIPT MAESTRO DE RECOPILACION FORENSE"

echo "Script maestro que orquesta la recopilacion completa:"
echo "  1. Datos volatiles (lo primero - mas volatil)"
echo "  2. Memoria RAM"
echo "  3. Imagen de disco (opcional)"
echo "  4. Artefactos del sistema"
echo "  5. Timeline unificado"
echo "  6. Escaneo YARA"
echo "  7. Analisis de logs"
echo "  8. Cadena de custodia"
echo "  Un solo comando para preservacion completa de evidencia."
echo ""

if ask "¿Instalar script maestro de recopilacion forense?"; then

    cat > "${FORENSICS_TOOLS}/forense-recopilar-todo.sh" << 'EOFMASTER'
#!/bin/bash
# ============================================================
# forense-recopilar-todo.sh - Recopilacion forense completa
# ============================================================
# Orquesta la recopilacion completa de evidencia forense.
# Ejecuta todas las herramientas forenses en orden optimo.
# Uso: forense-recopilar-todo.sh [id_caso] [investigador]
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[X]${NC} $1"; }

if [[ $EUID -ne 0 ]]; then
    log_error "Debe ejecutarse como root"
    exit 1
fi

CASO_ID="${1:-caso-$(date +%Y%m%d-%H%M%S)}"
INVESTIGADOR="${2:-$(whoami)}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
HOSTNAME_SHORT=$(hostname -s)
BASE_DIR="/var/forensics"
COLLECTION_DIR="${BASE_DIR}/recopilacion-${CASO_ID}-${TIMESTAMP}"
LOG_FILE="${COLLECTION_DIR}/recopilacion.log"

mkdir -p "${COLLECTION_DIR}"
chmod 700 "${COLLECTION_DIR}"

# Funcion para logging dual (pantalla + archivo)
log_both() {
    local msg="$1"
    log_info "${msg}"
    echo "[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] ${msg}" >> "${LOG_FILE}"
}

log_both_warn() {
    local msg="$1"
    log_warn "${msg}"
    echo "[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] WARN: ${msg}" >> "${LOG_FILE}"
}

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     RECOPILACION FORENSE COMPLETA                        ║"
echo "╠═══════════════════════════════════════════════════════════╣"
echo "║  Caso:          ${CASO_ID}"
echo "║  Investigador:  ${INVESTIGADOR}"
echo "║  Fecha:         $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "║  Hostname:      ${HOSTNAME_SHORT}"
echo "║  Directorio:    ${COLLECTION_DIR}"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

log_both "Inicio de recopilacion forense"
log_both "Caso: ${CASO_ID} | Investigador: ${INVESTIGADOR}"

PASOS_OK=0
PASOS_FAIL=0
PASOS_SKIP=0

ejecutar_paso() {
    local num="$1"
    local desc="$2"
    local cmd="$3"

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log_both "PASO ${num}: ${desc}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if ! command -v "$(echo "${cmd}" | awk '{print $1}')" &>/dev/null; then
        log_both_warn "Herramienta no disponible: $(echo "${cmd}" | awk '{print $1}')"
        PASOS_SKIP=$((PASOS_SKIP + 1))
        return
    fi

    if eval "${cmd}" >> "${LOG_FILE}" 2>&1; then
        log_both "Paso ${num} completado exitosamente"
        PASOS_OK=$((PASOS_OK + 1))
    else
        log_both_warn "Paso ${num} completo con advertencias (codigo: $?)"
        PASOS_FAIL=$((PASOS_FAIL + 1))
    fi
}

# --- Paso 1: Datos volatiles (lo mas urgente) ---
ejecutar_paso "1/8" "Datos volatiles" \
    "forense-volatil.sh ${COLLECTION_DIR}/volatile"

# --- Paso 2: Captura de memoria ---
ejecutar_paso "2/8" "Captura de memoria RAM" \
    "forense-capturar-ram.sh raw ${COLLECTION_DIR}/memory"

# --- Paso 3: Imagen de disco (solo si el usuario lo pide) ---
echo ""
echo -n "¿Realizar imagen de disco? (puede tardar horas) [s/N]: "
read -r resp_disk
if [[ "$resp_disk" =~ ^[sS]$ ]]; then
    echo -n "Dispositivo a copiar (ej: /dev/sda): "
    read -r disk_device
    if [[ -n "${disk_device}" ]] && [[ -b "${disk_device}" ]]; then
        ejecutar_paso "3/8" "Imagen de disco (${disk_device})" \
            "forense-imagen-disco.sh ${disk_device} ${COLLECTION_DIR}/disk"
    else
        log_both_warn "Dispositivo no valido: ${disk_device}"
        PASOS_SKIP=$((PASOS_SKIP + 1))
    fi
else
    log_both "Imagen de disco omitida por el usuario"
    PASOS_SKIP=$((PASOS_SKIP + 1))
fi

# --- Paso 4: Artefactos ---
ejecutar_paso "4/8" "Recopilacion de artefactos" \
    "forense-artefactos.sh ${COLLECTION_DIR}/artifacts 7"

# --- Paso 5: Timeline ---
ejecutar_paso "5/8" "Construccion de timeline" \
    "forense-timeline.sh ${COLLECTION_DIR}/timeline"

# --- Paso 6: Escaneo YARA ---
ejecutar_paso "6/8" "Escaneo YARA" \
    "forense-yara-scan.sh '' ${COLLECTION_DIR}/yara"

# --- Paso 7: Analisis de logs ---
ejecutar_paso "7/8" "Analisis de logs" \
    "forense-analizar-logs.sh ${COLLECTION_DIR}/logs 7"

# --- Paso 8: Cadena de custodia ---
log_both "PASO 8/8: Generando cadena de custodia..."
if command -v forense-custodia.sh &>/dev/null; then
    forense-custodia.sh crear "${CASO_ID}" "Recopilacion forense automatica - ${HOSTNAME_SHORT}" "${INVESTIGADOR}" >> "${LOG_FILE}" 2>&1 || true

    # Agregar todos los archivos de evidencia al caso
    find "${COLLECTION_DIR}" -type f -name "*.txt" -o -name "*.csv" -o -name "*.tar.gz" -o -name "*.dd" -o -name "*.raw" -o -name "*.lime" 2>/dev/null | \
    while read -r evidence_file; do
        forense-custodia.sh agregar "${CASO_ID}" "${evidence_file}" "Recopilacion automatica" >> "${LOG_FILE}" 2>&1 || true
    done
    PASOS_OK=$((PASOS_OK + 1))
    log_both "Cadena de custodia generada"
else
    log_both_warn "forense-custodia.sh no disponible"
    PASOS_SKIP=$((PASOS_SKIP + 1))
fi

# --- Resumen final ---
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     RECOPILACION FORENSE COMPLETADA                      ║"
echo "╠═══════════════════════════════════════════════════════════╣"
echo "║  Caso:          ${CASO_ID}"
echo "║  Directorio:    ${COLLECTION_DIR}"
echo "║  Pasos OK:      ${PASOS_OK}"
echo "║  Pasos WARN:    ${PASOS_FAIL}"
echo "║  Pasos SKIP:    ${PASOS_SKIP}"
echo "║  Tamano total:  $(du -sh "${COLLECTION_DIR}" 2>/dev/null | awk '{print $1}')"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

log_both "Recopilacion completada: ${PASOS_OK} OK, ${PASOS_FAIL} advertencias, ${PASOS_SKIP} omitidos"
log_both "Directorio de evidencia: ${COLLECTION_DIR}"
log_both "Log de recopilacion: ${LOG_FILE}"

# Hash del log de recopilacion
sha256sum "${LOG_FILE}" > "${LOG_FILE}.sha256"

echo ""
echo "Proximos pasos:"
echo "  1. Verificar evidencia: forense-custodia.sh verificar ${CASO_ID}"
echo "  2. Analizar timeline:  head -50 ${COLLECTION_DIR}/timeline/*.csv"
echo "  3. Ver alertas YARA:   cat ${COLLECTION_DIR}/yara/*hallazgos*"
echo "  4. Ver alertas logs:   cat ${COLLECTION_DIR}/logs/*alertas*"
echo "  5. Transferir a medio externo cifrado para preservacion"
EOFMASTER
    chmod +x "${FORENSICS_TOOLS}/forense-recopilar-todo.sh"
    log_change "Creado" "${FORENSICS_TOOLS}/forense-recopilar-todo.sh"

    log_info "Script maestro de recopilacion instalado"
    log_info "Uso: forense-recopilar-todo.sh [id_caso] [investigador]"
else
    log_skip "Script maestro de recopilacion forense"
fi

# ============================================================
# S10: AUDITORIA Y PUNTUACION DE PREPARACION FORENSE
# ============================================================
log_section "S10: AUDITORIA Y PUNTUACION DE PREPARACION FORENSE"

echo "Audita la preparacion forense del sistema:"
echo "  - Herramientas instaladas"
echo "  - Reglas YARA presentes"
echo "  - Scripts de recopilacion disponibles"
echo "  - Espacio en disco para imagen"
echo "  - Almacenamiento de evidencia configurado"
echo "  - Puntuacion: BUENO / MEJORABLE / DEFICIENTE"
echo ""

if ask "¿Instalar auditoria de preparacion forense?"; then

    cat > "${FORENSICS_TOOLS}/auditoria-forense.sh" << 'EOFAUDIT'
#!/bin/bash
# ============================================================
# auditoria-forense.sh - Auditoria de preparacion forense
# ============================================================
# Evalua la preparacion del sistema para respuesta a incidentes.
# Puntuacion: BUENO (>=80%), MEJORABLE (50-79%), DEFICIENTE (<50%)
# Uso: auditoria-forense.sh
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[X]${NC} $1"; }

TOTAL_CHECKS=0
PASSED_CHECKS=0
DETAILS=()

check() {
    local desc="$1"
    local result="$2"  # 0 = pass, 1 = fail
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    if [[ ${result} -eq 0 ]]; then
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
        DETAILS+=("  ${GREEN}[OK]${NC} ${desc}")
    else
        DETAILS+=("  ${RED}[!!]${NC} ${desc}")
    fi
}

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     AUDITORIA DE PREPARACION FORENSE                    ║"
echo "╠═══════════════════════════════════════════════════════════╣"
echo "║  Fecha: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "║  Host:  $(hostname -f 2>/dev/null || hostname)"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# === Herramientas de sistema ===
log_info "Verificando herramientas del sistema..."

check "dd disponible" $(command -v dd &>/dev/null; echo $?)
check "sha256sum disponible" $(command -v sha256sum &>/dev/null; echo $?)
check "md5sum disponible" $(command -v md5sum &>/dev/null; echo $?)
check "strings disponible (binutils)" $(command -v strings &>/dev/null; echo $?)
check "file disponible" $(command -v file &>/dev/null; echo $?)
check "lsof disponible" $(command -v lsof &>/dev/null; echo $?)
check "ss disponible" $(command -v ss &>/dev/null; echo $?)
check "pv disponible (progreso)" $(command -v pv &>/dev/null; echo $?)

# Herramientas forenses avanzadas
check "dc3dd disponible" $(command -v dc3dd &>/dev/null; echo $?)
check "yara disponible" $(command -v yara &>/dev/null; echo $?)

# === Scripts de recopilacion ===
echo ""
log_info "Verificando scripts de recopilacion..."

check "forense-capturar-ram.sh instalado" $([[ -x /usr/local/bin/forense-capturar-ram.sh ]]; echo $?)
check "forense-imagen-disco.sh instalado" $([[ -x /usr/local/bin/forense-imagen-disco.sh ]]; echo $?)
check "forense-volatil.sh instalado" $([[ -x /usr/local/bin/forense-volatil.sh ]]; echo $?)
check "forense-artefactos.sh instalado" $([[ -x /usr/local/bin/forense-artefactos.sh ]]; echo $?)
check "forense-timeline.sh instalado" $([[ -x /usr/local/bin/forense-timeline.sh ]]; echo $?)
check "forense-yara-scan.sh instalado" $([[ -x /usr/local/bin/forense-yara-scan.sh ]]; echo $?)
check "forense-analizar-binario.sh instalado" $([[ -x /usr/local/bin/forense-analizar-binario.sh ]]; echo $?)
check "forense-custodia.sh instalado" $([[ -x /usr/local/bin/forense-custodia.sh ]]; echo $?)
check "forense-analizar-logs.sh instalado" $([[ -x /usr/local/bin/forense-analizar-logs.sh ]]; echo $?)
check "forense-recopilar-todo.sh instalado" $([[ -x /usr/local/bin/forense-recopilar-todo.sh ]]; echo $?)

# === Reglas YARA ===
echo ""
log_info "Verificando reglas YARA..."

YARA_DIR="/etc/securizar/yara-rules"
check "Directorio de reglas YARA existe" $([[ -d "${YARA_DIR}" ]]; echo $?)
if [[ -d "${YARA_DIR}" ]]; then
    yara_count=$(find "${YARA_DIR}" -name "*.yar" -o -name "*.yara" 2>/dev/null | wc -l)
    check "Reglas YARA presentes (${yara_count} archivos)" $([[ ${yara_count} -gt 0 ]]; echo $?)
    check "Regla crypto_miners.yar" $([[ -f "${YARA_DIR}/crypto_miners.yar" ]]; echo $?)
    check "Regla reverse_shells.yar" $([[ -f "${YARA_DIR}/reverse_shells.yar" ]]; echo $?)
    check "Regla webshells.yar" $([[ -f "${YARA_DIR}/webshells.yar" ]]; echo $?)
    check "Regla rootkit_indicators.yar" $([[ -f "${YARA_DIR}/rootkit_indicators.yar" ]]; echo $?)
    check "Regla suspicious_scripts.yar" $([[ -f "${YARA_DIR}/suspicious_scripts.yar" ]]; echo $?)
    check "Regla encoded_payloads.yar" $([[ -f "${YARA_DIR}/encoded_payloads.yar" ]]; echo $?)
else
    for i in 1 2 3 4 5 6 7; do
        check "Regla YARA #${i}" 1
    done
fi

# === Almacenamiento de evidencia ===
echo ""
log_info "Verificando almacenamiento de evidencia..."

EVIDENCE_DIR="/var/forensics"
check "Directorio de evidencia existe (${EVIDENCE_DIR})" $([[ -d "${EVIDENCE_DIR}" ]]; echo $?)
check "Permisos restrictivos en ${EVIDENCE_DIR}" $([[ "$(stat -c '%a' "${EVIDENCE_DIR}" 2>/dev/null)" == "700" ]]; echo $?)

# Subdirectorios
for subdir in memory disk volatile artifacts timeline yara logs custody; do
    check "Subdirectorio ${subdir}/ existe" $([[ -d "${EVIDENCE_DIR}/${subdir}" ]]; echo $?)
done

# === Espacio en disco ===
echo ""
log_info "Verificando espacio en disco..."

if [[ -d "${EVIDENCE_DIR}" ]]; then
    avail_gb=$(df -BG "${EVIDENCE_DIR}" 2>/dev/null | awk 'NR==2 {gsub("G",""); print $4}')
    ram_gb=$(awk '/MemTotal/ {printf "%.0f", $2/1024/1024}' /proc/meminfo 2>/dev/null || echo "0")
    total_disk_gb=$(df -BG / 2>/dev/null | awk 'NR==2 {gsub("G",""); print $2}')

    echo "  Espacio disponible en ${EVIDENCE_DIR}: ${avail_gb}G"
    echo "  RAM del sistema: ${ram_gb}G"
    echo "  Disco total: ${total_disk_gb}G"

    # Necesitamos al menos espacio para un volcado de RAM
    check "Espacio para volcado de memoria (>= ${ram_gb}G)" $([[ ${avail_gb:-0} -ge ${ram_gb:-1} ]]; echo $?)

    # Idealmente espacio para imagen de disco
    check "Espacio para imagen de disco (>= ${total_disk_gb}G)" $([[ ${avail_gb:-0} -ge ${total_disk_gb:-1} ]]; echo $?)
    check "Espacio minimo 10G disponible" $([[ ${avail_gb:-0} -ge 10 ]]; echo $?)
fi

# === Plantilla de custodia ===
echo ""
log_info "Verificando configuracion..."

check "Plantilla de custodia existe" $([[ -f "/etc/securizar/custodia-plantilla.json" ]]; echo $?)

# === Logging del sistema ===
echo ""
log_info "Verificando logging del sistema..."

check "auditd instalado" $(command -v auditd &>/dev/null || command -v auditctl &>/dev/null; echo $?)
check "Logs de autenticacion accesibles" $([[ -f /var/log/auth.log ]] || [[ -f /var/log/secure ]]; echo $?)
check "journalctl disponible" $(command -v journalctl &>/dev/null; echo $?)
check "Persistencia de journal" $([[ -d /var/log/journal ]]; echo $?)

# === Calcular puntuacion ===
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

SCORE=0
if [[ ${TOTAL_CHECKS} -gt 0 ]]; then
    SCORE=$((PASSED_CHECKS * 100 / TOTAL_CHECKS))
fi

RATING=""
RATING_COLOR=""
if [[ ${SCORE} -ge 80 ]]; then
    RATING="BUENO"
    RATING_COLOR="${GREEN}"
elif [[ ${SCORE} -ge 50 ]]; then
    RATING="MEJORABLE"
    RATING_COLOR="${YELLOW}"
else
    RATING="DEFICIENTE"
    RATING_COLOR="${RED}"
fi

echo ""
# Mostrar todos los detalles
for detail in "${DETAILS[@]}"; do
    echo -e "${detail}"
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "  ${BOLD}PUNTUACION FORENSE: ${RATING_COLOR}${SCORE}% - ${RATING}${NC}"
echo -e "  ${BOLD}Checks:${NC} ${PASSED_CHECKS}/${TOTAL_CHECKS} pasados"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [[ "${RATING}" == "DEFICIENTE" ]]; then
    echo ""
    log_warn "RECOMENDACIONES URGENTES:"
    log_warn "  1. Ejecutar: forense-avanzado.sh (instalar todas las herramientas)"
    log_warn "  2. Instalar YARA: pkg_install yara"
    log_warn "  3. Verificar espacio en disco para evidencia"
    log_warn "  4. Activar auditd para logging avanzado"
elif [[ "${RATING}" == "MEJORABLE" ]]; then
    echo ""
    log_info "RECOMENDACIONES:"
    log_info "  - Completar la instalacion de herramientas faltantes"
    log_info "  - Asegurar espacio suficiente para imagenes forenses"
    log_info "  - Verificar que auditd esta activo y configurado"
fi
EOFAUDIT
    chmod +x "${FORENSICS_TOOLS}/auditoria-forense.sh"
    log_change "Creado" "${FORENSICS_TOOLS}/auditoria-forense.sh"

    log_info "Auditoria de preparacion forense instalada"
    log_info "Uso: auditoria-forense.sh"
else
    log_skip "Auditoria de preparacion forense"
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
show_changes_summary
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║           FORENSE AVANZADO COMPLETADO                    ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups guardados en: $BACKUP_DIR"
echo ""
echo "Comandos disponibles post-instalacion:"
echo "  - Capturar RAM:       forense-capturar-ram.sh [formato] [directorio]"
echo "  - Imagen de disco:    forense-imagen-disco.sh <dispositivo> [directorio]"
echo "  - Datos volatiles:    forense-volatil.sh [directorio]"
echo "  - Artefactos:         forense-artefactos.sh [directorio] [dias]"
echo "  - Timeline:           forense-timeline.sh [directorio] [inicio] [fin]"
echo "  - Escaneo YARA:       forense-yara-scan.sh [directorio] [salida]"
echo "  - Analizar binario:   forense-analizar-binario.sh <archivo>"
echo "  - Cadena custodia:    forense-custodia.sh {crear|agregar|verificar|listar}"
echo "  - Analizar logs:      forense-analizar-logs.sh [directorio] [dias]"
echo "  - Recopilar todo:     forense-recopilar-todo.sh [id_caso] [investigador]"
echo "  - Auditoria forense:  auditoria-forense.sh"
echo ""
log_warn "RECOMENDACION: Ejecuta 'auditoria-forense.sh' para evaluar la preparacion forense"
log_info "Modulo 46 completado"
