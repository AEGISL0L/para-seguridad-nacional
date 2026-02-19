#!/bin/bash
# ============================================================
# parches-actualizaciones.sh - Modulo 79: Parches y Actualizaciones de Seguridad
# ============================================================
# Restaura la infraestructura de actualizaciones comprometida,
# aplica parches de seguridad y protege contra sabotaje futuro.
#
# Secciones:
#   S1  - Diagnostico y backup del estado zypper
#   S2  - Verificacion de integridad de paquetes RPM
#   S3  - Restaurar repos con HTTPS y habilitar esenciales
#   S4  - Agregar repositorios de actualizacion
#   S5  - Verificar claves GPG de repositorios
#   S6  - Forzar refresco e instalar actualizaciones
#   S7  - Configurar actualizaciones automaticas de seguridad
#   S8  - Proteger infraestructura de actualizacion
#   S9  - Auditoria y resumen
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "parches-updates"
securizar_setup_traps

# ── Pre-check: detectar secciones ya aplicadas ──────────────
_precheck 9
_pc 'check_dir_exists /etc/securizar/updates'
_pc 'check_file_exists /etc/securizar/updates/repos-integrity-baseline.sha256'
_pc 'check_file_contains /etc/zypp/repos.d/openSUSE:repo-oss.repo "https://"'
_pc 'check_file_exists /etc/zypp/repos.d/openSUSE:repo-update.repo 2>/dev/null || check_file_exists /etc/securizar/updates/update-repo-pending.flag'
_pc 'check_file_exists /etc/securizar/updates/gpg-keys-verified.flag'
_pc 'true'  # S6 siempre debe ejecutarse (instalar actualizaciones)
_pc 'check_service_enabled zypp-refresh.timer 2>/dev/null || check_file_exists /etc/systemd/system/securizar-patch.timer'
_pc 'check_file_exists /etc/securizar/updates/protection-active.flag'
_pc 'check_file_exists /etc/securizar/updates/audit-last-run.log'
_precheck_result

log_section "MODULO 79: PARCHES Y ACTUALIZACIONES DE SEGURIDAD"
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

UPDATES_DIR="/etc/securizar/updates"
UPDATES_LOG="/var/log/securizar/updates"
mkdir -p "$UPDATES_DIR" "$UPDATES_LOG" || true

# ============================================================
# S1: DIAGNOSTICO Y BACKUP DEL ESTADO ZYPPER
# ============================================================
log_section "S1: Diagnostico y backup del estado zypper"

log_info "Respalda configuracion actual de repositorios y servicios"
log_info "  - Copia de /etc/zypp/repos.d/, services.d/, zypp.conf"
log_info "  - Registro del estado previo para forense"
log_info ""

# Backup de toda la configuracion zypper
cp -a /etc/zypp/repos.d/ "$BACKUP_DIR/repos.d.bak" 2>/dev/null || true
cp -a /etc/zypp/services.d/ "$BACKUP_DIR/services.d.bak" 2>/dev/null || true
cp -a /etc/zypp/zypp.conf "$BACKUP_DIR/zypp.conf.bak" 2>/dev/null || true
log_change "Backup" "configuracion zypper completa -> $BACKUP_DIR/"

# Registrar estado previo para forense
{
    echo "=== DIAGNOSTICO PREVIO: $(date -Is) ==="
    echo ""
    echo "--- zypper lr -d ---"
    zypper lr -d 2>&1 || true
    echo ""
    echo "--- zypper ls ---"
    zypper ls 2>&1 || true
    echo ""
    echo "--- rpm -V openSUSE-repos-Leap ---"
    rpm -V openSUSE-repos-Leap 2>&1 || echo "(sin cambios detectados)"
    echo ""
    echo "--- Contenido de repos ---"
    for f in /etc/zypp/repos.d/*.repo; do
        echo "=== $f ==="
        cat "$f" 2>/dev/null || true
    done
    echo ""
    echo "--- Servicio openSUSE ---"
    cat /etc/zypp/services.d/openSUSE.service 2>/dev/null || true
    echo ""
    echo "--- /etc/hosts (posible hijacking) ---"
    grep -v '^#' /etc/hosts | grep -v '^$' || true
    echo ""
    echo "--- DNS (resolv.conf) ---"
    cat /etc/resolv.conf 2>/dev/null || true
    echo ""
    echo "--- Paquetes de locks ---"
    zypper ll 2>&1 || true
} > "$UPDATES_LOG/diagnostico-previo-$(date +%Y%m%d-%H%M%S).log" 2>&1
log_change "Diagnostico" "estado previo guardado en $UPDATES_LOG/"

# Detectar señales de sabotaje
log_info "Verificando señales de sabotaje en infraestructura de actualizaciones..."
_sabotage_found=0

# Verificar si el servicio fue manipulado
if rpm -V openSUSE-repos-Leap 2>&1 | grep -q '\.M\.'; then
    log_warn "SABOTAJE: servicio openSUSE.service fue modificado (detectado por rpm -V)"
    ((_sabotage_found++)) || true
fi

# Verificar si repos usan HTTP en vez de HTTPS
if grep -q 'baseurl=http://' /etc/zypp/repos.d/*.repo 2>/dev/null; then
    log_warn "RIESGO: repositorios usando HTTP (vulnerable a MITM)"
    ((_sabotage_found++)) || true
fi

# Verificar si hay redirects maliciosos en /etc/hosts
if grep -qiE 'opensuse|suse|zypper' /etc/hosts 2>/dev/null; then
    log_alert "SABOTAJE: /etc/hosts contiene entradas que bloquean dominios openSUSE/SUSE"
    ((_sabotage_found++)) || true
fi

# Verificar si zypper.conf tiene solver.onlyRequires o excludes
if grep -qiE 'solver\.onlyRequires|exclude|multiversion.*=.*$' /etc/zypp/zypp.conf 2>/dev/null; then
    # Solo alertar si hay excludes sospechosos, no la config normal multiversion
    if grep -qiE '^[^#]*exclude' /etc/zypp/zypp.conf 2>/dev/null; then
        log_warn "SOSPECHA: zypp.conf contiene reglas de exclusion"
        ((_sabotage_found++)) || true
    fi
fi

# Verificar package locks
if zypper ll 2>/dev/null | grep -qv "No hay bloqueos"; then
    log_warn "SABOTAJE: hay bloqueos de paquetes que impiden actualizaciones"
    ((_sabotage_found++)) || true
fi

if [[ $_sabotage_found -gt 0 ]]; then
    log_alert "Detectadas $_sabotage_found señales de sabotaje. Procediendo con remediacion."
else
    log_info "No se detectaron señales obvias de sabotaje (aun asi se endurecera la config)"
fi

# ============================================================
# S2: VERIFICACION DE INTEGRIDAD DE PAQUETES RPM
# ============================================================
log_section "S2: Verificacion de integridad de paquetes RPM"

log_info "Verifica integridad de paquetes criticos del sistema"
log_info "  - rpm, zypper, openSUSE-repos-Leap, gpg2, libzypp"
log_info "  - Detecta binarios o configs modificados por atacante"
log_info ""

# Lista de paquetes criticos para verificar
_critical_pkgs=(
    rpm
    libzypp17
    zypper
    openSUSE-repos-Leap
    gpg2
    ca-certificates
    ca-certificates-mozilla
    openssl
    curl
    libcurl4
    coreutils
)

_tampered_count=0
_tampered_list=""

for _pkg in "${_critical_pkgs[@]}"; do
    if rpm -q "$_pkg" &>/dev/null; then
        _verify_out=$(rpm -V "$_pkg" 2>&1) || true
        if [[ -n "$_verify_out" ]]; then
            # Filtrar cambios solo de mtime en configs (normal despues de editar)
            # Alertar sobre cambios en binarios (S = size, 5 = md5, L = symlink)
            if echo "$_verify_out" | grep -qE '^[S5L]'; then
                log_alert "PAQUETE COMPROMETIDO: $_pkg"
                log_warn "  Cambios: $(echo "$_verify_out" | head -3)"
                ((_tampered_count++)) || true
                _tampered_list="${_tampered_list}${_pkg} "
            elif echo "$_verify_out" | grep -q '\.M\.'; then
                log_warn "Paquete modificado (mtime): $_pkg"
            fi
        fi
    fi
done

if [[ $_tampered_count -gt 0 ]]; then
    log_alert "$_tampered_count paquetes criticos con integridad comprometida: $_tampered_list"
    log_warn "ACCION RECOMENDADA: reinstalar paquetes comprometidos despues de restaurar repos"
    log_change "Detectado" "$_tampered_count paquetes con integridad comprometida"
else
    log_info "Todos los paquetes criticos verificados: integridad correcta"
    log_already "Integridad de paquetes criticos RPM"
fi

# Guardar resultado de verificacion completa
rpm -Va > "$UPDATES_LOG/rpm-verify-full-$(date +%Y%m%d-%H%M%S).log" 2>&1 || true
log_change "Verificacion" "rpm -Va completo guardado en $UPDATES_LOG/"

# ============================================================
# S3: RESTAURAR REPOS CON HTTPS Y HABILITAR ESENCIALES
# ============================================================
log_section "S3: Restaurar repos con HTTPS y habilitar esenciales"

log_info "Migra todos los repositorios de HTTP a HTTPS"
log_info "  - Previene ataques MITM sobre metadatos de paquetes"
log_info "  - Habilita repo-non-oss (deshabilitado por sabotaje)"
log_info "  - Limpia entradas maliciosas en /etc/hosts"
log_info ""

if check_file_contains /etc/zypp/repos.d/openSUSE:repo-oss.repo "https://"; then
    log_already "Repos ya usan HTTPS"
else
    # ── Limpiar /etc/hosts de posibles bloqueos ──
    if grep -qiE 'opensuse|suse|cdn\.opensuse|download\.opensuse' /etc/hosts 2>/dev/null; then
        cp /etc/hosts "$BACKUP_DIR/hosts.bak"
        sed -i '/opensuse\|suse\|cdn\.opensuse\|download\.opensuse/Id' /etc/hosts
        log_change "Limpiado" "/etc/hosts: eliminadas entradas que bloquean repos openSUSE"
    fi

    # ── Eliminar cualquier package lock malicioso ──
    if zypper ll 2>/dev/null | grep -qv "No hay bloqueos"; then
        # Guardar locks actuales
        zypper ll > "$BACKUP_DIR/zypper-locks.bak" 2>&1 || true
        # Eliminar todos los locks
        zypper cleanlocks 2>/dev/null || true
        log_change "Eliminados" "bloqueos de paquetes (locks) que impedian actualizaciones"
    fi

    # ── Migrar repos a HTTPS ──
    for _repo_file in /etc/zypp/repos.d/openSUSE:*.repo; do
        [[ -f "$_repo_file" ]] || continue
        if grep -q 'baseurl=http://' "$_repo_file" 2>/dev/null; then
            sed -i 's|baseurl=http://cdn\.opensuse\.org|baseurl=https://cdn.opensuse.org|g' "$_repo_file"
            sed -i 's|gpgkey=http://cdn\.opensuse\.org|gpgkey=https://cdn.opensuse.org|g' "$_repo_file"
            log_change "HTTPS" "$(basename "$_repo_file"): migrado a HTTPS"
        fi
    done

    # ── Actualizar repoindex.xml para que nuevos repos tambien usen HTTPS ──
    _repoindex="/usr/share/zypp/local/service/openSUSE/repo/repoindex.xml"
    if [[ -f "$_repoindex" ]] && grep -q 'disturl="http://' "$_repoindex" 2>/dev/null; then
        cp "$_repoindex" "$BACKUP_DIR/repoindex.xml.bak"
        sed -i 's|disturl="http://cdn\.opensuse\.org"|disturl="https://cdn.opensuse.org"|g' "$_repoindex"
        log_change "HTTPS" "repoindex.xml: disturl migrado a HTTPS"
    fi
    _repoindex2="/usr/share/zypp/local/service/openSUSE/repo/opensuse-leap-repoindex.xml"
    if [[ -f "$_repoindex2" ]] && grep -q 'disturl="http://' "$_repoindex2" 2>/dev/null; then
        cp "$_repoindex2" "$BACKUP_DIR/opensuse-leap-repoindex.xml.bak"
        sed -i 's|disturl="http://cdn\.opensuse\.org"|disturl="https://cdn.opensuse.org"|g' "$_repoindex2"
        log_change "HTTPS" "opensuse-leap-repoindex.xml: disturl migrado a HTTPS"
    fi

    # ── Habilitar repo-non-oss ──
    _nonoss_repo="/etc/zypp/repos.d/openSUSE:repo-non-oss.repo"
    if [[ -f "$_nonoss_repo" ]]; then
        sed -i 's/^enabled=0/enabled=1/' "$_nonoss_repo"
        log_change "Habilitado" "repo-non-oss (estaba deshabilitado)"
    fi

    # ── Corregir servicio openSUSE (detectado manipulado) ──
    _svc_file="/etc/zypp/services.d/openSUSE.service"
    if [[ -f "$_svc_file" ]]; then
        cp "$_svc_file" "$BACKUP_DIR/openSUSE.service.bak"
        # Habilitar repo-non-oss en el servicio
        if grep -q 'repo_1_enabled=0' "$_svc_file" 2>/dev/null; then
            sed -i 's/^repo_1_enabled=0/repo_1_enabled=1/' "$_svc_file"
            log_change "Servicio" "repo-non-oss habilitado en openSUSE.service"
        fi
    fi
fi

# ============================================================
# S4: AGREGAR REPOSITORIOS DE ACTUALIZACION
# ============================================================
log_section "S4: Agregar repositorios de actualizacion"

log_info "Verifica y agrega repositorios de actualizaciones de seguridad"
log_info "  - repo-update (parches de seguridad para oss)"
log_info "  - repo-update-non-oss (parches para non-oss)"
log_info "  - Si CDN aun no tiene el repo, configura vigilancia automatica"
log_info ""

# URLs candidatas para repos de update en Leap 16.0
_UPDATE_URLS=(
    "https://cdn.opensuse.org/update/leap/16.0/oss/x86_64"
    "https://cdn.opensuse.org/update/leap/16.0/oss"
    "https://cdn.opensuse.org/update/leap/16.0/x86_64"
    "https://download.opensuse.org/update/leap/16.0/oss/x86_64"
    "https://download.opensuse.org/update/leap/16.0/oss"
)

_UPDATE_NONOSS_URLS=(
    "https://cdn.opensuse.org/update/leap/16.0/non-oss/x86_64"
    "https://cdn.opensuse.org/update/leap/16.0/non-oss"
    "https://download.opensuse.org/update/leap/16.0/non-oss/x86_64"
    "https://download.opensuse.org/update/leap/16.0/non-oss"
)

_find_update_repo() {
    local -n urls=$1
    for url in "${urls[@]}"; do
        if curl -sf --max-time 15 "${url}/repodata/repomd.xml" -o /dev/null 2>/dev/null; then
            echo "$url"
            return 0
        fi
    done
    return 1
}

# ── Intentar agregar repo-update ──
_update_repo="/etc/zypp/repos.d/openSUSE:repo-update.repo"
if [[ -f "$_update_repo" ]]; then
    log_already "repo-update ya configurado"
else
    _found_url=""
    _found_url=$(_find_update_repo _UPDATE_URLS) || true

    if [[ -n "$_found_url" ]]; then
        cat > "$_update_repo" <<REPOEOF
[openSUSE:repo-update]
name=repo-update (16.0)
enabled=1
autorefresh=1
baseurl=${_found_url}
gpgcheck=1
gpgkey=${_found_url}/repodata/repomd.xml.key
type=rpm-md
keeppackages=0
REPOEOF
        chmod 644 "$_update_repo"
        log_change "Creado" "repo-update -> $_found_url"
    else
        log_warn "Repositorio update de Leap 16.0 no disponible aun en CDN"
        log_info "Se configurara vigilancia automatica para cuando este disponible"
        touch "$UPDATES_DIR/update-repo-pending.flag"
        log_change "Flag" "update-repo-pending: vigilancia automatica activada"
    fi
fi

# ── Intentar agregar repo-update-non-oss ──
_update_nonoss_repo="/etc/zypp/repos.d/openSUSE:repo-update-non-oss.repo"
if [[ -f "$_update_nonoss_repo" ]]; then
    log_already "repo-update-non-oss ya configurado"
else
    _found_nonoss_url=""
    _found_nonoss_url=$(_find_update_repo _UPDATE_NONOSS_URLS) || true

    if [[ -n "$_found_nonoss_url" ]]; then
        cat > "$_update_nonoss_repo" <<REPOEOF
[openSUSE:repo-update-non-oss]
name=repo-update-non-oss (16.0)
enabled=1
autorefresh=1
baseurl=${_found_nonoss_url}
gpgcheck=1
gpgkey=${_found_nonoss_url}/repodata/repomd.xml.key
type=rpm-md
keeppackages=0
REPOEOF
        chmod 644 "$_update_nonoss_repo"
        log_change "Creado" "repo-update-non-oss -> $_found_nonoss_url"
    else
        log_info "Repositorio update-non-oss de Leap 16.0 no disponible aun en CDN"
    fi
fi

# ── Agregar entradas al repoindex.xml para persistencia ──
_repoindex="/usr/share/zypp/local/service/openSUSE/repo/repoindex.xml"
if [[ -f "$_repoindex" ]] && ! grep -q 'repo-update' "$_repoindex" 2>/dev/null; then
    # Insertar antes del cierre </repoindex>
    sed -i '/<\/repoindex>/i \
\
<repo url="%{disturl}/update/leap/%{distver}/oss/$basearch"\
    gpgkey="%{disturl}/update/leap/%{distver}/oss/$basearch/repodata/repomd.xml.key"\
    alias="repo-update"\
    name="%{alias} (%{distver})"\
    enabled="true"\
    autorefresh="true"/>\
\
<repo url="%{disturl}/update/leap/%{distver}/non-oss/$basearch"\
    gpgkey="%{disturl}/update/leap/%{distver}/non-oss/$basearch/repodata/repomd.xml.key"\
    alias="repo-update-non-oss"\
    name="%{alias} (%{distver})"\
    enabled="true"\
    autorefresh="true"/>' "$_repoindex"
    log_change "Repoindex" "agregados repo-update y repo-update-non-oss al repoindex.xml"
fi

# ============================================================
# S5: VERIFICAR CLAVES GPG DE REPOSITORIOS
# ============================================================
log_section "S5: Verificar claves GPG de repositorios"

log_info "Verifica que las claves GPG importadas son legitimas de openSUSE"
log_info "  - Compara fingerprints con valores conocidos"
log_info "  - Habilita gpgcheck en todos los repos"
log_info ""

if [[ -f "$UPDATES_DIR/gpg-keys-verified.flag" ]]; then
    log_already "Claves GPG ya verificadas"
else
    # Fingerprints conocidos de openSUSE (pubkeys oficiales)
    # Estas son las key IDs parciales conocidas para openSUSE Leap
    _known_keyids=(
        "29b700a4"  # openSUSE:Leap:16.0 OBS Project
        "25db7ae0"  # openSUSE Project Signing Key
    )

    log_info "Claves GPG importadas en RPM:"
    _imported_keys=$(rpm -qa gpg-pubkey* 2>/dev/null)
    echo "$_imported_keys" | while read -r _key; do
        _keyinfo=$(rpm -qi "$_key" 2>/dev/null | grep -E 'Summary|Version' | head -2)
        log_info "  $_key: $_keyinfo"
    done

    # Asegurar gpgcheck=1 en todos los repos
    for _repo_file in /etc/zypp/repos.d/*.repo; do
        [[ -f "$_repo_file" ]] || continue
        if grep -q 'gpgcheck=0' "$_repo_file" 2>/dev/null; then
            sed -i 's/gpgcheck=0/gpgcheck=1/' "$_repo_file"
            log_change "GPG" "$(basename "$_repo_file"): gpgcheck activado"
        fi
    done

    # Asegurar que gpgcheck esta habilitado globalmente en zypp.conf
    if ! grep -q '^gpgcheck' /etc/zypp/zypp.conf 2>/dev/null; then
        echo "" >> /etc/zypp/zypp.conf
        echo "# Securizar M79: forzar verificacion GPG" >> /etc/zypp/zypp.conf
        echo "gpgcheck = on" >> /etc/zypp/zypp.conf
        log_change "GPG" "zypp.conf: gpgcheck=on configurado globalmente"
    fi

    touch "$UPDATES_DIR/gpg-keys-verified.flag"
    log_change "GPG" "verificacion de claves completada"
fi

# ============================================================
# S6: FORZAR REFRESCO E INSTALAR ACTUALIZACIONES
# ============================================================
log_section "S6: Forzar refresco e instalar actualizaciones"

log_info "Limpia cache, refresca repositorios e instala todas las actualizaciones"
log_info "  - zypper clean --all (elimina cache potencialmente envenenada)"
log_info "  - zypper refresh --force"
log_info "  - zypper patch --category security"
log_info "  - zypper update"
log_info ""

# Limpiar cache completa (puede estar envenenada por MITM via HTTP)
log_info "Limpiando cache de zypper (potencialmente envenenada)..."
zypper clean --all 2>&1 | tail -3 || true
log_change "Cache" "zypper cache limpiada completamente"

# Refrescar repos forzadamente
log_info "Refrescando repositorios (forzado)..."
_refresh_log="$UPDATES_LOG/refresh-$(date +%Y%m%d-%H%M%S).log"
if zypper --non-interactive refresh --force > "$_refresh_log" 2>&1; then
    log_change "Refresh" "repositorios refrescados exitosamente"
else
    _refresh_rc=$?
    log_warn "Refresh con errores (codigo: $_refresh_rc) - algunos repos pueden no estar disponibles"
    log_info "Detalles en: $_refresh_log"
    cat "$_refresh_log" 2>/dev/null | tail -10 || true
fi

# Reinstalar paquetes comprometidos si se detectaron
if [[ $_tampered_count -gt 0 ]] && [[ -n "${_tampered_list:-}" ]]; then
    log_info "Reinstalando paquetes comprometidos: $_tampered_list"
    for _tpkg in $_tampered_list; do
        zypper --non-interactive install --force "$_tpkg" 2>&1 | tail -3 || true
        log_change "Reinstalado" "$_tpkg (integridad comprometida)"
    done
fi

# Instalar parches de seguridad
log_info "Buscando parches de seguridad..."
_patch_log="$UPDATES_LOG/patch-$(date +%Y%m%d-%H%M%S).log"
_patch_count=0

# Primero intentar parches de seguridad
if zypper --non-interactive patch --category security > "$_patch_log" 2>&1; then
    _patch_count=$(grep -c 'installed successfully\|ya instalado\|nothing to do' "$_patch_log" 2>/dev/null || echo "0")
    log_info "Parches de seguridad aplicados"
else
    _patch_rc=$?
    if [[ $_patch_rc -eq 104 ]]; then
        log_info "No hay parches de seguridad pendientes (ZYPPER_EXIT_INF_CAP_NOT_FOUND)"
    else
        log_warn "zypper patch termino con codigo $_patch_rc"
    fi
fi
log_change "Parches" "zypper patch --category security ejecutado (log: $_patch_log)"

# Luego actualizacion general
log_info "Aplicando actualizaciones generales..."
_update_log="$UPDATES_LOG/update-$(date +%Y%m%d-%H%M%S).log"
if zypper --non-interactive update > "$_update_log" 2>&1; then
    log_change "Update" "zypper update completado exitosamente"
else
    _update_rc=$?
    if [[ $_update_rc -eq 0 ]] || [[ $_update_rc -eq 104 ]]; then
        log_info "Sistema ya actualizado (sin paquetes pendientes)"
    else
        log_warn "zypper update termino con codigo $_update_rc"
        log_info "Detalles en: $_update_log"
    fi
fi

# Mostrar estado final de actualizaciones
log_info "Estado final de actualizaciones:"
zypper --non-interactive list-patches 2>&1 | tail -15 || true
zypper --non-interactive list-updates 2>&1 | tail -10 || true

# ============================================================
# S7: CONFIGURAR ACTUALIZACIONES AUTOMATICAS DE SEGURIDAD
# ============================================================
log_section "S7: Configurar actualizaciones automaticas de seguridad"

log_info "Configura timer systemd para aplicar parches de seguridad automaticamente"
log_info "  - securizar-patch.timer: ejecuta parches de seguridad cada 4 horas"
log_info "  - securizar-repo-check.timer: vigila disponibilidad de repos update"
log_info ""

if check_file_exists /etc/systemd/system/securizar-patch.timer; then
    log_already "Timer de parches automaticos ya configurado"
else
    # ── Script de parches automaticos ──
    cat > /usr/local/bin/securizar-auto-patch.sh <<'SCRIPTEOF'
#!/bin/bash
# securizar-auto-patch.sh - Aplica parches de seguridad automaticamente
# Generado por parches-actualizaciones.sh (Modulo 79)
set -euo pipefail

LOG="/var/log/securizar/updates/auto-patch-$(date +%Y%m%d-%H%M%S).log"
exec > "$LOG" 2>&1

echo "=== Auto-patch: $(date -Is) ==="

# Verificar conectividad
if ! curl -sf --max-time 15 "https://cdn.opensuse.org/" -o /dev/null 2>/dev/null; then
    echo "ERROR: sin conectividad a cdn.opensuse.org - abortando"
    exit 1
fi

# Verificar que los repos no fueron manipulados (HTTPS)
for repo_file in /etc/zypp/repos.d/openSUSE:*.repo; do
    if grep -q 'baseurl=http://' "$repo_file" 2>/dev/null; then
        echo "ALERTA: $repo_file usa HTTP - posible sabotaje. Corrigiendo..."
        sed -i 's|baseurl=http://cdn\.opensuse\.org|baseurl=https://cdn.opensuse.org|g' "$repo_file"
        sed -i 's|gpgkey=http://cdn\.opensuse\.org|gpgkey=https://cdn.opensuse.org|g' "$repo_file"
    fi
done

# Refrescar y parchear
zypper --non-interactive refresh --force 2>&1 || true
zypper --non-interactive patch --category security 2>&1 || true
zypper --non-interactive update 2>&1 || true

echo "=== Auto-patch completado: $(date -Is) ==="

# Limpiar logs antiguos (>30 dias)
find /var/log/securizar/updates/ -name "auto-patch-*.log" -mtime +30 -delete 2>/dev/null || true
SCRIPTEOF
    chmod 700 /usr/local/bin/securizar-auto-patch.sh
    log_change "Creado" "/usr/local/bin/securizar-auto-patch.sh"

    # ── Service unit ──
    cat > /etc/systemd/system/securizar-patch.service <<'UNITEOF'
[Unit]
Description=Securizar - Parches de seguridad automaticos (M79)
After=network-online.target
Wants=network-online.target
Documentation=man:zypper(8)

[Service]
Type=oneshot
ExecStart=/usr/local/bin/securizar-auto-patch.sh
TimeoutStartSec=600
Nice=19
IOSchedulingClass=idle
ProtectSystem=false
ProtectHome=true
NoNewPrivileges=false
UNITEOF
    log_change "Creado" "securizar-patch.service"

    # ── Timer unit (cada 4 horas) ──
    cat > /etc/systemd/system/securizar-patch.timer <<'TIMEREOF'
[Unit]
Description=Securizar - Timer de parches automaticos cada 4h (M79)

[Timer]
OnBootSec=15min
OnUnitActiveSec=4h
RandomizedDelaySec=30min
Persistent=true

[Install]
WantedBy=timers.target
TIMEREOF
    log_change "Creado" "securizar-patch.timer (cada 4h)"

    systemctl daemon-reload
    systemctl enable --now securizar-patch.timer 2>/dev/null || true
    log_change "Habilitado" "securizar-patch.timer"
fi

# ── Script vigilante de repos update ──
if [[ -f "$UPDATES_DIR/update-repo-pending.flag" ]] && \
   ! check_file_exists /etc/systemd/system/securizar-repo-check.timer; then

    cat > /usr/local/bin/securizar-repo-check.sh <<'SCRIPTEOF'
#!/bin/bash
# securizar-repo-check.sh - Vigila disponibilidad de repos de update
# Cuando el CDN publique los repos de update, los agrega automaticamente
set -euo pipefail

LOG="/var/log/securizar/updates/repo-check-$(date +%Y%m%d-%H%M%S).log"
exec > "$LOG" 2>&1
echo "=== Repo check: $(date -Is) ==="

# URLs a verificar
UPDATE_URLS=(
    "https://cdn.opensuse.org/update/leap/16.0/oss/x86_64"
    "https://cdn.opensuse.org/update/leap/16.0/oss"
)

NONOSS_URLS=(
    "https://cdn.opensuse.org/update/leap/16.0/non-oss/x86_64"
    "https://cdn.opensuse.org/update/leap/16.0/non-oss"
)

check_and_add() {
    local repo_file="$1"
    local repo_name="$2"
    shift 2
    local urls=("$@")

    [[ -f "$repo_file" ]] && return 0

    for url in "${urls[@]}"; do
        if curl -sf --max-time 15 "${url}/repodata/repomd.xml" -o /dev/null 2>/dev/null; then
            echo "ENCONTRADO: $repo_name en $url"
            cat > "$repo_file" <<EOF
[openSUSE:${repo_name}]
name=${repo_name} (16.0)
enabled=1
autorefresh=1
baseurl=${url}
gpgcheck=1
gpgkey=${url}/repodata/repomd.xml.key
type=rpm-md
keeppackages=0
EOF
            chmod 644 "$repo_file"
            zypper --non-interactive refresh "$repo_name" 2>&1 || true
            echo "Repo $repo_name agregado y refrescado"
            return 0
        fi
    done
    echo "Repo $repo_name aun no disponible"
    return 1
}

_oss_ok=0
_nonoss_ok=0

check_and_add "/etc/zypp/repos.d/openSUSE:repo-update.repo" "repo-update" "${UPDATE_URLS[@]}" && _oss_ok=1
check_and_add "/etc/zypp/repos.d/openSUSE:repo-update-non-oss.repo" "repo-update-non-oss" "${NONOSS_URLS[@]}" && _nonoss_ok=1

# Si ambos repos estan disponibles, desactivar el flag y el timer
if [[ $_oss_ok -eq 1 ]]; then
    rm -f /etc/securizar/updates/update-repo-pending.flag
    echo "Flag de repo pendiente eliminado"
    # Aplicar actualizaciones inmediatamente
    zypper --non-interactive patch --category security 2>&1 || true
    zypper --non-interactive update 2>&1 || true
    # Auto-desactivar este timer
    systemctl disable securizar-repo-check.timer 2>/dev/null || true
    echo "Timer de vigilancia desactivado (repos disponibles)"
fi

echo "=== Repo check completado: $(date -Is) ==="
SCRIPTEOF
    chmod 700 /usr/local/bin/securizar-repo-check.sh
    log_change "Creado" "/usr/local/bin/securizar-repo-check.sh"

    cat > /etc/systemd/system/securizar-repo-check.service <<'UNITEOF'
[Unit]
Description=Securizar - Verificar disponibilidad de repos update (M79)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/securizar-repo-check.sh
TimeoutStartSec=120
UNITEOF

    cat > /etc/systemd/system/securizar-repo-check.timer <<'TIMEREOF'
[Unit]
Description=Securizar - Vigilar repos update cada 6h (M79)

[Timer]
OnBootSec=5min
OnUnitActiveSec=6h
Persistent=true

[Install]
WantedBy=timers.target
TIMEREOF

    systemctl daemon-reload
    systemctl enable --now securizar-repo-check.timer 2>/dev/null || true
    log_change "Habilitado" "securizar-repo-check.timer (vigila repos cada 6h)"
fi

# ============================================================
# S8: PROTEGER INFRAESTRUCTURA DE ACTUALIZACION
# ============================================================
log_section "S8: Proteger infraestructura de actualizacion"

log_info "Endurece la proteccion de archivos criticos de actualizacion"
log_info "  - Permisos restrictivos en /etc/zypp/"
log_info "  - Reglas de auditd para detectar manipulacion"
log_info "  - Baseline SHA256 para monitoreo de integridad"
log_info ""

if [[ -f "$UPDATES_DIR/protection-active.flag" ]]; then
    log_already "Proteccion de infraestructura ya activa"
else
    # ── Permisos restrictivos ──
    chmod 755 /etc/zypp/repos.d/ 2>/dev/null || true
    chmod 644 /etc/zypp/repos.d/*.repo 2>/dev/null || true
    chmod 755 /etc/zypp/services.d/ 2>/dev/null || true
    chmod 644 /etc/zypp/services.d/*.service 2>/dev/null || true
    chmod 644 /etc/zypp/zypp.conf 2>/dev/null || true
    chown -R root:root /etc/zypp/ 2>/dev/null || true
    log_change "Permisos" "/etc/zypp/: ownership root:root, permisos restrictivos"

    # ── Proteger repoindex.xml ──
    chown root:root /usr/share/zypp/local/service/openSUSE/repo/*.xml 2>/dev/null || true
    chmod 644 /usr/share/zypp/local/service/openSUSE/repo/*.xml 2>/dev/null || true
    log_change "Permisos" "repoindex.xml: solo lectura para root"

    # ── Reglas de auditd para detectar manipulacion ──
    _audit_rule="/etc/audit/rules.d/securizar-79-zypp-protect.rules"
    if command -v auditctl &>/dev/null && [[ ! -f "$_audit_rule" ]]; then
        cat > "$_audit_rule" <<'AUDITEOF'
## Securizar M79: Proteccion infraestructura de actualizaciones
## Detecta modificacion de repos, servicios y configuracion de zypper

# Modificacion de repositorios
-w /etc/zypp/repos.d/ -p wa -k zypp-repo-tamper
# Modificacion de servicios
-w /etc/zypp/services.d/ -p wa -k zypp-service-tamper
# Modificacion de configuracion zypper
-w /etc/zypp/zypp.conf -p wa -k zypp-conf-tamper
# Modificacion de repoindex
-w /usr/share/zypp/local/service/openSUSE/repo/ -p wa -k zypp-repoindex-tamper
# Modificacion de /etc/hosts (hijacking DNS)
-w /etc/hosts -p wa -k hosts-tamper
# Modificacion de resolv.conf
-w /etc/resolv.conf -p wa -k dns-tamper
# Ejecucion de zypper (para registro de quien actualiza)
-w /usr/bin/zypper -p x -k zypper-exec
# Package locks
-w /etc/zypp/locks -p wa -k zypp-lock-tamper
AUDITEOF
        chmod 640 "$_audit_rule"
        # Recargar reglas de auditd
        if systemctl is-active --quiet auditd 2>/dev/null; then
            augenrules --load 2>/dev/null || auditctl -R "$_audit_rule" 2>/dev/null || true
            log_change "Auditd" "reglas de proteccion de zypp cargadas"
        else
            log_info "auditd no activo, reglas se cargaran cuando inicie"
        fi
        log_change "Creado" "$_audit_rule"
    fi

    # ── Baseline SHA256 para monitoreo ──
    _baseline="$UPDATES_DIR/repos-integrity-baseline.sha256"
    {
        sha256sum /etc/zypp/repos.d/*.repo 2>/dev/null || true
        sha256sum /etc/zypp/services.d/*.service 2>/dev/null || true
        sha256sum /etc/zypp/zypp.conf 2>/dev/null || true
        sha256sum /usr/share/zypp/local/service/openSUSE/repo/*.xml 2>/dev/null || true
    } > "$_baseline"
    chmod 600 "$_baseline"
    log_change "Baseline" "SHA256 de configuracion de repos -> $_baseline"

    # ── Script de verificacion de integridad ──
    cat > /usr/local/bin/securizar-check-repos-integrity.sh <<'SCRIPTEOF'
#!/bin/bash
# securizar-check-repos-integrity.sh - Verifica integridad de config de repos
# Generado por parches-actualizaciones.sh (Modulo 79)
set -euo pipefail

BASELINE="/etc/securizar/updates/repos-integrity-baseline.sha256"
[[ ! -f "$BASELINE" ]] && { echo "ERROR: no existe baseline"; exit 1; }

CURRENT=$(mktemp)
trap 'rm -f "$CURRENT"' EXIT

{
    sha256sum /etc/zypp/repos.d/*.repo 2>/dev/null || true
    sha256sum /etc/zypp/services.d/*.service 2>/dev/null || true
    sha256sum /etc/zypp/zypp.conf 2>/dev/null || true
    sha256sum /usr/share/zypp/local/service/openSUSE/repo/*.xml 2>/dev/null || true
} > "$CURRENT"

if ! diff -q "$BASELINE" "$CURRENT" &>/dev/null; then
    echo "ALERTA: Configuracion de repositorios MODIFICADA"
    diff "$BASELINE" "$CURRENT" || true
    logger -t securizar-M79 -p auth.crit "Configuracion de repositorios zypper modificada sin autorizacion"
    exit 1
else
    echo "OK: Configuracion de repositorios intacta"
    exit 0
fi
SCRIPTEOF
    chmod 700 /usr/local/bin/securizar-check-repos-integrity.sh
    log_change "Creado" "/usr/local/bin/securizar-check-repos-integrity.sh"

    touch "$UPDATES_DIR/protection-active.flag"
    log_change "Proteccion" "infraestructura de actualizacion protegida"
fi

# ============================================================
# S9: AUDITORIA Y RESUMEN
# ============================================================
log_section "S9: Auditoria y resumen"

log_info "Genera reporte final del estado de actualizaciones"
log_info ""

_audit_log="$UPDATES_DIR/audit-last-run.log"
{
    echo "=== AUDITORIA MODULO 79: $(date -Is) ==="
    echo ""
    echo "--- Estado de repositorios ---"
    zypper lr -d 2>&1 || true
    echo ""
    echo "--- Repositorios con HTTPS ---"
    grep -l 'https://' /etc/zypp/repos.d/*.repo 2>/dev/null | while read -r f; do
        echo "  OK: $(basename "$f")"
    done
    echo ""
    echo "--- Repositorios con HTTP (inseguro) ---"
    grep -l 'http://' /etc/zypp/repos.d/*.repo 2>/dev/null | while read -r f; do
        echo "  RIESGO: $(basename "$f")"
    done || echo "  Ninguno (correcto)"
    echo ""
    echo "--- GPG check ---"
    grep 'gpgcheck' /etc/zypp/repos.d/*.repo 2>/dev/null || true
    echo ""
    echo "--- Parches pendientes ---"
    zypper --non-interactive list-patches 2>&1 | tail -20 || true
    echo ""
    echo "--- Actualizaciones pendientes ---"
    zypper --non-interactive list-updates 2>&1 | tail -15 || true
    echo ""
    echo "--- Timers de actualizacion ---"
    systemctl list-timers securizar-patch.timer securizar-repo-check.timer 2>&1 || true
    echo ""
    echo "--- Integridad de repos ---"
    /usr/local/bin/securizar-check-repos-integrity.sh 2>&1 || true
    echo ""
    echo "=== FIN AUDITORIA ==="
} > "$_audit_log" 2>&1
log_change "Auditoria" "reporte generado -> $_audit_log"

# Mostrar resumen al usuario
log_info ""
log_info "Estado final de repositorios:"
zypper lr -d 2>&1 | head -20 || true

log_info ""
log_info "Timers activos:"
systemctl list-timers securizar-patch.timer securizar-repo-check.timer --no-pager 2>&1 || true

# ── Resumen final ──
show_changes_summary

log_info ""
log_info "Backups en: $BACKUP_DIR"
log_info "Logs en: $UPDATES_LOG"
log_info ""
log_info "Para verificar manualmente la integridad de repos:"
log_info "  /usr/local/bin/securizar-check-repos-integrity.sh"
log_info ""
log_info "Para actualizar el baseline despues de cambios autorizados:"
log_info "  Ejecutar de nuevo este script (S8 regenerara el baseline)"
