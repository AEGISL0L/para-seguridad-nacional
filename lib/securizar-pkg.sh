#!/bin/bash
# ============================================================
# securizar-pkg.sh - Abstraccion del gestor de paquetes
# ============================================================
# Requiere: securizar-distro.sh, securizar-pkg-map.sh
# ============================================================

[[ -n "${_SECURIZAR_PKG_LOADED:-}" ]] && return 0
_SECURIZAR_PKG_LOADED=1

# Nombres legibles para mensajes al usuario
case "$DISTRO_FAMILY" in
    suse)
        PKG_MANAGER_NAME="zypper"
        PKG_UPDATE_CMD="sudo zypper up"
        ;;
    debian)
        PKG_MANAGER_NAME="apt"
        PKG_UPDATE_CMD="sudo apt update && sudo apt upgrade"
        ;;
    rhel)
        PKG_MANAGER_NAME="dnf"
        PKG_UPDATE_CMD="sudo dnf upgrade"
        ;;
    arch)
        PKG_MANAGER_NAME="pacman"
        PKG_UPDATE_CMD="sudo pacman -Syu"
        ;;
    *)
        PKG_MANAGER_NAME="(gestor de paquetes)"
        PKG_UPDATE_CMD="(actualizar paquetes manualmente)"
        ;;
esac

export PKG_MANAGER_NAME PKG_UPDATE_CMD

# ── pkg_install pkg1 [pkg2...] ─────────────────────────────
# Resuelve nombres via pkg_resolve_name y ejecuta instalacion
pkg_install() {
    local resolved=()
    local pkg resolved_name
    for pkg in "$@"; do
        resolved_name=$(pkg_resolve_name "$pkg") || continue
        resolved+=("$resolved_name")
    done

    [[ ${#resolved[@]} -eq 0 ]] && return 0

    case "$DISTRO_FAMILY" in
        suse)   zypper --non-interactive install "${resolved[@]}" ;;
        debian) DEBIAN_FRONTEND=noninteractive apt-get install -y "${resolved[@]}" ;;
        rhel)   dnf install -y "${resolved[@]}" ;;
        arch)   pacman -S --noconfirm "${resolved[@]}" ;;
        *)      echo "ERROR: gestor de paquetes no soportado ($DISTRO_FAMILY)" >&2; return 1 ;;
    esac
}

# ── pkg_remove pkg1 [pkg2...] ──────────────────────────────
pkg_remove() {
    local resolved=()
    local pkg resolved_name
    for pkg in "$@"; do
        resolved_name=$(pkg_resolve_name "$pkg") || continue
        resolved+=("$resolved_name")
    done

    [[ ${#resolved[@]} -eq 0 ]] && return 0

    case "$DISTRO_FAMILY" in
        suse)   zypper --non-interactive remove "${resolved[@]}" ;;
        debian) DEBIAN_FRONTEND=noninteractive apt-get remove -y "${resolved[@]}" ;;
        rhel)   dnf remove -y "${resolved[@]}" ;;
        arch)   pacman -R --noconfirm "${resolved[@]}" ;;
        *)      echo "ERROR: gestor de paquetes no soportado ($DISTRO_FAMILY)" >&2; return 1 ;;
    esac
}

# ── pkg_refresh ─────────────────────────────────────────────
# Actualiza la cache de repositorios
pkg_refresh() {
    case "$DISTRO_FAMILY" in
        suse)   zypper --non-interactive refresh ;;
        debian) apt-get update ;;
        rhel)   dnf makecache ;;
        arch)   pacman -Sy ;;
        *)      return 1 ;;
    esac
}

# ── pkg_patch_security ──────────────────────────────────────
# Instala solo parches/actualizaciones de seguridad
pkg_patch_security() {
    case "$DISTRO_FAMILY" in
        suse)   zypper --non-interactive patch --category security ;;
        debian) apt-get update && unattended-upgrade -d 2>/dev/null || apt-get upgrade -y ;;
        rhel)   dnf upgrade --security -y ;;
        arch)   pacman -Syu --noconfirm ;;
        *)      return 1 ;;
    esac
}

# ── pkg_list_security_patches ───────────────────────────────
# Lista parches de seguridad pendientes
pkg_list_security_patches() {
    case "$DISTRO_FAMILY" in
        suse)   zypper --non-interactive list-patches --category security ;;
        debian) apt-get update -qq && apt list --upgradable 2>/dev/null ;;
        rhel)   dnf updateinfo list security ;;
        arch)   checkupdates 2>/dev/null || echo "Instala pacman-contrib para checkupdates" ;;
        *)      return 1 ;;
    esac
}

# ── pkg_list_repos ──────────────────────────────────────────
pkg_list_repos() {
    case "$DISTRO_FAMILY" in
        suse)   zypper lr -d ;;
        debian) apt-cache policy ;;
        rhel)   dnf repolist -v ;;
        arch)   cat /etc/pacman.conf | grep -E "^\[" ;;
        *)      return 1 ;;
    esac
}

# ── pkg_is_installed pkg ────────────────────────────────────
# Devuelve 0 si el paquete esta instalado
pkg_is_installed() {
    local pkg="$1"
    local resolved
    resolved=$(pkg_resolve_name "$pkg") || return 1

    case "$DISTRO_FAMILY" in
        suse)   rpm -q "$resolved" &>/dev/null ;;
        debian) dpkg -s "$resolved" &>/dev/null ;;
        rhel)   rpm -q "$resolved" &>/dev/null ;;
        arch)   pacman -Qi "$resolved" &>/dev/null ;;
        *)      return 1 ;;
    esac
}

# ── pkg_query_all ───────────────────────────────────────────
# Lista todos los paquetes instalados (reemplazo de rpm -qa)
pkg_query_all() {
    case "$DISTRO_FAMILY" in
        suse|rhel) rpm -qa ;;
        debian)    dpkg -l | awk '/^ii/ {print $2}' ;;
        arch)      pacman -Q ;;
        *)         return 1 ;;
    esac
}

# ── pkg_query_file file ─────────────────────────────────────
# Consulta a que paquete pertenece un archivo (reemplazo de rpm -qf)
pkg_query_file() {
    local file="$1"
    case "$DISTRO_FAMILY" in
        suse|rhel) rpm -qf "$file" ;;
        debian)    dpkg -S "$file" 2>/dev/null | cut -d: -f1 ;;
        arch)      pacman -Qo "$file" 2>/dev/null | awk '{print $5}' ;;
        *)         return 1 ;;
    esac
}

# ── pkg_verify ──────────────────────────────────────────────
# Verifica integridad de paquetes instalados (reemplazo de rpm -Va)
pkg_verify() {
    case "$DISTRO_FAMILY" in
        suse|rhel) rpm -Va ;;
        debian)    debsums -c 2>/dev/null || dpkg --verify ;;
        arch)      pacman -Qkk 2>/dev/null ;;
        *)         return 1 ;;
    esac
}

# ── pkg_verify_single pkg ──────────────────────────────────
# Verifica integridad de un paquete especifico (reemplazo de rpm -V PKG)
pkg_verify_single() {
    local pkg="$1"
    case "$DISTRO_FAMILY" in
        suse|rhel) rpm -V "$pkg" ;;
        debian)    debsums "$pkg" 2>/dev/null || dpkg --verify "$pkg" ;;
        arch)      pacman -Qkk "$pkg" 2>/dev/null ;;
        *)         return 1 ;;
    esac
}

# ── pkg_query_signatures ───────────────────────────────────
# Lista paquetes con info de firma (reemplazo de rpm -qa --qf con SIGPGP)
pkg_query_signatures() {
    case "$DISTRO_FAMILY" in
        suse|rhel) rpm -qa --qf '%{NAME}-%{VERSION} %{SIGPGP:pgpsig}\n' ;;
        debian)    apt-key list 2>/dev/null; echo "---"; dpkg -l | awk '/^ii/ {print $2, $3}' ;;
        arch)      pacman -Q | while read -r p v; do echo "$p-$v (pacman-key verified)"; done ;;
        *)         return 1 ;;
    esac
}

# ── pkg_audit_tool_path ────────────────────────────────────
# Ruta al gestor de paquetes para reglas de auditoria
pkg_audit_tool_paths() {
    case "$DISTRO_FAMILY" in
        suse)
            echo "/usr/bin/zypper"
            echo "/usr/bin/rpm"
            ;;
        debian)
            echo "/usr/bin/apt"
            echo "/usr/bin/apt-get"
            echo "/usr/bin/dpkg"
            ;;
        rhel)
            echo "/usr/bin/dnf"
            echo "/usr/bin/rpm"
            ;;
        arch)
            echo "/usr/bin/pacman"
            ;;
    esac
}
