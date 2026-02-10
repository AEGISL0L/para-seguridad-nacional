#!/bin/bash
# ============================================================
# securizar-paths.sh - Rutas GRUB y SCAP por distribucion
# ============================================================
# Requiere: securizar-distro.sh
# Exporta: GRUB_CFG, GRUB_CFG_DIR, GRUB_EFI_CFG, GRUB_MKCONFIG_CMD,
#          GRUB_USER_CFG, GRUB_SETPASSWORD_CMD,
#          SCAP_DS_PATH, SCAP_OVAL_PATH
# ============================================================

[[ -n "${_SECURIZAR_PATHS_LOADED:-}" ]] && return 0
_SECURIZAR_PATHS_LOADED=1

# ── Rutas GRUB ──────────────────────────────────────────────

case "$DISTRO_FAMILY" in
    suse|rhel)
        GRUB_CFG_DIR="/boot/grub2"
        GRUB_CFG="/boot/grub2/grub.cfg"
        GRUB_USER_CFG="/boot/grub2/user.cfg"
        GRUB_MKCONFIG_CMD="grub2-mkconfig"
        GRUB_SETPASSWORD_CMD="grub2-setpassword"
        # EFI path varies by distro
        if [[ "$DISTRO_FAMILY" == "suse" ]]; then
            GRUB_EFI_CFG="/boot/efi/EFI/opensuse/grub.cfg"
        else
            GRUB_EFI_CFG="/boot/efi/EFI/redhat/grub.cfg"
            # CentOS/Rocky/Alma may use different paths
            for _p in /boot/efi/EFI/centos/grub.cfg /boot/efi/EFI/rocky/grub.cfg /boot/efi/EFI/almalinux/grub.cfg /boot/efi/EFI/fedora/grub.cfg; do
                [[ -f "$_p" ]] && GRUB_EFI_CFG="$_p" && break
            done
            unset _p
        fi
        ;;
    debian)
        GRUB_CFG_DIR="/boot/grub"
        GRUB_CFG="/boot/grub/grub.cfg"
        GRUB_USER_CFG="/boot/grub/user.cfg"
        GRUB_EFI_CFG="/boot/efi/EFI/ubuntu/grub.cfg"
        # Debian-based may also use /boot/efi/EFI/debian/grub.cfg
        for _p in /boot/efi/EFI/debian/grub.cfg /boot/efi/EFI/ubuntu/grub.cfg; do
            [[ -f "$_p" ]] && GRUB_EFI_CFG="$_p" && break
        done
        unset _p
        if command -v update-grub &>/dev/null; then
            GRUB_MKCONFIG_CMD="update-grub"
        else
            GRUB_MKCONFIG_CMD="grub-mkconfig"
        fi
        GRUB_SETPASSWORD_CMD="grub-setpassword"
        ;;
    arch)
        GRUB_CFG_DIR="/boot/grub"
        GRUB_CFG="/boot/grub/grub.cfg"
        GRUB_USER_CFG="/boot/grub/user.cfg"
        GRUB_EFI_CFG="/boot/efi/EFI/arch/grub.cfg"
        [[ -f /boot/efi/EFI/BOOT/grub.cfg ]] && GRUB_EFI_CFG="/boot/efi/EFI/BOOT/grub.cfg"
        GRUB_MKCONFIG_CMD="grub-mkconfig"
        GRUB_SETPASSWORD_CMD="grub-setpassword"
        ;;
    *)
        # Fallback: try grub2 first, then grub
        if [[ -d /boot/grub2 ]]; then
            GRUB_CFG_DIR="/boot/grub2"
            GRUB_CFG="/boot/grub2/grub.cfg"
            GRUB_MKCONFIG_CMD="grub2-mkconfig"
        else
            GRUB_CFG_DIR="/boot/grub"
            GRUB_CFG="/boot/grub/grub.cfg"
            GRUB_MKCONFIG_CMD="grub-mkconfig"
        fi
        GRUB_USER_CFG="$GRUB_CFG_DIR/user.cfg"
        GRUB_EFI_CFG=""
        GRUB_SETPASSWORD_CMD="grub2-setpassword"
        ;;
esac

export GRUB_CFG GRUB_CFG_DIR GRUB_EFI_CFG GRUB_MKCONFIG_CMD GRUB_USER_CFG GRUB_SETPASSWORD_CMD

# ── grub_regenerate ─────────────────────────────────────────
# Regenera grub.cfg con el comando correcto para la distro
grub_regenerate() {
    if [[ "$GRUB_MKCONFIG_CMD" == "update-grub" ]]; then
        update-grub 2>/dev/null || true
    else
        "$GRUB_MKCONFIG_CMD" -o "$GRUB_CFG" 2>/dev/null || true
        if [[ -n "$GRUB_EFI_CFG" && -d "$(dirname "$GRUB_EFI_CFG")" ]]; then
            "$GRUB_MKCONFIG_CMD" -o "$GRUB_EFI_CFG" 2>/dev/null || true
        fi
    fi
}

# ── grub_set_password ───────────────────────────────────────
# Establece contrasena de GRUB usando el comando correcto
grub_set_password() {
    if command -v "$GRUB_SETPASSWORD_CMD" &>/dev/null; then
        "$GRUB_SETPASSWORD_CMD" 2>/dev/null || true
    else
        echo "AVISO: $GRUB_SETPASSWORD_CMD no encontrado. Configura contrasena GRUB manualmente." >&2
    fi
}

# ── Rutas SCAP ──────────────────────────────────────────────

SCAP_DS_PATH=""
SCAP_OVAL_PATH=""

# Buscar datastream por orden de prioridad segun distro
_scap_ds_candidates=()
_scap_oval_candidates=()

case "$DISTRO_FAMILY" in
    suse)
        _scap_ds_candidates=(
            "/usr/share/xml/scap/ssg/content/ssg-sle15-ds.xml"
            "/usr/share/xml/scap/ssg/content/ssg-opensuse-ds.xml"
            "/usr/share/xml/scap/ssg/content/ssg-sle12-ds.xml"
        )
        _scap_oval_candidates=(
            "/usr/share/xml/scap/ssg/content/ssg-sle15-oval.xml"
            "/usr/share/xml/scap/ssg/content/ssg-opensuse-oval.xml"
        )
        ;;
    debian)
        _scap_ds_candidates=(
            "/usr/share/xml/scap/ssg/content/ssg-debian12-ds.xml"
            "/usr/share/xml/scap/ssg/content/ssg-debian11-ds.xml"
            "/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml"
            "/usr/share/xml/scap/ssg/content/ssg-ubuntu2004-ds.xml"
            "/usr/share/scap-security-guide/ssg-debian12-ds.xml"
            "/usr/share/scap-security-guide/ssg-debian11-ds.xml"
            "/usr/share/scap-security-guide/ssg-ubuntu2204-ds.xml"
        )
        _scap_oval_candidates=(
            "/usr/share/xml/scap/ssg/content/ssg-debian12-oval.xml"
            "/usr/share/xml/scap/ssg/content/ssg-debian11-oval.xml"
            "/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-oval.xml"
            "/usr/share/scap-security-guide/ssg-debian12-oval.xml"
        )
        ;;
    rhel)
        _scap_ds_candidates=(
            "/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml"
            "/usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml"
            "/usr/share/xml/scap/ssg/content/ssg-centos9-ds.xml"
            "/usr/share/xml/scap/ssg/content/ssg-centos8-ds.xml"
            "/usr/share/xml/scap/ssg/content/ssg-fedora-ds.xml"
        )
        _scap_oval_candidates=(
            "/usr/share/xml/scap/ssg/content/ssg-rhel9-oval.xml"
            "/usr/share/xml/scap/ssg/content/ssg-rhel8-oval.xml"
            "/usr/share/xml/scap/ssg/content/ssg-fedora-oval.xml"
        )
        ;;
    arch)
        _scap_ds_candidates=(
            "/usr/share/xml/scap/ssg/content/ssg-archlinux-ds.xml"
        )
        _scap_oval_candidates=(
            "/usr/share/xml/scap/ssg/content/ssg-archlinux-oval.xml"
        )
        ;;
esac

# Buscar primer candidato que exista
for _c in "${_scap_ds_candidates[@]}"; do
    if [[ -f "$_c" ]]; then
        SCAP_DS_PATH="$_c"
        break
    fi
done

for _c in "${_scap_oval_candidates[@]}"; do
    if [[ -f "$_c" ]]; then
        SCAP_OVAL_PATH="$_c"
        break
    fi
done

# Si no se encontro archivo, guardar el primer candidato como referencia
if [[ -z "$SCAP_DS_PATH" && ${#_scap_ds_candidates[@]} -gt 0 ]]; then
    SCAP_DS_PATH="${_scap_ds_candidates[0]}"
fi
if [[ -z "$SCAP_OVAL_PATH" && ${#_scap_oval_candidates[@]} -gt 0 ]]; then
    SCAP_OVAL_PATH="${_scap_oval_candidates[0]}"
fi

unset _scap_ds_candidates _scap_oval_candidates _c

export SCAP_DS_PATH SCAP_OVAL_PATH
