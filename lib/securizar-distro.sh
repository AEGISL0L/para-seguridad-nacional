#!/bin/bash
# ============================================================
# securizar-distro.sh - Deteccion automatica de distribucion
# ============================================================
# Exporta: DISTRO_ID, DISTRO_FAMILY, DISTRO_VERSION, DISTRO_NAME
# Familias: suse, debian, rhel, arch
# ============================================================

[[ -n "${_SECURIZAR_DISTRO_LOADED:-}" ]] && return 0
_SECURIZAR_DISTRO_LOADED=1

DISTRO_ID=""
DISTRO_FAMILY=""
DISTRO_VERSION=""
DISTRO_NAME=""

if [[ -f /etc/os-release ]]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    DISTRO_ID="${ID:-unknown}"
    DISTRO_VERSION="${VERSION_ID:-}"
    DISTRO_NAME="${PRETTY_NAME:-${NAME:-unknown}}"
else
    DISTRO_ID="unknown"
    DISTRO_NAME="Unknown Linux"
fi

# Clasificar en familias
case "$DISTRO_ID" in
    opensuse*|sles|sled)
        DISTRO_FAMILY="suse"
        ;;
    debian|ubuntu|linuxmint|pop|elementary|zorin|kali|raspbian|mx)
        DISTRO_FAMILY="debian"
        ;;
    fedora|rhel|centos|rocky|alma|ol|amzn|scientific)
        DISTRO_FAMILY="rhel"
        ;;
    arch|manjaro|endeavouros|garuda|artix)
        DISTRO_FAMILY="arch"
        ;;
    *)
        # Fallback via ID_LIKE
        if [[ -f /etc/os-release ]]; then
            _id_like=""
            _id_like=$(grep "^ID_LIKE=" /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || true)
            case "$_id_like" in
                *suse*)    DISTRO_FAMILY="suse" ;;
                *debian*|*ubuntu*) DISTRO_FAMILY="debian" ;;
                *rhel*|*fedora*|*centos*) DISTRO_FAMILY="rhel" ;;
                *arch*)    DISTRO_FAMILY="arch" ;;
                *)         DISTRO_FAMILY="unknown" ;;
            esac
            unset _id_like
        else
            DISTRO_FAMILY="unknown"
        fi
        ;;
esac

export DISTRO_ID DISTRO_FAMILY DISTRO_VERSION DISTRO_NAME
