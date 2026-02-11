#!/bin/bash
# ============================================================
# securizar-pkg-map.sh - Tabla de mapeo de nombres de paquetes
# ============================================================
# Formato: PKG_MAP[generico]="suse|debian|rhel|arch"
# Funcion: pkg_resolve_name() devuelve el nombre correcto
# ============================================================

[[ -n "${_SECURIZAR_PKG_MAP_LOADED:-}" ]] && return 0
_SECURIZAR_PKG_MAP_LOADED=1

declare -gA PKG_MAP

# Formato: "suse_name|debian_name|rhel_name|arch_name"
# Usar "-" para indicar que no existe en esa distro

PKG_MAP[fail2ban]="fail2ban|fail2ban|fail2ban|fail2ban"
PKG_MAP[clamav]="clamav|clamav|clamav|clamav"
PKG_MAP[aide]="aide|aide|aide|aide"
PKG_MAP[rkhunter]="rkhunter|rkhunter|rkhunter|rkhunter"
PKG_MAP[lynis]="lynis|lynis|lynis|lynis"
PKG_MAP[firejail]="firejail|firejail|firejail|firejail"
PKG_MAP[bubblewrap]="bubblewrap|bubblewrap|bubblewrap|bubblewrap"
PKG_MAP[wireguard-tools]="wireguard-tools|wireguard-tools|wireguard-tools|wireguard-tools"
PKG_MAP[arpwatch]="arpwatch|arpwatch|arpwatch|arpwatch"
PKG_MAP[inotify-tools]="inotify-tools|inotify-tools|inotify-tools|inotify-tools"
PKG_MAP[mokutil]="mokutil|mokutil|mokutil|mokutil"
PKG_MAP[usbguard]="usbguard|usbguard|usbguard|usbguard"
PKG_MAP[suricata]="suricata|suricata|suricata|suricata"
PKG_MAP[tor]="tor|tor|tor|tor"
PKG_MAP[stunnel]="stunnel|stunnel4|stunnel|stunnel"
PKG_MAP[obfs4proxy]="obfs4proxy|obfs4proxy|obfs4proxy|obfs4proxy"
PKG_MAP[chrony]="chrony|chrony|chrony|chrony"
PKG_MAP[gocryptfs]="gocryptfs|gocryptfs|gocryptfs|gocryptfs"

# Paquetes de email y SMTP
PKG_MAP[opendkim]="opendkim|opendkim|opendkim|opendkim"
PKG_MAP[opendmarc]="opendmarc|opendmarc|opendmarc|opendmarc"
PKG_MAP[postfix]="postfix|postfix|postfix|postfix"
PKG_MAP[spamassassin]="spamassassin|spamassassin|spamassassin|spamassassin"

# Paquetes de logging centralizado
PKG_MAP[rsyslog-gnutls]="rsyslog-module-gnutls|rsyslog-gnutls|rsyslog-gnutls|rsyslog-gnutls"

# Paquetes de cadena de suministro
PKG_MAP[rpm-sign]="rpm|rpm|-|rpm-tools"
PKG_MAP[dpkg-sig]="-|dpkg-sig|-|-"
PKG_MAP[debsigs]="-|debsigs|-|-"

# Paquetes con nombres significativamente diferentes
PKG_MAP[openscap-utils]="openscap-utils|libopenscap8|openscap-utils|openscap"
PKG_MAP[scap-security-guide]="scap-security-guide|ssg-base|scap-security-guide|scap-security-guide"
PKG_MAP[apparmor-profiles]="apparmor-profiles|apparmor-profiles|apparmor-profiles|apparmor"
PKG_MAP[apparmor-utils]="apparmor-utils|apparmor-utils|apparmor-utils|apparmor"
PKG_MAP[apparmor-parser]="apparmor-parser|apparmor|apparmor-parser|apparmor"
PKG_MAP[onboard]="onboard|onboard|onboard|onboard"
PKG_MAP[kvkbd]="kvkbd|kvkbd|kvkbd|kvkbd"

# Paquetes FTP (para remover)
PKG_MAP[vsftpd]="vsftpd|vsftpd|vsftpd|vsftpd"
PKG_MAP[proftpd]="proftpd|proftpd|proftpd|proftpd"
PKG_MAP[pure-ftpd]="pure-ftpd|pure-ftpd|pure-ftpd|pure-ftpd"

# Paquetes de auditoria y monitoreo
PKG_MAP[audit]="audit|auditd|audit|audit"
PKG_MAP[libpwquality]="libpwquality1|libpam-pwquality|libpwquality|libpwquality"
PKG_MAP[nmap]="nmap|nmap|nmap|nmap"
PKG_MAP[tcpdump]="tcpdump|tcpdump|tcpdump|tcpdump"
PKG_MAP[net-tools]="net-tools|net-tools|net-tools|net-tools"
PKG_MAP[debsums]="-|debsums|-|-"
PKG_MAP[acl]="acl|acl|acl|acl"
PKG_MAP[logwatch]="logwatch|logwatch|logwatch|logwatch"
PKG_MAP[rsyslog]="rsyslog|rsyslog|rsyslog|rsyslog"

# pam google authenticator
PKG_MAP[google-authenticator-libpam]="google-authenticator-libpam|libpam-google-authenticator|google-authenticator|libpam-google-authenticator"

# Indice de familia a posicion en el mapeo
_pkg_family_index() {
    case "$DISTRO_FAMILY" in
        suse)   echo 1 ;;
        debian) echo 2 ;;
        rhel)   echo 3 ;;
        arch)   echo 4 ;;
        *)      echo 1 ;;  # fallback a suse
    esac
}

# Resuelve un nombre generico al nombre correcto para la distro actual
# Uso: pkg_resolve_name "openscap-utils"
# Si no hay mapeo, devuelve el nombre tal cual
pkg_resolve_name() {
    local generic="$1"
    local mapping="${PKG_MAP[$generic]:-}"

    if [[ -z "$mapping" ]]; then
        echo "$generic"
        return 0
    fi

    local idx
    idx=$(_pkg_family_index)
    local resolved
    resolved=$(echo "$mapping" | cut -d'|' -f"$idx")

    if [[ "$resolved" == "-" ]]; then
        # Paquete no disponible en esta distro
        return 1
    fi

    echo "$resolved"
}
