#!/bin/bash
# ============================================================
# corregir-adaptador-red.sh - Correcciones de auditoria de red
# ============================================================
# Aplica hallazgos de la auditoria del adaptador de red:
#   A3  (ALTO)    IPv6 tempaddr inconsistente
#   A4  (ALTO)    ARP ignore per-interface wlp0s20f3
#   M4  (MEDIO)   TCP SACK/DSACK superficie innecesaria
#   M5  (MEDIO)   TCP keepalive demasiado permisivo
#   M6  (MEDIO)   NM connectivity check (tracking)
#   M7  (MEDIO)   Firefox HTTPS-Only mode
#   B1  (BAJO)    NM wifi enable/disable sin auth
#   B2  (BAJO)    iwlwifi bt_coex_active innecesario
# ============================================================
# Ejecutar como root: sudo bash corregir-adaptador-red.sh
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
init_backup "corregir-adaptador-red"
securizar_setup_traps

# ── Pre-check ──
_precheck 8
_pc check_sysctl net.ipv6.conf.all.use_tempaddr 2
_pc check_sysctl net.ipv4.conf.wlp0s20f3.arp_ignore 1
_pc check_sysctl net.ipv4.tcp_sack 0
_pc check_sysctl net.ipv4.tcp_keepalive_time 600
_pc check_file_exists /etc/NetworkManager/conf.d/99-no-connectivity-check.conf
_pc check_file_exists /usr/share/polkit-1/rules.d/50-restrict-nm-wifi.rules
_pc check_file_contains /etc/modprobe.d/network-hardening.conf "bt_coex_active=N"
_pc true  # M7: Firefox (verificacion manual)
_precheck_result

echo ""
log_section "Correcciones de auditoria del adaptador de red"
echo ""

# ============================================
# A3. IPv6 tempaddr inconsistente
# ============================================
log_info "=== A3. IPv6 use_tempaddr (defensa en profundidad) ==="
echo "net.ipv6.conf.all.use_tempaddr=0 pero default=1."
echo "Si IPv6 se reactiva, algunas interfaces no usarian direcciones temporales."
echo ""

if check_sysctl net.ipv6.conf.all.use_tempaddr 2; then
    log_already "IPv6 use_tempaddr=2 en all"
elif ask "¿Corregir use_tempaddr=2 en conf.all?"; then
    safe_backup_file /etc/sysctl.d/99-disable-ipv6.conf
    # Anadir al fichero existente si no contiene la linea
    if ! grep -q "net.ipv6.conf.all.use_tempaddr" /etc/sysctl.d/99-disable-ipv6.conf 2>/dev/null; then
        echo "" >> /etc/sysctl.d/99-disable-ipv6.conf
        echo "# Defensa en profundidad: si IPv6 se reactiva, usar tempaddr" >> /etc/sysctl.d/99-disable-ipv6.conf
        echo "net.ipv6.conf.all.use_tempaddr = 2" >> /etc/sysctl.d/99-disable-ipv6.conf
        sysctl -w net.ipv6.conf.all.use_tempaddr=2 > /dev/null
        log_change "Aplicado" "net.ipv6.conf.all.use_tempaddr=2"
    fi
else
    log_skip "IPv6 use_tempaddr"
fi

# ============================================
# A4. ARP ignore per-interface
# ============================================
echo ""
log_info "=== A4. ARP ignore en wlp0s20f3 ==="
echo "arp_ignore=1 global, pero 0 en la interfaz WiFi."
echo "El valor per-interface tiene precedencia -> vulnerable a ARP spoofing."
echo ""

if check_sysctl net.ipv4.conf.wlp0s20f3.arp_ignore 1; then
    log_already "arp_ignore=1 en wlp0s20f3"
elif ask "¿Aplicar arp_ignore=1 en wlp0s20f3?"; then
    # Anadir al fichero de network hardening existente
    safe_backup_file /etc/sysctl.d/99-network-hardening.conf
    if ! grep -q "conf.wlp0s20f3.arp_ignore" /etc/sysctl.d/99-network-hardening.conf 2>/dev/null; then
        {
            echo ""
            echo "# Correccion auditoria: ARP ignore per-interface"
            echo "net.ipv4.conf.wlp0s20f3.arp_ignore = 1"
            echo "net.ipv4.conf.enp2s0.arp_ignore = 1"
        } >> /etc/sysctl.d/99-network-hardening.conf
    fi
    sysctl -w net.ipv4.conf.wlp0s20f3.arp_ignore=1 > /dev/null
    sysctl -w net.ipv4.conf.enp2s0.arp_ignore=1 > /dev/null
    log_change "Aplicado" "arp_ignore=1 en wlp0s20f3 + enp2s0"
else
    log_skip "ARP ignore per-interface"
fi

# ============================================
# M4. TCP SACK/DSACK
# ============================================
echo ""
log_info "=== M4. Deshabilitar TCP SACK/DSACK ==="
echo "tcp_sack y tcp_dsack habilitados. Historicamente vulnerables"
echo "(CVE-2019-11477/11478/11479). Innecesarios en red domestica WiFi."
echo ""

if check_sysctl net.ipv4.tcp_sack 0; then
    log_already "tcp_sack=0"
elif ask "¿Deshabilitar TCP SACK y DSACK?"; then
    safe_backup_file /etc/sysctl.d/99-network-hardening.conf
    if ! grep -q "tcp_sack" /etc/sysctl.d/99-network-hardening.conf 2>/dev/null; then
        {
            echo ""
            echo "# Correccion auditoria: deshabilitar SACK (CVE-2019-11477)"
            echo "net.ipv4.tcp_sack = 0"
            echo "net.ipv4.tcp_dsack = 0"
        } >> /etc/sysctl.d/99-network-hardening.conf
    fi
    sysctl -w net.ipv4.tcp_sack=0 > /dev/null
    sysctl -w net.ipv4.tcp_dsack=0 > /dev/null
    log_change "Aplicado" "tcp_sack=0, tcp_dsack=0"
else
    log_skip "TCP SACK/DSACK"
fi

# ============================================
# M5. TCP keepalive time
# ============================================
echo ""
log_info "=== M5. Reducir TCP keepalive time ==="
echo "tcp_keepalive_time=7200 (2 horas). Conexiones zombie persisten"
echo "demasiado. Reducir a 600s (10 min) para deteccion rapida."
echo ""

if check_sysctl net.ipv4.tcp_keepalive_time 600; then
    log_already "tcp_keepalive_time=600"
elif ask "¿Reducir tcp_keepalive_time a 600?"; then
    safe_backup_file /etc/sysctl.d/99-network-hardening.conf
    if ! grep -q "tcp_keepalive_time" /etc/sysctl.d/99-network-hardening.conf 2>/dev/null; then
        {
            echo ""
            echo "# Correccion auditoria: keepalive mas agresivo"
            echo "net.ipv4.tcp_keepalive_time = 600"
            echo "net.ipv4.tcp_keepalive_intvl = 30"
            echo "net.ipv4.tcp_keepalive_probes = 5"
        } >> /etc/sysctl.d/99-network-hardening.conf
    fi
    sysctl -w net.ipv4.tcp_keepalive_time=600 > /dev/null
    sysctl -w net.ipv4.tcp_keepalive_intvl=30 > /dev/null
    sysctl -w net.ipv4.tcp_keepalive_probes=5 > /dev/null
    log_change "Aplicado" "tcp_keepalive: time=600 intvl=30 probes=5"
else
    log_skip "TCP keepalive time"
fi

# ============================================
# M6. NetworkManager connectivity check
# ============================================
echo ""
log_info "=== M6. Deshabilitar NM connectivity check ==="
echo "NetworkManager envia peticiones periodicas a servidores GNOME"
echo "para verificar conectividad. Genera tracking innecesario."
echo ""

if check_file_exists /etc/NetworkManager/conf.d/99-no-connectivity-check.conf; then
    log_already "NM connectivity check deshabilitado"
elif ask "¿Deshabilitar NM connectivity check?"; then
    cat > /etc/NetworkManager/conf.d/99-no-connectivity-check.conf << 'EOF'
# Correccion auditoria: deshabilitar phone-home a GNOME
[connectivity]
enabled=false
EOF
    chmod 644 /etc/NetworkManager/conf.d/99-no-connectivity-check.conf
    log_change "Creado" "/etc/NetworkManager/conf.d/99-no-connectivity-check.conf"
    nmcli general reload conf 2>/dev/null || true
    log_change "Recargado" "NetworkManager conf"
else
    log_skip "NM connectivity check"
fi

# ============================================
# M7. Firefox HTTPS-Only mode
# ============================================
echo ""
log_info "=== M7. Firefox HTTPS-Only mode ==="
echo "Se detectaron conexiones HTTP plano (puerto 80) desde Firefox."
echo "Activar HTTPS-Only fuerza HTTPS en toda navegacion."
echo ""

# Buscar perfiles de Firefox
FIREFOX_PROFILES_DIR=""
for d in /home/*/.mozilla/firefox; do
    [[ -d "$d" ]] && FIREFOX_PROFILES_DIR="$d" && break
done

if [[ -n "$FIREFOX_PROFILES_DIR" ]]; then
    _m7_applied=0
    while IFS= read -r -d '' profile_dir; do
        if grep -q 'user_pref("dom.security.https_only_mode", true)' "$profile_dir/user.js" 2>/dev/null; then
            _m7_applied=1
        fi
    done < <(find "$FIREFOX_PROFILES_DIR" -maxdepth 1 -name "*.default*" -type d -print0 2>/dev/null)

    if [[ $_m7_applied -eq 1 ]]; then
        log_already "Firefox HTTPS-Only mode"
    elif ask "¿Activar HTTPS-Only en Firefox via user.js?"; then
        while IFS= read -r -d '' profile_dir; do
            # Backup user.js si existe
            [[ -f "$profile_dir/user.js" ]] && safe_backup_file "$profile_dir/user.js"
            {
                echo ""
                echo '// Correccion auditoria: forzar HTTPS-Only'
                echo 'user_pref("dom.security.https_only_mode", true);'
                echo 'user_pref("dom.security.https_only_mode_ever_enabled", true);'
                echo 'user_pref("dom.security.https_only_mode.upgrade_local", true);'
                echo 'user_pref("dom.security.https_only_mode_ever_enabled_pbm", true);'
            } >> "$profile_dir/user.js"
            # Preservar permisos del usuario propietario del perfil
            local_user=$(stat -c '%U' "$profile_dir")
            chown "$local_user:$(id -gn "$local_user")" "$profile_dir/user.js"
            log_change "Aplicado" "HTTPS-Only en $profile_dir"
        done < <(find "$FIREFOX_PROFILES_DIR" -maxdepth 1 -name "*.default*" -type d -print0 2>/dev/null)
        log_warn "Requiere reiniciar Firefox para aplicarse"
    else
        log_skip "Firefox HTTPS-Only"
    fi
else
    log_warn "No se encontraron perfiles de Firefox"
fi

# ============================================
# B1. Polkit restrict NM wifi toggle
# ============================================
echo ""
log_info "=== B1. Restringir toggle WiFi sin autenticacion ==="
echo "Cualquier proceso del usuario puede deshabilitar la red WiFi"
echo "sin pedir credenciales. Restringir via polkit."
echo ""

POLKIT_RULES_DIR="/usr/share/polkit-1/rules.d"
POLKIT_RULE_FILE="${POLKIT_RULES_DIR}/50-restrict-nm-wifi.rules"

if check_file_exists "$POLKIT_RULE_FILE"; then
    log_already "Polkit NM wifi restriccion"
elif ask "¿Restringir enable/disable WiFi a usuarios con auth?"; then
    mkdir -p "$POLKIT_RULES_DIR"
    cat > "$POLKIT_RULE_FILE" << 'POLKIT_EOF'
// Correccion auditoria: requerir auth para toggle WiFi
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.NetworkManager.enable-disable-wifi" &&
        !subject.isInGroup("wheel")) {
        return polkit.Result.AUTH_ADMIN;
    }
});
POLKIT_EOF
    chmod 644 "$POLKIT_RULE_FILE"
    log_change "Creado" "$POLKIT_RULE_FILE"
else
    log_skip "Polkit NM wifi"
fi

# ============================================
# B2. iwlwifi bt_coex_active
# ============================================
echo ""
log_info "=== B2. Deshabilitar bt_coex_active en iwlwifi ==="
echo "Bluetooth esta deshabilitado a nivel kernel y servicio,"
echo "pero iwlwifi mantiene la coexistencia BT activa en firmware."
echo ""

if check_file_contains /etc/modprobe.d/network-hardening.conf "bt_coex_active=N" 2>/dev/null; then
    log_already "iwlwifi bt_coex_active=N"
elif ask "¿Deshabilitar bt_coex_active en iwlwifi?"; then
    safe_backup_file /etc/modprobe.d/network-hardening.conf
    if ! grep -q "bt_coex_active" /etc/modprobe.d/network-hardening.conf 2>/dev/null; then
        {
            echo ""
            echo "# Correccion auditoria: deshabilitar coexistencia BT (BT ya deshabilitado)"
            echo "options iwlwifi bt_coex_active=N"
        } >> /etc/modprobe.d/network-hardening.conf
    fi
    log_change "Aplicado" "iwlwifi bt_coex_active=N (efectivo tras reboot)"
    log_warn "Requiere reiniciar para que el modulo iwlwifi recargue con el parametro"
else
    log_skip "iwlwifi bt_coex_active"
fi

# ── Resumen ──
echo ""
show_changes_summary
echo ""
log_info "Ejecucion completada."
