#!/bin/bash
# ============================================================
# CONTRAMEDIDAS CONTRA VIGILANCIA AVANZADA/MILITAR
# ============================================================
# TEMPEST, interceptación de señales, side-channel attacks
# ============================================================


set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   CONTRAMEDIDAS CONTRA VIGILANCIA MILITAR/AVANZADA        ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# ============================================================
# 1. PROTECCIÓN CONTRA TEMPEST (Emanaciones Electromagnéticas)
# ============================================================
echo -e "${CYAN}═══ 1. PROTECCIÓN CONTRA TEMPEST ═══${NC}"
echo ""
echo "TEMPEST permite capturar lo que se muestra en pantalla mediante"
echo "las emisiones electromagnéticas del monitor/cables."
echo ""
echo "CONTRAMEDIDAS FÍSICAS (no se pueden hacer por software):"
echo ""
echo "  ▶ Jaula de Faraday: Envuelve el equipo en malla metálica"
echo "  ▶ Cables blindados: Usa cables con blindaje EMI"
echo "  ▶ Filtros de línea: En la toma de corriente"
echo "  ▶ Monitores con bajo EMI o pantallas de papel electrónico"
echo "  ▶ Habitación apantallada (pintura con partículas metálicas)"
echo ""

# Contramedidas por software
if ask "¿Aplicar contramedidas de software contra TEMPEST?"; then
    log_info "Aplicando ruido visual para dificultar captura TEMPEST..."

    # Crear script que añade ruido visual sutil
    cat > /usr/local/bin/tempest-noise.sh << 'EOFTEMPEST'
#!/bin/bash
# Genera actividad visual aleatoria para interferir TEMPEST
# Ejecutar en segundo plano

while true; do
    # Cambiar brillo sutilmente de forma aleatoria
    BRIGHTNESS=$(cat /sys/class/backlight/*/brightness 2>/dev/null | head -1)
    if [[ -n "$BRIGHTNESS" ]]; then
        VARIATION=$((RANDOM % 5))
        NEW=$((BRIGHTNESS + VARIATION - 2))
        echo $NEW > /sys/class/backlight/*/brightness 2>/dev/null || true
    fi
    sleep 0.5
done
EOFTEMPEST
    chmod +x /usr/local/bin/tempest-noise.sh
    log_info "Script de ruido TEMPEST creado: /usr/local/bin/tempest-noise.sh"
fi

# ============================================================
# 2. PROTECCIÓN CONTRA ACOUSTIC KEYSTROKE LOGGING
# ============================================================
echo ""
echo -e "${CYAN}═══ 2. PROTECCIÓN CONTRA ACOUSTIC LOGGING ═══${NC}"
echo ""
echo "Los atacantes pueden capturar lo que tecleas mediante el sonido"
echo "de las teclas (cada tecla tiene un sonido único)."
echo ""
echo "CONTRAMEDIDAS:"
echo ""
echo "  ▶ Usar teclado silencioso o con switches silenciosos"
echo "  ▶ Reproducir ruido blanco mientras tecleas"
echo "  ▶ Usar teclado virtual para datos sensibles"
echo "  ▶ Alfombrilla gruesa bajo el teclado"
echo ""

if ask "¿Instalar generador de ruido acústico?"; then
    # Crear script de ruido blanco
    cat > /usr/local/bin/ruido-blanco.sh << 'EOFNOISE'
#!/bin/bash
# Genera ruido blanco para enmascarar sonido del teclado
# Requiere: paplay o aplay

if command -v paplay &>/dev/null; then
    # Generar y reproducir ruido blanco
    while true; do
        dd if=/dev/urandom bs=1024 count=1 2>/dev/null | \
        paplay --raw --rate=8000 --channels=1 --format=u8 2>/dev/null
    done
elif command -v aplay &>/dev/null; then
    while true; do
        dd if=/dev/urandom bs=1024 count=1 2>/dev/null | \
        aplay -f U8 -r 8000 -c 1 2>/dev/null
    done
else
    echo "Instala pulseaudio o alsa-utils"
fi
EOFNOISE
    chmod +x /usr/local/bin/ruido-blanco.sh
    log_info "Generador de ruido: /usr/local/bin/ruido-blanco.sh"
fi

# ============================================================
# 3. PROTECCIÓN DE RED - TOR + VPN
# ============================================================
echo ""
echo -e "${CYAN}═══ 3. ANONIMIZACIÓN DE RED (TOR + VPN) ═══${NC}"
echo ""
echo "Para evitar interceptación de tráfico a nivel de ISP/militar:"
echo ""

if ask "¿Instalar Tor Browser?"; then
    log_info "Descargando Tor Browser..."

    TOR_DIR=~/.local/share/tor-browser
    mkdir -p "$TOR_DIR"

    # Descargar Tor Browser
    wget -q --show-progress -O /tmp/tor.tar.xz \
        "https://www.torproject.org/dist/torbrowser/13.5.1/tor-browser-linux-x86_64-13.5.1.tar.xz" 2>/dev/null || {
        log_warn "No se pudo descargar automáticamente"
        echo "Descarga manual: https://www.torproject.org/download/"
    }

    if [[ -f /tmp/tor.tar.xz ]]; then
        tar -xf /tmp/tor.tar.xz -C "$TOR_DIR" --strip-components=1
        rm /tmp/tor.tar.xz
        log_info "Tor Browser instalado en: $TOR_DIR"
        log_info "Ejecutar: $TOR_DIR/start-tor-browser"
    fi
fi

if ask "¿Configurar DNS sobre Tor?"; then
    # Instalar tor daemon
    pkg_install tor

    if command -v tor &>/dev/null; then
        sudo systemctl enable --now tor

        # Configurar resolución DNS por Tor
        cat > /tmp/tor-dns.conf << 'EOF'
DNSPort 9053
AutomapHostsOnResolve 1
EOF
        sudo cp /tmp/tor-dns.conf /etc/tor/torrc.d/dns.conf 2>/dev/null || \
        sudo bash -c 'cat /tmp/tor-dns.conf >> /etc/tor/torrc'

        sudo systemctl restart tor

        log_info "DNS sobre Tor configurado en puerto 9053"
        log_info "Para usar: edita /etc/resolv.conf -> nameserver 127.0.0.1"
    fi
fi

# ============================================================
# 4. CIFRADO DE TRÁFICO LOCAL (MAC Spoofing)
# ============================================================
echo ""
echo -e "${CYAN}═══ 4. MAC ADDRESS ALEATORIO ═══${NC}"
echo ""

if ask "¿Configurar MAC aleatorio permanente?"; then
    # NetworkManager random MAC
    sudo mkdir -p /etc/NetworkManager/conf.d/
    sudo tee /etc/NetworkManager/conf.d/99-random-mac.conf > /dev/null << 'EOF'
[device]
wifi.scan-rand-mac-address=yes

[connection]
wifi.cloned-mac-address=random
ethernet.cloned-mac-address=random
connection.stable-id=${CONNECTION}/${BOOT}
EOF

    sudo systemctl restart NetworkManager
    log_info "MAC aleatorio configurado para todas las conexiones"
fi

# ============================================================
# 5. TECLADO VIRTUAL PARA CONTRASEÑAS
# ============================================================
echo ""
echo -e "${CYAN}═══ 5. TECLADO VIRTUAL SEGURO ═══${NC}"
echo ""

if ask "¿Instalar teclado virtual para contraseñas sensibles?"; then
    pkg_install onboard || \
    pkg_install kvkbd

    log_info "Teclado virtual instalado"
    log_info "Usa el teclado virtual para escribir contraseñas sensibles"
    log_info "Esto evita keyloggers de hardware y acoustic logging"
fi

# ============================================================
# 6. VERIFICAR INTEGRIDAD DE FIRMWARE
# ============================================================
echo ""
echo -e "${CYAN}═══ 6. VERIFICACIÓN DE FIRMWARE ═══${NC}"
echo ""
echo "Ataques de nivel militar pueden comprometer el BIOS/UEFI."
echo ""

log_warn "VERIFICACIONES MANUALES NECESARIAS:"
echo ""
echo "1. Verificar hash del firmware UEFI con el fabricante"
echo "2. Habilitar Secure Boot en BIOS"
echo "3. Establecer contraseña de BIOS"
echo "4. Deshabilitar boot desde USB/red en BIOS"
echo "5. Verificar que no hay dispositivos USB desconocidos:"
echo ""
lsusb
echo ""
echo "6. Verificar módulos del kernel cargados:"
echo ""
lsmod | head -20

# ============================================================
# 7. GENERAR RUIDO EN LA RED (DECOY TRAFFIC)
# ============================================================
echo ""
echo -e "${CYAN}═══ 9. TRÁFICO SEÑUELO (DECOY) ═══${NC}"
echo ""
echo "Genera tráfico falso para confundir análisis de tráfico."
echo ""

if ask "¿Crear generador de tráfico señuelo?"; then
    cat > /usr/local/bin/trafico-decoy.sh << 'EOFDECOY'
#!/bin/bash
# Genera tráfico de red aleatorio para confundir análisis

SITES=(
    "https://www.wikipedia.org"
    "https://www.reddit.com"
    "https://news.ycombinator.com"
    "https://www.bbc.com"
    "https://www.reuters.com"
    "https://www.github.com"
    "https://stackoverflow.com"
    "https://www.amazon.com"
)

echo "Generando tráfico señuelo..."
echo "Ctrl+C para detener"

while true; do
    SITE=${SITES[$RANDOM % ${#SITES[@]}]}
    curl -s -o /dev/null "$SITE" 2>/dev/null &
    sleep $((RANDOM % 10 + 1))
done
EOFDECOY
    chmod +x /usr/local/bin/trafico-decoy.sh
    log_info "Generador de tráfico señuelo: trafico-decoy.sh"
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║    CONTRAMEDIDAS AVANZADAS CONFIGURADAS                   ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "HERRAMIENTAS INSTALADAS:"
echo "  • tempest-noise.sh    - Ruido visual contra TEMPEST"
echo "  • ruido-blanco.sh     - Ruido acústico contra keylogging"
echo "  • trafico-decoy.sh    - Tráfico falso para confundir"
echo ""
echo "MEDIDAS FÍSICAS NECESARIAS (no se pueden hacer por software):"
echo ""
echo "  ⚠️  TEMPEST: Jaula de Faraday o habitación apantallada"
echo "  ⚠️  KEYLOGGER HARDWARE: Inspeccionar conexiones USB/teclado"
echo "  ⚠️  CÁMARA: Cubrir físicamente la webcam"
echo "  ⚠️  MICRÓFONO: Usar bloqueador de audio o desconectar"
echo "  ⚠️  FIRMWARE: Verificar integridad de BIOS/UEFI"
echo ""
echo "PARA COMUNICACIONES SENSIBLES:"
echo ""
echo "  1. Usar Tor Browser para navegación"
echo "  2. Usar Signal o similar para mensajes (con desaparición)"
echo "  3. Considerar Tails OS (sistema operativo amnésico)"
echo "  4. Air-gap para documentos muy sensibles"
echo ""
log_alert "Si realmente enfrentas vigilancia militar, considera:"
log_alert "  • Consultar con expertos en seguridad"
log_alert "  • Contactar con organizaciones de derechos digitales"
log_alert "  • Asesoría legal especializada"
