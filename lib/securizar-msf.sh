#!/bin/bash
# ============================================================
# securizar-msf.sh - Abstracción de Metasploit Framework
# ============================================================
# Detecta: msfconsole → MSF_AVAILABLE=0|1
# Exporta: MSF_AVAILABLE, MSF_HOME, MSF_RC_DIR, MSF_RESULTS_DIR, MSF_TIMEOUT
# Return codes: 0=ok, 1=fallo, 2=no disponible
# ============================================================

[[ -n "${_SECURIZAR_MSF_LOADED:-}" ]] && return 0
_SECURIZAR_MSF_LOADED=1

# ── Detección de Metasploit ──────────────────────────────────
if command -v msfconsole &>/dev/null; then
    MSF_AVAILABLE=1
else
    MSF_AVAILABLE=0
fi

# ── Globals ──────────────────────────────────────────────────
MSF_HOME="${MSF_HOME:-/opt/metasploit-framework}"
MSF_RC_DIR="/var/lib/purple-team/msf-rc"
MSF_RESULTS_DIR="/var/lib/purple-team/msf-results"
MSF_TIMEOUT="${SECURIZAR_MSF_TIMEOUT:-120}"
MSF_TARGETS="${SECURIZAR_MSF_TARGETS:-127.0.0.1}"

export MSF_AVAILABLE MSF_HOME MSF_RC_DIR MSF_RESULTS_DIR MSF_TIMEOUT MSF_TARGETS

# Estado interno: ¿arrancamos PostgreSQL nosotros?
_MSF_PG_STARTED=0

# ── msf_is_available ─────────────────────────────────────────
# Retorna 0 si Metasploit está disponible, 2 si no
msf_is_available() {
    [[ "$MSF_AVAILABLE" -eq 1 ]] && return 0
    return 2
}

# ── msf_db_init ──────────────────────────────────────────────
# Arranca PostgreSQL + msfdb init si necesario
msf_db_init() {
    msf_is_available || return 2

    # Asegurar directorios
    mkdir -p "$MSF_RC_DIR" "$MSF_RESULTS_DIR"

    # Verificar si PostgreSQL ya está corriendo
    if ! systemctl is-active postgresql &>/dev/null 2>&1; then
        echo "[*] Arrancando PostgreSQL para Metasploit..."
        systemctl start postgresql 2>/dev/null || {
            echo "[!] No se pudo arrancar PostgreSQL" >&2
            return 1
        }
        _MSF_PG_STARTED=1
    fi

    # Inicializar base de datos MSF si necesario
    if command -v msfdb &>/dev/null; then
        msfdb init &>/dev/null || true
    fi

    return 0
}

# ── _msf_exec command [timeout] ──────────────────────────────
# Wrapper interno con timeout y logging
_msf_exec() {
    local cmd="$1"
    local tout="${2:-$MSF_TIMEOUT}"
    local tmp_rc tmp_out

    tmp_rc=$(mktemp "${MSF_RC_DIR}/msf-cmd-XXXXXX.rc")
    tmp_out=$(mktemp "${MSF_RESULTS_DIR}/msf-out-XXXXXX.txt")

    echo "$cmd" > "$tmp_rc"
    echo "exit" >> "$tmp_rc"

    timeout "$tout" msfconsole -q -r "$tmp_rc" > "$tmp_out" 2>&1
    local rc=$?

    rm -f "$tmp_rc"

    if [[ $rc -eq 124 ]]; then
        echo "[!] Timeout ejecutando Metasploit (${tout}s)" >&2
        rm -f "$tmp_out"
        return 1
    fi

    cat "$tmp_out"
    rm -f "$tmp_out"
    return $rc
}

# ── msf_run_check module rhosts [opts] ───────────────────────
# Ejecuta módulo en modo check (no destructivo)
msf_run_check() {
    local module="$1"
    local rhosts="${2:-$MSF_TARGETS}"
    local opts="${3:-}"

    msf_is_available || return 2

    local cmd="use ${module}
set RHOSTS ${rhosts}
${opts}
check"

    _msf_exec "$cmd" "$MSF_TIMEOUT"
}

# ── msf_run_scan module rhosts [opts] ────────────────────────
# Ejecuta auxiliary/scanner
msf_run_scan() {
    local module="$1"
    local rhosts="${2:-$MSF_TARGETS}"
    local opts="${3:-}"

    msf_is_available || return 2

    local cmd="use ${module}
set RHOSTS ${rhosts}
${opts}
run"

    _msf_exec "$cmd" "$MSF_TIMEOUT"
}

# ── msf_run_rc rc_file ───────────────────────────────────────
# Ejecuta resource script .rc
msf_run_rc() {
    local rc_file="$1"

    msf_is_available || return 2

    if [[ ! -f "$rc_file" ]]; then
        echo "[!] Resource script no encontrado: $rc_file" >&2
        return 1
    fi

    timeout "$MSF_TIMEOUT" msfconsole -q -r "$rc_file" 2>&1
    local rc=$?

    if [[ $rc -eq 124 ]]; then
        echo "[!] Timeout ejecutando resource script (${MSF_TIMEOUT}s)" >&2
        return 1
    fi

    return $rc
}

# ── msf_generate_payload format lhost lport output ───────────
# Wrapper msfvenom para test de antivirus
msf_generate_payload() {
    local format="$1"
    local lhost="${2:-127.0.0.1}"
    local lport="${3:-4444}"
    local output="$4"

    msf_is_available || return 2

    if ! command -v msfvenom &>/dev/null; then
        echo "[!] msfvenom no encontrado" >&2
        return 1
    fi

    timeout "$MSF_TIMEOUT" msfvenom -p linux/x64/meterpreter/reverse_tcp \
        LHOST="$lhost" LPORT="$lport" -f "$format" -o "$output" 2>&1
    local rc=$?

    if [[ $rc -eq 124 ]]; then
        echo "[!] Timeout generando payload (${MSF_TIMEOUT}s)" >&2
        return 1
    fi

    return $rc
}

# ── msf_parse_output text pattern ────────────────────────────
# Parsea salida MSF ([+], [-], [*])
# Retorna 0 si el patrón se encuentra, 1 si no
msf_parse_output() {
    local text="$1"
    local pattern="$2"

    echo "$text" | grep -qiE "$pattern"
}

# ── msf_cleanup ──────────────────────────────────────────────
# Limpia temporales, para PostgreSQL si lo arrancamos
msf_cleanup() {
    # Limpiar temporales antiguos (>1 día)
    find "$MSF_RC_DIR" -name "msf-cmd-*.rc" -mtime +1 -delete 2>/dev/null || true
    find "$MSF_RESULTS_DIR" -name "msf-out-*.txt" -mtime +1 -delete 2>/dev/null || true

    # Parar PostgreSQL solo si lo arrancamos nosotros
    if [[ "$_MSF_PG_STARTED" -eq 1 ]]; then
        echo "[*] Parando PostgreSQL (arrancado por securizar)..."
        systemctl stop postgresql 2>/dev/null || true
        _MSF_PG_STARTED=0
    fi

    return 0
}
