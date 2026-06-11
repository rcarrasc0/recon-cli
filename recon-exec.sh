#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
#  recon-cli · recon-exec.sh  v1.1.0
#  Launcher con validación de parámetros, carga de entorno
#  y paso de argumentos al main.py
#
#  Uso:
#    chmod +x recon-exec.sh
#    ./recon-exec.sh <dominio|IP> [opciones adicionales]
#
#  Ejemplos:
#    ./recon-exec.sh ejemplo.com
#    ./recon-exec.sh 1.2.3.4 --skip-leaks --verbose
#    ./recon-exec.sh ejemplo.com --scope greybox --output /tmp/report.pdf
# ─────────────────────────────────────────────────────────────

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
die()   { echo -e "${RED}[✗]${NC} $1"; exit 1; }

# ── Validación de parámetros ──────────────────────────────────

# Sin argumentos
if [[ $# -eq 0 ]]; then
    echo -e "\n${BOLD}  recon-cli · Launcher${NC}"
    echo    "  ─────────────────────────────────────────"
    echo -e "  ${RED}Error: debes indicar un target.${NC}"
    echo    ""
    echo    "  Uso:   ./recon-exec.sh <dominio|IP> [opciones]"
    echo    ""
    echo    "  Ejemplos:"
    echo    "    ./recon-exec.sh ejemplo.com"
    echo    "    ./recon-exec.sh 1.2.3.4 --skip-leaks"
    echo    "    ./recon-exec.sh ejemplo.com --scope greybox --verbose"
    echo    ""
    echo    "  Opciones disponibles:"
    echo    "    --scope [blackbox|greybox]   Tipo de análisis (default: blackbox)"
    echo    "    --skip-leaks                 Omitir Leak-Lookup"
    echo    "    --skip-shodan                Omitir Shodan"
    echo    "    --skip-ssl                   Omitir análisis SSL/TLS"
    echo    "    --skip-cves                  Omitir búsqueda de CVEs"
    echo    "    --output <ruta.pdf>          Ruta del informe PDF"
    echo    "    --verbose / -v               Output detallado"
    echo -e "  ─────────────────────────────────────────\n"
    exit 1
fi

TARGET="$1"
shift  # El resto de argumentos se pasan tal cual al main.py

# Validar formato: dominio o IPv4
DOMAIN_RE='^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
IPV4_RE='^([0-9]{1,3}\.){3}[0-9]{1,3}$'

is_valid_target=false

if [[ "$TARGET" =~ $DOMAIN_RE ]]; then
    is_valid_target=true
    target_type="dominio"
elif [[ "$TARGET" =~ $IPV4_RE ]]; then
    # Validar que cada octeto esté entre 0-255
    IFS='.' read -r o1 o2 o3 o4 <<< "$TARGET"
    if [[ $o1 -le 255 && $o2 -le 255 && $o3 -le 255 && $o4 -le 255 ]]; then
        is_valid_target=true
        target_type="IPv4"
    else
        die "IP inválida: algún octeto fuera de rango (0-255) → $TARGET"
    fi
fi

if [[ "$is_valid_target" == false ]]; then
    die "Target inválido: '$TARGET'\n  Se esperaba un dominio (ej: ejemplo.com) o una IPv4 (ej: 1.2.3.4)"
fi

# Advertencia para IPs privadas (RFC 1918)
if [[ "$TARGET" =~ $IPV4_RE ]]; then
    IFS='.' read -r o1 o2 o3 o4 <<< "$TARGET"
    if [[ $o1 -eq 10 ]] || \
       [[ $o1 -eq 172 && $o2 -ge 16 && $o2 -le 31 ]] || \
       [[ $o1 -eq 192 && $o2 -eq 168 ]]; then
        warn "IP privada detectada ($TARGET) — algunas fases (Shodan, Leaks) no aplican"
    fi
fi

# ── Localizar directorio del script ──────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
MAIN_PY="$SCRIPT_DIR/main.py"

# ── Verificar entorno ─────────────────────────────────────────
[[ ! -d "$VENV_DIR" ]]  && die "Entorno virtual no encontrado. Ejecuta primero: ./setup.sh"
[[ ! -f "$MAIN_PY" ]]   && die "main.py no encontrado en $SCRIPT_DIR"
[[ ! -f "$SCRIPT_DIR/.env" ]] && warn ".env no encontrado — APIs no estarán disponibles. Crea .env desde .env.example"

# ── Activar entorno virtual ───────────────────────────────────
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate" || die "No se pudo activar el entorno virtual"

# ── Lanzar análisis ───────────────────────────────────────────
echo -e "\n${BOLD}  recon-cli · Launcher${NC}"
echo    "  ─────────────────────────────────────────"
ok  "Target validado: ${BOLD}$TARGET${NC} ($target_type)"
ok  "Entorno virtual activado"
info "Lanzando análisis...\n"

cd "$SCRIPT_DIR"
python main.py "$TARGET" "$@"
