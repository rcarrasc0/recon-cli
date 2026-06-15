#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
#  recon-cli · setup.sh
#
#  Prepara el entorno completo: estructura de proyecto,
#  dependencias del sistema, herramientas externas,
#  entorno virtual Python y paquete de distribución ZIP.
#
#  Uso:
#    chmod +x setup.sh && ./setup.sh
#
#  Compatible con: Debian/Ubuntu/Kali · macOS (Homebrew)
# ─────────────────────────────────────────────────────────────

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[✗]${NC} $1"; exit 1; }

echo -e "\n${BOLD}  recon-cli · Setup${NC}"
echo    "  ─────────────────────────────────────────"

# ── Detectar OS ───────────────────────────────────────────────
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif grep -qi "kali" /etc/os-release 2>/dev/null; then
        echo "kali"
    elif grep -qi "debian\|ubuntu" /etc/os-release 2>/dev/null; then
        echo "debian"
    else
        echo "unknown"
    fi
}

OS=$(detect_os)
info "Sistema detectado: ${BOLD}$OS${NC}"

# ── 1. Estructura de directorios y paquetes Python ────────────
info "Creando estructura del proyecto..."

mkdir -p modules report reports

for pkg in modules report; do
    [[ ! -f "$pkg/__init__.py" ]] && touch "$pkg/__init__.py"
done

touch reports/.gitkeep
success "Directorios: modules/ report/ reports/ con __init__.py"

# ── 2. .gitignore ─────────────────────────────────────────────
if [[ ! -f ".gitignore" ]]; then
    cat > .gitignore << 'GITIGNORE'
.env
.venv/
__pycache__/
*.pyc
*.pyo
reports/
*.pdf
.DS_Store
recon-cli-*.zip
GITIGNORE
    success ".gitignore creado"
fi

# ── 3. Dependencias del sistema ───────────────────────────────
info "Instalando dependencias del sistema..."

install_sys_deps_debian() {
    sudo apt-get update -qq
    sudo apt-get install -y -qq \
        python3 python3-pip python3-venv \
        nmap dnsutils curl wget git \
        libssl-dev libffi-dev build-essential zip
}

install_sys_deps_macos() {
    command -v brew &>/dev/null || error "Homebrew no encontrado. Instálalo desde https://brew.sh"
    brew install python nmap curl wget zip
}

case "$OS" in
    debian|kali) install_sys_deps_debian ;;
    macos)       install_sys_deps_macos  ;;
    *)           warn "OS no reconocido — instala manualmente: python3, nmap, dnsutils, zip" ;;
esac

success "Dependencias del sistema OK"

# ── 4. testssl.sh ─────────────────────────────────────────────
info "Comprobando testssl.sh..."

if command -v testssl.sh &>/dev/null || command -v testssl &>/dev/null; then
    success "testssl.sh ya disponible"
else
    TESTSSL_DIR="/opt/testssl.sh"
    sudo git clone --depth 1 https://github.com/drwetter/testssl.sh.git "$TESTSSL_DIR" 2>/dev/null \
        || warn "No se pudo clonar testssl.sh — instálalo manualmente desde https://testssl.sh"
    if [[ -f "$TESTSSL_DIR/testssl.sh" ]]; then
        sudo ln -sf "$TESTSSL_DIR/testssl.sh" /usr/local/bin/testssl.sh
        sudo chmod +x "$TESTSSL_DIR/testssl.sh"
        success "testssl.sh instalado en /usr/local/bin/testssl.sh"
    fi
fi

# ── 5. Entorno virtual Python ─────────────────────────────────
info "Creando entorno virtual Python..."

VENV_DIR=".venv"
if [[ -d "$VENV_DIR" ]]; then
    warn "Entorno virtual ya existe — usando el existente"
else
    python3 -m venv "$VENV_DIR"
    success "Entorno virtual creado en .venv"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

# ── 6. Dependencias Python ────────────────────────────────────
info "Instalando dependencias Python..."
pip install --upgrade pip -q

# Pillow se instala primero desde wheel binario (evita compilación en Python 3.13+)
info "Instalando Pillow (wheel binario)..."
pip install --only-binary=:all: Pillow -q     || pip install Pillow --pre -q     || warn "Pillow no instalado — las imágenes en el PDF estarán desactivadas"

# Resto de dependencias
pip install -r requirements.txt -q
success "Dependencias Python instaladas"

# ── 7. Configuración .env ─────────────────────────────────────
info "Comprobando configuración .env..."

if [[ -f ".env" ]]; then
    warn ".env ya existe — no se sobreescribe"
else
    cp .env.example .env
    success ".env creado desde .env.example"
    echo -e "\n  ${YELLOW}⚠️  Edita .env con tus API keys antes de ejecutar:${NC}"
    echo    "     nano .env"
fi

# ── 8. Verificación final ─────────────────────────────────────
echo ""
info "Verificando herramientas..."
 
check_tool() {
    command -v "$1" &>/dev/null \
        && success "$1 → $(command -v "$1")" \
        || warn "$1 → no encontrado (funcionalidad limitada)"
}
check_tool nmap
check_tool testssl.sh
check_tool python3
 
# Validación simplificada (sslyze excluido: no compatible con Python 3.13)
if .venv/bin/python -c "import shodan, rich, click, reportlab" 2>/dev/null; then
    success "Módulos Python core → OK"
else
    echo "[✗] Faltan módulos Python — revisa requirements.txt"
fi
 
[[ -f "recon-exec.sh" ]] && chmod +x recon-exec.sh && success "recon-exec.sh → ejecutable"
 
warn "sslyze puede no ser compatible con Python 3.13"

# ── 9. Empaquetar distribución ZIP ────────────────────────────
info "Generando paquete de distribución..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZIP_NAME="recon-cli-$(date +%Y%m%d).zip"

zip -r "$SCRIPT_DIR/$ZIP_NAME" "$SCRIPT_DIR" \
    --exclude "*/.venv/*"          \
    --exclude "*/__pycache__/*"    \
    --exclude "*/*.pyc"            \
    --exclude "*/reports/*.pdf"    \
    --exclude "*/.env"             \
    --exclude "*/.git/*"           \
    --exclude "*/recon-cli-*.zip"  \
    -q

success "Paquete generado: $ZIP_NAME ($(du -sh "$SCRIPT_DIR/$ZIP_NAME" | cut -f1))"

# ── Resumen ───────────────────────────────────────────────────
echo ""
echo -e "${BOLD}  ─────────────────────────────────────────${NC}"
echo -e "${GREEN}${BOLD}  Setup completado ✓${NC}"
echo ""
echo    "  Próximos pasos:"
echo    "  1. Edita .env con tus API keys"
echo    "  2. Ejecuta el escaneo:"
echo ""
echo "      ./recon-exec.sh <dominio|IP>"
echo ""
echo "     El launcher se encarga de activar el entorno y ejecutar el pipeline automáticamente."
echo    ""
echo    "  Distribución lista:"
echo    "  → $ZIP_NAME"
echo -e "  ─────────────────────────────────────────\n"
