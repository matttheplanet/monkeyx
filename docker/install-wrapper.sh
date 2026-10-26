#!/bin/bash
set -euo pipefail

# ---------------------------------------------------------------------------
# MonkeyX Docker Wrapper Installer (Public / CLI-only)
#
# Installs the 'monkeyx' command that runs MonkeyX inside Docker.
# After this, 'monkeyx -t targets.txt -od ./output -w standard' just works.
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
INSTALL_PATH="/usr/local/bin/monkeyx"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[!]${NC} $*"; exit 1; }

# ---------------------------------------------------------------------------
# Splash
# ---------------------------------------------------------------------------

echo ""
echo -e "${CYAN}${BOLD}"
cat << 'BANNER'
    __  ___            __              _  __
   /  |/  /___  ____  / /_____  __  __| |/ /
  / /|_/ / __ \/ __ \/ //_/ _ \/ / / /|   /
 / /  / / /_/ / / / / ,< /  __/ /_/ //   |
/_/  /_/\____/_/ /_/_/|_|\___/\__, //_/|_|
                             /____/
BANNER
echo -e "${NC}"
echo -e "${BOLD}  MonkeyX Installer${NC}"
echo ""
echo "  This will install:"
echo "    1. Axiom fleet framework (on host for fleet management)"
echo "    2. Docker image:"
echo "       - Go security tools (dnsx, subfinder, httpx, naabu, nuclei, puredns, gowitness, ffuf)"
echo "       - System tools (nmap, masscan, whatweb, testssl, ssh-audit, feroxbuster)"
echo "       - Cloud CLIs (IBM Cloud, AWS)"
echo "       - Wordlists (SecLists, resolvers)"
echo "       - Python dependencies + MonkeyX engine"
echo "    3. MonkeyX CLI wrapper -> ${INSTALL_PATH}"
echo ""
echo -e "  ${YELLOW}Estimated build time: 5-15 minutes (first run, depending on network)${NC}"
echo ""
read -rp "  Press Enter to continue (or Ctrl+C to cancel)... "
echo ""

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

if ! command -v docker &>/dev/null; then
    error "Docker is not installed. Install Docker first: https://docs.docker.com/get-docker/"
fi

# Check if we can write to /usr/local/bin (or suggest sudo)
if [[ ! -w "$(dirname "$INSTALL_PATH")" ]]; then
    if [[ $EUID -ne 0 ]]; then
        warn "Need write access to $(dirname "$INSTALL_PATH")"
        echo "  Re-run with: sudo $0"
        echo "  Or install to a user directory: INSTALL_PATH=~/.local/bin/monkeyx $0"
        exit 1
    fi
fi

# Allow user to override install location
INSTALL_PATH="${INSTALL_PATH:-/usr/local/bin/monkeyx}"

# ---------------------------------------------------------------------------
# Install Axiom on host (fleet management — image builds, provider setup)
# ---------------------------------------------------------------------------

if command -v ax &>/dev/null || [[ -d "${HOME}/.axiom/interact" ]]; then
    info "Axiom already installed — skipping"
else
    info "Installing Axiom (fleet management)..."
    if git clone --depth 1 https://github.com/pry0cc/axiom "${HOME}/.axiom" 2>/dev/null; then
        # Add axiom interact scripts to PATH via shell profile
        AXIOM_PATH_LINE='export PATH="$HOME/.axiom/interact:$PATH"'
        for rcfile in "${HOME}/.zshrc" "${HOME}/.bashrc"; do
            if [[ -f "$rcfile" ]] && ! grep -q '.axiom/interact' "$rcfile"; then
                echo "$AXIOM_PATH_LINE" >> "$rcfile"
            fi
        done
        export PATH="${HOME}/.axiom/interact:${PATH}"
        info "Axiom installed to ~/.axiom"
        info "Run 'ax configure --run' after install to set up your cloud provider"
    else
        warn "Axiom install failed — you can install it manually later:"
        echo "       git clone https://github.com/pry0cc/axiom ~/.axiom"
        echo "       Add ~/.axiom/interact to your PATH"
        echo "       Run: ax configure --run"
    fi
fi

mkdir -p "${HOME}/.axiom"

# ---------------------------------------------------------------------------
# Build image
# ---------------------------------------------------------------------------

info "Building MonkeyX Docker image..."
docker build -t monkeyx:latest "$REPO_DIR"

# ---------------------------------------------------------------------------
# Install wrapper
# ---------------------------------------------------------------------------

info "Installing wrapper to ${INSTALL_PATH}..."
cp "$SCRIPT_DIR/monkeyx-wrapper.sh" "$INSTALL_PATH"
chmod +x "$INSTALL_PATH"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

echo ""
info "Installation complete!"
echo ""
echo -e "${CYAN}${BOLD}=== Next Steps ===${NC}"
echo ""
echo -e "${BOLD}  1. Configure Axiom (fleet scanning):${NC}"
echo ""
echo "     Run 'ax configure --run' to set up your cloud provider (IBM, AWS, DO, etc.)."
echo "     This creates ~/.axiom/ with your provider config and SSH keys."
echo ""
echo "       ax configure --run"
echo "       axiom-build              # build the fleet image"
echo ""
echo -e "     ${YELLOW}Files:${NC}"
echo "       ~/.axiom/axiom.json      # cloud provider config"
echo "       ~/.axiom/accounts/       # saved provider profiles"
echo ""
echo -e "${BOLD}  2. Configure MonkeyX:${NC}"
echo ""
echo "     Run 'monkeyx setup' to enter an interactive shell where you can"
echo "     edit credentials and module config. Or edit the files directly:"
echo ""
echo -e "     ${YELLOW}Files:${NC}"
echo "       ~/.monkeyx/credentials.yaml   # API keys (AI, Shodan, Censys, etc.)"
echo "       ~/.monkeyx/monkeyx.config     # module settings (ports, wordlists, AI depth)"
echo ""
echo "     Quick start:"
echo "       monkeyx setup"
echo "       # Inside container:"
echo "       #   cp /opt/monkeyx/credentials.yaml.example /root/.monkeyx/credentials.yaml"
echo "       #   cp /opt/monkeyx/monkeyx.config /root/.monkeyx/monkeyx.config"
echo "       #   nano /root/.monkeyx/credentials.yaml"
echo "       #   nano /root/.monkeyx/monkeyx.config"
echo "       #   exit"
echo ""
echo -e "${CYAN}${BOLD}=== Usage ===${NC}"
echo ""
echo "    monkeyx -t targets.txt -od ./output -w standard"
echo "    monkeyx --continue ./output -m ai_analyze"
echo "    monkeyx --resume ./output"
echo "    monkeyx bash                   # interactive shell (debugging)"
echo ""
echo "  To rebuild after code changes:"
echo "    docker build -t monkeyx:latest $REPO_DIR"
echo ""
