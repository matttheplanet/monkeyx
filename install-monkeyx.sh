#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# MonkeyX Public Installer
#
# Usage: clone the repo, then run from inside it:
#   git clone <repo> && cd monkeyx && sudo bash install-monkeyx.sh
# (The installer copies files relative to its own location and symlinks the
#  checkout into /opt/monkeyx, so it must be run from a real checkout — not
#  piped via `curl | bash`.)
#
# Installs MonkeyX and all dependencies on Ubuntu/Debian.
# Safe to re-run (idempotent). Requires root/sudo for system packages.
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/monkeyx"
VENV_DIR="/opt/monkeyx-venv"
GO_VERSION="1.24.4"
# Pinned Go release checksums (linux). PINNED (not fetched at runtime) so an
# intercepting proxy/captive portal that substitutes go.dev's tiny .sha256
# endpoint can't poison verification. Update both when bumping GO_VERSION:
#   curl -fsSL https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz.sha256
#   curl -fsSL https://go.dev/dl/go${GO_VERSION}.linux-arm64.tar.gz.sha256
GO_SHA256_AMD64="77e5da33bb72aeaef1ba4418b6fe511bc4d041873cbf82e5aa6318740df98717"
GO_SHA256_ARM64="d5501ee5aca0f258d5fe9bfaed401958445014495dc115f202d43d5210b45241"
LISTS_DIR="/home/op/lists"
RESOLVERS_URL="https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
# MonkeyX runs on our Ax fork, which carries fixes MonkeyX depends on that are
# not yet upstream in https://github.com/attacksurge/ax.
AX_REPO="https://github.com/matttheplanet/ax-fork"

# Detect real user behind sudo
REAL_USER="${SUDO_USER:-$USER}"
# Resolve the home dir via getent (avoids eval on a user-influenced value).
REAL_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"
REAL_HOME="${REAL_HOME:-$HOME}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[!]${NC} $*"; exit 1; }

# Verify a downloaded file's SHA-256. HARD-fails on a mismatch (tampered/corrupt
# download). If no VALID expected hash is available (empty, or garbage such as
# an HTML error page returned by an intercepting proxy for a vendor .sha256
# endpoint), warns and continues — a vendor format change or a poisoned
# reference must not brick a download that is itself fine; a real mismatch
# against a real 64-hex reference always aborts.
verify_sha256() {
    local file="$1" expected="$2" label="$3" actual
    if [[ ! "${expected}" =~ ^[0-9a-fA-F]{64}$ ]]; then
        warn "${label}: no valid checksum available — skipping integrity check"
        return 0
    fi
    actual="$(sha256sum "${file}" | awk '{print $1}')"
    # sha256sum emits lowercase; normalize the reference too (portable, no bash-4
    # case expansion) so an upper/mixed-case pinned hash still compares equal.
    expected="$(printf '%s' "${expected}" | tr 'A-F' 'a-f')"
    if [[ "${actual}" != "${expected}" ]]; then
        error "${label}: SHA-256 MISMATCH — refusing a tampered/corrupt download.
    expected ${expected}
    got      ${actual}"
    fi
    info "${label}: checksum verified"
}

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
echo -e "${BOLD}  MonkeyX Installer (Native)${NC}"
echo ""
echo "  This will install:"
echo "    1. System packages (nmap, masscan, chromium, etc.)"
echo "    2. Go ${GO_VERSION} + security tools (dnsx, subfinder, httpx, nuclei, etc.)"
echo "    3. Rust tools (feroxbuster)"
echo "    4. Axiom fleet framework"
echo "    5. Wordlists (SecLists, resolvers)"
echo "    6. MonkeyX engine + Python dependencies"
echo "    7. 'monkeyx' CLI command -> /usr/local/bin/monkeyx"
echo ""
read -rp "  Press Enter to continue (or Ctrl+C to cancel)... "
echo ""

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (use: sudo bash install-monkeyx.sh)"
fi

if ! command -v apt-get &>/dev/null; then
    error "This script requires apt-get (Debian/Ubuntu)"
fi

# ---------------------------------------------------------------------------
# System packages
# ---------------------------------------------------------------------------

info "Updating package lists..."
apt-get update -qq

info "Installing system dependencies..."
apt-get install -y -qq \
    build-essential \
    curl \
    git \
    jq \
    masscan \
    nmap \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    libxml2-dev \
    libxslt1-dev \
    libffi-dev \
    libpcap-dev \
    unzip \
    wget \
    whois \
    dnsutils \
    whatweb \
    snmp \
    smbclient \
    netcat-openbsd \
    openssh-client \
    rsync \
    fzf \
    tmux \
    2>/dev/null

# Chromium for gowitness screenshots
apt-get install -y -qq chromium-browser 2>/dev/null || \
    apt-get install -y -qq chromium 2>/dev/null || \
    warn "Chromium not available — gowitness will attempt its own download"

rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# Go installation
# ---------------------------------------------------------------------------

if command -v go &>/dev/null; then
    CURRENT_GO=$(go version | grep -oP '\d+\.\d+\.\d+')
    info "Go already installed (v${CURRENT_GO})"
else
    # Map machine arch -> Go's release naming + its pinned checksum.
    case "$(uname -m)" in
        x86_64|amd64)  GO_ARCH="amd64"; GO_SHA="${GO_SHA256_AMD64}" ;;
        aarch64|arm64) GO_ARCH="arm64"; GO_SHA="${GO_SHA256_ARM64}" ;;
        *) error "Go install: unsupported architecture '$(uname -m)' (need x86_64 or aarch64)" ;;
    esac
    info "Installing Go ${GO_VERSION} (linux-${GO_ARCH})..."
    # curl -fL: --fail rejects an HTTP error/proxy page instead of saving it (so
    # it can't masquerade as the tarball), -L follows the go.dev -> CDN redirect,
    # --retry rides out transient blips. Checksum is pinned (see GO_SHA256_*).
    curl -fL --retry 3 --retry-delay 2 -o /tmp/go.tar.gz \
        "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
    verify_sha256 /tmp/go.tar.gz "${GO_SHA}" "Go ${GO_VERSION} (linux-${GO_ARCH})"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
fi

export PATH="/usr/local/go/bin:/usr/local/bin:${PATH}"
export GOPATH="/opt/go-tools"
export GOBIN="/opt/go-tools/bin"
mkdir -p "${GOBIN}"

# Persist Go paths for all users
cat > /etc/profile.d/monkeyx.sh << 'ENVEOF'
export PATH="/usr/local/go/bin:/opt/go-tools/bin:${PATH}"
export GOPATH="/opt/go-tools"
export GOBIN="/opt/go-tools/bin"
ENVEOF

# ---------------------------------------------------------------------------
# Go-based security tools
# ---------------------------------------------------------------------------
# SUPPLY-CHAIN NOTE: these pull `@latest`, which is non-reproducible — a given
# install date silently gets whatever tag is newest, and a compromised upstream
# tag would be built in. Pin each to a reviewed version (e.g.
# `.../nuclei/v3/cmd/nuclei@v3.4.10`) once a known-good set is validated against
# the engine; `go install` records the module checksum in the Go sum DB per
# pinned version. Left at @latest here deliberately — pinning the wrong tag
# silently drops a tool (go install warns + skips), degrading scans.

install_go_tool() {
    local name="$1"
    local pkg="$2"
    if [[ -f "${GOBIN}/${name}" ]]; then
        info "${name} already installed"
    else
        info "Installing ${name}..."
        go install "${pkg}" 2>/dev/null || warn "Failed to install ${name}"
    fi
}

install_go_tool "dnsx"        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
install_go_tool "subfinder"   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool "httpx"       "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_tool "naabu"       "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
install_go_tool "nuclei"      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
install_go_tool "puredns"     "github.com/d3mondev/puredns/v2@latest"
install_go_tool "gowitness"   "github.com/sensepost/gowitness@latest"
install_go_tool "ffuf"        "github.com/ffuf/ffuf/v2@latest"

# Symlink Go tools to /usr/local/bin
for tool in "${GOBIN}"/*; do
    [[ -f "${tool}" ]] && ln -sf "${tool}" /usr/local/bin/
done

# ---------------------------------------------------------------------------
# Other security tools
# ---------------------------------------------------------------------------

# testssl.sh
if [[ -f /usr/local/bin/testssl ]]; then
    info "testssl already installed"
else
    info "Installing testssl.sh..."
    rm -rf /opt/testssl.sh
    git clone --quiet --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh
    ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl
fi

# ssh-audit (installed into monkeyx venv after it's created below)

# bbot (installed into monkeyx venv after it's created below)

# feroxbuster
if command -v feroxbuster &>/dev/null; then
    info "feroxbuster already installed"
else
    info "Installing feroxbuster..."
    # Try GitHub API first, fall back to known release URL
    FEROX_URL=$(curl -sL https://api.github.com/repos/epi052/feroxbuster/releases/latest \
        | jq -r '.assets[] | select(.name | test("x86_64.*linux.*musl")) | .browser_download_url' | head -1)
    if [[ -z "${FEROX_URL}" || "${FEROX_URL}" == "null" ]]; then
        FEROX_URL="https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.tar.gz"
    fi
    if wget -q "${FEROX_URL}" -O /tmp/feroxbuster.tar.gz; then
        tar -xzf /tmp/feroxbuster.tar.gz -C /usr/local/bin/ feroxbuster 2>/dev/null || \
            (mkdir -p /tmp/ferox && tar -xzf /tmp/feroxbuster.tar.gz -C /tmp/ferox && mv /tmp/ferox/feroxbuster /usr/local/bin/ && rm -rf /tmp/ferox)
        chmod +x /usr/local/bin/feroxbuster
        rm -f /tmp/feroxbuster.tar.gz
    else
        warn "feroxbuster download failed — skipping"
    fi
fi

# ---------------------------------------------------------------------------
# IBM Cloud CLI
# ---------------------------------------------------------------------------

if command -v ibmcloud &>/dev/null; then
    info "IBM Cloud CLI already installed"
else
    info "Installing IBM Cloud CLI..."
    # Download to a file first rather than piping to a root shell, so a failed or
    # truncated download is not executed. Don't hide stderr — surface real errors.
    if curl -fsSL https://clis.cloud.ibm.com/install/linux -o /tmp/ibmcloud-install.sh; then
        sh /tmp/ibmcloud-install.sh || warn "IBM Cloud CLI install failed"
        rm -f /tmp/ibmcloud-install.sh
        ibmcloud plugin install vpc-infrastructure -f || true
    else
        warn "IBM Cloud CLI download failed"
    fi
fi

# ---------------------------------------------------------------------------
# AWS CLI
# ---------------------------------------------------------------------------

if command -v aws &>/dev/null; then
    info "AWS CLI already installed"
else
    info "Installing AWS CLI..."
    curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip
    unzip -q /tmp/awscliv2.zip -d /tmp
    /tmp/aws/install
    rm -rf /tmp/aws /tmp/awscliv2.zip
fi

# ---------------------------------------------------------------------------
# Axiom dependency (packer)
# ---------------------------------------------------------------------------
# NOTE: interlace (the other axiom dependency) is a Python package and is
# installed into the venv further down, after the venv is created — see the
# "Python venv + dependencies" section.

# Packer — required by axiom for image building
if command -v packer &>/dev/null; then
    info "packer already installed"
else
    info "Installing packer..."
    PACKER_VERSION="1.11.2"
    wget -q "https://releases.hashicorp.com/packer/${PACKER_VERSION}/packer_${PACKER_VERSION}_linux_amd64.zip" -O /tmp/packer.zip
    PACKER_SHA="$(curl -fsSL "https://releases.hashicorp.com/packer/${PACKER_VERSION}/packer_${PACKER_VERSION}_SHA256SUMS" 2>/dev/null | awk '/_linux_amd64\.zip$/{print $1}')"
    verify_sha256 /tmp/packer.zip "${PACKER_SHA}" "Packer ${PACKER_VERSION}"
    unzip -o -q /tmp/packer.zip -d /usr/local/bin/
    rm -f /tmp/packer.zip
fi

# ---------------------------------------------------------------------------
# Axiom (installed to real user's home)
# ---------------------------------------------------------------------------

if [[ -d "${REAL_HOME}/.axiom/interact" ]]; then
    info "Axiom already installed"
else
    info "Installing Axiom..."
    # ~/.axiom exists but has no interact/ dir = a partial/broken clone, or a
    # layout we don't recognise. Do NOT blindly `rm -rf` it — that dir may hold
    # the user's cloud-provider credentials (accounts/*.json) and fleet configs.
    # Move it aside to a timestamped backup so a re-run of the installer can
    # never destroy configured credentials; the user can restore or delete it.
    if [[ -d "${REAL_HOME}/.axiom" ]]; then
        AXIOM_BACKUP="${REAL_HOME}/.axiom.bak-$(date +%Y%m%d-%H%M%S)"
        warn "Existing ${REAL_HOME}/.axiom has no interact/ (incomplete install)."
        warn "Preserving it at ${AXIOM_BACKUP} instead of deleting it."
        warn "If it held cloud credentials (accounts/*.json), restore them from there."
        mv "${REAL_HOME}/.axiom" "${AXIOM_BACKUP}"
        chown -R "${REAL_USER}" "${AXIOM_BACKUP}" 2>/dev/null || true
    fi
    git clone --quiet --depth 1 "${AX_REPO}" "${REAL_HOME}/.axiom"
    chown -R "${REAL_USER}" "${REAL_HOME}/.axiom"

    # Add to user's shell profile
    AXIOM_PATH_LINE='export PATH="$HOME/.axiom/interact:$PATH"'
    for rcfile in "${REAL_HOME}/.zshrc" "${REAL_HOME}/.bashrc"; do
        if [[ -f "$rcfile" ]] && ! grep -q '.axiom/interact' "$rcfile"; then
            echo "$AXIOM_PATH_LINE" >> "$rcfile"
        fi
    done
fi

# Always ensure axiom commands are executable and symlinked to /usr/local/bin
if [[ -d "${REAL_HOME}/.axiom/interact" ]]; then
    chmod +x "${REAL_HOME}/.axiom/interact"/*
    for cmd in "${REAL_HOME}/.axiom/interact"/ax*; do
        [[ -f "$cmd" ]] && ln -sf "$cmd" /usr/local/bin/
    done
fi

# ---------------------------------------------------------------------------
# Wordlists
# ---------------------------------------------------------------------------

info "Setting up wordlists..."
mkdir -p "${LISTS_DIR}"

if [[ -d "${LISTS_DIR}/seclists" ]]; then
    info "SecLists already present"
else
    info "Cloning SecLists (this may take a few minutes)..."
    git clone --quiet --depth 1 https://github.com/danielmiessler/SecLists.git "${LISTS_DIR}/seclists"
fi

if [[ -f "${LISTS_DIR}/resolvers.txt" ]]; then
    info "Resolvers list already present"
else
    info "Downloading resolvers list..."
    wget -q "${RESOLVERS_URL}" -O "${LISTS_DIR}/resolvers.txt"
fi

# ---------------------------------------------------------------------------
# MonkeyX — link repo to /opt/monkeyx
# ---------------------------------------------------------------------------

if [[ "${SCRIPT_DIR}" != "${INSTALL_DIR}" ]]; then
    info "Linking MonkeyX to ${INSTALL_DIR}..."
    ln -sfn "${SCRIPT_DIR}" "${INSTALL_DIR}"
fi

# ---------------------------------------------------------------------------
# Python venv + dependencies
# ---------------------------------------------------------------------------

if [[ -d "${VENV_DIR}" ]]; then
    info "Python venv already exists"
else
    info "Creating Python venv..."
    python3 -m venv "${VENV_DIR}"
fi

info "Installing Python dependencies..."
"${VENV_DIR}/bin/pip" install --no-cache-dir -q -r "${INSTALL_DIR}/requirements.txt"

# ssh-audit (into venv)
if command -v ssh-audit &>/dev/null; then
    info "ssh-audit already installed"
else
    info "Installing ssh-audit..."
    "${VENV_DIR}/bin/pip" install --no-cache-dir -q ssh-audit || warn "Failed to install ssh-audit"
    ln -sf "${VENV_DIR}/bin/ssh-audit" /usr/local/bin/ssh-audit
fi

# bbot (into venv — needs all deps for passive/active modules)
if "${VENV_DIR}/bin/pip" show bbot &>/dev/null; then
    info "bbot already installed"
else
    info "Installing bbot..."
    "${VENV_DIR}/bin/pip" install --no-cache-dir -q bbot || warn "Failed to install bbot — bbot modules will be unavailable"
    ln -sf "${VENV_DIR}/bin/bbot" /usr/local/bin/bbot
fi

# interlace (into venv — required by axiom for parallel command execution).
# Installed here, after the venv exists, so it never falls back to a venv that
# hasn't been created and never relies on the removed `setup.py install` path.
if command -v interlace &>/dev/null; then
    info "interlace already installed"
else
    info "Installing interlace..."
    rm -rf /tmp/interlace
    git clone --quiet --depth 1 https://github.com/codingo/Interlace.git /tmp/interlace
    if "${VENV_DIR}/bin/pip" install --no-cache-dir -q /tmp/interlace; then
        ln -sf "${VENV_DIR}/bin/interlace" /usr/local/bin/interlace
    else
        warn "Failed to install interlace — axiom parallel execution will be unavailable"
    fi
    rm -rf /tmp/interlace
fi


# ---------------------------------------------------------------------------
# MonkeyX CLI wrapper
# ---------------------------------------------------------------------------

info "Installing monkeyx CLI..."
cat > /usr/local/bin/monkeyx << 'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
export PYTHONPATH="/opt/monkeyx:${PYTHONPATH:-}"
exec /opt/monkeyx-venv/bin/python3 /opt/monkeyx/monkeyx.py "$@"
WRAPPER
chmod +x /usr/local/bin/monkeyx

# ---------------------------------------------------------------------------
# MonkeyX config directory
# ---------------------------------------------------------------------------

MONKEYX_HOME="${REAL_HOME}/.monkeyx"
mkdir -p "${MONKEYX_HOME}"

if [[ ! -f "${MONKEYX_HOME}/credentials.yaml" ]]; then
    cp "${INSTALL_DIR}/credentials.yaml.example" "${MONKEYX_HOME}/credentials.yaml"
    info "Created ${MONKEYX_HOME}/credentials.yaml — edit with your API keys"
fi

if [[ ! -f "${MONKEYX_HOME}/knowledge.yaml" ]]; then
    cp "${INSTALL_DIR}/knowledge.yaml.example" "${MONKEYX_HOME}/knowledge.yaml"
    info "Created ${MONKEYX_HOME}/knowledge.yaml — edit your sources, then run 'monkeyx --sync-knowledge'"
fi

if [[ ! -f "${MONKEYX_HOME}/monkeyx.config" ]]; then
    cp "${INSTALL_DIR}/monkeyx.config" "${MONKEYX_HOME}/monkeyx.config" 2>/dev/null || true
fi

chown -R "${REAL_USER}" "${MONKEYX_HOME}"

# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

echo ""
info "Verifying installations..."
echo "-------------------------------------------"

TOOLS=("nmap" "masscan" "dnsx" "subfinder" "httpx" "naabu" "nuclei" "puredns" "gowitness" "ffuf" "feroxbuster" "bbot" "testssl" "ssh-audit" "whatweb" "go" "python3" "aws" "ibmcloud" "interlace" "packer" "ax" "monkeyx")
ALL_GOOD=true

for tool in "${TOOLS[@]}"; do
    if command -v "${tool}" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} ${tool}"
    else
        echo -e "  ${RED}✗${NC} ${tool}: NOT FOUND"
        ALL_GOOD=false
    fi
done

echo "-------------------------------------------"

if $ALL_GOOD; then
    info "All tools installed successfully!"
else
    warn "Some tools failed to install — check warnings above"
fi

echo ""
echo -e "${CYAN}${BOLD}=== Next Steps ===${NC}"
echo ""
echo -e "${BOLD}  1. Configure Axiom (fleet scanning):${NC}"
echo ""
echo "     ax configure --run"
echo "     axiom-build              # build the fleet image"
echo ""
echo "     Set your default account (add to ~/.bashrc or ~/.zshrc):"
echo "       export AXIOM_ACCOUNT=your-account-name"
echo ""
echo "     Available accounts: ls ~/.axiom/accounts/"
echo ""
echo -e "${BOLD}  2. Configure MonkeyX:${NC}"
echo ""
echo "     Edit ~/.monkeyx/credentials.yaml with your API keys"
echo "     Edit ~/.monkeyx/monkeyx.config for module settings (optional)"
echo "     Edit ~/.monkeyx/knowledge.yaml to ground AI modules in your notes (optional)"
echo ""
echo -e "${BOLD}  3. Configure API Keys:${NC}"
echo ""
echo -e "     ${YELLOW}MonkeyX AI:${NC}"
echo "       ~/.monkeyx/credentials.yaml"
echo "       - Anthropic (or AWS Bedrock region) for ai_analyze, ai_validate, ai_next"
echo "       - OpenAI (optional alternative)"
echo ""
echo -e "     ${YELLOW}Subfinder:${NC}"
echo "       ~/.config/subfinder/provider-config.yaml"
echo "       - Shodan, Censys, SecurityTrails, VirusTotal, Chaos, etc."
echo "       - More keys = more subdomains discovered"
echo "       - See: subfinder -ls"
echo ""
echo -e "     ${YELLOW}Nuclei:${NC}"
echo "       ~/.config/nuclei/.nuclei-config.yaml"
echo "       - Interactsh server (for OOB testing)"
echo "       - Cloud API key (optional, for nuclei cloud)"
echo ""
echo -e "     ${YELLOW}Axiom:${NC}"
echo "       ~/.axiom/accounts/*.json"
echo "       - IBM Cloud / AWS / DO / Linode API keys for fleet provisioning"
echo "       - Set with: ax configure --run"
echo ""
echo -e "${CYAN}${BOLD}=== Usage ===${NC}"
echo ""
echo "    monkeyx -t targets.txt -od ./output -w standard"
echo "    monkeyx -d domains.txt -od ./output -w fast"
echo "    monkeyx --continue ./output -m ai_analyze"
echo "    monkeyx --resume ./output"
echo ""
