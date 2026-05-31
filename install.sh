#!/usr/bin/env bash
#
# wRecon Installer
# Installs all dependencies and makes wrecon globally accessible
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

info()  { echo -e "${CYAN}[i]${NC} $1"; }
ok()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[!]${NC} $1"; }
step()  { echo -e "\n${BOLD}${CYAN}[*] $1${NC}"; }

cat << "EOF"

        ██╗    ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
        ██║    ██║██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
        ██║ █╗ ██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
        ██║███╗██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
        ╚███╔███╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
         ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝

            wreck the target. systematically.
            Installation Script v2.0

EOF

if [[ $EUID -ne 0 ]]; then
    warn "Run with sudo: sudo ./install.sh"
    exit 1
fi

ACTUAL_USER="${SUDO_USER:-$USER}"
USER_HOME=$(eval echo "~$ACTUAL_USER")

step "System info"
info "OS:   $(uname -s) $(uname -r)"
info "Arch: $(uname -m)"
info "User: $ACTUAL_USER ($USER_HOME)"

# ── 1. System packages ──────────────────────────────────────────────────────
step "System packages"
if command -v apt &>/dev/null; then
    apt-get update -qq
    apt-get install -y wget curl git unzip python3 python3-pip tmux
    ok "apt packages installed"
elif command -v yum &>/dev/null; then
    yum install -y wget curl git unzip python3 python3-pip tmux
    ok "yum packages installed"
else
    warn "Unknown package manager — install manually: wget curl git unzip python3 python3-pip tmux"
fi

# ── 2. Python deps ──────────────────────────────────────────────────────────
step "Python dependencies"
pip3 install requests --break-system-packages 2>/dev/null || pip3 install requests
ok "requests installed"

# ── 3. Go (latest stable) ───────────────────────────────────────────────────
step "Go language runtime"

fetch_latest_go() {
    python3 - <<'PYEOF'
import urllib.request, json, sys
try:
    with urllib.request.urlopen("https://go.dev/dl/?mode=json", timeout=10) as r:
        data = json.loads(r.read())
    ver = next(v["version"] for v in data if v["stable"])
    print(ver)
except Exception as e:
    print("go1.23.0", file=sys.stderr)
    print("go1.23.0")
PYEOF
}

if command -v go &>/dev/null; then
    CURRENT=$(go version | awk '{print $3}')
    ok "Go already installed: $CURRENT"
    info "Checking for a newer version..."
    LATEST=$(fetch_latest_go)
    if [[ "$CURRENT" != "$LATEST" ]]; then
        warn "Newer Go available: $LATEST (installed: $CURRENT)"
        read -r -p "  Upgrade? [y/N]: " UPGRADE
        if [[ "$UPGRADE" =~ ^[Yy]$ ]]; then
            info "Downloading $LATEST..."
            curl -fsSL "https://go.dev/dl/${LATEST}.linux-amd64.tar.gz" -o /tmp/go.tgz
            rm -rf /usr/local/go
            tar -C /usr/local -xzf /tmp/go.tgz
            rm /tmp/go.tgz
            ok "Go upgraded to $LATEST"
        fi
    else
        ok "Go is up to date: $CURRENT"
    fi
else
    LATEST=$(fetch_latest_go)
    info "Installing Go $LATEST..."
    curl -fsSL "https://go.dev/dl/${LATEST}.linux-amd64.tar.gz" -o /tmp/go.tgz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tgz
    rm /tmp/go.tgz

    # PATH for user's shell
    if ! grep -q "/usr/local/go/bin" "$USER_HOME/.bashrc" 2>/dev/null; then
        echo 'export PATH=/usr/local/go/bin:$HOME/go/bin:$PATH' >> "$USER_HOME/.bashrc"
        chown "$ACTUAL_USER:$ACTUAL_USER" "$USER_HOME/.bashrc"
    fi

    ok "Go $LATEST installed → /usr/local/go"
    warn "After install, reload your shell: source ~/.bashrc"
fi

export PATH=/usr/local/go/bin:/usr/local/bin:$HOME/go/bin:$PATH
export GOPATH="$USER_HOME/go"

# ── 4. Go tools ─────────────────────────────────────────────────────────────
step "Go-based recon tools"

go_install() {
    local name="$1" pkg="$2"
    info "Installing $name..."
    if sudo -u "$ACTUAL_USER" env GOPATH="$GOPATH" \
        PATH="/usr/local/go/bin:$PATH" \
        go install "$pkg" 2>/dev/null; then
        if [[ -f "$GOPATH/bin/$name" ]]; then
            ln -sf "$GOPATH/bin/$name" /usr/local/bin/"$name" 2>/dev/null || true
            ok "$name installed"
        else
            warn "$name binary not found after install — check GOPATH"
        fi
    else
        warn "$name install failed"
    fi
}

go_install subfinder    github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go_install httpx        github.com/projectdiscovery/httpx/cmd/httpx@latest
go_install dnsx         github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go_install assetfinder  github.com/tomnomnom/assetfinder@latest
go_install waybackurls  github.com/tomnomnom/waybackurls@latest
go_install gau          github.com/lc/gau/v2/cmd/gau@latest
go_install unfurl       github.com/tomnomnom/unfurl@latest

# ── 5. amass ────────────────────────────────────────────────────────────────
step "amass"
if command -v amass &>/dev/null; then
    ok "amass already installed → $(which amass)"
else
    info "Downloading amass binary..."
    cd /tmp
    AMASS_URL=$(curl -fsSL https://api.github.com/repos/owasp-amass/amass/releases/latest \
        | python3 -c "import sys,json; d=json.load(sys.stdin); \
          print(next(a['browser_download_url'] for a in d['assets'] \
          if 'Linux_amd64' in a['name'] and a['name'].endswith('.zip')))" \
        2>/dev/null || echo "")

    if [[ -n "$AMASS_URL" ]]; then
        wget -q "$AMASS_URL" -O amass.zip
        unzip -oq amass.zip
        AMASS_BIN=$(find /tmp -name "amass" -type f | head -1)
        if [[ -n "$AMASS_BIN" ]]; then
            mv "$AMASS_BIN" /usr/local/bin/amass
            chmod +x /usr/local/bin/amass
            rm -rf /tmp/amass*
            ok "amass installed → /usr/local/bin/amass"
        else
            warn "amass binary not found in archive"
        fi
    else
        warn "Could not fetch amass release URL — install manually"
    fi
fi

# ── 6. wrecon ───────────────────────────────────────────────────────────────
step "wRecon"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -f "$SCRIPT_DIR/wrecon.py" ]]; then
    err "wrecon.py not found in $SCRIPT_DIR"
    err "Run this script from the wrecon repository directory."
    exit 1
fi

install -m 0755 "$SCRIPT_DIR/wrecon.py" /usr/local/bin/wrecon
ok "wrecon installed → /usr/local/bin/wrecon"

# ── 7. Verify ───────────────────────────────────────────────────────────────
step "Verification"
echo ""
TOOLS=(go subfinder assetfinder amass httpx dnsx waybackurls gau unfurl tmux wrecon)
ALL_OK=true
for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} ${tool} ${DIM}→ $(which $tool)${NC}"
    else
        echo -e "  ${RED}✗${NC} ${tool} ${DIM}(not in PATH)${NC}"
        ALL_OK=false
    fi
done

echo ""
step "Done!"
ok "wRecon installed successfully"
echo ""
echo -e "${BOLD}Next steps:${NC}"
echo -e "  ${CYAN}1.${NC} Reload shell:       ${DIM}source ~/.bashrc${NC}"
echo -e "  ${CYAN}2.${NC} Run:                ${DIM}wrecon${NC}"
echo -e "  ${CYAN}3.${NC} Check deps:         ${DIM}wrecon --install-deps${NC}"
echo -e "  ${CYAN}4.${NC} Set Shodan API key: ${DIM}export SHODAN_API_KEY=your_key${NC}"
echo ""
echo -e "${BOLD}Example:${NC}"
echo -e "  ${DIM}wrecon -d example.com --all --tmux${NC}"
echo ""
if [[ "$ALL_OK" == false ]]; then
    warn "Some tools missing from PATH. Run: source ~/.bashrc"
fi
echo -e "${DIM}Wreck the target. Systematically.${NC} 🎯"
echo ""
