#!/usr/bin/env bash
#
# wRecon Installer
# Installs all dependencies and makes wrecon globally accessible
#

set -e

# Colors
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

# Banner
cat << "EOF"

        ██╗    ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
        ██║    ██║██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
        ██║ █╗ ██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
        ██║███╗██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
        ╚███╔███╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
         ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝

            wreck the target. systematically.

            Installation Script v1.0

EOF

# Check if running as root for system-wide install
if [[ $EUID -ne 0 ]]; then
   warn "This script requires sudo for system-wide installation."
   warn "Run: sudo ./install.sh"
   exit 1
fi

# Get the actual user (not root when using sudo)
ACTUAL_USER="${SUDO_USER:-$USER}"
USER_HOME=$(eval echo "~$ACTUAL_USER")

step "Checking system"
info "OS: $(uname -s)"
info "Architecture: $(uname -m)"
info "User: $ACTUAL_USER"
info "Home: $USER_HOME"

# 1. Install system packages
step "Installing system packages"
if command -v apt &> /dev/null; then
    apt update -qq
    apt install -y wget curl git unzip python3 python3-pip
    ok "System packages installed (apt)"
elif command -v yum &> /dev/null; then
    yum install -y wget curl git unzip python3 python3-pip
    ok "System packages installed (yum)"
else
    warn "Unknown package manager — you may need to install: wget curl git unzip python3 python3-pip"
fi

# 2. Install Python dependencies
step "Installing Python dependencies"
pip3 install requests --break-system-packages 2>/dev/null || pip3 install requests
ok "Python requests installed"

# 3. Install Go
step "Installing Go (if needed)"
if command -v go &> /dev/null; then
    GO_VERSION=$(go version | awk '{print $3}')
    ok "Go already installed: $GO_VERSION"
else
    info "Installing Go 1.22.5..."
    cd /tmp
    wget -q https://go.dev/dl/go1.22.5.linux-amd64.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz
    rm go1.22.5.linux-amd64.tar.gz
    
    # Add to PATH for current user
    if ! grep -q "/usr/local/go/bin" "$USER_HOME/.bashrc"; then
        echo 'export PATH=/usr/local/go/bin:$HOME/go/bin:$PATH' >> "$USER_HOME/.bashrc"
        chown "$ACTUAL_USER:$ACTUAL_USER" "$USER_HOME/.bashrc"
    fi
    
    export PATH=/usr/local/go/bin:$HOME/go/bin:$PATH
    ok "Go installed → /usr/local/go"
    warn "Reload shell after install: source ~/.bashrc"
fi

# Ensure Go is in PATH for this script
export PATH=/usr/local/go/bin:$HOME/go/bin:$PATH
export GOPATH="$USER_HOME/go"

# 4. Install Go tools
step "Installing Go-based recon tools"

# subfinder
info "Installing subfinder..."
sudo -u "$ACTUAL_USER" GOPATH="$GOPATH" go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>&1 | tail -1
[[ -f "$GOPATH/bin/subfinder" ]] && ok "subfinder installed" || warn "subfinder install may have failed"

# httpx
info "Installing httpx..."
sudo -u "$ACTUAL_USER" GOPATH="$GOPATH" go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>&1 | tail -1
[[ -f "$GOPATH/bin/httpx" ]] && ok "httpx installed" || warn "httpx install may have failed"

# dnsx
info "Installing dnsx..."
sudo -u "$ACTUAL_USER" GOPATH="$GOPATH" go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest 2>&1 | tail -1
[[ -f "$GOPATH/bin/dnsx" ]] && ok "dnsx installed" || warn "dnsx install may have failed"

# assetfinder
info "Installing assetfinder..."
sudo -u "$ACTUAL_USER" GOPATH="$GOPATH" go install github.com/tomnomnom/assetfinder@latest 2>&1 | tail -1
[[ -f "$GOPATH/bin/assetfinder" ]] && ok "assetfinder installed" || warn "assetfinder install may have failed"

# waybackurls
info "Installing waybackurls..."
sudo -u "$ACTUAL_USER" GOPATH="$GOPATH" go install github.com/tomnomnom/waybackurls@latest 2>&1 | tail -1
[[ -f "$GOPATH/bin/waybackurls" ]] && ok "waybackurls installed" || warn "waybackurls install may have failed"

# gau
info "Installing gau..."
sudo -u "$ACTUAL_USER" GOPATH="$GOPATH" go install github.com/lc/gau/v2/cmd/gau@latest 2>&1 | tail -1
[[ -f "$GOPATH/bin/gau" ]] && ok "gau installed" || warn "gau install may have failed"

# unfurl
info "Installing unfurl..."
sudo -u "$ACTUAL_USER" GOPATH="$GOPATH" go install github.com/tomnomnom/unfurl@latest 2>&1 | tail -1
[[ -f "$GOPATH/bin/unfurl" ]] && ok "unfurl installed" || warn "unfurl install may have failed"

# 5. Install amass (binary release — more reliable)
step "Installing amass"
if command -v amass &> /dev/null; then
    ok "amass already installed"
else
    info "Downloading amass binary..."
    cd /tmp
    wget -q https://github.com/owasp-amass/amass/releases/latest/download/amass_Linux_amd64.zip
    unzip -oq amass_Linux_amd64.zip
    mv amass_Linux_amd64/amass /usr/local/bin/
    chmod +x /usr/local/bin/amass
    rm -rf amass_Linux_amd64*
    ok "amass installed → /usr/local/bin/amass"
fi

# 6. Install wrecon
step "Installing wRecon"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [[ ! -f "$SCRIPT_DIR/wrecon.py" ]]; then
    err "wrecon.py not found in $SCRIPT_DIR"
    err "Make sure you're running this from the wrecon directory"
    exit 1
fi

cp "$SCRIPT_DIR/wrecon.py" /usr/local/bin/wrecon
chmod +x /usr/local/bin/wrecon
ok "wrecon installed → /usr/local/bin/wrecon"

# 7. Verify installation
step "Verification"
echo ""
TOOLS=("go" "subfinder" "assetfinder" "amass" "httpx" "dnsx" "waybackurls" "gau" "unfurl" "wrecon")
for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &> /dev/null; then
        PATH_LOC=$(which "$tool")
        echo -e "  ${GREEN}✓${NC} $tool ${DIM}→ $PATH_LOC${NC}"
    else
        echo -e "  ${RED}✗${NC} $tool ${DIM}(not in PATH — may need: source ~/.bashrc)${NC}"
    fi
done

# 8. Final instructions
echo ""
step "Installation complete!"
ok "wRecon is ready to use"
echo ""
echo -e "${BOLD}Quick start:${NC}"
echo -e "  ${CYAN}1.${NC} Reload your shell:  ${DIM}source ~/.bashrc${NC}"
echo -e "  ${CYAN}2.${NC} Run the tool:       ${DIM}wrecon${NC}"
echo -e "  ${CYAN}3.${NC} Check dependencies: ${DIM}wrecon --install-deps${NC}"
echo ""
echo -e "${BOLD}Set API keys (optional):${NC}"
echo -e "  ${DIM}export SHODAN_API_KEY=\"your_key\"${NC}"
echo ""
echo -e "${BOLD}Example usage:${NC}"
echo -e "  ${DIM}wrecon -d example.com --all${NC}"
echo -e "  ${DIM}wrecon -d example.com --oos oos.txt --all --background${NC}"
echo ""
echo -e "${DIM}Wreck the target. Systematically.${NC} 🎯"
echo ""
