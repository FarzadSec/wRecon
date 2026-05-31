# wRecon

**Wide Reconnaissance Toolkit** — Multi-source subdomain enumeration, passive URL collection, parameter extraction, and live probing.

```
        ██╗    ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
        ██║    ██║██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
        ██║ █╗ ██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
        ██║███╗██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
        ╚███╔███╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
         ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝

            wreck the target. systematically.
```

---

## 📋 Overview

**wRecon** automates the reconnaissance phase by combining multiple passive and active sources into a single workflow. It handles subdomain enumeration from 8+ sources, collects historical URLs, extracts parameters, and probes live hosts — all with out-of-scope filtering, persistent configuration, and checkpoint-aware resumption.

Perfect for bug bounty hunters, penetration testers, and security researchers who need comprehensive recon without babysitting tools.

---

## ✨ Features

### 🔍 **Multi-Source Subdomain Enumeration**
- **8 passive sources**: subfinder, assetfinder, amass, crt.sh, Shodan, Wayback Machine, AlienVault OTX, HackerTarget
- Automatic deduplication and merging
- Per-source attribution (JSON report)

### 🌐 **Passive URL Collection**
- **waybackurls** — Internet Archive historical URLs
- **gau** (GetAllUrls) — multiple sources aggregated
- Smart filtering of static files (images, fonts, CSS, JS)

### 🔧 **Parameter Extraction**
- **unfurl** — extract all URL parameter keys
- Useful for identifying injection points

### 🚀 **Live Probing**
- **httpx** — fast HTTP probing with tech detection
- **dnsx** — DNS resolution
- Customizable threads and timeouts

### 🛡️ **Out-of-Scope Filtering**
- Wildcard support (`*.internal.example.com`)
- Applied across all stages (subdomains, URLs, active probes)
- Separate output files for filtered items

### 💾 **Persistent Configuration**
- Saves API keys, project preferences, and settings to `~/.config/wrecon/`
- No need to re-enter Shodan keys or OOS files every time

### 🖥️ **tmux Integration**
- Run inside a named tmux session with `--tmux`
- Session survives SSH disconnection
- If a session already exists: attach, kill & restart, or quit
- Session named `wrecon_<project>` for easy identification

### 🧠 **Checkpoint Memory**
- Tracks completed stages in `.wrecon_state.json` inside the project folder
- On re-run, skips already-completed stages and asks before re-running
- Shows previous run summary (stage, result count, timestamp) on startup
- `--force` to override and re-run everything
- `--status` to inspect checkpoint state without running anything

### 🔧 **Interactive + CLI Modes**
- **Interactive menu** (default) — guided setup, ideal for first-time use
- **CLI mode** — scriptable, automation-friendly

### 🛠️ **Built-in Installer**
- Checks dependencies, offers to install missing tools
- Always installs the latest stable Go version (fetched from go.dev)
- amass: tries `go install` first, falls back to binary release

---

## 📦 Installation

### Quick Install (Recommended)

```bash
git clone https://github.com/yourusername/wrecon.git
cd wrecon
chmod +x install.sh
sudo ./install.sh
```

This will:
- Install system packages including **tmux**
- Fetch and install the **latest stable Go** version automatically
- Install all Go-based recon tools
- Install amass (via `go install`, with binary release as fallback)
- Place `wrecon` in `/usr/local/bin/` and make it globally accessible

> The installer looks for `wrecon.py` next to `install.sh`, in the current directory, and falls back to downloading it from GitHub automatically.

### Manual Install

```bash
# 1. Install system dependencies (includes tmux)
sudo apt install wget curl git unzip python3 python3-pip tmux

# 2. Install Python dependencies
pip3 install requests

# 3. Install latest Go
GO_LATEST=$(curl -fsSL 'https://go.dev/dl/?mode=json' | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(next(r['version'] for r in d if r['stable']))")
curl -fsSL "https://go.dev/dl/${GO_LATEST}.linux-amd64.tar.gz" -o /tmp/go.tgz
sudo tar -C /usr/local -xzf /tmp/go.tgz
echo 'export PATH=/usr/local/go/bin:$HOME/go/bin:$PATH' >> ~/.bashrc
source ~/.bashrc

# 4. Install Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/unfurl@latest

# 5. Install amass
go install -v github.com/owasp-amass/amass/v4/...@latest

# 6. Make wrecon globally accessible
sudo cp wrecon.py /usr/local/bin/wrecon
sudo chmod +x /usr/local/bin/wrecon
```

---

## 🚀 Usage

### Interactive Mode (Default)

```bash
wrecon
```

You'll be guided through:
- Dependency check (first run only)
- Project name and target domain
- Out-of-scope file path
- API keys (Shodan — saved for future runs)
- Stage selection
- tmux session option

**All settings are saved** — next time you run `wrecon`, just press Enter to use defaults.

---

### CLI Mode

#### Basic Usage

```bash
# Run all stages
wrecon -d example.com --all

# With out-of-scope filtering
wrecon -d example.com --oos oos.txt --all

# Specific stages only
wrecon -d example.com --subs --passive --active
```

#### tmux Mode

```bash
# Launch inside a persistent tmux session
wrecon -d example.com --oos oos.txt --all --tmux

# Attach to a running session
tmux attach -t wrecon_example

# List all wrecon sessions
tmux ls | grep wrecon

# Stop a session
tmux kill-session -t wrecon_example
```

#### Checkpoint / Resume

```bash
# Check what stages are already done
wrecon -d example.com -p example --status

# Resume — skips completed stages, asks before re-running
wrecon -d example.com --all

# Force re-run everything regardless of checkpoint
wrecon -d example.com --all --force
```

#### Multiple Targets

```bash
wrecon -i targets.txt --all --tmux
```

#### Advanced Options

```bash
wrecon -d example.com \
    -p my_project \
    -o ~/recon_output \
    --oos targets/example_oos.txt \
    --threads 50 \
    --resolvers custom_resolvers.txt \
    --subs --passive --params --active \
    --tmux
```

---

## 📂 Output Structure

All output is saved to `<output_dir>/<project>/`:

```
~/hunt/example/
├── subdomains.txt              # In-scope subdomains only
├── subdomains_oos.txt          # Filtered out-of-scope subdomains
├── all_subdomains.txt          # All discovered (pre-filter)
├── subdomains_by_source.json   # Per-source attribution
├── passive.txt                 # In-scope URLs (waybackurls + gau)
├── passive_oos.txt             # Filtered OOS URLs
├── passive_params.txt          # Extracted parameter keys
├── passiveplus.txt             # httpx results on passive URLs (optional)
├── active.txt                  # dnsx + httpx live probing results
└── .wrecon_state.json          # Checkpoint: completed stages + timestamps
```

---

## 🔧 Configuration

### Out-of-Scope File Format

```
# example_oos.txt
*.internal.example.com
*.db.example.com
staging.example.com
test-*.example.com
```

Lines starting with `#` are comments. Wildcard patterns (`*`) are supported.

### API Keys

#### Shodan

```bash
export SHODAN_API_KEY="your_key_here"
```

Or just run `wrecon` — it will ask once and save to `~/.config/wrecon/config.json`.

#### subfinder (Optional but Recommended)

```bash
subfinder -d example.com   # creates config on first run
nano ~/.config/subfinder/provider-config.yaml
```

```yaml
shodan:
  - your_shodan_key
virustotal:
  - your_virustotal_key
securitytrails:
  - your_securitytrails_key
github:
  - your_github_token
```

---

## 🎯 Supported Stages

| Stage | Flag | Description |
|-------|------|-------------|
| **Subdomain Enumeration** | `--subs` | 8-source passive subdomain discovery |
| **Passive URL Collection** | `--passive` | waybackurls + gau |
| **Parameter Extraction** | `--params` | Extract URL parameter keys with unfurl |
| **PassivePlus** | `--passiveplus` | Probe passive URLs with httpx |
| **Active Probing** | `--active` | dnsx + httpx pipeline on discovered subdomains |

Use `--all` to run all stages.

---

## 🛠️ All Flags

| Flag | Description |
|------|-------------|
| `-d DOMAIN` | Single target domain |
| `-i FILE` | File with list of domains |
| `-p NAME` | Project name |
| `-o DIR` | Base output directory (default: `~/hunt`) |
| `--oos FILE` | Out-of-scope patterns file |
| `--threads N` | httpx thread count (default: 25) |
| `--resolvers FILE` | Custom DNS resolvers file |
| `--all` | Run all stages |
| `--subs` | Subdomain enumeration only |
| `--passive` | Passive URL collection only |
| `--params` | Parameter extraction only |
| `--passiveplus` | PassivePlus probing only |
| `--active` | Active probing only |
| `--tmux` | Run inside a named tmux session |
| `--force` | Ignore checkpoint, re-run all stages |
| `--status` | Show checkpoint status and exit |
| `--install-deps` | Run dependency installer and exit |
| `--reset-config` | Delete saved configuration and exit |

---

## 🔥 Example Workflow

```bash
# 1. Clone and install
git clone https://github.com/yourusername/wrecon.git
cd wrecon && sudo ./install.sh
source ~/.bashrc

# 2. Set Shodan API key (one-time)
export SHODAN_API_KEY="your_key_here"

# 3. Create out-of-scope file
cat > fivetran_oos.txt << EOF
*.db.fivetran.com
testing-datalake.fivetran.com
shop.fivetran.com
status.fivetran.com
support.fivetran.com
community-stage.fivetran.com
trust.fivetran.com
EOF

# 4. Run full recon inside tmux
wrecon -d fivetran.com \
    -p fivetran \
    --oos fivetran_oos.txt \
    --all \
    --tmux

# 5. Attach to watch progress
tmux attach -t wrecon_fivetran

# 6. Check status later (without re-running)
wrecon -d fivetran.com -p fivetran --status

# 7. Resume if interrupted (skips done stages)
wrecon -d fivetran.com -p fivetran --oos fivetran_oos.txt --all
```

---

## 🤝 Contributing

Contributions are welcome! Feel free to report bugs, suggest features, or submit pull requests.

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

## ⚠️ Disclaimer

This tool is intended for authorized security testing and research only. Always ensure you have explicit permission before scanning targets. Unauthorized reconnaissance may be illegal in your jurisdiction.

---

## 🙏 Credits

**wRecon** aggregates and automates these excellent tools:

- [subfinder](https://github.com/projectdiscovery/subfinder) — ProjectDiscovery
- [httpx](https://github.com/projectdiscovery/httpx) — ProjectDiscovery
- [dnsx](https://github.com/projectdiscovery/dnsx) — ProjectDiscovery
- [assetfinder](https://github.com/tomnomnom/assetfinder) — Tom Hudson
- [amass](https://github.com/owasp-amass/amass) — OWASP
- [waybackurls](https://github.com/tomnomnom/waybackurls) — Tom Hudson
- [gau](https://github.com/lc/gau) — lc
- [unfurl](https://github.com/tomnomnom/unfurl) — Tom Hudson

Plus public APIs: [crt.sh](https://crt.sh), [Shodan](https://shodan.io), [Wayback Machine](https://web.archive.org), [AlienVault OTX](https://otx.alienvault.com), [HackerTarget](https://hackertarget.com)

---

**Wreck the target. Systematically.** 🎯
