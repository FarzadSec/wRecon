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

**wRecon** automates the reconnaissance phase by combining multiple passive and active sources into a single workflow. It handles subdomain enumeration from 8+ sources, collects historical URLs, extracts parameters, and probes live hosts — all with out-of-scope filtering and persistent configuration.

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

### 🌙 **Background Mode**
- Detach to background with `--background` or `-bg`
- Survives SSH disconnection
- PID and log files for easy monitoring

### 🔧 **Interactive + CLI Modes**
- **Interactive menu** (default) — guided setup, ideal for first-time use
- **CLI mode** — scriptable, automation-friendly

### 🛠️ **Built-in Installer**
- Checks dependencies, offers to install missing tools
- Supports: subfinder, assetfinder, amass, httpx, dnsx, waybackurls, gau, unfurl

---

## 📦 Installation

### Quick Install (Recommended)

```bash
git clone https://github.com/FarzadSec/wrecon.git
cd wrecon
chmod +x install.sh
sudo ./install.sh
```

This will:
- Install all dependencies (Go tools, Python packages)
- Place `wrecon` in `/usr/local/bin/`
- Make it globally accessible via `wrecon` command

### Manual Install

```bash
# 1. Install Python dependencies
pip3 install requests

# 2. Install Go (if not present)
wget https://go.dev/dl/go1.22.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz
echo 'export PATH=/usr/local/go/bin:$HOME/go/bin:$PATH' >> ~/.bashrc
source ~/.bashrc

# 3. Install Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/unfurl@latest

# 4. Install amass (binary release)
wget https://github.com/owasp-amass/amass/releases/latest/download/amass_Linux_amd64.zip
unzip amass_Linux_amd64.zip
sudo mv amass_Linux_amd64/amass /usr/local/bin/
sudo chmod +x /usr/local/bin/amass

# 5. Make wrecon globally accessible
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
- Project name
- Target domain
- Out-of-scope file path
- API keys (Shodan — saved for future runs)
- Stage selection (subdomain enum, passive URLs, params, active probes)
- Background mode option

**All settings are saved** — next time you run `wrecon`, just press Enter to use defaults.

---

### CLI Mode

#### Basic Usage

```bash
# Run all stages on a single domain
wrecon -d example.com --all

# With out-of-scope filtering
wrecon -d example.com --oos oos.txt --all

# Run specific stages only
wrecon -d example.com --subs --passive --active
```

#### Multiple Targets

```bash
# From file
wrecon -i targets.txt --all

# From stdin
cat targets.txt | wrecon --all
```

#### Background Mode

```bash
# Detach to background (survives SSH disconnect)
wrecon -d example.com --oos oos.txt --all --background

# Monitor progress
tail -f ~/hunt/example/wrecon_example.log

# Check if still running
ps -p $(cat ~/hunt/example/wrecon_example.pid)

# Stop it
kill $(cat ~/hunt/example/wrecon_example.pid)
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
    --background
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
├── wrecon_example.log          # Execution log (background mode)
└── wrecon_example.pid          # Process ID (background mode)
```

---

## 🔧 Configuration

### Out-of-Scope File Format

Create a text file with one pattern per line. Supports wildcards:

```
# example_oos.txt
*.internal.example.com
*.db.example.com
staging.example.com
admin.example.com
test-*.example.com
```

Lines starting with `#` are comments.

### API Keys

#### Shodan

Set via environment variable or interactive prompt:

```bash
export SHODAN_API_KEY="your_key_here"
```

Or just run `wrecon` — it will ask once and save to `~/.config/wrecon/config.json`.

#### subfinder (Optional but Recommended)

subfinder can use multiple API keys for better results. Configure once:

```bash
subfinder -d example.com  # Creates config file on first run
nano ~/.config/subfinder/provider-config.yaml
```

Add your keys:

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
| **Subdomain Enumeration** | `--subs` | Multi-source passive subdomain discovery |
| **Passive URL Collection** | `--passive` | waybackurls + gau |
| **Parameter Extraction** | `--params` | Extract URL parameter keys with unfurl |
| **PassivePlus** | `--passiveplus` | Probe passive URLs with httpx |
| **Active Probing** | `--active` | dnsx + httpx pipeline on discovered subdomains |

Use `--all` to run all stages (recommended).

---

## 🛠️ Dependency Management

### Check Dependencies

```bash
wrecon --install-deps
```

This runs an interactive installer that:
1. Checks which tools are present
2. Offers to install missing ones
3. Handles Go, subfinder, assetfinder, amass, httpx, dnsx, waybackurls, gau, unfurl

### Reset Configuration

```bash
wrecon --reset-config
```

Deletes `~/.config/wrecon/config.json` — useful if you want to start fresh.

---

## 🔥 Example Workflow

```bash
# 1. First run — install deps, set up config
wrecon --install-deps

# 2. Set API key (one-time)
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

# 4. Run full recon in background
wrecon -d fivetran.com \
    -p fivetran \
    --oos fivetran_oos.txt \
    --all \
    --background

# 5. Monitor
tail -f ~/hunt/fivetran/wrecon_fivetran.log

# 6. When complete, review results
cat ~/hunt/fivetran/subdomains.txt | wc -l
head ~/hunt/fivetran/active.txt
```

---

## 🤝 Contributing

Contributions are welcome! Feel free to:
- Report bugs
- Suggest features
- Submit pull requests

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

Plus public APIs:
- [crt.sh](https://crt.sh) — Certificate Transparency
- [Shodan](https://shodan.io)
- [Wayback Machine](https://web.archive.org)
- [AlienVault OTX](https://otx.alienvault.com)
- [HackerTarget](https://hackertarget.com)

---

**Wreck the target. Systematically.** 🎯
