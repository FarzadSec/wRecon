#!/usr/bin/env python3
"""
wRecon — Wide Reconnaissance Toolkit
Multi-source subdomain enumeration, passive URL collection,
parameter extraction, and live probing.

Systematically wreck your target.
"""

import sys
import os
import json
import time
import shlex
import shutil
import signal
import argparse
import fnmatch
import tempfile
import subprocess
from pathlib import Path
from urllib.parse import urlparse, urlsplit

try:
    import requests
except ImportError:
    print("[!] 'requests' not installed. Run: pip3 install requests")
    sys.exit(1)


# ================== COLORS ==================
class Colors:
    GRAY    = "\033[90m"
    GREEN   = "\033[92m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    BLUE    = "\033[94m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"


def log_info(msg):  print(f"{Colors.GRAY}[i]{Colors.RESET} {msg}")
def log_ok(msg):    print(f"{Colors.GREEN}[+]{Colors.RESET} {msg}")
def log_err(msg):   print(f"{Colors.RED}[!]{Colors.RESET} {msg}")
def log_warn(msg):  print(f"{Colors.YELLOW}[!]{Colors.RESET} {msg}")
def log_step(msg):  print(f"\n{Colors.CYAN}{Colors.BOLD}[*] {msg}{Colors.RESET}")


# ================== BANNER ==================
BANNER = r"""
{c}{b}
        ██╗    ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
        ██║    ██║██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
        ██║ █╗ ██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
        ██║███╗██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
        ╚███╔███╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
         ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{r}
{d}            wreck the target. systematically.{r}
""".format(c=Colors.CYAN, b=Colors.BOLD, d=Colors.DIM, r=Colors.RESET)


def print_banner():
    print(BANNER)


# ================== CONFIG (PERSISTENT) ==================
CONFIG_DIR = Path.home() / ".config" / "wrecon"
CONFIG_FILE = CONFIG_DIR / "config.json"


def load_config():
    if not CONFIG_FILE.exists():
        return {}
    try:
        return json.loads(CONFIG_FILE.read_text())
    except Exception:
        return {}


def save_config(cfg):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
    try:
        os.chmod(CONFIG_FILE, 0o600)
    except Exception:
        pass


def get_or_ask(cfg, key, prompt, optional=False):
    if key in cfg and cfg[key]:
        return cfg[key]
    suffix = " (optional, blank to skip)" if optional else ""
    val = input(f"{Colors.CYAN}?{Colors.RESET} {prompt}{suffix}: ").strip()
    if val:
        cfg[key] = val
        save_config(cfg)
        log_ok(f"saved {key} to {CONFIG_FILE}")
    return val


# ================== UTILS ==================
def run_shell(command, timeout=None):
    # Runs in its own process group (setsid) so that on timeout we can kill
    # the ENTIRE pipeline (e.g. `gau ... | sort -u | tee ...`), not just the
    # shell wrapper. subprocess.run()'s own timeout handling only signals the
    # immediate child (the shell); any command it spawned via a pipe survives
    # as an orphan and keeps running/holding memory+sockets. On a small,
    # no-swap box, enough orphaned long-poll HTTP tools from repeated timeouts
    # (e.g. a hung archive.org CDX request) is what turns "one slow provider"
    # into a real OOM over the course of a multi-stage/multi-host run.
    try:
        proc = subprocess.Popen(
            command, shell=True, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            return stdout, stderr, proc.returncode
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.communicate()  # reap, discard any partial buffered output
            return "", "timeout", 124
    except Exception as e:
        return "", str(e), 1


def run_shell_to_file(command, out_path, timeout=None, append=False):
    # For commands whose stdout can be large (gau/waybackurls archive dumps,
    # `unfurl keys` over a big passive.txt): redirect straight to disk via the
    # shell instead of capturing through a Python PIPE. capture_output=True
    # holds the ENTIRE stdout as an in-memory str/bytes object regardless of
    # whether the caller ever reads it — on a target with a few thousand
    # subdomains, a full historical URL dump can be hundreds of MB to
    # multiple GB, which is enough alone to OOM a small box, doubly so if
    # nothing was reading it, only to be reloaded straight back off the file
    # tee'd to disk. Streaming to a file keeps Python's own memory flat
    # regardless of output size; only the shell's own (much smaller) I/O
    # buffers are in play.
    redirect = ">>" if append else ">"
    full_cmd = f"({command}) {redirect} {out_path}"
    try:
        proc = subprocess.Popen(full_cmd, shell=True, start_new_session=True)
        try:
            proc.wait(timeout=timeout)
            return proc.returncode
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
            return 124
    except Exception:
        return 1


def get_hostname(url):
    if url.startswith("http"):
        return urlsplit(url).netloc
    return url.strip()


def good_url(url):
    extensions = [
        '.js', '.gif', '.jpg', '.png', '.css', '.woff', '.woff2', '.svg',
        '.json', '.fnt', '.ogg', '.jpeg', '.img', '.exe', '.mp4', '.flv',
        '.pdf', '.doc', '.ogv', '.webm', '.wmv', '.webp', '.mov', '.mp3',
        '.m4a', '.m4p', '.ppt', '.pptx', '.scss', '.tif', '.tiff', '.ttf',
        '.otf', '.bmp', '.ico', '.eot', '.htc', '.swf', '.rtf', '.image',
        '.rf', '.txt', '.ml', '.ip', '.map', '.model', '.m3u8', '.dat', '.psd'
    ]
    try:
        path = urlparse(url).path or ""
        for ext in extensions:
            if path.endswith(ext):
                return False
        return True
    except Exception:
        return False


def generate_temp_file():
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
        return tmp.name


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def normalize_sub(sub, root_domain):
    sub = sub.strip().lower().rstrip(".")
    if not sub:
        return None
    if "://" in sub:
        sub = urlparse(sub).hostname or ""
    if ":" in sub:
        sub = sub.split(":")[0]
    if not sub.endswith(root_domain):
        return None
    if any(c in sub for c in " \t\n*\"'<>"):
        return None
    return sub


# ================== INSTALLER ==================
# Tool metadata: (name, install command, post-install check)
TOOL_REGISTRY = {
    "go": {
        "check_cmd": "go version",
        "install": (
            "_go_latest=$(curl -fsSL 'https://go.dev/dl/?mode=json' | "
            "python3 -c \"import sys,json; d=json.load(sys.stdin); "
            "print(next(r['version'] for r in d if r['stable']))\" "
            "2>/dev/null || echo 'go1.23.0') && "
            "echo \"[*] Installing ${_go_latest}\" && "
            "curl -fsSL https://go.dev/dl/${_go_latest}.linux-amd64.tar.gz "
            "-o /tmp/go.tgz && "
            "sudo rm -rf /usr/local/go && "
            "sudo tar -C /usr/local -xzf /tmp/go.tgz && "
            "rm /tmp/go.tgz"
        ),
        "post": (
            "grep -q '/usr/local/go/bin' ~/.bashrc || "
            "echo 'export PATH=/usr/local/go/bin:$HOME/go/bin:$PATH' >> ~/.bashrc"
        ),
        "notes": "After install, run: source ~/.bashrc",
    },
    "subfinder": {
        "install": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    },
    "assetfinder": {
        "install": "go install github.com/tomnomnom/assetfinder@latest",
    },
    "amass": {
        "install": (
            "cd /tmp && "
            "wget -q https://github.com/owasp-amass/amass/releases/latest/download/amass_Linux_amd64.zip && "
            "unzip -oq amass_Linux_amd64.zip && "
            "sudo mv amass_Linux_amd64/amass /usr/local/bin/ && "
            "sudo chmod +x /usr/local/bin/amass && "
            "rm -rf /tmp/amass_Linux_amd64*"
        ),
    },
    "httpx": {
        "install": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "notes": "Use ProjectDiscovery httpx, not the Python one",
    },
    "dnsx": {
        "install": "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    },
    "waybackurls": {
        "install": "go install github.com/tomnomnom/waybackurls@latest",
    },
    "gau": {
        "install": "go install github.com/lc/gau/v2/cmd/gau@latest",
    },
    "unfurl": {
        "install": "go install github.com/tomnomnom/unfurl@latest",
    },
}


def install_tool(name):
    """Try to install a tool. Returns True on success."""
    meta = TOOL_REGISTRY.get(name)
    if not meta:
        log_err(f"Unknown tool: {name}")
        return False

    log_step(f"Installing {name}")
    if meta.get("notes"):
        log_info(meta["notes"])

    cmd = meta["install"]
    log_info(f"Exec: {cmd}")
    proc = subprocess.run(cmd, shell=True)

    if proc.returncode != 0:
        log_err(f"Install of {name} failed (rc={proc.returncode})")
        return False

    if meta.get("post"):
        log_info("Running post-install step")
        subprocess.run(meta["post"], shell=True)

    # verify
    if shutil.which(name):
        log_ok(f"{name} installed → {shutil.which(name)}")
        return True
    else:
        log_warn(f"{name} installed but not in PATH yet. "
                 f"Try: source ~/.bashrc")
        return False


def check_and_offer_install(tools, interactive=True):
    """For each tool, if missing, offer to install."""
    missing = [t for t in tools if shutil.which(t) is None]
    if not missing:
        log_ok("All required tools are present.")
        return True

    log_warn(f"Missing tools: {', '.join(missing)}")

    if not interactive:
        log_info("Run with interactive mode to install, or install manually.")
        return False

    for t in missing:
        if t not in TOOL_REGISTRY:
            log_warn(f"No installer for '{t}' — install manually")
            continue
        if ask_yn(f"Install {t} now?", default=True):
            install_tool(t)
        else:
            log_info(f"Skipped {t}")

    # re-check
    still_missing = [t for t in tools if shutil.which(t) is None]
    if still_missing:
        log_warn(f"Still missing: {', '.join(still_missing)}")
        log_info("These stages may fail. Reload shell with: source ~/.bashrc")
        return False
    log_ok("All tools ready.")
    return True


def dependency_check_menu():
    """Standalone dep check that user can run from menu."""
    log_step("Dependency check")
    all_tools = ["go"] + [t for t in TOOL_REGISTRY if t != "go"]
    found = []
    missing = []
    for t in all_tools:
        if shutil.which(t):
            found.append(t)
            print(f"  {Colors.GREEN}✓{Colors.RESET} {t} "
                  f"{Colors.DIM}→ {shutil.which(t)}{Colors.RESET}")
        else:
            missing.append(t)
            print(f"  {Colors.RED}✗{Colors.RESET} {t} {Colors.DIM}(missing){Colors.RESET}")

    if missing:
        print()
        if ask_yn(f"Install {len(missing)} missing tool(s) now?", default=True):
            for t in missing:
                if t in TOOL_REGISTRY:
                    if ask_yn(f"  Install {t}?", default=True):
                        install_tool(t)


# ================== OOS FILTERING ==================
def load_oos(path):
    if not path or not Path(path).exists():
        return []
    with open(path) as f:
        return [l.strip().lower() for l in f
                if l.strip() and not l.startswith("#")]


def is_out_of_scope(sub, oos_patterns):
    for pattern in oos_patterns:
        if sub == pattern:
            return True
        if "*" in pattern and fnmatch.fnmatch(sub, pattern):
            return True
    return False


def filter_oos_list(items, oos_patterns, extract_host=None):
    if not oos_patterns:
        return list(items), []
    in_scope, out_of_scope = [], []
    for item in items:
        host = extract_host(item) if extract_host else item
        if host and is_out_of_scope(host.lower(), oos_patterns):
            out_of_scope.append(item)
        else:
            in_scope.append(item)
    return in_scope, out_of_scope


# ================== PASSIVE URL COLLECTION ==================
def run_passive(domain, output_dir, oos_patterns):
    log_step(f"Passive URL collection for {domain}")

    temp_file = generate_temp_file()
    log_info(f"Temp file: {temp_file}")

    # archive.org's CDX API is the data source behind BOTH `waybackurls` and
    # gau's own "wayback" provider — and it silently hangs from this network
    # position: TCP/TLS connects fine, then no HTTP response ever arrives.
    # Confirmed directly, repeatedly: `curl` to the CDX endpoint hung 12s+ with
    # zero response while archive.org's own homepage answered in ~90ms; gau
    # with `--providers wayback` still hung past 50s even with explicit
    # `--timeout 15 --retries 1` flags (gau 2.2.4's client-side timeout does
    # not bound this particular hang — a real gau/Go-http-client limitation,
    # not a config gap); `gau --providers commoncrawl,otx,urlscan` (wayback
    # excluded) completed cleanly in seconds every time. `waybackurls` has no
    # provider other than wayback, so it can't be worked around the same way.
    # Fix: skip `waybackurls` and gau's `wayback` provider entirely, keep
    # gau's other three providers. PROVIDER_TIMEOUT + run_shell_to_file's
    # process-group kill remain as defense-in-depth in case commoncrawl/otx/
    # urlscan ever hang too — a hang now fails fast and clean instead of
    # leaking an orphaned process that (repeated over a long multi-host run)
    # was the real path to memory exhaustion on this box's tiny 1.9GB/no-swap
    # ceiling. Streamed straight to disk (run_shell_to_file), not captured
    # through a Python PIPE — output for a large multi-subdomain target can be
    # hundreds of MB, and capturing that in Python memory just to rewrite it
    # to the same file was unnecessary overhead and a real OOM contributor.
    #
    # UPDATE 2026-09-08: `commoncrawl` is ALSO dead from this box — its index
    # host refuses the connection outright (`dial tcp4 54.237.141.66:80:
    # connect: connection refused`), confirmed directly and via isolated
    # single-provider runs. Worse, gau 2.2.4 doesn't degrade gracefully when
    # one provider in a comma-separated list errors like this: the combined
    # `commoncrawl,otx,urlscan` run exits 0 with EMPTY output, even though
    # `otx,urlscan` alone (no commoncrawl) returns real results (1733 URLs in
    # one direct test) — so this line has likely been silently returning
    # nothing since it was written, with no visible error. Fix: drop
    # commoncrawl, keep otx+urlscan only.
    PROVIDER_TIMEOUT = 180

    steps = [
        (f"echo https://{domain}/", False),
        (f"gau {domain} --threads 1 --subs --providers otx,urlscan | sort -u", True),
    ]

    for cmd, append in steps:
        log_info(f"Exec: {cmd}")
        rc = run_shell_to_file(cmd, temp_file, timeout=PROVIDER_TIMEOUT, append=append)
        if rc == 124:
            log_warn(f"Timed out after {PROVIDER_TIMEOUT}s (provider likely hung, e.g. archive.org CDX) — skipping: {cmd}")
        elif rc != 0:
            log_err(f"Command failed ({rc}): {cmd}")

    unique_lines = set()
    with open(temp_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if good_url(line):
                unique_lines.add(line)
    os.remove(temp_file)

    if not unique_lines:
        log_err(f"No URLs found for {domain}")
        return 0

    in_scope, oos_hits = filter_oos_list(
        unique_lines, oos_patterns,
        extract_host=lambda u: urlparse(u).hostname or ""
    )

    ensure_dir(output_dir)
    out_file = os.path.join(output_dir, "passive.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        for u in sorted(in_scope):
            f.write(u + "\n")
    log_ok(f"Passive URLs (in-scope): {out_file} ({len(in_scope)} lines)")

    if oos_hits:
        oos_file = os.path.join(output_dir, "passive_oos.txt")
        with open(oos_file, "w", encoding="utf-8") as f:
            for u in sorted(oos_hits):
                f.write(u + "\n")
        log_warn(f"Filtered OOS URLs: {len(oos_hits)} → {oos_file}")

    return len(in_scope)


# ================== SUBDOMAIN ENUM SOURCES ==================
def src_subfinder(domain, tmpdir):
    out = Path(tmpdir) / "subfinder.txt"
    _, stderr, rc = run_shell(f"subfinder -silent -all -d {domain} -o {out}",
                              timeout=600)
    if rc != 0:
        log_warn(f"subfinder rc={rc}: {stderr.strip()[:200]}")
    return _read_lines(out)


def src_assetfinder(domain, _tmpdir):
    stdout, _, _ = run_shell(f"assetfinder --subs-only {domain}", timeout=300)
    return [l for l in stdout.splitlines() if l.strip()]


def src_amass(domain, tmpdir):
    out = Path(tmpdir) / "amass.txt"
    _, stderr, rc = run_shell(
        f"amass enum -passive -d {domain} -o {out} -timeout 5",
        timeout=900
    )
    if rc != 0:
        log_warn(f"amass rc={rc}: {stderr.strip()[:200]}")
    return _read_lines(out)


def src_crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, timeout=60,
                         headers={"User-Agent": "Mozilla/5.0 wrecon"})
        if r.status_code != 200:
            log_warn(f"crt.sh returned {r.status_code}")
            return []
        data = r.json()
        results = set()
        for row in data:
            for field in ("name_value", "common_name"):
                val = row.get(field, "")
                for line in val.split("\n"):
                    results.add(line.strip().lstrip("*."))
        return list(results)
    except Exception as e:
        log_warn(f"crt.sh failed: {e}")
        return []


def src_shodan(domain, api_key):
    if not api_key:
        log_warn("SHODAN_API_KEY not set — skipping Shodan")
        return []
    url = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"
    try:
        r = requests.get(url, timeout=60)
        if r.status_code == 401:
            log_err("Shodan: invalid API key")
            return []
        if r.status_code != 200:
            log_warn(f"Shodan returned {r.status_code}: {r.text[:200]}")
            return []
        data = r.json()
        results = set()
        for entry in data.get("data", []):
            sub = entry.get("subdomain", "")
            results.add(f"{sub}.{domain}" if sub else domain)
        for s in data.get("subdomains", []):
            results.add(f"{s}.{domain}")
        return list(results)
    except Exception as e:
        log_warn(f"Shodan failed: {e}")
        return []


def src_wayback(domain):
    # Was `requests.get(url, timeout=20)`. Empirically confirmed (isolated
    # test on hunt-server1: hung past a 25s hard outer kill even with
    # timeout=20 set) that requests/urllib3's `timeout` is a PER-READ timeout,
    # not a wall-clock total — the documented requests limitation: "timeout
    # is not a time limit on the entire response... an exception is raised
    # if the server has not issued a response for `timeout` seconds" between
    # reads. archive.org's CDX endpoint apparently dribbles bytes just often
    # enough to keep resetting that per-read clock without ever completing,
    # so real observed hangs ran 487s-1173s despite the 20s setting. `curl
    # --max-time` is a true wall-clock deadline regardless of partial data
    # trickling in, so shell out to curl via the process-group-safe
    # run_shell() instead of using `requests` for this specific call.
    url = (f"http://web.archive.org/cdx/search/cdx?"
           f"url=*.{domain}/*&output=txt&fl=original&collapse=urlkey")
    cmd = f"curl -sS --max-time 20 {shlex.quote(url)}"
    stdout, stderr, rc = run_shell(cmd, timeout=25)
    if rc != 0:
        log_warn(f"wayback failed (rc={rc}): {stderr.strip()[:150] if stderr else 'curl timeout/error'}")
        return []
    results = set()
    for line in stdout.splitlines():
        try:
            host = urlparse(line.strip()).hostname
            if host:
                results.add(host)
        except Exception:
            continue
    return list(results)


def src_alienvault(domain):
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        r = requests.get(url, timeout=60)
        if r.status_code != 200:
            return []
        data = r.json()
        return [rec.get("hostname", "") for rec in data.get("passive_dns", [])]
    except Exception as e:
        log_warn(f"alienvault failed: {e}")
        return []


def src_gau(domain, tmpdir):
    # Subs-stage counterpart to run_passive()'s gau call: same wayback-hang
    # workaround (archive.org's CDX API silently hangs from this box's
    # network position — see run_passive's comment) AND the same dead-
    # commoncrawl workaround (connection refused from this box; also
    # confirmed to silently zero the WHOLE combined-provider run rather than
    # degrading gracefully — see run_passive's 2026-09-08 update comment).
    # Only otx/urlscan providers are used. Streamed to disk via
    # run_shell_to_file rather than captured in a Python PIPE — gau's URL
    # dump for a large target can be large enough to be a real memory
    # concern on this box (see run_shell_to_file's own docstring).
    out = Path(tmpdir) / "gau.txt"
    cmd = f"gau {domain} --threads 1 --subs --providers otx,urlscan | sort -u"
    rc = run_shell_to_file(cmd, out, timeout=180)
    if rc != 0:
        log_warn(f"gau rc={rc}")
    results = set()
    for line in _read_lines(out):
        try:
            host = urlparse(line).hostname
            if host:
                results.add(host)
        except Exception:
            continue
    return list(results)


def src_hackertarget(domain):
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        r = requests.get(url, timeout=60)
        if r.status_code != 200 or "API count exceeded" in r.text:
            return []
        results = []
        for line in r.text.splitlines():
            parts = line.split(",")
            if parts:
                results.append(parts[0])
        return results
    except Exception as e:
        log_warn(f"hackertarget failed: {e}")
        return []


def _read_lines(path):
    if not Path(path).exists():
        return []
    with open(path) as f:
        return [l.strip() for l in f if l.strip()]


def run_subdomain_enum(domain, output_dir, shodan_key, oos_patterns,
                      skip_sources=None):
    log_step(f"Subdomain enumeration for {domain}")
    skip_sources = skip_sources or set()
    sources_results = {}

    with tempfile.TemporaryDirectory() as tmpdir:
        registry = [
            ("subfinder",    lambda: src_subfinder(domain, tmpdir)),
            ("assetfinder",  lambda: src_assetfinder(domain, tmpdir)),
            ("amass",        lambda: src_amass(domain, tmpdir)),
            ("crtsh",        lambda: src_crtsh(domain)),
            ("shodan",       lambda: src_shodan(domain, shodan_key)),
            ("wayback",      lambda: src_wayback(domain)),
            ("alienvault",   lambda: src_alienvault(domain)),
            ("gau",          lambda: src_gau(domain, tmpdir)),
            ("hackertarget", lambda: src_hackertarget(domain)),
        ]

        for name, fn in registry:
            if name in skip_sources:
                log_info(f"skipping {name}")
                continue
            print(f"{Colors.CYAN}  → {name}{Colors.RESET}", end="", flush=True)
            t0 = time.time()
            try:
                raw = fn() or []
            except Exception as e:
                log_err(f"{name} crashed: {e}")
                raw = []
            cleaned = set()
            for r in raw:
                n = normalize_sub(r, domain)
                if n:
                    cleaned.add(n)
            sources_results[name] = sorted(cleaned)
            print(f" {Colors.GREEN}{len(cleaned)}{Colors.RESET} "
                  f"{Colors.DIM}({time.time()-t0:.1f}s){Colors.RESET}")

    all_subs = set()
    for subs in sources_results.values():
        all_subs.update(subs)
    log_ok(f"Total unique subdomains: {len(all_subs)}")

    in_scope, oos_hits = filter_oos_list(all_subs, oos_patterns)

    ensure_dir(output_dir)
    (Path(output_dir) / "all_subdomains.txt").write_text(
        "\n".join(sorted(all_subs)))
    (Path(output_dir) / "subdomains.txt").write_text(
        "\n".join(sorted(in_scope)))
    (Path(output_dir) / "subdomains_oos.txt").write_text(
        "\n".join(sorted(oos_hits)))
    (Path(output_dir) / "subdomains_by_source.json").write_text(
        json.dumps(sources_results, indent=2))

    log_ok(f"In-scope subdomains: {len(in_scope)} → subdomains.txt")
    if oos_hits:
        log_warn(f"Filtered OOS: {len(oos_hits)} → subdomains_oos.txt")

    return len(in_scope)


# ================== PASSIVEPLUS ==================
def run_passiveplus(domain, output_dir, threads):
    passive_file = os.path.join(output_dir, "passive.txt")
    if not os.path.isfile(passive_file):
        log_err(f"passive.txt not found in {output_dir}, skip passiveplus")
        return 0

    log_step(f"PassivePlus probing for {domain}")
    ua = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:108.0) "
          "Gecko/20100101 Firefox/108.0")
    referer = f"https://{domain}"

    cmd = (
        f"cat {passive_file} | "
        f"httpx -silent -follow-host-redirects "
        f"-title -status-code -cdn -tech-detect "
        f"-H 'User-Agent: {ua}' -H 'Referer: {referer}' "
        f"-threads {threads}"
    )

    log_info(f"Exec: {cmd}")
    out_file = os.path.join(output_dir, "passiveplus.txt")
    rc = run_shell_to_file(cmd, out_file, timeout=1800)

    if rc == 124:
        log_err("PassivePlus (httpx) timed out after 1800s.")
        return 0
    if rc != 0 or not os.path.isfile(out_file):
        log_err("PassivePlus failed.")
        return 0

    with open(out_file, "r", encoding="utf-8", errors="ignore") as f:
        count = sum(1 for line in f if line.strip())
    log_ok(f"PassivePlus saved: {out_file} ({count} lines)")
    return count


# ================== PARAMS ==================
def extract_params(output_dir):
    passive_file = os.path.join(output_dir, "passive.txt")
    if not os.path.isfile(passive_file):
        log_err(f"passive.txt not found in {output_dir}, skip params")
        return 0

    log_step("Extracting parameter keys with unfurl")
    out_file = os.path.join(output_dir, "passive_params.txt")
    cmd = f"cat {passive_file} | unfurl keys | sort -u"
    log_info(f"Exec: {cmd}")
    # Streamed straight to disk, not captured through Python — on a large
    # target passive.txt (evernote-com alone is 38k lines/2.7MB; big orgs with
    # thousands of subdomains can be far larger) capturing unfurl's full output
    # as a Python string just to immediately rewrite it to a file was pure
    # unnecessary memory overhead, and the actual OOM risk on constrained hosts.
    rc = run_shell_to_file(cmd, out_file, timeout=300)

    if rc == 124:
        log_err(f"unfurl timed out after 300s on {passive_file} — check file isn't corrupted/unbounded.")
        return 0
    if rc != 0 or not os.path.isfile(out_file) or os.path.getsize(out_file) == 0:
        log_err("unfurl failed or produced no params.")
        return 0

    with open(out_file, "r", encoding="utf-8", errors="ignore") as f:
        count = sum(1 for _ in f)
    log_ok(f"Params saved: {out_file} ({count} keys)")
    return count


# ================== ACTIVE ==================
def ensure_resolvers(resolvers_path):
    if os.path.isfile(resolvers_path):
        return
    log_info(f"{resolvers_path} not found, creating default.")
    with open(resolvers_path, "w") as f:
        f.write("1.1.1.1\n8.8.8.8\n9.9.9.9\n")


def run_active(domain, output_dir, resolvers_path, threads, oos_patterns):
    log_step(f"Active probing for {domain}")
    ensure_resolvers(resolvers_path)

    ua = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:108.0) "
          "Gecko/20100101 Firefox/108.0")
    referer = f"https://{domain}"

    subs_file = os.path.join(output_dir, "subdomains.txt")
    if os.path.isfile(subs_file):
        log_info(f"Using in-scope subdomains: {subs_file}")
        feeder = f"cat {subs_file}"
    else:
        log_info("No subdomains.txt — running subfinder inline")
        feeder = f"echo {domain} | subfinder -silent"

    cmd = (
        f"{feeder} | "
        f"dnsx -r {resolvers_path} -silent | "
        f"httpx -silent -follow-host-redirects "
        f"-title -status-code -cdn -tech-detect "
        f"-H 'User-Agent: {ua}' -H 'Referer: {referer}' "
        f"-threads {threads}"
    )

    log_info(f"Exec: {cmd}")
    stdout, stderr, rc = run_shell(cmd, timeout=1800)

    if rc != 0 and not stdout:
        log_err("Active pipeline failed.")
        if stderr:
            log_err(stderr.strip()[:300])
        return 0

    lines = [l for l in stdout.splitlines() if l.strip()]

    if oos_patterns:
        in_scope, oos_hits = filter_oos_list(
            lines, oos_patterns,
            extract_host=lambda l: l.split()[0] if l.split() else ""
        )
        lines = in_scope
        if oos_hits:
            log_warn(f"Filtered {len(oos_hits)} OOS lines from active output")

    out_file = os.path.join(output_dir, "active.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")
    log_ok(f"Active results saved: {out_file} ({len(lines)} lines)")
    return len(lines)


# ================== INPUT ==================
def read_targets(domain_arg, input_file):
    targets = []
    if not sys.stdin.isatty():
        for line in sys.stdin:
            line = line.strip()
            if line:
                targets.append(get_hostname(line))
    if input_file:
        with open(input_file, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    targets.append(get_hostname(line))
    if domain_arg:
        targets.append(get_hostname(domain_arg))
    return sorted(set(targets))


# ================== MENU HELPERS ==================
def ask(prompt, default=None):
    suffix = f" {Colors.DIM}[{default}]{Colors.RESET}" if default else ""
    val = input(f"{Colors.CYAN}?{Colors.RESET} {prompt}{suffix}: ").strip()
    return val or (default or "")


def ask_yn(prompt, default=True):
    d = "Y/n" if default else "y/N"
    val = input(f"{Colors.CYAN}?{Colors.RESET} {prompt} "
                f"{Colors.DIM}[{d}]{Colors.RESET}: ").strip().lower()
    if not val:
        return default
    return val.startswith("y")


# ================== TMUX EXECUTION ==================
def check_tmux():
    """Check if tmux is available."""
    if not shutil.which("tmux"):
        log_err("tmux is not installed.")
        log_info("Install it with:  sudo apt install tmux")
        return False
    return True


def build_cli_argv(opts):
    """Build CLI argv list from opts dict (for launching inside tmux)."""
    import shlex
    argv = [sys.executable, os.path.abspath(__file__),
            "-d", opts["domain"],
            "-p", opts["project"],
            "-o", os.path.dirname(opts["out_dir"]),
            "--threads", str(opts["threads"]),
            "--resolvers", opts["resolvers"],
            "--no-interactive"]
    if opts.get("oos_file"):
        argv += ["--oos", opts["oos_file"]]
    if opts.get("do_subs"):    argv.append("--subs")
    if opts.get("do_passive"): argv.append("--passive")
    if opts.get("do_params"):  argv.append("--params")
    if opts.get("do_pplus"):   argv.append("--passiveplus")
    if opts.get("do_active"):  argv.append("--active")
    return argv


def launch_tmux(opts):
    """Launch wrecon inside a named tmux session."""
    if not check_tmux():
        sys.exit(1)

    session = f"wrecon_{opts['project']}"
    ensure_dir(opts["out_dir"])

    # Check if session already exists
    exists = subprocess.run(
        ["tmux", "has-session", "-t", session],
        capture_output=True
    ).returncode == 0

    if exists:
        log_warn(f"tmux session '{session}' already exists.")
        print(f"  {Colors.DIM}It may still be running from a previous invocation.{Colors.RESET}")
        choice = input(
            f"{Colors.CYAN}?{Colors.RESET} "
            f"[a]ttach / [k]ill and restart / [q]uit: "
        ).strip().lower()
        if choice.startswith("a"):
            os.execvp("tmux", ["tmux", "attach", "-t", session])
        elif choice.startswith("k"):
            subprocess.run(["tmux", "kill-session", "-t", session])
            log_ok(f"Killed session '{session}'. Restarting...")
        else:
            log_info("Cancelled.")
            sys.exit(0)

    # Build the command string to run inside tmux
    import shlex
    argv = build_cli_argv(opts)
    env_prefix = ""
    if opts.get("shodan_key"):
        env_prefix = f"SHODAN_API_KEY={shlex.quote(opts['shodan_key'])} "
    cmd_str = env_prefix + " ".join(shlex.quote(a) for a in argv)

    # Create new detached session
    subprocess.run([
        "tmux", "new-session", "-d",
        "-s", session,
        "-x", "220", "-y", "50"
    ], check=True)

    # Send the command to the session
    subprocess.run([
        "tmux", "send-keys", "-t", session,
        cmd_str, "Enter"
    ], check=True)

    log_ok(f"Started in tmux session: {Colors.BOLD}{session}{Colors.RESET}")
    print()
    print(f"{Colors.BOLD}Useful commands:{Colors.RESET}")
    print(f"  {Colors.CYAN}tmux attach -t {session}{Colors.RESET}"
          f"          {Colors.DIM}# attach to session{Colors.RESET}")
    print(f"  {Colors.CYAN}tmux kill-session -t {session}{Colors.RESET}"
          f"     {Colors.DIM}# stop the session{Colors.RESET}")
    print(f"  {Colors.CYAN}tmux ls{Colors.RESET}"
          f"                           {Colors.DIM}# list all sessions{Colors.RESET}")
    print()
    sys.exit(0)


# ================== CHECKPOINT / MEMORY ==================
STATE_FILENAME = ".wrecon_state.json"


def _state_path(out_dir):
    return os.path.join(out_dir, STATE_FILENAME)


def load_state(out_dir):
    p = _state_path(out_dir)
    if not os.path.exists(p):
        return {}
    try:
        return json.loads(Path(p).read_text())
    except Exception:
        return {}


def save_state(out_dir, state):
    ensure_dir(out_dir)
    state["last_run"] = time.strftime("%Y-%m-%d %H:%M:%S")
    Path(_state_path(out_dir)).write_text(json.dumps(state, indent=2))


def mark_done(out_dir, stage, count=0):
    state = load_state(out_dir)
    state.setdefault("stages", {})[stage] = {
        "done": True,
        "count": count,
        "finished_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    save_state(out_dir, state)


def is_done(out_dir, stage):
    return load_state(out_dir).get("stages", {}).get(stage, {}).get("done", False)


def show_state(out_dir, domain):
    state = load_state(out_dir)
    stages = state.get("stages", {})
    if not stages:
        return
    print(f"\n{Colors.BOLD}── Previous run found for {domain} ──{Colors.RESET}")
    stage_labels = {
        "subs":    "Subdomain enum",
        "passive": "Passive URLs",
        "params":  "Parameters",
        "pplus":   "PassivePlus",
        "active":  "Active probe",
    }
    for key, label in stage_labels.items():
        info = stages.get(key)
        if info and info.get("done"):
            ts    = info.get("finished_at", "?")
            count = info.get("count", "?")
            print(f"  {Colors.GREEN}✓{Colors.RESET} {label:<18}"
                  f"{Colors.DIM}{count} results  @ {ts}{Colors.RESET}")
        else:
            print(f"  {Colors.DIM}○ {label}{Colors.RESET}")
    print()


def should_run(out_dir, stage, force=False, no_interactive=False):
    """
    Return True if the stage should run.
    If already done and not forced, ask user whether to re-run — unless
    no_interactive is set, in which case there is no stdin to read from a
    scripted/CI/SSH-heredoc invocation, and calling input() here raised a
    raw EOFError traceback instead of a clean skip (confirmed: run-wrecon.sh
    passes --no-interactive but this prompt fired anyway on a second run
    against the same project, since --no-interactive was never threaded down
    to this specific check). Skip = same as the interactive default (False),
    just without blocking on a read that can never succeed.
    """
    if force or not is_done(out_dir, stage):
        return True
    info = load_state(out_dir).get("stages", {}).get(stage, {})
    ts    = info.get("finished_at", "?")
    count = info.get("count", "?")
    log_warn(f"Stage '{stage}' already done: {count} results @ {ts}")
    if no_interactive:
        log_info(f"  --no-interactive: skipping re-run of '{stage}' (use --force to re-run non-interactively)")
        return False
    return ask_yn(f"  Re-run {stage}?", default=False)



# ================== INTERACTIVE MENU ==================
def interactive_menu():
    print_banner()
    print(f"{Colors.BOLD}{Colors.MAGENTA}»» Interactive Mode ««{Colors.RESET}\n")

    cfg = load_config()

    # offer dep check on first run
    if not cfg.get("deps_checked"):
        log_info("First run — let's check dependencies.")
        dependency_check_menu()
        cfg["deps_checked"] = True
        save_config(cfg)
    elif ask_yn("Run dependency check?", default=False):
        dependency_check_menu()

    print()
    # project name
    project = ask("Project name", cfg.get("last_project") or "example")
    if not project:
        log_err("Project name is required.")
        sys.exit(1)
    cfg["last_project"] = project

    # target domain
    domain = ask("Target domain",
                 cfg.get(f"last_domain_{project}") or "example.com")
    if not domain:
        log_err("Target domain is required.")
        sys.exit(1)
    cfg[f"last_domain_{project}"] = domain

    # output dir
    default_out = cfg.get("default_output_dir", str(Path.home() / "hunt"))
    out_base = ask("Base output dir", default_out)
    cfg["default_output_dir"] = out_base
    out_dir = os.path.join(out_base, project)

    # oos file
    default_oos = cfg.get(f"oos_{project}", "")
    oos_file = ask("Path to out-of-scope file (blank for none)", default_oos)
    if oos_file:
        cfg[f"oos_{project}"] = oos_file

    # api keys
    print(f"\n{Colors.DIM}── API Keys (saved to {CONFIG_FILE}) ──{Colors.RESET}")
    shodan_key = get_or_ask(cfg, "shodan_api_key",
                            "Shodan API key", optional=True)
    save_config(cfg)

    # stages
    print(f"\n{Colors.BOLD}── Select stages ──{Colors.RESET}")
    do_subs    = ask_yn("Subdomain enumeration (8 sources)?", True)
    do_passive = ask_yn("Passive URL collection (waybackurls + gau)?", True)
    do_params  = ask_yn("Extract parameter keys (unfurl)?", True)
    do_pplus   = ask_yn("Probe passive URLs with httpx?", False)
    do_active  = ask_yn("Active probe pipeline (dnsx + httpx)?", True)

    threads_default = str(cfg.get("threads", 25))
    threads = int(ask("httpx threads", threads_default) or threads_default)
    cfg["threads"] = threads

    resolvers = ask("Resolvers file", cfg.get("resolvers", "resolvers.txt"))
    cfg["resolvers"] = resolvers
    save_config(cfg)

    # tmux mode
    print(f"\n{Colors.BOLD}── Execution mode ──{Colors.RESET}")
    print(f"  {Colors.DIM}tmux mode runs in a persistent session that survives SSH disconnect{Colors.RESET}")
    use_tmux = ask_yn("Run inside tmux session?", False)
    if use_tmux and not shutil.which("tmux"):
        log_warn("tmux not found. Install with: sudo apt install tmux")
        use_tmux = False

    # summary
    print(f"\n{Colors.BOLD}── Summary ──{Colors.RESET}")
    print(f"  Project:    {Colors.GREEN}{project}{Colors.RESET}")
    print(f"  Domain:     {Colors.GREEN}{domain}{Colors.RESET}")
    print(f"  Output:     {Colors.GREEN}{out_dir}{Colors.RESET}")
    print(f"  OOS file:   {Colors.GREEN}{oos_file or '(none)'}{Colors.RESET}")
    print(f"  Threads:    {Colors.GREEN}{threads}{Colors.RESET}")
    print(f"  tmux:       {Colors.GREEN}{use_tmux}{Colors.RESET}")
    stages = " ".join(s for s, v in [
        ("subs", do_subs), ("passive", do_passive), ("params", do_params),
        ("pplus", do_pplus), ("active", do_active)] if v) or "(none)"
    print(f"  Stages:     {Colors.GREEN}{stages}{Colors.RESET}")

    if not ask_yn("\nProceed?", True):
        log_info("Cancelled.")
        sys.exit(0)

    return {
        "project": project,
        "domain": domain,
        "out_dir": out_dir,
        "oos_file": oos_file,
        "shodan_key": shodan_key,
        "threads": threads,
        "resolvers": resolvers,
        "do_subs": do_subs,
        "do_passive": do_passive,
        "do_params": do_params,
        "do_pplus": do_pplus,
        "do_active": do_active,
        "use_tmux": use_tmux,
    }


# ================== EXECUTE ==================
def execute(opts):
    domain     = opts["domain"]
    out_dir    = opts["out_dir"]
    oos_file   = opts["oos_file"]
    shodan_key = opts["shodan_key"]
    threads    = opts["threads"]
    resolvers  = opts["resolvers"]
    force      = opts.get("force", False)
    no_interactive = opts.get("no_interactive", False)

    ensure_dir(out_dir)
    oos_patterns = load_oos(oos_file)
    if oos_patterns:
        log_info(f"Loaded {len(oos_patterns)} OOS patterns from {oos_file}")

    # Show previous run state if any
    show_state(out_dir, domain)

    # Init state domain
    state = load_state(out_dir)
    if not state.get("domain"):
        state["domain"] = domain
        save_state(out_dir, state)

    print(f"\n{Colors.MAGENTA}{Colors.BOLD}"
          f"╔══ Running on {domain} ══╗{Colors.RESET}")
    start = time.time()

    if opts["do_subs"] and should_run(out_dir, "subs", force, no_interactive):
        count = run_subdomain_enum(domain, out_dir, shodan_key, oos_patterns)
        mark_done(out_dir, "subs", count)

    if opts["do_passive"] and should_run(out_dir, "passive", force, no_interactive):
        count = run_passive(domain, out_dir, oos_patterns)
        mark_done(out_dir, "passive", count)

    if opts["do_params"] and should_run(out_dir, "params", force, no_interactive):
        count = extract_params(out_dir)
        mark_done(out_dir, "params", count)

    if opts["do_pplus"] and should_run(out_dir, "pplus", force, no_interactive):
        count = run_passiveplus(domain, out_dir, threads)
        mark_done(out_dir, "pplus", count)

    if opts["do_active"] and should_run(out_dir, "active", force, no_interactive):
        count = run_active(domain, out_dir, resolvers, threads, oos_patterns)
        mark_done(out_dir, "active", count)

    elapsed = time.time() - start
    print(f"\n{Colors.GREEN}{Colors.BOLD}"
          f"╚══ Done in {elapsed:.1f}s ══╝{Colors.RESET}")
    log_ok(f"Output saved in: {out_dir}")
    # Show final state summary
    show_state(out_dir, domain)



# ================== MAIN ==================
def main():
    parser = argparse.ArgumentParser(
        description="wRecon — Wide Reconnaissance Toolkit")
    parser.add_argument("-d", "--domain", help="Single domain")
    parser.add_argument("-i", "--input", help="File with list of domains")
    parser.add_argument("-p", "--project", help="Project name")
    parser.add_argument("-o", "--out-dir", default=None,
                        help="Base output dir (default: ~/hunt)")
    parser.add_argument("--oos", help="Out-of-scope file")
    parser.add_argument("--resolvers", default="resolvers.txt")
    parser.add_argument("--threads", type=int, default=25)
    parser.add_argument("--passive",     action="store_true")
    parser.add_argument("--passiveplus", action="store_true")
    parser.add_argument("--active",      action="store_true")
    parser.add_argument("--subs",        action="store_true")
    parser.add_argument("--params",      action="store_true")
    parser.add_argument("--all",         action="store_true",
                        help="Run all stages")
    parser.add_argument("--tmux", action="store_true",
                        help="Run inside a tmux session (survives SSH disconnect)")
    parser.add_argument("--force", action="store_true",
                        help="Force re-run all stages (ignore checkpoint)")
    parser.add_argument("--status", action="store_true",
                        help="Show checkpoint status for a project and exit")
    parser.add_argument("--no-interactive", action="store_true")
    parser.add_argument("--reset-config", action="store_true")
    parser.add_argument("--install-deps", action="store_true",
                        help="Run dependency installer and exit")

    args = parser.parse_args()

    if args.reset_config:
        if CONFIG_FILE.exists():
            CONFIG_FILE.unlink()
            log_ok(f"Removed {CONFIG_FILE}")
        else:
            log_info("No config to remove.")
        sys.exit(0)

    if args.install_deps:
        print_banner()
        dependency_check_menu()
        sys.exit(0)

    # interactive mode
    cli_used = any([args.domain, args.input, args.no_interactive])
    if not cli_used:
        opts = interactive_menu()
        if opts.get("use_tmux"):
            launch_tmux(opts)  # exits
        execute(opts)
        return

    # CLI mode
    print_banner()
    cfg = load_config()
    targets = read_targets(args.domain, args.input)
    if not targets:
        log_err("No targets specified.")
        parser.print_help()
        sys.exit(1)

    if not (args.passive or args.passiveplus or args.active
            or args.subs or args.params or args.all):
        args.all = True
    if args.all:
        args.subs = args.passive = args.params = args.active = True

    out_base = args.out_dir or cfg.get("default_output_dir",
                                       str(Path.home() / "hunt"))
    shodan_key = os.environ.get("SHODAN_API_KEY") or cfg.get("shodan_api_key", "")

    for t in targets:
        project = args.project or t
        out_dir = os.path.join(out_base, project)

        # --status: just print checkpoint and exit
        if args.status:
            show_state(out_dir, t)
            sys.exit(0)

        opts = {
            "project": project, "domain": t,
            "out_dir": out_dir, "oos_file": args.oos,
            "shodan_key": shodan_key, "threads": args.threads,
            "resolvers": args.resolvers,
            "do_subs": args.subs, "do_passive": args.passive,
            "do_params": args.params, "do_pplus": args.passiveplus,
            "do_active": args.active,
            "force": args.force,
            "no_interactive": args.no_interactive,
        }

        # --tmux: launch inside tmux session
        if args.tmux:
            launch_tmux(opts)  # exits

        execute(opts)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Interrupted{Colors.RESET}")
        sys.exit(130)
