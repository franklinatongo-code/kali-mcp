# kali-mcp — Kali Linux as an MCP server (Playwright Firefox automation)

**Turn a Kali Linux box into an MCP server** — expose system info, network recon, remote control, and persistent Playwright Firefox browser automation to any MCP-capable AI: opencode, Claude Desktop, Claude mobile (via HTTP tunnel), Cline, and others.

No Docker, no containers, no cloud account to set up — just a Python virtualenv and a handful of native packages. Clone it, run one script, and your machine is talking to Claude in minutes.

> **Security status: PIN gate currently DISABLED.** The `terminal`, `open_app`, `screenshot`, `notify`, `clipboard`, `media`, and `lock_screen` tools are open — anyone with the server URL has full control of this machine. See [Security status](#security-status) before exposing this publicly.

---

## Why kali-mcp

- **Lightweight.** No Docker, no VM, no heavyweight runtime — a Python venv and a few CLI tools you already have on a Linux desktop.
- **Fast to stand up.** One script (`start-https.sh`) starts the server *and* the public tunnel, and prints everything you need to paste into Claude.
- **Works from your phone.** Once it's running, Claude mobile can read your system state, scan your LAN, launch apps, take screenshots, and more — all through a normal chat.
- **Built for Kali.** Ships with the recon and forensics tooling already on the box in mind — `nmap_quick`, `net_status`, `wifi_scan` — not a generic shell wrapper.

---

## Tools

| Tool | What it does | Access |
|---|---|---|
| `sysinfo` | OS / kernel / CPU / memory / disk / uptime | Read-only |
| `wifi_scan` | Nearby Wi-Fi networks via `nmcli` | Read-only |
| `net_status` | IPs, routes, DNS, listening ports | Read-only |
| `nmap_quick` | Fast nmap scan — **LAN-only**, public IPs refused | Read-only |
| `list_desktop_projects` | Lists `~/Desktop` AI projects | Read-only |
| `list_apps` | Installed GUI apps | Read-only |
| `terminal` | Run any shell command as the desktop user | Open (PIN disabled) |
| `open_app` | Launch any GUI app by fuzzy name | Open (PIN disabled) |
| `screenshot` | Capture the screen as an image | Open |
| `notify` | Desktop notification | Open |
| `clipboard` | Read / write the clipboard | Open |
| `media` | Play-pause / next / previous / volume | Open |
| `lock_screen` | Lock the PC | Open |
| `browser_open` | Go to a URL (starts persistent Firefox session if needed, visible by default) | Open |
| `browser_click` | Click element by CSS/XPath selector or visible text | Open |
| `browser_type` | Type into a field, optional Enter to submit | Open |
| `browser_read` | Visible page/element text (prefer this over screenshots) | Open |
| `browser_screenshot` | Current page as PNG (only when asked) | Open |
| `browser_eval` | Run JavaScript on the page, return result | Open |
| `browser_tabs` | List / switch / close / open tabs | Open |
| `browser_close` | Shut the browser session down | Open |

---

## Security status

The control PIN that gates the remote-control tools is **disabled** in `server.py` (`_need_pin` returns `None`). That means:

- The tunnel URL **alone** grants full shell access to this machine — no password, no PIN.
- OAuth client registration is auto-approved (no login screen).
- The random `trycloudflare.com` URL is the *only* thing standing between the internet and this box.

**To re-enable the PIN gate:** restore the check in `_need_pin()` against `.pin`, then pass `pin=<value>` with every state-changing tool call. See `./kali-mcp.sh pin`.

**Until then:**
- Never share the tunnel URL.
- Kill the tunnel when not actively using it: `./kali-mcp.sh stop`.
- Prefer Tailscale or a named Cloudflare tunnel over the random `trycloudflare.com` link for anything long-lived.

---

## Quick start (fresh box → Claude mobile)

```bash
sudo apt install cloudflared grim wl-clipboard libnotify-bin swaync playerctl
python3 -m venv .venv
.venv/bin/pip install "mcp" uvicorn starlette "playwright==1.64.0"
./start-https.sh   # starts server + tunnel, prints a fresh Public URL + token
```

Then download Playwright's Firefox (one-time, lands in `~/.cache/ms-playwright`,
nothing to do with your normal Firefox):

```bash
.venv/bin/python -m playwright install firefox
```

Hyprland users: notifications need a daemon running —
add `exec-once = swaync` to `~/.config/hypr/hyprland.conf`.

---

## Everyday use: `kali-mcp.sh` + `start-https.sh`

`start-https.sh` is the one-command path — restarts the server and the Cloudflare tunnel together and prints the fresh details (the URL rotates every launch):

```bash
./start-https.sh               # restart both, print Local / Public / Token
./start-https.sh --port 8000
```

`kali-mcp.sh` manages the HTTP server **and** the tunnel as one unit:

```bash
./kali-mcp.sh                                # up + report endpoint/token/URL
./kali-mcp.sh start --tunnel --host 0.0.0.0  # server + public HTTPS tunnel
./kali-mcp.sh status                         # server + tunnel state
./kali-mcp.sh tunnel-url                     # just the public https URL
./kali-mcp.sh token                          # just the bearer token
./kali-mcp.sh logs | ./kali-mcp.sh tunnel-log
./kali-mcp.sh stop                           # stops server AND tunnel
./kali-mcp.sh restart --tunnel               # bounce both (new tunnel URL!)
./kali-mcp.sh pin                            # show control PIN (gate disabled, unused)
```

**Typical Claude-ready session:**

```
$ ./kali-mcp.sh start --tunnel --host 0.0.0.0
[*] Starting cloudflared tunnel -> http://127.0.0.1:8000 ...
[OK] Tunnel up: https://xyz.trycloudflare.com
[*] Starting kali-mcp on http://0.0.0.0:8000/mcp ...
[OK] Started (pid ...)
     Endpoint: http://0.0.0.0:8000/mcp
     Token:    <token>
     Header:   Authorization: Bearer <token>
```

In Claude: add a connector named `kali`, paste the `https://.../mcp` URL, choose **Sign in now** (auto-approves — see [OAuth](#claude-custom-connectors-couldnt-sign-in) below). Transport: **Streamable HTTP**.

**Notes**

- `--tunnel` order matters internally: the tunnel starts first (random hostname), then the server starts pre-allow-listed for it — MCP's DNS-rebinding protection would otherwise 421 an unknown `Host` header. Manual equivalent:
  `./kali-mcp.sh start --host 0.0.0.0 --allow-host xyz.trycloudflare.com`
  (or `export KALI_MCP_ALLOW_HOSTS=xyz.trycloudflare.com`).
- One managed server per script — `start`/`stop` with a `--port` that doesn't match the running server **refuses** rather than touching it.
- State files live in this folder: `.kali-mcp.pid`, `.cloudflared.pid`, `.token` (mode 600), `.tunnel-url`, `kali-mcp.log`, `cloudflared.log`.
- The tunnel URL is **random per launch** — restarting it means updating the URL in Claude. For a fixed address, use a named Cloudflare tunnel or Tailscale instead.
- The stdio server opencode uses is spawned by opencode itself; this script only manages the HTTP ("any AI") mode.

---

## Local use (stdio — opencode, Claude Desktop)

```bash
.venv/bin/python server.py
```

`~/.config/opencode/opencode.json`:

```json
{ "mcp": { "kali": {
  "type": "local",
  "command": ["/home/kali/Desktop/kali-mcp/.venv/bin/python",
              "/home/kali/Desktop/kali-mcp/server.py"],
  "enabled": true } } }
```

---

## Manual HTTP (without the script)

```bash
# loopback only (default, token optional)
.venv/bin/python server.py --http --port 8000

# LAN / remote — token is MANDATORY, refuses to start without one
KALI_MCP_TOKEN="$(openssl rand -hex 32)" \
  .venv/bin/python server.py --http --host 0.0.0.0 --port 8000
```

Endpoint: `http://HOST:8000/mcp` · header: `Authorization: Bearer <token>`

To reach it from outside your LAN, **do not port-forward**. Use Tailscale (`tailscale serve`) or `cloudflared tunnel`, keep the bearer token, and rotate it with `openssl rand -hex 32`.

---

## Claude custom connectors ("couldn't sign in")

Claude's Add-connector dialog with **Sign in now** only speaks OAuth, not static tokens. This server ships a minimal auto-approve OAuth 2.1 service (dynamic registration + PKCE, no login page — it's your own box), so that flow works out of the box:

- Discovery: `/.well-known/oauth-protected-resource[/mcp]`, `/.well-known/oauth-authorization-server` (public, no token needed)
- Flow: `POST /oauth/register` → `GET /oauth/authorize` (instant 302 approval) → `POST /oauth/token` (authorization_code + refresh_token)

In the dialog: **No sign-in** + `authorization: Bearer <token>` under Request headers — *if* your org has that beta. Otherwise **Sign in now** (auto-approves, no password).

> **Trade-off:** OAuth registration is OPEN — anyone holding the URL can complete the flow and use **all** tools (PIN currently disabled). The random tunnel URL is the only secrecy. Never share it; kill the tunnel (`./kali-mcp.sh stop`) when not in use.

---

## Phone remote control (currently OPEN, no PIN)

`terminal` (run shell commands), `open_app` / `list_apps`, `screenshot` (returns an image), `notify`, `clipboard`, `media` (play-pause / next / …), `lock_screen`.

Example prompts: *"open firefox"* · *"run `df -h`"* · *"screenshot my screen"* · *"pause music"* · *"lock my pc"* · *"pop a notify title=Hi message=from Claude"*.

- No `pin` argument is needed right now (gate disabled). To re-enable: restore `_need_pin` in `server.py` to compare against `.pin` (`./kali-mcp.sh pin`, override with env `KALI_MCP_PIN`).
- `terminal` runs as your user (not root), 10–300s timeout, output truncated, and refuses catastrophic typos (`rm -rf /`, `mkfs`, `dd … of=/dev/…`, fork bombs).
- Needs your graphical session — works when launched from the desktop; screenshots use `grim`, clipboard uses `wl-copy` / `wl-paste`.

> These tools behind the public tunnel + open OAuth mean **anyone with the URL controls the PC** (PIN disabled). Never share the URL; prefer Tailscale / a named tunnel for permanent access.

---

## Browser automation (currently OPEN, no PIN)

One persistent Playwright Firefox session shared between calls — `browser_open` launches it once, later calls reuse it, `browser_close` shuts it down. Ephemeral profile: never touches your normal Firefox or its logins.

`browser_open(url)` (visible window by default, `headless=true` for no window) → `browser_click` / `browser_type(selector, text, press_enter=true)` → `browser_read` (page text, preferred) → `browser_screenshot` (only when asked) → `browser_eval(js)` → `browser_tabs` (list/switch/close/new) → `browser_close`.

Example prompts: *"open youtube.com and search atongo zimba"* · *"read me this page"* · *"click the first result"* · *"what does this page say in JS: document.title"*.

- Returns plain text wherever possible (token-cheap); images only via `browser_screenshot`.
- Every call has timeouts and never hangs; errors are plain messages (e.g. `no browser session — call browser_open(url) first`).
- Needs the graphical session for visible windows (Hyprland/Wayland: `MOZ_ENABLE_WAYLAND=1` is set automatically).

---

## Safety notes

- `nmap_quick` refuses non-private targets; edit the function to tighten further.
- HTTP on a non-loopback address without `--token` exits immediately.
- In-memory OAuth tokens die on server restart — clients re-register automatically on next use.
- Logs show every tool call (uvicorn + `Processing request of type ...`).

---

## License

MIT — see [LICENSE](LICENSE). Free for personal and commercial use.

---

## How is this different from other Kali MCP servers?

Most Kali MCP servers run in Docker, wrap pentest CLIs, and stop there.
kali-mcp is the opposite bet: no containers, your real desktop, and a
**visible browser the AI actually drives**:

| | kali-mcp | Typical Docker-based Kali MCP |
|---|---|---|
| Setup | venv + one script, runs on your desktop | Docker image + container networking |
| Browser automation | Persistent **visible** Playwright Firefox (watch it work, dark theme) | Headless-only or none |
| Phone control | Full desktop remote control via tunnel (apps, screenshots, media, lock) | Rarely / terminal-only |
| Claude mobile | Public HTTPS tunnel + auto-approve OAuth out of the box | Bring your own tunnel/auth |
| Recon | `nmap_quick` (LAN-only guard), `wifi_scan`, `net_status` | Broader pentest suites (sqlmap, hydra, metasploit…) |

If you want a full pentest arsenal in a sandbox, pick one of those. If you
want your own Kali desktop — browser included — remote-controlled from a
Claude chat on your phone, this is it.

---

## FAQ

**How do I connect Claude to my Kali Linux machine?**
Run `./start-https.sh`, copy the public `https://.../mcp` URL into Claude as
a custom connector (Streamable HTTP, Sign in now — it auto-approves), done.
No port-forwarding, no account.

**How do I let an AI control my Firefox?**
That's the `browser_*` tools: `browser_open` launches a persistent Playwright
Firefox you can watch on screen, then `browser_click`, `browser_type`,
`browser_read`, `browser_eval` drive it across calls. Pass `headless=true`
for an invisible instance.

**Can Claude use my computer from my phone?**
Yes — that's the main use case. With the tunnel up, Claude mobile can run
terminal commands, open apps, screenshot the screen, control media, and drive
the browser, all from chat.

**Does it work on Hyprland / Wayland?**
Yes — built on it. Visible windows, screenshots (`grim`), clipboard
(`wl-copy`/`wl-paste`) and notifications (`swaync`) are all Wayland-native.

**Does it touch my normal Firefox profile or logins?**
No — the automated browser uses an ephemeral Playwright profile. Your
`~/.mozilla` profile is never opened or modified.

**Is it safe to expose publicly?**
Only with eyes open: the PIN gate is currently disabled, so the tunnel URL
alone grants full control. Never share the URL, stop the tunnel when idle
(`./kali-mcp.sh stop`), and prefer Tailscale or a named Cloudflare tunnel
for anything permanent. See [Security status](#security-status).
