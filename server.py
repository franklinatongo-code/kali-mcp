#!/usr/bin/env python3
"""kali-mcp: this Kali box as an MCP server for any MCP-capable AI.

Toolset:
  read-only (no PIN): sysinfo, wifi_scan, net_status, nmap_quick (LAN-only),
      list_desktop_projects, list_apps, clipboard-read.
  PIN-gated remote control: terminal (any shell cmd as desktop user),
      open_app, screenshot, notify, clipboard-write, media, lock_screen.
      PIN lives in .pin (600); pass as 'pin' arg. See kali-mcp.sh pin.

Transports:
  stdio (default) .... local clients: opencode, Claude Desktop, etc.
      .venv/bin/python server.py
  HTTP (Streamable HTTP) ... network clients / "any AI" that accepts a remote MCP URL.
      .venv/bin/python server.py --http --port 8000 [--host 127.0.0.1] [--token SECRET]

Security rules enforced by this script:
  * HTTP binds to 127.0.0.1 unless you pass --host explicitly.
  * Binding a non-loopback address REQUIRES --token (refuses to start without one).
  * nmap tool only allows private/LAN targets + localhost (no public scanning).
  * terminal/open_app/screenshot/etc. REQUIRE the control PIN (.pin) as an
    argument — the PIN is the RCE guard. Never share it; the public tunnel
    URL + PIN together equal full control of this PC.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import platform
import secrets
import shutil
import socket
import subprocess
import time
import urllib.parse
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("kali")

WORKSPACE = Path.home() / "Desktop"

# ── control PIN (for state-changing / remote-control tools) ────────────
# The MCP connection itself may be open-registration (Claude OAuth shim),
# so dangerous tools take a second secret as an ARGUMENT. Read-only tools
# stay PIN-free. PIN lives in .pin (600) next to this file; override with
# env KALI_MCP_PIN.
def _load_pin() -> str:
    env_pin = os.environ.get("KALI_MCP_PIN", "").strip()
    if env_pin:
        return env_pin
    pinfile = Path(__file__).resolve().parent / ".pin"
    try:
        if pinfile.is_file() and pinfile.stat().st_size > 0:
            return pinfile.read_text().strip()
        pin = secrets.token_urlsafe(18)
        pinfile.write_text(pin + "\n")
        try:
            pinfile.chmod(0o600)
        except Exception:  # noqa: BLE001
            pass
        print(f"[kali-mcp] generated control PIN: {pin}  (saved to {pinfile})", flush=True)
        return pin
    except Exception:  # noqa: BLE001
        return ""


CONTROL_PIN = _load_pin()


def _need_pin(pin: str = "") -> dict | None:
    """PIN gate DISABLED by user request — all tools open (DANGEROUS with tunnel)."""
    return None


def _gui_env() -> dict:
    """Env needed to touch the graphical session (Wayland) from a daemon."""
    uid = os.geteuid()
    rtd = f"/run/user/{uid}"
    env = dict(os.environ)
    env.setdefault("XDG_RUNTIME_DIR", rtd)
    env.setdefault("DISPLAY", ":0")
    bus = os.path.join(rtd, "bus")
    if os.path.exists(bus):
        env.setdefault("DBUS_SESSION_BUS_ADDRESS", f"unix:path={bus}")
    if not env.get("WAYLAND_DISPLAY"):
        for cand in (f"{rtd}/wayland-1", f"{rtd}/wayland-0"):
            if os.path.exists(cand):
                env["WAYLAND_DISPLAY"] = os.path.basename(cand)
                break
        else:
            env.setdefault("WAYLAND_DISPLAY", "wayland-1")
    return env


def _run(cmd: list[str], timeout: int = 30) -> dict:
    """Run a fixed (non-shell) command, return {ok, output}."""
    if not shutil.which(cmd[0]):
        return {"ok": False, "error": f"not installed: {cmd[0]}"}
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (p.stdout or "") + (("\n[stderr]\n" + p.stderr) if p.stderr else "")
        return {"ok": p.returncode == 0, "exit_code": p.returncode,
                "output": out.strip()[:12000] or f"(exit {p.returncode}, no output)"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timeout after {timeout}s"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


# ── tools ──────────────────────────────────────────────────────────────

@mcp.tool()
def sysinfo() -> dict:
    """Host overview: OS, kernel, CPU, memory, disk, uptime. Read-only."""
    out: dict = {
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()} ({platform.version()})",
        "arch": platform.machine(),
        "python": platform.python_version(),
    }
    for key, cmd in (("uptime", ["uptime"]), ("memory", ["free", "-h"]),
                     ("disk", ["df", "-h", "/", "/home"])):
        r = _run(cmd)
        if r.get("ok"):
            out[key] = r["output"]
    return out


@mcp.tool()
def wifi_scan(rescan: bool = False) -> dict:
    """Nearby Wi-Fi networks via NetworkManager. Read-only radio query.

    Args:
        rescan: True forces a fresh radio scan (slower), False uses cached results.
    """
    cmd = ["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY,CHAN,RATE", "dev", "wifi", "list"]
    cmd += ["--rescan", "yes" if rescan else "no"]
    r = _run(cmd, timeout=45)
    if not r.get("ok"):
        return r
    nets = []
    for line in r["output"].splitlines():
        parts = line.split(":")
        if len(parts) >= 4 and parts[0]:
            nets.append({"ssid": parts[0], "signal": parts[1],
                         "security": parts[2], "channel": parts[3]})
    nets.sort(key=lambda n: int(n["signal"] or 0), reverse=True)
    return {"ok": True, "count": len(nets), "networks": nets[:50]}


@mcp.tool()
def net_status() -> dict:
    """IP addresses, routes, DNS, listening ports. Read-only."""
    out: dict = {}
    for key, cmd in (("addresses", ["ip", "-brief", "addr"]),
                     ("routes", ["ip", "route", "show"]),
                     ("dns", ["resolvectl", "status"]),
                     ("listening_ports", ["ss", "-tln"])):
        r = _run(cmd)
        if r.get("ok"):
            out[key] = r["output"][:4000]
    return out


@mcp.tool()
def nmap_quick(target: str, ports: str = "top20") -> dict:
    """Fast nmap scan of a LAN host. LAN/private targets ONLY (public IPs refused).

    Args:
        target: IPv4 address or hostname resolving to LAN (10/8, 172.16/12, 192.168/16, localhost).
        ports: 'top20' (default, quiet) or e.g. '22,80,443' (max 20 ports).
    """
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(target))
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"cannot resolve '{target}': {e}"}
    if not (ip.is_private or ip.is_loopback):
        return {"ok": False, "error": f"refused: {ip} is not a LAN/private address"}
    if ports == "top20":
        port_arg = "--top-ports 20"
    else:
        wanted = [p.strip() for p in ports.split(",") if p.strip().isdigit()][:20]
        if not wanted:
            return {"ok": False, "error": "ports must be 'top20' or a list like '22,80,443'"}
        port_arg = "-p " + ",".join(wanted)
    # -F fast, -T4, no OS detection (needs root): keep it unprivileged-friendly
    cmd = f"nmap -T4 -F {port_arg} {ip}".split()
    return _run(cmd, timeout=120)


@mcp.tool()
def list_desktop_projects() -> dict:
    """List the user's ~/Desktop projects (where the AI side-projects live). Read-only."""
    try:
        entries = sorted(p.name for p in WORKSPACE.iterdir() if not p.name.startswith("."))
        return {"ok": True, "projects": entries}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


# ── remote-control tools (PIN-gated) ───────────────────────────────────

# Patterns that are almost certainly accidents, not intent. The PIN is the
# real guard; this only stops catastrophic typos from a phone keyboard.
DENY_RES = (
    r"rm\s+.*-[a-z]*r[a-z]*f.*\s+/(?:\s|$)",   # rm -rf /
    r"rm\s+.*--no-preserve-root",
    r"\bmkfs(\.|$|\s)",
    r"\bdd\s+.*\bof=/dev/",
    r":\(\)\s*\{",                              # fork bomb
    r">\s*/dev/sd[a-z]",
    r"\bchmod\s+-R\s+777\s+/(\s|$)",
)


@mcp.tool()
def terminal(command: str, pin: str = "", timeout: int = 60, workdir: str = "") -> dict:
    """Run a shell command on the PC and return its output.

    Args:
        command: bash command to run (as the desktop user, NOT root).
        timeout: seconds (10-300, default 60).
        workdir: optional working directory (default: home).
    """
    bad = _need_pin(pin)
    if bad:
        return bad
    import re as _re
    for pat in DENY_RES:
        if _re.search(pat, command, _re.IGNORECASE):
            return {"ok": False, "error": f"refused by safety filter ({pat[:24]}…). "
                                          "If you really mean it, run it locally."}
    timeout = max(10, min(int(timeout or 60), 300))
    cwd = os.path.expanduser("~")
    if workdir:
        p = Path(workdir).expanduser()
        if not p.is_absolute():
            p = Path.home() / p
        if not p.is_dir():
            return {"ok": False, "error": f"workdir not a directory: {workdir}"}
        cwd = str(p)
    try:
        print(f"[terminal] exec (timeout={timeout}s, cwd={cwd}): {command[:200]}", flush=True)
        p = subprocess.run(command, shell=True, cwd=cwd, capture_output=True, text=True,
                           timeout=timeout, executable="/bin/bash", env=_gui_env())
        out = (p.stdout or "") + (("\n[stderr]\n" + p.stderr) if p.stderr else "")
        out = out.strip()[:12000] or f"(exit {p.returncode}, no output)"
        return {"ok": p.returncode == 0, "exit_code": p.returncode, "output": out}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timeout after {timeout}s (process killed)"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


def _desktop_apps() -> list:
    """Parse installed .desktop files -> [{id, name, exec, comment}]."""
    apps = []
    seen = set()
    for d in (Path.home() / ".local/share/applications", Path("/usr/share/applications")):
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.desktop")):
            if f.name in seen:
                continue
            seen.add(f.name)
            try:
                txt = f.read_text(errors="replace")
            except Exception:  # noqa: BLE001
                continue
            if "NoDisplay=true" in txt:
                continue
            name = exe = comment = ""
            in_entry = False
            for line in txt.splitlines():
                if line.startswith("[Desktop Entry]"):
                    in_entry = True
                elif line.startswith("["):
                    in_entry = False
                elif in_entry:
                    if line.startswith("Name=") and not name:
                        name = line[5:].strip()
                    elif line.startswith("Exec=") and not exe:
                        exe = line[5:].strip()
                    elif line.startswith("Comment=") and not comment:
                        comment = line[8:].strip()
            if name and exe:
                import re as _re
                exe = _re.sub(r"\s+%[fFuUickdDnNvm]", "", exe).strip()
                apps.append({"id": f.name[:-8], "name": name, "exec": exe, "comment": comment})
    return apps


def _norm(s: str) -> str:
    return "".join(c for c in s.lower() if c.isalnum())


@mcp.tool()
def list_apps(search: str = "") -> dict:
    """List installed GUI apps (name + launch command). Read-only.

    Args:
        search: optional fuzzy filter, e.g. 'fire', 'file manager'.
    """
    apps = _desktop_apps()
    if search:
        q = _norm(search)
        toks = [t for t in _norm(search).replace("-", " ").split() if t]
        scored = []
        for a in apps:
            n = _norm(a["name"]) + _norm(a["id"])
            if q and q in n:
                scored.append((0, a))
            elif toks and all(t in n for t in toks):
                scored.append((1, a))
        scored.sort(key=lambda x: x[0])
        apps = [a for _, a in scored[:30]]
    return {"ok": True, "count": len(apps),
            "apps": [{"name": a["name"], "id": a["id"], "comment": a["comment"]} for a in apps[:60]]}


@mcp.tool()
def open_app(query: str, pin: str = "") -> dict:
    """Open/launch a GUI app on the PC.

    Args:
        query: fuzzy app name, e.g. 'firefox', 'files', 'terminal', 'code'.
    """
    bad = _need_pin(pin)
    if bad:
        return bad
    apps = _desktop_apps()
    q = _norm(query)
    if not q:
        return {"ok": False, "error": "empty app name"}
    best = None
    for a in apps:  # exact / normalized-exact first
        if a["name"] == query or a["id"] == query or _norm(a["name"]) == q or _norm(a["id"]) == q:
            best = a
            break
    if not best:
        hits = [a for a in apps if q in _norm(a["name"]) or q in _norm(a["id"])]
        if len(hits) == 1:
            best = hits[0]
        elif hits:
            return {"ok": False, "error": f"ambiguous '{query}' — be specific",
                    "matches": [h["name"] for h in hits[:10]]}
        else:
            return {"ok": False, "error": f"no app matches '{query}' — try list_apps()"}
    try:
        env = _gui_env()
        if shutil.which("gtk-launch"):
            p = subprocess.Popen(["gtk-launch", best["id"]], env=env,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 start_new_session=True)
        else:
            p = subprocess.Popen(best["exec"], shell=True, env=env,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 start_new_session=True, executable="/bin/bash")
        print(f"[open_app] launched '{best['name']}' (pid {p.pid})", flush=True)
        return {"ok": True, "launched": best["name"], "pid": p.pid}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


@mcp.tool()
def screenshot(pin: str = "", max_width: int = 1280):
    """Take a screenshot of the PC display. Returns a PNG image.

    Args:
        max_width: downscale to this width (default 1280, keeps phone-sized replies fast).
    """
    from mcp.types import ImageContent, TextContent
    bad = _need_pin(pin)
    if bad:
        return bad["error"]
    if not shutil.which("grim"):
        return "screenshot needs the 'grim' tool (not installed)"
    import base64
    import tempfile
    tmp = tempfile.mktemp(suffix=".png")
    try:
        r = subprocess.run(["grim", "-t", "png", tmp], env=_gui_env(),
                           capture_output=True, timeout=30)
        if r.returncode != 0 or not Path(tmp).is_file():
            return f"grim failed: {(r.stderr or b'').decode()[:300]}"
        data = Path(tmp).read_bytes()
        if max_width and shutil.which("convert"):
            small = tmp + ".small.png"
            subprocess.run(["convert", tmp, "-resize", f"{int(max_width)}x>", small],
                           timeout=30, capture_output=True)
            if Path(small).is_file():
                data = Path(small).read_bytes()
                Path(small).unlink(missing_ok=True)
        return ImageContent(type="image",
                            data=base64.b64encode(data).decode(),
                            mimeType="image/png")
    except Exception as e:  # noqa: BLE001
        return f"screenshot failed: {e}"
    finally:
        Path(tmp).unlink(missing_ok=True)


@mcp.tool()
def notify(title: str, message: str = "", pin: str = "") -> dict:
    """Pop a desktop notification on the PC.

    Needs a notification daemon in the desktop session; errors clearly if none.
    """
    bad = _need_pin(pin)
    if bad:
        return bad
    try:
        subprocess.run(["notify-send", title[:100], message[:500]],
                       env=_gui_env(), timeout=8, capture_output=True, check=True)
        return {"ok": True, "shown": title}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "no notification daemon answered (none running?); "
                                      "notification not shown"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)[:300]}


@mcp.tool()
def clipboard(text: str = "", pin: str = "") -> dict:
    """Read (no text) or set the PC clipboard.

    Args:
        text: if given, copies it to the clipboard; if empty, reads it.
    """
    if text:
        bad = _need_pin(pin)
        if bad:
            return bad
        try:
            subprocess.run(["wl-copy"], input=text, text=True, env=_gui_env(), timeout=10)
            return {"ok": True, "copied_chars": len(text)}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)}
    r = _run(["wl-paste"])
    if r.get("ok"):
        return {"ok": True, "clipboard": r["output"][:4000]}
    return r


@mcp.tool()
def media(action: str, pin: str = "") -> dict:
    """Media keys on the PC: play-pause, next, previous, stop, volume-up, volume-down."""
    bad = _need_pin(pin)
    if bad:
        return bad
    mapping = {"play-pause": ["play-pause"], "next": ["next"], "previous": ["previous"],
               "stop": ["stop"], "volume-up": ["volume", "5%+"],
               "volume-down": ["volume", "5%-"]}
    if action not in mapping:
        return {"ok": False, "error": f"unknown action '{action}' — pick {sorted(mapping)}"}
    return _run(["playerctl"] + mapping[action])


@mcp.tool()
def lock_screen(pin: str = "") -> dict:
    """Lock the PC screen."""
    bad = _need_pin(pin)
    if bad:
        return bad
    return _run(["loginctl", "lock-session"])


# ── browser-control tools (PIN-gated, persistent Playwright Firefox) ────
# One persistent session between calls: browser_open() launches once,
# later calls reuse the same browser/context. Never touches the normal
# Firefox profile (~/.mozilla) — uses Playwright's ephemeral context.
# Async tools share the server event loop, so the session stays alive.
import asyncio as _asyncio

_bw_play = None        # async_playwright() instance
_bw_browser = None     # firefox browser
_bw_context = None     # single browser context (ephemeral, no login persistence)
_bw_pages: list = []   # tabs (Playwright pages), in open order
_bw_current: int = -1  # index into _bw_pages
_bw_headless: bool | None = None
_bw_lock = _asyncio.Lock()


def _bw_gui_env() -> dict:
    env = _gui_env()
    env.setdefault("MOZ_ENABLE_WAYLAND", "1")
    return env


def _bw_cur():
    """Current page or None."""
    if 0 <= _bw_current < len(_bw_pages):
        return _bw_pages[_bw_current]
    return None


async def _bw_ensure(headless: bool = False, timeout: int = 30):
    """Launch the persistent browser if needed. Returns (page, error_dict)."""
    global _bw_play, _bw_browser, _bw_context, _bw_pages, _bw_current, _bw_headless
    try:
        from playwright.async_api import async_playwright
    except Exception as e:  # noqa: BLE001
        return None, {"ok": False, "error": f"playwright not installed in kali-mcp .venv: {e}"}
    # Restart if caller wants a different headless mode than running.
    if _bw_browser is not None and _bw_headless is not None and _bw_headless != bool(headless):
        try:
            await _bw_browser.close()
        except Exception:  # noqa: BLE001
            pass
        _bw_browser = None
        _bw_context = None
        _bw_pages = []
        _bw_current = -1
        try:
            await _bw_play.stop()
        except Exception:  # noqa: BLE001
            pass
        _bw_play = None
    if _bw_browser is None:
        try:
            async def _launch():
                global _bw_play, _bw_browser, _bw_context
                _bw_play = await async_playwright().start()
                _bw_browser = await _bw_play.firefox.launch(
                    headless=bool(headless),
                    env=_bw_gui_env(),
                    timeout=30000,
                )
                _bw_context = await _bw_browser.new_context(
                    viewport={"width": 1280, "height": 720},
                )
            await _asyncio.wait_for(_launch(), timeout=max(10, min(int(timeout or 30), 120)))
            _bw_headless = bool(headless)
        except _asyncio.TimeoutError:
            return None, {"ok": False, "error": "browser launch timed out"}
        except Exception as e:  # noqa: BLE001
            return None, {"ok": False, "error": f"browser launch failed: {str(e)[:400]}"}
    page = _bw_cur()
    if page is None:
        try:
            page = await _bw_context.new_page()
            _bw_pages.append(page)
            _bw_current = len(_bw_pages) - 1
        except Exception as e:  # noqa: BLE001
            return None, {"ok": False, "error": f"new tab failed: {str(e)[:300]}"}
    return page, None


async def _bw_info(page) -> dict:
    try:
        return {"url": page.url, "title": (await page.title())[:300]}
    except Exception:  # noqa: BLE001
        return {"url": "", "title": ""}


async def _bw_try_click(page, selector: str, timeout_ms: int) -> dict:
    """Click by CSS/XPath first, then by visible text. Returns result dict."""
    sel = (selector or "").strip()
    if not sel:
        return {"ok": False, "error": "empty selector"}
    errs = []
    # 1. CSS / XPath / Playwright selector directly.
    try:
        loc = page.locator(sel).first
        await loc.click(timeout=timeout_ms)
        return {"ok": True, "via": "selector"}
    except Exception as e:  # noqa: BLE001
        errs.append(f"selector: {str(e)[:160]}")
    # 2. Visible text.
    try:
        await page.get_by_text(sel).first.click(timeout=timeout_ms)
        return {"ok": True, "via": "text"}
    except Exception as e:  # noqa: BLE001
        errs.append(f"text: {str(e)[:160]}")
    # 3. Placeholder (useful for search boxes that are found by hint text).
    try:
        await page.get_by_placeholder(sel).first.click(timeout=timeout_ms)
        return {"ok": True, "via": "placeholder"}
    except Exception as e:  # noqa: BLE001
        errs.append(f"placeholder: {str(e)[:160]}")
    return {"ok": False, "error": "click found nothing: " + " | ".join(errs)[:500]}


async def _bw_try_fill(page, selector: str, text: str, timeout_ms: int) -> dict:
    sel = (selector or "").strip()
    if not sel:
        return {"ok": False, "error": "empty selector"}
    errs = []
    try:
        await page.locator(sel).first.fill(text, timeout=timeout_ms)
        return {"ok": True, "via": "selector"}
    except Exception as e:  # noqa: BLE001
        errs.append(f"selector: {str(e)[:160]}")
    try:
        await page.get_by_placeholder(sel).first.fill(text, timeout=timeout_ms)
        return {"ok": True, "via": "placeholder"}
    except Exception as e:  # noqa: BLE001
        errs.append(f"placeholder: {str(e)[:160]}")
    try:
        await page.get_by_label(sel).first.fill(text, timeout=timeout_ms)
        return {"ok": True, "via": "label"}
    except Exception as e:  # noqa: BLE001
        errs.append(f"label: {str(e)[:160]}")
    return {"ok": False, "error": "type found nothing: " + " | ".join(errs)[:500]}


@mcp.tool()
async def browser_open(url: str, headless: bool = False, pin: str = "", timeout: int = 30) -> dict:
    """Start the persistent browser session if needed and go to the URL.

    Args:
        url: page to open (https:// added if missing).
        headless: False = visible window (default), True = no window.
        timeout: seconds (10-120, default 30).
    """
    bad = _need_pin(pin)
    if bad:
        return bad
    timeout = max(10, min(int(timeout or 30), 120))
    url = (url or "").strip()
    if not url:
        return {"ok": False, "error": "empty url"}
    if "://" not in url:
        url = "https://" + url
    async with _bw_lock:
        page, err = await _bw_ensure(headless=headless, timeout=timeout)
        if err:
            return err
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=timeout * 1000)
            try:
                await page.wait_for_load_state("networkidle", timeout=5000)
            except Exception:  # noqa: BLE001
                pass
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"goto failed: {str(e)[:300]}", "url": url}
        info = await _bw_info(page)
        return {"ok": True, "url": info["url"], "title": info["title"],
                "headless": _bw_headless, "tabs": len(_bw_pages), "current": _bw_current}


@mcp.tool()
async def browser_click(selector: str, pin: str = "", timeout: int = 10) -> dict:
    """Click an element by CSS/XPath selector or by its visible text.

    Args:
        selector: CSS/XPath (e.g. 'a#video-title', 'input[name=search]') or text ('Accept all').
        timeout: seconds per attempt (default 10).
    """
    bad = _need_pin(pin)
    if bad:
        return bad
    timeout_ms = max(1, min(int(timeout or 10), 60)) * 1000
    async with _bw_lock:
        page = _bw_cur()
        if page is None:
            return {"ok": False, "error": "no browser session — call browser_open(url) first"}
        r = await _bw_try_click(page, selector, timeout_ms)
        if not r.get("ok"):
            return r
        info = await _bw_info(page)
        r.update(info)
        return r


@mcp.tool()
async def browser_type(selector: str, text: str, press_enter: bool = False,
                       pin: str = "", timeout: int = 10) -> dict:
    """Type text into a field found by selector, placeholder or label.

    Args:
        selector: CSS (e.g. "input[name='search_query']") or placeholder/label text.
        text: text to type (replaces field content).
        press_enter: press Enter after typing (e.g. submit a search).
        timeout: seconds (default 10).
    """
    bad = _need_pin(pin)
    if bad:
        return bad
    timeout_ms = max(1, min(int(timeout or 10), 60)) * 1000
    async with _bw_lock:
        page = _bw_cur()
        if page is None:
            return {"ok": False, "error": "no browser session — call browser_open(url) first"}
        r = await _bw_try_fill(page, selector, text, timeout_ms)
        if not r.get("ok"):
            return r
        if press_enter:
            try:
                await page.keyboard.press("Enter")
                r["pressed_enter"] = True
            except Exception as e:  # noqa: BLE001
                return {"ok": False, "error": f"typed but Enter failed: {str(e)[:200]}"}
        info = await _bw_info(page)
        r.update(info)
        return r


@mcp.tool()
async def browser_read(selector: str | None = None, pin: str = "",
                       timeout: int = 10, max_chars: int = 8000) -> dict:
    """Return visible page text (default) or one element's text. Use this, NOT screenshots.

    Args:
        selector: None = whole page; else CSS for one element.
        timeout: seconds (default 10).
        max_chars: truncate (default 8000).
    """
    bad = _need_pin(pin)
    if bad:
        return bad
    timeout_ms = max(1, min(int(timeout or 10), 60)) * 1000
    max_chars = max(500, min(int(max_chars or 8000), 20000))
    async with _bw_lock:
        page = _bw_cur()
        if page is None:
            return {"ok": False, "error": "no browser session — call browser_open(url) first"}
        try:
            if selector:
                txt = await page.locator(selector).first.inner_text(timeout=timeout_ms)
            else:
                txt = await page.inner_text("body", timeout=timeout_ms)
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"read failed: {str(e)[:300]}"}
        info = await _bw_info(page)
        txt = (txt or "").strip()[:max_chars]
        return {"ok": True, "url": info["url"], "title": info["title"], "text": txt,
                "chars": len(txt)}


@mcp.tool()
async def browser_screenshot(pin: str = "", max_width: int = 800):
    """Take a PNG of the current page. Only when asked — prefer browser_read.

    Args:
        max_width: downscale width (default 800, 0 = full size).
    """
    from mcp.types import ImageContent
    bad = _need_pin(pin)
    if bad:
        return bad["error"]
    async with _bw_lock:
        page = _bw_cur()
        if page is None:
            return "no browser session — call browser_open(url) first"
        try:
            data = await page.screenshot(full_page=False, timeout=15000)
        except Exception as e:  # noqa: BLE001
            return f"page screenshot failed: {e}"[:300]
    import base64 as _b64
    import tempfile as _tf
    tmp = _tf.mktemp(suffix=".png")
    try:
        Path(tmp).write_bytes(bytes(data))
        if max_width and shutil.which("convert"):
            small = tmp + ".small.png"
            subprocess.run(["convert", tmp, "-resize", f"{int(max_width)}x>", small],
                           timeout=15, capture_output=True)
            if Path(small).is_file():
                data = Path(small).read_bytes()
                Path(small).unlink(missing_ok=True)
        return ImageContent(type="image", data=_b64.b64encode(bytes(data)).decode(),
                            mimeType="image/png")
    except Exception as e:  # noqa: BLE001
        return f"screenshot failed: {e}"[:300]
    finally:
        Path(tmp).unlink(missing_ok=True)


@mcp.tool()
async def browser_eval(js: str, pin: str = "", timeout: int = 10) -> dict:
    """Run JavaScript on the page and return the result.

    Args:
        js: JS snippet, e.g. "document.title" or "() => document.querySelectorAll('a').length".
        timeout: seconds (default 10).
    """
    bad = _need_pin(pin)
    if bad:
        return bad
    js = js or ""
    if len(js) > 4000:
        return {"ok": False, "error": "js too long (max 4000 chars)"}
    async with _bw_lock:
        page = _bw_cur()
        if page is None:
            return {"ok": False, "error": "no browser session — call browser_open(url) first"}
        try:
            res = await _asyncio.wait_for(page.evaluate(js),
                                          timeout=max(1, min(int(timeout or 10), 60)))
        except _asyncio.TimeoutError:
            return {"ok": False, "error": "eval timed out"}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"eval failed: {str(e)[:400]}"}
    try:
        txt = json.dumps(res, default=str)[:8000]
    except Exception:  # noqa: BLE001
        txt = str(res)[:8000]
    return {"ok": True, "result": txt}


@mcp.tool()
async def browser_tabs(action: str = "list", index: int | None = None,
                       url: str = "", pin: str = "") -> dict:
    """List, switch, close or open tabs in the persistent session.

    Args:
        action: 'list' (default), 'switch', 'close', 'new'.
        index: tab index for switch/close.
        url: URL for 'new' (blank tab if empty).
    """
    bad = _need_pin(pin)
    if bad:
        return bad
    global _bw_current
    action = (action or "list").strip().lower()
    async with _bw_lock:
        if action == "new":
            if _bw_context is None:
                return {"ok": False, "error": "no browser session — call browser_open(url) first"}
            try:
                page = await _bw_context.new_page()
                _bw_pages.append(page)
                _bw_current = len(_bw_pages) - 1
                target = (url or "").strip()
                if target:
                    if "://" not in target:
                        target = "https://" + target
                    await page.goto(target, wait_until="domcontentloaded", timeout=30000)
                info = await _bw_info(page)
                return {"ok": True, "opened": _bw_current, "url": info["url"],
                        "title": info["title"], "tabs": len(_bw_pages)}
            except Exception as e:  # noqa: BLE001
                return {"ok": False, "error": f"new tab failed: {str(e)[:300]}"}
        if not _bw_pages:
            return {"ok": False, "error": "no browser session — call browser_open(url) first"}
        if action == "list":
            tabs = []
            for i, pg in enumerate(_bw_pages):
                try:
                    tabs.append({"index": i, "url": pg.url,
                                 "title": (await pg.title())[:200],
                                 "current": i == _bw_current})
                except Exception:  # noqa: BLE001
                    tabs.append({"index": i, "url": "?", "title": "?",
                                 "current": i == _bw_current})
            return {"ok": True, "tabs": tabs, "current": _bw_current}
        if action in ("switch", "close"):
            if index is None:
                return {"ok": False, "error": "index required for switch/close"}
            try:
                index = int(index)
            except Exception:  # noqa: BLE001
                return {"ok": False, "error": "index must be a number"}
            if not 0 <= index < len(_bw_pages):
                return {"ok": False, "error": f"bad index {index} (0-{len(_bw_pages) - 1})"}
            if action == "switch":
                _bw_current = index
                info = await _bw_info(_bw_pages[index])
                return {"ok": True, "current": index, "url": info["url"], "title": info["title"]}
            try:
                await _bw_pages[index].close()
            except Exception:  # noqa: BLE001
                pass
            del _bw_pages[index]
            if not _bw_pages:
                _bw_current = -1
                return {"ok": True, "closed": index, "tabs": 0}
            _bw_current = max(0, min(_bw_current, len(_bw_pages) - 1))
            info = await _bw_info(_bw_pages[_bw_current])
            return {"ok": True, "closed": index, "tabs": len(_bw_pages),
                    "current": _bw_current, "url": info["url"], "title": info["title"]}
        return {"ok": False, "error": f"unknown action '{action}' — use list/switch/close/new"}


@mcp.tool()
async def browser_close(pin: str = "") -> dict:
    """Shut the persistent browser session down."""
    bad = _need_pin(pin)
    if bad:
        return bad
    global _bw_play, _bw_browser, _bw_context, _bw_pages, _bw_current, _bw_headless
    async with _bw_lock:
        n = len(_bw_pages)
        for pg in _bw_pages:
            try:
                await pg.close()
            except Exception:  # noqa: BLE001
                pass
        _bw_pages = []
        _bw_current = -1
        if _bw_browser is not None:
            try:
                await _bw_browser.close()
            except Exception:  # noqa: BLE001
                pass
        _bw_browser = None
        _bw_context = None
        _bw_headless = None
        if _bw_play is not None:
            try:
                await _bw_play.stop()
            except Exception:  # noqa: BLE001
                pass
        _bw_play = None
        return {"ok": True, "closed_tabs": n}


# ── entrypoint ─────────────────────────────────────────────────────────

# ── minimal OAuth 2.1 authorization server (auto-approve) ──────────────
# Why this exists: some AI apps (Claude custom connectors with "Sign in now")
# ONLY speak OAuth + Dynamic Client Registration — they cannot send a static
# Bearer token. This shim lets them register, instantly approves (no login
# page; it's your own box), and issues tokens — no passwords involved.
#
# SECURITY: this is OPEN registration — anyone who knows the URL can complete
# the flow and use the tools. The random tunnel URL is the only secrecy for
# read-only tools, and the control PIN is the only guard for terminal/open_app
# (RCE). Do NOT share the PIN or expose this tunnel more widely than needed.
oauth_clients: dict = {}  # client_id -> {"redirect_uris": [...], "created": ts}
oauth_codes: dict = {}    # code -> {"client_id","redirect_uri","challenge","method","exp"}
oauth_access: dict = {}   # access_token -> exp
oauth_refresh: dict = {}  # refresh_token -> exp

OAUTH_CODE_TTL = 600
OAUTH_ACCESS_TTL = 12 * 3600
OAUTH_REFRESH_TTL = 30 * 24 * 3600


def _public_base(request) -> str:  # noqa: ANN001, ANN201
    """Public base URL as the client sees it (honours the tunnel's proto)."""
    host = request.headers.get("host", "")
    proto = request.headers.get("x-forwarded-proto", "")
    if not proto:
        proto = "http" if host.split(":")[0] in ("127.0.0.1", "localhost", "::1") \
            or host.startswith(("192.168.", "10.", "172.16.", "172.17.")) else "https"
    return f"{proto}://{host}"


def _pkce_ok(verifier: str, challenge: str, method: str) -> bool:
    if method == "plain":
        return verifier == challenge
    digest = hashlib.sha256(verifier.encode()).digest()
    import base64
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode() == challenge


def _prune_oauth() -> None:
    now = time.time()
    for store, ttl_key in ((oauth_codes, None),):
        for k in [k for k, v in store.items() if v["exp"] < now]:
            del store[k]
    for k in [k for k, v in oauth_access.items() if v < now]:
        del oauth_access[k]
    for k in [k for k, v in oauth_refresh.items() if v < now]:
        del oauth_refresh[k]


def _oauth_routes():  # noqa: ANN201
    from starlette.requests import Request
    from starlette.responses import JSONResponse, RedirectResponse
    from starlette.routing import Route

    async def resource_meta(request: Request):  # noqa: ANN201
        base = _public_base(request)
        return JSONResponse({
            "resource": base + "/mcp",
            "authorization_servers": [base],
            "bearer_methods_supported": ["header"],
            "scopes_supported": ["tools"],
        })

    async def as_meta(request: Request):  # noqa: ANN201
        base = _public_base(request)
        return JSONResponse({
            "issuer": base,
            "authorization_endpoint": base + "/oauth/authorize",
            "token_endpoint": base + "/oauth/token",
            "registration_endpoint": base + "/oauth/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256", "plain"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": ["tools"],
        })

    async def register(request: Request):  # noqa: ANN201
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = {}
        redirect_uris = body.get("redirect_uris") or []
        client_id = "kali-" + secrets.token_hex(8)
        oauth_clients[client_id] = {"redirect_uris": redirect_uris, "created": time.time()}
        print(f"[oauth] registered client {client_id} uris={redirect_uris}", flush=True)
        return JSONResponse({
            "client_id": client_id,
            "client_secret": "",
            "client_id_issued_at": int(time.time()),
            "redirect_uris": redirect_uris,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        }, status_code=201)

    async def authorize(request: Request):  # noqa: ANN201
        q = request.query_params
        client_id = q.get("client_id", "")
        redirect_uri = q.get("redirect_uri", "")
        state = q.get("state", "")
        challenge = q.get("code_challenge", "")
        method = q.get("code_challenge_method", "plain")
        # Auto-approve: bind redirect_uri to the client if we know it,
        # otherwise trust it as long as it is https (or loopback) — it's your box.
        if client_id in oauth_clients and redirect_uri:
            known = oauth_clients[client_id]["redirect_uris"]
            if known and redirect_uri not in known:
                return JSONResponse({"error": "invalid redirect_uri"}, status_code=400)
        if not redirect_uri.startswith(("https://", "http://127.0.0.1", "http://localhost")):
            return JSONResponse({"error": "redirect_uri must be https (or loopback)"},
                                status_code=400)
        code = "kc-" + secrets.token_urlsafe(24)
        oauth_codes[code] = {"client_id": client_id, "redirect_uri": redirect_uri,
                             "challenge": challenge, "method": method,
                             "exp": time.time() + OAUTH_CODE_TTL}
        print(f"[oauth] approved client {client_id or '?'} -> code issued", flush=True)
        sep = "&" if "?" in redirect_uri else "?"
        loc = redirect_uri + sep + urllib.parse.urlencode(
            {k: v for k, v in (("code", code), ("state", state)) if v})
        return RedirectResponse(loc, status_code=302)

    async def token(request: Request):  # noqa: ANN201
        _prune_oauth()
        form = await request.form()
        grant = form.get("grant_type", "")
        if grant == "authorization_code":
            code = str(form.get("code", ""))
            redirect_uri = str(form.get("redirect_uri", ""))
            verifier = str(form.get("code_verifier", ""))
            rec = oauth_codes.pop(code, None)
            if not rec or rec["exp"] < time.time():
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            if redirect_uri and redirect_uri != rec["redirect_uri"]:
                return JSONResponse({"error": "redirect_uri mismatch"}, status_code=400)
            if rec["challenge"] and not _pkce_ok(verifier, rec["challenge"], rec["method"]):
                return JSONResponse({"error": "PKCE verification failed"}, status_code=400)
        elif grant == "refresh_token":
            rt = str(form.get("refresh_token", ""))
            if rt not in oauth_refresh or oauth_refresh.pop(rt) < time.time():
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
        else:
            return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
        access = "ka-" + secrets.token_urlsafe(32)
        refresh = "kr-" + secrets.token_urlsafe(32)
        oauth_access[access] = time.time() + OAUTH_ACCESS_TTL
        oauth_refresh[refresh] = time.time() + OAUTH_REFRESH_TTL
        return JSONResponse({"access_token": access, "token_type": "Bearer",
                             "expires_in": OAUTH_ACCESS_TTL,
                             "refresh_token": refresh, "scope": "tools"})

    return [
        Route("/.well-known/oauth-protected-resource", resource_meta),
        Route("/.well-known/oauth-protected-resource/mcp", resource_meta),
        Route("/.well-known/oauth-authorization-server", as_meta),
        Route("/oauth/register", register, methods=["POST"]),
        Route("/oauth/authorize", authorize, methods=["GET"]),
        Route("/oauth/token", token, methods=["POST"]),
    ]


def _is_loopback(host: str) -> bool:
    return host in ("127.0.0.1", "localhost", "::1")


def main() -> None:
    ap = argparse.ArgumentParser(description="kali-mcp server (stdio or Streamable HTTP)")
    ap.add_argument("--http", action="store_true", help="serve Streamable HTTP instead of stdio")
    ap.add_argument("--host", default="127.0.0.1", help="HTTP bind address (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8000, help="HTTP port (default 8000)")
    ap.add_argument("--token", default=os.environ.get("KALI_MCP_TOKEN", ""),
                    help="Bearer token for HTTP (or env KALI_MCP_TOKEN). REQUIRED for non-loopback bind.")
    ap.add_argument("--allow-host", action="append", default=[],
                    help="Extra Host header to accept (repeatable), e.g. your "
                         "trycloudflare.com tunnel name. Or env KALI_MCP_ALLOW_HOSTS "
                         "(comma-separated). Needed because the MCP SDK rejects "
                         "foreign Host headers (DNS-rebinding protection).")
    args = ap.parse_args()

    if not args.http:
        mcp.run()  # stdio
        return

    if not _is_loopback(args.host) and not args.token:
        raise SystemExit("REFUSING to bind {0} without --token (or KALI_MCP_TOKEN). "
                         "An open Kali MCP on the network is remote code execution.".format(args.host))

    # DNS-rebinding protection: the MCP SDK only accepts loopback Host headers
    # by default, so any public/tunnel hostname must be allow-listed explicitly.
    extra_hosts = list(args.allow_host)
    for h in os.environ.get("KALI_MCP_ALLOW_HOSTS", "").split(","):
        h = h.strip()
        if h:
            extra_hosts.append(h)
    if extra_hosts:
        from mcp.server.transport_security import TransportSecuritySettings
        mcp.settings.transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=["127.0.0.1:*", "localhost:*", "[::1]:*"] + extra_hosts,
            allowed_origins=["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"],
        )
        print(f"Allow-listed Host headers: {', '.join(extra_hosts)}", flush=True)

    token = args.token

    # Public paths: OAuth discovery + flow (must work WITHOUT credentials,
    # otherwise clients like Claude can never start "Sign in").
    PUBLIC_PREFIXES = ("/.well-known/", "/oauth/")

    def _token_ok(auth: str) -> bool:
        if token and auth == f"Bearer {token}":
            return True
        if auth.startswith("Bearer "):
            _prune_oauth()
            exp = oauth_access.get(auth[7:])
            if exp and exp > time.time():
                return True
        return False

    if token:
        from starlette.middleware.base import BaseHTTPMiddleware
        from starlette.responses import JSONResponse

        class BearerAuth(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):  # noqa: ANN001, ANN201
                if any(request.url.path.startswith(p) for p in PUBLIC_PREFIXES):
                    return await call_next(request)
                if _token_ok(request.headers.get("authorization", "")):
                    return await call_next(request)
                base = _public_base(request)
                return JSONResponse(
                    {"error": "unauthorized"},
                    status_code=401,
                    headers={"WWW-Authenticate":
                             f'Bearer resource_metadata="{base}/.well-known/oauth-protected-resource"'},
                )

        app = mcp.streamable_http_app()
        for route in _oauth_routes():
            app.routes.append(route)
        app.add_middleware(BearerAuth)
        import uvicorn
        print(f"kali-mcp HTTP on http://{args.host}:{args.port}/mcp  (auth: token REQUIRED)",
              flush=True)
        uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    else:
        print(f"kali-mcp HTTP on http://{args.host}:{args.port}/mcp  (loopback only, no token)",
              flush=True)
        mcp.run(transport="streamable-http", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
