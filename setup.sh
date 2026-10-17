#!/bin/bash
# One-time setup for kali-mcp. Run this once after cloning.
# Installs dependencies, sets up daemons, fixes permissions.
# Skips anything already present.

set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

echo "[*] Checking dependencies..."
MISSING=""
for pkg in ydotool grim wl-clipboard libnotify-bin playerctl; do
    if ! dpkg -l "$pkg" &>/dev/null; then
        MISSING="$MISSING $pkg"
    fi
done
if [ -n "$MISSING" ]; then
    echo "  Installing:$MISSING"
    sudo apt update -qq
    sudo apt install -y -qq $MISSING
else
    echo "  All packages already installed"
fi

echo "[*] Setting up ydotoold..."
sudo mkdir -p /run/user/$(id -u)
sudo chown $(whoami):$(whoami) /run/user/$(id -u)

if ! groups | grep -q input; then
    sudo usermod -aG input $(whoami)
    echo "  [!] Added to input group — re-login for it to take effect"
else
    echo "  Already in input group"
fi

if ! pgrep -x ydotoold > /dev/null; then
    sudo ydotoold -p /tmp/.ydotool_socket &
    sleep 1
    echo "  Started ydotoold"
else
    echo "  ydotoold already running"
fi
sudo chmod 666 /tmp/.ydotool_socket 2>/dev/null || true

mkdir -p ~/.config/systemd/user
if [ ! -f ~/.config/systemd/user/ydotoold.service ]; then
    cat > ~/.config/systemd/user/ydotoold.service << 'EOF'
[Unit]
Description=ydotool daemon (keyboard/mouse input)
After=graphical-session.target

[Service]
Type=simple
ExecStart=/usr/bin/ydotoold -p /tmp/.ydotool_socket
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
EOF
    systemctl --user daemon-reload
    systemctl --user enable ydotoold.service 2>/dev/null || true
    echo "  Created ydotoold systemd service"
else
    echo "  ydotoold service already exists"
fi

if [ ! -f ~/.config/systemd/user/swaync.service ]; then
    cat > ~/.config/systemd/user/swaync.service << 'EOF'
[Unit]
Description=Notification daemon (swaync)
After=graphical-session.target

[Service]
Type=simple
ExecStart=/usr/bin/swaync
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
EOF
    systemctl --user daemon-reload
    systemctl --user enable swaync.service 2>/dev/null || true
    echo "  Created swaync systemd service"
else
    echo "  swaync service already exists"
fi

echo "[*] Checking Python venv..."
if [ ! -d "$DIR/.venv" ]; then
    python3 -m venv "$DIR/.venv"
    "$DIR/.venv/bin/pip" install -q "mcp" uvicorn starlette "playwright==1.64.0"
    echo "  Created venv + installed packages"
else
    echo "  venv already exists"
fi

if [ ! -d ~/.cache/ms-playwright/firefox-* ]; then
    echo "  Installing Playwright Firefox..."
    "$DIR/.venv/bin/python" -m playwright install firefox 2>/dev/null || true
else
    echo "  Playwright Firefox already installed"
fi

echo ""
echo "[OK] Setup complete!"
echo "  Run: ./start-https.sh"
echo "  Or:  .venv/bin/python server.py"
