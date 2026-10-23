#!/usr/bin/env bash
# One-command setup of ScamShield on a fresh Ubuntu 22.04/24.04 server (e.g. a DigitalOcean Droplet).
#
# Run as root on the server:
#   curl -fsSL https://raw.githubusercontent.com/karthikeyaA06/scamshield/main/deploy/setup_droplet.sh | bash
#
# Options (environment variables):
#   SCAMSHIELD_MODEL   Ollama model to use (default gemma4:e2b, best for CPU servers)
#   SCAMSHIELD_REPO    Git repository to install (default the URL below)
#   SCAMSHIELD_PORT    Port to serve on (default 80, so http://<server-ip> works)
#   NO_MODEL=1         Skip Ollama/Gemma entirely and use rule explanations only
set -euo pipefail

REPO="${SCAMSHIELD_REPO:-https://github.com/karthikeyaA06/scamshield.git}"
MODEL="${SCAMSHIELD_MODEL:-gemma4:e2b}"
PORT="${SCAMSHIELD_PORT:-80}"
DIR=/opt/scamshield

say() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root (on a Droplet you log in as root)." >&2
  exit 1
fi

say "Installing system packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y git python3 python3-venv python3-pip curl

# Small servers need swap so the model and Python packages fit in memory.
if ! swapon --show | grep -q '/swapfile'; then
  say "Adding 4 GB of swap"
  fallocate -l 4G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
  grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

if [ "${NO_MODEL:-0}" != "1" ]; then
  if ! command -v ollama >/dev/null 2>&1; then
    say "Installing Ollama"
    curl -fsSL https://ollama.com/install.sh | sh
  fi
  systemctl enable --now ollama || true
  say "Downloading the model $MODEL (a few GB, this takes a while)"
  for i in 1 2 3; do ollama pull "$MODEL" && break || sleep 5; done
fi

say "Getting ScamShield"
if [ -d "$DIR/.git" ]; then
  git -C "$DIR" pull --ff-only
else
  git clone "$REPO" "$DIR"
fi

say "Installing Python packages"
python3 -m venv "$DIR/.venv"
"$DIR/.venv/bin/pip" install --upgrade pip -q
"$DIR/.venv/bin/pip" install -r "$DIR/requirements.txt" -q

say "Creating the scamshield service"
NO_MODEL_LINE=""
if [ "${NO_MODEL:-0}" = "1" ]; then NO_MODEL_LINE="Environment=SCAMSHIELD_NO_MODEL=1"; fi
REPO_WEB="${REPO%.git}"
cat > /etc/systemd/system/scamshield.service <<EOF
[Unit]
Description=ScamShield web app
After=network-online.target ollama.service
Wants=network-online.target

[Service]
WorkingDirectory=$DIR
Environment=SCAMSHIELD_HOSTED=1
Environment=SCAMSHIELD_MODEL=$MODEL
Environment=SCAMSHIELD_REPO_URL=$REPO_WEB
Environment=SCAMSHIELD_TIMEOUT=180
$NO_MODEL_LINE
ExecStart=$DIR/.venv/bin/python -m uvicorn app.server:app --host 0.0.0.0 --port $PORT --workers 1
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now scamshield
systemctl restart scamshield

# Open the port if the Ubuntu firewall is on.
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  ufw allow "$PORT"/tcp
fi

IP="$(curl -fsS https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')"
say "Done. Open http://$IP$( [ "$PORT" = 80 ] || echo ":$PORT" )"
echo "Logs:    journalctl -u scamshield -f"
echo "Update:  bash $DIR/deploy/setup_droplet.sh   (pulls the latest code and restarts)"
