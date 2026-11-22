#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/9ostudio/obsidian-collaboration-server.git}"
APP_DIR="${APP_DIR:-$HOME/obsidian-collaboration-server}"
CONF_DIR="$HOME/.config/obsidian-collaboration"
DATA_DIR="${DATA_DIR:-$HOME/.local/share/obsidian-collaboration}"
PORT="${PORT:-8790}"
NODE_HOME="$HOME/.local/opt/node"
SERVICE=obsidian-collaboration
ME="${USER:-$(id -un)}"

say() { printf '\033[1m%s\033[0m\n' "$*"; }
fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }

command -v curl >/dev/null || fail "curl is required"
command -v systemctl >/dev/null || fail "systemd is required"

export PATH="$NODE_HOME/bin:$PATH"
node_ok() { command -v node >/dev/null && [ "$(node -p 'process.versions.node.split(".")[0]')" -ge 20 ]; }
if ! node_ok; then
  case "$(uname -m)" in
    x86_64) arch=x64 ;;
    aarch64|arm64) arch=arm64 ;;
    armv7l) arch=armv7l ;;
    *) fail "unsupported CPU $(uname -m)" ;;
  esac
  say "Installing Node.js 22 to $NODE_HOME"
  base=https://nodejs.org/dist/latest-v22.x
  sums=$(curl -fsSL "$base/SHASUMS256.txt")
  file=$(printf '%s\n' "$sums" | grep -oE "node-v22\.[0-9]+\.[0-9]+-linux-$arch\.tar\.xz" | head -1)
  tmp=$(mktemp -d)
  curl -fsSL "$base/$file" -o "$tmp/$file"
  (cd "$tmp" && printf '%s\n' "$sums" | grep " $file\$" | sha256sum -c - >/dev/null)
  mkdir -p "$HOME/.local/opt"
  tar -xJf "$tmp/$file" -C "$HOME/.local/opt"
  ln -sfn "$HOME/.local/opt/${file%.tar.xz}" "$NODE_HOME"
  rm -rf "$tmp"
fi
NODE_BIN="$(command -v node)"

if [ -d "$APP_DIR/.git" ] && command -v git >/dev/null; then
  say "Updating $APP_DIR"
  git -C "$APP_DIR" fetch --quiet origin main
  git -C "$APP_DIR" reset --quiet --hard origin/main
elif command -v git >/dev/null && [ ! -e "$APP_DIR" ]; then
  say "Downloading to $APP_DIR"
  git clone --quiet "$REPO_URL" "$APP_DIR"
else
  say "Downloading to $APP_DIR"
  tmp=$(mktemp -d)
  curl -fsSL "${REPO_URL%.git}/archive/refs/heads/main.tar.gz" | tar -xz -C "$tmp" --strip-components=1
  mkdir -p "$APP_DIR"
  find "$APP_DIR" -mindepth 1 -maxdepth 1 ! -name node_modules -exec rm -rf {} +
  cp -a "$tmp"/. "$APP_DIR"/
  rm -rf "$tmp"
fi
(cd "$APP_DIR" && npm ci --omit=dev --no-audit --no-fund --loglevel=error)

mkdir -p "$CONF_DIR" "$DATA_DIR"
ENV_FILE="$CONF_DIR/server.env"
fresh=0
if [ ! -f "$ENV_FILE" ]; then
  fresh=1
  public_url="${PUBLIC_URL:-}"
  funnel=0
  if [ -z "$public_url" ] && command -v tailscale >/dev/null; then
    host=$(tailscale status --json 2>/dev/null | "$NODE_BIN" -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{process.stdout.write(JSON.parse(s).Self.DNSName.replace(/\.$/,""))}catch{}})')
    if [ -n "$host" ]; then public_url="https://$host"; funnel=1; fi
  fi
  [ -n "$public_url" ] || fail "set PUBLIC_URL to the https address that reaches 127.0.0.1:$PORT, then run again"
  umask 077
  cat > "$ENV_FILE" <<EOF
PORT=$PORT
HOST=127.0.0.1
DATA_DIR=$DATA_DIR
PUBLIC_URL=${public_url%/}
USE_FUNNEL=$funnel
EOF
  umask 022
fi
set -a; . "$ENV_FILE"; set +a

mkdir -p "$HOME/.config/systemd/user"
cat > "$HOME/.config/systemd/user/$SERVICE.service" <<EOF
[Unit]
Description=Collaboration server for Obsidian
After=network-online.target

[Service]
WorkingDirectory=$APP_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$NODE_BIN server.mjs
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
EOF
loginctl enable-linger "$ME" 2>/dev/null || say "Could not keep the server running after logout. Run: sudo loginctl enable-linger $ME"
systemctl --user daemon-reload
systemctl --user enable --quiet "$SERVICE"
systemctl --user restart "$SERVICE"

if [ "${USE_FUNNEL:-0}" = 1 ]; then
  timeout 60 tailscale funnel --bg "$PORT" >/dev/null || say "Tailscale Funnel failed. Run once: sudo tailscale set --operator=$ME, then run this installer again."
fi

for _ in $(seq 1 20); do curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null 2>&1 || fail "the server did not start. See: journalctl --user -u $SERVICE"

say "Collaboration server is running at $PUBLIC_URL"
if [ "$fresh" = 1 ]; then
  ENV_FILE="$ENV_FILE" "$APP_DIR/owner-link.sh"
else
  echo "For a one-time owner link, run: $APP_DIR/owner-link.sh"
fi
