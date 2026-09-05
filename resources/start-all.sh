#!/bin/bash
# start-all.sh — launched by systemd, keeps npm as foreground process
# so systemd can track it. All other services are backgrounded.
#
# Startup order: msfrpcd → cloudflared → FYP2 backend
# Each service is verified before moving to the next.
# Note: Hexstrike engine removed — tools run natively via direct subprocess.

set -e

cd /home/kali/SentinelAI
LOG_DIR="/home/kali"

# ── Helpers ──────────────────────────────────────────────────────────────────

log() { echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOG_DIR/sentinelai.log"; }

wait_for_port() {
  local port="$1"
  local name="$2"
  local max_wait="${3:-30}"
  local waited=0
  log "  Waiting for $name on port $port (max ${max_wait}s)..."
  while [ $waited -lt $max_wait ]; do
    if ss -tlnp 2>/dev/null | grep -q ":$port "; then
      log "  ✓ $name is listening on port $port"
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done
  log "  ⚠ $name did not start on port $port within ${max_wait}s"
  return 1
}

# ── 1. Metasploit RPC (port 55553) ──────────────────────────────────────────

log "=== Starting SentinelAI services ==="

log "[1/3] Starting Metasploit RPC daemon..."
MSF_USER="${MSF_USER:-msf}"
MSF_PASS="${MSF_PASS:-msf}"

if command -v msfrpcd &> /dev/null; then
  # Kill any stale instance
  pkill -f msfrpcd 2>/dev/null || true
  fuser -k 55553/tcp 2>/dev/null || true
  sleep 1
  nohup msfrpcd -U "$MSF_USER" -P "$MSF_PASS" -a 127.0.0.1 -p 55553 -S > "$LOG_DIR/msfrpcd.log" 2>&1 &
  wait_for_port 55553 "msfrpcd" 20 || log "  ⚠ msfrpcd may still be initializing — check $LOG_DIR/msfrpcd.log"
else
  log "[1/3] ⚠ msfrpcd not found — install: sudo apt install -y metasploit-framework"
fi

# ── 2. Cloudflare Tunnel ────────────────────────────────────────────────────

log "[2/3] Starting Cloudflare tunnel..."
if command -v cloudflared &> /dev/null; then
  pkill -f "tunnel.*run sentinelai" 2>/dev/null || true
  sleep 1
  nohup cloudflared tunnel --edge-ip-version 4 run sentinelai > "$LOG_DIR/cloudflared.log" 2>&1 &
  log "  ✓ Cloudflare tunnel started"
else
  log "[3/4] ⚠ cloudflared not installed — tunnel unavailable"
fi

# ── 3. FYP2 Platform (FOREGROUND — systemd tracks this) ─────────────────────

log "[3/3] Starting FYP2 Platform..."
log "=== All services started, FYP2 Platform running ==="
exec npm run dev