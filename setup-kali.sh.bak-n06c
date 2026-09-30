#!/bin/bash
set -e

echo "=== 🚀 Starting Automatic FYP2 Sentinel Platform Setup on Kali Linux ==="

# 0. Check & Install Security Tools (nmap, nuclei, httpx, arjun, dalfox, katana, sqlmap, etc.)
echo "[0/7] Checking & Installing Pentest Tools on Kali Linux..."
TOOLS=("nmap" "nikto" "nuclei" "gobuster" "feroxbuster" "sqlmap" "ffuf" "dirsearch" "wafw00f" "subfinder" "amass" "masscan" "sslscan" "whatweb" "wpscan" "arjun" "dalfox" "httpx-toolkit" "katana")

MISSING=()
for tool in "${TOOLS[@]}"; do
  # handle binary vs package name mapping
  cmd="$tool"
  if [ "$tool" == "httpx-toolkit" ]; then cmd="httpx"; fi
  
  if ! command -v "$cmd" &> /dev/null; then
    MISSING+=("$tool")
  fi
done

if [ ${#MISSING[@]} -ne 0 ]; then
  echo "  ⚙️ Installing missing tools: ${MISSING[*]}..."
  sudo apt update -y
  sudo apt install -y "${MISSING[@]}" 2>/dev/null || true
  
  # Fallback via pip for arjun if apt failed
  if ! command -v arjun &> /dev/null; then
    pip3 install arjun --break-system-packages 2>/dev/null || pip install arjun 2>/dev/null || true
  fi
  
  # Install Go-based tools (katana, dalfox, httpx) via go install if missing
  if ! command -v katana &> /dev/null; then
    echo "  ⚙️ Installing katana via go install..."
    go install github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null || true
    [ -f ~/go/bin/katana ] && sudo cp ~/go/bin/katana /usr/local/bin/katana 2>/dev/null || true
  fi
  if ! command -v dalfox &> /dev/null; then
    echo "  ⚙️ Installing dalfox via go install..."
    go install github.com/hahwul/dalfox/v2@latest 2>/dev/null || true
    [ -f ~/go/bin/dalfox ] && sudo cp ~/go/bin/dalfox /usr/local/bin/dalfox 2>/dev/null || true
  fi
  if ! command -v httpx &> /dev/null; then
    echo "  ⚙️ Installing httpx via go install..."
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || true
    [ -f ~/go/bin/httpx ] && sudo cp ~/go/bin/httpx /usr/local/bin/httpx 2>/dev/null || true
  fi
  
  # Fix wpscan if Ruby is broken
  if ! command -v wpscan &> /dev/null; then
    echo "  ⚙️ Installing wpscan via gem..."
    sudo gem install wpscan 2>/dev/null || true
  fi
else
  echo "  ✓ All 19 security tools are already installed!"
fi

USER_HOME="/home/kali"
if [ -n "$SUDO_USER" ]; then
  USER_HOME="/home/$SUDO_USER"
fi

# 1. BACKUP DATABASE before doing anything else
echo "[1/7] Backing up database..."
mkdir -p "${USER_HOME}/db-backups"
if [ -f "${USER_HOME}/SentinelAI/output/fyp2.db" ]; then
  TIMESTAMP=$(date +%Y%m%d_%H%M%S)
  DB_SIZE=$(stat -c%s "${USER_HOME}/SentinelAI/output/fyp2.db" 2>/dev/null || echo 0)
  cp "${USER_HOME}/SentinelAI/output/fyp2.db" "${USER_HOME}/db-backups/fyp2_${TIMESTAMP}.db"
  cp "${USER_HOME}/SentinelAI/output/fyp2.db-wal" "${USER_HOME}/db-backups/fyp2_${TIMESTAMP}.db-wal" 2>/dev/null || true
  cp "${USER_HOME}/SentinelAI/output/fyp2.db-shm" "${USER_HOME}/db-backups/fyp2_${TIMESTAMP}.db-shm" 2>/dev/null || true
  echo "  ✓ Database backed up: ${USER_HOME}/db-backups/fyp2_${TIMESTAMP}.db (${DB_SIZE} bytes)"
  
  # Auto-prune: keep only the 10 most recent backups
  cd "${USER_HOME}/db-backups"
  ls -t fyp2_*.db 2>/dev/null | tail -n +11 | while read old; do
    rm -f "$old" "${old}-wal" "${old}-shm" 2>/dev/null
    echo "  🗑 Pruned old backup: $old"
  done
  cd "${USER_HOME}"
else
  echo "  ℹ No existing database to backup (first deployment)"
fi

# 2. Extract codebase & clean permissions
echo "[2/7] Extracting latest FYP2 codebase into ${USER_HOME}/SentinelAI..."
mkdir -p "${USER_HOME}/SentinelAI"
if [ -f "${USER_HOME}/fyp2-code.tar.gz" ]; then
  tar -xzf "${USER_HOME}/fyp2-code.tar.gz" --exclude="output/*.db*" -C "${USER_HOME}/SentinelAI/"
fi

# Reset ownership to kali user & clear Vite dev cache to fix EACCES
sudo chown -R kali:kali "${USER_HOME}/SentinelAI" "${USER_HOME}/msfrpcd.log" "${USER_HOME}/cloudflared.log" "${USER_HOME}/sentinelai.log" 2>/dev/null || true
rm -rf "${USER_HOME}/SentinelAI/frontend/node_modules/.vite" 2>/dev/null || true

# 3. Kill existing processes on ports 5000 & 5173
echo "[3/7] Cleaning up old processes..."
fuser -k 5000/tcp 2>/dev/null || true
fuser -k 5173/tcp 2>/dev/null || true
sleep 1

# 4. Setup AI Agent Personas
echo "[4/7] Deploying 51 AI Agent Personas..."
sudo mkdir -p /opt/pentest-ai-agents/agents
if [ -d "${USER_HOME}/SentinelAI/agents" ]; then
  sudo cp -r "${USER_HOME}/SentinelAI/agents/"* /opt/pentest-ai-agents/agents/ 2>/dev/null || true
  echo "  ✓ Deployed 51 agent personas to /opt/pentest-ai-agents/agents"
fi

# 5. Install Node.js dependencies
echo "[5/7] Installing Node.js dependencies..."
cd "${USER_HOME}/SentinelAI"
npm install --quiet --legacy-peer-deps
npm run install:all --quiet

# 6. Create Cloudflare Tunnel config with HTTP2 protocol
echo "[6/7] Configuring Cloudflare Tunnel for sentinelai.studio..."
mkdir -p "${USER_HOME}/.cloudflared"
cat << EOF > "${USER_HOME}/.cloudflared/config.yml"
tunnel: sentinelai
credentials-file: ${USER_HOME}/.cloudflared/cd621432-8f3f-4e58-a7e8-00e5f26e21b7.json
protocol: http2

ingress:
  - hostname: sentinelai.studio
    service: http://127.0.0.1:5173
  - service: http_status:404
EOF

# Route DNS record
cloudflared tunnel route dns --overwrite-dns sentinelai sentinelai.studio 2>/dev/null || true

# 7. Setup Metasploit RPC daemon (msfrpcd)
echo "[7/7] Configuring Metasploit services..."

# Start Metasploit RPC daemon (msfrpcd) for autonomous exploitation
echo "  ⚔️ Starting Metasploit RPC daemon (msfrpcd)..."
MSF_USER="${MSF_USER:-msf}"
MSF_PASS="${MSF_PASS:-msf}"
if command -v msfrpcd &> /dev/null; then
  # Kill any existing msfrpcd
  pkill -f msfrpcd 2>/dev/null || true
  sleep 1
  nohup msfrpcd -U "$MSF_USER" -P "$MSF_PASS" -a 127.0.0.1 -p 55553 -S > "${USER_HOME}/msfrpcd.log" 2>&1 &
  echo "  ✓ msfrpcd started on 127.0.0.1:55553 (user: $MSF_USER)"
  echo "    Set MSF_USER / MSF_PASS in .env to customize credentials"
else
  echo "  ⚠ msfrpcd not found — install Metasploit Framework for exploit capabilities"
  echo "    Run: sudo apt install -y metasploit-framework"
fi

cd "${USER_HOME}/SentinelAI"

# 8. Register and start systemd service for 24/7 auto-restart
echo "[8/8] Registering & Starting SentinelAI systemd service..."
if [ -f "${USER_HOME}/SentinelAI/resources/sentinelai.service" ]; then
  sudo cp "${USER_HOME}/SentinelAI/resources/sentinelai.service" /etc/systemd/system/sentinelai.service
  sudo systemctl daemon-reload
  sudo systemctl enable sentinelai
  sudo systemctl restart sentinelai
  echo "  ✓ SentinelAI service started and registered for 24/7 auto-start!"
  echo "  📋 Commands:"
  echo "     sudo systemctl start sentinelai   — start now"
  echo "     sudo systemctl stop sentinelai    — stop"
  echo "     sudo systemctl status sentinelai  — check status"
  echo "     sudo journalctl -u sentinelai -f  — follow logs"
else
  echo "  ⚠ sentinelai.service not found — skipping auto-start setup"
  echo "  ⚠ After reboot, re-run: bash ~/SentinelAI/setup-kali.sh"
fi

# Show backup status
BACKUP_COUNT=$(ls "${USER_HOME}/db-backups/fyp2_"*.db 2>/dev/null | wc -l)
echo ""
echo "============================================================"
echo " ✅ SETUP COMPLETE! FYP2 Platform is now running 24/7!"
echo " 🌍 Access Dashboard: https://sentinelai.studio"
echo " 🤖 51 AI Specialist Personas active and ready!"
echo " 🗄️  Database backups: ${BACKUP_COUNT} saved in ~/db-backups/"
echo "============================================================"

# 9. Verify all services are running
echo ""
echo "▶ Verifying services..."
sleep 3

check_port() {
  local port="$1" name="$2"
  if ss -tlnp 2>/dev/null | grep -q ":$port "; then
    echo "  ✅ $name — port $port: RUNNING"
    return 0
  else
    echo "  ❌ $name — port $port: NOT RUNNING"
    return 1
  fi
}
ALL_OK=true
check_port 5000 "FYP2 Backend" || ALL_OK=false
check_port 5173 "FYP2 Frontend" || ALL_OK=false
check_port 8888 "Hexstrike Engine" || ALL_OK=false
check_port 55553 "Metasploit RPC" || ALL_OK=false

echo ""
if $ALL_OK; then
  echo "🎉 ALL SERVICES RUNNING — Platform is fully operational!"
else
  echo "⚠ Some services are not running. Check logs:"
  echo "   tail -f ~/sentinelai.log"
  echo "   tail -f ~/hexstrike.log"
  echo "   tail -f ~/msfrpcd.log"
  echo "   sudo journalctl -u sentinelai -f"
fi
