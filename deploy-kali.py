#!/usr/bin/env python3
"""
SentinelAI 1-Click Deployment Script to Kali Linux Server
Target: kali@192.168.68.132 (/home/kali/server/SentinelAI)

Actions:
1. Compresses local project into lightweight tar.gz (excluding node_modules, .git, .env)
2. Connects to Kali server via SSH/SFTP
3. Uploads archive to /home/kali/sentinel-deploy.tar.gz
4. Extracts cleanly into /home/kali/server/SentinelAI
5. Installs dependencies, builds frontend, and restarts services
"""

import os
import sys
import tarfile
import tempfile
import time

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

try:
    import paramiko
except ImportError:
    print("[Error] 'paramiko' is required. Run: pip install paramiko")
    sys.exit(1)

# Configuration
KALI_HOST = os.environ.get("KALI_HOST", "192.168.68.132")
KALI_PORT = int(os.environ.get("KALI_PORT", 22))
KALI_USER = os.environ.get("KALI_USER", "kali")
KALI_PASS = os.environ.get("KALI_PASS", "kali")
REMOTE_DIR = "/home/kali/server/SentinelAI"
REMOTE_TAR = "/home/kali/sentinel-deploy.tar.gz"

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

def should_ignore(path):
    rel = os.path.relpath(path, PROJECT_ROOT).replace("\\", "/")
    parts = rel.split("/")
    for p in parts:
        if p in ["node_modules", ".git", "dist", ".system_generated", "__pycache__", ".venv", "venv", "output", "backups", "reports", "SentinelAI_Data"]:
            return True
    if rel.endswith(".tar.gz") or rel.endswith(".log") or rel.endswith(".db") or rel.endswith(".db-wal") or rel.endswith(".db-shm") or rel.endswith(".pdf") or rel.endswith(".sqlite"):
        return True
    if rel in [".env", ".env.local"]:
        return True
    return False

def create_archive(output_tar):
    print(f"📦 [1/4] Compressing SentinelAI project from {PROJECT_ROOT}...")
    start_time = time.time()
    file_count = 0
    with tarfile.open(output_tar, "w:gz") as tar:
        for root, dirs, files in os.walk(PROJECT_ROOT):
            dirs[:] = [d for d in dirs if not should_ignore(os.path.join(root, d))]
            for file in files:
                full_path = os.path.join(root, file)
                if not should_ignore(full_path):
                    rel_path = os.path.relpath(full_path, PROJECT_ROOT)
                    tar.add(full_path, arcname=rel_path)
                    file_count += 1
    size_mb = os.path.getsize(output_tar) / (1024 * 1024)
    print(f"   ✓ Archived {file_count} files ({size_mb:.2f} MB) in {time.time() - start_time:.1f}s")

def get_local_env_var(name):
    env_path = os.path.join(PROJECT_ROOT, ".env")
    if not os.path.exists(env_path):
        return ""
    with open(env_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line.startswith(f"{name}="):
                return line.split("=", 1)[1].strip()
    return ""

def deploy_to_kali(local_tar):
    stripe_sec = get_local_env_var("STRIPE_SECRET_KEY")
    stripe_pub = get_local_env_var("STRIPE_PUBLISHABLE_KEY")
    stripe_cur = get_local_env_var("STRIPE_CURRENCY") or "MYR"

    print(f"🚀 [2/4] Connecting via SSH to {KALI_USER}@{KALI_HOST}:{KALI_PORT}...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(KALI_HOST, port=KALI_PORT, username=KALI_USER, password=KALI_PASS, timeout=15)
    print("   ✓ SSH connection established!")

    print(f"📤 [3/4] Uploading archive to {REMOTE_TAR} via SFTP...")
    sftp = ssh.open_sftp()
    
    last_reported = 0
    def sftp_progress(transferred, total):
        nonlocal last_reported
        pct = int((transferred / total) * 100)
        if pct >= last_reported + 20 or pct == 100:
            print(f"   Transferring: {pct}% ({transferred/(1024*1024):.1f}MB / {total/(1024*1024):.1f}MB)")
            last_reported = pct

    sftp.put(local_tar, REMOTE_TAR, callback=sftp_progress)
    sftp.close()
    print("   ✓ Upload complete!")

    print(f"⚙️  [4/4] Extracting & deploying on Kali server ({REMOTE_DIR})...")
    remote_commands = f"""
set -e
mkdir -p {REMOTE_DIR}
tar -xzf {REMOTE_TAR} -C {REMOTE_DIR}
rm -f {REMOTE_TAR}

mkdir -p /home/kali
ln -sfn {REMOTE_DIR} /home/kali/SentinelAI

echo "   ✓ Files extracted to {REMOTE_DIR}"

cd {REMOTE_DIR}

# Ensure .env exists if not present
if [ ! -f .env ] && [ -f .env.example ]; then
    cp .env.example .env
fi

# Ensure Stripe keys and currency are populated in .env on Kali
python3 -c "
import os, re
env_file = '{REMOTE_DIR}/.env'
keys = {{
    'STRIPE_SECRET_KEY': '{stripe_sec}',
    'STRIPE_PUBLISHABLE_KEY': '{stripe_pub}',
    'STRIPE_CURRENCY': '{stripe_cur}'
}}
content = open(env_file).read() if os.path.exists(env_file) else ''
for k, v in keys.items():
    if not v:
        continue
    if k not in content:
        content += f'\\n{{k}}={{v}}\\n'
    else:
        content = re.sub(rf'^{{k}}=.*$', f'{{k}}={{v}}', content, flags=re.MULTILINE)
with open(env_file, 'w') as f:
    f.write(content)
"

# Install backend dependencies (including stripe)
echo "   📦 Installing backend dependencies..."
npm install --prefix backend

# Install frontend dependencies if needed
echo "   📦 Installing frontend dependencies..."
npm install --prefix frontend

# Build production bundle for frontend
echo "   🔨 Building frontend..."
npm run build --prefix frontend

# Reload through PM2. PM2 owns 5000/5173 -- this script must NEVER fuser -k or
# pkill them. Killing another supervisor's port SIGKILLs the backend
# mid-transaction and corrupts SQLite backups. See defect N-06 in
# resources/ARCHIVED-second-supervisor.md and the port-ownership table.
echo "   🔄 Reloading SentinelAI via PM2 (PM2 owns 5000/5173)..."
pm2 reload sentinel-backend 2>/dev/null || pm2 restart sentinel-backend 2>/dev/null || true
pm2 reload sentinel-frontend 2>/dev/null || pm2 restart sentinel-frontend 2>/dev/null || true
pm2 save 2>/dev/null || true
sleep 3

echo "   ✓ SentinelAI reloaded via PM2"
pm2 jlist 2>/dev/null | head -c 400 || true
"""
    
    stdin, stdout, stderr = ssh.exec_command(remote_commands, get_pty=True)
    for line in stdout:
        print(line.rstrip())
    
    ssh.close()
    print("\n🎉 ========================================================")
    print(f"✅ SentinelAI successfully deployed & running on Kali!")
    print(f"� Public Domain: https://sentinelai.studio")
    print(f"🌐 Local Web:     http://{KALI_HOST}:5173")
    print(f"🔌 Local API:     http://{KALI_HOST}:5000")
    print("========================================================\n")

def main():
    temp_dir = tempfile.gettempdir()
    tar_path = os.path.join(temp_dir, "sentinel-deploy.tar.gz")
    try:
        create_archive(tar_path)
        deploy_to_kali(tar_path)
    finally:
        if os.path.exists(tar_path):
            try:
                os.remove(tar_path)
            except Exception:
                pass

if __name__ == "__main__":
    main()
