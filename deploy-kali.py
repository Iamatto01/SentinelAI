#!/usr/bin/env python3
"""
SentinelAI 1-Click Deployment Script to Kali Linux Server
Target: kali@192.168.68.132 (/home/kali/SentinelAI)

Actions:
1. Compresses local project into lightweight tar.gz (excluding node_modules, .git, .env)
2. Connects to Kali server via SSH/SFTP
3. Uploads archive to /home/kali/sentinel-deploy.tar.gz
4. Extracts cleanly into /home/kali/SentinelAI
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
REMOTE_DIR = "/home/kali/SentinelAI"
REMOTE_TAR = "/home/kali/sentinel-deploy.tar.gz"

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

def should_ignore(path):
    rel = os.path.relpath(path, PROJECT_ROOT).replace("\\", "/")
    parts = rel.split("/")
    for p in parts:
        if p in ["node_modules", ".git", "dist", ".system_generated", "__pycache__", ".venv", "venv"]:
            return True
    if rel.endswith(".tar.gz") or rel.endswith(".log"):
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

def deploy_to_kali(local_tar):
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

echo "   ✓ Files extracted to {REMOTE_DIR}"

cd {REMOTE_DIR}

# Ensure .env exists if not present
if [ ! -f .env ] && [ -f .env.example ]; then
    cp .env.example .env
fi

# Build production bundle for frontend
echo "   🔨 Building frontend..."
npm run build --prefix frontend

# Restart running SentinelAI server processes
echo "   🔄 Restarting SentinelAI server processes on Kali..."
pkill -f "concurrently.*SentinelAI" || true
pkill -f "node.*src/index.js" || true
pkill -f "node.*vite" || true
sleep 1

# Start SentinelAI in background
nohup npm run dev > sentinelai.log 2>&1 &
sleep 2

echo "   ✓ SentinelAI successfully restarted!"
ps aux | grep -E "node.*src/index.js|vite" | grep -v grep || true
"""
    
    stdin, stdout, stderr = ssh.exec_command(remote_commands, get_pty=True)
    for line in stdout:
        print(line.rstrip())
    
    ssh.close()
    print("\n🎉 ========================================================")
    print(f"✅ SentinelAI successfully deployed & running on Kali!")
    print(f"🌐 Web Dashboard: http://{KALI_HOST}:5173")
    print(f"🔌 Backend API:   http://{KALI_HOST}:5000")
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
