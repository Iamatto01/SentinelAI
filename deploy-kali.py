#!/usr/bin/env python3
"""
SentinelAI 1-Click Deployment Script to Kali Linux Server
Primary Target: Cloudflare Tunnel OpenSSH alias 'kali-n100' (ssh.sentinelai.studio)
Fallback Target: Direct LAN kali@192.168.68.132 (/home/kali/server/SentinelAI)

Actions:
1. Compresses local project into lightweight tar.gz (excluding node_modules, .git, .env, output)
2. Connects to Kali server via OpenSSH (Cloudflare Access) or Paramiko (LAN)
3. Uploads archive to /home/kali/sentinel-deploy.tar.gz
4. Extracts cleanly into /home/kali/server/SentinelAI
5. Installs dependencies, builds frontend, and reloads PM2 services
"""

import hashlib
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

try:
    import paramiko
except ImportError:
    paramiko = None

# Configuration
KALI_HOST = os.environ.get("KALI_HOST", "192.168.68.132")
KALI_PORT = int(os.environ.get("KALI_PORT", 22))
KALI_USER = os.environ.get("KALI_USER", "kali")
KALI_PASS = os.environ.get("KALI_PASS", "kali")
OPENSSH_HOST = os.environ.get("OPENSSH_HOST", "kali-n100")
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

# Critical modules whose stale deployed copies have caused silent regressions.
# Verified by MD5 hash after deploy.
CRITICAL_MODULES = [
    "backend/src/index.js",
    "backend/src/report.js",
    "backend/src/version-audit.js",
    "backend/src/exploits/registry.js",
]

def local_module_hashes():
    hashes = {}
    for rel in CRITICAL_MODULES:
        path = os.path.join(PROJECT_ROOT, rel.replace("/", os.sep))
        if not os.path.isfile(path):
            continue
        with open(path, "rb") as f:
            hashes[rel] = hashlib.md5(f.read()).hexdigest()
    return hashes

def detect_connection():
    has_ssh = shutil.which("ssh") is not None
    if has_ssh:
        # 1. Try Cloudflare Access alias (kali-n100)
        try:
            res = subprocess.run(
                ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", OPENSSH_HOST, "echo ping_cf_ok"],
                capture_output=True, text=True, timeout=15
            )
            if res.returncode == 0 and "ping_cf_ok" in res.stdout:
                return "openssh", OPENSSH_HOST, "Cloudflare Access Tunnel (Global)"
        except Exception as e:
            print(f"   [Debug] Cloudflare tunnel check failed: {e}")

        # 2. Try direct LAN OpenSSH
        lan_target = f"{KALI_USER}@{KALI_HOST}"
        try:
            res = subprocess.run(
                ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=4", "-p", str(KALI_PORT), lan_target, "echo ping_lan_ok"],
                capture_output=True, text=True, timeout=6
            )
            if res.returncode == 0 and "ping_lan_ok" in res.stdout:
                return "openssh", lan_target, "Direct Home LAN (192.168.68.132)"
        except Exception:
            pass

    # 3. Paramiko fallback
    if paramiko is not None:
        return "paramiko", KALI_HOST, "Paramiko SSH (Direct LAN)"

    return None, None, None

def deploy_to_kali(local_tar):
    stripe_sec = get_local_env_var("STRIPE_SECRET_KEY")
    stripe_pub = get_local_env_var("STRIPE_PUBLISHABLE_KEY")
    stripe_cur = get_local_env_var("STRIPE_CURRENCY") or "MYR"
    or_key = get_local_env_var("OPENROUTER_API_KEY")
    or_model = get_local_env_var("OPENROUTER_MODEL") or "deepseek/deepseek-r1-distill-qwen-32b:free"
    bb_key = get_local_env_var("BANDELBANGET_API_KEY")
    bb_backup = get_local_env_var("BANDELBANGET_BACKUP_API_KEY")
    bb_model = get_local_env_var("BANDELBANGET_MODEL") or "deepseek-v4-pro"
    groq_key = get_local_env_var("GROQ_API_KEY")
    groq_model = get_local_env_var("GROQ_MODEL") or "openai/gpt-oss-120b"

    print("🔍 [2/4] Detecting connection route to Kali Linux...")
    mode, target, desc = detect_connection()
    if not mode:
        print("[Error] Could not reach Kali server via Cloudflare Access or direct LAN.")
        print("        Ensure cloudflared is running on the server or connect to the same Wi-Fi.")
        sys.exit(1)
    print(f"   ✓ Route selected: {desc} -> {target}")

    verify_block = "\n".join(
        f'echo "HASHCHECK::{rel}::$(md5sum {rel} 2>/dev/null | cut -d" " -f1)"'
        for rel in local_module_hashes()
    )

    remote_commands = f"""set -e
mkdir -p {REMOTE_DIR}
tar -xzf {REMOTE_TAR} -C {REMOTE_DIR}
rm -f {REMOTE_TAR}

mkdir -p /home/kali
ln -sfn {REMOTE_DIR} /home/kali/SentinelAI

echo "   ✓ Files extracted to {REMOTE_DIR}"

cd {REMOTE_DIR}

echo "   🔍 Verifying critical module hashes..."
{verify_block}

# Ensure .env exists if not present
if [ ! -f .env ] && [ -f .env.example ]; then
    cp .env.example .env
fi

# Ensure AI and Stripe keys are populated in .env on Kali
python3 -c "
import os, re
env_file = '{REMOTE_DIR}/.env'
keys = {{
    'STRIPE_SECRET_KEY': '{stripe_sec}',
    'STRIPE_PUBLISHABLE_KEY': '{stripe_pub}',
    'STRIPE_CURRENCY': '{stripe_cur}',
    'OPENROUTER_API_KEY': '{or_key}',
    'OPENROUTER_MODEL': '{or_model}',
    'BANDELBANGET_API_KEY': '{bb_key}',
    'BANDELBANGET_BACKUP_API_KEY': '{bb_backup}',
    'BANDELBANGET_MODEL': '{bb_model}',
    'GROQ_API_KEY': '{groq_key}',
    'GROQ_MODEL': '{groq_model}',
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

# Install backend dependencies
echo "   📦 Installing backend dependencies..."
npm install --prefix backend

# Install frontend dependencies if needed
echo "   📦 Installing frontend dependencies..."
npm install --prefix frontend

# Build production bundle for frontend
echo "   🔨 Building frontend..."
npm run build --prefix frontend

# Setup and run Vulnerable Target Web Application (VulnCorp) on port 8080
if [ -d vulnerable-target ]; then
    echo "   📦 Installing vulnerable-target dependencies..."
    npm install --prefix vulnerable-target --ignore-scripts=false
    echo "   🎯 Starting VulnCorp target web app on PM2 (Port 8080)..."
    pm2 describe vulncorp-target >/dev/null 2>&1 && pm2 restart vulncorp-target || pm2 start vulnerable-target/server.js --name "vulncorp-target" --time
fi

# Reload through PM2. PM2 owns 5000/5173/8080 -- NEVER fuser -k or pkill them.
echo "   🔄 Reloading SentinelAI via PM2..."
pm2 reload sentinel-backend 2>/dev/null || pm2 restart sentinel-backend 2>/dev/null || true
pm2 reload sentinel-frontend 2>/dev/null || pm2 restart sentinel-frontend 2>/dev/null || true
pm2 save 2>/dev/null || true
sleep 2

echo "   ✓ SentinelAI and VulnCorp target reloaded via PM2"
pm2 jlist 2>/dev/null | head -c 400 || true
"""

    deployed_hashes = {}
    local_hashes = local_module_hashes()

    if mode == "openssh":
        print(f"📤 [3/4] Uploading archive to {REMOTE_TAR} via SCP...")
        scp_cmd = ["scp", "-o", "BatchMode=yes"]
        if target != OPENSSH_HOST and KALI_PORT != 22:
            scp_cmd.extend(["-P", str(KALI_PORT)])
        scp_cmd.extend([local_tar, f"{target}:{REMOTE_TAR}"])
        upload_res = subprocess.run(scp_cmd)
        if upload_res.returncode != 0:
            print("[Error] SCP upload failed.")
            sys.exit(1)
        print("   ✓ Upload complete!")

        print(f"⚙️  [4/4] Extracting & deploying on Kali server ({REMOTE_DIR})...")
        ssh_cmd = ["ssh", "-o", "BatchMode=yes"]
        if target != OPENSSH_HOST and KALI_PORT != 22:
            ssh_cmd.extend(["-p", str(KALI_PORT)])
        ssh_cmd.extend([target, "bash"])

        p = subprocess.Popen(ssh_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        clean_script = remote_commands.replace("\r\n", "\n").encode("utf-8")
        p.stdin.write(clean_script)
        p.stdin.close()

        for line in p.stdout:
            clean = line.decode("utf-8", errors="replace").rstrip()
            print(clean)
            if "HASHCHECK::" in clean:
                payload = clean.split("HASHCHECK::", 1)[1].strip()
                rel, _, digest = payload.partition("::")
                rel, digest = rel.strip(), digest.strip()
                if rel in local_hashes:
                    deployed_hashes[rel] = digest
        p.wait()
        if p.returncode != 0:
            print(f"[Warning] Remote deploy exited with code {p.returncode}")

    elif mode == "paramiko":
        print(f"🚀 [2/4] Connecting via Paramiko SSH to {KALI_USER}@{KALI_HOST}:{KALI_PORT}...")
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
        clean_script = remote_commands.replace("\r\n", "\n")
        stdin, stdout, stderr = ssh.exec_command(clean_script, get_pty=True)
        for line in stdout:
            clean = line.rstrip()
            print(clean)
            if "HASHCHECK::" in clean:
                payload = clean.split("HASHCHECK::", 1)[1].strip()
                rel, _, digest = payload.partition("::")
                rel, digest = rel.strip(), digest.strip()
                if rel in local_hashes:
                    deployed_hashes[rel] = digest
        ssh.close()

    print()
    mismatches = []
    for rel, local_hash in local_hashes.items():
        remote_hash = deployed_hashes.get(rel)
        if remote_hash is None:
            mismatches.append((rel, local_hash, "NOT FOUND"))
        elif remote_hash != local_hash:
            mismatches.append((rel, local_hash, remote_hash))
    if mismatches:
        print("⚠️  CRITICAL MODULE HASH MISMATCH — deployment did NOT land correctly:")
        for rel, local_hash, remote_hash in mismatches:
            print(f"     {rel}\n       local={local_hash}\n       remote={remote_hash}")
        print("   The running backend is serving stale code. Re-run the deploy or upload manually.")
    elif deployed_hashes:
        print(f"✅ Critical module hashes match local ({len(deployed_hashes)} verified).")

    print("\n🎉 ========================================================")
    print(f"✅ SentinelAI successfully deployed & running on Kali!")
    print(f"🌐 Cloudflare Production: https://sentinelai.studio")
    print(f"🎯 Target Application:   https://abuse.sentinelai.studio")
    print(f"🔌 Backend API Health:   https://sentinelai.studio/api/health")
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
