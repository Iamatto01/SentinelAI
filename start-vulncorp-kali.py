import os
import paramiko
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

KALI_HOST = os.environ.get("KALI_HOST", "192.168.68.132")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(KALI_HOST, port=22, username='kali', password='kali')

cmd = """
cd /home/kali/server/SentinelAI/vulnerable-target
npm install
pm2 describe vulncorp-target >/dev/null 2>&1 && pm2 restart vulncorp-target || pm2 start server.js --name "vulncorp-target" --time
pm2 save
pm2 list
sleep 2
curl -s http://127.0.0.1:8080/api/products/search?q=Quantum
"""

stdin, stdout, stderr = ssh.exec_command(cmd, get_pty=True)
for line in stdout:
    print(line.rstrip())

ssh.close()
