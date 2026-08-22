import paramiko
import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("192.168.68.132", username="kali", password="kali", timeout=10)

cmd = """
echo "=== Searching for 'This bot is private' on server ==="
grep -rn "This bot is private" /home/kali/ 2>/dev/null | head -n 30

echo "=== Checking running Node processes on server ==="
ps aux | grep -E "node|pm2|discord" | grep -v grep

echo "=== Checking PM2 list on server ==="
pm2 list 2>/dev/null || echo "No PM2"
"""

stdin, stdout, stderr = ssh.exec_command(cmd)
print(stdout.read().decode("utf-8", errors="replace"))
ssh.close()
