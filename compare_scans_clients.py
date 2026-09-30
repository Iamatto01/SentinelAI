import sqlite3
import os

dbs = [
    ("/mnt/external_hdd/SentinelAI_Data/fyp2.db", "Current Active DB"),
    ("/mnt/external_hdd/server/database/fyp2_20260817_092535.db", "Historical Archive 2026-08-17"),
]

for p, desc in dbs:
    print(f"\n=======================================================")
    print(f"DATABASE: {p} ({desc})")
    print(f"=======================================================")
    if not os.path.exists(p):
        print("Not found!")
        continue
    conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
    cur = conn.cursor()
    
    # 1. Check projects / clients
    try:
        cur.execute("SELECT id, name, client, target FROM projects LIMIT 10")
        projs = cur.fetchall()
        print(f"Projects count: {len(projs)}")
        for pr in projs:
            print(f"  Project: {pr}")
    except Exception as e:
        print(f"  Projects query error: {e}")

    # 2. Check client_credentials
    try:
        cur.execute("SELECT id, project_id, email, note FROM client_credentials LIMIT 10")
        creds = cur.fetchall()
        print(f"Client Credentials count: {len(creds)}")
        for cr in creds:
            print(f"  Client Credential: {cr}")
    except Exception as e:
        print(f"  Client Credentials query error: {e}")

    # 3. Check scans
    try:
        cur.execute("SELECT count(*) FROM scans")
        scan_cnt = cur.fetchone()[0]
        cur.execute("SELECT id, target, mode, status, created_at FROM scans ORDER BY created_at DESC LIMIT 10")
        scans = cur.fetchall()
        print(f"Scans total count: {scan_cnt}")
        for sc in scans:
            print(f"  Scan: {sc[0][:12]}.. | Target: {sc[1]:<25} | Mode: {sc[2]:<10} | Status: {sc[3]:<10} | Date: {sc[4]}")
    except Exception as e:
        print(f"  Scans query error: {e}")

    # 4. Check findings
    try:
        cur.execute("SELECT count(*) FROM findings")
        find_cnt = cur.fetchone()[0]
        print(f"Findings total count: {find_cnt}")
    except Exception as e:
        print(f"  Findings query error: {e}")

    # 5. Check users
    try:
        cur.execute("SELECT id, username, email, role FROM users")
        users = cur.fetchall()
        print(f"Users count: {len(users)}")
        for u in users:
            print(f"  User: {u}")
    except Exception as e:
        print(f"  Users query error: {e}")

    conn.close()