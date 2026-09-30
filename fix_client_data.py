import sqlite3
import datetime

db = sqlite3.connect("/home/kali/server/database/fyp2.db")
cur = db.cursor()

client_user_id = "usr_cred_6c2651c9_ecd8_48f4_870d_9cf640a276a4"
project_id = "proj_fc8a35f2-8a17-4bbf-91e3-13c99e2a4dd4"
now = datetime.datetime.utcnow().isoformat() + "Z"

# 1. Update project client_id
cur.execute("UPDATE projects SET client_id = ? WHERE id = ?", (client_user_id, project_id))
print("Projects updated:", cur.rowcount)

# 2. Update scans belonging to MyCES FMS
cur.execute("UPDATE scans SET project_id = ?, client = 'MyCES', user_id = ? WHERE target LIKE '%myces%'", (project_id, client_user_id))
print("Scans updated for MyCES:", cur.rowcount)

# 3. Insert or update active subscription for the client
cur.execute("""
INSERT OR REPLACE INTO subscriptions (id, user_id, plan_id, plan_name, status, scan_quota_total, scan_quota_used, current_period_end, created_at, updated_at)
VALUES (?, ?, 'enterprise', 'Enterprise Client', 'active', 100, 23, '2099-12-31T23:59:59.000Z', ?, ?)
""", ("sub_myces_client", client_user_id, now, now))
print("Subscription updated for client:", cur.rowcount)

db.commit()
db.close()
print("All client data linked successfully!")