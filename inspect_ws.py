import sqlite3

conn = sqlite3.connect(r'C:\Users\muham\AppData\Roaming\Antigravity IDE\User\workspaceStorage\45c29866d3dcafb864b85fa926854306\state.vscdb')
c = conn.cursor()
c.execute("SELECT key, value FROM ItemTable")
rows = c.fetchall()
for r in rows:
    val_snip = str(r[1])[:150].replace('\n', ' ')
    print(f"{r[0]} -> {val_snip}")
