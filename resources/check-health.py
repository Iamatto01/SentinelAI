import json, sys, urllib.request
d = json.load(urllib.request.urlopen("http://192.168.68.132:8888/health"))
print("TOTAL:", d["total_tools_available"], "/", d["total_tools_count"])
for k, v in sorted(d["category_stats"].items()):
    print(f"{k:15} {v['available']}/{v['total']}")
missing = [t for t, a in d["tools_status"].items() if not a]
print("MISSING:", missing)
