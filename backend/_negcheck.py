import sys
import audit_layout

bad = r"F:\FYP2PROJECT\backend\_neg_bad.pdf"
good = r"F:\FYP2PROJECT\backend\_neg_good.pdf"

eb, _ = audit_layout.audit(bad)
hb = audit_layout.hidden_content(bad)
eg, _ = audit_layout.audit(good)
hg = audit_layout.hidden_content(good)

print(f"BAD  card overflows={len(eb)} buried={len(hb)}")
print(f"GOOD card overflows={len(eg)} buried={len(hg)}")

ok = (len(eb) > 0 and len(hb) > 0 and len(eg) == 0 and len(hg) == 0)
print("NEGATIVE CONTROL:", "PASS (gate fires on defect, silent on clean)" if ok else "FAIL")
sys.exit(0 if ok else 1)
