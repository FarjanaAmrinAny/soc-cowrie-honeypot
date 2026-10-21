import json
from collections import Counter, defaultdict
from datetime import datetime, timezone

LOG_FILE = "var/log/cowrie/cowrie.json"

events = []

with open(LOG_FILE, encoding="utf-8") as f:
    for line in f:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue

failed = [
    e for e in events
    if e.get("eventid") == "cowrie.login.failed"
]

success = [
    e for e in events
    if e.get("eventid") == "cowrie.login.success"
]

by_ip = Counter(e.get("src_ip", "unknown") for e in failed)

print("\n=== SSH AUTHENTICATION DETECTION REPORT ===")
print("Total events:", len(events))
print("Failed login events:", len(failed))
print("Successful login events:", len(success))

print("\n=== ALERTS ===")

alerts = 0

for ip, count in by_ip.items():
    if count >= 5:
        alerts += 1
        severity = "HIGH"
    elif count >= 3:
        alerts += 1
        severity = "MEDIUM"
    else:
        continue

    print(f"[{severity}] {ip}: {count} failed login attempts")

if alerts == 0:
    print("No threshold-based alerts detected.")

print("\nNote: localhost activity is lab testing, not an external attack.")
