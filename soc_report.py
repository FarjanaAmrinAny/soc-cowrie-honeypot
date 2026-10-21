import json
from collections import Counter

log_file = "var/log/cowrie/cowrie.json"

events = []
with open(log_file) as f:
    for line in f:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue

event_counts = Counter(e.get("eventid", "unknown") for e in events)
source_ips = Counter(e.get("src_ip", "unknown") for e in events)
commands = Counter(
    e.get("input", "") for e in events
    if e.get("eventid") == "cowrie.command.input"
)

print("\n=== SOC DETECTION REPORT ===")
print("Total events:", len(events))

print("\nAuthentication:")
print("Login success:", event_counts["cowrie.login.success"])
print("Login failure:", event_counts["cowrie.login.failed"])

print("\nTop source IPs:")
for ip, count in source_ips.most_common(5):
    print(f"{ip}: {count} events")

print("\nCommands observed:")
for command, count in commands.most_common(10):
    print(f"{command}: {count}")
