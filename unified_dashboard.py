
import json
from pathlib import Path

import pandas as pd
import streamlit as st

st.set_page_config(page_title="SOC Honeypot Dashboard", layout="wide")
st.title("SOC Honeypot + Attack Visualization")
st.caption("Cowrie SSH + Flask Web Honeypot")

SSH_LOG = Path("var/log/cowrie/cowrie.json")
WEB_LOG = Path("var/log/webhoneypot/events.jsonl")


def read_json_lines(path):
    rows = []
    if not path.exists():
        return rows

    with path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    rows.append(item)
            except json.JSONDecodeError:
                continue
    return rows


events = []

for item in read_json_lines(SSH_LOG):
    event_id = item.get("eventid", "")
    events.append({
        "timestamp": item.get("timestamp"),
        "source": "SSH",
        "event": event_id or "ssh_event",
        "source_ip": item.get("src_ip", "Unknown"),
        "username": item.get("username", ""),
        "activity": item.get("input", ""),
        "path": "",
        "session": item.get("session", ""),
    })

for item in read_json_lines(WEB_LOG):
    events.append({
        "timestamp": item.get("timestamp"),
        "source": "Web",
        "event": item.get("event", "web_event"),
        "source_ip": item.get("source_ip", "Unknown"),
        "username": item.get("username", ""),
        "activity": item.get("method", ""),
        "path": item.get("path", ""),
        "session": "",
    })

columns = [
    "timestamp", "source", "event", "source_ip",
    "username", "activity", "path", "session"
]
df = pd.DataFrame(events, columns=columns)

if df.empty:
    st.warning("No events found. Check the SSH and Web log paths.")
    st.stop()

df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
df["source_ip"] = df["source_ip"].fillna("Unknown").astype(str)
df["event"] = df["event"].fillna("unknown").astype(str)
df = df.dropna(subset=["timestamp"]).sort_values("timestamp")

ssh_failed = df[
    (df["source"] == "SSH") &
    (df["event"] == "cowrie.login.failed")
]
ssh_success = df[
    (df["source"] == "SSH") &
    (df["event"] == "cowrie.login.success")
]
web_attempts = df[
    (df["source"] == "Web") &
    (df["event"] == "login_attempt")
]

a, b, c, d = st.columns(4)
a.metric("All Events", len(df))
b.metric("SSH Failed Logins", len(ssh_failed))
c.metric("SSH Successful Logins", len(ssh_success))
d.metric("Web Login Attempts", len(web_attempts))

st.subheader("Events by Source")
st.bar_chart(df["source"].value_counts())

st.subheader("Event Types")
st.bar_chart(df.groupby(["event", "source"]).size().unstack(fill_value=0))

st.subheader("Source IP Activity")
st.bar_chart(df["source_ip"].value_counts().head(15))

st.subheader("Detection Rules — 5-minute window")
st.caption(
    "Alert threshold: 5 or more failed SSH logins or web login attempts "
    "from one IP within five minutes. An alert indicates suspicious activity, "
    "not confirmed malicious intent."
)

attempts = pd.concat([
    ssh_failed[["timestamp", "source_ip"]].assign(kind="SSH failed login"),
    web_attempts[["timestamp", "source_ip"]].assign(kind="Web login attempt"),
], ignore_index=True)

alerts = []
for (ip, kind), group in attempts.groupby(["source_ip", "kind"]):
    group = group.sort_values("timestamp").reset_index(drop=True)
    left = 0
    for right in range(len(group)):
        while (
            group.loc[right, "timestamp"] -
            group.loc[left, "timestamp"] > pd.Timedelta(minutes=5)
        ):
            left += 1
        count = right - left + 1
        if count >= 5:
            alerts.append({
                "source_ip": ip,
                "rule": kind,
                "attempts_in_5m": count,
                "window_end_utc": group.loc[right, "timestamp"],
            })
            break

if alerts:
    st.warning("Suspicious repeated attempts detected")
    st.dataframe(pd.DataFrame(alerts), width="stretch")
else:
    st.success("No repeated-attempt threshold reached in current logs.")

st.subheader("Recent Events")
st.dataframe(
    df.sort_values("timestamp", ascending=False).head(100),
    width="stretch",
)

if (df["source_ip"] == "127.0.0.1").any():
    st.info(
        "127.0.0.1 is localhost test activity, not an external attacker."
    )
