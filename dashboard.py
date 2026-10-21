import json
import pandas as pd
import streamlit as st

st.set_page_config(page_title="Mini SOC Dashboard", layout="wide")

LOG_FILE = "var/log/cowrie/cowrie.json"

events = []

with open(LOG_FILE, encoding="utf-8") as f:
    for line in f:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue

df = pd.DataFrame(events)

st.title("Mini SOC Dashboard")
st.caption("Cowrie SSH Honeypot - Local Lab")

if df.empty:
    st.warning("No events found.")
    st.stop()

event_ids = df.get("eventid", pd.Series(dtype=str))

c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Events", len(df))
c2.metric("Login Success", int((event_ids == "cowrie.login.success").sum()))
c3.metric("Login Failure", int((event_ids == "cowrie.login.failed").sum()))
c4.metric("Command Events", int((event_ids == "cowrie.command.input").sum()))

st.subheader("Event Types")
st.bar_chart(event_ids.value_counts())

st.subheader("Source IP Activity")
if "src_ip" in df.columns:
    st.bar_chart(df["src_ip"].fillna("Unknown").value_counts())

st.subheader("Commands Observed")
if "input" in df.columns:
    commands = df.loc[event_ids == "cowrie.command.input", "input"].dropna()
    if not commands.empty:
        st.bar_chart(commands.value_counts())
    else:
        st.info("No command events found.")

st.subheader("SSH Detection Alerts")

failed = df.loc[event_ids == "cowrie.login.failed"].copy()

if failed.empty:
    st.success("No failed-login events found in current lab data.")
else:
    counts = failed.groupby("src_ip").size()
    for ip, count in counts.items():
        if count >= 5:
            severity = "HIGH"
        elif count >= 3:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        st.write(f"{severity} ALERT - {ip}: {count} failed logins")

st.subheader("Recent Events")
columns = [
    col for col in
    ["timestamp", "eventid", "src_ip", "username", "input", "session"]
    if col in df.columns
]
st.dataframe(df[columns].tail(20), width="stretch")

st.info("127.0.0.1 is localhost test activity, not an external attacker.")
