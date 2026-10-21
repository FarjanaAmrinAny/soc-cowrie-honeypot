
import json
import os
import pandas as pd
import streamlit as st

LOG_FILE = "var/log/webhoneypot/events.jsonl"

st.title("Web Honeypot Events")

if not os.path.exists(LOG_FILE):
    st.warning("No web honeypot log found. Visit the local test page first.")
else:
    events = []

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    if not events:
        st.info("No web events recorded yet.")
    else:
        df = pd.DataFrame(events)

        c1, c2 = st.columns(2)
        c1.metric("Total Web Events", len(df))
        c2.metric(
            "Login Attempts",
            int((df["event"] == "login_attempt").sum())
        )

        st.subheader("Event Types")
        st.bar_chart(df["event"].value_counts())

        st.subheader("Source IP Activity")
        st.bar_chart(df["source_ip"].fillna("Unknown").value_counts())

        st.subheader("Recent Web Events")
        cols = [
            c for c in [
                "timestamp", "event", "source_ip",
                "method", "path", "username"
            ] if c in df.columns
        ]
        st.dataframe(df[cols].tail(20), width="stretch")

        st.info(
            "127.0.0.1 represents localhost testing, "
            "not an external attacker."
        )
