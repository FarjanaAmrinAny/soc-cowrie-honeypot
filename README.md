# SOC Analyst Lab: Cowrie Honeypot & Attack Detection Dashboard

## Project Overview
This project demonstrates a small Security Operations Center (SOC) lab using Cowrie SSH Honeypot, Python log analysis, CSV reporting, and a Streamlit dashboard.

## Objectives
- Collect and inspect SSH honeypot events.
- Extract event information into a CSV report.
- Summarize authentication activity and executed commands.
- Detect suspicious failed-login activity using basic Python rules.
- Visualize security events through a dashboard.

## Tools and Technologies
- Kali Linux
- Cowrie SSH Honeypot
- Python
- CSV and JSON log processing
- Streamlit

## Project Components
- `soc_report.py` — summarizes honeypot events.
- `detect_attacks.py` — performs basic failed-login detection.
- `dashboard.py` — displays event statistics and recent activity.
- `cowrie_report.csv` — exported event report.
- `export_log.py` and `export_logs.py` — log export utilities.

## Lab Results
The initial local test generated 14 events, including one successful login event. The observed source IP was `127.0.0.1`, which represents localhost testing rather than an external attacker.

## Limitations
- Testing has been performed locally.
- Detection rules are basic and require further validation.
- Failed-login thresholds are not yet evaluated using a rolling time window.
- No claim is made that the lab has detected real external attacks.

## Future Improvements
- Add time-window-based brute-force detection.
- Add severity levels and improved alerting.
- Test safely with authorized lab traffic.
- Improve dashboard filtering and reporting.

## Disclaimer
This project is for educational and defensive cybersecurity purposes. Do not expose the honeypot to the public internet without appropriate isolation, firewall rules, and monitoring.

