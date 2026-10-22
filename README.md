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
<img width="1910" height="824" alt="1" src="https://github.com/user-attachments/assets/ee8d274b-7253-469e-a9c0-62328be29b49" />
<img width="1900" height="540" alt="2" src="https://github.com/user-attachments/assets/168f43d2-33b9-48c4-921f-da0ea0733af4" />
<img width="1913" height="474" alt="3" src="https://github.com/user-attachments/assets/c2076e88-968a-4aa7-8f12-0aed24432828" />
<img width="1920" height="967" alt="4" src="https://github.com/user-attachments/assets/ea3f5b1a-3772-4390-aea8-9f11d8839d71" />
<img width="1918" height="988" alt="5" src="https://github.com/user-attachments/assets/9e971064-5f6f-4bf8-a30f-3bbd6355e973" />
<img width="958" height="468" alt="6" src="https://github.com/user-attachments/assets/2518b5fa-6c7a-44aa-b40a-eb8394ca5d7b" />





