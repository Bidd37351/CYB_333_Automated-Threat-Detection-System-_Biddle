# CYB_333_Automated-Threat-Detection-System-_Biddle
# Automated Threat Detection System

## Project Overview

For this project, I had to use **Python, Wazuh SIEM, and Visual Studio Code** to automate security monitoring and threat detection. It collects Windows security events through the Wazuh Agent, analyzes alerts using Wazuh detection rules, and generates notifications for high-severity security events.

## Objectives and Features

- Monitor Windows security events using Wazuh SIEM.
- Detect potentially suspicious activity through automated log analysis.
- Classify alerts by severity level.
- Generate Windows desktop notifications for high-severity alerts.
- Save detected events to JSON reports.
- Reduce repeated notifications using a five-minute cooldown.

## Technologies and Dependencies

- Python 3 
- Wazuh SIEM Manager and Windows Agent
- Ubuntu/Windows Subsystem for Linux (WSL)
- Windows 11 and PowerShell
- Visual Studio Code with Python and WSL extensions

## Project Files

```text
Threat Detection System/
├── Threat_detection.py
├── wazuh_alert_monitor.py
├── security_logs.txt
├── alerts.json
├── security_alerts.json
├── wazuh_detected_alerts.jsonl
└── README.md
```

`Threat_detection.py` analyzes simulated security logs, while `wazuh_alert_monitor.py` monitors actual Wazuh alerts.

## Setup and Installation

1. Install and configure Wazuh SIEM in WSL
2. Install and register the Windows Wazuh Agent.
3. Connect VS Code to Ubuntu using the WSL extension.
4. Open the project folder in VS Code.
5. Verify that the Wazuh Manager and Agent are running.

**Verify the Wazuh Manager:**

```bash
sudo systemctl is-active wazuh-manager
```

**Verify the Windows Agent:**

```bash
sudo /var/ossec/bin/agent_control -l
```

**Verify the alert file:**

```bash
sudo ls -lh /var/ossec/logs/alerts/alerts.json
```

## Running the System

Start automated monitoring in the VS Code Ubuntu terminal:

```bash
sudo python3 wazuh_alert_monitor.py
```

Test the notification system without generating a real security incident:

```bash
python3 wazuh_alert_monitor.py --test
```

Press `Ctrl + C` to stop monitoring.

## Alert Severity Levels

| Level | Action |
|---|---|
| 0–6 | Ignored by Python |
| 7–9 | Displayed and saved |
| 10–11 | High-severity notification requested |
| 12–15 | Critical notification requested |

Detected events are saved to `wazuh_detected_alerts.jsonl`.

## Limitations and Future Improvements

The current system requires the Python monitor to remain running. It does not yet handle log rotation or automatically restart after a shutdown. WSL permissions and Windows notification settings may affect desktop notifications.

The Future improvements I would include email notifications, automated startup, a real-time security dashboard, and enhanced failed-login detection.

## Conclusion

This project demonstrates practical cybersecurity automation by integrating Python with Wazuh SIEM. It provides continuous security alert monitoring, severity-based detection, JSON reporting, and high-severity notification functionality to support security analysis and incident investigation.
