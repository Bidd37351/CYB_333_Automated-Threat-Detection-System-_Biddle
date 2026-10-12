
import base64
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Wazuh configuration
LOG_FILE = Path("/var/ossec/logs/alerts/alerts.json")
OUTPUT_FILE = Path(__file__).resolve().parent / "wazuh_detected_alerts.jsonl"

MIN_LEVEL = 7
NOTIFY_LEVEL = 10
CRITICAL_LEVEL = 12
COOLDOWN = 300
last_notified = {}


def analyze_alert(alert):
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    data = alert.get("data") or {}
    level = int(rule.get("level", 0))

    if level < MIN_LEVEL:
        return None

    severity = ("CRITICAL" if level >= CRITICAL_LEVEL
                else "HIGH" if level >= NOTIFY_LEVEL else "MEDIUM")

    return {
        "detected_at": datetime.now(timezone.utc).isoformat(),
        "event_timestamp": alert.get("timestamp", "Unknown"),
        "agent": agent.get("name", "Unknown"),
        "agent_id": agent.get("id", "Unknown"),
        "severity": severity,
        "level": level,
        "rule_id": str(rule.get("id", "Unknown")),
        "description": rule.get("description", "No description"),
        "source_ip": data.get("srcip") or data.get("src_ip") or "N/A",
        "rule_groups": rule.get("groups", [])
    }


def notify(alert):
    title = f"Wazuh {alert['severity']} Security Alert"
    message = f"Agent: {alert['agent']}\nRule: {alert['rule_id']}\n{alert['description']}"

    def quote(text):
        return "'" + text.replace("'", "''") + "'"

    script = f"""
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$n = New-Object System.Windows.Forms.NotifyIcon
$n.Icon = [System.Drawing.SystemIcons]::Warning
$n.Visible = $true
$n.BalloonTipTitle = {quote(title[:63])}
$n.BalloonTipText = {quote(message[:240])}
$n.BalloonTipIcon = "Warning"
$n.ShowBalloonTip(10000)
Start-Sleep -Seconds 12
$n.Dispose()
"""
    encoded = base64.b64encode(script.encode("utf-16le")).decode()

    try:
        subprocess.Popen(
            ["powershell.exe", "-NoProfile", "-NonInteractive",
             "-EncodedCommand", encoded],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )
        print("Windows notification requested.")
    except OSError as error:
        print(f"Notification unavailable: {error}")


def process_alert(alert):
    try:
        result = analyze_alert(alert)
    except (ValueError, TypeError):
        return

    if not result:
        return

    print(f"\n[{result['severity']}] WAZUH SECURITY ALERT")
    print(f"Agent: {result['agent']} | Level: {result['level']}")
    print(f"Rule: {result['rule_id']} | {result['description']}")

    with OUTPUT_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(result) + "\n")

    if result["level"] < NOTIFY_LEVEL:
        return

    key = (result["agent_id"], result["rule_id"])
    now = time.monotonic()

    if now - last_notified.get(key, -float("inf")) >= COOLDOWN:
        notify(result)
        last_notified[key] = now
    else:
        print("Repeated notification suppressed.")


def monitor():
    print(f"Automated Wazuh Threat Detection Started\nMonitoring: {LOG_FILE}")
    print(f"Notification threshold: {NOTIFY_LEVEL}\nPress Ctrl+C to stop.")

    with LOG_FILE.open("r", encoding="utf-8") as file:
        file.seek(0, 2)

        while True:
            line = file.readline()
            if not line:
                time.sleep(1)
                continue

            try:
                process_alert(json.loads(line))
            except json.JSONDecodeError:
                print("Invalid JSON skipped.")
            except OSError as error:
                print(f"Report error: {error}")


def test():
    process_alert({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent": {"id": "001", "name": "Windows-CamsDevice"},
        "rule": {
            "id": "TEST-100001",
            "level": 12,
            "description": "TEST ONLY: Simulated security event"
        },
        "data": {"srcip": "203.0.113.25"}
    })
    print("Notification test completed.")


if __name__ == "__main__":
    try:
        test() if "--test" in sys.argv else monitor()
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")
    except (PermissionError, FileNotFoundError) as error:
        print(f"Cannot access Wazuh log: {error}")

