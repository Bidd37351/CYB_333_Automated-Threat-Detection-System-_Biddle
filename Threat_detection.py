
import json
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "security_logs.txt"
ALERT_FILE = BASE_DIR / "alerts.json"

THRESHOLD = 3
WINDOW_SECONDS = 60


def detect_threats():
    attempts = defaultdict(deque)
    seen_events = set()

    print("Automated Threat Detection System started.")
    print(f"Monitoring: {LOG_FILE}")

    while True:
        if not LOG_FILE.exists():
            print("Waiting for the security log file...")
            time.sleep(5)
            continue

        with LOG_FILE.open("r", encoding="utf-8") as log:
            for line in log:
                line = line.strip()

                if not line or line in seen_events:
                    continue

                seen_events.add(line)

                if "LOGIN_FAILED" not in line:
                    continue

                fields = dict(
                    item.split("=", 1)
                    for item in line.split()
                    if "=" in item
                )

                source_ip = fields.get("ip", "unknown")
                now = datetime.now()
                recent = attempts[source_ip]

                recent.append(now)

                while recent and now - recent[0] > timedelta(
                    seconds=WINDOW_SECONDS
                ):
                    recent.popleft()

                if len(recent) == THRESHOLD:
                    alert = {
                        "timestamp": now.isoformat(),
                        "severity": "HIGH",
                        "type": "REPEATED_FAILED_LOGINS",
                        "source_ip": source_ip,
                        "attempts": len(recent),
                        "message": (
                            f"Potential brute-force activity "
                            f"from {source_ip}"
                        )
                    }

                    print("\nSECURITY ALERT")
                    print(json.dumps(alert, indent=4))

                    existing = []
                    if ALERT_FILE.exists():
                        try:
                            existing = json.loads(
                                ALERT_FILE.read_text(encoding="utf-8")
                            )
                        except (json.JSONDecodeError, OSError):
                            existing = []

                    existing.append(alert)
                    ALERT_FILE.write_text(
                        json.dumps(existing, indent=4),
                        encoding="utf-8"
                    )

        time.sleep(2)


if __name__ == "__main__":
    try:
        detect_threats()
    except KeyboardInterrupt:
        print("\nThreat detection stopped.")