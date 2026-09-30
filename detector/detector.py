from incidents_db import init_incidents_db, record_incident
import sys
import json
from datetime import datetime
from collections import defaultdict, deque

FOREIGN_THRESHOLD = 10   # foreign-order reads...
WINDOW = 60              # ...within this many seconds -> IDOR alert
ADMIN_PREFIX = "/admin"  # any non-admin request here -> access-control alert

def parse_time(t):
    return datetime.strptime(t, "%Y-%m-%dT%H:%M:%SZ")

def main():
    if len(sys.argv) < 2:
        print("Usage: python detector.py <audit.log>")
        sys.exit(1)

    log_path = sys.argv[1]
    print("config:", FOREIGN_THRESHOLD, WINDOW, ADMIN_PREFIX)
    init_incidents_db()

    foreign_reads = defaultdict(deque)
    alert_count = 0

    with open(log_path) as f:
        for line_num, raw in enumerate(f, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                print(f"Skipping invalid JSON on line {line_num}")
                continue

            user = entry.get("user")
            role = entry.get("role")
            path = entry.get("path", "")
            ip = entry.get("ip")
            ts = entry.get("time")
            if not ts:
                continue
            try:
                t = parse_time(ts)
            except ValueError:
                continue

            # Rule 2: non-admin hitting an admin path
            if role != "admin" and path.startswith(ADMIN_PREFIX):
                alert_count += 1
                msg = f"user={user} role={role} requested {path} at {ts}"
                print(f"[ALERT] access_control_violation: {msg}")
                record_incident(ts, "access_control_violation", "High", ip, user, msg, "logged_only")

            # Rule 1: foreign-order reads within WINDOW seconds
            order_owner = entry.get("order_owner")
            if order_owner and user and order_owner != user:
                dq = foreign_reads[user]
                dq.append(t)
                while dq and (t - dq[0]).total_seconds() > WINDOW:
                    dq.popleft()
                if len(dq) == FOREIGN_THRESHOLD:
                    alert_count += 1
                    msg = (f"user={user} hit {len(dq)} foreign-order reads within "
                           f"{WINDOW}s, triggering order_id={entry.get('order_id')} "
                           f"(owner={order_owner}) at {ts}")
                    print(f"[ALERT] idor_foreign_order_threshold: {msg}")
                    record_incident(ts, "idor_foreign_order_threshold", "Medium", ip, user, msg, "logged_only")

    if alert_count == 0:
        print("No findings.")

if __name__ == "__main__":
    main()