import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "incidents.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_incidents_db():
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
            time_detected TEXT NOT NULL,
            rule TEXT NOT NULL,
            severity TEXT NOT NULL,
            ip TEXT,
            user TEXT,
            details TEXT,
            action_taken TEXT,
            time_responded TEXT
        )
    """)
    conn.commit()
    conn.close()

def record_incident(time_detected, rule, severity, ip, user, details, action_taken):
    conn = get_connection()
    conn.execute(
        """INSERT INTO incidents (time_detected, rule, severity, ip, user, details, action_taken, time_responded)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (time_detected, rule, severity, ip, user, details, action_taken, time_detected)
    )
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_incidents_db()
    print(f"Incidents database ready at {DB_PATH}")