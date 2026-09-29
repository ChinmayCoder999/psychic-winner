import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "app.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY,
            owner TEXT NOT NULL,
            item TEXT NOT NULL,
            FOREIGN KEY(owner) REFERENCES users(username)
        )
    """)
    conn.commit()

    # Seed only if empty
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.execute("INSERT INTO users VALUES ('alice', 'alicepass', 'user')")
        cur.execute("INSERT INTO users VALUES ('admin', 'adminpass', 'admin')")
        conn.commit()
        print("Seeded users: alice (user), admin (admin)")

    cur.execute("SELECT COUNT(*) FROM orders")
    if cur.fetchone()[0] == 0:
        for i in range(1, 201):
            owner = "alice" if i % 2 == 1 else "admin"
            cur.execute("INSERT INTO orders (id, owner, item) VALUES (?, ?, ?)",
                        (i, owner, f"Order item #{i}"))
        conn.commit()
        print("Seeded 200 orders (alternating owner: alice / admin)")

    conn.close()

if __name__ == "__main__":
    init_db()