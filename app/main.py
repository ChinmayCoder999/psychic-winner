import json
import os
import time
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import JSONResponse
import jwt as pyjwt

from fastapi.responses import HTMLResponse
from database import init_db, get_connection
from auth import authenticate, create_token, decode_token, SECRET_KEY, ALGORITHM

app = FastAPI(title="AccessGuard Vulnerable App")

LOG_PATH = os.path.join(os.path.dirname(__file__), "..", "logs", "audit.log")
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

@app.on_event("startup")
def startup():
    init_db()

def write_audit_log(request: Request, user: str, role: str, status: int, extra: dict = None):
    entry = {
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "ip": request.client.host,
        "user": user,
        "role": role,
        "method": request.method,
        "path": request.url.path,
        "status": status,
    }
    if extra:
        entry.update(extra)
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")

def get_current_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = authorization.split(" ", 1)[1]
    try:
        payload = decode_token(token)
        return payload  # contains sub (username) and role
    except pyjwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/login")
def login(request: Request, username: str, password: str):
    row = authenticate(username, password)
    if not row:
        write_audit_log(request, username, "unknown", 401)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(row["username"], row["role"])
    write_audit_log(request, row["username"], row["role"], 200)
    return {"token": token, "role": row["role"]}

# FLAW: no ownership check — any authenticated user can read ANY order (IDOR)
@app.get("/api/orders/{order_id}")
def get_order(order_id: int, request: Request, user=None, authorization: str = Header(None)):
    current = get_current_user(authorization)
    conn = get_connection()
    row = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    conn.close()
    if not row:
        write_audit_log(request, current["sub"], current["role"], 404, {"order_id": order_id})
        raise HTTPException(status_code=404, detail="Order not found")

    # Note: we deliberately do NOT check row["owner"] == current["sub"] here.
    if row["owner"] != current["sub"]:
        write_audit_log(
            request, current["sub"], current["role"], 403,
            {"order_id": order_id, "order_owner": row["owner"], "requester": current["sub"],
             "note": "ownership_check_blocked"}
        )
        raise HTTPException(status_code=403, detail="Forbidden: not your order")

    write_audit_log(
        request, current["sub"], current["role"], 200,
        {"order_id": order_id, "order_owner": row["owner"], "requester": current["sub"]}
    )
    return {"id": row["id"], "owner": row["owner"], "item": row["item"]}

# FLAW: only checks that the user is logged in, not that they are admin
@app.get("/admin/users")
def list_users(request: Request, authorization: str = Header(None)):
    current = get_current_user(authorization)
    conn = get_connection()
    rows = conn.execute("SELECT username, role FROM users").fetchall()
    conn.close()

    if current["role"] != "admin":
        write_audit_log(
            request, current["sub"], current["role"], 403,
            {"note": "role_check_blocked"}
        )
        raise HTTPException(status_code=403, detail="Forbidden: admin only")

    write_audit_log(
        request, current["sub"], current["role"], 200,
        {"note": "authorized_admin_access"}
    )
    return {"users": [dict(r) for r in rows]}

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    rows = []
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

    def row_html(r):
        status = r.get("status")
        color = "#c0392b" if status == 403 else "#27ae60" if status == 200 else "#7f8c8d"
        note = r.get("note") or r.get("order_owner", "")
        return (f"<tr><td>{r.get('time')}</td><td>{r.get('user')}</td>"
                f"<td>{r.get('role')}</td><td>{r.get('method')}</td>"
                f"<td>{r.get('path')}</td>"
                f"<td style='color:{color};font-weight:bold'>{status}</td>"
                f"<td>{note}</td></tr>")

    rows_html = "".join(row_html(r) for r in reversed(rows[-50:]))

    return f"""
    <h2>AccessGuard - Live Audit Dashboard</h2>
    <p>Showing the most recent 50 requests. Refresh to see new activity.</p>
    <table border="1" cellpadding="6" style="border-collapse:collapse;font-family:Arial;font-size:14px">
        <tr style="background:#1F4E78;color:white">
            <th>Time</th><th>User</th><th>Role</th><th>Method</th>
            <th>Path</th><th>Status</th><th>Note</th>
        </tr>
        {rows_html}
    </table>
    """