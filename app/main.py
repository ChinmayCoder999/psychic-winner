import json
import os
import time
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import JSONResponse
import jwt as pyjwt

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