import jwt
import time
from database import get_connection

SECRET_KEY = "dev-secret-change-me"
ALGORITHM = "HS256"

def authenticate(username: str, password: str):
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password)
    ).fetchone()
    conn.close()
    return row

def create_token(username: str, role: str):
    payload = {
        "sub": username,
        "role": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str):
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])