import requests

BASE_URL = "http://127.0.0.1:8000"

login = requests.post(f"{BASE_URL}/login", params={"username": "alice", "password": "alicepass"})
token = login.json()["token"]
headers = {"Authorization": f"Bearer {token}"}

# Alice owns odd-numbered orders based on the seed script
own_order_ids = [1, 3, 5, 7, 9, 11]

for oid in own_order_ids:
    r = requests.get(f"{BASE_URL}/api/orders/{oid}", headers=headers)
    print(oid, r.status_code)