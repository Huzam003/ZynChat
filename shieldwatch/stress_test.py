import requests
import time
import random
import threading

BASE_URL = "http://localhost:3001"
COLLECTOR_URL = "http://localhost:3002"
USER_COUNT = 15
# The secret token from your environment
API_TOKEN = "sw-internal-token-xyz" 

def simulate_user(i):
    session = requests.Session()
    # Add ShieldWatch token to all outgoing requests and simulate Chrome UA
    session.headers.update({
        "x-shieldwatch-token": API_TOKEN,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    })
    username = f"tester_stress_{i}_{int(time.time())}"
    password = "password123"
    
    # 1. Register & Login
    try:
        # Submit fake fingerprint first to satisfy RASP gate
        session.post(f"{BASE_URL}/api/sw/fingerprint", json={
            "deviceId": f"stress-device-{i}-{int(time.time())}",
            "canvasHash": f"stress-canvas-{i}"
        })
        
        r1 = session.post(f"{BASE_URL}/api/register", json={"username": username, "password": password})
        r2 = session.post(f"{BASE_URL}/api/login", json={"username": username, "password": password})
        print(f"[User {i}] Registered (Status: {r1.status_code}) & Logged in (Status: {r2.status_code})")
    except Exception as e:
        print(f"[User {i}] Failed to connect: {e}")
        return

    # 2. Simulate legitimate traffic
    for _ in range(3):
        session.get(f"{BASE_URL}/chat")
        time.sleep(random.uniform(0.1, 0.5))

    # 3. Trigger some security events
    if i % 3 == 0:
        # SQL Injection attempt
        res = session.get(f"{BASE_URL}/api/messages?room=' OR 1=1 --")
        print(f"[User {i}] Simulated SQLi Attack | Status: {res.status_code} | Response: {res.text[:60]}")
    elif i % 3 == 1:
        # XSS attempt
        res = session.post(f"{BASE_URL}/api/messages", json={"roomId": 1, "content": "<script>alert(1)</script>"})
        print(f"[User {i}] Simulated XSS Attack | Status: {res.status_code} | Response: {res.text[:60]}")
    elif i % 3 == 2:
        # IDOR attempt
        res = session.get(f"{BASE_URL}/api/user/999")
        print(f"[User {i}] Simulated IDOR Attack | Status: {res.status_code} | Response: {res.text[:60]}")

if __name__ == "__main__":
    threads = []
    for i in range(USER_COUNT):
        t = threading.Thread(target=simulate_user, args=(i,))
        threads.append(t)
        t.start()
        time.sleep(0.2)
        
    for t in threads:
        t.join()
    
    print("\n[Test Complete] 15 Users Simulated. Check Dashboard.")
