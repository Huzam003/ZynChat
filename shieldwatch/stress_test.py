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
    # Add ShieldWatch token to all outgoing requests
    session.headers.update({"x-shieldwatch-token": API_TOKEN})
    username = f"tester_{i}"
    password = "password123"
    
    # 1. Register & Login
    try:
        session.post(f"{BASE_URL}/api/register", json={"username": username, "password": password})
        session.post(f"{BASE_URL}/api/login", json={"username": username, "password": password})
        print(f"[User {i}] Registered & Logged in")
    except: return

    # 2. Simulate legitimate traffic
    for _ in range(3):
        session.get(f"{BASE_URL}/chat")
        time.sleep(random.uniform(0.5, 1.5))

    # 3. Trigger some security events
    if i % 3 == 0:
        # SQL Injection attempt
        session.get(f"{BASE_URL}/api/messages?room=' OR 1=1 --")
        print(f"[User {i}] Simulated SQLi Attack")
    elif i % 3 == 1:
        # XSS attempt
        session.post(f"{BASE_URL}/api/messages", json={"roomId": 1, "content": "<script>alert(1)</script>"})
        print(f"[User {i}] Simulated XSS Attack")
    elif i % 3 == 2:
        # IDOR attempt
        session.get(f"{BASE_URL}/api/user/999")
        print(f"[User {i}] Simulated IDOR Attack")

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
