import requests
import json
import time
import concurrent.futures

import os

BASE_URL = os.getenv("TARGET_URL", "https://zynchat.onrender.com")    # RASP Direct
NGINX_URL = os.getenv("NGINX_URL", "https://zynchat.onrender.com")   # Network Gateway
COLLECTOR_URL = os.getenv("COLLECTOR_URL", "http://localhost:3002")

def print_result(attack_name, response, layer="App"):
    print(f"\n[+] Testing {attack_name} [Shield ({layer})]...")
    print(f"    Status Code: {response.status_code}")
    try:
        data = response.json()
        # print(f"    Response: {json.dumps(data, indent=4)}")
        
        # Success for Shield = Blocked (403/429) OR Decoy (Honeypot)
        if data.get('blocked') or response.status_code in [403, 429] or "CONFI" in str(data):
            print(f"    RESULT: ✅ {layer.upper()} SHIELD DETECTED/BLOCKED THE ATTACK")
        elif data.get('ok') == True:
             print(f"    RESULT: ⚠️ ATTACK SUCCESSFUL (PROTECTION FAILED OR LOGGED ONLY)")
    except:
        print(f"    Response Body: {response.text[:100]}...")

def run_attacks():
    session = requests.Session()
    session.headers.update({
        "x-fp-id": "python-test-device-123",
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1"
    })
    
    print("--- Starting Full-Stack Security Attack Simulation ---")

    # ─── 1. NGINX NETWORK SHIELD TESTS ───────────────────────────────────────────
    try:
        # A. Bot Scraper Detection (User-Agent based)
        print_result("Network: Malicious Bot Scraper", requests.get(NGINX_URL, headers={
            "User-Agent": "sqlmap/1.8.5#stable (http://sqlmap.org)"
        }), layer="Network")

        # B. Rate Limit / DDoS Flood Detection
        print("\n[+] Testing Network: Rate Limit / DDoS Flood (100 requests)...")
        def send_req():
            return requests.get(f"{NGINX_URL}/ping")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(send_req) for _ in range(100)]
            results = [f.result().status_code for f in futures]
            if 429 in results or 503 in results:
                print(f"    Status Codes: {results[:10]}... (429/503 detected!)")
                print(f"    RESULT: ✅ NETWORK SHIELD RATE-LIMITED THE FLOOD")
            elif 403 in results:
                print(f"    Status Codes: {results[:10]}... (403 Blocked detected!)")
                print(f"    RESULT: ✅ IP PERMANENTLY BANNED/BLOCKED BY SHIELDWATCH")
            elif any(code == 200 for code in results):
                print(f"    Status Codes: {results[:10]}...")
                print(f"    RESULT: ⚠️ RATE LIMIT FAILED (Requests allowed through with 200 OK)")
            else:
                print(f"    Status Codes: {results[:10]}...")
                print(f"    RESULT: ⚠️ RATE LIMIT TEST RETURNED UNEXPECTED CODES: {set(results)}")
    except requests.exceptions.ConnectionError:
        print(f"\n[!] Skipping Network tests: Nginx is not reachable at {NGINX_URL}")

    # ─── 2. SHIELDWATCH APP SHIELD (RASP) TESTS ───────────────────────────────────
    
    try:
        # 0. Submit Fingerprint (to bypass bot protection)
        print("\n[!] Submitting security fingerprint...")
        session.post(f"{BASE_URL}/api/sw/fingerprint", json={
            "deviceId": "python-test-device-123",
            "canvasHash": "fake-hash-789"
        })

        # A. SQL Injection (Login Bypass)
        print_result("App: SQL Injection", session.post(f"{BASE_URL}/api/login", json={
            "username": "admin'--",
            "password": "any"
        }))

        # Authenticate for subsequent attacks
        test_user = f"tester_{int(time.time())}"
        print(f"\n[!] Registering and logging in as '{test_user}' to perform authenticated attacks...")
        reg_res = session.post(f"{BASE_URL}/api/register", json={"username": test_user, "password": "password123"})
        login_res = session.post(f"{BASE_URL}/api/login", json={"username": test_user, "password": "password123"})
        if login_res.status_code != 200 or not login_res.json().get('ok'):
            print(f"Login failed: {login_res.status_code} - {login_res.text}")
            return

        # B. Command Injection
        print_result("App: Command Injection", session.post(f"{BASE_URL}/api/tools/ping", json={
            "host": "8.8.8.8 && id"
        }))

        # C. Path Traversal
        print_result("App: Path Traversal", session.get(f"{BASE_URL}/api/file", params={
            "path": "../private/db_config.txt"
        }))

        # D. Reflected XSS
        print_result("App: Reflected XSS", session.get(f"{BASE_URL}/api/search", params={
            "q": "<img src=x onerror=alert('ShieldWatch_Test')>",
            "roomId": 1
        }))

        # E. Honeypot Access
        print_result("App: Honeypot Access", session.get(f"{BASE_URL}/api/admin/config"))

        # F. IDOR (Insecure Direct Object Reference)
        print_result("App: IDOR Attack", session.get(f"{BASE_URL}/api/user/1"))
    except requests.exceptions.ConnectionError:
        print(f"\n[!] Skipping App tests: Server is not reachable at {BASE_URL}")

    print("\n--- Full-Stack Simulation Complete ---")
    print(f"Check your ShieldWatch Dashboard at {COLLECTOR_URL} to see the live detections.")

if __name__ == "__main__":
    run_attacks()
