import requests
import json
import time

BASE_URL = "http://localhost:3001"
COLLECTOR_URL = "http://localhost:3002"

def print_result(attack_name, response):
    print(f"\n[+] Testing {attack_name}...")
    print(f"    Status Code: {response.status_code}")
    try:
        data = response.json()
        print(f"    Response: {json.dumps(data, indent=4)}")
        if data.get('blocked') or response.status_code == 403:
            print(f"    RESULT: ✅ SHIELDWATCH BLOCKED THE ATTACK")
        elif data.get('ok') == True:
             print(f"    RESULT: ⚠️ ATTACK SUCCESSFUL (PROTECTION FAILED OR LOGGED ONLY)")
    except:
        print(f"    Response Body: {response.text[:200]}...")

def run_attacks():
    session = requests.Session()
    
    print("--- Starting Security Attack Simulation ---")

    # 0. Submit Fingerprint (to bypass bot protection)
    print("\n[!] Submitting security fingerprint...")
    session.post(f"{BASE_URL}/api/sw/fingerprint", json={
        "deviceId": "python-test-device-123",
        "canvasHash": "fake-hash-789"
    })

    # 1. SQL Injection (Login Bypass)
    # Payload: admin'-- 
    print_result("SQL Injection (Login Bypass)", session.post(f"{BASE_URL}/api/login", json={
        "username": "admin'--",
        "password": "any"
    }))

    # Authenticate for subsequent attacks
    print("\n[!] Logging in as 'tester' to perform authenticated attacks...")
    login_res = session.post(f"{BASE_URL}/api/login", json={"username": "tester", "password": "password123"})
    if login_res.status_code != 200:
        print("Login failed. Ensure the server is running and 'tester' user exists.")
        return

    # 2. Command Injection
    # Payload: 8.8.8.8 && id
    print_result("Command Injection", session.post(f"{BASE_URL}/api/tools/ping", json={
        "host": "8.8.8.8 && id"
    }))

    # 3. Path Traversal
    # Payload: ../private/db_config.txt
    print_result("Path Traversal", session.get(f"{BASE_URL}/api/file", params={
        "path": "../private/db_config.txt"
    }))

    # 4. Reflected XSS
    # Payload: <img src=x onerror=alert(1)>
    print_result("Reflected XSS", session.get(f"{BASE_URL}/api/search", params={
        "q": "<img src=x onerror=alert('ShieldWatch_Test')>",
        "roomId": 1
    }))

    # 5. Honeypot Access
    # Endpoint: /api/admin/config (Should trigger DECOY verdict)
    print_result("Honeypot Access", session.get(f"{BASE_URL}/api/admin/config"))

    # 6. IDOR (Insecure Direct Object Reference)
    # Endpoint: /api/user/1 (Accessing admin profile)
    print_result("IDOR Attack", session.get(f"{BASE_URL}/api/user/1"))

    print("\n--- Attack Simulation Complete ---")
    print(f"Check your ShieldWatch Dashboard at {COLLECTOR_URL} to see the live detections.")

if __name__ == "__main__":
    run_attacks()
