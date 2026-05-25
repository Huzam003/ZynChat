import requests
import time
#commented
#this is the testing file
# Target: Your local ZynChat server
TARGET_URL = "https://zynchat.onrender.com"

# Payloads to test different protection layers
ATTACKS = [
    {
        "name": "SQL Injection (Authentication Bypass)",
        "endpoint": "/api/auth/login",
        "method": "POST",
        "data": {"username": "' OR 1=1 --", "password": "password"},
        "expected": "BLOCKED (SQLi)"
    },
    {
        "name": "Cross-Site Scripting (XSS)",
        "endpoint": "/api/chat/send",
        "method": "POST",
        "data": {"message": "<script>alert('ShieldWatch_Test')</script>"},
        "expected": "CLEANED/BLOCKED (XSS)"
    },
    {
        "name": "Path Traversal (Sensitive File Access)",
        "endpoint": "/api/files/download?file=../../../../etc/passwd",
        "method": "GET",
        "data": {},
        "expected": "BLOCKED (Traversal)"
    },
    {
        "name": "Command Injection (System Access)",
        "endpoint": "/api/system/status",
        "method": "POST",
        "data": {"cmd": "id; cat /etc/shadow"},
        "expected": "BLOCKED (CmdExec)"
    },
    {
        "name": "Honeypot Trap (Fake Admin Panel)",
        "endpoint": "/admin/config.php",
        "method": "GET",
        "data": {},
        "expected": "PERMANENT BAN (Honeypot)"
    }
]

def run_security_test():
    print(f"\n🚀 Starting Security Validation against {TARGET_URL}")
    print("=" * 60)
    
    for attack in ATTACKS:
        print(f"\n[*] Testing: {attack['name']}")
        print(f"    Target: {attack['endpoint']}")
        
        try:
            if attack['method'] == "POST":
                res = requests.post(TARGET_URL + attack['endpoint'], json=attack['data'], timeout=5)
            else:
                res = requests.get(TARGET_URL + attack['endpoint'], params=attack['data'], timeout=5)
            
            print(f"    Response Code: {res.status_code}")
            
            if res.status_code == 403:
                print(f"    Result: ✅ SUCCESS - Attack was BLOCKED by ShieldWatch")
            elif res.status_code == 429:
                print(f"    Result: 🛡️  THROTTLED - Rate limit active")
            else:
                print(f"    Result: ⚠️  BYPASS? - Status {res.status_code}. Check dashboard for logs.")
                
        except Exception as e:
            print(f"    [-] Error: {e}")
        
        time.sleep(1.5) # Wait for telemetry to sync

    print("\n" + "=" * 60)
    print("Test Complete. Check your ShieldWatch Dashboard (http://localhost:3002) for the alerts!")

if __name__ == "__main__":
    run_security_test()
