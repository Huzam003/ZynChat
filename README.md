# [ZynChat 💬](https://github.com/Un-9oon/ZynChat)
> Secure Enterprise Messaging Platform & Security Hardening Benchmark

ZynChat is a modern, high-stakes real-time collaboration application designed for secure enterprise messaging. It serves as the official validation benchmark for the **ShieldWatch UADR (Unified Attack Detection & Response)** security appliance. 

The project demonstrates both common vulnerability profiles (OWASP Top 10) and active defense-in-depth mitigations utilizing edge-filtering proxies and Runtime Application Self-Protection (RASP).

---

## 🏛️ System Architecture

ZynChat is deployed inside a multi-layer security container architecture:

```
[Attacker / Client Browser]
             ↓
    [Nginx Gateway Proxy]  <--- Layer 7 rate limits, bot filtering, decoy blocks
             ↓
      [ZynChat Server]     <--- Node.js / Express / Socket.io / SQLite
             ↓ (Middleware Hooks)
    [ShieldWatch Sensor]   <--- Context-aware RASP scanning (IDOR, CSRF, Injection)
             ↓ (REST/WebSockets)
   [ShieldWatch Collector] <--- Central threat intelligence command console
```

---

## 🛡️ Configured Protection & Vulnerability Profile

ZynChat has two operational states: **Standard (Vulnerable Demo)** and **Secure (ShieldWatch RASP Hardened)**.

| Vulnerability Vector | Insecure Mode (Standard) | Hardened Mode (Secure) |
| :--- | :--- | :--- |
| **SQL Injection (SQLi)** | Concatenation in SQL query allows login bypass via `' OR 1=1 --`. | Parameterized SQLite queries + signature filtering block payload. |
| **Cross-Site Scripting (XSS)** | Message payloads are rendered unfiltered. | Direct string scrubbing and HTML entities encoding. |
| **Path Traversal** | Access to `private/db_config.txt` via relative path traversal `../`. | Path resolve tracking and sandboxing restricted to the `uploads/` root. |
| **Command Injection** | Unsanitized inputs concatenated to system utilities (e.g. `ping`). | Regex validations strictly enforce DNS/IP host formats. |
| **IDOR / Object Access** | Access to user profiles via direct database IDs returns password hashes. | Verification guarantees session userId ownership before data release. |
| **Session Fixation** | Arbitrary session IDs can be planted into client cookies. | Dynamic session regeneration on authentication. |
| **CSRF** | State-changing JSON endpoints have no origin checks. | Double-submit CSRF token validation and Origin verification. |

---

## ⚙️ Running Locally

### 1. Prerequisites
Ensure you have the following installed on your system:
* **Node.js** (v18.0.0 or higher)
* **Python 3** (for the automated testing runner)
* **Nginx** (optional, for the gateway proxy layer)

### 2. Standard Start
To run ZynChat in its standard configuration:
```bash
npm start
```
This runs the application on http://localhost:3001.

### 3. Hardened Start (ShieldWatch Active)
To launch ZynChat together with the security suite and automated network proxying:
```bash
npm run start:secure
```

---

## 🧪 Security Simulation & Testing

ZynChat includes an automated security testing suite to validate WAF and RASP detection capabilities. Run the testing runner:
```bash
python3 attacks.py
```
This script launches simulated exploit payloads targeting ZynChat endpoints and prints the response status and telemetry registration results.
