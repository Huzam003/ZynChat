# PROJECT REPORT: ShieldWatch UADR & ZynChat Secure Appliance (v2.1)
**Course:** Final Year Project (FYP) — Computer Science / Cyber Security
**System:** Unified Attack Detection & Response (UADR) Infrastructure

---

## 1. Abstract
This project presents **ShieldWatch UADR**, a comprehensive security appliance designed to protect high-stakes web applications, specifically the **ZynChat** enterprise messaging platform. By implementing a "Double Shield" architecture—combining a Network-level Nginx Gateway with an Application-level RASP (Runtime Application Self-Protection) sensor—the system provides 360-degree visibility and proactive defense against the OWASP Top 10 threats. The core innovation lies in the real-time synchronization between edge blocking and centralized threat intelligence.

## 2. Introduction
### 2.1 Problem Statement
Modern web applications face a dual threat: sophisticated automated bots and targeted manual exploits (SQLi, XSS). Traditional firewalls are often too far from the application logic to detect subtle payload manipulations, while application-level security often lacks the performance to handle network-level flooding.

### 2.2 Project Objective
To develop a unified security appliance that:
1.  Filters malicious traffic at the network edge using Nginx.
2.  Inspects internal application state using a RASP middleware.
3.  Provides a real-time, high-fidelity dashboard for security analysts to monitor, distinguish, and block attackers.

## 3. System Architecture
The system is divided into three functional layers:

### 3.1 Network Shield (Layer 7 Gateway)
Powered by a hardened **Nginx** configuration. It handles:
- **Bot Mitigation**: Signature-based blocking of attack tools (sqlmap, nmap, etc.).
- **DDoS Protection**: IP-based rate limiting and request burst control.
- **Traffic Routing**: Secure reverse-proxying to the target application.

### 3.2 Application Shield (RASP Sensor)
A custom-built **Node.js middleware** integrated into ZynChat. It performs:
- **Deep Packet Inspection (DPI)**: Scanning Query, Body, and URL parameters for exploit signatures.
- **Context-Aware Detection**: Identifying IDOR (Insecure Direct Object References) and Session Fixation by checking user session state.
- **Honeypots**: Deploying decoy endpoints to trap and fingerprint sophisticated attackers.
- **Self-Shield (Recursive Security)**: The sensor logic is recursively applied to the collector itself, protecting the management dashboard from targeted exploits.

### 3.3 Intelligence Shield (ShieldWatch Collector)
A centralized **Command & Control (C2)** dashboard that:
- **Aggregates Telemetry**: Consolidates alerts from both Nginx and the RASP sensor.
- **Attacker Profiling**: Uses browser fingerprinting to track attackers across IP rotations and VPNs.
- **Dynamic Response**: Allows analysts to manually block IPs or Fingerprints globally across the appliance.

- **Persistence**: JSON-based state persistence with automated state restoration.
- **Identity Hashing**: Password storage using **Bcrypt** with a cost factor of 12 for brute-force resistance.
- **Log Integrity**: **SHA-256 Hash-Chaining** for telemetry. Each event contains a hash of itself plus the previous event's hash, creating an immutable forensic chain.
- **Session Security**: **CSRF Protection** via double-submit tokens and **Helmet.js** for secure HTTP headers.

## 5. Testing and Validation
- **Automated Attack Suite**: Simulated SQLi, Command Injection, and Bot-scraping; 100% detection rate.
- **Unit Testing**: **Jest** suite for ShieldWatch RASP sensor logic, verifying signature matching for OWASP Top 10 exploits.
- **Integrity Testing**: Verified hash-chain continuity by manually inspecting `chainHash` propagation in the dashboard.
- **Identity Logic**: Verified Bcrypt salt/hash verification for all demo users.
- **Visualization**: Implemented a **Real-time Threat Timeline** (Chart.js) to monitor attack density over a rolling 120-second window.

## 6. Future Work
- **OS-Level Attack Detection**: Upgrading the appliance to detect specific Windows and Linux kernel-level exploits.
- **Mobile Attack Vectors**: Specialized sensors for Android/iOS specific attacks (deep-link hijacking).
- **Advanced Geo-Intelligence**: Integration of local MaxMind databases for offline IP reputation scoring.
- **Self-Healing Intelligence**: Developing automated response logic that dynamically updates Nginx firewall rules based on recursive attack patterns detected by the Self-Shield.

## 7. Conclusion
ShieldWatch UADR demonstrates that a multi-layered, integrated approach to security is significantly more effective than isolated solutions. By bridging the gap between the network gateway and the application runtime, we have created an appliance that not only protects against attacks but provides the deep forensic visibility required for modern cyber-defense.

---
**Developed by:** Security Engineering Team
**Project Repository:** ZynChat Secure Mainline
