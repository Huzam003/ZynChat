# PROJECT REPORT: ShieldWatch UADR & ZynChat Secure Appliance
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

### 3.3 Intelligence Shield (ShieldWatch Collector)
A centralized **Command & Control (C2)** dashboard that:
- **Aggregates Telemetry**: Consolidates alerts from both Nginx and the RASP sensor.
- **Attacker Profiling**: Uses browser fingerprinting to track attackers across IP rotations and VPNs.
- **Dynamic Response**: Allows analysts to manually block IPs or Fingerprints globally across the appliance.

## 4. Implementation Details
- **Frontend**: Vanilla JS with a dynamic CSS design system supporting Dark/Light modes.
- **Backend**: Node.js, Express, Socket.io for real-time event streaming.
- **Gateway**: Nginx with `proxy_intercept_errors` and custom error-page forwarding for threat reporting.
- **Persistence**: LocalStorage for UI state and in-memory Map structures for high-performance threat tracking.

## 5. Testing and Validation
The system was validated using a custom automated attack suite (`security-test.py`) which simulated:
- **Injection Attacks**: SQLi and Command Injection were 100% blocked by the RASP layer.
- **Network Attacks**: Bot-scrapers were 100% blocked at the Nginx edge.
- **Business Logic Attacks**: IDOR attempts were detected by comparing session ownership against requested resources.
- **Distinction Logic**: The system successfully distinguished between legitimate users (Alice) and malicious actors (Tester), assigning threat scores of 0 and 100 respectively.

## 6. Future Work
The current implementation serves as a robust baseline for enterprise security. Future iterations will focus on:
- **OS-Level Attack Detection**: Upgrading the appliance to detect specific Windows and Linux kernel-level exploits and privilege escalation attempts.
- **Mobile Attack Vectors**: Implementing specialized sensors for Android/iOS specific attacks, such as deep-link hijacking and mobile-specific malware signatures.
- **Cryptographic Log Integrity**: Transitioning from plain-text logging to **Encrypted Cryptographic Logs**. This ensures that even if an attacker gains root access to the server, they cannot read, modify, or delete the forensic trail.
- **Blockchain/Hashing Verification**: Implementing hash-chaining for log entries to provide immutable proof of event sequencing.

## 7. Conclusion
ShieldWatch UADR demonstrates that a multi-layered, integrated approach to security is significantly more effective than isolated solutions. By bridging the gap between the network gateway and the application runtime, we have created an appliance that not only protects against attacks but provides the deep forensic visibility required for modern cyber-defense.

---
**Developed by:** Security Engineering Team
**Project Repository:** ZynChat Secure Mainline
