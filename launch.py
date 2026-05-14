#!/usr/bin/env python3
import os
import sys
import subprocess
import time
import signal

def cleanup_ports():
    print("[*] Cleaning up ports (3001, 3002, 8080)...")
    subprocess.run("fuser -k 3001/tcp 3002/tcp 8080/tcp 2>/dev/null", shell=True)
    time.sleep(1)

def set_env(mode):
    env_path = ".env"
    if not os.path.exists(env_path):
        print(f"[-] {env_path} not found!")
        return

    with open(env_path, "r") as f:
        lines = f.readlines()

    with open(env_path, "w") as f:
        for line in lines:
            if line.startswith("SW_ENABLED="):
                f.write(f"SW_ENABLED={'true' if mode == 'secure' else 'false'}\n")
            else:
                f.write(line)

def launch_standard():
    print("🔓 Starting ZynChat STANDARD Environment (Unprotected)...")
    cleanup_ports()
    set_env("standard")
    print("🚀 ZynChat launching on http://localhost:3001")
    try:
        subprocess.run(["node", "server.js"])
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")

def launch_secure():
    print("🛡️  Starting ZynChat SECURE Environment...")
    cleanup_ports()
    set_env("secure")
    
    print("[*] Initializing ShieldWatch Collector...")
    collector_proc = subprocess.Popen(["node", "shieldwatch/collector.js"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    
    print("[*] Launching Nginx Gateway...")
    nginx_conf = os.path.abspath("nginx/zynchat.conf")
    subprocess.run(["nginx", "-c", nginx_conf])
    
    print("🚀 ZynChat Secure Mode launching on http://localhost:3001 (Gateway via Nginx/ShieldWatch)")
    try:
        subprocess.run(["node", "server.js"])
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
    finally:
        print("[*] Terminating ShieldWatch Collector...")
        collector_proc.terminate()

if __name__ == "__main__":
    mode = None
    if len(sys.argv) >= 2:
        mode = sys.argv[1]
    
    if mode not in ["standard", "secure"]:
        print("========================================")
        print("          ZYNCHAT LAUNCH MENU           ")
        print("========================================")
        print("1. Unprotected Mode (Standard Sync)")
        print("2. Protected Mode   (ShieldWatch Sync)")
        print("========================================")
        choice = input("Select mode [1/2]: ").strip()
        if choice == "1":
            mode = "standard"
        elif choice == "2":
            mode = "secure"
        else:
            print("Invalid choice. Exiting.")
            sys.exit(1)
            
    if mode == "standard":
        launch_standard()
    elif mode == "secure":
        launch_secure()
