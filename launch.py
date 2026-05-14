#!/usr/bin/env python3
import os
import sys
import subprocess
import time
import signal

# Ensure we are running in the script's directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(SCRIPT_DIR)

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
    
    if mode not in ["standard", "secure", "dashboard"]:
        print("========================================")
        print("          ZYNCHAT COMMAND CENTER        ")
        print("========================================")
        print("1. Launch Standard (Local Sync)")
        print("2. Launch Secure   (Local + Dashboard)")
        print("3. Access Live Dashboard (Render)")
        print("========================================")
        choice = input("Select action [1/2/3]: ").strip()
        if choice == "1":
            mode = "standard"
        elif choice == "2":
            mode = "secure"
        elif choice == "3":
            mode = "dashboard"
        else:
            print("Invalid choice. Exiting.")
            sys.exit(1)
            
    if mode == "standard":
        launch_standard()
    elif mode == "secure":
        print("\n[*] TIP: In Secure Mode, use http://localhost:8080/dashboard/ for the dashboard.")
        launch_secure()
    elif mode == "dashboard":
        url = "https://zynchat.onrender.com/dashboard/"
        print(f"[*] Opening Live Dashboard: {url}")
        if sys.platform == "linux":
            subprocess.run(["xdg-open", url])
        elif sys.platform == "darwin":
            subprocess.run(["open", url])
        elif sys.platform == "win32":
            os.startfile(url)
