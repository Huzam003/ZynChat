#!/usr/bin/env python3
import os
import sys
import subprocess
import time
import signal

# ─── ZynChat Unified Command Center ───────────────────────────────────────────
# Ensure we are running in the script's directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(SCRIPT_DIR)

# ANSI Colors
C_BLU = "\033[94m"
C_CYN = "\033[96m"
C_GRN = "\033[92m"
C_YLW = "\033[93m"
C_RED = "\033[91m"
C_RST = "\033[0m"
C_BOLD = "\033[1m"

def cleanup_ports():
    print(f"{C_YLW}[*] Cleaning up ports (3001, 3002, 8080)...{C_RST}")
    subprocess.run("fuser -k 3001/tcp 3002/tcp 8080/tcp 2>/dev/null", shell=True)
    time.sleep(1)

def set_env(mode):
    env_path = ".env"
    if not os.path.exists(env_path):
        print(f"{C_RED}[-] {env_path} not found!{C_RST}")
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
    print(f"\n{C_CYN}{C_BOLD}🔓 STARTING ZYNCHAT STANDARD (Unprotected Mode)...{C_RST}")
    cleanup_ports()
    set_env("standard")
    print(f"{C_GRN}🚀 ZynChat active on http://localhost:3001{C_RST}")
    try:
        subprocess.run(["node", "server.js"])
    except KeyboardInterrupt:
        print(f"\n{C_YLW}[*] Shutting down...{C_RST}")

def launch_secure():
    print(f"\n{C_BLU}{C_BOLD}🛡️  STARTING ZYNCHAT SECURE (ShieldWatch Protected)...{C_RST}")
    cleanup_ports()
    set_env("secure")
    
    print(f"{C_YLW}[*] Initializing ShieldWatch Intelligence Collector...{C_RST}")
    collector_proc = subprocess.Popen(["node", "shieldwatch/collector.js"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    
    print(f"{C_YLW}[*] Launching Nginx Gateway Architecture...{C_RST}")
    nginx_conf = os.path.abspath("nginx/zynchat.conf")
    subprocess.run(["nginx", "-c", nginx_conf])
    
    print(f"\n{C_GRN}🚀 ZynChat Secure Mode active via Nginx Gateway!{C_RST}")
    print(f"{C_CYN}   - Chat App:  http://localhost:8080/{C_RST}")
    print(f"{C_CYN}   - Dashboard: http://localhost:8080/dashboard/{C_RST}")
    
    try:
        subprocess.run(["node", "server.js"])
    except KeyboardInterrupt:
        print(f"\n{C_YLW}[*] Shutting down...{C_RST}")
    finally:
        print(f"{C_YLW}[*] Terminating ShieldWatch processes...{C_RST}")
        collector_proc.terminate()

def launch_collector_only():
    print(f"\n{C_BLU}{C_BOLD}🛡️  STARTING LOCAL DASHBOARD (Remote Monitoring Mode)...{C_RST}")
    cleanup_ports()
    print(f"{C_YLW}[!] IMPORTANT: To receive feeds from Render to this local dashboard:{C_RST}")
    print(f"    1. Run '{C_CYN}ngrok http 3002{C_RST}' to get a public URL.")
    print(f"    2. Set {C_CYN}SW_CEREBRO_ADDR=<ngrok_url>{C_RST} in Render Environment Variables.")
    print("-" * 70)
    print(f"{C_GRN}[*] Local Collector starting on port 3002...{C_RST}\n")
    try:
        subprocess.run(["node", "shieldwatch/collector.js"])
    except KeyboardInterrupt:
        print(f"\n{C_YLW}[*] Shutting down...{C_RST}")

def open_render_dashboard():
    url = "https://zynchat.onrender.com/dashboard/"
    print(f"{C_CYN}[*] Opening Remote Live Dashboard: {url}{C_RST}")
    if sys.platform == "linux":
        subprocess.run(["xdg-open", url])
    elif sys.platform == "darwin":
        subprocess.run(["open", url])
    elif sys.platform == "win32":
        os.startfile(url)

if __name__ == "__main__":
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"{C_BLU}{C_BOLD}=================================================={C_RST}")
    print(f"{C_CYN}{C_BOLD}             ZYNCHAT COMMAND CENTER               {C_RST}")
    print(f"{C_BLU}{C_BOLD}=================================================={C_RST}")
    print(f"{C_CYN}1.{C_RST} {C_BOLD}LOCAL:{C_RST} Launch Standard (Unprotected)")
    print(f"{C_CYN}2.{C_RST} {C_BOLD}LOCAL:{C_RST} Launch Secure   (RASP + Nginx)")
    print(f"{C_CYN}3.{C_RST} {C_BOLD}LOCAL:{C_RST} Launch Dashboard Only (Remote Monitor)")
    print(f"{C_CYN}4.{C_RST} {C_BOLD}REMOTE:{C_RST} Access Live Dashboard (Render)")
    print(f"{C_BLU}=================================================={C_RST}")
    
    choice = input(f"{C_BOLD}Select Operation [1-4]: {C_RST}").strip()
    
    if choice == "1":
        launch_standard()
    elif choice == "2":
        launch_secure()
    elif choice == "3":
        launch_collector_only()
    elif choice == "4":
        open_render_dashboard()
    else:
        print(f"{C_RED}[!] Invalid choice. Exiting.{C_RST}")
