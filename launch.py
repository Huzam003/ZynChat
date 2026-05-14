#!/usr/bin/env python3
import os
import sys
import subprocess
import time
import requests

# ─── ZynChat Remote Server Controller ──────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(SCRIPT_DIR)

# --- CONFIGURATION (Set these in your environment or here) ---
RENDER_API_KEY = os.getenv("RENDER_API_KEY", "rnd_66AXn28xtvkp3bTTiCwu6gqL1ei9")
SERVICE_ID     = os.getenv("RENDER_SERVICE_ID", "srv-d8146rr7uimc7381bbo0")
# --------------------------------------------------------------

C_BLU = "\033[94m"
C_CYN = "\033[96m"
C_GRN = "\033[92m"
C_YLW = "\033[93m"
C_RED = "\033[91m"
C_RST = "\033[0m"
C_BOLD = "\033[1m"

def update_render_env(enabled):
    if RENDER_API_KEY == "your_render_api_key_here":
        print(f"{C_RED}[!] Error: Render API Key not set in launch.py{C_RST}")
        return

    val = "true" if enabled else "false"
    print(f"{C_YLW}[*] Updating Render Environment: SW_ENABLED={val}...{C_RST}")
    
    headers = {
        "Authorization": f"Bearer {RENDER_API_KEY}",
        "Content-Type": "application/json"
    }
    
    # Render API expects a list of env vars to update/patch
    url = f"https://api.render.com/v1/services/{SERVICE_ID}/env-vars"
    data = [{"key": "SW_ENABLED", "value": val}]
    
    try:
        # Note: Render usually uses a PUT or PATCH for env vars
        response = requests.put(url, headers=headers, json=data)
        if response.status_code in [200, 201, 202]:
            print(f"{C_GRN}[+] Render updated successfully!{C_RST}")
            # Now trigger a cache-cleared redeploy
            clear_cache_and_redeploy()
        else:
            print(f"{C_RED}[-] Render API Error: {response.status_code} - {response.text}{C_RST}")
    except Exception as e:
        print(f"{C_RED}[-] Connection failed: {e}{C_RST}")

def clear_cache_and_redeploy():
    if RENDER_API_KEY == "your_render_api_key_here":
        print(f"{C_RED}[!] Error: Render API Key not set in launch.py{C_RST}")
        return

    print(f"{C_YLW}[*] Triggering Redeploy with Clear Cache on Render...{C_RST}")
    
    headers = {
        "Authorization": f"Bearer {RENDER_API_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    url = f"https://api.render.com/v1/services/{SERVICE_ID}/deploys"
    data = {"clearCache": "clear"}
    
    try:
        response = requests.post(url, headers=headers, json=data)
        if response.status_code in [200, 201]:
            print(f"{C_GRN}[+] Redeploy triggered successfully! Cache is being cleared.{C_RST}")
        else:
            print(f"{C_RED}[-] Render API Error: {response.status_code} - {response.text}{C_RST}")
    except Exception as e:
        print(f"{C_RED}[-] Connection failed: {e}{C_RST}")

def check_dependencies():
    if not os.path.exists("node_modules"):
        print(f"{C_YLW}[*] Missing dependencies. Installing now...{C_RST}")
        subprocess.run(["npm", "install"], check=True)
    else:
        print(f"{C_GRN}[+] Dependencies verified.{C_RST}")

def launch_local_dashboard():
    check_dependencies()
    print(f"\n{C_BLU}{C_BOLD}🛡️  STARTING LOCAL DASHBOARD (Monitoring Render)...{C_RST}")
    # Kill previous dashboard
    subprocess.run("fuser -k 3002/tcp 2>/dev/null", shell=True)
    
    print(f"{C_YLW}[!] SETUP REQUIRED:{C_RST}")
    print(f"    1. Run '{C_CYN}ngrok http 3002{C_RST}' in another terminal.")
    print(f"    2. Add the ngrok URL to Render env 'SW_CEREBRO_ADDR'.")
    print("-" * 60)
    print(f"{C_GRN}[*] Local Collector active on http://localhost:3002{C_RST}")
    print(f"{C_CYN}[*] Login: shieldwatch-admin-2024{C_RST}\n")
    
    try:
        subprocess.run(["node", "shieldwatch/collector.js"])
    except KeyboardInterrupt:
        print(f"\n{C_YLW}[*] Shutting down...{C_RST}")

if __name__ == "__main__":
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"{C_BLU}{C_BOLD}=================================================={C_RST}")
    print(f"{C_CYN}{C_BOLD}          ZYNCHAT REMOTE SERVER CONTROLLER        {C_RST}")
    print(f"{C_BLU}{C_BOLD}=================================================={C_RST}")
    print(f"{C_GRN}1.{C_RST} {C_BOLD}ENABLE{C_RST} ShieldWatch Protection (on Render)")
    print(f"{C_RED}2.{C_RST} {C_BOLD}DISABLE{C_RST} ShieldWatch Protection (on Render)")
    print(f"{C_CYN}3.{C_RST} {C_BOLD}LAUNCH{C_RST} Local Dashboard (Monitor Render)")
    print(f"{C_YLW}4.{C_RST} {C_BOLD}CLEAR CACHE{C_RST} and Redeploy (on Render)")
    print(f"{C_RED}5.{C_RST} {C_BOLD}EXIT{C_RST}")
    print(f"{C_BLU}=================================================={C_RST}")
    
    choice = input(f"{C_BOLD}Action [1-5]: {C_RST}").strip()
    
    if choice == "1":
        update_render_env(True)
    elif choice == "2":
        update_render_env(False)
    elif choice == "3":
        launch_local_dashboard()
    elif choice == "4":
        clear_cache_and_redeploy()
    elif choice == "5":
        sys.exit(0)
    else:
        print(f"{C_RED}[!] Invalid choice.{C_RST}")
