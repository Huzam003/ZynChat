#!/usr/bin/env python3
import os
import sys
import subprocess
import time
import requests
import json
import signal

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

def update_render_env_var(key, value):
    if RENDER_API_KEY == "your_render_api_key_here":
        return False

    print(f"{C_YLW}[*] Syncing Render Config: {key}={value}...{C_RST}")
    
    headers = {
        "Authorization": f"Bearer {RENDER_API_KEY}",
        "Content-Type": "application/json"
    }
    
    url = f"https://api.render.com/v1/services/{SERVICE_ID}/env-vars"
    # Note: We use PUT which replaces the whole list or PATCH? 
    # Render API PATCH /env-vars actually updates/adds. 
    # Let's use the same logic as before but for dynamic key.
    data = [{"key": key, "value": value}]
    
    try:
        response = requests.put(url, headers=headers, json=data)
        return response.status_code in [200, 201, 202]
    except:
        return False

def get_ngrok_url():
    try:
        # Check if ngrok is already running and get URL from its API
        res = requests.get("http://localhost:4040/api/tunnels", timeout=2)
        if res.status_code == 200:
            tunnels = res.json().get("tunnels", [])
            for t in tunnels:
                if t.get("proto") == "https":
                    return t.get("public_url")
    except:
        pass
    return None

def start_ngrok_tunnel():
    # 1. First, try to detect any EXISTING active tunnel
    for _ in range(3):
        url = get_ngrok_url()
        if url:
            clean_url = url.replace("https://", "").replace("http://", "")
            print(f"{C_GRN}[+] Found existing active tunnel: {url}{C_RST}")
            return clean_url, None
        time.sleep(1)

    print(f"{C_YLW}[*] Cleaning up any old ngrok processes...{C_RST}")
    # Force kill any ngrok processes
    if os.name == 'posix':
        subprocess.run("pkill -9 ngrok", shell=True, stderr=subprocess.DEVNULL)
    else:
        subprocess.run("taskkill /f /im ngrok.exe", shell=True, stderr=subprocess.DEVNULL)
    
    time.sleep(2)
    
    print(f"{C_YLW}[*] Starting fresh automated ngrok tunnel...{C_RST}")
    try:
        proc = subprocess.Popen(
            ["ngrok", "http", "3002"], 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.PIPE,
            text=True
        )
    except FileNotFoundError:
        print(f"{C_RED}[-] Error: 'ngrok' command not found.{C_RST}")
        return None, None
    
    # Wait for tunnel
    for _ in range(30):
        time.sleep(1)
        url = get_ngrok_url()
        if url:
            clean_url = url.replace("https://", "").replace("http://", "")
            print(f"{C_GRN}[+] Tunnel Active: {url}{C_RST}")
            return clean_url, proc
        
        if proc.poll() is not None:
            err = proc.stderr.read()
            if "already online" in err.lower():
                print(f"{C_YLW}[!] Tunnel is already online elsewhere. Trying to fetch URL...{C_RST}")
                time.sleep(2)
                url = get_ngrok_url()
                if url:
                    return url.replace("https://", "").replace("http://", ""), None
            print(f"{C_RED}[-] Ngrok failed. Error: {err.strip()}{C_RST}")
            return None, None
    
    print(f"{C_RED}[-] Timeout: Tunnel didn't appear.{C_RST}")
    return None, None

def wait_for_deployment(deploy_id):
    if not deploy_id: return
    
    print(f"{C_CYN}[*] Monitoring Deployment (ID: {deploy_id})...{C_RST}")
    headers = {"Authorization": f"Bearer {RENDER_API_KEY}", "Accept": "application/json"}
    url = f"https://api.render.com/v1/services/{SERVICE_ID}/deploys/{deploy_id}"
    
    start_time = time.time()
    last_status = ""
    
    while True:
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                deploy = response.json()
                status = deploy.get("status", "unknown")
                
                if status != last_status:
                    color = C_YLW if "progress" in status or status == "created" else (C_GRN if status == "live" else C_RED)
                    print(f"{C_CYN}[Deploy]{C_RST} Status changed to: {color}{status.upper()}{C_RST}")
                    last_status = status
                
                if status == "live":
                    print(f"\n{C_GRN}{C_BOLD}[✓] DEPLOYMENT SUCCESSFUL! Your app is now LIVE.{C_RST}")
                    break
                elif status in ["failed", "canceled", "pre_deploy_failed"]:
                    print(f"\n{C_RED}{C_BOLD}[×] DEPLOYMENT FAILED! Status: {status.upper()}{C_RST}")
                    break
            
            # Timeout after 10 minutes
            if time.time() - start_time > 600:
                print(f"\n{C_RED}[!] Timeout waiting for deployment.{C_RST}")
                break
                
            time.sleep(10) # Poll every 10 seconds
        except Exception as e:
            print(f"{C_RED}[-] Error polling status: {e}{C_RST}")
            time.sleep(10)

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
            deploy_data = response.json()
            deploy_id = deploy_data.get("id")
            print(f"{C_GRN}[+] Redeploy triggered successfully! Cache is being cleared.{C_RST}")
            wait_for_deployment(deploy_id)
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

def monitor_live_status():
    """Polls the local collector and prints a live table of active users"""
    print(f"{C_CYN}[*] Terminal Monitor: ACTIVE{C_RST}")
    last_count = -1
    
    while True:
        try:
            res = requests.get("http://localhost:3002/api/live-status", timeout=2)
            if res.status_code == 200:
                data = res.json()
                count = data.get('online_count', 0)
                users = data.get('online_users', [])
                
                if count != last_count:
                    # Only print if something changed
                    os.system('clear' if os.name == 'posix' else 'cls')
                    print(f"\n{C_BLU}{C_BOLD}🛡️  SHIELDWATCH LIVE MONITORING{C_RST}")
                    print(f"{C_CYN}Dashboard: http://localhost:3002{C_RST}")
                    print(f"{C_GRN}Active Users: {count}{C_RST} | {C_RED}Events: {data.get('total_events',0)}{C_RST}")
                    print("-" * 45)
                    if users:
                        print(f"{C_BOLD}{'USER':<25} | {'THREAT':<10}{C_RST}")
                        print("-" * 45)
                        for u in users:
                            color = C_RED if u['threat'] > 0 else C_GRN
                            print(f"{color}{u['session']:<25}{C_RST} | {color}{u['threat']:<10}{C_RST}")
                    else:
                        print(f"{C_YLW}No users currently online.{C_RST}")
                    print("-" * 45)
                    print(f"{C_DIM}Press Ctrl+C to stop dashboard...{C_RST}")
                    last_count = count
            
            time.sleep(5)
        except:
            pass

def launch_local_dashboard():
    check_dependencies()
    print(f"\n{C_BLU}{C_BOLD}🛡️  STARTING AUTOMATED DASHBOARD...{C_RST}")
    
    # 1. Start Tunnel
    addr, ngrok_proc = start_ngrok_tunnel()
    
    if addr:
        # 2. Check current Render env var
        print(f"{C_CYN}[*] Checking Render config...{C_RST}")
        headers = {"Authorization": f"Bearer {RENDER_API_KEY}", "Accept": "application/json"}
        try:
            res = requests.get(f"https://api.render.com/v1/services/{SERVICE_ID}/env-vars", headers=headers)
            current_addr = ""
            if res.status_code == 200:
                for ev in res.json():
                    if ev['envVar']['key'] == 'SW_CEREBRO_ADDR':
                        current_addr = ev['envVar']['value']
                        break
            
            if addr != current_addr:
                print(f"{C_YLW}[!] Updating Render with new URL: {addr}{C_RST}")
                if update_render_env_var("SW_CEREBRO_ADDR", addr):
                    clear_cache_and_redeploy()
            else:
                print(f"{C_GRN}[+] URL matches Render. Skipping redeploy.{C_RST}")
        except: pass

    # Kill previous dashboard
    subprocess.run("fuser -k 3002/tcp 2>/dev/null", shell=True)
    
    try:
        # Run collector
        collector_proc = subprocess.Popen(["node", "shieldwatch/collector.js"], stdout=subprocess.DEVNULL)
        
        # Start Terminal Monitor in this thread
        monitor_live_status()
        
    except KeyboardInterrupt:
        print(f"\n{C_YLW}[*] Shutting down...{C_RST}")
        if ngrok_proc: ngrok_proc.terminate()
        collector_proc.terminate()
        subprocess.run("pkill -9 ngrok", shell=True)

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
