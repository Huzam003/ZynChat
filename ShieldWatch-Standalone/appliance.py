#!/usr/bin/env python3
import os
import sys
import subprocess
import time
import requests
import json

# --- ShieldWatch Standalone Controller ---
C_GRN = "\033[92m"
C_CYN = "\033[96m"
C_YLW = "\033[93m"
C_RED = "\033[91m"
C_RST = "\033[0m"
C_BOLD = "\033[1m"

def get_ngrok_url():
    try:
        res = requests.get("http://localhost:4040/api/tunnels", timeout=2)
        if res.status_code == 200:
            tunnels = res.json().get('tunnels', [])
            if tunnels:
                return tunnels[0].get('public_url')
    except: pass
    return None

def start_tunnel():
    print(f"{C_YLW}[*] Starting Ngrok Tunnel...{C_RST}")
    subprocess.run("pkill -9 ngrok", shell=True, stderr=subprocess.DEVNULL)
    proc = subprocess.Popen(["ngrok", "http", "3002"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    for _ in range(20):
        time.sleep(1)
        url = get_ngrok_url()
        if url:
            print(f"{C_GRN}[+] Tunnel Active: {url}{C_RST}")
            return url, proc
    return None, None

def monitor():
    last_users = set()
    print(f"{C_CYN}[*] Live Terminal Monitor: ON{C_RST}")
    while True:
        try:
            res = requests.get("http://localhost:3002/api/live-status", timeout=2)
            if res.status_code == 200:
                data = res.json()
                current_users = {u['session'] for u in data.get('online_users', [])}
                for u in current_users - last_users: print(f"{C_GRN}[+] New Session Active: {u}{C_RST}")
                for u in last_users - current_users: print(f"{C_RED}[-] Session Offline: {u}{C_RST}")
                last_users = current_users
            time.sleep(5)
        except KeyboardInterrupt: break
        except: time.sleep(5)

def main():
    os.system('clear')
    print(f"{C_BOLD}🛡️  SHIELDWATCH SECURITY APPLIANCE{C_RST}")
    print("="*40)
    
    url, ngrok_p = start_tunnel()
    
    print(f"{C_CYN}[*] Launching Dashboard Collector...{C_RST}")
    collector_p = subprocess.Popen(["node", "dashboard/collector.js"], stdout=subprocess.DEVNULL)
    
    print("-" * 40)
    print(f"{C_GRN}DASHBOARD: http://localhost:3002{C_RST}")
    print(f"{C_YLW}INGRESS URL: {url if url else 'Local Only'}{C_RST}")
    print("-" * 40)
    print(f"To protect an external app, set its SW_CEREBRO_ADDR to:")
    print(f"{C_BOLD}{url.replace('https://','') if url else 'localhost:3002'}{C_RST}")
    print("-" * 40)
    
    try:
        monitor()
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        if ngrok_p: ngrok_p.terminate()
        collector_p.terminate()

if __name__ == "__main__":
    main()
