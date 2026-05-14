#!/usr/bin/env python3
import os
import requests
import socket
import time

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def check_dashboard():
    print("========================================")
    print("      SHIELDWATCH DASHBOARD STATUS      ")
    print("========================================")
    
    # 1. Check if collector is running
    collector_url = "http://localhost:3002/ping"
    try:
        response = requests.get(collector_url, timeout=2)
        if response.status_code == 200:
            data = response.json()
            print(f"[+] Collector: ONLINE")
            print(f"[+] App:       {data.get('app')}")
            print(f"[+] Version:   {data.get('version', '2.0.0')}")
            print(f"[+] History:   {data.get('events', 0)} events logged")
        else:
            print(f"[-] Collector: ERROR ({response.status_code})")
    except requests.exceptions.RequestException:
        print(f"[-] Collector: OFFLINE (Is 'launch.py secure' running?)")
        return

    # 2. Provide Access Links
    local_ip = get_ip()
    print("\n----------------------------------------")
    print("           ACCESS DASHBOARD             ")
    print("----------------------------------------")
    print(f"Local Access:   http://localhost:3002")
    print(f"Network Access: http://{local_ip}:3002")
    print("----------------------------------------")
    print("\nNote: Ensure port 3002 is open in your firewall.")

if __name__ == "__main__":
    check_dashboard()
