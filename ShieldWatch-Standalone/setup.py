#!/usr/bin/env python3
import os
import subprocess
import sys

def setup():
    print("🛡️  ShieldWatch Standalone Setup")
    print("--------------------------------")
    
    # 1. Install Dashboard Dependencies
    print("[*] Installing dashboard dependencies...")
    os.chdir("dashboard")
    subprocess.run(["npm", "install"], check=True)
    os.chdir("..")
    
    # 2. Configure Environment
    print("[*] Configuring security environment...")
    if not os.path.exists(".env"):
        with open(".env", "w") as f:
            f.write("SW_API_TOKEN=sw-internal-token-xyz\n")
            f.write("DASHBOARD_PORT=3002\n")
            f.write("NGROK_AUTH_TOKEN=\n")
    
    print("[+] Setup Complete! Use 'python3 appliance.py' to start your security suite.")

if __name__ == "__main__":
    setup()
