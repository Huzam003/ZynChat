#!/bin/bash

# ZynChat — Secure Launch Script
# Starts Nginx Gateway + ShieldWatch Collector + ZynChat Server

echo "🛡️  Starting ZynChat SECURE Environment..."

# 1. Kill any existing processes on our ports
echo "[1/4] Cleaning up ports..."
fuser -k 3001/tcp 3002/tcp 8080/tcp 2>/dev/null

# 2. Start ShieldWatch Collector
echo "[2/4] Initializing ShieldWatch Collector..."
cd shieldwatch
node collector.js > ../collector.log 2>&1 &
COLLECTOR_PID=$!
sleep 2

# 3. Configure ZynChat for Security
echo "[3/4] Enabling RASP Sensors..."
cd ..
sed -i 's/SW_ENABLED=false/SW_ENABLED=true/' .env

# 4. Start Nginx Gateway & Node App
echo "[4/4] Launching Nginx Gateway & ZynChat..."
nginx -c /home/we/.gemini/antigravity/scratch/nexachat/nexachat-main/nginx/zynchat.conf
npm run start

# Cleanup background collector on exit
trap "kill $COLLECTOR_PID" EXIT
