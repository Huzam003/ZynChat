#!/bin/bash

# ZynChat — Standard Launch Script
# Starts ZynChat Server only (No Nginx, No RASP)

echo "🔓 Starting ZynChat STANDARD Environment (Unprotected)..."

# 1. Kill existing app process
echo "[1/2] Cleaning up ports..."
fuser -k 3001/tcp 2>/dev/null

# 2. Disable RASP Sensors
echo "[2/2] Disabling Security Sensors..."
cd /home/we/.gemini/antigravity/scratch/nexachat/nexachat-main
sed -i 's/SW_ENABLED=true/SW_ENABLED=false/' .env

# 3. Launch App
echo "🚀 ZynChat launching on http://localhost:3001"
npm start
