#!/bin/bash

# ShieldWatch Unified Security Appliance Starter
# ─────────────────────────────────────────────────────────────────────────────

# 1. Config & Paths
BASE_DIR="/home/we/.gemini/antigravity/scratch/shieldwatch_uadr/ShieldWatch"
GATEWAY_CONF="$BASE_DIR/gateway/shieldwatch-gateway.conf"
LOG_DIR="$BASE_DIR/gateway/logs"
TEMP_DIR="$BASE_DIR/gateway/temp"

# 2. Cleanup old processes
echo "🛑 Shutting down existing ShieldWatch services..."
pkill -9 -f collector.js
pkill -9 -f server.js
fuser -k 3001/tcp 2>/dev/null
fuser -k 3002/tcp 2>/dev/null
fuser -k 8080/tcp 2>/dev/null

# 3. Ensure directories exist
mkdir -p "$LOG_DIR" "$TEMP_DIR"

# 4. Set Environment Variables
export SW_ADMIN_PASS="shieldwatch-admin-2024"
export SW_API_TOKEN="sw-internal-token-xyz"
export SW_SESSION_SECRET="zyn-shield-super-secret"
export SW_PORT=3002
export SW_CEREBRO_ADDR="localhost:3002"
export SW_ENABLED="true"

echo "🛡️  Starting ShieldWatch Collector..."
node "$BASE_DIR/collector.js" > "$BASE_DIR/collector.log" 2>&1 &

echo "🌐 Starting ShieldWatch Unified Gateway (Nginx)..."
nginx -c "$GATEWAY_CONF"

echo "🧪 Starting ZynChat (Target App) for testing..."
cd /home/we/.gemini/antigravity/scratch/nexachat/nexachat-main
node server.js > server.log 2>&1 &

echo "✅ ShieldWatch Appliance ACTIVE"
echo "   Management Dashboard: http://localhost:8080/dashboard/"
echo "   Protected Endpoint:   http://localhost:8080/"

# 5. Public Tunnel (Professional Deployment)
if command -v ngrok &> /dev/null; then
    echo "🚀 Launching Public Security Tunnel..."
    pkill ngrok
    ngrok http 8080 --log=stdout > "$BASE_DIR/gateway/logs/ngrok.log" 2>&1 &
    sleep 3
    PUBLIC_URL=$(curl -s http://127.0.0.1:4040/api/tunnels | jq -r '.tunnels[0].public_url')
    
    if [ "$PUBLIC_URL" != "null" ]; then
        echo "─────────────────────────────────────────────────────────────────────────────"
        echo "🌍 PUBLIC DEPLOYMENT SUCCESSFUL"
        echo "   Public Dashboard: $PUBLIC_URL/dashboard/"
        echo "   Public App:      $PUBLIC_URL/"
    else
        echo "⚠️  Public tunnel failed to initialize (is ngrok configured?)"
    fi
fi
echo "─────────────────────────────────────────────────────────────────────────────"
