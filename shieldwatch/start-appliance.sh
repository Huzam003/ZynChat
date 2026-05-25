#!/bin/bash

# ShieldWatch Standalone Appliance Starter
# ─────────────────────────────────────────────────────────────────────────────

# Clean base path
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$BASE_DIR"

TARGET_PORT=${1:-3001}
GATEWAY_PORT=${2:-8080}
COLLECTOR_PORT=3002

# Load collector environment if it exists
if [ -f "$BASE_DIR/collector/.env" ]; then
    # Load env variables
    export $(grep -v '^#' "$BASE_DIR/collector/.env" | xargs)
    if [ ! -z "$SW_PORT" ]; then
        COLLECTOR_PORT=$SW_PORT
    fi
fi

echo "🛡️  ShieldWatch Security Appliance Starting..."
echo "   Target Application Port: $TARGET_PORT"
echo "   Appliance Dashboard Port: $COLLECTOR_PORT"
echo "   Gateway Proxy Port:       $GATEWAY_PORT"

# 1. Cleanup old processes
echo "🛑 Terminating existing services on appliance ports..."
fuser -k $COLLECTOR_PORT/tcp 2>/dev/null
fuser -k $GATEWAY_PORT/tcp 2>/dev/null

# 2. Ensure logs and temp directories exist
mkdir -p "$BASE_DIR/gateway/logs" "$BASE_DIR/gateway/temp"

# 3. Dynamic Nginx Gateway Configuration Compilation
echo "⚙️  Compiling gateway configuration..."
TEMPLATE="$BASE_DIR/gateway/shieldwatch-gateway.conf.template"
CONF="$BASE_DIR/gateway/shieldwatch-gateway.conf"

if [ ! -f "$TEMPLATE" ]; then
    echo "❌ Error: Nginx configuration template not found at $TEMPLATE"
    exit 1
fi

# Replace placeholders with absolute paths and specified ports
sed -e "s|{{BASE_DIR}}|$BASE_DIR|g" \
    -e "s|{{TARGET_PORT}}|$TARGET_PORT|g" \
    -e "s|{{COLLECTOR_PORT}}|$COLLECTOR_PORT|g" \
    -e "s|{{GATEWAY_PORT}}|$GATEWAY_PORT|g" \
    "$TEMPLATE" > "$CONF"

# 4. Start Collector
echo "🛡️  Starting ShieldWatch C2 Collector..."
cd "$BASE_DIR/collector"
if [ ! -d "node_modules" ]; then
    echo "📦 node_modules not found. Installing collector dependencies..."
    npm install
fi
node collector.js > "$BASE_DIR/collector.log" 2>&1 &
cd "$BASE_DIR"

# Wait a brief moment for the collector server to start
sleep 2

# 5. Start Nginx Gateway
if command -v nginx &> /dev/null; then
    echo "🌐 Starting ShieldWatch Unified Gateway (Nginx)..."
    nginx -c "$CONF"
    if [ $? -eq 0 ]; then
        echo "✅ Gateway active on http://localhost:$GATEWAY_PORT"
    else
        echo "⚠️  Failed to start Nginx. Check logs at $BASE_DIR/gateway/logs/error.log"
    fi
else
    echo "⚠️  Nginx not found on system. Running in Collector-Only mode."
    echo "   Please direct traffic to your app directly or install Nginx for Network Shield protection."
fi

# 6. Ngrok Integration
if command -v ngrok &> /dev/null; then
    echo "🚀 Launching Public Security Tunnel..."
    pkill ngrok 2>/dev/null
    ngrok http $GATEWAY_PORT --log=stdout > "$BASE_DIR/gateway/logs/ngrok.log" 2>&1 &
    sleep 3
    PUBLIC_URL=$(curl -s http://127.0.0.1:4040/api/tunnels | jq -r '.tunnels[0].public_url' 2>/dev/null)
    
    if [ ! -z "$PUBLIC_URL" ] && [ "$PUBLIC_URL" != "null" ]; then
        echo "─────────────────────────────────────────────────────────────────────────────"
        echo "🌍 PUBLIC DEPLOYMENT SUCCESSFUL"
        echo "   Public Dashboard: $PUBLIC_URL/dashboard/"
        echo "   Public App:       $PUBLIC_URL/"
    fi
fi

echo "─────────────────────────────────────────────────────────────────────────────"
echo "✅ SHIELDWATCH APPLIANCE ACTIVE"
echo "   Management Dashboard: http://localhost:$GATEWAY_PORT/dashboard/"
echo "   Protected Entrypoint: http://localhost:$GATEWAY_PORT/"
echo "   Collector API Port:   http://localhost:$COLLECTOR_PORT/"
echo "─────────────────────────────────────────────────────────────────────────────"
