#!/bin/bash

# Use Render's PORT or default to 10000
export PORT=${PORT:-10000}

echo "Starting ZynChat Multi-Layer Security Suite..."
echo "Configuring Nginx to listen on port $PORT..."

# Replace ${PORT} in the Nginx template
envsubst '${PORT}' < /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf

# Start Nginx in the background
nginx -g "daemon on;"

# Start the Node.js application
echo "Launching ZynChat Backend..."
export SW_ENABLED=true
node server.js
