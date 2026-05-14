# ShieldWatch Standalone Appliance — Dockerfile
FROM node:20-slim

WORKDIR /app

# Install system dependencies for Nginx if needed (optional for standalone dashboard)
RUN apt-get update && apt-get install -y nginx procps && rm -rf /var/lib/apt/lists/*

# Copy package files
COPY package*.json ./
RUN npm install --production

# Copy dashboard code
COPY . .

# Environment Defaults
ENV SW_PORT=3002
ENV SW_ADMIN_PASS=shieldwatch-admin-2024
ENV SW_API_TOKEN=sw-internal-token-xyz
ENV SW_SESSION_SECRET=sw-appliance-secret-123

EXPOSE 3002

# Start the collector
CMD ["node", "collector.js"]
