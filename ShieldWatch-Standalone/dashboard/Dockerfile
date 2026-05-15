# ShieldWatch Hardened Appliance Dockerfile
FROM node:20-slim

WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install --omit=dev

# Copy application source
COPY . .

# Set production environment
ENV NODE_ENV=production
ENV SW_PORT=3002

# SECRETS: Do NOT embed secrets in the Dockerfile.
# Pass them at runtime via --env-file .env or -e flags.
# Required: SW_ADMIN_PASS, SW_API_TOKEN, SW_SESSION_SECRET

EXPOSE 3002

CMD ["node", "collector.js"]
