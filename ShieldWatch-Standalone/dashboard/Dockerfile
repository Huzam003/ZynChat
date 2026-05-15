# ShieldWatch Hardened Appliance Dockerfile
FROM node:20-slim

# Create a non-root user
RUN groupadd -r shieldwatch && useradd -r -g shieldwatch shieldwatch

WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install --omit=dev

# Copy application source
COPY . .

# Ensure the app user owns the files
RUN chown -R shieldwatch:shieldwatch /app

# Set production environment
ENV NODE_ENV=production
ENV SW_PORT=3002

# Run as non-root
USER shieldwatch

EXPOSE 3002

CMD ["node", "collector.js"]
