# Use Node.js as the base image
FROM node:18-slim

# Install Nginx and gettext (for envsubst)
RUN apt-get update && apt-get install -y nginx gettext-base && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install --production

# Copy the rest of the application
COPY . .

# Create directory for Nginx logs and temp files
RUN mkdir -p /app/nginx/body /app/nginx/proxy /app/nginx/fastcgi /app/nginx/uwsgi /app/nginx/scgi /var/cache/nginx /var/run /var/log/nginx && \
    chmod -R 777 /app/nginx /var/cache/nginx /var/run /var/log/nginx /var/lib/nginx

# Copy the Nginx template
COPY nginx/render.conf.template /etc/nginx/nginx.conf.template

# Copy the startup script
COPY scripts/start-render.sh /app/start-render.sh
RUN chmod +x /app/start-render.sh

# Render provides the PORT environment variable
EXPOSE 10000

# Start everything
CMD ["/app/start-render.sh"]
