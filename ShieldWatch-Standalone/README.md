# ShieldWatch Standalone Security Appliance 🛡️

ShieldWatch is a RASP (Runtime Application Self-Protection) suite that provides real-time monitoring and threat protection for Node.js/Express applications.

## Quick Start (PC Setup)

1. Extract this folder.
2. Run `python3 setup.py` to install all dependencies.
3. Run `python3 appliance.py` to start the dashboard and ngrok tunnel.

## Protecting Any App

To protect any Express.js app, follow these steps:

1. Copy `sensor.js` to your project's root.
2. In your `app.js` or `server.js`, add:

```javascript
const sw = require('./sensor');

// Add before your routes
app.use(sw.middleware);

// For active user sync (optional)
// Whenever your online users list changes:
sw.syncActiveUsers(['user1', 'user2']);
```

3. Set the environment variables in your app's host (e.g., Render, Heroku):
   - `SW_ENABLED=true`
   - `SW_CEREBRO_ADDR=<The URL shown in appliance.py>`
   - `SW_API_TOKEN=sw-internal-token-xyz`

## Features
- Real-time SQL Injection & XSS protection.
- Live active user tracking and session monitoring.
- Device fingerprinting and VPN detection.
- Automated terminal monitoring.
```
