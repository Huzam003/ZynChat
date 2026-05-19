const fs = require('fs');
const path = require('path');

function loadEnv(p) {
    const env = {};
    if (fs.existsSync(p)) {
        const lines = fs.readFileSync(p, 'utf8').split('\n');
        lines.forEach(line => {
            const [key, ...vals] = line.split('=');
            if (key && vals.length > 0) {
                const val = vals.join('=').trim().replace(/^["']|["']$/g, '');
                env[key.trim()] = val;
            }
        });
    }
    return env;
}

const rootEnv = loadEnv('.env');
const swEnv = loadEnv('shieldwatch/.env');

console.log('Root SW_API_TOKEN:', rootEnv.SW_API_TOKEN);
console.log('SW SW_API_TOKEN:  ', swEnv.SW_API_TOKEN);
console.log('Match:', rootEnv.SW_API_TOKEN === swEnv.SW_API_TOKEN);
