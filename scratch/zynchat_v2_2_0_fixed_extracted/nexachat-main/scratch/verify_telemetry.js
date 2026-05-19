const http = require('http');

const API_TOKEN = 'a22a8d9865a6902f7c7193333445b85587a59d5957cdd9ea69445a854569e783';

const payload = JSON.stringify({
    id: 'test-id',
    app: 'zynchat',
    timestamp: new Date().toISOString(),
    ip: '127.0.0.1',
    threat: {
        type: 'xss',
        matched: 'Shield (App): XSS Attempt signature detected',
        raw: '<script>alert("XSS")</script>'
    }
});

const options = {
    hostname: 'localhost',
    port: 3002,
    path: '/api/event',
    method: 'POST',
    headers: {
        'x-shieldwatch-token': API_TOKEN,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
    }
};

const req = http.request(options, (res) => {
    let data = '';
    res.on('data', (chunk) => { data += chunk; });
    res.on('end', () => {
        console.log('Status:', res.statusCode);
        console.log('Body:', data);
    });
});

req.on('error', (e) => {
    console.error(`problem with request: ${e.message}`);
});

req.write(payload);
req.end();
