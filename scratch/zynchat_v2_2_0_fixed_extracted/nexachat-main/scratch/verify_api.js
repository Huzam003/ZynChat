const http = require('http');

const API_TOKEN = 'a22a8d9865a6902f7c7193333445b85587a59d5957cdd9ea69445a854569e783';

const options = {
    hostname: 'localhost',
    port: 3002,
    path: '/api/live-status',
    method: 'GET',
    headers: {
        'x-shieldwatch-token': API_TOKEN
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

req.end();
