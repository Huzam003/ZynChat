const fs = require('fs');
const html = fs.readFileSync('shieldwatch/public/index.html', 'utf8');
const js = fs.readFileSync('shieldwatch/public/dashboard.js', 'utf8');

const idsInJs = [...js.matchAll(/\$\(['"]([^'"]+)['"]\)/g)].map(m => m[1]);
const uniqueIds = [...new Set(idsInJs)];

console.log('Checking IDs found in JS:');
uniqueIds.forEach(id => {
    if (!html.includes(`id="${id}"`)) {
        console.error(`[-] MISSING: ${id}`);
    } else {
        // console.log(`[+] Found:   ${id}`);
    }
});
