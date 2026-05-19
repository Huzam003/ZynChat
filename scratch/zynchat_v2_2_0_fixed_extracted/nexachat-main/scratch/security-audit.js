const BASE_URL = 'http://localhost:3001';

async function audit() {
  console.log('🚀 Starting ShieldWatch Security Audit (Native Fetch)...\n');

  // 1. Test SQL Injection on Login
  try {
    const res = await fetch(`${BASE_URL}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: "' OR '1'='1' --", password: "any" })
    });
    if (res.status === 403) {
      console.log('✅ SQLi Test Passed: Attack BLOCKED by RASP');
    } else {
      console.log('❌ SQLi Test Failed: Request returned status', res.status);
    }
  } catch (err) {
    console.log('⚠️ SQLi Test Error:', err.message);
  }

  // 2. Test XSS in Search
  try {
    const res = await fetch(`${BASE_URL}/api/search?q=<script>alert(1)</script>`);
    if (res.status === 403) {
      console.log('✅ XSS Test Passed: Attack BLOCKED by RASP');
    } else {
      console.log('❌ XSS Test Failed: Request returned status', res.status);
    }
  } catch (err) {
    console.log('⚠️ XSS Test Error:', err.message);
  }

  // 3. Test Path Traversal
  try {
    const res = await fetch(`${BASE_URL}/api/file?path=../../../etc/passwd`);
    if (res.status === 403) {
      console.log('✅ Path Traversal Passed: Attack BLOCKED by RASP');
    } else {
      console.log('❌ Path Traversal Failed: Request returned status', res.status);
    }
  } catch (err) {
    console.log('⚠️ Path Traversal Error:', err.message);
  }

  // 4. Test Command Injection
  try {
    const res = await fetch(`${BASE_URL}/api/tools/ping`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host: "8.8.8.8 && ls" })
    });
    if (res.status === 403 || res.status === 400) {
      console.log('✅ Cmd Injection Passed: Attack BLOCKED by RASP/Input Validation');
    } else {
      console.log('❌ Cmd Injection Failed: Request returned status', res.status);
    }
  } catch (err) {
    console.log('⚠️ Cmd Injection Error:', err.message);
  }

  // 5. Test CSP Headers & Information Leak
  try {
    const res = await fetch(`${BASE_URL}/`);
    const csp = res.headers.get('content-security-policy');
    if (csp && !csp.includes('unsafe-inline')) {
       console.log('✅ CSP Header Test Passed: Strict policy detected');
    } else {
       console.log('❌ CSP Header Test Failed: Insecure policy or missing header');
    }
    
    if (res.headers.get('x-powered-by')) {
       console.log('❌ Information Leak Test Failed: X-Powered-By is VISIBLE');
    } else {
       console.log('✅ Information Leak Test Passed: X-Powered-By is HIDDEN');
    }
  } catch (err) {
    console.log('⚠️ Header Test Error:', err.message);
  }

  console.log('\nAudit Complete.');
}

audit();
