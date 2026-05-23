const sensor = require('../shieldwatch-sensor');

describe('ShieldWatch Sensor Threat Detection', () => {
  
  test('detectThreats should identify SQL Injection', () => {
    const payload = "' OR '1'='1' --";
    const threat = sensor.detectThreats(payload);
    expect(threat).not.toBeNull();
    expect(threat.type).toBe('sqli');
  });

  test('detectThreats should identify XSS', () => {
    const payload = "<script>alert('XSS')</script>";
    const threat = sensor.detectThreats(payload);
    expect(threat).not.toBeNull();
    expect(threat.type).toBe('xss');
  });

  test('detectThreats should identify Path Traversal', () => {
    const payload = "../../../etc/passwd";
    const threat = sensor.detectThreats(payload);
    expect(threat).not.toBeNull();
    expect(threat.type).toBe('pathTraversal');

    const patterns = [
      "..%c0%afserver.js",
      "..%c1%9cserver.js",
      "..%c0%2eserver.js",
      "..%%2eserver.js",
      "..%u002eserver.js"
    ];
    for (const p of patterns) {
      const t = sensor.detectThreats(p);
      expect(t).not.toBeNull();
      expect(t.type).toBe('pathTraversal');
    }
  });

  test('detectThreats should identify Command Injection', () => {
    const payload = "; ls -la";
    const threat = sensor.detectThreats(payload);
    expect(threat).not.toBeNull();
    expect(threat.type).toBe('cmdInjection');
  });

  test('detectThreats should return null for clean strings', () => {
    const payload = "Hello world";
    const threat = sensor.detectThreats(payload);
    expect(threat).toBeNull();
  });

  test('detectThreats should handle HTML entity deobfuscation', () => {
    const payload = "&lt;script&gt;alert(1)&lt;/script&gt;";
    const threat = sensor.detectThreats(payload);
    expect(threat).not.toBeNull();
    expect(threat.type).toBe('xss');
  });

  test('detectThreats should handle SQL comment stripping obfuscation', () => {
    const payload = "SEL/**/ECT * FROM users";
    const threat = sensor.detectThreats(payload);
    expect(threat).not.toBeNull();
    expect(threat.type).toBe('sqli');
  });

  test('detectThreats should limit scanned length for ReDoS protection', () => {
    const threat = sensor.detectThreats("A".repeat(10000));
    expect(threat).toBeNull();
  });

  test('scanRequest should scan nested JSON structures recursively', () => {
    const mockReq = {
      body: {
        user: {
          profile: {
            bio: "<script>alert('nested')</script>"
          }
        }
      }
    };
    const threat = sensor.scanRequest(mockReq);
    expect(threat).not.toBeNull();
    expect(threat.type).toBe('xss');
  });

});
