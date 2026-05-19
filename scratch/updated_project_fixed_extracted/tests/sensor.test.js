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

});
