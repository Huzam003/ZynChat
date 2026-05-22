const canvas = document.getElementById('bgCanvas');
const ctx = canvas.getContext('2d');
let w, h;
function resize() { w = canvas.width = window.innerWidth; h = canvas.height = window.innerHeight; }
window.onresize = resize; resize();

class Particle {
  constructor() { this.reset(); }
  reset() {
    this.x = Math.random() * w;
    this.y = Math.random() * h;
    this.vx = (Math.random() - 0.5) * 0.5;
    this.vy = (Math.random() - 0.5) * 0.5;
    this.size = Math.random() * 2;
  }
  update() {
    this.x += this.vx; this.y += this.vy;
    if (this.x < 0 || this.x > w || this.y < 0 || this.y > h) this.reset();
  }
  draw() {
    ctx.fillStyle = '#ef4444';
    ctx.beginPath(); ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2); ctx.fill();
  }
}
const particles = Array.from({ length: 100 }, () => new Particle());
function anim() {
  ctx.clearRect(0,0,w,h);
  particles.forEach(p => { p.update(); p.draw(); });
  requestAnimationFrame(anim);
}
anim();

document.getElementById('loginForm').onsubmit = async (e) => {
  e.preventDefault();
  const password = document.getElementById('password').value;
  const res = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password })
  });
  const data = await res.json();
  if (data.ok) {
    window.location.href = './';
  } else {
    document.getElementById('error').textContent = data.error;
  }
};
