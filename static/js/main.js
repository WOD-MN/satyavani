/* ══════════════════════════════════════════════════════════════════════════════
   सत्यवाणी — SatyaVani | Main JavaScript
   Sacred particle system + UI interactions + counter animations
   ══════════════════════════════════════════════════════════════════════════ */

// ── DOM Ready ────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initParticles();
  initNavToggle();
  initCounters();
  initScrollAnimations();
  autoCloseFlashes();
  initTooltips();
  initPrintableToken();
});

// ── Sacred Particle System ───────────────────────────────────────────────────
function initParticles() {
  const canvas = document.getElementById('particleCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  let W = canvas.width  = window.innerWidth;
  let H = canvas.height = window.innerHeight;

  const PARTICLE_COUNT = Math.min(80, Math.floor(W * H / 15000));
  const SYMBOLS = ['ॐ', '🔱', '✦', '△', '◇', '⬡', '•', '◦', '⊹', '✧', '∗'];
  const COLORS  = ['rgba(196,130,60,', 'rgba(232,100,10,', 'rgba(139,26,42,',
                   'rgba(245,208,128,', 'rgba(26,107,124,'];

  class Particle {
    constructor() { this.reset(true); }
    reset(init = false) {
      this.x   = Math.random() * W;
      this.y   = init ? Math.random() * H : H + 20;
      this.vx  = (Math.random() - 0.5) * 0.4;
      this.vy  = -(Math.random() * 0.5 + 0.15);
      this.size = Math.random() * 14 + 6;
      this.symbol = SYMBOLS[Math.floor(Math.random() * SYMBOLS.length)];
      this.color  = COLORS[Math.floor(Math.random() * COLORS.length)];
      this.alpha  = 0;
      this.maxAlpha = Math.random() * 0.35 + 0.05;
      this.fadeIn  = true;
      this.rotation = Math.random() * Math.PI * 2;
      this.rotSpeed = (Math.random() - 0.5) * 0.008;
      this.life    = 0;
      this.maxLife = Math.random() * 400 + 200;
    }
    update() {
      this.x += this.vx + Math.sin(this.life * 0.02) * 0.3;
      this.y += this.vy;
      this.rotation += this.rotSpeed;
      this.life++;
      if (this.fadeIn) {
        this.alpha += 0.008;
        if (this.alpha >= this.maxAlpha) { this.alpha = this.maxAlpha; this.fadeIn = false; }
      } else if (this.life > this.maxLife * 0.7) {
        this.alpha -= 0.005;
      }
      if (this.y < -30 || this.alpha <= 0 || this.life > this.maxLife) this.reset();
    }
    draw() {
      ctx.save();
      ctx.translate(this.x, this.y);
      ctx.rotate(this.rotation);
      ctx.globalAlpha = Math.max(0, this.alpha);
      ctx.fillStyle   = this.color + this.alpha + ')';
      ctx.font        = `${this.size}px 'Tiro Devanagari Sanskrit', serif`;
      ctx.textAlign   = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(this.symbol, 0, 0);
      ctx.restore();
    }
  }

  const particles = Array.from({ length: PARTICLE_COUNT }, () => new Particle());

  // Constellation lines
  function drawLines() {
    const threshold = 120;
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < threshold) {
          const alpha = (1 - dist / threshold) * 0.06;
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.strokeStyle = `rgba(196,130,60,${alpha})`;
          ctx.lineWidth   = 0.5;
          ctx.stroke();
        }
      }
    }
  }

  let animId;
  function animate() {
    animId = requestAnimationFrame(animate);
    ctx.clearRect(0, 0, W, H);
    drawLines();
    particles.forEach(p => { p.update(); p.draw(); });
  }
  animate();

  window.addEventListener('resize', () => {
    W = canvas.width  = window.innerWidth;
    H = canvas.height = window.innerHeight;
  });

  // Pause when tab hidden (perf)
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) cancelAnimationFrame(animId);
    else animate();
  });
}

// ── Mobile Nav Toggle ────────────────────────────────────────────────────────
function initNavToggle() {
  const toggle = document.getElementById('navToggle');
  const links  = document.getElementById('navLinks');
  if (!toggle || !links) return;

  toggle.addEventListener('click', () => {
    const open = links.classList.toggle('open');
    toggle.setAttribute('aria-expanded', open);
    toggle.querySelectorAll('span').forEach((s, i) => {
      if (open) {
        if (i === 0) { s.style.transform = 'rotate(45deg) translate(5px, 5px)'; }
        if (i === 1) { s.style.opacity = '0'; }
        if (i === 2) { s.style.transform = 'rotate(-45deg) translate(5px, -5px)'; }
      } else {
        s.style.transform = '';
        s.style.opacity   = '';
      }
    });
  });

  // Close on outside click
  document.addEventListener('click', e => {
    if (!toggle.contains(e.target) && !links.contains(e.target)) {
      links.classList.remove('open');
      toggle.setAttribute('aria-expanded', 'false');
      toggle.querySelectorAll('span').forEach(s => { s.style.transform = ''; s.style.opacity = ''; });
    }
  });
}

// ── Animated Counter ──────────────────────────────────────────────────────────
function initCounters() {
  const counters = document.querySelectorAll('.counter');
  if (!counters.length) return;

  const ease = t => t < 0.5 ? 4*t*t*t : (t-1)*(2*t-2)*(2*t-2)+1;

  const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (!entry.isIntersecting) return;
      const el     = entry.target;
      const target = parseInt(el.dataset.target || '0', 10);
      const dur    = 1800;
      const start  = performance.now();
      const update = now => {
        const t   = Math.min((now - start) / dur, 1);
        el.textContent = Math.round(ease(t) * target).toLocaleString();
        if (t < 1) requestAnimationFrame(update);
      };
      requestAnimationFrame(update);
      observer.unobserve(el);
    });
  }, { threshold: 0.4 });

  counters.forEach(c => observer.observe(c));
}

// ── Scroll Animations ─────────────────────────────────────────────────────────
function initScrollAnimations() {
  const animated = document.querySelectorAll('[data-aos]');
  if (!animated.length) return;

  const obs = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const delay = entry.target.dataset.aosDelay || 0;
        setTimeout(() => entry.target.classList.add('aos-visible'), parseInt(delay));
        obs.unobserve(entry.target);
      }
    });
  }, { threshold: 0.15 });

  // Inject AOS styles
  const style = document.createElement('style');
  style.textContent = `
    [data-aos] { opacity:0; transform:translateY(24px); transition: opacity 0.6s ease, transform 0.6s ease; }
    [data-aos].aos-visible { opacity:1; transform:translateY(0); }
  `;
  document.head.appendChild(style);
  animated.forEach(el => obs.observe(el));
}

// ── Auto-close flash messages ─────────────────────────────────────────────────
function autoCloseFlashes() {
  document.querySelectorAll('.flash-msg').forEach(msg => {
    setTimeout(() => {
      msg.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
      msg.style.opacity = '0';
      msg.style.transform = 'translateX(20px)';
      setTimeout(() => msg.remove(), 400);
    }, 6000);
  });
}

// ── Simple Tooltips ───────────────────────────────────────────────────────────
function initTooltips() {
  document.querySelectorAll('[title]').forEach(el => {
    const title = el.getAttribute('title');
    if (!title) return;
    el.removeAttribute('title');
    let tip;
    el.addEventListener('mouseenter', e => {
      tip = document.createElement('div');
      tip.className = 'sv-tooltip';
      tip.textContent = title;
      tip.style.cssText = `
        position:fixed; background:rgba(10,6,8,0.95);
        border:1px solid rgba(196,130,60,0.4);
        color:#e8d9c5; font-size:0.8rem;
        padding:0.4rem 0.8rem; border-radius:6px;
        pointer-events:none; z-index:9999;
        max-width:240px; line-height:1.4;
        font-family:'Crimson Pro',serif;
        box-shadow:0 4px 20px rgba(0,0,0,0.4);
      `;
      document.body.appendChild(tip);
      const { left, top } = e.target.getBoundingClientRect();
      tip.style.left = (left + window.scrollX) + 'px';
      tip.style.top  = (top + window.scrollY - tip.offsetHeight - 8) + 'px';
    });
    el.addEventListener('mouseleave', () => { tip && tip.remove(); });
  });
}

// ── Printable Token Helper ────────────────────────────────────────────────────
function initPrintableToken() {
  const tokenVal = document.getElementById('tokenVal');
  if (!tokenVal) return;
  // Keyboard shortcut to copy: Ctrl+C when focused on token
  tokenVal.setAttribute('tabindex', '0');
  tokenVal.style.cursor = 'pointer';
  tokenVal.title = 'Click to copy token';
  tokenVal.addEventListener('click', () => {
    const txt = tokenVal.textContent;
    if (txt.includes('[Token cleared')) return;
    navigator.clipboard.writeText(txt).then(() => {
      const orig = tokenVal.textContent;
      tokenVal.textContent = '✅ Copied!';
      setTimeout(() => { tokenVal.textContent = orig; }, 1500);
    });
  });
}

// ── Utility: Debounce ─────────────────────────────────────────────────────────
function debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

// ── Scroll-to-top button ──────────────────────────────────────────────────────
(function() {
  const btn = document.createElement('button');
  btn.innerHTML = '↑';
  btn.setAttribute('aria-label', 'Scroll to top');
  btn.style.cssText = `
    position:fixed; bottom:2rem; right:2rem;
    background:rgba(139,26,42,0.8); color:#f5d080;
    border:1px solid rgba(196,130,60,0.4);
    border-radius:50%; width:44px; height:44px;
    font-size:1.2rem; cursor:pointer;
    opacity:0; transition:opacity 0.3s ease;
    z-index:50; backdrop-filter:blur(8px);
    display:flex; align-items:center; justify-content:center;
  `;
  document.body.appendChild(btn);
  window.addEventListener('scroll', debounce(() => {
    btn.style.opacity = window.scrollY > 400 ? '1' : '0';
    btn.style.pointerEvents = window.scrollY > 400 ? 'auto' : 'none';
  }, 100));
  btn.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));
})();

// ── Security: Disable right-click on admin pages ──────────────────────────────
if (window.location.pathname.startsWith('/admin')) {
  // Allow normal usage but log attempts
  document.addEventListener('keydown', e => {
    if (e.key === 'F12' || (e.ctrlKey && e.shiftKey && e.key === 'I')) {
      console.warn('[SatyaVani] Admin area. Unauthorized access attempts are logged.');
    }
  });
}

// ── Accessibility: Skip link ──────────────────────────────────────────────────
const skipLink = document.createElement('a');
skipLink.href = '#main-content';
skipLink.textContent = 'Skip to main content';
skipLink.style.cssText = `
  position:absolute; top:-100px; left:0; z-index:9999;
  background:var(--clr-gold); color:var(--clr-bg);
  padding:0.5rem 1rem; font-weight:bold;
  transition:top 0.2s ease;
`;
skipLink.addEventListener('focus', () => { skipLink.style.top = '0'; });
skipLink.addEventListener('blur',  () => { skipLink.style.top = '-100px'; });
document.body.prepend(skipLink);
