/**
 * auth.js  — loaded at the bottom of every protected page.
 *
 * What it does:
 *  1. Calls /api/me to check the session.
 *  2. If unauthenticated → redirects to /login.html immediately.
 *  3. Enforces role-based access: each page declares its allowed role via
 *     <meta name="auth-role" content="admin|staff|parent">
 *     (if the meta tag is absent the page is accessible to any logged-in user).
 *  4. Injects a "Logout" button into .nav-links (topbar).
 */
(async () => {
  // ── 1. Fetch current user ────────────────────────────────────────────────
  let user = null;
  try {
    const res = await fetch('/api/me', { credentials: 'include' });
    if (!res.ok) throw new Error('not authenticated');
    user = await res.json();
  } catch {
    window.location.replace('/login.html');
    return;
  }

  // ── 2. Role guard ────────────────────────────────────────────────────────
  const meta = document.querySelector('meta[name="auth-role"]');
  if (meta) {
    const allowed = meta.content.split(',').map(r => r.trim());
    if (!allowed.includes(user.role)) {
      // Redirect to correct home page instead of a blank 403
      const home = user.role === 'admin'  ? '/admin.html'
                 : user.role === 'staff'  ? '/scanner.html'
                 : '/parent.html';
      window.location.replace(home);
      return;
    }
  }

  // ── 3. Inject logout button into topbar nav ──────────────────────────────
  const nav = document.querySelector('.nav-links');
  if (nav) {
    const sep = document.createElement('span');
    sep.style.cssText = 'color:rgba(255,255,255,0.4);margin:0 4px;';
    sep.textContent = '|';
    nav.appendChild(sep);

    const btn = document.createElement('button');
    btn.textContent = '⎋ Logout';
    btn.style.cssText = [
      'background:transparent',
      'border:1px solid rgba(255,255,255,0.45)',
      'color:inherit',
      'padding:4px 12px',
      'border-radius:6px',
      'font-size:13px',
      'cursor:pointer',
      'font-weight:600',
      'transition:background 0.15s'
    ].join(';');
    btn.addEventListener('mouseenter', () => btn.style.background = 'rgba(255,255,255,0.15)');
    btn.addEventListener('mouseleave', () => btn.style.background = 'transparent');
    btn.addEventListener('click', async () => {
      await fetch('/api/logout', { method: 'POST', credentials: 'include' });
      window.location.replace('/login.html');
    });
    nav.appendChild(btn);
  }
})();
