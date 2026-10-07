// kiln service worker. kiln serves it with its version filled in, so every
// release installs a new worker and drops the old cache.
'use strict';
const V = 'kiln-__KILN_VERSION__';
const SHELL = ['/', '/icon.svg', '/icons/icon-192.png', '/icons/icon-512.png', '/icons/icon-maskable-512.png', '/icons/apple-touch-icon.png'];

self.addEventListener('install', e => {
  // cache: 'reload' skips the HTTP cache, so a new release never precaches last week's bytes.
  e.waitUntil(caches.open(V).then(c => c.addAll(SHELL.map(u => new Request(u, { cache: 'reload' })))).then(() => self.skipWaiting()));
});

self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k.startsWith('kiln-') && k !== V).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});

self.addEventListener('fetch', e => {
  const r = e.request, u = new URL(r.url);
  // /api/* is authenticated and live: always the network, never cached.
  if (r.method !== 'GET' || u.origin !== location.origin || u.pathname.startsWith('/api/')) return;
  if (r.mode === 'navigate') {
    // Network first; the cached shell (or a small offline page) only when kiln is unreachable.
    e.respondWith(fetch(r).then(res => {
      if (res.ok && u.pathname === '/') { const c = res.clone(); caches.open(V).then(x => x.put('/', c)); }
      return res;
    }).catch(() => caches.match('/').then(m => m || offline())));
    return;
  }
  // '/' outside a navigation (the offline page's probe) must reach kiln, not the cache.
  if (u.pathname !== '/' && SHELL.includes(u.pathname)) e.respondWith(caches.match(u.pathname).then(m => m || fetch(r)));
});

function offline() {
  return new Response(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="color-scheme" content="dark light"><title>kiln is unreachable</title><link rel="icon" href="/icon.svg">
<style>:root{--bg:#0A0A0A;--fg:#FAFAFA;--fg2:#C4C4C4;--ember:#F59E4C}@media(prefers-color-scheme:light){:root{--bg:#F5F5F5;--fg:#0A0A0A;--fg2:#404040;--ember:#933F00}}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,Ubuntu,sans-serif;padding:16px;box-sizing:border-box}
main{max-width:420px}h1{font-size:22px;font-weight:650;letter-spacing:-.015em;margin:16px 0 8px}p{margin:0;color:var(--fg2)}svg{display:block}</style></head>
<body><main><svg viewBox="0 0 16 16" width="40" height="40" aria-hidden="true"><path d="M2.5 14.5V7.5a5.5 5.5 0 0 1 11 0v7z" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M8 13c-1.5 0-2.4-.9-2.4-2.1 0-1.4 1.3-2 1.5-3.4 1 .7 1.4 1.6 1.3 2.4.4-.2.7-.7.8-1.1.8.6 1.2 1.4 1.2 2.1C10.4 12.1 9.4 13 8 13z" fill="var(--ember)"/></svg>
<h1>kiln is unreachable</h1><p>The box may be down, or this device is off the tailnet. Retrying in <span id="n">5</span>s.</p></main>
<script>let n=5;setInterval(()=>{if(--n>0)return void(document.getElementById('n').textContent=n);n=5;document.getElementById('n').textContent=n;fetch('/',{cache:'no-store'}).then(r=>{if(r.ok)location.reload()}).catch(()=>{})},1000)</script></body></html>`,
    { status: 503, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
}
