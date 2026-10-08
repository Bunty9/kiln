// Receives kiln's opt-in usage and crash reports (src/telemetry.rs) and stores them in D1.
// Only the fields kiln sends are accepted, each typed and length-limited (the only string
// with room in it is a crash's source location, path-like characters only); anything else
// is refused with a 4xx, which kiln drops rather than resends. No request metadata is stored.

const MAX_BODY = 4096;
const MAX_CRASHES_PER_DAY = 20;

const str = (max, re) => v => typeof v === 'string' && v.length <= max && (!re || re.test(v));
const int = v => Number.isSafeInteger(v) && v >= 0;
const bool = v => typeof v === 'boolean';
const oneOf = (...xs) => v => xs.includes(v);
const id = str(32, /^[0-9a-f]{32}$/);
const version = str(32, /^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$/);
const common = { id, version, build: oneOf('gnu', 'musl'), arch: str(16, /^[a-z0-9_]+$/) };

const SHAPES = {
  usage: {
    ...common,
    kind: oneOf('usage'),
    host_threads: int, host_mem_gb: int,
    auth: oneOf('app', 'token', 'none'),
    repos: int, max_vms: int, vm_cpus: int, warm_vms: int,
    egress: oneOf('open', 'filtered'),
    features: v => fits(v, { cache: bool, docker_mirror: bool, auto_rebake: bool, auto_update: bool, debug_hold: bool, confined: bool }),
    jobs_24h: int, passed_24h: int, job_minutes_24h: int,
    sizes_24h: v => v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length <= 64
      && Object.entries(v).every(([k, n]) => /^\d{1,4}$/.test(k) && int(n)),
    uptime_hours: int,
  },
  crash: {
    ...common,
    kind: oneOf('crash'),
    location: str(200, /^[\w.\/+-]+:\d+:\d+$|^unknown$/),
    thread: oneOf('main', 'tokio-runtime-worker', 'other'),
    uptime_secs: int, at: int,
  },
};

function fits(v, shape) {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return false;
  const keys = Object.keys(v);
  // Own keys only: `shape.constructor` and friends are inherited functions that would pass anything.
  return keys.length === Object.keys(shape).length && keys.every(k => Object.hasOwn(shape, k) && shape[k](v[k]));
}

export default {
  async fetch(req, env) {
    if (req.method !== 'POST' || new URL(req.url).pathname !== '/v1') return new Response('not found', { status: 404 });
    const text = await req.text();
    if (text.length > MAX_BODY) return new Response('too large', { status: 413 });
    let r;
    try { r = JSON.parse(text); } catch { return new Response('bad json', { status: 400 }); }
    const shape = Object.hasOwn(SHAPES, r?.kind) ? SHAPES[r.kind] : null;
    if (!shape || !fits(r, shape)) return new Response('bad report', { status: 400 });
    const day = new Date().toISOString().slice(0, 10), body = JSON.stringify(r);
    if (r.kind === 'usage') {
      // One a day per install; a retry or a restart the same day replaces it.
      await env.DB.prepare('INSERT OR REPLACE INTO usage (id, day, version, body) VALUES (?, ?, ?, ?)').bind(r.id, day, r.version, body).run();
    } else {
      const { n } = await env.DB.prepare('SELECT count(*) AS n FROM crash WHERE id = ? AND day = ?').bind(r.id, day).first();
      // Over the cap: accepted (so kiln deletes it) but not stored.
      if (n < MAX_CRASHES_PER_DAY) await env.DB.prepare('INSERT INTO crash (id, day, version, location, body) VALUES (?, ?, ?, ?, ?)').bind(r.id, day, r.version, r.location, body).run();
    }
    return new Response(null, { status: 204 });
  },
};
