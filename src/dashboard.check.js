// Checks the dashboard's analytics helpers without a browser: node src/dashboard.check.js src/dashboard.html
// Each helper is pulled out of the page by name, so renaming one fails here instead of skipping it.
const fs = require('fs'), assert = require('assert');
const src = fs.readFileSync(process.argv[2], 'utf8');
const grab = n => { const m = src.match(new RegExp(`^(?:const ${n} = .*|function ${n}\\([\\s\\S]*?\\n})$`, 'm')); assert(m, n); return m[0]; };
const esc = x => String(x);
const { pctl, jobMins, timed, outcome, anBuckets, runStatus, forgeOf, can, runActs, forgeUrl } = new Function('esc',
  ['hhmm', 'pctl', 'jobEnd', 'jobMins', 'refusedBy', 'refusedWhy', 'status', 'isFail', 'timed', 'outcome', 'anBuckets', 'runStatus', 'forgeOf', 'can', 'runActs', 'forgeUrl'].map(grab).join('\n') +
  '\nreturn { pctl, jobMins, timed, outcome, anBuckets, runStatus, forgeOf, can, runActs, forgeUrl };')(esc);

assert.equal(pctl([], .95), null);
assert.equal(pctl([5], .95), 5);
const a = [...Array(100).keys()].reverse();
assert.equal(pctl(a, .95), 95);
assert.equal(a[0], 99, "pctl doesn't sort the caller's array");

// Job minutes as vm.rs record_usage counts them: start to result, rounded up, at least 1.
assert.equal(jobMins({ busy_since: 0, done_at: 1 }), 1);
assert.equal(jobMins({ busy_since: 0, done_at: 61 }), 2);
assert.equal(jobMins({ busy_since: 0, done_at: 60, ended: 3600 }), 1, 'a debug hold after the result is not billed');
assert.equal(jobMins({ busy_since: 0, ended: 120 }), 2);
assert.equal(jobMins({ busy_since: 100, done_at: 50 }), 1, 'clock skew');

const o = (state, result, x = {}) => outcome({ state, result, busy_since: 1, ...x });
assert.equal(o('done', 'succeeded'), 0); assert.equal(o('done', ''), 0);
assert.equal(o('done', 'failure'), 1); assert.equal(o('failed'), 1); assert.equal(o('killed'), 1); assert.equal(o('lost'), 1);
assert.equal(o('killed', '', { note: 'refused: pull request from a fork' }), 2, 'a refusal is neither passed nor failed');
assert.equal(o('done', 'cancelled'), 2); assert.equal(o('unknown'), 2); assert.equal(o('failed', '', { mint_failed: true }), 2);
assert.equal(timed({ state: 'lost', busy_since: 1, ended: 1 }), false, 'a lost job has no real duration');
assert.equal(timed({ state: 'lost', busy_since: 1, done_at: 9 }), true);
assert.equal(timed({ state: 'done', result: 'succeeded' }), true);

for (const [r, n] of [[1, 24], [7, 7], [30, 30]]) {
  const B = anBuckets(r), now = Date.now() / 1000;
  assert.equal(B.length, n);
  B.forEach((b, i) => i && assert(b[0] > B[i - 1][0], 'buckets increase'));
  assert(B[n - 1][0] <= now && now - B[n - 1][0] < (r === 1 ? 3600 : 90000), 'the last bucket holds now');
}
// Forge API values map onto badge states; controls follow the forge's caps.
const rs = (status, outcome) => runStatus({ status, outcome });
assert.equal(rs('queued', null), 'queued'); assert.equal(rs('running', null), 'running');
assert.equal(rs('completed', 'Succeeded'), 'passed'); assert.equal(rs('completed', 'SucceededWithIssues'), 'passed');
assert.equal(rs('completed', 'Failed'), 'failed'); assert.equal(rs('completed', 'Canceled'), 'cancelled');
assert.equal(rs('completed', 'Skipped'), 'skipped'); assert.equal(rs('completed', null), 'failed', 'unknown fails closed');
const gh = { id: 'github', url: 'https://github.com', repos: ['Acme/Demo'], caps: { rerun: true, cancel: true, dispatch: true, workflows: true } };
const gl = { id: 'gitlab', url: 'https://gitlab.example', repos: ['gitlab:g/p'], caps: { rerun: true, cancel: false, dispatch: true, workflows: false } };
assert.equal(forgeOf([gh, gl], 'acme/demo'), gh, 'repo keys match ignoring case');
assert.equal(forgeOf([gh, gl], 'gitlab:g/p'), gl); assert.equal(forgeOf(null, 'a/b'), undefined);
assert.deepEqual(runActs(true, gh), ['rerun']); assert.deepEqual(runActs(false, gh), ['cancel']);
assert.deepEqual(runActs(false, gl), [], 'no cancel cap: no Cancel button');
assert.deepEqual(runActs(true, { caps: { rerun: false } }), [], 'no rerun cap: no Rerun button');
assert.deepEqual(runActs(true, undefined), [], 'forge not loaded: controls hidden');
assert(!can(gl, 'workflows') && can(gl, 'dispatch') && !can(undefined, 'rerun'));
assert.equal(forgeUrl(gh, 'https://github.com/acme/demo/pull/1'), 'https://github.com/acme/demo/pull/1');
assert.equal(forgeUrl(gh, 'https://github.com.evil.example/x'), '#', 'only the forge own origin');
assert.equal(forgeUrl(gh, 'javascript:alert(1)'), '#'); assert.equal(forgeUrl(undefined, 'https://github.com/x'), '#');
// GitLab: what the token's scopes mean, expiry in days, free forge ids, project paths.
const { glScopes, daysLeft, nextForgeId, repoPath } = new Function(['GL_SCOPES', 'glScopes', 'daysLeft', 'nextForgeId', 'repoPath'].map(grab).join('\n') +
  '\nreturn { glScopes, daysLeft, nextForgeId, repoPath };')();
assert.equal(glScopes({}), null, 'scopes not read yet'); assert.equal(glScopes({ scopes: null }), null);
assert.deepEqual(glScopes({ scopes: ['create_runner', 'manage_runner', 'read_api'] }), { full: false, missing: [] });
assert.deepEqual(glScopes({ scopes: ['read_api'] }), { full: false, missing: ['create_runner', 'manage_runner'] });
assert.deepEqual(glScopes({ scopes: ['api'] }), { full: true, missing: [] }, 'api covers the runner scopes');
assert.deepEqual(glScopes({ scopes: [] }).missing.length, 3);
const T = Date.UTC(2027, 9, 11, 12) / 1000;
assert.equal(daysLeft('2027-10-11', T), 0, 'valid through the day'); assert.equal(daysLeft('2027-10-12', T), 1);
assert.equal(daysLeft('2027-10-10', T), -1); assert.equal(daysLeft(null, T), null); assert.equal(daysLeft('soon', T), null);
assert.equal(nextForgeId('gitlab', []), 'gitlab'); assert.equal(nextForgeId('gitlab', ['gitlab']), 'gitlab-2');
assert.equal(nextForgeId('gitlab', ['gitlab', 'gitlab-2']), 'gitlab-3');
assert.equal(repoPath('gl', 'gl:g/s/p'), 'g/s/p'); assert.equal(repoPath('gl', 'o/n'), 'o/n');
assert.equal(repoPath('gl', 'gl2:g/p'), 'gl2:g/p', 'only this forge prefix');
// A GitLab forge whose token has no `api` scope shows no Rerun, Cancel or Run pipeline (the server's caps say so).
const glNoApi = { id: 'gl', url: 'https://gitlab.example', repos: ['gl:g/p'], caps: { rerun: false, rerun_failed: false, cancel: false, dispatch: false, workflows: false } };
assert.deepEqual(runActs(true, glNoApi), []); assert.deepEqual(runActs(false, glNoApi), []); assert(!can(glNoApi, 'dispatch'));
// Forge-aware Repos page, banners and job text.
const X = new Function('esc', ['tip', 'FN', 'fname', 'forgeOf', 'GL_SCOPES', 'glScopes', 'daysLeft', 'repoPath', 'jobEnd', 'jobMins', 'fl', 'kindOf', 'mixed', 'fbadge', 'forgeByKey', 'keyPath', 'repoText', 'repoLabel', 'labelHint', 'credsOk', 'ghErr', 'ciSnippet', 'sizeNote', 'otherMins', 'repoErr', 'forgeBanners'].map(grab).join('\n') +
  '\nreturn { fl, kindOf, mixed, fbadge, forgeByKey, keyPath, repoText, repoLabel, labelHint, credsOk, ghErr, ciSnippet, sizeNote, otherMins, repoErr, forgeBanners };')(esc);
const gl1 = { id: 'gitlab', kind: 'gitlab', url: 'https://gitlab.example', repos: ['gitlab:g/s/p'], health: null, auth: { source: 'file', scopes: ['create_runner', 'manage_runner', 'read_api'] } };
const ge1 = { id: 'gitea', kind: 'gitea', url: 'https://gitea.example', repos: ['gitea:o/n'], health: null, auth: { source: 'env' } };
const gh1 = { id: 'github', kind: 'github', url: 'https://github.com', repos: ['acme/demo'], health: null, auth: {} };
const FF = [gh1, gl1, ge1], NOW = Date.UTC(2027, 9, 11, 12) / 1000;
assert.equal(X.fl(gl1), 'GitLab'); assert.equal(X.fl({ ...gl1, id: 'corp' }), 'GitLab (corp)'); assert.equal(X.fl(undefined), 'the forge');
assert.equal(X.kindOf(FF, 'gitlab:g/s/p'), 'gitlab'); assert.equal(X.kindOf(FF, 'ACME/demo'), 'github'); assert.equal(X.kindOf(null, 'gitlab:g/p'), 'github', 'GitHub until forges load');
assert(X.mixed(FF) && !X.mixed([gh1]) && !X.mixed(null), 'badges only when more than GitHub is served');
assert.equal(X.fbadge(ge1), '<span class="fb">Gitea</span>'); assert.equal(X.fbadge(undefined), '');
assert(!X.credsOk([gh1], false) && X.credsOk([gh1], true) && X.credsOk(FF, false), 'a GitLab token is a credential too');
assert(!X.credsOk([gh1, { ...gl1, auth: { source: 'none' } }], false));
// GitHub's banners read only GitHub's errors once other forges are served.
const P = { error: 'gitlab:g/s/p: HTTP 401; acme/demo: rate', repo_errors: { 'gitlab:g/s/p': 'HTTP 401', 'acme/demo': 'rate' } };
assert.equal(X.ghErr(P, [gh1]), P.error, 'GitHub-only: unchanged'); assert.equal(X.ghErr(P, FF), 'acme/demo: rate'); assert.equal(X.ghErr({ error: null }, FF), '');
assert.equal(X.ghErr({ error: 'boom' }, null), 'boom');
assert(X.ciSnippet('gitlab', 'kiln').includes('tags: [kiln]') && X.ciSnippet('gitea', 'kiln').includes('runs-on: [kiln]\n') && X.ciSnippet('github', 'kiln').includes('runs-on: [self-hosted, kiln]'));
assert(X.sizeNote('gitlab', 'kiln', 2).includes('tags: [kiln-2cpu]') && X.sizeNote('gitea', 'kiln', 2).includes('runs-on: [kiln-2cpu]') && X.sizeNote('github', 'kiln', 4).includes('Default is 4 vCPUs'));
// Only non-GitHub minutes, this month, by forge name.
// Usage-ledger rows [utc day, forge id, jobs, minutes]; the forge id maps to its kind's name, older days are left out.
assert.deepEqual(X.otherMins([[10, 'gitlab', 1, 2], [11, 'gitlab', 1, 3], [10, 'gitea', 1, 1], [9, 'gitea', 4, 40]], FF, 10), { GitLab: 5, Gitea: 1 });
assert.deepEqual(X.otherMins([], FF, 0), {});
assert.deepEqual(X.otherMins(undefined, FF, 0), {});
// The repo page names the forge in its errors; GitHub's text is unchanged.
const er = (c, f, app) => X.repoErr(new Error('GET x: ' + c), f, app);
assert.equal(er('404', gh1, false), 'Repo not found or token lacks access.'); assert.equal(er('404', gh1, true), 'Repo not found, or the GitHub App is not installed on it.');
assert.equal(er('401', gh1, false), 'GitHub rejected the token. Replace it in Settings › Forges.');
assert.equal(er('401', gl1, false), 'GitLab rejected the token. Replace it in Settings › Forges.'); assert.equal(er('404', ge1), 'Project not found, or the Gitea token lacks access.');
assert.equal(er('500', gl1), 'GET x: 500');
// Per-forge banners: each names its forge; GitHub gets none here.
const bn = (F, p, vms = []) => X.forgeBanners(F, { repo_errors: {}, fork_queued: [], ...p }, vms, NOW).map(b => b.slice(0, 2).join(' | '));
assert.deepEqual(bn([gh1], {}), []); assert.deepEqual(bn(null, {}), []); assert.deepEqual(bn(FF, {}), []);
assert.deepEqual(bn([{ ...gl1, auth: { source: 'none' } }], {}), ["fail | GitLab: no token. kiln can't see its queued jobs."]);
assert.deepEqual(bn([{ ...gl1, health: 'GitLab rate limit: paused until 5' }], {}), ['warn | GitLab rate limit: paused until 5'], 'the forge is named once');
assert.deepEqual(bn([{ ...gl1, health: 'cannot reach it' }], {}), ['warn | GitLab: cannot reach it']);
assert.deepEqual(bn(FF, { repo_errors: { 'gitlab:g/s/p': 'HTTP 401 x', 'acme/demo': '401' } }), ['fail | GitLab rejected the token. Replace it in Settings › Forges.']);
assert.deepEqual(bn(FF, { repo_errors: { 'gitea:o/n': 'could not reach gitea.example' } }), ['warn | Gitea: o/n: could not reach gitea.example']);
assert.deepEqual(bn([{ ...gl1, auth: { source: 'file', scopes: ['read_api'] } }], {}), ['fail | GitLab: the token lacks create_runner, manage_runner.']);
assert.deepEqual(bn([{ ...gl1, auth: { ...gl1.auth, expires: '2027-10-14' } }], {}), ['fail | GitLab token expires in 3 days. Rotate it before then.']);
assert.deepEqual(bn([{ ...gl1, auth: { ...gl1.auth, expires: '2027-10-20' } }], {}), ['warn | GitLab token expires in 9 days. Rotate it before then.']);
assert.deepEqual(bn([{ ...gl1, auth: { ...gl1.auth, expires: '2027-10-10' } }], {}), ['fail | GitLab token has expired. Rotate it before then.']);
const mint = (repo, note, x = {}) => ({ repo, mint_failed: true, ended: NOW - 60, note, ...x });
assert.equal(bn(FF, {}, [mint('gitlab:g/s/p', 'runner registration failed: GitLab returned HTTP 403: the token user must be at least Maintainer')])[0].split(' | ')[1].startsWith('GitLab: kiln cannot create a runner in g/s/p.'), true);
assert(bn(FF, {}, [mint('gitea:o/n', 'runner registration failed: Gitea returned HTTP 403 (registration-token): must be repo owner')])[0].includes('Gitea: kiln cannot register a runner for o/n. The service account must own'));
assert.deepEqual(bn(FF, {}, [mint('gitlab:g/s/p', 'Maintainer', { ended: NOW - 7200 })]), [], 'an old failure is gone');
assert.deepEqual(bn(FF, {}, [{ repo: 'gitlab:g/s/p', ended: NOW }, mint('gitlab:g/s/p', 'Maintainer')]), [], 'only the newest VM of a repo counts');
assert.deepEqual(bn(FF, {}, [mint('gitlab:g/s/p', 'lacks the create_runner scope')]), [], 'a scope failure is not a role failure');
assert.deepEqual(bn(FF, { fork_queued: ['gitea:o/n'] }), ['warn | Gitea · o/n: a pull request from a fork is waiting. kiln refuses it, and a VM that is handed it is killed; close or cancel it on Gitea to stop that.']);
// UI-FIX: a refused job is its own status, never a failure; one repo label everywhere; alerts merge per forge.
const refusedVm = (x = {}) => ({ state: 'killed', busy_since: 1, note: 'refused: pull request from a fork', verdict: ['refuse', '7'], ...x });
const { status: st2, isFail: fail2, stTip: tip2 } = new Function('mixed', 'F', ['refusedBy', 'refusedWhy', 'status', 'isFail', 'stTip'].map(grab).join('\n') + '\nconst STATE = { refused: [0, "declined on purpose"] };\nreturn { status, isFail, stTip };')(() => false, null);
assert.equal(st2(refusedVm()), 'refused'); assert.equal(st2(refusedVm({ verdict: undefined })), 'refused', 'the note alone is enough');
assert.equal(st2(refusedVm({ note: 'x', verdict: ['refuse', '7'] })), 'refused', 'the verdict alone is enough');
assert.equal(st2({ state: 'killed', busy_since: 1, note: 'job timeout' }), 'killed'); assert(fail2({ state: 'killed', busy_since: 1, note: 'job timeout' }));
assert(!fail2(refusedVm()), 'a refusal is not a failure: no count, no title flip, no alert');
assert.equal(st2({ state: 'done', result: 'failure', note: 'refused: x' }), 'failed', 'only a killed VM can be a refusal');
// Alerts: tiers, the top of the list first, one card per forge, dismissed ones gone.
const { bnMerge } = new Function('esc', ['bnMerge'].map(grab).join('\n') + '\nreturn { bnMerge };')(esc);
const nm = id => ({ gl: 'GitLab', github: 'GitHub' })[id];
const it = (t, msg, o = {}) => ({ t, col: 'warn', msg, act: '', ...o });
const mg = (items, gone = () => false) => bnMerge(items, gone, nm);
assert.deepEqual(mg([it(2, 'fyi'), it(1, 'act'), it(0, 'block'), it(1, 'act2')]).map(i => i.msg), ['block', 'act', 'act2', 'fyi'], 'by tier, the order kept inside one');
assert.deepEqual(mg([it(2, 'update', { dismiss: 'u1' }), it(1, 'x')], k => k === 'u1').map(i => i.msg), ['x'], 'dismissed');
const one = mg([it(1, 'GitLab: the token expired', { forge: 'gl' }), it(0, 'Down', { forge: 'gl', col: 'fail' }), it(1, 'c')]);
assert.equal(one.length, 2, 'two GitLab problems are one card'); assert.equal(one[0].t, 0, 'the card takes its worst tier'); assert.equal(one[0].col, 'fail');
assert(one[0].msg.includes('GitLab needs attention') && one[0].msg.includes('<li>The token expired</li>') && one[0].msg.includes('<li>Down</li>') && one[0].act.includes('Open the GitLab card'));
assert.equal(mg([it(1, 'only', { forge: 'gl', act: '<a>Forges</a>' })])[0].act, '<a>Forges</a>', 'a lone problem keeps its own text and button');
assert.equal(mg([it(1, 'a', { forge: 'gl' }), it(1, 'b', { forge: 'github' }), it(1, 'c', { forge: 'gl' })]).length, 2, 'one card per forge');
// One label for a repo: path without the forge prefix, a chip only on a mixed box.
const rl = (F, k) => X.repoLabel(F, k), rt = (F, k) => X.repoText(F, k);
assert.equal(X.keyPath(FF, 'gitlab:g/s/p'), 'g/s/p'); assert.equal(X.keyPath(FF, 'acme/demo'), 'acme/demo'); assert.equal(X.keyPath(FF, 'gitea:gone/x'), 'gone/x', 'a project no longer listed keeps its prefix rule');
assert.equal(X.keyPath(null, 'gitlab:g/p'), 'gitlab:g/p', 'forges not loaded: the key as it is');
assert.equal(rt(FF, 'gitlab:g/s/p'), 'GitLab · g/s/p'); assert.equal(rt(FF, 'acme/demo'), 'GitHub · acme/demo', 'a mixed box names GitHub too, so a list reads the same all the way down');
assert.equal(rt([gh1], 'acme/demo'), 'acme/demo');
assert(rl(FF, 'gitlab:g/s/p').includes('<span class="fb">GitLab</span>g/s/p') && rl(FF, 'gitlab:g/s/p').includes('data-tip="gitlab:g/s/p"'), 'chip, clean path, full key in the tip');
assert.equal(rl([gh1], 'acme/demo'), '<span class="rl">acme/demo</span>', 'GitHub alone: no chip');
// What a job writes to opt in, per forge served.
assert.equal(X.labelHint([gh1], 'kiln'), 'Jobs opt in with runs-on: [self-hosted, kiln]'); assert.equal(X.labelHint(null, 'kiln'), 'Jobs opt in with runs-on: [self-hosted, kiln]');
assert.equal(X.labelHint(FF, 'kiln'), 'Jobs opt in with GitHub: runs-on: [self-hosted, kiln] · GitLab: tags: [kiln] · Gitea: runs-on: [kiln]');

// Smoke: run the page's own script on a stub DOM and mount every setup path (GitHub, GitLab, Gitea) and every Settings group,
// so a page that throws while it draws (the blank setup wizard, once) fails here and not in a user's browser.
{
  const main = [...src.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]).pop();
  const tail = "$('#fav').href = FAV(null);\nroute(); poll();";
  assert(main.includes(tail), 'the page still ends by routing and polling');
  const els = new Map(), box = () => {
    const o = { dataset: {}, style: {}, classList: { add() {}, remove() {}, toggle() {}, contains: () => false }, querySelectorAll: () => [], querySelector: s => qs(s), closest: () => null, matches: () => false, contains: () => false,
      getAttribute: () => null, hasAttribute: () => false, getBoundingClientRect: () => ({ left: 0, top: 0, right: 0, bottom: 0, width: 0, height: 0 }), animate() {}, focus() {}, select() {} };
    return new Proxy(o, { get: (t, k) => k in t ? t[k] : typeof k === 'symbol' || k === 'then' ? undefined : (...a) => box(), set: (t, k, v) => ((t[k] = v), true) });
  }, qs = s => els.get(s) || els.set(s, box()).get(s);
  const serve = { forges: [] }, store = new Map(), ls = { getItem: k => store.get(k) ?? null, setItem: (k, v) => store.set(k, String(v)), removeItem: k => store.delete(k) };
  const doc = { querySelector: qs, querySelectorAll: () => [], addEventListener() {}, createElement: () => box(), createDocumentFragment: () => box(), documentElement: box(), body: box(), hidden: false, activeElement: null, title: '' };
  const g = { document: doc, window: { isSecureContext: false }, location: { hash: '', search: '', hostname: 'box', pathname: '/', protocol: 'http:' }, history: { replaceState() {} }, localStorage: ls, matchMedia: () => ({ matches: false }),
    addEventListener() {}, setInterval: () => 0, setTimeout: () => 0, clearTimeout() {}, requestAnimationFrame: () => 0, cancelAnimationFrame() {}, CSS: { escape: x => x }, navigator: {}, fetch: async u => ({ ok: true, status: 200, text: async () => JSON.stringify(u === '/api/forges' ? serve.forges : {}) }),
    innerHeight: 800, innerWidth: 1000, scrollTo() {}, getComputedStyle: () => ({}), getSelection: () => '', kilnAppearance() {}, Notification: undefined };
  const hooks = `return { pages, G, GROUPS, GUIDES, GROUP_ORDER, GD, HELP, TIPS, TIPL, tipKey, banners, stats, set(s, f) { S = s; F = f; setupForge = null; draft = JSON.parse(JSON.stringify(s.config)); }, setupAs(k) { setupForge = k; } };`;
  const K = new Function(...Object.keys(g), main.replace(tail, hooks))(...Object.values(g));
  const cfg = { listen: '100.64.0.7:7878', repos: ['acme/api'], label: 'kiln', max_vms: 2, vm_cpus: 2, vm_mem_mb: 4096, vm_disk_gb: 40, size_mem_mb: {}, poll_secs: 5, job_timeout_mins: 60, idle_timeout_mins: 10, allowed_users: [], notify_rules: [], docker_mirror: true,
    auto_rebake: true, bake_node_versions: ['24'], bake_apt_packages: [], cache: true, cache_branches: {}, cache_gb: 30, repo_cache_gb: {}, debug_hold_mins: 0, debug_ssh_keys: [], egress: 'open', warm: {}, warm_recycle_mins: 30, auto_update: false,
    update_repo: 'o/k', usage_stats: null, crash_reports: null, stop_grace_secs: 25 };
  const t0 = Math.floor(Date.now() / 1000);
  const vms = [{ id: 'kiln-1', repo: 'acme/api', state: 'done', result: 'Succeeded', job: 'test', started: t0 - 900, busy_since: t0 - 890, done_at: t0 - 800, ended: t0 - 800, cpus: 2, run: { branch: 'main', sha: 'abc1234', event: 'push' } },
    { id: 'kiln-2', repo: 'gitlab:g/p', state: 'killed', job: 'rspec', started: t0 - 600, busy_since: t0 - 590, ended: t0 - 580, note: 'refused: pull request from a fork', verdict: ['refuse', '9'], cpus: 2 },
    { id: 'kiln-3', repo: 'gitea:o/r', state: 'held', job: 'build', started: t0 - 300, busy_since: t0 - 290, hold_until: t0 + 600, ssh: 'ssh -p 2201 runner@100.64.0.7', cpus: 4 }];
  const mkS = (o = {}) => ({ config: cfg, job_label: 'kiln', platform: { os: 'linux', arch: 'x86_64' }, token_set: false, app: null, poll: { queued: {}, repo_errors: {}, refused_forks: {}, fork_queued: [] }, vms: [], notify: { dests: [] }, usage: [], usage_other: [],
    image: null, image_ready: false, baking: false, host: { load: [0, 0, 0], cpus: 8, mem_total_mb: 32768, mem_avail_mb: 20000, disk_free_gb: 100, samples: [] }, version: '0.0.0', mirror: null, caches: {}, update: {}, restart: {}, ...o });
  const fg = (kind, id, x = {}) => ({ id, kind, url: `https://${id}.example`, repos: [], health: null, caps: {}, auth: { source: 'none' }, network: 'public', ...x });
  const boxes = {
    'fresh GitHub': [mkS(), [fg('github', 'github', { repos: ['acme/api'] })]],
    'fresh, forges not loaded yet': [mkS(), null],
    'fresh with a GitLab': [mkS(), [fg('github', 'github'), fg('gitlab', 'gitlab')]],
    'GitLab and Gitea with tokens, running jobs, a refusal': [mkS({ token_set: true, image_ready: true, vms, image: { runner_version: '2.328.0' }, poll: { queued: { 'gitlab:g/p': 1 }, repo_errors: { 'gitea:o/r': 'HTTP 500' }, refused_forks: { 'gitlab:g/p': 1 }, fork_queued: ['gitea:o/r'] } }),
      [fg('github', 'github', { repos: ['acme/api'], auth: { source: 'file' } }), fg('gitlab', 'gitlab', { repos: ['gitlab:g/p'], auth: { source: 'file', scopes: ['read_api'] } }), fg('gitea', 'gitea', { repos: ['gitea:o/r'], auth: { source: 'file' }, launches: false })]],
    'a Mac with the GitHub App': [mkS({ token_set: true, platform: { os: 'macos', arch: 'aarch64' }, app: { id: 1, slug: 'kiln', html_url: 'https://github.com/apps/kiln', repos: ['acme/api'], owner: 'acme' }, update: { flavor: 'macos' } }), [fg('github', 'github', { repos: ['acme/api'] })]],
  };
  for (const [name, [s, f]] of Object.entries(boxes)) {
    const at = what => { try { return what(); } catch (e) { throw new Error(`${name}: ${e.stack.split('\n').slice(0, 3).join(' / ')}`); } };
    serve.forges = f || []; at(() => K.set(s, f));
    for (const kind of ['github', 'gitlab', 'gitea']) at(() => {
      K.setupAs(kind); K.pages.setup.mount(); K.pages.setup.update();
      const body = els.get('#su').innerHTML;
      assert(typeof body === 'string' && (body.includes('class="stp"') || body.includes('ran its first job')), `${kind} setup path draws its steps`);
    });
    for (const grp of Object.keys(K.GROUPS)) at(() => { K.pages.settings.mount({ seg: [grp], q: new URLSearchParams() }); assert(typeof els.get('#set-body').innerHTML === 'string', `settings/${grp} draws`); });
    at(() => { K.banners(); K.stats(); K.pages.overview.mount(); K.pages.jobs.mount({ seg: [], q: new URLSearchParams() }); K.pages.jobs.update(); });
    for (const v of s.vms) at(() => { K.pages.job.mount({ seg: [v.id], q: new URLSearchParams() }); K.pages.job.update(); });
    at(() => { K.pages.repos.mount({ seg: [], q: new URLSearchParams() }); K.pages.repos.update(); });
    for (const gd of K.GUIDES) at(() => K.pages.guides.mount({ seg: [gd[0]], q: new URLSearchParams() }));
  }
  // Help content: every popover has an entry, every link lands on a guide, every tip can be shown.
  const ids = new Set(K.GUIDES.map(g => g[0])), sprite = new Set([...src.matchAll(/<symbol id="i-([a-z0-9-]+)"/g)].map(m => m[1]));
  assert.equal(ids.size, K.GUIDES.length, 'guide ids are unique');
  for (const m of src.matchAll(/\bhq(?:If)?\(\s*(?:[^()'"]*\?\s*)?'([a-z0-9]+)'(?:\s*:\s*'([a-z0-9]+)')?\)/g)) for (const id of [m[1], m[2]].filter(Boolean)) assert(K.HELP[id], `hq('${id}') has a HELP entry`);
  for (const m of src.matchAll(/\bfld\([^\n]*?, '([a-z0-9]+)'(?:, '[^']*')?\)\}/g)) if (!/^(f-|cb-)/.test(m[1])) assert(K.HELP[m[1]], `fld help '${m[1]}' has a HELP entry`);
  for (const [id, h] of Object.entries(K.HELP)) {
    assert(h.length === 3 && h[0] && h[1] && ids.has(h[2]), `HELP.${id} has a title, text and an existing guide (${h[2]})`);
    assert(h[1].length < 520, `HELP.${id} stays a short popover`);
  }
  for (const m of src.matchAll(/#\/guides\/([a-z0-9-]+)/g)) assert(ids.has(m[1]), `a link to guide ${m[1]} resolves`);
  for (const [k, g] of Object.entries(K.TIPL)) assert(ids.has(g), `tip ${k} links to guide ${g}`);
  for (const g of K.GUIDES) {
    assert(g.length === 5 && K.GROUP_ORDER.includes(g[3]), `${g[0]} is in a group`);
    for (const r of g[4]) assert(ids.has(r) && r !== g[0], `${g[0]} relates to a real guide: ${r}`);
    assert(sprite.has(K.GD[g[0]]), `${g[0]} has an icon`);
  }
  for (const grp of K.GROUP_ORDER) assert(K.GUIDES.some(g => g[3] === grp), `group ${grp} has guides`);
  // Search finds a guide by a word in its body.
  K.set(mkS({ token_set: true, image_ready: true, vms }), [fg('github', 'github')]);
  K.pages.guides.mount({ seg: ['start'], q: new URLSearchParams() }); K.pages.guides.find('refused fork');
  assert(els.get('#gres').innerHTML.includes('#/guides/gate'), 'search finds the gate guide'); K.pages.guides.find('zzzqq');
  assert(els.get('#gres').innerHTML.includes('No guide'), 'search says when nothing matches');
  // Every tip key is reachable: some page, in some state, shows it (and none is dead).
  const shown = new Set(), job = id => ({ seg: [id] }), t0j = Math.floor(Date.now() / 1000);
  const seen = (s, f, pk, pg, r) => { K.set(s, f); store.clear(); const k = K.tipKey(pk, pg, r); if (k) shown.add(k); };
  const base = mkS({ token_set: true, image_ready: true, vms }), mixF = [fg('github', 'github'), fg('gitlab', 'gitlab')];
  for (const pk of ['overview', 'jobs', 'repos', 'setup', 'guides']) seen(base, [fg('github', 'github')], pk, {}, { seg: [] });
  for (const grp of Object.keys(K.GROUPS)) seen(base, [fg('github', 'github')], 'settings', { g: grp }, { seg: [] });
  for (const v of vms) seen(base, mixF, 'jobs', {}, job(v.id));
  seen({ ...base, vms: [{ ...vms[0], id: 'plain' }] }, mixF, 'jobs', {}, job('plain'));
  seen(mkS({ token_set: true, image_ready: true, vms, update: { available: true, latest: '9.9.9' } }), mixF, 'overview', {}, { seg: [] });
  seen(mkS({ token_set: true, image_ready: true, vms, job_label: 'kiln-arm64' }), mixF, 'overview', {}, { seg: [] });
  seen(base, mixF, 'jobs', {}, { seg: [] });
  for (const k of Object.keys(K.TIPS)) assert(shown.has(k), `tip ${k} is shown somewhere`);
  for (const k of shown) assert(K.TIPS[k], `shown tip ${k} exists`);
  store.clear(); K.set(base, [fg('github', 'github')]); store.set('kiln-tip-overview', '1');
  assert.equal(K.tipKey('overview', {}, { seg: [] }), null, 'a dismissed tip is not shown again');
}
console.log('dashboard analytics ok');

// Host graphs: a VM's band exists only in the columns of samples that list it, and the
// per-VM sequence number the sampler hands out rotates six colours over consecutive VMs.
{
  const { hvCols, gcol } = new Function(['layers', 'hvCols', 'gcol'].map(grab).join('\n') + '\nreturn { hvCols, gcol };')();
  const smp = (t, ...vms) => ({ t, cpu: 4, mem: 9000, vms: vms.map(([k, id]) => [k, id, 1, 2000]) });
  // vm-a (seq 0) ends after t=4000; vm-b (seq 1) starts at t=8000; one slot throughout.
  const S = [smp(0, [0, 'a']), smp(2000, [0, 'a']), smp(4000, [0, 'a']), smp(6000), smp(8000, [1, 'b']), smp(10000, [1, 'b'])];
  const cols = hvCols(S, 'mem'), has = id => cols.filter(c => c.L.some(l => l.id === id)).map(c => c.t);
  assert.deepEqual(has('a'), [0, 2000, 4000], 'a ended VM has no columns after its last sample');
  assert.deepEqual(has('b'), [8000, 10000], 'a new VM has no columns before its first sample');
  assert(cols.every(c => c.L.at(-1).id === 'h'), 'host sits on top');
  const top = id => cols.filter(c => c.L.some(l => l.id === id)).map(c => c.L.find(l => l.id === id).hi);
  assert(top('a').every(v => v === 2000), 'values are the samples, not carried forward');
  // Two VMs ending together and one starting in the same tick: no step columns, bands still bounded.
  const c2 = hvCols([smp(0, [0, 'a']), smp(2000, [1, 'b'])], 'cpu');
  assert.equal(c2.length, 2); assert.deepEqual(c2.map(c => c.L.map(l => l.id)), [['a', 'h'], ['b', 'h']]);
  const cs = [0, 1, 2, 3, 4, 5, 6, 7].map(gcol);
  assert.equal(new Set(cs.slice(0, 6)).size, 6, 'six distinct colours'); assert.equal(cs[6], cs[0]);
  assert.notEqual(gcol(0), gcol(1), 'consecutive VMs differ even on a 2-slot box');
}

// Build reload: differing builds reload once per build; the guard stops a loop; no build id means no decision.
{
  const { reloadForBuild } = new Function(grab('reloadForBuild') + '\nreturn { reloadForBuild };')();
  assert.equal(reloadForBuild('a', 'b', null), true);
  assert.equal(reloadForBuild('a', 'b', 'b'), false, 'already reloaded for this build');
  assert.equal(reloadForBuild('a', 'b', 'x'), true, 'a guard for an older build does not block');
  assert.equal(reloadForBuild('a', 'a', null), false);
  assert.equal(reloadForBuild(null, 'b', null), false, 'a page without a build id never reloads');
  assert.equal(reloadForBuild('a', undefined, null), false);
}

// setHTML: a poll that renders after navigating away finds no element; that is a no-op, not a throw.
{
  const el = { _h: null, contains: () => false, innerHTML: '', querySelector: () => null };
  const setHTML = new Function('$$', 'document', 'fillTimes', 'popEl', 'popAnchor', 'tipFor', grab('setHTML') + '\nreturn setHTML;')(() => [], { activeElement: null }, () => {}, null, null, null);
  setHTML(null, 'x'); setHTML(undefined, 'x');
  setHTML(el, 'a'); assert.equal(el.innerHTML, 'a');
  el.innerHTML = 'b'; setHTML(el, 'a'); assert.equal(el.innerHTML, 'b', 'unchanged html is skipped');
}
