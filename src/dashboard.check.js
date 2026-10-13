// Checks the dashboard's analytics helpers without a browser: node src/dashboard.check.js src/dashboard.html
// Each helper is pulled out of the page by name, so renaming one fails here instead of skipping it.
const fs = require('fs'), assert = require('assert');
const src = fs.readFileSync(process.argv[2], 'utf8');
const grab = n => { const m = src.match(new RegExp(`^(?:const ${n} = .*|function ${n}\\([\\s\\S]*?\\n})$`, 'm')); assert(m, n); return m[0]; };
const esc = x => String(x);
const { pctl, jobMins, timed, outcome, anBuckets, runStatus, forgeOf, can, runActs, forgeUrl } = new Function('esc',
  ['hhmm', 'pctl', 'jobEnd', 'jobMins', 'status', 'isFail', 'timed', 'outcome', 'anBuckets', 'runStatus', 'forgeOf', 'can', 'runActs', 'forgeUrl'].map(grab).join('\n') +
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
// Forge-aware Repos page, banners and job text (X-5).
const X = new Function('esc', ['FN', 'forgeOf', 'GL_SCOPES', 'glScopes', 'daysLeft', 'repoPath', 'jobEnd', 'jobMins', 'fl', 'kindOf', 'mixed', 'fbadge', 'credsOk', 'ghErr', 'ciSnippet', 'sizeNote', 'otherMins', 'repoErr', 'forgeBanners'].map(grab).join('\n') +
  '\nreturn { fl, kindOf, mixed, fbadge, credsOk, ghErr, ciSnippet, sizeNote, otherMins, repoErr, forgeBanners };')(esc);
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
const vm = (repo, a, b) => ({ repo, busy_since: a, done_at: b });
assert.deepEqual(X.otherMins([vm('acme/demo', 100, 200), vm('gitlab:g/s/p', 100, 161), vm('gitea:o/n', 100, 130), vm('gitlab:g/s/p', 1, 2), { repo: 'gitlab:g/s/p', busy_since: 100 }], FF, 50), { GitLab: 2, Gitea: 1 });
assert.deepEqual(X.otherMins([vm('acme/demo', 100, 200)], FF, 0), {});
// The repo page names the forge in its errors; GitHub's text is unchanged.
const er = (c, f, app) => X.repoErr(new Error('GET x: ' + c), f, app);
assert.equal(er('404', gh1, false), 'Repo not found or token lacks access.'); assert.equal(er('404', gh1, true), 'Repo not found, or the GitHub App is not installed on it.');
assert.equal(er('401', gh1, false), 'GitHub rejected the token. Replace it in Settings › Forges.');
assert.equal(er('401', gl1, false), 'GitLab rejected the token. Replace it in Settings › Forges.'); assert.equal(er('404', ge1), 'Project not found, or the Gitea token lacks access.');
assert.equal(er('500', gl1), 'GET x: 500');
// Per-forge banners: each names its forge; GitHub gets none here.
const bn = (F, p, vms = []) => X.forgeBanners(F, { repo_errors: {}, fork_queued: [], ...p }, vms, NOW).map(b => b.join(' | '));
assert.deepEqual(bn([gh1], {}), []); assert.deepEqual(bn(null, {}), []); assert.deepEqual(bn(FF, {}), []);
assert.deepEqual(bn([{ ...gl1, auth: { source: 'none' } }], {}), ["fail | GitLab: no token. kiln can't see its queued jobs."]);
assert.deepEqual(bn([{ ...gl1, health: 'GitLab rate limit: paused until 5' }], {}), ['warn | GitLab: GitLab rate limit: paused until 5']);
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
assert.deepEqual(bn(FF, { fork_queued: ['gitea:o/n'] }), ['warn | gitea:o/n: a pull request from a fork is waiting; approve or close it on Gitea, or kiln will not start runners for this repo.']);
console.log('dashboard analytics ok');
