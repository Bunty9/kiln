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
console.log('dashboard analytics ok');
