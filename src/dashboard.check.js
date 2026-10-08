// Checks the dashboard's analytics helpers without a browser: node src/dashboard.check.js src/dashboard.html
// Each helper is pulled out of the page by name, so renaming one fails here instead of skipping it.
const fs = require('fs'), assert = require('assert');
const src = fs.readFileSync(process.argv[2], 'utf8');
const grab = n => { const m = src.match(new RegExp(`^(?:const ${n} = .*|function ${n}\\([\\s\\S]*?\\n})$`, 'm')); assert(m, n); return m[0]; };
const { pctl, jobMins, timed, outcome, anBuckets } = new Function(
  ['hhmm', 'pctl', 'jobEnd', 'jobMins', 'status', 'isFail', 'timed', 'outcome', 'anBuckets'].map(grab).join('\n') +
  '\nreturn { pctl, jobMins, timed, outcome, anBuckets };')();

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
console.log('dashboard analytics ok');
