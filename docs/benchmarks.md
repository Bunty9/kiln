# Benchmarks

Measured on 2026-10-08 against kiln's own repository. Everything here was
produced by GitHub Actions workflows whose YAML is reproduced below, and every
number comes from either the GitHub API (job and step timestamps) or a line the
job printed itself. The raw data is in [`docs/benchmarks/`](benchmarks/).

## Summary

| Metric | kiln | GitHub-hosted `ubuntu-latest` |
|---|---|---|
| kiln's CI job (fmt, clippy, test, cargo-deny, dashboard check), warm cache | **57 s** median (p95 60, n=11) | 157 s median (p95 168, n=11) |
| Same job, empty toolchain/crate cache | 193 s median (p95 200, n=11) | (same as above: hosted has no persistent cache) |
| VM created to runner "Listening for Jobs" (kiln's VM records) | 10 s median (p95 15, n=100) | n/a |
| Job queued to runner busy, VM booted for the job | 23 s median (p95 47, n=13) | 2 s median (p95 3, n=15) |
| Job queued to runner busy, warm pool (1 pre-booted VM) | 4 s median (p95 10, n=11) | n/a |
| `docker build` of `examples/docker-build`, first build in the job | 2.5 s median (p95 3.0, n=10) | 2.4 s median (p95 8.1, n=10) |
| Same build repeated, layers present | 0.83 s median (p95 0.87) | 0.20 s median (p95 0.30) |
| Download, 100 MiB over HTTPS | 44 Mbit/s median (n=12) | 269 Mbit/s median (n=12) |

The short version: kiln's CI job is about 2.8x faster than on `ubuntu-latest`,
and almost all of that comes from the persistent cache (a prebuilt
`cargo-deny` and the Rust toolchain), not from the CPU. Compile and test time
is about the same on both. With an empty cache kiln is slower than hosted.
Job start-up is about 20 s slower than hosted without a warm pool and a few
seconds slower with one, and network throughput is far lower.

## Setup

**kiln host.** One AMD Ryzen 7 3700X (8 cores, 16 threads) box with 32 GB
RAM (30 GiB usable) on a home connection, running kiln v0.2.4 as a systemd
user service. kiln's data directory (base image, overlays, cache disks) is on
a 512 GB PCIe Gen3 NVMe SSD; the box's two SATA hard disks are not used by
kiln. `max_vms` is 2, so at most two job VMs run at once. It also served
other CI work while these runs were taken (see [Caveats](#caveats)).

**kiln job VM.** The default size: 4 vCPU (`-cpu host`), 8 GB RAM
(7.9 GB visible), 38 GB root overlay on the frozen Ubuntu 24.04 base image
(recipe from `guest/user-data.yaml`, baked by `kiln bake`), and the repo's
persistent cache disk on `/mnt/cache`. Egress mode **filtered**: the
selftest workflow reported the internet and the Docker mirror reachable and the
LAN, tailnet and dashboard blocked, so every VM sits behind rootlesskit and
slirp4netns. Warm pool off (`warm` = `{}`) except for the warm-pool
measurement in section 2. `poll_secs` default 5.

**GitHub-hosted.** `ubuntu-latest` = `ubuntu-24.04` image 20261004.327.1,
4 vCPU Intel Xeon Platinum 8573C, 16 GB RAM, Rust preinstalled.

**Statistics.** Median, p95 (linear interpolation between ranks), min and
max. With n=10 to 15 the p95 is effectively the second-highest sample; read it
as "a bad run", not as a tail estimate. Times from the GitHub API have 1 s
resolution.

## 1. kiln's own CI vs `ubuntu-latest`

**Method.** A temporary workflow (`bench-ci`, below) ran the exact steps of
`.github/workflows/ci.yml`'s `test` job as a three-way matrix: `ubuntu-latest`,
`[self-hosted, kiln]`, and `[self-hosted, kiln]` with `CARGO_HOME` and
`RUSTUP_HOME` pointed at empty directories ("kiln-fresh"). It was triggered by
a push to a non-default branch and then re-run with `gh run rerun` (all jobs,
one attempt at a time): 11 samples per variant over two runs
(37739020357, 37739436747). Duration is the job's `started_at` to
`completed_at` from the GitHub API, which excludes queueing.

**Cache state.** kiln's cache disk is read by every job but written only by
successful pushes to the default branch. These runs were pushes to a feature
branch, so all 11 kiln samples read the same cache, last written by the
`ci` and `Stacks` workflows on `main` the day before: `~/.rustup` holds the
toolchain and `~/.cargo` holds the crate registry and the pinned `cargo-deny`
binary. `target/` is in the workspace, not on the cache disk, so every sample
compiles kiln from scratch. "kiln-fresh" ignores the cache for Rust: rustup,
crates and `cargo-deny` are downloaded and built as in a repo's very first job.
Hosted runners start clean every time; `ci.yml` uses no `actions/cache`.

| Variant | n | median | p95 | min | max |
|---|---|---|---|---|---|
| ubuntu-latest | 11 | 157 s | 168 s | 139 s | 168 s |
| kiln, warm cache | 11 | 57 s | 60 s | 51 s | 61 s |
| kiln, empty cache | 11 | 193 s | 200 s | 187 s | 201 s |

Median per step, seconds:

| Step | ubuntu-latest | kiln warm | kiln empty |
|---|---|---|---|
| Install Rust (rustup) | 2 | 4 | 31 |
| `cargo clippy` | 20 | 16 | 21 |
| `cargo test` | 22 | 20 | 20 |
| Dependency audit (`cargo-deny`) | 102 | 2 | 106 |
| checkout, fmt, dashboard check, setup | 4 | 5 | 5 |

Reading it honestly:

- `cargo install cargo-deny` (about 100 s) is the whole difference. On kiln the
  binary is already on the cache disk. A hosted workflow that installs it
  prebuilt (for example `taiki-e/install-action`) or caches `~/.cargo/bin` with
  `actions/cache` would land near 55 to 60 s, roughly kiln's number.
- Compile and test are within a few seconds of each other: a 4 vCPU slice of a
  2019 desktop CPU is about as fast as a 4 vCPU hosted VM for this crate.
- With an empty cache kiln is about 35 s *slower* than hosted: rustup has to
  download the toolchain (hosted has it preinstalled) through a slower network.

**History.** For context, all 95 successful `ci` `test` jobs on kiln between
2026-10-06 and 2026-10-08 (pushes and pull requests, while `ci.yml` was still
changing) took 48 s (pull requests, n=54) and 54 s (pushes, n=41) median. Raw
data: [`history-jobs.csv`](benchmarks/history-jobs.csv).

## 2. Boot to listening, and job pickup

### VM created to "Listening for Jobs"

**Method.** kiln keeps a record for each VM in `GET /api/state`: `started`
(the VM record is created, just before the runner registration call, the
overlay and QEMU), `online_at` (the runner printed "Listening for Jobs"),
`queued_at` (the job was queued on GitHub), `busy_since` (the runner took a
job) and `done_at`. Boot is `online_at - started`. The table uses all 100
records kiln held at the time (2026-10-08 06:39 to 08:11 UTC): the `bench-ci`
and `bench-boot` jobs above, other sessions' `ci` jobs, and the `selftest`
runs of the pickup measurement below. All are 4 vCPU / 8 GB
VMs in filtered egress mode. Raw data: [`vms.csv`](benchmarks/vms.csv).

| Interval | n | median | p95 | min | max |
|---|---|---|---|---|---|
| VM created to "Listening for Jobs" (kiln's records) | 100 | 10 s | 15 s | 9 s | 36 s |
| Guest kernel start to "Listening for Jobs" (inside the guest) | 15 | 9 s | 10 s | 8 s | 11 s |
| "Listening for Jobs" to "Running job" (inside the guest) | 15 | 4 s | 4 s | 3 s | 4 s |

The second and third rows come from the `bench-boot` workflow below, which
reads the guest's boot time (`btime` in `/proc/stat`) and the first
"Listening for Jobs" and "Running job" lines of the runner's
`_diag/Runner_*.log` (15 samples, runs 37743504516 and 37743719369). They
agree with kiln's records: roughly 1 s of the 10 s is before the guest kernel
starts, the rest is the guest booting and the runner starting. The slow tail
(up to 36 s) is VMs that booted while the other slot was busy; it was not
investigated further.

### Job pickup, with and without a warm pool

**Method.** `selftest.yml` (one short job) was dispatched one run at a time
with `scripts/bench/selftest-loop.sh`, with nothing else of ours queued:

- **cold:** `warm` at its configured value `{}`, 10 s between runs. Every job
  needs a VM booted for it.
- **warm:** `warm` set to `{"Bunty9/kiln": 1}` through `POST /api/config`,
  first run dispatched once the warm VM was idle, 35 s between runs so kiln
  could boot the replacement. The setting was then put back to `{}`, and the
  saved `config.json` was checked to be identical to the copy taken before
  the change; the remaining idle warm VM was reaped.

Pickup is `busy_since - queued_at` from kiln's records. A VM whose `started`
is before its job's `queued_at` was booted before the job existed, which is
how the warm-served jobs are told apart (the record's `warm` flag is cleared
once a warm VM takes a job). The cold set is 13 `probe` jobs (10 dispatched
for this plus 3 other selftest runs in the same window), the warm set 11.

| Pickup (`busy_since - queued_at`) | n | median | p95 | min | max |
|---|---|---|---|---|---|
| VM booted for the job (cold) | 13 | 23 s | 47 s | 17 s | 50 s |
| Warm pool, 1 pre-booted VM | 11 | 4 s | 10 s | 3 s | 15 s |
| GitHub-hosted (`created_at` to `started_at`, GitHub API) | 15 | 2 s | 3 s | 1 s | 3 s |

Cold pickup breaks down as up to one 5 s poll before kiln notices the job,
about 10 s to boot, and 3 to 4 s for GitHub to hand the job to the new runner.
The two cold samples over 40 s waited for a slot: another session's jobs held
both of the box's two VM slots. With a warm VM only the poll and GitHub's
assignment are left. The 15 s warm sample is one where the replacement VM was
still booting when the next run arrived.

Across all 99 jobs in kiln's records (any workflow, any load), pickup was 24 s
median (p95 72, max 209) for jobs that needed a VM booted and 4 s median for
the 12 that found one ready. The GitHub-side view agrees: the `ci` `test` jobs
in [`history-jobs.csv`](benchmarks/history-jobs.csv) waited 22 s median, 325 s
at p95 when several pull requests landed together.

## 3. Docker build with a warm cache

**Method.** `examples/docker-build` is a three-line Dockerfile
(`FROM alpine:3.20`, one `RUN`, a `CMD`), so it measures image pull and
BuildKit overhead, not real build work. In one job, `bench-ci`'s `docker`
matrix times:

1. `docker info` (daemon ready),
2. **first build**: the build as the VM finds it. On kiln the cache disk's
   `/var/lib/docker` was last written by a `main` push of the `Stacks`
   workflow, which builds this same example, so its layers should already be
   there; on hosted nothing is cached and `alpine` comes from Docker Hub,
3. **cold**: after `docker rmi` of every image and `docker builder prune -af`
   (on kiln this pulls `alpine` through the host's Docker Hub mirror),
4. **warm**: the same build again immediately.

On kiln none of this touches the saved cache: feature-branch pushes never
write it. 10 samples (run 37739436747), timed with `date +%s%N` around each
`docker build -q`.

| Build | kiln median | kiln p95 | hosted median | hosted p95 |
|---|---|---|---|---|
| `docker info` | 0.16 s | 0.42 s | 0.32 s | 2.17 s |
| first build (as found) | 2.48 s | 3.03 s | 2.35 s | 8.13 s |
| cold (images and build cache deleted) | 1.13 s | 1.97 s | 1.40 s | 1.76 s |
| warm (repeat) | 0.83 s | 0.87 s | 0.20 s | 0.30 s |

This is not a win for kiln. The first build in a kiln VM is no faster than a
cold pull on hosted, and it is slower than kiln's own cold build: for an image
this small, BuildKit's first start and reading the cache disk cost more than
the layers save. Repeated builds are about 4x slower on kiln (0.83 s vs
0.20 s), most likely the cache disk's qcow2 overlay and bind mount under
`/var/lib/docker`. The cache disk should pay off on images whose layers take
real time to build or pull (apt installs, large base images), but this
benchmark does not show that; a heavier Dockerfile would be the next thing to
measure.

## 4. Network throughput

Same `bench-boot` runs: `curl` the first 100 MiB of the Ubuntu 24.04 cloud
image from `cloud-images.ubuntu.com`, 12 samples each.

| | n | median | p95 | min | max |
|---|---|---|---|---|---|
| kiln (filtered egress, slirp4netns) | 12 | 44 Mbit/s | 46 Mbit/s | 29 Mbit/s | 46 Mbit/s |
| ubuntu-latest | 12 | 269 Mbit/s | 386 Mbit/s | 234 Mbit/s | 406 Mbit/s |

kiln's number is capped by two things this test cannot separate: the box's
home uplink and user-mode networking (slirp), which tops out well below line
rate. Either way, large downloads in a kiln job are several times slower than
on hosted, which is the reason the Docker mirror and cache disk exist.

## Caveats

- **One box, one repo, one day.** All kiln numbers come from a single Ryzen 7
  3700X machine serving kiln's own repository. Other repos' and other people's
  jobs ran on the same box during the measurements; queue times include that.
  The tight spread of the CI durations (51 to 61 s) suggests it did not matter
  much for run time.
- **Small n.** 10 to 15 samples per metric. The medians are stable; the p95s
  are close to the maximum.
- **Home network.** The box is on a residential connection and is reached by
  its operator over a tailnet; jobs themselves cannot reach the tailnet in
  filtered mode. Network-bound steps (rustup, Docker Hub, crates.io) depend on
  that uplink.
- **Shared box, two slots.** With `max_vms` 2, a selftest that arrived while
  another session's jobs held both slots waited for one; that is the 44 to
  50 s tail of the cold pickup numbers.
- **1 s resolution.** kiln's VM records are whole seconds.
- **Hosted variance.** GitHub-hosted runners vary by hardware generation and
  time of day; these were all 4 vCPU Xeon Platinum 8573C runners.
- **Fair comparison.** `ci.yml` was not tuned for hosted runners (no
  `actions/cache`, `cargo-deny` built from source). A tuned hosted workflow
  would be close to kiln's warm time for this job.

## Reproducing

Prerequisites: a repo served by kiln, `gh` authenticated with access to it.
`workflow_dispatch` only works once a workflow exists on the default branch, so
these were run from a branch with a `push` trigger instead.

1. Add the two workflows below on a branch, push it, and let each run once.
2. Re-run until you have enough samples, one attempt at a time:
   `scripts/bench/rerun.sh OWNER/REPO RUN_ID 10`.
3. Collect job timings: `scripts/bench/jobs.py OWNER/REPO RUN_ID ... > jobs.csv`
   (one row per job and attempt, with queue time, run time and every step).
4. Collect the numbers the jobs printed:
   `scripts/bench/bench-lines.sh OWNER/REPO RUN_ID > bench.csv`.
5. Summarize: `scripts/bench/summarize.py jobs.csv run_s job` or
   `scripts/bench/summarize.py bench.csv ms job measure`.

kiln-side numbers, on the kiln box:

```sh
KEY=$(cat ~/.local/share/kiln/dashboard.key)
curl -s -H "x-kiln-key: $KEY" http://127.0.0.1:7878/api/state | scripts/bench/vms.py OWNER/REPO > vms.csv
scripts/bench/summarize.py vms.csv boot_s repo
scripts/bench/summarize.py vms.csv pickup_s vm_ready_before_job
```

Pickup with and without a warm pool: `scripts/bench/selftest-loop.sh OWNER/REPO 10 10`
with `warm` at `{}`, then set `warm` to `{"OWNER/REPO": 1}` (Settings, or
`POST /api/config` with the full config and headers `x-kiln-key` and
`x-kiln: 1`), wait for the idle warm VM, run
`scripts/bench/selftest-loop.sh OWNER/REPO 10 35`, and set `warm` back.

Raw data: [`bench-ci-jobs.csv`](benchmarks/bench-ci-jobs.csv),
[`docker-builds.csv`](benchmarks/docker-builds.csv),
[`bench-boot-jobs.csv`](benchmarks/bench-boot-jobs.csv),
[`boot-net.csv`](benchmarks/boot-net.csv),
[`vms.csv`](benchmarks/vms.csv) (kiln's VM records; other repos anonymized),
[`history-jobs.csv`](benchmarks/history-jobs.csv).
In `boot-net.csv` the `ms` column holds the value in the unit its measure
name says (`_s`, `_mbit`).

### `bench-ci.yml`

```yaml
name: bench-ci
on:
  workflow_dispatch:
  # workflow_dispatch needs the file on main; push to the bench branch instead.
  push:
    branches: [launch-benchmarks]

permissions:
  contents: read

jobs:
  ci:
    strategy:
      fail-fast: false
      matrix:
        include:
          - name: hosted
            runs-on: ubuntu-latest
            fresh: false
          - name: kiln
            runs-on: [self-hosted, kiln]
            fresh: false
          # kiln with an empty toolchain and crate registry: what a repo's
          # first job sees before its cache disk has ever been written.
          - name: kiln-fresh
            runs-on: [self-hosted, kiln]
            fresh: true
    name: ci-${{ matrix.name }}
    runs-on: ${{ matrix.runs-on }}
    steps:
      - name: Facts
        run: |
          nproc; free -m | head -2; lscpu | grep "Model name" || true
          findmnt /mnt/cache >/dev/null && echo "cache disk: yes" || echo "cache disk: no"
          if [ "${{ matrix.fresh }}" = true ]; then
            echo "CARGO_HOME=$RUNNER_TEMP/cargo" >> "$GITHUB_ENV"
            echo "RUSTUP_HOME=$RUNNER_TEMP/rustup" >> "$GITHUB_ENV"
          fi
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
        with:
          persist-credentials: false
      - name: Install Rust
        run: curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal -c clippy,rustfmt
      - name: Format
        run: . "${CARGO_HOME:-$HOME/.cargo}/env" && cargo fmt --check
      - name: Lint
        run: . "${CARGO_HOME:-$HOME/.cargo}/env" && cargo clippy --locked --tests -- -D warnings
      - name: Test
        # Hosted runners may lack Landlock; kiln's own CI requires it.
        env:
          KILN_REQUIRE_LANDLOCK: ${{ matrix.name == 'hosted' && '0' || '1' }}
        run: . "${CARGO_HOME:-$HOME/.cargo}/env" && cargo test --locked
      - name: Dependency audit
        run: |
          . "${CARGO_HOME:-$HOME/.cargo}/env"
          [ "$(cargo deny --version 2>/dev/null)" = "cargo-deny 0.20.2" ] || cargo install cargo-deny --locked --version 0.20.2
          cargo deny --locked check
      - name: Dashboard script
        run: |
          node -e 'const fs = require("fs"); const s = fs.readFileSync("src/dashboard.html", "utf8");
            fs.writeFileSync(process.argv[1], [...s.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]).join("\n;\n"))' "$RUNNER_TEMP/dashboard.js"
          node --check "$RUNNER_TEMP/dashboard.js"

  docker:
    strategy:
      fail-fast: false
      matrix:
        include:
          - name: hosted
            runs-on: ubuntu-latest
          - name: kiln
            runs-on: [self-hosted, kiln]
    name: docker-${{ matrix.name }}
    runs-on: ${{ matrix.runs-on }}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
        with:
          persist-credentials: false
      - name: Docker builds
        run: |
          s=$(date +%s%N); docker info >/dev/null; echo "BENCH docker_info $(( ($(date +%s%N) - s) / 1000000 ))"
          t() { s=$(date +%s%N); docker build -q -t bench examples/docker-build >/dev/null; echo "BENCH $1 $(( ($(date +%s%N) - s) / 1000000 ))"; }
          t as_found
          docker rmi -f $(docker images -aq) >/dev/null 2>&1 || true
          docker builder prune -af >/dev/null
          t cold
          t warm
```

### `bench-boot.yml`

```yaml
name: bench-boot
on:
  workflow_dispatch:
  push:
    branches: [launch-benchmarks]
    paths: [.github/workflows/bench-boot.yml]

permissions: {}

jobs:
  boot:
    runs-on: [self-hosted, kiln]
    steps:
      - name: Boot timeline
        run: |
          d=/home/runner/actions-runner/_diag
          btime=$(awk '/^btime/ {print $2}' /proc/stat)
          listen=$(grep -h "Listening for Jobs" $d/Runner_*.log | head -1 | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:]{8}Z' | head -1)
          job=$(grep -h "Running job:" $d/Runner_*.log | head -1 | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:]{8}Z' | head -1)
          systemd-analyze time || true
          echo "BENCH kernel_to_listening_s $(( $(date -d "$listen" +%s) - btime ))"
          echo "BENCH listening_to_job_s $(( $(date -d "$job" +%s) - $(date -d "$listen" +%s) ))"
          echo "BENCH kernel_to_first_step_s $(( $(date +%s) - btime ))"

  net:
    strategy:
      matrix:
        name: [hosted, kiln]
    name: net-${{ matrix.name }}
    runs-on: ${{ matrix.name == 'hosted' && 'ubuntu-latest' || fromJSON('["self-hosted","kiln"]') }}
    steps:
      # First 100 MiB of the Ubuntu cloud image; on kiln this is bounded by the
      # host's uplink as well as by slirp.
      - name: Download 100 MiB
        run: |
          curl -fsS -o /dev/null -r 0-104857599 -w 'BENCH download_mbit %{speed_download}\n' \
            https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img |
            awk '{ printf "%s %s %.0f\n", $1, $2, $3 * 8 / 1000000 }'
```

The first `bench-ci` run (37739020357) used the same file without the
`docker info` line; its CI jobs are included above, its Docker numbers are not.
