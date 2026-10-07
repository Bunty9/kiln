# Architecture

kiln is one Rust binary (`kiln serve`) that turns a Linux box into a pool of ephemeral GitHub Actions runners, one KVM virtual machine per job. This page describes the pieces, the life of a job, and the design decisions behind them. For the settings mentioned here see [configuration.md](configuration.md); for the threat model see [../SECURITY.md](../SECURITY.md).

```
   GitHub (REST API)
     ^   |
     |   | poll queued/in_progress runs and jobs (ETag-cached),
     |   | generate-jitconfig, delete runner, job + run details
     |   v
 +--------------------------------------------------------------+
 | kiln serve (one process)                                     |
 |                                                              |
 |  scheduler ---- launch/reap ----> VM supervisor (per VM task)|
 |  (tick every poll_secs)             |  qemu-img overlay      |
 |                                     |  spawn QEMU (or        |
 |  mirror supervisor                  |    rootlesskit+QEMU)   |
 |  (registry on 127.0.0.1:5000)       |  read console, decide  |
 |                                     |  cache commit, cleanup |
 |  web/API  :7878 (axum, embedded     |                        |
 |  dashboard.html, access guard)      |                        |
 +-------------------------------------|------------------------+
             ^  tailnet only            | serial ttyS0 (console + control)
             |                          | serial ttyS1 (steps, unix socket)
          you / browser                 v
                         +--------------------------------+
                         | job VM (Ubuntu 24.04, q35, KVM)|
                         |  disk   = overlay of base.qcow2|
                         |  vdb    = overlay of repo cache|
                         |  kiln-job -> run.sh --jitconfig|
                         |  reaches host as 10.0.2.2      |
                         +--------------------------------+
   base image: `kiln bake` (cloud-init recipe guest/user-data.yaml)
```

## Components

**Scheduler and poller** (`main.rs`). A loop that runs a "tick" every `poll_secs`. Each tick checks the token, rate-limit pause and base image, asks GitHub which jobs are queued, decides how many VMs to launch or drop per repo and size, and publishes the poll status that the dashboard shows. At startup, before the first tick, it deletes offline idle `kiln-*` runners that a crashed kiln left registered.

**GitHub client** (`github.rs`). A small `reqwest` wrapper. GET responses are cached by ETag, so a 304 is free against the rate limit. It tracks `x-ratelimit-*` headers and pauses on a rate-limit 403 or a 429, per auth identity: the token, or in App mode each installation. A paused token stops the whole tick; a paused installation only skips its repos, each with a repo error. It also does JIT config generation, runner deletion, the cache trust lookup, the optional hello PR and the dashboard's proxied calls.

**VM supervisor** (`vm.rs`). One async task per VM. It creates the overlay, spawns QEMU, reads the console, tracks the runner's lifecycle, enforces timeouts, takes the debug-hold decision, commits or discards the cache overlay, and deletes everything when the VM ends. The same module holds the launch gates, the resource budget, the reaper, the egress ruleset and probe, `bake`, and the `doctor` checks.

**Bake** (`vm.rs`, `guest/user-data.yaml`). Builds `images/base.qcow2`: downloads the Ubuntu 24.04 cloud image and its kernel (all together so they match), fetches the latest `actions/runner` release, renders the cloud-init recipe, boots a one-off VM that installs packages, the runner and Node (each tarball checked against nodejs.org's `SHASUMS256.txt`), then freezes the result. Image and kernel are swapped in by rename, so a job never sees a half-copied file. `base.json` records the recipe version; kiln launches nothing on an image from an older recipe until it is rebaked.

**Mirror** (`mirror.rs`). Supervises a pinned `registry` binary as a Docker Hub pull-through cache on host loopback. Details under [Docker mirror](#docker-mirror).

**Web and API** (`web.rs`). An axum server that serves the dashboard (one HTML file embedded in the binary with `include_str!`) and a JSON API, behind an access guard. See [API](#api).

**Guest scripts** (inside `guest/user-data.yaml`, installed in the image). `kiln-job` is the boot entry: it reads the JIT config, runs one job and powers off. `kiln-steps` copies the runner's live step logs to the second serial port. `kiln-cache` formats and bind-mounts the cache disk. `kiln-prejob.sh` is the runner's job-started hook: it fails a job whose event is a pull request, or a `workflow_run` triggered by one, from another repository. `kiln-bake` is the one-time setup.

## Job lifecycle

1. **Queued.** The scheduler sees a queued job whose labels are ours (see [Sizes](#sizes)).
2. **Decision.** If the repo has more queued jobs of that size than VMs that are booting or idle, and the gates and budget allow, it launches the difference.
3. **JIT config.** kiln calls `generate-jitconfig` for the repo with a name like `kiln-<unix time>-<seq>` and the labels for that VM's size. The result is a single-use, auto-deregistering runner. The config is written to `<vm>/jit` with mode 0600 and handed to the guest as an SMBIOS OEM string (`-smbios type=11,path=...`): that works with the stock cloud kernel, and `path=` keeps it out of `ps`. kiln deletes the file as soon as the guest prints its first console line, which proves QEMU has read it. This happens before the VM's directory exists and before any disk or QEMU: if GitHub refuses (or does not answer), the attempt costs one API call, the VM record ends `failed` with a note like "runner registration failed: GitHub returned HTTP 500 (generate-jitconfig)", and nothing is left on disk (the record is kept in memory only, marked `mint_failed`, and only the latest 5 are kept; the dashboard does not count them as job failures or notify about them).
4. **Overlay.** `qemu-img create` makes `disk.qcow2` backed by `base.qcow2`. If caching is on, a second overlay backed by the repo's cache disk is attached as `vdb`.
5. **Boot.** QEMU (q35, KVM, `-cpu host`, virtio disk, virtio-net on user-mode networking, virtio-rng) boots `base.vmlinuz` directly with no initrd. virtio and ext4 are built into the Ubuntu kernel, which gets the runner listening in about 4 seconds. `panic=1` and `-no-reboot` make a kernel panic end the VM instead of hanging. Overlay disks use `cache=unsafe` because they are thrown away anyway.
6. **Runner.** `kiln-job` runs `run.sh --jitconfig` as user `runner`. The runner prints "Listening for Jobs" (VM state becomes idle), then GitHub assigns it a job ("Running job", state busy), and finally "completed with result: ..." ends it.
7. **Result.** When the runner exits, the guest prints `kiln: decide`. kiln answers `release` (or `hold N` for the [debug hold](#debug-hold-and-the-control-channel)) and the guest powers off through sysrq. QEMU exits and closes stdout, which ends the supervisor loop.
8. **Cache.** The overlay is merged into the repo cache or discarded (see [Cache](#cache)).
9. **Cleanup.** Whatever happened, kiln deletes the disk overlay, the JIT file, the nft file, sockets and the rootlesskit state, then records the end state:
   - `done`: the runner reported a result (even a failed job is `done`; the verdict is in `result`).
   - `failed`: kiln, the host or GitHub broke (runner registration refused, QEMU exited non-zero, a job started but the runner exited without a result, the runner exited before coming online, boot timeout).
   - `unneeded` (shown as "not needed"): the runner came online but no job reached it, because the queued job went to another runner or was cancelled, and it exited. Not a failure: the dashboard does not count it, and it does not feed the backoff.
   - `killed`: killed from the dashboard, by a timeout, by the reaper, or by shutdown.
   - `lost`: it was active when kiln stopped uncleanly.
   
   A runner that never ran a job is deleted from GitHub so it does not linger offline. A VM that failed without running any job counts toward the repo's [backoff](#backoff).

`console.log` and `steps.log` stay in `vms/<id>/` along with `meta.json`.

## Scheduling

### Demand by count

GitHub gives a queued job to any idle runner whose labels match, not necessarily to the runner kiln started for it. So kiln never matches VMs to job ids. Per repo and per VM size it computes:

```
launch = queued - (booting + idle)
```

capped by free `max_vms` slots. The poll lists runs with `status=queued` and `status=in_progress` (a run is in progress while its later jobs still wait) and then each run's jobs, counting a job only once. Jobs for a size larger than the host's thread count are ignored. Repos are visited starting at a rotating offset so the first repo does not always win scarce slots.

### Sizes

`job_size` accepts a job only if every label is one of the implicit ones (`self-hosted`, `linux`, `x64`) or ours, and exactly one is ours: `<label>` for the default size, or `<label>-<N>cpu` with N in 2, 4, 8, 16 (no leading zeros). RAM for a non-default size is min(N x 2048, 24576) MB; the default size uses `vm_cpus` and `vm_mem_mb`. A VM of N vCPUs registers `self-hosted, linux, x64, <label>-Ncpu`, and also `<label>` only when N equals `vm_cpus`, so a big VM never takes a default job while the default VM can also serve `<label>-<vm_cpus>cpu`.

### Gates and budgets

Before launching, a tick applies:

- **Launch gate.** Not enough memory (`MemAvailable` below the size's RAM plus 1 GB) or low disk (under 15 GB free) blocks launching and shows a banner. The disk message names the Docker mirror and repo cache sizes, the usual reclaimable hogs.
- **Egress gate.** In filtered mode, a failing egress probe blocks all launches.
- **Budget.** QEMU allocates guest RAM lazily, so `MemAvailable` alone lets a burst overcommit. The budget counts what active VMs have committed: memory is total RAM minus committed minus a 2 GB reserve, and vCPUs may oversubscribe the host's threads by 1.5x because CI load is bursty. A tick grants no more VMs than both allow.
- **`max_vms`** caps the number of active VMs; `0` pauses launching.

### Backoff

When a VM ends `failed` without ever having run a job, the repo's launches pause for 30 s x 2^fails seconds (so 60, 120, 240, 480, then a 900 s ceiling). A VM that runs a job clears the repo's backoff. The dashboard shows the retry time. A runner registration GitHub refuses with a 4xx (a missing permission, say) is such a per-repo failure.

A registration that fails with a 5xx, or that cannot reach GitHub, is GitHub's problem rather than the repo's: retrying another repo or job would fail the same way. It pauses **all** launches, warm ones included, for 1, 2, 5, then 10 minutes (capped) per consecutive failure, and does not touch the per-repo backoff. Once a pause is over kiln launches one VM as a probe (one mint attempt per step), not the whole queue; the rest wait until a registration succeeds. Each step is logged once at warn level. The first successful registration clears it. While paused, or while jobs are queued, `poll.blocked` says "GitHub is rejecting runner registration (HTTP 500) — launches paused, retrying in N min" with `blocked_kind` `github_api`, and the Overview shows it as a banner. GitHub's status page may show nothing during such an outage.

### Reaper

Surplus idle VMs (more waiting VMs than queued jobs plus the warm target) are dropped, oldest first, but only ones online for at least 30 seconds and not yet attached to a job. Deregistering the runner is the arbiter: if GitHub refuses because the runner just got a job, the VM lives. This covers cancelled jobs and jobs another runner took.

### Warm pool

`warm: {"owner/name": N}` keeps N idle default-size VMs ready per repo, so a job starts in about a second. Each tick launches `queued + N - waiting`. Idle warm VMs older than `warm_recycle_mins` are replaced, and their idle timeout is that plus 5 minutes. Warm launches wait while a cache commit is running or parked so that replacements boot on the new cache. If a parked commit is only blocked by idle job-less readers, kiln recycles those readers. A warm VM's `warm` flag clears when it takes a job.

### Security-policy recycling

Each VM records a fingerprint of the boot-time settings that matter for security (egress mode, debug SSH keys, whether failures are held). Idle VMs that have not taken a job and whose fingerprint differs from the current settings are deregistered, so an open-egress VM cannot pick up a job after you switched to filtered, nor can a VM carrying a removed SSH key.

### Timeouts

Not busy: `idle_timeout_mins` from VM start, which covers boot as well as waiting (the note says "boot timeout" if the runner never came online, "idle timeout" if it did). Busy: `job_timeout_mins` from the runner's "Running job". Held: the hold end plus 60 seconds. All of them are capped by a **hard lifetime cap** of (idle + job + hold) x 60 + 300 seconds from start, regardless of what the console says.

## Cache

Each repo has one persistent cache disk, `cache/<owner>__<name>.qcow2`, created blank at `cache_gb` virtual size. The guest formats it on first use and bind-mounts it over `/var/lib/docker`, `~/.cache`, `~/.npm`, `~/.cargo`, `~/.rustup`, `~/go/pkg/mod`, `~/.gradle/caches`, `~/.m2/repository` and `/var/cache/apt/archives`. `/opt/hostedtoolcache` is not cached because the baked Node versions (`bake_node_versions`) live there. Docker layers, package downloads and the Rust toolchain are therefore warm with no `actions/cache` round trip.

### Trust model: trusted writer, throwaway readers

Every job VM gets its own private qcow2 overlay of the repo's cache as a second disk. Any job (PR or branch) starts warm and many can run at once. kiln merges an overlay back (`qemu-img commit`) only if all of these hold:

- `cache` is enabled and the job succeeded on the console;
- GitHub's API reports the job's conclusion as `success` (the console result is controlled by the job, so it alone never earns a commit; kiln waits up to 30 s for GitHub to record the conclusion);
- the run's event is `push` and its branch is the repo's default branch (looked up through the API, cached for an hour) or one of its `cache_branches`;
- the pushed commit is really on that branch: the branch tip is resolved through `git/ref/heads/<branch>` and the compare API says the commit is identical to it or behind it. A pushed tag named like a writer branch also arrives as `event=push` with that name, and resolving the bare name could pick the tag.

Anything else is discarded with the overlay, and the job page says why ("cache not saved: pull_request event"). This mirrors GitHub's branch-scope rule for `actions/cache`: a PR can read the cache but can never poison it.

### Parking and lock retry

Committing under a live reader would corrupt that reader's overlay, so a trusted overlay is first renamed to `<repo>.pending.qcow2` ("parked"). It is committed as soon as no other active VM of the repo has the cache attached. A newer trusted overlay supersedes a parked one, since every live overlay shares the same base. `qemu-img commit` takes the image write lock before touching anything, so if some QEMU still has the cache open it refuses; kiln recognises that error, leaves the overlay parked, and the next tick retries.

While a commit runs, new jobs of that repo start without the cache and say "cache busy". A failed commit deletes the cache so it starts over. A cache whose allocated size grows past 1.2 x `cache_gb` is deleted after the commit. "Clear" in the dashboard (`POST /api/cache/clear`) deletes the cache and any parked overlay, and is refused while jobs of the repo run.

## Docker mirror

`mirror.rs` downloads the registry v3.1.2 tarball once (pinned URL and SHA-256; a mismatch is refused and not retried until restart), extracts it atomically, writes its config (filesystem storage under `registry/data`, proxy to `https://registry-1.docker.io`, 168 h TTL) and supervises it with restart backoff from 5 s to 60 s. It listens on `127.0.0.1:5000`. Guests reach it as `10.0.2.2:5000` because QEMU user-mode networking maps `10.0.2.2` to host loopback, and the base image's `daemon.json` lists it as a registry mirror, so Docker falls back to Docker Hub if it is down. A broken mirror therefore never breaks a job. Every 10 minutes the supervisor enforces `mirror_gb` by wiping the data directory when over the cap.

## Egress

`egress: "open"` boots QEMU directly with user-mode networking. The guest has full outbound access through the host's NAT, including the LAN and tailnet.

`egress: "filtered"` wraps QEMU as follows, and every step fails closed:

1. The VM's QEMU is started through `rootlesskit --net=slirp4netns`, so it lives in a new, unprivileged network namespace with its own slirp4netns TAP.
2. A shell with `sh -e` first sets `net.ipv4.conf.all.route_localnet=1` and loads a generated nftables ruleset (`egress.nft`). If either fails, QEMU never starts.
3. It then `exec`s QEMU through `setpriv` with all capabilities dropped and `no-new-privs`, so QEMU cannot alter the rules after they are loaded. Without `setpriv` the VM fails closed.

The ruleset has an output chain with policy `drop`. It accepts established traffic and loopback, DNS to slirp's resolver (`10.0.2.3:53`), and the Docker mirror (`10.0.2.2:5000`, only when `docker_mirror` is on). A DNAT rule rewrites the mirror's host-loopback address to slirp4netns's host alias. Then it drops the private and special ranges: `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10` (tailnet), `127.0.0.0/8`, `169.254.0.0/16` (cloud metadata), `172.16.0.0/12`, `192.0.0.0/24`, `192.168.0.0/16`, `198.18.0.0/15` and `224.0.0.0/3`. Outbound SMTP (port 25) is dropped. Finally it accepts IPv4 out of the TAP, which is the public internet. IPv6 is turned off in QEMU's network and has no accept rule. The result: a job reaches the internet, DNS and the mirror, and cannot reach the LAN, the tailnet, the host's own addresses, or any other port on host loopback.

**Readiness probe.** Before any filtered VM launches (cached for 10 minutes, forced when you switch the mode and by `kiln doctor`), kiln starts a probe namespace with the same ruleset and checks that the mirror is reachable, the dashboard port (via `10.0.2.2`) and the tailnet IP are not, and the internet is. It also requires `rootlesskit`, `slirp4netns`, `nft` and `setpriv`. While the probe fails the scheduler launches nothing and says why. It never falls back to open.

## Debug hold and the control channel

The guest's serial console `ttyS0` is QEMU's stdio. Its output is the console log and also kiln's event stream; its input is a host-to-guest control channel.

After the runner exits, `kiln-job` prints `kiln: decide` and waits up to 20 seconds for a line on `ttyS0`:

- `release`: power off.
- `hold <secs>`: write the authorized keys (passed as a second SMBIOS string), generate fresh SSH host keys and print their fingerprints (`kiln: hostkey ...`), start `sshd`, and wait until the time is up or a `release` line arrives.

kiln answers only the first `kiln: decide`; an early one gets `release`, which also forfeits the hold. The hold is granted only when `debug_hold_mins > 0`, a key is configured, a job actually started, and its result was anything other than "Succeeded". While held, the VM's state is `held`, it keeps its memory and its `max_vms` slot, and the dashboard shows the command (`ssh -p 2201 runner@100.73.48.98`) with Release and Kill buttons. Kill sends `release` first for a clean shutdown and kills QEMU five seconds later.

### SSH publish

sshd does not run during jobs. At launch kiln only reserves a port from 2200 to 2299 (no other active VM uses it and the host can bind it), bound to the box's Tailscale IPv4 address or to loopback if Tailscale is down. The port is published to the guest only when the hold starts:

- **Open egress:** `hostfwd_add` through the QEMU monitor socket.
- **Filtered, with `rootlessctl`:** `rootlessctl add-ports` on rootlesskit's API publishes host `<ip>:<port>` to the same port in the namespace.
- **Filtered, no `rootlessctl`:** the forward is set statically at launch (`-p`), so the port is open for the whole life of the VM.

If publishing fails the VM is released instead of held and a note says so. Host keys are not baked into the image, so the fingerprints shown on the job page let you check you reached the right guest (the guest is job-controlled, so this only catches network-level impersonation).

## Console parsing

The runner's console lines drive the VM's state: "Listening for Jobs" (booting to idle), "Running job: <name>" (to busy), "completed with result: <r>". Because a job is root in the guest and can print anything, each step is accepted once and only forward. Lines are read in chunks of at most 64 KiB, and a longer line and its remainder are never parsed. `console.log` and `steps.log` stop growing at 64 MiB while parsing continues. Console lines can shape the timeline but never extend a VM's life beyond the hard cap. Steps output travels over the second serial port (`ttyS1`) to a unix socket that kiln copies into `steps.log`.

## Shutdown and crash recovery

On SIGTERM or SIGINT kiln stops launching, marks active VMs "kiln shutting down", signals every VM's kill notifier and waits up to 20 seconds in total for the supervisors to finish cleanup (delete disk and JIT secret, deregister the runner, persist the record). The systemd unit uses `KillMode=mixed` with `TimeoutStopSec=30`. **Restarting kiln kills running jobs**, so do not restart while jobs are running.

Under systemd, the unit's cgroup kill takes QEMU down with kiln; outside systemd QEMU can outlive a SIGKILLed kiln, and `kiln doctor` reports it as stray. On the next `serve`, any VM recorded as active is marked `lost` and its disk, cache overlay and JIT secret are deleted, and the scheduler's startup sweep deletes offline idle `kiln-*` runners from GitHub. A parked cache overlay survives and is committed by a later tick.

## Self-update

See [configuration.md](configuration.md#updates) for the user-facing side. `update.rs` fetches `repos/{update_repo}/releases/latest` and, on apply, the three assets of this build's flavor (`kiln-X.Y.Z-x86_64-linux[-musl].tar.gz`, `.sha256`, `.sig`) with `Accept: application/octet-stream`. The Ed25519 signature is checked against the key compiled into the binary before anything else, then the SHA-256. `tar -tzf` must list only paths under `kiln-X.Y.Z-.../` with no `..`, and only `kiln-X.Y.Z-.../kiln` is extracted (into `<data>/update/`); it must print `kiln X.Y.Z` for `--version` (so a validly signed old tarball under a new tag is refused). It is copied to `<exe>.new` (mode 755) next to `/proc/self/exe`.

Draining sets `App.draining`: `tick` launches nothing, keeps no warm VMs, treats every waiting VM as surplus (reaped through runner deregistration as usual) and reports "draining" as the blocked reason. When no VM is active and no bake runs (or after the job timeout + 2 minutes), kiln writes `<data>/update/pending.json` `{from, to, attempts: 0}`, hard-links the executable to `<exe>.prev`, renames `<exe>.new` over it, runs the normal shutdown, waits for the mirror registry to stop, and `exec`s the new binary with the same arguments: the PID stays (systemd sees no restart) and every fd std and tokio opened is close-on-exec. If the exec fails it exits 1 so systemd starts the new binary.

At `serve` start, `pending.json` (if its `to` is the running version) gets `attempts + 1`; above 2 the previous binary is renamed back and exec'd, and the reason is kept in `<data>/update/error` for the dashboard. After 60 s of serving, `pending.json` is deleted. A version that hangs without exiting is not detected.

## API

Everything is under the access guard (see [SECURITY.md](../SECURITY.md)). All writes need the `x-kiln` header, and requests from the box itself need `x-kiln-key`.

| Method and path | Purpose |
|---|---|
| `GET /` | The dashboard page |
| `GET /api/state` | Config, token status, GitHub App (`app`: id, slug, owner, accounts, repos, last refresh, error, skipped installations), poll status (queued, errors, backoff, rate limit: the token's, or in App mode the most constrained installation's with each one's in `rates` by installation id; blocked reason and `blocked_kind`: `draining`, `old_image`, `github_api`, `egress`, `memory`, `disk` or `budget`), the last 100 VMs, image info, host stats, mirror status, cache sizes |
| `POST /api/config` | Save settings (validated); returns `{restart_required}` |
| `POST /api/token` | Validate and save a GitHub token |
| `POST /api/app/manifest` | Start the one-click GitHub App creation: returns GitHub's form URL, the manifest and a one-time state |
| `POST /api/app/convert` | Finish it: trade GitHub's code (with the state) for the App's id and key, save them, switch to App mode |
| `POST /api/app` | Use an existing App (id and private key), checked against GitHub before saving |
| `DELETE /api/app` | Remove the App's key and record, back to token auth |
| `POST /api/app/refresh` | Ask GitHub now which repos the App is installed on; returns the `app` object of `/api/state` |
| `GET /api/doctor` | The `kiln doctor` checks |
| `GET /api/log?src=<bake or vm id>&file=<console or steps>&from=<offset>` | Incremental log read (up to 512 KiB per call) |
| `POST /api/vms/{id}/kill` | Kill a VM |
| `POST /api/vms/{id}/release` | End a debug hold early |
| `POST /api/cache/clear` | Delete a repo's cache (`{"repo":"o/n"}`) |
| `GET /api/onboard` | Hello PRs this kiln has opened |
| `POST /api/onboard/hello` | Open a PR adding `.github/workflows/kiln-hello.yml` to a configured repo |
| `POST /api/bake` | Start a bake (202; refused while one runs) |
| `GET /api/update` | Update status: `{current, latest, available, notes, published_at, flavor, state, error, progress, rollback, checked_at, auto, repo}`; `state` is `idle`, `checking`, `downloading`, `verifying`, `draining`, `applying` or `error`. `/api/state` carries a compact copy as `update` |
| `POST /api/update/check` | Check for a release now; returns the status (a failed check is in its `error`). 409 while a check or update runs |
| `POST /api/update/apply` | Download, verify, drain and restart into the latest release (202). 409 while a check or update runs |
| `POST /api/update/cancel` | Stop a draining update and resume launching. 409 unless one is draining |
| `GET /api/tailscale` | Tailscale status and serve config |
| `GET /api/tailscale/netcheck` | `tailscale netcheck` |
| `POST /api/tailscale/ping` | Ping a peer (`{"peer": "..."}`, restricted characters) |
| `POST /api/tailscale/serve` | Turn HTTPS serve on or off (port 8443) |
| `GET, POST /api/gh/{path}` | Allow-listed GitHub proxy: `repos/<configured repo>/actions/` followed by `workflows...`, `runs`, `runs/...` or `jobs/...` |

The GitHub proxy is how the dashboard browses workflows and runs and dispatches, reruns or cancels them without a dedicated endpoint per call. Only GET and POST are proxied.
