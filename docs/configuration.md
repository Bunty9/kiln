# Configuration reference

kiln keeps its settings in `config.json` inside its data directory. You normally edit them from the dashboard (Settings), which calls `POST /api/config`. You can also edit the file by hand and restart kiln.

## How the file is handled

- Location: `<data>/config.json`, where `<data>` is `$KILN_DATA` or `~/.local/share/kiln`.
- A missing file means all defaults. A partial file is fine: every field has a default, and unknown fields are ignored.
- The dashboard saves the whole object atomically (write to `config.json.tmp`, then rename) after validating it. A rejected save returns the reason and changes nothing.
- On startup kiln validates the file with the same rules as a dashboard save and refuses to start if it is invalid (so a typo like `"egress": "Filtered"` can never quietly mean open networking). The error names the field.
- Changes made from the dashboard apply to the running process. Hand edits need a restart.

"Live" below means a change from the dashboard takes effect without restarting kiln. VMs that are already running keep the values they booted with (for example the timeouts and the memory size), unless noted.

## Fields

### Core

| Field | Type | Default | Valid values | Applies | What it does |
|---|---|---|---|---|---|
| `listen` | string | `"0.0.0.0:7878"` | `host:port` socket address | restart | Address the dashboard and API bind to. The dashboard refuses anything that is not a tailnet peer or the box itself regardless of the bind address, but prefer a narrower address if the box has a public interface. After saving a new address the Overview shows "Restart needed to apply: listen" with **Restart when idle** (see [Restarting kiln](#restarting-kiln)). kiln test-binds a new address before saving it and again before a restart, and refuses one it could not serve on (not an address of this machine, a port below 1024, a port another program holds). If the configured address still cannot be bound at startup (an interface that went away, a hand edit), kiln serves on the last address that worked (`<data>/listen.last`) or else `127.0.0.1:7878`, logs it, and shows "listen X could not be bound (...); serving on Y" on the Overview. |
| `repos` | string array | `[]` | `owner/name`, using letters, digits, `-`, `_`, `.`; no duplicates (case-insensitive) | live | Repositories kiln serves jobs for. |
| `label` | string | `"kiln"` | non-empty; `A-Z a-z 0-9 _ . -` | live (new VMs) | Label jobs put in `runs-on`. VMs also register `<label>-<N>cpu`. |
| `allowed_users` | string array | `[]` | Tailscale login names | live | Tailnet users allowed to use the dashboard. Empty means only the owner of the CI box. Nodes tagged `tagged-devices` get in only if you list `tagged-devices` explicitly. |

### Capacity and sizes

| Field | Type | Default | Valid values | Applies | What it does |
|---|---|---|---|---|---|
| `max_vms` | integer | `2` | `0` to `64` | live | Maximum VMs at once (booting, idle, busy or held). `0` pauses launching; polling and everything else continues, and warm VMs are not kept. |
| `vm_cpus` | integer | `4` | `1` to the host's thread count | live (new VMs) | vCPUs of the default size, the one plain `[self-hosted, kiln]` gets. Also used by `kiln bake` for the bake VM. |
| `vm_mem_mb` | integer | `8192` | at least `1024` | live (new VMs) | RAM in MB of the default size. Other sizes use min(N x 2048, 24576) MB unless `size_mem_mb` says otherwise. The bake VM uses at least 4096. |
| `size_mem_mb` | object | `{}` | vCPU count (`1` to the host's threads) to MB (`1024` to `1048576`) | live (new VMs) | Memory of a non-default size, e.g. `{"8": 12288}` for an 8 vCPU / 12 GB VM on a box shared with a desktop. The default size always uses `vm_mem_mb`. Set in Settings › Capacity as `8=12` (GB). |
| `vm_disk_gb` | integer | `40` | at least `10` | next bake | Virtual size of the guest disk. It is applied when the base image is baked (the image is resized then); job overlays inherit it. Rebake after changing it. |

### Polling and timeouts

| Field | Type | Default | Valid values | Applies | What it does |
|---|---|---|---|---|---|
| `poll_secs` | integer | `5` | at least `3` | live | Seconds between GitHub polls. 304 responses do not count against the rate limit, so 5 is cheap. When under 20% of the rate limit is left kiln slows to every 30 s; after a rate-limit 403 or a 429 it pauses until GitHub says to resume. With a GitHub App each installation has its own limit: only the repos of the limited installation pause (shown as a repo error), the rest keep polling, and the 20% check uses the most constrained installation. |
| `job_timeout_mins` | integer | `60` | `1` to `1440` | live (VMs started after the change) | Longest a job may run, counted from when the runner reports "Running job". |
| `idle_timeout_mins` | integer | `10` | `1` to `1440` | live (VMs started after the change) | A VM that never gets a job (boot included) is killed after this. |
| `stop_grace_secs` | integer | `25` | `0` to `570` | live | On SIGTERM (`systemctl stop` or `restart`), how long running jobs get to finish before their VMs are killed. The cap is the shipped unit's `TimeoutStopSec=600` minus about 30 s of cleanup. A host shutdown, reboot or logout of the user manager waits up to this long too. See [Restarting kiln](#restarting-kiln). |

Every VM also has a hard lifetime cap of (idle timeout + job timeout + debug hold) x 60 + 300 seconds from its start, whatever its console prints. Warm VMs use `max(idle_timeout_mins, warm_recycle_mins + 5)` as their idle component.

### Docker mirror

| Field | Type | Default | Valid values | Applies | What it does |
|---|---|---|---|---|---|
| `docker_mirror` | bool | `true` | | live (within seconds) | Run the Docker Hub pull-through cache. On `serve` kiln downloads the pinned `registry` v3.1.2 into `<data>/bin` (SHA-256 verified, refused on a mismatch), writes `<data>/registry/config.yml` and supervises `registry serve` on `127.0.0.1:5000`. Images are cached for 7 days. If port 5000 is taken kiln leaves it alone and reports "port 5000 in use". VMs reach it at `10.0.2.2:5000` and dockerd falls back to Docker Hub when it is down. Restart backoff is 5 s growing to 60 s. |
| `mirror_gb` | integer | `20` | `1` to `500` | live | Cap on the mirror's storage. Every 10 minutes kiln measures `<data>/registry/data`; over the cap it stops the registry, deletes the data and restarts it. There is no LRU, wiping is acceptable for a cache that refills. |

### Repo cache

| Field | Type | Default | Valid values | Applies | What it does |
|---|---|---|---|---|---|
| `cache` | bool | `true` | | live (new VMs) | Attach a per-repo persistent cache disk to every job and commit it back when the trust rule allows. |
| `cache_branches` | object | `{}` | `"owner/name"` (entries for repos kiln does not serve are ignored) to a list of exact branch names (case-sensitive, no wildcards; letters, digits, `-_./`) | live | Extra branches whose successful pushes also save that repo's cache, besides the default branch. For a branch model like feature, then PR to `dev`, then `dev` promoted: `{"o/n": ["dev"]}`. The other trust conditions are unchanged: only `push` events whose job GitHub reports as `success`, and the commit must really be on that branch (a tag named `dev` does not count). Pull requests never save, whatever their branch is called. |
| `cache_gb` | integer | `30` | `5` to `500` | live | Virtual size of a cache disk when it is created. A cache that has actually grown past 1.2 x `cache_gb` at commit time is deleted and starts empty. The size of existing cache files does not change. |
| `repo_cache_gb` | object | `{}` | `"owner/name"` (entries for repos kiln does not serve are ignored) to `5` to `500` | live | Per-repo override of `cache_gb`, for both the size of a new cache disk and the 1.2x reset limit. An existing disk keeps its virtual size until it is reset or cleared. Set on the repo page. |

### Image

| Field | Type | Default | Valid values | Applies | What it does |
|---|---|---|---|---|---|
| `bake_node_versions` | list of strings | `["24"]` | 1 to 4 entries, each a major (`"20"`, newest release of it) or an exact version (`"20.19.5"`) | next bake | Node versions pre-installed into `/opt/hostedtoolcache`, so `actions/setup-node` with a matching `node-version` resolves offline. The newest is the plain `node` on `PATH`. Versions are looked up on nodejs.org at bake time and recorded in `base.json`; changing the set (not just its order) marks the image stale (rebake needed). An image baked by an older kiln, before the current job hooks (fork refusal, cold release builds), is stale too. |
| `bake_apt_packages` | list of strings | `[]` | up to 32 apt package names (`a-z 0-9 . + -`, starting with a letter or digit and not ending in `-` or `+`, which apt reads as remove or install markers) | next bake | Extra packages installed into the base image (`apt-get install --no-install-recommends`), e.g. `chromium` and its fonts for a PDF render test. Recorded in `base.json`; changing the set marks the image stale. A name apt doesn't know fails the bake. |
| `auto_rebake` | bool | `true` | | live | Rebake automatically when the image is stale: its runner version differs from the latest actions/runner release, it is more than 25 days old, `bake_node_versions` or `bake_apt_packages` changed since the bake, or an older kiln baked it. At most once every 6 hours (the timer resets when kiln restarts). Jobs that queue meanwhile launch on the old base, which is swapped atomically, except when the image was baked by a kiln older than the current guest recipe (`recipe` in `base.json`): then nothing launches until the rebake, because that image lacks the current job hooks (fork refusal, cold release builds). With `auto_rebake` off, rebake by hand after upgrading kiln. |

### Network

| Field | Type | Default | Valid values | Applies | What it does |
|---|---|---|---|---|---|
| `egress` | string | `"open"` | `"open"`, `"filtered"` | live (new VMs) | Job network. `open`: full outbound via the host's NAT (LAN and tailnet included). `filtered`: each VM in a rootless network namespace with an nftables allow-list (internet, DNS, Docker mirror). Switching to `filtered` triggers a probe at once; if it fails no jobs launch (never a fallback to open). Idle VMs booted under the old mode are recycled. See [architecture.md](architecture.md#egress). |

### Debugging

| Field | Type | Default | Valid values | Applies | What it does |
|---|---|---|---|---|---|
| `debug_hold_mins` | integer | `0` | `0` to `120` | live (new VMs) | Keep a job VM whose job failed alive for SSH this long. `0` is off. Needs at least one key in `debug_ssh_keys`. A held VM keeps its VM slot; see [Debug holds and the queue](#debug-holds-and-the-queue). |
| `debug_ssh_keys` | string array | `[]` | single-line public keys starting `ssh-`, `ecdsa-` or `sk-` | live (new VMs) | Keys allowed into a held VM (login as `runner`, key-only). Changing keys, or turning the hold on or off, recycles idle VMs that booted with the old values. |

#### Debug holds and the queue

A held VM keeps its memory and one of the `max_vms` slots, so holds compete with queued jobs. kiln keeps that cost bounded:

- **Only failures are held.** A job whose result is `Failed` (or `Abandoned`, the runner losing the job) is held. A cancelled job never is: usually it is `concurrency: cancel-in-progress` on a branch someone is pushing to, and there is nothing to inspect. Succeeded, skipped, and jobs kiln itself stopped (job timeout, kill) are not held either, nor a VM that never ran a job. A job that hits its workflow `timeout-minutes` is cancelled by GitHub and is therefore not held.
- **Never the last slot.** At most `max_vms - 1` VMs are held at once, so one slot always stays free for the queue. With `max_vms: 1` nothing is held. A failure that finds no room is released at once, with the note "not held: holds never take the last free VM slot".
- **Early release when jobs wait.** When a job is queued and every slot is taken, with at least one held, kiln releases the hold that would expire first (one per poll). Its VM's note says "hold released early: a queued job needed the slot", and the journal logs it. Until the slot frees, the Overview shows "N of M slots held for debugging — jobs are waiting" (`poll.blocked_kind` `held`) with **Release oldest**.

In practice a hold lasts `debug_hold_mins` only while the box has spare slots; under load, SSH in quickly.

### Updates

| Field | Type | Default | Valid values | Applies | What it does |
|---|---|---|---|---|---|
| `auto_update` | bool | `false` | | live | Install a newer signed release by itself, once no job runs, no demand VM waits for one, no VM is held for debugging and no bake runs (looked at every minute after a successful check). Idle warm VMs do not hold it back; the drain reaps them. A version that was rolled back is never installed by itself again, only a newer one. See [Updates](#updates). |
| `update_repo` | string | `"Bunty9/kiln"` | `owner/name` | live (next check) | Repository whose GitHub releases kiln checks and installs. Only releases signed with kiln's release key are installed, whatever the repo. |

### Warm pool

| Field | Type | Default | Valid values | Applies | What it does |
|---|---|---|---|---|---|
| `warm` | object | `{}` | `{"owner/name": 0..4}`; entries for repos kiln does not serve are ignored | live | Pre-booted idle VMs of the default size kept ready per repo. They hold RAM and a `max_vms` slot while idle. |
| `warm_recycle_mins` | integer | `30` | `5` to `1440` | live | Idle warm VMs older than this are deregistered and replaced so they never go stale. |

## Install as an app

The dashboard is an installable web app: its own window, a dock or home-screen icon, and shortcuts to Jobs, Repos and Settings. Browsers allow this only over HTTPS (or on `localhost`), so:

1. Turn on **Serve over HTTPS** in Settings › Network (it runs `tailscale serve`). The dashboard is then at `https://<box>.<tailnet>.ts.net:8443`, still tailnet-only. The tailnet must have HTTPS certificates enabled ([admin console › DNS](https://login.tailscale.com/admin/dns) › HTTPS Certificates): without them `tailscale serve` waits forever, so kiln checks first and refuses with that message, and `kiln doctor` shows `tailscale HTTPS: unavailable on this tailnet`. Every tailscale CLI call kiln makes is bounded (15 s for `serve`, 20 s otherwise) and killed with its whole process group when it overruns, so turning serve on answers within 35 s at worst (the ≤20 s `tailscale status` preflight plus the ≤15 s `serve`).
2. Open that URL. In Chrome or Edge click **Install app** at the top right (or the install icon in the address bar). On iOS use Share › Add to Home Screen; on Android, the menu's Install app.

No dashboard key is needed over HTTPS: `tailscale serve` proxies to kiln's unix socket `<data>/serve.sock` and tells kiln who you are (`Tailscale-User-Login`), and the same `allowed_users` rule applies as over plain HTTP. A browser on the CI box itself still needs the key; a tagged node is refused unless `tagged-devices` is in `allowed_users`. Never point a raw TCP forward (`--tcp`, `--tls-terminated-tcp`) or Funnel at the socket: kiln then stops trusting it and asks for the key (see SECURITY.md). Funnel (serving to the public internet) is refused. If you turned Serve on with kiln 0.2.1 or older, turn it off and on again once: the old setting proxies to `127.0.0.1:7878`, where every request looks local and needs the key. The macOS App Store build of Tailscale is sandboxed and may not be able to reach the socket; the standalone `tailscaled` can.

Over plain `http://<box>:7878` nothing is installed and Settings › Notifications says so. The app talks to the same server as the tab; the API is never cached. If kiln is unreachable, the app shows the last loaded dashboard (or a short "kiln is unreachable" page) and retries on its own. A new kiln release installs a new service worker on the next load.

## Updates

kiln can update itself from GitHub releases (Settings › Updates, or `POST /api/update/apply`). It checks `update_repo`'s latest release 60 seconds after starting, every 6 hours and on demand (**Check now**). Drafts and pre-releases are never offered, and only a version newer than the running one (`X.Y.Z`) is.

**Applying an update:**

1. **Download** the tarball for this build: `kiln-X.Y.Z-x86_64-linux.tar.gz` for the glibc build, `kiln-X.Y.Z-x86_64-linux-musl.tar.gz` for the static musl build (Settings › Updates shows which one runs), with its `.sha256` and `.sig`.
2. **Verify** the Ed25519 signature against the release key built into the running kiln, then the SHA-256. Anything unsigned, signed with another key or corrupted is refused before it is unpacked. Only the `kiln` binary is extracted, and it must report the release's version.
3. **Drain:** kiln launches no new VMs (warm ones included), reaps idle ones, and waits for running jobs to finish, at most the job timeout plus 2 minutes; whatever still runs then is stopped as on a normal shutdown. A running bake is always waited for (it has its own 30-minute cap), and no bake can start while kiln drains. VMs held for debugging (`debug_hold_mins`) keep `auto_update` from starting, but not a manual update: its drain waits for them like for running jobs, up to the same deadline. Queued jobs wait. **Cancel** (Settings › Updates or the Overview banner, `POST /api/update/cancel`) stops a drain and resumes launching.
4. **Restart:** the executable is replaced atomically (the old one is kept as `<exe>.prev`, for example `~/.local/bin/kiln.prev`) and kiln re-executes itself in place with the same arguments. Under systemd the PID stays the same, so the unit sees no restart. Open dashboards reload themselves, including an installed app showing a page it kept from the old version.

kiln must be able to write the directory its binary lives in (`~/.local/bin` in the standard install). If it cannot, the update fails before draining.

**Rollback:** if the new version fails to start twice (systemd's `Restart=on-failure` restarts it), the next start puts `<exe>.prev` back, runs it, and shows why on the dashboard. A start counts from the moment `kiln serve` runs, before it reads `config.json`, so a version that dies early is rolled back too; `kiln bake`, `kiln doctor` and `kiln --version` never count. A start is confirmed after 60 seconds of serving, so restarting kiln twice by hand within 60 seconds of an update also counts as two failed starts and rolls it back. The rolled-back version is recorded in `<data>/update/skip`: `auto_update` never retries it, only a newer release; **Update** in Settings › Updates installs it anyway and clears the record. To roll back by hand, stop kiln and `mv ~/.local/bin/kiln.prev ~/.local/bin/kiln`.

**Access to the release repo:** with a token, kiln reads releases with it. In GitHub App mode it uses the installation token if the App is installed on `update_repo`, and otherwise reads it unauthenticated (never with another installation's token), so a public repo works and a private one needs the App installed on it. A check that cannot see the repo says so in Settings › Updates.

**Trust:** the signing key lives only in the release workflow's secrets; the public half is compiled into kiln. Changing `update_repo` cannot make kiln install a build not signed with that key: another repo can offer only genuine signed releases, and only ones newer than the running version (never a downgrade). If the key is ever rotated, kilns built with the old key refuse the new releases: install that one release by hand (see the README), after which updates resume.

## Restarting kiln

**Which settings need a restart:** only `listen`, which is bound once at startup. Every other field is read where it is used, so a dashboard save applies it within seconds (some only to VMs started afterwards, or at the next bake, as the tables say). Hand edits to `config.json` are read only at startup, so they all need a restart.

**Restart when idle** (Overview banner after saving `listen`, or `POST /api/restart`) restarts without killing jobs. It drains exactly like an update: no new VMs start (warm ones included), idle VMs are reaped, and kiln waits for running VMs to finish, at most the job timeout plus 2 minutes, and for a running bake. VMs held for debugging are not waited for, as on SIGTERM: the restart ends the hold. Then it shuts down as usual and re-executes the same binary in place (if you installed a new binary over it by hand, that one), so under systemd the PID stays and the unit sees no restart. The Overview shows "Restart pending · waiting for N VMs to finish" meanwhile, the journal logs the drain every 30 s, and `/api/state` carries it as `restart: {needed, state: "draining" | "restarting", progress, running}`. **Cancel restart** (`POST /api/restart/cancel`) resumes launching. Only one drain runs at a time: a restart is refused (409, with what is running: "an update is draining", "kiln is stopping", ...) while an update or an update check runs, and an update is refused while a restart drains. A restart is also refused when the saved `listen` cannot be bound (see `listen` above), so it never leaves kiln unreachable. A restart request confirms a just-applied update (it reached the new version), so it never counts as a failed boot toward the rollback. The audit log notes each restart as "when idle: N running" or "now: killed N running VMs".

**Restart now** (`POST /api/restart?now=true`, also offered during a restart's drain) does not wait: running jobs are killed and fail on GitHub with "The runner has received a shutdown signal". The dashboard asks for confirmation and says how many VMs that kills. A running bake is still waited for.

**`systemctl --user restart kiln` / `stop`:** on the first SIGTERM (or Ctrl-C) kiln stops launching at once, reaps idle VMs, and waits up to `stop_grace_secs` (default 25) for running jobs to finish; VMs held for debugging are not waited for. The journal logs "stopping: waiting for N running VMs (at most S s more)" every 5 s and the dashboard keeps serving with a "kiln is stopping" banner. Then, or on a second SIGTERM/SIGINT, kiln kills what still runs and cleans up as before (runners deregistered, disks deleted). `systemctl` itself never sends a second SIGTERM; to end the wait from a shell, send one to kiln only: `systemctl --user kill --kill-whom=main kiln` (plain `systemctl kill` signals the whole cgroup, QEMU included). In a foreground `kiln serve`, press Ctrl-C again: job VMs run in their own process group, so the first Ctrl-C reaches kiln only and they get the grace too. The shipped unit sets `TimeoutStopSec=600`, so `stop_grace_secs` goes up to 570. An update does not touch the installed unit: under systemd kiln reads the unit's `TimeoutStopSec` at startup and, if it is too short for `stop_grace_secs` plus 25 s of cleanup (an older unit says 30), shortens the grace to fit and logs a warning; `kiln doctor` flags it as "kiln.service TimeoutStopSec=30s is shorter than stop_grace_secs ...". Reinstall the unit (`install -Dm644 deploy/kiln.service ~/.config/systemd/user/kiln.service && systemctl --user daemon-reload`) to get the longer timeout.

## Environment variables

| Variable | Meaning |
|---|---|
| `KILN_DATA` | Data directory. Default `$HOME/.local/share/kiln`. |
| `KILN_GITHUB_TOKEN` | GitHub token, highest precedence. |
| `GITHUB_TOKEN` | GitHub token, used when `KILN_GITHUB_TOKEN` is unset. |
| `HOME` | Used to find the default data directory. |

kiln logs through `tracing` to stderr (the systemd journal for the user unit). To set a token for the unit, add `Environment=KILN_GITHUB_TOKEN=...` to the service, or save it from the dashboard instead.

## GitHub App

A GitHub App is the recommended way to authenticate. kiln holds only the App's private key; the tokens it uses are minted per installation, expire after an hour, and carry exactly *Administration: write*, *Actions: write*, *Contents: read* and *Metadata: read*. The App cannot push code (so the hello PR is off in App mode), but *Administration: write* lets it change branch protection and repository settings on every repo it is installed on. Treat `app.pem` like an admin credential.

**Create it from the dashboard:** Settings › GitHub › Create GitHub App (enter an organization to create it there, or leave it empty for your account). GitHub shows the App with its permissions preset; confirm, and GitHub sends you back to the dashboard, which saves the App and shows an **Install the App on your repos** button. No webhook is configured: kiln keeps polling. The setup link is valid for an hour and survives a kiln restart; if finishing it fails on a network error, try again with the same link. If GitHub says the code expired or was already used but the App exists on github.com, open it there, generate a private key, and use **Use an existing App**.

**Or use an existing App:** Settings › GitHub › Use an existing App, with its App ID and a private key (`.pem`, PKCS#1 as GitHub issues it, or PKCS#8). kiln checks the pair against GitHub before saving.

**Which repos:** in App mode the repos kiln serves are exactly the repos the App is installed on. Install or uninstall it on github.com to change the list; the `repos` setting is only used with a token. kiln refreshes the list every 5 minutes, or every 30 seconds while the App serves no repo or has never been discovered successfully, so a new installation shows up quickly. **Refresh** in Settings › GitHub (`POST /api/app/refresh`) runs it at once. If a refresh fails, kiln keeps the last list and shows the error. Per-repo settings (`warm`, `cache_branches`, `repo_cache_gb`) stay keyed by `owner/name`; entries for repos the App is not installed on are kept and ignored.

**Which accounts:** only installations on the App owner's account are served. The owner is read from GitHub at every refresh and matched by its numeric account id, so renaming the account is safe. Installations on other accounts (possible if the App is public) are ignored and listed as "Skipped" on the dashboard's GitHub App card. To serve one, add its user or org login to `app_accounts` (string array, default `[]`, GitHub logins: letters, digits and single hyphens, at most 39 characters; there is no dashboard field: edit `config.json` and restart kiln), then Refresh. `app_accounts` entries are matched by login, case-insensitively: if such an account is renamed, update the list.

**Files:** `<data>/app.pem` and `<data>/app.json` (`{id, slug, html_url, owner}`, `owner` being the owner's login for display), both mode 0600 and written atomically. `<data>/app_states.json` (mode 0600) holds setup links in progress for up to an hour. kiln uses App mode when `app.json` and `app.pem` load at startup; if the key is unusable it logs the error and falls back to the token. **Remove App** in Settings deletes both files and returns to token auth (the App stays on GitHub until you delete it there).

## GitHub token

**Precedence at startup:** `KILN_GITHUB_TOKEN`, then `GITHUB_TOKEN`, then `<data>/token`, then the output of `gh auth token`. The dashboard shows which source is in use.

**Saving from the dashboard** validates the token first: it must authenticate, and the runners API of every configured repo is probed, so a missing *Administration* permission shows immediately (Diagnostics checks the others). The token is then written to `<data>/token` with mode `0600` and used from then on. After a dashboard save, only the file counts for in-process reloads, so a stale environment variable cannot take over again. On the next restart the environment variable wins again if it is set, so unset it if you want the saved token to stay in charge.

**Reloading:** if there is no token, or a poll fails with a 401, kiln re-reads the sources at most once a minute. This picks up a token that appeared (an unlocked keyring, a fixed environment) or was rotated. On hosts where `gh` keeps its token in a keyring that stays locked after a headless reboot, save the token from the dashboard instead.

**Required permissions:**

- Classic PAT: the `repo` scope (plus `workflow` for the hello PR).
- Fine-grained token, on each repo: *Administration: write* (register and delete runners), *Actions: read and write* (list and rerun or cancel runs, dispatch workflows, read jobs), *Contents: read* (check that a cache-saving push is really on its branch; without it caches never save). *Contents: write* and *Workflows: write* are needed only for the optional hello PR. *Metadata: read* is implicit.

`kiln doctor` (and Settings › Diagnostics) probes each repo once per permission and names the one that is missing, for example "token lacks Contents: read". Reads can work while GitHub refuses to register runners, so it also exercises the write path: it mints a runner registration token (`POST …/actions/runners/registration-token`; harmless, it expires in an hour and nothing uses it) and reports "runner registration works" or "runner registration failing: HTTP 500". The result is cached for 10 minutes per repo, since the dashboard runs the checks periodically. When GitHub reports an expiry for the token (fine-grained tokens, and classic ones created with one), the dashboard shows it under Settings › GitHub and warns from 14 days before.

The token stays on the host. A job VM only ever receives a single-use JIT runner configuration.

## Data directory

```
<data>/                          $KILN_DATA or ~/.local/share/kiln; set to mode 0700 at every start
  config.json                    settings
  token                          GitHub token, mode 0600 (only if saved from the dashboard)
  app.json, app.pem              GitHub App id and private key (mode 0600), when an App is configured
  dashboard.key                  secret for requests from the box itself, mode 0600, generated on first start
  serve.sock                     unix socket `tailscale serve` proxies to, mode 0600, recreated by `serve` at start
  onboard.json                   hello PRs opened from the dashboard
  usage.json                     job minutes per UTC day and VM size, for "Saved this month" (the last 400 days that had jobs)
  audit.log, audit.log.1         one JSON line per admitted API write (mode 0600, rolled over at 8 MiB); refusals go to kiln's log
  update/                        self-update: pending.json (an update not yet confirmed), error (why
                                 the last one was rolled back), the release being unpacked
  images/
    base.qcow2                   frozen base image
    base.vmlinuz                 kernel the VMs boot (direct kernel boot)
    base.json                    {recipe, baked_at, runner_version, node_versions, node_wanted, apt_wanted}
    bake.log, bake.lock          last bake log; lock so only one bake runs
  bin/registry                   pinned Docker registry binary
  registry/                      config.yml, registry.log, data/ (the pull cache)
  cache/<owner>__<name>.qcow2    per-repo cache disk (lowercase names)
  rk/<id>/                       rootlesskit state of a filtered VM (deleted when it exits)
  vms/<id>/                      one directory per VM
    meta.json                    VM record
    console.log, steps.log       console and step output, each capped at 64 MiB
    egress.nft                   filtered mode's rules (deleted when the VM exits)
    q/                           the only directory the VM's confined QEMU may write: disk.qcow2,
                                 cache.qcow2, the JIT secret and sockets (deleted when the VM exits)
```

kiln keeps the 200 most recent VM records and prunes older finished ones, directory included. The cache directory counts toward the "low disk" message.

## Commands

```
kiln serve        run the scheduler and dashboard (default when no command is given)
kiln bake         build the base VM image
kiln doctor       check host prerequisites, exit 1 if any check fails
kiln --version    print the version (also -V and version)
```

- `kiln serve` is what the systemd unit runs. Only `serve` touches leftovers from a previous run, so `bake` and `doctor` are safe to run next to a live `serve`.
- `kiln bake` downloads the Ubuntu 24.04 cloud image and matching kernel (re-downloading only changed files), fetches the latest actions/runner version, boots a bake VM that runs the recipe in `guest/user-data.yaml`, and swaps the result into `images/` atomically. It takes about 5 minutes and times out after 30. Bake VMs always use open networking. Running job VMs keep using the old base until they exit.
- `kiln doctor` checks: KVM, `qemu-system-x86_64`, `qemu-img`, `xorriso`, `curl` and `tailscale`, free disk (at least 15 GB), memory against `max_vms` x `vm_mem_mb`, the image (and whether it is stale), the baked Node versions, the token (and its expiry, when GitHub reports one), each repo's permissions (runners, actions and contents, naming any that is missing) and whether GitHub registers runners for it, the Docker mirror, filtered egress, Tailscale state, and stray QEMU processes. The dashboard's Diagnostics page shows the same checks.
- Any other argument prints usage and exits with status 2.
