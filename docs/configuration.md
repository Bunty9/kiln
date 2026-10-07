# Configuration reference

kiln keeps its settings in `config.json` inside its data directory. You normally edit them from the dashboard (Settings), which calls `POST /api/config`. You can also edit the file by hand and restart kiln.

## How the file is handled

- Location: `<data>/config.json`, where `<data>` is `$KILN_DATA` or `~/.local/share/kiln`.
- A missing file means all defaults. A partial file is fine: every field has a default, and unknown fields are ignored.
- The dashboard saves the whole object atomically (write to `config.json.tmp`, then rename) after validating it. A rejected save returns the reason and changes nothing.
- On startup kiln only parses the file; it does not check the ranges below until the next save from the dashboard. Keep a hand-edited file within them.
- Changes made from the dashboard apply to the running process. Hand edits need a restart.

"Live" below means a change from the dashboard takes effect without restarting kiln. VMs that are already running keep the values they booted with (for example the timeouts and the memory size), unless noted.

## Fields

### Core

| Field | Type | Default | Valid values | Applies | What it does |
|---|---|---|---|---|---|
| `listen` | string | `"0.0.0.0:7878"` | `host:port` socket address | restart | Address the dashboard and API bind to. The dashboard refuses anything that is not a tailnet peer or the box itself regardless of the bind address, but prefer a narrower address if the box has a public interface. The dashboard tells you when a restart is required. |
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
| `poll_secs` | integer | `5` | at least `3` | live | Seconds between GitHub polls. 304 responses do not count against the rate limit, so 5 is cheap. When under 20% of the rate limit is left kiln slows to every 30 s; after a rate-limit 403 or a 429 it pauses until GitHub says to resume. |
| `job_timeout_mins` | integer | `60` | `1` to `1440` | live (VMs started after the change) | Longest a job may run, counted from when the runner reports "Running job". |
| `idle_timeout_mins` | integer | `10` | `1` to `1440` | live (VMs started after the change) | A VM that never gets a job (boot included) is killed after this. |

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
| `bake_node_versions` | list of strings | `["24"]` | 1 to 4 entries, each a major (`"20"`, newest release of it) or an exact version (`"20.19.5"`) | next bake | Node versions pre-installed into `/opt/hostedtoolcache`, so `actions/setup-node` with a matching `node-version` resolves offline. The newest is the plain `node` on `PATH`. Versions are looked up on nodejs.org at bake time and recorded in `base.json`; changing the set (not just its order) marks the image stale (rebake needed). An image baked by an older kiln, before the fork-refusal hook, is stale too. |
| `bake_apt_packages` | list of strings | `[]` | up to 32 apt package names (`a-z 0-9 . + -`, starting with a letter or digit) | next bake | Extra packages installed into the base image (`apt-get install --no-install-recommends`), e.g. `chromium` and its fonts for a PDF render test. Recorded in `base.json`; changing the set marks the image stale. A name apt doesn't know fails the bake. |
| `auto_rebake` | bool | `true` | | live | Rebake automatically when the image is stale: its runner version differs from the latest actions/runner release, it is more than 25 days old, or `bake_node_versions` changed since the bake. At most once every 6 hours (the timer resets when kiln restarts). Jobs that queue meanwhile launch on the old base, which is swapped atomically. |

### Network

| Field | Type | Default | Valid values | Applies | What it does |
|---|---|---|---|---|---|
| `egress` | string | `"open"` | `"open"`, `"filtered"` | live (new VMs) | Job network. `open`: full outbound via the host's NAT (LAN and tailnet included). `filtered`: each VM in a rootless network namespace with an nftables allow-list (internet, DNS, Docker mirror). Switching to `filtered` triggers a probe at once; if it fails no jobs launch (never a fallback to open). Idle VMs booted under the old mode are recycled. See [architecture.md](architecture.md#egress). |

### Debugging

| Field | Type | Default | Valid values | Applies | What it does |
|---|---|---|---|---|---|
| `debug_hold_mins` | integer | `0` | `0` to `120` | live (new VMs) | Keep a job VM whose job ended with a verdict other than success alive for SSH this long. `0` is off. Needs at least one key in `debug_ssh_keys`. |
| `debug_ssh_keys` | string array | `[]` | single-line public keys starting `ssh-`, `ecdsa-` or `sk-` | live (new VMs) | Keys allowed into a held VM (login as `runner`, key-only). Changing keys, or turning the hold on or off, recycles idle VMs that booted with the old values. |

### Warm pool

| Field | Type | Default | Valid values | Applies | What it does |
|---|---|---|---|---|---|
| `warm` | object | `{}` | `{"owner/name": 0..4}`; entries for repos kiln does not serve are ignored | live | Pre-booted idle VMs of the default size kept ready per repo. They hold RAM and a `max_vms` slot while idle. |
| `warm_recycle_mins` | integer | `30` | `5` to `1440` | live | Idle warm VMs older than this are deregistered and replaced so they never go stale. |

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

**Create it from the dashboard:** Settings › GitHub › Create GitHub App (enter an organization to create it there, or leave it empty for your account). GitHub shows the App with its permissions preset; confirm, and GitHub sends you back to the dashboard, which saves the App and opens its install page. No webhook is configured: kiln keeps polling. The setup link is valid for an hour and survives a kiln restart; if finishing it fails on a network error, try again with the same link. If GitHub says the code expired or was already used but the App exists on github.com, open it there, generate a private key, and use **Use an existing App**.

**Or use an existing App:** Settings › GitHub › Use an existing App, with its App ID and a private key (`.pem`, PKCS#1 as GitHub issues it, or PKCS#8). kiln checks the pair against GitHub before saving.

**Which repos:** in App mode the repos kiln serves are exactly the repos the App is installed on. Install or uninstall it on github.com to change the list; the `repos` setting is only used with a token. kiln refreshes the list every 5 minutes, or every 30 seconds while the App serves no repo or has never been discovered successfully, so a new installation shows up quickly. **Refresh** in Settings › GitHub (`POST /api/app/refresh`) runs it at once. If a refresh fails, kiln keeps the last list and shows the error. Per-repo settings (`warm`, `cache_branches`, `repo_cache_gb`) stay keyed by `owner/name`; entries for repos the App is not installed on are kept and ignored.

**Which accounts:** only installations on the App owner's account are served. The owner is read from GitHub at every refresh and matched by its numeric account id, so renaming the account is safe. Installations on other accounts (possible if the App is public) are ignored and named in the dashboard's App error. To serve one, add its user or org login to `app_accounts` (string array, default `[]`, GitHub logins: letters, digits and single hyphens, at most 39 characters), then Refresh. `app_accounts` entries are matched by login, case-insensitively: if such an account is renamed, update the list.

**Files:** `<data>/app.pem` and `<data>/app.json` (`{id, slug, html_url, owner}`, `owner` being the owner's login for display), both mode 0600 and written atomically. `<data>/app_states.json` (mode 0600) holds setup links in progress for up to an hour. kiln uses App mode when `app.json` and `app.pem` load at startup; if the key is unusable it logs the error and falls back to the token. **Remove App** in Settings deletes both files and returns to token auth (the App stays on GitHub until you delete it there).

## GitHub token

**Precedence at startup:** `KILN_GITHUB_TOKEN`, then `GITHUB_TOKEN`, then `<data>/token`, then the output of `gh auth token`. The dashboard shows which source is in use.

**Saving from the dashboard** validates the token first: it must authenticate, and the runners API of every configured repo is probed, so a missing *Administration* permission shows immediately (Diagnostics checks the others). The token is then written to `<data>/token` with mode `0600` and used from then on. After a dashboard save, only the file counts for in-process reloads, so a stale environment variable cannot take over again. On the next restart the environment variable wins again if it is set, so unset it if you want the saved token to stay in charge.

**Reloading:** if there is no token, or a poll fails with a 401, kiln re-reads the sources at most once a minute. This picks up a token that appeared (an unlocked keyring, a fixed environment) or was rotated. On hosts where `gh` keeps its token in a keyring that stays locked after a headless reboot, save the token from the dashboard instead.

**Required permissions:**

- Classic PAT: the `repo` scope (plus `workflow` for the hello PR).
- Fine-grained token, on each repo: *Administration: write* (register and delete runners), *Actions: read and write* (list and rerun or cancel runs, dispatch workflows, read jobs), *Contents: read* (check that a cache-saving push is really on its branch; without it caches never save). *Contents: write* and *Workflows: write* are needed only for the optional hello PR. *Metadata: read* is implicit.

`kiln doctor` (and Settings › Diagnostics) probes each repo once per permission and names the one that is missing, for example "token lacks Contents: read". When GitHub reports an expiry for the token (fine-grained tokens, and classic ones created with one), the dashboard shows it under Settings › GitHub and warns from 14 days before.

The token stays on the host. A job VM only ever receives a single-use JIT runner configuration.

## Data directory

```
<data>/                          $KILN_DATA or ~/.local/share/kiln
  config.json                    settings
  token                          GitHub token, mode 0600 (only if saved from the dashboard)
  app.json, app.pem              GitHub App id and private key (mode 0600), when an App is configured
  dashboard.key                  secret for requests from the box itself, mode 0600, generated on first start
  onboard.json                   hello PRs opened from the dashboard
  images/
    base.qcow2                   frozen base image
    base.vmlinuz                 kernel the VMs boot (direct kernel boot)
    base.json                    {recipe, baked_at, runner_version, node_versions, node_wanted, apt_wanted}
    bake.log, bake.lock          last bake log; lock so only one bake runs
  bin/registry                   pinned Docker registry binary
  registry/                      config.yml, registry.log, data/ (the pull cache)
  cache/<owner>__<name>.qcow2    per-repo cache disk (lowercase names)
  vms/<id>/                      one directory per VM
    meta.json                    VM record
    console.log, steps.log       console and step output, each capped at 64 MiB
                                 (disk.qcow2, cache.qcow2, the JIT secret and sockets are deleted when the VM exits)
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
- `kiln doctor` checks: KVM, `qemu-system-x86_64`, `qemu-img`, `xorriso`, `curl` and `tailscale`, free disk (at least 15 GB), memory against `max_vms` x `vm_mem_mb`, the image (and whether it is stale), the baked Node versions, the token (and its expiry, when GitHub reports one), each repo's permissions (runners, actions and contents, naming any that is missing), the Docker mirror, filtered egress, Tailscale state, and stray QEMU processes. The dashboard's Diagnostics page shows the same checks.
- Any other argument prints usage and exits with status 2.
