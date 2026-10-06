# kiln

Self-hosted CI on hardware you already own. kiln turns an always-on Linux box
(here: a Ryzen 7 on a Tailscale tailnet) into a pool of **ephemeral GitHub
Actions runners, one fresh KVM virtual machine per job**: no cloud build
minutes, no runner fleet to babysit, and no state leaking from one job into the
next.

```
 GitHub  ◄──── poll queued jobs (REST, ETag-cached) ────┐
    ▲                                                   │
    │ JIT runner registers, runs 1 job, exits      ┌────┴─────────────────────┐
    │                                              │ kiln (Rust, one binary)  │
 ┌──┴───────────────────────┐   qemu + KVM        │  scheduler · VM supervisor│
 │ job VM (Ubuntu 24.04)    │ ◄───────────────── │  dashboard :7878          │
 │ overlay of base.qcow2    │   console/steps logs│  tailscale CLI wrapper    │
 │ docker, build-essential  │ ──────────────────► └────┬─────────────────────┘
 └──────────────────────────┘                          │ tailnet only
                                                 you, from any device
```

## Why it is built this way

| Decision | Why |
|---|---|
| **A full VM per job** (QEMU/KVM, q35) instead of containers | Real isolation and a hosted-runner-like environment: `docker build`, `services:`, `sudo apt install` and kernel features all work, and nothing survives the job. |
| **Rootless** (needs only `/dev/kvm` + `qemu-system-x86_64`) | User-mode networking (slirp) means no tap devices, bridges, iptables or sudo. Runs as a systemd *user* service. |
| **qcow2 overlay on a frozen base image** | Creating a job disk takes milliseconds and costs nothing until written. Deleting the overlay erases the job. |
| **Direct kernel boot, no initrd** | virtio and ext4 are built into Ubuntu's kernel, so the VM reaches the runner in about 4 s (measured on the Ryzen box). |
| **JIT runner config** (`generate-jitconfig`) | Each VM gets a single-use, auto-deregistering runner. There's no long-lived registration token on disk. |
| **JIT secret via SMBIOS OEM string** | It works with the stock cloud kernel (fw_cfg needs a module the cloud kernel lacks), and `path=` keeps it out of `ps`. |
| **Polling, not webhooks** | The box is only reachable over Tailscale. Polling `runs?status=queued/in_progress` with ETags is almost free against the rate limit, because 304 responses don't count. |
| **Demand by count, not by job id** | GitHub gives any queued job to any idle runner whose labels match, so kiln boots `queued − (booting + idle)` VMs per repo and size. |
| **Docker Hub pull-through mirror** | Job VMs are fresh, so every `docker pull` would hit Docker Hub's rate limit. kiln runs a local registry cache they reach at `10.0.2.2:5000`; dockerd falls back to Docker Hub if it is down. |

## Quick start (on the CI box)

Requirements: Linux x86_64, read/write access to `/dev/kvm`, `qemu-system-x86_64`, `qemu-img`, `xorriso`, `curl`, `tailscale`, and Rust to build.

```sh
cargo build --release && install -Dm755 target/release/kiln ~/.local/bin/kiln
kiln bake          # one time: downloads the Ubuntu 24.04 cloud image and builds the base image (~5 min)
install -Dm644 deploy/kiln.service ~/.config/systemd/user/kiln.service
systemctl --user daemon-reload && systemctl --user enable --now kiln
loginctl enable-linger $USER
```

Run `kiln doctor` to check KVM, tools, disk, memory, the image, the token, the Docker mirror and Tailscale. Open `http://<box>:7878` from any tailnet device. Optionally publish it over
HTTPS from the Tailscale tab, which serves it at `https://<box>.<tailnet>.ts.net:8443`.

Then:
1. **GitHub token.** kiln uses `KILN_GITHUB_TOKEN`, then the token saved from the dashboard, then `gh auth token`. A classic PAT needs the `repo` scope. A fine-grained one needs *Administration: write* and *Actions: read/write* on each repo. On hosts where `gh` keeps its token in a keyring (locked after a headless reboot), save the token from the dashboard instead: the dashboard validates it against each repo before saving.
2. **Repos.** Add them on the Repos tab, as `owner/name`.
3. **Workflows.** Opt a workflow in:
   ```yaml
   jobs:
     test:
       runs-on: [self-hosted, kiln]
   ```

### VM sizes

The label picks the VM. `[self-hosted, kiln]` gets the default size (`vm_cpus` / `vm_mem_mb`, 4 vCPU / 8 GB unless changed); add a size to the label to choose another:

| `runs-on` | vCPU | RAM |
|---|---|---|
| `[self-hosted, kiln]` | `vm_cpus` (4) | `vm_mem_mb` (8 GB) |
| `[self-hosted, kiln-2cpu]` | 2 | 4 GB |
| `[self-hosted, kiln-4cpu]` | 4 | 8 GB (the default size's RAM if `vm_cpus` is 4) |
| `[self-hosted, kiln-8cpu]` | 8 | 16 GB |
| `[self-hosted, kiln-16cpu]` | 16 | 24 GB |

(`kiln` is the configured `label`.) RAM is min(N × 2 GB, 24 GB); disk is `vm_disk_gb` for all. A job must name exactly one kiln label: `[kiln, kiln-8cpu]` or `[kiln, gpu]` is not ours and is never picked up. A size larger than the host's CPU count is not served either (the job just waits, uncounted). A VM registers `kiln-Ncpu` plus the plain `kiln` only when N is the default size, so a big VM never steals a default job, and the default VM also serves `kiln-<default>cpu`. Each size is scheduled separately, within the shared `max_vms` and memory gate.

`POST /api/onboard/hello {"repo":"o/n"}` opens a PR adding `.github/workflows/kiln-hello.yml` (needs a token with contents and workflows write); `GET /api/onboard` lists the PRs opened.

kiln's own CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs this way.

## Dashboard

A first-run stepper (token, bake, repo, workflow, first job) takes over until kiln is set up. After that there are four pages:

- **Overview:** health banners only when something needs you (token, image, backoff, rate limit, memory, mirror), one "chamber" per VM slot with live timers, jobs today, failures, median job time, and an estimate of minutes saved against GitHub-hosted prices.
- **Jobs:** every job VM, filterable. The detail page shows a queue, boot, wait and job timeline, the exit reason, and three log sources: live **console** (boot and runner), live **steps** (the runner's `_diag/pages`, mirrored over a second serial port) and the **GitHub** log once the job finishes. Logs render ANSI colour and support follow, wrap, copy and download. Kill button.
- **Repos:** connected repos, whether jobs actually route to kiln, workflows (with dispatch), recent runs (rerun or cancel), and jobs and steps.
- **Settings:** capacity (and pause), timeouts, access, GitHub token (validated on save), image (rebake, Docker mirror, auto-rebake), Tailscale network (peers, ping, netcheck, HTTPS serve) and diagnostics (`kiln doctor`).

The tab title and favicon show running jobs and unseen failures. Opt-in browser notifications for failed jobs need HTTPS, so turn on Serve first.

For moving real projects over (stack compatibility, pricing, examples), see [docs/stacks.md](docs/stacks.md).

### Settings (`config.json`)

Editable from the dashboard (`POST /api/config`); changes apply without a restart except `listen`. Besides `repos`, `label`, `max_vms`, `vm_cpus`, `vm_mem_mb`, `vm_disk_gb`, `job_timeout_mins`, `idle_timeout_mins`, `allowed_users`:

- `poll_secs` (default 5, min 3): how often GitHub is polled. ETag 304s don't count against the rate limit, so 5s is cheap. A `config.json` saved by an older version keeps its old value.
- `docker_mirror` (default `true`): run the Docker Hub pull-through cache. On `serve` kiln downloads the pinned `registry` v3.1.2 into `<data>/bin` (sha256 verified, refused on mismatch), writes `<data>/registry/config.yml` and supervises `registry serve` on `127.0.0.1:5000` (restart backoff 5s to 60s; log in `<data>/registry/registry.log`; images cached 7 days under `<data>/registry/data`). If port 5000 is already taken kiln leaves it alone and reports "port 5000 in use". Toggling it takes effect within seconds.
- `mirror_gb` (default 20, 1 to 500): cap on the mirror's storage. Every 10 minutes kiln checks `<data>/registry/data`; over the cap it stops the registry, deletes the data and restarts it (no LRU: wiping is fine for a pull-through cache, which refills).
- `cache` (default `true`), `cache_gb` (default 30, 5 to 500): the per-repo cache disk, see [Repo cache](#repo-cache).
- `debug_hold_mins` (default 0 = off, max 120) and `debug_ssh_keys`: keep failed jobs for SSH, see [Debugging a failed job](#debugging-a-failed-job).
- `warm` (default `{}`), `warm_recycle_mins` (default 30, 5 to 1440): opt-in warm pool, see [Warm pool](#warm-pool).
- `auto_rebake` (default `true`): when the image is stale (runner behind the latest release, or over 25 days old), kiln rebakes by itself, at most once every 6 hours. Jobs that queue meanwhile still launch on the old base, which is swapped atomically.

## Repo cache

Each repo gets one persistent cache disk, `<data>/cache/<owner>__<name>.qcow2` (virtual size `cache_gb`, created blank on first use; the guest formats it). The guest bind-mounts these onto it: `/var/lib/docker`, `~/.cache`, `~/.npm`, `~/.cargo`, `~/.rustup` (the Rust toolchain too), `~/go/pkg/mod`, `~/.gradle/caches`, `~/.m2/repository`. `/opt/hostedtoolcache` is not cached (the pre-seeded Node lives there). So Docker layers and package downloads are warm on every job, with no `actions/cache` round trip.

**Trust rule: trusted writer, throwaway readers.** Every job VM gets a private qcow2 overlay of its repo's cache, as a second disk, so any job (PR or branch) starts warm and many can run at once. kiln merges the overlay back (`qemu-img commit`) only when all of these hold: the job succeeded, it was a `push` to the repo's default branch (checked through the GitHub API), and `cache` is on. If other jobs of the repo are still reading the cache, the overlay is parked and merged as soon as the last of them finishes (committing under a live reader would corrupt its overlay); a newer trusted overlay supersedes a parked one, since every live overlay shares the same base. Anything else is discarded with the overlay, and the job page says why ("cache not saved: pull_request event"). This mirrors GitHub's branch-scope rule for `actions/cache`: a PR can read the cache but can never poison it.

A cache that grows past 1.2x `cache_gb` is deleted at commit time and starts empty again. Changing `cache_gb` only affects caches created afterwards. To clear one, use Settings > Cache > Clear, or `POST /api/cache/clear {"repo":"o/n"}` (refused while jobs of that repo run), or delete the file while kiln is idle. The cache directory counts toward the low-disk message.

Older caches kept `~/.cargo/{registry,git}` as separate directories; `kiln-cache` deletes those obsolete dirs from the cache disk on first use (after a rebake, since it lives in the guest image).

## Warm pool

`"warm": {"owner/name": 2}` keeps that many pre-booted idle VMs of the default size ready for the repo (0 to 4; the repo must be in `repos`), so a job starts in about a second instead of waiting for a boot. They cost RAM and a `max_vms` slot while idle, and the reaper never drops below the target. Each tick kiln launches `queued + target - waiting` VMs; a VM that takes a job is a normal job VM and gets replaced. Idle warm VMs older than `warm_recycle_mins` are deregistered and replaced so they never go stale, and their idle timeout is that plus 5 minutes. `max_vms` 0 (paused) means no warm VMs. An idle warm VM reads the repo cache, which would block a parked cache commit forever: when only idle warm VMs still read it, kiln recycles them, and replacements launch after the commit. `/api/state` VMs carry `"warm": true` until they take a job.

## Debugging a failed job

Set `debug_hold_mins` (say 30) and add your public keys to `debug_ssh_keys` (Settings > Debugging). When a job fails (or its runner dies without a verdict) its VM stays up for that long instead of powering off, and its job page shows the command, e.g. `ssh -p 2201 runner@100.73.48.98`, with Release now and Kill buttons. Login is key-only as `runner`, on a port from 2200 to 2299 forwarded by QEMU, bound to the box's Tailscale IPv4 (loopback if tailscale is not up). kiln talks to the guest over the serial console: after the runner exits the guest asks (`kiln: decide`) and kiln answers `hold <secs>` or `release`.

Security notes: a held VM keeps its memory and its slot (it counts toward `max_vms`) until released or the time is up. sshd is not running during jobs; it is started only for a hold. The SSH port is reserved at launch (so the command is stable) but only published when the hold starts: through the QEMU monitor (`hostfwd_add`) in open mode, or `rootlessctl add-ports` in filtered mode (if `rootlessctl` is missing, filtered mode falls back to a static `-p`, open for the whole VM life). If publishing fails the VM is released instead of held, with a note. Host keys are not baked: the guest generates them at hold time and prints the fingerprints, shown on the job page for you to compare (the guest is job-controlled, so this only catches network-level impersonation). kiln honours `kiln: decide` only after the runner printed a result, so a job cannot force a hold early. Rebake after updating kiln to get the guest side.

## Security model

The dashboard holds a GitHub token, so who can call it matters:

- **Tailnet peers** are identified with `tailscale whois`. By default only the owner of the CI box gets in, which keeps out nodes shared in from other tailnets. Set `allowed_users` to change that.
- **Requests from the CI box itself** need the key in `~/.local/share/kiln/dashboard.key`; the browser asks for it once. This covers loopback, the box's own tailnet IP, and `tailscale serve`. The source address can't be trusted here, because job VMs reach the host through QEMU's NAT and show up exactly like local traffic.
- **Everything else** is refused. That includes the LAN, requests whose `Host` header isn't the tailnet name or an IP (to stop DNS rebinding), and POSTs without the `x-kiln` header (to stop CSRF).
- **The Docker mirror** listens on host loopback only (`127.0.0.1:5000`) and is a pull-only proxy of public Docker Hub images (content-addressed). Job VMs reach it by design, through the NAT as `10.0.2.2:5000`; it holds no credentials and can't push.
- `/v2/_catalog` and the other registry reads are visible to jobs; it only caches public images, which is acceptable.
- **The GitHub proxy** only passes `repos/<configured>/actions/{workflows,runs,jobs}`. Runners, secrets and variables are out of reach.

What a job can reach depends on **Settings > Network > Job network** (`egress`):

- **open** (default for now): a job VM has full outbound network through the host's NAT. That includes the LAN and **the tailnet**. Fine for your own repos.
- **filtered**: each job's QEMU runs in its own rootless network namespace (rootlesskit + slirp4netns) with an nftables egress filter loaded first. Jobs reach the public internet, DNS and the Docker mirror (`:5000` only). They cannot reach the LAN, the tailnet, the host's own addresses, cloud metadata or any other port on the host's loopback, and outbound SMTP (port 25) is dropped. IPv6 is off. If the filter cannot be set up, QEMU never starts, and kiln runs a probe (cached 10 minutes, shown in Diagnostics as "filtered egress") and launches nothing while it fails: it never falls back to open. Recommended before running untrusted pull requests from forks.

The ruleset is generated per VM: with `docker_mirror` off, the mirror DNAT and accept rules are omitted. QEMU is exec'd through `setpriv` with all capabilities dropped after nft loads (`setpriv` from util-linux is required; the VM fails closed without it). Console and steps output are capped (64 MiB each, steps over a unix socket; lines over 64 KiB are not parsed). The repo cache is committed only if GitHub's API also reports the job as `success`.

Residual risks in filtered mode: DNS goes through the host's resolver, so data can be exfiltrated in DNS queries; IPv6 is disabled rather than filtered; and the denylist only covers private ranges: public IPs the host can reach, notably the router's WAN IP if it hairpins (exposing forwarded ports), are not blocked. Keep Tailscale subnet-route acceptance off on this host.

Host requirements for filtered mode: `sudo apt install rootlesskit slirp4netns nftables uidmap`, plus subuid/subgid ranges for the kiln user (`/etc/subuid`, `/etc/subgid`; Ubuntu creates them). On Ubuntu 24.04 plain user namespaces are restricted by AppArmor, but the rootlesskit and slirp4netns packages ship profiles that allow them. Bake VMs always use open networking. A held debug VM's SSH port is published into the namespace by rootlesskit's port driver. The default will become filtered once verified on the host.

## Files

```
~/.local/share/kiln/          (override with KILN_DATA)
  config.json                 settings (editable from the dashboard)
  token                       GitHub token, mode 0600 (if set from the dashboard)
  images/base.qcow2           frozen base image   base.vmlinuz   base.json (runner version)
  images/bake.log             last bake
  bin/registry                pinned Docker registry binary (docker_mirror)
  registry/                   config.yml, registry.log, data/ (the pull cache)
  cache/<owner>__<name>.qcow2 per-repo cache disk (cache)
  vms/<id>/meta.json          per-VM record; console.log, steps.log
                              (disk.qcow2, cache.qcow2 and the JIT secret are deleted when the VM exits)
```

The base image recipe is [`guest/user-data.yaml`](guest/user-data.yaml) (cloud-init). It is the place to add toolchains your jobs expect.

## Known limits and next steps

- **Runner updates.** kiln pins the runner version at bake time. GitHub stops sending jobs to runners more than about 30 days out of date, so rebake monthly (one click). kiln rebakes automatically (`auto_rebake`) once the image is stale and the box is idle.
- **Network throughput.** Slirp tops out well below line rate and is CPU-heavy on large `docker pull`s. *Next:* `passt` (still rootless), or a one-time root setup of tap devices, which would also allow Firecracker or Cloud Hypervisor.
- **PAT auth.** *Next:* a GitHub App for org-wide runners and short-lived tokens.
- **Single host, x86_64 only.** Scheduling is a per-repo count; there are no priorities or fair-share yet.
- **Filtered egress is opt-in.** `egress: "filtered"` is implemented; *Next:* make it the default once verified on the host, and filter DNS.
