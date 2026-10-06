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
- `auto_rebake` (default `true`): when the image is stale (runner behind the latest release, or over 25 days old), kiln rebakes by itself, at most once every 6 hours. Jobs that queue meanwhile still launch on the old base, which is swapped atomically.

## Security model

The dashboard holds a GitHub token, so who can call it matters:

- **Tailnet peers** are identified with `tailscale whois`. By default only the owner of the CI box gets in, which keeps out nodes shared in from other tailnets. Set `allowed_users` to change that.
- **Requests from the CI box itself** need the key in `~/.local/share/kiln/dashboard.key`; the browser asks for it once. This covers loopback, the box's own tailnet IP, and `tailscale serve`. The source address can't be trusted here, because job VMs reach the host through QEMU's NAT and show up exactly like local traffic.
- **Everything else** is refused. That includes the LAN, requests whose `Host` header isn't the tailnet name or an IP (to stop DNS rebinding), and POSTs without the `x-kiln` header (to stop CSRF).
- **The Docker mirror** listens on host loopback only (`127.0.0.1:5000`) and is a pull-only proxy of public Docker Hub images (content-addressed). Job VMs reach it by design, through the NAT as `10.0.2.2:5000`; it holds no credentials and can't push.
- **The GitHub proxy** only passes `repos/<configured>/actions/{workflows,runs,jobs}`. Runners, secrets and variables are out of reach.

What a job can reach: a job VM has full outbound network through the host's
NAT. That includes the LAN and **the tailnet** (it routes like any process on
the host). That's fine for your own repos. Don't point kiln at repos that run
untrusted pull requests from forks until the egress filtering on the roadmap
is in place.

## Files

```
~/.local/share/kiln/          (override with KILN_DATA)
  config.json                 settings (editable from the dashboard)
  token                       GitHub token, mode 0600 (if set from the dashboard)
  images/base.qcow2           frozen base image   base.vmlinuz   base.json (runner version)
  images/bake.log             last bake
  bin/registry                pinned Docker registry binary (docker_mirror)
  registry/                   config.yml, registry.log, data/ (the pull cache)
  vms/<id>/meta.json          per-VM record; console.log, steps.log
                              (disk.qcow2 and the JIT secret are deleted when the VM exits)
```

The base image recipe is [`guest/user-data.yaml`](guest/user-data.yaml) (cloud-init). It is the place to add toolchains your jobs expect.

## Known limits and next steps

- **Runner updates.** kiln pins the runner version at bake time. GitHub stops sending jobs to runners more than about 30 days out of date, so rebake monthly (one click). kiln rebakes automatically (`auto_rebake`) once the image is stale and the box is idle.
- **Network throughput.** Slirp tops out well below line rate and is CPU-heavy on large `docker pull`s. *Next:* `passt` (still rootless), or a one-time root setup of tap devices, which would also allow Firecracker or Cloud Hypervisor.
- **No cache between jobs yet.** *Next:* one persistent cache disk per VM slot, mounted at `/var/lib/docker` and `~/.cache`. QEMU's image locking keeps two VMs from sharing one.
- **PAT auth.** *Next:* a GitHub App for org-wide runners and short-lived tokens.
- **Single host, x86_64 only.** Scheduling is a per-repo count; there are no priorities or fair-share yet.
- **Job egress filtering.** *Next:* passt or tap networking with a host firewall that allows only the internet, not the LAN or tailnet.
