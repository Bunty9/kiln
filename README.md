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
| **Demand by count, not by job id** | GitHub gives any queued job to any idle runner whose labels match, so kiln boots `queued − (booting + idle)` VMs per repo. |

## Quick start (on the CI box)

Requirements: Linux x86_64, read/write access to `/dev/kvm`, `qemu-system-x86_64`, `qemu-img`, `xorriso`, `curl`, `tailscale`, and Rust to build.

```sh
cargo build --release && install -Dm755 target/release/kiln ~/.local/bin/kiln
kiln bake          # one time: downloads the Ubuntu 24.04 cloud image and builds the base image (~5 min)
install -Dm644 deploy/kiln.service ~/.config/systemd/user/kiln.service
systemctl --user daemon-reload && systemctl --user enable --now kiln
loginctl enable-linger $USER
```

Open `http://<box>:7878` from any tailnet device. Optionally publish it over
HTTPS from the Tailscale tab, which serves it at `https://<box>.<tailnet>.ts.net:8443`.

Then:
1. **GitHub token.** kiln uses `KILN_GITHUB_TOKEN`, then the token saved from the dashboard, then `gh auth token`. A classic PAT needs the `repo` scope. A fine-grained one needs *Administration: write* and *Actions: read/write* on each repo.
2. **Repos.** Add them on the Repos tab, as `owner/name`.
3. **Workflows.** Opt a workflow in:
   ```yaml
   jobs:
     test:
       runs-on: [self-hosted, kiln]
   ```

kiln's own CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs this way.

## Dashboard

- **Overview:** health, host load and memory, VM slots, queued jobs per repo, recent VMs.
- **Repos:** connected repos, their workflows (with dispatch), recent runs (with rerun and cancel), jobs, steps, and logs of finished jobs.
- **VMs:** every job VM, with a live **console** (boot and runner) and live **steps** output. Step output comes from the runner's `_diag/pages`, mirrored over a second serial port. Kill button.
- **Tailscale:** connection state, peers (direct vs DERP), ping, netcheck, and the HTTPS serve toggle.
- **Settings:** limits and timeouts, token, rebaking the base image.

Access rules:
- The dashboard only answers loopback and tailnet addresses (100.64.0.0/10, fd7a:115c:a1e0::/48).
- Requests that change state need an `x-kiln` header, which blocks cross-site POSTs.
- `allowed_users` can restrict access to particular tailnet logins. kiln checks them with `tailscale whois`, or with the `Tailscale-User-Login` header when the dashboard is behind `tailscale serve`.

## Files

```
~/.local/share/kiln/          (override with KILN_DATA)
  config.json                 settings (editable from the dashboard)
  token                       GitHub token, mode 0600 (if set from the dashboard)
  images/base.qcow2           frozen base image   base.vmlinuz   base.json (runner version)
  images/bake.log             last bake
  vms/<id>/meta.json          per-VM record; console.log, steps.log
                              (disk.qcow2 and the JIT secret are deleted when the VM exits)
```

The base image recipe is [`guest/user-data.yaml`](guest/user-data.yaml) (cloud-init). It is the place to add toolchains your jobs expect.

## Known limits and next steps

- **Runner updates.** kiln pins the runner version at bake time. GitHub stops sending jobs to runners more than about 30 days out of date, so rebake monthly (one click). *Next:* automatic rebake when a new runner is released.
- **Network throughput.** Slirp tops out well below line rate and is CPU-heavy on large `docker pull`s. *Next:* `passt` (still rootless), or a one-time root setup of tap devices, which would also allow Firecracker or Cloud Hypervisor.
- **No cache between jobs yet.** *Next:* one persistent cache disk per VM slot, mounted at `/var/lib/docker` and `~/.cache`. QEMU's image locking keeps two VMs from sharing one.
- **PAT auth.** *Next:* a GitHub App for org-wide runners and short-lived tokens.
- **Single host, x86_64 only.** Scheduling is a per-repo count; there are no priorities or fair-share yet.
- **Old runner registrations.** If kiln dies mid-boot, the runner it registered stays offline on GitHub until GitHub removes it (about 1 day).
