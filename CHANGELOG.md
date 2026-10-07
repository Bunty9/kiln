# Changelog

All notable changes to kiln are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- GitHub App authentication: create the App from the dashboard (manifest flow) or use an existing one. Installation tokens are minted per installation and refreshed before they expire; only the private key is stored. The repos kiln serves are the repos the App is installed on, refreshed every 5 minutes. Token auth still works.
- `cache_branches`: per repo, extra branches whose successful pushes also save the cache (for branch models that integrate on `dev` rather than the default branch). Settable on the repo page.
- `bake_node_versions`: Node versions pre-seeded into the tool cache at bake time (default `["24"]`), resolved on nodejs.org and recorded in `base.json`. Changing the set marks the image stale; so does an image baked by an older kiln (recorded as `recipe` in `base.json`).
- `repo_cache_gb`: per-repo cache disk size, overriding `cache_gb`. Settable on the repo page.
- `size_mem_mb`: memory of non-default VM sizes (e.g. 8 vCPU / 12 GB). Settable in Settings › Capacity.
- `bake_apt_packages`: extra apt packages baked into the image. Changing the set marks the image stale.
- `/var/cache/apt/archives` lives on the repo cache disk, so `apt-get install` reuses downloaded packages.
- `kiln doctor` names the missing token permission per repo; the dashboard shows the token's expiry and save time and warns before it expires.

### Security

- Fork pull requests are refused by kiln itself: never counted as demand, failed by a pre-job hook in the VM before any step, and the VM killed. Needs a rebake for the hook.
- The "commit is really on the branch" check applies to every cache-writer branch, not only the default.

### Fixed

- The documented fine-grained token permissions now include *Contents: read*, without which caches never saved.

## [0.1.0] - 2026-10-06

First release.

### Added

- Self-hosted CI that boots one fresh rootless QEMU/KVM virtual machine per GitHub Actions job: direct kernel boot (no initrd) of a qcow2 overlay on a frozen Ubuntu 24.04 base image, about 4 seconds to a listening runner.
- `kiln serve`, `kiln bake` (builds the base image from a cloud-init recipe), and `kiln doctor` (checks KVM, tools, disk, memory, image, token, repos, Docker mirror, egress and Tailscale), and `kiln --version`.
- JIT runner registration: single-use, auto-deregistering runners, with the config passed to the guest as an SMBIOS OEM string. Stale offline runners are swept at startup.
- Polling scheduler with ETag-cached GitHub requests and rate-limit pacing. Demand-by-count scheduling per repo and VM size, rotating repo order, memory and vCPU budget, low memory and disk gates, per-repo failure backoff, and a reaper for surplus idle VMs.
- VM sizes by label: `kiln`, `kiln-2cpu`, `kiln-4cpu`, `kiln-8cpu`, `kiln-16cpu`, each scheduled separately.
- Embedded web dashboard with a first-run setup stepper, overview, filterable jobs list with timelines and live console, steps and GitHub logs, repos with workflow dispatch and run rerun and cancel, settings, diagnostics, and favicon and optional browser notifications. Includes an estimate of minutes saved, in-app help, and a hello PR that adds a sample workflow to a repo.
- Tailscale integration: peer list, ping, netcheck, and publishing the dashboard over HTTPS with `tailscale serve`.
- Docker Hub pull-through mirror (pinned registry v3.1.2, SHA-256 verified) with a storage cap, reachable by VMs at `10.0.2.2:5000` with fallback to Docker Hub.
- Per-repo persistent cache disks for Docker layers and package manager and toolchain directories, attached to every job as a private overlay and merged back only by a successful push to the default branch. Parked commits and lock retry for concurrent jobs, and a size reset at 1.2x `cache_gb`.
- Debug hold: a failed job's VM stays up for SSH (`debug_hold_mins`, `debug_ssh_keys`), controlled over the serial console, with host key fingerprints shown on the job page and a Release button.
- Warm pool of pre-booted idle VMs per repo (`warm`, `warm_recycle_mins`).
- Auto-rebake when the runner version or image age goes stale (`auto_rebake`).
- `selftest` and `stacks` workflows, example projects (Node with Postgres, Python with uv, Go, Docker build, Playwright), and a stack compatibility guide.
- Documentation: README, architecture, configuration reference, contributing guide and security policy. Dual licensed under MIT or Apache-2.0.
- Release automation that builds `kiln-<version>-x86_64-linux.tar.gz` with a SHA-256 file when a `v*` tag is pushed.

### Security

- Dashboard access control: tailnet peers identified with `tailscale whois` (owner of the box by default, `allowed_users` to change it), a dashboard key for requests from the box itself, Host header validation against DNS rebinding, a required `x-kiln` header on writes against CSRF, and fail-closed behavior when the box's own tailnet identity is unknown. Tagged nodes are never allowed by default.
- GitHub proxy limited to workflows, runs and jobs of configured repos, with strict path validation. Response headers deny framing and referrers, and prevent caching of API responses.
- Filtered egress (`egress: "filtered"`): each job VM runs in a rootless network namespace (rootlesskit and slirp4netns) with an nftables allow-list for the public internet, DNS and the Docker mirror, blocking the LAN, tailnet, host addresses, metadata and SMTP, with IPv6 off. Capabilities are dropped after the rules load, it fails closed, and a readiness probe gates launches.
- Cache trust rule using GitHub's own record of the job's conclusion, event, branch and commit, so pull requests can read but never poison the cache.
- Hardening against hostile guests: lifecycle lines on the console are accepted once and only forward, a hard VM lifetime cap, capped line length and log size, the hold is granted only after a non-success verdict line; a job can forge that or cancel its own hold, but cannot hold a VM that never ran a job, and SSH published only at hold time (at launch in filtered mode without `rootlessctl`).
- Idle VMs booted under older security settings (egress mode, debug keys) are recycled before they can take a job.
- Mirror binary is pinned and verified by checksum; the mirror is pull-only on host loopback.

[Unreleased]: https://github.com/Bunty9/kiln/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Bunty9/kiln/releases/tag/v0.1.0
