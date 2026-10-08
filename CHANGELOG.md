# Changelog

All notable changes to kiln are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Opt-in usage statistics and crash reports.** Both are off until you choose: the dashboard asks once (the Setup page, or an Overview banner on existing installs), and the new Settings › Privacy page changes the choice and shows the usage report exactly as it would be sent, plus an example crash report. Usage is a daily report of counts and settings; a crash report carries the version and the panic's location in kiln's code, never the message. Neither ever includes repo, account or host names, IPs, file paths on this box, tokens or logs. kiln sends them itself (the dashboard stays offline); `DO_NOT_TRACK=1` or `KILN_TELEMETRY=0` turns both off. New config keys `usage_stats` and `crash_reports`, and `GET /api/telemetry`. Reports go to `kiln-telemetry-api.vercel.app`, which stores them for 400 days without IPs. See SECURITY.md › Telemetry.
- A `check` workflow runs format, clippy, tests and the dashboard and service worker syntax checks on a GitHub-hosted runner for every push to main and every pull request, forks included (read-only token, no secrets).
- **Settings › Analytics.** Jobs, success rate, median and p95 job time, time to start, job minutes and savings for the last 24 hours, 7 or 30 days, filtered by repo and VM size; stacked charts of jobs by outcome and minutes by VM size, the median queue/boot/wait/job split, a per-repo table and the slowest jobs. Each chart's numbers are also a table under "Show numbers". A last chart reads the usage ledger, so it includes jobs older than the newest 100 VMs (last 30 UTC days, by the day each job finished).
- **Swipe between tabs on phones.** A quick sideways swipe on the page moves to the next or previous bottom tab; it is ignored on form fields, the host graphs, anything that scrolls sideways, and at the screen edges (the browser's back gesture).
- Job rows show where the code came from: branch, PR number, short commit and the run's title (commit message or PR title), plus the trigger when it is not a push or PR (manual, scheduled, ...). The job page shows the same, with the PR and commit linked to GitHub, and the workflow name with its run number. kiln records this on the VM when its runner picks up a job, so jobs from before the upgrade show none.

- Help for the new pages: guides for Analytics & savings and for Privacy & reports (what each report holds, and how to turn both off for good with `DO_NOT_TRACK=1`), and "?" help on Settings › Analytics, Settings › Privacy, the Overview's Recent failures and a job's branch/PR/commit line. Getting started mentions swiping between tabs on phones, and the Jobs tip and Debug guide mention the new run details.
- An Alerts & webhooks guide for Settings › Notifications: what each destination kind and event switch sends, workflow rules, which addresses are allowed, retries and the failing banner, and where to find how to verify signed requests.

### Changed

- README: says who kiln is for and what it needs (x86_64 Linux with KVM, Tailscale, GitHub) on the first screen, adds a "Why not X?" comparison and a Performance section, replaces the generated cover image with a recorded demo of the real dashboard (`docs/media/`), and links measured benchmarks with their method (`docs/benchmarks.md`).
- `docs/stacks.md` drops planned or nonexistent items (`kiln status`, forking kiln) and links GitHub's official pricing docs for the hosted runner prices it quotes. `CONTRIBUTING.md` describes the current `src/` layout.
- The Overview's Recent failures section shows only jobs that failed in the last 15 minutes (it was 7 days), and is hidden when there are none.

## [0.2.4] - 2026-10-08

### Security

- **QEMU is confined.** Every VM's QEMU runs with libvirt's seccomp policy (`-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny`): no exec, no setuid, no obsolete syscalls. A job VM's QEMU also starts through `kiln __confine`, which applies a Landlock ruleset first: QEMU sees the system directories, `/dev/kvm` and the standard character devices, the images directory and its repo's cache disk (read-only), and writes only `vms/<id>/q/` (its disks, JIT secret and sockets; kiln's record and logs sit outside it, and QEMU can only append to the console log through its own output). It never inherits a token from kiln's environment (`KILN_GITHUB_TOKEN`, `GITHUB_TOKEN`, `GH_TOKEN`). kiln refuses to start with its data directory under a path QEMU may read (such as `/opt`), connects to QEMU's sockets without following symlinks, and notes on a VM's page when the kernel has no Landlock. It cannot read the GitHub token, App key, dashboard key, other jobs or other repos' caches, or ptrace kiln or other VMs; on Linux 6.12+ it cannot signal them either. A trusted cache overlay is committed only if its qcow2 header names exactly the repo's cache disk and no external data file. New doctor checks "qemu sandbox" and "landlock". A QEMU built without seccomp now fails to start VMs instead of running unfiltered.
- **Release builds run cold.** A job for a pushed tag or a `release` event detaches the repo cache before its first step, so a toolchain planted in the cache by a compromised dependency in some default-branch job never reaches a release build. After every job, `cargo login` and `huggingface-cli login` tokens (`token` and `stored_tokens`) are deleted from the cache before it can be saved. This needs a rebake (recipe 5): launching waits until the image is rebaked, which `auto_rebake` does by itself.
- **Audit log.** Every admitted API write is appended to `<data>/audit.log` as a JSON line (who, from where, what, status, which config keys changed); refused writes go to kiln's log.
- **Stricter dashboard headers:** a hash-based `Content-Security-Policy` (only the page's own inline scripts run), `nosniff`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy` and `Permissions-Policy`. The page links only to `https://github.com/` URLs from the API and refuses repo names with dot segments when building GitHub proxy paths.
- **The GitHub proxy writes less:** POST is allowed only to rerun or cancel a run and to dispatch a workflow (no run approvals or deployment reviews).
- **Private files.** The data directory is set to mode 0700 at every start (it inherited the umask before, usually 0775, so other local users could read job logs and repo caches), the systemd unit sets `UMask=0077`, and the token and dashboard key are written atomically with mode 0600 even over an existing looser file.
- rootlesskit's state directory moved to `<data>/rk/<id>`, out of the confined QEMU's reach, and VM records are used at startup only if their id names their own directory.
- **Fail-closed config.** `config.json` is validated at startup with the dashboard's rules; kiln refuses to start on an invalid or unreadable file (only a missing one means the defaults) instead of, for example, treating an unknown `egress` value as open networking.
- `tailscale` CLI calls in the access guard time out after 20 s and fail closed (unknown identity, or local when kiln cannot read its own addresses); failures are logged.
- CI checks dependencies with `cargo deny` (RustSec advisories, licenses, sources), pins `actions/checkout` by SHA, and releases of the public repository carry build provenance attestations.

### Added

- **Host graphs on the Overview.** The Host card's CPU and memory bars are split by job VM, one colour per VM (the same colour marks its tile under Now running), with grey for the rest of the host. Opening the card shows stacked area charts of both over the last 5 minutes, 15 minutes or an hour, scrolling continuously, with a crosshair readout per VM. kiln samples `/proc` every 2 s and keeps an hour in memory (`GET /api/host`).
- **On crates.io as `kiln-ci`:** `cargo install kiln-ci --locked --root ~/.local` installs the `kiln` binary. Every `v*` tag publishes there after the GitHub release.

### Changed

- Restarts drain running jobs first instead of killing them ([#23](https://github.com/Bunty9/kiln/issues/23)). After saving a setting that only applies at startup (`listen` is the only one), the Overview shows "Restart needed to apply: listen" with **Restart when idle**, which drains like an update (no new VMs, idle ones reaped, running jobs finish, at most the job timeout + 2 min) and re-executes kiln in place, and **Restart now**, which kills running jobs after a confirmation that says so. The drain shows as "Restart pending · waiting for N VMs" with Cancel and Restart now, is logged in the journal, and is in `/api/state` as `restart`. New endpoints: `POST /api/restart` (`?now=true` to skip the wait) and `POST /api/restart/cancel`. A restart and an update never drain at once.
- `systemctl restart` / `stop` (SIGTERM) now stops launching at once and gives running jobs up to the new `stop_grace_secs` (default 25, Settings › Timeouts) to finish before killing their VMs; a second SIGTERM (`systemctl --user kill --kill-whom=main kiln`) or Ctrl-C skips the wait. The journal and the dashboard show the progress. `deploy/kiln.service` raises `TimeoutStopSec` from 30 to 600 so a longer grace (up to 570 s) fits: reinstall the unit to get it (see docs/configuration.md, Restarting kiln). Under an older unit kiln shortens the grace to fit its timeout, logs a warning, and `kiln doctor` flags the unit. Job VMs now run in their own process group, so Ctrl-C at a foreground `kiln serve` gives them the grace too.
- A `listen` address kiln cannot bind (not on this machine, a privileged port, a port in use) is refused when saved and before a restart, instead of leaving kiln crash-looping and unreachable. If the configured address cannot be bound at startup, kiln serves on the last address that worked or `127.0.0.1:7878` and says so on the Overview.
- Docs: install from public release downloads without `gh`, and report vulnerabilities through GitHub's private vulnerability reporting.

### Fixed

- **"Saved this month" counts every job.** It summed only the last 100 jobs the dashboard loads, so a busy month read low (one box ran 239 jobs in two days). kiln now keeps job minutes per UTC day and VM size in `<data>/usage.json`, seeded from the VM history on first start. Each job counts from start to its result as GitHub bills it, so a debug hold is no longer billed (jobs recorded before this version, and jobs killed before a result, count until the VM ended), and is priced at the current GitHub-hosted rate for its size (2-core $0.006, 4-core $0.012, 8-core $0.022, 16-core $0.042 per minute; the old figures predated GitHub's 2026 price cut). The month is the UTC calendar month GitHub bills by. A custom flat rate still overrides.

- VM records (`meta.json`) are written atomically, so a crash mid-write no longer hides a VM from the startup cleanup.

## [0.2.3] - 2026-10-07

### Fixed

- **Serve over HTTPS** no longer hangs and leaks a `tailscale serve` process on a tailnet without HTTPS certificates (#15). kiln reads `CertDomains` from `tailscale status` first and refuses with "This tailnet can't issue HTTPS certificates. Enable DNS › HTTPS Certificates in the Tailscale admin console…". Every tailscale CLI call now runs with stdin closed in its own process group, bounded (15 s for `serve`, 20 s otherwise; turning serve on takes at most 35 s end to end: the ≤20 s `tailscale status` preflight plus the ≤15 s `serve`), and the whole group is killed on timeout or when the client goes away, so the request always returns and nothing is left behind.
- The Serve toggle shows the server's error (including a timeout) next to it instead of silently reverting, and warns up front when the tailnet has HTTPS certificates off. `kiln doctor` and Diagnostics show "tailscale HTTPS: unavailable on this tailnet (DNS › HTTPS Certificates is off)" in that case.
- A GitHub outage of runner registration no longer burns a VM a minute with no signal ([#16](https://github.com/Bunty9/kiln/issues/16)). kiln mints the JIT runner config before it creates the VM's directory, disk or QEMU, so a refused registration costs one API call and leaves nothing on disk. The VM record, job page and journal say "runner registration failed: GitHub returned HTTP 500 (generate-jitconfig)" instead of a generic failure.
- A 5xx (or no answer) from runner registration pauses all launches for 1, 2, 5, then 10 minutes, capped, instead of a per-repo backoff that kept retrying every minute; a 4xx stays a per-repo failure. After each pause kiln launches a single probe VM rather than the whole queue, and in GitHub App mode a failure minting the installation token is classified the same way. The first successful registration resumes launches. Registration failures are marked `mint_failed` on the VM record: they stay out of Failed in 24h, Recent failures and browser notifications, and only the latest 5 are kept, so an outage does not push job history out. The Overview shows "GitHub is rejecting runner registration (HTTP 500) — launches paused, retrying in N min" (`poll.blocked_kind` `github_api`), and the journal logs a warning once per backoff step.
- A VM whose runner came online but got no job (it went to another runner or was cancelled) ends in the new `unneeded` state, shown as "not needed", instead of `failed`. It no longer counts in Failed in 24h, Recent failures or the per-repo backoff. A runner that exits before coming online, or after starting a job without a result, is still `failed`, with a note saying which.
- `debug_hold_mins` no longer holds cancelled jobs ([#17](https://github.com/Bunty9/kiln/issues/17)). Only a `Failed` (or `Abandoned`) result earns a hold; a `cancel-in-progress` cancellation, which has nothing to inspect, releases its VM at once.
- Debug holds can no longer deadlock the queue: at most `max_vms - 1` VMs are held at once (none with `max_vms: 1`), and when a job is queued with no free slot, kiln releases the hold that expires first, noting "hold released early: a queued job needed the slot" on the VM and in the journal.
- The Overview says when holds keep jobs waiting: "N of M slots held for debugging — jobs are waiting" (`poll.blocked_kind` `held`), with Release oldest and a link to the held job. docs/configuration.md explains what a hold costs.
- `kiln doctor`'s repo check exercises the write path: it mints a runner registration token (cached 10 minutes per repo) and reports "runner registration works" or "runner registration failing: HTTP 500", instead of a green "runners, actions and contents reachable" while registration was impossible.

## [0.2.2] - 2026-10-07

### Changed

- **Serve over HTTPS** no longer asks for the dashboard key. `tailscale serve` now proxies to a unix socket, `<data>/serve.sock` (mode 0600), and kiln identifies the tailnet user from the `Tailscale-User-Login` header tailscaled sets there, applying the usual `allowed_users` rule. Before, every HTTPS request arrived from `127.0.0.1` and looked local. A browser on the box itself still needs the key; Funnel requests are refused; identity headers on the TCP port are ignored. If Serve was already on, turn it off and on again in Settings › Network to switch to the socket.
- **Dashboard look:** a neutral monochrome theme on near-black (and a neutral light theme) with higher contrast throughout (body text 15:1+, secondary 8:1+, meta 6:1+), 1px borders defining surfaces, and colour kept for the accent and job states; the warm card glow is gone. Selects, switches, number and file inputs, details, focus rings and form errors are restyled to match, and Appearance gains a Mono accent.

### Fixed

- GitHub App mode tracks rate limits per installation: one installation hitting its limit pauses only its own repos (with a repo error saying until when) instead of all polling. `/api/state` reports the most constrained installation's limit in `poll.rate` and each installation's in `poll.rates`.
- The dashboard recognizes the "base image too old" launch block by a new `poll.blocked_kind` field instead of matching the message text.
- GitHub App mode never records or pauses on an unauthenticated call's rate limit, and a call that went out without a token because minting failed is billed to the anonymous budget, not the installation. A secondary-limit 403 on an anonymous call no longer stops all polling.
- The rate shown in `poll.rate` and `poll.rates` ignores identities whose rate-limit window has already reset.

### Security

- The serve socket trusts tailscaled's identity headers only while `tailscale serve status` shows nothing but HTTPS reverse proxies to it on ports without Funnel. A raw TCP forward (`--tcp`, `--tls-terminated-tcp`) or Funnel would let a client write `Tailscale-User-Login` itself; kiln then requires the dashboard key on the socket, logs a warning and fails the new "tailscale serve" doctor check. See SECURITY.md: never TCP-forward or funnel `serve.sock`.
- A serve login is cross-checked with `tailscale whois` of the forwarded address: the users must match and the node must not be the box itself. An address kiln does not recognize makes it re-read its own addresses (at most every 10 s) before deciding.
- A tagged node through serve (no login) is identified like a TCP peer and refused unless `tagged-devices` is in `allowed_users`, instead of being treated as local.

## [0.2.1] - 2026-10-07

### Fixed

- Dashboard tooltips meet WCAG 1.4.13: a tooltip stays open while the pointer moves onto it, Escape dismisses it, and it hides shortly after the pointer leaves both. Tips on badges, meters, status-line items and job metadata can be reached by keyboard; a job row shows its status and start time when focused.
- The Repos page switches between the add-repo form and the GitHub App layout when App mode is turned on or off while it is open.
- An image too old to launch VMs from shows one banner, with Rebake, instead of two.
- The GitHub App manifest name stays within GitHub's 34-character limit on long hostnames.

## [0.2.0] - 2026-10-07

### Added

- GitHub App authentication: create the App from the dashboard (manifest flow) or use an existing one. Installation tokens are minted per installation and refreshed before they expire; only the private key is stored. The repos kiln serves are the repos the App is installed on, refreshed every 5 minutes (every 30 s while it serves none), or at once with `POST /api/app/refresh`. Token auth still works.
- Installable dashboard (PWA) over HTTPS (`tailscale serve`): app icon, web manifest with shortcuts, a versioned service worker that never caches `/api` and falls back to the last loaded shell or an offline page, and an **Install app** button.
- `app_accounts`: in App mode, accounts whose installations are served besides the App owner's.
- `cache_branches`: per repo, extra branches whose successful pushes also save the cache (for branch models that integrate on `dev` rather than the default branch). Settable on the repo page.
- `bake_node_versions`: Node versions pre-seeded into the tool cache at bake time (default `["24"]`), resolved on nodejs.org and recorded in `base.json`. Changing the set marks the image stale; so does an image baked by an older kiln (recorded as `recipe` in `base.json`).
- `repo_cache_gb`: per-repo cache disk size, overriding `cache_gb`. Settable on the repo page.
- `size_mem_mb`: memory of non-default VM sizes (e.g. 8 vCPU / 12 GB). Settable in Settings › Capacity.
- `bake_apt_packages`: extra apt packages baked into the image. Changing the set marks the image stale.
- `/var/cache/apt/archives` lives on the repo cache disk, so `apt-get install` reuses downloaded packages.
- `kiln doctor` names the missing token permission per repo; the dashboard shows the token's expiry and save time and warns before it expires.
- Over-the-air updates from signed GitHub releases (Settings › Updates): kiln checks `update_repo` (default `Bunty9/kiln`) at startup and every 6 hours, shows the release notes, and on **Update** downloads the tarball for its build, verifies its Ed25519 signature and SHA-256, drains (no new or warm VMs, running jobs finish), swaps its binary keeping `<exe>.prev`, and re-execs in place. A version that fails to start twice (counted from the very start of `kiln serve`) is rolled back, and `auto_update` never installs it again, only a newer release. `auto_update` (default off) applies updates when no job runs and no VM is held (idle warm VMs do not count). No bake starts during the drain, and the drain waits for a running one. Open dashboards, including an installed app's cached page, reload into the new version. API: `GET /api/update`, `POST /api/update/{check,apply,cancel}`.
- Releases include a fully static `x86_64-linux-musl` build next to the glibc one, and a `.sig` (Ed25519) for each tarball.
- Dashboard polish: elevated surfaces instead of outlines, an icon set, hover and focus tooltips on states, stats and actions, no layout shift between pages, and Settings › Appearance (theme, density, accent, reduced motion; per browser). In App mode, Setup and Repos show the App install button and a Refresh, and a failed App creation can be retried.

### Security

- Self-update installs only tarballs signed with the release key compiled into kiln; a new key needs one manual install.
- GitHub App mode serves only installations on the App owner's account (matched by account id, read from GitHub at each refresh) or listed in `app_accounts`; others are ignored and reported. A call for a repo the App does not serve never borrows another installation's token.
- `app.pem`, `app.json` and the setup states are written atomically with mode 0600, also when the files already existed.
- Fork pull requests are refused by kiln itself: never counted as demand, failed by a pre-job hook in the VM before any step, and the VM killed. The hook also refuses `workflow_run` runs triggered from a fork (only the hook can see those).
- **Upgrade note:** kiln launches nothing on an image baked by an older guest recipe (now `recipe` 3), because such an image lacks the fork-refusal hook. `auto_rebake` (on by default) rebuilds it within minutes; with it off, rebake by hand after upgrading.
- Bake inputs are checked before they reach the bake VM's root shell: the config is re-validated, the runner release tag must be `N.N.N`, Node tarballs are verified against nodejs.org's SHASUMS256.txt, and apt names ending in `-` or `+` (apt's remove/install markers) are refused.
- Cache-writer branch names outside `[A-Za-z0-9._/-]` never save the cache.
- The "commit is really on the branch" check applies to every cache-writer branch, not only the default.

### Fixed

- App setup: a failed code conversion (network error, 5xx) can be retried with the same link, setup links survive a kiln restart, and an expired or used code explains how to recover an App GitHub already created.
- App mode: baking and the runner release check work before the App is installed anywhere (that lookup is public and now unauthenticated).
- App mode: a 401 on an installation token always invalidates the cached tokens; Diagnostics reuses a discovery from the last minute.
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

[Unreleased]: https://github.com/Bunty9/kiln/compare/v0.2.4...HEAD
[0.2.4]: https://github.com/Bunty9/kiln/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/Bunty9/kiln/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/Bunty9/kiln/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/Bunty9/kiln/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Bunty9/kiln/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Bunty9/kiln/releases/tag/v0.1.0
