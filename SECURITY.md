# Security

kiln runs other people's code, or at least your own code at its least trusted, on a machine you care about. This document describes what kiln assumes, what it defends, what it does not, and how to report a problem.

## Threat model

**A job is root in its VM.** The runner user has passwordless `sudo`, and the workflow can run anything. kiln assumes a job is hostile (a malicious pull request, a compromised dependency) and that it can print anything on the VM's console, use the network the VM is given, and try to outlive its timeout.

What kiln protects:

- the host and its other files and processes;
- your LAN and tailnet, and other machines on them;
- the GitHub token and the dashboard;
- other jobs, and the integrity of the repo cache and the base image;
- the Docker mirror's contents.

Out of scope: a QEMU or KVM escape or a Linux kernel bug (keep the host patched), a malicious owner of the box, and anyone who already has an account on the host (the dashboard key and token files are readable by that user).

## What kiln defends

### Dashboard and API access

The dashboard holds a GitHub token and can kill VMs, so access is checked on every request:

- **Tailnet identity.** A request from a tailnet address is mapped to a user with `tailscale whois`. By default only the owner of the CI box is allowed, which keeps out nodes shared in from other tailnets. `allowed_users` replaces that list. Tagged nodes (`tagged-devices`) are never allowed by default and only get in if listed explicitly.
- **HTTPS through `tailscale serve`.** Serve over HTTPS proxies to the unix socket `<data>/serve.sock` (mode 0600, owned by the kiln user), not to the TCP port. tailscaled (root) can connect to it; job VMs cannot reach a unix socket, and other local users lack the permission. Only on that socket does kiln read the `Tailscale-User-Login` and `X-Forwarded-For` headers, which tailscaled overwrites with the tailnet user and source address it saw. The login must match what `tailscale whois` says about that address, and is checked against the same `allowed_users` rule. A serve request without a login (a tagged node) is identified with `tailscale whois` exactly as over TCP, so a tagged node is refused unless `tagged-devices` is listed. A request from the box's own tailnet address or node (tailscaled names the box's owner for those, and a job VM can reach the box's address through QEMU's NAT) is treated as local and needs the dashboard key; an address kiln does not recognize makes it re-read its own addresses (at most every 10 s) first. A Funnel request (`Tailscale-Funnel-Request`, the public internet) is refused. On the TCP port these headers are ignored: anyone can send them there.
- **Never TCP-forward or funnel `serve.sock`.** tailscaled overwrites the identity headers only in its HTTPS reverse proxy (`tailscale serve --https=… unix:…`). A raw TCP forward to the socket (`--tcp`, `--tls-terminated-tcp`) passes the client's bytes through, headers included, and Funnel opens the port to the internet. kiln reads `tailscale serve status --json` (cached for a minute, re-read when Serve is toggled from the dashboard) and trusts the socket's headers only while every handler that targets it is a Web proxy on a port without Funnel. Otherwise, or when tailscale can't be asked, every request on the socket is treated as local and needs the dashboard key; kiln logs a warning and `kiln doctor` fails the "tailscale serve" check.
- **Dashboard key for local requests.** Requests from the box itself (loopback, the box's own tailnet IP) need the key in `<data>/dashboard.key` (mode 0600, 24 random bytes from `/dev/urandom`, compared in constant time). The source address cannot be trusted for these because job VMs reach the host through QEMU's NAT and look exactly like local traffic. If kiln cannot read its own Tailscale identity (for example while Tailscale is down), only loopback and tailnet addresses are admitted, and both need the dashboard key.
- **Everything else is refused:** the LAN, the public internet, and anything not on the tailnet.
- **Host header check.** The `Host` (through `tailscale serve`, the `X-Forwarded-Host` tailscaled sets) must be an IP, `localhost`, a `*.ts.net` name or a single-label MagicDNS name. This blocks DNS rebinding.
- **CSRF header.** Every non-GET request to `/api/` needs the custom `x-kiln` header, which a browser cannot add cross-origin without a CORS preflight that kiln never grants.
- **GitHub proxy allow-list.** `/api/gh/...` reads only `repos/<configured repo>/actions/` workflows, runs and jobs, with plain path characters only and no dot segments, and writes only what the dashboard does: rerun or cancel a run, dispatch a workflow. Runners, secrets, variables, run approvals and deployment reviews are unreachable.
- **Response headers.** A strict `Content-Security-Policy`: `default-src 'none'`, scripts only by the SHA-256 of the page's own inline blocks (computed from the embedded page at startup), connections to the same origin only, forms only to `https://github.com`, no framing, no `<base>`. An injected script or handler does not run even if some string slipped past the page's HTML escaping, which matters because the page holds the dashboard key. Also `X-Content-Type-Options: nosniff` (the GitHub proxy passes content types through), `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy: same-origin`, a `Permissions-Policy` denying camera, microphone, location, USB and payment, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and `Cache-Control: no-store` on API responses. The page only links to `https://github.com/` URLs it gets from the API.
- **Audit log.** Every admitted API write is appended to `<data>/audit.log` (mode 0600, rolled over at 8 MiB, also written to kiln's log); refused writes are logged to kiln's log only, so a job cannot flood the file: when, the tailnet login or `local`, the source address, method, path, status, and what changed (the keys of a config save, the repo of a cache clear). Ship it to your log pipeline if you need it kept.
- **Bounded identity lookups.** The `tailscale` CLI calls the guard depends on are killed after 20 seconds; a timeout counts as an unknown identity, which is refused, or, when kiln cannot learn its own addresses at all, as local, which needs the dashboard key.
- The GitHub token is stored with mode 0600 and never included in error messages. A job VM only ever receives a single-use JIT runner configuration, which is deleted from the host as soon as the guest has read it.

### VM isolation

Each job runs in its own QEMU/KVM guest on a throwaway qcow2 overlay, so nothing survives the job. QEMU runs as your unprivileged user, with no tap devices, bridges or sudo. The job's disk, JIT secret and sockets are deleted when the VM ends, and runners that never ran are deregistered.

### VMM confinement

A QEMU escape is out of scope, but kiln limits what one would gain, as libvirt does for its guests:

- **seccomp:** every QEMU runs with `-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny`, so an escaped QEMU cannot start a shell or any other program, gain privileges or use obsolete syscalls. A QEMU without seccomp support refuses the option and no VM starts.
- **Landlock:** a job VM's QEMU is started through `kiln __confine`, which restricts it to the system directories (read-only), `/dev/kvm` and the standard character devices, the images directory and its own repo's cache disk (read-only), and its VM's `q/` directory (disks, JIT secret, sockets). It cannot read the GitHub token, the App key, the dashboard key, other jobs' files or other repos' caches, cannot write its own VM record or logs, and cannot ptrace kiln or other VMs; on Linux 6.12+ it also cannot signal them or use abstract unix sockets; with the newest Landlock ABI it cannot connect to unix sockets such as tailscaled's or Docker's. Landlock is best effort: `kiln doctor` and kiln's startup log report what the kernel enforces. A trusted cache overlay is committed only after `qemu-img info` shows a plain qcow2 file backed by exactly that repo's cache disk, with no external data file, so a compromised QEMU cannot steer the commit into another file.

### Files on the host

The data directory is set to mode 0700 at every start, and the systemd unit sets `UMask=0077`: job logs (which may contain what a job printed), repo caches, VM disks and the key files are private to the kiln user. Secret files (token, App key, dashboard key) are written atomically with mode 0600 even when a looser file existed. `config.json` is validated at startup and kiln refuses to start on an invalid one, so a hand-edited typo cannot weaken a setting (for example an `egress` value that is neither `open` nor `filtered`).

### Filtered egress

With `egress: "filtered"` each job's QEMU runs in its own rootless network namespace with an nftables allow-list loaded first, and then drops all capabilities. Jobs reach the public internet, DNS and the Docker mirror port only; the LAN, tailnet, the host's own addresses, cloud metadata addresses, every other host loopback port and outbound SMTP are blocked, and IPv6 is off. If any setup step fails, QEMU never starts. A probe verifies the filter and kiln launches nothing while it fails, never falling back to open. See [docs/architecture.md](docs/architecture.md#egress).

### Cache trust

The per-repo cache disk follows a trusted-writer, throwaway-reader rule. Every job gets a private overlay, and an overlay is merged back only when the job succeeded according to GitHub's API (not just the console), the event was a `push`, the branch is the default branch or one of the repo's `cache_branches`, and the commit is really on that branch. A branch name outside `A-Z a-z 0-9 . _ / -` (or containing `..`) never writes. A pull request can read the cache but never poison it. The decision uses GitHub's data because the job controls its own console output.

Release builds do not read the cache at all: a job for a pushed tag or a `release` event detaches it before its first step and runs on the clean base image, so a dependency compromised in some default-branch job cannot plant a toolchain that ends up in what you ship. After every job, login tokens that tools write under cached paths (`cargo login`, `huggingface-cli login`) are deleted before the cache can be saved. See [docs/architecture.md](docs/architecture.md#release-builds-run-cold).

### Fork pull requests

kiln refuses to run code from a fork. The scheduler does not count queued jobs of runs whose head repository differs from the repository (or is gone), so they never boot a VM, and the dashboard lists them as refused. Because a JIT runner can still be handed any queued job with matching labels, every VM also runs a runner job-started hook before the job's first step: if the event is a pull request (`pull_request` or `pull_request_target`) from another repository, or a `workflow_run` whose triggering run's head repository is another one, it fails the job right there, and kiln kills the VM when it sees the assignment. It fails closed: a deleted fork, a `workflow_run` with no head repository, or an unreadable event payload are refused too. This is enforced whatever the workflow says; the `if:` guard in the workflows is a second layer.

The hook can only see where the event came from, not what the workflow then checks out. Workflows triggered by `issue_comment`, `repository_dispatch` or `workflow_dispatch` (or anything else) that check out a pull request's head, such as a "/test" comment bot, run fork code that kiln cannot detect. On a public repository such workflows must not run on kiln: give them a GitHub-hosted runner.

### Console and lifecycle hardening

Console lines may shape the timeline but cannot rewind state or extend a VM's life:

- each lifecycle line ("Listening for Jobs", "Running job", the result) is accepted once and only forward;
- the hold is granted only after a non-success verdict line; a job can forge that or cancel its own hold, but cannot hold a VM that never ran a job;
- lines are capped at 64 KiB (a longer line and its remainder are never parsed) and logs at 64 MiB;
- every VM has a **hard lifetime cap** of idle timeout + job timeout + hold time + 5 minutes, enforced by kiln outside the guest.

### Base image

kiln launches no VM, warm ones included, on a base image baked from an older recipe than the binary expects (`recipe` in `images/base.json`), since such an image may lack the current job hooks (fork refusal, cold release builds). The dashboard shows why, and `auto_rebake` (or Settings › Image) replaces the image. The bake refuses an `actions/runner` release tag that is not `N.N.N`, checks each Node tarball against the release's `SHASUMS256.txt` from nodejs.org before unpacking it, and accepts only plain apt package names in `bake_apt_packages` (no trailing `-` or `+`, which apt reads as remove or install, and no `=` or `/` version pins). The Node checksum guards against a corrupted or swapped tarball, not against nodejs.org itself, since the sums come from the same origin over HTTPS.

### Self-update

kiln installs only releases signed with its release key. Release CI signs each tarball's bytes with an Ed25519 key; the public key is compiled into kiln. The key is a secret of the `release` GitHub Environment, which only `v*` tags can deploy to, and only the `sign` job uses it: that job runs in its own fresh VM after a separate `build` job (where build scripts, proc macros and rustup run) has produced the tarballs, executes no project code, writes the key only to a mode 0600 temporary file removed in the same step, and verifies every signature against the embedded public key before publishing. A tag push runs the workflow file of the tagged commit, so whoever can push a `v*` tag can get a release signed: on this repository that is only the owner (there are no other collaborators; on GitHub Pro or a public repository, add a tag ruleset restricting `v*` to admins). The "tag is on main" check in the workflow guards against mistakes, not against a malicious tagger. Before unpacking anything, kiln verifies the signature, then the tarball's SHA-256, then lists the archive and extracts only the `kiln` binary, which must report the release's version (so an old signed build relabelled as a new release is refused). A compromised release page or `update_repo` setting cannot make kiln run an unsigned binary; what it can do is withhold updates, or (by pointing `update_repo` at a copy of the releases) offer a genuine signed release that is newer than the running one but not the newest. A compromised owner account can publish signed releases. Updates are applied only from the dashboard (or `auto_update`), behind the access guard.

**Who can sign:** the release workflow signs whatever a `v*` tag points at, so anyone who can push such a tag to the repository can produce a signed release, but only of a commit already on `main` (the workflow refuses otherwise) and only when the tag matches `Cargo.toml`'s version. Protect `main` and restrict who can push `v*` tags (a tag ruleset) accordingly. The key reaches only the signing step, which runs after the build and packaging, runs no project code and fetches nothing; the next step checks every signature against the public key in `src/update.rs`, so a wrong key never publishes.

**Key rotation:** a kiln trusts only the key it was built with. Releases signed with a new key are refused by older kilns, so after a rotation install one release by hand; later updates are automatic again. If the private key leaks, rotate it and reinstall by hand everywhere, since every kiln built with the old key would accept a release signed with it.

### Docker mirror

The mirror listens on host loopback only and is a pull-only proxy of public Docker Hub images. It holds no credentials and cannot be pushed to. The registry binary it runs is pinned by version and SHA-256, and a different download is refused.

### Debug SSH

sshd does not run during jobs. Held VMs accept keys from `debug_ssh_keys` only (no passwords, no root login), on a port bound to the box's tailnet address or loopback, with host key fingerprints printed for you to compare.

## Known residual risks

kiln is honest about these:

- **Open egress is the default.** With `egress: "open"`, a job has full outbound access including your LAN and your tailnet (it appears to come from the box), and, through QEMU's `10.0.2.2`, **every service listening on the host's loopback** (databases, dev servers, local admin UIs): QEMU's user networking has no switch to turn that off. That is fine for your own private repos and not for untrusted code or a box that runs other services. Filtered mode blocks all of it except the Docker mirror; it is opt-in until it has been verified on more hosts.
- **DNS exfiltration in filtered mode.** DNS goes through the host's resolver, so a job can leak data in DNS queries. DNS is not filtered.
- **IPv6 is disabled, not filtered.**
- **The denylist covers private ranges only.** Public addresses that the host can reach are not blocked. Notably, if your router hairpins its WAN address, a job could reach services you forwarded from the Internet. Keep Tailscale subnet-route acceptance off on this host, since routed subnets would also be reachable.
- **Without `rootlessctl`, the debug SSH port is open for the whole VM life in filtered mode.** The port is published statically at launch rather than at hold time. Nothing listens on it by default, but a job is root and could start a listener. Install `rootlesskit` with `rootlessctl` to publish it only at hold time.
- **The Docker mirror's `/v2/_catalog` and other reads are visible to every job** and shared between repos. It only caches public images, so this is acceptable, but jobs can learn what other jobs pulled.
- **The cache can be poisoned by a compromised default branch or cache branch.** The trust rule stops PRs and other branches, not code already merged into a writer branch. Only list branches in `cache_branches` that are as protected as the default.
- **The base image gives `runner` passwordless sudo,** and bake VMs always use open networking.
- **Local file secrets.** The GitHub token and dashboard key are plain files readable by the kiln user.
- **One host.** There is no tenant separation between repos beyond VM and cache-disk isolation.
- **Nested virtualization is on.** Guests get `-cpu host` and may use KVM themselves (Android emulators, VM tests), which exposes the host's nested-virtualization code to jobs.
- **Secrets in cached paths persist.** Apart from the login tokens kiln scrubs, anything a trusted job writes under a cached directory (including Docker images built with secrets in their layers) is visible to later jobs of the repo, pull requests included, exactly as with `actions/cache`.
- **One release key.** Self-update trusts a single Ed25519 key; losing it means installing one release by hand on every box, and a leaked key must be rotated the same way. Releases carry no signed expiry, so a mirror can withhold updates (see [Self-update](#self-update)).
- **Landlock depends on the kernel.** Without it (Linux older than 5.13, or `landlock` missing from `lsm=`), QEMU is limited by seccomp only.

## Recommendations

- **Never let fork pull requests reach kiln.** kiln refuses them itself (see [Fork pull requests](#fork-pull-requests)); as a second layer, for a public repo guard every `pull_request` job (kiln's own workflows and the `kiln-hello.yml` it generates already do):

```yaml
jobs:
  test:
    # Never run pull requests from forks on self-hosted hardware.
    if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository
    runs-on: [self-hosted, kiln]
```

  Also keep GitHub's "Require approval for all outside collaborators" setting on (Settings › Actions › General). Workflows that check out a pull request's head from an `issue_comment`, `repository_dispatch` or `workflow_dispatch` trigger must not use kiln on a public repo: kiln cannot tell (see [Fork pull requests](#fork-pull-requests)).

- Set `egress` to `filtered` before running untrusted pull requests, such as ones from forks, and check Diagnostics shows "filtered egress" passing. Also consider requiring approval for workflows from outside contributors in the repository's GitHub settings.
- Prefer a GitHub App (Settings › GitHub › Create GitHub App, see [docs/configuration.md](docs/configuration.md#github-app)): only its private key is stored, its tokens expire after an hour, and it never gets write access to code. Otherwise,
- use a fine-grained token with only the repos you serve and the permissions listed in [docs/configuration.md](docs/configuration.md#github-token): *Administration: write*, *Actions: read and write* and *Contents: read*. Add *Contents* and *Workflows* write only while you use the hello PR.
- Keep `allowed_users` empty (owner only) or minimal, and do not share the box's node to other tailnets.
- Keep the host, QEMU and Tailscale updated, and let `auto_rebake` keep the guest and runner current.
- Do not put secrets on the CI box that a job in an open-egress VM could reach over the LAN.
- Release debug holds when done; a held VM keeps a login path open until it expires.

## Reporting a vulnerability

Please report security problems privately, never in a public issue:

- preferred: GitHub's private vulnerability reporting on this repository (Security › Advisories › Report a vulnerability);
- otherwise: contact **@Bunty9** on GitHub and ask for a private channel.

Include what you found, how to reproduce it and the kiln version (`kiln --version`).

What to expect: an acknowledgement within 3 working days, an assessment within 10, and a fix or mitigation plan for confirmed issues as soon as it is ready; you are credited in the advisory unless you prefer not to be. Fixes ship as a new release (kiln updates itself, see [Self-update](#self-update)) with a GitHub security advisory. Only the latest release is supported: there are no backports.

Releases are signed (see [Self-update](#self-update)), and on the public repository each release tarball also has a GitHub build provenance attestation: `gh attestation verify kiln-X.Y.Z-x86_64-linux.tar.gz --repo Bunty9/kiln`. CI checks dependencies against the RustSec advisory database, licenses and sources with `cargo deny` on every change.
