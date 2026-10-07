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
- **Dashboard key for local requests.** Requests from the box itself (loopback, the box's own tailnet IP, `tailscale serve`) need the key in `<data>/dashboard.key` (mode 0600, 24 random bytes from `/dev/urandom`, compared in constant time). The source address cannot be trusted for these because job VMs reach the host through QEMU's NAT and look exactly like local traffic. If kiln cannot read its own Tailscale identity (for example while Tailscale is down), only loopback and tailnet addresses are admitted, and both need the dashboard key.
- **Everything else is refused:** the LAN, the public internet, and anything not on the tailnet.
- **Host header check.** The `Host` must be an IP, `localhost`, a `*.ts.net` name or a single-label MagicDNS name. This blocks DNS rebinding.
- **CSRF header.** Every non-GET request to `/api/` needs the custom `x-kiln` header, which a browser cannot add cross-origin without a CORS preflight that kiln never grants.
- **GitHub proxy allow-list.** `/api/gh/...` passes only GET and POST to `repos/<configured repo>/actions/` for workflows, runs and jobs, with plain path characters only and no dot segments. Runners, secrets and variables are unreachable.
- **Response headers.** `X-Frame-Options: DENY`, `Content-Security-Policy: frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, and `Cache-Control: no-store` on API responses.
- The GitHub token is stored with mode 0600 and never included in error messages. A job VM only ever receives a single-use JIT runner configuration, which is deleted from the host as soon as the guest has read it.

### VM isolation

Each job runs in its own QEMU/KVM guest on a throwaway qcow2 overlay, so nothing survives the job. QEMU runs as your unprivileged user, with no tap devices, bridges or sudo. The job's disk, JIT secret and sockets are deleted when the VM ends, and runners that never ran are deregistered.

### Filtered egress

With `egress: "filtered"` each job's QEMU runs in its own rootless network namespace with an nftables allow-list loaded first, and then drops all capabilities. Jobs reach the public internet, DNS and the Docker mirror port only; the LAN, tailnet, the host's own addresses, cloud metadata addresses, every other host loopback port and outbound SMTP are blocked, and IPv6 is off. If any setup step fails, QEMU never starts. A probe verifies the filter and kiln launches nothing while it fails, never falling back to open. See [docs/architecture.md](docs/architecture.md#egress).

### Cache trust

The per-repo cache disk follows a trusted-writer, throwaway-reader rule. Every job gets a private overlay, and an overlay is merged back only when the job succeeded according to GitHub's API (not just the console), the event was a `push`, the branch is the default branch or one of the repo's `cache_branches`, and the commit is really on that branch. A branch name outside `A-Z a-z 0-9 . _ / -` (or containing `..`) never writes. A pull request can read the cache but never poison it. The decision uses GitHub's data because the job controls its own console output.

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

kiln launches no VM, warm ones included, on a base image baked from an older recipe than the binary expects (`recipe` in `images/base.json`), since such an image may lack the fork-refusal hook. The dashboard shows why, and `auto_rebake` (or Settings › Image) replaces the image. The bake refuses an `actions/runner` release tag that is not `N.N.N`, checks each Node tarball against the release's `SHASUMS256.txt` from nodejs.org before unpacking it, and accepts only plain apt package names in `bake_apt_packages` (no trailing `-` or `+`, which apt reads as remove or install, and no `=` or `/` version pins). The Node checksum guards against a corrupted or swapped tarball, not against nodejs.org itself, since the sums come from the same origin over HTTPS.

### Self-update

kiln installs only releases signed with its release key. Release CI signs each tarball's bytes with an Ed25519 key held in a GitHub Actions secret (written to disk only as a mode 0600 temporary file, removed in the same step); the public key is compiled into kiln. Before unpacking anything, kiln verifies the signature, then the tarball's SHA-256, then lists the archive and extracts only the `kiln` binary, which must report the release's version (so an old signed build relabelled as a new release is refused). A compromised GitHub account, release page or `update_repo` setting cannot make kiln run an unsigned binary; what it can do is withhold updates. Updates are applied only from the dashboard (or `auto_update`), behind the access guard.

**Who can sign:** the release workflow signs whatever a `v*` tag points at, so anyone who can push such a tag to the repository can produce a signed release, but only of a commit already on `main` (the workflow refuses otherwise) and only when the tag matches `Cargo.toml`'s version. Protect `main` and restrict who can push `v*` tags (a tag ruleset) accordingly. The key reaches only the signing step, which runs after the build and packaging, runs no project code and fetches nothing; the next step checks every signature against the public key in `src/update.rs`, so a wrong key never publishes.

**Key rotation:** a kiln trusts only the key it was built with. Releases signed with a new key are refused by older kilns, so after a rotation install one release by hand; later updates are automatic again. If the private key leaks, rotate it and reinstall by hand everywhere, since every kiln built with the old key would accept a release signed with it.

### Docker mirror

The mirror listens on host loopback only and is a pull-only proxy of public Docker Hub images. It holds no credentials and cannot be pushed to. The registry binary it runs is pinned by version and SHA-256, and a different download is refused.

### Debug SSH

sshd does not run during jobs. Held VMs accept keys from `debug_ssh_keys` only (no passwords, no root login), on a port bound to the box's tailnet address or loopback, with host key fingerprints printed for you to compare.

## Known residual risks

kiln is honest about these:

- **Open egress is the default.** With `egress: "open"`, a job has full outbound access including your LAN and your tailnet (it appears to come from the box). That is fine for your own private repos and not for untrusted code. Filtered mode is opt-in until it has been verified on more hosts.
- **DNS exfiltration in filtered mode.** DNS goes through the host's resolver, so a job can leak data in DNS queries. DNS is not filtered.
- **IPv6 is disabled, not filtered.**
- **The denylist covers private ranges only.** Public addresses that the host can reach are not blocked. Notably, if your router hairpins its WAN address, a job could reach services you forwarded from the Internet. Keep Tailscale subnet-route acceptance off on this host, since routed subnets would also be reachable.
- **Without `rootlessctl`, the debug SSH port is open for the whole VM life in filtered mode.** The port is published statically at launch rather than at hold time. Nothing listens on it by default, but a job is root and could start a listener. Install `rootlesskit` with `rootlessctl` to publish it only at hold time.
- **The Docker mirror's `/v2/_catalog` and other reads are visible to every job** and shared between repos. It only caches public images, so this is acceptable, but jobs can learn what other jobs pulled.
- **The cache can be poisoned by a compromised default branch or cache branch.** The trust rule stops PRs and other branches, not code already merged into a writer branch. Only list branches in `cache_branches` that are as protected as the default.
- **The base image gives `runner` passwordless sudo,** and bake VMs always use open networking.
- **Local file secrets.** The GitHub token and dashboard key are plain files readable by the kiln user.
- **One host.** There is no tenant separation between repos beyond VM and cache-disk isolation.

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

kiln is a private personal project. If you find a security problem, please report it privately and do not open a public issue: contact **@Bunty9** on GitHub (for example through a private message or a private security advisory on the repository, if you have access). Include what you found, how to reproduce it and the kiln version (`kiln --version`). There is no formal response-time guarantee, but reports will be looked at promptly.
