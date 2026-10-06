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

The per-repo cache disk follows a trusted-writer, throwaway-reader rule. Every job gets a private overlay, and an overlay is merged back only when the job succeeded according to GitHub's API (not just the console), the event was a `push`, the branch is the default branch, and the commit is really on it. A pull request can read the cache but never poison it. The decision uses GitHub's data because the job controls its own console output.

### Console and lifecycle hardening

Console lines may shape the timeline but cannot rewind state or extend a VM's life:

- each lifecycle line ("Listening for Jobs", "Running job", the result) is accepted once and only forward;
- the hold is granted only after a non-success verdict line; a job can forge that or cancel its own hold, but cannot hold a VM that never ran a job;
- lines are capped at 64 KiB (a longer line and its remainder are never parsed) and logs at 64 MiB;
- every VM has a **hard lifetime cap** of idle timeout + job timeout + hold time + 5 minutes, enforced by kiln outside the guest.

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
- **The cache can be poisoned by a compromised default branch.** The trust rule stops PRs and other branches, not code already merged.
- **The base image gives `runner` passwordless sudo,** and bake VMs always use open networking.
- **Local file secrets.** The GitHub token and dashboard key are plain files readable by the kiln user.
- **One host.** There is no tenant separation between repos beyond VM and cache-disk isolation.

## Recommendations

- Set `egress` to `filtered` before running untrusted pull requests, such as ones from forks, and check Diagnostics shows "filtered egress" passing. Also consider requiring approval for workflows from outside contributors in the repository's GitHub settings.
- Use a fine-grained token with only the repos you serve and the permissions listed in [docs/configuration.md](docs/configuration.md#github-token): *Administration: write* and *Actions: read and write*. Add *Contents* and *Workflows* write only while you use the hello PR.
- Keep `allowed_users` empty (owner only) or minimal, and do not share the box's node to other tailnets.
- Keep the host, QEMU and Tailscale updated, and let `auto_rebake` keep the guest and runner current.
- Do not put secrets on the CI box that a job in an open-egress VM could reach over the LAN.
- Release debug holds when done; a held VM keeps a login path open until it expires.

## Reporting a vulnerability

kiln is a private personal project. If you find a security problem, please report it privately and do not open a public issue: contact **@Bunty9** on GitHub (for example through a private message or a private security advisory on the repository, if you have access). Include what you found, how to reproduce it and the kiln version (`kiln --version`). There is no formal response-time guarantee, but reports will be looked at promptly.
