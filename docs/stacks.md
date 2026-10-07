# Kiln: Self-Hosted CI for Heavy Builds

Kiln is a self-hosted GitHub Actions runner that boots fresh Ubuntu 24.04 VMs for each job, perfect for teams building on hardware you own.

## When to Use Kiln

**Kiln is right for:**
- Heavy builds on 4–16 core machines (faster and cheaper than GitHub's hosted runners)
- Reproducing flaky tests in a controlled environment
- Private code that stays on your hardware
- Homelab or on-premises setups

GitHub-hosted pricing context (2026): 2-core $0.006/min, 4-core $0.012/min, 8-core $0.022/min, 16-core $0.042/min. A 10k min/month 4-core job load costs ~$120/month on GitHub; kiln minutes are free (GitHub postponed the announced $0.002/min self-hosted fee).

**Kiln is not right for:**
- macOS or Windows builds (only Ubuntu 24.04)
- High-availability requirements (single-host design)
- Untrusted fork PRs unless you set `egress` to `filtered` (Settings > Network): then jobs reach only the internet and the Docker mirror, not your LAN or tailnet. It needs `rootlesskit slirp4netns nftables uidmap`; see [architecture](architecture.md#egress) and [SECURITY.md](../SECURITY.md)

## Migration in 3 Steps

1. Change `runs-on:` from `ubuntu-latest` to `[self-hosted, kiln]`
2. Pick the size: plain `kiln` is the default (4 vCPU / 8 GB RAM unless configured). Ask for another with exactly one size label:

   | `runs-on` | vCPU | RAM |
   |---|---|---|
   | `[self-hosted, kiln-2cpu]` | 2 | 4 GB |
   | `[self-hosted, kiln-4cpu]` | 4 | 8 GB |
   | `[self-hosted, kiln-8cpu]` | 8 | 16 GB |
   | `[self-hosted, kiln-16cpu]` | 16 | 24 GB |

   Sizes above the host's CPU count are never picked up, and don't combine `kiln` with a size label.
3. Keep everything else — your actions, scripts, and services work unchanged

## Compatibility Matrix

| Stack | Status | Notes |
|-------|--------|-------|
| setup-node / npm / pnpm / yarn | ✓ Works | Versions in `bake_node_versions` (default 24) pre-installed in `/opt/hostedtoolcache`; see [Node versions](#node-versions) |
| setup-python / uv / poetry | ✓ Works | Python 3.12+ available; uv recommended |
| setup-go | ✓ Works | ImageOS=ubuntu24 set for cache hits |
| Rust (rust-toolchain, rust-cache) | ✓ Works | libssl-dev, libffi-dev included; `~/.cargo` and `~/.rustup` live on the cache disk, so the toolchain is warm |
| setup-java + Gradle/Maven | ✓ Works | Wrapper recommended; bare `mvn` not pre-installed |
| setup-dotnet | ✓ Works | Install dir `/usr/share/dotnet` writable by runner |
| ruby / setup-ruby + Rails | ✓ Works | libyaml, libpq included; gems compile cleanly |
| setup-php | ✓ Works | Set `env: runner: self-hosted` per setup-php wiki |
| erlef/setup-beam (Erlang/OTP) | ✓ Works | ImageOS=ubuntu24 required; now set |
| Docker buildx / build-push / services | ✓ Works | Real Docker in VM; Docker Hub pulls cached by kiln's built-in mirror at 10.0.2.2:5000 (on by default) |
| container: jobs | ✓ Works | Image pulls go through local mirror. The job runs inside the container, which does not see the VM's cache mounts: `~/.npm` and friends start cold every time unless you mount them. The runner sets `HOME=/github/home` in the container, so e.g. `options: -v /home/runner/.npm:/github/home/.npm`. Jobs work either way; they are just never warm. |
| Playwright | ✓ Works | `install --with-deps` adds 1–2 min; xvfb pre-installed |
| Cypress | ◐ Partial | Needs GTK/NSS libs via apt in a setup step |
| Android build (setup-java + setup-android) | ✓ Works | setup-android installs the SDK, NDK and build tools |
| Android emulator | ✓ Experimental | Nested KVM enabled; requires host `-cpu host` |
| Elasticsearch / kind / file watchers | ✓ Works | vm.max_map_count, inotify sysctls set |
| Terraform / Nx / Turborepo remote cache | ✓ Works | gh CLI included; cache action works (goes over internet) |
| GPU jobs | ✗ Unsupported | Hardware not available |
| macOS / Windows | ✗ Unsupported | Ubuntu 24.04 only |

## Node versions

The image carries the Node versions in `bake_node_versions` (default `["24"]`) in the runner tool cache. `actions/setup-node` with a matching `node-version` uses them without a download. For a project pinned to an older major, add it (Settings › Image › Node versions, e.g. `20, 24`) and rebake; the bare `node` stays the newest. Other versions still work, they are just downloaded on every job.

## Tips

- **Public repos:** guard `pull_request` jobs so fork PRs never run on your hardware:

```yaml
jobs:
  test:
    # Never run pull requests from forks on self-hosted hardware.
    if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository
    runs-on: [self-hosted, kiln]
```

  kiln also refuses fork pull requests (and `workflow_run` runs triggered by one) itself, but it cannot see a workflow started by `issue_comment`, `repository_dispatch` or `workflow_dispatch` that checks out a PR's head: run those on GitHub-hosted runners. See [SECURITY.md](../SECURITY.md#fork-pull-requests).

- **Caching:** each repo has a persistent cache disk, so Docker layers (`/var/lib/docker`), `~/.cache`, `~/.npm`, the whole `~/.cargo` and `~/.rustup` (so the Rust toolchain is already there), Go modules, Gradle caches, `~/.m2/repository` and apt's downloaded packages are warm without any workflow change. Every job reads it; only a successful push to the default branch or a configured cache branch writes it (PRs never poison it). Clear it from Settings > Cache. `actions/cache` and `cache-to: type=gha` still work but route over the internet.
- **Debugging:** set `debug_hold_mins` and `debug_ssh_keys` in Settings > Debugging and a failed job's VM stays up for SSH (see [architecture](architecture.md#debug-hold-and-the-control-channel)).
- **Image pulls:** Docker Hub limits 100 pulls/6h per IP; kiln's built-in pull-through mirror (live, `docker_mirror` in settings; 10.0.2.2:5000 from the VM) avoids this, with a fallback to Docker Hub if it is down.
- **Parallelism:** Use `concurrency:` groups to avoid overwhelming your host.
- **Pin runner labels:** Always use `[self-hosted, kiln]` (or a size label) to avoid accidents with other self-hosted runners.

## Examples and Smoke Tests

See [`examples/`](../examples) for minimal, working projects:
- **node-postgres:** Node + pg driver, tests against a live Postgres 16 service
- **python-uv:** Python 3.12 + uv + pytest
- **go:** Go 1.22 with no external dependencies
- **docker-build:** Docker build and run with buildx
- **playwright:** Chromium-only browser automation tests

Run all stacks: `.github/workflows/stacks.yml` (workflow_dispatch or push to `examples/`).

## Next Steps

- Fork or mirror kiln to your organization
- `kiln bake` to build the base image
- Add `runs-on: [self-hosted, kiln]` to your workflows
- Monitor job logs via `kiln status` (planned)
