# Contributing

Thanks for helping with kiln. It is a small codebase on purpose: five Rust files and one HTML file.

## Development setup

- Rust stable (the crate sets `rust-version = "1.89"`, edition 2024). `rustup` with the `clippy` and `rustfmt` components.
- Node.js, only to syntax-check the dashboard script.
- To run kiln end to end you need a Linux x86_64 box (or, experimentally, an Apple Silicon Mac: see [docs/apple-silicon.md](docs/apple-silicon.md)) with `/dev/kvm`, `qemu-system-x86_64`, `qemu-img`, `xorriso`, `curl` and `tailscale`. `kiln doctor` tells you what is missing. Unit tests do not need any of this.

```sh
gh repo clone Bunty9/kiln && cd kiln
cargo build
```

## Layout

| Path | What lives there |
|---|---|
| `src/main.rs` | `Config` (all settings, defaults, validation), token loading, CLI commands, the scheduler tick (demand, gates, budget, backoff), shutdown |
| `src/vm.rs` | VM lifecycle (`launch`, `run`), QEMU command line, console parsing, repo cache, reaper and warm pool, egress ruleset and probe, debug hold, `bake`, `doctor` |
| `src/web.rs` | axum server, access guard (tailnet identity, dashboard key, Host and CSRF checks), JSON API, GitHub proxy allow-list |
| `src/github.rs` | GitHub REST client (ETag cache, rate limits), queued-job counting, JIT config, cache trust lookup, hello PR |
| `src/mirror.rs` | Docker Hub pull-through registry supervisor |
| `src/dashboard.html` | The whole dashboard: HTML, CSS and JavaScript in one file, embedded with `include_str!` |
| `guest/user-data.yaml` | Cloud-init recipe and guest scripts (`kiln-job`, `kiln-steps`, `kiln-cache`) baked into the VM image |
| `deploy/kiln.service` | systemd user unit |
| `examples/` | Small projects used by the stacks workflow |
| `docs/` | Architecture, configuration, stack compatibility |

Read [docs/architecture.md](docs/architecture.md) first; it explains how these fit together.

## Checks

Run all of these before sending a change. CI runs them on kiln itself, in a kiln VM:

```sh
cargo fmt --check
cargo clippy --locked --tests -- -D warnings
cargo test --locked
```

`rustfmt.toml` sets a width of 140, so run `cargo fmt` rather than formatting by hand. Warnings are errors in CI. Logic with a branch, a parser or a security decision gets a small unit test next to it (most modules already have a `tests` section to copy).

## The dashboard

`src/dashboard.html` has no build step, no framework and no dependencies. Edit it and rebuild; the file is embedded in the binary, so a redeploy shows up on reload (the page is served with `no-cache`).

Check its JavaScript parses:

```sh
sed -n '/<script>/,/<\/script>/p' src/dashboard.html | sed '1d;$d' > /tmp/dashboard.js && node --check /tmp/dashboard.js
```

For UI work you do not need a live kiln. Write a throwaway mock server (not committed) that serves `src/dashboard.html` at `/` and returns canned JSON for `/api/state` (the shape is built in `state()` in `src/web.rs`), `/api/doctor`, `/api/log` and the other `/api/` routes the page calls. Requests from a browser on the same machine need the `x-kiln-key` header, so the mock can simply ignore it. Vary the fixtures (no token, no image, backoff, failed job, held VM) to see each state.

## End-to-end testing

kiln builds itself. `.github/workflows/ci.yml` runs on pushes to main and on pull requests inside a kiln VM, so a working push is already an end-to-end test of the job path. Two more workflows exist for the rest:

- `.github/workflows/selftest.yml` (run from the Actions tab or `gh workflow run selftest.yml`) prints what a job VM can reach (internet, Docker mirror, dashboard, LAN, tailnet), which is the quickest way to verify `egress` settings. Run it with `fail: true` to exercise the debug hold and failure notifications.
- `.github/workflows/stacks.yml` runs the projects in `examples/` (Node with Postgres, Python with uv, Go, Docker build, Playwright, Rust) on kiln.

## Deploying to a box

On the CI box (or from your machine with `rsync`):

```sh
rsync -a --exclude target --exclude .git ./ box:~/src/kiln/
ssh box 'cd ~/src/kiln && cargo build --release --locked \
  && install -Dm755 target/release/kiln ~/.local/bin/kiln \
  && systemctl --user restart kiln'
```

**Do not restart while jobs are running.** Stopping kiln kills its VMs, so their jobs fail. Check the Overview page (or `/api/state`) first, or set `max_vms` to 0 to drain and wait for the VMs to finish. If you changed `guest/user-data.yaml`, run `kiln bake` (or Rebake in Settings) afterwards, because the guest scripts live in the image.

## Commits and pull requests

- Imperative subject line, around 70 characters ("Add warm pool", not "Added" or "Adds"). The body explains why the change was needed and anything non-obvious, not what the diff already shows.
- Keep a commit to one logical change, and keep the tests and docs for it in the same commit.
- Update [CHANGELOG.md](CHANGELOG.md) under `Unreleased` for anything a user would notice, and the relevant docs ([configuration](docs/configuration.md) for settings, [SECURITY.md](SECURITY.md) for security behaviour).
- No AI or tool attribution trailers (`Co-Authored-By`, "Generated with", and the like) in commit messages or pull request text.

## Releases

Bump `version` in `Cargo.toml` and add a `## [x.y.z] - date` section to `CHANGELOG.md` (the release workflow uses it as the release notes), then tag `vx.y.z` on main. The tag must match `Cargo.toml`. The release workflow builds `kiln-<version>-x86_64-linux.tar.gz` and its `.sha256`.

## License

By contributing you agree that your contribution is dual licensed under the Apache License 2.0 and the MIT license, at the user's option, without additional terms or conditions. See the License section of the [README](README.md#license).
