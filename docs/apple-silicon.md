# kiln on Apple Silicon (macOS)

> **Status: untested on a real Mac.** Lint and unit tests pass on a GitHub-hosted `macos-14` (Apple Silicon) runner, including real `sysctl`, `vm_stat` and `ps` readings. The arm64 guest path was run end to end on x86 Linux under emulation: the arm64 recipe baked under QEMU TCG, and an aarch64 kiln (under `qemu-user`, with a shim swapping `accel=kvm` for TCG) booted a warm VM from it that registered an `ARM64`/`kiln-arm64` runner, reached "Listening for Jobs" and was released over `ttyAMA0`; a hold with fw_cfg SSH keys worked too. But kiln has not yet booted a VM with Hypervisor.framework. Work through the [test checklist](#test-checklist) before relying on it. Release builds for macOS stay off until then (see [Releases](#releases)).

On a Mac with Apple Silicon, kiln runs **native linux/arm64 job VMs**: one fresh Ubuntu 24.04 arm64 VM per job, booted by QEMU with Apple's Hypervisor.framework (HVF). It is the same kiln as on Linux, with the differences listed below.

## Design

The guest always has the host's architecture (`std::env::consts::ARCH`), so an aarch64 host runs arm64 guests. That also makes an aarch64 Linux host with KVM work (`qemu-system-aarch64 -accel kvm`), as a bonus; it is not a release target.

| | x86_64 Linux | Apple Silicon macOS |
|---|---|---|
| QEMU | `qemu-system-x86_64 -machine q35,accel=kvm -cpu host` | `qemu-system-aarch64 -machine virt,gic-version=3,accel=hvf -cpu host` |
| Guest | Ubuntu 24.04 amd64 cloud image | Ubuntu 24.04 arm64 cloud image (`noble-server-cloudimg-arm64.img`) |
| Kernel | `unpacked/...-amd64-vmlinuz-generic`, direct boot, no initrd | `unpacked/...-arm64-vmlinuz-generic` (gzip; QEMU unpacks it), direct boot, no initrd |
| Console + control channel | `ttyS0` (QEMU stdio) | `ttyAMA0`, the PL011 UART (QEMU stdio) |
| Step logs | second serial port `ttyS1` | virtio-serial port `kiln.steps` (`/dev/virtio-ports/kiln.steps`) |
| JIT config, debug SSH keys | fw_cfg file `opt/kiln/jit` (and `opt/kiln/ssh`), plus the SMBIOS OEM string as before | fw_cfg only (no SMBIOS without UEFI) |
| Runner, Node | `actions-runner-linux-x64`, `node-...-linux-x64`, tool cache `.../x64` | `actions-runner-linux-arm64`, `node-...-linux-arm64`, tool cache `.../arm64` |
| Hypervisor check | `/dev/kvm` read/write, `kvm` group | `sysctl -n kern.hv_support` = 1 |
| Memory, load | `/proc/meminfo`, `/proc/loadavg` | `sysctl hw.memsize`, `vm_stat` (free + inactive pages), `sysctl vm.loadavg` |
| Stray QEMU scan | `/proc/*/cmdline` | `ps -axww -o pid=,command=` |
| Service | systemd user unit (`deploy/kiln.service`) | launchd LaunchAgent (`deploy/kiln.plist`) |
| Networking | user-mode (slirp); `egress: "filtered"` available | user-mode (slirp) only |
| Docker mirror | pinned `registry` on `127.0.0.1:5000` | none (no darwin build of the registry) |

Notes on the choices:

- **GICv3**: the `virt` machine's default GICv2 supports at most 8 vCPUs; GICv3 allows the 16cpu size. Under HVF QEMU emulates the GIC.
- **Control channel on ttyAMA0**: the PL011's input behaves exactly like `ttyS0`'s, so the host side is unchanged (kiln writes `release` / `hold N` to QEMU's stdin). A virtio-serial port for control was considered and not used: its reads return end-of-file whenever the host side is not connected, which would need a second, persistent host connection.
- **Secrets over fw_cfg**: SMBIOS type 11 strings do not reach an arm64 guest booted without UEFI. QEMU reads `-fw_cfg name=opt/kiln/jit,file=<vm>/q/jit` at start (the file is deleted as soon as the guest prints, as before); the guest loads `qemu_fw_cfg` (not in the cloud image: an arm64 bake installs it from `linux-modules-extra` for the kernel kiln boots) and reads `/sys/firmware/qemu_fw_cfg/by_name/opt/kiln/jit/raw`, falling back to `dmidecode` (SMBIOS) when it is absent. x86 VMs get both and keep reading SMBIOS (their image has no `qemu_fw_cfg`; the x86 bake is unchanged). The guest recipe changed, so `RECIPE` is 6 (after main's 5): images baked by older kilns are rebaked before VMs launch (automatic with `auto_rebake`).
- The platform layer (hypervisor check, memory, load, process list, Tailscale path, guest arch) lives in `src/platform.rs` (`src/host.rs` is the per-VM host graphs); guest differences are the `Guest` table in `src/vm.rs`.
- **No QEMU confinement on macOS**: Landlock and QEMU's seccomp `-sandbox` are Linux-only, so a Mac's QEMU runs unconfined as the kiln user (Hypervisor.framework still isolates the guest); `kiln doctor` warns. aarch64 Linux hosts get both: `qemu-system-aarch64` is under `/usr` and the fw_cfg files are in the VM's `q/` directory, inside the Landlock rules.

## Setup

Requirements: an Apple Silicon Mac on macOS 13 or newer (macOS 14 or newer recommended), [Homebrew](https://brew.sh), the [Tailscale app](https://tailscale.com/download/mac), and about 15 GB of free disk at a minimum.

```sh
brew install qemu xorriso          # qemu-system-aarch64, qemu-img; xorriso builds the bake's seed ISO
```

Install kiln (a release build once macOS releases are on, or from source):

```sh
v=0.3.0                                           # once a release ships an aarch64-macos tarball
f=kiln-$v-aarch64-macos.tar.gz url=https://github.com/Bunty9/kiln/releases/download/v$v
cd "$(mktemp -d)"
curl -fLO "$url/$f" -fLO "$url/$f.sha256"
shasum -a 256 -c "$f.sha256"
tar -xzf "$f" && cd "kiln-$v-aarch64-macos"
# or from source: cargo build --release, then use target/release/kiln and deploy/kiln.plist
install -d ~/.local/bin && install -m 755 kiln ~/.local/bin/kiln
```

Bake the image and start the service:

```sh
~/.local/bin/kiln doctor
~/.local/bin/kiln bake
sed "s|@HOME@|$HOME|g" deploy/kiln.plist > ~/Library/LaunchAgents/dev.kiln.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/dev.kiln.plist
tail -f ~/Library/Logs/kiln.log
```

- **launchd**: the LaunchAgent runs `~/.local/bin/kiln serve` with `RunAtLoad` and `KeepAlive` `{SuccessfulExit: false}`, the equivalent of systemd's `Restart=on-failure`, so self-update rollback (a new version that fails to start twice is replaced by the previous one) works the same way. It adds Homebrew to `PATH`, since launchd's default `PATH` lacks it. Stop it with `launchctl bootout gui/$(id -u)/dev.kiln`. A LaunchAgent only runs while you are logged in: on an always-on Mac turn on automatic login (and keep the Mac from sleeping: System Settings › Energy, "Prevent automatic sleeping").
- **Tailscale**: the Mac App Store or standalone app works. kiln uses `tailscale` from `PATH`, else `/Applications/Tailscale.app/Contents/MacOS/Tailscale`. The dashboard access rules are unchanged. **Serve over HTTPS** points `tailscale serve` at the unix socket `<data>/serve.sock`; whether the macOS app's tailscaled may open a socket in your home directory is untested (the sandboxed App Store build may not; the standalone build or the open-source `tailscaled` should). Without it, HTTPS needs the dashboard key, as before 0.2.2.
- **Self-update** replaces `~/.local/bin/kiln` by rename and re-executes it in place, as on Linux. Downloads made by kiln carry no quarantine attribute, and the Rust toolchain ad-hoc signs arm64 binaries, so Gatekeeper does not get involved.
- `kiln doctor` checks Hypervisor.framework, `qemu-system-aarch64`, `qemu-img`, `xorriso`, `curl` and the Tailscale CLI, then the usual disk, memory, image, token and repo checks.

## Labels

An arm64 kiln registers runners labelled `self-hosted`, `linux`, `ARM64`, `<label>-arm64-<N>cpu`, and `<label>-arm64` for the default size. It never advertises the plain `<label>` or `<label>-<N>cpu`, so a job written for x64 never lands on an arm64 VM. Opt a job in with:

```yaml
runs-on: [self-hosted, kiln-arm64]          # default size
runs-on: [self-hosted, kiln-arm64-8cpu]     # 8 vCPU
```

The matching rules are the same as on x64 (exactly one kiln label, sizes 2, 4, 8 and 16, not larger than the host's cores). An x64 kiln ignores `kiln-arm64...` jobs and an arm64 kiln ignores `kiln...` jobs, so both can serve the same repos. The dashboard's snippets show the right label.

## Limitations

- **No filtered egress.** `egress: "filtered"` needs Linux (rootlesskit, slirp4netns, nftables). On macOS saving it is refused, and `kiln doctor` explains. Jobs have open egress: they can reach your LAN and tailnet. Do not run untrusted pull requests on a Mac kiln.
- **No Docker mirror.** The pinned `registry` has no darwin build, so on macOS the mirror is off (`docker_mirror` is kept but ignored) and VMs pull from Docker Hub directly, with Docker Hub's rate limits. The guest still lists `10.0.2.2:5000` as a mirror, and dockerd falls back to Docker Hub when it does not answer. If macOS's AirPlay Receiver holds port 5000 it answers with an error and dockerd also falls back.
- **arm64 images only.** Jobs run on linux/arm64. Container images and `services:` must have arm64 variants; most official images do. x64-only images run only emulated, and only if the job sets up binfmt first (for example `docker/setup-qemu-action`), slowly. Prebuilt x64 binaries downloaded by a job will not run.
- **No nested virtualization**: expect no `/dev/kvm` in the guest (Android emulators and VM-in-CI jobs need an x86 Linux kiln).
- QEMU's user-mode networking and the rest of the job lifecycle (cache disks, warm pool, debug hold, timeouts) work as on Linux.

## Releases

`release.yml` has a `build-macos` job on a GitHub-hosted `macos-14` (Apple Silicon) runner that tests, builds and packages `kiln-X.Y.Z-aarch64-macos.tar.gz`; the `sign` job signs and publishes it with the Linux tarballs. It runs only while the repository variable `KILN_MACOS_RELEASE` is `true`; until then releases are Linux-only and `sign` does not wait for it. A macOS kiln updates itself only from `aarch64-macos` tarballs. Turn the variable on once the checklist below passes:

```sh
gh variable set KILN_MACOS_RELEASE -R Bunty9/kiln --body true
```

`.github/workflows/macos.yml` runs `cargo clippy` and `cargo test` on `macos-14`, from the Actions tab or on pull requests labelled `macos` (hosted macOS minutes are expensive). It cannot boot VMs: hosted runners have no nested virtualization.

## Test checklist

On the Mac, from a checkout of this branch:

1. `scripts/macos-smoke.sh` installs `qemu` and `xorriso`, runs `kiln doctor` and `kiln bake` in a scratch `KILN_DATA` (`~/kiln-smoke`), starts `kiln serve` on `127.0.0.1:7979` with `max_vms` 1 and one warm VM for `REPO` (default `Bunty9/kiln`), and waits for that VM's runner to print "Listening for Jobs" (labels `kiln-arm64`, so no job is sent to it). It then stops kiln, which deregisters the runner.
2. `kiln doctor`: `hvf`, `qemu-system-aarch64`, `qemu-img`, `xorriso`, `curl`, `tailscale` pass; `docker mirror` says "not available on macOS"; `filtered egress` says it needs Linux.
3. Bake: `images/bake.log` ends with "base image ready"; `images/base.json` has `"recipe": 4`. Check the bake log for `actions-runner-linux-arm64` and `node-v...-linux-arm64`.
4. Boot: the VM's `console.log` shows the kernel on `ttyAMA0`, then "Listening for Jobs"; the `jit` file is gone from `vms/<id>/` right after boot; `ps` shows `accel=hvf`. Time from launch to listening (Linux/KVM: about 4 s).
5. A real job: push a workflow with `runs-on: [self-hosted, kiln-arm64]` (run `uname -m`, `docker run --rm hello-world`, `node -v`, `actions/setup-node` with a baked version). Check: state goes idle, busy, done; the **Steps** log fills live (virtio-serial port); the job's `uname -m` is `aarch64`; Docker works; the cache disk is attached (`findmnt /mnt/cache`) and saved after a push to the default branch.
6. Sizes: `kiln-arm64-8cpu` boots an 8 vCPU VM; on a Mac with 16 or more cores try `kiln-arm64-16cpu` (GICv3).
7. Debug hold: set `debug_hold_mins` and a key, fail a job on purpose, `ssh -p 22xx runner@<tailnet ip>` works, **Release** powers the VM off (control channel on `ttyAMA0`).
8. Labels: an x64 job (`runs-on: [self-hosted, kiln]`) is not picked up by the Mac; the Mac's runners show `ARM64` and `kiln-arm64...` labels on GitHub.
9. Service: install the LaunchAgent, reboot (with automatic login), check kiln comes back; `launchctl bootout` stops it and its VMs; `kill -9` of kiln is restarted by launchd, and `kiln doctor` reports stray QEMUs only while they live.
10. Self-update: with a test release that has an `aarch64-macos` tarball, **Update** swaps `~/.local/bin/kiln` and re-execs; a deliberately broken build is rolled back after two failed starts under launchd.
11. Dashboard: Settings › Network › Serve over HTTPS works with the Tailscale app (the `tailscale serve` doctor check passes) and logs you in without the dashboard key; host memory, load and CPU numbers look right (compare with Activity Monitor); memory gating stops launches when memory runs out.
12. Then set `KILN_MACOS_RELEASE` (see [Releases](#releases)).
