#!/bin/bash
# First-boot smoke test of kiln on an Apple Silicon Mac. Safe next to nothing else: it uses a
# scratch data directory and its own port, and leaves your real kiln (if any) alone.
#
#   scripts/macos-smoke.sh [path/to/kiln]        (default: ./target/release/kiln, built if missing)
#
# Env: REPO (default Bunty9/kiln) a repo the token can register runners on; SMOKE_DATA (default
# ~/kiln-smoke) scratch KILN_DATA; PORT (default 7979). Token: KILN_GITHUB_TOKEN, GITHUB_TOKEN or `gh`.
#
# Steps: Homebrew prerequisites, `kiln doctor`, `kiln bake`, then `kiln serve` with max_vms 1 and
# one warm VM for $REPO, which registers a JIT runner (labels kiln-arm64, kiln-arm64-2cpu) and must
# reach "Listening for Jobs". No job runs: nothing asks for kiln-arm64. Stopping kiln deregisters
# the runner. Then it runs one real job if you want: see docs/apple-silicon.md, "Test checklist".
set -euo pipefail

[ "$(uname -s)/$(uname -m)" = Darwin/arm64 ] || { echo "run this on an Apple Silicon Mac"; exit 1; }
REPO=${REPO:-Bunty9/kiln}
DATA=${SMOKE_DATA:-$HOME/kiln-smoke}
PORT=${PORT:-7979}
cd "$(dirname "$0")/.."

say() { printf '\n== %s\n' "$*"; }

say "prerequisites (Homebrew)"
command -v brew >/dev/null || { echo "install Homebrew first: https://brew.sh"; exit 1; }
for f in qemu xorriso; do brew list --formula "$f" >/dev/null 2>&1 || brew install "$f"; done
qemu-system-aarch64 --version | head -1
[ "$(sysctl -n kern.hv_support)" = 1 ] || { echo "Hypervisor.framework unavailable (kern.hv_support != 1)"; exit 1; }

KILN=${1:-./target/release/kiln}
if [ ! -x "$KILN" ]; then
  say "building kiln"
  cargo build --release --locked
fi
"$KILN" --version

export KILN_DATA=$DATA
mkdir -p "$DATA"
if [ -z "${KILN_GITHUB_TOKEN:-}${GITHUB_TOKEN:-}" ] && command -v gh >/dev/null; then
  KILN_GITHUB_TOKEN=$(gh auth token) && export KILN_GITHUB_TOKEN
fi
cat > "$DATA/config.json" <<EOF
{ "listen": "127.0.0.1:$PORT", "repos": ["$REPO"], "max_vms": 1, "vm_cpus": 2, "vm_mem_mb": 4096,
  "warm": { "$REPO": 1 }, "docker_mirror": false, "auto_rebake": false, "auto_update": false }
EOF

say "kiln doctor (failures here are worth reading; the mirror and egress lines are expected to say macOS)"
"$KILN" doctor || true

if [ ! -f "$DATA/images/base.qcow2" ]; then
  say "kiln bake (downloads the arm64 Ubuntu image, ~5-10 minutes)"
  "$KILN" bake
fi
grep -q '"recipe"' "$DATA/images/base.json" && echo "base image: $(cat "$DATA/images/base.json")"

say "kiln serve on 127.0.0.1:$PORT with one warm VM for $REPO"
"$KILN" serve > "$DATA/serve.log" 2>&1 &
pid=$!
trap 'kill $pid 2>/dev/null; wait $pid 2>/dev/null || true' EXIT
deadline=$((SECONDS + 600))
log=""
until [ -n "$log" ] && grep -q "Listening for Jobs" "$log"; do
  [ $SECONDS -lt $deadline ] || { echo "no VM reached 'Listening for Jobs' in 10 minutes"; tail -50 "$DATA/serve.log"; [ -n "$log" ] && tail -80 "$log"; exit 1; }
  kill -0 $pid 2>/dev/null || { echo "kiln serve exited"; tail -50 "$DATA/serve.log"; exit 1; }
  log=$(ls -t "$DATA"/vms/*/console.log 2>/dev/null | head -1 || true)
  sleep 2
done
vm=$(dirname "$log")
echo "OK: $(basename "$vm") is listening for jobs"
grep -o '"cpus": *[0-9]*\|"state": *"[a-z]*"' "$vm/meta.json" | tr '\n' ' '; echo
pgrep -fl qemu-system-aarch64 | grep -q "accel=hvf" && echo "OK: QEMU runs with -accel hvf"
[ ! -e "$vm/jit" ] && echo "OK: JIT secret deleted after boot"
say "stopping kiln (deregisters the runner)"
kill $pid; wait $pid 2>/dev/null || true
trap - EXIT
echo "done. Logs: $DATA/serve.log, $vm/console.log. Remove $DATA when finished."
