# Command line

`kiln status`, `jobs`, `logs`, `wait` and `rerun` talk to the running `kiln serve` on the same machine. They read the dashboard key from `<data>/dashboard.key`, so run them as the user kiln runs as (set `KILN_DATA` if the data directory is not the default). They connect only to `<data>/serve.sock` (mode 0600). They start no second kiln and never contact a forge themselves. The socket is not keyless on purpose; see [Scripting the API](configuration.md#scripting-the-api).

There is no TCP fallback: the key is sent only over the 0600 socket, because another local user could bind kiln's port while kiln is down. If the socket is missing the command exits 6 (kiln is not running, or `KILN_DATA` is too long for a unix socket); use curl against the `listen` address if you accept sending the key over TCP.

Job logs are untrusted. On a terminal, `logs` drops every escape sequence except SGR colours, and every control character but newline and tab; piped to a file or another program it writes the bytes unchanged. Names, notes and messages in the other commands always lose control characters.

Every command takes `--json`, which prints the API's JSON and nothing else on stdout.

| Command | What it does |
|---|---|
| `kiln status [--doctor]` | Version and health, last poll, slots used, running VMs, queued jobs, backoff, wait reasons (when this kiln reports them) and health items. `--doctor` adds the doctor checks. |
| `kiln jobs [--repo R] [--pr N] [--sha S] [--branch B] [--limit N]` | One line per VM from kiln's last 100, newest first: id, state/result, repo, job, `#pr` or branch, short sha, duration, note. `--sha` matches by prefix. Default limit 20. |
| `kiln logs <vm> [--steps\|--console] [--failed] [--follow]` | The VM's steps log (default) or console log. `--follow` keeps reading while the VM is active. `--failed` prints the failure summary kiln stored when the job ended (the failing step and its first error lines); a job without one (older records, GitLab) falls back to the lines around `##[error]` and `FAIL` markers in the log, with BOM and ANSI escapes removed. |
| `kiln wait <run-id\|sha> [--repo R] [--timeout MIN] [--interval S]` | Blocks until the run, or every run of the commit, finishes (default 60 minutes, polling every 10 s). A sha is waited for up to 2 minutes to appear. A new attempt of a run is followed. Prints the run URL and each job's conclusion. All digits is a run id, anything else a sha; `sha:<hex>` forces a sha (for an all-digit prefix). |
| `kiln rerun <run-id> [--repo R] [--failed]` | Reruns a run, or only its failed jobs. |

`--repo` is needed by the run commands unless kiln serves exactly one repo (GitLab and Gitea projects are `<forge id>:<path>`).

## Exit codes of `kiln wait`

| Code | Meaning |
|---|---|
| 0 | Success (or skipped) |
| 1 | Failure, including kiln's job timeout |
| 2 | Cancelled |
| 3 | Infrastructure loss: a kiln VM for the run ended lost, killed, oom or without a result. This overrides the forge still saying in progress, or cancelled |
| 4 | Refused by kiln (a fork pull request, or a fail-closed refusal) |
| 5 | The wait timed out |
| 6 | kiln, auth or usage error (also the code of every other command on error) |

With several runs, the worst code wins: 3, then 1, 4, 2, 0.

## Scripts and agents

Use `kiln wait` to gate on CI, not `gh pr checks --watch`: that exits 0 on a cancelled run and cannot see that kiln lost the VM.

```sh
git push && kiln wait "$(git rev-parse HEAD)" --timeout 30 || {
  case $? in
    3) echo "infra loss: rerun" ; kiln rerun "$RUN" --failed ;;
    *) kiln jobs --sha "$(git rev-parse HEAD)" ;;
  esac
}
kiln logs <vm> --failed
```
