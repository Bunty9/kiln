# Command line

`kiln status`, `jobs`, `logs`, `wait` and `rerun` talk to the running `kiln serve` on the same machine. They read the dashboard key from `<data>/dashboard.key`, so run them as the user kiln runs as (set `KILN_DATA` if the data directory is not the default). They connect to `<data>/serve.sock`, or to `127.0.0.1:<port>` of `listen` when the socket is unusable (never to a non-local address). They start no second kiln and never contact a forge themselves. The socket is not keyless on purpose; see [Scripting the API](configuration.md#scripting-the-api).

Every command takes `--json`, which prints the API's JSON and nothing else on stdout.

| Command | What it does |
|---|---|
| `kiln status [--doctor]` | Version and health, last poll, slots used, running VMs, queued jobs, backoff, wait reasons (when this kiln reports them) and health items. `--doctor` adds the doctor checks. |
| `kiln jobs [--repo R] [--pr N] [--sha S] [--branch B] [--limit N]` | One line per VM from kiln's last 100, newest first: id, state/result, repo, job, `#pr` or branch, short sha, duration, note. `--sha` matches by prefix. Default limit 20. |
| `kiln logs <vm> [--steps\|--console] [--failed] [--follow]` | The VM's steps log (default) or console log. `--follow` keeps reading while the VM is active. `--failed` prints the failing step's name and the lines around `##[error]` and `FAIL` markers, with BOM and ANSI escapes removed. |
| `kiln wait <run-id\|sha> [--repo R] [--timeout MIN] [--interval S]` | Blocks until the run, or every run of the commit, finishes (default 60 minutes, polling every 10 s). A sha is waited for up to 2 minutes to appear. A new attempt of a run is followed. Prints the run URL and each job's conclusion. A number of up to 10 digits is a run id, anything else a sha. |
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
