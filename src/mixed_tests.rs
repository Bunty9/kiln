//! One kiln serving a GitHub, a GitLab and a Gitea repo at once, ticked against three mock forges.
//!
//! Deterministic by construction: every test has its own data dir, `vm_cpus` is 1 and memory 64 MB
//! (so budgets fit a 3-thread host), no GitHub registration succeeds (no VM reaches QEMU), and
//! anything that depends on how many VMs are alive mid-tick is either seeded (`seed-*` Busy VMs,
//! which never exit) or counted from records that outlive their task. Tests wait on `app.kills`,
//! never on a sleep.

use super::*;
use crate::forge_test_mock::{Mock, fixture, fixture_in};
use crate::tests::tick_app;
use serde_json::{Value, json};

const GT: &str = "/api/v1/repos/acme/demo/actions";
const GL: &str = "/api/v4";
const GH_REPO: &str = "acme/demo";
const GT_REPO: &str = "gitea:acme/demo";
const GL_REPO: &str = "gl:acme/demo";
const GL_JOBS: &str = "/api/v4/projects/1/jobs?scope%5B%5D=pending&scope%5B%5D=running&per_page=100&pagination=keyset";

struct Trio {
    app: Arc<App>,
    cfg: Config,
    gh: Mock,
    gt: Mock,
    gl: Mock,
}

impl Trio {
    /// One app with a GitHub, a Gitea and a GitLab forge, each on its own mock, every queue empty.
    async fn new(name: &str, max_vms: usize, tune: impl FnOnce(&mut Config)) -> Trio {
        let gh = Mock::github().await;
        let (gt, gl) = (Mock::start().await, Mock::start().await);
        // A registration that fails keeps every GitHub VM away from QEMU.
        gh.route("POST", "/repos/acme/demo/actions/runners/generate-jitconfig", 404, "{}");
        gh_queue(&gh, 0);
        let forges: Vec<forge::ForgeCfg> = serde_json::from_value(json!([
            { "id": "github", "kind": "github", "repos": [GH_REPO] },
            { "id": "gitea", "kind": "gitea", "url": "https://gitea.example.org", "repos": [GH_REPO] },
            { "id": "gl", "kind": "gitlab", "url": "https://gitlab.example.org", "repos": [GH_REPO] },
        ]))
        .unwrap();
        let (app, mut cfg) = tick_app(name, &gh, Some(forges.clone()));
        (cfg.max_vms, cfg.vm_cpus, cfg.vm_mem_mb) = (max_vms, 1, 64);
        tune(&mut cfg);
        *app.cfg.write().unwrap() = cfg.clone();
        std::fs::write(app.data.join("install_id"), "a1b2c3").unwrap();
        let g = forge::gitea::Gitea::for_mock("https://gitea.example.org", &gt.base, "gt-tok");
        app.forges.insert(forges[1].clone(), forge::Forge::Gitea(Box::new(g)));
        let g = forge::gitlab::GitLab::for_mock(&forges[2], &app.data, &gl.base, "gl-tok");
        app.forges.insert(forges[2].clone(), forge::Forge::GitLab(Box::new(g)));

        gt.route("GET", "/api/v1/version", 200, fixture_in("gitea", "version.json"));
        gt_queue(&gt, 0, false);
        for run in [70, 77] {
            gt.route("GET", &format!("{GT}/runs/{run}"), 200, fixture_in("gitea", &format!("run_{run}.json")));
        }
        let gfx = |f: &str| fixture_in("gitlab", f).replace("https://gitlab.example.org", &gl.base);
        gl.route("GET", &format!("{GL}/projects/acme%2Fdemo"), 200, gfx("project.json"));
        gl.route("GET", &format!("{GL}/projects/1/repository/branches/ci"), 200, gfx("branch_ci.json"));
        gl.route("GET", &format!("{GL}/projects/1/merge_requests/3"), 200, gfx("mr_fork.json"));
        gl_queue(&gl, vec![]);
        Trio { app, cfg, gh, gt, gl }
    }

    /// Run a tick with the config the app holds, or one adjusted for just this tick.
    async fn tick(&self) -> Result<HashMap<String, HashMap<u32, usize>>> {
        tick(&self.app, &self.cfg).await
    }

    /// VM records of `repo` that tasks launched (not the seeded ones).
    fn launched(&self, repo: &str) -> usize {
        self.app.vms.lock().unwrap().iter().filter(|v| v.repo == repo && !v.id.starts_with("seed-")).count()
    }

    /// Every launched VM task has finished (a task removes its `kills` entry last).
    async fn quiesce(&self) {
        for _ in 0..1000 {
            if self.app.kills.lock().unwrap().keys().all(|k| k.starts_with("seed-")) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("launched VMs did not finish: {:?}", self.app.kills.lock().unwrap().keys().collect::<Vec<_>>());
    }

    fn health(&self) -> Vec<(String, String)> {
        // Host-resource entries depend on the machine running the test.
        self.app.poll.lock().unwrap().health.iter().filter(|(k, _)| k != "memory" && k != "disk").cloned().collect()
    }
}

/// GitHub's queue: `n` plain `kiln` jobs in one push run, nothing in progress.
fn gh_queue(m: &Mock, n: usize) {
    let runs: Value = serde_json::from_str(&fixture("runs_queued.json")).unwrap();
    let run = runs["workflow_runs"].as_array().unwrap().iter().find(|r| r["id"] == 1001).unwrap().clone();
    let jobs: Value = serde_json::from_str(&fixture("jobs_1001.json")).unwrap();
    let job = jobs["jobs"].as_array().unwrap().iter().find(|j| j["id"] == 5001).unwrap().clone();
    let jobs: Vec<Value> = (0..n as u64)
        .map(|i| {
            let mut j = job.clone();
            j["id"] = (5001 + i).into();
            j
        })
        .collect();
    let runs = if n == 0 { vec![] } else { vec![run] };
    let r = "/repos/acme/demo/actions";
    m.route(
        "GET",
        &format!("{r}/runs?status=queued&per_page=30"),
        200,
        json!({ "total_count": runs.len(), "workflow_runs": runs }).to_string(),
    );
    m.route("GET", &format!("{r}/runs?status=in_progress&per_page=30"), 200, r#"{"total_count":0,"workflow_runs":[]}"#);
    m.route("GET", &format!("{r}/runs/1001/jobs?per_page=100"), 200, json!({ "total_count": n, "jobs": jobs }).to_string());
}

/// Gitea's queue: `ok` plain jobs of a push run, plus the queued fork job of the fixture when `fork`.
fn gt_queue(m: &Mock, ok: usize, fork: bool) {
    let all: Value = serde_json::from_str(&fixture_in("gitea", "jobs_queued_a.json")).unwrap();
    let find = |id: u64| all["jobs"].as_array().unwrap().iter().find(|j| j["id"] == id).unwrap().clone();
    let mut jobs: Vec<Value> = (0..ok as u64)
        .map(|i| {
            let mut j = find(76);
            j["id"] = (7600 + i).into();
            j
        })
        .collect();
    if fork {
        jobs.push(find(91));
    }
    m.route(
        "GET",
        &format!("{GT}/jobs?status=queued&limit=50&page=1"),
        200,
        json!({ "jobs": jobs, "total_count": jobs.len() }).to_string(),
    );
}

/// One pending `kiln` job of GitLab pipeline `n`: a push on a branch, or a merge request from a fork.
fn gl_job(n: u64, fork: bool) -> Value {
    let all: Vec<Value> =
        (1..=4).flat_map(|i| serde_json::from_str::<Vec<Value>>(&fixture_in("gitlab", &format!("jobs_p{i}.json"))).unwrap()).collect();
    let mut j = all.into_iter().find(|j| j["id"] == 215).unwrap();
    j["id"] = (1000 + n).into();
    j["pipeline"]["id"] = (2000 + n).into();
    j["status"] = "pending".into();
    j["tag_list"] = json!(["kiln"]);
    let (r, source) = if fork { ("refs/merge-requests/3/head", "merge_request_event") } else { ("ci", "push") };
    j["ref"] = r.into();
    j["pipeline"]["source"] = source.into();
    j
}

fn gl_queue(m: &Mock, jobs: Vec<Value>) {
    m.route("GET", GL_JOBS, 200, Value::Array(jobs).to_string());
}

/// Gitea's runner 52 as `retire` sees it; `busy` puts a job of run 70 on it.
fn gt_runner(m: &Mock, busy: bool) {
    let mut jobs: Value = serde_json::from_str(&fixture_in("gitea", "jobs_in_progress.json")).unwrap();
    jobs["jobs"][0]["runner_id"] = 52.into();
    let jobs = if busy { jobs.to_string() } else { r#"{"jobs":[],"total_count":0}"#.into() };
    m.route("GET", &format!("{GT}/jobs?status=in_progress&limit=50&page=1"), 200, jobs);
    m.route("PATCH", &format!("{GT}/runners/52"), 200, fixture_in("gitea", "runner_disabled.json"));
    m.route("DELETE", &format!("{GT}/runners/52"), 204, "");
    m.route("POST", &format!("{GT}/runs/70/cancel"), 200, "{}");
}

/// GitLab's runner 79 as `deregister` sees it; `jobs` is the fixture its job list answers with.
fn gl_runner(m: &Mock, jobs: &str) {
    m.route("PUT", &format!("{GL}/runners/79"), 200, fixture_in("gitlab", "runner_paused.json"));
    m.route("GET", &format!("{GL}/runners/79/jobs?status=running"), 200, fixture_in("gitlab", jobs));
    m.route("DELETE", &format!("{GL}/runners/79"), 204, "");
}

/// A VM record without a task behind it.
fn seed(app: &App, id: &str, repo: &str, state: &str, runner_id: u64, cpus: u32, mem_mb: u32) {
    let v: vm::Vm = serde_json::from_value(json!({
        "id": id, "repo": repo, "runner_id": runner_id, "state": state, "job": null, "result": null,
        "started": 1, "online_at": 2, "busy_since": null, "ended": null, "note": null,
        "cpus": cpus, "mem_mb": mem_mb, "warm": false, "policy": "old"
    }))
    .unwrap();
    app.vms.lock().unwrap().push(v);
}

/// A kill handle for a seeded VM, to see whether it was told to die.
fn watch(app: &App, id: &str) -> Arc<tokio::sync::Notify> {
    let k = Arc::new(tokio::sync::Notify::new());
    app.kills.lock().unwrap().insert(id.into(), k.clone());
    k
}

/// A stored permit completes at once, so a zero timeout tells "was killed" from "was not".
async fn killed(k: &tokio::sync::Notify) -> bool {
    tokio::time::timeout(Duration::ZERO, k.notified()).await.is_ok()
}

fn calls(m: &Mock) -> Vec<String> {
    m.requests()
}

#[tokio::test]
async fn demand_is_counted_per_forge() {
    let t = Trio::new("mixed-demand", 0, |_| {}).await;
    gh_queue(&t.gh, 2);
    gt_queue(&t.gt, 3, false);
    gl_queue(&t.gl, vec![gl_job(1, false)]);
    let q = t.tick().await.unwrap();
    let n = |repo: &str| q[repo].get(&1).copied().unwrap_or(0);
    assert_eq!(n(GH_REPO), 2);
    assert_eq!(n(GT_REPO), 3);
    assert_eq!(n(GL_REPO), 1);
    assert_eq!(q.len(), 3, "{q:?}");
    // Each forge was read through its own API only, and only read.
    assert!(calls(&t.gh).iter().all(|r| r.starts_with("GET /repos/")), "{:?}", calls(&t.gh));
    assert!(calls(&t.gt).iter().all(|r| r.starts_with("GET /api/v1/")), "{:?}", calls(&t.gt));
    assert!(calls(&t.gl).iter().all(|r| r.starts_with("GET /api/v4/")), "{:?}", calls(&t.gl));
    assert!(calls(&t.gh).iter().any(|r| r.contains("runs?status=queued")));
    assert!(calls(&t.gt).iter().any(|r| r.contains("jobs?status=queued")));
    assert!(calls(&t.gl).iter().any(|r| r.contains("/jobs?scope")));
    assert!(t.gt.log().iter().all(|r| r.auth.as_deref() == Some("token gt-tok")), "Gitea's token goes to Gitea only");
    assert!(t.app.poll.lock().unwrap().repo_errors.is_empty());
}

#[tokio::test]
async fn a_queued_fork_job_blocks_no_repo() {
    let t = Trio::new("mixed-forks", 99, |c| {
        c.warm.insert(GT_REPO.into(), 1);
        c.warm.insert(GL_REPO.into(), 1);
    })
    .await;
    gh_queue(&t.gh, 1);
    // Gitea has a queued fork run (any runner would take it); GitLab a fork MR next to a plain job.
    gt_queue(&t.gt, 1, true);
    gl_queue(&t.gl, vec![gl_job(1, false), gl_job(2, true)]);
    gt_runner(&t.gt, false);
    seed(&t.app, "seed-gt", GT_REPO, "idle", 52, 1, 64);
    let policy = vm::policy_id(&t.cfg);
    t.app.vms.lock().unwrap().iter_mut().for_each(|v| (v.policy, v.started, v.online_at) = (policy.clone(), now(), Some(now())));
    let gt_kill = watch(&t.app, "seed-gt");

    t.tick().await.unwrap();
    {
        let p = t.app.poll.lock().unwrap();
        assert!(p.repo_errors.is_empty(), "{:?}", p.repo_errors);
        assert_eq!((p.refused_forks.len(), p.refused_forks[GT_REPO], p.refused_forks[GL_REPO]), (2, 1, 1), "{:?}", p.refused_forks);
        // Gitea reports its queued fork (a banner only); GitLab refuses the MR job. Neither holds anything.
        assert_eq!(p.fork_queued, [GT_REPO]);
    }
    assert!(!killed(&gt_kill).await, "the idle Gitea VM is kept: the exec gate refuses a fork job on any VM");
    assert!(!t.gt.requests().iter().any(|r| r == &format!("DELETE {GT}/runners/52")), "{:?}", t.gt.requests());
    assert_eq!(t.launched(GH_REPO), 1, "GitHub launches for its own queue");
    assert!(t.launched(GL_REPO) >= 1, "GitLab keeps its warm pool");
    let writes =
        |m: &Mock| calls(m).into_iter().filter(|r| r.starts_with("DELETE") || r.starts_with("PUT") || r.starts_with("PATCH")).count();
    assert_eq!((writes(&t.gh), writes(&t.gl)), (0, 0), "nothing was retired on the other forges");

    // The fork job leaves: Gitea launches again, and nothing else moved.
    t.quiesce().await;
    t.app.vms.lock().unwrap().retain(|v| v.id != "seed-gt");
    gt_queue(&t.gt, 1, false);
    t.tick().await.unwrap();
    assert!(t.app.poll.lock().unwrap().fork_queued.is_empty());
    assert!(t.launched(GT_REPO) >= 1, "the Gitea warm pool refills");
    t.quiesce().await;
}

#[tokio::test]
async fn one_forges_backoff_leaves_the_others_launching() {
    let t = Trio::new("mixed-backoff", 99, |c| {
        for r in [GH_REPO, GT_REPO, GL_REPO] {
            c.warm.insert(r.into(), 1);
        }
    })
    .await;
    let gl = forge::ForgeId::new("gl").unwrap();
    t.app.api_backoff.lock().unwrap().entry(gl.clone()).or_default().fail(Some(503), now());
    t.tick().await.unwrap();
    let health = t.health();
    assert_eq!(health.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(), ["forge_api"], "{health:?}");
    assert!(health[0].1.starts_with("gl is rejecting runner registration (HTTP 503)"), "{health:?}");
    assert_eq!(t.app.poll.lock().unwrap().blocked_kind.as_deref(), Some("forge_api"));
    assert_eq!((t.launched(GH_REPO), t.launched(GT_REPO), t.launched(GL_REPO)), (1, 1, 0));

    // GitLab's pause ends: it alone starts launching; the others keep their own repo backoff.
    t.quiesce().await;
    t.app.api_backoff.lock().unwrap().remove(&gl);
    t.tick().await.unwrap();
    assert!(t.health().is_empty(), "{:?}", t.health());
    assert_eq!(t.launched(GL_REPO), 1);
    t.quiesce().await;
}

#[tokio::test]
async fn a_401_and_a_rate_limit_stay_with_their_own_forge() {
    let t = Trio::new("mixed-limits", 0, |_| {}).await;
    gh_queue(&t.gh, 1);
    t.gt.route("GET", &format!("{GT}/jobs?status=queued&limit=50&page=1"), 401, fixture_in("gitea", "err_401.json"));
    t.gl.route("GET", GL_JOBS, 429, fixture_in("gitlab", "err_429.txt"));
    let e = t.tick().await.unwrap_err().to_string();
    assert!(e.contains(GT_REPO) && e.contains(GL_REPO), "{e}");
    {
        let p = t.app.poll.lock().unwrap();
        let mut bad: Vec<_> = p.repo_errors.keys().cloned().collect();
        bad.sort();
        assert_eq!(bad, [GT_REPO, GL_REPO]);
        assert!(p.repo_errors[GT_REPO].contains("401"), "{:?}", p.repo_errors);
        assert!(p.repo_errors[GL_REPO].contains("429"), "{:?}", p.repo_errors);
    }
    assert!(calls(&t.gh).iter().any(|r| r.contains("runs?status=queued")), "GitHub was still polled");
    // GitLab's 429 paused that forge only; a bad Gitea token is a per-repo error and nothing more.
    assert!(t.app.forges.get(&forge::ForgeId::new("gl").unwrap()).unwrap().health().unwrap().contains("rate limit"));
    assert!(t.app.forges.get(&forge::ForgeId::github()).unwrap().health().is_none());
    assert!(t.app.forges.get(&forge::ForgeId::new("gitea").unwrap()).unwrap().health().is_none());

    // Next tick: GitLab is skipped outright (no request), Gitea's token fixed, GitHub unchanged.
    let before = calls(&t.gl).len();
    gt_queue(&t.gt, 1, false);
    let q = t.tick().await.unwrap();
    assert_eq!(calls(&t.gl).len(), before, "a paused forge is not polled");
    let mut polled: Vec<_> = q.keys().cloned().collect();
    polled.sort();
    assert_eq!(polled, [GH_REPO, GT_REPO]);
    let h = t.health();
    assert_eq!(h.len(), 1, "{h:?}");
    assert!(h[0].0 == "forge" && h[0].1.starts_with("gl: GitLab rate limit"), "{h:?}");
}

#[tokio::test]
async fn a_github_rate_limit_leaves_gitlab_and_gitea_polling() {
    let t = Trio::new("mixed-gh-limit", 0, |_| {}).await;
    gt_queue(&t.gt, 1, false);
    gl_queue(&t.gl, vec![gl_job(1, false)]);
    t.gh.fail("GET", "/repos/acme/demo/actions/runs?status=queued&per_page=30", 403, "You have exceeded a Secondary Rate Limit.");
    let e = t.tick().await.unwrap_err().to_string();
    assert!(e.contains(GH_REPO), "{e}");
    assert_eq!(t.app.poll.lock().unwrap().repo_errors.keys().collect::<Vec<_>>(), [GH_REPO]);
    assert!(calls(&t.gt).iter().any(|r| r.contains("jobs?status=queued")) && calls(&t.gl).iter().any(|r| r.contains("/jobs?scope")));

    let before = calls(&t.gh).len();
    let q = t.tick().await.unwrap();
    assert_eq!(calls(&t.gh).len(), before, "the limited forge is not polled");
    let mut polled: Vec<_> = q.keys().cloned().collect();
    polled.sort();
    assert_eq!(polled, [GT_REPO, GL_REPO]);
    let h = t.health();
    assert!(h.len() == 1 && h[0].0 == "forge" && h[0].1.contains("GitHub") && h[0].1.contains("rate limit"), "{h:?}");
    assert!(t.app.poll.lock().unwrap().repo_errors.is_empty());
}

#[tokio::test]
async fn max_vms_is_shared_across_forges() {
    let t = Trio::new("mixed-slots", 3, |_| {}).await;
    gh_queue(&t.gh, 2);
    // A job running on each forge takes a slot: 3 of 3 (cpus 0 and memory 0 keep the budget out of it).
    for (id, repo) in [("seed-gh", GH_REPO), ("seed-gt", GT_REPO), ("seed-gl", GL_REPO)] {
        seed(&t.app, id, repo, "busy", 1, 0, 0);
    }
    t.tick().await.unwrap();
    assert_eq!(t.launched(GH_REPO), 0, "GitHub's two queued jobs wait for a slot the other forges hold");
    let w = t.app.poll.lock().unwrap().waiting.clone();
    assert!(w.iter().any(|w| w.repo == GH_REPO && w.jobs == 2 && w.reason == "slots_full"), "{w:?}");
    assert!(t.app.poll.lock().unwrap().blocked_kind.is_none(), "a full house is no banner");
    // One slot frees up in the shared cap: GitHub gets exactly one of its two.
    let cfg = Config { max_vms: 4, ..t.cfg.clone() };
    tick(&t.app, &cfg).await.unwrap();
    assert_eq!((t.launched(GH_REPO), t.launched(GT_REPO), t.launched(GL_REPO)), (1, 0, 0));
    t.quiesce().await;
}

/// Three repos each want one warm VM; the budget (committed by a seeded Busy VM) leaves room for two.
async fn two_of_three(name: &str, seed_cpus: u32, seed_mem: u32) -> Trio {
    let t = Trio::new(name, 99, |c| {
        for r in [GH_REPO, GT_REPO, GL_REPO] {
            c.warm.insert(r.into(), 1);
        }
    })
    .await;
    seed(&t.app, "seed-busy", GH_REPO, "busy", 1, seed_cpus, seed_mem);
    t.tick().await.unwrap();
    t.quiesce().await;
    let per: Vec<_> = [GH_REPO, GT_REPO, GL_REPO].map(|r| t.launched(r)).into();
    assert_eq!(per.iter().sum::<usize>(), 2, "one budget for all forges: {per:?}");
    assert!(per.iter().all(|&n| n <= 1), "{per:?}");
    assert_eq!(t.app.poll.lock().unwrap().blocked_kind.as_deref(), Some("budget"));
    t
}

#[tokio::test]
async fn the_cpu_budget_is_shared_across_forges() {
    // The host budget is 1.5 vCPUs per thread; leave exactly two vCPUs.
    let max = HostReadings::TEST.threads * 3 / 2;
    let t = two_of_three("mixed-cpu", max - 2, 0).await;
    let why = t.app.poll.lock().unwrap().blocked.clone().unwrap();
    assert!(why.starts_with("cpu budget"), "{why}");
}

#[tokio::test]
async fn the_memory_budget_is_shared_across_forges() {
    // 2 GB stay reserved for the host; leave exactly two 64 MB VMs.
    let total = HostReadings::TEST.mem_total_mb;
    let t = two_of_three("mixed-mem", 0, (total - 2048 - 128) as u32).await;
    let why = t.app.poll.lock().unwrap().blocked.clone().unwrap();
    assert!(why.starts_with("memory budget"), "{why}");
}

#[tokio::test]
async fn retire_reaches_the_right_forge_with_the_right_reason() {
    let t = Trio::new("mixed-retire", 99, |_| {}).await;
    // A job got to every runner first: GitHub answers 422, Gitea and GitLab list it as running.
    t.gh.route("DELETE", "/repos/acme/demo/actions/runners/11", 422, r#"{"message":"runner is busy"}"#);
    gt_runner(&t.gt, true);
    gl_runner(&t.gl, "runner_jobs_running.json");
    let vms = [("seed-gh", GH_REPO, 11), ("seed-gt", GT_REPO, 52), ("seed-gl", GL_REPO, 79)];
    let kills: Vec<_> = vms
        .iter()
        .map(|&(id, repo, rid)| {
            seed(&t.app, id, repo, "idle", rid, 1, 64);
            watch(&t.app, id)
        })
        .collect();

    // Surplus: a runner that has a job lives, on every forge.
    for (_, repo, _) in vms {
        vm::reap(&t.app, repo, 1, 1).await;
    }
    for k in &kills {
        assert!(!killed(k).await);
    }
    assert!(t.gh.requests().iter().all(|r| r == "DELETE /repos/acme/demo/actions/runners/11"), "GitHub: one delete per attempt");
    assert_eq!(t.gl.requests(), [format!("PUT {GL}/runners/79"), format!("GET {GL}/runners/79/jobs?status=running")]);
    assert!(!t.gt.requests().iter().any(|r| r.starts_with("DELETE")), "{:?}", t.gt.requests());

    // A stale security policy: the VM must not take another job, so GitLab and Gitea end the runner
    // anyway; GitHub has no way to and keeps it.
    for (_, repo, _) in vms {
        vm::recycle_stale_policy(&t.app, repo, "new").await;
    }
    assert_eq!([killed(&kills[0]).await, killed(&kills[1]).await, killed(&kills[2]).await], [false, true, true]);
    assert_eq!(t.gl.requests().last().unwrap(), &format!("DELETE {GL}/runners/79"));
    assert!(t.gt.requests().iter().any(|r| r == &format!("POST {GT}/runs/70/cancel")), "{:?}", t.gt.requests());
    let note = |id: &str| t.app.vms.lock().unwrap().iter().find(|v| v.id == id).unwrap().note.clone();
    assert_eq!(note("seed-gl").as_deref(), Some(forge::Reason::StalePolicy.note()));
    assert_eq!(note("seed-gt").as_deref(), Some(forge::Reason::StalePolicy.note()));
    assert_eq!(note("seed-gh"), None);

    // A VM that ended unused: only the gated forges delete its runner (GitHub's JIT runner is
    // single-use), and with no pause or job check.
    t.gl.clear_log();
    t.gt.clear_log();
    t.gh.clear_log();
    gt_runner(&t.gt, false);
    for (id, repo, rid) in [("seed-ended-gh", GH_REPO, 11), ("seed-ended-gt", GT_REPO, 52), ("seed-ended-gl", GL_REPO, 79)] {
        seed(&t.app, id, repo, "done", rid, 1, 64);
        t.app.vms.lock().unwrap().iter_mut().find(|v| v.id == id).unwrap().ended = Some(now());
    }
    vm::retire_ended(&t.app).await;
    assert_eq!(t.gl.requests(), [format!("DELETE {GL}/runners/79")]);
    assert!(t.gt.requests().iter().any(|r| r.starts_with("DELETE")), "{:?}", t.gt.requests());
    assert!(t.gh.requests().is_empty(), "GitHub is not gated: {:?}", t.gh.requests());
}

/// A security recycle must not be undone by a forge that cannot delete the runner: the idle VM dies anyway,
/// and `retire` still reports the failure so the delete is tried again.
#[tokio::test]
async fn a_stale_policy_vm_dies_even_when_its_runner_cannot_be_deleted() {
    let t = Trio::new("mixed-retire-err", 99, |_| {}).await;
    t.gh.fail("DELETE", "/repos/acme/demo/actions/runners/11", 500, "boom");
    t.gl.route("PUT", &format!("{GL}/runners/79"), 500, "{}");
    t.gt.route("PATCH", &format!("{GT}/runners/52"), 500, "{}");
    let vms = [("seed-gh", GH_REPO, 11), ("seed-gl", GL_REPO, 79), ("seed-gt", GT_REPO, 52), ("seed-none", "gl2:acme/demo", 5)];
    let kills: Vec<_> = vms
        .iter()
        .map(|&(id, repo, rid)| {
            seed(&t.app, id, repo, "idle", rid, 1, 64);
            watch(&t.app, id)
        })
        .collect();
    // A VM that already has a job is not a candidate.
    seed(&t.app, "seed-job", GH_REPO, "idle", 12, 1, 64);
    t.app.vms.lock().unwrap().iter_mut().find(|v| v.id == "seed-job").unwrap().job_url = Some("https://x/1".into());
    let busy = watch(&t.app, "seed-job");
    for (_, repo, _) in vms {
        let ok = vm::recycle_stale_policy(&t.app, repo, "new").await;
        // GitLab goes on to delete after a failed pause when the policy is stale; the others report the failure.
        assert_eq!(ok, repo == GL_REPO, "{repo}: a failed delete is reported so it is retried");
    }
    for k in &kills {
        assert!(killed(k).await);
    }
    assert!(!killed(&busy).await);
    let note = |id: &str| t.app.vms.lock().unwrap().iter().find(|v| v.id == id).unwrap().note.clone().unwrap();
    assert!(note("seed-gh").contains("runner delete failed"), "{}", note("seed-gh"));
    // The forge recovers: the next recycle finds nothing left to do, and a retry of the delete is the sweep's.
}

/// A reboot loses the VMs and the network is not up when kiln starts: the lost VMs' runners are deleted
/// on every forge, and the sweep of GitHub's repo that failed is retried, not skipped for good.
#[tokio::test]
async fn startup_cleanup_is_retried_until_it_worked() {
    let t = Trio::new("mixed-cleanup", 0, |_| {}).await;
    let list = "/repos/acme/demo/actions/runners?per_page=100";
    t.gl.route("GET", &format!("{GL}/projects/1/runners?type=project_type&per_page=100&page=1"), 200, "[]");
    t.gt.route("GET", &format!("{GT}/runners?limit=50&page=1"), 200, r#"{"runners":[],"total_count":0}"#);
    // The last run's GitHub VM, lost in the reboot; GitHub is unreachable for now.
    seed(&t.app, "seed-lost", GH_REPO, "lost", 11, 1, 64);
    t.app.vms.lock().unwrap().iter_mut().for_each(|v| v.ended = Some(now()));
    t.gh.fail("GET", list, 503, "down");
    t.gh.fail("DELETE", "/repos/acme/demo/actions/runners/11", 503, "down");

    let mut c = Cleanup::default();
    c.step(&t.app).await;
    assert!(!c.retired && c.fails == 1 && c.next > now(), "nothing worked yet: retry later");
    assert!(c.swept.contains("gitea:acme/demo") && c.swept.contains("gl:acme/demo") && !c.swept.contains("acme/demo"), "{:?}", c.swept);

    // Not before its time; then the network is up.
    t.gh.clear_log();
    c.step(&t.app).await;
    assert!(t.gh.requests().is_empty(), "waits out its backoff: {:?}", t.gh.requests());
    t.gh.route("GET", list, 200, fixture("runners.json"));
    t.gh.route("DELETE", "/repos/acme/demo/actions/runners/11", 204, "");
    c.next = 0;
    c.step(&t.app).await;
    assert!(c.retired && c.fails == 0 && c.swept.contains("acme/demo"), "{:?}", c.swept);
    assert!(t.gh.requests().iter().any(|r| r == "DELETE /repos/acme/demo/actions/runners/11"), "{:?}", t.gh.requests());

    // Done: later steps ask nobody.
    t.gh.clear_log();
    c.step(&t.app).await;
    assert!(t.gh.requests().is_empty() && t.gl.requests().iter().filter(|r| r.contains("runners?")).count() == 1);
}

#[tokio::test]
async fn the_hourly_sweep_hits_each_gated_forge_and_one_failure_stops_no_other() {
    let t = Trio::new("mixed-sweep", 0, |_| {}).await;
    // GitLab: an `online` runner of this install, a day and ten minutes old, with no VM.
    let mut orphan: Value = serde_json::from_str::<Vec<Value>>(&fixture_in("gitlab", "runner_list.json")).unwrap().remove(0);
    orphan["id"] = 301.into();
    orphan["status"] = "online".into();
    orphan["created_at"] = "2020-01-01T00:00:00.000Z".into();
    t.gl.route("GET", &format!("{GL}/projects/1/runners?type=project_type&per_page=100&page=1"), 200, json!([orphan]).to_string());
    t.gl.route("DELETE", &format!("{GL}/runners/301"), 204, "");
    // Gitea: the fixture's offline runner of this install, first failing to list.
    let list = format!("{GT}/runners?limit=50&page=1");
    gt_runner(&t.gt, false);
    t.gt.route("GET", &list, 500, "{}");

    sweep_runners(&t.app, true, 0).await;
    assert!(t.gl.requests().iter().any(|r| r == &format!("DELETE {GL}/runners/301")), "{:?}", t.gl.requests());
    assert!(!t.gt.requests().iter().any(|r| r.starts_with("DELETE")));
    assert!(t.gh.requests().is_empty(), "GitHub's runners go by the startup sweep alone: {:?}", t.gh.requests());

    t.gl.clear_log();
    t.gt.route("GET", &list, 200, fixture_in("gitea", "runners_one.json"));
    t.gl.route("GET", &format!("{GL}/projects/1/runners?type=project_type&per_page=100&page=1"), 200, "[]");
    sweep_runners(&t.app, true, 0).await;
    assert!(t.gt.requests().iter().any(|r| r == &format!("DELETE {GT}/runners/52")), "{:?}", t.gt.requests());
    assert!(t.gl.requests().iter().all(|r| r.starts_with("GET ")), "nothing left to delete: {:?}", t.gl.requests());

    // The startup sweep covers GitHub too.
    sweep_runners(&t.app, false, 0).await;
    assert!(t.gh.requests().iter().any(|r| r.starts_with("GET /repos/acme/demo/actions/runners")), "{:?}", t.gh.requests());
}

fn fresh(repo: &str) -> vm::Vm {
    serde_json::from_value(json!({
        "id": "kiln-1-0", "repo": repo, "runner_id": 1, "state": "booting", "job": null, "result": null,
        "started": 1, "busy_since": null, "ended": null, "note": null
    }))
    .unwrap()
}

#[tokio::test]
async fn the_vms_forge_picks_its_console_parser() {
    let t = Trio::new("mixed-console", 0, |_| {}).await;
    let step = |repo: &str, state: vm::State, line: &str| {
        let (f, _) = vm::forge_for(&t.app, repo).unwrap();
        let mut v = fresh(repo);
        v.state = state;
        vm::apply_line(f.kind(), &mut v, line, 100);
        v
    };
    let gh_listen = "2026-10-06 10:00:01Z: Listening for Jobs";
    let gh_run = "x: Running job: build";
    let gl_listen = "Starting runner for http://x with token tGmfbUlVk ...";
    let gl_start = "Checking for jobs... received correlation_id=c job=200 job_name=x runner=r";
    let hostkey = "[   32.2] kiln-job[1395]: kiln: hostkey 256 SHA256:x (ED25519)";
    use vm::State::*;
    // Each VM understands its own forge's runner and nobody else's.
    assert_eq!(step(GH_REPO, Booting, gh_listen).state, Idle);
    assert_eq!(step(GL_REPO, Booting, gl_listen).state, Idle);
    assert_eq!(step(GH_REPO, Booting, gl_listen).state, Booting);
    assert_eq!(step(GL_REPO, Booting, gh_listen).state, Booting);
    assert_eq!(step(GT_REPO, Booting, gh_listen).state, Booting);
    assert_eq!(step(GT_REPO, Booting, gl_listen).state, Booting);
    let gh = step(GH_REPO, Idle, gh_run);
    assert_eq!((gh.state, gh.job.as_deref(), gh.starts), (Busy, Some("build"), 1));
    let gl = step(GL_REPO, Idle, gl_start);
    assert_eq!((gl.state, gl.job.as_deref(), gl.starts), (Busy, Some("200"), 1));
    assert_eq!(step(GH_REPO, Idle, gl_start).state, Idle);
    assert_eq!(step(GL_REPO, Idle, gh_run).state, Idle);
    assert_eq!(step(GT_REPO, Idle, gl_start).state, Idle);
    assert_eq!(step(GT_REPO, Idle, gh_run).state, Idle);
    // The guest's own journal line is forge-neutral.
    for repo in [GH_REPO, GT_REPO, GL_REPO] {
        assert_eq!(step(repo, Held, hostkey).ssh_hostkeys, ["256 SHA256:x (ED25519)"], "{repo}");
    }
}

#[tokio::test]
async fn the_vms_forge_picks_the_guest_secret() {
    let t = Trio::new("mixed-secret", 0, |_| {}).await;
    t.gh.route("POST", "/repos/acme/demo/actions/runners/generate-jitconfig", 201, fixture("jitconfig.json"));
    t.gt.route("POST", &format!("{GT}/runners/registration-token"), 200, fixture_in("gitea", "registration_token.json"));
    t.gt.route("POST", "/api/actions/runner.v1.RunnerService/Register", 200, fixture_in("gitea", "register.json"));
    t.gl.route("POST", &format!("{GL}/user/runners"), 201, fixture_in("gitlab", "runner_register.json"));
    let labels = t.cfg.runner_labels(1);
    let mint = |repo: &str| {
        let (f, rr) = vm::forge_for(&t.app, repo).unwrap();
        let labels = labels.clone();
        async move { f.register(&rr, "kiln-5-0", &labels).await }
    };

    let gh = mint(GH_REPO).await.unwrap().guest_secret;
    assert!(gh.starts_with("kiln.jit=") && !gh.contains('\n'), "{gh}");
    let gt = mint(GT_REPO).await.unwrap().guest_secret;
    assert!(gt.starts_with("kiln.forge=gitea\nkiln.cred="), "{gt}");
    let r = mint(GL_REPO).await.unwrap();
    assert!(r.guest_secret.starts_with("kiln.forge=gitlab\nkiln.url=") && r.guest_secret.contains("\nkiln.cred="), "{}", r.guest_secret);
    // The GitLab guest gets the runner's own token, never kiln's personal access token.
    assert!(!r.guest_secret.contains("gl-tok"));
    assert!(!gt.contains("gt-tok"), "kiln's Gitea token never reaches the guest");
    // Each registration went to its own forge.
    assert!(t.gh.requests().iter().all(|r| r.contains("generate-jitconfig") || r.starts_with("GET ")), "{:?}", t.gh.requests());
    assert_eq!(t.gt.requests().iter().filter(|r| r.starts_with("POST ")).count(), 2);
}

const GH: &str = "/repos/acme/demo/actions";

/// A GitHub VM kiln lost while `job` of `run` ran on it, with a busy runner 11.
fn lost_gh(t: &Trio, id: &str, run: u64, job: u64) {
    seed(&t.app, id, GH_REPO, "lost", 11, 1, 64);
    let mut vms = t.app.vms.lock().unwrap();
    let v = vms.iter_mut().find(|v| v.id == id).unwrap();
    v.ended = Some(now());
    v.busy_since = Some(5);
    v.job = Some("build".into());
    v.job_url = Some(format!("https://github.com/acme/demo/actions/runs/{run}/job/{job}"));
}

fn gh_job(t: &Trio, job: u64, status: &str, runner: &str) {
    t.gh.route("GET", &format!("{GH}/jobs/{job}"), 200, json!({ "id": job, "status": status, "runner_name": runner }).to_string());
}

fn forced(t: &Trio) -> usize {
    t.gh.requests().iter().filter(|r| r.ends_with("/force-cancel")).count()
}

fn gh_note(t: &Trio, id: &str) -> Option<String> {
    t.app.vms.lock().unwrap().iter().find(|v| v.id == id).unwrap().note.clone()
}

#[tokio::test]
async fn a_lost_vms_busy_runner_gets_its_run_force_cancelled_once_then_the_delete_is_retried() {
    let t = Trio::new("mixed-reclaim", 99, |_| {}).await;
    t.gh.fail("DELETE", &format!("{GH}/runners/11"), 422, "Bad request - Runner is busy");
    gh_job(&t, 7001, "in_progress", "seed-a");
    t.gh.route("POST", &format!("{GH}/runs/9001/force-cancel"), 202, "{}");
    lost_gh(&t, "seed-a", 9001, 7001);
    assert!(!vm::retire_ended(&t.app).await, "the delete is to be retried");
    assert_eq!(forced(&t), 1);
    assert!(gh_note(&t, "seed-a").unwrap().starts_with("kiln force-cancelled run 9001: its job was lost when"));
    // The retry: still busy for a moment, then gone. No second cancel either way.
    assert!(!vm::retire_ended(&t.app).await);
    t.gh.route("DELETE", &format!("{GH}/runners/11"), 204, "");
    assert!(vm::retire_ended(&t.app).await);
    assert_eq!(forced(&t), 1);
    assert_eq!(t.gh.requests().iter().filter(|r| r.starts_with("GET ") && r.contains("/jobs/")).count(), 1);
}

#[tokio::test]
async fn nothing_is_cancelled_unless_the_job_runs_on_that_runner() {
    let t = Trio::new("mixed-reclaim-no", 99, |_| {}).await;
    t.gh.fail("DELETE", &format!("{GH}/runners/11"), 422, "busy");
    t.gh.route("POST", &format!("{GH}/runs/9001/force-cancel"), 202, "{}");
    lost_gh(&t, "seed-a", 9001, 7001);
    for (status, runner) in [("in_progress", "someone-else"), ("completed", "seed-a"), ("in_progress", "")] {
        gh_job(&t, 7001, status, runner);
        assert!(vm::retire_ended(&t.app).await, "nothing to retry");
    }
    // The job cannot be read at all: no cancel, and the check is repeated later.
    t.gh.fail("GET", &format!("{GH}/jobs/7001"), 500, "boom");
    assert!(!vm::retire_ended(&t.app).await);
    assert_eq!(forced(&t), 0);
    assert_eq!(gh_note(&t, "seed-a"), None);
}

#[tokio::test]
async fn a_run_another_active_vm_holds_is_cancelled_only_after_it_ends() {
    let t = Trio::new("mixed-reclaim-shared", 99, |_| {}).await;
    t.gh.fail("DELETE", &format!("{GH}/runners/11"), 422, "busy");
    gh_job(&t, 7001, "in_progress", "seed-a");
    t.gh.route("POST", &format!("{GH}/runs/9001/force-cancel"), 202, "{}");
    lost_gh(&t, "seed-a", 9001, 7001);
    seed(&t.app, "seed-b", GH_REPO, "busy", 12, 1, 64);
    t.app.vms.lock().unwrap().iter_mut().find(|v| v.id == "seed-b").unwrap().job_url =
        Some("https://github.com/acme/demo/actions/runs/9001/job/7002".into());
    assert!(!vm::retire_ended(&t.app).await, "retried later");
    assert_eq!(forced(&t), 0);
    assert!(!t.gh.requests().iter().any(|r| r.contains("/jobs/")), "not even asked");
    // The sibling ends: the next try cancels.
    t.app.vms.lock().unwrap().iter_mut().find(|v| v.id == "seed-b").unwrap().state = vm::State::Done;
    assert!(!vm::retire_ended(&t.app).await);
    assert_eq!(forced(&t), 1);
}

/// A VM kiln ended while the job ran: the record `launch` leaves after a shutdown or dashboard kill.
fn killed_gh(t: &Trio, id: &str, note: &str) {
    lost_gh(t, id, 9001, 7001);
    let mut vms = t.app.vms.lock().unwrap();
    let v = vms.iter_mut().find(|v| v.id == id).unwrap();
    (v.state, v.note) = (vm::State::Killed, Some(note.into()));
}

fn cause(t: &Trio, id: &str) -> Option<&'static str> {
    t.app.vms.lock().unwrap().iter().find(|v| v.id == id).unwrap().fail_cause()
}

#[tokio::test]
async fn a_reclaim_appends_to_the_note_and_keeps_the_failure_cause() {
    for (note, state, want) in [
        ("kiln shutting down", vm::State::Killed, "killed"),
        ("killed from dashboard", vm::State::Killed, "killed"),
        ("", vm::State::Lost, "lost"),
    ] {
        let t = Trio::new("mixed-reclaim-note", 99, |_| {}).await;
        t.gh.fail("DELETE", &format!("{GH}/runners/11"), 422, "busy");
        gh_job(&t, 7001, "in_progress", "seed-a");
        t.gh.route("POST", &format!("{GH}/runs/9001/force-cancel"), 202, "{}");
        killed_gh(&t, "seed-a", note);
        t.app.vms.lock().unwrap().iter_mut().find(|v| v.id == "seed-a").unwrap().state = state;
        assert_eq!(cause(&t, "seed-a"), Some(want));
        assert!(!vm::retire_ended(&t.app).await, "{note}");
        assert_eq!(forced(&t), 1, "{note}");
        let n = gh_note(&t, "seed-a").unwrap();
        assert!(n.starts_with(note) && n.contains("kiln force-cancelled run 9001"), "{n}");
        assert_eq!(cause(&t, "seed-a"), Some(want), "{n}");
        // The cancel is not repeated on the next start, even though the note changed.
        vm::retire_ended(&t.app).await;
        assert_eq!(forced(&t), 1, "{note}");
    }
}

#[tokio::test]
async fn a_job_timeout_kill_is_not_reclaimed() {
    let t = Trio::new("mixed-reclaim-timeout", 99, |_| {}).await;
    t.gh.fail("DELETE", &format!("{GH}/runners/11"), 422, "busy");
    gh_job(&t, 7001, "in_progress", "seed-a");
    killed_gh(&t, "seed-a", "job timeout after 60 min");
    assert!(vm::retire_ended(&t.app).await);
    assert!(t.gh.requests().is_empty(), "today's behaviour: not even retired at start: {:?}", t.gh.requests());
}

#[tokio::test]
async fn a_rate_limited_force_cancel_is_retried() {
    let t = Trio::new("mixed-reclaim-rate", 99, |_| {}).await;
    t.gh.fail("DELETE", &format!("{GH}/runners/11"), 422, "busy");
    gh_job(&t, 7001, "in_progress", "seed-a");
    t.gh.fail("POST", &format!("{GH}/runs/9001/force-cancel"), 403, "API rate limit exceeded for installation");
    lost_gh(&t, "seed-a", 9001, 7001);
    assert!(!vm::retire_ended(&t.app).await);
    assert_eq!(gh_note(&t, "seed-a"), None, "not final");
    t.gh.route("POST", &format!("{GH}/runs/9001/force-cancel"), 202, "{}");
    assert!(!vm::retire_ended(&t.app).await);
    assert_eq!(forced(&t), 2);
    assert!(gh_note(&t, "seed-a").unwrap().starts_with("kiln force-cancelled"));
}

/// Without a VM scope a kill -9 of kiln leaves QEMU running: the job is healthy, nothing is cancelled.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_vm_whose_qemu_still_runs_is_not_reclaimed() {
    let t = Trio::new("mixed-reclaim-qemu", 99, |_| {}).await;
    t.gh.fail("DELETE", &format!("{GH}/runners/11"), 422, "busy");
    gh_job(&t, 7001, "in_progress", "seed-a");
    t.gh.route("POST", &format!("{GH}/runs/9001/force-cancel"), 202, "{}");
    lost_gh(&t, "seed-a", 9001, 7001);
    let q = format!("{}/vms/seed-a/q/disk", t.app.data.display());
    let mut qemu = std::process::Command::new("bash").args(["-c", "exec -a \"qemu-system-x86_64 $0\" sleep 30", &q]).spawn().unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert!(!vm::retire_ended(&t.app).await, "retried later");
    assert_eq!(forced(&t), 0);
    qemu.kill().unwrap();
    qemu.wait().unwrap();
    assert!(!vm::retire_ended(&t.app).await);
    assert_eq!(forced(&t), 1);
}

#[tokio::test]
async fn reclaim_lost_jobs_off_cancels_nothing() {
    let t = Trio::new("mixed-reclaim-off", 99, |c| c.reclaim_lost_jobs = false).await;
    t.gh.fail("DELETE", &format!("{GH}/runners/11"), 422, "busy");
    gh_job(&t, 7001, "in_progress", "seed-a");
    t.gh.route("POST", &format!("{GH}/runs/9001/force-cancel"), 202, "{}");
    lost_gh(&t, "seed-a", 9001, 7001);
    assert!(vm::retire_ended(&t.app).await);
    assert_eq!(t.gh.requests(), [format!("DELETE {}/runners/11", "/repos/acme/demo/actions")]);
}

#[tokio::test]
async fn a_refused_force_cancel_is_final() {
    for status in [409, 403, 404] {
        let t = Trio::new("mixed-reclaim-409", 99, |_| {}).await;
        t.gh.fail("DELETE", &format!("{GH}/runners/11"), 422, "busy");
        gh_job(&t, 7001, "in_progress", "seed-a");
        t.gh.fail("POST", &format!("{GH}/runs/9001/force-cancel"), status, "no");
        lost_gh(&t, "seed-a", 9001, 7001);
        assert!(vm::retire_ended(&t.app).await, "{status}: no retry");
        assert!(vm::retire_ended(&t.app).await);
        assert_eq!(forced(&t), 1, "{status}: asked once");
        assert!(gh_note(&t, "seed-a").unwrap().starts_with("kiln could not force-cancel run 9001"));
    }
}

#[tokio::test]
async fn gitlab_and_gitea_vms_are_never_force_cancelled() {
    let t = Trio::new("mixed-reclaim-others", 99, |_| {}).await;
    gt_runner(&t.gt, true);
    gl_runner(&t.gl, "runner_jobs_running.json");
    for (id, repo, rid) in [("seed-gt", GT_REPO, 52), ("seed-gl", GL_REPO, 79)] {
        seed(&t.app, id, repo, "lost", rid, 1, 64);
        let mut vms = t.app.vms.lock().unwrap();
        let v = vms.iter_mut().find(|v| v.id == id).unwrap();
        v.ended = Some(now());
        v.busy_since = Some(5);
        v.job_url = Some("https://github.com/acme/demo/actions/runs/9001/job/7001".into());
    }
    vm::retire_ended(&t.app).await;
    for m in [&t.gh, &t.gt, &t.gl] {
        assert!(!m.requests().iter().any(|r| r.contains("force-cancel")), "{:?}", m.requests());
    }
    assert!(t.gh.requests().is_empty(), "{:?}", t.gh.requests());
}
