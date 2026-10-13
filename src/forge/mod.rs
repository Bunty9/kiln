//! Forge identity: which forge a repo lives on, its canonical key, and the `forges[]` config.
//! A repo is `(forge id, path)`. The key is bare `owner/name` on GitHub (every existing key,
//! `Vm.repo` value and cache file stays valid), else `forge-id:path`.

#![allow(dead_code)] // the call sites arrive with the later forge tasks

pub mod console;
pub mod gitea;
pub mod github;
pub mod gitlab;
pub mod net;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, RwLock};

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    GitHub,
    Gitea,
    GitLab,
}

/// What triggered a run, normalised across forges.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default, Debug)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Push,
    PullRequest,
    Tag,
    Release,
    Manual,
    Schedule,
    #[default]
    Other,
}

/// A job's result, normalised across forges. `as_str` is what the runner console prints, so
/// persisted history, notifications and telemetry keep their strings.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    Succeeded,
    SucceededWithIssues,
    Failed,
    Abandoned,
    Canceled,
    Skipped,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "Succeeded",
            Self::SucceededWithIssues => "SucceededWithIssues",
            Self::Failed => "Failed",
            Self::Abandoned => "Abandoned",
            Self::Canceled => "Canceled",
            Self::Skipped => "Skipped",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        use Outcome::*;
        [Succeeded, SucceededWithIssues, Failed, Abandoned, Canceled, Skipped].into_iter().find(|o| o.as_str() == s)
    }
}

/// Same-origin links a forge builds for a run; absent ones stay `None`.
#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Eq, Debug)]
pub struct Links {
    pub run: Option<String>,
    pub job: Option<String>,
    pub commit: Option<String>,
    pub pr: Option<String>,
    pub branch: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Credential {
    File,
    Env,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Public,
    Internal,
}

/// One `forges[]` entry. Optional fields stay `None` when absent so a save writes back what was read.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ForgeCfg {
    pub id: ForgeId,
    pub kind: Kind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<Credential>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<Network>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repos: Vec<String>,
    /// Keys this version does not know (a newer kiln's), kept so a rollback still starts and a
    /// save does not drop them. `unknown_keys` is how a dashboard write is held to typo protection.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Forge entry keys in `new` that this version does not know and `old` (the stored config) does
/// not already carry: a typo in a write. Loading never refuses them.
pub fn unknown_keys(old: &[ForgeCfg], new: &[ForgeCfg]) -> Vec<String> {
    let mut out = vec![];
    for f in new {
        let had = old.iter().find(|o| o.id == f.id);
        out.extend(f.extra.keys().filter(|k| !had.is_some_and(|o| o.extra.contains_key(*k))).map(|k| format!("{}.{k}", f.id.as_str())));
    }
    out
}

/// `[a-z][a-z0-9-]{0,23}`; part of cache filenames, so effectively immutable.
#[derive(Serialize, Clone, PartialEq, Eq, Hash, Debug)]
pub struct ForgeId(String);

impl ForgeId {
    pub fn new(s: &str) -> Result<Self> {
        let b = s.as_bytes();
        if b.is_empty()
            || b.len() > 24
            || !b[0].is_ascii_lowercase()
            || !b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        {
            bail!("forge id must match [a-z][a-z0-9-]{{0,23}}: {s:?}");
        }
        Ok(Self(s.into()))
    }
    pub fn github() -> Self {
        Self("github".into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ForgeId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::new(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RepoRef {
    pub forge: ForgeId,
    pub path: String,
}

impl RepoRef {
    /// A canonical key: bare `owner/name` (GitHub) or `forge-id:path`. `github:x/y` is refused
    /// (not canonical), as is any path segment outside `[A-Za-z0-9._-]` or a dot segment.
    /// Segment-count limits are per kind, see `check_kind`.
    pub fn parse(s: &str) -> Result<Self> {
        let (forge, path) = match s.split_once(':') {
            None => (ForgeId::github(), s),
            Some((f, p)) => {
                let f = ForgeId::new(f)?;
                if f.as_str() == "github" {
                    bail!("{s:?}: GitHub repos are written owner/name, without a forge prefix");
                }
                (f, p)
            }
        };
        if path.is_empty()
            || path.split('/').any(|p| {
                p.is_empty()
                    || p == "."
                    || p == ".."
                    || p.ends_with(".git")
                    || !p.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
            })
        {
            bail!("repo path must be plain segments of [A-Za-z0-9._-] joined by /: {s:?}");
        }
        Ok(Self { forge, path: path.into() })
    }

    /// Per-kind path shape: GitHub and Gitea exactly owner/name, GitLab 2..=20 segments.
    pub fn check_kind(&self, kind: Kind) -> Result<()> {
        let n = self.path.split('/').count();
        let ok = match kind {
            Kind::GitHub | Kind::Gitea => n == 2,
            Kind::GitLab => (2..=20).contains(&n),
        };
        if !ok {
            bail!("{}: path {:?} has the wrong number of segments for this forge kind", self.forge.as_str(), self.path);
        }
        Ok(())
    }

    pub fn key(&self) -> String {
        if self.forge.as_str() == "github" { self.path.clone() } else { format!("{}:{}", self.forge.as_str(), self.path) }
    }

    pub fn eq_key(&self, k: &str) -> bool {
        self.key().eq_ignore_ascii_case(k)
    }

    /// Filename stem of the repo's cache disk. GitHub keeps today's name; others are
    /// `{forge}~{path}` with `/` as `%2F`, and a long one is cut to 150 bytes plus `~` and a
    /// SHA-256 prefix. A GitHub stem has no `~`, a short other one has exactly one, a cut one two.
    pub fn cache_stem(&self) -> String {
        if self.forge.as_str() == "github" {
            return self.path.to_ascii_lowercase().replace('/', "__");
        }
        let s = format!("{}~{}", self.forge.as_str(), self.path).to_ascii_lowercase().replace('%', "%25").replace('/', "%2F");
        if s.len() <= 200 {
            return s;
        }
        let h: String =
            ring::digest::digest(&ring::digest::SHA256, s.as_bytes()).as_ref()[..8].iter().map(|b| format!("{b:02x}")).collect();
        format!("{}~{h}", &s[..150])
    }
}

/// The effective forge list: an absent `forges` is just GitHub carrying the top-level `repos`.
/// ponytail: the synthesised entry is for readers of the list; top-level `repos` stays the GitHub source of truth.
pub fn effective(forges: &Option<Vec<ForgeCfg>>, repos: &[String]) -> Vec<ForgeCfg> {
    match forges {
        Some(f) => f.clone(),
        None => {
            vec![ForgeCfg {
                id: ForgeId::github(),
                kind: Kind::GitHub,
                url: None,
                credential: None,
                network: None,
                repos: repos.to_vec(),
                extra: Default::default(),
            }]
        }
    }
}

/// Checks `forges[]` against the top-level GitHub `repos`.
pub fn validate(forges: &Option<Vec<ForgeCfg>>, repos: &[String]) -> Result<()> {
    let Some(list) = forges else { return Ok(()) };
    let mut keys: Vec<RepoRef> = vec![];
    let mut has_github = false;
    for (i, f) in list.iter().enumerate() {
        if list[..i].iter().any(|p| p.id == f.id) {
            bail!("forge id {:?} listed twice", f.id.as_str());
        }
        if (f.kind == Kind::GitHub) != (f.id.as_str() == "github") {
            bail!("forge id \"github\" is reserved for kind github (and the only id it may have)");
        }
        if f.kind == Kind::GitHub {
            has_github = true;
            if f.url.is_some() || !f.repos.is_empty() {
                bail!("the github forge takes no url or repos here; GitHub repos stay in the top-level repos");
            }
        } else {
            match f.url.as_deref() {
                Some(u) => {
                    net::check_forge_url(u, f.network.unwrap_or(Network::Public))
                        .map_err(|e| anyhow::anyhow!("forge {:?}: {e:#}", f.id.as_str()))?;
                }
                None => bail!("forge {:?} needs an http(s) url", f.id.as_str()),
            }
            for r in &f.repos {
                let rr = RepoRef::parse(&format!("{}:{r}", f.id.as_str()))?;
                rr.check_kind(f.kind)?;
                keys.push(rr);
            }
        }
    }
    if !has_github && !repos.is_empty() {
        bail!(
            "forges has no github entry but top-level repos is not empty; add {{\"id\":\"github\",\"kind\":\"github\"}} or move the repos"
        );
    }
    for r in repos {
        keys.push(RepoRef::parse(r)?);
    }
    for (i, k) in keys.iter().enumerate() {
        if keys[..i].iter().any(|p| p.eq_key(&k.key())) {
            bail!("repo listed twice (names are case-insensitive): {:?}", k.key());
        }
    }
    Ok(())
}

/// The job a runner picked up, as the forge lists it.
#[derive(Clone, PartialEq, Debug)]
pub struct JobInfo {
    /// The forge's job id (GitHub: the numeric id, as text). A VM binds to the first one it sees.
    pub id: String,
    pub url: String,
    pub queued_at: u64,
    /// From a fork pull request, which kiln refuses to run.
    pub fork: bool,
    pub run: crate::vm::Run,
}

/// A job to ask the forge about.
pub struct JobRef {
    pub repo: RepoRef,
    pub id: String,
}

/// A registered runner: its id and the only thing the guest gets (`kiln.<k>=<v>` lines).
pub struct RunnerReg {
    pub runner_id: u64,
    pub guest_secret: String,
}

/// Why a runner is being retired; `note` is what the dashboard shows on the VM.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reason {
    Surplus,
    Warm,
    StalePolicy,
    /// The VM ended without ever running a job.
    Unused,
}

impl Reason {
    pub fn note(self) -> &'static str {
        match self {
            Self::Surplus => "no job left for this runner",
            Self::Warm => "recycled warm VM",
            Self::StalePolicy => "recycled: security settings changed",
            Self::Unused => "",
        }
    }
}

/// What deregistering a runner came to.
#[derive(Debug)]
pub enum Dereg {
    /// The runner is gone (or already was): no job can reach it.
    Gone,
    /// The forge refuses: the runner has a job.
    Busy,
    Err(anyhow::Error),
}

/// One poll's view of a repo's queue.
#[derive(Default, Debug)]
pub struct Demand {
    /// Queued jobs of ours per VM size.
    pub by_size: HashMap<u32, usize>,
    /// VM id -> the job our runner picked up.
    pub claimed: HashMap<String, JobInfo>,
    /// Queued fork jobs kiln refuses (never counted in `by_size`).
    pub refused_forks: usize,
    /// Gitea: a queued (not `waiting`) fork job with our labels exists. A fork job runs on any
    /// matching runner, warm ones included, so kiln launches nothing for the repo meanwhile.
    pub fork_queued: bool,
}

/// What a forge can do from the dashboard; it hides the controls whose flag is false.
#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
pub struct Caps {
    pub rerun: bool,
    pub rerun_failed: bool,
    pub cancel: bool,
    pub dispatch: bool,
    pub workflows: bool,
    pub live_steps: bool,
}

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum RunStatus {
    Queued,
    Running,
    Completed,
}

#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct RunSummary {
    pub id: u64,
    pub name: String,
    pub title: String,
    pub number: u64,
    pub attempt: u64,
    pub status: RunStatus,
    pub outcome: Option<Outcome>,
    pub event: EventKind,
    pub branch: String,
    pub sha: String,
    pub actor: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub links: Links,
}

#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct StepSummary {
    pub number: u64,
    pub name: String,
    pub status: RunStatus,
    pub outcome: Option<Outcome>,
}

#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct JobSummary {
    pub id: u64,
    pub name: String,
    pub status: RunStatus,
    pub outcome: Option<Outcome>,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub runner: Option<String>,
    pub steps: Vec<StepSummary>,
    pub links: Links,
}

#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct RunPage {
    pub runs: Vec<RunSummary>,
    /// The `page` to ask for next, if there is one.
    pub next: Option<u32>,
}

#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct RunDetail {
    #[serde(flatten)]
    pub run: RunSummary,
    pub jobs: Vec<JobSummary>,
}

#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct LogPage {
    pub text: String,
    /// The byte offset to pass as `from` for the rest.
    pub next: usize,
    pub complete: bool,
    /// Set on the last page we can give when the log is longer than kiln reads (16 MiB).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

/// Most log bytes returned per request (the caller continues from `next`), and most read from a forge.
pub const LOG_CAP: usize = 1 << 20;
pub const LOG_DOWNLOAD_CAP: usize = 16 << 20;

impl LogPage {
    /// The page of `body` from byte `from`, never cutting a UTF-8 sequence in half. `truncated`:
    /// the download hit `LOG_DOWNLOAD_CAP`, so there is more than `body`.
    pub fn slice(body: &[u8], from: usize, truncated: bool) -> Self {
        let start = from.min(body.len());
        let mut end = (start + LOG_CAP).min(body.len());
        while end > start && end < body.len() && body[end] & 0xC0 == 0x80 {
            end -= 1;
        }
        Self {
            text: String::from_utf8_lossy(&body[start..end]).into_owned(),
            next: end,
            complete: end == body.len() && !truncated,
            truncated: truncated && end == body.len(),
        }
    }
}

#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct Workflow {
    pub id: u64,
    pub name: String,
    pub file: String,
}

/// Filters of a run listing; `status` is kiln's (queued|running|completed).
#[derive(Default, Debug)]
pub struct RunQuery {
    pub status: Option<String>,
    pub branch: Option<String>,
    pub page: u32,
}

/// `gl` -> `KILN_FORGE_GL_TOKEN`: the environment variable of a forge's `env` credential.
pub fn env_name(id: &ForgeId) -> String {
    format!("KILN_FORGE_{}_TOKEN", id.as_str().to_ascii_uppercase().replace('-', "_"))
}

/// Where a forge's `file` credential lives.
pub fn token_path(data: &std::path::Path, id: &ForgeId) -> std::path::PathBuf {
    data.join("forges").join(format!("{}.token", id.as_str()))
}

/// The raw `file` credential; a missing file is no credential, an unreadable one is logged (never its content).
pub fn read_token_file(data: &std::path::Path, id: &ForgeId) -> Option<String> {
    match std::fs::read_to_string(token_path(data, id)) {
        Ok(t) => Some(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            tracing::warn!("forge {}: reading the token file: {e}", id.as_str());
            None
        }
    }
}

/// What a Gitea call says until its task lands (GT-2/GT-3 and the dashboard actions).
const NOT_YET: &str = "not implemented for Gitea yet";

/// A configured forge.
pub enum Forge {
    GitHub(github::GitHub),
    Gitea(Box<gitea::Gitea>),
    GitLab(Box<gitlab::GitLab>),
}

impl Forge {
    pub fn new(cfg: &ForgeCfg, gh: &Arc<crate::github::Gh>, data: &std::path::Path) -> Result<Self> {
        match cfg.kind {
            Kind::GitHub => Ok(Self::GitHub(github::GitHub { gh: gh.clone() })),
            Kind::GitLab => Ok(Self::GitLab(Box::new(gitlab::GitLab::new(cfg, data)?))),
            Kind::Gitea => Ok(Self::Gitea(Box::new(gitea::Gitea::new(cfg, data)?))),
        }
    }
    pub fn caps(&self) -> Caps {
        match self {
            Self::GitHub(_) => github::CAPS,
            Self::GitLab(_) => gitlab::CAPS,
            Self::Gitea(g) => g.caps(),
        }
    }
    /// Where the forge's own web UI lives.
    pub fn web_url(&self) -> &str {
        match self {
            Self::GitHub(_) => "https://github.com",
            Self::GitLab(g) => g.web_url(),
            Self::Gitea(g) => g.web_url(),
        }
    }
    /// Which credential is in use and when it expires; never the credential.
    pub fn auth(&self) -> Value {
        match self {
            Self::GitHub(g) => g.auth(),
            Self::GitLab(g) => g.auth(),
            Self::Gitea(g) => g.auth(),
        }
    }
    pub async fn runs(&self, repo: &RepoRef, q: &RunQuery) -> Result<RunPage> {
        match self {
            Self::GitHub(g) => g.runs(repo, q).await,
            Self::GitLab(g) => g.runs(repo, q).await,
            Self::Gitea(_) => bail!(NOT_YET),
        }
    }
    pub async fn run(&self, repo: &RepoRef, id: u64) -> Result<RunDetail> {
        match self {
            Self::GitHub(g) => g.run(repo, id).await,
            Self::GitLab(g) => g.run(repo, id).await,
            Self::Gitea(_) => bail!(NOT_YET),
        }
    }
    pub async fn job_log(&self, repo: &RepoRef, id: u64, from: usize) -> Result<LogPage> {
        match self {
            Self::GitHub(g) => g.job_log(repo, id, from).await,
            Self::GitLab(g) => g.job_log(repo, id, from).await,
            Self::Gitea(_) => bail!(NOT_YET),
        }
    }
    pub async fn workflows(&self, repo: &RepoRef) -> Result<Vec<Workflow>> {
        match self {
            Self::GitHub(g) => g.workflows(repo).await,
            Self::GitLab(g) => g.workflows(repo).await,
            Self::Gitea(_) => bail!(NOT_YET),
        }
    }
    pub async fn rerun(&self, repo: &RepoRef, id: u64, failed_only: bool) -> Result<()> {
        match self {
            Self::GitHub(g) => g.rerun(repo, id, failed_only).await,
            Self::GitLab(g) => g.rerun(repo, id, failed_only).await,
            Self::Gitea(_) => bail!(NOT_YET),
        }
    }
    pub async fn cancel(&self, repo: &RepoRef, id: u64) -> Result<()> {
        match self {
            Self::GitHub(g) => g.cancel(repo, id).await,
            Self::GitLab(g) => g.cancel(repo, id).await,
            Self::Gitea(_) => bail!(NOT_YET),
        }
    }
    pub async fn dispatch(&self, repo: &RepoRef, workflow: Option<&str>, git_ref: &str, inputs: &HashMap<String, String>) -> Result<()> {
        match self {
            Self::GitHub(g) => g.dispatch(repo, workflow, git_ref, inputs).await,
            Self::GitLab(g) => g.dispatch(repo, workflow, git_ref, inputs).await,
            Self::Gitea(_) => bail!(NOT_YET),
        }
    }
    pub fn id(&self) -> ForgeId {
        match self {
            Self::GitHub(_) => ForgeId::github(),
            Self::GitLab(g) => g.id(),
            Self::Gitea(g) => g.id(),
        }
    }
    pub fn kind(&self) -> Kind {
        match self {
            Self::GitHub(_) => Kind::GitHub,
            Self::GitLab(_) => Kind::GitLab,
            Self::Gitea(_) => Kind::Gitea,
        }
    }
    pub fn has_credential(&self) -> bool {
        match self {
            Self::GitHub(g) => g.gh.has_token(),
            Self::GitLab(g) => g.has_credential(),
            Self::Gitea(g) => g.has_credential(),
        }
    }
    /// What keeps this forge from polling (no credential, rate limited), if anything.
    pub fn health(&self) -> Option<String> {
        match self {
            Self::GitHub(g) => g.health(),
            Self::GitLab(g) => g.health(),
            Self::Gitea(g) => g.health(),
        }
    }
    /// Re-reads a file credential from the data dir (`<data>/forges/<id>.token`).
    pub fn load_token(&self, data: &std::path::Path) {
        match self {
            Self::GitHub(_) => {}
            Self::Gitea(g) => g.load_token(data),
            Self::GitLab(g) => g.load_token(data),
        }
    }
    pub async fn refresh(&self) {
        match self {
            Self::GitHub(g) => g.gh.refresh_latest().await,
            Self::GitLab(_) => {}
            Self::Gitea(g) => g.refresh().await,
        }
    }
    pub fn repo_paused(&self, repo: &RepoRef) -> Option<String> {
        match self {
            Self::GitHub(g) => g.gh.repo_paused(&repo.path),
            Self::GitLab(_) => None,
            Self::Gitea(_) => None,
        }
    }
    /// (remaining, limit, reset) of the tightest rate limit, if any is known.
    pub fn rate(&self) -> Option<(u64, u64, u64)> {
        match self {
            Self::GitHub(g) => g.gh.rate(),
            Self::GitLab(_) => None,
            Self::Gitea(_) => None,
        }
    }
    pub fn repos(&self, cfg: &ForgeCfg) -> Vec<RepoRef> {
        match self {
            Self::GitHub(g) => g.repos(cfg),
            Self::GitLab(g) => g.repos(cfg),
            Self::Gitea(g) => g.repos(cfg),
        }
    }
    pub async fn demand(&self, repo: &RepoRef, label: &str, default_cpus: u32) -> Result<Demand> {
        match self {
            Self::GitHub(g) => g.demand(repo, label, default_cpus).await,
            Self::GitLab(g) => g.demand(repo, label, default_cpus).await,
            Self::Gitea(g) => g.demand(repo, label, default_cpus).await,
        }
    }
    /// Registers a single-use runner named `name` for `repo`. A refusal is a `github::MintError`.
    pub async fn register(&self, repo: &RepoRef, name: &str, labels: &[String]) -> Result<RunnerReg> {
        match self {
            Self::GitHub(g) => g.register(repo, name, labels).await,
            Self::GitLab(g) => g.register(repo, name, labels).await,
            Self::Gitea(g) => g.register(repo, name, labels).await,
        }
    }
    pub async fn deregister(&self, repo: &RepoRef, runner_id: u64, reason: Reason) -> Dereg {
        match self {
            Self::GitHub(g) => g.deregister(repo, runner_id).await,
            Self::GitLab(g) => g.deregister(repo, runner_id, reason).await,
            Self::Gitea(g) => g.deregister(repo, runner_id).await,
        }
    }
    /// (event, head branch, default branch, job conclusion) of the job that ran.
    pub async fn cache_trust(&self, job: &JobRef, writers: &[String]) -> Result<(String, String, String, String)> {
        match self {
            Self::GitHub(g) => g.cache_trust(job, writers).await,
            Self::GitLab(g) => g.cache_trust(job, writers).await,
            Self::Gitea(_) => bail!("Gitea cache trust is not implemented yet"),
        }
    }
    pub async fn sweep(&self, repo: &RepoRef) -> Result<usize> {
        match self {
            Self::GitHub(g) => g.gh.sweep_runners(&repo.path).await,
            Self::GitLab(g) => g.sweep(repo).await,
            Self::Gitea(g) => g.sweep(repo).await,
        }
    }
    /// Whether jobs wait for a host verdict (section 4 of the forge design). GitHub's path has no
    /// gate: `kiln-prejob.sh` and the JIT config bind it.
    pub fn gated(&self) -> bool {
        match self {
            Self::GitHub(_) => false,
            Self::GitLab(_) => true,
            Self::Gitea(_) => true,
        }
    }
    /// Stops the runner taking a second job and lists the jobs it holds. `None`: this forge needs
    /// no pause (Gitea refuses a second task server-side; GitHub is not gated). `Some(ids)`:
    /// the gate accepts exactly the console's job id.
    pub async fn pause(&self, _repo: &RepoRef, runner_id: u64) -> Result<Option<Vec<String>>> {
        match self {
            Self::GitHub(_) => Ok(None),
            Self::GitLab(g) => g.pause(runner_id).await.map(Some),
            Self::Gitea(_) => Ok(None),
        }
    }
    /// What the API says about `job_id`, for `decide`. Never a `CI_*` value or anything the guest sent.
    pub async fn verdict_facts(&self, repo: &RepoRef, job_id: &str) -> Result<VerdictFacts> {
        match self {
            Self::GitHub(_) => bail!("GitHub has no verdict gate"),
            Self::GitLab(g) => g.verdict_facts(repo, job_id).await,
            Self::Gitea(_) => bail!("Gitea verdict facts are not implemented yet"),
        }
    }
}

/// The host's call on a gated job (4 of the forge design).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Call {
    Ok,
    /// Run, but without the repo cache (tags and releases).
    Cold,
    Refuse,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Verdict {
    pub v: Call,
    pub why: String,
}

impl Verdict {
    fn refuse(why: impl Into<String>) -> Self {
        Self { v: Call::Refuse, why: why.into() }
    }
    /// The serial line the guest's `verdict_reader` accepts.
    pub fn line(&self, job_id: &str) -> String {
        let v = match self.v {
            Call::Ok => "ok",
            Call::Cold => "cold",
            Call::Refuse => "refuse",
        };
        format!("kiln.verdict={v} {job_id}\n")
    }
}

/// API facts about one job; each forge fills them in from API data only.
/// Fail closed: a forge that cannot tell sets the refusing flag.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct VerdictFacts {
    /// The job belongs to the repo this runner serves.
    pub ours: bool,
    pub fork: bool,
    /// Gitea `workflow_run`: runs with the base repo's trust on attacker-chosen input.
    pub workflow_run: bool,
    /// The pipeline source or event is none the forge knows.
    pub unknown_source: bool,
    /// Tag or release.
    pub tag: bool,
}

/// Pure: facts to verdict. Anything but a plain, known, same-repo, non-fork job refuses or goes cold.
pub fn decide(f: &VerdictFacts) -> Verdict {
    if !f.ours {
        Verdict::refuse("job is not for this repo")
    } else if f.workflow_run {
        Verdict::refuse("workflow_run is never run")
    } else if f.unknown_source {
        Verdict::refuse("unknown job source")
    } else if f.fork {
        Verdict::refuse("pull request from a fork")
    } else if f.tag {
        Verdict { v: Call::Cold, why: "tag or release".into() }
    } else {
        Verdict { v: Call::Ok, why: String::new() }
    }
}

/// How long the host may spend on pause and API reads before it refuses (the guest waits 60 s).
pub const GATE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The per-job verdict engine: `job_id` is the console's, `pause` and `facts` are the forge's
/// calls (futures, so `facts` only runs after `pause`). Refuses on a bad id, a pause or API error,
/// a runner holding any job but `job_id`, and on `limit`. Never reads anything from the guest.
pub async fn gate(
    job_id: &str,
    limit: std::time::Duration,
    pause: impl Future<Output = Result<Option<Vec<String>>>>,
    facts: impl Future<Output = Result<VerdictFacts>>,
) -> Verdict {
    let run = async {
        // The id goes onto the serial line and into API paths: digits only.
        if job_id.is_empty() || job_id.len() > 20 || !job_id.bytes().all(|b| b.is_ascii_digit()) {
            return Verdict::refuse("console job id is not numeric");
        }
        match pause.await {
            Err(e) => return Verdict::refuse(format!("pause failed: {e:#}")),
            Ok(Some(held)) if held.len() != 1 || held[0] != job_id => {
                return Verdict::refuse(format!("runner holds {} job(s), not only the one it started", held.len()));
            }
            Ok(_) => {}
        }
        match facts.await {
            Ok(f) => decide(&f),
            Err(e) => Verdict::refuse(format!("API error: {e:#}")),
        }
    };
    tokio::time::timeout(limit, run).await.unwrap_or_else(|_| Verdict::refuse("verdict timed out"))
}

/// The live forges. A settings save keeps the same `Arc<Forge>` for every forge whose config did
/// not change, so client state (ETags, rate limits, App tokens) survives.
#[derive(Default)]
pub struct Forges(RwLock<HashMap<ForgeId, (ForgeCfg, Arc<Forge>)>>);

impl Forges {
    /// Match the registry to `list`. A forge that cannot be built (bad config) is logged and left out.
    pub fn sync(&self, list: &[ForgeCfg], gh: &Arc<crate::github::Gh>, data: &std::path::Path) {
        let mut m = self.0.write().unwrap();
        m.retain(|id, _| list.iter().any(|c| &c.id == id));
        for c in list {
            // The repo list is read per tick; changing it needs no new client.
            let key = ForgeCfg { repos: vec![], ..c.clone() };
            if m.get(&c.id).is_some_and(|(k, _)| *k == key) {
                continue;
            }
            m.remove(&c.id);
            match Forge::new(c, gh, data) {
                Ok(f) => {
                    m.insert(c.id.clone(), (key, Arc::new(f)));
                }
                Err(e) => tracing::warn!("{e:#}"),
            }
        }
    }

    /// Reads every forge's file credential from `data`; call after `sync` and when a token is replaced.
    pub fn load_tokens(&self, data: &std::path::Path) {
        for f in self.all() {
            f.load_token(data);
        }
    }

    pub fn get(&self, id: &ForgeId) -> Option<Arc<Forge>> {
        self.0.read().unwrap().get(id).map(|(_, f)| f.clone())
    }

    /// All forges, ordered by id.
    pub fn all(&self) -> Vec<Arc<Forge>> {
        let m = self.0.read().unwrap();
        let mut v: Vec<_> = m.iter().collect();
        v.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
        v.into_iter().map(|(_, (_, f))| f.clone()).collect()
    }
}

/// Allowed `<label>-<N>cpu` sizes.
pub const SIZES: [u32; 4] = [2, 4, 8, 16];

/// RAM for a size label; the default size uses the configured memory instead.
pub fn size_mem_mb(cpus: u32) -> u32 {
    (cpus * 2048).min(24576)
}

/// The configured label as runners of this architecture advertise it: arm64 hosts
/// add `-arm64`, so a job written for x64 (`<label>`) never lands on an arm64 VM.
pub fn arch_label(label: &str, arm64: bool) -> String {
    if arm64 { format!("{label}-arm64") } else { label.to_string() }
}

/// Does a runner (its `labels` from the runners API) have this host's architecture label?
pub fn same_arch(labels: &Value, arm64: bool) -> bool {
    let arch = if arm64 { "arm64" } else { "x64" };
    labels.as_array().into_iter().flatten().any(|l| l["name"].as_str().is_some_and(|n| n.eq_ignore_ascii_case(arch)))
}

/// The VM size a job asks for, if it is ours: every label must be implicit
/// (GitHub adds `self-hosted`, `linux` and the architecture, `x64` or `ARM64`, to
/// self-hosted runners) or one of ours, and exactly one of ours must be present.
/// `<label>` is the default size, `<label>-Ncpu` size N (`<label>-arm64`... on an
/// arm64 host). A plain `self-hosted` job is someone else's, and so is a job for
/// the other architecture.
pub fn job_size(job_labels: &Value, label: &str, default_cpus: u32, arm64: bool) -> Option<u32> {
    let label = arch_label(label, arm64).to_ascii_lowercase();
    let arch = if arm64 { "arm64" } else { "x64" };
    let mut size = None;
    let mut found = 0;
    for l in job_labels.as_array()? {
        let l = l.as_str()?.to_ascii_lowercase();
        if ["self-hosted", "linux", arch].contains(&l.as_str()) {
            continue;
        }
        found += 1;
        size = Some(if l == label {
            default_cpus
        } else {
            // Round-trip so `kiln-04cpu` (which no runner label matches) is not ours.
            let digits = l.strip_prefix(&label)?.strip_prefix('-')?.strip_suffix("cpu")?;
            digits.parse::<u32>().ok().filter(|n| SIZES.contains(n) && n.to_string() == digits)?
        });
    }
    if found == 1 { size } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forge_test_mock::FakeForge;
    use serde_json::json;
    use std::time::Duration;

    const LIMIT: Duration = Duration::from_secs(5);

    fn facts(f: impl FnOnce(&mut VerdictFacts)) -> VerdictFacts {
        let mut v = VerdictFacts { ours: true, ..Default::default() };
        f(&mut v);
        v
    }

    #[test]
    fn decide_table() {
        let t = |f: VerdictFacts| decide(&f).v;
        assert_eq!(t(facts(|_| {})), Call::Ok);
        assert_eq!(t(facts(|f| f.tag = true)), Call::Cold);
        assert_eq!(t(facts(|f| f.fork = true)), Call::Refuse);
        assert_eq!(t(facts(|f| f.workflow_run = true)), Call::Refuse);
        assert_eq!(t(facts(|f| f.unknown_source = true)), Call::Refuse);
        assert_eq!(t(VerdictFacts::default()), Call::Refuse, "a job not known to be ours");
        // Refusal outranks cold.
        assert_eq!(t(facts(|f| (f.tag, f.fork) = (true, true))), Call::Refuse);
        assert_eq!(decide(&facts(|_| {})).line("42"), "kiln.verdict=ok 42\n");
    }

    #[tokio::test]
    async fn gate_ok_cold_refuse() {
        let mut f = FakeForge::ok("7");
        assert_eq!(f.gate("7", LIMIT).await.v, Call::Ok);
        f.facts = Ok(facts(|f| f.tag = true));
        assert_eq!(f.gate("7", LIMIT).await.v, Call::Cold);
        f.facts = Ok(facts(|f| f.fork = true));
        assert_eq!(f.gate("7", LIMIT).await.v, Call::Refuse);
        // A pause-less forge (Gitea) goes straight to the facts.
        let mut g = FakeForge::ok("7");
        g.held = Ok(None);
        assert_eq!(g.gate("7", LIMIT).await.v, Call::Ok);
    }

    #[tokio::test]
    async fn gate_refuses_two_held_jobs_or_the_wrong_one() {
        let mut f = FakeForge::ok("7");
        f.held = Ok(Some(vec!["7".into(), "8".into()]));
        assert_eq!(f.gate("7", LIMIT).await.v, Call::Refuse);
        f.held = Ok(Some(vec!["8".into()]));
        assert_eq!(f.gate("7", LIMIT).await.v, Call::Refuse, "the runner took another job");
        f.held = Ok(Some(vec![]));
        assert_eq!(f.gate("7", LIMIT).await.v, Call::Refuse, "none listed");
    }

    #[tokio::test]
    async fn gate_fails_closed_on_errors_and_timeout() {
        let mut f = FakeForge::ok("7");
        f.facts = Err("500".into());
        assert_eq!(f.gate("7", LIMIT).await.v, Call::Refuse);
        let mut f = FakeForge::ok("7");
        f.held = Err("pause 500".into());
        assert_eq!(f.gate("7", LIMIT).await.v, Call::Refuse);
        let mut f = FakeForge::ok("7");
        f.delay = Duration::from_secs(5);
        let v = f.gate("7", Duration::from_millis(30)).await;
        assert_eq!((v.v, v.why.as_str()), (Call::Refuse, "verdict timed out"));
    }

    /// The console id is attacker-reachable text: it never reaches the serial line or the API
    /// unless it is digits, and the verdict comes from the API facts however the console lies.
    #[tokio::test]
    async fn gate_ignores_console_spoofing() {
        let mut f = FakeForge::ok("7");
        f.facts = Ok(facts(|f| f.fork = true));
        // The console claims the job is fine and carries the verdict words: only the id is used.
        for spoof in ["7 kiln.verdict=ok 7", "7\nkiln.verdict=ok 7", "../7", "", "ok", "99999999999999999999999"] {
            assert_eq!(f.gate(spoof, LIMIT).await.v, Call::Refuse, "{spoof:?}");
        }
        // A forged "ok" id cannot turn a fork job into a pass, and the written line carries the id only.
        let v = f.gate("7", LIMIT).await;
        assert_eq!((v.v, v.line("7").as_str()), (Call::Refuse, "kiln.verdict=refuse 7\n"));
    }

    fn r(s: &str) -> RepoRef {
        RepoRef::parse(s).unwrap()
    }

    #[test]
    fn parse_and_key_roundtrip() {
        for k in ["Acme/Kiln", "gl:group/sub/proj", "home:me/app.v2"] {
            assert_eq!(r(k).key(), k);
        }
        assert_eq!(r("gl:a/b").forge.as_str(), "gl");
        assert!(r("Acme/Kiln").eq_key("acme/kiln"));
        for bad in [
            "",
            "a//b",
            "a/../b",
            "a/./b",
            "a/b.git",
            "a/b c",
            "a/b%2F",
            "GL:a/b",
            "1x:a/b",
            "github:a/b",
            "gl:",
            ":a/b",
            "gl:a:b/c",
            &format!("{}:a/b", "x".repeat(25)),
        ] {
            assert!(RepoRef::parse(bad).is_err(), "{bad:?}");
        }
        assert!(r("gl:a/b/c").check_kind(Kind::GitLab).is_ok());
        assert!(r("gl:a/b/c").check_kind(Kind::Gitea).is_err());
        assert!(r("a/b").check_kind(Kind::GitHub).is_ok());
        assert!(r("gl:a").check_kind(Kind::GitLab).is_err());
        let deep = vec!["s"; 21].join("/");
        assert!(r(&format!("gl:{deep}")).check_kind(Kind::GitLab).is_err());
    }

    #[test]
    fn outcome_strings() {
        for (o, s) in [
            (Outcome::Succeeded, "Succeeded"),
            (Outcome::Failed, "Failed"),
            (Outcome::Abandoned, "Abandoned"),
            (Outcome::Canceled, "Canceled"),
            (Outcome::Skipped, "Skipped"),
            (Outcome::SucceededWithIssues, "SucceededWithIssues"),
        ] {
            assert_eq!((o.as_str(), Outcome::parse(s)), (s, Some(o)));
        }
        assert_eq!(Outcome::parse("Cancelled"), None);
    }

    #[test]
    fn github_cache_stem_is_unchanged() {
        assert_eq!(r("Acme/Kiln").cache_stem(), "acme__kiln");
        assert_eq!(r("Acme/Kiln").cache_stem(), "Acme/Kiln".to_ascii_lowercase().replace('/', "__"));
    }

    #[test]
    fn cache_stem_escapes_and_is_injective() {
        assert_eq!(r("gl:Group/Sub/Proj").cache_stem(), "gl~group%2Fsub%2Fproj");
        let long = |c: &str| format!("gl:{}/p", c.repeat(250));
        let (a, b) = (r(&long("a")).cache_stem(), r(&long("b")).cache_stem());
        assert!(a.len() <= 167 && a.matches('~').count() == 2 && a != b);
        // same 150-byte prefix, different tail: the hash tells them apart
        let (c, d) = (r(&format!("gl:{}x/p", "a".repeat(250))).cache_stem(), r(&format!("gl:{}y/p", "a".repeat(250))).cache_stem());
        assert_ne!(c, d);
        let keys = [
            "a/b",
            "a_/b",
            "gl:a/b",
            "gh:a/b",
            "gl:a/b/c",
            "gl:a/b-c",
            "gl:a-b/c",
            "home:a/b",
            "gl:a/b.c",
            "gl:a/b_c",
            "gl:a_b/c",
            "gl:ab/c",
            "gl:a/bc",
            &long("a"),
            &long("b"),
        ];
        let mut stems: Vec<_> = keys.iter().map(|k| r(k).cache_stem()).collect();
        // ponytail: GitHub's own `a_/b` vs `a/_b` collision predates forges and its names must not change.
        stems.sort();
        stems.dedup();
        assert_eq!(stems.len(), keys.len());
        assert!(stems.iter().all(|s| !s.contains('/')));
    }

    fn cfg(j: &str) -> Result<Option<Vec<ForgeCfg>>> {
        Ok(serde_json::from_str(j)?)
    }

    #[test]
    fn absent_forges_is_github() {
        let e = effective(&None, &["a/b".into()]);
        assert_eq!((e.len(), e[0].id.as_str(), e[0].kind, e[0].repos.clone()), (1, "github", Kind::GitHub, vec!["a/b".to_string()]));
        assert!(validate(&None, &["a/b".into()]).is_ok());
    }

    #[test]
    fn forges_validation() {
        let gl = r#"{"id":"gl","kind":"gitlab","url":"https://gitlab.example.com","repos":["g/s/p"]}"#;
        let ok = |j: &str, top: &[&str]| validate(&cfg(j).unwrap(), &top.iter().map(|s| s.to_string()).collect::<Vec<_>>()).is_ok();
        assert!(ok(&format!("[{gl}]"), &[]));
        assert!(!ok(&format!("[{gl}]"), &["a/b"]), "forges without github plus top-level repos");
        assert!(ok(&format!(r#"[{{"id":"github","kind":"github"}},{gl}]"#), &["a/b"]));
        assert!(!ok(&format!("[{gl},{gl}]"), &[]), "duplicate id");
        assert!(!ok(r#"[{"id":"github","kind":"gitea","url":"https://x.example.org"}]"#, &[]), "reserved id");
        assert!(!ok(r#"[{"id":"gl","kind":"gitlab"}]"#, &[]), "needs url");
        assert!(!ok(r#"[{"id":"h","kind":"gitea","url":"https://x.example.org","repos":["a/b/c"]}]"#, &[]));
        assert!(
            !ok(r#"[{"id":"h","kind":"gitea","url":"https://x.example.org","repos":["A/b","a/B"]}]"#, &[]),
            "case-insensitive duplicate"
        );
        assert!(cfg(r#"[{"id":"GL","kind":"gitlab"}]"#).is_err());
        // M5: a newer kiln's extra field must not stop an older one from starting (rollback), and
        // survives a save; but a dashboard write may not introduce one (typo protection).
        let newer = cfg(r#"[{"id":"gl","kind":"gitlab","url":"https://x.example.org","tls_ca":"/x"}]"#).unwrap();
        assert_eq!(serde_json::to_value(&newer).unwrap()[0]["tls_ca"], "/x");
        assert!(validate(&newer, &[]).is_ok());
        assert!(unknown_keys(newer.as_deref().unwrap(), newer.as_deref().unwrap()).is_empty());
        let typo = cfg(r#"[{"id":"gl","kind":"gitlab","url":"https://x.example.org","urll":"x"}]"#).unwrap();
        assert_eq!(unknown_keys(newer.as_deref().unwrap(), typo.as_deref().unwrap()), ["gl.urll"]);
        assert_eq!(unknown_keys(&[], newer.as_deref().unwrap()), ["gl.tls_ca"]);
        // Still invalid is still refused.
        assert!(cfg(r#"[{"id":"gl","kind":"nope"}]"#).is_err());
    }

    fn label_matching() {
        let size = |v: Value| job_size(&v, "kiln", 4, false);
        assert_eq!(size(json!(["self-hosted", "kiln"])), Some(4));
        assert_eq!(size(json!(["kiln"])), Some(4));
        assert_eq!(size(json!(["Self-Hosted", "Linux", "KILN"])), Some(4));
        assert_eq!(size(json!(["self-hosted", "linux", "x64", "kiln-16cpu"])), Some(16));
        assert_eq!(size(json!(["kiln-8cpu"])), Some(8));
        assert_eq!(size(json!(["self-hosted", "Kiln-2CPU"])), Some(2));
        assert_eq!(size(json!(["kiln-4cpu"])), Some(4));
        assert_eq!(job_size(&json!(["kiln"]), "kiln", 6, false), Some(6));
        assert_eq!(size(json!(["ubuntu-latest"])), None);
        assert_eq!(size(json!(["self-hosted"])), None);
        assert_eq!(size(json!(["self-hosted", "linux"])), None);
        assert_eq!(size(json!(["self-hosted", "kiln", "gpu"])), None);
        assert_eq!(size(json!(["kiln", "kiln-8cpu"])), None);
        assert_eq!(size(json!(["kiln-8cpu", "kiln-8cpu"])), None);
        assert_eq!(size(json!(["kiln-3cpu"])), None);
        assert_eq!(size(json!(["kiln-04cpu"])), None);
        assert_eq!(size(json!(["kiln-32cpu"])), None);
        assert_eq!(size(json!(["kiln-"])), None);
        assert_eq!(size(json!(["kilnx-8cpu"])), None);
        assert_eq!(size(json!([])), None);
        assert_eq!(size(json!(null)), None);
        // An x64 host ignores arm64 jobs.
        assert_eq!(size(json!(["self-hosted", "kiln-arm64"])), None);
        assert_eq!(size(json!(["self-hosted", "kiln-arm64-8cpu"])), None);
        assert_eq!(size(json!(["self-hosted", "ARM64", "kiln"])), None);
    }

    #[test]
    fn arm64_label_matching() {
        let size = |v: Value| job_size(&v, "kiln", 4, true);
        assert_eq!(size(json!(["self-hosted", "kiln-arm64"])), Some(4));
        assert_eq!(size(json!(["self-hosted", "linux", "ARM64", "kiln-arm64"])), Some(4));
        assert_eq!(size(json!(["kiln-arm64-8cpu"])), Some(8));
        assert_eq!(size(json!(["self-hosted", "Kiln-ARM64-16CPU"])), Some(16));
        // x64 jobs never land on an arm64 host.
        assert_eq!(size(json!(["self-hosted", "kiln"])), None);
        assert_eq!(size(json!(["self-hosted", "kiln-8cpu"])), None);
        assert_eq!(size(json!(["self-hosted", "x64", "kiln-arm64"])), None);
        assert_eq!(size(json!(["kiln-arm64", "kiln-arm64-8cpu"])), None);
        assert_eq!(size(json!(["kiln-arm64-3cpu"])), None);
        assert_eq!(size(json!(["kiln-arm64-"])), None);
        assert_eq!(arch_label("kiln", true), "kiln-arm64");
        assert_eq!(arch_label("kiln", false), "kiln");
        let labels = |names: &[&str]| Value::from(names.iter().map(|n| json!({ "id": 1, "name": n })).collect::<Vec<_>>());
        assert!(same_arch(&labels(&["self-hosted", "Linux", "X64", "kiln"]), false));
        assert!(!same_arch(&labels(&["self-hosted", "Linux", "X64", "kiln"]), true), "an arm64 kiln leaves x64 runners alone");
        assert!(same_arch(&labels(&["self-hosted", "Linux", "ARM64", "kiln-arm64"]), true));
        assert!(!same_arch(&labels(&["self-hosted", "Linux", "ARM64", "kiln-arm64"]), false));
        assert!(!same_arch(&Value::Null, false));
    }

    #[test]
    fn size_memory() {
        assert_eq!(size_mem_mb(2), 4096);
        assert_eq!(size_mem_mb(8), 16384);
        assert_eq!(size_mem_mb(16), 24576);
    }
}
