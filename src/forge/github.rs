//! The GitHub forge: a thin face over `Gh` (which keeps the ETag cache, rate counters, App tokens).

use std::sync::Arc;

use super::{Demand, ForgeCfg, ForgeId, RepoRef};
use crate::github::Gh;
use anyhow::Result;

pub struct GitHub {
    /// Shared with `App.gh`, so code that has not moved to the registry yet sees the same client state.
    pub gh: Arc<Gh>,
}

impl GitHub {
    /// What stops this forge polling at all: no credential, or the rate limit.
    pub fn health(&self) -> Option<String> {
        if !self.gh.has_token() {
            return Some("no GitHub token: set one in the dashboard, export KILN_GITHUB_TOKEN, or `gh auth login`".into());
        }
        self.gh.paused_until().map(|t| format!("GitHub rate limit: paused until {t}"))
    }

    /// App mode: the installations' repos, else the configured list.
    pub fn repos(&self, cfg: &ForgeCfg) -> Vec<RepoRef> {
        let names = match self.gh.app() {
            Some(a) => a.names.read().unwrap().clone(),
            None => cfg.repos.clone(),
        };
        // Not `RepoRef::parse`: App names come from GitHub and were never re-validated.
        names.into_iter().map(|path| RepoRef { forge: ForgeId::github(), path }).collect()
    }

    pub async fn demand(&self, repo: &RepoRef, label: &str, default_cpus: u32) -> Result<Demand> {
        let (by_size, claimed, refused_forks) = self.gh.queued_jobs(&repo.path, label, default_cpus).await?;
        Ok(Demand { by_size, claimed, refused_forks })
    }
}
