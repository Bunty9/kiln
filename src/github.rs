//! Thin GitHub REST client: just the calls the scheduler needs, plus a raw
//! passthrough the dashboard uses for everything else.

use anyhow::{Context, Result, bail};
use reqwest::{Method, StatusCode, header};
use serde_json::{Value, json};
use std::collections::HashMap;
use tokio::sync::Mutex;

pub struct Gh {
    http: reqwest::Client,
    token: std::sync::RwLock<String>,
    // URL -> (etag, body). Conditional GETs that return 304 are free against
    // the rate limit, which is what makes 10s polling of several repos viable.
    etags: Mutex<HashMap<String, (String, Value)>>,
}

pub struct Resp {
    pub status: u16,
    pub content_type: String,
    pub body: bytes::Bytes,
}

impl Gh {
    pub fn new(token: String) -> Self {
        let http = reqwest::Client::builder()
            .user_agent("kiln-ci")
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .expect("http client");
        Self { http, token: std::sync::RwLock::new(token), etags: Mutex::default() }
    }

    pub fn set_token(&self, t: String) {
        *self.token.write().unwrap() = t;
    }

    pub fn has_token(&self) -> bool {
        !self.token.read().unwrap().is_empty()
    }

    fn request(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        let url = format!("https://api.github.com/{}", path.trim_start_matches('/'));
        self.http
            .request(method, url)
            .bearer_auth(self.token.read().unwrap().as_str())
            .header(header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
    }

    /// Raw call for the dashboard proxy. Follows redirects (job logs redirect
    /// to a signed blob URL; reqwest drops the auth header cross-origin).
    pub async fn raw(&self, method: Method, path: &str, body: Option<Value>) -> Result<Resp> {
        let mut rb = self.request(method, path);
        if let Some(b) = body {
            rb = rb.json(&b);
        }
        let r = rb.send().await?;
        let status = r.status().as_u16();
        let content_type = r
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/json")
            .to_string();
        Ok(Resp { status, content_type, body: r.bytes().await? })
    }

    async fn get(&self, path: &str) -> Result<Value> {
        let cached = self.etags.lock().await.get(path).cloned();
        let mut rb = self.request(Method::GET, path);
        if let Some((etag, _)) = &cached {
            rb = rb.header(header::IF_NONE_MATCH, etag);
        }
        let r = rb.send().await?;
        if r.status() == StatusCode::NOT_MODIFIED
            && let Some((_, v)) = cached {
                return Ok(v);
            }
        if !r.status().is_success() {
            bail!("GET {path}: {} {}", r.status(), r.text().await.unwrap_or_default());
        }
        let etag = r.headers().get(header::ETAG).and_then(|v| v.to_str().ok()).map(String::from);
        let v: Value = r.json().await?;
        if let Some(e) = etag {
            self.etags.lock().await.insert(path.to_string(), (e, v.clone()));
        }
        Ok(v)
    }

    async fn send(&self, method: Method, path: &str, body: Value) -> Result<Value> {
        let r = self.request(method.clone(), path).json(&body).send().await?;
        if !r.status().is_success() {
            bail!("{method} {path}: {} {}", r.status(), r.text().await.unwrap_or_default());
        }
        Ok(r.json().await.unwrap_or(Value::Null))
    }

    /// Queued jobs whose `runs-on` labels are all served by us
    /// (GitHub matches a job to a runner when job labels ⊆ runner labels).
    pub async fn queued_jobs(&self, repo: &str, labels: &[String]) -> Result<Vec<u64>> {
        let mut out = vec![];
        // A run is "in_progress" while later jobs of it still wait in the queue,
        // so both statuses have to be scanned.
        for status in ["queued", "in_progress"] {
            let runs = self.get(&format!("repos/{repo}/actions/runs?status={status}&per_page=30")).await?;
            for run in runs["workflow_runs"].as_array().into_iter().flatten() {
                let id = run["id"].as_u64().context("run id")?;
                let jobs = self.get(&format!("repos/{repo}/actions/runs/{id}/jobs?per_page=100")).await?;
                for j in jobs["jobs"].as_array().into_iter().flatten() {
                    if j["status"] == "queued" && wants_us(&j["labels"], labels) {
                        out.push(j["id"].as_u64().unwrap_or_default());
                    }
                }
            }
        }
        out.sort_unstable();
        out.dedup();
        Ok(out)
    }

    /// Returns (runner_id, encoded_jit_config).
    pub async fn jit_config(&self, repo: &str, name: &str, labels: &[String]) -> Result<(u64, String)> {
        let v = self
            .send(
                Method::POST,
                &format!("repos/{repo}/actions/runners/generate-jitconfig"),
                json!({ "name": name, "runner_group_id": 1, "labels": labels, "work_folder": "_work" }),
            )
            .await?;
        let id = v["runner"]["id"].as_u64().context("runner.id missing")?;
        let jit = v["encoded_jit_config"].as_str().context("encoded_jit_config missing")?;
        Ok((id, jit.to_string()))
    }

    /// Unused JIT registrations linger as offline runners; clean them up.
    pub async fn delete_runner(&self, repo: &str, id: u64) -> Result<()> {
        let r = self.request(Method::DELETE, &format!("repos/{repo}/actions/runners/{id}")).send().await?;
        // 404 = the ephemeral runner already deregistered itself after its job.
        if !r.status().is_success() && r.status() != StatusCode::NOT_FOUND {
            bail!("delete runner {id}: {}", r.status());
        }
        Ok(())
    }
}

/// Every label the job asks for must be one our runners carry. GitHub adds
/// `self-hosted`, `linux`, `x64` implicitly to self-hosted runners.
fn wants_us(job_labels: &Value, ours: &[String]) -> bool {
    let Some(arr) = job_labels.as_array() else { return false };
    let implicit = ["self-hosted", "linux", "x64"];
    !arr.is_empty()
        && arr.iter().filter_map(Value::as_str).all(|l| {
            implicit.iter().any(|i| i.eq_ignore_ascii_case(l)) || ours.iter().any(|o| o.eq_ignore_ascii_case(l))
        })
        // Without this, a plain `runs-on: self-hosted` job (meant for some
        // other runner) would make us boot VMs.
        && arr.iter().filter_map(Value::as_str).any(|l| ours.iter().any(|o| o.eq_ignore_ascii_case(l)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_matching() {
        let ours = vec!["kiln".to_string()];
        assert!(wants_us(&json!(["self-hosted", "kiln"]), &ours));
        assert!(wants_us(&json!(["kiln"]), &ours));
        assert!(wants_us(&json!(["Self-Hosted", "Linux", "KILN"]), &ours));
        assert!(!wants_us(&json!(["ubuntu-latest"]), &ours));
        assert!(!wants_us(&json!(["self-hosted"]), &ours));
        assert!(!wants_us(&json!(["self-hosted", "kiln", "gpu"]), &ours));
        assert!(!wants_us(&json!([]), &ours));
    }
}
