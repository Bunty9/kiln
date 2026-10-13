//! Test-only mock GitHub: an in-process HTTP server on 127.0.0.1 that answers `METHOD path?query`
//! from canned replies (fixtures under `testdata/forge/github/`), records every request, and can
//! be told to fail a route. An unknown route answers 404 and is logged, so a changed request
//! sequence shows up as a failed assertion, not a hang.

use axum::{
    Router,
    body::to_bytes,
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// One recorded request.
#[derive(Debug, Clone)]
pub struct Req {
    pub method: String,
    /// Path and query, as sent.
    pub path: String,
    pub body: Option<Value>,
    pub auth: Option<String>,
}

#[derive(Default)]
struct Inner {
    routes: HashMap<String, (u16, String)>,
    log: Vec<Req>,
}

pub struct Mock {
    /// `http://127.0.0.1:port`, for `Gh::for_mock`.
    pub base: String,
    inner: Arc<Mutex<Inner>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub fn fixture(name: &str) -> String {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/src/testdata/forge/github/");
    std::fs::read_to_string(format!("{p}{name}")).unwrap_or_else(|e| panic!("fixture {name}: {e}"))
}

async fn serve(State(inner): State<Arc<Mutex<Inner>>>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let bytes = to_bytes(body, usize::MAX).await.unwrap_or_default();
    let path = parts.uri.path_and_query().map(|p| p.as_str().to_string()).unwrap_or_default();
    let method = parts.method.to_string();
    let auth = parts.headers.get("authorization").and_then(|v| v.to_str().ok()).map(String::from);
    let mut i = inner.lock().unwrap();
    i.log.push(Req { method: method.clone(), path: path.clone(), body: serde_json::from_slice(&bytes).ok(), auth });
    let (status, body) = i.routes.get(&format!("{method} {path}")).cloned().unwrap_or((404, r#"{"message":"Not Found"}"#.into()));
    (StatusCode::from_u16(status).unwrap(), [("content-type", "application/json")], body).into_response()
}

impl Mock {
    /// Empty: every route is a 404 until added.
    pub async fn start() -> Mock {
        let inner = Arc::new(Mutex::new(Inner::default()));
        let app = Router::new().fallback(serve).with_state(inner.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Mock { base, inner, task }
    }

    /// The routes kiln calls for `acme/demo`, all healthy.
    pub async fn github() -> Mock {
        let m = Mock::start().await;
        let r = "/repos/acme/demo";
        for (path, file) in [
            ("/actions/runs?status=queued&per_page=30", "runs_queued.json"),
            ("/actions/runs?status=in_progress&per_page=30", "runs_in_progress.json"),
            ("/actions/runs/1001/jobs?per_page=100", "jobs_1001.json"),
            ("/actions/runs/1002/jobs?per_page=100", "jobs_1002.json"),
            ("/actions/runs/1004/jobs?per_page=100", "jobs_1004.json"),
            ("/actions/runners?per_page=100", "runners.json"),
            ("", "repo.json"),
            ("/git/ref/heads/main", "ref_main.json"),
            ("/compare/a1b2c3d4e5f60718293a4b5c6d7e8f9012345678...a1b2c3d4e5f60718293a4b5c6d7e8f9012345678", "compare_identical.json"),
            ("/compare/a1b2c3d4e5f60718293a4b5c6d7e8f9012345678...c3d4e5f60718293a4b5c6d7e8f9012345678a1b2", "compare_diverged.json"),
            ("/actions/jobs/6001", "job_6001.json"),
            ("/actions/jobs/6002", "job_6002.json"),
            ("/actions/jobs/6003", "job_6003.json"),
            ("/actions/jobs/6004", "job_6004.json"),
            ("/actions/runs/2001", "run_2001.json"),
            ("/actions/runs/2002", "run_2002.json"),
            ("/actions/runs/2003", "run_2003.json"),
            ("/actions/runs/2004", "run_2004.json"),
        ] {
            m.route("GET", &format!("{r}{path}"), 200, fixture(file));
        }
        m.route("POST", &format!("{r}/actions/runners/generate-jitconfig"), 201, fixture("jitconfig.json"));
        for id in [11, 12, 13, 15] {
            m.route("DELETE", &format!("{r}/actions/runners/{id}"), 204, "");
        }
        m
    }

    pub fn route(&self, method: &str, path: &str, status: u16, body: impl Into<String>) {
        self.inner.lock().unwrap().routes.insert(format!("{method} {path}"), (status, body.into()));
    }

    /// Make a route fail with GitHub's error body shape.
    pub fn fail(&self, method: &str, path: &str, status: u16, message: &str) {
        self.route(method, path, status, json!({ "message": message, "documentation_url": "https://docs.github.com/rest" }).to_string());
    }

    pub fn log(&self) -> Vec<Req> {
        self.inner.lock().unwrap().log.clone()
    }

    /// `"GET /repos/..."` per request, in order.
    pub fn requests(&self) -> Vec<String> {
        self.log().into_iter().map(|r| format!("{} {}", r.method, r.path)).collect()
    }

    pub fn clear_log(&self) {
        self.inner.lock().unwrap().log.clear();
    }
}

/// An App on a fresh temp data dir whose GitHub client talks to `mock`.
pub fn app(name: &str, mock: &Mock, cfg: crate::Config) -> Arc<crate::App> {
    let data = std::env::temp_dir().join(format!("kiln-test-mock-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data);
    std::fs::create_dir_all(data.join("update")).unwrap();
    Arc::new(crate::App::new(data, cfg, crate::github::Gh::for_mock(&mock.base)))
}

/// Byte-exact comparison with `testdata/forge/golden/<name>`. `KILN_BLESS=1` rewrites the file instead.
pub fn golden(name: &str, actual: &str) {
    let path = format!("{}/src/testdata/forge/golden/{name}", env!("CARGO_MANIFEST_DIR"));
    if std::env::var_os("KILN_BLESS").is_some() {
        std::fs::write(&path, actual).unwrap();
    }
    let want = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("golden {name}: {e}"));
    assert_eq!(actual, want, "golden {name} changed (KILN_BLESS=1 rewrites it, only for an intended change)");
}

/// A scripted gated forge for the verdict engine: what `pause` lists and what the API says about
/// the job, each optionally failing or slow. Nothing here reads the console or the guest.
pub struct FakeForge {
    pub held: Result<Option<Vec<String>>, String>,
    pub facts: Result<crate::forge::VerdictFacts, String>,
    pub delay: std::time::Duration,
}

impl FakeForge {
    /// A same-repo push job that holds only `job_id`.
    pub fn ok(job_id: &str) -> Self {
        let facts = crate::forge::VerdictFacts { ours: true, ..Default::default() };
        Self { held: Ok(Some(vec![job_id.into()])), facts: Ok(facts), delay: std::time::Duration::ZERO }
    }

    pub async fn pause(&self) -> anyhow::Result<Option<Vec<String>>> {
        tokio::time::sleep(self.delay).await;
        self.held.clone().map_err(|e| anyhow::anyhow!(e))
    }

    pub async fn verdict_facts(&self) -> anyhow::Result<crate::forge::VerdictFacts> {
        self.facts.clone().map_err(|e| anyhow::anyhow!(e))
    }

    /// The engine, run against this fake with the console's `job_id`.
    pub async fn gate(&self, job_id: &str, limit: std::time::Duration) -> crate::forge::Verdict {
        crate::forge::gate(job_id, limit, self.pause(), self.verdict_facts()).await
    }
}
