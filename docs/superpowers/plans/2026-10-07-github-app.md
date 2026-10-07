# GitHub App Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** kiln can authenticate as a GitHub App (installation tokens minted per installation and refreshed before they expire), with the set of served repos being wherever the App is installed. PAT mode keeps working unchanged.

**Architecture:** A new `src/app_auth.rs` holds the pure, testable pieces: PEM parsing, RS256 JWT signing, token freshness, choosing an installation for an API path, the manifest JSON and the one-time `state` store. `Gh` (`src/github.rs`) gains an optional `AppAuth`; its request builder becomes async and picks a token per path. `App::repos()` (`src/main.rs`) is the one place that answers "which repos do we serve", and every former reader of `cfg.repos` goes through it.

**Tech Stack:** Rust 2024, tokio, axum 0.8, reqwest 0.12 (rustls), ring 0.17, base64 0.22, embedded vanilla-JS dashboard.

**Spec:** `docs/superpowers/specs/2026-10-07-github-app-design.md`

## Global Constraints

- PAT mode behaves exactly as today when no App is configured (all existing tests stay green).
- The App's permissions are exactly `administration: write, actions: write, contents: read, metadata: read`, with no events and an inactive hook.
- JWT claims are `iat = now - 60`, `exp = now + 540`, `iss = <app id>`, signed RS256 (`RSA_PKCS1_SHA256`).
- Installation tokens are re-minted when `now + 300 >= expires_at`.
- The key file `<data>/app.pem` is mode 0600; `<data>/app.json` is `{id, slug, html_url}`.
- `state` is single-use and expires after 3600 s.
- Discovery runs at startup and every 300 s. A failed discovery keeps the previous map.
- New direct dependencies are `ring = "0.17"` and `base64 = "0.22"` only (both already in Cargo.lock).
- Commits are authored by Bunty9 with no AI attribution trailers.

**Deviation from the spec (approved at planning):** the manifest `redirect_url` is the dashboard page `/#/app` (`?code&state` arrive in the query string). The page then POSTs `/api/app/convert` with its normal `x-kiln` and key headers. This needs no guard exemption and also works from the box itself, where API calls need the dashboard key that a browser redirect cannot carry. A 401 on an installation token drops it from the cache; the next call re-mints. There is no in-call retry.

## Review Focus

1. **PKCS#8 key (`BEGIN PRIVATE KEY`) instead of PKCS#1.** Users who re-export a key get PKCS#8, so both must load. Test in Task 1.
2. **A path for an owner with no installation** (`repos/actions/runner/releases/latest`) must still get some installation's token, not fail. Test in Task 1.
3. **Repo name case.** GitHub returns `Bunty9/kiln` but the poll path may carry other casing, so the installation lookup must ignore case. Test in Task 1.
4. **Per-repo config keys for repos the App is no longer installed on** must not block saving the config. Test in Task 3.
5. **The manifest `redirect_url`** must take the origin the browser actually used (`Host` header), not the `listen` address. Test in Task 4.

---

## File Structure

| File | Responsibility |
|---|---|
| `src/app_auth.rs` (new) | Pure App helpers: `parse_key`, `jwt`, `needs_mint`, `install_for`, `manifest`, `States`. No I/O beyond reading the key file in `load`. |
| `src/testdata/app-test.pem` (new) | A 2048-bit RSA test key, PKCS#1, used only by tests. |
| `src/github.rs` | `Gh` gains `app: RwLock<Option<Arc<AppAuth>>>`, async `request`, `token_for`, `mint`, `discover`. |
| `src/main.rs` | `mod app_auth`; load the App at startup; `App::repos()`; a validation variant for App mode; discovery refresh in the scheduler. |
| `src/web.rs` | `/api/app` (POST manual, DELETE), `/api/app/manifest`, `/api/app/convert`; App fields in `/api/state`; `cfg.repos` replaced by `app.repos()`. |
| `src/vm.rs` | `cfg.repos` replaced by `app.repos()`; doctor App checks. |
| `src/dashboard.html` | Settings › GitHub App card, `#/app` callback handling, Repos page and hello PR in App mode. |
| `docs/configuration.md`, `SECURITY.md`, `README.md`, `CHANGELOG.md` | GitHub App section and token posture. |

---

### Task 1: `app_auth` core (keys, JWT, freshness, installation choice)

**Files:**
- Create: `src/app_auth.rs`, `src/testdata/app-test.pem`
- Modify: `Cargo.toml` (`[dependencies]`), `src/main.rs:1-4` (add `mod app_auth;`)

**Interfaces:**
- Produces:
  - `pub fn parse_key(pem: &str) -> anyhow::Result<ring::signature::RsaKeyPair>`
  - `pub fn jwt(key: &RsaKeyPair, app_id: u64, now: u64) -> anyhow::Result<String>`
  - `pub fn needs_mint(expires_at: u64, now: u64) -> bool`
  - `pub fn install_for(path: &str, repos: &BTreeMap<String, u64>) -> Option<u64>` returns the installation for `repos/{o}/{n}/...` (case-insensitive), else any installation, else `None`.

- [ ] **Step 1: Generate the test key and add the dependencies.**

```bash
mkdir -p src/testdata && openssl genrsa -traditional -out src/testdata/app-test.pem 2048
```

Add `base64 = "0.22"` and `ring = "0.17"` under `[dependencies]` in `Cargo.toml`, and `mod app_auth;` at the top of `src/main.rs`.

- [ ] **Step 2: Write the failing tests** at the bottom of `src/app_auth.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    const PEM: &str = include_str!("testdata/app-test.pem");

    #[test]
    fn jwt_shape_and_signature() {
        let key = parse_key(PEM).unwrap();
        let t = jwt(&key, 42, 1_000_000).unwrap();
        let parts: Vec<&str> = t.split('.').collect();
        assert_eq!(parts.len(), 3);
        let b = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&b(parts[0])).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&b(parts[1])).unwrap();
        assert_eq!(header, serde_json::json!({"alg": "RS256", "typ": "JWT"}));
        assert_eq!(claims, serde_json::json!({"iat": 999_940, "exp": 1_000_540, "iss": "42"}));
        let public = ring::signature::UnparsedPublicKey::new(&ring::signature::RSA_PKCS1_2048_8192_SHA256, key.public().as_ref());
        public.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &b(parts[2])).unwrap();
    }

    #[test]
    fn keys() {
        assert!(parse_key(PEM).is_ok());
        assert!(parse_key("not a key").is_err());
        assert!(parse_key(&PEM.replace("RSA PRIVATE KEY", "EC PRIVATE KEY")).is_err(), "only RSA keys");
        // a PKCS#1 body under a PKCS#8 label is rejected, not misparsed
        assert!(parse_key(&PEM.replace("RSA PRIVATE KEY", "PRIVATE KEY")).is_err());
    }

    #[test]
    fn mint_margin() {
        assert!(!needs_mint(10_000, 10_000 - 301));
        assert!(needs_mint(10_000, 10_000 - 300));
        assert!(needs_mint(0, 5));
    }

    #[test]
    fn installation_choice() {
        let m: BTreeMap<String, u64> = [("bunty9/kiln".to_string(), 7), ("org/x".to_string(), 9)].into();
        assert_eq!(install_for("repos/Bunty9/Kiln/actions/runs", &m), Some(7));
        assert_eq!(install_for("repos/org/x/compare/a...b", &m), Some(9));
        // not installed (public runner releases): any installation's token
        assert!(install_for("repos/actions/runner/releases/latest", &m).is_some());
        assert_eq!(install_for("repos/a/b", &BTreeMap::new()), None);
    }
}
```

Also add a PKCS#8 fixture so Review Focus #1 is really pinned:

```bash
openssl pkcs8 -topk8 -nocrypt -in src/testdata/app-test.pem -out src/testdata/app-test.pk8.pem
```

and a fourth assertion in `keys()`: `assert!(parse_key(include_str!("testdata/app-test.pk8.pem")).is_ok());`

- [ ] **Step 3: Run the tests and watch them fail to compile**

Run: `cargo test app_auth`
Expected: FAIL with `cannot find function parse_key`.

- [ ] **Step 4: Implement** `src/app_auth.rs` (above the tests):

```rust
//! GitHub App authentication: pure helpers (keys, JWTs, token freshness,
//! which installation serves a path, the manifest, one-time setup states).

use anyhow::{Context, Result, bail};
use base64::Engine;
use ring::signature::RsaKeyPair;
use std::collections::BTreeMap;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const URL: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// DER body of a single PEM block, and whether it was PKCS#8 ("PRIVATE KEY").
fn pem_body(pem: &str) -> Result<(Vec<u8>, bool)> {
    let begin = pem.lines().find(|l| l.starts_with("-----BEGIN ")).context("no PEM block")?;
    let pkcs8 = begin == "-----BEGIN PRIVATE KEY-----";
    if !pkcs8 && begin != "-----BEGIN RSA PRIVATE KEY-----" {
        bail!("not an RSA private key ({begin})");
    }
    let body: String = pem.lines().skip_while(|l| *l != begin).skip(1).take_while(|l| !l.starts_with("-----END ")).collect();
    Ok((B64.decode(body.trim()).context("PEM body is not base64")?, pkcs8))
}

/// The App's private key: GitHub hands out PKCS#1; a re-exported key may be PKCS#8.
pub fn parse_key(pem: &str) -> Result<RsaKeyPair> {
    let (der, pkcs8) = pem_body(pem)?;
    let k = if pkcs8 { RsaKeyPair::from_pkcs8(&der) } else { RsaKeyPair::from_der(&der) };
    k.map_err(|e| anyhow::anyhow!("unusable RSA key: {e}"))
}

/// App JWT (RS256): issued 60 s back for clock drift, valid 9 minutes (GitHub caps at 10).
pub fn jwt(key: &RsaKeyPair, app_id: u64, now: u64) -> Result<String> {
    let head = URL.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let claims = serde_json::json!({ "iat": now - 60, "exp": now + 540, "iss": app_id.to_string() });
    let msg = format!("{head}.{}", URL.encode(claims.to_string()));
    let mut sig = vec![0; key.public().modulus_len()];
    key.sign(&ring::signature::RSA_PKCS1_SHA256, &ring::rand::SystemRandom::new(), msg.as_bytes(), &mut sig)
        .map_err(|_| anyhow::anyhow!("signing the App JWT failed"))?;
    Ok(format!("{msg}.{}", URL.encode(sig)))
}

/// Installation tokens live an hour: mint a new one 5 minutes before expiry.
pub fn needs_mint(expires_at: u64, now: u64) -> bool {
    now + 300 >= expires_at
}

/// Installation whose token serves `path`: the repo's own for `repos/{o}/{n}/...`,
/// else any (public reads like runner releases work with any installation token).
pub fn install_for(path: &str, repos: &BTreeMap<String, u64>) -> Option<u64> {
    let mut seg = path.trim_start_matches('/').split('/');
    if seg.next() == Some("repos")
        && let (Some(o), Some(n)) = (seg.next(), seg.next())
        && let Some(&id) = repos.get(&format!("{o}/{n}").to_ascii_lowercase())
    {
        return Some(id);
    }
    repos.values().next().copied()
}
```

Note: the claims test expects `"iss": "42"` as a string, which GitHub accepts (a client ID also goes there).

- [ ] **Step 5: Run the tests**

Run: `cargo test app_auth`
Expected: PASS (4 tests). Then `cargo clippy --all-targets` shows no warnings (`#[allow(dead_code)]` is not needed: Task 2 uses everything. If clippy flags dead code before Task 2, leave it; it disappears in Task 2).

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock src/app_auth.rs src/testdata src/main.rs
git commit -m "app_auth: App key parsing, RS256 JWT, token freshness, installation choice"
```

---

### Task 2: App mode in `Gh` (per-path tokens, minting, discovery)

**Files:**
- Modify: `src/github.rs` (struct `Gh` and impl: `new`, `set_token`, `source`, `has_token`, `request`, `raw`, `get`, `send`, `delete_runner`, the JIT call), `src/app_auth.rs` (add `AppAuth` and `load`)

**Interfaces:**
- Consumes: Task 1 functions.
- Produces:
  - `pub struct AppAuth { pub id: u64, pub slug: String, pub html_url: String, key: RsaKeyPair, tokens: tokio::sync::Mutex<HashMap<u64, (String, u64)>>, pub repos: std::sync::RwLock<BTreeMap<String, u64>>, pub discovered_at: AtomicU64 }`
  - `pub fn load(data: &Path) -> Option<Result<AppAuth>>` (`None` = no App configured)
  - `Gh::set_app(&self, a: Option<Arc<AppAuth>>)`, `Gh::app(&self) -> Option<Arc<AppAuth>>`
  - `Gh::discover(&self) -> Result<usize>` refreshes `AppAuth.repos` and returns the repo count
  - `source()` returns `"app"` in App mode; `has_token()` is true in App mode.

- [ ] **Step 1: Add `AppAuth` and `load` to `src/app_auth.rs`:**

```rust
pub struct AppAuth {
    pub id: u64,
    pub slug: String,
    pub html_url: String,
    key: RsaKeyPair,
    /// installation id -> (token, expires_at unix)
    pub tokens: tokio::sync::Mutex<std::collections::HashMap<u64, (String, u64)>>,
    /// "owner/name" (lowercase) -> installation id
    pub repos: std::sync::RwLock<BTreeMap<String, u64>>,
    /// Display names as GitHub spells them ("Bunty9/kiln"), same keys lowercased in `repos`.
    pub names: std::sync::RwLock<Vec<String>>,
    pub discovered_at: std::sync::atomic::AtomicU64,
}

impl AppAuth {
    pub fn new(id: u64, slug: String, html_url: String, pem: &str) -> Result<Self> {
        Ok(Self {
            id,
            slug,
            html_url,
            key: parse_key(pem)?,
            tokens: Default::default(),
            repos: Default::default(),
            names: Default::default(),
            discovered_at: Default::default(),
        })
    }

    pub fn jwt(&self, now: u64) -> Result<String> {
        jwt(&self.key, self.id, now)
    }
}

/// `<data>/app.json` + `<data>/app.pem`; None when no App is configured.
pub fn load(data: &std::path::Path) -> Option<Result<AppAuth>> {
    let meta = std::fs::read(data.join("app.json")).ok()?;
    Some((|| {
        let m: serde_json::Value = serde_json::from_slice(&meta).context("app.json")?;
        let pem = std::fs::read_to_string(data.join("app.pem")).context("app.pem")?;
        AppAuth::new(
            m["id"].as_u64().context("app.json has no id")?,
            m["slug"].as_str().unwrap_or("").into(),
            m["html_url"].as_str().unwrap_or("").into(),
            &pem,
        )
    })())
}

/// Write the App's files (key mode 0600) and load them.
pub fn save(data: &std::path::Path, id: u64, slug: &str, html_url: &str, pem: &str) -> Result<AppAuth> {
    use std::os::unix::fs::OpenOptionsExt;
    let a = AppAuth::new(id, slug.into(), html_url.into(), pem)?;
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(data.join("app.pem"))?;
    std::io::Write::write_all(&mut f, pem.as_bytes())?;
    std::fs::write(data.join("app.json"), serde_json::json!({ "id": id, "slug": slug, "html_url": html_url }).to_string())?;
    Ok(a)
}
```

- [ ] **Step 2: Make token choice async in `Gh`.** Add the field `app: std::sync::RwLock<Option<std::sync::Arc<crate::app_auth::AppAuth>>>` (initialised as `Default::default()` in `new`) and:

```rust
    pub fn set_app(&self, a: Option<std::sync::Arc<crate::app_auth::AppAuth>>) {
        *self.app.write().unwrap() = a;
        *self.expires.lock().unwrap() = None;
    }

    pub fn app(&self) -> Option<std::sync::Arc<crate::app_auth::AppAuth>> {
        self.app.read().unwrap().clone()
    }

    /// Bearer for `path`: the PAT, the App JWT for `app/...`, or the owning installation's token.
    async fn token_for(&self, path: &str) -> Result<String> {
        let Some(a) = self.app() else { return Ok(self.token.read().unwrap().clone()) };
        let now = crate::now();
        if path.trim_start_matches('/').starts_with("app/") {
            return a.jwt(now);
        }
        let inst = crate::app_auth::install_for(path, &a.repos.read().unwrap()).context("the GitHub App has no installations")?;
        self.mint(&a, inst).await
    }

    /// Cached installation token, minted when missing or within 5 min of expiry.
    async fn mint(&self, a: &crate::app_auth::AppAuth, inst: u64) -> Result<String> {
        let mut tokens = a.tokens.lock().await;
        if let Some((t, exp)) = tokens.get(&inst)
            && !crate::app_auth::needs_mint(*exp, crate::now())
        {
            return Ok(t.clone());
        }
        let jwt = a.jwt(crate::now())?;
        let r = self.request_with(&jwt, Method::POST, &format!("app/installations/{inst}/access_tokens")).send().await?;
        let status = r.status();
        let v: Value = r.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            bail!("minting an installation token: {status} {}", v["message"].as_str().unwrap_or(""));
        }
        let t = v["token"].as_str().context("no token in response")?.to_string();
        let exp = v["expires_at"].as_str().and_then(parse_rfc3339).context("no expires_at")?;
        tokens.insert(inst, (t.clone(), exp));
        Ok(t)
    }

    async fn request(&self, method: Method, path: &str) -> Result<reqwest::RequestBuilder> {
        Ok(self.request_with(&self.token_for(path).await?, method, path))
    }
```

Then update every `self.request(...)` caller to `self.request(...).await?` (in `raw`, `get`, `send`, `delete_runner` and any other), and change `source()` and `has_token()`:

```rust
    pub fn source(&self) -> &'static str {
        if self.app().is_some() { "app" } else { *self.source.read().unwrap() }
    }

    pub fn has_token(&self) -> bool {
        self.app().is_some() || !self.token.read().unwrap().is_empty()
    }
```

In `exec`, after the rate bookkeeping, drop a rejected installation token so the next call re-mints:

```rust
        if r.status() == StatusCode::UNAUTHORIZED
            && let Some(a) = self.app()
            && let Ok(mut t) = a.tokens.try_lock()
        {
            // ponytail: drops every cached installation token on any 401; per-installation if it matters.
            t.clear();
        }
```

Token expiry tracking stays PAT-only: wrap the existing `github-authentication-token-expiration` block in `if self.app().is_none()`.

- [ ] **Step 3: Add discovery** to `impl Gh`:

```rust
    /// App mode: map every repo of every installation to its installation id.
    /// Leaves the previous map in place on any error.
    pub async fn discover(&self) -> Result<usize> {
        let a = self.app().context("not in GitHub App mode")?;
        let jwt = a.jwt(crate::now())?;
        let (mut map, mut names) = (BTreeMap::new(), vec![]);
        let mut page = 1;
        loop {
            let r = self.request_with(&jwt, Method::GET, &format!("app/installations?per_page=100&page={page}")).send().await?;
            if !r.status().is_success() {
                bail!("listing App installations: {}", r.status());
            }
            let insts: Vec<Value> = r.json().await?;
            for i in &insts {
                let id = i["id"].as_u64().context("installation id")?;
                let token = self.mint(&a, id).await?;
                let mut p = 1;
                loop {
                    let r = self.request_with(&token, Method::GET, &format!("installation/repositories?per_page=100&page={p}")).send().await?;
                    if !r.status().is_success() {
                        bail!("listing repos of installation {id}: {}", r.status());
                    }
                    let v: Value = r.json().await?;
                    let repos = v["repositories"].as_array().cloned().unwrap_or_default();
                    for repo in &repos {
                        if let Some(n) = repo["full_name"].as_str() {
                            map.insert(n.to_ascii_lowercase(), id);
                            names.push(n.to_string());
                        }
                    }
                    if repos.len() < 100 {
                        break;
                    }
                    p += 1;
                }
            }
            if insts.len() < 100 {
                break;
            }
            page += 1;
        }
        names.sort_by_key(|n| n.to_ascii_lowercase());
        let n = names.len();
        *a.repos.write().unwrap() = map;
        *a.names.write().unwrap() = names;
        a.discovered_at.store(crate::now(), std::sync::atomic::Ordering::Relaxed);
        Ok(n)
    }
```

Add `use std::collections::BTreeMap;` to the imports.

- [ ] **Step 4: Build and run all tests**

Run: `cargo test && cargo clippy --all-targets`
Expected: all existing tests pass (PAT mode unchanged) and there are no warnings.

- [ ] **Step 5: Commit**

```bash
git commit -am "github: App mode with per-path installation tokens and repo discovery"
```

---

### Task 3: `App::repos()`, startup loading, discovery refresh, validation

**Files:**
- Modify: `src/main.rs` (`Config::validate_for`, `App`, `main`, `scheduler`, `tick`), `src/web.rs:282,318,403,484`, `src/vm.rs:966,1700`

**Interfaces:**
- Consumes: `app_auth::load`, `Gh::set_app`, `Gh::app`, `Gh::discover`.
- Produces: `App::repos(&self) -> Vec<String>`; `Config::validate_for(&self, host: u32, app_mode: bool)`.

- [ ] **Step 1: Write the failing test** in `src/main.rs` tests (Review Focus #4):

```rust
    #[test]
    fn app_mode_per_repo_keys() {
        // In App mode the served repos come from the installation, so per-repo keys
        // for repos not (or no longer) installed are kept and ignored, not rejected.
        let mut c = Config::default();
        c.warm.insert("gone/repo".into(), 1);
        c.cache_branches.insert("gone/repo".into(), vec!["dev".into()]);
        assert!(c.validate_for(8, true).is_ok());
        assert!(c.validate_for(8, false).is_err());
        // shape is still checked
        c.cache_branches.insert("gone/repo".into(), vec!["bad branch".into()]);
        assert!(c.validate_for(8, true).is_err());
    }
```

and update the existing calls `c.validate_for(8)` to `c.validate_for(8, false)`.

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test app_mode_per_repo_keys`
Expected: FAIL (wrong number of arguments).

- [ ] **Step 3: Implement.** In `validate_for`, add the `app_mode: bool` parameter and skip only the "is a configured repo" membership checks when it is true (in `warm` and `cache_branches`, and in any other per-repo map present on main, such as `repo_cache_gb`, if merged):

```rust
        let served = |r: &str| app_mode || self.repos.iter().any(|x| x.eq_ignore_ascii_case(r));
```

Replace each `self.repos.iter().any(|x| x.eq_ignore_ascii_case(r))` membership test with `served(r)`. `validate()` becomes `self.validate_for(host_threads(), false)`. `App::save_cfg` calls `c.validate_for(host_threads(), self.gh.app().is_some())`.

Add to `impl App`:

```rust
    /// Repos kiln serves: the App's installations in App mode, else the configured list.
    pub fn repos(&self) -> Vec<String> {
        match self.gh.app() {
            Some(a) => a.names.read().unwrap().clone(),
            None => self.cfg().repos,
        }
    }
```

In `main`, after building `app`, load the App:

```rust
    match app_auth::load(&app.data) {
        Some(Ok(a)) => app.gh.set_app(Some(Arc::new(a))),
        Some(Err(e)) => tracing::error!("GitHub App configured but unusable, using token auth: {e:#}"),
        None => {}
    }
```

In `scheduler`, discover before the sweep and then every 300 s:

```rust
async fn refresh_app(app: &Arc<App>) {
    static LAST: AtomicU64 = AtomicU64::new(0);
    if app.gh.app().is_none() || now() < LAST.load(Ordering::Relaxed) + 300 {
        return;
    }
    LAST.store(now(), Ordering::Relaxed);
    match app.gh.discover().await {
        Ok(n) => tracing::info!("GitHub App: {n} repo(s) installed"),
        Err(e) => {
            tracing::warn!("GitHub App discovery: {e:#}");
            app.poll.lock().unwrap().error = Some(format!("GitHub App discovery: {e:#}"));
        }
    }
}
```

Call `refresh_app(&app).await;` at the start of `scheduler` (before the sweep) and at the start of `tick` (after `reload_token`). Make `reload_token` return early in App mode (`if app.gh.app().is_some() { return; }`).

Replace the `cfg.repos` readers:
- `src/main.rs` scheduler sweep loop: `for repo in &app.repos()`.
- `src/main.rs` `tick`: `let repos = app.repos();` and use `repos.len()` / `repos.iter()` instead of `cfg.repos`.
- `src/web.rs:282`: `vm::cache_stats(&app.data, &app.repos())`.
- `src/web.rs:318` (`set_token` probe loop): `for r in app.repos()`.
- `src/web.rs:403` (hello PR): `app.repos().into_iter().find(...)`, and in App mode bail with "the hello PR is off in GitHub App mode (the App cannot write code)".
- `src/web.rs:484`: `proxy_path_ok(&path, &app.repos())`.
- `src/vm.rs:966` (cache clear): `app.repos().iter().any(...)`.
- `src/vm.rs:1700` (doctor): `for repo in &app.repos()`.

Also `Config::warm_target`, `cache_branches` and per-repo lookups already search by key, so stale keys are ignored automatically.

- [ ] **Step 4: Run the tests**

Run: `cargo test && cargo clippy --all-targets`
Expected: PASS, no warnings.

- [ ] **Step 5: Commit**

```bash
git commit -am "Serve the App's installed repos; refresh discovery every 5 minutes"
```

---

### Task 4: Setup endpoints (manifest, convert, manual, remove) and state fields

**Files:**
- Modify: `src/app_auth.rs` (add `manifest`, `States`), `src/web.rs` (routes, handlers, `/api/state`), `src/main.rs` (`App` gains `app_states: Mutex<app_auth::States>`)

**Interfaces:**
- Produces:
  - `pub fn manifest(origin: &str, host: &str) -> serde_json::Value`
  - `pub struct States(HashMap<String, u64>)` with `fn issue(&mut self, now: u64) -> String` and `fn take(&mut self, s: &str, now: u64) -> bool`
  - Routes:
    - `POST /api/app/manifest {org?}` returns `{url, manifest, state}`
    - `POST /api/app/convert {code, state}` returns `{slug, html_url}`
    - `POST /api/app {id, pem}` returns `{slug}`
    - `DELETE /api/app`

- [ ] **Step 1: Write the failing tests** in `src/app_auth.rs` tests (Review Focus #5):

```rust
    #[test]
    fn manifest_shape() {
        let m = manifest("http://ryzen7.tail1234.ts.net:7878", "ryzen7");
        assert_eq!(m["redirect_url"], "http://ryzen7.tail1234.ts.net:7878/#/app");
        assert_eq!(m["name"], "kiln-ryzen7");
        assert_eq!(m["public"], false);
        assert_eq!(m["hook_attributes"]["active"], false);
        assert_eq!(
            m["default_permissions"],
            serde_json::json!({"administration": "write", "actions": "write", "contents": "read", "metadata": "read"})
        );
        assert_eq!(m["default_events"], serde_json::json!([]));
    }

    #[test]
    fn states_are_single_use_and_expire() {
        let mut s = States::default();
        let a = s.issue(1000);
        assert_eq!(a.len(), 32);
        assert!(!s.take("nope", 1000));
        assert!(s.take(&a, 1000));
        assert!(!s.take(&a, 1000), "single use");
        let b = s.issue(1000);
        assert!(!s.take(&b, 1000 + 3601), "expired");
    }
```

- [ ] **Step 2: Run and watch them fail**

Run: `cargo test app_auth`
Expected: FAIL (`manifest` and `States` not found).

- [ ] **Step 3: Implement** in `src/app_auth.rs`:

```rust
/// App manifest for GitHub's one-click creation flow. GitHub sends the browser back
/// to the dashboard page (not an API route) with ?code&state.
pub fn manifest(origin: &str, host: &str) -> serde_json::Value {
    serde_json::json!({
        "name": format!("kiln-{host}"),
        "url": "https://github.com/Bunty9/kiln",
        "redirect_url": format!("{}/#/app", origin.trim_end_matches('/')),
        "public": false,
        "hook_attributes": { "url": "https://example.invalid/kiln", "active": false },
        "default_permissions": { "administration": "write", "actions": "write", "contents": "read", "metadata": "read" },
        "default_events": [],
    })
}

/// One-time `state` values for the manifest flow (1 h, single use).
#[derive(Default)]
pub struct States(std::collections::HashMap<String, u64>);

impl States {
    pub fn issue(&mut self, now: u64) -> String {
        let mut b = [0u8; 16];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b).expect("system rng");
        let s: String = b.iter().map(|x| format!("{x:02x}")).collect();
        self.0.retain(|_, at| now < *at + 3600);
        self.0.insert(s.clone(), now);
        s
    }

    pub fn take(&mut self, s: &str, now: u64) -> bool {
        self.0.remove(s).is_some_and(|at| now < at + 3600)
    }
}
```

In `src/main.rs`, add `pub app_states: Mutex<app_auth::States>` to `App` (`Default::default()` in `main`).

In `src/web.rs`, add the routes:

```rust
        .route("/api/app", post(app_manual).delete(app_remove))
        .route("/api/app/manifest", post(app_manifest))
        .route("/api/app/convert", post(app_convert))
```

and the handlers (`hostname` comes from `/etc/hostname`; the origin is `http://` plus the request's `Host` header, which `admit` has already checked):

```rust
#[derive(Deserialize)]
struct ManifestBody {
    #[serde(default)]
    org: String,
}

async fn app_manifest(State(app): S, headers: axum::http::HeaderMap, Json(b): Json<ManifestBody>) -> R<Json<Value>> {
    let host = headers.get("host").and_then(|v| v.to_str().ok()).ok_or_else(|| anyhow!("no Host header"))?;
    let name = std::fs::read_to_string("/etc/hostname").unwrap_or_else(|_| "box".into());
    let state = app.app_states.lock().unwrap().issue(crate::now());
    let org = b.org.trim();
    if !org.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        bail_r("org must be a GitHub org login")?;
    }
    let base = if org.is_empty() { "https://github.com/settings/apps/new".to_string() } else { format!("https://github.com/organizations/{org}/settings/apps/new") };
    Ok(Json(json!({
        "url": format!("{base}?state={state}"),
        "manifest": crate::app_auth::manifest(&format!("http://{host}"), name.trim()),
        "state": state,
    })))
}

#[derive(Deserialize)]
struct ConvertBody {
    code: String,
    state: String,
}

async fn app_convert(State(app): S, Json(b): Json<ConvertBody>) -> R<Json<Value>> {
    if !app.app_states.lock().unwrap().take(&b.state, crate::now()) {
        bail_r("this setup link is unknown, used or older than an hour: start again")?;
    }
    if !b.code.chars().all(|c| c.is_ascii_alphanumeric()) {
        bail_r("bad code")?;
    }
    let v = app.gh.manifest_conversion(&b.code).await?;
    let id = v["id"].as_u64().ok_or_else(|| anyhow!("GitHub returned no app id"))?;
    let (slug, url, pem) = (v["slug"].as_str().unwrap_or(""), v["html_url"].as_str().unwrap_or(""), v["pem"].as_str().unwrap_or(""));
    let a = crate::app_auth::save(&app.data, id, slug, url, pem)?;
    app.gh.set_app(Some(Arc::new(a)));
    let _ = app.gh.discover().await;
    Ok(Json(json!({ "slug": slug, "html_url": url })))
}

#[derive(Deserialize)]
struct ManualBody {
    id: u64,
    pem: String,
}

async fn app_manual(State(app): S, Json(b): Json<ManualBody>) -> R<Json<Value>> {
    let a = crate::app_auth::AppAuth::new(b.id, String::new(), String::new(), &b.pem)?;
    let me = app.gh.app_info(&a).await?; // GET /app with the JWT: proves id + key match
    let (slug, url) = (me["slug"].as_str().unwrap_or(""), me["html_url"].as_str().unwrap_or(""));
    let a = crate::app_auth::save(&app.data, b.id, slug, url, &b.pem)?;
    app.gh.set_app(Some(Arc::new(a)));
    let _ = app.gh.discover().await;
    Ok(Json(json!({ "slug": slug })))
}

async fn app_remove(State(app): S) -> R<Json<Value>> {
    let _ = std::fs::remove_file(app.data.join("app.pem"));
    let _ = std::fs::remove_file(app.data.join("app.json"));
    app.gh.set_app(None);
    Ok(Json(json!({ "ok": true })))
}
```

In `src/github.rs`:

```rust
    /// Exchange a manifest-flow code for the new App's id, slug, html_url and pem (no auth).
    pub async fn manifest_conversion(&self, code: &str) -> Result<Value> {
        let r = self.http.post(format!("https://api.github.com/app-manifests/{code}/conversions"))
            .header(header::ACCEPT, "application/vnd.github+json").send().await?;
        let status = r.status();
        let v: Value = r.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            bail!("GitHub refused the setup code ({status}): it is single use and expires after an hour, start again");
        }
        Ok(v)
    }

    /// GET /app with this App's JWT.
    pub async fn app_info(&self, a: &crate::app_auth::AppAuth) -> Result<Value> {
        let r = self.request_with(&a.jwt(crate::now())?, Method::GET, "app").send().await?;
        let status = r.status();
        let v: Value = r.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            bail!("GitHub rejected the App id or key: {status} {}", v["message"].as_str().unwrap_or(""));
        }
        Ok(v)
    }
```

Add the App fields to `/api/state` (in `state()` in `src/web.rs`):

```rust
        "app": app.gh.app().map(|a| json!({
            "id": a.id, "slug": a.slug, "html_url": a.html_url,
            "repos": a.names.read().unwrap().clone(),
            "discovered_at": a.discovered_at.load(std::sync::atomic::Ordering::Relaxed),
        })),
```

Also replace `"repos"`-dependent client data (`config.repos` is still sent) so that `S.app?.repos` exists for the dashboard.

- [ ] **Step 4: Run the tests**

Run: `cargo test && cargo clippy --all-targets`
Expected: PASS, no warnings.

- [ ] **Step 5: Commit**

```bash
git commit -am "App setup: manifest flow, manual key, remove; App info in /api/state"
```

---

### Task 5: Doctor App checks

**Files:**
- Modify: `src/vm.rs` (`doctor`, the token check block)

- [ ] **Step 1: Implement.** Replace the `out.push(match (app.gh.has_token(), src) {...})` block with:

```rust
    if let Some(a) = app.gh.app() {
        out.push(match app.gh.app_info(&a).await {
            Ok(v) => check("github app", true, format!("{} (id {})", v["slug"].as_str().unwrap_or("?"), a.id)),
            Err(e) => check("github app", false, format!("{e:#}")),
        });
        let n = a.names.read().unwrap().len();
        out.push(check("app installations", n > 0, if n > 0 { format!("{n} repo(s)") } else { format!("installed nowhere: {}/installations/new", a.html_url) }));
    } else {
        out.push(match (app.gh.has_token(), src) {
            // ... existing arms unchanged ...
        });
    }
```

The per-repo `NEEDS` probes stay as they are; they now run with installation tokens. The `token expiry` check only fires in PAT mode, because `expires` stays `None` in App mode (Task 2).

- [ ] **Step 2: Run the tests**

Run: `cargo test && cargo clippy --all-targets`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git commit -am "doctor: GitHub App and installation checks"
```

---

### Task 6: Dashboard

**Files:**
- Modify: `src/dashboard.html` (Settings › GitHub card, router for `#/app`, Repos page, hello button, overview banner)

- [ ] **Step 1: Callback route.** In the router, before normal page dispatch, handle `#/app?code=...&state=...`:

```js
async function appCallback() {
  const q = new URLSearchParams(location.hash.split('?')[1] || '');
  if (!q.get('code')) { location.hash = '#/settings/github'; return; }
  try {
    const r = await post('/api/app/convert', { code: q.get('code'), state: q.get('state') || '' });
    toast(`GitHub App ${r.slug} created. Now install it on your repos.`);
    location.hash = '#/settings/github'; await poll();
    if (r.html_url) window.open(r.html_url + '/installations/new', '_blank', 'noopener');
  } catch (e) { toast(String(e.message || e), true); location.hash = '#/settings/github'; }
}
```

Call it when `location.hash.startsWith('#/app')`.

- [ ] **Step 2: Settings › GitHub.** Add an App card under the token card:
  - **App configured** (`S.app`): a `<dl>` with App (linked to `S.app.html_url`), Repos (`S.app.repos.length`, listed), Last refresh (`rel(S.app.discovered_at)`), an "Install on more repos" link to `S.app.html_url + '/installations/new'`, and a "Remove App" button (`DELETE /api/app` after `confirm()`).
  - **Not configured:** an org input (optional) and a "Create GitHub App" button that calls `POST /api/app/manifest`, builds a hidden `<form method=post action=url>` with one `<input name=manifest value=JSON.stringify(manifest)>` and submits it. Below that, a `<details>` "Use an existing App" with an id input, a file input (`.pem`, read with `FileReader`) and a Save button that calls `POST /api/app`.
  - Hide the token form's "Validate and save" area when `S.app` is set, with the note "Using the GitHub App; the token is not used."

  The `post()` helper must support DELETE; if it doesn't, add `del(url)` next to it using the same headers.

- [ ] **Step 3: Repos page in App mode.** When `S.app` is set, list `S.app.repos` instead of `S.config.repos`, hide Add and Remove, and show "Repos come from the GitHub App's installations. Install it on more repos →" (link). Hide the hello PR button (`helloBtn`) in App mode and show only the snippet.

- [ ] **Step 4: Overview banner.** `if (S.app && !S.app.repos.length) B('warn', 'The GitHub App is not installed on any repo.', A('Install', S.app.html_url + '/installations/new'))`. Check that `A()` supports external links; use a plain `<a target=_blank rel=noopener>` if not.

- [ ] **Step 5: Verify.** Extract the scripts and run `node --check`. Run `cargo build`. Load the page against a local `kiln serve` with `KILN_DATA` pointing at a temp dir and check that the GitHub settings page renders in both modes (App mode by writing `app.json` and `app.pem` from the test key into the temp dir; discovery will fail, which is the expected banner).

- [ ] **Step 6: Commit**

```bash
git commit -am "dashboard: GitHub App setup, App-mode repos and settings"
```

---

### Task 7: Docs, live verification, PR

**Files:**
- Modify: `docs/configuration.md` (GitHub token section gains a GitHub App section; data directory lists `app.json` and `app.pem`), `SECURITY.md` (token posture: the App is recommended), `README.md` (Known limits: drop "PAT auth" and mention the App), `CHANGELOG.md` (Unreleased › Added)

- [ ] **Step 1: Write the docs.** Cover:
  - the manifest flow from Settings;
  - the manual route;
  - the exact permissions;
  - that the installation is the repo list;
  - Remove App;
  - that tokens expire after an hour and only the key is on disk;
  - that the hello PR is off in App mode.

- [ ] **Step 2: Live check on ryzen7** (see memory `kiln-box-ryzen7`):
  1. Build the branch there and install it. Back up `token`.
  2. Settings › GitHub › Create GitHub App from a tailnet browser. Install it on `Bunty9/kiln`.
  3. Rename `<data>/token` aside and restart. Confirm `kiln doctor` passes: github app, installations, `repo Bunty9/kiln`.
  4. Dispatch `ci` with `gh workflow run ci.yml --ref github-app` and confirm it runs on kiln.
  5. Open the job's logs in the dashboard (proxy through the installation token).
  6. Restore `token` afterwards only if you want PAT mode back. Leave App mode on if it works.

- [ ] **Step 3: Full checks, then the PR**

```bash
cargo fmt && cargo clippy --all-targets && cargo test
git commit -am "docs: GitHub App authentication"
git push -u origin github-app
gh pr create --base main --title "GitHub App authentication" --body "Implements docs/superpowers/specs/2026-10-07-github-app-design.md. Refs #7"
```
