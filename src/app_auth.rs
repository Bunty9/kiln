//! GitHub App authentication: pure helpers (keys, JWTs, token freshness,
//! which installation serves a path, the manifest, one-time setup states).

use anyhow::{Context, Result, bail};
use base64::Engine;
use ring::signature::RsaKeyPair;
use std::collections::BTreeMap;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const URL: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// DER body of the first PEM block, and whether it is PKCS#8 ("PRIVATE KEY").
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

/// Origin the browser reached the dashboard at: its (already vetted) Host header, and
/// https when it came through `tailscale serve`.
pub fn origin(host: &str, https: bool) -> String {
    format!("{}://{host}", if https { "https" } else { "http" })
}

/// Installations kiln serves, and a note per one it ignores. Anyone can install a
/// (private) App only if they own it, but a public one, or one made public later, can be
/// installed by strangers: only the App owner's account and `app_accounts` are served.
/// Suspended installations can't mint tokens and are skipped silently.
pub fn served_installations(insts: &[serde_json::Value], owner: &str, accounts: &[String]) -> (Vec<u64>, Vec<String>) {
    let (mut ids, mut notes) = (vec![], vec![]);
    for i in insts.iter().filter(|i| i["suspended_at"].is_null()) {
        let Some(id) = i["id"].as_u64() else { continue };
        let login = i["account"]["login"].as_str().unwrap_or("");
        let ok = !login.is_empty()
            && ((!owner.is_empty() && login.eq_ignore_ascii_case(owner)) || accounts.iter().any(|a| a.eq_ignore_ascii_case(login)));
        if ok {
            ids.push(id);
        } else {
            let on = if login.is_empty() { format!("{id}") } else { login.to_string() };
            notes.push(format!("ignored installation on {on}: not the App owner; add it to app_accounts to serve it"));
        }
    }
    (ids, notes)
}

/// App manifest for GitHub's one-click creation flow. GitHub sends the browser back
/// to the dashboard page (not an API route, so no headers are needed) with ?code&state.
pub fn manifest(origin: &str, host: &str) -> serde_json::Value {
    serde_json::json!({
        "name": format!("kiln-{host}"),
        "url": "https://github.com/Bunty9/kiln",
        "redirect_url": format!("{}/", origin.trim_end_matches('/')),
        "public": false,
        "hook_attributes": { "url": "https://example.invalid/kiln", "active": false },
        "default_permissions": { "administration": "write", "actions": "write", "contents": "read", "metadata": "read" },
        "default_events": [],
    })
}

/// One-time `state` values for the manifest flow (1 h, single use), kept in
/// `<data>/app_states.json` so a kiln restart mid-setup does not strand the callback.
pub struct States {
    path: std::path::PathBuf,
    map: std::collections::HashMap<String, u64>,
}

impl States {
    pub fn open(path: std::path::PathBuf) -> Self {
        let map = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        Self { path, map }
    }

    fn save(&self) -> Result<()> {
        write_private(&self.path, &serde_json::to_vec(&self.map)?)
    }

    pub fn issue(&mut self, now: u64) -> Result<String> {
        let mut b = [0u8; 16];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b).expect("system rng");
        let s: String = b.iter().map(|x| format!("{x:02x}")).collect();
        self.map.retain(|_, at| now < *at + 3600);
        self.map.insert(s.clone(), now);
        self.save()?;
        Ok(s)
    }

    /// Known and under an hour old. Not used up: that waits for a successful conversion.
    pub fn valid(&self, s: &str, now: u64) -> bool {
        self.map.get(s).is_some_and(|at| now < at + 3600)
    }

    pub fn consume(&mut self, s: &str) -> Result<()> {
        self.map.remove(s);
        self.save()
    }
}

pub struct AppAuth {
    pub id: u64,
    pub slug: String,
    pub html_url: String,
    /// Login of the account that owns the App; "" until known (app.json from before it was kept).
    pub owner: std::sync::RwLock<String>,
    /// Data directory the App's files live in (None: a key being checked, not saved yet).
    dir: Option<std::path::PathBuf>,
    key: RsaKeyPair,
    /// installation id -> (token, expires_at unix)
    pub tokens: tokio::sync::Mutex<std::collections::HashMap<u64, (String, u64)>>,
    /// "owner/name" (lowercase) -> installation id
    pub repos: std::sync::RwLock<BTreeMap<String, u64>>,
    /// The same repos as GitHub spells them ("Bunty9/kiln").
    pub names: std::sync::RwLock<Vec<String>>,
    pub discovered_at: std::sync::atomic::AtomicU64,
    /// Why the last discovery failed (cleared by a successful one).
    pub error: std::sync::Mutex<Option<String>>,
}

impl AppAuth {
    pub fn new(id: u64, slug: String, html_url: String, pem: &str) -> Result<Self> {
        Ok(Self {
            id,
            slug,
            html_url,
            owner: Default::default(),
            dir: None,
            key: parse_key(pem)?,
            tokens: Default::default(),
            repos: Default::default(),
            names: Default::default(),
            discovered_at: Default::default(),
            error: Default::default(),
        })
    }

    pub fn jwt(&self, now: u64) -> Result<String> {
        jwt(&self.key, self.id, now)
    }

    /// Record the owner's login, in app.json too when the App is saved.
    pub fn set_owner(&self, owner: &str) -> Result<()> {
        *self.owner.write().unwrap() = owner.into();
        match &self.dir {
            Some(d) => self.write_meta(d),
            None => Ok(()),
        }
    }

    fn write_meta(&self, data: &std::path::Path) -> Result<()> {
        let m = serde_json::json!({ "id": self.id, "slug": self.slug, "html_url": self.html_url, "owner": *self.owner.read().unwrap() });
        write_private(&data.join("app.json"), m.to_string().as_bytes())
    }
}

/// `<data>/app.json` + `<data>/app.pem`; None when no App is configured.
pub fn load(data: &std::path::Path) -> Option<Result<AppAuth>> {
    let meta = std::fs::read(data.join("app.json")).ok()?;
    Some((|| {
        let m: serde_json::Value = serde_json::from_slice(&meta).context("app.json")?;
        let pem = std::fs::read_to_string(data.join("app.pem")).context("app.pem")?;
        let mut a = AppAuth::new(
            m["id"].as_u64().context("app.json has no id")?,
            m["slug"].as_str().unwrap_or("").into(),
            m["html_url"].as_str().unwrap_or("").into(),
            &pem,
        )?;
        a.owner = m["owner"].as_str().unwrap_or("").to_string().into();
        a.dir = Some(data.into());
        Ok(a)
    })())
}

/// Replace `path` atomically with a 0600 file (temp file + rename).
pub fn write_private(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let tmp = std::path::PathBuf::from(format!("{}.tmp", path.display()));
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    // `mode` only applies to a new file: a leftover temp file keeps its own.
    f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    std::io::Write::write_all(&mut f, bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))
}

/// Write the App's files (key mode 0600) and load them. app.json goes last: it is
/// what marks the App as configured, so a crash never leaves it without its key.
pub fn save(data: &std::path::Path, id: u64, slug: &str, html_url: &str, owner: &str, pem: &str) -> Result<AppAuth> {
    let mut a = AppAuth::new(id, slug.into(), html_url.into(), pem)?;
    a.owner = owner.to_string().into();
    a.dir = Some(data.into());
    write_private(&data.join("app.pem"), pem.as_bytes())?;
    a.write_meta(data)?;
    Ok(a)
}

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
        assert!(parse_key(include_str!("testdata/app-test.pk8.pem")).is_ok());
        assert!(parse_key("not a key").is_err());
        assert!(parse_key(&PEM.replace("RSA PRIVATE KEY", "EC PRIVATE KEY")).is_err(), "only RSA keys");
        // a PKCS#1 body under a PKCS#8 label is rejected, not misparsed
        assert!(parse_key(&PEM.replace("RSA PRIVATE KEY", "PRIVATE KEY")).is_err());
    }

    #[test]
    fn manifest_shape() {
        let m = manifest("http://ryzen7.tail1234.ts.net:7878", "ryzen7");
        // GitHub appends ?code&state: a plain path keeps them in location.search
        assert_eq!(m["redirect_url"], "http://ryzen7.tail1234.ts.net:7878/");
        // the dashboard behind tailscale serve is https
        assert_eq!(origin("box.ts.net:8443", true), "https://box.ts.net:8443");
        assert_eq!(origin("127.0.0.1:7878", false), "http://127.0.0.1:7878");
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
    fn states_persist_expire_and_are_consumed_only_on_success() {
        use std::os::unix::fs::PermissionsExt;
        let p = scratch("states").join("app_states.json");
        let mut s = States::open(p.clone());
        let a = s.issue(1000).unwrap();
        assert_eq!(a.len(), 32);
        assert!(!s.valid("nope", 1000));
        assert!(s.valid(&a, 1000));
        assert!(s.valid(&a, 1000), "checking does not use it up: a failed conversion can be retried");
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        // a kiln restart mid-setup keeps it
        let mut s = States::open(p.clone());
        assert!(s.valid(&a, 1500));
        s.consume(&a).unwrap();
        assert!(!s.valid(&a, 1500), "single use");
        assert!(!States::open(p.clone()).valid(&a, 1500), "consumed on disk too");
        let b = s.issue(1000).unwrap();
        assert!(!s.valid(&b, 1000 + 3600), "expired after an hour");
        s.issue(1000 + 3600).unwrap();
        assert!(!std::fs::read_to_string(&p).unwrap().contains(&b), "expired states are pruned");
        assert!(!States::open(p.with_file_name("missing.json")).valid(&a, 1000));
    }

    #[test]
    fn suspended_installations_are_skipped() {
        let me = serde_json::json!({ "login": "Bunty9" });
        let insts = serde_json::json!([{ "id": 1, "account": me, "suspended_at": null }, { "id": 2, "account": me, "suspended_at": "2026-10-01T00:00:00Z" }, { "id": 3, "account": me }]);
        assert_eq!(served_installations(insts.as_array().unwrap(), "Bunty9", &[]).0, [1, 3]);
    }

    #[test]
    fn only_the_owners_and_allowed_accounts_are_served() {
        let insts = serde_json::json!([
            { "id": 1, "account": { "login": "bunty9" } },
            { "id": 2, "account": { "login": "stranger" } },
            { "id": 3, "account": { "login": "MyOrg" } },
            { "id": 4, "account": null },
        ]);
        let insts = insts.as_array().unwrap();
        let (ids, notes) = served_installations(insts, "Bunty9", &[]);
        assert_eq!(ids, [1], "owner only by default, case-insensitive");
        assert_eq!(notes.len(), 3);
        assert_eq!(notes[0], "ignored installation on stranger: not the App owner; add it to app_accounts to serve it");
        let (ids, _) = served_installations(insts, "Bunty9", &["myorg".into()]);
        assert_eq!(ids, [1, 3]);
        // no known owner: only the allowlist, never an account-less installation
        let (ids, _) = served_installations(insts, "", &[]);
        assert!(ids.is_empty());
    }

    #[test]
    fn owner_is_saved_and_loaded() {
        let d = scratch("owner");
        save(&d, 42, "kiln-x", "https://github.com/apps/kiln-x", "Bunty9", PEM).unwrap();
        let a = load(&d).unwrap().unwrap();
        assert_eq!(*a.owner.read().unwrap(), "Bunty9");
        // an app.json from before `owner` existed loads with none, and learns it once
        std::fs::write(d.join("app.json"), r#"{"id":42,"slug":"kiln-x","html_url":"u"}"#).unwrap();
        let a = load(&d).unwrap().unwrap();
        assert_eq!(*a.owner.read().unwrap(), "");
        a.set_owner("Bunty9").unwrap();
        let m: serde_json::Value = serde_json::from_slice(&std::fs::read(d.join("app.json")).unwrap()).unwrap();
        assert_eq!(m, serde_json::json!({ "id": 42, "slug": "kiln-x", "html_url": "u", "owner": "Bunty9" }));
    }

    /// A per-test scratch dir under the system temp dir.
    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("kiln-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn private_files_are_0600_even_if_they_existed() {
        use std::os::unix::fs::PermissionsExt;
        let d = scratch("private");
        let p = d.join("app.pem");
        std::fs::write(&p, "old").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        // a leftover temp file from a crash must not keep its looser mode either
        std::fs::write(d.join("app.pem.tmp"), "junk").unwrap();
        std::fs::set_permissions(d.join("app.pem.tmp"), std::fs::Permissions::from_mode(0o644)).unwrap();
        write_private(&p, b"new").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "new");
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(!d.join("app.pem.tmp").exists());
        let a = save(&d, 42, "kiln-x", "https://github.com/apps/kiln-x", "Bunty9", PEM).unwrap();
        assert_eq!(a.id, 42);
        assert_eq!(std::fs::metadata(d.join("app.json")).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(load(&d).unwrap().unwrap().slug, "kiln-x");
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
