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

/// Installations kiln can use: a suspended one can't mint tokens.
pub fn live_installations(insts: &[serde_json::Value]) -> Vec<u64> {
    insts.iter().filter(|i| i["suspended_at"].is_null()).filter_map(|i| i["id"].as_u64()).collect()
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

pub struct AppAuth {
    pub id: u64,
    pub slug: String,
    pub html_url: String,
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

    #[test]
    fn suspended_installations_are_skipped() {
        let insts =
            serde_json::json!([{ "id": 1, "suspended_at": null }, { "id": 2, "suspended_at": "2026-10-01T00:00:00Z" }, { "id": 3 }]);
        assert_eq!(live_installations(insts.as_array().unwrap()), [1, 3]);
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
