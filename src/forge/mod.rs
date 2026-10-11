//! Forge identity: which forge a repo lives on, its canonical key, and the `forges[]` config.
//! A repo is `(forge id, path)`. The key is bare `owner/name` on GitHub (every existing key,
//! `Vm.repo` value and cache file stays valid), else `forge-id:path`.

#![allow(dead_code)] // the call sites arrive with the later forge tasks

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    GitHub,
    Gitea,
    GitLab,
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
#[serde(deny_unknown_fields)]
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
            vec![ForgeCfg { id: ForgeId::github(), kind: Kind::GitHub, url: None, credential: None, network: None, repos: repos.to_vec() }]
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
                Some(u) if u.starts_with("https://") || u.starts_with("http://") => {}
                _ => bail!("forge {:?} needs an http(s) url", f.id.as_str()),
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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(cfg(r#"[{"id":"gl","kind":"gitlab","typo":1}]"#).is_err());
    }
}
