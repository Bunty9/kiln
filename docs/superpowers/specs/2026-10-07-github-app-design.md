# GitHub App authentication

Issue: #7, item 3. Status: approved design, 2026-10-07.

## Goal

Let kiln authenticate as a GitHub App instead of a long-lived personal access token, so that:

- no human admin's token, with full read/write to every repo's code, has to sit on the CI box;
- the only durable secret is the App's private key, and the tokens kiln uses expire after an hour;
- the repos kiln serves are decided by where the App is installed, not by hand-editing a list.

PAT mode keeps working unchanged. Org-level runners (runner groups) are out of scope: runners stay registered per repo.

## Decisions

| Question | Decision |
|---|---|
| Scope | App auth plus repo discovery. Runners stay repo-level. |
| Setup | One-click App manifest flow from the dashboard, with manual app id + key upload as a fallback. |
| Repo list in App mode | The installation is the list: installing the App on a repo makes kiln serve it, uninstalling stops it. The manual `repos` list is used only in PAT mode. |
| JWT signing | RS256 with `ring` and `base64` as direct dependencies (both already in `Cargo.lock` through rustls, so no new code in the build). |
| Hello PR | Hidden in App mode: the App gets *Contents: read* only, never write. The workflow snippet is shown instead. |

## Design

### 1. Auth inside `Gh`

`Gh` replaces its `token: RwLock<String>` with an auth mode:

```rust
enum Auth {
    Pat(String),
    App(AppAuth),
}

struct AppAuth {
    id: u64,
    key: ring::signature::RsaKeyPair, // from <data>/app.pem (PKCS#1 PEM)
    /// installation id -> (token, expires_at unix)
    tokens: tokio::sync::Mutex<HashMap<u64, (String, u64)>>,
    /// owner/name (lowercase) -> installation id, from discovery
    repos: std::sync::RwLock<BTreeMap<String, u64>>,
}
```

Every API call already goes through `request` / `request_with`. In App mode the token is chosen per call:

- the path `repos/{owner}/{name}/...` maps to that repo's installation;
- any other path (for example `repos/actions/runner/releases/latest`, a public repo the App is not installed on) uses any installation's token;
- `/app/...` endpoints use the JWT itself.

Because choosing a token may need a network call (minting), `request` becomes `async`. Its callers are all already async.

**JWT:** header `{"alg":"RS256","typ":"JWT"}`, claims `{"iat": now-60, "exp": now+540, "iss": app_id}` (60 s back for clock drift, 9 minutes forward, under GitHub's 10-minute cap), base64url without padding, signed with `RSA_PKCS1_SHA256`.

**Installation tokens:** `POST /app/installations/{id}/access_tokens` with the JWT. They are cached until 5 minutes before `expires_at`. One mutex around the cache means a burst of calls mints one token. A 401 on an installation token drops it from the cache and retries the call once.

`has_token()` is true in App mode once the key has loaded. `source()` returns `"app"`.

### 2. Repo discovery

In App mode the scheduler refreshes the repo map at startup and then every 5 minutes:

1. `GET /app/installations` (JWT), paginated.
2. For each installation, `GET /installation/repositories?per_page=100` (installation token), paginated.
3. Store `owner/name -> installation id`.

`App::repos() -> Vec<String>` returns `cfg.repos` in PAT mode and the discovered names in App mode. Every current reader of `cfg.repos` switches to it: the scheduler tick, the runner sweep, the dashboard proxy allowlist, `cache_stats`, doctor's per-repo checks, `/api/state`, and the per-repo map validation.

If a refresh fails, the previous map is kept and the error is shown as a poll error, so a GitHub hiccup does not unschedule every repo. An empty result (the App is installed nowhere) is a dashboard banner that links to the App's install page.

Per-repo settings (`warm`, `cache_branches`, `repo_cache_gb`) stay keyed by `owner/name` in `config.json`. In App mode, validation at save time checks keys against the discovered repos. An entry whose repo later stops being served is ignored, not an error, so uninstalling the App from a repo never makes the config invalid.

### 3. Setup

**Manifest flow** (Settings > GitHub > "Create GitHub App"):

1. kiln generates a random `state`, keeps it in memory for 1 hour, and returns the manifest to the dashboard.
2. The dashboard POSTs a form with `manifest` to `https://github.com/settings/apps/new?state=...`, or `https://github.com/organizations/{org}/settings/apps/new?state=...` when an org is entered.
3. The manifest:

```json
{
  "name": "kiln-<hostname>",
  "url": "https://github.com/Bunty9/kiln",
  "redirect_url": "<dashboard origin>/api/app/callback",
  "public": false,
  "hook_attributes": { "url": "https://example.invalid/kiln", "active": false },
  "default_permissions": { "administration": "write", "actions": "write", "contents": "read", "metadata": "read" },
  "default_events": []
}
```

4. GitHub redirects the browser to `GET /api/app/callback?code=...&state=...`. kiln checks `state` (constant-time compare, single use), then calls `POST /app-manifests/{code}/conversions` (no auth) and gets `id`, `slug`, `pem` and `html_url`.
5. kiln writes `<data>/app.pem` (mode 0600) and `<data>/app.json` (`{id, slug, html_url}`), switches `Gh` to App mode, and redirects the browser to the dashboard, which links to `<html_url>/installations/new`.

The callback is a top-level browser GET, so it cannot carry the `x-kiln` header that writes need. It still passes the normal tailnet-identity, `Host` and dashboard-key checks; the exemption from the header rule applies to this one route, and the single-use `state` is what protects it.

**Manual fallback:** `POST /api/app` with `{id, pem}`. It validates the key (parse it, then `GET /app` with a JWT) before saving. **Remove App:** `DELETE /api/app` deletes both files and returns to PAT mode, using whatever token source exists.

**Startup:** if `app.json` and `app.pem` exist and load, kiln uses App mode. Otherwise it falls back to the existing token precedence.

### 4. Behaviour differences in App mode

- The hello PR button is hidden, and the snippet is shown instead.
- Settings > GitHub shows the App name and link, the installations (account and repo count), the last discovery time and Remove App, instead of the token's source and expiry.
- The Repos page has no Add or Remove. It says that repos are managed by installing the App, with a link.
- `kiln doctor`:
  - checks that the key parses;
  - checks that `GET /app` with the JWT works;
  - checks that there is at least one installation;
  - runs the existing per-repo `NEEDS` probes, now through installation tokens. A missing permission means the App's permissions were edited down.
- The `token_expires` and `token_saved` dashboard fields are null in App mode.

### 5. Error handling

| Failure | Behaviour |
|---|---|
| Key unreadable or not RSA PKCS#1 | Startup logs it and falls back to PAT mode. Doctor fails "app key". Dashboard banner. |
| JWT rejected (App deleted, clock skew) | Poll error with GitHub's message. Doctor fails "app". |
| Minting fails for one installation | That installation's repos get repo errors and the others keep working. |
| Discovery fails | Keep the last map and show a poll error. |
| `state` missing, wrong or reused | 400 with no side effects. |
| Conversion code expired (1 hour) | 400 "start again". |

### 6. Testing

Unit tests, in the existing style (pure functions, no HTTP mocks):

- the JWT's header and claims, and that its signature verifies with the key pair's public key (ring), using a test key generated once and committed under `src/testdata/`;
- picking the installation from a path: a matching repo, a different owner falling back to any installation, `/app/` using the JWT, and case-insensitivity;
- token cache freshness: a pure `needs_mint(expires_at, now)` with the 5-minute margin;
- the manifest JSON: permissions, `redirect_url` taken from the request's origin, hook inactive;
- `state` checks: single use, and expiry after 1 hour;
- per-repo map validation in App mode, against a discovered list.

Live, on the kiln box: create the App with the manifest flow, install it on `Bunty9/kiln`, remove the PAT, and confirm that `ci` runs, doctor passes, the cache saves on a push to main, and the dashboard proxy (logs, rerun) works.

## Out of scope

- Org-level runners and runner groups.
- Webhooks (kiln keeps polling).
- Rate limits per installation: one shared `rate` state stays (`ponytail:` note; split it if more than one installation hits limits).
- Migrating an existing PAT setup's `repos` list into the installation automatically. The dashboard shows which listed repos the App is not installed on.
