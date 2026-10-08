# kiln telemetry receiver

A Cloudflare Worker with a D1 database that stores kiln's opt-in usage and crash reports
(see `src/telemetry.rs` and SECURITY.md › Telemetry). It accepts only the exact fields kiln
sends, stores no IP or request metadata, keeps at most one usage report per install per UTC
day and 20 crash reports per install per UTC day.

## Deploy

```sh
cd deploy/telemetry
npx wrangler d1 create kiln-telemetry        # put the printed database_id in wrangler.toml
npx wrangler d1 execute kiln-telemetry --remote --file schema.sql
npx wrangler deploy
```

Then set `ENDPOINT` in `src/telemetry.rs` to `https://<worker host>/v1` and release. Until
then kiln sends nothing. To test a Worker without a release, run kiln with
`KILN_TELEMETRY_URL=https://<worker host>/v1` (anything not `https://` sends nothing).

The Worker must accept exactly the fields kiln sends (`usage()` and `crash()` in
`src/telemetry.rs`; the `usage_fields_match_the_worker` test pins kiln's side). Deploy a
Worker change before the kiln release that needs it: kiln drops a report the Worker refuses.

## Queries

```sh
q() { npx wrangler d1 execute kiln-telemetry --remote --command "$1"; }
# Active installs per day, and their versions
q "SELECT day, count(*) installs FROM usage GROUP BY day ORDER BY day DESC LIMIT 30"
q "SELECT version, count(*) FROM usage WHERE day = date('now') GROUP BY version"
# Feature adoption today
q "SELECT avg(json_extract(body,'$.features.cache')) cache, avg(json_extract(body,'$.egress')='filtered') filtered, avg(json_extract(body,'$.auth')='app') app FROM usage WHERE day = date('now')"
# Jobs per day across all installs
q "SELECT day, sum(json_extract(body,'$.jobs_24h')) jobs, sum(json_extract(body,'$.job_minutes_24h')) minutes FROM usage GROUP BY day ORDER BY day DESC LIMIT 30"
# Top crash sites
q "SELECT version, location, count(*) n, count(DISTINCT id) installs FROM crash GROUP BY 1, 2 ORDER BY n DESC LIMIT 20"
```

Retention: delete old rows as you see fit, e.g.
`q "DELETE FROM usage WHERE day < date('now','-400 days')"`.
