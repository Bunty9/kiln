-- kiln telemetry: one row per usage report (at most one per install per UTC day) and
-- per crash report. No IP, user agent or other request metadata is stored.
CREATE TABLE IF NOT EXISTS usage (
  id TEXT NOT NULL,
  day TEXT NOT NULL,
  version TEXT NOT NULL,
  body TEXT NOT NULL,
  PRIMARY KEY (id, day)
);
CREATE TABLE IF NOT EXISTS crash (
  id TEXT NOT NULL,
  day TEXT NOT NULL,
  version TEXT NOT NULL,
  location TEXT NOT NULL,
  body TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS crash_by_id_day ON crash (id, day);
CREATE INDEX IF NOT EXISTS crash_by_site ON crash (version, location);
