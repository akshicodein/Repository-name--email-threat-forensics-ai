-- Production schema (PostgreSQL).
-- The hackathon build uses an equivalent SQLite schema embedded directly in
-- backend/intelligence/db.py for zero-setup dev. When ready to deploy, swap
-- db.py's connection layer for psycopg and point it at this schema — per the
-- team's "Golden Rule": change internals freely, keep the input/output
-- contract stable.

CREATE TABLE IF NOT EXISTS cases (
    case_id         TEXT PRIMARY KEY,
    email_id        TEXT,
    attack_dna      TEXT,
    classification  TEXT,
    risk_score      NUMERIC,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ip_observations (
    id           SERIAL PRIMARY KEY,
    case_id      TEXT NOT NULL REFERENCES cases(case_id),
    ip           INET NOT NULL,
    country      TEXT,
    asn          TEXT,
    isp          TEXT,
    observed_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS domain_observations (
    id            SERIAL PRIMARY KEY,
    case_id       TEXT NOT NULL REFERENCES cases(case_id),
    domain        TEXT NOT NULL,
    resolved_ip   INET,
    observed_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ip_observations_ip ON ip_observations(ip);
CREATE INDEX IF NOT EXISTS idx_domain_observations_domain ON domain_observations(domain);
