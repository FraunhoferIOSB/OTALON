-- Baseline-traffic windows used by the subagent for "compare against normal" tooling.
-- See: openspec/changes/subagent-classification/specs/cross--subagent-postgres-schema/spec.md

CREATE TABLE IF NOT EXISTS baselines (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name             VARCHAR(128) NOT NULL UNIQUE,
    description      TEXT,
    start_ts         TIMESTAMPTZ NOT NULL,
    end_ts           TIMESTAMPTZ NOT NULL,
    is_active        BOOLEAN NOT NULL DEFAULT FALSE,
    pcap_chunk_count INTEGER,
    uci_count        INTEGER,
    size_bytes       BIGINT,
    audit_log        JSONB NOT NULL DEFAULT '[]'::jsonb,
    archived_at      TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by       VARCHAR(64)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_baselines_active
    ON baselines (is_active) WHERE is_active = TRUE;

CREATE INDEX IF NOT EXISTS ix_baselines_window
    ON baselines (start_ts, end_ts);
