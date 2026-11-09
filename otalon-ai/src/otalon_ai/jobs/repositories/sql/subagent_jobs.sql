-- Subagent classification jobs.
-- See: openspec/changes/subagent-classification/specs/cross--subagent-postgres-schema/spec.md
--
-- alarm_id is VARCHAR(64) (NOT UUID): matches alarms.id which is `character varying`
-- in the live otalon-clas database. ON DELETE CASCADE so jobs are removed when the
-- parent alarm is removed.

CREATE TABLE IF NOT EXISTS subagent_jobs (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alarm_id             VARCHAR(64) NOT NULL REFERENCES alarms(id) ON DELETE CASCADE,
    status               VARCHAR(16) NOT NULL,
    prompt_variant       VARCHAR(16) NOT NULL,
    prompt_hash          VARCHAR(32) NOT NULL,
    llm_provider         VARCHAR(32) NOT NULL,
    llm_model            VARCHAR(64) NOT NULL,
    llm_endpoint         VARCHAR(512),
    reasoning_effort     VARCHAR(8),
    baseline_id          UUID REFERENCES baselines(id) ON DELETE SET NULL,
    timeout_seconds      INTEGER NOT NULL,
    trigger_source       VARCHAR(16) NOT NULL DEFAULT 'api',
    started_at           TIMESTAMPTZ,
    finished_at          TIMESTAMPTZ,
    duration_seconds     REAL,
    step1_technical      JSONB,
    step2_classification JSONB,
    verdict              JSONB,
    tool_trace           JSONB NOT NULL DEFAULT '[]'::jsonb,
    tokens_prompt        INTEGER NOT NULL DEFAULT 0,
    tokens_completion    INTEGER NOT NULL DEFAULT 0,
    error_message        TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_subagent_jobs_status CHECK (
        status IN ('pending', 'running', 'completed', 'degraded', 'failed', 'timeout', 'cancelled')
    ),
    CONSTRAINT chk_subagent_jobs_prompt CHECK (
        prompt_variant IN ('open', 'expert')
    )
);

ALTER TABLE subagent_jobs ADD COLUMN IF NOT EXISTS verdict JSONB;

-- AI-036: 'degraded' marks a run that produced no MITRE technique because an
-- evidence tool namespace (typically pcap.*) was unavailable. Re-created
-- unconditionally so pre-existing tables pick the widened set up on startup.
ALTER TABLE subagent_jobs DROP CONSTRAINT IF EXISTS chk_subagent_jobs_status;
ALTER TABLE subagent_jobs ADD CONSTRAINT chk_subagent_jobs_status CHECK (
    status IN ('pending', 'running', 'completed', 'degraded', 'failed', 'timeout', 'cancelled')
);

-- AI-017: 'forensic' prompt variant for FP-first forensic analysis with
-- runtime-injected context. Re-created unconditionally so pre-existing
-- tables pick the widened set up on startup.
ALTER TABLE subagent_jobs DROP CONSTRAINT IF EXISTS chk_subagent_jobs_prompt;
ALTER TABLE subagent_jobs ADD CONSTRAINT chk_subagent_jobs_prompt CHECK (
    prompt_variant IN ('open', 'expert', 'forensic')
);

CREATE INDEX IF NOT EXISTS ix_subagent_jobs_alarm_id  ON subagent_jobs (alarm_id);
CREATE INDEX IF NOT EXISTS ix_subagent_jobs_status    ON subagent_jobs (status);
CREATE INDEX IF NOT EXISTS ix_subagent_jobs_created_at ON subagent_jobs (created_at DESC);
