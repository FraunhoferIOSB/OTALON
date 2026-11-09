-- Migration 001: chat_sessions table for the chat surface of otalon-ai.
--
-- Per openspec/changes/replace-n8n-chat-orchestration/specs/chat--postgres-schema/spec.md.
-- Idempotent: re-applying this script on an existing database is a no-op
-- (CREATE TABLE / CREATE INDEX use IF NOT EXISTS).

CREATE TABLE IF NOT EXISTS chat_sessions (
    session_id   VARCHAR(128) PRIMARY KEY,
    messages     JSONB        NOT NULL DEFAULT '[]'::jsonb,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS chat_sessions_updated_at_idx ON chat_sessions (updated_at);
