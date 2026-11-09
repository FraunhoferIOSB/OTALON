"""Unit tests for the UI-075 Wave B operations domain models."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from otalon_api.domain.operations import (
    REDACTED,
    OperationsAuditAppend,
    OperationsAuditEntry,
    OperationsAuditImport,
    OperationsJob,
    OperationsJobCreate,
    redact_sensitive,
    redact_text,
)


class TestOperationsJobModel:
    """1.1 Pydantic model for operations jobs."""

    def test_defaults_are_object_and_array(self) -> None:
        job = OperationsJob(
            id=1,
            display_id="J-1",
            type="service",
            title="x",
            state="running",
            trigger="t",
            started_at=datetime.now(timezone.utc),
        )
        assert job.params == {}
        assert job.log == []

    def test_invalid_state_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationsJob(
                id=1,
                display_id="J-1",
                type="service",
                title="x",
                state="bogus",  # type: ignore[arg-type]
                trigger="t",
                started_at=datetime.now(timezone.utc),
            )

    def test_invalid_type_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationsJobCreate(type="bogus", title="x", trigger="t")  # type: ignore[arg-type]

    def test_params_must_be_object(self) -> None:
        with pytest.raises(ValidationError):
            OperationsJobCreate(type="service", title="x", trigger="t", params="not-object")  # type: ignore[arg-type]

    def test_log_must_be_array(self) -> None:
        with pytest.raises(ValidationError):
            OperationsJob(
                id=1,
                display_id="J-1",
                type="service",
                title="x",
                state="running",
                trigger="t",
                started_at=datetime.now(timezone.utc),
                log={"not": "array"},  # type: ignore[arg-type]
            )

    def test_no_percentage_field(self) -> None:
        assert "percent" not in OperationsJob.model_fields


class TestOperationsAuditModel:
    """2.x Change Audit domain model."""

    def test_invalid_category_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationsAuditAppend(category="bogus", actor="operator", action="x", target="y")  # type: ignore[arg-type]

    def test_entry_serializes_source_default(self) -> None:
        entry = OperationsAuditEntry(
            id=1,
            at=datetime.now(timezone.utc),
            category="job",
            actor="operator",
            action="cancel",
            target="job:J-1",
        )
        assert entry.source == "operations"

    def test_import_idempotency_columns(self) -> None:
        imp = OperationsAuditImport(
            source="bounds_history",
            source_id="bh-1",
            category="bounds",
            actor="operator",
            action="update",
            target="conn:x",
        )
        assert imp.source == "bounds_history"
        assert imp.source_id == "bh-1"


class TestRedaction:
    """Security: sensitive keys in params/log are recursively redacted."""

    def test_top_level_secret_key_redacted(self) -> None:
        result = redact_sensitive({"action": "restart", "api_key": "cda_secret"})
        assert result["action"] == "restart"
        assert result["api_key"] == REDACTED

    def test_nested_and_list_secrets_redacted(self) -> None:
        payload = {
            "outer": {"password": "hunter2", "keep": 1},
            "items": [{"token": "abc"}, {"safe": "value"}],
        }
        result = redact_sensitive(payload)
        assert result["outer"]["password"] == REDACTED
        assert result["outer"]["keep"] == 1
        assert result["items"][0]["token"] == REDACTED
        assert result["items"][1]["safe"] == "value"

    def test_non_sensitive_payload_unchanged(self) -> None:
        payload = {"action": "restart", "service": "otalon-api", "window": "24h"}
        assert redact_sensitive(payload) == payload

    def test_scalar_passthrough(self) -> None:
        assert redact_sensitive("plain") == "plain"
        assert redact_sensitive(42) == 42


class TestTextRedaction:
    """B-F03: key-structured free-text redaction for audit fields."""

    def test_none_passthrough(self) -> None:
        assert redact_text(None) is None

    def test_plain_text_unchanged(self) -> None:
        text = "Started compose action restart for otalon-api"
        assert redact_text(text) == text

    def test_key_value_pair_redacted(self) -> None:
        result = redact_text("restart --api-key=cda_live_secret --service api")
        assert "cda_live_secret" not in result
        assert REDACTED in result
        # Surrounding, non-sensitive tokens are preserved.
        assert "restart" in result
        assert "--service api" in result

    def test_colon_separated_pair_redacted(self) -> None:
        result = redact_text("connect password: hunter2 host: db")
        assert "hunter2" not in result
        assert REDACTED in result
        assert "host: db" in result

    def test_quoted_value_redacted(self) -> None:
        result = redact_text('token="abc.def.ghi"')
        assert "abc.def.ghi" not in result
        assert REDACTED in result

    def test_bare_value_without_sensitive_key_is_not_scrubbed(self) -> None:
        # Honest scope: a value with no sensitive key in front is NOT
        # detected (key-structured, not arbitrary value scanning).
        text = "series conn:mac ratio 0.87 label anomalous"
        assert redact_text(text) == text
