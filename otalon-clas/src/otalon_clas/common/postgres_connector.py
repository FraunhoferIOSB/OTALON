"""PostgreSQL connection management and ORM models.

Provides engine creation, session factory, and SQLAlchemy ORM models for
the ``bounds``, ``anomalies``, and ``alarms`` tables. The schema matches
the OpenSpec ``cyberclas--anomaly-persistence`` and is identical to the
production schema shared with ``otalon-api`` and the legacy
``otalon-clas`` module.
"""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

from loguru import logger
from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    create_engine,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Session, declarative_base, relationship, sessionmaker

DEFAULT_POOL_SIZE: int = 5
DEFAULT_MAX_OVERFLOW: int = 10

Base = declarative_base()


class Bound(Base):
    """ORM model for the ``bounds`` table.

    Stores per ``(module, series_id)`` quantile-based lower and upper
    bounds as JSON dicts keyed by feature name.
    """

    __tablename__ = "bounds"

    module = Column(String, primary_key=True)
    series_id = Column(String, primary_key=True)
    lower_bounds = Column(JSON, nullable=False)
    upper_bounds = Column(JSON, nullable=False)
    trained_at = Column(DateTime(timezone=True), nullable=False)
    first_ts = Column(DateTime(timezone=True), nullable=True)
    last_ts = Column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        """Return a string representation."""
        return f"<Bound module={self.module!r} series_id={self.series_id!r}>"


class AnomalyRecord(Base):
    """ORM model for the ``anomalies`` table.

    Stores individual anomaly intervals with detection metadata,
    feature summaries, and ML classification details. The schema
    matches the OpenSpec ``cyberclas--anomaly-persistence`` DDL.
    """

    __tablename__ = "anomalies"

    id = Column(String, primary_key=True)
    module = Column(String, nullable=False, index=True)
    series_id = Column(String, nullable=False, index=True)
    anomaly_type = Column(String, nullable=False)
    start_ts = Column(DateTime(timezone=True), nullable=False, index=True)
    end_ts = Column(DateTime(timezone=True), nullable=False)
    value = Column(Float, nullable=True)
    is_anomaly = Column(Boolean, nullable=False, default=True)
    confidence = Column(Float, nullable=True)
    confirmed = Column(Boolean, nullable=False, default=False)
    is_grouped = Column(Boolean, nullable=False, default=False)
    bucket_seconds = Column(Integer, nullable=True)
    bound_severity_max = Column(Float, nullable=True)
    bound_severity_mean = Column(Float, nullable=True)
    violated_feature_count = Column(Integer, nullable=True)
    violated_feature_details = Column(JSON, nullable=True)
    violated_features = Column(JSON, nullable=False)
    ml_details = Column(JSON, nullable=True)
    feature_summary = Column(JSON, nullable=True)
    rate_summary = Column(JSON, nullable=True)
    alarm_id = Column(String, ForeignKey("alarms.id"), nullable=True, index=True)

    alarm = relationship("Alarm", back_populates="anomalies")

    def __repr__(self) -> str:
        """Return a string representation of the anomaly record."""
        return f"<AnomalyRecord id={self.id!r} type={self.anomaly_type!r}>"


class Alarm(Base):
    """ORM model for the ``alarms`` table.

    Stores aggregated alarm groups that span one or more anomaly
    intervals across one or multiple detection modules.
    """

    __tablename__ = "alarms"

    id = Column(String, primary_key=True)
    module = Column(String, nullable=False)
    start_timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    end_timestamp = Column(DateTime(timezone=True), nullable=False)
    primary_type = Column(JSON, nullable=True)
    multi_type = Column(Boolean, nullable=False, default=False)
    confirmed = Column(Boolean, nullable=False, default=False)
    is_active = Column(Boolean, nullable=False, default=True)
    series_ids = Column(JSON, nullable=False)
    anomaly_type_stats = Column(JSON, nullable=True)
    enrichment = Column(JSON, nullable=True)

    anomalies = relationship("AnomalyRecord", back_populates="alarm")

    def __repr__(self) -> str:
        """Return a string representation of the alarm."""
        return f"<Alarm id={self.id!r} module={self.module!r}>"


class BoundsHistory(Base):
    """ORM model for the ``bounds_history`` table.

    Audit log of all changes made to the ``bounds`` table through the
    MCP write/expand/replace tools. Each row captures the action, the
    old payload (NULL on initial ``write``), the new payload, and the
    operator-supplied reason. Used by the FP-remediation workflow to
    trace why a series-level bound was changed.
    """

    __tablename__ = "bounds_history"

    id = Column(String, primary_key=True)
    module = Column(String, nullable=False, index=True)
    series_id = Column(String, nullable=False, index=True)
    action = Column(String, nullable=False)
    old_lower = Column(JSON, nullable=True)
    old_upper = Column(JSON, nullable=True)
    new_lower = Column(JSON, nullable=False)
    new_upper = Column(JSON, nullable=False)
    reason = Column(Text, nullable=False)
    changed_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        Index(
            "ix_bounds_history_module_series_changed",
            "module",
            "series_id",
            "changed_at",
        ),
    )

    def __repr__(self) -> str:
        """Return a string representation of the history record."""
        return (
            "<BoundsHistory "
            f"id={self.id!r} module={self.module!r} "
            f"series_id={self.series_id!r} action={self.action!r}>"
        )


class AnomalySuppression(Base):
    """ORM model for the ``anomaly_suppression`` table.

    Stores per-UCI suppression rules that silence anomalies whose
    ``anomaly_type`` is in ``suppressed_types`` for the corresponding
    ``series_id``. Used by the fusion / persistence layer to drop
    operator-confirmed false positives (e.g. legitimate ARP discovery,
    LLDP, asset-discovery scans) BEFORE rows are written to
    ``anomalies`` / ``alarms``.

    One row per ``series_id`` (UCI). ``suppressed_types`` is the editable
    set; emptying it deletes the row. ``expires_at`` may be NULL (no
    expiry) or a future UTC timestamp.
    """

    __tablename__ = "anomaly_suppression"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    series_id = Column(Text, nullable=False, unique=True, index=True)
    suppressed_types: "Column[list[str]]" = Column(ARRAY(Text), nullable=False)
    reason = Column(Text, nullable=False)
    created_by = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "cardinality(suppressed_types) > 0",
            name="ck_anomaly_suppression_types_nonempty",
        ),
        Index(
            "ix_anomaly_suppression_expires_at",
            "expires_at",
            postgresql_where=Column("expires_at").isnot(None),
        ),
    )

    def __repr__(self) -> str:
        """Return a string representation of the suppression row."""
        return (
            "<AnomalySuppression " f"id={self.id!r} series_id={self.series_id!r} " f"types={self.suppressed_types!r}>"
        )


class FrequencyProfile(Base):
    """ORM model for the ``frequency_profiles`` table.

    Persists the per ``(module, series_id)`` frequency statistics used by
    :class:`otalon_clas.detection.frequency_monitor.FrequencyMonitor`
    so they survive container recreates and can be steered by operators
    via the MCP frequency-profile tools.

    The four stats columns (``mean_interval``, ``std_interval``,
    ``last_seen``, ``trained_at``) are written by ``train()`` via a
    stats-only UPSERT. The two nullable override columns
    (``tolerance_factor_override``, ``absence_factor_override``) are
    written only by the MCP write tools; ``train()`` never touches them.

    Effective threshold semantics in the detection hot path:

    * ``tolerance = tolerance_factor_override ?? global_default``
    * ``absence_timeout_factor = absence_factor_override ?? global_default``

    NULL overrides therefore fall back to the global default from
    ``config.json``; an explicit float survives re-training.
    """

    __tablename__ = "frequency_profiles"

    module = Column(String, primary_key=True)
    series_id = Column(String, primary_key=True)
    mean_interval = Column(Float, nullable=False)
    std_interval = Column(Float, nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    trained_at = Column(DateTime(timezone=True), nullable=False)
    tolerance_factor_override = Column(Float, nullable=True)
    absence_factor_override = Column(Float, nullable=True)

    def __repr__(self) -> str:
        """Return a string representation."""
        return (
            "<FrequencyProfile "
            f"module={self.module!r} series_id={self.series_id!r} "
            f"mean={self.mean_interval!r} std={self.std_interval!r}>"
        )


class FrequencyProfileHistory(Base):
    """ORM model for the ``frequency_profile_history`` table.

    Audit log of every override change applied through the MCP
    ``update_frequency_profile`` / ``reset_frequency_profile`` tools.
    Mirrors :class:`BoundsHistory` shape: an action string, the old and
    new override payload, the operator-supplied reason, and a server
    ``changed_at`` timestamp. The composite index
    ``(module, series_id, changed_at)`` keeps the history-newest-first
    query cheap.
    """

    __tablename__ = "frequency_profile_history"

    id = Column(String, primary_key=True)
    module = Column(String, nullable=False, index=True)
    series_id = Column(String, nullable=False, index=True)
    action = Column(String, nullable=False)
    old_tolerance = Column(Float, nullable=True)
    old_absence = Column(Float, nullable=True)
    new_tolerance = Column(Float, nullable=True)
    new_absence = Column(Float, nullable=True)
    reason = Column(Text, nullable=False)
    changed_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        Index(
            "ix_frequency_profile_history_module_series_changed",
            "module",
            "series_id",
            "changed_at",
        ),
    )

    def __repr__(self) -> str:
        """Return a string representation of the history record."""
        return (
            "<FrequencyProfileHistory "
            f"id={self.id!r} module={self.module!r} "
            f"series_id={self.series_id!r} action={self.action!r}>"
        )


class RetrainJob(Base):
    """ORM model for the ``retrain_jobs`` table.

    Persists runtime-retrain jobs written by otalon-api and
    claimed/updated by otalon-clas. The job state machine is
    ``queued → running → publishing → succeeded/failed``.
    """

    __tablename__ = "retrain_jobs"

    job_ref = Column(String, primary_key=True)
    scope = Column(
        String,
        nullable=False,
    )
    state = Column(
        String,
        nullable=False,
        default="queued",
    )
    window_start = Column(String, nullable=False)
    window_stop = Column(String, nullable=False)
    intervals = Column(JSON, nullable=True)
    mitre_file = Column(String, nullable=True)
    requested_by = Column(String, nullable=True)
    requested_at = Column(DateTime(timezone=True), nullable=False)
    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    detail = Column(Text, nullable=False, default="")
    error = Column(Text, nullable=True)
    metrics = Column(JSON, nullable=True)
    history_snapshot_rows = Column(Integer, nullable=False, default=0)
    worker_id = Column(String, nullable=True)
    heartbeat_at = Column(DateTime(timezone=True), nullable=True)
    operations_job_id = Column(BigInteger, nullable=True, unique=True)

    __table_args__ = (
        Index("ix_retrain_jobs_state_requested_at", "state", "requested_at"),
        CheckConstraint(
            "scope IN ('bounds_frequency', 'classifier')",
            name="ck_retrain_job_scope",
        ),
        CheckConstraint(
            "state IN ('queued', 'running', 'publishing', 'succeeded', 'failed', 'rejected')",
            name="ck_retrain_job_state",
        ),
    )

    def __repr__(self) -> str:
        """Return a string representation of the job."""
        return f"<RetrainJob job_ref={self.job_ref!r} scope={self.scope!r} state={self.state!r}>"


class RuntimeConfig(Base):
    """ORM model for the ``runtime_config`` table.

    Holds hot-reconfigurable, non-sensitive operating parameters with
    boot-precedence over environment/config defaults. ``value_prev``
    retains the previous value for a one-step rollback.
    """

    __tablename__ = "runtime_config"

    service = Column(String, primary_key=True)
    key = Column(String, primary_key=True)
    value = Column(Text, nullable=False)
    value_prev = Column(Text, nullable=True)
    updated_at = Column(DateTime(timezone=True), nullable=False)
    updated_by = Column(String, nullable=True)

    def __repr__(self) -> str:
        """Return a string representation of the config row."""
        return f"<RuntimeConfig ({self.service!r}, {self.key!r})>"


class PortCollapseRuleRecord(Base):
    """ORM model for the ``port_collapse_rules`` table.

    Persists per ``(module, base-key)`` rules used to normalize UCIs and
    select dynamic time-bucket sizes. Schema mirrors the legacy
    ``otalon-clas`` table so both implementations share the same data.
    """

    __tablename__ = "port_collapse_rules"

    module = Column(String, primary_key=True)
    src_mac = Column(String, primary_key=True)
    dst_mac = Column(String, primary_key=True)
    vlan = Column(String, primary_key=True)
    ip_proto = Column(String, primary_key=True)
    src_ip = Column(String, primary_key=True)
    dst_ip = Column(String, primary_key=True)
    protocols = Column(String, primary_key=True)
    normalized_uci = Column(String, nullable=False)
    wildcard_src_port = Column(Boolean, nullable=False, default=True)
    wildcard_dst_port = Column(Boolean, nullable=False, default=False)
    bucket_seconds = Column(Integer, nullable=False, default=5)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    def __repr__(self) -> str:
        """Return a string representation."""
        return "<PortCollapseRuleRecord " f"module={self.module!r} normalized_uci={self.normalized_uci!r}>"


class PostgresConnector:
    """Manages PostgreSQL connections via SQLAlchemy engine and session factory.

    Args:
        dsn: PostgreSQL connection string (e.g.,
            ``postgresql://user:pass@host:5432/db``).
        pool_size: Connection pool size.
        max_overflow: Maximum overflow connections beyond pool_size.
    """

    def __init__(
        self,
        dsn: str,
        pool_size: int = DEFAULT_POOL_SIZE,
        max_overflow: int = DEFAULT_MAX_OVERFLOW,
    ) -> None:
        """Initialize the PostgreSQL connector.

        Args:
            dsn: Database connection string.
            pool_size: Core pool size.
            max_overflow: Max overflow connections.
        """
        is_sqlite = dsn.startswith("sqlite")
        if is_sqlite:
            # SQLite's default SingletonThreadPool/NullPool rejects the
            # QueuePool-only pool_size/max_overflow kwargs, so omit them
            # for the test backend (audit F2). pool_pre_ping is likewise
            # a no-op there.
            self._engine = create_engine(dsn)
        else:
            self._engine = create_engine(
                dsn,
                pool_size=pool_size,
                max_overflow=max_overflow,
                pool_pre_ping=True,
            )
        # expire_on_commit=False keeps attributes readable on the write
        # path after commit; reads are additionally hardened by returning
        # detached DTOs from the repositories (audit A-04 / B-11 / F1).
        self._session_factory = sessionmaker(bind=self._engine, expire_on_commit=False)
        logger.info(
            "PostgreSQL engine created (sqlite={}, pool_size={}, max_overflow={})",
            is_sqlite,
            pool_size if not is_sqlite else "n/a",
            max_overflow if not is_sqlite else "n/a",
        )

    @property
    def engine(self) -> Any:
        """Return the underlying SQLAlchemy engine."""
        return self._engine

    @contextmanager
    def session(self) -> Generator[Session, None, None]:
        """Provide a transactional session scope via context manager.

        Commits on success, rolls back on exception, and always closes
        the session.

        Yields:
            Active SQLAlchemy session.

        Raises:
            Exception: Re-raises any exception after rollback.
        """
        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def create_tables(self) -> None:
        """Create all ORM-mapped tables if they do not exist.

        Existing tables managed by other services (legacy otalon-clas
        and otalon-api) will remain untouched because
        ``Base.metadata.create_all()`` only issues DDL for missing tables.

        Additionally applies idempotent additive-nullable column
        migrations that ``create_all`` cannot perform on pre-existing
        tables (e.g. the ``alarms.enrichment`` JSON column added for the
        multi-source x1 cross-source aggregation). Each migration uses
        ``ADD COLUMN IF NOT EXISTS`` so it is safe to run on every start
        and never drops or truncates existing data.
        """
        Base.metadata.create_all(self._engine)
        self._apply_additive_migrations()
        logger.info("Ensured all ORM tables exist in PostgreSQL")

    def _apply_additive_migrations(self) -> None:
        """Apply idempotent additive-nullable column migrations.

        Only ever issues ``ADD COLUMN IF NOT EXISTS`` statements; never
        drops, renames, or truncates. Safe to run on every startup.
        """
        from sqlalchemy import text

        statements = (
            "ALTER TABLE alarms ADD COLUMN IF NOT EXISTS enrichment JSONB",
            "ALTER TABLE bounds_history ADD COLUMN IF NOT EXISTS actor TEXT",
        )
        with self._engine.begin() as conn:
            for stmt in statements:
                conn.execute(text(stmt))
        logger.info("Applied additive-nullable column migrations")

    def dispose(self) -> None:
        """Dispose of the connection pool and release all connections."""
        self._engine.dispose()
        logger.info("PostgreSQL connection pool disposed")
