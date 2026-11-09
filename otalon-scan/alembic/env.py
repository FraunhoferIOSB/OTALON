"""Alembic environment for otalon-scan.

Reads the DSN from ``$POSTGRES_DSN`` (workspace convention) and ignores
the placeholder ``sqlalchemy.url`` from ``alembic.ini``. Uses the SYNC
SQLAlchemy engine (``create_engine``) — Alembic's migration runner does
not need the asyncpg driver and a sync engine simplifies the migration
file shape (no top-level ``await`` in ``upgrade()`` / ``downgrade()``).

The target metadata comes from :mod:`otalon_scan.repositories.models` so that
``alembic revision --autogenerate`` can detect future drift between the
declarative models and the live schema. F-01 ships a hand-written
initial migration (``0001_initial_view_and_upserts``) — autogenerate is
not used for that revision because the change includes view DDL and
column drops that autogenerate cannot express cleanly.
"""

from __future__ import annotations

import os
import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import engine_from_config, pool

from alembic import context

# Make ``otalon_scan`` importable when alembic runs from the otalon-scan
# root: SUITE-032 moved the package under ``src/``, so ``src`` is the
# sys.path entry, not the subproject root.
_PROJECT_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from otalon_scan.repositories.models import Base  # noqa: E402

# Alembic Config object provides access to values from alembic.ini.
config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def _resolve_dsn() -> str:
    """Resolve the migration DSN from ``$POSTGRES_DSN``.

    Strips SQLAlchemy driver-suffixes (``+asyncpg``, ``+psycopg2``) so
    Alembic can use the default sync ``psycopg2`` or ``psycopg`` driver.
    Falls back to the alembic.ini placeholder only if the env var is
    missing — that path then fails loudly at engine-connection time
    with a clear "placeholder@localhost" error.
    """
    raw = os.environ.get("POSTGRES_DSN", "")
    if not raw:
        return str(config.get_main_option("sqlalchemy.url"))
    if raw.startswith("postgresql+asyncpg://"):
        return "postgresql://" + raw[len("postgresql+asyncpg://") :]
    if raw.startswith("postgresql+psycopg2://"):
        return "postgresql://" + raw[len("postgresql+psycopg2://") :]
    return raw


target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Generate SQL scripts without connecting to a database.

    Useful for review / dry-run; not used in normal operator flow.
    """
    url = _resolve_dsn()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Apply migrations against a live database.

    Connects via the sync SQLAlchemy engine to the DSN resolved from
    ``$POSTGRES_DSN``.
    """
    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = _resolve_dsn()
    connectable = engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
