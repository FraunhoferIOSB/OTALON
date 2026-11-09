"""On-startup SQL migration runner.

Per design.md § Decision 4 the suite does NOT introduce Alembic for the
single-table ``chat_sessions`` change. Instead a tiny runner executes every
``.sql`` file in ``otalon-ai/migrations/`` in lexicographic order against
the configured DSN, wrapped in a transaction. All migrations SHOULD use
``CREATE TABLE IF NOT EXISTS`` / ``CREATE INDEX IF NOT EXISTS`` so re-runs
are idempotent.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

from loguru import logger

from otalon_ai.db import Database


def _default_migrations_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "migrations"


def list_migrations(directory: Path | None = None) -> List[Path]:
    """Return all ``.sql`` files in the migrations directory, sorted by name."""
    directory = directory or _default_migrations_dir()
    if not directory.exists():
        return []
    return sorted(p for p in directory.iterdir() if p.is_file() and p.suffix == ".sql")


def run(database: Database, directory: Path | None = None) -> int:
    """Execute every pending migration. Returns the count of files applied.

    The runner is intentionally dumb: every file is executed on every start.
    Idempotency is the migration author's responsibility (use ``IF NOT
    EXISTS`` guards).
    """
    files = list_migrations(directory)
    if not files:
        logger.info("migrations: no .sql files found in {}", directory or _default_migrations_dir())
        return 0

    logger.info("migrations: applying {} file(s)", len(files))
    with database.admin_connection() as conn:
        for path in files:
            sql = path.read_text(encoding="utf-8")
            with conn.cursor() as cur:
                cur.execute(sql)
            logger.info("migrations: applied {}", path.name)
    return len(files)
