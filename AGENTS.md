# Contributor Contract

Read [README.md](README.md) for the project overview and [INSTALL.md](INSTALL.md)
for deployment. Each top-level module owns its package, configuration, and
focused tests; preserve those boundaries and existing runtime contracts.

Retained tests belong under each module's `tests/` directory. Python modules
use their local `pyproject.toml` pytest configuration; the UI uses
`otalon-ui/package.json` (`npm run test:run`). Review a module's configuration
before selecting tests. Scanner repository tests use PostgreSQL when their
database gate is satisfied; API tests tagged or documented as PostgreSQL,
external-service, or captured/golden-data tests are not isolated unit tests.
Do not import omitted integration tiers into a retained unit test.

Prefer deterministic mocks for unit tests. Do not point tests at live databases,
InfluxDB, network interfaces, external LLMs, or operator data unless the task
explicitly authorizes those effects. Do not fabricate measured output or weaken
assertions to accommodate missing production fixtures.

Keep credentials out of source, logs, and test output. Use the root
`.env.compose.sample` as the sole tracked environment template and keep the
working `.env.compose` local. Build images from the checked-out source before
deployment; do not patch running containers or treat hot changes as release
validation.

Do not perform unrequested destructive operations, active scans, database
changes, or deployment actions. Preserve existing security boundaries,
capabilities, compatibility behavior, and runtime assets unless a task
explicitly approves a change.
