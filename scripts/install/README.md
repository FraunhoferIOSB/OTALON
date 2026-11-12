# Local Installer Utilities

Dependency-free Python 3.10+ helpers for a native Linux checkout. These commands prepare local files only; they do not build images, initialize databases, authorize interfaces or verify external models.

```sh
python3 scripts/install/setup.py --workspace "$PWD"
python3 scripts/install/check.py --workspace "$PWD"
sudo python3 scripts/install/bootstrap_influx.py --workspace "$PWD"
```

- setup.py creates .env.compose only when absent, fills missing/template local DB, service and callback secrets with cryptographic randomness, and derives the workspace path/build reference. Configured values, comments, order, inode, owner and mode are retained. External LiteLLM credentials/model aliases and approved interfaces remain operator inputs. Generated values are never printed.
- check.py validates local required values, model-alias shapes, PostgreSQL DSNs, credential-derived caller registries and endpoint shapes. `http://host.docker.internal:4000/v1` is a valid Desktop host URL in both modes when credentials/model aliases are configured. Neither mode contacts the endpoint or proves served-model availability. --syntax-only permits explicit `.invalid`/`offline-unconfigured` endpoint markers, still requires configured non-placeholder credentials/model aliases, and is not a deployment-readiness gate. The normal check rejects those actual offline markers. Literal `@url:` prefixes or Markdown backticks are malformed input, not normalized URLs.
- bootstrap_influx.py requires an existing shared/ directory. New files use exclusive no-replace publication and ownership 1500:1500 with mode 0600. Matching existing JSON is preserved, including extra members and formatting. Mismatched tokens, duplicate keys, unsafe links or wrong existing metadata fail without automatic repair. Database credentials/volumes are never accessed or rotated.

The environment parser deliberately accepts only a restricted Compose subset: UTF-8, LF/CRLF, NAME=value, single-quoted literals and bare/double-quoted ${NAME} references to earlier assignments. Unsupported shell-style substitutions, duplicate assignments, malformed quotes, control characters and unsafe links are rejected. Environment input and cumulative expanded values are each limited to 1 MiB; bootstrap JSON is limited to 1 MiB. Parent directories must be readable/searchable by the caller. In-place updates require file write access, not ownership; preservation is not a promise of transactional recovery from disk failure.

Tests use stdlib unittest and disposable files only. Set INSTALL_TEST_ROOT to an absolute disposable directory to keep fixtures outside the checkout. No application/database fixtures are imported.

```sh
INSTALL_TEST_ROOT="$HOME/.cache/otalon-install-tests" \
  python3 -m unittest discover -s scripts/install/tests -p 'test_*.py' -v
```

Ownership cases require an authorized privileged run against disposable files; an ordinary run reports those skips explicitly. A root test is not a substitute for an actual nonroot supplementary-group writer. These helpers do not establish native/WSL, database-migration, HTTPS/UI-PCAP, detection or provider-tool-loop acceptance.
