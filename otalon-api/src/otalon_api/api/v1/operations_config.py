"""Operations Configuration router (WAVE E).

Exposes the Boot & Environment, AI Connection and Change History surfaces
of the Operations Configuration page. Every route lives under the
``/api/v1/operations`` prefix and is therefore protected by
:class:`~otalon_api.middleware.auth.ApiKeyAuthMiddleware` (fail-closed when no
admin key is configured). A redundant per-route :func:`require_api_key`
dependency is applied so the endpoints are also authenticated when the
middleware is not mounted (direct unit testing).

Design (``openspec/changes/ui075-configuration``):

* AI key is **write-only** — ``GET`` never returns it, a dedicated replace
  endpoint rotates it, and no secret is ever written to an audit row.
* Boot ``GET`` exposes only the approved boot keys with sensitive values
  masked; ``PUT`` is reason-gated, records a redacted ``config`` audit row
  with actor + reason and reports the exact affected services.
* Change History is derived from ``operations_audit`` (category ``config``);
  rollback re-applies a captured non-secret prior value behind an explicit
  confirmation and appends a new redacted audit row.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from loguru import logger
from otalon_common.runtime import (
    MANIFEST,
    OTALON_AI_SERVICE,
    RuntimeKeySpec,
    Validator,
    is_secret_key,
    normalize_value,
    register,
)
from otalon_common.runtime.registry import (
    ListEntryValidationError,
    bool_literal,
    float_interval,
    int_range,
)
from otalon_common.runtime.series_blacklist import series_blacklist_syntax_validator

from otalon_api.api.schemas.operations_config import (
    AIConnectionDriftResponse,
    AIConnectionResponse,
    AIConnectionSaveResult,
    AIConnectionTest,
    AIConnectionTestResult,
    AIConnectionUpdate,
    AIKeyReplace,
    AIModelListResponse,
    BootConfigResponse,
    ConfigApplyRequest,
    ConfigApplyResponse,
    ConfigHistoryItem,
    ConfigRollbackRequest,
    ConfigRollbackResult,
)
from otalon_api.api.schemas.runtime_config import (
    PassiveSeederStatusResponse,
    RuntimeConfigApplyResponse,
    RuntimeConfigItem,
    RuntimeConfigJobRequest,
    RuntimeConfigResponse,
    RuntimeConfigWrite,
)
from otalon_api.dependencies import (
    get_ai_connection_service,
    get_ai_model_catalog_service,
    get_ai_runtime_client,
    get_env_compose_service,
    get_operations_jobs_service,
    get_passive_seeder_status_repo,
    get_runtime_config_repo,
    get_settings,
    require_api_key,
)
from otalon_api.domain.operations import OperationsAuditAppend, OperationsAuditEntry
from otalon_api.middleware.auth import require_operator_api_key
from otalon_api.repositories.runtime_config_repo import (
    PassiveSeederStatusRepo,
    RuntimeConfigRepo,
)
from otalon_api.services.ai_connection_service import (
    AI_FIELD_TO_ENV,
    AI_FIELD_TO_RUNTIME_KEY,
    AIConnectionService,
)
from otalon_api.services.ai_model_catalog_service import (
    AIModelCatalogService,
    ModelCatalogError,
)
from otalon_api.services.ai_runtime_client import AIRuntimeClient, AIRuntimePushError
from otalon_api.services.env_compose_service import (
    AFFECTED_SERVICES_BY_KEY,
    BOOT_ENV_KEYS,
    DISPLAY_BOOT_ENV_KEYS,
    READONLY_BOOT_ENV_KEYS,
    EnvComposeService,
    _is_sensitive,
)
from otalon_api.services.operations_jobs_service import OperationsJobsService
from otalon_api.settings import Settings

router = APIRouter(prefix="/api/v1/operations", tags=["operations-config"])

_INT_DOMAIN = re.compile(r"\[(\d+), (\d+)\]")
_FLOAT_DOMAIN = re.compile(r"\(([-+0-9.]+), ([-+0-9.]+)(\]|\))")
_OTALON_SCAN_SERVICE = "otalon-scan"
_GATE_JOB_TASKS: set[asyncio.Task[None]] = set()


SERIES_BLACKLIST_KEY = "detection.series_blacklist"
"""Runtime key whose write must wake the otalon-clas listener (CLAS-071)."""

_BLACKLIST_NOTIFY_CHANNEL = "cyberclas_runtime_invalidation"


def _notify_series_blacklist(repo: RuntimeConfigRepo) -> None:
    """Emit the invalidation NOTIFY after the write has committed (CLAS-071 D1).

    Failure is logged and swallowed: the write already succeeded, and the
    otalon-clas poll-cycle TTL pull (30 s) converges the snapshot anyway.
    """
    payload = json.dumps({"service": "otalon-clas", "key": SERIES_BLACKLIST_KEY})
    try:
        repo._repo._execute_update(
            "SELECT pg_notify(%(channel)s, %(payload)s)",
            {"channel": _BLACKLIST_NOTIFY_CHANNEL, "payload": payload},
        )
    except Exception:  # noqa: BLE001 - notify is an accelerator, never a write failure
        logging.getLogger(__name__).warning(
            "series-blacklist NOTIFY failed; clas converges via TTL pull", exc_info=True
        )


def _register_manifest() -> None:
    """Register manifest declarations locally without importing service code."""
    for entry in MANIFEST:
        validator: Validator
        if entry.value_type == "bool":
            validator = bool_literal()
        elif entry.value_type == "int":
            match = _INT_DOMAIN.fullmatch(entry.domain or "")
            if match is None:
                raise RuntimeError(f"invalid integer manifest domain: {entry.domain}")
            validator = int_range(int(match.group(1)), int(match.group(2)))
        elif entry.value_type == "float":
            match = _FLOAT_DOMAIN.fullmatch(entry.domain or "")
            if match is None:
                raise RuntimeError(f"invalid float manifest domain: {entry.domain}")
            validator = float_interval(
                float(match.group(1)),
                float(match.group(2)),
                inclusive_hi=match.group(3) == "]",
            )
        elif entry.value_type == "list":
            validator = series_blacklist_syntax_validator
        else:

            def accept_string(_value: str) -> None:
                """Accept manifest string values."""

            validator = accept_string
        register(
            RuntimeKeySpec(
                entry.service,
                entry.key,
                entry.value_type,
                validator,
                entry.domain,
                entry.description,
            )
        )


_register_manifest()


_TYPE_FALLBACKS: dict[str, str] = {
    "bool": "false",
    "int": "0",
    "float": "0.0",
    "list": "[]",
    "string": "",
}
"""Last-resort boot value per manifest ``value_type``.

Deliberately conservative: a bool defaults to disabled and a numeric to
zero, so an unmapped key can never read as "this feature is on" in the UI.
"""


def _manifest_value_type(service: str, key: str) -> str:
    """Return the manifest-declared ``value_type`` for a runtime key.

    Args:
        service: Owning service name.
        key: Runtime configuration key.

    Returns:
        The declared value type, or ``"string"`` when the key is not in the
        manifest (which cannot happen for manifest-driven callers, but keeps
        this helper total).
    """
    for entry in MANIFEST:
        if entry.service == service and entry.key == key:
            return str(entry.value_type)
    return "string"


def _boot_value(service: str, key: str) -> str:
    """Return boot-derived fallback for a manifest key.

    Resolution order: an environment override when one is mapped, then the
    per-key boot default, then a conservative per-type fallback.
    """
    defaults = {
        ("otalon-clas", "detection.series_blacklist"): "[]",
        ("otalon-clas", "classification.training_enabled"): "false",
        ("otalon-clas", "training.default_quantile"): "0.0001",
        ("otalon-clas", "training.retrain_paused"): "false",
        ("otalon-clas", "detection.conn.bounds_enabled"): "unknown",
        ("otalon-clas", "detection.conn.classification_enabled"): "false",
        ("otalon-clas", "detection.conn.frequency_enabled"): "true",
        ("otalon-clas", "detection.mac_traffic.bounds_enabled"): "unknown",
        ("otalon-clas", "detection.mac_traffic.classification_enabled"): "false",
        ("otalon-clas", "detection.mac_traffic.frequency_enabled"): "true",
        ("otalon-clas", "detection.proto_traffic.bounds_enabled"): "unknown",
        ("otalon-clas", "detection.proto_traffic.classification_enabled"): "false",
        ("otalon-clas", "detection.proto_traffic.frequency_enabled"): "true",
        # Port-collapse rule refresh (CLAS-033). Mirrors the field defaults on
        # otalon_clas.common.settings.PortRuleRefreshConfig (settings.py:443-448),
        # which ARE the boot values: config/config.json carries no
        # port_rule_refresh block and there is no env override, so
        # PortRuleRefreshConfig.resolve() falls back to exactly these when no
        # runtime_config row exists.
        ("otalon-clas", "detection.conn.port_rule_refresh.enabled"): "true",
        ("otalon-clas", "detection.conn.port_rule_refresh.interval_seconds"): "300",
        ("otalon-clas", "detection.conn.port_rule_refresh.lookback_hours"): "6",
        ("otalon-clas", "detection.conn.port_rule_refresh.confirm_cycles"): "2",
        ("otalon-clas", "detection.conn.port_rule_refresh.min_samples"): "2",
        (
            "otalon-clas",
            "detection.conn.port_rule_refresh.rotation_distinct_ports",
        ): "3",
        (_OTALON_SCAN_SERVICE, "enabled"): "false",
        (_OTALON_SCAN_SERVICE, "poll_interval_s"): "60",
        (_OTALON_SCAN_SERVICE, "lookback_window_s"): "300",
        (_OTALON_SCAN_SERVICE, "drop_laa"): "false",
    }
    env_names = {
        (_OTALON_SCAN_SERVICE, "enabled"): "PASSIVE_SEEDER_ENABLED",
        (_OTALON_SCAN_SERVICE, "poll_interval_s"): "PASSIVE_SEEDER_POLL_INTERVAL_S",
        (_OTALON_SCAN_SERVICE, "lookback_window_s"): "PASSIVE_SEEDER_LOOKBACK_WINDOW_S",
        (_OTALON_SCAN_SERVICE, "drop_laa"): "PASSIVE_SEEDER_DROP_LAA",
        ("otalon-clas", SERIES_BLACKLIST_KEY): "SERIES_BLACKLIST",
        (
            "otalon-clas",
            "classification.training_enabled",
        ): "TRAINING_CLASSIFICATION_ENABLED",
        (
            "otalon-clas",
            "detection.conn.classification_enabled",
        ): "PREDICTION_CLASSIFICATION_ENABLED",
        (
            "otalon-clas",
            "detection.mac_traffic.classification_enabled",
        ): "PREDICTION_CLASSIFICATION_ENABLED",
        (
            "otalon-clas",
            "detection.proto_traffic.classification_enabled",
        ): "PREDICTION_CLASSIFICATION_ENABLED",
    }
    fallback = defaults.get((service, key))
    if fallback is None:
        # The MANIFEST is the source of truth for which keys exist; this
        # table only supplies their boot-time fallback. A key added to the
        # manifest without a matching entry here used to raise KeyError and
        # take the whole Runtime tab down with HTTP 500 (SUITE-046) — one
        # missing fallback must degrade to one wrong-looking value, not to a
        # dead page.
        fallback = _TYPE_FALLBACKS.get(_manifest_value_type(service, key), "")
        logger.warning(
            "operations_config: no boot default mapped for runtime key "
            "{}/{}; falling back to {!r}. Add it to _boot_value's defaults.",
            service,
            key,
            fallback,
        )
    # Raw environment read on purpose (API-043): this is a runtime registry that
    # reports the *boot-time* value of another service's variable. The variable
    # name is looked up per (service, key) at call time and most of these belong
    # to otalon-clas, not to otalon-api's own configuration, so there is no
    # typed Settings field they could resolve from.
    return os.environ.get(env_names.get((service, key), ""), fallback)


def _runtime_items(repo: RuntimeConfigRepo) -> list[RuntimeConfigItem]:
    """Build manifest-complete response items from persisted rows."""
    rows = {(str(row["service"]), str(row["key"])): row for row in repo.list_rows()}
    items: list[RuntimeConfigItem] = []
    for entry in MANIFEST:
        row = rows.get((entry.service, entry.key), {})
        items.append(
            RuntimeConfigItem(
                service=entry.service,
                key=entry.key,
                value=str(row.get("value", _boot_value(entry.service, entry.key))),
                value_prev=row.get("value_prev"),
                updated_at=row.get("updated_at"),
                updated_by=row.get("updated_by"),
                type=entry.value_type,
                domain=entry.domain,
                description=entry.description,
            )
        )
    return items


@router.get(
    "/configuration/runtime",
    response_model=RuntimeConfigResponse,
    dependencies=[Depends(require_api_key)],
)
async def get_runtime_config(
    repo: RuntimeConfigRepo = Depends(get_runtime_config_repo),
) -> RuntimeConfigResponse:
    """Return every manifest key, including keys without persisted rows."""
    items = await asyncio.to_thread(_runtime_items, repo)
    return RuntimeConfigResponse(items=items)


@router.put(
    "/configuration/runtime",
    response_model=RuntimeConfigApplyResponse,
    dependencies=[Depends(require_operator_api_key)],
)
async def apply_runtime_config(
    body: RuntimeConfigWrite,
    request: Request,
    repo: RuntimeConfigRepo = Depends(get_runtime_config_repo),
    jobs_service: OperationsJobsService = Depends(get_operations_jobs_service),
) -> RuntimeConfigApplyResponse:
    """Validate and persist one runtime key, then append exactly one audit row."""
    try:
        value = normalize_value(body.service, body.key, body.value)
    except ListEntryValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    actor = getattr(getattr(request.state, "api_key_entry", None), "name", "operator")
    audit = OperationsAuditAppend(
        category="config",
        actor=actor,
        action="update-runtime",
        target=f"{body.service}:{body.key}",
        reason=body.reason,
        detail=json.dumps(
            {
                "changed_keys": [body.key],
                "prior_value": None,
                "sensitive": is_secret_key(body.key),
            }
        ),
    )
    if hasattr(repo, "upsert_with_audit"):
        await asyncio.to_thread(
            repo.upsert_with_audit, body.service, body.key, value, actor, audit
        )
    else:
        await asyncio.to_thread(repo.upsert, body.service, body.key, value, actor)
        await jobs_service.append_audit(audit)
    if body.key == SERIES_BLACKLIST_KEY:
        await asyncio.to_thread(_notify_series_blacklist, repo)
    items = await asyncio.to_thread(_runtime_items, repo)
    return RuntimeConfigApplyResponse(
        items=items,
        changed_keys=[body.key],
        restart_required=False,
    )


async def _run_runtime_config_job(
    job_id: int,
    updates: list[RuntimeConfigWrite],
    actor: str,
    repo: RuntimeConfigRepo,
    jobs_service: OperationsJobsService,
) -> None:
    """Apply gate writes and reconcile their durable operations job."""
    try:
        await jobs_service.start_job(job_id)
        for update in updates:
            value = normalize_value(update.service, update.key, update.value)
            audit = OperationsAuditAppend(
                category="config",
                actor=actor,
                action="update-runtime",
                target=f"{update.service}:{update.key}",
                reason=update.reason,
                detail=json.dumps(
                    {
                        "changed_keys": [update.key],
                        "sensitive": is_secret_key(update.key),
                    }
                ),
            )
            if hasattr(repo, "upsert_with_audit"):
                await asyncio.to_thread(
                    repo.upsert_with_audit,
                    update.service,
                    update.key,
                    value,
                    actor,
                    audit,
                )
            else:
                await asyncio.to_thread(
                    repo.upsert, update.service, update.key, value, actor
                )
                await jobs_service.append_audit(audit)
        await jobs_service.complete_job(
            job_id, result="Detection modes queued and applied"
        )
    except Exception as exc:
        await jobs_service.fail_job(job_id, error=str(exc))


@router.post(
    "/configuration/runtime/job",
    response_model=dict[str, Any],
    dependencies=[Depends(require_operator_api_key)],
)
async def enqueue_runtime_config_job(
    body: RuntimeConfigJobRequest,
    request: Request,
    repo: RuntimeConfigRepo = Depends(get_runtime_config_repo),
    jobs_service: OperationsJobsService = Depends(get_operations_jobs_service),
) -> dict[str, Any]:
    """Queue detection-mode writes and return immediately with job reference."""
    for update in body.updates:
        try:
            normalize_value(update.service, update.key, update.value)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    actor = getattr(getattr(request.state, "api_key_entry", None), "name", "operator")
    job = await jobs_service.record_job(
        type_="detection_gate_change",
        title="Change detection modes",
        trigger="operator",
        actor=actor,
        params={"updates": [update.model_dump() for update in body.updates]},
    )
    task = asyncio.create_task(
        _run_runtime_config_job(job.id, body.updates, actor, repo, jobs_service)
    )
    _GATE_JOB_TASKS.add(task)
    task.add_done_callback(_GATE_JOB_TASKS.discard)
    return {"job": job.model_dump(mode="json")}


@router.get(
    "/passive-seeder/status",
    response_model=PassiveSeederStatusResponse,
    dependencies=[Depends(require_api_key)],
)
async def get_passive_seeder_status(
    repo: PassiveSeederStatusRepo = Depends(get_passive_seeder_status_repo),
) -> PassiveSeederStatusResponse:
    """Return persisted seeder status or an explicit unknown state."""
    row = await asyncio.to_thread(repo.get, _OTALON_SCAN_SERVICE)
    if row is None:
        return PassiveSeederStatusResponse(
            service=_OTALON_SCAN_SERVICE, state="unknown"
        )
    return PassiveSeederStatusResponse.model_validate(row)


def _boot_response(service: EnvComposeService) -> BootConfigResponse:
    """Return masked boot values and the exact per-key service impact.

    Args:
        service: The env-compose service (freshly reloaded by the caller).

    Returns:
        A :class:`BootConfigResponse` limited to the approved boot keys.
    """
    masked = service.get_masked_env(full_mask_sensitive=True)
    return BootConfigResponse(
        env={key: masked.get(key, "") for key in DISPLAY_BOOT_ENV_KEYS},
        editable_keys=list(BOOT_ENV_KEYS),
        readonly_keys=list(READONLY_BOOT_ENV_KEYS),
        sensitive_keys=[key for key in DISPLAY_BOOT_ENV_KEYS if _is_sensitive(key)],
        affected_services={
            key: AFFECTED_SERVICES_BY_KEY.get(key, []) for key in DISPLAY_BOOT_ENV_KEYS
        },
    )


@router.get(
    "/configuration/boot",
    response_model=BootConfigResponse,
    dependencies=[Depends(require_api_key)],
)
async def get_boot_config(
    env_service: EnvComposeService = Depends(get_env_compose_service),
) -> BootConfigResponse:
    """Read masked compose boot configuration.

    Re-reads ``.env.compose`` from disk so a value changed out-of-band is
    reflected without an API restart.
    """
    await asyncio.to_thread(env_service.load)
    return _boot_response(env_service)


@router.put(
    "/configuration/boot",
    response_model=ConfigApplyResponse,
    dependencies=[Depends(require_operator_api_key)],
)
async def apply_boot_config(
    body: ConfigApplyRequest,
    env_service: EnvComposeService = Depends(get_env_compose_service),
    jobs_service: OperationsJobsService = Depends(get_operations_jobs_service),
) -> ConfigApplyResponse:
    """Apply one approved boot key and append a redacted config audit entry.

    The prior value is captured for rollback only when the key is
    non-sensitive; sensitive keys never have their value persisted to the
    audit ``detail``.
    """
    if body.key not in BOOT_ENV_KEYS:
        raise HTTPException(status_code=400, detail="Key is not an approved boot key")
    await asyncio.to_thread(env_service.load)
    prior = env_service.to_dict().get(body.key)
    try:
        _, changed, _ = await asyncio.to_thread(
            env_service.update_and_save, {body.key: body.value}
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await jobs_service.append_audit(
        OperationsAuditAppend(
            category="config",
            actor="operator",
            action="update",
            target=body.key,
            reason=body.reason,
            detail=json.dumps(
                {
                    "changed_keys": changed,
                    "prior_value": None if _is_sensitive(body.key) else prior,
                    "sensitive": _is_sensitive(body.key),
                }
            ),
        )
    )
    result = _boot_response(env_service)
    return ConfigApplyResponse(
        **result.model_dump(),
        changed_keys=changed,
        restart_required=bool(changed),
    )


_LIVE_PUSH_SKIP_DETAIL = "live push skipped: OTALON_AI_INTERNAL_KEY is not configured"


def _drift(meta: dict[str, str | bool], active: dict[str, str] | None) -> bool:
    """Compare active models against the persisted ones (partial when unknown).

    Args:
        meta: Persisted connection metadata (``chat_model``/``job_model``).
        active: ``otalon-ai``-reported active models, or ``None`` when the
            status could not be retrieved.

    Returns:
        True when any known active model differs from its persisted
        counterpart; unknowns never fabricate drift.
    """
    if active is None:
        return False
    if active["chat_model"] != str(meta.get("chat_model", "")):
        return True
    return active["job_model"] != str(meta.get("job_model", ""))


async def _get_runtime_llm_status(
    runtime: AIRuntimeClient, api_key: str
) -> tuple[dict[str, str] | None, str | None]:
    """Fetch the active llm-config status from otalon-ai.

    Args:
        runtime: The otalon-ai internal-surface client.
        api_key: Internal key (may be empty; the call is then skipped).

    Returns:
        ``(status, error)`` where exactly one is ``None``. The error names
        only the failed step, never response bodies or key material.
    """
    if not api_key:
        return None, None
    try:
        status = await runtime.get_llm_config_status(api_key)
    except AIRuntimePushError as exc:
        return None, str(exc)
    return status, None


@router.get(
    "/ai-connection",
    response_model=AIConnectionDriftResponse,
    dependencies=[Depends(require_api_key)],
)
async def get_ai_connection(
    service: AIConnectionService = Depends(get_ai_connection_service),
    runtime: AIRuntimeClient = Depends(get_ai_runtime_client),
    settings: Settings = Depends(get_settings),
) -> AIConnectionDriftResponse:
    """Read the ACTIVE configuration from otalon-ai (no key material).

    The ``GET`` reports what the runtime actually serves and how it
    compares to ``.env.compose`` (drift), per Task 2.5. When otalon-ai is
    unreachable or no internal key is configured, the active fields are
    ``null`` and drift is ``false`` — the UI must not present an
    unreachable runtime as "in sync".
    """
    meta = await asyncio.to_thread(service.metadata)
    active, error = await _get_runtime_llm_status(
        runtime, settings.otalon_ai_internal_key
    )
    if error is not None:
        logger.warning("ai-connection: active status unavailable: {}", error)
    return AIConnectionDriftResponse(
        provider=str(meta.get("provider", "litellm")),
        endpoint=str(meta.get("endpoint", "")),
        chat_model=str(meta.get("chat_model", "")),
        job_model=str(meta.get("job_model", "")),
        context_window=int(meta.get("context_window", 128000)),  # type: ignore[arg-type]
        state=meta.get("state", "not-configured"),
        key_configured=bool(meta.get("key_configured", False)),
        active_chat_model=None if active is None else active["chat_model"],
        active_job_model=None if active is None else active["job_model"],
        drift=_drift(meta, active),
    )


async def _validate_models_against_catalog(
    body: AIConnectionUpdate, catalog: AIModelCatalogService
) -> None:
    """Reject chat/job models the proxy does not offer (AI-045 D4 step 1).

    Args:
        body: The operator save request.
        catalog: The proxy model-catalog service.

    Raises:
        HTTPException: 422 naming the first unknown model (spec detail
            ``model '<name>' not offered by proxy``) — not 502: the
            operator's request is being validated, the reachability of
            the proxy is the reason the model cannot be confirmed. A
            proxy outage therefore surfaces as the 422 asking for
            ``allow_unlisted_model``.
        HTTPException: 502 when the catalog call failed for a reason
            other than reachability (unexpected internal error).
    """
    if body.allow_unlisted_model:
        return
    try:
        offered = await catalog.list_models()
    except ModelCatalogError as exc:
        raise HTTPException(
            status_code=422,
            detail=(
                f"model list unavailable ({exc}); set allow_unlisted_model=true to "
                "save without verification"
            ),
        ) from exc
    except (
        Exception
    ) as exc:  # noqa: BLE001 - reason: unexpected catalog failure must surface as 502, never 500
        raise HTTPException(
            status_code=502, detail="model list could not be retrieved"
        ) from exc
    for model in (body.chat_model, body.job_model):
        if model and model not in offered:
            raise HTTPException(
                status_code=422, detail=f"model '{model}' not offered by proxy"
            )


@router.put(
    "/ai-connection",
    response_model=AIConnectionSaveResult,
    dependencies=[Depends(require_operator_api_key)],
)
async def update_ai_connection(
    body: AIConnectionUpdate,
    env_service: EnvComposeService = Depends(get_env_compose_service),
    ai_service: AIConnectionService = Depends(get_ai_connection_service),
    catalog: AIModelCatalogService = Depends(get_ai_model_catalog_service),
    runtime: AIRuntimeClient = Depends(get_ai_runtime_client),
    settings: Settings = Depends(get_settings),
    jobs_service: OperationsJobsService = Depends(get_operations_jobs_service),
    runtime_repo: RuntimeConfigRepo = Depends(get_runtime_config_repo),
) -> AIConnectionSaveResult:
    """Update the non-secret AI fields, audit the change, push live (no secret).

    Design.md D4 order: (1) validate models against the proxy list, (2)
    write ``.env.compose``, (3) push to otalon-ai, (4) report
    ``live_applied``/``live_detail``. A failed push never rolls the file
    back: the file is the source for the next start. No secret is ever
    written to the audit row or any response.
    """
    await _validate_models_against_catalog(body, catalog)
    # AI-045: refuse an unsafe endpoint BEFORE anything is written or pushed live. Same
    # target rule as the connectivity test (blocked always, public only https).
    if body.endpoint:
        try:
            AIConnectionService._validate_target(body.endpoint)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    # AI-045: the non-secret connection values live in runtime_config (same store as
    # the other services), so saving needs no file write and no container restart.
    # The API key is NOT stored here; it stays in .env.compose.
    updates = {AI_FIELD_TO_ENV[name]: getattr(body, name) for name in AI_FIELD_TO_ENV}
    actor = "operator"
    # Iterate by API field name (AI_FIELD_TO_RUNTIME_KEY is keyed by field), not by the
    # .env.compose key that `updates` is keyed by.
    for field in AI_FIELD_TO_RUNTIME_KEY:
        runtime_key = AI_FIELD_TO_RUNTIME_KEY[field]
        value = getattr(body, field)
        if value is None:
            # AI-046: an absent optional field keeps the saved value; never write "None".
            continue
        try:
            normalized = normalize_value(OTALON_AI_SERVICE, runtime_key, str(value))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        audit = OperationsAuditAppend(
            category="config",
            actor=actor,
            action="update-ai",
            target=f"{OTALON_AI_SERVICE}:{runtime_key}",
            reason=body.reason.strip() or None,
            detail=json.dumps({"changed_keys": [runtime_key], "sensitive": False}),
        )
        await asyncio.to_thread(
            runtime_repo.upsert_with_audit,
            OTALON_AI_SERVICE,
            runtime_key,
            normalized,
            actor,
            audit,
        )
    live_applied = False
    live_detail: str = _LIVE_PUSH_SKIP_DETAIL
    internal_key = settings.otalon_ai_internal_key
    if internal_key:
        try:
            await runtime.push_llm_config(
                api_key=internal_key,
                chat_model=body.chat_model,
                job_model=body.job_model,
                base_url=body.endpoint or None,
                context_window=body.context_window,
            )
        except AIRuntimePushError as exc:
            live_detail = str(exc)
        except (
            Exception
        ) as exc:  # noqa: BLE001 - reason: any push failure must degrade to live_applied=false, never 500
            logger.warning(
                "ai-connection: live push failed unexpectedly: {}", type(exc).__name__
            )
            live_detail = f"live push failed: {type(exc).__name__}"
        else:
            live_applied = True
            live_detail = "llm-config applied"
    else:
        logger.warning("ai-connection: {}", _LIVE_PUSH_SKIP_DETAIL)
    await jobs_service.append_audit(
        OperationsAuditAppend(
            category="config",
            actor="operator",
            action="update-ai",
            target="ai-connection",
            reason=body.reason.strip() or None,
            detail=json.dumps(
                {
                    "keys": sorted(updates),
                    "live_applied": live_applied,
                    "sensitive": False,
                }
            ),
        )
    )
    meta = await asyncio.to_thread(ai_service.metadata)
    return AIConnectionSaveResult(
        provider=str(meta.get("provider", "litellm")),
        endpoint=str(meta.get("endpoint", "")),
        chat_model=str(meta.get("chat_model", "")),
        job_model=str(meta.get("job_model", "")),
        context_window=int(meta.get("context_window", 128000)),  # type: ignore[arg-type]
        state=meta.get("state", "not-configured"),  # type: ignore[arg-type]
        key_configured=bool(meta.get("key_configured", False)),
        live_applied=live_applied,
        live_detail=live_detail,
    )


@router.post(
    "/ai-connection/models",
    response_model=AIModelListResponse,
    dependencies=[Depends(require_operator_api_key)],
)
async def list_ai_models(
    catalog: AIModelCatalogService = Depends(get_ai_model_catalog_service),
) -> AIModelListResponse:
    """List the models the proxy offers (identifiers only, never the key).

    Raises:
        HTTPException: 502 when the proxy is unreachable or answers with
            an unusable shape; the detail never contains the proxy
            response body or key material.
    """
    try:
        models = await catalog.list_models()
    except ModelCatalogError as exc:
        logger.warning("ai-connection models: catalog unavailable: {}", exc)
        raise HTTPException(status_code=502, detail="model list unavailable") from exc
    return AIModelListResponse(models=models)


@router.post(
    "/ai-connection/key",
    response_model=AIConnectionResponse,
    dependencies=[Depends(require_operator_api_key)],
)
async def replace_ai_key(
    body: AIKeyReplace,
    env_service: EnvComposeService = Depends(get_env_compose_service),
    ai_service: AIConnectionService = Depends(get_ai_connection_service),
    jobs_service: OperationsJobsService = Depends(get_operations_jobs_service),
) -> AIConnectionResponse:
    """Replace the AI key write-only; the audit row carries no secret."""
    try:
        await asyncio.to_thread(
            env_service.update_and_save, {"LITELLM_API_KEY": body.key}
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await jobs_service.append_audit(
        OperationsAuditAppend(
            category="config",
            actor="operator",
            action="replace-ai-key",
            target="LITELLM_API_KEY",
            reason=body.reason,
            detail=json.dumps(
                {"note": "write-only credential replacement", "sensitive": True}
            ),
        )
    )
    return AIConnectionResponse.model_validate(
        await asyncio.to_thread(ai_service.metadata)
    )


@router.post(
    "/ai-connection/test",
    response_model=AIConnectionTestResult,
    dependencies=[Depends(require_operator_api_key)],
)
async def test_ai_connection(
    body: AIConnectionTest,
    service: AIConnectionService = Depends(get_ai_connection_service),
) -> AIConnectionTestResult:
    """Perform a bounded server-side connectivity test without leaking secrets."""
    try:
        return AIConnectionTestResult.model_validate(await service.test())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _history_item(entry: OperationsAuditEntry) -> ConfigHistoryItem:
    """Map an audit entry to a safe history item with explicit eligibility.

    Rollback is eligible only when the entry is a non-sensitive ``update``
    that captured a concrete ``prior_value`` snapshot. Sensitive keys, key
    replacements and reason-less rollbacks are never eligible.
    """
    prior_value: Any = None
    try:
        snapshot = json.loads(entry.detail or "{}")
        prior_value = (
            snapshot.get("prior_value") if isinstance(snapshot, dict) else None
        )
    except json.JSONDecodeError:
        prior_value = None
    eligible = (
        entry.action == "update"
        and not _is_sensitive(entry.target)
        and prior_value is not None
        and entry.target in BOOT_ENV_KEYS
    )
    return ConfigHistoryItem(
        id=entry.id,
        at=entry.at.isoformat(),
        actor=entry.actor,
        action=entry.action,
        target=entry.target,
        reason=entry.reason,
        rollback_eligible=eligible,
    )


@router.get(
    "/configuration/history",
    response_model=list[ConfigHistoryItem],
    dependencies=[Depends(require_api_key)],
)
async def config_history(
    jobs_service: OperationsJobsService = Depends(get_operations_jobs_service),
) -> list[ConfigHistoryItem]:
    """Return config-only audit rows, most-recent first, without secrets."""
    entries = await jobs_service.query_audit(category="config")
    return [_history_item(entry) for entry in entries]


@router.post(
    "/configuration/history/{entry_id}/rollback",
    response_model=ConfigRollbackResult,
    dependencies=[Depends(require_operator_api_key)],
)
async def rollback_config(
    entry_id: int,
    body: ConfigRollbackRequest,
    env_service: EnvComposeService = Depends(get_env_compose_service),
    jobs_service: OperationsJobsService = Depends(get_operations_jobs_service),
) -> ConfigRollbackResult:
    """Re-apply a captured non-secret prior value after explicit confirmation.

    Sensitive targets, entries without a usable snapshot and unconfirmed
    requests are rejected safely; a successful rollback appends a new
    redacted ``config`` audit row.
    """
    if not body.confirmed:
        raise HTTPException(status_code=400, detail="Rollback requires confirmed=true")
    entry = await jobs_service.get_audit(entry_id)
    if entry is None or entry.category != "config":
        raise HTTPException(
            status_code=404, detail="Configuration audit entry not found"
        )
    if _is_sensitive(entry.target) or entry.target not in BOOT_ENV_KEYS:
        raise HTTPException(
            status_code=409, detail="Entry is not eligible for rollback"
        )
    try:
        snapshot = json.loads(entry.detail or "{}")
        prior = snapshot.get("prior_value") if isinstance(snapshot, dict) else None
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=409, detail="Rollback snapshot is invalid"
        ) from exc
    if prior is None:
        raise HTTPException(
            status_code=409, detail="Rollback snapshot is unavailable for this entry"
        )
    try:
        _, changed, _ = await asyncio.to_thread(
            env_service.update_and_save, {entry.target: str(prior)}
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await jobs_service.append_audit(
        OperationsAuditAppend(
            category="config",
            actor="operator",
            action="rollback",
            target=entry.target,
            reason=body.reason,
            detail=json.dumps(
                {"rollback_of": entry_id, "prior_value": None, "sensitive": False}
            ),
        )
    )
    return ConfigRollbackResult(success=True, target=entry.target, changed_keys=changed)
