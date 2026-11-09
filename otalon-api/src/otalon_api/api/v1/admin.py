"""Admin router.

Provides REST endpoints for Docker container management, Compose actions,
environment variable configuration, and database administration.
All endpoints are protected by the API-key authentication middleware
which intercepts requests to ``/api/v1/admin/*``.
"""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from loguru import logger
from pydantic import BaseModel

from otalon_api.api.schemas.admin import (
    ComposeActionResponse,
    ContainerInfoResponse,
    ContainerListResponse,
    ContainerLogsResponse,
    DbTruncateResponse,
    EnvResponse,
    EnvUpdateResponse,
)
from otalon_api.dependencies import (
    get_compose_runner,
    get_docker_service,
    get_env_compose_service,
    get_operations_jobs_service,
    get_postgres_repo,
)
from otalon_api.domain.operations import OperationsAuditAppend
from otalon_api.repositories.postgres_repo import PostgresRepository
from otalon_api.services.compose_runner import ComposeRunner
from otalon_api.services.docker_service import DockerService
from otalon_api.services.env_compose_service import ALLOWED_ENV_KEYS, EnvComposeService
from otalon_api.services.operations_jobs_service import OperationsJobsService

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


class ComposeActionRequest(BaseModel):
    """Request body for triggering a Docker Compose action."""

    action: str
    service: str | None = None


class EnvValueRequest(BaseModel):
    """Request body for updating a single environment variable."""

    value: str


class DbTruncateRequest(BaseModel):
    """Request body for a database truncate operation."""

    table: str
    cascade: bool = False


@router.get("/containers", response_model=ContainerListResponse)
async def list_containers(
    docker_service: DockerService = Depends(get_docker_service),
) -> ContainerListResponse:
    """List all Docker containers with their status information.

    Args:
        docker_service: Injected Docker service.

    Returns:
        A ContainerListResponse with container info items.
    """
    try:
        raw_containers = await asyncio.to_thread(docker_service.list_containers)
    except Exception as exc:
        logger.error("list_containers failed: {}", exc)
        raise HTTPException(status_code=500, detail="Failed to list Docker containers") from exc

    containers = [ContainerInfoResponse(**c) for c in raw_containers]
    return ContainerListResponse(containers=containers)


@router.get("/containers/{name}/logs", response_model=ContainerLogsResponse)
async def get_container_logs(
    name: str,
    tail: int = 100,
    docker_service: DockerService = Depends(get_docker_service),
) -> ContainerLogsResponse:
    """Retrieve recent log lines from a specific Docker container.

    Args:
        name: The container name (must be in the allowed services list).
        tail: Number of recent log lines to return.
        docker_service: Injected Docker service.

    Returns:
        A ContainerLogsResponse with the log output.

    Raises:
        HTTPException: 404 if the container name is not allowed or not found.
    """
    try:
        logs = await asyncio.to_thread(
            docker_service.get_container_logs,
            name=name,
            tail=tail,
        )
    except ValueError as exc:
        logger.warning("get_container_logs rejected: {}", exc)
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RuntimeError as exc:
        logger.error("get_container_logs failed for {}: {}", name, exc)
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.error("get_container_logs unexpected error for {}: {}", name, exc)
        raise HTTPException(status_code=500, detail="Failed to retrieve container logs") from exc

    return ContainerLogsResponse(name=name, lines=tail, logs=logs)


@router.post("/compose/action", response_model=ComposeActionResponse)
async def run_compose_action(
    body: ComposeActionRequest,
    compose_runner: ComposeRunner = Depends(get_compose_runner),
    jobs_service: OperationsJobsService = Depends(get_operations_jobs_service),
) -> ComposeActionResponse:
    """Execute a Docker Compose action (up, stop, restart, recreate).

    Args:
        body: Request body with action and optional service name.
        compose_runner: Injected Compose runner.
        jobs_service: Service that records the lifecycle job and audit trail.

    Returns:
        A ComposeActionResponse with exit code, output, and success flag.

    Raises:
        HTTPException: 400 if the action or service is not allowed.
    """
    title = f"{body.action.title()} {'service ' + body.service if body.service else 'all services'}"
    job = await jobs_service.record_job(
        type_="service",
        title=title,
        trigger="operator (UI)",
        actor="operator",
        params={"action": body.action, "service": body.service},
        can_cancel=False,
        can_retry=False,
    )
    await jobs_service.start_job(job.id)
    await jobs_service.append_audit(
        OperationsAuditAppend(
            category="service",
            actor="operator",
            action=body.action,
            target=body.service or "all",
            reason=f"Started compose action {body.action} for {body.service or 'all services'}",
        )
    )

    try:
        result = await asyncio.to_thread(
            compose_runner.run_action,
            action=body.action,
            service=body.service,
        )
    except ValueError as exc:
        logger.warning("run_compose_action rejected: {}", exc)
        await jobs_service.fail_job(job.id, error=str(exc))
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.error("run_compose_action failed: {}", exc)
        await jobs_service.fail_job(job.id, error=str(exc))
        raise HTTPException(status_code=500, detail="Failed to execute compose action") from exc

    await jobs_service.maybe_finish_service_job(job.id, result.get("exit_code", 1))
    return ComposeActionResponse(**result)


@router.get("/env", response_model=EnvResponse)
async def get_env(
    env_service: EnvComposeService = Depends(get_env_compose_service),
) -> EnvResponse:
    """Return masked environment variables from ``.env.compose``.

    Args:
        env_service: Injected environment compose service.

    Returns:
        An EnvResponse with masked env vars and the list of editable keys.
    """
    try:
        masked = await asyncio.to_thread(env_service.get_masked_env)
    except Exception as exc:
        logger.error("get_env failed: {}", exc)
        raise HTTPException(status_code=500, detail="Failed to read environment variables") from exc

    return EnvResponse(env=masked, editable_keys=list(ALLOWED_ENV_KEYS))


@router.put("/env/{key}", response_model=EnvUpdateResponse)
async def update_env_key(
    key: str,
    body: EnvValueRequest,
    env_service: EnvComposeService = Depends(get_env_compose_service),
) -> EnvUpdateResponse:
    """Update a single environment variable and persist the change.

    Args:
        key: The ENV key to update (must be in the allowed list).
        body: Request body containing the new value.
        env_service: Injected environment compose service.

    Returns:
        An EnvUpdateResponse with the new env state and changed keys.

    Raises:
        HTTPException: 400 if the key is not allowed or validation fails.
    """
    try:
        new_env, changed_keys, backup_path = await asyncio.to_thread(
            env_service.update_and_save,
            updates={key: body.value},
        )
    except ValueError as exc:
        logger.warning("update_env_key rejected for key={}: {}", key, exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.error("update_env_key failed for key={}: {}", key, exc)
        raise HTTPException(status_code=500, detail="Failed to update environment variable") from exc

    return EnvUpdateResponse(
        env=new_env,
        changed_keys=changed_keys,
        backup_path=backup_path,
    )


@router.post("/db/truncate", response_model=DbTruncateResponse)
async def truncate_table(
    body: DbTruncateRequest,
    request: Request,
    postgres_repo: PostgresRepository = Depends(get_postgres_repo),
) -> DbTruncateResponse:
    """Truncate a database table (restricted to the allowlist).

    Requires the ``X-Confirm: true`` header for safety.

    Args:
        body: Request body with table name and cascade flag.
        request: The incoming HTTP request (used for header validation).
        postgres_repo: Injected PostgreSQL repository.

    Returns:
        A DbTruncateResponse indicating success or failure.

    Raises:
        HTTPException: 400 if the table is not in the allowlist or
            the ``X-Confirm`` header is missing.
    """
    confirm = request.headers.get("X-Confirm", "").lower()
    if confirm != "true":
        raise HTTPException(
            status_code=400,
            detail="Destructive operation requires X-Confirm: true header",
        )
    try:
        await asyncio.to_thread(
            postgres_repo.truncate_table,
            table_name=body.table,
            cascade=body.cascade,
        )
    except ValueError as exc:
        logger.warning("truncate_table rejected: {}", exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.error("truncate_table failed for {}: {}", body.table, exc)
        raise HTTPException(status_code=500, detail="Failed to truncate table") from exc

    return DbTruncateResponse(
        table=body.table,
        success=True,
        message=f"Table '{body.table}' truncated successfully",
    )


@router.delete("/db/{table}")
async def delete_table_rows(
    table: str,
    request: Request,
    postgres_repo: PostgresRepository = Depends(get_postgres_repo),
) -> dict[str, Any]:
    """Delete all rows from a database table (restricted to the allowlist).

    Requires the ``X-Confirm: true`` header for safety.

    Args:
        table: Name of the table to clear.
        request: The incoming HTTP request (used for header validation).
        postgres_repo: Injected PostgreSQL repository.

    Returns:
        A dict with the table name, deleted row count, and success flag.

    Raises:
        HTTPException: 400 if the table is not in the allowlist or
            the ``X-Confirm`` header is missing.
    """
    confirm = request.headers.get("X-Confirm", "").lower()
    if confirm != "true":
        raise HTTPException(
            status_code=400,
            detail="Destructive operation requires X-Confirm: true header",
        )
    try:
        deleted = await asyncio.to_thread(postgres_repo.delete_all_rows, table_name=table)
    except ValueError as exc:
        logger.warning("delete_table_rows rejected: {}", exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.error("delete_table_rows failed for {}: {}", table, exc)
        raise HTTPException(status_code=500, detail="Failed to delete rows from table") from exc

    return {
        "table": table,
        "deleted_rows": deleted,
        "success": True,
    }
