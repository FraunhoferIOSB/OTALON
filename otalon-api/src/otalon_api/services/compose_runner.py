"""Docker Compose runner service.

Executes Docker Compose commands by spawning a short-lived Docker CLI
container with the compose file and Docker socket mounted. All service
names and actions are validated against allowlists before execution.
"""

from __future__ import annotations

import os
from typing import Any

import docker
from docker.types import Mount
from loguru import logger

from otalon_api.settings import Settings

ALLOWED_ACTIONS: frozenset[str] = frozenset({"up", "stop", "restart", "recreate"})

ALLOWED_SERVICES: frozenset[str] = frozenset(
    {
        "postgres",
        "influxdb3",
        "otalon-capture",
        "otalon-clas",
        "otalon-ui",
        "otalon-api",
        "otalon-scan",
        "otalon-mcp",
        "otalon-ai",
    }
)


class ComposeRunner:
    """Service for executing Docker Compose operations via a CLI container."""

    def __init__(self, settings: Settings) -> None:
        """Initialize ComposeRunner with application settings.

        Args:
            settings: Application settings with compose_image, compose_file, etc.
        """
        self._settings = settings
        self._image = settings.compose_image
        self._compose_file = settings.compose_file
        self._socket_path = "/var/run/docker.sock"
        self._default_timeout_s = 180
        self._client: docker.DockerClient | None = None

    def _get_client(self) -> docker.DockerClient:
        """Lazily initialize and return the Docker client.

        Returns:
            A connected DockerClient instance.

        Raises:
            RuntimeError: If the Docker daemon is not reachable.
        """
        if self._client is None:
            try:
                self._client = docker.from_env()
                self._client.ping()
            except Exception as exc:
                self._client = None
                raise RuntimeError(f"Docker daemon not reachable: {exc}") from exc
        return self._client

    def is_available(self) -> tuple[bool, str]:
        """Check if the Docker daemon and socket are accessible.

        Returns:
            A tuple of (available, detail_message).
        """
        if not os.path.exists(self._socket_path):
            return False, f"docker.sock missing: {self._socket_path}"
        try:
            self._get_client()
            return True, "ok"
        except RuntimeError as exc:
            return False, str(exc)

    def run_action(self, action: str, service: str | None = None) -> dict[str, Any]:
        """Execute a Docker Compose action with validation.

        Args:
            action: The compose action (up, stop, restart, recreate).
            service: The target service name (must be in the allowlist).

        Returns:
            A dict with service, action, exit_code, output, and success fields.

        Raises:
            ValueError: If action or service is not in the allowlist.
        """
        if action not in ALLOWED_ACTIONS:
            raise ValueError(f"Action '{action}' is not allowed. Allowed: {sorted(ALLOWED_ACTIONS)}")

        if service and service not in ALLOWED_SERVICES:
            raise ValueError(f"Service '{service}' is not allowed. Allowed: {sorted(ALLOWED_SERVICES)}")

        args = self._build_compose_args(action, service)
        exit_code, output = self._run_container(args)

        return {
            "service": service or "all",
            "action": action,
            "exit_code": exit_code,
            "output": output,
            "success": exit_code == 0,
        }

    def _build_compose_args(self, action: str, service: str | None) -> list[str]:
        """Build the docker compose command arguments.

        Args:
            action: The compose action.
            service: Optional target service.

        Returns:
            A list of command arguments.
        """
        if action == "up":
            args = ["up", "-d"]
        elif action == "recreate":
            args = ["up", "-d", "--force-recreate", "--no-deps"]
        elif action == "stop":
            args = ["stop"]
        elif action == "restart":
            args = ["restart"]
        else:
            args = [action]

        if service:
            args.append(service)
        return args

    def _run_container(self, args: list[str], timeout_s: int | None = None) -> tuple[int, str]:
        """Spawn a short-lived Docker CLI container to execute compose commands.

        Args:
            args: Compose command arguments.
            timeout_s: Timeout in seconds for the operation.

        Returns:
            A tuple of (exit_code, log_output).
        """
        ok, detail = self.is_available()
        if not ok:
            logger.error("ComposeRunner not available: {}", detail)
            return 127, detail

        try:
            client = self._get_client()
            client.images.get(self._image)
        except docker.errors.ImageNotFound:
            logger.info("Pulling compose runner image: {}", self._image)
            try:
                client = self._get_client()
                client.images.pull(self._image)
            except Exception as exc:
                logger.error("Image pull failed for {}: {}", self._image, exc)
                return 125, f"Image pull failed: {exc}"

        workspace_dir = os.path.dirname(self._compose_file)
        # Pass --env-file explicitly so `up --force-recreate` (recreate action)
        # re-reads .env.compose for both `${VAR}` interpolation and the
        # services' `env_file:` resolution. Without it Compose falls back to a
        # `.env` default and the freshly-written TRAINING_ENABLED/window values
        # would not reach recreated otalon-clas container.
        env_file = getattr(self._settings, "env_compose_path", "") or ""
        cmd = ["docker", "compose", "--project-directory", workspace_dir or ".", "-f", self._compose_file]
        if env_file:
            cmd += ["--env-file", env_file]
        cmd += args

        vols = {self._socket_path: {"bind": "/var/run/docker.sock", "mode": "rw"}}
        mounts: list[Mount] = []
        if workspace_dir and workspace_dir != "/":
            mounts.append(
                Mount(
                    type="bind",
                    source=workspace_dir,
                    target=workspace_dir,
                    read_only=False,
                )
            )

        timeout = timeout_s or self._default_timeout_s

        logger.info("Starting compose runner: {} (timeout={}s)", " ".join(cmd), timeout)

        try:
            client = self._get_client()
            container = client.containers.create(
                image=self._image,
                command=cmd,
                volumes=vols,
                mounts=mounts,
                working_dir=workspace_dir or "/workspace",
                tty=False,
                stdin_open=False,
            )
        except Exception as exc:
            logger.error("Runner container creation failed: {}", exc)
            return 125, f"create failed: {exc}"

        try:
            container.start()
        except Exception as exc:
            try:
                container.remove(force=True)
            except Exception:
                pass
            logger.error("Runner container start failed: {}", exc)
            return 125, f"start failed: {exc}"

        exit_code = 1
        logs_text = ""
        try:
            result = container.wait(timeout=timeout)
            exit_code = int(result.get("StatusCode", 1))
            logs = container.logs(stdout=True, stderr=True, stream=False)
            logs_text = logs.decode("utf-8", errors="replace") if isinstance(logs, (bytes, bytearray)) else str(logs)

            if len(logs_text) > 10000:
                half = 5000
                logs_text = logs_text[:half] + "\n...\n" + logs_text[-half:]

            if exit_code != 0:
                logger.error("Compose runner exited with code {}: {}", exit_code, logs_text[:500])
        except Exception as exc:
            logger.error("Runner wait/logs failed: {}", exc)
            exit_code = 124
            try:
                logs = container.logs(stdout=True, stderr=True, stream=False)
                logs_text = (
                    logs.decode("utf-8", errors="replace") if isinstance(logs, (bytes, bytearray)) else str(logs)
                )
            except Exception:
                pass
        finally:
            try:
                container.remove(force=True)
            except Exception:
                pass

        return exit_code, logs_text
