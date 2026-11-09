"""Docker service for querying container status and logs.

Uses the Docker SDK to inspect containers, retrieve their status,
and fetch log output. Requires Docker socket access.
"""

from __future__ import annotations

from typing import Any

import docker
import docker.errors
from loguru import logger

from otalon_api.settings import Settings

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


class DockerService:
    """Service for Docker container management and status queries."""

    def __init__(self, settings: Settings, socket_path: str = "/var/run/docker.sock") -> None:
        """Initialize DockerService.

        Args:
            settings: Application settings.
            socket_path: Path to the Docker socket.
        """
        self._settings = settings
        self._socket_path = socket_path
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
        """Check if the Docker daemon is accessible.

        Returns:
            A tuple of (available, detail_message).
        """
        try:
            self._get_client()
            return True, "ok"
        except RuntimeError as exc:
            return False, str(exc)

    def list_containers(self, all_: bool = True) -> list[dict[str, Any]]:
        """List all Docker containers with status information.

        Args:
            all_: If True, include stopped containers.

        Returns:
            A list of container info dictionaries.
        """
        try:
            client = self._get_client()
        except RuntimeError as exc:
            logger.warning("Cannot list containers: {}", exc)
            return []

        containers = client.containers.list(all=all_)
        result: list[dict[str, Any]] = []
        for container in containers:
            if container.name in ALLOWED_SERVICES:
                item = self._container_to_dict(container)
                item["core_db"] = container.name in {"postgres", "influxdb3"}
                result.append(item)
        return result

    def get_container_status(self, name: str) -> dict[str, Any] | None:
        """Get status of a specific container by name.

        Args:
            name: The container name to look up.

        Returns:
            A container info dict, or None if not found.
        """
        try:
            client = self._get_client()
            container = client.containers.get(name)
            return self._container_to_dict(container)
        except docker.errors.NotFound:
            return None
        except Exception as exc:
            logger.warning("Error getting container {}: {}", name, exc)
            return None

    def get_container_logs(self, name: str, tail: int = 100) -> str:
        """Retrieve recent log lines from a container.

        Args:
            name: The container name.
            tail: Number of recent lines to return.

        Returns:
            The log output as a string.

        Raises:
            ValueError: If the container name is not in the allowed service list.
            RuntimeError: If the container is not found or logs cannot be fetched.
        """
        if not self._is_allowed_container(name):
            raise ValueError(f"Container '{name}' is not in the allowed services list")

        try:
            client = self._get_client()
            container = client.containers.get(name)
            logs = container.logs(stdout=True, stderr=True, tail=tail, stream=False)
            if isinstance(logs, (bytes, bytearray)):
                return logs.decode("utf-8", errors="replace")
            return str(logs)
        except docker.errors.NotFound as exc:
            raise RuntimeError(f"Container '{name}' not found") from exc
        except Exception as exc:
            raise RuntimeError(f"Failed to get logs for '{name}': {exc}") from exc

    @staticmethod
    def _container_to_dict(container: Any) -> dict[str, Any]:
        """Convert a Docker container object to a serializable dict.

        Args:
            container: A docker.models.containers.Container instance.

        Returns:
            A dictionary with name, status, exit_code, image, created, ports, and health.
            ``exit_code`` mirrors Docker's ``State.ExitCode`` (int when the
            container has exited, ``None`` otherwise). Required by the
            boundary-retrain orchestrator (Phase-6 F1) so a crashed
            otalon-clas trainer is not mistaken for a clean
            ``sys.exit(0)``.
        """
        attrs = container.attrs or {}
        state = attrs.get("State", {})

        health_status = ""
        health_data = state.get("Health")
        if health_data:
            health_status = health_data.get("Status", "")

        ports = attrs.get("NetworkSettings", {}).get("Ports", {}) or {}

        image_tags: list[str] = []
        try:
            image_tags = container.image.tags if container.image else []
        except Exception:
            pass
        image_name = image_tags[0] if image_tags else attrs.get("Config", {}).get("Image", "unknown")

        # State.ExitCode is meaningful only for terminated containers; a
        # running container reports 0 here, which would be misleading. We
        # surface the raw int when the container is in a terminal status
        # ("exited"/"dead") and ``None`` otherwise.
        exit_code: int | None = None
        container_status = container.status or ""
        if container_status in ("exited", "dead"):
            raw_exit = state.get("ExitCode")
            if isinstance(raw_exit, bool):
                # bool is a subclass of int — coerce explicitly.
                exit_code = int(raw_exit)
            elif isinstance(raw_exit, int):
                exit_code = raw_exit
            elif raw_exit is not None:
                try:
                    exit_code = int(raw_exit)
                except (TypeError, ValueError):
                    exit_code = None

        return {
            "name": container.name or "",
            "status": container_status,
            "exit_code": exit_code,
            "image": image_name,
            "created": attrs.get("Created", ""),
            "ports": ports,
            "health": health_status,
        }

    @staticmethod
    def _is_allowed_container(name: str) -> bool:
        """Check if a container name matches an allowed service.

        Args:
            name: The container name to validate.

        Returns:
            True if the container name is in the allowed list.
        """
        return name in ALLOWED_SERVICES
