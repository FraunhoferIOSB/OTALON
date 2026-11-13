"""The Desktop profile cannot inherit raw capture or physical host access."""

import json
import subprocess
from pathlib import Path


def test_desktop_overlay_removes_host_network_and_privileges(tmp_path):
    root = Path(__file__).parents[3]
    assert (root / "docker-compose.wsl.yml").exists(), "Desktop runtime overlay missing"
    sample = (root / ".env.compose.sample").read_text()
    # Synthetic render only: no container creation, socket or database access.
    import re

    sample = re.sub(r"<[^>]+>", "fixture", sample)
    sample = re.sub(r"^WORKSPACE_DIR=.*$", "WORKSPACE_DIR=" + str(root), sample, flags=re.M)
    sample = re.sub(r"^POSTGRES_PASSWORD=.*$", "POSTGRES_PASSWORD=fixture-only", sample, flags=re.M)
    (tmp_path / "env").write_text(sample)
    (tmp_path / ".env.compose").write_text(sample)
    for name in ["docker-compose.yml", "docker-compose.wsl.yml"]:
        (tmp_path / name).write_bytes((root / name).read_bytes())
    result = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            str(tmp_path / "env"),
            "-f",
            str(tmp_path / "docker-compose.yml"),
            "-f",
            str(tmp_path / "docker-compose.wsl.yml"),
            "--profile",
            "all",
            "config",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    services = json.loads(result.stdout)["services"]
    for name in ["otalon-capture", "otalon-scan"]:
        assert not services[name].get("network_mode")
        assert not services[name].get("cap_add")
        assert "ALL" in services[name]["cap_drop"]
    assert "desktop_ingest.main" in services["otalon-capture"]["command"]
    assert services["otalon-scan"]["command"] == [
        "python", "-m", "uvicorn", "otalon_scan.api.server:app",
        "--host", "0.0.0.0", "--port", "8091", "--forwarded-allow-ips", "*",
    ]
    assert services["otalon-capture"]["environment"]["INFLUX_URL"] == "http://influxdb3:8181"
    assert services["otalon-api"]["environment"]["PCAP_RECORDER_HOST"] == "otalon-capture"
    assert services["otalon-clas"]["environment"]["CONTINUOUS_RECOVERY_ENABLED"] == "true"
    targets = {v["target"] for v in services["otalon-api"]["volumes"]}
    assert not any(v.startswith("/host-storage/") for v in targets)
    assert services["postgres"]["ports"][0]["host_ip"] == "127.0.0.1"
