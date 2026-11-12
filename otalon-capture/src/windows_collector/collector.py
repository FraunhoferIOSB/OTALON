"""Non-destructive dumpcap rotation, durable custody, verified HTTPS retries."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import re
import shutil
import signal
import sqlite3
import ssl
import subprocess
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from desktop_ingest.pcap import validate


def command(executable, interface, output, seconds, size_kb):
    return [
        str(executable),
        "-i",
        interface,
        "-F",
        "pcap",
        "-s",
        "65535",
        "-w",
        str(output),
        "-b",
        "duration:" + str(seconds),
        "-b",
        "filesize:" + str(size_kb),
        "-b",
        "printname:stdout",
    ]


class Spool:
    def __init__(self, root):
        self.root = Path(root).absolute()
        self.root.mkdir(parents=True, exist_ok=True)
        if self.root.is_symlink():
            raise ValueError("unsafe spool")
        self.db = sqlite3.connect(self.root / "collector.sqlite3")
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;
CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY,
    seq INTEGER UNIQUE,
    predecessor TEXT,
    ended INTEGER DEFAULT 0,
    end_sent INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS files(run TEXT,
    ordinal INTEGER,
    path TEXT UNIQUE,
    hash TEXT,
    size INTEGER,
    acked INTEGER DEFAULT 0,
    PRIMARY KEY(run,
    ordinal));""")

    def close(self):
        self.db.close()

    def begin_run(self):
        old = self.db.execute("SELECT * FROM runs ORDER BY seq DESC LIMIT 1").fetchone()
        run = uuid.uuid4().hex
        with self.db:
            self.db.execute(
                "INSERT INTO runs(id,seq,predecessor) VALUES(?,?,?)",
                (run, old["seq"] + 1 if old else 0, old["id"] if old else None),
            )
        return run

    def closed_file(self, run, path):
        path = Path(path)
        if not path.is_absolute():
            path = self.root / path
        path = path.absolute()
        if path.is_symlink() or not path.is_relative_to(self.root) or not path.is_file():
            raise ValueError("unowned capture file")
        if self.db.execute("SELECT 1 FROM files WHERE path=?", (str(path),)).fetchone():
            return
        payload = path.read_bytes()
        validate(payload)
        digest = hashlib.sha256(payload).hexdigest()
        match = re.fullmatch(re.escape(run) + r"_([0-9]+)_[0-9]{14}\.pcap", path.name)
        if not match:
            raise ValueError("capture filename does not identify owned run/ordinal")
        ordinal = int(match[1]) - 1
        if ordinal < 0:
            raise ValueError("invalid capture ordinal")
        with path.open("rb") as f:
            os.fsync(f.fileno())
        with self.db:
            self.db.execute(
                "INSERT INTO files(run,ordinal,path,hash,size) VALUES(?,?,?,?,?)",
                (run, ordinal, str(path), digest, path.stat().st_size),
            )

    def pending(self):
        return [
            dict(r)
            for r in self.db.execute(
                "SELECT f.* FROM files f JOIN runs r ON r.id=f.run WHERE acked=0 ORDER BY r.seq,f.ordinal"
            )
        ]

    def acknowledge(self, run, ordinal, digest):
        row = self.db.execute("SELECT * FROM files WHERE run=? AND ordinal=?", (run, ordinal)).fetchone()
        if not row or row["hash"] != digest:
            raise ValueError("receipt identity mismatch")
        path = Path(row["path"])
        if path.exists() and (path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            raise ValueError("owned file mutated")
        with self.db:
            self.db.execute("UPDATE files SET acked=1 WHERE run=? AND ordinal=?", (run, ordinal))
        path.unlink(missing_ok=True)

    def end_run(self, run):
        with self.db:
            self.db.execute("UPDATE runs SET ended=1 WHERE id=?", (run,))


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError("redirect refused")


class Transport:
    def __init__(self, url, key_file, ca_file, interface="fixture", fingerprint="a" * 64):
        self.interface = interface
        self.fingerprint = fingerprint
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("verified HTTPS required")
        self.url = url.rstrip("/")
        self.key = Path(key_file).read_text().strip()
        if len(self.key) < 32:
            raise ValueError("source credential required")
        self.opener = build_opener(HTTPSHandler(context=ssl.create_default_context(cafile=str(ca_file))), NoRedirect())

    def request(self, path, body=None, method="POST", raw=False):
        data = body if raw else json.dumps(body).encode() if body is not None else None
        headers = {"X-Source-Key": self.key, "Content-Type": "application/octet-stream" if raw else "application/json"}
        if raw:
            headers["X-Chunk-SHA256"] = hashlib.sha256(data).hexdigest()
        request = Request(self.url + path, data=data, method=method, headers=headers)
        with self.opener.open(request, timeout=10) as response:
            return json.load(response)

    def flush(self, spool):
        for run in spool.db.execute("SELECT * FROM runs ORDER BY seq").fetchall():
            self.request(
                "/ingest/v1/runs/" + run["id"],
                {
                    "version": 1,
                    "interface_id": self.interface,
                    "capture_fingerprint": self.fingerprint,
                    "predecessor": run["predecessor"],
                },
                "PUT",
            )
            for row in [f for f in spool.pending() if f["run"] == run["id"]]:
                data = Path(row["path"]).read_bytes()
                if len(data) != row["size"] or hashlib.sha256(data).hexdigest() != row["hash"]:
                    raise ValueError("spool changed")
                result = self.request(
                    "/ingest/v1/runs/" + run["id"] + "/chunks/" + str(row["ordinal"]), data, "PUT", True
                )
                if result.get("accepted") is not True or result.get("hash") != row["hash"]:
                    raise ValueError("unproven custody")
                receipt = self.request("/ingest/v1/runs/" + run["id"] + "/chunks/" + str(row["ordinal"]), method="GET")
                if (
                    receipt.get("custody") != "accepted"
                    or receipt.get("hash") != row["hash"]
                    or receipt.get("size_bytes") != row["size"]
                ):
                    raise ValueError("receipt readback mismatch")
                spool.acknowledge(run["id"], row["ordinal"], row["hash"])
            if run["ended"] and not run["end_sent"]:
                last = spool.db.execute(
                    "SELECT COALESCE(MAX(ordinal),-1) FROM files WHERE run=?", (run["id"],)
                ).fetchone()[0]
                self.request("/ingest/v1/runs/" + run["id"] + "/end", {"last_ordinal": last})
                with spool.db:
                    spool.db.execute("UPDATE runs SET end_sent=1 WHERE id=?", (run["id"],))


def secure_windows_root(root):
    if os.name != "nt":
        raise ValueError("collector requires native Windows, not WSL")
    root.mkdir(parents=True, exist_ok=True)
    # Restrict inherited access before writing any capture/key material.
    subprocess.run(
        [
            "icacls",
            str(root),
            "/inheritance:r",
            "/grant:r",
            os.environ["USERDOMAIN"] + "\\" + os.environ["USERNAME"] + ":(OI)(CI)F",
        ],
        check=True,
        capture_output=True,
    )
    for p in [root, *root.parents]:
        if p.exists() and getattr(p.stat(), "st_file_attributes", 0) & 0x400:
            raise ValueError("reparse spool path refused")


def previous_owner_alive(pid):
    if not isinstance(pid, int) or pid <= 0:
        raise RuntimeError("previous owner identity invalid")
    try:
        result = subprocess.run(
            ["tasklist", "/FI", "PID eq " + str(pid), "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("previous owner status unavailable") from exc
    if result.returncode != 0 or not result.stdout.strip():
        raise RuntimeError("previous owner status unavailable")
    return '"' + str(pid) + '"' in result.stdout


def main():
    parser = argparse.ArgumentParser(description="Continuous Windows physical capture with automatic durable handoff")
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    cfg = json.loads(Path(args.config).read_text())
    root = Path(cfg["spool"]).absolute()
    secure_windows_root(root)
    exe = Path(cfg["dumpcap"])
    interface = cfg["interface"]
    if not exe.is_absolute() or not exe.is_file() or not interface.startswith("\\Device\\NPF_"):
        raise ValueError("absolute dumpcap and Npcap interface required")
    help_text = subprocess.check_output([str(exe), "-h"], text=True, stderr=subprocess.STDOUT)
    if "printname" not in help_text:
        raise ValueError("dumpcap printname close notifications required")
    devices = subprocess.check_output([str(exe), "-D"], text=True, stderr=subprocess.STDOUT)
    if interface not in devices:
        raise ValueError("selected Npcap interface unavailable")
    spool = Spool(root)
    transport = Transport(
        cfg["url"],
        cfg["key_file"],
        cfg["ca_file"],
        interface,
        hashlib.sha256(
            json.dumps({"interface": interface, "snaplen": 65535, "linktype": 1}, sort_keys=True).encode()
        ).hexdigest(),
    )
    stop = threading.Event()
    closed = queue.Queue(maxsize=1024)
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    # Crash reconciliation: only after positive owner PID absence, validate every
    # final file. Never use size stability as a close notification.
    pid_file = root / "owner.json"
    if pid_file.exists():
        previous = json.loads(pid_file.read_text())
        if previous_owner_alive(previous["pid"]):
            raise ValueError("previous collector still running")
        run = previous["run"]
        for path in sorted(root.glob(run + "_*.pcap")):
            spool.closed_file(run, path)
        spool.end_run(run)
    run = spool.begin_run()
    output = root / (run + ".pcap")
    proc = subprocess.Popen(
        command(exe, interface, output, cfg.get("chunk_seconds", 2), cfg.get("chunk_kb", 8192)),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
    )
    pid_file.write_text(json.dumps({"pid": proc.pid, "run": run}))

    def reader():
        assert proc.stdout is not None
        for line in proc.stdout:
            closed.put(line.strip())

    def drain():
        assert proc.stderr is not None
        for _ in proc.stderr:
            pass  # Never persist raw stderr, paths or credentials.

    reader_thread = threading.Thread(target=reader, daemon=True)
    reader_thread.start()
    threading.Thread(target=drain, daemon=True).start()
    retry = 0
    try:
        while not stop.is_set() and proc.poll() is None:
            try:
                while True:
                    spool.closed_file(run, Path(closed.get_nowait()))
            except queue.Empty:
                pass
            if shutil.disk_usage(root).free < cfg.get("min_free_bytes", 1_000_000_000) or sum(
                r["size"] for r in spool.pending()
            ) > cfg.get("max_spool_bytes", 2_000_000_000):
                stop.set()
                print("Capture stopped: spool storage limit; pending data retained")
                break
            if time.monotonic() >= retry:
                try:
                    transport.flush(spool)
                    transport.request("/ingest/v1/observation", {"interface": interface, "recording": True})
                    retry = time.monotonic() + 2
                except Exception:
                    retry = time.monotonic() + 5
                    print("Receiver unavailable: capture continues, durable backlog retained")
            time.sleep(0.2)
    finally:
        if proc.poll() is None:
            proc.send_signal(getattr(signal, "CTRL_BREAK_EVENT"))
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                raise RuntimeError("capture hard-stopped; final file needs reconciliation")
        reader_thread.join(timeout=5)
        if reader_thread.is_alive():
            raise RuntimeError("capture close notifications incomplete")
        while not closed.empty():
            spool.closed_file(run, Path(closed.get()))
        for path in sorted(root.glob(run + "_*.pcap")):
            spool.closed_file(run, path)
        spool.end_run(run)
        pid_file.unlink(missing_ok=True)
        try:
            transport.flush(spool)
            transport.request("/ingest/v1/observation", {"interface": interface, "recording": False})
        except Exception:
            print("Pending capture retained for next collector start")
        spool.close()


if __name__ == "__main__":
    main()
