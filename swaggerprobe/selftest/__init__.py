import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

from .mock_target import MockServer


ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
SPEC = os.path.join(os.path.dirname(__file__), "sample_openapi.yaml")


def main():
    server = MockServer()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    _wait(base)
    try:
        failures = 0
        failures += _assert("dry-run sends no requests", _dry_run_no_requests(base, server))
        result, data = _run_probe(base)
        failures += _assert("probe command exits with findings", result.returncode == 1)
        checks = {f["check"] for f in data["findings"]}
        for check in ("auth", "bola", "injection", "massassign", "method", "errors"):
            failures += _assert(f"{check} planted bug caught", check in checks)
        failures += _assert("clean control endpoint produces zero findings",
                            not any(f["path"] == "/health" for f in data["findings"]))
        failures += _assert("JSON output schema is valid", _valid_schema(data))
        print("SELFTEST PASS" if failures == 0 else "SELFTEST FAIL")
        return 0 if failures == 0 else 1
    finally:
        server.shutdown()
        server.server_close()


def _wait(base):
    for _ in range(40):
        try:
            urllib.request.urlopen(base + "/health", timeout=1).read()
            return
        except Exception:
            time.sleep(0.05)
    raise RuntimeError("mock target did not start")


def _dry_run_no_requests(base, server):
    before = len(server.logs)
    cmd = [sys.executable, "-m", "swaggerprobe", "-s", SPEC, "--base", base, "--allow-write", "-q"]
    proc = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, timeout=30)
    after = len(server.logs)
    return proc.returncode == 0 and after == before


def _run_probe(base):
    with tempfile.NamedTemporaryFile("r", suffix=".json", delete=False) as handle:
        path = handle.name
    cmd = [
        sys.executable, "-m", "swaggerprobe", "-s", SPEC, "--base", base,
        "--auth", "Authorization: Bearer A",
        "--auth-a", "Authorization: Bearer A",
        "--auth-b", "Authorization: Bearer B",
        "--allow-host", "127.0.0.1",
        "--run", "--allow-write", "-q", "-o", path,
    ]
    proc = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, timeout=60)
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    os.unlink(path)
    return proc, data


def _valid_schema(data):
    if sorted(data.keys()) != ["findings", "summary"]:
        return False
    required = {"severity", "check", "method", "path", "request", "response_status", "evidence", "confidence"}
    return all(required <= set(item.keys()) for item in data["findings"])


def _assert(name, ok):
    print(f"{'PASS' if ok else 'FAIL'} {name}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
