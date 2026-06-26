import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class MockServer(ThreadingHTTPServer):
    def __init__(self):
        self.logs = []
        super().__init__(("127.0.0.1", 0), Handler)


class Handler(BaseHTTPRequestHandler):
    server_version = "MockTarget/1.0"

    def log_message(self, fmt, *args):
        return

    def _log(self):
        self.server.logs.append((self.command, self.path))

    def _json(self, status, body):
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_GET(self):
        self._log()
        if self.path == "/health":
            return self._json(200, {"ok": True})
        if self.path == "/private":
            return self._json(200, {"secret": "auth bypass data"})
        match = re.match(r"^/orders/([^/?]+)", self.path)
        if match:
            token = self.headers.get("Authorization", "")
            oid = match.group(1)
            if oid == "1":
                return self._json(200, {"id": 1, "owner": "A", "marker": "ownerA", "item": "order-a"})
            if oid == "2" and token.endswith("B"):
                return self._json(200, {"id": 2, "owner": "B", "marker": "ownerB", "item": "order-b"})
            return self._json(403, {"error": "forbidden"})
        if self.path.startswith("/search"):
            if "%27" in self.path or "'" in self.path:
                return self._json(500, {"error": "sqlite SQL syntax error near quote"})
            if "%7B%7B7%2A7%7D%7D" in self.path:
                return self._json(200, {"result": "49"})
            return self._json(200, {"results": []})
        if self.path == "/debug":
            body = b"Traceback (most recent call last):\n  File \"/srv/app.py\", line 7\ndebug=true\n"
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self._json(404, {"error": "not found"})

    def do_POST(self):
        self._log()
        if self.path == "/users":
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8", "replace") if length else "{}"
            try:
                body = json.loads(raw)
            except Exception:
                body = {}
            body.setdefault("id", 99)
            return self._json(200, body)
        self._json(404, {"error": "not found"})

    def do_DELETE(self):
        self._log()
        if self.path == "/public":
            return self._json(200, {"deleted": True})
        self._json(404, {"error": "not found"})

    def do_OPTIONS(self):
        self._log()
        self.send_response(405)
        self.send_header("Allow", "GET,POST,DELETE")
        self.end_headers()

    def do_HEAD(self):
        self._log()
        self.send_response(405)
        self.end_headers()
