import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from .models import HttpResponse


DEFAULT_TIMEOUT = 10


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects, but drop credentials when the host changes so an
    Authorization/Cookie header set for the original host is never replayed to a
    redirect target on a different host."""

    _SENSITIVE = ("authorization", "cookie", "proxy-authorization")

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is None:
            return None
        old_host = urllib.parse.urlsplit(req.full_url).netloc
        new_host = urllib.parse.urlsplit(newurl).netloc
        if old_host != new_host:
            for name in list(new.headers):
                if name.lower() in self._SENSITIVE:
                    del new.headers[name]
        return new


_OPENER = urllib.request.build_opener(_SafeRedirectHandler)


def parse_headers(values):
    headers = {}
    for value in values or []:
        if ":" not in value:
            raise ValueError(f"Header must be NAME: value, got {value!r}")
        name, val = value.split(":", 1)
        headers[name.strip()] = val.strip()
    return headers


def build_request(op, base_url, auth_headers=None, overrides=None, method=None, body_extra=None):
    overrides = overrides or {}
    headers = {"User-Agent": "swaggerprobe/0.1"}
    headers.update(auth_headers or {})
    used_method = (method or op.method).upper()
    path = op.path
    query = {}
    body = None

    for param in op.params:
        value = overrides.get(param.name, sample_value(param.name, param.typ, param.schema))
        if param.location == "path":
            path = path.replace("{" + param.name + "}", urllib.parse.quote(str(value), safe=""))
        elif param.location == "query":
            query[param.name] = value
        elif param.location == "header":
            headers[param.name] = str(value)

    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    if query:
        url += "?" + urllib.parse.urlencode(query, doseq=True)

    if op.request_body and used_method not in {"GET", "HEAD"}:
        body = sample_body(op.request_body)
        if body_extra and isinstance(body, dict):
            body.update(body_extra)
        headers.setdefault("Content-Type", "application/json")

    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=used_method)
    return req, {
        "method": used_method,
        "url": url,
        "headers": dict(headers),
        "body": body,
    }


def send(req, timeout=DEFAULT_TIMEOUT):
    start = time.time()
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            body = resp.read(51200).decode("utf-8", "replace")
            return HttpResponse(resp.status, dict(resp.headers), body, time.time() - start)
    except urllib.error.HTTPError as exc:
        body = exc.read(51200).decode("utf-8", "replace")
        return HttpResponse(exc.code, dict(exc.headers), body, time.time() - start)
    except urllib.error.URLError as exc:
        return HttpResponse(0, {}, str(exc.reason), time.time() - start)


def sample_value(name, typ="string", schema=None):
    schema = schema or {}
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    lname = name.lower()
    if lname in {"id", "order_id"} or lname.endswith("_id") or lname.endswith("id"):
        return "1"
    if typ in {"integer", "number"}:
        return 1
    if typ == "boolean":
        return True
    if "uuid" in (schema.get("format") or "").lower():
        return "11111111-1111-1111-1111-111111111111"
    if "email" in lname:
        return "user@example.com"
    if "search" in lname or "q" == lname:
        return "test"
    return "test"


def sample_body(schema):
    if not schema:
        return {}
    if schema.get("type") == "array":
        return [sample_body(schema.get("items") or {})]
    props = schema.get("properties") or {}
    return {name: sample_value(name, prop.get("type", "string"), prop) for name, prop in props.items()}


def mutate_param_value(value, payload):
    if isinstance(value, int):
        return payload
    return payload


def body_contains_json_field(body, field):
    try:
        parsed = json.loads(body)
    except Exception:
        return re.search(r'"?' + re.escape(field) + r'"?\s*[:=]', body, re.I) is not None
    if isinstance(parsed, dict):
        return field in parsed or any(isinstance(v, dict) and field in v for v in parsed.values())
    return False
