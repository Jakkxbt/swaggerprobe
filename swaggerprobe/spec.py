import json
import os
import urllib.request

from .models import Operation, Param


READ_METHODS = {"GET", "HEAD", "OPTIONS"}


def load_spec(source):
    raw = _read_source(source)
    data = _parse_json_or_yaml(raw, source)
    base = _base_from_spec(data)
    return data, normalize(data), base


def _read_source(source):
    if source.startswith(("http://", "https://")):
        with urllib.request.urlopen(source, timeout=20) as resp:
            return resp.read().decode("utf-8", "replace")
    with open(os.path.expanduser(source), "r", encoding="utf-8") as handle:
        return handle.read()


def _parse_json_or_yaml(raw, source):
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        try:
            import yaml
        except ImportError as exc:
            raise SystemExit(
                "YAML spec support requires PyYAML: python3 -m pip install PyYAML"
            ) from exc
        return yaml.safe_load(raw)


def _base_from_spec(data):
    if str(data.get("openapi") or "").startswith("3"):
        servers = data.get("servers") or []
        if servers and isinstance(servers[0], dict):
            return servers[0].get("url", "")
        return ""
    scheme = (data.get("schemes") or ["http"])[0]
    host = data.get("host", "")
    base_path = data.get("basePath", "")
    return f"{scheme}://{host}{base_path}" if host else base_path


def normalize(data):
    if not isinstance(data, dict):
        raise ValueError("Spec must be a JSON/YAML object")
    if str(data.get("openapi") or "").startswith("3"):
        return _normalize_v3(data)
    if data.get("swagger") == "2.0":
        return _normalize_v2(data)
    raise ValueError("Unsupported spec version; expected Swagger 2.0 or OpenAPI 3.x")


def _normalize_v3(data):
    ops = []
    global_security = data.get("security")
    for path, item in (data.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        path_params = [_param_v3(p) for p in (item.get("parameters") or []) if isinstance(p, dict)]
        for method, raw in item.items():
            if method.lower() not in _http_methods():
                continue
            if not isinstance(raw, dict):
                continue
            params = path_params + [_param_v3(p) for p in (raw.get("parameters") or []) if isinstance(p, dict)]
            body = _request_body_v3(raw.get("requestBody") or {})
            ops.append(Operation(
                operation_id=raw.get("operationId") or f"{method}_{path}",
                method=method.upper(),
                path=path,
                params=tuple(params),
                request_body=body,
                security=raw.get("security", global_security),
                responses=raw.get("responses") or {},
            ))
    return ops


def _normalize_v2(data):
    ops = []
    global_security = data.get("security")
    for path, item in (data.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        path_params = [_param_v2(p) for p in (item.get("parameters") or []) if isinstance(p, dict)]
        for method, raw in item.items():
            if method.lower() not in _http_methods():
                continue
            if not isinstance(raw, dict):
                continue
            params = path_params + [_param_v2(p) for p in (raw.get("parameters") or []) if isinstance(p, dict)]
            body = {}
            non_body = []
            for p in params:
                if p.location == "body":
                    body = p.schema
                else:
                    non_body.append(p)
            ops.append(Operation(
                operation_id=raw.get("operationId") or f"{method}_{path}",
                method=method.upper(),
                path=path,
                params=tuple(non_body),
                request_body=body,
                security=raw.get("security", global_security),
                responses=raw.get("responses") or {},
            ))
    return ops


def paths_to_methods(ops):
    out = {}
    for op in ops:
        out.setdefault(op.path, set()).add(op.method)
    return out


def _param_v3(raw):
    schema = raw.get("schema") or {}
    return Param(raw.get("name", ""), raw.get("in", "query"), raw.get("required", False),
                 schema.get("type", "string"), schema)


def _param_v2(raw):
    schema = raw.get("schema") or {}
    typ = raw.get("type") or schema.get("type", "string")
    return Param(raw.get("name", ""), raw.get("in", "query"), raw.get("required", False),
                 typ, schema or raw)


def _request_body_v3(raw):
    content = raw.get("content") or {}
    for ctype in ("application/json", "application/x-www-form-urlencoded", "multipart/form-data"):
        if ctype in content:
            return content[ctype].get("schema") or {}
    if content:
        first = next(iter(content.values()))
        return first.get("schema") or {}
    return {}


def _http_methods():
    return {"get", "post", "put", "patch", "delete", "head", "options"}
