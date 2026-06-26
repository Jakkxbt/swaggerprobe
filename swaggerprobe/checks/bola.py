import re

from ..models import Finding
from ..request import build_request, send

ID_RE = re.compile(r"^(id|.*_id|uuid|guid|.*Id)$")


def run(op, ctx, baseline):
    targets = [p for p in op.params if p.location in {"path", "query"} and _is_id_param(p)]
    if not targets:
        return []
    findings = []
    if ctx.auth_a and ctx.auth_b:
        for param in targets:
            req_a, meta_a = build_request(op, ctx.base_url, ctx.auth_a, overrides={param.name: "1"})
            req_b, meta_b = build_request(op, ctx.base_url, ctx.auth_b, overrides={param.name: "2"})
            resp_a = send(req_a, timeout=ctx.timeout)
            resp_b = send(req_b, timeout=ctx.timeout)
            ctx.requests_sent += 2
            req_cross, meta_cross = build_request(op, ctx.base_url, ctx.auth_b, overrides={param.name: "1"})
            resp_cross = send(req_cross, timeout=ctx.timeout)
            ctx.requests_sent += 1
            if 200 <= resp_cross.status < 300 and resp_cross.body and resp_cross.body != resp_b.body and _shares_marker(resp_cross.body, resp_a.body):
                findings.append(Finding("HIGH", "bola", op.method, op.path, meta_cross, resp_cross.status,
                                        f"auth-b accessed auth-a {param.name}=1 marker", "HIGH"))
    else:
        for param in targets:
            req, meta = build_request(op, ctx.base_url, ctx.auth, overrides={param.name: "2"})
            resp = send(req, timeout=ctx.timeout)
            ctx.requests_sent += 1
            base_resp = baseline["response"]
            if 200 <= resp.status < 300 and resp.body and resp.body != base_resp.body and "owner" in resp.body.lower():
                findings.append(Finding("MEDIUM", "bola", op.method, op.path, meta, resp.status,
                                        f"ID enumeration changed object for {param.name}", "LOW"))
    return findings


def _is_id_param(param):
    return ID_RE.match(param.name) or param.typ in {"integer", "number"} or "uuid" in (param.schema.get("format") or "")


def _shares_marker(cross, original):
    if not original:
        return False
    for marker in ("ownerA", "order-a", "alice", '"owner":"A"', '"id":1'):
        if marker in original and marker in cross:
            return True
    return cross == original
