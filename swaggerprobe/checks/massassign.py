from ..models import Finding
from ..request import body_contains_json_field, build_request, send

EXTRA = {"is_admin": True, "role": "admin", "verified": True, "balance": 999999}


def run(op, ctx, baseline):
    if not op.request_body or op.method not in {"POST", "PUT", "PATCH"}:
        return []
    req, meta = build_request(op, ctx.base_url, ctx.auth, body_extra=EXTRA)
    resp = send(req, timeout=ctx.timeout)
    ctx.requests_sent += 1
    base_resp = baseline["response"]
    reflected = [field for field in EXTRA if body_contains_json_field(resp.body, field)]
    if reflected:
        return [Finding("HIGH", "massassign", op.method, op.path, meta, resp.status,
                        f"response reflected extra field {reflected[0]}", "HIGH")]
    if resp.status != base_resp.status and resp.status < 500:
        return [Finding("MEDIUM", "massassign", op.method, op.path, meta, resp.status,
                        f"extra fields changed status {base_resp.status}->{resp.status}", "MEDIUM")]
    return []
