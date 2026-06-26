from .request import build_request, send


def capture(op, ctx, auth_headers=None):
    req, meta = build_request(op, ctx.base_url, auth_headers or ctx.auth)
    resp = send(req, timeout=ctx.timeout)
    return {"request": meta, "response": resp}
