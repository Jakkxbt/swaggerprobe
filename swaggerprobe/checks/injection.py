import re
import time

from ..models import Finding
from ..request import build_request, send

PAYLOADS = ["'", "../../../../etc/passwd", "$(id)"]
ERROR_RE = re.compile(r"(sql syntax|sqlite|mysql|postgres|ora-|odbc|traceback|root:x:0:0|uid=\d+|syntax error)", re.I)

# SSTI probes across template engines. Each payload evaluates 7*7; a reflected
# "49" that was not in the baseline is server-side evaluation. Covering the
# common engine syntaxes catches Freemarker/JSP-EL/Ruby/ERB SSTI, not just Jinja.
SSTI_PROBES = [
    ("{{7*7}}", "49"),      # Jinja2, Twig, Nunjucks
    ("${7*7}", "49"),       # Freemarker, JSP EL, Thymeleaf
    ("#{7*7}", "49"),       # Ruby (slim/haml), JSF EL
    ("<%= 7*7 %>", "49"),   # ERB, EJS
]


def run(op, ctx, baseline):
    findings = []
    base_resp = baseline["response"]
    for param in [p for p in op.params if p.location in {"path", "query", "header"}]:
        for payload in PAYLOADS:
            req, meta = build_request(op, ctx.base_url, ctx.auth, overrides={param.name: payload})
            resp = send(req, timeout=ctx.timeout)
            ctx.requests_sent += 1
            evidence = _evidence(resp.body)
            if evidence and evidence not in base_resp.body:
                findings.append(Finding(_severity(evidence), "injection", op.method, op.path, meta, resp.status,
                                        f"{param.name} triggered {evidence}", "HIGH"))
            elif resp.status >= 500 and base_resp.status < 500:
                findings.append(Finding("MEDIUM", "injection", op.method, op.path, meta, resp.status,
                                        f"{param.name} caused HTTP {resp.status} vs baseline {base_resp.status}", "MEDIUM"))
        for payload, expected in SSTI_PROBES:
            req, meta = build_request(op, ctx.base_url, ctx.auth, overrides={param.name: payload})
            resp = send(req, timeout=ctx.timeout)
            ctx.requests_sent += 1
            # Confirmed SSTI: the arithmetic result appears in the response but the
            # literal payload does not (i.e. the server evaluated it, not echoed it),
            # and it was not already present in the baseline body.
            if (expected in resp.body and payload not in resp.body
                    and expected not in base_resp.body):
                findings.append(Finding("HIGH", "injection", op.method, op.path, meta, resp.status,
                                        f"{param.name} evaluated SSTI '{payload}' -> {expected}", "HIGH"))
                break  # one confirmed engine is enough; avoid duplicate findings
        if ctx.time_based:
            req, meta = build_request(op, ctx.base_url, ctx.auth, overrides={param.name: "sleep(2)"})
            first = send(req, timeout=max(ctx.timeout, 5))
            second = send(req, timeout=max(ctx.timeout, 5))
            ctx.requests_sent += 2
            if first.elapsed > base_resp.elapsed + 1.5 and second.elapsed > base_resp.elapsed + 1.5:
                findings.append(Finding("LOW", "injection", op.method, op.path, meta, second.status,
                                        f"{param.name} repeated time delay", "LOW"))
                time.sleep(0)
    return findings


def _evidence(body):
    match = ERROR_RE.search(body or "")
    return match.group(1) if match else ""


def _severity(evidence):
    ev = evidence.lower()
    if "root:x:0:0" in ev:
        return "HIGH"
    if "sql" in ev or "sqlite" in ev or "mysql" in ev:
        return "HIGH"
    return "MEDIUM"
