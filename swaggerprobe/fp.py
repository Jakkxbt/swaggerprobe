FP_TOKENS = (
    "example", "sample", "demo", "placeholder", "dummy", "test value",
    "not found", "route not found", "cannot get", "swagger", "openapi",
)


def is_false_positive(finding):
    evidence = (finding.evidence or "").lower()
    if any(token in evidence for token in FP_TOKENS):
        return True
    if finding.response_status == 404 and finding.check not in {"method"}:
        return True
    return False
