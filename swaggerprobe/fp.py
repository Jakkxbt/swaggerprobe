import re

# Boilerplate / placeholder markers that indicate a response is demo or spec
# content rather than a real vulnerability. Matched on word boundaries so a real
# finding whose evidence merely contains a substring (e.g. "exampleId",
# "resampled") is not suppressed. The over-generic single words "example",
# "sample" and "demo" are deliberately excluded — they occur in legitimate leak
# evidence (example.com, sample rows in a real SQL error) and caused genuine
# findings to be discarded.
FP_TOKENS = (
    "placeholder", "dummy", "test value",
    "not found", "route not found", "cannot get", "swagger", "openapi",
)

_FP_RE = re.compile(r"\b(?:" + "|".join(re.escape(t) for t in FP_TOKENS) + r")\b", re.I)


def is_false_positive(finding):
    evidence = finding.evidence or ""
    if _FP_RE.search(evidence):
        return True
    if finding.response_status == 404 and finding.check not in {"method"}:
        return True
    return False
