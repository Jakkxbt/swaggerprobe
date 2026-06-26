import json

from .fp import is_false_positive

ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def clean_findings(findings):
    seen = set()
    out = []
    for finding in findings:
        if is_false_positive(finding):
            continue
        sig = finding.signature()
        if sig in seen:
            continue
        seen.add(sig)
        out.append(finding)
    return sorted(out, key=lambda f: (ORDER.get(f.severity, 9), f.method, f.path, f.check))


def to_dict(findings, summary):
    return {"summary": summary, "findings": [f.__dict__ for f in findings]}


def write_json(path, findings, summary):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(to_dict(findings, summary), handle, indent=2, sort_keys=True)
        handle.write("\n")


def write_markdown(path, findings, summary):
    lines = [
        "# SwaggerProbe Report",
        "",
        f"- Operations tested: {summary.get('operations', 0)}",
        f"- Requests sent: {summary.get('requests_sent', 0)}",
        f"- Findings: {len(findings)}",
        "",
    ]
    for f in findings:
        lines.extend([
            f"## {f.severity} - {f.check} - {f.method} {f.path}",
            "",
            f"Evidence: {f.evidence}",
            "",
            f"Status: `{f.response_status}`",
            "",
            "Request:",
            "```json",
            json.dumps(f.request, indent=2, sort_keys=True),
            "```",
            "",
        ])
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))


def console(findings, summary, verbose=True):
    if not verbose:
        return
    print(f"Operations: {summary.get('operations', 0)}  Requests: {summary.get('requests_sent', 0)}  Findings: {len(findings)}")
    if not findings:
        print("No findings.")
        return
    print("SEVERITY  CHECK        TARGET                    EVIDENCE")
    for f in findings:
        target = f"{f.method} {f.path}"[:24]
        print(f"{f.severity:<9} {f.check:<12} {target:<25} {f.evidence[:90]}")
