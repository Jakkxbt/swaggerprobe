# SwaggerProbe

OpenAPI and Swagger attack surface tester for authorised security testing. It ingests an API spec, builds real requests for each operation, baselines the documented behavior, and then probes for common bugs exposed by specs: missing auth, BOLA/IDOR, injection, mass assignment, method tampering, and verbose error leakage.

Pure Python standard library for JSON specs. YAML specs require PyYAML:

```bash
python3 -m pip install PyYAML
```

## Installation

Run from the checkout:

```bash
python3 -m swaggerprobe -h
```

Install as a command:

```bash
pipx install .
swaggerprobe -h
```

## Usage

Dry-run is the default and sends no traffic:

```bash
swaggerprobe -s openapi.yaml --base https://api.target.com
```

Active testing requires `--run` and a host allowlist:

```bash
swaggerprobe -s openapi.yaml --base https://api.target.com \
  --auth "Authorization: Bearer <token>" \
  --allow-host api.target.com --run
```

Two-context BOLA testing:

```bash
swaggerprobe -s spec.json --base https://api.target.com \
  --auth-a "Authorization: Bearer A" \
  --auth-b "Authorization: Bearer B" \
  --allow-host api.target.com --run --checks bola
```

Write operations are skipped unless explicitly enabled:

```bash
swaggerprobe -s openapi.yaml --base https://api.target.com \
  --auth "Authorization: Bearer <token>" \
  --allow-host api.target.com --run --allow-write
```

## Checks

- `auth` - missing or broken authentication on operations declaring security
- `bola` - cross-context object access and ID enumeration probes
- `injection` - SQL, NoSQL, command, traversal, error-based, and multi-engine SSTI payloads (Jinja/Twig, Freemarker/JSP-EL, Ruby/JSF, ERB/EJS), confirmed by server-side evaluation rather than a loose string match
- `massassign` - extra sensitive fields in JSON request bodies
- `method` - undeclared HTTP methods that unexpectedly work
- `errors` - stack traces, framework banners, debug flags, SQL errors, and internal hosts

Select checks with:

```bash
swaggerprobe -s openapi.yaml --base https://api.target.com --checks auth,injection
```

## Output

Console output shows a compact severity-ranked table. JSON and Markdown reports are also supported:

```bash
swaggerprobe -s openapi.yaml --base https://api.target.com \
  --allow-host api.target.com --run -o report.json --md report.md
```

JSON schema:

```json
{
  "summary": {
    "tool": "swaggerprobe",
    "version": "0.1.0",
    "operations": 0,
    "checks": ["auth"],
    "requests_sent": 0,
    "base_url": "https://api.target.com"
  },
  "findings": [
    {
      "severity": "HIGH",
      "check": "auth",
      "method": "GET",
      "path": "/private",
      "request": {},
      "response_status": 200,
      "evidence": "missing credentials returned HTTP 200",
      "confidence": "HIGH"
    }
  ]
}
```

## Selftest

The bundled selftest starts a local vulnerable mock API and validates every check class, dry-run behavior, false-positive filtering on the control endpoint, and JSON report shape:

```bash
python3 -m swaggerprobe.selftest
```

## Banner

Interactive terminal output includes the CobraSEC banner. Piped output and JSON stay clean.

## Authorized Testing Only

Use this tool only on systems you own or have explicit written permission to test. Unauthorized scanning or exploitation is illegal.

## License

MIT.
