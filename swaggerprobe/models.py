from dataclasses import dataclass, field


@dataclass(frozen=True)
class Param:
    name: str
    location: str
    required: bool = False
    typ: str = "string"
    schema: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Operation:
    operation_id: str
    method: str
    path: str
    params: tuple = field(default_factory=tuple)
    request_body: dict = field(default_factory=dict)
    security: object = None
    responses: dict = field(default_factory=dict)


@dataclass
class HttpResponse:
    status: int
    headers: dict
    body: str
    elapsed: float = 0.0


@dataclass
class Finding:
    severity: str
    check: str
    method: str
    path: str
    request: dict
    response_status: int
    evidence: str
    confidence: str = "HIGH"

    def signature(self):
        return (
            self.severity,
            self.check,
            self.method.upper(),
            self.path,
            self.response_status,
            self.evidence[:120],
        )
