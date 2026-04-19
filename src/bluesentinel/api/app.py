"""FastAPI service — replaces the v1 Flask dashboard.

Endpoints:

    GET  /             — html landing page with a quick link to /docs
    GET  /health       — liveness + version + which detectors are loaded
    GET  /rules        — list all loaded Sigma rules
    GET  /mitre        — full list of detectable ATT&CK techniques
    POST /analyze      — run parsing + enrichment + detection on submitted text

The service is stateless; every ``/analyze`` call parses the submitted
text and runs detectors from scratch. For production scale you'd swap
in a model cache + streaming ingest, but for portfolio / CI use the
stateless path is plenty fast and means no shared state to worry about.
"""

from __future__ import annotations

from collections import Counter

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from bluesentinel._version import __version__
from bluesentinel.api.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    DetectionResponse,
    HealthResponse,
    MitreCoverageResponse,
    RulesListResponse,
)
from bluesentinel.detectors import (
    BaseDetector,
    IsolationForestDetector,
    LogBERTDetector,
)
from bluesentinel.enrichment import MitreEnricher
from bluesentinel.parsers import DrainParser
from bluesentinel.rules import SigmaEngine


def _default_detectors() -> dict[str, BaseDetector]:
    """The detectors we spin up by default.

    ``DeepLogDetector`` is deliberately omitted here because it needs a
    training corpus to be useful — callers who want it should fit it
    offline and POST their own trained state.
    """
    return {
        "isolation_forest": IsolationForestDetector(),
        "logbert": LogBERTDetector(),
    }


def create_app() -> FastAPI:
    app = FastAPI(
        title="BlueSentinel",
        version=__version__,
        description="Advanced log anomaly detection & UBA for SOC teams",
    )

    detectors = _default_detectors()
    enricher = MitreEnricher()
    rules = SigmaEngine()
    rules.load_builtin()

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def index() -> str:
        return f"""
        <html>
          <head><title>BlueSentinel v{__version__}</title></head>
          <body style="font-family:system-ui;max-width:720px;margin:2rem auto;padding:0 1rem;background:#0a0b0f;color:#e4e4e7;">
            <h1 style="margin-bottom:0;">BlueSentinel</h1>
            <p style="color:#9ca3af;margin-top:.25rem;">v{__version__} — SOC-grade log anomaly detection</p>
            <ul>
              <li><a style="color:#60a5fa;" href="/docs">Swagger UI</a></li>
              <li><a style="color:#60a5fa;" href="/health">/health</a></li>
              <li><a style="color:#60a5fa;" href="/rules">/rules</a></li>
              <li><a style="color:#60a5fa;" href="/mitre">/mitre</a></li>
            </ul>
          </body>
        </html>
        """

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse(
            version=__version__,
            detectors=list(detectors.keys()),
            rules_loaded=len(rules.rules),
        )

    @app.get("/rules", response_model=RulesListResponse)
    async def list_rules() -> RulesListResponse:
        return RulesListResponse(
            rules=[
                {
                    "id": r.id,
                    "title": r.title,
                    "level": r.level.value,
                    "tags": r.tags,
                    "mitre_techniques": r.mitre_techniques,
                }
                for r in rules.rules
            ]
        )

    @app.get("/mitre", response_model=MitreCoverageResponse)
    async def mitre_coverage() -> MitreCoverageResponse:
        return MitreCoverageResponse(techniques=enricher.coverage())

    @app.post("/analyze", response_model=AnalyzeResponse)
    async def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
        parser = DrainParser()
        events = list(parser.parse_lines(req.log_text.splitlines()))
        if not events:
            raise HTTPException(
                400, "No recognisable syslog lines found. Check format."
            )

        if req.enable_mitre:
            enricher.enrich_all(events)

        selected = detectors if req.detectors is None else {
            k: v for k, v in detectors.items() if k in (req.detectors or [])
        }

        all_detections = []
        for det in selected.values():
            all_detections.extend(det.detect(events))
        if req.enable_rules:
            all_detections.extend(rules.evaluate_all(events))

        mitre_counter: Counter[str] = Counter()
        for d in all_detections:
            for t in d.mitre_techniques or d.event.mitre_techniques:
                mitre_counter[t] += 1

        return AnalyzeResponse(
            events_parsed=len(events),
            detectors_run=list(selected.keys()) + (["sigma"] if req.enable_rules else []),
            detections=[
                DetectionResponse(
                    event=d.event.to_dict(),
                    detector=d.detector,
                    score=d.score,
                    threshold=d.threshold,
                    explanation=d.explanation,
                    mitre_techniques=d.mitre_techniques or d.event.mitre_techniques,
                    sigma_rule_id=d.sigma_rule_id,
                )
                for d in all_detections
            ],
            mitre_coverage=dict(mitre_counter),
        )

    return app


# Module-level app so ASGI servers pick it up with `uvicorn bluesentinel.api.app:app`
app = create_app()


def run() -> None:
    """CLI entry point for `bluesentinel-api`."""
    import uvicorn

    uvicorn.run("bluesentinel.api.app:app", host="0.0.0.0", port=8000, reload=False)


if __name__ == "__main__":
    run()
