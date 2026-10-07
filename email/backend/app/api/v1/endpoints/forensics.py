"""Advanced email-forensics endpoints — header analysis + BEC detection.

Exposes the new v2 services as a simple POST endpoint so the frontend
dashboard (or external clients / SIEM) can get structured forensic
reports on any raw email.
"""

from __future__ import annotations

from email import message_from_string
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.bec_detector import detect_bec
from app.services.header_forensics import analyze_message
from app.services.mitre_mapping import coverage_matrix, map_signal_to_techniques

router = APIRouter(prefix="/forensics", tags=["forensics"])


class RawEmailRequest(BaseModel):
    raw_email: str = Field(..., description="Full RFC 5322 email including headers and body.")
    protected_domains: list[str] = Field(
        default_factory=list,
        description="Your organisation's domains — BEC lookalike detection compares against these.",
    )
    known_senders: list[str] = Field(
        default_factory=list,
        description="Previously-seen sender addresses — used for first-time-sender signalling.",
    )


class ForensicsResponse(BaseModel):
    header_forensics: dict[str, Any]
    bec: dict[str, Any]
    mitre_techniques: list[str]
    risk_score: float


@router.post("/analyze", response_model=ForensicsResponse)
async def analyze_email(payload: RawEmailRequest) -> ForensicsResponse:
    try:
        msg = message_from_string(payload.raw_email)
    except Exception as exc:  # pragma: no cover
        raise HTTPException(400, f"Malformed email: {exc}") from exc

    header_report = analyze_message(msg)
    bec_report = detect_bec(
        msg,
        known_senders=payload.known_senders,
        protected_domains=payload.protected_domains,
    )

    # Map every signal to ATT&CK techniques
    techniques: set[str] = set()
    for sig in bec_report.signals:
        techniques.update(map_signal_to_techniques(sig.code))
    if header_report.spf_pass is False:
        techniques.update(map_signal_to_techniques("spf_fail"))
    if header_report.dkim_pass is False:
        techniques.update(map_signal_to_techniques("dkim_fail"))
    if header_report.dmarc_pass is False:
        techniques.update(map_signal_to_techniques("dmarc_fail"))

    # Risk score combines both sub-scores (capped at 1.0)
    combined_risk = min(
        0.6 * header_report.risk_score + 0.6 * bec_report.risk_score,
        1.0,
    )

    return ForensicsResponse(
        header_forensics=header_report.to_dict(),
        bec=bec_report.to_dict(),
        mitre_techniques=sorted(techniques),
        risk_score=round(combined_risk, 3),
    )


@router.get("/mitre/coverage")
async def mitre_coverage() -> dict[str, Any]:
    """List every ATT&CK technique this service can potentially tag."""
    return {"techniques": coverage_matrix()}
