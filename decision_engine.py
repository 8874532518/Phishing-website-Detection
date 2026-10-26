"""
decision_engine.py — PhishGuard AI
=====================================
Combines ML model prediction + threat-intelligence result → final verdict.

This module is the only place where a final verdict is produced.
It is designed so that:
  - A confirmed TI match always overrides a benign ML prediction
  - The verdict is one of four clear categories
  - Every decision is transparent and explainable
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
import time

# ──────────────────────────────────────────────────────────────────────────────
# Constants — Thresholds
# ──────────────────────────────────────────────────────────────────────────────

PHISHING_THRESHOLD = 0.70   # ML probability ≥ this → HIGH RISK
SUSPICIOUS_THRESHOLD = 0.40  # ML probability ≥ this → SUSPICIOUS
MIN_INDICATORS_FOR_SUSPICIOUS = 3  # Even if ML score is low

# ──────────────────────────────────────────────────────────────────────────────
# Result Types
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class MLResult:
    """Output from the machine-learning detector."""
    phishing_probability: float        # 0.0 – 1.0 model risk estimate
    predicted_class: int               # 1 = phishing, 0 = legitimate
    top_features: list[tuple[str, float]] = field(default_factory=list)
    model_available: bool = True
    error: Optional[str] = None


@dataclass
class TIResult:
    """Output from the threat-intelligence checker."""
    checked: bool = False              # Was a TI check actually performed?
    is_malicious: bool = False         # Confirmed malicious in a TI database?
    sources: list[str] = field(default_factory=list)  # Which TI services flagged it
    details: str = ""                  # Human-readable details from TI
    error: Optional[str] = None        # Error message if check failed
    status: str = "NOT_CHECKED"
    provider_results: list[dict] = field(default_factory=list)


@dataclass
class RedirectResult:
    """Output from the redirect checker."""
    checked: bool = False
    redirect_count: int = 0
    final_url: Optional[str] = None
    chain: list[str] = field(default_factory=list)
    suspicious_redirect: bool = False
    error: Optional[str] = None


@dataclass
class AnalysisResult:
    """
    Full analysis result returned to the UI.
    """
    # Input
    original_url: str = ""
    normalized_url: str = ""
    timestamp: str = ""

    # Component results
    ml: Optional[MLResult] = None
    ti: Optional[TIResult] = None
    redirect: Optional[RedirectResult] = None

    # Risk indicators from feature extraction
    risk_indicators: list[str] = field(default_factory=list)
    features: dict = field(default_factory=dict)

    # Final verdict
    verdict: str = ""                 # Short label
    verdict_label: str = ""           # Full sentence
    verdict_color: str = ""           # CSS color hint: red / orange / green / gray
    confidence_level: str = ""        # HIGH / MEDIUM / LOW
    explanation: list[str] = field(default_factory=list)  # Why this verdict
    recommended_action: str = ""

    # Error state
    error: Optional[str] = None
    is_valid_url: bool = True


# ──────────────────────────────────────────────────────────────────────────────
# Decision Engine
# ──────────────────────────────────────────────────────────────────────────────

def make_verdict(
    original_url: str,
    normalized_url: str,
    features: dict,
    risk_indicators: list[str],
    ml_result: Optional[MLResult],
    ti_result: Optional[TIResult],
    redirect_result: Optional[RedirectResult],
) -> AnalysisResult:
    """
    Combine all detection signals into a single transparent verdict.

    Decision rules (in priority order):
    1. Confirmed TI match → PHISHING / KNOWN MALICIOUS
    2. ML risk estimate ≥ 0.70 → HIGH RISK
    3. ML risk estimate ≥ 0.40 OR ≥ 3 risk indicators → SUSPICIOUS
    4. Otherwise → NO KNOWN THREAT DETECTED
    5. If both ML and TI are unavailable → INCONCLUSIVE
    """
    result = AnalysisResult(
        original_url=original_url,
        normalized_url=normalized_url,
        timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
        features=features,
        risk_indicators=risk_indicators,
        ml=ml_result,
        ti=ti_result,
        redirect=redirect_result,
    )

    explanation = []
    ml_available = ml_result is not None and ml_result.model_available and ml_result.error is None
    ti_confirmed = ti_result is not None and ti_result.checked and ti_result.is_malicious
    ml_prob = ml_result.phishing_probability if ml_available else None
    ti_failed = ti_result is not None and bool(ti_result.error)
    ti_skipped = ti_result is not None and not ti_result.checked and not ti_failed

    # ── Rule 1: Confirmed TI match ────────────────────────────────────────────
    if ti_confirmed:
        result.verdict = "PHISHING"
        result.verdict_label = "⛔ PHISHING / KNOWN MALICIOUS"
        result.verdict_color = "red"
        result.confidence_level = "HIGH"
        sources = ", ".join(ti_result.sources) if ti_result.sources else "threat intelligence database"
        explanation.append(f"This URL was found in {sources} as a confirmed malicious URL.")
        if ml_available:
            explanation.append(
                f"The ML model also assigned a {ml_prob:.0%} risk score, "
                "which supports the TI finding."
            )
        result.recommended_action = (
            "Do NOT visit this URL. Report it if you received it via email or message. "
            "If you have already visited it, change your passwords immediately and run a malware scan."
        )

    # ── Rule 2: High ML probability ───────────────────────────────────────────
    elif ml_available and ml_prob >= PHISHING_THRESHOLD:
        result.verdict = "HIGH RISK"
        result.verdict_label = "🔴 HIGH RISK — Likely Phishing"
        result.verdict_color = "red"
        result.confidence_level = "MEDIUM"
        explanation.append(
            f"The machine-learning model assigned a {ml_prob:.0%} phishing risk score. "
            "This is above the high-risk threshold of 70%."
        )
        if risk_indicators:
            explanation.append(
                f"{len(risk_indicators)} structural risk indicator(s) were found in the URL."
            )
        if ti_result and ti_result.checked and not ti_result.is_malicious and not ti_failed:
            explanation.append(
                "Note: This URL was not found in the checked threat-intelligence feeds, "
                "but that does not make it safe — phishing URLs are often too new to be listed."
            )
        elif ti_failed:
            explanation.append(f"Threat-intelligence check was incomplete: {ti_result.error}")
        elif not ti_result or not ti_result.checked:
            explanation.append(
                "Threat-intelligence check was not performed or was unavailable."
            )
        result.recommended_action = (
            "Avoid visiting this URL. Verify the site through official channels "
            "(e.g., type the company's URL directly in your browser). "
            "This is a model prediction, not a confirmed threat. "
            "Treat with extreme caution."
        )

    # ── Rule 3: Suspicious ────────────────────────────────────────────────────
    elif (
        (ml_available and ml_prob >= SUSPICIOUS_THRESHOLD)
        or len(risk_indicators) >= MIN_INDICATORS_FOR_SUSPICIOUS
        or (len(risk_indicators) >= 2 and ml_available and ml_prob >= 0.25)
    ):
        result.verdict = "SUSPICIOUS"
        result.verdict_label = "🟠 SUSPICIOUS — Treat with Caution"
        result.verdict_color = "orange"
        result.confidence_level = "LOW"
        if ml_available:
            explanation.append(
                f"The ML model assigned an elevated {ml_prob:.0%} phishing risk score."
            )
        if risk_indicators:
            explanation.append(
                f"{len(risk_indicators)} structural risk indicator(s) were flagged: {', '.join(risk_indicators[:3])}."
            )
        result.recommended_action = (
            "Proceed with caution. Do not enter passwords or personal information. "
            "Verify the URL is from an expected source before interacting with the page."
        )

    # ── Rule 4: No known threat detected ─────────────────────────────────────
    elif ti_failed or ti_skipped:
        result.verdict = "INCONCLUSIVE"
        result.verdict_label = "⚪ Inconclusive — Check Unavailable"
        result.verdict_color = "gray"
        result.confidence_level = "LOW"
        if ti_failed:
            explanation.append(
                f"Threat-intelligence analysis was incomplete: {ti_result.error}"
            )
        else:
            explanation.append(
                "Threat-intelligence analysis was not run, so this result cannot be treated as clean."
            )
        if ml_available:
            explanation.append(
                f"The model returned a {ml_prob:.0%} risk score, but the unavailable "
                "threat-intelligence check prevents a clean conclusion."
            )
        result.recommended_action = (
            "Treat this URL cautiously and retry when the threat-intelligence check is available. "
            "Do not enter credentials based on an inconclusive result."
        )

    # ── Rule 5: No known threat detected ─────────────────────────────────────
    elif ml_available or (ti_result and ti_result.checked):
        result.verdict = "NO THREAT DETECTED"
        result.verdict_label = "✅ No Known Threat Detected"
        result.verdict_color = "green"
        result.confidence_level = "MEDIUM"
        if ml_available:
            explanation.append(
                f"The ML model assigned a {ml_prob:.0%} phishing risk score "
                "(below the suspicious threshold)."
            )
        if ti_result and ti_result.checked:
            explanation.append("This URL was not found in the checked threat-intelligence feeds.")
        explanation.append(
            "⚠️ Important: 'No threat detected' does NOT mean this URL is safe. "
            "The model only checked URL structure. Sophisticated phishing sites can appear "
            "structurally legitimate. Always verify the source of a URL."
        )
        result.recommended_action = (
            "The URL appears structurally normal. "
            "Always verify the source before entering personal information. "
            "This result is not a safety guarantee."
        )

    # ── Rule 6: Insufficient evidence ─────────────────────────────────────────
    else:
        result.verdict = "INCONCLUSIVE"
        result.verdict_label = "⚪ Inconclusive — Check Unavailable"
        result.verdict_color = "gray"
        result.confidence_level = "LOW"
        explanation.append(
            "Neither the ML model nor threat-intelligence checks could be completed. "
            "The model file may be missing — run train_model.py first."
        )
        result.recommended_action = (
            "Run train_model.py to train the model, then try again. "
            "If this is a suspicious URL, do not visit it until it can be analysed."
        )

    # ── Add redirect note ─────────────────────────────────────────────────────
    if redirect_result and redirect_result.checked:
        if redirect_result.redirect_count > 0:
            explanation.append(
                f"Redirect analysis: URL redirected {redirect_result.redirect_count} "
                f"time(s). Final destination: {redirect_result.final_url}"
            )
        if redirect_result.suspicious_redirect:
            explanation.append(
                "⚠️ Redirect analysis detected a suspicious destination URL."
            )

    result.explanation = explanation
    return result


def format_verdict_for_ui(result: AnalysisResult) -> dict:
    """
    Flatten AnalysisResult into a plain dict for API or UI display.
    """
    ml = result.ml
    ti = result.ti
    rd = result.redirect

    return {
        "original_url": result.original_url,
        "timestamp": result.timestamp,
        "verdict": result.verdict,
        "verdict_label": result.verdict_label,
        "verdict_color": result.verdict_color,
        "confidence": result.confidence_level,
        "explanation": result.explanation,
        "recommended_action": result.recommended_action,
        "risk_indicators": result.risk_indicators,
        # ML
        "ml_probability": f"{ml.phishing_probability:.1%}" if ml and ml.model_available else "Unavailable",
        "ml_score_label": "Model risk score",
        "ml_raw_prob": ml.phishing_probability if ml and ml.model_available else None,
        "ml_available": ml.model_available if ml else False,
        # TI
        "ti_checked": ti.checked if ti else False,
        "ti_malicious": ti.is_malicious if ti else False,
        "ti_sources": ti.sources if ti else [],
        "ti_details": ti.details if ti else "",
        "ti_error": ti.error if ti else None,
        # Redirect
        "redirect_checked": rd.checked if rd else False,
        "redirect_count": rd.redirect_count if rd else 0,
        "final_url": rd.final_url if rd else None,
        "redirect_chain": rd.chain if rd else [],
        "redirect_error": rd.error if rd else None,
        # Features (for advanced view)
        "features": result.features,
    }
