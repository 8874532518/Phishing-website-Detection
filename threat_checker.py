"""
threat_checker.py — PhishGuard AI
====================================
Optional threat-intelligence module.
Checks a URL against external TI services (VirusTotal, Google Safe Browsing).

Privacy Notice (displayed in UI before any call):
  "Your URL will be sent to an external threat-intelligence service for analysis.
   This service may log your query. Do not submit URLs containing passwords,
   personal information, or internal network addresses."

All API keys are read from environment variables / .env file.
The module fails gracefully if no API key is configured or if the service
is unreachable.

Supported services:
  - VirusTotal (VIRUSTOTAL_API_KEY env var); review current API terms.
  - Google Safe Browsing (GSB_API_KEY env var); review current API terms.
"""

import os
import logging
import hashlib
import time
from typing import Optional
from pathlib import Path
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

from decision_engine import TIResult
from feature_extraction import validate_url

load_dotenv()

log = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
GSB_API_KEY = os.getenv("GSB_API_KEY", "").strip()
URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY", "").strip()

VT_URL_REPORT = "https://www.virustotal.com/api/v3/urls"
GSB_LOOKUP = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
URLHAUS_LOOKUP = "https://urlhaus-api.abuse.ch/v1/url/"

REQUEST_TIMEOUT = 10   # seconds per request
MAX_RETRIES = 1


def _provider(
    name: str,
    status: str,
    *,
    summary: str,
    categories: Optional[list[str]] = None,
    statistics: Optional[dict] = None,
) -> dict:
    """Return a frontend-safe provider result without raw upstream responses."""
    result = {
        "provider": name,
        "status": status,
        "summary": summary,
    }
    if categories:
        result["categories"] = categories
    if statistics:
        result["statistics"] = statistics
    return result


def _ti_from_provider(provider: dict) -> TIResult:
    matched = provider["status"] == "MATCH"
    completed = provider["status"] in {"MATCH", "NO_MATCH"}
    return TIResult(
        checked=completed,
        is_malicious=matched,
        sources=[provider["provider"]] if completed else [],
        details=provider["summary"],
        error=None if provider["status"] not in {"ERROR", "UNAVAILABLE"} else provider["summary"],
        status=provider["status"],
        provider_results=[provider],
    )


# ──────────────────────────────────────────────────────────────────────────────
# VirusTotal
# ──────────────────────────────────────────────────────────────────────────────

def _vt_url_id(url: str) -> str:
    """
    VirusTotal v3 URL IDs are base64url-encoded (no padding) SHA-256 of the URL.
    Using requests to VT with the URL lookup endpoint is simpler and equivalent.
    """
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return url_id


def check_virustotal(url: str) -> TIResult:
    """
    Check url against VirusTotal API v3.
    Returns TIResult.
    Free tier: 4 req/min. We add a short sleep to avoid rate-limit errors.
    """
    api_key = VT_API_KEY or os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return _ti_from_provider(_provider(
            "VirusTotal", "NOT_CONFIGURED",
            summary="VirusTotal is not configured on the backend.",
        ))

    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
        "content-type": "application/x-www-form-urlencoded",
    }

    try:
        # Submit URL for scanning
        resp = requests.post(
            VT_URL_REPORT,
            headers=headers,
            data={"url": url},
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
        )

        if resp.status_code == 429:
            return _ti_from_provider(_provider(
                "VirusTotal", "UNAVAILABLE",
                summary="VirusTotal rate limit reached.",
            ))

        resp.raise_for_status()
        submission = resp.json()
        if not isinstance(submission.get("data"), dict):
            return _ti_from_provider(_provider(
                "VirusTotal", "ERROR", summary="VirusTotal returned an unexpected submission response.",
            ))

        # Small delay to let VT process
        time.sleep(2)

        # Fetch analysis result
        url_id = _vt_url_id(url)
        get_resp = requests.get(
            f"{VT_URL_REPORT}/{url_id}",
            headers=headers,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
        )

        if get_resp.status_code == 404:
            return _ti_from_provider(_provider(
                "VirusTotal", "NO_MATCH",
                summary="VirusTotal has no completed result for this URL.",
            ))

        get_resp.raise_for_status()
        data = get_resp.json().get("data", {}).get("attributes", {})
        if data.get("status") not in (None, "completed"):
            return _ti_from_provider(_provider(
                "VirusTotal", "PENDING",
                summary="VirusTotal analysis is still pending.",
            ))
        stats = data.get("last_analysis_stats", {})

        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        if not isinstance(stats, dict):
            return _ti_from_provider(_provider(
                "VirusTotal", "ERROR", summary="VirusTotal returned invalid analysis statistics.",
            ))
        total_engines = sum(value for value in stats.values() if isinstance(value, int)) if stats else 0

        is_malicious = malicious_count >= 2  # At least 2 engines must flag it

        details = (
            f"VirusTotal: {malicious_count}/{total_engines} engines flagged as malicious, "
            f"{suspicious_count} flagged as suspicious."
        )

        provider = _provider(
            "VirusTotal", "MATCH" if is_malicious else "NO_MATCH",
            summary=details,
            statistics={
                "malicious": malicious_count,
                "suspicious": suspicious_count,
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total": total_engines,
            },
        )
        return _ti_from_provider(provider)

    except requests.exceptions.Timeout:
        return _ti_from_provider(_provider("VirusTotal", "UNAVAILABLE", summary="VirusTotal request timed out."))
    except requests.exceptions.ConnectionError:
        return _ti_from_provider(_provider("VirusTotal", "UNAVAILABLE", summary="VirusTotal could not be reached."))
    except requests.exceptions.HTTPError as exc:
        status = getattr(exc.response, "status_code", None)
        if status in (401, 403):
            label = "VirusTotal authentication failed."
        elif status == 429:
            label = "VirusTotal rate limit reached."
        else:
            label = "VirusTotal returned an HTTP error."
        return _ti_from_provider(_provider("VirusTotal", "ERROR", summary=label))
    except (ValueError, TypeError, KeyError):
        return _ti_from_provider(_provider("VirusTotal", "ERROR", summary="VirusTotal returned malformed JSON."))
    except requests.exceptions.RequestException:
        return _ti_from_provider(_provider("VirusTotal", "UNAVAILABLE", summary="VirusTotal request failed."))


# ──────────────────────────────────────────────────────────────────────────────
# Google Safe Browsing
# ──────────────────────────────────────────────────────────────────────────────

def check_google_safe_browsing(url: str) -> TIResult:
    """
    Check url against Google Safe Browsing v4 API.
    Free tier: ~10,000 lookups/day.
    Note: Google receives a hash prefix of the URL (privacy-preserving protocol).
    """
    api_key = GSB_API_KEY or os.getenv("GSB_API_KEY", "").strip()
    if not api_key:
        return _ti_from_provider(_provider(
            "Google Safe Browsing", "NOT_CONFIGURED",
            summary="Google Safe Browsing is not configured on the backend.",
        ))

    payload = {
        "client": {
            "clientId": "phishguard-ai",
            "clientVersion": "1.0.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        resp = requests.post(
            f"{GSB_LOOKUP}?key={api_key}",
            json=payload,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
        )

        if resp.status_code == 429:
            return _ti_from_provider(_provider(
                "Google Safe Browsing", "UNAVAILABLE",
                summary="Google Safe Browsing rate limit reached.",
            ))

        resp.raise_for_status()
        result_data = resp.json()
        if not isinstance(result_data, dict):
            return _ti_from_provider(_provider(
                "Google Safe Browsing", "ERROR", summary="Google Safe Browsing returned malformed JSON.",
            ))
        matches = result_data.get("matches", [])
        is_malicious = len(matches) > 0

        if is_malicious:
            threat_types = list({m.get("threatType", "UNKNOWN") for m in matches})
            details = f"Google Safe Browsing: URL flagged as {', '.join(threat_types)}."
        else:
            details = "Google Safe Browsing: URL not found in any threat lists."

        return _ti_from_provider(_provider(
            "Google Safe Browsing", "MATCH" if is_malicious else "NO_MATCH",
            summary=details, categories=threat_types if is_malicious else None,
        ))

    except requests.exceptions.Timeout:
        return _ti_from_provider(_provider("Google Safe Browsing", "UNAVAILABLE", summary="Google Safe Browsing timed out."))
    except requests.exceptions.ConnectionError:
        return _ti_from_provider(_provider("Google Safe Browsing", "UNAVAILABLE", summary="Google Safe Browsing could not be reached."))
    except requests.exceptions.HTTPError as exc:
        status = getattr(exc.response, "status_code", None)
        summary = "Google Safe Browsing authentication failed." if status in (401, 403) else "Google Safe Browsing returned an HTTP error."
        return _ti_from_provider(_provider("Google Safe Browsing", "ERROR", summary=summary))
    except (ValueError, TypeError, KeyError):
        return _ti_from_provider(_provider("Google Safe Browsing", "ERROR", summary="Google Safe Browsing returned malformed JSON."))
    except requests.exceptions.RequestException:
        return _ti_from_provider(_provider("Google Safe Browsing", "UNAVAILABLE", summary="Google Safe Browsing request failed."))


def check_urlhaus(url: str) -> TIResult:
    """Check the submitted URL against URLhaus malware-URL intelligence."""
    auth_key = URLHAUS_AUTH_KEY or os.getenv("URLHAUS_AUTH_KEY", "").strip()
    if not auth_key:
        return _ti_from_provider(_provider(
            "URLhaus", "NOT_CONFIGURED",
            summary="URLhaus is not configured on the backend.",
        ))
    headers = {"accept": "application/json", "Auth-Key": auth_key}
    try:
        response = requests.post(
            URLHAUS_LOOKUP,
            data={"url": url},
            headers=headers,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
        )
        if response.status_code in (401, 403):
            return _ti_from_provider(_provider("URLhaus", "ERROR", summary="URLhaus authentication failed."))
        if response.status_code == 429:
            return _ti_from_provider(_provider("URLhaus", "UNAVAILABLE", summary="URLhaus rate limit reached."))
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            return _ti_from_provider(_provider("URLhaus", "ERROR", summary="URLhaus returned malformed JSON."))
        query_status = payload.get("query_status")
        if query_status == "no_results":
            return _ti_from_provider(_provider(
                "URLhaus", "NO_MATCH",
                summary="URLhaus found no malware-URL record for this URL.",
            ))
        if query_status == "ok" or payload.get("urlhaus_reference"):
            threat = payload.get("threat") or "malware URL"
            return _ti_from_provider(_provider(
                "URLhaus", "MATCH",
                summary=f"URLhaus reported this URL as {threat}.",
                categories=[str(threat)],
            ))
        return _ti_from_provider(_provider("URLhaus", "ERROR", summary="URLhaus returned an unrecognized response."))
    except requests.exceptions.Timeout:
        return _ti_from_provider(_provider("URLhaus", "UNAVAILABLE", summary="URLhaus request timed out."))
    except requests.exceptions.HTTPError:
        return _ti_from_provider(_provider("URLhaus", "ERROR", summary="URLhaus returned an HTTP error."))
    except (requests.exceptions.RequestException, OSError):
        return _ti_from_provider(_provider("URLhaus", "UNAVAILABLE", summary="URLhaus could not be reached."))
    except (ValueError, TypeError, KeyError):
        return _ti_from_provider(_provider("URLhaus", "ERROR", summary="URLhaus returned malformed JSON."))


# ──────────────────────────────────────────────────────────────────────────────
# Local PhishTank Threat Feed
# ──────────────────────────────────────────────────────────────────────────────

_LOCAL_PHISHING_DB = None

def get_local_phishing_db() -> tuple[set, set]:
    """Load cached set of known phishing domains and URLs from local feed."""
    global _LOCAL_PHISHING_DB
    if _LOCAL_PHISHING_DB is not None:
        return _LOCAL_PHISHING_DB

    domains = set()
    urls = set()
    feed_path = Path(__file__).parent / "dataset" / "phishing_active.txt"
    if feed_path.exists():
        try:
            with open(feed_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    u = line.strip().lower()
                    if not u or u.startswith("#"):
                        continue
                    urls.add(u)
                    if "://" in u:
                        parts = u.split("/")
                        if len(parts) > 2:
                            d = parts[2].split(":")[0]
                            if d:
                                domains.add(d)
        except Exception as exc:
            log.warning(f"Could not load local phishing database: {exc}")

    _LOCAL_PHISHING_DB = (domains, urls)
    return _LOCAL_PHISHING_DB


def check_phishtank_feed(url: str) -> TIResult:
    """Check the local phishing URL snapshot without presenting it as live."""
    valid, validation_error = validate_url(url)
    if not valid:
        return TIResult(
            checked=False,
            error=f"Invalid URL for local feed lookup: {validation_error}",
        )
    if any(character.isspace() for character in url):
        return TIResult(
            checked=False,
            error="Invalid URL for local feed lookup: whitespace is not allowed.",
        )
    domains, urls = get_local_phishing_db()
    if not domains and not urls:
        return TIResult(checked=False, details="Local phishing feed snapshot not found.")

    url_clean = url.strip().lower().rstrip("/")
    parsed = urlparse(url_clean)
    host = (parsed.hostname or "").lower()
    feed_path = Path(__file__).parent / "dataset" / "phishing_active.txt"
    try:
        snapshot_date = time.strftime("%Y-%m-%d", time.localtime(feed_path.stat().st_mtime))
    except OSError as exc:
        return TIResult(
            checked=False,
            error=f"Local phishing feed snapshot is unavailable: {exc}",
        )
    source = "Local phishing feed snapshot"

    if url_clean in urls or (host and host in domains):
        return TIResult(
            checked=True,
            is_malicious=True,
            sources=[source],
            details=f"Exact URL or hostname match in the local snapshot file dated {snapshot_date}.",
        )

    return TIResult(
        checked=True,
        is_malicious=False,
        sources=[source],
        details=(
            f"No match in the local URL/hostname snapshot ({len(urls):,} URLs, "
            f"{len(domains):,} hostnames; local file date {snapshot_date}). "
            "This is not a live-feed guarantee."
        ),
    )


# ──────────────────────────────────────────────────────────────────────────────
# Combined Checker
# ──────────────────────────────────────────────────────────────────────────────

def run_threat_intelligence(url: str, user_consented: bool = False, check_local: bool = True) -> TIResult:
    """
    Run all configured threat-intelligence checks and merge results.

    Parameters
    ----------
    url : str
        The URL to check.
    user_consented : bool
        Must be True to send the URL to external services.
        If False, returns an unchecked result with a privacy notice.
    check_local : bool
        If True, queries the local PhishTank threat database (0 API keys needed).

    Returns
    -------
    TIResult
        Merged result from all checked services.
    """
    if not user_consented:
        return TIResult(
            checked=False,
            details=(
                "Threat-intelligence check was not run. "
                "Enable it in the settings panel and confirm the privacy notice."
            ),
        )

    results = []
    providers = []

    # 1. Local PhishTank Threat Feed (privacy-safe, offline, zero API keys required)
    if check_local:
        local_res = check_phishtank_feed(url)
        local_provider = _provider(
            "Local snapshot",
            "MATCH" if local_res.is_malicious else "NO_MATCH"
            if local_res.checked else "UNAVAILABLE",
            summary=local_res.details or local_res.error or "Local snapshot unavailable.",
        )
        providers.append(local_provider)
        results.append(local_res)

    # 2. VirusTotal (if API key configured)
    log.info("Checking configured threat-intelligence providers.")
    vt = check_virustotal(url)
    results.append(vt)
    providers.extend(vt.provider_results)

    # 3. Google Safe Browsing (if API key configured)
    gsb = check_google_safe_browsing(url)
    results.append(gsb)
    providers.extend(gsb.provider_results)

    urlhaus = check_urlhaus(url)
    results.append(urlhaus)
    providers.extend(urlhaus.provider_results)

    # Merge: any confirmed malicious → overall is malicious
    any_checked = any(r.checked for r in results)
    any_malicious = any(r.is_malicious for r in results if r.checked)
    all_sources = []
    all_details = []

    errors = []
    for r in results:
        if r.checked:
            all_sources.extend(r.sources)
            if r.details:
                all_details.append(r.details)
        if r.error:
            errors.append(r.error)

    if not any(r.checked for r in results):
        return TIResult(
            checked=False,
            details="No configured threat-intelligence provider completed a check.",
            error="; ".join(errors) if errors else None,
            status="NOT_CONFIGURED",
            provider_results=providers,
        )

    return TIResult(
        checked=any_checked,
        is_malicious=any_malicious,
        sources=all_sources,
        details=" | ".join(all_details) if all_details else "",
        error="; ".join(errors) if errors else None,
        status="MATCH" if any_malicious else "NO_MATCH" if any_checked else "UNAVAILABLE",
        provider_results=providers,
    )
