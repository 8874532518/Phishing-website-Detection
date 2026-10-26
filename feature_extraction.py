"""
feature_extraction.py — PhishGuard AI
======================================
Extracts 18 URL-lexical features from a raw URL string.
All features are computed OFFLINE from the URL string alone.
No network requests are made by this module.

Feature list (in order returned by extract_features()):
  0  url_length
  1  hostname_length
  2  dot_count
  3  hyphen_count
  4  at_symbol
  5  has_ip
  6  digit_count_domain
  7  subdomain_depth
  8  has_https
  9  path_length
  10 query_length
  11 param_count
  12 has_shortener
  13 https_in_hostname
  14 suspicious_keywords
  15 is_punycode
  16 double_slash_redirect
  17 registered_domain_length
"""

import re
import math
import ipaddress
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, Optional

import tldextract

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "dot_count",
    "hyphen_count",
    "at_symbol",
    "has_ip",
    "digit_count_domain",
    "subdomain_depth",
    "has_https",
    "path_length",
    "query_length",
    "param_count",
    "has_shortener",
    "https_in_hostname",
    "suspicious_keywords",
    "is_punycode",
    "double_slash_redirect",
    "registered_domain_length",
]

# Known URL shorteners / redirectors
URL_SHORTENERS = frozenset([
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "short.link",
    "is.gd", "buff.ly", "adf.ly", "bc.vc", "clk.sh", "cutt.ly",
    "rb.gy", "shorturl.at", "tiny.cc", "u.to", "yourls.org", "v.gd",
])

# Keywords commonly abused in phishing URLs
SUSPICIOUS_WORDS = frozenset([
    "login", "signin", "sign-in", "logon", "secure", "security",
    "verify", "verification", "update", "account", "billing", "bank",
    "paypal", "amazon", "apple", "google", "microsoft", "support",
    "helpdesk", "confirm", "password", "credential", "wallet",
    "suspend", "unlock", "recover", "alert", "urgent", "manage",
    "uber", "netflix", "chase", "wellsfargo", "facebook", "instagram",
    "whatsapp", "dropbox", "coinbase", "binance", "portal", "auth",
])

# High-risk / high-abuse Top-Level Domains (Spamhaus & Interisle research)
HIGH_RISK_TLDS = frozenset([
    "cfd", "sbs", "icu", "top", "xyz", "buzz", "cam", "rest",
    "work", "gq", "ml", "cf", "ga", "tk", "click", "link",
    "country", "stream", "download", "racing", "accountant",
])
# ──────────────────────────────────────────────────────────────────────────────

def normalize_url(raw_url: str) -> str:
    """
    Lightly normalize a URL for consistent analysis.
    - Strips leading/trailing whitespace
    - Adds 'http://' scheme if missing (required for urlparse to work correctly)
    - Does NOT modify the URL in ways that lose security-relevant information
    """
    url = raw_url.strip()
    if not url:
        raise ValueError("URL must not be empty.")
    # If no scheme, prepend http:// so urlparse can split hostname correctly
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', url):
        url = "http://" + url
    return url


def validate_url(raw_url: str) -> tuple[bool, str]:
    """
    Validate URL syntax. Returns (is_valid, error_message).
    Only http and https schemes are accepted.
    """
    try:
        url_stripped = raw_url.strip()
        if not url_stripped:
            return False, "URL must not be empty."

        # Detect any existing URI scheme (e.g. javascript:, data:, ftp:, etc.)
        scheme_match = re.match(r'^([a-zA-Z][a-zA-Z0-9+\-.]*):', url_stripped)
        if scheme_match:
            scheme = scheme_match.group(1).lower()
            if scheme not in ("http", "https"):
                return False, f"Unsupported scheme '{scheme}'. Only http and https are allowed."

        url = normalize_url(raw_url)
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False, f"Unsupported scheme '{parsed.scheme}'. Only http and https are allowed."
        if not parsed.netloc:
            return False, "URL has no hostname."
        return True, ""
    except Exception as exc:
        return False, str(exc)


# ──────────────────────────────────────────────────────────────────────────────
# Individual Feature Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _is_ip_address(hostname: str) -> bool:
    """Return True if the hostname is an IPv4 or IPv6 address."""
    hostname = hostname.strip("[]")  # strip IPv6 brackets
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _count_digits(text: str) -> int:
    return sum(c.isdigit() for c in text)


def _subdomain_depth(ext: tldextract.tldextract.ExtractResult) -> int:
    """Number of subdomain labels (0 if no subdomain)."""
    if not ext.subdomain:
        return 0
    return len(ext.subdomain.split("."))


def _has_double_slash_redirect(url: str) -> bool:
    """
    True if '//' appears AFTER position 7 in the URL
    (i.e., not the '//' that is part of the scheme 'http://').
    """
    # Find all '//' occurrences beyond position 7
    idx = url.find("//", 7)
    return idx != -1


def _url_entropy(text: str) -> float:
    """Shannon entropy of the character distribution in text."""
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# ──────────────────────────────────────────────────────────────────────────────
# Main Feature Extractor
# ──────────────────────────────────────────────────────────────────────────────

def extract_features(raw_url: str) -> Dict[str, Any]:
    """
    Extract all 18 URL-lexical features from a raw URL string.

    Parameters
    ----------
    raw_url : str
        The URL to analyze (with or without scheme).

    Returns
    -------
    dict
        A dictionary mapping each feature name to its numeric value.
        All values are int or float.

    Raises
    ------
    ValueError
        If the URL is empty or its scheme is not http/https.
    """
    url = normalize_url(raw_url)
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported scheme: {parsed.scheme}")

    hostname = parsed.hostname or ""
    ext = tldextract.extract(url)
    if hasattr(ext, "top_domain_under_public_suffix"):
        registered_domain = ext.top_domain_under_public_suffix or ""
    else:
        registered_domain = getattr(ext, "registered_domain", "") or ""
    subdomain = ext.subdomain or ""

    # ── 1. URL length ─────────────────────────────────────────────────────────
    url_length = len(url)

    # ── 2. Hostname length ────────────────────────────────────────────────────
    hostname_length = len(hostname)

    # ── 3. Dot count (in full hostname) ───────────────────────────────────────
    dot_count = hostname.count(".")

    # ── 4. Hyphen count (in hostname) ─────────────────────────────────────────
    hyphen_count = hostname.count("-")

    # ── 5. @ symbol in URL ────────────────────────────────────────────────────
    at_symbol = 1 if "@" in url else 0

    # ── 6. IP address as hostname ─────────────────────────────────────────────
    has_ip = 1 if _is_ip_address(hostname) else 0

    # ── 7. Digit count in domain ──────────────────────────────────────────────
    digit_count_domain = _count_digits(hostname)

    # ── 8. Subdomain depth ────────────────────────────────────────────────────
    subdomain_depth_val = _subdomain_depth(ext)

    # ── 9. HTTPS scheme ───────────────────────────────────────────────────────
    has_https = 1 if parsed.scheme == "https" else 0

    # ── 10. Path length ───────────────────────────────────────────────────────
    path_length = len(parsed.path)

    # ── 11. Query string length ───────────────────────────────────────────────
    query_length = len(parsed.query)

    # ── 12. Parameter count ───────────────────────────────────────────────────
    param_count = len(parse_qs(parsed.query))

    # ── 13. Known URL shortener ───────────────────────────────────────────────
    has_shortener = 1 if registered_domain in URL_SHORTENERS else 0

    # ── 14. "https" token embedded in hostname (deceptive) ───────────────────
    https_in_hostname = 1 if "https" in hostname.lower() else 0

    # ── 15. Suspicious keyword count in URL ───────────────────────────────────
    # Brand names should not be penalized when on their own official domain
    domain_name = ext.domain.lower() if hasattr(ext, "domain") and ext.domain else ""
    url_lower = url.lower()
    suspicious_keywords = 0
    for w in SUSPICIOUS_WORDS:
        if w in url_lower:
            if domain_name and w == domain_name:
                continue  # Legitimate brand on its own domain (e.g. google on google.com)
            suspicious_keywords += 1

    # ── 16. Punycode / Internationalized Domain Name ──────────────────────────
    is_punycode = 1 if "xn--" in hostname.lower() else 0

    # ── 17. Double-slash redirect after scheme ────────────────────────────────
    double_slash_redirect = 1 if _has_double_slash_redirect(url) else 0

    # ── 18. Registered domain length ──────────────────────────────────────────
    registered_domain_length = len(registered_domain)

    features = {
        "url_length": url_length,
        "hostname_length": hostname_length,
        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "at_symbol": at_symbol,
        "has_ip": has_ip,
        "digit_count_domain": digit_count_domain,
        "subdomain_depth": subdomain_depth_val,
        "has_https": has_https,
        "path_length": path_length,
        "query_length": query_length,
        "param_count": param_count,
        "has_shortener": has_shortener,
        "https_in_hostname": https_in_hostname,
        "suspicious_keywords": suspicious_keywords,
        "is_punycode": is_punycode,
        "double_slash_redirect": double_slash_redirect,
        "registered_domain_length": registered_domain_length,
    }

    return features


def features_to_vector(features: Dict[str, Any]) -> list:
    """
    Convert the features dict to an ordered list matching FEATURE_NAMES.
    This ordering must match the order used during training.
    """
    return [features[name] for name in FEATURE_NAMES]


def get_risk_indicators(features: Dict[str, Any], url: Optional[str] = None) -> list[str]:
    """
    Return human-readable descriptions of the risk indicators found in features.
    Used by the UI to explain why a URL was flagged.
    """
    indicators = []

    if features["has_ip"]:
        indicators.append("🔴 IP address used as hostname instead of a domain name")
    if features["at_symbol"]:
        indicators.append("🔴 '@' symbol in URL — browser ignores everything before it")
    if features["is_punycode"]:
        indicators.append("🔴 Internationalized domain (xn--) — possible homograph/lookalike attack")
    if features["https_in_hostname"]:
        indicators.append("🔴 'https' keyword embedded inside the hostname (deceptive)")
    if features["double_slash_redirect"]:
        indicators.append("🟠 Double slash '//' found after the scheme — possible redirect trick")
    if features["has_shortener"]:
        indicators.append("🟠 Known URL shortener used — actual destination is hidden")
    if features["suspicious_keywords"] >= 3:
        indicators.append(f"🟠 {features['suspicious_keywords']} suspicious keywords found (login, secure, verify, etc.)")
    elif features["suspicious_keywords"] >= 1:
        indicators.append(f"🟡 {features['suspicious_keywords']} suspicious keyword(s) found")
    if features["subdomain_depth"] >= 3:
        indicators.append(f"🟠 Deep subdomain nesting ({features['subdomain_depth']} levels) — brand impersonation pattern")
    elif features["subdomain_depth"] == 2:
        indicators.append(f"🟡 Multiple subdomains ({features['subdomain_depth']} levels)")
    if features["hyphen_count"] >= 3:
        indicators.append(f"🟠 Many hyphens in domain ({features['hyphen_count']}) — common in brand-impersonation domains")
    elif features["hyphen_count"] >= 1:
        indicators.append(f"🟡 Hyphen(s) in domain ({features['hyphen_count']})")
    if features["url_length"] > 100:
        indicators.append(f"🟡 Very long URL ({features['url_length']} characters)")
    if features["dot_count"] >= 5:
        indicators.append(f"🟡 Many dots in hostname ({features['dot_count']}) — unusual structure")
    if not features.get("has_https", 1):
        indicators.append("🟡 No HTTPS — connection is not encrypted (note: HTTPS alone doesn't mean safe)")
    if url:
        try:
            host = (urlparse(url if "://" in url else f"http://{url}").hostname or "").lower()
            tld = host.split(".")[-1] if "." in host else ""
            if tld in HIGH_RISK_TLDS:
                indicators.append(f"🟠 High-abuse Top-Level Domain (.{tld}) — commonly used for disposable phishing sites")
        except Exception:
            pass

    return indicators


if __name__ == "__main__":
    # Quick self-test
    test_urls = [
        "https://www.google.com",
        "http://paypal-secure-login.verify-account.com/update?user=test@mail.com",
        "http://192.168.1.1/admin",
        "https://xn--pypal-4ve.com",
        "http://bit.ly/3xAbCde",
    ]
    for u in test_urls:
        f = extract_features(u)
        indicators = get_risk_indicators(f)
        print(f"\nURL: {u}")
        print(f"  Features: {f}")
        print(f"  Risk indicators: {indicators}")
