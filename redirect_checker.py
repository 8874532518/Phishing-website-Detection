"""
redirect_checker.py — PhishGuard AI
========================================
Safe HTTP redirect chain analysis.

IMPORTANT SECURITY NOTICE
--------------------------
This module follows HTTP redirects from a submitted URL to its final destination.
This involves making REAL network requests. The following safeguards are applied:

  ✓ Only http:// and https:// schemes are allowed
  ✓ Loopback (127.0.0.0/8), private (RFC 1918), link-local (169.254.0.0/16),
    and reserved IP ranges are BLOCKED
  ✓ Maximum 10 redirects per chain
  ✓ Per-hop timeout: 5 seconds
  ✓ Total timeout: 30 seconds
  ✓ Maximum response size read: 0 bytes (headers only, no body downloaded)
  ✓ No JavaScript execution, no form submission, no credential entry
  ✓ DNS rebinding protection: re-validate IP after each redirect

This module is DISABLED by default. It must be explicitly enabled by the user.
"""

import os
import socket
import ipaddress
import logging
import time
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter

from decision_engine import RedirectResult

log = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────

REDIRECT_ENABLED = os.getenv("ENABLE_REDIRECT_CHECKER", "false").strip().lower() == "true"

MAX_REDIRECTS = 10
PER_HOP_TIMEOUT = 5      # seconds
TOTAL_TIMEOUT = 30       # seconds
MAX_RESPONSE_BYTES = 0   # We only read headers, never download the body

ALLOWED_SCHEMES = frozenset(["http", "https"])

# SSRF — blocked IP ranges
BLOCKED_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback
    ipaddress.ip_network("10.0.0.0/8"),       # RFC 1918 private
    ipaddress.ip_network("172.16.0.0/12"),    # RFC 1918 private
    ipaddress.ip_network("192.168.0.0/16"),   # RFC 1918 private
    ipaddress.ip_network("169.254.0.0/16"),   # Link-local
    ipaddress.ip_network("100.64.0.0/10"),    # Shared address space
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),         # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
    ipaddress.ip_network("0.0.0.0/8"),        # Reserved
    ipaddress.ip_network("240.0.0.0/4"),      # Reserved
    ipaddress.ip_network("224.0.0.0/4"),      # Multicast
]


# ──────────────────────────────────────────────────────────────────────────────
# SSRF Protection Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _is_blocked_ip(ip_str: str) -> bool:
    """Return True if the IP address falls in any blocked range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
            or any(ip in network for network in BLOCKED_RANGES)
        )
    except ValueError:
        return True  # Fail safe: if we can't parse it, block it


def _resolve_and_validate_host(hostname: str) -> tuple[bool, str]:
    """
    Resolve hostname → IP, check against blocked ranges.
    Returns (is_safe, message).
    """
    try:
        resolved = socket.getaddrinfo(hostname, None)
        if not resolved:
            return False, f"DNS resolution returned no addresses for '{hostname}'"
        for item in resolved:
            ip_str = item[4][0]
            if _is_blocked_ip(ip_str):
                return False, f"Hostname '{hostname}' resolves to blocked IP {ip_str}"
        return True, ""
    except socket.gaierror as exc:
        return False, f"DNS resolution failed for '{hostname}': {exc}"


def _validate_url_for_request(url: str) -> tuple[bool, str]:
    """
    Validate a URL before making a request to it.
    Returns (is_safe, error_message).
    """
    try:
        parsed = urlparse(url)

        if parsed.scheme not in ALLOWED_SCHEMES:
            return False, f"Blocked scheme '{parsed.scheme}' (only http/https allowed)"

        hostname = parsed.hostname
        if not hostname:
            return False, "URL has no hostname"
        if parsed.username is not None or parsed.password is not None:
            return False, "URLs containing embedded credentials are not allowed"

        # Check if hostname is a raw IP
        try:
            ip = ipaddress.ip_address(hostname.strip("[]"))
            if _is_blocked_ip(str(ip)):
                return False, f"Direct IP address {hostname} is in a blocked range"
        except ValueError:
            # Not a raw IP — resolve the hostname
            safe, msg = _resolve_and_validate_host(hostname)
            if not safe:
                return False, msg

        return True, ""
    except Exception as exc:
        return False, f"URL validation error: {exc}"


# ──────────────────────────────────────────────────────────────────────────────
# Redirect Checker
# ──────────────────────────────────────────────────────────────────────────────

def follow_redirects(url: str, force_enable: bool = False) -> RedirectResult:
    """
    Follow the redirect chain from url to its final destination.
    Returns a RedirectResult with the chain and final URL.

    This function only reads HTTP response headers (no body content).
    All intermediate and final URLs are validated against the SSRF blocklist.
    """
    if not REDIRECT_ENABLED and not force_enable:
        return RedirectResult(
            checked=False,
            error=(
                "Redirect checker is disabled. "
                "Enable 'Follow Redirects' in the sidebar options or set ENABLE_REDIRECT_CHECKER=true in .env."
            ),
        )

    chain = []
    current_url = url
    start_time = time.monotonic()

    session = requests.Session()
    # Do not route user-supplied destinations through ambient proxy settings.
    session.trust_env = False
    # Disable automatic redirect following — we do it manually
    session.max_redirects = 0

    # Use a conservative adapter
    adapter = HTTPAdapter(max_retries=0)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    try:
        for hop in range(MAX_REDIRECTS + 1):
            # Check total time
            elapsed = time.monotonic() - start_time
            if elapsed > TOTAL_TIMEOUT:
                return RedirectResult(
                    checked=True,
                    redirect_count=len(chain),
                    final_url=current_url,
                    chain=chain,
                    suspicious_redirect=False,
                    error=f"Total timeout ({TOTAL_TIMEOUT}s) exceeded after {hop} hops.",
                )

            # Validate URL before requesting
            is_safe, reason = _validate_url_for_request(current_url)
            if not is_safe:
                return RedirectResult(
                    checked=True,
                    redirect_count=len(chain),
                    final_url=current_url,
                    chain=chain,
                    suspicious_redirect=True,
                    error=f"Blocked redirect destination: {reason}",
                )

            chain.append(current_url)

            try:
                resp = session.head(
                    current_url,
                    allow_redirects=False,
                    timeout=PER_HOP_TIMEOUT,
                    headers={
                        "User-Agent": "PhishGuardAI/1.0 (educational security tool)",
                    },
                    stream=True,
                )
            except requests.exceptions.SSLError as exc:
                return RedirectResult(
                    checked=True,
                    redirect_count=len(chain) - 1,
                    final_url=current_url,
                    chain=chain,
                    suspicious_redirect=True,
                    error=f"SSL error at {current_url}: invalid or self-signed certificate.",
                )
            except requests.exceptions.Timeout:
                return RedirectResult(
                    checked=True,
                    redirect_count=len(chain) - 1,
                    final_url=current_url,
                    chain=chain,
                    error=f"Request timed out after {PER_HOP_TIMEOUT}s at hop {hop + 1}.",
                )
            except requests.exceptions.ConnectionError as exc:
                return RedirectResult(
                    checked=True,
                    redirect_count=len(chain) - 1,
                    final_url=current_url,
                    chain=chain,
                    error=f"Connection failed at hop {hop + 1}: {str(exc)[:100]}",
                )

            # Not a redirect → we reached the final destination
            if resp.status_code not in (301, 302, 303, 307, 308):
                return RedirectResult(
                    checked=True,
                    redirect_count=len(chain) - 1,
                    final_url=current_url,
                    chain=chain,
                    suspicious_redirect=False,
                )

            # Follow the redirect
            location = resp.headers.get("Location", "").strip()
            if not location:
                return RedirectResult(
                    checked=True,
                    redirect_count=len(chain) - 1,
                    final_url=current_url,
                    chain=chain,
                    error="Redirect with no Location header — broken redirect chain.",
                )

            # Resolve relative redirects, then validate the absolute destination
            location = urljoin(current_url, location)
            if urlparse(location).scheme not in ALLOWED_SCHEMES:
                return RedirectResult(
                    checked=True,
                    redirect_count=len(chain) - 1,
                    final_url=current_url,
                    chain=chain,
                    suspicious_redirect=True,
                    error=f"Suspicious redirect location: '{location[:100]}'",
                )

            # Detect redirect loops
            if location in chain:
                return RedirectResult(
                    checked=True,
                    redirect_count=len(chain),
                    final_url=location,
                    chain=chain,
                    suspicious_redirect=True,
                    error=f"Redirect loop detected at: {location[:100]}",
                )

            current_url = location

        # Exceeded max redirects
        return RedirectResult(
            checked=True,
            redirect_count=MAX_REDIRECTS,
            final_url=current_url,
            chain=chain,
            suspicious_redirect=True,
            error=f"Exceeded maximum redirect limit ({MAX_REDIRECTS}).",
        )

    except Exception as exc:
        return RedirectResult(
            checked=True,
            redirect_count=len(chain),
            final_url=current_url if chain else url,
            chain=chain,
            error=f"Unexpected error during redirect analysis: {str(exc)[:200]}",
        )
    finally:
        session.close()
