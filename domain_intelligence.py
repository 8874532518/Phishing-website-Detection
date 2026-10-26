"""Bounded, hostname-only DNS and RDAP enrichment.

This module never opens the submitted URL. RDAP receives only the registrable
domain, and DNS results are filtered so private or special-use addresses are
never treated as public intelligence.
"""

from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any
from urllib.parse import urlparse

import requests
import tldextract

LOOKUP_TIMEOUT = 3.0
RDAP_URL = "https://rdap.org/domain/{domain}"


def _status(status: str, value: Any = None, source: str = "") -> dict[str, Any]:
    result = {"status": status, "value": value, "source": source}
    return result


def _public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
        return not (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
            or address.is_unspecified
            or address.is_multicast
        )
    except ValueError:
        return False


def _resolve_addresses(hostname: str) -> list[str]:
    resolved = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    return sorted({item[4][0] for item in resolved if _public_ip(item[4][0])})


def _port_value(parsed: Any) -> int | None:
    try:
        return parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return None


def _empty(hostname: str, reason: str) -> dict[str, Any]:
    unavailable = _status("Unavailable", None, reason)
    return {
        "hostname": _status("Available", hostname, "URL parser"),
        "registrable_domain": _status("Not found", None, "offline tldextract"),
        "scheme": _status("Available", "", "URL parser"),
        "port": _status("Not found", None, "URL parser"),
        "addresses": unavailable,
        "dns_records": {
            "A": unavailable,
            "AAAA": unavailable,
            "MX": _status("Not checked", None, "No DNS resolver configured"),
            "NS": _status("Not checked", None, "No DNS resolver configured"),
        },
        "registration": unavailable,
        "registrar": unavailable,
        "nameservers": unavailable,
        "domain_age_days": unavailable,
        "notes": [reason],
    }


@lru_cache(maxsize=128)
def inspect_domain(normalized_url: str) -> dict[str, Any]:
    """Inspect a normalized URL with short, cached, non-page lookups."""
    parsed = urlparse(normalized_url)
    hostname = (parsed.hostname or "").rstrip(".").lower()
    if not hostname:
        return _empty("", "Hostname was not available after URL parsing.")

    try:
        parsed_ip = ipaddress.ip_address(hostname.strip("[]"))
    except ValueError:
        parsed_ip = None
    if parsed_ip is not None:
        return _empty(hostname, "IP-literal hosts are not queried for registration data.")

    extracted = tldextract.extract(hostname)
    registrable = extracted.top_domain_under_public_suffix or ""
    if not registrable:
        return _empty(hostname, "A registrable domain could not be determined.")

    result = {
        "hostname": _status("Available", hostname, "URL parser"),
        "registrable_domain": _status("Available", registrable, "offline tldextract"),
        "scheme": _status("Available", parsed.scheme, "URL parser"),
        "port": _status("Available" if _port_value(parsed) is not None else "Unavailable", _port_value(parsed), "URL parser"),
        "addresses": _status("Unavailable", None, "DNS resolution"),
        "dns_records": {
            "A": _status("Unavailable", None, "DNS resolution"),
            "AAAA": _status("Unavailable", None, "DNS resolution"),
            "MX": _status("Not checked", None, "No DNS resolver configured"),
            "NS": _status("Not checked", None, "No DNS resolver configured"),
        },
        "registration": _status("Unavailable", None, "RDAP: rdap.org"),
        "registrar": _status("Unavailable", None, "RDAP: rdap.org"),
        "nameservers": _status("Unavailable", None, "RDAP: rdap.org"),
        "domain_age_days": _status("Unavailable", None, "RDAP registration event"),
        "notes": [],
    }

    try:
        executor = ThreadPoolExecutor(max_workers=1)
        try:
            addresses = executor.submit(_resolve_addresses, hostname).result(timeout=LOOKUP_TIMEOUT)
        finally:
            executor.shutdown(wait=False, cancel_futures=True)
        if addresses:
            result["addresses"] = _status("Available", addresses, "DNS A/AAAA via system resolver")
            result["dns_records"]["A"] = _status(
                "Available",
                [ip for ip in addresses if ":" not in ip],
                "DNS A via system resolver",
            )
            result["dns_records"]["AAAA"] = _status(
                "Available",
                [ip for ip in addresses if ":" in ip],
                "DNS AAAA via system resolver",
            )
        else:
            result["addresses"] = _status("Privacy-redacted", [], "DNS returned no public address")
            result["notes"].append("Private, loopback, link-local, reserved, or malformed DNS results were omitted.")
    except (OSError, socket.gaierror, ValueError, FutureTimeoutError) as exc:
        result["addresses"] = _status("Unavailable", None, "DNS resolution failed")
        result["notes"].append(f"DNS lookup failed: {exc.__class__.__name__}.")

    try:
        response = requests.get(
            RDAP_URL.format(domain=registrable),
            headers={"Accept": "application/rdap+json, application/json"},
            timeout=LOOKUP_TIMEOUT,
            allow_redirects=False,
        )
        if response.status_code == 200:
            payload = response.json()
            events = {
                event.get("eventAction"): event.get("eventDate")
                for event in payload.get("events", [])
                if isinstance(event, dict)
            }
            registration = events.get("registration")
            if registration:
                result["registration"] = _status("Available", registration, "RDAP: rdap.org")
                try:
                    registered = datetime.fromisoformat(registration.replace("Z", "+00:00"))
                    age = datetime.now(timezone.utc) - registered.astimezone(timezone.utc)
                    result["domain_age_days"] = _status("Available", max(0, age.days), "RDAP registration event")
                except ValueError:
                    result["domain_age_days"] = _status("Unavailable", None, "RDAP date could not be parsed")
            else:
                result["registration"] = _status("Not found", None, "RDAP: rdap.org")
            entities = payload.get("entities", [])
            registrar = next(
                (
                    entity.get("vcardArray", [None, []])[1]
                    for entity in entities
                    if "registrar" in entity.get("roles", [])
                ),
                None,
            )
            result["registrar"] = _status(
                "Privacy-redacted" if not registrar else "Available",
                "Registration data redacted" if not registrar else registrar,
                "RDAP: rdap.org",
            )
            nameservers = [item.get("ldhName") for item in payload.get("nameservers", []) if item.get("ldhName")]
            result["nameservers"] = _status(
                "Available" if nameservers else "Not found",
                nameservers or None,
                "RDAP: rdap.org",
            )
        else:
            result["notes"].append(f"RDAP returned HTTP {response.status_code}.")
    except (requests.RequestException, ValueError, TypeError, KeyError):
        result["notes"].append("RDAP was unavailable or returned incomplete data.")

    return result


def not_checked(normalized_url: str) -> dict[str, Any]:
    parsed = urlparse(normalized_url)
    hostname = parsed.hostname or ""
    return {
        "hostname": _status("Available", hostname, "URL parser"),
        "registrable_domain": _status("Not checked", None, "Domain intelligence opt-in is disabled"),
        "scheme": _status("Available", parsed.scheme, "URL parser"),
        "port": _status("Available" if _port_value(parsed) is not None else "Unavailable", _port_value(parsed), "URL parser"),
        "addresses": _status("Not checked", None, "Domain intelligence opt-in is disabled"),
        "dns_records": {record: _status("Not checked", None, "Domain intelligence opt-in is disabled") for record in ("A", "AAAA", "MX", "NS")},
        "registration": _status("Not checked", None, "Domain intelligence opt-in is disabled"),
        "registrar": _status("Not checked", None, "Domain intelligence opt-in is disabled"),
        "nameservers": _status("Not checked", None, "Domain intelligence opt-in is disabled"),
        "domain_age_days": _status("Not checked", None, "Domain intelligence opt-in is disabled"),
        "notes": ["Only the hostname is shown locally; no DNS or RDAP lookup was run."],
    }
