"""Validation and security sanitization module.

Protects against SSRF (Server-Side Request Forgery), DNS rebinding,
and malformed user inputs.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit


class CheckError(Exception):
    """Raised when a website assessment or network probe fails safely."""
    pass


def public_ip(value: str) -> bool:
    """Verify that an IP address is a routable global public address.

    Rejects private, loopback, link-local, multicast, and reserved addresses.
    """
    try:
        ip = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    return (
        ip.is_global
        and not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    )


def validate_url(value: object) -> str:
    """Sanitize and validate user-supplied URL for passive assessment.

    Ensures valid HTTP/HTTPS scheme, public hostname, port validity,
    and IDNA normalization.
    """
    if not isinstance(value, str) or not value.strip() or len(value) > 2048:
        raise ValueError("Enter a valid public website URL (up to 2,048 characters).")

    raw = value.strip()
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        raise ValueError("That URL is not valid.") from None

    if parts.scheme.lower() not in {"http", "https"}:
        raise ValueError("Use an http:// or https:// website URL.")

    if parts.username is not None or parts.password is not None:
        raise ValueError("URLs containing a username or password are not accepted.")

    if not parts.hostname or any(ord(c) < 33 for c in raw):
        raise ValueError("Enter a valid public website URL.")

    try:
        host = parts.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("That hostname is not valid.") from None

    if host in {"localhost", "localhost.localdomain"} or host.endswith(".localhost") or host.endswith(".local"):
        raise ValueError("Local and internal hostnames are not allowed.")

    if port is not None and not (1 <= port <= 65535):
        raise ValueError("The URL port is invalid.")

    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    else:
        if not public_ip(host.strip("[]")):
            raise ValueError("The URL must point to a public internet address.")

    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), netloc, path, parts.query, ""))


def resolve_public(host: str, port: int) -> list[str]:
    """Resolve hostname and assert that all resolved IPs are public internet addresses."""
    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        raise CheckError("The website hostname could not be resolved.") from None

    addresses = sorted({record[4][0].split("%", 1)[0] for record in records})
    if not addresses or any(not public_ip(addr) for addr in addresses):
        raise CheckError(
            "The hostname resolves to a non-public or unsupported address, so the request was blocked."
        )
    return addresses
