"""Core assessment engine for HTTP, SSL/TLS, headers, and public files."""
from __future__ import annotations

import re
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

import requests

from scanner.validator import CheckError, resolve_public, validate_url
from scanner.threat import lookup_threat_intelligence
from scanner.scorer import score

MAX_BODY = 512_000
MAX_REDIRECTS = 3
TIMEOUT = (3.05, 5)
RATE_LOCK = threading.Lock()
ACTIVE = threading.BoundedSemaphore(4)
LAST_REQUEST: dict[str, float] = {}
RATE_INTERVAL = 2.0


def _check(
    id: str,
    title: str,
    category: str,
    weight: int,
    result: str,
    evidence: str | None = None,
    impact: str = "",
    remediation: str = "",
    confidence: str = "High",
) -> dict:
    """Construct a standardized check finding object with beginner-friendly context."""
    severity = (
        "unknown"
        if result == "unknown"
        else "not applicable"
        if result == "not_applicable"
        else "review"
        if result == "not_present" and weight >= 2
        else "informational"
        if result == "not_present"
        else "observed"
    )
    return {
        "id": id,
        "title": title,
        "category": category,
        "weight": weight,
        "status": result,
        "evidence": evidence or "No evidence was available for this check.",
        "impact": impact,
        "remediation": remediation,
        "confidence": confidence,
        "severity": severity,
    }


def parse_headers(headers: dict) -> list[dict]:
    """Inspect HTTP response headers for defensive security directives."""
    h = {k.lower(): v for k, v in headers.items()}
    checks = []
    specs = [
        (
            "csp",
            "Content Security Policy",
            "Content-Security-Policy",
            "A policy can limit where scripts, styles, and other resources may load from.",
            "Define a Content-Security-Policy appropriate to the site; start with report-only if needed.",
        ),
        (
            "hsts",
            "HTTPS Strict Transport Security",
            "Strict-Transport-Security",
            "A policy tells browsers to prefer HTTPS for future visits.",
            "Send Strict-Transport-Security over HTTPS with a suitable max-age; consider subdomains only after validating them.",
        ),
        (
            "nosniff",
            "Content type protection",
            "X-Content-Type-Options",
            "This header helps browsers honor declared content types.",
            "Send X-Content-Type-Options: nosniff.",
        ),
        (
            "referrer",
            "Referrer policy",
            "Referrer-Policy",
            "This controls how much referring page information browsers share.",
            "Choose and send an appropriate Referrer-Policy, such as strict-origin-when-cross-origin.",
        ),
    ]

    for cid, title, key, impact, fix in specs:
        value = h.get(key.lower())
        checks.append(
            _check(
                cid,
                title,
                "Headers",
                1,
                "present" if value else "not_present",
                f"Observed {key}: {value[:500]}"
                if value
                else f"{key} was not observed on the homepage response.",
                impact,
                fix,
            )
        )

    # Clickjacking / Framing Protection Check
    framing = h.get("x-frame-options") or h.get("content-security-policy", "")
    protected = bool(
        h.get("x-frame-options")
        or re.search(
            r"(?i)(?:^|;)\s*frame-ancestors\s+[^;]+",
            h.get("content-security-policy", ""),
        )
    )
    checks.append(
        _check(
            "framing",
            "Framing protection",
            "Headers",
            1,
            "present" if protected else "not_present",
            f"Observed framing control: {framing[:500]}"
            if protected
            else "No X-Frame-Options or CSP frame-ancestors directive was observed.",
            "Framing controls can reduce unwanted embedding in another site.",
            "Set a suitable Content-Security-Policy frame-ancestors directive or X-Frame-Options.",
        )
    )

    # Cookie Security Attributes Check
    cookies = [v for k, v in headers.items() if k.lower() == "set-cookie"]
    if not cookies:
        checks.append(
            _check(
                "cookies",
                "Cookie attributes",
                "Cookies",
                2,
                "not_applicable",
                "No Set-Cookie header was observed on the homepage response.",
                "No cookie attributes could be assessed for this response.",
            )
        )
    else:
        missing = []
        for cookie in cookies[:30]:
            parts = [part.strip().lower() for part in cookie.split(";")]
            name = cookie.split("=", 1)[0][:80]
            for attr in ("secure", "httponly"):
                if attr not in parts:
                    missing.append(f"{name}: missing {attr.title()}")
            if not any(part.startswith("samesite=") for part in parts):
                missing.append(f"{name}: missing SameSite")
        checks.append(
            _check(
                "cookies",
                "Cookie attributes",
                "Cookies",
                2,
                "not_present" if missing else "present",
                "; ".join(missing[:12])
                if missing
                else f"Checked {min(len(cookies), 30)} Set-Cookie header(s); Secure, HttpOnly, and SameSite attributes were observed.",
                "Cookie flags can limit exposure to network interception and script access, and help control cross-site sending.",
                "Review each cookie's purpose and set Secure, HttpOnly where appropriate, and a suitable SameSite value.",
            )
        )

    return checks


def _request(
    url: str,
    max_bytes: int = MAX_BODY,
    redirect_scope: tuple[str, str] | None = None,
) -> dict:
    """Issue one bounded request, validating DNS for this hop before letting requests connect."""
    current = validate_url(url)
    for hop in range(MAX_REDIRECTS + 1):
        p = urlsplit(current)
        port = p.port or (443 if p.scheme == "https" else 80)
        resolve_public(p.hostname, port)
        try:
            with requests.get(
                current,
                timeout=TIMEOUT,
                allow_redirects=False,
                stream=True,
                headers={"User-Agent": "PostureCheck/2.0 (passive cybersecurity configuration review)"},
                verify=True,
                proxies={"http": None, "https": None},
            ) as response:
                if response.status_code in {301, 302, 303, 307, 308}:
                    location = response.headers.get("Location")
                    if not location:
                        raise CheckError("The website returned a redirect without a destination.")
                    if hop >= MAX_REDIRECTS:
                        raise CheckError("The website redirected too many times.")
                    next_url = validate_url(urljoin(current, location))
                    if redirect_scope is not None:
                        np = urlsplit(next_url)
                        next_origin = (np.scheme, np.netloc)
                        if next_origin != redirect_scope[0] or np.path != redirect_scope[1]:
                            raise CheckError(
                                "The public file redirected outside its allowed path, so the request was stopped."
                            )
                    current = next_url
                    continue

                tls_info = "TLS certificate details were unavailable from the HTTP runtime."
                if p.scheme == "https":
                    try:
                        cert = response.raw._connection.sock.getpeercert()
                        subject = ", ".join(
                            "=".join(item) for group in cert.get("subject", ()) for item in group
                        )[:180]
                        issuer = ", ".join(
                            "=".join(item) for group in cert.get("issuer", ()) for item in group
                        )[:180]
                        tls_info = f"TLS certificate presented; subject: {subject or 'not exposed'}; issuer: {issuer or 'not exposed'}."
                    except (AttributeError, OSError):
                        pass

                chunks, size = [], 0
                for chunk in response.iter_content(8192):
                    size += len(chunk)
                    if size > max_bytes:
                        raise CheckError("The response was larger than the allowed limit.")
                    chunks.append(chunk)

                return {
                    "status": response.status_code,
                    "headers": dict(response.headers),
                    "body": b"".join(chunks),
                    "url": current,
                    "tls_info": tls_info,
                }
        except requests.Timeout:
            raise CheckError("The website did not respond before the time limit.") from None
        except requests.RequestException:
            raise CheckError("The website could not be reached or its TLS connection could not be verified.") from None

    raise CheckError("The website redirected too many times.")


def run_assessment(target: str, client_ip: str | None = None) -> dict:
    """Run full passive cybersecurity assessment against a validated public URL."""
    normalized = validate_url(target)
    p = urlsplit(normalized)

    if not ACTIVE.acquire(blocking=False):
        raise CheckError("The checker is busy. Please try again shortly.")
    try:
        with RATE_LOCK:
            now = time.monotonic()
            key = client_ip or "unknown"
            if now - LAST_REQUEST.get(key, 0) < RATE_INTERVAL:
                raise CheckError("Please wait a moment before starting another check.")
            LAST_REQUEST[key] = now

        home = _request(normalized)
        checks = []

        # HTTPS Connection Check
        if p.scheme == "https":
            checks.append(
                _check(
                    "https",
                    "HTTPS homepage",
                    "Connection",
                    2,
                    "present",
                    f"Homepage was requested using HTTPS; final response status {home['status']}. {home.get('tls_info', 'TLS certificate details were unavailable from the HTTP runtime.')}",
                    "HTTPS protects the connection between the browser and website when configured correctly.",
                    "Keep the homepage available over HTTPS and redirect HTTP visitors to HTTPS.",
                )
            )
        else:
            checks.append(
                _check(
                    "https",
                    "HTTPS homepage",
                    "Connection",
                    2,
                    "not_present",
                    f"Submitted homepage URL uses HTTP; final response status {home['status']}.",
                    "The HTTP connection is not encrypted in transit.",
                    "Enable HTTPS and redirect visitors from HTTP to HTTPS.",
                )
            )

        # HTTP Security Headers & Cookies
        checks.extend(parse_headers(home["headers"]))

        # Mixed Content Check
        if p.scheme == "https":
            try:
                body = home["body"].decode("utf-8", "replace")
                refs = re.findall(r"(?i)(?:src|href|poster)\s*=\s*['\"](http://[^'\"\s>]+)", body)
                refs = list(dict.fromkeys(refs))[:20]
                checks.append(
                    _check(
                        "mixed",
                        "Possible mixed content",
                        "Page content",
                        2,
                        "not_present" if refs else "present",
                        "HTTP resource references observed: " + ", ".join(refs[:10])
                        if refs
                        else "No HTTP src, href, or poster references were found in the inspected homepage HTML. Referenced assets were not fetched.",
                        "Browsers may block or warn about HTTP resources on an HTTPS page.",
                        "Update affected resource URLs to HTTPS or remove unused references.",
                        "Medium",
                    )
                )
            except Exception:
                checks.append(
                    _check("mixed", "Possible mixed content", "Page content", 2, "unknown", "Homepage markup could not be parsed.")
                )
        else:
            checks.append(
                _check(
                    "mixed",
                    "Possible mixed content",
                    "Page content",
                    2,
                    "not_applicable",
                    "The homepage uses HTTP, so HTTPS mixed content does not apply.",
                )
            )

        # Public Files (robots.txt and security.txt)
        base = f"{p.scheme}://{p.netloc}"
        for cid, path, label in [
            ("robots", "/robots.txt", "robots.txt"),
            ("securitytxt", "/.well-known/security.txt", "security.txt"),
        ]:
            try:
                item = _request(
                    base + path,
                    max_bytes=64_000,
                    redirect_scope=((p.scheme, p.netloc), path),
                )
                ok = 200 <= item["status"] < 300
                checks.append(
                    _check(
                        cid,
                        f"{label} availability",
                        "Public files",
                        1,
                        "present" if ok else "not_present",
                        f"{label} returned HTTP {item['status']}."
                        + (f" Parsed {len(item['body'].decode('utf-8','replace').splitlines())} text line(s)." if ok else ""),
                        "A public file may help automation owners or security reporters understand site policy and contact routes.",
                        f"Publish a valid {label} if appropriate for your site.",
                    )
                )
            except CheckError as exc:
                checks.append(
                    _check(
                        cid,
                        f"{label} availability",
                        "Public files",
                        1,
                        "unknown",
                        str(exc),
                        confidence="Low",
                    )
                )

        return {
            "target": f"{p.scheme}://{p.netloc}{p.path or '/'}",
            "assessed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "summary": score(checks),
            "checks": checks,
            "threat_lookup": lookup_threat_intelligence(normalized),
            "limitations": "Passive, single-response review only. No crawl, exploit, port scan, or asset fetching. Results reflect one moment and do not establish that a site is safe or secure.",
        }
    finally:
        ACTIVE.release()
