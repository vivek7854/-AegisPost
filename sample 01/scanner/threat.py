"""Threat intelligence module querying Google Safe Browsing API.

Passive lookup for known phishing, malware, and social engineering domains.
"""
from __future__ import annotations

import os
import requests


def lookup_threat_intelligence(url: str, api_key: str | None = None) -> dict:
    """Look up a submitted URL without treating a no-match as proof of legitimacy."""
    if api_key is None:
        api_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    else:
        api_key = api_key.strip()

    if not api_key:
        return {
            "status": "unknown",
            "provider": "Google Safe Browsing",
            "threat_types": [],
            "evidence": "Threat lookup was not configured. No phishing conclusion can be made."
        }

    try:
        response = requests.get(
            "https://safebrowsing.googleapis.com/v5/urls:search",
            params=[("key", api_key), ("urls", url)],
            timeout=(3.05, 5),
        )
        if response.status_code >= 400:
            return {
                "status": "unknown",
                "provider": "Google Safe Browsing",
                "threat_types": [],
                "evidence": "The threat intelligence service did not complete the lookup."
            }

        data = response.json()
        threats = data.get("threats", []) if isinstance(data, dict) else []
        threat_types = sorted({
            kind
            for threat in threats
            if isinstance(threat, dict)
            for kind in threat.get("threatTypes", [])
            if isinstance(kind, str)
        })

        if threat_types:
            return {
                "status": "match",
                "provider": "Google Safe Browsing",
                "threat_types": threat_types,
                "evidence": "The submitted URL matched a known unsafe URL entry at the time of lookup."
            }

        return {
            "status": "no_match",
            "provider": "Google Safe Browsing",
            "threat_types": [],
            "evidence": "No matching threat entry was returned at the time of lookup. This does not prove that the website is genuine or phishing-free."
        }
    except (requests.Timeout, requests.RequestException, ValueError):
        return {
            "status": "unknown",
            "provider": "Google Safe Browsing",
            "threat_types": [],
            "evidence": "The threat intelligence service could not be reached or its response could not be read."
        }
