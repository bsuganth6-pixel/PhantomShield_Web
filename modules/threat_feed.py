"""
PhantomShield AI — Threat Feed Search
Searches open-source threat intelligence feeds for IPs / domains / hashes:
  - AbuseIPDB-style scoring (offline heuristic if no key)
  - abuse.ch ThreatFox (free, no key required)
  - AlienVault OTX (optional API key)
"""

import os
import re
import requests

OTX_API_KEY = os.environ.get("OTX_API_KEY", "")
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "")

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"

IOC_TYPE_REGEX = {
    "ipv4": re.compile(r'^(\d{1,3}\.){3}\d{1,3}$'),
    "domain": re.compile(r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'),
    "md5": re.compile(r'^[a-fA-F0-9]{32}$'),
    "sha256": re.compile(r'^[a-fA-F0-9]{64}$'),
}


def detect_ioc_type(value):
    value = value.strip()
    for ioc_type, pattern in IOC_TYPE_REGEX.items():
        if pattern.match(value):
            return ioc_type
    return "unknown"


def search_threatfox(ioc):
    """Free, keyless lookup against abuse.ch ThreatFox IOC database."""
    try:
        payload = {"query": "search_ioc", "search_term": ioc}
        resp = requests.post(THREATFOX_URL, json=payload, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        if data.get("query_status") == "ok":
            entries = data.get("data", [])
            return {
                "source": "abuse.ch ThreatFox",
                "found": len(entries) > 0,
                "count": len(entries),
                "entries": [{
                    "ioc": e.get("ioc"),
                    "threat_type": e.get("threat_type"),
                    "malware": e.get("malware_printable", e.get("malware")),
                    "confidence": e.get("confidence_level"),
                    "first_seen": e.get("first_seen"),
                    "tags": e.get("tags") or [],
                } for e in entries[:10]],
            }
        else:
            return {"source": "abuse.ch ThreatFox", "found": False, "count": 0, "entries": []}
    except Exception as e:
        return {"source": "abuse.ch ThreatFox", "error": str(e), "found": False}


def search_otx(ioc, ioc_type):
    """Optional AlienVault OTX lookup. Requires OTX_API_KEY."""
    if not OTX_API_KEY:
        return {"available": False, "reason": "No OTX_API_KEY configured."}

    section_map = {"ipv4": "IPv4", "domain": "domain", "md5": "file", "sha256": "file"}
    section = section_map.get(ioc_type)
    if not section:
        return {"available": False, "reason": "Unsupported IOC type for OTX."}

    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/{section}/{ioc}/general"
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        pulses = data.get("pulse_info", {}).get("pulses", [])
        return {
            "available": True,
            "pulse_count": len(pulses),
            "pulse_names": [p.get("name") for p in pulses[:5]],
            "reputation": data.get("reputation", 0),
        }
    except Exception as e:
        return {"available": False, "reason": str(e)}


def search_abuseipdb(ip):
    """Optional AbuseIPDB lookup. Requires ABUSEIPDB_KEY. Only valid for IPv4."""
    if not ABUSEIPDB_KEY:
        return {"available": False, "reason": "No ABUSEIPDB_KEY configured."}
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            timeout=10,
        )
        resp.raise_for_status()
        d = resp.json()["data"]
        return {
            "available": True,
            "abuse_confidence_score": d.get("abuseConfidenceScore"),
            "total_reports": d.get("totalReports"),
            "country": d.get("countryCode"),
            "isp": d.get("isp"),
            "is_whitelisted": d.get("isWhitelisted"),
        }
    except Exception as e:
        return {"available": False, "reason": str(e)}


def search_ioc(ioc):
    """Master entry point — detects IOC type and queries relevant feeds."""
    ioc = ioc.strip()
    ioc_type = detect_ioc_type(ioc)

    result = {"ioc": ioc, "ioc_type": ioc_type, "sources": {}}

    result["sources"]["threatfox"] = search_threatfox(ioc)

    if ioc_type in ("ipv4", "domain", "md5", "sha256"):
        result["sources"]["otx"] = search_otx(ioc, ioc_type)

    if ioc_type == "ipv4":
        result["sources"]["abuseipdb"] = search_abuseipdb(ioc)

    # Aggregate a simple combined verdict
    tf = result["sources"].get("threatfox", {})
    otx = result["sources"].get("otx", {})
    abdb = result["sources"].get("abuseipdb", {})

    malicious_hits = 0
    if tf.get("found"):
        malicious_hits += 1
    if otx.get("available") and otx.get("pulse_count", 0) > 0:
        malicious_hits += 1
    if abdb.get("available") and (abdb.get("abuse_confidence_score") or 0) > 50:
        malicious_hits += 1

    if malicious_hits >= 2:
        result["verdict"] = "MALICIOUS — Multiple Sources Confirm"
    elif malicious_hits == 1:
        result["verdict"] = "SUSPICIOUS — Reported by One Source"
    else:
        result["verdict"] = "NO THREAT INTEL MATCHES FOUND"

    return result
