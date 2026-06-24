"""
PhantomShield AI — CVE Intelligence
Queries the NVD (National Vulnerability Database) public API for CVE details
and keyword/product searches. Requires internet; includes offline sample fallback.
"""

import os
import requests

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")  # optional, raises rate limit from 5/30s to 50/30s

# Small offline fallback dataset so the module still demos something with no internet.
OFFLINE_SAMPLE = [
    {
        "id": "CVE-2024-3094",
        "summary": "Backdoor in XZ Utils (liblzma) via malicious build-time code injection, "
                   "enabling remote unauthenticated SSH access on affected systems.",
        "severity": "CRITICAL", "cvss": 10.0,
        "published": "2024-03-29",
    },
    {
        "id": "CVE-2023-44487",
        "summary": "HTTP/2 Rapid Reset — allows attackers to cause denial-of-service via "
                   "rapid stream creation/cancellation in HTTP/2 servers.",
        "severity": "HIGH", "cvss": 7.5,
        "published": "2023-10-10",
    },
    {
        "id": "CVE-2021-44228",
        "summary": "Log4Shell — Remote code execution in Apache Log4j2 via crafted JNDI "
                   "lookups in logged input strings.",
        "severity": "CRITICAL", "cvss": 10.0,
        "published": "2021-12-10",
    },
    {
        "id": "CVE-2014-0160",
        "summary": "Heartbleed — OpenSSL TLS heartbeat extension buffer over-read leaking "
                   "private keys, session data, and memory contents.",
        "severity": "HIGH", "cvss": 7.5,
        "published": "2014-04-07",
    },
]


def _cvss_severity_color(score):
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "NONE"


def search_cve(keyword=None, cve_id=None, results_limit=15):
    """
    Search NVD by keyword (product/vendor name) or fetch a specific CVE ID.
    Falls back to offline sample data if the API is unreachable.
    """
    params = {"resultsPerPage": results_limit}
    if cve_id:
        params["cveId"] = cve_id.upper()
    elif keyword:
        params["keywordSearch"] = keyword
    else:
        return {"error": "Provide a keyword or CVE ID."}

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        resp = requests.get(NVD_BASE, params=params, headers=headers, timeout=12)
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        parsed = []
        for v in vulns:
            cve = v.get("cve", {})
            cve_id_ = cve.get("id")
            descs = cve.get("descriptions", [])
            summary = next((d["value"] for d in descs if d.get("lang") == "en"), "No description.")

            metrics = cve.get("metrics", {})
            cvss = 0.0
            severity = "UNKNOWN"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    cvss_data = metrics[key][0]["cvssData"]
                    cvss = cvss_data.get("baseScore", 0.0)
                    severity = metrics[key][0].get("baseSeverity", _cvss_severity_color(cvss))
                    break

            parsed.append({
                "id": cve_id_,
                "summary": summary,
                "severity": severity,
                "cvss": cvss,
                "published": cve.get("published", "")[:10],
                "references": [r["url"] for r in cve.get("references", [])[:3]],
            })

        return {"source": "NVD Live API", "total_results": data.get("totalResults", len(parsed)),
                "results": parsed}

    except Exception as e:
        # Offline fallback — filter sample data by keyword if possible
        filtered = OFFLINE_SAMPLE
        if keyword:
            kw = keyword.lower()
            filtered = [c for c in OFFLINE_SAMPLE if kw in c["summary"].lower() or kw in c["id"].lower()]
            if not filtered:
                filtered = OFFLINE_SAMPLE
        if cve_id:
            filtered = [c for c in OFFLINE_SAMPLE if c["id"].lower() == cve_id.lower()]

        return {
            "source": "OFFLINE SAMPLE (NVD unreachable)",
            "error": str(e),
            "total_results": len(filtered),
            "results": filtered,
        }
