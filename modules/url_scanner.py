"""
PhantomShield AI — URL Scanner
Lexical/heuristic URL analysis (always works offline) +
optional VirusTotal v3 lookup if VT_API_KEY is configured (live internet required).
"""

import re
import os
import math
import socket
import urllib.parse
import requests

VT_API_KEY = os.environ.get("VT_API_KEY", "")

SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".loan", ".work", ".info"]
SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly"]
BRANDS = ["paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook",
          "instagram", "whatsapp", "linkedin", "bankofamerica", "chase", "wellsfargo"]


def _shannon_entropy(s):
    if not s:
        return 0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def lexical_analysis(url):
    """Pure offline structural analysis of a URL — no network needed."""
    findings = []
    score = 0

    parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    domain = parsed.netloc.lower()
    path = parsed.path or ""

    if not domain:
        return {"score": 0, "verdict": "INVALID URL", "findings": [], "domain": "", "parsed": str(parsed)}

    # IP address instead of domain
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain.split(":")[0]):
        score += 30
        findings.append({"type": "IP-based URL", "severity": "high",
                         "detail": "Domain is a raw IP address — legit sites rarely do this."})

    # Suspicious TLD
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 20
        findings.append({"type": "Suspicious TLD", "severity": "medium",
                         "detail": f"TLD '.{domain.split('.')[-1]}' is frequently abused for phishing."})

    # URL shortener
    if any(s in domain for s in SHORTENERS):
        score += 15
        findings.append({"type": "URL Shortener", "severity": "medium",
                         "detail": "Shortened URL hides the real destination."})

    # @ symbol trick (browser ignores everything before @)
    if "@" in url:
        score += 25
        findings.append({"type": "@ Symbol Trick", "severity": "high",
                         "detail": "URL contains '@' — text before it is ignored by browsers, "
                                  "a classic redirection trick."})

    # Excessive subdomains / hyphens
    if domain.count(".") >= 4:
        score += 10
        findings.append({"type": "Excessive Subdomains", "severity": "low",
                         "detail": f"Domain has {domain.count('.')} dots — may be disguising true host."})
    if domain.count("-") >= 3:
        score += 10
        findings.append({"type": "Excessive Hyphens", "severity": "low",
                         "detail": "Many hyphens in domain — common in typosquatting."})

    # Brand keyword not in root domain (typosquat / subdomain abuse)
    root_parts = domain.split(".")
    root_domain = ".".join(root_parts[-2:]) if len(root_parts) >= 2 else domain
    for brand in BRANDS:
        if brand in domain and brand not in root_domain:
            score += 25
            findings.append({"type": "Brand Impersonation", "severity": "high",
                             "detail": f"'{brand}' appears in a subdomain/path, not the actual root domain "
                                      f"'{root_domain}' — likely impersonation."})
            break

    # High entropy domain (randomly generated, common in malware C2 / DGA)
    label = root_parts[0] if root_parts else domain
    ent = _shannon_entropy(label)
    if ent > 3.6 and len(label) > 10:
        score += 15
        findings.append({"type": "High Entropy Domain", "severity": "medium",
                         "detail": f"Domain label has high randomness (entropy={ent:.2f}) — "
                                  f"typical of algorithmically generated malicious domains."})

    # No HTTPS
    if parsed.scheme != "https":
        score += 10
        findings.append({"type": "No HTTPS", "severity": "low",
                         "detail": "URL does not use HTTPS encryption."})

    # Suspicious path keywords
    if re.search(r'(login|verify|account|secure|update|confirm|signin).{0,20}\.(php|html)', path.lower()):
        score += 10
        findings.append({"type": "Credential Harvesting Path", "severity": "medium",
                         "detail": "Path pattern resembles a fake login/verification page."})

    score = min(100, score)
    if score >= 70:
        verdict = "MALICIOUS — High Risk"
    elif score >= 40:
        verdict = "SUSPICIOUS"
    elif score >= 15:
        verdict = "LOW RISK"
    else:
        verdict = "LIKELY SAFE"

    return {"score": score, "verdict": verdict, "findings": findings,
            "domain": domain, "scheme": parsed.scheme}


def dns_resolve(domain):
    """Try resolving the domain — confirms it's a live host (needs internet)."""
    try:
        ip = socket.gethostbyname(domain.split(":")[0])
        return {"resolved": True, "ip": ip}
    except Exception as e:
        return {"resolved": False, "error": str(e)}


def virustotal_lookup(url):
    """Optional live VirusTotal v3 check. Requires VT_API_KEY env var + internet."""
    if not VT_API_KEY:
        return {"available": False, "reason": "No VT_API_KEY configured. Set environment variable to enable."}
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_API_KEY}
        resp = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=10)
        if resp.status_code == 404:
            # submit for analysis
            requests.post("https://www.virustotal.com/api/v3/urls",
                          headers=headers, data={"url": url}, timeout=10)
            return {"available": True, "status": "submitted",
                   "message": "URL not previously scanned — submitted for analysis. Check back shortly."}
        resp.raise_for_status()
        data = resp.json()["data"]["attributes"]
        stats = data.get("last_analysis_stats", {})
        return {"available": True, "status": "complete", "stats": stats,
               "categories": data.get("categories", {})}
    except Exception as e:
        return {"available": False, "reason": str(e)}
