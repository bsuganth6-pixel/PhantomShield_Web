"""
PhantomShield AI — Security Header Checker
Fetches a live URL and grades its HTTP security headers (needs internet).
"""

import requests

HEADER_CHECKS = {
    "Strict-Transport-Security": {
        "weight": 15,
        "desc": "Forces HTTPS, prevents downgrade/SSL-stripping attacks.",
        "recommend": "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload"
    },
    "Content-Security-Policy": {
        "weight": 20,
        "desc": "Restricts which sources can load scripts/styles — mitigates XSS.",
        "recommend": "Content-Security-Policy: default-src 'self'"
    },
    "X-Frame-Options": {
        "weight": 12,
        "desc": "Prevents clickjacking via iframe embedding.",
        "recommend": "X-Frame-Options: DENY"
    },
    "X-Content-Type-Options": {
        "weight": 10,
        "desc": "Stops MIME-sniffing attacks.",
        "recommend": "X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "weight": 8,
        "desc": "Controls how much referrer info leaks to other sites.",
        "recommend": "Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "weight": 10,
        "desc": "Restricts access to browser features (camera, mic, geolocation).",
        "recommend": "Permissions-Policy: geolocation=(), camera=(), microphone=()"
    },
    "X-XSS-Protection": {
        "weight": 5,
        "desc": "Legacy XSS filter (deprecated but still checked by scanners).",
        "recommend": "X-XSS-Protection: 1; mode=block"
    },
    "Cross-Origin-Opener-Policy": {
        "weight": 10,
        "desc": "Isolates browsing context — mitigates Spectre-style attacks.",
        "recommend": "Cross-Origin-Opener-Policy: same-origin"
    },
    "Cross-Origin-Resource-Policy": {
        "weight": 5,
        "desc": "Controls cross-origin resource embedding.",
        "recommend": "Cross-Origin-Resource-Policy: same-origin"
    },
}

INFO_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime"]


def check_headers(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        resp = requests.get(url, timeout=10, allow_redirects=True,
                           headers={"User-Agent": "PhantomShield-AI/1.0 (Security Scanner)"})
    except Exception as e:
        return {"error": str(e), "url": url}

    headers = resp.headers
    results = []
    total_score = 0
    max_score = sum(h["weight"] for h in HEADER_CHECKS.values())

    for name, meta in HEADER_CHECKS.items():
        present = name in headers
        if present:
            total_score += meta["weight"]
        results.append({
            "header": name,
            "present": present,
            "value": headers.get(name, None),
            "description": meta["desc"],
            "recommendation": meta["recommend"],
            "weight": meta["weight"],
        })

    leaks = []
    for h in INFO_LEAK_HEADERS:
        if h in headers:
            leaks.append({"header": h, "value": headers[h]})

    pct = round((total_score / max_score) * 100)
    if pct >= 85:
        grade = "A"
    elif pct >= 70:
        grade = "B"
    elif pct >= 50:
        grade = "C"
    elif pct >= 30:
        grade = "D"
    else:
        grade = "F"

    return {
        "url": url,
        "final_url": resp.url,
        "status_code": resp.status_code,
        "score_pct": pct,
        "grade": grade,
        "results": results,
        "info_leaks": leaks,
        "cookies_secure": all(c.secure for c in resp.cookies) if resp.cookies else None,
        "raw_headers": dict(headers),
    }
