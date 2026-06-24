"""
PhantomShield AI — Phishing Analyzer
Heuristic + pattern-based phishing detection for email content / raw text.
No external API required — works fully offline.
"""

import re
import urllib.parse

URGENCY_WORDS = [
    "urgent", "immediately", "act now", "verify your account", "suspended",
    "click here", "limited time", "confirm your identity", "unusual activity",
    "your account will be", "final notice", "winner", "congratulations",
    "claim your", "password expires", "security alert", "unauthorized login",
    "update your payment", "verify now", "act fast", "last chance",
]

SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".loan", ".work"]

BRAND_KEYWORDS = ["paypal", "apple", "microsoft", "google", "amazon", "netflix",
                   "bank", "irs", "facebook", "instagram", "whatsapp", "linkedin"]

URL_REGEX = re.compile(r'https?://[^\s<>"\')\]]+', re.IGNORECASE)
IP_URL_REGEX = re.compile(r'https?://(\d{1,3}\.){3}\d{1,3}')
SHORTENER_DOMAINS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"]


def _extract_urls(text):
    return URL_REGEX.findall(text)


def _domain_from_url(url):
    try:
        return urllib.parse.urlparse(url).netloc.lower()
    except Exception:
        return ""


def analyze_email(raw_text, sender="", subject=""):
    """
    Analyze raw email body / pasted text for phishing indicators.
    Returns a dict: score (0-100), verdict, indicators[], urls[]
    """
    text = f"{subject}\n{raw_text}".lower()
    indicators = []
    score = 0

    # 1. Urgency / social-engineering language
    matched_urgency = [w for w in URGENCY_WORDS if w in text]
    if matched_urgency:
        pts = min(25, 5 * len(matched_urgency))
        score += pts
        indicators.append({
            "type": "Urgency Language",
            "severity": "high" if len(matched_urgency) >= 3 else "medium",
            "detail": f"Found {len(matched_urgency)} urgency/pressure phrase(s): "
                      f"{', '.join(matched_urgency[:5])}",
            "points": pts
        })

    # 2. Brand impersonation check (brand mentioned but sender domain mismatched)
    mentioned_brands = [b for b in BRAND_KEYWORDS if b in text]
    sender_domain = sender.split("@")[-1].lower() if "@" in sender else ""
    if mentioned_brands and sender_domain:
        mismatched = [b for b in mentioned_brands if b not in sender_domain]
        if mismatched:
            score += 25
            indicators.append({
                "type": "Brand Impersonation",
                "severity": "high",
                "detail": f"Mentions brand(s) {', '.join(mismatched)} but sender domain "
                          f"'{sender_domain}' does not match.",
                "points": 25
            })

    # 3. URL analysis
    urls = _extract_urls(raw_text)
    url_flags = []
    for url in urls:
        domain = _domain_from_url(url)
        flags = []
        if IP_URL_REGEX.match(url):
            flags.append("raw IP address instead of domain")
        if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
            flags.append(f"suspicious TLD ({domain.split('.')[-1]})")
        if any(s in domain for s in SHORTENER_DOMAINS):
            flags.append("URL shortener (hides real destination)")
        if domain.count("-") >= 3:
            flags.append("excessive hyphens in domain (typosquatting pattern)")
        if flags:
            url_flags.append({"url": url, "domain": domain, "flags": flags})

    if url_flags:
        pts = min(30, 10 * len(url_flags))
        score += pts
        indicators.append({
            "type": "Suspicious URLs",
            "severity": "high",
            "detail": f"{len(url_flags)} suspicious link(s) detected.",
            "points": pts
        })

    # 4. Generic greeting (no personalization)
    if re.search(r'\b(dear (customer|user|valued|sir|member)|hello user)\b', text):
        score += 10
        indicators.append({
            "type": "Generic Greeting",
            "severity": "low",
            "detail": "Uses generic greeting instead of your actual name — common in mass phishing.",
            "points": 10
        })

    # 5. Mismatched display name vs reply domain
    if "reply-to" in text or "reply to" in text:
        score += 5
        indicators.append({
            "type": "Reply-To Redirection",
            "severity": "medium",
            "detail": "Email specifies a different Reply-To address — common spoofing tactic.",
            "points": 5
        })

    # 6. Attachment / macro request bait
    if re.search(r'(enable (macros|content)|open the attached|download.{0,15}invoice|\.exe\b|\.scr\b|\.zip\b)', text):
        score += 15
        indicators.append({
            "type": "Malicious Attachment Bait",
            "severity": "high",
            "detail": "References enabling macros or downloading an executable/archive attachment.",
            "points": 15
        })

    # 7. Spelling/formatting irregularities (rough heuristic)
    odd_spacing = len(re.findall(r'\b\w\.\w\.\w\b', text))
    if odd_spacing:
        score += 5
        indicators.append({
            "type": "Formatting Irregularities",
            "severity": "low",
            "detail": "Unusual character spacing detected (possible filter-evasion).",
            "points": 5
        })

    score = min(100, score)

    if score >= 70:
        verdict = "PHISHING — High Confidence"
    elif score >= 40:
        verdict = "SUSPICIOUS — Review Carefully"
    elif score >= 15:
        verdict = "LOW RISK — Minor Flags"
    else:
        verdict = "LIKELY LEGITIMATE"

    return {
        "score": score,
        "verdict": verdict,
        "indicators": indicators,
        "urls": url_flags,
        "all_urls_found": urls,
    }
