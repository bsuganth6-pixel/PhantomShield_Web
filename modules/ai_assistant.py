"""
PhantomShield AI — AI Security Assistant
Conversational assistant for security questions. Uses Groq (LLaMA) API if
GROQ_API_KEY is set — same pattern as your CloudMind project. Falls back to
a rule-based local knowledge base if no key / no internet.
"""

import os
import requests

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")

SYSTEM_PROMPT = (
    "You are PhantomShield AI Security Assistant, an expert in cybersecurity, "
    "ethical hacking, threat analysis, malware, and network security. "
    "Give concise, accurate, practical answers. When relevant, mention specific "
    "tools, CVEs, OWASP categories, or mitigation steps. Never provide actual "
    "working exploit code for unpatched/zero-day vulnerabilities or step-by-step "
    "attack instructions against real, named targets."
)

# ── Offline fallback knowledge base (keyword → canned expert answer) ──
KB = [
    (["sql injection", "sqli"],
     "SQL Injection occurs when untrusted input is concatenated into SQL queries. "
     "Mitigate with parameterized queries/prepared statements, ORM usage, least-privilege "
     "DB accounts, and input validation. Test with tools like sqlmap (authorized environments only)."),
    (["xss", "cross-site scripting"],
     "XSS lets attackers inject scripts into pages viewed by other users. Prevent it with "
     "output encoding/escaping, a strict Content-Security-Policy, HttpOnly+Secure cookies, "
     "and frameworks that auto-escape (React, Vue) instead of raw innerHTML."),
    (["csrf", "cross-site request forgery"],
     "CSRF tricks a logged-in user's browser into making unwanted requests. Defend with "
     "anti-CSRF tokens (synchronizer token pattern), SameSite=Strict/Lax cookies, and "
     "re-authentication for sensitive actions."),
    (["phishing"],
     "Phishing relies on social engineering. Red flags: urgency language, mismatched sender "
     "domains, shortened/IP-based links, generic greetings, and unexpected attachments. "
     "Defend with email authentication (SPF/DKIM/DMARC), user training, and link sandboxing."),
    (["firewall"],
     "A firewall filters traffic based on rules (IP, port, protocol, or application-layer). "
     "Stateful firewalls track connection state; next-gen firewalls add deep packet inspection "
     "and IDS/IPS integration. Always follow least-privilege: deny by default, allow by exception."),
    (["zero day", "0day", "zero-day"],
     "A zero-day is a vulnerability unknown to the vendor with no patch available. Mitigation "
     "relies on defense-in-depth: network segmentation, EDR/behavioral detection, virtual "
     "patching via WAF rules, and rapid patch management once a fix ships."),
    (["man in the middle", "mitm"],
     "MITM attacks intercept communication between two parties — via ARP spoofing, rogue Wi-Fi "
     "APs, or DNS spoofing. Defenses: TLS/HTTPS everywhere, certificate pinning, VPNs on "
     "untrusted networks, and DNSSEC."),
    (["ransomware"],
     "Ransomware encrypts files and demands payment. Prevention: offline/immutable backups "
     "(3-2-1 rule), email attachment sandboxing, EDR with ransomware behavior detection, "
     "least-privilege + network segmentation to limit lateral spread, and patched RDP/VPN access."),
    (["owasp top 10", "owasp"],
     "OWASP Top 10 (2021) categories: Broken Access Control, Cryptographic Failures, Injection, "
     "Insecure Design, Security Misconfiguration, Vulnerable Components, Auth Failures, "
     "Data Integrity Failures, Logging Failures, and SSRF."),
    (["password", "brute force"],
     "Strong password policy: 12+ chars, no reuse, stored via bcrypt/argon2 (never plaintext/MD5). "
     "Mitigate brute force with rate limiting, account lockout/backoff, MFA, and CAPTCHA on login."),
    (["nmap"],
     "Nmap is used for host discovery and port scanning. Common flags: -sS (SYN scan), "
     "-sV (version detection), -O (OS detection), -A (aggressive), -p- (all ports). "
     "Only scan systems you own or are authorized to test."),
    (["vpn"],
     "A VPN creates an encrypted tunnel between your device and a server, hiding traffic from "
     "local network observers and masking your IP. It does not anonymize you from the VPN "
     "provider itself — choose providers with audited no-logs policies."),
]


def _kb_fallback(question):
    q = question.lower()
    matches = []
    for keywords, answer in KB:
        if any(k in q for k in keywords):
            matches.append(answer)
    if matches:
        return "\n\n".join(matches[:2]) + \
               "\n\n_[Offline knowledge base response — configure GROQ_API_KEY for full AI chat.]_"
    return ("I don't have an offline answer for that specific question. "
            "Configure GROQ_API_KEY (free tier at console.groq.com) to unlock full "
            "AI-powered answers for any security topic.")


def ask_assistant(question, history=None):
    """
    Send question to Groq LLaMA if API key configured, else use local KB fallback.
    `history` = list of {"role": "user"/"assistant", "content": str} for context.
    """
    if not GROQ_API_KEY:
        return {"source": "offline-kb", "answer": _kb_fallback(question)}

    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    if history:
        messages.extend(history[-10:])
    messages.append({"role": "user", "content": question})

    try:
        resp = requests.post(
            GROQ_URL,
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
            json={"model": GROQ_MODEL, "messages": messages, "temperature": 0.4, "max_tokens": 700},
            timeout=20,
        )
        resp.raise_for_status()
        answer = resp.json()["choices"][0]["message"]["content"]
        return {"source": "groq-llama", "answer": answer}
    except Exception as e:
        fallback = _kb_fallback(question)
        return {"source": "offline-kb-fallback", "answer": fallback,
               "error": f"Groq API call failed: {e}"}
