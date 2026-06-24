# 🛡️ PhantomShield AI

**A unified cybersecurity platform — Phishing Analyzer, URL Scanner, Security
Header Checker, CVE Intelligence, Malware Analysis, Threat Feed Search, and
an AI Security Assistant — all in one Flask web app.**

Built for CSE (Cybersecurity) coursework | Phantom brand

---

## ✨ Modules

| Module | What it does | Needs Internet? |
|---|---|---|
| 🛡️ **Dashboard** | Overview + module launcher | No |
| 📧 **Phishing Analyzer** | Paste email/text → urgency language, brand impersonation, malicious link detection | **No** (fully offline) |
| 🔗 **URL Scanner** | Lexical analysis (IP-based URLs, typosquatting, entropy, shorteners) + optional VirusTotal | Lexical: **No** · VT/DNS: Yes |
| 🔒 **Security Headers** | Grades any live site's HTTP headers A–F (CSP, HSTS, X-Frame-Options...) | **Yes** (fetches the live site) |
| 🐛 **CVE Intelligence** | Search NVD by keyword/product or exact CVE ID, with CVSS scores | Yes (offline sample fallback included) |
| 📄 **Malware Analysis** | Upload a file → hashes (MD5/SHA1/SHA256), entropy, filetype mismatch, embedded scripts | **No** (fully offline) + optional VT hash check |
| 📡 **Threat Feed Search** | Look up IP/domain/hash against ThreatFox, OTX, AbuseIPDB | Yes |
| 🤖 **AI Assistant** | Chat about any security topic — Groq LLaMA 3.3 70B | Optional (offline KB fallback) |

Every module works **out of the box with zero API keys**. Keys just upgrade
specific modules from heuristic/offline mode to live threat intelligence.

---

## 🚀 Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. (Optional) Add API keys
cp .env.example .env
# edit .env and paste in any free API keys you have

# 3. Run
python3 app.py
```

Open **http://127.0.0.1:5000** in your browser.

---

## 🔑 Optional API Keys (all have free tiers)

| Variable | Unlocks | Get it at |
|---|---|---|
| `VT_API_KEY` | VirusTotal URL & file hash reputation | virustotal.com/gui/join-us |
| `NVD_API_KEY` | Higher CVE search rate limit (5→50 req/30s) | nvd.nist.gov/developers/request-an-api-key |
| `OTX_API_KEY` | AlienVault OTX threat pulses | otx.alienvault.com → Settings → API Key |
| `ABUSEIPDB_KEY` | IP abuse confidence scoring | abuseipdb.com/account/api |
| `GROQ_API_KEY` | Full AI Assistant (LLaMA 3.3 70B, very fast + free) | console.groq.com/keys |

Without `python-dotenv` installed, just export them manually instead:
```bash
export VT_API_KEY="your_key_here"
export GROQ_API_KEY="your_key_here"
python3 app.py
```

---

## 📂 Project Structure

```
phantomshield/
├── app.py                      ← Flask routes + API endpoints
├── requirements.txt
├── .env.example                ← copy to .env for API keys
├── modules/
│   ├── phishing_analyzer.py    ← heuristic phishing detection
│   ├── url_scanner.py          ← lexical URL analysis + VT lookup
│   ├── header_checker.py       ← live HTTP header grading
│   ├── cve_intel.py            ← NVD API wrapper + offline samples
│   ├── malware_analysis.py     ← hashing, entropy, static analysis
│   ├── threat_feed.py          ← ThreatFox / OTX / AbuseIPDB lookups
│   └── ai_assistant.py         ← Groq LLaMA chat + offline KB fallback
├── templates/                  ← Jinja2 HTML (one per module)
└── static/
    ├── css/style.css           ← Phantom brand design system
    └── js/
        ├── app.js              ← shared frontend utilities
        └── matrix.js           ← matrix rain background effect
```

---

## 🎨 Design

Matches your existing **Phantom** brand: cyan `#00F5FF` / violet `#9B5DE5` /
green `#00FF88` on near-black, Space Grotesk + JetBrains Mono, glassmorphism
cards, animated matrix-rain canvas background, circular SVG risk gauges.

---

## ⚠️ Ethics & Scope Notes

- **Malware Analysis** is *static* analysis only (hashing, entropy, filetype) —
  it does **not** execute uploaded files. Safe to use on suspicious files.
- **AI Assistant** is instructed to explain concepts/defenses, not generate
  working exploits against real named targets.
- All offline heuristics (phishing scoring, URL lexical rules, entropy
  thresholds) are educational approximations, not production-grade detection —
  good for learning the *signals* analysts look for, not a replacement for
  commercial threat intel.
- Files uploaded to Malware Analysis are deleted from disk immediately after
  analysis — nothing is persisted.

---

## 🧩 Extending It

Each module is a self-contained Python file with plain functions — no shared
state. To add a new module:
1. Create `modules/your_module.py` with an analyze function returning a dict
2. Add a route + API endpoint in `app.py`
3. Add `your_module.html` extending `base.html` (copy an existing page as a template)
4. Add a nav link in `templates/base.html` and a card in `templates/dashboard.html`

---

*Built for Prathyusha Engineering College — CSE (Cybersecurity)*
