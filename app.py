#!/usr/bin/env python3
"""
PhantomShield AI — Main Flask Application
A unified cybersecurity platform: Phishing Analyzer, URL Scanner,
Security Header Checker, CVE Intelligence, Malware Analysis,
Threat Feed Search, AI Security Assistant.
"""

import os
import tempfile
from flask import Flask, render_template, request, jsonify, session
from werkzeug.utils import secure_filename

try:
    from dotenv import load_dotenv
    load_dotenv()  # auto-loads .env if present (pip install python-dotenv)
except ImportError:
    pass  # .env support is optional — env vars can still be set manually

from modules import phishing_analyzer, url_scanner, header_checker
from modules import cve_intel, malware_analysis, threat_feed, ai_assistant

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "phantomshield-dev-key-change-me")
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25MB upload cap

UPLOAD_DIR = tempfile.mkdtemp(prefix="phantomshield_")

MODULES = [
    {"id": "dashboard", "name": "Dashboard", "icon": "shield", "desc": "Overview"},
    {"id": "phishing", "name": "Phishing Analyzer", "icon": "mail-warning", "desc": "Detect phishing emails"},
    {"id": "url", "name": "URL Scanner", "icon": "link", "desc": "Inspect suspicious links"},
    {"id": "headers", "name": "Security Headers", "icon": "lock", "desc": "Grade HTTP headers"},
    {"id": "cve", "name": "CVE Intelligence", "icon": "bug", "desc": "Search vulnerabilities"},
    {"id": "malware", "name": "Malware Analysis", "icon": "file-warning", "desc": "Static file analysis"},
    {"id": "threatfeed", "name": "Threat Feed Search", "icon": "radar", "desc": "IOC reputation lookup"},
    {"id": "assistant", "name": "AI Assistant", "icon": "bot", "desc": "Ask security questions"},
]


@app.context_processor
def inject_modules():
    return {"modules": MODULES}


# ════════════════════════════════════════════════════════════════
#  PAGE ROUTES
# ════════════════════════════════════════════════════════════════

@app.route("/")
def dashboard():
    return render_template("dashboard.html", active="dashboard")


@app.route("/phishing")
def phishing_page():
    return render_template("phishing.html", active="phishing")


@app.route("/url-scanner")
def url_page():
    return render_template("url_scanner.html", active="url")


@app.route("/headers")
def headers_page():
    return render_template("headers.html", active="headers")


@app.route("/cve")
def cve_page():
    return render_template("cve.html", active="cve")


@app.route("/malware")
def malware_page():
    return render_template("malware.html", active="malware")


@app.route("/threat-feed")
def threatfeed_page():
    return render_template("threat_feed.html", active="threatfeed")


@app.route("/assistant")
def assistant_page():
    return render_template("assistant.html", active="assistant")


# ════════════════════════════════════════════════════════════════
#  API ROUTES
# ════════════════════════════════════════════════════════════════

@app.route("/api/phishing/analyze", methods=["POST"])
def api_phishing():
    data = request.get_json(force=True)
    result = phishing_analyzer.analyze_email(
        raw_text=data.get("body", ""),
        sender=data.get("sender", ""),
        subject=data.get("subject", ""),
    )
    return jsonify(result)


@app.route("/api/url/scan", methods=["POST"])
def api_url_scan():
    data = request.get_json(force=True)
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided."}), 400

    lexical = url_scanner.lexical_analysis(url)
    dns = url_scanner.dns_resolve(lexical.get("domain", url))
    vt = url_scanner.virustotal_lookup(url) if data.get("check_vt") else {"available": False, "reason": "Not requested"}

    return jsonify({"lexical": lexical, "dns": dns, "virustotal": vt})


@app.route("/api/headers/check", methods=["POST"])
def api_headers():
    data = request.get_json(force=True)
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided."}), 400
    result = header_checker.check_headers(url)
    return jsonify(result)


@app.route("/api/cve/search", methods=["POST"])
def api_cve():
    data = request.get_json(force=True)
    result = cve_intel.search_cve(
        keyword=data.get("keyword"),
        cve_id=data.get("cve_id"),
    )
    return jsonify(result)


@app.route("/api/malware/analyze", methods=["POST"])
def api_malware():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400
    f = request.files["file"]
    if f.filename == "":
        return jsonify({"error": "Empty filename."}), 400

    filename = secure_filename(f.filename)
    path = os.path.join(UPLOAD_DIR, filename)
    f.save(path)

    result = malware_analysis.analyze_file(path)

    check_vt = request.form.get("check_vt") == "true"
    if check_vt and "sha256" in result:
        result["virustotal"] = malware_analysis.virustotal_hash_lookup(result["sha256"])

    try:
        os.remove(path)
    except OSError:
        pass

    return jsonify(result)


@app.route("/api/threatfeed/search", methods=["POST"])
def api_threatfeed():
    data = request.get_json(force=True)
    ioc = data.get("ioc", "").strip()
    if not ioc:
        return jsonify({"error": "No IOC provided."}), 400
    result = threat_feed.search_ioc(ioc)
    return jsonify(result)


@app.route("/api/assistant/ask", methods=["POST"])
def api_assistant():
    data = request.get_json(force=True)
    question = data.get("question", "").strip()
    if not question:
        return jsonify({"error": "No question provided."}), 400

    history = session.get("chat_history", [])
    result = ai_assistant.ask_assistant(question, history=history)

    history.append({"role": "user", "content": question})
    history.append({"role": "assistant", "content": result["answer"]})
    session["chat_history"] = history[-20:]  # cap memory

    return jsonify(result)


@app.route("/api/assistant/clear", methods=["POST"])
def api_assistant_clear():
    session.pop("chat_history", None)
    return jsonify({"status": "cleared"})


@app.route("/api/status")
def api_status():
    """Reports which optional API keys are configured."""
    return jsonify({
        "vt_configured": bool(os.environ.get("VT_API_KEY")),
        "nvd_configured": bool(os.environ.get("NVD_API_KEY")),
        "otx_configured": bool(os.environ.get("OTX_API_KEY")),
        "abuseipdb_configured": bool(os.environ.get("ABUSEIPDB_KEY")),
        "groq_configured": bool(os.environ.get("GROQ_API_KEY")),
    })


if __name__ == "__main__":
    print(r"""
   ███████╗██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
   ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
   ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
   ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
   ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
        SHIELD AI — Unified Cybersecurity Platform
        Running at http://127.0.0.1:5000
    """)
    app.run(debug=True, host="0.0.0.0", port=5000)
