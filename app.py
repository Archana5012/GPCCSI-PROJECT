from flask import Flask, render_template, request, jsonify
import cv2
import numpy as np
from PIL import Image
import io, re, socket, ssl, datetime, urllib.parse, json, os, base64
import urllib.request
import whois

app = Flask(__name__)

# ─── VirusTotal API ───────────────────────────────────────────────────────────
VT_API_KEY = "1024484f2a58d633c56d0fb928189fa037b152c7efb679d04805a6baa9e87ff9"

def check_virustotal(url):
    """Submit URL to VirusTotal and return threat summary."""
    info = {
        "malicious": 0, "suspicious": 0, "harmless": 0,
        "undetected": 0, "total_engines": 0,
        "scan_id": None, "permalink": None, "error": None
    }
    try:
        # Step 1: Submit URL for scanning
        vt_url    = "https://www.virustotal.com/api/v3/urls"
        post_data = urllib.parse.urlencode({"url": url}).encode()
        req = urllib.request.Request(
            vt_url,
            data=post_data,
            headers={"x-apikey": VT_API_KEY, "Content-Type": "application/x-www-form-urlencoded"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result  = json.loads(resp.read().decode())
            scan_id = result["data"]["id"]
            info["scan_id"] = scan_id

        # Step 2: Get analysis result using scan id
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
        req2 = urllib.request.Request(
            analysis_url,
            headers={"x-apikey": VT_API_KEY}
        )
        with urllib.request.urlopen(req2, timeout=10) as resp2:
            analysis = json.loads(resp2.read().decode())
            stats    = analysis["data"]["attributes"]["stats"]
            info["malicious"]    = stats.get("malicious",  0)
            info["suspicious"]   = stats.get("suspicious", 0)
            info["harmless"]     = stats.get("harmless",   0)
            info["undetected"]   = stats.get("undetected", 0)
            info["total_engines"]= sum(stats.values())

        # Permalink to full report
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        info["permalink"] = f"https://www.virustotal.com/gui/url/{url_id}"

    except Exception as e:
        info["error"] = f"Could not reach VirusTotal ({type(e).__name__})"

    return info


# ─── QR Decode ────────────────────────────────────────────────────────────────
def decode_qr(file_bytes):
    img_pil = Image.open(io.BytesIO(file_bytes)).convert("RGB")
    img_np  = np.array(img_pil)
    img_bgr = cv2.cvtColor(img_np, cv2.COLOR_RGB2BGR)

    try:
        detector = cv2.wechat_qrcode_WeChatQRCode()
        results, _ = detector.detectAndDecode(img_bgr)
        if results:
            return results[0]
    except Exception:
        pass

    gray = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY)
    h, w = gray.shape
    if max(h, w) < 800:
        scale = 800 / max(h, w)
        gray  = cv2.resize(gray, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_CUBIC)

    det  = cv2.QRCodeDetector()
    data, _, _ = det.detectAndDecode(gray)
    return data if data else None


# ─── WHOIS ────────────────────────────────────────────────────────────────────
def get_whois_info(domain):
    info = {"registrar": "Unknown", "creation_date": "Unknown",
            "expiry_date": "Unknown", "domain_age_days": None, "country": "Unknown"}
    try:
        w = whois.whois(domain.split(":")[0])
        info["registrar"] = w.registrar or "Unknown"
        info["country"]   = w.country   or "Unknown"
        cd = w.creation_date
        if isinstance(cd, list): cd = cd[0]
        if isinstance(cd, datetime.datetime):
            info["creation_date"]   = cd.strftime("%d %b %Y")
            info["domain_age_days"] = (datetime.datetime.utcnow() - cd).days
        ed = w.expiration_date
        if isinstance(ed, list): ed = ed[0]
        if isinstance(ed, datetime.datetime):
            info["expiry_date"] = ed.strftime("%d %b %Y")
    except Exception:
        pass
    return info


# ─── IP Analysis ──────────────────────────────────────────────────────────────
def get_ip_analysis(domain, resolved_ip):
    info = {"ip": resolved_ip, "hostname": "Unknown", "org": "Unknown",
            "city": "Unknown", "region": "Unknown", "country": "Unknown",
            "timezone": "Unknown", "blacklisted": False, "blacklist_note": ""}

    if not resolved_ip or resolved_ip == "N/A":
        return info

    try:
        info["hostname"] = socket.gethostbyaddr(resolved_ip)[0]
    except Exception:
        info["hostname"] = resolved_ip

    try:
        with urllib.request.urlopen(
            f"http://ip-api.com/json/{resolved_ip}?fields=status,org,city,regionName,country,timezone",
            timeout=4
        ) as resp:
            geo = json.loads(resp.read().decode())
            if geo.get("status") == "success":
                info["org"]      = geo.get("org",        "Unknown")
                info["city"]     = geo.get("city",       "Unknown")
                info["region"]   = geo.get("regionName", "Unknown")
                info["country"]  = geo.get("country",    "Unknown")
                info["timezone"] = geo.get("timezone",   "Unknown")
    except Exception:
        pass

    suspicious_orgs = ["bulletproof", "fozzy", "3NT", "serverius", "psychz", "hostkey"]
    if any(s.lower() in info["org"].lower() for s in suspicious_orgs):
        info["blacklisted"]    = True
        info["blacklist_note"] = "Hosted on known abuse-prone network"

    return info


# ─── URL Threat Analysis ───────────────────────────────────────────────────────
SUSPICIOUS_KEYWORDS = [
    "login","signin","verify","account","update","secure","bank",
    "paypal","amazon","apple","google","microsoft","password",
    "credential","confirm","wallet","free","prize","winner","click",
    "limited","urgent","suspended","unusual"
]

def analyze_url(url):
    score, flags, details = 0, [], {}

    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower().replace("www.", "")
        path   = parsed.path.lower()
        scheme = parsed.scheme.lower()
    except Exception:
        return {"risk": "Unknown", "score": 0, "flags": ["Invalid URL"], "details": {}}

    details["domain"] = domain
    details["scheme"] = scheme

    if scheme != "https":
        score += 20; flags.append("No HTTPS — unencrypted connection")
    else:
        flags.append("✓ HTTPS enabled")

    found_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in domain or kw in path]
    if found_kw:
        score += len(found_kw) * 10
        flags.append(f"Suspicious keywords: {', '.join(found_kw)}")

    if len(url) > 75:
        score += 10; flags.append(f"Long URL ({len(url)} chars)")
    details["url_length"] = len(url)

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        score += 30; flags.append("IP address used instead of domain — high risk")

    parts = domain.split(".")
    if len(parts) > 3:
        score += 15; flags.append(f"Deep subdomain ({len(parts)-2} levels)")
    details["subdomains"] = max(0, len(parts) - 2)

    found_chars = [c for c in ["@", "%", "~"] if c in url]
    if found_chars:
        score += 15; flags.append(f"Suspicious characters: {' '.join(found_chars)}")

    shorteners = ["bit.ly","tinyurl","t.co","goo.gl","ow.ly",
                  "short.io","rebrand.ly","is.gd","me-qr.com","qr.io"]
    if any(s in domain for s in shorteners):
        score += 20; flags.append("URL shortener — true destination is hidden")

    resolved_ip = "N/A"
    try:
        resolved_ip = socket.gethostbyname(domain)
        details["resolved_ip"] = resolved_ip
        flags.append(f"✓ Domain resolves to {resolved_ip}")
    except Exception:
        score += 25; flags.append("Domain does not resolve — possibly fake")
        details["resolved_ip"] = "N/A"

    if scheme == "https":
        try:
            ctx  = ssl.create_default_context()
            conn = ctx.wrap_socket(socket.socket(), server_hostname=domain)
            conn.settimeout(3); conn.connect((domain, 443))
            cert    = conn.getpeercert()
            exp_str = cert.get("notAfter", "")
            if exp_str:
                exp_date  = datetime.datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (exp_date - datetime.datetime.utcnow()).days
                details["ssl_expiry_days"] = days_left
                if days_left < 0:
                    score += 30; flags.append("SSL certificate EXPIRED")
                elif days_left < 30:
                    score += 10; flags.append(f"SSL expires in {days_left} days")
                else:
                    flags.append(f"✓ SSL valid for {days_left} more days")
            conn.close()
        except Exception:
            details["ssl_expiry_days"] = "N/A"

    whois_info = get_whois_info(domain)
    details["whois"] = whois_info
    age = whois_info.get("domain_age_days")
    if age is not None:
        if age < 30:
            score += 40; flags.append(f"⚠️ Very new domain — only {age} days old")
        elif age < 180:
            score += 20; flags.append(f"Domain is {age} days old (relatively new)")
        elif age < 365:
            score += 5;  flags.append(f"Domain is ~{age//30} months old")
        else:
            flags.append(f"✓ Established domain — {age//365} year(s) old")
    else:
        score += 10; flags.append("WHOIS unavailable — privacy-protected domain")

    ip_info = get_ip_analysis(domain, resolved_ip)
    details["ip_analysis"] = ip_info
    if ip_info.get("blacklisted"):
        score += 30; flags.append(f"⚠️ IP flagged: {ip_info['blacklist_note']}")
    if ip_info.get("country") not in ("Unknown", ""):
        flags.append(f"✓ Server location: {ip_info['city']}, {ip_info['country']}")

    # ─── VirusTotal ───────────────────────────────────────────────────────────
    vt_info = check_virustotal(url)
    details["virustotal"] = vt_info
    if vt_info.get("error"):
        flags.append(f"VirusTotal: {vt_info['error']}")
    else:
        mal   = vt_info.get("malicious",  0)
        sus   = vt_info.get("suspicious", 0)
        total = vt_info.get("total_engines", 0)
        if mal > 0:
            score += min(40, mal * 8)
            flags.append(f"🔴 VirusTotal: {mal}/{total} engines flagged MALICIOUS")
        elif sus > 0:
            score += min(20, sus * 5)
            flags.append(f"🟡 VirusTotal: {sus}/{total} engines flagged SUSPICIOUS")
        else:
            flags.append(f"✓ VirusTotal: Clean — 0/{total} engines flagged")

    score = min(score, 100)
    details["score"] = score

    if score >= 60:
        risk, color, emoji = "Malicious", "#ff4444", "🔴"
    elif score >= 30:
        risk, color, emoji = "Suspicious", "#ffaa00", "🟡"
    else:
        risk, color, emoji = "Safe", "#00cc88", "🟢"

    return {"risk": risk, "color": color, "emoji": emoji,
            "score": score, "flags": flags, "details": details, "url": url}


# ─── Routes ───────────────────────────────────────────────────────────────────
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    files = request.files.getlist("qr_image")
    if not files:
        return jsonify({"error": "No file uploaded"}), 400

    results = []
    for file in files:
        file_bytes = file.read()
        url = decode_qr(file_bytes)
        if not url:
            results.append({"filename": file.filename, "error": "QR not found"})
            continue
        analysis = analyze_url(url)
        entry = {
            "filename":  file.filename,
            "url":       url,
            "analysis":  analysis,
            "timestamp": datetime.datetime.now().strftime("%d %b %Y, %I:%M %p")
        }
        results.append(entry)

    return jsonify({"results": results})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host='0.0.0.0', port=port)