from flask import Flask, render_template, request
import re
from urllib.parse import urlparse

app = Flask(__name__)

def check_url_safety(url):
    suspicious_keywords = [
        "login", "verify", "bank", "free", "win", "prize",
        "account", "secure", "update", "confirm", "password",
        "billing", "paypal", "amazon", "netflix", "apple",
        "microsoft", "google", "suspended", "locked", "urgent"
    ]

    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top"]
    url_shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co"]

    score = 0
    warnings = []

    # Ensure URL has a scheme for parsing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    parsed_url = urlparse(url)
    domain = parsed_url.netloc.split(":")[0]

    # 1. HTTPS Check
    if parsed_url.scheme != "https":
        score += 2
        warnings.append("Not using HTTPS (data not encrypted)")

    # 2. IP Address Check
    import ipaddress
    try:
        ipaddress.ip_address(domain)
        score += 3
        warnings.append("IP address used instead of domain")
    except ValueError:
        pass

    # 3. Suspicious TLD Check
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            score += 2
            warnings.append(f"Suspicious TLD detected: {tld}")

    # 4. URL Length Analysis (FULL FEATURE)
    url_length = len(url)

    if url_length < 30:
        length_type = "Short URL"
    elif url_length <= 75:
        length_type = "Moderate URL"
    elif url_length <= 150:
        score += 1
        length_type = "Long URL"
        warnings.append("Long URL detected (may hide malicious content)")
    else:
        score += 2
        length_type = "Very Long URL"
        warnings.append("Very long URL detected (high phishing risk)")

    # 5. Subdomain Check
    if len(domain.split(".")) > 4:
        score += 2
        warnings.append("Too many subdomains")

    # 6. Suspicious Characters
    if "@" in domain or "---" in url:
        score += 2
        warnings.append("Suspicious characters detected")

    # 7. Keyword Check
    keyword_count = 0
    for keyword in suspicious_keywords:
        if re.search(keyword, url, re.IGNORECASE):
            keyword_count += 1

    if keyword_count >= 2:
        score += 3
        warnings.append(f"Multiple phishing keywords detected ({keyword_count})")
    elif keyword_count == 1:
        score += 1
        warnings.append("Single phishing keyword detected")

    # 8. URL Shortener Check
    for shortener in url_shorteners:
        if shortener in domain:
            score += 1
            warnings.append("URL shortener detected")

    # Threat Level
    if score >= 6:
        threat_level = "HIGH"
    elif score >= 3:
        threat_level = "MEDIUM"
    else:
        threat_level = "LOW"

    # World Safety Class & Rank
    if score >= 8:
        world_class = "CRITICAL"
        rank = "Rank 5 (Globally Dangerous)"
    elif score >= 6:
        world_class = "DANGEROUS"
        rank = "Rank 4 (High Global Risk)"
    elif score >= 4:
        world_class = "SUSPICIOUS"
        rank = "Rank 3 (Moderate Risk)"
    elif score >= 2:
        world_class = "SAFE"
        rank = "Rank 2 (Generally Safe)"
    else:
        world_class = "TRUSTED"
        rank = "Rank 1 (Globally Trusted)"

    return {
        "score": score,
        "threat_level": threat_level,
        "world_class": world_class,
        "rank": rank,
        "url_length": url_length,
        "length_type": length_type,
        "warnings": warnings
    }

@app.route("/", methods=["GET", "POST"])
def index():
    result = ""
    if request.method == "POST":
        url = request.form["url"]
        result = check_url_safety(url)
    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True, port=5001)
