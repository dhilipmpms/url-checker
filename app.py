from flask import Flask, render_template, request
import re
from urllib.parse import urlparse

app = Flask(__name__)

def check_url_safety(url):
    """
    Enhanced URL safety checker with multiple security checks
    """
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
    parsed_url = urlparse(url)

    # HTTPS check
    if parsed_url.scheme != "https":
        score += 2
        warnings.append("Not using HTTPS")

    # Check for IP address instead of domain
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parsed_url.netloc.split(':')[0]):
        score += 3
        warnings.append("Using IP address instead of domain")

    # Suspicious TLD check
    for tld in suspicious_tlds:
        if parsed_url.netloc.endswith(tld):
            score += 2
            warnings.append(f"Suspicious TLD: {tld}")

    # URL length check
    if len(url) > 75:
        score += 1
        warnings.append("Unusually long URL")

    # Excessive subdomains check
    domain_parts = parsed_url.netloc.split('.')
    if len(domain_parts) > 4:
        score += 2
        warnings.append("Too many subdomains")

    # Suspicious characters check
    if '@' in parsed_url.netloc or '-' * 3 in url:
        score += 2
        warnings.append("Suspicious characters detected")

    # Keyword check
    keyword_count = 0
    for keyword in suspicious_keywords:
        if re.search(keyword, url, re.IGNORECASE):
            keyword_count += 1
    
    if keyword_count >= 2:
        score += 3
        warnings.append(f"Multiple phishing keywords ({keyword_count})")
    elif keyword_count == 1:
        score += 1
        warnings.append("Phishing keyword detected")

    # URL shortener check
    for shortener in url_shorteners:
        if shortener in parsed_url.netloc:
            score += 1
            warnings.append("URL shortener detected")

    # Determine safety level
    if score >= 5:
        return f"🚨 Unsafe URL ❌ (Risk Score: {score})"
    elif score >= 3:
        return f"⚠️ Suspicious URL (Risk Score: {score})"
    else:
        return f"✅ Safe URL (Risk Score: {score})"

@app.route("/", methods=["GET", "POST"])
def index():
    result = ""
    if request.method == "POST":
        url = request.form["url"]
        result = check_url_safety(url)
    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True, port=5001)
