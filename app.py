from flask import Flask, render_template, request
import re
from urllib.parse import urlparse
import ipaddress

app = Flask(__name__)

def check_url_safety(url):
    suspicious_keywords = [
        "login","verify","bank","free","win","prize",
        "account","secure","update","confirm","password",
        "billing","paypal","amazon","netflix","apple",
        "microsoft","google","suspended","locked","urgent"
    ]
    suspicious_tlds = [".tk",".ml",".ga",".cf",".gq",".xyz",".top"]
    url_shorteners = ["bit.ly","tinyurl.com","goo.gl","ow.ly","t.co"]

    score = 0
    report = []
    original_url = url
    if not url.startswith(('http://','https://')):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.split(":")[0]
    domain_safe = True

    # HTTPS Check
    if parsed.scheme != "https":
        score += 2
        report.append(("HTTPS Check","FAIL",f"Protocol: {parsed.scheme}",2))
        domain_safe = False
    else:
        report.append(("HTTPS Check","PASS",f"Protocol: {parsed.scheme}",0))

    # IP Address Check
    try:
        ipaddress.ip_address(domain)
        score += 3
        report.append(("Domain Type","FAIL",f"IP Address: {domain}",3))
        domain_safe = False
    except:
        report.append(("Domain Type","PASS",f"Domain: {domain}",0))

    # TLD Check
    tld_found = None
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            tld_found = tld
            score += 2
            report.append(("Top Level Domain","FAIL",f"TLD: {tld}",2))
            domain_safe = False
            break
    if not tld_found:
        report.append(("Top Level Domain","PASS",f"TLD: .{domain.split('.')[-1]}",0))

    # URL Length
    url_length = len(original_url)
    if url_length <= 75:
        length_type = "Short/Moderate"
    else:
        length_type = "Long"
        score += 1
    report.append(("URL Length","PASS" if url_length<=75 else "WARNING",
                   f"Length: {url_length} ({length_type})",
                   1 if url_length>75 else 0))

    # Subdomain Detection
    domain_parts = domain.split(".")
    subdomain_list = []
    if len(domain_parts) > 2:
        subdomain_list = domain_parts[:-2]

    if subdomain_list:
        subdomain_names = ", ".join(subdomain_list)
        if len(subdomain_list) > 2:
            score += 2
            sub_status = "FAIL"
            domain_safe = False
        else:
            score += 1
            sub_status = "WARNING"
        report.append(("Subdomain Analysis",sub_status,
                       f"Subdomains: {subdomain_names} (Total: {len(subdomain_list)})",
                       1 if sub_status=="WARNING" else 2))
    else:
        report.append(("Subdomain Analysis","PASS","No subdomains",0))

    # Suspicious Characters
    special_chars = []
    if "@" in original_url:
        special_chars.append("@")
    if "---" in original_url:
        special_chars.append("---")
    if special_chars:
        score += 2
        report.append(("Special Characters","FAIL",
                       f"Detected: {', '.join(special_chars)}",2))
        domain_safe = False
    else:
        report.append(("Special Characters","PASS","None",0))

    # Keyword Detection
    detected_keywords = []
    for keyword in suspicious_keywords:
        if re.search(keyword, original_url, re.IGNORECASE):
            detected_keywords.append(keyword)
    if len(detected_keywords) >= 2:
        score += 3
        report.append(("Phishing Keywords","FAIL",
                       f"Keywords: {', '.join(detected_keywords)}",3))
        domain_safe = False
    elif len(detected_keywords) == 1:
        score += 1
        report.append(("Phishing Keywords","WARNING",
                       f"Keyword: {detected_keywords[0]}",1))
    else:
        report.append(("Phishing Keywords","PASS","None",0))

    # URL Shortener
    short_found = None
    for short in url_shorteners:
        if short in domain:
            short_found = short
            score += 1
            report.append(("URL Shortener","WARNING",f"Shortener: {short}",1))
            domain_safe = False
            break
    if not short_found:
        report.append(("URL Shortener","PASS","None",0))

    # Risk Level
    if score >= 6:
        level = "HIGH"
        emoji = "🚨"
    elif score >= 3:
        level = "MEDIUM"
        emoji = "⚠"
    else:
        level = "LOW"
        emoji = "✅"

    if domain_safe and level == "LOW":
        world_level = "Globally Trusted (Safe Domain & Subdomain)"
    elif domain_safe and level == "MEDIUM":
        world_level = "Moderately Safe (Minor Issues)"
    else:
        world_level = "Globally Dangerous (Unsafe Domain / Subdomain)"

    return {
        "score": score,
        "level": level,
        "emoji": emoji,
        "report": report,
        "url": url,
        "world_level": world_level
    }

# -----------------------
# Routes
# -----------------------
@app.route("/", methods=["GET","POST"])
def index():
    if request.method == "POST":
        url = request.form["url"]
        result = check_url_safety(url)
        return render_template("result.html", result=result)
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True, port=5001)
