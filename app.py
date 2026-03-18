from flask import Flask, request, jsonify, render_template
import re
import socket
import ssl
import requests
import whois
import datetime
import tldextract
import base64

app = Flask(__name__)

# 🔑 VirusTotal API Key
VT_API_KEY = "b9c166bd9613b8c62d6bc82b100a1827285aad995034c9160963f7c7a6fef8ed"

# suspicious keywords
SUSPICIOUS_KEYWORDS = [
    "login","verify","update","secure","account","bank",
    "signin","confirm","password","wallet","payment"
]

# temporary hosting domains
TEMP_DOMAINS = [
    "trycloudflare.com","ngrok.io","vercel.app",
    "pages.dev","netlify.app","herokuapp.com"
]

# suspicious TLDs
SUSPICIOUS_TLDS = [
    ".tk",".ml",".ga",".cf",".gq",".xyz",".top"
]

def add_score(current,value):
    current += value
    return min(current,100)


# VirusTotal Check
def check_virustotal(url):
    try:

        headers = {"x-apikey": VT_API_KEY}

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        response = requests.get(report_url,headers=headers)

        if response.status_code != 200:
            return None

        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        return stats["malicious"]

    except:
        return None


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/analyze', methods=['POST'])
def analyze():

    data = request.get_json()
    url = data['url']

    score = 0
    warnings = []

    ext = tldextract.extract(url)
    domain = ext.domain + "." + ext.suffix
    subdomain = ext.subdomain


    # RULE 1 - URL length
    if len(url) > 75:
        score = add_score(score,10)
        warnings.append("URL is unusually long")


    # RULE 2 - @ symbol
    if "@" in url:
        score = add_score(score,20)
        warnings.append("URL contains @ symbol")


    # RULE 3 - IP address
    ip_pattern = r"https?://\d+\.\d+\.\d+\.\d+"
    if re.search(ip_pattern,url):
        score = add_score(score,25)
        warnings.append("URL uses IP address instead of domain")


    # RULE 4 - HTTP
    if url.startswith("http://"):
        score = add_score(score,10)
        warnings.append("Website not using HTTPS")


    # RULE 5 - Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if url.endswith(tld):
            score = add_score(score,15)
            warnings.append("Suspicious domain extension")


    # RULE 6 - Subdomain abuse
    if subdomain.count(".") >= 2:
        score = add_score(score,15)
        warnings.append("Too many subdomains detected")


    # RULE 7 - Long subdomain
    if len(subdomain) > 20:
        score = add_score(score,15)
        warnings.append("Suspicious long subdomain")


    # RULE 8 - Hyphens
    if url.count("-") > 3:
        score = add_score(score,10)
        warnings.append("Multiple hyphens in domain")


    # RULE 9 - Port numbers
    if ":" in url[8:]:
        score = add_score(score,10)
        warnings.append("Non standard port detected")


    # RULE 10 - Keywords
    for word in SUSPICIOUS_KEYWORDS:
        if word in url.lower():
            score = add_score(score,5)
            warnings.append(f"Suspicious keyword detected: {word}")


    # RULE 11 - Temporary hosting
    for host in TEMP_DOMAINS:
        if host in url:
            score = add_score(score,25)
            warnings.append("Temporary hosting domain detected")


    # RULE 12 - WHOIS Domain Age
    try:

        w = whois.whois(domain)

        creation = w.creation_date

        if isinstance(creation,list):
            creation = creation[0]

        if creation:

            age = (datetime.datetime.now() - creation).days

            if age < 180:
                score = add_score(score,20)
                warnings.append("Domain is very new (<6 months)")
            else:
                warnings.append(f"Domain age: {age} days")

        else:
            warnings.append("Domain creation date unavailable")

    except:
        warnings.append("WHOIS lookup failed")


    # RULE 13 - DNS check
    try:
        socket.gethostbyname(domain)
    except:
        score = add_score(score,15)
        warnings.append("DNS resolution failed")


    # RULE 14 - SSL certificate
    try:

        ctx = ssl.create_default_context()

        with ctx.wrap_socket(socket.socket(),server_hostname=domain) as s:
            s.settimeout(3)
            s.connect((domain,443))
            cert = s.getpeercert()

            if not cert:
                score = add_score(score,20)
                warnings.append("Invalid SSL certificate")

    except:
        score = add_score(score,20)
        warnings.append("SSL certificate check failed")


    # RULE 15 - PhishTank
    try:

        response = requests.get(
            "https://checkurl.phishtank.com/checkurl/",
            params={"url":url}
        )

        if "phish" in response.text.lower():
            score = add_score(score,50)
            warnings.append("URL found in phishing database")

    except:
        warnings.append("PhishTank check unavailable")


    # RULE 16 - VirusTotal
    vt_result = check_virustotal(url)

    if vt_result is not None:

        if vt_result > 0:
            score = add_score(score,40)
            warnings.append("VirusTotal flagged this URL as malicious")
        else:
            warnings.append("VirusTotal scan clean")


    score = min(score,100)


    if score < 30:
        status = "Safe"
        color = "green"

    elif score < 70:
        status = "Suspicious"
        color = "orange"

    else:
        status = "Phishing Detected"
        color = "red"


    return jsonify({
        "score":score,
        "status":status,
        "color":color,
        "warnings":warnings
    })


if __name__ == "__main__":
    app.run(debug=True)