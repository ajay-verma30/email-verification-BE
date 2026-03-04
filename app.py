from fastapi import FastAPI
import dns.resolver
import whois
import requests
import httpx
import re
import pandas as pd
import numpy as np
import joblib
from datetime import datetime
from fastapi.middleware.cors import CORSMiddleware

# Model load karo
ml_model = joblib.load('email_model.pkl')
important_features = joblib.load('features.pkl')

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Temp domains load karo
urls = [
    "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf",
    "https://raw.githubusercontent.com/martenson/disposable-email-domains/master/disposable.txt"
]
temp_domains = set()
for url in urls:
    try:
        response = requests.get(url, timeout=10)
        temp_domains.update(response.text.splitlines())
    except:
        pass

extra_domains = ["tempmail.com", "temp-mail.org", "throwmail.com", "dollicons.com"]
temp_domains.update(extra_domains)

free_providers = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "icloud.com", "protonmail.com", "zoho.com",
    "yandex.com", "mail.com", "gmx.com", "live.com"
}

whitelist = {
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "servicenow.com", "salesforce.com", "oracle.com", "sap.com",
    "zohocorp.com"
}

# ─── ML Check ─────────────────────────────────────────────────────────────────
def ml_check(email):
    try:
        username, domain = email.split('@')

        features = {
            'is_free_provider': int(domain in free_providers),
            'domain_length': len(domain),
            'is_known_fake': int(domain in temp_domains),
            'is_known_legit': int(domain in whitelist),
            'username_length': len(username)
        }

        df = pd.DataFrame([features])
        prediction = ml_model.predict(df)[0]
        probability = ml_model.predict_proba(df)[0]

        return {
            'prediction': int(prediction),
            'confidence': round(float(max(probability)) * 100, 2)
        }
    except:
        return None

# ─── Spam Blacklist Check ─────────────────────────────────────────────────────
def check_spam_blacklist(domain):
    blacklists = [
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "dnsbl.sorbs.net"
    ]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_host = str(list(mx_records)[0].exchange).rstrip('.')
        ip_records = dns.resolver.resolve(mx_host, 'A')
        ip = str(list(ip_records)[0])
        reversed_ip = '.'.join(reversed(ip.split('.')))

        for blacklist in blacklists:
            try:
                dns.resolver.resolve(f"{reversed_ip}.{blacklist}", 'A')
                return False
            except:
                pass
        return True
    except:
        return True

# ─── MX Hostname Check ───────────────────────────────────────────────────────
def check_mx_hostname(domain):
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        for mx in mx_records:
            mx_host = str(mx.exchange).rstrip('.')
            try:
                dns.resolver.resolve(mx_host, 'A')
                return True
            except:
                pass
        return False
    except:
        return False

# ─── Typosquatting Check ─────────────────────────────────────────────────────
def check_typosquatting(domain):
    famous_domains = [
        "google", "microsoft", "apple", "amazon", "facebook",
        "twitter", "linkedin", "github", "netflix", "paypal"
    ]
    domain_name = domain.split('.')[0].lower()
    normalized = domain_name.replace('0', 'o').replace('1', 'l').replace('3', 'e')

    for famous in famous_domains:
        if normalized == famous and domain_name != famous:
            return True
    return False

# ─── Website Check ───────────────────────────────────────────────────────────
def check_website(domain):
    try:
        response = httpx.get(f"http://{domain}", timeout=5, follow_redirects=True)
        content = response.text.lower()

        if response.status_code == 403:
            return False

        bad_keywords = [
            "parked domain", "buy this domain", "domain for sale",
            "this domain is for sale", "search ads",
            "public email service", "temporary email", "disposable email",
            "anonymous email", "free email service", "privacy email",
            "throwaway email", "fake email", "this domain is parked"
        ]

        for keyword in bad_keywords:
            if keyword in content:
                return False

        return True
    except:
        return False

# ─── Main Endpoint ───────────────────────────────────────────────────────────
@app.get("/check-email")
def check_email(email: str):
    score = 0
    reasons = []

    # Basic format check
    if "@" not in email or len(email) < 5:
        return {"email": email, "score": 0, "status": "Block", "reasons": ["❌ Invalid email format"]}

    username, domain = email.split("@")[0], email.split("@")[1]

    # Special characters check
    if not re.match(r'^[a-zA-Z0-9._%+\-]+$', username):
        return {"email": email, "score": 0, "status": "Block", "reasons": ["❌ Invalid characters in email"]}

    # IP based email check
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
        return {"email": email, "score": 0, "status": "Block", "reasons": ["❌ IP based email not allowed"]}

    # Too many subdomains
    if domain.count('.') > 3:
        return {"email": email, "score": 0, "status": "Block", "reasons": ["❌ Too many subdomains - suspicious"]}

    # Punycode check
    if 'xn--' in domain:
        return {"email": email, "score": 0, "status": "Block", "reasons": ["❌ Punycode domain - suspicious"]}

    # Whitelist
    if domain in whitelist:
        return {"email": email, "score": 100, "status": "Allow", "reasons": ["✅ Trusted domain - Whitelisted"]}

    # Free provider check
    if domain in free_providers:
        return {"email": email, "score": 20, "status": "Block", "reasons": ["❌ Personal/Free email provider not allowed"]}

    # Temp mail check (+25)
    if domain not in temp_domains:
        score += 25
        reasons.append("✅ Not a known temp mail domain")
    else:
        return {"email": email, "score": 0, "status": "Block", "reasons": ["❌ Known temp/disposable email"]}

    # Typosquatting check
    if check_typosquatting(domain):
        return {"email": email, "score": 0, "status": "Block", "reasons": ["❌ Typosquatting detected - fake domain!"]}

    # MX records (+20)
    try:
        dns.resolver.resolve(domain, 'MX')
        score += 20
        reasons.append("✅ MX records valid")
    except:
        return {"email": email, "score": score, "status": "Block", "reasons": reasons + ["❌ No MX records found"]}

    # MX hostname (+10)
    if check_mx_hostname(domain):
        score += 10
        reasons.append("✅ MX hostname resolves correctly")
    else:
        reasons.append("⚠️ MX hostname does not resolve")

    # Domain age (+20)
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age_days = (datetime.now() - creation_date.replace(tzinfo=None)).days
        if age_days > 365:
            score += 20
            reasons.append(f"✅ Domain {age_days} days old")
        else:
            reasons.append(f"⚠️ New domain - only {age_days} days old")
    except whois.exceptions.WhoisDomainNotFoundError:
        return {"email": email, "score": score, "status": "Block", "reasons": reasons + ["❌ Domain does not exist"]}
    except:
        reasons.append("⚠️ WHOIS check failed")

    # Spam blacklist (+10)
    if check_spam_blacklist(domain):
        score += 10
        reasons.append("✅ Not on spam blacklists")
    else:
        reasons.append("⚠️ Domain found on spam blacklist")
        return {"email": email, "score": score, "status": "Block", "reasons": reasons}

    # Website check (+15)
    if check_website(domain):
        score += 15
        reasons.append("✅ Real website exists")
    else:
        reasons.append("⚠️ Parked, fake or public email service")
        return {"email": email, "score": score, "status": "Block", "reasons": reasons}

    # ML Check
    ml_result = ml_check(email)
    if ml_result:
        reasons.append(f"🤖 ML Model: {'✅ Legit' if ml_result['prediction'] == 0 else '❌ Fake'} ({ml_result['confidence']}% confidence)")

    # Final status
    if score >= 75:
        status = "Allow"
    elif score >= 50:
        status = "Suspicious"
    else:
        status = "Block"

    return {
        "email": email,
        "score": score,
        "status": status,
        "reasons": reasons
    }
