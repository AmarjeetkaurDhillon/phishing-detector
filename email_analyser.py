import re
import email
from email import policy
from email.parser import BytesParser, Parser
from datetime import datetime

def parse_email(raw_email):
    try:
        msg = Parser(policy=policy.default).parsestr(raw_email)
    except Exception as e:
        return None, f"Failed to parse email: {e}"
    return msg, None

def check_spf_dkim_dmarc(msg):
    headers = dict(msg.items())
    results = {
        "spf": "missing",
        "dkim": "missing", 
        "dmarc": "missing",
        "received_spf": "missing"
    }
    
    for key, value in headers.items():
        key_lower = key.lower()
        value_lower = value.lower()
        
        if key_lower == "received-spf":
            if "pass" in value_lower:
                results["received_spf"] = "pass"
            elif "fail" in value_lower:
                results["received_spf"] = "fail"
            elif "softfail" in value_lower:
                results["received_spf"] = "softfail"
            else:
                results["received_spf"] = "neutral"
                
        if key_lower == "authentication-results":
            if "spf=pass" in value_lower:
                results["spf"] = "pass"
            elif "spf=fail" in value_lower:
                results["spf"] = "fail"
            elif "spf=softfail" in value_lower:
                results["spf"] = "softfail"
                
            if "dkim=pass" in value_lower:
                results["dkim"] = "pass"
            elif "dkim=fail" in value_lower:
                results["dkim"] = "fail"
                
            if "dmarc=pass" in value_lower:
                results["dmarc"] = "pass"
            elif "dmarc=fail" in value_lower:
                results["dmarc"] = "fail"
    
    return results

def check_sender_spoofing(msg):
    issues = []
    
    from_header = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")
    
    from_email = re.findall(r'[\w\.-]+@[\w\.-]+', from_header)
    reply_to_emails = re.findall(r'[\w\.-]+@[\w\.-]+', reply_to)
    return_path_emails = re.findall(r'[\w\.-]+@[\w\.-]+', return_path)
    
    if from_email and reply_to_emails:
        if from_email[0].split('@')[1] != reply_to_emails[0].split('@')[1]:
            issues.append(f"Reply-To domain differs from From domain — From: {from_email[0]}, Reply-To: {reply_to_emails[0]}")
    
    if from_email and return_path_emails:
        if from_email[0].split('@')[1] != return_path_emails[0].split('@')[1]:
            issues.append(f"Return-Path domain differs from From domain")
    
    display_name = re.findall(r'^([^<]+)<', from_header)
    if display_name and from_email:
        name = display_name[0].strip().lower()
        domain = from_email[0].split('@')[1].lower()
        trusted_brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'bank', 'hsbc', 'barclays']
        for brand in trusted_brands:
            if brand in name and brand not in domain:
                issues.append(f"Display name mentions '{brand}' but sender domain is '{domain}' — possible impersonation")
    
    return issues

def extract_urls(text):
    url_pattern = re.compile(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    )
    return list(set(url_pattern.findall(text)))

def check_suspicious_patterns(msg):
    suspicious = []
    
    subject = msg.get("Subject", "").lower()
    urgent_words = ['urgent', 'immediate', 'action required', 'verify', 'suspended', 
                   'locked', 'unusual activity', 'confirm', 'click here', 'limited time',
                   'act now', 'your account', 'security alert', 'winner', 'prize']
    
    for word in urgent_words:
        if word in subject:
            suspicious.append(f"Urgent/alarming language in subject: '{word}'")
    
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                except:
                    pass
    else:
        try:
            body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
        except:
            body = str(msg.get_payload())
    
    body_lower = body.lower()
    phishing_phrases = [
        'click here to verify', 'confirm your account', 'your account has been',
        'unusual sign-in', 'we detected', 'verify your identity', 'update your payment',
        'your password will expire', 'click the link below'
    ]
    
    for phrase in phishing_phrases:
        if phrase in body_lower:
            suspicious.append(f"Phishing phrase detected: '{phrase}'")
    
    urls = extract_urls(body)
    
    for url in urls:
        if any(char in url for char in ['@', '%', '-login', '-verify', '-secure']):
            suspicious.append(f"Suspicious URL pattern: {url[:60]}")
    
    return suspicious, urls, body

def calculate_risk_score(auth_results, spoofing_issues, suspicious_patterns, url_count):
    score = 0
    
    if auth_results['spf'] == 'fail':
        score += 25
    elif auth_results['spf'] == 'missing':
        score += 10
        
    if auth_results['dkim'] == 'fail':
        score += 25
    elif auth_results['dkim'] == 'missing':
        score += 10
        
    if auth_results['dmarc'] == 'fail':
        score += 20
    elif auth_results['dmarc'] == 'missing':
        score += 5
    
    score += len(spoofing_issues) * 15
    score += len(suspicious_patterns) * 10
    
    if url_count > 3:
        score += 10
    
    score = min(score, 100)
    
    if score >= 70:
        risk_level = "HIGH"
        verdict = "LIKELY PHISHING"
    elif score >= 40:
        risk_level = "MEDIUM"
        verdict = "SUSPICIOUS"
    else:
        risk_level = "LOW"
        verdict = "LIKELY LEGITIMATE"
    
    return score, risk_level, verdict

def analyse_email(raw_email):
    msg, error = parse_email(raw_email)
    if error:
        return {"error": error}
    
    auth_results = check_spf_dkim_dmarc(msg)
    spoofing_issues = check_sender_spoofing(msg)
    suspicious_patterns, urls, body = check_suspicious_patterns(msg)
    score, risk_level, verdict = calculate_risk_score(
        auth_results, spoofing_issues, suspicious_patterns, len(urls)
    )
    
    return {
        "from": msg.get("From", "Unknown"),
        "subject": msg.get("Subject", "No Subject"),
        "date": msg.get("Date", "Unknown"),
        "auth_results": auth_results,
        "spoofing_issues": spoofing_issues,
        "suspicious_patterns": suspicious_patterns,
        "urls": urls[:10],
        "url_count": len(urls),
        "risk_score": score,
        "risk_level": risk_level,
        "verdict": verdict
    }