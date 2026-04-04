import requests
import os
import base64
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def check_url_virustotal(url):
    if not VIRUSTOTAL_API_KEY:
        return get_fallback_result(url)
    
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())
            
            if malicious > 0:
                verdict = "MALICIOUS"
                risk = "HIGH"
            elif suspicious > 0:
                verdict = "SUSPICIOUS"
                risk = "MEDIUM"
            else:
                verdict = "CLEAN"
                risk = "LOW"
            
            return {
                "url": url,
                "verdict": verdict,
                "risk": risk,
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "total_engines": total,
                "source": "VirusTotal"
            }
        else:
            return submit_url_virustotal(url)
            
    except Exception as e:
        print(f"VirusTotal error for {url}: {e}")
        return get_fallback_result(url)

def submit_url_virustotal(url):
    try:
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY,
            "content-type": "application/x-www-form-urlencoded"
        }
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data=f"url={url}",
            timeout=10
        )
        
        if response.status_code == 200:
            return {
                "url": url,
                "verdict": "SUBMITTED",
                "risk": "UNKNOWN",
                "malicious_count": 0,
                "suspicious_count": 0,
                "total_engines": 0,
                "source": "VirusTotal (submitted for analysis)"
            }
    except:
        pass
    
    return get_fallback_result(url)

def get_fallback_result(url):
    suspicious_patterns = [
        'bit.ly', 'tinyurl', 'goo.gl', 't.co',
        'login', 'verify', 'secure', 'account',
        'update', 'confirm', 'banking', 'paypal-',
        'amazon-', 'google-', 'microsoft-'
    ]
    
    url_lower = url.lower()
    risk_factors = [p for p in suspicious_patterns if p in url_lower]
    
    if len(risk_factors) >= 2:
        verdict = "SUSPICIOUS"
        risk = "MEDIUM"
    elif len(risk_factors) == 1:
        verdict = "POTENTIALLY SUSPICIOUS"
        risk = "LOW-MEDIUM"
    else:
        verdict = "UNKNOWN"
        risk = "UNKNOWN"
    
    return {
        "url": url,
        "verdict": verdict,
        "risk": risk,
        "malicious_count": 0,
        "suspicious_count": len(risk_factors),
        "total_engines": 0,
        "source": "Pattern analysis (VirusTotal unavailable)"
    }

def check_urls(urls):
    results = []
    for url in urls[:5]:
        result = check_url_virustotal(url)
        results.append(result)
    return results