from flask import Flask, render_template, request
from email_analyser import analyse_email
from url_checker import check_urls
import os

app = Flask(__name__)

SAMPLE_PHISHING_EMAIL = """From: "PayPal Security" <security@paypal-verify-account.com>
To: victim@example.com
Subject: URGENT: Your PayPal account has been suspended
Date: Sat, 04 Apr 2026 10:00:00 +0000
Reply-To: support@totally-not-paypal.ru

Dear Customer,

We have detected unusual activity on your PayPal account. Your account has been suspended.

You must verify your identity immediately or your account will be permanently closed.

Click here to verify: http://paypal-login-secure-verify.com/account/confirm?id=123456

This is urgent. Act now to restore access to your account.

PayPal Security Team"""

@app.route("/", methods=["GET", "POST"])
def index():
    results = None
    url_results = None
    raw_email = ""
    error = None

    if request.method == "POST":
        raw_email = request.form.get("email_content", "").strip()
        
        if not raw_email:
            error = "Please paste an email to analyse."
        else:
            try:
                results = analyse_email(raw_email)
                if "error" not in results and results.get("urls"):
                    url_results = check_urls(results["urls"])
            except Exception as e:
                error = f"Analysis failed: {str(e)}"

    return render_template("index.html", 
                         results=results,
                         url_results=url_results,
                         raw_email=raw_email,
                         error=error,
                         sample_email=SAMPLE_PHISHING_EMAIL)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)