"""
VulnScanner - OWASP Top 10 Vulnerability Scanner (Reflected XSS, SQLi, Security Headers)

Author: [Your Name]
License: MIT
Description:
A lightweight Python CLI tool that performs basic security checks for common OWASP Top 10 vulnerabilities:
- Reflected Cross-Site Scripting (XSS)
- SQL Injection (SQLi)
- Missing HTTP Security Headers

Supports Markdown reporting for GitHub integration.
"""

import requests
import argparse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import Fore, init
from datetime import datetime
import html

# Initialize colorama for colorful terminal output
init(autoreset=True)

# === Payload Definitions ===
XSS_PAYLOAD = "<script>alert(1)</script>"
SQLI_PAYLOAD = "' OR 1=1 --"
SQLI_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated"
]

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "X-Frame-Options"
]


def test_xss(url, output_lines):
    """
    Tests for reflected XSS vulnerabilities by injecting a script payload into each query parameter.
    """
    print(f"\n🔍 Testing for Reflected XSS...")

    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    if not query:
        print(Fore.YELLOW + "[WARN] No query parameters found to test for XSS.")
        output_lines.append("### XSS\n- No parameters to test.\n")
        return

    found = False
    output_lines.append("### XSS\n")
    for param in query:
        test_query = query.copy()
        test_query[param] = XSS_PAYLOAD
        test_url = parsed._replace(query=urlencode(test_query, doseq=True))
        final_url = urlunparse(test_url)

        response = requests.get(final_url, verify=False)
        body_raw = response.text
        body_unescaped = html.unescape(body_raw)

        if response.status_code >= 500:
            print(Fore.YELLOW + f"[!] Warning: Received {response.status_code} status code.")
            output_lines.append(f"- [!] Status {response.status_code} from `{param}` may indicate error-based XSS.\n")

        if (
            XSS_PAYLOAD in body_unescaped or
            XSS_PAYLOAD.replace('<', '&lt;').replace('>', '&gt;') in body_raw or
            f'value="{XSS_PAYLOAD}"' in body_unescaped or
            f'>{XSS_PAYLOAD}<' in body_unescaped
        ):
            print(Fore.RED + f"[XSS] Found reflected XSS on parameter '{param}' using payload: {XSS_PAYLOAD}")
            output_lines.append(f"- 🔥 **Vulnerable:** `{param}` reflected XSS detected.\n")
            found = True

    if not found:
        print(Fore.GREEN + "[XSS] No reflected XSS detected.")
        output_lines.append("- ✅ No reflected XSS found.\n")


def test_sqli(url, output_lines):
    """
    Tests for basic SQL Injection by injecting SQLi payload and looking for errors or output length anomalies.
    """
    print(f"\n🔍 Testing for SQL Injection...")

    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    if not query:
        print(Fore.YELLOW + "[WARN] No query parameters found to test for SQLi.")
        output_lines.append("### SQL Injection\n- No parameters to test.\n")
        return

    response_base = requests.get(url, verify=False)
    len_base = len(response_base.text)

    found = False
    output_lines.append("### SQL Injection\n")
    for param in query:
        test_query = query.copy()
        test_query[param] = SQLI_PAYLOAD
        test_url = parsed._replace(query=urlencode(test_query, doseq=True))
        final_url = urlunparse(test_url)

        response = requests.get(final_url, verify=False)
        body = response.text.lower()

        if response.status_code >= 500:
            print(Fore.YELLOW + f"[!] Warning: Received {response.status_code} status code.")
            output_lines.append(f"- [!] Status {response.status_code} from `{param}` may indicate SQL error.\n")

        if any(err in body for err in SQLI_ERRORS) or abs(len(response.text) - len_base) > 100:
            print(Fore.RED + f"[SQLi] Found vulnerability on parameter '{param}' using payload: {SQLI_PAYLOAD}")
            output_lines.append(f"- 💉 **Vulnerable:** `{param}` SQLi detected with payload `{SQLI_PAYLOAD}`\n")
            found = True

    if not found:
        print(Fore.GREEN + "[SQLi] No SQLi detected.")
        output_lines.append("- ✅ No SQL injection found.\n")


def check_security_headers(url, output_lines):
    """
    Checks for missing HTTP security headers such as CSP, HSTS, etc.
    """
    print(f"\n🔍 Checking for Security Headers...")

    try:
        response = requests.get(url, verify=False)
        missing = [h for h in SECURITY_HEADERS if h not in response.headers]

        output_lines.append("### Security Headers\n")
        if missing:
            print(Fore.YELLOW + f"[Headers] Missing: {', '.join(missing)}")
            output_lines.append(f"- ⚠️ Missing headers: {', '.join(missing)}\n")
        else:
            print(Fore.GREEN + "[Headers] All essential headers are present.")
            output_lines.append("- ✅ All essential headers present.\n")
    except Exception as e:
        print(Fore.RED + f"[ERROR] Could not fetch headers: {e}")
        output_lines.append(f"- ❌ Error fetching headers: {e}\n")


def main():
    """
    Main CLI logic – parses arguments, runs tests, and writes optional report.
    """
    parser = argparse.ArgumentParser(description="OWASP Top 10 Vuln Scanner")
    parser.add_argument("--url", required=True, help="Target URL (with parameters)")
    parser.add_argument("--output", help="Save report to file (supports .txt or .md)")

    args = parser.parse_args()
    url = args.url
    output_lines = []

    print(Fore.MAGENTA + f"🚨 Starting vulnerability scan on {url}...")

    from urllib3 import disable_warnings
    from urllib3.exceptions import InsecureRequestWarning
    disable_warnings(InsecureRequestWarning)

    # Markdown Header
    if args.output and args.output.endswith(".md"):
        output_lines.append(f"# Vulnerability Report – {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        output_lines.append(f"**Target:** `{url}`\n\n---\n")

    test_xss(url, output_lines)
    test_sqli(url, output_lines)
    check_security_headers(url, output_lines)

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            if not args.output.endswith(".md"):
                f.write(f"Vulnerability Scan Report – {datetime.now()}\n\n")
            f.write("".join(output_lines))
        print(Fore.CYAN + f"\n📄 Report saved to {args.output}")
        print(Fore.YELLOW + "💡 Tip: Open with any Markdown or text viewer.")


if __name__ == "__main__":
    main()
