#!/usr/bin/env python3
import argparse
import csv
import json
import sys
from requests.exceptions import RequestException
import requests

# [EN] Dictionary of critical security headers with weights, descriptions, and fixes
# [UA] Словник критичних заголовків безпеки з вагою, описами та рішеннями
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "weight": 25,
        "why": "Forces browsers to access the site exclusively via HTTPS, protecting against MitM attacks.",
        "fix": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    },
    "Content-Security-Policy": {
        "weight": 25,
        "why": "Protects against Cross-Site Scripting (XSS) attacks by restricting script sources.",
        "fix": "Add header: Content-Security-Policy: default-src 'self'"
    },
    "X-Frame-Options": {
        "weight": 20,
        "why": "Prevents the site from being loaded in iframes of third-party sites (Clickjacking defense).",
        "fix": "Add header: X-Frame-Options: SAMEORIGIN (or DENY)"
    },
    "X-Content-Type-Options": {
        "weight": 15,
        "why": "Stops browsers from MIME-sniffing away from the declared content type.",
        "fix": "Add header: X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "weight": 10,
        "why": "Controls how much sensitive URL information is sent when navigating to other sites.",
        "fix": "Add header: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "weight": 5,
        "why": "Restricts the site's access to sensitive browser APIs (camera, microphone, geolocation).",
        "fix": "Add header: Permissions-Policy: geolocation=(), microphone=()"
    }
}

def audit_domain(domain):
    """
    [EN] Performs HTTP request and checks headers presence.
    [UA] Виконує HTTP-запит та перевіряє наявність заголовків.
    """
    url = domain if domain.startswith("http") else f"https://{domain}"
    score = 0
    max_score = sum(item["weight"] for item in SECURITY_HEADERS.values())
    results = {}

    try:
        # [EN] Send GET request with timeout and redirects allowed
        # [UA] Надсилаємо GET-запит із таймаутом та дозвілом редиректів
        response = requests.get(url, timeout=7, allow_redirects=True)
        response_headers = {k.lower(): v for k, v in response.headers.items()}

        for header, info in SECURITY_HEADERS.items():
            header_lower = header.lower()
            if header_lower in response_headers:
                results[header] = {
                    "status": "Present",
                    "value": response_headers[header_lower],
                    "why": info["why"],
                    "fix": None
                }
                score += info["weight"]
            else:
                results[header] = {
                    "status": "Missing",
                    "value": None,
                    "why": info["why"],
                    "fix": info["fix"]
                }

        return {
            "domain": domain,
            "final_url": response.url,
            "status_code": response.status_code,
            "score": score,
            "max_score": max_score,
            "percentage": round((score / max_score) * 100, 2),
            "details": results,
            "error": None
        }

    except RequestException as e:
        return {
            "domain": domain,
            "final_url": None,
            "status_code": None,
            "score": 0,
            "max_score": max_score,
            "percentage": 0.0,
            "details": {},
            "error": str(e)
        }

def print_pretty_report(res):
    """
    [EN] Prints intuitive and detailed report to terminal.
    [UA] Виводить інтуїтивний та детальний звіт у термінал.
    """
    print("=" * 70)
    print(f" TARGET DOMAIN: {res['domain']} (Final URL: {res.get('final_url', 'N/A')})")
    print("=" * 70)
    
    if res["error"]:
        print(f"[-] SCAN ERROR: {res['error']}")
        print("=" * 70)
        return

    percentage = res["percentage"]
    
    # [EN] Security rating evaluation
    # [UA] Оцінка рівня безпеки
    if percentage >= 80:
        rating_status = "HIGH SECURITY LEVEL (GOOD)"
    elif percentage >= 50:
        rating_status = "MEDIUM LEVEL (NEEDS IMPROVEMENT)"
    else:
        rating_status = "CRITICALLY LOW LEVEL (NEEDS FIXING)"

    print(f" Security Score: {res['score']}/{res['max_score']} points ({percentage}%)")
    print(f" Status: {rating_status}")
    print("-" * 70)

    for header, data in res["details"].items():
        if data["status"] == "Present":
            print(f" [✓] {header}: PRESENT")
        else:
            print(f" [❌] {header}: MISSING (-{SECURITY_HEADERS[header]['weight']} pts)")
            print(f"     💡 Why it matters: {data['why']}")
            print(f"     🛠️ How to fix:     {data['fix']}")
            print("-" * 40)
    print("=" * 70 + "\n")

def save_to_json(data, filename):
    # [EN] Save report as JSON file / [UA] Збереження звіту у файл JSON
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print(f"[+] Full JSON report saved to: {filename}")

def save_to_csv(data, filename):
    # [EN] Save report as CSV file / [UA] Збереження звіту у файл CSV
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Domain", "Score", "Max Score", "Percentage", "Status/Error"])
        for item in data:
            status = item["error"] if item["error"] else f"{item['score']}/{item['max_score']}"
            writer.writerow([item["domain"], item["score"], item["max_score"], f"{item['percentage']}%", status])
    print(f"[+] Report saved in CSV format to: {filename}")

def main():
    parser = argparse.ArgumentParser(description="Web Security Headers Checker with detailed developer recommendations.")
    parser.add_argument("-d", "--domain", type=str, help="Single domain to audit (e.g., example.com)")
    parser.add_argument("-f", "--file", type=str, help="Path to file containing a list of domains (one per line)")
    parser.add_argument("-o", "--output", type=str, help="Output filename for the report (without extension)")
    parser.add_argument("--format", choices=["json", "csv"], default="json", help="Report export format")

    args = parser.parse_args()

    targets = []
    if args.domain:
        targets.append(args.domain)
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                targets.extend([line.strip() for line in f if line.strip() and not line.startswith("#")])
        except FileNotFoundError:
            print(f"[-] Error: File {args.file} not found.")
            sys.exit(1)

    if not targets:
        print("[-] Error: No domains specified. Use -d or -f. Run with --help for details.")
        sys.exit(1)

    print(f"\n[*] Starting security headers audit for {len(targets)} domain(s)...\n")
    results = []

    for target in targets:
        res = audit_domain(target)
        results.append(res)
        print_pretty_report(res)

    if args.output:
        filename = f"{args.output}.{args.format}"
        if args.format == "json":
            save_to_json(results, filename)
        elif args.format == "csv":
            save_to_csv(results, filename)

if __name__ == "__main__":
    main()