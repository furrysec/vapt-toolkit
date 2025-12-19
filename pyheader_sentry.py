import requests
import json
import os
import concurrent.futures
from datetime import datetime
from colorama import Fore, Style, init
from tabulate import tabulate

# Initialize Colorama for terminal styling
init(autoreset=True)

class PyHeaderSentry:
    # MODIFIED: Accepts target_url from main.py
    def __init__(self, target_url=None):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'PyHeaderSentry-Security-Audit-v2.5'})
        self.all_results = []
        self.target_url = target_url
        
        # Vulnerability & Remediation Database
        self.db = {
            "Strict-Transport-Security": {
                "risk": "Man-in-the-Middle (MitM) attacks; allows protocol downgrades.",
                "fix": "add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains' always;",
                "weight": 30
            },
            "Content-Security-Policy": {
                "risk": "Cross-Site Scripting (XSS) and data injection attacks.",
                "fix": "add_header Content-Security-Policy \"default-src 'self';\" always;",
                "weight": 40
            },
            "X-Frame-Options": {
                "risk": "Clickjacking; allows site to be embedded in malicious iframes.",
                "fix": "add_header X-Frame-Options \"SAMEORIGIN\" always;",
                "weight": 15
            },
            "X-Content-Type-Options": {
                "risk": "MIME-sniffing; can lead to drive-by downloads or script execution.",
                "fix": "add_header X-Content-Type-Options \"nosniff\" always;",
                "weight": 15
            }
        }

    def audit_site(self, url):
        url = url.strip()
        if not url: return None
        target = url if url.startswith('http') else f'https://{url}'
        
        try:
            response = self.session.get(target, timeout=10, allow_redirects=True)
            h = response.headers
            missing = [head for head in self.db.keys() if head not in h]
            
            # Calculate Score
            score = 100
            for m in missing:
                score -= self.db[m]['weight']
            
            result = {
                "URL": target,
                "HSTS": "✅" if "Strict-Transport-Security" in h else "❌",
                "CSP": "✅" if "Content-Security-Policy" in h else "❌",
                "X-Frame": "✅" if "X-Frame-Options" in h else "❌",
                "X-Content": "✅" if "X-Content-Type-Options" in h else "❌",
                "Score": f"{max(0, score)}/100"
            }
            return result, missing
        except Exception as e:
            return {"URL": target, "Score": f"ERROR: {str(e)[:20]}"}, []

    # MODIFIED: This is the entry point used by main.py
    def run_audit(self):
        if not self.target_url:
            print(f"{Fore.RED}Error: No URL provided for audit.")
            return

        res, missing = self.audit_site(self.target_url)
        if res:
            print(f"\n{Fore.CYAN}{Style.BRIGHT}🛡️  WEB HEADER AUDIT RESULTS")
            print(tabulate([res], headers="keys", tablefmt="fancy_grid"))
            self.print_remediation(missing)
            self.all_results.append(res)
            self.save_json()

    def print_remediation(self, missing_headers):
        if not missing_headers:
            print(f"\n{Fore.GREEN}✨ Perfect Score! No remediation needed.")
            return

        print(f"\n{Fore.YELLOW}{Style.BRIGHT}⚠️ VULNERABILITY ADVISORY & FIX GUIDE:")
        advice_table = []
        for m in missing_headers:
            advice_table.append([f"{Fore.RED}{m}", self.db[m]['risk']])
        
        print(tabulate(advice_table, headers=["Missing Header", "Risk Description"], tablefmt="simple"))
        
        print(f"\n{Fore.CYAN}🛠️ NGINX CONFIGURATION FIX:")
        for m in missing_headers:
            print(f"  {Fore.WHITE}{self.db[m]['fix']}")

    def save_json(self):
        # Create reports directory if it doesn't exist
        if not os.path.exists('reports'): os.makedirs('reports')
        filename = f"reports/Header_Audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(self.all_results, f, indent=4)
        print(f"\n{Fore.MAGENTA}[+] JSON report saved to {filename}")
