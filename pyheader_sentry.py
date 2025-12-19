import requests
import json
import re
import os
import concurrent.futures
from datetime import datetime
from colorama import Fore, Style, init
from tabulate import tabulate

# Initialize Colorama for terminal styling
init(autoreset=True)

class PyHeaderSentry:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'PyHeaderSentry-Security-Audit-v2.0'})
        self.all_results = []
        
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
        except Exception:
            return {"URL": target, "Score": "ERROR"}, []

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

    def run_batch(self, file_path):
        if not os.path.exists(file_path):
            print(f"{Fore.RED}File {file_path} not found.")
            return
        
        with open(file_path, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        print(f"{Fore.BLUE}[*] Auditing {len(urls)} sites using multi-threading...")
        
        final_table = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_url = {executor.submit(self.audit_site, url): url for url in urls}
            for future in concurrent.futures.as_completed(future_to_url):
                res, _ = future.result()
                if res: 
                    final_table.append(res)
                    self.all_results.append(res)

        print(tabulate(final_table, headers="keys", tablefmt="fancy_grid"))
        self.save_json()

    def save_json(self):
        filename = f"Audit_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(self.all_results, f, indent=4)
        print(f"\n{Fore.MAGENTA}[+] JSON report saved to {filename}")

    def menu(self):
        print(f"{Fore.CYAN}{Style.BRIGHT}=== PYHEADER SENTRY PRO v2.5 ===")
        print("1. Scan Single URL (with full remediation guide)")
        print("2. Batch Scan (.txt file)")
        choice = input(f"{Fore.YELLOW}Selection: ")

        if choice == "1":
            target = input("Enter URL: ")
            res, missing = self.audit_site(target)
            if res:
                print(tabulate([res], headers="keys", tablefmt="fancy_grid"))
                self.print_remediation(missing)
        elif choice == "2":
            path = input("Enter path to .txt file: ")
            self.run_batch(path)

if __name__ == "__main__":
    sentry = PyHeaderSentry()
    sentry.menu()
