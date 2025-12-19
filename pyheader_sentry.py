import requests
import re
import os
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class PyHeaderSentry:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'
        }
        self.checks = {
            "Strict-Transport-Security": self.check_hsts,
            "Content-Security-Policy": self.check_csp,
            "X-Frame-Options": lambda v: f"{Fore.GREEN}OK ({v})" if v in ['DENY', 'SAMEORIGIN'] else f"{Fore.RED}WEAK ({v})",
            "X-Content-Type-Options": lambda v: f"{Fore.GREEN}OK ({v})" if v == 'nosniff' else f"{Fore.RED}WEAK ({v})",
            "Referrer-Policy": lambda v: f"{Fore.GREEN}OK ({v})"
        }

    def check_hsts(self, value):
        match = re.search(r'max-age=(\d+)', value)
        if match:
            age = int(match.group(1))
            return f"{Fore.GREEN}STRONG ({age}s)" if age >= 31536000 else f"{Fore.YELLOW}WEAK ({age}s)"
        return f"{Fore.RED}INVALID"

    def check_csp(self, value):
        if "'unsafe-inline'" in value or "'unsafe-eval'" in value:
            return f"{Fore.YELLOW}MODERATE (Unsafe directives found)"
        return f"{Fore.GREEN}STRONG (Strict)"

    def scan(self, url):
        target = url.strip() if url.startswith('http') else f'https://{url.strip()}'
        print(f"\n{Style.BRIGHT}{Fore.CYAN}🔎 Auditing: {target}")
        
        try:
            response = requests.get(target, headers=self.headers, timeout=10)
            for header, validator in self.checks.items():
                val = response.headers.get(header)
                status = validator(val) if val else f"{Fore.RED}MISSING"
                print(f"  {Fore.WHITE}{header:28} | {status}")
        except Exception as e:
            print(f"  {Fore.RED}Error: Could not connect to {target}")

    def run(self):
        print(f"{Fore.GREEN}--- PyHeaderSentry v1.0 ---")
        choice = input("Choose mode: [1] Single URL [2] Batch File (.txt): ")
        
        if choice == "1":
            url = input("Enter URL: ")
            self.scan(url)
        elif choice == "2":
            path = input("Enter file path: ")
            if os.path.exists(path):
                with open(path, 'r') as f:
                    for line in f:
                        if line.strip(): self.scan(line)
            else:
                print(f"{Fore.RED}File not found.")

if __name__ == "__main__":
    sentry = PyHeaderSentry()
    sentry.run()
