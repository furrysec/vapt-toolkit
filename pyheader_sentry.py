import requests
import re
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class AdvancedHeaderScanner:
    def __init__(self, url):
        # Ensure URL has a scheme
        self.url = url if url.startswith('http') else f'https://{url}'
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'
        }

    def check_hsts(self, value):
        match = re.search(r'max-age=(\d+)', value)
        if match:
            age = int(match.group(1))
            if age < 31536000:
                return f"{Fore.YELLOW}WEAK (max-age is too short: {age}s)"
            return f"{Fore.GREEN}STRONG (max-age: {age}s)"
        return f"{Fore.RED}INVALID (No max-age found)"

    def check_csp(self, value):
        if "'unsafe-inline'" in value or "'unsafe-eval'" in value:
            return f"{Fore.YELLOW}MODERATE (Contains 'unsafe' directives)"
        return f"{Fore.GREEN}STRONG (Strict policy)"

    def scan(self):
        print(f"\n{Style.BRIGHT}{Fore.CYAN}--- Security Audit for: {self.url} ---{Style.RESET_ALL}\n")
        try:
            response = requests.get(self.url, headers=self.headers, timeout=10)
            resp_headers = response.headers

            # Mapping headers to their validation functions (if any)
            checks = {
                "Strict-Transport-Security": self.check_hsts,
                "Content-Security-Policy": self.check_csp,
                "X-Frame-Options": lambda v: f"{Fore.GREEN}OK ({v})" if v in ['DENY', 'SAMEORIGIN'] else f"{Fore.RED}WEAK ({v})",
                "X-Content-Type-Options": lambda v: f"{Fore.GREEN}OK ({v})" if v == 'nosniff' else f"{Fore.RED}WEAK ({v})",
                "Referrer-Policy": lambda v: f"{Fore.GREEN}OK ({v})"
            }

            found_count = 0
            for header, validator in checks.items():
                if header in resp_headers:
                    found_count += 1
                    status = validator(resp_headers[header])
                    print(f"{Fore.WHITE}{header:28} | {status}")
                else:
                    print(f"{Fore.RED}{header:28} | MISSING")

            print(f"\n{Style.BRIGHT}Summary: Found {found_count}/{len(checks)} critical headers.")

        except Exception as e:
            print(f"{Fore.RED}Error: {e}")

if __name__ == "__main__":
    target_url = input("Enter target URL: ").strip()
    scanner = AdvancedHeaderScanner(target_url)
    scanner.scan()
