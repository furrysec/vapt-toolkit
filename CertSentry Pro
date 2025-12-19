import ssl
import socket
import json
from datetime import datetime, timezone
from colorama import Fore, Style, init
from tabulate import tabulate

init(autoreset=True)

class CertSentryPro:
    def __init__(self):
        self.results = []

    def get_cert_info(self, hostname):
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    # Fix timezone comparison
                    expiry_str = cert['notAfter']
                    expiry_date = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_left = (expiry_date - now).days

                    # Recon: Extract Subject Alternative Names (SAN)
                    # cert['subjectAltName'] is a tuple of (('DNS', 'domain.com'), ...)
                    alt_names = [item[1] for item in cert.get('subjectAltName', []) if item[0] == 'DNS']
                    # Show first 3 and count of others for clean UI
                    recon_data = ", ".join(alt_names[:3]) + (f" (+{len(alt_names)-3})" if len(alt_names) > 3 else "")

                    status = {
                        "Domain": hostname,
                        "Days Left": days_left,
                        "Protocol": f"{version}",
                        "Cipher": f"{cipher[0]}",
                        "SAN Recon": f"{Fore.CYAN}{recon_data}",
                        "Status": "✅ SECURE" if days_left > 30 else "⚠️ ACTION"
                    }
                    return status
        except Exception as e:
            return {"Domain": hostname, "Status": f"{Fore.RED}FAILED: {str(e)[:25]}"}

    def audit(self, targets):
        print(f"\n{Fore.CYAN}{Style.BRIGHT}🛡️  SSL/TLS Security Audit & Recon in Progress...")
        self.results = [self.get_cert_info(t) for t in targets]
        print(tabulate(self.results, headers="keys", tablefmt="fancy_grid"))

if __name__ == "__main__":
    sentry = CertSentryPro()
    user_input = input("Enter domains (e.g., google.com github.com): ").split()
    sentry.audit(user_input)
