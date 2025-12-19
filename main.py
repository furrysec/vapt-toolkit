import os
import sys
from colorama import Fore, Style, init

# Import your tools
try:
    from net_scout import NetScoutSovereign
    from pyheader_sentry import HeaderSentry
    from cert_sentry import CertSentryPro
except ImportError as e:
    print(f"Error: Missing tool files or dependencies. {e}")
    sys.exit(1)

init(autoreset=True)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def show_banner():
    print(f"""
    {Fore.CYAN}{Style.BRIGHT}==============================================
    {Fore.WHITE}      🛡️  PYTHON SECURITY TOOLKIT (PST) v1.0
    {Fore.CYAN}==============================================
    {Fore.GREEN} [1] {Fore.WHITE}Network Recon & VAPT (NetScout)
    {Fore.GREEN} [2] {Fore.WHITE}Web Security Header Audit (Sentry)
    {Fore.GREEN} [3] {Fore.WHITE}SSL/TLS Recon & Audit (CertSentry)
    {Fore.RED} [0] {Fore.WHITE}Exit
    """)

def main():
    while True:
        clear_screen()
        show_banner()
        choice = input(f"{Fore.YELLOW}Select an option: ")

        if choice == '1':
            target = input("\nEnter Target IP: ")
            start = int(input("Start Port: "))
            end = int(input("End Port: "))
            mode = input("Mode (aggressive/stealth): ")
            scanner = NetScoutSovereign(target)
            scanner.run_suite(start, end, mode)
            input("\nPress Enter to return to menu...")

        elif choice == '2':
            url = input("\nEnter URL (with http/https): ")
            auditor = HeaderSentry(url)
            auditor.run_audit()
            input("\nPress Enter to return to menu...")

        elif choice == '3':
            domains = input("\nEnter domains (space separated): ").split()
            sentry = CertSentryPro()
            sentry.audit(domains)
            input("\nPress Enter to return to menu...")

        elif choice == '0':
            print(f"{Fore.MAGENTA}Happy Hacking! Goodbye.")
            break
        else:
            print(f"{Fore.RED}Invalid selection.")
            time.sleep(1)

if __name__ == "__main__":
    main()
