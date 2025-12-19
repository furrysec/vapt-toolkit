import os
import sys
import time
from colorama import Fore, Style, init

# Standardized imports - files must end in .py
try:
    import NetScout as ns
    import pyheader_sentry as phs
    import CertSentry_Pro as csp
except ImportError as e:
    print(f"{Fore.RED}Status Error: Could not load toolkit modules. {e}")
    print(f"{Fore.YELLOW}Tip: Run 'mv NetScout NetScout.py' etc. in your terminal.")
    sys.exit(1)

init(autoreset=True)

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def main_menu():
    clear()
    print(f"""
    {Fore.CYAN}{Style.BRIGHT}╔════════════════════════════════════════════════════╗
    {Fore.CYAN}{Style.BRIGHT}║          🛠️  VAPT TOOLKIT - MASTER CONSOLE         ║
    {Fore.CYAN}{Style.BRIGHT}╚════════════════════════════════════════════════════╝
    
    {Fore.WHITE}[1] {Fore.GREEN}NetScout        {Fore.WHITE}- Infrastructure & Port Audit
    {Fore.WHITE}[2] {Fore.GREEN}PyHeaderSentry  {Fore.WHITE}- Web Security Header Analysis
    {Fore.WHITE}[3] {Fore.GREEN}CertSentry Pro  {Fore.WHITE}- SSL/TLS Recon & Expiry Audit
    
    {Fore.WHITE}[0] {Fore.RED}Exit Toolkit
    """)

def run():
    while True:
        main_menu()
        choice = input(f"{Fore.YELLOW}Select Tool >> ")

        if choice == '1':
            target = input(f"\n{Fore.CYAN}Enter Target IP/Domain: ")
            start_p = int(input("Start Port: "))
            end_p = int(input("End Port: "))
            # Using the 'Sovereign' class we built for NetScout
            scanner = ns.NetScoutSovereign(target)
            scanner.run_suite(start_p, end_p, mode="aggressive")
            input(f"\n{Fore.WHITE}Press Enter to return to menu...")

        elif choice == '2':
            url = input(f"\n{Fore.CYAN}Enter Target URL (e.g., https://google.com): ")
            auditor = phs.HeaderSentry(url)
            auditor.run_audit()
            input(f"\n{Fore.WHITE}Press Enter to return to menu...")

        elif choice == '3':
            domains = input(f"\n{Fore.CYAN}Enter Domains (separated by space): ").split()
            sentry = csp.CertSentryPro()
            sentry.audit(domains)
            input(f"\n{Fore.WHITE}Press Enter to return to menu...")

        elif choice == '0':
            print(f"\n{Fore.MAGENTA}Shutting down systems... Goodbye.")
            break
        else:
            print(f"{Fore.RED}Invalid Selection!")
            time.sleep(1)

if __name__ == "__main__":
    run()
