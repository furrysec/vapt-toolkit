import socket
import struct
import time
import random
import concurrent.futures
from colorama import Fore, Style, init
from tabulate import tabulate

# Initialize Colorama for cross-platform colored terminal output
init(autoreset=True)

class NetScoutSovereign:
    def __init__(self, target, threads=50):
        self.target = target
        self.threads = threads
        self.findings = []
        
        # Expert VAPT Advisory Database
        self.vapt_db = {
            21:  {"svc": "FTP",    "risk": "HIGH",     "vuln": "Cleartext Creds", "fix": "Use SFTP/SSH"},
            22:  {"svc": "SSH",    "risk": "LOW",      "vuln": "Brute Force",     "fix": "Key-Auth Only"},
            23:  {"svc": "TELNET", "risk": "CRITICAL", "vuln": "Sniffing Target", "fix": "Disable/Remove"},
            25:  {"svc": "SMTP",   "risk": "MED",      "vuln": "Relay/Spam",      "fix": "Enable STARTTLS"},
            53:  {"svc": "DNS",    "risk": "MED",      "vuln": "Zone Transfer",   "fix": "Restrict AXFR"},
            80:  {"svc": "HTTP",   "risk": "MED",      "vuln": "Header Leakage",  "fix": "Add Sec Headers"},
            443: {"svc": "HTTPS",  "risk": "LOW",      "vuln": "SSL Weakness",    "fix": "Use CertSentry"},
            445: {"svc": "SMB",    "risk": "CRITICAL", "vuln": "EternalBlue/RCE", "fix": "Disable SMBv1"},
            1433:{"svc": "MSSQL",  "risk": "HIGH",     "vuln": "Injection/Auth",  "fix": "No Remote Root"},
            3306:{"svc": "MySQL",  "risk": "HIGH",     "vuln": "DB Leakage",      "fix": "Bind Localhost"},
            3389:{"svc": "RDP",    "risk": "CRITICAL", "vuln": "BlueKeep/CVE",    "fix": "MFA/VPN Only"},
            8080:{"svc": "PROXY",  "risk": "MED",      "vuln": "Open Proxy",      "fix": "Access Control"}
        }

    def get_os_fingerprint(self):
        """Perform OS Fingerprinting via ICMP TTL analysis."""
        try:
            # Requires Sudo/Admin to use raw sockets
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            s.settimeout(2)
            packet = struct.pack("bbHHh", 8, 0, 0, 1, 1) + struct.pack("d", time.time())
            s.sendto(packet, (self.target, 1))
            
            data, _ = s.recvfrom(1024)
            ttl = data[8]
            
            if ttl <= 64: return f"Linux/Unix (TTL: {ttl})"
            if ttl <= 128: return f"Windows (TTL: {ttl})"
            if ttl <= 255: return f"Cisco/Network Device (TTL: {ttl})"
            return f"Unknown Stack (TTL: {ttl})"
        except PermissionError:
            return "Unknown (Run as Sudo/Admin for OS Detection)"
        except:
            return "Detection Blocked (Firewall)"

    def aggressive_probe(self, port):
        """Perform banner grabbing and service identification."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.2)
                if s.connect_ex((self.target, port)) == 0:
                    # Send probes for common services to trigger banners
                    if port in [80, 8080]:
                        s.send(b"HEAD / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\n\r\n")
                    
                    banner = s.recv(1024).decode(errors='ignore').strip().split('\n')[0][:40]
                    
                    # Match found port to Advisory DB
                    data = self.vapt_db.get(port, {"svc": "Unknown", "risk": "INFO", "vuln": "Version Audit", "fix": "Standard Hardening"})
                    
                    risk_color = Fore.RED if data['risk'] in ["CRITICAL", "HIGH"] else Fore.YELLOW
                    
                    return [
                        port, 
                        data['svc'], 
                        banner if banner else "OPEN (No Banner)", 
                        f"{risk_color}{data['risk']}", 
                        data['vuln'], 
                        data['fix']
                    ]
        except:
            pass
        return None

    def run_suite(self, p_start, p_end, mode="aggressive"):
        print(f"\n{Fore.RED}{Style.BRIGHT}☣️  NETSCOUT SOVEREIGN VAPT ENGINE")
        print(f"{Fore.WHITE}Targeting: {self.target} | Mode: {mode.upper()}")
        
        # 1. OS Discovery
        print(f"{Fore.CYAN}[*] Fingerprinting OS...")
        print(f"{Fore.GREEN}[+] Result: {self.get_os_fingerprint()}")

        # 2. Multi-threaded Scanning
        print(f"{Fore.CYAN}[*] Scanning Ports {p_start}-{p_end}...")
        ports = range(p_start, p_end + 1)
        
        # Handle Stealth Timing
        delay = 0
        if mode == "stealth": delay = random.uniform(0.5, 1.5)
        elif mode == "sneaky": delay = random.uniform(2, 5)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            # If stealth, we drop to 1 worker to ensure timing works correctly
            if mode != "aggressive":
                futures = []
                for p in ports:
                    time.sleep(delay)
                    futures.append(executor.submit(self.aggressive_probe, p))
            else:
                futures = [executor.submit(self.aggressive_probe, p) for p in ports]

            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res: self.findings.append(res)

        # 3. Final Report
        self.findings.sort()
        headers = ["PORT", "SERVICE", "BANNER/VERSION", "RISK", "VULNERABILITY", "FIX"]
        print(f"\n{Fore.MAGENTA}--- SOVEREIGN AUDIT REPORT ---")
        print(tabulate(self.findings, headers=headers, tablefmt="fancy_grid"))

if __name__ == "__main__":
    target_ip = input("Enter Target IP: ")
    p_start = int(input("Start Port (e.g., 1): "))
    p_end = int(input("End Port (e.g., 1000): "))
    scan_mode = input("Mode (aggressive/stealth/sneaky): ").lower()
    
    # 100 threads for aggressive, 1 for stealth
    thread_count = 100 if scan_mode == "aggressive" else 1
    
    scanner = NetScoutSovereign(target_ip, threads=thread_count)
    scanner.run_suite(p_start, p_end, mode=scan_mode)
