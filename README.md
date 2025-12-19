# VAPT Toolkit 🛠️

This **Master README** is designed to act as a professional landing page for your repository. It organizes your three tools into a cohesive "Security Suite," making it look like a high-end open-source project.

---

# 🛡️ Python Security Toolkit (PST)

A comprehensive suite of professional cybersecurity utilities for network reconnaissance, web application auditing, and encryption health checks.

## 🧰 Included Tools

### 1. 🌐 PyHeaderSentry

**Layer 7 (Application) Security Auditor**
An advanced web scanner that evaluates HTTP response headers to defend against XSS, Clickjacking, and MitM attacks.

* **Key Features:** Automated security scoring (0-100), detailed risk advisories, and copy-paste remediation guides for Nginx/Apache.
* **Best For:** Web developers and Pentesters auditing site security.

### 2. 📡 NetScout

**Layer 3/4 (Network/Transport) Reconnaissance**
A low-level network scanner that combines ICMP "Scouting" with TCP port discovery.

OS Fingerprinting: Analyzes ICMP Time-to-Live (TTL) values to identify the target's Operating System (Linux, Windows, or Network Infrastructure).

  * **Adaptive Scan Modes: * Aggressive: High-speed multi-threading (100+ threads) for rapid discovery.

  * **stealth: Randomized jitter to bypass basic threshold-based firewalls.

  * **Sneaky: Slow-crawl timing designed to evade Intrusion Detection Systems (IDS).

  * **Deep Banner Grabbing: Performs context-aware service "pokes" (e.g., HTTP HEAD requests) to force services to reveal version data.

    VAPT Advisory Engine: Automatically correlates open ports with known vulnerabilities (like EternalBlue or BlueKeep) and provides industry-standard fixes.
### 3. 📜 CertSentry Pro

**Encryption & Identity Validator**
A deep-dive SSL/TLS certificate auditor that checks the integrity of the encryption tunnel.

* **Key Features:** Expiry countdown, protocol version analysis (flags TLS 1.0/1.1), cipher bit-strength validation, and batch domain auditing.

---

## 🚀 Installation & Setup

### 1. Clone the repository

```bash
git clone https://github.com/furrysec/Python-Security-Toolkit.git
cd vapt-toolkit

```

### 2. Install Dependencies

This toolkit relies on `requests`, `colorama`, and `tabulate` for its logic and UI.

```bash
pip install -r requirements.txt

```

---

## 📖 Usage Guide

| Tool | Command | Privileges |
| --- | --- | --- |
| **Web Headers** | `python pyheader_sentry.py` | User |
| **Port Scanner** | `sudo python Netscout.py` | **Admin/Root** |
| **SSL Auditor** | `python cert_sentry.py` | User |

---

## 📂 Project Structure

```text
Python-Security-Toolkit/
├── main.py               <-- The Launcher
├── Netscout.py          <-- Infrastructure/VAPT
├── pyheader_sentry.py    <-- Web Security
├── CertSentry_Pro.py      <-- SSL/TLS Recon
├── requirements.txt      <-- colorama, requests, tabulate
└── README.md             <-- The Master Documentation```

## ⚖️ Legal Disclaimer

**For Educational and Authorized Testing Purposes Only.** Unauthorized scanning of third-party systems is illegal. The developer assumes no liability for misuse of this toolkit. Always obtain written consent before performing security audits.

---

**Would you like me to create the `main.py` "Control Center" script now, so you can run all these tools from a single interactive dashboard?**

