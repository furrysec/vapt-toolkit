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

* **Key Features:** Raw socket ICMP pinging, multi-threaded TCP scanning, and a "Force Mode" to audit hosts behind stealth firewalls.
* **Requirement:** Requires **Admin/Sudo** privileges to send raw ICMP packets.

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
| **Port Scanner** | `sudo python net_scout.py` | **Admin/Root** |
| **SSL Auditor** | `python cert_sentry.py` | User |

---

## 📂 Project Structure

```text
Python-Security-Toolkit/
├── pyheader_sentry.py    # Web Security Auditor
├── net_scout.py          # ICMP & Port Scanner
├── cert_sentry.py        # SSL/TLS Certificate Auditor
├── requirements.txt      # List of dependencies
├── setup.sh              # Linux/macOS setup script
└── README.md             # Project documentation

```

## ⚖️ Legal Disclaimer

**For Educational and Authorized Testing Purposes Only.** Unauthorized scanning of third-party systems is illegal. The developer assumes no liability for misuse of this toolkit. Always obtain written consent before performing security audits.

---

**Would you like me to create the `main.py` "Control Center" script now, so you can run all these tools from a single interactive dashboard?**

