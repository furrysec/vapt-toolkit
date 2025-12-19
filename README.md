# VAPT Toolkit 🛠️

This **Master README** is designed to act as a professional landing page for your repository. It organizes your three tools into a cohesive "Security Suite," making it look like a high-end open-source project.

To create a compelling GitHub post (which usually takes the form of a **README.md** or a **Social Preview/Release** note), you want to highlight the technical sophistication of your suite. This project has evolved from separate scripts into a unified **Vulnerability Assessment and Penetration Testing (VAPT)** framework.

Here is a professional template you can use for your repository's landing page.

---

# 🛡️ VAPT Toolkit: Integrated Security Suite

A modular, high-performance security framework built in Python for infrastructure reconnaissance, web security auditing, and SSL/TLS analysis. This toolkit consolidates three specialized security modules into a single "Master Console" for streamlined security engagements.

## 🧰 The Suite Architecture

The toolkit is divided into three strategic pillars:

### 1. 📡 NetScout (Infrastructure Audit)

A stealth-focused port scanner and OS fingerprinter.

* **Capabilities:** Multi-threaded TCP scanning, banner grabbing, and ICMP TTL-based OS detection.
* **Intelligence:** Maps open ports to a built-in vulnerability database with risk levels and remediation fixes.
* **Modes:** Supports `Aggressive`, `Stealth`, and `Sneaky` timings to bypass various IDS/Firewall configurations.

### 2. 🛡️ PyHeaderSentry (Web Security)

An automated auditor for HTTP response headers.

* **Capabilities:** Analyzes headers like HSTS, CSP, X-Frame-Options, and X-Content-Type-Options.
* **Scoring:** Generates a security posture score (0-100) based on header weights.
* **Fixes:** Provides immediate **Nginx configuration snippets** to remediate missing headers.

### 3. 🔐 CertSentry Pro (SSL/TLS Recon)

A deep-dive tool for certificate analysis and subdomain discovery.

* **Capabilities:** Extracts certificate expiry, protocol versions (TLS 1.2/1.3), and cipher strength.
* **Recon:** Utilizes **Subject Alternative Name (SAN)** extraction to discover hidden subdomains without active brute-forcing.

---

## 🚀 Installation & Deployment

### Prerequisites

* Python 3.8+
* Root/Sudo privileges (Required for NetScout's raw socket OS fingerprinting)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/furrysec/vapt-toolkit.git
cd vapt-toolkit

# Run the automated setup script
chmod +x setup.sh
./setup.sh

# Launch the Master Console
sudo python3 main.py

```

---

## 📂 Project Structure

```text
vapt-toolkit/
├── main.py               # Master Dashboard (The Entry Point)
├── NetScout.py           # Infrastructure & VAPT Engine
├── pyheader_sentry.py    # Web Header Auditor
├── CertSentry_Pro.py     # SSL/TLS & SAN Recon
├── requirements.txt      # Project Dependencies
└── reports/              # Auto-generated JSON Audit Reports

```

## ⚖️ Legal Disclaimer

This toolkit is designed for **authorized security auditing and educational purposes only**. Users are responsible for complying with local, state, and federal laws. Unauthorized access to networks or web resources is illegal.

---

