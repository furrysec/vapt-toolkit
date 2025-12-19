# VAPT Toolkit 🛠️

This repository serves as my personal laboratory and toolkit for Vulnerability Assessment and Penetration Testing.

## 📁 Structure
- **/methodology**: 
- **/payloads**: 
- **/pyheader_sentry.py**
  
## 🚀 Getting Started
To use the scripts in this repo, clone it locally:
`git clone https://github.com/furrysec/vapt-toolkit.git`

🛡️ PyHeaderSentry

PyHeaderSentry is a professional-grade Python security tool designed to audit HTTP response headers. It doesn't just check if headers exist; it evaluates their configurations against modern security standards (like HSTS age and CSP strictness).
✨ Features

  Deep Validation: Analyzes HSTS max-age and CSP "unsafe" directives.

  Security Grading: Provides a clear "Strong/Weak/Missing" status for each header.

  WAF Bypass: Uses a custom Browser User-Agent to prevent blocks during scans.

  Colorized Output: Visual feedback for quick identification of vulnerabilities.

🚀 Quick Start

1. Install Dependencies
Bash

          pip install requests colorama

2. Run the Scanner
Bash

          python pyheader_sentry.py

## ⚠️ Disclaimer
This toolkit is for **educational and ethical purposes only**. Use it only on systems you have explicit permission to test.
