#!/bin/bash
echo "🛡️ Setting up Python Security Toolkit..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
echo "✅ Setup complete. Use 'source venv/bin/activate' to start."
