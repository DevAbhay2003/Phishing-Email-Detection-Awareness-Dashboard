"""
Root Launcher for Phishing Email Detection & Awareness Dashboard
Run with: python run.py
"""

import sys
import os

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.app import app, create_app

if __name__ == "__main__":
    application = create_app()
    port = int(os.getenv("PORT", 5000))
    host = os.getenv("HOST", "127.0.0.1")
    print(f"\n" + "=" * 65)
    print(f"  PHISHING EMAIL DETECTION & AWARENESS DASHBOARD")
    print(f"  Defensive Cybersecurity Capstone Project")
    print(f"=" * 65)
    print(f"  Web Dashboard:  http://{host}:{port}")
    print(f"  REST API Base:  http://{host}:{port}/api")
    print(f"  Health Check:   http://{host}:{port}/api/health")
    print(f"=" * 65 + "\n")
    application.run(host=host, port=port, debug=False)
