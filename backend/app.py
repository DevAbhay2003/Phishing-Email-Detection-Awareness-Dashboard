"""
Main Flask Web & API Server
Cybersecurity Project: Phishing Email Detection & Awareness Dashboard
"""

import os
from flask import Flask, send_from_directory, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from backend.database import init_db
from backend.routes.analyze import analyze_bp
from backend.routes.history import history_bp
from backend.routes.dashboard import dashboard_bp
from ml.predictor import MLPredictor

# Load environment configuration
load_dotenv()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
CORS(app)

# Register API blueprints
app.register_blueprint(analyze_bp, url_prefix="/api")
app.register_blueprint(history_bp, url_prefix="/api")
app.register_blueprint(dashboard_bp, url_prefix="/api")


@app.route("/")
def serve_index():
    """Serves the main frontend single-page dashboard."""
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/api/health", methods=["GET"])
def health_check():
    """Service liveness and readiness probe."""
    return jsonify({
        "status": "healthy",
        "service": "Phishing Email Detection & Awareness Dashboard",
        "version": "1.0.0",
        "ml_model_loaded": MLPredictor._loaded
    }), 200


def create_app():
    """Factory function for initialization and testing."""
    init_db()
    # Preload ML model artifacts
    MLPredictor.load_artifacts()
    return app


if __name__ == "__main__":
    init_db()
    MLPredictor.load_artifacts()
    port = int(os.getenv("PORT", 5000))
    host = os.getenv("HOST", "127.0.0.1")
    print(f"\n========================================================")
    print(f"[*] Phishing Email Detection Dashboard is starting...")
    print(f"[*] Access the Dashboard at: http://{host}:{port}")
    print(f"========================================================\n")
    app.run(host=host, port=port, debug=True)
