"""
Machine Learning Phishing Predictor Service
Cybersecurity Project: Phishing Email Detection & Awareness Dashboard

Provides real-time probability estimates using the serialized TF-IDF vectorizer
and trained classifier. Fails gracefully if model files are not yet generated.
"""

import os
import joblib
from typing import Dict, Any


class MLPredictor:
    """
    Inference service for ML-assisted phishing detection.
    """
    _model = None
    _vectorizer = None
    _loaded = False

    @classmethod
    def load_artifacts(cls):
        """Loads trained model and vectorizer if available."""
        if cls._loaded:
            return

        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        model_path = os.path.join(base_dir, "models", "phishing_model.joblib")
        vectorizer_path = os.path.join(base_dir, "models", "tfidf_vectorizer.joblib")

        if os.path.exists(model_path) and os.path.exists(vectorizer_path):
            try:
                cls._model = joblib.load(model_path)
                cls._vectorizer = joblib.load(vectorizer_path)
                cls._loaded = True
            except Exception as e:
                print(f"[!] Warning: Could not load ML artifacts: {e}")
                cls._loaded = False
        else:
            cls._loaded = False

    @classmethod
    def predict_phishing_probability(cls, subject: str, body: str) -> Dict[str, Any]:
        """
        Calculates probability that the email text exhibits phishing intent.
        Returns probability (0.0 to 1.0) and model prediction.
        """
        cls.load_artifacts()

        if not cls._loaded or cls._model is None or cls._vectorizer is None:
            return {
                "available": False,
                "phishing_probability": None,
                "label": "UNAVAILABLE",
                "message": "ML model not trained or artifacts not found"
            }

        input_text = f"{subject or ''} {body or ''}".strip()
        if not input_text:
            return {
                "available": True,
                "phishing_probability": 0.0,
                "label": "LEGITIMATE",
                "confidence": 1.0
            }

        try:
            vec = cls._vectorizer.transform([input_text])
            # Probability estimates
            if hasattr(cls._model, "predict_proba"):
                probs = cls._model.predict_proba(vec)[0]
                phish_prob = round(float(probs[1]), 4)
            else:
                pred = cls._model.predict(vec)[0]
                phish_prob = 1.0 if pred == 1 else 0.0

            label = "PHISHING" if phish_prob >= 0.50 else "LEGITIMATE"

            return {
                "available": True,
                "phishing_probability": phish_prob,
                "percentage": round(phish_prob * 100, 1),
                "label": label,
                "confidence": round(max(phish_prob, 1.0 - phish_prob), 4)
            }
        except Exception as e:
            return {
                "available": False,
                "phishing_probability": None,
                "label": "ERROR",
                "message": str(e)
            }
