"""
Hybrid Phishing Detection Engine
Cybersecurity Project: Phishing Email Detection & Awareness Dashboard

Blends deterministic rule-based indicators with probabilistic machine learning predictions
to construct an explainable, defense-in-depth risk score.
"""

from typing import Dict, Any, List, Union
from .risk_engine import RiskEngine
from ml.predictor import MLPredictor


class HybridEngine:
    """
    Coordinates multi-layered triage:
    Final Score = (Rule_Score * Rule_Weight) + (ML_Probability * 100 * ML_Weight)
    """

    DEFAULT_RULE_WEIGHT = 0.60
    DEFAULT_ML_WEIGHT = 0.40

    @classmethod
    def evaluate(
        cls,
        sender: str,
        subject: str,
        body: str,
        urls: Union[str, List[str]] = "",
        attachment_name: str = "",
        expected_org: str = "",
        rule_weight: float = DEFAULT_RULE_WEIGHT,
        ml_weight: float = DEFAULT_ML_WEIGHT
    ) -> Dict[str, Any]:
        """
        Executes both Rule Engine and ML Engine, synthesizing them into a hybrid assessment.
        """
        # 1. Calculate deterministic rule-based score
        rule_result = RiskEngine.calculate_phishing_score(
            sender=sender,
            subject=subject,
            body=body,
            urls=urls,
            attachment_name=attachment_name,
            expected_org=expected_org
        )
        rule_score = rule_result["risk_score"]

        # 2. Query probabilistic machine learning classifier
        ml_result = MLPredictor.predict_phishing_probability(subject=subject, body=body)

        # 3. Hybrid synthesis
        if ml_result.get("available", False) and ml_result.get("phishing_probability") is not None:
            ml_prob_pct = ml_result["phishing_probability"] * 100.0
            hybrid_score = round((rule_score * rule_weight) + (ml_prob_pct * ml_weight))
            hybrid_mode_active = True
        else:
            # Fall back purely to rule-based score if ML is unavailable
            hybrid_score = rule_score
            hybrid_mode_active = False

        hybrid_score = min(max(hybrid_score, 0), 100)

        # 4. Map hybrid score to classification tier
        if hybrid_score <= 20:
            classification = "LOW RISK"
            color_code = "#22c55e"
            tier = "Informational / Benign"
        elif hybrid_score <= 40:
            classification = "MODERATE RISK"
            color_code = "#eab308"
            tier = "Caution Advised"
        elif hybrid_score <= 70:
            classification = "SUSPICIOUS"
            color_code = "#f97316"
            tier = "Potential Threat"
        else:
            classification = "HIGH RISK / LIKELY PHISHING"
            color_code = "#ef4444"
            tier = "High Confidence Threat"

        return {
            "risk_score": hybrid_score,
            "rule_score": rule_score,
            "ml_assessment": ml_result,
            "classification": classification,
            "threat_level": tier,
            "color_code": color_code,
            "hybrid_mode_active": hybrid_mode_active,
            "weights": {"rule": rule_weight, "ml": ml_weight},
            "indicators": rule_result["indicators"],
            "recommendations": rule_result["recommendations"],
            "sender_analysis": rule_result["sender_analysis"],
            "content_analysis": rule_result["content_analysis"],
            "url_analyses": rule_result["url_analyses"],
            "attachment_analysis": rule_result["attachment_analysis"],
            "features": rule_result["features"]
        }
