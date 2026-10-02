"""
Dashboard Analytics API Routes
Cybersecurity Project: Phishing Email Detection & Awareness Dashboard
"""

from flask import Blueprint, jsonify
from sqlalchemy import func
from backend.database import SessionLocal
from backend.models.schema import AnalysisRecord, IndicatorRecord

dashboard_bp = Blueprint("dashboard_bp", __name__)


@dashboard_bp.route("/dashboard/stats", methods=["GET"])
def get_dashboard_stats():
    """
    Computes top-level KPI metrics for the executive and SOC dashboard.
    """
    db = SessionLocal()
    try:
        total = db.query(AnalysisRecord).count()
        if total == 0:
            return jsonify({
                "success": True,
                "total_analyzed": 0,
                "high_risk": 0,
                "suspicious": 0,
                "moderate_risk": 0,
                "low_risk": 0,
                "average_risk_score": 0.0,
                "classification_breakdown": {
                    "HIGH RISK / LIKELY PHISHING": 0,
                    "SUSPICIOUS": 0,
                    "MODERATE RISK": 0,
                    "LOW RISK": 0
                },
                "risk_distribution": {"0-20": 0, "21-40": 0, "41-70": 0, "71-100": 0}
            }), 200

        high_risk = db.query(AnalysisRecord).filter(AnalysisRecord.classification == "HIGH RISK / LIKELY PHISHING").count()
        suspicious = db.query(AnalysisRecord).filter(AnalysisRecord.classification == "SUSPICIOUS").count()
        moderate = db.query(AnalysisRecord).filter(AnalysisRecord.classification == "MODERATE RISK").count()
        low = db.query(AnalysisRecord).filter(AnalysisRecord.classification == "LOW RISK").count()

        avg_score = db.query(func.avg(AnalysisRecord.risk_score)).scalar() or 0.0

        # Distribution buckets
        b1 = db.query(AnalysisRecord).filter(AnalysisRecord.risk_score <= 20).count()
        b2 = db.query(AnalysisRecord).filter(AnalysisRecord.risk_score > 20, AnalysisRecord.risk_score <= 40).count()
        b3 = db.query(AnalysisRecord).filter(AnalysisRecord.risk_score > 40, AnalysisRecord.risk_score <= 70).count()
        b4 = db.query(AnalysisRecord).filter(AnalysisRecord.risk_score > 70).count()

        return jsonify({
            "success": True,
            "total_analyzed": total,
            "high_risk": high_risk,
            "suspicious": suspicious,
            "moderate_risk": moderate,
            "low_risk": low,
            "average_risk_score": round(float(avg_score), 1),
            "classification_breakdown": {
                "HIGH RISK / LIKELY PHISHING": high_risk,
                "SUSPICIOUS": suspicious,
                "MODERATE RISK": moderate,
                "LOW RISK": low
            },
            "risk_distribution": {
                "0-20 (Low)": b1,
                "21-40 (Moderate)": b2,
                "41-70 (Suspicious)": b3,
                "71-100 (High)": b4
            }
        }), 200
    finally:
        db.close()


@dashboard_bp.route("/dashboard/indicators", methods=["GET"])
def get_top_indicators():
    """
    Computes top triggered indicators across all triaged emails for telemetry charts.
    """
    db = SessionLocal()
    try:
        results = db.query(
            IndicatorRecord.indicator_type,
            func.count(IndicatorRecord.indicator_id).label("count")
        ).group_by(IndicatorRecord.indicator_type).order_by(func.count(IndicatorRecord.indicator_id).desc()).limit(10).all()

        formatted = [{"indicator": r[0], "count": r[1]} for r in results]
        return jsonify({"success": True, "top_indicators": formatted}), 200
    finally:
        db.close()
