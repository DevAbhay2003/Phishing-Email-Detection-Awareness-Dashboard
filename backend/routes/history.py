"""
Analysis History API Routes
Cybersecurity Project: Phishing Email Detection & Awareness Dashboard
"""

from flask import Blueprint, request, jsonify
from backend.database import SessionLocal
from backend.models.schema import AnalysisRecord

history_bp = Blueprint("history_bp", __name__)


@history_bp.route("/analyses", methods=["GET"])
def get_analyses():
    """
    Returns historical analysis logs with search, filtering, and sorting.
    Query parameters:
      - classification: filter by tier ('HIGH RISK / LIKELY PHISHING', etc.)
      - search: filter by keyword in subject or domain
      - sort: 'newest', 'oldest', 'highest_risk', 'lowest_risk'
      - limit: default 50
    """
    classification = request.args.get("classification", "").strip()
    search = request.args.get("search", "").strip()
    sort = request.args.get("sort", "newest").strip()
    limit = min(int(request.args.get("limit", 50)), 200)

    db = SessionLocal()
    try:
        query = db.query(AnalysisRecord)

        if classification:
            query = query.filter(AnalysisRecord.classification == classification)

        if search:
            search_pat = f"%{search}%"
            query = query.filter(
                (AnalysisRecord.subject.ilike(search_pat)) |
                (AnalysisRecord.sender_domain.ilike(search_pat)) |
                (AnalysisRecord.sender.ilike(search_pat))
            )

        if sort == "oldest":
            query = query.order_by(AnalysisRecord.created_at.asc())
        elif sort == "highest_risk":
            query = query.order_by(AnalysisRecord.risk_score.desc())
        elif sort == "lowest_risk":
            query = query.order_by(AnalysisRecord.risk_score.asc())
        else:  # newest
            query = query.order_by(AnalysisRecord.created_at.desc())

        records = query.limit(limit).all()
        return jsonify({
            "success": True,
            "count": len(records),
            "analyses": [r.to_dict() for r in records]
        }), 200
    finally:
        db.close()


@history_bp.route("/analyses/<int:analysis_id>", methods=["GET"])
def get_analysis_detail(analysis_id: int):
    """Fetches full telemetry for a specific analysis."""
    db = SessionLocal()
    try:
        record = db.query(AnalysisRecord).filter(AnalysisRecord.analysis_id == analysis_id).first()
        if not record:
            return jsonify({"success": False, "error": "Analysis not found"}), 404
        return jsonify({"success": True, "analysis": record.to_dict()}), 200
    finally:
        db.close()


@history_bp.route("/analyses/<int:analysis_id>", methods=["DELETE"])
def delete_analysis(analysis_id: int):
    """Deletes an analysis record and associated indicators from the audit database."""
    db = SessionLocal()
    try:
        record = db.query(AnalysisRecord).filter(AnalysisRecord.analysis_id == analysis_id).first()
        if not record:
            return jsonify({"success": False, "error": "Analysis not found"}), 404
        db.delete(record)
        db.commit()
        return jsonify({"success": True, "message": f"Analysis #{analysis_id} deleted."}), 200
    except Exception as e:
        db.rollback()
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        db.close()
