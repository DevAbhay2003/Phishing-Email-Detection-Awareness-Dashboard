"""
Database Initialization and Access Layer
Cybersecurity Project: Phishing Email Detection & Awareness Dashboard
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from .models.schema import Base, AnalysisRecord, IndicatorRecord, URLAnalysisRecord

# Determine path for local SQLite database
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "backend", "data")
os.makedirs(DATA_DIR, exist_ok=True)

DB_PATH = os.path.join(DATA_DIR, "phishing_analysis.db")
DATABASE_URI = os.getenv("DATABASE_URI", f"sqlite:///{DB_PATH}")

engine = create_engine(DATABASE_URI, connect_args={"check_same_thread": False})
SessionLocal = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))


def init_db():
    """Initializes tables in the SQLite database."""
    Base.metadata.create_all(bind=engine)
    print(f"[+] Initialized SQLite database at: {DB_PATH}")


def get_db():
    """Session generator for API requests."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def save_analysis(
    sender: str,
    sender_domain: str,
    subject: str,
    risk_score: int,
    classification: str,
    attachment_name: str,
    indicators: list,
    url_analyses: list
) -> AnalysisRecord:
    """Saves analysis session and child records to database."""
    db = SessionLocal()
    try:
        record = AnalysisRecord(
            sender=sender[:255] if sender else "",
            sender_domain=sender_domain[:255] if sender_domain else "",
            subject=subject[:500] if subject else "No Subject",
            risk_score=risk_score,
            classification=classification,
            attachment_name=attachment_name[:255] if attachment_name else ""
        )
        db.add(record)
        db.flush()

        for ind in indicators:
            ind_record = IndicatorRecord(
                analysis_id=record.analysis_id,
                indicator_type=ind.get("type", "UNKNOWN"),
                description=ind.get("description", ""),
                severity=ind.get("severity", "LOW")
            )
            db.add(ind_record)

        for u in url_analyses:
            u_record = URLAnalysisRecord(
                analysis_id=record.analysis_id,
                url_safe_representation=u.get("url", "")[:1000],
                risk_score=u.get("url_risk_score", 0),
                findings=" | ".join(u.get("findings", []))
            )
            db.add(u_record)

        db.commit()
        db.refresh(record)
        return record
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()
