"""
Database Schema Definitions
Cybersecurity Project: Phishing Email Detection & Awareness Dashboard

Defines tables for storing defensive email analysis telemetry and security audit logs
without storing sensitive raw email bodies by default (Defensive Privacy by Design).
"""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class AnalysisRecord(Base):
    """
    Core metadata for an analyzed email session.
    Omits full email body to maintain privacy and data protection compliance.
    """
    __tablename__ = "analyses"

    analysis_id = Column(Integer, primary_key=True, autoincrement=True)
    sender = Column(String(255), nullable=True)
    sender_domain = Column(String(255), nullable=True, index=True)
    subject = Column(String(500), nullable=True)
    risk_score = Column(Integer, nullable=False)
    classification = Column(String(50), nullable=False, index=True)
    attachment_name = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    # Relationships
    indicators = relationship("IndicatorRecord", back_populates="analysis", cascade="all, delete-orphan")
    url_analyses = relationship("URLAnalysisRecord", back_populates="analysis", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "analysis_id": self.analysis_id,
            "sender": self.sender,
            "sender_domain": self.sender_domain,
            "subject": self.subject,
            "risk_score": self.risk_score,
            "classification": self.classification,
            "attachment_name": self.attachment_name,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "indicators": [ind.to_dict() for ind in self.indicators],
            "url_analyses": [u.to_dict() for u in self.url_analyses]
        }


class IndicatorRecord(Base):
    """
    Specific suspicious heuristic triggers identified during email triage.
    """
    __tablename__ = "indicators"

    indicator_id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(Integer, ForeignKey("analyses.analysis_id", ondelete="CASCADE"), nullable=False, index=True)
    indicator_type = Column(String(100), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)

    analysis = relationship("AnalysisRecord", back_populates="indicators")

    def to_dict(self):
        return {
            "indicator_id": self.indicator_id,
            "indicator_type": self.indicator_type,
            "description": self.description,
            "severity": self.severity
        }


class URLAnalysisRecord(Base):
    """
    Static URL inspection audit logs associated with an email analysis.
    """
    __tablename__ = "url_analyses"

    url_analysis_id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(Integer, ForeignKey("analyses.analysis_id", ondelete="CASCADE"), nullable=False, index=True)
    url_safe_representation = Column(String(1000), nullable=False)
    risk_score = Column(Integer, nullable=False)
    findings = Column(Text, nullable=True)

    analysis = relationship("AnalysisRecord", back_populates="url_analyses")

    def to_dict(self):
        return {
            "url_analysis_id": self.url_analysis_id,
            "url": self.url_safe_representation,
            "risk_score": self.risk_score,
            "findings": self.findings.split(" | ") if self.findings else []
        }


class UserRecord(Base):
    """
    Optional authentication table for SOC Analyst portal access.
    """
    __tablename__ = "users"

    user_id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), default="analyst")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
