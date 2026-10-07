"""
Database Models
SQLAlchemy models for SOCShield
"""

from sqlalchemy import Column, Integer, String, DateTime, Boolean, Float, Text, JSON, ForeignKey, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum

from app.core.database import Base


class RiskLevel(str, enum.Enum):
    """Risk level enumeration"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class EmailStatus(str, enum.Enum):
    """Email processing status"""
    PENDING = "pending"
    ANALYZING = "analyzing"
    ANALYZED = "analyzed"
    QUARANTINED = "quarantined"
    BLOCKED = "blocked"
    SAFE = "safe"
    ERROR = "error"


class Email(Base):
    """Email model"""
    __tablename__ = "emails"
    
    id = Column(Integer, primary_key=True, index=True)
    message_id = Column(String(255), unique=True, index=True, nullable=False)
    subject = Column(String(500))
    sender = Column(String(255), index=True)
    recipient = Column(String(255))
    body_text = Column(Text)
    body_html = Column(Text)
    headers = Column(JSON)
    received_date = Column(DateTime, index=True)
    processed_date = Column(DateTime, default=func.now())
    
    # Analysis results
    is_phishing = Column(Boolean, default=False, index=True)
    confidence = Column(Float, default=0.0)
    risk_level = Column(Enum(RiskLevel), default=RiskLevel.UNKNOWN, index=True)
    status = Column(Enum(EmailStatus), default=EmailStatus.PENDING, index=True)
    
    # AI analysis
    ai_analysis = Column(JSON)  # Full AI response
    indicators = Column(JSON)  # List of phishing indicators
    explanation = Column(Text)
    
    # Processing metadata
    analysis_duration = Column(Float)  # seconds
    ai_provider = Column(String(50))
    
    # Relationships
    threats = relationship("Threat", back_populates="email", cascade="all, delete-orphan")
    iocs = relationship("IOC", back_populates="email", cascade="all, delete-orphan")
    
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())


class Threat(Base):
    """Threat/Incident model"""
    __tablename__ = "threats"
    
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False)
    
    title = Column(String(500))
    description = Column(Text)
    severity = Column(Enum(RiskLevel), index=True)
    
    # Response actions
    auto_quarantined = Column(Boolean, default=False)
    auto_blocked = Column(Boolean, default=False)
    manual_review_required = Column(Boolean, default=False)
    
    # Analyst assignment
    assigned_to = Column(String(255))
    status = Column(String(50), default="open", index=True)  # open, investigating, resolved, closed
    resolution_notes = Column(Text)
    
    # Timestamps
    detected_at = Column(DateTime, default=func.now())
    resolved_at = Column(DateTime)
    
    # Relationships
    email = relationship("Email", back_populates="threats")
    
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())


class IOC(Base):
    """Indicator of Compromise model"""
    __tablename__ = "iocs"
    
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False)
    
    ioc_type = Column(String(50), index=True)  # domain, url, ip, email, file_hash
    value = Column(String(1000), index=True)
    
    # Threat intelligence
    is_malicious = Column(Boolean, default=False)
    threat_score = Column(Float)
    first_seen = Column(DateTime, default=func.now())
    last_seen = Column(DateTime, default=func.now())
    occurrence_count = Column(Integer, default=1)
    
    # External threat intel
    virustotal_score = Column(Integer)
    abuse_ipdb_score = Column(Integer)
    threat_intel_sources = Column(JSON)
    
    # Relationships
    email = relationship("Email", back_populates="iocs")
    
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())


class Alert(Base):
    """Alert model for notifications"""
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(Integer, ForeignKey("threats.id"))
    
    alert_type = Column(String(50))  # email, slack, teams, sms
    recipient = Column(String(255))
    message = Column(Text)
    
    sent = Column(Boolean, default=False)
    sent_at = Column(DateTime)
    error_message = Column(Text)
    
    created_at = Column(DateTime, default=func.now())


class EmailAccount(Base):
    """Email account configuration"""
    __tablename__ = "email_accounts"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255))
    email_address = Column(String(255), unique=True, index=True)
    
    # IMAP Configuration
    imap_server = Column(String(255))
    imap_port = Column(Integer)
    imap_username = Column(String(255))
    imap_password = Column(String(500))  # Encrypted
    
    # Monitoring settings
    enabled = Column(Boolean, default=True)
    monitored_folders = Column(JSON)  # List of folders to monitor
    scan_interval = Column(Integer, default=60)  # seconds
    
    # Statistics
    total_emails_scanned = Column(Integer, default=0)
    threats_detected = Column(Integer, default=0)
    last_scan = Column(DateTime)
    
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())


class AuditLog(Base):
    """Audit log for tracking actions"""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    
    action = Column(String(100), index=True)
    entity_type = Column(String(50))
    entity_id = Column(Integer)
    
    user = Column(String(255))
    details = Column(JSON)
    ip_address = Column(String(45))
    
    created_at = Column(DateTime, default=func.now(), index=True)
