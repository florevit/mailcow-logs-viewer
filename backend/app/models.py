"""
SQLAlchemy database models for storing mailcow logs

SIMPLIFIED VERSION:
- Correlation now relies solely on Message-ID
- Removed old generate_correlation_key function
- Correlation key is now SHA256 of Message-ID
"""
from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, Text, Index, JSON
from sqlalchemy.dialects.postgresql import JSONB
from datetime import datetime

from .database import Base


class PostfixLog(Base):
    """Postfix mail server logs"""
    __tablename__ = "postfix_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    time = Column(DateTime, index=True, nullable=False)
    program = Column(String(100), index=True)
    priority = Column(String(20))
    message = Column(Text)
    
    # Parsed fields from message
    queue_id = Column(String(50), index=True)
    message_id = Column(String(255), index=True)
    sender = Column(String(255), index=True)
    recipient = Column(String(255), index=True)
    status = Column(String(50), index=True)  # sent, bounced, deferred, rejected
    relay = Column(String(255))
    delay = Column(Float)
    dsn = Column(String(20))
    
    # Correlation
    correlation_key = Column(String(64), index=True)  # SHA256 hash of Message-ID
    
    # Raw data
    raw_data = Column(JSONB)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_postfix_time_queue', 'time', 'queue_id'),
        Index('idx_postfix_sender_recipient', 'sender', 'recipient'),
        Index('idx_postfix_correlation', 'correlation_key'),
        Index('idx_postfix_message_id', 'message_id'),  # Critical for Message-ID lookup
    )
    
    def __repr__(self):
        return f"<PostfixLog(queue_id={self.queue_id}, status={self.status})>"


class RspamdLog(Base):
    """Rspamd spam filtering logs"""
    __tablename__ = "rspamd_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    time = Column(DateTime, index=True, nullable=False)
    
    # Message details
    message_id = Column(String(255), index=True)  # CRITICAL: Used for correlation
    queue_id = Column(String(50), index=True)
    subject = Column(Text)
    size = Column(Integer)
    
    # Email addresses
    sender_smtp = Column(String(255), index=True)
    sender_mime = Column(String(255))
    recipients_smtp = Column(JSONB)  # List of recipients
    recipients_mime = Column(JSONB)
    
    # Spam analysis
    score = Column(Float, index=True)
    required_score = Column(Float)
    action = Column(String(50), index=True)  # no action, greylist, add header, reject
    symbols = Column(JSONB)  # Spam detection symbols
    
    # Authentication & Direction
    user = Column(String(255), index=True)  # Authenticated user (for outbound)
    direction = Column(String(20), index=True)  # inbound, outbound, unknown
    ip = Column(String(50), index=True)
    
    # Flags
    is_spam = Column(Boolean, index=True)
    is_skipped = Column(Boolean)
    has_auth = Column(Boolean, index=True)  # Has MAILCOW_AUTH symbol
    
    # Correlation
    correlation_key = Column(String(64), index=True)
    
    # Raw data
    raw_data = Column(JSONB)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_rspamd_time_direction', 'time', 'direction'),
        Index('idx_rspamd_sender', 'sender_smtp'),
        Index('idx_rspamd_recipients', 'recipients_smtp', postgresql_using='gin'),
        Index('idx_rspamd_score', 'score', 'action'),
        Index('idx_rspamd_correlation', 'correlation_key'),
        Index('idx_rspamd_message_id', 'message_id'),  # Critical for Message-ID lookup
    )
    
    def __repr__(self):
        return f"<RspamdLog(message_id={self.message_id}, score={self.score}, action={self.action})>"


class NetfilterLog(Base):
    """Netfilter/Authentication failure logs"""
    __tablename__ = "netfilter_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    time = Column(DateTime, index=True, nullable=False)
    priority = Column(String(20))
    message = Column(Text)
    
    # Parsed fields
    ip = Column(String(50), index=True)
    rule_id = Column(Integer)
    attempts_left = Column(Integer)
    username = Column(String(255), index=True)
    auth_method = Column(String(50))  # SASL LOGIN, SASL PLAIN, etc.
    action = Column(String(50), index=True)  # warning, banned
    
    # Raw data
    raw_data = Column(JSONB)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_netfilter_time_ip', 'time', 'ip'),
        Index('idx_netfilter_username', 'username'),
    )
    
    def __repr__(self):
        return f"<NetfilterLog(ip={self.ip}, username={self.username}, action={self.action})>"


class MessageCorrelation(Base):
    """
    Correlation table to link related logs from different sources
    
    SIMPLIFIED APPROACH:
    - Uses Message-ID as the primary correlation key (SHA256 hashed)
    - Links all Postfix logs via Queue-ID
    - Links Rspamd log via Message-ID match
    """
    __tablename__ = "message_correlations"
    
    id = Column(Integer, primary_key=True, index=True)
    correlation_key = Column(String(64), unique=True, index=True, nullable=False)
    
    # Message identifiers - BOTH are now critical
    message_id = Column(String(255), index=True, unique=True)  # Primary correlation identifier
    queue_id = Column(String(50), index=True)  # Secondary identifier
    
    # Related log IDs
    postfix_log_ids = Column(JSONB)  # List of ALL postfix log IDs for this message
    rspamd_log_id = Column(Integer, index=True)
    
    # Message summary
    sender = Column(String(255), index=True)
    recipient = Column(String(255), index=True)  # First/primary recipient
    subject = Column(Text)
    direction = Column(String(20))  # inbound, outbound, unknown
    final_status = Column(String(50))  # delivered, bounced, deferred, rejected, spam
    
    # Completion tracking
    is_complete = Column(Boolean, default=False, index=True)  # Has Queue-ID and Postfix logs
    
    # Timeline
    first_seen = Column(DateTime, index=True)
    last_seen = Column(DateTime)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_correlation_message_id', 'message_id'),  # CRITICAL INDEX
        Index('idx_correlation_queue_id', 'queue_id'),
        Index('idx_correlation_sender_recipient', 'sender', 'recipient'),
    )
    
    def __repr__(self):
        return f"<MessageCorrelation(message_id={self.message_id}, status={self.final_status})>"


class DomainDNSCheck(Base):
    """Cached DNS check results for domains"""
    __tablename__ = "domain_dns_checks"
    
    id = Column(Integer, primary_key=True, index=True)
    domain_name = Column(String(255), unique=True, index=True, nullable=False)
    
    spf_check = Column(JSONB)
    dkim_check = Column(JSONB)
    dmarc_check = Column(JSONB)
    
    checked_at = Column(DateTime, nullable=False)
    is_full_check = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)