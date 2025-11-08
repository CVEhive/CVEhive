from sqlalchemy import Column, String, Text, Float, JSON, Boolean, DateTime, Index, Integer
from sqlalchemy.orm import relationship
from .base import BaseModel

class CVE(BaseModel):
    """CVE (Common Vulnerabilities and Exposures) model."""
    __tablename__ = 'cves'
    
    # Core CVE Information
    cve_id = Column(String(20), unique=True, nullable=False, index=True)
    summary = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    
    # CVSS Scoring
    cvss_v2_score = Column(Float, nullable=True)
    cvss_v3_score = Column(Float, nullable=True)
    cvss_v2_vector = Column(String(200), nullable=True)
    cvss_v3_vector = Column(String(200), nullable=True)
    severity = Column(String(20), nullable=True, index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    
    # Dates
    published_date = Column(DateTime, nullable=True, index=True)
    modified_date = Column(DateTime, nullable=True)
    
    # Vendor and Product Information
    vendor = Column(String(200), nullable=True, index=True)
    product = Column(String(200), nullable=True, index=True)
    version = Column(String(100), nullable=True)
    
    # References and Links
    references = Column(JSON, nullable=True)  # List of reference URLs
    nvd_url = Column(String(500), nullable=True)
    
    # CWE (Common Weakness Enumeration)
    cwe_ids = Column(JSON, nullable=True)  # List of CWE IDs
    
    # Exploit Information
    has_exploit = Column(Boolean, default=False, index=True)
    exploit_count = Column(Integer, default=0)
    
    # Additional Metadata
    vulnerability_type = Column(String(100), nullable=True)
    attack_vector = Column(String(50), nullable=True)  # NETWORK, ADJACENT, LOCAL, PHYSICAL
    attack_complexity = Column(String(20), nullable=True)  # LOW, HIGH
    
    # Data Source Information
    source = Column(String(50), default='NVD', nullable=False)  # NVD, CVE_DETAILS, etc.
    raw_data = Column(JSON, nullable=True)  # Store original JSON for debugging
    
    # Relationships
    exploits = relationship("Exploit", back_populates="cve", cascade="all, delete-orphan")
    
    # Indexes for better query performance
    __table_args__ = (
        Index('idx_cve_search', 'cve_id', 'vendor', 'product'),
        Index('idx_cve_severity_date', 'severity', 'published_date'),
        Index('idx_cve_exploit_status', 'has_exploit', 'severity'),
    )
    
    def __repr__(self):
        return f"<CVE(cve_id='{self.cve_id}', severity='{self.severity}')>"
    
    @property
    def severity_score(self):
        """Get the highest available CVSS score."""
        return self.cvss_v3_score or self.cvss_v2_score or 0.0
    
    @property
    def severity_level(self):
        """Get severity level based on CVSS score."""
        score = self.severity_score
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0.0:
            return "LOW"
        else:
            return "UNKNOWN"
    
    @property
    def search_text(self):
        """Combined text for search indexing."""
        parts = [
            self.cve_id,
            self.summary or '',
            self.description or '',
            self.vendor or '',
            self.product or '',
            self.vulnerability_type or ''
        ]
        return ' '.join(filter(None, parts)).lower()
    
    def to_dict(self):
        """Convert to dictionary with additional computed fields."""
        data = super().to_dict()
        data.update({
            'severity_score': self.severity_score,
            'severity_level': self.severity_level,
            'exploit_count': len(self.exploits) if self.exploits else 0
        })
        return data 