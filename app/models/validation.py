from sqlalchemy import Column, String, Text, Integer, Boolean, DateTime, JSON, ForeignKey, Index, Float
from sqlalchemy.orm import relationship
from .base import BaseModel

class ValidationResult(BaseModel):
    """Model for storing exploit validation results."""
    __tablename__ = 'validation_results'
    
    # Foreign Key to Exploit
    exploit_id = Column(Integer, ForeignKey('exploits.id'), nullable=False, index=True)
    
    # Validation Information
    validation_date = Column(DateTime, nullable=False, index=True)
    success = Column(Boolean, nullable=False, index=True)
    
    # Test Environment
    test_environment = Column(String(200), nullable=True)  # Docker image, VM, etc.
    test_platform = Column(String(100), nullable=True)  # Linux, Windows, etc.
    test_version = Column(String(100), nullable=True)  # OS version, app version
    
    # Execution Details
    execution_time = Column(Float, nullable=True)  # Time in seconds
    exit_code = Column(Integer, nullable=True)
    stdout_output = Column(Text, nullable=True)
    stderr_output = Column(Text, nullable=True)
    
    # Error Information
    error_type = Column(String(100), nullable=True)  # TIMEOUT, RUNTIME_ERROR, etc.
    error_message = Column(Text, nullable=True)
    
    # Validation Metadata
    validator_version = Column(String(50), nullable=True)
    test_case = Column(String(200), nullable=True)  # Which test case was run
    confidence_level = Column(Integer, default=0)  # 0-100 confidence in result
    
    # Network/Security Context
    network_activity = Column(JSON, nullable=True)  # Network connections made
    file_system_changes = Column(JSON, nullable=True)  # Files created/modified
    process_activity = Column(JSON, nullable=True)  # Processes spawned
    
    # Dependencies and Requirements
    missing_dependencies = Column(JSON, nullable=True)  # List of missing deps
    installed_packages = Column(JSON, nullable=True)  # Packages installed for test
    
    # Manual Review
    manual_review = Column(Boolean, default=False)
    reviewer_notes = Column(Text, nullable=True)
    false_positive = Column(Boolean, default=False)
    
    # Additional Metadata
    validation_config = Column(JSON, nullable=True)  # Configuration used for validation
    raw_logs = Column(Text, nullable=True)  # Full execution logs
    
    # Relationships
    exploit = relationship("Exploit", back_populates="validation_results")
    
    # Indexes
    __table_args__ = (
        Index('idx_validation_exploit_date', 'exploit_id', 'validation_date'),
        Index('idx_validation_success_date', 'success', 'validation_date'),
        Index('idx_validation_platform', 'test_platform', 'success'),
    )
    
    def __repr__(self):
        status = "SUCCESS" if self.success else "FAILED"
        return f"<ValidationResult(exploit_id={self.exploit_id}, status={status})>"
    
    @property
    def status_display(self):
        """Get human-readable status."""
        if self.success:
            return "Validated"
        elif self.error_type:
            return f"Failed ({self.error_type})"
        else:
            return "Failed"
    
    @property
    def execution_time_display(self):
        """Get formatted execution time."""
        if not self.execution_time:
            return "N/A"
        
        if self.execution_time < 1:
            return f"{self.execution_time * 1000:.0f}ms"
        elif self.execution_time < 60:
            return f"{self.execution_time:.1f}s"
        else:
            minutes = int(self.execution_time // 60)
            seconds = self.execution_time % 60
            return f"{minutes}m {seconds:.1f}s"
    
    @property
    def has_security_impact(self):
        """Check if validation showed actual security impact."""
        if not self.success:
            return False
        
        # Check for indicators of successful exploitation
        indicators = [
            self.network_activity and len(self.network_activity) > 0,
            self.file_system_changes and len(self.file_system_changes) > 0,
            self.process_activity and len(self.process_activity) > 0,
            self.exit_code == 0,
            "exploit" in (self.stdout_output or "").lower(),
            "shell" in (self.stdout_output or "").lower(),
        ]
        
        return any(indicators)
    
    @property
    def risk_level(self):
        """Calculate risk level based on validation results."""
        if not self.success:
            return "NONE"
        
        if self.has_security_impact:
            if self.confidence_level >= 80:
                return "HIGH"
            elif self.confidence_level >= 60:
                return "MEDIUM"
            else:
                return "LOW"
        
        return "INFORMATIONAL"
    
    def get_summary(self):
        """Get a summary of the validation result."""
        summary = {
            'status': self.status_display,
            'execution_time': self.execution_time_display,
            'confidence': f"{self.confidence_level}%",
            'risk_level': self.risk_level,
            'has_impact': self.has_security_impact,
            'platform': self.test_platform or 'Unknown',
            'environment': self.test_environment or 'Unknown'
        }
        
        if not self.success and self.error_message:
            summary['error'] = self.error_message[:200] + ("..." if len(self.error_message) > 200 else "")
        
        return summary
    
    def to_dict(self):
        """Convert to dictionary with additional computed fields."""
        data = super().to_dict()
        data.update({
            'status_display': self.status_display,
            'execution_time_display': self.execution_time_display,
            'has_security_impact': self.has_security_impact,
            'risk_level': self.risk_level,
            'summary': self.get_summary()
        })
        return data 