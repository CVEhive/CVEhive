from datetime import datetime
from sqlalchemy import Column, Integer, DateTime, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from app.config import Config

# Create the declarative base
Base = declarative_base()

class BaseModel(Base):
    """Base model class with common fields."""
    __abstract__ = True
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    def to_dict(self):
        """Convert model instance to dictionary."""
        return {
            column.name: getattr(self, column.name)
            for column in self.__table__.columns
        }
    
    def __repr__(self):
        return f"<{self.__class__.__name__}(id={self.id})>"

# Database setup
engine = create_engine(Config.DATABASE_URL, echo=Config.DEBUG)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Flask-SQLAlchemy setup for admin panel
from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()

def get_db():
    """Get database session."""
    db_session = SessionLocal()
    try:
        yield db_session
    finally:
        db_session.close()

def init_db(app=None):
    """Initialize database - create tables if they don't exist."""
    if app:
        # Initialize Flask-SQLAlchemy
        app.config['SQLALCHEMY_DATABASE_URI'] = Config.DATABASE_URL
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        db.init_app(app)
        
        with app.app_context():
            create_tables()
    else:
        create_tables()

def create_tables():
    """Create all tables."""
    Base.metadata.create_all(bind=engine)

def drop_tables():
    """Drop all tables."""
    Base.metadata.drop_all(bind=engine) 