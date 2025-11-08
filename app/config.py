import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Config:
    """Application configuration class."""
    
    # Flask Configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    DEBUG = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
    HOST = os.getenv('FLASK_HOST', '0.0.0.0')
    PORT = int(os.getenv('FLASK_PORT', '5000'))
    
    # Database Configuration
    DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///cvehive.db')
    REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    
    # API Keys
    GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
    NVD_API_KEY = os.getenv('NVD_API_KEY')
    
    # Celery Configuration
    CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
    CELERY_RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')
    
    # Docker Configuration
    DOCKER_IMAGE = os.getenv('DOCKER_IMAGE', 'ubuntu:20.04')
    EXPLOIT_TIMEOUT = int(os.getenv('EXPLOIT_TIMEOUT', '300'))
    
    # Rate Limiting
    GITHUB_RATE_LIMIT = int(os.getenv('GITHUB_RATE_LIMIT', '5000'))
    NVD_RATE_LIMIT = int(os.getenv('NVD_RATE_LIMIT', '50'))
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = os.getenv('LOG_FILE', 'logs/cvehive.log')
    
    # Security
    ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', '*').split(',')
    
    # Feature Flags
    ENABLE_EXPLOIT_VALIDATION = os.getenv('ENABLE_EXPLOIT_VALIDATION', 'True').lower() == 'true'
    ENABLE_REAL_TIME_SCRAPING = os.getenv('ENABLE_REAL_TIME_SCRAPING', 'True').lower() == 'true'
    ENABLE_API = os.getenv('ENABLE_API', 'True').lower() == 'true'
    
    # Pagination
    RESULTS_PER_PAGE = 20
    MAX_RESULTS_PER_PAGE = 100
    
    # Scraping Configuration
    SCRAPE_INTERVAL_HOURS = 6
    MAX_GITHUB_SEARCH_RESULTS = 100
    
    # CVE Sources
    NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    EXPLOITDB_BASE_URL = "https://www.exploit-db.com"
    GITHUB_SEARCH_API = "https://api.github.com/search/repositories"
    
    @classmethod
    def validate_config(cls):
        """Validate required configuration."""
        required_vars = []
        
        if not cls.SECRET_KEY or cls.SECRET_KEY == 'dev-secret-key-change-in-production':
            if cls.FLASK_ENV == 'production':
                required_vars.append('SECRET_KEY')
        
        if cls.ENABLE_REAL_TIME_SCRAPING and not cls.GITHUB_TOKEN:
            required_vars.append('GITHUB_TOKEN (recommended for higher rate limits)')
            
        if required_vars:
            raise ValueError(f"Missing required environment variables: {', '.join(required_vars)}")
        
        return True 