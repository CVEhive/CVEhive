from celery import Celery
from app.config import Config
import logging

# Create Celery instance
celery_app = Celery('cvehive')

# Configure Celery
celery_app.conf.update(
    broker_url=Config.REDIS_URL,
    result_backend=Config.REDIS_URL,
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    
    # Task routing
    task_routes={
        'app.tasks.scraping_tasks.*': {'queue': 'scraping'},
        'app.tasks.validation_tasks.*': {'queue': 'validation'},
        'app.tasks.maintenance_tasks.*': {'queue': 'maintenance'},
    },
    
    # Task execution settings
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_reject_on_worker_lost=True,
    
    # Result settings
    result_expires=3600,  # 1 hour
    
    # Beat schedule for periodic tasks
    beat_schedule={
        # CVE Monitoring - Check for new CVEs every hour
        'monitor-new-cves-hourly': {
            'task': 'app.tasks.scraping_tasks.monitor_new_cves',
            'schedule': 3600.0,  # Every hour
            'args': (1,)  # Look back 1 hour
        },
        # CVE Monitoring - Backup check every 6 hours
        'monitor-new-cves-6-hourly': {
            'task': 'app.tasks.scraping_tasks.monitor_new_cves',
            'schedule': 21600.0,  # Every 6 hours
            'args': (6,)  # Look back 6 hours
        },
        # Compare database with sources daily
        'compare-database-daily': {
            'task': 'app.tasks.scraping_tasks.compare_database_with_sources',
            'schedule': 86400.0,  # Daily
        },
        # Scrape GitHub exploits every 12 hours
        'scrape-github-exploits': {
            'task': 'app.tasks.scraping_tasks.scrape_github_exploits',
            'schedule': 43200.0,  # Every 12 hours
            'args': (12,)  # Scrape last 12 hours
        },
        # Scrape ExploitDB exploits daily
        'scrape-exploitdb-daily': {
            'task': 'app.tasks.scraping_tasks.scrape_exploitdb_exploits',
            'schedule': 86400.0,  # Every day
            'args': (7,)  # Scrape last 7 days
        },
        'cleanup-old-data': {
            'task': 'app.tasks.maintenance_tasks.cleanup_old_data',
            'schedule': 86400.0,  # Every day
        },
        'update-statistics': {
            'task': 'app.tasks.maintenance_tasks.update_statistics',
            'schedule': 1800.0,  # Every 30 minutes
        },
        'health-check': {
            'task': 'app.tasks.maintenance_tasks.health_check',
            'schedule': 300.0,  # Every 5 minutes
        }
    },
    beat_schedule_filename='celerybeat-schedule'
)

# Auto-discover tasks
celery_app.autodiscover_tasks([
    'app.tasks.scraping_tasks',
    'app.tasks.validation_tasks', 
    'app.tasks.maintenance_tasks'
])

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@celery_app.task(bind=True)
def debug_task(self):
    """Debug task for testing Celery setup."""
    logger.info(f'Request: {self.request!r}')
    return 'Debug task completed' 