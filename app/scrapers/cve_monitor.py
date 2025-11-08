"""
CVE Monitoring Service
Continuously polls multiple sources for new CVEs and updates the database.
"""

import logging
import time
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from app.scrapers.nvd_scraper import NVDScraper
from app.scrapers.cve_project_scraper import CVEProjectScraper
from app.models import CVE
from app.models.base import get_db
from sqlalchemy import func

logger = logging.getLogger(__name__)


class CVEMonitor:
    """
    Monitors multiple CVE sources for new and updated CVEs.
    Implements intelligent polling with incremental updates.
    """
    
    def __init__(self, api_key: Optional[str] = None):
        self.nvd_scraper = NVDScraper(api_key=api_key)
        self.cve_project_scraper = CVEProjectScraper()
        self.last_check_time = None
        self.monitoring_state_file = 'data/cve_monitor_state.json'
        self._load_state()
    
    def _load_state(self):
        """Load monitoring state from file."""
        try:
            if Path(self.monitoring_state_file).exists():
                with open(self.monitoring_state_file, 'r') as f:
                    state = json.load(f)
                    self.last_check_time = datetime.fromisoformat(state.get('last_check_time'))
                    logger.info(f"Loaded monitoring state: last check at {self.last_check_time}")
        except Exception as e:
            logger.warning(f"Could not load monitoring state: {str(e)}")
            self.last_check_time = None
    
    def _save_state(self):
        """Save monitoring state to file."""
        try:
            Path(self.monitoring_state_file).parent.mkdir(parents=True, exist_ok=True)
            with open(self.monitoring_state_file, 'w') as f:
                state = {
                    'last_check_time': self.last_check_time.isoformat() if self.last_check_time else None,
                    'last_update': datetime.utcnow().isoformat()
                }
                json.dump(state, f, indent=2)
        except Exception as e:
            logger.error(f"Could not save monitoring state: {str(e)}")
    
    def check_for_new_cves(self, lookback_hours: int = 24, use_backup: bool = True) -> Dict:
        """
        Check for new CVEs published or modified since last check.
        
        Args:
            lookback_hours (int): Hours to look back if no last check time
            use_backup (bool): If True, also check CVE Project API as backup
            
        Returns:
            Dict: Statistics about new/updated CVEs
        """
        logger.info("Starting CVE check...")
        
        # Determine time range
        if self.last_check_time:
            start_time = self.last_check_time
        else:
            start_time = datetime.utcnow() - timedelta(hours=lookback_hours)
        
        end_time = datetime.utcnow()
        
        logger.info(f"Checking for CVEs from {start_time} to {end_time}")
        
        stats = {
            'check_time': end_time.isoformat(),
            'lookback_start': start_time.isoformat(),
            'sources': {},
            'total_cves_new': 0,
            'total_cves_updated': 0
        }
        
        # Check NVD first (primary source)
        try:
            logger.info("Checking NVD...")
            cves_data = self.nvd_scraper.fetch_cves_by_date_range(start_time, end_time)
            
            if cves_data:
                new_count, updated_count = self.nvd_scraper.save_cves_batch(cves_data)
                stats['sources']['nvd'] = {
                    'cves_found': len(cves_data),
                    'cves_new': new_count,
                    'cves_updated': updated_count,
                    'success': True
                }
                stats['total_cves_new'] += new_count
                stats['total_cves_updated'] += updated_count
                
                logger.info(f"NVD: {new_count} new, {updated_count} updated")
            else:
                stats['sources']['nvd'] = {
                    'cves_found': 0,
                    'cves_new': 0,
                    'cves_updated': 0,
                    'success': True
                }
                
        except Exception as e:
            error_msg = f"Error checking NVD: {str(e)}"
            logger.error(error_msg)
            stats['sources']['nvd'] = {
                'success': False,
                'error': error_msg
            }
        
        # Check CVE Project as backup
        if use_backup:
            try:
                logger.info("Checking CVE Project...")
                cves_data = self.cve_project_scraper.fetch_cves_by_date_range(start_time, end_time)
                
                if cves_data:
                    new_count, updated_count = self.cve_project_scraper.save_cves_batch(cves_data)
                    stats['sources']['cve_project'] = {
                        'cves_found': len(cves_data),
                        'cves_new': new_count,
                        'cves_updated': updated_count,
                        'success': True
                    }
                    stats['total_cves_new'] += new_count
                    stats['total_cves_updated'] += updated_count
                    
                    logger.info(f"CVE Project: {new_count} new, {updated_count} updated")
                else:
                    stats['sources']['cve_project'] = {
                        'cves_found': 0,
                        'cves_new': 0,
                        'cves_updated': 0,
                        'success': True
                    }
                    
            except Exception as e:
                error_msg = f"Error checking CVE Project: {str(e)}"
                logger.error(error_msg)
                stats['sources']['cve_project'] = {
                    'success': False,
                    'error': error_msg
                }
        
        # Update last check time
        self.last_check_time = end_time
        self._save_state()
        
        logger.info(
            f"CVE check complete: {stats['total_cves_new']} new, "
            f"{stats['total_cves_updated']} updated"
        )
        
        return stats
    
    def compare_with_database(self) -> Dict:
        """
        Compare CVE sources with local database to find gaps.
        
        Returns:
            Dict: Comparison statistics
        """
        logger.info("Comparing database with CVE sources...")
        
        db = next(get_db())
        
        try:
            # Get database statistics
            total_local = db.query(CVE).count()
            oldest_cve = db.query(CVE).order_by(CVE.published_date.asc()).first()
            newest_cve = db.query(CVE).order_by(CVE.published_date.desc()).first()
            
            # Get CVEs by year
            year_counts = {}
            for year in range(2021, datetime.utcnow().year + 1):
                count = db.query(CVE).filter(
                    func.extract('year', CVE.published_date) == year
                ).count()
                year_counts[year] = count
            
            # Get counts by source
            source_counts = {}
            for source in ['NVD', 'CVE_PROJECT']:
                count = db.query(CVE).filter(CVE.source == source).count()
                source_counts[source] = count
            
            stats = {
                'total_cves_local': total_local,
                'oldest_cve_date': oldest_cve.published_date.isoformat() if oldest_cve else None,
                'newest_cve_date': newest_cve.published_date.isoformat() if newest_cve else None,
                'year_breakdown': year_counts,
                'source_breakdown': source_counts,
                'last_check': self.last_check_time.isoformat() if self.last_check_time else None
            }
            
            logger.info(f"Database contains {total_local} CVEs")
            return stats
            
        except Exception as e:
            logger.error(f"Error comparing database: {str(e)}")
            return {'error': str(e)}
        finally:
            db.close()
    
    def start_monitoring(self, interval_minutes: int = 60, run_once: bool = False):
        """
        Start continuous monitoring loop.
        
        Args:
            interval_minutes (int): Minutes between checks
            run_once (bool): If True, only run once instead of continuous loop
        """
        logger.info(f"Starting CVE monitoring (interval: {interval_minutes} minutes)")
        
        while True:
            try:
                stats = self.check_for_new_cves()
                
                if stats.get('total_cves_new', 0) > 0 or stats.get('total_cves_updated', 0) > 0:
                    logger.info(
                        f"Monitor cycle complete: {stats['total_cves_new']} new, "
                        f"{stats['total_cves_updated']} updated"
                    )
                
                if run_once:
                    logger.info("Single run complete, exiting...")
                    break
                
                # Sleep until next check
                logger.info(f"Next check in {interval_minutes} minutes")
                time.sleep(interval_minutes * 60)
                
            except KeyboardInterrupt:
                logger.info("Monitoring stopped by user")
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {str(e)}")
                # Sleep on error to avoid rapid retry
                time.sleep(300)  # 5 minutes
    
    def backfill_missing_cves(self, start_date: datetime, end_date: datetime) -> Dict:
        """
        Backfill CVEs for a specific date range (useful for filling gaps).
        
        Args:
            start_date (datetime): Start date
            end_date (datetime): End date
            
        Returns:
            Dict: Backfill statistics
        """
        logger.info(f"Backfilling CVEs from {start_date} to {end_date}")
        
        stats = {
            'success': True,
            'date_range': f"{start_date} to {end_date}",
            'sources': {}
        }
        
        # Backfill from NVD
        try:
            cves_data = self.nvd_scraper.fetch_cves_by_date_range(start_date, end_date)
            new_count, updated_count = self.nvd_scraper.save_cves_batch(cves_data)
            
            stats['sources']['nvd'] = {
                'cves_found': len(cves_data),
                'cves_new': new_count,
                'cves_updated': updated_count
            }
        except Exception as e:
            logger.error(f"Error backfilling from NVD: {str(e)}")
            stats['sources']['nvd'] = {'error': str(e)}
        
        # Backfill from CVE Project
        try:
            cves_data = self.cve_project_scraper.fetch_cves_by_date_range(start_date, end_date)
            new_count, updated_count = self.cve_project_scraper.save_cves_batch(cves_data)
            
            stats['sources']['cve_project'] = {
                'cves_found': len(cves_data),
                'cves_new': new_count,
                'cves_updated': updated_count
            }
        except Exception as e:
            logger.error(f"Error backfilling from CVE Project: {str(e)}")
            stats['sources']['cve_project'] = {'error': str(e)}
        
        return stats

