from celery import current_task
from app.tasks.celery_app import celery_app
from app.scrapers import NVDScraper, GitHubScraper, ExploitDBScraper
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

@celery_app.task(bind=True, name='app.tasks.scraping_tasks.scrape_nvd_cves')
def scrape_nvd_cves(self, days: int = 1):
    """
    Scrape CVEs from NVD for the last N days.
    
    Args:
        days (int): Number of days to look back
        
    Returns:
        dict: Scraping results
    """
    try:
        logger.info(f"Starting NVD scraping for last {days} days")
        
        # Update task state
        self.update_state(state='PROGRESS', meta={'status': 'Initializing NVD scraper'})
        
        scraper = NVDScraper()
        
        # Fetch recent CVEs
        self.update_state(state='PROGRESS', meta={'status': f'Fetching CVEs from last {days} days'})
        cves_data = scraper.fetch_recent_cves(days=days)
        
        if not cves_data:
            logger.warning("No CVEs found from NVD")
            return {
                'success': True,
                'source': 'nvd',
                'cves_found': 0,
                'cves_saved': 0,
                'message': 'No new CVEs found'
            }
        
        # Parse and save CVEs
        self.update_state(state='PROGRESS', meta={
            'status': f'Processing {len(cves_data)} CVEs',
            'cves_found': len(cves_data)
        })
        
        parsed_cves = []
        for i, cve_data in enumerate(cves_data):
            try:
                parsed_cve = scraper.parse_cve_data(cve_data)
                parsed_cves.append(parsed_cve)
                
                # Update progress every 10 CVEs
                if i % 10 == 0:
                    self.update_state(state='PROGRESS', meta={
                        'status': f'Parsed {i+1}/{len(cves_data)} CVEs',
                        'cves_found': len(cves_data),
                        'cves_parsed': i+1
                    })
            except Exception as e:
                logger.error(f"Error parsing CVE data: {str(e)}")
                continue
        
        # Save to database
        self.update_state(state='PROGRESS', meta={
            'status': 'Saving CVEs to database',
            'cves_found': len(cves_data),
            'cves_parsed': len(parsed_cves)
        })
        
        saved_count = scraper.save_cves_to_database(parsed_cves)
        
        result = {
            'success': True,
            'source': 'nvd',
            'cves_found': len(cves_data),
            'cves_parsed': len(parsed_cves),
            'cves_saved': saved_count,
            'completed_at': datetime.utcnow().isoformat()
        }
        
        logger.info(f"NVD scraping completed: {result}")
        return result
        
    except Exception as e:
        logger.error(f"NVD scraping failed: {str(e)}")
        return {
            'success': False,
            'source': 'nvd',
            'error': str(e),
            'completed_at': datetime.utcnow().isoformat()
        }

@celery_app.task(bind=True, name='app.tasks.scraping_tasks.scrape_github_exploits')
def scrape_github_exploits(self, days: int = 7):
    """
    Scrape exploit code from GitHub for the last N days.
    
    Args:
        days (int): Number of days to look back
        
    Returns:
        dict: Scraping results
    """
    try:
        logger.info(f"Starting GitHub scraping for last {days} days")
        
        self.update_state(state='PROGRESS', meta={'status': 'Initializing GitHub scraper'})
        
        scraper = GitHubScraper()
        
        # Search for recent exploits
        self.update_state(state='PROGRESS', meta={'status': f'Searching GitHub for exploits from last {days} days'})
        exploits_data = scraper.search_recent_exploits(days=days, limit=200)
        
        if not exploits_data:
            logger.warning("No exploits found on GitHub")
            return {
                'success': True,
                'source': 'github',
                'exploits_found': 0,
                'exploits_saved': 0,
                'message': 'No new exploits found'
            }
        
        # Process exploits
        self.update_state(state='PROGRESS', meta={
            'status': f'Processing {len(exploits_data)} exploits',
            'exploits_found': len(exploits_data)
        })
        
        # Save to database
        saved_count = scraper.save_exploits_to_database(exploits_data)
        
        result = {
            'success': True,
            'source': 'github',
            'exploits_found': len(exploits_data),
            'exploits_saved': saved_count,
            'completed_at': datetime.utcnow().isoformat()
        }
        
        logger.info(f"GitHub scraping completed: {result}")
        return result
        
    except Exception as e:
        logger.error(f"GitHub scraping failed: {str(e)}")
        return {
            'success': False,
            'source': 'github',
            'error': str(e),
            'completed_at': datetime.utcnow().isoformat()
        }

@celery_app.task(bind=True, name='app.tasks.scraping_tasks.scrape_exploitdb_exploits')
def scrape_exploitdb_exploits(self, days: int = 7):
    """
    Scrape exploit code from ExploitDB for the last N days.
    
    Args:
        days (int): Number of days to look back
        
    Returns:
        dict: Scraping results
    """
    try:
        logger.info(f"Starting ExploitDB scraping for last {days} days")
        
        self.update_state(state='PROGRESS', meta={'status': 'Initializing ExploitDB scraper'})
        
        scraper = ExploitDBScraper()
        
        # Search for recent exploits
        self.update_state(state='PROGRESS', meta={'status': f'Searching ExploitDB for exploits from last {days} days'})
        exploits_data = scraper.search_recent_exploits(days=days, limit=200)
        
        if not exploits_data:
            logger.warning("No exploits found on ExploitDB")
            return {
                'success': True,
                'source': 'exploitdb',
                'exploits_found': 0,
                'exploits_saved': 0,
                'message': 'No new exploits found'
            }
        
        # Process exploits
        self.update_state(state='PROGRESS', meta={
            'status': f'Processing {len(exploits_data)} exploits',
            'exploits_found': len(exploits_data)
        })
        
        # Save to database
        saved_count = scraper.save_exploits_to_database(exploits_data)
        
        result = {
            'success': True,
            'source': 'exploitdb',
            'exploits_found': len(exploits_data),
            'exploits_saved': saved_count,
            'completed_at': datetime.utcnow().isoformat()
        }
        
        logger.info(f"ExploitDB scraping completed: {result}")
        return result
        
    except Exception as e:
        logger.error(f"ExploitDB scraping failed: {str(e)}")
        return {
            'success': False,
            'source': 'exploitdb',
            'error': str(e),
            'completed_at': datetime.utcnow().isoformat()
        }

@celery_app.task(bind=True, name='app.tasks.scraping_tasks.scrape_exploits_for_cve')
def scrape_exploits_for_cve(self, cve_id: str):
    """
    Scrape exploits for a specific CVE from all sources.
    
    Args:
        cve_id (str): CVE identifier
        
    Returns:
        dict: Scraping results
    """
    try:
        logger.info(f"Starting exploit search for {cve_id}")
        
        self.update_state(state='PROGRESS', meta={'status': f'Searching exploits for {cve_id}'})
        
        all_exploits = []
        results = {}
        
        # Search GitHub
        try:
            self.update_state(state='PROGRESS', meta={'status': f'Searching GitHub for {cve_id}'})
            github_scraper = GitHubScraper()
            github_exploits = github_scraper.search_exploits_for_cve(cve_id, limit=50)
            all_exploits.extend(github_exploits)
            results['github'] = {
                'found': len(github_exploits),
                'saved': github_scraper.save_exploits_to_database(github_exploits)
            }
        except Exception as e:
            logger.error(f"GitHub search failed for {cve_id}: {str(e)}")
            results['github'] = {'error': str(e)}
        
        # Search ExploitDB
        try:
            self.update_state(state='PROGRESS', meta={'status': f'Searching ExploitDB for {cve_id}'})
            exploitdb_scraper = ExploitDBScraper()
            exploitdb_exploits = exploitdb_scraper.search_exploits_for_cve(cve_id, limit=50)
            all_exploits.extend(exploitdb_exploits)
            results['exploitdb'] = {
                'found': len(exploitdb_exploits),
                'saved': exploitdb_scraper.save_exploits_to_database(exploitdb_exploits)
            }
        except Exception as e:
            logger.error(f"ExploitDB search failed for {cve_id}: {str(e)}")
            results['exploitdb'] = {'error': str(e)}
        
        total_found = sum(r.get('found', 0) for r in results.values() if 'found' in r)
        total_saved = sum(r.get('saved', 0) for r in results.values() if 'saved' in r)
        
        result = {
            'success': True,
            'cve_id': cve_id,
            'total_exploits_found': total_found,
            'total_exploits_saved': total_saved,
            'source_results': results,
            'completed_at': datetime.utcnow().isoformat()
        }
        
        logger.info(f"Exploit search for {cve_id} completed: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Exploit search for {cve_id} failed: {str(e)}")
        return {
            'success': False,
            'cve_id': cve_id,
            'error': str(e),
            'completed_at': datetime.utcnow().isoformat()
        }

@celery_app.task(bind=True, name='app.tasks.scraping_tasks.scrape_all_sources')
def scrape_all_sources(self, days: int = 1):
    """
    Scrape all sources (NVD, GitHub, ExploitDB) in sequence.
    
    Args:
        days (int): Number of days to look back
        
    Returns:
        dict: Combined scraping results
    """
    try:
        logger.info(f"Starting comprehensive scraping for last {days} days")
        
        results = {}
        
        # Scrape NVD
        self.update_state(state='PROGRESS', meta={'status': 'Scraping NVD CVEs'})
        nvd_result = scrape_nvd_cves.apply(args=[days]).get()
        results['nvd'] = nvd_result
        
        # Scrape GitHub
        self.update_state(state='PROGRESS', meta={'status': 'Scraping GitHub exploits'})
        github_result = scrape_github_exploits.apply(args=[days]).get()
        results['github'] = github_result
        
        # Scrape ExploitDB
        self.update_state(state='PROGRESS', meta={'status': 'Scraping ExploitDB exploits'})
        exploitdb_result = scrape_exploitdb_exploits.apply(args=[days]).get()
        results['exploitdb'] = exploitdb_result
        
        # Calculate totals
        total_cves = results['nvd'].get('cves_saved', 0)
        total_exploits = (results['github'].get('exploits_saved', 0) + 
                         results['exploitdb'].get('exploits_saved', 0))
        
        result = {
            'success': True,
            'total_cves_saved': total_cves,
            'total_exploits_saved': total_exploits,
            'source_results': results,
            'completed_at': datetime.utcnow().isoformat()
        }
        
        logger.info(f"Comprehensive scraping completed: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Comprehensive scraping failed: {str(e)}")
        return {
            'success': False,
            'error': str(e),
            'completed_at': datetime.utcnow().isoformat()
        }

@celery_app.task(bind=True, name='app.tasks.scraping_tasks.bulk_import_historical_cves')
def bulk_import_historical_cves(self, start_year: int = 2021, end_year: int = None, use_both_sources: bool = False):
    """
    Bulk import all CVEs from start_year to end_year.
    This is a long-running task for initial database population.
    
    Args:
        start_year (int): Starting year
        end_year (int): Ending year (default: current year)
        use_both_sources (bool): If True, import from both NVD and CVE Project
        
    Returns:
        dict: Import statistics
    """
    try:
        logger.info(f"Starting bulk CVE import from {start_year} to {end_year or 'now'}")
        
        self.update_state(state='PROGRESS', meta={
            'status': f'Starting bulk import from {start_year}...'
        })
        
        results = {}
        
        # Import from NVD (primary source)
        logger.info("Importing from NVD...")
        self.update_state(state='PROGRESS', meta={'status': 'Importing from NVD...'})
        
        nvd_scraper = NVDScraper()
        nvd_stats = nvd_scraper.bulk_import_cves(start_year=start_year, end_year=end_year)
        results['nvd'] = nvd_stats
        
        # Import from CVE Project (backup/supplement)
        if use_both_sources:
            logger.info("Importing from CVE Project...")
            self.update_state(state='PROGRESS', meta={'status': 'Importing from CVE Project...'})
            
            from app.scrapers.cve_project_scraper import CVEProjectScraper
            cve_project_scraper = CVEProjectScraper()
            cve_project_stats = cve_project_scraper.bulk_import_cves(start_year=start_year, end_year=end_year)
            results['cve_project'] = cve_project_stats
        
        total_saved = nvd_stats['total_cves_saved']
        if use_both_sources:
            total_saved += results['cve_project']['total_cves_saved']
        
        logger.info(f"Bulk import completed: {total_saved} CVEs total")
        
        return {
            'success': True,
            'total_cves_saved': total_saved,
            'sources': results,
            'completed_at': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Bulk import failed: {str(e)}")
        return {
            'success': False,
            'error': str(e),
            'completed_at': datetime.utcnow().isoformat()
        }


@celery_app.task(bind=True, name='app.tasks.scraping_tasks.monitor_new_cves')
def monitor_new_cves(self, lookback_hours: int = 24):
    """
    Check for new CVEs and update database.
    Scheduled task that runs periodically.
    
    Args:
        lookback_hours (int): Hours to look back
        
    Returns:
        dict: Monitoring results
    """
    try:
        logger.info(f"Checking for new CVEs (lookback: {lookback_hours} hours)")
        
        from app.scrapers.cve_monitor import CVEMonitor
        
        monitor = CVEMonitor()
        stats = monitor.check_for_new_cves(lookback_hours=lookback_hours)
        
        logger.info(
            f"CVE monitor complete: {stats['total_cves_new']} new, "
            f"{stats['total_cves_updated']} updated"
        )
        
        return {
            'success': True,
            **stats,
            'completed_at': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"CVE monitoring failed: {str(e)}")
        return {
            'success': False,
            'error': str(e),
            'completed_at': datetime.utcnow().isoformat()
        }


@celery_app.task(bind=True, name='app.tasks.scraping_tasks.compare_database_with_sources')
def compare_database_with_sources(self):
    """
    Compare local database with CVE sources to identify gaps.
    
    Returns:
        dict: Comparison statistics
    """
    try:
        from app.scrapers.cve_monitor import CVEMonitor
        
        monitor = CVEMonitor()
        stats = monitor.compare_with_database()
        
        logger.info(f"Database comparison complete: {stats.get('total_cves_local', 0)} CVEs")
        return {
            'success': True,
            **stats,
            'completed_at': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Database comparison failed: {str(e)}")
        return {
            'success': False,
            'error': str(e),
            'completed_at': datetime.utcnow().isoformat()
        } 