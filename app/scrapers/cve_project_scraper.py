"""
CVE Project API Scraper
Alternative data source using the official CVE Program API
https://github.com/CVEProject/cvelistV5
"""

import requests
import logging
import time
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
from app.models import CVE
from app.models.base import get_db

logger = logging.getLogger(__name__)


class CVEProjectScraper:
    """
    Scraper for the official CVE Project API.
    This is a backup/alternative to NVD API.
    """
    
    def __init__(self):
        self.base_url = "https://cveawg.mitre.org/api"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CVEhive/1.0 (Security Research Tool)',
            'Accept': 'application/json'
        })
    
    def fetch_recent_cves(self, days: int = 7) -> List[Dict]:
        """
        Fetch CVEs published in the last N days from CVE Project.
        
        Args:
            days (int): Number of days to look back
            
        Returns:
            List[Dict]: List of CVE data
        """
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        return self.fetch_cves_by_date_range(start_date, end_date)
    
    def fetch_cves_by_date_range(self, start_date: datetime, end_date: datetime) -> List[Dict]:
        """
        Fetch CVEs within a date range from CVE Project.
        
        Args:
            start_date (datetime): Start date
            end_date (datetime): End date
            
        Returns:
            List[Dict]: List of CVE data
        """
        cves = []
        
        # CVE Project API uses a different approach - fetch by year and filter
        start_year = start_date.year
        end_year = end_date.year
        
        for year in range(start_year, end_year + 1):
            try:
                year_cves = self._fetch_cves_by_year(year)
                
                # Filter by date range
                filtered_cves = []
                for cve in year_cves:
                    pub_date = self._extract_published_date(cve)
                    if pub_date and start_date <= pub_date <= end_date:
                        filtered_cves.append(cve)
                
                cves.extend(filtered_cves)
                logger.info(f"Fetched {len(filtered_cves)} CVEs from year {year}")
                
                # Rate limiting
                time.sleep(0.5)
                
            except Exception as e:
                logger.error(f"Error fetching CVEs for year {year}: {str(e)}")
                continue
        
        logger.info(f"Total CVEs fetched from CVE Project: {len(cves)}")
        return cves
    
    def _fetch_cves_by_year(self, year: int) -> List[Dict]:
        """
        Fetch all CVEs for a specific year.
        
        Args:
            year (int): Year to fetch
            
        Returns:
            List[Dict]: List of CVE data
        """
        url = f"{self.base_url}/cve"
        cves = []
        page = 1
        page_size = 100
        
        while True:
            params = {
                'year': year,
                'page': page,
                'per_page': page_size
            }
            
            try:
                response = self.session.get(url, params=params, timeout=30)
                
                if response.status_code == 404:
                    # No more data
                    break
                
                response.raise_for_status()
                data = response.json()
                
                if not data or 'cves' not in data or not data['cves']:
                    break
                
                batch = data['cves']
                cves.extend(batch)
                
                # Check if we have more pages
                if len(batch) < page_size:
                    break
                
                page += 1
                time.sleep(0.2)  # Rate limiting
                
            except requests.exceptions.RequestException as e:
                logger.error(f"Error fetching page {page} for year {year}: {str(e)}")
                break
        
        return cves
    
    def fetch_cve_by_id(self, cve_id: str) -> Optional[Dict]:
        """
        Fetch a specific CVE by ID.
        
        Args:
            cve_id (str): CVE identifier (e.g., CVE-2023-1234)
            
        Returns:
            Optional[Dict]: CVE data or None if not found
        """
        url = f"{self.base_url}/cve/{cve_id}"
        
        try:
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 404:
                logger.warning(f"CVE {cve_id} not found in CVE Project")
                return None
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching CVE {cve_id} from CVE Project: {str(e)}")
            return None
    
    def parse_cve_data(self, cve_data: Dict) -> Dict:
        """
        Parse CVE Project data into our format.
        
        Args:
            cve_data (Dict): Raw CVE data from CVE Project
            
        Returns:
            Dict: Parsed CVE data
        """
        containers = cve_data.get('containers', {})
        cna = containers.get('cna', {})
        
        # Basic information
        cve_id = cve_data.get('cveMetadata', {}).get('cveId', '')
        
        # Descriptions
        descriptions = cna.get('descriptions', [])
        description = ''
        summary = ''
        
        for desc in descriptions:
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                summary = description[:500] if description else ''
                break
        
        # Dates
        metadata = cve_data.get('cveMetadata', {})
        published_date = metadata.get('datePublished')
        modified_date = metadata.get('dateUpdated')
        
        if published_date:
            published_date = datetime.fromisoformat(published_date.replace('Z', '+00:00'))
        if modified_date:
            modified_date = datetime.fromisoformat(modified_date.replace('Z', '+00:00'))
        
        # References
        references = []
        for ref in cna.get('references', []):
            references.append({
                'url': ref.get('url'),
                'source': 'CVE_PROJECT',
                'tags': ref.get('tags', [])
            })
        
        # CWE IDs
        cwe_ids = []
        for problem_type in cna.get('problemTypes', []):
            for desc in problem_type.get('descriptions', []):
                cwe_id = desc.get('cweId')
                if cwe_id:
                    cwe_ids.append(cwe_id)
        
        # Vendor and product
        affected = cna.get('affected', [])
        vendor = None
        product = None
        
        if affected:
            first_affected = affected[0]
            vendor = first_affected.get('vendor')
            product = first_affected.get('product')
        
        # CVSS scores (may not be available in CVE Project API)
        metrics = cna.get('metrics', [])
        cvss_v3_score = None
        cvss_v3_vector = None
        cvss_v2_score = None
        cvss_v2_vector = None
        
        for metric in metrics:
            if 'cvssV3_1' in metric:
                cvss_v3_score = metric['cvssV3_1'].get('baseScore')
                cvss_v3_vector = metric['cvssV3_1'].get('vectorString')
            elif 'cvssV3_0' in metric:
                cvss_v3_score = metric['cvssV3_0'].get('baseScore')
                cvss_v3_vector = metric['cvssV3_0'].get('vectorString')
            elif 'cvssV2_0' in metric:
                cvss_v2_score = metric['cvssV2_0'].get('baseScore')
                cvss_v2_vector = metric['cvssV2_0'].get('vectorString')
        
        severity = self._determine_severity(cvss_v3_score or cvss_v2_score)
        
        return {
            'cve_id': cve_id,
            'summary': summary,
            'description': description,
            'cvss_v2_score': cvss_v2_score,
            'cvss_v3_score': cvss_v3_score,
            'cvss_v2_vector': cvss_v2_vector,
            'cvss_v3_vector': cvss_v3_vector,
            'severity': severity,
            'published_date': published_date,
            'modified_date': modified_date,
            'vendor': vendor,
            'product': product,
            'references': references,
            'nvd_url': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            'cwe_ids': cwe_ids,
            'source': 'CVE_PROJECT',
            'raw_data': cve_data
        }
    
    def _extract_published_date(self, cve_data: Dict) -> Optional[datetime]:
        """Extract published date from CVE data."""
        try:
            pub_date = cve_data.get('cveMetadata', {}).get('datePublished')
            if pub_date:
                return datetime.fromisoformat(pub_date.replace('Z', '+00:00'))
        except Exception:
            pass
        return None
    
    def _determine_severity(self, cvss_score: Optional[float]) -> str:
        """Determine severity level based on CVSS score."""
        if not cvss_score:
            return 'UNKNOWN'
        
        if cvss_score >= 9.0:
            return 'CRITICAL'
        elif cvss_score >= 7.0:
            return 'HIGH'
        elif cvss_score >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def save_cves_batch(self, cves_data: List[Dict]) -> Tuple[int, int]:
        """
        Save a batch of CVEs to database with upsert logic.
        
        Args:
            cves_data (List[Dict]): List of raw CVE data
            
        Returns:
            Tuple[int, int]: (new_count, updated_count)
        """
        new_count = 0
        updated_count = 0
        db = next(get_db())
        
        try:
            for cve_data in cves_data:
                try:
                    parsed_data = self.parse_cve_data(cve_data)
                    
                    # Check if CVE exists
                    existing_cve = db.query(CVE).filter(
                        CVE.cve_id == parsed_data['cve_id']
                    ).first()
                    
                    if existing_cve:
                        # Only update if source is not NVD (NVD has priority)
                        if existing_cve.source != 'NVD':
                            for key, value in parsed_data.items():
                                if hasattr(existing_cve, key) and value:
                                    setattr(existing_cve, key, value)
                            updated_count += 1
                    else:
                        # Create new CVE
                        new_cve = CVE(**parsed_data)
                        db.add(new_cve)
                        new_count += 1
                    
                except Exception as e:
                    logger.error(f"Error processing CVE: {str(e)}")
                    continue
            
            db.commit()
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error saving CVE batch: {str(e)}")
            raise
        finally:
            db.close()
        
        return new_count, updated_count
    
    def bulk_import_cves(self, start_year: int = 2021, end_year: int = None) -> Dict:
        """
        Bulk import all CVEs from start_year to end_year.
        
        Args:
            start_year (int): Starting year (default: 2021)
            end_year (int): Ending year (default: current year)
            
        Returns:
            Dict: Import statistics
        """
        if end_year is None:
            end_year = datetime.utcnow().year
        
        logger.info(f"Starting bulk import from CVE Project: {start_year} to {end_year}")
        
        total_stats = {
            'years_processed': 0,
            'total_cves_found': 0,
            'total_cves_saved': 0,
            'total_cves_updated': 0,
            'errors': [],
            'year_breakdown': {}
        }
        
        for year in range(start_year, end_year + 1):
            logger.info(f"Processing year {year}...")
            
            try:
                cves_data = self._fetch_cves_by_year(year)
                
                saved, updated = self.save_cves_batch(cves_data)
                
                year_stats = {
                    'year': year,
                    'cves_found': len(cves_data),
                    'cves_saved': saved,
                    'cves_updated': updated
                }
                
                total_stats['year_breakdown'][year] = year_stats
                total_stats['total_cves_found'] += len(cves_data)
                total_stats['total_cves_saved'] += saved
                total_stats['total_cves_updated'] += updated
                total_stats['years_processed'] += 1
                
            except Exception as e:
                error_msg = f"Error processing year {year}: {str(e)}"
                logger.error(error_msg)
                total_stats['errors'].append(error_msg)
        
        logger.info(f"CVE Project bulk import completed. Total: {total_stats['total_cves_saved']}")
        return total_stats

