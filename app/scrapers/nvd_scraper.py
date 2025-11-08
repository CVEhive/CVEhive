import requests
import logging
import time
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
from app.config import Config
from app.models import CVE
from app.models.base import get_db

class NVDScraper:
    """Scraper for the National Vulnerability Database (NVD)."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or Config.NVD_API_KEY
        self.base_url = Config.NVD_BASE_URL
        self.session = requests.Session()
        
        # Set headers
        headers = {
            'User-Agent': 'CVEhive/1.0 (Security Research Tool)',
        }
        if self.api_key:
            headers['apiKey'] = self.api_key
        
        self.session.headers.update(headers)
        
    def fetch_recent_cves(self, days: int = 7) -> List[Dict]:
        """
        Fetch CVEs published in the last N days.
        
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
        Fetch CVEs within a date range.
        
        Args:
            start_date (datetime): Start date
            end_date (datetime): End date
            
        Returns:
            List[Dict]: List of CVE data
        """
        cves = []
        start_index = 0
        results_per_page = 2000  # NVD API maximum
        
        while True:
            params = {
                'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                'startIndex': start_index,
                'resultsPerPage': results_per_page
            }
            
            try:
                response = self.session.get(self.base_url, params=params, timeout=30)
                response.raise_for_status()
                
                data = response.json()
                
                if 'vulnerabilities' not in data:
                    logging.warning("No vulnerabilities found in NVD response")
                    break
                
                batch_cves = data['vulnerabilities']
                cves.extend(batch_cves)
                
                # Check if we've got all results
                total_results = data.get('totalResults', 0)
                if start_index + len(batch_cves) >= total_results:
                    break
                
                start_index += len(batch_cves)
                
                # Rate limiting - NVD allows 50 requests per 30 seconds without API key
                if not self.api_key:
                    time.sleep(0.6)  # Conservative rate limiting
                
                logging.info(f"Fetched {len(cves)} CVEs so far...")
                
            except requests.exceptions.RequestException as e:
                logging.error(f"Error fetching CVEs from NVD: {str(e)}")
                break
            except Exception as e:
                logging.error(f"Unexpected error fetching CVEs: {str(e)}")
                break
        
        logging.info(f"Fetched {len(cves)} CVEs from NVD")
        return cves
    
    def fetch_cve_by_id(self, cve_id: str) -> Optional[Dict]:
        """
        Fetch a specific CVE by ID.
        
        Args:
            cve_id (str): CVE identifier (e.g., CVE-2023-1234)
            
        Returns:
            Optional[Dict]: CVE data or None if not found
        """
        params = {'cveId': cve_id}
        
        try:
            response = self.session.get(self.base_url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('vulnerabilities'):
                return data['vulnerabilities'][0]
            
            return None
            
        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching CVE {cve_id}: {str(e)}")
            return None
    
    def parse_cve_data(self, cve_data: Dict) -> Dict:
        """
        Parse NVD CVE data into our format.
        
        Args:
            cve_data (Dict): Raw CVE data from NVD
            
        Returns:
            Dict: Parsed CVE data
        """
        # Ensure cve_data is a dictionary
        if not isinstance(cve_data, dict):
            logging.warning(f"Expected dict but got {type(cve_data)}: {str(cve_data)[:100]}")
            raise ValueError(f"cve_data must be a dictionary, got {type(cve_data)}")
        
        cve = cve_data.get('cve', {})
        
        # Basic information
        cve_id = cve.get('id', '')
        
        # Descriptions
        descriptions = cve.get('descriptions', [])
        description = ''
        summary = ''
        
        for desc in descriptions:
            # Ensure desc is a dictionary
            if isinstance(desc, dict) and desc.get('lang') == 'en':
                description = desc.get('value', '')
                summary = description[:500] if description else ''
                break
        
        # CVSS scores
        metrics = cve_data.get('metrics', {})
        cvss_v3_score = None
        cvss_v3_vector = None
        cvss_v2_score = None
        cvss_v2_vector = None
        
        # CVSS v3
        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
            v3_data = metrics['cvssMetricV31'][0].get('cvssData', {})
            cvss_v3_score = v3_data.get('baseScore')
            cvss_v3_vector = v3_data.get('vectorString')
        elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
            v3_data = metrics['cvssMetricV30'][0].get('cvssData', {})
            cvss_v3_score = v3_data.get('baseScore')
            cvss_v3_vector = v3_data.get('vectorString')
        
        # CVSS v2
        if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
            v2_data = metrics['cvssMetricV2'][0].get('cvssData', {})
            cvss_v2_score = v2_data.get('baseScore')
            cvss_v2_vector = v2_data.get('vectorString')
        
        # Determine severity
        severity = self._determine_severity(cvss_v3_score or cvss_v2_score)
        
        # Dates
        published_date = cve.get('published')
        modified_date = cve.get('lastModified')
        
        if published_date:
            published_date = datetime.fromisoformat(published_date.replace('Z', '+00:00'))
        if modified_date:
            modified_date = datetime.fromisoformat(modified_date.replace('Z', '+00:00'))
        
        # References
        references = []
        for ref in cve.get('references', []):
            # Ensure ref is a dictionary
            if isinstance(ref, dict):
                references.append({
                    'url': ref.get('url'),
                    'source': ref.get('source'),
                    'tags': ref.get('tags', [])
                })
        
        # CWE IDs
        cwe_ids = []
        for weakness in cve.get('weaknesses', []):
            if isinstance(weakness, dict):
                descriptions = weakness.get('description', [])
                if isinstance(descriptions, list):
                    for desc in descriptions:
                        if isinstance(desc, dict) and desc.get('lang') == 'en':
                            cwe_list = desc.get('value', [])
                            if isinstance(cwe_list, list):
                                cwe_ids.extend([
                                    cwe.get('value') for cwe in cwe_list 
                                    if isinstance(cwe, dict) and cwe.get('value')
                                ])
        
        # Vendor and product information
        configurations = cve_data.get('configurations', [])
        vendor = None
        product = None
        
        if configurations:
            for config in configurations:
                if isinstance(config, dict):
                    for node in config.get('nodes', []):
                        if isinstance(node, dict):
                            for cpe_match in node.get('cpeMatch', []):
                                if isinstance(cpe_match, dict):
                                    cpe_name = cpe_match.get('criteria', '')
                                    if cpe_name and cpe_name.startswith('cpe:2.3:'):
                                        parts = cpe_name.split(':')
                                        if len(parts) >= 5:
                                            vendor = vendor or parts[3]
                                            product = product or parts[4]
        
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
            'source': 'NVD',
            'raw_data': cve_data
        }
    
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
    
    def save_cves_to_database(self, cves_data: List[Dict]) -> int:
        """
        Save CVEs to database.
        
        Args:
            cves_data (List[Dict]): List of parsed CVE data
            
        Returns:
            int: Number of CVEs saved
        """
        saved_count = 0
        db = next(get_db())
        
        try:
            for cve_data in cves_data:
                parsed_data = self.parse_cve_data(cve_data)
                
                # Check if CVE already exists
                existing_cve = db.query(CVE).filter(CVE.cve_id == parsed_data['cve_id']).first()
                
                if existing_cve:
                    # Update existing CVE
                    for key, value in parsed_data.items():
                        if hasattr(existing_cve, key):
                            setattr(existing_cve, key, value)
                    logging.debug(f"Updated CVE {parsed_data['cve_id']}")
                else:
                    # Create new CVE
                    new_cve = CVE(**parsed_data)
                    db.add(new_cve)
                    saved_count += 1
                    logging.debug(f"Added CVE {parsed_data['cve_id']}")
            
            db.commit()
            logging.info(f"Saved {saved_count} new CVEs to database")
            
        except Exception as e:
            db.rollback()
            logging.error(f"Error saving CVEs to database: {str(e)}")
            raise
        finally:
            db.close()
        
        return saved_count
    
    # NEW METHODS FOR BULK IMPORT AND MONITORING
    
    def bulk_import_cves(self, start_year: int = 2021, end_year: int = None) -> Dict:
        """
        Bulk import all CVEs from start_year to end_year.
        This is optimized for initial database population.
        
        Args:
            start_year (int): Starting year (default: 2021)
            end_year (int): Ending year (default: current year)
            
        Returns:
            Dict: Import statistics
        """
        if end_year is None:
            end_year = datetime.utcnow().year
        
        logging.info(f"Starting bulk import of CVEs from {start_year} to {end_year}")
        
        total_stats = {
            'years_processed': 0,
            'total_cves_found': 0,
            'total_cves_saved': 0,
            'total_cves_updated': 0,
            'errors': [],
            'year_breakdown': {}
        }
        
        for year in range(start_year, end_year + 1):
            logging.info(f"Processing year {year}...")
            
            try:
                year_stats = self._import_cves_by_year(year)
                total_stats['year_breakdown'][year] = year_stats
                total_stats['total_cves_found'] += year_stats['cves_found']
                total_stats['total_cves_saved'] += year_stats['cves_saved']
                total_stats['total_cves_updated'] += year_stats['cves_updated']
                total_stats['years_processed'] += 1
                
            except Exception as e:
                error_msg = f"Error processing year {year}: {str(e)}"
                logging.error(error_msg)
                total_stats['errors'].append(error_msg)
        
        logging.info(f"Bulk import completed. Total CVEs: {total_stats['total_cves_saved']}")
        return total_stats
    
    def _import_cves_by_year(self, year: int) -> Dict:
        """
        Import all CVEs for a specific year.
        
        Args:
            year (int): Year to import
            
        Returns:
            Dict: Import statistics for the year
        """
        start_date = datetime(year, 1, 1)
        end_date = datetime(year, 12, 31, 23, 59, 59)
        
        # If current year, use current date as end
        if year == datetime.utcnow().year:
            end_date = datetime.utcnow()
        
        stats = {
            'year': year,
            'cves_found': 0,
            'cves_saved': 0,
            'cves_updated': 0,
            'batches_processed': 0
        }
        
        # Split year into monthly batches to avoid timeout/memory issues
        months = []
        for month in range(1, 13):
            month_start = datetime(year, month, 1)
            
            # Calculate month end
            if month == 12:
                month_end = datetime(year, 12, 31, 23, 59, 59)
            else:
                month_end = datetime(year, month + 1, 1) - timedelta(seconds=1)
            
            # Don't process future months
            if month_start > datetime.utcnow():
                break
            
            # Cap at current time for current month
            if month_end > datetime.utcnow():
                month_end = datetime.utcnow()
            
            months.append((month_start, month_end))
        
        # Process each month
        for month_start, month_end in months:
            logging.info(f"Fetching CVEs for {month_start.strftime('%Y-%m')}")
            
            try:
                cves_data = self.fetch_cves_by_date_range(month_start, month_end)
                stats['cves_found'] += len(cves_data)
                
                # Save in smaller batches to avoid memory issues
                batch_size = 100
                for i in range(0, len(cves_data), batch_size):
                    batch = cves_data[i:i + batch_size]
                    saved, updated = self.save_cves_batch(batch)
                    stats['cves_saved'] += saved
                    stats['cves_updated'] += updated
                    stats['batches_processed'] += 1
                    
                    logging.info(
                        f"Processed batch {stats['batches_processed']}: "
                        f"+{saved} new, ~{updated} updated"
                    )
                
            except Exception as e:
                logging.error(f"Error processing month {month_start.strftime('%Y-%m')}: {str(e)}")
                continue
        
        return stats
    
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
                    # Skip if not a dictionary (shouldn't happen, but safety check)
                    if not isinstance(cve_data, dict):
                        logging.warning(f"Skipping non-dict CVE data: {type(cve_data)}")
                        continue
                    
                    parsed_data = self.parse_cve_data(cve_data)
                    
                    # Check if CVE exists
                    existing_cve = db.query(CVE).filter(
                        CVE.cve_id == parsed_data['cve_id']
                    ).first()
                    
                    if existing_cve:
                        # Update if modified date is newer
                        if (parsed_data.get('modified_date') and 
                            (not existing_cve.modified_date or 
                             parsed_data['modified_date'] > existing_cve.modified_date)):
                            
                            for key, value in parsed_data.items():
                                if hasattr(existing_cve, key):
                                    setattr(existing_cve, key, value)
                            updated_count += 1
                    else:
                        # Create new CVE
                        new_cve = CVE(**parsed_data)
                        db.add(new_cve)
                        new_count += 1
                    
                except Exception as e:
                    logging.error(f"Error processing CVE: {str(e)}")
                    continue
            
            db.commit()
            
        except Exception as e:
            db.rollback()
            logging.error(f"Error saving CVE batch: {str(e)}")
            raise
        finally:
            db.close()
        
        return new_count, updated_count 