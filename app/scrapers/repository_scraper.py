"""
Repository Scraper for Notable PoC Collections
Integrates with curated repositories to find validated CVE PoCs.
"""

import re
import json
import time
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse

from app.models import CVE, Exploit
from app.models.base import db
import logging

logger = logging.getLogger(__name__)

class RepositoryScraper:
    """Scraper for notable PoC repositories with high validation rates."""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CVEhive/1.0 (Security Research Tool)',
            'Accept': 'application/json'
        })
        
        # Repository configurations
        self.repositories = {
            'trickest': {
                'name': 'Trickest CVE',
                'api_base': 'https://api.github.com/repos/trickest/cve',
                'web_base': 'https://github.com/trickest/cve',
                'workflow': self._parse_trickest_workflow,
                'priority': 'high',
                'validation_confidence': 0.9
            },
            'poc_in_github': {
                'name': 'PoC-in-GitHub',
                'api_base': 'https://api.github.com/repos/nomi-sec/PoC-in-GitHub',
                'web_base': 'https://github.com/nomi-sec/PoC-in-GitHub',
                'workflow': self._parse_poc_in_github,
                'priority': 'medium',
                'validation_confidence': 0.7
            },
            'pocsuite3': {
                'name': 'Pocsuite3',
                'api_base': 'https://api.github.com/repos/knownsec/Pocsuite3',
                'web_base': 'https://github.com/knownsec/Pocsuite3',
                'workflow': self._parse_pocsuite3,
                'priority': 'medium',
                'validation_confidence': 0.8
            }
        }
    
    def sync_all_repositories(self) -> Dict[str, int]:
        """Sync all configured repositories and return statistics."""
        results = {}
        
        for repo_key, repo_config in self.repositories.items():
            try:
                logger.info(f"Syncing repository: {repo_config['name']}")
                count = self.sync_repository(repo_key)
                results[repo_key] = count
                
                # Rate limiting
                time.sleep(2)
                
            except Exception as e:
                logger.error(f"Error syncing {repo_config['name']}: {e}")
                results[repo_key] = 0
        
        return results
    
    def sync_repository(self, repo_key: str) -> int:
        """Sync a specific repository."""
        if repo_key not in self.repositories:
            raise ValueError(f"Unknown repository: {repo_key}")
        
        repo_config = self.repositories[repo_key]
        workflow_func = repo_config['workflow']
        
        try:
            new_exploits = workflow_func(repo_config)
            logger.info(f"Found {len(new_exploits)} new exploits from {repo_config['name']}")
            return len(new_exploits)
            
        except Exception as e:
            logger.error(f"Error in {repo_config['name']} workflow: {e}")
            return 0
    
    def _parse_trickest_workflow(self, repo_config: Dict) -> List[Dict]:
        """
        Parse Trickest CVE repository using their workflow methodology.
        Their workflow: Monitor CVE feeds -> Validate PoCs -> Curate collection
        """
        new_exploits = []
        
        try:
            # Get recent commits to see new CVEs added
            commits_url = f"{repo_config['api_base']}/commits"
            commits_response = self.session.get(commits_url, timeout=30)
            commits_response.raise_for_status()
            
            recent_commits = commits_response.json()
            
            # Process commits from last 7 days
            week_ago = datetime.now() - timedelta(days=7)
            
            for commit in recent_commits:
                commit_date = datetime.fromisoformat(
                    commit['commit']['committer']['date'].replace('Z', '+00:00')
                )
                
                if commit_date < week_ago:
                    continue
                
                # Get commit details to see files changed
                commit_url = f"{repo_config['api_base']}/commits/{commit['sha']}"
                commit_response = self.session.get(commit_url, timeout=30)
                commit_response.raise_for_status()
                
                commit_data = commit_response.json()
                
                # Look for new CVE files
                for file in commit_data.get('files', []):
                    if file['status'] == 'added' and file['filename'].endswith('.md'):
                        cve_data = self._parse_trickest_file(file, repo_config)
                        if cve_data:
                            new_exploits.append(cve_data)
                
                time.sleep(1)  # Rate limiting
        
        except Exception as e:
            logger.error(f"Error parsing Trickest workflow: {e}")
        
        # Save new exploits to database
        for exploit_data in new_exploits:
            self._save_exploit(exploit_data, repo_config)
        
        return new_exploits
    
    def _parse_trickest_file(self, file_info: Dict, repo_config: Dict) -> Optional[Dict]:
        """Parse a Trickest CVE file to extract PoC information."""
        try:
            # Extract CVE ID from filename
            cve_match = re.search(r'CVE-\d{4}-\d+', file_info['filename'])
            if not cve_match:
                return None
            
            cve_id = cve_match.group(0)
            
            # Get file content
            contents_url = f"{repo_config['api_base']}/contents/{file_info['filename']}"
            response = self.session.get(contents_url, timeout=30)
            response.raise_for_status()
            
            file_data = response.json()
            content = requests.get(file_data['download_url']).text
            
            # Parse markdown content for PoC links
            poc_links = self._extract_poc_links(content)
            
            if poc_links:
                return {
                    'cve_id': cve_id,
                    'title': f"Trickest curated PoCs for {cve_id}",
                    'source': 'trickest_cve',
                    'source_url': f"{repo_config['web_base']}/blob/main/{file_info['filename']}",
                    'poc_links': poc_links,
                    'validation_status': 'validated',  # Trickest pre-validates
                    'confidence_score': repo_config['validation_confidence'],
                    'description': f"Curated PoC collection from Trickest for {cve_id}",
                    'raw_content': content
                }
        
        except Exception as e:
            logger.error(f"Error parsing Trickest file {file_info['filename']}: {e}")
        
        return None
    
    def _parse_poc_in_github(self, repo_config: Dict) -> List[Dict]:
        """Parse PoC-in-GitHub repository for new PoCs."""
        new_exploits = []
        
        try:
            # This repository maintains a JSON file with PoC mappings
            json_url = f"{repo_config['api_base']}/contents/poc_list.json"
            response = self.session.get(json_url, timeout=30)
            
            if response.status_code == 200:
                file_data = response.json()
                content = requests.get(file_data['download_url']).text
                poc_data = json.loads(content)
                
                # Process recent entries
                for entry in poc_data[-50:]:  # Last 50 entries
                    if self._is_new_poc(entry['cve_id'], 'poc_in_github'):
                        exploit_data = {
                            'cve_id': entry['cve_id'],
                            'title': entry.get('title', f"PoC for {entry['cve_id']}"),
                            'source': 'poc_in_github',
                            'source_url': entry['url'],
                            'validation_status': 'pending',
                            'confidence_score': repo_config['validation_confidence'],
                            'description': entry.get('description', ''),
                            'author': entry.get('author', ''),
                            'programming_language': self._detect_language(entry['url'])
                        }
                        new_exploits.append(exploit_data)
        
        except Exception as e:
            logger.error(f"Error parsing PoC-in-GitHub: {e}")
        
        # Save new exploits
        for exploit_data in new_exploits:
            self._save_exploit(exploit_data, repo_config)
        
        return new_exploits
    
    def _parse_pocsuite3(self, repo_config: Dict) -> List[Dict]:
        """Parse Pocsuite3 repository for PoCs."""
        new_exploits = []
        
        try:
            # Get PoC directory structure
            pocs_url = f"{repo_config['api_base']}/contents/pocs"
            response = self.session.get(pocs_url, timeout=30)
            
            if response.status_code == 200:
                poc_files = response.json()
                
                for poc_file in poc_files:
                    if poc_file['name'].endswith('.py'):
                        # Extract CVE from filename or content
                        file_response = self.session.get(poc_file['download_url'], timeout=30)
                        content = file_response.text
                        
                        cve_matches = re.findall(r'CVE-\d{4}-\d+', content)
                        if cve_matches:
                            cve_id = cve_matches[0]
                            
                            if self._is_new_poc(cve_id, 'pocsuite3'):
                                exploit_data = {
                                    'cve_id': cve_id,
                                    'title': f"Pocsuite3 PoC for {cve_id}",
                                    'source': 'pocsuite3',
                                    'source_url': poc_file['html_url'],
                                    'validation_status': 'validated',  # Pocsuite3 includes tested PoCs
                                    'confidence_score': repo_config['validation_confidence'],
                                    'programming_language': 'python',
                                    'exploit_code': content,
                                    'file_path': poc_file['name']
                                }
                                new_exploits.append(exploit_data)
        
        except Exception as e:
            logger.error(f"Error parsing Pocsuite3: {e}")
        
        # Save new exploits
        for exploit_data in new_exploits:
            self._save_exploit(exploit_data, repo_config)
        
        return new_exploits
    
    def _extract_poc_links(self, content: str) -> List[str]:
        """Extract PoC links from markdown content."""
        links = []
        
        # Common PoC link patterns
        patterns = [
            r'https://github\.com/[^/]+/[^/\s\)]+',
            r'https://gitlab\.com/[^/]+/[^/\s\)]+',
            r'https://gist\.github\.com/[^\s\)]+',
            r'https://[^\s\)]*exploit[^\s\)]*',
            r'https://[^\s\)]*poc[^\s\)]*'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            links.extend(matches)
        
        return list(set(links))  # Remove duplicates
    
    def _detect_language(self, url: str) -> str:
        """Detect programming language from URL."""
        try:
            response = self.session.head(url, timeout=10)
            if 'github.com' in url:
                # Try to get language from GitHub API
                api_url = url.replace('github.com', 'api.github.com/repos')
                if '/blob/' in api_url:
                    api_url = api_url.split('/blob/')[0]
                
                lang_response = self.session.get(f"{api_url}/languages", timeout=10)
                if lang_response.status_code == 200:
                    languages = lang_response.json()
                    if languages:
                        return max(languages, key=languages.get).lower()
        
        except Exception:
            pass
        
        # Fallback to file extension detection
        if url.endswith('.py'):
            return 'python'
        elif url.endswith('.c') or url.endswith('.cpp'):
            return 'c'
        elif url.endswith('.java'):
            return 'java'
        elif url.endswith('.js'):
            return 'javascript'
        elif url.endswith('.rb'):
            return 'ruby'
        elif url.endswith('.php'):
            return 'php'
        
        return 'unknown'
    
    def _is_new_poc(self, cve_id: str, source: str) -> bool:
        """Check if PoC is already in database."""
        existing = Exploit.query.filter_by(cve_id=cve_id, source=source).first()
        return existing is None
    
    def _save_exploit(self, exploit_data: Dict, repo_config: Dict) -> bool:
        """Save exploit to database."""
        try:
            # Check if CVE exists
            cve = CVE.query.filter_by(cve_id=exploit_data['cve_id']).first()
            if not cve:
                logger.warning(f"CVE {exploit_data['cve_id']} not found in database")
                return False
            
            # Create exploit
            exploit = Exploit(
                cve_id=exploit_data['cve_id'],
                title=exploit_data['title'],
                source=exploit_data['source'],
                source_url=exploit_data['source_url'],
                validation_status=exploit_data.get('validation_status', 'pending'),
                confidence_score=exploit_data.get('confidence_score', 0.5),
                description=exploit_data.get('description', ''),
                author=exploit_data.get('author', ''),
                programming_language=exploit_data.get('programming_language', 'unknown'),
                exploit_code=exploit_data.get('exploit_code', ''),
                file_path=exploit_data.get('file_path', ''),
                raw_data=exploit_data
            )
            
            db.session.add(exploit)
            db.session.commit()
            
            # Update CVE exploit status
            cve.has_exploit = True
            cve.exploit_count = Exploit.query.filter_by(cve_id=cve_id).count()
            db.session.commit()
            
            logger.info(f"Saved exploit for {exploit_data['cve_id']} from {repo_config['name']}")
            return True
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error saving exploit for {exploit_data['cve_id']}: {e}")
            return False
    
    def get_repository_stats(self) -> Dict[str, Dict]:
        """Get statistics for each repository."""
        stats = {}
        
        for repo_key, repo_config in self.repositories.items():
            try:
                exploit_count = Exploit.query.filter_by(source=repo_key).count()
                validated_count = Exploit.query.filter_by(
                    source=repo_key, 
                    validation_status='validated'
                ).count()
                
                stats[repo_key] = {
                    'name': repo_config['name'],
                    'total_exploits': exploit_count,
                    'validated_exploits': validated_count,
                    'validation_rate': validated_count / exploit_count if exploit_count > 0 else 0,
                    'priority': repo_config['priority'],
                    'confidence': repo_config['validation_confidence']
                }
                
            except Exception as e:
                logger.error(f"Error getting stats for {repo_key}: {e}")
                stats[repo_key] = {
                    'name': repo_config['name'],
                    'error': str(e)
                }
        
        return stats

# Standalone functions for CLI integration
def sync_trickest():
    """Sync Trickest repository."""
    scraper = RepositoryScraper()
    return scraper.sync_repository('trickest')

def sync_all_notable_repositories():
    """Sync all notable repositories."""
    scraper = RepositoryScraper()
    return scraper.sync_all_repositories() 