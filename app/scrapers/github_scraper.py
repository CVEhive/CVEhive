import requests
import logging
import time
import re
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Set
from github import Github, GithubException
from app.config import Config
from app.models import Exploit
from app.models.base import get_db

class GitHubScraper:
    """Scraper for finding exploit code on GitHub."""
    
    def __init__(self, token: Optional[str] = None):
        self.token = token or Config.GITHUB_TOKEN
        self.github = Github(self.token) if self.token else Github()
        self.session = requests.Session()
        
        # Set headers for direct API calls
        headers = {
            'User-Agent': 'CVEhive/1.0 (Security Research Tool)',
            'Accept': 'application/vnd.github.v3+json'
        }
        if self.token:
            headers['Authorization'] = f'token {self.token}'
        
        self.session.headers.update(headers)
        
        # Keywords that indicate exploit code
        self.exploit_keywords = [
            'exploit', 'poc', 'proof of concept', 'vulnerability',
            'rce', 'remote code execution', 'privilege escalation',
            'buffer overflow', 'sql injection', 'xss', 'csrf',
            'bypass', 'payload', 'shellcode', 'metasploit'
        ]
        
        # File extensions that commonly contain exploit code
        self.exploit_extensions = [
            '.py', '.rb', '.pl', '.sh', '.c', '.cpp', '.java',
            '.js', '.php', '.go', '.rs', '.ps1', '.bat'
        ]
    
    def search_exploits_for_cve(self, cve_id: str, limit: int = 50) -> List[Dict]:
        """
        Search for exploit code related to a specific CVE.
        
        Args:
            cve_id (str): CVE identifier (e.g., CVE-2023-1234)
            limit (int): Maximum number of results to return
            
        Returns:
            List[Dict]: List of exploit repositories/files
        """
        exploits = []
        
        # Search queries to try
        search_queries = [
            f"{cve_id}",
            f"{cve_id} exploit",
            f"{cve_id} poc",
            f"{cve_id} proof of concept",
            f'"{cve_id}" exploit',
            f'"{cve_id}" vulnerability'
        ]
        
        seen_repos = set()
        
        for query in search_queries:
            if len(exploits) >= limit:
                break
                
            try:
                # Search repositories
                repos = self.github.search_repositories(
                    query=query,
                    sort='updated',
                    order='desc'
                )
                
                for repo in repos[:20]:  # Limit per query
                    if len(exploits) >= limit:
                        break
                    
                    if repo.full_name in seen_repos:
                        continue
                    
                    seen_repos.add(repo.full_name)
                    
                    # Check if repository looks like it contains exploits
                    if self._is_exploit_repository(repo, cve_id):
                        exploit_data = self._extract_repo_data(repo, cve_id)
                        if exploit_data:
                            exploits.append(exploit_data)
                
                # Search code files
                try:
                    code_results = self.github.search_code(
                        query=f"{cve_id} language:python OR language:c OR language:shell",
                        sort='indexed',
                        order='desc'
                    )
                    
                    for code in code_results[:10]:  # Limit code results
                        if len(exploits) >= limit:
                            break
                        
                        repo_name = code.repository.full_name
                        if repo_name not in seen_repos:
                            seen_repos.add(repo_name)
                            
                            if self._is_exploit_file(code, cve_id):
                                exploit_data = self._extract_file_data(code, cve_id)
                                if exploit_data:
                                    exploits.append(exploit_data)
                
                except GithubException as e:
                    logging.warning(f"Code search failed for {query}: {str(e)}")
                
                # Rate limiting
                time.sleep(1)
                
            except GithubException as e:
                logging.error(f"GitHub search failed for {query}: {str(e)}")
                continue
            except Exception as e:
                logging.error(f"Unexpected error searching GitHub for {query}: {str(e)}")
                continue
        
        logging.info(f"Found {len(exploits)} potential exploits for {cve_id}")
        return exploits
    
    def search_recent_exploits(self, days: int = 7, limit: int = 100) -> List[Dict]:
        """
        Search for recently published exploit code.
        
        Args:
            days (int): Number of days to look back
            limit (int): Maximum number of results to return
            
        Returns:
            List[Dict]: List of recent exploit repositories/files
        """
        exploits = []
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        # Search for repositories with exploit-related keywords
        search_queries = [
            "CVE-2024 exploit",
            "CVE-2023 exploit", 
            "poc vulnerability",
            "proof of concept exploit",
            "zero day exploit",
            "rce exploit",
            "privilege escalation"
        ]
        
        seen_repos = set()
        
        for query in search_queries:
            if len(exploits) >= limit:
                break
            
            try:
                repos = self.github.search_repositories(
                    query=f"{query} created:>{start_date.strftime('%Y-%m-%d')}",
                    sort='updated',
                    order='desc'
                )
                
                for repo in repos[:20]:
                    if len(exploits) >= limit:
                        break
                    
                    if repo.full_name in seen_repos:
                        continue
                    
                    seen_repos.add(repo.full_name)
                    
                    # Extract CVE IDs from repository
                    cve_ids = self._extract_cve_ids(repo.name + " " + (repo.description or ""))
                    
                    if cve_ids and self._is_exploit_repository(repo):
                        for cve_id in cve_ids:
                            exploit_data = self._extract_repo_data(repo, cve_id)
                            if exploit_data:
                                exploits.append(exploit_data)
                
                time.sleep(1)  # Rate limiting
                
            except GithubException as e:
                logging.error(f"GitHub search failed for {query}: {str(e)}")
                continue
        
        return exploits
    
    def _is_exploit_repository(self, repo, cve_id: str = None) -> bool:
        """Check if a repository likely contains exploit code."""
        # Check repository name and description
        text_to_check = (repo.name + " " + (repo.description or "")).lower()
        
        # Look for exploit keywords
        has_exploit_keywords = any(keyword in text_to_check for keyword in self.exploit_keywords)
        
        # Look for CVE pattern if specific CVE not provided
        has_cve_pattern = bool(re.search(r'cve-\d{4}-\d+', text_to_check))
        
        # Check if specific CVE is mentioned
        has_target_cve = cve_id and cve_id.lower() in text_to_check
        
        return has_exploit_keywords and (has_cve_pattern or has_target_cve)
    
    def _is_exploit_file(self, code_file, cve_id: str) -> bool:
        """Check if a code file likely contains exploit code."""
        filename = code_file.name.lower()
        
        # Check file extension
        has_exploit_extension = any(filename.endswith(ext) for ext in self.exploit_extensions)
        
        # Check filename for exploit keywords
        has_exploit_keywords = any(keyword in filename for keyword in self.exploit_keywords)
        
        return has_exploit_extension and (has_exploit_keywords or cve_id.lower() in filename)
    
    def _extract_repo_data(self, repo, cve_id: str) -> Optional[Dict]:
        """Extract exploit data from a repository."""
        try:
            # Get repository statistics
            stars = repo.stargazers_count
            forks = repo.forks_count
            
            # Calculate quality score based on various factors
            quality_score = self._calculate_quality_score(repo, stars, forks)
            
            # Try to find main exploit files
            exploit_files = self._find_exploit_files(repo, cve_id)
            
            return {
                'cve_id': cve_id,
                'source': 'github',
                'title': repo.name,
                'description': repo.description or '',
                'url': repo.html_url,
                'author': repo.owner.login,
                'published_date': repo.created_at,
                'updated_date': repo.updated_at,
                'stars': stars,
                'forks': forks,
                'language': repo.language,
                'quality_score': quality_score,
                'exploit_files': exploit_files,
                'repository_data': {
                    'size': repo.size,
                    'open_issues': repo.open_issues_count,
                    'has_wiki': repo.has_wiki,
                    'has_pages': repo.has_pages,
                    'archived': repo.archived,
                    'disabled': repo.disabled
                }
            }
            
        except Exception as e:
            logging.error(f"Error extracting repository data: {str(e)}")
            return None
    
    def _extract_file_data(self, code_file, cve_id: str) -> Optional[Dict]:
        """Extract exploit data from a code file."""
        try:
            repo = code_file.repository
            
            return {
                'cve_id': cve_id,
                'source': 'github',
                'title': f"{repo.name}/{code_file.name}",
                'description': f"Exploit code in {code_file.name}",
                'url': code_file.html_url,
                'author': repo.owner.login,
                'published_date': repo.created_at,
                'updated_date': repo.updated_at,
                'stars': repo.stargazers_count,
                'forks': repo.forks_count,
                'language': self._detect_language_from_extension(code_file.name),
                'quality_score': self._calculate_quality_score(repo, repo.stargazers_count, repo.forks_count),
                'exploit_files': [code_file.name],
                'file_path': code_file.path
            }
            
        except Exception as e:
            logging.error(f"Error extracting file data: {str(e)}")
            return None
    
    def _find_exploit_files(self, repo, cve_id: str) -> List[str]:
        """Find potential exploit files in a repository."""
        exploit_files = []
        
        try:
            contents = repo.get_contents("")
            
            for content in contents:
                if content.type == "file":
                    filename = content.name.lower()
                    
                    # Check if file looks like an exploit
                    if (any(filename.endswith(ext) for ext in self.exploit_extensions) and
                        (any(keyword in filename for keyword in self.exploit_keywords) or
                         cve_id.lower() in filename)):
                        exploit_files.append(content.name)
                
                elif content.type == "dir" and len(exploit_files) < 10:
                    # Recursively check subdirectories (limited depth)
                    try:
                        subcontents = repo.get_contents(content.path)
                        for subcontent in subcontents:
                            if subcontent.type == "file":
                                filename = subcontent.name.lower()
                                if (any(filename.endswith(ext) for ext in self.exploit_extensions) and
                                    (any(keyword in filename for keyword in self.exploit_keywords) or
                                     cve_id.lower() in filename)):
                                    exploit_files.append(f"{content.name}/{subcontent.name}")
                    except:
                        pass  # Skip if can't access subdirectory
        
        except Exception as e:
            logging.warning(f"Error finding exploit files in {repo.name}: {str(e)}")
        
        return exploit_files[:10]  # Limit number of files
    
    def _calculate_quality_score(self, repo, stars: int, forks: int) -> float:
        """Calculate a quality score for the exploit based on repository metrics."""
        score = 0.0
        
        # Stars contribute to quality
        score += min(stars * 0.1, 5.0)
        
        # Forks contribute to quality
        score += min(forks * 0.2, 3.0)
        
        # Recent activity is good
        if repo.updated_at and (datetime.utcnow() - repo.updated_at).days < 30:
            score += 1.0
        
        # Having a description is good
        if repo.description:
            score += 0.5
        
        # Having a README is good
        try:
            repo.get_readme()
            score += 0.5
        except:
            pass
        
        # Not being archived is good
        if not repo.archived:
            score += 0.5
        
        return min(score, 10.0)  # Cap at 10
    
    def _detect_language_from_extension(self, filename: str) -> str:
        """Detect programming language from file extension."""
        ext = filename.lower().split('.')[-1] if '.' in filename else ''
        
        language_map = {
            'py': 'Python',
            'rb': 'Ruby', 
            'pl': 'Perl',
            'sh': 'Shell',
            'c': 'C',
            'cpp': 'C++',
            'cc': 'C++',
            'java': 'Java',
            'js': 'JavaScript',
            'php': 'PHP',
            'go': 'Go',
            'rs': 'Rust',
            'ps1': 'PowerShell',
            'bat': 'Batch'
        }
        
        return language_map.get(ext, 'Unknown')
    
    def _extract_cve_ids(self, text: str) -> Set[str]:
        """Extract CVE IDs from text."""
        cve_pattern = r'CVE-\d{4}-\d+'
        matches = re.findall(cve_pattern, text, re.IGNORECASE)
        return set(match.upper() for match in matches)
    
    def save_exploits_to_database(self, exploits_data: List[Dict]) -> int:
        """
        Save exploits to the database.
        
        Args:
            exploits_data (List[Dict]): List of exploit data
            
        Returns:
            int: Number of exploits saved
        """
        saved_count = 0
        
        with get_db() as db:
            for exploit_data in exploits_data:
                try:
                    # Check if exploit already exists
                    existing = db.query(Exploit).filter(
                        Exploit.url == exploit_data['url']
                    ).first()
                    
                    if existing:
                        # Update existing exploit
                        for key, value in exploit_data.items():
                            if hasattr(existing, key) and key not in ['id', 'created_at']:
                                setattr(existing, key, value)
                        existing.updated_at = datetime.utcnow()
                    else:
                        # Create new exploit
                        exploit = Exploit(**exploit_data)
                        db.add(exploit)
                        saved_count += 1
                    
                    db.commit()
                    
                except Exception as e:
                    logging.error(f"Error saving exploit {exploit_data.get('url', 'unknown')}: {str(e)}")
                    db.rollback()
                    continue
        
        logging.info(f"Saved {saved_count} new exploits to database")
        return saved_count 