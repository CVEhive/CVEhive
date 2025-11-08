"""
AI Analyzer Layer
Uses AI model to intelligently interact with GitHub MCP server
"""

import os
import logging
import json
from typing import List, Dict, Optional
from app.analyzers.github_mcp_client import GitHubMCPClient

logger = logging.getLogger(__name__)


class AIAnalyzer:
    """
    AI-powered analyzer that uses GitHub MCP server intelligently.
    
    This layer uses an AI model to:
    - Generate intelligent search queries for CVEs
    - Analyze repository relevance
    - Extract execution instructions from READMEs
    - Rank and filter results
    """
    
    def __init__(self, mcp_client: GitHubMCPClient, ai_model=None):
        """
        Initialize AI analyzer.
        
        Args:
            mcp_client: GitHub MCP client instance
            ai_model: AI model instance (optional, will initialize if not provided)
        """
        self.mcp_client = mcp_client
        self.ai_model = ai_model
        self.tokenizer = None
        self.model_provider = os.getenv("AI_MODEL_PROVIDER", "huggingface")
        self._initialize_ai_model()
    
    def _initialize_ai_model(self):
        """Initialize AI model based on environment configuration."""
        if self.ai_model:
            return  # Already initialized
        
        try:
            if self.model_provider == "huggingface":
                self._initialize_huggingface()
            elif self.model_provider == "openai":
                self._initialize_openai()
            elif self.model_provider == "anthropic":
                self._initialize_anthropic()
            else:
                logger.warning(f"Unknown AI model provider: {self.model_provider}")
                logger.info("AI features will be limited. Set AI_MODEL_PROVIDER environment variable.")
        except Exception as e:
            logger.warning(f"Failed to initialize AI model: {str(e)}")
            logger.info("AI features will be limited. Some operations may fall back to simple heuristics.")
    
    def _initialize_huggingface(self):
        """Initialize Hugging Face model."""
        try:
            from transformers import AutoTokenizer, AutoModelForCausalLM
            import torch
            
            model_name = os.getenv("AI_MODEL_NAME", "deepseek-ai/deepseek-coder-6.7b-instruct")
            logger.info(f"Loading Hugging Face model: {model_name}")
            
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.model = AutoModelForCausalLM.from_pretrained(
                model_name,
                device_map="auto",
                torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
                low_cpu_mem_usage=True
            )
            self.model_provider = "huggingface"
            logger.info("✅ Hugging Face model loaded")
        except ImportError:
            logger.warning("transformers not installed. Install with: pip install transformers torch")
        except Exception as e:
            logger.error(f"Failed to load Hugging Face model: {str(e)}")
    
    def _initialize_openai(self):
        """Initialize OpenAI API."""
        try:
            import openai
            openai.api_key = os.getenv("OPENAI_API_KEY")
            if not openai.api_key:
                raise ValueError("OPENAI_API_KEY not set")
            self.model = os.getenv("OPENAI_MODEL", "gpt-4")
            self.model_provider = "openai"
            logger.info(f"✅ OpenAI API configured (model: {self.model})")
        except ImportError:
            logger.warning("openai not installed. Install with: pip install openai")
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI: {str(e)}")
    
    def _initialize_anthropic(self):
        """Initialize Anthropic Claude API."""
        try:
            import anthropic
            api_key = os.getenv("ANTHROPIC_API_KEY")
            if not api_key:
                raise ValueError("ANTHROPIC_API_KEY not set")
            self.client = anthropic.Anthropic(api_key=api_key)
            self.model = os.getenv("ANTHROPIC_MODEL", "claude-3-opus-20240229")
            self.model_provider = "anthropic"
            logger.info(f"✅ Anthropic API configured (model: {self.model})")
        except ImportError:
            logger.warning("anthropic not installed. Install with: pip install anthropic")
        except Exception as e:
            logger.error(f"Failed to initialize Anthropic: {str(e)}")
    
    async def search_repositories_for_cve(self, cve_id: str, limit: int = 20) -> List[Dict]:
        """
        Use AI to generate intelligent search queries, then use MCP server.
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2024-12345)
            limit: Maximum repositories to return
            
        Returns:
            List of repository dictionaries
        """
        logger.info(f"🔍 AI-powered search for {cve_id}")
        
        # Step 1: AI generates intelligent search queries
        queries = await self._generate_search_queries(cve_id)
        logger.info(f"Generated {len(queries)} search queries")
        
        # Step 2: Search using MCP server for each query
        all_repos = []
        seen_repos = set()
        
        for query in queries:
            try:
                result = await self.mcp_client.search_repositories(
                    query=query,
                    per_page=min(limit, 30),  # Get more per query
                    sort="updated",
                    order="desc"
                )
                
                repos = result.get("items", [])
                for repo in repos:
                    repo_id = repo.get("id")
                    if repo_id and repo_id not in seen_repos:
                        seen_repos.add(repo_id)
                        all_repos.append(repo)
                        
            except Exception as e:
                logger.error(f"Error searching with query '{query}': {str(e)}")
                continue
        
        # Step 3: AI ranks and filters results
        ranked_repos = await self._rank_repositories_with_ai(all_repos, cve_id)
        
        logger.info(f"Found {len(ranked_repos)} relevant repositories")
        return ranked_repos[:limit]
    
    async def _generate_search_queries(self, cve_id: str) -> List[str]:
        """Use AI to generate intelligent GitHub search queries."""
        prompt = f"""Generate 5 GitHub search queries to find exploit code, PoC (proof-of-concept), or vulnerability information for {cve_id}.

Consider these patterns:
- CVE ID variations: "{cve_id}", "{cve_id.replace('-', ' ')}"
- Exploit keywords: "exploit", "poc", "proof of concept", "vulnerability"
- Code patterns: "CVE-{cve_id.split('-')[-1]}", "{cve_id.lower()}"

Return ONLY the search queries, one per line, without numbering or explanations.
Each query should be optimized for GitHub's search syntax."""

        try:
            queries_text = self._generate_with_ai(prompt)
            queries = [q.strip() for q in queries_text.split('\n') if q.strip()][:5]
            
            # Fallback queries if AI fails
            if not queries or len(queries) < 3:
                queries = [
                    f"{cve_id}",
                    f"{cve_id} exploit",
                    f"{cve_id} poc",
                    f"{cve_id} proof of concept",
                    f"exploit {cve_id}"
                ]
            
            return queries[:5]
        except Exception as e:
            logger.warning(f"AI query generation failed: {str(e)}, using fallback queries")
            return [
                f"{cve_id}",
                f"{cve_id} exploit",
                f"{cve_id} poc"
            ]
    
    async def analyze_repository_with_ai(self, repo_url: str, cve_id: str) -> Dict:
        """
        Use AI to analyze repository for CVE relevance.
        
        Args:
            repo_url: GitHub repository URL
            cve_id: CVE identifier
            
        Returns:
            Analysis results dictionary
        """
        logger.info(f"🤖 AI analyzing repository: {repo_url}")
        
        try:
            # Parse repo URL
            owner, repo = self.mcp_client._parse_repo_url(repo_url)
            
            # Get repository details via MCP
            repo_data = await self.mcp_client.get_repository(owner, repo)
            if not repo_data:
                return {
                    'repository_url': repo_url,
                    'cve_id': cve_id,
                    'relevance_score': 0,
                    'analysis': 'Repository not found',
                    'exploit_files_found': []
                }
            
            # Get README if available
            readme_content = None
            try:
                readme_files = await self.mcp_client.list_repository_files(owner, repo, "")
                readme_path = next((f["path"] for f in readme_files if "readme" in f["path"].lower()), None)
                if readme_path:
                    readme_data = await self.mcp_client.get_file_contents(owner, repo, readme_path)
                    if readme_data:
                        import base64
                        content = readme_data.get("content", "")
                        if readme_data.get("encoding") == "base64":
                            readme_content = base64.b64decode(content).decode('utf-8', errors='ignore')
                        else:
                            readme_content = content
            except Exception as e:
                logger.debug(f"Could not fetch README: {str(e)}")
            
            # Use AI to analyze
            analysis = await self._analyze_repository_with_ai(
                repo_data, readme_content, cve_id
            )
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing repository: {str(e)}")
            return {
                'repository_url': repo_url,
                'cve_id': cve_id,
                'relevance_score': 0,
                'error': str(e)
            }
    
    async def _analyze_repository_with_ai(self, repo_data: Dict, 
                                         readme_content: Optional[str],
                                         cve_id: str) -> Dict:
        """Use AI to analyze repository data."""
        description = repo_data.get("description", "")
        name = repo_data.get("name", "")
        full_name = repo_data.get("full_name", "")
        
        prompt = f"""Analyze this GitHub repository for CVE {cve_id}:

Repository: {full_name}
Name: {name}
Description: {description}
README (first 500 chars): {readme_content[:500] if readme_content else "N/A"}

Determine:
1. Relevance score (0-100) - How likely is this repository to contain exploit code for {cve_id}?
2. Analysis - Brief explanation of why this repository is relevant or not
3. Exploit files likely found - List potential exploit file names/paths

Return JSON format:
{{
    "relevance_score": <number>,
    "analysis": "<explanation>",
    "exploit_files_found": ["file1.py", "file2.sh"]
}}"""

        try:
            response = self._generate_with_ai(prompt)
            
            # Try to extract JSON from response
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                analysis = json.loads(json_match.group())
            else:
                # Fallback: simple heuristic scoring
                analysis = self._heuristic_analysis(repo_data, readme_content, cve_id)
            
            return {
                'repository_url': repo_data.get("html_url", ""),
                'cve_id': cve_id,
                'relevance_score': analysis.get("relevance_score", 0),
                'analysis': analysis.get("analysis", ""),
                'exploit_files_found': analysis.get("exploit_files_found", []),
                'readme_content': readme_content
            }
            
        except Exception as e:
            logger.warning(f"AI analysis failed: {str(e)}, using heuristic")
            return self._heuristic_analysis(repo_data, readme_content, cve_id)
    
    def _heuristic_analysis(self, repo_data: Dict, readme_content: Optional[str],
                           cve_id: str) -> Dict:
        """Fallback heuristic analysis when AI is unavailable."""
        score = 0
        name = repo_data.get("name", "").lower()
        description = repo_data.get("description", "").lower()
        readme = (readme_content or "").lower()
        
        # Check for CVE ID
        if cve_id.lower() in name or cve_id.lower() in description:
            score += 40
        
        # Check for exploit keywords
        exploit_keywords = ["exploit", "poc", "proof", "vulnerability", "cve"]
        for keyword in exploit_keywords:
            if keyword in name or keyword in description:
                score += 10
        
        # Check README
        if readme_content:
            if cve_id.lower() in readme:
                score += 20
            if any(kw in readme for kw in exploit_keywords):
                score += 10
        
        return {
            'repository_url': repo_data.get("html_url", ""),
            'cve_id': cve_id,
            'relevance_score': min(score, 100),
            'analysis': f"Heuristic analysis: Found CVE references and exploit keywords",
            'exploit_files_found': [],
            'readme_content': readme_content
        }
    
    async def _rank_repositories_with_ai(self, repos: List[Dict], cve_id: str) -> List[Dict]:
        """Use AI to rank repositories by relevance."""
        if not repos:
            return []
        
        # Simple ranking: sort by stars and name/description relevance
        # In production, you'd use AI to rank more intelligently
        scored_repos = []
        for repo in repos:
            score = repo.get("stargazers_count", 0)
            name_desc = f"{repo.get('name', '')} {repo.get('description', '')}".lower()
            if cve_id.lower() in name_desc:
                score += 1000
            scored_repos.append((score, repo))
        
        scored_repos.sort(key=lambda x: x[0], reverse=True)
        return [repo for _, repo in scored_repos]
    
    async def get_repository_files(self, repo_url: str, cve_id: str) -> List[Dict]:
        """
        Use AI to identify exploit-related files, then fetch via MCP.
        
        Args:
            repo_url: GitHub repository URL
            cve_id: CVE identifier
            
        Returns:
            List of file information dictionaries
        """
        try:
            owner, repo = self.mcp_client._parse_repo_url(repo_url)
            
            # Get all files
            all_files = await self.mcp_client.list_repository_files(owner, repo, "")
            
            # Use AI to identify exploit-related files
            exploit_files = await self._identify_exploit_files(all_files, cve_id)
            
            # Fetch file contents
            files_with_content = []
            for file_info in exploit_files[:10]:  # Limit to 10 files
                try:
                    path = file_info.get("path", "")
                    file_data = await self.mcp_client.get_file_contents(owner, repo, path)
                    if file_data:
                        import base64
                        content = file_data.get("content", "")
                        if file_data.get("encoding") == "base64":
                            content = base64.b64decode(content).decode('utf-8', errors='ignore')
                        
                        files_with_content.append({
                            "name": file_info.get("name", ""),
                            "path": path,
                            "language": file_info.get("language", ""),
                            "content": content,
                            "url": file_data.get("html_url", "")
                        })
                except Exception as e:
                    logger.debug(f"Could not fetch file {path}: {str(e)}")
                    continue
            
            return files_with_content
            
        except Exception as e:
            logger.error(f"Error getting repository files: {str(e)}")
            return []
    
    async def _identify_exploit_files(self, files: List[Dict], cve_id: str) -> List[Dict]:
        """Use AI to identify exploit-related files."""
        # Simple heuristic: look for exploit-related keywords in filenames
        exploit_keywords = ["exploit", "poc", "proof", "vulnerability", "cve", "payload"]
        exploit_files = []
        
        for file_info in files:
            name = file_info.get("name", "").lower()
            path = file_info.get("path", "").lower()
            
            if any(keyword in name or keyword in path for keyword in exploit_keywords):
                exploit_files.append(file_info)
            elif cve_id.lower() in name or cve_id.lower() in path:
                exploit_files.append(file_info)
        
        return exploit_files
    
    async def extract_readme_instructions(self, repo_url: str, 
                                         file_path: str) -> Optional[str]:
        """
        Use AI to extract execution instructions from README.
        
        Args:
            repo_url: GitHub repository URL
            file_path: Path to exploit file
            
        Returns:
            Extracted execution instructions
        """
        try:
            owner, repo = self.mcp_client._parse_repo_url(repo_url)
            
            # Get README
            readme_files = await self.mcp_client.list_repository_files(owner, repo, "")
            readme_path = next((f["path"] for f in readme_files if "readme" in f["path"].lower()), None)
            
            if not readme_path:
                return None
            
            readme_data = await self.mcp_client.get_file_contents(owner, repo, readme_path)
            if not readme_data:
                return None
            
            import base64
            content = readme_data.get("content", "")
            if readme_data.get("encoding") == "base64":
                readme_content = base64.b64decode(content).decode('utf-8', errors='ignore')
            else:
                readme_content = content
            
            # Use AI to extract instructions
            prompt = f"""Extract execution instructions for the file '{file_path}' from this README:

{readme_content[:2000]}

Return ONLY the execution steps/instructions, formatted clearly."""

            instructions = self._generate_with_ai(prompt)
            return instructions.strip() if instructions else None
            
        except Exception as e:
            logger.error(f"Error extracting README instructions: {str(e)}")
            return None
    
    def _generate_with_ai(self, prompt: str) -> str:
        """Generate text using AI model."""
        if self.model_provider == "huggingface":
            return self._generate_huggingface(prompt)
        elif self.model_provider == "openai":
            return self._generate_openai(prompt)
        elif self.model_provider == "anthropic":
            return self._generate_anthropic(prompt)
        else:
            # Fallback: return empty
            return ""
    
    def _generate_huggingface(self, prompt: str) -> str:
        """Generate using Hugging Face model."""
        if not hasattr(self, 'model') or not self.model:
            return ""
        
        try:
            inputs = self.tokenizer(prompt, return_tensors="pt", truncation=True, max_length=512)
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=256,
                temperature=0.7,
                do_sample=True
            )
            return self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        except Exception as e:
            logger.error(f"Hugging Face generation error: {str(e)}")
            return ""
    
    def _generate_openai(self, prompt: str) -> str:
        """Generate using OpenAI API."""
        try:
            import openai
            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=512,
                temperature=0.7
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"OpenAI generation error: {str(e)}")
            return ""
    
    def _generate_anthropic(self, prompt: str) -> str:
        """Generate using Anthropic Claude API."""
        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=512,
                temperature=0.7,
                messages=[{"role": "user", "content": prompt}]
            )
            return message.content[0].text
        except Exception as e:
            logger.error(f"Anthropic generation error: {str(e)}")
            return ""

