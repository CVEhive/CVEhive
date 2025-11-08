"""
GitHub MCP Client for Official GitHub MCP Server
Connects to: https://github.com/github/github-mcp-server
"""

import os
import json
import logging
from typing import List, Dict, Optional, Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class GitHubMCPClient:
    """
    Client for official GitHub MCP Server.
    Connects to: https://github.com/github/github-mcp-server
    
    This client provides direct access to GitHub API tools via MCP protocol.
    The AI layer (AIAnalyzer) will use this client intelligently.
    """
    
    def __init__(self, github_token: Optional[str] = None, 
                 mcp_server_path: Optional[str] = None,
                 use_docker: bool = True):
        """
        Initialize GitHub MCP client.
        
        Args:
            github_token: GitHub personal access token
            mcp_server_path: Path to github-mcp-server binary (if not using Docker)
            use_docker: If True, use Docker container (recommended)
        """
        self.github_token = github_token or os.getenv("GITHUB_PERSONAL_ACCESS_TOKEN")
        self.mcp_server_path = mcp_server_path
        self.use_docker = use_docker
        self.session = None
        self._initialized = False
        
        if not self.github_token:
            logger.warning("GITHUB_PERSONAL_ACCESS_TOKEN not set - some features may not work")
    
    async def _initialize_mcp(self):
        """Initialize connection to GitHub MCP server."""
        if self._initialized and self.session:
            return
        
        try:
            from mcp import ClientSession, StdioServerParameters
            from mcp.client.stdio import stdio_client
            
            # Option 1: Use Docker (recommended)
            if self.use_docker:
                server_params = StdioServerParameters(
                    command="docker",
                    args=[
                        "run", "-i", "--rm",
                        "-e", f"GITHUB_PERSONAL_ACCESS_TOKEN={self.github_token}",
                        "ghcr.io/github/github-mcp-server"
                    ],
                    env={}
                )
            # Option 2: Use binary directly
            elif self.mcp_server_path:
                server_params = StdioServerParameters(
                    command=self.mcp_server_path,
                    args=[],
                    env={"GITHUB_PERSONAL_ACCESS_TOKEN": self.github_token}
                )
            else:
                # Try to find binary in PATH
                server_params = StdioServerParameters(
                    command="github-mcp-server",
                    args=[],
                    env={"GITHUB_PERSONAL_ACCESS_TOKEN": self.github_token}
                )
            
            # Store server params for connection
            self._server_params = server_params
            self._stdio_client = stdio_client(server_params)
            self._read, self._write = await self._stdio_client.__aenter__()
            self.session = ClientSession(self._read, self._write)
            await self.session.__aenter__()
            await self.session.initialize()
            self._initialized = True
            logger.info("✅ Connected to GitHub MCP server")
                    
        except ImportError:
            logger.error("MCP SDK not installed. Install with: pip install mcp")
            raise
        except Exception as e:
            logger.error(f"Failed to connect to GitHub MCP server: {str(e)}")
            logger.info("Make sure github-mcp-server is installed or Docker is running")
            logger.info("See: https://github.com/github/github-mcp-server")
            raise
    
    async def close(self):
        """Close MCP connection."""
        if self.session:
            try:
                await self.session.__aexit__(None, None, None)
            except:
                pass
        if hasattr(self, '_stdio_client'):
            try:
                await self._stdio_client.__aexit__(None, None, None)
            except:
                pass
        self._initialized = False
        self.session = None
    
    async def search_repositories(self, query: str, per_page: int = 20, 
                                  page: int = 1, sort: Optional[str] = None,
                                  order: Optional[str] = None) -> Dict:
        """
        Search GitHub repositories using MCP server.
        Uses official tool: search_repositories
        
        Args:
            query: GitHub search query
            per_page: Results per page (max 100)
            page: Page number
            sort: Sort field (stars, forks, updated, etc.)
            order: Sort order (asc, desc)
            
        Returns:
            Dictionary with search results
        """
        await self._initialize_mcp()
        
        try:
            params = {
                "query": query,
                "perPage": min(per_page, 100),
                "page": page
            }
            if sort:
                params["sort"] = sort
            if order:
                params["order"] = order
            
            result = await self.session.call_tool("search_repositories", params)
            
            # Parse result
            return self._parse_mcp_result(result)
            
        except Exception as e:
            logger.error(f"MCP search_repositories error: {str(e)}")
            return {"items": [], "total_count": 0}
    
    async def get_repository(self, owner: str, repo: str) -> Optional[Dict]:
        """
        Get repository details using MCP server.
        Uses official tool: get_repository
        """
        await self._initialize_mcp()
        
        try:
            result = await self.session.call_tool(
                "get_repository",
                {"owner": owner, "repo": repo}
            )
            
            return self._parse_mcp_result(result)
            
        except Exception as e:
            logger.error(f"MCP get_repository error: {str(e)}")
            return None
    
    async def list_repository_files(self, owner: str, repo: str, 
                                   path: str = "", recursive: bool = False) -> List[Dict]:
        """
        List files in repository using MCP server.
        Uses official tool: list_repository_files
        """
        await self._initialize_mcp()
        
        try:
            params = {"owner": owner, "repo": repo}
            if path:
                params["path"] = path
            if recursive:
                params["recursive"] = recursive
            
            result = await self.session.call_tool("list_repository_files", params)
            data = self._parse_mcp_result(result)
            
            # Handle different response formats
            if isinstance(data, list):
                return data
            elif isinstance(data, dict):
                return data.get("files", data.get("items", []))
            return []
            
        except Exception as e:
            logger.error(f"MCP list_repository_files error: {str(e)}")
            return []
    
    async def get_file_contents(self, owner: str, repo: str, 
                               path: str) -> Optional[Dict]:
        """
        Get file contents using MCP server.
        Uses official tool: get_file_contents
        
        Returns:
            Dictionary with file content and metadata
        """
        await self._initialize_mcp()
        
        try:
            result = await self.session.call_tool(
                "get_file_contents",
                {"owner": owner, "repo": repo, "path": path}
            )
            
            return self._parse_mcp_result(result)
            
        except Exception as e:
            logger.error(f"MCP get_file_contents error: {str(e)}")
            return None
    
    async def search_code(self, query: str, per_page: int = 20, 
                         page: int = 1) -> Dict:
        """
        Search code using MCP server.
        Uses official tool: search_code
        """
        await self._initialize_mcp()
        
        try:
            result = await self.session.call_tool(
                "search_code",
                {
                    "query": query,
                    "perPage": min(per_page, 100),
                    "page": page
                }
            )
            
            return self._parse_mcp_result(result)
            
        except Exception as e:
            logger.error(f"MCP search_code error: {str(e)}")
            return {"items": [], "total_count": 0}
    
    async def list_global_security_advisories(self, cve_id: Optional[str] = None,
                                              **kwargs) -> List[Dict]:
        """
        List global security advisories using MCP server.
        Uses official tool: list_global_security_advisories
        
        Args:
            cve_id: Filter by CVE ID
            **kwargs: Additional filters (severity, ecosystem, etc.)
        """
        await self._initialize_mcp()
        
        try:
            params = {}
            if cve_id:
                params["cveId"] = cve_id
            params.update(kwargs)
            
            result = await self.session.call_tool(
                "list_global_security_advisories",
                params
            )
            
            data = self._parse_mcp_result(result)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict):
                return data.get("advisories", data.get("items", []))
            return []
            
        except Exception as e:
            logger.error(f"MCP list_global_security_advisories error: {str(e)}")
            return []
    
    def _parse_mcp_result(self, result: Any) -> Any:
        """Parse MCP tool result."""
        if not result or not hasattr(result, 'content'):
            return {}
        
        try:
            # MCP returns TextContent objects
            if result.content:
                # Get first text content
                text_content = result.content[0]
                if hasattr(text_content, 'text'):
                    return json.loads(text_content.text)
                elif isinstance(text_content, str):
                    return json.loads(text_content)
            
            return {}
        except json.JSONDecodeError:
            logger.warning("Failed to parse MCP result as JSON")
            return {}
        except Exception as e:
            logger.error(f"Error parsing MCP result: {str(e)}")
            return {}
    
    def _parse_repo_url(self, repo_url: str) -> tuple:
        """Parse GitHub repository URL into owner/repo."""
        parsed = urlparse(repo_url)
        path_parts = parsed.path.strip('/').split('/')
        if len(path_parts) >= 2:
            return path_parts[0], path_parts[1]
        raise ValueError(f"Invalid repository URL: {repo_url}")
    
    def is_available(self) -> bool:
        """Check if MCP client is available and connected."""
        return self._initialized and self.session is not None
