#!/usr/bin/env python3
"""
CVEhive CLI - Command Line Interface
Manage CVEhive database, scrapers, and application.
"""

import click
import logging
from datetime import datetime, timedelta

from app.config import Config
from app.models.base import create_tables, drop_tables, get_db
from app.models import CVE, Exploit, ValidationResult
from app.scrapers.nvd_scraper import NVDScraper
from app.scrapers.github_scraper import GitHubScraper
from app.scrapers.exploitdb_scraper import ExploitDBScraper
from app.scrapers.repository_scraper import RepositoryScraper, sync_trickest, sync_all_notable_repositories
from app.scrapers.cve_project_scraper import CVEProjectScraper
from app.scrapers.cve_monitor import CVEMonitor
from app.validators.exploit_validator import ExploitValidator
from app.validators.docker_sandbox import DockerSandbox
from app.utils.logger import setup_logging

# Setup logging
setup_logging(Config.LOG_LEVEL, Config.LOG_FILE)

@click.group()
def cli():
    """CVEhive CLI - Manage your CVE search engine."""
    pass

@cli.group()
def db():
    """Database management commands."""
    pass

@db.command()
def init():
    """Initialize database tables."""
    click.echo("  Initializing database...")
    try:
        create_tables()
        click.echo("[PASS] Database initialized successfully!")
    except Exception as e:
        click.echo(f"[FAIL] Error initializing database: {str(e)}")

@db.command()
@click.confirmation_option(prompt='Are you sure you want to drop all tables?')
def reset():
    """Reset database (drop and recreate all tables)."""
    click.echo("  Resetting database...")
    try:
        drop_tables()
        create_tables()
        click.echo("[PASS] Database reset successfully!")
    except Exception as e:
        click.echo(f"[FAIL] Error resetting database: {str(e)}")

@db.command()
def stats():
    """Show database statistics."""
    try:
        db_session = next(get_db())
        
        total_cves = db_session.query(CVE).count()
        total_exploits = db_session.query(Exploit).count()
        total_validations = db_session.query(ValidationResult).count()
        validated_exploits = db_session.query(ValidationResult).filter(
            ValidationResult.is_validated == True
        ).count()
        
        # Recent activity
        last_week = datetime.utcnow() - timedelta(days=7)
        recent_cves = db_session.query(CVE).filter(
            CVE.created_at >= last_week
        ).count()
        recent_exploits = db_session.query(Exploit).filter(
            Exploit.created_at >= last_week
        ).count()
        
        click.echo("[INFO] Database Statistics:")
        click.echo(f"   Total CVEs: {total_cves:,}")
        click.echo(f"   Total Exploits: {total_exploits:,}")
        click.echo(f"   Total Validations: {total_validations:,}")
        click.echo(f"   Validated Exploits: {validated_exploits:,}")
        click.echo(f"   CVEs added last week: {recent_cves:,}")
        click.echo(f"   Exploits added last week: {recent_exploits:,}")
        
        if total_validations > 0:
            validation_rate = (validated_exploits / total_validations) * 100
            click.echo(f"   Validation Success Rate: {validation_rate:.1f}%")
        
        db_session.close()
        
    except Exception as e:
        click.echo(f"[FAIL] Error getting database stats: {str(e)}")

@cli.group()
def scrape():
    """Data scraping commands."""
    pass

@scrape.command()
@click.option('--days', default=7, help='Number of days to look back (default: 7)')
@click.option('--api-key', help='NVD API key for higher rate limits')
def nvd(days, api_key):
    """Scrape CVEs from NVD (National Vulnerability Database)."""
    click.echo(f"[SEARCH] Scraping CVEs from NVD (last {days} days)...")
    
    try:
        scraper = NVDScraper(api_key=api_key)
        cves_data = scraper.fetch_recent_cves(days=days)
        
        if not cves_data:
            click.echo("[INFO]  No CVEs found")
            return
        
        click.echo(f"[FETCH] Fetched {len(cves_data)} CVEs, saving to database...")
        
        # Parse CVEs
        parsed_cves = []
        for cve_data in cves_data:
            try:
                parsed_cve = scraper.parse_cve_data(cve_data)
                parsed_cves.append(parsed_cve)
            except Exception as e:
                logging.error(f"Error parsing CVE: {str(e)}")
                continue
        
        saved_count = scraper.save_cves_to_database(parsed_cves)
        click.echo(f"[PASS] Saved {saved_count} new CVEs to database!")
        
    except Exception as e:
        click.echo(f"[FAIL] Error scraping NVD: {str(e)}")
        logging.error(f"NVD scraping error: {str(e)}")

@scrape.command()
@click.option('--days', default=7, help='Number of days to look back (default: 7)')
@click.option('--limit', default=100, help='Maximum number of exploits to fetch')
def github(days, limit):
    """Scrape exploits from GitHub."""
    click.echo(f"[SEARCH] Scraping exploits from GitHub (last {days} days)...")
    
    try:
        scraper = GitHubScraper()
        exploits_data = scraper.search_recent_exploits(days=days, limit=limit)
        
        if not exploits_data:
            click.echo("[INFO]  No exploits found")
            return
        
        click.echo(f"[FETCH] Found {len(exploits_data)} exploits, saving to database...")
        saved_count = scraper.save_exploits_to_database(exploits_data)
        
        click.echo(f"[PASS] Saved {saved_count} new exploits to database!")
        
    except Exception as e:
        click.echo(f"[FAIL] Error scraping GitHub: {str(e)}")
        logging.error(f"GitHub scraping error: {str(e)}")

@scrape.command()
@click.option('--days', default=7, help='Number of days to look back (default: 7)')
@click.option('--limit', default=100, help='Maximum number of exploits to fetch')
def exploitdb(days, limit):
    """Scrape exploits from ExploitDB."""
    click.echo(f"[SEARCH] Scraping exploits from ExploitDB (last {days} days)...")
    
    try:
        scraper = ExploitDBScraper()
        exploits_data = scraper.search_recent_exploits(days=days, limit=limit)
        
        if not exploits_data:
            click.echo("[INFO]  No exploits found")
            return
        
        click.echo(f"[FETCH] Found {len(exploits_data)} exploits, saving to database...")
        saved_count = scraper.save_exploits_to_database(exploits_data)
        
        click.echo(f"[PASS] Saved {saved_count} new exploits to database!")
        
    except Exception as e:
        click.echo(f"[FAIL] Error scraping ExploitDB: {str(e)}")
        logging.error(f"ExploitDB scraping error: {str(e)}")

@scrape.command()
@click.argument('cve_id')
def exploits(cve_id):
    """Search for exploits for a specific CVE."""
    click.echo(f"[SEARCH] Searching exploits for {cve_id}...")
    
    total_found = 0
    total_saved = 0
    
    # Search GitHub
    try:
        click.echo("  Searching GitHub...")
        github_scraper = GitHubScraper()
        github_exploits = github_scraper.search_exploits_for_cve(cve_id, limit=50)
        github_saved = github_scraper.save_exploits_to_database(github_exploits)
        click.echo(f"    Found: {len(github_exploits)}, Saved: {github_saved}")
        total_found += len(github_exploits)
        total_saved += github_saved
    except Exception as e:
        click.echo(f"    [FAIL] GitHub search failed: {str(e)}")
    
    # Search ExploitDB
    try:
        click.echo("  Searching ExploitDB...")
        exploitdb_scraper = ExploitDBScraper()
        exploitdb_exploits = exploitdb_scraper.search_exploits_for_cve(cve_id, limit=50)
        exploitdb_saved = exploitdb_scraper.save_exploits_to_database(exploitdb_exploits)
        click.echo(f"    Found: {len(exploitdb_exploits)}, Saved: {exploitdb_saved}")
        total_found += len(exploitdb_exploits)
        total_saved += exploitdb_saved
    except Exception as e:
        click.echo(f"    [FAIL] ExploitDB search failed: {str(e)}")
    
    click.echo(f"[PASS] Total found: {total_found}, Total saved: {total_saved}")

@scrape.command()
@click.argument('cve_id')
def cve(cve_id):
    """Fetch a specific CVE by ID."""
    click.echo(f"[SEARCH] Fetching CVE {cve_id}...")
    
    try:
        scraper = NVDScraper()
        cve_data = scraper.fetch_cve_by_id(cve_id)
        
        if not cve_data:
            click.echo(f"[FAIL] CVE {cve_id} not found")
            return
        
        parsed_cve = scraper.parse_cve_data(cve_data)
        saved_count = scraper.save_cves_to_database([parsed_cve])
        
        if saved_count > 0:
            click.echo(f"[PASS] Saved CVE {cve_id} to database!")
        else:
            click.echo(f"[INFO]  CVE {cve_id} already exists in database")
        
    except Exception as e:
        click.echo(f"[FAIL] Error fetching CVE: {str(e)}")

@scrape.command()
def trickest():
    """Sync with Trickest CVE repository for validated PoCs."""
    click.echo("[SYNC] Syncing with Trickest CVE repository...")
    
    try:
        count = sync_trickest()
        click.echo(f"[PASS] Synced {count} new exploits from Trickest!")
        
    except Exception as e:
        click.echo(f"[FAIL] Error syncing Trickest: {str(e)}")
        logging.error(f"Trickest sync error: {str(e)}")

@scrape.command()
def repositories():
    """Sync with all notable PoC repositories (Trickest, PoC-in-GitHub, Pocsuite3)."""
    click.echo("📚 Syncing with notable PoC repositories...")
    
    try:
        results = sync_all_notable_repositories()
        
        total_synced = 0
        for repo_name, count in results.items():
            click.echo(f"  {repo_name}: {count} new exploits")
            total_synced += count
        
        click.echo(f"[PASS] Total synced: {total_synced} new exploits from all repositories!")
        
    except Exception as e:
        click.echo(f"[FAIL] Error syncing repositories: {str(e)}")
        logging.error(f"Repository sync error: {str(e)}")

@scrape.command()
@click.option('--repository', type=click.Choice(['trickest', 'poc_in_github', 'pocsuite3']), 
              help='Specific repository to sync')
def repo(repository):
    """Sync with a specific notable repository."""
    if not repository:
        click.echo("[FAIL] Please specify a repository: --repository [trickest|poc_in_github|pocsuite3]")
        return
    
    click.echo(f"📦 Syncing with {repository} repository...")
    
    try:
        scraper = RepositoryScraper()
        count = scraper.sync_repository(repository)
        click.echo(f"[PASS] Synced {count} new exploits from {repository}!")
        
    except Exception as e:
        click.echo(f"[FAIL] Error syncing {repository}: {str(e)}")
        logging.error(f"{repository} sync error: {str(e)}")

@scrape.command()
def repo_stats():
    """Show statistics for notable repositories."""
    click.echo("[INFO] Repository Statistics:")
    
    try:
        scraper = RepositoryScraper()
        stats = scraper.get_repository_stats()
        
        for repo_key, repo_stats in stats.items():
            if 'error' in repo_stats:
                click.echo(f"  {repo_stats['name']}: [FAIL] {repo_stats['error']}")
            else:
                validation_rate = repo_stats['validation_rate'] * 100
                click.echo(f"  {repo_stats['name']}:")
                click.echo(f"    Total PoCs: {repo_stats['total_exploits']}")
                click.echo(f"    Validated: {repo_stats['validated_exploits']}")
                click.echo(f"    Validation Rate: {validation_rate:.1f}%")
                click.echo(f"    Priority: {repo_stats['priority']}")
                click.echo(f"    Confidence: {repo_stats['confidence']:.1%}")
        
    except Exception as e:
        click.echo(f"[FAIL] Error getting repository stats: {str(e)}")

@cli.group()
def validate():
    """Exploit validation commands."""
    pass

@validate.command()
@click.option('--level', default='basic', type=click.Choice(['basic', 'standard', 'comprehensive']),
              help='Validation level (default: basic)')
@click.option('--limit', default=10, help='Maximum number of exploits to validate')
def pending():
    """Validate pending exploits."""
    click.echo(f"[SEARCH] Validating pending exploits (level: {level})...")
    
    try:
        # Check if Docker is available for advanced validation
        sandbox = DockerSandbox()
        if level in ['standard', 'comprehensive'] and not sandbox.is_available():
            click.echo("[WARN]  Docker not available, falling back to basic validation")
            level = 'basic'
        
        validator = ExploitValidator()
        
        # Get pending exploits
        db_session = next(get_db())
        exploits = db_session.query(Exploit).filter(
            ~Exploit.id.in_(
                db_session.query(ValidationResult.exploit_id)
            )
        ).limit(limit).all()
        
        if not exploits:
            click.echo("[INFO]  No pending exploits found")
            return
        
        click.echo(f"📋 Found {len(exploits)} pending exploits")
        
        validated_count = 0
        for i, exploit in enumerate(exploits, 1):
            click.echo(f"  [{i}/{len(exploits)}] Validating exploit {exploit.id}...")
            
            try:
                result = validator.validate_exploit(exploit, validation_level=level)
                if result.is_validated:
                    validated_count += 1
                    click.echo(f"    [PASS] Validated (Score: {result.validation_score:.1f}/10)")
                else:
                    click.echo(f"    [FAIL] Not validated (Score: {result.validation_score:.1f}/10)")
            except Exception as e:
                click.echo(f"    [FAIL] Validation failed: {str(e)}")
        
        click.echo(f"[PASS] Validation complete: {validated_count}/{len(exploits)} validated")
        db_session.close()
        
    except Exception as e:
        click.echo(f"[FAIL] Error during validation: {str(e)}")

@validate.command()
@click.argument('exploit_id', type=int)
@click.option('--level', default='standard', type=click.Choice(['basic', 'standard', 'comprehensive']),
              help='Validation level (default: standard)')
def exploit(exploit_id, level):
    """Validate a specific exploit by ID."""
    click.echo(f"[SEARCH] Validating exploit {exploit_id} (level: {level})...")
    
    try:
        # Check if Docker is available for advanced validation
        sandbox = DockerSandbox()
        if level in ['standard', 'comprehensive'] and not sandbox.is_available():
            click.echo("[WARN]  Docker not available, falling back to basic validation")
            level = 'basic'
        
        validator = ExploitValidator()
        
        # Get exploit
        db_session = next(get_db())
        exploit_obj = db_session.query(Exploit).filter(Exploit.id == exploit_id).first()
        
        if not exploit_obj:
            click.echo(f"[FAIL] Exploit {exploit_id} not found")
            return
        
        click.echo(f"📋 Exploit: {exploit_obj.title}")
        click.echo(f"    Source: {exploit_obj.source}")
        click.echo(f"    Language: {exploit_obj.language}")
        
        result = validator.validate_exploit(exploit_obj, validation_level=level)
        
        click.echo(f"\n[INFO] Validation Results:")
        click.echo(f"    Status: {'[PASS] Validated' if result.is_validated else '[FAIL] Not Validated'}")
        click.echo(f"    Score: {result.validation_score:.1f}/10")
        click.echo(f"    Syntax Valid: {'[PASS]' if result.syntax_valid else '[FAIL]'}")
        click.echo(f"    Execution: {'[PASS]' if result.execution_successful else '[FAIL]'}")
        
        if result.security_analysis_results:
            security = result.security_analysis_results
            click.echo(f"    Risk Level: {security.get('risk_level', 'unknown').title()}")
            if security.get('exploit_techniques'):
                click.echo(f"    Techniques: {', '.join(security['exploit_techniques'])}")
        
        db_session.close()
        
    except Exception as e:
        click.echo(f"[FAIL] Error validating exploit: {str(e)}")

@validate.command()
def stats():
    """Show validation statistics."""
    try:
        validator = ExploitValidator()
        stats = validator.get_validation_statistics()
        
        click.echo("[INFO] Validation Statistics:")
        click.echo(f"   Total Validations: {stats['total_validations']:,}")
        click.echo(f"   Successful Validations: {stats['successful_validations']:,}")
        click.echo(f"   Success Rate: {stats['success_rate']:.1%}")
        click.echo(f"   Average Score: {stats['average_score']:.1f}/10")
        click.echo(f"   Sandbox Available: {'[PASS]' if stats['sandbox_available'] else '[FAIL]'}")
        
    except Exception as e:
        click.echo(f"[FAIL] Error getting validation stats: {str(e)}")

@cli.group()
def docker():
    """Docker sandbox management."""
    pass

@docker.command()
def status():
    """Check Docker sandbox status."""
    try:
        sandbox = DockerSandbox()
        info = sandbox.get_system_info()
        
        if info['available']:
            click.echo("[DOCKER] Docker Status: [PASS] Available")
            click.echo(f"   Version: {info['version']['Version']}")
            click.echo(f"   Running Containers: {info['containers_running']}")
            click.echo(f"   Total Containers: {info['containers_total']}")
            click.echo(f"   Images: {info['images_total']}")
            click.echo(f"   Memory: {info['memory_total'] // (1024**3):.1f} GB")
            click.echo(f"   CPUs: {info['cpu_count']}")
        else:
            click.echo("[DOCKER] Docker Status: [FAIL] Not Available")
            if 'error' in info:
                click.echo(f"   Error: {info['error']}")
        
    except Exception as e:
        click.echo(f"[FAIL] Error checking Docker status: {str(e)}")

@docker.command()
def build():
    """Build the CVEhive sandbox image."""
    click.echo("[DOCKER] Building CVEhive sandbox image...")
    
    try:
        sandbox = DockerSandbox()
        if sandbox.create_sandbox_image():
            click.echo("[PASS] Sandbox image built successfully!")
        else:
            click.echo("[FAIL] Failed to build sandbox image")
        
    except Exception as e:
        click.echo(f"[FAIL] Error building sandbox image: {str(e)}")

@docker.command()
def cleanup():
    """Clean up old Docker containers and networks."""
    click.echo("[DOCKER] Cleaning up old Docker resources...")
    
    try:
        sandbox = DockerSandbox()
        sandbox.cleanup_old_containers()
        click.echo("[PASS] Cleanup completed!")
        
    except Exception as e:
        click.echo(f"[FAIL] Error during cleanup: {str(e)}")

@cli.command()
@click.option('--host', default='0.0.0.0', help='Host to bind to')
@click.option('--port', default=5000, help='Port to bind to')
@click.option('--debug', is_flag=True, help='Enable debug mode')
def run(host, port, debug):
    """Run the CVEhive web application."""
    click.echo("[RUN] Starting CVEhive web application...")
    click.echo(f"   Host: {host}")
    click.echo(f"   Port: {port}")
    click.echo(f"   Debug: {debug}")
    click.echo(f"   Database: {Config.DATABASE_URL}")
    
    try:
        from app import app
        app.run(host=host, port=port, debug=debug)
    except Exception as e:
        click.echo(f"[FAIL] Error starting application: {str(e)}")

@cli.command()
def setup():
    """Setup CVEhive with sample data."""
    click.echo("[SETUP]  Setting up CVEhive...")
    
    # Initialize database
    click.echo("1. Initializing database...")
    try:
        create_tables()
        click.echo("   [PASS] Database initialized")
    except Exception as e:
        click.echo(f"   [FAIL] Database initialization failed: {str(e)}")
        return
    
    # Check Docker
    click.echo("2. Checking Docker availability...")
    try:
        sandbox = DockerSandbox()
        if sandbox.is_available():
            click.echo("   [PASS] Docker available")
            if sandbox.create_sandbox_image():
                click.echo("   [PASS] Sandbox image built")
            else:
                click.echo("   [WARN]  Failed to build sandbox image")
        else:
            click.echo("   [WARN]  Docker not available (validation will be limited)")
    except Exception as e:
        click.echo(f"   [WARN]  Docker check failed: {str(e)}")
    
    # Fetch recent CVEs
    click.echo("3. Fetching recent CVEs from NVD...")
    try:
        scraper = NVDScraper()
        cves_data = scraper.fetch_recent_cves(days=3)  # Start with 3 days
        
        if cves_data:
            parsed_cves = []
            for cve_data in cves_data:
                try:
                    parsed_cve = scraper.parse_cve_data(cve_data)
                    parsed_cves.append(parsed_cve)
                except Exception as e:
                    continue
            
            saved_count = scraper.save_cves_to_database(parsed_cves)
            click.echo(f"   [PASS] Saved {saved_count} CVEs")
        else:
            click.echo("   [WARN]  No CVEs found")
    except Exception as e:
        click.echo(f"   [FAIL] CVE fetching failed: {str(e)}")
    
    # Fetch some exploits
    click.echo("4. Fetching recent exploits...")
    try:
        github_scraper = GitHubScraper()
        exploits_data = github_scraper.search_recent_exploits(days=7, limit=20)
        
        if exploits_data:
            saved_count = github_scraper.save_exploits_to_database(exploits_data)
            click.echo(f"   [PASS] Saved {saved_count} exploits from GitHub")
        else:
            click.echo("   [WARN]  No exploits found on GitHub")
    except Exception as e:
        click.echo(f"   [FAIL] Exploit fetching failed: {str(e)}")
    
    click.echo("\n🎉 Setup complete!")
    click.echo("You can now run:")
    click.echo("  python cli.py run                    # Start web application")
    click.echo("  python cli.py validate pending       # Validate exploits")
    click.echo("  python cli.py db stats               # View statistics")

@cli.group()
def search():
    """Search commands."""
    pass

@search.command()
@click.argument('query')
@click.option('--limit', default=10, help='Maximum number of results')
def cves(query, limit):
    """Search CVEs in the database."""
    try:
        from app.utils.search import SearchEngine
        
        search_engine = SearchEngine()
        results = search_engine.search_cves(query, limit=limit)
        
        if not results:
            click.echo("[INFO]  No CVEs found")
            return
        
        click.echo(f"[SEARCH] Found {len(results)} CVEs:")
        for cve in results:
            click.echo(f"  {cve.cve_id} - {cve.summary[:80]}...")
            click.echo(f"    CVSS: {cve.cvss_v3_score or cve.cvss_v2_score or 'N/A'}")
            click.echo(f"    Published: {cve.published_date}")
            click.echo()
        
    except Exception as e:
        click.echo(f"[FAIL] Error searching CVEs: {str(e)}")

@search.command()
@click.argument('query')
@click.option('--limit', default=10, help='Maximum number of results')
def exploits(query, limit):
    """Search exploits in the database."""
    try:
        from app.utils.search import SearchEngine
        
        search_engine = SearchEngine()
        results = search_engine.search_exploits(query, limit=limit)
        
        if not results:
            click.echo("[INFO]  No exploits found")
            return
        
        click.echo(f"[SEARCH] Found {len(results)} exploits:")
        for exploit in results:
            click.echo(f"  {exploit.title}")
            click.echo(f"    Source: {exploit.source}")
            click.echo(f"    Language: {exploit.language}")
            click.echo(f"    Quality: {exploit.quality_score:.1f}/10")
            click.echo()
        
    except Exception as e:
        click.echo(f"[FAIL] Error searching exploits: {str(e)}")

@cli.group()
def analyze():
    """AI-powered exploit analysis commands."""
    pass

@analyze.command()
@click.argument('cve_id')
@click.option('--limit', default=20, help='Maximum repositories to discover via MCP')
@click.option('--min-score', default=50, help='Minimum baseline score for filtering')
def cve(cve_id, limit, min_score):
    """
    Search and analyze GitHub repositories for a CVE using MCP/AI.
    
    Pipeline stages:
    1. MCP/AI discovers repositories
    2. MCP/AI analyzes repositories
    3. Static analysis on code
    4. Filter based on analysis
    5. Save for dynamic analysis
    """
    click.echo(f"[AI] MCP/AI-Powered CVE Analysis: {cve_id}")
    click.echo(f"[INFO] Discovering up to {limit} repositories via MCP...\n")
    
    try:
        import asyncio
        from app.analyzers import CVEExploitPipeline
        
        pipeline = CVEExploitPipeline()
        pipeline.min_baseline_score = min_score
        
        # Run async pipeline
        results = asyncio.run(pipeline.process_cve(cve_id, limit=limit))
        
        click.echo("=" * 50)
        click.echo("[INFO] PIPELINE RESULTS")
        click.echo("=" * 50)
        
        # Stage 1: MCP Discovery
        stage1 = results.get('stage_1_mcp_discovery', {})
        click.echo(f"\n[SEARCH] Stage 1 - MCP/AI Discovery:")
        click.echo(f"   Repositories found: {stage1.get('repositories_found', 0)}")
        
        # Stage 2: Static Analysis
        stage2 = results.get('stage_2_static_analysis', {})
        click.echo(f"\n[ANALYZE] Stage 2 - Static Analysis:")
        click.echo(f"   Files analyzed: {stage2.get('files_analyzed', 0)}")
        
        # Stage 3: Filtering
        stage3 = results.get('stage_3_filtering', {})
        click.echo(f"\n[SYNC] Stage 3 - Filtering:")
        click.echo(f"   Before filtering: {stage3.get('before_filtering', 0)}")
        click.echo(f"   After filtering: {stage3.get('after_filtering', 0)}")
        click.echo(f"   Filtered out: {stage3.get('filtered_out', 0)}")
        
        # Stage 4: Saved
        stage4 = results.get('stage_4_saved', {})
        click.echo(f"\n[SAVE] Stage 4 - Saved for Dynamic Analysis:")
        click.echo(f"   Exploits saved: {stage4.get('exploits_saved', 0)}")
        click.echo(f"   Ready for dynamic analysis: {stage4.get('ready_for_dynamic_analysis', 0)}")
        
        if results.get('errors'):
            click.echo(f"\n[WARN]  Errors: {len(results['errors'])}")
            for error in results['errors'][:3]:
                click.echo(f"   - {error}")
        
        click.echo(f"\n[PASS] Pipeline complete!")
        click.echo(f"[TIP] Next: Run dynamic analysis stage")
        click.echo(f"[TIP] View results: python3 cli.py db stats")
        
    except Exception as e:
        click.echo(f"[FAIL] Error: {str(e)}")
        logging.error(f"Analysis error: {str(e)}")

@analyze.command()
@click.option('--severity', type=click.Choice(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']), 
              help='Filter by CVE severity')
@click.option('--limit', default=5, help='Maximum CVEs to process')
@click.option('--repos-per-cve', default=20, help='Repositories per CVE (MCP discovery limit)')
@click.option('--min-score', default=50, help='Minimum baseline score for filtering')
def batch(severity, limit, repos_per_cve, min_score):
    """Batch analyze multiple CVEs using MCP/AI pipeline."""
    click.echo(f"[AI] Batch MCP/AI Analysis")
    click.echo(f"[INFO] Processing {limit} CVEs ({repos_per_cve} repos each)...\n")
    
    try:
        import asyncio
        from app.analyzers import CVEExploitPipeline
        from app.models import CVE
        from app.models.base import get_db
        
        # Get CVEs from database
        db = next(get_db())
        query = db.query(CVE)
        
        if severity:
            query = query.filter(CVE.severity == severity)
        
        # Get CVEs without exploits
        cves = query.filter(CVE.has_exploit == False).limit(limit).all()
        
        if not cves:
            click.echo("[INFO]  No CVEs found matching criteria")
            return
        
        click.echo(f"Found {len(cves)} CVEs to analyze\n")
        
        pipeline = CVEExploitPipeline()
        pipeline.min_baseline_score = min_score
        cve_ids = [cve.cve_id for cve in cves]
        
        summary = asyncio.run(pipeline.process_multiple_cves(cve_ids, limit_per_cve=repos_per_cve))
        
        click.echo("\n" + "=" * 50)
        click.echo("[INFO] BATCH ANALYSIS SUMMARY")
        click.echo("=" * 50)
        click.echo(f"CVEs processed: {summary['processed']}/{summary['total_cves']}")
        click.echo(f"Total exploits saved: {summary['total_exploits_saved']}")
        click.echo(f"[TIP] All saved exploits are ready for dynamic analysis stage")
        
        db.close()
        
    except Exception as e:
        click.echo(f"[FAIL] Error: {str(e)}")
        logging.error(f"Batch analysis error: {str(e)}")

@cli.group()
def cve():
    """CVE management commands."""
    pass

@cve.command()
@click.option('--start-year', default=2021, help='Starting year')
@click.option('--end-year', default=None, type=int, help='Ending year (default: current)')
@click.option('--source', type=click.Choice(['nvd', 'cve-project', 'both']), default='nvd', help='Data source')
def bulk_import(start_year, end_year, source):
    """Import all CVEs from start_year to end_year."""
    click.echo(f"[MONITOR] Starting bulk import from {start_year} to {end_year or 'now'}...")
    click.echo(f"📡 Source: {source}")
    click.echo("⏳ This will take a while. Please be patient...\n")
    
    results = {}
    
    if source in ['nvd', 'both']:
        click.echo("=" * 50)
        click.echo("IMPORTING FROM NVD")
        click.echo("=" * 50)
        scraper = NVDScraper()
        nvd_stats = scraper.bulk_import_cves(start_year=start_year, end_year=end_year)
        results['nvd'] = nvd_stats
        
        click.echo(f"\n[PASS] NVD Import Complete:")
        click.echo(f"   Years processed: {nvd_stats['years_processed']}")
        click.echo(f"   Total CVEs found: {nvd_stats['total_cves_found']:,}")
        click.echo(f"   New CVEs saved: {nvd_stats['total_cves_saved']:,}")
        click.echo(f"   CVEs updated: {nvd_stats['total_cves_updated']:,}")
    
    if source in ['cve-project', 'both']:
        click.echo("\n" + "=" * 50)
        click.echo("IMPORTING FROM CVE PROJECT")
        click.echo("=" * 50)
        scraper = CVEProjectScraper()
        cve_project_stats = scraper.bulk_import_cves(start_year=start_year, end_year=end_year)
        results['cve_project'] = cve_project_stats
        
        click.echo(f"\n[PASS] CVE Project Import Complete:")
        click.echo(f"   Years processed: {cve_project_stats['years_processed']}")
        click.echo(f"   Total CVEs found: {cve_project_stats['total_cves_found']:,}")
        click.echo(f"   New CVEs saved: {cve_project_stats['total_cves_saved']:,}")
        click.echo(f"   CVEs updated: {cve_project_stats['total_cves_updated']:,}")
    
    click.echo("\n" + "=" * 50)
    click.echo("[INFO] BULK IMPORT SUMMARY")
    click.echo("=" * 50)
    
    total_saved = sum(r['total_cves_saved'] for r in results.values())
    total_updated = sum(r['total_cves_updated'] for r in results.values())
    
    click.echo(f"[PASS] Total new CVEs: {total_saved:,}")
    click.echo(f"[MONITOR] Total updated CVEs: {total_updated:,}")
    click.echo(f"[INFO] Grand total: {total_saved + total_updated:,}")

@cve.command()
@click.option('--hours', default=24, help='Hours to look back')
def check_new(hours):
    """Check for new CVEs."""
    click.echo(f"[SEARCH] Checking for CVEs from last {hours} hours...")
    
    monitor = CVEMonitor()
    stats = monitor.check_for_new_cves(lookback_hours=hours)
    
    click.echo(f"\n[INFO] Results:")
    click.echo(f"   Total new: {stats['total_cves_new']:,}")
    click.echo(f"   Total updated: {stats['total_cves_updated']:,}")
    
    for source, source_stats in stats['sources'].items():
        if source_stats.get('success'):
            click.echo(f"\n   {source.upper()}:")
            click.echo(f"      Found: {source_stats['cves_found']:,}")
            click.echo(f"      New: {source_stats['cves_new']:,}")
            click.echo(f"      Updated: {source_stats['cves_updated']:,}")
        else:
            click.echo(f"\n   {source.upper()}: [FAIL] ERROR - {source_stats.get('error')}")

@cve.command()
@click.option('--interval', default=60, help='Minutes between checks')
@click.option('--once', is_flag=True, help='Run once instead of continuous')
def monitor(interval, once):
    """Start CVE monitoring service."""
    if once:
        click.echo("[MONITOR] Running monitor once...")
    else:
        click.echo(f"[MONITOR] Starting CVE monitor (interval: {interval} minutes)...")
        click.echo("[PAUSE]  Press Ctrl+C to stop")
    
    monitor = CVEMonitor()
    monitor.start_monitoring(interval_minutes=interval, run_once=once)
    
    click.echo("[PASS] Monitor complete!")

@cve.command()
def compare():
    """Compare local database with CVE sources."""
    click.echo("[SEARCH] Comparing database with CVE sources...\n")
    
    monitor = CVEMonitor()
    stats = monitor.compare_with_database()
    
    click.echo("=" * 50)
    click.echo("[INFO] DATABASE STATISTICS")
    click.echo("=" * 50)
    click.echo(f"Total CVEs: {stats['total_cves_local']:,}")
    click.echo(f"Oldest CVE: {stats['oldest_cve_date']}")
    click.echo(f"Newest CVE: {stats['newest_cve_date']}")
    click.echo(f"Last check: {stats['last_check']}")
    
    click.echo("\n📅 CVEs by Year:")
    for year, count in sorted(stats['year_breakdown'].items()):
        click.echo(f"   {year}: {count:,} CVEs")
    
    click.echo("\n📡 CVEs by Source:")
    for source, count in stats['source_breakdown'].items():
        click.echo(f"   {source}: {count:,} CVEs")

@cve.command()
@click.option('--start-date', required=True, help='Start date (YYYY-MM-DD)')
@click.option('--end-date', required=True, help='End date (YYYY-MM-DD)')
def backfill(start_date, end_date):
    """Backfill CVEs for a specific date range."""
    start = datetime.strptime(start_date, '%Y-%m-%d')
    end = datetime.strptime(end_date, '%Y-%m-%d')
    
    click.echo(f"[MONITOR] Backfilling CVEs from {start_date} to {end_date}...")
    
    monitor = CVEMonitor()
    stats = monitor.backfill_missing_cves(start, end)
    
    click.echo("\n[PASS] Backfill complete:")
    for source, source_stats in stats['sources'].items():
        if 'error' not in source_stats:
            click.echo(f"\n   {source.upper()}:")
            click.echo(f"      Found: {source_stats['cves_found']:,}")
            click.echo(f"      New: {source_stats['cves_new']:,}")
            click.echo(f"      Updated: {source_stats['cves_updated']:,}")
        else:
            click.echo(f"\n   {source.upper()}: [FAIL] {source_stats['error']}")

@cli.command()
def version():
    """Show CVEhive version information."""
    click.echo("CVEhive v1.0.0")
    click.echo("A comprehensive CVE search engine with exploit validation")
    click.echo("https://github.com/yourusername/cvehive")

if __name__ == '__main__':
    cli() 