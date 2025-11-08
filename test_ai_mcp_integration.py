#!/usr/bin/env python3
"""
Test script for AI Analyzer + MCP integration
Run this to verify your setup is working
"""

import os
import sys
import asyncio
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def check_requirements():
    """Check if all requirements are met."""
    print("🔍 Checking Requirements...\n")
    
    issues = []
    warnings = []
    
    # Check GitHub token
    github_token = os.getenv("GITHUB_PERSONAL_ACCESS_TOKEN")
    if not github_token:
        issues.append("❌ GITHUB_PERSONAL_ACCESS_TOKEN not set")
    else:
        print("✅ GitHub token found")
    
    # Check MCP SDK
    try:
        import mcp
        print("✅ MCP SDK installed")
    except ImportError:
        issues.append("❌ MCP SDK not installed: pip install mcp")
    
    # Check AI provider
    ai_provider = os.getenv("AI_MODEL_PROVIDER", "huggingface")
    print(f"📊 AI Provider: {ai_provider}")
    
    if ai_provider == "huggingface":
        try:
            import transformers
            import torch
            print("✅ Hugging Face dependencies installed")
            
            # Check if GPU is available
            if torch.cuda.is_available():
                print(f"   🚀 GPU available: {torch.cuda.get_device_name(0)}")
            else:
                warnings.append("⚠️  No GPU detected - model will run on CPU (slower)")
        except ImportError:
            issues.append("❌ Hugging Face not installed: pip install transformers torch")
    elif ai_provider == "openai":
        try:
            import openai
            if not os.getenv("OPENAI_API_KEY"):
                issues.append("❌ OPENAI_API_KEY not set")
            else:
                print("✅ OpenAI configured")
        except ImportError:
            issues.append("❌ OpenAI not installed: pip install openai")
    elif ai_provider == "anthropic":
        try:
            import anthropic
            if not os.getenv("ANTHROPIC_API_KEY"):
                issues.append("❌ ANTHROPIC_API_KEY not set")
            else:
                print("✅ Anthropic configured")
        except ImportError:
            issues.append("❌ Anthropic not installed: pip install anthropic")
    
    # Check Docker (for MCP server)
    import subprocess
    try:
        result = subprocess.run(['docker', '--version'], 
                              capture_output=True, timeout=5, text=True)
        if result.returncode == 0:
            print(f"✅ Docker installed: {result.stdout.strip()}")
            
            # Check if Docker daemon is running
            result = subprocess.run(['docker', 'ps'], 
                                  capture_output=True, timeout=5)
            if result.returncode == 0:
                print("✅ Docker daemon running")
            else:
                warnings.append("⚠️  Docker daemon not running: docker ps failed")
        else:
            warnings.append("⚠️  Docker not working properly")
    except FileNotFoundError:
        warnings.append("⚠️  Docker not found (will try binary)")
    except Exception as e:
        warnings.append(f"⚠️  Docker check failed: {str(e)}")
    
    # Check database
    try:
        import sqlalchemy
        print("✅ SQLAlchemy installed")
    except ImportError:
        issues.append("❌ SQLAlchemy not installed")
    
    print("\n" + "=" * 50)
    if issues:
        print("❌ Issues Found:")
        for issue in issues:
            print(f"   {issue}")
    if warnings:
        print("\n⚠️  Warnings:")
        for warning in warnings:
            print(f"   {warning}")
    
    if not issues:
        print("✅ All critical requirements met!")
        return True
    else:
        return False

async def test_mcp_connection():
    """Test MCP server connection."""
    print("\n🔌 Testing MCP Connection...\n")
    
    try:
        from app.analyzers import GitHubMCPClient
        
        print("Initializing MCP client...")
        client = GitHubMCPClient()
        
        print("Connecting to GitHub MCP server...")
        await client._initialize_mcp()
        
        if client.is_available():
            print("✅ MCP server connected!")
            
            # Test a simple query
            print("\nTesting search_repositories...")
            result = await client.search_repositories("test", per_page=1)
            if result.get('items'):
                print("✅ Search test successful!")
            else:
                print("⚠️  Search returned no results (might be rate limited)")
            
            await client.close()
            return True
        else:
            print("❌ MCP server not connected")
            print("\n💡 Troubleshooting:")
            print("   1. Check Docker is running: docker ps")
            print("   2. Pull MCP image: docker pull ghcr.io/github/github-mcp-server")
            print("   3. Check GitHub token is valid")
            return False
    except Exception as e:
        print(f"❌ MCP connection failed: {str(e)}")
        print("\n💡 Troubleshooting:")
        print("   1. Install MCP SDK: pip install mcp")
        print("   2. Check Docker is running: docker ps")
        print("   3. Pull MCP image: docker pull ghcr.io/github/github-mcp-server")
        print("   4. Verify GITHUB_PERSONAL_ACCESS_TOKEN is set")
        import traceback
        traceback.print_exc()
        return False

async def test_ai_analyzer():
    """Test AI Analyzer initialization."""
    print("\n🤖 Testing AI Analyzer...\n")
    
    try:
        from app.analyzers import GitHubMCPClient, AIAnalyzer
        
        print("Initializing MCP client...")
        mcp_client = GitHubMCPClient()
        
        print("Initializing AI Analyzer...")
        ai_analyzer = AIAnalyzer(mcp_client)
        
        # Check if AI model loaded
        print(f"Provider: {ai_analyzer.model_provider}")
        
        if hasattr(ai_analyzer, 'model') and ai_analyzer.model:
            print("✅ AI model loaded successfully")
            return True
        elif hasattr(ai_analyzer, 'client') and ai_analyzer.client:
            print("✅ AI API client configured")
            return True
        else:
            print("⚠️  AI model not loaded - will use heuristic fallbacks")
            return True
    except Exception as e:
        print(f"❌ AI Analyzer initialization failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

async def test_search():
    """Test repository search."""
    print("\n🔍 Testing Repository Search...\n")
    
    try:
        from app.analyzers import GitHubMCPClient, AIAnalyzer
        
        mcp_client = GitHubMCPClient()
        ai_analyzer = AIAnalyzer(mcp_client)
        
        # Test with a well-known CVE
        test_cve = "CVE-2021-44228"  # Log4j (should have many results)
        print(f"Searching for: {test_cve}")
        print("(This may take a minute...)\n")
        
        repos = await ai_analyzer.search_repositories_for_cve(test_cve, limit=5)
        
        if repos:
            print(f"✅ Found {len(repos)} repositories:")
            for i, repo in enumerate(repos[:5], 1):
                name = repo.get('full_name', 'Unknown')
                stars = repo.get('stargazers_count', 0)
                print(f"   {i}. {name} ({stars} ⭐)")
            
            await mcp_client.close()
            return True
        else:
            print("⚠️  No repositories found")
            print("   This might be due to:")
            print("   - Rate limiting")
            print("   - AI model not generating good queries")
            print("   - GitHub token issues")
            
            await mcp_client.close()
            return False
    except Exception as e:
        print(f"❌ Search test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

async def test_full_pipeline():
    """Test full pipeline with a simple CVE."""
    print("\n🚀 Testing Full Pipeline...\n")
    
    try:
        from app.analyzers import CVEExploitPipeline
        
        pipeline = CVEExploitPipeline()
        
        # Use a well-known CVE
        test_cve = "CVE-2021-44228"  # Log4j
        print(f"Processing: {test_cve}")
        print("(This may take several minutes...)\n")
        
        results = await pipeline.process_cve(test_cve, limit=3)
        
        print("\n" + "=" * 50)
        print("📊 Pipeline Results:")
        print("=" * 50)
        
        stage1 = results.get('stage_1_mcp_discovery', {})
        print(f"\n🔍 Stage 1 - Discovery:")
        print(f"   Repositories found: {stage1.get('repositories_found', 0)}")
        
        stage2 = results.get('stage_2_mcp_analysis', {})
        print(f"\n🤖 Stage 2 - AI Analysis:")
        print(f"   Repositories analyzed: {stage2.get('repositories_analyzed', 0)}")
        
        stage3 = results.get('stage_2_static_analysis', {})
        print(f"\n🔬 Stage 3 - Static Analysis:")
        print(f"   Files analyzed: {stage3.get('files_analyzed', 0)}")
        
        stage4 = results.get('stage_3_filtering', {})
        print(f"\n🎯 Stage 4 - Filtering:")
        print(f"   Before: {stage4.get('before_filtering', 0)}")
        print(f"   After: {stage4.get('after_filtering', 0)}")
        
        stage5 = results.get('stage_4_saved', {})
        print(f"\n💾 Stage 5 - Saved:")
        print(f"   Exploits saved: {stage5.get('exploits_saved', 0)}")
        
        if results.get('errors'):
            print(f"\n⚠️  {len(results['errors'])} errors occurred:")
            for error in results['errors'][:3]:
                print(f"   - {error}")
        
        # Close MCP connection
        await pipeline.mcp_client.close()
        
        print("\n✅ Pipeline test complete!")
        return True
    except Exception as e:
        print(f"❌ Pipeline test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

async def main():
    """Run all tests."""
    print("=" * 50)
    print("🧪 CVEhive AI Analyzer + MCP Integration Test")
    print("=" * 50)
    print()
    
    # Step 1: Check requirements
    print("Step 1: Checking requirements...")
    if not check_requirements():
        print("\n❌ Please fix the issues above before continuing")
        print("\n📖 See MCP_SETUP.md for detailed setup instructions")
        sys.exit(1)
    
    # Step 2: Test MCP connection
    print("\n" + "=" * 50)
    print("Step 2: Testing MCP connection...")
    if not await test_mcp_connection():
        print("\n❌ MCP connection failed.")
        print("📖 See MCP_SETUP.md for troubleshooting")
        sys.exit(1)
    
    # Step 3: Test AI Analyzer
    print("\n" + "=" * 50)
    print("Step 3: Testing AI Analyzer...")
    await test_ai_analyzer()
    
    # Step 4: Test search (quick test)
    print("\n" + "=" * 50)
    response = input("\nRun search test? (y/n): ")
    if response.lower() == 'y':
        await test_search()
    
    # Step 5: Test full pipeline (longer test)
    print("\n" + "=" * 50)
    response = input("\nRun full pipeline test? This may take 5-10 minutes. (y/n): ")
    if response.lower() == 'y':
        await test_full_pipeline()
    
    print("\n" + "=" * 50)
    print("✅ Testing complete!")
    print("\n💡 Next steps:")
    print("   1. View CVEs: python3 cli.py db stats")
    print("   2. Analyze CVE: python3 cli.py analyze cve CVE-2024-12345")
    print("   3. Batch analyze: python3 cli.py analyze batch --severity CRITICAL")
    print("\n📖 See IMPLEMENTATION_SUMMARY.md for more details")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

