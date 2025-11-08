# GitHub MCP Server Setup Guide

## Overview

This implementation uses the **official GitHub MCP Server** from https://github.com/github/github-mcp-server and adds an **AI Analyzer layer** that intelligently uses the MCP server's tools.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│              CVEhive Application                        │
│  ┌──────────────────────────────────────────────────┐   │
│  │  CVEExploitPipeline                              │   │
│  │  ┌──────────────────────────────────────────┐   │   │
│  │  │  AIAnalyzer                               │   │   │
│  │  │  (Uses AI model to intelligently use      │   │   │
│  │  │   GitHub MCP server tools)                │   │   │
│  │  └──────────────┬─────────────────────────────┘   │   │
│  │  ┌──────────────▼─────────────────────────────┐   │   │
│  │  │  GitHubMCPClient                          │   │   │
│  │  │  (Connects to official GitHub MCP server) │   │   │
│  │  └──────────────┬─────────────────────────────┘   │   │
│  └─────────────────┼───────────────────────────────┘   │
└─────────────────────┼───────────────────────────────────┘
                      │ MCP Protocol (stdio)
                      │
┌─────────────────────▼───────────────────────────────────┐
│     Official GitHub MCP Server (Go Binary)               │
│     https://github.com/github/github-mcp-server         │
│                                                          │
│  Tools Available:                                       │
│  - search_repositories                                  │
│  - get_repository                                       │
│  - list_repository_files                                │
│  - get_file_contents                                    │
│  - search_code                                          │
│  - list_global_security_advisories                      │
│  - ... (many more GitHub API tools)                     │
└──────────────┬──────────────────────────────────────────┘
               │ GitHub API
               │
┌──────────────▼───────────────────────────────────────────┐
│                    GitHub                                 │
└───────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│  AI Model (Part of CVEhive)                             │
│  - Hugging Face / OpenAI / Anthropic                    │
│  - Generates intelligent search queries                 │
│  - Analyzes repository relevance                        │
│  - Extracts execution instructions                      │
└───────────────────────────────────────────────────────────┘
```

## Setup Instructions

### Step 1: Install GitHub MCP Server

**Option A: Use Docker (Recommended)**

```bash
# Pull the Docker image
docker pull ghcr.io/github/github-mcp-server

# Test it works
docker run -i --rm \
  -e GITHUB_PERSONAL_ACCESS_TOKEN=your_token \
  ghcr.io/github/github-mcp-server
```

**Option B: Download Binary**

1. Go to https://github.com/github/github-mcp-server/releases
2. Download the binary for your platform
3. Make it executable: `chmod +x github-mcp-server`
4. Move to PATH or specify path in code

### Step 2: Install Python Dependencies

```bash
# Install MCP SDK
pip install mcp

# Install AI model dependencies (choose one):

# Option 1: Hugging Face (Open Source)
pip install transformers torch

# Option 2: OpenAI API
pip install openai

# Option 3: Anthropic Claude API
pip install anthropic
```

### Step 3: Set Environment Variables

Create a `.env` file or export variables:

```bash
# Required: GitHub token
export GITHUB_PERSONAL_ACCESS_TOKEN=your_github_token

# Required: Choose AI provider
export AI_MODEL_PROVIDER=huggingface  # or "openai" or "anthropic"

# For Hugging Face
export AI_MODEL_NAME=deepseek-ai/deepseek-coder-6.7b-instruct

# For OpenAI
export OPENAI_API_KEY=your_openai_key
export OPENAI_MODEL=gpt-4

# For Anthropic
export ANTHROPIC_API_KEY=your_anthropic_key
export ANTHROPIC_MODEL=claude-3-opus-20240229
```

### Step 4: Configure MCP Client

The `GitHubMCPClient` will automatically:
- Use Docker if available (recommended)
- Fall back to binary if Docker not available
- Use environment variables for configuration

You can also specify manually:

```python
from app.analyzers import GitHubMCPClient, AIAnalyzer

# Use Docker (default)
mcp_client = GitHubMCPClient(use_docker=True)

# Use binary
mcp_client = GitHubMCPClient(
    mcp_server_path="/path/to/github-mcp-server",
    use_docker=False
)
```

## Usage

### Basic Usage

```python
from app.analyzers import CVEExploitPipeline
import asyncio

# Initialize pipeline (automatically sets up MCP + AI)
pipeline = CVEExploitPipeline()

# Process a CVE
results = asyncio.run(pipeline.process_cve("CVE-2024-12345", limit=20))

print(f"Found {results['stage_1_mcp_discovery']['repositories_found']} repositories")
print(f"Saved {results['stage_4_saved']['exploits_saved']} exploits")
```

### CLI Usage

```bash
# Analyze a CVE
python3 cli.py analyze cve CVE-2024-12345 --limit 20

# Batch analyze
python3 cli.py analyze batch --severity CRITICAL --limit 10
```

## How It Works

### Stage 1: AI/MCP Repository Discovery

1. **AI generates search queries**: AI model creates intelligent GitHub search queries for the CVE
2. **MCP searches GitHub**: Uses official GitHub MCP server to search repositories
3. **AI ranks results**: AI model ranks repositories by relevance

### Stage 2: AI Repository Analysis

1. **MCP gets repository data**: Uses MCP server to fetch repository details and README
2. **AI analyzes relevance**: AI model determines if repository contains exploit code
3. **AI identifies files**: AI identifies which files are likely exploit code

### Stage 3: Static Analysis

1. **MCP gets file contents**: Uses MCP server to fetch exploit file contents
2. **Static analysis**: Your code validates syntax, security, dependencies
3. **Baseline scoring**: Calculates quality score (0-100)

### Stage 4: Filtering

1. **Filter by baseline score**: Removes low-quality code
2. **Filter by syntax**: Removes invalid code
3. **Filter by AI confidence**: Removes low-confidence matches

### Stage 5: Save for Dynamic Analysis

1. **AI extracts README instructions**: AI extracts execution steps from README
2. **Save to database**: Stores all metadata for dynamic analysis stage

## Troubleshooting

### MCP Server Not Connecting

```bash
# Check Docker is running
docker ps

# Test MCP server manually
docker run -i --rm \
  -e GITHUB_PERSONAL_ACCESS_TOKEN=your_token \
  ghcr.io/github/github-mcp-server
```

### AI Model Not Loading

```bash
# Check environment variables
echo $AI_MODEL_PROVIDER
echo $AI_MODEL_NAME

# For Hugging Face, check disk space (models are large)
df -h

# For OpenAI/Anthropic, check API keys
echo $OPENAI_API_KEY
echo $ANTHROPIC_API_KEY
```

### GitHub Rate Limits

The GitHub MCP server respects GitHub API rate limits. If you hit limits:
- Use a GitHub Personal Access Token (increases rate limit)
- Reduce the number of repositories searched (`--limit`)
- Add delays between requests

## Files

- `app/analyzers/github_mcp_client.py` - Connects to official GitHub MCP server
- `app/analyzers/ai_analyzer.py` - AI layer that intelligently uses MCP tools
- `app/analyzers/cve_exploit_pipeline.py` - Main pipeline orchestration
- `app/analyzers/static_analyzer.py` - Static code analysis

## References

- GitHub MCP Server: https://github.com/github/github-mcp-server
- MCP Protocol: https://modelcontextprotocol.io
- GitHub API: https://docs.github.com/en/rest
