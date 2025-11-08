# Quick Start Testing

## 1. Set up your environment (5 minutes)

```bash
# Copy environment template
cp .env.example .env

# Edit .env and add your GitHub token
nano .env
# Set: GITHUB_PERSONAL_ACCESS_TOKEN=ghp_your_token_here
```

**Get GitHub token:** https://github.com/settings/tokens (select `public_repo` permission)

## 2. Choose AI provider

Edit `.env` and choose ONE:

**Option A: Hugging Face (Free, runs locally)**
```bash
AI_MODEL_PROVIDER=huggingface
# No API key needed, but first run downloads ~13GB
```

**Option B: OpenAI (Paid, fast)**
```bash
AI_MODEL_PROVIDER=openai
OPENAI_API_KEY=sk-your-key-here
```

**Option C: Anthropic (Paid, fast)**
```bash
AI_MODEL_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-your-key-here
```

## 3. Install dependencies

```bash
# Install MCP SDK (required)
pip install mcp

# Install AI provider (choose one):

# For Hugging Face
pip install transformers torch

# For OpenAI
pip install openai

# For Anthropic
pip install anthropic
```

## 4. Pull GitHub MCP Server

```bash
docker pull ghcr.io/github/github-mcp-server
```

## 5. Run tests

```bash
python3 test_ai_mcp_integration.py
```

## 6. Test with real CVE

```bash
python3 cli.py analyze cve CVE-2021-44228 --limit 3
```

---

## Expected output

```
🧪 CVEhive AI Analyzer + MCP Integration Test
==================================================

🔍 Checking Requirements...

✅ GitHub token found
✅ MCP SDK installed
📊 AI Provider: huggingface
✅ Hugging Face dependencies installed
✅ Docker installed: Docker version 24.0.6
✅ Docker daemon running
✅ SQLAlchemy installed

==================================================
✅ All critical requirements met!

🔌 Testing MCP Connection...

Initializing MCP client...
Connecting to GitHub MCP server...
✅ MCP server connected!

Testing search_repositories...
✅ Search test successful!
```

---

## Troubleshooting

### "GITHUB_PERSONAL_ACCESS_TOKEN not set"
- Create token at: https://github.com/settings/tokens
- Add to `.env` file

### "MCP SDK not installed"
```bash
pip install mcp
```

### "Docker not found"
```bash
# Install Docker Desktop from docker.com
# Or download binary from: https://github.com/github/github-mcp-server/releases
```

### "MCP connection failed"
```bash
# Check Docker is running
docker ps

# Pull MCP image
docker pull ghcr.io/github/github-mcp-server
```

---

## What the test does

1. ✅ Checks all requirements are installed
2. ✅ Connects to GitHub MCP server
3. ✅ Initializes AI model
4. ✅ Tests repository search
5. ✅ Tests full pipeline (optional)

---

## Next steps after testing

```bash
# Import CVEs
python3 cli.py cve bulk_import --start-year 2023

# Analyze CVE
python3 cli.py analyze cve CVE-2024-12345

# View results
python3 cli.py db stats
```

