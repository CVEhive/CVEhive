# Testing Guide: AI Analyzer + MCP Integration

## Quick Start

### 1. Set up environment

Copy the example environment file and configure it:

```bash
cp .env.example .env
```

Edit `.env` and set:
- `GITHUB_PERSONAL_ACCESS_TOKEN` - Your GitHub token
- `AI_MODEL_PROVIDER` - Choose: `huggingface`, `openai`, or `anthropic`
- Additional API keys if using OpenAI or Anthropic

### 2. Install dependencies

```bash
# Install Python dependencies
pip install -r requirements.txt

# Pull GitHub MCP Server (Docker)
docker pull ghcr.io/github/github-mcp-server
```

### 3. Run test script

```bash
python3 test_ai_mcp_integration.py
```

---

## Detailed Setup

### GitHub Token

1. Go to https://github.com/settings/tokens
2. Click "Generate new token (classic)"
3. Name: `CVEhive MCP Access`
4. Permissions: Select `public_repo`
5. Generate token
6. Copy token and add to `.env`:
   ```
   GITHUB_PERSONAL_ACCESS_TOKEN=ghp_your_token_here
   ```

### AI Provider Setup

Choose one option:

#### Option 1: Hugging Face (Open Source)

**Pros:** Free, runs locally, full control  
**Cons:** Large download (~13GB), slow without GPU

```bash
# Install dependencies
pip install transformers torch

# Configure in .env
AI_MODEL_PROVIDER=huggingface
AI_MODEL_NAME=deepseek-ai/deepseek-coder-6.7b-instruct
```

First run will download the model automatically.

#### Option 2: OpenAI API

**Pros:** Fast, high quality  
**Cons:** Paid service, requires API key

```bash
# Install dependencies
pip install openai

# Configure in .env
AI_MODEL_PROVIDER=openai
OPENAI_API_KEY=sk-your-key-here
OPENAI_MODEL=gpt-4
```

Get API key: https://platform.openai.com/api-keys

#### Option 3: Anthropic Claude

**Pros:** Fast, high quality  
**Cons:** Paid service, requires API key

```bash
# Install dependencies
pip install anthropic

# Configure in .env
AI_MODEL_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-your-key-here
ANTHROPIC_MODEL=claude-3-opus-20240229
```

Get API key: https://console.anthropic.com/

### GitHub MCP Server

**Option A: Docker (Recommended)**

```bash
# Pull image
docker pull ghcr.io/github/github-mcp-server

# Test it works
docker run -i --rm \
  -e GITHUB_PERSONAL_ACCESS_TOKEN=$GITHUB_PERSONAL_ACCESS_TOKEN \
  ghcr.io/github/github-mcp-server --help
```

**Option B: Binary**

1. Download: https://github.com/github/github-mcp-server/releases
2. Choose your platform (macOS, Linux, Windows)
3. Extract and make executable:
   ```bash
   chmod +x github-mcp-server
   mv github-mcp-server /usr/local/bin/
   ```

---

## Running Tests

### Test 1: Requirements Check

```bash
python3 test_ai_mcp_integration.py
```

This will check:
- GitHub token is set
- MCP SDK is installed
- AI dependencies are installed
- Docker is available
- Database is configured

### Test 2: MCP Connection

The test script will automatically test MCP connection:
- Connect to GitHub MCP server
- Test search_repositories tool
- Verify GitHub API access

### Test 3: AI Analyzer

Tests AI model initialization:
- Hugging Face: Loads model
- OpenAI: Verifies API key
- Anthropic: Verifies API key

### Test 4: Search Test (Optional)

Tests repository search with AI:
- AI generates search queries
- MCP searches GitHub
- Returns ranked results

### Test 5: Full Pipeline (Optional)

Tests complete pipeline:
1. AI/MCP discovery
2. AI analysis
3. Static analysis
4. Filtering
5. Save to database

---

## Troubleshooting

### MCP Connection Failed

**Error:** `Failed to connect to GitHub MCP server`

**Solutions:**
1. Check Docker is running:
   ```bash
   docker ps
   ```
2. Pull MCP image:
   ```bash
   docker pull ghcr.io/github/github-mcp-server
   ```
3. Verify GitHub token:
   ```bash
   echo $GITHUB_PERSONAL_ACCESS_TOKEN
   ```

### AI Model Not Loading

**Hugging Face:**
- Check disk space (model is ~13GB)
- First download takes time
- Try smaller model: `facebook/opt-350m`

**OpenAI:**
- Verify API key is valid
- Check credits: https://platform.openai.com/usage

**Anthropic:**
- Verify API key is valid
- Check credits: https://console.anthropic.com/

### Rate Limiting

**Error:** `rate limit exceeded`

**Solutions:**
1. Use GitHub token (increases rate limit)
2. Reduce `--limit` parameter
3. Add delays between requests
4. Wait for rate limit to reset

### Docker Not Available

**Solution:** Use binary instead

1. Download from releases
2. Set in `.env`:
   ```bash
   # In code, modify GitHubMCPClient
   client = GitHubMCPClient(
       mcp_server_path="/path/to/github-mcp-server",
       use_docker=False
   )
   ```

---

## Manual Testing

### Test MCP Connection Only

```python
from app.analyzers import GitHubMCPClient
import asyncio

async def test():
    client = GitHubMCPClient()
    result = await client.search_repositories("test", per_page=5)
    print(f"Found {len(result.get('items', []))} repositories")
    await client.close()

asyncio.run(test())
```

### Test AI Analyzer Only

```python
from app.analyzers import GitHubMCPClient, AIAnalyzer
import asyncio

async def test():
    client = GitHubMCPClient()
    analyzer = AIAnalyzer(client)
    repos = await analyzer.search_repositories_for_cve("CVE-2021-44228", limit=3)
    print(f"Found {len(repos)} repositories")
    await client.close()

asyncio.run(test())
```

### Test with CLI

```bash
# Quick test with well-known CVE
python3 cli.py analyze cve CVE-2021-44228 --limit 3

# Batch test
python3 cli.py analyze batch --severity CRITICAL --limit 5
```

---

## Performance Notes

### Hugging Face (Local)

- **First run:** 10-30 minutes (model download)
- **Subsequent runs:** 
  - With GPU: ~30 seconds per CVE
  - Without GPU: ~5-10 minutes per CVE
- **Memory:** 8-16GB RAM recommended

### OpenAI API

- **Speed:** ~5-10 seconds per CVE
- **Cost:** ~$0.01-0.05 per CVE (GPT-4)
- **Rate limits:** 3500 requests/min (Tier 1)

### Anthropic Claude

- **Speed:** ~5-10 seconds per CVE
- **Cost:** ~$0.01-0.05 per CVE
- **Rate limits:** Varies by tier

---

## Next Steps

After successful testing:

1. **Import CVEs:**
   ```bash
   python3 cli.py cve bulk_import --start-year 2021
   ```

2. **Analyze CVEs:**
   ```bash
   python3 cli.py analyze batch --severity CRITICAL --limit 10
   ```

3. **View results:**
   ```bash
   python3 cli.py db stats
   ```

4. **Develop dynamic analysis** (next stage)

---

## Support

- Setup issues: See `MCP_SETUP.md`
- Architecture: See `IMPLEMENTATION_SUMMARY.md`
- Pipeline details: See `MCP_PIPELINE_SUMMARY.md`
- GitHub MCP Server: https://github.com/github/github-mcp-server

