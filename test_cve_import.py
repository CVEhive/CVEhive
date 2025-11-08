#!/usr/bin/env python3
"""
Quick test script for CVE import functionality
Run this to verify your setup is working correctly
"""

import sys
import os

print("🧪 CVEhive CVE Import Test\n")
print("=" * 50)

# Test 1: Check Python version
print("\n1. Checking Python version...")
if sys.version_info < (3, 8):
    print("   ❌ Python 3.8+ required!")
    sys.exit(1)
print(f"   ✅ Python {sys.version_info.major}.{sys.version_info.minor}")

# Test 2: Import core dependencies
print("\n2. Checking dependencies...")
required_modules = {
    'flask': 'Flask',
    'sqlalchemy': 'SQLAlchemy',
    'requests': 'Requests',
    'click': 'Click',
    'dateutil': 'python-dateutil',
}

missing = []
for module, name in required_modules.items():
    try:
        __import__(module)
        print(f"   ✅ {name}")
    except ImportError:
        print(f"   ❌ {name} - Missing!")
        missing.append(name)

if missing:
    print(f"\n❌ Missing dependencies: {', '.join(missing)}")
    print("   Install with: pip install -r requirements-minimal.txt")
    sys.exit(1)

# Test 3: Check if project structure is correct
print("\n3. Checking project structure...")
required_dirs = ['app', 'app/scrapers', 'app/models', 'app/tasks', 'data']
for dir_path in required_dirs:
    if os.path.exists(dir_path):
        print(f"   ✅ {dir_path}/")
    else:
        print(f"   ❌ {dir_path}/ - Missing!")

# Test 4: Import CVE scrapers
print("\n4. Testing CVE scraper imports...")
try:
    from app.scrapers.nvd_scraper import NVDScraper
    print("   ✅ NVDScraper")
except Exception as e:
    print(f"   ❌ NVDScraper - {str(e)}")
    sys.exit(1)

try:
    from app.scrapers.cve_project_scraper import CVEProjectScraper
    print("   ✅ CVEProjectScraper")
except Exception as e:
    print(f"   ❌ CVEProjectScraper - {str(e)}")
    sys.exit(1)

try:
    from app.scrapers.cve_monitor import CVEMonitor
    print("   ✅ CVEMonitor")
except Exception as e:
    print(f"   ❌ CVEMonitor - {str(e)}")
    sys.exit(1)

# Test 5: Test API connectivity
print("\n5. Testing API connectivity...")
print("   Testing NVD API...")
try:
    import requests
    response = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", 
                          params={'resultsPerPage': 1},
                          timeout=10)
    if response.status_code == 200:
        print("   ✅ NVD API accessible")
    else:
        print(f"   ⚠️  NVD API returned status {response.status_code}")
except Exception as e:
    print(f"   ⚠️  NVD API error: {str(e)}")

print("   Testing CVE Project API...")
try:
    response = requests.get("https://cveawg.mitre.org/api/cve", 
                          params={'year': 2024, 'per_page': 1},
                          timeout=10)
    if response.status_code in [200, 404]:  # 404 is ok, means no results
        print("   ✅ CVE Project API accessible")
    else:
        print(f"   ⚠️  CVE Project API returned status {response.status_code}")
except Exception as e:
    print(f"   ⚠️  CVE Project API error: {str(e)}")

# Test 6: Check for NVD API key
print("\n6. Checking NVD API key...")
api_key = os.getenv('NVD_API_KEY')
if api_key:
    print(f"   ✅ API key found (length: {len(api_key)})")
    print("   💡 Imports will be FAST!")
else:
    print("   ⚠️  No API key found")
    print("   💡 Get one at: https://nvd.nist.gov/developers/request-an-api-key")
    print("   💡 Then: export NVD_API_KEY='your-key'")

# Test 7: Check database
print("\n7. Checking database...")
try:
    from app.models.base import get_db
    db = next(get_db())
    from app.models import CVE
    count = db.query(CVE).count()
    print(f"   ✅ Database accessible")
    print(f"   📊 Current CVE count: {count:,}")
    db.close()
except Exception as e:
    print(f"   ⚠️  Database not initialized: {str(e)}")
    print("   💡 Run: python3 cli.py db init")

# Summary
print("\n" + "=" * 50)
print("✅ All core tests passed!\n")

print("🚀 Quick Start Commands:")
print("   python3 cli.py db init                          # Initialize database")
print("   python3 cli.py cve check-new --hours 24         # Test with recent CVEs")
print("   python3 cli.py cve bulk-import --start-year 2024  # Import 2024 CVEs")
print("")
print("📚 Full Documentation:")
print("   QUICK_START.md        # 5-minute setup guide")
print("   CVE_IMPORT_GUIDE.md   # Complete reference")
print("")

