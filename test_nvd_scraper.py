#!/usr/bin/env python3
"""
Quick test script for NVD scraper
Tests the basic functionality without importing thousands of CVEs
"""

import sys
from datetime import datetime, timedelta

print("[TEST] Testing NVD Scraper\n")
print("=" * 50)

# Test 1: Import the scraper
print("\n1. Testing NVDScraper import...")
try:
    from app.scrapers.nvd_scraper import NVDScraper
    print("   [PASS] NVDScraper imported successfully")
except Exception as e:
    print(f"   [FAIL] Import failed: {str(e)}")
    sys.exit(1)

# Test 2: Initialize scraper
print("\n2. Initializing scraper...")
try:
    scraper = NVDScraper()
    print("   [PASS] Scraper initialized")
    if scraper.api_key:
        print(f"   [PASS] API key loaded ({len(scraper.api_key)} chars)")
    else:
        print("   [WARN]  No API key (will be slower)")
except Exception as e:
    print(f"   [FAIL] Initialization failed: {str(e)}")
    sys.exit(1)

# Test 3: Test API connectivity
print("\n3. Testing NVD API connectivity...")
try:
    import requests
    response = requests.get(
        scraper.base_url,
        params={'resultsPerPage': 1},
        headers=scraper.session.headers,
        timeout=10
    )
    if response.status_code == 200:
        print("   [PASS] NVD API is accessible")
    else:
        print(f"   [WARN]  NVD API returned status {response.status_code}")
except Exception as e:
    print(f"   [FAIL] API test failed: {str(e)}")
    sys.exit(1)

# Test 4: Fetch a single recent CVE
print("\n4. Testing fetch_recent_cves (last 7 days)...")
try:
    cves = scraper.fetch_recent_cves(days=7)
    print(f"   [PASS] Fetched {len(cves)} CVEs from last 7 days")
    if cves:
        print(f"   📋 Sample CVE: {cves[0].get('cve', {}).get('id', 'N/A')}")
except Exception as e:
    print(f"   [FAIL] Fetch failed: {str(e)}")
    sys.exit(1)

# Test 5: Test parsing
print("\n5. Testing CVE data parsing...")
try:
    if cves:
        parsed = scraper.parse_cve_data(cves[0])
        print(f"   [PASS] Parsed CVE: {parsed['cve_id']}")
        print(f"      Summary: {parsed['summary'][:60]}...")
        print(f"      CVSS Score: {parsed.get('cvss_v3_score') or parsed.get('cvss_v2_score') or 'N/A'}")
        print(f"      Severity: {parsed.get('severity', 'N/A')}")
    else:
        print("   [WARN]  No CVEs to parse (this is normal if no recent CVEs)")
except Exception as e:
    print(f"   [FAIL] Parsing failed: {str(e)}")
    sys.exit(1)

# Test 6: Test date range fetch
print("\n6. Testing fetch_cves_by_date_range...")
try:
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=1)
    cves_range = scraper.fetch_cves_by_date_range(start_date, end_date)
    print(f"   [PASS] Fetched {len(cves_range)} CVEs from date range")
except Exception as e:
    print(f"   [FAIL] Date range fetch failed: {str(e)}")
    sys.exit(1)

# Test 7: Database connection (if available)
print("\n7. Testing database connection...")
try:
    from app.models.base import get_db
    from app.models import CVE
    db = next(get_db())
    count = db.query(CVE).count()
    print(f"   [PASS] Database accessible")
    print(f"   [INFO] Current CVE count: {count:,}")
    db.close()
except Exception as e:
    print(f"   [WARN]  Database not initialized: {str(e)}")
    print("   [TIP] Run: python3 cli.py db init")

print("\n" + "=" * 50)
print("[PASS] All NVD scraper tests passed!\n")

print("[RUN] Next Steps:")
print("   1. python3 cli.py db init                    # Initialize database")
print("   2. python3 cli.py cve check-new --hours 24   # Import recent CVEs")
print("   3. python3 cli.py db stats                   # Check what was imported")
print("   4. python3 cli.py cve bulk-import --start-year 2024  # Import full year")
print("")

