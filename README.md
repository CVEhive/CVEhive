# CVEhive 🔍

A modern CVE search engine that automatically discovers, validates, and provides up-to-date proof-of-concept exploits for security researchers.

## 🎯 Features

- **Google-like Search Interface**: Clean, fast, and intuitive CVE search
- **Real-time CVE Monitoring**: Continuously pulls latest CVEs from multiple sources
- **Automated Exploit Discovery**: Searches GitHub and ExploitDB for exploit code
- **Exploit Validation**: Tests and validates exploit code in sandboxed environments
- **Advanced Filtering**: Search by severity, vendor, date, exploit availability
- **RESTful API**: Programmatic access for security tools and researchers
- **Validated Results**: Only shows working, tested exploits

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Backend API   │    │   Scrapers      │
│   (Flask)       │◄──►│   (FastAPI)     │◄──►│   (Celery)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │   PostgreSQL    │    │   Redis Queue   │
                       │   Database      │    │   & Cache       │
                       └─────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │   Docker        │
                       │   Sandbox       │
                       └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- PostgreSQL
- Redis
- Docker (for exploit validation)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd CVEhive
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. Initialize the database:
```bash
python -m app.database.init_db
```

5. Start the services:
```bash
# Start Redis and PostgreSQL
# Then start the application
python app.py
```

## 📊 Data Sources

- **NVD (NIST)**: Official CVE database
- **GitHub**: Exploit code repositories
- **ExploitDB**: Known exploit database
- **CVE Details**: Additional metadata and references

## 🔧 Configuration

Key environment variables:
- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `GITHUB_TOKEN`: GitHub API token for increased rate limits
- `SECRET_KEY`: Flask secret key
- `EXPLOIT_SANDBOX`: Docker configuration for exploit testing

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## ⚠️ Disclaimer

This tool is for educational and authorized security research only. Users are responsible for complying with applicable laws and regulations.

## 📄 License

MIT License - see LICENSE file for details. 