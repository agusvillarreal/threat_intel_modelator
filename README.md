# Threat Intelligence Data Integration Framework

This framework provides a comprehensive solution for collecting, processing, and analyzing threat intelligence data from multiple sources including MISP, MITRE ATT&CK, and CAPEC. It features dual database storage using Neo4j for graph relationships and SQLite for structured data.

## Features

- Data collection from multiple threat intelligence sources:
  - MISP (Malware Information Sharing Platform)
  - MITRE ATT&CK Framework
  - Common Attack Pattern Enumeration and Classification (CAPEC)
- Dual database storage:
  - Neo4j for graph-based relationship analysis
  - SQLite for structured data and quick queries
- ETL pipeline for data transformation and loading
- Advanced threat intelligence analysis capabilities
- Comprehensive API for data querying and analysis

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/threat-intel-framework.git
cd threat-intel-framework
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Copy the environment template and fill in your API keys:
```bash
cp .env.example .env
```

## Environment Configuration

Create a `.env` file with the following variables:

```env
# Neo4j Configuration
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_password

# MISP Configuration
MISP_URL=https://your-misp-instance.com
MISP_API_KEY=your_misp_api_key

# MITRE ATT&CK Configuration
MITRE_API_URL=https://attack.mitre.org/api/

# Database Configuration
SQLITE_DB_PATH=data/threat_intel.db
```

## Usage

Basic usage example:

```python
from src.data_sources import MISPClient, MITREClient
from src.database import SQLiteManager, Neo4jManager
from src.etl import DataTransformer, DataLoader

# Initialize data sources
misp_client = MISPClient()
mitre_client = MITREClient()

# Initialize databases
sqlite_db = SQLiteManager()
neo4j_db = Neo4jManager()

# Collect and process data
threat_data = misp_client.get_recent_threats()
attack_patterns = mitre_client.get_attack_patterns()

# Transform and load data
transformer = DataTransformer()
loader = DataLoader(sqlite_db, neo4j_db)

processed_data = transformer.transform(threat_data)
loader.load(processed_data)
```

## Analysis Capabilities

The framework provides various analysis capabilities:

1. Recent Threat Actor Analysis:
```python
from src.analysis import ThreatAnalyzer

analyzer = ThreatAnalyzer()
recent_threats = analyzer.get_recent_threat_actors(months=6)
```

2. Vulnerability Analysis:
```python
top_vulnerabilities = analyzer.get_top_vulnerabilities(limit=5)
```

3. Attack Chain Analysis:
```python
attack_chains = analyzer.get_attack_chains(actor_name="APT123")
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Testing

Run tests using pytest:
```bash
pytest tests/
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
```