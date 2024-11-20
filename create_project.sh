#!/bin/bash

# Crear estructura de directorios principales
mkdir -p src/{config,data_sources,models,database,etl,analysis,cli/commands,utils}
mkdir -p tests/{test_data_sources,test_models,test_etl,test_analysis}
mkdir -p examples
mkdir -p scripts
mkdir -p reports
mkdir -p logs

# Crear archivos principales
touch README.md
touch requirements.txt
touch setup.py
touch .env.example
touch .gitignore

# Crear __init__.py en todos los directorios de Python
find . -type d -name "src" -o -name "tests" -o -name "examples" | while read dir; do
    touch "${dir}/__init__.py"
done

# Crear archivos en src/config
touch src/config/__init__.py
touch src/config/settings.py

# Crear archivos en src/data_sources
touch src/data_sources/__init__.py
touch src/data_sources/{misp_client,mitre_client,capec_client}.py

# Crear archivos en src/models
touch src/models/__init__.py
touch src/models/{base,threat_actor,attack_pattern,malware,vulnerability,indicator}.py

# Crear archivos en src/database
touch src/database/__init__.py
touch src/database/{sqlite_manager,neo4j_manager}.py

# Crear archivos en src/etl
touch src/etl/__init__.py
touch src/etl/{base_etl,transformers,loader,neo4j_to_sqlite,validators}.py

# Crear archivos en src/analysis
touch src/analysis/__init__.py
touch src/analysis/{threat_analyzer,risk_scorer,pattern_analyzer}.py

# Crear archivos en src/cli
touch src/cli/__init__.py
touch src/cli/cli.py
touch src/cli/commands/{__init__,collect,analyze,migrate}.py

# Crear archivos en src/utils
touch src/utils/__init__.py
touch src/utils/{logger,helpers,validators}.py

# Crear archivos en tests
touch tests/{test_data_sources,test_models,test_etl,test_analysis}/__init__.py
touch tests/test_etl/{test_neo4j_to_sqlite,test_validators}.py

# Crear archivos en examples
touch examples/{__init__,basic_usage,etl_examples,analysis_examples}.py

# Crear archivos en scripts
touch scripts/{setup_databases,run_migration}.py

# Crear contenido básico para .gitignore
cat > .gitignore << EOL
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual Environment
venv/
ENV/
env/

# IDE
.idea/
.vscode/
*.swp
*.swo

# Project specific
.env
logs/
reports/
*.db
*.log
EOL

# Crear contenido básico para requirements.txt
cat > requirements.txt << EOL
neo4j==5.14.1
python-dotenv==1.0.0
requests==2.31.0
pytest==7.4.3
pymisp==2.4.175
stix2==3.0.1
taxii2-client==2.3.0
python-dateutil==2.8.2
pandas==2.1.1
numpy==1.24.3
loguru==0.7.2
pydantic==2.4.2
aiohttp==3.8.5
cryptography==41.0.4
jsonschema==4.19.1
tqdm==4.66.1
click>=8.0.0
EOL

# Crear contenido básico para .env.example
cat > .env.example << EOL
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
EOL

# Crear contenido básico para setup.py
cat > setup.py << EOL
from setuptools import setup, find_packages

setup(
    name="threat_intel_framework",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        line.strip()
        for line in open("requirements.txt").readlines()
        if not line.startswith("#")
    ],
    entry_points={
        'console_scripts': [
            'threat-intel=src.cli.cli:cli',
        ],
    },
    author="Your Name",
    author_email="your.email@example.com",
    description="A framework for threat intelligence data integration and analysis",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/threat_intel_framework",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)
EOL

# Hacer ejecutables los scripts
chmod +x scripts/*.py

echo "Estructura del proyecto creada exitosamente"
echo "Para comenzar:"
echo "1. python -m venv venv"
echo "2. source venv/bin/activate"
echo "3. pip install -r requirements.txt"
echo "4. cp .env.example .env"
echo "5. Edita .env con tus credenciales"
