from dotenv import load_dotenv
import os

load_dotenv()

class Settings:
    # Database settings
    SQLITE_DB_PATH = os.getenv('SQLITE_DB_PATH', 'data/threat_intel.db')
    NEO4J_URI = os.getenv('NEO4J_URI', 'bolt://localhost:7687')
    NEO4J_USER = os.getenv('NEO4J_USER', 'neo4j')
    NEO4J_PASSWORD = os.getenv('NEO4J_PASSWORD')

    # API Settings
    MISP_URL = os.getenv('MISP_URL')
    MISP_API_KEY = os.getenv('MISP_API_KEY')
    MITRE_API_URL = os.getenv('MITRE_API_URL')

# src/models/base.py
from datetime import datetime
from typing import Dict, Any, Optional

class BaseModel:
    def __init__(self, stix_id: str, name: str, description: Optional[str] = None):
        self.stix_id = stix_id
        self.name = name
        self.description = description
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        return {
            'stix_id': self.stix_id,
            'name': self.name,
            'description': self.description,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }