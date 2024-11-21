import pytest
from src.database.sqlite_manager import SQLiteManager
from src.database.neo4j_manager import Neo4jManager
from src.config.settings import Settings
import os
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

@pytest.fixture
def test_db_path(tmp_path):
    """Create a temporary database file"""
    db_file = tmp_path / "test_threat_intel.db"
    return str(db_file)

@pytest.fixture
def sqlite_manager(test_db_path):
    """Create a test SQLite manager"""
    original_path = Settings.SQLITE_DB_PATH
    Settings.SQLITE_DB_PATH = test_db_path
    manager = SQLiteManager()
    yield manager
    Settings.SQLITE_DB_PATH = original_path

@pytest.fixture
def neo4j_manager():
    """Create a test Neo4j manager"""
    manager = Neo4jManager()
    yield manager
    manager.close()
    
@pytest.fixture(autouse=True)
def clean_neo4j(neo4j_manager):
    """Clean Neo4j database before each test"""
    with neo4j_manager.driver.session() as session:
        session.run("MATCH (n) DETACH DELETE n")
    yield