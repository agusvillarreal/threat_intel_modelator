from typing import Dict, Any
from src.database.sqlite_manager import SQLiteManager
from src.database.neo4j_manager import Neo4jManager

class DataLoader:
    def __init__(
        self,
        sqlite_manager: SQLiteManager,
        neo4j_manager: Neo4jManager
    ):
        self.sqlite_manager = sqlite_manager
        self.neo4j_manager = neo4j_manager

    def load_threat_actor(self, actor_data: Dict[str, Any]):
        """Load threat actor data into both databases"""
        # Load into SQLite
        sqlite_id = self.sqlite_manager.insert_threat_actor(actor_data)
        
        # Load into Neo4j
        neo4j_node = self.neo4j_manager.create_threat_actor(actor_data)
        
        return {
            'sqlite_id': sqlite_id,
            'neo4j_node': neo4j_node
        }