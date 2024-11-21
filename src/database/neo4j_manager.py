from neo4j import GraphDatabase
from typing import Dict, Any
from src.config.settings import Settings

class Neo4jManager:
    def __init__(self):
        self.uri = Settings.NEO4J_URI
        self.user = Settings.NEO4J_USER
        self.password = Settings.NEO4J_PASSWORD
        self.driver = GraphDatabase.driver(
            self.uri, auth=(self.user, self.password)
        )

    def close(self):
        self.driver.close()

    def create_threat_actor(self, actor: Dict[str, Any]):
        with self.driver.session() as session:
            return session.execute_write(self._create_threat_actor_tx, actor)

    @staticmethod
    def _create_threat_actor_tx(tx, actor):
        query = """
        MERGE (ta:ThreatActor {stix_id: $stix_id})
        SET ta.name = $name,
            ta.description = $description,
            ta.sophistication_level = $sophistication_level,
            ta.first_seen = datetime($first_seen),
            ta.last_seen = datetime($last_seen),
            ta.updated_at = datetime()
        RETURN ta
        """
        result = tx.run(query, **actor)
        return result.single()