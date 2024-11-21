from typing import Dict, Any, List
from collections import defaultdict
from src.database.neo4j_manager import Neo4jManager
from src.utils.logger import log

class PatternAnalyzer:
    def __init__(self, neo4j_manager: Neo4jManager):
        self.neo4j_manager = neo4j_manager

    def find_attack_patterns(self, min_occurrences: int = 2) -> List[Dict[str, Any]]:
        """Find common attack patterns across threat actors"""
        with self.neo4j_manager.driver.session() as session:
            query = """
            MATCH (ta:ThreatActor)-[:USES]->(ap:AttackPattern)
            WITH ap, COUNT(DISTINCT ta) as actor_count
            WHERE actor_count >= $min_occurrences
            MATCH (ta:ThreatActor)-[:USES]->(ap)
            RETURN 
                ap.name as pattern_name,
                ap.mitre_id as mitre_id,
                actor_count,
                COLLECT(DISTINCT ta.name) as actors
            ORDER BY actor_count DESC
            """
            
            result = session.run(query, min_occurrences=min_occurrences)
            return [dict(record) for record in result]

    def analyze_attack_sequences(self, lookback_days: int = 180) -> List[Dict[str, Any]]:
        """Analyze sequences of attack patterns used together"""
        with self.neo4j_manager.driver.session() as session:
            query = """
            MATCH (ta:ThreatActor)-[:USES]->(ap1:AttackPattern)
            MATCH (ta)-[:USES]->(ap2:AttackPattern)
            WHERE ap1 <> ap2
            AND ta.first_seen >= datetime() - duration({days: $lookback_days})
            WITH ap1, ap2, COUNT(DISTINCT ta) as actor_count
            WHERE actor_count >= 2
            RETURN 
                ap1.name as pattern1,
                ap2.name as pattern2,
                actor_count,
                ap1.mitre_id as mitre_id1,
                ap2.mitre_id as mitre_id2
            ORDER BY actor_count DESC
            LIMIT 20
            """
            
            result = session.run(query, lookback_days=lookback_days)
            return [dict(record) for record in result]