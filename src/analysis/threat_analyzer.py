from typing import List, Dict, Any
from datetime import datetime, UTC
from contextlib import contextmanager
from src.database.sqlite_manager import SQLiteManager
from src.database.neo4j_manager import Neo4jManager
from src.utils.logger import log

class ThreatAnalyzer:
    def __init__(self):
        self.sqlite_manager = SQLiteManager()
        self.neo4j_manager = Neo4jManager()

    def __del__(self):
        if hasattr(self, 'neo4j_manager'):
            self.neo4j_manager.close()

    @contextmanager
    def _get_neo4j_session(self):
        session = self.neo4j_manager.driver.session()
        try:
            yield session
        finally:
            session.close()

    def get_recent_threat_actors(self, months: int = 6) -> List[Dict[str, Any]]:
        """Get threat actors and their malware from the last X months"""
        try:
            with self.sqlite_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                # First check if we have any data
                cursor.execute("SELECT COUNT(*) as count FROM threat_actor")
                if cursor.fetchone()['count'] == 0:
                    log.info("No threat actors found in database")
                    return []
                
                query = """
                SELECT 
                    ta.name as actor_name,
                    m.name as malware_name,
                    aum.first_seen,
                    aum.confidence
                FROM threat_actor ta
                LEFT JOIN actor_uses_malware aum ON ta.id = aum.actor_id
                LEFT JOIN malware m ON aum.malware_id = m.id
                WHERE aum.first_seen >= datetime('now', ?)
                    OR aum.first_seen IS NULL
                ORDER BY aum.first_seen DESC
                """
                cursor.execute(query, (f'-{months} months',))
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            log.error(f"Error querying recent threat actors: {str(e)}")
            return []

    def get_attack_chains(self, actor_name: str) -> List[Dict[str, Any]]:
        """Get complete attack chains for a specific actor using Neo4j"""
        try:
            with self.neo4j_manager.driver.session() as session:
                # First check if the actor exists
                check_query = """
                MATCH (ta:ThreatActor {name: $actor_name})
                RETURN count(ta) as count
                """
                result = session.run(check_query, actor_name=actor_name)
                if result.single()['count'] == 0:
                    log.info(f"No threat actor found with name: {actor_name}")
                    return []
                
                # Then look for attack chains
                query = """
                MATCH path = (ta:ThreatActor {name: $actor_name})-[r:USES*1..5]->(target)
                WHERE NOT (target)-[:USES]->()
                RETURN path
                """
                result = session.run(query, actor_name=actor_name)
                
                attack_chains = []
                for record in result:
                    path = record['path']
                    chain = []
                    for node in path.nodes:
                        chain.append({
                            'type': list(node.labels)[0],
                            'name': node.get('name', 'Unknown'),
                            'stix_id': node.get('stix_id', 'Unknown')
                        })
                    attack_chains.append(chain)
                
                return attack_chains
                
        except Exception as e:
            log.error(f"Error querying attack chains: {str(e)}")
            return []

    def get_related_actors(self, indicator_threshold: int = 1) -> List[Dict[str, Any]]:
        """Find actors related through common indicators"""
        with self.sqlite_manager.get_connection() as conn:
            cursor = conn.cursor()
            query = """
            SELECT DISTINCT
                ta1.name as actor_1,
                ta2.name as actor_2,
                COUNT(DISTINCT i.id) as common_indicators
            FROM threat_actor ta1
            JOIN actor_uses_malware aum1 ON ta1.id = aum1.actor_id
            JOIN indicator_indicates_malware iim1 ON aum1.malware_id = iim1.malware_id
            JOIN indicator i ON iim1.indicator_id = i.id
            JOIN indicator_indicates_malware iim2 ON i.id = iim2.indicator_id
            JOIN actor_uses_malware aum2 ON iim2.malware_id = aum2.malware_id
            JOIN threat_actor ta2 ON aum2.actor_id = ta2.id
            WHERE ta1.id < ta2.id
            GROUP BY ta1.id, ta2.id, ta1.name, ta2.name
            HAVING COUNT(DISTINCT i.id) > ?
            ORDER BY common_indicators DESC
            """
            cursor.execute(query, (indicator_threshold,))
            return [dict(row) for row in cursor.fetchall()]
        
    def get_database_stats(self) -> Dict[str, int]:
        """Get basic statistics about the data in both databases"""
        stats = {'sqlite': {}, 'neo4j': {}}
        
        try:
            # Get SQLite stats
            with self.sqlite_manager.get_connection() as conn:
                cursor = conn.cursor()
                tables = ['threat_actor', 'malware', 'attack_pattern', 'vulnerability']
                for table in tables:
                    cursor.execute(f"SELECT COUNT(*) as count FROM {table}")
                    stats['sqlite'][table] = cursor.fetchone()['count']
                    
            # Get Neo4j stats
            with self.neo4j_manager.driver.session() as session:
                query = """
                MATCH (n)
                RETURN labels(n) as type, count(n) as count
                """
                result = session.run(query)
                for record in result:
                    stats['neo4j'][record['type'][0]] = record['count']
                    
        except Exception as e:
            log.error(f"Error getting database stats: {str(e)}")
            
        return stats