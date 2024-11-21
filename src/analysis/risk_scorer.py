from typing import Dict, Any, List
from src.database.sqlite_manager import SQLiteManager
from src.utils.logger import log

class RiskScorer:
    def __init__(self, sqlite_manager: SQLiteManager):
        self.sqlite_manager = sqlite_manager

    def calculate_actor_risk_score(self, actor_id: int) -> float:
        """Calculate risk score for a specific threat actor"""
        with self.sqlite_manager.get_connection() as conn:
            cursor = conn.cursor()
            
            # Get actor details
            cursor.execute("""
                SELECT 
                    ta.*,
                    COUNT(DISTINCT m.id) as malware_count,
                    COUNT(DISTINCT ap.id) as attack_pattern_count,
                    AVG(v.cvss_score) as avg_vuln_score
                FROM threat_actor ta
                LEFT JOIN actor_uses_malware aum ON ta.id = aum.actor_id
                LEFT JOIN malware m ON aum.malware_id = m.id
                LEFT JOIN actor_uses_attack_pattern auap ON ta.id = auap.actor_id
                LEFT JOIN attack_pattern ap ON auap.attack_pattern_id = ap.id
                LEFT JOIN malware_exploits_vulnerability mev ON m.id = mev.malware_id
                LEFT JOIN vulnerability v ON mev.vulnerability_id = v.id
                WHERE ta.id = ?
                GROUP BY ta.id
            """, (actor_id,))
            
            actor_data = dict(cursor.fetchone())
            
            # Calculate base score
            sophistication_weight = {
                'novice': 0.2,
                'intermediate': 0.4,
                'advanced': 0.6,
                'expert': 0.8,
                'innovator': 1.0
            }
            
            base_score = sophistication_weight.get(
                actor_data['sophistication_level'].lower(), 
                0.3
            ) * 100
            
            # Adjust score based on capabilities
            capability_score = (
                min(actor_data['malware_count'] / 10.0, 1.0) * 30 +
                min(actor_data['attack_pattern_count'] / 20.0, 1.0) * 30 +
                min((actor_data['avg_vuln_score'] or 0) / 10.0, 1.0) * 40
            )
            
            final_score = (base_score + capability_score) / 2
            return min(final_score, 100)  # Cap at 100

    def get_high_risk_actors(self, threshold: float = 75.0) -> List[Dict[str, Any]]:
        """Get all threat actors above a risk threshold"""
        with self.sqlite_manager.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('SELECT id, name FROM threat_actor')
            actors = cursor.fetchall()
            
            high_risk_actors = []
            for actor in actors:
                risk_score = self.calculate_actor_risk_score(actor['id'])
                if risk_score >= threshold:
                    high_risk_actors.append({
                        'id': actor['id'],
                        'name': actor['name'],
                        'risk_score': risk_score
                    })
            
            return sorted(
                high_risk_actors, 
                key=lambda x: x['risk_score'], 
                reverse=True
            )