from typing import Any, Dict, List
import hashlib
import json
from datetime import datetime

class DataHelper:
    @staticmethod
    def generate_stix_id(type_name: str, unique_data: Dict[str, Any]) -> str:
        """Generate a deterministic STIX ID based on input data"""
        data_str = json.dumps(unique_data, sort_keys=True)
        hash_object = hashlib.sha256(data_str.encode())
        return f"{type_name}--{hash_object.hexdigest()[:8]}"

    @staticmethod
    def merge_indicators(indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Merge duplicate indicators based on pattern"""
        merged = {}
        for indicator in indicators:
            pattern = indicator.get('pattern')
            if pattern in merged:
                # Update confidence if higher
                if indicator.get('confidence', 0) > merged[pattern].get('confidence', 0):
                    merged[pattern]['confidence'] = indicator['confidence']
                # Update valid_until if later
                if indicator.get('valid_until'):
                    current_valid = datetime.fromisoformat(merged[pattern]['valid_until'])
                    new_valid = datetime.fromisoformat(indicator['valid_until'])
                    if new_valid > current_valid:
                        merged[pattern]['valid_until'] = indicator['valid_until']
            else:
                merged[pattern] = indicator
        return list(merged.values())

    @staticmethod
    def calculate_threat_score(actor_data: Dict[str, Any]) -> float:
        """Calculate a threat score based on various factors"""
        score = 0.0
        
        # Base score from sophistication level
        sophistication_levels = {
            'novice': 0.2,
            'intermediate': 0.4,
            'advanced': 0.6,
            'expert': 0.8,
            'innovator': 1.0
        }
        score += sophistication_levels.get(actor_data.get('sophistication_level', '').lower(), 0.3)
        
        # Add score based on number of techniques
        techniques_count = len(actor_data.get('techniques', []))
        score += min(techniques_count / 20.0, 0.5)  # Cap at 0.5
        
        # Add score based on number of malware
        malware_count = len(actor_data.get('malware', []))
        score += min(malware_count / 10.0, 0.3)  # Cap at 0.3
        
        # Normalize final score to 0-100
        return min(score * 100, 100)