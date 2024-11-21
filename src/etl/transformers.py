from typing import Dict, Any, List
from datetime import datetime

class DataTransformer:
    @staticmethod
    def transform_threat_actor(raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform raw threat actor data into standardized format"""
        return {
            'stix_id': raw_data.get('stix_id'),
            'name': raw_data.get('name'),
            'description': raw_data.get('description'),
            'sophistication_level': raw_data.get('sophistication_level'),
            'first_seen': datetime.fromisoformat(raw_data.get('first_seen', '')),
            'last_seen': datetime.fromisoformat(raw_data.get('last_seen', ''))
        }