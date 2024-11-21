import pytest
from src.etl.transformers import DataTransformer
from datetime import datetime, timezone

def test_transform_threat_actor():
    """Test transformation of threat actor data"""
    raw_data = {
        'stix_id': 'threat-actor--test-123',
        'name': 'Test Actor',
        'description': 'Test Description',
        'sophistication_level': 'advanced',
        'first_seen': '2023-01-01T00:00:00+00:00',
        'last_seen': '2023-12-31T23:59:59+00',
        'last_seen': '2023-12-31T23:59:59+00:00'
    }
    
    transformer = DataTransformer()
    transformed = transformer.transform_threat_actor(raw_data)
    
    assert transformed['stix_id'] == 'threat-actor--test-123'
    assert transformed['name'] == 'Test Actor'
    assert transformed['sophistication_level'] == 'advanced'
    assert isinstance(transformed['first_seen'], datetime)
    assert isinstance(transformed['last_seen'], datetime)