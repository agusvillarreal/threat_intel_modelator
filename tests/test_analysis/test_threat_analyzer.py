import pytest
from datetime import datetime, timedelta, UTC
from src.analysis.threat_analyzer import ThreatAnalyzer

@pytest.fixture
def sample_data(sqlite_manager):
    """Insert sample data for testing analysis"""
    # Insert test threat actors
    actor1_data = {
        'stix_id': 'threat-actor--test-1',
        'name': 'Test Actor 1',
        'sophistication_level': 'advanced',
        'first_seen': datetime.now(UTC) - timedelta(days=30),
        'last_seen': datetime.now(UTC)
    }
    
    actor2_data = {
        'stix_id': 'threat-actor--test-2',
        'name': 'Test Actor 2',
        'sophistication_level': 'intermediate',
        'first_seen': datetime.now(UTC) - timedelta(days=60),
        'last_seen': datetime.now(UTC)
    }
    
    # Insert malware data
    malware1_data = {
        'stix_id': 'malware--test-1',
        'name': 'Test Malware 1',
        'malware_type': 'ransomware',
        'is_family': False,
        'first_seen': datetime.now(UTC) - timedelta(days=30),
        'last_seen': datetime.now(UTC)
    }
    
    # Insert actors and malware
    actor1_id = sqlite_manager.insert_threat_actor(actor1_data)
    actor2_id = sqlite_manager.insert_threat_actor(actor2_data)
    malware1_id = sqlite_manager.insert_malware(malware1_data)
    
    # Create relationships
    relationship1 = {
        'actor_id': actor1_id,
        'malware_id': malware1_id,
        'first_seen': datetime.now(UTC) - timedelta(days=25),
        'last_seen': datetime.now(UTC),
        'confidence': 85
    }
    
    sqlite_manager.insert_actor_uses_malware(relationship1)
    
    return {
        'actor1_id': actor1_id,
        'actor2_id': actor2_id,
        'malware1_id': malware1_id
    }

def test_get_recent_threat_actors(sqlite_manager, sample_data):
    """Test retrieving recent threat actors"""
    analyzer = ThreatAnalyzer()
    recent_actors = analyzer.get_recent_threat_actors(months=1)
    
    assert len(recent_actors) >= 1
    assert any(actor['actor_name'] == 'Test Actor 1' for actor in recent_actors)
    assert any(actor['malware_name'] == 'Test Malware 1' for actor in recent_actors)