import pytest
from src.models.threat_actor import ThreatActor
from datetime import datetime, UTC

def test_threat_actor_creation():
    """Test creating a threat actor instance"""
    actor = ThreatActor(
        stix_id="threat-actor--123",
        name="Test Actor",
        description="Test description",
        sophistication_level="advanced",
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC)
    )
    
    assert actor.stix_id == "threat-actor--123"
    assert actor.name == "Test Actor"
    assert actor.sophistication_level == "advanced"

def test_threat_actor_to_dict():
    """Test converting threat actor to dictionary"""
    first_seen = datetime.now(UTC)
    last_seen = datetime.now(UTC)
    
    actor = ThreatActor(
        stix_id="threat-actor--123",
        name="Test Actor",
        description="Test description",
        sophistication_level="advanced",
        first_seen=first_seen,
        last_seen=last_seen
    )
    
    actor_dict = actor.to_dict()
    
    assert actor_dict['stix_id'] == "threat-actor--123"
    assert actor_dict['name'] == "Test Actor"
    assert actor_dict['sophistication_level'] == "advanced"
    assert actor_dict['first_seen'] == first_seen
    assert actor_dict['last_seen'] == last_seen