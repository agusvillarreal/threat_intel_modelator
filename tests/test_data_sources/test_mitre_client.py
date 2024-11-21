import pytest
from unittest.mock import patch, MagicMock
from src.data_sources.mitre_client import MITREClient

@pytest.fixture
def mitre_client():
    return MITREClient()

def test_get_attack_patterns(mitre_client):
    """Test obtención de patrones de ataque"""
    mock_response = {
        'data': [
            {
                'id': 'attack-pattern--123',
                'attributes': {
                    'name': 'Test Pattern',
                    'description': 'Test Description',
                    'external_references': [
                        {'external_id': 'T1234'}
                    ],
                    'kill_chain_phases': [
                        {'phase_name': 'initial-access'}
                    ]
                }
            }
        ]
    }
    
    with patch('requests.get') as mock_get:
        mock_get.return_value = MagicMock(
            json=lambda: mock_response,
            status_code=200
        )
        
        patterns = mitre_client.get_attack_patterns()
        assert len(patterns) == 1
        assert patterns[0]['mitre_id'] == 'T1234'