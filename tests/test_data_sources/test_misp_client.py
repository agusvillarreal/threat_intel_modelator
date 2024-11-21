import pytest
from unittest.mock import patch, MagicMock
from src.data_sources.misp_client import MISPClient
from datetime import datetime

@pytest.fixture
def misp_client():
    return MISPClient()

def test_get_recent_threats(misp_client):
    """Test obtención de amenazas recientes de MISP"""
    mock_response = {
        'response': [
            {
                'Event': {
                    'uuid': '123',
                    'info': 'Test Threat',
                    'date': '2023-01-01',
                    'timestamp': '1672531200',
                    'description': 'Test Description'
                }
            }
        ]
    }
    
    with patch('requests.get') as mock_get:
        mock_get.return_value = MagicMock(
            json=lambda: mock_response,
            status_code=200
        )
        
        threats = misp_client.get_recent_threats(days=30)
        assert len(threats) == 1
        assert threats[0]['name'] == 'Test Threat'

def test_error_handling(misp_client):
    """Test manejo de errores en MISP"""
    with patch('requests.get') as mock_get:
        mock_get.side_effect = Exception("API Error")
        
        with pytest.raises(Exception):
            misp_client.get_recent_threats()
