import pytest
from unittest.mock import patch, MagicMock
from src.data_sources.capec_client import CAPECClient
import xml.etree.ElementTree as ET

@pytest.fixture
def capec_client():
    return CAPECClient()

def test_get_attack_patterns(capec_client):
    """Test obtención de patrones de ataque CAPEC"""
    mock_xml = """
    <Attack_Patterns>
        <Attack_Pattern ID="1">
            <Name>Test Pattern</Name>
            <Description>Test Description</Description>
            <Likelihood_Of_Attack>High</Likelihood_Of_Attack>
            <Typical_Severity>High</Typical_Severity>
            <Prerequisites>
                <Prerequisite>Test Prerequisite</Prerequisite>
            </Prerequisites>
            <Solutions_and_Mitigations>
                <Solution_or_Mitigation>Test Mitigation</Solution_or_Mitigation>
            </Solutions_and_Mitigations>
        </Attack_Pattern>
    </Attack_Patterns>
    """
    
    with patch('requests.get') as mock_get:
        mock_get.return_value = MagicMock(
            content=mock_xml.encode(),
            status_code=200
        )
        
        patterns = capec_client.get_attack_patterns()
        assert len(patterns) == 1
        assert patterns[0]['capec_id'] == '1'
        assert patterns[0]['name'] == 'Test Pattern'