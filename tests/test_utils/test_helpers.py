import pytest
from src.utils.helpers import DataHelper
from datetime import datetime

def test_generate_stix_id():
    """Test STIX ID generation"""
    data = {
        'name': 'Test Actor',
        'description': 'Test Description'
    }
    
    stix_id = DataHelper.generate_stix_id('threat-actor', data)
    assert stix_id.startswith('threat-actor--')
    assert len(stix_id) > 20  # Verificar que el ID tenga una longitud razonable

def test_merge_indicators():
    """Test merging of duplicate indicators"""
    indicators = [
        {
            'pattern': '[file:hashes.md5 = "d41d8cd98f00b204e9800998ecf8427e"]',
            'confidence': 80,
            'valid_until': '2023-12-31T23:59:59+00:00'
        },
        {
            'pattern': '[file:hashes.md5 = "d41d8cd98f00b204e9800998ecf8427e"]',
            'confidence': 90,
            'valid_until': '2024-01-31T23:59:59+00:00'
        }
    ]
    
    merged = DataHelper.merge_indicators(indicators)
    assert len(merged) == 1
    assert merged[0]['confidence'] == 90
    assert merged[0]['valid_until'] == '2024-01-31T23:59:59+00:00'