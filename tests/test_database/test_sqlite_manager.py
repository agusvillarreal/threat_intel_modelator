import pytest
from src.database.sqlite_manager import SQLiteManager
from datetime import datetime, UTC

def test_create_tables(sqlite_manager):
    """Test table creation in SQLite"""
    with sqlite_manager.get_connection() as conn:
        cursor = conn.cursor()
        
        # Check if tables exist
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='threat_actor'
        """)
        
        assert cursor.fetchone() is not None

def test_insert_threat_actor(sqlite_manager):
    """Test inserting a threat actor"""
    actor_data = {
        'stix_id': 'threat-actor--test-123',
        'name': 'Test Actor',
        'description': 'Test Description',
        'sophistication_level': 'advanced',
        'first_seen': datetime.now(UTC),
        'last_seen': datetime.now(UTC)
    }
    
    actor_id = sqlite_manager.insert_threat_actor(actor_data)
    assert actor_id is not None
    
    # Verify insertion
    with sqlite_manager.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            'SELECT name FROM threat_actor WHERE id = ?',
            (actor_id,)
        )
        result = cursor.fetchone()
        assert result['name'] == 'Test Actor'