import pytest
from datetime import datetime
from src.etl.neo4j_to_sqlite import Neo4jToSQLiteETL
from src.database import Neo4jManager, SQLiteManager

@pytest.fixture
def etl_instance(neo4j_manager, sqlite_manager):
    return Neo4jToSQLiteETL(neo4j_manager, sqlite_manager)

def test_migrate_threat_actors(etl_instance, neo4j_manager):
    """Test migración de threat actors"""
    # Crear datos de prueba en Neo4j
    with neo4j_manager.driver.session() as session:
        session.run("""
            CREATE (ta:ThreatActor {
                stix_id: 'threat-actor--test',
                name: 'Test Actor',
                description: 'Test Description',
                sophistication_level: 'advanced',
                first_seen: datetime('2023-01-01'),
                last_seen: datetime('2023-12-31')
            })
        """)
    
    # Ejecutar migración
    etl_instance.migrate_threat_actors()
    
    # Verificar resultados en SQLite
    with etl_instance.sqlite.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM threat_actor WHERE stix_id = 'threat-actor--test'"
        )
        result = cursor.fetchone()
        
        assert result is not None
        assert result['name'] == 'Test Actor'
        assert result['sophistication_level'] == 'advanced'

def test_migrate_relationships(etl_instance, neo4j_manager):
    """Test migración de relaciones"""
    # Crear datos de prueba en Neo4j
    with neo4j_manager.driver.session() as session:
        session.run("""
            CREATE (ta:ThreatActor {
                stix_id: 'threat-actor--test',
                name: 'Test Actor'
            })
            CREATE (m:Malware {
                stix_id: 'malware--test',
                name: 'Test Malware'
            })
            CREATE (ta)-[:USES {
                first_seen: datetime('2023-01-01'),
                confidence: 85
            }]->(m)
        """)
    
    # First migrate the entities
    etl_instance.migrate_threat_actors()
    etl_instance.migrate_malware()
    
    # Then migrate relationships
    etl_instance.migrate_relationships()
    
    # Verify results
    with etl_instance.sqlite.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT aum.*
            FROM actor_uses_malware aum
            JOIN threat_actor ta ON aum.actor_id = ta.id
            JOIN malware m ON aum.malware_id = m.id
            WHERE ta.stix_id = 'threat-actor--test'
            AND m.stix_id = 'malware--test'
        """)
        result = cursor.fetchone()
        
        assert result is not None
        assert result['confidence'] == 85
        
def test_validation(etl_instance, neo4j_manager):
    """Test validación de migración"""
    # Create test data
    with neo4j_manager.driver.session() as session:
        session.run("""
            CREATE (ta:ThreatActor {
                stix_id: 'threat-actor--test',
                name: 'Test Actor'
            })
        """)
    
    # Execute migration
    etl_instance.migrate_all_data()
    
    # Verify validation
    validation = etl_instance.validate_migration()
    assert validation['threat_actors_match'] is True
    assert validation.get('error') is None  # Check no errors occurred