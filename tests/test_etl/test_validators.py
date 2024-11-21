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
            SELECT aum.*, ta.stix_id as actor_stix_id, m.stix_id as malware_stix_id,
                   ta.name as actor_name, m.name as malware_name
            FROM actor_uses_malware aum
            JOIN threat_actor ta ON aum.actor_id = ta.id
            JOIN malware m ON aum.malware_id = m.id
            WHERE ta.stix_id = 'threat-actor--test'
            AND m.stix_id = 'malware--test'
        """)
        result = dict(cursor.fetchone())
        
        # Verify relationship data
        assert result is not None
        assert result['confidence'] == 85
        assert result['actor_stix_id'] == 'threat-actor--test'
        assert result['malware_stix_id'] == 'malware--test'
        assert result['actor_name'] == 'Test Actor'
        assert result['malware_name'] == 'Test Malware'

def test_validation(etl_instance):
    """Test validación de migración"""
    # Ejecutar migración
    etl_instance.migrate_all_data()
    
    # Verificar validación
    validation = etl_instance.validate_migration()
    assert validation['threat_actors_match'] is True
    assert validation['data_integrity'] is True

# tests/test_etl/test_validators.py

import pytest
from datetime import datetime
from src.etl.validators import DataValidator, ThreatActorValidator, MalwareValidator

def test_stix_id_validation():
    """Test validación de STIX ID"""
    validator = DataValidator()
    
    # Test caso válido
    valid_stix = 'threat-actor--123e4567-e89b-12d3-a456-426614174000'
    assert validator.validate_stix_id(valid_stix) is True
    
    # Test casos inválidos
    invalid_stix = 'not-a-stix-id'
    assert validator.validate_stix_id(invalid_stix) is False

def test_threat_actor_validation():
    """Test validación de Threat Actor"""
    validator = DataValidator()
    
    # Datos válidos
    valid_data = {
        'stix_id': 'threat-actor--123e4567-e89b-12d3-a456-426614174000',
        'name': 'Test Actor',
        'description': 'Test Description',
        'sophistication_level': 'advanced',
        'created': datetime.now(),
        'modified': datetime.now()
    }
    
    is_valid, validated_data = validator.validate(valid_data, 'threat-actor')
    assert is_valid is True
    assert validated_data['name'] == 'Test Actor'

    # Datos inválidos
    invalid_data = {
        'stix_id': 'invalid-id',
        'name': 'Test Actor',
        'sophistication_level': 'invalid_level',
        'created': datetime.now(),
        'modified': datetime.now()
    }
    
    is_valid, _ = validator.validate(invalid_data, 'threat-actor')
    assert is_valid is False

def test_batch_validation():
    """Test validación por lotes"""
    validator = DataValidator()
    
    batch_data = [
        {
            'stix_id': f'threat-actor--123e4567-e89b-12d3-a456-42661417400{i}',
            'name': f'Actor {i}',
            'description': f'Test description {i}',  # Add description as it's required
            'sophistication_level': 'advanced',
            'created': datetime.now(),
            'modified': datetime.now()
        }
        for i in range(3)
    ]
    
    valid_data = validator.validate_batch(batch_data, 'threat-actor')
    assert len(valid_data) == 3