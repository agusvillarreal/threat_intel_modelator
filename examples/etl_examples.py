import datetime
from src.etl import Neo4jToSQLiteETL
from src.database import Neo4jManager, SQLiteManager
from src.etl.validators import DataValidator
from src.utils.logger import log

def run_migration_example():
    """Ejemplo de migración de datos"""
    neo4j_db = Neo4jManager()
    sqlite_db = SQLiteManager()
    
    try:
        # Crear instancia ETL
        etl = Neo4jToSQLiteETL(neo4j_db, sqlite_db)
        
        # Ejecutar migración
        print("Iniciando migración...")
        etl.migrate_all_data()
        
        # Mostrar estadísticas
        stats = etl.get_migration_stats()
        print("\nEstadísticas de Migración:")
        for table, count in stats.items():
            print(f"{table}: {count} registros")
        
        # Validar migración
        validation = etl.validate_migration()
        print("\nResultados de Validación:")
        for check, result in validation.items():
            status = '✓' if result else '✗'
            print(f"{check}: {status}")
            
    finally:
        neo4j_db.close()

def validate_data_example():
    """Ejemplo de validación de datos"""
    validator = DataValidator()
    
    # Ejemplo de datos
    test_data = {
        'stix_id': 'threat-actor--123',
        'name': 'APT Test',
        'description': 'Test actor',
        'sophistication_level': 'advanced',
        'created': datetime.now(),
        'modified': datetime.now()
    }
    
    # Validar datos
    is_valid, validated_data = validator.validate(test_data, 'threat-actor')
    
    if is_valid:
        print("\nDatos válidos:")
        print(validated_data)
    else:
        print("\nDatos inválidos")

if __name__ == "__main__":
    print("=== Ejemplos de ETL ===")
    run_migration_example()
    validate_data_example()