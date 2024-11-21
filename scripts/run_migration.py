# scripts/run_migration.py

import os
import sys
from pathlib import Path

# Agregar el directorio raíz al PATH
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from src.database import Neo4jManager, SQLiteManager
from src.etl.neo4j_to_sqlite import Neo4jToSQLiteETL
from src.utils.logger import log

def run_migration():
    """Ejecutar migración completa con reportes"""
    
    try:
        # Inicializar componentes
        neo4j_manager = Neo4jManager()
        sqlite_manager = SQLiteManager()
        etl = Neo4jToSQLiteETL(neo4j_manager, sqlite_manager)
        
        # Ejecutar migración
        print("Iniciando migración de datos...")
        etl.migrate_all_data()
        
        # Mostrar estadísticas
        stats = etl.get_migration_stats()
        print("\nEstadísticas de migración:")
        for table, count in stats.items():
            print(f"{table}: {count} registros")
        
        # Validar resultados
        print("\nValidando migración...")
        validation = etl.validate_migration()
        print("\nResultados de validación:")
        for check, result in validation.items():
            status = '✓' if result else '✗'
            print(f"{check}: {status}")
            
        # Guardar reporte
        report_path = project_root / "reports" / "migration_report.txt"
        report_path.parent.mkdir(exist_ok=True)
        
        with open(report_path, 'w') as f:
            f.write("=== Reporte de Migración ===\n\n")
            f.write("Estadísticas:\n")
            for table, count in stats.items():
                f.write(f"{table}: {count} registros\n")
            
            f.write("\nValidación:\n")
            for check, result in validation.items():
                status = '✓' if result else '✗'
                f.write(f"{check}: {status}\n")
                
        print(f"\nReporte guardado en: {report_path}")
        
    except Exception as e:
        log.error(f"Error durante la migración: {str(e)}")
        print(f"Error: {str(e)}")
        sys.exit(1)
        
    finally:
        neo4j_manager.close()

if __name__ == "__main__":
    run_migration()