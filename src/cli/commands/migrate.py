import click
from src.database import Neo4jManager, SQLiteManager
from src.etl.neo4j_to_sqlite import Neo4jToSQLiteETL
from src.utils.logger import log

@click.group(name='migrate')
def migrate_cli():
    """Comandos de migración de datos"""
    pass

@migrate_cli.command(name='neo4j-to-sqlite')
@click.option('--validate/--no-validate', default=True,
              help='Validar la migración después de completarla')
@click.option('--only', type=click.Choice(['threat-actors', 'malware', 'attack-patterns', 'all']),
              default='all', help='Migrar solo un tipo específico de datos')
@click.option('--batch-size', default=1000, help='Tamaño del lote para la migración')
def neo4j_to_sqlite(validate, only, batch_size):
    """Migrar datos desde Neo4j hacia SQLite"""
    try:
        # Inicializar managers
        neo4j_manager = Neo4jManager()
        sqlite_manager = SQLiteManager()
        
        # Crear instancia del ETL
        etl = Neo4jToSQLiteETL(neo4j_manager, sqlite_manager)
        
        click.echo("Iniciando migración desde Neo4j hacia SQLite...")
        
        if only == 'all':
            etl.migrate_all_data(batch_size=batch_size)
        elif only == 'threat-actors':
            etl.migrate_threat_actors(batch_size=batch_size)
        elif only == 'malware':
            etl.migrate_malware(batch_size=batch_size)
        elif only == 'attack-patterns':
            etl.migrate_attack_patterns(batch_size=batch_size)
            
        click.echo("Migración completada exitosamente.")
        
        # Mostrar estadísticas
        stats = etl.get_migration_stats()
        click.echo("\nEstadísticas de migración:")
        for table, count in stats.items():
            click.echo(f"{table}: {count} registros")
        
        # Validar si se solicitó
        if validate:
            click.echo("\nValidando migración...")
            validation = etl.validate_migration()
            click.echo("\nResultados de validación:")
            for check, result in validation.items():
                status = '✓' if result else '✗'
                click.echo(f"{check}: {status}")
                
    except Exception as e:
        log.error(f"Error durante la migración: {str(e)}")
        click.echo(f"Error: {str(e)}", err=True)
        
    finally:
        neo4j_manager.close()