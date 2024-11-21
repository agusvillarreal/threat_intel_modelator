import click
from datetime import datetime, timedelta
from src.data_sources import MISPClient, MITREClient, CAPECClient
from src.database import SQLiteManager, Neo4jManager
from src.etl import DataTransformer, DataLoader
from src.utils.logger import log

@click.group(name='collect')
def collect_cli():
    """Comandos de recolección de datos"""
    pass

@collect_cli.command(name='misp')
@click.option('--days', default=30, help='Días hacia atrás para recolectar')
@click.option('--validate/--no-validate', default=True,
              help='Validar datos antes de guardar')
def collect_misp(days, validate):
    """Recolectar datos de MISP"""
    try:
        client = MISPClient()
        sqlite_db = SQLiteManager()
        neo4j_db = Neo4jManager()
        
        click.echo(f"Recolectando datos de MISP de los últimos {days} días...")
        
        # Recolectar datos
        threats = client.get_recent_threats(days=days)
        click.echo(f"Encontradas {len(threats)} amenazas")
        
        if validate:
            transformer = DataTransformer()
            validated_threats = []
            with click.progressbar(threats, label='Validando datos') as threats_iter:
                for threat in threats_iter:
                    try:
                        transformed = transformer.transform_threat_actor(threat)
                        validated_threats.append(transformed)
                    except Exception as e:
                        log.warning(f"Error validando amenaza: {str(e)}")
            
            threats = validated_threats
        
        # Cargar datos
        loader = DataLoader(sqlite_db, neo4j_db)
        with click.progressbar(threats, label='Cargando datos') as threats_iter:
            for threat in threats_iter:
                try:
                    loader.load_threat_actor(threat)
                except Exception as e:
                    log.warning(f"Error cargando amenaza: {str(e)}")
        
        click.echo("Recolección completada exitosamente")
        
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        log.error(f"Error en recolección MISP: {str(e)}")

@collect_cli.command(name='mitre')
@click.option('--validate/--no-validate', default=True,
              help='Validar datos antes de guardar')
def collect_mitre(validate):
    """Recolectar datos de MITRE ATT&CK"""
    try:
        client = MITREClient()
        sqlite_db = SQLiteManager()
        neo4j_db = Neo4jManager()
        
        click.echo("Recolectando datos de MITRE ATT&CK...")
        
        # Recolectar patrones
        patterns = client.get_attack_patterns()
        click.echo(f"Encontrados {len(patterns)} patrones de ataque")
        
        if validate:
            transformer = DataTransformer()
            validated_patterns = []
            with click.progressbar(patterns, label='Validando datos') as patterns_iter:
                for pattern in patterns_iter:
                    try:
                        transformed = transformer.transform_attack_pattern(pattern)
                        validated_patterns.append(transformed)
                    except Exception as e:
                        log.warning(f"Error validando patrón: {str(e)}")
            
            patterns = validated_patterns
        
        # Cargar datos
        loader = DataLoader(sqlite_db, neo4j_db)
        with click.progressbar(patterns, label='Cargando datos') as patterns_iter:
            for pattern in patterns_iter:
                try:
                    loader.load_attack_pattern(pattern)
                except Exception as e:
                    log.warning(f"Error cargando patrón: {str(e)}")
        
        click.echo("Recolección completada exitosamente")
        
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        log.error(f"Error en recolección MITRE: {str(e)}")

@collect_cli.command(name='capec')
@click.option('--validate/--no-validate', default=True,
              help='Validar datos antes de guardar')
def collect_capec(validate):
    """Recolectar datos de CAPEC"""
    try:
        client = CAPECClient()
        sqlite_db = SQLiteManager()
        neo4j_db = Neo4jManager()
        
        click.echo("Recolectando datos de CAPEC...")
        
        # Recolectar patrones
        patterns = client.get_attack_patterns()
        click.echo(f"Encontrados {len(patterns)} patrones CAPEC")
        
        if validate:
            transformer = DataTransformer()
            validated_patterns = []
            with click.progressbar(patterns, label='Validando datos') as patterns_iter:
                for pattern in patterns_iter:
                    try:
                        transformed = transformer.transform_capec_pattern(pattern)
                        validated_patterns.append(transformed)
                    except Exception as e:
                        log.warning(f"Error validando patrón CAPEC: {str(e)}")
            
            patterns = validated_patterns
        
        # Cargar datos
        loader = DataLoader(sqlite_db, neo4j_db)
        with click.progressbar(patterns, label='Cargando datos') as patterns_iter:
            for pattern in patterns_iter:
                try:
                    loader.load_attack_pattern(pattern)
                except Exception as e:
                    log.warning(f"Error cargando patrón CAPEC: {str(e)}")
        
        click.echo("Recolección completada exitosamente")
        
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        log.error(f"Error en recolección CAPEC: {str(e)}")

@collect_cli.command(name='all')
@click.option('--days', default=30, help='Días hacia atrás para MISP')
@click.option('--validate/--no-validate', default=True,
              help='Validar datos antes de guardar')
def collect_all(days, validate):
    """Recolectar datos de todas las fuentes"""
    ctx = click.get_current_context()
    
    # Recolectar de MISP
    ctx.invoke(collect_misp, days=days, validate=validate)
    
    # Recolectar de MITRE
    ctx.invoke(collect_mitre, validate=validate)
    
    # Recolectar de CAPEC
    ctx.invoke(collect_capec, validate=validate)