import click
import json
from datetime import datetime
from src.analysis import ThreatAnalyzer, RiskScorer, PatternAnalyzer
from src.database import Neo4jManager, SQLiteManager
from src.utils.logger import log

@click.group(name='analyze')
def analyze_cli():
    """Comandos de análisis de amenazas"""
    pass

@analyze_cli.command(name='recent-threats')
@click.option('--months', default=6, help='Número de meses hacia atrás para analizar')
@click.option('--output', type=click.Path(), help='Archivo para guardar resultados')
def analyze_recent_threats(months, output):
    """Analizar amenazas recientes"""
    try:
        analyzer = ThreatAnalyzer()
        threats = analyzer.get_recent_threat_actors(months=months)
        
        click.echo(f"\nAmenazas encontradas en los últimos {months} meses: {len(threats)}")
        
        for threat in threats:
            click.echo(f"\n- Actor: {threat['actor_name']}")
            click.echo(f"  Malware: {threat['malware_name']}")
            click.echo(f"  Primera vez visto: {threat['first_seen']}")
        
        if output:
            with open(output, 'w') as f:
                json.dump(threats, f, indent=2, default=str)
            click.echo(f"\nResultados guardados en: {output}")
            
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        log.error(f"Error en análisis de amenazas recientes: {str(e)}")

@analyze_cli.command(name='risk-assessment')
@click.option('--threshold', default=75.0, help='Umbral de riesgo (0-100)')
@click.option('--output', type=click.Path(), help='Archivo para guardar resultados')
def analyze_risk(threshold, output):
    """Analizar actores de alto riesgo"""
    try:
        sqlite_db = SQLiteManager()
        scorer = RiskScorer(sqlite_db)
        
        high_risk_actors = scorer.get_high_risk_actors(threshold=threshold)
        
        click.echo(f"\nActores de alto riesgo (threshold: {threshold}):")
        for actor in high_risk_actors:
            click.echo(f"\n- {actor['name']}")
            click.echo(f"  Score: {actor['risk_score']:.2f}")
        
        if output:
            with open(output, 'w') as f:
                json.dump(high_risk_actors, f, indent=2, default=str)
            click.echo(f"\nResultados guardados en: {output}")
            
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        log.error(f"Error en análisis de riesgo: {str(e)}")

@analyze_cli.command(name='attack-patterns')
@click.option('--min-occurrences', default=2, help='Número mínimo de ocurrencias')
@click.option('--output', type=click.Path(), help='Archivo para guardar resultados')
def analyze_patterns(min_occurrences, output):
    """Analizar patrones de ataque comunes"""
    neo4j_db = None
    try:
        neo4j_db = Neo4jManager()
        analyzer = PatternAnalyzer(neo4j_db)
        
        patterns = analyzer.find_attack_patterns(min_occurrences=min_occurrences)
        
        click.echo(f"\nPatrones de ataque (min. ocurrencias: {min_occurrences}):")
        for pattern in patterns:
            click.echo(f"\n- {pattern['pattern_name']}")
            click.echo(f"  MITRE ID: {pattern['mitre_id']}")
            click.echo(f"  Usado por: {', '.join(pattern['actors'])}")
        
        if output:
            with open(output, 'w') as f:
                json.dump(patterns, f, indent=2, default=str)
            click.echo(f"\nResultados guardados en: {output}")
            
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        log.error(f"Error en análisis de patrones: {str(e)}")
    finally:
        if neo4j_db:
            neo4j_db.close()