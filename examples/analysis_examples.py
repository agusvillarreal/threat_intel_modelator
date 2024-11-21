from src.analysis import ThreatAnalyzer, RiskScorer, PatternAnalyzer
from src.database import Neo4jManager, SQLiteManager
from src.utils.logger import log
from datetime import datetime, timedelta

def analyze_high_risk_actors():
    """Analizar actores de alto riesgo"""
    sqlite_db = SQLiteManager()
    scorer = RiskScorer(sqlite_db)
    
    # Obtener actores de alto riesgo
    high_risk = scorer.get_high_risk_actors(threshold=75.0)
    print("\nActores de Alto Riesgo:")
    for actor in high_risk:
        print(f"- {actor['name']}: Score {actor['risk_score']:.2f}")

def analyze_attack_patterns():
    """Analizar patrones de ataque"""
    neo4j_db = Neo4jManager()
    pattern_analyzer = PatternAnalyzer(neo4j_db)
    
    try:
        # Encontrar patrones comunes
        common_patterns = pattern_analyzer.find_attack_patterns(min_occurrences=2)
        print("\nPatrones de Ataque Comunes:")
        for pattern in common_patterns:
            print(f"- {pattern['pattern_name']}")
            print(f"  Usado por: {', '.join(pattern['actors'])}")

        # Analizar secuencias de ataque
        sequences = pattern_analyzer.analyze_attack_sequences(lookback_days=180)
        print("\nSecuencias de Ataque Comunes:")
        for seq in sequences:
            print(f"- {seq['pattern1']} -> {seq['pattern2']}")
            print(f"  Observado {seq['actor_count']} veces")

    finally:
        neo4j_db.close()

def run_comprehensive_analysis():
    """Ejecutar análisis completo"""
    sqlite_db = SQLiteManager()
    neo4j_db = Neo4jManager()
    analyzer = ThreatAnalyzer()
    
    try:
        # Análisis temporal
        recent = analyzer.get_recent_threat_actors(months=3)
        print(f"\nAmenazas en los últimos 3 meses: {len(recent)}")

        # Análisis de relaciones
        related = analyzer.get_related_actors(indicator_threshold=2)
        print("\nActores Relacionados:")
        for rel in related:
            print(f"- {rel['actor_1']} <-> {rel['actor_2']}")
            print(f"  Indicadores comunes: {rel['common_indicators']}")

    finally:
        neo4j_db.close()

if __name__ == "__main__":
    print("=== Ejemplos de Análisis ===")
    analyze_high_risk_actors()
    analyze_attack_patterns()
    run_comprehensive_analysis()