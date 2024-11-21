import os
import sys
from pathlib import Path
import sqlite3
from neo4j import GraphDatabase
from src.config.settings import Settings
from src.utils.logger import log

def setup_sqlite():
    """Configurar base de datos SQLite"""
    try:
        db_path = Settings.SQLITE_DB_PATH
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Crear tablas
        cursor.executescript("""
            -- Tabla de Threat Actors
            CREATE TABLE IF NOT EXISTS threat_actor (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stix_id TEXT UNIQUE,
                name TEXT NOT NULL,
                description TEXT,
                sophistication_level TEXT,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            -- Tabla de Malware
            CREATE TABLE IF NOT EXISTS malware (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stix_id TEXT UNIQUE,
                name TEXT NOT NULL,
                description TEXT,
                malware_type TEXT,
                is_family BOOLEAN DEFAULT FALSE,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            -- Tabla de Attack Patterns
            CREATE TABLE IF NOT EXISTS attack_pattern (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stix_id TEXT UNIQUE,
                name TEXT NOT NULL,
                description TEXT,
                mitre_id TEXT,
                capec_id TEXT,
                tactics TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            -- Tabla de Vulnerabilidades
            CREATE TABLE IF NOT EXISTS vulnerability (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stix_id TEXT UNIQUE,
                name TEXT NOT NULL,
                description TEXT,
                cve_id TEXT UNIQUE,
                cvss_score REAL,
                cvss_vector TEXT,
                published_date TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            -- Tabla de Indicadores
            CREATE TABLE IF NOT EXISTS indicator (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stix_id TEXT UNIQUE,
                type TEXT,
                pattern TEXT NOT NULL,
                pattern_type TEXT,
                valid_from TIMESTAMP,
                valid_until TIMESTAMP,
                confidence INTEGER CHECK (confidence BETWEEN 0 AND 100),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            -- Tablas de Relaciones
            CREATE TABLE IF NOT EXISTS actor_uses_malware (
                actor_id INTEGER,
                malware_id INTEGER,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                confidence INTEGER CHECK (confidence BETWEEN 0 AND 100),
                PRIMARY KEY (actor_id, malware_id),
                FOREIGN KEY (actor_id) REFERENCES threat_actor(id),
                FOREIGN KEY (malware_id) REFERENCES malware(id)
            );

            CREATE TABLE IF NOT EXISTS actor_uses_attack_pattern (
                actor_id INTEGER,
                attack_pattern_id INTEGER,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                confidence INTEGER CHECK (confidence BETWEEN 0 AND 100),
                PRIMARY KEY (actor_id, attack_pattern_id),
                FOREIGN KEY (actor_id) REFERENCES threat_actor(id),
                FOREIGN KEY (attack_pattern_id) REFERENCES attack_pattern(id)
            );

            CREATE TABLE IF NOT EXISTS malware_exploits_vulnerability (
                malware_id INTEGER,
                vulnerability_id INTEGER,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                confidence INTEGER CHECK (confidence BETWEEN 0 AND 100),
                PRIMARY KEY (malware_id, vulnerability_id),
                FOREIGN KEY (malware_id) REFERENCES malware(id),
                FOREIGN KEY (vulnerability_id) REFERENCES vulnerability(id)
            );

            CREATE TABLE IF NOT EXISTS indicator_indicates_malware (
                indicator_id INTEGER,
                malware_id INTEGER,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                confidence INTEGER CHECK (confidence BETWEEN 0 AND 100),
                PRIMARY KEY (indicator_id, malware_id),
                FOREIGN KEY (indicator_id) REFERENCES indicator(id),
                FOREIGN KEY (malware_id) REFERENCES malware(id)
            );

            -- Índices
            CREATE INDEX IF NOT EXISTS idx_threat_actor_stix_id ON threat_actor(stix_id);
            CREATE INDEX IF NOT EXISTS idx_malware_stix_id ON malware(stix_id);
            CREATE INDEX IF NOT EXISTS idx_attack_pattern_mitre_id ON attack_pattern(mitre_id);
            CREATE INDEX IF NOT EXISTS idx_vulnerability_cve_id ON vulnerability(cve_id);
            CREATE INDEX IF NOT EXISTS idx_indicator_pattern ON indicator(pattern);
        """)
        
        conn.commit()
        log.info("Base de datos SQLite configurada exitosamente")
        
    except Exception as e:
        log.error(f"Error configurando SQLite: {str(e)}")
        raise
    finally:
        if conn:
            conn.close()

def setup_neo4j():
    """Configurar base de datos Neo4j"""
    driver = None
    try:
        driver = GraphDatabase.driver(
            Settings.NEO4J_URI,
            auth=(Settings.NEO4J_USER, Settings.NEO4J_PASSWORD)
        )
        
        with driver.session() as session:
            # Crear constraints
            constraints = [
                "CREATE CONSTRAINT threat_actor_stix_id IF NOT EXISTS FOR (ta:ThreatActor) REQUIRE ta.stix_id IS UNIQUE",
                "CREATE CONSTRAINT malware_stix_id IF NOT EXISTS FOR (m:Malware) REQUIRE m.stix_id IS UNIQUE",
                "CREATE CONSTRAINT attack_pattern_stix_id IF NOT EXISTS FOR (ap:AttackPattern) REQUIRE ap.stix_id IS UNIQUE",
                "CREATE CONSTRAINT vulnerability_stix_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.stix_id IS UNIQUE",
                "CREATE CONSTRAINT indicator_stix_id IF NOT EXISTS FOR (i:Indicator) REQUIRE i.stix_id IS UNIQUE"
            ]
            
            for constraint in constraints:
                session.run(constraint)
            
            # Crear índices
            indexes = [
                "CREATE INDEX threat_actor_name_idx IF NOT EXISTS FOR (ta:ThreatActor) ON (ta.name)",
                "CREATE INDEX malware_name_idx IF NOT EXISTS FOR (m:Malware) ON (m.name)",
                "CREATE INDEX attack_pattern_mitre_idx IF NOT EXISTS FOR (ap:AttackPattern) ON (ap.mitre_id)",
                "CREATE INDEX vulnerability_cve_idx IF NOT EXISTS FOR (v:Vulnerability) ON (v.cve_id)",
                "CREATE INDEX indicator_pattern_idx IF NOT EXISTS FOR (i:Indicator) ON (i.pattern)"
            ]
            
            for index in indexes:
                session.run(index)
                
            log.info("Base de datos Neo4j configurada exitosamente")
            
    except Exception as e:
        log.error(f"Error configurando Neo4j: {str(e)}")
        raise
    finally:
        if driver:
            driver.close()

def verify_setup():
    """Verificar la configuración de las bases de datos"""
    try:
        # Verificar SQLite
        conn = sqlite3.connect(Settings.SQLITE_DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        log.info(f"Tablas SQLite creadas: {len(tables)}")
        conn.close()
        
        # Verificar Neo4j
        driver = GraphDatabase.driver(
            Settings.NEO4J_URI,
            auth=(Settings.NEO4J_USER, Settings.NEO4J_PASSWORD)
        )
        with driver.session() as session:
            result = session.run("CALL db.schema.visualization()")
            log.info("Conexión a Neo4j verificada")
        driver.close()
        
        return True
        
    except Exception as e:
        log.error(f"Error en verificación: {str(e)}")
        return False

def main():
    """Función principal para configurar las bases de datos"""
    try:
        print("Iniciando configuración de bases de datos...")
        
        # Configurar SQLite
        print("\nConfigurando SQLite...")
        setup_sqlite()
        
        # Configurar Neo4j
        print("\nConfigurando Neo4j...")
        setup_neo4j()
        
        # Verificar configuración
        print("\nVerificando configuración...")
        if verify_setup():
            print("\n✅ Configuración completada exitosamente")
        else:
            print("\n❌ Error en la configuración")
            
    except Exception as e:
        print(f"\n❌ Error durante la configuración: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()