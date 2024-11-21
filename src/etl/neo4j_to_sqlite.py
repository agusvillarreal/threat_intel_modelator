# src/etl/neo4j_to_sqlite.py

from typing import Dict, Any, List, Optional
from datetime import datetime
from src.database.neo4j_manager import Neo4jManager
from src.database.sqlite_manager import SQLiteManager
from src.utils.logger import log
from src.utils.validators import DataValidator
from tqdm import tqdm

class Neo4jToSQLiteETL:
    """Clase para manejar la migración de datos desde Neo4j hacia SQLite"""
    
    def __init__(self, neo4j_manager: Neo4jManager, sqlite_manager: SQLiteManager):
        self.neo4j = neo4j_manager
        self.sqlite = sqlite_manager
        self.validator = DataValidator()
        self.stats = {
            'threat_actors': 0,
            'malware': 0,
            'attack_patterns': 0,
            'vulnerabilities': 0,
            'indicators': 0,
            'relationships': 0
        }
        
    def migrate_all_data(self):
        """Ejecutar la migración completa de todos los datos"""
        try:
            log.info("Iniciando migración completa de Neo4j a SQLite")
            
            # Migrar cada tipo de entidad
            self.migrate_threat_actors()
            self.migrate_malware()
            self.migrate_attack_patterns()
            self.migrate_vulnerabilities()
            self.migrate_indicators()
            
            # Migrar relaciones
            self.migrate_relationships()
            
            log.info("Migración completa finalizada exitosamente")
            
        except Exception as e:
            log.error(f"Error durante la migración: {str(e)}")
            raise

    def migrate_threat_actors(self):
        """Migrar actores de amenaza desde Neo4j a SQLite"""
        query = """
        MATCH (ta:ThreatActor)
        RETURN ta
        """
        
        try:
            with self.neo4j.driver.session() as session:
                result = session.run(query)
                actors = [record['ta'] for record in result]
                
                log.info(f"Migrando {len(actors)} actores de amenaza")
                
                with self.sqlite.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    for actor in tqdm(actors, desc="Migrando actores"):
                        # Convert Neo4j DateTime to string format
                        first_seen = actor.get('first_seen')
                        if first_seen:
                            first_seen = first_seen.isoformat()
                            
                        last_seen = actor.get('last_seen')
                        if last_seen:
                            last_seen = last_seen.isoformat()
                        
                        cursor.execute("""
                            INSERT OR REPLACE INTO threat_actor (
                                stix_id, name, description,
                                sophistication_level, first_seen, last_seen
                            ) VALUES (?, ?, ?, ?, ?, ?)
                        """, (
                            actor.get('stix_id'),
                            actor.get('name'),
                            actor.get('description'),
                            actor.get('sophistication_level'),
                            first_seen,
                            last_seen
                        ))
                    
                    conn.commit()
                    self.stats['threat_actors'] = len(actors)
                    
        except Exception as e:
            log.error(f"Error migrando actores de amenaza: {str(e)}")
            raise

    def migrate_malware(self):
        """Migrar malware desde Neo4j a SQLite"""
        query = """
        MATCH (m:Malware)
        RETURN m
        """
        
        try:
            with self.neo4j.driver.session() as session:
                result = session.run(query)
                malware_list = [record['m'] for record in result]
                
                log.info(f"Migrando {len(malware_list)} malware")
                
                with self.sqlite.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    for malware in tqdm(malware_list, desc="Migrando malware"):
                        first_seen = malware.get('first_seen')
                        if first_seen:
                            first_seen = first_seen.isoformat()
                            
                        last_seen = malware.get('last_seen')
                        if last_seen:
                            last_seen = last_seen.isoformat()
                        
                        cursor.execute("""
                            INSERT OR REPLACE INTO malware (
                                stix_id, name, description,
                                malware_type, is_family,
                                first_seen, last_seen
                            ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """, (
                            malware.get('stix_id'),
                            malware.get('name'),
                            malware.get('description'),
                            malware.get('malware_type'),
                            malware.get('is_family', False),
                            first_seen,
                            last_seen
                        ))
                    
                    conn.commit()
                    self.stats['malware'] = len(malware_list)
                    
        except Exception as e:
            log.error(f"Error migrando malware: {str(e)}")
            raise

    def migrate_attack_patterns(self):
        """Migrar patrones de ataque desde Neo4j a SQLite"""
        query = """
        MATCH (ap:AttackPattern)
        RETURN ap
        """
        
        try:
            with self.neo4j.driver.session() as session:
                result = session.run(query)
                patterns = [record['ap'] for record in result]
                
                log.info(f"Migrando {len(patterns)} patrones de ataque")
                
                with self.sqlite.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    for pattern in tqdm(patterns, desc="Migrando patrones"):
                        cursor.execute("""
                            INSERT OR REPLACE INTO attack_pattern (
                                stix_id, name, description,
                                mitre_id, capec_id, tactics
                            ) VALUES (?, ?, ?, ?, ?, ?)
                        """, (
                            pattern.get('stix_id'),
                            pattern.get('name'),
                            pattern.get('description'),
                            pattern.get('mitre_id'),
                            pattern.get('capec_id'),
                            ','.join(pattern.get('tactics', []))
                        ))
                    
                    conn.commit()
                    self.stats['attack_patterns'] = len(patterns)
                    
        except Exception as e:
            log.error(f"Error migrando patrones de ataque: {str(e)}")
            raise

    def migrate_vulnerabilities(self):
        """Migrar vulnerabilidades desde Neo4j a SQLite"""
        query = """
        MATCH (v:Vulnerability)
        RETURN v
        """
        
        try:
            with self.neo4j.driver.session() as session:
                result = session.run(query)
                vulnerabilities = [record['v'] for record in result]
                
                log.info(f"Migrando {len(vulnerabilities)} vulnerabilidades")
                
                with self.sqlite.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    for vuln in tqdm(vulnerabilities, desc="Migrando vulnerabilidades"):
                        published_date = vuln.get('published_date')
                        if published_date:
                            published_date = published_date.isoformat()
                            
                        cursor.execute("""
                            INSERT OR REPLACE INTO vulnerability (
                                stix_id, name, description,
                                cve_id, cvss_score, cvss_vector,
                                published_date
                            ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """, (
                            vuln.get('stix_id'),
                            vuln.get('name'),
                            vuln.get('description'),
                            vuln.get('cve_id'),
                            vuln.get('cvss_score'),
                            vuln.get('cvss_vector'),
                            published_date
                        ))
                    
                    conn.commit()
                    self.stats['vulnerabilities'] = len(vulnerabilities)
                    
        except Exception as e:
            log.error(f"Error migrando vulnerabilidades: {str(e)}")
            raise

    def migrate_indicators(self):
        """Migrar indicadores desde Neo4j a SQLite"""
        query = """
        MATCH (i:Indicator)
        RETURN i
        """
        
        try:
            with self.neo4j.driver.session() as session:
                result = session.run(query)
                indicators = [record['i'] for record in result]
                
                log.info(f"Migrando {len(indicators)} indicadores")
                
                with self.sqlite.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    for indicator in tqdm(indicators, desc="Migrando indicadores"):
                        valid_from = indicator.get('valid_from')
                        if valid_from:
                            valid_from = valid_from.isoformat()
                            
                        valid_until = indicator.get('valid_until')
                        if valid_until:
                            valid_until = valid_until.isoformat()
                        
                        cursor.execute("""
                            INSERT OR REPLACE INTO indicator (
                                stix_id, type, pattern,
                                pattern_type, valid_from, valid_until,
                                confidence
                            ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """, (
                            indicator.get('stix_id'),
                            indicator.get('type'),
                            indicator.get('pattern'),
                            indicator.get('pattern_type'),
                            valid_from,
                            valid_until,
                            indicator.get('confidence')
                        ))
                    
                    conn.commit()
                    self.stats['indicators'] = len(indicators)
                    
        except Exception as e:
            log.error(f"Error migrando indicadores: {str(e)}")
            raise

    def migrate_relationships(self):
        """Migrar todas las relaciones"""
        try:
            self._migrate_uses_relationships()
            self._migrate_indicates_relationships()
            self._migrate_exploits_relationships()
        except Exception as e:
            log.error(f"Error migrando relaciones: {str(e)}")
            raise

    def _migrate_uses_relationships(self):
        """Migrar relaciones 'USES'"""
        query = """
        MATCH (ta:ThreatActor)-[r:USES]->(m:Malware)
        RETURN ta.stix_id as actor_stix_id,
            m.stix_id as malware_stix_id,
            r.first_seen as first_seen,
            r.last_seen as last_seen,
            r.confidence as confidence
        """
        
        try:
            with self.neo4j.driver.session() as session:
                result = session.run(query)
                relationships = list(result)
                
                log.info(f"Migrando {len(relationships)} relaciones USES")
                
                with self.sqlite.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    for rel in tqdm(relationships, desc="Migrando relaciones"):
                        try:
                            # Get SQLite IDs for the entities
                            cursor.execute(
                                "SELECT id FROM threat_actor WHERE stix_id = ?",
                                (rel['actor_stix_id'],)
                            )
                            actor_result = cursor.fetchone()
                            
                            if not actor_result:
                                log.warning(f"Actor not found: {rel['actor_stix_id']}")
                                continue
                                
                            cursor.execute(
                                "SELECT id FROM malware WHERE stix_id = ?",
                                (rel['malware_stix_id'],)
                            )
                            malware_result = cursor.fetchone()
                            
                            if not malware_result:
                                log.warning(f"Malware not found: {rel['malware_stix_id']}")
                                continue
                            
                            first_seen = rel['first_seen']
                            if first_seen:
                                first_seen = first_seen.isoformat()
                                
                            last_seen = rel['last_seen']
                            if last_seen:
                                last_seen = last_seen.isoformat()
                            
                            cursor.execute("""
                                INSERT OR REPLACE INTO actor_uses_malware (
                                    actor_id, malware_id,
                                    first_seen, last_seen, confidence
                                ) VALUES (?, ?, ?, ?, ?)
                            """, (
                                actor_result[0],
                                malware_result[0],
                                first_seen,
                                last_seen,
                                rel['confidence']
                            ))
                            
                        except Exception as e:
                            log.error(f"Error processing relationship: {str(e)}")
                            continue
                    
                    conn.commit()
                    self.stats['relationships'] += len(relationships)
                    
        except Exception as e:
            log.error(f"Error migrando relaciones USES: {str(e)}")
            raise

    def _migrate_indicates_relationships(self):
        """Migrar relaciones 'INDICATES'"""
        query = """
        MATCH (i:Indicator)-[r:INDICATES]->(m:Malware)
        RETURN i.stix_id as indicator_stix_id,
               m.stix_id as malware_stix_id,
               r.first_seen as first_seen,
               r.last_seen as last_seen,
               r.confidence as confidence
        """
        
        try:
            with self.neo4j.driver.session() as session:
                result = session.run(query)
                relationships = list(result)
                
                log.info(f"Migrando {len(relationships)} relaciones INDICATES")
                
                with self.sqlite.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    for rel in tqdm(relationships, desc="Migrando relaciones"):
                        try:
                            cursor.execute("""
                                INSERT OR REPLACE INTO indicator_indicates_malware (
                                    indicator_id, malware_id,
                                    first_seen, last_seen, confidence
                                ) VALUES (
                                    (SELECT id FROM indicator WHERE stix_id = ?),
                                    (SELECT id FROM malware WHERE stix_id = ?),
                                    ?, ?, ?
                                )
                            """, (
                                rel['indicator_stix_id'],
                                rel['malware_stix_id'],
                                rel['first_seen'].isoformat() if rel['first_seen'] else None,
                                rel['last_seen'].isoformat() if rel['last_seen'] else None,
                                rel['confidence']
                            ))
                        except Exception as e:
                            log.error(f"Error en relación INDICATES: {str(e)}")
                            continue
                    
                    conn.commit()
                    self.stats['relationships'] += len(relationships)
                    
        except Exception as e:
            log.error(f"Error migrando relaciones INDICATES: {str(e)}")
            raise

    def _migrate_exploits_relationships(self):
        """Migrar relaciones 'EXPLOITS'"""
        query = """
        MATCH (m:Malware)-[r:EXPLOITS]->(v:Vulnerability)
        RETURN m.stix_id as malware_stix_id,
               v.stix_id as vuln_stix_id,
               r.first_seen as first_seen,
               r.last_seen as last_seen,
               r.confidence as confidence
        """
        
        try:
            with self.neo4j.driver.session() as session:
                result = session.run(query)
                relationships = list(result)
                
                log.info(f"Migrando {len(relationships)} relaciones EXPLOITS")
                
                with self.sqlite.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    for rel in tqdm(relationships, desc="Migrando relaciones"):
                        try:
                            cursor.execute("""
                                INSERT OR REPLACE INTO malware_exploits_vulnerability (
                                    malware_id, vulnerability_id,
                                    first_seen, last_seen, confidence
                                ) VALUES (
                                    (SELECT id FROM malware WHERE stix_id = ?),
                                    (SELECT id FROM vulnerability WHERE stix_id = ?),
                                    ?, ?, ?
                                )
                            """, (
                                rel['malware_stix_id'],
                                rel['vuln_stix_id'],
                                rel['first_seen'].isoformat() if rel['first_seen'] else None,
                                rel['last_seen'].isoformat() if rel['last_seen'] else None,
                                rel['confidence']
                            ))
                        except Exception as e:
                            log.error(f"Error en relación EXPLOITS: {str(e)}")
                            continue
                    
                    conn.commit()
                    self.stats['relationships'] += len(relationships)
                    
        except Exception as e:
            log.error(f"Error migrando relaciones EXPLOITS: {str(e)}")
            raise

    def get_migration_stats(self) -> Dict[str, int]:
        """Obtener estadísticas de la migración"""
        return self.stats

    def validate_migration(self) -> Dict[str, bool]:
        """Validar la integridad de la migración"""
        validation = {}
        
        try:
            # Validar conteos entre Neo4j y SQLite
            with self.neo4j.driver.session() as session:
                # Validar threat actors
                result = session.run("MATCH (ta:ThreatActor) RETURN COUNT(ta) as count")
                neo4j_actor_count = result.single()['count']
                
                with self.sqlite.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT COUNT(*) FROM threat_actor")
                    sqlite_actor_count = cursor.fetchone()[0]
                    
                    validation['threat_actors_match'] = neo4j_actor_count == sqlite_actor_count
                    
                    # Validar datos nulos en campos requeridos
                    cursor.execute("""
                        SELECT COUNT(*) FROM threat_actor 
                        WHERE name IS NULL OR stix_id IS NULL
                    """)
                    has_null_required = cursor.fetchone()[0] > 0
                    validation['required_fields_valid'] = not has_null_required
                    
                    # Validar foreign keys
                    cursor.execute("PRAGMA foreign_key_check")
                    fk_violations = cursor.fetchall()
                    validation['foreign_keys_valid'] = len(fk_violations) == 0
                    
                    validation['data_integrity'] = (
                        validation['required_fields_valid'] and 
                        validation['foreign_keys_valid']
                    )
                    
            return validation
                
        except Exception as e:
            log.error(f"Error durante la validación: {str(e)}")
            return {
                'error': str(e),
                'threat_actors_match': False,
                'data_integrity': False,
                'required_fields_valid': False,
                'foreign_keys_valid': False
            }

    def _validate_data_integrity(self) -> bool:
        """Validar la integridad de los datos migrados"""
        try:
            with self.sqlite.get_connection() as conn:
                cursor = conn.cursor()
                
                # Verificar foreign keys
                cursor.execute("PRAGMA foreign_key_check")
                fk_violations = cursor.fetchall()
                
                if fk_violations:
                    log.error(f"Encontradas {len(fk_violations)} violaciones de foreign key")
                    return False
                
                # Verificar datos nulos en campos requeridos
                queries = [
                    "SELECT COUNT(*) FROM threat_actor WHERE name IS NULL OR stix_id IS NULL",
                    "SELECT COUNT(*) FROM malware WHERE name IS NULL OR stix_id IS NULL",
                    "SELECT COUNT(*) FROM attack_pattern WHERE name IS NULL OR stix_id IS NULL",
                    "SELECT COUNT(*) FROM indicator WHERE pattern IS NULL OR stix_id IS NULL"
                ]
                
                for query in queries:
                    cursor.execute(query)
                    if cursor.fetchone()[0] > 0:
                        log.error(f"Encontrados registros con campos requeridos nulos: {query}")
                        return False
                
                return True
                
        except Exception as e:
            log.error(f"Error en validación de integridad: {str(e)}")
            return False

    def _validate_references(self) -> bool:
        """Validar referencias entre tablas"""
        try:
            with self.sqlite.get_connection() as conn:
                cursor = conn.cursor()
                
                # Validar referencias en relaciones
                queries = [
                    """
                    SELECT COUNT(*) FROM actor_uses_malware aum
                    LEFT JOIN threat_actor ta ON aum.actor_id = ta.id
                    LEFT JOIN malware m ON aum.malware_id = m.id
                    WHERE ta.id IS NULL OR m.id IS NULL
                    """,
                    """
                    SELECT COUNT(*) FROM indicator_indicates_malware iim
                    LEFT JOIN indicator i ON iim.indicator_id = i.id
                    LEFT JOIN malware m ON iim.malware_id = m.id
                    WHERE i.id IS NULL OR m.id IS NULL
                    """,
                    """
                    SELECT COUNT(*) FROM malware_exploits_vulnerability mev
                    LEFT JOIN malware m ON mev.malware_id = m.id
                    LEFT JOIN vulnerability v ON mev.vulnerability_id = v.id
                    WHERE m.id IS NULL OR v.id IS NULL
                    """
                ]
                
                for query in queries:
                    cursor.execute(query)
                    if cursor.fetchone()[0] > 0:
                        log.error(f"Encontradas referencias huérfanas: {query}")
                        return False
                
                return True
                
        except Exception as e:
            log.error(f"Error en validación de referencias: {str(e)}")
            return False