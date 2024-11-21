import sqlite3
from typing import List, Dict, Any
from contextlib import contextmanager
from datetime import datetime
from src.config.settings import Settings

class SQLiteManager:
    def __init__(self):
        self.db_path = Settings.SQLITE_DB_PATH
        # Register datetime adapter
        sqlite3.register_adapter(datetime, lambda dt: dt.isoformat())
        sqlite3.register_converter("TIMESTAMP", lambda dt: datetime.fromisoformat(dt.decode()))
        self._create_tables()

    @contextmanager
    def get_connection(self):
        conn = sqlite3.connect(
            self.db_path,
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES
        )
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _create_tables(self):
        """Create all necessary database tables"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Enable foreign keys
            cursor.execute("PRAGMA foreign_keys = ON")
            
            # Create tables
            cursor.executescript('''
                -- Threat Actor table
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

                -- Malware table
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

                -- Relationship table: Actor uses Malware
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

                -- Create indexes for better query performance
                CREATE INDEX IF NOT EXISTS idx_threat_actor_stix_id ON threat_actor(stix_id);
                CREATE INDEX IF NOT EXISTS idx_malware_stix_id ON malware(stix_id);
                CREATE INDEX IF NOT EXISTS idx_actor_uses_malware_dates ON actor_uses_malware(first_seen, last_seen);
            ''')
            
            conn.commit()

    def insert_threat_actor(self, actor: Dict[str, Any]) -> int:
        """
        Insert a threat actor into the database.
        
        Args:
            actor: Dictionary containing threat actor data
                Required keys: stix_id, name
                Optional keys: description, sophistication_level, first_seen, last_seen
        
        Returns:
            The ID of the inserted record
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO threat_actor (
                    stix_id, name, description, sophistication_level,
                    first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                actor['stix_id'],
                actor['name'],
                actor.get('description'),
                actor.get('sophistication_level'),
                actor.get('first_seen'),
                actor.get('last_seen')
            ))
            conn.commit()
            return cursor.lastrowid

    def insert_malware(self, malware: Dict[str, Any]) -> int:
        """
        Insert malware into the database.
        
        Args:
            malware: Dictionary containing malware data
                Required keys: stix_id, name
                Optional keys: description, malware_type, is_family, first_seen, last_seen
        
        Returns:
            The ID of the inserted record
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO malware (
                    stix_id, name, description, malware_type,
                    is_family, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                malware['stix_id'],
                malware['name'],
                malware.get('description'),
                malware.get('malware_type'),
                malware.get('is_family', False),
                malware.get('first_seen'),
                malware.get('last_seen')
            ))
            conn.commit()
            return cursor.lastrowid

    def insert_actor_uses_malware(self, relationship: Dict[str, Any]) -> bool:
        """
        Create a relationship between a threat actor and malware.
        
        Args:
            relationship: Dictionary containing relationship data
                Required keys: actor_id, malware_id
                Optional keys: first_seen, last_seen, confidence
        
        Returns:
            True if successful
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO actor_uses_malware (
                    actor_id, malware_id, first_seen, last_seen, confidence
                ) VALUES (?, ?, ?, ?, ?)
            ''', (
                relationship['actor_id'],
                relationship['malware_id'],
                relationship.get('first_seen'),
                relationship.get('last_seen'),
                relationship.get('confidence', 50)
            ))
            conn.commit()
            return True