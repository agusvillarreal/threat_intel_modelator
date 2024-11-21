# src/etl/base_etl.py

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Generator
from datetime import datetime
from src.utils.logger import log
from src.database import SQLiteManager, Neo4jManager

class BaseETL(ABC):
    """Clase base para todas las operaciones ETL"""
    
    def __init__(
        self,
        sqlite_manager: Optional[SQLiteManager] = None,
        neo4j_manager: Optional[Neo4jManager] = None
    ):
        self.sqlite = sqlite_manager
        self.neo4j = neo4j_manager
        self.batch_size = 1000
        self.stats = {
            'processed': 0,
            'failed': 0,
            'skipped': 0,
            'start_time': None,
            'end_time': None
        }

    @abstractmethod
    def extract(self, **kwargs) -> List[Dict[str, Any]]:
        """Extraer datos de la fuente"""
        pass

    @abstractmethod
    def transform(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Transformar los datos al formato requerido"""
        pass

    @abstractmethod
    def load(self, data: List[Dict[str, Any]]) -> bool:
        """Cargar los datos en el destino"""
        pass

    def process(self, **kwargs) -> Dict[str, Any]:
        """Ejecutar el proceso ETL completo"""
        try:
            self.stats['start_time'] = datetime.now()
            log.info("Iniciando proceso ETL")

            # Extracción
            raw_data = self.extract(**kwargs)
            log.info(f"Extraídos {len(raw_data)} registros")

            # Transformación
            transformed_data = self.transform(raw_data)
            log.info(f"Transformados {len(transformed_data)} registros")

            # Carga
            self.load(transformed_data)
            log.info("Carga completada")

            self.stats['end_time'] = datetime.now()
            duration = self.stats['end_time'] - self.stats['start_time']
            self.stats['duration'] = str(duration)

            return self.stats

        except Exception as e:
            log.error(f"Error en proceso ETL: {str(e)}")
            raise

    def process_batch(
        self,
        data: List[Dict[str, Any]],
        batch_size: int = None
    ) -> Generator[List[Dict[str, Any]], None, None]:
        """
        Procesar datos en lotes
        
        Args:
            data: Lista de datos a procesar
            batch_size: Tamaño del lote (opcional)
            
        Returns:
            Generator que produce lotes de datos
        """
        batch_size = batch_size or self.batch_size
        for i in range(0, len(data), batch_size):
            batch = data[i:i + batch_size]
            yield batch