from datetime import datetime, UTC
from typing import Dict, Any, Optional

class BaseModel:
    """Clase base para todos los modelos de datos."""

    def __init__(
        self,
        stix_id: str,
        name: str,
        description: Optional[str] = None
    ):
        self.stix_id = stix_id
        self.name = name
        self.description = description
        self.created_at = datetime.now(UTC)
        self.updated_at = datetime.now(UTC)

    def to_dict(self) -> Dict[str, Any]:
        """Convertir el modelo a diccionario"""
        return {
            'stix_id': self.stix_id,
            'name': self.name,
            'description': self.description,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }

    def __str__(self) -> str:
        return f"{self.__class__.__name__}(stix_id={self.stix_id}, name={self.name})"

    def __repr__(self) -> str:
        return self.__str__()