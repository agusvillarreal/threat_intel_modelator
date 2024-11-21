from typing import Optional, List, Dict, Any
from datetime import datetime
from .base import BaseModel

class Indicator(BaseModel):
    """Modelo para indicadores de amenazas"""

    def __init__(
        self,
        stix_id: str,
        name: str,
        pattern: str,
        pattern_type: str,
        description: Optional[str] = None,
        valid_from: Optional[datetime] = None,
        valid_until: Optional[datetime] = None,
        confidence: int = 0,
        labels: Optional[List[str]] = None,
        kill_chain_phases: Optional[List[str]] = None
    ):
        super().__init__(stix_id, name, description)
        self.pattern = pattern
        self.pattern_type = pattern_type
        self.valid_from = valid_from or datetime.utcnow()
        self.valid_until = valid_until
        self.confidence = min(max(confidence, 0), 100)  # Asegurar que esté entre 0 y 100
        self.labels = labels or []
        self.kill_chain_phases = kill_chain_phases or []

    def to_dict(self) -> Dict[str, Any]:
        """Convertir el indicador a diccionario"""
        base_dict = super().to_dict()
        base_dict.update({
            'pattern': self.pattern,
            'pattern_type': self.pattern_type,
            'valid_from': self.valid_from,
            'valid_until': self.valid_until,
            'confidence': self.confidence,
            'labels': self.labels,
            'kill_chain_phases': self.kill_chain_phases
        })
        return base_dict

    def is_valid(self) -> bool:
        """Verificar si el indicador es válido actualmente"""
        now = datetime.utcnow()
        if self.valid_until:
            return self.valid_from <= now <= self.valid_until
        return self.valid_from <= now
