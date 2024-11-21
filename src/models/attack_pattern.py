from typing import Optional, List, Dict, Any
from datetime import datetime
from .base import BaseModel

class AttackPattern(BaseModel):
    """Modelo para patrones de ataque (MITRE ATT&CK)"""

    def __init__(
        self,
        stix_id: str,
        name: str,
        description: Optional[str] = None,
        mitre_id: Optional[str] = None,
        capec_id: Optional[str] = None,
        tactics: Optional[List[str]] = None,
        platforms: Optional[List[str]] = None,
        permissions_required: Optional[List[str]] = None,
        detection: Optional[str] = None
    ):
        super().__init__(stix_id, name, description)
        self.mitre_id = mitre_id
        self.capec_id = capec_id
        self.tactics = tactics or []
        self.platforms = platforms or []
        self.permissions_required = permissions_required or []
        self.detection = detection

    def to_dict(self) -> Dict[str, Any]:
        """Convertir el patrón de ataque a diccionario"""
        base_dict = super().to_dict()
        base_dict.update({
            'mitre_id': self.mitre_id,
            'capec_id': self.capec_id,
            'tactics': self.tactics,
            'platforms': self.platforms,
            'permissions_required': self.permissions_required,
            'detection': self.detection
        })
        return base_dict
