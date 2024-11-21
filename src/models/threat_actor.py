from typing import Optional, List
from datetime import datetime
from .base import BaseModel

class ThreatActor(BaseModel):
    def __init__(
        self,
        stix_id: str,
        name: str,
        description: Optional[str] = None,
        sophistication_level: Optional[str] = None,
        first_seen: Optional[datetime] = None,
        last_seen: Optional[datetime] = None
    ):
        super().__init__(stix_id, name, description)
        self.sophistication_level = sophistication_level
        self.first_seen = first_seen
        self.last_seen = last_seen

    def to_dict(self) -> dict:
        base_dict = super().to_dict()
        base_dict.update({
            'sophistication_level': self.sophistication_level,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen
        })
        return base_dict