from typing import Dict, Any, Optional, List, Tuple, Union
from datetime import datetime
import re
from pydantic import BaseModel, Field, field_validator, ConfigDict
from src.utils.logger import log

class BaseDataValidator(BaseModel):
    """Base validator for common STIX fields"""
    model_config = ConfigDict(str_strip_whitespace=True, extra='allow')
    
    stix_id: str
    name: str
    description: str = ""
    created: Optional[datetime] = None
    modified: Optional[datetime] = None

    @field_validator('stix_id')
    @classmethod
    def validate_stix_id(cls, v: str) -> str:
        """Validate STIX ID format"""
        pattern = r'^[a-z-]+--[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
        if not re.match(pattern, v):
            raise ValueError(f'Invalid STIX ID format: {v}')
        return v

    @field_validator('created', 'modified')
    @classmethod
    def validate_timestamps(cls, v: Optional[datetime]) -> Optional[datetime]:
        """Validate timestamp fields"""
        if v and v > datetime.now():
            raise ValueError('Timestamp cannot be in the future')
        return v

class ThreatActorValidator(BaseDataValidator):
    """Validator for Threat Actor data"""
    sophistication_level: str = Field(default="unknown")
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    aliases: List[str] = Field(default_factory=list)
    
    @field_validator('sophistication_level')
    @classmethod
    def validate_sophistication(cls, v: str) -> str:
        valid_levels = ['none', 'minimal', 'intermediate', 'advanced', 'expert', 'innovator', 'unknown']
        if v.lower() not in valid_levels:
            raise ValueError(f'Invalid sophistication level: must be one of {valid_levels}')
        return v.lower()

    @field_validator('last_seen')
    @classmethod
    def validate_last_seen(cls, v: Optional[datetime], values: Dict[str, Any]) -> Optional[datetime]:
        first_seen = values.data.get('first_seen')
        if v and first_seen and v < first_seen:
            raise ValueError('last_seen cannot be before first_seen')
        return v

class MalwareValidator(BaseDataValidator):
    """Validator for Malware data"""
    malware_type: List[str] = Field(default_factory=list)
    is_family: bool = False
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    
    @field_validator('malware_type')
    @classmethod
    def validate_malware_types(cls, v: List[str]) -> List[str]:
        valid_types = {
            'ransomware', 'backdoor', 'trojan', 'virus',
            'worm', 'spyware', 'rootkit', 'botnet'
        }
        invalid_types = [t for t in v if t.lower() not in valid_types]
        if invalid_types:
            raise ValueError(f'Invalid malware types: {", ".join(invalid_types)}')
        return [t.lower() for t in v]

class IndicatorValidator(BaseDataValidator):
    """Validator for Indicator data"""
    pattern: str
    pattern_type: str
    valid_from: datetime
    valid_until: Optional[datetime] = None
    confidence: int = Field(ge=0, le=100)

    @field_validator('pattern')
    @classmethod
    def validate_pattern(cls, v: str) -> str:
        if not (v.startswith('[') and v.endswith(']')):
            raise ValueError('Pattern must be enclosed in square brackets')
        return v

    @field_validator('pattern_type')
    @classmethod
    def validate_pattern_type(cls, v: str) -> str:
        valid_types = ['stix', 'snort', 'yara', 'sigma']
        if v.lower() not in valid_types:
            raise ValueError(f'Invalid pattern type: must be one of {valid_types}')
        return v.lower()

class VulnerabilityValidator(BaseDataValidator):
    """Validator for Vulnerability data"""
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None
    published_date: Optional[datetime] = None

    @field_validator('cve_id')
    @classmethod
    def validate_cve_id(cls, v: Optional[str]) -> Optional[str]:
        if v:
            pattern = r'^CVE-\d{4}-\d{4,}$'
            if not re.match(pattern, v):
                raise ValueError('Invalid CVE ID format')
        return v

    @field_validator('cvss_vector')
    @classmethod
    def validate_cvss_vector(cls, v: Optional[str]) -> Optional[str]:
        if v:
            pattern = r'^CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]'
            if not re.match(pattern, v):
                raise ValueError('Invalid CVSS vector format')
        return v

class DataValidator:
    """Main validator class for handling all types of threat intelligence data"""
    
    def __init__(self):
        self.validators = {
            'threat-actor': ThreatActorValidator,
            'malware': MalwareValidator,
            'indicator': IndicatorValidator,
            'vulnerability': VulnerabilityValidator
        }
        self.validation_stats = {
            'processed': 0,
            'valid': 0,
            'invalid': 0,
            'errors': []
        }

    def validate_stix_id(self, stix_id: str) -> bool:
        """Validate STIX ID format"""
        try:
            BaseDataValidator(stix_id=stix_id, name="validation_only")
            return True
        except Exception:
            return False

    def validate(
        self,
        data: Dict[str, Any],
        data_type: str
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Validate a single data record
        
        Args:
            data: Dictionary containing the data to validate
            data_type: Type of data ('threat-actor', 'malware', etc.)
            
        Returns:
            Tuple of (is_valid, validated_data)
        """
        try:
            if data_type not in self.validators:
                raise ValueError(f'Unsupported data type: {data_type}')
            
            validator_class = self.validators[data_type]
            validated = validator_class(**data)
            
            self.validation_stats['processed'] += 1
            self.validation_stats['valid'] += 1
            
            return True, validated.model_dump()
            
        except Exception as e:
            self.validation_stats['processed'] += 1
            self.validation_stats['invalid'] += 1
            self.validation_stats['errors'].append({
                'data': data,
                'error': str(e)
            })
            log.error(f"Error de validación: {str(e)}")
            return False, None

    def validate_batch(
        self,
        data_list: List[Dict[str, Any]],
        data_type: str
    ) -> List[Dict[str, Any]]:
        """
        Validate a batch of data records
        
        Args:
            data_list: List of dictionaries containing the data to validate
            data_type: Type of data ('threat-actor', 'malware', etc.)
            
        Returns:
            List of validated data dictionaries
        """
        return [
            validated_data for is_valid, validated_data 
            in [self.validate(item, data_type) for item in data_list]
            if is_valid and validated_data is not None
        ]

    def get_validation_report(self) -> Dict[str, Any]:
        """Get a report of validation statistics"""
        return {
            'total_processed': self.validation_stats['processed'],
            'valid_records': self.validation_stats['valid'],
            'invalid_records': self.validation_stats['invalid'],
            'error_rate': (
                self.validation_stats['invalid'] /
                self.validation_stats['processed']
                if self.validation_stats['processed'] > 0 else 0
            ),
            'recent_errors': self.validation_stats['errors'][-5:]
        }

    def reset_stats(self) -> None:
        """Reset validation statistics"""
        self.validation_stats = {
            'processed': 0,
            'valid': 0,
            'invalid': 0,
            'errors': []
        }