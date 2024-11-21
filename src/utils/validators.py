from typing import Dict, Any, Optional
from datetime import datetime
import re

class DataValidator:
    @staticmethod
    def validate_stix_id(stix_id: str) -> bool:
        """Validate STIX ID format"""
        pattern = r'^[a-z-]+--[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
        return bool(re.match(pattern, stix_id))

    @staticmethod
    def validate_cvss_score(score: float) -> bool:
        """Validate CVSS score range"""
        return 0.0 <= score <= 10.0

    @staticmethod
    def validate_indicator_pattern(pattern: str) -> bool:
        """Validate basic indicator pattern format"""
        try:
            # Check if pattern starts and ends with square brackets
            if not (pattern.startswith('[') and pattern.endswith(']')):
                return False
            
            # Check if pattern contains at least one comparison operator
            operators = ['=', '!=', '>', '<', '>=', '<=', 'LIKE', 'MATCHES']
            return any(op in pattern for op in operators)
        except:
            return False

    @staticmethod
    def validate_date_range(
        start_date: Optional[datetime],
        end_date: Optional[datetime]
    ) -> bool:
        """Validate date range logic"""
        if start_date and end_date:
            return start_date <= end_date
        return True

    @staticmethod
    def sanitize_input(input_str: str) -> str:
        """Sanitize input strings"""
        # Remove any potentially dangerous characters
        return re.sub(r'[;"\'\\]', '', input_str)