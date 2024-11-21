import requests
from typing import List, Dict, Any
from xml.etree import ElementTree
import xml.etree.ElementTree as ET
from src.utils.logger import log

class CAPECClient:
    def __init__(self):
        self.base_url = "https://capec.mitre.org/data/xml/views/1000.xml.zip"

    def get_attack_patterns(self) -> List[Dict[str, Any]]:
        """Fetch and parse CAPEC attack patterns"""
        try:
            response = requests.get(self.base_url)
            response.raise_for_status()
            
            # Parse XML content
            root = ET.fromstring(response.content)
            
            # Define XML namespaces
            ns = {'capec': 'https://capec.mitre.org/capec-3'}
            
            patterns = []
            # Find all attack patterns
            for pattern in root.findall('.//Attack_Pattern', ns):
                pattern_data = {
                    'capec_id': pattern.get('ID'),
                    'name': pattern.find('Name', ns).text if pattern.find('Name', ns) is not None else '',
                    'description': pattern.find('Description', ns).text if pattern.find('Description', ns) is not None else '',
                    'likelihood': pattern.find('Likelihood_Of_Attack', ns).text if pattern.find('Likelihood_Of_Attack', ns) is not None else '',
                    'severity': pattern.find('Typical_Severity', ns).text if pattern.find('Typical_Severity', ns) is not None else '',
                    'prerequisites': [],
                    'mitigations': []
                }
                
                prereqs = pattern.find('Prerequisites', ns)
                if prereqs is not None:
                    pattern_data['prerequisites'] = [p.text for p in prereqs.findall('Prerequisite', ns) if p.text]
                
                mitigations = pattern.find('Solutions_and_Mitigations', ns)
                if mitigations is not None:
                    pattern_data['mitigations'] = [m.text for m in mitigations.findall('Solution_or_Mitigation', ns) if m.text]
                
                patterns.append(pattern_data)
            
            return patterns
            
        except Exception as e:
            log.error(f"Error fetching CAPEC data: {str(e)}")
            return []

    def _parse_attack_patterns(self, root: ElementTree.Element) -> List[Dict[str, Any]]:
        """Parse CAPEC XML data into structured format"""
        patterns = []
        
        # Define XML namespaces
        ns = {
            'capec': 'http://capec.mitre.org/capec-2'
        }
        
        # Find all attack patterns
        for pattern in root.findall('.//capec:Attack_Pattern', ns):
            pattern_data = {
                'capec_id': pattern.get('ID'),
                'name': pattern.find('capec:Name', ns).text,
                'description': pattern.find('capec:Description', ns).text,
                'likelihood': pattern.find('capec:Likelihood_Of_Attack', ns).text,
                'severity': pattern.find('capec:Typical_Severity', ns).text,
                'prerequisites': [],
                'mitigations': []
            }
            
            # Get prerequisites
            prereqs = pattern.find('capec:Prerequisites', ns)
            if prereqs is not None:
                for prereq in prereqs.findall('capec:Prerequisite', ns):
                    pattern_data['prerequisites'].append(prereq.text)
            
            # Get mitigations
            mitigations = pattern.find('capec:Solutions_and_Mitigations', ns)
            if mitigations is not None:
                for mitigation in mitigations.findall('capec:Solution_or_Mitigation', ns):
                    pattern_data['mitigations'].append(mitigation.text)
            
            patterns.append(pattern_data)
        
        return patterns