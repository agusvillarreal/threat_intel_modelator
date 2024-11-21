# src/data_sources/mitre_client.py
import requests
import json
from typing import List, Dict, Any
from src.config.settings import Settings
from src.utils.logger import log

class MITREClient:
    def __init__(self):
        self.base_url = Settings.MITRE_API_URL
        self.headers = {
            'Accept': 'application/json'
        }

    def get_attack_patterns(self) -> List[Dict[str, Any]]:
        """Fetch MITRE ATT&CK patterns"""
        try:
            url = f"{self.base_url}/enterprise-attack/enterprise-attack.json"
            log.info(f"Fetching MITRE ATT&CK data from: {url}")
            
            response = requests.get(url, headers=self.headers, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            attack_patterns = []
            
            # Filter and process attack patterns
            for obj in data.get('objects', []):
                if obj.get('type') == 'attack-pattern':
                    # Get external references (MITRE ID)
                    external_refs = obj.get('external_references', [])
                    mitre_id = next(
                        (ref.get('external_id') for ref in external_refs 
                         if ref.get('source_name') == 'mitre-attack'),
                        None
                    )
                    
                    # Get kill chain phases
                    kill_chain_phases = obj.get('kill_chain_phases', [])
                    tactics = [phase.get('phase_name') for phase in kill_chain_phases]
                    
                    pattern = {
                        'stix_id': obj.get('id'),
                        'name': obj.get('name'),
                        'description': obj.get('description'),
                        'mitre_id': mitre_id,
                        'tactics': tactics,
                        'platforms': obj.get('x_mitre_platforms', []),
                        'created': obj.get('created'),
                        'modified': obj.get('modified')
                    }
                    attack_patterns.append(pattern)
            
            log.info(f"Successfully processed {len(attack_patterns)} attack patterns")
            return attack_patterns
            
        except requests.exceptions.RequestException as e:
            log.error(f"Error fetching MITRE data: {str(e)}")
            return []
        except json.JSONDecodeError as e:
            log.error(f"Error parsing MITRE data: {str(e)}")
            return []
        except Exception as e:
            log.error(f"Unexpected error processing MITRE data: {str(e)}")
            return []

    def get_tactics(self) -> List[Dict[str, Any]]:
        """Fetch MITRE ATT&CK tactics"""
        try:
            url = f"{self.base_url}/enterprise-attack/enterprise-attack.json"
            response = requests.get(url, headers=self.headers, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            tactics = []
            
            for obj in data.get('objects', []):
                if obj.get('type') == 'x-mitre-tactic':
                    tactic = {
                        'stix_id': obj.get('id'),
                        'name': obj.get('name'),
                        'description': obj.get('description'),
                        'shortname': obj.get('x_mitre_shortname')
                    }
                    tactics.append(tactic)
            
            return tactics
            
        except Exception as e:
            log.error(f"Error fetching MITRE tactics: {str(e)}")
            return []

    def print_debug_info(self):
        """Print debug information about the MITRE connection"""
        try:
            url = f"{self.base_url}/enterprise-attack/enterprise-attack.json"
            response = requests.get(url, headers=self.headers, timeout=30)
            
            print("\nMITRE Debug Information:")
            print(f"URL: {url}")
            print(f"Status Code: {response.status_code}")
            print(f"Response Headers: {dict(response.headers)}")
            
            if response.ok:
                data = response.json()
                total_objects = len(data.get('objects', []))
                attack_patterns = len([obj for obj in data.get('objects', []) 
                                    if obj.get('type') == 'attack-pattern'])
                
                print(f"Total Objects: {total_objects}")
                print(f"Attack Patterns: {attack_patterns}")
            else:
                print(f"Error Response: {response.text}")
                
        except Exception as e:
            print(f"Debug Error: {str(e)}")