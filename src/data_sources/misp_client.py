import requests
from typing import List, Dict, Any
from datetime import datetime
from src.config.settings import Settings
from src.utils.logger import log

class MISPClient:
    def __init__(self):
        self.url = Settings.MISP_URL
        self.api_key = Settings.MISP_API_KEY
        self.headers = {
            'Authorization': self.api_key,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

    def get_recent_threats(self, days: int = 30) -> List[Dict[str, Any]]:
        """Fetch recent threats from MISP"""
        try:
            endpoint = f"{self.url}/events/index"
            params = {
                'days': days,
                'published': True
            }
            
            response = requests.get(
                endpoint,
                headers=self.headers,
                params=params,
                verify=False  # Note: In production, use proper SSL verification
            )
            response.raise_for_status()
            
            # Parse the response
            data = response.json()
            if isinstance(data, list):
                events = data  # Direct list of events
            else:
                events = data.get('response', [])  # Wrapped in 'response' key
                if not isinstance(events, list):
                    events = []
            
            return self._transform_misp_data(events)
            
        except requests.exceptions.RequestException as e:
            log.error(f"MISP API request failed: {str(e)}")
            raise
        except Exception as e:
            log.error(f"Error processing MISP data: {str(e)}")
            raise

    def _transform_misp_data(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Transform MISP data into standardized format"""
        transformed_data = []
        for event in events:
            try:
                event_data = event.get('Event', event)  # Handle both wrapped and unwrapped events
                if not event_data:
                    continue

                # Extract fields with safe fallbacks
                uuid = event_data.get('uuid', '')
                info = event_data.get('info', 'Unknown Event')
                description = event_data.get('description', '')
                
                # Handle date fields
                date_str = event_data.get('date', '')
                timestamp_str = event_data.get('timestamp', '')
                
                try:
                    first_seen = datetime.strptime(date_str, '%Y-%m-%d').isoformat() if date_str else None
                except ValueError:
                    first_seen = None
                    
                try:
                    last_seen = datetime.fromtimestamp(int(timestamp_str)).isoformat() if timestamp_str else None
                except (ValueError, TypeError):
                    last_seen = None

                transformed = {
                    'stix_id': f"threat-actor--{uuid}" if uuid else None,
                    'name': info,
                    'description': description,
                    'first_seen': first_seen,
                    'last_seen': last_seen
                }
                
                # Only add if we have the minimum required fields
                if transformed['stix_id'] and transformed['name']:
                    transformed_data.append(transformed)
                    
            except Exception as e:
                log.warning(f"Error transforming MISP event: {str(e)}")
                continue
                
        return transformed_data