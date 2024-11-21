from src.data_sources import MISPClient, MITREClient
from src.database import SQLiteManager, Neo4jManager
from src.analysis import ThreatAnalyzer
from src.utils.logger import log
from src.config.settings import Settings

def basic_data_collection():
    """Example of basic data collection"""
    try:
        print("\nAttempting to collect threat data...")
        
        # MITRE Data Collection
        try:
            mitre_client = MITREClient()
            print("\nTesting MITRE ATT&CK connection...")
            mitre_client.print_debug_info()
            
            attack_patterns = mitre_client.get_attack_patterns()
            
            if attack_patterns:
                print(f"\nMITRE Patterns: {len(attack_patterns)}")
                print("\nSample Pattern:")
                sample = attack_patterns[0]
                print(f"- Name: {sample['name']}")
                print(f"- ID: {sample['mitre_id']}")
                print(f"- Tactics: {', '.join(sample['tactics'])}")
            else:
                print("\nNo MITRE patterns found")
                
        except Exception as e:
            print(f"\nError collecting MITRE data: {str(e)}")
            print(f"MITRE Base URL: {Settings.MITRE_API_URL}")
            
        # MISP Data Collection
        try:
            misp_client = MISPClient()
            recent_threats = misp_client.get_recent_threats(days=30)
            print(f"\nThreats from MISP: {len(recent_threats)}")
            
            if recent_threats:
                print("\nSample MISP Threat:")
                sample = recent_threats[0]
                print(f"- Name: {sample['name']}")
                print(f"- First Seen: {sample['first_seen']}")
            
        except Exception as e:
            print(f"\nError collecting MISP data: {str(e)}")
            print("Make sure MISP_URL and MISP_API_KEY are set in your .env file")

    except Exception as e:
        log.error(f"Error in data collection: {str(e)}")
        print(f"\nError: {str(e)}")

if __name__ == "__main__":
    print("=== Basic Usage Demo ===")
    basic_data_collection()