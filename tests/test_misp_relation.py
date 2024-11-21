# test_misp_relations.py
from pymisp import PyMISP, MISPEvent, MISPObject
from datetime import datetime
from src.config.settings import Settings

def create_related_events():
    misp = PyMISP(Settings.MISP_URL, Settings.MISP_API_KEY, ssl=False)
    
    # Crear evento principal (campaña)
    campaign = MISPEvent()
    campaign.info = "Test Campaign - Financial Sector Attack"
    campaign.distribution = 0
    campaign.threat_level_id = 3
    campaign_result = misp.add_event(campaign)
    campaign_id = campaign_result['Event']['id']
    
    # Crear evento de malware
    malware = MISPEvent()
    malware.info = "Malware Used in Campaign"
    malware.distribution = 0
    malware.threat_level_id = 3
    malware_result = misp.add_event(malware)
    
    # Relacionar eventos
    misp.add_event_tag(malware_result['Event']['id'], 'misp-galaxy:threat-actor="APT Test Group"')
    misp.add_event_tag(campaign_id, 'misp-galaxy:threat-actor="APT Test Group"')
    
    return campaign_id, malware_result['Event']['id']

if __name__ == "__main__":
    campaign_id, malware_id = create_related_events()
    print(f"Eventos relacionados creados: {campaign_id}, {malware_id}")