from pymisp import PyMISP, MISPEvent, MISPObject, MISPTag
from datetime import datetime
import os
from src.config.settings import Settings

class MISPTester:
    def __init__(self):
        self.misp = PyMISP(Settings.MISP_URL, Settings.MISP_API_KEY, ssl=False)

    def create_threat_actor_event(self):
        """Crear un evento de actor de amenaza"""
        event = MISPEvent()
        event.info = "APT Test Group Activity"
        event.distribution = 0
        event.threat_level_id = 3  # Alto
        event.analysis = 2  # Completado
        
        # Agregar detalles del actor
        event.add_attribute('threat-actor', 'APT-TEST-GROUP')
        event.add_attribute('comment', 'Grupo de amenazas focalizadas en sector financiero')
        
        # Agregar tags
        event.add_tag('tlp:amber')
        event.add_tag('type:threat-actor')
        
        # Imprimir los datos del evento que se están enviando
        print(f"Enviando evento: {event}")

        # Imprimir los encabezados de la solicitud
        print(f"Encabezados de la solicitud: {self.misp.session.headers}")

        # Enviar el evento y capturar la respuesta
        response = self.misp.add_event(event)

        # Imprimir la respuesta completa
        print(f"Respuesta del servidor: {response}")

        return response

    def create_malware_event(self):
        """Crear un evento de malware"""
        event = MISPEvent()
        event.info = "Nueva variante de Ransomware"
        event.distribution = 0
        event.threat_level_id = 3
        
        # Crear objeto malware
        malware = MISPObject('file')
        malware.add_attribute('filename', 'ransom.exe')
        malware.add_attribute('md5', 'a1b2c3d4e5f6g7h8i9j0')
        malware.add_attribute('size-in-bytes', '2048576')
        
        # Agregar comportamientos observados
        malware.add_attribute('text', 'Encrypts files with .encrypted extension')
        
        event.add_object(malware)
        
        # Agregar IOCs relacionados
        event.add_attribute('ip-dst', '10.0.0.1')
        event.add_attribute('domain', 'malicious-c2.com')
        
        # Imprimir los datos del evento que se están enviando
        print(f"Enviando evento: {event}")

        # Imprimir los encabezados de la solicitud
        print(f"Encabezados de la solicitud: {self.misp.session.headers}")

        # Enviar el evento y capturar la respuesta
        response = self.misp.add_event(event)

        # Imprimir la respuesta completa
        print(f"Respuesta del servidor: {response}")

        return response

    def create_vulnerability_event(self):
        """Crear un evento de vulnerabilidad"""
        event = MISPEvent()
        event.info = "CVE-2024-TEST - SQL Injection Vulnerability"
        event.distribution = 0
        event.threat_level_id = 2
        
        # Agregar detalles de la vulnerabilidad
        vuln = MISPObject('vulnerability')
        vuln.add_attribute('id', 'CVE-2024-TEST')
        vuln.add_attribute('description', 'SQL Injection en módulo de login')
        vuln.add_attribute('cvss-score', '7.5')
        
        event.add_object(vuln)
        
        # Imprimir los datos del evento que se están enviando
        print(f"Enviando evento: {event}")

        # Imprimir los encabezados de la solicitud
        print(f"Encabezados de la solicitud: {self.misp.session.headers}")

        # Enviar el evento y capturar la respuesta
        response = self.misp.add_event(event)

        # Imprimir la respuesta completa
        print(f"Respuesta del servidor: {response}")

        return response

    def create_incident_event(self):
        """Crear un evento de incidente"""
        event = MISPEvent()
        event.info = "Incident Report - Data Breach Attempt"
        event.distribution = 0
        event.threat_level_id = 2
        event.analysis = 1  # En curso
        
        # Línea de tiempo
        event.add_attribute('datetime', datetime.now().strftime('%Y-%m-%d'))
        event.add_attribute('datetime', datetime.now().strftime('%Y-%m-%d'))
        
        # Indicadores observados
        event.add_attribute('ip-src', '192.168.1.100')
        event.add_attribute('user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        event.add_attribute('hostname', 'INFECTED-PC001')
        
        # Imprimir los datos del evento que se están enviando
        print(f"Enviando evento: {event}")

        # Imprimir los encabezados de la solicitud
        print(f"Encabezados de la solicitud: {self.misp.session.headers}")

        # Enviar el evento y capturar la respuesta
        response = self.misp.add_event(event)

        # Imprimir la respuesta completa
        print(f"Respuesta del servidor: {response}")

        return response

def main():
    tester = MISPTester()
    
    try:
        # Crear varios tipos de eventos
        threat_actor = tester.create_threat_actor_event()
        if isinstance(threat_actor, dict) and 'Event' in threat_actor:
            print(f"✅ Evento de Actor de Amenaza creado: {threat_actor['Event']['id']}")
        else:
            print(f"❌ Error al crear evento de Actor de Amenaza: Respuesta inesperada del servidor")
            print(f"Respuesta del servidor: {threat_actor}")
        
        malware = tester.create_malware_event()
        if isinstance(malware, dict) and 'Event' in malware:
            print(f"✅ Evento de Malware creado: {malware['Event']['id']}")
        else:
            print(f"❌ Error al crear evento de Malware: Respuesta inesperada del servidor")
            print(f"Respuesta del servidor: {malware}")
        
        vuln = tester.create_vulnerability_event()
        if isinstance(vuln, dict) and 'Event' in vuln:
            print(f"✅ Evento de Vulnerabilidad creado: {vuln['Event']['id']}")
        else:
            print(f"❌ Error al crear evento de Vulnerabilidad: Respuesta inesperada del servidor")
            print(f"Respuesta del servidor: {vuln}")
        
        incident = tester.create_incident_event()
        if isinstance(incident, dict) and 'Event' in incident:
            print(f"✅ Evento de Incidente creado: {incident['Event']['id']}")
        else:
            print(f"❌ Error al crear evento de Incidente: Respuesta inesperada del servidor")
            print(f"Respuesta del servidor: {incident}")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")

if __name__ == "__main__":
    main()