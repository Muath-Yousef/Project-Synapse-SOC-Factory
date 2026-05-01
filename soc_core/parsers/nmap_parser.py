import xml.etree.ElementTree as ET
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class NmapParser:
    """
    Parses raw Nmap XML output into a unified JSON/Dict structure
    suitable for LLM consumption and Aggregator merging.
    """
    
    def parse(self, xml_output: str) -> Dict[str, Any]:
        """
        Takes raw XML string and returns a structured dictionary.
        """
        result = {
            "scanner": "nmap",
            "hosts": []
        }
        
        if not xml_output or not xml_output.strip():
            logger.warning("[NmapParser] Received empty XML string.")
            return result
            
        try:
            root = ET.fromstring(xml_output)
            
            # Iterate through all discovered hosts
            for host_element in root.findall("host"):
                host_data = {
                    "ip": "Unknown",
                    "status": "Unknown",
                    "ports": []
                }
                
                # Extract IP Address
                address_elem = host_element.find("address[@addrtype='ipv4']")
                if address_elem is not None:
                    host_data["ip"] = address_elem.get("addr")
                    
                # Extract Status
                status_elem = host_element.find("status")
                if status_elem is not None:
                    host_data["status"] = status_elem.get("state")
                    
                # Only process ports if the host is up
                if host_data["status"] == "up":
                    ports_elem = host_element.find("ports")
                    if ports_elem is not None:
                        for port_elem in ports_elem.findall("port"):
                            # Only record open ports
                            state_elem = port_elem.find("state")
                            if state_elem is not None and state_elem.get("state") == "open":
                                port_id = port_elem.get("portid")
                                protocol = port_elem.get("protocol")
                                
                                port_info = {
                                    "port": int(port_id) if port_id else 0,
                                    "protocol": protocol,
                                    "service": "Unknown",
                                    "version": "Unknown"
                                }
                                
                                # Extract Service details
                                service_elem = port_elem.find("service")
                                if service_elem is not None:
                                    port_info["service"] = service_elem.get("name", "Unknown")
                                    # If version scan (-sV) was used, grab version and product info
                                    product = service_elem.get("product", "")
                                    version = service_elem.get("version", "")
                                    if product or version:
                                        port_info["version"] = f"{product} {version}".strip()
                                        
                                host_data["ports"].append(port_info)
                
                result["hosts"].append(host_data)
                
            return result
            
        except ET.ParseError as e:
            logger.error(f"[NmapParser] Failed to parse XML: {e}")
            # Could not parse XML cleanly, returning base minimal dict
            return result
