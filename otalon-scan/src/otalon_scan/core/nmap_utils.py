# core/nmap_utils.py
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Tuple

from loguru import logger


def format_nmap_result_str(result_str: str) -> str:
    """Format nmap result string for better readability."""
    host_lines = result_str.splitlines()
    formatted_output = "; ".join(line for line in host_lines)
    return formatted_output


def parse_nmap_xml(xml_string: str) -> Tuple[List[str], List[str]]:
    """Parse nmap XML output and extract lists of IP and MAC addresses."""
    ip_list: List[str] = []
    mac_list: List[str] = []
    try:
        root = ET.fromstring(xml_string)
        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.get("state") != "up":
                continue
            address_elements = host.findall("address")
            ip = None
            mac = None
            for addr in address_elements:
                if addr.get("addrtype") == "ipv4":
                    ip = addr.get("addr")
                elif addr.get("addrtype") == "mac":
                    mac = addr.get("addr")
            if ip:
                ip_list.append(ip)
            if mac:
                mac_list.append(mac)
    except Exception as ex:
        logger.error("Error parsing nmap XML: {ex}", ex=ex)
    return ip_list, mac_list


def parse_nmap_portscan_xml(xml_string: str) -> List[Dict[str, Any]]:
    """
    Parses Nmap XML output (Portscan) and returns a list of dictionaries per host.
    Each dictionary contains:
        - ip_address: str
        - hostnames: List[str]
        - open_ports: List[Dict[str, Any]] (each with: port, protocol, state, service, product, version, cpe)
    """
    results: List[Dict[str, Any]] = []
    try:
        root = ET.fromstring(xml_string)
        for host in root.findall("host"):
            host_info: Dict[str, Any] = {}
            ip_elem = host.find('address[@addrtype="ipv4"]')
            host_info["ip_address"] = ip_elem.get("addr") if ip_elem is not None else ""

            hostnames = []
            hostnames_elem = host.find("hostnames")
            if hostnames_elem is not None:
                for hn in hostnames_elem.findall("hostname"):
                    name = hn.get("name")
                    if name:
                        hostnames.append(name)
            host_info["hostnames"] = hostnames

            open_ports = []
            ports_elem = host.find("ports")
            if ports_elem is not None:
                for port in ports_elem.findall("port"):
                    port_state = port.find("state")
                    if port_state is not None and port_state.get("state") == "open":
                        port_info: Dict[str, Any] = {
                            "port": port.get("portid"),
                            "protocol": port.get("protocol"),
                            "state": port_state.get("state"),
                        }
                        service_elem = port.find("service")
                        if service_elem is not None:
                            port_info["service"] = service_elem.get("name", "")
                            port_info["product"] = service_elem.get("product", "")
                            port_info["version"] = service_elem.get("version", "")
                            port_info["extrainfo"] = service_elem.get("extrainfo", "")
                            # CPE
                            cpe_elem = service_elem.find("cpe")
                            port_info["cpe"] = cpe_elem.text if cpe_elem is not None else ""
                        open_ports.append(port_info)
            host_info["open_ports"] = open_ports

            results.append(host_info)
    except Exception as ex:
        logger.error("Error parsing nmap XML: {ex}", ex=ex)
    return results
