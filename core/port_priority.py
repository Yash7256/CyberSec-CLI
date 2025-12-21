"""
Port Priority Module for Cybersec CLI.
Defines port priority tiers and provides functions for priority-based scanning.
"""

from typing import List, Dict, Set
from collections import defaultdict

# Define port priority tiers
PRIORITY_PORTS = {
    "critical": {21, 22, 23, 25, 80, 443, 3306, 3389, 5432, 8080, 8443},
    "high": {20, 53, 110, 143, 445, 1433, 1521, 3000, 5000, 8000, 27017},
    "medium": {135, 139, 389, 636, 1723, 2049, 5900, 6379, 9200, 11211},
    # Low priority ports are dynamically determined as all other ports
}

def get_scan_order(port_range: List[int]) -> List[List[int]]:
    """
    Takes a list of ports to scan and returns ports grouped by priority.
    Returns ports grouped as: [critical, high, medium, low]
    Preserves original port numbers user requested.
    
    Args:
        port_range: List of ports to scan
        
    Returns:
        List of lists, where each inner list contains ports of the same priority tier
        ordered as [critical, high, medium, low]
    """
    # Convert to set for faster lookups
    port_set = set(port_range)
    
    # Initialize result lists for each priority tier
    critical_ports = []
    high_ports = []
    medium_ports = []
    low_ports = []
    
    # Categorize ports by priority
    for port in port_range:
        if port in PRIORITY_PORTS["critical"]:
            critical_ports.append(port)
        elif port in PRIORITY_PORTS["high"]:
            high_ports.append(port)
        elif port in PRIORITY_PORTS["medium"]:
            medium_ports.append(port)
        else:
            low_ports.append(port)
    
    # Return grouped ports in priority order
    return [critical_ports, high_ports, medium_ports, low_ports]


def get_priority_for_port(port: int) -> str:
    """
    Get the priority level for a specific port.
    
    Args:
        port: Port number to check
        
    Returns:
        String representing the priority level ("critical", "high", "medium", "low")
    """
    if port in PRIORITY_PORTS["critical"]:
        return "critical"
    elif port in PRIORITY_PORTS["high"]:
        return "high"
    elif port in PRIORITY_PORTS["medium"]:
        return "medium"
    else:
        return "low"


# Example usage:
# ports = [21, 22, 23, 80, 443, 3306, 8080, 8443, 25, 110, 143, 993, 995, 1000, 2000, 3000]
# priority_groups = get_scan_order(ports)
# print("Critical:", priority_groups[0])
# print("High:", priority_groups[1])
# print("Medium:", priority_groups[2])
# print("Low:", priority_groups[3])