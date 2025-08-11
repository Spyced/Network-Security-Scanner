"""
Network Utilities - Helper functions for network operations
"""

import ipaddress
import socket
import re
from typing import List, Union

def validate_target(target: str) -> List[str]:
    """
    Validate and expand target specification
    
    Args:
        target: IP address, hostname, or CIDR range
        
    Returns:
        List of valid IP addresses
    """
    targets = []
    
    try:
        # Try parsing as CIDR range
        if '/' in target:
            network = ipaddress.ip_network(target, strict=False)
            targets = [str(ip) for ip in network.hosts()]
            
            # Limit to reasonable size to prevent huge scans
            if len(targets) > 254:
                raise ValueError(f"Target range too large: {len(targets)} hosts")
                
        else:
            # Single IP or hostname
            if is_valid_ip(target):
                targets = [target]
            else:
                # Try to resolve hostname
                resolved_ip = socket.gethostbyname(target)
                targets = [resolved_ip]
                
    except (ipaddress.AddressValueError, socket.gaierror, ValueError) as e:
        raise ValueError(f"Invalid target specification: {target} - {str(e)}")
    
    return targets

def is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IP address"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ipaddress.AddressValueError:
        return False

def parse_port_range(port_spec: str) -> List[int]:
    """
    Parse port specification into list of ports
    
    Args:
        port_spec: Port specification (e.g., "80", "1-1000", "80,443,8080")
        
    Returns:
        List of port numbers
    """
    ports = []
    
    try:
        # Handle comma-separated ports
        if ',' in port_spec:
            for part in port_spec.split(','):
                ports.extend(parse_port_range(part.strip()))
            return sorted(list(set(ports)))
        
        # Handle port ranges
        if '-' in port_spec:
            start, end = port_spec.split('-', 1)
            start_port = int(start.strip())
            end_port = int(end.strip())
            
            if start_port > end_port:
                raise ValueError("Start port must be less than end port")
            
            # Limit range size to prevent excessive scanning
            if end_port - start_port > 65535:
                raise ValueError("Port range too large")
            
            ports = list(range(start_port, end_port + 1))
        
        else:
            # Single port
            port = int(port_spec.strip())
            if port < 1 or port > 65535:
                raise ValueError("Port number must be between 1 and 65535")
            ports = [port]
            
    except ValueError as e:
        raise ValueError(f"Invalid port specification: {port_spec} - {str(e)}")
    
    return ports

def is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """
    Check if a port is open on a host
    
    Args:
        host: Target hostname or IP
        port: Port number
        timeout: Connection timeout
        
    Returns:
        True if port is open
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def get_local_ip() -> str:
    """Get local IP address"""
    try:
        # Connect to a remote address to determine local IP
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]
        sock.close()
        return local_ip
    except:
        return "127.0.0.1"

def reverse_dns_lookup(ip: str) -> str:
    """Perform reverse DNS lookup"""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        return ip_port < 1 or end_port > 65535:
                raise ValueError("Port numbers must be between 1 and 65535")
            
            if start
