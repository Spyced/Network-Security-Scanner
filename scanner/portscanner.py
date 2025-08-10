"""
Port Scanner Module - Multi-threaded TCP/UDP port scanning
"""

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set
import logging

logger = logging.getLogger(__name__)

class PortScanner:
    """High-performance multi-threaded port scanner"""
    
    def __init__(self, threads: int = 100, timeout: float = 1.0):
        self.threads = threads
        self.timeout = timeout
        self.open_ports = set()
        self.lock = threading.Lock()
    
    def scan_tcp_port(self, target: str, port: int) -> bool:
        """Scan a single TCP port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                with self.lock:
                    self.open_ports.add(port)
                logger.debug(f"Port {port}/tcp open on {target}")
                return True
            return False
            
        except socket.gaierror:
            logger.error(f"Hostname {target} could not be resolved")
            return False
        except Exception as e:
            logger.debug(f"Error scanning port {port}: {str(e)}")
            return False
    
    def scan_udp_port(self, target: str, port: int) -> bool:
        """Scan a single UDP port (basic implementation)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send empty UDP packet
            sock.sendto(b'', (target, port))
            
            try:
                sock.recvfrom(1024)
                with self.lock:
                    self.open_ports.add(port)
                logger.debug(f"Port {port}/udp open on {target}")
                return True
            except socket.timeout:
                # No response - port might be open
                with self.lock:
                    self.open_ports.add(port)
                return True
            
        except Exception as e:
            logger.debug(f"Error scanning UDP port {port}: {str(e)}")
            return False
        finally:
            sock.close()
        
        return False
    
    def scan(self, target: str, ports: List[int], protocol: str = 'tcp') -> Set[int]:
        """
        Scan multiple ports on a target
        
        Args:
            target: IP address or hostname
            ports: List of ports to scan
            protocol: 'tcp' or 'udp'
        
        Returns:
            Set of open ports
        """
        self.open_ports.clear()
        start_time = time.time()
        
        logger.info(f"Starting {protocol.upper()} scan of {target}")
        logger.info(f"Scanning {len(ports)} ports with {self.threads} threads")
        
        scan_func = self.scan_tcp_port if protocol == 'tcp' else self.scan_udp_port
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all scanning tasks
            future_to_port = {
                executor.submit(scan_func, target, port): port 
                for port in ports
            }
            
            # Process completed tasks
            completed = 0
            for future in as_completed(future_to_port):
                completed += 1
                if completed % 100 == 0:
                    progress = (completed / len(ports)) * 100
                    logger.info(f"Progress: {progress:.1f}% ({completed}/{len(ports)})")
        
        scan_time = time.time() - start_time
        logger.info(f"Scan completed in {scan_time:.2f} seconds")
        logger.info(f"Found {len(self.open_ports)} open ports")
        
        return self.open_ports.copy()
    
    def get_scan_stats(self) -> Dict:
        """Get scanning statistics"""
        return {
            'threads_used': self.threads,
            'timeout': self.timeout,
            'open_ports_found': len(self.open_ports)
        }
