"""
Service Detection Module - Identify services running on open ports
"""

import socket
import ssl
import re
import logging
from typing import Dict, List, Optional, Tuple
from .banner_grabber import BannerGrabber

logger = logging.getLogger(__name__)

class ServiceDetector:
    """Detect and identify services running on open ports"""
    
    def __init__(self):
        self.banner_grabber = BannerGrabber()
        self.common_services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MSSQL',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            6379: 'Redis',
            27017: 'MongoDB'
        }
        
        # Service fingerprints for banner analysis
        self.service_patterns = {
            'Apache': [
                re.compile(r'Apache/(\d+\.\d+\.\d+)', re.IGNORECASE),
                re.compile(r'Server:\s*Apache', re.IGNORECASE)
            ],
            'Nginx': [
                re.compile(r'nginx/(\d+\.\d+\.\d+)', re.IGNORECASE),
                re.compile(r'Server:\s*nginx', re.IGNORECASE)
            ],
            'OpenSSH': [
                re.compile(r'OpenSSH[_\s]+(\d+\.\d+)', re.IGNORECASE),
                re.compile(r'SSH-\d+\.\d+-OpenSSH', re.IGNORECASE)
            ],
            'Microsoft IIS': [
                re.compile(r'Microsoft-IIS/(\d+\.\d+)', re.IGNORECASE),
                re.compile(r'Server:\s*Microsoft-IIS', re.IGNORECASE)
            ],
            'vsftpd': [
                re.compile(r'vsftpd\s+(\d+\.\d+\.\d+)', re.IGNORECASE)
            ],
            'ProFTPD': [
                re.compile(r'ProFTPD\s+(\d+\.\d+\.\d+)', re.IGNORECASE)
            ]
        }
    
    def detect_services(self, target: str, ports: List[int]) -> Dict[int, Dict]:
        """
        Detect services on the given ports
        
        Args:
            target: IP address or hostname
            ports: List of open ports to analyze
        
        Returns:
            Dictionary mapping port numbers to service information
        """
        services = {}
        
        logger.info(f"Detecting services on {len(ports)} ports")
        
        for port in ports:
            try:
                service_info = self._analyze_port(target, port)
                services[port] = service_info
                
                service_name = service_info.get('service', 'Unknown')
                version = service_info.get('version', '')
                logger.info(f"Port {port}: {service_name} {version}")
                
            except Exception as e:
                logger.debug(f"Error analyzing port {port}: {str(e)}")
                services[port] = {
                    'service': 'Unknown',
                    'version': '',
                    'banner': '',
                    'confidence': 'low'
                }
        
        return services
    
    def _analyze_port(self, target: str, port: int) -> Dict:
        """Analyze a single port to determine the service"""
        
        # Start with common service identification
        service_name = self.common_services.get(port, 'Unknown')
        confidence = 'medium' if port in self.common_services else 'low'
        
        # Get banner for more detailed analysis
        banner = self.banner_grabber.grab_banner(target, port)
        
        # Analyze banner for service details
        version, detected_service = self._parse_banner(banner)
        
        if detected_service:
            service_name = detected_service
            confidence = 'high'
        
        # Additional HTTP-specific detection
        if port in [80, 443, 8080, 8443]:
            http_info = self._detect_http_service(target, port)
            if http_info:
                service_name = http_info.get('server', service_name)
                version = http_info.get('version', version)
                confidence = 'high'
        
        return {
            'service': service_name,
            'version': version,
            'banner': banner,
            'confidence': confidence,
            'port': port,
            'protocol': 'tcp'
        }
    
    def _parse_banner(self, banner: str) -> Tuple[str, Optional[str]]:
        """Parse banner to extract service name and version"""
        if not banner:
            return '', None
        
        for service, patterns in self.service_patterns.items():
            for pattern in patterns:
                match = pattern.search(banner)
                if match:
                    version = match.group(1) if match.groups() else ''
                    return version, service
        
        return '', None
    
    def _detect_http_service(self, target: str, port: int) -> Optional[Dict]:
        """Perform HTTP-specific service detection"""
        try:
            # Try HTTP request
            http_banner = self.banner_grabber.grab_http_banner(target, port)
            
            if http_banner:
                server_header = ''
                version = ''
                
                # Parse Server header
                server_match = re.search(r'Server:\s*([^\r\n]+)', http_banner, re.IGNORECASE)
                if server_match:
                    server_header = server_match.group(1).strip()
                    
                    # Extract version from server header
                    version_match = re.search(r'/(\d+\.\d+[\.\d]*)', server_header)
                    if version_match:
                        version = version_match.group(1)
                
                return {
                    'server': server_header,
                    'version': version,
                    'banner': http_banner
                }
        
        except Exception as e:
            logger.debug(f"HTTP detection failed for {target}:{port}: {str(e)}")
        
        return None
