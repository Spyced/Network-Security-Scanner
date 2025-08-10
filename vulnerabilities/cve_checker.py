"""
CVE Checker Module - Check for known vulnerabilities
"""

import requests
import re
import json
import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class CVEChecker:
    """Check services for known CVE vulnerabilities"""
    
    def __init__(self):
        self.cve_api_base = "https://cve.circl.lu/api"
        self.nvd_api_base = "https://services.nvd.nist.gov/rest/json/cves/1.0"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'NetSecScan/1.0 Security Scanner'
        })
        
        # Cache for CVE lookups
        self.cve_cache = {}
        
        # Known vulnerable versions (examples)
        self.known_vulnerabilities = {
            'Apache': {
                '2.4.49': ['CVE-2021-41773', 'CVE-2021-42013'],
                '2.4.48': ['CVE-2021-40438'],
                '2.2.34': ['CVE-2017-15710', 'CVE-2017-15715']
            },
            'OpenSSH': {
                '7.4': ['CVE-2018-15473'],
                '6.6.1': ['CVE-2016-0777', 'CVE-2016-0778'],
                '5.3': ['CVE-2010-4478']
            },
            'Nginx': {
                '1.3.9': ['CVE-2013-2028'],
                '1.1.17': ['CVE-2012-1180'],
                '0.8.54': ['CVE-2011-4963']
            },
            'Microsoft IIS': {
                '10.0': ['CVE-2017-7269'],
                '8.5': ['CVE-2015-1635'],
                '7.5': ['CVE-2010-2730']
            }
        }
    
    def check_vulnerabilities(self, services: Dict[int, Dict]) -> List[Dict]:
        """
        Check services for known vulnerabilities
        
        Args:
            services: Dictionary of detected services
            
        Returns:
            List of vulnerability findings
        """
        vulnerabilities = []
        
        logger.info("Checking for known vulnerabilities...")
        
        for port, service_info in services.items():
            service = service_info.get('service', '')
            version = service_info.get('version', '')
            
            if not service or service == 'Unknown':
                continue
            
            # Check against known vulnerability database
            vulns = self._check_service_vulnerabilities(service, version, port)
            vulnerabilities.extend(vulns)
            
            # Check for common misconfigurations
            config_issues = self._check_misconfigurations(service, port, service_info)
            vulnerabilities.extend(config_issues)
        
        # Sort by severity
        vulnerabilities.sort(key=lambda x: self._get_severity_score(x.get('severity', 'low')), reverse=True)
        
        logger.info(f"Found {len(vulnerabilities)} potential security issues")
        return vulnerabilities
    
    def _check_service_vulnerabilities(self, service: str, version: str, port: int) -> List[Dict]:
        """Check a specific service version for known CVEs"""
        vulnerabilities = []
        
        # Check local vulnerability database first
        if service in self.known_vulnerabilities:
            service_vulns = self.known_vulnerabilities[service]
            
            for vuln_version, cves in service_vulns.items():
                if self._version_matches(version, vuln_version):
                    for cve in cves:
                        vuln_details = self._get_cve_details(cve)
                        vulnerabilities.append({
                            'type': 'CVE',
                            'id': cve,
                            'service': service,
                            'version': version,
                            'port': port,
                            'severity': vuln_details.get('severity', 'medium'),
                            'description': vuln_details.get('description', f'Known vulnerability in {service} {version}'),
                            'cvss_score': vuln_details.get('cvss_score', 0.0),
                            'references': vuln_details.get('references', [])
                        })
        
        # Check for version-specific vulnerabilities
        version_vulns = self._check_version_vulnerabilities(service, version, port)
        vulnerabilities.extend(version_vulns)
        
        return vulnerabilities
    
    def _check_misconfigurations(self, service: str, port: int, service_info: Dict) -> List[Dict]:
        """Check for common service misconfigurations"""
        issues = []
        banner = service_info.get('banner', '').lower()
        
        # Common misconfiguration checks
        if service.lower() in ['ftp', 'telnet'] and port in [21, 23]:
            issues.append({
                'type': 'misconfiguration',
                'id': 'INSECURE_PROTOCOL',
                'service': service,
                'port': port,
                'severity': 'high',
                'description': f'{service} uses unencrypted communication',
                'recommendation': f'Replace {service} with secure alternatives (SFTP/SSH)'
            })
        
        # Check for default credentials hints
        if 'default' in banner or 'admin' in banner:
            issues.append({
                'type': 'misconfiguration',
                'id': 'DEFAULT_CREDENTIALS',
                'service': service,
                'port': port,
                'severity': 'high',
                'description': 'Service may be using default credentials',
                'recommendation': 'Change default credentials immediately'
            })
        
        # Check for outdated SSL/TLS
        if service.lower() in ['https', 'imaps', 'pop3s'] and 'ssl' in banner:
            if any(weak in banner for weak in ['sslv2', 'sslv3', 'tls1.0']):
                issues.append({
                    'type': 'misconfiguration',
                    'id': 'WEAK_SSL',
                    'service': service,
                    'port': port,
                    'severity': 'medium',
                    'description': 'Service supports weak SSL/TLS versions',
                    'recommendation': 'Disable SSLv2, SSLv3, and TLS 1.0'
                })
        
        # Check for information disclosure
        if any(info in banner.lower() for info in ['version', 'build', 'debug']):
            issues.append({
                'type': 'information_disclosure',
                'id': 'BANNER_DISCLOSURE',
                'service': service,
                'port': port,
                'severity': 'low',
                'description': 'Service banner reveals version information',
                'recommendation': 'Configure service to hide version information'
            })
        
        return issues
    
    def _get_cve_details(self, cve_id: str) -> Dict:
        """Get detailed information about a CVE"""
        if cve_id in self.cve_cache:
            return self.cve_cache[cve_id]
        
        try:
            # Try CVE CIRCL API first
            response = self.session.get(f"{self.cve_api_base}/cve/{cve_id}", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                details = {
                    'description': data.get('summary', ''),
                    'severity': self._map_cvss_to_severity(data.get('cvss', 0)),
                    'cvss_score': data.get('cvss', 0.0),
                    'references': data.get('references', [])
                }
                
                self.cve_cache[cve_id] = details
                return details
        
        except Exception as e:
            logger.debug(f"Failed to fetch CVE details for {cve_id}: {str(e)}")
        
        # Return default if API fails
        return {
            'description': f'Known vulnerability {cve_id}',
            'severity': 'medium',
            'cvss_score': 5.0,
            'references': []
        }
    
    def _version_matches(self, detected_version: str, vuln_version: str) -> bool:
        """Check if detected version matches vulnerable version"""
        if not detected_version:
            return False
        
        # Exact match
        if detected_version == vuln_version:
            return True
        
        # Version range checking (simplified)
        try:
            detected_parts = [int(x) for x in detected_version.split('.')]
            vuln_parts = [int(x) for x in vuln_version.split('.')]
            
            # Compare version numbers
            for i in range(min(len(detected_parts), len(vuln_parts))):
                if detected_parts[i] < vuln_parts[i]:
                    return True
                elif detected_parts[i] > vuln_parts[i]:
                    return False
            
            return len(detected_parts) <= len(vuln_parts)
            
        except ValueError:
            # Fallback to string comparison
            return detected_version.startswith(vuln_version)
    
    def _check_version_vulnerabilities(self, service: str, version: str, port: int) -> List[Dict]:
        """Check for version-specific vulnerabilities"""
        vulnerabilities = []
        
        # Check for very old versions (general heuristic)
        if version:
            try:
                version_parts = version.split('.')
                major_version = int(version_parts[0])
                
                # Flag very old major versions
                old_version_thresholds = {
                    'Apache': 2,
                    'Nginx': 1,
                    'OpenSSH': 7,
                    'Microsoft IIS': 8
                }
                
                threshold = old_version_thresholds.get(service)
                if threshold and major_version < threshold:
                    vulnerabilities.append({
                        'type': 'outdated_version',
                        'id': 'OLD_VERSION',
                        'service': service,
                        'version': version,
                        'port': port,
                        'severity': 'medium',
                        'description': f'{service} version {version} is outdated and may contain vulnerabilities',
                        'recommendation': f'Update {service} to the latest stable version'
                    })
                    
            except (ValueError, IndexError):
                pass
        
        return vulnerabilities
    
    def _map_cvss_to_severity(self, cvss_score: float) -> str:
        """Map CVSS score to severity level"""
        if cvss_score >= 9.0:
            return 'critical'
        elif cvss_score >= 7.0:
            return 'high'
        elif cvss_score >= 4.0:
            return 'medium'
        else:
            return 'low'
    
    def _get_severity_score(self, severity: str) -> int:
        """Get numeric score for severity level"""
        severity_scores = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1
        }
        return severity_scores.get(severity.lower(), 0)
