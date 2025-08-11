"""
Report Generation Module - Generate security scan reports
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List
from jinja2 import Template

logger = logging.getLogger(__name__)

class ReportGenerator:
    """Generate reports in various formats"""
    
    def __init__(self):
        self.report_templates = {
            'html': self._get_html_template(),
            'json': self._get_json_template()
        }
    
    def generate_report(self, scan_results: Dict, format_type: str, output_file: str):
        """
        Generate a report in the specified format
        
        Args:
            scan_results: Scan results dictionary
            format_type: Output format ('json', 'html')
            output_file: Output file path
        """
        try:
            if format_type == 'json':
                self._generate_json_report(scan_results, output_file)
            elif format_type == 'html':
                self._generate_html_report(scan_results, output_file)
            else:
                raise ValueError(f"Unsupported format: {format_type}")
                
            logger.info(f"Report generated: {output_file}")
            
        except Exception as e:
            logger.error(f"Failed to generate report: {str(e)}")
            raise
    
    def print_console_report(self, scan_results: Dict):
        """Print formatted report to console"""
        print("\n" + "="*80)
        print("                    NETSEC SCAN REPORT")
        print("="*80)
        print(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Targets Scanned: {len(scan_results)}")
        
        total_ports = sum(len(result['open_ports']) for result in scan_results.values())
        total_vulns = sum(len(result['vulnerabilities']) for result in scan_results.values())
        
        print(f"Total Open Ports: {total_ports}")
        print(f"Total Vulnerabilities: {total_vulns}")
        print("="*80)
        
        for target, results in scan_results.items():
            self._print_target_results(target, results)
    
    def _print_target_results(self, target: str, results: Dict):
        """Print results for a single target"""
        print(f"\n🎯 TARGET: {target}")
        print("-" * 60)
        
        # Open Ports Summary
        open_ports = results['open_ports']
        if open_ports:
            print(f"📊 OPEN PORTS ({len(open_ports)} found):")
            
            services = results.get('services', {})
            for port in sorted(open_ports):
                service_info = services.get(port, {})
                service_name = service_info.get('service', 'Unknown')
                version = service_info.get('version', '')
                confidence = service_info.get('confidence', 'low')
                
                status_icon = "✅" if confidence == 'high' else "🔍" if confidence == 'medium' else "❓"
                version_str = f" ({version})" if version else ""
                
                print(f"  {status_icon} {port}/tcp - {service_name}{version_str}")
        else:
            print("📊 No open ports found")
        
        # Vulnerabilities
        vulnerabilities = results.get('vulnerabilities', [])
        if vulnerabilities:
            print(f"\n⚠️  VULNERABILITIES ({len(vulnerabilities)} found):")
            
            # Group by severity
            severity_groups = {}
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'low')
                if severity not in severity_groups:
                    severity_groups[severity] = []
                severity_groups[severity].append(vuln)
            
            severity_icons = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🔵'
            }
            
            for severity in ['critical', 'high', 'medium', 'low']:
                if severity in severity_groups:
                    print(f"\n  {severity_icons[severity]} {severity.upper()} SEVERITY:")
                    for vuln in severity_groups[severity]:
                        self._print_vulnerability(vuln)
        else:
            print("\n✅ No vulnerabilities found")
        
        print("\n" + "-" * 60)
    
    def _print_vulnerability(self, vuln: Dict):
        """Print a single vulnerability"""
        vuln_id = vuln.get('id', 'UNKNOWN')
        description = vuln.get('description', 'No description available')
        port = vuln.get('port', 'N/A')
        service = vuln.get('service', 'Unknown')
        
        print(f"    • {vuln_id} - Port {port} ({service})")
        print(f"      {description}")
        
        if 'recommendation' in vuln:
            print(f"      💡 Recommendation: {vuln['recommendation']}")
    
    def _generate_json_report(self, scan_results: Dict, output_file: str):
        """Generate JSON report"""
        report_data = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'scanner': 'NetSecScan v1.0',
                'targets_scanned': len(scan_results)
            },
            'summary': self._generate_summary(scan_results),
            'results': scan_results
        }
        
        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
    
    def _generate_html_report(self, scan_results: Dict, output_file: str):
        """Generate HTML report"""
        template = Template(self.report_templates['html'])
        
        report_data = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'summary': self._generate_summary(scan_results),
            'results': scan_results
        }
        
        html_content = template.render(**report_data)
        
        with open(output_file, 'w') as f:
            f.write(html_content)
    
    def _generate_summary(self, scan_results: Dict) -> Dict:
        """Generate summary statistics"""
        total_targets = len(scan_results)
        total_ports = sum(len(result['open_ports']) for result in scan_results.values())
        total_services = sum(len(result.get('services', {})) for result in scan_results.values())
        total_vulns = sum(len(result.get('vulnerabilities', [])) for result in scan_results.values())
        
        # Vulnerability severity breakdown
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for result in scan_results.values():
            for vuln in result.get('vulnerabilities', []):
                severity = vuln.get('severity', 'low')
                if severity in severity_counts:
                    severity_counts[severity] += 1
        
        return {
            'targets': total_targets,
            'open_ports': total_ports,
            'services_detected': total_services,
            'vulnerabilities': total_vulns,
            'severity_breakdown': severity_counts
        }
    
    def _get_html_template(self) -> str:
        """Get HTML report template"""
        return '''<!DOCTYPE html>
<html>
<head>
    <title>NetSecScan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; border-bottom: 3px solid #2c3e50; padding-bottom: 20px; margin-bottom: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .summary-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }
        .summary-card h3 { margin: 0 0 10px 0; font-size: 1.2em; }
        .summary-card .number { font-size: 2em; font-weight: bold; }
        .target-section { margin-bottom: 40px; border: 1px solid #ddd; border-radius: 8px; overflow: hidden; }
        .target-header { background: #34495e; color: white; padding: 15px; font-size: 1.3em; font-weight: bold; }
        .target-content { padding: 20px; }
        .ports-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .port-card { border: 1px solid #e1e8ed; border-radius: 6px; padding: 15px; background: #f8f9fa; }
        .port-number { font-weight: bold; color: #27ae60; font-size: 1.1em; }
        .service-info { margin-top: 8px; color: #666; }
        .vuln-section { margin-top: 25px; }
        .vuln-item { margin: 10px 0; padding: 15px; border-left: 4px solid #e74c3c; background: #fff5f5; border-radius: 4px; }
        .vuln-critical { border-left-color: #c0392b; background: #ffebee; }
        .vuln-high { border-left-color: #e67e22; background: #fff3e0; }
        .vuln-medium { border-left-color: #f39c12; background: #fffbf0; }
        .vuln-low { border-left-color: #3498db; background: #e3f2fd; }
        .vuln-header { font-weight: bold; margin-bottom: 5px; }
        .vuln-desc { color: #555; line-height: 1.4; }
        .severity-badge { display: inline-block; padding: 4px 8px; border-radius: 12px; font-size: 0.8em; font-weight: bold; text-transform: uppercase; }
        .severity-critical { background: #c0392b; color: white; }
        .severity-high { background: #e67e22; color: white; }
        .severity-medium { background: #f39c12; color: white; }
        .severity-low { background: #3498db; color: white; }
        .timestamp { color: #7f8c8d; font-style: italic; text-align: center; margin-top: 30px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 NetSecScan Security Report</h1>
            <p>Generated on {{ timestamp }}</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>Targets Scanned</h3>
                <div class="number">{{ summary.targets }}</div>
            </div>
            <div class="summary-card">
                <h3>Open Ports</h3>
                <div class="number">{{ summary.open_ports }}</div>
            </div>
            <div class="summary-card">
                <h3>Services Detected</h3>
                <div class="number">{{ summary.services_detected }}</div>
            </div>
            <div class="summary-card">
                <h3>Vulnerabilities</h3>
                <div class="number">{{ summary.vulnerabilities }}</div>
            </div>
        </div>
        
        {% for target, result in results.items() %}
        <div class="target-section">
            <div class="target-header">🎯 {{ target }}</div>
            <div class="target-content">
                <h3>Open Ports & Services</h3>
                {% if result.open_ports %}
                <div class="ports-grid">
                    {% for port in result.open_ports|sort %}
                    <div class="port-card">
                        <div class="port-number">Port {{ port }}/tcp</div>
                        {% if result.services[port] %}
                        <div class="service-info">
                            <strong>{{ result.services[port].service }}</strong>
                            {% if result.services[port].version %}
                            <br>Version: {{ result.services[port].version }}
                            {% endif %}
                        </div>
                        {% endif %}
                    </div>
                    {% endfor %}
                </div>
                {% else %}
                <p>No open ports found.</p>
                {% endif %}
                
                {% if result.vulnerabilities %}
                <div class="vuln-section">
                    <h3>⚠️ Security Issues ({{ result.vulnerabilities|length }})</h3>
                    {% for vuln in result.vulnerabilities %}
                    <div class="vuln-item vuln-{{ vuln.severity }}">
                        <div class="vuln-header">
                            {{ vuln.id }} 
                            <span class="severity-badge severity-{{ vuln.severity }}">{{ vuln.severity }}</span>
                        </div>
                        <div class="vuln-desc">{{ vuln.description }}</div>
                        {% if vuln.recommendation %}
                        <div style="margin-top: 8px; color: #27ae60;">
                            <strong>💡 Recommendation:</strong> {{ vuln.recommendation }}
                        </div>
                        {% endif %}
                    </div>
                    {% endfor %}
                </div>
                {% endif %}
            </div>
        </div>
        {% endfor %}
        
        <div class="timestamp">
            Report generated by NetSecScan v1.0
        </div>
    </div>
</body>
</html>'''
    
    def _get_json_template(self) -> Dict:
        """Get JSON report template structure"""
        return {
            "scan_info": {
                "timestamp": "",
                "scanner": "NetSecScan",
                "version": "1.0"
            },
            "summary": {},
            "results": {}
        }
