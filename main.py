#!/usr/bin/env python3
"""
NetSecScan - Network Scanner & Vulnerability Detector
Main entry point for the application
"""

import click
import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from scanner.port_scanner import PortScanner
from scanner.service_detector import ServiceDetector
from vulnerabilities.cve_checker import CVEChecker
from reporting.report_generator import ReportGenerator
from utils.logger import setup_logger
from utils.network_utils import validate_target, parse_port_range

@click.command()
@click.option('-t', '--target', required=True, help='Target IP address or range')
@click.option('-p', '--ports', default='1-1000', help='Port range (default: 1-1000)')
@click.option('--vuln-scan', is_flag=True, help='Enable vulnerability scanning')
@click.option('--threads', default=100, help='Number of threads (default: 100)')
@click.option('--timeout', default=1.0, help='Connection timeout (default: 1.0)')
@click.option('--output', default='console', help='Output format: console, json, html')
@click.option('--report-file', help='Output file for reports')
@click.option('--config', help='Custom config file path')
@click.option('-v', '--verbose', is_flag=True, help='Verbose output')
def main(target, ports, vuln_scan, threads, timeout, output, report_file, config, verbose):
    """NetSecScan - Network Scanner & Vulnerability Detector"""
    
    # Setup logging
    logger = setup_logger(verbose)
    
    try:
        # Validate inputs
        targets = validate_target(target)
        port_range = parse_port_range(ports)
        
        click.echo(f"🔍 Starting NetSecScan on {target}")
        click.echo(f"📊 Scanning {len(port_range)} ports with {threads} threads")
        
        results = {}
        
        for target_ip in targets:
            click.echo(f"\n🎯 Scanning target: {target_ip}")
            
            # Port scanning
            scanner = PortScanner(threads=threads, timeout=timeout)
            open_ports = scanner.scan(target_ip, port_range)
            
            if not open_ports:
                click.echo("❌ No open ports found")
                continue
                
            click.echo(f"✅ Found {len(open_ports)} open ports")
            
            # Service detection
            service_detector = ServiceDetector()
            services = service_detector.detect_services(target_ip, open_ports)
            
            target_results = {
                'target': target_ip,
                'open_ports': open_ports,
                'services': services,
                'vulnerabilities': []
            }
            
            # Vulnerability scanning
            if vuln_scan:
                click.echo("🔎 Checking for vulnerabilities...")
                cve_checker = CVEChecker()
                vulns = cve_checker.check_vulnerabilities(services)
                target_results['vulnerabilities'] = vulns
                
                if vulns:
                    click.echo(f"⚠️  Found {len(vulns)} potential vulnerabilities")
                else:
                    click.echo("✅ No known vulnerabilities found")
            
            results[target_ip] = target_results
        
        # Generate report
        report_gen = ReportGenerator()
        
        if output == 'console':
            report_gen.print_console_report(results)
        elif output in ['json', 'html']:
            if not report_file:
                report_file = f"scan_report.{output}"
            report_gen.generate_report(results, output, report_file)
            click.echo(f"📄 Report saved to {report_file}")
        
        click.echo("\n🎉 Scan completed successfully!")
        
    except KeyboardInterrupt:
        click.echo("\n⏹️  Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
