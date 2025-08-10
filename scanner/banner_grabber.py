"""
Banner Grabbing Module - Collect service banners and headers
"""

import socket
import ssl
import time
import logging
from typing import Optional

logger = logging.getLogger(__name__)

class BannerGrabber:
    """Grab banners from network services"""
    
    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
    
    def grab_banner(self, target: str, port: int) -> str:
        """
        Grab banner from a service
        
        Args:
            target: IP address or hostname
            port: Port number
            
        Returns:
            Service banner as string
        """
        try:
            # Try different banner grabbing methods based on port
            if port in [80, 8080]:
                return self.grab_http_banner(target, port)
            elif port in [443, 8443]:
                return self.grab_https_banner(target, port)
            elif port in [21, 22, 23, 25, 110, 143]:
                return self.grab_tcp_banner(target, port)
            else:
                return self.grab_tcp_banner(target, port)
                
        except Exception as e:
            logger.debug(f"Banner grab failed for {target}:{port}: {str(e)}")
            return ''
    
    def grab_tcp_banner(self, target: str, port: int) -> str:
        """Grab banner using raw TCP connection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            # Some services send banner immediately
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            # If no immediate banner, try sending common probes
            if not banner:
                probes = [b'\r\n', b'GET / HTTP/1.0\r\n\r\n', b'HELP\r\n']
                
                for probe in probes:
                    try:
                        sock.send(probe)
                        time.sleep(0.5)
                        response = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                        if response:
                            banner = response
                            break
                    except:
                        continue
            
            sock.close()
            return banner
            
        except Exception as e:
            logger.debug(f"TCP banner grab failed: {str(e)}")
            return ''
    
    def grab_http_banner(self, target: str, port: int) -> str:
        """Grab HTTP banner and headers"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            # Send HTTP request
            request = f"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: NetSecScan/1.0\r\nConnection: close\r\n\r\n"
            sock.send(request.encode())
            
            # Receive response
            response = b''
            while True:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data
                    
                    # Stop after headers (double CRLF)
                    if b'\r\n\r\n' in response:
                        break
                        
                except socket.timeout:
                    break
            
            sock.close()
            return response.decode('utf-8', errors='ignore')
            
        except Exception as e:
            logger.debug(f"HTTP banner grab failed: {str(e)}")
            return ''
    
    def grab_https_banner(self, target: str, port: int) -> str:
        """Grab HTTPS banner and headers"""
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect with SSL
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            ssl_sock = context.wrap_socket(sock, server_hostname=target)
            ssl_sock.connect((target, port))
            
            # Get certificate info
            cert_info = ssl_sock.getpeercert()
            
            # Send HTTP request
            request = f"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: NetSecScan/1.0\r\nConnection: close\r\n\r\n"
            ssl_sock.send(request.encode())
            
            # Receive response
            response = b''
            while True:
                try:
                    data = ssl_sock.recv(4096)
                    if not data:
                        break
                    response += data
                    
                    # Stop after headers
                    if b'\r\n\r\n' in response:
                        break
                        
                except socket.timeout:
                    break
            
            ssl_sock.close()
            
            # Add certificate info to response
            cert_subject = dict(x[0] for x in cert_info.get('subject', []))
            banner = response.decode('utf-8', errors='ignore')
            banner += f"\n[SSL Certificate: {cert_subject.get('commonName', 'Unknown')}]"
            
            return banner
            
        except Exception as e:
            logger.debug(f"HTTPS banner grab failed: {str(e)}")
            return ''
    
    def grab_ssh_banner(self, target: str, port: int = 22) -> str:
        """Specialized SSH banner grabbing"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            # SSH servers send version string immediately
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner
            
        except Exception as e:
            logger.debug(f"SSH banner grab failed: {str(e)}")
            return ''
