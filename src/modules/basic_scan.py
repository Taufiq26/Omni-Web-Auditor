import ssl
import socket
from datetime import datetime
from typing import List, Dict
from urllib.parse import urlparse
from src.core.session import ScannerSession

class BasicScanner:
    def __init__(self, session: ScannerSession):
        self.session = session

    def check_security_headers(self, url: str) -> List[Dict]:
        findings = []
        response = self.session.get_request(url)
        
        if response is None:
            return findings
            
        headers_to_check = {
            'Strict-Transport-Security': 'Enforces secure (HTTP over SSL/TLS) connections to the server',
            'Content-Security-Policy': 'Prevents Cross-Site Scripting (XSS) and other code injection attacks',
            'X-Frame-Options': 'Protects against Clickjacking attacks',
            'X-Content-Type-Options': 'Prevents MIME-sniffing'
        }
        
        for header, remediation_hint in headers_to_check.items():
            if header not in response.headers:
                findings.append({
                    "vulnerability": f"Missing Security Header: {header}",
                    "severity": "Low",
                    "location": url,
                    "evidence": f"Header {header} tidak ditemukan pada response HTTP",
                    "remediation": f"Tambahkan konfigurasi header {header} pada web server. {remediation_hint}."
                })
                
        return findings

    def check_ssl_cert(self, domain: str) -> List[Dict]:
        findings = []
        parsed = urlparse(domain)
        # Handle cases where domain might be a full URL or just a hostname
        hostname = parsed.hostname or domain.replace("http://", "").replace("https://", "").split("/")[0]
        hostname = hostname.split(':')[0]
        
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check expiration
                    not_after_str = cert.get('notAfter')
                    if not_after_str:
                        # Format example: 'Oct  8 12:00:00 2024 GMT'
                        not_after_date = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                        days_left = (not_after_date - datetime.utcnow()).days
                        if days_left < 14:
                            findings.append({
                                "vulnerability": "SSL Certificate Expiring Soon",
                                "severity": "Medium",
                                "location": f"{hostname}:443",
                                "evidence": f"Sertifikat akan kedaluwarsa dalam {days_left} hari ({not_after_str})",
                                "remediation": "Segera perbarui sertifikat SSL/TLS sebelum masa aktif habis."
                            })
                    
                    # Check protocol version
                    protocol = ssock.version()
                    if protocol in ['SSLv3', 'TLSv1', 'TLSv1.1']:
                        findings.append({
                            "vulnerability": "Obsolete SSL/TLS Protocol",
                            "severity": "High",
                            "location": f"{hostname}:443",
                            "evidence": f"Server menggunakan protokol usang: {protocol}",
                            "remediation": "Nonaktifkan SSLv3, TLS 1.0, dan TLS 1.1. Gunakan minimal TLS 1.2 atau TLS 1.3."
                        })
                        
        except ssl.SSLError as e:
            findings.append({
                "vulnerability": "SSL/TLS Error",
                "severity": "Medium",
                "location": f"{hostname}:443",
                "evidence": f"SSL Error: {str(e)}",
                "remediation": "Periksa konfigurasi sertifikat SSL/TLS, pastikan valid dan diterbitkan oleh Certificate Authority yang terpercaya."
            })
        except socket.timeout:
            pass # Timeout on port 443, skip gracefully
        except Exception as e:
            pass # Other connection errors like connection refused, skip gracefully
            
        return findings

    def check_exposed_files(self, base_url: str) -> List[Dict]:
        findings = []
        base_url = base_url.rstrip('/')
        
        paths_to_check = {
            '/.env': {'signatures': ['DB_PASSWORD', 'APP_KEY', 'DB_HOST', 'SECRET'], 'vuln': 'Exposed .env File'},
            '/.git/config': {'signatures': ['[core]'], 'vuln': 'Exposed Git Repository'},
            '/robots.txt': {'signatures': ['User-agent:'], 'vuln': 'Information Disclosure via robots.txt', 'severity': 'Low'},
            '/server-status': {'signatures': ['Apache Server Status'], 'vuln': 'Exposed Apache Server Status'},
            '/.DS_Store': {'signatures': [], 'vuln': 'Exposed .DS_Store File', 'check_binary': b'Bud1'},
            '/backup.zip': {'signatures': [], 'vuln': 'Exposed Backup File', 'check_binary': b'PK\x03\x04'}
        }
        
        for path, info in paths_to_check.items():
            url = f"{base_url}{path}"
            response = self.session.get_request(url, allow_redirects=False)
            
            if response is None:
                continue
                
            if response.status_code == 200:
                is_vulnerable = False
                
                # Check signature
                if 'check_binary' in info:
                    if response.content.startswith(info['check_binary']) or info['check_binary'] in response.content[:100]:
                        is_vulnerable = True
                else:
                    text_content = response.text
                    for sig in info['signatures']:
                        if sig in text_content:
                            is_vulnerable = True
                            break
                            
                if is_vulnerable:
                    severity = info.get('severity', 'High')
                    findings.append({
                        "vulnerability": info['vuln'],
                        "severity": severity,
                        "location": url,
                        "evidence": "File ditemukan (HTTP 200) dan cocok dengan signature sensitif.",
                        "remediation": f"Hapus file {path} dari server publik atau batasi akses menggunakan konfigurasi web server (.htaccess / nginx config)."
                    })
                    
        return findings

    def run_scan(self, target: str) -> List[Dict]:
        all_findings = []
        
        print(f"[*] Menjalankan pemeriksaan Security Headers pada {target}...")
        all_findings.extend(self.check_security_headers(target))
        
        print(f"[*] Menjalankan pemeriksaan SSL/TLS pada {target}...")
        all_findings.extend(self.check_ssl_cert(target))
        
        print(f"[*] Menjalankan pemeriksaan Exposed Files pada {target}...")
        all_findings.extend(self.check_exposed_files(target))
        
        return all_findings
