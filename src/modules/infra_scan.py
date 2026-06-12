import socket
import requests
import re
import urllib3
from typing import List, Dict
from urllib.parse import urlparse
from src.core.session import ScannerSession

# Disable insecure request warning for direct requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class InfraScanner:
    def __init__(self, session: ScannerSession = None):
        self.session = session

    def scan_open_ports(self, ip_target: str) -> List[Dict]:
        findings = []
        
        target_ports = {
            21: "FTP",
            22: "SSH",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            27017: "MongoDB"
        }
        
        for port, service in target_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                result = sock.connect_ex((ip_target, port))
                
                if result == 0:
                    severity = "High" if port in [3306, 5432, 6379, 27017] else "Medium"
                    findings.append({
                        "vulnerability": f"Exposed {service} Database/Service Port",
                        "severity": severity,
                        "location": f"{ip_target}:{port}",
                        "evidence": f"Koneksi TCP berhasil dibangun (Port {port} berstatus OPEN).",
                        "remediation": f"Batasi akses port {port} menggunakan firewall (iptables/UFW) atau Security Group hanya untuk IP internal yang diizinkan."
                    })
                sock.close()
            except (socket.timeout, socket.error):
                continue
                
        return findings

    def check_storage_privacy(self, target_domain: str) -> List[Dict]:
        findings = []
        parsed = urlparse(target_domain)
        hostname = parsed.hostname or target_domain.replace("http://", "").replace("https://", "").split("/")[0]
        hostname = hostname.split(':')[0]
        
        # Variasi nama bucket
        bucket_names = list(set([
            hostname,
            hostname.replace('.', '-'),
            hostname.split('.')[0]
        ]))
        
        endpoints_to_test = []
        
        # S3 endpoints
        for b in bucket_names:
            endpoints_to_test.append(f"https://{b}.s3.amazonaws.com")
            
        # MinIO endpoints
        endpoints_to_test.append(f"http://{hostname}:9000")
        endpoints_to_test.append(f"https://storage.{hostname}")
        
        for url in endpoints_to_test:
            try:
                # Request tanpa autentikasi
                resp = requests.get(url, timeout=3, verify=False)
                if resp.status_code == 200:
                    if 'ListBucketResult' in resp.text or '<?xml' in resp.text:
                        findings.append({
                            "vulnerability": "Publicly Accessible Cloud Storage (Data Leakage)",
                            "severity": "High",
                            "location": url,
                            "evidence": f"Penyimpanan merespon HTTP 200 OK dengan daftar struktur XML (ListBucketResult).",
                            "remediation": "Ubah kebijakan akses (Bucket Policy / ACL) menjadi Private. Nonaktifkan akses publik untuk listing file."
                        })
            except requests.exceptions.RequestException:
                continue
                
        # Google Drive public URL from HTML
        if self.session:
            try:
                main_resp = self.session.get_request(target_domain)
                if main_resp and main_resp.status_code == 200:
                    gdrive_links = re.findall(r'(https?://drive\.google\.com/file/d/[a-zA-Z0-9_-]+/view\?usp=sharing)', main_resp.text)
                    for link in set(gdrive_links):
                        findings.append({
                            "vulnerability": "Exposed Public Google Drive Link",
                            "severity": "Low",
                            "location": link,
                            "evidence": "URL public share Google Drive ditemukan di dalam HTML halaman utama target.",
                            "remediation": "Pastikan file yang dibagikan tidak mengandung informasi sensitif atau gunakan akses terbatas."
                        })
            except Exception:
                pass
                
        return findings

    def audit_ssh_service(self, ip_target: str) -> List[Dict]:
        findings = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            result = sock.connect_ex((ip_target, 22))
            
            if result == 0:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner.startswith("SSH-") and 'OpenSSH_' in banner:
                    version_str = banner.split('OpenSSH_')[1].split(' ')[0]
                    major_ver_match = re.match(r'^(\d+)', version_str)
                    if major_ver_match:
                        major_ver = int(major_ver_match.group(1))
                        # Versi OpenSSH di bawah 7.x dianggap usang
                        if major_ver < 7:
                            findings.append({
                                "vulnerability": "Outdated SSH Service (OpenSSH)",
                                "severity": "Medium",
                                "location": f"{ip_target}:22",
                                "evidence": f"Banner SSH menunjukkan versi OpenSSH usang: {banner}",
                                "remediation": "Perbarui paket OpenSSH di server ke versi terbaru."
                            })
            sock.close()
        except (socket.timeout, socket.error):
            pass
            
        return findings

    def run_scan(self, target: str) -> List[Dict]:
        all_findings = []
        
        parsed = urlparse(target)
        hostname = parsed.hostname or target.replace("http://", "").replace("https://", "").split("/")[0]
        hostname = hostname.split(':')[0]
        
        print(f"[*] Resolving host {hostname} ke IP Address...")
        try:
            ip_address = socket.gethostbyname(hostname)
            print(f"    Ter-resolve ke: {ip_address}")
            
            print(f"[*] Menjalankan pemindaian Port terbuka pada IP {ip_address}...")
            all_findings.extend(self.scan_open_ports(ip_address))
            
            print(f"[*] Menjalankan Audit Banner SSH pada IP {ip_address}...")
            all_findings.extend(self.audit_ssh_service(ip_address))
            
        except socket.gaierror:
            print(f"[!] Gagal mendapatkan IP address dari hostname: {hostname}")
            
        print(f"[*] Memeriksa kesalahan konfigurasi Cloud Storage & Backup pada domain...")
        all_findings.extend(self.check_storage_privacy(target))
        
        return all_findings
