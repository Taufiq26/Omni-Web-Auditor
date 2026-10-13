import socket
import requests
import re
import urllib3
from typing import List, Dict, Optional
from urllib.parse import urlparse
from src.core.session import ScannerSession
from src.core.cdn import detect_cdn
from src.core.coverage import (
    coverage_entry,
    STATUS_TESTED,
    STATUS_SKIPPED,
)

# Disable insecure request warning for direct requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class InfraScanner:
    def __init__(self, session: ScannerSession = None, origin_ip: Optional[str] = None):
        """Scanner infrastruktur (port, SSH banner, cloud storage).

        Args:
            session: sesi HTTP (untuk cek header CDN & Google Drive link).
            origin_ip: IP origin yang DIBERIKAN MANUAL penguji untuk target di balik
                CDN. Hanya dipakai bila penguji memang punya izin/akses langsung ke
                server tsb (docs/07, Masalah #3). Tool tidak pernah menebak IP origin.
        """
        self.session = session
        self.origin_ip = origin_ip
        self.coverage: List[Dict[str, str]] = []

    def _add_coverage(self, test: str, status: str, detail: str):
        self.coverage.append(coverage_entry(test, status, detail))

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
            except Exception as e:
                print(f"[!] Gagal memeriksa link Google Drive publik: {e}")

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

    def _resolve_response_headers(self, target: str):
        """Ambil header respons target (untuk deteksi CDN). None bila gagal."""
        if not self.session:
            return None
        resp = self.session.get_request(target)
        return resp.headers if resp is not None else None

    def _select_scan_ip(self, target: str, hostname: str) -> Optional[str]:
        """Tentukan IP yang BOLEH dipindai, dengan proteksi CDN.

        Mengembalikan IP yang aman dipindai, atau None bila scan harus dilewati
        (mis. di balik CDN tanpa --origin-ip). Mencatat coverage secara jujur.
        """
        # Origin-ip manual selalu menang: penguji sudah menyatakan punya izin ke IP ini.
        if self.origin_ip:
            self._add_coverage(
                "Port/SSH scan", STATUS_TESTED,
                f"Memakai --origin-ip {self.origin_ip} yang diberikan penguji secara eksplisit.",
            )
            return self.origin_ip

        try:
            ip_address = socket.gethostbyname(hostname)
        except socket.gaierror:
            self._add_coverage(
                "Port/SSH scan", STATUS_SKIPPED,
                f"Gagal me-resolve hostname {hostname} ke IP. Belum teruji.",
            )
            print(f"[!] Gagal mendapatkan IP address dari hostname: {hostname}")
            return None

        print(f"    Ter-resolve ke: {ip_address}")
        headers = self._resolve_response_headers(target)
        cdn = detect_cdn(ip=ip_address, headers=headers)
        if cdn:
            msg = (
                f"IP ter-resolve ({ip_address}) terdeteksi milik {cdn}, bukan server asal. "
                "Port scan & SSH banner grab TIDAK dijalankan (infrastruktur pihak ketiga di "
                "luar izin). Berikan --origin-ip bila kamu punya izin langsung ke server asal."
            )
            print(f"[!] {msg}")
            self._add_coverage("Port/SSH scan", STATUS_SKIPPED, msg)
            return None

        self._add_coverage(
            "Port/SSH scan", STATUS_TESTED,
            f"Memindai IP ter-resolve {ip_address} (tidak terdeteksi di belakang CDN).",
        )
        return ip_address

    def run_scan(self, target: str) -> List[Dict]:
        all_findings = []

        parsed = urlparse(target)
        hostname = parsed.hostname or target.replace("http://", "").replace("https://", "").split("/")[0]
        hostname = hostname.split(':')[0]

        print(f"[*] Resolving host {hostname} ke IP Address...")
        scan_ip = self._select_scan_ip(target, hostname)

        if scan_ip:
            print(f"[*] Menjalankan pemindaian Port terbuka pada IP {scan_ip}...")
            all_findings.extend(self.scan_open_ports(scan_ip))

            print(f"[*] Menjalankan Audit Banner SSH pada IP {scan_ip}...")
            all_findings.extend(self.audit_ssh_service(scan_ip))

        print(f"[*] Memeriksa kesalahan konfigurasi Cloud Storage & Backup pada domain...")
        all_findings.extend(self.check_storage_privacy(target))
        self._add_coverage(
            "Cloud storage misconfiguration", STATUS_TESTED,
            "Dicek endpoint S3/MinIO/storage umum & link Google Drive publik di HTML.",
        )

        return all_findings
