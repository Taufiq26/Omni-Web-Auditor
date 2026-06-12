import time
from typing import List, Dict
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from src.core.session import ScannerSession

class ActiveScanner:
    def __init__(self, session: ScannerSession):
        self.session = session

    def detect_components(self, url: str) -> List[Dict]:
        findings = []
        response = self.session.get_request(url)
        if not response:
            return findings
            
        # 1. Pengecekan X-Powered-By
        powered_by = response.headers.get('X-Powered-By', '')
        if powered_by:
            outdated_php = ['PHP/5.', 'PHP/7.0', 'PHP/7.1', 'PHP/7.2', 'PHP/7.3', 'PHP/7.4']
            if any(ver in powered_by for ver in outdated_php):
                findings.append({
                    "vulnerability": "Outdated Server Component Detected",
                    "severity": "Medium",
                    "location": url,
                    "evidence": f"Header X-Powered-By menunjukkan versi usang: {powered_by}",
                    "remediation": "Perbarui komponen server (misal: PHP) ke versi terbaru yang masih mendapatkan dukungan keamanan."
                })
        
        # 2. Pengecekan Meta Generator & Scripts
        content_type = response.headers.get('Content-Type', '')
        if 'text/html' in content_type:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Meta Generator
            generator = soup.find('meta', attrs={'name': 'generator'})
            if generator and generator.get('content'):
                content = generator['content'].lower()
                outdated_cms = ['wordpress 4.', 'wordpress 3.', 'joomla! 1.', 'joomla! 2.']
                if any(cms in content for cms in outdated_cms):
                    findings.append({
                        "vulnerability": "Outdated CMS Detected",
                        "severity": "Medium",
                        "location": url,
                        "evidence": f"Tag meta generator menunjukkan versi CMS usang: {generator['content']}",
                        "remediation": "Perbarui CMS (WordPress/Joomla dll) beserta plugin ke versi terbaru."
                    })
                    
            # Script libraries
            for script in soup.find_all('script', src=True):
                src = script['src'].lower()
                if 'jquery-1.' in src or 'jquery-2.' in src:
                    findings.append({
                        "vulnerability": "Outdated JavaScript Library",
                        "severity": "Medium",
                        "location": url,
                        "evidence": f"Pustaka JavaScript usang ditemukan pada URL: {script['src']}",
                        "remediation": "Perbarui pustaka JavaScript (jQuery dll) ke versi terbaru."
                    })
                    
        return findings

    def test_input_validation(self, url_with_param: str) -> List[Dict]:
        findings = []
        parsed_url = urlparse(url_with_param)
        query_params = parse_qs(parsed_url.query)
        
        if not query_params:
            return findings
            
        def safe_request(test_url: str):
            time.sleep(1) # Delay untuk mencegah DoS/WAF blocks
            return self.session.get_request(test_url)
            
        for param, values in query_params.items():
            for value in values:
                # 1. Test SQLi (Error-Based)
                sqli_payload = value + "'"
                test_params = query_params.copy()
                test_params[param] = sqli_payload
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed_url._replace(query=test_query))
                
                response = safe_request(test_url)
                if response:
                    text = response.text.lower()
                    sql_errors = ["sql syntax", "mysql_fetch_array", "ora-", "postgresql query failed"]
                    if any(err in text for err in sql_errors):
                        findings.append({
                            "vulnerability": f"Potential SQL Injection pada parameter '{param}'",
                            "severity": "High",
                            "location": test_url,
                            "evidence": "Pesan error database terdeteksi saat menyisipkan kutip tunggal (')",
                            "remediation": "Gunakan Prepared Statements atau ORM. Lakukan sanitasi dan validasi input dengan ketat."
                        })
                        
                # 2. Test XSS (Reflected)
                xss_payload = "<testxss>123</testxss>"
                test_params[param] = xss_payload
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed_url._replace(query=test_query))
                
                response = safe_request(test_url)
                if response:
                    if xss_payload in response.text:
                        findings.append({
                            "vulnerability": f"Reflected XSS pada parameter '{param}'",
                            "severity": "High",
                            "location": test_url,
                            "evidence": f"Payload '{xss_payload}' dipantulkan kembali tanpa HTML encoding.",
                            "remediation": "Terapkan output encoding/escaping (misal: htmlspecialchars) saat menampilkan input pengguna di halaman web."
                        })
                        
        return findings

    def check_api_idor(self, api_endpoint: str) -> List[Dict]:
        findings = []
        parsed = urlparse(api_endpoint)
        path_parts = parsed.path.strip('/').split('/')
        
        numeric_id_index = -1
        original_id = None
        
        for i, part in enumerate(path_parts):
            if part.isdigit():
                numeric_id_index = i
                original_id = part
                break
                
        if numeric_id_index != -1 and original_id is not None:
            # Mencoba ID lain (ID + 1)
            test_id = str(int(original_id) + 1)
            test_path_parts = list(path_parts)
            test_path_parts[numeric_id_index] = test_id
            test_path = '/' + '/'.join(test_path_parts)
            test_url = urlunparse(parsed._replace(path=test_path))
            
            time.sleep(1) # Delay untuk keamanan
            response = self.session.get_request(test_url)
            
            if response and response.status_code == 200:
                content_type = response.headers.get('Content-Type', '')
                if 'application/json' in content_type:
                    findings.append({
                        "vulnerability": "Broken Object Level Authorization (BOLA/IDOR)",
                        "severity": "High",
                        "location": test_url,
                        "evidence": f"Berhasil mengakses resource JSON milik user/objek lain (ID: {test_id}) dengan respon HTTP 200 OK.",
                        "remediation": "Terapkan pengecekan otorisasi pada level objek. Pastikan user yang sedang login memiliki hak akses ke resource yang diminta."
                    })
                    
        return findings

    def run_scan(self, target: str, has_auth: bool = False) -> List[Dict]:
        all_findings = []
        
        print(f"[*] Menjalankan pendeteksian komponen usang pada {target}...")
        all_findings.extend(self.detect_components(target))
        
        parsed = urlparse(target)
        if parsed.query:
            print(f"[*] Menjalankan pengujian validasi input (SQLi & XSS) pada parameter URL...")
            all_findings.extend(self.test_input_validation(target))
        else:
            print(f"[*] Melewati pengujian validasi input (tidak ada parameter URL pada target).")
            
        if has_auth and ('/api/' in parsed.path or 'api' in parsed.netloc):
            print(f"[*] Menjalankan pengujian IDOR/BOLA pada endpoint API {target}...")
            all_findings.extend(self.check_api_idor(target))
            
        return all_findings
