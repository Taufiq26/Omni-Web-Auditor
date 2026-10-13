import time
import copy
from typing import List, Dict, Optional
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from src.core.session import ScannerSession
from src.core.coverage import (
    coverage_entry,
    STATUS_TESTED,
    STATUS_SKIPPED,
    STATUS_NOT_APPLICABLE,
)
from src.core.idor_utils import is_uuid, response_similarity
from src.core.endpoints import EndpointsConfig, INJECT_MARKER

# Payload non-destruktif (tidak mengubah/menghapus data) -- hanya memicu error/reflection.
SQLI_PROBE = "'"
SQL_ERROR_SIGNATURES = ["sql syntax", "mysql_fetch_array", "ora-", "postgresql query failed"]
XSS_PROBE = "<testxss>123</testxss>"
REQUEST_DELAY_SECONDS = 1  # jeda antar request aktif -> cegah DoS/WAF block

# Ambang kemiripan respons untuk membedakan "objek berbeda" vs "respon generik".
IDOR_SIMILARITY_THRESHOLD = 0.98


class ActiveScanner:
    def __init__(
        self,
        session: ScannerSession,
        endpoints: Optional[EndpointsConfig] = None,
        session_b: Optional[ScannerSession] = None,
    ):
        """Scanner aktif (SQLi/XSS/IDOR).

        Args:
            session: sesi utama (juga berperan sebagai "akun A" pada uji IDOR dua-akun).
            endpoints: konfigurasi endpoint manual (--endpoints-file), bila ada.
            session_b: sesi "akun B" (penyerang) untuk uji IDOR dua-akun, bila ada.
        """
        self.session = session
        self.endpoints = endpoints
        self.session_b = session_b
        self.coverage: List[Dict[str, str]] = []

    def _add_coverage(self, test: str, status: str, detail: str):
        self.coverage.append(coverage_entry(test, status, detail))

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

    def _safe_request(self, test_url: str):
        time.sleep(REQUEST_DELAY_SECONDS)  # jeda -> cegah DoS/WAF block
        return self.session.get_request(test_url)

    def _inspect_injection_response(self, response, payload: str, param: str, location: str) -> Optional[Dict]:
        """Deteksi non-destruktif: error SQL atau reflection XSS pada satu respons."""
        if not response:
            return None
        text = response.text
        lowered = text.lower()
        if payload == SQLI_PROBE and any(err in lowered for err in SQL_ERROR_SIGNATURES):
            return {
                "vulnerability": f"Potential SQL Injection pada '{param}'",
                "severity": "High",
                "location": location,
                "evidence": "Pesan error database terdeteksi saat menyisipkan kutip tunggal (').",
                "remediation": "Gunakan Prepared Statements atau ORM. Lakukan sanitasi dan validasi input dengan ketat."
            }
        if payload == XSS_PROBE and XSS_PROBE in text:
            return {
                "vulnerability": f"Reflected XSS pada '{param}'",
                "severity": "High",
                "location": location,
                "evidence": f"Payload '{XSS_PROBE}' dipantulkan kembali tanpa HTML encoding.",
                "remediation": "Terapkan output encoding/escaping saat menampilkan input pengguna."
            }
        return None

    def test_input_validation(self, url_with_param: str) -> List[Dict]:
        """Uji SQLi/XSS pada query parameter URL (error-based & reflected)."""
        findings = []
        parsed_url = urlparse(url_with_param)
        query_params = parse_qs(parsed_url.query)

        if not query_params:
            return findings

        for param, values in query_params.items():
            for value in values:
                for payload in (SQLI_PROBE, XSS_PROBE):
                    # Immutable: salin dict, jangan mutasi query_params asli.
                    test_params = copy.deepcopy(query_params)
                    test_params[param] = [value + payload if payload == SQLI_PROBE else payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed_url._replace(query=test_query))

                    response = self._safe_request(test_url)
                    finding = self._inspect_injection_response(response, payload, param, test_url)
                    if finding:
                        findings.append(finding)

        return findings

    def test_input_validation_body(self) -> List[Dict]:
        """Uji SQLi/XSS pada endpoint berbasis body/query JSON (dari --endpoints-file).

        Hanya menguji endpoint yang DISIAPKAN MANUAL oleh penguji -- tidak ada
        crawling otomatis (docs/07, Masalah #1 poin 3).
        """
        findings = []
        if not self.endpoints or not self.endpoints.injection_tests:
            return findings

        for test in self.endpoints.injection_tests:
            method, url = test["method"], test["url"]
            for payload in (SQLI_PROBE, XSS_PROBE):
                # Bangun body & query BARU dengan marker diganti payload (immutable).
                body = self._apply_payload(test.get("body", {}), payload)
                query = self._apply_payload(test.get("query", {}), payload)

                time.sleep(REQUEST_DELAY_SECONDS)
                kwargs = {}
                if body:
                    kwargs["json"] = body
                if query:
                    kwargs["params"] = query
                response = self.session.request(method, url, **kwargs)

                injected_fields = self._injected_field_names(test)
                finding = self._inspect_injection_response(
                    response, payload, ", ".join(injected_fields) or "body", f"{method} {url}"
                )
                if finding:
                    findings.append(finding)

        return findings

    @staticmethod
    def _apply_payload(template: Dict, payload: str) -> Dict:
        """Kembalikan salinan baru template dengan setiap nilai '{{INJECT}}' -> payload."""
        result = {}
        for key, value in template.items():
            result[key] = payload if value == INJECT_MARKER else value
        return result

    @staticmethod
    def _injected_field_names(test: Dict) -> List[str]:
        names = [k for k, v in test.get("body", {}).items() if v == INJECT_MARKER]
        names += [k for k, v in test.get("query", {}).items() if v == INJECT_MARKER]
        return names

    def check_api_idor(self, api_endpoint: str) -> List[Dict]:
        """Uji IDOR/BOLA berbasis ID numerik berurutan (ID+1).

        Diperkuat dengan request KONTROL ke ID yang hampir pasti tidak ada, untuk
        menekan false-positive pada endpoint yang selalu balas 200.
        Untuk ID berbentuk UUID, metode ID+1 TIDAK berlaku -> dicatat jujur sebagai
        belum teruji (perlu uji dua-akun).
        """
        findings = []
        parsed = urlparse(api_endpoint)
        path_parts = parsed.path.strip('/').split('/')

        numeric_id_index = next((i for i, p in enumerate(path_parts) if p.isdigit()), -1)
        uuid_in_path = any(is_uuid(p) for p in path_parts)

        if numeric_id_index == -1:
            if uuid_in_path:
                self._add_coverage(
                    "IDOR/BOLA (ID+1 sekuensial)", STATUS_NOT_APPLICABLE,
                    "Path memakai UUID (tidak berurutan by design). Metode ID+1 tidak berlaku; "
                    "gunakan uji dua-akun (--token-a/--token-b + --endpoints-file).",
                )
            else:
                self._add_coverage(
                    "IDOR/BOLA (ID+1 sekuensial)", STATUS_SKIPPED,
                    "Tidak ditemukan ID numerik berurutan di path. Belum teruji dengan metode ID+1.",
                )
            return findings

        original_id = path_parts[numeric_id_index]

        def build_url(new_id: str) -> str:
            parts = list(path_parts)
            parts[numeric_id_index] = new_id
            return urlunparse(parsed._replace(path='/' + '/'.join(parts)))

        test_id = str(int(original_id) + 1)
        control_id = str(int(original_id) + 987654321)  # hampir pasti tidak ada

        time.sleep(REQUEST_DELAY_SECONDS)
        test_resp = self.session.get_request(build_url(test_id))
        time.sleep(REQUEST_DELAY_SECONDS)
        control_resp = self.session.get_request(build_url(control_id))

        self._add_coverage(
            "IDOR/BOLA (ID+1 sekuensial)", STATUS_TESTED,
            f"Diuji ID+1 ({test_id}) dengan request kontrol ({control_id}) terhadap {api_endpoint}.",
        )

        if not (test_resp and test_resp.status_code == 200):
            return findings
        if 'application/json' not in test_resp.headers.get('Content-Type', ''):
            return findings

        # Guard false-positive: kalau ID kontrol (objek tak-ada) juga balas 200 dengan
        # isi sangat mirip, berarti endpoint balas 200 untuk apa pun -> bukan bukti IDOR.
        if control_resp and control_resp.status_code == 200:
            if response_similarity(test_resp.text, control_resp.text) >= IDOR_SIMILARITY_THRESHOLD:
                self._add_coverage(
                    "IDOR/BOLA (ID+1 sekuensial)", STATUS_TESTED,
                    "Endpoint membalas 200 untuk ID valid maupun ID kontrol tak-ada dengan isi "
                    "serupa -> indikasi respons generik, bukan IDOR. Tidak dilaporkan.",
                )
                return findings

        findings.append({
            "vulnerability": "Broken Object Level Authorization (BOLA/IDOR)",
            "severity": "High",
            "location": build_url(test_id),
            "evidence": (
                f"Resource JSON milik objek lain (ID: {test_id}) dapat diakses (HTTP 200), "
                f"dan isinya berbeda dari request kontrol ke ID tak-ada (ID: {control_id})."
            ),
            "remediation": "Terapkan pengecekan otorisasi pada level objek (object-level authorization).",
        })
        return findings

    def check_idor_two_account(self) -> List[Dict]:
        """Uji IDOR/BOLA dua-akun untuk sistem berbasis UUID (docs/07, Masalah #2).

        Akun A (self.session) memiliki objek di idor_object_urls. Tool mengakses URL
        yang sama dengan akun B (self.session_b). Bila B bisa melihat objek milik A
        (200 + isi mirip respons A), itu temuan IDOR valid.

        ETIKA: kedua akun adalah akun UJI milik penguji sendiri, dan URL objek
        disiapkan manual -- tidak menyentuh data pengguna nyata.
        """
        findings = []
        object_urls = self.endpoints.idor_object_urls if self.endpoints else []

        if not object_urls:
            self._add_coverage(
                "IDOR/BOLA (dua-akun UUID)", STATUS_SKIPPED,
                "Tidak ada idor_object_urls di endpoints-file. Belum teruji.",
            )
            return findings
        if not self.session_b:
            self._add_coverage(
                "IDOR/BOLA (dua-akun UUID)", STATUS_SKIPPED,
                "Butuh dua kredensial uji (--token-a/-b atau --cookie-a/-b). Belum teruji.",
            )
            return findings

        tested_any = False
        for url in object_urls:
            time.sleep(REQUEST_DELAY_SECONDS)
            resp_a = self.session.get_request(url)
            time.sleep(REQUEST_DELAY_SECONDS)
            resp_b = self.session_b.get_request(url)

            if not (resp_a and resp_a.status_code == 200):
                # Objek A sendiri tidak bisa diambil -> URL/kredensial A keliru; lewati.
                continue
            tested_any = True

            if resp_b and resp_b.status_code == 200:
                similarity = response_similarity(resp_a.text, resp_b.text)
                if similarity >= IDOR_SIMILARITY_THRESHOLD:
                    findings.append({
                        "vulnerability": "Broken Object Level Authorization (BOLA/IDOR) - Cross-Account",
                        "severity": "High",
                        "location": url,
                        "evidence": (
                            "Akun B berhasil mengakses objek milik akun A (HTTP 200, isi respons "
                            f"identik ~{similarity:.0%}). Otorisasi level objek tidak diterapkan."
                        ),
                        "remediation": "Validasi kepemilikan objek terhadap identitas pemanggil pada setiap request.",
                    })

        if tested_any:
            self._add_coverage(
                "IDOR/BOLA (dua-akun UUID)", STATUS_TESTED,
                f"Diuji {len(object_urls)} URL objek dengan dua akun (A vs B).",
            )
        else:
            self._add_coverage(
                "IDOR/BOLA (dua-akun UUID)", STATUS_SKIPPED,
                "Tidak ada objek milik A yang berhasil diambil (cek URL/kredensial A). Belum teruji.",
            )
        return findings

    def run_scan(self, target: str, has_auth: bool = False) -> List[Dict]:
        all_findings = []

        print(f"[*] Menjalankan pendeteksian komponen usang pada {target}...")
        all_findings.extend(self.detect_components(target))

        parsed = urlparse(target)

        # --- SQLi/XSS: query parameter URL ---
        if parsed.query:
            print(f"[*] Menjalankan pengujian validasi input (SQLi & XSS) pada parameter URL...")
            all_findings.extend(self.test_input_validation(target))
            self._add_coverage(
                "SQLi/XSS (query parameter)", STATUS_TESTED,
                f"Diuji parameter query pada {target}.",
            )
        else:
            self._add_coverage(
                "SQLi/XSS (query parameter)", STATUS_NOT_APPLICABLE,
                "Target tidak punya parameter query (?param=). Lihat uji berbasis body di bawah.",
            )

        # --- SQLi/XSS: body/query JSON dari endpoints-file ---
        if self.endpoints and self.endpoints.injection_tests:
            print(f"[*] Menjalankan pengujian validasi input (SQLi & XSS) pada body JSON endpoint...")
            all_findings.extend(self.test_input_validation_body())
            self._add_coverage(
                "SQLi/XSS (body/JSON endpoint)", STATUS_TESTED,
                f"Diuji {len(self.endpoints.injection_tests)} endpoint dari endpoints-file.",
            )
        else:
            self._add_coverage(
                "SQLi/XSS (body/JSON endpoint)", STATUS_SKIPPED,
                "Tidak ada --endpoints-file dengan injection_tests. API berbasis body belum teruji.",
            )

        # --- IDOR/BOLA numerik ---
        if has_auth and ('/api/' in parsed.path or 'api' in parsed.netloc):
            print(f"[*] Menjalankan pengujian IDOR/BOLA (ID+1) pada endpoint API {target}...")
            all_findings.extend(self.check_api_idor(target))
        else:
            self._add_coverage(
                "IDOR/BOLA (ID+1 sekuensial)", STATUS_SKIPPED,
                "Butuh kredensial (--cookie/--token) dan endpoint API. Belum teruji.",
            )

        # --- IDOR/BOLA dua-akun (UUID) ---
        print(f"[*] Menjalankan pengujian IDOR/BOLA dua-akun (jika dikonfigurasi)...")
        all_findings.extend(self.check_idor_two_account())

        return all_findings
