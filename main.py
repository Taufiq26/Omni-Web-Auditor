import sys
from urllib.parse import urlparse
from src.core.cli_parser import parse_args
from src.core.session import ScannerSession
from src.modules.basic_scan import BasicScanner
from src.modules.active_scan import ActiveScanner

def main():
    # 1. Eksekusi cli_parser untuk menangkap argumen pengguna
    args = parse_args()
    
    # 2. Inisialisasi ScannerSession
    session = ScannerSession(cookie=args.cookie, bearer_token=args.token)
    
    # 3. Validasi sederhana URL target
    if args.scan_type in ['web', 'full']:
        parsed_url = urlparse(args.target)
        if parsed_url.scheme not in ['http', 'https']:
            print("[!] Peringatan: Target web tidak memiliki skema http:// atau https://")
            print(f"    Target saat ini: {args.target}")
            print("    Pastikan Anda menyertakan skema URL yang valid untuk pemindaian web.")
            print("----------------------------------------------------------------------")
            
    # 4. Print sukses inisialisasi
    print(f"[+] Memulai sesi audit untuk target: {args.target} dan tipe scan: {args.scan_type}")
    print("-" * 70)
    
    all_findings = []
    
    # 5. Eksekusi Web Basic Scan
    if args.scan_type in ['web', 'full']:
        print("[+] Memulai Web Basic Security Scan...")
        basic_scanner = BasicScanner(session)
        web_findings = basic_scanner.run_scan(args.target)
        all_findings.extend(web_findings)
        
    # 6. Eksekusi Web Active Scan
    if args.scan_type in ['web', 'full']:
        print("[+] Memulai Web Intermediate & Advanced Scan (Active)...")
        has_auth = bool(args.cookie or args.token)
        active_scanner = ActiveScanner(session)
        active_findings = active_scanner.run_scan(args.target, has_auth=has_auth)
        all_findings.extend(active_findings)
        
    print("-" * 70)
    print(f"[+] Audit sementara selesai. Ditemukan {len(all_findings)} potensi kerentanan.")
    
    # Print temuan sementara sebelum modul laporan PDF jadi
    for finding in all_findings:
        print(f"    - [{finding['severity']}] {finding['vulnerability']} at {finding['location']}")

if __name__ == "__main__":
    main()
