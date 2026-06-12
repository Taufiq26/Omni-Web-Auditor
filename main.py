import sys
import datetime
from urllib.parse import urlparse
from src.core.cli_parser import parse_args
from src.core.session import ScannerSession
from src.modules.basic_scan import BasicScanner
from src.modules.active_scan import ActiveScanner
from src.modules.infra_scan import InfraScanner
from src.reports.pdf_gen import PDFReportGenerator

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
        
    # 7. Eksekusi Infra Scan
    if args.scan_type in ['infra', 'full']:
        print("[+] Memulai Server & Infrastructure Scan...")
        infra_scanner = InfraScanner(session)
        infra_findings = infra_scanner.run_scan(args.target)
        all_findings.extend(infra_findings)
        
    print("-" * 70)
    print(f"[+] Audit sementara selesai. Ditemukan {len(all_findings)} potensi kerentanan.")
    
    # 8. Menghasilkan Laporan PDF
    report_filename = args.output
    if report_filename == "report_target.pdf":
        parsed_target = urlparse(args.target)
        target_name = parsed_target.hostname or args.target.replace('http://', '').replace('https://', '').split('/')[0]
        target_name = target_name.split(':')[0]
        date_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"audit_report_{target_name}_{date_str}.pdf"
        
    print(f"[+] Menghasilkan Laporan PDF: {report_filename}...")
    report_gen = PDFReportGenerator(all_findings, args.target)
    report_gen.generate_report(report_filename)
    
    print(f"[+] Selesai! Laporan berhasil disimpan ke {report_filename}")

if __name__ == "__main__":
    main()
