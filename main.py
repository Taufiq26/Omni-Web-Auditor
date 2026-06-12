import sys
from urllib.parse import urlparse
from src.core.cli_parser import parse_args
from src.core.session import ScannerSession

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

if __name__ == "__main__":
    main()
