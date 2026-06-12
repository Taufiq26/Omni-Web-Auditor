import argparse

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Omni-Web-Auditor: Security Auditor CLI")
    
    parser.add_argument(
        "--target",
        required=True,
        help="URL atau IP address target (contoh: https://kotabaruparahyangan.com atau 192.168.1.100)"
    )
    
    parser.add_argument(
        "--scan-type",
        required=True,
        choices=['web', 'infra', 'full'],
        help="Pilihan tipe scan"
    )
    
    parser.add_argument(
        "--cookie",
        required=False,
        help="String session cookie untuk audit terautentikasi"
    )
    
    parser.add_argument(
        "--token",
        required=False,
        help="String Bearer token untuk audit API terautentikasi"
    )
    
    parser.add_argument(
        "--output",
        required=False,
        default="report_target.pdf",
        help="Nama file laporan (default: report_target.pdf)"
    )
    
    return parser.parse_args()
