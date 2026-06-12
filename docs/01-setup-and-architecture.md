# Tahap 01: Setup Proyek & Arsitektur Dasar

## 1. Tujuan Tahap Ini
Membangun fondasi utama aplikasi CLI, mengatur manajemen *library*, dan membuat kerangka *request* HTTP yang *scalable* serta mendukung autentikasi (sesi/token) untuk pengujian yang mendalam. Tahap ini belum melibatkan logika pemindaian celah apa pun, murni arsitektur dasar.

## 2. Struktur Direktori Proyek
Buat struktur *folder* dan *file* berikut sebagai kerangka awal:
```text
omni-web-auditor/
├── main.py                 # Entry point aplikasi CLI
├── requirements.txt        # Daftar dependencies
└── src/
    ├── __init__.py
    ├── core/               # Konfigurasi inti dan wrapper
    │   ├── __init__.py
    │   ├── cli_parser.py   # Logika argparse
    │   └── session.py      # HTTP Session Wrapper
    ├── modules/            # (Akan diisi pada tahap selanjutnya)
    └── reports/            # (Akan diisi pada tahap selanjutnya)
```

## 3. Manajemen Library (requirements.txt)
Instruksi: Buat file requirements.txt dengan library dasar berikut:
- requests: Untuk menangani HTTP/HTTPS requests dan manajemen sesi.
- urllib3: Untuk mengelola konfigurasi koneksi level rendah (termasuk suppress peringatan SSL/TLS jika melakukan audit pada server internal).
(Catatan: Library untuk PDF generation dan scanning jaringan akan ditambahkan di tahap-tahap berikutnya).

## 4. Pengembangan Modul Inti
### A. Core HTTP Session Wrapper (src/core/session.py)
Buat class ScannerSession yang meng-enkapsulasi requests.Session().
Fungsi dan Ketentuan Class ini:
- Harus memiliki parameter inisialisasi untuk menangkap nilai cookie atau bearer_token dari CLI.
- Secara otomatis menyisipkan header User-Agent: Omni-Auditor/1.0 ke setiap request.
- Jika cookie diberikan, sisipkan ke dalam session.
- Jika bearer_token diberikan, tambahkan header Authorization: Bearer <token>.
- Sediakan method terpusat (misal get_request dan post_request) yang secara default membungkus fungsi requests.get/post dengan timeout global (misal 10 detik) dan penanganan error dasar (seperti requests.exceptions.RequestException) agar aplikasi tidak crash jika target down.

### B. CLI Command Parser (src/core/cli_parser.py)
Buat class atau fungsi menggunakan library bawaan argparse.
Argumen yang wajib didukung:
- `--target` (Wajib): URL atau IP address target (contoh: `https://kotabaruparahyangan.com` atau `192.168.1.100`).
- `--scan-type` (Wajib): Pilihan tipe scan. Gunakan `choices=['web', 'infra', 'full']`.
- `--cookie` (Opsional): String session cookie untuk audit terautentikasi.
- `--token` (Opsional): String Bearer token untuk audit API terautentikasi.
- `--output` (Opsional): Nama file laporan (default: `report_target.pdf`).

### C. Entry Point (main.py)
Buat logika utama yang menghubungkan parser dan session wrapper.
Alur Kerja `main.py`:
1. Eksekusi `cli_parser` untuk menangkap argumen pengguna.
2. Lakukan inisialisasi `ScannerSession` menggunakan argumen `--cookie` atau `--token` (jika ada).
3. Buat validasi sederhana: Jika URL tidak valid (misal tidak memiliki skema `http://` atau `https://` untuk target web), berikan peringatan di terminal.
4. Print ke terminal pesan sukses inisialisasi: `[+] Memulai sesi audit untuk target: <target> dan <target_scan_type>`.

## 5. Standar Kode
- Gunakan Type Hinting (misal: def get_request(self, url: str) -> requests.Response:) untuk kejelasan kode.
- Jangan menuliskan logika eksploitasi apa pun di tahap ini. Fokus pada kestabilan kelas Session agar siap dipakai oleh module lain.