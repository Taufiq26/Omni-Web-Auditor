# Tahap 02: Web Basic Security Scanner (Passive Scan)

## 1. Tujuan Tahap Ini
Membangun modul pemindaian lapisan pertama yang bersifat pasif (*non-intrusive*). Modul ini bertugas memeriksa konfigurasi dasar HTTP, keamanan enkripsi SSL/TLS, dan mendeteksi kebocoran informasi dari *file* sensitif yang mungkin tertinggal di server publik.

## 2. Struktur Modul
Buat *file* baru di `src/modules/basic_scan.py`. 
Modul ini harus menggunakan *class* `ScannerSession` yang telah dibuat pada Tahap 01 untuk melakukan semua *request* HTTP.

## 3. Fitur & Logika Pengembangan

### A. Analisis HTTP Security Headers
Buat *method* `check_security_headers(url: str)` di dalam *class* `BasicScanner`.
* **Logika:** Lakukan HTTP GET *request* ke URL target (contoh: `https://kotabaruparahyangan.com`). Ambil objek `response.headers`.
* **Pengecekan:** Periksa apakah *header* berikut ADA di dalam respons:
    * `Strict-Transport-Security`
    * `Content-Security-Policy`
    * `X-Frame-Options`
    * `X-Content-Type-Options`
* **Output Temuan:** Jika *header* hilang, catat sebagai kerentanan tingkat rendah (Low Severity).

### B. Validasi SSL / TLS
Buat *method* `check_ssl_cert(domain: str)`.
* **Logika:** Gunakan modul standar bawaan Python `ssl` dan `socket` untuk menarik informasi sertifikat dari *port* 443.
* **Pengecekan:** * Ekstrak tanggal kedaluwarsa sertifikat (`notAfter`). Jika sisa waktu kurang dari 14 hari, catat sebagai peringatan.
    * (Opsional) Pastikan versi protokol bukan SSLv3, TLS 1.0, atau TLS 1.1 yang sudah usang.

### C. Pendeteksian File Sensitif (Information Disclosure)
Buat *method* `check_exposed_files(base_url: str)`.
* **Logika:** Buat daftar *array* berisi *path* umum yang sering kali terekspos akibat kesalahan konfigurasi *deployment* atau *backup*. 
    * Contoh *path*: `/.env`, `/.git/config`, `/robots.txt`, `/server-status`, `/.DS_Store`, `/backup.zip`.
* **Eksekusi:** Lakukan *request* GET ke masing-masing *path* tersebut secara iteratif.
* **Validasi Keamanan:** Jangan memunculkan status rentan hanya berdasarkan HTTP 200 OK (karena beberapa server membelokkan *error* ke *custom* 200 OK page). AI harus mengecek *signature* isi *file*. 
    * *Contoh:* Jika mengecek `/.env`, pastikan teks respons mengandung kata `DB_PASSWORD` atau `APP_KEY`. Jika mengecek `/.git/config`, pastikan mengandung teks `[core]`.

## 4. Standar Output Data (PENTING untuk Tahap 5)
Agar pembuatan laporan PDF nantinya mudah, semua hasil temuan dari *method* di atas harus dikembalikan dalam format struktur data *dictionary* Python yang baku.

**Format Wajib:**
```python
{
    "vulnerability": "Nama Celah (misal: Missing X-Frame-Options)",
    "severity": "Low/Medium/High",
    "location": "URL atau Port spesifik",
    "evidence": "Bukti (misal: snippet response atau pesan error)",
    "remediation": "Langkah perbaikan teknis"
}
```

## 5. Integrasi
Pastikan modul ini bisa dipanggil dari `main.py` ketika user menjalankan perintah CLI dengan flag `--scan-type web` atau `--scan-type full`. Tangani potensi `requests.exceptions.SSLError` secara elegan tanpa menghentikan proses scan lainnya.