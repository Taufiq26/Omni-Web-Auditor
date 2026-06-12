# Tahap 04: Server & Infrastructure Auditor

## 1. Tujuan Tahap Ini
Memperluas jangkauan audit dari lapisan aplikasi (Layer 7) menuju lapisan infrastruktur (Layer 3 & 4). Modul ini bertugas mendeteksi layanan server yang terekspos secara tidak aman, memeriksa versi protokol akses jarak jauh, dan mengaudit kesalahan konfigurasi privasi pada layanan penyimpanan awan (*cloud storage*) yang sering digunakan untuk *backup* data operasional.

## 2. Struktur Modul
Buat *file* baru di `src/modules/infra_scan.py`.
Karena pemindaian ini sering kali tidak menggunakan protokol HTTP standar (kecuali untuk pengecekan *cloud storage*), modul ini akan mengkombinasikan penggunaan `requests` dan pustaka bawaan Python `socket`.

## 3. Fitur & Logika Pengembangan

### A. Port & Service Enumerator (Pemindai Jaringan)
Buat *method* `scan_open_ports(ip_or_domain: str)`.
* **Logika:** Gunakan *library* `socket` bawaan Python. Definisikan daftar *port* krusial yang seharusnya tidak terbuka bebas ke internet publik (misal: 22 untuk SSH, 21 untuk FTP, 3306 untuk MySQL, 5432 untuk PostgreSQL, 6379 untuk Redis).
* **Eksekusi:** Lakukan iterasi koneksi TCP ke *port-port* tersebut dengan *timeout* singkat (maksimal 1-2 detik per *port* agar proses tidak terlalu lama).
* **Output Temuan:** Jika *port database* (seperti 3306) terdeteksi berstatus `OPEN`, catat sebagai kerentanan High/Critical Severity, karena *database* seharusnya hanya dapat diakses melalui jaringan internal atau VPN.

### B. Cloud Storage & Backup Misconfiguration Checker
Buat *method* `check_storage_privacy(target_domain: str)`.
* **Konteks:** Sering kali infrastruktur modern menyimpan *file* statis atau melakukan rotasi *backup* aset harian menggunakan layanan *object storage* pihak ketiga atau *self-hosted*.
* **Logika:** Lakukan HTTP GET *request* (tanpa token autentikasi) ke pola URL penyimpanan yang umum.
    * Uji *endpoint* AWS S3 (*pattern*: `https://[bucket-name].s3.amazonaws.com`).
    * Uji keberadaan *endpoint* MinIO yang sering berjalan di *port* spesifik (misal: `http://target:9000` atau *subdomain* `storage.target.com`).
    * Uji pola URL berbagi publik dari layanan seperti Google Drive jika terdeteksi di dalam respons HTML target.
* **Pengecekan:** Jika *request* ke *bucket* penyimpanan tersebut mengembalikan status HTTP `200 OK` dan menampilkan struktur direktori (XML list) atau mengizinkan pengunduhan *file backup*, catat sebagai High Severity (Data Leakage). Status yang aman seharusnya adalah `403 Forbidden` atau `401 Unauthorized`.

### C. SSH Banner Grabbing (Audit Akses Server)
Buat *method* `audit_ssh_service(ip_target: str)`.
* **Logika:** Buka koneksi TCP ke *port* 22. Tangkap *string* teks (banner) pertama yang dikirimkan oleh server sebelum proses *login* dimulai.
* **Pengecekan:** Ekstrak informasi dari *banner* tersebut (misal: `SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10`). Cocokkan versinya. Jika terdeteksi menggunakan versi OpenSSH yang sudah sangat usang (misal versi di bawah 7.x), catat sebagai Medium Severity.

## 4. Mekanisme Kestabilan (Error Handling)
* Gunakan blok `try...except socket.error` dan `socket.timeout` yang solid. Operasi jaringan sangat rentan terhadap *timeout* asinkron. Jika satu *port* memblokir koneksi, sistem harus langsung melanjutkan ke *port* berikutnya tanpa membuat aplikasi utama *crash*.

## 5. Standar Output Data
Hasil temuan harus tetap konsisten menggunakan struktur *dictionary* yang disepakati untuk *Report Generator* di Tahap 05:
```python
{
    "vulnerability": "Nama Celah (misal: Exposed MySQL Database Port)",
    "severity": "High",
    "location": "Target IP pada Port 3306",
    "evidence": "Koneksi TCP berhasil dibangun (Port berstatus OPEN)",
    "remediation": "Batasi akses port 3306 menggunakan firewall (iptables/UFW) hanya untuk IP lokal/internal server."
}
```

## 6. Integrasi
Impor class dari `infra_scan.py` ke dalam `main.py`. Tambahkan logika argumen agar pemindaian jaringan ini hanya dieksekusi jika user memilih flag `--scan-type infra` atau `--scan-type full`. Pastikan tool dapat mengkonversi input domain (misal: `target.com`) menjadi IP Address (`socket.gethostbyname`) sebelum melakukan `scan_open_ports`.