# Tahap 06: Finalisasi & Pembuatan Dokumentasi (README.md)

## 1. Tujuan Tahap Ini
Tahap ini adalah fase penutup dari pengembangan tool Omni-Web-Auditor. Tugasmu sebagai asisten AI adalah membaca, menganalisis seluruh struktur kode dan fungsionalitas yang telah kita bangun dari Tahap 01 hingga Tahap 05, lalu menghasilkan file `README.md` yang komprehensif, akurat, dan profesional.

## 2. Instruksi Analisis Kode
Sebelum menulis `README.md`, silakan pindai file-file berikut di dalam repositori:
* `main.py` (untuk melihat kerangka utama dan argumen CLI yang sebenarnya diimplementasikan).
* `requirements.txt` (untuk melihat daftar dependensi final).
* Folder `src/modules/` dan `src/reports/` (untuk memastikan fitur apa saja yang benar-benar berhasil dibangun dan berjalan).

## 3. Struktur README.md yang Wajib Dibuat
Buat file `README.md` di root direktori dengan struktur berikut:

### A. Header & Deskripsi
* Berikan judul proyek yang jelas (misal: 🛡️ Omni-Web-Auditor CLI).
* Tuliskan deskripsi singkat mengenai apa tool ini, siapa target penggunanya, dan pendekatan arsitekturnya (OOP, modular, dual-layer reporting).

### B. Disclaimer / Peringatan Etika (SANGAT PENTING)
* Buat bagian peringatan dengan teks tebal (*bold*). 
* Nyatakan secara eksplisit bahwa tool ini hanya untuk tujuan edukasi dan audit sistem yang sah dengan izin tertulis (Rules of Engagement). Penulis tidak bertanggung jawab atas penyalahgunaan tool ini.

### C. Daftar Fitur Utama
* Tuliskan poin-poin fitur (*bullet points*) berdasarkan modul yang benar-benar ada di dalam kode (misalnya: Passive Scan untuk Security Headers, Active Scan untuk XSS/SQLi, Infrastructure Scan untuk Port & Storage, dan PDF Report Generation).

### D. Panduan Instalasi
* Berikan *snippet* kode *bash* langkah demi langkah:
    1. Cara melakukan `git clone` (gunakan *placeholder* URL repositori).
    2. Cara membuat dan mengaktifkan *virtual environment* (`venv`).
    3. Cara menginstal dependensi melalui `pip install -r requirements.txt`.

### E. Cara Penggunaan (Usage & CLI Arguments)
* Dokumentasikan semua argumen CLI yang tersedia di `main.py` (seperti `--target`, `--scan-type`, `--cookie`, `--token`, `--output`) beserta penjelasannya.
* Berikan 3 contoh skenario perintah (*command*) yang bisa di-*copy-paste* oleh pengguna:
    1. Scan aplikasi web biasa secara pasif.
    2. Scan infrastruktur server.
    3. Scan dengan menggunakan autentikasi (cookie/token).

### F. Penjelasan Output Laporan
* Jelaskan secara singkat bahwa tool ini menghasilkan file PDF.
* Terangkan perbedaan antara halaman "Management Summary" dan halaman "Technical Details" agar pengguna tahu cara membaca laporannya.

## 4. Eksekusi
Silakan *generate* isi lengkap `README.md` sekarang berdasarkan status kode kita saat ini!