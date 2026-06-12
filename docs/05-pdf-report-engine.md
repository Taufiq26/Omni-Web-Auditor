# Tahap 05: PDF Report Engine (Dual-Layer Reporting)

## 1. Tujuan Tahap Ini
Membangun mesin pembuat laporan otomatis yang mengkonsumsi struktur data *dictionary* dari semua modul *scanner* sebelumnya. Laporan PDF ini harus memisahkan informasi menjadi dua bagian utama: ringkasan eksekutif berorientasi bisnis untuk manajemen, dan panduan remediasi detail untuk tim teknis.

## 2. Struktur Modul & Library
* Buat *file* baru di `src/reports/pdf_gen.py`.
* **Library:** Gunakan `reportlab` (sangat direkomendasikan karena *powerful* untuk menangani *layout* tabel dan paragraf panjang secara dinamis) atau `fpdf2` (lebih sederhana namun *styling*-nya manual). Tambahkan ke `requirements.txt`.

## 3. Arsitektur Class ReportGenerator

Buat *class* `PDFReportGenerator`. *Class* ini harus menerima *list of dictionaries* yang berisi semua temuan celah dari tahap 02, 03, dan 04.

### A. Fungsi Pra-Pemrosesan (Data Calculation)
Buat *method* internal untuk menghitung statistik celah.
* **Logika:** Lakukan iterasi pada data temuan, lalu hitung total celah berdasarkan tingkat keparahan (*severity*).
* **Output:** Variabel statistik seperti `total_high`, `total_medium`, dan `total_low`. Ini akan menentukan "Nilai Kesehatan" (Health Score) keseluruhan target.

### B. Halaman 1: Management Summary (Executive Level)
Buat *method* `_build_executive_summary()`.
* **Fokus:** Visualisasi risiko bisnis, BUKAN kode atau *port*.
* **Komponen yang harus ada di halaman ini:**
    * **Header Laporan:** Nama *tool* (Omni-Web-Auditor), Tanggal Audit, dan Target URL/IP (misal: `Target: https://kotabaruparahyangan.com`).
    * **Indikator Skor Visual:** Tampilkan teks tebal dengan warna yang mewakili tingkat bahaya tertinggi. (Jika ada 1 saja *High*, maka status = MERAH/CRITICAL).
    * **Tabel Ringkasan Temuan:** Tabel kecil berisi jumlah temuan High, Medium, dan Low.
    * **Business Impact Statement:** Logika AI harus memetakan kategori *severity* ke dalam narasi bisnis. Contoh: *"Ditemukan kerentanan tingkat Tinggi. Jika dieksploitasi, hal ini dapat menyebabkan gangguan layanan aplikasi dan potensi kebocoran data klien. Disarankan untuk segera mengalokasikan sumber daya teknis untuk perbaikan."*

### C. Halaman 2+: Technical Details (Developer Level)
Buat *method* `_build_technical_details()`.
* **Fokus:** Akurasi data untuk memudahkan proses *patching*.
* **Komponen yang harus ada:**
    * Lakukan *looping* untuk setiap temuan di dalam *list dictionary*.
    * Buat tabel detail untuk **setiap** celah keamanan.
    * **Format Tabel:**
        * **Vulnerability:** (Nama celah, dicetak tebal dengan warna teks sesuai *severity*)
        * **Location:** (Endpoint URL atau nomor *port* yang rentan)
        * **Evidence:** (Potongan *response header*, pesan *error*, atau status *port*)
        * **Remediation:** (Langkah perbaikan, misalnya "Ubah izin bucket menjadi private" atau "Tambahkan header CSP")

## 4. Mekanisme Ekspor & Integrasi

* Buat *method* utama `generate_report(filename: str)` yang memanggil *method* eksekutif dan teknis secara berurutan, lalu menyimpan *file*-nya.
* **Integrasi `main.py`:** Setelah `ScannerSession` dan semua modul *scan* selesai dijalankan, kumpulkan semua hasil (*list.extend*) ke dalam satu *array* besar bernama `all_vulnerabilities`.
* Panggil `PDFReportGenerator(all_vulnerabilities)` dan eksekusi `generate_report()`. Jika *user* tidak memberikan argumen `--output` di CLI, buat nama *file* *default* secara otomatis berbasis waktu dan target (misalnya: `audit_report_kotabaruparahyangan_20260612.pdf`).