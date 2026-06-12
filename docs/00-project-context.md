# Master Context: Proyek Pembuatan Security Auditor CLI

## 1. Nama & Visi Proyek
* **Nama Tool:** Omni-Web-Auditor
* **Visi:** Membangun *command-line tool* (CLI) otomatis berbasis Python untuk melakukan audit keamanan komprehensif pada infrastruktur web dan server. Tool ini dirancang agar ringan, modular, dan menghasilkan laporan ganda yang mudah dipahami oleh pihak manajemen maupun tim teknis.

## 2. Target Penggunaan & Skenario Bisnis
* **Pengguna Utama:** DevOps Engineer, IT Freelancer, Cloud Architect, dan System Administrator.
* **Skenario Pengujian:** Digunakan untuk melakukan *sanity check* dan audit keamanan berkala pada *environment* produksi klien yang beragam. Ruang lingkup target meliputi:
    * **Aplikasi Web Umum & Kustom:** Sistem Informasi internal/publik, portal layanan, dan aplikasi web berbasis API.
    * **Aplikasi Berbasis Platform:** Sistem CMS, e-commerce, atau Landing Page.
    * **Infrastruktur & Arsitektur Cloud:** Server host, endpoint API, dan sistem backup atau object storage (seperti AWS S3 atau MinIO) yang terkait dengan aplikasi target.

## 3. Aturan Main & Batasan Sistem (Rules of Engagement)
* **Sifat Pengujian:** Mayoritas adalah *Passive Scanning* dan *Non-Destructive Active Scanning*. AI harus merancang alat ini agar dapat menangani aplikasi dinamis maupun statis.
* **Batasan Mutlak:**
    * TIDAK BOLEH ada payload yang merusak integritas database (seperti injeksi modifikasi/penghapusan data) pada Sistem Informasi yang sedang berjalan.
    * TIDAK BOLEH memicu Denial of Service (DoS) yang membebani memori atau CPU server klien.
    * Harus memiliki mekanisme timeout dan penanganan error jaringan yang elegan agar tool tetap berjalan stabil di berbagai kondisi server target (misalnya jika target down atau memblokir IP).
* **Dukungan Autentikasi:** Tool harus dirancang untuk menerima kredensial sesi (seperti *session cookie* atau *bearer token* melalui argumen CLI) agar dapat melakukan audit pada endpoint di balik halaman login.

## 4. Arsitektur Hasil Laporan (The Output)
* Aplikasi wajib menghasilkan output akhir berupa dokumen PDF.
* **Bagian 1: Management Summary.** Ringkasan tingkat eksekutif, mencakup skor keamanan visual (warna Hijau/Kuning/Merah), jumlah celah yang ditemukan, dan penjelasan non-teknis tentang risiko bisnis operasional (misalnya dampak terhadap reputasi atau kebocoran data pengguna).
* **Bagian 2: Technical Remediation.** Detail teknis untuk tim pengembang/engineer. Wajib mencantumkan kategori kerentanan, lokasi pasti (URL/Port/Parameter API yang bermasalah), bukti temuan (*response snippet*), dan langkah spesifik untuk remediasi keamanan atau perbaikan konfigurasi.

## 5. Standar Penulisan Kode untuk AI
* Gunakan bahasa pemrograman Python.
* Terapkan pendekatan *Object-Oriented Programming* (OOP) murni yang *scalable*. Setiap jenis scanner (Web, API, Infrastruktur) harus dipisahkan ke dalam class atau modul tersendiri.
* Wajib menyertakan *docstrings* di setiap method dan komentar yang jelas pada baris kode yang memiliki logika kompleks.
* Gunakan pustaka standar bawaan Python sebisa mungkin untuk menekan jumlah *dependencies*. Pustaka eksternal hanya diperbolehkan untuk kebutuhan esensial seperti interaksi HTTP (`requests`) dan pembuatan laporan PDF (`reportlab` atau `fpdf2`).
* Pastikan standar struktur data (seperti format JSON/Dictionary internal) konsisten antar modul sebelum dikirim ke *Report Generator*.