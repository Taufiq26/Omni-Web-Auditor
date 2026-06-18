# 🛡️ Omni-Web-Auditor CLI

Omni-Web-Auditor adalah sebuah *command-line tool* (CLI) otomatis berbasis Python yang dirancang untuk melakukan audit keamanan komprehensif pada lapisan aplikasi web (Layer 7) hingga infrastruktur server (Layer 3 & 4). Tool ini dibangun menggunakan arsitektur *Object-Oriented Programming* (OOP) yang modular, serta dilengkapi dengan fitur *dual-layer reporting* yang cocok untuk kebutuhan manajemen maupun tim teknis.

Target pengguna aplikasi ini meliputi DevOps Engineer, IT Freelancer, Cloud Architect, hingga System Administrator yang membutuhkan validasi keamanan (*sanity check*) secara cepat dan menyeluruh.

---

## ⚠️ Peringatan Etika & Disclaimer (SANGAT PENTING)

**Tool ini dikembangkan secara murni HANYA UNTUK TUJUAN EDUKASI dan AUDIT SISTEM YANG SAH di mana Anda memiliki izin tertulis secara eksplisit (Rules of Engagement) dari pemilik sistem. Penulis maupun kontributor TIDAK BERTANGGUNG JAWAB atas segala bentuk kerusakan, kerugian, atau penyalahgunaan tool ini untuk aktivitas ilegal.**

---

## ✨ Daftar Fitur Utama

Omni-Web-Auditor dilengkapi dengan berbagai modul keamanan cerdas:

*   **Passive Web Scan (Basic)**
    *   Analisis ketiadaan HTTP Security Headers (HSTS, CSP, X-Frame-Options, dsb).
    *   Pemeriksaan validitas, masa kedaluwarsa, dan versi protokol SSL/TLS.
    *   Pendeteksian kebocoran file sensitif (*Information Disclosure*) melalui *path* publik (seperti `/.env`, `/.git/config`, `/.DS_Store`, `/backup.zip`).
*   **Active Web Scan (Intermediate & Advanced)**
    *   Identifikasi *Outdated Components* (versi CMS WordPress/Joomla, pustaka JavaScript, dan *Header* PHP).
    *   Injeksi *payload proof-of-concept* untuk mendeteksi *SQL Injection* (*Error-Based*) dan *Reflected XSS*.
    *   Otomatisasi pengujian celah API logika bisnis (IDOR / BOLA) pada kondisi terautentikasi.
*   **Server & Infrastructure Scan**
    *   Pemindaian TCP *Port* untuk mendeteksi layanan *database* terekspos (MySQL, PostgreSQL, Redis, MongoDB).
    *   Audit celah miskonfigurasi keamanan di layanan *Cloud Storage* (AWS S3, MinIO) dan Google Drive URL.
    *   *Banner Grabbing* untuk mendeteksi penggunaan versi OpenSSH yang rentan.
*   **PDF Report Engine (Dual-Layer Reporting)**
    *   Pembuatan laporan PDF secara otomatis dengan desain yang profesional menggunakan pustaka `reportlab`.
    *   Menghasilkan *Health Score* berdasarkan temuan secara *real-time*.

---

## ⚙️ Panduan Instalasi

Ikuti langkah-langkah di bawah ini untuk menjalankan Omni-Web-Auditor di mesin Anda:

1.  **Clone Repositori**
    ```bash
    git clone https://github.com/Taufiq26/Omni-Web-Auditor.git
    cd Omni-Web-Auditor
    ```

2.  **Buat & Aktifkan Virtual Environment**
    ```bash
    python3 -m venv venv
    
    # Untuk MacOS / Linux:
    source venv/bin/activate
    
    # Untuk Windows:
    venv\Scripts\activate
    ```

3.  **Instal Dependensi**
    ```bash
    pip install -r requirements.txt
    ```

---

## 🚀 Cara Penggunaan (Usage & CLI Arguments)

Jalankan *entry point* `main.py` menggunakan Python. 

### Argumen CLI yang Tersedia

*   `--target` **(Wajib)**: URL atau IP address target. Contoh: `https://example.com` atau `192.168.1.10`.
*   `--scan-type` **(Wajib)**: Pilihan tipe modul pemindaian yang ingin dijalankan.
    *   `web`: Menjalankan *Basic* dan *Active Scan* pada target berbasis web.
    *   `infra`: Menjalankan pemindaian port dan *Cloud Storage* pada level server.
    *   `full`: Menjalankan seluruh modul pengujian dari awal hingga akhir.
*   `--cookie` *(Opsional)*: Menyisipkan string *session cookie* HTTP untuk melewati halaman *login* (pengujian terautentikasi).
*   `--token` *(Opsional)*: Menyisipkan *Bearer Token* otorisasi khusus untuk pengujian *endpoint* API (wajib untuk deteksi IDOR).
*   `--output` *(Opsional)*: Menentukan nama file keluaran laporan PDF. Jika tidak diisi, *tool* akan men-generate nama otomatis berdasarkan waktu (contoh: `audit_report_example.com_20260612_211658.pdf`).

### Contoh Skenario Penggunaan

**1. Scan Aplikasi Web Biasa (Pasif & Aktif)**
```bash
python main.py --target https://example.com --scan-type web
```

**2. Scan Infrastruktur Server Saja**
```bash
python main.py --target 192.168.1.100 --scan-type infra
```

**3. Scan Lengkap (Full Scan) Menggunakan Autentikasi API (JWT/Bearer)**
```bash
python main.py --target https://api.example.com --scan-type full --token "eyJhbGciOiJIUzI1NiIsInR5..."
```

**4. Scan Terautentikasi pada Framework Monolithic (Laravel/CodeIgniter)**
Gunakan argumen `--cookie` untuk memasukkan *Session Cookie* jika target menggunakan autentikasi berbasis sesi alih-alih API Token.
```bash
python main.py --target https://laravel-app.com --scan-type full --cookie "laravel_session=eyJpdiI6I..."
```

---

## 📄 Penjelasan Output Laporan (PDF)

Setiap proses audit yang selesai akan menghasilkan sebuah dokumen PDF. Dokumen ini terbagi menjadi 2 (dua) bagian berlapis (*Dual-Layer*):

1.  **Management Summary (Executive Level)**
    Halaman utama ini menampilkan indikator visual sederhana berupa "Nilai Kesehatan Target". AI di belakang *tool* menyusun *Business Impact Statement* yang mudah dipahami eksekutif (misalnya "Potensi Kebocoran Data") tanpa perlu mengerti bahasa pemograman. Terdapat tabel ringkasan total temuan celah *High*, *Medium*, dan *Low*.
2.  **Technical Remediation Details (Developer Level)**
    Halaman berikutnya merinci setiap celah secara presisi (dilengkapi *Location URL*, bukti respon HTTP pada *Evidence*, serta panduan *Remediation* langkah demi langkah) agar dapat segera di-*patch* oleh para *Developer* atau tim IT internal.
