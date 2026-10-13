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
    *   Injeksi *payload proof-of-concept* untuk mendeteksi *SQL Injection* (*Error-Based*) dan *Reflected XSS* — baik pada **query parameter URL** maupun pada **body/parameter JSON** endpoint API (via `--endpoints-file`).
    *   Otomatisasi pengujian celah API logika bisnis (IDOR / BOLA):
        *   **ID numerik berurutan** (ID+1) dengan *request kontrol* untuk menekan *false-positive*.
        *   **Dua-akun (UUID-based)** — akun uji A vs akun uji B — untuk sistem yang memakai UUID (tidak bisa diuji dengan ID+1).
*   **Server & Infrastructure Scan**
    *   Pemindaian TCP *Port* untuk mendeteksi layanan *database* terekspos (MySQL, PostgreSQL, Redis, MongoDB).
    *   Audit celah miskonfigurasi keamanan di layanan *Cloud Storage* (AWS S3, MinIO) dan Google Drive URL.
    *   *Banner Grabbing* untuk mendeteksi penggunaan versi OpenSSH yang rentan.
    *   **Proteksi CDN/WAF:** mendeteksi target di balik Cloudflare secara otomatis dan **menolak memindai IP pihak ketiga**; pindai server asal hanya bila IP origin diberikan manual via `--origin-ip`.
*   **PDF Report Engine (Dual-Layer + Evidence)**
    *   Pembuatan laporan PDF secara otomatis dengan desain yang profesional menggunakan pustaka `reportlab`.
    *   Menghasilkan *Health Score* berdasarkan temuan secara *real-time*.
    *   **Scan Coverage & Evidence:** bagian khusus yang mencatat setiap pengujian — dijalankan / dilewati / tidak berlaku — lengkap dengan hasil (✔ Aman / ⚠ Ada temuan / Belum teruji) dan alasan singkat mengapa suatu aspek dianggap aman. Laporan tetap informatif & bisa menjadi bukti meski **tidak ada** kerentanan.
    *   **Status jujur:** bila tidak ada temuan **tetapi** ada pengujian yang dilewati, status laporan menjadi `INCONCLUSIVE` (bukan `SECURE`) — mencegah *false sense of security*.

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
*   `--token` *(Opsional)*: Menyisipkan *Bearer Token* otorisasi khusus untuk pengujian *endpoint* API (wajib untuk deteksi IDOR ID+1).
*   `--output` *(Opsional)*: Menentukan nama file keluaran laporan PDF. Jika tidak diisi, *tool* akan men-generate nama otomatis berdasarkan waktu (contoh: `audit_report_example.com_20260612_211658.pdf`).
*   `--endpoints-file` *(Opsional)*: Path file JSON berisi daftar *endpoint* uji yang **disiapkan manual** dari dokumentasi API resmi target (bukan hasil *crawling*). Dipakai untuk uji SQLi/XSS berbasis **body JSON** dan uji IDOR **dua-akun**. Lihat contoh di `examples/endpoints.example.json`.
*   `--origin-ip` *(Opsional)*: IP server asal untuk target di balik CDN/WAF (mis. Cloudflare). **Isi HANYA jika Anda memiliki izin/akses langsung ke server tersebut** — *tool* tidak pernah menebak IP origin.
*   `--token-a` / `--token-b` *(Opsional)*: *Bearer Token* dua **akun uji milik Anda sendiri** (A = pemilik objek, B = penyerang) untuk uji IDOR/BOLA dua-akun pada sistem berbasis UUID.
*   `--cookie-a` / `--cookie-b` *(Opsional)*: Alternatif berbasis *session cookie* untuk uji IDOR dua-akun.

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

**5. Uji SQLi/XSS pada Body JSON API (Endpoint dari Dokumentasi Resmi)**
Siapkan `endpoints.json` (lihat `examples/endpoints.example.json`), tandai titik injeksi dengan `{{INJECT}}`:
```bash
python main.py --target https://api.example.com --scan-type web \
  --endpoints-file endpoints.json --token "eyJhbGciOiJIUzI1Ni..."
```

**6. Uji IDOR / BOLA Dua-Akun untuk Sistem Berbasis UUID**
Isi `idor_object_urls` di *endpoints-file* dengan URL objek milik **akun uji A**, lalu berikan token kedua akun uji Anda:
```bash
python main.py --target https://api.example.com --scan-type web \
  --endpoints-file endpoints.json \
  --token-a "TOKEN_AKUN_A" --token-b "TOKEN_AKUN_B"
```
> ⚠️ Kedua akun **wajib milik Anda sendiri** (akun uji), bukan akun pengguna nyata di *production*.

**7. Scan Infrastruktur untuk Target di Balik Cloudflare/CDN**
Secara *default*, port scan akan **dilewati otomatis** jika target di balik CDN. Berikan `--origin-ip` hanya bila Anda punya izin langsung ke server asal:
```bash
python main.py --target https://target.com --scan-type infra --origin-ip 203.0.113.10
```

### Format `--endpoints-file` (JSON)
```json
{
  "injection_tests": [
    { "method": "POST", "url": "https://api.example.com/api/auth/login",
      "body": { "email": "{{INJECT}}", "password": "dummy" } },
    { "method": "GET", "url": "https://api.example.com/api/search",
      "query": { "q": "{{INJECT}}" } }
  ],
  "idor_object_urls": [
    "https://api.example.com/api/passes/<UUID-objek-milik-akun-A>"
  ]
}
```
*   `injection_tests`: field apa pun bernilai `"{{INJECT}}"` menjadi titik injeksi SQLi/XSS.
*   `idor_object_urls`: URL objek milik akun uji A (disiapkan manual) untuk uji IDOR dua-akun.

---

## 📄 Penjelasan Output Laporan (PDF)

Setiap proses audit yang selesai akan menghasilkan sebuah dokumen PDF. Dokumen ini terbagi menjadi 3 (tiga) bagian:

1.  **Management Summary (Executive Level)**
    Halaman utama ini menampilkan indikator visual sederhana berupa "Nilai Kesehatan Target" (`SECURE` / `NOTICE` / `WARNING` / `CRITICAL` / `INCONCLUSIVE`) beserta *Business Impact Statement* yang mudah dipahami eksekutif. Terdapat tabel ringkasan total temuan celah *High*, *Medium*, dan *Low*.
    > Status `INCONCLUSIVE` muncul bila tidak ada temuan **tetapi** ada pengujian yang dilewati — artinya target **belum tentu aman**, sebagian cakupan belum teruji.
2.  **Scan Coverage & Evidence**
    Bagian ini adalah **bukti audit**: daftar seluruh pengujian beserta **hasilnya** (✔ Aman / ⚠ Ada temuan / Belum teruji / Tidak berlaku) dan **alasan singkat** kenapa suatu aspek dianggap aman. Dengan begini, meski hasil akhirnya "tidak ada kerentanan", laporan tetap menunjukkan apa saja yang diuji dan mengapa dinyatakan aman — bukan halaman kosong.
3.  **Technical Remediation Details (Developer Level)**
    Bagian ini merinci setiap celah secara presisi (dilengkapi *Location URL*, bukti respon HTTP pada *Evidence*, serta panduan *Remediation* langkah demi langkah) agar dapat segera di-*patch* oleh para *Developer* atau tim IT internal.
