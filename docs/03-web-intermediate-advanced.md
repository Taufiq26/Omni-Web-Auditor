# Tahap 03: Web Intermediate & Advanced Scanner (Active Scan)

## 1. Tujuan Tahap Ini
Membangun modul pemindaian aktif yang berinteraksi langsung dengan logika aplikasi. Modul ini akan mengirimkan *payload* jinak untuk menguji validasi *input* (seperti XSS dan SQLi dasar), mendeteksi komponen CMS yang usang, dan menguji celah logika pada level API (seperti BOLA/IDOR) menggunakan sesi yang terautentikasi.

## 2. Struktur Modul
Buat *file* baru di `src/modules/active_scan.py`. 
Modul ini juga wajib menggunakan *class* `ScannerSession` dari `src/core/session.py` untuk menjaga konsistensi *header* dan autentikasi.

## 3. Fitur & Logika Pengembangan

### A. Pendeteksi Komponen Usang (Outdated Components)
Buat *method* `detect_components(url: str)`.
* **Logika:** Lakukan GET *request* ke halaman utama atau *landing page*. Analisis DOM HTML menggunakan `BeautifulSoup4`.
* **Pengecekan:**
    * Cari *tag* `<meta name="generator" content="...">` untuk melihat versi CMS (misal: WordPress, Joomla).
    * Cari *header* respons seperti `X-Powered-By` (misal: PHP/7.4.3, Express).
    * Identifikasi pustaka JavaScript dari tag `<script>` (misal: versi jQuery atau React).
* **Output Temuan:** Jika versi yang terdeteksi diketahui sudah usang (*outdated*), catat sebagai kerentanan tingkat menengah (Medium Severity).

### B. Pengujian Validasi Input Dasar (XSS & SQLi)
Buat *method* `test_input_validation(url_with_param: str)`.
* **Aturan Ketat:** Hanya gunakan *payload* uji coba (*proof of concept*), JANGAN gunakan *payload* yang merusak *database* atau mengeksekusi skrip berbahaya.
* **Logika SQLi (Error-Based):** * Sisipkan karakter kutip tunggal `'` atau `%27` pada nilai parameter URL (contoh: `?id=1'`).
    * Periksa respons HTML. Jika memunculkan pesan *error* spesifik (seperti "SQL syntax", "mysql_fetch_array", atau "ORA-"), indikasi kuat aplikasi rentan terhadap SQL Injection. Catat sebagai High Severity.
* **Logika XSS (Reflected):**
    * Sisipkan *string* acak namun spesifik, misalnya `<testxss>123</testxss>`.
    * Periksa respons HTML. Jika *string* tersebut dipantulkan kembali (*reflected*) secara utuh tanpa di-HTML-encode (seperti `&lt;testxss&gt;`), maka parameter tersebut rentan terhadap Cross-Site Scripting. Catat sebagai Medium/High Severity.

### C. Pengujian Logika API (BOLA / IDOR)
Buat *method* `check_api_idor(api_endpoint: str)`.
* **Kondisi:** Fitur ini hanya dijalankan jika pengguna memberikan argumen `--token` atau `--cookie` di CLI.
* **Logika:** Analisis URL *endpoint* API. Jika terdapat format angka ID (contoh: `/api/users/100`), minta *tool* untuk secara otomatis mencoba mengakses ID lain (misal: `/api/users/101` atau `/api/users/0`) menggunakan sesi yang sama.
* **Pengecekan:** Jika status respons mengembalikan `200 OK` dan struktur JSON menampilkan data entitas lain, ini adalah celah *Broken Object Level Authorization* (BOLA). Catat sebagai High Severity.

## 4. Mekanisme Keamanan (Rate-Limiting)
Karena modul ini melakukan modifikasi *request* dan berpotensi mengirim banyak *traffic* ke server klien, wajib tambahkan:
* Fungsi jeda bawaan menggunakan `time.sleep(1)` atau `time.sleep(2)` di antara setiap *request* manipulasi *input*.
* Ini bertujuan untuk mencegah aplikasi web target terkena *Denial of Service* (DoS) atau memicu pemblokiran otomatis dari Web Application Firewall (WAF).

## 5. Standar Output Data
Tetap gunakan format *dictionary* yang sama dengan Tahap 02 agar pengolahan PDF di Tahap 05 berjalan mulus:
```python
{
    "vulnerability": "Nama Celah (misal: Reflected XSS pada parameter 'search')",
    "severity": "Low/Medium/High",
    "location": "URL lengkap target yang bermasalah",
    "evidence": "Bukti (misal: snippet HTML yang memantulkan payload)",
    "remediation": "Langkah perbaikan (misal: Terapkan input sanitization atau gunakan prepared statements untuk SQL)"
}
```

## 6. Integrasi
Impor method-method di atas ke dalam `main.py` dan kondisikan agar hanya berjalan jika pengguna memilih `--scan-type web` atau `--scan-type full`. Pastikan tool dapat mengenali apakah target memiliki parameter URL sebelum menjalankan fungsi `test_input_validation`.