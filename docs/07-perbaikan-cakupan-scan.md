# Perbaikan Cakupan Scan — Supaya Benar-Benar Menyeluruh (dalam Batas Kode Etik Pentester)

> **Latar belakang:** full scan ke `http://kbp-discover-pass-api.baradeveloper.com` (domain
> root, tanpa path/parameter) menghasilkan "0 kerentanan / SECURE". Setelah ditelusuri ke
> kode (`src/modules/active_scan.py`, `src/modules/infra_scan.py`), hasil itu sebagian besar
> berasal dari pengujian yang **tidak benar-benar berjalan**, bukan dari target yang memang
> aman. Dokumen ini berisi 3 celah konkret yang ditemukan + cara memperbaikinya, dan prinsip
> kode etik yang harus tetap dipegang saat memperbaikinya.

---

## Prinsip yang tidak boleh dilanggar saat memperbaiki tool ini

Sebelum ke detail teknis — ini batasan yang harus tetap berlaku di semua perbaikan di bawah:

1. **Hanya uji target yang sudah diberi izin eksplisit.** Tool ini tidak boleh menambah fitur yang mempermudah scan ke target tanpa otorisasi (mis. auto-discover subdomain pihak ketiga lalu langsung menyerang).
2. **Tidak ada payload destruktif.** Uji SQLi/XSS boleh diperluas, tapi tetap deteksi berbasis **bukti non-destruktif** (pesan error, reflection, perbedaan response time/behavior) — jangan pernah payload yang bisa mengubah/menghapus data (`DROP TABLE`, `UPDATE ... SET`, dsb).
3. **Tidak ada brute-force tanpa batas.** Semua pengujian aktif baru (IDOR, fuzzing path, dsb.) wajib tetap pakai `time.sleep()` / rate limit seperti pola yang sudah ada di `active_scan.py`, supaya tidak berubah jadi DoS ke target.
4. **IDOR hanya diuji dengan akun milik penguji sendiri.** Uji IDOR yang sah adalah: akun A mencoba akses objek milik akun B **yang juga milik/dikuasai penguji** (dua akun uji, bukan akun pengguna asli di production). Jangan pernah mengakses data pengguna nyata yang bukan milik penguji.
5. **Scan infrastruktur hanya ke IP yang sudah dikonfirmasi milik target**, bukan hasil resolve DNS mentah tanpa verifikasi (lihat Masalah #3 — ini justru sebabnya perlu diperbaiki, supaya tidak keliru menyasar pihak ketiga seperti Cloudflare).
6. **Setiap scan tetap dicatat** (target, waktu, mode) di laporan PDF yang sudah ada — jangan dihapus, supaya ada jejak audit kalau suatu saat dipertanyakan.

---

## Masalah #1 — Modul SQLi/XSS hanya menguji query parameter URL

**Lokasi:** `src/modules/active_scan.py`, fungsi `test_input_validation()` dan `run_scan()`.

**Kondisi sekarang:**
```python
parsed = urlparse(target)
if parsed.query:
    ...jalankan test_input_validation...
else:
    print("Melewati pengujian validasi input (tidak ada parameter URL pada target).")
```
Kalau target tidak punya `?param=value` di URL-nya, pengujian **dilewati total**. Banyak API modern (termasuk NestJS/REST khas) menerima input lewat **JSON body** (`POST`/`PUT`), bukan query string — tool ini sama sekali tidak menyentuhnya.

**Perbaikan yang disarankan:**
1. Tambah parameter CLI baru, mis. `--endpoints-file endpoints.json`, berisi daftar endpoint + method + contoh body yang **sudah disiapkan penguji sendiri** (bukan di-crawl otomatis dari target):
   ```json
   [
     { "method": "POST", "url": "https://.../api/admin/login", "body": {"email": "{{INJECT}}", "password": "x"} },
     { "method": "GET",  "url": "https://.../api/admin/finance/dashboard", "query": {"sales_point_id": "{{INJECT}}"} }
   ]
   ```
2. Tulis fungsi baru `test_input_validation_body()` yang meniru pola `test_input_validation()` yang sudah ada (payload `'` untuk SQLi error-based, `<testxss>123</testxss>` untuk reflected XSS), tapi menyuntikkan ke **field body JSON** yang ditandai `{{INJECT}}`, bukan hanya query string. Tetap pertahankan `time.sleep(1)` antar request dan tetap deteksi berbasis **pesan error** (`sql syntax`, `mysql_fetch_array`, dst.) — jangan payload yang mengubah data.
3. Endpoint yang diuji **wajib berasal dari daftar yang disiapkan manual oleh penguji** (dari dokumentasi API resmi target, seperti `api-contract.md` proyek ini), **bukan hasil crawling otomatis** — ini yang menjaga tool tetap di jalur kode etik (tidak menyerang endpoint yang di luar scope izin).

---

## Masalah #2 — Modul IDOR/BOLA hanya mendeteksi ID numerik berurutan

**Lokasi:** `src/modules/active_scan.py`, fungsi `check_api_idor()`.

**Kondisi sekarang:**
```python
for i, part in enumerate(path_parts):
    if part.isdigit():
        numeric_id_index = i
        ...
```
Modul ini **hanya aktif kalau ada segmen path berupa angka murni** (`/orders/42` → coba `/orders/43`). Banyak sistem modern (termasuk proyek Discover Pass yang baru diuji — 30 dari 30 entity-nya pakai UUID) **tidak pernah punya ID numerik berurutan**. Untuk sistem seperti itu, kondisi `part.isdigit()` **tidak akan pernah `True`**, sehingga "0 temuan IDOR" tidak mencerminkan apa pun — tes-nya memang tidak pernah berjalan.

**Perbaikan yang disarankan (2 jenis IDOR, keduanya tetap non-destruktif):**

1. **Deteksi pola ID yang lebih luas** — tambahkan pendeteksian UUID v4 di path (regex
   `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`), bukan hanya `isdigit()`.
   **Catatan penting:** untuk UUID, strategi "ID+1" di kode numerik **tidak berlaku** (UUID
   tidak berurutan/predictable by design — itu justru kontrol keamanan yang baik, bukan
   celah). Jadi deteksi UUID saja tidak cukup untuk menguji IDOR secara bermakna.

2. **Uji IDOR dua-akun (yang sebenarnya dibutuhkan untuk sistem berbasis UUID)** — ini
   perubahan desain, bukan sekadar regex:
   - Tool menerima **dua kredensial/token uji** lewat CLI baru, mis. `--token-a` dan `--token-b`
     (atau `--cookie-a`/`--cookie-b`), **keduanya akun uji milik penguji sendiri** — satu
     berperan "pemilik objek", satu berperan "penyerang".
   - Alur: pakai `token-a` untuk membuat/mengambil ID objek milik akun A (mis. ambil UUID pass
     milik akun A dari endpoint "list milik saya sendiri" yang memang tersedia untuk pengguna
     biasa). Lalu **ulangi request yang sama persis, tapi pakai `token-b`**, ke URL yang
     mengandung UUID milik A tadi.
   - Kalau `token-b` berhasil mengakses/mengubah objek milik A (HTTP 200 dengan data A, atau
     berhasil melakukan aksi), itu baru temuan IDOR/BOLA yang valid.
   - Ini **jauh lebih kuat** daripada menebak ID+1, dan tetap etis karena hanya memakai dua
     akun uji yang memang disiapkan/dikuasai penguji — tidak pernah menyentuh akun pengguna
     nyata.

3. Kalau tidak ada waktu membangun alur dua-akun, minimal **ubah pesan log-nya** supaya jujur:
   ```python
   else:
       print("[*] Dilewati: tidak ditemukan ID numerik berurutan di path "
             "(sistem UUID-based tidak dapat diuji dengan metode ID+1 — "
             "perlu uji dua-akun manual, lihat docs/07-perbaikan-cakupan-scan.md).")
   ```
   Supaya laporan PDF tidak menyiratkan "aman dari IDOR" padahal sebenarnya "belum teruji".

---

## Masalah #3 — Port scan & SSH banner menyasar IP hasil resolve DNS mentah (bisa salah sasaran ke CDN/WAF pihak ketiga)

**Lokasi:** `src/modules/infra_scan.py`, fungsi `run_scan()` (pemanggil `scan_open_ports`).

**Kondisi sekarang:** tool me-resolve hostname target ke IP lewat `socket.gethostbyname()`
lalu langsung memindai IP itu. Untuk domain yang **di belakang Cloudflare/CDN** (seperti
`kbp-discover-pass-api.baradeveloper.com`), IP yang didapat adalah **milik Cloudflare**, bukan
server asli. Tool lalu melaporkan port scan/SSH banner grab terhadap infrastruktur **pihak
ketiga** yang tidak diberi izin eksplisit untuk diuji oleh klien — ini bukan cuma soal hasil
yang tidak akurat, tapi **berisiko melanggar kode etik** kalau terus dipindai tanpa sadar (scan
port ke infrastruktur pihak ketiga di luar scope izin, meski tidak disengaja).

**Perbaikan yang disarankan:**
1. **Deteksi otomatis apakah IP hasil resolve adalah milik CDN/WAF yang diketahui** (Cloudflare,
   dll. — bisa pakai daftar range IP publik Cloudflare, atau cek header respons seperti
   `server: cloudflare` / `cf-ray`). Kalau terdeteksi:
   ```
   [!] IP yang ter-resolve (172.67.208.13) terdeteksi milik Cloudflare, bukan server asal.
       Port scan & SSH banner grab TIDAK dijalankan ke IP ini -- itu infrastruktur pihak
       ketiga di luar izin pengujian.
       Untuk menguji infrastruktur asli, berikan IP origin secara eksplisit lewat
       --origin-ip (HANYA jika kamu sudah punya izin/akses langsung ke server tsb,
       misal lewat SSH sendiri).
   ```
2. Tambahkan flag CLI baru `--origin-ip <IP>` khusus untuk kasus ini — **wajib diisi manual
   oleh penguji** yang sudah tahu IP origin sebenarnya (bukan di-guess/di-bruteforce oleh
   tool), supaya tool tidak pernah menebak-nebak IP origin di balik CDN (itu teknik bypass
   WAF yang sensitif secara etika kalau dilakukan tanpa izin eksplisit pemilik infrastruktur).
3. Kalau `--origin-ip` tidak diberikan dan target terdeteksi di belakang CDN, **tetap
   laporkan status "Infra scan dilewati — di belakang CDN" di PDF**, bukan diam-diam dianggap
   "0 temuan = aman". Ini sejalan dengan prinsip #6 di atas (jejak audit jujur).

---

## Ringkasan dampak setelah perbaikan

| Area | Sebelum | Sesudah |
|---|---|---|
| SQLi/XSS | Hanya jalan kalau target punya `?query=param` di URL | Bisa diarahkan ke endpoint + body JSON yang disiapkan manual dari daftar resmi (mis. `api-contract.md`) |
| IDOR/BOLA | Hanya jalan untuk ID numerik berurutan (tidak berlaku untuk sistem UUID) | Bisa diuji dua-akun (A vs B) untuk sistem UUID, sekaligus pesan log jujur kalau memang belum teruji |
| Infra scan | Diam-diam memindai IP CDN pihak ketiga seolah itu server target | Mendeteksi CDN, berhenti otomatis, dan hanya lanjut kalau penguji secara eksplisit memberi IP origin yang sudah diizinkan |

**Catatan akhir:** perbaikan ini membuat cakupan scan lebih jujur dan lebih dalam, tapi tetap
menolak jadi tool yang bisa "menyerang apa saja secara otomatis" — setiap perluasan cakupan di
atas tetap mensyaratkan **daftar target/endpoint yang disiapkan manual oleh penguji**, bukan
auto-discovery agresif. Itu batas yang memisahkan security scanner yang etis dari sekadar
exploit tool.
