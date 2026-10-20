# 🛡️ Omni-Web-Auditor

Omni-Web-Auditor adalah **kerangka kerja asesmen keamanan web berbasis OWASP WSTG**
(Web Security Testing Guide v4.2) berupa CLI Python. Tool ini menggabungkan
pemeriksaan otomatis (native + tool industri seperti nuclei, testssl.sh, OWASP ZAP,
sqlmap), checklist WSTG yang dapat diisi manual, pengumpulan bukti ber-hash, dan
verdict `PASS/FAIL/INCOMPLETE` yang dapat dipertanggungjawabkan — lalu menghasilkan
laporan PDF yang layak diserahkan ke klien.

> **Posisi yang jujur:** tool ini menghasilkan **WSTG-based self-assessment**, bukan
> pengganti pentest pihak ketiga independen. Verdict `PASS` berarti lolos kriteria
> asesmen yang didefinisikan (lihat di bawah) — bukan sertifikasi keamanan.

---

## ⚠️ Peringatan Etika & Disclaimer (SANGAT PENTING)

**Tool ini dikembangkan secara murni HANYA UNTUK TUJUAN EDUKASI dan AUDIT SISTEM YANG SAH di mana Anda memiliki izin tertulis secara eksplisit (Rules of Engagement) dari pemilik sistem. Penulis maupun kontributor TIDAK BERTANGGUNG JAWAB atas segala bentuk kerusakan, kerugian, atau penyalahgunaan tool ini untuk aktivitas ilegal.**

Prinsip yang ditegakkan oleh kode (bukan sekadar dokumen):
- **Scope ditegakkan**: request ke host di luar `scope` ditolak otomatis (`ScopeError`).
- **Non-destruktif**: payload hanya memicu bukti (error/reflection), tidak mengubah data.
- **Mode intrusif (sqlmap, ZAP active) hanya di environment `staging`** dengan flag eksplisit.
- **Di balik CDN**: port scan dilewati otomatis kecuali IP origin diberikan manual.
- **Tool yang tidak tersedia ditandai belum teruji**, tidak pernah dianggap lulus diam-diam.

---

## ✨ Fitur Utama

- **Native checks**: security headers, SSL/TLS (protokol dinegosiasikan), file sensitif
  terekspos, deteksi komponen usang, IDOR/BOLA (ID+1 dengan request kontrol & dua-akun UUID),
  port/servis terekspos, cloud storage, deteksi CDN.
- **Adapter tool industri (via Docker)**: `nuclei` (CVE/misconfig), `testssl.sh` (audit TLS
  lengkap), `OWASP ZAP` (baseline pasif / full active), `sqlmap` (konfirmasi SQLi, staging).
- **Checklist WSTG v4.2**: status `auto`/`manual`/`hybrid`, diisi otomatis dari hasil scan +
  dilengkapi penilaian & bukti manual.
- **Verdict engine**: `PASS/FAIL/INCOMPLETE` dengan aturan tegas (lihat di bawah).
- **Evidence store**: bukti disalin + di-hash SHA-256 + timestamp; header sensitif disensor.
- **Laporan PDF**: cover+verdict, scope/RoE, metodologi, executive summary, checklist matrix,
  findings (dengan skor CVSS v3.1), lampiran bukti, dan sign-off (watermark DRAFT bila belum).

---

## ⚙️ Instalasi

```bash
git clone https://github.com/Taufiq26/Omni-Web-Auditor.git
cd Omni-Web-Auditor

python3.11 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

pip install -r requirements.txt           # runtime
# untuk pengembangan + test:
pip install -r requirements-dev.txt
```

**Docker** diperlukan untuk adapter tool eksternal (nuclei/testssl/ZAP). Tanpa Docker,
native checks tetap jalan dan item terkait adapter ditandai "belum teruji". Image ditarik
sekali: `docker pull projectdiscovery/nuclei:latest drwetter/testssl.sh:latest zaproxy/zap-stable:latest`.

---

## 🚀 Alur Penggunaan (CLI `audit`)

Entry point tunggal: `python audit.py <subcommand>`.

```bash
# 1. Buat engagement (scope default = host target)
python audit.py init proyek-x --target https://staging.proyek-x.com \
    --environment staging --tester "Nama Penguji" --intrusive

# 2. Jalankan scan (native + adapter yang tersedia)
python audit.py run proyek-x --allow-intrusive \
    --endpoints-file endpoints.json \
    --token-a "TOKEN_A" --token-b "TOKEN_B"

# 3. Lihat checklist WSTG & isi item manual + bukti
python audit.py checklist proyek-x
python audit.py mark WSTG-ATHZ-02 --name proyek-x --status pass \
    --note "User biasa tidak bisa akses /admin" --evidence bukti1.png

# 4. Kelola temuan (terima risiko / tandai fixed / false positive)
python audit.py findings proyek-x
python audit.py finding 0 --name proyek-x --status accepted --note "risiko diterima"

# 5. Hitung verdict, tanda tangani, lalu buat laporan
python audit.py verdict proyek-x
python audit.py signoff proyek-x --name-signer "Nama Penguji"
python audit.py report proyek-x            # -> engagements/proyek-x/pentest_report_proyek-x.pdf
```

Subcommand: `init · run · checklist · mark · findings · finding · verdict · signoff · report`.
Bila hanya ada satu engagement, nama boleh dihilangkan.

### Opsi penting `run`
- `--scan-type {web,infra,full}` (default `full`)
- `--endpoints-file` — daftar endpoint uji **disiapkan manual** (SQLi/XSS body JSON & IDOR
  dua-akun). Lihat `examples/endpoints.example.json`.
- `--origin-ip` — IP origin untuk target di balik CDN (hanya bila punya izin langsung).
- `--cookie/--token`, `--cookie-a/-b`, `--token-a/-b` — kredensial & akun uji IDOR dua-akun.
- `--allow-intrusive` — aktifkan sqlmap & ZAP active (hanya berlaku di environment `staging`).
- `--no-adapters` — native checks saja.

---

## ✅ Definisi "Lolos" (Verdict)

> **Scope verdict:** verdict menilai **hanya item yang dapat diperiksa tool** (type `auto`
> & `hybrid`). Item **murni manual** tidak ikut dinilai di sini — dipisahkan ke
> **Lembar Kerja Manual** (lihat di bawah). Jadi `PASS` berarti **lolos pemeriksaan
> otomatis**, bukan sertifikasi keamanan menyeluruh.

- **FAIL** — ada temuan `Critical`/`High` yang belum tuntas (accept tidak berlaku untuk High+).
- **PASS** — semua item tool relevan (`auto`/`hybrid`, non-N/A) berstatus `pass` & berbukti,
  tidak ada `Critical`/`High` terbuka, temuan `Medium` semua *risk-accepted*, dan laporan
  sudah **sign-off**.
- **INCOMPLETE** — masih ada item tool belum dikerjakan / bukti kurang / `Medium` belum
  di-accept / belum sign-off.

Item `hybrid` yang dinilai manual lulus **wajib** melampirkan bukti, atau verdict tetap
`INCOMPLETE`. Pengujian ber-status `SKIPPED` (mis. adapter belum tersedia) berarti tool
**mampu namun belum dijalankan** — bukan indikasi aman.

---

## 🧪 Keandalan (Benchmark)

Keandalan diukur objektif terhadap OWASP Juice Shop & DVWA (celah diketahui) plus target
bersih (false-positive). Lihat [`benchmark/README.md`](benchmark/README.md) untuk cara
menjalankan dan snapshot angkanya.

---

## 🛠️ Pengembangan

```bash
pytest --cov=src --cov-report=term-missing   # tes + coverage (ambang CI: 80%)
ruff check src/ tests/ audit.py benchmark/   # lint
```

CI (GitHub Actions) menjalankan lint + test + coverage pada setiap push/PR.

---

## 📄 Output Laporan (dua file terpisah)

`audit report <nama>` menghasilkan **dua dokumen**: laporan tool otomatis + lembar kerja
manual. Pemisahan ini menjaga laporan tool fokus pada **apa yang tool periksa & hasilnya**,
sementara pengujian manual punya dokumennya sendiri.

### A. `pentest_report_<nama>.pdf` — Laporan Tool (otomatis)
1. **Cover & Verdict** — target, periode, penguji + peran, label "WSTG-based self-assessment".
2. **Scope & Rules of Engagement**.
3. **Metodologi** — WSTG v4.2 + daftar tool.
4. **Batasan Asesmen & Cakupan Manual** — penegasan: cakupan otomatis terbatas **bukan**
   berarti aman; sisanya ditangani manual oleh pen-tester (ada di dokumen B).
5. **Executive Summary** — ringkasan severity + dasar verdict.
6. **Checklist Matrix (auto & hybrid)** — hanya item yang dapat diperiksa tool + jumlah bukti.
7. **Cakupan Pengujian (Coverage)** — status `TESTED`/`SKIPPED`/`NOT_APPLICABLE` tiap tes + alasan.
8. **Findings & Remediation** — severity, skor CVSS, WSTG-ID, lokasi, bukti, remediasi, status.
9. **Lampiran Bukti** — daftar file + hash SHA-256.
10. **Sign-off** — nama, peran, pernyataan (atau watermark DRAFT bila belum).

### B. `manual_worksheet_<nama>.pdf` — Lembar Kerja Manual
Berisi **hanya item murni manual** (type `manual`) yang tidak dapat dinilai otomatis
(mis. session fixation, business logic, SSRF, stored XSS, authz vertical bypass), lengkap
dengan objective & langkah untuk diisi pen-tester. Nonaktifkan dengan `--no-worksheet`.
