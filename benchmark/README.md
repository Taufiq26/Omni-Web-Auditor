# Benchmark Harness

Mengukur keandalan tool secara objektif terhadap target yang celahnya sudah
diketahui (OWASP Juice Shop, DVWA) plus satu target "bersih" (nginx hardened)
untuk mengukur false-positive.

## Menjalankan

```bash
# 1. Hidupkan lab (butuh Docker)
docker-compose -f benchmark/docker-compose.yml up -d
#    atau: docker compose -f benchmark/docker-compose.yml up -d

# 2. Tunggu service siap, lalu jalankan
python -m benchmark.run            # cetak metrik + simpan results/benchmark_<ts>.json
python -m benchmark.run --baseline # simpan juga sebagai results/baseline.json

# 3. Matikan lab
docker-compose -f benchmark/docker-compose.yml down
```

Port: Juice Shop `3001`, DVWA `8080`, clean-nginx `8081`. Sesuaikan di
`docker-compose.yml` + `ground_truth.yaml` bila bentrok.

## Metrik

- **Matched/App** — temuan tertangkap / item ground-truth yang *dapat* dideteksi
  oleh sumber yang tersedia saat ini (lihat `detectable_by` di `ground_truth.yaml`).
- **Expected** — total celah diketahui pada target (termasuk yang butuh tool lain).
- **Recall** — Matched / Applicable.
- **FP** — temuan pada target bersih (seharusnya 0).

`results/` di-gitignore (machine-specific). Snapshot di bawah untuk acuan antar fase.

## Snapshot Baseline (Fase 1 — sumber: `native` saja)

| Target      | Findings | Matched/App | Expected | Recall | FP |
|-------------|----------|-------------|----------|--------|----|
| juice-shop  | 3        | 1/1         | 5        | 100%   | -  |
| dvwa        | 5        | 1/1         | 3        | 100%   | 0  |
| clean-nginx | 0        | 0/0         | 0        | -      | 0  |

**Interpretasi jujur:** "Recall 100%" di sini berarti native menangkap 100% dari
yang *native mampu* deteksi — yaitu hanya **1 dari 5** celah Juice Shop dan **1 dari 3**
celah DVWA (sisanya butuh SQLi/XSS aktif & deteksi CVE dari ZAP/nuclei/sqlmap).
False-positive 0 pada target bersih. Fase 2 (adapter tool eksternal) menargetkan
kenaikan kolom **Matched/Expected** secara signifikan.

## Snapshot Fase 2 (sumber: native + testssl + nuclei, sesudah perbaikan scope)

Terukur dengan ketiga target hidup dan NucleiAdapter non-intrusif dibatasi `-type http`:

| Target      | Findings | Matched/App | Expected | Recall | FP (Med+) | Noise (Low/Info) |
|-------------|----------|-------------|----------|--------|-----------|------------------|
| juice-shop  | 15       | 1/3         | 5        | 33%    | -         | -                |
| dvwa        | 4        | 1/1         | 3        | 100%   | -         | -                |
| clean-nginx | 0–5      | 0/0         | 0        | -      | **0**     | 0–5              |

**Yang terbukti:**
- Cakupan naik dari baseline native: nuclei+adapter menambah temuan nyata (juice-shop 3→15).
- Recall & Matched/App deterministik antar-run (juice-shop 1/3, dvwa 1/1).
- **False-positive (Medium+) di target bersih = 0 (stabil antar-run).** Noise Low/Info di
  clean-nginx bervariasi 0–5 per run (deteksi teknologi nginx info-level yang fluktuatif,
  bukan kerentanan) — run baseline terakhir (2026-10-13) menghasilkan 0 temuan sama sekali.
  Sebelum perbaikan, run tanpa `-type http`
  menghasilkan 9 FP yang ternyata BUKAN tentang nginx — melainkan "Redis/Postgres default
  login", "mDNS", dll., karena template **network (tcp)** nuclei memindai *seluruh host*
  lewat `host.docker.internal` (pelanggaran scope).
- **Perbaikan:** NucleiAdapter non-intrusif dibatasi `-type http` (hanya template HTTP ke URL
  target); template network yang melakukan port-probing & credential testing hanya aktif di
  mode `--intrusive`. 5 sisa di clean-nginx hanyalah noise Low/Info (deteksi teknologi), bukan
  kerentanan.

**Catatan lab:** target lab berbasis HTTP (tanpa 443), jadi adapter `testssl` wajar
menghasilkan 0 temuan di sini; nilainya terlihat pada target ber-HTTPS nyata. dvwa berjalan
via emulasi amd64 sehingga durasinya jauh lebih lama.
