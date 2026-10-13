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
