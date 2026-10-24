# Compresión gzip y Brotli — datos crudos (C11 / H6)

Language: **Spanish** (raw data; the evidence document is in English).

- Binary: `/Volumes/Lexar/Cursor/EQProxy/target/release/eqproxy`, sha256 `adb6dfffa1587a3f02e5f70dd7ba8383970b19e9fc370444660c042c840c48f2`
- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`
- Host: `Darwin arm64`, loopback TCP, one sequential client, no TLS
- 5 repetitions × 50 requests per cell (plus 3 warm-up);
  every compressed response was decoded and compared with the origin's bytes
  (zlib for gzip, the Brotli reference module for `br`).
- `raw.jsonl` holds one line per repetition (all columns).

| Config | Corpus | Wire B/req (median) | Ratio vs identity | Req/s median [min–max] | Válidos |
|---|---|---|---|---|---|
| `identity` | `text` | 771,214 | 1.000 | 1,417.9 [1,324.4–1,500.8] | 0/0 |
| `identity` | `json` | 1,037,124 | 1.000 | 755.5 [625.0–950.1] | 0/0 |
| `identity` | `binary` | 262,144 | 1.000 | 1,957.7 [1,419.9–2,373.6] | 0/0 |
| `gzip-level-1` | `text` | 64,636 | 0.084 | 474.2 [426.3–478.4] | 250/250 |
| `gzip-level-1` | `json` | 88,371 | 0.085 | 356.0 [344.1–359.9] | 250/250 |
| `gzip-level-1` | `binary` | 262,144 | 1.000 | 2,561.2 [2,518.3–2,966.5] | 0/0 |
| `gzip-level-6` | `text` | 49,799 | 0.065 | 187.4 [182.9–190.9] | 250/250 |
| `gzip-level-6` | `json` | 77,132 | 0.074 | 77.1 [69.9–80.0] | 250/250 |
| `gzip-level-6` | `binary` | 262,144 | 1.000 | 2,849.0 [2,678.0–3,010.7] | 0/0 |
| `gzip-level-9` | `text` | 49,769 | 0.065 | 143.6 [129.9–145.2] | 250/250 |
| `gzip-level-9` | `json` | 77,134 | 0.074 | 35.5 [32.3–36.0] | 250/250 |
| `gzip-level-9` | `binary` | 262,144 | 1.000 | 2,775.2 [2,601.3–3,079.0] | 0/0 |
| `brotli-quality-1` | `text` | 59,240 | 0.077 | 227.2 [222.5–240.2] | 250/250 |
| `brotli-quality-1` | `json` | 79,392 | 0.077 | 166.8 [157.2–172.0] | 250/250 |
| `brotli-quality-1` | `binary` | 262,144 | 1.000 | 2,636.1 [2,432.0–2,707.7] | 0/0 |
| `brotli-quality-5` | `text` | 12,726 | 0.017 | 127.5 [125.4–131.9] | 250/250 |
| `brotli-quality-5` | `json` | 30,380 | 0.029 | 66.1 [60.4–68.1] | 250/250 |
| `brotli-quality-5` | `binary` | 262,144 | 1.000 | 2,406.7 [2,396.2–2,700.3] | 0/0 |
| `brotli-quality-11` | `text` | 11,998 | 0.016 | 0.5 [0.5–0.6] | 250/250 |
| `brotli-quality-11` | `json` | 32,366 | 0.031 | 0.5 [0.5–0.5] | 250/250 |
| `brotli-quality-11` | `binary` | 262,144 | 1.000 | 2,580.5 [2,202.4–2,655.6] | 0/0 |

El corpus `binary` (`application/octet-stream`) queda fuera de la lista de
tipos por defecto: sus filas comprimidas muestran el caso en que no se
comprime (ratio 1.000) aun aceptando el cliente esa codificación.

Los req/s son una medición indicativa de un cliente secuencial en un portátil
compartido: el rango entre repeticiones (columna min–max y `raw.jsonl`) es
amplio y no se promete ninguna cifra de rendimiento. Lo que sí es estable y
reproducible es el tamaño en el cable y el ratio por corpus.
