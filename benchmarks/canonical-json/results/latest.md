# Language Optimization Competition

- timestamp: 2026-02-18T06:26:47Z
- round: qa-full-20260218T062625Z
- host: Darwin arm64 (Apple M2 Max)
- runs per lane: 7
- profiles: base(iter=50000, warmup=5000), stress(iter=5000, warmup=500)

## Profile: base

| Rank | Language | Mean ops/s | Median ops/s | Mean elapsed (ms) | Stddev ops/s |
| ---: | --- | ---: | ---: | ---: | ---: |
| 1 | julia | 37991009.9 | 38675991.9 | 3.96 | 2147194.6 |
| 2 | rust | 36295825 | 35045369.7 | 4.19 | 4542078.9 |

## Profile: stress

| Rank | Language | Mean ops/s | Median ops/s | Mean elapsed (ms) | Stddev ops/s |
| ---: | --- | ---: | ---: | ---: | ---: |
| 1 | rust | 25819886 | 26063064.6 | 11.63 | 799978.6 |
| 2 | julia | 25672080.8 | 26039596.2 | 11.7 | 821778.1 |

## Checksum Integrity

- base: MATCH, checksum=caceec5bcfbdd390
- stress: MATCH, checksum=16f483da5283a340
