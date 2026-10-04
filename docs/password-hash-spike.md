# Password hash spike (APS 48 decision 6)

Measured with `wrangler dev` on the local workerd runtime using `argon2-wasm-edge` and the OWASP minimum Argon2id profile used here: 19,456 KiB, 2 iterations, parallelism 1, 32 byte output.

| Measurement | CPU time | Memory |
|---|---:|---:|
| First hash in a fresh isolate (includes WASM initialization) | 282 ms | 19,456 KiB |
| Warm hashes, next eight observations | 103–116 ms | 19,456 KiB |
| PBKDF2-SHA256 fallback probe, 600,000 iterations | 558 ms | below Argon2's 19 MiB working set |

The warmed Argon2id hash remained below the decision's approximately 150 ms threshold, so credential rows use Argon2id. Each row stores `alg`, the memory and iteration cost, salt, and encoded verifier. The first hash in a new isolate is slower because it initializes the WASM module; this cold-start cost is retained above for review.
