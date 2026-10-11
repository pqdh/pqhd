# Registry

Generated from [`registry.json`](registry.json) by
`reference/python/gen_vectors.py`; edit the JSON, not this file.

Scheme indices are the `<scheme>'` level of
`m/83696968'/505153'/<coin_type>'/<scheme>'/<account>'/<index>'`. `L` is the
number of bytes read from BIP-85-DRNG-SHAKE256, split into the key-generation
inputs in the order listed. Indices are append-only and never reused.

| Index | Scheme | Standard | Category | Status | `L` | Key generation inputs |
|------:|--------|----------|:--------:|--------|----:|-----------------------|
| 0 | ML-DSA-44 | FIPS 204 | 2 | active | 32 | `ML-DSA.KeyGen_internal`: xi (32) |
| 1 |  | | | reserved | | Reserved, as in Project Eleven's scheme. Indices 0-2 mirror Project Eleven's assignments; 3 and 4 match pqseed's extensions. |
| 2 | SLH-DSA-SHA2-128s | FIPS 205 | 1 | active | 48 | `slh_keygen_internal`: SK.seed (16) \|\| SK.prf (16) \|\| PK.seed (16) |
| 3 | ML-DSA-65 | FIPS 204 | 3 | active | 32 | `ML-DSA.KeyGen_internal`: xi (32) |
| 4 | ML-DSA-87 | FIPS 204 | 5 | active | 32 | `ML-DSA.KeyGen_internal`: xi (32) |
| 5 | SLH-DSA-SHAKE-128s | FIPS 205 | 1 | active | 48 | `slh_keygen_internal`: SK.seed (16) \|\| SK.prf (16) \|\| PK.seed (16) |
| 6 | SLH-DSA-SHA2-128f | FIPS 205 | 1 | active | 48 | `slh_keygen_internal`: SK.seed (16) \|\| SK.prf (16) \|\| PK.seed (16) |
| 7 | SLH-DSA-SHAKE-128f | FIPS 205 | 1 | active | 48 | `slh_keygen_internal`: SK.seed (16) \|\| SK.prf (16) \|\| PK.seed (16) |
| 8 | SLH-DSA-SHA2-192s | FIPS 205 | 3 | active | 72 | `slh_keygen_internal`: SK.seed (24) \|\| SK.prf (24) \|\| PK.seed (24) |
| 9 | SLH-DSA-SHAKE-192s | FIPS 205 | 3 | active | 72 | `slh_keygen_internal`: SK.seed (24) \|\| SK.prf (24) \|\| PK.seed (24) |
| 10 | SLH-DSA-SHA2-192f | FIPS 205 | 3 | active | 72 | `slh_keygen_internal`: SK.seed (24) \|\| SK.prf (24) \|\| PK.seed (24) |
| 11 | SLH-DSA-SHAKE-192f | FIPS 205 | 3 | active | 72 | `slh_keygen_internal`: SK.seed (24) \|\| SK.prf (24) \|\| PK.seed (24) |
| 12 | SLH-DSA-SHA2-256s | FIPS 205 | 5 | active | 96 | `slh_keygen_internal`: SK.seed (32) \|\| SK.prf (32) \|\| PK.seed (32) |
| 13 | SLH-DSA-SHAKE-256s | FIPS 205 | 5 | active | 96 | `slh_keygen_internal`: SK.seed (32) \|\| SK.prf (32) \|\| PK.seed (32) |
| 14 | SLH-DSA-SHA2-256f | FIPS 205 | 5 | active | 96 | `slh_keygen_internal`: SK.seed (32) \|\| SK.prf (32) \|\| PK.seed (32) |
| 15 | SLH-DSA-SHAKE-256f | FIPS 205 | 5 | active | 96 | `slh_keygen_internal`: SK.seed (32) \|\| SK.prf (32) \|\| PK.seed (32) |
| 16 | ML-KEM-512 | FIPS 203 | 1 | active | 64 | `ML-KEM.KeyGen_internal`: d (32) \|\| z (32) |
| 17 | ML-KEM-768 | FIPS 203 | 3 | active | 64 | `ML-KEM.KeyGen_internal`: d (32) \|\| z (32) |
| 18 | ML-KEM-1024 | FIPS 203 | 5 | active | 64 | `ML-KEM.KeyGen_internal`: d (32) \|\| z (32) |
| 19 | FN-DSA-512 | | | reserved | | Reserved pending a final FIPS 206; output_bytes and inputs are not yet defined. |
| 20 | FN-DSA-1024 | | | reserved | | Reserved pending a final FIPS 206; output_bytes and inputs are not yet defined. |
