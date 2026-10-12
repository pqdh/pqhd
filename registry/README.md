# Registry

Generated from [`registry.json`](registry.json) by
`reference/python/gen_vectors.py`; edit the JSON, not this file.

Scheme indices are the `<scheme>'` level of
`m/83696968'/505153'/<coin_type>'/<scheme>'/<account>'/<index>'`. Each family
owns a block of 100 indices starting at `100 * block`, and its parameter sets
are numbered within the block. `L` is the number of bytes read from
BIP-85-DRNG-SHAKE256, split into the key-generation inputs in the order listed.
Indices are append-only and never reused.

## Families

| Block | Indices | Family | Type | Standard | Key generation |
|------:|--------:|--------|------|----------|----------------|
| 1 | 100-199 | ML-KEM | kem | FIPS 203 | `ML-KEM.KeyGen_internal` |
| 2 | 200-299 | ML-DSA | signature | FIPS 204 | `ML-DSA.KeyGen_internal` |
| 3 | 300-399 | SLH-DSA | signature | FIPS 205 | `slh_keygen_internal` |
| 4 | 400-499 | FN-DSA | signature | FIPS 206 (draft) |  |

## Parameter sets

| Index | Scheme | OID | Category | Status | `L` | Key generation inputs |
|------:|--------|-----|:--------:|--------|----:|-----------------------|
| 100 | ML-KEM-512 | 2.16.840.1.101.3.4.4.1 | 1 | active | 64 | d (32) \|\| z (32) |
| 101 | ML-KEM-768 | 2.16.840.1.101.3.4.4.2 | 3 | active | 64 | d (32) \|\| z (32) |
| 102 | ML-KEM-1024 | 2.16.840.1.101.3.4.4.3 | 5 | active | 64 | d (32) \|\| z (32) |
| 200 | ML-DSA-44 | 2.16.840.1.101.3.4.3.17 | 2 | active | 32 | xi (32) |
| 201 | ML-DSA-65 | 2.16.840.1.101.3.4.3.18 | 3 | active | 32 | xi (32) |
| 202 | ML-DSA-87 | 2.16.840.1.101.3.4.3.19 | 5 | active | 32 | xi (32) |
| 300 | SLH-DSA-SHA2-128s | 2.16.840.1.101.3.4.3.20 | 1 | active | 48 | SK.seed (16) \|\| SK.prf (16) \|\| PK.seed (16) |
| 301 | SLH-DSA-SHA2-128f | 2.16.840.1.101.3.4.3.21 | 1 | active | 48 | SK.seed (16) \|\| SK.prf (16) \|\| PK.seed (16) |
| 302 | SLH-DSA-SHA2-192s | 2.16.840.1.101.3.4.3.22 | 3 | active | 72 | SK.seed (24) \|\| SK.prf (24) \|\| PK.seed (24) |
| 303 | SLH-DSA-SHA2-192f | 2.16.840.1.101.3.4.3.23 | 3 | active | 72 | SK.seed (24) \|\| SK.prf (24) \|\| PK.seed (24) |
| 304 | SLH-DSA-SHA2-256s | 2.16.840.1.101.3.4.3.24 | 5 | active | 96 | SK.seed (32) \|\| SK.prf (32) \|\| PK.seed (32) |
| 305 | SLH-DSA-SHA2-256f | 2.16.840.1.101.3.4.3.25 | 5 | active | 96 | SK.seed (32) \|\| SK.prf (32) \|\| PK.seed (32) |
| 306 | SLH-DSA-SHAKE-128s | 2.16.840.1.101.3.4.3.26 | 1 | active | 48 | SK.seed (16) \|\| SK.prf (16) \|\| PK.seed (16) |
| 307 | SLH-DSA-SHAKE-128f | 2.16.840.1.101.3.4.3.27 | 1 | active | 48 | SK.seed (16) \|\| SK.prf (16) \|\| PK.seed (16) |
| 308 | SLH-DSA-SHAKE-192s | 2.16.840.1.101.3.4.3.28 | 3 | active | 72 | SK.seed (24) \|\| SK.prf (24) \|\| PK.seed (24) |
| 309 | SLH-DSA-SHAKE-192f | 2.16.840.1.101.3.4.3.29 | 3 | active | 72 | SK.seed (24) \|\| SK.prf (24) \|\| PK.seed (24) |
| 310 | SLH-DSA-SHAKE-256s | 2.16.840.1.101.3.4.3.30 | 5 | active | 96 | SK.seed (32) \|\| SK.prf (32) \|\| PK.seed (32) |
| 311 | SLH-DSA-SHAKE-256f | 2.16.840.1.101.3.4.3.31 | 5 | active | 96 | SK.seed (32) \|\| SK.prf (32) \|\| PK.seed (32) |
| 400 | FN-DSA-512 |  | | reserved | | Reserved pending a final FIPS 206; output_bytes and inputs are not yet defined. |
| 401 | FN-DSA-1024 |  | | reserved | | Reserved pending a final FIPS 206; output_bytes and inputs are not yet defined. |
