# pqhd

Post-quantum HD wallets: a standard for deriving post-quantum keys from a BIP-39 seed phrase, and a registry of the schemes it covers.

One seed phrase should be able to back up keys for any post-quantum scheme, on any chain, without those keys sharing secrets with each other or with existing elliptic-curve keys.

Website: [pqhd.projecteleven.com](https://pqhd.projecteleven.com/)

## Derivation path

```
m/83696968'/505153'/<coin_type>'/<scheme>'/<account>'/<index>'
```

| Level | Meaning |
|---|---|
| `83696968'` | BIP-85 purpose |
| `505153'` | BIP-85 application number for this standard (hex bytes of ASCII `PQS`) |
| `<coin_type>'` | Chain, from SLIP-44 |
| `<scheme>'` | Post-quantum scheme and parameter set, from the [registry](registry/README.md) |
| `<account>'` | Account, as in BIP-44 |
| `<index>'` | Key index, as in BIP-44 |

Every level is hardened. The BIP-85 entropy at the derived node seeds a SHAKE256 stream (BIP-85-DRNG-SHAKE256), and the registry says how many bytes each scheme reads and how they split into its key-generation inputs. See the [specification](spec/README.md).

## Registry

Each scheme family owns a block of 100 indices, and its parameter sets are numbered within the block.

| Indices | Schemes |
|---|---|
| 100-102 | ML-KEM-512, ML-KEM-768, ML-KEM-1024 (key encapsulation, for encryption) |
| 200-202 | ML-DSA-44, ML-DSA-65, ML-DSA-87 |
| 300-311 | SLH-DSA, all twelve SHA2 and SHAKE parameter sets |
| 400-401 | Reserved for FN-DSA-512 and FN-DSA-1024, pending FIPS 206 |

This covers every final NIST post-quantum signature standard that suits seed-based derivation, plus ML-KEM for encryption. Stateful hash-based signatures (LMS/XMSS, SP 800-208) are excluded because SP 800-208 forbids exporting their key material and a mnemonic can't restore their state; see the [spec](spec/README.md#coverage-and-exclusions).

Full table: [`registry/README.md`](registry/README.md).

## Repository

| Path | Contents |
|---|---|
| `spec/` | The specification |
| `registry/` | Scheme index assignments |
| `reference/` | Reference implementations |
| `test-vectors/` | Test vectors for every registry entry |

## Status

Draft. Nothing here is final until the spec reaches v1.0.

## Adding a scheme

Open a pull request adding an entry to `registry/registry.json` and regenerate the registry table and test vectors with `reference/python/gen_vectors.py`. An entry becomes `active` only with test vectors.

## Supporters

Projects and organizations that support or implement pqhd. To be listed, open a pull request adding a row.

| Supporter | Role |
|---|---|
| [iqlusion](https://github.com/iqlusioninc) | Implementer: [`pqseed`](https://github.com/iqlusioninc/crates/tree/main/pqseed) Rust crate |
| [Project Eleven](https://www.projecteleven.com) | Originator and co-author: [post-quantum keys from a 24-word seed phrase](https://www.projecteleven.com/blog/generating-post-quantum-keypairs-from-a-single-24word-seed-phrase) |

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT), at your option. Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work by you shall be dual licensed as above, without any additional terms or conditions.
