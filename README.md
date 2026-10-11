# pqhd

Post-quantum HD wallets: a standard for deriving post-quantum keys from a BIP-39 seed phrase, and a registry of the schemes it covers.

One seed phrase should be able to back up keys for any post-quantum scheme, on any chain, without those keys sharing secrets with each other or with existing elliptic-curve keys.

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

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT), at your option. Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work by you shall be dual licensed as above, without any additional terms or conditions.
