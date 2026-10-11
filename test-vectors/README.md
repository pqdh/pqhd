# Test vectors

One file per registry entry, named by scheme index. Each file covers three
mnemonic/passphrase pairs (including a non-ASCII passphrase, to exercise NFKD
normalization) at three scopes: `(coin_type, account, index)` of `(0, 0, 0)`,
`(133, 0, 0)`, and `(60, 1, 7)`.

| Field | Meaning |
|-------|---------|
| `mnemonic`, `passphrase` | BIP-39 inputs |
| `seed` | 64-byte BIP-39 seed |
| `path` | Full derivation path |
| `bip85_entropy` | 64-byte HMAC-SHA512 output at the leaf |
| `output` | First `L` bytes of SHAKE256(`bip85_entropy`) |
| `inputs` | `output` split into the scheme's key-generation inputs |
| `public_key_sha256` | SHA-256 of the raw FIPS-encoded public key, where present |

## Provenance

All fields except `public_key_sha256` are produced by the
[Python reference implementation](../reference/python/), which uses only the
Python standard library. Its test suite checks each layer against an
independent source:

| Layer | Checked against |
|-------|-----------------|
| BIP-32 hardened derivation and BIP-85 entropy | The BIP-85 specification's derived-key and derived-entropy vectors |
| BIP-85-DRNG-SHAKE256 | The BIP-85 specification's DRNG vector |
| BIP-39 seed, BIP-32, and BIP-85 at Project Eleven's paths | Seeds generated with `@scure/bip39`, `@scure/bip32`, and `@noble/hashes` |

The composed pqhd output (application `505153'` plus the DRNG) has so far been
produced by this one implementation only. A second implementation should
reproduce these files before v1.0.

Regenerate with `python3 gen_vectors.py [--pk-hashes <file>]` from
`reference/python`; without the flag, existing hashes are kept. The test suite
fails if these files or the registry table are stale.
