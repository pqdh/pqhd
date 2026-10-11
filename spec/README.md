# pqhd: post-quantum keys from BIP-39 mnemonics

Status: **Draft, v0.1.0.** Nothing here is final until v1.0. Do not protect
real assets with keys derived under a draft.

## Abstract

pqhd derives keys for post-quantum schemes from a single 24-word BIP-39
mnemonic. A chain, scheme, account, and key index select a hardened BIP-32 path
under a BIP-85 application; the BIP-85 entropy at that path seeds a SHAKE256
stream; and the scheme's registry entry says how many bytes to read and how to
split them into the scheme's deterministic key-generation function.

Any two conforming implementations derive identical keys from the same
mnemonic, passphrase, coin type, scheme, account, and index.

## Motivation

Wallets already back up elliptic-curve keys for every chain with one mnemonic.
Post-quantum keys need the same property, plus:

- **Separation.** Keys for different chains, schemes, accounts, and indices
  must share no usable secret, so compromise or misuse of one reveals nothing
  about another, and the same post-quantum public key never appears on two
  chains.
- **Interoperability.** A chain adopting a post-quantum scheme needs one
  derivation that every wallet implements identically.
- **Extensibility.** New schemes and parameter sets must be added without
  changing the derivation procedure, by adding a registry entry.

## Conventions

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as in
RFC 2119. `||` is byte concatenation. `x'` denotes the hardened index
`x + 2^31`.

## Specification

### Inputs

| Input | Description |
|-------|-------------|
| `mnemonic` | A BIP-39 mnemonic of exactly 24 words (256 bits of entropy) |
| `passphrase` | A BIP-39 passphrase, possibly empty |
| `coin_type` | The chain's [SLIP-44] coin type |
| `scheme` | A scheme index with status `active` in the [registry] |
| `account` | Account number, as in BIP-44 |
| `index` | Key index within the account |

`coin_type`, `scheme`, `account`, and `index` MUST each be in `[0, 2^31)`.

### Step 1: seed

Implementations MUST validate the mnemonic against a BIP-39 wordlist, including
its checksum, and MUST reject mnemonics that do not have exactly 24 words.
Implementations MUST support the English wordlist.

The 64-byte `seed` is computed as in BIP-39: PBKDF2-HMAC-SHA512 with 2048
iterations, password the NFKD-normalized mnemonic sentence (words separated by
a single U+0020 space), and salt `"mnemonic" || NFKD(passphrase)`.

### Step 2: BIP-32 path

Derive the BIP-32 secp256k1 master key from `seed`, then derive the hardened
path:

```text
m / 83696968' / 505153' / coin_type' / scheme' / account' / index'
```

| Level | Value |
|-------|-------|
| Purpose | `83696968'`, BIP-85 |
| Application | `505153'`, pqhd (the hex bytes of ASCII `PQS`) |
| Chain | `coin_type'` |
| Scheme | `scheme'` |
| Account | `account'` |
| Key | `index'` |

Every level is hardened. If BIP-32 reports an invalid master or child key
(`parse256(IL) >= n` or a zero key), derivation MUST fail. Implementations MUST
NOT skip to the next index as BIP-32 suggests, because each index is
meaningful. This occurs with probability below 2<sup>-127</sup> per step.

Let `k` be the resulting 32-byte private key, big-endian.

### Step 3: BIP-85 entropy

```text
entropy = HMAC-SHA512(key = "bip-entropy-from-k", message = k)
```

`entropy` is 64 bytes, as defined by BIP-85.

### Step 4: expansion

Read `L` bytes from BIP-85-DRNG-SHAKE256 seeded with `entropy`:

```text
output = SHAKE256(entropy)[0 .. L]
```

`L` is the scheme's `output_bytes` in the registry. The DRNG is used for every
scheme, including those with `L <= 64`, so there is a single procedure.

### Step 5: key generation

Split `output` into the scheme's `inputs`, consecutively and in registry order,
and call the scheme's deterministic key-generation function, also named in the
registry.

The registry, not this document, is authoritative for `L`, the input layout,
and the key-generation function of each scheme.

## Registry

The [registry] assigns scheme indices. Each entry has:

| Field | Meaning |
|-------|---------|
| `index` | Scheme index, the `scheme'` path level |
| `name` | Scheme and parameter set |
| `family` | Scheme family, e.g. `ML-DSA` |
| `type` | `signature` or `kem` |
| `standard` | The defining standard |
| `security_category` | NIST security category |
| `status` | `active`, `reserved`, or `deprecated` |
| `output_bytes` | `L`, the number of DRNG bytes to read |
| `keygen` | The deterministic key-generation function |
| `inputs` | Ordered list of `{name, bytes}`; lengths sum to `output_bytes` |

Rules:

1. Indices are assigned sequentially, are append-only, and are never reused or
   reassigned, including after deprecation.
2. Only `active` entries may be derived. `reserved` entries hold an index for a
   scheme whose standard or input layout is not final.
3. An entry becomes `active` only with test vectors covering it.

New schemes are proposed by pull request adding a registry entry and test
vectors.

## Relationship to Project Eleven's scheme

Project Eleven derives keys at `m/83696968'/503131'/alg'` and truncates the
BIP-85 entropy instead of using the DRNG. pqhd differs in application number,
path depth, and expansion, so **pqhd keys are never equal to Project Eleven
keys**. Wallets supporting both MUST keep them
distinct.

## Security considerations

- **Classical derivation.** BIP-32 uses secp256k1, which a quantum computer can
  break. The post-quantum keys derive only from hardened private derivation,
  but any extended public key along these paths would let a quantum attacker
  recover the corresponding private scalar. Implementations MUST NOT export
  extended public keys or extended private keys for any node on a pqhd path.
- **No public derivation.** Post-quantum keys cannot be derived from a parent
  public key, so watch-only wallets need exported public keys, not an xpub.
  This is why there are no non-hardened levels such as BIP-44's `change`.
- **Mnemonic reuse.** The same mnemonic may also back classical wallets. Their
  keys are on different BIP-32 paths, but compromise of the classical root key
  (for example, through a leaked extended private key) compromises every pqhd
  key. Exposing a classical extended public key at or above `m/83696968'`
  exposes pqhd keys to a quantum attacker.
- **Entropy.** All keys are bounded by the mnemonic's 256 bits of entropy,
  about 128 bits against Grover's algorithm, and by the 256-bit secp256k1
  scalar at each node. This is why 24 words are required. Derived keys for
  NIST category 3 and 5 schemes do not exceed this bound.
- **Passphrase.** A wrong passphrase yields valid but different keys, with no
  way to detect the mistake.
- **Key separation.** Each `(coin_type, scheme, account, index)` uses a
  different hardened path, so keys share no secret beyond the seed. A key
  derived for one scheme MUST NOT be used with a different scheme.
- **Implementation hygiene.** The seed, intermediate keys and chain codes,
  `entropy`, and `output` are all secret and should be erased after use.

## Test vectors

Every active registry entry has a vector file in [`test-vectors/`]. Each case
gives the mnemonic, passphrase, seed, path, BIP-85 entropy, DRNG output, split
inputs and, where available, the SHA-256 of the encoded public key. See the
test vector README for what each field has been independently checked against.

## References

- [BIP-32]: Hierarchical Deterministic Wallets
- [BIP-39]: Mnemonic code for generating deterministic keys
- [BIP-44]: Multi-Account Hierarchy for Deterministic Wallets
- [BIP-85]: Deterministic Entropy From BIP32 Keychains, including BIP-85-DRNG-SHAKE256
- [SLIP-44]: Registered coin types for BIP-0044
- FIPS 202 (SHA-3 and SHAKE), FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
- [Project Eleven: Generating Post-Quantum Keypairs from a Single 24-Word Seed Phrase][p11]

[registry]: ../registry/README.md
[`test-vectors/`]: ../test-vectors/
[BIP-32]: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
[BIP-39]: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
[BIP-44]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
[BIP-85]: https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki
[SLIP-44]: https://github.com/satoshilabs/slips/blob/master/slip-0044.md
[p11]: https://www.projecteleven.com/blog/generating-post-quantum-keypairs-from-a-single-24word-seed-phrase
