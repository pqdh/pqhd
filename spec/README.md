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
| `scheme` | A scheme index with status `active` or `deprecated` in the [registry] |
| `account` | Account number, as in BIP-44 |
| `index` | Key index within the account |

`coin_type`, `scheme`, `account`, and `index` MUST each be in `[0, 2^31)`.

### Step 1: seed

Implementations MUST validate the mnemonic against a BIP-39 wordlist, including
its checksum, and MUST reject mnemonics that do not have exactly 24 words.
Implementations MUST support the English wordlist.

The 64-byte `seed` is computed as in BIP-39: PBKDF2-HMAC-SHA512 with 2048
iterations, the canonical mnemonic sentence as the password, and salt
`"mnemonic" || NFKD(passphrase)`.

The canonical mnemonic sentence is formed by NFKD-normalizing the input,
splitting it on whitespace, and joining the words with a single U+0020 space.
Leading, trailing, and repeated whitespace in the input therefore does not
affect the seed. This is required because PBKDF2 hashes the exact bytes of the
sentence, and BIP-39 does not say how to treat irregular whitespace. Whitespace
in the passphrase is significant and is not altered beyond NFKD normalization.

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
registry. For example:

- ML-DSA: `ML-DSA.KeyGen_internal(ξ)` with `ξ = output[0..32]` (FIPS 204).
- SLH-DSA with security parameter `n`:
  `slh_keygen_internal(SK.seed, SK.prf, PK.seed)` with the three `n`-byte
  chunks of `output`, in that order (FIPS 205).
- ML-KEM: `ML-KEM.KeyGen_internal(d, z)` with `d = output[0..32]` and
  `z = output[32..64]` (FIPS 203).

The registry, not this document, is authoritative for `L`, the input layout,
and the key-generation function of each scheme.

## Registry

The [registry] assigns scheme indices in blocks. Each scheme family, such as
ML-DSA, owns a block of `block_size` (100) consecutive indices starting at
`100 * block`, and each of its parameter sets takes the next free index in that
block. ML-KEM is block 1 (indices 100-199), ML-DSA block 2, SLH-DSA block 3,
and FN-DSA block 4. Block 0 is never assigned.

Fields shared by every parameter set of a family are stated once, on the
family:

| Family field | Meaning |
|--------------|---------|
| `block` | Block number; the family's indices are `100 * block` to `100 * block + 99` |
| `name` | Family name, e.g. `ML-DSA` |
| `type` | `signature` or `kem` |
| `standard` | The defining standard |
| `keygen` | The deterministic key-generation function, absent until the standard is final |

Each parameter set is an entry:

| Entry field | Meaning |
|-------------|---------|
| `index` | Scheme index, the `scheme'` path level |
| `name` | Scheme and parameter set |
| `family` | Name of its family |
| `oid` | The parameter set's object identifier, where one is assigned |
| `security_category` | NIST security category |
| `status` | `active`, `reserved`, or `deprecated` |
| `output_bytes` | `L`, the number of DRNG bytes to read |
| `inputs` | Ordered list of `{name, bytes}`; lengths sum to `output_bytes` |

Rules:

1. A new family takes the next unused block. A new parameter set takes the next
   unused index in its family's block. If a family fills its block, it is
   assigned an additional block.
2. Indices are append-only and are never reused or reassigned, including after
   deprecation.
3. `reserved` entries hold an index for a scheme whose standard or input layout
   is not final, and MUST NOT be derived. `deprecated` entries MUST remain
   derivable so existing keys can be recovered from the mnemonic; wallets
   SHOULD NOT generate new keys under them.
4. An entry becomes `active` only with test vectors covering it.

New schemes are proposed by pull request adding a registry entry, and a family
if needed, with test vectors.

### Coverage and exclusions

For signatures, the registry covers every final NIST post-quantum signature
standard suitable for seed-based derivation: ML-DSA (FIPS 204) and SLH-DSA
(FIPS 205), all parameter sets. For encryption, it covers the NIST
key-encapsulation mechanism ML-KEM (FIPS 203), so wallets can derive keys for
receiving encrypted data from the same mnemonic. A KEM key and a signature key
never share a path, because they have different scheme indices.

- **FN-DSA** (FIPS 206) holds reserved indices until FIPS 206 is final. Its key
  generation consumes a variable amount of randomness, so its entries may need
  to read the DRNG stream on demand instead of a fixed `L`.
- **Stateful hash-based signatures** (LMS, HSS, XMSS, and XMSS^MT; NIST
  SP 800-208) are not eligible. SP 800-208 "requires that key and signature
  generation be performed in hardware cryptographic modules that do not allow
  secret keying material to be exported, even in encrypted form", which
  mnemonic backup contradicts by design. A mnemonic also cannot restore the
  one-time-signature state, so a restored wallet could reuse a one-time key,
  which enables forgery.

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

Every active or deprecated registry entry has a vector file in [`test-vectors/`]. Each case
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
- [NIST SP 800-208]: Recommendation for Stateful Hash-Based Signature Schemes

[registry]: ../registry/README.md
[`test-vectors/`]: ../test-vectors/
[BIP-32]: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
[BIP-39]: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
[BIP-44]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
[BIP-85]: https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki
[SLIP-44]: https://github.com/satoshilabs/slips/blob/master/slip-0044.md
[NIST SP 800-208]: https://doi.org/10.6028/NIST.SP.800-208
