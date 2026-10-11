"""pqhd reference implementation (Python standard library only).

Derives post-quantum key-generation input from a BIP-39 mnemonic:

    BIP-39 seed -> BIP-32 (secp256k1) master key
    -> m/83696968'/505153'/coin_type'/scheme'/account'/index'
    -> BIP-85 entropy: HMAC-SHA512(key="bip-entropy-from-k", leaf private key)
    -> BIP-85-DRNG-SHAKE256: read output_bytes from SHAKE256(entropy)
    -> split into the scheme's key-generation inputs, per the registry

This is a reference for checking other implementations, not production code:
it makes no attempt at constant-time arithmetic or erasing secrets.

Every path level is hardened, so BIP-32 derivation needs only scalar addition
modulo the secp256k1 group order; no elliptic-curve point arithmetic is used.
"""

import hashlib
import hmac
import json
import os
import sys
import unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
REGISTRY_PATH = os.path.join(HERE, "..", "..", "registry", "registry.json")

BIP85_PURPOSE = 83696968
PQHD_APP = 505153
HARDENED = 0x80000000
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
WORD_COUNT = 24


class DerivationError(Exception):
    """Raised for invalid input or an invalid BIP-32 derivation step."""


def _wordlist():
    with open(os.path.join(HERE, "english.txt"), encoding="utf-8") as f:
        words = f.read().split()
    assert len(words) == 2048
    return words


def load_registry(path=REGISTRY_PATH):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def scheme(registry, index):
    """Return the active registry entry for a scheme index."""
    for entry in registry["entries"]:
        if entry["index"] == index:
            if entry["status"] != "active":
                raise DerivationError(f"scheme {index} is {entry['status']}")
            return entry
    raise DerivationError(f"scheme {index} is not in the registry")


def normalize_mnemonic(phrase):
    """NFKD-normalize, split on whitespace, and validate a 24-word English mnemonic."""
    words = unicodedata.normalize("NFKD", phrase).split()
    if len(words) != WORD_COUNT:
        raise DerivationError(f"expected {WORD_COUNT} words, got {len(words)}")
    wordlist = _wordlist()
    try:
        indices = [wordlist.index(w) for w in words]
    except ValueError as err:
        raise DerivationError("unknown word") from err
    bits = "".join(format(i, "011b") for i in indices)
    entropy = int(bits[:256], 2).to_bytes(32, "big")
    checksum = format(hashlib.sha256(entropy).digest()[0], "08b")
    if bits[256:] != checksum:
        raise DerivationError("invalid checksum")
    return " ".join(words)


def bip39_seed(phrase, passphrase=""):
    """BIP-39 seed: PBKDF2-HMAC-SHA512, 2048 iterations, NFKD-normalized inputs."""
    sentence = normalize_mnemonic(phrase)
    salt = "mnemonic" + unicodedata.normalize("NFKD", passphrase)
    return hashlib.pbkdf2_hmac("sha512", sentence.encode(), salt.encode(), 2048, 64)


def _master(seed):
    i = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k = int.from_bytes(i[:32], "big")
    if k == 0 or k >= SECP256K1_N:
        raise DerivationError("invalid master key")
    return k, i[32:]


def _hardened_child(k, chain_code, index):
    if not 0 <= index < HARDENED:
        raise DerivationError(f"path element {index} is not below 2^31")
    data = b"\x00" + k.to_bytes(32, "big") + (index | HARDENED).to_bytes(4, "big")
    i = hmac.new(chain_code, data, hashlib.sha512).digest()
    il = int.from_bytes(i[:32], "big")
    child = (il + k) % SECP256K1_N
    # pqhd fails instead of skipping to the next index, as BIP-32 suggests:
    # each index is meaningful, so silently substituting another is wrong.
    if il >= SECP256K1_N or child == 0:
        raise DerivationError("invalid BIP-32 child key")
    return child, i[32:]


def path(coin_type, scheme_index, account, index):
    return [BIP85_PURPOSE, PQHD_APP, coin_type, scheme_index, account, index]


def bip85_entropy(seed, path_elements):
    """BIP-85: HMAC-SHA512 keyed with "bip-entropy-from-k" over the leaf private key."""
    k, c = _master(seed)
    for element in path_elements:
        k, c = _hardened_child(k, c, element)
    return hmac.new(b"bip-entropy-from-k", k.to_bytes(32, "big"), hashlib.sha512).digest()


def drng(entropy, length):
    """BIP-85-DRNG-SHAKE256: the first `length` bytes of SHAKE256(entropy)."""
    if len(entropy) != 64:
        raise DerivationError("BIP-85-DRNG input must be exactly 64 bytes")
    return hashlib.shake_256(entropy).digest(length)


def split_inputs(entry, output):
    """Split DRNG output into the scheme's key-generation inputs, in registry order."""
    inputs, offset = [], 0
    for item in entry["inputs"]:
        inputs.append((item["name"], output[offset:offset + item["bytes"]]))
        offset += item["bytes"]
    assert offset == entry["output_bytes"] == len(output)
    return inputs


def derive(seed, coin_type, scheme_index, account, index, registry=None):
    """Return (entry, entropy, output, inputs) for a scoped pqhd key."""
    registry = registry or load_registry()
    entry = scheme(registry, scheme_index)
    entropy = bip85_entropy(seed, path(coin_type, scheme_index, account, index))
    output = drng(entropy, entry["output_bytes"])
    return entry, entropy, output, split_inputs(entry, output)


def main(argv):
    if len(argv) != 6:
        print("usage: pqhd.py <mnemonic> <passphrase> <coin_type> <scheme> <account> <index>",
              file=sys.stderr)
        return 2
    phrase, passphrase = argv[0], argv[1]
    coin_type, scheme_index, account, index = (int(x) for x in argv[2:])
    seed = bip39_seed(phrase, passphrase)
    entry, _, output, inputs = derive(seed, coin_type, scheme_index, account, index)
    print(f"scheme: {entry['index']} {entry['name']}")
    print("path:   m/" + "/".join(f"{e}'" for e in path(coin_type, scheme_index, account, index)))
    print(f"output: {output.hex()}")
    for name, value in inputs:
        print(f"  {name}: {value.hex()}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
