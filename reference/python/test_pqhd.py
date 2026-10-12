"""Tests for the pqhd reference implementation, registry, and test vectors.

    python3 -m unittest test_pqhd     (from reference/python)
"""

import hashlib
import json
import os
import unittest

import gen_vectors
import pqhd

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

ABANDON_ART = gen_vectors.MNEMONICS[0][0]


def xprv_decode(xprv):
    """Base58Check-decode a BIP-32 xprv into (private key int, chain code)."""
    n = 0
    for ch in xprv:
        n = n * 58 + B58.index(ch)
    raw = n.to_bytes(82, "big")
    payload, checksum = raw[:-4], raw[-4:]
    assert hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == checksum
    return int.from_bytes(payload[46:78], "big"), payload[13:45]


class Bip85(unittest.TestCase):
    """Vectors from the BIP-85 specification."""

    XPRV = ("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdq"
            "tQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb")

    def test_derived_entropy(self):
        k, c = xprv_decode(self.XPRV)
        for element in (83696968, 0, 0):
            k, c = pqhd._hardened_child(k, c, element)
        self.assertEqual(
            k.to_bytes(32, "big").hex(),
            "cca20ccb0e9a90feb0912870c3323b24874b0ca3d8018c4b96d0b97c0e82ded0")
        entropy = pqhd.hmac.new(b"bip-entropy-from-k", k.to_bytes(32, "big"),
                                pqhd.hashlib.sha512).digest()
        self.assertEqual(
            entropy.hex(),
            "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f0"
            "0b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7")

    def test_drng(self):
        entropy = bytes.fromhex(
            "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f0"
            "0b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7")
        self.assertEqual(
            pqhd.drng(entropy, 80).hex(),
            "b78b1ee6b345eae6836c2d53d33c64cdaf9a696487be81b03e822dc84b3f1cd8"
            "83d7559e53d175f243e4c349e822a957bbff9224bc5dde9492ef54e8a439f6bc"
            "8c7355b87a925a37ee405a7502991111")


class ProjectEleven(unittest.TestCase):
    """Cross-check BIP-39/32/85 against seeds generated independently with
    @scure/bip39, @scure/bip32 and @noble/hashes at Project Eleven's paths,
    which truncate the BIP-85 entropy instead of using the DRNG."""

    def test_seed_and_entropy(self):
        seed = pqhd.bip39_seed(ABANDON_ART)
        self.assertEqual(
            seed.hex(),
            "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf70"
            "5489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840")
        cases = {
            0: "e727e39395418f1af9ba73362ea790007d9f95512e8b28ace7f447240ccc313c",
            2: "7e76dfee07ba669b21ab0afc238896714463b45273b3d8ef8ebbba678814c454"
               "f51157f51515d2df8b111290b776d662",
        }
        for alg, expected in cases.items():
            entropy = pqhd.bip85_entropy(seed, [83696968, 503131, alg])
            self.assertEqual(entropy[:len(expected) // 2].hex(), expected)


class Mnemonics(unittest.TestCase):
    def test_rejects_short_mnemonic(self):
        short = " ".join(["abandon"] * 11 + ["about"])
        with self.assertRaises(pqhd.DerivationError):
            pqhd.bip39_seed(short)

    def test_rejects_bad_checksum(self):
        with self.assertRaises(pqhd.DerivationError):
            pqhd.bip39_seed(" ".join(["abandon"] * 24))

    def test_rejects_unknown_word(self):
        with self.assertRaises(pqhd.DerivationError):
            pqhd.bip39_seed(ABANDON_ART.replace("art", "notaword"))

    def test_normalization(self):
        phrase, _ = gen_vectors.MNEMONICS[2]
        spaced = "  " + phrase.replace(" ", " \t ") + "\n"
        self.assertEqual(pqhd.bip39_seed(spaced, "café"),
                         pqhd.bip39_seed(phrase, "café"))

    def test_rejects_unhardenable_path(self):
        seed = pqhd.bip39_seed(ABANDON_ART)
        for scope in [(2**31, 0, 0, 0), (0, 2**31, 0, 0), (0, 0, 2**31, 0), (0, 0, 0, 2**31)]:
            with self.assertRaisesRegex(pqhd.DerivationError, "not below 2"):
                pqhd.bip85_entropy(seed, pqhd.path(*scope))


class Registry(unittest.TestCase):
    def setUp(self):
        self.registry = pqhd.load_registry()
        self.entries = self.registry["entries"]

    def test_indices_are_sorted_and_unique(self):
        indices = [e["index"] for e in self.entries]
        self.assertEqual(indices, sorted(set(indices)))

    def test_entries_are_in_their_family_block(self):
        size = self.registry["block_size"]
        blocks = {f["name"]: f["block"] for f in self.registry["families"]}
        self.assertEqual(len(set(blocks.values())), len(blocks))
        self.assertNotIn(0, blocks.values())
        for name, block in blocks.items():
            indices = [e["index"] for e in self.entries if e["family"] == name]
            # Contiguous from the block start, so no index is skipped or left ambiguous.
            self.assertEqual(indices, list(range(block * size, block * size + len(indices))))
            self.assertLessEqual(len(indices), size)

    def test_oids_are_unique(self):
        oids = [e["oid"] for e in self.entries if "oid" in e]
        self.assertEqual(len(oids), len(set(oids)))

    def test_app_number(self):
        self.assertEqual(self.registry["app"], pqhd.PQHD_APP)

    def test_names_are_unique(self):
        names = [e["name"] for e in self.entries if "name" in e]
        self.assertEqual(len(names), len(set(names)))

    def test_active_entries_are_complete(self):
        for e in self.entries:
            if e["status"] != "active":
                self.assertIn(e["status"], ("reserved", "deprecated"))
                continue
            e = pqhd.resolve(self.registry, e)
            for field in ("name", "family", "oid", "type", "standard", "security_category",
                          "output_bytes", "keygen", "inputs"):
                self.assertIn(field, e, f"{e['index']} missing {field}")
            self.assertEqual(sum(i["bytes"] for i in e["inputs"]), e["output_bytes"])

    def test_reserved_and_inactive_schemes_cannot_derive(self):
        seed = pqhd.bip39_seed(ABANDON_ART)
        for e in self.entries:
            if e["status"] != "active":
                with self.assertRaises(pqhd.DerivationError):
                    pqhd.derive(seed, 0, e["index"], 0, 0, self.registry)


class Vectors(unittest.TestCase):
    def test_registry_table_is_current(self):
        with open(gen_vectors.TABLE_PATH, encoding="utf-8") as f:
            self.assertEqual(f.read(), gen_vectors.registry_table(pqhd.load_registry()))

    def test_vector_files_match_reference(self):
        registry = pqhd.load_registry()
        active = {e["index"] for e in registry["entries"] if e["status"] == "active"}
        files = {int(f[:-5]) for f in os.listdir(gen_vectors.OUT_DIR) if f.endswith(".json")}
        self.assertEqual(files, active)
        for entry, cases in gen_vectors.cases(registry):
            path = os.path.join(gen_vectors.OUT_DIR, f"{entry['index']}.json")
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
            self.assertEqual(doc["name"], entry["name"])
            self.assertEqual(doc["registry_version"], registry["version"])
            got = [{k: v for k, v in c.items() if k != "public_key_sha256"} for c in doc["cases"]]
            self.assertEqual(got, cases, f"{entry['index']}.json is stale")


if __name__ == "__main__":
    unittest.main()
