"""Generate test-vectors/<index>.json for every active registry entry.

    python3 gen_vectors.py --inputs > inputs.txt
        Print "<index> <case> <scheme name> <output hex>" lines for an external
        key-generation backend to hash.
    python3 gen_vectors.py [--pk-hashes hashes.txt]
        Write the registry table and vector files. hashes.txt holds
        "<index> <case> <sha256 hex>" lines: SHA-256 of the raw FIPS-encoded
        public key. Without it, existing hashes are kept.
"""

import json
import os
import sys

import pqhd

OUT_DIR = os.path.join(pqhd.HERE, "..", "..", "test-vectors")
TABLE_PATH = os.path.join(pqhd.HERE, "..", "..", "registry", "README.md")

TABLE_HEADER = """# Registry

Generated from [`registry.json`](registry.json) by
`reference/python/gen_vectors.py`; edit the JSON, not this file.

Scheme indices are the `<scheme>'` level of
`m/83696968'/505153'/<coin_type>'/<scheme>'/<account>'/<index>'`. `L` is the
number of bytes read from BIP-85-DRNG-SHAKE256, split into the key-generation
inputs in the order listed. Indices are append-only and never reused.

| Index | Scheme | Standard | Category | Status | `L` | Key generation inputs |
|------:|--------|----------|:--------:|--------|----:|-----------------------|
"""


def registry_table(registry):
    rows = []
    for e in registry["entries"]:
        if e["status"] == "active":
            inputs = " \\|\\| ".join(f"{i['name']} ({i['bytes']})" for i in e["inputs"])
            rows.append(f"| {e['index']} | {e['name']} | {e['standard']} | "
                        f"{e['security_category']} | {e['status']} | {e['output_bytes']} | "
                        f"`{e['keygen']}`: {inputs} |")
        else:
            rows.append(f"| {e['index']} | {e.get('name', '')} | | | {e['status']} | | "
                        f"{e.get('note', '')} |")
    return TABLE_HEADER + "\n".join(rows) + "\n"


MNEMONICS = [
    ("abandon abandon abandon abandon abandon abandon abandon abandon "
     "abandon abandon abandon abandon abandon abandon abandon abandon "
     "abandon abandon abandon abandon abandon abandon abandon art", ""),
    ("abandon amount liar amount expire adjust cage candy arch gather drum bullet "
     "absurd math era live bid rhythm alien crouch range attend journey unaware", "TREZOR"),
    ("abandon amount liar amount expire adjust cage candy arch gather drum bullet "
     "absurd math era live bid rhythm alien crouch range attend journey unaware", "café"),
]

# (coin_type, account, index): Bitcoin defaults, Zcash, and a non-zero account
# and index on Ethereum.
SCOPES = [(0, 0, 0), (133, 0, 0), (60, 1, 7)]


def cases(registry):
    for entry in registry["entries"]:
        if entry["status"] != "active":
            continue
        out = []
        for phrase, passphrase in MNEMONICS:
            seed = pqhd.bip39_seed(phrase, passphrase)
            for coin_type, account, index in SCOPES:
                _, entropy, output, inputs = pqhd.derive(
                    seed, coin_type, entry["index"], account, index, registry)
                elements = pqhd.path(coin_type, entry["index"], account, index)
                out.append({
                    "mnemonic": phrase,
                    "passphrase": passphrase,
                    "seed": seed.hex(),
                    "coin_type": coin_type,
                    "account": account,
                    "index": index,
                    "path": "m/" + "/".join(f"{e}'" for e in elements),
                    "bip85_entropy": entropy.hex(),
                    "output": output.hex(),
                    "inputs": {name: value.hex() for name, value in inputs},
                })
        yield entry, out


def main(argv):
    registry = pqhd.load_registry()
    if argv == ["--inputs"]:
        for entry, out in cases(registry):
            for n, case in enumerate(out):
                print(entry["index"], n, entry["name"], case["output"])
        return 0

    hashes = {}
    if len(argv) == 2 and argv[0] == "--pk-hashes":
        with open(argv[1], encoding="utf-8") as f:
            for line in f:
                index, n, digest = line.split()
                hashes[(int(index), int(n))] = digest
    elif argv:
        print(__doc__, file=sys.stderr)
        return 2

    with open(TABLE_PATH, "w", encoding="utf-8") as f:
        f.write(registry_table(registry))

    for entry, out in cases(registry):
        path = os.path.join(OUT_DIR, f"{entry['index']}.json")
        existing = {}
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                for case in json.load(f)["cases"]:
                    if "public_key_sha256" in case:
                        existing[(case["seed"], case["path"])] = case["public_key_sha256"]
        for n, case in enumerate(out):
            if (entry["index"], n) in hashes:
                case["public_key_sha256"] = hashes[(entry["index"], n)]
            elif (case["seed"], case["path"]) in existing:
                # Keep hashes from an earlier run when none are supplied.
                case["public_key_sha256"] = existing[(case["seed"], case["path"])]
        doc = {
            "scheme": entry["index"],
            "name": entry["name"],
            "registry_version": registry["version"],
            "cases": out,
        }
        with open(path, "w", encoding="utf-8") as f:
            f.write(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
