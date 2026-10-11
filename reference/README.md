# Reference implementations

One directory per language.

| Directory | Notes |
|-----------|-------|
| [`python/`](python/) | Standard library only. Derives key-generation inputs, generates `test-vectors/` and the registry table, and tests both. Not for production use. |

```sh
cd python
python3 -m unittest test_pqhd
python3 pqhd.py "<24 words>" "" 133 0 0 0   # mnemonic, passphrase, coin_type, scheme, account, index
```

`python/english.txt` is the BIP-39 English wordlist from
[bitcoin/bips](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt)
(SHA-256 `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`),
published with BIP-39 under the MIT license.
