# pqhd

Post-quantum HD wallets: a standard for deriving post-quantum keys from a BIP-39 seed phrase, and a registry of the schemes it covers.

One seed phrase should be able to back up keys for any post-quantum scheme, on any chain, without those keys sharing secrets with each other or with existing elliptic-curve keys.

## Derivation path

```
m/83696968'/<app>'/<coin_type>'/<scheme>'/<account>'/<index>'
```

| Level | Meaning |
|---|---|
| `83696968'` | BIP-85 purpose |
| `<app>'` | BIP-85 application number for this standard |
| `<coin_type>'` | Chain, from SLIP-44 |
| `<scheme>'` | Post-quantum scheme and parameter set, from this registry |
| `<account>'` | Account, as in BIP-44 |
| `<index>'` | Key index, as in BIP-44 |

Every level is hardened. The derived node is turned into key-generation input as defined in the spec.

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

Open a pull request adding an entry to `registry/registry.json` with test vectors in `test-vectors/`.
