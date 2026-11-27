# Legacy Bank: Milestone 3

Milestone 2 (DES-ECB, static key, no sender checks) is upgraded to:

- **Signed Diffie-Hellman handshake.** The server signs its DH value with its RSA key. The client verifies the certificate against the pre-trusted CA root before deriving any key.
- **AES-256-GCM** replaces DES-ECB. Each message has a random nonce, and the authentication tag rejects any change.
- **Ephemeral DH per session.** Fresh secrets are generated each session and discarded, which gives perfect forward secrecy.
- **RSA-PSS signature on every transaction**, checked against `server_truststore/` before the server processes it.

`Client.py` and `Server.py` are the Milestone 2 files, upgraded in place. `DES.py` is no longer imported and is left in the repo.

## Files

| File | Purpose |
|------|---------|
| `LB_Crypto.py` | Framing, DH, HKDF, RSA-PSS, certificate checks, AES-GCM channel |
| `make_pki.py` | Creates the CA root, server certificate and client-01 key pair (run once) |
| `Server.py` | Signed handshake, then verifies each transaction |
| `Client.py` | Verifies the server, derives the key, sends signed transactions |
| `MITM_Proxy.py` | Attack lab: `none`, `swap-dh`, `fake-cert`, `flip-bit` modes |
| `ECB_vs_GCM_Demo.py` | Shows repeated ciphertext blocks under ECB and GCM |
| `requirements.txt` | `cryptography>=42` |

## Setup

Run everything from the repo root, the folder that contains `Client.py` and `Server.py`.

```
pip install -r requirements.txt
python make_pki.py
```

## Normal run (two terminals)

```
python Server.py
python Client.py --count 2
```

Expected: the client prints "server certificate chain and DH signature verified", then both transactions are accepted. Each accepted transaction is appended to `transactions.log`.

## Attack tests

Start `Server.py` first. Then run the proxy in one terminal and the client, pointed at port 5100, in another.

| Test | Commands | Expected result |
|------|----------|-----------------|
| Control through proxy | `python MITM_Proxy.py --mode none` then `python Client.py --port 5100` | Accepted |
| MITM on DH | `python MITM_Proxy.py --mode swap-dh` then `python Client.py --port 5100` | Client aborts: DH signature invalid |
| Fake certificate | `python MITM_Proxy.py --mode fake-cert` then `python Client.py --port 5100` | Client aborts: not issued by the trusted CA root |
| Tampered ciphertext | `python MITM_Proxy.py --mode flip-bit` then `python Client.py --port 5100` | Server logs an AES-GCM authentication failure |
| Forged transaction | `python Client.py --forge` | Rejected: signature does not match |
| Replayed transaction | `python Client.py --count 2 --replay` | Second reply rejected: replayed transaction |
| ECB vs GCM | `python ECB_vs_GCM_Demo.py` | ECB: 7 repeated blocks. GCM: 0 |

## Notes

- `pki/` holds private keys in unencrypted form. This is acceptable for coursework only. Do not commit those keys to a shared repository. The included `.gitignore` excludes them.
- The Milestone 3 handshake creates one session key per connection. Keys are not rotated during a long session. Milestone 4, Task 4.2 covers this.
- The replay cache is held in memory and resets when the server restarts.
