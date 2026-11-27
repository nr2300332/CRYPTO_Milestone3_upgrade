"""Legacy Bank Milestone 3 client.

Verifies the server's certificate and DH signature BEFORE it derives the session key,
then sends RSA-signed transactions over the AES-256-GCM channel.

Run (after make_pki.py and with Server.py running):  python Client.py

Options used by the attack tests:
  --port N           connect to N instead of 5000 (use 5100 through MITM_Proxy.py)
  --count N          send N transactions
  --replay           resend the same signed transaction
  --forge            sign with a key the server does not trust
"""

import argparse
import json
import secrets
import socket
import time
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import LB_Crypto as lb

HOST = "127.0.0.1"
PKI_DIR = Path("pki")


def load_private_key(path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def run(args):
    root_cert = lb.load_certificate((PKI_DIR / "ca_root.pem").read_bytes())
    signing_key = load_private_key(PKI_DIR / f"{args.client_id}_key.pem")
    if args.forge:
        signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        print("[client] --forge: signing with a key the server does not trust")

    with socket.create_connection((HOST, args.port)) as sock:
        hello = lb.recv_json(sock)
        if hello.get("type") != "server_hello":
            raise ValueError("expected server_hello")

        # 1. Verify the server BEFORE any session secret is chosen or derived.
        server_cert = lb.load_certificate(hello["cert"].encode())
        try:
            lb.verify_server_certificate(server_cert, root_cert)
        except ValueError as exc:
            print(f"[client] ABORT: {exc}")
            return
        server_pub = bytes.fromhex(hello["B"])
        if len(server_pub) != lb.P_BYTES or not lb.rsa_verify(
                server_cert.public_key(), bytes.fromhex(hello["sig"]), server_pub):
            print("[client] ABORT: signature on the server's DH value is invalid (possible MITM)")
            return
        B = lb.check_dh_peer(int.from_bytes(server_pub, "big"))
        print("[client] server certificate chain and DH signature verified")

        # 2. Fresh ephemeral secret and session key.
        a = lb.dh_generate_private()
        client_pub = lb.dh_public(a).to_bytes(lb.P_BYTES, "big")
        lb.send_json(sock, {"type": "client_hello", "A": client_pub.hex()})
        key = lb.derive_session_key(lb.dh_shared_bytes(B, a), client_pub, server_pub)
        channel = lb.SecureChannel(sock, key, send_label=b"C2S", recv_label=b"S2C")
        print("[client] AES-256-GCM session established")

        # 3. Signed transactions.
        message = None
        for i in range(args.count):
            if message is None or not args.replay:
                payload = {
                    "sender": args.client_id,
                    "from_account": args.from_account,
                    "to_account": args.to_account,
                    "amount": args.amount,
                    "currency": args.currency,
                    "timestamp": int(time.time()),
                    "nonce": secrets.token_hex(16),
                }
                message = lb.sign_transaction(signing_key, payload)
            channel.send(json.dumps(message).encode())
            reply = json.loads(channel.recv().decode())
            print(f"[client] transaction {i + 1} reply: {reply}")


def main():
    parser = argparse.ArgumentParser(description="Legacy Bank Milestone 3 client")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--client-id", default="client-01")
    parser.add_argument("--from-account", default="1001")
    parser.add_argument("--to-account", default="4455")
    parser.add_argument("--amount", default="1500.00")
    parser.add_argument("--currency", default="EGP")
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--replay", action="store_true")
    parser.add_argument("--forge", action="store_true")
    args = parser.parse_args()
    try:
        run(args)
    except (ConnectionError, InvalidTag, ValueError) as exc:
        print(f"[client] session ended: {exc}")


if __name__ == "__main__":
    main()
