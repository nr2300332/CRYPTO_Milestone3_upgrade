"""Legacy Bank Milestone 3 attack lab: an active man-in-the-middle between Client.py and Server.py.

Modes
  none       relay everything unchanged (control test)
  swap-dh    replace the server's DH value B with the attacker's own g^m mod p, keeping the
             server's original signature
  fake-cert  present a self-signed certificate and sign the DH value with its own key
  flip-bit   flip one bit in the client's first encrypted frame (the AES-GCM tag must fail)

Usage (Server.py running in another terminal):
  python MITM_Proxy.py --mode swap-dh
  python Client.py --port 5100
"""

import argparse
import socket
import threading

from cryptography.hazmat.primitives import serialization

import LB_Crypto as lb
from make_pki import build_cert, name, new_rsa_key

SERVER_PORT = 5000


def swap_dh(hello):
    m = lb.dh_generate_private()
    fake_b = lb.dh_public(m).to_bytes(lb.P_BYTES, "big")
    print("[mitm] replaced B with the attacker's g^m mod p; kept the server's original signature")
    return {**hello, "B": fake_b.hex()}


def fake_cert(hello):
    attacker_key = new_rsa_key()
    fake = build_cert(name("legacy-bank-server"), attacker_key.public_key(),
                      name("legacy-bank-server"), attacker_key, is_ca=False, san="localhost")
    m = lb.dh_generate_private()
    fake_b = lb.dh_public(m).to_bytes(lb.P_BYTES, "big")
    print("[mitm] presented a self-signed certificate and signed the DH value with its own key")
    return {
        "type": "server_hello",
        "cert": fake.public_bytes(serialization.Encoding.PEM).decode(),
        "B": fake_b.hex(),
        "sig": lb.rsa_sign(attacker_key, fake_b).hex(),
    }


def flip_first_encrypted_bit(frame, index):
    if index == 0:
        frame = frame[:-1] + bytes([frame[-1] ^ 0x01])
        print("[mitm] flipped one bit in the client's first encrypted frame")
    return frame


def pump(src, dst, transform=None):
    index = 0
    try:
        while True:
            frame = lb.recv_frame(src)
            if transform:
                frame = transform(frame, index)
            lb.send_frame(dst, frame)
            index += 1
    except (ConnectionError, OSError, ValueError):
        pass


def handle(client_sock, args):
    with client_sock:
        try:
            with socket.create_connection((args.server_host, SERVER_PORT)) as server_sock:
                hello = lb.recv_json(server_sock)
                if args.mode == "swap-dh":
                    hello = swap_dh(hello)
                elif args.mode == "fake-cert":
                    hello = fake_cert(hello)
                lb.send_json(client_sock, hello)

                # Relay the client's DH value unchanged, then relay the session both ways.
                lb.send_frame(server_sock, lb.recv_frame(client_sock))
                threading.Thread(target=pump, args=(server_sock, client_sock), daemon=True).start()
                transform = flip_first_encrypted_bit if args.mode == "flip-bit" else None
                pump(client_sock, server_sock, transform)
        except (ConnectionError, OSError, ValueError) as exc:
            print(f"[mitm] session ended: {exc}")


def main():
    parser = argparse.ArgumentParser(description="Legacy Bank Milestone 3 MITM lab")
    parser.add_argument("--mode", choices=["none", "swap-dh", "fake-cert", "flip-bit"], default="none")
    parser.add_argument("--listen-port", type=int, default=5100)
    parser.add_argument("--server-host", default="127.0.0.1")
    args = parser.parse_args()
    with socket.create_server(("127.0.0.1", args.listen_port)) as listener:
        print(f"[mitm] mode={args.mode}; listening on {args.listen_port}, forwarding to {SERVER_PORT}")
        while True:
            conn, _ = listener.accept()
            threading.Thread(target=handle, args=(conn, args), daemon=True).start()


if __name__ == "__main__":
    main()
