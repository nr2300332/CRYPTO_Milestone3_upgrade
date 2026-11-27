"""Legacy Bank Milestone 3 server.

- Signed Diffie-Hellman handshake: the server signs its DH value with its RSA key, and the
  client checks the certificate against the CA root first.
- AES-256-GCM encrypted channel (replaces DES-ECB).
- Every transaction must carry an RSA signature from a sender in server_truststore/.

Run (after make_pki.py):  python Server.py
"""

import json
import re
import socket
import threading
import time
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization

import LB_Crypto as lb

HOST = "127.0.0.1"
PORT = 5000
PKI_DIR = Path("pki")
TRUSTSTORE_DIR = Path("server_truststore")
LOG_FILE = Path("transactions.log")

ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
MAX_CLOCK_SKEW_SECONDS = 300


class Server:
    def __init__(self):
        self.server_key = serialization.load_pem_private_key(
            (PKI_DIR / "server_key.pem").read_bytes(), password=None)
        self.server_cert_pem = (PKI_DIR / "server_cert.pem").read_bytes()
        self.seen = set()  # (sender, nonce) pairs already accepted
        self.lock = threading.Lock()

    def handle(self, conn, addr):
        with conn:
            try:
                channel = self.handshake(conn)
                print(f"[server] {addr}: signed DH handshake complete, AES-256-GCM channel up")
                self.serve(channel)
            except InvalidTag:
                print(f"[server] {addr}: AES-GCM authentication failed (tampered frame), closing")
            except ConnectionError as exc:
                print(f"[server] {addr}: connection ended ({exc})")
            except (ValueError, KeyError, TypeError) as exc:
                print(f"[server] {addr}: protocol error ({exc}), closing")

    def handshake(self, conn):
        b = lb.dh_generate_private()
        server_pub = lb.dh_public(b).to_bytes(lb.P_BYTES, "big")
        lb.send_json(conn, {
            "type": "server_hello",
            "cert": self.server_cert_pem.decode(),
            "B": server_pub.hex(),
            "sig": lb.rsa_sign(self.server_key, server_pub).hex(),
        })

        hello = lb.recv_json(conn)
        if hello.get("type") != "client_hello":
            raise ValueError("expected client_hello")
        client_pub = bytes.fromhex(hello["A"])
        if len(client_pub) != lb.P_BYTES:
            raise ValueError("client DH value has the wrong length")
        A = lb.check_dh_peer(int.from_bytes(client_pub, "big"))
        key = lb.derive_session_key(lb.dh_shared_bytes(A, b), client_pub, server_pub)
        return lb.SecureChannel(conn, key, send_label=b"S2C", recv_label=b"C2S")

    def serve(self, channel):
        while True:
            request = json.loads(channel.recv().decode())
            channel.send(json.dumps(self.check_transaction(request)).encode())

    def check_transaction(self, request):
        if request.get("type") != "transaction":
            return {"status": "rejected", "reason": "unknown message type"}

        payload_text = request.get("payload", "")
        try:
            payload = json.loads(payload_text)
            sender = payload["sender"]
            nonce = payload["nonce"]
            timestamp = int(payload["timestamp"])
            signature = bytes.fromhex(request["sig"])
        except (KeyError, TypeError, ValueError):
            return {"status": "rejected", "reason": "malformed transaction"}
        if not isinstance(sender, str) or not ID_PATTERN.match(sender):
            return {"status": "rejected", "reason": "invalid sender id"}
        if not isinstance(nonce, str):
            return {"status": "rejected", "reason": "malformed transaction"}

        key_path = TRUSTSTORE_DIR / f"{sender}.pem"
        if not key_path.exists():
            return {"status": "rejected", "reason": "sender not in truststore"}
        sender_key = serialization.load_pem_public_key(key_path.read_bytes())
        if not lb.rsa_verify(sender_key, signature, payload_text.encode()):
            return {"status": "rejected", "reason": "signature does not match the sender's public key"}
        if abs(int(time.time()) - timestamp) > MAX_CLOCK_SKEW_SECONDS:
            return {"status": "rejected", "reason": "timestamp outside the allowed window"}

        with self.lock:
            if (sender, nonce) in self.seen:
                return {"status": "rejected", "reason": "replayed transaction"}
            self.seen.add((sender, nonce))
            with LOG_FILE.open("a") as log:
                log.write(json.dumps({
                    "received": int(time.time()),
                    "payload": payload_text,
                    "sig": request["sig"],
                }) + "\n")

        print(f"[server] accepted from {sender}: {payload.get('amount')} {payload.get('currency')} "
              f"from {payload.get('from_account')} to {payload.get('to_account')}")
        return {"status": "accepted", "sender": sender, "nonce": nonce}


def main():
    server = Server()
    with socket.create_server((HOST, PORT)) as listener:
        print(f"[server] Milestone 3 server waiting on port {PORT} ...")
        while True:
            conn, addr = listener.accept()
            threading.Thread(target=server.handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
