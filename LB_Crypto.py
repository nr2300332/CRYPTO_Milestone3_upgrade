"""Shared helpers for the Legacy Bank Milestone 3 tunnel (Client.py and Server.py).

- length-prefixed framing over TCP
- Diffie-Hellman over RFC 3526 group 14 (2048-bit safe prime, generator 2)
- HKDF-SHA256 session key derivation
- RSA-PSS (SHA-256) signatures
- X.509 checks against the pre-trusted CA root
- AES-256-GCM channel, with direction and sequence number bound as associated data
- signed transaction helper
"""

import datetime
import json
import secrets
import struct

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# RFC 3526 group 14: 2048-bit safe prime, generator 2
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
G = 2
P_BYTES = (P.bit_length() + 7) // 8  # 256 bytes on the wire

MAX_FRAME = 1 << 20
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


# ---------- framing ----------

def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed the connection")
        buf.extend(chunk)
    return bytes(buf)


def send_frame(sock, data):
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_frame(sock):
    (length,) = struct.unpack(">I", _recv_exact(sock, 4))
    if length > MAX_FRAME:
        raise ValueError("frame too large")
    return _recv_exact(sock, length)


def send_json(sock, obj):
    send_frame(sock, json.dumps(obj).encode())


def recv_json(sock):
    return json.loads(recv_frame(sock).decode())


# ---------- Diffie-Hellman ----------

def dh_generate_private():
    return secrets.randbelow(P - 3) + 2  # uniform in [2, P-2]


def dh_public(private):
    return pow(G, private, P)


def check_dh_peer(value):
    if not 2 <= value <= P - 2:
        raise ValueError("DH public value out of range")
    return value


def dh_shared_bytes(peer_public, private):
    return pow(peer_public, private, P).to_bytes(P_BYTES, "big")


def derive_session_key(shared, client_pub, server_pub):
    """32-byte AES-256 key from the DH secret, bound to both public values."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"LegacyBank-M3-session|" + client_pub + server_pub,
    ).derive(shared)


# ---------- RSA-PSS signatures ----------

def rsa_sign(private_key, data):
    return private_key.sign(data, PSS, hashes.SHA256())


def rsa_verify(public_key, signature, data):
    try:
        public_key.verify(signature, data, PSS, hashes.SHA256())
        return True
    except InvalidSignature:
        return False


# ---------- certificates ----------

def load_certificate(pem):
    return x509.load_pem_x509_certificate(pem)


def verify_server_certificate(cert, root_cert):
    """Raise ValueError unless cert is a current RSA certificate issued directly by root_cert."""
    try:
        cert.verify_directly_issued_by(root_cert)
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise ValueError("certificate is not issued by the trusted CA root") from exc
    now = datetime.datetime.now(datetime.timezone.utc)
    if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
        raise ValueError("certificate is outside its validity period")
    if not isinstance(cert.public_key(), rsa.RSAPublicKey):
        raise ValueError("server certificate does not hold an RSA key")


# ---------- AES-256-GCM channel ----------

class SecureChannel:
    """Each message gets a fresh random 96-bit nonce.

    The direction label and a per-direction sequence number are passed as associated data,
    so a modified, dropped, reordered or replayed frame fails the GCM check.
    """

    def __init__(self, sock, key, send_label, recv_label):
        self.sock = sock
        self.aead = AESGCM(key)
        self.send_label = send_label
        self.recv_label = recv_label
        self.send_seq = 0
        self.recv_seq = 0

    def send(self, plaintext):
        nonce = secrets.token_bytes(12)
        aad = self.send_label + struct.pack(">Q", self.send_seq)
        ciphertext = self.aead.encrypt(nonce, plaintext, aad)
        self.send_seq += 1
        send_frame(self.sock, nonce + ciphertext)

    def recv(self):
        frame = recv_frame(self.sock)
        if len(frame) < 12 + 16:
            raise ValueError("encrypted frame too short")
        nonce, ciphertext = frame[:12], frame[12:]
        aad = self.recv_label + struct.pack(">Q", self.recv_seq)
        plaintext = self.aead.decrypt(nonce, ciphertext, aad)  # raises InvalidTag if altered
        self.recv_seq += 1
        return plaintext


# ---------- transactions ----------

def sign_transaction(private_key, payload):
    """Serialize the payload once and sign those exact bytes, so both sides hash the same text."""
    payload_text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    signature = rsa_sign(private_key, payload_text.encode())
    return {"type": "transaction", "payload": payload_text, "sig": signature.hex()}
