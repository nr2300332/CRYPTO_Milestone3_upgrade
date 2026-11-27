"""Create the lab PKI for Milestone 3. Run once from inside the Milestone3 folder:

    python make_pki.py

Creates:
  pki/ca_root_key.pem            CA private key (keep offline in a real deployment)
  pki/ca_root.pem                CA root certificate: the client's pre-trusted anchor
  pki/server_key.pem             server private key
  pki/server_cert.pem            server certificate signed by the CA root
  pki/client-01_key.pem          client-01 private key (signs transactions)
  server_truststore/client-01.pem  client-01 public key (the server's truststore)

Running it again replaces every key and certificate.
"""

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

PKI_DIR = Path("pki")
TRUSTSTORE_DIR = Path("server_truststore")
CLIENT_IDS = ["client-01"]


def new_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def build_cert(subject, public_key, issuer, issuer_key, is_ca, san=None, days=365):
    now = datetime.datetime.now(datetime.timezone.utc)
    key_usage = x509.KeyUsage(
        digital_signature=not is_ca,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=is_ca,
        crl_sign=is_ca,
        encipher_only=False,
        decipher_only=False,
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(key_usage, critical=True)
    )
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
    return builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())


def save_private_key(key, path):
    path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))


def main():
    PKI_DIR.mkdir(exist_ok=True)
    TRUSTSTORE_DIR.mkdir(exist_ok=True)

    ca_key = new_rsa_key()
    ca_name = name("Legacy Bank Root CA")
    ca_cert = build_cert(ca_name, ca_key.public_key(), ca_name, ca_key, is_ca=True)

    server_key = new_rsa_key()
    server_cert = build_cert(name("legacy-bank-server"), server_key.public_key(),
                             ca_name, ca_key, is_ca=False, san="localhost")

    save_private_key(ca_key, PKI_DIR / "ca_root_key.pem")
    (PKI_DIR / "ca_root.pem").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    save_private_key(server_key, PKI_DIR / "server_key.pem")
    (PKI_DIR / "server_cert.pem").write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))

    for client_id in CLIENT_IDS:
        client_key = new_rsa_key()
        save_private_key(client_key, PKI_DIR / f"{client_id}_key.pem")
        (TRUSTSTORE_DIR / f"{client_id}.pem").write_bytes(client_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

    print("PKI created in ./pki and ./server_truststore")


if __name__ == "__main__":
    main()
