"""Milestone 3 evidence: why ECB leaks patterns and AES-GCM does not.

Encrypts eight identical 16-byte blocks with AES-256 in ECB mode and in GCM mode,
then counts repeated ciphertext blocks.

Run:  python ECB_vs_GCM_Demo.py
"""

import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BLOCK_SIZE = 16
TAG_SIZE = 16

block = b"Transfer 1500 EG"
assert len(block) == BLOCK_SIZE
plaintext = block * 8
key = os.urandom(32)


def split(data):
    return [data[i:i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]


def repeated_blocks(data):
    blocks = split(data)
    return len(blocks) - len(set(blocks))


encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
ecb_ciphertext = encryptor.update(plaintext) + encryptor.finalize()

gcm_output = AESGCM(key).encrypt(os.urandom(12), plaintext, None)
gcm_ciphertext = gcm_output[:-TAG_SIZE]  # drop the tag, compare only the encrypted blocks

print("Plaintext: 8 identical 16-byte blocks")
print(f"AES-256-ECB: {len(split(ecb_ciphertext))} blocks, repeated blocks = {repeated_blocks(ecb_ciphertext)}")
print(f"AES-256-GCM: {len(split(gcm_ciphertext))} blocks, repeated blocks = {repeated_blocks(gcm_ciphertext)}")
