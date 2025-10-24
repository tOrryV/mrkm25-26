import os
import hmac
import hashlib


def hkdf_extract(salt, ikm):
    if salt is None or len(salt) == 0:
        salt = b"\x00" * hashlib.sha256().digest_size
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, length):
    assert length > 0
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def hkdf(ikm, salt, info, length):
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, length)


def keystream(key, nonce, nbytes):
    out = b""
    counter = 0
    while len(out) < nbytes:
        block = hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:nbytes]


def encrypt(key, plaintext):
    nonce = os.urandom(12)
    ks = keystream(key, nonce, len(plaintext))
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, ks))
    tag = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    return nonce, ciphertext, tag


def decrypt(key, nonce, ciphertext, tag):
    expected = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, tag):
        raise ValueError("Integrity check failed (HMAC mismatch)")
    ks = keystream(key, nonce, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, ks))
