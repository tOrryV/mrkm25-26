import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_ecc_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def _uncompressed_point_len_bits(curve):
    key_bits = curve.key_size
    coord_len = (key_bits + 7) // 8
    return 1 + 2 * coord_len  # 0x04 + X + Y


def ecies_encrypt(public_key, plaintext):
    curve = public_key.curve
    ephemeral_private = ec.generate_private_key(curve)

    shared_secret = ephemeral_private.exchange(ec.ECDH(), public_key)

    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ecies-demo"
    ).derive(shared_secret)

    aes = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aes.encrypt(nonce, plaintext, None)

    ephemeral_public_bytes = ephemeral_private.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )

    return ephemeral_public_bytes + nonce + ciphertext


def ecies_decrypt(private_key, data):
    curve = private_key.curve
    eph_len = _uncompressed_point_len_bits(curve)

    if len(data) < eph_len + 12 + 1:
        raise ValueError("Incorrect format of ciphertext ECIES")

    ephemeral_pub = data[:eph_len]
    nonce = data[eph_len:eph_len + 12]
    ciphertext = data[eph_len + 12:]

    ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, ephemeral_pub)

    shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public_key)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ecies-demo"
    ).derive(shared_secret)

    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, None)
