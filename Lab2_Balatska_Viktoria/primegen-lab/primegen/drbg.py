import hmac, hashlib, os

class HMAC_DRBG:
    """Small educational HMAC-DRBG (SP 800-90A style, simplified).
    Not for production use. Good enough for lab/demo.
    """
    def __init__(self, seed: bytes, hash_fn=hashlib.sha256):
        self.hash_fn = hash_fn
        self.K = b"\x00" * hash_fn().digest_size
        self.V = b"\x01" * hash_fn().digest_size
        self._update(seed)

    def _hmac(self, key, data): 
        return hmac.new(key, data, self.hash_fn).digest()

    def _update(self, provided_data: bytes | None):
        self.K = self._hmac(self.K, self.V + b"\x00" + (provided_data or b""))
        self.V = self._hmac(self.K, self.V)
        if provided_data:
            self.K = self._hmac(self.K, self.V + b"\x01" + provided_data)
            self.V = self._hmac(self.K, self.V)

    def reseed(self, entropy: bytes): 
        self._update(entropy)

    def random_bytes(self, n: int) -> bytes:
        out = b""
        while len(out) < n:
            self.V = self._hmac(self.K, self.V)
            out += self.V
        return out[:n]

def new_drbg():
    seed = os.urandom(48)
    return HMAC_DRBG(seed)
