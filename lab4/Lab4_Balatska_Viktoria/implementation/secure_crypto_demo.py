import os
from secure_mem import mlock_memory, munlock_memory, secure_zero
from guards import apply_process_guards
from hkdf_stream import encrypt, decrypt
from audit import log_event

def self_test(key):
    print("[+] Running self-test...")
    msg = b"Self-test OK"
    nonce, ct, tag = encrypt(key, msg)
    pt = decrypt(key, nonce, ct, tag)
    assert pt == msg, "Self-test failed"
    print("[+] Self-test passed ✅")


def main():
    apply_process_guards()

    kid = "demo-key-1"
    key = bytearray(os.urandom(32))
    print("[*] 256-bit key generated")

    mlock_memory(key)
    print("[*] Key locked in RAM (mlock)")

    try:
        self_test(key)
        log_event("selftest", kid, "ok")

        message = input("Enter message to encrypt: ").encode()
        nonce, ct, tag = encrypt(key, message)

        print("\n[+] Encrypted data:")
        print("nonce     :", nonce.hex())
        print("ciphertext:", ct.hex())
        print("tag(HMAC) :", tag.hex())
        log_event("encrypt", kid, f"len={len(message)}B")

        recovered = decrypt(key, nonce, ct, tag)
        print("\n[+] Decrypted message:", recovered.decode())
        log_event("decrypt", kid, f"len={len(recovered)}B")

    finally:
        secure_zero(key)
        munlock_memory(key)
        print("\n[*] Key securely wiped and memory unlocked (zeroization + munlock)\n")


if __name__ == "__main__":
    main()
