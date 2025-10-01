from __future__ import annotations
import secrets
from .drbg import HMAC_DRBG

def int_from_bytes(b: bytes) -> int: 
    return int.from_bytes(b, "big")


def random_bits(bits: int) -> int:
    nbytes = (bits + 7) // 8
    x = int_from_bytes(secrets.token_bytes(nbytes))
    x |= 1 << (bits - 1)  # ensure top bit set
    x |= 1                # make odd
    return x


def small_primes(limit=10000):
    sieve = bytearray(b"\x01")*(limit+1)
    sieve[0:2] = b"\x00\x00"
    for p in range(2, int(limit**0.5)+1):
        if sieve[p]:
            step = p
            start = p*p
            sieve[start:limit+1:step] = b"\x00"*(((limit - start)//step)+1)
    return [i for i, v in enumerate(sieve) if v]


SMALL_PRIMES = small_primes(10000)


def trial_division_pass(n: int) -> bool:
    for p in SMALL_PRIMES:
        if p*p > n:
            break
        if n % p == 0:
            return n == p
    return True


def is_probable_prime_mr(n: int, k: int) -> bool:
    if n < 2:
        return False
    for p in (2,3,5,7,11,13,17,19,23,29,31,37):
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = secrets.randbelow(n-3) + 2  # in [2, n-2]
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            continue
        for __ in range(s-1):
            x = pow(x, 2, n)
            if x == n-1:
                break
        else:
            return False
    return True


def is_probable_prime_mr_bases(n: int, bases: list[int]) -> bool:
    if n < 2:
        return False
    for p in (2,3,5,7,11,13,17,19,23,29,31,37):
        if n % p == 0:
            return n == p

    # n-1 = 2^s * d
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for a in bases:
        a %= n
        if a < 2:
            a += 2
        if a >= n - 2:
            a = (a % (n-3)) + 2
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            continue
        for _ in range(s-1):
            x = pow(x, 2, n)
            if x == n-1:
                break
        else:
            return False
    return True


def generate_prime_deterministic(bits: int, bases: list[int], seed: bytes) -> int:
    """
    Генерує просте детерміновано: кандидати з HMAC-DRBG(seed),
    перевірка простоти з фіксованими базами MR.
    """
    drbg = HMAC_DRBG(seed)
    nbytes = (bits + 7)//8
    while True:
        x = int.from_bytes(drbg.random_bytes(nbytes), "big")
        x |= 1 << (bits - 1)
        x |= 1
        if trial_division_pass(x) and is_probable_prime_mr_bases(x, bases):
            return x


def jacobi(a, n):
    a %= n; result = 1
    while a:
        while a % 2 == 0:
            a //= 2
            if n % 8 in (3,5):
                result = -result
        a, n = n, a
        if a % 4 == 3 and n % 4 == 3:
            result = -result
        a %= n
    return result if n == 1 else 0


def is_probable_prime_ss(n: int, k: int) -> bool:
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    for _ in range(k):
        a = secrets.randbelow(n-3) + 2
        j = jacobi(a, n)
        if j == 0:
            return False
        if pow(a, (n-1)//2, n) != (j % n):
            return False
    return True


def rounds_for_bits(bits: int, target_error_bits: int = 128) -> int:
    k = (target_error_bits + 1)//2
    base = 7 if bits <= 1024 else (10 if bits <= 2048 else 12)
    return max(base, k)


def generate_prime(bits: int, target_error_bits: int = 128) -> int:
    k = rounds_for_bits(bits, target_error_bits)
    while True:
        n = random_bits(bits)
        if not trial_division_pass(n):
            continue
        if is_probable_prime_mr(n, k):
            return n


def generate_safe_prime(bits: int, target_error_bits: int = 128) -> int:

    q_bits = bits - 1
    while True:
        q = generate_prime(q_bits, target_error_bits)
        p = 2 * q + 1
        if is_probable_prime_mr(p, rounds_for_bits(bits, target_error_bits)):
            return p
