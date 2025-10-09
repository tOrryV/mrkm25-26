import argparse, time
import base64
from math import gcd

from .primes import (
    generate_prime, is_probable_prime_mr, rounds_for_bits,
    generate_safe_prime,
)


def cmd_genprime(args):
    t0 = time.time()
    p = generate_prime(args.bits, args.err)
    dt = time.time() - t0
    k = rounds_for_bits(args.bits, args.err)
    print(f"Prime ({args.bits} bits) found in {dt:.2f}s with MR rounds={k}:\n{p}\n")
    print(f"Check: bit_length={p.bit_length()}  MR({k})={is_probable_prime_mr(p, k)}")


def cmd_rsa_demo(args):
    t0 = time.time()
    p = generate_prime(args.bits, args.err)
    q = generate_prime(args.bits, args.err)
    n = p * q
    dt = time.time() - t0
    print(f"RSA demo: bits={args.bits}, err={args.err}")
    print(f"p bits={p.bit_length()}\nq bits={q.bit_length()}\nn bits={n.bit_length()}\nTime: {dt:.2f}s")


def cmd_safeprime(args):
    p = generate_safe_prime(args.bits, args.err)
    k = rounds_for_bits(args.bits, args.err)
    print(f"✅ safe prime p=2q+1 (bits={p.bit_length()}), MR rounds={k}\n{p}")


def _egcd(a, b):
    if b == 0:
        return (1, 0, a)
    x1, y1, g = _egcd(b, a % b)
    return (y1, x1 - (a // b) * y1, g)


def _modinv(a, m):
    x, y, g = _egcd(a, m)
    if g != 1:
        raise ValueError("mod inverse does not exist")
    return x % m


def _pem_block(title: str, raw: bytes) -> str:
    b64 = base64.encodebytes(raw).decode("ascii").replace("\n", "")
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {title}-----\n" + "\n".join(lines) + f"\n-----END {title}-----\n"


def cmd_keygen(args):
    p = generate_prime(args.bits, args.err)
    q = generate_prime(args.bits, args.err)
    while p == q:
        q = generate_prime(args.bits, args.err)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    while gcd(e, phi) != 1:
        e += 2
    d = _modinv(e, phi)

    pub = f"n={n}\ne={e}\n".encode()
    prv = f"n={n}\nd={d}\np={p}\nq={q}\n".encode()

    print(_pem_block("RSA PUBLIC KEY (LAB)", pub))
    print(_pem_block("RSA PRIVATE KEY (LAB)", prv))
    print(f"# bits: n={n.bit_length()}  p={p.bit_length()}  q={q.bit_length()}")


def cmd_bench(args):
    t0 = time.time()
    for _ in range(args.count):
        _ = generate_prime(args.bits, args.err)
    dt = time.time() - t0
    print(f"Generated {args.count} primes of {args.bits} bits in {dt:.2f}s  -> {dt/args.count:.2f}s/prime")


def main():
    ap = argparse.ArgumentParser(prog="primegen", description="Educational prime generator (Miller–Rabin)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ap_gen = sub.add_parser("genprime", help="Generate a probable prime")
    ap_gen.add_argument("--bits", type=int, default=1024, help="Bit length of prime (default: 1024)")
    ap_gen.add_argument("--err", type=int, default=128, help="Target error in bits for MR (default: 128)")
    ap_gen.set_defaults(func=cmd_genprime)

    ap_rsa = sub.add_parser("rsa-demo", help="Generate two primes and an RSA modulus")
    ap_rsa.add_argument("--bits", type=int, default=1024, help="Bit length for each prime (default: 1024)")
    ap_rsa.add_argument("--err", type=int, default=128, help="Target error in bits for MR (default: 128)")
    ap_rsa.set_defaults(func=cmd_rsa_demo)

    ap_sp = sub.add_parser("safeprime", help="Generate a safe prime p=2q+1")
    ap_sp.add_argument("--bits", type=int, default=1024)
    ap_sp.add_argument("--err", type=int, default=128)
    ap_sp.set_defaults(func=cmd_safeprime)

    ap_k = sub.add_parser("keygen", help="Generate an RSA keypair (LAB format)")
    ap_k.add_argument("--bits", type=int, default=1024, help="bit length for each prime")
    ap_k.add_argument("--err", type=int, default=128, help="target error (bits) for MR")
    ap_k.set_defaults(func=cmd_keygen)

    ap_b = sub.add_parser("bench", help="Benchmark prime generation")
    ap_b.add_argument("--bits", type=int, default=1024)
    ap_b.add_argument("--err", type=int, default=128)
    ap_b.add_argument("--count", type=int, default=3)
    ap_b.set_defaults(func=cmd_bench)

    args = ap.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
