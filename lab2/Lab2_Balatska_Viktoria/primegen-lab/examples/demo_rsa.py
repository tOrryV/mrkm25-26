from primegen.primes import generate_prime

if __name__ == "__main__":
    bits = 1024
    err = 128
    p = generate_prime(bits, err)
    q = generate_prime(bits, err)
    n = p*q
    print(f"p bits={p.bit_length()}\nq bits={q.bit_length()}\nn bits={n.bit_length()}")
