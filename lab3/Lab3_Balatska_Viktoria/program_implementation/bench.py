import csv
import statistics as stats
import time
import secrets

from shamir import split_secret, reconstruct_secret
from rsa_tools import generate_rsa_keys, encrypt_share as rsa_encrypt, decrypt_share as rsa_decrypt
from ecc_tools import generate_ecc_keypair, ecies_encrypt, ecies_decrypt


N = 5
T = 3
P = 2**256 - 189
TRIALS = 100


def timeit(fn, *args, **kwargs):
    t0 = time.perf_counter()
    res = fn(*args, **kwargs)
    t1 = time.perf_counter()
    return res, (t1 - t0)


def bench_shamir_once():
    secret = secrets.randbelow(P)
    _, t_split = timeit(split_secret, secret, N, T, P)
    shares = split_secret(secret, N, T, P)
    _, t_recon = timeit(reconstruct_secret, shares[:T], P)
    return t_split, t_recon, secret, shares


def bench_rsa_transport(shares):
    t_keygen = []
    rsa_keys = []
    for _ in range(N):
        (priv, pub), dt = timeit(generate_rsa_keys)
        rsa_keys.append((priv, pub))
        t_keygen.append(dt)

    enc_times, dec_times, sizes = [], [], []
    ciphertexts = []

    for i in range(N):
        payload = str(shares[i][1]).encode()
        ct, dt = timeit(rsa_encrypt, rsa_keys[i][1], payload)
        enc_times.append(dt)
        ciphertexts.append(ct)
        sizes.append(len(ct))

    for i in range(T):
        payload, dt = timeit(rsa_decrypt, rsa_keys[i][0], ciphertexts[i])
        dec_times.append(dt)
        if int(payload.decode()) != shares[i][1]:
            raise RuntimeError("RSA transport: невідповідність частки після дешифрування")

    return {
        "keygen": t_keygen,
        "enc": enc_times,
        "dec": dec_times,
        "size": sizes
    }


def bench_ecc_transport(shares):
    t_keygen = []
    ecc_keys = []
    for _ in range(N):
        (priv, pub), dt = timeit(generate_ecc_keypair)
        ecc_keys.append((priv, pub))
        t_keygen.append(dt)

    enc_times, dec_times, sizes = [], [], []
    ciphertexts = []

    for i in range(N):
        payload = str(shares[i][1]).encode()
        ct, dt = timeit(ecies_encrypt, ecc_keys[i][1], payload)
        enc_times.append(dt)
        ciphertexts.append(ct)
        sizes.append(len(ct))

    for i in range(T):
        payload, dt = timeit(ecies_decrypt, ecc_keys[i][0], ciphertexts[i])
        dec_times.append(dt)
        if int(payload.decode()) != shares[i][1]:
            raise RuntimeError("ECC transport: невідповідність частки після дешифрування")

    return {
        "keygen": t_keygen,
        "enc": enc_times,
        "dec": dec_times,
        "size": sizes
    }


def summarize(name, t_keygen, t_enc, t_dec, sizes, t_split_list, t_recon_list):
    def m(x): return stats.mean(x) if x else 0.0
    def sd(x): return stats.pstdev(x) if x else 0.0

    summary = {
        "scheme": name,
        "keygen_mean_ms": m(t_keygen) * 1000,
        "keygen_sd_ms": sd(t_keygen) * 1000,

        "enc_mean_ms": m(t_enc) * 1000,
        "enc_sd_ms": sd(t_enc) * 1000,

        "dec_mean_ms": m(t_dec) * 1000,
        "dec_sd_ms": sd(t_dec) * 1000,

        "cipher_len_mean_B": m(sizes),
        "cipher_len_sd_B": sd(sizes),

        "shamir_split_mean_ms": m(t_split_list) * 1000,
        "shamir_recon_mean_ms": m(t_recon_list) * 1000,
    }
    return summary


def main():
    shamir_split_times = []
    shamir_recon_times = []

    rsa_keygen_times = []
    rsa_enc_times = []
    rsa_dec_times = []
    rsa_sizes = []

    ecc_keygen_times = []
    ecc_enc_times = []
    ecc_dec_times = []
    ecc_sizes = []

    for _ in range(TRIALS):
        t_split, t_recon, secret, shares = bench_shamir_once()
        shamir_split_times.append(t_split)
        shamir_recon_times.append(t_recon)

        rsa_stats = bench_rsa_transport(shares)
        ecc_stats = bench_ecc_transport(shares)

        rsa_keygen_times.extend(rsa_stats["keygen"])
        rsa_enc_times.extend(rsa_stats["enc"])
        rsa_dec_times.extend(rsa_stats["dec"])
        rsa_sizes.extend(rsa_stats["size"])

        ecc_keygen_times.extend(ecc_stats["keygen"])
        ecc_enc_times.extend(ecc_stats["enc"])
        ecc_dec_times.extend(ecc_stats["dec"])
        ecc_sizes.extend(ecc_stats["size"])

    rsa_summary = summarize(
        "RSA-OAEP",
        rsa_keygen_times, rsa_enc_times, rsa_dec_times, rsa_sizes,
        shamir_split_times, shamir_recon_times
    )
    ecc_summary = summarize(
        "ECIES (ECC)",
        ecc_keygen_times, ecc_enc_times, ecc_dec_times, ecc_sizes,
        shamir_split_times, shamir_recon_times
    )

    def line(s): print("-" * s)
    line(72)
    print("{:<14} {:>12} {:>12} {:>12} {:>12} {:>12}".format(
        "Схема", "KeyGen(ms)", "Enc(ms)", "Dec(ms)", "Cipher(B)", "ShamirSplit(ms)"
    ))
    line(72)

    for summ in [rsa_summary, ecc_summary]:
        print("{:<14} {:>12.3f} {:>12.3f} {:>12.3f} {:>12.1f} {:>12.3f}".format(
            summ["scheme"],
            summ["keygen_mean_ms"],
            summ["enc_mean_ms"],
            summ["dec_mean_ms"],
            summ["cipher_len_mean_B"],
            summ["shamir_split_mean_ms"],
        ))
    line(72)
    print("Shamir Reconstruct (mean): {:.3f} ms".format(
        stats.mean(shamir_recon_times) * 1000
    ))

    with open("results.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "scheme",
                "keygen_mean_ms", "keygen_sd_ms",
                "enc_mean_ms", "enc_sd_ms",
                "dec_mean_ms", "dec_sd_ms",
                "cipher_len_mean_B", "cipher_len_sd_B",
                "shamir_split_mean_ms", "shamir_recon_mean_ms",
            ],
        )
        writer.writeheader()
        writer.writerow(rsa_summary)
        writer.writerow(ecc_summary)


if __name__ == "__main__":
    main()
