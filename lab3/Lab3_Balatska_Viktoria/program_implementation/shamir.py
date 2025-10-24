import secrets


def generate_polynomial(secret, t, p):
    coeffs = [secret] + [secrets.randbelow(p) for _ in range(t - 1)]
    return coeffs


def evaluate_polynomial(coeffs, x, p):
    y = 0
    for power, coeff in enumerate(coeffs):
        y = (y + coeff * pow(x, power, p)) % p
    return y


def split_secret(secret, n, t, p):
    coeffs = generate_polynomial(secret, t, p)
    shares = [(i, evaluate_polynomial(coeffs, i, p)) for i in range(1, n+1)]
    return shares


def reconstruct_secret(shares, p):
    secret = 0
    for i, (xi, yi) in enumerate(shares):
        li = 1
        for j, (xj, yj) in enumerate(shares):
            if i != j:
                li = (li * (-xj) * pow(xi - xj, -1, p)) % p
        secret = (secret + yi * li) % p
    return secret
