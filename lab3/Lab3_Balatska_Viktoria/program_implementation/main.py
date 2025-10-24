from ecc_tools import generate_ecc_keypair, ecies_encrypt, ecies_decrypt
from shamir import split_secret, reconstruct_secret
from rsa_tools import generate_rsa_keys, encrypt_share, decrypt_share
import secrets

n = 5
t = 3
p = 2**256 - 189

secret = secrets.randbelow(p)
print("Original secret:", secret)

shares = split_secret(secret, n, t, p)

keys_rsa = [generate_rsa_keys() for _ in range(n)]
keys_ecc = [generate_ecc_keypair() for _ in range(n)]

encrypted_shares_rsa = [
    encrypt_share(keys_rsa[i][1], str(shares[i][1]).encode())
    for i in range(n)
]

encrypted_shares_ecc = [
    ecies_encrypt(keys_ecc[i][1], str(shares[i][1]).encode())
    for i in range(n)
]

received_shares_rsa = []
for i in range(t):
    decrypted = int(decrypt_share(keys_rsa[i][0], encrypted_shares_rsa[i]).decode())
    received_shares_rsa.append((i+1, decrypted))

received_shares_ecc = []
for i in range(t):
    decrypted = int(ecies_decrypt(keys_ecc[i][0], encrypted_shares_ecc[i]).decode())
    received_shares_ecc.append((i+1, decrypted))

recovered_secret_rsa = reconstruct_secret(received_shares_rsa, p)
recovered_secret_ecc = reconstruct_secret(received_shares_ecc, p)


print(f'================== RSA secret share ===================')
print("Recovered secret: ", recovered_secret_rsa)
print("Secret is recovered correct?", recovered_secret_rsa == secret)

print(f'================== ECC secret share ===================')
print("Recovered secret: ", recovered_secret_ecc)
print("Secret is recovered correct?", recovered_secret_ecc == secret)
