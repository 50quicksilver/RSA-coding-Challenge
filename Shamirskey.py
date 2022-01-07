
"""
Author: Emir Beg, emirbeg2017@gmail.com
Assignment: 12.1 - Solo Wof
Date: 09/13/2021

Description:
   Write a CLI program that creates an RSA key pair and shards the private key into k of n shares
    using Shamir's secret sharing algorithm. The app should be able to re-create the private key if 2
    of n shares are presented.

Sources:
https://www.youtube.com/watch?v=rrKuqbTDom8
https://pycryptodome.readthedocs.io/en/latest/src/protocol/ss.html
"""
import random
from math import ceil
from decimal import Decimal

import basehash
import base64
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Protocol.SecretSharing import Shamir
from binascii import hexlify
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes


##########################RSA key generation#############################
key = RSA.generate(1024)
p_key = key.publickey().exportKey("PEM")
priv_key = key.exportKey("PEM")

public_key = RSA.importKey(p_key.decode())
private_key = RSA.importKey(priv_key.decode())

print()


pri_key_l = list(priv_key.decode().split('\n'))
pri_key_l.pop(0)
pri_key_l.pop(len(pri_key_l)-1)

encryptor = PKCS1_OAEP.new(public_key)
encrypted = encryptor.encrypt(b'hello world')



rsa_private_key = PKCS1_OAEP.new(private_key)
decrypted = rsa_private_key.decrypt(encrypted)
print('your decrypted_text is : {}'.format(decrypted.decode()))

with open('Public.TXT', 'w') as f:
    f.write(p_key.decode())



########################share generator#################################

# ######FROM https://www.geeksforgeeks.org/implementing-shamirs-secret-sharing-scheme-in-python/ ######
FIELD_SIZE = 10**5
 
 
def reconstruct_secret(shares):
    """
    Combines individual shares (points on graph)
    using Lagranges interpolation.
 
    `shares` is a list of points (x, y) belonging to a
    polynomial with a constant of our key.
    """
    sums = 0
    prod_arr = []
 
    for j, share_j in enumerate(shares):
        xj, yj = share_j
        prod = Decimal(1)
 
        for i, share_i in enumerate(shares):
            xi, _ = share_i
            if i != j:
                prod *= Decimal(Decimal(xi)/(xi-xj))
 
        prod *= yj
        sums += Decimal(prod)
 
    return int(round(Decimal(sums), 0))
 
 
def polynom(x, coefficients):
    """
    This generates a single point on the graph of given polynomial
    in `x`. The polynomial is given by the list of `coefficients`.
    """
    point = 0
    # Loop through reversed list, so that indices from enumerate match the
    # actual coefficient indices
    for coefficient_index, coefficient_value in enumerate(coefficients[::-1]):
        point += x ** coefficient_index * coefficient_value
    return point
 
 
def coeff(t, secret):
    """
    Randomly generate a list of coefficients for a polynomial with
    degree of `t` - 1, whose constant is `secret`.
 
    For example with a 3rd degree coefficient like this:
        3x^3 + 4x^2 + 18x + 554
 
        554 is the secret, and the polynomial degree + 1 is
        how many points are needed to recover this secret.
        (in this case it's 4 points).
    """
    coeff = [random.randrange(0, FIELD_SIZE) for _ in range(t - 1)]
    coeff.append(secret)
    return coeff
 
 
def generate_shares(n, m, secret):
    """
    Split given `secret` into `n` shares with minimum threshold
    of `m` shares to recover this `secret`, using SSS algorithm.
    """
    coefficients = coeff(m, secret)
    shares = []
 
    for i in range(1, n+1):
        x = random.randrange(1, FIELD_SIZE)
        shares.append((x, polynom(x, coefficients)))
 
    return shares
 
 
# Driver code
if __name__ == '__main__':
    t, n = 2, 6
    secret = len(pri_key_l) - 1
    print(f"Original Secret: {''.join(pri_key_l)}")
 
    # Phase I: Generation of shares
    shares = generate_shares(n, t, secret)
    print(f'Shares: {", ".join(str(share) for share in shares)}')
 
    # Phase II: Secret Reconstruction
    # Picking t shares randomly for
    # reconstruction
    pool = random.sample(shares, t)
    with open('Shard[k].TXT', 'w') as f:
        f.write(", ".join(str(share) for share in shares))

    print(f'Combining shares: {", ".join(str(share) for share in pool)}')
    if secret == len(pri_key_l) - 1:
        print(f'Reconstructed secret: {reconstruct_secret(pool)}')
    else:
        print('Incorrect values')

##### END OF BLOCK ######