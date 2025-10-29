import math
import string
from cryptography.fernet import Fernet
# MADE BY MARCIWHITE
# DISCLAIMER: THIS IS IN NO WAY SECURE, NEVER TRY TO IMPLEMENT YOUR OWN CRYPTO. THIS WAS DONE AS A PERSONAL EXPERIMENT, WHERE SECURITY WAS NOT A PRIORITY.
# It's vulnerable to a lot cyber attacks (no padding, small prime numbers etc.)
import random
def encode(s,public_key):
    arr = []
    # Step 1: convert
    for i in s:
        if isinstance(i,int):
            arr.append(i)
        else:
            arr.append(ord(i))

    # Step 2: Raise to the power of the first public key
    for n,i in enumerate(arr):
        # Step 3: remainder of the second public key
        arr[n] = (i**public_key[0]) % public_key[1]

    return ";".join([str(x) for x in arr])
def decode(arr,private_key):
    # Step 1: raise to the power of private key
    for n,i in enumerate(arr):
        # Step 2: remainder of the second public key
        arr[n] = (i**private_key[0]) % private_key[1]

    # Step 3: Decode
    return "".join([chr(x) for x in arr])

# Fermat's theorem used due to simplicity not appropriate when working with large numbers
# k raised to n - k is divideable with n then its a prime
def is_prime(n):
    return (2**n-2) % n == 0
def generate_primes(n):
    prime = [True for _ in range(n + 1)]
    p = 2
    while (p * p <= n):
        if (prime[p] == True):
            for i in range(p ** 2, n + 1, p):
                prime[i] = False
        p += 1
    prime[0] = False
    prime[1] = False
    return [x for x in range(n + 1) if prime[x]]


def generate_keys(prime_range=1000):
    """
    :param prime_range: how large prime numbers should it choose for key generation, larger number means more secure also takes more time to decode/encode
    :return: {'public':(e,n), 'private':(d,n)}
    """
    primes = generate_primes(prime_range)# [x for x in range(10,prime_range) if is_prime(x)]
    # Original primes, TOP SECRET:
    p = random.choice(primes)
    q = random.choice(primes)
    # Product of primes:
    n = p*q
    # Calculate totient:
    o = (p-1)*(q-1)
    # Coprime (GCD is 1) 1 < e < o:
    coprimes = [x for x in range(1,o) if math.gcd(x,o)==1]
    e = random.choice(coprimes)
    # Calculate concurrent
    d = -1
    i = 0
    while d == -1:
        i += 1
        if i*e % o == 1:
            d = i
            break
    return {"public":(e,n),"private":(d,n)}
