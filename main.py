import secrets, math, random
E = 65537
def is_prime(n, k=40):
    if n < 2: return False
    for p in (2,3,5,7,11,13,17,19,23,29,31,37):
        if n % p == 0: return n == p
    d, r = n - 1, 0
    while d % 2 == 0: d //= 2; r += 1
    for _ in range(k):
        a = random.randrange(2, n - 1); x = pow(a, d, n)
        if x in (1, n - 1): continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1: break
        else: return False
    return True
def gen_prime(bits):
    while True:
        c = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if (c - 1) % E and is_prime(c): return c

LOW = 960
N_pub = gen_prime(1024) * gen_prime(1024)          # stand-in for a genuine DSC modulus
T = N_pub & ((1 << LOW) - 1)                        # its low 960 bits (public)
p = gen_prime(1024)
q_low = (T * pow(p, -1, 1 << LOW)) & ((1 << LOW) - 1)
while True:
    q = q_low + (secrets.randbits(1024 - LOW) | (1 << (1024 - LOW - 1))) * (1 << LOW)
    if q.bit_length() == 1024 and (q - 1) % E and is_prime(q): break
N_prime = p * q
d = pow(E, -1, (p - 1) * (q - 1) // math.gcd(p - 1, q - 1))
assert N_prime != N_pub
assert (N_prime & ((1 << LOW) - 1)) == T           # SAME low 960 bits -> SAME leaf
print("different key, identical low 960 bits:", (N_prime & ((1<<LOW)-1)) == T, "; private key known:", pow(pow(2,d,N_prime),E,N_prime)==2)