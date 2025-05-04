p = 0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53
a = 0x7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826
b = 0x4a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11
Gx = 0x1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e 
Gy = 0x8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315
n = 0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565


def chunked_big(x):
    res = []
    x_clone = x
    for i in range(4):
        res.append(hex(x_clone % 2**120))
        x_clone = x_clone // 2**120
    return res

def print_big(x):
    res = str(chunked_big(x)).replace("'", "")
    print(res)

def get_param(x):
    return (2**(384 * 2 + 4) // x)

print_big(Gx)
print_big(Gy)

print_big(a)
print_big(b)

print_big(p)
print_big(get_param(p))

print_big(n)
print_big(get_param(n))


h = "c99bfafc04367131e792c1383719238d2bce8d4c91ceb76d73f3a80cb4d997470868ae19f748e8183b82ff46aa3edd6a"
print(list(bytearray.fromhex(h)))