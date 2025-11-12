import hashlib

def append(*arrays: bytes) -> bytes:
    return b"".join(arrays)

def mod_exp(base, exponent, modulus):
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent // 2
        base = (base * base) % modulus
    return result

def hash1000(data: bytes) -> bytes:
    for _ in range(1000):
        data = hashlib.sha256(data).digest()
    return data

import secrets
import math

# a = secrets.randbits(256)
a = 88780883629599628452516828182721579921267855274791530685136261044453349207148
print(f"a = {a}")
g = 5
p = 233000556327543348946447470779219175150430130236907257523476085501968599658761371268535640963004707302492862642690597042148035540759198167263992070601617519279204228564031769469422146187139698860509698350226540759311033166697559129871348428777658832731699421786638279199926610332604408923157248859637890960407

mypubkey = mod_exp(g, a, p)
print("My public key:", mypubkey)

password = b"cryptococcal"
salt_hex = "a3511747"
salt_bytes = bytes.fromhex(salt_hex)
saltpluspassword = append(salt_bytes, password)
x = hash1000(saltpluspassword)
print("x (integer):", int.from_bytes(x, 'big'))
k = hashlib.sha256(append(p.to_bytes((p.bit_length() + 7) // 8, 'big'), g.to_bytes((g.bit_length() + 7) // 8, 'big'))).digest()
kint = int.from_bytes(k, 'big')
print("k (integer):", kint)
fancyB = 123398674177378025647285012787545114564319542791140465312232149309822615596401777911044524275998343004247116945476521816409570123792273469153258291204699170041710679392283222339889308167740315783146891053093968962751341887561761908074716357843730407754122172256778264163355606432456577789520532806395948408967
gpowerb = (fancyB - kint * mod_exp(g, int.from_bytes(x, 'big'), p)) % p
print("g^b mod p:", gpowerb)
byte_len = (p.bit_length() + 7) // 8
gpowera = 108872541137512748179849709895225728038691115368725606610966473388536802379031116631280704466075857464771214252305988170145899927038744745463678031947621787968580425080241987604044356170594929253352442985037984742709563487335442364883401153430529757012582621657160250214129274949282407960307436392615522593699
u = hashlib.sha256(append(mypubkey.to_bytes((mypubkey.bit_length() + 7) // 8, 'big'), gpowerb.to_bytes((gpowerb.bit_length() + 7) // 8, 'big'))).digest()
print("u (integer):", int.from_bytes(u, 'big'))
sharedkey = mod_exp(gpowerb, a + int.from_bytes(u, 'big') * int.from_bytes(x, 'big'), p)
print("Shared key (integer):", sharedkey)
hashp = hashlib.sha256(p.to_bytes((p.bit_length() + 7) // 8, 'big')).digest()
hashg = hashlib.sha256(g.to_bytes((g.bit_length() + 7) // 8, 'big')).digest()
inthp = int.from_bytes(hashp, 'big')
inthg = int.from_bytes(hashg, 'big')
xoresult = inthp ^ inthg
M1 = hashlib.sha256(append(xoresult.to_bytes((xoresult.bit_length() + 7) // 8, 'big'), hashlib.sha256("dli44".encode()).digest(), salt_bytes, mypubkey.to_bytes((mypubkey.bit_length() + 7) // 8, 'big'), gpowerb.to_bytes((gpowerb.bit_length() + 7) // 8, 'big'), sharedkey.to_bytes((sharedkey.bit_length() + 7) // 8, 'big'))).digest()
print("M1:", M1.hex())
M2 = hashlib.sha256(append(mypubkey.to_bytes((mypubkey.bit_length() + 7) // 8, 'big'), M1, sharedkey.to_bytes((sharedkey.bit_length() + 7) // 8, 'big'))).digest()
print("M2:", M2.hex())