import os
BLOCK = 16

def xtime(a):
    a <<= 1
    return (a ^ 0x11B) if a & 0x100 else a

def gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = xtime(a)
        b >>= 1
    return r

def rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF

def build_sbox():
    sbox = [0] * 256
    for x in range(256):
        inv = 0
        if x:
            inv = next(y for y in range(1, 256) if gmul(x, y) == 1)
        sbox[x] = inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63
    inv_sbox = [0] * 256
    for i, v in enumerate(sbox):
        inv_sbox[v] = i
    return sbox, inv_sbox

SBOX, INV_SBOX = build_sbox()
MIX = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
INV_MIX = [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]]

def expand_key(key):
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = xtime(rcon)
        elif nk > 6 and i % nk == 4:
            t = [SBOX[b] for b in t]
        w.append([a ^ b for a, b in zip(w[i - nk], t)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(nr + 1)]

def add_round_key(s, k):
    return [a ^ b for a, b in zip(s, k)]

def sub_bytes(s, box):
    return [box[b] for b in s]

def shift_rows(s):
    return [s[r + 4 * ((c + r) % 4)] for c in range(4) for r in range(4)]

def inv_shift_rows(s):
    return [s[r + 4 * ((c - r) % 4)] for c in range(4) for r in range(4)]

def mix_columns(s, m):
    out = []
    for c in range(4):
        col = s[4 * c:4 * c + 4]
        for r in range(4):
            v = 0
            for i in range(4):
                v ^= gmul(m[r][i], col[i])
            out.append(v)
    return out

def encrypt_block(block, rk):
    nr = len(rk) - 1
    s = add_round_key(list(block), rk[0])
    for rnd in range(1, nr):
        s = sub_bytes(s, SBOX)
        s = shift_rows(s)
        s = mix_columns(s, MIX)
        s = add_round_key(s, rk[rnd])
    s = sub_bytes(s, SBOX)
    s = shift_rows(s)
    s = add_round_key(s, rk[nr])
    return bytes(s)

def decrypt_block(block, rk):
    nr = len(rk) - 1
    s = add_round_key(list(block), rk[nr])
    for rnd in range(nr - 1, 0, -1):
        s = inv_shift_rows(s)
        s = sub_bytes(s, INV_SBOX)
        s = add_round_key(s, rk[rnd])
        s = mix_columns(s, INV_MIX)
    s = inv_shift_rows(s)
    s = sub_bytes(s, INV_SBOX)
    s = add_round_key(s, rk[0])
    return bytes(s)

def pad(data):
    n = BLOCK - len(data) % BLOCK
    return data + bytes([n]) * n

def unpad(data):
    n = data[-1] if data else 0
    if n < 1 or n > BLOCK or data[-n:] != bytes([n]) * n:
        raise ValueError("padding tidak valid (key salah?)")
    return data[:-n]

def check_key(key):
    if not key.isascii():
        raise ValueError("key harus ASCII")
    if len(key) not in (16, 24, 32):
        raise ValueError(f"panjang key harus 16/24/32 karakter, bukan {len(key)}")
    return key.encode("ascii")

def encrypt(plaintext, key):
    if not plaintext.isascii():
        raise ValueError("plaintext harus ASCII")
    rk = expand_key(check_key(key))
    iv = os.urandom(BLOCK)
    data = pad(plaintext.encode("ascii"))
    prev, out = iv, b""
    for i in range(0, len(data), BLOCK):
        block = bytes(a ^ b for a, b in zip(data[i:i + BLOCK], prev))
        prev = encrypt_block(block, rk)
        out += prev
    return (iv + out).hex()

def decrypt(cipher_hex, key):
    rk = expand_key(check_key(key))
    raw = bytes.fromhex(cipher_hex)
    if len(raw) < 2 * BLOCK or len(raw) % BLOCK:
        raise ValueError("panjang ciphertext tidak valid")
    prev, out = raw[:BLOCK], b""
    for i in range(BLOCK, len(raw), BLOCK):
        block = raw[i:i + BLOCK]
        out += bytes(a ^ b for a, b in zip(decrypt_block(block, rk), prev))
        prev = block
    return unpad(out).decode("ascii")