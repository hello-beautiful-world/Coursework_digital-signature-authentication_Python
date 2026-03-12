# -*- coding: utf-8 -*-
import random
import hashlib


# 使用miller - rabin算法进行素性检测
def miller_rabin(n, k):
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d = d // 2
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


# 生成指定比特长度的素数
def generate_bit_prime(bit):
    while True:
        num = random.getrandbits(bit)
        if miller_rabin(num, 5):
            return num


# 在模p的简化剩余系中寻找一个本原元
def find_primitive_element(p):
    factors = []
    phi = p - 1
    n = phi
    div = 2
    while n > 1:
        while n % div == 0:
            factors.append(div)
            n = n // div
        div += 1
    for g in 1, p:
        is_primitive = True
        for factor in factors:
            if pow(g, phi // factor, p) == 1:
                is_primitive = False
                break
        if is_primitive:
            return g


# 快速模幂运算
def fast_mod_pow(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result


# 扩展欧几里得算法求逆元
def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = extended_gcd(b % a, a)
        return g, x - (b // a) * y, y


# 计算模逆元
def mod_inverse(a, m):
    g, x, _ = extended_gcd(a, m)
    if g!= 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


# 生成Schnorr签名体制参数
def generate_parameters(bit_length):
    q = generate_bit_prime(bit_length)
    while True:
        p = generate_bit_prime(bit_length * 2)
        if (p - 1) % q == 0:
            break
    g = find_primitive_element(p)
    x = random.randint(1, q - 1)
    y = fast_mod_pow(g, x, p)
    return p, q, g, x, y


# 对消息进行哈希并转换为整数
def hash_message(message):
    hash_obj = hashlib.sha256(message).digest()
    return int.from_bytes(hash_obj, 'big')


# Schnorr签名
def schnorr_sign(message, p, q, g, x):
    k = random.randint(1, q - 1)
    r = fast_mod_pow(g, k, p)
    r_bytes = r.to_bytes((r.bit_length() + 7) // 8, 'big')
    e = hash_message(r_bytes + message) % q
    s = (k + x * e) % q
    return e, s


# Schnorr验签
def schnorr_verify(message, p, q, g, y, e, s):
    v = fast_mod_pow(g, s, p)
    w = fast_mod_pow(y, e, p)
    v = (v * w) % p
    v_bytes = v.to_bytes((v.bit_length() + 7) // 8, 'big')
    e_prime = hash_message(v_bytes + message) % q
    return e_prime == e

if __name__ == '__main__':
    bit_length = 16
    p, q, g, x, y = generate_parameters(bit_length)
    message = b"nihao"
    e, s = schnorr_sign(message, p, q, g, x)
    if schnorr_verify(message, p, q, g, y, e, s):
        print("签名验证成功")
    else:
        print("签名验证失败")

