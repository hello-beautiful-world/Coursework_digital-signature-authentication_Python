import random 
'''
函数名：miller_rabin(n,k=5)
功能：使用miller_rabin算法进行素性检测
参数传递：n——待检测的数,k——检测次数
返回值：若检测结果为素数返回True,反之返回False
'''
def miller_rabin(n, k=10):  # 进行k测素性检测，提高准确性
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    # 将n-1写为2^r * d的形式
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    # 执行k次测试
    for _ in range(10):
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


'''
函数名：gcd(a, b)
功能：欧几里得算法求两个数的最大公约数
参数传递：a、b——待求公约数的两个整数
返回值：a、b的最大公约数
'''
def gcd(a, b):
    """计算两个正整数 a 和 b 的最大公约数。"""
    while b:
        a, b = b, a % b
    return a

'''
函数名：extended_gcd(a, b)
功能：扩展欧几里得算法计算a、b的最大公约数和等式中的系数
参数传递：a、b——待求公约数的两个整数
返回值：gcd-最大公约数，x、y-系数
'''
def extended_gcd(a, b):
    x, y, u, v = 0, 1, 1, 0
    while a != 0:
        q, r = b // a, b % a
        m, n = x - u * q, y - v * q
        b, a, x, y, u, v = a, r, u, v, m, n
    gcd = b
    return gcd, x, y


'''
函数名：mod_inverse(a, m):
功能：计算a在模m下的逆元
参数传递：a-待求逆元的整数,m——模数
返回值：a在模 m下的逆元
'''
def mod_inverse(a, m):
    gcd, x, y = extended_gcd(a, m)
    if gcd != 1:
        raise Exception('模逆元不存在')
    else:
        return x % m
    
'''
函数名：key_generation()
功能：RSA密钥和相关参数生成，p、q长度均为k比特
'''
def key_generation(k):
    while(True):
        # 生成一个k比特长的随机整数
        p = random.randint(2**(k-1), 2**k)
        q = random.randint(2**(k-1), 2**k)
        if miller_rabin(p) and miller_rabin(q):
            break
        else:
            continue
    n=p*q
   # 计算 φ(n) = (p-1) * (q-1)
    euler=(p-1)*(q-1)
    #生成公钥e
    e=random.randint(2,euler-1)
    while gcd(e, euler)!=1:
        e=random.randint(2,euler-1)
    #计算私钥d,使得 (d * e) % φ(n) = 1
    d=mod_inverse(e,euler)
    return p,q,n,e,d
    
    # 生成一个k比特长的随机整数
    while(True):
        p =random.randint(2**(k-1), 2**k)
        q =random.randint(2**(k-1), 2**k)
        if miller_rabin(p) and miller_rabin(q):
            break
        else:
            continue
    print(f"p={p} ")
    print(f"q={q} ")
    n=p*q
    print(f"n={n} ")
   # 计算 φ(n) = (p-1) * (q-1)
    euler=(p-1)*(q-1)
    #生成公钥e
    e=random.randint(2,euler-1)
    while gcd(e, euler)!=1:
        e=random.randint(2,euler-1)
    print(f"公钥e1={e} ")
    #计算私钥d,使得 (d * e) % φ(n) = 1
    d=mod_inverse(e,euler)
    print(f"私钥d1={d}")
    return p,q,n,e,d

'''
函数名：genenal_mod()
功能：一般模幂运算
参数传递：m^e模mod
返回值：result-一般模幂运算结果
'''
def general_mod(m,e,mod):
    result = 1
    for _ in range(e):
        result = (result*m) % mod
    return result

'''
函数名：fast_mod(m,e, mod)
功能：快速模幂运算
参数传递：m^e 模mod
返回值：result-快速模幂运算结果
'''
def fast_mod(m,e, mod):
    result = 1
    m = m % mod
    #从右向左
    while e > 0:
        if e & 1:#可以使用与运算&判断e的二进制最低为是否为1
            result = (result * m) % mod
        # 指数右移一位
        e = e >> 1
        m = (m * m) % mod
    return result


'''
函数名： RSA_encryption():
功能：RSA加密过程
返回值:fast_c——明文对应密文
'''
def RSA_encryption(m,n,e):
    fast_c=fast_mod(m,e,n)
    print(f"加密所得密文为{fast_c}")
    return fast_c
 
'''
函数名： RSA_decryption
功能：RSA解密过程
返回值:plaintext——解密所获得的明文
'''   
def RSA_decryption(c,d,p,q,n):
    d_p=d%(p-1)
    d_q=d%(q-1)
    #计算q在模p意义下的乘法逆元
    q_inv=mod_inverse(q, p)
    #对密文分别进行模p和模q的解密计算
    m_p= fast_mod(c, d_p, p)
    m_q= fast_mod(c, d_q, q)
    #使用中国剩余定理从m_p和m_q中恢复明文
    h = (q_inv * (m_p- m_q)) % p
    plaintext = (m_p+h * q)%n
    #print(f"解密所得明文为{plaintext}")
    return plaintext 
 


sender_p,sender_q,sender_n,sender_e,sender_d=key_generation(5)  #发送方参数生成
print(f"发送方的参数p,q,n,e,d={sender_p,sender_q,sender_n,sender_e,sender_d}")
receiver_p,receiver_q,receiver_n,receiver_e,receiver_d=key_generation(5)   #接收方参数生成
print(f"接收方的参数p,q,n,e,d={receiver_p,receiver_q,receiver_n,receiver_e,receiver_d}")
m1=input("请输入明文:")
m=int(m1)
#先签名
y=fast_mod(m,sender_d,sender_n)
#后加密
ciphertext1=RSA_encryption(y,receiver_n,receiver_e)
#解密
y2=RSA_decryption(ciphertext1,receiver_d,receiver_p,receiver_q,receiver_n)
#验签
x=fast_mod(y,sender_e,sender_n)
print(f"验签所得明文为{x}")
