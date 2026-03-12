# -*- coding: utf-8 -*-
import random
import hashlib
'''
函数名：miller_rabin
功能：使用miller_rabin算法进行素性检测
参数传递：n——待检测的数,k——检测次数
返回值：若检测结果为素数返回True,反之返回False
'''
def miller_rabin(n, k):  # 进行k测素性检测，提高准确性
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    # 将n-1写为2^r * d的形式
    r, d = 0, n - 1
    while d % 2 == 0:  # 使d为奇数
        r += 1
        d //= 2#注意使用//保证结果为整数，避免了由浮点数带来的潜在问题
    # 执行k次测试
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else: #else与最近的for循环配对，只有当循环自然结束（即没有遇到break）才会执行
            return False
    return True
'''
功能：生成指定比特长度的素数
'''
def generate_bit_prime(bit):
    p = random.randint(2**(bit-1), 2**bit-1)
    while not miller_rabin(p, 5):#5次素性检测
        p = random.randint(2**(bit-1), 2**bit-1)
    return p

'''
功能：快速模幂运算
参数传递：base-底数，exp-指数，mod-模数
'''
def fast_mod_pow(base, exp, mod):
    result = 1  # 运算结果初始化为1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:  # 最低为是否为1
            result = (result*base) % mod
        exp = exp >> 1  # 右移1位
        base = (base*base) % mod
    return result


'''    
功能：模乘运算
'''
def mod_mul(num1, num2, mod):
    return (num1 % mod)*(num2 % mod) % mod  # 每次中间计算时就取模操作

'''
功能：扩展的欧几里得算法,求最小公因数和逆元
返回值：y2-num2模num1的逆元(num1>num2)
'''
def extended_gcd(num1, num2):
    if num1 < num2:  # 保证num1>=num2
        num1, num2 = num2, num1
    x1, x2, x3 = 1, 0, num1
    y1, y2, y3 = 0, 1, num2
    while y3 != 0 and y3 != 1:
        Q = int(x3 / y3)
        temp_y1, temp_y2, temp_y3 = y1, y2, y3
        y1, y2, y3 = x1 - Q * y1, x2 - Q * y2, x3 - Q * y3
        x1, x2, x3 = temp_y1, temp_y2, temp_y3
    if y3 == 1:
        return y3, y2  # y3为最大公因子，y2为逆元
    if y3 == 0:
        return y2, 0  # y2为最大公因子，无逆元
'''
功能：对byte类型的消息进行哈希
返回值：int(hash_m)-int类型的哈希值
'''
def hash_byte_to_int(byte_m):
    hash_obj = hashlib.sha256()#创建SHA-256哈希对象
    hash_obj.update(byte_m)#更新哈希对象，添加数据
    hash_m=hash_obj.hexdigest()#十六进制表示,hash_m是str类型,64字节
    return int(hash_m,16)    
'''
功能：生成DSA签名体制参数p,q,g,x,y
'''
def generate_parameter():
    #选p
    '''mul = random.randint(8,16)
    L = mul*64#512<=L<=1024,且L为64的倍数'''
    L=8#使用小数验证代码
    p = generate_bit_prime(L)#2^(L-1)<p<2^L
    #选q
    factors=[]
    euler_p = p - 1
    factor = 2#从2开始
    while euler_p > 1:
        if euler_p % factor==0:
            factors.append(factor)#为了方便使用小数验证代码，下面注释中为现实条件
            '''if factor>2**159 and factor<2**160:#p为160比特长度的p-1的素因子
                q=factor
                break'''
            while euler_p % factor==0:
                euler_p//=factor#保证后续加入集合的factor都为素数，注意使用//
        factor+=1
    q = max(factors)
    #计算g
    h = random.randint(2, p-2)
    g = fast_mod_pow(h, int((p-1)/q), p)
    while g <= 1:
        h = random.randint(2, p-2)
        g = fast_mod_pow(h, (p-1)/q, p)
    #选密钥x(0<x<q)
    x = random.randint(1, q-1)
    #计算公钥y
    y = fast_mod_pow(g, x, p)
    '''测试参数
    p =0xa030b2bbea795e7533769ff4e6bed8becae8e1f57d80062ed2b38397cc4c110f
    q = 0x71e886bc4600d3869118146a5abf785911d
    x= 0x3B2F0C9E3A1B5D8A6E7C0D4F8A6B2E1C3D9F5E1
    g = 0x12972b7570fb64952411d8a190995caaf1a573f5141c26b6bb17380a1880d00d'''
    y = fast_mod_pow(g, x, p)
    return p, q, g, x, y

'''
功能：签名算法
返回值：签名 r, s
'''
def sign(str_m, p, q, g, x):
    #选随机数k(0<k<q)
    k = random.randint(1, q-1)
    #计算r
    r = fast_mod_pow(g, k, p)%q
    #计算s
    gcd, inverse_k = extended_gcd(q, k)
    byte_m = str_m.encode('utf-8')#将str类型消息转化为byte类型
    hash_m = hash_byte_to_int(byte_m)
    s = mod_mul(inverse_k, hash_m+x*r, q)
    return r,s
    

'''
功能：验签
返回值：是否为有效签名
'''
def verify_sign(str_m, r, s, p, q, g, y):
    gcd, inverse_s = extended_gcd(q, s)
    byte_m = str_m.encode('utf-8')#将str类型消息转化为byte类型
    hash_m = hash_byte_to_int(byte_m)
    u1 = mod_mul(hash_m, inverse_s, q)
    u2 = mod_mul(r, inverse_s, q)
    v = mod_mul(fast_mod_pow(g, u1, p), fast_mod_pow(y, u2, p), p)%q
    if v == r:
        return True
    else:
        return False
def main():
    str_m="This is a test message for DSA signature"
    p, q, g, x, y = generate_parameter()
    print(f"签名所使用的p、q、g、x、y ={p,q,g,x,y}")
    r, s = sign(str_m, p, q, g, x)
    print(f"消息m={str_m}\n签名(r,s))为:\n{r,s}")
    if verify_sign(str_m, r, s, p, q, g, y):
        print("经过验签，签名有效")
    else:
        print("经过验签，签名无效")


if __name__ == "__main__":
    main()

