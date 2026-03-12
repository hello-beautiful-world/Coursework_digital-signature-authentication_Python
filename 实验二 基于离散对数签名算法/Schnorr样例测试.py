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
功能：在模p的简化剩余系中寻找一个本原元，注意此代码获得的是最小的本原元
'''
def find_primitive_element(p):
    euler_p = p - 1
    factors = set()#集合存放p-1的素因子
    factor = 2#从2开始
    while euler_p > 1:
        if euler_p % factor==0:
            factors.add(factor)
            while euler_p % factor==0:
                euler_p//=factor#保证后续加入集合的factor都为素数，注意使用//
        factor+=1
    #寻找本原元
    euler_p = p-1#前面被改变了
    for g in range(2,p):#2到p-1
        judge = True
        # 如果g^(euler_p/factor) ≡ 1 (mod p)，则g不是本原元
        for factor in factors:
            if pow(g,euler_p//factor,p)==1:
                judge=False
                break
        if judge: 
            return g    
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
功能：生成Schnorr签名体制参数p(大素数),q(大素数)g（在模q的简化剩余系中的一个本原元),
      x（私钥）,y（公钥）
'''
def generate_parameter(bit):
    p = 0xb9c0faef108e0da9bc6a7fd87b9b837a19c2fa3b2daa3ef276fd87fcb7fe690f
    q = 0x169f3edc9665f26b65fc6e805e3c997160a388a376e9266cfdbb512e107
    g = 0x5119a79a9849f5c98659566b890077dfa71a7cb22f92e9089d3462b3b2bc16fa
    x = 0x7C5D9F8B4A2F30D2E5AFA59F3C7B9A18E0DDAF23
    y = fast_mod_pow(g, x, p)
    return p, q, g, x, y

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
功能：Schnorr签名
返回值：str_m-string类型消息，r,s-m的签名
'''
def sign(str_m, g, p, x, q):#先使用小数验证
    k = random.randint(1, p-2)
    while k>=q:
        k = random.randint(1, p-2)#k 如果未限制在模 q 的范围内，可能导致 r 和 s 无效
    print(f"签名所使用的k={k}")
    w = fast_mod_pow(g, k, p)
    byte_length = w.bit_length() // 8 + 1 
    byte_m = str_m.encode('utf-8')#将str类型消息转化为byte类型
    byte_w = w.to_bytes(byte_length,byteorder='big',signed=False)#将w转化为byte类型
    #计算hash(w||m)
    r = hash_byte_to_int(byte_w + byte_m)
    s = ( k + mod_mul( x, r, q) ) % q
    return  r, s
    
     
'''
功能：Schnorr验签
'''
def verify_sign( str_m, g, y, p, r, s):
    byte_m = str_m.encode('utf-8')#将str类型消息转化为byte类型
    gcd, inverse_y_r = extended_gcd( p, fast_mod_pow(y, r, p))
    print(f"签名gcd={gcd}")
    #将验签过程中的w'转化为byte类型
    w_ver = mod_mul( fast_mod_pow(g, s, p), inverse_y_r, p)
    byte_length = w_ver.bit_length() // 8 + 1 
    byte_w_ver = w_ver.to_bytes(byte_length,byteorder='big',signed=False)
    if hash_byte_to_int(byte_w_ver + byte_m)==r:
        return True
    else:
        return False
    
def main():
    str_m="This is a test message for Schnorr signature"
    p, q, g, x, y = generate_parameter(5)
    print(f"签名所使用的p、q、g、x、y={p,q,g,x,y}")
    r, s = sign(str_m, g, p, x, q)
    print(f"消息m={str_m}\n签名(r,s)为:\n{r,s}")
    if verify_sign(str_m, g, y, p, r, s):
        print("经过验签，签名有效")
    else:
        print("经过验签，签名无效")
    
if __name__ == "__main__":
    main()
