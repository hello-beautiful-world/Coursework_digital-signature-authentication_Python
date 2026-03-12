# -*- coding: utf-8 -*-
import random
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
功能：在模p的简化剩余系中寻找一个本原元，注意此代码获得的是最小的本原元
'''
def find_peimitive_element(p):
    euler_p = p - 1
    factors = set()#集合存放p-1的素因子
    factor = 2#从2开始
    while euler_p > 1:
        if euler_p % factor==0:
            factors.add(factor)
            while euler_p % factor==0:
                euler_p//=factor#!!!!!保证后续加入集合的factor都为素数，注意使用//
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
功能：生成ElGamal签名体制参数p(大素数),g（本原元）,x（私钥）,y（公钥）
'''
def generate_parameter():
    p = generate_bit_prime(5)
    g = find_peimitive_element(p)
    x = random.randint(1,p-2)
    y = fast_mod_pow(g, x, p)
    return p, g, x, y


'''
功能：对两个消息使用相同随机数k签名
'''
def sign(str_m1, str_m2, p, g, x):
    k = random.randint(1, p-2)#使用相同的K对两个消息签名
    gcd, inverse_k = extended_gcd(k, p-1)
    while not inverse_k:  # 要求k与p-1互素
        k = random.randint(1, p-2)
        gcd, inverse_k = extended_gcd(k, p-1)
    print(f"签名所使用的随机数k={k}")
    #签名
    byte_m1 = str_m1.encode('utf-8')
    int_m1 = int.from_bytes(byte_m1, 'big')
    byte_m2 = str_m2.encode('utf-8')
    int_m2 = int.from_bytes(byte_m2, 'big')
    r = fast_mod_pow(g, k, p)
    #int()只能处理string,使用需要用十六进制string表示
    s1 = mod_mul(int_m1-x*r, inverse_k, p-1)
    s2 = mod_mul(int_m2-x*r, inverse_k, p-1)
    return int_m1, int_m2, r, s1, s2, k
    

'''
功能：验签
返回值：是否为有效签名
'''
def verify_sign(y, p, g, m, r, s):
    if fast_mod_pow(g, m, p) == mod_mul(fast_mod_pow(y, r, p), fast_mod_pow(r, s, p), p):
        return True
    else:
        return False
    
    
'''
功能：随机数重复攻击
'''
def re_k_attack(int_m1, int_m2, s1, s2, p, r, g, k):
    d , num = extended_gcd(s1 - s2, int_m1 - int_m2 )
    m_d = (int_m1 - int_m2)//d
    s_d =(s1 - s2)//d
    p_d = (p - 1)//d
    gcd, inverse_s_d= extended_gcd( p_d, s_d,)
    k_mod_p_d =  mod_mul(m_d, inverse_s_d,  p_d)
    while fast_mod_pow(g,  k_mod_p_d, p) != r:
        k_mod_p_d += p_d
    if k_mod_p_d==k:
        print(f"攻击获得随机数k={k_mod_p_d}，与签名所用的k相同，攻击成功")
    else:
        print(f"随机数重复攻击获得的随机数k={k_mod_p_d}，与签名所用的不相同，攻击失败")
    return  k_mod_p_d

def main():
    str_m1=  "a"
    str_m2 = "b"#对不同的消息签名
    p, g, x, y = generate_parameter()
    print(f"签名所使用的p、g、x、y={p,g,x,y}")
    int_m1, int_m2, r, s1, s2, k = sign(str_m1, str_m2, p, g, x)
    print(f"消息m1={str_m1}\n签名1(m1,(r,s1))为:\n（{str_m1},{r,s1}）")
    print(f"消息m2={str_m2}\n签名2(m2,(r,s2))为:\n（{str_m2},{r,s2}）")
    if verify_sign(y, p, g,int_m1, r, s1):
        print("经过验签，签名1有效")
    else:
        print("经过验签，签名1无效")
    if verify_sign(y, p, g,int_m2, r, s2):
        print("经过验签，签名2有效")
    else:
        print("经过验签，签名2无效")
        
    print("随机数重复攻击")
    re_k_attack(int_m1, int_m2, s1, s2, p, r, g, k) 

        

if __name__ == "__main__":
    main()