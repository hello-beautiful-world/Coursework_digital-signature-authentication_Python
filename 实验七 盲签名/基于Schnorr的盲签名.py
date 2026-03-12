# -*- coding: utf-8 -*-
import random
from Crypto.Random import get_random_bytes
import hashlib

#需要用到的功能函数
class Sub_function:
    '''
    函数名：miller_rabin
    功能：使用miller_rabin算法进行素性检测
    参数传递：n——待检测的数,k——检测次数
    返回值：若检测结果为素数返回True,反之返回False'''
    def miller_rabin(self, n, k):  # 进行k测素性检测，提高准确性
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
    '''功能：计算两个数的最大公因数'''
    def gcd(self, a, b):  
        while b != 0:
            a, b = b, a % b
        return a
    '''
    功能：扩展的欧几里得算法,求逆元
    参数传递：num2-模数，num1-待求逆元的数(前提条件num1和num2互素)
    返回值：逆元
    '''
    def extended_gcd(self, num1, num2):
        tmp = num2
        x, y, u, v = 0, 1, 1, 0
        while num1:
            q, r = divmod(num2, num1)
            num2, num1 = num1, r
            x, y, u, v = u - q * x, v - q * y, x, y
        return v % tmp
    '''
    功能：快速模幂运算
    参数传递：base-底数，exp-指数，mod-模数
    '''
    def fast_mod_pow(self, base, exp, mod):
        result = 1  # 运算结果初始化为1
        base = base % mod
        while exp > 0:
            if exp % 2 == 1:  # 最低为是否为1
                result = (result*base) % mod
            exp = exp >> 1  # 右移1位
            base = (base*base) % mod
        return result
    '''
    功能：对byte类型的消息进行哈希
    返回值：int(hash_m)-int类型的哈希值
    '''
    def hash_byte_to_int(self,byte_m):
        hash_obj = hashlib.sha256()#创建SHA-256哈希对象
        hash_obj.update(byte_m)#更新哈希对象，添加数据
        hash_m=hash_obj.hexdigest()#十六进制表示,hash_m是str类型,64字节
        byte_hash_m =  hash_m.encode('utf - 8')
        return int.from_bytes( byte_hash_m , 'big')
    '''
    功能：生成指定字节长度的素数
    '''
    def generate_byte_prime(self,byte):
        p = int.from_bytes(get_random_bytes(byte), byteorder='big')
        while not self.miller_rabin(p, 5):#5次素性检测
            p = int.from_bytes(get_random_bytes(byte), byteorder='big')
        return p
    '''
    功能：在模p的简化剩余系中寻找一个本原元，注意此代码获得的是最小的本原元
    '''
    def find_primitive_element(self,p):
        euler_p = p-1
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
#定义签名者类
class Signer(Sub_function):
    def __init__(self):
        self.p = None
        self.q = None
        self.g = None
        self.x = None
        self.y = None
        self.k_signer = None#第一步选取的随机数，保存下来用于第三步
    '''
    功能：生成Schnorr签名体制参数p(大素数),q(大素数)g（在模q的简化剩余系中的一个本原元),
          x（私钥）,y（公钥）
    '''
    def generate_parameter(self):
        #先产成q,再生成p
        self.q =  super().generate_byte_prime(32)
        k = 2  # 可以从2开始，因为如果k为奇数，k*q必定为奇数
        self.p = k * self.q + 1
        while not super().miller_rabin(self.p, 5):
            k += 2
            self.p = k * self.q + 1
        print(f"p:\n{self.p}\nq:\n{self.q}")
        #self.g = super().find_primitive_element( self.p )#注意g^q = 1 mod p
        self.g = random.randint(2,self.p-1)
        self.g = super().fast_mod_pow(self.g, (self.p-1)//self.q, self.p)
        self.x = random.randint(2,self.q-1)#注意私钥1<x<q而不是p!!
        self.y =super().fast_mod_pow(self.g, self.x, self.p)
        return self.p, self.q, self.g, self.y#返回公开参数
    #基于Schnorr盲签名的第一步
    def Schnorr_signer_1(self):
        self.k_signer = random.randint(2,self.q-1)
        return super().fast_mod_pow(self.g, self.k_signer, self.p)#发送给用户
    #基于Schnorr盲签名的第三步
    def Schnorr_signer_3(self, e2):
        return (self.k_signer + self.x * e2) % self.q#发送给用户，签名

#定义用户类
class User(Sub_function):
    def __init__(self):
        self.p = None
        self.q = None
        self.g = None
        self.y = None
        self.a = None#第二步选取的随机数，保存下来用于第四步
        self.m = None
        self.e = None
    
    #基于Schnorr盲签名的第二步
    def Schnorr_user_2(self , w_signer):
        self.a = random.randint(2,self.q-1)
        b = random.randint(2,self.q-1)
        w_user = (super().fast_mod_pow(self.g, self.a, self.p) * super().fast_mod_pow(self.y, b, self.p)*w_signer)%self.p
        print("请用户输入要签名的内容：")
        self.m = input()
        byte_m = self.m.encode('utf - 8')#str类型转byte类型
        byte_w_user = w_user.to_bytes((w_user.bit_length() + 7) // 8, 'big') #int类型转byte类型
        self.e = super().hash_byte_to_int(byte_w_user+byte_m)
        return (self.e + b)% self.q
    #基于Schnorr盲签名的第四步
    def Schnorr_user_4(self , s_signer):
        return self.e, (s_signer+self.a) % self.q

#定义验签者类
class Verify(Sub_function):
    def __init__(self):
        self.p = None
        self.g = None
        self.y = None
        self.q = None
    '''功能：验签'''
    def verify_sign(self, m, e, s):
        
        inverse_y = super().extended_gcd( self.y, self.p)
        inverse_y_e = super().fast_mod_pow(inverse_y, e, self.p)
        w = (super().fast_mod_pow(self.g, s, self.p) * inverse_y_e) % self.p
        byte_m = m.encode('utf - 8')#str类型转byte类型
        byte_w = w.to_bytes((w.bit_length() + 7) // 8, 'big') #int类型转byte类型
        return super().hash_byte_to_int(byte_w + byte_m)==e
def main():#基于Schnorr的盲签名  
    user = User()
    verfy = Verify() 
    signer = Signer()
    #参数选取
    p, q, g, y = signer.generate_parameter()
    user.p ,user.q ,user.g ,user.y =  p, q, g, y
    verfy.p, verfy.q, verfy.g, verfy.y= p, q, g, y
    #第一步
    w_signer = signer.Schnorr_signer_1()
    #第二步
    e2 = user.Schnorr_user_2(w_signer)
    #第三步
    s_signer = signer.Schnorr_signer_3(e2)
    #第四步
    e, s = user.Schnorr_user_4(s_signer)
    print(f"对{ user.m}的签名为({e},{s})")
    if verfy.verify_sign( user.m, e, s):
        print("经过验签，签名有效")
    else:
        print("经过验签，签名无效")
if __name__ == "__main__":
    main()
