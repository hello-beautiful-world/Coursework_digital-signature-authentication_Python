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
       return int(hash_m,16)
   '''
   功能：生成指定字节长度的素数
   '''
   def generate_byte_prime(self,byte):
       p = int.from_bytes(get_random_bytes(byte), byteorder='big')
       while not self.miller_rabin(p, 5):#5次素性检测
           p = int.from_bytes(get_random_bytes(byte), byteorder='big')
       return p
#定义签名者类
class Signer(Sub_function):
    def __init__(self):
        self.p = None#大素数
        self.q = None#大素数
        self.n = None#p*q
        self.e = None#签名者公钥
        self.d = None#签名者私钥
        self.r = None#盲化时选择的随机数，存储下来用于去盲化
        self.m = None#签名消息
    '''
    功能：生成RSAr签名体制参数p(大素数),q(大素数),d（私钥）,e（公钥）
    '''
    def generate_parameter(self):
        self.p = super().generate_byte_prime(32)#256bits
        self.q = super().generate_byte_prime(32)#256bits
        print(f"p:\n{self.p}\nq:\n{self.q}\n")
        self.n = self.p*self.q 
        euler=(self.p-1)*(self.q-1)
        #生成公钥e
        self.e=random.randint(2,euler-1)
        while super().gcd(self.e, euler)!=1:
            self.e=random.randint(2,euler-1)
        #计算私钥d,使得 (d * e) % φ(n) = 1
        self.d=super().extended_gcd(self.e,euler)
        return self.n, self.e
    '''功能：签名'''
    def sign(self, blind_m):
        return super().fast_mod_pow(blind_m, self.d, self.n)#签名，发送给用户

#定义用户类
class User(Sub_function):
    def __init__(self):
        self.n = None#p*q
        self.e = None#签名者公钥
        self.r = None#盲化时选择的随机数，存储下来用于去盲化
        self.m = None#签名消息
    '''功能：盲化'''
    def blinding(self):
        self.r = random.randint(2,self.n-1)#!!保证r与n互素
        while super().gcd(self.r, self.n)!=1:
            self.r=random.randint(2,self.n-1)
        print("请用户输入要签名的内容：")
        self.m = input()
        byte_m = self.m.encode('utf-8')
        hash_m = super().hash_byte_to_int(byte_m)
        return (super().fast_mod_pow(self.r, self.e, self.n)*hash_m)%self.n#盲化处理的消息，发送给签名者
    '''功能：去盲化'''
    def de_blinding(self, sign_blinding):
        return (sign_blinding * super().extended_gcd(self.r, self.n))%self.n#真正签名，发送给验签者
#定义验签者类
class Verify(Sub_function):
    def verify_sign(self, m, sign, e, n):
        byte_m = m.encode('utf-8')
        hash_m = super().hash_byte_to_int(byte_m)
        return super().fast_mod_pow(sign, e, n) == hash_m%n
        
def main():#基于RSA的盲签名
    user = User()
    verfy = Verify() 
    signer = Signer()
    #参数选取
    n, e = signer.generate_parameter()
    user.n, user.e = n, e
    #盲化
    blind_m = user.blinding()
    #签名
    sign_blinding=  signer.sign(blind_m)
    #去盲化
    sign = user.de_blinding(sign_blinding)
    print(f"对{user.m}的签名为{sign}")
    #验签
    if verfy.verify_sign(user.m, sign, e, n):
        print("经过验签，签名有效")
    else:
        print("经过验签，签名无效")
    
if __name__ == "__main__":
    main()