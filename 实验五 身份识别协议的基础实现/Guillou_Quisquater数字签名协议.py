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
#定义信任中心TA类
class TA(Sub_function): #TA继承自Sub_function
    def __init__(self ):    
        self.p = None#保密
        self.q = None#保密
        self.n = None#TA选择并公布的模数
        self.e = None#公共参数
        self.euler = None
    '''功能：TA选择系统参数'''
    def TA_parameterSelection(self):
        byte = 1
        self.p = super().generate_byte_prime(byte)
        self.q = super().generate_byte_prime(byte)
        self.n = self.p*self.q
        print(f"q = {self.q},p = {self.p},n = {self.n}")
        self.euler = (self.p-1)*(self.q-1)
        self.e=random.randint(1,self.n-1)
        while super().gcd(self.e, self.euler)!=1:#e与euler互素
            self.e=random.randint(1,self.n-1)
        return self.e, self.n#返回公开参数(e,n)
    '''功能：给签名者分配密钥'''
    def generate_P_key(self, v):
        for i in range(1,self.n):
            if (v*super().fast_mod_pow(i, self.e, self.n)-1)%self.n == 0:
                break
        return i
#定义签名者P类
class P(Sub_function):#P继承自Sub_function
    def __init__(self ):
        self.ID = None#唯一性身份
        self.n = None#系统公开参数
        self.e = None#系统公开参数
        self.s = None#TA分配的密钥
        self.v = None#公钥
    '''功能:利用唯一性身份ID得哈希值发送给TA'''
    def generate_v(self):
        print("请输入唯一性身份ID：")
        self.ID = input()
        byte_ID =self.ID.encode('utf-8')
        self.v = super().hash_byte_to_int(byte_ID)%self.n#v与n互素
        while super().gcd(self.v, self.n)!=1:#v与n互素
            self.v -=1
        print(f"v = {self.v}")
        return self.v#发送给TA，用于TA给签名者分配密钥
        
    '''功能：签名'''
    def sign(self):
        print("**********签名过程**********")
        print(f"e={self.e},n={self.n}")
        r = random.randint(1,self.n-1)
        u = super().fast_mod_pow(r, self.e, self.n)
        print(f"r={r},u={u}")
        print("请输入签名内容：")
        m = input()
        byte_m =m.encode('utf-8')
        byte_length = (u.bit_length() + 7) // 8 # 确定需要多少个字节来存储这个整数
        byte_u = u.to_bytes(byte_length, 'big') 
        L = super().hash_byte_to_int(byte_m + byte_u)
        s = (r * super().fast_mod_pow(self.s, L, self.n)) % self.n
        print(f"签名为：m={m}\nL={L}\ns={s}")
        print("**********签名结束**********")
        return m, L, s#返回签名给验签者
    
#定义验签者V类
class V(Sub_function):#V继承自Sub_function
    def __init__(self ):
        self.n = None#系统公开参数
        self.v = None##签名者公钥
        self.e = None#系统公开参数
    '''功能：验签'''
    def verify(self, m, L, s):
        print("**********验签过程**********")
        print(f"e={self.e},n={self.n}")
        print(f"m = {m}\nL = {L}\ns = {s}")
        u = (super().fast_mod_pow(s, self.e, self.n) * super().fast_mod_pow(self.v, L, self.n))%self.n
        print(f"u'={u}")
        byte_m =m.encode('utf-8')
        byte_length = (u.bit_length() + 7) // 8 # 确定需要多少个字节来存储这个整数
        byte_u = u.to_bytes(byte_length, 'big') 
        L_V = super().hash_byte_to_int(byte_m + byte_u)
        print(f"L'={L_V}")
        print("**********验签结束**********")
        return L_V == L

def main():#Guillou-Quisquater数字签名协议
    example_TA =TA()
    e, n = example_TA.TA_parameterSelection()
    example_P = P()#签名者
    example_V = V()#验签者
    example_P.n ,example_P.e, example_V.n, example_V.e = n, e, n, e
    v = example_P.generate_v()#公钥
    example_V.v = v
    example_P.s = example_TA.generate_P_key(v)#TA给签名者分配私钥
    m, L, s = example_P.sign()#签名
    if example_V.verify(m, L, s):
        print("验证成功！")
    else:
        print("验证失败！")
if __name__ == "__main__":
    main()  

