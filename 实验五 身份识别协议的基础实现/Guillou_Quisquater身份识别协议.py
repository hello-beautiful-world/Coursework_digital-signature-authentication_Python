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
        self.d = None#保密
        self.euler = None
    '''功能：TA选择系统参数'''
    def TA_parameterSelection(self):
        byte = 1
        self.p = super().generate_byte_prime(byte)
        self.q = super().generate_byte_prime(byte)
        self.n = self.p*self.q
        print(f"q = {self.q},p = {self.p},n = {self.n}")
        self.euler = (self.p-1)*(self.q-1)
        self.e=random.randint(2,self.euler-1)
        while super().gcd(self.e, self.euler)!=1:#e与euler互素
            self.e=random.randint(2,self.euler-1)
        self.d = super().extended_gcd(self.e, self.euler)
        return self.e, self.n#返回公开参数(e,n)
    '''功能：给示证者分配密钥'''
    def generate_P_key(self, Jp):
        return super().fast_mod_pow( super().extended_gcd(Jp, self.n), self.d, self.n)
#定义示证者P类
class P(Sub_function):#P继承自Sub_function
    def __init__(self ):
        self.ID = None#唯一性身份
        self.r = None#第一步生成的随机数，保存下来以在第三步中使用
        self.n = None#系统公开参数
        self.e = None#系统公开参数
        self.s = None#TA分配的密钥
    '''功能:利用唯一性身份ID得哈希值发送给TA'''
    def generate_Jp(self):
        print("请输入唯一性身份ID：")
        self.ID = input()
        byte_ID =self.ID.encode('utf-8')
        Jp = super().hash_byte_to_int(byte_ID)%self.n#0<=Jp<=n-1
        return Jp#发送给TA，用于TA给示证者分配密钥
        
    '''功能：Guillou-Quisquater身份识别协议第一步'''
    def Guillou_Quisquater_1_P(self):
        self.r=random.randint(1,self.n-1)
        x = super().fast_mod_pow(self.r, self.e, self.n)
        return self.ID, x#转发给验证者
    '''功能：Guillou-Quisquater身份识别协议第三步'''
    def Guillou_Quisquater_3_P(self, u):
        return (self.r*super().fast_mod_pow(self.s, u, self.n))%self.n
        
        
        
  
#定义验证者V类
class V(Sub_function):#V继承自Sub_function
    def __init__(self ):
        self.n = None#系统公开参数
        self.b = None#系统公开参数
        self.e = None#系统公开参数
        self.u = None#第二步生成的随机数，保存下来以在第四步中使用
    '''功能：Guillou-Quisquater身份识别协议第二步'''
    def Guillou_Quisquater_2_V(self):
         self.u = random.randint(1,self.e)
         return self.u#转发给示证者
    '''功能：Guillou-Quisquater身份识别协议第四步'''
    def Guillou_Quisquater_4_V(self, ID, y, x):
         byte_ID =ID.encode('utf-8')
         Jp = super().hash_byte_to_int(byte_ID)%self.n#0<=Jp<=n-1
         return (super().fast_mod_pow(Jp, self.u, self.n)*super().fast_mod_pow(y, self.e, self.n))%self.n == x
def main():#Guillou-Quisquater身份识别协议
    example_TA =TA()
    e, n = example_TA.TA_parameterSelection()
    example_P = P()#示证者
    example_V = V()#验证者
    example_P.n ,example_P.e, example_V.n, example_V.e = n, e, n, e
    example_P.s = example_TA.generate_P_key(example_P.generate_Jp())#TA给示证者分配私钥
    #第一步
    ID, x = example_P.Guillou_Quisquater_1_P()
    print(f"第一步示证者P发给验证者V的消息为{ID}，{x}")
    #第二步
    u = example_V.Guillou_Quisquater_2_V()
    print(f"第二步验证者V发给示证者P的消息为{u}")
    #第三步
    y = example_P.Guillou_Quisquater_3_P(u)
    print(f"第三步示证者P发给验证者V的消息为{y}")
    #第四部
    if example_V.Guillou_Quisquater_4_V(ID, y, x):
        print("验证成功！")
    else:
        print("验证失败！")
if __name__ == "__main__":
    main()    

