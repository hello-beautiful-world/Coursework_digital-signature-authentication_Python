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
#KGC类
class KGC(Sub_function): #KGC继承自Sub_function
    def __init__(self ):
        self.p = None #大素数
        self.q = None #大素数
        self.n = None #p*q
        self.e = None #系统公钥
        self.d = None #系统私钥
    '''功能：系统参数生成'''
    def KGC_key_generation(self):
        self.p = super().generate_byte_prime(1)
        self.q = super().generate_byte_prime(1)
        self.n = self.p*self.q 
        euler=(self.p-1)*(self.q-1)
        #生成公钥e
        self.e=random.randint(2,euler-1)
        while super().gcd(self.e, euler)!=1:
            self.e=random.randint(2,euler-1)
        #计算私钥d,使得 (d * e) % φ(n) = 1
        self.d=super().extended_gcd(self.e,euler)
        return self.n, self.e
    '''功能：用户私钥生成'''
    def user_key_generation(self, ID):
        return super().fast_mod_pow(ID, self.d, self.n)
#定义示证者Signer类
class Signer(Sub_function):#Signer继承自Sub_function
    def __init__(self ):
        self.g = None#签名者私钥
    '''功能：用户签名生成'''
    def sign(self, e, n):
        print("请输入消息m：")
        char_m = input()
        byte_m = char_m.encode('utf-8')
        r = random.randint(2,n-1)
        t = super().fast_mod_pow(r, e, n)
        byte_t = t.to_bytes((t.bit_length()+7)//8, 'big')
        h = super().hash_byte_to_int(byte_t + byte_m)
        s = (self.g *super().fast_mod_pow(r, h, n) )%n 
        return char_m, t, s

#定义验证者Verifier类       
class Verifier(Sub_function):#Verifier继承自Sub_function
    '''
    功能：验签
    参数传递:(m,(t,s))-签名对,e-系统公开公钥,ID-签名者身份(int类型),n-系统公开参数
    '''
    def verify(self, t, s, m, e, ID, n):
        byte_m = m.encode('utf-8')
        byte_t = t.to_bytes((t.bit_length()+7)//8, 'big')
        h = super().hash_byte_to_int(byte_t + byte_m)
        return super().fast_mod_pow(s, e, n) == (ID * super().fast_mod_pow(t, h, n))%n
        
def main():#shamir基于身份的数字签名
    example_KGC = KGC()
    example_Signer =Signer()
    example_Verifier = Verifier()
    n, e = example_KGC.KGC_key_generation()#系统参数生成
    print("请输入签名者ID：")
    char_ID = input()
    byte_ID = char_ID.encode('utf-8')
    int_ID = int.from_bytes(byte_ID, 'big')%n#int_ID < n
    example_Signer.g = example_KGC.user_key_generation(int_ID)#用户私钥生成
    #签名
    m, t, s = example_Signer.sign(e, n)
    print(f"对{m}的签名为{t},{s}")
    #验签
    if example_Verifier.verify( t, s, m, e, int_ID, n):
        print("验签成功！")
    else:
        print("验签失败！")
    
if __name__ == "__main__":
    main()  


