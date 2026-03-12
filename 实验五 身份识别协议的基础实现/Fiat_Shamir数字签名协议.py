# -*- coding: utf-8 -*-
import random
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

    '''
    功能：生成指定比特长度的素数
    '''
    def generate_bit_prime(self, bit):
        p = random.randint(2**(bit-1), 2**bit-1)
        while not self.miller_rabin(p, 5):#5次素性检测
            p = random.randint(2**(bit-1), 2**bit-1)
        return p
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
    def hash_byte_to_int(self, byte_m):
        hash_obj = hashlib.sha256()#创建SHA-256哈希对象
        hash_obj.update(byte_m)#更新哈希对象，添加数据
        hash_m=hash_obj.hexdigest()#十六进制表示,hash_m是str类型,64字符
        return int(hash_m,16)
    
#定义签名者P类
class P(Sub_function):#P继承自Sub_function
    def __init__(self ):
        self.p = None#P的秘密
        self.q = None#P的秘密
        self.s = None#P的秘密
        self.n = None#公开
        self.v = None#公开
        self.m = None#签名内容
    '''
    功能：签名者产生参数p\q\s\n\v
    参数传递：bit-生成的p\v的比特长度
    返回值：公开参数n\v
    '''
    def parameterSelection(self,bit):
        self.p = super().generate_bit_prime(bit)
        self.q = super().generate_bit_prime(bit)
        self.n = self.p*self.q
        self.s = super().generate_bit_prime(bit)
        self.v = pow(self.s, 2, self.n)
        print("请输入待签名的内容：")
        self.m = input()
        return self.n, self.v
    '''功能：Fiat_Shamir签名协议形成签名 '''
    def Fiat_Shamir_p(self):
        self.r = random.randint(1 ,self.n-1)#r<n
        x = pow(self.r, 2 ,self.n)#签名的第一个部分
        byte_m = self.m.encode('utf-8')#将str类型签名内容转化为byte类型
        byte_length = (x.bit_length() + 7) // 8 # 确定需要多少个字节来存储这个整数
        byte_x = x.to_bytes(byte_length, 'big') 
        hash_x_m = super().hash_byte_to_int(byte_m + byte_x)
        y = (self.r*super().fast_mod_pow(self.s, hash_x_m, self.n))%self.n#签名第二部分
        print(f"签名者对{self.m}的签名为：{x},{y}")
        return x,y#发给验签者V

#定义验签者V类       
class V(Sub_function):#V继承自Sub_function
    def __init__(self):
        self.n = None#P的公开参数
        self.v = None#P的公开参数
    
    '''功能：Fiat_Shamir签名协议验签 '''
    def Fiat_Shamir_v(self, m, x, y):
        byte_m = m.encode('utf-8')#将str类型签名内容转化为byte类型
        byte_length = (x.bit_length() + 7) // 8 # 确定需要多少个字节来存储这个整数
        byte_x = x.to_bytes(byte_length, 'big') 
        hash_x_m = super().hash_byte_to_int(byte_m + byte_x)
        return (pow(y, 2, self.n) == (x*super().fast_mod_pow(self.v, hash_x_m, self.n))%self.n) if True else False
        
def main():#Fiat-Shamir数字签名协议
    example_V = V()#验签者
    example_P = P()#签名者
    bit = 16
    example_V.n, example_V.v = example_P.parameterSelection(bit)
    x, y =example_P.Fiat_Shamir_p()
    if example_V.Fiat_Shamir_v(example_P.m, x, y):
        print("经过验签者验签，验签成功！")
    else:
        print("经过验签者验签，验签失败！")
        
if __name__ == "__main__":
    main()   

