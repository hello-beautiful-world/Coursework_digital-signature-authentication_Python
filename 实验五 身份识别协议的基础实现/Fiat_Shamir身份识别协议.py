# -*- coding: utf-8 -*-
import random
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
      

#定义示证者P类
class P(Sub_function):#P继承自Sub_function
    def __init__(self ):
        self.p = None#P的秘密
        self.q = None#P的秘密
        self.s = None#P的秘密
        self.n = None#公开
        self.v = None#公开
        self.r = None#证明过程第一步的数据,需要保存以提供给第三步
    '''
    功能：示证者产生参数p\q\s\n\v
    参数传递：bit-生成的p\v的比特长度
    返回值：公开参数n\v
    '''
    def parameterSelection(self,bit):
        self.p = super().generate_bit_prime(bit)
        self.q = super().generate_bit_prime(bit)
        self.n = self.p*self.q
        self.s = super().generate_bit_prime(bit)
        self.v = pow(self.s, 2, self.n)
        return self.n, self.v
    '''功能：Fiat_Shamir协议第1步 '''
    def Fiat_Shamir_1_p(self):
        self.r = random.randint(1 ,self.n-1)#r<n
        x = pow(self.r, 2 ,self.n)
        return x#发给验证者V
    '''功能：Fiat_Shamir协议第3步 '''
    def Fiat_Shamir_3_p(self, b):
        if b == 0:
            return self.r 
        else:
            return self.r*self.s
    
#定义验证者V类       
class V(Sub_function):#V继承自Sub_function
    def __init__(self):
        self.n = None#P的公开参数
        self.v = None#P的公开参数
        self.b = None#证明过程第二步的数据,需要保存以提供给第四步
        self.x = None#证明过程第一步的P发送给V数据,需要保存以提供给第四步
    '''功能：Fiat_Shamir协议第2步 '''
    def Fiat_Shamir_2_v(self):
        self.b = random.randint(0, 1)#随机生成0或1
        return self.b#发送给P
    '''功能：Fiat_Shamir协议第4步 '''
    def Fiat_Shamir_4_v(self, y):
        if self.b ==0:
            return (self.x==pow(y, 2, self.n)) if True else False
        else:
            return ((self.x*self.v - y**2)%self.n==0) if True else False
        
def main():#Fiat-Shamir识别协议
    example_V = V()
    example_P = P()
    bit = 3
    example_V.n, example_V.v = example_P.parameterSelection(bit)
    print(f"n = {example_V.n},v = {example_V.v}")
        #第一步
    example_V.x = example_P.Fiat_Shamir_1_p()
    print(f"第一步:\nP发送给V的数据为{example_V.x}")
    count = 5#验证次数
    i = 0
    while count > 0:#重复执行过程2到4
        i +=1
        print(f"***第{i}次执行证明过程***")
        #第二步
        b = example_V.Fiat_Shamir_2_v()
        print(f"第二步V产生的随机比特为{b}")
        #第三步
        y = example_P.Fiat_Shamir_3_p(b)
        print(f"第三步P发送给V的数据为{y}")
        #第四步
        if not example_V.Fiat_Shamir_4_v(y):
            print("验证失败，不接受P的身份！")
            break
        count -= 1
    if count == 0 :
        print(f"经过{i}次验证，验证成功，V接受P的身份！")
if __name__ == "__main__":
    main()    
