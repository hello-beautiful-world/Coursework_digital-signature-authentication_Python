# -*- coding: utf-8 -*-
import random
import hashlib
#需要用到的功能函数
class Sub_function:
    '''功能：计算两个数的最大公因数'''
    def gcd(self, a, b):  
        while b != 0:
            a, b = b, a % b
        return a
    '''
    功能：对byte类型的消息进行哈希
    返回值：int类型的哈希值
    '''
    def hash_byte(self, byte_m):
        hash_obj = hashlib.sha256()#创建SHA-256哈希对象
        hash_obj.update(byte_m)#更新哈希对象，添加数据
        hash_m = hash_obj.hexdigest()# 获取字节类型的哈希值，长度固定为32字节
        return int(hash_m, 16)

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
#定义信任中心TA类
class TA(Sub_function): #TA继承自Sub_function
    def __init__(self ):    
        self.p = None#保密
        self.q = None#保密
        self.n = None#TA选择并公布的模数
    '''功能：TA选择RSA型模数n，此处选择实例参数n=35'''
    def TA_parameterSelection(self):
        self.p = 5
        self.q = 7
        self.n = self.p*self.q
        return self.n

#定义签名者P类
class P(Sub_function):#P继承自Sub_function
    def __init__(self ):
        self.n = None
        self.k = None#签名者选择的秘密值个数K
        self.s = []#k个与n互素的秘密值，私钥
        self.v = []#公钥，s^2modn
        self.e = []#挑战
    '''功能：签名者生成公钥v[]、私钥s[]'''   
    def generate_key(self):
        self.k = 4#使用实例参数4
        for i in range(1, self.n):
            if super().gcd(i, self.n)==1 :
                self.s.append(i)#i与n互素，私钥
                self.v.append(super().extended_gcd( pow(i, 2, self.n), self.n ))#公钥
            if len(self.s) == self.k :#找到k个就停止
                break   
        return self.v#返回公钥
        '''功能：签名''' 
    def sign(self):
        print("请输入待签名的内容：")
        m = input()
        r = random.randint(1 ,self.n-1)#r<n
        x = pow(r, 2 ,self.n)
        byte_m = m.encode('utf-8')
        byte_length = (x.bit_length() + 7) // 8 # 确定需要多少个字节来存储这个整数
        byte_x = x.to_bytes(byte_length, 'big') 
        hash_int = super().hash_byte(byte_m + byte_x)
        bin_str = format(hash_int, 'b')#转化为二级制串
        self.e = list(map(int, list(bin_str[-self.k:])))#生成挑战比特值列表
        s = r
        for i in range(self.k):
            s =(s*self.s[i]**self.e[i])%self.n #签名第二部分
        print(f"对{m}的签名为（ {self.e}，{s} ）")
        return m, self.e, s#返回签名e,s
        

#定义验签者V类       
class V(Sub_function):#V继承自Sub_function
    def __init__(self):
        self.k = 4#使用实例参数4
        self.n = None

    '''功能：验签 '''
    def  verify(self, v, m, e, s):
        u = pow(s, 2, self.n)
        for i in range(self.k):
            u = (u*pow(v[i], e[i], self.n))%self.n
        byte_m = m.encode('utf-8')
        byte_length = (u.bit_length() + 7) // 8 # 确定需要多少个字节来存储这个整数
        byte_u = u.to_bytes(byte_length, 'big') 
        hash_int = super().hash_byte(byte_m + byte_u)#byte类型
        bin_str = format(hash_int, 'b')#转化为二级制串
        e_v = list(map(int, list(bin_str[-self.k:])))#验签者生成挑战比特值列表
        return e_v == e
       
def main():#Feige-Fiat-Shamir数字签名协议
    example_TA =TA()
    example_V = V()#验签者
    example_P = P()#签名者
    #系统初始化
    n= example_TA.TA_parameterSelection()
    example_V.n , example_P.n = n, n 
    v = example_P.generate_key()
    #签名
    m, e, s = example_P.sign()
    #验签
    if example_V.verify(  v, m, e, s):
        print("经过验签者验签，验签成功！")
    else:
        print("经过验签者验签，验签失败！")
if __name__ == "__main__":
    main()   

