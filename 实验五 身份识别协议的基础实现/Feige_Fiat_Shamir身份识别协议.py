# -*- coding: utf-8 -*-
import random
#需要用到的功能函数
class Sub_function:
    '''功能：计算两个数的最大公因数'''
    def gcd(self, a, b):  
        while b != 0:
            a, b = b, a % b
        return a
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

#定义示证者P类
class P(Sub_function):#P继承自Sub_function
    def __init__(self ):
        self.n = None
        self.k = None#示证者选择的秘密值个数K
        self.s = []#k个与n互素的秘密值
        self.v = []#公钥，s^2modn
        self.r = None#鉴别协议流程第一步生成的数据，存储下来第三步使用
    '''功能：示证者选择秘密值和公钥'''    
    def parameterSelection(self, n):
        self.n = n
        self.k = 4#使用实例参数4
        for i in range(1, self.n):
            if super().gcd(i, self.n)==1 :
                self.s.append(i)#i与n互素
                self.v.append(pow(i, 2, self.n))#公钥
            if len(self.s) == self.k :#找到k个就停止
                break
        return self.v  #返回公钥    
    '''功能：Feige-Fiat-Shamir协议第1步 '''
    def Feige_Fiat_Shamir_1_p(self):
        self.r = random.randint(1 ,self.n-1)#r<n
        return pow(self.r, 2 ,self.n)#发给验证者V
    '''功能：Feige_Fiat_Shamir协议第3步 '''
    def Feige_Fiat_Shamir_3_p(self, a):
        y = self.r
        for i in range(self.k):
            y =(y*self.s[i]**a[i])%self.n 
        return y#发送给验证者V
        

#定义验证者V类       
class V(Sub_function):#V继承自Sub_function
    def __init__(self):
        self.a = []#鉴别流程第二步生成的数据，保存下来在第四步中使用
        self.v = []#P的公开参数
        self.k = 4#使用实例参数4
        self.n = None
        self.x = None#证明过程第一步的P发送给V数据,需要保存以提供给第四步
    '''功能： Feige_Fiat_Shamir协议第2步 '''
    def  Feige_Fiat_Shamir_2_v(self):
        for i in range(self.k):#循环k次
            self.a.append(random.randint(0, 1))#随机生成0或1
        return self.a#发送给P
    '''功能： Feige_Fiat_Shamir协议第4步 '''
    def  Feige_Fiat_Shamir_4_v(self, y):
        if y ==0:
            return False
        tmp = self.x
        for i in range(self.k):
            tmp =(tmp*self.v[i]**self.a[i])%self.n 
        return (pow(y, 2, self.n)==tmp) if True else False
       
def main():#Feige-Fiat-Shamir身份识别协议
    example_TA =TA()
    example_V = V()#验证者
    example_P = P()#示证者
    #系统初始化
    n = example_TA.TA_parameterSelection()
    example_V.v = example_P.parameterSelection(n)
    example_V.n = n
    print(f"n = {example_V.n},v = {example_V.v}")
    #第一步
    example_V.x = example_P.Feige_Fiat_Shamir_1_p()#把第一步的数据传给V
    print(f"第一步:\nP发送给V的数据为{example_V.x}")
    count = 5#验证次数
    i = 0
    while count > 0:#重复执行过程2到4
        i +=1
        print(f"*********第{i}次执行证明过程*********")
        #第二步
        a = example_V.Feige_Fiat_Shamir_2_v()
        print(f"第二步:\nv发送给p的数据为{a}")
        #第三步
        y = example_P.Feige_Fiat_Shamir_3_p(a)
        print(f"第三步:\nP发送给V的数据为{y}")
        #第四步
        if not example_V.Feige_Fiat_Shamir_4_v(y):
            print("验证失败，不接受P的身份！")
            break
        a.clear()#!!!注意清空列表元素
        count -= 1
    if count == 0 :
        print(f"经过{i}次验证，验证成功，V接受P的身份！")
if __name__ == "__main__":
    main()    



