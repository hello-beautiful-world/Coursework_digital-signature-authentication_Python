# -*- coding: utf-8 -*-
from charm.toolbox.pairinggroup import PairingGroup, G1, G2, GT, ZR
        p = int.from_bytes(get_random_bytes(byte), byteorder='big')
        while not self.miller_rabin(p, 5):#5次素性检测
            p = int.from_bytes(get_random_bytes(byte), byteorder='big')
        return p
#KGC类
class KGC(Sub_function): #KGC继承自Sub_function
    def __init__(self, group):
        self.group = group
        self.s = None#系统私钥
    '''功能：系统参数生成'''
    def KGC_key_generation(self):
        P = self.group.random(G1)  # 从群G1中随机选择一个元素作为生成元
        self.s = self.group.random(ZR)  # 系统私钥
        P_pub = P ** self.s  # 系统公钥，倍点运算
        return P, P_pub
    '''功能：用户私钥生成'''
    def user_key_generation(self, ID):
        Q_id = self.group.hash(ID)  # 用户公钥
        d_id = Q_id ** self.s  # 计算用户的私钥
        return   d_id
#定义签名者Signer类
class Signer(Sub_function):#Signer继承自Sub_function
    def __init__(self,  group):
        self.group = group
        self.d_id = None#签名者私钥
    '''功能：用户签名生成'''
    def sign(self,P):
        print("请输入消息m：")
        m = input()
        k = self.group.random(ZR)  
        R = P**k
        x_R = R.affine_x()#取横坐标
        hash_m = self.group.hash(m)  # 对str类型消息进行哈希处理
        S = (self.d_id ** x_R + P ** hash_m) * self.group.invert(k, ZR) 
        return m, R, S

#定义验签者Verifier类       
class Verifier(Sub_function):#Verifier继承自Sub_function
    def __init__(self,  group):
        self.group = group
    '''功能：验签'''
    def verify(self,ID, m, R, S, P,P_pub):
        Q_id = self.group.hash(ID)  
        hash_m = self.group.hash(m)  #对str类型消息进行哈希处理
        left = pair(R, S)
        right = (pair(P, P)**hash_m)*(pair(P_pub,  Q_id )**(R.affine_x()))
        return left == right  # 比较两边是否相等，以验证签名
        
def main():#基于身份ElGamal数字签名(未安装库)
     group = PairingGroup('SS512')
     example_KGC = KGC(group)
     example_Signer =Signer(group)
     example_Verifier = Verifier(group)
     print("请输入签名者ID：")
     ID = input()
     #生成系统参数
     P, P_pub = example_KGC.KGC_key_generation()
     # 生成用户私钥
     example_Signer.d_id = example_KGC.user_key_generation(ID)
     # 签名
     m, R, S = example_Signer.sign(P)
     #验签
     if example_Verifier.verify( ID, m, R, S, P,P_pub):
         print("验签成功！")
     else:
         print("验签失败！")
    
if __name__ == "__main__":
    main()  


