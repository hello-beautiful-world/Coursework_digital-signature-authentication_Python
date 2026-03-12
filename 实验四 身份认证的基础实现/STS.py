# -*- coding: utf-8 -*-
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import random
import hashlib

#需要用到的功能函数
class Sub_function:
    '''    
    功能：模乘运算
    '''
    def mod_mul(self, num1, num2, mod):
        return (num1 % mod)*(num2 % mod) % mod  # 每次中间计算时就取模操作
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
    '''功能：在模p的简化剩余系中寻找一个本原元，注意此代码获得的是最小的本原元'''
    def find_peimitive_element(self,p):
        euler_p = p - 1
        factors = set()#集合存放p-1的素因子
        factor = 2#从2开始
        while euler_p > 1:
            if euler_p % factor==0:
                factors.add(factor)
                while euler_p % factor==0:
                    euler_p//=factor#!保证后续加入集合的factor都为素数，注意使用//
            factor+=1
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
    '''
    功能：快速模幂运算
    参数传递：base-底数，exp-指数，mod-模数'''
    def fast_mod_pow(self,base, exp, mod):
        result = 1  # 运算结果初始化为1
        base = base % mod
        while exp > 0:
            if exp % 2 == 1:  # 最低为是否为1
                result = (result*base) % mod
            exp = exp >> 1  # 右移1位
            base = (base*base) % mod
        return result
    '''
    功能：扩展的欧几里得算法,求逆元
    '''
    def extended_gcd(self,num1, num2):
        x, y, u, v = 0, 1, 1, 0
        while num1:
            q, r = divmod(num2, num1)
            num2, num1 = num1, r
            x, y, u, v = u - q * x, v - q * y, x, y
        return num2, v % num1 if num1 > 1 else v
    '''
    功能：生成指定字节长度的素数
    '''
    def generate_bit_prime(self,byte):
        p = int.from_bytes(get_random_bytes(byte), byteorder='big')
        while not self.miller_rabin(p, 5):#5次素性检测
            p = int.from_bytes(get_random_bytes(byte), byteorder='big')
        return p
    '''功能：生成DH密钥交换的参数p(byte字节)、g'''
    def DH_p_g_generation(self,byte):
        p = self.generate_bit_prime(byte)
        g = self.find_peimitive_element(p)
        return p,g
    '''
    功能：对byte类型的消息进行哈希
    返回值：int(hash_m)-int类型的哈希值
    '''
    def hash_byte(self,byte_m):
        hash_obj = hashlib.sha256()#创建SHA-256哈希对象
        hash_obj.update(byte_m)#更新哈希对象，添加数据
        hash_m=hash_obj.digest()#计算SHA-256哈希值并将其转换为bytes类型
        return hash_m
    '''
    功能：AES加密（ECB模式）
    参数传递：key-用于加密的密钥（byte_len_key字节），plaintext-待加密消息，已填充为16字节的整数倍
    '''
    def AES_encrypt(self, key, plaintext):
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(plaintext)
    '''
    功能：AES解密（ECB模式）
    参数传递：key-用于解密的密钥（byte_len_key字节），ciphertext-待解密消息，已填充为16字节的整数倍
    '''
    def AES_decrypt(self, key, ciphertext):
        decipher = AES.new(key, AES.MODE_ECB)
        return decipher.decrypt(ciphertext) 
    '''
    功能：ElGamal签名算法
    返回值：签名int(hash_m,16), r, s
    '''
    def sign(self,str_m,p, g, x):
        k = random.randint(2, p-2)
        gcd, inverse_k = self.extended_gcd(k, p-1)
        while gcd != 1:
           k = random.randint(2, p-2)
           gcd, inverse_k = self.extended_gcd(k, p-1)
        #对信息的哈希值签名
        hash_obj = hashlib.sha256()#创建SHA-256哈希对象
        hash_obj.update(str_m.encode('utf-8'))#更新哈希对象，添加数据
        hash_m = hash_obj.hexdigest()#十六进制表示,hash_m是str类型,64字节
        #签名
        r = self.fast_mod_pow(g, k, p)
        #int()只能处理string,使用需要用十六进制string表示
        s = self.mod_mul(int(hash_m,16)-x*r, inverse_k, p-1)
        return int(hash_m,16), r, s

    '''
    功能：ElGamal验签
    返回值：是否为有效签名
    '''
    def verify_sign(self,y, p, g, m, r, s):
        if self.fast_mod_pow(g, m, p) == self.mod_mul(self.fast_mod_pow(y, r, p), self.fast_mod_pow(r, s, p), p):
            return True
        else:
            return False
#定义用户类       
class User(Sub_function):
    '''参数传递：ID（用户名） '''
    def __init__(self, ID):
        self.ID = ID
        self.pub_key =  None#由私钥生成的公钥，用于ElGamal签名
        self.pri_key  = None
        self.other_pub_key = None#与此用户进行认证的用户的公钥
        self.other_g_x_mod = None#与此用户进行认证的用户的的密钥协商数据
        self. g_x_mod =  None#自己的密钥协商数据
        self.Ks = None#存储会话密钥
    def generate_own_key(self, g ,p ):
        self.pri_key  = get_random_bytes(16)#byte类型私钥
        self.pub_key = super().fast_mod_pow(g, int.from_bytes(self.pri_key, byteorder = 'big'), p)#int类型公钥
        return self.pub_key#用户间交换公钥
    '''功能：KDC生成随机数计算自己的公钥，用于和用户进行Diffie-Hellman密钥协商'''
    def DH_pubKey(self, p, g):
        random_user = random.randint(2,p-1)#保证其小于p
        self.g_x_mod = super().fast_mod_pow(g, random_user, p)#调用父类（或超类）的方法 
        return self.g_x_mod
    '''功能：协商出16字节会话密钥'''
    def generate_sessionKey(self,p):
        g_xy_mod = (self.g_x_mod * self.other_g_x_mod  )%p
        byte_key = g_xy_mod.to_bytes(16,byteorder='big')
        self.Ks = super().hash_byte(byte_key)[:16]#取前16字节
    '''功能：STS协议第二步密钥确认'''
    def STS_B2(self, p, g):
        self.generate_sessionKey(p)#计算会话密钥
        str_m = str(self.g_x_mod) + str(self.other_g_x_mod)
        int_hash_m, r , s = super().sign(str_m, p, g, int.from_bytes(self.pri_key, byteorder = 'big'))#使用B的私钥签名
        Sign_B = r.to_bytes(16, byteorder='big')+s.to_bytes(16, byteorder='big')
        return super().AES_encrypt(self.Ks,Sign_B),int_hash_m
    '''功能：STS协议第二步用户A对收到的用户B的消息处理'''
    def STS_A2(self, E_Ks_B, p,g,int_hash_m):
        self.generate_sessionKey(p)#A计算会话密钥
        Sign_B = super().AES_decrypt(self.Ks, E_Ks_B)
        r = int.from_bytes(Sign_B[:16], byteorder = 'big')
        s = int.from_bytes(Sign_B[16:], byteorder = 'big')
        return super().verify_sign(self.other_pub_key, p, g, int_hash_m, r, s)
    '''功能：STS协议第三步，用户A向B发送'''
    def STS_A3(self, p ,g) :
        str_m = str(self.g_x_mod) + str(self.other_g_x_mod)
        int_hash_m, r , s = super().sign(str_m, p, g, int.from_bytes(self.pri_key, byteorder = 'big'))#使用A的私钥签名
        Sign_A = r.to_bytes(16, byteorder='big')+s.to_bytes(16, byteorder='big')
        return super().AES_encrypt(self.Ks,Sign_A),int_hash_m
    '''功能：STS协议第三步，用户B对收到的用户A的消息处理'''
    def STS_B3(self, E_Ks_A, p,g,int_hash_m2):
        Sign_A = super().AES_decrypt(self.Ks, E_Ks_A)
        r = int.from_bytes(Sign_A[:16], byteorder = 'big')
        s = int.from_bytes(Sign_A[16:], byteorder = 'big')
        return super().verify_sign(self.other_pub_key, p, g, int_hash_m2, r, s)
         
def main():
    print("请输入用户1的ID：",end="")
    ID_A = input()
    print("请输入用户2的ID：",end="")
    ID_B = input()
    print("****************STS协议*****************")
    #创建用户类
    user_A =User(ID_A)
    user_B =User(ID_B)
    sub_function = Sub_function()  
    byte = 2
    p, g = sub_function.DH_p_g_generation(byte)#生成参数p\g
    user_B.other_pub_key = user_A.generate_own_key(g,p)#拥有对方公钥的可信副本
    user_A.other_pub_key = user_B.generate_own_key(g,p)
    #第一步
    user_B.other_g_x_mod = user_A.DH_pubKey(p, g)#直接传输给对方
    print(f"第一步用户{ID_A}发送给用户{ID_B}的内容为：\n{user_B.other_g_x_mod}")
    #第二步
    user_A.other_g_x_mod = user_B.DH_pubKey(p, g)
    E_Ks_B ,int_hash_m= user_B.STS_B2( p, g)
    print(f"第二步用户{ID_B}发送给用户{ID_A}的内容为：\n{user_A.other_g_x_mod}\n{E_Ks_B}")
    if  not user_A.STS_A2(E_Ks_B, p, g, int_hash_m):
        print("认证失败")
        return
    else:
       print(f"对用户{ID_B}的身份验证通过！")
    #第三步
    E_Ks_A ,int_hash_m2= user_A.STS_A3( p ,g)
    print(f"第一步用户{ID_A}发送给用户{ID_B}的内容为：\n{E_Ks_A}")
    if not user_B.STS_B3( E_Ks_A, p,g,int_hash_m2):
        print("认证失败")
        return
    else:
       print(f"对用户{ID_A}的身份验证通过！")
    print("****************认证结束*****************")
       
if __name__ == "__main__":
    main()    