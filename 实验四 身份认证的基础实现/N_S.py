# -*- coding: utf-8 -*-
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import random
import hashlib

byte_len_key =16#使用AES128，要求密钥长度为16字节，加密内容字节长度为16的整数倍

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
#定义KDC类
class KDC(Sub_function):#KDC继承自Sub_function
    '''
    功能：初始化
    参数传递：ID（ID列表）, hash_password（口令哈希值列表）, key_KDC(对应用户与KDC之间密钥列表), Ks（会话密钥）'''
    def __init__(self, ID, hash_password, key_KDC, Ks):
        self.user = [[ID[i], hash_password[i], key_KDC[i]]for i in range(len(ID))]
        self.Ks =Ks#此代码只需要两个用户间双向认证、形成会话密钥，因此只存一个Ks
    '''功能：打印user'''
    def display(self):
        for row in self.user:
            print(row)
    '''功能：KDC生成随机数计算自己的公钥，用于和用户进行Diffie-Hellman密钥协商'''
    def DH_pubKey(self, p, g, byte):
        random_kdc = random.randint(2,p-1)#保证其小于p
        return super().fast_mod_pow(g, random_kdc, p)#调用父类（或超类）的方法 
    '''
    功能：KDC收到用户发来的公钥num_user，计算会话密钥
    参数传递： p-DH共享参数p, num_user-用户发来的公钥,num_kdc-KDC自己的公钥
    返回值：用户和KDC间的16字节会话密钥
    '''
    def DH_sessionKey(self, p, num_user,num_kdc,ID):
        count = 0
        for sublist in self.user:
            if  sublist[0] == ID:#找到对应用户ID的子列表
                key = (num_user*num_kdc)%p
                byte_key = key.to_bytes(byte_len_key, byteorder='big')#int转化为byte类型用于哈希
                hash_key= super().hash_byte(byte_key)
                self.user[count][2] = hash_key[:byte_len_key]#只取前16字节
                break
            count+=1
    '''功能：KDC处理N_S协议第一步接受到的数据,验证用户的口令哈希值是否与KDC存储的内容相同'''
    def N_S_KDC_1(self, request_ticket):
        hash_pw = super().hash_byte(request_ticket[byte_len_key*3:])
        count = 0
        receiving_ID1 = unpad(request_ticket[:byte_len_key], byte_len_key).decode('utf-8')#前16字节,先去掉填充再转字符串
        for sublist in self.user:
            if  sublist[0] == receiving_ID1:#找到对应用户ID的子列表
                if hash_pw == self.user[count][1]:
                    return True
            count+=1
        return False
    ''''功能：N-S协议第二步，KDC生成两个用户间的会话密钥，生成并发送票据给A'''
    def N_S_KDC_2(self, request_ticket):
        self.Ks = get_random_bytes(byte_len_key)#随机生成16字节会话密钥
        receiving_ID2 = unpad(request_ticket[byte_len_key:byte_len_key*2], byte_len_key).decode('utf-8')#前16字节,先去掉填充再转字符串
        count = 0
        for sublist in self.user:#形成票据
            if  sublist[0] == receiving_ID2:#找到对应用户ID的子列表
                E_Kb = super().AES_encrypt(self.user[count][2], self.Ks + request_ticket[:byte_len_key])
            count+=1
        count = 0
        receiving_ID1 = unpad(request_ticket[:byte_len_key], byte_len_key).decode('utf-8')#前16字节,先去掉填充再转字符串
        for sublist in self.user:
            if  sublist[0] == receiving_ID1:#找到对应用户ID的子列表,找到其与KDC的会话密钥
                E_Ka = super().AES_encrypt(self.user[count][2], self.Ks + request_ticket[byte_len_key:byte_len_key*3] + E_Kb)
            count+=1
        return E_Ka
#定义用户类       
class User(Sub_function):
    '''参数传递：ID, password（口令明文）, key_KDC（用户与KDC间的密钥）, Ks（用户间的会话密钥）'''
    def __init__(self, ID, password, key_KDC, Ks, N1, N2):
        self.ID = ID
        self. password =  password
        self.key_KDC = key_KDC
        self.Ks = Ks
        self.N1 = N1#对应申请认证者，N1存储第一步生成的随机数；对于认证者，N1存储第四步生成的随机数
        self.N2 = N2##对应申请认证者，N2存储第三步生成的随机数;对于认证者，N2存储第三步获得的申请认证者生成的N2
    '''
    功能：用户生成随机数计算自己的公钥，用于和KDC进行DH密钥交换
    参数传递：p\g--DH密钥交换参数'''
    def DH_pubKey(self, p, g, byte):
        random_user = random.randint(2,p-1)
        return super().fast_mod_pow(g, random_user, p)#调用父类（或超类）的方法
        
    '''
    功能：用户收到KDC发来的公钥num_kdc，计算会话密钥
    参数传递： p-DH共享参数p, num_user-用户自己的公钥,num_kdc-KDC发来的公钥
    返回值：用户和KDC间的会话密钥
    '''
    def DH_sessionKey(self, p, num_user,num_kdc):
        key = (num_user*num_kdc)%p
        byte_key = key.to_bytes(byte_len_key, byteorder='big')
        hash_key= super().hash_byte(byte_key)
        self.key_KDC = hash_key[:byte_len_key]#只取前16字节，符合后续AES对密钥的要求
        print(f"用户{self.ID}与KDC间的密钥为：\n{self.key_KDC}")
    ''''功能：N-S协议第一步，用户A请求票据'''
    def N_S_UserA_1(self, ID_B):
        self.N1 = get_random_bytes(byte_len_key)
        padded_ID_A = pad(self.ID.encode('utf-8'),byte_len_key)
        padded_ID_B = pad(ID_B.encode('utf-8'),byte_len_key)
        return b''.join([padded_ID_A, padded_ID_B, self.N1,self.password.encode('utf-8')])#把口令一起传过去
    '''功能：N-S协议第三步，接收票据，用户A处理N-S协议第二步KDC发来的内容，核对N1\ID_B，存储Ks,将票据转发给用户B'''
    def N_S_UserA_3(self, ID_B,ticket):
        pt = super().AES_decrypt( self.key_KDC, ticket)
        padded_ID_B = unpad(pt[byte_len_key:byte_len_key*2], AES.block_size).decode('utf-8')
        if padded_ID_B==ID_B and self.N1 == pt[byte_len_key*2:byte_len_key*3]:
            self.Ks = pt[:byte_len_key]
            self.N2 = get_random_bytes(byte_len_key)
            E_Ks_N2 = super().AES_encrypt(self.Ks, self.N2)
        return  pt[byte_len_key*3:], E_Ks_N2#直接转发
    '''功能：N-S协议第四步，B接收票据，B处理N-S协议第三步A发来的内容，获得ID_A,存储Ks,使用会话密钥加密N2发送给A'''
    def  N_S_UserB_4(self, ticket_B, E_Ks_Na2):
        #处理A发的消息，获得Ks和NA'
        pt = super().AES_decrypt( self.key_KDC, ticket_B)
        self.Ks = pt[:byte_len_key]
        self.N2 = super().AES_decrypt( self.Ks, E_Ks_Na2)#byte类型,注意
        #生成随机数N2（存储在N1中）,将其和NA'-1一起使用Ks加密发给A
        self.N1 = get_random_bytes(byte_len_key)
        return super().AES_encrypt(self.Ks, self.N1+ (int.from_bytes(self.N2, 'big')-1).to_bytes(16, 'big'))
    '''功能：N-S协议第五步，用户A处理B发的消息，解密后核对NA'-1，获得N2，将f(N2)加密后发给B'''
    def N_S_UserA_5(self,E_Ks_B4):
        pt = super().AES_decrypt( self.Ks, E_Ks_B4 )
        if self.N2 == ((int.from_bytes(pt[byte_len_key:], 'big')+1).to_bytes(byte_len_key, 'big')):#核对NA'-1
            return super().AES_encrypt( self.Ks, (int.from_bytes(pt[:byte_len_key], 'big')+1).to_bytes(byte_len_key, 'big'))#f(N2)加密后发给B
        else:
            return False
    '''功能：N-S协议第五步，用户B处理A发的消息，解密后核对N2(在B中存放在N1)'''
    def N_S_UserB_5(self,E_Ks_A5):
        pt = super().AES_decrypt( self.Ks, E_Ks_A5 )
        if self.N1 == (int.from_bytes(pt, 'big')-1).to_bytes(byte_len_key, 'big'):#核对N2
            return True
        else:
            return False
        
def main():#双向认证
    sub_function = Sub_function()     
    #创建User类的用户A、B
    print("**********用户在KDC中注册**********")
    print("请输入用户1的ID：",end="")
    ID_A =input()
    print("请输入用户1的口令：",end="")
    password_A =input()
    print("请输入用户2的ID：",end="")
    ID_B =input()
    print("请输入用户2的口令：",end="")
    password_B =input()
    user_A ,user_B =User(ID_A, password_A, 0, 0,bytes(0),bytes(0)),User(ID_B, password_B, 0, 0,bytes(0),bytes(0))
    #创建KDC类的对象
    ID = [ID_A ,ID_B]#使用列表存放，便于放入KDC中
    byte_password_A = password_A.encode('utf-8')#将str类型转化为byte类型
    byte_password_B = password_B.encode('utf-8')
    hash_password = [sub_function.hash_byte(byte_password_A), sub_function.hash_byte(byte_password_B)]#存放口令对应哈希值
    key_KDC = [0, 0]
    KDC1 = KDC(ID, hash_password, key_KDC,0)
    #用户和KDC进行DH密钥协商，生成128比特长度的密钥
    print("用户和KDC进行DH密钥协商:")
    byte = 1
    #用户A
    p1, g1 = sub_function.DH_p_g_generation(byte)
    num_a = user_A.DH_pubKey( p1, g1,byte)#用户A生成自己的公钥用于和KDC密钥交换
    num_kdc1 = KDC1.DH_pubKey(p1, g1,byte)#KDC生成自己的公钥用于和用户A密钥交换
    user_A.DH_sessionKey( p1, num_a,num_kdc1)#用户A计算与KDC的会话密钥
    KDC1.DH_sessionKey( p1, num_a,num_kdc1,ID_A)#KDC计算与用户A的会话密钥
    #用户B
    p2, g2 = sub_function.DH_p_g_generation(byte)
    num_b = user_B.DH_pubKey( p2, g2, byte)#用户B生成自己的公钥用于和KDC密钥交换
    num_kdc2 = KDC1.DH_pubKey(p2, g2,byte)#KDC生成自己的公钥用于和用户B密钥交换
    KDC1.DH_sessionKey( p2, num_b,num_kdc2,ID_B)#用户B计算与KDC的会话密钥
    user_B.DH_sessionKey( p2, num_b,num_kdc2)#KDC计算与用户B的会话密钥
    print("KDC中存储的用户数据表（ID、口令哈希值、与KDC的会话密钥）:")
    KDC1.display()
    print("***************注册完成***************\n")
    print("***************双向认证***************")
    #第一步
    request_ticket = user_A.N_S_UserA_1(ID_B)#用户发出消息请求票据
    print("第一步用户A发给KDC的消息为：\n",request_ticket)
    if KDC1.N_S_KDC_1(request_ticket):
        print(f"用户{ID_A}口令正确，可继续认证！")
    else:
        print(f"用户{ID_A}口令错误，无法继续认证！")
        return 
    #第二步
    ticket = KDC1.N_S_KDC_2(request_ticket)
    print(f"第二步KDC发给用户{ID_A}的内容为：\n",ticket)
    #第三步
    ticket_B ,E_Ks_Na2 = user_A.N_S_UserA_3( ID_B,ticket)
    print(f"第三步用户{ID_A}发给用户{ID_B}的内容为：\n",ticket_B ,E_Ks_Na2)
    #第四步
    E_Ks_B4 = user_B.N_S_UserB_4(ticket_B, E_Ks_Na2)
    print(f"第四步用户{ID_B}发给用户{ID_A}的内容为：\n",E_Ks_B4)
    #第五步
    E_Ks_A5 = user_A.N_S_UserA_5(E_Ks_B4)
    if  not  E_Ks_A5 :#解密获得随机数与A保存的随机数对不上，认证失败
        print("认证失败！")
        return
    print(f"第五步用户{ID_A}发给用户{ID_B}的内容为：\n",E_Ks_A5)
    if user_B.N_S_UserB_5(E_Ks_A5):
        print("双向认证成功！")
    else:
        print("认证失败！")
    print("***************认证结束***************")
if __name__ == "__main__":
    main()    