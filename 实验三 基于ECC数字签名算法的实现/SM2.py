# -*- coding: utf-8 -*-
import random
import hashlib
'''
功能：快速模幂运算
参数传递：base-底数，exp-指数，mod-模数
'''
def fast_mod_pow(base, exp, mod):
    result = 1  # 运算结果初始化为1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:  # 最低为是否为1
            result = (result*base) % mod
        exp = exp >> 1  # 右移1位
        base = (base*base) % mod
    return result
'''
功能：计算勒让德符号，其中p为奇素数
'''
def Lrgendre_symbol(num, p):
    if num%p == 0:#num是p的倍速
        return 0
    return fast_mod_pow(num , int((p-1)/2), p)
'''    
功能：模乘运算
'''
def mod_mul(num1, num2, mod):
    return (num1 % mod)*(num2 % mod) % mod  # 每次中间计算时就取模操作   

'''
功能：求num模p的逆元,此时num不限制大小
'''
def inverse(num, p):
    num = num%p
    x1, x2, x3 = 1, 0, p
    y1, y2, y3 = 0, 1, num
    while y3 != 0 and y3 != 1:
        Q = x3 // y3
        temp_y1, temp_y2, temp_y3 = y1, y2, y3
        y1, y2, y3 = x1 - Q * y1, x2 - Q * y2, x3 - Q * y3
        x1, x2, x3 = temp_y1, temp_y2, temp_y3
    return y2  # y3为最大公因子，y2为逆元
'''
功能：对byte类型的消息进行哈希
返回值：int(hash_m)-int类型的哈希值
'''
def hash_byte_to_int(byte_m):
    hash_obj = hashlib.sha256()#创建SHA-256哈希对象
    hash_obj.update(byte_m)#更新哈希对象，添加数据
    hash_m=hash_obj.hexdigest()#十六进制表示,hash_m是str类型,64字节
    return int(hash_m,16)
'''
功能:构造椭圆曲线y^2=x^3+ax+b(mod p)的点集
'''
def point_set( a, b, p):
    count = 0
    point_set = []
    x_value =[]#将遍历0到p-1的x的x^3+ax+b(mod p)的值(除去0)中有二次剩余的值和对应的x存储起来，避免后面重复计算
    for x in range(p):#遍历0到p-1
        tmp = (pow(x, 3, p) + a*x + b)%p
        Lrgendre = Lrgendre_symbol(tmp, p)
        if Lrgendre == 0:#tmp = 0
            point_set.append(( x, 0 ))#y只能为0,后续无需计算,直接存储在point_set中
            count +=1
        else:
            if Lrgendre == 1:
                x_value.append(( x, tmp))#为二次剩余，存储在x_value中
            else:
                continue#勒让德符号为-1，无二次剩余
    #求y
    for point in x_value:
        tmp = point[1]
        '''
        #此方法y从1到（p-1)/遍历,最多需要循环（p-1）/2次
        for i in range(1 , p):
            if pow(i,2,p) == tmp:
                y1 = i
                break
        '''
        #此方法循环次数最大为（（(p-1)/2）^2-tmp)/p + 1下取整
        while True:
            y1 = int(tmp**0.5)
            if y1**2 != tmp:
                tmp += p
            else:
                break
        point_set.append(( point[0], y1))
        y2 = p-y1 #一个x对应两个y都在曲线上，y1和y2不可能相等，成对出现
        point_set.append(( point[0], y2))
        count+=2#y1和y2两个点
    return point_set,count+1#加无穷远点

'''
功能：有限域上椭圆曲线的加法运算
'''
def addition(point1, point2, p,a):
    if point1 == ( 0 ,0 ):#若至少有一个点为无穷员点（0，0）
        return point2
    if point2 ==  ( 0 ,0 ):
        return point1
    if point1 ==(point2[0],p-point2[1]) or point2 ==(point1[0],p-point1[1]):#注意这里不能直接加负号判断
        return (0,0)
    if point1 == point2:
        tmp =  ( (3*pow(point1[0], 2)+a) * inverse(2*point1[1], p) )%p
    else:
        tmp = ((point2[1]-point1[1]) * inverse(point2[0]-point1[0], p)) %p
    x3 = (tmp**2 -point1[0]- point2[0])%p
    y3 = (tmp*(point1[0] - x3)-point1[1] )%p
    return (x3, y3)
'''
功能：有限域上椭圆曲线的高效倍点运算
'''
def EDPC(n, point, p, a):
    Q = point 
    R = (0,0)
    while n>0:
        if n%2 ==1:
            R =addition(R, Q, p,a)
        n = n>>1#从最低位开始，右移一位取下一位
        Q = addition(Q, Q, p,a)
    return R
'''
功能：求椭圆曲线中一个点G的阶
'''
def order_point(G, p, a,order_groud):
    for i in range (1,order_groud+1):
        if EDPC(i, G, p, a)==(0,0):        
            return i       

'''
功能：生成SM2签名体系所需要的参数p,a,b,G（基点）,n,公钥Q,私钥d
'''
def generate_parameter():
    p, a, b =23, 1 ,1
    G = ( 3, 10 )#p为奇素数，不能为2，后续要计算勒让德符号
    point_list=[]
    point_list,order_groud = point_set( a, b, p)
    n = order_point(G, p, a,order_groud)
    d = random.randint(1, n-2)
    tmp = EDPC(d, G, p, a)
    Q = (tmp[0]%n,tmp[1]%n)#公钥为dG (mod n)
    return p, a, b, G, n, d, Q


'''
功能：SM2签名生成
'''
def SM2_sign(str_m, n, G, p, a, d):
    '''byte_m = str_m.encode('utf-8')#将str类型消息转化为byte类型
    hash_m = hash_byte_to_int(byte_m)'''
    hash_m =3
    while True:
        k = random.randint(1,n-1)
        kG = EDPC(k, G, p, a)
        x1=kG[0]
        r = (hash_m  + x1)%n
        if r ==0 or r ==n-k:
            continue
        else: 
            s =  ( inverse(1 + d, n) * (k - r*d) )%n
            return r,s
'''
功能：SM2签名验证
'''
def SM2_verify_sign(str_m, r, s, n, Q, G, p, a):
    if  r < 1 or r >= n or s < 1 or s >= n:
        return False
    '''byte_m = str_m.encode('utf-8')#将str类型消息转化为byte类型
    hash_m = hash_byte_to_int(byte_m)'''
    hash_m =3
    t = (r + s) % n
    if t ==0:
        return False
    x_y = addition(EDPC(s, G, p, a), EDPC(t,Q , p, a), p,a)
    x1_ver = x_y[0]
    R = (hash_m + x1_ver) % n
    if R==r:
        return True
    else:
        return False
def main():
    str_m="a"
    p, a, b, G, n, d, Q = generate_parameter()
    print(f"签名所使用的p, a, b, G, n, d, Q={p, a, b, G, n, d, Q}")
    r, s = SM2_sign(str_m, n, G, p, a, d)
    print(f"e=3\n签名(r,s)为:\n{r,s}")
    if SM2_verify_sign(str_m, r, s, n, Q, G, p, a):
        print("经过验签，签名有效")
    else:
        print("经过验签，签名无效")


if __name__ == "__main__":
    main()    


