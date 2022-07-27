# 实验名称
deduce_pk

# 实验简介
尝试从ECDSA签名恢复公钥

# 实验完成人
权周雨 

学号：202000460021 

git账户名称：baekhunee

# 运行指导
代码可以直接运行

# 实验思路
## ECDSA签名生成过程
```
  规定待签名的消息为M，n为椭圆曲线的可倍积阶数,G为所有点倍积运算的基点，私钥d=rand(1,n-1),公钥Q=d*G。
  1、计算E=HASH(M)。
  2、计算Z，来自E的二进制形式下最左边（即最高位）的l个比特，其中l是n的二进制长度。
  3、从[1,n-1]中随机选取一个符合整数k，注意每次生成新的数字签名时k都要更新。
  4、计算(x1,y1)=k*G
  5、计算：r = x1 mod n,如果r等于0，返回步骤三重新计算。
  6、计算：s = k^(-1)(z+rd) mod n
  7、生成的签名即为(r,s)
```
 
## 公钥恢复
```
  接收方是有可能恢复签名方的公钥的，关键在于确定公钥在椭圆曲线上的坐标，具体过程如下所示：
  1、首先验证r和s是否是属于[1,n-1]的整数，如果不是那么该签名无效。
  2、计算点R=(x1,y1)，其中x1是r,r+n,r+2n等其中之一，y1是满足椭圆曲线方程式的值。这里需要注意的是有可能会有不同的R，那么产生的已恢复密钥也会不同。
  3、计算E=HASH(M)，哈希函数与生成签名时所用的相同。
  4、计算Z，来自E的二进制形式下最左边（即最高位）的l个比特，其中l是n的二进制长度。
  5、计算：
     u1 = -zr^(-1) mod n
     u2 = sr^(-1) mod n
  6、计算Q =（x_a,y_a）=u1*G+u2*R
     如果Q匹配签名方的公钥则签名有效，如果尝试了所有可能的R且未能匹配签名方的公钥，则签名无效。
     无效的签名或来自其他消息的签名将导致恢复不正确的公钥，如果事先知道签名者的公钥，则恢复算法只能用于检查签名的有效性。
```
  按照以上思路逐步实现代码即可。
  
# 部分代码说明
## def isQR(n,p)
判断二次剩余
## def QR(n,p)
求解二次剩余
## def egcd(B,N)与def xgcd(b,n)
扩展欧几里得算法求逆元
## def epoint_add(P,Q)
椭圆曲线上的加法（P与Q不等）
## def epoint_add1(P)
椭圆曲线上的加法（P与Q相等）
## def epoint_mul(k,g)
椭圆曲线上的点乘
## def keygen()
生成公私钥对
## def signature(sk, m)
使用私钥sk对m进行签名
## def deduce_pk(sign,m)
从签名反推出公钥

# 测试截图
## pk1与原公钥匹配
![image](https://user-images.githubusercontent.com/105578152/181173613-b397fde5-68ad-4fa2-ab64-86877c020b0c.png)

## pk2与原公钥匹配
![image](https://user-images.githubusercontent.com/105578152/181173523-0467e8be-7e6c-4637-b8d3-5df4a6c4e090.png)

# 参考链接：
【1】CSDN：密码学系列 - 椭圆曲线 ECDSA - 签名与验签https://blog.csdn.net/wcc19840827/article/details/103857971
