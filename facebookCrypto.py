from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from nacl.public import PrivateKey, PublicKey, Box
from nacl.secret import SecretBox
from nacl.utils import random
import hashlib
import base64
import os

# 基础参数定义
j = 64
k = 1
l = 1
m = 1
n = 2
o = 32
p = 16
overheadLength = 48
q = l + m + n + o + overheadLength + p

# 处理公钥
def s(a):
    b = []
    for c in range(0, len(a), 2):
        b.append(int(a[c:c+2], 16))
    return b

# BLAKE2b 更新
def BLAKE2b_Update(input_a, input_b, nonce_length):
    # 初始化 BLAKE2b 哈希对象
    blake2b = hashlib.blake2b(digest_size=nonce_length)

    # 更新哈希内容
    blake2b.update(input_a)
    blake2b.update(input_b)

    # 计算并返回最终的哈希值
    return blake2b.digest()

# 使用 PBKDF2 派生函数生成一个 256 位（32 字节）AES-GCM 密钥
def generate_aes_gcm_key():
    # 您可以选择随机生成一个密码（如 os.urandom(16)）或直接使用硬编码密码（不推荐）
    password = os.urandom(16)  # 生成一个随机密码
    salt = os.urandom(16)      # 生成一个随机盐值

    # 创建 KDF（密钥派生函数），用于生成固定长度的密钥
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,           # 32 字节 = 256 位
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    # 生成密钥（此处的 key 是 256 位长度的 AES-GCM 密钥）
    key = kdf.derive(password)
    return key

# AES-GCM 加密函数
def encrypt_aes_gcm(key, data, iv, additional_data):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(additional_data)
    
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return ciphertext + encryptor.tag

# 导出私钥和公钥为原始字节格式
def export_key_bytes(private_key, public_key):
    # 导出私钥为 32 字节
    private_key_bytes = private_key.private_numbers().private_value.to_bytes(32, byteorder='big')
    
    # 导出公钥为 32 字节 (x 坐标)
    public_key_bytes = public_key.public_numbers().x.to_bytes(32, byteorder='big')
    
    return private_key_bytes, public_key_bytes

# 生成共享密钥，类似于 `box.before`
def generate_shared_key(sender_private_key, receiver_public_key):
    box = Box(sender_private_key, receiver_public_key)
    return box.shared_key()

# 加密消息
def encrypt_message(b, c, d, e):
    receiver_public_key = PublicKey(d) 
    
    # 生成共享密钥 d 和 e 相当于 sender_private_key 和 receiver_public_key
    shared_key = generate_shared_key(e, receiver_public_key)
    
    # 使用共享密钥创建 SecretBox
    secret_box = SecretBox(shared_key)
    
    encrypted_message = secret_box.encrypt(b, c)
    return encrypted_message[24:]

# 加密数据
def encrypt(keyId, pubkey, pwd, date):
    # 密码字符转 Ascii
    p_ascii = pwd.encode('utf-8')
    d_ascii = date.encode('utf-8')
    g = q + len(p_ascii)
    
    # 进入加密逻辑判断
    if (len(pubkey) != j):
        return "public key is not a valid hex sting"
    
    t = bytes(s(pubkey))
    if (len(t) == 0):
        return "public key is not a valid hex string"
    
    u = bytearray([0] * g)
    v = 0
    
    u[v] = k
    v += l
    u[v] = int(keyId)
    v += m
    
    # 加密流程
    key = generate_aes_gcm_key()    # 生成 AES-GCM 256 位密钥
    iv = bytearray(12)              # 生成 12 字节的随机 IV（推荐的 GCM IV 大小）
    data = p_ascii                  # 要加密的数据（字节格式）
    additional_data = d_ascii       # 附加数据
    
    # 生成基础 Aes-gcm 密文
    ciphertext = encrypt_aes_gcm(key, data, iv, additional_data)
    
    # 密钥生成前序工作完成！

    # 生成 ECDH 算法
    private_key = PrivateKey.generate()  # 生成私钥
    public_key_bytes = private_key.public_key.encode()

    # var c = new Uint8Array(g.a + a.length)
    sealKey = bytearray((overheadLength + len(public_key_bytes)))
    sealKey[:32] = public_key_bytes
    
    # 更新签名密钥
    i = BLAKE2b_Update(public_key_bytes, t, 24)
    
    # 计算共享密钥
    a = encrypt_message(key, i, t, private_key)
    
    # 组合共享密钥
    sealKey[32:] = a
    
    # 进入下一阶段
    u[v] = len(sealKey) & 255
    u[v + 1] = len(sealKey) >> 8 & 255
    v += n
    u[v:] = sealKey
    v += o
    v += overheadLength
    
    if (len(sealKey) != o + overheadLength):
        return "encrypted key is the wrong length"
    
    # 取倒数十六个字节
    a = ciphertext[-p:]
    b = ciphertext[0: -p]
    u[v:] = a
    v += p
    u[v:] = b
    
    return base64.b64encode(u).decode('utf-8')