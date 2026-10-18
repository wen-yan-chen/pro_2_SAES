# saes/core.py

# S盒和逆S盒
S_BOX = [
    [0x9, 0x4, 0xA, 0xB],
    [0xD, 0x1, 0x8, 0x5],
    [0x6, 0x2, 0x0, 0x3],
    [0xC, 0xE, 0xF, 0x7]
]

INV_S_BOX = [
    [0xA, 0x5, 0x9, 0xB],
    [0x1, 0x7, 0x8, 0xF],
    [0x6, 0x0, 0x2, 0x3],
    [0xC, 0x4, 0xD, 0xE]
]


def sub_nibbles(word, inverse=False):
    """半字节替换"""
    box = INV_S_BOX if inverse else S_BOX
    # 将16位拆分成4个4位
    n0 = (word >> 12) & 0xF
    n1 = (word >> 8) & 0xF
    n2 = (word >> 4) & 0xF
    n3 = word & 0xF

    n0 = box[n0 >> 2][n0 & 0x3]
    n1 = box[n1 >> 2][n1 & 0x3]
    n2 = box[n2 >> 2][n2 & 0x3]
    n3 = box[n3 >> 2][n3 & 0x3]

    return (n0 << 12) | (n1 << 8) | (n2 << 4) | n3


def shift_rows(word, inverse=False):
    """行移位：交换第2个和第4个半字节"""
    n0 = (word >> 12) & 0xF
    n1 = (word >> 8) & 0xF
    n2 = (word >> 4) & 0xF
    n3 = word & 0xF

    # 无论正向还是逆向，行移位都是交换 n1 和 n3
    return (n0 << 12) | (n3 << 8) | (n2 << 4) | n1


def gf_mult(a, b):
    """GF(2^4) 上的乘法，多项式为 x^4 + x + 1 (0b10011)"""
    p = 0
    for _ in range(4):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x8
        a = (a << 1) & 0xF
        if hi_bit_set:
            a ^= 0x3  # x^4 + x + 1 的简化形式
        b >>= 1
    return p


def mix_columns(word, inverse=False):
    """列混淆"""
    n0 = (word >> 12) & 0xF
    n1 = (word >> 8) & 0xF
    n2 = (word >> 4) & 0xF
    n3 = word & 0xF

    if not inverse:
        # 矩阵: [[1, 4], [4, 1]]
        r0 = gf_mult(n0, 1) ^ gf_mult(n1, 4)
        r1 = gf_mult(n0, 4) ^ gf_mult(n1, 1)
        r2 = gf_mult(n2, 1) ^ gf_mult(n3, 4)
        r3 = gf_mult(n2, 4) ^ gf_mult(n3, 1)
    else:
        # 逆矩阵: [[9, 2], [2, 9]]
        r0 = gf_mult(n0, 9) ^ gf_mult(n1, 2)
        r1 = gf_mult(n0, 2) ^ gf_mult(n1, 9)
        r2 = gf_mult(n2, 9) ^ gf_mult(n3, 2)
        r3 = gf_mult(n2, 2) ^ gf_mult(n3, 9)

    return (r0 << 12) | (r1 << 8) | (r2 << 4) | r3


def expand_key(key):
    """密钥扩展：生成3个轮密钥"""
    # 将16位密钥分成两个字（8位）
    w0 = (key >> 8) & 0xFF
    w1 = key & 0xFF

    # 轮常数
    rcon1 = 0x80
    rcon2 = 0x30

    # 生成 w2, w3
    temp = ((w1 << 4) & 0xFF) | (w1 >> 4)  # 字节内半字节交换
    temp = sub_nibbles((temp << 8) | temp) >> 8  # 借用一下替换函数查S盒(取高8位)
    w2 = w0 ^ rcon1 ^ temp
    w3 = w2 ^ w1

    # 生成 w4, w5
    temp = ((w3 << 4) & 0xFF) | (w3 >> 4)
    temp = sub_nibbles((temp << 8) | temp) >> 8
    w4 = w2 ^ rcon2 ^ temp
    w5 = w4 ^ w3

    # 组合成三个16位轮密钥
    k0 = (w0 << 8) | w1
    k1 = (w2 << 8) | w3
    k2 = (w4 << 8) | w5

    return k0, k1, k2


def add_round_key(state, round_key):
    """轮密钥加"""
    return state ^ round_key


def s_aes_encrypt(plaintext, key):
    """S-AES 加密主函数"""
    k0, k1, k2 = expand_key(key)

    # 初始轮密钥加
    state = add_round_key(plaintext, k0)

    # 第1轮
    state = sub_nibbles(state)
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_round_key(state, k1)

    # 第2轮
    state = sub_nibbles(state)
    state = shift_rows(state)
    state = add_round_key(state, k2)

    return state


def s_aes_decrypt(ciphertext, key):
    """S-AES 解密主函数"""
    k0, k1, k2 = expand_key(key)

    # 初始轮密钥加
    state = add_round_key(ciphertext, k2)

    # 第1轮
    state = shift_rows(state, inverse=True)
    state = sub_nibbles(state, inverse=True)
    state = add_round_key(state, k1)
    state = mix_columns(state, inverse=True)

    # 第2轮
    state = shift_rows(state, inverse=True)
    state = sub_nibbles(state, inverse=True)
    state = add_round_key(state, k0)

    return state