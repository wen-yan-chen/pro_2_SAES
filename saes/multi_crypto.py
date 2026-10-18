# saes/multi_crypto.py
from .core import s_aes_encrypt, s_aes_decrypt


def double_encrypt(plaintext, key32):
    """双重加密: C = Enc(K2, Enc(K1, P))"""
    k1 = (key32 >> 16) & 0xFFFF
    k2 = key32 & 0xFFFF
    return s_aes_encrypt(s_aes_encrypt(plaintext, k1), k2)


def double_decrypt(ciphertext, key32):
    """双重解密: P = Dec(K1, Dec(K2, C))"""
    k1 = (key32 >> 16) & 0xFFFF
    k2 = key32 & 0xFFFF
    return s_aes_decrypt(s_aes_decrypt(ciphertext, k2), k1)


def meet_in_the_middle_attack(plaintext, ciphertext, extra_pairs=None):
    """中间相遇攻击 (针对双重加密)

    对 C = Enc(K2, Enc(K1, P))：分别从两端各枚举 2^16 个 K1 / K2，
    用 16 bit 的中间值做碰撞匹配，把 2^32 的密钥空间降到 2×2^16 次运算。

    注意：分组只有 16 bit，仅凭一对明密文必然出现大量假阳性碰撞
    （实测约 6.5 万个候选），因此支持传入额外的明密文对来验证、收敛到唯一密钥。

    :param plaintext: 已知明文 (16 bit)
    :param ciphertext: 对应密文 (16 bit)
    :param extra_pairs: 额外的 [(明文, 密文), ...]，用于剔除假阳性
    :return: [(K1, K2), ...] 候选密钥对
    """
    extra_pairs = extra_pairs or ()

    # 1. 正向：枚举 K1，记录每个中间值可能对应的全部 K1
    #   S-AES 加密对 K1 不是单射，同一中间值可能被多个 K1 命中，
    #   若每个中间值只存一个 K1，真正的 K1 会被后来的候选覆盖而漏解。
    mid_to_keys = {}
    for k1 in range(0x10000):
        mid_to_keys.setdefault(s_aes_encrypt(plaintext, k1), []).append(k1)

    # 2. 反向：枚举 K2 解密到中间值，凡能在正向表中命中的都算候选
    found_keys = []
    for k2 in range(0x10000):
        mid_value = s_aes_decrypt(ciphertext, k2)
        for k1 in mid_to_keys.get(mid_value, ()):
            # 3. 用额外的明密文对复核，过滤仅靠 16 bit 中间值产生的假阳性
            if all(double_encrypt(p, (k1 << 16) | k2) == c for p, c in extra_pairs):
                found_keys.append((k1, k2))

    return found_keys


def triple_encrypt(plaintext, key48):
    """三重加密 (选择 48-bit 密钥模式 K1+K2+K3)"""
    k1 = (key48 >> 32) & 0xFFFF
    k2 = (key48 >> 16) & 0xFFFF
    k3 = key48 & 0xFFFF
    # 加密: C = Enc(K3, Dec(K2, Enc(K1, P)))
    return s_aes_encrypt(s_aes_decrypt(s_aes_encrypt(plaintext, k1), k2), k3)


def triple_decrypt(ciphertext, key48):
    """三重解密"""
    k1 = (key48 >> 32) & 0xFFFF
    k2 = (key48 >> 16) & 0xFFFF
    k3 = key48 & 0xFFFF
    # 解密: P = Dec(K1, Enc(K2, Dec(K3, C)))
    return s_aes_decrypt(s_aes_encrypt(s_aes_decrypt(ciphertext, k3), k2), k1)